# jQuery 热点（一）

> 原文：[`zh.annas-archive.org/md5/80D5F95AD538B43FFB0AA93A33E9B04F`](https://zh.annas-archive.org/md5/80D5F95AD538B43FFB0AA93A33E9B04F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

欢迎来到 *jQuery Hotshot*。本书旨在尽可能多地介绍组成 jQuery 的不同方法和实用程序。您不需要是 jQuery 热门人物来阅读和理解本书包含的项目，但是当您完成本书时，您应该是 jQuery 热门人物。

除了学习如何使用 jQuery，我们还将研究一系列相关技术，包括使用一些更近期的 HTML5 和相关的 API，比如 localStorage，如何使用和创建 jQuery 插件，以及如何使用其他 jQuery 库，比如 jQuery UI、jQuery Mobile 和 jQuery 模板。

jQuery 已经改变了我们多年来编写 JavaScript 的方式。它并不是第一个在开发者中流行和广泛使用的 JavaScript 库，但是它强大的选择器引擎、跨浏览器兼容性和易于使用的语法迅速将其推上了史上最受欢迎和广泛使用的 JavaScript 框架之一。

除了易于使用和将复杂而强大的技术抽象成简单的 API 外，jQuery 还得到了一个日益壮大的开发者社区的支持，并且可能是唯一由非营利基金会保护的 JavaScript 库，以确保该库的开发保持活跃，并且它始终是开源的，对于每个人都是免费的，只要它可用。

最好的事情之一是任何人都可以参与进来。您可以为其他开发人员编写插件，以完成常见或不太常见的任务。您可以使用 bug 跟踪器提出新问题，或者与源代码一起工作以添加功能，或者修复错误，并通过 Git 形式的拉取请求回馈。简而言之，每个想要参与的人，无论其背景或技能水平如何，都有事情可做。

# 入门 jQuery

本书中的每个项目都是围绕 jQuery 构建的；它是我们做的一切的基础。要下载 jQuery 的副本，我们可以访问 jQuery 网站 [`jquery.com/`](http://jquery.com/)。这里有下载按钮可以获取库的生产和开发版本，以及大量其他资源，包括完整的 API 文档、教程等等，以帮助您熟悉使用该库。

jQuery 的核心概念之一是基于从网页的 **文档对象模型** (**DOM**) 中选择一个或多个元素，然后使用库提供的方法对这些元素进行某种操作。

在本书的项目中，我们将查看从页面中选择元素的一系列不同方式，以及我们可以在元素上调用的各种不同方法，但是现在让我们看一个基本的示例。

假设页面上有一个具有 `id` 属性为 `myElement` 的元素。我们可以使用以下代码使用它的 `id` 选择此元素：

```js
jQuery("#myElement");
```

如您所见，我们使用简单的 CSS 选择器来选择我们希望处理的页面元素。这些选择器可以是从简单的 `id` 选择器（如此示例中）到 `class` 选择器，或者更复杂的属性选择器。

除了使用 `jQuery` 选择元素之外，使用 `$` 别名也很常见。这将使用 `$` 而不是 `jQuery` 编写，如下所示：

```js
$("#myElement");
```

一旦以这种方式选择了元素，我们会说该元素被 jQuery 包装了，或者说它是一个包含该元素的 jQuery 对象。使用带有选择器的 `jQuery` （或 `$`）方法始终会返回一个元素集合。

如果没有匹配选择器的元素，则集合的长度为`0`。当使用 `id` 选择器时，我们期望集合包含单个元素。集合中可以返回的元素数量没有限制；这完全取决于所使用的选择器。

现在，我们可以调用操作已选择的元素或元素的 jQuery 方法。大多数 jQuery 方法的一个很棒的特性是，相同的方法可以用于获取值或设置值，这取决于传递给方法的参数。

因此，继续我们的例子，我们已经选择了 `id` 属性为 `myElement` 的元素，如果我们想要找出其像素宽度，我们可以使用 jQuery 的 `width()` 方法：

```js
$("#myElement").width();
```

这将返回一个数字，指定元素有多少像素宽。然而，如果我们希望设置我们的元素的 `width`，我们可以将要设置为元素宽度的像素数作为参数传递给相同的方法：

```js
$("#myElement").width(500);
```

当然，使用 jQuery 并不仅仅是这些简单示例展示的内容，我们将在本书中的项目中探索更多，但这种简洁是该库的核心，也是使其如此受欢迎的因素之一。

# 这本书涵盖了什么内容

项目 1, *滑动拼图*，帮助我们构建一个滑动拼图游戏。我们将使用 jQuery 和 jQuery UI 结合起来制作这个有趣的应用程序，还会看看 localStorage API。

项目 2, *带动画滚动的固定位置侧边栏*，帮助我们实现了一个流行的用户界面特性 - 固定位置的侧边栏。我们专注于处理元素的 CSS，动画和事件处理。

项目 3, *交互式谷歌地图*，教我们如何使用谷歌庞大的地图 API 来创建一个交互式地图。我们将查看一系列 DOM 操作方法，并了解如何将 jQuery 与其他框架一起使用。

项目 4, *jQuery Mobile 单页应用*，介绍了优秀的 jQuery Mobile 框架，以构建一个结合了 jQuery 和 Stack Exchange API 的移动应用程序。我们还研究了 jQuery 的官方模板引擎 JsRender。

项目 5, *jQuery 文件上传器*，再次使用 jQuery UI，这次实现了一个动态前端文件上传器的 Progressbar 小部件。我们还通过将我们的上传器制作成可配置的 jQuery 插件来讲解编写 jQuery 插件。

项目 6, *使用 jQuery 扩展 Chrome 浏览器*，向我们展示了如何使用 jQuery、HTML 和 CSS 扩展流行的 Chrome 浏览器。我们再次利用了 JsRender。

项目 7, *构建你自己的 jQuery*，介绍了如何使用一系列关键的 web 开发工具（包括 Node.js、Grunt.js、Git 和 QUnit）构建 jQuery 的自定义版本。

项目 8, *使用 jQuery 实现无限滚动*，介绍了另一个流行的用户界面特性 - 无限滚动。我们关注 jQuery 的 AJAX 能力，再次使用 JsRender，并查看了方便的 imagesLoaded 插件。

项目 9, *使用 jQuery 构建热图*，帮助我们构建一个由 jQuery 驱动的热图。这个项目有几个方面，包括捕获访问页面时的点击的代码，以及管理员控制台，该控制台汇总并显示信息给站点管理员。

项目 10, *使用 Knockout.js 构建可排序、分页的表格*，向我们展示了如何使用 jQuery 与 MVVM 框架 Knockout.js 构建动态应用程序，使用户界面与数据保持同步。

# 本书所需材料

本书涵盖的一些项目可以仅使用浏览器和简单的文本编辑器完成。当然，完整的 IDE 总是会让事情变得更容易，具有代码完成、代码着色和可折叠块等功能。因此，建议使用 IDE 而不是简单的文本编辑器。

其他项目依赖于其他 JavaScript 框架或社区构建的插件。几个项目使用互联网上托管的第三方服务来消耗数据。其中一个项目需要使用几个额外的高度专业化的应用程序。

如果需要额外的软件或脚本，或者需要 API 访问，这些要求将在相关项目中进行讨论，并包括在哪里获取所需代码或应用程序的信息，如何安装它们以及如何充分使用它们以完成项目。

# 本书适合谁

本书主要面向具有一定 HTML、CSS 和 JavaScript 知识和理解的前端开发人员。希望具有一些 jQuery 经验，但不是必要条件。所有代码，无论是 HTML、CSS 还是 JavaScript（包括 jQuery），都会进行充分讨论，以解释它如何用于完成项目。

# 约定

在本书中，你会经常看到几个标题出现。

为了清晰地说明如何完成某个程序或任务，我们使用：

## 任务简报

本节解释了你将建立的内容，并附有完成项目的截图。

## 为什么这很棒？

该部分解释了为什么该项目很酷、独特、令人兴奋和有趣。它描述了项目将给你带来的优势。

## 你的火热目标

本节解释了完成项目所需的主要任务。

+   任务 1

+   任务 2

+   任务 3

+   任务 4 等等

## 任务清单

本节解释了项目的任何先决条件，例如需要下载的资源或库等等。

## 任务 1

本节解释了你将执行的任务。

## 为升空做准备

本节解释了在开始任务之前可能需要做的任何初步工作。

## 启动推进器

本节列出了完成任务所需的步骤。

## 目标完成 - 迷你总结

本节解释了在上一节中执行的步骤如何帮助我们完成任务。本节是必需的。

## 机密情报

本节中的额外信息与任务相关。

您还将找到一些区分不同信息类型的文本样式。以下是一些这些样式的示例，并解释了它们的含义。

文本中的代码词将显示如下："首先，我们定义一个名为`correctPieces`的新变量，并将其值设置为`0`"。

一个代码块设置如下：

```js
<!DOCTYPE html>

<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title></title>
    <link rel="stylesheet" href="css/common.css" />
  </head>
  <body>
    <script src="img/jquery-1.9.0.min.js"></script>
  </body>
</html>
```

两行独立的代码显示如下：

```js
<div data-role="header">
    <a href="bounty-hunter.html" data-icon="home" 
```

由于空间限制而导致换行的代码行将显示为如下所示：

```js
        filter: "!)4k2jB7EKv1OvDDyMLKT2zyrACssKmSCXeX5DeyrzmOdRu8sC5L8d7X3ZpseW5o_nLvVAFfUSf"
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```js
pieces.appendTo(imgContainer).draggable("destroy");

if (timer) {
 clearInterval(timer);
 timerDisplay.text("00:00:00");
}

timer = setInterval(updateTime, 1000);
currentTime.seconds = 0;
currentTime.minutes = 0;
currentTime.hours = 0;

pieces.draggable({
```

任何命令行输入或输出均按以下方式编写：

```js
cd C:\\msysgit\\msysgit\\share\\msysGit

```

**新术语** 和 **重要单词** 以粗体显示。例如屏幕上看到的单词、菜单或对话框中的单词会在文本中显示为："单击 **下一个** 按钮将您移到下一个屏幕"。

### 注意

警告或重要说明以这样的框显示。

### 提示

贴士和技巧会以此形式出现。


# 第一章：滑动拼图

在我们的第一个项目中，我们将在一个有趣和轻松的环境中看到各种技术的实际运用。把它看作是本书其余部分的轻松热身。

我们将看到如何使用 jQuery UI 使元素可拖动，以及如何配置可拖动元素的行为。我们还将研究其他主题，包括排序算法，以及使用 localStorage API 进行客户端存储。

# 任务简报

在这个项目中，我们将制作一个简单但有趣的拼图游戏，在这个游戏中，一张图片被打乱，必须通过移动板上的不同片段将其复原成原始图片 - 这是对昔日经典游戏的现代基于网络的改编。

通常在板上有一个空白空间，片段只能移动到这个空白空间，因此我们需要建立一个跟踪空白空间位置并只允许片段直接相邻的地方被拖动的系统。

为了给玩家一些动力，我们还可以看看如何跟踪玩家解决拼图所需的时间，以便记录玩家的最佳时间。以下是显示这个项目的最终结果的屏幕截图：

![任务简报](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_01_02.jpg)

## 为什么它如此棒？

游戏很有趣，它可以吸引人们回到您的网站，尤其是年轻的观众。非闪存浏览器游戏以非常大的方式起飞，但是进入顶层行动可能有一个陡峭的学习曲线。

这样一个简单的基于拖动的游戏是让你毫不费力地进入游戏市场的完美方式，而不是立即跳入深水区，让您用一些游戏开发的简单概念来磨练您的技能。

这也是学习如何构建一个精确而引人入胜的可视化接口的绝佳方式，非常适合其预期目标，并且易于直观使用。我们还可以研究一些更高级的可拖动概念，例如避免碰撞和精确定位。我们还将学习如何使用 localStorage API 与会话之间存储和检索数据。

## 你的热门目标

这个项目将被分解成以下任务，我们将按顺序逐步进行工作以产生一个可工作的最终结果：

+   布置基础 HTML

+   创建代码包装器并定义变量

+   将图像分割成片段

+   洗牌拼图片段

+   使拼图片段可拖动

+   启动和停止计时器

+   确定拼图是否已解决

+   记住美好时光，并增加一些最终的样式

## 任务检查清单

除了 jQuery，我们还将在这个项目中使用 jQuery UI，所以现在是时候获取这些库并将它们放在合适的位置。我们还可以花一点时间来设置我们的项目文件夹，这是我们可以存储在整本书中创建的所有文件的地方。

在某个地方创建一个名为 `jquery-hotshots` 的新文件夹。在此文件夹中创建三个新文件夹，分别命名为 `js`、`css` 和 `img`。我们创建的所有 HTML 页面都将放在根目录 `jquery-hotshots` 文件夹中，而我们使用的其他文件将根据其类型分布在子文件夹中。

对于本书中涵盖的项目，我们将使用最新版本的 jQuery 的本地副本，撰写本文时是全新的 1.9.0。从 [`code.jquery.com/jquery-1.9.0.min.js`](http://code.jquery.com/jquery-1.9.0.min.js) 下载压缩版本的副本并将其保存在 `js` 文件夹中。

### 提示

使用 Google 的**内容传送网络**（**CDN**）加载 jQuery，并链接到文件而不指定协议被认为是最佳实践。使用 CDN 意味着文件更可能在访问者的浏览器缓存中，使库加载速度更快。

还建议在某种原因导致 CDN 不可访问时提供一个备用方案。如果未找到 CDN 版本，我们可以非常容易地使用优秀的 **yepnope** 来加载脚本的本地版本。有关此及其他资源加载技巧和技巧的更多信息，请参阅 yepnope 网站 [`yepnopejs.com/`](http://yepnopejs.com/)。

要下载我们需要的 jQuery UI 组件，请访问下载构建器 [`jqueryui.com/`](http://jqueryui.com/)。我们将在后续项目中使用各种其他组件，所以为了简单起见，我们可以使用 **Stable** 按钮下载完整库。撰写本文时的当前版本为 1.10.0。

下载完成后，您需要从存档中的 `js` 目录中获取 `jquery-ui-x.x.x.custom.min.js 文件`（其中 `x.x.x` 是版本号），并将其粘贴到您的 `js` 文件夹中。

### 提示

最近版本的 jQuery UI，以及一些通过 Themeroller 生成的更受欢迎的预定义主题，也可以通过 Google 的 CDN 获取。

# 奠定基础 HTML

首先，我们需要构建包含滑动拼图的页面。初始页面将是一个主要只包含几个容器的外壳；当需要时，可以动态创建组成拼图的可拖动元素。

## 为起飞做准备

我们将为本书中的所有不同项目使用标准起点，因此现在简要介绍一下以节省在每个项目中显示它的时间：

```js
<!DOCTYPE html>

<html lang="en">
    <head>
        <meta charset="utf-8" />
        <title></title>
        <link rel="stylesheet" href="css/common.css" />
    </head>
    <body>
        <script src="img/jquery-1.9.0.min.js"></script>
    </body>
</html>
```

### 提示

**下载示例代码**

您可以从您在 [`www.packtpub.com`](http://www.packtpub.com) 购买的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 并注册，直接将文件发送到您的邮箱。

我们所涵盖的每个项目都将包含在一个页面中，该页面的开头与此相同。现在在您的本地项目文件夹中保存上一个文件的副本，并将其命名为`template.html`。在每个项目的开头，我会说类似于"将模板文件另存为`project-name.html`"。这就是我将要引用的文件。

因此，在主项目目录（`jquery-hotshots`）中保存上一个 HTML（或`template.html`，如果您愿意），并将其命名为`sliding-puzzle.html`。

我们还将使用一个通用的样式表进行基本样式设置，每个项目都将使用它。它包含诸如 HTML5 重置、清除浮动和其他实用工具，以及一些基本的排版修复和主题设置，以确保项目之间的一致性。虽然我不会在这里详细介绍它，但你可以查看本书附带下载的`common.css`源文件以获取更多信息。

每个项目还将需要自己的样式表。在适当的情况下，这些将会涵盖，并将根据需要按项目讨论。我们现在可以创建这个项目中将使用的自定义样式表。

创建一个新文件并将其命名为`sliding-puzzle.css`，然后将其保存在`css`文件夹中。我们可以使用以下代码在页面的`<head>`部分链接到这个文件：

```js
<link rel="stylesheet" href="css/sliding-puzzle.css" />
```

这应该直接出现在`common.css`样式表引用之后。

我们还可以链接到本项目中将要使用的脚本文件。首先，我们下载并复制到`js`文件夹中的 jQuery UI 文件可以使用以下代码链接：

```js
<script src="img/jquery-ui-1.10.0.custom.min.js"></script>
```

记得在 jQuery 本身的脚本之后始终添加 jQuery UI 的脚本。

最后，我们可以添加用于此项目的脚本文件。创建一个新文件并将其保存为`sliding-puzzle.js`，保存在`js`文件夹中。我们可以通过在 jQuery UI 引用之后直接添加以下`<script>`元素来链接到它：

```js
<script src="img/sliding-puzzle.js"></script>
```

## 启动推进器

在根项目文件夹中将模板文件另存为`sliding-puzzle.html`，然后将以下标记添加到`<body>`元素中（在 jQuery`<script>`元素之前）：

```js
<div id="puzzle" class="clearfix">
    <figure>
        <img src="img/space-girl-vera.jpg" />
    </figure>
    <div id="ui">
        <p id="time">Current time: <span>00:00:00</span></p>
        <button id="start">Start!</button>
    </div>
</div>
```

## 目标完成 - 小结

这个简单的 HTML 就是开始的全部。由于这是一本关于 JavaScript 的书，我不会详细介绍 HTML，除非绝对必要。在这种情况下，大部分元素本身并不重要。

主要的是我们有一系列具有`id`属性的容器，这使得选择它们变得快速简便。唯一真正重要的元素是`<img>`，它显示我们将要转换成拼图的原始图像。

### 注意

此示例中使用的精彩图像是由极具天赋的*奥登纽·奥达诺休*先生创建的。您可以在[`eamonart.com/`](http://eamonart.com/)上查看更多他精美作品的示例。项目中使用的图像可以在[`eamonart.com/IMAGES/PINUPSLINKS/Space%20Girl%20Vera.html`](http://eamonart.com/IMAGES/PINUPSLINKS/Space%20Girl%20Vera.html)找到。

# 创建代码包装器和定义变量

我们所有的代码都需要包含在一个在页面加载完成后立即执行的包装函数中。

## 准备起飞

我们在项目的这一部分将完成的步骤如下：

+   为我们的代码添加一个包装函数，该函数将在页面加载完成后立即执行

+   定义我们将在整个脚本中使用的变量

## 启动推进器

第一步是为我们的代码创建一个包装函数，该函数将在页面加载完成后立即执行。将以下代码添加到一个名为 `sliding-puzzle.js` 的新脚本文件中，该文件应保存在我们之前创建的 `js` 目录中：

```js
$(function () {

    //all our code will be in here...

});
```

我们在野外看到的大多数 jQuery 代码都位于某种包装器内。使用 `$(function(){});` 是 jQuery 的 `document.ready` 函数的快捷方式，该函数在页面的 DOM 加载完成后触发。

### 提示

**使用 $**

如果我们与其他开发人员共享我们的代码，我们通常不会在全局范围内像这样使用 `$`，因为页面上可能还有其他库也在使用它。最佳实践是在自动调用的匿名函数内或者您喜欢的立即调用的函数表达式内将 `$` 字符别名化。可以使用 `(function($) { … }(jQuery));` 语法来完成此操作。

接下来，我们可以在脚本文件的顶部设置一些变量。这样做是为了避免我们希望稍后更改的大量值分布在整个文件中。组织是编写可维护代码的关键之一，我们应该始终努力使我们的代码以及我们的意图尽可能清晰。

接下来，在我们刚刚定义的函数内添加以下代码，替换前一个代码示例中显示的注释：

```js
var numberOfPieces = 12,
    aspect = "3:4",
    aspectW = parseInt(aspect.split(":")[0]),
    aspectH = parseInt(aspect.split(":")[1]),
    container = $("#puzzle"),
    imgContainer = container.find("figure"),
    img = imgContainer.find("img"),
    path = img.attr("src"),
    piece = $("<div/>"),
    pieceW = Math.floor(img.width() / aspectW),
    pieceH = Math.floor(img.height() / aspectH),
    idCounter = 0,
    positions = [],
    empty = {
        top: 0, 
        left: 0,
        bottom: pieceH, 
        right: pieceW
    },
    previous = {},
    timer,
    currentTime = {},
    timerDisplay = container.find("#time").find("span");
```

这不是我们将使用的所有变量，只是其中大部分。列表还包括我们将需要在回调函数中使用的任何变量，以便我们不会遇到作用域问题。

## 完成目标 - 迷你总结

我们首先定义的变量是简单（原始）值和我们将在整个代码中使用的对象或数组以及缓存的 jQuery 元素的组合。在使用 jQuery 时，为了获得最佳性能，最好从页面中选择元素并将它们存储在变量中，而不是反复从页面中选择它们。

虽然我们的变量都没有直接赋值给`window`，因此实际上不是全局变量，但由于我们将它们定义在最外层函数的顶部，它们将在整个代码中可见，我们可以将它们视为全局变量。这样我们就能获得全局变量的可见性，而不会实际上使全局命名空间混乱。

### 注意

最佳实践是在它们所属的函数顶部定义变量，因为存在一种被称为**提升**的现象，其中在函数内部深处定义的变量，例如在`for`循环内部，有时会在函数顶部“提升”，可能导致难以追踪的错误。

在可能的情况下，在函数顶部定义变量是避免此类情况发生的简单方法，在编写 jQuery 或一般 JavaScript 时被认为是一种良好的实践。

大多数变量都非常直接。我们存储了我们想要使用的拼图块数以及所使用图像的宽高比。重要的是，拼图块的数量可以被宽度和高度的比率组件等分。

我们使用 JavaScript 的`split()`函数将宽高比拆分为其组成部分，并指定冒号作为拆分字符。我们还使用 JavaScript 的`parseInt()`函数确保我们最终得到的是实际数字而不是字符串，存在`aspectW`和`aspectH`变量中。

接下来的三个变量都是我们需要操作的页面中选择的不同元素。随后是使用 jQuery 创建的新元素。

接下来，我们根据原始图像的宽度和高度以及宽高比计算每个拼图块需要调整大小的`width`和`height`，并初始化一个计数器变量，我们将使用它向每个拼图块添加一个唯一的、有序的`id`属性。我们还添加了一个名为`positions`的空数组，我们将用它来存储每个新块的`top`和`left`位置。

当拼图块在板上移动时，我们需要一种方法来跟踪空白空间，因此我们创建了一个名为`empty`的对象，并赋予它`top`、`left`、`bottom`和`right`属性，以便我们随时知道空白位置在哪里。我们还希望跟踪任何给定块的上一个位置，因此我们创建了一个名为`previous`的空对象，我们将在需要时填充它的属性。

剩下的三个变量都与跟踪解决拼图所需的时间有关。我们定义了但没有初始化`timer`变量，稍后在脚本中将使用它来存储对 JavaScript `setInterval()`-based 定时器的引用。我们还创建了一个名为`currentTime`的空对象，当需要时会再次填充它，并缓存了一个引用，我们将用它来显示当前时间的元素。

# 将图像拆分为块

我们的下一个任务是将图像分割成指定数量的方块，以表示拼图的各个部分。为此，我们将创建一系列较小的元素，每个元素显示图像的不同部分，并可以单独操作。

## 准备起飞

完成此任务所需的单个步骤是创建指定数量的拼图块，并为每个拼图块设置唯一的背景位置和位置，以重新创建图像。

## 启动推进器

我们现在想要生成组成拼图的不同部分。我们可以使用以下代码来完成这个任务，这段代码应该直接添加在我们刚刚在 `sliding-puzzle.js` 中定义的变量之后：

```js
for (var x = 0, y = aspectH; x < y; x++) {
    for (var a = 0, b = aspectW; a < b; a++) {
        var top = pieceH * x,
            left = pieceW * a;

        piece.clone()
             .attr("id", idCounter++)
             .css({
                 width: pieceW,
                 height: pieceH,
                 position: "absolute",
                 top: top,
                 left: left,
                 backgroundImage: ["url(", path, ")"].join(""),
                 backgroundPosition: [
                     "-", pieceW * a, "px ", 
                     "-", pieceH * x, "px"
                 ].join("")
        }).appendTo(imgContainer);

        positions.push({ top: top, left: left });
    }
}
```

## 目标完成 - 小结

我们使用嵌套的 `for` 循环来以网格模式创建新的拼图块。第一个循环将根据需要运行多少行；对于像本示例中使用的 3:4 宽高比图像，我们将需要四行方块。内部循环将根据需要运行多少列，本例中是三列。

在内部循环中，我们首先创建两个新变量 `top` 和 `left`。我们需要在几个地方使用这些值，因此一次创建并在每次需要时重用它们是有意义的。

`top` 位置等于外部循环的计数变量（`x`）的当前值乘以拼图块的 `height`，而 `left` 位置等于内部循环的计数变量（`a`）的当前值乘以拼图块的 `width`。这些变量用于使拼图块在网格中排列。

然后，我们使用 jQuery 的 `clone()` 方法复制我们存储的 `<div>` 元素，并使用 `attr()` 方法使用我们在项目的第一部分初始化的 `idCounter` 变量设置一个唯一的 `id` 属性。请注意，我们同时在 `attr()` 方法中设置变量并递增变量。

我们可以像这样在方法内部递增变量，也可以在方法外部递增变量；在性能或其他方面没有真正区别。我只是觉得在原地更新更简洁。

接下来，我们使用 `css()` 方法在新元素上设置一个 `style` 属性。我们设置拼图块的 `width` 和 `height` 并使用我们的 `top` 和 `left` 变量定位它，以及设置其 `backgroundImage` 和 `backgroundPosition` 样式属性。

### 注意

通常使用连字符单词定义的任何样式属性，例如 `background-image`，在与 jQuery 的 `css()` 方法一起使用对象时，应该使用驼峰命名法。

`backgroundImage` 属性可以使用我们的 `path` 变量和样式的其余字符串组件设置，但是 `backgroundPosition` 属性需要为每个拼图块单独计算。

`backgroundPosition`样式属性的水平分量等于`width`乘以内部循环计数变量（`a`）的值，而垂直分量等于`height`乘以外部循环计数变量（`x`）的值。

一旦新元素被创建，我们可以使用 JavaScript 的`push()`方法将其位置添加到我们的`positions`数组中，传递一个包含元素的`top`和`left`位置属性的对象，以供以后使用。

## 机密情报

我们不再使用标准的字符串连接来构造`backgroundImage`和`backgroundPosition`字符串，而是将值放入数组文字中，然后使用 JavaScript 的`join()`方法将数组连接起来。通过指定一个空字符串作为用于连接字符串的值，我们确保不会向字符串添加任何附加字符。

将一个子字符串数组连接成一个单一字符串比使用`+`运算符在子字符串上构建字符串要快得多，并且由于我们在循环内部重复工作，我们应尽可能优化循环内的代码。

# 洗牌拼图块

在此步骤中，我们需要随机洗牌拼图块，使其成为一个谜题，以便访问者可以重新排列它们。我们还可以删除原始图像，因为它不再需要，并删除第一个拼图块以创建一个空白空间，以便其他拼图块可以移动。

## 准备升空

我们在本任务中将涵盖的步骤是：

+   从页面中删除原始图像

+   删除拼图的第一个块

+   从位置数组中删除第一个项目

+   随机洗牌拼图块

## 启动推进器

完成第一步仅需要添加以下代码行，应直接添加到上一任务中我们在`sliding-puzzle.js`中添加的外部`for`循环的结束大括号之后：

```js
img.remove();
```

第二步同样简单；以下内容可以直接添加到上一行代码之后：

```js
container.find("#0").remove();
```

我们还可以为下一步使用一行代码。将以下内容直接添加到上一行代码之后： 

```js
positions.shift();
```

洗牌拼图块将稍微复杂一些；您会记得项目的第一部分中我们添加基础 HTML 时其中一个元素是一个开始按钮。我们将使用此按钮来触发洗牌。将以下代码直接添加到我们刚刚添加的前两行代码之后（确保它们仍然在外部函数包装器内）：

```js
$("#start").on("click", function (e) {
    var pieces = imgContainer.children();

    function shuffle(array) {
        var i = array.length;

        if (i === 0) { 
            return false;
        }
        while (--i) {
            var j = Math.floor(Math.random() * (i + 1)),
                tempi = array[i],
                tempj = array[j];

                array[i] = tempj;
                array[j] = tempi;
        }
    }

    shuffle(pieces);

    $.each(pieces, function (i) {
        pieces.eq(i).css(positions[i]);
    });

    pieces.appendTo(imgContainer);

    empty.top = 0;
    empty.left = 0;

    container.find("#ui").find("p").not("#time").remove();

});
```

## 目标完成 - 迷你总结

jQuery 的`remove()`方法用于从页面中删除原始图像元素，这些元素在脚本开头声明变量时已经选择了。我们使用相同的方法来删除第一个拼图块，我们应该在拼图块被洗牌之前*之前*这样做，以避免删除关键部件，例如脸部。与此示例中使用的图像一样，其中感兴趣的主要项目不在左上角的图像是有益的。

我们从面板上移除了第一块拼图，因此我们也应该移除`positions`数组中的第一项。当我们来检查拼图是否已经还原时，我们将使用这个数组，由于第一个位置上没有拼图块，我们不需要存储它的位置。我们使用 JavaScript 的`unshift()`方法来实现这一点，它简单地移除调用它的数组中的第一个项目。

### 使用 on()为按钮添加事件处理程序

我们通过选择按钮并调用 jQuery 的`on()`方法为按钮添加了点击事件处理程序。在这个例子中，`on()`方法接受两个参数（尽管在需要事件委托时它可以接受三个参数）。

第一个参数是要监听的事件，第二个参数是每次检测到事件时要执行的处理程序函数。在这种情况下，我们正在监听`click`事件。

### 提示

**全能的 on()方法**

jQuery 的`on()`方法，自 1.7 版本引入，取代了现已废弃的`bind()`、`live()`和`delegate()`方法。现在使用`on()`是 jQuery 中附加事件处理程序的推荐方法。

在处理程序函数内部，我们首先定义一个变量，它存储了`<figure>`元素的子元素。虽然我们需要再次从页面中选择拼图块，但我们仍然可以使用我们缓存的`imgContainer`变量来避免创建新的 jQuery 对象。

### 洗牌拼图块

接下来我们定义了一个名为`shuffle()`的函数，它接受要洗牌的数组作为参数。这个函数执行了一个**Fisher-Yates**洗牌算法，这是一个创建给定值的随机排序的已知模式。

在函数内部，我们首先获取传入的数组的长度，如果数组为空，则返回`false`（退出函数）。然后，我们使用`while`循环遍历数组。在 JavaScript 中，`while`循环类似于`for`循环，但是当括号中指定的条件具有`truthy`值（或者评估为`true`）时执行，而不是执行指定次数的循环。使用预减量循环条件是为了避免在所有项都被洗牌后不必要地迭代循环。

### 注意

在 JavaScript 中，除了`true`或`false`布尔值之外，其他类型的变量也可以被称为`truthy`或`falsey`。以下值都被认为是`falsey`：

+   布尔值`false`

+   数字`0`

+   空字符串

+   `null`

+   `undefined`

+   `NaN`

所有其他值都被认为是`truthy`。这样可以使非布尔值用作条件。falsey 和 false 之间的相似性可能会导致混淆；只需记住 false 是一个实际的值，而 falsey 是一个值的一个方面，除了 false 还有其他值也具有。

有关此主题的更多信息，请参见[`james.padolsey.com/javascript/truthy-falsey/`](http://james.padolsey.com/javascript/truthy-falsey/)。

在循环内，对数组中的每个项（除第一个项外）进行随机选择，并与数组中的另一项交换位置。为了生成用作要交换的项的索引的随机数，我们首先使用 JavaScript 的`Math.random()`函数生成一个随机数，把得到的随机数（在`0`和`1`之间）乘以数组的长度加`1`。这将给我们一个在`0`和数组长度之间的随机数。

然后，我们从数组中取出当前索引的项，以及随机生成的索引处的项，并交换它们的位置。这可能看起来很复杂，但这几乎被普遍认为是随机洗牌数组中项的最有效方式。它给了我们最随机的结果，处理的工作量最少。

一旦我们定义了函数，我们就会调用它，将`pieces`数组作为要洗牌的数组传递进去。

### 注意

有关 Fisher-Yates 乱序的 JavaScript 实现的更多信息，请参阅[`sedition.com/perl/javascript-fy.html`](http://sedition.com/perl/javascript-fy.html)。

### 定位元素

完成元素数组的洗牌后，我们使用 jQuery 的`each()`方法对其进行迭代。此方法传递了要迭代的数组，在这种情况下是刚刚洗牌的`pieces`数组。第二个参数是一个迭代器函数，将对数组中的每个项进行调用。

在这个函数中，我们使用我们的`positions`数组将洗牌后的元素放在页面的正确位置。如果我们不这样做，元素将被洗牌，但因为它们的`absolute`定位，它们仍会出现在页面的同一位置。我们可以使用在创建新元素时更新的`positions`数组来获得每个洗牌元素的正确`top`和`left`位置。

一旦元素集合被迭代并设置了它们的位置，我们就可以使用 jQuery 的`appendTo()`方法把它们再次附加到页面上。同样，我们可以把我们的`imgContainer`变量作为`appendTo()`的参数，以避免再次从页面选择容器。

### 定位空白空间

最后，我们应该确保空白空间确实位于板的顶部和左边的`0`位置。如果点击了按钮，移动了一些方块，然后再次点击按钮，我们必须确保空白空间在正确的位置。我们通过将`empty`对象的`top`和`left`属性都设置为`0`来实现这一点。

我们还可以删除显示在 UI 区域的任何先前消息（我们将在项目的最后部分涵盖添加这些消息）。但我们不想删除计时器，所以我们使用 jQuery 的`not()`方法来过滤出当前元素，该方法接受一个选择器，匹配的元素被丢弃，因此不会从页面中删除。

此时，我们应该能够在浏览器中运行页面，并通过点击**开始！**按钮来打乱拼图块：

![定位空白区域](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_01_01.jpg)

# 使拼图块可拖动

现在是时候启动 jQuery UI，使拼图的各个部分可拖动了。

jQuery UI 是一套用于构建交互式和高效用户界面的 jQuery 插件。它稳定、成熟，并被公认为是 jQuery 的官方 UI 库，尽管不是唯一的。

## 准备起飞

在此任务中，我们将涵盖以下步骤：

+   使用 jQuery UI 的可拖动组件使拼图块可拖动

+   配置可拖动的元素，以便只有直接相邻空白区域的块可以移动

+   配置可拖动的元素，以便块只能移动到空白区域

## 启动推进器

首先，我们将使拼图块可拖动，并设置一些组件公开的配置选项。此代码应添加到上一个任务中添加的代码之后的`sliding-puzzle.js`中：

```js
pieces.draggable({
    containment: "parent",
    grid: [pieceW, pieceH],
    start: function (e, ui) {

    },
    drag: function (e, ui) {

    },
    stop: function (e, ui) {

    }
});
```

在此任务的接下来几个步骤中，将在上一个代码示例的`start`、`drag`和`stop`回调函数中添加额外的代码。

我们还需要配置可拖动性，以便块只能移动到空白区域，而不是在彼此之间移动，并且只有直接相邻空白区域的块才能被移动。

现在让我们将以下代码添加到我们刚刚添加的`start`回调函数中：

```js
var current = getPosition(ui.helper);

if (current.left === empty.left) {
    ui.helper.draggable("option", "axis", "y");
} else if (current.top === empty.top) {
    ui.helper.draggable("option", "axis", "x");
} else {
    ui.helper.trigger("mouseup");
    return false;
}

if (current.bottom < empty.top || 
    current.top > empty.bottom ||
    current.left > empty.right || 
    current.right < empty.left) {
        ui.helper.trigger("mouseup");
        return false;
    }

    previous.top = current.top;
    previous.left = current.left;
```

接下来，将以下代码添加到`drag`回调函数中：

```js
var current = getPosition(ui.helper);

ui.helper.draggable("option", "revert", false);

if (current.top === empty.top && current.left === empty.left) {
    ui.helper.trigger("mouseup");
    return false;
}

if (current.top > empty.bottom ||
    current.bottom < empty.top || 
    current.left > empty.right || 
    current.right < empty.left) {
        ui.helper.trigger("mouseup")
                 .css({ 
                     top: previous.top, 
                     left: previous.left 
                 });
        return false;
}
```

最后，我们应该将以下代码添加到`stop`回调函数中：

```js
var current = getPosition(ui.helper);

if (current.top === empty.top && current.left === empty.left) {

    empty.top = previous.top;
    empty.left = previous.left;
    empty.bottom = previous.top + pieceH;
    empty.right = previous.left + pieceW;
}
```

在我们的每个回调函数中，我们使用了一个辅助函数，返回当前可拖动元素的确切位置。我们还应该在`draggable()`方法之后添加此函数：

```js
function getPosition(el) {
    return {
        top: parseInt(el.css("top")),
        bottom: parseInt(el.css("top")) + pieceH,
        left: parseInt(el.css("left")),
        right: parseInt(el.css("left")) + pieceW
    }
}
```

## 目标完成 - 小结

我们在上一个任务中写了很多代码，让我们来分解并看看我们做了什么。我们首先通过使用 jQuery UI 的可拖动组件使块可拖动。我们通过调用`draggable()`方法来实现这一点，传入一个对象字面量，设置可拖动组件公开的各种选项。

首先，我们将`containment`选项设置为`parent`，这样可以阻止任何拼图块被拖出它们所在的`<figure>`元素。我们还设置了`grid`选项，允许我们指定拼图块应该捕捉到的点的网格。我们将数组设置为此选项的值。

此数组中的第一项设置了网格的水平点，第二项设置了网格的垂直点。设置这些选项使块的移动更具真实感和触觉体验。

接下来我们设置的最后三个选项实际上是回调函数，在拖动的生命周期的不同点被调用。我们使用`start`、`drag`和`stop`回调。

### 当拖动开始时

`start`回调将在可拖动对象上的`mousedown`事件后的拖动交互的最开始触发一次。`stop`回调将在拖动交互的最后，即`mouseup`事件注册后触发一次。`drag`回调几乎在被拖动元素每移动一个像素时都会连续触发，因为它被用于每次拖动元素移动时都调用。

让我们首先看一下`start`回调。每个回调在被调用时由 jQuery UI 传递两个参数。其中之一是事件对象，在这个项目中我们不需要，而第二个是一个包含有关当前可拖动对象的有用属性的对象。

在函数开始时，我们首先获取拖动开始的块的确切位置。当我们调用我们的`getPosition()`函数时，我们传入`ui`对象的`helper`属性，它是对已开始被拖动的基础 DOM 元素的 jQuery 封装引用。

一旦我们获得了元素的位置，我们首先检查元素是否与空白空间在同一行，方法是将当前对象（由`getPosition()`返回的对象）的`left`属性与`empty`对象的`left`属性进行比较。

如果这两个属性相等，则将可拖动对象的`axis`选项设置为`y`，以便它只能水平移动。可以使用`option`方法在任何 jQuery UI 小部件或组件中设置配置选项。

如果它不在同一行，则通过比较`current`和`empty`对象的`top`属性来检查它是否在同一列。如果这两个属性相等，则我们将`axis`选项设置为`x`，以便块只能垂直移动。

如果这些条件都不为真，则该块不能与空白空间相邻，因此我们使用 jQuery 的`trigger()`方法手动触发`mouseup`事件来停止拖动，并从函数中返回`false`，以便我们的`stop`处理程序不会被触发。

我们需要确保只有与空白空间在同一行或同一列的方块可以被拖动，但我们还需要确保任何不直接与空白空间相邻的方块也不能被拖动。

为了阻止非邻近空白空间的块被拖动，我们只需检查：

+   当前块的*下边*小于空白空间的*上边*

+   当前块的*上边*大于空白空间的*下边*

+   当前块的*左边*大于空白空间的*右边*

+   当前块的*右边*小于空白空间的*左边*

如果这些条件中的任何一个为真，我们再次通过手动触发`mouseup`事件停止拖动，并通过返回`false`来停止调用拖动对象上的任何进一步事件处理程序（但仅限于当前拖动交互）。

如果回调函数在这一点没有返回，我们就知道我们正在处理一个与空白空间相邻的可拖动对象，因此我们通过在项目开始时初始化的`previous`对象的`top`和`left`属性来存储它当前的位置，以便以后使用。

### 提示

**ui.helper 的位置**

传递给我们回调函数的`ui`对象实际上包含一个称为`position`的对象，它可以用于获取当前可拖动物体的位置。然而，由于我们使用了`grid`选项，此对象中包含的值可能对我们的需求不够精细。

### 在拖动期间

接下来，我们可以走一遍`drag`回调，这将在每次当前可拖动物体的位置改变时调用。这将发生在`mousedown`事件期间。

首先，我们需要知道被拖动的拼图在哪里，所以我们再次调用我们的`getPosition()`辅助函数。

然后我们想要检查被拖动的拼图是否在空白空间中。如果是，我们可以像之前一样停止拖动-手动触发`mouseup`事件并返回`false`。

在拖动过程中，只有有效的拼图才能被拖动，因为我们已经筛选掉了与空白空间不直接相邻的拼图。然而，我们还需要检查被拖动的拼图是否正在远离空白空间。我们可以在`start`回调中筛选出与空白空间不直接相邻的拼图的方式进行检查。

### 拖动结束时

`stop`回调是三个回调中最简单的。我们获取被拖动的拼图的位置，如果它确实在空白空间中，我们就把空白空间移到拖动时它所在的位置。记住，我们把这些信息存储在一个叫`previous`的对象中。

# 启动和停止计时器

此时，我们的游戏已经功能完善，拼图也可以被拼好了；但是为了增加乐趣，我们应该通过引入计时器来增加竞争元素。

## 为起飞做准备

在这个任务中，我们需要完成以下步骤：

+   检查是否在单击**开始**按钮时计时器已经在运行

+   从`0`开始计时

+   每秒增加一次计时器

+   在页面上更新显示，以便玩家可以看到当前游戏已经进行了多长时间

## 启动推进器

要检查在单击**开始**按钮时计时器是否已经在运行，我们应该在将洗牌后的拼图追加到页面之后直接添加以下代码，并紧接着调用`draggable()`之前：

```js
pieces.appendTo(imgContainer).draggable("destroy");

if (timer) {
 clearInterval(timer);
 timerDisplay.text("00:00:00");
}

timer = setInterval(updateTime, 1000);
currentTime.seconds = 0;
currentTime.minutes = 0;
currentTime.hours = 0;

pieces.draggable({
```

接下来，我们可以添加一个增加计时器并更新显示的函数。这段代码应该直接放在我们在前面更新`currentTime.hours`的代码之后：

```js
function updateTime() {

    if (currentTime.hours === 23 && currentTime.minutes === 59 &&
currentTime.seconds === 59) {
        clearInterval(timer);          
    } else if (currentTime.minutes === 59 && currentTime.seconds === 59) {

        currentTime.hours++;
        currentTime.minutes = 0;
        currentTime.seconds = 0;
    } else if (currentTime.seconds === 59) {
        currentTime.minutes++;
        currentTime.seconds = 0;
    } else {
        currentTime.seconds++;
    }

    newHours = (currentTime.hours <= 9) ? "0" + currentTime.hours :

    currentTime.hours;
    newMins = (currentTime.minutes <= 9) ? "0" + currentTime.minutes :

    currentTime.minutes;
    newSecs = (currentTime.seconds <= 9) ? "0" + currentTime.seconds : 

    currentTime.seconds;

    timerDisplay.text([
        newHours, ":", newMins, ":", newSecs
    ].join(""));

}
```

## 目标完成-小结报告

在此任务中，我们首先要做的是检查定时器是否已经在运行。定时器将存储在我们的一个“全局”变量中，因此我们可以轻松地检查它。我们使用`if`语句来检查`timer`是否包含真值（请参阅有关 JavaScript 的真值和虚值的先前信息）。

如果有的话，我们知道定时器已经在运行，因此我们使用 JavaScript 的`clearInterval()`函数取消定时器，将我们的`timer`变量作为要清除的定时器传入。如果定时器已经在运行，我们还可以重置定时器显示。在项目开始时，我们从页面中选择了定时器显示元素，并在最初声明变量时对其进行了缓存。

接下来，我们使用 JavaScript 的`setInterval()`方法启动定时器，并将其分配给我们的`timer`变量。当定时器开始时，此变量将包含定时器的 ID，而不是定时器的值，这就是`clearInterval()`知道要清除哪个定时器的方式。

`setInterval()`函数接受一个要在指定间隔后执行的函数作为第一个参数，间隔作为第二个参数。我们将间隔指定为`1000`毫秒，等于 1 秒，因此将每秒调用作为第一个参数传递的函数，直到定时器被清除。

一旦定时器启动，我们还可以重置存储在我们将用于跟踪定时器的对象中的值 - `currentTime`对象。我们将此对象的`seconds`，`minutes`和`hours`属性设置为`0`。我们需要一个对象来跟踪时间，因为`timer`变量本身只包含定时器的 ID。

接下来，我们添加了`updateTime()`函数，该函数将由我们的间隔每秒调用一次。在此函数中，我们只需更新`currentTime`对象的相关属性，并更新显示。我们使用`if`条件来检查要更新定时器的哪些部分。

我们首先检查定时器是否尚未达到 24 小时。我希望没有人会实际花费那么长的时间来玩游戏，但是如果出于某种原因浏览器保持打开状态达到这么长时间，我们不希望时间显示为，例如，24 小时 1 分钟，因为在那时，我们真的应该更新显示为 1 天 0 小时 1 分钟。但我们不关心天数，所以我们只是停止定时器。

如果定时器尚未达到此时间长度，则我们检查当前分钟是否等于`59`，当前秒是否等于`59`。如果是，我们需要将`currentTime.hours`增加`1`，并将`currentTime.minutes`和`currentTime.seconds`属性重置为`0`。

如果此检查失败，则我们检查秒是否等于`59`。如果是，则我们增加`currentTime.minutes`属性，然后将`currentTime.seconds`重置为`0`。如果此第二个测试也失败，则我们知道我们所要做的就是增加`currentTime.seconds`。

接下来，我们需要检查是否需要在时间组件的前面加上前导`0`。我们可以使用另一个`if else`条件来实现，但 JavaScript 的三元结构更简洁更紧凑，所以我们使用它。

首先我们测试`currentTime.hours`是否小于或等于`9`，如果是，我们在值的开头添加`0`。对于`currentTime.minutes`和`currentTime.seconds`，我们也是这样做的。

最后，我们构建将用于更新计时器显示的字符串。我们不再使用乏味且缓慢的字符串连接，而是再次使用包含显示各个部分的数组，然后将数组连接起来。

结果字符串被设置为`timerDisplay`变量中包含的`<span>`元素的值，并使用 jQuery 的`text()`方法更新页面上的元素。

在这一点上，我们现在可以点击按钮来洗牌拼图块，并观察计时器开始递增。

# 确定拼图是否已解决

在这个任务中，我们将专注于确定拼图块是否已放回其正确位置，从而对拼图进行解开并解决。

## 准备起飞

在此任务中将涵盖以下步骤：

+   检查拼图块的顺序是否与拼图块的初始顺序匹配

+   停止计时器

+   显示祝贺消息

## 启动推进器

首先，我们需要决定何时检查拼图是否已完成。在拖动的`stop`事件上进行检查的好地方。

首先，在`stop()`回调的顶部的现有`current`变量之后直接添加以下新变量：

```js
var current = getPosition(ui.helper),
 correctPieces = 0;

```

不要忘记在第一个变量之后添加尾随逗号，就像前面的代码示例中所示的那样。接下来，在`if`语句之后直接添加以下代码：

```js
$.each(positions, function (i) {
    var currentPiece = $("#" + (i + 1)),
        currentPosition = getPosition(currentPiece);

    if (positions[i].top === currentPosition.top && positions[i].left === currentPosition.left) {

        correctPieces++;
    }
});

if (correctPieces === positions.length) {
    clearInterval(timer);
    $("<p/>", {
        text: "Congratulations, you solved the puzzle!"
    }).appendTo("#ui");
}
```

## 完成目标 - 小结

首先，我们定义了一个名为`correctPieces`的新变量，并将其值设置为`0`。然后，我们使用 jQuery 的`each()`方法迭代了我们在代码早期，当我们最初对拼图块进行洗牌时，填充的`positions`数组。

在这一点上，我们需要做的是获取拼图的每一块，并检查这些块是否按正确的顺序排列。然而，我们不能仅仅使用 jQuery 的`children()`方法或`find()`方法选择页面上的元素，因为 jQuery 不会以它们在 DOM 中找到的顺序返回元素，尤其是因为我们已经将它们全部移动到了它们的父容器周围。

我们需要做的是通过其`id`属性选择每个元素，然后检查其在`style`属性中具有的`top`和`left`CSS 属性。`positions`数组的长度与拼图块的数量相同，因此我们可以迭代此数组，并使用 jQuery 自动传递给迭代器函数的索引参数。

在迭代器中，我们首先选择当前元素。每个方块的`id`属性将从`1`开始，而不是从`0`开始，因为我们已经从拼图中移除了第一个方块，所以在选择每个方块时，我们将索引值加`1`。我们还使用现有的`getPosition()`函数获取当前元素的位置，传入我们刚刚选择的元素。

接下来，我们将当前方块的`top`和`left`属性与`positions`数组中等效的项目进行比较，如果`top`和`left`属性都匹配，我们将增加`correctPieces`变量。

一旦页面上的每个方块和`positions`数组中的每个项目都被比较，并且`each()`方法完成迭代，我们接着检查`correctPieces`变量的值是否等于`positions`数组的长度。如果是的话，我们知道每个方块都在正确的位置上。

我们可以像以前一样停止计时器，使用`clearInterval()`函数，然后创建祝贺消息并将其附加到具有`id`为`ui`的元素。

# 记住最佳时间并添加一些最终样式

现在游戏已经可以玩得很好。我们可以打乱方块，只允许按规则拖动它们，游戏将会检测拼图何时完成。使用简单的计时器，我们可以告诉玩家解决问题所需的时间，但接下来呢？玩家应该做些什么，只是记住他/她的最高分吗？

当然，现在我们需要一种方法来保存玩家的最佳时间。如果他们超过存储的最佳时间，显示额外的消息也会很方便。我们将使用 JavaScript 的 localStorage API 来存储最佳时间。

我们还可以添加一些额外的样式来完成游戏的外观，并更好地布置不同的元素。

## 为起飞做准备

我们在这项任务中将要涉及的步骤如下：

+   检查是否已保存了最佳时间

+   检查当前最佳时间是否优于保存的最佳时间

+   当当前最佳时间优于保存的最佳时间时更新保存的最佳时间

+   在超过保存的最佳时间时显示额外消息

+   用 CSS 整理游戏的呈现方式

## 启动推进器

我们在这项任务中需要做的一切都可以在`if`语句中完成，该语句在方块恢复正确顺序后执行。在上个任务中显示祝贺消息的地方后面直接添加以下代码：

```js
var totalSeconds = (currentTime.hours * 60 * 60) + (currentTime.minutes * 60) + currentTime.seconds;

if (localStorage.getItem("puzzleBestTime")) {

    var bestTime = localStorage.getItem("puzzleBestTime");

    if (totalSeconds < bestTime) {

        localStorage.setItem("puzzleBestTime", totalSeconds);

        $("<p/>", {
            text: "You got a new best time!"
        }).appendTo("#ui");
    }
} else {
    localStorage.setItem("puzzleBestTime", totalSeconds);

    $("<p/>", {
        text: "You got a new best time!"
    }).appendTo("#ui");
}
```

我们已经创建了我们将用于此的样式表 – `sliding-puzzle.css`，所以我们只需要将以下选择器和样式规则添加到该文件中： 

```js
#puzzle { 
    width:730px; padding:5px; margin:auto; 
    border:1px solid #aaa; border-radius:5px; 
    background-color:#eee; 
}
#puzzle figure { 
    width:510px; height:676px; border:1px solid #aaa; 
    position:relative; float:left; background-color:#fff; 
}
#ui { padding:10px 0 0 10px; float:left; }
#ui button { margin-bottom: 2em; }
#ui p { font-size:1.7em; }
#start { width:204px; height:50px; font-size:1.75em; }
```

## 目标完成 - 小型总结

首先我们将当前时间转换为秒，这样我们就只有一个值可以使用和存储。秒数是使用`currentTime`对象的`hours`、`minutes`和`seconds`属性来计算的，用来更新页面上可见的计时器。

`hours` 属性乘以 `60` 转换为分钟，然后再乘以 `60` 转换为秒。 `minutes` 属性仅乘以 `60` 一次，然后将这两个值加到 `seconds` 属性中剩余的秒数中，得到最终的总数，我们将其存储在 `totalSeconds` 变量中。

接下来，我们检查 localStorage 是否存在一个名称为 `puzzleBestTime` 的键。如果存在，则将 `localStorage` 中保存的值存储在 `bestTime` 变量中。如果 `totalSeconds` 变量的值小于 `bestTime` 变量，我们就有了一个新的最高分，我们将其保存在 localStorage 中，名称为 `puzzleBestTime`，以覆盖旧的最佳时间。然后，我们显示第二个祝贺消息，表示已经取得了新的最高分。

如果 localStorage 不包含具有此名称的键，那么这必须是此浏览器中首次玩游戏，因此我们将键的名称设置为并将 `currentTime` 变量的值存储为新的最佳时间，然后再次显示第二个祝贺消息。

在我们添加的 CSS 中没有什么真正关键的内容；它只是一点点轻微的样式，用来整理我们使用的各种元素，并以更清晰的风格呈现游戏。

## 机密情报

localStorage API 是 HTML5 通用术语中比较稳定的 JavaScript API 之一，并且受到所有常见浏览器的最新版本的广泛支持。

我们可能仍然需要支持的旧浏览器，比如 IE7 或 Firefox 2，不支持 localStorage。幸运的是，有大量的填充和解决方法可以在这些旧浏览器中添加基本的支持。

请参阅[`github.com/Modernizr/Modernizr/wiki/HTML5-Cross-Browser-Polyfills`](https://github.com/Modernizr/Modernizr/wiki/HTML5-Cross-Browser-Polyfills)获取一系列支持现代 API 的填充和补丁，以在旧浏览器中添加支持。

# 任务完成

在这个项目的过程中，我们使用了大量的 jQuery 和原生 JavaScript 来创建这个简单的游戏。我们还研究了使用 jQuery UI 的可拖动组件以及 localStorage API。

我们涵盖了很多代码，所以让我们简要回顾一下我们做过的事情。

我们首先在 `document.ready` 函数的开头声明了大部分在整个项目中使用的变量。这样做很有用，因为变量可以在我们的代码中使用，而不需要将它们全局范围化。出于性能原因，最好缓存 jQuery 对象，以便它们可以经常被操作，而无需在页面中不断地重新选择它们。

我们接着看到了如何利用一些嵌套的`for`循环和简单的数学知识，轻松地将已知长宽比的图像分割成多个等大小的块，排列在一个网格中。我们还发现，使用子字符串数组来创建字符串而不是使用字符串连接是一个非常简单的优化，可以在构建长字符串时帮助加快我们应用程序的速度。

然后，我们看到了如何使用一个接受的算法来随机化——费希尔-耶茨洗牌算法，将各个部分随机排列。实际上，我们完全没有使用 jQuery 来做这个，但不要忘记，生成洗牌的代码是在使用 jQuery 的`on()`方法添加的事件处理程序内执行的。

接下来，我们看了如何使用 jQuery UI 使拼图的各个部分可拖动。我们看了组件暴露的一些可配置选项，以及如何在拖动部分时对生成的不同事件作出反应。具体来说，我们使用了`start`、`drag`和`stop`回调来执行游戏规则，限制哪些部分可以在游戏中移动，以及它们在游戏过程中如何移动。

之后，我们看了如何使用标准的 JavaScript 定时器来跟踪解谜游戏所需的时间，以及如何更新页面上可见的计时器，让玩家能够看到他们开始以来经过的时间。

检测拼图何时被解决也是代码的一个关键能力。我们在这里的主要障碍是，拼图的部分并不是按照我们在屏幕上看到的可见顺序选取的，但这很容易通过使用它们的编号`id`属性来选取部分，然后手动检查它们的 CSS 位置来克服。

最后，我们看了如何记录玩家解谜游戏的最佳时间。在这里，localStorage 是显而易见的选择，只需一小步检查是否已经存储了分数，然后比较当前时间和存储的时间，就能知道记录是否被打破了。

# 你准备好全力以赴了吗？一个高手的挑战

我们的简单游戏仍然可以添加许多更多的功能。为什么不更新游戏，让玩家可以选择不同的技能水平呢？

要实现这一点，我们只需要提供某种接口，允许访问者选择技能水平，然后考虑一种使游戏变得更难的方式。

如果我们假设当前游戏格式是最简单的技能水平，那么使游戏变得更难的一个非常简单的方法是增加将原始图像分割成的块数。尝试自己做这个吧。那些对数学有深刻理解的人可能会意识到我们的游戏还有另一个缺陷——一些随机组合的部分根本无法解决。存储或计算所有可解决的可能组合可能超出了实际可行，但还有另一种选择。

而不是随机洗牌一堆碎片，然后将它们的位置写入板上，我们可以通过程序化地在棋盘上移动它们来洗牌。根据玩家受限的游戏规则进行洗牌的拼图将每次都得到一个可解的拼图。


# 第二章：固定位置侧边栏带有动画滚动

`position:fixed` CSS 样式添加了一个有趣的效果，允许一个目标元素在页面被滚动时保持其位置。然而，它的有效性受到一个限制，即无论这个元素被嵌套在其他元素中多深，它始终是相对于整个文档固定的。

# 任务简报

在这个项目中，我们将创建一个侧边栏，模拟`position:fixed`的 CSS 样式，但不会受到纯 CSS 解决方案的相同限制。我们还可以在页面上添加一种吸引人的动画，以便当侧边栏中的导航项被点击时，页面的不同部分被滚动到视图中。

以下是此项目的最终结果的截图：

![任务简报](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106_02_01_preFinal.jpg)

## 为什么很棒？

能够在页面上固定一个元素是一种非常流行的 UI 设计模式，被许多大型和受欢迎的网站使用。

将访问者的主要工具或行动呼吁保持在任何时候都可以接触到，提高了网站的用户体验，并可以帮助保持您的访问者满意。方便是重要的，所以如果访问者必须向下滚动一个长页面，然后再次向上滚动才能点击某些内容，他们很快就会对页面失去兴趣。

这个原理在移动设备上也是一个新兴的趋势。实际的`position:fixed`样式在移动设备上普遍支持较差，但在某些当今最知名的应用程序中，将重要工具保持在手边，而不需要过多滚动或更改屏幕，这一想法正在被采用和实施。

## 你的炫酷目标

要完成此项目，我们需要完成以下任务：

+   构建一个合适的演示页面

+   存储固定元素的初始位置

+   检测页面何时滚动

+   处理浏览器窗口的调整大小

+   自动滚动

+   恢复浏览器的返回按钮

+   处理页面加载时的哈希片段

# 构建一个合适的演示页面

在这个任务中，我们将准备演示页面和其他我们需要的文件，以便为脚本做好准备。

为了明显展示这种技术的好处，我们将需要使用一些额外的元素，严格来说，这些元素不是侧边栏所需的元素的一部分，我们将固定在一个地方。

我们将在此示例中使用的侧边栏需要位于完整页面结构内，为了看到固定位置效果，页面也需要非常长。

在构建我们的演示页面时，我们将使用一系列 HTML5 元素，你应该知道这些元素在某些浏览器的旧版本中不受支持。如果你发现你需要支持旧版本的浏览器，你将需要使用 Google Code 提供的`html5shiv`脚本（[`code.google.com/p/html5shiv/`](http://code.google.com/p/html5shiv/)）。

## 为起飞做准备

我们应首先将模板文件的新副本保存到项目的根文件夹中，并将新文件命名为`fixed-sidebar.html`。我们还可以创建一个名为`fixed-sidebar.css`的新样式表，将其保存在`css`文件夹中，并创建一个名为`fixed-sidebar.js`的新 JavaScript 文件，应保存到`js`文件夹中。

我们可以使用以下新的`<link>`元素将新样式表链接到 HTML 页面的`<head>`部分，该元素应直接添加到链接到`common.css`之后：

```js
<link rel="stylesheet" href="css/fixed-sidebar.css" />
```

请记住，`common.css`样式表用于提供诸如重置、简单的排版框架和一些常见的布局样式等有用内容，以尽量减少每个项目所需的 CSS。

我们可以使用以下新的`<script>`元素将新的 JavaScript 文件链接到`fixed-sidebar.html`页面的`<body>`部分中的 jQuery `<script>`文件之后：

```js
<script src="img/fixed-sidebar.js"></script>
```

底层页面现在已设置好，准备为这个项目添加所需的元素。

## 启动推进器

我们将为我们的页面使用基本布局，其中包括以下元素，这些元素应添加到`fixed-sidebar` `.html`中：

```js
<header>
    <h1>jQuery fixed sidebar example page</h1>
</header>

<div class="wrapper">
    <article>
        <h1>Example content area</h1>
        <section id="part1">
        </section>    
        <section id="part2">
        </section>
        <section id="part3">
        </section>  
        <section id="part4">
        </section> 
        <section id="part5">
        </section>
    </article>   
    <aside>
        <h2>Important content to fix in place</h2>
        <nav>
            <h3>Some in page navigation</h3>
            <ul>
                <li><a href="#part1">Section 1</a></li>
                <li><a href="#part2">Section 2</a></li>
                <li><a href="#part3">Section 3</a></li>
                <li><a href="#part4">Section 4</a></li>
                <li><a href="#part5">Section 5</a></li>
            </ul>
        </nav>
    </aside>
</div>
```

这些元素应直接添加到页面的`<script>`元素之前，该元素链接到 jQuery。

我们的示例页面还需要一些基本的 CSS，以创建此示例所需的布局。在我们为此示例创建的`fixed-sidebar.css`样式表中，添加以下样式：

```js
header, .wrapper { width:80%; max-width:1140px; margin:auto; }
header { 
    padding-bottom:2em; border-bottom:4px solid; 
    margin-bottom:3em; 
}
header h1 { margin-top:.75em; }
article { 
    width:70%; padding-right:4%; border-right:4px solid;
    margin-right:5%; float:left; 
}
aside { width:20%; float:left; }
```

与之前一样，实际上并不需要任何这些代码，我们只是为了根据这个示例的需要布置演示页面。

## 目标完成 - 小型简报

我们添加了一个非常简单的布局来创建我们的演示页面。HTML5`<article>`填充了五个不同的 HTML5`<section>`元素，每个元素都有自己的`id`属性。稍后在项目中我们会使用这些来允许它们之间的动画导航。

在上面的代码示例中，每个`<section>`元素都是空的。但是，如果你一边跟着进行并编写示例代码，你应该用各种随机元素填充每个元素，以增加页面的长度。

在这个示例中，我们使用的元素都不重要。HTML5`<aside>`是我们将要固定的元素，但它是`<aside>`元素并不重要 - 任何元素都可以使用这种技术。

在`<aside>`元素内部是一个 HTML5`<nav>`元素。正如我之前提到的，这将使我们能够稍后添加另一个很酷的功能，但同样，并不是基本技术的必需品。任何内容都可以在要固定在原位的元素中使用。

还要注意，在 CSS 中我们根本不使用`position:fixed`。其原因很简单。具有固定位置的元素相对于整个文档而言是定位的，而不是相对于其父容器。

如果没有提供像素坐标，则渲染一个固定位置元素，其元素在页面上的位置取决于其 DOM 位置（尽管从技术上讲它仍然不在页面的正常流中）。

如果我们尝试使用我们的示例布局来做这件事，它最终会出现在外部 `.wrapper` 元素的最左边，因为在 `<article>` 元素上指定的 `float` 也会将 `<article>` 元素从正常文档流中移除。这不好。

如果提供了像素坐标，渲染引擎将解释这些坐标相对于窗口的位置，就像绝对定位元素一样。在某些情况下，指定像素坐标可能是可以接受的，但是在使用本示例中的流式布局时，设置 `<aside>` 元素的 `left` 和 `top` 样式属性所需的坐标将取决于用于查看页面的屏幕分辨率，这就是我们面临的困境，因此我们使用 jQuery 来实现它而不是简单的 CSS。

## 机密情报

为了节省创建示例布局（如本项目中使用的布局）的时间，我们可以使用诸如 Placehold It ([`placehold.it/`](http://placehold.it/)) 这样的服务，用任意尺寸的占位图像代替图像，以及 HTML Ipsum ([`html-ipsum.com`](http://html-ipsum.com)) 来填充常见 HTML 元素的 Lorem Ipsum 占位文本。

# 存储固定元素的初始位置

在我们能够将元素固定在某个位置之前，我们需要知道那个位置在哪里。在这个任务中，我们将获取我们将要固定在某个位置的 `<aside>` 元素的当前起始位置。

## 启动推进器

在 `fixed-sidebar.js` 中，我们应该从以下代码开始：

```js
$(function() {

});
```

我们可以在函数顶部缓存一些 jQuery 选中的元素，并存储固定元素的初始位置，然后我们可以在刚刚添加的函数内添加以下代码：

```js
var win = $(window),
    page = $("html,body"),
    wrapper = page.find("div.wrapper"),
    article = page.find("article"),
    fixedEl = page.find("aside"),
    sections = page.find("section"),
    initialPos = fixedEl.offset(),
    width = fixedEl.width(),
    percentWidth = 100 * width / wrapper.width();
```

## 目标完成 - 小结

我们使用了与第一个项目中相同的外部包装器。就像我之前提到的那样，这是在页面加载完成后执行代码的非常常见的方式。我们可能会在本书中的每个项目中都使用它。

然后，我们缓存我们将要引用的元素的引用，这样我们就不必一直从 DOM 中选择它们。稍后我们将在事件处理程序中查询这些元素，为了性能考虑，最好是从页面中选择一次并在我们的代码中引用保存或缓存的版本，而不是反复从页面中选择元素。

我们将引用 `window` 对象，因为我们将向其附加多个事件处理程序。稍后我们将滚动整个页面，为了实现全面的跨浏览器兼容性，我们应该选择并存储对 `<html>` 和 `<body>` 元素的引用，因为不同的浏览器使用 `<html>` 或 `<body>` 元素，所以这样涵盖了所有情况。

我们需要选择具有类名`wrapper`的元素，包含的`<article>`，所有不同的`<section>`元素，当然还有我们将在剩余代码中经常使用的`<aside>`元素。

我们还存储了固定元素的初始位置，以便我们知道要将元素固定到页面上的坐标。我们使用 jQuery 的`offset()`方法，该方法返回一个包含`top`和`left`属性的对象，显示相对于文档的当前位置，正是我们所需的。

根据周围元素应用的样式，被固定元素的`width`可能会发生变化。为了缓解这种情况，我们还使用了 jQuery 的`width()`方法来存储元素的初始`width`，该方法返回以像素表示的整数。

最后，我们还可以计算并将`width`存储为百分比。稍后当我们想要对浏览器窗口大小调整做出反应时，我们将需要知道这一点。通过将固定元素的`width`乘以`100`，然后将这个数字除以其容器的宽度，我们很容易就能计算出来，而我们再次使用 jQuery 的`width()`方法来获取容器的宽度。这也意味着固定侧边栏的`width`可以很容易地在 CSS 文件中更改，并且脚本将继续工作。

# 检测页面滚动时

我们的下一个任务是在页面滚动时检测到，并在发生滚动时将元素固定在原位。对于我们来说，通过 jQuery，检测滚动事件变得很容易，将`position`设置为`fixed`也很容易，因为有简单的 jQuery 方法可以调用来执行这些确切的操作。

## 启动推进器

在上一个任务中初始化变量之后，将以下代码直接添加到脚本文件中：

```js
win.one("scroll", function () { 
    fixedEl.css({
        width: width,
        position: "fixed",
        top: Math.round(initialPos.top),
        left: Math.round(initialPos.left)
    });
});
```

## 目标完成 - 迷你简报

我们可以使用 jQuery 的`one()`方法将事件处理程序附加到我们存储在变量中的`window`对象上。`one()`方法将在第一次检测到事件时自动解除绑定，这很有用，因为我们只需要一次将元素设置为`position:fixed`。在本示例中，我们正在寻找`scroll`事件。

当检测到事件时，我们将作为`one()`的第二个参数传递的匿名函数将被执行。在发生这种情况时，我们使用 jQuery 的`css()`方法来设置一些`style`属性。我们将元素的`width`设置为对应情况的原因是，我们的目标元素的`width`因周围元素的`float`和/或`margin`而增加。

我们将`position`设置为`fixed`，并使用在项目开始时存储在`initialPos`变量中的元素的初始位置，设置`top`和`left`样式属性。我们使用 JavaScript 的`Math.round()`方法来将`top`和`left`像素位置四舍五入为整数，这有助于避免任何与子像素舍入相关的跨浏览器问题。

# 处理浏览器窗口调整

目前，我们的 `<aside>` 元素在页面滚动时会立即固定在原地，这符合我们的需求，只要浏览器保持相同的大小。

但是，如果由于某种原因调整了窗口大小，则 `<aside>` 元素将从其固定位置掉落，并且可能会丢失在视口的边界之外。在这个任务中，我们将通过添加一个事件处理程序来修复这个问题，该处理程序监听窗口的 resize 事件。

## 启动推进器

为了保持固定元素相对于页面其余部分的正确位置，我们应该在上一任务中添加的 `one()` 方法之后直接添加以下代码：

```js
win.on("resize", function () {
    if (fixedEl.css("position") === "fixed") {
        var wrapperPos = wrapper.offset().left,
            wrapperWidth = wrapper.width(),
            fixedWidth = (wrapperWidth / 100) * percentWidth;

        fixedEl.css({
            width: fixedWidth,
            left: wrapperPos + wrapperWidth - fixedWidth,
            top: article.offset().top
        });
    }
});
```

## 目标完成 - 迷你总结

这次我们使用 jQuery 的 `on()` 方法来附加我们的事件处理程序。我们向这个方法传递两个参数；第一个是我们要监听的事件，在这个任务中是窗口的 `resize` 事件，第二个是我们希望在检测到事件时执行的函数。

我们只希望在页面已经滚动并且元素的 `position` 已经设置为 `fixed` 时重新定位和调整 `<aside>` 元素的大小，因此在我们做任何其他事情之前，我们首先检查这是否是这种情况。

如果元素的 `position` 设置为 `fixed`，我们首先使用 jQuery 的 `offset()` 方法返回的对象的 `left` 属性确定包装器元素的当前 `left` 样式属性。我们还使用 jQuery 的 `width()` 方法获取包装器元素的 `width`。

因为我们的布局是液体的，所以我们还需要调整固定元素的 `width`。在 CSS 中，我们最初将 `width` 设置为 `20%`，所以我们可以通过将容器的当前宽度除以 100，然后乘以我们在第一个任务中存储的 `percentWidth` 变量来确保它保持在其容器的 20%。

然后，我们使用 jQuery 的 `css()` 方法设置固定元素的 `width` 以及它的 `top` 和 `left` 样式属性，以确保在 `window` 调整大小时它保持在正确的位置。

# 自动滚动

此时，我们应该能够单击固定元素中添加的导航菜单中的任何链接，页面将跳转以将相应的部分带入视图。固定元素仍然固定在原地。

跳转到部分的方式相当突兀，因此在这个任务中，我们将手动将每个部分滚动到位，以便每个部分的跳转不那么突然。我们还可以对滚动进行动画处理，以获得最大的美观效果。

## 启动推进器

对于这个任务，我们应该再添加另一个事件处理程序，这次是为导航列表中的链接的 `click` 事件，然后动画滚动页面以将所选的 `<section>` 带入视野。

首先，我们可以添加一个用于滚动页面的通用函数，该函数接受一些参数，然后使用这些参数执行滚动动画。我们应该在上一任务中添加的 `one()` 方法之后直接定义该函数，使用以下代码：

```js
function scrollPage(href, scrollAmount, updateHash) {
    if (page.scrollTop() !== scrollAmount) {
        page.animate({
            scrollTop: scrollAmount
        }, 500, function () {
            if (updateHash) {
                document.location.hash = href;
            }
        });
    }
}
```

接下来，我们可以在我们的固定元素上为点击事件添加一个处理程序。这应该直接添加在我们刚刚添加的`scrollPage()`函数之后：

```js
page.on("click", "aside a", function (e) {
    e.preventDefault();

    var href = $(this).attr("href"),
        target = parseInt(href.split("#part")[1]),
        targetOffset = sections.eq(target - 1).offset().top;

    scrollPage(href, targetOffset, true);
});
```

## 目标完成 - 小结

首先我们定义了`scrollPage()`函数，它接受三个参数。第一个是`href`，第二个是一个整数，代表页面的`scrollTop`属性需要动画到的数值，第三个是一个布尔值，将告诉函数是否更新浏览器地址栏中的哈希片段。

在这个函数中，我们首先检查页面是否确实需要滚动。为了确保它需要，我们只需检查当前页面的滚动，使用 jQuery 的`scrollTop()`方法获取，是否与我们希望滚动到的数量不同。

jQuery 的`animate()`方法还接受三个参数。第一个是一个对象，其中每个键都是要动画的属性，每个值都是要将其动画到的值。在这种情况下，我们要使用传递给我们的函数的`scrollAmount`参数来动画化`scrollTop`属性。

`animate()`方法的第二个参数是动画应该运行的持续时间。它接受一个代表以毫秒为单位的持续时间的整数。我们指定为`500`，这样动画将需要半秒钟来完成。

第三个参数是一个回调函数，我们希望在动画结束后立即执行。如果我们函数中传递的`updateHash`参数设置为`true`，我们可以更新浏览器的地址栏，显示所需的`<section>`元素的`id`。

我们可以通过使用传递给我们的`scrollPage()`函数的`href`参数更新`document.location`对象的`hash`属性来实现这一点。这会更新地址栏，但因为它只是一个哈希片段，所以不会导致页面重新加载。

添加了`scrollPage()`函数后，我们随后添加了对固定元素内导航的`click`事件处理程序。我们再次使用 jQuery 的`on()`方法附加此事件，但这次我们向该方法传递了三个参数，这样可以启用事件委派。处理程序附加到我们已经存储在变量中的页面的`<body>`上。

第一个参数是我们要绑定处理程序的事件，在这种情况下是`click`事件。第二个参数是选择器；`on()`方法将过滤所有点击事件，以便只有那些来自与选择器匹配的元素的事件才会调用绑定的处理程序函数。

在这种情况下，我们只对我们的固定元素 - `<aside>`中的`<a>`元素的点击感兴趣。第三个参数是要绑定为处理程序的函数，jQuery 会自动将原始事件对象传递给它。

在这个函数内部，我们首先使用事件对象的`preventDefault()`方法停止浏览器导航到相应的`<section>`元素。

接下来，我们设置一个变量，告诉我们用户想要导航到哪个`<section>`。 在我们的事件处理程序函数中，`$(this)`对象的作用域限定为被点击的链接，因此我们可以通过使用 jQuery 的`attr()`方法获取所需的部分`id`来轻松地获取点击链接的`href`属性。 我们将其存储在名为`href`的变量中。

我们需要知道所需的`<section>`元素在页面上的位置，我们通过使用 JavaScript 的`split()`方法来分割刚刚设置的`href`变量中存储的字符串来获取它。

如果我们将`#part`指定为要拆分的字符串，则`split()`方法将返回一个包含两个项目的数组，其中第二个项目是被点击的部分号的字符串版本。 通过将此语句包装在 JavaScript 的`parseInt()`中，我们得到一个整数。 我们将此整数存储在`target`变量中。

我们设置的最后一个变量是所需`<section>`元素的偏移量。 要选择正确的`<section>`元素，我们可以使用我们在项目开始时存储的`sections`数组。

要从此数组中提取正确的元素，我们使用 jQuery 的`eq()`方法，并将其设置为刚刚保存在`target`变量中的值减去`1`。 我们需要减去`1`，因为 JavaScript 中的数组从`0`开始，但是我们的`<section>` `id`属性从`1`开始。

一旦我们获得了这些信息，我们就可以调用我们的`scrollPage()`函数，将我们刚刚计算的值传递给它，以动画形式滚动页面，以将所需的`<section>`元素带入视图。

# 恢复浏览器的后退按钮

此时，我们可以点击`<aside>`元素中的任何链接，页面将平滑滚动到页面上所需的位置。 浏览器的地址栏也将被更新。

但是，如果用户尝试使用其浏览器的返回按钮返回到先前的`<section>`，则什么也不会发生。 在此任务中，我们将修复此问题，以使返回按钮按预期工作，并且甚至可以在使用返回按钮返回到先前的`<section>`时使用平滑滚动。

## 启动推进器

我们可以通过在刚刚添加的点击事件之后直接添加另一个事件处理程序来非常容易地启用返回按钮：

```js
win.on("hashchange", function () {

    var href = document.location.hash,
        target = parseInt(href.split("#part")[1]),
        targetOffset = (!href) ? 0 : sections.eq(target - 1).offset().top;

    scrollPage(href, targetOffset, false);
});
```

## 目标完成 - 小型总结

我们再次使用 jQuery 的`on()`方法附加我们的事件，这次我们不需要使用事件委托，因此我们恢复到该方法的两个参数形式。

这次我们正在监听`hashchange`事件，与之前一样，它作为第一个参数传递，并且每当`document.location`对象的`hash`属性更改时就会发生。

在我们的处理程序函数中，作为第二个参数传递，我们设置各种变量的不同值，以便传递给`scrollPage()`函数，以执行滚动。这次我们不需要阻止浏览器的默认行为，`href`变量是使用`document.location.hash`属性设置的，因为触发事件的是返回按钮，而不是`<aside>`中的链接之一。

实际上，当点击链接时，这个处理程序也会被触发，因为链接也会更新哈希值，但在`scrollPage()`函数内的条件检查将阻止不必要地调用 jQuery 的`animate()`方法。

`target`变量的计算方式与上一个事件处理程序中的计算方式完全相同，但这次，`targetOffset`变量需要处理浏览器地址栏中没有哈希片段的情况。为了处理这一点，我们使用 JavaScript 的三元条件结构来检查刚刚定义的`target`变量是否具有假值，这将指示空字符串。如果是，我们希望只是将滚动平滑返回到零。如果不是，我们确定所需的滚动量的方式与之前一样。

现在我们应该能够加载页面，在`<aside>`元素中点击链接后滚动到页面的某个部分，然后使用浏览器的返回按钮滚动回页面顶部。

# 处理页面加载时的哈希片段

目前浏览器返回按钮的功能已经恢复，访问者可以看到地址栏中的可书签的网址。

如果页面在其中包含哈希片段的情况下被请求，页面将在加载时自动跳转到指定的`<section>`。在这部分我们将添加一些代码，检查`document.location`对象的哈希属性，如果检测到哈希，则将平滑滚动到页面对应部分。

## 启动推进器

要实现这一点，我们应该在脚本文件顶部定义起始变量后直接添加以下代码，并在监听滚动事件之前直接添加：

```js
if (document.location.hash) {

    var href = document.location.hash,
        target = parseInt(href.split("#part")[1]),
        targetOffset = sections.eq(target - 1).offset().top;

    page.scrollTop(0);
    document.location.hash = "";
    scrollPage(href, targetOffset, true);

}
```

## 目标完成 - 小型总结

在这段代码中，页面加载后将立即执行，我们首先检查`document.location`对象是否包含`hash`（或至少包含一个非空字符串的`hash`）。

如果是这样，我们获得`hash`，获取`<section>`的编号，并以与之前任务相同的方式计算距页面顶部的偏移量。然后我们将页面的`scrollTop`设置为`0`，强制浏览器滚动到页面顶部。此时我们还会移除哈希值。

最后，我们可以调用我们的`scrollPage()`函数，传入新的`href`片段，所需的滚动量，并将最后一个参数设置为`true`，以便将正确的哈希片段添加回浏览器的位置栏。所有这些都应该发生得非常快，用户不会注意到页面加载已被拦截并修改了行为。

# 任务完成

在这个项目中，我们看了一种非常简单的方法来模仿 CSS 的`position:fixed`样式，以固定一个重要的元素。只在页面开始滚动时应用固定定位的技巧简单而有效，并且是解决实际`position:fixed`在处理复杂或流动布局时的缺陷的绝佳方式。

我们看到了如何处理窗口大小调整，并添加了一个平滑滚动功能，以在页面的不同命名部分之间滚动页面。

我们还看了如何读取和写入`window`对象的`document.location.hash`属性，以及在页面加载时如何手动滚动到请求的部分。我们还修复了浏览器的后退按钮，使其与我们的平滑滚动动画配合工作。

# 你准备好全力以赴了吗？一个高手的挑战

很多时候，在我们在这个项目中使用的页面内导航中，当手动滚动到一个部分时，或者点击其中一个链接时，将导航链接显示为当前状态是很有用的。试着将这个简单但有效的补充添加到我们在本项目过程中看到的代码中。


# 第三章：一个交互式的 Google 地图

在这个项目中，我们将创建一个与 Google 最新 API 版本配合工作的高度交互式 Google 地图，以生成带有自定义覆盖层和标记、地理编码地址以及计算距离的地图。我们还将看看如何使用谷歌和 jQuery 事件处理程序的组合来保持我们的简单 UI 与地图上添加的位置同步。

# 任务简报

出于本项目的目的，我们将有一个场景，需要为一个将物品从一个地方运送到另一个地方的公司构建一个基于地图的应用程序。他们希望客户可以访问一个页面，通过点击地图上的不同区域来计算运输某物品从一个地方到另一个地方的成本，并可能下单。

我们将了解如何监听地图上的点击事件，以便可以添加标记并记录每个标记的精确位置。然后我们可以更新 UI 以显示被点击位置的实际街道地址，并允许访问者根据两个地址之间的计算距离生成报价。

## 为什么这很棒？

谷歌地图是一个很棒的 API 来构建应用程序。已经具有高度交互性和丰富的功能，我们可以在其提供的坚实基础上构建稳健且高度功能性的应用程序。谷歌提供地图数据和地图的交互性，而 jQuery 用于构建 UI——这是一个胜利的组合。

我们最终将得到的页面将类似于以下屏幕截图：

![为什么这很棒？](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_03_01.jpg)

## 你的高能目标 

该项目将分解为以下任务： 

+   创建页面和界面

+   初始化地图

+   使用自定义覆盖层显示公司总部位置

+   捕获地图上的点击事件

+   更新 UI，显示起始位置和终点位置

+   处理标记重新定位

+   考虑权重因素

+   显示预计距离和费用

## 任务清单

我们需要链接到由谷歌提供的脚本文件，以初始化地图并加载 API。我们还可以在此时创建项目中将要使用的新文件。

不用担心，我们不需要从谷歌获取 API 密钥之类的东西，这个项目可以直接通过链接使用脚本。

### 注意

谷歌地图 API 功能丰富且稳定，包含所有最知名的地图功能入口，包括街景、地理位置和导航服务。除了我们在此处使用的配置选项外，还有许多其他选项。有关更多信息，请参阅[`developers.google.com/maps/`](http://developers.google.com/maps/)上的文档网站。

首先，我们应该将模板文件的新副本保存到我们的根项目文件夹中，并将其命名为`google-map.html`。还创建一个`google-map.css`文件和一个`google-map.js`文件，并将它们分别保存在`css`和`js`文件夹中。

我们可以通过将以下`<link>`元素添加到页面的`<head>`中，直接在`common.css`的`<link>`元素后面，来链接到此示例的样式表：

```js
<link rel="stylesheet" href="css/google-map.css" />
```

### 提示

别忘了，我们每个项目都使用`common.css`，这样我们就可以专注于实际项目中需要的样式，而不用关注大多数网页所需的所有无聊的重置、浮动清除和其他常见 CSS 样式。

我们可以使用以下`<script>`元素直接在 jQuery 的`<script>`元素后面链接到 Google 的脚本文件以及我们刚刚创建的 JavaScript 文件：

```js
<script src="img/js?sensor=false">
</script>
<script src="img/google-map.js"></script>
```

在这个项目中，我们还将使用几张图片，`hq.png`和`start.png`，它们都可以在本书的附带代码下载中找到。你应该将它们复制到本地`jquery-hotshots`项目目录中的`img`目录下。我们的页面现在已经准备好进行第一个任务了。

# 创建页面和界面

在我们的第一个任务中，我们可以添加地图的不同容器，以及页面所需的初始 UI 元素。我们也可以添加一些基本的样式，将事物布局成我们想要的样子。

## 启动推进器

我们应该将以下元素添加到我们刚刚设置的`google-map.html`页面的`<body>`元素中：

```js
<div id="map"></div>
<div id="ui">
    <h1>I Am Mover</h1>
    <p>Enter the weight of your goods below and click on two 
    different places on the map to see the distance between 
    them and the cost of moving your goods.</p>
    <h3>Our charges</h3>
    <dl class="clearfix">
        <dt>Base rate (per mile)</dt>
        <dd>&pound;3</dd>
        <dt>Cost per kg per mile</dt>
        <dd>&pound;0.25</dd>
    </dl>
    <input id="weight" placeholder="Weight (kg)" />
</div>
```

为了进行一些基本的样式设置，并为初始化地图做好页面布局准备，我们可以将以下选择器和样式添加到我们刚刚创建的`google-map.css`文件中：

```js
#map { width:100%; height:100%; }
#ui { 
    width:16%; height:99.8%; padding:0 2%; 
    border:1px solid #fff; position:absolute; top:0; right:0;
    z-index:1; box-shadow:-3px 0 6px rgba(0,0,0,.5);
    background-color:rgba(238,238,238,.9); 
}
#ui h1 { margin-top:.5em; }
#ui input { width:100%; }
#ui dl { 
    width:100%; padding-bottom:.75em; 
    border-bottom:1px dashed #aaa; margin-bottom:2em; 
}
#ui dt, #ui dd { margin-bottom:1em; float:left; }
#ui dt { width:50%; margin-right:1em; clear:both; }
#ui dd { font-weight:bold; }
```

## 目标完成 - 迷你总结

在这个任务中，我们只是开始添加我们将在接下来的几个任务中正确填充的基础 HTML 元素。这是让示例页面开始运行并让项目启动的一个略微无聊但有些必要的第一步。

我们添加的第一个元素是 Google Maps API 将渲染地图瓦片到其中的容器。我们给它一个`id`为`map`，以便可以有效地选择它，但它一开始是完全空的。

下一个元素是各种 UI 元素的容器，示例需要它。它也有一个`id`为`ui`，以便我们的脚本可以轻松选择它，并且用 CSS 样式添加。

### 提示

**使用 ID 进行样式设置**

避免使用 ID 选择器添加 CSS 样式正逐渐成为一种普遍的最佳实践，例如**CSSLint**等工具建议不要使用它。

尽管使用类、元素或属性选择器的理由很有说服力，但为了简单起见，我们将在本书中的一些项目中使用它们。

CSSLint 是一个开源的 CSS 代码质量工具，它对源代码进行静态分析，并标记可能是错误或可能会给开发人员带来问题的模式。有关更多信息，请参见[`csslint.net/`](http://csslint.net/)。

在界面容器中，我们有一个虚构公司的名称，一些使用页面的基本说明，一个不同费用的列表，以及一个`<input>`元素用于输入权重。

我们在此任务中添加的大多数 CSS 仅仅是装饰性的，并且特定于此示例。如果需要不同的外观和感觉，它很容易会完全不同。我们已经让地图容器占据了页面的全宽度和高度，并且设计了界面，使其似乎漂浮在页面的右侧。

# 初始化地图

让一个可缩放和可平移的交互式 Google 地图运行起来只需要极少量的代码。在这个任务中，我们将添加这段代码，并设置稍后在脚本中将使用的一些变量。

## 为起飞做准备

在这个任务中，我们将初始化配置地图所需的变量，并调用 Google 地图 API。我们应该从添加标准 jQuery 封装到之前创建的空白 `google-map.js` 文件开始：

```js
$(function () {
    //all other code in here...
});
```

记住，`$(function () { … });` 结构是 jQuery 的 `document.ready` 事件处理程序的快捷方式。

## 启动推进器

在我们刚刚添加的封装器中，我们应该添加以下代码：

```js
var api = google.maps,
    mapCenter = new api.LatLng(50.91710, -1.40419), 
    mapOptions = {
        zoom: 13,
        center: mapCenter,
        mapTypeId: api.MapTypeId.ROADMAP,
        disableDefaultUI: true
    },
    map = new api.Map(document.getElementById("map"), mapOptions),
    ui = $("#ui"),
    clicks = 0,
    positions = [];
```

## 目标完成 - 迷你简报

在这个任务中，我们首先创建了一些需要初始化地图的变量。我们将在整个代码中处理 `google.maps` 命名空间，因此我们设置的第一个变量是为了方便起见而设置的顶级两个命名空间的内容。

拥有一个本地范围的副本，可以直接访问我们想要使用的实际 API，这将使我们的代码稍微更有效率，因为我们的代码更容易解析一个变量。而且，一开始输入时也会快得多。

Google 地图 API 使用的所有属性和方法都是命名空间的。它们都位于 `maps` 命名空间中，而 `maps` 命名空间本身位于 `google` 命名空间中。Google 在许多不同应用程序中使用了如此庞大的代码库，因此使用命名空间将所有内容隔离并组织起来是有意义的。

### 注意

有关 JavaScript 命名空间复杂性的深入讨论，请参阅 JavaScript 专家 *Addy Osmani* 的关于这个主题的优秀文章（[`addyosmani.com/blog/essential-js-namespacing/`](http://addyosmani.com/blog/essential-js-namespacing/)）。

接下来，我们存储我们想要将地图居中显示的纬度和经度。这是使用 Google 地图 API 的 `LatLng()` 方法完成的，该方法接受两个参数，纬度和经度值，并返回一个用于其他 API 方法的 `LatLng` 对象。请注意我们如何使用本地的 `api` 变量调用 `LatLng` 构造函数。

然后，我们可以创建一个对象字面量，其中包含我们的地图将需要的一些配置选项。这些选项包括缩放级别、地图应该居中的位置、地图类型，以及一个禁用默认地图类型和缩放/平移控件的选项。我们可以使用 `mapCenter` 中包含的 `LatLng` 对象作为 `center` 配置选项。

然后，我们使用地图 API 的`Map()`构造函数创建一个新的地图实例。这个函数接受两个参数：第一个是地图应该呈现的 DOM 元素，第二个是包含我们想要设置的配置选项的对象文字。

第一个参数需要一个真正的 DOM 元素，而不是一个用 jQuery 包装的 DOM 元素。因此，虽然我们可以使用 jQuery 从页面中选择元素，然后提取原始的 DOM 元素，但更有效的方法是使用 JavaScript 的原生`getElementById()`函数来检索我们在上一个任务中添加到页面中的地图容器，并将其传递给`Map()`构造函数。

接下来，我们缓存一个用于 UI 容器的 jQuery 选择器，以便我们可以重复地从页面中访问它，而不必每次都从 DOM 中选择它，并定义一个名为`clicks`的变量，我们将用它来记录地图被点击的次数。我们需要在顶层函数范围内定义它，以便我们可以在代码中后续的点击处理程序中引用它。

最后，我们在变量`positions`中添加一个空的数组文字，以便在需要存储地图上不同区域时稍后填充。数组需要在顶层函数范围内，以便我们在后面的代码中从不同的事件处理程序中访问它。

# 显示公司总部及自定义叠加层

在这个任务中，我们将在地图上直接放置公司总部，通过添加一个自定义标记和叠加层，提供一些关于公司的基本信息，也许还有场所的图片。

## 准备升空

在这个任务中，我们将涵盖以下子任务：

+   在地图上添加一个标记

+   添加一个包含有关公司信息的隐藏元素

+   在新标记被单击时添加一个自定义叠加层以显示公司信息

+   在标记被单击时添加一个单击处理程序来显示叠加层

## 启动推进器

在上一个任务中添加的变量后面，可以通过以下简单的代码块实现在地图上添加自定义标记：

```js
var homeMarker = new api.Marker({
    position: mapCenter,
    map: map,
    icon: "img/hq.png"
});
```

要为我们的新标记创建信息叠加层，或者使用正确的谷歌术语，信息窗口，首先应该添加一个包含我们希望在叠加层中显示内容的 HTML 元素。我们可以在 UI 容器后面直接添加以下新的元素集合到`google-map.html`中：

```js
<div id="hqInfo">
    <img class="float-left" src="img/140x100"/>
    <h1>I Am Mover</h1>
    <p>This is where we are based.</p>
    <p>Call: 0123456789</p>  
    <p>Email: info@i-am-mover.com</p>
</div>
```

### 提示

我们再次使用`placehold.it`服务，这样我们就不必为这个示例内容担心获取或创建实际的图像。在快速创建原型时，这是一个很好的服务。

为了告诉地图新的信息窗口，我们可以使用以下代码，在`google-map.js`中`homeMarker`代码后直接添加：

```js
var infoWindow = new api.InfoWindow({
    content: document.getElementById("hqInfo")
});
```

我们还需要一些额外的 CSS 来样式化信息窗口的内容，并在需要时隐藏它。将以下代码添加到`google-map.css`的底部：

```js
body > #hqInfo { display:none; }
#hqInfo { width:370px; }
#hqInfo h1 { margin-bottom:.25em; line-height:.9em; }
#hqInfo p { margin-bottom:.25em; }
```

最后，我们可以添加一个简单的点击处理程序，使用以下代码，在刚刚在`google-map.js`中添加的`infoWindow`变量之后添加：

```js
api.event.addListener(homeMarker, "click", function(){
    infoWindow.open(map, homeMarker);
});
```

## 目标完成 - 小结

首先，我们定义了一个新的标记，使用的是 Google 的`Marker()`构造函数。这个函数接受一个参数，即定义标记不同属性的对象字面量。

我们将标记的`position`设置为地图的中心，以简化操作，尽管在定义其他标记时，您会看到任何`LatLng`对象都可以使用。我们还应该定义标记所属的地图，我们将其设置为包含地图实例的`map`变量。要指定用作标记的图像，我们可以提供一个相对路径的字符串格式给`icon`选项。

然后，我们向页面添加了一个新的容器，其中包含我们想要在自定义信息窗口中显示的信息。这里的内容并不重要；重要的是技术。我们还为信息窗口的内容添加了一些额外的样式。

为了将信息窗口添加到我们的地图实例中，我们使用了 Google 的`InfoWindow()`构造函数。这个方法也接受一个参数，再次是一个对象字面量，其中包含我们希望设置的选项。在这个示例中，我们只是将`content`选项设置为包含我们刚刚添加到页面上内容的元素。

这应该是一个实际的 DOM 元素，因此我们使用 JavaScript 的`document.getElementById()`来获取元素，而不是使用 jQuery 进行选择。

最后，我们使用 Google 的`addListener()`方法向地图添加了一个事件处理程序。该方法接受要附加事件处理程序的元素作为第一个参数，本例中为我们添加的标记；要监听的事件作为第二个参数；以及处理事件的回调函数作为第三个参数。该方法的签名与其他常见 JavaScript 库中找到的事件处理方法非常相似，尽管与 jQuery 中添加事件处理程序的方式略有不同。

在作为`addListener()`方法的第三个参数传递的匿名函数中，我们所做的就是调用我们信息窗口的`open()`方法。`open()`方法接受两个参数；第一个是信息窗口所属的地图，第二个是信息窗口添加到的位置，我们将其设置为我们的标记。

在这一点上，我们应该能够在浏览器中运行页面，单击我们的自定义标记，并将隐藏的`<div>`的内容显示在信息窗口中，如下面的截图所示：

![目标完成 - 小结](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_03_02.jpg)

# 捕获地图上的点击事件

在这个任务中，我们需要为地图添加一个点击处理程序，以便访问者可以设置其交通旅程的起点和终点。

## 启动推进器

首先，我们需要添加当地图被单击时将执行的函数。在上一个任务中添加的监听器之后，直接添加以下函数表达式：

```js
var addMarker = function (e) {

    if (clicks <= 1) {

        positions.push(e.latLng);

        var marker = new api.Marker({
            map: map,
            position: e.latLng,
            flat: (clicks === 0) ? true : false,
            animation: api.Animation.DROP,
            title: (clicks === 0) ? "Start" : "End",
            icon: (clicks === 0) ? "img/start.png" : "",
            draggable: true,
            id: (clicks === 0) ? "Start" : "End"
        });

        api.event.trigger(map, "locationAdd", e);

    } else {
        api.event.removeListener(mapClick);
        return false;
    }
}
```

然后，为地图上的单击附加一个触发此函数的监听器，我们可以在其后直接添加以下代码：

```js
var mapClick = api.event.addListener(map, "click", addMarker);
```

## 目标完成 - 小型简报

首先，我们添加了每次单击地图时将执行的函数。该函数会自动通过`addListener()`方法传递事件对象，其中包含了在地图上单击的坐标的`latLng`对象。

函数中的第一件事是将事件对象的`latLng`属性存储在我们的`positions`数组中。我们需要知道单击了哪两个位置，因此将它们都添加到我们的`positions`数组中很有用，并且该数组可以在整个代码中可见。

然后我们检查之前定义的`clicks`变量是否小于或等于`1`。如果是，我们继续使用 Google 的`Marker()`构造函数创建一个新的标记。之前在添加标记显示公司总部时我们已经使用了该构造函数，但这次我们设置了一些不同的属性。

我们将`map`属性设置为我们的地图实例，并将标记的`position`设置为事件对象中包含的`latLng`对象，该对象将匹配在地图上单击的点。

我们将为第一次单击使用绿色标记图像，表示旅程的起始点。我们将使用的图像已经有了自己的阴影，因此当添加第一个标记时，我们可以使用 JavaScript 三元运算符确定是否`clicks`等于`0`，然后将`flat`属性设置为`true`以禁用 Google 否则会添加的阴影。

我们可以轻松地添加一个漂亮的掉落动画，以使当地图被单击时新的标记掉落到位。动画采用弹跳的缓动效果，视觉上也很愉悦。动画使用`animation`属性进行设置，该属性使用`Animation` API 设置为`DROP`。

我们还可以设置标记的`title`，当光标悬停在上面时会显示，使用`title`属性。同样，我们使用一个简单的 JavaScript 三元运算符根据`clicks`变量的值设置`Start`或`End`字符串。

我们使用`icon`属性指定用于起始标记的图像的路径。当`clicks`不等于`0`时，我们只指定一个空字符串，这会导致添加默认的红色标记。

我们还将`draggable`属性设置为`true`，以使标记可拖动。这将允许用户根据需要修改旅程的起始位置或终点位置。稍后我们可以添加处理这一功能的代码。

接下来，我们可以使用谷歌的`event`API 来触发一个自定义事件。我们使用`trigger()`方法，指定`map`实例作为事件源对象，`locationAdd`作为我们自定义事件的名称，并将我们在`addMarker()`函数中使用的事件对象（存储在`e`中）作为参数传递给可能正在监听我们自定义事件的任何处理程序。我们在下一节中添加对此事件的处理程序。

最后，我们可以在标记上设置一个唯一的`id`属性，以便我们可以区分每个标记。当我们想要在标记拖动后更新我们的 UI 时，我们会用到这一点，稍后我们会讨论这一点。

这是我们在`clicks`变量仍小于或等于`1`的情况下想要做的一切。我们`addMarker()`函数中外部条件分支的第二个分支处理`clicks`大于`1`的情况。

在这种情况下，我们知道地图已经被点击了两次，所以当这种情况发生时，我们希望停止监听地图上的点击事件。我们可以使用`event`API 的`removeListener()`方法解除绑定我们的处理程序。该方法只需一个对`addListener()`方法返回的`eventListener`的引用。

当我们将地图上的点击事件绑定到我们的`addMarker`函数时，我们将返回的内容存储在`mapClick`变量中，这是传递给`removeListener()`方法的内容。

在这一点上，我们应该能够在浏览器中运行页面，并通过单击不同位置来向地图添加新标记。

## 机密情报

在这个任务中，我们使用了**函数表达式**，通过将事件处理程序分配给一个变量，而不是更熟悉的**函数声明**。这通常被认为是一个好习惯，虽然在这种情况下不是必需的，但养成这种习惯肯定是一个好习惯。想要全面理解为什么函数表达式通常比函数声明更好，请参阅*John Resig*的博客文章[`ejohn.org/blog/javascript-as-a-first-language/`](http://ejohn.org/blog/javascript-as-a-first-language/)。

# 使用起点和终点位置更新 UI

一旦两个标记已添加到地图上，我们希望在页面右侧的 UI 侧边栏中显示它们的位置，以便在计算行程费用时使用。

我们将希望显示每个点击位置的完整街道地址，并添加一个按钮，触发基于访问者在地图上选择的位置计算报价。

## 为起飞做准备

在上一个任务中，我们使用了谷歌的`trigger()`方法，以便在每次通过点击向地图添加新标记时触发一个自定义事件。在这个任务中，我们将为该自定义事件添加一个处理程序。

到目前为止，在这个项目中，我们几乎完全使用了谷歌的地图 API，除了在代码的其余部分中添加了最初的`document.load`包装器之外，几乎没有使用 jQuery。在项目的这一部分，我们将纠正这一点，启动 jQuery 来更新我们的用户界面。

## 启动推进器

我们的自定义 `locationAdd` 事件的处理程序应该如下所示，可以直接添加到上一个任务的 `mapClick` 变量后面：

```js
api.event.addListener(map, "locationAdd", function (e) {

    var journeyEl = $("#journey"),
        outer = (journeyEl.length) ? journeyEl : $("<div>", {
            id: "journey"
        });

    new api.Geocoder().geocode({
        "latLng": e.latLng }, 
        function (results) {

            $("<h3 />", {
                text: (clicks === 0) ? "Start:" : "End:"
            }).appendTo(outer);
            $("<p />", {
                text: results[0].formatted_address,
                id: (clicks === 0) ? "StartPoint" : "EndPoint",
                "data-latLng": e.latLng
            }).appendTo(outer);

            if (!journeyEl.length) {
                outer.appendTo(ui);
            } else {
                $("<button />", {
                    id: "getQuote",
                    text: "Get quote"
                }).prop("disabled", true).appendTo(journeyEl);
            }

            clicks++;
        });
});
```

因为我们将向页面添加一些新元素，所以我们还需要更新这个项目的样式表。在 `google-map.css` 的底部添加以下新样式：

```js
#journey { margin-top:2em; }
#journey h3 { margin-bottom:.25em; }
```

## 目标完成 - 小型总结

我们以与添加点击事件相同的方式为我们的自定义 `locationAdd` 事件添加事件处理程序，使用 Google 的 `addListener()` 方法。

在事件处理程序中，我们首先定义了一些变量。第一个是一个缓存的 jQuery 对象，表示显示起始点和终点的元素。

然后我们设置的下一个变量是两者之一。如果我们将第一个变量设置为 jQuery 对象的长度，我们知道页面上存在行程元素，所以我们只是存储对它的引用。如果它不存在，我们将创建一个新元素用作行程元素，并将其 `id` 设置为 `journey`。

当地图首次被点击时，行程元素不存在并将被创建。第二次点击地图时，该元素将存在，因此它将从页面中选择而不是被创建。

接下来我们使用 Google 的 `Geocoder()` API 的 `geocode()` 方法，它允许我们对 `latLng` 对象进行逆地理编码以获取街道地址。这个方法有两个参数。第一个是配置对象，我们可以用它来指定我们想要转换的 `latLng` 对象。

第二个参数是一个回调函数，一旦地理编码完成就会执行。这个函数会自动传递一个包含地址的 `results` 对象。

在这个回调函数中，我们可以使用 jQuery 创建新元素来显示地址，然后将它们附加到行程元素上。完整的街道地址在 `results` 对象的 `formatted_address` 属性中找到，我们可以将其设置为新元素之一的文本。我们还可以在此元素上设置一个 `id` 属性，以便在需要时可以轻松地通过编程选择它，并使用自定义的 `data-latLng` 属性存储位置的 `latLng` 对象。

`results` 对象还包含有关地址的一系列其他有用属性，因此一定要在您喜爱的基于浏览器的开发者工具包的对象浏览器中查看它。

如果行程元素不存在，我们可以将其附加到 UI 中以显示位置的地址。如果它存在，我们知道这是第二次点击，然后可以创建一个新的 `<button>`，该按钮可用于根据两个位置之间的距离生成报价。

我们使用 jQuery 的 `prop()` 方法禁用 `<button>` 元素来设置 `disabled` 属性。当 UI 中的 `<input>` 添加了重量后，我们可以稍后启用按钮。

一旦我们在 UI 中添加了显示行程起点和终点的新元素，我们就可以增加 `clicks` 变量，以便我们可以跟踪添加了多少个标记。

现在，当我们运行页面并点击地图两次以添加两个标记时，我们点击的点的地址应该显示在页面右侧的 UI 区域中。现在，我们还应该看到红色的结束标记，并且现在由于增加了 `clicks` 变量，我们只能添加两个标记。

# 处理标记重新定位

我们已经使我们的地图标记可拖动，因此我们需要处理标记拖动后的地址更改。这个任务将展示如何轻松完成。这只需要两个步骤：

+   将每个标记绑定到 `dragend` 事件上

+   为事件添加处理函数

## 启动推进器

首先，当创建标记时，我们需要将每个标记绑定到 `dragend` 事件上。为此，我们应该在 `addMarker()` 函数中添加以下突出显示的代码行，直接放在标记构造函数之后：

```js
var marker = new api.Marker({
    map: map,
    position: e.latLng,
    flat: (clicks === 0) ? true : false,
    animation: api.Animation.DROP,
    title: (clicks === 0) ? "Start" : "End",
    icon: (clicks === 0) ? "img/start.png" : "",
    draggable: true,
    id: (clicks === 0) ? "start" : "end"
});

api.event.addListener(marker, "dragend", markerDrag);

```

接下来，我们应该添加 `markerDrag()` 函数本身。这可以直接放在我们在上一个任务中添加的 `locationAdd` 处理程序之后：

```js
var markerDrag = function (e) {
    var elId = ["#", this.get("id"), "Point"].join("");

    new api.Geocoder().geocode({ 
        "latLng": e.latLng 
    }, function (results) {
        $(elId).text(results[0].formatted_address);
    });
};
```

## 目标完成 - 小型总结

在这个任务中，我们首先更新了 `addMarker()` 函数，将每个新的标记绑定到 `dragend` 事件上，该事件将在标记停止拖动时触发。我们将标记指定为 Google 的 `addListener()` 方法的第一个参数，该方法是要绑定到事件的对象。事件的名称 `dragend` 被指定为第二个参数，`markerDrag` 被指定为将处理事件的函数的名称。

然后，我们添加了 `markerDrag()` 作为函数表达式。因为它是一个事件处理程序，所以它将自动传递给事件对象，该对象再次包含我们需要传递给 `Geocoder()` 的 `latLng`。

在处理程序内，我们首先设置一个新变量，它将用作我们想要更新的 UI 元素的选择器。为了性能原因，我们使用 `array.join()` 技术来连接字符串，而不是将字符串连接在一起。我们连接的数组中的第一个和最后一个项目只是文本。

第二个项目将是一个字符串，其中包含 `start` 或 `end`，这取决于拖动了哪个标记。在我们的事件处理程序内部，这指的是标记，因此我们可以使用它获取我们在创建每个标记时添加的自定义 `id` 属性，从而允许我们更新 UI 中的正确元素。

一旦构造了选择器，我们就可以像之前一样使用 Google 的 `geocode()` 方法来获取街道地址，这将给我们带来标记拖动后的新地址。

在 `geocode()` 的回调函数内，我们使用刚刚创建的选择器来选择 UI 中的 `<p>` 元素，并将其文本内容更新为新的地理编码地址。

现在当我们查看页面时，我们应该能够像以前一样将标记添加到地图中，然后拖拽它们并在页面右侧的 UI 区域中看到新的地址。

# 考虑到重量

现在我们有了两个地址——旅程的起点和终点标记。访客现在只需要输入一个重量，我们就能计算并显示距离和费用。

## 启动推进器

在这项任务中，我们所需要做的就是为 UI 区域中的`<input>`元素添加一个处理程序，这样一旦输入了重量，`<button>`就会变得可点击。我们可以通过以下代码实现这一点，直接添加到上一个任务中的`markerDrag()`函数之后：

```js
$("#weight").on("keyup", function () {
    if (timeout) {
        clearTimeout(timeout);
    }

    var field = $(this),
        enableButton = function () {
            if (field.val()) {
                $("#getQuote").removeProp("disabled");
            } else {
                $("#getQuote").prop("disabled", true);
            }
        },
        timeout = setTimeout(enableButton, 250);
});
```

## 目标完成-迷你总结

我们可以使用 jQuery 的`on()`方法为用户生成的`keyup` DOM 事件添加事件处理程序。现在使用`on()`方法是在 jQuery 中附加事件处理程序的标准方法。旧的方法，如`live()`或`delegate()`现在已被弃用，不应再使用。

在事件处理程序内部，我们首先检查是否设置了一个超时，如果设置了，就清除它。

然后我们缓存了`<input>`元素的选择器，以便我们可以在`enableButton()`函数中看到它。我们再次添加`enableButton()`函数，这次是作为函数表达式。

这个函数的作用只是检查`<input>`元素是否有值，如果有，我们使用 jQuery 的`prop()`方法将`disabled`属性设置为`false`。如果没有值，我们再次通过将`disabled`属性设置为`true`来禁用它。最后，我们使用 JavaScript 的`setTimeout()`函数设置了一个超时，将`enableButton()`函数作为第一个参数传递给它。我们将`250`，或四分之一秒，作为超时长度。超时存储在`timeout`变量中，准备好在下次函数被执行时检查。

## 机密情报

我们在这里使用超时的原因是为了限制`enableButton()`函数被执行的次数。每输入一个字符后，函数就会被调用。

四分之一秒的延迟几乎是难以察觉的，但如果有人快速在字段中输入了一个长数字，它就会大大减少函数运行的次数。在函数内部，我们从页面中选择一个元素并创建一个 jQuery 对象。这并不太过于密集，而且在这个例子中我们可能甚至不需要担心它。但像这样使用超时是一个健壮的解决方案，可以帮助在频繁触发的事件处理程序内执行更加密集的操作时提供帮助。

我们本来可以只使用 jQuery 的`one()`方法来附加一个事件处理程序，它只是简单地启用`<button>`，然后自行删除。但是，这样就不允许我们在字段中输入的数字被移除后再次禁用`<button>`。

# 显示预计距离和费用

我们在这个项目中的最后一个任务是获取两个标记之间的距离并计算旅程的成本。一旦计算出来，我们可能也应该向访问者显示结果。

## 启动推进器

首先，我们应该为我们的`<button>`附加一个点击事件处理程序。在我们在上一个任务中添加的`keyup`事件处理程序之后，直接添加以下代码：

```js
$("body").on("click", "#getQuote", function (e) {
    e.preventDefault();

    $(this).remove();
});
```

接下来，我们可以获取两点之间的距离。在我们刚刚添加的`remove()`方法之后（但仍在点击处理程序函数内部），添加以下代码：

```js
new api.DistanceMatrixService().getDistanceMatrix({
    origins: [$("#StartPoint").attr("data-latLng")],
    destinations: [$("#EndPoint").attr("data-latLng")],
    travelMode: google.maps.TravelMode.DRIVING,
    unitSystem: google.maps.UnitSystem.IMPERIAL
}, function (response) {

});
```

现在我们只需要计算并显示成本，我们可以通过添加以下代码到我们刚刚添加的空回调函数来完成。首先我们可以添加我们需要的变量：

```js
var list = $("<dl/>", {
        "class": "clearfix",
        id: "quote"
    }),
    format = function (number) {
        var rounded = Math.round(number * 100) / 100,
            fixed = rounded.toFixed(2);

        return fixed;
    },
    term = $("<dt/>"),
    desc = $("<dd/>"),
    distance = response.rows[0].elements[0].distance,
    weight = $("#weight").val(),
    distanceString = distance.text + "les",
    distanceNum = parseFloat(distance.text.split(" ")[0]),
    distanceCost = format(distanceNum * 3),
    weightCost = format(distanceNum * 0.25 * distanceNum),
    totalCost = format(+distanceCost + +weightCost);
```

接下来我们可以生成用于显示计算出的数字的 HTML 结构：

```js
$("<h3>", {
    text: "Your quote",
    id: "quoteHeading"
}).appendTo(ui);

term.clone().html("Distance:").appendTo(list);
desc.clone().text(distanceString).appendTo(list);
term.clone().text("Distance cost:").appendTo(list);
desc.clone().text("£" + distanceCost).appendTo(list);
term.clone().text("Weight cost:")
            .appendTo(list);

desc.clone().text("£" + weightCost).appendTo(list); term.clone().addClass("total").text("Total:").appendTo(list);
desc.clone().addClass("total")
            .text("£" + totalCost)
            .appendTo(list);

list.appendTo(ui);
```

最后，我们可能应该为我们刚刚创建并添加到页面中的新元素添加一些额外的样式。在`google-map.css`的底部，添加以下新样式：

```js
#quoteHeading { 
    padding-top:1em; border-top:1px dashed #aaa; 
    margin-top:1em;
}
#quote dt { margin-right:0; }
#quote dd { width:50%; }
#quote .total { 
    padding-top:.5em; border-top:1px dashed #aaa; 
    margin-bottom:0; font-size:1.5em; 
}
```

## 目标完成 - 小结

我们首先使用 jQuery 的`on()`方法将点击事件处理程序绑定到页面的`body`上。这次我们使用了该方法的三个参数形式，其中第一个参数仍然是事件的名称，第二个参数是用于筛选事件的选择器，第三个参数是事件发生时触发的函数。

JavaScript 中的事件会通过它们的容器冒泡，并且当事件到达`body`时，它将被第二个参数用作筛选器过滤，并且只有当它是由与选择器匹配的元素分派时，函数才会被执行。在这个示例中，只有由`<button>`分派的事件才会触发该函数。

使用这种形式的`on()`方法为我们提供了一种使用强大的事件委托的方法，这使我们能够为可能存在也可能不存在的元素绑定事件。

在处理程序函数中，我们首先阻止了浏览器的默认行为。因为页面上没有`<form>`，所以不应该有任何默认行为，因此`<button>`没有什么可提交的。但是如果有人试图在一个通常包含页面上大多数甚至所有元素的`<form>`的 ASPX 页面上运行这个，它可能会以意想不到的方式行事。除非绝对必要，否则应始终使用`preventDefault()`。

然后我们从页面中移除了`<button>`。请注意，尽管事件处理程序绑定到了`<body>`，但处理程序函数内部的`this`对象仍指向触发事件的`<button>`元素。

然后我们使用了 Google 的另一个 API - `DistanceMatrixService()`，它允许我们在地图上计算两个或多个点之间的距离。因为我们不需要引用`DistanceMatrixService()`构造函数返回的对象，所以我们可以直接将`getDistanceMatrix()`方法链接到它上面。

这个方法有两个参数，第一个参数是一个配置对象，第二个参数是一个方法返回时执行的回调函数。回调函数会自动传入一个包含响应的对象。

我们使用第一个参数来设置几个配置选项。`origins`和`destinations`选项都采用了数组的形式，其中每个数组中的每个项目都是一个`latLng`对象。我们可以使用自定义的`data-latLng`属性，它在显示地址时设置，很容易地获取这两个标记的`latLng`对象。

我们还将`travelMode`选项设置为通过道路行驶的距离，使用`google.maps.TravelMode.DRIVING`常量，并将`unitSystem`选项设置为`google.maps.UnitSystem.IMPERIAL`，以获得英里而不是公里的距离，除了因为我是英国人，习惯使用英里之外，并没有其他原因。

我们提供的回调函数会自动传入一个结果对象，其中包含了距离矩阵返回的结果。回调函数的前半部分涉及创建变量和计算值。函数的后半部分处理显示已计算的信息。

我们首先创建一个新的`<dl>`元素，并给它一个`class`，这是在`common.css`样式表中需要使用的，以及一个`id`属性，主要用于装饰性样式。然后我们添加一个简单的函数表达式，接收一个数字作为参数，对其四舍五入，然后将其修正为两位小数，最后返回它。我们将使用这个函数来确保我们的财务数字符合要求的格式。

我们还创建了一个新的`<dt>`元素和一个新的`<dd>`元素，可以根据需要克隆多次，而无需反复创建新的 jQuery 实例，然后使用 jQuery 的`val()`方法存储在重量文本字段中输入的值。

接下来，我们从传递给回调函数的对象中提取`distance`属性。它的结构可能看起来复杂，因为我们实际上感兴趣的对象被埋在一个多维数组中，但正如方法的名字所暗示的，它能够返回多个起点和目的地的复杂结果矩阵。

在此之后，我们连接一个字符串，其中包括我们刚刚存储的`distance`对象的`text`属性和完整的单词`miles`。距离矩阵以`mi`的形式返回英里的结果，因此我们在值的末尾添加字符串`les`。

然后我们通过在英里数量和字母`mi`之间进行拆分来获取数字距离。JavaScript 的`split()`函数会返回一个包含字符串部分的数组，该数组包含了拆分字符的前端，但不包括拆分字符和拆分字符后的部分。我们只对数组中的第一个项目感兴趣，并且使用 JavaScript 的`parseFloat()`函数来确保这个值绝对是一个数字而不是一个字符串。

现在我们有足够的信息来实际计算旅程的费用了。我们指定了每英里的费用为 £3，所以我们将距离乘以 `3`，然后将结果传递给我们的`format()`函数，以便数字的格式正确。

我们还可以通过非常类似的方式计算每千克每英里的费用，首先将重量乘以每千克的成本，然后乘以距离。再次将这个数字传递给我们的`format()`函数。然后，我们可以通过将这两个数字相加来计算总费用。我们一直在使用的数字变成了字符串。为了解决这个问题，我们仍然可以使用我们的`format()`函数，但是我们需要使用`+`字符作为我们要添加的每个值的前缀，这将强制它们成为数字而不是字符串。

一旦我们创建了要显示的图形，我们就可以创建我们需要用来显示它们的新元素，首先是一个漂亮的标题，以帮助澄清我们正在添加到 UI 的新信息集。

然后我们可以创建包含每个标签和图形的`<dt>`和`<dd>`元素的克隆。一旦这些被创建，我们就将它们附加到我们创建的`<dl>`元素上，然后最终将新列表作为一个整体附加到 UI 上，如下图所示：

![目标完成 - 小结](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_03_03.jpg)

## 机密情报

机敏的你会注意到，我们在这个例子中使用的数值舍入解决方案并不那么健壮，并且不会像真实处理实际货币所需的那样准确（或正确地）舍入所有分数。

JavaScript 不像其他一些语言那样优雅地处理浮点运算，因此创建一个完美的舍入系统，100% 正确地舍入是超出了本书范围的。

对于那些感兴趣的人，stackoverflow 网站上发布了一些极具启发性的关于 JavaScript 货币格式化的问题的答案。例如，参见：[`stackoverflow.com/questions/149055/how-can-i-format-numbers-as-money-in-javascript`](http://stackoverflow.com/questions/149055/how-can-i-format-numbers-as-money-in-javascript)。

# 任务完成

在这个项目中，我们涵盖了大量的 Google 和 jQuery 功能。具体来说，我们研究了以下主题：

+   使用`Marker()`和`InfoWindow()`构造函数将标记和覆盖物添加到地图上。

+   对地图驱动事件的反应，比如点击标记或标记拖动。事件处理程序使用`google.maps`API 的`addListener()`方法附加。我们还看到如何使用`trigger()`方法触发自定义事件。

+   使用 Google 的服务来操作地图生成的数据。我们使用的服务是`Geocoder()`，用于反向地理编码地图上每个点击的点的`latLng`，以获取其地址，以及`DistanceMatrixService()`，用于确定点之间的距离。

+   利用 jQuery 的事件功能，使用`on()`方法添加标准事件和委托事件，以便检测 UI 的不同部分与之交互的情况，比如点击`<button>`或输入`<input>`。

+   使用 jQuery 强大的 DOM 操作方法来更新 UI，包括地址和报价。我们使用了一系列这些方法，包括`clone()`，`html()`，`text()`和`prop()`，既选择又创建新元素。

# 你准备好全力以赴了吗？一个火热的挑战

在这个例子中，访客只能生成一份报价。一旦点击`getQuote` `<button>`，结果就会显示，不再允许进一步交互。为什么不在生成报价时添加一个重置按钮到 UI？访客可以清除报价和地图上的标记，从头开始。
