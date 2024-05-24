# jQuery2 动画技术入门指南（一）

> 原文：[`zh.annas-archive.org/md5/71BE345FA56C4A075E859338F3DCA6DA`](https://zh.annas-archive.org/md5/71BE345FA56C4A075E859338F3DCA6DA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

jQuery 是一个跨浏览器的 JavaScript 库，旨在简化 HTML 的客户端脚本编写，并且是当今最流行的 JavaScript 库。利用 jQuery 提供的功能，开发人员能够创建动态网页。这本书将作为您在 Web 应用程序中创建动画和高级特效的资源，通过遵循其中易于理解的步骤。

*jQuery 2.0 动画技术初学者指南* 将使您能够掌握 jQuery 中的动画技术，以生成响应您访问者交互的流畅且具有吸引力的界面。您将学会使用 jQuery 创建引人入胜和有效的网页动画所需的一切。该书使用许多示例，并解释了如何使用简单的、逐步的初学者指南方法创建动画。

本书提供了各种示例，逐渐增强读者在使用 jQuery API 中创建令人惊叹的动画方面的知识和实践经验。该书首先解释了动画如何使您的用户界面具有交互性和吸引力。它解释了用于使正在动画化的元素出现或消失的各种方法。它提供了一套步骤，以创建简单的动画并显示淡入淡出的动画。

你可以之后学习如何通过链接不同的效果来制作复杂的动画，以及如何停止当前正在运行的动画。你将了解如何滑动动画元素，并学会创建复杂和专业化的自定义动画。

您将学习如何获取和设置 jQuery UI——jQuery 的官方用户界面库。本书将告诉您如何为页面的背景图像设置动画，并教您如何根据鼠标指针的移动使图像以特定方向和速度滚动。

# 本书涵盖的内容

第一章，*入门*，涵盖了包括下载 jQuery 和设置开发区域在内的基础知识，Web 上动画的简要历史，何时何地不要使用动画，动画如何增强界面以及 jQuery 提供的动画方法。还介绍了动画的基本示例。

第二章，*图像动画*，使用简单的方法创建图像幻灯片。然后我们在幻灯片中构建功能，留下一个值得您下一个开发项目使用的脚本。

第三章，*背景动画*，带领我们穿越创建动态背景图像和背景颜色的旅程，当用户向下滚动我们的网站时。这种非常细微的动画为网站增添了许多审美吸引力。

第四章，*导航动画*，介绍了在网站导航中添加动画的创造性方法。我们将网页背景颜色渐隐，并实现对页面上点击链接的平滑滚动。

第五章，*表格和输入动画*，专注于由我们的用户与表单交互触发的动画。我们将通过表单动画引导用户进行表单验证，并提供更好的整体体验。

第六章，*使用 jQuery UI 扩展动画*，介绍了 jQuery UI 增加的额外效果，这是建立在 jQuery 之上的官方 UI 库。我们会介绍其中的 14 种效果，以及库内置的缓动函数。

第七章，*自定义动画*，侧重于`animate()`方法，jQuery 提供此方法用于创建未预定义的自定义动画。这个非常强大的方法允许我们几乎可以动画化任何 CSS 样式属性，轻松创建复杂和吸引人的动画。

第八章，*其他流行动画*，介绍了网页上一些常见类型的动画，包括鼠标指针触发的近距离动画、动画标题以及现代版的走马灯元素。

第九章，*CSS3 动画*，介绍了如何使用 CSS3 基于最新的 CSS 变换创建吸引人的动画，以及如何使用 jQuery 使这个过程更加简单。

第十章，*画布动画*，展示了 HTML5 画布元素的用法，说明了如何在不使用 Flash 或其他专有技术的情况下创建令人惊叹的动画。书的结尾通过深入的示例介绍了如何只使用 HTML 和 JavaScript 创建交互式游戏。

# 本书的要求

要充分利用本书，你应该具备一定的前端开发知识，最好包括 JavaScript。有 jQuery 的经验也比较理想，但并非必需，因为书中涉及到的所有技术都会有详细讨论。

你需要一台能运行最新浏览器的计算机，最好有互联网连接。拥有一个代码编辑开发软件包将会有所帮助，但同样也不是必需的，只要你有某种文本编辑器即可。

# 本书适合谁

本书适合具有良好 HTML 和 CSS 知识的网页设计师和前端开发人员。虽然不是必需条件，但对 jQuery 或 JavaScript 的一些经验将会有所帮助。如果你想学习如何使用 jQuery 为你的 Web 应用程序添加用户界面动画，那么这本书就适合你。

# 习惯用法

在本书中，你会经常看到一些标题。

为了清晰地说明如何完成一个过程或任务，我们使用：

# 行动时间 - 标题

1.  行动 1

1.  行动 2

1.  行动 3

指示通常需要一些额外的解释以使其有意义，因此它们后面跟着：

## *刚刚发生了什么？*

这个标题解释了你刚刚完成的任务或指示的工作方式。

书中还包含其他一些学习辅助工具，包括：

## 突发提问时间 - 标题

这些是短的多项选择题，旨在帮助你测试自己的理解。

## 自我挑战时间 - 标题

这些实际挑战为你提供了尝试所学内容的想法。

你也会发现一些不同类型信息的文本样式。以下是一些示例和它们的含义解释。

文本中的代码示例如下："使用 jQuery 执行最简单的动画的方法为`fadeIn()`和`fadeOut()`"

代码块设置如下：

```js

$("#next").click(function(event) {

activeSlide++;

rotate();

event.preventDefault();

});

```

当我们希望引起你对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```js

$("#slider, #prev, #next").hover(function() {

clearInterval(timer);

pause = true;

}, function() {

timer = setInterval(rotate, speed);

pause = false;

});

```

**新** **术语** 和 **重要** **词语** 以粗体显示。屏幕上看到的文字，如菜单或对话框中的文字等，会出现在文本中，如："在这种情况下，我们清除整个画布，移除飞船和任何幸存的外星人，并在画布中央打印文本 **GAME OVER!**"。

### 注意

警告或重要提示以如下方式出现在框中。

### 提示

贴士和技巧如下所示。


# 第一章：入门

*欢迎来到 jQuery 2.0 动画技术初学者指南。在本书中，我们将研究 jQuery JavaScript 库中可用的每一种产生或控制动画的方法。我们将看到这些方法的使用方式，它们能接受的参数以及它们产生的不同行为。我们还将研究如何使用一系列配套资源，包括精选的 jQuery 插件和 jQuery UI 库。*

在这个介绍性的章节中，我们将讨论以下主题：

+   网络动画简史

+   为什么动画您的 UI 很重要

+   jQuery 提供的动画方法

+   每个示例使用的模板文件

+   基本动画示例

# 网络动画

1989 年，CompuServe 发布了 GIF89a，这是流行的 GIF 图像格式的增强版本，它允许将一系列帧存储为单个图像，并由支持的软件播放。

GIF 格式在那些年已经在被称为互联网的东西上非常流行了（记住，万维网直到 1991 年才存在），因为它的文件大小小，无损压缩，并且得到了广泛的支持。增强版本使得任何人都可以使用支持的软件创建动画，很快就变得流行起来。

除了动画 GIF 之外，浏览器厂商还添加了对原生处理动画的专有 HTML 元素的支持，例如`<blink>`和`<marquee>`元素，它们为文本添加了不同的动画效果。

这两个元素都不是特别吸引人或成功的，W3C 以及领先的行业无障碍性和可用性专家建议在大多数情况下不要使用它们。当时的不同浏览器支持其中一个或另一个元素，但不能同时支持。这两个元素都是由各自的供应商作为原始浏览器战争的一部分添加的。

在 1990 年代末，流行的浏览器增加了对一种称为**动态 HTML**（**DHTML**）的技术的支持，该技术允许脚本语言在页面加载后修改页面的内容。DHTML 不是任何单一技术，而是一组技术（JavaScript，CSS，DOM 等），它们共同作用以实现基本的互动和/或动画。

实际上，DHTML 使得创建相当先进的动画成为可能，但是早期实现所需技术的限制，以及极其不同的浏览器支持使得 DHTML 变得棘手起来。

这个时代还见证了 Flash 的发布和崛起（以及 Shockwave，一种最终被 Macromedia 吞并的竞争技术），这是一种矢量和光栅图形格式，允许音频和视频流，逐帧动画，以及一系列其他功能。Flash 迅速成为流行，并且在撰写本文时仍然是基于网络的视频，基于浏览器的游戏和广告的首选格式。

浏览器中的 DOM 逐渐标准化（大部分），以及 JavaScript 库（如 jQuery）的兴起，这些库抽象化了浏览器之间仍然存在的差异，使得动画对比以往更多的人开放。如今很少使用 DHTML 这个术语，因为它与浏览器之间的支持不佳有关，但是许多交互式和动画网站的基本原理和技术仍然相似。

如今，除了 JavaScript 库可能实现的动画外，我们还有更加新颖和令人兴奋的可能性，比如 CSS3 和本机 HTML 元素（如 `<canvas>` 元素），后者提供了对页面区域的完全像素级控制。我们将在本书的后面更详细地介绍一些 CSS3 动画技术，以及 `<canvas>` 元素。基于 Flash 的动画首次在本世纪出现下降趋势，新技术正在地平线上崛起。

# 动画化用户界面的力量

现代操作系统不断地使用动画来吸引用户，创造更引人入胜的计算体验。在正确的使用方式下，动画为系统的用户提供帮助，引导他们完成不同的任务，提供上下文或反馈，并加强积极的行为。

一个很好的例子是在 Windows 7 或 OS X 中最小化应用程序的方式——应用程序似乎压缩到任务栏/停靠栏上的图标中，这向用户显示了他们想要返回到应用程序时应该去哪里。正是这样的简单细节最有效。

良好的动画可以赋予界面一种时尚的专业感，使其显得更先进或更现代。苹果的 iPhone（或 iPad）就是一个完美的例子——在操作系统及其应用程序中无缝地使用微妙的动画和过渡，使用户能够以一种深刻满意和沉浸式的方式与设备连接。任何出现或消失的内容都会平滑地淡入淡出，菜单和内容面板会从顶部或侧面滑入或滑出。突然的事件可能会使用户感到不安或分心，但是适时的动画可以帮助他们意识到即将发生的事情。

但是需要警告的是，执行不好、笨拙或过于无意义的动画可能会产生相反的效果，使您的界面显得基本、设计不佳或劣质。没有动画总比糟糕的动画好。即使您的应用程序运行完美，过多的动画也可能使用户感到沮丧，导致他们放弃使用您的应用程序或网站。

桌面电脑以及日益增长的移动和手持设备的计算能力已经足够强大，能够处理相当复杂的动画，并且随着集成硬件加速和更加精细的 CSS3 和 HTML5 进入最新的浏览器，网络上可以实现的可能性呈指数级增长。

## 何时使用动画

在以下情况下，动画可以留下深刻印象并增强用户体验：

+   当显示或隐藏窗口、弹出窗口和内容面板时

+   当某物被移动到窗口或页面的其他区域时

+   当用户的操作导致页面上某个内容发生了状态变化时

+   引导用户执行特定的行动或者引起他们对重要事项的注意

## 不适合使用动画的情况

在不必要的地方进行过多的动画可能会有害。在以下情况下，请尽量避免动画，或者至少认真考虑：

+   当用户需要非常频繁地重复某个操作时

+   已知使用该系统的设备可能无法充分显示动画的情况下

+   对于时间敏感的操作或过程

### 注意

请记住，这些只是指南，而不是必须始终遵守的法则，它们当然也不是绝对的。几乎没有任何情况下动画绝对不应该被使用，也几乎没有任何情况下动画一定要被使用。

使用您的判断力来确定动画是否适用于您的应用程序或页面及其预期的受众。如果可能的话，请让用户有机会根据自己的个人喜好启用或禁用动画。

## 动画检查表

在我们的页面或应用程序中实现动画之前，请考虑以下问题清单：

+   动画是否适用于您的目标用户？

+   动画是否实用？

+   动画是否增加了价值或者增强了用户体验？

+   设备上是否会以适当的速度运行动画，这些设备很可能会被使用？

如果您能回答以上所有问题都是肯定的，那么该动画可能是一个积极的特征。如果您对其中任何问题的回答是否定的，您可能需要停下来思考一下您试图通过添加动画来实现什么，以及是否可以以其他方式更好地实现它。

# 使用 jQuery 进行动画

jQuery ([`jquery.com`](http://jquery.com)) 在本地提供了一系列动画方法，无需使用额外的效果库或插件。然而，许多插件都是由在线社区贡献的，包括 jQuery UI ([`jqueryui.com`](http://jqueryui.com))，它是官方的 jQuery UI 库，扩展了 jQuery 的动画能力。本地，jQuery 提供了一些方法，只需最小的配置就能添加滑动和淡出效果，并且能够跨浏览器工作。它还提供了与管理动画队列相关的方法，并提供了一种创建几乎适用于所有数字 CSS 样式的自定义动画的方法。在本书的过程中，我们将详细介绍库中包含的每个动画方法。这些方法在此处列出，并附有各自的描述：

| 方法 | 描述 |
| --- | --- |
| `animate()` | 它执行一组 CSS 属性的自定义动画。 |
| `clearQueue()` | 它从队列中移除尚未运行的所有项。 |
| `delay()` | 它设置一个计时器来延迟队列中后续项的执行。 |
| `dequeue()` | 它执行匹配元素队列中的下一个函数。 |
| `fadeIn()` | 它通过使匹配的元素逐渐变为不透明来显示它们。 |
| `fadeOut()` | 它通过使匹配的元素逐渐变为透明来隐藏它们。 |
| `fadeTo()` | 它调整匹配的元素的不透明度。 |
| `fadeToggle()` | 它通过动画其不透明度来显示或隐藏匹配的元素。 |
| `finish()` | 它停止当前正在运行的动画，移除所有排队的动画，并完成所有匹配元素的动画。 |
| `hide()` | 它隐藏匹配的元素。 |
| `queue()` | 它显示要在匹配的元素上执行的函数队列。 |
| `show()` | 它显示匹配的元素。 |
| `slideDown()` | 它以滑动动画显示匹配的元素。 |
| `slideToggle()` | 它以滑动动画显示或隐藏匹配的元素。 |
| `slideUp()` | 它以滑动动画隐藏匹配的元素。 |
| `stop()` | 它停止匹配的元素上当前正在运行的动画。 |
| `toggle()` | 它显示或隐藏匹配的元素。 |

需要注意的是，有两个属性可以更改全局 jQuery 对象。它们如下所示：

| 属性 | 描述 |
| --- | --- |
| `jQuery.fx.interval` | 它是动画触发的速率（以毫秒为单位）。 |
| `jQuery.fx.off` | 它全局禁用所有动画。 |

总的来说，它为我们提供了一个强大而稳健的环境，可以轻松添加几乎任何类型的动画。

动画也是插件的热门主题，有许多可用的插件，可以让我们即时使用各种不同类型的动画，只需进行最小的配置。我们将在本书的后面看到几个插件。

# 创建项目文件夹

所以，这就是我们将在整本书中引用和使用的模板文件。让我们也花点时间看看示例文件使用的文件夹结构。创建一个项目文件夹并将其命名为`jquery-animation`或类似的名称。在其中创建三个新文件夹并将它们命名为`css`、`img`和`js`。

我们创建的 HTML 页面将放在`jquery-animation`文件夹中的子文件夹旁边。我们创建的所有 CSS 文件将放在`css`文件夹中，我们在示例中使用的所有图像将放在`img`文件夹中。jQuery 库和我们使用或创建的任何其他脚本文件将放在`js`文件夹中。这也是您在下载和解压缩包含所有示例的附带代码存档时将找到的目录结构。

## 模板文件

在本书的整个课程中，我们将创建的每个示例文件都依赖于一组公共元素。与其在书中的每个代码部分和示例中反复显示相同的元素，不如在这里仅查看它们一次：

```js

<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="utf-8">

    <title></title>

    <link rel="stylesheet" href="css/.css">

</head>

<body>

    <script src="img/jquery.js"></script>

    <script>

    $(function(){

    });

    </script>

</body>

</html>

```

### 小贴士

**下载示例代码**

您可以从您在 [`packtpub.com`](http://packtpub.com) 购买的所有 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了本书，您可以访问 [`packtpub.com/support`](http://packtpub.com/support) 并注册，文件将直接通过电子邮件发送给您。

把这个文件保存到刚刚创建的`jquery-animation`文件夹中，并把它命名为`template.html`。这是我们将用于每个示例的基础文件，所以当我们开始逐个示例地工作时，我说*将以下标记添加到* `<body>` *的模板文件中*时，意思是将其直接插入到我们刚刚在前面的代码中创建的模板文件的第一个 `<script>` 标记之前的 `<body>` 标记之间。每当我们向模板文件中添加任何 JavaScript 时，它都将添加到第二个 `<script>` 标记中的匿名函数内。

让我们来看看模板文件包含了什么。我们从 HTML5 doctype 声明开始，因为我们将在示例中使用大量的 HTML5 元素。我们还将`<html>`元素的`lang`属性设置为`en`，以及`<meta>`标签的`charset`属性设置为`utf-8`，虽然这两者都不是严格必需的，但仍然是最佳实践。

接下来是一个空的`<title>`元素，我们可以在其中添加每个示例的名称，以及一个不完整的`<link>`元素的`href`，准备好添加每个示例将使用的样式表的名称。

由于**Internet Explorer 9**（**IE9**）之前的版本不支持任何 HTML5 元素，我们需要使用 Remy Sharp 的`html5shiv`脚本来正确使用 HTML5。我们可以链接到此文件的在线版本以便使用条件注释，该注释针对所有低于版本 9 的 IE 版本。如果您计划在没有互联网连接的情况下在 IE 中尝试示例，请随时下载`html5.js`并将其存储在本地。

为了充分利用本书中的示例，最好将浏览器升级至撰写本文时（*Firefox 24*, *Chrome 30*, *Safari 6*, and *Opera 17*）的最新稳定发布版本，尽管这些版本可能会迅速改变。

### 注

值得注意的是，jQuery 2.0 不支持*oldIE*，也就是 IE8 及以下版本。因此，我们不会为这些版本的 IE 提供任何浏览器兼容性修复。

如果您的项目需要与 IE8 或更早的浏览器兼容，您需要使用**jQuery 1.10**或更低版本。此外，如果您的项目使用 HTML5 元素并需要与 IE8 或更低版本兼容，则需要使用`html5shiv` ([`code.google.com/p/html5shiv`](https://code.google.com/p/html5shiv))。

IE9 确实支持大量的 HTML5 和 CSS3，因此通常只有在 IE8 保持全球最常用浏览器的首位时才需要使用`html5shiv`文件。撰写本文时，根据 NetMarketShare 的数据，全球范围内 IE8 的市场份额为 21%（[`netmarketshare.com`](http://netmarketshare.com)）。IE10 占据第二位，占有 19%，Chrome 29、FireFox 23 和 IE9 紧随其后。页面的`<body>`标签为空，除了一些`<script>`标签。我们显然会在每个示例中使用 jQuery，所以第一个标签链接到 jQuery。撰写本文时，当前版本的 jQuery 是 2.0（但与浏览器版本一样，这很可能会迅速改变）。

在本书中，我们将使用 jQuery 的本地版本，这样我们就不必依赖互联网连接或担心互联网速度。然而，在大多数情况下，在生产环境中，建议链接到 jQuery 的 4 个 CDN（内容分发网络）之一。这些可以在下面找到：

| CDN 主办 | URL |
| --- | --- |
| jQuery | [`code.jquery.com`](http://code.jquery.com) |
| Google | [`developers.google.com/speed/libraries/devguide?csw=1#jquery`](https://developers.google.com/speed/libraries/devguide?csw=1#jquery) |
| Microsoft | [`asp.net/ajaxlibrary/cdn.ashx#jQuery_Releases_on_the_CDN_0`](http://asp.net/ajaxlibrary/cdn.ashx#jQuery_Releases_on_the_CDN_0) |
| CDNJS | [`cdnjs.com/libraries/jquery`](http://cdnjs.com/libraries/jquery) |

在第二个 `<script>` 标签中，我们有一个空函数，我们编写的所有示例 JavaScript 代码将放入其中。我们将 jQuery 对象传递到匿名函数中，并将其命名为 `$` 字符。虽然这并非绝对必要（除非我们创建 jQuery 插件的示例），但这是一个很好的习惯。

# 一个基本的动画示例

让我们看一个基本的例子，这种动画可以帮助我们的访问者放心，显示一些事情正在发生。如果用户执行了一个动作，但结果并没有立即显示，提供反馈给用户，告诉他们的动作正在执行的过程中是一种有用的动画使用。

在下一个截图中，我们可以看到加载指示器位于“启动动作”按钮的正下方。它包含三个单独的加载条，顺序点亮，以显示有事发生。每个条形稍有不同的样式。

# 时机成熟 - 创建一个动画加载器

在这个示例中，我们将创建一个简单的动画加载指示器，当特定进程被启动时我们可以启动它，并在进程完成后停止它。

1.  打开刚刚查看的模板文件，并将以下 `<button>` 元素添加到 `<body>` 中（这应该放在 `<script>` 元素之前）：

    ```js

    <button id="go">启动动作</button>

    ```

1.  接下来，在页面底部第二个空函数中，添加以下代码：

    ```js

    var loader = $("<div></div>", {

    id: "loader"

    }).css("display", "none");

    var bar = $("<span></span>").css("opacity", 0.2);

    var loadingInterval = null;

    for (var x = 0; x < 3; x++) {

    bar.clone().addClass("bar-" + x).appendTo(loader);

    }

    loader.insertAfter("#go");

    function runLoader() {

    var firstBar = loader.children(":first"),

    secondBar = loader.children().eq(1),

    thirdBar = loader.children(":last");

    firstBar.fadeTo("fast", 1, function () {

        firstBar.fadeTo("fast", 0.2, function () {

        secondBar.fadeTo("fast", 1, function () {

            secondBar.fadeTo("fast", 0.2, function () {

            thirdBar.fadeTo("fast", 1, function () {

                thirdBar.fadeTo("fast", 0.2);

            });

            });

        });

        });

    });

    };

    $("#go").click(function () {

    if (!$("#loader").is(":visible") ) {

    loader.show();

    loadingInterval = setInterval(function () {

        runLoader();

    }, 1200);

    } else {

    loader.hide();

    clearInterval(loadingInterval);

    }

    });

    ```

1.  将文件保存为 `loading.html`，放在主项目文件夹（`jquery-animation`）中。最后，我们需要在示例中添加一些基本样式。在文本编辑器中创建一个新文件，将以下代码添加到其中：

    ```js

    #loader { margin:10px 0 0 36px; }

    #loader span {

    display:block;

    width:6px;

    float:left;

    margin-right:6px;

    border:1px solid #336633;

    position:relative;

    background-color:#ccffcc;

    }

    #loader .bar-0 {

    height:15px;

    bottom:-20px;

    }

    #loader .bar-1 {

    height:25px;

    bottom:-10px;

    }

    #loader .bar-2 {

    height:35px;

    margin-right:0;

    }

    ```

1.  将此文件保存在 `css` 文件夹中为 `loading.css`，并更新 HTML 文件以调用此样式表。

1.  此时，当我们点击按钮后，你的代码应该看起来像以下截图一样：![行动时间-创建动画加载器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642OS_01_01.jpg)

## *刚才发生了什么？*

在页面上硬编码的 `<button>` 用于显示和隐藏加载动画。这纯粹是为了这个例子。在实际的实现中，我们会在加载操作开始时显示加载动画，例如当新内容被添加到页面上时，并且在操作完成后再次隐藏它。

在外部函数内部我们做的第一件事是设置一些变量。我们创建了一个新的 `<div>` 元素作为加载器的容器，使用**对象字面量**作为匿名函数的第二个参数，给它赋予一个 `id` 为 `loader`。然后我们用 jQuery 的 `css()` 方法将其样式设置为 `display:none`，这样它就不会立即可见。

### 注意

*对象*字面量是一组由逗号分隔并用大括号括起来的成对值。

我们还创建了一个新的 `<span>` 元素，它将被用作创建三个单独的加载条的模板。我们使用 `css()` 方法将其不透明度设置为 `0.2`（20% 不透明）。jQuery 为我们标准化了这个样式，使其在 Internet Explorer 中正确工作。最后一个变量，`loadingInterval`，将用于存储一个**间隔**的 `id`，以便我们在需要时清除间隔。最初我们将其设置为 null，因为间隔还没有设置。

### 注意

*间隔*是一个数字值（以毫秒为单位），用于暂停或延迟一个操作。

一旦我们的变量被定义和初始化，我们就执行了一个简短的 `for` 循环，只有三次迭代。在这个循环中，我们克隆了我们创建的 span 元素，给它一个类名（以便每个条可以分别样式化），然后将它附加到容器中。一旦三个加载条被添加到容器中，我们就在 `<button>` 元素之后插入了加载器。

接下来，我们定义了一个名为 `runLoader` 的函数。这是将会被间隔重复调用的函数。该函数在按钮被点击之前不会运行。在这个函数内部，我们缓存了每个单独条形图的选择器，然后运行了一系列嵌套函数。

我们首先使用 `fadeTo()` jQuery 动画方法将第一个加载条的不透明度增加到完全不透明。此方法将一个字符串作为其第一个参数（以毫秒为单位表示动画的速度，或使用字符串 `"fast"` 或 `"slow"`），将元素应该淡出到的不透明度作为其第二个参数（值范围从 0 到 1，包括小数，如 0.50），并将回调函数作为第三个参数。回调函数在动画结束后立即执行。

在回调函数中，我们将第一个加载条的不透明度淡化为原始的`0.2`。我们为这个方法调用提供了另一个回调函数，在这个回调函数中，我们将第二个加载条的不透明度动画到完全不透明，然后再动画到原始的不透明度。同样的过程也用于第三个加载条。

最后，我们使用 jQuery 的`click()`方法添加两个函数，这两个函数将在每次点击按钮时交替执行。我们将使用`if`语句来检查我们的`#loader`元素是否在页面上可见，使用`.is(":visible")`并添加一个感叹号(`!`)，以便如果`#loader`元素不可见，则返回 true。如果它不可见，我们将显示加载器，然后设置一个重复调用`runLoader()`函数的间隔。如果元素已经可见，我们隐藏加载器并清除间隔。

## 动手试试英雄 —— 扩展加载动画

我提到过，在进行请求并等待响应时，我们可以使用加载动画。试试在使用 jQuery 的 AJAX 方法时使用它，在发出请求之前显示加载器，一旦响应被处理，再次隐藏它。jQuery 网站上的 JSONP 示例([`api.jquery.com/jQuery.getJSON`](http://api.jquery.com/jQuery.getJSON))，用来获取猫的图片，是一个很好的测试案例。根据您的连接速度，加载器可能不会显示很长时间。

## 快速测验 —— 使用 jQuery 进行基本动画

Q1\. 考虑我们之前讨论的关于何时使用动画和何时不使用动画的问题，什么时候使用这个动画是合适的？

1.  当浏览器进行密集的操作时

1.  当有一个从服务器请求某些内容并且请求返回服务器的延迟，但浏览器需要处理的内容很少时

1.  作为 Flash 动画的替代方案

1.  当不支持动画 GIF 图像时

Q2\. jQuery 的`fadeTo()`方法使用了哪些参数？

1.  表示结束不透明度的整数

1.  包含动画的配置选项的对象

1.  第一个参数表示动画的速度或持续时间，目标元素的最终不透明度，可选的回调函数在动画结束时执行。

1.  不需要参数

# 总结

在这个介绍性的章节中，我们简要介绍了 Web 动画的历史，包括它是如何开始的，早期的 HTML 元素和浏览器支持，Flash 的兴起，以及它在不太遥远的未来的发展方向。

我们还看到了动画如何在用户界面中用来增强用户体验。我们了解了一些关于何时应该使用动画和何时不应该使用动画的指导方针，并看了一些在实现动画时应该考虑的事项。

我们用一个加载动画的基本示例结束了本章。在这个例子中，我们使用了`fadeTo()` jQuery 方法来改变页面元素的不透明度，以及一个简单的间隔来播放动画。我们没有详细讨论这个方法，但我们看到了一个它的使用示例。在下一章中，我们将更详细地讨论这个方法，该章涵盖了 jQuery 提供的所有淡入淡出动画。

在下一章中，我们将专注于图片动画。我们将创建一个基本的图片旋转器，然后扩展该脚本的功能，以构建更多功能。我们将得到一个非常轻量级的图片旋转器，可以在未来的开发项目中使用。


# 第二章：图像动画

*在本章中，我们将使用 jQuery 动画函数创建一个基本的图像轮换器（幻灯片）。我们还将扩展我们脚本的功能，以便在用户悬停在轮换器上时暂停动画。然后，我们将在脚本中添加上一页和下一页链接，以允许用户以自己的节奏滚动图像。最后，我们将添加分页链接，以便我们的用户可以翻页查看图像轮换器中的图像。*

# 图像动画

在您学习 jQuery 的过程中，您会发现有时需要某种形式的内容或图像旋转。图像轮换器比直接在页面上显示图像更具视觉吸引力。它们还可以导致更紧凑和高效的设计，允许预加载内容或图像，并且还可以使我们能够控制用户何时以及何时看到。

### 注意

图像轮换器通常被称为**幻灯片**、**滑块**、**滚动器**或**走马灯**，根据其不同的功能。

在本章中，我们将讨论以下动画方法：

+   `fadeIn()`

+   `fadeOut()`

+   `fadeToggle()`

# 渐变动画

`fadeIn()` 和 `fadeOut()` 方法是通过 jQuery 实现的最简单的动画效果。它们只是简单地调整选定元素的不透明度，以显示或隐藏元素，并且可以在不需要额外配置的情况下使用。`fadeToggle()` 方法几乎同样简单，但确实提供了一些基本逻辑来检查选定元素的当前状态。

使用 `display:none` 隐藏的元素在 `fadeIn()` 动画开始时将尽可能设置为其正确的显示类型（对于块级元素为 `display:block`，对于内联元素为 `display:inline`）。重要的是要注意这一点，因为您的 CSS 样式可能会影响您要淡入的元素的外观。尽可能使用元素的自然显示类型，因此隐藏的 `<li>` 元素将设置为 `display:list-item`，隐藏的 `<td>` 元素将设置为 `display:table-cell`。

被设置为 `display:block`（或被设置为另一种显示类型但仍然在页面上可见）的元素将在 `fadeOut()` 动画结束时设置为 `display:none`。使用 `fadeToggle()` 方法时，元素将在其可见和不可见状态之间切换。

使用 `fadeIn()` 方法显示的元素必须最初使用 `display:none` 隐藏，而使用 `visibility:hidden` 等方式隐藏的元素在动画结束时将保持隐藏，因为淡入淡出方法专门修改 `opacity` 和 `display` 属性，而不是 `visibility` 属性。

在它们最简单的形式中，这些方法可以在不使用任何额外配置的情况下使用。我们可以简单地在任何一组选定的元素上调用这些方法，而不使用任何参数：

+   `$(elements).fadeIn();`

+   `$(elements).fadeOut();`

+   `$(elements).fadeToggle();`

当未提供参数时，动画将具有默认持续时间 400 毫秒和默认缓动`swing`。我们很快会讨论动画缓动。

# 用参数配置动画

带有参数的淡化方法可以采用以下形式（方括号表示可选参数）：

```js

$(elements).fadeIn([duration] [,easing] [,callback]);

$(elements).fadeOut([duration] [,easing] [,callback]);

$(elements).fadeToggle([duration] [,easing] [,callback]);

```

我们可以使用`duration`参数来控制动画的持续时间，指定整数毫秒或字符串`"slow"`和`"fast"`。这些字符串是 600 毫秒和 200 毫秒的快捷方式，分别。如果未指定，则默认给出的持续时间为 400。

我们还可以将`duration`参数设置为`0`，这将有效地禁用动画。我们不太可能需要这样做，因为根本不使用动画会更高效，但了解这一点是有用的。我应该指出，淡出仍将发生；只是会在`0`毫秒的持续时间内发生。这样做基本上与使用`.hide()`相同。

缓动参数可以从其默认值`swing`更改为`linear`，这会使动画在整个动画过程中以相同的速度进行。默认值`swing`会使动画开始缓慢，稍微加速，然后在动画结束时放慢速度。

### 提示

`duration`参数与动画运行的时间长度有关，而不是动画的速度。因此，较高的值将意味着较慢、较长的动画，而不是更快、更短的动画。使用插件可以大大增加缓动类型的数量。我们将在本书后面看到 jQuery UI 添加的额外缓动类型。

我们可以提供一个**回调**函数（可以是函数引用，也可以是匿名函数，后者更常见）。此回调函数将在选择集中的每个元素的动画结束后执行，因此如果有多个元素正在进行动画，可能会触发多次。

### 注意

回调函数是作为参数传递给另一个函数内部的函数。

下面的回调代码示例在动画完成后触发警报（回调部分加粗）：

```js

$(".selector").fadeOut("slow", function() { alert("callback triggered!"); });

```

为了可读性，您经常会看到前面的行像以下代码块一样格式化：

```js

$(".selector").fadeOut("slow", function() {

alert("callback triggered!");

});

```

# 行动时间——设置标记和样式

首先，我们需要创建示例中将要使用的元素以及设置它们的视觉外观的样式。

1.  使用我们在第一章中创建的模板文件创建一个新的 HTML 文档，在`<body>`标签之间添加以下底层标记，用于我们的图像幻灯片演示：

    ```js

    `<div class="container">`

    `<div id="slider">`

        `<img src="img/200?image=1">`

        `<img src="img/200?image=2">`

        `<img src="img/200?image=3">`

        `<img src="img/200?image=4">`

        `<img src="img/200?image=5">`

        `<img src="img/200?image=6">`

        `<img src="img/200?image=7">`

    `</div>`

    `</div>`

    ```

1.  将页面保存在`jquery-animation`目录下，文件名为`image-rotator.html`。

1.  我们还需要为这个示例添加样式表。在我们刚刚创建的 HTML 文件中，将`image-rotator`添加到我们的占位符样式表链接中。

1.  接下来，我们应该创建我们刚刚链接的样式表。在一个新文件中，添加以下代码：

    ```js

    `.container {`

    `position:relative;`

    `width:200px;`

    height:200px;

    }

    `#slider img {`

    `position:absolute;`

    `display:none;`

    `border-radius:3px;`

    `}`

    ```

1.  将此文件保存为`image-rotator.css`，保存在我们项目文件夹中的`css`文件夹中。

## *发生了什么？*

对于这个例子，我们将在我们的图像旋转器中使用七个图像。这可以根据我们的需求轻松更改，只需简单地将其他图像添加到`<div id="slider">`中即可。

我们将我们的`#slider`元素包裹在一个类名为`container`的`<div>`元素中，这样我们可以设置我们的图像旋转器的尺寸，以防我们的所有图像的宽度和高度不同。另外，我们将`position:relative`设置为`#slider` div，这样被设置为`position:absolute`的旋转器图像就不会从页面流中移除。

### 注意

当一个元素被设置为`position:absolute`时，该元素不再保持其所在的空间，这使得其他元素可以根据周围元素上使用的其他 CSS 在其后面或其前面。这与浮动元素的情况相似，当浮动元素被移出页面流时。

需要注意的是，在某些情况下，如果一个元素（或一组元素）被设置为`position:absolute`，而没有父元素被设置为`position:relative`，那么`position:absolute`元素可能会脱离其父元素，导致父元素崩溃。

这些图像被设置为`position:absolute`，因为它们需要在彼此之后堆叠，这样我们的图像旋转器元素在图像淡入淡出时不会跳动。这是必要的，因为所有的图像将占据页面上的同一相对位置。然而，我们只想要显示一张图像。使用`display:none`将关闭所有图像的可见性。这是必要的，这样我们就不必担心图像的**堆叠顺序**。我们希望我们的图像呈现良好，所以我们在图像上添加了一个小的`border-radius`来软化角落。

### 注意

**堆叠顺序** 指的是元素在页面上堆叠的顺序。如果一个元素在另一个元素之前加载，那么它将在后面的元素之前。可以通过在 CSS 中使用 `z-index` 和为元素添加 `position` 来修改堆叠顺序。

## 突然测验 —— 使用 fadeIn()

Q1\. 作为 `fadeIn()` 方法的第一个参数，可以传递哪些字符串？

1.  字符串 `"short"` 或 `"long"`，它们指的是动画的持续时间。

1.  字符串 `"low"` 或 `"high"`，它们指的是元素淡出到的不透明度。

1.  字符串 `"slow"` 或 `"fast"`，它们指的是动画的持续时间。

1.  一个十六进制字符串，指定了元素的 `background-color`。

Q2\. 还可以传递什么到这个方法里？

1.  一个字符串，指定了用于动画的缓动函数，以及在动画结束时执行的回调函数。

1.  包含额外配置选项的对象。

1.  一个包含额外配置选项的数组。

1.  在动画开始时执行的回调函数，以及在动画结束时执行的回调函数。

## 编写图片轮播脚本

接下来，我们将通过添加 jQuery 代码为我们的图像旋转器添加最后的修饰。

# 行动时间 —— 编写图像旋转器

现在让我们添加脚本的代码，这些代码将为我们的图像添加动画效果。在 `<body>` 标签下面的匿名函数中添加以下代码：

```js

var image = $("#slider img");

var numSlides = image.length;

var activeSlide = 0;

var speed = 2000;

var fade = 1000;

var timer = setInterval(rotate, speed);

image.eq(activeSlide).show();

function rotate() {

activeSlide++;

if (activeSlide == numSlides) {

    activeSlide = 0;

}

image.not(activeSlide).fadeOut(fade);

image.eq(activeSlide).fadeIn(fade);

}

```

## *刚刚发生了什么？*

我们做的第一件事是缓存对位于 `#slider` 元素内的所有 `<img>` 元素的引用。我们将多次引用它，因此只从 **文档对象模型** (**DOM**) 中选择一次更有效率。出于性能考虑，通常最好尽量减少执行的 DOM 操作数量。

使用 `length()` 来计算图片数量。这会计算父元素 (`#slider`) 内的子元素 (`<img>`) 的数量。在我们的例子中，我们使用了七张图片。通过使用 `length()` 函数来计算 `<img>` 元素的数量，我们可以在不更改 jQuery 代码的情况下轻松地添加或移除图片来实现图片轮播。

我们将 `activeSlide` 变量设置为 `0`，以便从我们集合中的第一张图片开始。一般情况下，这是您不想更改的内容，除非您想要从特定的图片开始。只要我们的图片集合中至少有这个数量的图片，这个数字就可以更改为您喜欢的任何数字。

`activeSlide`变量表示我们刚刚选择的元素组内的位置。 `length()`函数返回元素的数量，从`0`开始。 在我们的示例中，`image.length()`将返回`6`，因此`activeSlide`可以为`0`至`6`，因为有七个`<img>`元素。 我们将`activeSlide`初始化为`0`，因此我们从序列中的第一个图像开始。 如果我们想要从不同的图像开始，初始化`activeSlide`为该组内的位置，记住，第一个位置是`0`而不是`1`。

要设置`rotate()`函数每次执行之间的时间，我们将`speed`变量设置为`2000`毫秒（2 秒）。 对于我们的示例来说，2 秒是一个很好的速度，但根据您旋转的图像而定，可能需要设置更长的持续时间。 如果您的图像上有您希望用户阅读的文本，应基于您认为用户舒适阅读所有文本需要多长时间来设置旋转速度。 如果您的图像中有高度细节，将速度设置为您认为可以充分欣赏所有细节的时间。 如果您有一个需要“呼吁行动”的可点击元素，那么这个时间将需要根据用户消化信息并采取您希望他们采取的行动所需要的时间来考虑。

我们的`fade`变量设置为`1000`（1 秒），因为这是一个不错的淡出图像的速度。 这可以根据您的需求进行更改，您会发现没有标准时间或速度。 您需要调整这些时间，以便为您的用户在网站上提供最佳体验。

`setInterval()`（原生 JavaScript 方法）函数在脚本中创建一个计时器，在此期间执行被调用的函数。 在我们的示例中，`setInterval()`将执行`rotate()`函数，但会等待直到经过`speed`变量指定的时间量再次调用它。 由于`speed`设置为`2000`，所以`rotate()`函数将每 2 秒执行一次。

### 提示

带有参数的，`setInterval` 事件可以采用以下形式：

`setInterval(function, duration);`

然后，我们告诉脚本使用`show()`来显示活动图像。 由于我们最初将`activeSlide`变量设置为`0`，所以我们设置的图像组中的第一个图像将首先显示。 这是必要的，因为如果您回忆一下，在我们的 CSS 中，我们使用`display：none`关闭了旋转器中所有图像的可见性。 如果更改了`activeSlide`变量的初始值，则在脚本启动时将显示该图像。

接下来，我们转向脚本的主要部分。对于我们的素食主义读者，无论你在饮食中吃什么蛋白质等效物，豆浆？豆腐？总之，`rotate()` 函数是我们在代码中普遍进行大量工作的地方。`rotate()` 函数上面的代码主要是设置我们的图像旋转器要使用的设置。在我们庞大的`rotate()`函数中，我们有一个变量（`activeSlide`），每次调用它时我们都会递增一次。这是为了在函数循环时将我们的活动图像设置为我们组中的下一个图像。

`if`语句用于在脚本到达所选组中最后一个`<img>`元素时重置`activeSlide`编号为`0`。

最后，我们有我们代码中最重要的两行（有人说的）。我们使用`fadeOut()`动画函数对所有非活动图像执行动画。然后，我们对等于`activeSlide`图像的图像使用`fadeIn()`。您会注意到我们的`fadeOut()`和`fadeIn()`动画中的 fade 变量。这决定了动画执行的速度。除了一些其他 jQuery 动画函数之外，`"slow"`和`"fast"`也可以使用—分别为 600 和 200 毫秒。

这是我们使用之前的代码创建的截图。您会注意到第一张图像在我们的下一张图像淡入时减弱。这种效果被称为**交叉淡入**。

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642OS_02_01.jpg)

## 课堂测验 – length() 和毫秒

Q1\. `length()` 指的是什么？

1.  变量的字符计数。

1.  对象中的元素数量。

1.  对象的宽度。

1.  动画运行的时间量。

Q2\. 1 秒中有多少毫秒？

1.  10

1.  100

1.  1000

1.  10000

# 行动时间 – 扩展悬停时暂停功能

当你的图像具有许多细节、用户需要阅读的文本或你希望他们采取的特定行动时，悬停暂停是必要的。即使你不需要这些东西中的任何一种，添加这个功能仍然是一个好主意，因为它允许用户在希望时好好查看图像。

以下截图说明了当用户在图片上悬停时图像旋转停止的情况：

![行动时间 – 扩展悬停时暂停功能](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642OS_02_02.jpg)

为了检测我们何时悬停在图像旋转器上和离开，以便我们可以暂停图像旋转器，我们需要将以下代码添加到`image.eq(activeSlide).show();`下面的行：

```js

$("#slider").hover(function() {

clearInterval(timer);

}, function() {

timer = setInterval(rotate, speed);

});

```

## *刚刚发生了什么？*

我们添加了一个悬停事件，以便告知我们的脚本当我们悬停在`#slider`元素上以及当我们离开该元素时。我们在`timer`变量上使用`clearInterval()`（原生 JavaScript 方法）停止我们旋转器的计时器，有效暂停动画。

### 注意

更多关于悬停事件的信息可以在这里找到：[`api.jquery.com/hover/`](http://api.jquery.com/hover/)

需要注意的是，`stop()`和`clearQueue()`是停止动画或函数运行的其他方法。但是，在这个示例中，我们不想使用它们，因为它们会立即停止我们的动画。这意味着它会在动画进行到一半时暂停动画，并且会部分淡化显示当前活动和下一个活动的图像。或者，我们可以让间隔保持运行，并在`rotate()`函数中使用标志来确定是执行`fadeIn()`还是`fadeOut()`方法。

下一行告诉脚本我们不再悬停在其上，并且要恢复图像的动画。然后，使用`setInterval`（本机 JavaScript 方法）将计时器重置回最初设置的值。

# 执行操作的时机 - 扩展上一个和下一个链接功能

为了让用户更好地控制旋转图像的速度，我们将按照以下步骤添加上一个和下一个链接：

1.  我们需要添加用于上一个和下一个链接的锚标签。为此，请在最后两个`</div>`标签之间添加以下代码：

    ```js

    <a id="prev">prev</a>

    <a id="next">next</a>

    ```

1.  我们的下一个和上一个链接需要一些基本的样式，所以让我们在我们的`image-rotator.css`文件的底部添加以下 CSS 行：

    ```js

    #prev, #next {

    position:absolute;

    bottom:10px;

    padding:5px 10px;

    color:#000;

    background:#FFF;

    border-radius:3px;

    text-decoration:none;

    opacity:0.7;

    }

    #prev:hover, #next:hover {

    opacity:1;

    cursor:pointer;

    }

    #prev {left:10px;}

    #next {right:10px;}

    ```

1.  为了处理下一个和上一个链接上的点击事件，我们需要在`rotate()`函数的上面添加以下代码：

    ```js

    $("#prev").click(function(event) {

    activeSlide--;

    rotate();

    event.preventDefault();

    });

    $("#next").click(function(event) {

    activeSlide++;

    rotate();

    event.preventDefault();

    });

    ```

1.  在`image.not(activeSlide).fadeOut(fade);`上面添加以下代码行：

    ```js

    if (activeSlide < 0) {

    activeSlide = numSlides - 1;

    }

    ```

1.  通过以下代码替换`rotate()`函数来更新它：

    ```js

    if (!pause == true) {

    activeSlide++;

    }

    ```

1.  查找`hover()`函数并用以下代码替换它（新代码已经突出显示）：

    ```js

    $("#slider, #prev, #next").hover(function() {

    clearInterval(timer);

    pause = true;

    }, function() {

    timer = setInterval(rotate, speed);

    pause = false;

    });

    ```

以下截图显示，在点击下一个链接后，我们的图像旋转器移动到下一个图像：

![执行操作的时机 - 扩展上一个和下一个链接功能](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642OS_02_03.jpg)

## *刚刚发生了什么？*

在第三步中，我们为上一个和下一个链接添加了两个单击函数。在上一个函数中，我们将活动图像编号减一，在下一个函数中，我们将其加一。然后我们需要再次调用 rotate 函数，以便我们的旧图像淡出，新图像淡入。我们使用 `preventDefault()`（本地 JavaScript 方法）使得上一个和下一个链接不会向我们地址栏中的 URL 添加一个井号（**#**）。这样可以防止上一个和下一个链接像传统锚点标签一样工作。

第四步允许我们在我们的图像集中向后移动。这个 `if` 语句类似于我们已经在 `rotate()` 函数中使用的 `if` 语句，用于在活动变量等于我们旋转器中的图像数时重置它。

我们需要更改 `rotate()` 函数，以便仅在我们的图像旋转器未悬停在其上时才递增 `active` 图像变量。为此，我们用一个 `if` 语句替换了递增 `activeSlide` 变量的行。使用此 `if` 语句，我们告诉脚本仅在用户未悬停在图像旋转器上时才允许 `activeSlide` 变量递增。

我们需要在暂停悬停功能中添加下一个和上一个链接，这样当您悬停在上面时，图像旋转也会暂停。这可以通过在 `#slider` 后面添加逗号，并添加我们的 `#next` 和 `#previous` ID 选择器来实现。我们将 `pause` 变量设置为基于我们是否触发了 `hover` 事件的布尔值 `true` 或 `false`。这是告诉 `rotate` 函数仅在我们没有悬停在其上时才递增 `activeSlide` 变量所需的。为了告诉我们的脚本我们正在悬停在其上，我们将变量 `pause` 设置为值 `true`。然后一旦我们的光标离开图像旋转器，我们就将其设置为 `false`。

## 快速测验 – preventDefault() 和 setInterval()

Q1\. `preventDefault()` 用于什么？

1.  防止脚本在函数中默认变量。

1.  防止事件的默认操作被使用时。

1.  在其所在的函数中关闭所有 JavaScript 错误。

1.  关闭返回空值的变量的 JavaScript 错误。

Q2\. `setInterval()` 方法需要使用的两个参数是什么？

1.  `speed` 和 `time`

1.  `function` 和 `duration`

1.  `duration` 和 `speed`

1.  `speed` 和 `function`

# 行动时间 – 扩展分页功能

为了让我们的用户更多地控制我们的图像旋转器，我们将添加所谓的**分页**。分页允许您直接移动到我们旋转器中的特定图像，而不必点击下一个和上一个链接，直到找到所需的图像。如果我们的图像旋转器中有大量图像，此功能非常有用。为了添加分页，我们执行以下步骤：

让我们首先将以下代码添加到 `image-rotator.css` 中：

```js

#pagination {

position:absolute;

top:10px;

width:100%;

text-align:center;

}

#pagination a {

padding:2px 5px;

color:#000;

background:#FFF;

border-radius:3px;

text-decoration:none;

opacity:0.7;

}

#pagination a:hover {

opacity:1;

cursor:pointer;

}

```

1.  在 `image-rotator.html` 中，在 `var pause;` 下方直接添加以下行：

    ```js

    var paging = "";

    ```

1.  在我们的 HTML 中，在 `<a id="next" href="#">next</a>` 下面添加以下代码：

    ```js

    <div id="pagination"></div>

    ```

1.  在 `image.eq(activeSlide).show();` 下面放置以下代码：

    ```js

    for (var page = 0; page < numSlides; page++) {

    paging += "<a rel=\"" + (page + 1) + "\">" + (page + 1) + "</a>\n";

    }

    $("#pagination").html(paging);

    ```

1.  找到下面的 `hover` 事件，并用以下代码替换（新代码已突出显示）：

    ```js

    $("#slider, #prev, #next, #pagination").hover(function() {

    clearInterval(timer);

    pause = true;

    }, function() {

    timer = setInterval(rotate, speed);

    pause = false;

    });

    ```

1.  在我们的 `rotate()` 函数上方直接添加以下代码：

    ```js

    $("#pagination a").click(function(event) {

    event.preventDefault();

    activeSlide = $(this).attr("rel") - 1;

    rotate();

    });

    ```

以下截图说明了我们添加的分页功能，以及在点击相应链接后显示的第四张图像：

![执行动作-扩展分页功能](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642OS_02_04.jpg)

## *刚刚发生了什么？*

我们做的第一件事是声明并设置新的分页变量。如果没有这个变量，我们的代码将会出现严重的 JavaScript 错误。

使用 `for` 循环，我们定义了我们的 `page` 变量，告诉它继续循环直到 `page` 小于我们集合中的图像数量，然后使用 `++` 递增这个新定义的变量。下一行是到目前为止我们脚本中最复杂的代码，所以请跟着我走！一个变量后面跟着 `+=` 告诉变量使用已经存储的内容，并继续添加到末尾。这种将值或字符串串在一起的方法称为 **串联**。

接下来我们需要构建分页链接的 HTML 结构。我们正在构建一系列七个 `<a>` 标签，每个标签对应我们组中的一个图像。为了在链接上打印图像编号，我们将使用 `(page + 1)`。我们使用 `+ 1` 是因为 JavaScript 以所谓的 **零索引** 或 **基于零的编号** 对事物进行编号，这意味着在对组或列表中的项目进行编号时，它不是从 1 开始，而是从 0 开始。直到现在这没有成为问题（因为我们没有打印出值），但现在我们需要告诉我们的脚本从 1 开始，以便正确显示分页链接。`for` 循环的最后一行用 `html()` 替换 `#pagination` 的内容，并用 `paging` 变量内部存储的值替换它。

### 注

`html()` 方法用于获取或设置所选元素的 HTML 内容。

再次，我们需要扩展我们的鼠标悬停暂停功能，以便在悬停在新的 `#pagination` 元素上时知道要暂停。如果不这样做，当您悬停在 `#pagination` div 上时，图像会继续旋转。

我们添加了另一个点击函数（`$("#pagination a").click`）来处理我们的分页链接。您会注意到我们之前使用的`preventDefault()`以确保在点击分页链接时不会向页面 URL 中添加井号（#）。下一行将`activeSlide`变量设置为分页锚点标签中`rel`的值，然后减去一。这样做是因为我们将其设置为增加一，以抵消我们在第三步中看到的零索引问题。

最后，我们添加了包含所有分页链接的 `<div>` 元素。

## 尝试进一步扩展图片轮播器

在此示例中，我们使用 `fadeIn()` 和 `fadeOut()` 来轮换我们的图像。尝试扩展示例，使脚本能够检测应该进行动画处理的子元素。

扩展图片轮播的其他想法：

+   让脚本动态设置子元素的尺寸，使脚本能够按比例缩放以适应内容。

+   构建能够同时显示多个元素的功能

+   为分页栏中的当前活动链接提供不同的外观，以便我们的用户知道轮播器当前显示的是哪张图像。

+   添加额外的过渡效果（例如，滑动）。

## 小测验 - 更改变量和零索引

Q1\. 在变量后使用 `++` 是什么意思？

1.  合并两个变量的值。

1.  告诉脚本只允许向变量添加，而不允许减去。

1.  将变量增加一个。

1.  将变量增加两个。

Q2\. **零索引**是什么意思？

1.  JavaScript 是从零开始计数的。

1.  如果未明确定义，变量的默认值为零。

1.  将元素的索引设置为零的方法。

1.  在使用后将变量的值设置为零的方法。

# 摘要

在本章中，我们看了一些 jQuery 最基本的动画方法。淡入淡出方法是 jQuery 中最简单的动画方法，只会动画选定元素的不透明度。

`show()`、`hide()` 和 `toggle()` 方法也可用于执行动画，但会改变元素的尺寸以及不透明度。所有这些方法都简单易用，几乎不需要额外的配置即可运行。

在下一章中，我们将学习如何操纵元素的背景属性以创建背景动画。


# 第三章：背景动画

*在上一章中，我们使用`fadeIn()`和`fadeOut()`方法来对图像元素进行动画处理。在本章中，我们将使用`animate()`效果来对背景颜色进行动画处理，并学习如何对元素内部的背景图像的位置进行动画处理。在第七章，*Custom Animation*中，我们将更深入地了解`animate()`方法所能做的一切。*

# 背景颜色动画

对元素的背景颜色进行动画处理是吸引用户眼球到我们想让他们看到的对象的绝佳方法。对元素的背景颜色进行动画处理的另一个用途是显示发生了某些变化。如果对象的状态发生了变化（添加、移动、删除等），或者需要关注以解决问题，通常会以这种方式使用动画。我们将在接下来的两章中了解到其中的一些内容。

### 注意

由于 jQuery 2.0 不支持背景颜色动画，我们将使用 jQuery UI 来为我们提供所需功能以创建此效果。

我们将在第六章中详细介绍 jQuery UI 给予我们的能力，*使用 jQuery UI 扩展动画*。

## 介绍动画方法

`animate()`方法是 jQuery 在动画领域提供的最有用的方法之一。借助它，我们能够做一些事情，比如将元素移到页面上的其他位置，或者改变并动画处理颜色、背景、文本、字体、框模型、位置、显示、列表、表格、生成内容等属性。

# 行动时间 - 对 body 背景颜色进行动画处理

按照下面的步骤，我们将从创建一个示例开始，该示例更改`body`的背景颜色。

1.  首先创建一个名为`background-color.html`的新文件（使用我们的模板）并将其保存在`jquery-animation`文件夹中。

1.  接下来，我们需要通过在 jQuery 库下面直接添加这行来包含 jQuery UI 库：

    ```js

    <script src="img/jquery-ui.min.js"></script>

    ```

    ### 注意

    jQuery UI 的自定义或稳定版本可从[`jqueryui.com`](http://jqueryui.com)下载，或者您可以使用下面三个**内容传送网络**（**CDN**）之一链接到库。要快速访问库，转到[`jqueryui.com`](http://jqueryui.com)，滚动到最底部，找到**快速访问**部分。在这里使用 jQuery UI 库 JS 文件将完全符合我们本章示例的需求。

    媒体模板：[`code.jquery.com`](http://code.jquery.com)

    谷歌：[`developers.google.com/speed/libraries/devguide#jquery-ui`](http://developers.google.com/speed/libraries/devguide#jquery-ui)

    微软：[`asp.net/ajaxlibrary/cdn.ashx#jQuery_Releases_on_the_CDN_0`](http://asp.net/ajaxlibrary/cdn.ashx#jQuery_Releases_on_the_CDN_0)

    CDNJS: [`cdnjs.com/libraries/jquery`](http://cdnjs.com/libraries/jquery)

1.  然后，我们将以下 jQuery 代码添加到匿名函数中：

    ```js

    var speed = 1500;

    `$( "body" ).animate({ backgroundColor: "#D68A85" }, speed);`

    $( "body" ).animate({ backgroundColor: "#E7912D" }, speed);

    `$( "body" ).animate({ backgroundColor: "#CECC33" }, speed);`

    `$( "body" ).animate({ backgroundColor: "#6FCD94" }, speed);`

    `$( "body" ).animate({ backgroundColor: "#3AB6F1" }, speed);

    `$( "body" ).animate({ backgroundColor: "#8684D8" }, speed);`

    `$( "body" ).animate({ backgroundColor: "#DD67AE" }, speed);`

    ```

## *刚才发生了什么？*

首先，我们向页面添加了 jQuery UI 库。这是必需的，因为当前版本的 jQuery 不支持动画显示背景颜色。接下来，我们添加了将动画显示背景的代码。然后，我们将`speed`变量设置为`1500`（毫秒），以便我们可以控制动画的持续时间。最后，使用`animate()`方法，我们设置了 body 元素的背景颜色，并将持续时间设置为我们上面命名为`speed`的变量。我们多次复制了相同的行，只改变了背景颜色的十六进制值。

以下截图是整个 body 背景颜色动画经过的颜色示意图：

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642_03_01.jpg)

## 链接在一起的 jQuery 方法

需要注意的是，jQuery 方法（在这种情况下为`animate()`）可以链接在一起。如果我们将`animate()`方法链接在一起，我们之前提到的代码将如下所示：

```js

`$("body")`

.animate({ backgroundColor: "#D68A85" }, speed)  //红色

.animate({ backgroundColor: "#E7912D" }, speed)  //橙色

.animate({ backgroundColor: "#CECC33" }, speed)  //黄色

.animate({ backgroundColor: "#6FCD94" }, speed)  //绿色

.animate({ backgroundColor: "#3AB6F1" }, speed)  //蓝色

.animate({ backgroundColor: "#8684D8" }, speed)  //紫色

.animate({ backgroundColor: "#DD67AE" }, speed); //粉色

```

这里是链接方法的另一个示例：

`$(selector).animate(properties).animate(properties).animate(properties);`

## 尝试一下吧，英雄- 用循环扩展我们的脚本

在这个示例中，我们使用了`animate()`方法，并借助 jQuery UI 的帮助，我们能够动画显示页面的整个背景颜色。试着扩展脚本以使用循环，这样一旦脚本到达函数的末尾，颜色就会持续动画而不会停止。

## 突发小测验 - 用 animate() 方法进行链接

Q1\. 哪个代码能够正确地使用链接从红色渐变到蓝色？

1.  ```js

    `$("body")`

    .animate({ background: "red" }, "fast")

    .animate({ background: "blue" }, "fast");

    ```

1.  ```js

    `$("body")`

    .animate({ background-color: "red" }, "slow")

    .animate({ background-color: "blue" }, "slow");

    ```

1.  ```js

    `$("body")`

    .animate({ backgroundColor: "red" })

    .animate({ backgroundColor: "blue" });

    ```

1.  ```js

    `$("body")`

    .animate({ backgroundColor, "red" }, "slow")

    .animate({ backgroundColor, "blue" }, "slow");

    ```

# 视差的深度 illision

在计算机图形学的背景下，特别是在视频游戏中，术语**视差**指的是使用多个背景层，以稍微不同的速度滚动，以创建深度 illision 的技术。尽管在现代游戏中不如以前那样广泛应用，因为有了更丰富的 3D 图形引擎，但视差仍然经常在便携式游戏设备上看到，并且越来越多地出现在 Web 上。

使用纯 CSS 可以实现视差效果，正如在 Silverback 站点上演示得很好一样（请查看[`silverbackapp.com`](http://silverbackapp.com)获取效果，以及[`blog.teamtreehouse.com/how-to-recreate-silverbacks-parallax-effect`](http://blog.teamtreehouse.com/how-to-recreate-silverbacks-parallax-effect)获取有关如何实现的详细信息）。当窗口水平调整大小时，视差的这种应用只有在窗口调整大小时才会显现出来。虽然这在窗口调整大小时是一个很棒的效果，但如果我们希望效果更加突出，这并不能帮助我们。

# 行动时间 - 创建舞台并添加样式

该底层页面仅需要四个元素（对于此简单示例），这些元素位于页面的`<body>`中。

1.  将以下结构的元素添加到模板文件的新副本中，在第一个`<script>`标签之间：

    ```js

    <div id="背景"></div>

    <div id="中景"></div>

    <div id="前景"></div>

    <div id="地面"></div>

    ```

1.  将此页面保存为`parallax-horizontal.html`，放在我们的`jquery-animation`文件夹中。

1.  此示例中的 CSS 和底层 HTML 一样简单。将以下代码添加到文本编辑器中的新文件中：

    ```js

    div {

    width:100%;

    height:1000px;

    position:absolute;

    left:0;

    top:0;

    }

    #背景 { background:url(../images/background.png) repeat-x 0 0; }

    #中景 { background:url(../images/midground.png) repeat-x 0 0; }

    #前景 { background:url(../images/foreground.png) repeat-x 0 0; }

    #舞台 { background:url(../images/ground.png) repeat-x 0 100%; }

    ```

1.  将此文件保存为`parallax-` `horizontal.css`，放在`css`目录中，并更新我们刚刚创建的 HTML 文件，以链接到此文件。

1.  此时，页面应如下截图所示：

![行动时间 - 创建舞台并添加样式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642_03_02.jpg)

前景区域是地面，前景层是较暗的灌木丛，中景是较浅的灌木丛，背景是天空和云。

## *刚才发生了什么？*

您还会在此书附带的代码下载的 images 文件夹中找到此示例的图像。我们为每个要成为视差效果一部分的元素准备了单独的图像，在此示例中有三个，一个用于背景，一个用于中景，一个用于前景。

底层 HTML 也非常简单。我们只需要为背景的每一层添加一个单独的`<div>`。在 CSS 中，每个图像层都被绝对定位，这样它们就能重叠在一起。现在，让我们让视差的层移动起来吧！

# 时间行动 - 动画背景位置

现在轮到 `<script>` 本身了。在 HTML 文件底部，像往常一样，在空匿名函数中添加以下代码：

```js

var bg = $("#background");

var mg = $("#midground");

var fg = $("#foreground");

$(document).keydown(function(e) {

if (e.which === 39) { //右箭头键

    bg.animate({ backgroundPosition: "-=1px" }, 0, "linear" );

    mg.animate({ backgroundPosition: "-=10px" }, 0, "linear" );

    fg.animate({ backgroundPosition: "-=20px" }, 0, "linear" );

}

});

```

如果我们现在在浏览器中运行这个页面，我们应该会发现当我们按住右箭头键时，不同的背景图像切片以相对较慢的速度移动，前景几乎匆匆而过，而背景则悠闲地移动。

## *刚才发生了什么?*

在脚本中，我们首先缓存了将要使用的选择器，这样我们就不必在每次`background-position`变化时都创建一个新的 jQuery 对象并从 DOM 中选择元素，而这将非常频繁。然后，我们在 document 对象上设置了一个`keydown`事件监听器。在作为事件处理程序的匿名函数中，我们检查事件对象的`which`属性提供的键码是否等于`39`，这是右箭头键返回的键码。

然后我们在`backgroundPosition`上调用`animate()`，并为每一层提供`-=1px`、`-=10px`和`-=20px`的相对值，以逐渐加快速度，从而产生视差效果。这些动画同时进行，持续时间设置为零(0)毫秒，并且采用`linear`缓动。这是我们的`keydown`处理程序需要做的最后一件事情。

## 试试看 - 扩展视差

在这个示例中，背景只从右向左进行动画。扩展示例，使左向右和右向左的运动都可用。需要帮助开始吗？您需要为左箭头键创建另一个函数，并递增`backgroundPostion`值，而不是像我们在示例中所做的那样递减。

# 自动化的背景动画

在这个示例中，我们将使背景图像在页面上自动上移，而无需我们的用户特别交互。

# 时间行动 - 创建自动化的背景动画

我们将创建一个示例，现在将自动地对背景图像进行动画。

1.  使用我们的模板创建一个名为`background-auto.html`的新文件，并将其保存在我们的`jquery-animation`目录中。

1.  由于我们的示例只有一行 CSS，我们不打算创建样式表。我们将其放在我们刚刚创建的文件（`background-auto.html`）下的 `<title>` 标签下：

    ```js

    <style>

    body {background:url(images/background.jpg) top center fixed;}

    </style>

    ```

1.  接下来，我们将删除样式表 `<link>`，因为我们不会在此示例中使用它。这将是我们刚刚添加的代码之后的一行。

1.  最后，将以下代码添加到我们等待的匿名函数中：

    ```js

    var yPos = 0;

    var timer = setInterval(start, 50);

    function start() {

        yPos = yPos - 5;

        $('body').css({ backgroundPosition: '50% ' + yPos + 'px' });

    }

    ```

以下是我们刚刚创建的屏幕截图。您会注意到，在查看示例时，背景图像从底部向上方向动画。

![行动时间 - 创建自动背景动画](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642_03_03.jpg)

## *刚刚发生了什么？*

我们做的第一件事是将我们的变量 `yPos` 声明为整数。做到这一点，你可能知道，会吓跑任何在 Internet Explorer 和类似的非现代浏览器版本中出现的可怕的 JavaScript 错误。

接下来，我们使用 `setInterval()` 声明了我们的 `timer` 变量。在上一章中，我们学习了这个方法的参数是 `function` 和 `duration`。我们的函数名是 `start`，所以我们将 `function` 参数设置为那个。我们还将我们的 `duration` 设置为 `50`（毫秒），因为这是我们的函数在再次执行之前等待的合适时间框架。

然后，我们创建了一个可以由我们的计时器调用的函数，名为 `start`。我们每次函数执行时，都将 `yPos` 的当前值减去五。我们函数的最后一行是做所有繁重工作的地方。这一行每次我们的脚本中的函数来到这一行时，都会垂直地将 `<body>` 背景图像的位置向上移动五个像素。

## 尝试吧，英雄 - 在引擎盖下玩耍

尝试更改 `timer` 持续时间和 `yPos` 偏移值，看看这些值如何影响我们的背景动画的速度和帧率。另一个挑战是尝试使背景水平动画，而不是垂直动画，就像我们为此示例所做的那样。

# 让我们使它变成斜线！

现在，我们不再垂直地使背景图像动画，而是斜向地进行动画。抓住你们的编程帽子！

# 行动时间 - 对背景进行斜向动画

现在我们要让我们的动画斜向移动。

1.  让我们使用与之前相同的文件（`background-auto.html`），并使用以下代码替换我们匿名函数中的代码（新代码已突出显示）：

    ```js

    var xPos = 0;

    var yPos = 0;

    var timer = setInterval(start, 50);

    function start() {

    xPos = xPos - 5;

        yPos = yPos - 5;

    $('body').css({ backgroundPosition: xPos +

    'px ' +  yPos + 'px' });

    }

    ```

1.  将此文件保存为 `background-auto-diagonal.html`，并在您的网络浏览器中查看。

    预览动画应该是这样的：

    ![行动时间 - 对背景进行对角线动画](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642_03_04.jpg)

## *刚刚发生了什么？*

使用相同的代码，我们对其进行了一些升级，以便能够动画化背景位置的 X 坐标以及 Y 坐标。添加了变量`xPos`来控制左右水平位置，并且还将其添加到`backgroundPostion`行中。

## 试试看看

在我们之前提到的示例中，我们使背景图像向西北方向动画化。尝试使背景动画向东北、东南和西南移动。还尝试使用不同的`xPos`和`yPos`偏移值，以查看它如何影响背景图像的动画方向。

# 页面元素的视差背景

我们的下一个示例将向您展示如何根据窗口滚动的交互来动画化元素的背景位置。根据您的浏览器中平滑滚动的外观以及您鼠标上的平滑滚轮的外观，可能很难看到此动画效果。如果您看不到平滑的滚动效果，只需抓住浏览器上的滚动条并缓慢上下移动，即可更清楚地看到效果。您会注意到，背景位置的移动速度比页面上的元素慢。

# 行动时间 - 设置标记和样式

要开始，我们需要向新文档添加必要的 HTML 和 CSS。

1.  使用与之前相同的模板创建一个新的 HTML 页面，并将以下代码插入`<body>`中：

    ```js

    <div class="row row1">

    <img src="img/image1.png">

    </div>

    <div class="row row2">

    <img src="img/image2.png">

    </div>

    <div class="row row3">

    <img src="img/image3.png">

    </div>

    ```

1.  将页面保存在`jquery-animation`目录中，命名为`parallax-vertical.html`。

1.  接下来，我们应该创建刚刚链接的样式表。在一个新文件中，添加以下代码：

    ```js

    html, body {

        margin:0;

        padding:0;

    }

    img {

        display:block;

        width:1000px;

        margin:0 auto;

        padding-top:200px;

    }

    .row { height:700px; }

    .row1 { background:url(images/background1.jpg) repeat-x top center fixed;}

    .row2 { background:url(images/background2.jpg) repeat-x top center fixed;}

    .row3 { background:url(images/background3.jpg) repeat-x top center fixed;}

    ```

1.  将此文件保存为`parallax-vertical.css`，放在`project`文件夹内的`css`文件夹中。

## *刚刚发生了什么？*

首先，我们添加了示例的 HTML 结构。这包括三行，每行只包含一个图像。CSS 也很简单。我们首先删除了`html`和`body`元素周围的所有空格。然后，我们设置了图像的宽度和位置。然后，我们设置了行的高度，以便我们有一些空间来看到效果。在实际应用中，这通常会由元素的内容来调整。最后，我们在每一行上设置了一个背景图像，以便我们在示例中看到一些变化。

# 行动时间 - 编写我们的视差脚本

现在，让我们添加代码，使我们的背景在页面向下滚动时动画。

1.  将以下代码添加到我们的匿名函数中，以便我们能够启动并运行此脚本：

    ```js

    $(window).scroll(function() {

        var yPos = -($(window).scrollTop() / 2);

        $(".row").css({ backgroundPosition: "50% " + yPos + "px" });

    });

    ```

这里有一个截图示例，展示了我们的脚本在浏览器中预览时的功能：

![行动时间 - 编写我们的视差脚本](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642_03_05.jpg)

## *刚刚发生了什么？*

我们在这里使用窗口滚动函数，因为我们希望每次用户使用鼠标滚轮或浏览器滚动条滚动窗口时都触发我们的代码。

我们的变量 `yPos` 设置为负值，因为我们希望背景动画与正在滚动的页面元素朝同一个方向移动。 使用 `scrollTop()` 给我们当前 `window` 的垂直滚动条位置。 然后我们将该数字除以二。

我们使用 `css()` 方法来设置我们的背景位置。 值 `50%` 是用于 x 轴的，即浏览器的水平轴。 这告诉我们的背景图像在垂直方向上居中。 y 轴（或此处的 `yPos`）设置为我们上面的变量 `yPos`，然后附加 `px` 以告诉脚本这个数字是以像素为单位的。 `yPos` 控制图像的水平放置，因此水平居中背景图像。

## 自定义速度和方向效果

尝试更改 `yPos` 被除的数字的值，然后尝试将负数更改为正数。 更改这些值会影响我们的背景位置滚动的速度和方向。

## 知识问答 - `scroll()` 和 `scrollTop()` 方法

Q1\. `scroll()` 方法是做什么的？

1.  滚动到集合中的下一个同级元素

1.  允许您平滑地滚动到页面上的元素或数字值（以像素为单位）

1.  允许在每次选择的元素滚动时运行代码

1.  当设置为 `false` 时，启用页面上的禁用滚动

Q2\. `scrollTop()` 方法是做什么的？

1.  跳回到页面顶部

1.  输出所选元素的当前滚动位置

1.  当与 `click()` 方法一起使用时，可以让您滚动到元素的顶部

1.  将选定的元素动画成像一张纸一样卷起来

# 摘要

在本章中，我们看了几个示例，它们在元素上动画背景图像。 我们学到的一些事情包括：

+   `animate()` 方法及其一些伟大的应用

+   使用 jQuery UI 为我们的脚本提供颜色动画支持

+   在元素之间淡入淡出背景颜色

+   链接 jQuery 方法在一起

+   视差动画，其中背景层以不同的速度和方向动画，以创造深度的幻觉

+   创建自动背景图像动画以及如何使它们在不同方向上动画

+   `scroll()` 和 `scrollTop()` 方法

在下一章中，我们将看看导航动画以及如何为这个常见的网站功能注入一些生机。我们将创建一个单页面滚动脚本，根据点击的链接跳转到页面中的各个部分。此外，我们还将研究如何更改元素的背景颜色，以吸引用户关注网站的特定区域。


# 第四章：导航动画

*在本章中，我们将讨论一些用于导航的动画方法。导航允许用户在我们的网站中的不同页面之间移动。在这个常见的网站功能中添加一些动画将为我们的 Web 项目增添一些情趣。辣味是好的！*

下面是本章我们将学习的内容：

+   当我们的鼠标指针进入和离开元素时，向元素添加和删除 CSS 类

+   使用`animate()`方法更改悬停元素的样式，同时指定持续时间

+   学习如何平滑地滚动窗口到页面元素

+   我们将制作一个示例，当单击链接时平滑滚动并更改页面背景颜色。花哨！

# 创建简单的导航动画

我们将从简单地在鼠标悬停在锚标签（`<a>`）上时更改背景颜色开始。这是导航动画的最简单形式，所以这是一个很好的开始。我们将通过向元素添加类来更改背景颜色。这将轻松地允许我们根据需要构建更多样式到类中。

### 注意

在本章中我们将再次使用 jQuery UI 来弥补 jQuery 2.0 中对颜色动画的支持不足。请参考上一章关于从哪里下载 jQuery UI 库。

## 配置 addClass()和 removeClass()

`addClass()`和`removeClass()`的语法可能如下所示（方括号表示可选参数）：

```js

$(selector).addClass( className [,duration] [,easing] [,complete] );

$(selector).removeClass( className [,duration] [,easing] [,complete] );

```

### 注意

重要的是要注意，`duration`不是`addClass()`或`removeClass()`的 jQuery 选项。这个选项是由 jQuery UI 添加的，并且被称为方法重写。

# 行动时间 - 设置我们的导航

让我们通过执行以下步骤创建我们的导航结构和基本动画：

1.  我们将从根据第一章的模板文件创建一个新文档开始，将其命名为`navigation-animation1.html`并保存在我们的`jquery-animation`目录中。

1.  接下来，我们需要在我们的 jQuery 库之后添加 jQuery UI 库，方法是添加这一行：

    ```js

    <script src="img/jquery-ui.min.js"></script>

    ```

1.  然后，我们将把以下 HTML 代码添加到我们新创建的文档中的`<body>`标签下：

    ```js

    <nav>

    <a href="#">链接 1</a>

    <a href="#">链接 2</a>

    <a href="#">链接 3</a>

    <a href="#">链接 4</a>

    <a href="#">链接 5</a>

    <a href="#">链接 6</a>

    <a href="#">链接 7</a>

    </nav>

    ```

1.  将以下代码保存到名为`navigation-animation1.css`的文件中，并将其链接到我们的 HTML 文档：

    ```js

    nav a {

    display:block;

    float:left;

    padding:5px 10px;

    background:#DDD;

    }

    nav a.hover {background:#F0F;}

    ```

1.  将此代码添加到我们的空匿名函数中，以便我们的脚本能够运行：

    ```js

    $("nav a").hover(function(){

    $(this).addClass("hover", 300);

    }, function(){

    $(this).removeClass("hover", 300);

    });

    ```

## *发生了什么？*

我们使用 `hover()` 处理程序告诉我们的导航链接当鼠标光标进入和离开元素时该做什么。我们还将持续时间设置为 `300`（毫秒），以便 `hover()` 方法动画略有延迟，并为我们提供所需的动画效果。

以下屏幕截图是说明动画应该如何工作的示例，通过从第一个链接移动光标到最后一个链接：

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642OS_04_01.jpg)

## 动手试一试 - 扩展我们的悬停样式

尝试一下，看看通过向我们的 `hover` 类添加其他样式可以实现什么其他效果。首先，尝试更改元素的 `height` 和 `position`。

# 使用 stop() 方法

上一个示例是一种简单的方式，允许轻松更新样式。您会注意到，如果您非常快地将鼠标悬停在所有导航链接上，来回多次并停止，动画会继续播放直到每个动画都播放完毕。这通常不是一种非常理想的效果，因此我们需要添加 `stop()` 方法来在下一个动画开始之前停止上一个动画。由于 `addClass()` 和 `removeClass()` 无法在动画队列中停止，因此我们需要调整我们的代码一点。为此，我们将使用 `animate()` 方法来允许我们停止动画。

# 行动时间 - 添加 `stop()` 方法

在下一个动画开始之前停止我们的动画，我们需要稍微修改我们的代码。在 `animate()` 效果之前添加 `stop()` 就是我们需要做的。

使用与之前相同的文件（`navigation-animation1.html`），我们将在我们的匿名函数中更新代码，用以下代码替换（新代码已突出显示）：

```js

$("nav a").hover(function(){

$(this).stop().animate({ backgroundColor:"#F0F" }, 300);

}, function(){

$(this).stop().animate({ backgroundColor:"#DDD" }, 300);

});

```

## *刚才发生了什么？*

现在，如果我们迅速将鼠标指针移动到导航链接上（来回移动光标），您会注意到上一个动画在下一个动画开始之前会停止。这比以前的动画更优雅。就像香辣一样，我们也喜欢优雅。

# 使用 `scrollTop()` 动画窗口

在上一章中，我们学习了如何使用 `scrollTop()` 来使我们 `<body>` 元素的背景图像在页面上以不同的方向和速度动画。在下一个示例中，我们将使用 `scrollTop()` 来通过平滑滚动到页面上的一个元素来动画窗口。

*平滑滚动* 动画方法可以用于向我们的用户视觉地指示窗口位置已根据他们在页面上采取的操作而更改，通常是在鼠标单击元素后。这种动画方法通常被称为*一页式*，正如我们将要构建的一样。

# 行动时间 - 编写我们的平滑滚动动画

在接下来的步骤中，我们将创建我们的平滑滚动、单页动画，它将动画到页面内容的不同部分：

1.  首先，让我们从使用我们的模板 `smooth-scrolling.html` 创建一个新文件开始，然后将其保存在我们的 `jquery-animation` 文件夹中。

1.  其次，我们将再次添加我们的 jQuery UI 库，方法是直接在我们的 jQuery 库下面插入以下代码（新代码已经被突出显示）：

    ```js

    <script src="img/jquery.js"></script>

    <script src="img/jquery-ui.min.js"></script>

    ```

1.  接下来，我们需要将以下 CSS 代码添加到一个名为 `smooth-scrolling.css` 的新文件中，并在 `smooth-scrolling.html` 中链接它：

    ```js

    body, html {

    margin:0;

    padding:0;

    }

    body {background:#CCC;}

    nav {

    width:100%;

    position:fixed;

    top:0;

    padding:10px 0;

    text-align:center;

    outline:1px dotted #FFF;

    background:#EEE;

    background-color:rgba(255, 255, 255, 0.9);

    }

    nav a {

    color:#222;

    margin:0 10px;

    text-decoration:none;

    }

    content {margin-top:50px;}

    content div {

    height:400px;

    margin:10px;

    padding:10px;

    outline:1px solid #FFF;

    background:#EEE;

    background-color:rgba(255, 255, 255, 0.8);

    }

    ```

1.  然后，我们将以下 HTML 代码添加到 `<body>` 标签下面：

    ```js

    <nav>

    <a href="#link1">链接 1</a>

    <a href="#link2">链接 2</a>

    <a href="#link3">链接 3</a>

    <a href="#link4">链接 4</a>

    <a href="#link5">链接 5</a>

    <a href="#link6">链接 6</a>

    <a href="#link7">链接 7</a>

    </nav>

    <div class="content">

    <div id="link1">链接 1</div>

    <div id="link2">链接 2</div>

    <div id="link3">链接 3</div>

    <div id="link4">链接 4</div>

    <div id="link5">链接 5</div>

    <div id="link6">链接 6</div>

    <div id="link7">链接 7</div>

    </div>

    ```

1.  最后，将以下内容添加到我们的匿名函数中：

    ```js

    $("a[href^='#']").click(function(e){

    var pos = $(this.hash).offset().top - 50;

    $("body, html").stop().animate({ scrollTop:pos }, 1000);

    e.preventDefault();

    });

    ```

## *刚才发生了什么？*

我们使用了 `click()` 处理程序与一个看起来复杂的选择器。我们使用的选择器意味着：选择所有 `href` 属性以井号 (`#`) 开头的锚标签 (`<a>`)。

对于这个示例，我们的选择器将是 `<body>` 标签，我们正在使用 `animate()` 方法来处理我们的繁重工作。再次使用 `stop()` 方法，以便在下一个动画开始之前停止前一个动画。我们设置一个名为 `pos` 的新变量，用来保存点击链接（`<a>`）距页面顶部的位置，使用 `offset().top`。此外，我们从 `pos` 变量中减去 `50` 作为偏移量，因为我们希望 `content` 元素的顶部落在导航栏的下方。我们将动画的持续时间设置为 `1000` 毫秒，因为我们希望动画从页面上的当前位置跳转到下一个位置需要 1 秒钟的时间。

# 平滑滚动和页面背景颜色

现在，让我们将上面学到的两种动画方法合并到一起。此示例将使用平滑滚动方法跳转到我们的链接元素，并同时更改页面背景颜色。

以下截图展示了在我们的导航栏中点击链接后对应链接的停止点：

![平滑滚动和页面背景色](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642OS_04_02.jpg)

# 行动时间-创建超级动画

将我们之前的两个示例合并在一起，我们需要创建一个新文件，并将来自两个示例的 CSS 和 jQuery 代码混合在一起。当然，我们需要进行一些调整，以使它们能够一起工作。

1.  使用文件模板创建名为 `navigation-animation2.html` 的新文档，并将其保存在我们的 `jquery-animation` 文件夹下。

1.  然后，将以下 CSS 代码放入一个名为 `navigation-animation2.css` 的新文件中，并在我们刚创建的 HTML 文档中链接它：

    ```js

    body, html {

    margin:0;

    padding:0;

    }

    body {background:#F00;}

    nav {

    width:100%;

    position:fixed;

    top:0;

    padding:10px 0;

    text-align:center;

    outline:1px solid #FFF;

    background:#EEE;

    background-color:rgba(255, 255, 255, 0.5);

    }

    nav a {

    color:#222;

    margin:0 10px;

    text-decoration:none;

    }

    content {margin-top:50px;}

    content div {

    height:400px;

    margin:10px;

    padding:10px;

    outline:1px solid #FFF;

    background:#EEE;

    background-color:rgba(255, 255, 255, 0.8);

    }

    ```

1.  最后，我们需要将以下代码放入我们的匿名函数中：

    ```js

    $("a[href^='#']").click(function(e){

    e.preventDefault();

    var link = $(this).index() + 1;

    var background = "";

    if (link == 1) {

        background = "#F00"        //红色

    } else if (link == 2) {

        background = "#FF5000"     //橙色

    } else if (link == 3) {

        background = "#FF0"        //黄色

    } else if (link == 4) {

        background = "#0F0"        //绿色

    } else if (link == 5) {

        background = "#0FF"        //浅蓝色

    } else if (link == 6) {

        background = "#00F"        //深蓝色

    } else if (link == 7) {

        background = "#F0F"        //紫红色

    }

    var pos = $(this.hash).offset().top - 50;

    $("body, html").stop().animate({ scrollTop:pos, backgroundColor:background }, 1000);

    });

    ```

## *发生了什么？*

我们做的第一件事是添加一个新的 `link` 变量。这将保存我们的用户点击的链接的索引值。我们将索引值递增了 `1`，因为 `index()` 方法是从零开始的，而且今天已经很长时间了，所以我们不想从零开始计数。

`background` 变量被声明以抵御那些肮脏的 JavaScript 错误怪物，一如既往。我们创建了一个 `if` 语句来处理背景颜色的十六进制值。`background` 变量被设置为点击的链接的颜色（我们定义的）。

我们这个魔术技巧的选择器将再次是`<body>`标签，因为我们既要滚动到页面上的另一个位置，又要改变页面的背景颜色。这与之前的代码相同，唯一不同的是，这次我们添加了`backgroundColor`，并且根据上面的 if 语句设置了值（背景）。

## 挑战英雄 – 进一步扩展脚本

尝试为我们合并的动画示例添加一些功能。以下是一些启发你的想法：

+   动态地将内容`<div>`元素的高度改变为窗口的高度（不要忘记添加窗口调整大小函数）

+   使用窗口滚动功能改变背景颜色，这样当你手动滚动页面时，颜色就会改变，而不仅仅是通过点击链接实现

+   当内容`<div>`元素通过点击链接或手动滚动页面进入视图时，进行淡入

+   自动滚动内容，无需点击链接

## 突击测验 – 符号^ 与 stop() 方法

Q1\. 我们在`<a>`选择器中使用符号^代表什么意思？

1.  它表示“等于”

1.  它表示“包含”

1.  它表示“以…开始”

1.  它表示“以…结束”

Q2\. `stop()`方法的作用是什么？

1.  它会停止所选元素的动画队列

1.  它会阻止页面加载

1.  它会停止页面上的所有动画

1.  它会阻止动画运行，直到页面重新加载

# 总结

在这一章中，我们学会了如何根据鼠标交互来改变元素的样式，使用`addClass()`和`removeClass()`，以及如何通过 jQuery UI 的方法覆盖来控制添加和移除这些类的速度（持续时间）。

接着，我们学会了如何平滑地将窗口滚动到页面上指定的元素。之后，我们将两个示例合并成了一个示例，这个示例可以平滑地滚动窗口并让页面背景颜色淡入。同时在这一章中，我们找到了一只小狗。什么？你没有找到小狗？你一定是错过了某个分号。

现在我们已经为我们的导航元素添加了一些活力，接下来，我们将在下一章中学习如何为我们的表单输入添加一些生命。下一章中我们将学到一些内容，包括表单验证动画，视觉上改变表单以提醒用户提交时出现问题，并且如何在需要用户修正输入时摇动表单。
