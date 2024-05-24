# jQuery 基础知识（一）

> 原文：[`zh.annas-archive.org/md5/9E8057489CB5E1187C018B204539E747`](https://zh.annas-archive.org/md5/9E8057489CB5E1187C018B204539E747)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

*jQuery 基础* 帮助您掌握史上最流行的开源库的核心能力。您将从选择器开始，学习 DOM 操作、事件、表单验证等最基本的 jQuery 部分。为了保持站点的运行速度，您将不得不测量其性能并加以改进。在此过程中，我们将向您展示许多易于记忆的最佳实践。最后，您将能够通过 jQuery 使您的站点比以往更加引人注目。

# 本书内容概要

第一章，*逐部分学习 jQuery*，快速介绍了 jQuery 并说明了它的创建原因。

第二章，*jQuery 选择器和过滤器*，展示了如何使用 jQuery 的最基本功能：查询文档对象模型（DOM）。

第三章，*操作 DOM*，指导您如何使用 jQuery 修改和替换屏幕上的元素的各种方式。

第四章，*事件*，解释了如何通过使用事件来响应用户和系统的交互使您的站点动态化。

第五章，*使用 jQuery 使您的站点华丽起来*，介绍了使用动画使您的站点生动起来的方法。

第六章, *使用 jQuery 改善表单*，提供了使用 jQuery 处理和验证用户表单数据并将其发送到服务器的示例和说明。

第七章，*与服务器通信*，深入介绍了使用 Ajax 从服务器发送和检索数据。

第八章，*编写稍后可读的代码*，讨论了克服 jQuery 被认为是难以阅读的意大利面条代码的方法。

第九章，*更快的 jQuery*，介绍了一些简单的技术来加速您的 jQuery 代码以及测量其性能的方法。

第十章，*通过插件受益于他人的工作*，介绍了 jQuery UI 和插件，这两者都可以通过使用他人编写的代码来更轻松地增强您的站点。

# 本书所需材料

要跟随本书中使用的代码，您所需的只是一款程序员文本编辑器。可以使用完整的集成开发环境（IDE），但并非必需。大多数示例可以直接在浏览器中运行，除了涵盖 Ajax 的示例。要运行 Ajax 示例，您需要一个 Web 服务器或带有内置服务器的 IDE。

# 这本书是为谁准备的

无论您是初学者还是经验丰富的开发人员，都可以在本书中找到您需要的答案。

# 约定

在本书中，您会发现一些区分不同信息种类的文本样式。以下是这些样式的一些示例及其含义的解释。

此文中的代码字词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄均显示如下：“根据调用的方法不同，文档方法会返回不同的内容。如果您调用 `document.getElementById`，它会返回元素对象，如果找不到该元素，则返回`null`。”

代码块设置如下：

```js
var $hide = $('#hide'),
        $show = $('#show'),
        $toggle = $('#toggle'),
        $allPictures = $('#allPictures')
```

当我们希望引起您对代码块特定部分的注意时，相关行或项目会以粗体显示：

```js
$(document).ready(function () {
    var $hide = $('#hide'),
        $show = $('#show'),
        $toggle = $('#toggle'),
        $allPictures = $('#allPictures');

    $hide.click(function () {
        $allPictures.hide();
    });
    $show.click(function () {
        $allPictures.show();
    });
    $toggle.click(function () {
 $allPictures.toggle();
 });
});
```

**新术语** 和 **重要单词** 以粗体显示。屏幕上看到的单词，例如在菜单或对话框中，会以这种方式出现在文本中：“用户界面由一个名为 **stop** 的按钮和一个水平规则组成。成员将出现在水平规则下方，并且消息将出现在按钮旁边。”

### 注意

警告或重要说明会以此类框的形式出现。

### 小贴士

小贴士和技巧看起来像这样。


# 第一章：逐步学习 jQuery

jQuery 无疑是互联网上最受欢迎的 JavaScript 库。根据[`builtwith.com`](http://builtwith.com)的数据，它被超过 87%的使用 JavaScript 库的网站使用。这是惊人的渗透率。很难相信 jQuery 自 2006 年以来一直存在。

在本章中，我们将开始让您熟悉 jQuery。我们将涉及以下主题：

+   为什么会创建 jQuery？

+   jQuery 的主要组成部分

+   为什么 jQuery 存在两个维护版本？

+   什么是内容交付网络？

# jQuery 出现之前的生活

2006 年也许并不久远，但它在互联网年代几乎就是一个世纪。如果你不同意，那么想想当时你用的是什么样的手机，如果你有的话。那个时候，最受欢迎的四款浏览器是 Internet Explorer、Firefox、Safari 和 Opera。Chrome 呢？那时还没有，直到 2008 年末才出现。在超过 80%的用户中使用的 Internet Explorer 是迄今最受欢迎的浏览器。

当时，微软似乎并不太关心是否符合标准。为什么要这样做呢？他们占据 80%以上的市场份额。如果一个网站必须选择，他们通常会选择与 IE 合作。但变革的风声已经如潮，80%可能看起来像是一个无法逾越的领先优势，但两年前，这个数字是超过 90%。由 Firefox 等其他浏览器领导的其他浏览器正在慢慢地削弱这一领先优势。许多人，包括开发者，正在转向其他浏览器，他们希望能在上面运行的网站。

不幸的是，编写 Web 应用程序现在很困难，过去更糟。JavaScript 不是最友好的编程语言。但 JavaScript 并不是问题，问题是浏览器。相同的代码在不同的浏览器上运行得不同。在一个上，它完美运行；在另一个上，它崩溃，令用户感到沮丧。

要理解浏览器实现的差异如何会导致开发者额外的工作量，让我们来看一下实现 JavaScript Ajax 调用。在 2006 年，**W3C**（**万维网联盟**）的标准并没有涵盖到`XMLHttpRequest`对象，这个对象是所有 Ajax 请求的核心。微软在 1999 年就用 Internet Explorer 5 实现了这项技术。不幸的是，他们选择将其实现为一个 ActiveX 控件。ActiveX 是微软的专有技术，其他浏览器无法以相同的方式实现它。Mozilla、Safari 和 Opera 选择将其实现为一个对象附加到全局窗口。因此，为了在所有浏览器上添加可以工作的 Ajax 网站，开发者必须编写、测试和维护两倍多的代码：一套是为 IE 设计的，另一套是为其他浏览器设计的。

你在想浏览器是否是 IE，然后做一些不同的事情有多难吗？嗯，你是对的，检测代码运行的浏览器并不难，但要可靠地做到这一点却很难，因为浏览器可以撒谎。根据 W3C 标准，检测浏览器的方法很简单：

```js
window.navigator.appName
```

这个属性应该返回浏览器的名称，但是如果你在 Chrome、Safari 或 Internet Explorer 上尝试它，它们都会返回相同的值，“Netscape”。怎么回事？正如我已经说过的，浏览器可以撒谎。

### 提示

**下载示例代码**

你可以从[`www.packtpub.com`](http://www.packtpub.com)的你的账户中下载示例代码文件，获取你购买的所有 Packt Publishing 图书。如果你在其他地方购买了本书，你可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以直接通过电子邮件接收文件。

在 90 年代，网站开始检测访问它们的浏览器。那时，实际上只有三种浏览器：网景导航器（Netscape Navigator）、微软的 Internet Explorer 以及开创浏览器时代的浏览器，NCSA Mosaic。Mosaic 由伊利诺伊大学厄巴纳-香槟分校的国家超级计算应用中心创建。在那个时候，浏览器霸权的真正战斗在微软和网景之间展开。公司们通过为其浏览器添加新功能来进行竞争。

网景为其浏览器添加的功能之一是框架元素。它非常受欢迎。当时许多网站只有在浏览器为网景导航器时才使用框架元素。他们通过`window.navigator.appName`或`window.navigator.userAgent`来检查是否为网景。导航器的代号是 Mozilla，它包含在用户代理字符串中。后来，当微软向 IE 添加了框架元素时，网站继续不向 IE 提供基于框架的内容，因为他们只通过名称而不是通过特性检测来识别浏览器。所以，IE 开始撒谎。它从`window.navigator.appName`返回网景，并在用户代理中包含 Mozilla。现在，出于历史兼容性考虑，许多其他浏览器也在撒谎。

处理浏览器兼容性问题有两种方法。第一种方法是我们已经展示过的：浏览器检测。浏览器检测比你想象的要困难，它可能会产生意想不到的副作用，就像网站尽管 IE 支持框架，但仍然无法向其提供框架一样。第二种技术是特性检测，也称为属性嗅探。在使用某个特性之前，你应该确保浏览器支持它。虽然这通常是更难编写的代码，但对用户来说更有益。如果一个浏览器版本不支持某个特性，那么下一个版本可能会支持。特性检测是 jQuery 中使用的方法。

### 提示

**最佳实践**

使用功能检测，而不是浏览器检测。如果您需要编写代码来自己检测一个功能，而不是使用 jQuery 或其他第三方解决方案，比如 Modernizr，始终使用功能检测，绝不使用浏览器检测。

# 为什么创建了 jQuery？

创建 jQuery 的一个主要原因之一是为了让开发人员摆脱不得不检查整个浏览器上以不同方式实现的无数功能。事实上，jQuery 的座右铭是“写得更少，做得更多”。jQuery 的目标之一是让开发人员摆脱编写管道代码，而集中精力添加功能到他们的网站上。

# jQuery 的主要组成部分

第一次查看 jQuery API 页面，[`api.jquery.com`](http://api.jquery.com)，可能会令人心烦意乱。它列出了 300 多种不同的方法。不要惊慌；这里有一个方法来处理这种疯狂。大多数 API 方法可以分为几个类别。

## DOM 选择

这些是给 jQuery 起名字的方法。它们帮助在**文档对象模型**（**DOM**）中找到您正在查找的元素或元素。如果您了解浏览器 JavaScript，您可能在想什么是大不了的呢？一直都可以查询 DOM。有 `document.getElementById`、`document.getElementsByClassName` 等等。但是 jQuery 的接口比任何这些方法都要干净得多。jQuery 使用 CSS 风格的选择器来解析 DOM，并且一致地返回一个 jQuery 对象作为零个或多个元素的数组。

文档方法根据您调用的方法返回不同的内容。如果调用 `document.getElementById`，它将返回一个元素对象，如果找不到该元素，则返回 null。对于 `document.getElementsByClassName`，它返回 `HTMLCollection`，一个类似数组的对象。

## DOM 操作

一旦您找到了一个元素，通常都希望以某种方式修改它。jQuery 有一套广泛的操作方法。内置的文档方法无法比拟。jQuery 的方法允许您删除或替换标记。您还可以在旧标记之前、之后或周围插入新的标记。

## 事件

能够处理事件对于创建动态网站至关重要。虽然现代浏览器基本上都遵循标准，但几年前情况并非如此。jQuery 使得可以从同一代码库支持现代和旧的浏览器。

## 表单

互联网上有很多网站都有一个或多个论坛，用于将用户信息发送回 Web 服务器。这些方法使得将信息发送回服务器变得更加容易。

## CSS 和动画

CSS 方法是便利方法，有助于处理类和元素的位置和尺寸。与内置的 JavaScript 方法不同，它们不仅仅是简单地读取类属性的字符串；它们允许您添加、删除、切换和检查类的存在。

动画方法简单易行，但可以为您的网站增添光彩。您不再需要接受一个出现或消失的标记；现在，它可以淡入淡出，甚至滑入滑出。如果您有兴趣，还可以使用 jQuery 的效果框架来创建自己的自定义动画效果。

## Ajax

正如我们已经讨论过的那样，Ajax 是 jQuery 的主要特性之一。即使您不需要支持旧版浏览器，jQuery 的 Ajax 方法也比浏览器的方法更清晰。它们还内置了对异步成功和错误函数的支持，甚至返回一个 JavaScript promise 对象。

## 辅助功能

最后，主要的 jQuery 方法组是关于辅助函数的，例如 `.each()`，用于对集合进行迭代。jQuery 还添加了用于确定 JavaScript 对象类型的方法，并且提供了语言中奇怪缺失的功能。此外，它还添加了其他不容易归类的方法。

# 为什么会有两个维护版本的 jQuery？

几乎经过了 7 年的开发，jQuery 开始显露其陈旧之态。1.8 版本是一个重大发布版本，包括对 Sizzle 选择器引擎的重写和对动画的改进，但还需要更多。接口存在一些不一致性，有许多已弃用的方法，以及需要彻底清理的大量代码。因此，1.9 版本的发布包括了 jQuery 和 jQuery 迁移插件。

jQuery 开发团队认为 1.9 版是如此重大的变化，以至于他们创建了 jQuery 迁移插件来帮助缓解过渡。迁移插件包括了所有已弃用的方法，听起来很奇怪，但在其开发版本中，它会在控制台记录使用已弃用的方法。这使开发人员可以得到一个可工作的站点以及一个了解需要修复的内容的方法。生产版本不会进行任何额外的记录。

几个月后，2.0 版本发布了，并带来了一个朋友。开发团队继续解决平台的重量和速度问题，决定不再支持 Internet Explorer 9 以下的所有版本。jQuery 中的大量代码是专门针对旧版本 Internet Explorer 中的怪异行为编写的。差异是显著的。jQuery 1.10 的最小化版本为 93 KB，而 jQuery 2.0 的最小化版本为 83 KB，大小减少了近 11%。

因此，目前和可预见的未来，将会有两个版本的 jQuery：支持大多数浏览器的 1.x 版本，包括 Internet Explorer 的 6、7 和 8 版本。2.x 版本支持所有现代浏览器，包括 IE 9 及更高版本。重要的是要注意，这两个版本具有相同的 API，尽管它们的内部不同。

# 精简版和非精简版之间的区别

对于每个 jQuery 的分支，都有两个版本：压缩和非压缩。非压缩版本仅用于开发。它允许你在调试时轻松步进 jQuery 代码，并提供更有意义的堆栈跟踪。压缩版本应该用于生产。它经过压缩，删除了所有不必要的空白和 JavaScript 变量和内部方法的重命名。压缩减少了文件的下载时间。jQuery 2.1.1 的开发版本为 247 KB，而生产版本仅为 84 KB。

如果有必要调试压缩版本的 jQuery，可以下载源映射文件。源映射允许您访问原始调试信息，并受到所有现代浏览器的支持，包括 IE。

# 什么是内容传送网络？

网站加载速度越快，就越能鼓励游客以后返回。加快页面加载速度的另一种方法就是使用**内容传送网络**，或**CDN**。CDN 的魔力有两个方面。首先，CDN 通常位于边缘服务器上，这意味着它们不是在单个物理位置托管，而是分布在互联网的多个位置。这意味着它们可以更快地被找到和下载。其次，浏览器通常会在用户的机器上缓存静态文件，加载本地文件比从互联网下载快得多。许多大大小小的公司都使用 CDNs。因此，有可能其中一家公司正在使用你网站所需的相同副本的 jQuery，并已经在用户的机器上本地缓存。因此，当你的网站需要它时，它已经存在，你的网站免费获得了良好的性能提升。

# 总结

现代浏览器比它们几乎被遗忘的祖先功能更强大。一位新的 web 开发人员会很容易想知道为什么 jQuery 存在。在本章中，我们通过看看 jQuery 出现的原因来探讨它的存在的原因，以及在 jQuery 出现之前 web 开发的情况。然后，我们将 jQuery 的 API 分解成易于理解的主要组件。我们了解了为什么 jQuery 有两个维护的版本，以及每个版本为什么有两个不同的形式。在下一章中，我们将开始深入研究 API，学习如何编写选择器和过滤器。


# 第二章：jQuery 选择器和过滤器

名称“jQuery”来自于该库快速而智能地查询**DOM**（**文档对象模型**）的能力。

在本章中，我们将学习如何自己查询 DOM，并且一旦我们有了一组项目，我们将学习如何使用过滤器进一步细化我们的数据集。我们将涵盖以下主题：

+   选择器和过滤器是什么

+   如何创建选择器

+   如何创建过滤器

+   如何根据元素属性进行查询

+   如何使用链式方法快速而整洁地继续查询

# jQuery 选择器

在每个浏览器网页的底层是 DOM。DOM 跟踪渲染到页面上的所有单个对象。能够找到 DOM 元素是创建动态网页的第一步。浏览器带有内置方法来查询 DOM。这些方法通常以`document`开头。有`document.getElementById`、`document.getElementsByClass`等等。这些方法的问题在于它们的接口既不一致也不完整。

jQuery 之所以得名于其查询 DOM 的能力。与浏览器方法不同，它的接口既完整又功能丰富。查询 DOM 的开始是创建选择器。选择器是一个字符串，告诉 jQuery 如何找到你想要的元素。由于它是一串文本，因此可能的选择器数量是无限的。但不要惊慌；它们都属于几个广泛的类别。

## 章节代码

本章的代码包含在一个名为`chapter02`的目录中。请记住，这是用于教学的示例代码，不适用于生产。代码做了两件特别乏味而值得一提的事情。首先，它使用内联 JavaScript，这意味着 JavaScript 包含在主页面的 HTML 中的脚本标签中。这违反了关注点分离的规则，可能会导致性能不佳的代码。其次，它大量使用警报。浏览器的`alert`方法是在屏幕上快速而肮脏地显示东西的一种方法，与`console.log`方法不同，所有浏览器都支持它。但不建议在生产中使用。警报无法进行样式设置，因此除非您的网站未进行样式设置，否则它们会显得非常突兀。其次，警报会使浏览器停止所有操作，并强制用户承认它们，这显然是会让用户快速变得烦躁的事情：

```js
    function showJqueryObject(title, $ptr) {
        var ndx, sb = title + "\n";

        if ($ptr) {
            for (ndx = 0; ndx < $ptr.length; ndx += 1) {
                sb += $ptr[ndx].outerHTML + "\n";
            }
            alert(sb);
        }
    }
```

用于显示 jQuery 对象的方法被命名为`showJqueryObject()`。它通过 jQuery 对象进行迭代，依次显示每个节点。现在，说实话，我只在这本书中使用这个方法。在开发自己的程序时，处理问题时，我通常依赖于浏览器的`console.log`方法。但由于并非所有浏览器都支持它，而且对支持它的浏览器来说，显示东西在屏幕上的最简单方法是编写自己的方法。

## 协议相对 URL

一件敏锐的读者可能会注意到的有趣事情是脚本标签中缺少了 URL 的协议。我不是网络安全专家，但我足够聪明，足以留意网络安全专家的警告，所有这些专家都会说混合使用 HTTP 协议是危险的。协议相对 URL 使得保持网站安全变得容易。现在，许多网站都会在开放的 HTTP 或安全的 HTTP（HTTPS）上运行。以前实现这一点需要从你自己的网站加载所有 JavaScript 库，放弃 CDN 的好处，或者包含一些复杂的内联 JavaScript 代码来检测你网站的协议，并使用`document.write`将一些新的 JavaScript 注入到页面中。

使用协议相对 URL，你只需省略 URL 中的协议。然后，当你的网站被加载时，如果它是通过 HTTP 加载的，则库也将通过 HTTP 加载。如果是通过 HTTPS 加载的，那么所有库也将通过 HTTPS 加载。

## jQuery 对象

在我们查看 jQuery 选择器的类之前，让我们先看看选择器返回了什么。调用选择器的结果始终是一个 jQuery 对象。jQuery 对象具有许多类似数组的功能，但它不是数组。如果你在其上使用 jQuery 的 `isArray()` 函数，它将返回 false。对于许多事情，这种差异并不重要，但偶尔你可能想要执行像 `concat()` 这样的操作，但不幸的是，这个数组方法在 jQuery 对象上不存在，尽管它有一个几乎相等的方法 `add()`。

如果没有找到匹配选择器的元素，则 jQuery 对象的长度为零。永远不会返回 null 值。结果是一个长度为零或更多的 jQuery 对象。理解这一点很重要，因为它减少了在检查 jQuery 调用结果时需要做的工作量。你只需检查长度是否大于零即可。

当调用 jQuery 时，你可以使用其正式名称`jQuery`，也可以使用其缩写名称`$`。此外，请注意，在 JavaScript 中，字符串可以以单引号或双引号开头，只要它们以相同的引号结束即可。因此，在示例中，你可能会看到单引号或双引号，而且通常没有选择单引号或双引号的原因。

### 注意

关于浏览器中 JavaScript 的有趣之处之一是，一些方法实际上不是 JavaScript 的一部分；相反，它们是由浏览器提供的。当你在非基于浏览器的环境中使用 JavaScript，比如 `node.js` 时，这一点就变得很明显。例如，文档方法的方法不是 JavaScript 的一部分；它们是浏览器的一部分。在 `node.js` 中，没有文档对象，因此也没有文档方法。浏览器方法的另外两个来源是 window 和 navigator 对象。

# 创建选择器

使 jQuery 选择器如此酷且易学的一点是它们基于 CSS 中使用的选择器；这在浏览器方法中并非如此。因此，如果您已经知道如何创建 CSS 选择器，那么学习 jQuery 选择器将毫不费力。如果您不了解 CSS 选择器，也不用担心；jQuery 选择器仍然很容易学习，并且了解它们将让您提前学习 CSS 选择器。

## ID 选择器

我们将要看的第一种选择器是 ID 选择器。它以井号开头，后跟所需元素的 ID 属性中使用的相同字符串。看看这个例子：

```js
<div id="my-element"></div>
var jqObject = $("#my-element");
or 
var jqObject = jQuery('#my-element');

```

从上述示例可以看出，选择器调用的结果是一个 jQuery 对象。我们可以自由地使用引号的任一样式。此外，我们可以使用正式名称或缩写名称进行调用。在本书的其余部分，我将使用简称`$`。`ID`选择器返回一个数组，其中包含零个或一个元素。它永远不会返回多于一个元素。

根据**W3C**（**万维网联盟**）规范，每个 DOM 元素最多可以有一个`ID 选择器`，并且每个`ID 选择器`必须对网页唯一。现在，我见过很多违反唯一性规则的网站。这些都是糟糕的网站；不要效仿它们。而且，它们有不可预测的代码。当存在多个具有相同 ID 的元素时，只返回一个元素，但没有规定应该返回哪一个。因此，代码可能会根据运行的浏览器不同而表现不同。

## 类选择器

我们将要检查的下一个选择器类型是类选择器。类选择器以句点开头，后跟所有所需元素的类的名称。与最多返回一个元素的 ID 选择器不同，类选择器可以返回零个、一个或多个元素。

元素中类的顺序无关紧要。它可以是第一个、最后一个或中间的某个类，jQuery 都可以找到它：

```js
var jqClassObject = $('.active');

```

## 标签选择器

有时，您想要的元素既没有 ID 也没有类名；它们只是具有相同的标签名称。这就是您将使用标签选择器的时候。它搜索具有特定标签名称的元素，例如`div`、`p`、`li`等等。要创建标签选择器，只需传递带引号括起来的标签名称：

```js
var jqTagObject = $('div');

```

## 结合选择器

如果我们想要在页面上将所有段落标签和所有包含`active`类的元素放在一个集合中，我们可以进行两次调用，然后使用 jQuery 的`add`方法将结果对象相加。更好的方法是组合选择器，让 jQuery 执行组合结果的繁重工作。要组合选择器，只需将两个或更多选择器放在字符串中并用逗号分隔：

```js
    var jqClassResults = $('.special'),
            jqTagResults = $('p'),
            jqTotal = jqClassResults.add(jqTagResults);

var jqTotal = $('.special, p'); // give me all of the elements with the special class and all of the paragraphs
```

重要的是要记住，逗号用来分隔选择器。如果忘记了逗号，你不会收到错误消息；你会得到一个结果，只是不是你所期望的结果。相反，它将是后代选择器的最终结果，这是我们马上就会讨论的一个东西。

## 后代选择器

有时，你希望选择的元素没有一个易于设计的选择器。也许它们都是特定元素的子元素或孙子元素。这就是后代选择器的用武之地。它们允许你将查询的焦点缩小到特定的祖先，然后在那里查询。后代选择器有两种类型：子选择器和后代选择器。所需的子元素必须是父元素的直接子元素。要创建一个子选择器，你需要创建父选择器，加上一个大于符号，然后加上要在父元素结果集中查找子元素的选择器。

考虑以下 HTML 标记：

```js
<ul id="languages">
    <li>Mandarin</li>
    <li>English
        <ul class="greetings">
            <li class="main-greeting">Hi</li>
            <li>Hello</li>
            <li>Slang
                <ul data-troy>
                    <li>What's up doc?</li>
                </ul>
            </li>
        </ul>
    </li>
    <li>Hindustani</li>
    <li data-troy="true">Spanish</li>
    <li>Russian</li>
    <li>Arabic</li>
    <li>Bengali</li>
    <li>Portuguese</li>
    <li>Malay-Indonesian</li>
    <li>French</li>
</ul>
```

还看一下以下代码：

```js
    var jqChildren = $('#languages>li');
    showJqueryObject("Direct", jqChildren);
```

上面的代码示例将返回所有是 `<ul id="languages">` 元素的子级的 `<li>` 标签。它不会返回 `<ul class="greetings">` 标签的子级 `<li>` 标签，因为这些是它的孙子：

```js
    var jqDescendant = $('#languages li');
    showJqueryObject("Direct", jqDescendant);
```

后代选择器几乎与子选择器完全相同，只是没有大于号。第二个查询将返回包含在 `<ul id="languages">` 中的所有 `<li>` 标签，而不管它们在后代树中的位置。

## 属性选择器

除了根据元素的基本特征（如名称、标签和类）选择元素外，我们还可以根据它们的属性选择元素。属性选择器在工作时有点棘手，因为它们的语法比较复杂。另外，请记住，与其他 jQuery 选择器一样，如果你的语法错误，不会收到错误消息；你只会得到一个长度为零的 jQuery 对象。

只有九个属性选择器，所以它们相当容易记住，具体如下：

+   `有属性`选择器

+   `属性等于`选择器

+   `属性不等于`选择器

+   `属性包含`选择器

+   `属性起始为`选择器

+   `属性结尾为`选择器

+   `属性包含前缀`选择器

+   `属性包含单词`选择器

+   `多个属性`选择器

让我们从最简单的一个开始：`有属性`选择器。它选择所有具有指定属性的元素。属性的值无关紧要；事实上，甚至不必有值：

```js
var jqHasAttr = $("[name]");
```

就选择器而言，这个非常简单。它由所需属性的名称括在方括号中组成。接下来的两个选择器略微复杂一些。

`Has Attribute` 选择器不关心属性的值，但有时，您需要属性要么具有特定的值，要么不具有特定的值。这就是 `Attribute Equals` 选择器及其相反者 `Attribute Not Equals` 选择器的作用。前者返回所有具有所需属性和所需值的元素。请记住，这必须是精确匹配；接近的东西不算。后者返回所有没有所需属性或者具有但不具有所需值的元素。`Attribute Not Equals` 选择器返回 `Attribute Equals` 选择器未返回的所有元素。有时这会让人感到困惑，但不应该。只要记住这两个选择器是相反的：

```js
    var jqEqualAttr = $('[data-employee="Bob"]');

    var jqNotEqualAttr = $('[data-employee!="Bob"]');
```

下面的三个选择器也彼此相关。每个选择器都寻找一个具有值的属性，只是现在值是子字符串而不是完全匹配。区分这三者的是它们寻找子字符串的位置。第一个选择器，`Attribute Contains`，在属性值的任何位置寻找子字符串。只要字符串包含在值中，它就通过：

```js
    var jqContainsAttr = $('[data-employee*="Bob"]');
    showJqueryObject("Contains Attribute", jqContainsAttr);
```

`Attribute Starts With` 选择器更加具体地指定了子字符串的位置。它要求字符串必须位于值的开头。值字符串不必完全匹配；只有字符串的开头必须匹配：

```js
    var jqStartsAttr = $('[data-employee^="Bob"]');
    showJqueryObject("Starts Attribute", jqStartsAttr);
```

`Attribute Ends With` 选择器将指定的字符串与值字符串的末尾匹配。如果值字符串的末尾与指定的字符串匹配，那就没问题。就像 `Attribute Starts With` 选择器一样，剩下的字符串不必匹配：

```js
    var jqEndsAttr = $('[data-employee$="Bob"]');
    showJqueryObject("Ends Attribute", jqEndsAttr);
```

区分这些选择器有点麻烦，因为它们只有一个字符的差异，但是如果您了解 JavaScript 正则表达式，您会认识到 jQuery 借鉴了它们。正则表达式中的 '`^`' 表示字符串的开头，它用于 `Attribute Begins With` 选择器。正则表达式中的 '`$`' 表示字符串的结尾，它用于 `Attribute Ends With` 选择器。`Attribute Contains` 选择器使用了星号 `*`，它是正则表达式通配符字符。

`Attribute Contains Prefix` 选择器在值字符串的开头寻找指定的字符串。它与 `Attribute Begins With` 选择器的区别在于，如果没有连字符，则字符串必须与值完全匹配。如果值中有连字符，则字符串需要与连字符匹配。

`Attribute Contains Word` 选择器检查值字符串中的指定字符串。这听起来可能与 `Attribute Contains` 选择器很相似，但有一个微妙的区别。指定的字符串必须被空白符包围，而 `Attribute Contains` 选择器不关心字符串在哪里或者什么是分隔它的：

```js
Attribute Contains Word Selector [name~="value"]
```

最后一个属性选择器是`Multiple Attribute`选择器，它只是前面任何属性选择器的组合。每个选择器都包含在自己的方括号内，并连接在一起。不需要任何分隔字符：

```js
Multiple Attribute Selector [name="value"][name2="value2"]
```

现在我们已经学会了一些选择元素的方法，让我们学习如何过滤我们选择的结果集。

# 创建基本过滤器选择器

过滤器将选择器调用的结果进一步减少。有三种类型的过滤器选择器：基本、子、内容。基本选择器仅在 jQuery 对象结果集上操作。子选择器在元素之间的父子关系上操作。内容过滤器处理结果集中每个元素的内容。

有 14 个基本过滤器选择器。第一组处理结果集中结果的位置。让我们首先处理它们。

最容易理解的之一是`:eq()`过滤选择器。当传递索引号时，它检索结果。它非常类似于访问 JavaScript 数组中的元素。就像数组一样，它是从零开始的，所以第一个元素是零，而不是一：

```js
var jqEq = $("a:eq(1)");
showJqueryObject("EQ Attribute", jqEq);
```

您可以通过在常规选择器后添加冒号和`eq(x)`来创建一个`:eq()`过滤选择器。这里的`x`是元素的索引。如果索引超出范围，将不会生成错误。

`:eq()`过滤器选择器允许您访问结果集中的任何项，只要您知道可能的索引范围。但有时候，这太费力了。您可能只想知道第一个或最后一个元素。对于这些情况，jQuery 提供了`:first`和`:last`过滤选择器。每个选择器都正如它们的名字所说的那样：它获取第一个或最后一个元素：

```js
    var jqFirst = $("a:first");
    showJqueryObject("First Attribute", jqFirst);
    var jqLast = $("a:last");
    showJqueryObject("Last Attribute", jqLast);
```

保持与索引操作的主题一致，有时我们想要获取到某个索引之前的所有元素或所有索引大于某个数字的元素。对于这些时候，有`:lt()`和`:gt()`选择器。`:lt()`选择器返回所有索引小于传递值的元素。`:gt()`选择器返回所有索引大于传递值的元素。这两个选择器还接受负值，它们是从结果集的末尾开始计数而不是从开头开始：

```js
    var jqLt = $("a:lt(1)");
    showJqueryObject("Less Than Selector", jqLt);
    var jqGt = $("a:gt(1)");
    showJqueryObject("Greater Than Attribute", jqGt);
    jqLt = $("a:lt(-4)");
    showJqueryObject("Less Than Selector", jqLt);
    jqGt = $("a:gt(-2)");
    showJqueryObject("Greater Than Attribute", jqGt);
```

最后两个基本过滤器非常方便。它们是`:even`和`:odd`选择器。它们非常简单，除了一个小小的怪异之处。JavaScript 是从零开始的，所以 0 是第一个元素，零是偶数，这意味着偶数选择器将获取第一个、第三个、第五个（以此类推）元素。另外，奇数选择器将获取第二个、第四个、第六个（以此类推）元素。看起来有些奇怪，但只要记住 JavaScript 是从零开始的就完全说得通。

剩下的基本属性过滤器没有清晰地归入任何类别。因此，我们将逐一讨论它们，从 `:animated` 选择器开始。`:animated` 选择器返回当前正在执行动画的所有元素。请记住，它不会自动更新，因此在运行查询时，事物的状态是在那时存在的，但之后事物会发生变化。

`:focus` 选择器返回当前选定的元素（如果它在当前结果集中）。对于这个选择器要小心。我将在后面的章节中讨论性能问题，但是如果不与结果集一起使用，这个选择器的性能可能非常差。考虑一下，你只是简单地调用以下内容：

```js
    var jqFocus = $(":focus");
    showJqueryObject("The Focused Element", jqFocus);
```

它将搜索整个 DOM 树以找到焦点元素，该元素可能存在，也可能不存在。虽然前面的调用会起作用，但是有更快的方法可以做到这一点。

`:header` 选择器是一个方便的实用方法，返回所有 `<h1>`、`<h2>`、`<h3>`、`<h4>`、`<h5>` 和 `<h6>` 元素。你自己制作这个方法的等效版本应该相当容易，但是为什么要费这个事呢，当这个快捷方式随手可得时：

```js
    var jqHeader = $(":header");
    showJqueryObject("The Header Elements", jqHeader);
```

`:lang` 选择器将查找所有与指定语言匹配的元素。它将匹配单独的语言代码，如 `en`，或者语言代码与国家代码配对，如 `en-us`。随着越来越多的全球性网站的重视，这个选择器每天都变得更加重要：

```js
    var jqLang = $("a:lang('en')");
    showJqueryObject("The Lang Elements", jqLang);
```

`:not` 选择器不是我的最爱之一。它对传递的选择器执行逻辑 `not` 操作。

它从 jQuery 的开始就存在了，但是在我看来，它导致了混乱的代码。而 jQuery 最不需要的就是更难以阅读的代码。我将在第六章中更多地讨论如何编写可读的 jQuery 代码，*使用 jQuery 改进表单*，但是现在，如果可以的话，你应该避免使用它：

```js
    var jqNot = $( "a:not(:lang('en'))");
    showJqueryObject("The Not Elements", jqNot);
```

`:target` 选择器听起来很复杂，但是鉴于单页 JavaScript 应用程序的丰富性，它可能非常有用。它查看当前页面的 URL。如果它有一个片段，即用散列符号标识的片段，它将匹配 ID 与该片段相匹配的元素。这是 jQuery 的较新的添加之一，它是在 1.9 版本中添加的。

最后，让我们谈谈 `:root` 选择器。我要诚实地承认，我还没有需要使用这个选择器。它返回文档的根元素，这个根元素始终是 HTML 中的 `<html>` 元素：

```js
    var jqRoot = $( ":root");
    alert("The Root Element: " + jqRoot.get(0).tagName);
```

## 内容过滤器

只有四个内容过滤选择器。我会对所有这些选择器提出一个一般性的警告，因为它们可能性能不佳。我将在第七章中更详细地讨论性能，*与服务器交流*，但是在那之前，只有在必要时才使用这些选择器。

这些选择器中的前两个，`:empty`和`:parent`，是彼此的反义词。第一个，`:empty`选择器，返回所有没有子元素的元素。第二个，`:parent`选择器，选择至少有一个子元素的所有元素。

`:contains`选择器返回所有具有指定字符串的元素。字符串的大小写必须匹配。字符串可以位于任何后代元素中。

`:has()`选择器选择所有包含至少一个匹配项的元素。

接下来是子选择器。这些都涉及元素之间的父子关系。第一组很容易理解；它处理子元素在所有子元素中的位置。所有示例代码都将引用以下标记：

```js
<div>
    <p>I am the first child of div #1.</p>
    <p>I am the second child of div #1.</p>
    <p>I am the third child of div #1.</p>
    <p>I am the fourth child of div #1.</p>
    <p>I am the fifth child of div #1.</p>
</div>
<div>
    <p>I am the first child of div #2.</p>
    <p>I am the second child of div #2.</p>
    <p>I am the third child of div #2.</p>
</div>
<div>
    <p>I am the only child of div #3.</p>
</div>
```

首先是`:first-child`选择器；它选择所有作为其父元素的第一个子元素的元素。与`:first`选择器不同，它可以返回多个元素：

```js
    var jqChild = $('div p:first-child');
    showJqueryObject("First Child", jqChild);
```

示例代码的第一行说你应该获取所有`div`标签的段落后代。有三个定义的`<div>`标签；第一个有五个段落，第二个有三个段落，第三个只有一个段落。`:first-child`选择器查看这九个段落，并找到它们各自父元素的前三个子元素。这里它们是：

```js
<p>I am the first child of div #1.</p>
<p>I am the first child of div #2.</p>
<p>I am the only child of div #3.</p>
```

`:last-child`选择器的操作方式类似于`first-child`，只是它搜索其各自父元素的最后一个子元素：

```js
    var jqLastChild = $('div p:last-child');
    showJqueryObject("Last Child", jqLastChild);
```

再次，我们要求获取所有`div`标签的段落子元素，然后用子选择器过滤返回集。这个示例几乎与之前的示例相同，只是返回的元素是从末尾而不是从开头计数的：

```js
<p>I am the fifth child of div #1.</p>
<p>I am the third child of div #2.</p>
<p>I am the only child of div #3.</p>
```

如果你对最后一段`<p>我是第三个 div 的唯一子元素。</p>`与两个方法调用相同这一事实感到惊讶，不要惊慌。记住，它是第三个`<div>`的唯一子元素，因此它既是第一个也是最后一个子元素。

接下来，我们有`:nth-child()`选择器。它返回传递给方法的索引的子元素。`first-child`选择器可以被视为传递索引为 1 的这个选择器的特殊情况。正如我之前提到的，如果传递了超出范围的索引值，不会出现错误；你只会得到一个长度等于 0 的 jQuery 对象：

```js
    var jqNthChild = $('div p:nth-child(2)');
    showJqueryObject("Nth Child", jqNthChild);
```

关于这个和`:nth-last-child()`选择器的一个特殊之处是，除了传递索引值之外，你还可以传递一些特殊值。前两个特殊值是`even`和`odd`。这些将返回其各自父元素的偶数和奇数子元素。结果集与`:even`选择器的结果集不同。因为这些选择器是基于 CSS 的，计数从一开始，而不是 JavaScript 中的零。所以，看一下以下代码：

```js
    var jqNthChild = $('div p:nth-child(odd)');
    showJqueryObject("Nth Child", jqNthChild);
```

奇数参数将返回第一个、第三个、第五个（依此类推）元素：

```js
<p>I am the first child of div #1.</p>
<p>I am the third child of div #1.</p>
<p>I am the fifth child of div #1.</p>
<p>I am the first child of div #2.</p>
<p>I am the third child of div #2.</p>
```

`:nth-last-child()` 选择器与 `nth-child()` 选择器本质上相同，只是从列表末尾向前计数而不是从开头。同样，`:last-child` 选择器也可以被视为该选择器的特例，传递的索引为 1。和 `:nth-child` 选择器一样，它可以接受 even、odd 或公式等特殊参数：

```js
    var jqNthLastChild = $('div p:nth-last-child(3)');
    showJqueryObject("Nth Last Child", jqNthLastChild);
```

示例代码的结果集由两个元素组成，分别是它们各自父元素的倒数第三个子元素：

```js
<p>I am the third child of div #1.</p>
<p>I am the first child of div #2.</p>
```

子选择器中的最后一个是 `:only-child`。它返回其各自父元素的唯一子元素：

```js
    var jqOnlyChild = $('div p:only-child');
    showJqueryObject("Only Child", jqOnlyChild);
```

由于只有一个段落是唯一的子元素，所以下一个元素被显示：

```js
<p>I am the only child of div #3.</p>
```

接下来的选择器是 `of-type` 选择器。所有这些选择器都作用于相同元素类型的兄弟元素。其中第一个是 `:first-of-type` 选择器，它将返回每个父元素类型的第一个元素：

```js
    var jqFirstOfType = $('p:first-of-type');
    showJqueryObject("First Of Type", jqFirstOfType);
```

子选择器和 `of-type` 选择器之间的区别微妙但重要。`of-type` 选择器不指定父元素。你只需告诉 jQuery 关于子元素，它就会弄清哪些是兄弟元素，父元素是谁。

`:last-of-type` 选择器根据我们已经学到的关于 jQuery 的所有内容，做的正是我们所期望的。它返回了该类型的最后一个元素：

```js
    var jqLastOfType = $('p:last-of-type');
    showJqueryObject("Last Of Type", jqLastOfType);
```

`of-type` 选择器中的最后一个看起来很熟悉；它是 `:only-of-type` 选择器。像 `:only-child` 选择器一样，它返回唯一的子元素。但不像 `:only-child` 选择器，它查看元素的类型。所以，考虑到我们将第三个 `<div>` 更改为以下内容：

```js
<div>
    <p>I am the only child of div #3.</p>
    <span>Here is some text</span>
</div>
```

运行以下代码示例时，我们进行了更改：

```js
    var jqOnlyOfType = $('p:only-of-type');
    showJqueryObject("Only Of Type", jqOnlyOfType);
```

这将返回以下元素：

```js
<p>I am the only child of div #3.</p>
```

然而，使用 `:only-child` 选择器编写的相应代码不返回任何元素：

```js
    var jqOnlyChild = $('div p:only-child');
    showJqueryObject("Only Child", jqOnlyChild);
```

# 使用链接快速整洁地继续查询

jQuery 的一个好处是它能够链接查询。任何返回 jQuery 对象的方法调用都可以链接，这意味着你只需要添加一个句点和你的下一个方法调用。但要小心，因为并不是所有方法都返回 jQuery 对象。一些方法，如 `.width()`，返回无法链接的值。链中的每个方法都在前一个方法调用的结果集上执行其操作。如果在链的后续操作中执行过滤操作，则结果集将减少，链式方法将在减少的集合上工作而不是原始集合上。

下一个示例不是最好的，但希望它能开始展示链接的强大之处：

```js
    var jqLiUl = $("li").find("ul");
    showJqueryObject("LL UL", jqLiUl);
```

在这个示例中，我们首先要求页面上的所有 `<li>` 元素。然后，有了结果集，我们要求它包含的所有 `<ul>` 元素。我们可以用以下代码更简洁地请求：

```js
    var jqLiUl = $("li ul");
    showJqueryObject("LL UL concise", jqLiUl);
```

这里的要点是我们利用了 jQuery 的链式能力来在结果集上执行更多操作。通常情况下，您会使用链式来在链中的每个链接中执行不同的操作。您可能想在一个步骤中添加 CSS 类，对另一个步骤进行 DOM 操作，依此类推。为了清晰起见，请尽量保持所有操作相关，否则您可能会编写难以阅读的代码。

# 总结

在本章中，我们开始深入研究 jQuery，并希望发现它并不像从外面看起来那样复杂。我们也看到 jQuery 习惯于使用现有的做事方式。例如，它使用 CSS 选择器和与 JavaScript 正则表达式类似的符号。它还遵循一种常规模式来分解事物。一旦你习惯了这些模式，你几乎可以预测某些方法的存在。

现在我们已经学会了如何从 DOM 中读取元素，在下一章中，我们将学习如何向 DOM 写入标记，并开始制作动态网页。


# 第三章：操作 DOM

在上一章中，我们学习了如何使用 jQuery 的选择器来查找 DOM 中我们正在寻找的元素。在本章中，我们将利用这些知识首先找到元素，然后修改它们。我们将学习 jQuery 提供的不同方法，以帮助我们的网站既美观又动态。

jQuery 有三十多个方法以某种方式操纵 DOM，但不要让这个数字吓到你。所有方法都可以轻松分为四个不同的类别：尺寸和位置、类和样式、属性和属性以及内容。就像 jQuery 中的大多数事物一样，一旦你深入研究，你就会很快看到这些不同方法组之间的模式是如何相关的。

许多方法运行在两种模式之一：获取器或设置器。在获取器模式中，该方法从元素中检索或获取值，并将其返回给调用者。在设置器模式中，调用者向方法传递值，以便它可以修改匹配的元素集。我认为现在我们已经准备好开始处理尺寸和位置了。

许多方法有两种形式，它们只在选择器和内容的顺序上有所不同。一种版本将采用更传统的形式，即选择器然后是内容形式，另一种将采用内容然后是选择器形式。顺序颠倒的主要原因是链式操作。当一个方法返回一个包含我们需要的内容的 jQuery 对象时，能够使用内容优先版本给我们一个可以使用的方法。

本章将涵盖大量内容。以下是我们将深入探讨的主题：

+   尺寸和位置

+   读取屏幕和元素的大小

+   类和样式

+   JSON 对象

+   属性和属性

+   保持图片的比例

+   删除属性和属性

# 尺寸和位置

在 Web 开发中，我们通常倾向于不想处理元素大小的具体细节，但偶尔这样的信息会派上用场。在我们深入了解大小的细节之前，你需要知道一些事情。首先，只返回匹配集中第一个元素的大小。其次，读取大小会终止 jQuery 链，因此你不能在其后使用任何其他方法。最后，读取元素大小的方法不止一种。你选择的方法种类取决于你想要知道什么。让我们以读取宽度为例。

## 例子

在前一章中，我们从一个空白的网页开始，并添加了足够的 HTML 来解释每个方法的作用。在现实世界中，我们很少有一块空白的画布可以使用。所以在本章中，我们将使用一个看起来更完整的网页，它将基于非常受欢迎的 Bootstrap Jumbotron 模板。Bootstrap 是最受欢迎的 CSS 框架之一，在我们的示例中使用它将帮助你熟悉现代网站设计，因为如今很少有人编写自己的 CSS。我们不打算多谈 Bootstrap 或它的工作原理，但在 Packt Publishing 网站上有很多关于它的好书，包括*Learning Bootstrap*。

![示例](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ess/img/00002.jpeg)

## 开发者工具

大多数现代浏览器都有一组内置的开发者工具。如何激活这些工具因浏览器而异。在 Internet Explorer 中，按下*F12*会激活开发者工具。在 Chrome 和 Firefox 中，*Ctrl + Shift + I*可以完成这项工作。我们将使用开发者工具来查看控制台日志输出。通过将信息写入日志而不是使用`alert()`方法显示它，我们不会中断网站的流程，也不会在你在被允许继续之前被弹出窗口打扰。

大多数现代浏览器的控制台对象将附有许多方法，但我们只关心一个方法，即`log()`。我们将以最简单的形式使用`log()`方法：简单地输出字符串。希望示例代码在你运行它的任何浏览器上都能顺利运行。

## 读取屏幕和元素的大小

读取宽度有三种方法：`.width()`、`.innerWidth()`和`.outerWidth()`。第一个方法`.width()`只返回元素的宽度。接下来的方法`.innerWidth()`返回元素及其边框和填充的宽度。最后一种方法`.outerWidth()`返回元素加上边框和填充的宽度，并且如果你传递 true，它还会包括其外边距的宽度。

对于处理元素高度的每个方法，都有一个对应的高度方法。这些方法是`.height()`、`.innerHeight()`和`outerHeight()`。每个与其宽度对应方法类似。

为了确定显示的大小，你可以调用窗口的`.width()`和`.height()`方法：

```js
var screenWidth = $(window).width();
var screenHeight = $(window).height();
```

上面的代码检索了一个指向窗口元素的 jQuery 对象。第一行代码获取了窗口的宽度，第二行获取了它的高度。

尽量不要混淆窗口和文档。有时它们可能给出相同的结果，但要记住文档可以超出窗口的大小。当它超出时，将出现滚动条。它们不是等价的。

获取屏幕元素的尺寸是很好的，但有时候，你也需要知道它的位置。只有一个方法返回位置，它被命名为`.position()`。与其他值方法一样，它会打破链条，因为它返回一个对象，该对象包含相对于其父元素的位置的顶部和左侧值。

与`.position()`相对应的一个方法是`.offset()`。它们之间的区别很重要。`.offset()`方法返回相对于文档而不是其父元素的元素位置。使用`.offset()`方法允许我们比较具有不同父元素的两个元素，这是使用`.position()`方法几乎没有意义的事情。除非我们使用绝对或相对定位而不是浏览器默认的静态定位，否则我们通常看不到这两种方法之间的区别：

```js
// .position() vs. .offset()
var myPosition = $("body > .container > .row > .col-md-4:last").position();
console.log("My Position = " + JSON.stringify(myPosition));
var myOffset = $("body > .container > .row > .col-md-4:last").offset();
console.log("My Offset = " + JSON.stringify(myOffset));
```

该组中的最后两个方法是`.scrollLeft()`和`.scrollTop()`。这两种方法与其他方法不同，因为它们既是获取器又是设置器。如果传递了参数，`.scrollLeft()`会使用它来设置滚动条的水平位置。`.scrollTop()`方法执行类似的操作，设置滚动条的垂直位置。这两种方法将设置匹配集中每个元素的位置。

# 类和样式

类和样式组中的第一个方法是`.css()`。这个方法非常强大，展示了为什么 jQuery 是 HTML5 浏览器时代的必需和有用的库。`.css()`方法既是获取器又是设置器。作为获取器，它返回计算出的样式属性或属性。它接受一个字符串作为参数，该字符串是要检索的 CSS 属性的名称，或者是表示所有 CSS 属性的字符串数组：

```js
// .css(), retrieving a single property
var backgroundColor = $(".jumbotron > .container > p > a").css("background-color");
console.log("Background Color = " + JSON.stringify(backgroundColor));
// .css(), retrieving multiple properties in a single call
var colors = $(".jumbotron > .container > p > a").css(["background-color", "color"]);
console.log("Colors = " + JSON.stringify(colors));
```

上述代码的结果如下：

**背景颜色 = "rgb(51, 122, 183)"**

**颜色 = {"background-color":"rgb(51, 122, 183)","color":"rgb(255, 255, 255)"}**

## JSON 对象

大多数现代浏览器都包含 JSON 对象。JSON，就像 XML 一样，是一种数据交换格式。它是与语言无关的，轻量级的，易于理解的。添加到浏览器的 JSON 对象具有两个重要方法。第一个方法`.parse()`接受一个表示 JSON 对象的字符串，并将其转换为 JavaScript 对象。第二个函数`.stringify()`接受一个 JavaScript 对象，并将其转换为 JSON 字符串。这些方法旨在用于序列化和反序列化对象。但我们也可以在我们的示例代码中使用这些方法。`.stringify()`方法可以将 JavaScript 对象呈现为字符串，我们可以将这些字符串发送到控制台。

使用`.css()`方法的强大之处之一在于它可以理解多种不同格式中你引用的属性。举个例子，CSS 属性`margin-left`，DOM 将其称为`marginLeft`；jQuery 理解这两个术语是相同的。同样，它理解用于实际访问属性的浏览器方法，大多数浏览器称之为`getComputedStyle()`，但不同版本的 Internet Explorer 称之为`currentStyle()`或者`runtimeStyle()`。

`.css()`方法的设置模式有几种设置属性的方式。最简单的方法是简单地将属性名和它的新值作为参数传递进去。

```js
// .css(), passing a property name and value, change the button to orange
$(".jumbotron > .container > p > a").css("background-color", "orange");
```

你也可以通过将值设置为空字符串来以相同的方式移除属性。我们可以改变属性的另一种方式是将它们作为键值对传递给对象：

```js
// .css(), passing in multiple properties as an object
var moreProperties =; { "background-color": "pink", "color": "black"};
$("body > .container > .row > .col-md-4 .btn:first").css(moreProperties);
```

我们改变属性的最后一种方法是传递一个属性和一个函数。函数的返回值由 jQuery 用于设置属性。如果函数既不返回任何内容，也不返回"undefined"，那么属性的值就不会发生变化：

```js
// .css(), setting a random background color on each call
$("body > .container > .row > .col-md-4 .btn:last").css("background-color", function (index) {
   var r = Math.floor(Math.random() * 256),
           g = Math.floor(Math.random() * 256),
           b = Math.floor(Math.random() * 256),
           rgb = "rgb(" + r + "," + g + "," + b + ")";
   return rgb;
});
```

```js
When you only have one or two properties that you are changing in one element, you can get away with directly tweaking the CSS properties of the element. But a better and faster way is to put all of the changes into CSS classes and add or remove a class to/from the elements. jQuery has four methods that will help you manipulate the classes assigned to an element.
```

这个组的第一种方法是`.addClass()`，它将一个类添加到一个元素中。如果你使用 DOM 方法分配了一个类，你必须确保该类不会被重复分配，但是使用`.addClass()`，如果类已经分配给元素，它不会被重复分配。你不只是限于一次只分配一个类。你可以添加任意多个，只要确保每个类之间用空格分隔。

像许多其他的 jQuery 方法一样，`.addClass()`也有一个非常酷的额外功能：它也可以接受一个函数。这个有什么酷的呢？好吧，想象一下，你有一组按钮，你想根据它们在集合中的位置给每个按钮分配一个不同的颜色类。你可以很容易地编写一个函数来处理这种情况。jQuery 向函数传递两个参数。第一个是匹配集合中元素的索引。第二个参数是一个字符串，其中包含所有当前应用的类，每个类由一个空格分隔。下面是一个例子：

```js
// changes each of the buttons a different color
$("body > .container > .row > .col-md-4 .btn").addClass(function (index) {
   var styles = ["info", "warning", "danger"],
           ndx = index % 3,
           newClass = "btn-" + styles[ndx];

   return newClass;
});
```

最终，我们需要删除一个类，这就是为什么我们使用`.removeClass()`。取决于你传递给它的参数，它的行为会发生变化。如果你传递一个类名给它，它将删除该类。如果你传递多个由空格分隔的类名，它将删除这些类。如果不传递参数，它将删除所有当前分配的类。如果传递的类名不存在，就不会发生错误。

像`.addClass()`一样，`.removeClass()`也可以接受一个函数。jQuery 向函数传递一个索引和当前分配的所有类的字符串。要删除类，你的函数应该返回一个包含你想要删除的所有类名的字符串。

`.hasClass()`方法返回`true`，如果匹配集中的任何元素具有传递的类，则返回`true`。如果没有任何元素具有传递的类，则返回 false。请记住，如果你传递给它一个具有 100 个`<div>`的匹配集，只有一个具有传递的类名，该方法将返回 true：

```js
// does any of the divs have the .bosco class?
var hasBosco = $("body > .container > .row > .col-md-4").hasClass("bosco");
console.log("has bosco: " + hasBosco);
```

`.toggleClass()`方法是一个节省时间的便利功能。通常，我们会发现自己只是添加一个类（如果不存在）并删除它（如果存在）。这正是`.toggleClass()`被创建解决的场景。你传递给它一个或多个要切换打开或关闭的类。

你还可以传递`.toggleClass()`的第二个参数，一个布尔值，表示是否应该添加或删除类：

```js
// remove the info class
var shouldKeepClass = false;
$("body > .container > .row > .col-md-4 .btn").toggleClass("btn-info", shouldKeepClass);
```

它比简单调用`.removeClass()`的优势是，你可以将布尔值作为变量传递，并在运行时决定是否添加或删除类。

像其兄弟一样，你也可以将一个函数传递给`.toggleClass()`。函数传递一个索引，该索引是匹配集中对象的位置，当前类名和当前状态。它返回 true 以添加类，false 以删除类。

## 行为类

通常，你添加一个类来影响其外观。有时，你可能想要添加一个类以影响 JavaScript 如何处理元素。为什么要为行为使用类？这是因为类是布尔值，一个元素要么具有给定的类，要么没有。另一方面，属性是键值对，你需要知道属性是否存在以及它持有什么值。这通常使处理类比处理等价的属性更容易，在某些情况下，语法上更清晰。

# 属性和属性

在我们讨论处理属性和属性的方法之前，我们必须首先讨论一个更大的问题：属性和属性之间有什么区别？它们是不同的，但是怎么样？

当 DOM 从 HTML 属性构建时，构建包含在标记中的键值对。这些属性大多被转换为属性，并放置到 DOM 元素节点上。要理解的重要一点是，一旦构建了元素节点，属性将用于跟踪节点的状态，而不是属性。如果使用 jQuery 更新属性，则不会更新属性；如果是，JavaScript 会更改 DOM。它们表示 DOM 在首次加载时的状态，这是个问题。想想复选框：

```js
<input id="myCheckbox" type="checkbox" checked="checked" />
```

当 DOM 解析此复选框时，它会为此元素的节点创建一个已检查的属性。它还根据 W3C 规范中制定的规则创建一个 `defaultChecked` 属性。属性和属性之间的区别变得清晰起来。无论用户点击多少次复选框，`.attr()` 总是返回 `checked`，因为这是它在解析 HTML 时的状态。另一方面，`.prop()` 将根据当前实际状态从 "true" 切换到 "false"。

`.attr()` 方法从 jQuery 的一开始就存在。最初它被用来读取和设置属性和属性的值。这是一个错误；属性和属性是不同的，但理解这种区别是困难的。在 jQuery 1.6 中，引入了 `.prop()` 方法，并且将 `.attr()` 方法的范围限制在只能是属性。这打破了很多使用 `.attr()` 方法来设置属性的网站。这在 jQuery 社区引起了相当大的骚动，但现在已经平息。一般来说，如果你想要属性的当前值，请使用 `.prop()` 而不是 `.attr()`。现在我们理解了属性和属性之间的区别，让我们学习如何使用这些方法。

`.attr()` 方法既充当属性的获取器，也充当属性的设置器。当以获取器形式使用时，它将获取匹配集中第一个元素的属性。它只接受一个参数：要检索的属性的名称。当以设置器形式使用时，它将在匹配集中的所有成员上设置一个或多个属性。你可以以几种不同的方式调用它。第一种是用字符串中的属性名称和其设置值。第二种是通过传递一个包含你希望设置的所有属性值对的对象来调用它。最后一种是用属性名称和一个函数。函数将传递一个索引和属性的旧值。它返回所需的设置值。以下是一些示例：

```js
// setting an element attribute with an attribute and value
$("body > .container > .row > .col-md-4 .btn").attr("disabled", "disabled");
// setting an element attribute with an object
$("body > .container > .row > .col-md-4 .btn").attr({"disabled": "disabled"});
// setting an element attribute with a function
$("body > .container > .row > .col-md-4 .btn").attr("name", function(index, attribute){
   return attribute + "_" + index;
});
```

`.prop()` 方法在其获取器和设置器形式中都以与 `.attr()` 方法相同的方式调用。一般来说，当操作元素的属性时，这是首选方法。

## 保持图像比例

使用 `.attr()` 方法，你可以通过调整高度和宽度属性来调整图像的大小。如果你希望保持图像大小的比例而不必计算正确的宽度对应的高度或反之亦然，有一个简单的方法。而不是同时更改宽度和高度，删除高度属性并只修改宽度。浏览器将自动调整高度以与宽度成比例。

## 删除属性和属性

为了从元素中删除一个属性，我们使用 `.removeAttr()`。你可以用单个属性名称或用以空格分隔的多个属性名称来调用它。它有一个额外的好处，即在删除属性时不会泄露内存。

`.removeProp()`方法与`.removeAttr()`密切相关。请记住，您应该只从元素中删除自定义属性，而不是原生属性。如果您删除原生属性，比如 checked、disabled 等，它将无法添加回元素。您可能希望使用`.prop()`方法将属性设置为 false，而不是删除属性。

`.val()` 方法主要用于从表单元素中检索值。它从匹配集的第一个元素中获取值，该集包括输入、选择和`textarea`方法元素：

```js
// retrieving data from an input tag with .val()
var firstName = $('#firstName').val();
console.log("First name:" + firstName);
var lastName = $('#lastName').val();
console.log("Last name:" + lastName);
```

从输入标记中检索值非常容易，就像前面的代码所示。`.val()`方法提取元素的当前字符串值。

返回的数据类型取决于它从中检索数据的元素类型。如果它从输入标记获取数据，则返回类型为字符串。如果使用多个属性选择标记，则如果未选择任何项目，则返回类型为 null。如果选择了一个或多个项目，则返回类型为字符串数组，数组中的每个项都是所选选项的值。

```js
// .val() reading the value of a multiple select
var options = $('#vehicleOptions').val();
$.each(options, function (index, value) {
   console.log("item #" + index + " = " + value);
});
```

在其设置器形式中使用时，您可以将单个字符串值、字符串数组或函数传递给`.val()`。传递单个字符串是最典型的用例。它正是您所期望的：它设置元素的值：

```js
// using .val() to set the last name field
$('#lastName').val("Robert");
```

当您将字符串数组传递给设置了多个属性的选择元素时，它首先会清除任何以前选择的选项，然后选择所有值与传递的数组中的值相匹配的选项：

```js
// using .val() to select multiple new options
$('#vehicleOptions').val(["powerSeats", "moonRoof"]);
```

像另外两种方法`.attr()`和`.prop()`一样，您也可以传递一个函数。jQuery 将向函数发送两个参数：一个整数，表示匹配集中元素的索引，和一个表示元素当前值的值。您的函数应返回一个表示元素新值的字符串。

要检索元素的 HTML 内容，我们使用`.html()`方法。它将标记作为字符串返回：

```js
// .html() getting some markup
var html = $('#testClass').html();
console.log("HTML: " + html);
```

当`.html()`传递一个字符串时，它会将匹配集的所有元素设置为新的标记。您也可以将一个函数传递给`.html()`。该函数传递给这两个参数：索引和保存旧 HTML 的字符串。您从函数中返回一个包含新 HTML 的字符串：

```js
// .html() setting markup
$('#testClass').html("<div><h2>Hello there</h2></div>");
```

`.text()`方法检索匹配集中所有元素的文本内容。需要注意的是，就这个方面，此方法的操作方式与其他方法非常不同。通常，getter 仅从集合中的第一个元素获取数据。此方法将连接所有元素的文本，如果您没有预期到这一点，可能会产生令人惊讶的结果：

```js
// .text() getting text values
var comboText = $("select").text();
console.log(comboText);
```

需要注意的是，`.text()`方法用于文本，而不是 HTML。如果您尝试将 HTML 标记发送给它，它将不会被呈现。例如，让我们尝试向`.html()`方法成功发送的相同标记：

```js
// .text() trying to send HTML
$('#testClass').text("<div><h2>Hello there</h2></div>");
```

如果我们想要添加更多的 HTML 而不是替换它，我们可以使用`.append()`和`.appendTo()`方法。它们都会将传递的内容添加到匹配集中每个元素的末尾。两者之间的区别在于可读性，而不是功能性。使用`.append()`时，选择器先出现；然后是新内容。`.appendTo()`方法将此反转，使得新内容出现在选择器之前：

```js
// .append()
$("body > .container > .row > .col-md-4").append("<div><h2>Hello</h2></div>");
// .appendTo()
$("<div><h2>Goodbye</h2></div>").appendTo("body > .container > .row > .col-md-4");
```

`.prepend()`和`.prependTo()`方法与`.append()`和`.appendTo()`类似，只是内容放在每个元素的开头而不是结尾：

```js
// .prepend()
$("body > .container > .row > .col-md-4").prepend("<div><h2>Hello</h2></div>");
// .prependTo()
$("<div><h2>Goodbye</h2></div>").prependTo("body > .container > .row > .col-md-4");
```

前面的方法使新内容成为父级的子级。接下来的几种方法使新内容成为父级的同级。`.after()`和`.insertAfter()`方法将新内容添加为父级后的同级。与`.append()`和`.appendTo()`一样，两者之间的唯一区别是内容和选择器的顺序：

```js
// .after()
$("select").after("<h2>Hello</h2>");
// .insertAfter()
$("<h2>Goodbye</h2>").insertAfter("select");
```

`.before()`和`.insertBefore()`方法将新内容添加为父元素之前的同级。同样，它们之间的唯一区别是内容和选择器的顺序：

```js
// .before()
$("select").before("<h2>Hello</h2>");
// .insertBefore()
$("<h2>Goodbye</h2>").insertBefore("select");
```

`.wrap()`方法允许您用新元素包围匹配集中的每个成员：

```js
// .wrap() surrounds the button with a border
$("a").wrap("<div style='border: 3px dotted black;'></div>");
```

此方法不应与`.wrapInner()`方法混淆。两者之间的区别在于`.wrap()`将匹配集的每个成员用新元素包围起来。然而，`.wrapInner()`将匹配集的每个子元素用新内容包围起来。这两种方法的区别在示例代码中非常清晰。`.wrap()`方法用点线框包围每个按钮`<a>`标签。而`.wrapInner()`方法则将按钮的文本用点线框包围起来：

```js
// wrapInner() surrounds the button's text with a border
$("a").wrapInner("<div style='border: 3px dotted black;'></div>");
```

`.wrapAll()`方法会用新的 HTML 元素包围匹配集中的所有元素。要小心使用此方法；它可能会彻底改变您的网页。如果集合的成员相距甚远，可能会产生很大甚至负面的影响。在使用此方法时，一定要选择最狭窄的选择器：

```js
// wrapAll() everything
$("select").wrapAll("<div style='border: 3px dotted black;'></div>");
```

此组方法的最后一个成员是`.unwrap()`。它移除了匹配集的父元素。本质上，它是`.wrap()`的反向操作：

```js
// .unwrap() removes the divs we added earlier
$("a").unwrap();
```

保持删除标记的主题，我们有这些方法：`.remove()`、`.empty()`和`.detatch()`。这些方法中的第一个，`.remove()`，从 DOM 中删除匹配的元素集。元素及其所有子元素都将被删除：

```js
// .remove() deletes the a tags from the page
$("a").remove();
```

与之密切相关的`.empty()`方法也会从 DOM 中删除内容。两者之间的区别在于`.empty()`删除匹配集的子元素，而`.remove()`删除匹配的元素本身：

```js
// .empty() keeps the a tags but deletes their text
$("a").empty();
```

最后一个方法`.detached()`，与`.remove()`方法的行为类似，只有一个区别：被移除的内容以一组 jQuery 对象的形式返回给调用者。如果你需要将网页中的标记从一个地方移动到另一个地方，这就是你的方法。不要忘记你可以在这个方法上使用链式调用：

```js
// .detach() deletes the a tags from the page and returns them to the caller
var myButtons = $("a").detach();
$('hr:last').append(myButtons);
```

`.replaceAll()` 和与之密切相关的`.replaceWith()`方法分别用传递的内容替换匹配的集合。两者之间唯一的区别是选择器和内容的顺序。在`.replaceWith()`方法中，选择器首先出现；然后是新内容。在`.replaceAll()`方法中，新内容首先出现：

```js
// .replaceWith() replacing the selects with divs
$('select').replaceWith("<div>Replaced</div>");
```

`.clone()` 方法复制匹配元素集合的副本。它复制每个元素及其所有子元素，然后将它们作为 jQuery 对象返回给调用者：

```js
// .clone() makes a copy of the form then we insert the copy 
$('.myForm').clone().insertBefore('.myForm');
```

# 总结

这一章节是一个相当艰难的旅程，但希望你已经看到了 jQuery 的 DOM 操作方法是经过合理思考的。我们学习了如何在现有元素之前和之后添加内容到页面。我们还学习了如何从页面中删除内容，甚至如何将内容从一个位置移动到另一个位置。

我们还学习到许多 jQuery 方法有两种不同的形式，以便为我们提供一种方法来使用一个方法获取页面内容并使用另一个方法设置页面内容。还有一些简单但方便的信息，可以使用 JSON 对象保持图像的比例，并确定元素的大小。

即使我们学到了很多，我们的网站仍然是静态的；在执行完 JavaScript 后，它不会做任何其他事情。在下一章中，我们将改变这种情况。我们将学习如何使用事件使我们的网站可以交互。


# 第四章：事件

在前几章中，我们了解了如何在 DOM 中查找元素以及在找到它们后如何操作它们。在本章中，我们实际开始了解如何使用 jQuery 构建应用程序以及事件所起的重要作用。Web 应用程序使用事件驱动的编程模型，因此深入了解事件非常重要。没有事件，我们现在所知的 Web 应用程序将不可能存在。但在我们进一步深入之前，让我们先了解一下什么是事件。

**事件**是系统认为重要的任何事物的发生。它可以起源于浏览器、表单、键盘或任何其他子系统，也可以由应用程序通过触发生成。事件可以简单到按键，也可以复杂到完成 Ajax 请求。

虽然存在大量潜在的事件，但只有在应用程序监听它们时事件才重要。这也被称为挂钩事件。通过挂钩事件，您告诉浏览器此发生对您很重要，并让它在发生时通知您。当事件发生时，浏览器调用您的事件处理代码并将事件对象传递给它。事件对象保存重要的事件数据，包括触发它的页面元素。我们将在本章后面更详细地查看事件对象。以下是本章将涵盖的内容列表：

+   就绪事件

+   挂钩和取消事件

+   命名空间

+   事件处理程序和对象

+   向事件传递数据

+   事件快捷方式方法

+   自定义事件

+   触发事件

# 就绪事件

刚接触 jQuery 的事件编程者通常会学习的第一件事是 ready 事件，有时也被称为**文档就绪事件**。该事件表示 DOM 已完全加载，并且 jQuery 可以正常运行。就绪事件类似于文档加载事件，但不会等待页面的所有图像和其他资源加载完毕。它只等待 DOM 就绪。此外，如果就绪事件在挂钩之前触发，处理程序代码将至少被调用一次，与大多数事件不同。`.ready()`事件只能附加到文档元素上。仔细想想，这是有道理的，因为它在 DOM 完全加载时触发。

`.ready()`事件有几种不同的挂钩样式。所有样式都做同样的事情：它们挂钩事件。使用哪种挂钩取决于你。在其最基本的形式中，挂钩代码看起来像下面这样：

```js
$(document).ready(handler);
```

由于它只能附加到文档元素，因此选择器可以省略。在这种情况下，事件挂钩如下所示：

```js
$().ready(handler);
```

然而，jQuery 文档不推荐使用上述形式。此事件的挂钩有一个更简洁的版本。此版本几乎什么都省略了，只将事件处理程序传递给 jQuery 函数。它看起来像这样：

```js
$(handler);
```

虽然所有不同的样式都能起作用，但我只推荐第一种形式，因为它最清晰。虽然其他形式也能起作用并节省一些字节的字符，但这是以代码清晰度为代价的。如果你担心表达式使用的字节数，你应该使用 JavaScript 缩小器；它会比你手工做的工作更彻底地缩小代码。

准备事件可以挂接多次。当事件被触发时，处理程序按照挂接的顺序调用。让我们通过代码示例来看一下：

```js
// ready event style no# 1
    $(document).ready(function () {
        console.log("document ready event handler style no# 1");
    // we're in the event handler so the event has already fired.
    // let's hook it again and see what happens
        $(document).ready(function () {
        console.log("We get this handler even though the ready event has already fired");
    });
    });
// ready event style no# 2
    $().ready(function () {
        console.log("document ready event handler style no# 2");
    });
// ready event style no# 3
    $(function () {
        console.log("document ready event handler style no# 3");
    });
```

在上述代码中，我们三次挂接准备事件，每次使用不同的挂接样式。处理程序按照它们被挂接的顺序调用。在第一个事件处理程序中，我们再次挂接事件。由于事件已经被触发，我们可能期望处理程序永远不会被调用，但我们会错。jQuery 对待准备事件与其他事件不同。它的处理程序总是会被调用，即使事件已经被触发。这使得准备事件成为初始化和其他必须运行的代码的理想场所。

# 挂接事件

准备事件与所有其他事件不同。它的处理程序将被调用一次，不像其他事件。它也与其他事件挂接方式不同。所有其他事件都是通过将`.on()`方法链接到您希望触发事件的元素集来挂接的。传递给挂接的第一个参数是事件的名称，后跟处理函数，它可以是匿名函数或函数的名称。这是事件挂接的基本模式。它看起来像这样：

```js
$(selector).on('event name', handling function);
```

`.on()`方法及其伴侣`.off()`方法首次在 jQuery 的 1.7 版本中添加。对于旧版本的 jQuery，用于挂接事件的方法是`.bind()`。`.bind()`方法及其伴侣`.unbind()`方法都没有被弃用，但是`.on()`和`.off()`比它们更受青睐。如果您从`.bind()`切换，那么`.on()`的调用在最简单的层面上是相同的。`.on()`方法具有超出`.bind()`方法的能力，需要传递不同的参数集。我们将在本章后面探讨这些功能。

如果您希望多个事件共享相同的处理程序，只需在前一个事件之后用空格分隔它们的名称：

```js
$("#clickA").on("mouseenter mouseleave", eventHandler);
```

# 取消事件挂接

主要用于取消事件处理程序的方法是`.off()`，调用它很简单。它看起来像这样：

```js
$(elements).off('event name', handling function);
```

处理函数是可选的，事件名称也是可选的。如果省略了事件名称，那么所有添加到元素的事件都被移除。如果包括了事件名称，那么所有指定事件的处理程序都被移除。这可能会造成问题。想象一下这种情况：你为一个按钮编写了一个点击事件处理程序。在应用程序的后期，其他人需要知道按钮何时被点击。他们不想干扰已经工作的代码，所以他们添加了一个第二个处理程序。当他们的代码完成后，他们移除了处理程序，如下所示：

```js
$('#myButton').off('click');
```

由于处理程序只使用事件名称被调用，它不仅移除了添加的处理程序，还移除了所有关于点击事件的处理程序。这不是想要的结果。然而，不要绝望；对于这个问题有两种解决方法：

```js
function clickBHandler(event){
    console.log('Button B has been clicked, external');
}
$('#clickB').on('click', clickBHandler);
$('#clickB').on('click', function(event){
    console.log('Button B has been clicked, anonymous');
    // turn off the 1st handler without during off the 2nd
    $('#clickB').off('click', clickBHandler);
});
```

第一个解决方法是将事件处理程序传递给`.off()`方法。在前面的代码中，我们在名为`clickB`的按钮上放置了两个点击事件处理程序。第一个事件处理程序是使用函数声明安装的，第二个是使用匿名函数安装的。当按钮被点击时，两个事件处理程序都会被调用。第二个通过调用`.off()`方法并将其事件处理程序作为参数传递来关闭第一个处理程序。通过传递事件处理程序，`.off()`方法能够匹配你想要关闭的处理程序的签名。如果你不使用匿名函数，这种修复方法很有效。但是如果你想要将匿名函数作为事件处理程序传递怎么办？有没有办法关闭一个处理程序而不关闭另一个处理程序呢？是的，有；第二种解决方法是使用事件命名空间。

# 事件命名空间

有时需要能够在不使用处理程序函数的情况下区分相同事件的不同处理程序。当出现这种需求时，jQuery 提供了对事件进行命名空间的能力。要给事件设置命名空间，你需要在事件名称后加上一个句点和命名空间。例如，要给点击事件设置`alpha`的命名空间，执行以下操作：

```js
$("button").on("click.alpha", handler);
```

jQuery 只允许你创建一级深的命名空间。如果添加第二级命名空间，你不会创建第二级，而是为同一事件创建第二个命名空间。看一下下面的代码：

```js
$("button").on("click.alpha.beta", handler);
```

前面的代码等同于创建两个独立的命名空间，如下所示：

```js
$("button").on("click.alpha", handler);
$("button").on("click.beta", handler);
```

使用命名空间使我们能够更细粒度地处理我们的事件，以及如何在程序中触发它们。我们将在本章后面探讨如何以编程方式触发事件。

## 事件处理程序

到目前为止，我们只是大致了解了事件处理程序。我们使用了它，但并没有真正解释它。是时候纠正这一点，彻底了解事件处理程序了。让我们从 jQuery 传递给事件处理程序的内容开始。jQuery 将两个东西传递给每个事件处理程序：`event` 对象和 `this` 对象。`this` 对象是隐式传递的，这意味着它不像 `event` 对象那样是一个参数。它由 jQuery 设置为指向绑定事件处理程序的元素。JavaScript 中的 `this` 对象有点像 Java 和 C# 中的 `this` 或 Objective-C 中的 `self`；它指向活动对象。这非常方便，特别是当一组元素共享相同的处理程序时。`this` 对象的使用使得在许多其他元素中轻松地对正确的元素进行操作：

```js
$(document).ready(function(){
    // place a click event on the <li> tags
    $('ul> li').on('click', function(){
        console.log(this.id + " was clicked");
    });
});
```

在前面的代码中，我们在每个 `<li>` 标签上放置了一个点击事件。我们使用隐式传递给我们的 `this` 对象来告诉我们哪个 `<li>` 标签触发了事件。还要注意，我们没有使用事件参数，因为它对我们的示例不需要。

## 事件对象

事件对象是基于 W3C 规范的，并作为参数明确传递给所有事件处理程序，它拥有许多重要属性，其中许多属性对事件处理程序函数可能很有用。因为每个事件都不同，所以在事件对象中传递的属性值也不同。并非每个事件都填充每个属性，因此某些属性可能未定义。但有一些属性是通用的，我们将在下面详细探讨它们。

### event.target

这是触发事件的元素。这与绑定到事件处理程序的元素（由 `this` 对象指向的元素）不同。例如，如果单击一个没有处理程序但其父级 `<div>` 有处理程序的 `<a>` 标签，则事件会冒泡到父级。在这种情况下，`event.target` 指向 `<a>` 标签，但 `this` 对象指向 `<div>` 元素。让我们用代码来探索一下：

```js
$('#theParent').on('click', function (event) {
    console.log("this points to: "+this.id+", event.target points to: "+event.target.id);
    return false;
});
```

在示例中，我们在包围 `<a>` 标签的 `<div>` 标签上放置了一个点击事件处理程序。在 `<a>` 中没有放置处理程序。当单击 `<a>` 时，由于它没有电梯，它会将事件冒泡到其父级，即 `<div>` 标签。现在 `this` 对象将指向 `<div>` 元素，而 `event.target` 仍将指向 `<a>` 标签。

### event.relatedTarget

`relatedTarget` 属性在有效时也指向一个元素，但与触发事件的元素不同，它是与事件相关的元素。一个简单的例子是使用 `mouseenter` 事件。看看下面的代码：

```js
$("form").on('mouseenter', function (event) {
    console.log("target is: " + event.target);
    console.log("relatedTarget is: " + event.relatedTarget);
});
```

当触发`mouseenter`事件时，`relatedTarget`属性指向将接收`mouseleave`事件的元素。在我们的示例中，如果我们从顶部`<a>`开始并移动光标并跨越`<input>`标签，则相关目标将是包围`<a>`标签的`<div>`标签。

### event.type

此属性保存当前事件的名称。如果您对多个事件使用单个事件处理程序，这可能会派上用场：

```js
function eventHandler(event) {
    console.log("event type = " + event.type);
}
$("#clickA").on("mouseenter", eventHandler);
$("#clickB").on("mouseleave", eventHandler);
```

在上面的代码中，我们有两个共享相同处理程序的不同事件。当任一事件发生时，它显示事件类型以使我们能够将它们区分开。

### event.which

当鼠标或键盘事件发生时，可以使用此属性来告诉按下了哪个按钮或键。让我们快速看一个代码示例：

```js
$("#itemName").on('keypress', function (event) {
    console.log("key type: " + event.which);
});
```

按下键时，`which`属性保存键的代码，这是一个数字值。

### event.metaKey

这是一个简单的属性，它保存一个布尔值。如果在事件触发时按下了`metaKey`，则设置为`true`；如果没有按下，则设置为`false`。Macintosh 键盘上的`metaKey`方法通常是命令键；在 Windows 机器上，通常是 Windows 键。

### event.pageX 和 event.pageY

`pageX`和`pageY`属性保存鼠标相对于页面左上角的位置。这在创建随着用户移动鼠标而更新页面的动态应用程序时非常有用，就像在绘图程序中所做的那样：

```js
$(document).on('mousemove', function (event) {
    console.log("x position: " + event.pageX + ", y position: " + event.pageY);
});
```

在代码示例中，我们挂钩`mousemove`事件并动态显示鼠标当前的 x 和 y 位置。

### event.originalEvent

当事件发生时，jQuery 会对其进行归一化，以便每个浏览器中的事件表现出相同的行为。偶尔，jQuery 的标准化事件对象缺少原始事件对象具有的某些内容，而您的应用程序需要。正是出于这个原因，jQuery 在`originalEvent`属性中放置了原始事件对象的完整副本。

# 向事件传递数据

如果您曾经需要向事件传递数据，您需要做的就是在挂钩事件之后传递数据。您几乎可以传递任何类型的数据，但有一些注意事项。首先，如果数据是字符串，那么您还必须设置参数列表中它之前的可选选择器参数。如果您不需要选择器参数，可以将其设置为 null。其次，传递的数据不能是 null 或 undefined。以下是一个小示例，展示了如何向事件传递数据：

```js
// here we pass an object
// we don't have to pass the selector param
$('#clickA').on('click',{msg: "The answer is: ", val: 42}, function (event) {
    alert(event.data.msg + event.data.val);
    return false;
});
// here we pass a string as the data param. 
// Note the null selector param
$('clickB').on('click', null, "The answer is 42.", function(event){
    alert(event.data);
    return false;
});
```

在第二个事件挂钩中，我们传递了一个空的选择器参数，以避免混淆，因为我们将字符串作为数据参数传递。

# 事件快捷方法

Web 编程是事件驱动的，一些事件是如此常用，以至于 jQuery 已经创建了快捷方法来挂钩它们。以下两种方法是相等的：

```js
$(element).on('click', handling function);
$(element).click(handling function);
```

第二种形式更短，可能更易阅读，但有一个缺点。在简写形式中，没有办法添加额外的和可选的参数。如果你需要选择器或数据参数，那么必须使用长格式。以下是所有简写方法的列表：

```js
.change();
.click();
.dblclick();
.error();
.focus();
.focusin();
.focusout();
.hover();
.keydown();
.keypress();
.keyup();
.load();
.mousedown();
.mouseenter();
.mouseleave();
.mousemove();
.mouseout();
.mouseover();
.resize();
.scroll();
.select();
.submit();
```

# 创建您自己的事件

在 JavaScript 中创建自定义事件是常见实践。这样做有很多原因。首先，这是最佳实践，因为它促进了代码的松耦合。使用事件进行通信的代码不是紧密耦合的。这很容易做到；你可以以与为系统事件创建处理程序相同的方式为自己的事件创建事件处理程序。假设我们需要创建一个事件并希望调用`superDuperEvent`。这是创建其处理程序的代码：

```js
$(document).on('superDuperEvent', function (event) {
    console.log(event.type + " triggered");
});
$('#clickA').click(function(){
    $(document).trigger('superDuperEvent');
})
```

在代码中，我们创建了两个事件处理程序。第一个为我们的`superDuperEvent 方法`创建了一个处理程序。如果代码看起来与我们为系统事件创建的处理程序代码几乎相同，那么这就是意图。

# 触发事件

一旦为您的自定义事件创建了处理程序代码，您需要回答的下一个问题是：如何触发事件？这是我们还没有提到的事情，但你所需要的只是`.trigger()`方法。`.trigger()`方法执行与事件类型匹配的元素集绑定的所有处理程序。如上述代码所示，要触发我们的自定义事件，我们所需的就是在一组元素上调用`.trigger()`方法并传入事件的名称。

如果我们愿意，我们也可以将自定义数据传递给事件处理程序。再次强调，这与我们对常规事件所做的操作是一样的。我们只需调用`.trigger()`方法，然后在传递事件名称之后传递自定义数据：

```js
$(document).on('superDuperEvent', function (event, message) {
    console.log(event.type + " triggered with message: " + message);
});
$('#clickA').click(function(){
    $(document).trigger('superDuperEvent', ["Hello from the trigger function at: "+(new Date()).getTime()]);
})
```

如上述代码所示，向我们的事件处理程序传递数据可以做一件钩子事件绑定数据无法做到的事情：我们可以传递新鲜的数据。当我们在事件钩子中传递数据时，它永远不会改变，这限制了其有用性。但是在触发器中的数据可以每次调用事件时更改。看一下这个代码示例：

```js
$(document).on('superDuperEvent', function (event, message) {
    console.log(event.type + " triggered with message: " + message);
});
$('#clickA').click(function(){
    $(document).trigger('superDuperEvent', ["Hello from the trigger function at: "+(new Date()).getTime()]);
});
```

每次我们触发自定义事件时，我们向其传递当前时间的毫秒数。当挂接事件时，无法传递新鲜的数据。

# `.live()`和`.die()`方法的消失

从 jQuery 1.7 版开始，`.live()`方法及其伴侣`.die()`方法已被弃用。并且从版本 1.9 开始从库中删除了它们。尽管它们仍存在于 jQuery 迁移插件中，但不应用于编写新代码，并且应该重写任何旧代码使用它们。许多用户真的很喜欢这些方法，尤其是`.live()`方法。它被用来编写非常动态的代码。那么，为什么这些方法从库中删除了呢？

jQuery 文档在列出 `.live()` 方法的一些问题方面做得很好。其中最重要的是性能问题。尽管传递给选择器的内容不同，`.live()` 方法实际上绑定到了文档元素上。然而，它仍然会检索由选择器指定的元素集，这在大型文档中可能是耗时的。当事件发生时，它必须冒泡到文档才能被处理。这意味着每个由 `.live()` 处理的事件都保证要走最长、最慢的路径到其处理函数。

`.live()` 方法的行为与其他 jQuery 方法不同，这导致了 bug 的产生。它不支持事件链接，尽管看起来像支持。调用 `event.stopProgation()` 什么也不做，因为没有比文档更高级别的东西。它也不与其他事件协调。因此，决定废弃此事件并最终删除它。

# 深入研究 .on()

`.on()` 方法不仅仅是一个重命名的 `.bind()` 方法。它具有前者缺乏的功能。这些新功能的部分原因是为了给开发人员提供一种以与 `.live()` 方法相似的方式编写代码的方法。

`.on()` 方法有一个可选参数；`which` 选择器是一个字符串。大多数情况下，它并不是必需的，所以要么没有传递它，要么传递了一个空值。当你想要替换 `.live()` 方法而又不希望效率低下时，可以使用 `.on()` 方法：

```js
$(document).ready(function (event) {
    var count = 0;
        // hooks the live replacement
    $('#holder').on('click', "li", function (event) {
        console.log("<li> clicked: " + this.id);
    });
    // clicking on the a button will add another element to the ul
    $('#clickA').on('click', function (event) {
        var id = "Li_" + count++;
        $('#holder').append('<li id="' + id + '">' + id + '</li>');
    });
});
```

在上面的代码中，我们挂接了两个事件。首先挂接父元素，即 `<ul>` 标签，它将作为所有 `<li>` 标签的容器：现在存在的和以后创建的。然后，我们挂接了用于生成新 `<li>` 标签的按钮。每次我们创建一个新标签时，我们都会增加一个计数器并将其连接到用于新标签 `id` 的字符串，然后将其附加到 `<ul>` 标签上。

# 摘要

我们学到了 Web 编程中最重要的事情之一：事件。事件使网站具有交互性。我们首先从最重要的事件之一开始，即 jQuery 就绪事件。我们继续讨论挂接和取消挂接事件、命名空间，并最终使用事件对象编写事件处理程序。基础知识介绍完毕后，我们展示了如何编写自己的事件并触发它们。

在下一章中，我们将学习如何使用 jQuery 的内置和自定义动画使我们的网站变得流畅和精致。动画有助于使应用程序状态之间的过渡变得平滑。没有它，当页面上的元素突然出现和消失时，网站对用户来说可能会显得令人不适。


# 第五章：用 jQuery 使你的网站漂亮

动画对于任何现代、精致的 Web 应用程序的重要性很容易被低估。有时，添加动画似乎是一种轻率且几乎是不必要的浪费时间，因为它们似乎并没有为应用程序增添任何内容。但对于用户来说，动画有着巨大的影响。它们有助于平稳过渡从一个应用程序状态到下一个。它们还有助于给用户一种位置感。当用户点击一个按钮导致页面向左移动，点击另一个按钮导致页面向右移动时，用户从动画中得到了一种位置感。在本章中，我们将学习如何使用 jQuery 动画和效果来使我们的网站漂亮起来。

我们将涵盖以下主题：

+   动画的重要性

+   隐藏和显示元素

+   滑动元素

+   创建自定义效果

+   正确使用效果

# 动画的重要性

作为开发人员，我们很容易忘记我们的应用程序有多抽象。一个 *home* 的概念被嵌入到我们的开发人员大脑中，但与任何其他页面相比，我们网站的一页并没有什么家的感觉。但如果所有其他页面都似乎集中在一个页面上而没有标记它，那么在大多数用户眼中，那个页面就成了主页。

动画效果在过渡到下一个应用程序状态时非常有帮助。没有动画，很容易忽略页面中添加或删除元素的情况。诀窍在于熟练使用动画。动画永远不应该让用户感觉它们阻碍了他们的目标。

# 隐藏和显示元素

让我们用 jQuery 来看一下动画，其中最有用的两个是 `hide` 和 `show`。jQuery 为我们提供了 `.hide()` 和 `.show()` 方法，它们正如它们的名字所暗示的那样。直接使用这两种方法，它们不会动画化；它们作为简单的开关，立即隐藏或显示附加的一组元素。然而，它们都有几种调用方式。首先，让我们看一下 `.hide()` 方法，然后再看看它的伴侣，`.show()` 方法。

在其最基本的模式下，`.hide()` 方法被调用时不带任何参数，如下所示：

```js
$(elements).hide();
```

在这种情况下调用时，它立即隐藏指定的一组元素。在内部，jQuery 向元素添加了一个样式属性，属性为 "`display: none`"。这意味着元素既不可见，也在 DOM 中放弃了它的空间。`.hide()` 方法还接受可选参数：

```js
$(elements).hide(duration, easing, complete);
```

第一个参数是持续时间。它可以是字符串或整数。如果是整数，则是完成动画所需的毫秒数。如果是字符串，则必须是持续时间的两个提供的便利名称之一，即 `fast` 或 `slow`。Fast 相当于 200 毫秒，slow 相当于 600 毫秒。

在其基本模式下，`.show()` 方法也是不带任何参数被调用的，如下所示：

```js
$(elements).show();
```

当以这种方式调用时，它将立即显示指定的元素。jQuery 将删除具有属性"`display: none;`"的样式属性。`.show()`方法接受与`.hide()`方法相同的参数。

让我们更实际地看看如何使用这些方法：

```js
<body>
<div>
<button id="hide">Hide Pics</button>
<button id="show">Show Pics</button>
</div>
<div id="allPictures">
<img id="picture1" src="img/1" class="thumbnail"/>
<img id="picture2" src="img/2" class="thumbnail"/>
<img id="picture3" src="img/3" class="thumbnail"/>
<img id="picture4" src="img/4" class="thumbnail"/>
</div>
<script type="text/javascript">
    $(document).ready(function () {
        var $hide = $('#hide'),
            $show = $('#show'),
            $allPictures = $('#allPictures');

        $hide.click(function () {
            $allPictures.hide();
        });
        $show.click(function () {
            $allPictures.show();
        });
    });
</script>
```

在我们的示例应用中，有四个缩略图图像，由非常有用的网站提供，即 lorem pixel ([`lorempixel.com`](http://lorempixel.com))。Lorem pixel 为网页设计师提供占位图像，用于构建网站时使用。这些图像不应该用于生产。

占位符 URL 由主机站点组成，后面跟着所需图像的宽度和高度（以像素为单位）。接下来是图像的类别；在我们的案例中，它是`nature`，最后的数字标识了特定的图片。lorem pixel 网站上有关于如何为占位图像创建自己的 URL 的详细信息。

图像上方是一组按钮，触发缩略图上的操作。按钮被缓存在`$hide`和`$show`变量中。当单击隐藏按钮时，我们隐藏图像。当单击显示按钮时，我们执行相反的操作并显示图像。请注意我们如何通过将它们存储在 JavaScript 对象中而不是重新查找它们来缓存 jQuery 对象的方式。缓存它们在再次使用时会提高速度。在这个小应用中，这没有任何区别，但在更复杂的应用中，这可能会导致速度显著提高。我们将在第七章中更详细地讨论这个问题，*与服务器交互*。

### 提示

为了更容易知道哪些变量保存了 jQuery 对象，我们采用了以美元符号`$`开头的标准。一些开发人员不喜欢在变量名中使用助记符，但我发现这对我很有帮助，尤其是在阅读我的团队其他开发人员编写的代码时。

`hide`和`show`是如此密切相关，以至于 jQuery 有一个特殊的方法可以执行两者。`.toggle()`方法会在显示时隐藏元素，并在隐藏时显示元素。对于我们的用例来说，这是一个更合适的方法，所以让我们修改代码：

```js
$(document).ready(function () {
    var $hide = $('#hide'),
        $show = $('#show'),
        $toggle = $('#toggle'),
        $allPictures = $('#allPictures');

    $hide.click(function () {
        $allPictures.hide();
    });
    $show.click(function () {
        $allPictures.show();
    });
    $toggle.click(function () {
 $allPictures.toggle();
 });
});
```

我们只需要更改几行代码。首先，我们需要一个变量来保存切换按钮。然后，我们添加了钩子点击切换按钮的代码，最后，我们调用了`.toggle()`方法。切换按钮的好处是我们可以不断点击它，它将继续切换图片的状态。

隐藏和显示图片是有趣的，但并不是非常令人激动。因此，让我们在代码中添加持续时间。以下是应用程序的修改：

```js
$(document).ready(function () {
    var $hide = $('#hide'),
        $show = $('#show'),
        $toggle = $('#toggle'),
        $allPictures = $('#allPictures');

    $hide.click(function () {
 $allPictures.hide('slow');
    });
    $show.click(function () {
        $allPictures.show('fast');
    });
    $toggle.click(function () {
 $allPictures.toggle(1500);
    });
});
```

这次，我们只对三行进行了更改。每行都调用一个效果方法。我们将`slow`传递给`.hide()`方法，`fast`传递给`.show()`方法，将`1500`传递给`.toggle()`方法。记住，当一个整数被传递给一个效果方法时，它表示的是以毫秒为单位的时间，因此 1,500 表示 1.5 秒。

对我们目前已有的效果添加一些持续时间比简单地打开和关闭元素更吸引人，但让图像淡入淡出而不是缩小和放大可能更好。幸运的是，jQuery 提供了一些恰好可以做到这一点的方法：淡出和淡入。

## `.fadeOut()`

`.fadeOut()`方法逐渐将 CSS 不透明度属性减小到 0，使元素不再可见，然后将显示属性设置为`none`。该方法的参数与`.hide()`相同。

## `.fadeIn()`

`.fadeIn()`方法与`.fadeOut()`方法相反。它首先将显示属性设置为增加不透明度属性为 1，以便元素完全不透明。

## `.fadeToggle()`

与`.toggle()`方法类似，`.fadeToggle()`方法将会淡出元素（如果它们可见）并且淡入元素（如果它们不可见）。

为了更实际的例子，让我们将`.hide()`、`.show()`和`.toggle()`方法分别替换为`.fadeOut()`、`.fadeIn()`和`.fadeToggle()`：

```js
$(document).ready(function () {
    var $hide = $('#hide'),
        $show = $('#show'),
        $toggle = $('#toggle'),
        $allPictures = $('#allPictures');

    $hide.click(function () {
        $allPictures.fadeOut('slow');
    });
    $show.click(function () {
        $allPictures.fadeIn('fast');
    });
    $toggle.click(function () {
        $allPictures.fadeToggle(1500);
    });
});
```

在上述代码中，我们用它们的淡入淡出等效方法替换了隐藏/显示方法。代码仍然像之前一样运行，只是现在，我们有了一个新的动画效果：淡入淡出。

到目前为止，我们只使用了持续时间参数，但我们知道还有两个：`easing`和`complete`。让我们先查看`complete`，因为它相当容易理解。

`complete`参数是一个在动画完成后调用的函数。它没有显式传递任何参数，但隐式传递了指向动画元素的`this`对象。通过对我们的示例程序进行一些小的修改，我们可以看到这一点：

```js
$toggle.click(function () {
    $allPictures.fadeToggle(1500, function () {
 alert("Hola: "+this.id);
 });
});
```

在持续时间之后，我们添加了一个内联匿名函数，该函数在动画完成后调用。`this`对象指向动画元素，因此我们在警报消息框中显示它的`id`。完整函数对每个动画元素调用一次，这可能会让人感到惊讶。在我们当前的例子中，我们正在动画显示一些图片的`<div>`的内容。考虑到我们将我们的代码更改为以下内容：

```js
$toggle.click(function () {
    $('img').fadeToggle(1500, function () {
 alert("Hola: "+this.id);
 });
});
```

通过将我们的代码更改为指向各个`<img>`标签而不是它们的父`<div>`容器，完整函数现在针对每个标签调用一次，我们将逐个查看`<img>`标签的警报信息。

缓动参数处理动画对象的移动方式。在现实世界中，物体很少以恒定的速度移动。想象一下火车离开车站的情景。它慢慢加速离开。它缓慢加速直到达到所需速度，然后在某个时刻，它将开始减速，因为它接近下一个车站。如果我们将火车的速度图表化，它将是一条曲线，而不是一条直线。物体的加速和减速对我们来说似乎很自然，因为这是自然界中物体移动的方式，无论是火车，还是猎豹追逐羚羊，还是我们从桌子上站起来拿杯水。

jQuery 开箱即用提供了两种缓动效果：默认的名为 swing 和第二个称为 linear。到目前为止，我们一直在使用 swing，因为它是默认的。让我们也看看 linear，并比较两者：

```js
<div>
<button id="hide">Hide Pics</button>
<button id="show">Show Pics</button>
<button id="toggleSwing">Toggle Swing Pics</button>
<button id="toggleLinear">Toggle Linear Pics</button>
</div>
<div id="allPictures">
<img id="picture1" src="img/1" class="thumbnail"/>
<img id="picture2" src="img/2" class="thumbnail"/>
<img id="picture3" src="img/3" class="thumbnail"/>
<img id="picture4" src="img/4" class="thumbnail"/>
</div>
<script type="text/javascript">
    $(document).ready(function () {
        var $hide = $('#hide'),
                $show = $('#show'),
$toggleSwing = $('#toggleSwing'),
$toggleLinear = $('#toggleLinear'),
                $allPictures = $('#allPictures');

        $hide.click(function () {
            $allPictures.fadeOut('slow');
        });
        $show.click(function () {
            $allPictures.fadeIn('fast');
        });
$toggleSwing.click(function () {
 $allPictures.fadeToggle(1500, "swing");
 });
 $toggleLinear.click(function () {
 $allPictures.fadeToggle(1500, "linear");
 });
    });
</script>
```

在前述代码中，我们去掉了切换按钮，并用两个新的切换替换它：一个使用 `"swing"`，另一个使用 `"linear"`。我们还创建了两个事件处理程序来实现适当的淡入和淡出。虽然两种缓动之间的差异很细微，但确实存在。当物体在移动时更加明显。因此，在下一节中，我们将介绍滑动动画，并看看我们的两种缓动效果如何。

# 将元素滑动

下一组方法的调用方式与前两组相同。滑动方法与显示和隐藏方法非常相似，不同之处在于，它只改变集合元素的高度维度，而不是宽度维度。

## .slideUp()

`.slideUp()` 方法将一组元素的高度减小到零，然后将显示属性设置为 `none`。该方法采用了与之前讨论过的相同的三个可选参数：`duration`、`easing` 和 `complete`：

```js
$(elements).slideUp([duration],[easing], [complete]);
```

## .slideDown()

`.slideDown()` 方法将一组元素的高度增加到 100%。它的调用如下：

```js
$(elements).slideDown([duration],[easing], [complete]);
```

## .slideToggle()

此组的最后一个成员是 `.slideToggle()` 方法，它会在显示状态和隐藏状态之间交替切换一组元素：

```js
$(elements).slideDown([duration],[easing], [complete]);
```

我们已经修改了代码，使用了滑动方法而不是淡入淡出方法。缓动方法现在更加明显不同。这是更改后的代码：

```js
$hide.click(function () {
    $allPictures.slideUp('slow');
});
$show.click(function () {
    $allPictures.slideDown('fast');
});
$toggleSwing.click(function () {
    $allPictures.slideToggle(1500, "swing");
});
$toggleLinear.click(function () {
    $allPictures.slideToggle(1500, "linear");
});
```

由于 jQuery 动画方法的调用方式都很相似，我们只需简单地将 `fadeOut`、`fadeIn` 和 `fadeToggle` 这些词替换为它们的滑动效果对应词即可。

我认为我们已经花了足够的时间研究基本动画效果。真正有趣和引人注目的是自定义效果。

# 创建自定义效果

jQuery 并没有包含许多效果；开箱即用，只有隐藏和显示、淡入和淡出以及滑动方法。如果只有这些，可能不值得将它们包含在库中。幸运的是，jQuery 让我们可以创建自己的动画。

## .animate()

理解 `.animate()` 方法是理解如何创建自定义效果的关键。虽然其他方法也很重要，但在让动画方法生效之前，它们都无济于事，而让动画方法生效其实并不太难，特别是如果你记住动画属性的工作原理的话。它通过操纵 CSS 属性的值来实现。大多数——但不是全部——属性都可以操纵。让我们快速查看一下，以更好地解释 `.animate()` 方法的工作原理：

```js
<div>
<button id="hide">Hide Pics</button>
<button id="show">Show Pics</button>
<button id="toggleSwing">Animate Swing Pics</button>
<button id="toggleLinear">Animate Linear Pics</button>
</div>
<div id="allPictures" style="position: relative;">
<img id="picture1" src="img/1" class="thumbnail"/>
<img id="picture2" src="img/2" class="thumbnail"/>
<img id="picture3" src="img/3" class="thumbnail"/>
<img id="picture4" src="img/4" class="thumbnail"/>
</div>
<script type="text/javascript">
    $(document).ready(function () {
        var $hide = $('#hide'),
                $show = $('#show'),
                $toggleSwing = $('#toggleSwing'),
                $toggleLinear = $('#toggleLinear'),
                $allPictures = $('#allPictures');

        $hide.click(function () {
            $allPictures.slideUp('slow');
        });
        $show.click(function () {
            $allPictures.slideDown('fast');
        });
        $toggleSwing.click(function () {
 $allPictures.animate({left: "+=200"}, 1500, "swing");
        });
        $toggleLinear.click(function () {
$allPictures.animate({left: "-=200"}, 1500, "linear");
        });
```

我们对我们值得尊敬的示例进行了一些修改。我们改变了按钮的文本，添加了两个 `.animate()` 方法，并且还不得不添加一个相对于 `allPictures<div>` 的定位样式。相对定位的添加非常重要，其缺失可能是动画困扰的根源。jQuery 的动画函数不会改变 CSS 规则。为了移动 `<div>`，它必须是可移动的。缺少位置属性的元素默认为位置 static，这意味着它们与页面的布局一起定位，无法移动。所以如果你尝试对其进行动画，什么也不会发生。将 `<div>` 放置在相对定位中意味着它可以相对于其布局位置移动。

`.animate()` 方法接受我们已经熟悉的三个参数——持续时间、缓动和完成回调——并添加一个新参数：properties，其中包括我们希望动画的一个或多个 CSS 属性。属性的值可以是绝对的或相对的。如果你只是在属性中放入一个值，那么它是绝对的。jQuery 将会动画到这个值。如果你尝试第二次运行绝对动画，什么也不会发生，因为属性已经包含了所需的值。另一方面，相对值更具方向性。在早期的示例应用程序中，我们使用了两个不同的相对属性值。第一个告诉 jQuery 将 `<div>` 向右移动 200 像素。第二个，附加到切换线性按钮，告诉 jQuery 将 `<div>` 向左移动 200 像素。要使用相对值，只需将值放在引号中，并在前面加上 `+=xx` 或 `-=xx`，其中 `xx` 是要更改属性的量。

你可以一次修改多个属性。当你添加更多属性时，jQuery 将逐个动画到其值：

```js
$toggleSwing.click(function () {
    $allPictures.animate({
 left: "+=200",
 top: "+=200",
 opacity: "-=1"
    }, 1500, "swing");
});
$toggleLinear.click(function () {
        $allPictures.animate({
 left: "-=200",
 top: "-=200",
 opacity: "+=1"
    }, 1500, "linear");
});
```

在前面的示例中，我们给每个 `.animate()` 方法添加了两个更多属性：top 和 opacity，都像 left 属性一样是相对的。关于动画方法的一个重要事项是，与 show/hide、fade 或 slide 方法不同，它从不将 `"display: none"` 样式添加到元素。即使不透明度为 0，元素仍然占据页面上的所有空间。

## .delay()

动画可以通过将动画方法链接在一起按顺序运行。您还可以使用`.delay()`方法为动画引入延迟。它接受两个参数：持续时间和队列名称。`持续时间`告诉您应该暂停动画引擎多长时间（以毫秒为单位），而`queueName`是要延迟的队列的名称。在本书中，我们不会使用命名队列，因此我们不会讨论队列名称：

```js
$toggleSwing.click(function () {
    $allPictures
 .animate({
 left: "+=200"
 }, 1500, "swing")
 .delay(1000)
 .animate({
 top: "+=200",
 opacity: "-=1"
 }, 1500, "swing");
});
$toggleLinear.click(function () {
    $allPictures
 .animate({
 top: "-=200",
 opacity: "+=1"
 }, 1500, "linear")
 .delay(1000)
 .animate({
 left: "-=200"
 }, 1500, "linear");
});
```

在此示例中，我们将两个单独的动画链接在一起，并在它们之间延迟 1 秒。请注意，如果您快速按下任一按钮，很快，`<div>`将从页面中消失，并且可能再也看不到。这个问题是由于 jQuery 将每个新的动画请求添加到队列中引起的。很容易比 jQuery 执行它们更快地将项目添加到队列中。我们将在下一节中解决这个问题。

## `.queue()`、`.dequeue()`和`.clearQueue()`

队列方法为我们提供了访问 jQuery 用于运行动画的动画队列。jQuery 允许我们有多个队列，但很少需要多个队列。`.queue()`方法可用于获取和设置标准动画队列或自定义队列。我们可以使用队列方法查看当前队列中有多少项目，并且我们可以将回调函数传递给它，一旦队列为空，就会调用该函数。

当队列被停止并添加了新项目时，`.dequeue()`方法很方便。为了让队列再次运行，必须调用`.dequeue()`方法。`.clearQueue()`方法从队列中移除尚未执行的所有排队项目。

## `.stop()`和`.finish()`

`.stop()`方法停止当前动画。如果正在运行动画有关联的回调，则不会调用它们。`.finish()`方法与此非常相似，只是它做了所有事情。它停止正在运行的动画，清除队列，并完成匹配集的所有动画。

## jQuery.fx.interval 和 jQuery.fx.off

这些是 jQuery 内部的两个全局变量。`jQuery.fx.interval`方法设置动画速率。值越低，动画运行得越快，可能更平滑。一般来说，您可能不想改变此值。这是全局动画计时器。更改它会更改所有动画的时间，而不仅仅是您的动画。当`jQuery.fx.off`方法设置为 true 时，它会停止所有动画。

# 正确使用效果

当 jQuery 遇到需要执行的新动画时，它将新动画放在动画队列的末尾。虽然这在大多数情况下是处理事情的好方法，但可能会通过更快地将项目放入队列中而超载队列。一般来说，当向队列中添加更多项目时，您应该小心。您可能希望在向队列添加更多项目之前清除队列。

尽管 jQuery 的动画特性非常方便，但它们并不完全是最先进的，它们开始显得有些过时了。jQuery 源代码中可以看到一个例子。以下代码来自 jQuery 版本 2.1.1 的源代码：

```js
jQuery.fx.start = function() {
    if ( !timerId ) {
        timerId = setInterval( jQuery.fx.tick, jQuery.fx.interval );
    }
};
```

在运行动画时，jQuery 使用 `setInterval()` 方法来定时每个动画帧；事实上，`jQuery.fx.interval` 全局值被用作计时器值。虽然几年前这很酷，但大多数现代浏览器使用 `window.requestAnimationFrame()` 方法，对于缺乏该方法的浏览器，有可用的 polyfill。使用 `setInterval` 方法而不是 `requestAnimationFramework` 的最终效果是，即使在最新的浏览器和最快的硬件上，jQuery 的动画看起来仍然有点闪烁，因为渲染帧和 `setInterval` 方法之间没有协调，就像使用 `requestAnimationFrame` 一样。

# 摘要

我们在本章涵盖了大量代码。动画可能看起来很容易编写，但是当做得好时，它们可以为应用程序增加很多内容，并帮助用户了解应用程序状态的变化。我们首先学习了如何使用 jQuery 的易于使用的内置动画方法。一旦我们理解了它们，我们就转向了 `.animate()` 和 `.delay()` 方法，这些方法允许我们创建自己的自定义动画。

我们用一点关于 jQuery 执行动画的信息结束了本章。虽然在示例中显示的简单示例中是可以的，但实际上有点过时。如果您想执行更复杂的动画，您可能想看看更复杂的库，如 `Velocity.js`、`GSAP` 或其他库。

在下一章中，我们将学习使用 jQuery 提交表单数据。特别是，我们将学习如何在发送数据到服务器之前验证我们的表单。


# 第六章：使用 jQuery 创建更好的表单

在上一章中，我们讨论了动画以及它们如何使您的网站生动起来。在本章中，我们将研究任何网站最重要的功能之一——表单。一个精心制作的表单可能是获取新客户和错失机会之间的区别。所以表单值得仔细研究。

让用户完成表单并提交可能是具有挑战性的。如果我们的网站在任何时候让用户感到沮丧，他们可能会放弃填写表单和离开我们的网站。因此，我们通过使用工具提示、占位符文本和视觉指示器为用户提供温和的提示，让他们知道表单的每个输入元素需要什么。

jQuery 并没有太多专门处理表单的方法。其中的第一个都是快捷方式方法；它们用事件的名称作为第一个参数替换了`.on()`的使用。让我们来看看它们，并学习如何使用它们。

# 使用表单方法

让我们来看看一些与表单一起使用的 jQuery 方法。

## .submit()

最重要的表单方法之一是`.submit()`。它将处理程序绑定到浏览器提交事件。当用户已经（希望）填写了您的表单并单击提交按钮时，此处的事件处理程序将被激活。如果您想要自己处理此事件，而不实际提交表单，则必须调用`event.preventDefault()`或从方法中返回`false`。如果您没有执行其中一项操作，表单将被提交到您的服务器。

```js
// Cancel the default action by returning false from event handler
$('form').submit(function(event){
    alert('submit');
    return false;
});
```

在上述事件处理程序中，我们返回`false`来阻止浏览器提交我们的表单。我们也可以调用`event.preventDefault()`。我们可以将上述内容写成：

```js
// Cancel the default action by call 
$('form').on('submit', function(event){
    alert('submit');
    event.preventDefault();
});
```

这个示例的工作方式与第一个示例完全相同，但使用了更多的文本。我们用长格式的`.on()`方法替换了提交的快捷方式方法，并且我们还用事件对象直接调用了`preventDefault()`方法来替换了`return false`。

## .focus()

当用户在表单元素上切换或单击时，浏览器会触发一个焦点事件。焦点方法为此事件创建了一个处理程序。如果您希望为用户创建某种指示，表明这是活动元素，则这可能很方便。查看`.blur()`方法的代码示例，了解如何与`.focus()`一起使用。

需要注意的是，只有表单元素才能接收焦点。以下所有内容都是表单元素：

+   `<input>`

+   `<select>`

+   `<textarea>`

+   `<button>`

## .blur()

`.blur()`方法是`.focus()`方法的伴侣。它创建了一个处理程序，当用户切换或离开此元素时触发，导致它失去焦点。此事件也可以用于对元素进行验证，但实际上使用变化事件更好，并且将在稍后使用`.change()`方法进行解释。

```js
// Adds / removes the active class using the focus/blur events
$("input, textarea").focus(function(event){
    $(this).addClass('active');
});

$("input, textarea").blur(function(event){
    $(this).removeClass('active');
});
```

我们可以一起使用`.focus()`和`.blur()`方法，为活动元素添加一个类，并在失去焦点时移除它，以为我们的用户提供更好的视觉提示。请注意，我们通过用逗号分隔标签名称来挂接输入元素和文本区域元素。

使用`.focus()`和`.blur()`方法的一个潜在问题是它们不会冒泡。如果将要接收焦点的子元素放置在父元素中，并挂接父元素的焦点事件，那么事件将永远不会触发。这意味着您无法将这些事件委托给它们的父级。如果您需要挂接动态生成的输入标签的焦点/失焦事件，您也会遇到麻烦。

```js
// These handlers will never be triggered
$('#fiOne').focus(function (event) {
    console.info('Focus: ' + this.id + ', triggered by: ' + event.target.id);
    $(this).addClass('active');
});

$('#fiOne').blur(function (event) {
    console.info('Blur: ' + this.id + ', triggered by: ' + event.target.id);
    $(this).removeClass('active');
});
```

在上述代码中，我们挂接了`fieldset`，即所有单选按钮的父元素`fiOne`的焦点和失焦事件。在任何单选按钮子元素上都没有这些事件的处理程序。不幸的是，由于这两个事件都不会冒泡到其父元素，因此永远不会触发任何事件。

## `.focusin()`和`.focusout()`

现在我们知道焦点和失焦事件都不会冒泡到它们的父级。我们还在之前的章节中了解了冒泡如何帮助我们创建更具动态性的应用程序。有没有办法规避冒泡的缺乏呢？幸运的是，有一个解决方案：`.focusin()`和`.focusout()`方法。`.focusin()`方法为`focusin`事件创建一个处理程序，当元素即将获得焦点时触发。`.focusout()`方法与`.focusin()`方法相同，只是它与`focusout`事件一起工作，当元素即将失去焦点时触发。这两种方法都会冒泡到它们的父元素。

```js
// These handlers use the focusin/focusout, which bubble up
$('#fiOne').focusin(function (event) {
    console.info('Focusin: ' + this.id + ', triggered by: ' + event.target.id);
    $(this).addClass('active');
});

$('#fiOne').focusout(function (event) {
    console.info('Focusout: ' + this.id + ', triggered by: ' + event.target.id);
    $(this).removeClass('active');
});
```

此代码示例与前一个示例几乎相同，只是焦点和失焦事件分别替换为`focusin`和`focusout`事件。我们再次挂接父级`fieldset`元素。但是，这次，事件会冒泡到它们的父级。我们将活动类添加到`fieldset`，甚至通过从事件对象的目标属性获取其 ID 来显示生成事件的元素。

```js
// Adds an input tag dynamically by clicking the "Add Another" button
var inputCounter = 0;
$('#addAnother').click(function (event) {
    console.info("Adding another");
    $('#inputMomma').append($("<input>").attr({'type': 'text', 'id': 'newInput' + inputCounter++}));
});

// Makes the parent element the active class
$('#inputMomma').focusin(function (event) {
    console.info('Focusin: ' + this.id + ', triggered by: ' + event.target.id);
    $(this).addClass('active');
});

// Removes the active class from the parent
$('#inputMomma').focusout(function (event) {
    console.info('FocusOut: ' + this.id + ', triggered by: ' + event.target.id);
    $(this).removeClass('active');
});
```

在此示例中，我们使用 jQuery 动态创建新的输入标签。请注意我们如何使用链式操作来附加新的输入标签并设置其属性。即使这些标签在它们的父级挂接`focusin`和`focusout`事件时并不存在，它们仍然会将它们的事件冒泡到它。

## `.change()`

`.change()`方法为 change 事件创建一个处理程序。change 事件的好处是只有在输入或文本元素的值发生更改并且字段不再具有焦点时才触发。这使其比使用失焦事件更适合用于验证，因为失焦事件总是在元素失去焦点时触发，无论其值是否已更改。通过使用 change 事件，我们可以避免进行一些不必要的处理。

```js
// only called once focus is lost and contents have changed
$("input, textarea").change(function (event) {
    console.info('Change is good:' + this.id);
});
```

## `.select()`

我们在本章将要检查的事件处理程序方法中的最后一个是`.select()`方法。它绑定到 select 事件。此事件仅在允许输入文本的两个元素上触发：`<textarea>`和`<input type='text'>`。当用户选择某些文本时才会发生 select 事件。

```js
// Triggered when some text is selected
$('textarea').select(function(event){
    console.info("Something was selected: " + this.tagName);
});
```

在这个例子中，我们简单地挂接了 select 事件，并在接收到该事件时显示标签的名称。像大多数事件一样，我们也可以使用`.trigger()`方法触发 select 事件。

```js
// Selects all of the textarea text
$('#selectText').click(function (event) {
    console.info("Adding another");
    $('textarea').select();
});
```

```js
textarea and also gives <textarea> the focus. Other shortcomings of the select event are that there is no standard way to retrieve the selected text or to declare the range of characters to select. When the select event is fired, it always selects all of the characters. There are jQuery plugins available to fill the gap.
```

# 工具提示

自 HTML 4.01 以来，除了`<base>`、`<basefont>`、`<head>`、`<html>`、`<meta>`、`<param>`、`<script>`和`<title>`元素之外，title 属性可用。它定义了一个字符串，大多数浏览器在鼠标位于元素上方时会在元素上方附近渲染。显示的字符串通常称为工具提示。

标准的 HTML 工具提示留下了很多问题。默认情况下，它们的样式通常很简单，可能与您的网站不搭配。例如，如果您的网站使用大号字体来帮助用户，标准的工具提示看起来会非常尴尬。幸运的是，jQuery 有解决方案，尽管它不在核心库中。

jQuery UI 是一个包含一组用户界面组件的库。设计该组是为了可定制。该组的成员之一是工具提示。对于缺乏本机工具提示（title 属性支持）的浏览器，它提供支持。对于具有本机工具提示支持的浏览器，它通过使它们可定制和动画化来增强它们。

jQuery UI 的所有组件都需要 jQuery 核心库以及 CSS 和 JavaScript 文件才能正常工作。CSS 文件必须在 jQuery 之前添加到您的 HTML 文件中，JavaScript 文件必须在 jQuery 之后添加。

```js
<head lang="en">
<meta charset="UTF-8">
<link rel="stylesheet" href="//code.jquery.com/ui/1.11.4/themes/smoothness/jquery-ui.css">
<script src="img/"></script>
<script src="img/jquery-ui.js"></script>
<title>Chapter06-Forms</title>
```

上面的标记显示了如何正确地将 jQuery UI 支持添加到网站中。首先，我们添加 CSS 文件，然后是 jQuery，最后我们添加 jQuery UI。

### 注意

在上面的代码中，使用内容交付网络（CDN）来托管文件。您也可以将文件托管在您自己的服务器上，但是使用 CDN，您可以获得潜在的性能提升，因为用户浏览器可能已经在第一次访问您的网站时缓存了您的文件。

一旦我们加载了 jQuery 库，使用工具提示就很简单。我们需要挂接 jQuery 文档准备事件并在其中设置我们的工具提示。

```js
// Hook the document ready event and
$(document).ready(function () {
    // bind the tooltip plugin to the document
    $(document).tooltip({
        show: {
            effect: "slideDown",
            delay: 150
        }
    });
});
```

在上面的示例中，我们等待文档准备事件。在事件处理程序中，我们将工具提示绑定到文档上。这样就可以在整个网站上使用它。最后一步是添加动画效果。工具提示可以定制为在页面上以及页面外播放动画。在这里，我们让工具提示在 150 毫秒延迟后以`slideDown`的动画效果进入页面。

# 占位符

另一个现代浏览器具有但旧版本浏览器缺少的功能是占位符文本。它是出现在输入元素内部的略微灰色的文本，一旦用户开始输入就会消失。占位符对于表单很重要。它们为用户提供关于内容格式的提示，不像 `<label>` 元素，它提供了什么类型的信息是预期的。占位符属性自 HTML5 以来才有。仍然有很多浏览器不支持它。

为了在旧版本浏览器中添加对占位符属性的支持，我们将再次使用一个插件，但不是来自 jQuery 团队的插件。相反，我们将使用出色的 jquery-placeholder，来自 Mathias Bynens。可以从 bower 和 npm 下载，但我们将直接从其 GitHub 仓库下载：[`mathiasbynens.github.io/jquery-placeholder/`](http://mathiasbynens.github.io/jquery-placeholder/)。由于我们不关心它的工作原理，只关心如何使用它，我们将在我们的网站上安装缩小版。为此，我们在 HTML 文件中添加以下行：

```js
<script src="img/jquery.placeholder.min.js"></script>
```

占位符是一种称为 polyfill 的插件类型。这意味着它的目标只是给缺少标准功能的浏览器提供该功能。如果浏览器已经支持该标准，它将不起作用。为了激活插件，我们将其添加到 jQuery 文档就绪事件中，方式与之前处理工具提示相同。

```js
// Hook the document ready event and
$(document).ready(function () {
    // bind the placeholder to the input & textarea elements
    $('input, textarea').placeholder();
});
```

# 启用和禁用元素

表单中无效的元素应该被禁用。禁用的元素通常显示为灰色文本。禁用的元素无法聚焦，不响应用户，并且在提交表单时不会被发送。

关于禁用属性的奇怪之处在于，它在元素内的存在就会禁用它。它不需要设置为 `true` 或 `false`。实际上，将其设置为 `true` 或 `false` 没有任何效果。要禁用元素，请添加禁用属性。要启用元素，请移除禁用属性。幸运的是，jQuery 理解这种奇怪的行为并为我们处理了这个细节。

我们可以使用 jQuery 的 `.prop()` 方法来帮助我们。当我们想要禁用元素时，我们执行以下操作：

```js
$('#someId).prop('disabled', true);
```

当我们想要启用元素时，我们执行以下操作：

```js
$('#someId).prop('disabled', false);
```

尽管事情看起来很奇怪，但 jQuery 将会按照我们说的那样执行。第一行代码将向元素添加禁用属性，第二行将其移除。这里是一个更全面的代码片段：

```js
// disables/enable elements
$('#disableEnable').click(function (event) {
    var $ptr = $('#names > *');
    if ($ptr.prop('disabled')) {
        $ptr.prop('disabled', false);
        $(this).text('Disable Them');
    } else {
        $ptr.prop('disabled', true);
        $(this).text('Enable Them');
    }
});
```

我们首先通过为 `disableEnable` 按钮的点击事件绑定事件监听器。一旦接收到事件，我们检查按钮当前是否已禁用。如果是，则启用它并更改按钮的文本标签。如果元素未禁用，则禁用它并更改文本消息。

# 验证

到目前为止，我们学会了如何挂钩表单事件，如何为旧版浏览器提供现代浏览器功能，如占位符和工具提示，以及如何使用 jQuery 表单方法来收集所有的表单数据。但是我们没有做一件非常重要的事情：验证数据。

对用户和我们作为站点创建者来说，验证都很重要。对于用户，验证可以用来告诉他们如何正确填写表单。当他们犯错时，我们可以轻轻地提醒他们，而不是让他们提交一个错误的表单，然后告诉他们表单中包含错误。作为站点的维护者，发现一个应该有电话号码的字段中却找到了地址，这可能会令人沮丧。HTML5 为 Web 添加了许多验证功能。在我们看看 jQuery 提供了什么之前，让我们先看看现代浏览器中免费提供了什么。

我们将看到的第一个 HTML5 新添加的属性似乎如此简单和微不足道，以至于很难想象它以前并不存在：`autofocus`。`autofocus` 属性声明了在加载表单时应该拥有焦点的表单元素。在它出现之前，用户必须点击一个元素才能选择它，或者我们必须使用一点 jQuery 代码，如下所示：

```js
// Hook the document ready event and
$(document).ready(function () {
    // Give the title select element the focus
    $('#title').focus();
});
```

使用 HTML5，先前的代码被替换为：

```js
<select id="title" name="title" autofocus>
```

`autofocus` 属性声明该元素获得焦点。在任何给定时间，只应该有一个元素具有该属性。

HTML5 还增加了 `<input>` 元素类型的数量。以前，唯一可用的类型是：

| 类型 | 用途 |
| --- | --- |
| 按钮 | 按钮 |
| 复选框 | 复选框 |
| 文件 | 文件选择 |
| 隐藏 | 不显示但提交到服务器 |
| 图片 | 提交按钮的图形版本 |
| 密码 | 值被隐藏的文本字段 |
| 单选按钮 | 单选按钮 |
| 重置 | 将表单内容重置为默认值 |
| 提交 | 提交表单 |
| 文本 | 单行文本字段 |

HTML5 添加了以下新的 `<input>` 类型：

| 类型 | 用途 |
| --- | --- |
| 颜色 | 颜色选择器 |
| 日期 | 日期选择器（不含时间） |
| 日期/时间 | UTC 的日期/时间选择器 |
| 本地日期/时间 | 本地时区的日期/时间选择器 |
| 电子邮件 | 电子邮件地址 |
| 月份 | 月份/年份选择器 |
| 数字 | 浮点数的文本字段 |
| 范围 | 范围滑块 |
| 搜索 | 用于搜索字符串的文本字段 |
| 电话 | 用于电话号码的文本字段 |
| 时间 | 无时区的时间选择器 |
| 链接 | 用于 URL 的文本字段 |
| 周 | 周/年选择器 |

非常重要的一点是，对不同类型的检查非常少。例如，Tel 类型允许输入通常不是电话号码的字符。HTML5 提供了三个属性可以帮助：`minlength`、`maxlength` 和 `pattern`。`minlength` 属性表示输入的字符串必须包含的最小字符数才能被视为有效。`maxlength` 属性也是如此，只不过是最大字符数。最后一个属性是 `pattern`；它指定了要检查输入字符串的正则表达式。为了使字符串被视为有效，它必须通过。正则表达式在验证目的上非常方便，但编写正确的正则表达式可能会有些棘手。请务必对你网站中添加的任何正则表达式进行彻底测试。我还强烈建议使用一个有流行验证方案的网站。其中一个很受欢迎的正则表达式网站是：[`www.regular-expressions.info`](http://www.regular-expressions.info)。

HTML5 还添加了一个非常简单但重要的验证属性：required。required 属性简单地表示输入元素必须填写才能使表单被视为有效。如果它为空或填写但无效，符合规范的浏览器在用户尝试提交表单时会标记错误。不幸的是，错误消息和样式因浏览器而异。所以，如果我们真的想要掌控我们网站的样式，我们必须再次求助于我们的好朋友 jQuery。

验证并不是 jQuery 或 jQuery UI 的一部分，而是 jquery-validate 插件的主要功能。该插件由 jQuery、jQuery UI 和 QUnit 团队成员 Jörn Zaefferer 编写和维护。它始于 2006 年，至今仍在维护，是最古老的 jQuery 插件之一。jquery-validate 的主页是：[`jqueryvalidation.org/`](http://jqueryvalidation.org/)。你可以在那里下载 zip 文件，也可以通过 bower 或 nuget 包管理器下载。该插件的核心在文件 `jquery.validate.js` 中。对于大多数安装来说，这就是你所需要的。

一旦你将插件添加到你的脚本文件中，接下来你需要在你的 jQuery 文档准备好的事件处理器中，对你想要验证的表单添加调用验证方法。为了最小化验证，仅增强 HTML5 提供的内容，你只需添加如下一行代码：

```js
$('#personalInfo').validate();
```

这一行告诉插件验证名为 `personalInfo` 的表单。不需要其他进一步的操作。该插件将根据你在表单元素上放置的验证属性的行为进行操作，即使是不符合 HTML5 规范的浏览器也是如此。

如果您想要更多自定义，您将需要将一个初始化对象传递给插件。最重要的两个属性是 rules 和 messages。rules 属性定义插件将如何验证每个表单元素。messages 属性定义了当元素验证失败时插件将显示哪个消息。以下是我们验证示例的代码：

```js
<!DOCTYPE html>
<html>
<head lang="en">
<meta charset="UTF-8">
<link rel="stylesheet" href="//code.jquery.com/ui/1.11.4/themes/smoothness/jquery-ui.css">
<script src="img/"></script>
<script src="img/jquery-ui.js"></script>
<script src="img/jquery.validate.min.js"></script>
<script src="img/jquery.placeholder.min.js"></script>
<title>Chapter06-Forms</title>
<style type="text/css">
        .wider {
            display: inline-block;
            width: 125px;
            margin-right: 8px;
        }
        select {
            margin-right: 8px;
        }
        .error{
            color: red;
        }
</style>
</head>
<body>
<div>
<form id="personalInfo">
<fieldset>
<legend>Personal Info</legend>
<p>
<label for="title" class="wider">Greeting</label>
<select id="title" name="title" class="wider" autofocus>
<option selected></option>
<option>Mr.</option>
<option>Ms.</option>
<option>Miss</option>
<option>Mrs.</option>
<option>Dr.</option>
</select>
</p>
<p>
<label for="firstName" class="wider">First Name:</label>
<input id="firstName" name="firstName" class="wider" type="text" title="Your first name"/>
</p>
<p>
<label for="lastName" class="wider">Last Name:</label>
<input id="lastName" name="lastName" class="wider" type="text" title="Your last name"/>
</p>
<p>
<label for="password" class="wider">Password:</label>
<input id="password" name="password" class="wider" type="password"  title="Your password" title="Your password"/>
</p>
<p>
<label for="confirmPassword" class="wider">Confirm Password</label>
<input id="confirmPassword" name="confirmPassword" class="wider" type="password"  title="Confirm your password"/>
</p>
<p>
<label for="email" class="wider">E-Mail:</label>
<input id="email" name="email" class="wider" type="email" title="Your email address" placeholder="yourname@email.com" />
</p>
</fieldset>
<input type="reset" value="Reset" class="wider"/>
<input type="submit" value="Submit" class="wider"/>
</form>
</div>
```

除了添加验证插件之外，我们还需要包含 jQuery，因为我们仍然使用 jQuery 的提示和占位符插件，我们也将它们包含在内。接下来，我们添加了一点内联 CSS 来为我们增加一些样式。

我们的表单相当标准，除了一件事：我们不再添加任何内联验证属性。相反，我们在传递给验证方法的 JavaScript 对象中定义验证规则，接下来我们将看到：

```js
<script type="text/javascript">
    (function () {
        "use strict";

        // Hook the document ready event and
        $(document).ready(function () {
            // bind the placeholder polyfill to the input + textarea elements
            $('input, textarea').placeholder();
            // bind the tooltip plugin to the document
            $(document).tooltip({
                show: {
                    effect: "slideDown",
                    delay: 150
                }
            });
```

此代码示例的第一部分相当直接了当。我们绑定到 jQuery 的就绪事件，然后启用占位符 polyfill 和工具提示。

```js
            // bind validation to the personalInfo form
            $('#personalInfo').validate({
                rules: {
                    title: {
                        required: true
                    },
                    firstName: {
                        required: true,
                        minlength: 5
                    },
                    lastName: {
                        required: true,
                        minlength: 5
                    },
                    password: {
                        required: true,
                        minlength: 5
                    },
                    confirmPassword: {
                        required: true,
                        minlength: 5,
                        equalTo: '#password'
                    },
                    email: {
                        required: true,
                        email: true
                    }
                },
```

在验证对象的 rules 属性中，我们传递了我们希望验证的所有元素的名称。我们可以告诉验证器哪些元素是必需的，它们的最小长度，它们是否应该与另一个元素匹配等等。验证器可以做的远远超出了代码所示的内容，因此一定要阅读文档以了解更多信息。

```js
                messages: {
                    title: "Please choose a title.",
                    firstName: "Please enter your first name.",
                    lastName: "Please enter your last name.",
                    password: "Please create a password.",
                    confirmPassword: {
                        required: "Please confirm your password.",
                        equalTo: "Your passwords must match."
                    },
                    email: "Please enter a valid email."
                },
                submitHandler: function(form) {
                    alert('submit');
                }
            });
        });
    }());
</script>
</body>
</html>
```

在验证对象的 message 属性中，我们传递了我们希望显示的所有消息。这里未定义的任何元素或状态将简单地分配一个默认的验证错误消息，这在许多情况下可能已经足够了。

传递给验证方法的最后一个属性是 submit 处理程序。这是用户成功提交表单后调用的方法。您必须使用 submit 处理程序，而不是 jQuery 的 submit 处理程序。

# 过滤掉不需要的字符

作为 web 开发人员，我们的工作是防止用户意外做出一些不好的事情。验证可以让用户知道他们输入了错误的内容。过滤有助于防止用户输入无效字符。为了过滤输入到文本字段中的字符，我们需要挂钩两个事件："keypress" 和 "paste"。

```js
// filters out unwanted characters
$('#alphaNumOnly').on('keypress paste', function (event) {
    // convert the keycode into a character
    var nextChar = String.fromCharCode(event.which);
    if(event.type === 'keypress'){
    // add it to the current input text string, the remove any
    bad chars via regex
    this.value = (this.value + nextChar).replace(/[⁰-9|a-z|AZ]+/g, '');
}
    // let the browser know we've handled this event
    event.preventDefault();
    return false;
});
```

挂钩 `keypress` 事件允许我们在按下每个键时查看每个键，并决定我们是否希望这个字符出现在我们的文本字段中。我们挂钩粘贴键以阻止用户将字符串剪切并粘贴到我们的文本字段中。大部分工作由正则表达式完成。它过滤掉除数字和字母之外的所有内容。

# 概要

表单对于大多数网站来说非常重要。它们是我们网站用户与网站交流的主要方式。帮助我们的用户填写表单，并确保我们获得的数据是良好的。我们已经看到了 jQuery 如何帮助我们处理表单的许多方式。工具提示插件帮助我们向缺乏它的浏览器添加工具提示，并将工具提示样式设置为与我们网站外观相匹配。占位符填充为较旧的浏览器提供占位符属性，并对已支持该属性的浏览器静默地退出。

jQuery 也为我们提供了简单的方法来挂钩提交、更改和其他表单事件。这些事件还提供了在我们提交数据之前或数据更改后验证数据的点。

在下一章中，我们将学习关于 Ajax 以及 jQuery 如何使得从我们的服务器发送和接收数据几乎变得轻而易举。
