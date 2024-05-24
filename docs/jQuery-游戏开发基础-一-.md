# jQuery 游戏开发基础（一）

> 原文：[`zh.annas-archive.org/md5/7D66632184130FBF91F62E87E7F01A36`](https://zh.annas-archive.org/md5/7D66632184130FBF91F62E87E7F01A36)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

编写游戏不仅有趣，而且是通过透彻地学习一项技术的非常好的方法。尽管 HTML 和 JavaScript 并不是为了运行游戏而设计的，但在过去的几年中，一系列事件发生，使得用 JavaScript 编写游戏成为可行的解决方案：

+   浏览器的 JavaScript 引擎性能有了显著提高，现代引擎比 2008 年的最先进引擎快了十倍。

+   jQuery 和其他类似的库使得与 DOM 的操作尽可能轻松。

+   Flash 在某种程度上由于在 iOS 上的缺失而失去了很多地位。

+   W3C 开始了许多面向游戏的 API 的工作，如 canvas、WebGL 和全屏 API。

在整本书中，你将制作三款游戏并学习各种技术。你不仅可以使用自己的游戏，更重要的是你将在过程中获得乐趣！

# 本书内容

第一章, *游戏中的 jQuery*，深入探讨了对游戏开发可能有用的 jQuery 函数。

第二章, *创建我们的第一个游戏*，使用精灵、动画和预加载实现了一个简单的游戏。

第三章, *更好、更快、但不更难*，通过各种技术如超时内联、键盘轮询和 HTML 片段优化了我们在第二章中看到的游戏*创建我们的第一个游戏*。

第四章, *横向看*，用瓷砖地图和碰撞检测编写了一个平台游戏。

第五章, *物以类聚*，创建了一个正交 RPG 游戏，采用了瓦片地图优化、精灵遮挡和更好的碰撞检测。

第六章, *给你的游戏添加关卡*，通过使用 JSON 和 AJAX 添加多个关卡，扩展了我们在第四章中看到的游戏*横向看*。

第七章, *制作多人游戏*，将我们在第五章中看到的游戏转变为支持多台机器上的多个玩家。

第八章, *让我们变得社交化*，将平台游戏与 Facebook 和 Twitter 集成，并创建一个防作弊的排行榜。

第九章, *让你的游戏移动起来*，将我们在第五章中看到的游戏优化为适用于移动设备和触摸控制。

第十章, *制造一些声音*，通过音频元素、Web Audio API 或 Flash，为你的游戏添加音效和音乐。

# 本书的需要

使用 web 技术的一个优势是，你无需任何复杂或昂贵的软件即可开始。对于纯粹的客户端游戏，你只需要你最喜欢的代码编辑器（甚至是一个简单的文本编辑器，如果你不介意在没有任何语法高亮的情况下工作）。如果你还没有选择的话，那么你可以试试周围的免费软件，从非常老式的软件，比如 VIM（[`www.vim.org/`](http://www.vim.org/)）和 Emacs（[`www.gnu.org/software/emacs/`](http://www.gnu.org/software/emacs/)）到更现代的软件，比如 Eclipse（[`www.eclipse.org/`](http://www.eclipse.org/)）和 Aptana（[`www.aptana.com/`](http://www.aptana.com/)），Notepad++（[`notepad-plus-plus.org/`](http://notepad-plus-plus.org/)），或者 Komodo Edit（[`www.activestate.com/komodo-edit`](http://www.activestate.com/komodo-edit)）。这些只是你可以找到的一些可用编辑器。对于 JavaScript，你不需要一个非常先进的编辑器，所以只需使用你更熟悉的那个。

如果你创建自己的图形，你还需要一款图像编辑软件。在这方面，你会有很多选择。最著名的开源软件是 Gimp（[`www.gimp.org/`](http://www.gimp.org/)），还有我个人最喜欢的 Pixen（[`pixenapp.com/`](http://pixenapp.com/)）。

对于书中需要一些服务器端脚本的部分，我们将会使用 PHP 和 MySQL。如果你还没有支持它们的服务器，你可以在你的机器上安装它们，你可以使用 MAMP（[`www.mamp.info/`](http://www.mamp.info/)）、XAMPP（[`www.apachefriends.org/en/xampp.html`](http://www.apachefriends.org/en/xampp.html)），或者 EasyPHP（[`www.easyphp.org/`](http://www.easyphp.org/)），具体根据你的操作系统来选择。

# 本书适合人群

本书的主要观众是有一些 JavaScript 和 jQuery 经验的初学者 web 开发人员。由于服务器端部分是用 PHP 实现的，如果你对 PHP 也有一些了解的话会有所帮助，但是如果你更喜欢其他服务器端语言的话，你也可以使用其他语言代替 PHP 而不会有太多麻烦。

你完全不需要任何游戏开发的先验知识就能享受本书！

# 约定

在这本书中，你会发现许多不同种类的信息的文本样式。以下是其中一些样式的例子，以及它们的含义解释。

文本中的代码单词显示如下: "jQuery 的`.animate()`函数允许你让一个属性从当前值按照时间变化到一个新值。"

一个代码块设置如下：

```js
$("#myElementId")
.animate({top: 200})
.animate({left: 200})
.dequeue();
```

当我们想吸引你的注意到代码块的特定部分时，相关的行或项用粗体表示：

```js
gf.keyboard = [];
// keyboard state handler
 $(document).keydown(function(event){
 gf.keyboard[event.keyCode] = true;
});
$(document).keyup(function(event){
    gf.keyboard[event.keyCode] = false;
});
```

任何命令行输入或输出都如下所示：

```js
# cp /usr/src/asterisk-addons/configs/cdr_mysql.conf.sample
     /etc/asterisk/cdr_mysql.conf
```

**新术语**和**重要词汇**以粗体显示。例如，在屏幕上看到的单词，在菜单或对话框中出现的单词，将以这样的方式出现在文本中："下图显示了两个段 **a** 和 **b** 的一维交集 **i** 的典型情况"。

### 注意

警告或重要提示将以这样的方式出现在一个框中。

### 提示

提示和技巧会以这样的方式出现。


# 第一章 jQuery 游戏编程

在过去的几年里，jQuery 几乎已经成为任何 JavaScript 开发的默认框架。超过 55％的最受欢迎的 10,000 个网站以及估计总共 2400 万个网站正在使用它（更多信息，请参阅[`trends.builtwith.com/javascript/JQuery`](http://trends.builtwith.com/javascript/JQuery)）。而且这一趋势并没有显示出任何停止的迹象。

本书期望您具有一些 jQuery 的相关经验。如果您觉得自己不符合这个要求，那么您可以首先在*学习 jQuery*，*Jonathan Chaffer*，*Karl Swedberg*，*Packt Publishing*中了解更多。

本章将快速浏览 jQuery 的特点，然后更深入地了解它最具游戏性的函数。即使您可能已经使用过其中的大部分，您可能还不了解它们的全部功能。以下是本章涵盖的主题的详细列表：

+   jQuery 的特点

+   将帮助您移动元素的函数

+   事件处理

+   DOM 操作

# jQuery 的方式

jQuery 的哲学与大多数之前的 JavaScript 框架有所不同。了解它使用的设计模式是编写可读和高效代码的关键。我们将在接下来的几节中讨论这些模式。

## 链接

大多数 jQuery 语句的形式如下：选择后跟一个或多个操作。这些操作的组合方式被称为链式，并且是 jQuery 最优雅的方面之一。一个使用 jQuery 的初学者想要将元素的宽度设置为 300 像素，高度设置为 100 像素，通常会写成：

```js
$("#myElementId").width(300);
$("#myElementId").height(100);
```

使用链接，这可以写成：

```js
$("#myElementId").width(300).height(100);
```

这有很多优点：元素只被选择一次，并且生成的代码更紧凑，传达了语义意义，即你想要实现的确实只是一件事，那就是改变元素的大小。

允许链式调用的函数不仅可以将许多调用组合在同一个对象上，还有许多实际上可以在哪个对象（或对象）上进行下一个链上的函数操作的方法。在这些情况下，通常使用缩进来传达这样一个想法：你不是在同一层级的元素上操作。

例如，以下链首先选择一个元素，然后将其背景颜色设置为`red`。然后将链中的元素更改为前一个元素的子元素，并将它们的`background-color`属性更改为`yellow`。

```js
$("#myElementId").css("background-color", "red")
   .children().css("background-color", "yellow");
```

很重要的一点是，您必须始终问自己当前和链中上一个和下一个元素的相互作用如何可以避免产生不良行为。

## 多态性

jQuery 有自己的多态使用方式，给定函数可以以许多不同的方式调用，具体取决于你想给它多少信息。让我们看一下`.css()`函数。如果只使用`String`数据类型作为唯一参数调用该函数，则该函数将作为 getter 运行，返回你要求的 CSS 属性的值。

例如，以下行检索给定元素的左侧位置（假设它是绝对定位的）：

```js
var elementLeft = $("#myElementId").css("left");
```

但是，如果传递第二个参数，则它将开始行为类似于 setter，并设置 CSS 属性的值。有趣的是，第二个参数也可以是一个函数。在这种情况下，函数预计返回将设置为 CSS 属性的值。

以下代码就是这样做的，并使用一个函数，该函数将增加元素的左侧位置一个单位：

```js
$("#myElementId").css("left", function(index, value){
   return parseInt(value)+1;
});
```

但是；等一下，还有更多！如果你向同一个函数只传递一个元素，但该元素是一个对象文字，那么它将被视为保存属性/值映射。这将允许你在一个单一调用中更改许多 CSS 属性，就像在以下示例中将左侧和顶部位置设置为 100 像素一样：

```js
$("#myElementId").css({
   left: 100,
   top: 100
});
```

你也可以像在 JSON 中那样，使用字符串作为对象文字的键和值。

一个非常完整的资源，用于了解调用函数的所有方式，是 jQuery API 网站 ([`api.jquery.com`](http://api.jquery.com))。

现在我们将重点关注一些对开发游戏感兴趣的函数。

# 移动物体

对于动画，链式有着稍微不同的意义。虽然你在大多数游戏中实际上可能从未需要使用 jQuery 动画函数，但仍然有意思看到它们的工作特点，因为它可能导致许多奇怪的行为。

## 链接动画

jQuery 的`.animate()`函数允许你通过时间使属性的值从当前值变化到新值。举个典型的例子，可以移动它左边 10 像素，或者改变它的高度。从你之前看到的以及体验到其他类型的函数，你可能期望以下代码将使一个 div（DOM division 元素）对角线移动到位置`left = 200px`和`top = 200px`。

```js
$("#myElementId").animate({top: 200}).animate({left: 200});
```

然而，它并不会！相反，你将看到 div 首先移动到达`top = 200px`，然后才移动到`left = 200px`。这称为排队；每次调用`animate`都将排队到之前的调用，并且只有在它们都完成后才会执行。如果你想同时执行两个移动，从而生成对角线移动，你将只能使用一次`.animate()`调用。

```js
$("#myElementId").animate({top: 200,left: 200});
```

另一种可能性是明确告诉`.animate()`函数不要排队执行动画：

```js
$("#myElementId").animate({top: 200}).animate({left: 200},{queue: false});
```

请记住，这也适用于实际上是包装在`.animate()`函数周围的其他函数，例如以下情况：

+   `fadeIn()`、`fadeOut()`和`fadeTo()`

+   `hide()` 和 `show()`

+   `slideUp()` 和 `slideDown()`

![链接动画](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_01_01.jpg)

## 管理队列

下面是一系列函数，你可以使用它们来操作这个动画队列。

### .stop()

`.stop()` 函数停止队列当前的动画。如果你在调用时提供了更多的参数，你还可以清除队列并定义元素是否停止动画并停留在原地，或者跳转到它们的目标位置。

### .clearQueue()

`.clearQueue()` 函数从队列中删除所有动画；不仅是当前的动画，还有所有接下来的动画。

### .dequeue()

`.dequeue()` 函数启动队列中的下一个动画。这意味着当调用此函数时正在执行动画时，新的动画将在当前动画执行完成后开始。例如，如果我们拿本节开头的示例并在结尾添加一个 `dequeue()` 函数，元素将实际上开始对角线移动。

```js
$("#myElementId")
.animate({top: 200})
.animate({left: 200})
.dequeue();
```

### .delay()

`.delay()` 函数允许你在队列中的两个动画之间插入一个暂停。例如，如果你想要使用 `.fadeIn()` 使元素可见，然后等待 2 秒，再用 `.fadeOut()` 使其消失。这将被写成这样：

```js
$("#myElementId").fadeIn().delay(2000).fadeOut();
```

## 队列的其他用途

队列不仅用于动画。当你没有另外指定时，被这些函数操作的队列是 `fx` 队列。这是动画使用的默认队列。但是，如果你愿意，你可以创建另一个队列，并添加任意数量的自定义函数和延迟，以便在游戏中脚本一些时间相关的行为。

# 事件处理

如果您以前使用过 jQuery，您可能在某个时候使用过 `.click()`。它用于定义一个事件处理程序，用于在 jQuery 中响应鼠标点击。还有许多其他的事件处理程序，从键盘输入、表单提交到窗口调整大小，但我们不会逐一介绍所有这些。而是专注于更 "低级别" 的函数来处理 jQuery 中的事件，并准确解释它们之间的微妙差异。

你通常会使用其中一些函数来实现游戏的控制，无论是通过鼠标还是键盘输入。

## .bind()

`.bind()` 函数是处理事件的基本方式。`.click()` 例如，只是它的一个包装器。以下示例的两行具有完全相同的效果：

```js
$("#myElementId").click(function(){alert("Clicked!")});
$("#myElementId").bind('click', function(){alert("Clicked!")});
```

但是，使用 `bind` 有一个限制。像所有其他 jQuery 函数一样，它仅适用于所选元素。现在，想象一种情况，你想要在用户每次点击具有给定类的链接时执行某些任务。你会写出这样的代码：

```js
$(".myClass").click(function(){/** do something **/});
```

这将按预期工作，但仅适用于网页中在执行时存在的链接。如果你使用 Ajax 调用更改页面内容，并且新内容也包含具有此类的链接，那么你将不得不再次调用此行代码来增强新链接！

这远非理想，因为你必须手动跟踪你定义的所有事件处理程序，这些处理程序可能需要稍后再次调用，以及你改变页面内容的所有位置。这个过程很可能会出错，你最终会得到一些不一致的结果。

解决这个问题的方法是 `.delegate()`，详细说明见下一节。

## .delegate()

使用 `.delegate()`，你将事件处理的责任交给了一个父节点。这样，稍后添加到该节点（直接或间接）下面的所有元素仍将看到相应的处理程序执行。

以下代码修复了前面的示例，使其能够与稍后添加的链接一起工作。这意味着所有这些链接都是 `ID` 属性为 `page` 的 div 的子元素。

```js
$("#page").delegate(
".myClass", 
"click", 
function(){/** do something **/});
```

这是解决问题的一个非常优雅的方式，当你创建游戏时，它会非常方便，例如，当你点击精灵时。

## 移除事件处理程序

如果你需要移除一个事件处理程序，你可以简单地使用 `.unbind()` 和 `.undelegate()` 函数。

## jQuery 1.7

在 jQuery 1.7 中，`.delegate()` 和 `.bind()` 已被 `.on()`（以及 `.off()` 用于移除处理程序）取代。将其视为一个具有像 `.bind()` 一样行为能力的 `.delegate()` 函数。如果你理解了 `.delegate()` 的工作原理，你将没有问题使用 `.on()`。

# 将数据与 DOM 元素关联

假设你为游戏中的每个敌人创建一个 div 元素。你可能想要将它们与一些数值关联起来，比如它们的生命值。如果你正在编写面向对象的代码，你甚至可能想要关联一个对象。

jQuery 提供了一个简单的方法来做到这一点，即 `.data()`。这个方法接受一个键和一个值。如果你稍后只调用它的键，它将返回这个值。例如，以下代码将数值 `3` 与键 `"numberOfLife"` 关联到了 ID 为 `enemy3` 的元素上。

```js
 $("#enemy3").data("numberOfLife", 3);
```

你可能在想，“为什么我不能直接将我的值存储在 DOM 元素上呢？”对此有一个非常好的答案。通过使用 `.data()`，你完全解耦了你的值和 DOM，这将使得避免因为你仍然在某个地方保持着对它的某个循环引用而导致垃圾回收器没有释放与已移除元素的 DOM 关联的内存的情况变得更容易。

如果你使用 HTML5 数据属性定义了一些值（[`ejohn.org/blog/html-5-data-attributes/`](http://ejohn.org/blog/html-5-data-attributes/)），`.data()` 函数也会将它们检索出来。

但是，你必须记住调用这个函数会有一些性能成本，如果你需要为一个元素存储许多值，你可能会希望将它们全部存储在与单个键关联的对象字面量中，而不是许多值，每个值都与自己的键关联。

# 操纵 DOM

使用 jQuery 创建游戏时，您将花费相当多的时间向 DOM 添加和移除节点。例如，您可以创建新的敌人或移除已经死亡的敌人。在下一节中，我们将介绍您将要使用的函数，还将看到它们的工作原理。

## .append()

此函数允许您将子元素添加到当前选择的元素（或元素）。它的参数可以是一些已经存在的 DOM 元素、包含描述元素的 HTML 代码的字符串（或一整个元素层次结构），或者是选择某些节点的 jQuery 元素。例如，如果您想要将子元素添加到具有 ID `"content"` 的节点上，您可以这样写：

```js
$("#content").append("<div>This is a new div!</div>");
```

请记住，如果您向此函数传递一个字符串，那么内容将需要被解析，如果您经常这样做或者字符串非常大，可能会导致性能问题。

## .prepend()

此函数与`.append()`完全相同，但是将新内容添加到所选元素的第一个子元素之前，而不是添加到其最后一个子元素之后。

## .html()

此函数允许您使用作为参数传递的字符串完全替换所选节点的内容。如果没有传递参数调用它，它将返回所选元素中第一个的当前 HTML 内容。

如果您使用空字符串调用它，您将擦除所有节点的内容。这也可以通过调用`.empty()`来实现。

![.html()](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_01_02.jpg)

## .remove()

此函数将简单地删除所有选定的元素并注销所有关联的事件处理程序和数据。

## .detach()

在某些情况下，您可能只想暂时删除一些内容，然后稍后再添加。这通常是 `.remove()` 做得太好的情况。您真正想要的是保留与节点关联的所有其他内容，以便稍后重新添加时，它们将与以前完全相同。`.detach()` 就是为了这种情况而创建的。它的行为类似于 `.remove()`，但是允许您轻松重新插入元素。

# 保持好奇，我的朋友！

就是这样。我真的鼓励您阅读每个函数的 API，因为这里还有一些未显示的参数集。如果对其中任何函数仍然不清楚，不要犹豫在网络上寻找更多关于如何使用它们的示例。由于 jQuery 是如此流行的库，而网络文化是开放的，您将很容易在网上找到大量帮助。

以下是一些可以开始寻找有关 jQuery 更多信息的地方：

+   jQuery 的 API: [`api.jquery.com/`](http://api.jquery.com/)

+   学习 jQuery: [`www.learningjquery.com/`](http://www.learningjquery.com/)

# 摘要

在本章中，我们已经看到了一些对游戏开发非常有用的 jQuery 函数以及如何使用它们。到目前为止，您应该已经熟悉了 jQuery 的哲学和语法。在下一章中，我们将将学到的知识付诸实践，并创建我们的第一个游戏。


# 第二章：创建我们的第一个游戏

如果你看着电子设备，很有可能上面运行着一个浏览器！你可能在每台 PC 上安装了一个以上的浏览器，并在你的便携设备上运行了更多。如果你想以最低的入门成本将你的游戏分发给广泛的受众，使其在浏览器中运行是非常有意义的。

Flash 长时间以来一直是浏览器中游戏的首选平台，但在过去几年中它的速度逐渐减慢。有很多原因造成了这种情况，并且关于这是否是一件好事有无数的争论。然而，有一个共识是现在你可以在浏览器中以合理的速度运行游戏而无需插件。

本书将重点关注 2D 游戏，因为它们在当前浏览器上运行良好，并且它们依赖的功能已经标准化。这意味着浏览器的更新不应该破坏你的游戏，而且在大多数情况下，你不必过多担心不同浏览器之间的差异。

然而，你很快将能够开发现代 3D 游戏，就像在游戏机上一样，并让它们在浏览器上运行。如果这是你擅长的领域，这本书将为你提供制作这些游戏所需的基本知识。

在本章中，我们将涵盖以下主题：

+   创建动画精灵

+   移动精灵

+   预加载资源

+   使用有限状态机实现主游戏循环

+   基本碰撞检测

# 这本书是如何工作的？

制作游戏有这个惊人的优势，你可以立即看到你刚写的代码的结果在你眼前移动。这就是为什么这本书中学到的一切都将直接应用于一些实际例子的原因。在本章中，我们将一起编写一个受经典游戏*青蛙过河*启发的小游戏。在接下来的章节中，我们将制作一个平台游戏和一个角色扮演游戏（RPG）。

我真的鼓励你写下你自己版本的这里所介绍的游戏，并修改提供的代码以查看其效果。没有比动手做更好的学习方式了！

# 让我们认真对待 - 游戏

我们现在将要实现的游戏灵感来自*青蛙过河*。在这个老派街机游戏中，你扮演一个青蛙，试图通过跳上原木并避开汽车来穿过屏幕。

![让我们认真对待 - 游戏](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_02_01.jpg)

在我们的版本中，玩家是一个开发人员，他必须通过跳跃数据包来穿越网络电缆，然后通过避开错误来穿越浏览器的"道路"。总而言之，游戏规格如下：

+   如果玩家按一次向上箭头键，"青蛙"将前进一步。

+   通过按右箭头和左箭头键，玩家可以水平移动。

+   在第一部分（网络电缆）中，玩家必须跳跃到从屏幕左边出现并向右移动的数据包上。数据包按行组织，每行的数据包以不同的速度行进。一旦玩家站在数据包上，他/她将随之移动。如果数据包把玩家带到屏幕外，或者玩家跳到电缆上未到达数据包，他/她将会死亡，然后重新开始同一级别。

+   在第二部分（浏览器部分）中，玩家必须躲避从左边出现的错误以穿过浏览器屏幕。如果玩家被错误击中，他/她将会重新开始同一级别。

这些规则非常简单，但正如您将看到的，它们已经给我们提供了很多值得思考的地方。

# 学习基础

在本书中，我们将使用 DOM 元素来渲染游戏元素。另一个流行的解决方案是使用 Canvas 元素。这两种技术都有各自的优点和缺点，也有一些效果仅通过 DOM 元素是无法实现的。

然而，对于初学者来说，DOM 提供了易于调试的优势，几乎在所有现有的浏览器上运行（是的，即使在 Internet Explorer 6 上也是如此），而且在大多数情况下可以提供合理的游戏速度。DOM 还抽象了繁琐的工作，无需单独针对像素进行操作以及跟踪屏幕的哪一部分需要重新绘制。

即使 Internet Explorer 支持本书中所介绍的大部分功能，我也不建议创建支持 IE 的游戏。事实上，如今它的市场份额微不足道（[`www.ie6countdown.com/`](http://www.ie6countdown.com/)），而且您可能会遇到一些性能问题。

现在介绍一些游戏术语，精灵是游戏的移动部分。它们可以是动画的或非动画的（在改变外观与简单移动之间）。其他游戏的部分可能包括背景、用户界面和图块（我们将在第四章中深入讨论，*向旁边看*）。

## 框架

在本书中，我们将编写一些代码；部分代码属于一个示例游戏，并用于描述特定于该游戏的场景或逻辑。但是，某些代码很可能会在您的每个游戏中被重用。因此，我们将把一些这样的功能集中到一个被巧妙地称为`gameFramework`或简称`gf`的框架中。

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)账户下载您购买过的 Packt 书籍的示例代码文件。如果您在其他地方购买了本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给您。

在 JavaScript 中定义命名空间的一个非常简单的方法是创建一个对象，并直接将所有函数添加到其中。以下代码为名称空间`cocktail`中的两个函数`shake`和`stir`提供了示例。

```js
// define the namespace
var cocktail = {};

// add the function shake to the namespace
cocktail.shake = function(){...}

// add the function stir to the namespace
cocktail.stir = function(){...}
```

这样做的优点是避免与其他使用类似名称的库的对象或函数发生冲突。因此，从现在开始，当您看到任何添加到命名空间的函数时，意味着我们认为这些函数将被其他我们稍后在本书中创建的游戏所使用，或者您可能想要自己创建的游戏使用。

下面的代码是另一种命名空间的表示法。您可以使用其中之一是个人偏好，您真的应该使用感觉正确的那个！

```js
var cocktail = {

    // add the function shake to the namespace
   shake: function(){...},

   // add the function stir to the namespace
   stir: function(){...}
};
```

通常，您会将框架的代码保存在一个 JS 文件中（假设为`gameFramework.js`），并将游戏的代码保存在另一个 JS 文件中。一旦您的游戏准备发布，您可能希望将所有 JavaScript 代码重新组合到一个文件中（包括 jQuery 如果您愿意的话）并将其最小化。但是，在整个开发阶段，将它们分开将更加方便。

## 精灵

精灵是您的游戏的基本构建块。它们基本上是可以在屏幕上移动和动画的图像。要创建它们，您可以使用任何图像编辑器。如果您使用的是 OS X，有一个我觉得特别好的免费软件，叫做 Pixen ([`pixenapp.com/`](http://pixenapp.com/))。

有许多使用 DOM 绘制精灵的方法。最明显的方法是使用`img`元素。这会带来几个不便。首先，如果要对图像进行动画处理，您有两个选项，但两者都不是没有缺点：

+   您可以使用动画 GIF。通过这种方法，您无法通过 JavaScript 访问当前帧的索引，并且无法控制动画何时开始播放或何时结束。此外，拥有许多动画 GIF 会导致速度大大减慢。

+   您可以更改图像的来源。这已经是一个更好的解决方案，但是提出的性能较差，而且需要大量单独的图像。

另一个缺点是您无法选择仅显示图像的一部分；您必须每次都显示整个图像。最后，如果您想要一个由重复图像组成的精灵，您将不得不使用许多`img`元素。

为了完整起见，我们应该在这里提到`img`的一个优点；缩放`img`元素非常容易——只需调整宽度和高度。

提出的解决方案使用了定义尺寸的简单 div，并在背景中设置了图像。要生成动画精灵，您可以更改背景图像，但我们使用的是背景位置 CSS 属性。在此情况下使用的图像称为精灵表，通常看起来像以下的屏幕截图：

![精灵](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_02_02.jpg)

生成动画的机制如下屏幕截图所示：

![Sprites](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_02_06.jpg)

另一个优点是你可以使用单个雪碧图来容纳多个动画。这样你就可以避免加载许多不同的图像。根据情况，您可能仍然希望使用多个雪碧图，但尽量减少它们的数量是件好事。

### 实现动画

实现这个解决方案非常简单。我们将使用`.css()`来改变背景属性，并使用简单的`setInterval`来改变动画的当前帧。因此，假设我们有一个包含 4 帧行走循环的雪碧图，其中每帧测量`64 by 64`像素。

首先，我们只需创建一个带有雪碧图作为其背景的`div`。这个`div`应该测量`64 by 64`像素，否则下一帧会泄漏到当前帧。在下面的示例中，我们将雪碧图添加到 ID 为`mygame`的`div`中。

```js
$("#mygame").append("<div id='sprite1'>");
$("#sprite1").css("backgroundImage","url('spritesheet1.png')");
```

由于背景图像默认与`div`的左上角对齐，所以我们只会看到行走循环雪碧图的第一帧。我们想要的是能够改变哪个帧是可见的。以下函数根据传递给它的参数将背景位置更改为正确的位置。请查看以下代码以了解参数的确切含义：

```js
/**
 * This function sets the current frame. 
 * -divId: the Id of the div from which you want to change the
 *         frame
 * -frameNumber: the frame number
 * -frameDimension: the width of a frame
 **/
gameFramework.setFrame = function(divId,frameNumber, frameDimension) {
   $("#"+divId)
      .css("bakgroundPosition", "" + frameNumber * frameDimension + "px 0px");
}
```

现在我们必须定期调用这个函数来生成动画。我们将使用间隔为 60 毫秒的`setInterval`，即每秒约 17 帧。这应该足以给人一种行走的印象；然而，这确实必须进行微调，以匹配您的雪碧图。为此，我们使用一个匿名函数传递给`setInterval`，该函数将进一步使用正确的参数调用我们的函数。

```js
var totalNumberOfFrame = 4;
var frameNumber = 0;
setInterval(function(){
 gameFramework.setFrame("sprite1",frameNumber, 64);
   frameNumber = (frameNumber + 1) % totalNumberOfFrame;
}, 60);
```

你可能注意到我们正在做一些特殊的事情来计算当前帧。目标是覆盖从 0 到 3 的值（因为有 4 帧），并在达到 4 时循环回到 0。我们用于此的操作称为模数（`%`），它是整数除法的余数（也称为欧几里德除法）。

例如，在第三帧我们有`3 / 4`等于 0 加上余数 3，所以`3 % 4 = 3`。当帧数达到 4 时，我们有`4 / 4 = 1`加上余数 0，所以`4 % 4 = 0`。这个机制在很多情况下都被使用。

### 将动画添加到我们的框架

正如你所看到的，生成动画需要越来越多的变量：图像的 URL、帧数、它们的尺寸、动画的速率和当前帧。此外，所有这些变量都与一个动画相关联，因此如果我们需要第二个动画，我们必须定义两倍数量的变量。

显而易见的解决方案是使用对象。我们将创建一个动画对象，它将保存我们需要的所有变量（现在，它不需要任何方法）。这个对象，像我们框架中所有的东西一样，将位于`gameFramework`命名空间中。与其将动画的每个属性的所有值作为参数给出，不如使用单个对象文字，并且所有未定义的属性将默认为一些经过深思熟虑的值。

为此，jQuery 提供了一个非常方便的方法：`$.extend`。这是一个非常强大的方法，你应该真正看一下 API 文档（[`api.jquery.com/`](http://api.jquery.com/)）来看看它能做什么。这里我们将向它传递三个参数：第一个将被第二个的值扩展，结果对象将被第三个的值扩展。

```js
/**
 * Animation Object.
 **/
gf.animation = function(options) {
    var defaultValues = {
        url : false,
        width : 64,
        numberOfFrames : 1,
        currentFrame : 0,
        rate : 30
    };
    $.extend(this, defaultValues, options);
}
```

要使用此功能，我们只需使用所需值创建一个新实例即可。这里你可以看到在前面的示例中使用的值：

```js
var firstAnim = new gameFramework.animation({
   url: "spritesheet1.png",
   numberOfFrames: 4,
   rate: 60
});
```

正如你所看到的，我们不需要指定`width:` `64`，因为这是默认值！这种模式非常方便，每次需要默认值和灵活性来覆盖它们时都应该记住它。

我们可以重写函数以使用动画对象：

```js
gf.setFrame = function(divId, animation) {
    $("#" + divId)
        .css("bakgroundPosition", "" + animation.currentFrame * animation.width + "px 0px");
}
```

现在，我们将根据我们已经看到的技术为我们的框架创建一个函数，但这次它将使用新的动画对象。这个函数将开始对精灵进行动画处理，可以是一次或循环播放。有一件事我们必须注意——如果我们为已经在动画中的精灵定义动画，我们需要停用当前动画，并用新动画替换它。

为此，我们将需要一个数组来保存所有间隔句柄的列表。然后我们只需要检查这个精灵是否存在一个间隔句柄，并清除它，然后再次定义它。

```js
gf.animationHandles = {};

/**
 * Sets the animation for the given sprite.
 **/
gf.setAnimation = function(divId, animation, loop){
    if(gf.animationHandles[divId]){
        clearInterval(gf.animationHandles[divId]);
    }
    if(animation.url){
        $("#"+divId).css("backgroundImage","url('"+animation.url+"')");
    }
    if(animation.numberOfFrame > 1){
        gf.animationHandles[divId] = setInterval(function(){
            animation.currentFrame++;
            if(!loop && currentFrame > animation.numberOfFrame){
                clearInterval(gf.animationHandles[divId]);
                gf.animationHandles[divId] = false;
            } else {
                animation.currentFrame %= animation. numberOfFrame;
                gf.setFrame(divId, animation);
            }
        }, animation.rate);
    }
}
```

这将提供一个方便、灵活且相当高级的方法来为精灵设置动画。

## 在画布上移动精灵

现在我们知道如何对精灵进行动画处理了，我们需要将其移动到使其有趣的位置。这需要一些必要条件；首先，我们使用的 div 必须绝对定位。这对于两个原因非常重要：

+   对开发人员来说，一旦场景变得复杂起来，操作其他定位就成了噩梦。

+   这是浏览器计算元素位置最不昂贵的方式。

那么我们想要的是精灵相对于包含游戏的 div 定位。这意味着它也必须被定位，绝对，相对或固定。

一旦满足这两个条件，我们就可以简单地使用`top`和`left`CSS 属性来选择精灵在屏幕上出现的位置，如下图所示：

![在画布上移动精灵](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_02_07.jpg)

以下代码设置了容器 div 的正确参数并添加了一个精灵：

```js
$("#mygame").css("position", "relative").append("<div id='sprite1' style='position: absolute'>");
```

由于我们将经常使用这段代码，因此即使它很简单，我们也会将其合并到我们的框架函数中。与我们对动画构造函数所做的一样，我们将使用对象字面量来定义可选参数。

```js
/**
 * This function adds a sprite the div defined by the first argument
 **/
gf.addSprite = function(parentId, divId, options){
    var options = $.extend({
        x: 0,
        y: 0,
        width: 64,
        height: 64
    }, options);

    $("#"+parentId).append("<div id='"+divId+"' style='position: absolute; left:"+options.x+"px; top: "+options.y+"px; width: "+options.width+"px ;height: "+options.height+"px'></div>");
}
```

然后我们将编写一个函数，使一个精灵沿着 x 轴移动，另一个精灵沿着 y 轴移动。图形编程中的一个典型约定是将 x 轴从左到右，y 轴从上到下。这些函数将接受要移动的元素的 ID 和要移动到的位置作为参数。为了模仿一些 jQuery 函数的工作方式，如果你不提供第二个参数，我们的函数将返回精灵的当前位置。

```js
/**
 * This function sets or returns the position along the x-axis.
 **/
gf.x = function(divId,position) {
    if(position) {
        $("#"+divId).css("left", position); 
    } else {
        return parseInt($("#"+divId).css("left")); 
    }
}
/**
 * This function sets or returns the position along the y-axis.
 **/
gf.y = function(divId,position) {
    if(position) {
        $("#"+divId).css("top", position); 
    } else {
        return parseInt($("#"+divId).css("top")); 
    }
}
```

有了这三个简单的函数，你就拥有了生成游戏图形所需的所有基本工具。

## 预加载

然而，在大多数情况下还需要最后一件事情；资源加载。为了避免在一些图片加载完成之前启动游戏，你需要在游戏开始之前加载它们。大多数用户希望游戏只在他们决定启动它时开始加载。此外，他们想要一些关于加载过程进度的反馈。

在 JavaScript 中，你有可能为每张图片定义一个在图片加载完成后将被调用的函数。然而，这有一个限制，它不会提供关于其他图片的信息。而且你不能简单地为最后一张开始运行的图片定义一个回调，因为你无法保证图片加载的顺序，而且在大多数情况下，图片不是依次加载的，而是一次性加载一堆。

有许多可能的解决方案，大多数都同样出色。由于这段代码大多数情况下只运行一次，而且在游戏开始之前，性能在这里并不是特别重要。真正想要的是一个稳健、灵活的系统，能够知道所有图片都加载完毕的情况，并且能够追踪总体进度。

我们的解决方案将使用两个函数：一个用于将图片添加到预加载列表中，另一个用于开始预加载。

```js
gf.imagesToPreload = [];

/**
 * Add an image to the list of image to preload
 **/
gf.addImage = function(url) {
    if ($.inArray(url, gf.imagesToPreload) < 0) {
        gf.imagesToPreload.push();
    }
    gf.imagesToPreload.push(url);
};
```

这个第一个函数并不做太多事情。它只是获取一个 URL，检查它是否已经存在于我们存储预加载图片的数组中，如果新图片不在数组中，则将其添加进去。

下一个函数接受两个回调函数。第一个回调函数在所有图片加载完成时调用，第二个回调函数（如果定义了）以百分比的形式调用当前进度。

```js
/**
 * Start the preloading of the images.
 **/
gf.startPreloading = function(endCallback, progressCallback) {
    var images = [];
    var total = gf.imagesToPreload.length;

    for (var i = 0; i < total; i++) {
        var image = new Image();
        images.push(image);
        image.src = gf.imagesToPreload[i];
    }
    var preloadingPoller = setInterval(function() {
        var counter = 0;
        var total = gf.imagesToPreload.length;
        for (var i = 0; i < total; i++) {
            if (images[i].complete) {
                counter++;
            }
        }
        if (counter == total) {
            //we are done!
            clearInterval(preloadingPoller);
            endCallback();
        } else {
            if (progressCallback) {
                count++;
                progressCallback((count / total) * 100);
            }
        }
    }, 100);
}; 
```

在这个函数中，我们首先为添加到列表中的每个 URL 定义一个新的 `Image` 对象。它们将自动开始加载。然后我们定义一个将定期调用的函数。它将使用图片的 `complete` 属性来检查每个图片是否已加载。如果加载完毕的图片数量等于总图片数量，这意味着我们已经完成了预加载。

有用的是自动将用于动画的图像添加到预加载列表中。为此，只需在动画对象的末尾添加三行代码，如下所示：

```js
gf.animation = function(options) {
    var defaultValues = {
        url : false,
        width : 64,
        numberOfFrames : 1,
        currentFrame : 0,
        rate : 30
    };
    $.extend(this, defaultValues, options);
    if(this.url){
        gf.addImage(this.url);
    }
}
```

# 初始化游戏

游戏的框架部分已经完成。现在我们想要实现图形和游戏逻辑。我们可以将游戏的代码分为两部分，一部分仅在开头执行一次，另一部分会定期调用。我们将第一个称为初始化。

只要图像加载完成，就应立即执行这部分；这就是为什么我们将它作为`startPreloading`函数的结束回调。这意味着在一开始时，我们需要将所有要使用的图像添加到预加载列表中。然后，一旦用户启动游戏（例如通过点击 ID 为`startButton`的图像），我们将调用预加载程序。

以下代码使用标准的 jQuery 方式在页面准备就绪后执行函数。我不会在这里提供完整的代码，因为一些代码相当重复，但我会至少给出每个这里执行的动作的一个示例，如果你感兴趣，你可以随时查看完整的源代码。

```js
$(function() {
    var backgroundAnim = new gf.animation({
        url : "back.png"
    });
    var networkPacketsAnim = new gf.animation({
        url : "packet.png"
    });
    var bugsAnim = new gf.animation({
        url : "bug.png"
    });
    var playerAnim = new gf.animation({
        url : "player.png"
    });

    var initialize = /* we will define the function later */

   $("#startButton").click(function() {
         gf.startPreloading(initialize);
       });
});
```

以下是我们在初始化函数中需要做的事情列表：

+   创建组成游戏场景的精灵

+   创建 GUI 元素

下图展示了我们将如何构建游戏场景：

![初始化游戏](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_02_03.jpg)

不超过八个精灵：一个用于背景，一个用于玩家，三个用于网络数据包，和三个用于虫子。为了简化事情，我们只使用每个数据包/虫子组的一个精灵。这三组数据包将有相同的动画，三组虫子也一样。

为了避免添加元素时它们突然出现，我们将它们首先添加到一个不可见的元素中，直到所有精灵都创建完毕后才使此元素可见。

唯一的 GUI 元素将是包含玩家生命数的小`div`。

```js
var initialize = function() {
    $("#mygame").append("<div id='container' style='display: none; width: 640px; height: 480px;'>");
    gf.addSprite("container","background",{width: 640, height: 480});
    gf.addSprite("container","packets1",{width: 640, height: 40, y: 400});
    /* and so on */
    gf.addSprite("container","player",{width: 40, height: 40, y: 440, x: 260});

    gf.setAnimation("background", backgroundAnim);
    gf.setAnimation("player", playerAnim);
    gf.setAnimation("packets1", networkPacketsAnim);
    /* and so on */    

    $("#startButton").remove();
    $("#container").append("<div id='lifes' style='position: relative; color: #FFF;'>life: 3</div>").css("display", "block");
    setInterval(gameLoop, 100);
}
```

这个函数的最后一行是启动主循环。主循环是会定期执行的代码。它包含大部分（如果不是全部）与玩家输入没有直接关联的游戏逻辑。

# 主循环

主循环通常包含一个**有限状态机（FSM）**。FSM 由一系列状态和从一个状态到另一个状态的转换列表定义。简单游戏的 FSM，玩家需要依次点击三个出现的方框，看起来会像以下的图表：

![主循环](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_02_04.jpg)

当你实现 FSM 时，你需要考虑两件事：游戏在每个状态下应该如何行为，以及什么条件使游戏转移到新状态。FSM 的优势在于它们提供了一种正式的方法来组织游戏逻辑。这将使您更容易阅读您的代码，并且如果需要的话，您可以随时添加/更改您的逻辑。我建议你先为你的游戏绘制 FSM，并将其放在某个地方，以帮助你调试你的游戏。

对于我们的*Frogger*游戏，有 10 个状态。初始状态是`START`，两个最终状态分别是`GAMEOVER`和`WON`。以下是每个状态中确切发生的描述：

+   所有状态：数据包和虫子向右移动

+   `STARTPOS`：没有特殊情况发生

+   `LINE1`：玩家以第一行数据包的速度移动；如果玩家走出屏幕，就会死亡并回到`START`

+   `LINE2`：玩家以第二行数据包的速度移动，如果玩家走出屏幕，就会死亡并回到`START`

+   `LINE3`：玩家以第三行数据包的速度移动，如果玩家走出屏幕，就会死亡并回到`START`

+   `REST`：没有特殊情况发生

+   `LINE4`：如果玩家被第四行的虫子击中，就会死亡并回到`REST`

+   `LINE5`：如果玩家被第一行的虫子击中，就会死亡并回到`REST`

+   `LINE6`：如果玩家被第六行的虫子击中，就会死亡并回到`REST`

+   `WON`和`GAMEOVER`：没有特殊情况发生

除了`WON`和`GAMEOVER`状态外，玩家可以四处移动。这将触发以下转换：

+   成功跳跃：转到下一个状态

+   成功向左/向右滑动：保持在相同状态

+   向左/向右滑动失败的跳转：如果剩余生命大于零，回到上次的“安全”状态（`START`或`REST`），否则转移到`GAMEOVER`

## 主循环实现

编写 FSM 最易读的方法是使用 switch 语句。我们将使用两个，一个在主循环中更新游戏，另一个用于处理键盘输入。

以下代码是主循环的一部分。我们首先初始化一些变量，这些变量将用于定义游戏的行为，然后编写前面部分描述的 FSM。为了移动数据包和虫子，我们将使用一个技巧，简单地改变`background-position`。这比我们之前编写的函数少了灵活性，但在这种情况下更快，并且很容易让人以一个精灵给出无限数量的元素的假象。

```js
var screenWidth = 640;
var packets1 = {
    position: 300,
    speed: 3
}
/* and so on */

var gameState = "START";

var gameLoop = function() {
    packets1.position += packets1.speed;
    $("#packets1").css("background-position",""+ packets1.position +"px 0px");

   /* and so on */

    var newPos = gf.x("player");
    switch(gameState){
        case "LINE1":
            newPos += packets1.speed;
            break;
        case "LINE2":
            newPos += packets2.speed;
            break;
        case "LINE3":
            newPos += packets3.speed;
            break;
    }
    gf.x("player", newPos);
};
```

此时，游戏显示了所有移动的部分。 仍然没有办法让玩家控制其化身。 为了做到这一点，我们将使用 `keydown` 事件处理程序。 我们将实现两种不同的方案来移动角色。 对于水平移动，我们将使用之前编写的 `gf.x` 函数。 这是有道理的，因为这是一个非常小的移动，但对于垂直跳跃，我们将使用 `$.animate` 以使化身在许多步骤中移动到目的地，并创建更流畅的移动。

```js
$(document).keydown(function(e){
        if(gameState != "WON" && gameState != "GAMEOVER"){
            switch(e.keyCode){
                case 37: //left
                    gf.x("player",gf.x("player") - 5);
                    break;
                case 39: // right
                    gf.x("player",gf.x("player") + 5);
                    break;
                case 38: // jump
                    switch(gameState){
                        case "START":
                            $("#player").animate({top: 400},function(){
                                gameState = "LINE1";
                            });
                            break;
                        case "LINE1":
                            $("#player").animate({top: 330},function(){
                                gameState = "LINE2";
                            });
                            break;
                        /* and so on */
                        case "LINE6":
                            $("#player").animate({top: 0},function(){
                                gameState = "WON";
                                $("#lifes").html("You won!");
                            });
                            break;
                    }
            }
        }
    });
```

在这里，我们开始检查游戏的状态，以确保玩家被允许移动。 然后我们检查按下了哪个键。 左右部分都很简单明了，但跳跃部分要微妙些。

我们需要检查游戏的状态来找出玩家应该跳到哪里。 然后，我们使用传递给 `animate` 函数的回调来更新游戏的状态，这样只有在动画完成后才会更新游戏的状态。

就是这样，你现在可以控制玩家了。如果你跳上了一个数据包，玩家将会随着它移动，当你到达终点时，你就赢得了游戏。 不过，你可能已经注意到我们忘记了一些重要的东西：没有办法让玩家死亡！ 要添加这个功能，我们需要检测玩家是否处于安全位置。

# 碰撞检测

我们将使用某种碰撞检测，但这只是针对这种情况设计的非常简单的版本。 在后面的章节中，我们将会看到更一般的解决方案，但在这里不是必要的。

在这个游戏中，碰撞检测有六个重要的地方；第一部分中的三行数据包和第二部分中的三行臭虫。 两者代表完全相同的情况。 一系列的元素被一些空间分隔开。 每个元素之间的距离是恒定的，大小也是恒定的。 我们不需要知道玩家跳到了哪个数据包上，或者哪些臭虫打中了玩家，重要的是玩家是否站在了一个数据包上，或者是否被臭虫击中了。

因此我们将使用我们之前使用过的**取模技巧**来降低问题的复杂性。 我们要考虑的是以下的情况：

![碰撞检测](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_02_05.jpg)

要知道玩家是否触碰了元素，我们只需比较其 x 坐标与元素位置即可。

以下代码就做到了这一点。 首先，它检查游戏状态以了解要检测的碰撞（如果有的话），然后使用取模运算将玩家带回我们想要考虑的简化情况。 最后，它检查玩家的坐标。

```js
var detectSafe = function(state){
    switch(state){
        case "LINE1":
            var relativePosition = (gf.x("player") - packets1.position) % 230;
            relativePosition = (relativePosition < 0) ? relativePosition + 230: relativePosition;
            if(relativePosition > 110 && relativePosition < 210) {
                return true;
            } else {
                return false;
            }
            break;
        /* and so on */ 
        case "LINE4":
            var relativePosition = (gf.x("player") - bugs1.position) % 190;
            relativePosition = (relativePosition < 0) ? relativePosition + 190: relativePosition;
            if(relativePosition < 130) {
                return true;
            } else {
                return false;
            }
            break;
        /* and so on */
    }
    return true;
}
```

还有一件小事情你需要注意：取模运算可能会得到负值。 这就是为什么我们需要检查并简单地加上重复部分的宽度以转换为正值。

这是一种相当快速的检测解决方案的方法，有许多这样的情况，你可以设计自己的碰撞检测，并且使其非常有效，因为你知道在你特定的情况下需要检查什么。

现在我们可以在我们的游戏中调用这个方法。有两个地方应该这样做：在主循环中和在输入处理程序中。当我们检测到玩家死亡时，我们需要减少其生命并将其移动到正确的位置。此外，我们希望在这种情况下检测到玩家没有生命了，并将游戏状态更改为`GAMEOVER`。以下函数就是这样做的：

```js
var life = 3;
var kill = function (){
    life--;
    if(life == 0) {
        gameState = "GAMEOVER";
        $("#lifes").html("Game Over!");
    } else {
        $("#lifes").html("life: "+life);
        switch(gameState){
            case "START":
            case "LINE1":
            case "LINE2":
            case "LINE3":
                gf.x("player", 260);
                gf.y("player", 440);
                gameState = "START";
                break;
            case "REST":
            case "LINE4":
            case "LINE5":
            case "LINE6":
                gf.x("player", 260);
                gf.y("player", 220);
                gameState = "REST";
                break;
        }
    }
}
```

现在我们可以在主循环中添加碰撞检测。我们还需要检查另一件事：玩家不应该在其中一个数据包中走出屏幕。

```js
var newPos = gf.x("player");
switch(gameState){
    case "LINE1":
        newPos += packets1.speed;
        break;
    /* and so on */
}
if(newPos > screenWidth || newPos < -40){
        kill();
} else {
    if(!detectSafe(gameState)){
        kill();
    }
    gf.x("player", newPos);
}
```

在输入处理程序中，我们将代码添加到跳跃动画结束时执行的回调中。例如，要检查从起始位置跳到第一行的碰撞，我们将编写以下内容：

```js
case "START":
    $("#player").animate({top: 400},function(){
        if(detectSafe("LINE1")){
            gameState = "LINE1";
        } else {
            kill();
        }
    });
    break;
```

这里你可以看到为什么我们在`kill`函数中没有使用`gameState`。在这种情况下，玩家仍处于其先前的状态。它仍然没有“着陆”，可以这么说。只有在跳跃安全时，我们才会将玩家的状态更改为下一行。

# 摘要

现在我们有了一个完全实现了我们在本章开头定义的规范的游戏。代码还没有优化，这将是我们下一章的主题，但为了制作一个好玩的游戏，它确实需要更多的打磨。你可以添加一个高分系统，与社交网络集成，以及声音和触摸设备兼容性。

我们将在未来的章节中涵盖这些主题及更多内容。然而，有很多事情你现在已经学到了，可以用来改善游戏：你可能想为玩家死亡时添加动画，一个更好的 GUI，更漂亮的图形，能够向后跳跃，以及不止一个关卡。正是这些小细节将使你的游戏脱颖而出，你真的应该投入大部分时间来给你的游戏以专业的完成！


# 第三章：更好、更快，但不更难

我们刚刚开发的游戏在几乎所有设备和几乎所有浏览器上都能正常工作，主要原因是它非常简单，包含很少的移动精灵。然而，一旦你尝试制作一个像我们在接下来的章节中将要制作的更复杂的游戏，你会意识到你需要非常小心地编写优化代码以获得良好的性能。

在本章中，我们将回顾我们之前的代码，并提出某些方面的优化版本。其中一些优化是为了使您的游戏运行更快，而另一些是为了使您的代码更可读和更易于维护。

一般来说，实现游戏的第一个版本时，最好减少一些功能，不要过多担心性能问题，然后进行优化并添加更多功能。这有助于避免花费过多时间在游戏中可能不需要的东西上，允许您对优化进行基准测试，以确保它们真正加快了速度，最重要的是，保持您的动力。

在本章中，我们将深入探讨以下几个方面：

+   减少间隔和超时的数量

+   键盘轮询

+   使用 HTML 片段

+   避免重新排版

+   使用 CSS Transform 加速精灵定位

+   使用`requestAnimationFrame`代替超时

# 间隔和超时

在我们的游戏中，我们使用了许多`setInterval`调用。你可能会认为这些调用是多线程的，但实际上并不是。JavaScript 是严格单线程的（最近的一个例外是 WebWorkers，但我们这里不会深入讨论）。这意味着所有这些调用实际上都是依次运行的。

如果你对间隔和超时的工作原理感兴趣，我建议阅读 *John Resig* 撰写的优秀文章，*JavaScript 计时器的工作原理*（[`ejohn.org/blog/how-javascript-timers-work/`](http://ejohn.org/blog/how-javascript-timers-work/)）。

因此，间隔和超时并不会为您的代码添加多线程，有许多原因可能会使您希望避免过多使用它们。首先，它使您的代码有些难以调试。实际上，根据每次调用需要花费的时间，您的间隔将以不同的顺序执行，并且即使这些调用的周期性完全相同，它们也会有所不同。

此外，从性能方面考虑，过多使用`setInterval`和`setTimeout`可能会对较老的浏览器造成很大的负担。

另一种选择是使用一个单一的间隔来替换所有你的动画函数和游戏循环。

## 一次间隔统治它们

使用一个单一的间隔并不一定意味着你希望所有的动画以相同的速率执行。在大多数情况下，一个可接受的解决方案是允许任何基本间隔的倍数来执行动画。

通常，您的游戏循环将以给定的速率运行（假设为 30 毫秒），而您的动画将以相同的速率运行，或者是两倍、三倍、四倍等速率。但是，这并不局限于动画；您可能希望有多个游戏循环，其中一些以更低的速率执行。

例如，您可能希望在平台游戏中每秒增加水的水平。这样，玩家就有动力尽快完成关卡，否则他/她将会淹死。为了在框架中实现这一点，我们将添加一个`addCallback`函数，该函数将接受一个函数和一个速率。我们先前游戏中的游戏循环将使用此函数实现，而不是`setInterval`。

这意味着`startPreloading`函数将略有变化。在调用`endCallback`函数后，我们将启动一个`setInterval`函数，其中包含一个新函数，该函数将调用所有通过`addCallback`定义的函数，并负责动画。此外，我们将其简单地更名为`startGame`以反映用法的变化。

在游戏中，不需要显式地创建具有游戏循环的间隔，因为这由`startGame`函数自动完成；我们只需使用`addCallback`函数将其添加到游戏中。以下图片显示了这种方法与使用许多`setTimeout`函数的方法的比较：

![统一的间隔](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_03_01.jpg)

我们将通过向`initialize`函数提供这个最小刷新率来在我们的框架中实现这一点。从这一点开始，所有动画和周期性函数将被定义为它的倍数。我们仍然在 API 中使用毫秒来描述它们的速率，但是将速率内部存储为基础速率的最接近倍数。

### 代码

我们的初始化函数将使用我们之前使用的`$.extend`函数。从现在开始，我们将只有基本刷新率，但随着需要，我们将添加更多值。我们还需要定义基本刷新率的默认值，以解决用户未手动指定时的情况。

```js
gf = {
    baseRate: 30
};

gf.initialize = function(options) {
    $.extend(gf, options);
} 
```

新更名的`startGame`函数将如下所示代码所示：

```js
gf.startGame = function(progressCallback) {
    /* ... */
    var preloadingPoller = setInterval(function() {
        /* ... */
        if (counter == total) {
            //we are done!
            clearInterval(preloadingPoller);
            endCallback();
            setInterval(gf.refreshGame, gf.baseRate);
        } else {
            /* ... */
        }
    }, 100);
};
```

在这里我们没有改变太多；在`endCallback`函数之后，我们添加了对内部函数的调用：`gf.refreshGame`。正是这个函数将协调动画的刷新和周期性函数调用。

这个新函数将使用两个列表来知道何时做什么，一个用于回调，一个用于动画。我们已经有一个用于动画的列表：`gf.animationHandles`。我们将其简单重命名为`gf.animations`并创建第二个名为`gf.callbacks`的列表。

两个列表都必须包含一种方法来知道它们是否应在基础速率的当前迭代中执行。为了检测这一点，我们将为每个动画和回调使用一个简单的计数器。每次基本循环执行时，我们将递增所有这些计数器，并将它们的值与关联动画/回调的速率进行比较。如果它们相等，这意味着我们需要执行它并重置计数器。

```js
gf.refreshGame = function (){
    // update animations
    var finishedAnimations = [];

    for (var i=0; i < gf.animations.length; i++) {

        var animate = gf.animations[i];

        animate.counter++;
        if (animate.counter == animate.animation.rate) {
            animate.counter = 0;
            animate.animation.currentFrame++;
            if(!animate.loop && animate.animation.currentFrame > animate.animation.numberOfFrame){
                finishedAnimations.push(i);
            } else {
                animate.animation.currentFrame %= animate.animation.numberOfFrame;
                gf.setFrame(animate.div, animate.animation);
            }
        }
    }
    for(var i=0; i < finishedAnimations.length; i++){
        gf.animations.splice(finishedAnimations[i], 1);
    }

    // execute the callbacks
    for (var i=0; i < gf.callbacks.length; i++) {
        var call  = gf.callbacks[i];

        call.counter++;
        if (call.counter == call.rate) {
            call.counter = 0;
            call.callback();
        }
    }
} 
```

这个简单的机制将替换对`setInterval`的许多调用并解决我们之前提到的与此相关的问题。

将动画设置为 div 的函数必须相应地进行调整。就像你在前面的示例中看到的那样，负责确定动画帧的实际代码现在在`refreshGame`函数中。这意味着`setAnimation`函数只需将动画添加到列表中，而不必关心如何进行动画化。

函数的一部分检查 div 是否已经与动画关联起来现在稍微复杂了一些，但是除此之外，函数现在更简单了。

**gf.animations = [];**

```js
/**
 * Sets the animation for the given sprite.
 **/
gf.setAnimation = function(divId, animation, loop){
    var animate = {
 animation: animation,        
 div: divId,

        loop: loop,
        counter: 0
    }

    if(animation.url){
        $("#"+divId).css("backgroundImage","url('"+animation.url+"')");
    }

    // search if this div already has an animation
    var divFound = false;
    for (var i = 0; i < gf.animations.length; i++) {
        if(gf.animations[i].div == divId){
            divFound = true;
            gf.animations[i] = animate
        }
    }

    // otherwise we add it to the array
    if(!divFound) {
        gf.animations.push(animate);
    }
} 
```

我们需要编写类似的代码将回调添加到基础循环中：

```js
gf.callbacks = [];

gf.addCallback = function(callback, rate){
    gf.callbacks.push({
        callback: callback,
        rate: Math.round(rate / gf.baseRate),
        counter: 0
    });
}
```

这个函数很琐碎；唯一有趣的部分是将刷新率标准化为基础速率的倍数。你可能注意到我们在动画方面没有做任何这样的事情，但是现在我们将在创建动画的函数中执行此操作。它现在将是这样的：

```js
gf.animation = function(options) {
    var defaultValues = {
        url : false,
        width : 64,
        numberOfFrames : 1,
        currentFrame : 0,
        rate : 1
    }
    $.extend(this, defaultValues, options);
    if(options.rate){
        // normalize the animation rate
        this.rate = Math.round(this.rate / gf.baseRate);
    }
    if(this.url){
        gf.addImage(this.url);
    }
}
```

就是这样；通过这些简单的改变，我们将摆脱大多数`setInterval`函数。将功能与普通的 JavaScript 一起获得的功能复制似乎需要相当多的工作，但是你会发现随着时间的推移，当你开始调试你的游戏时，它确实会帮助很多。

# 键盘轮询

如果你玩过上一章的游戏，你可能会注意到我们的“青蛙”从左到右的移动有些奇怪，也就是说，如果你按住左键，你的角色会向左移动一点，停顿一段时间，然后开始持续向左移动。

这种行为并不是由浏览器直接引起的，而是由操作系统引起的。这里发生的情况是，当键长时间保持按下时，操作系统会重复任何键（也称为“粘滞键”）。有两个参数定义了这种行为：

+   宽限期：这是操作系统在重复按键之前等待的时间。这样做可以避免在你确实只想按一次时重复按键。

+   按键重复的频率。

你对这些参数或此行为的发生没有控制权。这一切都取决于操作系统和用户配置的方式。

对于连续动作，这远非理想。如果你在 RPG 或平台游戏中移动角色，你需要移动是连续且线性的速度。这个问题的解决方案被称为状态轮询。使用这种方法，你希望主动查询一些键的状态，而不是等待状态的改变，就像事件处理中所做的那样。

在你的游戏循环中，你会在某个时刻询问键“left”是否被按下，并根据情况做出反应。这在本地游戏中经常使用，但是 JavaScript 并没有提供这种可能性。我们将不得不自己实现一个状态轮询技术。

## 跟踪按键状态

为了做到这一点，我们将使用唯一可用的工具：`keydown` 和 `keyup` 事件。我们将注册两个事件处理程序：

1.  如果按下具有给定键码“c”的键，则第一个事件处理程序将在索引“c”处的数组中写入 `true`。

1.  当相同的键释放时，第二个事件处理程序将索引“c”的值设置为 `false`。

这种解决方案的一个好处是，我们不需要为每个可能的键初始化数组的状态，因为默认情况下它是未定义的；所以，当我们检查时，它的值将返回 `false`。下图说明了这两个事件处理程序的工作原理：

![跟踪按键状态](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_03_02.jpg)

我们将在我们的框架末尾注册这两个事件处理程序：

```js
gf.keyboard = [];
// keyboard state handler
 $(document).keydown(function(event){
    gf.keyboard[event.keyCode] = true;
});
$(document).keyup(function(event){
    gf.keyboard[event.keyCode] = false;
});
```

一旦完成了这一步，我们就可以简单地将处理左右移动的代码移动到游戏循环中，并重写它以使用 `gf.keyboard` 数组。

```js
if(gf.keyboard[37]){ //left
    newPos -= 5;
}
if(gf.keyboard[39]){ //right
    newPos += 5;
}
```

在这里，我们不需要检查玩家是否死亡，因为我们在游戏循环中已经这样做了。你只需要记住，可能会同时按下多个键。这在以前版本中不是这样的，在以前版本中，使用事件处理程序，每按下一个键就会生成一个事件。

如果现在尝试游戏，你会注意到你的玩家的水平移动要好得多。

如你所见，使用轮询的代码更漂亮，在大多数情况下更紧凑。此外，它在游戏循环内部，这总是一件好事。然而，仍然存在一些可能不是最佳解决方案的情况。使我们的青蛙跳跃就是一个很好的例子。

在选择事件处理和轮询之间，真正取决于情况，但一般来说，如果你想对按键做出一次反应，你会使用事件，如果你想对按键持续做出反应，你会使用轮询。

# HTML 片段

在这里，我们将看一些创建精灵的代码中的小优化。由于这个函数在我们整个游戏中仅调用了八次，并且仅在初始化阶段调用，所以在这种情况下它的速度并不是很重要。然而，在许多情况下，你需要在游戏过程中创建大量的精灵，例如，在射击游戏中射击激光时，创建平台游戏的关卡或 RPG 地图时。

这种技术避免了每次将精灵添加到游戏中都解析 HTML 代码（描述一个精灵）。它使用了所谓的 HTML 片段，这是一种从常规 HTML 节点树中截取的分支。

![HTML 片段](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_03_03.jpg)

jQuery 提供了一种非常简单的方法来生成这样的片段：

```js
var fragment = $("<div>fragment</div>");
```

在这个例子中，变量 `fragment` 将在内存中保存 HTML 元素，直到我们需要使用它。它不会自动添加到文档中。如果以后想要添加它，只需简单地编写：

```js
$("#myDiv").append(fragment);
```

请记住，片段仍然引用着已添加的元素，这意味着如果稍后将其添加到另一个位置，它将从先前的位置删除，并且如果修改它，你也将修改文档。

要避免这种情况，你需要在将片段插入文档之前将其克隆，如下代码所示：

```js
$("#myDiv").append(fragment.clone());
```

这正是我们将重写 `addSprite` 函数使其更快的方式：

```js
gf.spriteFragment = $("<div style='position: absolute'></div>");
gf.addSprite = function(parentId, divId, options){
    var options = $.extend({}, {
        x: 0,
        y: 0,
        width: 64,
        height: 64
    }, options);
    $("#"+parentId).append(gf.spriteFragment.clone().css({
            left:   options.x,
            top:    options.y,
            width:  options.width,
            height: options.height}).attr("id",divId));
}; 
```

在这里，我们为每个精灵共同的部分创建了一个片段。然后，在将其添加到文档之前，我们克隆它并添加了 `addSprite` 函数提供的特殊参数，例如它的位置、大小和 ID。

就像我之前说的，对于我们非常简单的游戏，你可能不会注意到任何可见的变化，但这段代码更高效，在我们生成大量精灵的更复杂的游戏中会很方便。

# 避免回流

在修改 DOM 时，必须尽量避免生成整个文档或大部分文档的完全回流。有许多方法可以最小化做到这一点的风险，而且现代浏览器在进行优化时做得相当不错。

通常，浏览器会尝试在重新回流文档之前尽可能地重新组织修改。然而，如果尝试访问依赖于这些修改之一的信息，它将不得不执行重新回流以便能够计算新信息。

一个相当不错的经验法则是尽量避免像瘟疫一样读取 DOM，并作为最后的手段，将所有读取分组，并在刷新循环结束时执行它们。

在我们的游戏中，有一个地方我们正处于这种情况：每次访问玩家角色的 X 位置时，我们都会强制浏览器重新回流。在游戏循环中，位置和大小可能是最经常访问的信息之一。加快速度的一个简单方法是避免从 DOM 获取它们。事实上，只要它们通过框架函数设置，我们就可以简单地将它们存储在某个地方，并在需要时检索它们。

为此，我们将使用 jQuery 的 `data` 函数将我们的精灵与包含这些有趣值的对象文字关联起来。`addSprite` 函数将以此方式扩展：

```js
gf.addSprite = function(parentId, divId, options){
    /* ... */
    $("#"+parentId).append(gf.spriteFragment.clone().css({
            left:   options.x,
            top:    options.y,
            width:  options.width,
            height: options.height}).attr("id",divId).data("gf",options));
}
```

然后，在 `gf.x` 和 `gf.y` 函数中，我们将使用这个值而不是 CSS 属性：

```js
gf.x = function(divId,position) {
    if(position) {
        $("#"+divId).css("left", position); 
 $("#"+divId).data("gf").x = position;
    } else {
 return $("#"+divId).data("gf").x; 
    }
}
gf.y = function(divId,position) {
    if(position) {
        $("#"+divId).css("top", position); 
 $("#"+divId).data("gf").y = position;
    } else {
 return $("#"+divId).data("gf").y; 
    }
}
```

这还有一个好处，就是消除了两个 `parseInt` 值，而且游戏的代码甚至不需要改变！

# 使用 CSS 转换移动您的精灵

使用 CSS 转换是一种简单的技巧，可以让您比使用 CSS `top` 和 `left` 属性在屏幕上移动对象更快。如果您决定使用这个，您必须意识到并非所有的浏览器都支持它。

我们不会进入太多细节，因为 CSS 转换在下一章*环视*中有解释。下面的代码是使用 CSS 转换所需的修改：

```js
gf.x = function(divId,position) {
    if(position) {
        var data = $("#"+divId).data("gf");
        var y = data.y;
        data.x = position;
        $("#"+divId).css("transform", "translate("+position+"px, "+y+"px)");
    } else {
        return $("#"+divId).data("gf").x; 
    }
}
gf.y = function(divId,position) {
    if(position) {
        var data = $("#"+divId).data("gf");
        var x = data.x;
        data.y = position;
        $("#"+divId).css("transform", "translate("+x+"px, "+position+"px)"); 
    } else {
        return $("#"+divId).data("gf").y; 
    }
}
```

正如您在代码的突出部分中所看到的，我们需要每次设置好两个坐标。这意味着当我们修改 x 坐标时，我们必须检索 y 坐标，反之亦然。

# 使用 requestAnimationFrame 而不是 timeouts

最近在浏览器中添加了一个新的功能，以使动画更加流畅： `requestAnimationFrame`。这使得浏览器告诉您什么时候最适合动画您的页面，而不是在您喜欢的任何时间都进行动画。您应该使用这个代替使用 `setInterval` 或 `setTimeout` 来注册回调。

当您使用 `requestAnimationFrame` 时，是浏览器决定何时调用函数。因此，您必须考虑自上次调用以来过去的确切时间。用于定义此时间的标准规范是毫秒（就像您使用 `Date.now()` 可以得到的那些），但现在由一个高精度计时器给出。

由于这两个版本的实现存在，而且该功能在大多数浏览器中都有供应商前缀，您应该使用一个工具来抽象脏细节。我建议阅读以下两篇文章，两篇文章都提供了可用的代码片段：

+   [`paulirish.com/2011/requestanimationframe-for-smart-animating/`](http://paulirish.com/2011/requestanimationframe-for-smart-animating/)

+   [`www.makeitgo.ws/articles/animationframe/`](http://www.makeitgo.ws/articles/animationframe/)

# 总结

在这一章中，我们花了一些时间优化了我们在第二章中编写的游戏，*创建我们的第一个游戏*。我们看到了一些优化技术，将使我们的游戏更加流畅，而不会影响我们的代码可读性。

我们建立的框架现在是一个合理的基础，我们可以在接下来的章节中构建一个更完整的框架。我们将在接下来的章节中开始添加创建瓷砖地图的能力，这些地图将用于实现一个平台游戏。


# 第四章：横看成岭侧成峰

现在是时候制作一个更复杂的游戏了。我们将实现一个非常流行的类型，即 2D 平台游戏。这一类型的早期示例包括 *超级马里奥兄弟* 和 *索尼克小子*。这些游戏通常使用小型重复的精灵，称为瓦片地图，进行关卡设计。我们将添加这些内容，以及更通用的碰撞检测，到我们的框架中。对于游戏逻辑本身，我们将使用面向对象的代码。

这是我们将不得不添加到我们的框架中的功能的快速列表：

+   离线 div

+   分组

+   精灵变换

+   瓦片地图

+   碰撞检测

首先，我们将逐个遍历所有这些，然后开始游戏。

# 离线 div

如前一章节末尾所解释的那样，避免重排是加快速度的好方法。在进行操作时完全避免查询 DOM 状态并不总是容易的。即使您非常小心，作为框架开发者，您也永远不确定您的框架的用户会做什么。然而，有一种方法可以减少重排的负面影响；分离您正在操作的 DOM 片段，修改它，然后将其重新附加到文档中。

假设您有一个带有 ID `box` 的节点，并且想要以复杂的方式操纵其子元素。以下代码向您展示了如何分离它：

```js
// detach box
var box = $("#box").detach();

var aSubElement = box.find("#aSubElement")
// and so on

// attach it back
box.appendTo(boxParent);
```

这需要对我们的框架 API 进行小的修改；到目前为止，我们使用字符串来标识精灵。这会导致需要将精灵作为文档的一部分。例如，如果您调用 `gf.x("sprite")`，jQuery 将尝试在文档中查找 ID 为 `sprite` 的节点。如果分离精灵或其父级之一，则该函数将找不到其 ID。

解决方案很简单，只需将 DOM 节点本身提供给我们框架的函数。由于我们使用 jQuery，因此我们将在 jQuery 中包装此节点。让我们比较当前 API 和提议的 `gf.x` 函数的 API。

```js
// current API
var xCoordinate = gf.x("mySprite");

// proposed API
var xCoordinate = gf.x($("#mySprite"));
```

此解决方案还有另一个优点；它允许进一步优化。如果我们看一下此函数的实现，我们会发现另一个问题：

```js
gf.x = function(divId,position) {
    if(position) {
        $("#"+divId).css("left", position);
        $("#"+divId).data("gf").x = position;
    } else {
        return $("#"+divId).data("gf").x; 
    }
}
```

每次调用函数时，都可以看到 jQuery 被用于检索元素。任何对 DOM 的访问（即使在选择器中使用元素的 ID 来查找元素）都会产生性能成本。理想情况下，如果相关元素被使用超过几次，您可能希望对其进行缓存以提高性能。这是由所提出的 API 可能实现的。

实现非常简单，因此我们将只显示 `gf.x` 函数：

```js
gf.x = function(div,position) {
    if(position) {
        div.css("left", position);
        div.data("gf").x = position;
    } else {
        return div.data("gf").x; 
    }
}
```

# 分组

将游戏元素以分层方式组织起来非常方便。一个典型的游戏可以这样组织：

![分组](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_04_01.jpg)

为了允许这一点，我们需要向我们的框架添加一个非常简单的东西，称为组。组基本上是一个简单的 div，位置与精灵完全相同，但没有背景和宽度和高度。我们将添加一个 `gf.addGroup` 函数来为我们执行此操作。它的签名将与 `gf.addSprite` 的签名相同，但选项参数将仅保存 *x* 和 *y* 坐标。

以下示例向您展示了如何生成前面图示中显示的树：

```js
var enemies   = gf.addGroup(container,"enemies");
var enemy1    = gf.addSprite(group,"enemy1",{...});
var enemy2    = gf.addSprite(group,"enemy2",{...});

var player    = gf.addSprite(group,"player",{...});

var level     = gf.addGroup(container,"level");
var ground    = gf.addSprite(group,"ground",{...});
var obstacle1 = gf.addSprite(group,"obstacle1",{...});
var obstacle2 = gf.addSprite(group,"obstacle2",{...});
```

此功能的实现与 `gf.addSprite` 的实现非常相似：

```js
gf.groupFragment = $("<div style='position: absolute; overflow: visible;'></div>");
gf.addGroup = function(parent, divId, options){
    var options = $.extend({
        x: 0,
        y: 0,
    }, options);
    var group = gf.groupFragment.clone().css({
            left:   options.x,
            top:    options.y}).attr("id",divId).data("gf",options);
    parent.append(group);
    return group;
}
```

在我们的游戏屏幕上有多个实体使得有一个简单的方法来区分它们成为必要。我们可以在通过 `$.data` 函数与节点关联的对象字面量中使用标志，但我们将改用 CSS 类。这有一个优点，就是可以非常容易地检索或过滤所有相同类型的元素。

要实现这一点，我们只需改变精灵和组的片段。我们将给 CSS 类命名为命名空间。在 CSS 中，命名空间简单地在类名中加上前缀。例如，我们将给我们的精灵添加类 `gf_sprite`；这将最大程度地减少另一个插件使用相同类的机会，与 `sprite` 相比。

新的片段看起来像这样：

```js
gf.spriteFragment = $("<div class='gf_sprite' style='position: absolute; overflow: hidden;'></div>");
gf.groupFragment = $("<div class='gf_group' style='position: absolute; overflow: visible;'></div>");
```

现在，如果您想要查找所有子精灵，您可以这样写：

```js
$("#someElement").children(".gf_sprite");

```

# 精灵变换

有许多情况下，您将希望以简单的方式转换您的精灵。例如，您可能希望使它们变大或变小，或者旋转或翻转它们。实现这一点的最方便的方法是使用 CSS 变换。在过去几年中，大多数浏览器都已很好地支持 CSS 变换。

如果您决定使用此功能，您只需意识到 Microsoft Internet Explorer 9 之前的版本不支持它。有可能使用专有的 `filter` CSS 属性，但在大多数情况下，这太慢了。

另一个可能性是使用一些旧的 8 位和 16 位游戏中使用的技术。您只需为变换后的精灵生成图像。这有很快的优势，并且与所有浏览器兼容。另一方面，它会增加您艺术品的大小，并且如果您需要在某个时候更改您的精灵，则需要重新生成所有的变换。

在这里，我们将仅实现 CSS 变换解决方案，因为在大多数情况下，仅针对现代浏览器是可接受的。

## CSS 变换

CSS 有许多可能的变换，甚至是 3D 变换（您可以查看 [`github.com/boblemarin/Sprite3D.js`](https://github.com/boblemarin/Sprite3D.js) 以获取一些非常好的示例），但我们将坚持旋转和缩放。

在大多数浏览器中，CSS 属性“transform”都是供应商前缀的。意思是，在 Safari 中，它将被称为`-webkit-transform`，而在 Firefox 中，将是`-moz-transform`。以往处理这类属性是一件真正痛苦的事情，但使用 jQuery 1.8，你可以简单地忘记它，就像没有前缀一样。jQuery 会在需要时自动使用正确的前缀。

正如之前所解释的，这个属性可以取许多值，我们将在这里专注于`rotate`和`scale`两个：`rotate`的语法如下：

```js
transform: rotate(angle)
```

在这里，`angle`是以**deg**或**rad**（分别缩写为度和弧度）表示的顺时针角度。旋转默认是围绕元素的原点进行的，大多数情况下，这是你希望的，但如果出于某种原因你想要改变它，你可以简单地使用`transform-origin` CSS 属性来实现。

例如，如果你想要逆时针旋转你的元素 10 度，你会写：

```js
transform: rotate(-10deg);
```

如果你的元素是一个红色的正方形，它会像这样：

![CSS transform](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_04_02.jpg)

`scale`的工作方式非常相似，但具有两种可能的语法：

+   `transform: scale(ratio)`

+   `transform: scale(ratio_x, ratio_y)`

如果您只指定一个值，结果将是各向同性的变换；换句话说，沿着两个轴的大小是相等的。相反，如果你指定两个值，第一个将沿着 x 轴缩放，第二个将沿着 y 轴缩放（各向异性变换）。下图说明了这两者之间的区别。

![CSS transform](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_04_03.jpg)

在我们的情况下，我们将不包括任意的各向异性缩放到我们的框架中，但我们仍将使用双值语法，因为这将允许我们翻转我们的精灵；的确，如果我们写`scale(-1,1)`，这实际上意味着“横向翻转元素并保持纵向不变”。当然，这对于除 1 之外的值也适用；只要两个值的大小相同，你只会翻转精灵而不改变其长宽比。

对于 transform 属性的这两个值，很好地配合在一起，所以如果你想要将一个元素逆时针旋转 10 度，垂直翻转它，并使其大小加倍，你会这样写：

```js
transform: rotate(-10deg) scale(2,-2);
```

## 将 transform 添加到框架中

现在我们必须写一个函数来代替我们完成这个工作。与我们框架的大多数函数一样，我们将使用对象字面量来保存可选参数，并将函数应用于的节点作为第一个参数。调用这个函数来生成示例的示例为：

```js
gf.transform (myDiv, {rotate: -10, scale: 2, flipV: true});
```

角度以度为单位，`flipH`和`flipV`选项是布尔值。省略的参数的值（在本例中是`flipH`）将不会默认为常规值；相反，我们将采用给定元素的该参数的当前值。这将允许您两次调用变换函数并改变两个不同的参数，而无需知道另一个调用正在做什么。例如：

```js
gf.transform (myDiv, {rotate: -10});
// do some other things
gf.transform (myDiv, {scale: 2, flipV: true});
```

然而，这意味着我们将无法像过去那样使用`$.extend`函数。相反，我们将不得不手动检查给定元素的未定义参数的存储值。

这些值将存储在与`gf`键关联的对象文字中，该键与具有`$.data`函数的元素相关联。这也意味着在创建精灵（或组）时，我们需要为这些属性定义默认值。例如，`addSprite`函数将以以下方式开始：

```js
gf.addSprite = function(parent, divId, options){
    var options = $.extend({
        x: 0,
        y: 0,
        width: 64,
        height: 64,
        flipH: false,
      flipV: false,
      rotate: 0,
      scale: 1
    }, options);
//...
```

一旦你理解了 CSS `transform`属性的工作方式，实现我们的`gf.transform`函数将变得非常简单：

```js
gf.transform = function(div, options){
   var gf = div.data("gf");
   if(options.flipH !== undefined){
      gf.flipH = options.flipH;
   }
   if(options.flipV !== undefined){
      gf.flipV = options.flipV;
   }
   if(options.rotate !== undefined){
      gf.rotate = options.rotate;
   }
   if(options.scale !== undefined){
      gf.scale = options.scale;
   }
   var factorH = gf.flipH ? -1 : 1;
   var factorV = gf.flipV ? -1 : 1;
   div.css("transform", "rotate("+gf.rotate+"deg) scale("+(gf.scale*factorH)+","+(gf.scale*factorV)+")");
}
```

再一次，这是一个简单的函数，会提供出色的功能，并允许我们在游戏中创建整洁的效果。根据你的游戏，你可能希望将各向异性缩放加入其中，甚至是 3D 转换，但函数的基本结构和 API 可以保持不变。

# 瓦片地图

瓦片地图是制作许多游戏的常用工具。其背后的理念是大多数关卡由类似的部分组成。例如，地面很可能会重复很多次，只是有少许变化；会有几种不同的树反复出现很多次，以及一些物品，如石头、花或草将以完全相同的精灵表示多次出现。

这意味着使用一个大图像来描述你的关卡并不是以空间为最有效的解决方案。你真正想要的是能够给出所有唯一元素的列表，然后描述它们如何组合生成你的关卡。

瓦片地图是最简单的实现方式。但是它增加了一个限制；所有元素都必须具有相同的大小并放置在网格上。如果你能够适应这些约束，这种解决方案将变得非常高效；这就是为什么那么多老游戏都是用它创建的原因。

我们将从实现一个非常天真的版本开始，然后在本章末尾展示如何在大多数情况下以不太多的工作快速实现它。

总而言之，瓦片地图由以下组成：

+   一系列图片（我们在框架中称之为动画）

+   一个描述图像放置位置的二维数组

以下图示说明了这一点：

![瓦片地图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_04_04.jpg)

除了有助于减小游戏尺寸之外，瓦片地图还提供以下优点：

+   检测与瓦片地图的碰撞非常容易。

+   描述瓦片地图外观的数组还包含关于级别的语义信息。例如，瓦片 1 到 3 是地面瓦片，而 4 到 6 是景观的一部分。这将使您能够轻松“阅读”级别并对其做出反应。

+   生成不同层次的随机变化非常简单。只需按照几条规则创建二维数组，每次玩家重新开始游戏时，游戏都会有所不同！

+   存在许多开源工具可帮助您创建它们。

但是，您必须意识到也有一些约束：

+   由于组成瓦片地图的所有元素大小相同，如果要创建更大的元素，则必须将其分解为较小的部分，这可能会很繁琐。

+   即使具有很多才华，它也会给您的游戏带来一定的连续外观。如果您不想在级别周围重复一些块，则瓦片地图不适合您。

## 朴素的实现

我们已经知道如何创建精灵，所以基本上我们需要为创建瓦片地图生成组成它的精灵。就像`gf.addSprite`一样，我们的`gf.addTilemap`函数将接受父 div、生成的瓦片地图的 ID 以及描述选项的对象字面量。

选项是瓦片地图的位置、每个瓦片的尺寸、以及横向和纵向组成瓦片地图的瓦片数量、动画列表和描述瓦片位置的二维数组。

我们将遍历二维数组，并根据需要创建精灵。在我们的瓦片地图中有些地方没有精灵往往是很方便的，因此我们将使用以下约定：

+   如果所有条目都是零，则意味着不需要在此位置创建精灵

+   如果所有地方的数字都大于零，则表示应创建一个带有动画的精灵，该动画位于动画数组中对应此数字减一的索引处

这通常是您希望在将其添加到文档之前创建完整瓦片地图的地方。我们将使用克隆的片段来生成包含所有瓦片的`div`标签，并将我们用于精灵的克隆片段添加到其中。只有在创建所有瓦片后，我们才会将瓦片地图添加到文档中。

这里还有一个微妙之处。我们将向我们的瓦片添加两个类，一个标记瓦片所属的列，另一个标记瓦片所属的行。除此之外，目前代码中没有其他重要的细节：

```js
gf.tilemapFragment = $("<div class='gf_tilemap' style='position: absolute'></div>");
gf.addTilemap = function(parent, divId, options){
    var options = $.extend({
        x: 0,
        y: 0,
        tileWidth: 64,
        tileHeight: 64,
        width: 0,
        height: 0,
        map: [],
        animations: []
    }, options);

    //create line and row fragment:
    var tilemap = gf.tilemapFragment.clone().attr("id",divId).data("gf",options);
    for (var i=0; i < options.height; i++){
        for(var j=0; j < options.width; j++) {
            var animationIndex = options.map[i][j];

            if(animationIndex > 0){
                var tileOptions = {
                    x: options.x + j*options.tileWidth,
                    y: options.y + i*options.tileHeight,
                    width: options.tileWidth,
                    height: options.tileHeight
                }
                var tile = gf.spriteFragment.clone().css({
                    left:   tileOptions.x,
                    top:    tileOptions.y,
                    width:  tileOptions.width,
                    height: tileOptions.height}
                ).addClass("gf_line_"+i).addClass("gf_column_"+j).data("gf", tileOptions);

                gf.setAnimation(tile, options.animations[animationIndex-1]);

                tilemap.append(tile);
            }
        }
    }
    parent.append(tilemap);
    return tilemap;
}
```

就这些了。这将在初始化时生成整个瓦片地图。这意味着非常大的瓦片地图会很慢。在本章末尾，我们将看到如何仅生成可见部分的瓦片地图。

# 碰撞检测

这是我们框架的一个非常重要的部分，我们将从精灵与瓦片地图碰撞的情况开始看看我们将如何做到这一点。这种情况有一个好处，即比一般情况更容易，但仍然使用了大部分相同的基本思想。然而，我们将坚持轴对齐元素。这意味着不会在此处显示与旋转元素的碰撞。  

## 与瓦片地图碰撞

找到与精灵碰撞的瓦片地图的瓦片可以分为两部分。首先找到表示两者交集的框。然后，列出此框中的所有精灵。下图中以红色显示了一些可能的交叉点列表：

![与瓦片地图碰撞](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_04_05.jpg)

一开始可能会觉得复杂，但是如果你考虑到这与寻找两个一维交叉点（每个轴一个）完全相同的问题，那就会变得容易得多。

你可能没有意识到，在我们的*青蛙过河*克隆中，我们使用了一维交叉的简化版本来检测碰撞。下图显示了两个段，**a**和**b**的典型一维交叉**i**的样子：

![与瓦片地图碰撞](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_04_06.jpg)

在这种情况下，交叉点只是第二个元素，因为它完全包含在第一个元素中。下图显示了另外三种可能的情况：

![与瓦片地图碰撞](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_04_07.jpg)

解决这个问题的一种方法是从第二个元素的角度来表达解决方案。两个点将定义区间；我们将最左边的点称为`i1`，最右边的点称为`i2`。

首先考虑这样一个情况，即确实存在这样的交叉点，两个元素相互接触。您可能会发现`i1`是`a1`和`b1`之间的较大点。以同样的方式，`i2`是`a2`和`b2`之间的较小点。但是，如果两个区间不相交怎么办？如果区间`a`在其左侧，我们将简单地返回`i1=b1`和`i2=b1`，如果区间`a`在其右侧，我们将返回`i1=b2`和`i2=b2`。为了计算这个，我们只需要将`i1`和`i2`的结果约束在`b1`和`b2`之间。

结果函数如下所示：

```js
gf.intersect = function(a1,a2,b1,b2){
    var i1 = Math.min(Math.max(b1, a1), b2);
    var i2 = Math.max(Math.min(b2, a2), b1);
    return [i1, i2];
}
```

好处是我们每个点只使用两次比较。现在我们可以将此应用于我们的二维问题。下图显示了如何将框交叉分解为两个线交叉点：

![与瓦片地图碰撞](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_04_08.jpg)

### 寻找碰撞瓦片

现在我们将编写一个函数，它接受一个精灵和一个瓦片地图。然后，它将为两个轴找到交叉点：x1 到 x2 和 y1 到 y2。现在点（x1，y1）将是交集框的左上角，点（x2，y2）将是右下角。

然而，我们在砖块地图中真正想要的不是坐标，而是二维数组中的索引。因此，我们将首先转换坐标，使原点是瓦片地图的左上角。然后，我们将根据单个瓦片的宽度和相应的高度来划分新坐标。在执行此操作的结果四舍五入后，我们将得到组成相交框的左上角和右下角瓦片的索引：

```js
gf.tilemapBox = function(tilemapOptions, boxOptions){
    var tmX  = tilemapOptions.x;
    var tmXW = tilemapOptions.x + tilemapOptions.width * tilemapOptions.tileWidth;
    var tmY  = tilemapOptions.y;
    var tmYH = tilemapOptions.y + tilemapOptions.height * tilemapOptions.tileHeight;

    var bX  = boxOptions.x;
    var bXW = boxOptions.x + boxOptions.width;
    var bY  = boxOptions.y;
    var bYH = boxOptions.y + boxOptions.height;

    var x = gf.intersect(tmX,tmXW, bX, bXW);
    var y = gf.intersect(tmY, tmYH, bY, bYH);

    return {
        x1: Math.floor((x[0] - tilemapOptions.x) / tilemapOptions.tileWidth),
        y1: Math.floor((y[0] - tilemapOptions.y) / tilemapOptions.tileHeight),
        x2: Math.ceil((x[1] - tilemapOptions.x) / tilemapOptions.tileWidth),
        y2: Math.ceil((y[1] - tilemapOptions.y) / tilemapOptions.tileHeight)
    }
}
```

现在我们将在碰撞检测函数中使用这个结果。我们只需列出这两个点之间的所有瓦片。我们将使用二维数组来查找所有非零条目，然后使用我们为线和列定义的类来找到我们的瓦片。

```js
gf.tilemapCollide = function(tilemap, box){
    var options = tilemap.data("gf");
    var collisionBox = gf.tilemapBox(options, box);
    var divs = []

    for (var i = collisionBox.y1; i < collisionBox.y2; i++){
        for (var j = collisionBox.x1; j < collisionBox.x2; j++){
            var index = options.map[i][j];
            if( index > 0){
                divs.push(tilemap.find(".gf_line_"+i+".gf_column_"+j));
            }
        }
    }
    return divs;
}
```

这将允许我们找到与精灵发生碰撞的所有瓦片，但我们必须确保我们为精灵和瓦片地图提供的坐标是正确的。如果精灵在一个向右移动了十个像素的组中，我们将不得不将十添加到精灵的 x 坐标值；否则，碰撞检测方法将不会注意到它。

我们可以编写一个版本的这个函数，它查看所有精灵和瓦片地图的坐标，以找出它们的相对偏移量。这会使函数稍微慢一些，稍微复杂一些，但你应该能够做到。

## 精灵与精灵的碰撞

用于检测两个精灵是否发生碰撞的函数将使用我们刚刚编写的同一维度交集函数。要使两个精灵发生碰撞，我们必须在两个一维投影上都发生碰撞。

如果 `gf.intersect` 函数返回的间隔长度为零（两个值相等），则表示这两个精灵在此轴上发生碰撞。要使两个精灵发生碰撞，两个投影都必须发生碰撞。

我们的函数实现非常简单，因为大部分逻辑都包含在 `gf.intersect` 函数中：

```js
gf.spriteCollide = function(sprite1, sprite2){
   var option1 = sprite1.data("gf");
   var option2 = sprite2.data("gf");

   var x = gf.intersect(
      option1.x,
      option1.x + option1.width,
      option2.x,
      option2.x + option2.width);
   var y = gf.intersect(
      option1.y,
      option1.y + option1.height,
      option2.y,
      option2.y + option2.height);

   if (x[0] == x[1] || y[0] == y[1]){
      return false;
   } else {
      return true;
   }
}
```

# 编写游戏

我们现在有了开始游戏所需的所有工具。对于这个游戏，我们将使用 Kenney Vleugels 的精美艺术作品（[`www.kenney.nl`](http://www.kenney.nl)）。这将是一个经典的平台游戏，玩家可以在其中移动和跳跃。

将有两种类型的敌人，一种是一种类似于斑点的物体，另一种是一种飞行昆虫。为了简单起见，玩家是不朽的，并在接触到敌人时将其杀死。我们将按以下顺序描述游戏的每个部分：

+   游戏屏幕的基本设置

+   用于玩家的面向对象代码

+   玩家控制

+   视差滚动

+   敌人

# 游戏屏幕的基本设置

这与我们为 *Frogger* 克隆所做的非常相似。以下是我们将组织游戏屏幕的方式：

![游戏屏幕的基本设置](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_04_09.jpg)

在这个游戏中我们将有很多动画；玩家有三个，每个敌人有三个，两个背景动画有两个。为了使事情更加可读，我们将对它们进行分组。玩家和敌人的动画将分别存储在对象字面量中，而瓷砖的动画将存储在数组中。

这里是我们代码的一部分摘录：

```js
var playerAnim = {
    stand: new gf.animation({
        url: "player.png",
        offset: 75
    }),
    walk:  new gf.animation({
        url:    "player.png",
        offset: 150,
        width:  75, 
        numberOfFrames: 10,
        rate: 90
    }),
    jump:  new gf.animation({
        url: "player.png",
        offset: 900
    })
};

var slimeAnim = {
   stand: new gf.animation({
        url: "slime.png"
    }),
    walk: new gf.animation({
        url: "slime.png",
        width:  43, 
        numberOfFrames: 2,
        rate: 90
    }),
    dead: new gf.animation({
        url: "slime.png",
        offset: 86
    })
};

var flyAnim = {
   stand: new gf.animation({
        url: "fly.png"
    }),
   ...
}
var tiles = [
    new gf.animation({
        url: "tiles.png"
    }),
    new gf.animation({
        url: "tiles.png",
        offset: 70
    }),
    ...
];
```

# 玩家的面向对象代码

在你的游戏中使用面向对象(OO)代码有许多原因。首先，这是组织代码的非常好的方式。其次，它提供了一些有用的方式来重用和扩展您的代码。

如果你不熟悉面向对象编程，JavaScript 可能不是学习的最佳语言。我们不会深入讨论 OO 的理论；即使没有，你也应该能够看到我们将要编写的代码背后的逻辑以及它带来了什么。

由于我们只需要一个玩家，我们将创建一个匿名类并立即实例化它。这相当不寻常，只在这种特殊情况下才有意义。这是我们类的框架，具有所有方法，但没有它们的实现。我们稍后将逐个查看它们。

```js
var player = new (function(){
        var acceleration = 9;
        var speed = 20;
        var status = "stand";
        var horizontalMove = 0;

        this.update = function (delta) {
            //...
        };

        this.left = function (){
            //...
        };

        this.right = function (){
            //...
        };

        this.jump  = function (){
            //...
        };

        this.idle  = function (){
            //...
        };
});
```

正如你所看到的，我们首先定义了一些稍后将要使用的变量，然后定义了对象的方法。

## 更新玩家的位置

我们为玩家沿 y 轴的移动实现了一个非常基本的物理模拟；如果没有碰撞发生，头像将以给定的加速度和有限的最大速度下落。这足以生成整洁的跳跃轨迹。

让我们看看`update`函数做了什么。首先，它需要计算头像的下一个位置：

```js
var delta = 30;
speed = Math.min(100,Math.max(-100,speed + acceleration * delta / 100.0)); 
var newY = gf.y(this.div) + speed * delta / 100.0;
var newX = gf.x(this.div) + horizontalMove;
var newW = gf.width(this.div);
var newH = gf.height(this.div);
```

在这段代码中，你可以看到我们计算了速度；这是玩家的垂直速度。我们在这里使用了正确的物理规则，即时间间隔后的速度等于*前一个速度加上时间间隔的加速度*。然后将其限制在-100 到 100 之间，以模拟终端速度。在这里，加速度是恒定的，重力也是如此。

然后我们使用这个速度来计算沿 y 轴的下一个位置，同样使用正确的物理规则。

沿 x 轴的新位置要简单得多；它是由玩家控制引起的水平移动修改后的当前位置（我们稍后将看到这个值是如何生成的）。

然后我们需要检查碰撞以查看头像是否真的可以去想去的地方，或者是否有障碍物。为此，我们将使用之前编写的`gf.tilemapCollision`方法。

一旦我们拥有所有与我们的精灵碰撞的瓷砖，我们可以做什么？我们将查看其中任何一个并通过最短可能的移动将精灵移出它们的路径。为此，我们将计算精灵与瓷砖之间的确切交叉点，并找出其宽度或高度哪个是其较大的尺寸。如果宽度大于高度，则意味着在 y 轴上移动较短，如果高度大于宽度，则在 x 轴上移动较短。

如果我们对所有瓷砖都这样做，我们将把角色移到一个不与任何瓷砖碰撞的位置。这是我们刚刚描述的全部代码：

```js
var collisions = gf.tilemapCollide(tilemap, {x: newX, y: newY, width: newW, height: newH});
var i = 0;
while (i < collisions.length > 0) {
    var collision = collisions[i];
    i++;
    var collisionBox = {
        x1: gf.x(collision),
        y1: gf.y(collision),
        x2: gf.x(collision) + gf.width(collision),
        y2: gf.y(collision) + gf.height(collision)
    };

    var x = gf.intersect(newX, newX + newW, collisionBox.x1,collisionBox.x2);
    var y = gf.intersect(newY, newY + newH, collisionBox.y1,collisionBox.y2);

    var diffx = (x[0] === newX)? x[0]-x[1] : x[1]-x[0];
    var diffy = (y[0] === newY)? y[0]-y[1] : y[1]-y[0];
    if (Math.abs(diffx) > Math.abs(diffy)){
        // displace along the y axis
         newY -= diffy;
         speed = 0;
         if(status=="jump" && diffy > 0){
             status="stand";
             gf.setAnimation(this.div, playerAnim.stand);
         }
    } else {
        // displace along the x axis
        newX -= diffx;
    }
    //collisions = gf.tilemapCollide(tilemap, {x: newX, y: newY, width: newW, height: newH});
}
gf.x(this.div, newX);
gf.y(this.div, newY);
horizontalMove = 0;
```

你会注意到，如果我们检测到我们需要沿 y 轴向上移动玩家，我们会改变角色动画和状态，如果玩家正在跳跃，这仅仅是因为这意味着玩家已经着陆。

这段代码足以包含你在关卡中制作出一个体面的玩家移动所需的所有规则。

## 控制玩家的角色

除了`update`之外的所有方法都直接对应于玩家的特定输入类型。它们将在主循环中在相应的键被检测为按下后被调用。如果没有键被按下，将调用空闲函数。

让我们看一下将玩家向左移动的函数：

```js
this.left = function (){
            switch (status) {
                case "stand":
                    gf.setAnimation(this.div, playerAnim.walk, true);
                    status = "walk";
                    horizontalMove -= 7;
                    break;
                case "jump":
                    horizontalMove -= 5;
                    break;
                case "walk":
                    horizontalMove -= 7;
                    break;
            }
            gf.transform(this.div, {flipH: true});
};
```

其主要部分是一个开关，因为我们将根据玩家的状态有不同的反应。如果玩家当前正在站立，我们将需要改变动画以行走，设置玩家的新状态，并沿 x 轴移动玩家。如果玩家正在跳跃，我们只是沿 x 轴移动玩家（但稍微慢一点）。如果玩家已经在行走，我们只需移动它。

最后一行水平翻转了精灵，因为我们的图像描述了面向右的玩家。向右的方向函数基本上是相同的。

`jump`方法将检查玩家当前是否处于站立或行走状态，如果是，则会更改动画，更改状态，并在`update`函数期间设置垂直速度以生成跳跃。

`idle`状态将将状态设置为站立，并相应地设置`animation`函数，但仅当玩家正在行走时。

```js
this.jump  = function (){
    switch (status) {
        case "stand":
        case "walk":
            status = "jump";
            speed = -60;
            gf.setAnimation(this.div, playerAnim.jump);
            break;
    }
};

this.idle  = function (){
    switch (status) {
        case "walk":
            status = "stand";
            gf.setAnimation(this.div, playerAnim.stand);
            break;
    }
};
```

关于玩家移动就是这些。如果你仅仅使用这个对象中包含的逻辑开始游戏，你将已经拥有大部分构成平台游戏的东西——一个角色在各个平台之间移动跳跃。

# 玩家控制

我们仍然需要将玩家对象连接到主循环。这真的很简单，因为所有逻辑都包含在对象中。然而，我们忽略了一个小细节。由于玩家向左移动，他将离开屏幕。我们需要跟随他！我们将实现的方式如下：如果玩家超出了一个给定的点，我们将开始移动包含所有精灵和瓷砖的组，朝相反的方向移动。这会给人一种摄像机在跟随玩家的印象。

```js
var gameLoop = function() {

    var idle = true;
    if(gf.keyboard[37]){ //left arrow
        player.left();
        idle = false;
    }
    if(gf.keyboard[38]){ //up arrow
        player.jump();
        idle = false;
    }
    if(gf.keyboard[39]){ //right arrow
        player.right();
        idle = false;
    }
    if(idle){
        player.idle();
    }

    player.update();
    var margin = 200;
    var playerPos = gf.x(player.div);
    if(playerPos > 200) {
        gf.x(group, 200 - playerPos);
    }
}
```

这是包含我们之前描述的所有内容的主循环。

# 视差滚动

视差滚动是给 2D 游戏增加一点深度的很好的方法。它利用了远离的物体看起来移动得越慢这一原理。这通常是当你从汽车的侧窗往外看到的景象。

![视差滚动](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_04_10.jpg)

在上图中的第一层将是包含所有精灵和平铺地图的组。第二层和第三层将简单地是图像。我们将使用与以前的游戏相同的技术：简单地使用背景位置来生成它们的移动。

最终的代码在主游戏循环中进行，就在我们移动组以保持玩家在屏幕上可见之后：

```js
var margin = 200;
var playerPos = gf.x(player.div);
if(playerPos > 200) {
    gf.x(group, 200 - playerPos);
    $("#backgroundFront").css("background-position",""+(200 * 0.66 - playerPos * 0.66)+"px 0px");
    $("#backgroundBack").css("background-position",""+(200 * 0.33 - playerPos * 0.33)+"px 0px");
}
```

正如你所看到的，代码很简单；唯一微妙的地方在于选择每个图层速度的合适值。遗憾的是除了用赤裸裸的眼睛观察效果外，没有其他方法来做到这一点。

# 创建敌人

对于敌人，我们也将使用面向对象的代码。这将允许我们仅仅使用继承来指定两种敌人之间的不同之处。第一种是史莱姆。这种类型的敌人在地面上爬行，当它们死亡时，它们会被压扁并停留在它们被杀死的地方。它们在两点之间来回巡逻。

第二种是苍蝇。它们的行为与史莱姆完全相同，但它们在天空中飞行，一旦被杀死，就会坠入深渊。

我们将开始编写史莱姆的代码。它的结构与玩家的对象类似，但简单得多：

```js
var Slime = function() {

   this.init = function(div, x1, x2, anim) {
      this.div = div;
      this.x1 = x1;
      this.x2 = x2;
      this.anim = anim;
      this.direction = 1;
      this.speed     = 5;
      this.dead      = false;

      gf.transform(div, {flipH: true});
      gf.setAnimation(div, anim.walk);
   };

   this.update = function(){
      if(this.dead){
         this.dies();
      } else {
         var position = gf.x(this.div);
         if (position < this.x1){
            this.direction = 1;
            gf.transform(this.div, {flipH: true});
         }
         if (position > this.x2){
            this.direction = -1;
            gf.transform(this.div, {flipH: false});
         }
         gf.x(this.div, gf.x(this.div) + this.direction * this.speed);
      }
   }
   this.kill = function(){
      this.dead = true;
      gf.setAnimation(this.div, this.anim.dead);
   }
   this.dies = function(){}
};
```

敌人只有两种状态，活着和死亡。这是`update`函数生成它们的行为，要么让它们巡逻，要么让它们死去。这里唯一的微妙之处在于我们使用一个方向变量来存储史莱姆是向左移动还是向右移动。

因为苍蝇的行为如此相似，我们不需要写太多来实现它们的对象：

```js
var Fly = function() {}
Fly.prototype = new Slime();
Fly.prototype.dies = function(){
   gf.y(this.div, gf.y(this.div) + 5);
}
```

在这里，你可以看到 JavaScript 中对象继承的相当奇怪的语法（它被称为原型继承）。如果你对此不熟悉，你应该阅读一些关于 JavaScript 的高级书籍，因为这里发生的一切的全部意义超出了本书的范围。然而，直观理解它的方式是这样的：你创建一个简单的对象，并将另一个类的所有方法复制到它里面。然后你修改你想要覆盖的类。

这里我们真的只需要改变苍蝇死亡后的行为，让它坠落。

现在我们需要在主游戏循环中调用更新函数并检查与玩家的碰撞。同样，这样做的方式非常简单，因为大部分逻辑已经编写或者在框架中：

```js
player.update();
for (var i = 0; i < enemies.length; i++){
   enemies[i].update();
   if (gf.spriteCollide(player.div, enemies[i].div)){
      enemies[i].kill();
   }
}
```

这就是我们的游戏。当然，就像上一个游戏一样，你可以在这里添加很多东西：让玩家有能力死亡，只有当他跳在敌人上时才允许他杀死敌人，或者任何你喜欢的东西。有了这个基本模板，你将能够根据你对基本规则的选择生成各种各样游戏玩法完全不同的游戏。这就是最终游戏的样子：

![创建敌人](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_04_11.jpg)

# 摘要

现在我们知道如何绘制瓦片地图以及检测它们和精灵之间以及精灵之间的碰撞。我们对于我们的游戏逻辑有一个可用的面向对象的代码的工作示例，我们将能够在许多其他类型的游戏中使用它。

至于我们之前的游戏，这里的游戏可以在许多方面进行改进，我建议这样做以更加熟悉代码。你可以增加更多的敌人，只有当玩家跳在它们上面时它们才会死亡，并且检测玩家何时到达关卡的结尾。

在下一章中，我们将运用我们在这里学到的技巧来制作一个俯视视角的 RPG 游戏。
