# 面向设计师的 jQuery 入门指南（一）

> 原文：[`zh.annas-archive.org/md5/FFDF3B70B19F674D777B2A63156A89D7`](https://zh.annas-archive.org/md5/FFDF3B70B19F674D777B2A63156A89D7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

感谢阅读*jQuery for Designers*。本书旨在面向具有基本 HTML 和 CSS 理解的设计师，但希望通过学习一些基本 JavaScript 来提升他们的技能。即使你以前从未尝试过编写 JavaScript，本书也将引导你完成设置一些基本 JavaScript 和完成常见任务的过程，如折叠内容、下拉菜单、幻灯片等，这都要归功于 jQuery 库！

# 本书涵盖内容

第一章，*设计师，遇见 jQuery*，是对 jQuery 库和 JavaScript 的介绍。你将了解到 jQuery 的崛起，为何对设计师如此重要，以及如何在不需要学习大量代码的情况下创建一些花哨的特效。本章还包括对 JavaScript 的简要介绍，并引导你编写第一个 JavaScript 代码。

第二章，*增强链接*，将引导你完成一些基本的链接增强。你将学习如何使用 jQuery 在新窗口中打开链接，如何为链接添加图标，以及如何将一组链接转换为选项卡界面。

第三章，*制作更好的常见问题解答页面*，将介绍如何折叠和显示内容，以及在 HTML 文档中移动从一个元素到另一个元素。在本章中，我们将设置一个基本的常见问题解答列表，然后逐步增强它，使我们的网站访问者更容易使用。

第四章，*构建自定义滚动条*，是我们对 jQuery 插件的第一次介绍。我们将使用 jScrollPane 插件创建在几种不同浏览器中按预期工作的自定义滚动条。我们将看看如何设置滚动条，自定义它们的外观，并实现动画滚动行为。

第五章，*创建自定义工具提示*，介绍了如何使用 qTip 插件替换浏览器的默认工具提示为自定义工具提示。然后我们进一步创建自定义工具提示来增强导航栏，并使用工具提示显示额外内容。

第六章，*构建交互式导航菜单*，将指导你设置功能完善且视觉上令人惊叹的下拉和飞出菜单。我们将逐步讲解使这些类型的菜单工作所需的复杂 CSS，使用 Superfish 插件填补纯 CSS 解决方案缺失的功能，并看看如何自定义菜单的外观。

第七章, *异步导航*，介绍了 Ajax，并展示了如何使用一点 jQuery 将简单网站转换为单页面 Web 应用程序。首先，我们设置了一个简单的示例，然后逐步介绍了一个更全面的示例，其中包括对传入链接和返回按钮的支持。

第八章, *展示灯箱中的内容*，将为您介绍如何使用 Colorbox jQuery 插件在灯箱中展示照片和幻灯片。一旦我们掌握了基础知识，我们还将学习如何使用 Colorbox 插件来创建一个精美的登录界面，播放一系列视频，甚至搭建一个单页面网站画廊。

第九章, *创建幻灯片*，将会介绍创建图像幻灯片的几种不同方法。首先，我们将介绍一个从头开始构建基本淡入淡出幻灯片的例子。然后，我们将学习如何使用 CrossSlide 插件、Nivo Slider 插件和 Galleriffic 插件创建不同类型的幻灯片。

第十章, *在走马灯和滑块中展示内容*，介绍了使用 jCarousel jQuery 插件构建走马灯、新闻滚动和滑块。我们将创建一个水平走马灯、垂直新闻滚动和特色内容滑块。然后，我们将看看当我们将幻灯片集成到走马灯中时，插件如何被进一步扩展。

第十一章, *创建交互式数据网格*，介绍了如何将简单的 HTML 表格转换为完全交互式的数据网格，从而使您的网站访问者能够浏览表格、搜索条目，并按不同的列进行排序。

第十二章, *改进表单*，探讨了如何改进表单。本章将指导您正确设置 HTML 表单，使用最新的 HTML5 表单元素。然后，我们通过将光标放在第一个字段中、使用占位符文本和验证网站访问者的表单输入来增强表单。最后，我们将了解 Uniform jQuery 插件，该插件允许我们为了在不同的浏览器中实现一致的表单外观而给最难以应对的表单元素添加样式。

# 你需要准备什么

你需要一个文本编辑器来创建 HTML、CSS 和 JavaScript。一些很好的免费选项是 Mac 上的 TextWrangler 或 Windows 上的 Notepad++。还有许多其他选择可供选择，你可以随意使用你喜欢的文本编辑器来运行本书中的任何示例。

你还需要一个浏览器。我个人最喜欢的是 Google Chrome，它包含了对 CSS 和 JavaScript 非常有帮助的调试工具。同样，你也可以随意选择你喜欢的浏览器来运行本书中的示例。

如果您想为自己的设计创建图像，那么 Adobe Photoshop 和 Adobe Illustrator 将会很有帮助，尽管它们并非必须。 本书示例代码中使用的所有示例所需的图像都已包含在内。

# 本书适合谁

本书适合那些具有 HTML 和 CSS 基本理解的设计师，但希望通过学习使用 JavaScript 和 jQuery 来扩展他们的知识。

# 约定

在本书中，您会经常看到几个标题。

为了清晰地说明如何完成一个过程或任务，我们使用：

## 行动时间 — 标题

1.  行动 1

1.  行动 2

1.  行动 3

说明通常需要一些额外的解释，以便它们有意义，因此它们后面跟着：

### 刚刚发生了什么？

此标题解释了您刚刚完成的任务或说明的工作原理。

在本书中，您还会找到一些其他的学习辅助工具，包括：

### 快速测验 — 标题

这些是短的多项选择题，旨在帮助您测试自己的理解。

### 尝试一下 — 标题

这些设定了实际挑战，并给出了您学到的东西的实验想法。

您还会发现一些文本样式，用于区分不同类型的信息。 以下是这些样式的一些示例及其含义的解释。

文本中的代码词如下所示："jQuery 对象的 `filter()` 方法将允许我们过滤先前选择的一组元素。"

代码块设置如下：

```js
$('#tabs a').bind('click', function(e){
$('#tabs a.current').removeClass('current');
$('.tab-section:visible').hide();

```

当我们希望引起您对代码块特定部分的注意时，相关行或项目将以粗体显示：

```js
$(this.hash).show();
$(this).addClass('current');
e.preventDefault;
}).filter(':first').click();

```

**新术语** 和 **重要单词** 以粗体显示。 例如，在屏幕上看到的词语、菜单或对话框中出现的词语会在文本中显示为："有人认为在新窗口中打开链接会破坏 **返回** 按钮的预期行为，因此应该避免这样做。"

### 注意

警告或重要提示会以如下的方式显示：

### 小贴士

小贴士和技巧会以这种方式显示。


# 第一章：设计师，遇见 jQuery

> 在过去几年里，你可能已经听说了很多关于 jQuery 的事情 —— 它很快成为了当今网络上使用最广泛的代码包之一。你可能会想知道这一切到底是怎么回事。
> 
> 无论你以前是否尝试过理解 JavaScript 并因挫折而放弃，或者对此感到害怕而不敢尝试，你会发现 jQuery 是一种非常易于接近且相对容易学习的方法，可以让你初次接触 JavaScript 时感到轻松自如。

在这一章中，我们将涵盖：

+   jQuery 是什么，为什么它非常适合设计师

+   渐进增强和优雅降级

+   JavaScript 基础知识

+   下载 jQuery

+   你的第一个 jQuery 脚本

# jQuery 是什么？

jQuery 是一个 JavaScript 库。这意味着它是一组可重复使用的 JavaScript 代码，用于完成常见任务 —— 网页开发者经常发现自己一遍又一遍地解决相同的问题。与其每次从头开始设计解决方案，不如将所有这些有用的代码片段收集到一个单独的包中，可以在任何项目中包含并使用。jQuery 的创建者已经编写了代码来平稳而轻松地处理我们想要使用 JavaScript 完成的最常见和最乏味的任务 —— 并且他们已经解决了在不同浏览器中让代码工作所需解决的所有小差异。

重要的是要记住 jQuery 是 JavaScript，而不是自己的语言。它遵循同样的规则，以及与 JavaScript 相同的写法。不要因此而退缩 —— jQuery 确实使编写 JavaScript 变得更加容易。

jQuery 的官方口号是 *写更少，做更多*。这是对 jQuery 库的一个极好而准确的描述 —— 你真的可以在几行代码中完成惊人的事情。我自己对 jQuery 的非官方口号是 *找到东西并对其进行操作*，因为使用原始 JavaScript 找到并操作 HTML 文档的不同部分非常乏味，并且需要大量的代码行。jQuery 使得同样的任务变得轻松而快速。多亏了 jQuery，你不仅可以快速创建一个下拉菜单 —— 你可以创建一个动画效果并且在许多不同的浏览器中流畅运行的下拉菜单。

# 为什么 jQuery 对设计师来说如此棒？

那么，究竟是什么让 jQuery 如此易于学习，即使你对 JavaScript 有限或没有经验？

## 使用你已经了解的 CSS 选择器

在 jQuery 脚本中，你通常会做的第一件事情是选择你想要操作的元素。例如，如果你要向导航菜单添加一些效果，你会首先选择导航菜单中的项目。用于这项工作的工具是选择器 —— 一种选择页面上要操作的特定元素的方法。

jQuery 从 CSS 中借用了选择器一直到 CSS3，即使在尚不支持 CSS3 选择器的浏览器中也可以工作。

尽管 CSS 提供了一组相当强大的选择器，但 jQuery 自己添加了一些额外的选择器，使得你需要的元素更容易处理。

如果你已经知道如何做一些事情，比如将所有的一级标题变为蓝色，或者将所有的链接变为绿色并带下划线，那么你很容易学会如何用 jQuery 选择你想要修改的元素。

## 使用你已经了解的 HTML 标记语言

如果你想要用原始的 JavaScript 创建新元素或修改现有元素，最好揉揉手指，准备好写很多很多的代码 —— 而且这些代码可能并不那么容易理解。

例如，如果我们想要向页面附加一个段落，内容是*这个页面由 JavaScript 驱动*，我们首先必须创建段落元素，然后将应该在段落中的文本分配给一个变量作为字符串，最后将字符串附加到新创建的段落作为文本节点。然后，我们仍然必须将段落附加到文档中。哎呀！（如果你没有完全理解这一切，别担心，这只是为了说明做这么简单的事情需要多少工作和代码。）

通过 jQuery，向页面底部添加一个段落就这么简单：

```js
$('body').append('<p>This page is powered by jQuery.</p>');

```

没错 —— 你只需将一小段 HTML 直接附加到 body 中，然后一切就搞定了。我敢打赌，即使你完全不理解 JavaScript，你也能读懂那行代码并理解它在做什么。这段代码是将一个段落附加到我的 HTML 文档的 body 中，内容是*这个页面由 jQuery 驱动*。

## 仅需几行代码即可实现令人印象深刻的效果。

你有更重要的事情要做，而不是坐在那里写一行一行的代码来添加淡入和淡出效果。jQuery 为你提供了一些基本的动画和创建自定义动画的能力。比如说，我想让一张图片淡入到页面中：

```js
$('img').fadeIn();

```

是的，就是这样 —— 一行代码，我选择了我的图片然后告诉它淡入。我们稍后会在本章中确切地了解这行代码在你的 HTML 页面中的位置。

## 可用的巨大插件库

正如我之前所说，Web 开发者经常发现自己反复解决相同的问题。你很可能不是第一个想要构建旋转图片幻灯片、动画下拉菜单或新闻滚动条的人。

jQuery 有一个令人印象深刻的大型脚本库 —— 脚本用于创建工具提示、幻灯片、新闻滚动条、下拉菜单、日期选择器、字符计数器等等。你不需要学会如何从头开始构建所有这些东西 —— 你只需要学会如何利用插件的威力。我们将在本书中介绍一些最受欢迎的 jQuery 插件，你将能够利用你所学到的知识使用 jQuery 插件库中的任何插件。

## 庞大的社区支持

jQuery 是一个开源项目 — 这意味着它是由一群超级聪明的 JavaScript 编码人员共同构建的，并且任何人都可以免费使用。开源项目的成功或失败通常取决于项目背后的社区 — 而 jQuery 有一个庞大而活跃的支持社区。

这意味着 jQuery 本身正在不断改进和更新。除此之外，还有成千上万的开发人员创建新的插件，为现有插件添加功能，并为新手提供支持和建议 —— 你会发现针对几乎任何你想学习的内容，每天都会有新的教程、博客文章和播客。

# JavaScript 基础知识

在本节中，我将介绍一些 JavaScript 的基础知识，这将使事情更加顺利进行。我们将查看一小部分代码，并解释它的工作原理。不要感到害怕 —— 这将很快并且没有痛苦，然后我们将准备好真正开始使用 jQuery 了。

## 渐进增强和优雅降级

在增强 HTML 页面与 JavaScript 时，有几种不同的思想流派。在我们着手进行有趣的事情之前，让我们谈谈一些在深入研究之前应该考虑的事情。

渐进增强和优雅降级本质上是同一枚硬币的两面。它们都意味着我们的页面及其令人印象深刻的 JavaScript 动画和特效将仍然适用于具有较差浏览器或设备的用户。优雅降级意味着我们创建特效，然后确保如果未启用 JavaScript，则优雅地失败。如果我们采用渐进增强方法，我们将首先构建一个适用于所有人的简约页面，然后通过添加我们的 JavaScript 特效来增强它。我倾向于采用渐进增强方法。

我们为什么要关心那些没有启用 JavaScript 的用户呢？好吧，网络上最大的用户之一 — 搜索引擎 — 没有 JavaScript 功能。当搜索引擎爬行和索引您的页面时，它们将无法访问 JavaScript 加载到您的页面中的任何内容。这通常被称为动态内容，如果无法在禁用 JavaScript 的情况下访问，搜索引擎将无法索引或找到它。

我们也处于一个时代，不再能指望用户使用传统的台式机或笔记本电脑访问我们构建的网页。我们很快就会想到智能手机和平板电脑是下一个候选者，虽然它们非常受欢迎，但它们仍然只占互联网访问的一小部分。

人们从游戏机、电子书阅读器、互联网电视、各种各样的移动设备甚至可能还有数百种其他方式访问网络。并非所有这些设备都能执行 JavaScript —— 其中一些甚至没有彩色屏幕！你的头等大事应该是确保你的内容对任何要求它的人都是可用的，无论他们使用的设备是什么。

## 必须分开处理它们

要完成这个尽可能使我们的内容对尽可能广泛的受众可用的任务，我们必须将我们的网页看作是三个独立且不同的层次：内容、呈现和行为。

### 内容

内容是我们网页的重点 —— 它是我们最感兴趣的呈现在我们页面上的文本或音频或视频，所以这是我们开始的地方。

用干净、简单的 HTML 代码标记您的内容。使用 HTML 元素的方式是它们预期的使用方式。使用标题标记标记标题、使用段落标记标记段落、使用列表标记标记列表，并将表格保留给表格数据。

浏览器为这些基本的 HTML 标签内置了样式 —— 标题将会是较大的字体且可能会加粗。列表将具有项目符号或编号。可能看起来不太花哨，但它对任何人来说都是可读的和可访问的。

### 呈现

展示层是我们开始变得花哨的地方。这是我们引入 CSS 并开始对我们创建的内容应用自己的样式的地方。当我们为页面添加样式时，我们可能会发现我们需要回到我们的 HTML 中添加一些新的容器和标记，以使诸如多列布局之类的东西成为可能，但我们仍然应该努力保持我们的标记尽可能简单和直接。

### 行为

一旦我们的页面所有内容都被正确标记并且样式看起来我们喜欢的方式，现在我们可以考虑添加一些交互行为。这就是 JavaScript 和 jQuery 起作用的地方。这一层包括动画、特效、AJAX 等等。

# 设计师，见识 JavaScript

JavaScript 是一种功能强大且复杂的语言 —— 你可以与之一起工作 10 年，仍然有更多要学习的内容。但不要让这吓倒你，你不必了解它的所有内容才能利用它所提供的内容。事实上，你只需要掌握一些基础知识。

这一节介绍了一些 JavaScript 基础和 JavaScript 语法。不要被那个开发者词语 —— 语法 吓倒。语法只是指编写语言的规则，就像我们有写英语的语法规则一样。

## 变量

让我们从简单的开始：

```js
var x = 5;

```

这是 JavaScript 中的*句子*。在英语中，我们以句号或者可能是问号或感叹号结束句子。在 JavaScript 中，我们以分号结束我们的句子。

在这个句子中，我们正在创建一个变量，`x`。变量只是一个容器，用来保存东西。在这种情况下，`x`保存的是数字`5`。

我们可以用 JavaScript 这样做数学：

```js
var x = 5;
var y = 2;
var z = x + y;

```

就像代数一样，我们的变量`z`现在为我们保存了数字`7`的值。

但变量可以保存除了数字之外的其他东西。例如：

```js
var text = 'A short phrase';

```

在这里，我们命名了我们的变量`text`，它为我们保存了一些字母字符。这叫做**字符串**。字符串是一组字母数字字符。

## 对象

对于 JavaScript 新手来说，对象可能是最难理解的东西，但那往往是因为我们想得太多，坚信它必须比实际更复杂。

一个对象就像它听起来的那样 —— 一个东西，任何东西。就像汽车、狗或咖啡壶都是对象。

对象具有属性和方法。属性是对象的特征。例如 — 一只狗可以高或矮，有尖耳或垂耳，是棕色或黑色，或白色。所有这些都是一只狗的属性。方法是对象可以做的事情。例如一只狗可以跑、吠、走路和吃东西。

让我们以我的狗，马格达莱纳·冯·巴尔金顿，为例，看看我们如何在 JavaScript 中处理对象、属性和方法：

```js
var dog = Magdelena von Barkington;

```

这里我创建了一个变量`dog`，我将其用作一个容器来容纳我的狗，主要是因为我不想每次在代码中提及她时都要输入她的全名。现在假设我想要获取我的狗的颜色：

```js
var color = dog.color;

```

我创建了一个名为`color`的容器，我用它来容纳我的狗的颜色属性 — `color`现在等于我的狗的颜色。

现在，我训练过我的狗，我想让她翻滚。这是我用 JavaScript 告诉她翻滚的方法：

```js
dog.rollOver();

```

`rollOver`是一个方法 —— 我的狗能做的事情。在我的狗翻滚后，我可能想用零食奖励她。这是我用 JavaScript 让我的狗吃零食的方法：

```js
dog.eat('bacon');

```

等等，这里发生了什么？ 让我们一步一步来看。我们有 dog，我们知道它是一个容器，里面装着我的狗，马格达莱纳·冯·巴尔金顿。我们有`eat`方法，我们知道这是我的狗能做的事情。但是我的狗不能只是吃 —— 她必须吃*某物*。我们用括号来表示她在吃什么。在这种情况下，我的幸运狗在吃培根。在 JavaScript 里，我们会说我们正在将培根传递给狗的`eat`方法。

所以你看，对象并不那么难 — 它们只是事物。属性就像形容词 — 它们描述对象的特征或特性。方法就像动词 — 它们描述对象可以做的动作。

## 函数

函数是一小段可重复使用的代码，告诉 JavaScript 做某事。例如：

```js
function saySomething() {
alert('Something!');
}

```

该函数告诉 JavaScript 弹出一个显示`Something!`的警告框。我们总是用单词`function`开始一个函数，然后命名我们的函数。接着是一对括号和一对花括号。指令行写在花括号里。

现在，我的`saySomething`函数在被调用之前实际上不会做任何事情，所以我需要添加一行代码来调用我的函数：

```js
function saySomething() {
alert('Something!');
}
saySomething();

```

### 提示

**下载示例代码**

你可以从你在 [`www.PacktPub.com`](http://www.PacktPub.com) 上购买的所有 Packt 书籍的帐户中下载示例代码文件。如果你在其他地方购买了这本书，你可以访问 [`www.PacktPub.com/support`](http://www.PacktPub.com/support) 并注册，让文件直接通过电子邮件发送给你。

也许你会想知道那些括号是干什么的。还记得我们是如何通过将它们包含在括号中将东西传递给一个方法的吗？

```js
dog.eat('bacon');

```

在这种情况下，我们通过`bacon`来说明狗正在吃什么。对于函数，我们也可以做类似的事情。事实上，方法实际上就是函数 —— 它们只是专门用于描述对象可以做什么的函数。让我们看看如何修改我们的`saySomething`函数，以便我们可以向其传递文本：

```js
function saySomething(text) {
alert(text);
}
saySomething('Hello there!');

```

在这种情况下，当我编写`saySomething`函数时，我只是留下了一个通用的容器。这被称为参数 —— 我们会说`saySomething`函数接受一个文本参数，因为我将我的参数称为`text`。我选择了`text`这个名字，因为它是对我们传入的内容的一个简短而方便的描述。我们可以向这个函数传递任何文本片段，所以`text`是一个合适的名字。你可以给你的参数起任何名字 —— 但是如果在选择参数名称时应用一些常识规则，你的代码将更容易阅读和理解。参数行为非常像变量 —— 它只是一个东西的容器。

# 下载 jQuery 并设置

我们准备将 jQuery 的魔力引入项目中，但首先我们需要下载它并弄清如何将它附加到一个 HTML 页面上。在这里，我们将逐步了解如何启动一个示例 HTML 文件，以及我们需要处理一个示例项目设置所需的所有关联文件和文件夹。完成后，你可以将其用作本书中所有未来练习的模板。

# 行动时间 —— 下载并附加 jQuery

之前，我描述了 HTML 文档的三个层次 —— 内容、展示和行为。让我们看看如何为这三个层次设置我们的文件：

1.  首先，让我们在你的硬盘上创建一个文件夹，用来保存你在本书中学习过程中的所有工作。在你的硬盘上找一个合适的位置，创建一个名为`jQueryForDesigners`的文件夹。

1.  在文件夹内创建一个名为`styles`的文件夹。我们将使用这个文件夹来保存我们创建的任何 CSS。在`styles`文件夹内，创建一个名为`styles.css`的空 CSS 文件。

    样式代表着我们的展示层。我们将所有的样式保存在这个文件中以保持它们的分离。同样，创建一个名为`images`的文件夹来保存我们将要使用的任何图片。

1.  接下来，创建一个名为`scripts`的文件夹来保存我们的 JavaScript 和 jQuery 代码。在`scripts`文件夹内，创建一个名为`scripts.js`的空 JavaScript 文件。

    这里编写的 JavaScript 代表我们的行为层。我们将所有的 JavaScript 都放在这个文件中，以使其与其他层分开。

1.  现在，在`jQueryForDesigners`文件夹中，创建一个非常基本的新 HTML 页面，如下所示：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
    <title>Practice Page</title>
    </head>
    <body>
    <!-- Our content will go here -->
    </body>
    </html>

    ```

    将该文件保存为`index.html`。HTML 文件是我们的内容层，可以说是最重要的层；因为这很可能是网站访问者访问我们网站的原因。

1.  接下来，我们将把我们制作的 CSS 和 JavaScript 文件附加到我们的 HTML 页面上。在头部部分，添加一行来包含 CSS 文件：

    ```js
    <head>
    <title>Practice Page</title>
    <link rel="stylesheet" href="styles/styles.css"/>
    </head>

    ```

    然后转到 HTML 文件的底部，在闭合的`</body>`标签之前，包含 JavaScript 文件：

    ```js
    <script src="img/scripts.js"></scripts>
    </body>
    </html>

    ```

    由于这些文件只是空占位符，将它们附加到你的 HTML 页面上不会产生任何效果。但现在当我们准备进行练习时，我们有一个方便的地方来编写我们的 CSS 和 JavaScript。

    ### 注意

    注意，自闭合`<link>`元素是完全可以的，但是`<script>`元素总是需要一个单独的闭合`</script>`标签。没有它，你的 JavaScript 将无法工作。

    +   到目前为止，我的文件夹看起来是这样的：

    ![操作时间 — 下载并附加 jQuery](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_01_004.jpg)

1.  现在我们要在我们的页面中包含 jQuery。前往 [`jquery.com`](http://jquery.com)，点击**Download(jQuery)**按钮：![操作时间 — 下载并附加 jQuery](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_01_001.jpg)

    你会注意到**选择你的压缩级别**下有两个选项。你总是要勾选**生产**复选框。这是一个准备在网站上使用的版本。**开发**版本是为有经验的 JavaScript 开发人员准备的，他们想要编辑 jQuery 库的源代码。

1.  点击**下载**按钮会在你的浏览器窗口中打开生产 jQuery 文件，看起来有点吓人，如下所示：![操作时间 — 下载并附加 jQuery](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_01_002.jpg)

1.  不用担心，你不必阅读它，你绝对不必理解它。只需转到浏览器的文件菜单，选择**另存为...**。或右键单击页面，选择**另存为**，然后将文件保存到我们创建的`scripts`文件夹中。默认情况下，脚本文件名中会包含版本号。我将继续将文件重命名为`jquery.js`，以保持简单。

1.  现在我们只需在我们的页面中包含我们的 jQuery 脚本，就像我们包含我们的空 JavaScript 文件一样。转到你的练习 HTML 文件的底部，在我们之前创建的`<script>`标签之前添加一行来包含 jQuery：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/scripts.js"></script>
    </body>
    </html>

    ```

你不会在你的 HTML 页面上注意到任何变化 — jQuery 自己不会做任何事情。它只是让它的魔法可供你使用。

# 使用 jQuery 的另一个选项

下载并使用自己的 jQuery 副本没有任何问题，但你还有另一个选项可用，可以帮助提高你的网站性能。那就是使用 CDN 托管的 jQuery 副本。

你可能不知道，**CDN**是**内容传递网络**的简称。CDN 的前提是从离站点访问者位置物理上更近的服务器下载文件速度更快。例如，如果您在加利福尼亚州的洛杉矶，那么位于亚利桑那州凤凰城的服务器上的 jQuery 副本将比位于纽约市的服务器上的 jQuery 副本下载得更快。为了加快这个过程，CDN 在世界各地的许多不同服务器上都有相同文件的副本。每当站点访问者请求文件时，CDN 会智能地将他们的请求路由到最接近的可用服务器，有助于改善响应时间和整体站点性能。

对于本书中构建的相对简单的示例和页面来说，这并不会有太大影响，但对于公开面向网站来说，使用 CDN 托管的 jQuery 副本可以带来明显的改善。虽然有几种选择，但远非最受欢迎的是谷歌的 Ajax API CDN。您可以在[`code.google.com/apis/libraries/devguide.html#jquery`](http://code.google.com/apis/libraries/devguide.html#jquery)获取有关最新版本和正确 URL 的信息。

如果您想在您的文件中使用谷歌 CDN 托管的 jQuery 版本，只需将以下代码行添加到您的 HTML 文件中即可，而不是以前用于包含 jQuery 的行:

```js
<script src="img/jquery.min.js"></script>

```

不需要下载文件，也不需要保存自己的副本，您只需直接将您的`<script>`标签指向存储在 Google 服务器上的 jQuery 的副本即可。谷歌会负责从最近可用的服务器向您的站点访问者发送 jQuery。

不仅如此，因为谷歌的 CDN 非常受欢迎，您的站点访问者很可能已经访问过另一个也使用谷歌 CDN 托管的 jQuery 副本的站点，他们将会有

jQuery 在他们的浏览器中已缓存。这意味着您的站点访问者根本不需要下载 jQuery-它已保存在他们的浏览器中，并可以随时使用。这又如何提高性能呢?

# 您的第一个 jQuery 脚本

好了，现在我们对 JavaScript 的一些基本概念有了一些了解，并且知道如何设置文件和文件夹以构建一个示例练习，让我们构建我们的第一个简单的示例页面，并使用 jQuery 实现一些花里胡哨的东西。

# 行动时间-准备好使用 jQuery 了

1.  就像我们在前面的练习中所做的那样设置您的文件和文件夹。在 HTML 文档的`<body>`内，添加一个标题和一个段落:

    ```js
    <body>
    <h1>My First jQuery</h1>
    <p>Thanks to jQuery doing fancy JavaScript stuff is easy.</p>
    </body>

    ```

1.  在`styles`文件夹中的`styles.css`中随意创建一些 CSS 样式-您可以随心所欲地对其进行样式化。

1.  接下来，打开我们之前创建的空白`scripts.js`文件，并向文件中添加以下脚本:

    ```js
    $(document).ready();

    ```

## 刚刚发生了什么?

让我们一次来分析这个陈述-首先是一个美元符号?真的吗?JavaScript 里面怎么会出现这个符号？

这里的`$`只是一个变量——就这样。它是 jQuery 函数的容器。还记得我说过我们可能使用一个变量来节省几次按键吗？jQuery 的聪明作者们提供了`$`变量，使我们不必每次都写出`jQuery`。这段代码也能完成同样的事情：

```js
jQuery(document).ready();

```

除了输入时间更长之外。jQuery 使用`$`作为其简称，因为你很少会自己使用变量`$`，因为这是一个不常见的字符。使用不常见的字符可以减少在页面上使用其他 JavaScript 代码和 jQuery 库之间发生冲突的可能性。

所以，在这种情况下，我们将`document`传递给 jQuery 或`$`方法，因为我们希望将我们的 HTML 文档作为我们代码的目标选择。当我们调用 jQuery 函数时，我们得到一个 jQuery 对象。在 JavaScript 中，我们会说 jQuery 函数*返回*一个 jQuery 对象。jQuery 对象是 jQuery 库赋予其强大功能的核心。整个 jQuery 库存在的目的就是为了给 jQuery 对象提供许多属性和方法，使我们的生活更轻松。我们不必处理很多不同类型的对象——我们只需要处理 jQuery 对象。

jQuery 对象有一个名为`ready()`的方法。在这种情况下，当文档加载到浏览器中并且可以与之一起工作时，将调用 ready 方法。所以`$(document).ready()`的意思就是“当文档准备就绪时”。

## 添加一个段落

现在我们已经准备好在文档就绪时执行某些操作了，但我们要做什么呢？让我们向页面添加一个新段落。

# 行动时间——添加一个新段落

1.  我们需要告诉 jQuery 在文档准备就绪时要做什么。因为我们希望发生某些事情，所以我们将传入一个函数，如下所示：

    ```js
    $(document).ready(function(){
    // Our code will go here
    });

    ```

    我们将在这个函数内写明将要发生的事情。

    那行以`//`开头的代码呢？那是 JavaScript 中编写注释的一种方式。`//`告诉 JavaScript 忽略该行上的所有内容，因为它是一条注释。在 JavaScript 中添加注释是帮助自己跟踪代码发生了什么的好方法。对于可能需要处理您的代码的其他开发人员来说，这也很有帮助。即使在几个月后再次查看自己的代码，这也是很有帮助的。

1.  接下来，我们将添加我们想要在文档准备就绪时立即发生的事情：

    ```js
    $(document).ready(function(){
    $('body').append('<p>This paragraph was added with jQuery!</ p>');
    });

    ```

## 刚刚发生了什么？

我们的函数再次使用了 jQuery 函数：

```js
$('body')

```

还记得我说过 jQuery 使用 CSS 选择器来查找东西吗？这就是我们如何使用这些 CSS 选择器的方式。在这种情况下，我想要`<body>`标签，所以我将`'body'`传递给 jQuery 函数。这会返回包装在 jQuery 对象中的`<body>`标签。巧妙的是，jQuery 对象有一个`append()`方法，让我可以向页面添加新内容：

```js
$('body').append();

```

现在我所要做的就是将要添加到页面的内容传递给 append 方法。在引号中，我将传递一行 HTML 代码，我想要添加的内容：

```js
$('body').append('<p>This paragraph was added with jQuery!</p>');

```

这就是全部！现在，当我在浏览器中加载我的页面时，我会看到我的标题，后面跟着两个段落 —— jQuery 会在文档加载到浏览器中时添加第二个段落：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_01_003.jpg)

# 摘要

在本章中，你已经介绍了 jQuery 库，并学习了一些关于它的知识。我们讲解了一些 JavaScript 基础知识，然后学习了如何为本书中的练习设置我们的文件和文件夹。最后，我们设置了一个简单的 HTML 页面，利用 jQuery 添加了一些动态内容。现在让我们看看如何使用 jQuery 使链接更加强大。


# 第二章 增强链接

> 如今我们理所当然地使用链接，但事实上，这个不起眼的链接是改变文档并使今天的网络成为可能的事物。在此之前，将读者直接链接到另一个文档或另一个文档内的另一个位置是不可能的。
> 
> 因此，你可以说超链接是互联网的支柱 —— 没有它们，搜索引擎就不可能存在，也不会有大多数网站。让我们来看看一些方法，我们可以让链接为我们提供更大的帮助。

在本章中，我们将涵盖：

+   如何在新窗口打开链接

+   如何向链接添加图标以识别我们正在链接到的文档类型

+   如何将链接列表转换为简单的选项卡

# 在新窗口打开链接

尽管在新窗口打开链接是很常见的，但这种做法本身有些争议。有些人认为网站访问者应该自己决定是否要在新窗口打开链接，而且许多浏览器都让他们轻松实现这一点。一些人认为在新窗口打开链接会破坏**返回**按钮的预期行为，应该避免这样做。还有一些人认为，不在新窗口打开链接会让网站访问者感到困惑和失落，当他们突然发现自己在一个不同的网站上时。

无论你对这个问题持何种观点，客户通常都会提出这样的要求，而且这种做法可能不会很快消失，所以了解处理这种功能的选择是很重要的。我假设你已经意识到了在新窗口打开链接的问题，并已经认真权衡了所有选项，并向客户提出了一个知情的论点。

## 为什么不直接使用`target`属性呢？

你可能知道，HTML 提供了一个`target`属性，可以与链接一起使用，用于指定链接应该在哪里打开。例如，下面的代码：

```js
<a href="http://packtpub.com" target="_new">Link</a>

```

将创建一个链接，它将尽力在新窗口或新选项卡中打开，具体取决于用户在其浏览器中设置的偏好。

开发网页标准（如 HTML）的机构 W3C 已经废弃了`target`属性的严格文档类型的使用，但已经将该标签重新引入了 HTML5 规范。但是，`target`属性旨在与框架一起使用，以控制如何将新页面加载到框架和 iframe 中。它并不是用来打开一个不使用框架的页面中的链接的，因此严格来说，为此目的使用它是不正确的。

相反，我们可以使用一点 JavaScript 来创建我们想要的行为，而不使用无效或已弃用的代码。让我们来看看如何做到这一点。

# 行动时间 —— 在新窗口打开链接

1.  我们将从我们在第一章中创建的基本 HTML 文件和相关文件夹开始。在 HTML 文档的`<body>`中，我们将添加一些链接，如下所示：

    ```js
    <h1>Opening Links in a New Window</h1>
    <p>This link will open in a new window: <a href ="http://packtpub.com">New Window!</a></p>
    <p>This link will not: <a href ="http://packtpub.com">Same Window!</a></p>

    ```

    这只是一个标题和两个简单的段落，每个段落都有一个链接——一个应该在新窗口中打开，另一个不应该。

1.  我们需要一种方法来选择应该在新窗口中打开的链接。这与我们如果想要用 CSS 对其中一个链接进行不同样式处理时的情况类似。

    如果我们使用 CSS，我们可以为链接分配一个`ID`或一个类。`ID`会相当受限，因为`ID`必须在页面上是唯一的——它只适用于这个特定的链接。`class`将允许我们样式化任何在新窗口中打开的链接，所以这就是我们要使用的。如下所示，为应该在新窗口中打开的链接添加一个`class`：

    ```js
    <a href="http://packtpub.com" class="new-window">New Window!</a>

    ```

1.  现在我们可以使用这个类名来进行 CSS 样式设置，并使用 jQuery 使链接在新窗口中打开。为这个链接添加一个图标是个好主意，你可以在链接的左侧或右侧添加一些填充，然后为链接添加一个背景图像。打开你的`styles`文件夹中的空`styles.css`文件，并添加以下 CSS：

    ```js
    a.new-window {
    padding-right: 18px;
    background: url('../images/new-window-icon.png') 100% 50% no-repeat;

    ```

1.  接下来，我们将打开我们的`scripts`文件夹中的`scripts.js`文件，并在我们的文档准备好声明之外开始编写我们的函数来获取我们的`new-window`链接并使它们在新窗口中打开。首先声明一个新函数：

    ```js
    $(document).ready(function(){
    });
    function externalLinks() {
    }

    ```

    这里我们创建了一个新函数，并将其命名为`externalLinks`，因为这是一个合理的名称，用于在新窗口中打开链接。为 JavaScript 函数和变量命名为能帮助你记住它们的功能是非常有帮助的。

1.  接下来，我们将使用 jQuery 选择所有具有`new-window`类的链接。我们将利用 jQuery 的 CSS 选择器来选择这些链接，就像我们在用 CSS 对它们进行样式设置时一样。

    ```js
    function externalLinks() {
    $('a.new-window'); 
    }

    ```

1.  我们使用了`$`快捷方式调用 jQuery 函数，并向函数传递了 CSS 选择器。重要的是要记住将 CSS 选择器用单引号或双引号括起来。我们不希望链接在用户点击之前就打开新窗口，因此我们的下一步是告诉链接在被点击时运行一个函数。jQuery 使这变得非常容易。我们可以使用 jQuery 提供的`bind()`方法将一个函数绑定到链接上，当链接被点击时将调用该函数。代码如下所示：

    ```js
    function externalLinks() {
    $('a.new-window').bind('click', function() {
    });
    }

    ```

    这段代码将一个函数绑定到我们的链接上——当我们的链接被点击时，我们在这个新函数内编写的任何代码都将被调用。但到目前为止，我们的函数是空的，实际上什么也没做。

1.  接下来我们需要做的是获取链接将我们发送到的位置：

    ```js
    function externalLinks() {
    $('a.new-window').bind('click', function() {
    var location = $(this).attr('href');
    });
    }

    ```

    让我们逐一检查这一行新代码。首先，我们声明了一个名为`location`的新变量。你记得吧，变量只是一个容器。所以我们有了一个新的空容器，现在让我们看看我们放了什么进我们的容器。

    `$(this)`是 jQuery 引用我们当前正在处理的 jQuery 对象的方式。在这种情况下，我们选择所有具有`new-window`类的链接，并且我们已经附加了该函数，以便在站点访客点击链接时调用它。当站点访客点击链接时，我们希望检查被点击的链接以获取链接要前往的位置。引用当前链接的一个简单快捷的方式是使用`$(this)`。

    接下来我们使用`attr()`方法来获取链接的属性。链接要前往的位置包含在`href`属性中，因此我们将`href`传递给`attr()`方法。

    因此，我们命名为`location`的容器现在包含了链接指向的 URL，或者在这种特殊情况下，[`packtpub.com.`](http://packtpub.com)

1.  现在我们知道我们想要去哪里了，我们只需要在新窗口中打开那个位置。在 JavaScript 中打开一个新窗口是简单直接的：

    ```js
    function externalLinks() {
    $('a.new-window').bind('click', function() {
    var location = $(this).attr('href');
    window.open(location);
    });
    }

    ```

    `window`是 JavaScript 中的一个全局对象，始终可供我们使用。window 对象有一个`open()`方法，我们只需将位置传递给该方法，以便浏览器知道在新窗口中打开的位置是什么。

1.  现在，如果你在浏览器中打开这个 HTML 页面并尝试点击链接，你可能会失望地发现我们的链接没有在新窗口中打开。就像我们的 JavaScript 根本就不在页面上一样。我们写了一个非常好的函数，但它不起作用。那是因为函数在我们告诉它们之前不会做任何事情。在 JavaScript 中告诉一个函数做它的事情的方式是'调用该函数'。

    我们希望这个函数在页面在浏览器窗口加载时立即启动，找到所有具有类`new-window`的链接，并将我们的新窗口函数绑定到它们上。这样，我们的应该在新窗口中打开的链接将在我们的站点访客点击其中一个链接时准备好打开一个新窗口。

    我们只需在我们的文档准备好的语句中添加一行来调用我们的函数：

    ```js
    $(document).ready(function(){
    externalLinks();
    });
    function externalLinks() {
    $('a.new-window').bind('click', function() {
    var location = $(this).attr('href');
    window.open(location);
    });
    }

    ```

    这段新代码将在页面在浏览器中加载时立即调用我们的`externalLinks`函数。

1.  只剩下一件事要做了。现在，如果你在浏览器中加载页面并点击链接，你会发现链接确实会在新窗口中打开，但它也会在当前窗口中打开——所以我们最终会在两个不同的窗口中加载我们的新页面。这不是我们想要的结果。我们需要做的是取消链接的默认行为——我们已经处理了在新窗口中打开位置的事情，所以现在我们需要告诉浏览器，在站点访客点击链接时不需要做任何事情。所以让我们给我们的函数添加一个参数和一行代码来取消默认链接行为。

    ```js
    function externalLinks() {
    $('a.new-window').bind('click', function(e) {
    var location = $(this).attr('href');
    window.open(location);
    e.preventDefault();
    });
    }

    ```

    你会注意到我们附加到链接点击动作的函数现在括号里有一个 e。这是我们传递给这个函数的一个参数。在这种情况下，e 代表链接的点击事件。

    我们在函数中添加的代码行是：

    ```js
    e.preventDefault();

    ```

    这告诉浏览器停止链接的默认行为。如果你在浏览器中重新加载页面并点击链接，你会发现它会在新窗口中正确地打开目标页面，并且不再在当前窗口中打开链接：

    ![执行动作的时间——在新窗口中打开链接](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_02_001.jpg)

1.  如果页面上有第二个应该在新窗口打开的链接，你认为会发生什么？让我们回到文档的`<body>`部分，添加一个应该在新窗口打开的第二个链接。在其他链接之后，添加一个新的段落和链接到一个新页面：

    ```js
    <p>This paragraph will open in a new window too: <a href="http://nataliemac.com" class="new-window">New Window!</a></p>

    ```

    确保将`new-window`类添加到你的链接中。

现在，当你在浏览器中刷新页面时，新链接会出现在页面上。尝试点击它，你会发现它也会像其他`new-window`链接一样在新窗口中打开。

## 刚刚发生了什么？

我们给那些希望在新窗口打开的链接添加了一个 CSS 类名。现在，我们在页面上创建的任何带有`new-window`类的链接都会在新窗口中打开，但是当有多个链接时，JavaScript 怎么知道要在新窗口中打开哪个页面呢？

答案就在我们的`externalLinks`函数中。我们选择了所有带有`new-window`类的链接，并绑定了一个函数，当这些链接被点击时触发。在这个函数内部，我们捕获了链接的位置。这个函数只有在链接被点击时才会运行。在那之前，它只是在场边等待行动。当一个带有`new-window`类的链接被点击时，我们的函数开始工作，捕获了那个特定链接的位置，并打开了一个指向该链接位置的新窗口。

# 为链接添加图标

向链接添加图标是向您的站点访客传达链接类型的最简单方法之一。您可能对站点的不同部分有不同的图标，或者您可能希望向站点访客提供一些可下载的文件 —— 例如，您编写的 PDF 或电子书，您进行的演示文稿的幻灯片，或者您创建的一些股票图标或摄影作品。向这些类型的链接添加图标可以帮助向您的站点访客提供视觉线索，以便他们知道单击链接时会发生什么。让我们看看我们如何使用 jQuery 为不同类型的链接添加适当的图标。

这是我们向链接添加图标后页面的示例：

![向链接添加图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_02_002.jpg)

# 行动时间 —— 创建链接列表

1.  我们将从我们创建的基本 HTML 文件和相关文件夹开始，就像我们在第一章中创建的那样，*设计师，遇见 jQuery*。我们将向 HTML 文档的`<body>`添加一系列链接列表，链接到几种不同类型的可下载文件：

    ```js
    <h1>Adding Icons to Links</h1>
    <p>Here's a list of downloadable files:</p>
    <ul>
    <li><a href="http://presentation.ppt">Presentation slides</a></li>
    <li><a href="video.mp4">Video of presentation</a></li>
    <li><a href="notes.pdf">Notes for presentation</a></li>
    <li><a href="http://icons.gif">Icon sprite</a></li>
    </ul>

    ```

    当我们在浏览器中查看此列表时，我们将看到一个链接的项目列表 —— 没有视觉指示告诉用户每个链接背后是什么类型的文件 —— 用户必须根据链接的文本猜测。让我们获取所有链接并根据链接指向的文件类型为每个链接添加适当的类名。为此，我们将使用 jQuery 的属性选择器。

1.  接下来，我们将准备好将 JavaScript 添加到我们的页面中。打开`scripts`文件夹中的`scripts.js`文件。

    让我们弄清楚如何区分一种类型的链接与另一种类型的链接。`<a>`链接具有`href`属性。这个`href`属性告诉我们链接将带我们去哪个页面或文件的 URL，但它也给了我们选择具有不同属性值的链接所需的信息。让我们看看 jQuery 属性选择器的工作原理：

    ```js
    $('a')

    ```

    这将选择页面上的所有链接。如果我们只想获取具有`href`属性的`<a>`标签，我们可以修改我们的选择器如下：

    ```js
    $('a[href]')

    ```

    我们可以再进一步，并仅获取属性等于特定值的链接：

    ```js
    $('a[href="video.mp4"]')

    ```

    这个选择器只会选择链接到`video.mp4`文件的链接。请注意这里单引号和双引号的嵌套方式 —— 我可以使用单引号或双引号来包装我的选择器，但是如果我需要引用选择器内的内容，我必须小心选择另一种类型的引号。

    我们想要为这些链接中的每一个添加一个类名，以便我们可以使用 CSS 为它们添加我们的图标作为背景图像进行样式设置。为此，我们将使用 jQuery 对象的`.addClass()`方法。根据我们迄今学到的知识，我们可以在我们的文档准备就绪的语句中做类似以下的事情：

    ```js
    $(document).ready(function(){
    $('a[href ="http://presentation.ppt"]').addClass('presentation');
    $('a[href="video.mp4"]').addClass('video');
    $('a[href="notes.pdf"]').addClass('pdf');
    $('a[href="http://icons.gif"]').addClass('image');
    });

    ```

    ...但这样并不是很灵活。如果我们想要添加第二个视频或另一个 PDF 文件怎么办？我们将不得不调整我们的 jQuery 来匹配。相反，让我们通过简单地查看链接的 `href` 属性的文件扩展名来使我们的链接更加灵活。jQuery 将允许我们检查属性是否以某些字符开头，以某些字符结尾或包含某些字符。您可以在 jQuery 文档中获取可能的属性选择器的完整列表 [`api.jquery.com/category/selectors/.`](http://api.jquery.com/category/selectors/)。

    要检查属性是否以某些字符开头，请使用 `^=` 如下所示：

    ```js
    $('a[href^="video"]')

    ```

    要检查属性是否在名称中任意位置包含某些字符，请使用 `*=` 如下所示：

    ```js
    $('a[href*="deo"]')

    ```

    在这种情况下，文件扩展名始终是链接的最后一部分，因此我们将使用以属性选择器结尾的方式，该方式使用 `$=` 如下所示：

    ```js
    $(document).ready(function(){
    $('a[href$="ppt"]').addClass('presentation');
    $('a[href$="mp4"]').addClass('video');
    $('a[href$="pdf"]').addClass('pdf');
    $('a[href$="gif"]').addClass('image');
    });

    ```

1.  现在，例如，任何我们添加的具有 `.pdf` 扩展名的链接将自动被赋予 `pdf` 类。如果您在浏览器中刷新页面，此时您不会看到页面上的任何区别，但是如果您使用浏览器检查工具（例如内置在 Chrome 和 WebKit 中的工具或 Firefox 的 Firebug）检查 **DOM** **(Document Object Model)**，您将看到链接已被赋予类名。剩下的就是编写 CSS 来包含图标了。打开 `styles` 文件夹中的 `styles.css` 文件，并添加一些代码行，如下所示：

    ```js
    a {
    background: 0 50% no-repeat;
    padding-left: 20px;
    }
    a.presentation {
    background-image: url(../images/presentation.gif);
    }
    a.video {
    background-image: url(../images/video.gif);
    }
    a.pdf {
    background-image: url(../images/pdf.gif);
    }
    a.image {
    background-image: url(../images/image.gif);
    }

    ```

    您必须确保将图标图像放在 `images` 文件夹内。您可以使用本章示例代码中包含的图标图像，也可以创建您自己的图标。

    现在，如果您在浏览器中刷新页面，您将看到每个链接显示适当的图标。如果您向页面添加了这四种文件类型的新链接，它们也将具有相应的图标。我们为链接添加图标创建了一个灵活且简单的解决方案。

    ![行动时间 — 创建链接列表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_02_002.jpg)

## 刚刚发生了什么？

我们根据 `href` 属性中的文件扩展名选择了页面上的所有链接，并使用 jQuery 添加了适当的类名。然后，我们在 CSS 中使用这些类名为每个链接类型添加了图标，并应用了一些 CSS 样式。没有启用 JavaScript 的网站访问者仍然可以单击链接并下载相关文件。他们只会错过指示每个链接后面文件类型的图标。

现在您可以看到 jQuery 和 CSS 如何共同工作以向您的页面添加新功能。jQuery 可以修改元素的类名，然后可以使用 CSS 根据其类名样式化这些元素。

# 简单的标签页

如果我们有大量信息需要呈现，但这些信息可能对所有网站访问者都不相关，我们可以通过隐藏选定的信息位来压缩信息占用的空间，直到网站访问者请求它。制作所有信息可用但隐藏直到请求的最常见方法之一是选项卡。选项卡反映了现实世界中的一个例子，即带标签的笔记本或文件柜中的标记文件夹，并且易于网站访问者理解。信不信由你，它们还可以使用 jQuery 轻松实现。

这是我们创建选项卡后页面的大致样子：

![简单选项卡](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_02_003.jpg)

# 行动时间 —— 创建简单的选项卡

1.  我们将从我们的基本 HTML 文件和相关文件夹开始，就像我们在 第一章中创建的那样，*设计师，遇见 jQuery*。在`<body>`标签内，我们将从设置一个简单的示例开始，即使对于禁用 JavaScript 的用户也可以使用：我们将在页面顶部放置一系列指向页面不同区域的锚链接，然后将每个内容部分包装在一个带有`id`的`div`中，如下所示：

    ```js
    <h1>Simple Tabs Product</h1>
    <p>You should buy this, it's great!</p>
    <ul>
    <li><a href="#description">Description</a></li>
    <li><a href="#photos">Photos</a></li>
    <li><a href="#details">Details</a></li>
    <li><a href="#reviews">Customer Reviews</a></li>
    <li><a href="#related">Related Items</a></li>
    </ul>
    <div id="description">
    <h2>Overview</h2>
    <p>This section contains a basic overview of our product.</p>
    </div>
    <div id="photos">
    <h2>Photos</h2>
    <p>This section contains additional photos of our product.</p>
    </div>
    <div id="details">
    <h2>Details</h2>
    <p>This is where we list out all the details of our product—size, weight, color, materials, etc.</p>
    </div>
    <div id="reviews">
    <h2>Customer Reviews</h2>
    <p>Here's where we would list all of the glowing reviews our customers had written</p>
    </div>
    <div id="related">
    <h2>Related Items</h2>
    <p>And here we would list out other super items that our customers might also like to buy.</p>
    </div>

    ```

    如果我们在浏览器中查看此 HTML，我们将看到页面顶部有一个链接列表，点击后页面会跳转到相应部分，这样网站访问者就可以轻松找到每个部分，而不需要自己滚动。我们基本上为我们的页面创建了一个可点击的目录。

1.  现在我们想要为启用 JavaScript 的网站访问者增强此功能。我们将首先为包含我们目录的`<ul>`添加一个`id`，并为包含我们内容部分的每个`<div>`添加一个类名 —— 这将使我们更容易使用 jQuery 选择我们想要的页面部分，并且也将使我们更容易使用 CSS 样式化我们的选项卡。

    ```js
    <ul id="tabs">
    <li><a href="#description">Description</a></li>
    <li><a href="#photos">Photos</a></li>
    <li><a href="#details">Details</a></li>
    <li><a href="#reviews">Customer Reviews</a></li>
    <li><a href="#related">Related Items</a></li>
    </ul>
    <div id="description" class="tab-section">
    <h2>Overview</h2>
    <p>This section contains a basic overview of our product.</p>
    </div>
    <div id="photos" class="tab-section">
    <h2>Photos</h2>
    <p>This section contains additional photos of our product.</p>
    </div>
    <div id="details" class="tab-section">
    <h2>Details</h2>
    <p>This is where we list out all the details of our product—size, weight, color, materials, etc.</p>
    </div>
    <div id="reviews" class="tab-section">
    <h2>Customer Reviews</h2>
    <p>Here's where we would list all of the glowing reviews our customers had written</p>
    </div>
    <div id="related" class="tab-section">
    <h2>Related Items</h2>
    <p>And here we would list out other super items that our customers might also like to buy.</p>
    </div>

    ```

1.  接下来，我们将使用 jQuery 隐藏所有我们的`tab-sections`。打开你的`scripts`文件夹中的`scripts.js`文件，在文档`ready`语句内选择`tab-sections`并隐藏它们：

    ```js
    $(document).ready(function(){
    $('.tab-section').hide();
    });

    ```

    现在当我们加载页面时，我们只会看到我们的目录。

1.  接下来，当我们的选项卡之一被点击时，我们需要显示相应的部分。我们将从将函数绑定到目录内链接的单击事件开始 —— 就像我们在打开新窗口时所做的那样：

    ```js
    $(document).ready(function(){
    $('.tab-section').hide();
    $('#tabs a').bind('click', function(e){
    e.preventDefault;
    });
    });

    ```

    通过这一小段代码，我们选择了带有 id 为`#tabs`的`<ul>`内的所有链接，并将一个函数绑定到单击链接上。到目前为止，这个函数所做的一切都是取消点击 —— 如果你在浏览器中加载页面，你会发现点击链接不会做任何事情 —— 页面不再跳转到相关部分。

1.  接下来，我们想要选择适当的部分并显示它。为此，我们将使用哈希 —— 或包含`#`符号的`href`属性的部分。

    ```js
    $('#tabs a').bind('click', function(e){
    $(this.hash).show();
    e.preventDefault;
    });

    ```

    当我把`this.hash`传递给 jQuery 函数时，我正在处理的`this`是刚刚点击的链接，`this.hash`是从#符号开始直到结尾的 href 属性的值。例如，如果我点击概览标签，把`this.hash`传递给 jQuery 函数就等同于写下以下内容：

    ```js
    $('#overview')

    ```

    当然，这是以一种更加灵活的方式完成的 —— 它将适用于页面任何与之链接的标签。例如，如果我想用运输信息标签替换客户评论标签，我就不需要更新我的 JavaScript 代码，只需要更新 HTML 标记本身 —— JavaScript 足够灵活，可以适应变化。

1.  现在当我点击目录链接中的一个时，它将显示给我相应的部分，但如果我不断点击链接，部分就会不断显示，点击所有链接后，所有部分都可见，这不是我们想要的。我们需要隐藏可见的部分，只显示我们想要的部分。让我们在代码中添加一行来选择可见的`tab-section`并在显示新部分之前隐藏它：

    ```js
    $('#tabs a').bind('click', function(e){
    $('.tab-section:visible').hide();
    $(this.hash).show();
    e.preventDefault;
    });

    ```

    你可能熟悉 CSS 中的**伪类**选择器 —— 它们经常用于选择链接的 hover、visited 和 active 状态（`a:hover, a:visited`和`a:active`）。jQuery 为我们提供了一些额外的`伪类`选择器，这里有用于按钮、空元素、禁用表单字段、复选框等的伪类选择器。你可以在 jQuery 文档中查看 jQuery 的所有可用选择器 http://api.jquery.com/category/selectors/。这里，我们使用`:visible`伪类选择器来选择当前可见的`.tab-section`。一旦我们选择了可见的`.tab-section`，我们就把它隐藏起来，然后找到正确的`tab-section`并显示它。

1.  现在我们需要一些 CSS 来使我们的标签样式看起来像内容的分栏部分。打开你的`styles`文件夹中的`styles.css`文件，添加一些 CSS 样式如下。随意定制它们以适应你自己的口味。

    ```js
    #tabs {
    overflow: hidden;
    zoom: 1;
    }
    #tabs li {
    display: block;
    list-style: none;
    margin: 0;
    padding: 0;
    float: left;
    }
    #tabs li a {
    display: block;
    padding: 2px 5px;
    border: 2px solid #ccc;
    border-bottom: 0 none;
    text-align: center;
    }
    .tab-section {
    padding: 10px;
    border: 2px solid #ccc;
    }

    ```

1.  现在如果你在浏览器中加载这个页面，你会发现有一点还不够 —— 我们应该突出显示当前选定的标签，以便明确显示哪一个被选定。我们可以通过为当前标签添加一个 CSS 类来实现这一点。回到你的`scripts.js`文件，添加一段代码为当前标签添加一个类，并从任何非当前标签中移除类如下：

    ```js
    $('#tabs a').bind('click', function(e){
    $('#tabs a.current').removeClass('current');
    $('.tab-section:visible').hide();
    $(this.hash).show();
    $(this).addClass('current');
    e.preventDefault;
    });

    ```

    首先，我们会找到具有`current`类的选项卡，并删除那个类。然后我们将获取刚刚点击的选项卡，并在它上面添加`current`类。这样，我们确保每次只有一个选项卡被标记为当前选项卡。

1.  接下来，在我们的 CSS 中为我们的新类添加一些样式。打开`styles.css`，添加一些代码以区分当前选定的选项卡。同样，随意定制这种风格以适应你自己的口味：

    ```js
    #tabs li a.current {
    background: #fff;
    color: #000;
    }

    ```

1.  现在我们的选项卡已经按我们的期望工作了，剩下的唯一事情就是在页面首次加载时使第一个选项卡处于活动状态，并显示第一个内容部分，而不是将它们全部隐藏。我们已经编写了执行此操作的函数，现在我们只需为我们的第一个选项卡调用它：

    ```js
    $('#tabs a').bind('click', function(e){
    $('#tabs a.current').removeClass('current');
    $('.tab-section:visible').hide();
    $(this.hash).show();
    $(this).addClass('current');
    e.preventDefault;
    }).filter(':first').click();

    ```

    jQuery 对象的 `filter()` 方法将允许我们过滤先前选择的一组元素 —— 在本例中，我们处理的是具有 `id #tabs` 的 `<ul>` 中的所有 `<a>` 标签。我们将一个点击函数绑定到所有这些链接，然后我们将使用 `:first` 伪类过滤出第一个链接 —— 在 jQuery 中为我们提供了这个功能，并告诉 jQuery 为我们点击第一个选项卡，这将运行我们的函数，将 `current` 类添加到第一个链接，并显示第一个 `.tab-section` —— 就像我们加载页面时期望的那样。

    ![行动时间 —— 创建简单选项卡](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_02_003.jpg)

## 刚才发生了什么？

我们使用 jQuery 设置了一组简单的选项卡。对于禁用 JavaScript 的网站访问者，选项卡将像文档顶部的目录一样运行，当点击它们时，它们会跳转到各个内容部分。然而，对于启用 JavaScript 的网站访问者，内容部分将完全隐藏，直到需要。点击每个选项卡会显示与该选项卡相关联的内容。这是在用户界面中节省空间的绝佳方式 —— 在一个小空间中按需提供所有内容。

我们使用 JavaScript 隐藏选项卡内容，而不是使用 CSS，以确保没有启用 JavaScript 的用户仍然能够访问我们的所有内容。

# 总结

在本章中，您学习了如何使用基本链接 —— 互联网的支柱 —— 并增强它们以添加一些新的行为和功能。您学习了如何使链接在新窗口中打开，根据链接的文件类型添加图标以及如何设置基本的选项卡界面。这些都是网站的非常常见的要求，当您学习更多关于 jQuery 和 JavaScript 的知识时，这些将作为您的良好基石。


# 第三章：打造更好的常见问题解答页面

> 自互联网诞生以来，常见问题解答页面一直是各种类型的网站的主要页面。它被用作营销页面，试图减少对客户服务部门的电话或电子邮件数量，并且作为站点访问者了解与之交易的公司或组织，或者他们感兴趣购买的产品或服务的有用工具。
> 
> 虽然我们将为此示例构建一个常见问题解答页面，但此展开和折叠技术在许多不同情况下都很有用 — 事件列表与事件详情、员工或成员列表与简介、产品列表与详情 — 任何情况下都应该使站点访问者能够快速浏览项目列表，但在他们找到所需内容时应该能够立即轻松地根据需求获取更多信息。

在本章中，我们将学习：

+   如何使用 jQuery 遍历 HTML 文档

+   如何显示和隐藏元素

+   如何使用简单的 jQuery 动画

+   如何轻松切换元素的类名

# 常见问题解答页面标记

我们将从特别关注我们如何标记常见问题解答列表开始。与大多数涉及 Web 开发的事情一样，没有一种正确的方法，所以不要将这种方法视为唯一正确的方法。任何语义上合理且便于使用 CSS 和 JavaScript 增强列表的标记都是完全可以接受的。

# 行动时间 — 设置 HTML

1.  我们将从我们的示例 HTML 文件和关联的文件和文件夹开始，就像我们在第一章中设置的那样，*设计师，遇见 jQuery*。在这种情况下，我们的 HTML 将是一个包含在`<dt>`标签中的问题的定义列表，而答案则包含在`<dd>`标签中。默认情况下，大多数浏览器会缩进`<dd>`标签，这意味着问题会悬挂在左边距中，使其易于浏览。在 HTML 文档的`<body>`内，按如下方式添加标题和定义列表：

    ```js
    <h1>Frequently Asked Questions</h1>
    <dl>
    <dt>What is jQuery?</dt>
    <dd>
    <p>jQuery is an awesome JavaScript library</p>
    </dd>
    <dt>Why should I use jQuery?</dt> <dd>
    <p>Because it's awesome and it makes writing JavaScript faster and easier</p>
    </dd>
    <dt>Why would I want to hide the answers to my questions? </dt>
    <dd>
    <p>To make it easier to peruse the list of available questions - then you simply click to see the answer you're interested in reading.</p>
    </dd>
    <dt>What if my answers were a lot longer and more complicated than these examples?</dt>
    <dd>
    <p>The great thing about the &lt;dd&gt; element is that it's a block level element that can contain lots of other elements.</p>
    <p>That means your answer could contain:</p>
    <ul>
    <li>Unordered</li>
    <li>Lists</li>
    <li>with lots</li>
    <li>of items</li>
    <li>(or ordered lists or even another definition list)</li>
    </ul>
    <p>Or it might contain text with lots of <strong>special</strong> <em>formatting</em>.</p>
    <h2>Other things</h2>
    <p>It can even contain headings. Your answers could take up an entire screen or more all on their own - it doesn't matter since the answer will be hidden until the user wants to see it.</p>
    </dd>
    <dt>What if a user doesn't have JavaScript enabled?</dt>
    <dd>
    <p>You have two options for users with JavaScript disabled - which you choose might depend on the content of your page.</p>
    <p>You might just leave the page as it is - and make sure the &lt;dt&gt; tags are styled in a way that makes them stand out and easy to pick up when you're scanning down through the page. This would be a great solution if your answers are relatively short.</p>
    <p>If your FAQ page has long answers, it might be helpful to put a table of contents list of links to individual questions at the top of the page so users can click it to jump directly to the question and answer they're interested in. This is similar to what we did in the tabbed example, but in this case, we would use jQuery to hide the table of contents when the page loaded since users with JavaScript wouldn't need to see the table of contents.</p>
    </dd>
    </dl>

    ```

1.  你可以通过添加一些 CSS 来调整页面的样式。以下是我的样式设置方式：![行动时间 — 设置 HTML](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_03_img1.jpg)

对于禁用 JavaScript 的用户，该页面可以正常工作。问题会悬挂在左边距中，比页面上的其他文本更加粗体和深色，使其易于浏览。

## 刚刚发生了什么？

我们设置了一个基本的定义列表来保存我们的问题和答案。默认样式的定义列表很好地使得问题列表对于没有 JavaScript 的站点访问者易于浏览。我们可以进一步通过自定义 CSS 来增强我们的样式以使列表的风格与我们的站点匹配。

# 行动时间 — 在 HTML 文档中移动

1.  我们将继续使用前一节设置的文件进行工作。打开位于您的`scripts`文件夹内的`scripts.js`文件。在文档就绪语句之后，编写一个名为`dynamicFaq`的新空函数：

    ```js
    function dynamicFaq() {
    //our FAQ code will go here
    }

    ```

1.  让我们思考一下我们希望此页面的行为。我们希望在页面加载时将所有问题的答案隐藏，然后当用户找到他们正在寻找的问题时，当他们点击问题时，我们希望显示相关答案。

    这意味着当页面加载时，我们首先需要隐藏所有答案。这只是简单地选择所有我们的`<dd>`元素并隐藏它们。在您的`dynamicFaq`函数内，添加一行代码以隐藏`<dd>`元素：

    ```js
    function dynamicFaq() {
    $('dd').hide();
    }

    ```

    ![行动时间 - 在 HTML 文档中移动](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_03_img2.jpg)

    ### 注意

    您可能想知道为什么我们没有使用 CSS 将`<dd>`标签的显示设置为`none`。那样会隐藏我们的答案，但会使所有人都无法访问我们的答案 - 没有启用 JavaScript 的网站访问者将无法访问页面的最重要部分 - 答案！

    这也会阻止大多数搜索引擎索引我们答案内的内容，这对于试图在搜索引擎中找到答案的人可能是有帮助的。通过使用 JavaScript 隐藏答案，我们可以确保答案将可用，除非用户启用了 JavaScript 并且能够再次显示它们。

1.  现在，当网站访问者点击问题时，我们需要显示答案。为此，我们需要告诉 jQuery 在有人点击其中一个问题或`<dt>`标签时做些什么。在`dynamicFaq`函数内，添加一行代码以将点击函数绑定到`<dt>`标签：

    ```js
    function dynamicFaq() {
    $('dd').hide();
    $('dt').bind('click', function(){
    //Show function will go here
    });
    }

    ```

1.  当网站访问者点击问题时，我们希望获取该问题的答案并显示出来，因为我们的常见问题列表设置与以下代码类似：

    ```js
    <dl>
    <dt>Question 1</dt>
    <dd>Answer to Question 1</dd>
    <dt>Question 2</dt>
    <dd>Answer to Question 2</dd>
    ...
    </dl>

    ```

    …我们知道答案是我们问题后的 DOM 中的下一个节点或元素。我们将从问题开始。当网站访问者点击问题时，我们可以使用 jQuery 的`$(this)`选择器获取当前问题。用户刚刚点击了一个问题，我们使用`$(this)`来表示他们刚刚点击的问题。在该新的`click`函数中，添加`$(this)`以便我们可以引用点击的问题：

    ```js
    $('dt').bind('click', function(){
    $(this);
    });

    ```

1.  现在我们已经有了刚刚点击的问题，我们需要获取下一个内容或该问题的答案，以便我们可以显示它。这在 JavaScript 中称为**DOM 遍历**。这只是意味着我们正在移动到文档的另一部分。

    jQuery 为我们提供了`next()`方法来移动到 DOM 中的下一个节点。我们将通过以下方式选择我们的答案：

    ```js
    $('dt').bind('click', function(){
    $(this).next();
    });

    ```

1.  现在我们已经从问题移动到答案。现在剩下的就是显示答案：

    ```js
    $('dt').bind('click', function(){
    $(this).next().show();
    });

    ```

1.  别忘了，我们的`dynamicFaq`函数在我们调用它之前什么都不会做。在您的文档就绪语句中调用`dynamicFaq`函数：

    ```js
    $(document).ready(function(){
    dynamicFaq();
    });

    ```

1.  现在，如果我们在浏览器中加载页面，您会发现在单击问题之前，我们所有的答案都是隐藏的。这很好也很有用，但是如果网站访问者完成阅读后可以再次隐藏答案以摆脱它，那将更好。幸运的是，这是一个常见任务，jQuery 为我们提供了很大的帮助。我们所要做的就是将我们的 `.show()` 方法替换为 `.toggle()` 方法，如下所示：

    ```js
    $('dt').bind('click', function(){
    $(this).next().toggle();
    });

    ```

现在，当您在浏览器中刷新页面时，您会发现单击问题会显示答案，再次单击问题会再次隐藏答案。

## 刚刚发生了什么？

在页面上切换元素的显示是一个常见的 JavaScript 任务，所以 jQuery 已经内置了处理它的方法，并且使得在我们的页面上实现这个功能变得简单明了。这相当容易；只需几行代码。

# 点缀我们的常见问题解答页面

实际上，这么简单，我们还有大量时间来增强我们的常见问题解答页面，使其变得更好。这就是 jQuery 的威力所在 — 您不仅可以创建一个显示/隐藏的常见问题解答页面，而且还可以使其变得花哨，并且仍然能够按时完成任务。这对于给客户或老板留下深刻印象来说如何？

# 行动时间 — 让它变得花哨

1.  让我们从一点 CSS 开始，将鼠标光标更改为指针，并向我们的问题添加一点悬停效果，以便向网站访问者明确表明问题是可点击的。打开位于样式文件夹中的 `styles.css` 文件，并添加以下 CSS 代码：

    ```js
    dt {
    color: #268bd2;
    font-weight: bold;
    cursor: pointer;
    margin: 0 0 1em 0;
    }
    dt:hover {
    color: #2aa198;
    }

    ```

    这绝对有助于向网站访问者传达问题是可点击的信息。

    ![行动时间 — 让它变得花哨](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_03_img3.jpg)

1.  当我们单击问题查看答案时，页面上的变化没有很好地传达给网站访问者 — 页面上的跳转有点让人不安，需要一会儿才能意识到刚刚发生了什么。如果问题能够平滑地显示出来，那将更加舒适和易于理解；网站访问者可以看到问题的出现，立即理解屏幕上刚刚发生的变化。

    jQuery 为我们提供了便利。我们只需将我们的 `.toggle()` 方法替换为 `.slideToggle()` 方法。

    ```js
    $('dt').bind('click', function(){
    $(this).next().slideToggle();
    });

    ```

现在，如果您在浏览器中查看页面，您会发现点击问题时，问题会平滑地显示和隐藏。当页面发生变化时，很容易理解发生了什么，并且动画效果很不错。

## 刚刚发生了什么？

我们用 `slideToggle()` 方法替换了我们的 `toggle()` 方法来动画显示和隐藏答案。这使得网站访问者更容易理解页面上发生的变化。我们还添加了一些 CSS，使问题看起来像是可点击的，以向我们的网站访问者传达我们页面的能力。

# 我们快要完成了！

jQuery 使得动画的显示和隐藏变得如此容易，以至于我们仍然有时间进一步增强我们的 FAQ 页面。添加一些指示器来显示我们的问题已经折叠并且可以展开，以及一旦它们被打开就添加一些特殊的样式以显示它们可以再次折叠，这将是很好的。

# 行动时间——添加一些最后的修饰

1.  让我们从一些简单的 CSS 开始，向我们的问题的左侧添加一个小箭头图标。返回`style.css`并稍微修改样式以添加一个箭头图标或您选择的图标。您可以将所选图标放在`images`文件夹中：

    ```js
    dt {
    color: #268bd2;
    font-weight: bold;
    cursor: pointer;
    margin: 0 0 1em 0;
    padding: 0 0 0 20px;
    background: url(../images/arrow.png) 0 0 no-repeat;
    line-height: 16px;
    }
    dt:hover {
    color: #2aa198;
    background-position: 0 -32px;
    }

    ```

    我正在使用图像精灵来显示箭头。当鼠标悬停在问题上时，我将我的问题从蓝色更改为绿色，因此我在精灵中包含了蓝色和绿色的箭头，并且在文本变为绿色时使用了一些 CSS 来显示绿色箭头。这意味着只需下载一个图像，无需在鼠标悬停在我的问题上时下载新图像来显示。如果您对 CSS 图像精灵技术不熟悉，我建议您查看*Chris Coyier*在[`css-tricks.com/css-sprites/.`](http://css-tricks.com/css-sprites/. )上解释它的文章。

1.  现在，当问题打开时，我们想要将箭头改为不同的方向。我们所要做的就是为我们的问题的打开状态使用一个新的 CSS 类，并编写关闭和打开状态的代码，以便新的箭头形状也会改变颜色。同样，我已经将这些箭头图像包含在同一个精灵中，所以我唯一需要改变的就是背景位置：

    ```js
    dt.open {
    background-position: 0 -64px;
    }
    dt.open:hover {
    background-position: 0 -96px;
    }

    ```

    ### 注意

    请确保在我们用来为`<dt>`标签添加样式的其他 CSS 之后添加这些新类。这样可以确保 CSS 按照我们的意图级联。

1.  所以我们有了 CSS 来显示我们的问题是打开的，但是我们如何实际使用它呢？我们将使用 jQuery 在问题打开时向我们的问题添加类，并在关闭时删除类。

    jQuery 提供了一些很好的方法来处理 CSS 类。`addClass()`会将一个类添加到 jQuery 对象中，而`removeClass()`会删除一个类。但是，我们想要像切换问题的显示和隐藏一样切换我们的类。jQuery 也为此提供了支持。当我们点击问题时，我们希望类发生变化，因此我们将在我们每次点击`<dt>`时调用的`dynamicFaq`函数中添加一行代码：

    ```js
    $('dt').bind('click', function(){
    $(this).toggleClass('open');
    $(this).next().slideToggle();
    });

    ```

    现在当您查看页面时，您将看到在`<dt>`标签打开时应用的打开样式，并在关闭时再次删除。但我们实际上可以将我们的代码压缩得更小一些。

1.  jQuery 最强大的功能之一被称为链式调用。当我们在一行中向`next()`方法添加了`slideToggle()`时，我们已经使用了链式调用。

    ```js
    $(this).next().slideToggle();

    ```

    jQuery 中的方法可以链接在一起。您可以继续添加新的方法来进一步转换、修改或动画化一个元素。这行代码获取问题，遍历 DOM 到下一个节点，我们知道这是我们的 `<dd>`，然后切换那个 `<dd>` 的滑动动画。

    我们可以再次利用链接。我们的代码中存在一些冗余，因为我们在两行不同的代码中都以 `$(this)` 开头。我们可以删除额外的 `$(this)`，并将我们的 `toggleClass()` 方法添加到我们已经开始的链中，如下所示：

    ```js
    $(this).toggleClass('open').next().slideToggle();

    ```

    ![行动时间 — 添加最后的一些修饰](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_03_img4.jpg)

## 刚刚发生了什么？

我们创建了 CSS 样式来为我们的问题的打开和关闭状态添加样式，然后我们在我们的 JavaScript 中添加了一点代码来更改问题的 CSS 类以使用我们的新样式。jQuery 提供了几种不同的方法来更新 CSS 类，这通常是对来自站点访问者的输入做出响应时更新文档显示的一种快速简便的方法。在这种情况下，由于我们想要添加和移除一个类，所以我们使用了 `toggleClass()` 方法。这使我们免于自己去弄清楚是否需要添加或移除打开类。

我们还利用链接来简单地将这个新功能添加到我们现有的代码行中，使得答案的动画显示和隐藏以及我们问题的 CSS 类的更改都只需一行代码即可完成。这对于在短时间内用少量代码实现令人印象深刻的功能来说，算怎么样？

# 总结

在本章中，我们学习了如何设置一个基本的常见问题解答页面，该页面在站点访问者需要查看答案之前隐藏问题。由于 jQuery 让这个过程变得如此简单，我们有足够的时间来进一步增强我们的常见问题解答页面，为我们的问题的显示和隐藏添加动画效果，并利用 CSS 来为我们的问题添加特殊的打开和关闭类，以向我们的站点访问者传达我们页面的工作方式。而我们只用了几行代码就完成了所有这些工作。

接下来，我们将学习如何在我们的页面上使用自定义滚动条。


# 第四章：构建自定义滚动条

> 处理具有大量内容的页面的常见策略是隐藏一些内容，直到站点访问者希望或需要它。有许多方法可以做到这一点 —— 您可以使用选项卡、手风琴、灯箱，或者本章重点，可滚动区域。
> 
> 可滚动区域易于站点访问者理解和使用，但它们经常被忽视，因为一些操作系统有难看的滚动条，这会破坏您精心调整的设计美感。浏览器几乎没有提供用于自定义滚动条外观的选项，也从未在任何 HTML 或 CSS 规范中包含官方手段。
> 
> 一些设计师已经转向 Flash 来创建自定义滚动条，我相信你一定遇到过这些 Flash 滚动条的示例，往往它们笨拙且违反处理可滚动区域的常规惯例。例如，您很少能够使用鼠标的滚轮来滚动 Flash 可滚动区域。

在本章中，我们将学习： 

+   如何下载和使用 jQuery 插件，以便更多地使用 jQuery

+   如何使用插件的内置定制选项来定制插件的工作方式

+   如何使用 CSS 进一步定制插件

+   如何设置自定义设计的滚动条，使其与您的站点访问者的期望一样工作

+   如何使用 jScrollPane 插件在我们的可滚动区域之间平滑滚动到不同的内容部分

# 设计师，认识一下插件

我们已经谈过程序员如何一次又一次地解决相同的问题。正是这些常见的任务，jQuery 简化了我们能够用最少的代码完成这些任务。但是对于一些仅仅是有些常见的任务，比如想要漂亮的自定义滚动条，如何解决呢？

这就是 jQuery 社区变得重要的地方。jQuery 社区的开发人员能够编写代码，扩展 jQuery 的功能，简化一些常见的任务。这些代码片段称为**插件**，它们与 jQuery 库一起使用，使编写复杂的交互、小部件和效果就像使用 jQuery 已经内置的功能一样简单。

在官方 jQuery 网站上，您会找到数百个 jQuery 插件的库。除此之外，还有数千个来自 Web 上各个站点的插件，几乎可以完成您想要完成的任何任务。

要创建自定义滚动条，我们将使用*Kelvin Luck*的 jScrollPane 插件。您将学习如何在您的页面上安装插件以及如何配置 CSS 和选项，使您的滚动条看起来和工作方式符合您的要求。

## 选择插件

最近，jQuery 团队已经开始支持一小部分官方 jQuery 插件，你可以放心使用这些插件，因为它们具有与 jQuery 本身相同水平的专业知识、文档和支持。所有其他 jQuery 插件都是由 jQuery 社区的各个成员提供的，这些作者对其自己的插件负有文档和支持的责任。撰写和提供 jQuery 插件有点像自由竞争，遗憾的是，你会发现一大堆文档质量差、支持不够好，甚至更糟糕，编写得很差的 jQuery 插件。作为一个新手 jQuery 用户，选择插件时应该寻找哪些特征呢？

+   *插件的最新更新*。频繁的更新意味着插件得到了良好的支持，作者也在保持插件随着 jQuery 和浏览器的演变而更新。

+   *彻底易懂的文档*。在尝试下载和使用插件之前，请浏览插件的文档，并确保您了解如何实现插件以及如何使用插件提供给您的任何选项。

+   *浏览器支持*。优秀的插件一般具有与 jQuery 库本身相同的浏览器支持。

+   *工作演示*。大多数插件作者都会提供一个或多个插件的工作演示。尽可能在不同的浏览器中查看演示，以确保插件如广告所述的那样工作。

+   *评论和评分*。并非所有插件都有评论和评分，但如果你能找到一些，它们可以是插件质量和可靠性的有用指标。

# 设置一些可滚动的 HTML

让我们看看如何设置一个包含可滚动区域的简单 HTML 页面。一旦我们完成了这个，我们将看看如何用自定义的滚动条替换默认的滚动条。

# 行动时间 —— 可滚动 HTML

按照以下步骤设置一个包含可滚动区域的简单 HTML 页面：

1.  我们将从设置一个基本的 HTML 页面和相关的文件和文件夹开始，就像我们在 Chapter 1 中所做的那样，*设计师，遇见 jQuery*。我们需要有一个足够大的内容区域来滚动，所以我们将在 HTML 文档的正文部分添加几段文本：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
    <title>Custom Scrollbars</title>
    <link rel="stylesheet" href="styles/styles.css"/>
    </head>
    <body>
    <h2>We don't want this box of content to get too long, so we'll make it scroll:</h2>
    <p>Lorem ipsum dolor sit amet...
    Include several paragraphs of lorem ipsum here
    ...mollis arcu tincidunt.</p>
    <script src="img/jquery.js"></script>
    <script src="img/scripts.js"></script>
    </body>
    </html>

    ```

    我没有包含所有内容，但我在我的页面上包含了五段长的 lorem ipsum 文本，以增加页面的长度，并为我们提供一些可滚动的内容。如果你不知道，lorem ipsum 只是一种虚拟的填充文本。你可以在[`lipsum.com`](http://lipsum.com)上生成一些随机的 lorem ipsum 文本来填充你的页面。

1.  现在，我们需要使我们的文本滚动。为了做到这一点，我要将所有那些 lorem ipsum 的段落包裹在一个`div`中，然后使用 CSS 在`div`上设置高度，将`overflow`设置为`auto`：

    ```js
    <h2>We don't want this box of content to get too long, so we'll make it scroll:</h2>
    <div id="scrolling">
    <p>Lorem ipsum dolor sit amet...
    Include several paragraphs of lorem ipsum here
    ...mollis arcu tincidunt.</p>
    </div>

    ```

1.  接下来，打开你的空的`styles.css`文件，添加下面的 CSS 来实现我们的文本区域可以滚动：

    ```js
    #scrolling {
    width:500px;
    height:300px;
    overflow:auto;
    }

    ```

    随意添加一些额外的 CSS 来自定义您的文本样式。

    现在，当我在浏览器中查看我的页面时，我会看到浏览器已经为我的文本添加了一些（丑陋的）滚动条：

    ![实践时间—可滚动的 HTML](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_04_img1.jpg)

# 添加自定义滚动条

在大多数情况下，滚动条的外观是由您的网站访问者所使用的操作系统决定的，而不是他们的浏览器。所以，无论您在 Mac 上使用 Firefox、Safari、Chrome 还是其他浏览器，您总是会看到那些标志性的闪亮蓝色滚动条。在 PC 上，无论您在 Windows 选项中设置了什么颜色方案，您总是会看到那些笨拙的方形滚动条。

# 实践时间—简单自定义滚动条

您会发现操作系统的默认滚动条在我们精美设计的页面中格外突兀。让我们来解决这个问题，好吗？

1.  首先，我们要找到要使用的插件来创建自定义滚动条。前往[`jscrollpane.kelvinluck.com/`](http://jscrollpane.kelvinluck.com/)，点击导航菜单中的**下载**链接：![实践时间—简单自定义滚动条](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_04_img2.jpg)

    这将带您跳转到站点的**下载**部分，在那里您会看到 Kelvin Luck 正在使用 Github 来托管他的代码。Github 是一个社交编程中心—一种面向开发者的 Facebook—主要集中在撰写、分享和讨论代码。如今，使用 Github 来托管 jQuery 插件和其他开源代码项目变得越来越普遍，因为 Github 为开发者提供了一个简单的方式来与他人分享和合作他们的代码。

    别担心—从 Github 下载插件很简单。我会带你一步步完成。

1.  首先，在*Kelvin Luck*的网站上点击 Github 链接：![实践时间—简单自定义滚动条](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_04_img3.jpg)

1.  这将带您进入 jScrollPane 项目在 Github 上的主页。在页面的右侧，您会看到一个**下载**按钮：![实践时间—简单自定义滚动条](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_04_img4.jpg)

1.  点击**下载**按钮后，会弹出模态对话框，显示项目的所有可用下载包。简单明了，只需点击**下载 .zip**按钮即可获取最新版本：![实践时间—简单自定义滚动条](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_04_img5.jpg)

1.  ZIP 下载将自动开始。一旦完成，在 Github 完成。我告诉过你，这很简单。现在，让我们解压这个包并看看里面有什么。![实践时间—简单自定义滚动条](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_04_img6.jpg)

    哇！这么多文件！我们应该怎么处理这些文件？

    看上去有点吓人和混乱，但这些文件大部分都是关于如何使用插件的示例和文档。我们只需要找到组成插件的 JavaScript 文件。我们将在`script`文件夹中找到它们。

    ![实践时间—简单自定义滚动条](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_04_img7.jpg)

1.  在`script`文件夹内，我们将找到更多我们期望的内容。让我们弄清楚这些文件是什么。

    +   `demo.js`是示例代码。这是*凯尔文·拉克*用来组合压缩文件中各种演示的内容。如果我们卡住了，看看示例可能会有用，但我们不需要它来进行我们自己的项目。

    +   `jquery.jscrollpane.js`是 jScrollPane 插件的源代码。如果我们想要修改插件的工作方式或深入研究源代码，我们可以使用这个文件，但我们现在还不是专家级的程序员，所以我们可以暂时不管它。为什么文件名以`jquery.`开头？将`jquery.`添加到文件名前面以标记为 jQuery 插件是一种常见做法。在使用了十几个或更多 jQuery 插件以及其他 JavaScript 文件的大型项目中，这样可以更容易地找到 jQuery 插件。 

    +   `jquery.jscrollpane.min.js`是插件的压缩版本。它和`jquery.jscrollpane.js`是相同的代码，只是进行了压缩。这意味着所有额外的空格、制表符等都被移除，使文件更小——你可以看到效果相当不错。压缩后的文件只有 16 KB，而常规文件则为 45 KB。如果我们打开它，我们将无法轻松地阅读此文件，但这没关系。我们不需要能够阅读它，更重要的是我们要为我们的站点访问者提供尽可能小的文件。

    +   `jquery.mousewheel.js`是我们将用于自定义滚动条的另一个插件。它是一个让我们的鼠标滚轮在可滚动区域中正常工作的插件。

    +   `mwheelintent.js`是另一个插件。浏览 *凯尔文·拉克* 的文档，我们发现这个插件用于确保当我们将可滚动区域嵌套在彼此内时，它们的工作方式与我们期望的一样。但现在我们不需要它。

1.  复制`jquery.jscrollpane.min.js`和`jquery.mousewheel.js`并将它们放在你的`scripts`文件夹内，紧挨着`jquery.js`文件。

1.  接下来，我们需要像之前引入 jQuery 一样，在我们的页面中包含这两个文件。滚动到页面底部，在 jQuery 的`<script>`标签和你自己的`<script>`标签之间附加新文件：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/jquery.mousewheel.js"></script>
    <script src="img/jquery.jscrollpane.min.js"></script>
    <script src="img/scripts.js"></script>
    </body>
    </html>

    ```

    ### 小贴士

    每当你使用 jQuery 插件时，你要确保你的`<script>`标签的顺序是正确的。jQuery 的`<script>`标签应始终排在第一位，任何插件将紧随其后。最后是任何使用 jQuery 或插件的脚本。这是因为浏览器将按照我们指定的顺序加载这些脚本。插件文件需要在 jQuery 之后加载，因为它们正在使用 jQuery 库，并依赖于它在可用之前工作。在 JavaScript 中，我们称之为依赖关系。插件代码依赖于 jQuery。反过来，我们自己的代码依赖于插件代码和 jQuery 库本身，因此需要在这些可用后加载。

    在这种情况下，我们有一个额外的依赖项需要注意。jScrollPane 插件依赖于 MouseWheel 插件。因此，我们需要确保首先加载 MouseWheel 插件，然后加载 jScrollPane 插件。如果您遇到了 jQuery 或插件无法工作的问题，检查您的脚本顺序是个好主意 —— 缺少或顺序错误的依赖关系通常是原因。

    我们几乎准备好设置滚动条了，但还有一个文件我们需要包含。jScrollPane 插件实际上通过隐藏浏览器的原生滚动条并从普通的`<div>`和`<span>`构建替代品来工作。这意味着我们需要一些 CSS 来样式化那些`<div>`和`<span>`，使它们看起来像滚动条。稍后，我们将看看如何编写我们自己的 CSS 来使我们的滚动条看起来任何我们想要的样子，但现在，我们将使用 Kelvin Luck 提供的 CSS 来保持简单。

1.  回到我们从 Github 下载的文件中，找到`style`文件夹。在文件夹内，你会找到两个文件：`demo.css`和`jquery.jscrollpane.css`。就像脚本文件一样，`demo.css`是专门为示例编写的特殊代码，但`jquery.jscrollpane.css`是将为我们的滚动条设置样式的文件。将该文件复制到您自己的`styles`文件夹中，然后在文档的`<head>`部分，在您自己的`styles.css`文件之前附加新样式表：

    ```js
    <head>
    <title>Custom Scrollbars</title>
    <link rel="stylesheet" href="styles/jquery.jscrollpane.css"/>
    <link rel="stylesheet" href="styles/styles.css"/>	
    </head>

    ```

1.  哎呀！我们已经做了很多工作，但我们仍然需要将我们的自定义滚动条添加到我们的页面中。别担心，在真正的 jQuery 风格中，这只是几行代码。打开您的`scripts.js`文件，添加以下代码：

    ```js
    $(document).ready(function(){
    $('#scrolling').jScrollPane();
    });

    ```

    现在，如果您刷新页面，您将看到我们的可滚动区域现在有一个 jScrollPane 风格的滚动条。

    ![操作时间 —— 简单自定义滚动条](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_04_img8.jpg)

## 刚刚发生了什么？

让我们分解最后一段代码，以理解发生了什么。

我们已经熟悉了这个：

```js
$(document).ready();

```

这是在文档上调用的 jQuery 对象的 ready 方法。这意味着我们将在文档准备就绪时运行我们的代码。像往常一样，我们通过向该方法传递一个函数来告诉 jQuery 在文档准备就绪时应该发生什么：

```js
$(document).ready(function(){
//our code will go here
});

```

所以我们要看的唯一真正新的东西就是我们写在函数内的代码行：

```js
$('#scrolling').jScrollPane();

```

但即使这一点我们也能理解至少一点。我们知道`$('#scrolling')`将选择页面上`id`为 scrolling 的项目。记住，我们在我们想要滚动的文本段落周围包裹了`<div id="scrolling"></div>`。然后我们使用了一些 CSS 来限制`#scrolling div`的高度并显示浏览器的滚动条。

然后我们可以看到我们正在调用 `jScrollPane()` 方法。大多数 jQuery 插件都是这样工作的 —— 通过添加一个你可以调用的新方法。你如何知道新方法的名称是什么？你通常会在插件的文档中找到它。jScrollPane 文档详尽，提供了大量的示例供你学习和修改。

# 添加箭头控件

好的，现在我们已经掌握了使用插件的基础知识，现在我们可以看看如何进一步使用它。

# 行动时间 —— 添加上下箭头

让我们给我们的滚动条添加上下按钮，这样我们的滚动条看起来和行为更像原生的滚动条。

1.  让我们回到我们的 `scripts.js` 文件中调用 `jScrollPane()` 方法创建自定义滚动条的那行代码：

    ```js
    $('#scrolling').jScrollPane();

    ```

    记得我们如何通过将它们放在括号里传递给方法和函数的吗？我们有以下例子：

    ```js
    dog.eat('bacon');

    ```

    我们想说狗在吃培根。所以，在 JavaScript 中，我们向狗的 eat 方法传递了培根。

    好吧，在这种情况下，我们可以向 `jScrollPane` 方法传递一组选项，以控制我们的滚动条的外观和行为。我们想在我们的滚动条上显示顶部和底部箭头，我们可以通过将 `showArrows` 选项设置为 true 来实现。我们只需要对我们的代码做一个简单的修改：

    ```js
    $('#scrolling').jScrollPane({showArrows:true});

    ```

1.  现在当你刷新页面时，你会看到顶部和底部的滚动条上有方框，就像顶部和底部箭头会出现的地方一样。![行动时间 —— 添加上下箭头](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709_04_img10.jpg)

如果你点击这些框，你会发现它们的行为就像普通滚动条上的上下箭头一样。它们只是有点朴素 — 我们可以用一些 CSS 来为它们增加样式，让它们看起来任何我们想要的样子。

## 刚刚发生了什么？

我们将 `jScrollPane` 方法的 `showArrows` 选项设置为 `true`。这个插件提供了一长串高级选项，但幸运的是，我们不需要学习或了解它们全部才能充分利用它。

我们怎么知道有一个 `showArrows` 选项？我们会在插件的文档中找到它。一旦你更加了解 JavaScript 和 jQuery，你就能够阅读插件文件本身，查看插件为你提供的选项和方法。

要向方法传递一个选项，你需要用花括号括起来。然后你会输入你要设置的选项的名称（在本例中为`showArrows`)，然后是一个冒号，然后是你要设置选项的值（在本例中为`true`表示显示箭头）。就像我们之前所做的一样：

```js
$('#scrolling').jScrollPane({showArrows:true});

```

如果你想向一个方法传递多个选项，你需要做的一切都一样，只是在选项之间需要用逗号隔开。例如，如果我想在我的文本和滚动条之间添加一点间距，我可以通过为 `verticalGutter` 选项设置一个值来实现：

```js
$('#scrolling').jScrollPane({ showArrows:true,verticalGutter:20});

```

现在，您可以看到，如果我设置了十几个或更多选项，这行代码会变得又长又难读。因此，将选项分开放在单独的行上是常见的做法，如下所示：

```js
$('#scrolling').jScrollPane({
showArrows: true,
verticalGutter: 20
});

```

您可以看到内容和顺序是相同的，只是这个例子更容易被人读到和理解。计算机无论如何都不会在意。

### 提示

注意不要在最后一个选项/值对之后添加额外的逗号。大多数浏览器会优雅地处理这个错误，但是 Internet Explorer 会抛出错误，您的 JavaScript 将无法工作。

# 自定义滚动条样式

现在我们的滚动条上有了顶部和底部按钮，让我们将它们的外观调整得正好符合我们的要求。我们可以编写自己的 CSS 样式来设置滚动条的外观。

如果您花了一些时间来调试 CSS，那么您肯定已经知道您喜欢的浏览器中为您提供的调试工具。以防您还不知道，我强烈建议您看看 Firefox 的 Firebug 扩展，或者 Opera、Chrome、Safari 和 IE9 内置的开发工具。通过快速的谷歌搜索“您的浏览器 *开发者工具教程*”应该能够获得很多教程，让您学会如何充分利用这些工具所提供的便利。

如果您使用的是 IE 的旧版本，那么看看**Debug Bar**能帮助您调试 CSS 问题的 IE 扩展程序。这个扩展程序可以免费个人使用。

我在开发新页面时倾向于使用 Google Chrome。要访问 Chrome 中的开发者工具，请单击工具栏最右侧的扳手图标，然后选择**工具** | **开发者工具**。这是使用内置工具可以得到的 CSS 信息的一个例子：

![自定义滚动条样式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_04_img9.jpg)

在左侧，您可以看到我的文档的 DOM —— 构成文档树的所有 HTML 元素。我可以与之交互 —— 每个节点都可以被展开或折叠，以显示或隐藏嵌套在内的元素。在这种情况下，高亮显示的元素是我们 jScrollPane 滚动条的容器。

在右侧，我可以看到应用于左侧已选择元素的 CSS。我还可以看到特定 CSS 出现在哪个文件中，以及在哪一行。在这种情况下，大部分样式我的滚动条容器的 CSS 可以在`jquery.jscrollpane.css`文件的第 20 行找到。

通过这种方式深入 DOM 和 CSS 很快且容易地找出我们需要修改的 CSS 行，以满足我们所需的外观。

我们有几种选项来定制滚动条的 CSS。我们可以直接修改`jquery.jscrollpane.css`文件，也可以将这些样式复制到我们自己的样式表中进行更改。这是个人喜好的问题，但如果你选择直接修改`jquery.jscrollpane.css`文件，就像我在这里做的那样，那么我强烈建议你制作一个单独的副本以供参考，这样你就可以在不重新下载的情况下轻松地恢复它。

# 行动时间——添加我们自己的样式

1.  打开`jquery.jscrollpane.css`。大约在第 56 行附近，你会找到为`.jspTrack`样式化的 CSS。这是我们滚动条的轨道，也可以说是背景区域。它的默认样式是淡紫色。

    ```js
    .jspTrack
    {
    background: #dde;
    position: relative;
    }

    ```

    我们不想动位置，因为我们的滚动条依赖于它来正确工作，但你可以随意将背景颜色改为任何你喜欢的颜色、渐变或图片。我会选择淡粉色：

    ```js
    .jspTrack
    {
    background: #fbebf3;
    position: relative;
    }
    The next style I'd like to change is for .jspDrag. This is the actual scrollbar handle. I'm going to make it bright pink:
    .jspDrag
    {
    background: #D33682;
    position: relative;
    top: 0;
    left: 0;
    cursor: pointer;
    }

    ```

1.  接下来，我将处理顶部和底部按钮。我不仅有一个默认样式，还有一个禁用样式。例如，当滚动区域完全位于顶部时，顶部按钮被禁用，因为我不可能再向上滚动了。如果我用开发者工具检查按钮，我还可以看到按钮上有一个额外的类名，在默认 CSS 中没有样式化——顶部按钮有一个类名为`jspArrowUp`，底部按钮有一个类名为`jspArrowDown`。这将让我为上下按钮设置不同的样式——我将使用向上指向箭头的图片作为顶部箭头的背景，使用向下指向箭头作为底部按钮的背景，以便让我的网站访客清楚地了解它们的功能。

    这是我用来样式化它们的 CSS：

    ```js
    .jspArrow
    {
    text-indent: -20000px;
    display: block;
    cursor: pointer;
    }
    .jspArrow.jspDisabled
    {
    cursor: default;
    background-color: #999;
    }
    .jspArrowUp
    {
    background: #d6448b url(../images/arrows.png) 0 0 no-repeat;
    }
    .jspArrowDown
    {
    background: #d6448b url(../images/arrows.png) 0 -16px no-repeat;
    }

    ```

## 刚刚发生了什么？

现在刷新浏览器，你会看到滚动条被样式化成了粉色——就像我想要的那样。我们修改了插件开发者提供的 CSS，使滚动条的外观符合我们的要求。我们能够使用浏览器内置的开发者工具来定位需要更新的代码的文件和行号，以改变滚动条的外观。

## 试试吧，勇士——按照你想要的样式设计滚动条

现在，也许你不喜欢鲜艳的粉红色滚动条，你可能会觉得我的示例有点平淡，你是对的。但是你可以创造性地使用背景颜色、渐变、图片、圆角等来设计你喜欢的滚动条样式。你可以模仿你喜欢的操作系统的滚动条，让你的所有网站访客都能看到你喜欢的样式，或者你可以创建一个全新的样式。尝试使用 CSS 来创建自己的滚动条样式。

# 平滑滚动

jScrollPane 是一个成熟且功能齐全的插件。如果你浏览示例和文档，你会发现各种有趣的选项可供使用。我将带你设置其中一个我最喜欢的功能：可滚动区域内的动画滚动。

# 行动时间 —— 设置平滑滚动

你可以将任何类型的内容放在可滚动区域内——新闻故事列表、照片画廊，或者是一篇包含几个部分、标题和副标题的长文章。下面是如何设置控件以平滑滚动到另一节的方法：

1.  我们需要做的第一件事是为我们的每个段落分配一个 ID。我在可滚动区域中有五个 lorem ipsum 段落，所以我将它们分配为`para1, para2, para3, para4`和`para5`的`ids`。你可以选择任何你喜欢的`ids`，但请记住，`id`不能以数字开头。所以现在我的代码看起来像这样（我已经截断了文本以节省空间）：

    ```js
    <div id="scrolling">
    <p id="para1">Lorem ipsum...</p>
    <p id="para2">...</p>
    <p id="para3">...</p>
    <p id="para4">...</p>
    <p id="para5">...</p>
    </div>

    ```

1.  现在，让我们在可滚动区域上方添加一些内部链接，以跳转到每个段落。在标题之后和可滚动区域之前，添加以下代码：

    ```js
    <h2>We don't want this box of content to get too long, so we'll make it scroll:</h2>
    <p>Scroll to a paragraph:
    <a href="#para1">1</a>,
    <a href="#para2">2</a>,
    <a href="#para3">3</a>,
    <a href="#para4">4</a>,
    <a href="#para5">5</a>
    </p>
    <div id="scrolling">

    ```

1.  如果我们禁用了 JavaScript，这些链接也可以工作；它们会将可滚动区域滚动到相关的段落，使其对我们的网站访客可见。但我们希望它们与我们的花哨自定义滚动条一起工作。因此，我们只需向 jScrollPane 方法传递一个新选项：

    ```js
    $(document).ready(function(){
    $('#scrolling').jScrollPane({
    showArrows: true,
    verticalGutter: 30,
    hijackInternalLinks: true
    });
    });

    ```

    这个新选项是为了阻止浏览器在点击内部链接时尝试其默认行为。刷新页面，然后尝试点击段落的链接。

1.  它可以运行，但并不完美，当可滚动区域突然跳动时可能会让人感到不安——我们的网站访客可能不会完全意识到发生了什么。让我们通过平滑地动画化跳转到不同的段落来明显地展现出来。我们只需在代码中添加另一个选项：

    ```js
    $(document).ready(function(){
    $('#scrolling').jScrollPane({
    showArrows: true,
    verticalGutter: 30,
    hijackInternalLinks: true,
    animateScroll: true
    });
    });

    ```

    现在，当你刷新页面并点击段落链接时，你会发现可滚动区域平滑滚动到正确的段落。很容易理解发生了什么，你在页面上和可滚动区域中的位置。

## 刚刚发生了什么？

我们利用了 jScrollPane 插件的一个功能，并使得在可滚动容器内平滑滚动到任何内容成为可能。我们可以使用的选项和值都在插件的文档和示例中有所说明。由于插件作者在使艰难的事情变得容易方面的努力工作，你可以看到我们有多么容易地定制了这个插件来添加这种良好的行为。

# 总结

哦，这一章真是够繁重的。我们学到了关于 jQuery 插件的知识，如何使用它们，以及如何使用它们提供的选项来定制它们。我们了解了依赖关系，并按正确的顺序将多个脚本插入到我们的文件中。我们使用了 Kelvin Luck 的出色 jScrollPane 插件，将我们无聊的操作系统滚动条替换为我们自己设计的花哨的自定义滚动条。而且，好处是，它们的工作方式与浏览器的滚动条完全相同，我们的网站访问者可以点击轨道，点击上下按钮，他们可以拖动手柄，或者使用鼠标滚轮在我们设置的可滚动区域上下导航。这既提升了美观性又提高了可用性。

最后，我们学会了如何在可滚动区域内平稳滚动至锚点，这样我们的网站访问者就可以轻松地进入可滚动区域内的各个内容片段，并清楚地传达了正在发生的事情。

接下来，我们将看看如何用我们自己设计的漂亮工具提示覆盖浏览器的默认工具提示，并学习如何通过添加额外内容使它们更加有效。


# 第五章：制作自定义工具提示

> 现在我们已经看到插件有多强大以及它们如何轻松地实现高级功能，让我们看看如何利用另一个插件来制作自定义工具提示。
> 
> 当您包含`title`属性时，浏览器会自动创建工具提示 —— 通常在链接或图像上。当您的网站访客将鼠标悬停在该项上或通过按 Tab 键将焦点移到该项上时，工具提示将显示 —— 通常为一个看起来悬浮在页面上的小黄色框。工具提示是向页面添加一些附加信息的好方法。屏幕阅读器软件会为使用辅助技术的残障网站访客朗读出工具提示文本，从而增强可访问性。此外，图像和链接上的`title`属性可以帮助搜索引擎更有效地索引您的内容。

在本章中，我们将学习:

+   如何使用克雷格·汤普森的 qTip 插件来替换浏览器的默认工具提示

+   如何自定义 qTip 工具提示的外观

+   如何通过自定义工具提示增强导航栏

+   如何在自定义工具提示中显示 Ajax 内容

# 简单的自定义文本工具提示

希望我已经说服了你，`title` 属性对于增强网站的可用性和可访问性都很棒。工具提示的唯一问题是它们无法以任何方式定制。每个浏览器都有自己的工具提示样式，并且这种样式不能通过 CSS 定制。有时这没关系，但有时控制工具提示的外观会更好。

# 行动时间 — 简单文本工具提示

我们将通过制作一个简单的替代浏览器默认工具提示的工具提示来开始工作，我们可以自定义样式:

1.  设置一个基本的 HTML 文件以及像我们在第一章中所做的那样的相关文件和文件夹，*设计师，见 jQuery*。我们的 HTML 文件应包含一组链接，每个链接都有一个像这样的`title`属性:

    ```js
    <p>Here's a list of links:</p>
    <ul>
    <li><a href="home.html" title="An introduction to who we are and what we do">Home</a></li>
    <li><a href ="about.html" title="Learn more about our company">About</a></li>
    <li><a href="contact.html" title="Send us a message. We'd love to hear from you!">Contact</a></li>
    <li><a href="work.html" title="View a portfolio of the work we've done for our clients">Our Work</a></li>
    </ul>

    ```

1.  在浏览器中打开该页面，并将鼠标移动到链接上。您将看到`title`属性中包含的文本显示为工具提示。工具提示出现的位置和外观取决于您的浏览器，但以下是我的浏览器（Mac OS 上的 Google Chrome）中的外观:![行动时间 — 简单文本工具提示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709_05_01.jpg)

1.  现在，让我们将其美化一下，用我们自己的样式替换默认的浏览器工具提示。首先，我们需要下载克雷格·汤普森的 qTip 插件。可以从[`craigsworks.com/projects/qtip2`](http://craigsworks.com/projects/qtip2)获取。他的网站上列出了一些功能、几个示例演示、您需要学习使用插件的文档、一个可以获取帮助的论坛，并且所需的文件可供下载。转到下载页面，您将看到一个选项清单，帮助您下载正确的版本。

    让我们逐个部分地浏览此页面:

    ![操作时间 —— 简单文本工具提示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709_05_02.jpg)

1.  **第 1 步**为我们提供了多种下载脚本的选项。在标题为**版本**的部分，我将选择**稳定**版本，这样我就可以得到经过彻底测试的最新版本的脚本。那些想要在开发者开发插件时尝试和测试插件的人可以选择夜间版本。

1.  在**额外**部分，我将取消**jQuery 1.5**的选择，因为我已经下载了 jQuery 并将其附加到我的项目中。如果您正在启动一个新项目，并且还没有下载 jQuery，您可以将其选中以与插件同时下载 jQuery。

1.  在**样式**部分，我将保留所有三组样式选中，因为我希望尽可能多地选择样式来设置我的工具提示。同样，在**插件**部分，我将保留所有选项选中，因为我将会使用各种不同类型的工具提示，并利用这些不同的功能。如果你只想创建简单的基于文本的工具提示，你可以取消所有这些额外的选项，这样可以得到一个更小的下载文件。这些额外的功能只在你要利用额外功能时才需要。这个插件的一个很好的功能是，我们可以挑选我们想要的功能，以尽可能保持我们的 JavaScript 文件尽可能小。

1.  **第 2 步**为那些正在更新他们的代码，可能之前使用了插件的早期版本的任何人提供了一个自动转换器。由于我们是 qTip 插件的新手，所以我们可以忽略这一步。

1.  **第 3 步**为我们提供了一个机会，告诉插件开发者我们的网站使用了插件，并有机会被列入插件主页的画廊中。由于在本章节中我们只是做了一些练习，所以我们现在不会使用这个，但这可能是你以后在自己的项目中考虑的事情。

1.  **第 4 步**要求我们接受许可证的条款。该插件根据开源 MIT 和 GPLv2 许可证授权，这使得我们可以自由使用、修改甚至重新分发代码，只要在文件中包含许可证或链接到许可证。当您下载这些文件时，许可证已经包含在插件文件中了，所以只要您不编辑这些文件以删除许可证，您就不会有问题。

1.  最后，我们可以点击**下载 qTip**按钮，您的浏览器将为您下载一个 ZIP 文件。解压它并检查其内容。在内部，我们会找到两个 CSS 文件和两个 JavaScript 文件。（如果您选择同时下载 jQuery 和插件脚本，可能会有一个额外的 JavaScript 文件）。![操作时间 —— 简单文本工具提示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709_05_03.jpg)

1.  让我们从两个 CSS 文件开始。我们有`jquery.qtip.css`和`jquery.qtip.min.css`。这两个文件的内容完全相同。它们之间的区别在于第二个文件被缩小了，使其更小且更适合在生产中使用。另一个文件是开发版本，如果我们想要为我们的工具提示编写自己的样式而不是使用预构建的样式，我们可以轻松地编辑它或将其用作示例。您将选择其中一个文件并将其附加到您的页面上。在本示例中，为了使文件尽可能小，我将使用文件的经过缩小的版本，因为此时我不想编写自己的样式。将`jquery.qtip.min.css`复制到您自己的`styles`文件夹中，然后将文件附加到 HTML 文档的`<head>`部分：

    ```js
    <head>
    <title>Chapter 5: Creating Custom Tooltips</title>
    <link rel="stylesheet" href="styles/jquery.qtip.min.css"/>
    <link rel="stylesheet" href="styles/styles.css"/>
    </head>

    ```

    我将 qTip 样式表附加到自己的`styles.css`之前，这样如果需要，我就可以更轻松地覆盖 qTip 样式表中的样式。

1.  接下来，让我们看看 JavaScript 文件。我们有`jquery.qtip.js`和`jquery.qtip.min.js`。就像 CSS 文件一样，这是同一个文件的两个不同版本，我们只需选择一个并将其附加到我们的 HTML 文档即可。第一个文件`jquery.qtip.js`是文件的开发版本，大小为 94K，而第二个文件是经过缩小的，只有 41K。由于我们不需要编辑插件，而是要直接使用它，让我们选择经过缩小的版本。将`jquery.qtip.min.js`复制到您自己的`scripts`文件夹中，并将其附加到 HTML 文件底部，在 jQuery 和我们自己的`scripts.js`文件之间：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/jquery.qtip.min.js"></script>
    <script src="img/scripts.js"></script>
    </body>
    </html>

    ```

1.  我们需要做的最后一件事是调用插件代码。打开您的`scripts.js`文件并添加文档准备好的语句和函数：

    ```js
    $(document).ready(function(){
    });

    ```

1.  在函数内部，选择文档中所有具有`title`属性的链接，并在这些链接上调用`qtip()`方法：

    ```js
    $(document).ready(function(){
    $('a[title]').qtip();
    });

    ```

1.  现在，当您在浏览器中查看页面并将鼠标移动到具有`title`属性的链接上时，您将看到 qTip 样式的工具提示，而不是浏览器的默认工具提示：![操作时间 —— 简单文本工具提示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709_05_04.jpg)

+   更好的是，无论我们使用哪个浏览器和操作系统，这些工具提示都会以相同的样式显示。

## 刚才发生了什么？

我们下载了 qTip 插件并将一个 CSS 文件和一个 JavaScript 文件附加到我们的 HTML 文档中。然后我们只添加了几行 jQuery 代码来激活自定义工具提示。

我们选择了页面上所有具有`title`属性的链接元素。我们利用了 jQuery 的属性选择器来实现这一点：

```js
$('a[title]')

```

在我们的元素选择器后面加上`title`括号意味着我们只想要页面上具有`title`属性的链接。

一旦我们选择了这些链接，剩下的就是调用 qTip 插件为我们提供的`qtip()`方法了。`qtip()`方法会处理所有需要做的动作，以替换默认的工具提示为自定义的工具提示。但是如果我们想使用 qTip 配备的其他样式呢？

# 自定义 qTip 的外观

毫无疑问，当鼠标悬停在链接上时，qTip 的左上角与链接的右下角对齐，工具提示显示为黄色方框并且侧边有一个小箭头。qTip 插件提供了很多选项来定制工具提示的位置和外观，而且使用起来直观而易懂。

# 实战任务 — 自定义 qTips

让我们来看一下我们对自定义 qTip 工具提示外观的选项：

1.  假设我们想改变工具提示的位置。qTip 为我们在页面上定位工具提示提供了很多选项。

1.  我们可以把工具提示的任何一个点与链接的任何一个点匹配起来：![实战任务 — 自定义 qTips](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709_05_05.jpg)

1.  在这个例子中，我们将把链接右侧的中间和工具提示左侧的中间匹配起来，这样工具提示就会直接出现在链接的右侧。我们只需要向`qTip()`方法传递一些额外的信息。我们将继续使用上一个例子中设置的文件。打开你的`scripts.js`文件，并将这些额外的信息传递给`qtip()`方法：

    ```js
    $('a[title]').qtip({
    position: {
    my: 'center left',
    at: 'center right'
    }
    });

    ```

    开发人员的目标是使之用通俗的语言来解释。从工具提示的角度来说，我们将把我的中心左侧与链接的中心右侧对齐。当我们在浏览器中刷新页面时，你会看到工具提示现在直接出现在链接的右侧。

    ![实战任务 — 自定义 qTips](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709_05_06.jpg)

1.  除了改变工具提示的位置，我们还可以改变工具提示本身的外观。插件中包含的 CSS 包括几种颜色方案和样式。通过向我们的工具提示添加 CSS 类，可以应用不同的颜色和样式。让我们看看如何添加这些 CSS 类。

    ```js
    $('a[title]').qtip({
    position: {
    my: 'center left',
    at: 'center right'
    },
    style: {
    classes: 'ui-tooltip-blue'
    }
    });

    ```

    现在当我们在浏览器中查看工具提示时，我们发现它是蓝色的:

    ![实战任务 — 自定义 qTips](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709_05_07.jpg)

1.  qTip 提供的颜色方案包括:

    +   `ui-tooltip`（默认的黄色方案）

    +   `ui-tooltip-light`（在白色工具提示上的黑色文字）

    +   `ui-tooltip-dark`（在深灰色工具提示上的白色文字）

    +   `ui-tooltip-red`

    +   `ui-tooltip-green`

    +   `ui-tooltip-blue`

        你可以将这些类中的任意一个添加到你的工具提示中，以调整颜色方案。

1.  对于支持 CSS3 的浏览器，qTip 还提供了一些更花哨的样式。这些样式在不支持 CSS3 规范的浏览器中看不到，但在大多数情况下，这应该没问题。这些样式可以被视为对能够显示它们的浏览器的渐进增强。使用较低版本浏览器的网站访问者仍然可以看到和阅读提示，没有任何问题。他们只是看不到应用了更花哨的样式。可用的样式如下所示：![操作时间 — 自定义 qTips](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709_05_08.jpg)

1.  与配色方案一样，我们可以通过向提示添加 CSS 类来利用这些样式。可以像这样向提示添加多个 CSS 类：

    ```js
    $('a[title]').qtip({
    position: {
    my: 'center left',
    at: 'center right'
    },
    style: {
    classes: 'ui-tooltip-blue ui-tooltip-shadow'
    }
    });

    ```

    此代码创建了一个蓝色带阴影的提示。

## 刚才发生了什么？

我们看到了如何将位置和样式值传递给 qTip 方法以自定义我们的提示外观。我们了解了 qTip 插件包含的颜色方案和样式，并学会了如何在我们自己的页面中使用这些样式来自定义 qTip 提示。

# 提示的自定义样式

如果没有任何可用选项完全适合我们的站点，我们还可以编写自己的颜色方案和样式。

# 操作时间 — 编写自定义提示样式

让我们看看如何编写我们自己的 qTip 提示的自定义样式，编写一个新的紫色配色方案：

1.  我们将开始检查编码了红色提示样式的 CSS，这是 qTip 自带的。你会在随 qTip 下载的 `jquery.qtip.css` 文件中找到这段 CSS。以下是影响红色提示的所有 CSS 样式：

    ```js
    /*! Red tooltip style */
    .ui-tooltip-red .ui-tooltip-titlebar,
    .ui-tooltip-red .ui-tooltip-content{
    border-color: #D95252;
    color: #912323;
    }
    .ui-tooltip-red .ui-tooltip-content{
    background-color: #F78B83;
    }
    .ui-tooltip-red .ui-tooltip-titlebar{
    background-color: #F06D65;
    }
    .ui-tooltip-red .ui-state-default .ui-tooltip-icon{
    background-position: -102px 0;
    }
    .ui-tooltip-red .ui-tooltip-icon{
    border-color: #D95252;
    }
    .ui-tooltip-red .ui-tooltip-titlebar .ui-state-hover{
    border-color: #D95252;
    }

    ```

1.  通过检查这段 CSS，我们可以看到要创建新的颜色方案，我们只需要创建一个新的类名和四种紫色色调来创建新的样式。这是我的紫色配色方案的 CSS。打开你的 `styles.css` 文件并添加这些样式：

    ```js
    /*! Purple tooltip style */
    .ui-tooltip-purple .ui-tooltip-titlebar,
    .ui-tooltip-purple .ui-tooltip-content{
    border-color: #c1c3e6;
    color: #545aba;
    }
    .ui-tooltip-purple .ui-tooltip-content{
    background-color: #f1f2fa;
    }
    .ui-tooltip-purple .ui-tooltip-titlebar{
    background-color: #d9daf0;
    }
    .ui-tooltip-purple .ui-state-default .ui-tooltip-icon{
    background-position: -102px 0;
    }
    .ui-tooltip-purple .ui-tooltip-icon{
    border-color: #c1c3e6;
    }
    .ui-tooltip-purple .ui-tooltip-titlebar .ui-state-hover{
    border-color: #c1c3e6;
    }

    ```

1.  现在，要利用我们的新紫色提示样式，我们只需调整我们的 jQuery 代码，将新创建的 `ui-tooltip-purple` 类添加到我们的提示中。打开 `scripts.js` 文件并调整添加到提示中的类：

    ```js
    $('a[title]').qtip({
    position: {
    my: 'center left',
    at: 'center right'
    },
    style: {
    classes: 'ui-tooltip-purple'
    }
    });

    ```

    现在，在浏览器中预览链接时，你将看到一个紫色的提示，如下截图所示：

    ![操作时间 — 编写自定义提示样式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709_05_09.jpg)

## 刚才发生了什么？

使用 qTip 提供的一个 CSS 类，我们编写了自己的自定义样式并将其应用到了我们的提示中。你可以使用任何 CSS 样式来为 qTip 提示创建自定义外观。当你开始混合颜色和字体选择、背景图片、边框样式等时，几乎没有限制样式的可能性。

## 动手试试 — 创建自己设计的提示

尝试编写自己的 CSS 类来为提示样式。尝试新的配色方案、新的字体样式和大小、文字阴影、盒阴影 — 任何你能想到的，以使提示与网站设计相匹配或真正突出。

# 使用工具提示增强导航

一旦你知道如何制作自定义工具提示，你会发现它们有很多可能的用途。让我们看看如何使用 qTip 插件增强标准导航栏的自定义工具提示。

# 行动时间 —— 建立一个花哨的导航栏

让我们看看如何使用定制设计的工具提示为基本导航栏添加一些逐步增强的效果：

1.  让我们从设置一个带有关联文件夹和文件的基本 HTML 页面开始，就像我们在第一章中所做的一样，*Designer, Meet jQuery*。在文档的主体中，包含一个简单的导航栏，就像这样：

    ```js
    <ul id="navigation"> <li><a href="home.html" title="An introduction to who we are and what we do">Home</a></li>
    <li><a href ="about.html" title="Learn more about our company">About</a></li>
    <li><a href="contact.html" title="Send us a message. We'd love to hear from you!">Contact</a></li>
    <li><a href="work.html" title="View a portfolio of the work we've done for our clients">Our Work</a></li>
    </ul>

    ```

1.  接下来，我们将为我们的导航栏添加一些 CSS 样式。这里有很多 CSS，因为我正在使用渐变作为背景，而且目前不同的浏览器需要很多不同的 CSS。将这些 CSS 行添加到你的`styles.css`文件中。如果你喜欢不同的风格，请随意自定义 CSS 以适应你自己的口味：

    ```js
    #navigation {
    background: rgb(132,136,206); /* Old browsers */
    background: -moz-linear-gradient(top, rgba(132,136,206,1) 0%, rgba(72,79,181,1) 50%, rgba(132,136,206,1) 100%); /* FF3.6+ */
    background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,rgba(132,136,206,1)), color-stop(50%,rgba(72,79,181,1)), color-stop(100%,rgba(132,136,206,1))); /* Chrome,Safari4+ */
    background: -webkit-linear-gradient(top, rgba(132,136,206,1) 0%,rgba(72,79,181,1) 50%,rgba(132,136,206,1) 100%); /* Chrome10+,Safari5.1+ */
    background: -o-linear-gradient(top, rgba(132,136,206,1) 0%,rgba(72,79,181,1) 50%,rgba(132,136,206,1) 100%); /* Opera11.10+ */
    background: -ms-linear-gradient(top, rgba(132,136,206,1) 0%,rgba(72,79,181,1) 50%,rgba(132,136,206,1) 100%); /* IE10+ */
    filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#8488ce', endColorstr='#8488ce',GradientType=0 ); /* IE6-9 */
    background: linear-gradient(top, rgba(132,136,206,1) 0%,rgba(72,79,181,1) 50%,rgba(132,136,206,1) 100%); /* W3C */
    list-style-type: none;
    margin: 100px 20px 20px 20px;
    padding: 0;
    overflow: hidden;
    -webkit-border-radius: 5px;
    -moz-border-radius: 5px;
    border-radius: 5px;
    }
    #navigation li {
    margin: 0;
    padding: 0;
    display: block;
    float: left;
    border-right: 1px solid #4449a8;
    }
    #navigation a {
    color: #fff;
    border-right: 1px solid #8488ce;
    display: block;
    padding: 10px;
    }
    #navigation a:hover {
    background: #859900;
    border-right-color: #a3bb00;
    }

    ```

1.  现在我们的页面上有了一个水平的导航栏，就像这样：![行动时间 —— 建立一个花哨的导航栏](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709_05_10.jpg)

1.  我在我的链接上包含了`title`属性，当我将鼠标移动到导航链接上时，它们是可见的。我想用友好的对话框替换这些无聊的浏览器默认工具提示，在我的导航下方。

1.  就像我们在上一个例子中所做的那样，我们要复制 qTip 的 CSS 和 JavaScript 到我们自己的 styles 和 scripts 文件夹中，并将它们附加到 HTML 文档中：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
    <title>Chapter 5: Creating Custom Tooltips</title>
    <link rel="stylesheet" href="styles/jquery.qtip.min.css"/>
    <script src="img/jquery.js"></script>
    <script src="img/jquery.qtip.min.js"></script>
    <script src="img/scripts.js"></script>
    </body>
    </html>

    ```

1.  接下来，打开你的`scripts.js`文件，这样我们就可以调用`qtip()`方法并传递我们的自定义内容。我们将几乎像上次那样开始，只是我们将使用不同的选择器，因为我们只想选择导航栏内的链接：

    ```js
    $(document).ready(function(){
    $('#navigation a').qtip();
    });

    ```

    现在默认的工具提示已经被 qTip 样式的工具提示替换了。

1.  接下来，我们将为导航工具提示创建我们自己的样式，所以我们将编写一些新的 CSS 使它们看起来像对话框。将这些样式添加到你的`styles.css`文件中：

    ```js
    .ui-tooltip-conversation .ui-tooltip-titlebar,
    .ui-tooltip-conversation .ui-tooltip-content{
    border: 3px solid #555;
    filter: none; -ms-filter: none;
    }
    .ui-tooltip-conversation .ui-tooltip-titlebar{
    background: #859900;
    color: white;
    font-weight: normal;
    font-family: serif;
    border-bottom-width: 0;
    }
    .ui-tooltip-conversation .ui-tooltip-content{
    background-color: #F9F9F9;
    color: #859900;
    -moz-border-radius: 9px;
    -webkit-border-radius: 9px;
    border-radius: 9px;
    padding: 10px;
    }
    .ui-tooltip-conversation .ui-tooltip-icon{
    border: 2px solid #555;
    background: #859900;
    }
    .ui-tooltip-conversation .ui-tooltip-icon .ui-icon{
    background-color: #859900;
    color: #555;
    }

    ```

1.  现在我们已经准备好了新的工具提示 CSS 样式，我们只需将这个新类添加到工具提示中即可。回到`scripts.js`，并将新类添加到 JavaScript 中：

    ```js
    $('#navigation a').qtip({
    style: {
    classes: 'ui-tooltip-conversation'
    }
    });

    ```

1.  接下来，让我们将对话框定位到每个导航链接的下方。在`scripts.js`中，将位置信息传递给`qtip()`方法：

    ```js
    $('#navigation a').qtip({
    position: {
    my: 'top center',
    at: 'bottom center'
    },
    style: {
    classes: 'ui-tooltip-conversation',
    width: '150px'
    }
    });

    ```

1.  现在，我们需要控制工具提示的宽度，使其不要显得太宽。我们将宽度设置为 150px：

    ```js
    $('#navigation a').qtip({
    position: {
    my: 'top center',
    at: 'bottom center'
    },
    style: {
    classes: 'ui-tooltip-conversation',
    width: '150px'
    }
    });

    ```

1.  现在我们要做的最后一件事是改变工具提示从页面上出现和消失的方式。默认情况下，qTip 插件使用非常快速和微妙的淡入淡出效果。让我们改变一下，让工具提示滑入视图并滑出视图：

    ```js
    $('#navigation a').qtip({
    position: {
    my: 'top center',
    at: 'bottom center'
    },
     show: {
    effect: function(offset) {
    $(this).slideDown(300);
    }
    },
    hide: {
    effect: function(offset) {
    $(this).slideUp(100);
    }
    },
    style: {
    classes: 'ui-tooltip-conversation',

    width: '150px'
    }
    });

    ```

1.  现在当您在浏览器中查看页面时，您可以看到对话气泡在您将鼠标悬停在链接上时从下方滑入视图，并在您将鼠标移出链接时滑出视图。

## 刚刚发生了什么？

我们回顾了如何创建和附加自定义 CSS 样式到 qTip 的工具提示，以及如何定位工具提示在任何你想要的位置。我们还学会了如何控制工具提示的宽度，以确保我们得到统一的大小。

然后我们看到了如何覆盖默认的显示和隐藏行为，并用自定义动画替换它们。在这种情况下，我们使用了 jQuery 的 `slideDown()` 效果来显示工具提示。我们向 `slideDown()` 方法传递了一个值为 300，这意味着动画将花费 300 毫秒完成，或者大约三分之一秒。我发现如果动画持续时间超过这个时间，网站访客会因等待而感到不耐烦。

接下来，我们使用 jQuery 的 `slideUp()` 方法覆盖了默认的隐藏行为。我传递了一个值为 100，意味着动画将在大约十分之一秒内完成。当此动画运行时，网站访客已经决定继续前进，因此最好尽快将信息移出他们的视线。

# 在工具提示中显示其他内容

到目前为止，我们已经看到了如何自定义 qTip 工具提示的外观，控制它们的外观、动画和位置。然而，我们只是用工具提示来显示文本，即我们放置在链接的 `title` 属性中的文本。然而，我们有更强大的选项。我们可以加载几乎任何内容到我们的工具提示中。我们还可以确保当项目被点击而不是悬停在上面时出现工具提示。让我们看看当我们点击链接时如何将内容从另一个 HTML 页面加载到我们的工具提示中。

在本节中，我们将首次深入使用 Ajax。如果您不熟悉，**Ajax** 是一种从服务器获取一些新内容并将其显示给网站访问者的方法，而无需完全刷新页面。因为浏览器只是获取并显示网站访问者所需的那一部分信息，所以它通常会更快速、更敏捷。

在我们第一次深入 Ajax 之前，先简单说明一下。现代浏览器有很多对 Ajax 请求的安全规定。你不会像之前那样简单地在浏览器中查看你的 ajaxified HTML 文件。为了观看 Ajax 的操作，你要么必须将你的文件上传到服务器上，然后再查看它们，要么你必须在自己的电脑上搭建一个服务器。如果你是 Mac 用户，我强烈推荐使用**MAMP**，它有免费和高级付费版本。你可以从[`www.mamp.info`](http://www.mamp.info)获取更多信息并下载 MAMP。如果你使用 Windows，我强烈推荐使用**WampServer**，它是免费的。你可以从[`www.wampserver.com.`](http://www.wampserver.com.)获取更多信息并下载 WampServer。

# 行动时间 - 创建自定义 Ajax 工具提示

按照以下步骤设置一些显示 Ajax 内容的工具提示：

1.  我们将从创建一个 HTML 文档和相关文件夹和文件开始，就像我们在第一章 *设计师，遇见 jQuery*中所做的那样。我们的 HTML 页面应该包含一些段落文字，其中有一些链接指向更多信息。我的第一个 HTML 文档看起来如下：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
    <title>Pittsburgh, Pennsylvania</title>
    <link rel="stylesheet" href="styles/styles.css"/>
    </head>
    <body>
    <h2>Pittsburgh, Pennsylvania</h2>
    <p>Pittsburgh is the second-largest city in the US Commonwealth of Pennsylvania and the county seat of Allegheny County. Regionally, it anchors the largest urban area of Appalachia and the Ohio River Valley, and nationally, it is the 22nd-largest urban area in the United States. The population of the city in 2010 was 305,704 while that of the seven-county metropolitan area stood at 2,356,285\. <a href="http://infoboxes/downtown.html">Downtown Pittsburgh</a> retains substantial economic influence, ranking at 25th in the nation for jobs within the urban core and 6th in job density.</p>
    <p>The characteristic shape of Pittsburgh's central business district is a triangular tract carved by the confluence of the Allegheny and Monongahela rivers, which form the Ohio River. The city features 151 high-rise buildings, 446 bridges, two inclined railways, and a pre-revolutionary fortification. Pittsburgh is known colloquially as "The City of Bridges" and "The Steel City" for its <a href="http://infoboxes/bridges.html">many bridges</a> and former steel manufacturing base.</p>
    <p>The warmest month of the year in Pittsburgh is July, with a 24-hour average of 72.6&deg;F. Conditions are often humid, and combined with the 90&deg;F (occurring on an average of 8.4 days per annum), a considerable <a href="http://infoboxes/heatindex.html">heat index</a> arises.</p>
    <script src="img/jquery.js"></script>
    <script src="img/scripts.js"></script>
    </body>
    </html>

    ```

1.  我们需要一种轻松的方法来选择这三个更多信息链接，所以我们会像这样给每一个添加一个 CSS 类：

    ```js
    <a href ="http://infoboxes/downtown.html" class="infobox">Downtown Pittsburgh</a>

    ```

1.  接下来，我们需要创建一组简短的页面，每个页面中都包含一个链接和前文中链接的标题。以下是我其中一个简短 HTML 页面的示例：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
    <title>Downtown Pittsburgh</title>
    </head>
    <body>
    <img src="img/downtown.jpg"/>
    <p>Downtown Pittsburgh</p>
    </body>
    </html>

    ```

    如你所见，文件非常小而简单。

1.  在主页旁边创建一个`infoboxes`目录。将你的简单 HTML 文件保存到这个目录中，并为主文档中的每个链接创建更多的简单文件。

1.  现在，如果你在浏览器中打开主页并点击文本中的链接，你会发现这些简短而普通的页面加载到了浏览器中。我们已经掌握了基本功能，接下来我们将逐步增强页面功能，以满足那些启用了 JavaScript 的用户。

1.  我们将使用在本章前面设置的紫色配色方案来为我们的工具提示添加 CSS，所以让我们把`ui-tooltip-purple`类的 CSS 添加到`styles.css`文件中：

    ```js
    /*! Purple tooltip style */
    .ui-tooltip-purple .ui-tooltip-titlebar,
    .ui-tooltip-purple .ui-tooltip-content{
    border-color: #c1c3e6;
    color: #545aba;
    }
    .ui-tooltip-purple .ui-tooltip-content{
    background-color: #f1f2fa;
    }
    .ui-tooltip-purple .ui-tooltip-titlebar{
    background-color: #d9daf0;
    }
    .ui-tooltip-purple .ui-state-default .ui-tooltip-icon{
    background-position: -102px 0;
    }
    .ui-tooltip-purple .ui-tooltip-icon{
    border-color: #c1c3e6;
    }
    .ui-tooltip-purple .ui-tooltip-titlebar .ui-state-hover{
    border-color: #c1c3e6;
    }

    ```

1.  现在我们已经设置好了 HTML 和 CSS，让我们开始学习 JavaScript。在页面底部，介于 jQuery 和你的`scripts.js`文件之间，添加 qTip 插件：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/jquery.qtip.min.js"></script>
    <script src="img/js"></script>
    </body>
    </html>

    ```

1.  接下来，打开`scripts.js`，我们将开始使用我们的文档就绪功能：

    ```js
    $(document).ready(function(){
    });

    ```

1.  接下来，我们将以与以往略有不同的方式调用`qtip()`方法。在`qtip()`方法内部，我们需要轻松地获取与我们正在处理的链接相关的信息，因此我们将使用 jQuery 的`each()`方法逐个循环处理它们。代码如下：

    ```js
    $(document).ready(function(){
    $('a.infobox').each(function(){
    $(this).qtip()
    });
    });

    ```

1.  现在，如果你在浏览器中刷新页面，你会发现当你悬停在链接上时什么也不会发生。这是因为我们的链接没有`title`属性，默认情况下 qTip 插件正在寻找它。然而，我们可以覆盖默认值，插入我们想要的任何内容到我们的工具提示中。

1.  我们将在工具提示中显示我们设置的简单 HTML 页面。尽管 Ajax 请求往往很快，但仍可能会有一些延迟，所以让我们准备使用 Ajax，在我们的站点访问者等待真正的内容显示时显示一个加载消息：

    ```js
    $(document).ready(function(){
    $('a.infobox').each(function(){
    $(this).qtip({
    content: {
    text: 'Loading...'
    }
    });
    })
    });

    ```

    现在，当你在浏览器中刷新页面时，你会发现工具提示包含**正在加载...**的文本。

1.  我们希望改变工具提示的行为，使其在点击链接时显示，而不是在鼠标悬停时显示。我们还希望确保页面上一次只能看到一个工具提示。如果站点访问者在另一个工具提示已经打开的情况下打开了一个工具提示，第一个工具提示应该关闭，以免他们在屏幕上到处打开许多工具提示。我们将这样做：

    ```js
    $(document).ready(function(){
    $('a.infobox').each(function(){
    $(this).qtip({
    content: {
    text: 'Loading...'
    },
    show: {
    event: 'click',
    solo: true
    },
    });
    })
    });

    ```

1.  现在，如果你在浏览器中刷新页面，你会发现当我们悬停在链接上时工具提示不再出现了。

1.  但是，当我们现在点击链接时，我们被带到了我们设置的简单的 HTML 页面。我们必须告诉浏览器忽略这个链接，因为我们有其他计划。我们可以通过在我们早期的代码之上并在文档就绪语句内添加这一行代码来取消默认行为：

    ```js
    $(document).ready(function(){
    $('a.infobox').bind('click', function(e){e.preventDefault()});
    $('a.infobox').each(function(){

    ```

1.  我们在这里做的是绑定一个在链接被点击时触发的函数。我们的函数很简单。我们将当前链接传递给函数（在这种情况下是 e，为了简洁起见，但我们几乎可以将其命名为任何东西），然后告诉浏览器阻止默认链接行为。

    现在，如果你在浏览器中刷新页面，你会发现当我们点击链接时工具提示出现了 —— 点击链接不再将我们带到新页面。

1.  但是我们可以用更简洁的方式编写我们的代码。记住，jQuery 允许我们链式调用方法，一个接一个。在这种情况下，我们可以直接将`bind()`方法链到我们之前编写的`each()`方法的末尾。新的 JavaScript 代码将如下所示：

    ```js
    $(document).ready(function(){
    $('a.infobox').each(function(){
    $(this).qtip({
    content: {
    text: 'Loading...'
    },
    show: {
    event: 'click',
    solo: true
    },
    });
    }).bind('click', function(e){e.preventDefault()});
    });

    ```

1.  接下来，让我们通过添加阴影和应用我们为工具提示编写的紫色配色方案来调整工具提示的样式：

    ```js
    $(document).ready(function(){
    $('a.infobox').each(function(){
    $(this).qtip({
    content: {
    text: 'Loading...',
    },
    show: {
    event: 'click',
    solo: true
    },
    style: {
    classes: 'ui-tooltip-purple ui-tooltip-shadow'
    }
    });
    }).bind('click', function(e){e.preventDefault();});
    });

    ```

    现在，当你在浏览器中刷新页面时，你会发现我们有紫色的工具提示，带有阴影。我们离目标越来越近了。

1.  接下来，让我们加入 Ajax 魔法，将我们的简单 HTML 页面加载到工具提示中。请记住，这只能从服务器上运行，所以要看到这一步的效果，你要么必须将文件上传到服务器上，要么在自己的计算机上设置一个服务器。

    要通知工具提示通过 Ajax 获取内容，我们只需要传递我们想要获取的内容的 URL。在这种情况下，我们已经链接到了那个内容。我们只需要从每个链接中获取链接 URL。我们可以通过使用 jQuery 的 `attr()` 方法很容易地获取到这个 URL。代码如下：

    ```js
    $(this).attr('href')

    ```

    在这种情况下，`$(this)` 指的是当前链接。我调用 `attr()` 方法，并传递我想要获取的属性，在这种情况下，链接的 `href` 属性包含了我想要的信息。`attr()` 方法可以用于获取任何属性——图像的 `src` 属性，任何元素的 `title` 属性，表格的 `cellspacing` 属性，等等：

    ```js
    $('img').attr('src')
    $('p').attr('title')
    $('table').attr('cellspacing')

    ```

1.  现在我们知道如何获取我们链接的 `href` 属性，我们将使用它来告诉工具提示要使用哪个 URL 来获取工具提示的内容：

    ```js
    $(document).ready(function(){
    $('a.infobox').each(function(){
    $(this).qtip({
    content: {
    text: 'Loading...',
    ajax: {
    url: $(this).attr('href')
    }
    },
    show: {
    event: 'click',
    solo: true
    },
    style: {
    classes: 'ui-tooltip-purple ui-tooltip-shadow'
    }
    });
    }).bind('click', function(e){e.preventDefault()});
    });

    ```

1.  刷新浏览器，然后点击其中一个链接——你会看到紫色的工具提示弹出，显示我们简单的 HTML 页面中的 HTML 内容。使用 Ajax 获取内容是如此简单，是不是很惊人？

    现在，让我们对工具提示进行一些其他最后的调整，使它们变得更好。

1.  首先，我们将为工具提示添加一个标题栏。为了获得一些自定义文本，让我们回到 `index.html` 文件中的每个链接，并添加一个包含要在工具提示顶部显示的文本的 `title` 属性：

    ```js
    <a href ="http://infoboxes/downtown.html" class="infobox" title="Downtown Pittsburgh">Downtown Pittsburgh</a>
    ...
    <a href ="http://infoboxes/bridges.html" class="infobox" title="Pittsburgh Bridges">many bridges</a>
    <a href ="http://infoboxes/heatindex.html" class="infobox" title="Beating the Heat">heat index</a>

    ```

1.  现在，我们可以以类似的方式获取这些链接的 `title` 属性，就像我们获取了 `href` 属性的 URL 一样，并将其传递给 qTip 作为工具提示的标题文本。顺便说一下，我们还可以为 button 传递一个 `true` 值，以在工具提示的右上角显示一个小的关闭按钮：

    ```js
    $(document).ready(function(){
    $('a.infobox').each(function(){
    $(this).qtip({
    content: {
    text: 'Loading...',
    ajax: {
    url: $(this).attr('href')
    },
    title: {
    text: $(this).attr('title'), button: true
    }
    },
    show: {
    event: 'click',
    solo: true
    },
    style: {
    classes: 'ui-tooltip-purple ui-tooltip-shadow'
    }
    });
    }).bind('click', function(e){e.preventDefault()});
    });

    ```

    现在当你刷新浏览器，你会看到每个工具提示顶部会出现一个带有关闭按钮的较深色标题栏。

1.  但是，如果你试图移动鼠标点击关闭按钮时，你会看到工具提示在你到达之前就消失了。我们将工具提示的显示值改为在点击时显示而不是鼠标悬停时显示，但我们从未改变隐藏值——当我们移开鼠标离开链接时，工具提示仍然被隐藏。这有点尴尬，所以我将隐藏值改为`unfocus`，这样当链接失去焦点或网站访问者单击工具提示的关闭按钮时，工具提示将被隐藏：

    ```js
    $(document).ready(function(){
    $('a.infobox').each(function(){
    $(this).qtip({
    content: {
    text: 'Loading...',
    ajax: {
    url: $(this).attr('href')
    },
    title: {
    text: $(this).attr('title'),
    button: true
    }
    },
    show: {
    event: 'click',
    solo: true
    },
    hide: 'unfocus',
    style: {
    classes: 'ui-tooltip-purple ui-tooltip-shadow'
    }
    });
    }).bind('click', function(e){e.preventDefault()});
    });

    ```

1.  刷新浏览器，你会发现交互现在好多了。我们网站的访问者不必小心将鼠标悬停在链接上以查看工具提示内的内容。而且我们的工具提示仍然容易移除——网站访问者可以点击关闭按钮，或者在页面上工具提示外的任何地方单击，工具提示就会隐藏起来。

1.  现在，只剩下一件事要做，那就是将工具提示定位到我们希望它们出现的位置。我希望我的工具提示在链接下方居中显示，所以我将工具提示的顶部中心与链接的底部中心对齐：

    ```js
    $(document).ready(function(){
    $('a.infobox').each(function(){
    $(this).qtip({
    content: {
    text: 'Loading...',
    ajax: {
    url: $(this).attr('href')
    },
    title: {
    text: $(this).attr('title'),
    button: true
    }
    },
    position: {
    my: 'top center',
    at: 'bottom center'
    },
    show: {
    event: 'click',
    solo: true
    },
    hide: 'unfocus',
    style: {
    classes: 'ui-tooltip-purple ui-tooltip-shadow'
    }
    });
    }).bind('click', function(e){e.preventDefault()});
    });

    ```

    现在，如果你在浏览器中刷新页面并点击链接，你会看到工具提示从默认位置滑动到指定位置。

1.  我们的工具提示看起来不错，但我们仍然有一些问题。一个问题是工具提示从底角到中间位置的动画有点分散注意力。为了解决这个问题，让我们将 `effect` 值设置为 `false`。这样工具提示将直接出现在应该出现的位置，而不会有滑动到指定位置的动画效果。另一个问题是，根据浏览器窗口的大小，有时工具提示会被裁剪并显示在屏幕区域之外。为了确保这种情况不会发生，我们将 `viewport` 值设置为窗口，如下所示：

    ```js
    $(document).ready(function(){
    $('a.infobox').each(function(){
    $(this).qtip({
    content: {
    text: 'Loading...',
    ajax: {
    url: $(this).attr('href')
    },
    title: {
    text: $(this).attr('title'),
    button: true
    }
    },
    position: {
    my: 'top center',
    at: 'bottom center',
    effect: false,
    viewport: $(window)
    },
    show: {
    event: 'click',
    solo: true
    },
    hide: 'unfocus',
    style: {
    classes: 'ui-tooltip-purple ui-tooltip-shadow'
    }
    });
    }).bind('click', function(e){e.preventDefault()});
    });

    ```

1.  现在当你在浏览器中重新加载页面时，如果可能的话，工具提示将显示在链接下方的中心位置，但如果这会使其超出窗口区域，则工具提示将调整其位置以确保在与链接相关的最佳位置显示。我们失去了对工具提示出现位置的一些控制，但我们可以确保我们的网站访问者始终能够看到工具提示的内容，这更重要。

![行动时间 — 构建自定义 Ajax 工具提示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709_05_11.jpg)

# 摘要

在本章中，我们涵盖了很多内容。我们学习了如何使用 qTip 插件来替换浏览器默认的工具提示为自定义设计的工具提示。我们看到如何通过在导航栏中添加气泡工具提示来进一步定制化。最后，我们使用 Ajax 来拉取一些外部内容，不仅定制了工具提示的外观，还拉取了自定义内容，添加了标题栏和关闭按钮，确保工具提示始终可见，并定制了工具提示的显示和隐藏行为。我希望你能看到 qTip 插件有多灵活，以及它除了定制工具提示外还有多种用途。愿你在尝试插件文档中列出的所有不同设置时玩得开心，并发挥你在定制工具提示外观方面的创意。

接下来，我们将看看如何创建设计精美且动画效果出色的下拉式导航菜单。
