# WordPress3 和 jQuery（一）

> 原文：[`zh.annas-archive.org/md5/5EB3887BDFDDB364C2173BCD8CEFADC8`](https://zh.annas-archive.org/md5/5EB3887BDFDDB364C2173BCD8CEFADC8)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

这本易于使用的指南将带领您深入了解创建精致的专业增强功能的方方面面，特别定制以充分利用 WordPress 个人发布平台的优势。它将通过清晰的、逐步的说明，指导您构建几种针对不同类型的假想客户的自定义 jQuery 解决方案，并向您展示如何创建一个 jQuery 和 WordPress 插件。

# 本书涵盖内容

*第一章*, *入门：WordPress 和 jQuery*...本章向读者介绍了他们需要熟悉的核心基础知识，以便充分利用本书。涵盖了 HTML、CSS、PHP 和 JavaScript 的语法，以及如何识别这些语法的各个部分，还有一份“行业工具”清单，涵盖了他们的代码编辑器、浏览器甚至图像编辑器应具备的功能。本章还详细说明了 CSS、JavaScript 和 jQuery 如何在浏览器中与从 WordPress 站点提供的 HTML 配合使用。

*第二章*, *在 WordPress 中使用 jQuery*...本章详细介绍了如何在 WordPress 中开始使用 jQuery。它涵盖了如何使用脚本 API 正确地包含 jQuery，并专注于 jQuery 的选择器（在 WordPress 中非常重要），以及 jQuery 的顶级功能。

*第三章*, *深入了解 jQuery 和 WordPress*...本章将读者带入更深层次，介绍了 jQuery 可以应用于 WordPress 站点的各种方式：通过 WordPress 主题中的自定义脚本，作为通过主题调用的 jQuery 插件，以及作为应用于 WordPress 插件的自定义 jQuery 脚本或插件！通过 jQuery 影响 WordPress 站点的方法有很多，本章考虑了每种方法的利弊，以便读者能够准确评估自己的项目。本章还向读者介绍了他们的第一个“假想客户”，并介绍了如何创建自己的 jQuery 插件，然后将该 jQuery 插件封装成 WordPress 插件，以便站点管理员可以轻松实施增强功能，而不必知道如何编辑主题。

*第四章*, *用更少的代码做更多事情: 利用 jQuery 和 WordPress 的插件*...你以为你在 第三章 中学到了不少？抓住你的鼠标。你将开始一个小项目，需要你熟悉流行的 jQuery 插件 Colorbox，以及流行的 WordPress 插件 Cforms II，并且将两者与你自己的自定义 jQuery 魔术融合在一起，以制作一些漂亮的事件注册，会让客户大吃一惊。

*第五章*, *在 WordPress 中使用 jQuery 动画*...如果你要使用 jQuery，最好真正充分利用它，这意味着动画。本章介绍了使用 jQuery 的动画函数和快捷方式来创建一些锐利、精确的视觉增强效果，吸引网站用户的注意力，以及创建一个超级流畅的导航增强和一个精彩的旋转幻灯片展示粘性帖子。

*第六章*, *WordPress 和 jQuery 的 UI*...现在我们已经掌握了一些动画技巧，我们可以通过使用 jQuery 的 UI 插件来更轻松地进行工作，该插件包括我们在 第五章 中学到的 Easing 和 Color 插件。在本章中，我们还将利用 UI 插件的小部件和事件功能，在我们的 WordPress 站点中创建一些非常有用的界面。

*第七章*, *使用 jQuery 和 WordPress 进行 AJAX*...本章介绍了什么是 AJAX，以及在您的 WordPress 站点中开始使用 AJAX 技术的最佳方法；您将加载来自站点其他页面的 HTML，通过 JSON 获取您的推文和喜爱的 flickr 图片，并且 last but not least，自定义 AJAXing 内置的 WordPress 评论表单。

*第八章*, *使用 jQuery 和 WordPress 的技巧和诀窍*...本章介绍了在 WordPress 中充分利用 jQuery 的顶级技巧和诀窍。大多数这些最佳实践都在整个标题中涵盖，但在本章中，我们将看看它们为什么如此重要，特别是在 WordPress 的环境中如何实现它们。

*附录 A*，*jQuery 和 WordPress 参考指南*……将此附录折角，并将其视为您的“备忘单”。一旦您通过本书，为什么要浪费时间来回翻阅，以回忆某个功能的语法及其参数？本书提取了关于 jQuery 和 WordPress 的最重要信息，并将其拆分成易于快速浏览的参考指南，以便您可以轻松找到大多数 jQuery 选择器的语法，提醒自己关于大多数 WordPress 开发所需的顶级 jQuery 函数及其参数，以及有用的 WordPress 模板标记和 API 函数以及其他有用的 WordPress 技巧，如结构化循环和主题模板层次结构。

# 本书所需材料

+   WordPress（2.9.2 或 3.0）

+   jQuery 库（1.4.2）

+   Web 服务器（本地 WAMP 或 MAMP 安装或由提供商托管）

+   一个 Web 浏览器（Firefox 或更好）

+   一个好的代码或 HTML 编辑器

# 本书适合谁

本书适用于任何有兴趣在 WordPress 网站中使用 jQuery 的人。假定大多数读者将是具有相当了解 PHP 或 JavaScript 编程并且至少具有 HTML/CSS 开发经验的 WordPress 开发人员，他们想要学习如何快速将 jQuery 应用于他们的 WordPress 项目。

# 约定

在本书中，您将找到一些区分不同类型信息的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词如下所示：“我们可以通过使用`include`指令来包含其他上下文。”

代码块设置如下：

```js
<script type="text/javascript">
jQuery("document").ready(function(){
jQuery("p").css("background-color", "#ff6600");
});
</script>

```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```js
<script type="text/javascript">
jQuery("document").ready(function(){
jQuery("p").css("background-color", "#ff6600");
});
</script>

```

为了清晰和简洁，本标题中的许多代码示例都是提取的。提取的代码块设置如下：

```js
...
jQuery("p").css("background-color", "#ff6600");
}
...

```

前后用省略号“…”标记的代码和标记是从完整代码和/或更大代码和标记主体中提取的。请参考可下载的代码包以查看整个作品。

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，会出现在文本中，如下所示：“单击**下一步**按钮将您移到下一个屏幕”。

### 注意

警告或重要说明以这样的框出现。

### 注意

提示和技巧显示如下。


# 第一章：入门：WordPress 和 jQuery

欢迎来到 WordPress 和 jQuery。WordPress 网络发布平台和 jQuery 的 JavaScript 库是当今网络上使用最广泛的两个强大工具之一。将这些工具结合在一起，可以使您的网站的功能和灵活性加倍。这两种技术都易于学习和有趣，可以创造出网络魔法的秘诀。我希望您准备好通过学习 jQuery 如何改善您的 WordPress 开发经验，获得一些有趣和有趣的见解。

在本章中，我们将涵盖以下主题：

+   本书的方法和您应该了解的核心 JavaScript 语言和 WordPress 技能，以便从中获得最大优势

+   您将需要的基本软件工具来启动和运行您的项目

+   jQuery 和 WordPress 的基本概述

如果以下任何部分中的任何内容让您感到困惑，您可能需要更多的背景信息和理解，然后才能继续阅读本书。不过，别担心，我会为您指出一些更多信息的优秀来源。

# 本书的方法

本书介绍了使用 jQuery 与 WordPress 的基本原则和最佳实践。本书不是 JavaScript 和 PHP 编程的介绍，也不是使用 CSS 和 HTML 标记的入门指南。我假设您是 WordPress 网站开发人员和/或 WordPress 主题设计师。也许您只是一个花费足够多时间管理和调试 WordPress 网站的人，以至于您可能符合上述一种或两种角色。不管您如何标记自己，您都在使用 WordPress。WordPress 可以帮助您或您的客户快速简单地发布内容，而您总是在寻找更多、更快、更容易地完成任务的方法。

jQuery 是一个库，可以加速编写自定义 JavaScript 的时间并减少复杂性。我相信您一定知道 JavaScript 对网站有很多用处。它们还可以使网站具有非常酷的功能。虽然我将尽可能深入地介绍 jQuery，但我们不会将 jQuery 视为其他大多数书籍所强调的“重要”的 JavaScript 库实体。相反，我们将把 jQuery 视为一个能够帮助我们更轻松地完成更多工作（是的，用更少的代码）的伟大工具，使用 WordPress。

总结一下：那么，您是 WordPress 用户、开发人员还是设计师？太好了。让我们来看看这个名为 jQuery 的“工具”。它将使您的 WordPress 开发更加轻松，也可能看起来更加美观。准备好开始了吗？

# 您需要了解的核心基础知识

正如我所提到的，这本书是针对 WordPress 用户、视觉主题设计师和开发人员的，他们希望通过使用 jQuery 来学习如何更好地利用 WordPress。我尽力编写本书，以便明确要求客户端和服务器端脚本编写或编程经验并不是必需的。然而，您将至少会发现，对于给定主题的一般熟悉程度会有所帮助。

无论你的网络开发技能或水平如何，都会通过清晰的、一步一步的说明来引导你。让我们来看看你需要熟悉哪些网络开发技能和 WordPress 知识，以便从本书中获得最大的收益。再次强调，如果你觉得需要更多背景知识，我也会为你指引一些好的资源。

## WordPress

首先，你应该已经熟悉了最新、稳定版本的 WordPress。你应该了解如何在网络服务器上或本地计算机上安装和运行 WordPress 的基础知识（特别是因为你需要一个安装来尝试本书中的示例）。不用担心，我会指引你正确的方向，在你的 Mac 或 PC 上获得一个基本的本地 WordPress 安装。此外，许多托管提供商提供简单的一键安装。你需要查看你的托管提供商是否提供 WordPress。我还会指引你到一些其他好的 WordPress 安装资源。让 WordPress 安装和运行通常是使用 WordPress 的最简单的部分。

更深入地说，你需要熟悉 WordPress 管理面板。你需要了解如何向 WordPress 发布系统添加内容以及文章、分类、静态页面和子页面的工作原理。你还需要了解如何使用**媒体**上传工具向文章和页面添加图片，以及创建图库。最后，理解安装和使用不同主题和插件的基础知识也会有所帮助，虽然在本书中我们也会在一定程度上涵盖这些内容。

即使你将和更有技术的 WordPress 管理员一起工作，你也应该对你正在开发的 WordPress 网站有一个概述，以及项目所需的（如果有的话）主题或附加插件或小部件。如果你的网站确实需要特定的主题或附加插件和小部件，你需要在你的 WordPress 开发安装中准备好这些安装或已经安装好（或者**沙盒**——一个用于测试和玩耍而不会弄乱现场网站的地方）。

### 注意

**这本书使用哪个版本的 WordPress？**

本书重点介绍了 2.8、2.9 和 3.0 RC（在本书写作时的候选版本）中引入的新功能。本书涵盖的所有内容都在 WordPress 2.9.2 和 3.0 RC 中进行了测试和检查。尽管本书的案例研究是使用版本 2.9.2 和 3.0 RC 开发的，但任何更新版本的 WordPress 都应该具有相同的核心功能，使您能够使用这些技术来增强主题和插件与 jQuery。每个新版本的 WordPress 的错误修复和新功能都在[`WordPress.org`](http://WordPress.org)上有文档记录。

如果你完全是 WordPress 新手，那么我建议你阅读**April Hodge Silver**和**Hasin Hayder**的《WordPress 2.7 完全手册》。

## 基本编程

无论你了解任何客户端或服务器端语言的编程，都会对你有所帮助，无论是 JavaScript、VBScript、.NET、ASP、PHP、Python、Java、Ruby，你都会做得很好。当然，以下具体的语言也会帮助你。

### JavaScript 和 AJAX 技术

OK，你绝对不需要有任何与 AJAX 相关的经验。但如果你对 JavaScript 有一些了解（这就是"AJAX"中的"J"），那么你就已经迈出了很大的一步。特别是，你应该能够理解如何识别 JavaScript 语句的语法和结构。例如：JavaScript 中变量的样子以及如何使用"`{ }`"（花括号）设置**函数**或**条件**的**块**。你还需要知道如何用";"（分号）正确结束一行 JavaScript 代码。再次强调，你不需要直接的经验，但你应该可以轻松地看一段 JavaScript 代码并理解它是如何设置的。

例如，让我们快速看一下以下代码示例，其中包含了解释性的注释：

```js
<script type="text/javascript"> /*this is an XHTML script tag with the type attribute set to define javascript*/
/*
This is a multi-line Comment.
You can use multi-line comments like this to add instructions or notes about your code.
*/
//This is a single line comment for quick notes
function writeHelloWorld(){ /*this line sets up a function and starts block of code*/
var text1 = "Hello"; //this is a variable called text1
document.write(text1); /*This writes "Hello" to the HTML body via the variable "text1"*/
document.write(" World!"); /*Writes the string " World!" to the HTML body. Note the ";" semi-colons ending each statement above, very important!*/
}// this bracket ends the function block
writeHelloWorld(); /*evokes the function as a statement again, ending with a ";" semi-colon.*/
//this closes the HTML script tag
</script>
```

如果你能明白给定的代码片段中发生了什么，并且自信地说你可以修改变量而不会破坏脚本，或者改变函数的名称以及它被调用的地方，那么你已经足够了解本书的内容。

当然，你对处理不同**类型**的信息，比如**字符串、整数**和**数组**以及**循环**和**if/else**语句等都了解得越多，越好。但同样，仅仅理解一般的语法，现在就足以让你开始使用 jQuery 和这个主题了。

AJAX 实际上并不是一种语言。正如我们将在第七章中所学到的，*AJAX with jQuery and WordPress*，它只是一组用于使用异步 JavaScript 和 XML 的技术，使用 JavaScript 和 HTTP 请求共同开发高度动态页面的技术。开发者喜欢这种方法，因为它使他们能够创建更像桌面程序而不是标准网页的页面。如果你有兴趣在 WordPress 中使用 AJAX，我们将在第七章中详细介绍如何使用 jQuery 来帮助你使用各种 AJAX 技术。但这并不是使用 jQuery 与 WordPress 利用的必不可少的内容。

### 注意

如果你是 JavaScript 新手，并希望快速、有趣地入门，我强烈推荐 W3Schools 网站。这个网站是一个很好的资源，可以让你对所有符合 W3C 标准的 Web 技术有所了解。[`w3schools.com/js/`](http://w3schools.com/js/)。你也可以了解 AJAX: [`w3schools.com/ajax/`](http://w3schools.com/ajax/)。

### PHP

你绝对不必成为 PHP 程序员才能读完这本书，但 WordPress 是用 PHP 构建的，它的主题中使用了大量的 PHP 来实现其魔法！WordPress 插件几乎纯粹是 PHP。想要给 WordPress 主题或插件添加 jQuery 功能，就需要一点 PHP 语法的挑战。

与 JavaScript 一样，如果你至少了解基本的 PHP 语法结构，你在重新输入或复制粘贴 PHP 和 WordPress 模板标签的代码片段时，就会少出错得多，这些代码放在你主题的模板文件中。

PHP 语法与 JavaScript 语法结构类似。PHP 也使用大括号来表示函数、循环和其他条件的代码块。你在 PHP 中的每个语句末尾都需要加上分号，就像在 JavaScript 中一样。主要区别在于，PHP 是通过在`<?php ?>`标签中包裹代码片段来调用的，这些标签不是 XHTML 标签集的一部分，而 JavaScript 是通过将代码片段放在 XHTML 的`<script>`标签内来调用的。此外，PHP 中的变量是用"$"（美元）符号表示的，永久地添加到你创建的变量名之前，而不是像`var`语句一样只在开始时设定。

最大的区别在于，PHP 是一种服务器端脚本语言，而 JavaScript 是客户端脚本。这意味着 JavaScript 在用户的浏览器内下载和运行，而 PHP 代码是在 Web 服务器上进行预解释的，只有最终的 XHTML（有时还有 CSS 和 JavaScript - 你可以用 PHP 做很多事情！）被提供到用户的 Web 浏览器中。

让我们快速看一下一些基本的 PHP 语法：

```js
<?php /*All PHP is evoked using greater-than brackets and a "?" question mark, followed by the letters "php"*/
//This is a single-line comment
/*
This is multi-line
comment block
*/
function newHelloWorld(){/*this sets up a function and code block*/
$text1 = "Hello"; //creates a variable called: $text1
echo $text1." World!"; /*tells the HTML page to print , aka: "echo" the variable $text1 with the string " World!" concatenated onto it.*/
}//this ends the code block
newHelloWorld(); //calls the function as a statement ending with a semi-colon.
//the question mark and closing less-than tag end the PHP code.
?>
```

我相信你立刻就能注意到 PHP 和 JavaScript 之间的一些不同之处，但也有许多相似之处。同样，如果你确信在不破坏功能的情况下可以替换变量值，那么你在 WordPress 和这个标题上都会做得很好。一如既往，你对 PHP 的了解越多，就会越好。

### 提示

**我必须在我的**`<?`**起始块中添加"php"吗？**

你会注意到我将我的 PHP 起始块设置为："`<?php`"。对于一些有一些 PHP 知识或有 WordPress 经验的人来说，你可能熟悉只以`<?`开始和以`?>`结束的 PHP 块。在启用了**简写支持**的服务器上，你可以以"`<?`"开始一个脚本块（以及使用一些其他很酷的 PHP 简写技巧）。

然而，尽管通常启用了简写支持，但并非每个人的 PHP 安装都启用了它。当我的客户或朋友似乎无法让新的插件或主题在他们的 WordPress 安装中正常工作时，这通常会成为罪魁祸首。主题或插件是使用简写编写的，而客户的 PHP 安装没有启用它，出于某种原因，他们的 IT 人员或托管提供者不想启用它。为了尽可能保持兼容性，我们在此书中将使用标准形式（`<?php`）而不是简写形式。

### 注意

如果您想通过了解更多关于 PHP 的信息来更好地理解 WordPress，那么再次，W3School 网站是一个很好的开始！([`w3schools.com/php/`](http://w3schools.com/php/))。

在阅读本书之后，如果您对 PHP 以及 JavaScript、AJAX 和 jQuery 感兴趣，您可能想继续阅读*Audra Hendrix、Bogdan Brinzarea*和*Cristian Darie*的**AJAX 和 PHP：构建现代 Web 应用程序第二版**。

更喜欢通过视觉“亲自实践”学习的人？`lynda.com`有来自全球顶尖 CSS、XHTML/XML、PHP、JavaScript（甚至 jQuery）专家的出色课程选择。您可以订阅在线学习课程，也可以购买 DVD-ROM 进行离线观看。

起初，这些课程或每月订阅可能显得价格不菲，但如果你是一个视觉学习者，花钱和时间在这些课程上是值得的。您可以参考官方网站[`lynda.com`](http://lynda.com)。

# 基本工具

技能是一回事，但您的工具越好，对这些工具的掌握程度越高，您的技能就能发挥得越好（您可以问问任何木匠、高尔夫球手或应用程序程序员关于“行业工具”的绝对重要性）。

## 代码/HTML 编辑器

首先，我们需要处理标记和代码——大量的标记、CSS、PHP 和 jQuery。因此，您需要一个好的代码或 HTML 编辑器。Dreamweaver 是一个很好的选择([`www.adobe.com/products/dreamweaver/`](http://www.adobe.com/products/dreamweaver/))，尽管我更喜欢在 Mac 上使用 Coda (http://www.panic.com/coda/)。在我发现使用 Coda 进行工作之前，我非常喜欢免费编辑器 TextWrangler ([`www.barebones.com/products/textwrangler/`](http://www.barebones.com/products/textwrangler/))。当我在 PC 上工作时，我喜欢使用免费的文本/代码编辑器 HTML-kit ([`www.htmlkit.com/`](http://www.htmlkit.com/))。

有成千上万的编辑器，有些是免费的，有些是昂贵的，功能也各不相同。我和每个开发人员和设计师都谈过的人，都使用不同的工具，并对为什么他们的编辑器是最好的有十分钟的“演讲”。最终，任何一个可以让您启用以下功能的 HTML 或文本编辑器都会很好地工作。我建议您启用/使用以下所有功能：

+   **查看行号：** 在验证和调试过程中非常方便。它可以帮助您在 jQuery 脚本、主题或插件文件中找到特定行，针对这些行，验证工具已返回修复。这对于其他主题或插件的作者给出的指令也很有帮助，这些指令可能涉及到在不同条件下需要自定义或编辑的特定代码行。

+   **查看语法颜色：** 任何值得信赖的代码和 HTML 编辑器通常都有这个功能，默认设置为默认。好的编辑器可以让你选择自己喜欢的颜色。这会以各种颜色显示代码和其他标记，使得区分各种语法类型变得更容易。许多编辑器还可以帮助你识别损坏的 XHTML 标记、CSS 规则或 PHP 代码。

+   **查看不可打印字符：** 你可能不想一直开启这个功能。它可以让你看到硬回车、空格、制表符和其他你可能希望或不希望在你的标记和代码中的特殊字符。

+   **文本自动换行：** 当然，这可以让你在窗口内部换行文本，这样你就不必水平滚动以编辑一行很长的代码。最好学习一下你的编辑器中这个功能的快捷键是什么，和/或者为其设置一个快捷键。你会发现，通过未换行、缩进良好的标记和 PHP 代码进行快速浏览或找到上次停止的地方会更容易；但是，你仍然希望快速地打开换行功能，这样你就可以轻松地看到并将注意力集中在一行长代码上。

+   **通过 FTP 或本地目录加载文件：** 一个允许你通过 FTP 连接或在侧面板中看到本地工作目录的编辑器非常有帮助。它可以帮助你避免手动在你的操作系统资源管理器或查找器中查找文件，也不必通过额外的 FTP 客户端上传。能够在一个应用程序中连接到你的文件只会加快你的工作流程。

    ### 小贴士

    **免费开源 HTML 编辑器：**

    我还使用过 Nvu（[`www.net2.com/nvu/`](http://www.net2.com/nvu/)）和 KompoZer（[`kompozer.net/`](http://kompozer.net/)）。它们都是免费的、开源的，并且适用于 Mac、PC 和 Linux 平台。KompoZer 是从与 Nvu 相同的源代码构建的，并且显然修复了一些 Nvu 存在的问题。（我自己没有遇到 Nvu 的任何主要问题）。这两个编辑器都对我的日常使用来说有些限制，但我确实喜欢能够快速格式化 HTML 文本并将表单对象拖放到页面上。这两个编辑器都有一个**源代码**视图，但在**普通**和**源代码**视图标签之间切换时必须小心。Nvu 和 KompoZer 过于*贴心*了，如果你没有正确设置偏好设置，它们会尝试重写你的手写标记！

    Ubuntu 和 Debian 的 Linux 用户（以及使用 Fink 的 Mac 用户）可能也有兴趣尝试 Bluefish 编辑器([`bluefish.openoffice.nl`](http://bluefish.openoffice.nl))。我在 Ubuntu Linux 上工作时使用 Bluefish。我在 Linux 上更喜欢它，尽管它足够强大，可以被认为更像是一个 IDE（集成开发环境），类似于 Eclipse([`www.eclipse.org`](http://www.eclipse.org))，而不仅仅是一个基本的代码或 HTML 编辑器。对于大多数人来说，像 Bluefish 或 Eclipse 这样的工具可能过于强大，超出了他们在 WordPress 开发和维护中的一般需求。另一方面，如果您认真对待 WordPress 开发，它们可能具有您发现无价的功能，值得下载并尝试。

## Firefox

最后，您需要一个网络浏览器。我强烈建议您使用最新稳定版本的 Firefox 浏览器，可在[`mozilla.com/firefox/`](http://mozilla.com/firefox/)下载。

现在有人可能会问，为什么使用 Firefox？虽然这个浏览器也有其缺点（与任何其他浏览器一样），但总的来说，我认为它是一个非常优秀的 Web 开发工具。对我来说，它和我的 HTML 编辑器、FTP 程序以及图形工具一样重要。Firefox 具有很多优秀的功能，我们将利用这些功能来帮助我们简化 WordPress 和 jQuery 增强以及网站制作。除了内置功能（如 DOM 源选择查看器和遵循由 W3C 指定的 CSS2 和一些 CSS3 标准）之外，Firefox 还有一系列非常有用的**扩展**，例如**Web 开发者工具栏**和**Firebug**，我推荐您使用以进一步增强您的工作流程。

如果您有一些 jQuery 的经验，您可能已经注意到 jQuery 网站上的优秀文档以及大多数 jQuery 书籍，倾向于专注于 jQuery 的细节，使用非常简单和基本的 HTML 标记示例，并添加了最少的 CSS 属性。在 WordPress 中，您将发现自己在使用由其他人创建的主题或插件。您需要一种简单的方法来探索主题、插件和 WordPress 生成的**文档对象模型**（**DOM**）和 CSS，以便通过生成的标记来使 jQuery 实现您想要的效果。Firefox 浏览器及其扩展程序比其他任何浏览器更容易实现这一点。

### Web 开发者工具栏

这是一个很棒的扩展，它为您的 Firefox 浏览器添加了一个工具栏。该扩展也适用于 Seamonkey 套件和新的 Flock 浏览器，这两者都使用 Mozilla 的开源代码，就像 Firefox 一样。[`chrispederick.com/work/web-developer/`](http://chrispederick.com/work/web-developer/)。

该工具栏允许你直接链接到浏览器的 DOM 和错误控制台，以及 W3C 的 XHTML 和 CSS 验证工具。它还允许你以各种方式切换和查看你的 CSS 输出，并允许你查看和实时操纵你的网站输出的各种信息。这个工具栏的用途是无穷无尽的。每当我开发设计或创建 jQuery 增强功能时，似乎都会发现一些以前从未使用过但非常有用的功能。

![Web 开发者工具栏](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_01_01.jpg)

### Firebug

一种更强大的工具是 Joe Hewitt 的 Firefox 的 Firebug 扩展，位于[`www.getfirebug.com/`](http://www.getfirebug.com/)。请注意，还有一个适用于 Internet Explorer、Safari 和 Opera 的“Firebug Lite”版本。但完整版的 Firebug 对于 Firefox 是最佳选择。

当与 Web 开发者工具栏的功能结合使用时，此扩展功能强大。单独使用时，Firebug 将找到你需要操纵或调试的任何内容：HTML、CSS、JavaScript，无所不包。它甚至可以帮助你实时找到发生在你的 DOM 上的一些小“怪异”情况。有各种有趣的检查器，几乎所有的检查器都是不可替代的。

我最喜欢的 Firebug 功能是查看 HTML、CSS 和 DOM 的选项。Firebug 将向你展示你的框模型，并让你看到每个边缘的尺寸。此外，Firebug 的最新版本允许你实时编辑，轻松尝试不同的修复方案，然后再将其提交到你的实际源文件中。 （Web 开发者工具栏也有一些实时编辑的功能，但我发现 Firebug 接口更加深入和易于使用。）

![Firebug](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_01_02.jpg)

## 不是必需的，但很有帮助：图像编辑器

我想提到的最后一个工具是图像编辑器。虽然你可以用纯 CSS 做很多酷炫的增强效果，但很可能你会想通过使用图形编辑器（如 GIMP、Photoshop 或 Fireworks）进一步扩展你的 WordPress 设计和 jQuery 增强功能，添加一些时髦的视觉元素，比如酷炫的图标或自定义背景。这些最好通过使用图形编辑器来实现。

Adobe 拥有 Photoshop 和 Fireworks。它还提供了一款轻量且价格较低的 Photoshop 版本，称为 Photoshop Elements，可以进行基本的图像编辑（[`www.adobe.com/products/`](http://www.adobe.com/products/)）。

任何你喜欢的图形编辑器都可以。最好选择一个可以使用图层的编辑器。

### 提示

**免费开源图像编辑器**

如果你预算有限且需要一款优秀的图像编辑器，我推荐 GIMP。它适用于 PC、Mac 和 Linux。你可以从[`gimp.org/`](http://gimp.org/)下载。

另一方面，如果像我一样更喜欢矢量艺术的话，那么尝试一下 Inkscape 吧，它也适用于 PC、Mac 和 Linux。位图图形编辑器很棒，因为它们还可以让你增强和编辑照片，并进行一些绘图。但如果你只想创建漂亮的按钮和图标或其他界面元素和基于矢量的插图，Inkscape 可以让你获得详细的绘图控制，值得一试([`inkscape.org`](http://inkscape.org))。你会发现，本书中的许多图形示例都是主要使用 Inkscape 制作的。

我个人同时使用位图图像编辑器，比如 GIMP 或 Photoshop，以及 Inkscape 这样的强大矢量绘图程序。我发现同时使用这两种类型的图像编辑器来创建大多数网站设计和效果是很有必要的。

# jQuery 背景和要点

jQuery，由**约翰·雷西格**创建，是一个免费的开源 JavaScript 库。它简化了创建高度响应页面的任务，并在所有现代浏览器中表现良好。约翰在开发 jQuery 时特别留意，使其抽象出所有浏览器之间的差异。因此，你可以专注于项目的功能和设计，而不会陷入繁琐的 JavaScript 编码来处理所有不同的浏览器，以及各个浏览器喜欢处理 DOM 和自己的浏览器事件模型的不同方式。

## jQuery 的作用（非常出色）

在其核心，jQuery 擅长通过找到和选择（因此名称中有“query”一词）DOM 元素为**jQuery 对象**，通常称为**包装器**。这使你可以轻松获取和设置页面元素和内容，并使用所有现代浏览器事件模型，允许你为站点添加复杂功能。最后但并非最不重要的一点是，jQuery 还拥有一套非常酷的特效和 UI 库。动画和界面小部件现在完全受你指挥。

### 注意

**等等！DOM？！**

不要惊慌。我知道，我们才刚刚进入第一章，我已经多次提到这个神秘的缩写**DOM**。我将会更多地提到它。学习关于**文档对象模型（Document Object Model）**可以真正增强你对 HTML 的理解，对 WordPress 主题设计和 jQuery 增强也十分有帮助。

它还将帮助你更好地理解如何有效地构建 CSS 规则，并编写更清晰准确的 jQuery 脚本。有关更多信息，当然可以参考 W3Schools 网站：([`w3schools.com/htmldom/`](http://w3schools.com/htmldom/)。

除了所有这些酷炫的 DOM 操作内容，jQuery 有一个不错的易学曲线。你这些 CSS 专家们会特别喜欢掌握 jQuery。再次强调，为了找到最佳的选择元素的方式，约翰开发了 jQuery，以便利用 Web 开发人员对 CSS 的现有知识。你会发现 jQuery 选择器非常简单易用，特别是在你可以几乎像使用 CSS 样式一样轻松地获取和选择一组元素时！

## 我们是如何到达这里的：从 JavaScript 到 jQuery

JavaScript，最初被称为 LiveScript，是在 90 年代初由 Netscape 的开发人员发明的。到 1996 年，Netscape 将 LiveScript 重命名为 JavaScript，以便通过将其与独立开发的 Java（由 Sun Microsystems 开发）相关联来提高其知名度。Java 本身已经存在了几年，因为人们开始通过使用称为“小程序”的单独插件在网站中运行它，所以它变得更加流行。有一些方式，Netscape 的开发人员确保 JavaScript 的语法和功能与 Java 非常相似，但当然也有区别。最大的区别在于 JavaScript 是一个在客户端执行的解释型脚本语言，这意味着它在浏览器中实时运行，而不是像 Java 那样预编译以执行和运行。

解释它所有内容有点复杂，超出了本书的范围，但当然，微软的浏览器 Internet Explorer 与 Netscape 竞争时，采取了完全不同的路线，发布了具有运行微软自己 VBScript 能力的 IE。VBScript 被设计成外观和功能类似于 VisualBasic，但再次作为解释语言，而不是像 VB 那样编译的语言。当 JavaScript 似乎比 VBScript 更受新兴网页开发人员欢迎时，微软推出了 JScript。JScript 被设计成与 JavaScript 非常相似，以吸引 JavaScript 开发人员，而不需要为微软支付任何许可费用，但仍然存在一些差异。然而，如果你非常小心，没有很高的期望，你可以编写一个在 Netscape 中执行为 JavaScript，而在 IE 3.0 中执行为 JScript 的脚本。

是的。多么痛苦啊！直到今天，IE 仍然只执行 VBScript 和 JScript！不同之处在于，微软和 Mozilla（Netscape 的创建基金会）都向 **ECMA International**（一个专注于创建和维护信息通信系统标准的组织）提交了 JavaScript 和 JScript。除了 JavaScript，你还可以感谢 ECMA Int. 制定的标准范围从 CD-ROM 和 DVD 格式规范到像 MSOffice 和 OpenOffice 这样的办公套件中使用的较新的 Open XML 标准。

从 1997 年 JavaScript 首次提交至今已经超过十年了。但截至 2010 年，JavaScript 和 JScript 标准非常相似，现在两者在技术上都被称为 ECMAScript（但谁想一直这样说呢？）。

许多在 90 年代后期和 21 世纪初成长起来的开发人员将 JScript 和 JavaScript 术语混用，而不意识到它们之间有区别！然而，仍然存在差异。IE 在某些方面处理 ECMAScript 与 Firefox 和其他浏览器不同。为了清晰和理智，本标题将继续称 ECMAScript 为 JavaScript。

### 从前，有一种叫做 JavaScript 的东西。

在"黑暗时代"，也就是在 jQuery 在 2006 年初出现之前，为了创建一个更具动态响应事件或使用 JavaScript 操纵 DOM 的页面，你必须花费大量时间编写使用`while`和`foreach`循环，其中可能还有一些或许很多被挤在这些循环内的`if/else`语句，且通常笨拙的 JavaScript。

如果你想要立即调用你的 JavaScript，它必须放置在头标签中或在主体中使用`onload`事件处理程序。问题在于这种方法等待*整个*页面及其所有内容加载，包括诸如 CSS 文件和图像之类的内容。如果你创建了一个循环来选择和操作一组元素，并且想要对该组元素执行额外的更改，那么你必须在另一个循环中重新选择它们，或者有一个带有`if/else`语句的长循环，这可能变得复杂且难以跟踪和维护。

最后，你可能想让页面响应的许多事件通常需要单独调用。我记得有时候不得不为 Firefox（或远古的 Netscape）创建一个事件脚本，为 IE 创建一个单独的事件脚本。偶尔，我甚至会想出一些小创意方法来检测不同的浏览器，或者"欺骗"它们以响应不同的事件，总的来说，这只是为了让页面在两种浏览器之间看起来和响应类似的一些东西。

尽管我喜欢为我的网站编程并添加引人入胜的互动性，但我常常对深入 JavaScript 的努力稍感不满。

### 为什么 jQuery 比 JavaScript 更简单

这一切随着 jQuery 而结束。jQuery 并不是独立存在的，也就是说它不是浏览器支持的新语言。它本质上只是创建更好的、可工作的 JavaScript。正如前面提到的，它是一个 JavaScript 库，提供了更简单、更易于构建的语法。浏览器的 JavaScript 引擎会将 jQuery 语法解释为普通的 JavaScript。jQuery 只是隐藏了你以前用 JavaScript 必须自行完成的许多"丑陋"和复杂的东西，并替你完成了这些工作。

我最初喜欢 jQuery 的一点是它实质上是一个奇妙的"循环引擎"（除了它出色的、清晰的文档）。现在我称之为"循环"，但是那些有更正式编程背景或者对 jQuery 有一些先前经验的人可能已经听说过这个术语：**隐式迭代**。基本上，jQuery 迭代，也就是说，通过所选元素的容器对象重复（又称：循环），而不需要引入一个*显式*的迭代器对象，因此使用术语*隐式*。好了，请忽略复杂的定义，它只是意味着你几乎可以做任何你需要做的事情，而不必编写`foreach`或`while`循环！我和大多数关于 jQuery 的人聊过的人都不知道这才是 jQuery 在幕后真正在做的事情。

比能够轻松循环遍历所选元素更酷的是，使用标准的 CSS 符号可以首先选择它们。然后，如果这两个功能还不够出色的话，一旦你抓到了一组元素，如果你有多个操作要应用于所选元素集，那也没问题！与其一遍又一遍地在选择上调用单独的函数和脚本，不如一次性在一行代码中执行 *多个* 操作。这被称为 **语句链接**。语句链接非常棒，我们将在本标题中经常学习并经常利用它。

最后，jQuery 是非常灵活的，最重要的是可扩展的。在它存在的四年中，已经有数千个第三方插件为它编写。正如我们在本书中将发现的那样，编写自己的 jQuery 插件也非常容易。然而，你可能会发现，对于你更实际的日常 WordPress 开发和维护需求，你不需要这样做！就像 WordPress 为你节省了大量的时间和工作一样，你会发现使用 jQuery 也已经有很多工作完成了。

无论你想创建什么，你可能可以很容易地通过一个 jQuery 插件和对你的 WordPress 主题进行一两个调整来实现。也许你只需要编写一个快速简单的 jQuery 脚本来增强你喜欢的 WordPress 插件之一。在本书中，我们将介绍 jQuery 的基础知识和将其应用于 WordPress 的最常见用法，你很快就会发现可能性是无限的。

### 提示

**了解 jQuery**

本书旨在帮助您为 WordPress 用户常遇到的场景和问题创建解决方案。我希望能帮助您节省一些时间，无需深入研究 WordPress 的精彩但又广泛的 codex 和 jQuery 的 API 文档。但这本书绝不会取代那些资源或 jQuery 和 WordPress 社区成员维护的优秀资源。

对于 jQuery，我强烈建议你查看 jQuery 的文档和 Learning jQuery 网站：

[`docs.jquery.com`](http://docs.jquery.com)

[`www.learningjquery.com`](http://www.learningjquery.com)

## 理解 jQuery 包装器

随着我们在本标题中的深入，你将听到并学到更多关于 jQuery 对象的信息，也被称为“包装器”或“包装器集”，这可能是最合理的，因为它是你选择要处理的一组元素。但由于这是 jQuery 工作的关键，我们现在会进行一个快速介绍。

要完全理解包装器，让我们稍微离开 jQuery。归根结底，一切都始于你的浏览器。你的浏览器有一个 JavaScript 引擎和一个 CSS 引擎。浏览器可以加载、读取和解释格式正确的 HTML、CSS 和 JavaScript（当然，还有大量的 Java、Flash 和许多不同的媒体播放器的插件，但出于本解释的目的，我们不需要担心它们）。

现在这只是一个非常粗糙的高级概述。但我认为这将帮助你理解 jQuery 的工作原理。浏览器接收加载的 HTML 文档并创建文档的映射，称为 DOM（文档对象模型）。DOM 本质上是 HTML 文档对象的树。

您会认出大多数对象作为 HTML 文档中的标记标签，例如`<body>, <h1>, <div>, <p>, <a>`等。DOM 树被展开，显示这些对象之间的父子关系，以及将关系映射到每个对象的属性和内容。例如，看一下以下示例 DOM 树插图：

![了解 jQuery 包装器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_01_03.jpg)

现在是有趣的部分。如果有 CSS 样式表附加或嵌入到文档中，浏览器的 CSS 引擎会遍历 DOM 树，并根据样式规则为每个元素添加样式。当然，如果文档中附加或嵌入了任何 JavaScript，浏览器的 JavaScript 引擎也能遍历 DOM 树并执行脚本包含的指令。

jQuery 库被附加到您的 XHTML 文档作为 JavaScript 文件。然后，该库能够准备 JavaScript 引擎创建一个对象，该对象将在其中具有所有 jQuery 功能，准备在被调用时使用（也称为 jQuery 对象）。当您创建 jQuery 代码时，您自动调用了 jQuery 对象，并且可以开始使用它。

通常，您将指示 jQuery 对象通过 CSS 选择器遍历 DOM，并将特定元素放入其中。所选元素现在在 jQuery 对象中“包裹”并且您现在可以在所选元素集上执行额外的 jQuery 功能。jQuery 然后可以循环遍历它所包装的每个元素，执行其他功能。当它遇到集合中的最后一个对象并执行了通过语句链传递给它的所有指令时，jQuery 对象停止循环。

以下插图显示了传递给 jQuery 对象的一些 DOM 对象。

![了解 jQuery 包装器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_01_04.jpg)

## 开始使用 jQuery

很容易开始使用 jQuery。我们将在这里涵盖最直接的基本方法，在下一章中，我们将探讨在 WordPress 中使用 jQuery 的几种其他方法。

### 从 jQuery 网站下载

如果您前往[jQuery 网站](http://jquery.com)，您会发现首页为您提供了两个下载选项：版本为 1.4.2 的生产和开发库，这是本文撰写时最新发布的稳定版本。

![从 jQuery 网站下载](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_01_05.jpg)

生产版已经被压缩和“缩小”成一个更小的文件大小，加载速度会快得多。它的大小为 24KB。开发版则未经压缩，大小为 155KB。虽然体积大得多，但如果你遇到调试问题并需要打开和阅读时，它会更容易阅读。

理想情况下，你应该在创建网站时使用 jQuery 的开发版本，并在发布到线上时切换到生产版本，这样加载速度会快得多。你们中的许多人可能永远不想查看 jQuery 库的内部，但不管怎样，下载两个版本都是个好主意。如果在调试过程中一直显示 jQuery 库中的某行代码出现问题，你可以切换到开发版本以更清楚地了解该代码行试图做什么。我可以告诉你，jQuery 库中的某行代码出现问题的可能性很小！几乎总是你的 jQuery 脚本或插件有问题，但能够查看完整的 jQuery 库可能会让你了解你的脚本代码哪里出了问题，以及为什么库不能与它一起工作。生产和开发库之间没有区别，只有文件大小和人类可读性。

![从 jQuery 网站下载](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_01_06.jpg)

在 jQuery 的主页上，当你点击**下载**时，你将被带到 Google code 网站。然后你可以返回并选择其他版本进行下载。请注意，该库没有以任何方式进行压缩或打包。它下载的是实际的`.js` JavaScript 文件，可以直接放入你的开发环境中使用。如果你点击**下载**按钮，看到 jQuery 代码出现在你的浏览器中，只需点击返回按钮，然后右键单击或按住控制键单击，然后点击**另存为目标**进行下载。

### 提示

**使用 Visual Studio？**

如果你的代码/HTML 编辑器恰好是 Visual Studio，你可以下载一个额外的文档文件，在 Visual Studio 中使用并访问嵌入到库中的注释。这使得 Visual Studio 编辑器在编写 jQuery 脚本时可以进行语句完成，有时也称为 IntelliSense。

要下载定义文件，请点击主页顶部的蓝色**下载**选项卡。在**下载 jQuery**页面上，你会找到指向最新版本中的 Visual Studio 文档文件的链接。

![从 jQuery 网站下载](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_01_07.jpg)

你会将这个文件放在你下载的 jQuery 库（生产版或开发版）的同一位置，然后它应该可以在你的 Visual Studio 编辑器中工作了。

## 包括 jQuery 库

让我们立即设置一个基本的 HTML 文档，其中包含我们刚刚下载的 jQuery 库文件。我已经下载了较小的生产版。

在接下来的标记中，我们将附加库并编写我们的第一个 jQuery 脚本。现阶段不要太担心 jQuery 代码本身。它只是在那里让你看到它的运行情况。我们将在下一章中真正了解 jQuery 功能。

```js
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html  xml:lang="en">
<head>
<title>First jQuery Test</title>
<script type="text/javascript"
src="jquery-1.3.2.min.js"></script>
<script type="text/javascript">
jQuery("document").ready(function(){
jQuery("p").css("background-color", "#ff6600");
});
</script>
</head>
<body>
<h1>Sample Page</h1>
<p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. </p>
<p>Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat.</p>
<p>Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
</body>
</html>

```

就是这样！在没有包含或嵌入到页面或标记中的任何 CSS 的情况下，我们使用 jQuery 改变了段落标签的 CSS `background` 属性。最终，我们并不希望 jQuery 取代我们对 CSS 的正常使用！但是从这个快速示例中，你可以看到 jQuery 如何在响应事件时动态改变网站页面的外观和布局，使网站页面对用户非常响应；这是一个强大的功能。你现在应该能够将这个文件加载到 Firefox 中，看到你的第一个 jQuery 脚本在运行中的效果。

![包含 jQuery 库](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_01_08.jpg)

如果你之前有过与 WordPress 的工作经验，根据前面的示例，你可能很容易看到如何在你的 WordPress 主题中包含 jQuery 库并开始使用它。你可以很好地通过这种方式将 jQuery 包含到你的主题中。然而，在下一章中，我们将讨论将 jQuery 库包含到你的 WordPress 安装中的更优化的方式。

# WordPress 背景和要点

现在你对 jQuery 有了一点背景，并且了解了如何在 HTML 文档中使用它，让我们来看看 WordPress。再次强调，你们大多数人都已经是 WordPress 用户和开发者了。至少，你可能以某种方式与之合作过。你甚至可能有一个自己拥有或维护的 WordPress 站点。

对于那些对 WordPress 有最少经验的人，我们将快速介绍一些背景和要点，以便开始使用它。即使你是经验丰富的用户，你也可能想要继续阅读，因为我将介绍如何设置一个 WordPress 的“沙盒”或开发安装。这样，你就可以在没有任何东西出现在你实际站点上的情况下，进行 WordPress 和 jQuery 的实验、学习和玩耍，直到你准备好部署它。

## WordPress 概述

WordPress 是由 *Matt Mullenweg* 和 *Mike Little* 共同开发的，起源于原始的 b2/cafelog 软件的一个分支。它首次出现于 2003 年。最初是一个博客平台，多年来已经发展成为一个强大的发布平台，数百万人和组织以各种方式使用它来维护他们站点的内容。

与 jQuery 一样，WordPress 是灵活和可扩展的。Matt 和他的 WordPress 开发人员团队在 Automattic 公司一直致力于确保 WordPress 符合当前的 W3C 网络标准。一个 WordPress 站点的设计和额外的自定义功能可以很容易地通过平台的 API 进行控制和更新，这些 API 简化了主题和插件的开发。

作为一个希望通过 jQuery 增强网站的人，你应该记住 WordPress 网站是多么动态。WordPress 使用 MySQL 数据库、一组主题模板页面以及插件页面，更不用说数百个核心功能页面来生成你的网站。这意味着最终显示的 XHTML 页面标记来自许多地方；来自主题的模板文件，来自 MySQL 数据库中存储的帖子和页面内容，以及一些可能在安装中使用的插件或小部件的代码中定义的内容。

你了解你的 WordPress 安装及其文件如何组合，你就能更容易地使用 jQuery 增强网站。

下图说明了 WordPress 如何向浏览器提供完整的 HTML 页面：

![WordPress 概述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_01_09.jpg)

### 小贴士

**对 WordPress 完全不了解？**

同样，我强烈推荐**April Hodge Silver**和**Hasin Hayder**合著的书籍**WordPress 2.7 完整手册**。这本书是一本绝佳的资源。它涵盖了你需要了解的有关 WordPress 的一切，还将帮助你开始使用 WordPress 主题和插件。

**对 WordPress 感兴趣吗？**

如果你已经熟悉使用 WordPress，但想更深入了解主题和插件开发，那么你一定要看看**WordPress 插件开发**，作者是*弗拉迪米尔·普雷洛瓦克*，当然，如果你可以原谅我对自己的书的不自量力的推销，那也一定要看看**WordPress 2.8 主题设计**。

## WordPress 运行的必要条件

如果你已经有一个可以使用的 WordPress 版本，那太好了。如果没有，我强烈建议你在本地安装一个。随着 WAMP（Windows、Apache、MySQL 和 PHP）和 MAMP（Mac、Apache、MySQL 和 PHP）的发布，安装和运行一个小型 Web 服务器在你的本地机器或笔记本电脑上变得非常容易。与在托管提供商上安装 WordPress 相比，本地服务器为你提供了几个便利。

我经常发现当我旅行时，尽管越来越多的互联网 WiFi 热点出现，但我经常身处某些地方没有 WiFi，或者我在星巴克，我不想向 T-Mobile 支付“特权”以连接到 WiFi。有了 WordPress 的本地安装，我就不用担心了。我可以随心所欲地开发和调试，而不受互联网连接的限制，最重要的是，我不用担心我会在正在为其开发或设计的现场网站上出现故障。

如果你对 WordPress 的本地沙盒安装感兴趣，我建议你下载 Windows 版的 WAMP 或 Mac 版的 MAMP。

### 使用 WAMP

WAMP 代表 Windows、Apache、MySQL 和 PHP，它使得在你的计算机上运行本地 web 服务器非常容易，只需几次点击。如果你使用的是 Windows 操作系统，比如 XP、Vista 或 Windows 7，你可以访问[`www.wampserver.com`](http://www.wampserver.com)并下载 WAMP 2。

一定要遵循 WAMP 安装向导中的说明！如果您已经在 localhost 上运行 Web 服务器和/或已安装了 WAMP 的先前版本，请仔细阅读向导说明，以便禁用或卸载该服务器，备份您的数据，并安装最新版本的 WAMP。

您还可以同意让 WAMP 为您安装一个起始页。从这个起始页以及任务栏中的 WAMP 图标，您将能够轻松启动 **phpMyAdmin**。phpMyAdmin 将允许您轻松创建安装 WordPress 所需的数据库和数据库用户帐户。

## 使用 MAMP

与 WAMP 类似，MAMP 代表（你猜对了！）Mac、Apache、MySQL 和 PHP。Mac 用户将前往 [`mamp.info`](http://mamp.info) 并下载服务器的免费版本。

一旦您下载并解压缩 ZIP 文件并启动 `.dmg` 文件，将 MAMP 文件夹复制到您的 `Applications` 文件夹并启动应用程序就是一个相当简单的过程。

同样，像 WAMP 一样，MAMP 从起始页上为您提供了一个启动 **phpMyAdmin** 的简单方法。phpMyAdmin 将允许您轻松创建数据库和数据库用户帐户，这是安装 WordPress 所必需的。

### 提示

**使用 Ubuntu？**

如果您正在使用 Ubuntu 并且需要一个本地服务器，那么您很幸运。毕竟，Linux 是大多数 Web 服务器使用的操作系统（我认为您此时已经知道 LAMP 是什么意思了）。

我建议您通过 Google 进行一些研究，找到安装您自己本地 Web 服务器的最佳方法。我发现以下资源对我最有用，也是我用来在我的 Ubuntu 10.04 安装上安装 LAMP 的资源：[`www.unixmen.com/linux-tutorials/570-install-lamp-with-1-command-in-ubuntu-910`](http://www.unixmen.com/linux-tutorials/570-install-lamp-with-1-command-in-ubuntu-910)。

### 选择主机提供商

如果您使用学校或图书馆的计算机，无法（或者其他原因不想）本地安装软件，您将需要一个拥有 Web 主机提供商的帐户。您选择的主机提供商必须运行 Apache、MySQL 和 PHP，以适应 WordPress。选择一个提供易于理解的帐户面板的主机提供商将极大地有利于您，该面板允许您轻松访问 phpMyAdmin。

### 提示

**轻松、一键安装—很简单，但要小心！**

许多网络主机提供商提供超级简单的“一键”安装，包括今天的顶级 CMS 发布平台和其他有用的网络应用，包括 WordPress。务必查看您的主机提供商的服务和选项，因为这将让您填写一个简单的表格，并避免直接处理 phpMyAdmin 或 WordPress 安装向导所带来的麻烦。

**小心一键安装！** 虽然许多提供商只是为你安装一个 WordPress 单一安装，这很完美，但有些提供商可能正在运行 **WordPressMU**。这些提供商将创建一个 MU 帐户，该帐户将映射到你的域名，但不会给你访问任何安装文件的权限。如果是这种情况，你将无法完全控制你的 WordPress 站点！

你必须能够通过 FTP 登录到你的托管帐户并查看你的 WordPress 安装文件，特别是 `wp-content` 目录，其中包含你需要编辑的主题和插件目录和文件，以便用 jQuery 增强你的站点。在选择一键安装之前，请务必与你的托管提供商仔细核对。

WordPressMU 是多用户 WordPress。它是 **WordPress.com** 帐户的动力来源。虽然在 `WordPress.com` 上建立一个站点并让他们托管它非常简单，但你不能上传或自定义自己的主题和插件。这就是为什么这个标题甚至不尝试涵盖 `WordPress.com` 帐户，因为你需要访问 `wp-content` 文件夹才能用 jQuery 增强你的站点。

### 部署 WordPress

WordPress 本身安装非常容易。一旦你设置了一个带有数据库用户名和密码的 MySQL 数据库，你就可以解压最新版本的 WordPress 并将其放入你的本地 `httpdoc` 或 `www` 根目录中，然后通过导航到 `http://localhost-or-domainname-url/my-wp-files/wp-admin/install.php` 运行安装。

### 提示

**5 分钟（或更少！）内的 WordPress**

要了解安装 WordPress 的完整概述，请务必查看 Codex 的 **WordPress 5 分钟安装指南**：[`codex.wordpress.org/Installing_WordPressAgain`](http://codex.wordpress.org/Installing_WordPressAgain)。书籍 **WordPress 2.7 完全手册** 将逐步引导你完成 WordPress 的安装。

# jQuery 与 WordPress：将它们结合起来

你可能属于两种类型中的一种：你可能了解并有经验的 jQuery，并且正在寻找 WordPress 来帮助维护你的站点。或者，更可能的是，你有 WordPress 的经验，正在看看 jQuery 能为你做什么。

如果你对 jQuery 有些经验，但对 WordPress 还比较新，你可能熟悉各种 jQuery 示例，展示了干净清晰的手工编码的 HTML 和 CSS，然后你会根据这些示例编写你自己的 jQuery 脚本。打开一个 HTML 文件并能够快速地看到甚至直接操纵所有的 HTML 标记和 CSS `id` 和 `class` 引用以使你的 jQuery 脚本尽可能简单是很容易的。

如我们在这里详细讨论过的，使用 WordPress 时，所有的 HTML 都是动态生成的。没有单个文件可以在编辑器中打开，以便了解 jQuery 要处理的内容。你需要了解 WordPress 发布系统，最重要的是了解 WordPress 主题和你使用的任何插件，以便让你的 jQuery 脚本能够定位并影响你想要影响的元素。正如我已经提到的，这就是你会发现 Web Developer 工具栏和 Firefox 的 Firebug 扩展程序将成为你最好的朋友的地方。

另一方面，熟悉 WordPress 并逐渐熟悉 jQuery 的专家们可能会遇到相同的问题，但你们从略有不同的角度来处理它。你可能习惯于让 WordPress 为你生成所有内容，而不用过多考虑。为了让 jQuery 影响你的 WordPress 内容，你将不得不更加熟悉 WordPress 和你的主题在幕后到底发生了什么。

在实施 jQuery 时，你的优势在于熟悉你的 WordPress 系统中主题的设定以及你使用的任何 WordPress 插件。你需要真正专注于理解 jQuery 选择器，以便能够导航 WordPress 生成的所有可能的 DOM 元素，并创建你想要的增强效果。

以下插图展示了 WordPress 如何向浏览器提供完整的 HTML 页面，然后解释 DOM，以便应用 CSS 样式，并增强 jQuery 和其他 JavaScript：

![jQuery 和 WordPress：将一切整合在一起](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_01_10.jpg)

# 总结

我们已经审视了使用 jQuery 和 WordPress 有效工作所需的基本背景知识和工具。

我们还研究了以下主题：

+   你需要启动项目的软件工具

+   jQuery 和 WordPress 的背景和基础知识

现在你已经了解了这些内容，在下一章中，我们将在 WordPress 中启用 jQuery，并深入了解 jQuery 的巨大可能性。准备好在我们的 WordPress 网站上玩得开心了。让我们开始吧！


# 第二章：在 WordPress 中使用 jQuery

现在我们了解了 jQuery 和 WordPress 的基础知识，并对它们如何相互作用有了一点背景了，我们现在准备好看看如何使用 jQuery 动态增强 WordPress 安装了。我们将从在 WordPress 中包含 jQuery 开始，并以我们的第一个酷项目结束：展开和折叠内容。这只是你的 WordPress 站点中 jQuery 可能性的开始！再次强调，我们在这个标题中将使用 WordPress 3.0 和新的默认 Twenty Ten 主题与 jQuery 1.4.2，但请放心，如果你的站点或项目仍在使用 WordPress 2.9，这些 jQuery 技术也会很好地工作。

在本章中，我们将涵盖以下主题：

+   在 WordPress 中注册 jQuery

+   使用谷歌的 CDN 来包含 jQuery

+   回顾所有 jQuery 的“秘密武器”

+   我们的第一个 jQuery 和 WordPress 增强

# 将 jQuery 引入 WordPress

jQuery 可以以以下三种不同的方式包含到 WordPress 中：

+   你可以从`jQuery.com`下载，并直接在 XHTML 头标签中使用`script`标签包含它，放在你的主题的`header.php`文件中（这种方法可行，但出于各种原因并不推荐）

+   你可以在主题和插件中注册 WordPress 捆绑的 jQuery

+   你也可以利用谷歌的 CDN（代码分发网络）来注册和包含 jQuery 到你的主题和插件中。

我们在第一章中涵盖了第一种方法的基础知识，*开始：WordPress 和 jQuery*。WordPress 非常灵活，任何具有正确管理员级别的用户都可以更新、增强主题，或安装其他插件，这些插件可能也使用 jQuery 或其他 JavaScript 库的版本。因此，直接将 jQuery 或任何 JavaScript 直接包含到主题中，带有硬编码脚本标记，这并不推荐，因为它可能会与通过主题定制或添加到 WordPress 安装的插件中包含的其他脚本和库发生冲突。在本章中，让我们来看看使用剩余的两种方法，通过 WordPress 的**Script** API 注册 jQuery 和使用谷歌的 CDN。

## jQuery 现在与 WordPress 捆绑在一起

从 WordPress 2.7 开始，jQuery 和其他几个 JavaScript 库和插件已经捆绑到 WordPress 的 Script API 中，并通过一个叫做`wp_enqueue_script`的方便函数可用。实际上，WordPress 已经将 jQuery 和相当多的其他 JavaScript 库（包括与 Prototype 和更多其他库一起的`Script.aculo.us`）捆绑到`wp-includes`目录中一段时间了，但直到 2.7 版本，这些包都不那么容易访问。

### 在 WP 主题中注册 jQuery

你可以以两种不同的方式激活 WordPress 捆绑的 jQuery：

首先，在你的`header.php`文件中在闭合的`</head>`标签前放置以下代码：

```js
<?php wp_enqueue_script("jquery"); ?>
<?php wp_head(); ?>
<script type="text/javascript">
//add jQuery code here
jQuery(document).ready(function() {
jQuery("p").click(function() {
alert("Hello world!");
});
});
</script>

```

或者，你可以在主题的`functions.php`文件中注册`wp_enqueue_script`（以及你编写的任何自定义 jQuery 代码）。如果你的主题没有`functions.php`文件，只需创建一个新文件，命名为`functions.php`，并将其放在主题的根目录中，与其他模板文件一起放置（`functions.php`是一个与我们正在使用的默认主题一起提供的标准模板文件）。将以下代码放入你的`functions.php`文件中：

```js
<?php wp_enqueue_script('jquery');/*this registers jquery*/
function jq_test(){ /*This is your custom jQuery script*/
?>
<script type="text/javascript">
jQuery(document).ready(function() {
jQuery("p").click(function() {
alert("Hello world!");
});
});
</script>
<?php
}
add_filter('wp_head', 'jq_test');/*this adds your script to the wp_head() hook in the header.php file and ensures your custom jQuery script is run*/
?>

```

### 避免注册 jQuery 时遇到的问题

我第一次尝试使用`wp_enqueue_script`加载 jQuery 时（无论是在`functions.php`文件中还是通过`header.php`文件），都无法使其工作。在 WordPress Codex 上花了一些时间和一些头发后，我终于意识到了以下事实：

+   如果你直接加载到你的`header.php`模板文件中，请确保`wp_enqueue_script`函数位于你的`wp_head`函数之前。你的自定义 jQuery 代码必须位于`wp_head`函数之后。

+   如果你在`functions.php`文件中注册`wp_enqueue_script`，请确保它出现在通过`add_filter`函数加载到`wp_head`中的任何自定义函数之前。

    ### 提示

    **了解一下** `wp_enqueue_script` **函数！**

    这个函数是 WordPress 的脚本 API 的一部分，实际上它做的不仅仅是加载 jQuery！正如我所提到的，实际上有超过五十个 JavaScript 工具包、框架、用户界面库、插件和帮助程序，你可以安全地使用`wp_enqueue_script`函数进行加载。在这里查看：[`codex.wordpress.org/Function_Reference/wp_enqueue_script`](http://codex.wordpress.org/Function_Reference/wp_enqueue_script)。

## 使用 Google 的 CDN

就我个人而言，我对注册并引用 WordPress 自带的副本有些犹豫。我发现，有时从**Google Code 的代码分发网络**（**CDN**）加载库是一个更好的选择。CDN 节省了带宽，允许您的站点在下载其他脚本和相关内容时进行一些并行处理。而且，可以很容易地始终获取最新版本的 jQuery。从 Google 的 CDN 加载 jQuery 库非常快，作为一个额外的奖励，如果您的站点用户以前访问过另一个从 Google Code 的 CDN 提供 jQuery 的站点，该库将已经缓存。

### 在主题中通过 Google 的 CDN 注册和包含 jQuery

要从 Google Code 的 CDN 中包含 jQuery，我们将确保注销 jQuery，然后通过 Google 的 CDN 进行注册。这就是注册和使用 `wp_enqueue_script` 函数的美妙之处：如果任何其他插件或脚本需要 jQuery，并且与从 Google 加载的版本没有冲突，那么该脚本将使用已加载的 Google CDN 库。如果脚本依赖于特定版本的 jQuery，比如 1.3.2 或 1.2.6，并且 CDN 正在加载 1.4.2 版本，那么该脚本将继续加载它需要的 jQuery 版本。因为（正如我们将学到的那样）通过 Script API 加载的每个脚本都保持在 `noConflict` 模式下，所以只要它们被注册和需要，同时加载两个库版本是可以的。

```js
...
wp_deregister_script( 'jquery' );
wp_register_script( 'jquery', 'http://ajax.googleapis.com/ajax/libs/jquery/1.4/jquery.min.js');
...

```

Google 提供了一个很棒的版本控制系统，允许你尽可能精确，或者只拉取最新的稳定版本。考虑前面的代码示例（注意前面代码示例中的突出显示的数字，1.4）。

#### 了解 Google 的版本控制系统

上述注册脚本引用了 jQuery 的 1.4.2 版本（在撰写本标题时是最新版本）。当 jQuery 的开发人员发布一个新版本，比如 1.4.3 时，该版本将自动由相同的 URL 调用，因为我没有准确定位版本的具体细节。同样，我可以选择调用 `...jquery/1.3/jquery..`，这将给我 `1.3` 版本中的最高版本 `1.3.2`。你猜对了，针对一个简单的 `...jquery/1/..` 将会拉取最新版本的 jQuery，直到 jQuery 升级到 2.0 版本！

通常情况下，始终加载最新的库是一个好习惯，但你永远不知道，你可能会使用一个 jQuery 插件或编写一些自己的代码，与新版本不兼容。然后，你会想要针对与你的插件或自定义脚本兼容的库的最后一个特定版本，直到你能够修复和更新它们。

## 使用 WordPress 的捆绑 jQuery 与包含自己的 jQuery 下载或使用 Google 的 CDN

正如我之前提到的，`wp_enqueue_script` 函数允许安全地将 jQuery（和其他包含项）加载到 `noConflict` 模式中。只要你从 Google CDN 注销并注册 jQuery，该库就会以相同的 `noConflict` 模式保护加载到 WordPress 中。我真的很喜欢利用 Google 的 CDN，因为我提到的各种性能原因，但对于大型项目，有许多编辑和管理员对如何管理 WordPress 站点以及使用什么 WordPress 插件作出不同决策，我会保守行事并将捆绑版本注册到主题中。此外，对于开发而言，如果我正在开发一个主题，并且由于旅行（或需要提高生产力）而与网络断开连接，我会发现在我的 MAMP 或 LAMP 服务器上已经运行 jQuery 很好。一旦网站上线，我会考虑将其切换到 Google CDN 版本的 jQuery。

# 避免冲突！

因为 WordPress 和 jQuery 预期其他可能使用短变量`$`的库将被加载。`wp_enqueue_script`确保以`noConflict`模式加载 jQuery。因此，你还需要确保使用`noConflict`模式的**语法**编写你的自定义 jQuery 代码。最简单的方法是将`$`变量（在许多 jQuery 脚本中常见）替换为完整的`jQuery`变量，正如我在第一章中讨论的，*入门：WordPress 和 jQuery*，并在我之前的两个示例中完成的那样。

## 设置你自己的 jQuery 变量

如果你觉得写出`jQuery`变量很麻烦，但又想保持在`noConflict`模式下，你可以将标准的`$`变量替换为你想要的任何变量，如下所示：

```js
<script type="text/javascript">
var $jq = jQuery.noConflict();
$jq(document).ready(function() {
$jq("p").click(function() {
alert("Hello world!");
});
});
</script>

```

## 但我真的想使用$变量！

在 WordPress 中**不应**使用`$`变量来表示 jQuery。好吧，我知道，你有一个很好的理由。比如说，你正在从另一个非 WordPress 项目复制一个 jQuery 脚本，将所有的`$`变量转换为`jQuery`或一些其他自定义快捷变量可能会很麻烦。好吧。（从未听说过“查找和替换”？）无论如何，这里是一个如何将 jQuery 快捷方式安全地使用`$`变量的示例：

```js
jQuery(function ($) {
/* jQuery only code using $ can safely go here */
});

```

上述解决方案的唯一缺点是，我发现很容易开始使用`$`变量，然后忘记将其他脚本封装在上述 jQuery 函数中。如果我的所有 jQuery 脚本都使用`jQuery`变量或自定义变量（如`$jq`），我在`noConflict`模式下会更好地工作。

### 提示

**在 WordPress 插件中包含 jQuery**

你可以使用前面提到的任何方法将 jQuery 包含到 WordPress 插件中。但是，你需要对使用 WordPress 插件有所了解。我们将在稍后的第三章中详细介绍这个主题，*深入挖掘：理解 jQuery 和 WordPress*。

# 启动 jQuery 脚本

大多数时候，你希望你的脚本在 DOM 加载和准备好后立即启动和/或可用。为此，你可以使用标准的“文档就绪”技术，如下所示：

```js
jQuery(document).ready(function(){
// Your jQuery script go here
});

```

你可以通过使用以下代码稍微简化上述代码：

```js
jQuery(function(){
// Your jQuery script go here
});

```

如果调用了`jQuery`变量并立即传递了一个函数，jQuery 会假定暗示了`.ready`事件，并在 DOM 加载完成后立即运行下一个选择器和函数。

# 我们的第一个 WordPress 和 jQuery 设置

我明白了。已经说了足够多的话。让我们开始使用 jQuery 吧。本书的大部分代码和示例使用的是 WordPress 3.0 RC 和全新的默认主题“Twenty Ten”。这是一个很棒、干净、符合 HTML5 标准的主题。即使你想增强旧版本的 WordPress，比如 2.8 或 2.9，你也会很高兴地知道，本书的每一个脚本（或其近似版本）都是最初在 2.8.6 和 2.9.2 版本中编写和测试的，然后才移植到 3.0 版本中。

在适当的情况下，我将向你展示 WordPress 2.9.2 默认主题的替代 jQuery 解决方案，并指出 jQuery 1.3.2 库（随版本 2.9.2 捆绑）与 jQuery 1.4.2 库（随 WordPress 版本 3.0 捆绑）之间的区别。

每个示例的重点不仅是向你展示如何增强 WordPress 的默认主题，而是任何主题，我希望你能发挥创造力，利用这些示例找到将它们以独特的方式应用于各种 WordPress 版本、主题和插件的方法！

## 在我们的设置中注册 jQuery

因为随 WordPress 3.0 一起提供的捆绑版本的 jQuery 也恰好是可用的最新版本的 jQuery，即 1.4.2，我将简单地导航到`wp-content/themes/twentyten`并打开`header.php`文件，然后使用基本的`wp_enqueue_script`函数来调用 jQuery，如下所示：

```js
//placed right above the wp_head function
wp_enqueue_script( 'jquery' );
wp_head();

```

## 注册您自己的自定义脚本文件

接下来，我们需要将一个单独的脚本文件包含到我们的主题中，这个文件将有我们的自定义 jQuery 脚本。我想在主题中创建一个名为`js`的目录，我将在那里保存所有我的 JavaScripts。在那个目录中，我将创建一个文件并命名为`custom-jquery.js`。

这里有个很棒的东西：你可以使用`wp_enqueue_script`来包含你写的任何脚本。你将这样做是为了宣布该脚本依赖于 jQuery，因此如果出于某种原因，jQuery 尚未加载，WordPress 将加载 jQuery！你将想把你的自定义脚本放在 jQuery 调用下面，但在`wp_head()`调用之前。

```js
...
wp_enqueue_script( 'jquery' );
wp_enqueue_script('custom-jquery', get_bloginfo('stylesheet_directory') . '/js/custom-jquery.js', array('jquery'), '20100510' );
wp_head();

```

在上述函数`wp_enqueue_script`中，我首先注册了我的脚本名为`custom-jquery`。然后在下一个参数中，我告诉 WordPress 在哪里找到我的脚本，使用`get_bloginfo`模板标记将 WordPress 导向`twentyten`主题的文件夹 "`.../js/custom-jquery.js`"。对于函数的第三个参数，我将脚本设置为依赖于`jquery`，在最后一个参数中，我简单地设置了一个版本号。我通常将这个数字设置为当天的日期。如果我更新了脚本，我会尝试更新函数中的日期，因此当主题“渲染”时，我的脚本加载起来看起来像这样：

```js
<script type='text/javascript' src='http://localhost/wp-content/themes/twentyten/js/custom-jquery.js?ver=20100510'></script>

```

这有助于浏览器“新鲜”加载脚本，而不是如果我更新了脚本，则从缓存中加载脚本。

### 提示

**之前的自定义脚本包含方法也适用于 jQuery 库本身！**

比如，在不久的将来，jQuery 更新到版本 1.4.3（或 1.5 等等），但是在 WordPress 更新并包含该版本之前还需要一段时间。你当然可以使用 Google CDN 注册最新的脚本版本，但是，如果出于某种原因，你不想使用 Google CDN，那么你可以直接从 jQuery.com 网站下载最新版本的 jQuery，并将其放置在你主题的根目录中，并使用我们刚刚用来包含我们的 `custom-jquery.js` 文件的自定义注册方法进行注册。

别忘了首先 `deregister` 绑定的 jQuery！

还有：通过 `wp_enqueue_script` 调用脚本时，同时“注册”它，因此如果使用 `wp_enqueue_script`，就不需要单独调用 `register` 函数。

## 设置自定义 jQuery 文件

最后，让我们打开 `custom-jquery.js` 文件，并使用我们之前学到的技巧，设置 jQuery 的文档就绪函数的快捷方式如下：

```js
jQuery(function(){ /*<- shortcut for document ready*/
/*any code we write will go here*/
});//end docReady

```

就是这样！让我们开始探索 jQuery 的“秘密武器”并将它们投入使用吧。现在，你可以将以下各节描述的任何代码放入你的 `custom-jquery.js` 文件中，并进行实验！

# jQuery 的秘密武器 #1：使用选择器和过滤器

是时候开始享受一些 jQuery 的乐趣了！我觉得 jQuery 可以分解为三个核心优势，我称之为它的“秘密武器”：

+   理解选择器和过滤器

+   操纵 CSS 和内容

+   处理事件和效果

如果你掌握了这三个最重要的优点，那么你就已经在成为 jQuery 的巨星的路上了！

第一项，理解选择器和过滤器，是**必不可少**的。如果你想要能够使用 jQuery 做任何其他事情，你就需要对选择器和过滤器有很强的理解能力。你在使用选择器和过滤器方面越好，你在整个 jQuery 方面就会越好。

选择器和过滤器让你有能力（你猜对了！）将页面上的对象选择到 jQuery 包装器对象中，然后以几乎任何你认为合适的方式来使用和操作它们。选择器将允许你使用简单的 CSS 语法轻松地抓取一个元素数组。过滤器将进一步缩小和精炼该数组的结果。

请记住，使用选择器和过滤器将对象选择到 jQuery 包装器中后，这些对象不再是真正的 DOM 元素了。它们是一个对象数组，位于 jQuery 对象包装器中，具有一整套可用的函数和功能。如果你有需要的话，你可以通过每个数组元素中添加的 jQuery 项目和功能来逐个逐个地找到实际的 DOM 元素，但为什么呢？jQuery 的整个目的就是为了避免你这样做，但知道它在那里也是好的。

## 从文档中选择任何你想要的东西

在接下来的示例中，我们将看看选择器和过滤器；但为了说明 jQuery 的选择，我将使用一个名为`css()`的函数。我将在后面的部分中介绍该函数和更多内容。现在，只需关注样本开头的选择器和过滤器。

jQuery 选择器的本质是它们基于 CSS 语法。这意味着大多数人会发现，您可以非常容易地使用 jQuery，就像您如何使用 CSS 来定位和样式化页面上的特定元素一样。

选择在主要 jQuery 函数的开头声明：

```js
jQuery(function(){
jQuery("selector:filter").jqFunctionName();
});

```

您还可以根据 CSS 语法将以下元素选择到 jQuery 包装器中：

+   HTML **标签名称**，如 `body, p, h1, h2, div` 等等

+   使用在 CSS 中用 `#`（井号）表示的**id 属性**，如`#header`或`#sidebar`。

+   以及**类属性**，在 CSS 中用`.`（点）表示，如`.body`或`.post`

当然，您可以使用 CSS 中允许的任何组合来定位元素，您也可以使用 jQuery 执行。例如：

+   `标签`（空格，或无空格）`#id` 或 `.className`，例如 `div#sidebar li`—这将抓取`sidebar` ID 名称中的 `div` 中的 *所有* `li` 实例

+   `标签`，（逗号）`.class` 如 `p, .post`—逗号确保这将抓取所有 *要么* 是段落 *要么* 用`.post`类标记的内容

为了澄清，就像在 CSS 中一样，您也可以使用**语法**来*结构化*选择器：

+   逗号表示选择此元素，（和）此元素。例如：`div, p`（选择所有`div`标签*和*所有`p`标签）。

+   空格表示选择此元素（其中有）此元素在内部。例如：`div p .className`（选择所有具有段落`p`标签的`div`标签，其中 *带有* 任何其他分配给`.className`类的元素 *在* `p` 标签内）。

+   最后，**没有空格** 将表示直接应用于元素而不仅仅是包含在其中的类：`p.className`（选择所有带有`.className`分配的段落 `p` 标签。这将 *不会* 选择具有相同`.className`类分配的 `div` 标签）。

除了标准的 CSS 逗号空格和附加的 id 和类名之外，在 jQuery 中，您还可以使用这些额外的符号来澄清您的选择：

+   大于号 `>` 仅会查找符合选择条件的父元素的子元素。

    例如，`.post > p` 将找到直接位于 `.post` 类中的段落 `p` 标签。在 `.post` 类内部的不同类中的 `p` 标签 *将不* 被选择。

让我们比较 `".post（空格）p"` 和 `".post> p"` 并查看结果。

在我们的第一个示例中，我们将如下检查代码：

```js
jQuery(function(){
jQuery(".post p").css("background", "#f60");
});

```

请注意，此代码生成类似于下一个截图的输出，显示了所有段落的高亮显示，即使它们嵌套在具有名为`.entry-content`的类中：

![从文档中选择任何您想要的内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_01.jpg)

然而，让我们看一下这个代码示例：

```js
jQuery(function(){
jQuery(".post > p").css("background", "#f60");
});

```

让我们也看一下以下截图。我们发现没有段落被突出显示，因为它们位于另一个具有名为 `.entry-content` 的 `div` 标签内，因此 *不* 是 `.post` 的子元素。

![从文档中选择任何你想要的内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_02.jpg)

`+` 选择器将找到与匹配选择器相匹配的所有 *下一个* 元素。例如：`li + li` 将选择列表中每个列表项 `li`，*除了* 第一项。只有与该第一项 *相邻* 的项目如下所示：

```js
...
jQuery("li + li").css("background", "#f60");
...

```

以下截图说明了这一点：

![从文档中选择任何你想要的内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_03.jpg)

`~` 选择器将找到选择器的所有兄弟元素。例如：`li ~ li` 将选择列表中除第一项之外的每个列表项，只选择该第一项的兄弟项。代码示例如下：

```js
...
jQuery("li ~ li").css("background", "#f60");
...

```

由于兄弟元素通常紧邻被选定的项，因此 `+` 和 `~` 选择器通常会获得类似的结果。注意以下截图与上一截图相似：

![从文档中选择任何你想要的内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_04.jpg)

## 过滤这些选择

很多人可能只需使用基本的 CSS 样式选择器就能满足大部分需求。但是，等等，还有更多！过滤器是我发现非常有用的选择部分，特别是考虑到我们正在使用 WordPress。同样，对于 WordPress 主题，你的许多 HTML 元素、ID 和类名可能是由你不是作者的主题生成的，或者由于各种原因，你不想编辑它们，或者你可能被禁止编辑主题。（什么？设计师在开发人员开始编辑他们的标记时有点“暴躁”？我不知道。）但没关系。有了过滤器，你根本不必担心。

问题是，初学 jQuery 时，想要去更改 HTML 标记以便更容易地用 jQuery 进行选择是很诱人的。但是在 WordPress 中，这并不容易。更改标记意味着你有可能破坏主题，或者更糟糕的是，不得不提醒内容编辑者手动向帖子和页面添加特定标记（在某些方面，这有悖于使用 WordPress 的初衷）。理解过滤器将允许你在每种情况和场景中对你的选择进行精确控制，每一次。

很容易细化过滤器，你只需包括这些项目，它们将获取你选定的元素并将它们与特定条件匹配，例如它们相对于其他元素的位置或索引。同样，为了符合 CSS 选择语法的精神，一些这些过滤器看起来类似于 **CSS 伪类**，例如 `:hover` 和 `:first-child`。这些实际上并不都是 CSS 伪类；它们在 CSS 样式表中不起作用，但在 jQuery 中会起作用。

这些筛选器在 jQuery API 中分为以下类别（按我发现它们在 WordPress 开发中最有用的顺序列出）：基本筛选器、内容筛选器、子筛选器、表单筛选器、属性筛选器和可见性筛选器。

### 基本筛选器

当你使用 WordPress 时，我相信你会发现`:not()`筛选器和`:header`筛选器非常有用。`:header`筛选器允许你简单地选择*所有*选择中的标题，无论它们是什么级别的标题。而不是必须选择`h1`和`h2`等等，将`:header`筛选器添加到你的选择器中将抓取所有标题，从`h1`到`h6`都包含在包装器中。在你的`custom-jquery.js`文件中试一试，并添加以下代码（不要担心`.css(...)`；代码的一部分；我们稍后会讲到这一点。我只是用它来帮助我们可视化 jQuery 可以做什么）：

```js
jQuery(function(){
jQuery(":header").css("background", "#f60");
});

```

在下一个屏幕截图中，你将看到所有标题都被选择了，`h1, h2`，等等：

![基本筛选器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_05.jpg)

我最喜欢的筛选器是`:not`筛选器。曾经在飞机上有没有注意到，你经常被提醒“最近的出口可能在你身后”？同样的原则适用于当你试图将正确的元素装入你的 jQuery 包装器时。有时候告诉 jQuery 你*不*想要包装器中的东西会更容易！我曾经使用一个主题，里面有一些非常漂亮的电子邮件和 PDF 图标元素隐藏在`.post`类中。主题没有`.entry`类。这很烦人，因为我想对加载到 WordPress 文章中的图像应用一般的转换，但这些图标受到了影响！主题作者将它们包装在一个名为`.postIcons`的类中。使用`:not()`筛选器，我能够转换所有在`.post`类中但*不*在`.postIcons`类中的`img`标签。太棒了。

加上前述的`:header`选择器后再加上`:not`筛选器，看看会发生什么：

```js
...
jQuery(":header:not(li :header)").css("background", "#f60");
...

```

以下筛选器现在显示我们已选择所有标题，除了列表项中的标题：

![基本筛选器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_06.jpg)

你可能已经从前面的例子中注意到了，你可以在选择器中巧妙地使用筛选器，多次使用它们。

你说什么？没错，你说得对：`(":headers:not(li h2)")`会得到与前面例子*完全相同*的结果，而且是始终更好地选择最直接的路径来进行选择。我只是试图说明这两个筛选器如何使用。最终，你会遇到更复杂的情况，它们会非常有用。对于其他情况，在使用筛选器之前，先使用普通选择器。

让我们逐个查看每个基本过滤器，看看它的语法是什么样的，以及它的详细功能。因为大多数 WordPress 主题作者使用`.post`类，而且大多数时候你将会以文章元素为目标，所以使语法更有意义。我在示例中经常使用`.post`类名，但请记住，您的主选择器可以是 CSS 选择器语法中使用的任何`tag、id`名称或`class`名称！

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| :not(selector) | `jQuery(".post img:not(.pIcon)").jqFn()`; | 过滤掉所有匹配给定选择器的元素。 |
| :header | `jQuery(".post:header").jqFn()`; | 过滤到所有标题元素，例如 h1、h2、h3 等。 |
| :first | `jQuery(".post:first") .jqFn()`; | 仅过滤到第一个选定的元素。 |
| :last | `jQuery(".post:last") .jqFn()`; | 仅过滤到最后一个选定的元素。 |
| :even | `jQuery(".post:even") .jqFn()`; | 仅过滤到偶数元素。注意：数组是从零开始索引的！零被视为偶数，因此您的第一个项目将被选中！ |
| :odd | `jQuery(".post:odd") .jqFn()`; | 仅过滤到奇数元素。注意：数组是从零开始索引的！零被视为偶数，因此您的第二个项目将被选中！ |
| :eq(number) | `jQuery(".post:eq(0)") .jqFn()`; | 通过其索引过滤到单个元素，这再次是从零开始计数的。 |
| :gt(number) | `jQuery(".post:gt(0)") .jqFn()`; | 过滤到所有索引**大于**给定索引的元素，再次强调，这是从零开始计数的。 |
| :lt(number) | `jQuery(".post:lt(2)") .jqFn()`; | 过滤到所有索引**小于**给定索引的元素。 |
| :animated | `jQuery(".post:animated").jqFn()`; | 过滤到当前正在进行动画的所有元素（我们将在本章后面讨论动画）。 |

### 子过滤器

在 jQuery 包装器中的任何内容都是一个数组，这些子过滤器会派上用场，但当你使用`li`标签或在 WordPress 中使用定义列表元素时，你可能会发现这些过滤器最有用。默认情况下，WordPress 将相当数量的链接内容拆分为 `li` 标签元素和画廊，这些画廊是通过将图像和描述包装在定义列表 (`dt dd` 元素) 中创建的。

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| :nth-child(number/even/odd) | `jQuery(".linkcat li:nth-child(1)").css("background", "#f60")`; | 过滤到其选择器的“nth”子元素。请注意，这**不是**从零开始计数的！`1` 和 odd 选择**第一个**元素。 |
| :first-child | `jQuery(".linkcat li:first-child").css("background", "#f60")`; | 过滤到其父元素的第一个子元素。 |
| :last-child | `jQuery(".linkcat li:last-child").css("background", "#f60")`; | 过滤到其父元素的最后一个子元素。 |
| :only-child | `jQuery(".pagenav li:only-child").css("background", "#f60")`; | 筛选出只是其父元素的唯一子元素的元素。如果父元素有多个子元素，则不选中任何元素。 |

在这里您可以看到`only-child`过滤器的运行情况：

```js
...
jQuery("li:only-child").css("background", "#f60");
...

```

![子过滤器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_07.jpg)

这是`nth-child`过滤器在 Meta 列表中的示例：

```js
...
jQuery(".widget_meta li:nth-child(odd)").css("background", "#f60");
...

```

![子过滤器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_08.jpg)

### 内容过滤器

在基本和子过滤器之后，您将遇到的下一个最有用的过滤器是内容过滤器。内容过滤器允许您基于**匹配**各种类型的元素和内容进行选择。我经常在 WordPress 中使用的最有用的内容过滤器是`:has()`过滤器。我经常需要选择具有*内部内容*的元素，比如内部包含`img`图像标签的锚`a`标签，或者内部包含列表`li`标签的段落`p`标签，或者内部包含特定类名的其他元素。定位特定对象很容易，但如果您发现需要基于内部包含的元素类型来定位一个更大的父对象，`:has()`过滤器将成为您的好朋友。

接下来最有用的项目是`:contains()`元素，乍看之下，可能与`:has()`非常相似！但这个过滤器非常不同（而且非常酷），因为它允许您定位元素内的特定*文本*。

对于这两种过滤器要小心，尽量做好尽可能多的“预选”。确保 jQuery 针对您尝试选择的元素和文本指向正确的方向。仅仅指定 `...(p:contains('my text'))..`. 可能对于大量内容的页面太泛，会导致 jQuery 延迟，或者更糟糕的是，由于它必须搜索页面上每一个小的 `p, div` 或 `a` 元素的文本或元素，而导致挂起和超时。一个明确指定了 `...(#divIdName .className a:contains('my text'))...` 的 jQuery 要好得多，因为 jQuery 只需要搜索指定 ID 容器内指定类的文本中的每个 `a` 元素，而不是整个页面的内容。

让我们更详细地看一下以下内容过滤器：

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| :has(selector) | `jQuery(".post:has(.entry)") .css("background", "#f60")`; | 筛选出至少有一个匹配元素内部的元素。 |
| :contains(text) | `jQuery(".post:contains('Hello world')").css("background", "#f60")`; | 筛选出包含特定文本的元素。注意：这是**区分大小写的！** |
| :empty | `jQuery(":empty')") .css("background", "#f60")`; | 筛选出没有子元素的元素。这包括文本节点。 |
| :parent | `jQuery(":parent')") .css("background", "#f60")`; | 筛选出是另一个元素的父元素的元素。这包括了文本节点。 |

举个详细的例子，让我们看一下默认主题的侧边栏。侧边栏有一些项目，没有用特殊的`id`名称或`class`进行标注。如果我想要定位仅在 Meta 标题下的`ul`列表，我可以使用`:has()`和`:contains()`来定位它。注意我如何“直接”告诉 jQuery，先预先选择或指向`.widget-area li`标签，这样 jQuery 在我告诉它查找子元素和包含的文本*之前*会忽略页面的其余部分。

您可以在下一个截图中看到以下代码的结果：

```js
...
jQuery(".widget-area li:has(h3:contains('Meta')) ul")
.css("background", "#f60");
...

```

![内容过滤器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_09.jpg)

### 表单过滤器

如果所有之前的选择器和过滤器还不够酷，你还可以明确过滤到几种类型的表单元素，以及这些元素的事件类型。使用这些过滤器，您将能够控制 WordPress 生成的评论表单以及自定义和 WordPress 插件表单，并使它们更直观和易于使用。在本书的后面，我们将看到 jQuery 如何使表单使用和验证变得非常简单。

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| :input | `jQuery("form:input").css("background", "#f60")`; | 过滤到所有输入、文本区域、选择和按钮元素 |
| :text | `jQuery("form:text").css("background", "#f60")`; | 过滤到所有类型为文本的输入元素 |
| :password | `jQuery("form:password").css("background", "#f60")`; | 过滤到所有类型为密码的输入元素 |
| :radio | `jQuery("form:radio").css("background", "#f60")`; | 过滤到所有类型为单选框的输入元素 |
| :checkbox | `jQuery("form:checkbox").css("background", "#f60")`; | 过滤到所有类型为复选框的输入元素 |
| :submit | `jQuery("form:submit").css("background", "#f60")`; | 过滤到所有类型为提交的输入元素 |
| :image | `jQuery("form:image").css("background", "#f60")`; | 过滤到所有图像元素（分类为表单过滤器，但对常规图像也有用） |
| :reset | `jQuery("form:reset").css("background", "#f60")`; | 过滤到所有类型为 reset 的输入元素 |
| :button | `jQuery("form:button") .css("background", "#f60")`; | 过滤到所有类型为按钮的输入元素 |
| :file | `jQuery("form:file").css("background", "#f60")`; | 过滤到所有类型为文件的输入元素 |

使用以下代码，我只突出显示了`text`输入和`submit`按钮，如下一个截图所示：

```js
...
jQuery(":text, :submit").css("background", "#f60");
...

```

![表单过滤器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_10.jpg)

### 属性过滤器

属性就是在 HTML 标签内部找到的附加属性，允许标签自我完善。你可能最熟悉`id`和`class`属性，以及`img`和`script`标签的`src`属性，当然还有`a`标签的`href`属性。

属性是用于定义和细化 HTML 元素的强大属性，因此您可以想象使用它们进行过滤有多么强大。确实强大，但请记住，选择将项目放入 jQuery 包装器中的最简单和最直接的方法通常是最好的。我的示例将展示不同类别的选择，因为它们创建了漂亮的视觉示例，但实际上，最好使用常规选择器来定位类别项，并保留属性过滤器用于更精细、棘手的工作。

您会注意到这些过滤器与其他过滤器有所不同。而不是使用`:`（冒号标记），这些过滤器使用`[]`（方括号）。这意味着您可以轻松看到在您的选择器语法中，是否在过滤属性。您还会注意到，在 HTML 的 DOM 中的每个属性中，您都可以为其进行过滤。没有标准的“属性过滤器名称”集合；您只需使用方括号来指示您想要过滤的任何属性。您甚至可以以几种方式构建属性过滤器：

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| [attribute] | `jQuery("div [href]").css("background", "#f60")`; | 过滤一个属性，无论其值如何 |
| [attribute=value] | `jQuery("div [class='entry']").css("background", "#f60")`; | 过滤属性和*精确*指定的值 |
| [attribute!=value] | `jQuery("div [class!='entry']").css("background", "#f60")`; | 过滤不具有指定值的属性 |
| [attribute^=value] | `jQuery("div [href^='http://']").css("background", "#f60")`; | 过滤具有以特定字符串*开头*的值的属性 |
| [attribute$=value] | `jQuery("div [href$='/']").css("background", "#f60")`; | 过滤具有以特定字符串*结尾*的值的属性 |
| [attribute*=value] | `jQuery("div [href*='page_id']").css("background", "#f60")`; | 过滤包含特定字符串的属性 |

在这里，我们可以通过以下 jQuery 代码查看仅针对侧边栏中的本地链接进行定位：

```js
...
jQuery(".widget-area [href^='http://localhost']").css("background", "#f60");
...

```

以下截图显示了结果，只有指向 WordPress 安装的`localhost`链接被突出显示：

![属性过滤器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_11.jpg)

### 可见性

我把这两个过滤器放在最后，主要是因为在我大多数的 WordPress 项目中我很少使用它们，但它们是选择器/过滤器 API 的一部分，所以我会在这里介绍它们。

大多数情况下，你使用 jQuery 需要操作的元素默认是可见的。但偶尔会有一些通过 jQuery 转换隐藏的项目或者隐藏的表单字段，你可能需要对它们进行转换。对于这种情况，你可以使用 `:hidden` 过滤器。这有点棘手，因为你已经将项目选中到你的包装器中，但你不一定会看到任何转换（除非转换是使其可见的）。如果你发现自己有很多隐藏的元素，你可以随时过滤出可见的元素，如果这样更容易的话。

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| :hidden | `jQuery("form:input:hidden") .css("background", "#f60")`; | 用于选择显示值为 none 或类型值为 hidden 或具有显式宽度和高度为 `0` 的元素的过滤器 |
| :visible | `jQuery("div .post:visible") .css("background", "#f60")`; | 用于选择可见元素的过滤器 |

### 注意

我已经涵盖了我作为 WordPress 开发者最常使用的主要选择器和过滤器。务必查阅 jQuery 文档，了解所有按字母顺序列出的选择器和过滤器：[`api.jquery.com/category/selectors/`](http://api.jquery.com/category/selectors/)。

# jQuery 的秘密武器 #2：操作 CSS 和 DOM 中的元素

现在我们可以可靠地选择 WordPress 网站在页面上显示的任何 *对象*，让我们开始操纵和增强我们的选择！我们可以操作显示我们对象的 CSS 样式，如果这还不够酷，我们还可以在 DOM 中操作 HTML 对象本身。让我们开始操作 CSS。

## 操作 CSS

到目前为止，我们所看到的关于选择器和过滤器的所有内容都是必不可少的，用于定位你想要影响的元素。现在你可以将任何你想要的东西选入到包装器中了，让我们开始做些事情吧！多亏了之前的所有示例，你已经熟悉了 `css()` 函数。大多数情况下，你会使用这个函数来赋予标准的 CSS 属性值，比如：`background、border、padding、margins` 等等。如果你可以在 CSS 样式表中分配属性，你也可以使用 `css()` 函数来分配它。你还可以使用这个函数检索和获取 CSS 属性。

在 jQuery 的属性 API 中，你会发现更多的 CSS 操作特性，比如 `.addClass、.removeClass` 和 `.toggleClass`。这三个函数单独就能给你很大的动态化你的 WordPress 网站的能力。不要被我继续谈论属性所迷惑了！我们不再处理选择器和过滤器了。我们正在处理允许你操作这些选择的函数。让我们详细了解一下 jQuery 的 CSS 和类属性操作函数：

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| .css('property', 'value') | `jQuery(".post") .css("background", "#f60");` | 添加或更改所选元素的 CSS 属性。 |
| .addClass('className') | `jQuery(".post") .addClass("sticky");` | 将所列类添加到每个所选元素中。 |
| .removeClass('className') | `jQuery(".post") .removeClass("sticky");` | 从每个所选元素中删除所列类。 |
| .toggleClass('className', switch-optional) | `jQuery(".post") .toggleClass("sticky");` | 根据它们当前的状态，从每个所选元素中切换所列类。如果类存在，则删除，如果不存在，则添加。 |
| .hasClass('className') | `jQuery(".post") .hasClass("sticky");` | 如果每个所选元素中存在所列类，则返回 true 或 false。 |

让我们通过向所有帖子添加默认主题的`sticky`类来检查一下`addClass()`函数。

### 注意

当进行选择时，您需要从`id`名称和`tag`名称中标注`class`名称，但在这些 jQuery 类属性函数中，您只需要输入类名。您不需要用"."来表示它。该函数只期望一个类名，因此不是必需的。正如您可能期望的那样，您显然不能使用`addClass`函数向选择添加`id`名称（不好意思，没有`addId`函数！）

```js
...
jQuery(".post").addClass("sticky");
...

```

现在，您可以在下一个截图中看到，通过 jQuery 而不是 WordPress，已将`.sticky`类添加到所有`.post`类中！

![操纵 CSS](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_12.jpg)

### 操纵属性

您也可以影响特定对象的属性（这对于切换我们的图像路径很方便，并提供了与`class`名称甚至`object`ID 名称一起使用的另一种方法）

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| .attr | `jQuery(".post") .attr();` | 检索所选元素的第一个元素的属性值 |
| .removeAttr | `jQuery(".post a") .removeAttr("href");` | 从每个所选元素中移除一个属性 |

### 提示

**CSS 的更多控制力：**

如果您需要以友好的跨浏览器方式处理 HTML 对象，那么很容易检索并设置任何目标选择器上的一系列属性、高度和宽度变量。偶尔，这些变量会派上用场，但您会发现大部分工作都是在前一个表中列出的函数中完成的。尽管如此，您可能会想查看 jQuery 的 CSS API 下的定位、高度和宽度函数：[`docs.jquery.com/CSS`](http://docs.jquery.com/CSS)。

## 操纵元素和内容

jQuery 的 API 中的 Manipulation 部分再次非常广泛，但我发现其中一些函数对帮助我的 WordPress 和 jQuery 的增强非常有用。例如，如果你想要制作可展开或可收起的内容，你将需要一个元素来处理该事件，而不是每次都进入每篇文章并添加控制按钮（或提醒你的客户或站点编辑在每篇文章中添加控制链接或按钮 —— 是的，他们会这样做）。你可以使用 jQuery 在运行时添加和删除内容和 HTML 元素。

最有用的函数是 `prepend()` 和 `append()` 函数，允许您在选择之前或之后包含文本。这些函数允许您专注于内容，或者是选择器内的特定选择器，以便您更容易地进行目标选择。

接下来最有用的函数是 `before()` 和 `after()` 以及 `instertBefore()` 和 `instertAfter()` 函数。如果你发现需要在类名或 HTML 元素内部包装元素以添加额外的样式，那么使用 `wrap()` 函数就没问题了。你甚至可以删除和克隆元素！让我们更详细地看一下这些操作函数。

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| .append(html 和 text) | `jQuery(".post") .append("<b>文章在这里结束</b>");` | 将参数中的内容插入到每个选定元素的末尾。 |
| .appendTo(selector) | `jQuery("<b>文章在这里结束</b>").appendTo(".post");` | 执行与 append 相同的操作，只是反转了元素选择和内容参数。 |
| .prepend(html 和 text) | `jQuery(".post") .prepend("<b>文章从这里开始</b>");` | 将参数中的内容插入到每个选定元素的开头。 |
| .prependTo(selector) | `jQuery("<b>文章从这里开始</b>").prependTo(".post");` | 执行与 prepend 相同的操作，只是反转了元素选择和内容参数。 |
| .after(string) | `jQuery(".post") .after("<b>这个在后面</b>");` | 将参数中的内容插入到每个选定元素之后并在外部。 |
| .insertAfter(selector) | `jQuery("<b>这个在后面</b>").insertAfter(".post");` | 执行与 after 相同的操作，只是反转了元素选择和内容参数。 |
| .before(HTML 和 text) | `jQuery(".post") .before("<b>这个在前面</b>");` | 将参数中的内容插入到每个选定元素之前并在外部。 |
| .insertBefore(selector) | `jQuery("<b>这个在前面</b>") .insertBefore("class");` | 执行与 before 相同的操作，只是反转了元素选择和内容参数。 |
| .wrap(html 或 functionName) | `jQuery(".post").wrap("<div class=".fun" />");` | 在每个选定元素周围包装一个 HTML 结构。您还可以构造一个将每个元素包装在 HTML 中的函数。 |
| .wrapAll(HTML) | `jQuery(".post").wrapAll("<div />");` | 类似于 wrap，但将 HTML 结构放置在所有元素周围，而不是每个单独的元素周围。 |
| .wrapInner(selector) | `jQuery(".post") .wrapInner("<div class=".fun" />");` | 类似于包装，但它将 HTML 结构放置在所选元素的每个文本或子元素周围。 |
| .html(HTML 和文本) | `jQuery(".post") .html("<h2>替换文本</h2>");` | 用参数中的内容替换所选项的任何内容和子元素。 |
| .text(仅限文本 HTML 字符将被转义) | `jQuery(".post") .text("替换文本");` | 类似于 HTML，但只限文本。任何 HTML 字符都将被转义为 ASCII 代码。 |
| .empty(selector) | `jQuery(".post").empty(".entry");` | 删除所选元素的任何内容和子元素。保留元素。 |
| .remove(selector) | `jQuery(".post").remove()`; | 类似于 empty 但删除整个元素。 |
| .clone(selector) | `jQuery(".post").clone()`; | 复制所选元素。 |

在这里，我们可以看到使用这些类型的函数是多么容易：

```js
...
jQuery(".post").append("<div style='text-align:right;
border-bottom: 1px solid #333'>End of Post</div>");
...

```

上述 jQuery 脚本将在以下截图中为每篇文章的末尾添加**文章结束**：

![操作元素和内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_13.jpg)

## 操作 DOM

使用 jQuery，您实际上可以遍历和处理 DOM 本身，而不仅仅是处理 jQuery 包装器集中的元素（请记住，这些不再是纯粹的 DOM 元素数组）。为了直接处理 DOM，您可以使用一些 jQuery 函数和属性。jQuery 的文档站点本身列出了大约 20 或 30 个函数，您可以使用这些函数来帮助您遍历 DOM，尽管再次强调，与 WordPress 一起工作时，您很可能不需要直接处理它。我最常使用的是 jQuery 的核心部分，而不是遍历 API 找不到的，但我使用它们类似于帮助我细化和导航 DOM 对象。 

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| .length 或 size() | `jQuery(".post") .length;` | 返回所选集合中的元素数量。 |
| .get(数字-可选) | `jQuery(".post") .get(3);` | 这将返回原生 DOM 元素的数组。如果您不想直接处理 DOM 而不是 jQuery 包装元素，这将很方便。 |
| .find(selector) | `jQuery(".post") .find(".entry b");` | 返回与查找函数的选择器匹配的第一个选择器内的 jQuery 元素的数组。 |
| .each(functionName) | `jQuery(".post") .each(function(){//code});` | 这将对与 jQuery 选择器匹配的每个元素运行一个函数。 |

由于这些函数返回数字和数组，您将发现它们在故障排除时最有用。要轻松引用其中一个函数，我只需设置带有我的 jQuery 语句的 `alert()` 函数，如下所示：

```js
...
alert("How many posts does this blog have? "+jQuery(".post").length);
jQuery(".post").each(function(){
alert("one alert for each .post")
});
...

```

您可以在以下截图中看到结果警示：

![操作 DOM](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_14.jpg)

### 提示

**一定要查看完整的遍历函数。**

再次强调，jQuery 的目的是让你摆脱 DOM 的细节，但随着你对 jQuery 的运用变得更加复杂，你不想忘记这些函数在[`docs.jquery.com/Traversing`](http://docs.jquery.com/Traversing)可以使用。

你也可以更仔细地查看 jQuery 核心部分在[`docs.jquery.com/Core`](http://docs.jquery.com/Core)。

# jQuery 秘密武器#3：事件和效果（又名：锦上添花）

好了，你是*选择*大师；你可以从任何人的 CSS 和 WordPress 主题中获取任何你想要的东西，你可以*操纵*这些选择的 CSS 属性和属性，直到牛回到家。仅从这些第一个例子中，你可能已经设法想出了自己的令人印象深刻的 jQuery 增强功能。但等等，还有更多！让我们用事件和效果把它们结合起来。

## 处理事件

你可以使用 jQuery 处理很多事件。你可以手动**绑定**和**解绑**元素的事件，你可以引用**统一事件对象**，还可以使用事件助手。我们暂时不会深入研究 jQuery 的统一事件对象，现在先看一下开始处理事件的最直接方法。

### 助手非常有用！

辅助函数，也经常被称为“快捷方式”，让你可以轻松地设置点击或悬停事件。你也可以轻松地切换事件。在 CSS 操作部分，我们看到了`toggleClass()`函数是多么有用；想象一下能够切换*更多*的函数。

大多数情况下，`hover()`函数能够满足你的需求，但如果你想要的是点击事件，那么`toggle()`函数可能是最合适的。`toggle()`函数比`hover`更灵活一些，因为你可以添加额外的函数，而不仅仅限于一个或两个函数。

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| .click(functionName) | `jQuery(".post") .click(function(){//code});` | 绑定一个要在单击时执行的函数到`click`事件类型。 |
| .dbclick(functionName) | `jQuery(".post") .dbclick(function(){//code});` | 绑定一个函数到`click`事件类型，当双击时执行。 |
| .hover(functionName1, functionName2) | `jQuery(".post") .hover(function(){//code});` | 适用于`mouseenter/mouseleave`事件类型，为所选元素绑定两个函数，分别在`mouseenter`和`mouseleave`时执行。 |
| .toggle(functionName1, functionName2, functionName3, etc) | `jQuery(".post") .toggle(function(){//code});` | 适用于`click`事件类型，为所选元素绑定两个或更多函数，交替执行。 |
| .mouseenter(functionName) | `jQuery(".post") .mouseenter(function(){//code});` | 绑定一个要在鼠标进入所选元素时执行的函数。 |
| .mouseleave(functionName) | `jQuery(".post") .mouseleave(function(){//code});` | 绑定一个函数，在鼠标离开选定的元素时执行。 |
| .keydown(functionName) | `jQuery(".post") .keydown(function(){//code});` | 将一个函数绑定到`keydown`事件类型，仅在选定的元素有 *焦点* 且按键按下时执行。 |
| .keyup(functionName) | `jQuery(".post") .keyup(function(){//code});` | 将一个函数绑定到`keyup`事件类型，仅在选定的元素有 *焦点* 且按键后释放时执行。 |

随着事件的发生，页面更加活跃和动态。让我们在侧边栏导航项目上设置一个非常简单的悬停效果：

```js
...
jQuery(".widget-area li ul li").hover(function(){
jQuery(this).css("background", "#f60");
},
function(){
jQuery(this).css("background", "none");
});
...

```

![助手非常有用！](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_15.jpg)

### 使用 bind、unbind 和事件对象

我们只需快速概述这些函数；使用这种方法有点过火，但在特定情况下可能会派上用场，如果没有其他办法，它会让你感激 jQuery 提供的所有辅助快捷函数。

有时，您可能需要真正细化事件的控制，并使用`bind()`和`unbind()`函数，您很可能会为自己处理这些问题。您可以传递事件类型的参数，例如`click`或`mouseenter`；您也可以传递一些数据以及事件处理程序（或者您可以调用另一个函数）。数据是一个可选参数，这超出了本章的范围，但对于那些真正对使用 jQuery 进行开发感兴趣的人来说，知道您可以传递数据是很有用的（即使在本章中，我们也会稍微提及）！

让我们仔细看看并分解这些函数的各个部分：

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| .bind(event type, data, functionName) | `jQuery(".post").bind("mouseenter", function(){//code})`; | 将一个函数附加到选定元素上触发的事件类型。 |
| .unbind(event type, functionName) | `jQuery(".post").bind("mouseenter", function(){//code})`; | 从选定的元素中移除事件类型。 |

我们可以通过使用`bind`和`unbind`来重新创建我们用 hover 类实现的效果。这有点麻烦，最终并不是实现简单悬停效果的最优雅方式。`bind`的优点是可以传递数据。以下示例演示了传递数据，即我们背景的颜色，到事件的函数：

```js
...
jQuery(".widget-area li ul li").bind("mouseenter", {color: "#f60"}, function(event){
jQuery(this).css("background", event.data.color);
jQuery(this).unbind("mouseleave");
});
jQuery(".widget-area li ul li").bind("mouseleave", function(){
jQuery(this).css("background", "none");
jQuery(this).unbind("mouseenter");
});
...

```

在前面的代码示例中，我们使用了 jQuery 的事件对象来传递数据。使用数据，统一的事件对象返回可以帮助您创建精细的 jQuery 转换，我经常使用对象的信息来帮助传递事件信息到函数中以获得更干净的代码，并帮助我进行故障排除。

| 示例 | 描述 |
| --- | --- |
| `event.type` | 返回事件类型，例如点击或`mouseenter`或`keyup`。 |
| `event.target` | 返回触发事件的选定元素。 |
| `event.data` | 返回并包含通过绑定函数传递的可选数据。 |
| `event.pageX, .pageY` | 确定鼠标相对于文档左边缘（pageX）或顶部（pageY）的位置。 |
| `event.result` | 返回由由此事件触发的事件处理程序返回的最后一个值。用于故障排除非常有用。 |
| `event.timeStamp` | 返回触发事件的 Unix 时间戳。 |

下面的代码将跟踪单击事件对象属性：

```js
...
jQuery(".post").click(function(event){
jQuery(this).html("event type: "+event.type+"<br/>event timestamp: "+event.timeStamp+"<br/>event x: "+event.pageX+"<br/>event y: "+event.pageY);
});
...

```

下面是一个你可能会发现有用的事件对象函数——`preventDefault()函数`。它可以阻止元素的默认操作。最常见的例子是使`link`标签不执行其`href`。如果你需要知道一个元素的默认事件是否已经调用了这个函数，你可以使用`isPreventDefault()`函数进行测试。

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| .preventDefault() | `jQuery(.post a).preventDefault()`; | 将阻止所选元素执行其浏览器设置的默认操作。 |
| .isPreventDefault() | `jQuery(.post a).isPreventDefault()`; | 如果在一组选定的元素上调用了`ispreventDefault`，则返回 true 或 false。 |

## 添加效果

所以现在我们准备好了本章的有趣部分——添加华丽的效果。jQuery 库为我们提供了一些非常基本的动画和效果函数。这些都是视觉效果，如显示和隐藏，淡入淡出，向上和向下滑动，或者使用`animate`函数在屏幕上移动元素，更精确地说。大多数人都会对标准的快捷动画函数感到满意，但我们也会看一下`animate`函数。

这些函数中的大多数也允许使用回调函数，这使得在元素动画完成时触发其他动画或功能变得容易。让我们开始使用效果和动画吧。

### 显示和隐藏

关于显示和隐藏的第一件事情要注意的是，目标元素的大小和淡入淡出效果会受到影响。如果你只想淡化或影响大小，那么你需要查看其他动画函数。你也可以非常容易地使用我们之前讨论过的`toggle`事件来帮助你的效果。

| 示例 | 语法 | 描述 |
| --- | --- | --- |
| .show(speed-optional, functionName) | `jQuery(".post") .css("background", "#f60").show("slow")`; | 显示匹配的元素；如果设置了速度，对象从左到右增长，alpha 淡入从 0 到 1。完成后可以调用一个函数。速度可以是"slow"或"fast"或毫秒。 |
| .hide(speed-optional, functionName) | `jQuery(".post") .css("background", "#f60").show(200)`; | 类似于 show 但是隐藏。如果设置了速度，元素会从右到左收缩，alpha 渐隐从 1 到 0。完成后可以调用一个函数。速度可以是"slow"或"fast"或毫秒。 |

### 滑入和滑出

你会注意到显示和隐藏对象是从右到左“增长”的。滑动是一种优雅的处理打开和关闭元素的方式，带有更直接的上下运动。

| 例子 | 语法 | 描述 |
| --- | --- | --- |
| .slideUp(speed, 函数名称) | `jQuery(".post") .slideUp('slow', function() {``// 代码``})`; | 从底部向上滑动所选元素，直到它被隐藏。速度可以是“快”或“慢”，也可以是毫秒数。动画完成时可以调用函数。 |
| .slideDown(speed, 函数名称) | `jQuery(".post") .slideDown('slow', function() {``// 代码``})`; | 从顶部向下滑动隐藏的所选元素，直到其大小被定义。速度可以是“快”或“慢”，也可以是毫秒数。动画完成时可以调用函数。 |
| .slideToggle() | `jQuery(".post") .slideToggle('slow', function() {``// 代码``})`; | 使用幻灯片动画切换所选元素的可见性。速度可以是“快”或“慢”，也可以是毫秒数。动画完成时可以调用函数。 |

### 淡入和淡出

良好的淡入淡出效果也很好。我想指出的是，`fadeIn()` 和 `fadeOut()` 只有在从 alpha 为 `0` 或 `1` 开始时才有效。例如：`fadeOut` 只有在元素的 alpha 设置为 `1` 时才有效，而 `fadeIn` 只有在元素的 alpha 设置为 `0` 时才有效。

我还想指出，如果之前使用了 `fadeTo()` 函数来淡出到特定的 alpha 数字，然后尝试全部`fadeOut()` 或全部`fadeIn()` ，这是行不通的。继续使用 `fadeTo()` 函数来平滑地进行渐变效果。此外，当使用 `fadeOut()` 时，一旦元素的 alpha 为 `0`，它就会完全消失。它所占用的任何空间都会发生一种相当惊人的坍塌效果。在决定使用 `fadeOut()` 时，请考虑此因素。

| 例子 | 语法 | 描述 |
| --- | --- | --- |
| .fadeOut(speed, 函数名称) | `jQuery(".post") .fadeOut("slow"`, | 将处于可见状态或 alpha 为 `1` 的所选元素淡出为 `0` |
| .fadeIn(speed, 函数名称) | `jQuery(".post") .fadeIn("slow"`, | 将一个处于隐藏状态或 alpha 设置为 `0` 的所选元素淡入为 `1` |
| .fadeTo(speed, alpha, 函数名称) | `jQuery(".post") .fadeTo("slow"`, | 将所选元素淡出到特定的 alpha 值，从 `0` 到 `1` |

### 使用 `animate` 函数

上表中的三个动画函数将满足大部分需求。然而，你可能会发现自己处于需要更多控制的情况。在这种罕见的情况下，你可以使用 `animate` 函数。

| 例子 | 语法 | 描述 |
| --- | --- | --- |
| .animate(css 属性, 持续时间, 缓动, 函数名称) | `jQuery(".post") .animate({width:` | 在所选元素上创建自定义 CSS 属性的过渡 |
| .stop() | `jQuery(".post").stop()`; | 停止所选元素上的动画 |

这里有一个使用`animate()`函数自定义动画`img`的示例：

```js
...
jQuery(".post img").animate({
opacity: 0.25,
left: '+=50',
height: 'toggle'}, 1000, function() {
//alert("animate function finished");
});
...

```

在书中捕捉动画是很困难的，所以我没有尝试其他示例，但是在这里，你可以了解到帖子图像部分动画（图像高度正在减小，透明度正在向 0 逼近）的想法：

![使用 animate 函数工作](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_16.jpg)

# 使用语句链使一切变得容易

正如我所提到的，jQuery 的众多强大功能之一是语句链，也就是说，将多个函数串在一起，这些函数将按照它们添加到链中的顺序（从左到右）在所选集合上执行，所有这些都可以在一行漂亮的代码字符串中完成。例如，我们可以用一行代码改变 CSS 属性，隐藏所选元素，并平滑地淡出它们：

```js
...
jQuery(".post").css("background", "#f60").hide().fadeIn("slow");
...

```

要深入了解语句链的更多示例，请开始我们的第一个 WordPress jQuery 项目。

# 我们的第一个项目：扩展/折叠 WordPress 帖子

好了，这是一个快速项目，但是需要我们使用我们刚刚讨论过的一点东西。我一直喜欢 WordPress 有`<!--more->`功能，可以使帖子在主帖视图页面上"可压缩"，但这并不总适用于我某些类型的帖子。让我们假设我的博客将有相对较短的帖子，但我真的希望读者能够在屏幕上方看到尽可能多的标题，而无需滚动或扫描任何内容（我们将暂时忽略现实，并假装我的帖子标题仅仅是非常有趣和引人入胜的）。

我希望用户能够选择扩展他感兴趣的帖子，同时保持在所有其他帖子标题的上下文中。你可能在许多网站上看到过类似的增强功能。这是一个非常受欢迎的 jQuery 增强功能，适用于 FAQ 和新闻发布帖子。

让我们看看如何做到这一点。在你的主题中设置一个干净的`custom-jquery.js`文件，然后让我们开始吧。

首先，我们需要隐藏我们的帖子内容：

```js
jQuery(".post .entry-content").hide();

```

接下来，我们需要一些控件，让人们点击，并给他们一些直观的说明。当然，让编辑器为每篇文章添加一个控件元素会非常低效，所以我们不会这样做（但不幸的是，我在一些项目中看到过这样做）。我们可以将其添加到主题的`post.php`页面，但是，如果用户禁用了 JavaScript，则该控件将显示出来。我们希望它可以优雅地退化，毕竟这是一种*增强*。

如果有人在移动浏览器中遇到此内容，而没有 JavaScript 支持或仅支持文本或文本到语音浏览器，则我们希望他们只能查看正常的内容，而无需任何非功能性元素干扰他们。我们将使用 jQuery 添加我们的控制元素。如果 JavaScript 被禁用，它就不会出现。

```js
jQuery(".post").after("<div class='openIt' style='border-top: 1px solid #666; color: #036; text-align:right; cursor:pointer;'>Expand</div>");

```

现在我们只需要一种好的方法来显示和隐藏帖子的内容：

```js
jQuery(".openIt").click(function() {
jQuery(this).prev(".post").find(".entry").slideToggle("slow");
});

```

最后，让我们确保`.openIt` div 中的说明更新：

```js
jQuery(".openIt").toggle(function(){
jQuery(this).html("Close")},
function(){
jQuery(this).html("Expand")
});
...

```

就是这样！这是你的第一个，*有用的*用于 WordPress 的 jQuery 增强。下面是它的屏幕截图：

![我们的第一个项目：扩展/折叠 WordPress 文章](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_02_17.jpg)

## 使 jQuery 可读

在现实世界中，这种增强可以被彻底清理和优化。例如，最好为`.openIt`拥有现有的 CSS 样式，而不是将样式应用到`div`。

另外，我强烈建议编写单独的、具有名称的函数。例如，这样更容易阅读：

```js
...
jQuery(".openIt").toggle(closePost, expandPost);

```

然后，在下面看到：

```js
function expandPost(evt){
//jQuery(evt.target)...
}
function closePost(evt){
//jQuery(evt.target)...
}
...

```

如果你发现自己与其他开发人员一起在一个项目上工作，请考虑像这样将你的函数拆分开来，而不是像我的第一个例子那样直接将它们打包到 jQuery 函数中。这样做可以使代码更易于维护，并且你可以将你的函数与其他 jQuery 函数和脚本一起重用。

# 摘要

总结一下，我们通过注册 WordPress 捆绑版本和使用 Google 的 CDN 来将 jQuery 包含到 WordPress 中。我们还研究了 jQuery 的三个“秘密武器”：

+   选择器和过滤器

+   操纵和改变内容

+   事件和效果

在探索 WordPress 中的 jQuery 基础知识并且对它们的工作方式有所了解之后，你可能会觉得你已经准备好了！在很多方面，你确实已经准备好了，但我们将会继续深入探讨 WordPress 和 jQuery，更详细地了解 WordPress 生成内容的部分，我们可以使用 jQuery 来增强它们：我们将更深入地研究 WordPress 主题和插件，以及看看另一种类型的插件，即 jQuery 插件。主题和插件可以使我们的 WordPress 开发工作在多个站点和项目中非常强大和灵活。


# 第三章：深入了解 jQuery 和 WordPress

现在我们已经了解了 WordPress 中 jQuery 的基础知识，我们准备通过理解以下内容深入了解：

+   WordPress 主题、WordPress 插件和 jQuery 插件是什么以及它们的作用

+   创建您自己的 WordPress 主题、插件和 jQuery 插件的基础知识

+   如何在主题或 WordPress 插件中直接应用 jQuery 的最佳实践是什么，以及将其作为脚本或 jQuery 插件。

通过仔细研究 WordPress 的这两个主要组成部分，主题和插件，以及如何将我们的 jQuery 代码封装为 jQuery 插件，以便在项目中更轻松地使用，我们正在掌握动态 WordPress 开发的路上。

# 将 jQuery“插入”WordPress 网站的两种方法

您知道 WordPress 是一个令人印象深刻的发布平台。它的核心优势在于完美地将内容、显示和功能分开。同样，jQuery 是一个令人印象深刻的 JavaScript 库，花了很多精力使其跨平台工作，非常灵活和可扩展，但是，如果用户由于某种原因未启用 JavaScript，则优雅地退化。

您知道 WordPress 主题控制您网站的外观和感觉，WordPress 插件可以帮助您的网站做更多事情，但是我们将详细了解这两个组件在 WordPress 系统中的工作原理以及如何从主题或 WordPress 插件中使用 jQuery。通过这样做，您将能够更好地利用它们来开发您的 jQuery 增强功能。

说到 jQuery 增强功能，jQuery 脚本可以转换为它们自己的插件类型，不要与 WordPress 插件混淆。这使得您在 jQuery 中所做的工作可以轻松地在不同的项目和用途中使用。

在这三个组件之间，主题、WordPress 插件和 jQuery 插件，您会发现几乎您想要创建的任何东西都近在咫尺。更好的是，您会意识到大部分工作已经完成。这三种组件类型都有广泛的已开发的第三方创作库。大多数都是免费的！如果它们不是免费的，您将准备好确定它们是否物有所值。

通过了解编辑主题和创建您自己的 WordPress 和 jQuery 插件的基础知识，您将准备好穿越第三方创作的世界，并为您的项目找到最佳解决方案。您还将能够确定是与其他开发人员的主题、插件或 jQuery 插件一起工作更好还是更快，还是从头开始创建自己的。

## WordPress 主题概述

WordPress 主题是根据 WordPress codex 的说法*一组文件，这些文件共同产生一个带有统一设计的图形界面，用于博客*。主题包括一系列模板文件和网页素材，例如图像、CSS 样式表和 JavaScript。主题允许您修改 WordPress 站点的外观方式，而无需了解 WordPress 的工作原理，更不用说修改其工作方式了。有许多站点提供免费主题或销售高级 WordPress 主题。快速搜索“wordpress 主题”将让您了解可用选项的庞大性。然而，当首次寻找或研究主题时，始终可以从 WordPress 的免费主题库开始，您可以轻松地查看和演示不同的主题和样式：[`wordpress.org/extend/themes/`](http://wordpress.org/extend/themes/)。下一个截图显示了 WordPress 主题目录的主页：

![WordPress 主题概览](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_01.jpg)

一旦您选择了要使用或处理的主题，您将通过导航到 WordPress 安装管理面板的左侧面板中的**管理 | 外观 | 主题**来激活主题。下一个截图显示了**管理主题**面板：

![WordPress 主题概览](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_02.jpg)

这就是您作为 WordPress 用户需要了解的关于主题的最低要求。在我们深入了解之前，让我们先简要了解一下 WordPress 插件和 jQuery 插件。

## WordPress 插件概览

因此，主题改变了 WordPress 的外观，而不影响其功能。但是，如果您想要更改或添加功能怎么办？WordPress 插件允许对 WordPress 站点进行轻松修改、定制和增强。您可以通过安装和激活 WordPress 插件来添加功能，而不必深入了解 WordPress 的主要文件并更改其核心编程。

WordPress 开发团队非常注意，通过使用 WordPress 提供的访问点和方法来创建插件变得很容易，这些访问点和方法由 WordPress 的**插件 API**（应用程序接口）提供。搜索插件的最佳位置是：[`wordpress.org/extend/plugins/`](http://wordpress.org/extend/plugins/)。以下是 WordPress 插件目录主页的截图：

![WordPress 插件概览](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_03.jpg)

一旦您安装了插件，只需解压文件（通常只需解压缩），然后阅读包含的`readme.txt`文件以获取安装和激活说明。对于大多数 WordPress 插件来说，这只是将文件或目录上传到您的 WordPress 安装的`wp-content/plugins`目录，然后导航到**管理 | 插件 | 已安装**面板来激活它。下一个截图显示了**插件**管理面板，其中包含了默认的**Askimet、Hello Dolly**和新的**WordPress Importer**插件的激活屏幕：

![WordPress 插件概览](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_04.jpg)

那么 WordPress 插件与 jQuery 插件有什么不同呢？在理论和意图上，差别不大，但在实践中，有相当多的区别。让我们来看看 jQuery 插件。

## jQuery 插件概览

jQuery 有能力让你将你创建的脚本封装到 jQuery 函数对象中。这使得你的 jQuery 代码可以做一些关键的事情。首先，它变得更容易地移植到不同的情况和用途中。其次，你的插件作为一个函数可以集成到较大脚本中作为 jQuery 语句链的一部分。

浏览 jQuery 插件的最佳地点是 jQuery 插件页面（[`plugins.jquery.com/`](http://plugins.jquery.com/)），如下截图所示：

![jQuery 插件概览](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_05.jpg)

除了已经捆绑了 jQuery 外，WordPress 还捆绑了相当多的 jQuery 插件。WordPress 自带 **Color, Thickbox** 以及 **Form** 还有大多数 **jQuery UI** 插件。这些插件中的每一个都可以通过在主题的 `header.php` 文件或 `function.php` 文件中使用 `wp_enqueue_script` 来启用，就像我们在 第二章 中学到的那样，*在 WordPress 中使用 jQuery*。在本章中，我们将简要学习如何直接在 WordPress 插件中启用一个 jQuery 插件。

当然，你也可以下载 jQuery 插件并将它们手动包含到你的 WordPress 主题或插件中。你可以为那些没有与 WordPress 捆绑在一起的插件这样做，或者如果你需要以某种方式修改插件。

是的，你注意到 WordPress 中没有简单的 jQuery 插件激活面板。这就是了解你选择的主题和 WordPress 插件的地方！很快你会发现，在利用 jQuery 时有很多选择。现在我们已经对 WordPress 主题、插件和 jQuery 插件有了一个概述，让我们学习如何更好地利用它们。

# WordPress 主题的基础知识

到目前为止，你已经明白了 WordPress 主题基本上包含了包裹和样式化你的 WordPress 内容的 HTML 和 CSS。因此，当你将 jQuery 整合到站点中时，通常这是你会开始的地方。大多数情况下，这是一个好的方法。了解更多关于主题如何工作以及编辑它们的最佳实践只会让你的 jQuery 开发变得更加顺畅。让我们来看看主题的结构以及编辑主题的最佳实践。

### 小贴士

**想了解更多关于 WordPress 主题设计的内容吗？**

这个标题专注于你在 WordPress 中使用 jQuery 最需要了解的内容。如果你对 WordPress 主题开发感兴趣，我强烈推荐*April Hodge Silver*和*Hasin Hayer*的**WordPress 2.7 Complete**。除了涵盖管理 WordPress 站点的完整核心能力，第六章*WordPress 和 jQuery 的 UI*还对编辑和创建 WordPress 的标准主题进行了概述。

如果你真的想深入主题设计，我的标题**WordPress 2.8 主题设计**会带你创建一个工作的 HTML 和 CSS 设计模型，并从头开始编码。

## 理解模板的层次结构

我们已经讨论过，WordPress 主题包括许多文件类型，包括模板页面。模板页面有它们的结构或层次结构。这意味着，如果一个模板类型不存在，那么 WordPress 系统将调用下一个级别的模板类型。这使开发人员能够创建非常详细的主题，充分利用了所有可用模板页面类型的层次结构，使设置变得非常简单。一个完全运行的 WordPress 主题只需一个`index.php`文件！

要充分利用主题进行 jQuery 增强（更不用说帮助你解决常见的 WordPress 问题），最好先了解主题的层次结构。

除了这些模板文件，主题当然还包括图像文件、样式表，甚至自定义模板页和 PHP 代码文件。基本上，你可以在你的 WordPress 主题中拥有 14 种不同的默认页面模板，不包括你的`style.css`表或者像`header.php, sidebar.php`和`searchform.php`这样的包含文件。如果你利用 WordPress 对个别自定义页面、类别和标签模板的能力，还可以拥有更多模板页面。

如果你打开我们一直在使用的默认主题的目录，你会看到大部分这些模板文件，以及一个图像目录，`style.css`和`js`目录中的我们在第二章中开始的`custom-jquery.js`文件，*用 jQuery 在 WordPress 中使用*。下面的屏幕截图展示了 WordPress 3.0 的新默认主题**Twenty Ten**中的主要文件：

![理解模板的层次结构](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_06.jpg)

下一个列表包含一般的模板层次结构规则。你可以拥有的最简单的主题必须包含一个`index.php`页面。如果没有其他特定的模板页面存在，那么`index.php`就是默认的。

然后你可以开始扩展你的主题，添加以下页面：

+   当查看类别、标签、日期或作者页面时，`archive.php`优先于`index.php`。

+   当查看主页时，`home.php`优先于`index.php`。

+   当查看单个帖子时，`single.php`优先于`index.php`。

+   当查看搜索结果时，`search.php`优先于`index.php`。

+   当 URI 地址找不到现有内容时，`404.php`优先于`index.php`。

+   当查看静态页面时，`page.php`优先于`index.php`。

    +   选择自定义**模板**页面，例如：`page_about.php`，通过页面的**管理**面板后，将优先于`page.php`，而当查看该特定页面时，将优先于`index.php`。

+   当查看类别时，`category.php`优先于`archive.php`，然后优先于`index.php`。

    +   选择自定义**category-ID**页面，例如：`category-12.php`，将优先于`category.php`。这又优先于`archive.php`，而优先于`index.php`。

+   当查看标签页面时，`tag.php`优先于`archive.php`。这又优先于`index.php`。

    +   选择自定义**tag-tagname**页面，例如：`tag-reviews.php`，将优先于`tag.php`。这将优先于`archive.php`，而优先于`index.php`。

+   当查看作者页面时，`author.php`优先于`archive.php`。这又优先于`index.php`。

+   当查看日期页面时，`date.php`优先于`archive.php`。这将优先于`index.php`。

    ### 注意

    您可以在此处了解有关 WordPress 主题模板层次结构的更多信息：

    [`codex.wordpress.org/Template_Hierarchy`](http://codex.wordpress.org/Template_Hierarchy)。

### 一个全新的主题

如果您想要创建一个新主题，或者像本书的情况一样，如果您将大幅修改一个主题，您将想要创建一个类似于先前解释的层次结构的目录。再次强调，因为它是分层的，您不必创建每个建议的页面，更高级的页面将承担角色，除非您另有决定。正如我所提到的，只有一个`index.php`文件的工作主题是可能的。

我将修改默认主题，但仍希望可以参考原始默认主题。我将复制默认主题的目录并将其重命名为：`twentyten-wp-jq`。WordPress 依赖于主题目录的命名空间。这意味着，每个主题都需要一个唯一命名的文件夹！否则，您将复制另一个主题。下一个截图显示了此目录的创建：

![一个全新的主题 WordPress 主题扩展](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_08.jpg)

然后我将打开`style.css`文件并修改 CSS 文件开头的信息：

```js
/*
Theme Name: Twenty Ten - edited for Chapter 3 of WordPress & jQuery
WordPress themenew theme, creatingTheme URI: http://wordpress.org/
Description: The 2010 default theme for WordPress.
Author: the WordPress team & Tessa Silver
Version: 1.0
Tags: black, blue, white, two-columns, fixed-width, custom-header, custom-background, threaded-comments, sticky-post, translation-ready, microformats, rtl-language-support, editor-style
*/
...

```

我的“新”主题将出现在管理面板的**管理主题**页面中。您可以拍摄新主题或修改后的主题的新截图。如果没有截图，框架将显示一个灰色框。由于主题的外观将有些变化，我暂时从目录中删除了`screenshot.png`文件，您可以在下一个截图中看到：

![一个全新的主题 WordPress 主题扩展](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_09.jpg)

## 循环

在第一章，*入门：WordPress 和 jQuery*和第二章，*在 WordPress 中使用 jQuery*中，我们学到了 jQuery 在包装器中“循环”所选元素有多有用。WordPress 也有自己的一些循环；事实上，它非常重要，以至于被命名为“循环”。 **循环**是您的 WordPress 主题的重要组成部分。它按时间顺序显示您的帖子，并使用包含在 HTML 标记中的各种 WordPress 模板标记定义自定义显示属性。

在 WordPress 中，循环是一个**while 循环**，因此以 PHP 代码开始：`while (have_posts()):`，后跟模板标签`the_post()`。然后，所有标记和额外的模板标签都应用于每个要循环显示的帖子。然后，使用 PHP 的`endwhile`语句结束循环。

每个模板页面视图都可以有自己的循环，以便您可以修改和更改每种类型的帖子排序的外观和布局。每个模板页面本质上只是以不同的方式对您的帖子进行排序。例如，不同的类别或标记模板页面将帖子排序和精炼到满足特定标准。那些排序的帖子可以与主页上的帖子或存档列表中的帖子看起来不同，等等。下一个示例是从 WordPress 2.9.2 的默认 Kubrick 主题中取出的一个非常简单的循环：

```js
...
<?php while (have_posts()) : the_post(); ?>
<div <?php post_class() ?> id="post-<?php the_ID(); ?>">
<h2>
<a href="<?php the_permalink() ?>"
rel="bookmark" title="Permanent Link to
<?php the_title_attribute(); ?>">
<?php the_title(); ?>
</a>
</h2>
<small><?php the_time('F jS, Y') ?>
<!-- by <?php the_author() ?> -->
</small>
<div class="entry">
<?php the_content('Read the rest of this entry &raquo;'); ?>
</div>
<p class="postmetadata">
<?php the_tags('Tags: ', ', ', '<br />'); ?>
Posted in <?php the_category(', ') ?> |
<?php edit_post_link('Edit', '', ' | '); ?>
<?php comments_popup_link('No Comments »',
'1 Comment »', '% Comments »'); ?>
</p>
</div>
<?php endwhile; ?>
...

```

循环被嵌套在一个大的`if/else`语句中，最重要的是检查是否有要排序的帖子。如果没有匹配的帖子要显示，则显示“抱歉”消息，并使用`get_search_form()`包含标签包含`searchform.php`文件。

新的 WordPress 3.0 Twenty Ten 主题将其循环分离到名为`loop.php`的自己的模板页面中，其中包含了相当多的`if/else`语句，以便相同的循环代码可以处理许多不同的情况，而不是为不同的模板页面编写单独的循环。总的来说，新主题中使用的基本模板标签以及条件和包含标签与以前的默认主题中的使用方式相同。现在只有几个新的模板和包含标签可以帮助您简化主题。

让我们仔细看一些这些模板标签、包含标签和条件标签，以及 WordPress 主题中可用的 API 挂钩。

## 标签和挂钩

在循环内，你可能会注意到一些有趣的代码片段被包裹在 PHP 标签中。这些代码不是纯 PHP，大多数是 WordPress 特定的标签和函数，比如**模板标签**，它们只在 WordPress 系统中工作。在循环中最显然重要的模板标签是`the_title()`和`the_content()`。你会注意到大多数标签和函数可以通过它们传递各种参数。你会注意到在前面的代码片段中，`the_content` 标签有一个参数`'Read the rest of this entry &raquo;'`传递给它。如果 `<!--more-->` 标签被放置到帖子中，这串带有右尖括号的文本将出现。

并非所有 WordPress 标签和函数都放在循环内。如果你在 第一章——*入门：WordPress 和 jQuery* 和 第二章——*在 WordPress 中使用 jQuery* 中浏览过`header.php`文件，你可能会注意到诸如`blog_info()`和`body_class()`，当然还有我们在安装中使用的`wp_enqueue_script()`来注册 jQuery。

在需要处理主题模板文件进行开发和增强时，我发现以下模板标签和函数是有用的：

+   `bloginfo()`——此标签可以传递参数来检索关于你的博客的各种信息。在 `header.php` 文件中，你会注意到它最常用于查找你的样式表目录 `bloginfo('stylesheet_directory')` 和样式表 URL `bloginfo('stylesheet_url')`。它还可以显示你的 RSS URL，你的站点正在运行的 WordPress 版本，以及一些其他详细信息。更多详情，请查看：[`codex.wordpress.org/Template_Tags/bloginfo`](http://codex.wordpress.org/Template_Tags/bloginfo)。

+   `wp_title()`——此标签可以在循环外，并显示页面或单个帖子的标题（不是若干帖子的排序列表）。你可以传递一些选项，比如在标题中使用什么文本分隔符，以及分隔符文本是显示在左侧还是右侧。你还可以传递一个布尔值 true 或 false 来显示标题。`wp_title("--",true,"right")`。更多详情，请查看[`codex.wordpress.org/Template_Tags/wp_title`](http://codex.wordpress.org/Template_Tags/wp_title)。

+   `the_title()`——此标签放在循环内。它显示当前文章的标题，你可以传递任何你想将标题包裹在其中的文本字符：`the_title("<h2>", "</h2>")`。更多详情，请查看[`codex.wordpress.org/Template_Tags/the_title`](http://codex.wordpress.org/Template_Tags/the_title)。

+   `the_content()`—这个标签放在循环中，用于显示帖子的内容。如果您不传递任何 `params`，它将在帖子中使用 `<!--more-->` 标签时显示一个通用的**阅读更多**链接。否则，您可以传递您想要的“阅读更多”说明（我甚至发现在这里传递现有的标签也起作用。`the_content("Continue Reading".the_title())`）。有关更多详细信息，请查看 [`codex.wordpress.org/Template_Tags/the_content`](http://codex.wordpress.org/Template_Tags/the_content)。

+   `the_category()`—这个标签也必须放在循环中，它显示分配给帖子的类别的链接或链接。如果有多个类别，您可以传递您选择的文本分隔符。`the_category(", ")`。有关更多详细信息，请查看 [`codex.wordpress.org/Template_Tags/the_category`](http://codex.wordpress.org/Template_Tags/the_category)。

+   `the_author_meta()`—这个标签也必须放在循环中。它有丰富的参数可供传递。你可能最熟悉的是 `the_author_meta("nickname")`，或者 `the_author_meta("first_name")`，或者 `the_author_meta("last_name")`。你还可以获取作者的简介，`the_author_meta("description")`，以及电子邮件和网站的 URL。最好的办法是查看 Codex，了解可以使用这个标签做什么：[`codex.wordpress.org/Template_Tags/the_author_meta`](http://codex.wordpress.org/Template_Tags/the_author_meta)。

    ### 注意

    WordPress 模板标签库非常丰富，您可以在主题中使用这些标签的创造性方式几乎无限。我包括了使模板有用且出色的标签，但请务必查看 Codex：

    [`codex.wordpress.org/Template_Tags`](http://codex.wordpress.org/Template_Tags)。

### 条件标签

条件标签可以在模板文件中使用，根据页面匹配的条件改变显示的内容以及如何显示该内容。例如，您可能希望在一系列帖子上方显示一小段文字，但只在博客的主页上显示。使用 `is_home()` 条件标签，这个任务就变得很容易。

几乎可以为一切内容编写条件标签；在所有条件标签中，以下是我在主题开发中最常需要的几个：

+   `is_page()`

+   `is_home()` 或 `is_front_page()`

+   `is_single()`

+   `is_sticky()`

所有这些函数都可以使用以下参数：帖子 ID 或页面 ID 数字，帖子或页面标题，或帖子或页面别名。尽管主题很棒，但我相信您已经遇到过这样的困境，即您或您的客户不希望每个页面或帖子上都有完全相同的侧边栏。

我使用这些条件标签来确保特定页面可以打开或关闭特定样式或内容 div，并显示或不显示特定内容。这些标签真的有助于使项目站点具有真正的自定义网站感觉。

### 注意

条件标签的乐趣并不止于此。你可能会发现还有许多其他标签在帮助你的主题自定义方面非常有用：

[`codex.wordpress.org/Conditional_Tags`](http://codex.wordpress.org/Conditional_Tags).

### 模板包含标签

在 `index.php` 模板页面和其他模板页面，比如 `single.php` 或 `page.php` 等等，你可能会注意到这些包含标签。它们允许你将标准页面包含到其他模板页面中：

+   `get_header()` 

+   `get_footer()`

+   `get_sidebar()`

+   `comments_template()`

+   自定义包含：`include(TEMPLATEPATH."/file-name.php")`

#### 创建自定义头部、尾部、侧边栏包含

有一段时间了，WordPress 2.7 引入了创建*自定义*头部、尾部和侧边栏模板的能力。你只需创建自定义的头部、尾部或侧边栏，并使用标准的 include 模板标签调用它。确保添加一个文件*前缀*为 `header-`、`footer-` 或 `sidebar-`，以及你自己的文件名。然后，你可以按如下方式调用你的自定义模板文件：

+   `get_header('customHeader')` 将包含 `header-customHeader.php`

+   `get_footer('customFooter')` 将包含 `footer-customFooter.php`

+   `get_sidebar('customSidebar')` 将包含 `sidebar-customSidebar.php`

### 插件钩子

一般来说，除非你是插件开发者，否则你可能没有太多需要研究插件 API 的需求。然而，有一些钩子应该放在主题中，以便插件能够有效地与你的主题配合使用。如果你正在编辑一个主题，请确保不要删除这些钩子标签，或者如果你正在创建一个自定义主题，请确保包含它们：

+   `wp_head:` 放在 `header.php` 模板的 `<head>` 标签内：

    ```js
    <?php wp_head(); ?>

    ```

+   `wp_footer:` 放在 `footer.php` 模板中：

    ```js
    <?php wp_footer(); ?>

    ```

+   `wp_meta:` 你最有可能将这个钩子放在`sidebar.php`模板中。但是，最好在你打算让插件和小部件出现的任何地方添加这个钩子：

    ```js
    <?php wp_meta(); ?>

    ```

+   `comment_form:` 放在 `comments.php` 和 `comments-popup.php` 中，在 `</form>` 结束标签之前：

    ```js
    <?php do_action('comment_form'); ?>

    ```

### 项目：编辑默认主题中的主循环和侧边栏

好了！那看起来可能是关于主题的很多知识！作为一个只是想用 jQuery 增强 WordPress 网站的人，你可能会问：“真的有必要了解这些吗？”即使你对创建自定义主题没有兴趣，但是偶尔在使用 jQuery 时，了解 WordPress 主题的工作原理、主题输出的 HTML 标记以及大多数不同标记和函数的作用，对你会非常有用。

当然，在第二章中，*在 WordPress 中使用 jQuery*，我强烈建议您学习如何精通 jQuery 的选择器，以便能够在不编辑其主题的情况下增强任何 WordPress 网站。虽然您应该对 jQuery 的选择器和过滤器了如指掌，但这并不总是最快或最简单的方式。有时，虽然您可以选择和编辑页面上的任何内容，但 jQuery 的选择过程和语句链显得臃肿；如果某些元素只有特定的 HTML 标签，`class`或`id`属性，那么它或许可以被清理并缩减代码。有很多情况下直接编辑主题将使您能够更快地创建 jQuery 增强功能，并减少代码。更不用说，许多主题都很棒，但通常能够通过简单的主题调整使其更好并更加个性化适合您的网站。现在让我们做这个，并将我们刚刚学到的关于主题的东西付诸实践。

现在，我们使用的新的 Twenty Ten 默认主题很好，但是如果在帖子中日期更加突出，并且侧边栏被清理得更像“官方”链接，而不只是项目列表，会更好。

#### 改变循环

既然我们正在修改主题，我想改变循环显示的内容。我们要假设这是一个客户的网站，我知道客户*最终*会想要关注帖子的作者（在这个“假设”的网站上有很多作者），尽管日期很重要，但它不应该与作者的姓名放在同一行。我相信你肯定见过一些博客在帖子旁边有一个小日历或 iCal 样式的图标。我认为那是显示类似信息的一种视觉上吸引人的方式，而且不会占据太多空间。

使用免费的开源矢量编辑器 Inkscape ([`inkscape.org`](http://inkscape.org))，我制作了一个可以在顶部显示当天日期并在下面显示三个月份缩写的日历背景图标。该图标约为 32 像素正方形。您可以使用您喜欢的任何图形程序，比如 GIMP，Photoshop，Illustrator 等，来创建一个类似的图标，或者您可能在网上找到免版税的图像。

![改变循环](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_10.jpg)

为了让我们的日历背景在日期后面并且格式正确，让我们深入循环。默认主题的循环位于名为 `loop.php` 的模板文件中。如果这是您第一次使用 Twenty Ten 默认主题，那么这个循环可能比您所习惯的要长得多。最终，我们对显示在网站“主页”或默认博客页面上的“正常”或“其他一切”视图感兴趣。您会在代码的第 **127** 行左右找到它，以 `<div class="entry-meta">` 开头。

要开始，注释掉自定义的 PHP 函数 `twentyten_posted_on`（它引用了主题的`function.php`文件中的自定义函数，这有点超出了这个标题的范围），然后在粗体中添加以下 HTML 标记和 PHP 模板标签:

```js
...
<div class="entry-meta">
<?php //twentyten_posted_on();//comment this out ?>
<small class="date">
<?php the_time('d') ?><br/>
<span><?php the_time('M') ?></span>
</small>
</div><!-- .entry-meta -->
...

```

我们要关注的是日期显示。日期以称为`the_time`的模板标签显示，其中的参数设置为显示完整的月份，"如所说"的日期和年份；例如；2010 年 2 月 4 日。

我只想显示日期的数字和月份的三个字母缩写。`the_time`标签的参数实际上不允许我添加 HTML 换行标记，因此我将我的日期分为两个独立的`the_time`标签调用，以便我可以更好地控制 HTML。我还希望确保我的样式仅适用于这个循环，而不适用于其他模板页面循环中包裹的`<small>`日期和内容，因此我一定要为`<small>`标签添加自定义`date`类。我还将年份日期显示包含在一些`<span>`标签中，以便我可以对其进行额外的样式控制。我的日期显示和类最终如下：

```js
...
<small class="date">
<?php the_time('d') ?><br/>
<span><?php the_time('M') ?></span>
<!-- by <?php the_author() ?>-->
</small>
...

```

接下来，我们打开 CSS 的`style.css`样式表，并添加特殊类名的规则到日期显示，并修改标题显示。我只是简单地将我的修改添加到`style.css`样式表的底部。如果碰巧我的样式名称与样式表中已经定义的任何东西相同，我的规则将继承自上一个规则并进行更改（或者明确表示我需要更独特的样式名称）。

首先，我会将主页上的`h2`标题（位于`.post`类中）向上移动 40 个像素，以便为我的日期腾出空间。接下来，我将把我的日期移到`.post`类中，向上移动约 25 个像素，使其与标题并排。在这条规则中，我还为自己在 Inkscape 中创建的`dateBackground.png`分配了背景，并微调日期数字的大小、颜色和其他一些属性。最后，我在 span 标签中设置了月份显示大小和颜色，结果如下：

```js
...
/*----------twentyten chapter 3 customizations------------*/
.home .post .entry-title{
padding-left: 40px;
}
.post small.date{
display:block;
background: url(images/dateBackground.png) no-repeat;
margin-top: -25px;
padding-top: 4px;
width: 32px;
height: 32px;
font-size: 20px;
line-height: 12px;
text-align: center;
color: #eee;
}
.post small.date span{
font-size: 10px;
color: #666;
}
...

```

然后，下一张截图展示了我们帖子的标题和日期的现在的样子：

![修改循环](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_11.jpg)

不错！现在，让我们来处理一下侧边栏。

#### 改变侧边栏

侧边栏很容易。Twenty Ten 默认主题中的整个侧边栏都是小部件化的，因此我们想要重新排序的任何内容都可以通过管理面板进行。但是，我们确实想微调一下侧边栏项目的项目符号列表的 CSS。在修改一个不是从头开始创建的主题时，最好总是将新的类添加到标记和样式表中，而不是更改或编辑作者放置的任何原始样式。这样做只会使多种原因下还原更容易。正如你之前可能已经注意到的，我总是将我的新自定义样式添加到`style.css`样式表的底部。

让我们从在编辑器中打开`sidebar.php`开始，只需添加一个新的类名，我们可以用来为加载到任何小部件区域的任何小部件设置样式。无论我在哪里找到`<ul class="xoxo">`标签，我都会在.xoxo 类之后添加一个额外的类，称为.currentsidebar。这在`sidebar.php`文件中大约在第**12**行附近出现了两次，还有一次大约在第**51**行附近。

```js
...
<ul class="xoxo currentsidebar">
...
<ul class="xoxo currentsidebar">
...

```

接下来，我们现在只需打开我们的`style.css`样式表，在其底部再次编写我们的新的.currentsidebar CSS 规则以影响列表项：

```js
...
.currentsidebar li{
padding: 0;
margin: 15px 0 20px 0;
}
.currentsidebar li ul li{
list-style: none;
padding: 5px 0; margin: 0 0 0 -15px; border-bottom: 1px solid #ddd;
font-size: 105%;
}
...

```

哇！正如您在下一个截图中所见，我们的页面和侧边栏导航现在是这样的：

![更改侧边栏默认主循环，更改](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_12.jpg)

如您所见，对 WordPress 主题进行微调很容易。您不仅可以自定义主题以满足您的外观和功能需求，还可以想象调整主题的 HTML 标记以便更轻松地添加您的 jQuery 增强功能有多容易。接下来，让我们转向 WordPress 插件。

# WordPress 插件的基础知识

现在说实话，撰写 WordPress 插件的细节远远超出了本标题的范围；我的目标是向您展示简单 WordPress 插件的结构以及如何构建插件的基础知识。理解这一点，您可以开始编写自己的基本插件，并且在评估其他人的插件时更有信心，看看它们为您的 WordPress 站点提供了什么样的功能，以及您是否需要为您的 jQuery 增强功能进行任何调整。即使是我们将要进行的简单和基本的工作，您也会看到 WordPress 插件确实有多么强大。

### 提示

**想成为 WordPress 插件之星？**

您可以再次选择**WordPress 2.7 完全手册**，作者是*April Hodge Silver*和*Hasin Hayder*。其中有一章介绍了插件，指导您创建非常有用的简单插件，以及一个更复杂的插件，可以写入 WordPress 数据库。此外，您还可以查看*Vladimir Prelovac*的**WordPress 插件开发入门指南**。不要被标题迷惑，Vladimir 将通过清晰的、逐步的代码讲解，使您按照 WordPress 的编码标准生成功能丰富、动态的 WordPress 插件。

使用插件需要一些 PHP 经验。对于非 PHP 开发人员，我将保持这个解释相当简单，而有 PHP 经验的人应该能够看到如何在 WordPress 中扩展此示例以便于您。总的来说，如果您迄今为止一直在本书中跟随 jQuery 和 WordPress PHP 示例，那么您应该没问题。

与主题一样，WordPress 插件需要一点结构才能开始使用它们。插件文件没有明确定义的层次结构，但你至少需要一个带有特殊注释的 PHP 文件，以便 WordPress 可以在插件管理页面中显示它。虽然有一些单文件插件存在，比如你的 WordPress 安装中自带的 Hello Dolly 插件，但是当你开始开发时，你永远不知道一个插件可能会如何增长。为了安全起见，我喜欢将我的插件组织成一个唯一命名的文件夹。再次强调，与主题一样，WordPress 依赖于插件目录的命名空间，因此唯一性非常重要！

在`wp-content/plugins`目录中，你可以放置一个独特的文件夹，在其中创建一个`.php`文件，并在文件的开头，在`<?php ?>`标签内包含以下头信息。只有粗体信息是绝对必需的。其余信息是可选的，并填充了管理插件页面中的**管理插件**。

```js
<?php
WordPress pluginabout/*
Plugin Name: your WordPress Plugin Name goes here
Plugin URI: http://yoururl.com/plugin-info
Description: Explanation of what it does
Author: Your Name
Version: 1.0
Author URI: http://yoururl.com
*/
//plugin code will go here
?>

```

### 提示

确保你的`<?php`标签前后没有任何**空格**。如果有的话，WordPress 会显示一些错误，因为系统会出现关于页面标题已经被发送的错误。

一旦你在插件目录中设置好了自己的`.php`文件，你就可以在其中添加一个基本的 PHP 函数。然后，你可以决定如何调用该函数，使用一个**动作挂钩**或一个**过滤器挂钩**。例如：

```js
<?php
filter hookusing/*
Plugin Name: your WordPress Plugin Name goes here
Plugin URI: http://yoururl.com/plugin-info
Description: Explanation of what it does
Author: Your Name
Version: 1.0
Author URI: http://yoururl.com
*/
function myPluginFunction(){
//function code will go here
}
add_filter('the_title', 'myPluginFunction');
//or you could:
/*add_action('wp_head', 'myPluginFunction');*/
?>

```

记得在前面的主题部分，我讲解了插件挂钩以及它们在主题中的重要性吗？这就是原因所在。如果你的主题中没有`wp_head`或`wp_footer`，许多插件就无法正常运行，而且你只能使用你自己编写的插件。在我的插件中，我主要使用`wp_header`和`init`动作挂钩。

幸运的是，大多数过滤器挂钩在你的插件中也会起作用，因为 WordPress 会在循环中运行它们。在很大程度上，你将在插件中使用`the_title`和`the_content`过滤器挂钩完成大部分工作。当 WordPress 在循环中循环这些模板标签时，每个过滤器挂钩都会执行你的函数。

### 提示

**想知道有哪些可用的过滤器和动作挂钩吗？**

列表是详尽的。事实上，它是如此之庞大，以至于 WordPress codex 似乎没有将它们全部记录下来！如果你想要查看所有动作和过滤器挂钩的最完整列表，包括 2.9.x 版本中可用的新挂钩，你应该查看亚当·布朗的**WordPress 挂钩数据库：** [`adambrown.info/p/wp_hooks`](http://adambrown.info/p/wp_hooks)

对数据库感到不知所措？当然，查看弗拉基米尔的**WordPress 插件开发：初学者指南**将帮助你入门，并提供一系列动作和过滤器挂钩。

你现在理解了 WordPress 插件的基础知识！让我们开始做点什么吧。

## 项目：编写一个 WordPress 插件以显示作者简介

正如我们所讨论的，插件可以帮助扩展 WordPress 并赋予其新功能。然而，我们已经看到，在大多数情况下，直接向主题添加 jQuery 脚本并在各处编辑其模板页面即可完成任务。但让我们想象一个更复杂的情况，使用我们修改过的默认主题和本章前一个项目中提到的假想客户。

当我们调整默认主题时，我想到这个客户可能希望她网站的重点更加倾向于新闻报道，因此，她希望每篇文章的作者引起一些关注。我是对的，她是这样希望的。然而，有一个问题。她不只是想要显示他们的 WordPress 昵称；她更希望显示他们完整的名字，因为这更加专业。她还想显示他们简要的自传，并附带一个指向他们自己网址的链接，但又不想让这些信息“妨碍”文章本身，也不想让它们丢失在文章底部。这里真正有趣的是；她希望这种变化不仅影响到这个站点，还要覆盖她的一系列特定类型新闻站点的网络，至少有 20 个（天啊，我忘记了她有这么多站点！幸好她只是假设的）。

对于这个特定的 WordPress 站点，很容易进入并注释掉我们之前处理过的自定义函数：添加 `the_author` 标签并显示两次，为每个标签传递一些参数以显示名字的第一个和最后一个字。我还可以添加一个标签来显示用户面板中的作者简介片段和 URL（如果他们填写了该信息）。此外，很容易添加一小段 jQuery 脚本，使得该简介 `div` 在鼠标悬停在作者姓名上时显示出来。然而，将所有这些工作复制并重新复制到其他 20 个不同的站点中，其中许多站点不使用默认主题，大多数站点也没有将 jQuery 包含到他们的主题中，听起来确实是一项不必要的工作（此外，客户提到她正在考虑一些新主题用于一些站点，但她还不知道哪些站点将获得哪些新主题）。

这是一项不必要的工作量。与其修改这个主题，然后在其他 20 个主题中来回测试、粘贴、测试和调整，不如花费这些时间创建一个 WordPress 插件。然后，将其轻松部署到客户的所有站点上，而且每个站点使用的主题都不重要。让我们开始吧！

### 编写插件

首先，浏览客户的站点网络，不多的站点显示作者的昵称或姓名。只有少数几个这样做，而其中的姓名是不引人注意的。有一个插件显示作者的姓名会更容易，然后注释掉或删除一些主题中的 `the_author` 标签。

这里有一个需要注意的小细节：模板标签在插件中表现得不太好。这是因为模板标签，即一个函数，被设置为显示文本，而在另一个函数内，我们实际上不需要这样。我们想要做的是获取信息并将其传递给我们的钩子，当插件函数运行时显示它。大多数模板标签都有可比的 WordPress 函数，它们只会获取信息而不会立即写入或显示它。对于编写插件，我喜欢查看**函数参考**，而不是查看 WordPress Codex 的**模板标签**函数列表。几乎以`get_`开头的任何内容都适用于插件。有关更多详细信息，请参阅[`codex.wordpress.org/Function_Reference`](http://codex.wordpress.org/Function_Reference)。

Codex 函数参考有一个`get_the_author()`，它将满足我在这个项目中的一些需求，但我更喜欢使用在 WordPress 版本 2.8 中出现的一个新函数，称为`get_the_author_meta()`。与`get_the_author`不同，您可以向此函数传递超过 25 个参数，以了解您在 WordPress 用户上关心的几乎任何内容。

接下来给出的是我的插件基本的`addAuthor`函数，然后是我的`add_filter`钩子，它将在每个帖子的内容上运行我的函数。您可以阅读加粗的注释以获取更多详细信息：

```js
...
//add author function
function addAuthor($text) {
/*the $text var picks up content from hook filter*/
//check if author has a url, a first name and last name.
//if not, no "Find out more" link will be displayed
//and just the required nickname will be used.
if (get_the_author_meta('user_url')){
$bioUrl = "<a href='".get_the_author_meta('user_url')."'>
Find Out More</a>";
}
if (get_the_author_meta('first_name')
&& get_the_author_meta('last_name')){
$bioName = get_the_author_meta('first_name').
" ".get_the_author_meta('last_name');
}else{
$bioName = get_the_author_meta('nickname');
}
//check if author has a description, if not
//then, no author bio is displayed.
if (get_the_author_meta('description')){
$bio = "<div class='authorName'>by <strong>".$bioName."</strong>
<div class='authorBio'>"
.get_the_author_meta('description')." ".$bioUrl."
</div>
</div>";
}else{
$bio = "<div class='authorName'>
by <strong>".$bioName."</strong>
</div>";
}
//returns the post content
//and prepends the bio to the top of the content
return $bio.$text;
}//addAuthor
//calls the post content and runs the function on it.
add_filter('the_content', 'addAuthor');
...

```

您会注意到在上一个代码片段中，我特别注意检查 WordPress 用户的个人资料中是否填写了 URL，并且他们是否已添加了他们的名字和姓氏以及简介描述。如果没有，我的插件将仅显示用户的昵称（昵称是必填字段），通常与用户的登录名相同。

如果任何作者没有填写他们的名字和姓氏，或者没有填写简介，我会让我们的客户强制他们更新他们的个人资料。与此同时，插件不会显示任何空白、空的或损坏的内容，因此不会造成任何损害。

现在我只关注将作者的姓名和简介放入 WordPress 中，现在姓名和简介应该已经生成了，我只是想确保简介的样式漂亮，以便与帖子内容区分开来，但又不会太过显眼。

为此，我将在我的插件目录中添加一个名为`authover.css`的样式表，并添加以下样式：

```js
.authorBio {
border-top: 2px solid #666;
border-bottom: 2px solid #999;
background-color: #ccc;
padding: 10px;
font-size: 10px;
}

```

现在，我将 CSS 放在自己的样式表中，而不是作为另一个功能脚本化到插件中的字符串，主要是为了演示使用 Script API 中的`wp_register_style`和`wp_enqueue_style`函数的最佳实践。正如使用`wp_enqueue_scripts`函数帮助我们避免与其他 JavaScript 和 jQuery 库冲突一样，这些函数注册新样式表并加载它，确保不会与其他同名样式表冲突。

对于样式表，我很确定它将是我插件的独特之处，甚至更甚的是，仅仅针对一个单一规则来说，这可能有些小题大作，但你应该了解这种方法，特别是当你查阅更健壮的常用插件时，你可能会遇到它。而且，这会使插件在未来更容易扩展。你不需要在 PHP 字符串中编辑或修改 CSS。事实上，如果你要编写一个样式表足够长的插件，你可以把样式表交给一个 CSS 设计师，而你专注于 PHP 功能。更不用说，这样可以使你的插件对其他用户更有用。一个没有 PHP 经验的 WordPress 用户可以下载并安装这个插件，并轻松编辑其 CSS 样式表，使其在其网站设计中看起来很好。

下面是我的`addCSS`函数。此外，不同于通过过滤挂钩激活样式表，我希望样式表可以在 WordPress 加载之前注册并加载，甚至在`wp_head`挂钩之前！因此，你会看到我使用了`init`动作挂钩。

除了我加粗的评论之外，你还会注意到`WP_PLUGIN_URL`变量的使用。这类似于我在主题部分向你展示的`TEMPLATEPATH`变量，用于创建一个自定义包含，不同的是，这个变量在插件中使用，帮助 WordPress 动态地找到你的插件文件，而不是硬编码它们。

请阅读下一个代码块中加粗的评论，了解每个代码语句的作用：

```js
...
// Some CSS to position for the paragraph
function authorCSS() {
//These variables set the url and directory paths:
$authorStyleUrl =
WP_PLUGIN_URL . '/add_author_bio-tbs/authover.css';
$authorStyleFile =
WP_PLUGIN_DIR . '/add_author_bio-tbs/authover.css';
//if statement checks that file does exist
if ( file_exists($authorStyleFile) ) {
//registers and evokes the stylesheet
wp_register_style('authorStyleSheet', $authorStyleUrl);
wp_enqueue_style( 'authorStyleSheet');
}
}
//evoke the authorCSS function on WordPress initialization
add_action('init', 'authorCSS');

```

好了！应该没问题了。现在我们需要激活我们的插件并在 WordPress 中检查一下。

### 在 WordPress 中激活我们的插件

我们的插件已经在 WordPress 的`wp-content/plugins`目录中。这意味着我们只需要导航到我们的**管理插件**页面并激活它即可。

代码注释头中的`Plugin Name：`空间中名为**jQuery Add Author Biography**的插件显示在插件表中，如下截图所示：

![在 WordPress 中激活我们的插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_13.jpg)

一旦插件被激活，我们可以导航到网站上查看它的运行情况：

![在 WordPress 中激活我们的插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_14.jpg)

它正在工作！主题中不包含`the_author_meta`标签，现在显示作者的全名和简介描述。简介描述使用了我们插件类中的 CSS 规则来进行样式设置。

你现在已经手动编辑了一个主题，并进一步通过从头开始创建一个 WordPress 插件来扩展了这个网站。干得好！但是你说什么？你希望再做一点 jQuery？你是对的。让我们通过创建一个 jQuery 插件来进一步增强这个网站。

# jQuery 插件的基础

我们会发现，与 WordPress 主题和插件相比，jQuery 插件实际上并不那么复杂。

要设置一个 jQuery 插件，你需要遵循 jQuery 的**插件结构**。基本结构包括如下设置 jQuery 函数来定义你的插件。请注意加粗的`.fn`添加到 jQuery 对象中。这是使你的函数成为 jQuery 函数的关键。

```js
jQuery.fn.yourFunctionName = function() {
//code
};

```

在其中，最好的做法是添加一个`this.each(function(){...})`来确保你的函数会运行每个 jQuery 选择器中的每个项目。

```js
jQuery.fn.yourFunctionName = function() {
return this.each(function(){
//code
});
};

```

与 WordPress 不同，WordPress 在主题 CSS 样式表和插件头部需要特定格式的注释，而 jQuery 不需要注释头部，但在顶部添加一个是很好的习惯。

```js
/*
You can name the plugin
Give some information about it
Share some details about yourself
Maybe offer contact info for support questions
*/
jQuery.fn.yourFunctionName = function() {
return this.each(function(){
//code
});
};

```

注意，你在插件中包装和使用的每个函数和方法都必须以一个";"分号结尾。否则你的代码可能会出错，如果你压缩它，它肯定会出错。

这就是，一个 jQuery 插件所需要的全部。现在，让我们深入了解如何使用 jQuery 插件来增强我们的 WordPress 插件的输出。

## 项目：jQuery 淡入子 div 插件

采用前面讨论过的所需的 jQuery 函数，我将编写一个基本函数，它不仅可以传递给主要的 jQuery 包装选择器，还可以传递一个额外的选择器参数，以便轻松地定位所选择的`div`的子元素，或者传递参数的 jQuery 选择器的特定参数。

再次注意，跟着我的`authorHover`函数里的粗体注释一起看：

```js
...
//sets up the new plugin function: authorHover
jQuery.fn.authorHover = function(applyTo) {
//makes sure each item in the wrapper is run
return this.each(function(){
//if/else to determine if parameter has been passed
//no param, just looks for the child div
if(applyTo){
obj = applyTo
}else{
jQuery pluginchild div pluginobj = "div";
}
//hides the child div or passed selector
jQuery(this).find(obj).hide();
//sets the main wrapper selection with a hover
jQuery(this).css("cursor", "pointer").hover(function(){
//restyles the child div or passed selector
// and fades it in
jQuery(this).find(obj).css("position","absolute")
.css("margin-top","-10px").css("margin-left","-10px")
.css("width","400px")
.css("border", "1px solid #666").fadeIn("slow");
}, function(){
//fades out the child selector
jQuery(this).find(obj).fadeOut("slow");
});
});
};

```

就是这样。现在我们已经创建了一个 jQuery 插件脚本，让我们首先在我们的主题中快速测试一下。我们所需要做的就是将我们的新 jQuery 插件命名为`jquery.authover.js`嵌入到我们的主题中，在`wp_enque_script`调用下面，在`wp_head` hook 下方调用它：

```js
...
<script type="text/javascript">
jQuery(function(){
jQuery(".authorName").authorHover();
});
</script>
...

```

我们可以在我们的网站上查看结果。我截取了两张截图，这样你就可以看到淡入效果。在下面的截图中，你可以看到新的`div`开始淡入：

![项目：jQuery 淡入子 div 插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_15.jpg)

在接下来的截图中，你可以看到完成的淡入动画：

![项目：jQuery 淡入子 div 插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_16.jpg)

### 额外加分：将你的新 jQuery 插件添加到你的 WordPress 插件中

现在你可以自由地安装你的 WordPress 插件，并在需要时在尽可能多的网站上包含 jQuery 插件！但是，如果你想知道的话，是的，我们可以进一步完善安装过程，只需将此 jQuery 插件合并到我们的 WordPress 插件中即可。

第一步是简单地将我们的`jquery.authover.js`脚本放在我们的插件目录中，然后使用`wp_enqueue_script`来调用它。你需要特别注意`wp_enqueue_script`函数的使用，因为如果主题或插件中还没有注册 jQuery 1.4.2，它将会自动包含 jQuery 1.4.2！这意味着客户的网站，如果还没有包含 jQuery，也不用担心！只需安装此插件即可自动包含它！

```js
...
function addjQuery() {
wp_enqueue_script('authover',
WP_PLUGIN_URL . '/add_author_bio-tbs/jquery.authover.js',
array('jquery'), '1.4.2' );
}
...

```

然后，我们将在 WordPress 插件中添加一个函数，该函数会写入使用插件的`authorHover`函数的 jQuery 脚本。通常情况下，最好并且推荐通过`wp_enque_script`函数加载所有脚本，但对于非常小的、定制化程度极高的脚本，你确信不会出现冲突，并且你知道 jQuery 已经正确加载（就像我们使用插件一样），如果你愿意，你可以像这样硬编码脚本标签：

```js
...
function addAuthorHover(){
echo '<script type="text/javascript">
jQuery(function(){
jQuery(".authorName").authorHover();
});
</script>';
}
...

```

最后，我们添加激活这些功能的动作过滤器：

```js
...
add_action('init', 'addjQuery');
add_action('wp_head', 'addAuthorHover');
?>

```

现在，如果你从主题中移除你的 jQuery 插件，并确保你的插件已被激活，你应该看到与之前完全相同的结果！在下一个截图中，你会注意到我已经添加了一个 URL 到我的个人资料中，现在**了解更多**功能设置得非常好，如果没有 URL 存在，它会自动降级。太棒了。

![额外加分：将新的 jQuery 插件添加到您的 WordPress 插件中](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/wp3-jq/img/1742_03_17.jpg)

# 综合起来：编辑主题还是创建自定义插件？

在本章中，我们学习了编辑主题、创建 WordPress 插件和 jQuery 插件的简易方法。对于大部分 WordPress 开发工作，直接将 jQuery 增强功能添加到主题中就可以了。如果你觉得你的 jQuery 脚本有点复杂，并且你被允许编辑主题（当然，假设你不会破坏布局或大幅改变外观），你可能会发现在 WordPress 内容中包裹自定义 HTML 标签，带有特殊的`class`或`id`属性是一个巨大的帮助和时间节省。

本章项目示例中的“假设客户请求”还表明，如果你的工作有可能或将被重复使用或部署到多个单独的 WordPress 安装中，你应该考虑将工作封装在 jQuery 插件、WordPress 插件中，或者我们发现的两者都要考虑。

除了考虑你的工作是否需要被重复使用或部署之外，你可能还想考虑 jQuery 增强和 WordPress 主题的寿命。很容易认为 jQuery 增强实际上更多是主题的一部分，因为它在视觉上影响主题，但真的是这样吗？我发现，我更多的 WordPress 和 jQuery 开发工作似乎集中在将 jQuery 开发封装到 WordPress 插件中，或者使 WordPress 插件更有效地使用 jQuery。

由于将 jQuery 包含到 WordPress 站点中只有两种方法，通过主题或插件，如果你对编辑和创建插件感到舒适，你可能会发现这是更好的方法（当然，总是有例外的）。使用 jQuery 增强 WordPress 插件，甚至将 jQuery 插件封装在 WordPress 插件中，都将使您能够轻松地独立扩展主题设计和任何 jQuery 功能/增强。

这种方法非常方便，如果你喜欢经常重新设计或更新主题，或者你有一个有点“主题换来换去”的客户。如果你想保留酷炫的 jQuery 增强表单、图像和画廊灯箱以及各种其他功能，甚至只是你为网站创建的“整洁眼睛糖果”，而不必一次又一次地手动更新一个新主题，创建一个插件是一个不错的选择，不管是为了 jQuery、WordPress 还是两者兼有。

最终，这取决于你和你的舒适度，以及对项目最有利的做法，但我发现，除了一些例外，我们将在后面的章节中提到的例子，尝试让大多数 jQuery 增强功能不要嵌入 WordPress 主题中对我来说效果很好。

# 摘要

现在你应该理解以下内容：

+   WordPress 主题、WordPress 插件和 jQuery 插件是什么。

+   如何编辑主题并创建自己的基本 WordPress 和 jQuery 插件。

+   了解何时编辑和自定义主题，或者制作 WordPress 插件、jQuery 插件或三者兼有的最佳实践！

掌握了这些信息，我们将继续进行下一章，在那里我们将看看如何使用一个 jQuery 插件与一个即插即用的 WordPress 插件。我们还将讨论如何通过 jQuery 增强和扩展 WordPress 插件的功能。准备好用灯箱模态窗口迷住用户，并用易于使用的表单给用户带来惊喜。
