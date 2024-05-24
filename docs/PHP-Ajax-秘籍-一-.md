# PHP Ajax 秘籍（一）

> 原文：[`zh.annas-archive.org/md5/5ed725dded7917e2907901dccf658d88`](https://zh.annas-archive.org/md5/5ed725dded7917e2907901dccf658d88)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Ajax 是 Web 2.0 网站中必不可少的范式。大多数 Web 2.0 网站都是用 PHP 和 Ajax 构建的。扩展 Ajax 是为了以快速简便的方式提供访问 PHP 后端服务的前端服务。有了这本书，你将学会如何使用必要的工具来实现网站和 iPhone 的 Ajax 化。

*PHP Ajax Cookbook*将教你如何将 PHP 和 Ajax 的组合作为网站或 Web 应用程序的强大平台。使用 Ajax 与服务器通信可以加快 PHP 后端服务的响应速度。Ajax 和 PHP 的组合具有许多功能，如加快用户体验、让你的 Web 客户端获得更快的响应时间，并让客户端浏览器从服务器检索数据而无需刷新整个页面。你将学会优化和调试 Ajax 应用程序。此外，你还将学会如何在 iPhone 设备上编写 Ajax 程序。

本书将教你流行的基于选择器的 JavaScript，然后介绍调试、优化和最佳实践的重要概念。其中包括一系列的配方，重点是创建基本工具，如使用 Ajax 验证表单和创建五星评级系统。由于 jQuery 非常流行，因此随后介绍了有用的工具和 jQuery 插件，如 Ajax 工具提示、选项卡导航、自动完成、购物车和 Ajax 聊天。到第七章结束时，你将学会如何加快网站响应速度，并构建 SEO 友好的 Ajax 网站。你还将了解所有流行的 Ajax web 服务和 API，如 Twitter、Facebook 和 Google Maps，这些都在第八章 *Ajax Mashups*中介绍。最后，逐步介绍了使用基本库和日常有用的 Ajax 工具构建 iPhone 应用的配方。

使用 PHP Ajax 构建丰富、交互式的 Web 2.0 网站和丰富的标准和 Mashups。

# 本书内容包括

第一章，*Ajax 库*，教我们如何使用最著名的 JavaScript 库和框架，具有 Ajax 功能的能力。这些库是根据我们的主观意见选择的，我们并不试图说哪个库/框架更好或更差。它们各自都有优点和缺点。

第二章，*基本工具*，着重介绍处理表单、表单控件、Ajax 表格和上传操作的基本 Ajax 操作。根据用户体验和特定系统的性能，解释了一些基于“最佳”实践。

第三章，*使用 jQuery 的有用工具*，讨论了 jQuery 插件，这些插件对将普通网站转变为具有良好外观的 Ajax 网站非常有用，如工具提示、带有灯箱的图库、日期选择器、快速视觉效果和布局功能。

第四章，*高级工具*，教我们如何构建高级功能，如聊天、绘制图表、使用画布解码验证码以及在网格中显示数据。

第五章，*调试和故障排除*，讨论了使用浏览器插件如 Firebug 进行 JavaScript 调试的技术。

第六章，*优化*，教我们如何通过缩小、提前触发 JavaScript、对象缓存以及来自 YSlow 和 Google Page Speed 工具的技巧来加快代码执行速度。

第七章，*实施构建 Ajax 网站的最佳实践*，讨论了避免特定标记代码、构建搜索引擎友好的 Ajax 网站、安全考虑和实施 Ajax Comet 等最佳实践。

第八章, *Ajax 混搭*，讨论了如何通过利用 Flickr、Picasa、Facebook、Twitter、Google Maps 和地理编码网络服务，从 JavaScript 中利用现有的网络服务。

第九章, *iPhone & Ajax*，教我们如何使用移动框架构建移动友好的网站，并使用 PhoneGap 框架构建原生 iPhone 应用程序。

# 你需要什么来读这本书

在这本书中，您基本上需要在计算机上安装 Apache、MySQL 和 PHP。如果您的计算机上没有安装 PHP、MySQL 或 Apache，我们建议您从其网站下载 XAMPP 软件包：[`www.apachefriends.org/en/xampp.html`](http://www.apachefriends.org/en/xampp.html)。此外，作为代码编辑器，您可以使用像 Notepad++（Windows）、IDE Netbeans 或 Eclipse 这样的简单编辑器。

# 这本书是为谁准备的

这本书是一个理想的资源，适合喜欢为网站添加 Ajax 功能并倾向于使用标准和最佳实践来构建 SEO 友好网站的人。由于本书涵盖了高级主题，读者需要了解基本的 PHP、JavaScript 和 XML 功能。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例，以及它们的含义解释。

文本中的代码单词显示如下：“我们可以通过使用`include`指令来包含其他上下文。”

代码块设置如下：

```php
if(isset($_GET["param"])){
$result["status"] = "OK";
$result["message"] = "Input is valid!";
} else {
$result["status"] = "ERROR";
$result["message"] = "Input IS NOT valid!";
}

```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将以粗体显示：

```php
" $('#dob').datepicker({
" numberOfMonths: 2
" });

```

任何命令行输入或输出都以以下方式书写：

```php
# cp /usr/src/asterisk-addons/configs/cdr_mysql.conf.sample
/etc/asterisk/cdr_mysql.conf

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，如菜单或对话框中的单词，会在文本中出现，如：“点击**下一步**按钮会将您移至下一个屏幕”。

### 注意

警告或重要提示会以这样的方式出现。

### 注意

提示和技巧会以这样的方式出现。


# 第一章：Ajax 库

在本章中，我们将涵盖：

+   使用 jQuery 设计简单导航

+   创建选项卡导航

+   使用 Ext JS 设计组件

+   在 MochiKit 中处理事件

+   使用 Dojo 构建选项卡导航

+   使用 YUI 库构建图表应用程序

+   使用 jQuery 滑块加载动态内容

+   使用 MooTools 创建 Ajax 购物车

+   使用 prototype.js 构建 Ajax 登录表单

在本章中，我们将学习如何使用最著名的 JavaScript 库和框架的 Ajax 功能。这些库是根据我们的主观意见选择的，我们并不试图说哪个库/框架更好或更差。它们每个都有其优点和缺点。

# 使用 jQuery 设计简单导航

**jQuery**是一个开发框架，允许我们在 HTML 文档中使用 JavaScript。现在我们将使用基本的 jQuery 功能构建一个简单的导航。

## 准备就绪

在我们开始之前，我们需要包含最新的 jQuery 库。我们可以从[www.jquery.com](http://www.jquery.com)的下载部分下载它。我们将把它保存在名为`js`的 JavaScript 文件夹中，放在我们 HTML 文档的根目录中，例如`cookbook`。

本书中提到的所有库也可以在在线缓存中找到，例如[`code.google.com/apis/libraries/`](http://code.google.com/apis/libraries)。

### 注意

您可以从您在[`www.PacktPub.com`](http://www.PacktPub.com)购买的所有 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)并注册，以便直接通过电子邮件接收文件。

## 如何做...

现在，我们可以开始编写我们的`task1.html`页面。我们将把它放在`cookbook`文件夹中。

```php
<!doctype html>
<html>
<head>
<title>Example 1</title>
</head>
<body>
<ul id="navigation">
<li id="home"><a href="#">Home</a></li>
<li class="active"><a href="#">Our Books</a></li>
<li><a href="#">Shop</a></li>
<li><a href="#">Blog</a></li>
</ul>
<div id="placeHolder">
<!-- our content goes here -->
</div>
<script src=js/jquery.min.js></"></script>
<script>
$(document).ready(function(){
$('#navigation li a').each(function(){
var $item = $(this);
$item.bind('click',function(event){
event.preventDefault();
var title = $item.html();
var html = title + ' was selected.';
$('#placeHolder').html(html);
});
});
$.get('ajax/test.html', function(data) {
$('.result').html(data);
alert('Load was performed.');
});
});
</script>
</body>
</html>

```

## 它是如何工作的...

现在，让我们解释一下在前面的代码片段中做了什么。我们脚本的主要思想是在文档中找到每个超链接`<a>`，阻止其默认功能，并在我们的`placeHolder`中显示超链接内容。从一开始，我们从`doctype`和主 HTML 布局开始。页面的主体包含用于动态内容的`navigation`和`placeholder`元素。

jQuery 功能最重要的部分是包含我们的 jQuery 库。让我们将它放在关闭`<body>`标签之前。这将允许页面的 HTML 首先加载：

```php
<script src="js/jquery.min.js"></script>

```

在加载我们的 HTML 页面并且文档准备就绪后，我们可以在`$(document).ready()`函数中定义我们的 JavaScript 脚本：

```php
<script>
$(document).ready(function(){
alert("Hello jQuery!");
});
</script>

```

这也可以缩短为`$():`

```php
<script>
$(function(){
alert("Hello jQuery!");
});
</script>

```

美元符号`$()`代表对`jQuery()`工厂函数的别名。在这个函数中，我们可以使用所有的 CSS 选择器，如 ID，类，或确切的标签名称。例如：

+   `$('a'):`选择文档中的所有超链接

+   `$('#myID'):`选择具有此 ID 的元素

+   `$('.myID'):`选择具有此类的所有元素

在我们的情况下，我们正在选择`navigation <div>`中的所有超链接，并为`click`事件定义它们自己的功能：

```php
$item.bind('click',function(event){
// prevent default functionality
event.preventDefault();
// here goes the rest
});

```

我们示例的最后一步是创建`title` VAR 和 HTML 字符串，它将进入`placeHolder`：

```php
var title = $(this).html();
var html = title + ' was selected.';
$('#placeHolder').html(html);

```

## 还有更多...

前面的例子非常简单。但是 jQuery 还有很多功能可以提供给我们。这包括特殊选择器，效果，DOM 操作或 Ajax 功能。

我们可以更精确地指定我们的选择器。例如，我们可以根据它们的`href`属性指定应该受到影响的超链接：

```php
$('a[href^=mailto:]').addClass('mailto);
$('a[href$=.pdf]').addClass('pdf');
$('a[href^=http] [href*=milan]').addClass('milan');

```

jQuery 还涵盖了所有可能的事件（`click`，`blur，focus，dblclick`等），视觉效果（`hide`，`show，toggle，fadeIn，fadeOut`等），或 DOM 操作（`appendTo`，`prependTo`等）。它具有完整的 AJAX 功能，非常容易使用，例如：

```php
$.get('test.html', function(data) {
$('.result').html(data);
});

```

但是我们将在进一步的任务和章节中更仔细地了解更多 jQuery 功能。

## 另请参阅

第一章,*使用 jQuery 进行 AJAX*

第二章,*jQuery UI*

第三章,*使用 jQuery 创建选项卡导航*

# 创建选项卡导航

**jQuery UI**是由 jQuery 的核心交互插件构建的。作为一个高级框架，它使得对每个开发人员来说创建效果和动画变得容易。现在我们将使用 jQuery UI 构建一个选项卡导航。

## 准备工作

首先，我们需要从[www.jquery.com](http://www.jquery.com)包含 jQuery 库，如果我们在前面的步骤中还没有这样做。然后，我们可以从[www.jqueryui.com/download](http://www.jqueryui.com/download)下载 jQuery UI 库。在这个页面上，我们可以下载特定的模块或整个库。我们可以选择我们喜欢的主题，或者使用高级主题设置创建自己的主题。现在，我们将选择带有`ui-lightness`主题的整个库。

## 如何做...

1.  现在我们已经准备好编码了。让我们从 HTML 部分开始。这部分将定义一个带有三个选项卡和一个手风琴的`navigation`元素。

```php
<body>
<div id="navigation">
<ul>
<li><a href="#tabs-1">Home</a></li>
<li><a href="#tabs-2">Our Books</a></li>
<li><a href="http://ajax/shop.html">Shop</a></li>
</ul>
<div id="tabs-1">
<p>Lorem ipsum dolor 1</p>
</div>
<div id="tabs-2">
<p>Lorem ipsum dolor 2</p>
</div>
</div>
</body>

```

1.  当 HTML 准备好后，我们可以继续使用 CSS 和 JavaScript CSS 样式在`<head>`标签中，如下面的代码所示：

```php
<head>
<link href="css/ui-lightness/jquery-ui.custom.css"
rel="stylesheet" />
</head>

```

1.  在`<body>`标签关闭之前，我们将添加 JavaScript：

```php
<script src="js/jquery.min.js"></script>
<script src="js/jquery-ui.custom.min.js"></script>
<script>
$(document).ready(function(){
$('#navigation').tabs();
});
</script>
</body>

```

1.  我们的结果如下所示：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_01_01.jpg)

## 它是如何工作的...

下载的 jQuery UI 包含所选主题的整个 CSS 内容（jquery-ui.custom.css）。我们需要做的就是在`<head>`标签中包含它：

```php
...
<link href="css/ui-lightness/jquery-ui.custom.css"
rel="stylesheet" />

```

在 CSS 之后，我们包括 jQuery 和 jQuery UI 库：

```php
<script src="js/jquery.min.js"></script>
<script src="js/jquery-ui.custom.min.js"></script>

```

JavaScript 部分非常简单：

```php
$('#navigation').tabs();

```

重要的是要适应所需的 HTML 结构。每个超链接都将目标 HTML 内容定位到选定的`<div>`标签中。为了在它们之间创建关系，我们将在每个超链接中使用`#id`，以及选定`<div>`标签的 ID（例如，`tabs-1`）。

在第三个选项卡中有一个例外，它通过 Ajax 加载所请求的数据。在这种情况下，我们不定义任何目标区域，因为它将自动创建。正如你所看到的，使用 jQuery UI 中的 Ajax 非常简单和舒适。

## 还有更多...

jQuery UI 为我们提供了很多选项。我们可以只使用前面代码片段中呈现的默认功能，也可以使用一些附加功能：

| 通过 Ajax 获取内容： | `$( "#navigation" ).tabs({ajaxOptions: {} })`; |
| --- | --- |
| 鼠标悬停时打开： | `$( "#navigation" ).tabs({event: "mouseover"})`; |
| 折叠内容： | `$( "#navigation" ).tabs({collapsible: true})`; |
| 可排序的： | `$( "navigation" ).tabs().find( ".ui-tabs-nav" ).sortable({ axis: "x" })`; |
| Cookie 持久性： | `$( "#navigation" ).tabs({cookie: { expires: 1 }})`; |

## 另请参阅

第三章,*使用 jQuery 设计组件*

# 使用 Ext JS 设计组件

**Ext JS**是一个 JavaScript 框架，提供了许多跨浏览器用户界面小部件。Ext JS 的核心是基于组件设计构建的，可以很容易地扩展以满足我们的需求。

## 准备工作

我们可以从[www.sencha.com](http://www.sencha.com)的 Ext JS 部分下载最新版本的 Ext JS 框架。现在，我们已经准备好使用两列和一个手风琴构建经典的 Ext JS 布局。我们还可以准备一个简单的 HTML 文件`ajax/center-content.html`来测试 Ajax 功能：

```php
…
<body>
<p>Center content</p>
</body>
…

```

## 如何做...

1.  首先，我们将包括像 CSS 和 Ext JS 库文件这样的强制性文件。

```php
<link rel="stylesheet" href="css/ext-all.css" />
<script src="js/ext-base.js"></script>
<script src="js/ext-all.js"></script>

```

1.  我们将继续使用`onReady`函数，它将运行我们的脚本：

```php
<script type="text/javascript">
Ext.onReady(function(){
var viewport = new Ext.Viewport({
layout:'border',
items:[{
region:'west',
id:'west-panel',
title:'West',
split:true,
width: 200,
layout:'accordion',
items: [{
html: 'Navigation content',
title:'Navigation'
},{
title:'Settings',
html: 'Settings content'
}]
},{
region:'center',
layout:'column',
autoLoad:{
url: 'ajax/center-content.html',
method:'GET'
}
}]
});
});
</script>

```

1.  我们的带有手风琴导航的布局已经准备好了：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_01_02.jpg)

## 它是如何工作的...

Ext JS 是为开发人员构建的，以使他们的生活更轻松。正如您在源代码中所看到的，我们已经使用一个简单的 JavaScript 对象构建了一个布局。我们有一个“Viewport”和两个项目。一个位于左侧（区域：**West)**，第二个位于右侧（区域：**East)**。在这种情况下，我们不必关心 CSS。一切都由 Ext JS 直接处理，通过我们的变量如`width, margins, cmargins`等。`layout`属性非常强大。**West**侧的内部布局是一个手风琴，其中包含**Navigation**和**Settings**。在中心列，我们可以看到通过 Ajax 加载的内容，使用`autoLoad`方法。

## 还有更多...

布局的可能选项包括：Absolute，Anchor，Card，Column，Fit，Table，Vbox 和 Hbox。

# MochiKit 中的事件处理

本章中的下一个轻量级库是**MochiKit**。在这个任务中，我们将构建一个用于列出`onkeydown`和`onkeypress`事件的脚本。在每个事件之后，我们将显示按下的键及其键代码和键字符串。

## 准备工作

所有必需的文件、文档和演示都可以在[www.mochikit.com](http://www.mochikit.com)上找到。我们需要下载整个 MochiKit 库并将其保存在我们的`js`文件夹中。请注意，`MochiKit.js`只是一个主文件，其中包含了来自 MochiKit 的所有必要子模块（如`base.js, signal.js, DOM.js`等）。Ajax 请求的登陆页面将是`ajax/actions.php:`

```php
<?php
if($_GET["action"] && $_GET["key"]) {
// our logic for processing given data
} else {
echo "No params provided";
}
?>

```

## 如何做...

1.  让我们从 HTML 代码开始：

```php
<table>
<tr>
<th>Event</th>
<th>Key Code</th>
<th>Key String</th>
</tr>
<tr>
<td>onkeydown</td>
<td id="onkeydown_code">-</td>
<td id="onkeydown_string">-</td>
</tr>
<tr>
<td>onkeypress</td>
<td id="onkeypress_code">-</td>
<td id="onkeypress_string">-</td>
</tr>
</table>

```

1.  包括 MochiKit 框架：

```php
<script type="text/javascript" src="js/MochiKit/MochiKit.js"> </script>

```

1.  定义 JavaScript 功能：

```php
<script>
connect(document, 'onkeydown',
function(e) {
var key = e.key();
replaceChildNodes('onkeydown_code', key.code);
replaceChildNodes('onkeydown_string', key.string);
doSimpleXMLHttpRequest("ajax/actions.php",
{ action: "keydown", key: key.code});
});
connect(document, 'onkeypress',
function(e) {
var key = e.key();
replaceChildNodes('onkeypress_code', key.code);
replaceChildNodes('onkeypress_string', key.string);
doSimpleXMLHttpRequest("ajax/actions.php",
{ action: "keypress", key: key.code});
});
</script>

```

1.  我们的结果是：![How to do it...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_01_03.jpg)

## 它是如何工作的...

`connect()`函数将信号（Mochikit.Signal API 参考）连接到插槽。在我们的情况下，我们将我们的文档连接到`onkeydown`和`onkeypress`处理程序以调用一个`function(e)`。参数`e`表示我们的事件对象，当`key()`对象引用返回键代码和字符串时。

`replaceChildNodes(node[, childNode[,...]])`是 Mochikit.DOM API 参考的一个函数，它从给定的 DOM 元素中删除所有子元素，然后将给定的`childNode`附加到其中。

在每个`onkeydown`和`onkeypress`事件之后，我们都会使用`doSimpleXMLHttpRequest()`函数发送一个 Ajax 调用。在我们的示例中，我们页面的请求看起来像`ajax/actions.php?action=onkeydown&key=87`。

## 还有更多...

任何具有连接插槽的对象都可以通过`disconnect()`或`disconnectAll()`函数断开连接。在我们想要仅使用`connect()`一次的情况下，我们可以使用`connectOnce()`函数，这将在信号处理程序触发后自动断开信号处理程序。

MochiKit 允许我们充分利用现有的浏览器生成的事件，但其中一些事件并不是所有浏览器都原生支持的。MochiKit 能够合成这些事件，其中包括`onmouseenter, onmouseleave`和`onmousewheel`。

# 使用 Dojo 构建选项卡导航

现在我们将看一下 Dojo JavaScript 库。我们将使用`Dojo Toolkit`（dojoToolKit）的基本功能构建一个简单的选项卡导航。

## 准备工作

我们需要从 Google CDN（[`ajax.googleapis.com/ajax/libs/dojo/1.5/dojo/dojo.xd.js`](http://ajax.googleapis.com/ajax/libs/dojo/1.5/dojo/dojo.xd.js)）或 AOL CDN（[`o.aolcdn.com/dojo/1.5/dojo/dojo.xd.js.`](http://o.aolcdn.com/dojo/1.5/dojo/dojo.xd.js)）等网站上包含 Dojo Toolkit。

如果您想要下载整个 Dojo SDK，您可以在[www.dojotoolkit.org/download](http://www.dojotoolkit.org/download)找到它。

Ajax 请求的登陆页面将是`ajax/content1.html:`

```php
<body>
<h1>Operation completed.</h1>
</body>

```

## 如何做...

1.  我们将在文档的`<head>`标签中包含来自`claro`主题（包含在`dojoToolKit`中）的样式：

```php
<link rel="stylesheet" type="text/css" href="http://js/dojoToolKit/dijit/themes/claro/claro.css" />

```

1.  我们将在我们的文档的主体中定义我们的 HTML 代码：

```php
<body class="claro">
<div>
<div dojoType="dijit.layout.TabContainer">
<div dojoType="dijit.layout.ContentPane"
title="Our first tab" selected="true">
<div id="showMe">
click here to see how it works
</div>
</div>
<div dojoType="dijit.layout.ContentPane"
title="Our second tab">
Lorem ipsum - the second
</div>
<div dojoType="dijit.layout.ContentPane"
title="Our last tab" closable="true">
Lorem ipsum - the last...
</div>
</div>
</div>
</body>

```

1.  当 HTML 和 CSS 准备就绪时，我们将包含所需的模块`DojoToolkit`：

```php
<script type="text/javascript"
src="js/dojoToolKit/dojo/dojo.js"
djConfig="parseOnLoad: true"></script>
<script type="text/javascript">
dojo.require("dijit.layout.TabContainer");
dojo.require("dijit.layout.ContentPane");
</script>

```

1.  添加 JavaScript 功能给我们带来了以下结果：

```php
<script type="text/javascript">
dojo.addOnLoad(function() {
if (document.pub) { document.pub(); }
dojo.query("#showMe").onclick(function(e) {
dojo.xhrGet({
url: "ajax/content1.html",
load: function(result) {
alert("The loaded content is: " + result);
}
});
var node = e.target;
node.innerHTML = "wow, that was easy!";
});
});
</script>

```

1.  当上述代码片段准备好并保存后，我们的结果将是一个带有三个选项卡的简单选项卡导航。![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_01_04.jpg)

## 工作原理...

正如您在源代码中所看到的，我们正在使用 Dijit-Dojo UI 组件系统。**Dijit**包含在 Dojo SDK 中，并包括四种支持的主题的 UI 组件，`(nihilo soria, tundra,and claro)`。我们可以通过选择`<body>`标签中的一个类来设置我们想要使用的主题。在前面的例子中，我们有`class="claro"`。

当我们包含`dojoToolKit`脚本时，需要为`djConfig`属性提供`parseOnLoad:true`。如果没有这个，Dojo 将无法找到应该转换为 Dijit 小部件的页面元素。

当我们想要使用特定的小部件时，我们需要调用小部件的所需类（`dojo.require("dijit.layout.TabContainer")`），并提供其`dojoType`属性（`dojoType="dijit.layout.TabContainer"`）。作为在 Dojo 中使用 Ajax 的示例，我们使用`dojo.xhrGet()`函数每次点击`showMe` div 时获取`ajax/content1.html`的内容。

# 使用 YUI 库构建图表应用程序

在这个任务中，我们将使用 Yahoo!开发的 UI 库来构建一个图表。

## 准备工作

YUI 库可以在 Yahoo!的开发者网站([`developer.yahoo.com/yui/3`](http://developer.yahoo.com/yui/3))上下载。将其保存在我们的`js`文件夹中后，我们就可以开始编程了。

## 如何做...

1.  我们必须首先在文档的`<head>`标签中包含 YUI 库以及我们图表的占位符的样式：

```php
<script type="text/javascript" src="js/yui-min.js"></script>
<style>
#mychart {
margin:10px;
width:90%; max-width: 800px; height:400px;
}
</style>

```

1.  我们将把我们的 HTML 放在`<body>`标签中，以标记我们的图表将放置的位置：

```php
<div id="mychart"></div>

```

1.  我们的 JavaScript 如下：

```php
<script type="text/javascript">
(function() {
YUI().use('charts', function (Y){
//dataProvider source
var myDataValues = [
{date:"January" , windows:2000, mac:800, linux:200},
{date:"February", windows:3000, mac:1200, linux:300},
{date:"March" , windows:3500, mac:1900, linux:1400},
{date:"April" , windows:3000, mac:2800, linux:200},
{date:"May" , windows:1500, mac:3500, linux:700},
{date:"June" , windows:2000, mac:3000, linux:250}
];
//Define our axes for the chart.
var myAxes = {
financials:{
keys:["windows", "mac", "linux"],
position:"right", type:"numeric"
},
dateRange:{
keys:["date"],
position:"bottom",type:"category"
}
};
//instantiate the chart
var myChart = new Y.Chart({
type:"column", categoryKey:"date",
dataProvider:myDataValues, axes:myAxes,
horizontalGridlines: true,
verticalGridlines: true,
render:"#mychart"
});
});
})();</script>

```

1.  保存并打开我们的 HTML 文档后的结果如下：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_01_05.jpg)

## 工作原理...

YUI 图表是在`Chart`对象中定义的。对于“文档准备就绪”函数，我们将使用`(function(){...})()`语法。我们需要指定我们要使用`YUI() 'charts'`。

主要部分是创建一个`Y.Chart`对象。我们可以定义这个图表的渲染方式，网格线的外观，图表的显示位置以及要显示的数据。我们将使用`myAxes`对象定义坐标轴，该对象处理侧边的图例。我们的数据存储在`myDataValues`对象中。

## 还有更多...

有许多可能性和方法来设置我们的图表样式。我们可以将图表分割成最小的部分并设置每个属性。例如，标签的旋转或边距：

```php
styles:{
label: {rotation:-45, margin:{top:5}}
}

```

YUI 还包括 Ajax 功能。一个简单的 Ajax 调用将如下所示：

```php
<div id="content">
<p>Place for a replacing text</p>
</div>
<p><a href="http://ajax/content.html" onclick="return callAjax();">Call Ajax</a></p>
<script type="text/javascript">
//<![CDATA[
function callAjax(){
var sUrl = "http://ajax/content.html";
var callback = {
success: function(o) {
document.getElementById('content')
.innerHTML = o.responseText;
},
failure: function(o) {
alert("Request failed.");
}
}
var transaction = YAHOO.util.Connect
.asyncRequest('GET', sUrl, callback, null);
return false;
}
//]]>
</script>

```

我们创建了`callAjax()`函数，当点击`Call Ajax`超链接时触发该函数。Ajax 调用由`YAHOO.util.Connect.asyngRequest()`提供。我们定义了 HTTP 方法（GET），请求的 URL`ajax/content.html`，以及`callback`功能与`success`方法，该方法在`'content' <div>`中显示响应文本。

# 使用 jQuery 滑块加载动态内容

在这个任务中，我们将学习如何使用 jQuery 滑块动态加载页面内容。

## 准备工作

在这个任务中，我们也将使用 jQuery UI 库。我们可以从[`jqueryui.com/download`](http://jqueryui.com/download)下载 jQuery UI 库，也可以从一些 CDN 上下载。然后我们将为我们的小项目创建一个名为`packt1`的文件夹。在我们的`packt1`文件夹中将有更多的文件夹；这些是通过 Ajax 加载的 HTML 文件的`ajax`文件夹，用于我们的样式的 CSS 文件夹，以及用于我们的 JavaScript 库的`js`文件夹。

文件夹结构将如下所示：

```php
Packt1/
ajax/
content1.html
content2.html
content3-broken.php
items.html
css/ - all stylesheets
js/
ui/ - all jQuery UI resources
jquery-1.4.4.js
index.html

```

## 如何做...

一切都准备好了，我们可以开始了。

1.  我们将从基本的 HTML 布局和内容开始。这部分已经包括了一个链接到我们的 CSS，来自 jQuery UI 库。我们可以将其保存为`index.html:`

```php
<!DOCTYPE html>
<html lang="en">
<head>
<title>Ajax using jQuery</title>
<link href="css/ui-lightness/jquery-ui.custom.css"
rel="stylesheet" />
</head>
<body>
<div class="demo">
<div id="tabs">
<ul>
<li><a href="#tabs-1">Home</a></li>
<li><a href="http://ajax/content1.html">Books</a></li>
<li><a href="http://ajax/content2.html">FAQ</a></li>
<li><a href="http://ajax/content3-broken.php">
Contact(broken) </a>
</li>
</ul>
<div id="tabs-1">
This content is preloaded.
</div>
</div>
</div>
</body>
</html>

```

1.  现在我们将添加 JavaScript 库及其功能：

```php
<script src="js/jquery-1.4.4.js"></script>
<script src="js/ui/jquery-ui.min.js"></script>
<script>
$(function() {
$("#tabs").tabs({
ajaxOptions: {
success: function(){
$("#slider").slider({
range: true,
min: 1,
max: 10,
values: [1,10],
slide: function( event, ui ) {
$("#amount").val(ui.values[0] + " to " +
ui.values[1]);
},
change: function(event, ui) {
var start = ui.values[0];
var end = ui.values[1];
$('#result').html('');
for(var i = start; i <= end; i++){
var $item = $('<h3></h3>');
$item
.load('ajax/items.html #item-'+i);
.appendTo($('#result'));
} }
});
},
error: function(xhr, status, index, anchor) {
$(anchor.hash).html(
"Couldn't load this tab. We'll try to fix
this as soon as possible. " +
"If this wouldn't be a demo." );
}
}
});
});
</script>

```

1.  我们的`index.html`页面已经准备好了，我们可以创建要通过 Ajax 在我们的页面中加载的文件。

第一页将是 ajax/content1.html。此页面将包含一个具有额外功能的滑块，稍后将进行描述。

```php
<h2>Slider</h2>
<p>
<label for="amount">Displaying items:</label>
<input type="text" id="amount" style="border:0;
color:#f6931f; font-weight:bold;" value="none" />
</p>
<div id="slider"></div>
<div id="result"></div>

```

1.  第二页将是`ajax/content2.html:`

```php
<p><strong>This tab was loaded using ajax.</strong></p>
<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Aenean nec turpis justo, et facilisis ligula.</p>

```

我们 Ajax 文件夹中的最后一个文件将是 items.html：

```php
<div id="item-1">Item 1</div>
<div id="item-2">Item 2</div>
<div id="item-3">Item 3</div>
<div id="item-4">Item 4</div>
<div id="item-5">Item 5</div>
<div id="item-6">Item 6</div>
<div id="item-7">Item 7</div>
<div id="item-8">Item 8</div>
<div id="item-9">Item 9</div>
<div id="item-10">Item 10</div>

```

1.  现在，如下面的屏幕截图所示，我们有一个具有四个选项卡的多功能页面。其中三个通过 Ajax 加载，其中一个包含一个滑块。这个滑块有额外的功能，每次更改都会加载选定数量的商品。![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_01_06.jpg)

## 它是如何工作的...

从一开始，我们使用 jQuery UI 库创建了一个简单的带有四个选项卡的选项卡布局。其中一个(#tabs-1)直接包含在`index.html`文件中。jQuery UI 库允许我们定义`ajaxOptions`，以便我们可以通过 Ajax 加载我们的内容。我们在每个超链接的`href`属性之前找到所需内容的导航。如果此目标不存在，则会触发`error`方法。

我们希望在我们的第二个选项卡(名为**Books**)上有一个功能性的滑块。为了使其工作，我们不能在`$(document).ready()`函数中初始化它，因为它的 HTML 内容尚未创建。我们将仅在`success`方法中需要时添加滑块初始化。

在每次滑块更改后，都会触发`load()`函数。此函数通过 Ajax 加载给定目标的内容。在我们的情况下，我们使用了一个更具体的选择器，具有对象的确切 ID，该 ID 显示在我们的结果框中。

## 还有更多...

在这项任务中，我们只使用了基本的`load()`函数，但 jQuery 提供了更多的 Ajax 方法，如下表所示:

| `$.ajax` | 执行 Ajax 请求 |
| --- | --- |
| `jQuery.post()` | 使用 HTTP POST 请求从服务器加载数据 |
| `jQuery.get()` | 使用 HTTP GET 请求从服务器加载数据 |
| `jQuery.getJSON()` | 使用 HTTP GET 请求从服务器加载 JSON 数据 |
| `jQuery.getScript()` | 使用 HTTP GET 请求从服务器加载并执行 JavaScript 文件 |

## 另请参阅

第三章,*使用 jQuery 的有用工具*

# 使用 MooTools 创建 Ajax 购物车

这项任务将向我们展示如何在 MooTools JavaScript 框架中使用 Ajax。我们将构建一个带有拖放功能的购物车。在每次 UI 解释添加新商品到购物车后，我们将向服务器发送一个 HTTP POST 请求。

## 准备工作

**MooTools**可在[`mootools.net/download`](http://https://mootools.net/download)或 Google 的 CDN 上下载。为了在服务器和客户端之间进行通信，我们将在我们的`ajax`文件夹中创建一个新文件，例如`addItem.php:`

```php
<?php
if($_POST['type']=='Item'){
echo 'New Item was added successfuly.';
}
?>

```

创建了这个虚拟的 PHP 文件后，我们准备继续进行此任务的编程部分。

## 如何做...

1.  我们将像通常一样从 HTML 布局开始，包括 MooTools 库：

```php
<!doctype html>
<html>
<head>
<title>Ajax Using MooTools</title>
</head>
<body>
<div id="items">
<div class="item">
<span>Shirt 1</span>
</div>
<div class="item">
<span>Shirt 2</span>
</div>
<div class="item">
<span>Shirt 3</span>
</div>
<div class="item">
<span>Shirt 4</span>
</div>
<div class="item">
<span>Shirt 5</span>
</div>
<div class="item">
<span>Shirt 6</span>
</div>
</div>
<div id="cart">
<div class="info">Drag Items Here</div>
</div>
<h3 id="result"></h3>
<script src="js/mootools-core-1.3-full.js"></script>
<script src="js/mootools-more-1.3-full.js"></script>
<script src="js/mootools-art-0.87.js"></script>
</body>
</html>

```

1.  在这项任务中，我们必须提供自己的 CSS 样式：

```php
<style>
#items {
float: left; border: 1px solid #F9F9F9; width: 525px;
}
item {
background-color: #DDD;
float: left;
height: 100px;
margin: 10px;
width: 100px;
position: relative;
}
item span {
bottom: 0;
left: 0;
position: absolute;
width: 100%;
}
#cart {
border: 1px solid #F9F9F9;
float: right;
padding-bottom: 50px;
width: 195px;
}
#cart .info {
text-align: center;
}
#cart .item {
background-color: green;
border-width: 1px;
cursor: default;
height: 85px;
margin: 5px;
width: 85px;
}
</style>

```

1.  当我们的 UI 外观符合我们的期望时，我们可以开始 JavaScript：

```php
<script>
window.addEvent('domready', function(){
$('.item').addEvent('mousedown', function(event){
event.stop();
var shirt = this;
var clone = shirt.clone()
.setStyles(shirt.getCoordinates())
.setStyles({
opacity: 0.6,
position: 'absolute'
})
.inject(document.body);
var drag = new Drag.Move(clone, {
droppables: $('cart'),
onDrop: function(dragging, cart){
dragging.destroy();
new Request.HTML({
url: 'ajax/addItem.php',
onRequest: function(){
$('result').set('text', 'loading...');
console.log('loading...');
},
onComplete: function(response){
$('result').empty().adopt(response);
console.log(response);
}a
}).post('type=shirt');
if (cart != null){
shirt.clone().inject(cart);
cart.highlight('#7389AE', '#FFF');
}
},
onCancel: function(dragging){
dragging.destroy();
}
});
drag.start(event);
});
});
</script>

```

1.  一旦我们保存了我们的代码，我们的购物车就准备好了。结果如下:![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_01_07.jpg)

## 它是如何工作的...

`$(document).ready`函数通过将`domready`事件绑定到`window`对象来执行。对于每个项目，我们都会添加一个`mousedown`事件，其中包含将每个项目添加到购物车中的整个过程，使用`Drag`对象和`clone()`函数。

为了与服务器通信，我们使用`Request.HTML`方法，并使用`HTTP post`方法发送它，带有`post`变量`type`。如果变量`type`等于字符串`shirt`，这意味着新商品已添加到购物车，并且信息框结果已更新为`'新商品已成功添加'`。

## 还有更多...

`Class Request`代表处理`XMLHttpRequest`的主要类:

```php
var myRequest = new Request([options]);

```

前述模板的示例如下:

```php
var request = new Request({
url: 'sample.php', data: { sample: 'sample1'},
onComplete: function(text, xml){
$('result').set('text ', text);
}

```

在 MooTools 库的核心中，`Request`类被扩展为`Request.HTML`和`Request.JSON`。

`Request.HTML`是专门用于接收 HTML 数据的扩展`Request`类：

```php
new Request.HTML({
url: 'sample.php',
onRequest: function(){
console.log('loading...');
},
onComplete: function(response){
$('result').empty().adopt(response);
}
}).post('id=242');

```

我们可以使用`post`或`get`方法：

```php
new Request.HTML([options]).get({'id': 242});

```

作为客户端和服务器之间有效的通信实践，我们可以使用`Request.JSON`以`JSON`格式接收和传输 JavaScript 对象。

```php
var jsonRequest = new Request.JSON({
url: 'sample.php', onSuccess: function(author){
alert(author.firstname); // "Milan".
alert(author.lastname); // "Sedliak"
alert(author.company); // "Skype"
}}).get({bookTitle: 'PHP Ajax CookBook', 'bookID': 654});

```

# 使用 prototype.js 构建 Ajax 登录表单

本章中最后一个 JavaScript 框架是`prototype.js`。在这个任务中，我们将使用 Ajax 功能制作一个简单的登录表单。我们将看一下在 Ajax 中最常用的`prototype.js`实践。

## 准备工作

我们可以从[`www.prototypejs.org/download`](http://www.prototypejs.org/download)下载`prototype.js`。然后，只需将其保存在`js`文件夹中。要完成这个任务，我们需要让 Apache 服务器运行。

## 如何做...

1.  首先，让我们创建我们的虚拟`.php`文件，`login.php:`

```php
<?php
if($_POST['username']==$_POST['password']){
echo 'proceed';
}
?>

```

然后，我们可以继续进行 HTML 布局。

```php
<!DOCTYPE html>
<html>
<head>
</head>
<body>
<form id="loginForm">
<label for="username">Username: </label>
<input type="text" id="username" name="username" />
<br />
<label for="password">Password:</label>
<input type="password" id="password" name="password"/>
<br /><br />
<input type="submit" value="Sign In" id="submit" />
</form>
</body>
</html>

```

1.  当 HTML 设置好后，我们将定义我们的 JavaScript：

```php
<script src="js/prototype.js"></script>
<script>
$('submit').observe('click', login);
function login(e) {
Event.stop(e);
var url = "ajax/login.php";
new Ajax.Request(url, {
method: 'post',
parameters: {
username: document.getElementById('username').value,
password: document.getElementById('password').value
},
onSuccess: process,
onFailure: function() {
alert("There was an error with the connection");
}
});
}
function process(transport) {
var response = transport.responseText;
if(response == 'proceed'){
$('loginForm').hide();
var my_div = document.createElement('div');
my_div.appendChild(document.createTextNode("You are logged in!"));
document.body.appendChild(my_div);
}
else
alert("Sorry, your username and password don't match.");
}
</script>

```

### 它是如何工作的...

正如您在源代码中所看到的，我们在 ID 为`submit`的按钮元素上`observe`了一个新的`click`事件，这是我们登录表单中的`submit`按钮。`login()`函数由`click`事件触发。`submit`按钮的默认行为被`Event.stop(event)`替换，因此触发了 HTTP 请求的行为被禁用。而是创建了一个 Ajax 请求。`Ajax.Request`是在`prototype.js`中使用 Ajax 的基本类。我们使用了两个参数（用户名和密码）的`post`方法。如果请求成功，并且来自`login.php`的响应文本是`proceed`，那么我们成功登录了。

### 还有更多...

`prototype.js`将`Ajax.Request`对象扩展到了更多功能，如下所述：

+   Ajax.Updater:

Ajax.Updater 是`Ajax.Request`对象的扩展，它执行 Ajax 请求并根据响应文本更新容器：

```php
<div id="container">Send the request</div>
<script>
$('submit').observe('click', login);
function login(){
new Ajax.Updater(
'saladContainer', 'login.php', { method: 'post' }
);
})
</script>

```

+   **Ajax.PeriodicalUpdater:**

在我们需要定期更新内容的情况下，我们可以使用周期性更新器：

```php
new Ajax.PeriodicalUpdater('items', '/items', {
method: 'get', frequency: 3, decay: 2
});

```

频率表示更新内容的周期性（以秒为单位）。在上面的代码片段中，我们的内容将每 3 秒更新一次。

+   **Ajax.Responders:**

`Ajax.Responders`表示全局监听器的存储库，用于监视页面上的所有 Ajax 活动：

```php
Ajax.Responders.register(responder)
Ajax.Responders.unregister(responder)

```

使用 responders，我们可以轻松跟踪页面上有多少个 Ajax 请求是活动的。

```php
Ajax.Responders.register({
onCreate: function() {
Ajax.activeRequestCount++;
},
onComplete: function() {
Ajax.activeRequestCount--;
}
});

```


# 第二章：基本实用程序

在本章中，我们将涵盖：

+   使用 Ajax 验证表单

+   创建一个自动建议控件

+   制作表单向导

+   使用 Ajax 上传文件

+   使用 Ajax 上传多个文件

+   创建一个五星评分系统

+   使用 Ajax 构建一个带有验证的 PHP 联系表单

+   在 Ajax 中显示表格

+   使用 PHP 和 Ajax 构建分页

在本章中，我们将学习如何构建基本的 Ajax 表单。我们将尝试理解在哪里可以使用 Ajax 方法，以及在哪里不能。我们可以使用 Ajax 的方式有很多种。以下是一些基于用户体验和特定系统性能的“最佳”实践。Ajax 使我们的生活更轻松，更快速，更好；如何以及在哪里使用取决于我们。

# 使用 Ajax 验证表单

Ajax 的主要思想是实时从服务器获取数据，而不需要重新加载整个页面。在这个任务中，我们将使用 Ajax 构建一个带有验证的简单表单。

## 准备就绪

由于在此任务中使用了 JavaScript 库，我们将选择 jQuery。我们将下载（如果我们还没有下载）并将其包含在我们的页面中。我们需要准备一些虚拟的 PHP 代码来检索验证结果。在这个例子中，让我们将其命名为`inputValidation.php`。我们只是检查`param`变量是否存在。如果这个变量在`GET`请求中被引入，我们确认验证并将一个`OK`状态发送回页面：

```php
<?php
$result = array();
if(isset($_GET["param"])){
$result["status"] = "OK";
$result["message"] = "Input is valid!";
} else {
$result["status"] = "ERROR";
$result["message"] = "Input IS NOT valid!";
}
echo json_encode($result);
?>

```

## 如何做...

1.  让我们从基本的 HTML 结构开始。我们将定义一个带有三个输入框和一个文本区域的表单。当然，它是放在`<body>`中的：

```php
<body>
<h1>Validating form using Ajax</h1>
<form class="simpleValidation">
<div class="fieldRow">
<label>Title *</label>
<input type="text" id="title" name="title"
class="required" />
</div>
<div class="fieldRow">
<label>Url</label>
<input type="text" id="url" name="url"
value="http://" />
</div>
<div class="fieldRow">
<label>Labels</label>
<input type="text" id="labels" name="labels" />
</div>
<div class="fieldRow">
<label>Text *</label>
<textarea id="textarea" class="required"></textarea>
</div>
<div class="fieldRow">
<input type="submit" id="formSubmitter" value="Submit" disabled="disabled" />
</div>
</form>
</body>

```

1.  为了对有效输入进行视觉确认，我们将定义 CSS 样式：

```php
<style>
label{ width:70px; float:left; }
form{ width:320px; }
input, textarea{ width:200px;
border:1px solid black; float:right; padding:5px; }
input[type=submit] { cursor:pointer;
background-color:green; color:#FFF; }
input[disabled=disabled], input[disabled] {
background-color:#d1d1d1; }
fieldRow { margin:10px 10px; overflow:hidden; }
failed { border: 1px solid red; }
</style>

```

1.  现在，是时候包括 jQuery 及其功能了：

```php
<script src="js/jquery-1.4.4.js"></script>
<script>
var ajaxValidation = function(object){
var $this = $(object);
var param = $this.attr('name');
var value = $this.val();
$.get("ajax/inputValidation.php",
{'param':param, 'value':value }, function(data) {
if(data.status=="OK") validateRequiredInputs();
else
$this.addClass('failed');
},"json");
}
var validateRequiredInputs = function (){
var numberOfMissingInputs = 0;
$('.required').each(function(index){
var $item = $(this);
var itemValue = $item.val();
if(itemValue.length) {
$item.removeClass('failed');
} else {
$item.addClass('failed');
numberOfMissingInputs++;
}
});
var $submitButton = $('#formSubmitter');
if(numberOfMissingInputs > 0){
$submitButton.attr("disabled", true);
} else {
$submitButton.removeAttr('disabled');
}
}
</script>

```

1.  我们还将初始化文档`ready`函数：

```php
<script>
$(document).ready(function(){
var timerId = 0;
$('.required').keyup(function() {
clearTimeout (timerId);
timerId = setTimeout(function(){
ajaxValidation($(this));
}, 200);
});
});
</script>

```

1.  当一切准备就绪时，我们的结果如下：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_02_01.jpg)

## 它是如何工作的...

我们创建了一个带有三个输入框和一个文本区域的简单表单。具有类`required`的对象在`keyup`事件后会自动进行验证，并调用`ajaxValidation`函数。我们的`keyup`功能还包括`Timeoutfunction`，以防止用户仍在输入时进行不必要的调用。验证基于两个步骤：

+   验证实际输入框：我们通过 Ajax 将插入的文本传递给`ajax/inputValidation.php`。如果服务器的响应不是`OK`，我们将标记此输入框为“失败”。如果响应是`OK`，我们将进行第二步。

+   检查我们表单中的其他必填字段。当表单中没有剩余的“失败”输入框时，我们将启用提交按钮。

## 还有更多...

在这个例子中，验证是非常基本的。我们只是检查服务器的响应状态是否为`OK`。我们可能永远不会遇到像我们这里一样的必填字段验证。在这种情况下，最好直接在客户端使用`length`属性，而不是用很多请求打扰服务器，只是为了检查必填字段是空还是填充了。这个任务只是基本`Validation`方法的演示。最好在服务器端扩展它，直接检查 URL 表单或标题是否已经存在于我们的数据库中，并让用户知道问题所在以及如何解决。

## 另请参阅

*在本章中使用 PHP Ajax 联系表单和验证*配方

# 创建一个自动建议控件

这个配方将向我们展示如何创建一个自动建议控件。当我们需要在大量数据中进行搜索时，这个功能非常有用。基本功能是根据输入框中的文本显示建议数据列表。

## 准备就绪

我们可以从虚拟的 PHP 页面开始，它将作为数据源。当我们用`GET`方法和变量`string`调用这个脚本时，它将返回包含所选字符串的记录（名称）列表：

```php
<?php
$string = $_GET["string"];
$arr = array(
"Adam",
"Eva",
"Milan",
"Rajesh",
"Roshan",
// ...
"Michael",
"Romeo"
);
function filter($var){
global $string;
if(!empty($string))
return strstr($var,$string);
}
$filteredArray = array_filter($arr, "filter");
$result = "";
foreach ($filteredArray as $key => $value){
$row = "<li>".str_replace($string,
"<strong>".$string."</strong>", $value)."</li>";
$result .= $row;
}
echo $result;
?>

```

## 如何做...

1.  和往常一样，我们将从 HTML 开始。我们将用一个输入框和一个未排序的列表`datalistPlaceHolder`来定义表单：

```php
<h1>Dynamic Dropdown</h1>
autosuggest controlcreating<form class="simpleValidation">
<div class="fieldRow">
<label>Skype name:</label>
<div class="ajaxDropdownPlaceHolder">
<input type="text" id="name" name="name"
class="ajaxDropdown" autocomplete="OFF" />
<ul class="datalistPlaceHolder"></ul>
</div>
</div>
</form>

```

1.  当 HTML 准备好后，我们将使用 CSS 进行调整：

```php
<style>
label { width:80px; float:left; padding:4px; }
form { width:320px; }
input, textarea {
width:200px; border:1px solid black;
border-radius: 5px; float:right; padding:5px;
}
input[type=submit] { cursor:pointer;
background-color:green; color:#FFF; }
input[disabled=disabled] { background-color:#d1d1d1; }
.fieldRow { margin:10px 10px; overflow:hidden; }
.validationFailed { border: 1px solid red; }
.validationPassed { border: 1px solid green; }
.datalistPlaceHolder {
width:200px; border:1px solid black;
border-radius: 5px;
float:right; padding:5px; display:none;
}
ul.datalistPlaceHolder li { list-style: none;
cursor:pointer; padding:4px; }
ul.datalistPlaceHolder li:hover { color:#FFF;
background-color:#000; }
</style>

```

1.  现在真正的乐趣开始了。我们将包括 jQuery 库并定义我们的 keyup 事件：

```php
<script src="js/jquery-1.4.4.js"></script>
autosuggest controlcreating<script>
var timerId;
var ajaxDropdownInit = function(){
$('.ajaxDropdown').keyup(function() {
var string = $(this).val();
clearTimeout (timerId);
timerId = setTimeout(function(){
$.get("ajax/dropDownList.php",
{'string':string}, function(data) {
if(data)
$('.datalistPlaceHolder').show().html(data);
else
$('.datalistPlaceHolder').hide();
});
}, 500 );
});
}
</script>

```

1.  当一切准备就绪时，我们将在文档`ready`函数中调用`ajaxDropdownInit`函数：

```php
<script>
$(document).ready(function(){
ajaxDropdownInit();
});
</script>

```

1.  我们的自动建议控件已经准备好了。以下截图显示了输出：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_02_02.jpg)

## 它是如何工作的...

本教程中的`autosuggest`控件基于输入框和`datalistPlaceHolder`中的项目列表。在输入框的每个`keyup`事件之后，`datalistPlaceHolder`将通过`ajax/dropDownList.php`中定义的 Ajax 函数加载项目列表。本教程的一个很好的特性是`timerID`变量，当与`setTimeout`方法一起使用时，将允许我们仅在停止输入时向服务器发送请求（在我们的情况下是 500 毫秒）。这可能看起来并不那么重要，但它将节省大量资源。当我们已经输入“米兰”时，我们不想等待“M”在输入框中的响应。而不是 5 个请求（每个 150 毫秒），我们只有一个。例如，每天有 1 万个用户，效果是巨大的。

## 还有更多...

我们始终需要记住，服务器的响应是以 JSON 格式返回的。

```php
[{
'id':'1',
'contactName':'Milan'
},...,{
'id':'99',
'contactName':'Milan (office)'
}]

```

在 JavaScript 中使用 JSON 对象并不总是从性能的角度来看都有用。让我们想象一下，我们有一个 JSON 文件中有 5000 个联系人。

从 5000 个对象构建 HTML 可能需要一些时间，但是，如果我们构建一个 JSON 对象，代码将如下所示：

```php
[{
autosuggest controlcreating"status": "100",
"responseMessage": "Everything is ok! :)",
"data": "<li><h2><ahref=\"#1\">Milan</h2></li>
<li><h2><ahref=\"#2\">Milan2</h2></li>
<li><h2><ahref=\"#3\">Milan3</h2></li>"
}]

```

在这种情况下，我们将在 HTML 中拥有完整的数据，不需要创建任何逻辑来创建一个简单的项目列表。

# 制作表单向导

**表单向导**基本上是分成几个步骤的表单。它们对于投票或表单的特殊情况非常有用，当我们想要在网站上分割注册流程时。它们也用于电子商务网站，在购买过程中（购物车付款方式送货地址确认购买本身）。在这个教程中，我们将构建一个表单向导（尽可能简单）。

## 准备工作

我们将准备虚拟的 PHP 文件`step1.php, step2.php`和`step3.php`。这些文件的内容很简单：

```php
<?php
echo "STEP 1"; // Same for 2 and 3
?>

```

在这里，我们将包括 jQuery 库：

```php
<script src="js/jquery-1.4.4.js"></script>

```

## 如何做...

1.  我们首先定义 HTML 内容：

```php
<div class="wizard">
<ul class="wizardNavigation">
<li class="active first" id="step1">Step 1</li>
<li id="step2">Step 2</li>
<li id="step3" class="last">Step 3</li>
</ul>
<div class="wizardBody">STEP 1</div>
<div class="wizardActionButtons">
<a href="javascript:submitThePage('back');" class="back"
style="display:none;">Back</a>
<a href="http:// class="finish" style="display:none;"> Finish</a>
<a href="javascript:submitThePage('next');"
class="next">Next</a>
</div>
</div>

```

1.  接下来，我们将在 HTML 中包含 CSS 样式如下：

```php
<style>
.wizard { width:300px; overflow:hidden;
border:1px solid black; }
.wizardNavigation { overflow:hidden;
border-bottom:1px solid #D2D2D2; }
.wizardNavigation li { float:left; list-style:none;
padding:10px; cursor:default; color:#D2D2D2; }
.wizardNavigation li.active { color:#000; }
.wizardBody { clear:both; padding:20px; }
.wizardActionButtons { padding:10px;
border-top:1px solid #D2D2D2; }
.wizardActionButtons .back { float:left; cursor:pointer; }
.wizardActionButtons .next,
.wizardActionButtons .finish { float:right; cursor:pointer; }
.wizard .disabled { color:#D2D2D2; }
</style>

```

1.  接下来，我们将在关闭`</body>`标签之前放置 JavaScript：

```php
<script>
var submitThePage = function (buttonDirection){
var $currentTab = $('.wizardNavigation li.active');
if(buttonDirection == 'next')
var $actionTab = $currentTab.next('li');
else
var $actionTab = $currentTab.prev('li');
var target = "ajax/"+ $actionTab.attr('id') +".php";
$.get(target, {'param':'test'},
function(data) {
if(data){
if($actionTab){
$currentTab.removeClass('active');
$actionTab.addClass('active');
}
displayFinishButton($actionTab.hasClass('last'));
displayNextButton(!$actionTab.hasClass('last'));
displayBackButton(!$actionTab.hasClass('first'));
$('.wizardBody').html(data);
}
});
}
var displayBackButton = function(enabled){
enabled == true ?
$('.back').show() : $('.back').hide();
}
var displayNextButton = function(enabled){
enabled == true ?
$('.next').show() : $('.next').hide();
}
var displayFinishButton = function(enabled){
enabled == true ?
$('.finish').show() : $('.finish').hide();
}
</script>

```

1.  结果如下：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_02_03.jpg)

## 它是如何工作的...

向导分为三个部分：

+   第一部分是`wizardNavigation`，其中包括向导中的所有步骤（选项卡）。

+   第二个是`wizardBody`，其中包含当前步骤（选项卡）的内容。

+   最后一部分是`wizardActionButtons`，其中包含**返回**、**下一步**和**完成**按钮。**返回**和**下一步**按钮触发`submitThePage`函数，带有`buttonDirection`参数（**返回**或**下一步**）。此函数将通过`$.get()`函数将 Ajax 请求发送到下一步，该下一步由`target`参数表示。目标自动从选项卡导航中获取。它等于每个导航元素的`id`属性。

## 还有更多...

我们已经理解了表单向导的基本思想。但有时我们没有时间或资源来创建自己的 jQuery 功能。在这种情况下，我们可以使用一些免费的 jQuery 插件，比如来自[`plugins.jquery.com/project/formwizard`](http://plugins.jquery.com/project/formwizard)的`formwizard`插件。并非所有插件都是 100%功能的；每样东西都有自己的“bug”。然而，帮助总是很容易得到的。我们可以修改插件以满足我们的要求，然后等待插件的下一个版本中修复 bug，或者我们可以贡献自己的代码。

# 使用 Ajax 上传文件

在这个示例中，我们将讨论通过 Ajax 上传文件。实际上，没有 Ajax 方法可以做到这一点。我们可以使用`iframe`方法来模拟 Ajax 功能。

## 准备工作

首先，我们将准备`uploads`文件夹，并确保它是可访问的。在 Mac OS X/Linux 中，我们将使用：

```php
$ sudo chmod 777 'uploads/'

```

### 注意

在 Windows 7 中，我们可以右键单击**文件夹属性|编辑|选择用户|组**，从权限窗口中选择（选择任何人），并在**允许**列下选择**完全控制**以分配完全访问权限控制权限。

现在让我们创建一个 HTML 文件`(ajaxUpload.html)`和一个 PHP 文件`(ajax/uploadFile.php)`。

## 如何做...

1.  `ajaxUpload.html`将如下所示：

```php
<script>
function submitForm(upload_field){
upload_field.form.submit();
upload_field.disabled = true;
return true;
}
</script>

```

1.  我们的 HTML 主体如下：

```php
<h1>Uploading File Using Ajax</h1>
<form action="ajax/uploadFileSingle.php" target="uploadIframe"
method="post" enctype="multipart/form-data">
<div class="fieldRow">
<label>Select the file: </label>
<input type="file" name="file" id="file"
onChange="submitForm(this)" />
</div>
</form>
<iframe id="uploadIframe" name="uploadIframe"></iframe>
<div id="placeHolder"></div>

```

ajax/uploadFile.php 的内容如下：

```php
<head>
<script src="../js/jquery-1.4.4.js"></script>
</head>
<body>
<?php
$upload_dir = "../uploads";
$result["status"] = "200";
$result["message"]= "Error!";
if(isset($_FILES['file'])){
echo "Uploading file... <br />";
if ($_FILES['file']['error'] == UPLOAD_ERR_OK) {
$filename = $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'],
$upload_dir.'/'.$filename);
$result["status"] = "100";
$result["message"]=
"File was uploaded successfully!";
} elseif ($_FILES['file']['error'] ==
UPLOAD_ERR_INI_SIZE) {
$result["status"] = "200";
$result["message"]= "The file is too big!";
} else {
$result["status"] = "500";
$result["message"]= "Unknown error!";
}
}
?>
</body>

```

1.  在`$(document).ready`上初始化结果消息：

```php
<script>
$(document).ready(function(){
$('#placeHolder', window.parent.document)
.html('<?php echo htmlspecialchars($result["message"]); ?>');
});
</script>

```

1.  结果如下：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_02_04.jpg)

## 它是如何工作的...

正如您在这个任务中所看到的，我们创建了一个简单的表单，可以上传文件。这个例子的主要重点在于**iframe**，我们将表单提交到这个**iframe**。这个**iframe**代表一个包含 PHP 的容器，它提供所选文件的物理上传。当上传成功时，我们将在父文档的`placeHolder`中显示结果消息。

## 还有更多...

要增加上传文件的最大允许大小，我们可以在`php.ini`中使用`upload_max_filesize`指令。还有更多用于上传文件的指令：

| 指令 | 默认值 |   |
| --- | --- | --- |
| `file_uploads` | `1` | 允许/禁止 HTTP 文件上传 |
| `upload_tmp_dir` | `NULL` | 文件上传期间存储文件的临时目录 |
| `upload_max_filesize` | `2M` | 上传文件的最大大小 |
| `max_file_uploads` | `20` | 同时进行的文件上传的最大数量 |

# 使用 Ajax 上传多个文件

在上一个任务中，我们学习了如何通过伪 Ajax 方法使用 iframe 上传单个文件。这个例子有一个很大的缺点；我们无法选择多个文件。这只能通过使用 HTML5（并非所有浏览器都完全支持）、Flash 或 Java 来实现。在这个示例中，我们将构建一个表单，允许我们选择多个文件，并在单击一次后将它们上传到服务器。

## 准备工作

对于这个任务，我们需要下载 jQuery 库、SWFUpload 库([`swfupload.org/`](http://swfupload.org/))，以及 Adam Royle 的 SWFUpload jQuery 插件([`blogs.bigfish.tv/adam/`](http://blogs.bigfish.tv/adam/))。

## 如何做...

1.  让我们从 HTML 开始：

```php
<div id="swfupload-control">
<p>Upload files.</p>
<input type="button" id="button" value="Upload" />
<p id="queuestatus"></p>
<ol id="log"></ol>
</div>

```

1.  接下来，我们定义 CSS：

```php
<style>
#swfupload-control p { margin:10px 5px; }
#log li { list-style:none; margin:2px; padding:10px;
font-size:12px; color:#333; background:#fff;
position:relative; border:1px solid black;
border-radius: 5px;}
#log li .progressbar { height:5px; background:#fff; }
#log li .progress { background:#999; width:0%; height:5px; }
#log li p { margin:0; line-height:18px; }
#log li.success { border:1px solid #339933;
background:#ccf9b9;}
</style>

```

1.  现在，我们将包括 jQuery、`SWFUpload`和 SWFUpload jQuery 库：

```php
<script src="js/jquery-1.4.4.js"></script>
<script src="js/swfupload/swfupload.js"></script>
<script src="js/jquery.swfupload.js"></script>

```

1.  接下来，我们将定义`SWFUpload`对象和绑定事件，如下所示：

```php
<script>
$(function(){
$('#swfupload-control').swfupload({
upload_url: "upload-file.php",
file_post_name: 'uploadfile',
flash_url : "js/swfupload/swfupload.swf",
button_image_url :
'js/swfupload/wdp_buttons_upload_114x29.png',
button_width : 114,
button_height : 29,
button_placeholder : $('#button')[0],
debug: false
})
.bind('fileQueued', function(event, file){
var listitem='<li id="'+file.id+'" >'+
file.name+' ('+Math.round(file.size/1024)+' KB)
<span class="progressvalue" ></span>'+
'<div class="progressbar" >
<div class="progress" ></div></div>'+
'<p class="status" >Pending</p>'+'</li>';
$('#log').append(listitem);
$(this).swfupload('startUpload');
})
.bind('uploadStart', function(event, file){
$('#log li#'+file.id)
.find('p.status').text('Uploading...');
$('#log li#'+file.id)
.find('span.progressvalue').text('0%');
})
.bind('uploadProgress', function(event, file, bytesLoaded){
var percentage=Math.round((bytesLoaded/file.size)*100);
$('#log li#'+file.id)
.find('div.progress').css('width', percentage+'%');
$('#log li#'+file.id)
.find('span.progressvalue').text(percentage+'%');
})
.bind('uploadSuccess', function(event, file, serverData){
var item=$('#log li#'+file.id);
item.find('div.progress').css('width', '100%');
item.find('span.progressvalue').text('100%');
item.addClass('success').find('p.status')
.html('File was uploaded successfully.');
})
.bind('uploadComplete', function(event, file){
$(this).swfupload('startUpload');
})
});
</script>

```

1.  用于上传文件的 PHP 如下：

```php
<?php
$uploaddir = './uploads/';
$file = $uploaddir . basename($_FILES['uploadfile']['name']);
if (move_uploaded_file($_FILES['uploadfile']['tmp_name'], $file)) { echo "success"; } else { echo "error"; }
?>

```

1.  我们的结果如下：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_02_05.jpg)

## 它是如何工作的...

首先，我们为`swfupload-control`定义一个简单的 HTML 表单，包括输入按钮。这个按钮被一个`swf`对象覆盖，它允许我们选择多个文件。在 JavaScript 中，我们使用基本设置`(upload_url、file_post_name、flash_url、button_image_url`等)定义主`SWFUpload`对象。我们可以使用预定义的事件为每个文件构建一个带有进度条的容器。

## 还有更多...

在`SWFUpload`中定义的事件为我们提供了在文件上传期间完全控制的能力，如下所示：

| **flashReady** | 这是由 Flash 控件调用的，通知`SWFUpload`Flash 电影已加载。 |
| --- | --- |
| **swfUploadLoaded** | 这是为了确保可以安全调用`SWFUpload`方法而调用的。 |
| **fileDialogStart** | 在调用`selectFile`选择文件后触发此事件。 |
| **fileQueued** | 在**FileSelectionDialog**窗口关闭后，每个排队的文件都会触发此事件。 |
| **fileQueueError** | 在**FileSelectionDialog**窗口关闭后，每个未排队的文件都会触发此事件。 |
| **fileDialogComplete** | 这在**FileSelectionDialog**窗口关闭并且所有选定的文件都已处理后触发。 |
| **uploadStart** | 这是在文件上传之前立即调用的。 |
| **uploadProgress** | 这是由 Flash 控件定期触发的。 |
| **uploadError** | 每当上传被中断或未成功完成时触发。 |
| **uploadSuccess** | 当整个上传已传输并服务器返回 HTTP 200 状态代码时触发。 |
| **uploadComplete** | 这总是在上传周期结束时触发（在`uploadError`或`uploadSuccess`之后）。 |

# 创建一个五星级评分系统

在这个任务中，我们将学习如何构建一个五星级评分系统。这个功能经常被电子商务网站使用，允许用户对产品、文章或任何值得用户评价的东西进行评分。

## 准备工作

让我们准备一个虚拟的 PHP 文件`ajax/saveRating.php`来确认评分已保存：

```php
<?php
$result = array();
$result["status"] = "";
$result["message"] = "";
if(isset($_POST["itemID"]) && isset($_POST["itemValue"])){
$result["status"] = "OK";
$result["message"] = "Rating has been saved successfully.";
} else {
$result["status"] = "ERROR";
$result["message"] = "Provide itemID and itemValue!";
}
echo json_encode($result);
?>

```

我们需要准备一个带有星星的.gif 图像。这个.gif 包括星星的三种变化：第一种是非活动状态的星星，第二种是“悬停”事件的星星，第三种是活动状态的星星。

![准备工作](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_02_06.jpg)

## 如何做...

1.  我们准备开始 HTML 部分：

```php
<body>
five star rating systemcreating, steps<h1>Creating Five Stars Rating System</h1>
<div class="fieldRow">
<label>Book 123A</label>
<ul id="book-123a" class="ratingStars">
<li></li>
<li class="active"></li>
<li></li>
<li></li>
<li></li>
</ul>
</div>
<div class="fieldRow">
<label>Book 123B</label>
<ul id="book-123b" class="ratingStars">
<li class="active"></li>
<li></li>
<li></li>
<li></li>
<li></li>
</ul>
</div>
<div class="fieldRow">
<label>Book 123C</label>
<ul id="book-123c" class="ratingStars">
<li></li>
<li></li>
<li></li>
<li></li>
<li class="active"></li>
</ul>
</div>
<div id="placeHolder"></div>
</body>

```

1.  让我们包括 jQuery 库并定义 JavaScript 功能：

```php
<script src="js/jquery-1.4.4.js"></script>
<script>
$(document).ready(function(){
$('ul.ratingStars li.active').prevAll().addClass('active');
$('ul.ratingStars li').each(function(){
var $item = $(this);
var $itemContainer = $item.parents('ul.ratingStars');
var containerID = $itemContainer.attr('id');
var $itemsAll = $itemContainer.find('li');
$item.mouseover(function(){
$itemsAll.addClass('default');
$item.prevAll().addClass('highlighted');
})
.mouseout(function(){
$itemsAll
.removeClass('default')
.removeClass('highlighted');
});
.bind('click', function(){
var itemIndex = $itemsAll.index(this);
$.post('ajax/saveRating.php',
{'itemID':containerID, 'itemValue': itemIndex},
function(data) {
if(data && data.status == "100"){
$item
.addClass('active')
.removeClass('highlighted');
$item.nextAll().removeClass('active');
$item.prevAll().addClass('active');
} else {
alert('Error!');
}
}, "json");
});
});
});
</script>

```

1.  CSS 是这项任务中的关键部分之一：

```php
<style>
five star rating systemcreating, stepslabel, ul { float:left; }
.fieldRow { clear:both; margin:5px 0px; overflow:hidden; }
ul.ratingStars { list-style:none; margin:0px 0px;
overflow:hidden; }
ul.ratingStars li { float:left; width:16px; height:16px;
background:url('icons/star.gif') no-repeat left top;
cursor:pointer; }
ul.ratingStars li.active { background-position: 0px -32px; }
ul.ratingStars li.default { background-position: 0px 0px; }
ul.ratingStars li.highlighted,
ul.ratingStars li:hover { background-position: 0px -16px; }

```

1.  我们的结果如下：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_02_07.jpg)

## 它是如何工作的...

基本上，整个评分系统是一个项目的无序列表。每个项目代表一个星星，可以提供三种状态；默认、活动或突出显示。通过改变每颗星星的背景位置来改变状态。在我们的情况下，我们使用`icons/star.gif`，其中包括所有三种可能的状态（灰色、红色和黄色）。定义了一个`mouseover`事件，它将突出显示悬停的星星和之前选择的所有星星。点击星星后，我们调用一个 Ajax post 请求到`ajax/saveRating.php`并设置所有必需的星星为激活状态。

## 还有更多...

在大多数情况下，我们不希望允许一个用户进行多次投票。在这种情况下，我们可以设置 cookie 如下：

```php
...
if(isset($_POST["itemID"]) && isset($_POST["itemValue"])){
setcookie("rated".$id, $id, time()+60*60*60*24*365);
$result["status"] = "OK";
$result["message"] = "Rating has been saved successfully.";
}

```

当 cookie 设置为一年后过期时，我们可以在我们的评分系统中使用它：

```php
if(isset($_COOKIE['rated'.$id])) {
$result["status"] = "550";
$result["message"] = "Already voted!";
}
echo json_encode($result);

```

# 使用验证构建 PHP Ajax 联系表单

在提交表单之前对输入框进行验证已成为非常重要的 Ajax 功能之一。用户不必等到整个表单返回一些无效的输入框消息，然后再尝试重新填写。在这个任务中，我们将构建一个带有 Ajax 验证的联系表单。

## 如何做...

1.  让我们从 HTML 开始：

```php
<body>
<form id="contactForm" action="#" method="post">
<h1>PHP Ajax Contact Form</h1>
<div class="fieldRow">
<label for="name">Your Name:</label>
<input type="text" name="name" id="name"
class="required" />
</div>
<div class="fieldRow">
<label for="email">Your e-mail:</label>
<input type="text" name="email" id="email"
class="required email" />
</div>
<div class="fieldRow">
<label for="url">Website:</label>
<input type="text" name="url" id="url"
class="url" />
</div>
<div class="fieldRow">
<label for="phone">Mobile Phone:</label>
<input type="text" name="phone" id="phone"
class="phone"/>
</div>
<div class="fieldRow">
<label for="message">Your Message:</label>
<textarea name="message" id="message"
class="required"></textarea>
</div>
<div class="fieldRow buttons">
<input type="reset" value="Clear" />
<input type="submit" value="Send" />
</div>
</form>
</body>

```

1.  现在，我们可以定义样式：

```php
<style>
form{ width:450px; }
label { float:left; width:100px; padding:5px; }
.fieldRow { overflow:hidden; margin:20px 10px; }
.buttons { text-align:center; }
input[type=text], textarea{ width:200px; border:1px solid black; border-radius: 5px; padding:5px; }
input.required, textarea.required{ border:1px solid orange; }
.failed input.required, .failed textarea.required{ border:1px solid red; }
.failed { color:red; }
</style>

```

1.  主要的 PHP 验证如下：

```php
"status" => "50500",
"message" => "Error: No parameters provided."
);
if(isset($_POST["param"])){
$param = $_POST["param"];
$value = $_POST["value"];
switch($param){
default:
$result["status"] = "10100";
$result["message"] = "OK";
break;
case 'email':
if(filter_var($value, FILTER_VALIDATE_EMAIL)){
$result["status"] = "10100";
$result["message"] = "E-mail is valid!";
} else {
$result["status"] = "50502";
$result["message"] = "Error: E-mail is not
valid.";
}
break;
case 'url':
if(filter_var($value, FILTER_VALIDATE_URL)){
$result["status"] = "10100";
$result["message"] = "URL is valid!";
} else {
$result["status"] = "50502";
$result["message"] = "Error: URL is not valid.";
}
break;
case 'phone':
if(preg_match('/^\+?[0-9]+$/', $value)){
$result["status"] = "10100";
$result["message"] = "Phone is valid!";
} else {
$result["status"] = "50502";
$result["message"] = "Error: Phone number is not
valid.";
}
break;
}
}
echo json_encode($result);
?>

```

1.  具有 Ajax 调用的 JavaScript 功能如下：

```php
<script src="js/jquery-1.4.4.js"></script>
<script>
$(document).ready(function(){
$('#contactForm').submit(function(e){
var $form = $(this);
$.ajaxSetup({async:false});
$('.required').each(function(){
var $this = $(this);
var value = $this.val();
if(value.length == 0)
$this.parents('.fieldRow').addClass('failed');
else
$this.parents('.fieldRow').removeClass('failed');
});
$('.email').each(function(){
var $this = $(this);
var value = $this.val();
$.post("validators/main.php",
{'param':'email', 'value':value },
function(data) {
if(data.status==10100)
$this
.parents('.fieldRow').removeClass('failed');
else
$this.parents('.fieldRow').addClass('failed');
}, "json");
});
$('.url').each(function(){
...
$.post("validators/main.php",
{'param':'url', 'value':value }, function(data) {
...
});
$('.phone').each(function(){
...
$.post("validators/main.php",
{'param':'phone', 'value':value }, function(data) {
...
});
return !$('.failed').length;
});
});
</script>

```

1.  结果如下：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_02_08.jpg)

## 它是如何工作的...

我们从 HTML 源代码开始。它包含四个输入框和一个文本区域。正如你在源代码中所看到的，我们准备了两种验证。第一种是检查必填字段（标有`class="required"`），第二种是基于特定类型的数据（电子邮件、URL 和电话）。第一种验证仅在客户端进行，第二种涉及发送一个 post 请求到`validators/main.php`，对给定的参数进行评估。如果输入未通过验证，则标记为`failed`。如果表单中没有`failed`输入框，则启用`submit`事件。当所有请求完成时，该事件返回`true`值。这是通过允许同步请求来实现的——`$.ajaxSetup({async:false})`。请注意，同步请求可能会暂时锁定浏览器，禁用任何活动，而请求处于活动状态时。

## 还有更多...

在这个例子中，我们使用了服务器端字段的验证。这个逻辑并不完全是我们在现实生活中会使用的。当然，我们应该始终在服务器端进行验证(以防用户关闭了 JavaScript)，但我们不需要让服务器处理一些我们可以在客户端轻松找到的东西，比如验证电子邮件、URL 或必填字段。jQuery 有一个名为`validate.js`的很好的验证插件([`docs.jquery.com/Plugins/validation`](http://docs.jquery.com/Plugins/validation))。

我们需要做的就是下载带有`validate`插件的 jQuery 库，并将其包含在我们的源代码中：

```php
<script src="jquery/jquery-latest.js"></script>
<script src="jquery/plugins/validate/jquery.validate.js">
</script>

```

为必填字段定义`required`类，并为特定验证器定义一些额外的类，比如电子邮件：

```php
<form id="commentForm" method="get" action="">
<label for="email">E-Mail</label>
<input id="email" name="email" class="required email" />
</form>

```

之后，在特定表单中调用`validate()`函数：

```php
<script>
$(document).ready(function(){$("#commentForm").validate();});
</script>

```

# 在 Ajax 中显示表格

在这个任务中，我们将使用 Ajax 以表格形式显示数据。作为数据源，我们将使用预定义的 JSON 对象。

## 准备工作

首先，我们需要准备一个虚拟的 JSON 数据源，其中包含我们表格中将显示的所有项目：

```php
json/requests.json:
[{
"id": "1",
"name": "Milan Sedliak Group",
"workflow": "Front End Q Evaluation",
"user": "Milan Sedliak",
"requestor": "Milan Sedliak",
"status": "submitted",
"email": "milan@milansedliak.com",
"date": "Today 15:30"
},
{...}]

```

## 如何做...

1.  作为基本 HTML，我们可以使用这个包含表格和工具栏的源代码。这个工具栏将包括我们项目的选择功能。

```php
<div class="tableContainer">
<div class="tableToolbar">
Select
<a href="#" class="selectAll">All</a>,
<a href="#" class="selectNone">None</a>,
<a href="#" class="selectInverse">Inverse</a>
</div>
<table>
<thead></thead>
<tbody></tbody>
</table>
</div>

```

1.  现在，我们可以为我们的 HTML 设置样式：

```php
<style>
.tableContainer { width:900px; }
.tableToolbar { background-color:#EEFFEE; height:20px;
padding:5px; }
table { border-collapse: collapse; width:100%; }
table th { background-color:#AAFFAA; padding:4px; }
table tr td { padding:4px; }
table tr.odd td { background-color:#E3E3E3; }
.floatr { float:right; }
.textAlignR { text-align: right; }
</style>

```

1.  当 HTML 和 CSS 准备好后，我们可以开始使用 JavaScript：

```php
<script src="js/jquery-1.4.4.js"></script>
<script>
$(document).ready(function(){
$.getJSON('json/requests.json', function(data) {
buildHeader(data);
buildBody(data);
});
});
var buildHeader = function(data){
var keys = [];
var $headRow = $('<tr />');
for(var key in data[0]){
if(key=="id")
var $cell = $('<th />');
else
var $cell = $('<th>'+key+'</th>');
$cell.appendTo($headRow);
}
$headRow.appendTo($('.tableContainer table thead'));
}
var buildBody = function(data){
for(var i = 0; i < data.length; i++){
var dataRow = data[i];
var $tableRow = $('<tr />');
for(var key in dataRow){
var $cell = $('<td />');
switch(key){
default:
$cell.html(dataRow[key]);
break;
case 'id':
var $checkbox = $('<input type="checkbox"
name="select['+dataRow[key]+']" />');
$checkbox.appendTo($cell);
break;
case 'date':
$cell.html(dataRow[key]);
$cell.addClass('textAlignR');
break;
}
$cell.appendTo($tableRow);
}
if(i % 2 == 0)
$tableRow.addClass('odd');
$tableRow.appendTo($('.tableContainer table tbody'));
}
}
</script>

```

1.  结果如下：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_02_09.jpg)

## 它是如何工作的...

起初，我们为表格制定了基本的 HTML 结构。我们只定义了表头和表体的位置。在`(document).event`中，我们发送一个`getJSON`请求，从服务器获取一个`json`对象(`json/requests.json`)。我们将数据放入`data`变量中，并继续构建表格。在第一步中，我们构建表头(buildHeader(data))。这个函数获取数据，从 JSON 对象中解析键，并将它们用于表头单元格。在第二步中，我们构建表体(buildBody(data))。这个函数基于一个循环，将指定表格的每一行。我们使用一个开关，它能够根据键提供每个值的特定功能。

## 还有更多...

在这个任务中，我们已经构建了一个带有工具箱的表格，但它还没有任何功能；至少目前还没有。在每一行中，我们定义了一个复选框。通过定义这个复选框，我们可以指定额外的功能：

```php
$checkbox.bind('click', function(e){
$(this).parents('tr').addClass('highlighted');
})
.appendTo($cell);

```

对于前面代码片段中提到的工具栏，我们可以指定：

```php
$('.selectAll').bind('click',function(){
$(this) .parents('table')
.find('input[type="checkbox"]').each(function(){
var $checkbox = $(this);
$checkbox.attr('checked', 'checked');
var $row = $checkbox.parents('tr');
$row.addClass('highlighted');
});
});

```

# 使用 PHP 和 Ajax 构建分页

在这个任务中，我们将学习如何使用 Ajax 功能构建**分页**。这意味着我们将能够在不重新加载整个网站的情况下翻页查看联系人列表。

## 如何做...

1.  我们将从包含页面容器、显示联系人第一页的联系人网格和联系人分页的 HTML 开始：

```php
<div id="pageContainer">
<div id="contactGrid">
<div class="contact">
<img src="images/avatar.png" alt="avatar" />
<h2>Milan Sedliak</h2>
<p>Prague, Czech Republic</p>
</div>
<!-- // add more contacts -->
<div class="contact">
<img src="images/avatar.png" alt="avatar" />
<h2>Milan Sedliak (home)</h2>
<p>Malacky, Slovakia</p>
</div>
</div>
<ul id="contactPagination">
<li><a href="#previous" id="previous">Previous</a></l
<li><a href="#1" id="1">1</a></li>
<li><a href="#2" id="2">2</a></li>
<li><a href="#3" id="3">3</a></li>
<li><a href="#4" id="4">4</a></li>
<li><a href="#5" id="5" class="active">5</a></li>
<li><a href="#6" id="6">6</a></li>
<li><a href="#7" id="7">7</a></li>
<li><a href="#next" id="next">Next</a></li>
</ul>
</div>

```

1.  所需的 CSS 如下：

```php
<style>
#pageContainer { width: 410px; margin:0px auto; }
#contactGrid { width: 410px; margin:10px auto;
overflow:hidden; position:relative; }
#contactGrid .contact { float:left; width:200px;
margin:10px 0px; }
.contact img { float:left; margin-right:5px;
margin-bottom:10px; }
.contact h2 { font-size:14px; }
.contact p { font-size: 12px; }
#contactPagination { clear:both; margin-left:50px; }
#contactPagination li { float:left; list-style:none; }
#contactPagination li a { padding:5px; margin:5px;
border:1px solid blue; text-decoration:none; }
#contactPagination li:hover a { color:orange;
border:1px solid orange; }
#contactPagination li a.active { color:black;
border:1px solid black; }
</style>

```

1.  分页的 JavaScript 功能如下：

```php
<script src="js/jquery-1.4.4.js"></script>
<script>
$(document).ready(function(){
paginationInit();
});
var paginationInit = function(){
$('#contactPagination li a').bind('click', function(e){
e.preventDefault();
var $this = $(this);
var target = $this.attr('id');
var $currentItem = $('#contactPagination a.active')
.parents('li');
var $contactGrid = $('#contactGrid');
switch(target){
default:
$('#contactPagination a').removeClass('active');
$this.addClass('active');
var page = target;
$.get('contacts.php',
{'page': page}, function(data) {
$contactGrid.html(data);
});
break;
case 'next':
var $nextItem = $currentItem.next('li');
$('#contactPagination a').removeClass('active');
var $pageToActive = $nextItem.find('a')
.addClass('active');
var page = $pageToActive.attr('id');
$.get('contacts.php',
{'page': page}, function(data) {
$contactGrid.html(data);
});
break;
case 'previous':
var $previousItem = $currentItem.prev('li');
$('#contactPagination a').removeClass('active');
var $pageToActive = $previousItem.find('a')
.addClass('active');
var page = $pageToActive.attr('id');
$.get('contacts.php',
{'page': page}, function(data) {
$contactGrid.html(data);
});
break;
}
hidePreviousNextButtons();
});
}
var hidePreviousNextButtons = function(){
var $currentItem = $('#contactPagination a.active');
var currentItemID = $currentItem.attr('id');
var $nextButton = $('#contactPagination #next');
var $previousButton = $('#contactPagination #previous');
var lastItemID = $nextButton.parents('li').prev('li')
.find('a').attr('id');
var firstItemID = $previousButton.parents('li').next('li')
.find('a').attr('id');
currentItemID == lastItemID ?
$nextButton.hide() : $nextButton.show();
currentItemID == firstItemID ?
$previousButton.hide() : $previousButton.show();
}
</script>

```

1.  要检索所需的页面，我们将定义`contact.php:`

```php
<?php
if (isset($_GET["page"])) { $page = (int)$_GET["page"]; } else { $page = 1; };
$start_from = ($page-1) * 20;
$sql = "SELECT * FROM contacts ORDER BY name ASC LIMIT $start_from, 20";
$result = mysql_query ($sql,$connection);
?>
<?php
$result="";
while ($row = mysql_fetch_assoc($result)) {
$avatar = htmlspecialchars($row["avatar"]); $fullName = htmlspecialchars($row["fullName"]);
$address = htmlspecialchars($row["address"]);
$result .= sprintf('
<div class="contact">
<img src="%s" alt="avatar" />
<h2>%s</h2>
<p>%s</p>
</div>',$avatar,$fullName,$address);
};

```

1.  结果如下：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_02_10.jpg)

## 它是如何工作的...

我们在`paginationInit()`函数中定义了分页的主要功能。主要步骤是获取分页中的每个超链接，并根据其`id`属性分配特定的功能。当`id`为`next`或`previous`时，这意味着我们点击了**下一页**或**上一页**按钮。在这种情况下，我们查找当前活动的页面，并选择`next/previous`超链接。如果我们已经到达了`first/last`超链接，我们通过调用`hidePreviousNextButtons()`函数隐藏`previous/next`按钮。在这个例子中，默认目标是数字项(页面)之一。当我们点击时，我们保存当前活动页面，从`contacts.php`调用`GET`请求以获取所需的页面，并在`contactGrid`中显示它。

## 还有更多...

我们学会了如何构建基本的分页。现在我们可以玩一下用户体验。我们的用户喜欢看到页面上发生了什么。在这种情况下，我们点击代表页面的链接，并等待联系人在联系人网格中显示出来。现在，我们可以为我们的用户提供一个经典的旋转器，作为内容正在加载的通知。

首先，我们需要找到一个`.gif`图像作为旋转器。我们可以在互联网上很容易找到一个。当图像准备好并保存在我们的图像文件夹中时，我们可以定义 CSS 如下：

```php
#spinnerContainer { opacity:0.85; position:absolute;
width:100%; height:100%;
background:url('images/loader-big.gif') no-repeat
center center #000; }

```

我们可以直接将旋转器的显示添加到现有的函数中；这可以在 Ajax 请求之前完成，当请求`id`完成时。我们将使用`.html()`函数覆盖 HTML 内容。

```php
$('<div id="spinnerContainer"></div>')
.prependTo($contactGrid);
$.get('contacts.php',
{'page': page}, function(data) {
$contactGrid.html(data);
});

```

修改后的版本如下：

![还有更多...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_02_11.jpg)
