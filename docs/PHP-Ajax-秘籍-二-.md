# PHP Ajax 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/5ed725dded7917e2907901dccf658d88`](https://zh.annas-archive.org/md5/5ed725dded7917e2907901dccf658d88)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：使用 jQuery 的实用工具

在本章中，我们将涵盖：

+   使用 Ajax 制作工具提示

+   从数据库创建自动完成

+   使用 jQuery 构建选项卡导航

+   旋转内容

+   创建图像滑块

+   创建无页码分页

+   使用 Lightbox 加载图像

+   使用 jGrow 插件增加文本区域

+   HTML 替换选择下拉框

+   通过 Datepicker 改进日期选择

+   拖放功能

+   Ajax 购物车

+   排序和过滤数据

+   添加视觉效果和动画

我们需要 Ajax 工具或插件来获取“Ajax 化”的网站。jQuery 插件通常是一个很好的时间节省者，因为它们通常是即插即用类型的脚本。jQuery 的基于选择器的方法使得将普通网页转换为“Ajax 化”网页变得更加简单，以不显眼的方式。在本章中，我们将看到一些高效的 jQuery 插件及其用法。

# 使用 Ajax 制作工具提示

Web 浏览器会在**工具提示**中呈现`title`属性的内容。浏览器工具提示存在一些问题，例如：

+   它们的外观在各个浏览器中不一致

+   浏览器工具提示无法样式化

为了解决这些美学 UI 问题，我们有许多 jQuery 插件。在本教程中，我们将研究如何使用 BeautyTips 插件获取工具提示。

## 准备工作

我们需要从[`plugins.jquery.com/project/bt`](http://plugins.jquery.com/project/bt)获取 BeautyTips jQuery 插件以及 jQuery Core。可选地，我们可能需要以下内容：

+   **ExplorerCanvas**来自[`excanvas.sourceforge.net/`](http://excanvas.sourceforge.net/)，以支持 Internet Explorer 中的`canvas`元素。请注意，BeautyTips 使用`canvas`元素来生成气泡提示。

+   **hoverIntent**插件来自[`cherne.net/brian/resources/jquery.hoverIntent.html`](http://cherne.net/brian/resources/jquery.hoverIntent.html)，因为它改变了悬停行为。jQuery 的默认`hover`事件在绑定元素悬停时触发，有时会导致用户体验不佳，特别是当用户无意中悬停在特定元素上时。hoverIntent 插件通过为悬停事件添加间隔和超时来解决此问题，以便清楚地满足用户意图。安装后，BeautyTips 使用 hoverIntent 而不是 hover。

+   **bgiframe**插件来自[`plugins.jquery.com/project/bgiframe`](http://plugins.jquery.com/project/bgiframe)，因为它修复了 IE6 中表单元素的 z-index 问题。当页面上有 bgiframe 时，BeautyTips 将自动使用它。

+   **Easing**插件在需要动画效果时使用。

## 如何做...

使用 BeautyTips 插件制作工具提示很容易，因为它只是一个即插即用的设置。让我们看看当用户填写表单时如何提供帮助提示。

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_01.jpg)

以下代码使得在前面的屏幕截图中获取显示更容易：

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<script src="js/jquery.min.js" type="text/javascript">
</script>
<script src="js/jquery.hoverIntent.minified.js" type="text/javascript">
</script>
<script src="js/jquery.bgiframe.min.js" type="text/javascript">
</script>
<!--[if IE]>
<script src="js/excanvas.js" type="text/javascript">
</script>
<![endif]-->
<script src="js/jquery.bt.min.js" type="text/javascript">
</script>
<script src="js/jquery.easing. js" type="text/javascript">
</script>
<script src="js/script.js" type="text/javascript">
</script>
<title>Tooltips for form inputs</title>
</head>
<body>
<form method="post" action="action.php">
<fieldset>
<legend>Bio</legend>
<label for="name">Name</label><br />
<input type="text" id="name" title="Hey, how can we call you?"/
<label for="age">Age</label><br />
<input type="text" id="age" title="This site isn't for babies and so we need your age!" /><br />
<label for="gender">Gender</label><br />
<select id="gender" title="Are you she or he in your bio?">
<option value="" selected="selected">- Choose -</option>
<option value="M">Male</option>
<option value="F">Female</option>
</select><br />
<input type="submit" value="Submit" />
</fieldset>
</form>
</body>
</html>

```

而在 JavaScript 触发中，使用以下代码更简单：

```php
jQuery(document).ready(function($){
         $('input, select').bt();
});

```

## 它是如何工作的...

BeautyTips 使用`canvas`元素来绘制通常称为工具提示、帮助提示、帮助气球和对话气泡的气泡。使用`canvas`的主要思想是实现任何形状的气泡。BeautyTips 具有内置样式支持，用于普通气泡、Google 地图气泡、Facebook 工具提示和 Netflix 工具提示。它还通过 CSS 支持自定义气泡主题。

如我们的示例中所述，要在表单输入上获取工具提示，气泡文本会自动从附加元素的`title`属性中获取。因此，它会优雅地降级，并符合辅助功能标准。在可能需要在气泡提示中显示其他文本的情况下，我们可以通过添加以下代码来实现：

```php
$(selector).bt('Bubble tip text');

```

气泡提示通常放置在元素的右侧。当没有可用空间时，它会自动调整和检测位置。API 还提供了设置位置的能力，如下所示：

```php
$(selector).bt({positions: 'top'});

```

默认的触发事件是`hover`。当页面上找到 hoverIntent 插件时，它将利用它来改善用户体验。如前文所述，hoverIntent 插件将设置触发`hover`事件的时间，从而在用户意外移动到元素上时避免不必要的事件触发。通过 API，我们还可以将触发事件定制为除`hover`之外的其他内容，如下所示：

```php
$(selector).bt({trigger: 'click'});

```

要指定`trigger`事件何时应该隐藏，我们必须传递第二个参数。以下代码将在`focus`事件中触发`bubble tip`，并在`blur`事件中隐藏它：

```php
$(selector).bt({trigger: ['focus', 'blur']});

```

气泡文本内容也可以使用`ajaxPath`属性作为参数从远程 Ajax 页面加载：

```php
$(selector).bt({ ajaxPath: 'ajax.html', ajaxError: "Ajax error: %error." });

```

## 还有更多...

jQuery 生态系统中有很多可用的插件可以轻松获取工具提示。BeautyTips 的功能在大多数情况下通常足够了。然而，我们可能会遇到一种情况，我们希望获取其他网站中使用的确切（或类似）工具提示。在这里，我们讨论了一些这样的插件：

+   **tipsy**

这个插件可以在[`onehackoranother.com/projects/jquery/tipsy/`](http://onehackoranother.com/projects/jquery/tipsy/)找到。它专注于轻松获取类似 Facebook 的迷你信息工具提示。

+   **BubbleTip**

这个插件可以在[`code.google.com/p/bubbletip/`](http://code.google.com/p/bubbletip/)找到，它可以帮助我们获取阴影和动画工具提示。

+   **jGrowl**

在 Mac OS X 中，Growl 框架允许开发人员发出警报消息。这个 jGrowl 插件可以在[`stanlemon.net/projects/jgrowl.html`](http://stanlemon.net/projects/jgrowl.html)找到，它模仿了相同的警报功能。我们可以使用这个插件在浏览器上创建漂亮的工具提示/警报弹出窗口。

+   **qTip**

这是另一个工具提示插件，可以在[`craigsworks.com/projects/qtip2./`](http://craigsworks.com/projects/qtip2./)找到。它有很多选项，还提供视觉上令人愉悦的工具提示。

# 从数据库创建自动完成

大多数时候，用户厌倦了填写表单。然而，从网站的角度来看，用户输入对于数据挖掘和更好的服务非常重要。当最终用户能够快速填写表单或轻松填写表单时，这将有助于最终用户和网站所有者。自动完成是帮助最终用户的一种尝试。总的来说，我们有两种类型的自动完成设计：

+   通过允许浏览器记住某些表单输入，在浏览器 UI 中

+   在使用自动完成技术快速填写表单的网站中

在这个教程中，我们将看到如何在 PHP 脚本中集成 jQuery UI Autocomplete 插件。

## 准备工作

我们需要从[`jqueryui.com/`](http://jqueryui.com/)获取 jQuery UI，其中包括自动完成组件。请注意，jQuery UI 下载页面[`jqueryui.com/download`](http://jqueryui.com/download)具有向导式界面，可以轻松选择必要的文件。

关于数据库，我们需要一个具有模式`jslibs（id，name）`的表。

## 操作步骤...

首先，我们将从没有数据库的情况下开始自动完成集成，然后再添加数据库支持。集成 jQuery UI Autocomplete 小部件很简单。让我们通过自动完成支持改进轮询应用程序的用户界面。请注意，自动完成模式通常在输入可以是预定集合中的任何内容或来自用户的情况下首选。

![操作步骤...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_02.jpg)

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<link rel="stylesheet" type="text/css" href="http://themes/base/jquery.ui.all.css" />
<script type="text/javascript" src="js/jquery.js">
</script>
<script type="text/javascript" src="js/ui/jquery.ui.core.js">
</script>
<script type="text/javascript" src="js/ui/jquery.ui.widget.js">
</script>
<script type="text/javascript" src="js/ui/jquery.ui.position.js">
</script>
<script type="text/javascript" src="js/ui/jquery.ui.autocomplete.js">
</script>
<script type="text/javascript" src="js/script.js">
</script>
<title>jQuery UI Autocomplete</title>
</head>
<body>
<form method="post" action="poll.php">
<div class="ui-widget">
<fieldset>
<legend>Poll</legend>
<label for="jslibs">Your favorite JavaScript framework</label>
<;input id="jslibs" />
<input type="submit" value="Submit" />
</fieldset>
</div>
</form>
</body>
</html>

```

在 JavaScript 代码中，通过其`id`挂钩输入元素就像这样简单：

```php
jQuery(document).ready(function($){
  $('#jslibs').autocomplete( {
source : ['dojo',       

'ExtJS',
'jQuery',
'MochiKit',
'mootools',
'Prototype',
'YUI']
});
});

```

在这里，我们通过`source`选项硬编码了自动完成值。当`values`集的大小很大时，我们必须通过服务器脚本远程提供值。因此，让我们通过创建`values.php`来为前面的设置添加远程值功能，如下面的代码片段所示：

```php
<?php
// JSON header...
header('Content-Type: application/json');
// DB connections...
$con = mysql_connect('localhost', 'db_user', 'db_password');
mysql_select_db('db_name', $con);
// 'term' passed from autocomplete component...
$term = isset($_GET['term']) ? mysql_real_escape_string ($_GET['term']) : '';
$values = array();
if ($term) {
$sql = 'SELECT name from jslibs WHERE name LIKE \'%' . $term .

$result = mysql_query($sql, $con);
while ($row = mysql_fetch_assoc($result)) {
$values[] = $row['name'];
}
}
echo json_encode($values);
?>

```

接下来，在自动完成调用中挂钩`values.php`：

```php
jQuery(document).ready(function($){
var cache={}, prevReq;
$('#jslibs').autocomplete({
source: function(request, response){
var term=request.term;
if (term in cache){
response(cache[term]);
return;
}
prevReq=$.getJSON('values.php', request, function(data, status,
req){
cache[term]=data;
if (req===prevReq){
response(data);
}
});
}
});
});

```

## 它是如何工作的...

`source`参数保存要自动完成的值。我们可以直接使用对象集来设置它们。另一个选项是通过远程 Ajax 请求设置它们。由于服务器脚本动态提取值，当数据没有被缓存时，它会有点低效。因此，我们为每个发送到服务器的术语形成了一个`cache`缓冲对象。这样可以提高用户按退格键或重新输入上一个查询时的性能。在这种情况下，请求将立即从本地保存的数据中提供服务。

## 还有更多...

值得注意的是，jQuery UI 自动完成插件具有许多功能，例如自动完成多个值（例如在`delicious.com`中输入标签时），固定输入数量等。接下来描述了一些有趣的主题和插件：

+   **Sphinx:**

服务器端脚本搜索功能不高效，因为它使用`LIKE`运算符，这将需要完整的表扫描。更好的选择是使用 Sphinx 使用全文搜索。有关 Sphinx 的更多信息，请访问[`sphinxsearch.com/`](http://sphinxsearch.com/)。

+   **地理编码自动完成：**

这是一个有趣的 jQuery 插件，可以使用 Google Maps API 自动完成地点地址。集成后，用户更容易输入他们的地址。它可以在[`github.com/lorenzsell/Geocoded-Autocomplete`](https://github.com/lorenzsell/Geocoded-Autocomplete)找到。

# 使用 jQuery 构建选项卡导航

任何网站都不完整没有导航链接。选项卡是将导航引入网站的良好用户界面方法。通过 CSS，可以轻松地设计导航链接看起来像选项卡。在 jQuery 中有许多选项卡实现。在这个教程中，我们将看看如何轻松集成 jQuery UI 选项卡插件。

## 准备就绪

我们将需要从[`jqueryui.com/`](http://jqueryui.com/)获取 jQuery UI，其中包括选项卡组件。

## 如何做...

**jQuery UI 选项卡**插件使用了可访问的标记标准。只要我们使用预定义的 HTML 标记，并使用选择器将其连接到**jQuery UI 选项卡**，我们就完成了！

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_03.jpg)

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<link rel="stylesheet" type="text/css" href="http://themes/base/jquery.ui.all.css" />
<script type="text/javascript" src="js/jquery.js"></script>
<script type="text/javascript" src="js/ui/jquery.ui.core.js"></script>
<script type="text/javascript" src="js/ui/jquery.ui.widget.js"></script>
tab navigationcreating, steps<script type="text/javascript" src="js/ui/jquery.ui.tabs.js"></script>
<script type="text/javascript" src="js/script.js"></script>
<title>jQuery UI Tabs</title>
</head>
<body>
<div id="tabs">
<ul>
<li><a href="#tab-1">Tab 1</a></li>
<li><a href="#tab-2">Tab 2</a></li>
<li><a href="#tab-3">Tab 3</a></li>
<li><a href="#tab-4">Tab 4</a></li>
</ul>
<div id="tab-1">
<p>Tab 1</p>
</div>
<div id="tab-2">
<p>Tab 2</p>
</div>
<div id="tab-3">
<p>Tab 3</p>
</div>
<div id="tab-4">
<p>Tab 4</p>
</div>
</div>
</body>
</html>

```

而且，在 JavaScript 调用中，我们只需绑定它如下：

```php
jQuery(document).ready(function($){
         $('#tabs').tabs();
tab navigationcreating, steps});

```

## 它是如何工作的...

**jQuery UI 选项卡**标记在`tabs`容器中定义了无序列表中的导航链接。选项卡内容放置在导航链接旁边。从导航链接到选项卡容器的映射是通过容器的`id`完成的。

选项卡的主题是通过 JavaScript 应用 CSS 选择器应用的`jquery.ui.all.css`。

如下截图所示，当由于某种原因 JavaScript 不可用时，标记提供了优雅的降级。导航仍然有效，让链接跳转到容器。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_04.jpg)

## 还有更多...

**jQuery UI 选项卡**插件还提供其他一些不错的功能，例如加载 Ajax 内容，能够在底部显示选项卡，通过 jQuery UI Sortable 实现可排序选项卡等。让我们看看如何实现这些常见功能：

+   **远程 Ajax 选项卡：**

获取远程链接以在选项卡中加载很容易。jQuery UI 选项卡内置支持此功能。因此，仅更改 HTML 标记就足够了：

```php
<div id="tabs">
<ul>
<li><a href="#tab-1">Tab 1</a></li>
<li><a href="http:///remote-link.html">Tab 2</a></li>
</ul>
<div id="tab-1">
<p>Tab 1</p>
</div>
</div>

```

在这里，请注意我们不必为远程链接加载添加任何容器`div`元素。

+   **可排序选项卡：**

Firefox 浏览器的选项卡是**可排序**的-它们可以拖放以更改顺序。**jQuery UI 选项卡**默认情况下不可排序，但可以通过使用`sortable`UI 插件添加该功能：

```php
jQuery(document).ready(function($) {
$('#tabs').tabs().find('.ui-tabs-nav').sortable( {
axis: 'x'
});
});

```

请注意，当调用`tabs()`并且无序列表的`ul`元素已经与`sortable()`调用连接时，无序列表中找到的选项卡导航链接部分将动态添加`ui-tabs-nav`类。

+   **样式选项卡：**

通过样式化选项卡来改变外观很容易。可以通过以下方式完成：

+   一个名为**ThemeRoller**的在线主题工具，位于[`jqueryui.com/themeroller/`](http://jqueryui.com/themeroller/)

+   手动调整以`ui-tabs-`开头的 CSS 声明中找到的样式

## 另请参阅

*在第七章中的*构建 SEO 友好的 Ajax 网站*食谱*，*实施构建 Ajax 网站的最佳实践*

# 旋转内容

在 iPhone 和 Mac OS 中使用效果滚动内容非常吸引人。在 Web 2.0 网站中，有时我们也需要飞行或滚动内容。通常需要内容旋转的地方包括新闻滚动条、公告滚动条、漂亮的幻灯片效果等。jQuery 生态系统中有很多插件可用于此目的。然而，`jQuery.scrollTo`插件相对简单，提供了很多效果，因此可以在许多情况下有效地使用。

## 准备工作

除了 jQuery 核心库，我们还需要从[`plugins.jquery.com/project/ScrollTo`](http://plugins.jquery.com/project/ScrollTo)获取`jQuery.scrollTo`插件。

## 如何做...

在这里，我们将看到如何使用 JavaScript 动态滚动`div`容器的内容。最初，HTML 标记很简单，有一个`div`容器和用于触发向下或向上滚动事件的链接。

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_05.jpg)

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<link rel="stylesheet" type="text/css" href="styles/style.css" />
<script type="text/javascript" src="js/jquery.js"></script>
<script type="text/javascript" src="js/jquery.scrollTo-min.js"></script>
<script type="text/javascript" src="js/script.js"></script>
<title>Content Scrolling - scrollTo</title>
</head>
<body>
<div id="content">

<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Proin non sem eget est vestibulum commodo nec at quam. Nullam et dignissim mi. Maecenas eget sem non nisl ornare pellentesque. Mauris accumsan nunc eu eros tristique at ultrices ipsum interdum. Fusce vel nulla nibh, sed feugiat orci. Ut dignissim velit ac lacus varius ultrices. Morbi sollicitudin fermentum ultricies. Cum sociis natoque penatibus et magnis dis parturient montes, nascetur ridiculus mus. Aliquam vel aliquam leo. Nam consectetur sodales mauris, in pretium diam facilisis a. Duis tincidunt lorem eu felis placerat ac volutpat elit lacinia.</p>
<p>Vivamus ac odio id lectus mollis suscipit. Etiam consequat semper dignissim. Aenean odio dui, interdum eu mattis non, pretium vel massa. Nulla ultrices suscipit euismod. Donec consequat nisl in ante ultricies ornare. Ut sit amet quam sed mauris placerat adipiscing a ut sapien. Suspendisse vel orci lectus. Quisque ut sollicitudin orci. Quisque molestie augue quis quam convallis quis congue magna lobortis. Quisque feugiat felis ut dolor commodo condimentum. Ut volutpat iaculis interdum. Praesent accumsan mollis ultricies. Suspendisse potenti. Duis ac ornare sapien. In hac habitasse platea dictumst. Etiam vel purus ligula. Suspendisse libero velit, convallis non elementum non, accumsan eu urna. Fusce fringilla facilisis hendrerit. Nam sollicitudin mattis diam, id tincidunt urna ornare et. Duis sit amet lacus ut quam bibendum pulvinar eu eu massa.</p>
</div>
<ul>
<li><a id="trigger-down" href="#">Scroll down</a></li>
<li><a id="trigger-up" href="#">Scroll up</a></li>
</ul>
</div>
</body>
</html>

```

在 JavaScript 代码中，触发链接`click`事件附加到`scrollTo()`调用：

```php
jQuery(document).ready(function($){
$('#trigger-down').click(function(){
$('#content').scrollTo(800, 'slow');

return false;
});
$('#trigger-up').click(function(){
$('#content').scrollTo(0, 'slow');
return false;
});
});

```

通过 CSS 设置宽度、高度和溢出属性，以在内容上获得滚动条：

```php
div#content {
width:400px;
height:100px;
overflow: auto;
}

```

## 它是如何工作的...

`scrollTo()`是一个单一的方法，它接受可变参数来控制滚动效果。在上面的例子中，通过 CSS 将`content`容器设置为固定的`width`和`height`。为了获得滚动条，我们已经将`overflow`属性设置为`auto`值。因此，当页面加载时，一些内容会被隐藏。要向下滚动，我们使用了`$('#content').scrollTo(800, 'slow')`；。

在这里，`800`是内容应该滚动到的偏移值。动画速度设置为`slow`；没有这个参数和值，内容将立即滚动。类似地，要向上滚动或重置内容的位置，我们使用了`$('#content').scrollTo(0, 'slow')`；。

`scrollTo()`的第一个参数接受以下值：

+   **百分比值：**

例如，如果我们调用$(`'#content').scrollTo('50%', 'slow')`，内容将只滚动到一半的位置。要滚动到最底部，我们也可以使用`$('#content').scrollTo('100%', 'slow')`，而不是`$('#content').scrollTo(800,'slow')`。

+   **选择器：**

可以通过在第一个参数中传递选择器值来滚动到内容中的特定选择器，如下所示：`$('#content')` .scrollTo(`'#target','slow')`。

+   **像素值：**

它还接受像这样的像素值：$('#content').scrollTo('50px','slow')。这将保持像素偏移值。

+   **jQuery 对象：**

也可以传递 jQuery 对象来指定目标，如下所示：`$('#content').scrollTo($('#target'),'slow')`。

除此之外，还有控制轴（是水平方向还是垂直方向滚动）、边距、队列（当设置为`true`时，会使滚动在两个轴上依次进行），以及回调函数的参数。例如，以下代码片段将滚动内容到特定的目标元素，并在滚动完成后弹出警告框：

```php
$('#content').scrollTo('#target', 'slow', {
onAfter: function() {
alert('Done');
}
});

```

## 还有更多...

`scrollTo()`是一个通用插件。它通过几个插件进行了扩展，以便更容易使用：

+   **jQuery.SerialScroll：**

此插件可在[`flesler.blogspot.com/2008/02/jqueryserialscroll.html.`](http://flesler.blogspot.com/2008/02/jqueryserialscroll.html.)上找到。它使用了 scrollTo 插件，可用于获取新闻滚动条或轻松的水平和垂直滚动。

+   **jQuery.LocalScroll：**

这可以在[`flesler.blogspot.com/2007/10/jquerylocalscroll-10.html`](http://flesler.blogspot.com/2007/10/jquerylocalscroll-10.html)找到。它改进了带有动画的锚链接的本地滚动。例如，以下 JavaScript 代码将使所有本地链接平滑滚动带有动画：

```php
$.localScroll();

```

然后，像这样的本地链接将在跳转时进行动画：

```php
<a href="#toc">Table of Contents</a>

```

# 创建图像滑块

在页面中显示照片相册、特色、截图等图像是大多数网站的常见需求。在滑块中显示图像并添加一些效果将使其更加生动，并且会使网站“Ajax 化”。为了提供这样的效果并获得更好的效果，有很多 jQuery 插件。在本食谱中，我们将看到如何使用 jCarousel 插件显示图像滑块。

## 准备工作

我们将需要从[`sorgalla.com/projects/jcarousel/`](http://sorgalla.com/projects/jcarousel/)获取 jCarousel 插件，以及 jQuery 核心库。

## 如何做...

只需使用普通的 HTML 标记——无序列表中的图像——即可获得照片列表。为了将 jCarousel 插件连接到无序列表，我们已经设置了`id`。为了设置主题，我们将类设置为`jcarousel-skin-ie7`。

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_06.jpg)

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<link rel="stylesheet" type="text/css" href="http://skins/ie7/skin.css" />
<script type="text/javascript" src="js/jquery.js"></script>
<script type="text/javascript"src ="js/jquery.jcarousel.min.js"></script>
<script type="text/javascript" src="js/script.js"></script>
<title>Image slider - jCarousel</title>
</head>
<body>
<div id="container">

<ul id="carousel" class="jcarousel-skin-ie7">
<li><img src="http://uscites.gov/sites/default/files/ African%20Elehant%203.jpg" width="75" height="75" alt="[Image: Elephant]" /></li>
<li><img src="http://uscites.gov/sites/default/files/ elephant%202.jpg" width="75" height="75" alt="[Image: Elephant]" /></li>
<li><img src="http://uscites.gov/sites/default/files/elephant1.jpg" width="75" height="75" alt="[Image: Elephant]" /></li>
<li><img src="http://uscites.gov/sites/default/files/Tim%20Knepp%20African%20Elephant001_0.jpg" width="75" height="75" alt="[Image: Elephant]" /></li>
<li><img src="http://uscites.gov/sites/default/files/ African%20Elephant%201.jpg" width="75" height="75" alt="[Image: Elephant]" /></li>
<li><img src="http://uscites.gov/sites/default/files/ African%20Elephant%202.jpg" width="75" height="75" alt="[Image: Elephant]" /></li>
<li><img src="http://uscites.gov/sites/default/files/ elephant_bull_amboseli_best.jpg" width="75" height="75" alt="[Image: Elephant]" /></li>
<li><img src="http://uscites.gov/sites/default/files/ elephant_pano3.jpg" width="75" height="75" alt="[Image: Elephant]" /></li>
</ul>
</div>
</body>
</html>

```

接下来，我们通过选择器将 jCarousel 附加到无序列表中，如下面的代码片段所示：

```php
jQuery(document).ready(function($){
image slidercreating$('#carousel').jcarousel();
});

```

这带来了精彩的**图像滑块**，如前面的屏幕截图所示。

## 工作原理...

在这里，我们使用简单和易于访问的 HTML 标记来显示图像——每个图像都包裹在无序列表中。我们通过其`id`将 jCarousel 连接到无序列表，以获得一个漂亮的图像滑块。

jCarousel 捆绑了两种 CSS 皮肤：

+   Tango——符合**Tango 桌面项目**的规定，使得所有开源软件都能获得一致的图形用户体验，网址为[`tango.freedesktop.org/`](http://tango.freedesktop.org/)。

+   **IE7**

jCarousel 迭代无序列表中的每个图像并形成滑动面板。它还负责导航到下一个和上一个图像。默认情况下，图像滑块以水平方向显示。要使其以垂直方向显示，我们必须进行如下设置：

```php
$('#carousel').jcarousel( {
});

```

图像滑块不是循环的。在滑块中的最后一个图像后，下一个和上一个按钮将被禁用。有时，我们可能需要一个保持以循环方式滚动的滑块。使用 jCarousel 很简单，可以通过以下代码片段实现：

```php
$('#carousel').jcarousel( {
});

```

jCarousel 具有设置下一个或上一个滑动应滚动多少图像的能力：

```php
$('#carousel').jcarousel( {
});

```

## 还有更多...

实际上，我们有很多插件和方法可以获得图像滑块。以下是一些 jCarousel 的替代方案：

+   **Lightbox:**

Lightbox 将在本章的即将推出的食谱中介绍。一些实现具有图像滑动和幻灯片选项，因此我们可以使用这样的版本作为图像滑块。

+   **GalleryView:**

GalleryView，网址为[`plugins.jquery.com/project/galleryview`](http://plugins.jquery.com/project/galleryview)，具有视觉上令人愉悦的功能来显示图像库。它还具有缩略图选项，可以立即查看可用的图像。

# 创建无页码分页

当页面上的记录超过一定限制时，通常会将记录分成多个页面，并让用户通过页码链接/下一页/上一页/第一页/最后一页链接访问页面。这样的系统称为**分页**。在一些 Web 2.0 网站中，我们可以找到无页码分页。这是独特的；底部有一个“更多”链接，点击后将通过 Ajax 加载其下方的内容。这种用户界面很有趣，因为用户不必点击“上一页”链接来查看以前的页面；它们已经在当前页面中可用。

## 准备工作

我们将需要 jQuery 核心库和与以下代码片段中所示的模式类似的 DB 表。

```php
CREATE TABLE users (
'id' mediumint(8) unsigned NOT NULL auto_increment,
'name' varchar(255) default NULL,
'bio' TEXT default NULL,
PRIMARY KEY ('id')
) TYPE=MyISAM;

```

## 如何做...

我们创建了一个简单的分页，通过查询字符串传递页码。在这里，我们使用了数据库连接语句来连接和选择`users`表的数据库。在每一页中，我们设置了代码只加载`10`条记录。在这段代码中，我们将**模板**与编程逻辑混合使用：

```php
<?php
// DB connections...
$con = mysql_connect('localhost', 'db_user', 'db_password');
mysql_select_db('db_name', $con);
// Pager logic...
$records_per_page = 10;
$page = isset($_GET['page']) ? intval($_GET['page']) : 1;
$nextpage = $page + 1;
$offset = $records_per_page * ($page -1);
// Ajax call?
$_isAjax = isset($_SERVER['HTTP_X_REQUESTED_WITH']) &&
($_SERVER['HTTP_X_REQUESTED_WITH'] == 'XMLHttpRequest');

// Query...
$sql = 'SELECT * from users LIMIT '.$offset. ', '. $records_per_page;
$result = mysql_query($sql, $con);
// Template...
if (!$_isAjax):
?>
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<script type="text/javascript" src="js/jquery.js"></script>
<script type="text/javascript" src="js/script.js"></script>
<title>Pageless paging</title>
</head>
<body>
<h1>Users and Bio</h1>
<div id="users">
<?php
endif;
while($row = mysql_fetch_assoc($result)):
?>
<h2><?php echo htmlspecialchars($row['name']);?></h2>
<p><?php echo htmlspecialchars($row['bio']);?></p>
<?php
endwhile;

?>

<a id="next" href="http://

Load next page</a>
<?php
if (!$_isAjax):
?>
</div>
</body>
</html>
<?php
endif;
?>

```

对于 JavaScript 部分，我们只需简单调用，不需要其他插件：

```php
jQuery(document).ready(function($) {
$('#users').delegate('#next', 'click', function() {
$(this).html('Loading...'); // Loader message
$.ajax( {
url: this.href, // URL from next link
success: function(data) {
$('#next').after(data).remove();
}
});
return false;
});
});

```

## 它是如何工作的...

这个简单的设置甚至不需要任何插件。在 PHP 代码中，我们通过 MySQL 的`LIMIT`语法列出了`$records_per_page`条记录。此外，当通过嗅探`HTTP_X_REQUESTED_WITH`进行 Ajax 调用时，代码输出不带头部和页脚的 HTML。为了简洁起见，我们使用了模板的基本语法。在 JavaScript 代码中，我们使用了`delegate()`。这是因为**加载下一页**链接是动态加载的——否则，我们可以使用`click()`方法。请注意，`click()`只对页面上现有的元素起作用，而`delegate()`将对页面上已经存在的元素以及将来创建的元素起作用。`delegate()`方法优雅地处理事件委托，并且是`click()`的一个简单替代。除了分页逻辑和对 Ajax 调用的选择性输出之外，使用事件委托来使动态加载的链接响应`click`事件（JavaScript 中的核心逻辑）非常简单——调用`$.ajax()`。还要注意，我们的代码在 JavaScript 不可用时可以通过页面刷新来工作，因此可以很好地降级。

## 还有更多...

要测试无页面分页，我们可能需要生成虚拟数据。一些编程框架内置支持生成测试数据。也有在线工具可用。

+   **生成数据**

在线服务 GenerateData 位于[`www.generatedata.com/`](http://www.generatedata.com/)，是一个非常好用的工具，可以生成样本测试数据。

# 使用 Lightbox 加载图像

在 Ajax 中，Lightbox 是一个非常有用的概念，点击链接的内容，或者图像，或视频加载到容器窗口中，而不会将用户带到单独的页面。Lightbox 还将页面上找到的一组图像转换为容器窗口中的幻灯片放映。原始的 Lightbox 脚本是在 Prototype 框架中编写的。在 jQuery 中，有很多实现可用。然而，ColorBox 插件以更好的用户界面和功能领先。在这个教程中，我们将看到如何使用 ColorBox 插件来改进 Lightbox。

### 注意

Lightbox 概念是由 Lokesh Dhakar 引入的。关于这个更多的细节可以在他的网站[`www.lokeshdhakar.com/projects/lightbox2/`](http://www.lokeshdhakar.com/projects/lightbox2/)上找到。

## 准备工作

我们需要从[`colorpowered.com/colorbox/`](http://colorpowered.com/colorbox/)获取 ColorBox jQuery 插件以及 jQuery 核心库。

## 如何做...

ColorBox HTML 标记仅仅是一组图像链接。我们通过无序列表列出了图像链接。

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_07.jpg)

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<link rel="stylesheet" type="text/css" href="styles/colorbox.css" />
<script type="text/javascript" src="js/jquery.js"></script>
<script type="text/javascript" src="js/jquery.colorbox-min.js"></script>
<script type="text/javascript" src="js/script.js"></script>
<title>Lightbox - ColorBox</title>
</head>
<body>
<ul id="colorbox">
<li><a href="http://uscites.gov/sites/default/files/African%20Elehant%203.jpg" title="Elephant">Elephant</a></li>
<li><a href="http://uscites.gov/sites/default/files/elephant%202.jpg" title="Elephant">Elephant</a></li>
<li><a href="http://uscites.gov/sites/default/files/elephant1.jpg" title="Elephant">Elephant</a></li>
<li><a href="http://uscites.gov/sites/default/files/Tim%20Knepp%20African%20Elephant001_0.jpg" title="Elephant">Elephant</a></li>
<li><a href="http://uscites.gov/sites/default/files/African%20Elephant%201.jpg" title="Elephant">Elephant</a></li>
<li><a href="http://uscites.gov/sites/default/files/African%20Elephant%202.jpg" title="Elephant">Elephant</a></li>
<li><a href="http://uscites.gov/sites/default/files/elephant_bull_amboseli_best.jpg" title="Elephant">Elephant</a></li>
<li><a href="http://uscites.gov/sites/default/files/elephant_pano3.jpg" title="Elephant">Elephant</a></li>
</ul>
</body>
</html>

```

与其他 jQuery 插件类似，只需通过选择器触发：

```php
jQuery(document).ready(function($){
$('#colorbox a').colorbox();
});

```

这会导致图像在 ColorBox 叠加中加载，如前面的屏幕截图所示。

## 它是如何工作的...

原则上，Lightbox 脚本会迭代所有挂接的链接，并阻止它们在页面刷新时加载。在这里，我们列出了一个无序列表中的一组图像链接，然后将它们附加到`colorbox()`调用。ColorBox 首先形成了用于加载图像的叠加容器。ColorBox 尺寸采用以下默认值，并可以通过参数设置进行覆盖：

```php
width: false,
initialWidth: "600",
innerWidth: false,
maxWidth: false,
height: false,
initialHeight: "450",
innerHeight: false,
maxHeight: false,

```

默认选项下，ColorBox 没有启用自动幻灯片放映功能。要启用自动幻灯片放映，代码如下：

```php
$('#colorbox a').colorbox( {
         slideshow: true
});

```

ColorBox 主题可以通过 CSS 轻松更改，它已经带有五种不同的样式。

## 还有更多...

通常会发现对于相同功能有多种实现，因为开发人员有时会因对现有实现不满而开始新项目。出于同样的原因，我们有许多 Lightbox 实现可用，例如以下内容：

+   **Lightbox 克隆矩阵:**

Lightbox 克隆矩阵，可在[`planetozh.com/projects/lightbox-clones/`](http://planetozh.com/projects/lightbox-clones/)上找到，显示了各种 Lightbox 实现之间的比较。

+   **SlimBox 2:**

这是另一种 Lightbox 实现。最初在 Mootools 框架中编写的原始 SlimBox 实现因其轻量级而受到很高评价。后来，在第 2 版中，作者将他的代码移植到了 jQuery 中—[`www.digitalia.be/software/slimbox2`](http://www.digitalia.be/software/slimbox2)。它在功能和 HTML 标记方面与 Lokesh Dhakar 的原始 Lightbox 完全兼容。因此，我们可以通过更改 JavaScript 库路径来快速将原始 Lightbox 替换为它。

# 使用 jGrow 插件增长 textarea

在 Web 浏览器中，`textarea`元素的高度和宽度通过`rows`和`cols`属性或通过`height`和`width`CSS 属性进行控制。当我们在`textarea`中输入更多文本时，上方的文本将向上移动，留下滚动条。为了改进`textarea`的 UI，一些 Ajax 专家已经使`textarea`在输入更多文本时增长。在这个教程中，我们将看到如何使用 jGrow 插件来获得这样一个增长的`textarea`。

## 准备就绪

我们需要从[`lab.berkerpeksag.com/jGrow`](http://lab.berkerpeksag.com/jGrow)获取 jGrow jQuery 插件以及 jQuery 核心库。

## 如何做到...

在这里，我们使用了一个简单的带有设置`id`的`textarea`，以便可以轻松地与 jQuery 选择器连接。

![如何做到...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_08.jpg)

以下是 HTML 标记：

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
textareagrowing, jGrow plugin used"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<script type="text/javascript" src="js/jquery.js"></script>
<script type="text/javascript" src="js/jquery.jgrow.js"></script>
<script type="text/javascript" src="js/script.js"></script>
<title>Growing textarea - jGrow</title>
</head>
<body>
<form action="submit.php" method="post">
<textarea name="description" id="description" cols="40" rows="4"></textarea>
<br />
<input name="submit" id="submit" value="Submit" type="submit" />
</form>
</body>
</html>

```

同样，我们通过`textarea`的`id`值附加了插件：

```php
jQuery(document).ready(function($){
         $('#description').jGrow();
});

```

## 它是如何工作的...

当连接到`textarea`时，jGrow 插件会在文本区域上方创建一个`div`元素，并开始保存输入文本。这样可以通过 CSS 属性更容易地控制高度。在每次`keyup`事件上，都会进行新的 jGrow 调用来触发，从而在必要时增加高度。

它还有一个选项来限制增长的高度，以便它不会超出指定的高度：

```php
$('#description').jGrow({

         max_height:'250px'
});

```

## 还有更多...

改进`textarea`的 UI 将提高可用性。在 jQuery 生态系统中有类似的插件可用。其中之一是**autoGrowInput**。就像我们有一个增长的`textarea`一样，有时候我们可能想要一个增长的输入框。在这种情况下，我们可以使用这个插件，该插件可在[`stackoverflow.com/questions/931207/is-there-a-jquery-autogrow-plugin-for-text-fields`](http://stackoverflow.com/questions/931207/is-there-a-jquery-autogrow-plugin-for-text-fields)上找到。

# 替换 select 下拉框的 HTML

改进表单选择下拉框的 UI 是一个有趣的话题。例如，除了 Internet Explorer 之外，其他 Web 浏览器支持对`select`元素中的每个选项进行样式设置。这对我们来说非常有帮助，特别是当我们在**selectbox**中列出国家时，需要显示国家旗帜和国家名称。由于在 Internet Explorer 中无法直接对`option`元素进行样式设置，因此一种方法是将其替换为带有锚定的有序/无序列表，以便对每个列表进行样式设置。在这个教程中，我们将研究这种 HTML 替换方法。

## 准备就绪

我们需要从[`github.com/fnagel/jquery-ui`](http://https://github.com/fnagel/jquery-ui)获取 jQuery UI selectmenu 插件以及 jQuery UI 核心。

## 如何做到...

要完成此操作的 HTML 标记是一个带有`select`元素的简单表单。请注意，我们将使用 jQuery UI selectmenu 插件将`select`元素转换为无序列表，并通过 CSS 进行样式设置。

![如何做到...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_09.jpg)

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<link rel="stylesheet" type="text/css" href="http://themes/base/jquery.ui.all.css" />
<link rel="stylesheet" type="text/css" href="http://themes/base/ui.selectmenu.css" />
<script type="text/javascript" src="js/jquery.js"></script>
<script type="text/javascript" src="js/ui/jquery.ui.core.js"></script>
<script type="text/javascript" src="js/ui/jquery.ui.widget.js"></script>
<script type="text/javascript" src="js/ui/ui.selectmenu.js"></script>
<script type="text/javascript" src="js/script.js"></script>
<title>jQuery UI selectmenu</title>
</head>
<body>
<form action="submit.php" action="post">
<label for="jslib">Choose JavaScript framework:</label>
<option value="jQuery" selected="selected">jQuery</option>
<option value="Mootools">Mootools</option>
<option value="ExtJs">ExtJs</option>
<option value="YUI">YUI</option>
</select>
<br />
<input name="submit" id="submit" value="Submit" type="submit" />
</form>
</body>
</html>

```

当我们将 jQuery UI selectmenu 附加到`select`元素时，它会被替换为一个无序列表。

```php
jQuery(document).ready(function($){
         $('#jslib').selectmenu();
});

```

## 它是如何工作的...

正如前面提到的，至少目前来看，易于样式化更可能出现在有序/无序列表中，而不是在选择框中，特别是在 Internet Explorer 中。当选择框附加到插件时，它会遍历选择选项并创建一个无序选项列表。它还会隐藏原始的选择框。为了模仿选择框的其余效果，所有选择和高亮都是通过 JavaScript 在无序列表上处理的。

由于这个插件符合 jQuery UI，它为这个插件带来了相同的主题化能力。我们可以像其他 jQuery UI 元素一样对其应用主题。

## 还有更多...

有一些特殊情况，我们将被迫使用选择框替换。这在我们针对更多的浏览器时可能会经常发生。

+   **选项图标：**

当尝试在选项旁边放置图标时，我们需要这个替代。一些示例情况包括：在国家下拉菜单中包含国家旗帜图标，在用户下拉菜单中包含用户头像等。

+   **Chosen:**

这个选择框替换插件转换了单个选择框 UI，使其可以像自动完成一样进行搜索。对于多选选择框，它会转换为 delicious.com 的标签输入 UI。它可以在 http://harvesthq.github.com/chosen/上找到。

# 通过日期选择器改进日期选择

日期选择器或日历小部件是任何 Web 2.0 网站的一部分。它有助于快速可视地选择日期，从而避免用户在特定格式中输入日期时出现错误。jQuery UI 提供了一个日期选择器插件，可以应用主题。在这个教程中，我们将看到如何在任何网站中使用或集成这个日期选择器。

## 准备工作

我们需要从[`jqueryui.com/`](http://jqueryui.com/)获取 jQuery UI，其中包含日期选择器组件。

## 如何做...

要获得日期选择器小部件，我们创建一个日期输入字段来获取出生日期。我们将`name`和`id`属性设置为`dob`。

![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_10.jpg)

```php
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN"
"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
<html >
<head>
<link rel="stylesheet" type="text/css" href="http://themes/base/jquery.ui.all.css" />
<script src="js/jquery.js"></script>
<script src="js/ui/jquery.ui.core.js"></script>
<script src="js/ui/jquery.ui.widget.js"></script>
<script src="js/ui/jquery.ui.datepicker.js"></script>
<script type="text/javascript" src="js/script.js"></script>
<title>jQuery UI Datepicker</title>
</head>
<body>
<form action="submit.php" method="post">
<input name="dob" id="dob" type="text" /><br />
<input name="submit" id="submit" value="Submit" type="submit" />
</form>
</body>
</html>

```

当使用`datepicker()`调用触发`dob`输入字段时，它会附加日历小部件。当单击输入字段时，日历小部件会弹出：

```php
jQuery(document).ready(function($){

         $('#dob').datepicker();
});

```

## 它是如何工作的...

当附加到任何`input`元素上时，jQuery UI 日期选择器插件会创建一个动态日历小部件。在其默认行为中，当触发附加的输入文本框时，它会弹出。它极大地提高了选择日期的可用性。

我们可以通过将其挂钩到`div`标签来获得内联日历：

```php
<div id="datepicker"></div>

```

也可以通过设置`numberOfMonths`参数在日历中显示更多月份：

```php
$('#dob').datepicker({
});

```

同样，我们也可以限制日期到特定范围：

```php
$('#dob').datepicker( {
});

```

在前面的情况下，可以选择的日期范围从“当前日期后 2 天”到“当前日期后 1 个月 15 天”。

默认情况下，日期格式使用美国格式 mm/dd/yy。可以使用`dateFormat`参数更改为另一种格式，比如 ISO 格式，如下所示：

```php
$('#dob').datepicker( {
});

```

## 还有更多...

我们有非常好的 jQuery 插件来选择日期。以下是一些有用的日期选择器插件：

+   **连续日历：**

这个插件以连续格式列出日历，使得跨月选择日期更容易。它可以在[`old.laughingpanda.org/mediawiki/index.php/Continuous_calendar`](http://old.laughingpanda.org/mediawiki/index.php/Continuous_calendar)上找到。

+   **wdCalendar:**

这个插件不是用于选择日期的，而是类似于 Google 日历的完整日历应用程序。它可以在[`www.web-delicious.com/jquery-plugins/`](http://www.web-delicious.com/jquery-plugins/)上找到 PHP 服务器脚本。

# 拖放功能

拖放功能是现代 Web 的一个重要特性。它是在网站上移动对象的能力。在这个任务中，我们将学习如何使用`jQuery.sortable()`构建一个漂亮的拖放布局。

## 准备工作

首先，我们需要下载带有 jQuery UI 的 jQuery 库，并在`</body>`标签之前包含它们：

```php
<script src="js/jquery-1.4.4.js"></script>
<script src="js/jquery-ui-1.8.11.custom.min.js"></script>

```

在这个例子中，我们将使用从互联网上下载的随机图片（首选尺寸为 200x80 像素）。

## 如何做...

1.  当 jQuery 库与 jQuery UI 准备就绪时，我们可以开始使用 HTML。我们将构建四个主要的`div`元素：`top, sidebar, sidebar2`和`mainContent`。每个都包括一个`sortable`列表：

```php
<div id="page">
<div id="top">
<ul class="sortable">
<li id="news"><h2>News</h2></li>
<li id="about"><h2>About</h2></li>
<li id="contact-us"><h2>Contact Us</h2></li>
</ul>
</div>
<div id="sidebar">
<ul class="sortable">
<li id="item1">
<div class="imgContainer">
<img src="images/p2.jpg" /></div>
<h2>Sidebar Item 1</h2>
</li>
<li id="item...">...</li>
<li id="item3">
<div class="imgContainer">
<img src="images/p2.jpg" /></div>
<h2>Sidebar Item 3</h2>
</li>
</ul>
</div>
<div id="mainContent">
<ul class="sortable">
<li id="milan">
<div class="imgContainer">
<img src="images/p2.jpg" /></div>
<h2>Milan Sedliak</h2>
<p>Web designer, jQuery guru, front end psycho</p>
</li>
<li id="...">...</li>
<li id="james">
<div class="imgContainer">
<img src="images/p2.jpg" /></div>
<h2>James Watt</h2>
<p>Scottish inventor and mechanical engineer</p>
</li>
</ul>
</div>
<div id="sidebar2">
<ul class="sortable">
<li id="item4">Sidebar Item 4</li>
<li id="item5">Sidebar Item 5</li>
</ul>
</div>
</div>

```

1.  现在需要应用 CSS 样式：

```php
<style>
#page { width:900px; margin:0px auto; }
#top, #sidebar, #sidebar2 { display:block; }
#top { width:100%; min-height:50px; border: 1px solid #000000; overflow:hidden; margin-bottom:10px; }
#sidebar { clear:both; float:left; width:190px; }
#sidebar2 { float:right; width:190px; }
#mainContent { float:left; width:500px; margin-left:10px; }
ul li { background-color: #FFFFFF; border: 1px solid #000000;
cursor: move; display: block; font-weight: bold;
list-style:none; margin-bottom: 5px; padding: 20px 0;
text-align: center; }
#top ul li { width: 200px; float:left; border:none; }
#top p { display: none; }
.imgContainer { display:none; }
.placeholder { background-color: #E2F2CE;
border: 1px dashed #000000; }
#mainContent ul li { text-align: left; height:80px; }
#mainContent p { font-weight: normal; }
#mainContent h2, #mainContent p { margin-left:200px; }
#mainContent .imgContainer { display:block; overflow:hidden;
float:left; width:150px; height:70px; margin-left:20px; }
</style>

```

1.  当 HTML 和 CSS 准备就绪时，我们可以看到以下结果：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_11.jpg)

1.  现在我们有了漂亮的静态布局。让我们从 JavaScript 开始：

```php
<script>
$(document).ready(function(){
$('#sidebar ul, #top ul, #sidebar2 ul, #mainContent ul')
.sortable({
connectWith: '.sortable',
placeholder: 'placeholder'
});
});
</script>

```

1.  应用这个简单的功能后，我们的结果将如下所示：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_12.jpg)

## 它是如何工作的...

主要的魔术发生在`sortable`函数内部。我们正在将可排序功能绑定到文档中的所有列表，如下所示：

`$('#sidebar ul, #top ul, #sidebar2 ul, #mainContent ul')`

```php
.sortable();

```

我们正在将它们连接在一起，以便能够将一个项目从一个列表移动到另一个列表，如下所示：

`connectWith: '.sortable'`

当对象靠近其中一个可排序的列表时，我们可以看到占位符（带有虚线边框的绿色分区）的帮助下`placeholder: 'placeholder'`。

## 还有更多...

在网站上移动对象确实很好，但如果没有保存当前位置的能力，它就不那么有用。现在，我们将学习如何将这些信息存储在 cookies 中，以及在需要时如何读取它们。我们将使用来自[`plugins.jquery.com/project/Cookie`](http://plugins.jquery.com/project/Cookie)的 jQuery Cookie 插件，如下所示：

```php
<script src="js/jquery.cookie.js"></script>

```

我们还将使用 Ajax 在服务器端保存布局信息的可能性，如下所示：

+   **保存物品：**

我们可以创建一个`getItems()`函数，来查找文档中的每个未排序列表，将其 ID 保存为 groupName，并找到与该组相关的所有项目。结果将是以`"group1=item1,item2&group2=item3,item4,..."`形式的字符串`items`：

```php
function getItems(){
var items = [];
$('ul').each(function(){
var groupName = $(this).parent().attr('id');
var groupItems = $(this).sortable('toArray')
.join(',').toString();
var item = groupName + '=' + groupItems;
items.push(item);
});
return items.join('&');
}

```

一旦我们知道如何获取所有的物品，我们就想要将它们保存在 cookies 中。为此，我们将在`sortable`函数中使用`update`方法：

```php
$('#sidebar ul, #top ul, #sidebar2 ul, #mainContent ul')
sortable function.sortable({
connectWith: '.sortable',
placeholder: 'placeholder',
update: function(){
$.cookie('items', getItems());
$.ajax({
type: "POST",
url: "ajax/saveLayout.php",
data: { items: getItems()},
success: function(data) {
if(data.status=="OK"){
// processing the further actions
} else {
// some logic for error handling
}
}
});
}
});

```

我们的`ajax/saveLayout.php`文件可能如下所示：

```php
<?php
if($_POST["items"]){
// logic for saving items
...
$result["status"] = "OK";
$result["message"] = "Items saved...";
echo json_encode($result);
}
?>

```

+   **加载物品：**

加载物品与反转`getItems`函数相同。首先，我们需要从 cookies 中读取`items`，它们以字符串的形式存储在那里。我们将通过`'&'`拆分这个字符串成组，通过`'='`拆分成组名和项目数组，通过`,`拆分成单独的项目。当我们有项目列表时，我们将它们按组名拆分成列表。如果项目没有存储在 cookies 中，我们将从服务器加载它们（`ajax/getLayout.php`）。

```php
function renderItems(){
if($.cookie('items')!=null){
var items = $.cookie('items');
var groups = items.split('&');
} else {
$.ajax({
type: "POST",
url: "ajax/getLayout.php",
data: {},
success: function(data) {
if(data.status=="OK"){
var items = data.items;
var groups = items.split('&');
} else {
// some logic for error handling
}
}
});
}
for(var key in groups){
var group = groups[key]; // top=item1,item2,item3
var groupArray = group.split('=');
var groupName = groupArray[0]; // top
var groupItemsArray = groupArray[1].split(',');
// item1,item2,item3
for(var itemKey in groupItemsArray){
$('#'+groupItemsArray[itemKey])
.appendTo($('#'+groupName+'>ul'));
}
}
}

```

`ajax/getLayout.php`示例文件将如下所示：

```php
<?php
if($_POST){
// logic to retreive items
...
$result["status"] = "OK"; // OK
$result["items"] = "top=news,about,contact-us&sidebar=item2,item3&mainContent=milan-sedliak,albert-einstein,item1,james-watt&sidebar2=item4,item5";
echo json_encode($result);
}
?>

```

`renderItems()`函数可以由`renderButton`上的`click`事件触发：

```php
$('#renderButton').click(function(){
renderItems();});

```

# Ajax 购物车

购物车在电子商务网站中扮演着重要的角色。在这个任务中，我们将学习如何使用 Ajax 功能构建一个购物车，以提供最佳的用户体验。这个任务的结果将如下截图所示：

![Ajax 购物车](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_13.jpg)

## 准备工作

我们为这个任务所需要的只是最新的 jQuery 库和一个样本`.php`文件，`ajax/shopping-cart.php`。

这个脚本将提供基本的服务器功能来检索和接收数据：

```php
<?php
if($_POST["productID"] && $_POST["action"]){
$productID = $_POST["productID"];
$action = $_POST["action"];
switch($action){
default:
$result["status"] = "ERROR";
$result["message"] = "Product has been added to the shopping cart.";
break;
case "add":
// logic for adding a product to the shopping cart
$result["status"] = "OK";
$result["message"] = "Product has been added to the shopping cart.";
break;
case "delete":
// logic for removing a product from the shopping cart
$result["status"] = "OK";
$result["message"] = "Product has been removed from the shopping cart.";
break;
}
} else {
$result["status"] = "ERROR";
$result["message"] = "Missing required data";
}
echo json_encode($result);

```

## 如何做...

1.  让我们从 HTML 开始：

```php
<div id="page">
<div id="shoppingCartContainer">
<h1>Your Basket:</h1>
<ul id="shoppingCart">
<li id="incart-product-template">
{productname} (<span>$</span>
<span class="value">{price}</span>)
<input type="button" value="delete" />
</li>
<li id="incart-product3">Product 3 (<span>$</span>
<span class="value">35</span>)
<input type="button" value="delete" /></li>
<li id="incart-product4">Product 4 (<span>$</span>
<span class="value">12</span>)
<input type="button" value="delete" /></li>
<li id="total">Total: $<span>47</span></li>
</ul>
</div>
<div id="productListContainer">
<ul id="productList">
<li id="product1">
<h1>Product 1</h1>
<div class="productPrice">
<span class="currency">$</span>
<span class="value">95</span></div>
<input type="button" value="Buy" />
</li>
<li id="product2">
<h1>Product 2</h1>
<div class="productPrice">
<span class="currency">$</span>
<span class="value">34</span></div>
<input type="button" value="Buy" />
</li>
<li id="product3">
<h1>Product 3</h1>
<div class="productPrice">
<span class="currency">$</span>
<span class="value">66</span></div>
<input type="button" value="Buy" />
</li>
</ul>
</div>
</div>

```

1.  现在，我们需要包含我们的 CSS：

```php
<style>
* { margin:0px; padding:0px; }
body { font-family: Arial, sans-serif; font-size: 16px; }
h1 { font-size:18px; padding: 10px 0; }
ul li { list-style:none; }
#page { width:900px; margin:20px auto; }
#productList li { float:left; width:200px;
text-align:center; }
#productListContainer { float:left; }
#shoppingCartContainer { float:right; }
#shoppingCart { width: 200px; }
#shoppingCart li { height:20px; }
#shoppingCart li span { color:#A3A3A3; font-weight:normal; }
#shoppingCart li#total { border-top:1px solid gray;
margin-top:5px; padding-top:5px; text-align:right; }
#shoppingCart li#total span { color:#000; font-weight:bold; }
#shoppingCart span { width:50px; font-weight:bold; }
#shoppingCart input[type=button] { float:right; }
#incart-product-template { display:none; }
</style>

```

1.  最后，但最重要的是 JavaScript 功能：

```php
<script src="js/jquery-1.4.4.js"></script>
<script>
$(document).ready(function(){
// product list functionality
$('#productList > li > input[type=button]')
.live('click', function(){
var $this = $(this).parents('li');
var productID = $this.attr('id');
var productName = $this.find('h1').html();
var productPrice =
$this.find('.productPrice .value').html();
var productCurrency =
$this.find('.productPrice .currency').html();
$.ajax({
type: "POST",
url: "ajax/shopping-cart.php",
data: { productID: productID, action: "add"},
success: function(data) {
if(data.status=="OK"){
var $item = $('#incart-product-template').clone();
var itemHTML = $item.html();
itemHTML =
itemHTML.replace(/{productname}/gi, productName);
itemHTML =
itemHTML.replace(/{price}/gi, productPrice);
$item.html(itemHTML);
$item.attr('id', productID);
$item.show()
.insertBefore($('#shoppingCart li#total'));
displayTotalPrice();
} else {
// some logic for error handling
}
}
});
});
// shopping cart functionality
$('#shoppingCart li input[type=button]')
.live('click', function(){
var $item = $(this).parents('li');
var itemID = $item.attr('id');
$.ajax({
type: "POST",
url: "ajax/shopping-cart.php",
data: { productID: itemID, action: "remove"},
success: function(data) {
if(data.status=="OK"){
$item.remove();
displayTotalPrice();
} else {
// some logic for error handling
}
}
});
});
});
// calculate the total price
var displayTotalPrice = function(){
var totalPrice = 0;
$('#shoppingCart
li:not(#incart-product-template)
span.value')
.each(function(){
totalPrice += parseInt($(this).html());
});
$('#shoppingCart #total span').html(totalPrice);
}
</script>

```

### 它是如何工作的...

Ajax 购物车功能有两个主要部分。第一部分处理产品列表。每个产品项都有一个`Buy`按钮，我们可以将`click`事件与将产品添加到购物车的功能绑定在一起：

```php
$('#productList > li > input[type=button]')
.live('click', function(){
var $this = $(this).parents('li');
var productID = $this.attr('id');
var productName = $this.find('h1').html();
var productPrice =
$this.find('.productPrice .value').html();
var productCurrency =
$this.find('.productPrice .currency').html();

```

第二部分是购物车本身。默认情况下，它包括`incart-product-template`。此模板用于基于产品列表中选择的产品构建产品。

```php
itemHTML = itemHTML.replace(/{productname}/gi, productName);

```

### 还有更多...

在电子商务网站中，我们需要非常小心地保护我们的数据。我们可以准备的攻击之一是**跨站请求伪造（CSRF）**。CSRF 是一种欺骗受害者加载包含恶意请求的特定页面的攻击。该页面的行为类似于一个喜爱的网站（例如我们的电子邮件提供商），等待我们的请求（更改密码，发送电子邮件），并试图获取敏感数据。

保护我们的网站免受 CSRF 攻击的最佳策略是在我们的请求中使用 CSRF 令牌。我们可以为用户生成一个唯一的令牌并将其存储在会话中。当请求中提供的令牌与会话中存储的令牌匹配时，我们可以接受该请求。如果不匹配，我们将拒绝它。

要在我们的源代码中使用这个令牌，我们需要在 JavaScipt 中使其可用：

```php
var csrf_token = '<%= token_value %>';

```

然后，我们将在我们的 jQuery 源中包含一个额外的`csrf_token`后参数：

```php
$.ajax({
type: "POST",
url: "ajax/shopping-cart.php",
data: {
productID: itemID,
action: "remove",
token: csrf_token
},
success: function(data) {
// our jQuery code
}
});

```

# 排序和过滤数据

通常，对数据进行排序和过滤的最佳位置是数据库。但有时，我们需要仅在客户端处理给定的数据。例如，过滤简单的联系人列表或对小型数据网格进行排序。在这个任务中，我们将学习如何在客户端对数据进行过滤和排序。

## 准备工作

我们需要 jQuery 库：

```php
<script src="js/jquery-1.4.4.js"></script>

```

我们还需要从`json/developers.json`中获取 JSON 格式的数据样本：

```php
[{
"fullname" : "Hefin Jones",
"contactlocation" : "St David's, Wales",
"labels" : "MS SQL, DBA"
},
...
{
"fullname" : "Raphaël Gabbarelli",
"contactlocation" : "Rome, Italy",
"labels" : ".Net(C#), Windows Phone 7"
}]

```

## 如何做...

1.  一开始，我们将使用`searchPlaceHolder`和`datalist`构建 HTML 代码，如下面的代码片段所示：

```php
<div class="searchPlaceHolder">
<label for="search" style="">Type to Search: </label>
<div class="loader hidden"></div>
<input type="text" autocomplete="OFF" class="search" name="search" id="search">
</div>
<div class="hidden" id="contactItemTemplate">
<li>
<div>
<h1>{fullname}</h1>
<p>{contactlocation}</p>
</div>
<a href="#">{labels}</a>
</li>
</div>
<ul class="datalist">
</ul>

```

1.  我们将使用一些巧妙的 CSS：

```php
<style>
body {
font-family: Georgia,"Times New Roman",Times,serif;
font-size: 12px; font-weight: 400; font-style: normal;
color: #60493E; }
ul li { list-style:none; padding:0px; margin:0px; }
a { color: #0181E3; text-decoration:none; }
p { padding:0px; margin:0px; }
h1 {
font: 14px/125% 'Copse',Georgia,serif;
letter-spacing: -0.03em; font-weight: 400;
font-style: normal; color: #8F0206;
text-shadow: 0 2px 0 #FCF9EE, 0 2px 0 rgba(0, 0, 0, 0.15);
margin-bottom:0px;
}
datasorting.hidden { display:none; }
.searchPlaceHolder { position:relative; z-index:0; }
.searchPlaceHolder .loader {
background: url("./images/loader-grey-on-transparent.gif") no-repeat scroll 0 0 transparent; height: 40px; position: absolute; right: 10px; top: 6px; width: 40px; z-index: 50;}
.search { width:300px; }
</style>

```

1.  当 HTML 和 CSS 准备好后，我们可以开始使用 JavaScript：

```php
<script>
var developers = [];
$(document).ready(function(){
// get json data from the server
$.get('/json/developers.json', function(data) {
if(data){
developers = data;
// sort data
developers = developers.sort(function(a, b){
var nameA=a.fullname.toLowerCase(),
nameB=b.fullname.toLowerCase();
if (nameA < nameB) //sort string ascending
return -1
if (nameA > nameB)
return 1
return 0 //default return value (no sorting)
});
initContacts();
}
}, "json");
initSearch();
});
var initContacts = function(searchString){
var searchString = searchString || "";
var items="";
var contactItemTemplate = $('#contactItemTemplate').html();
for(var i in developers){
var fullname = developers[i].fullname || "";
var contactlocation = developers[i].contactlocation || "";
var labels = developers[i].labels || "";
if(searchString!=""){
var targetString = fullname + contactlocation + labels;
if(targetString.indexOf(searchString) >= 0){
items += contactItemTemplate
.replace(/{fullname}/g, fullname)
.replace(/{contactlocation}/g, contactlocation)
.replace(/{labels}/g, labels);
}
} else {
items += contactItemTemplate
.replace(/{fullname}/g, fullname)
.replace(/{contactlocation}/g, contactlocation)
.replace(/{labels}/g, labels);
}
}
$('.datalist').html(items);
}
var initSearch = function(){
var timerId;
$('.search').keyup(function() {
var string = $(this).val();
clearTimeout (timerId);
timerId = setTimeout(function(){
initContacts(string);
}, 500 );
})
}
</script>

```

1.  当一切准备就绪时，我们的结果如下所示：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_14.jpg)

## 它是如何工作的...

在`document.ready`事件中，我们向服务器请求数据。这些数据保存为`developers`对象，并按每个开发人员的全名进行排序。

一旦从服务器检索到数据对象，我们调用`initContacts()`函数。该函数处理开发人员对象并在数据列表中创建开发人员列表。当用户输入搜索词时，搜索字符串变量被填充。这会触发开发人员列表的刷新，仅显示那些名字、位置或标签包含完全匹配搜索字符串的开发人员。

## 还有更多...

在前面的示例中，数据的排序仅适用于字符串。如果我们想要按整数或日期进行排序，我们必须创建新的排序函数：

+   **按整数排序：**

这是一个按整数排序的示例函数（升序）：

```php
theArray.sort(function(a, b){
return a.age-b.age;});

```

+   **按日期排序：**

在这里，数据按日期排序：

```php
theArray.sort(function(a, b){
var dateA=new Date(a.startingDate);
vaf dateB=new Date(b.startingDate);
return dateA-dateB;
});

```

# 添加视觉效果和动画

jQuery 最大的优势在于它能够与 DOM 一起工作，并创建整洁的效果和动画。在这个任务中，我们将学习如何创建我们自己的图像/内容滑块，并能够动态加载图像。

## 准备工作

我们需要准备一些示例图片并将它们保存到我们的`images`文件夹中。当然，我们还需要 jQuery 库。

## 如何做...

1.  像往常一样，我们将从 HTML 代码开始：

```php
<div class="slideBox">
<div id="slider1" class="mslider">
<ul>
<li title="1.jpg"></li>
<li title="2.jpg"></li>
<li title="3.jpg"></li>
<li title="5.jpg"></li>
</ul>
<div class="navContainer">
<div class="buttonsContainer">
<span class="btnPrev button">Prev</span>
<span class="btnNext button">Next</span>
</div>
</div>
</div>
</div>

```

1.  在这个任务中，CSS 代码非常重要：

```php
<style>
.slideBox { width:900px; float:left; margin:0px; text-align:center; margin-bottom:50px; }
#slider1 { height:400px; width:800px; margin:0 auto; }
.mslider { border:1px solid black; position:relative;
overflow:hidden; text-align:left; }
.mslider ul { float:left; margin-left:0px; width:8000px;}
.mslider ul li { float:left; list-style-type: none;
margin:0px; }
.mslider .navContainer { display:none; position:absolute; bottom:0; left:0; background-color:#000;
width:100%; height:80px; color:white; }
.mslider .buttonsContainer { float:right; color:white;
margin-right:10px; margin-top:10px; font-weight:normal;
text-decoration:none; }
.mslider .buttonsContainer a { margin:5px; color:white;
font-weight:normal; text-decoration:none;
text-shadow:5px 5px 5px #000000; }
.mslider .buttonsContainer .button { cursor:pointer;
margin-left:10px; }
.mSlide-nav-panel { position:absolute; bottom:0; left:0; }
</style>

```

1.  最后，JavaScript 功能：

```php
<script>
var activeItem = 0;
var itemsNb = 0;
$(document).ready(function(){
preloadPictures(activeItem);
$('#slider1').hover(function(){
$(this).find('.navContainer').fadeIn('200');
}, function(){
$(this).find('.navContainer').fadeOut('200');
});
// our JS goodness
$('.btnPrev').bind('click', function(){
moveTo(activeItem-1);
});
$('.btnNext').bind('click', function(){
moveTo(activeItem+1);
});
itemsNb = $('#slider1 > ul > li').length;
});
var preloadPictures = function(activeItem){
for(var i = (activeItem == 0) ? 0:1; i < 2; i++){
var $activeItem = $(".mslider ul li").eq(activeItem+i);
var imageNextName = $activeItem.attr('title');
if(imageNextName!=""){
var $imageNext =
$('<img src="images/'+imageNextName+'" />');
$activeItem.html("");
$imageNext.appendTo($activeItem);
}
}
}
var moveTo = function ( itemNumber ){
var $btnPrev = $('.btnPrev');
var $btnNext = $('.btnNext');
var $mSliderList = $('#slider1 > ul');
var $mSliderItem = $('#slider1 > ul > li');
var margin = itemNumber * $mSliderItem.width();
$mSliderList.animate({ marginLeft: "-" + margin + "px" }, 500 );
activeItem = itemNumber;
// hide 'prev' button if the active item is #1
activeItem == 0 ? $btnPrev.hide():$btnPrev.show();
// hide 'next' button if the active item is the last item
activeItem == (itemsNb-1)?$btnNext.hide():$btnNext.show();
}
</script>

```

1.  前面源代码的结果是一个简单的图像滑块：![如何做...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_15.jpg)

## 它是如何工作的...

滑块有两个主要对象——包含图像的列表和导航。导航包含**（上一个，下一个）**按钮，用于更改当前图像。单击其中一个按钮后，我们调用`moveTo()`函数。该函数会动画显示滑动列表的左边距：

```php
$mSliderList.animate({ marginLeft: "-" + margin + "px" }, 500 );

```

当动画完成时，我们检查导航按钮的可见性，如下所示：

```php
// hide 'prev' button if the active item is #1
activeItem == 0 ? $btnPrev.hide():$btnPrev.show();
// hide 'next' button if the active item is the last item
activeItem == (itemsNb-1)?$btnNext.hide():$btnNext.show();

```

滑块使用`preloadPictures()`函数动态预加载所需的图片。当页面首次加载时，我们将把前两张图片加载到滑块中。第一张图片被显示，第二张图片被准备好进行平滑滑动。点击**下一个**按钮后，我们将再次调用`preloadPictures()`函数，预加载另一张图片到列表中。这将为下一张幻灯片做准备，如下所示：

```php
var preloadPictures = function(activeItem){
/**
* logic for the preloading loop. If the page is loaded
* for the first time, we need to load two pictures.
* This will provide a smooth sliding
* from picture 1.jpg to 2.jpg
**/
for(var i = (activeItem == 0) ? 0:1; i < 2; i++){
var $activeItem = $(".mslider ul li").eq(activeItem+i);
var imageNextName = $activeItem.attr('title');
if(imageNextName!=""){
var $imageNext =
$('<img src="images/'+imageNextName+'" />');
$activeItem.html("");
$imageNext.appendTo($activeItem);
}
}
}

```

## 还有更多...

我们可以在一个滑块中结合更多的动画。现在，我们将创建一个描述列表，为当前幻灯片提供单独的信息。我们将修改`navContainer:`

```php
<div class="navContainer">
<div class="descContainer">
<ul class="descList">
<li>
<div class="title">Dotique.sk</div>
<div class="desc">PSD to HTML, CSS, ...</div>
<div class="url">
<a href="/my-work/dotique-sk/">
Read more &gt;&gt;</a>
</div>
</li>
<li>...</li>
<li>
<div class="title">Tatrawell.com</div>
<div class="desc">PSD to HTML, CSS, ...</div>
<div class="url">
<a href="/my-work/tatrawell/">
Read more &gt;&gt;</a>
</div>
</li>
</ul>
</div>
<div class="buttonsContainer">...</div>
</div>

```

我们还将对我们的 CSS 进行以下添加：

```php
.mslider .descContainer { position:relative; width:580px; height:80px; overflow:hidden; float:left; margin:10px; color:white; }
.mslider ul.descList { float:left; width:600px; height:80px; color:white; }
.mslider ul.descList li { float:left; width:600px; height:80px; }

```

接下来，我们将扩展`moveTo()`函数，如下所示：

```php
var navHeight = $('.navContainer').height();
var marginDescList = (itemNumber * navHeight);
$('.descList').animate({
marginTop: "-" + marginDescList + "px"
}, 500 );

```

现在，我们已经实现了一个具有专业外观的漂亮的图像/内容滑块：

![还有更多...](https://github.com/OpenDocCN/freelearn-php-zh/raw/master/docs/php-ajax-cb/img/3081_03_16.jpg)
