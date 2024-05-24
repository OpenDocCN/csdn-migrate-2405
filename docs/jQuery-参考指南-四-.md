# jQuery 参考指南（四）

> 原文：[`zh.annas-archive.org/md5/0AC785FD3E3AB038A029EF6BA3FEE889`](https://zh.annas-archive.org/md5/0AC785FD3E3AB038A029EF6BA3FEE889)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：插件 API

> 现在我一次做两个
> 
> 我已经开发了一种技术
> 
> —Devo，
> 
> "Fräulein"

每当一个任务要执行两次或更多次时，都应用**DRY**原则——不要重复自己是一个好主意。为了方便起见，jQuery 为开发人员提供了几种工具，超出了简单的迭代和函数创建。**插件**开发是一种反复证明有益的技术。

在本章中，我们将简要介绍使用其他开发者的插件的基础知识，然后深入探讨用我们自己定义的插件扩展 jQuery 的各种方法。

# 使用插件

利用现有的 jQuery 插件非常简单。插件包含在一个标准的 JavaScript 文件中。获得该文件的方法有很多种，但最简单的方法是浏览[`jquery.com/plugins`](http://jquery.com/plugins)上的 jQuery 插件仓库。许多热门插件的最新版本都可以从该网站下载。

要使插件的方法对我们可用，我们只需将其包含在文档的`<head>`中。我们必须确保它出现在主要的 jQuery 源文件之后，并且出现在我们自定义的 JavaScript 代码之前：

```js
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
  <script src="img/jquery.js" type="text/javascript"></script>
 <script src="img/jquery.plug-in.js" type="text/javascript"></script>
  <script src="img/custom.js" type="text/javascript"></script>
  <title>Example</title>
</head>
```

在那之后，我们就可以使用插件公开的任何方法了。例如，使用*Form*插件，我们可以在我们自定义文件的`$(document).ready`方法内添加一行代码来通过 AJAX 提交表单：

```js
$(document).ready(function() {
  $('#myForm').ajaxForm();
});
```

每个插件都有独立的文档。在接下来的章节中，我们将详细介绍一些更显著的插件，描述它们的每个方法。要了解更多关于其他插件的信息，我们可以查看从 jQuery 插件仓库链接的文档，或者阅读源代码中的解释性注释。

如果我们在插件仓库、作者的网站或插件的注释中找不到所有问题的答案，我们总是可以求助于 jQuery 讨论列表。许多插件作者经常在列表上发表意见，并且总是乐意帮助新用户可能面临的任何问题。订阅讨论列表的说明可以在[`docs.jquery.com/Discussion`](http://docs.jquery.com/Discussion)找到。

# 开发插件

正如我们上面讨论的，当我们要执行一个任务超过一次时，插件开发是一种有用的技术。在这里，我们将列举可以填充我们自己设计的插件文件的组件。我们的插件可以使用以下四种类型的 jQuery 增强的任意组合：对象方法、全局函数、选择器表达式和缓动样式。

## 对象方法

| 将一个新的方法添加到由`$()`工厂函数创建的所有 jQuery 对象中。

```js
jQuery.fn.methodName = methodDefinition

```

|

### 组件

+   `methodName`：新方法的标签。

+   `methodDefinition`：在 jQuery 对象实例上调用`.methodName()`时要执行的函数对象。

### 讨论

当函数需要对一个或多个 DOM 元素进行操作时，通常适合创建一个新的 jQuery 对象方法。对象方法可以访问由 jQuery 对象引用的匹配元素，并且可以检查或操作它们。

可以通过引用关键字 `this` 从方法实现中检索到 jQuery 对象。我们可以调用这个对象的内置 jQuery 方法，也可以直接提取 DOM 节点以直接处理它们。正如我们在第八章中看到的那样，我们可以使用数组表示法检索引用的 DOM 节点：

```js
jQuery.fn.showAlert = function() {
  alert('You called the method on "' + this[0] + '".');
  return this;
}
```

在这里，我们使用 `this[0]` 来找到一个元素，但是我们需要记住，jQuery 选择器表达式始终可以匹配零个、一个或多个元素。在设计插件方法时，我们必须为这些情况中的任何一种留出空间。实现这一点的最简单方法是在方法上下文中调用 `.each()`；这强制进行**隐式迭代**，这对于保持插件和内置方法之间的一致性很重要。在 `.each()` 调用的函数参数内，`this` 依次引用每个 DOM 元素：

```js
jQuery.fn.showAlert = function() {
  return this.each(function() {
    alert('You called the method on "' + this + '".');
  });
}
```

现在我们可以将我们的方法应用于引用多个项的 jQuery 对象：

```js
$('.myClass').showAlert();

```

我们的方法为每个由前面选择器表达式匹配的元素生成一个单独的警报。

还要注意，在这些示例中，当我们完成工作时，我们会返回 jQuery 对象本身（由 `this` 引用）。这样一来，就实现了 jQuery 用户应该依赖的**链接**行为。除非方法明确用于检索不同的信息并且已经记录了这样的用法，否则我们必须从所有插件方法中返回一个 jQuery 对象。

## 全局函数

| 使一个新的函数可用于脚本，包含在 jQuery 命名空间内。

```js
jQuery.pluginName = fnDefinition;
jQuery.pluginName = {
function1: fnDefinition1,
function2: fnDefinition2
};

```

|

### 组件（第一个版本）

+   `pluginName`: 当前插件的名称。

+   `fnDefinition`: 当调用 `$.pluginName()` 时要执行的函数对象。

### 组件（第二个版本）

+   `pluginName`: 当前插件的名称。

+   `function1`: 第一个函数的标签。

+   `fnDefinition1`: 当调用 `$.pluginName.function1()` 时要执行的函数对象。

+   `function2`: 第二个函数的标签。

+   `fnDefinition2`: 当调用 `$.pluginName.function2()` 时要执行的函数对象。

### 讨论

我们这里称之为**全局函数**的东西在技术上是 `jQuery` 函数对象的方法。从实际上来说，它们是 jQuery 命名空间内的函数。通过将函数放在 jQuery 命名空间内，我们减少了与脚本中其他函数和变量的名称冲突的机会。

**单一函数**

第一种用法反映了当插件仅需要一个单独的函数时创建全局函数的情况。通过使用插件名称作为函数名称，我们可以确保我们的函数定义不会被其他插件踩踏（只要其他插件遵循相同的准则！）。新函数被分配为 `jQuery` 函数对象的属性：

```js
jQuery.myPlugin = function() {
  alert('This is a test. This is only a test.');
};
```

现在在使用此插件的任何代码中，我们可以编写：

```js
jQuery.myPlugin();

```

我们也可以使用 `$` 别名并写：

```js
$.myPlugin();

```

这将像任何其他函数调用一样工作，并显示警报。

**多个函数**

在第二种用法中，我们看到如何在同一个插件需要多个函数时定义全局函数。我们将所有插件封装在一个名为我们插件的命名空间中：

```js
jQuery.myPlugin = {
  foo: function() {
    alert('This is a test. This is only a test.');
  },
  bar: function(param) {
    alert('This function takes a parameter, which is "' + param + '".');
  }
};
```

要调用这些函数，我们将它们视为命名为我们插件的对象的成员，该对象本身是全局 jQuery 函数对象的属性：

```js
$.myPlugin.foo();
$.myPlugin.bar('baz');

```

现在函数已正确保护，不会与全局命名空间中的其他函数和变量发生冲突。

通常，从一开始就使用第二种用法是明智的，即使看起来只需要一个函数，因为这样做可以更轻松地进行将来的扩展。

## 选择器表达式

| 添加了一种使用 jQuery 选择器字符串查找 DOM 元素的新方法。

```js
jQuery.extend(jQuery.expr[selectorType], {
selectorName: elementTest
});

```

|

### 组件

+   `selectorType`：选择器字符串的前缀字符，指示正在定义哪种类型的选择器。在实践中，对于插件来说，有用的值是 `':'`，表示伪类选择器。

+   `selectorName`：一个唯一标识此选择器的字符串。

+   `elementTest`：包含要评估的 JavaScript 表达式的字符串。如果表达式对元素 `a` 评估为 `true`，则该元素将包含在结果集中；否则，该元素将被排除。

### 讨论

插件可以添加允许脚本使用紧凑语法找到特定集合的 DOM 元素的选择器表达式。通常，插件添加的表达式是新的伪类，以领先的 `':'` 字符标识。

jQuery 支持的伪类具有 `:selectorName(param1(param2))` 的一般格式。此格式仅需要 `selectorName` 部分；如果伪类允许参数以使其更具体，`param1` 和 `param2` 可用。

元素测试表达式可以引用两个特殊变量，名为 `a` 和 `m`。正在测试的 DOM 元素存储在 `a` 中，选择器表达式的组件存储在 `m` 中。`m` 的内容是正则表达式匹配的结果，它将 `:selectorName(param1(param2))` 分解如下：

```js
m[0] == ':selectorName(param1(param2))'
m[1] == ':'
m[2] == 'selectorName'
m[3] == 'param1(param2)'
m[4] == '(param2)'

```

例如，我们可以构建一个测试元素的子节点数的伪类，并将这个新的选择器表达式称为 `:num-children(n)`：

```js
jQuery.extend(jQuery.expr[':'], {
  'num-children': 'a.childNodes.length == m[3]'
});
```

现在我们可以，例如，选择所有具有两个子节点的 `<ul>` 元素，并将它们变为红色：

```js
$(document).ready(function() {
  $('ul:num-children(2)').css('color', 'red');
});
```

如果需要添加除伪类之外的选择器表达式，应查看`jquery.js`中的`jQuery.parse`以找到其他选择器类型的相关正则表达式匹配。

## **缓动样式**

| 为未来的动画定义了一个加速曲线。

```js
jQuery.extend(jQuery.easing, {
easingStyleName: easingFunction
});

```

|

### 组件

+   `easingStyleName`：新缓动样式的标签。

+   `easingFunction`：确定任何给定时刻的动画值的函数对象。缓动函数传递以下参数：

    +   `fraction`：动画的当前位置，以从 0（动画的开始）到 1（动画的结束）的时间来衡量。

    +   `elapsed`：动画开始后经过的毫秒数（很少使用）。

    +   `attrStart`：正在进行动画的 CSS 属性的起始值。

    +   `attrDelta`：正在进行动画的 CSS 属性的起始值和结束值之间的差异。

    +   `duration`：动画期间总共经过的毫秒数（很少使用）。

### 讨论

大多数有效的方法都会触发一个具有固定**缓动样式**的动画，称为**swing**。缓动样式定义了动画随时间加速和减速的方式。`.animate` 方法给了我们更大的灵活性；该方法的一个参数允许指定自定义缓动样式。可以使用这个插件机制创建新的缓动样式。

缓动函数必须在动画的任何时刻返回正在动画的属性的值。由于传递给缓动函数的参数，计算通常采用以下形式：

```js
f(fraction) * attrDelta + attrStart

```

在这个计算中，`f`代表一个数学函数，其值随着参数从 0 到 1 的变化而从 0 到 1 变化。例如，一个导致动画以恒定速率进行的缓动样式将需要一个线性函数（`f(x) = x`）：

![关于缓动样式的讨论](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_09_01.jpg)

在一个插件中，这个缓动样式将用以下代码表示：

```js
jQuery.extend(jQuery.easing, { 
  'linear': function(fraction, elapsed, attrStart, attrDelta,
                                                       duration) {
    return fraction * attrDelta + attrStart;
  }
});
```

另一方面，如果我们希望我们的动画开始缓慢，然后逐渐加速，我们可以使用一个二次函数（`f(x)` `=` `x` `2` `）`：

![关于缓动样式的讨论](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_09_02.jpg)

在一个插件中，这个缓动样式将用以下代码表示：

```js
jQuery.extend(jQuery.easing, { 
  'quadratic': function(fraction, elapsed, attrStart, attrDelta,
                                                       duration) {
    return fraction * fraction * attrDelta + attrStart;
  }
});
```

安装了这样一个缓动插件后，我们可以在调用`.animate`方法时随时选择新的缓动样式：

```js
$('.myClass').animate({
  'left': 500,
  'opacity': 0.1
}, 'slow', 'quadratic');
```

通过这个调用，所有附有`myClass`类的元素都会移动并淡出到指定的值，开始缓慢，然后逐渐加速直到它们到达目的地。

# 示例：维护多个事件日志

在前面的参考章节中的各种示例中，我们需要在各种事件发生时显示日志事件。JavaScript 的 `alert` 函数通常用于此类演示，但不允许我们按时显示频繁的消息。一个更好的选择是 Firefox 和 Safari 可用的 `console.log` 函数，它允许将消息打印到不会中断页面交互流程的单独日志中。然而，由于此函数不适用于 Internet Explorer，因此我们使用了一个自定义函数来实现此类消息记录的样式。

### 注意

Firebug Lite 脚本（见 附录 B）提供了一个非常强大的跨平台日志记录工具。我们在这里开发的方法专门针对前几章的示例；对于一般情况，通常更倾向于使用 Firebug Lite。

记录消息的一个简单方法是创建一个全局函数，将消息附加到页面上的特定元素：

```js
jQuery.log = function(message) {
  $('<div class="log-message"></div>')
    .text(message).appendTo('.log');
};
```

我们可以变得更加花哨，让新消息以动画的方式出现：

```js
jQuery.log = function(message) {
  $('<div class="log-message"></div>')
    .text(message)
    .hide()
    .appendTo('.log')
    .fadeIn();
};
```

现在我们可以调用 `$.log('foo')` 在页面上的日志框中显示 `foo`。

然而，我们有时在单个页面上有多个示例，因此，将每个示例保持单独的日志记录是很方便的。我们通过使用方法而不是全局函数来实现这一点：

```js
jQuery.fn.log = function(message) {
  return this.each(function() {
    $('<div class="log-message"></div>')
      .text(message)
      .hide()
      .appendTo(this)
      .fadeIn();
  });
};
```

现在调用 `$('.log').log('foo')` 就像我们之前的全局函数调用一样，但我们可以更改选择器表达式以定位不同的日志框。

然而，理想情况下，`.log` 方法应该足够智能，能够在没有显式选择器的情况下找到最相关的日志消息框。通过利用传递给方法的上下文，我们可以遍历 DOM，找到最接近所选元素的日志框：

```js
jQuery.fn.log = function(message) {
  return this.each(function() {
    $context = $(this);
    while ($context.length) {
      $log = $context.find('.log');
      if ($log.length) {
        $('<div class="log-message"></div>')
          .text(message).hide().appendTo($log).fadeIn();
        break;
      }
      $context = $context.parent();
    }
  });
};
```

此代码在匹配元素中查找日志消息框，如果找不到，则向上遍历 DOM 查找一个。

最后，有时我们需要显示对象的内容。直接打印对象本身得到的是几乎没有信息的东西，像 `[object Object]`，因此，我们可以检测参数类型，在传递对象时进行一些自己的美化打印：

```js
jQuery.fn.log = function(message) {
  if (typeof(message) == 'object') {
    string = '{';
    $.each(message, function(key, value) {
      string += key + ': ' + value + ', ';
    });
    string += '}';
    message = string;
  }
  return this.each(function() {
    $context = $(this);
    while ($context.length) {
      $log = $context.find('.log');
      if ($log.length) {
        $('<div class="log-message"></div>')
          .text(message).hide().appendTo($log).fadeIn();
        break;
      }
      $context = $context.parent();
    }
  });
};
```

现在我们有了一个可以在页面上与正在进行的工作相关的地方写出对象和字符串的方法。

# 总结

在本章中，我们从两个角度查看了插件：使用和开发。我们看了四种类型的 jQuery 插件添加：插件可以引入新的全局方法和 jQuery 对象方法；此外，它们可以添加选择器表达式和缓动样式。

虽然如此，我们通常更感兴趣的是使用其他人创建的插件。虽然我们已经指向了许多插件的可用文档，但在接下来的章节中，我们将更详细地介绍两个较受欢迎的插件。


# 第十章：尺寸插件

> 我们信仰的符号
> 
> 有时会颠倒过来
> 
> 重塑每个尺寸
> 
> 我们对此深信不疑
> 
> —Devo，
> 
> "纯真的真相"

**Dimensions** 插件，由 Paul Bakaus 和 Brandon Aaron 共同编写，有助于弥合 CSS 盒模型与开发者准确测量文档中元素的高度和宽度之间的差距。它还以像素精度测量元素的顶部和左侧偏移量，无论它们在页面的哪个位置。在本章中，我们将探讨此插件的各种方法并讨论它们的选项。

# 尺寸方法

除了确定浏览器窗口或文档的尺寸之外，以下尺寸方法还形成了一组强大的工具，用于识别元素的高度和宽度，无论我们是否想考虑元素的填充和边框大小。

我们将在接下来的每个示例中使用相同的基本 HTML：

```js
<body>
  <div id="container">
<!-- CODE CONTINUES -->    
    <div id="content">
      <div class="dim-outer">
        <p>This is the outer dimensions box. It has the following CSS rule:</p>
<pre><code>.dim-outer {
  height: 200px;
  width: 200px;
  margin: 10px;
  padding: 1em;
  border: 5px solid #e3e3e3;
  overflow: auto;
  font-size: 12px;
}</code></pre>
        <p>Scroll down for the inner dimensions box.</p>
        <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit,sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p>
        <div class="dim-inner"> This is the inner dimensions box.
        </div>
      </div> 

<!-- CODE CONTINUES -->

    </div>
  </div> 
</body>
```

## .height()

| 获取 `document` 或 `window` 对象的高度。

```js
.height()

```

|

### 参数

无。

### 返回值

一个表示高度的像素整数。

### 讨论

`.height` 方法简单地使用了 jQuery 核心方法相同名称的方法。Dimensions 将 `.height()` 方法扩展到浏览器 `window` 和 `document` 上。

`$(window).height()` 返回浏览器窗口的像素高度。如果有水平滚动条，则不包含在高度计算中。

`$(document).height()` 返回文档的像素高度。如果文档的高度大于可见区域——在这种情况下存在垂直滚动条——`$(document).height()` 计算总高度，包括可见部分和隐藏部分。

以下图像说明了 `$(document).height()` 和 `$(window).height()` 之间的差异：

![Discussion.height()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_01.jpg)

有关在页面上使用 `.height` 方法的信息，请参见 第四章。

## .width()

| 获取 `document` 或 `window` 对象的宽度。

```js
.width()

```

|

### 参数

无。

### 返回值

一个表示宽度的像素整数。

### 描述

`.width` 方法，就像它的 `.height()` 对应物一样，当应用到元素时，简单地使用了 jQuery 核心方法相同名称的方法。然而，Dimensions 将 `.width()` 扩展，以便我们可以将其应用到 `document` 和浏览器 `window` 上。

`$(document).width()` 返回文档的像素宽度。如果有垂直滚动条，则 `$(document).width()` 不包括在计算中。如果文档的宽度大于可见区域——在这种情况下存在水平滚动条——`$(document).width()` 计算总高度，包括页面的可见部分和隐藏部分。

`$(window).width()` 返回浏览器的像素宽度。如果有垂直滚动条，则不包含在宽度计算中。

下面的图像说明了`$(document).width()`和`$(window).width()`之间的差异：

![Description.width()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_02.jpg)

有关在页面上使用`.width`方法的信息，请参阅第四章。

## .innerHeight()

| 获取匹配元素集中第一个元素的计算内部高度。

```js
.innerHeight()

```

|

### 参数

无。

### 返回值

一个表示元素内部高度的整数，以像素为单位。

### 描述

`.innerHeight` 方法与基本的`.height()`不同之处在于它计算顶部和底部填充的高度，而不仅仅是元素本身的高度。但是，它的计算不包括边框或外边距。

如果与`document`或`window`一起使用，`.innerHeight()` 调用 Dimensions`.height`方法返回这个值。

给定一个高度为`200px`，字体大小为`12px`，顶部和底部填充为`1em`的元素，`.innerHeight()` 返回`224`（像素），如下图所示：

![Description.innerHeight()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_03.jpg)

## .innerWidth()

| 获取匹配元素集合中第一个元素的计算内部宽度。

```js
.innerWidth()

```

|

### 参数

无。

### 返回值

一个表示元素内部宽度的整数，以像素为单位。

### 描述

`.innerWidth` 方法与基本的`.width()`不同之处在于它计算左右填充的宽度，而不仅仅是元素本身的宽度。然而，它的计算不包括边框或外边距。

如果与`document`或`window`一起使用，`.innerWidth()`调用 Dimensions`.width`方法返回这个值。

给定宽度为`200px`，字体大小为`12px`，左右填充为`1em`的元素，`.innerWidth()`返回`224`（像素），如下图所示：

![Description.innerWidth()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_04.jpg)

## .outerHeight()

| 获取匹配元素集中第一个元素的计算外部高度。

```js
.outerHeight()

```

|

### 参数

无。

### 返回值

一个表示元素外部高度的整数，以像素为单位。

### 讨论

`.outerHeight` 方法与基本的 `.height()` 不同之处在于它计算顶部和底部填充以及顶部和底部边框的高度，而不仅仅是元素本身的高度。但是，与`.height()`和`.innerHeight()`一样，它的计算不包括元素的外边距。

如果与`document`或`window`一起使用，`.outerHeight()` 调用 Dimensions`.height`方法返回这个值。

![Discussion.outerHeight()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_05.jpg)

## .outerWidth()

| 获取匹配元素集中第一个元素的计算外部宽度。

```js
.outerWidth()

```

|

### 参数

无。

### 返回值

一个表示元素外部宽度的整数，以像素为单位。

### 描述

`.outerWidth`方法与基本的`.width()`不同之处在于，它在计算元素本身的宽度之外还计算左右填充和左右边框的宽度。然而，与`.width()`和`.innerWidth()`一样，它不包括元素的边距在内的计算。

如果与`document`或`window`一起使用，`.outerWidth()`调用尺寸`.width`方法来返回值。

![Description.outerWidth()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_06.jpg)

# 定位方法

以下方法有助于确定元素的精确位置——相对于定位祖先、文档主体或文档的可视区域。

就像*尺寸方法*部分一样，我们将为以下每个示例使用相同的基本 HTML：

```js
<body>
  <div id="container">
<!-- CODE CONTINUES -->    
    <div id="content">
      <div class="dim-outer">
        <p>This is the outer dimensions box. It has the following CSS rule:</p>
<pre><code>.dim-outer {
  height: 200px;
  width: 200px;
  margin: 10px;
  padding: 1em;
  border: 5px solid #e3e3e3;
  overflow: auto;
  font-size: 12px;
}</code></pre>
        <p>Scroll down for the inner dimensions box.</p>
        <p>Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.</p><div class="dim-inner"> This is the inner dimensions box.
        </div>
      </div> 

<!-- CODE CONTINUES -->

    </div>
  </div> 
</body>
```

## .scrollTop()

| 获取窗口或文档内的可滚动元素向下滚动的像素数。

```js
.scrollTop()

```

|

### 参数

无。

### 返回值

表示像素的垂直滚动条位置的整数。

### 讨论

`.scrollTop`方法能够返回浏览器窗口或文档内元素的垂直滚动位置。例如，在`<div class="dim-outer">`向下滚动了 96 像素后（如下图所示），`$('div.dim-outer').scrollTop()`返回`96`：

![Discussion.scrollTop()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_07.jpg)

## .scrollTop(value)

| 设置在窗口或文档内匹配的可滚动元素中从上向下滚动的像素数。

```js
.scrollTop(value)

```

|

### 参数

+   `value`：表示像素数的整数。

### 返回值

用于链接目的的 jQuery 对象。

### 描述

通过将数值传递给`.scrollTop`方法，我们可以将浏览器窗口或文档内可滚动元素的滚动位置上下移动。在下图中，`<div class="dim-outer">`的滚动位置已经设置为`$('div.dim-outer').scrollTop(200)`：

![Description.scrollTop(value)about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_08.jpg)

## .scrollLeft()

| 获取窗口或文档内可滚动元素从左向右滚动的像素数。

```js
.scrollLeft()
```

|

### 参数

无。

### 返回值

表示水平滚动条位置的整数。

### 描述

`.scrollLeft`方法能够返回浏览器窗口或文档内元素的水平滚动位置。例如，在浏览器窗口向右滚动了 24 像素后，如下图所示，`$(window).scrollLeft()`的返回值是`24`：

![Description.scrollLeft()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_09.jpg)

## .scrollLeft(value)

| 设置在窗口或文档内匹配的可滚动元素中从左向右滚动的像素数。

```js
.scrollLeft(value)
```

|

### 参数

+   `value`：表示像素数的整数。

### 返回值

用于链接目的的 jQuery 对象。

### 讨论

通过向`.scrollLeft`方法传递一个数字值，我们可以将浏览器窗口或文档内可滚动元素的滚动位置向左或向右移动。在下面的图像中，浏览器窗口的滚动位置已经设置为`$(window).scrollLeft(50)`

![关于 Discussion.scrollLeft(value)](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_10.jpg)

## .偏移量()

| 获取匹配元素集中第一个元素的顶部和左侧坐标。还获取匹配元素的`scrollTop`和`scrollLeft`偏移量。

```js
.offset([options])
.offset(options, returnObject)

```

|

### 参数（第一版）

+   `options` (optional)：一个设置映射，用于配置偏移量的计算方式。可以包含以下项目：

    +   `margin` (optional)：一个布尔值，表示是否在计算中包含元素的外边距。默认为`true`。

    +   `border` (optional)：一个布尔值，表示是否在计算中包含元素的边框。默认为`false`。

    +   `padding` (optional)：一个布尔值，表示是否在计算中包含元素的填充。默认为`false`。

    +   `scroll` (optional)：一个布尔值，表示是否在计算中包含所有祖先元素的滚动偏移量。默认为`true`。

    +   `lite` (optional)：一个布尔值，表示是否使用 offsetLite 而不是 offset。默认为`false`。

+   `relativeTo` (optional)：表示匹配元素将被偏移到哪个祖先元素的 HTML 元素。默认为`document.body`。

### 参数（第二版）

+   `options`：一个设置映射，用于配置偏移量的计算方式。

    +   `margin` (optional)：一个布尔值，表示是否在计算中包含元素的外边距。默认为`true`。

    +   `border` (optional)：一个布尔值，表示是否在计算中包含元素的边框。默认为`false`。

    +   `padding` (optional)：一个布尔值，表示是否在计算中包含元素的填充。默认为`false`。

    +   `scroll` (optional)：一个布尔值，表示是否在计算中包含所有祖先元素的滚动偏移量。默认为`true`。

    +   `lite` (optional)：一个布尔值，表示是否使用`offsetLite`而不是`offset`。默认为`false`。

    +   `relativeTo` (optional)：表示匹配元素将被偏移到哪个祖先元素的 HTML 元素。默认为`document.body`。

    +   `returnObject`：一个对象，用于存储返回值。当使用方法的第二个版本时，链条将不会被打破，并且结果将被分配到此对象中。

### 返回值（第一版）

包含`top, left`值，以及可选的`scrollTop`和`scrollLeft`值的对象。

### 返回值（第二版）

jQuery 对象，用于链式目的。

### 描述

`.offset`方法允许我们定位页面上任何位置的任何元素的`top`和`left`位置，不管其`position`是`static`还是`relative, absolute`还是`fixed`，也不管滚动条的位置如何。通过对 margin、border、padding 和 scroll 进行计算，`.offset()`提供了极大的灵活性和准确性。

以下一系列图像展示了不同设置下`.offset()`返回的不同值。

**默认设置**

在第一个示例中，使用了 padding（false）、border（false）和 margin（true）的默认设置。结果：

```js
{top: 117, left: 580, scrollTop: 0, scrollLeft: 0}

```

![Description.offset()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_11.jpg)

请注意，由于 margin 的默认值是`true`，因此从窗口左边缘到匹配元素的距离一直延伸到（但不包括）元素的边框。

**包括边框**

在第二个示例中，边框选项设置为`true`。由于`<div class="dim-outer">`周围有 5 像素的边框，`top`和`left`值分别增加了 5 像素：

```js
{top: 122, left: 585, scrollTop: 0, scrollLeft: 0}

```

![Description.offset()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_12.jpg)

**包括边框和内边距**

接下来的示例将边框和 padding 选项都设置为`true`（记住 margin 选项的默认值为`true`）。结果是边框增加了 5 像素，内边距增加了另外 12 像素（1em）：

```js
{top: 134, left: 597, scrollTop: 0, scrollLeft: 0}

```

![Description.offset()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_13.jpg)

**查找相对于祖先的位置**

通过`relativeTo`选项，我们可以找到元素与其任何一个定位祖先之间的偏移距离。在下一个示例中，我们正在获取`<div class="dim-outer">`和`<div id="content">`之间的偏移量。由于`content <div>`本身就是由于容器的 24 像素左边距而从窗口左侧偏移，左侧的值现在比上一个示例少了 24 像素：

```js
{top: 27, left: 573, scrollTop: 0, scrollLeft: 0}

```

![Description.offset()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_14.jpg)

值得注意的是，由于`relativeTo`设置需要一个 DOM 元素，所以我们在使用它的`relativeTo`参数之前，使用了简写`[0]`来将 jQuery 对象转换为 DOM 元素。

`top`值为`27`是由浮动`<div class="dim-outer">`元素的 margin（`12`）、border（`5`）和 padding（`10`）的总和得出的。如果`<div id="content">`有任何应用到其顶部的 padding，那也将被添加到总的顶部偏移量中。

**返回滚动偏移**

`scroll`选项的默认值为`true`，当匹配的元素位于一个或多个`overflow`属性设置为`auto`或`scroll`的元素内部时，它特别有用。它将所有祖先元素的滚动偏移量添加到总偏移量中，并向返回的对象添加了两个属性，`scrollTop`和`scrollLeft`。其实用性可以在下面的示例中观察到，示例显示了`<div class="dim-outer">`在`<div class="dim-outer">`向下滚动了 79 像素时的偏移量。

```js
{top: 509, left: 597, scrollTop: 79, scrollLeft: 0}

```

![描述.offset()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_15.jpg)

**保持链式操作**

如果我们希望传递返回对象以便继续链接方法，我们仍然必须包含选项映射。为了保持这些选项的默认值不变，同时传递返回对象，我们可以简单地使用一个空映射。例如，`$('div.dim-outer').offset({}, returnObject)`获得与`$('div.dim-outer').offset()`相同的值，但将它们存储在`returnObject`中以供以后使用。

假设我们希望在更改`<div class="dim-outer">`的背景颜色为灰色（#cccccc）的同时获取其偏移和滚动值。代码将如下所示：

```js
var retObj = {};
$('div.dim-outer')
  .offset({}, retObj)
  .css('background','#ccc');
$(this).log(retObj);
```

我们首先声明一个返回对象的变量（retObj）。然后我们将`.offset`和`.css`方法链接到选择器上。最后，我们对`.offset()`返回的对象执行某些操作—在这种情况下，使用我们的日志插件记录结果。 `<div>`的背景颜色被更改，并且`.offset()`值如下所示被记录：

```js
{top: 117, left: 580, scrollTop: 0, scrollLeft: 0}

```

![描述.offset()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_10_16.jpg)

## `.position()`

| 获取匹配元素集中第一个元素相对于其最近的相对、绝对或固定定位的祖先的位置。

```js
.position()
.position(returnObject)

```

|

### 参数（第一个版本）

无。

### 参数（第二个版本）

+   `returnObject`：用于存储返回值的对象。当使用方法的第二个版本时，链不会中断，并且结果将被分配给此对象。

### 返回值（第一个版本）

包含`top`和`left`值的对象。

### 返回值（第二个版本）

jQuery 对象，用于链式操作。

### 描述

`.position`方法是以下`.offset()`变体的简写形式：

```js
.offset({
  margin: false, 
  scroll: false, 
  relativeTo: offsetParent
  }, 
  returnObject);
```

在这里，只确定元素的顶部和左侧位置—没有填充、边框或边距—与其最近的定位祖先相关。有关这些选项的更多详细信息，请参阅`.offset()`的描述。

对于`relativeTo`，`.position()`方法使用一个名为`offsetParent`的变量，该变量在 Dimensions 代码中设置。实际上，这段代码从元素的直接父级开始，然后在 DOM 中向上爬行，停止在第一个具有`relative, absolute`或`fixed`位置的元素处。然后，相对于最近的定位元素计算初始元素的偏移位置。

考虑以下 HTML：

```js
<div id="outer">
  <div id="middle" style="position: relative">
    <div id="inner">
      <p>Use .position() for this paragraph</p>
    </div>
  </div>
</div>
```

使用`$('p').position()`计算段落相对于`<div id="middle">`的顶部和左侧偏移，因为该`<div>`是最近的定位祖先（请注意其`style`属性）。

由于`.position()`不带任何参数（第二个版本中除了`returnValue`），它比`.offset()`灵活性要小得多。在大多数情况下，建议使用上述讨论的`.offset()`。


# 第十一章：表单插件

> 你最好找出来
> 
> 在你填写空白之前
> 
> —Devo,
> 
> "找出"

**Form** 插件是一个很好的例子，它使得一个困难、复杂的任务变得非常简单。它帮助我们以 AJAX 方式提交表单（即使表单包含文件上传字段），以及检查和操作表单字段的内容。

# AJAX 表单提交

这些方法有助于使用 AJAX 调用将表单内容提交到服务器。

## .ajaxSubmit()

| 发送表单内容到服务器而不刷新页面。

```js
.ajaxSubmit(success)
.ajaxSubmit(options)

```

|

### 参数 (第一个版本)

+   `success`：当服务器成功响应时执行的回调。

### 参数 (第二个版本)

+   `options`：配置提交的选项的映射。可以包含以下项目：

    +   `url` (可选)：表单将被提交到的 URL。默认值为表单的 `action` 属性值，如果没有找到则为当前页面的 URL。

    +   `type` (可选)：提交表单时要使用的方法（`GET` 或 `POST`）。默认值为表单的 `method` 属性值，如果没有找到则为 `GET`。

    +   `beforeSubmit` (可选)：在发送请求之前执行的回调。

    +   `dataType` (可选)：如何解释响应数据。可以是 `'xml', 'script'` 或 `'json'`。

    +   `target` (可选)：响应 HTML 将放置的元素。可以是选择器字符串、jQuery 对象或 DOM 元素引用。仅当省略 `dataType` 时有效。

    +   `success` (可选)：当服务器成功响应时执行的回调。

    +   `semantic` (可选)：是否强制 HTML 字段的严格排序。默认值为 `false`。

    +   `resetForm` (可选)：一个布尔值，指示在成功提交后将表单值重置为默认值。默认值为 `false`。

    +   `clearForm` (可选)：一个布尔值，指示是否在成功提交后清除表单值。默认值为 `false`。

### 返回值

用于链接目的的 jQuery 对象。

### 讨论

`.ajaxSubmit` 方法使用提供的 `url` 和 `type` 信息发起一个 AJAX 请求，同时使用表单中当前存在的数据。表单内容使用 `.formToArray` 方法进行编码，而文件上传等细节则在幕后处理。

如果使用 `beforeSubmit` 选项提供了回调函数，则在发送请求之前将触发该回调。这给我们一个机会来进行最后一分钟的验证或清理。如果验证程序检测到用户必须更正的错误，程序可以返回 `false` 阻止表单提交。回调函数通过由 `.formToArray()` 返回的表单数据、引用表单的 jQuery 对象以及提供给 `.ajaxSubmit()` 的选项对象来传递。有关此回调函数的示例，请查看后面关于 `.ajaxForm()` 的讨论中的示例。

当提供了`dataType`时，响应数据将相应地进行解释。所执行的处理与支持的数据类型的`$.ajax`函数相同。任何`script`响应都将被解释为 JavaScript 并在全局上下文中执行，而`json`响应将被解析为 JavaScript 对象或数组。指定`xml`数据类型的调用在接收到响应时不会引起任何解析。

如果未提供`dataType`，则可以使用`target`选项。目标引用的 DOM 元素将被填充为 AJAX 请求的响应，解释为纯 HTML。`dataType`和`target`选项是互斥的。

在由于`dataType`或`target`选项而执行了任何相关处理后，将执行`success`回调。此函数会提供响应数据以进行操作。有关解释和操作响应数据的方法，请参见第七章中的`$.ajax`函数讨论。

`semantic`标志以执行速度为代价强制使用严格的语义排序。有关更多信息，请参见稍后的`.formToArray()`讨论。

如果`resetForm`或`clearForm`设置为`true`，则在执行`success`回调（如果提供）之前会执行相应的操作。有关这些操作的更多信息，请参见稍后的`.clearForm`和`.resetForm`方法讨论。

如果要提交的表单包含文件上传字段，则文件数据将使用`multipart/form-data` MIME 类型正确上传。无需采取进一步操作。

请注意，`.ajaxSubmit`方法会立即执行。由于通常在单击提交按钮时发出 AJAX 请求，因此通常更方便使用`.ajaxForm`方法。但是，`.ajaxSubmit()`的直接操作可能是实现此插件与其他插件（如流行的**Validation**插件）之间交互的最简便方法。

## .ajaxForm()

| 准备一个表单以进行自动 AJAX 提交。

```js
.ajaxForm(options)
```

|

### 参数

+   `options`：配置提交的选项映射。可以包含以下项目（这些项目将原样传递给`.ajaxSubmit()`）：

    +   `url`（可选）：表单将提交到的 URL。默认值为表单的`action`属性值，如果找不到则为当前页面的 URL。

    +   `type`（可选）：提交表单时使用的方法（`GET`或`POST`）。默认值为表单的`method`属性值，如果找不到则为`GET`。

    +   `beforeSubmit`（可选）：在发送请求之前执行的回调。

    +   `dataType`（可选）：响应数据的解释方式。可以是`'xml'，'script'`或`'json'`。

    +   `target`（可选）：将响应 HTML 放置到其中的元素。可以是选择器字符串、jQuery 对象或 DOM 元素引用。仅当省略`dataType`时有效。

    +   `success`（可选）：服务器成功响应时执行的回调。

    +   `semantic`（可选）：是否强制使用严格的 HTML 字段顺序。默认值为 `false`。

    +   `resetForm`（可选）：一个布尔值，指示在成功提交后是否将表单值重置为默认值。默认值为 `false`。

    +   `clearForm`（可选）：一个布尔值，指示在成功提交后是否清除表单值。默认值为 `false`。

### 返回值

jQuery 对象，用于链式调用目的。

### 讨论

`.ajaxForm` 方法通过 AJAX 准备表单以供稍后提交。当提交表单时，AJAX 请求将使用提供的 `url` 和 `type` 信息以及当前在表单中的数据。表单内容使用 `.formToArray` 方法进行编码，并且诸如文件上传之类的复杂性在幕后处理。

与 `.ajaxSubmit` 方法不同，`.ajaxForm` 方法不会导致立即操作。相反，它将处理器绑定到表单的 `submit` 事件和表单按钮的 `click` 事件，从而导致表单内容作为 AJAX 请求发送。这消除了设置 AJAX 表单的一些工作。

此外，`.ajaxForm` 方法能够模拟标准表单提交的其他方面，而`.ajaxSubmit` 方法则不能。当 `.ajaxForm()` 执行时，包括被点击的提交按钮的名称和值在内的请求会被包含在其中。此外，当表单包含一个类型为 `image` 的 `<input>` 字段时，`.ajaxForm()` 可以捕获鼠标坐标并将它们与请求一起发送。

为了获得最佳效果，在使用图像输入时，**Dimensions** 插件也应该存在。Form 插件将自动检测 Dimensions 的存在，并在可能的情况下使用它。

`.ajaxForm` 方法可用于包含任何标准字段类型的表单：

```js
<form id="test-form" name="test-form" action="submit.php" method="post">
  <div class="form-row">
    <label for="city">City</label>
    <input type="text" id="city" name="city" size="20" />
  </div>
  <div class="form-row">
    <label for="state">State</label>
    <input type="text" id="state" name="state" size="5" value="MI" />
  </div>
  <div class="form-row">
    <label for="comment">Comments</label>
    <textarea id="comment" name="comment" rows="8" cols="30">
    </textarea>
  </div>

  <div class="form-row">
    <label for="sacks">Villages sacked</label>
    <select name="villages" id="villages">
      <option value="0">none</option>
      <option value="5" selected="selected">1-5</option>
      <option value="10">6-10</option>
      <option value="20">11-20</option>
      <option value="50">21-50</option>
      <option value="100">51-100</option>
      <option value="more">over 100</option>
    </select>
  </div>
  <div class="form-row multi">
    <span class="multi-label">Preferred tactic</span>
    <input type="radio" name="tactic" value="loot" id="loot" checked="checked" /><label for="loot">loot</label>
    <input type="radio" name="tactic" value="pillage" id="pillage" /><label for="pillage">pillage</label>
    <input type="radio" name="tactic" value="burn" id="burn" /><label for="burn">burn</label>
  </div>

  <div class="form-row multi">
    <span class="multi-label">Viking gear</span>
    <input type="checkbox" name="gear[helmet]" value="yes" id="helmet" checked="checked" /><label for="helmet">horned helmet</label>
    <input type="checkbox" name="gear[longboat]" value="yes" id="longboat" /><label for="pillage">longboat</label>
    <input type="checkbox" name="gear[goat]" value="yes" id="goat" checked="checked"/><label for="goat">magic goat</label>
  </div>

  <div class="form-row buttons">
    <input type="submit" id="submit" name="submit" value="Send" />
    <input type="button" id="more" name="more" value="More Options" />
  </div>
</form>
```

要准备表单进行提交，我们只需要在 DOM 就绪时调用 `.ajaxForm()` 一次。

```js
$(document).ready(function() {
  $('#test-form').ajaxForm({
     target: '.log'
  });
});
```

用户随后可以填写表单字段：

![Discussion.ajaxForm()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_11_01.jpg)

当稍后点击**发送**按钮时，服务器将接收到所有表单信息，而无需浏览器刷新。为了测试目的，我们可以使用 PHP 的 `print_r` 函数来显示已发布的表单内容：

```js
Array
(
    [city] => Morton
    [state] => IL
    [comment] => Eric the Red is my hero!
    [villages] => 50
    [tactic] => pillage
    [gear] => Array
        (
            [helmet] => yes
            [longboat] => yes
        )

    [submit] => Send
)
```

如果使用 `beforeSubmit` 选项提供回调函数，则在发送请求之前将触发回调。回调以由 `.formToArray()` 返回的表单数据、引用表单的 jQuery 对象和提供给 `.ajaxForm()` 的选项对象作为参数传递。此回调主要用于执行表单验证：

```js
$(document).ready(function() {
  $('#test-form').ajaxForm({
     target: '.ajax-form .log',
     beforeSubmit: function(formData, $form, options) {
       if ($form.find('#city').val() == '') {
         alert('You must enter a city.');
         return false;
       }
     }
  });
});
```

如果验证例程检测到用户必须更正的错误，则该例程可以返回 `false` 以防止提交表单。在我们的示例中，**城市**字段必须输入一个值，否则将显示警报并且不会提交。

当提供了`dataType`时，响应数据将相应地进行解释。执行的处理与`$.ajax`函数相同，适用于支持的数据类型。任何`script`响应都将被解释为 JavaScript 并在全局上下文中执行，而`json`响应将被解析为 JavaScript 对象或数组。指定`xml`数据类型的调用在接收到响应时不会引起任何解析。

如果未提供`dataType`，则可以使用`target`选项。由目标引用的 DOM 元素将填充为 AJAX 请求的响应，解释为纯 HTML。`dataType`和`target`选项是互斥的。

在由于`dataType`或`target`选项而执行了任何相关处理后，将执行`success`回调。此函数被给予响应数据以便执行操作。有关解释和操作响应数据的方法，请参见第七章中的`$.ajax`函数讨论。

`semantic`标志以执行速度为代价强制执行严格的语义顺序。有关更多信息，请参见稍后的`.formToArray()`讨论。

如果`resetForm`或`clearForm`设置为`true`，则会在执行`success`回调（如果提供）之前执行相应的操作。有关这些操作的更多信息，请参见稍后的`.clearForm`和`.resetForm`方法讨论。

如果要提交的表单包含文件上传字段，则文件数据将使用`multipart/form-data` MIME 类型正确上传。无需采取进一步的操作。

## .ajaxFormUnbind()

| 将表单恢复到其非 AJAX 状态。

```js
.ajaxFormUnbind()

```

|

### 参数

无。

### 返回值

用于链接目的的 jQuery 对象。

### 讨论

在表单上调用`.ajaxForm()`会将处理程序绑定到表单的`submit`事件以及其中任何按钮和图像输入的`click`事件上。如果以后表单不再使用 AJAX 提交，我们可以在同一表单上调用`.ajaxFormUnbind()`来移除这些处理程序，而不会中断可能已绑定到表单元素的任何其他处理程序。

# 检索表单值

这些方法允许脚本读取和转换 Web 表单中字段的值。

## .formToArray()

| 将表单中的值收集到对象数组中。

```js
.formToArray([semantic])
```

|

### 参数

+   `semantic`（可选）：是否强制执行字段的严格 HTML 排序。默认值为`false`。

### 返回值

一个对象数组，每个对象代表表单中的一个字段。

### 讨论

`.formToArray`方法获取表单的值，并将它们组织成适合传递给 jQuery AJAX 函数（如`$.ajax(), $.post()`和`.load()`）的数据结构。它可以处理具有任何标准字段类型的表单。

给定在`.ajaxFor()`讨论中说明的表单，`.formToArray`方法将返回一个 JavaScript 数组，其中包含表单的值：

```js
[
  {name: city, value: Morton},
  {name: state, value: IL},
  {name: comment, value: Eric the Red is my hero!},
  {name: villages, value: 50},
  {name: tactic, value: pillage},
  {name: gear[helmet], value: yes},
  {name: gear[longboat], value: yes}
]
```

数组中的每个对象都有`name`和`value`属性。未选中的复选框元素不会在数组中表示。

如果将`semantic`参数设置为`true`，则数组中列出的字段将保证按照它们在 HTML 源代码中的顺序排序。如果表单中不包含`<input>`类型为`image`的元素，则这已经是事实。除非需要，否则避免使用此选项，因为涉及的额外处理会减慢方法的速度。

## .formSerialize()

| 将表单中的值收集到序列化字符串中。

```js
.formSerialize([semantic])
```

|

### 参数

+   `semantic`（可选）：是否强制严格的 HTML 字段排序。默认值为`false`。

### 返回值

适合提交的表单字段的字符串表示。

### 讨论

`.formSerialize`方法获取表单的值，并将其转换为适合作为`GET`请求的查询字符串传递的字符串。它可以处理任何标准字段类型的表单。

考虑到在`.ajaxFor()`讨论中所示的表单，`.formSerialize`方法将返回表单值的字符串表示：

```js
city=Morton&state=IL&comment=Eric%20the%20Red%20is%20my%20hero!
  &villages=50&tactic=pillage&gear%5Bhelmet%5D=yes
  &gear%5Blongboat%5D=yes
```

每个字段在字符串中显示为键值对。未选中的复选框元素不会在字符串中表示。字符串根据需要进行 URL 编码。

如果将`semantic`参数设置为`true`，那么字符串中列出的字段将保证按照它们在 HTML 源代码中的顺序排序。如果表单中不包含`<input>`类型为`image`的元素，则这已经是事实。除非需要，否则避免使用此选项，因为涉及的额外处理会减慢方法的速度。

## .fieldSerialize()

| 将一组字段的值收集到序列化字符串中。

```js
.fieldSerialize([successful])
```

|

### 参数

+   `successful`（可选）：是否修剪包含的字段值以获取成功的字段。默认值为`true`。

### 返回值

适合提交的表单字段的字符串表示。

### 讨论

类似于之前的`.formSerialize`方法，`.fieldSerialize`方法获取表单的值，并将其转换为适合作为`GET`请求的查询字符串传递的字符串。然而，`.fieldSerialize()`作用于一个引用单个字段而不是整个表单的 jQuery 对象上。

它可以处理任何标准类型的字段，例如`<select>`菜单：

```js
<select name="villages" id="villages">
  <option value="0">none</option>
  <option value="5" selected="selected">1-5</option>
  <option value="10">6-10</option>
  <option value="20">11-20</option>
  <option value="50">21-50</option>
  <option value="100">51-100</option>
  <option value="more">over 100</option>
</select>
```

用户可以选择任何选项：

![Discussion.fieldSerialize()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_11_02.jpg)

值从当前选择的选项中获取，并且`.fieldSerialize`方法将返回此值的字符串表示：

```js
villages=50

```

每个给定的字段在字符串中显示为键值对。未选中的复选框元素不会在字符串中表示。字符串根据需要进行 URL 编码。

默认情况下，如果字段不成功，则不会在字符串中表示它们，如 HTML 表单的 W3C 规范中所定义：

[`www.w3.org/TR/html4/interact/forms.html#h-17.13.2`](http://www.w3.org/TR/html4/interact/forms.html#h-17.13.2)

成功的字段是在正常表单提交操作期间提交到服务器的字段。例如，当前选中的复选框是成功的；未选中的不是。很少会想要不成功字段的值，但如果需要，可以将`.fieldSerialize()`的`successful`参数设置为`false`。

在`.ajaxFor()`讨论中所示的表单中，当`successful`设置为`true`时，`.fieldSerializer()`仅包括选中的单选按钮和复选框：

```js
tactic=loot&gear%5Bhelmet%5D=yes&gear%5Bgoat%5D=yes

```

但是当`successful`设置为`false`时，`fieldSerializer()`也包括未选中的选项：

```js
tactic=loot&tactic=pillage&tactic=burn&gear%5Bhelmet%5D=yes
  &gear%5Blongboat%5D=yes&gear%5Bgoat%5D=yes
```

## `.fieldValue()`

| 将一组字段的值收集到一个字符串数组中。

```js
.fieldValue([successful])
$.fieldValue(element[, successful])

```

|

### 参数（第一个版本）

+   `successful`（可选）：是否将包含的字段值修剪为成功的值。默认值为`true`。

### 参数（第二个版本）

+   `element`：要检索其值的表单输入元素。

+   `successful`（可选）：是否将包含的字段值修剪为成功的值。默认值为`true`。

### 返回值

一个包含字段值的字符串数组。

### 讨论

`.fieldValue()`方法和`$.fieldValue()`函数都会获取表单的值，并将它们作为字符串数组返回。`.fieldValue()`方法作用于引用单个字段的 jQuery 对象，而`$.fieldValue()`函数在其第一个参数作为字段元素时执行相同的任务。

这些操作可以处理任何标准类型的字段，比如`<select>`菜单：

```js
<select name="villages" id="villages">
  <option value="0">none</option>
  <option value="5" selected="selected">1-5</option>
  <option value="10">6-10</option>
  <option value="20">11-20</option>
  <option value="50">21-50</option>
  <option value="100">51-100</option>
  <option value="more">over 100</option>
</select>
```

用户随后可以选择任何选项：

![Discussion.fieldValue()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_11_02.jpg)

该值从当前选定的选项中获取，并且`.fieldValue()`方法将以数组表示此值：

```js
[50]

```

给定的每个字段都以数组中的字符串形式出现。未选中的复选框元素不会在数组中表示。

默认情况下，如果字段在 W3C HTML 表单规范中定义的不成功，则不会在数组中表示这些字段：

[`www.w3.org/TR/html4/interact/forms.html#h-17.13.2`](http://www.w3.org/TR/html4/interact/forms.html#h-17.13.2)

成功的字段是在正常表单提交操作期间提交到服务器的字段。例如，当前选中的复选框是成功的；未选中的不是。很少会想要不成功字段的值，但如果需要，可以将`.fieldValue()`的`successful`参数设置为`false`。

在`.ajaxFor()`讨论中所示的表单中，当`successful`设置为`true`时，`.fieldValue()`仅包括选中的单选按钮和复选框：

```js
[loot, yes, yes]

```

但是当`successful`设置为`false`时，`.fieldValue()`也包括未选中的选项：

```js
[loot, pillage, burn, yes, yes, yes]

```

`.fieldValue` 方法始终返回一个数组；如果在被操作元素集中没有要报告的值，则结果数组将为空。相比之下，如果所询问的字段元素不成功，`$.fieldValue` 函数将返回 `null`。

# 表单操作

这些方法使脚本可以轻松地更改页面上表单的当前内容。

## .clearForm()

| 清除表单中的所有数据。

```js
.clearForm()
```

|

### 参数

无。

### 返回值

jQuery 对象，用于链式调用。

### 讨论

此方法查找匹配元素内的所有输入字段（<input>、`<select>` 和 `<textarea>` 元素），并清除它们的值。此方法通常应用于 `<form>` 元素，但也可以与任何字段容器（如 `<fieldset>`）一起使用。

所有字段都将清空，而不考虑其默认值：

![Discussion.clearForm()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_11_03.jpg)

根据其类型清除字段，如下所示：

+   文本字段和文本区域的值设置为空字符串。

+   选择元素设置为 -1，表示无选择。

+   复选框和单选按钮未选中。

+   其他字段，如提交按钮和图像输入，不受影响。

请注意，尽管隐藏字段具有值，但它们不受清除操作的影响。

## .clearFields()

| 清除输入字段中的所有数据。

```js
.clearFields()

```

|

### 参数

无。

### 返回值

jQuery 对象，用于链式调用。

### 讨论

此方法清除所有匹配的输入字段元素的值（<input>、`<select>` 和 `<textarea>` 元素）。

`.clearFields` 方法与 `.clearForm()` 仅在 `.clearForm()` 发送到匹配表单元素的 jQuery 对象时有所不同，而 `.clearFields()` 发送到匹配的字段本身的 jQuery 对象时有所不同：

![Discussion.clearFields()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_11_04.jpg)

根据其类型清除字段，如下所示：

+   文本字段和文本区域的值设置为空字符串。

+   选择元素设置为 -1，表示“无选择”。

+   复选框和单选按钮未选中。

+   其他字段，如提交按钮和图像输入，不受影响。

请注意，尽管隐藏字段具有值，但它们不受清除操作的影响。

## .resetForm()

| 将表单重置为其初始值。

```js
.resetForm()
```

|

### 参数

无。

### 返回值

jQuery 对象，用于链式调用。

### 讨论

此方法将表单中的所有字段返回到其初始值（在 HTML 源代码中定义的值）：

![Discussion.resetForm()about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_11_05.jpg)

使用 DOM API 的本地 `.reset` 方法完成此操作。因此，`.resetForm()` 只能应用于引用 `<form>` 元素的 jQuery 对象，而不像 `.clearForm()` 那样，后者可以应用于引用任何包含元素的 jQuery 对象。


# 附录 A. 在线资源

> 我不记得我曾经知道的东西
> 
> 有人现在帮帮我，让我离开
> 
> —Devo,
> 
> "Deep Sleep"

以下在线资源代表了进一步了解 jQuery、JavaScript 和 Web 开发的起点，超出了本书介绍的范围。网络上有太多优质信息源，本附录不可能涵盖所有。此外，虽然其他印刷出版物也可以提供有价值的信息，但它们在此未予记录。

# jQuery 文档

## jQuery Wiki

jquery.com 上的文档以 wiki 的形式呈现，这意味着内容可以由公众编辑。该网站包括完整的 jQuery API、教程、入门指南、插件存储库等等：

[`docs.jquery.com/`](http://docs.jquery.com/)

## jQuery API

在 jQuery.com 上，API 可以在两个位置找到——文档部分和分页 API 浏览器。

jQuery.com 的文档部分不仅包括 jQuery 方法，还包括所有 jQuery 选择器表达式：

[`docs.jquery.com/Selectors`](http://docs.jquery.com/Selectors)

[`docs.jquery.com/`](http://docs.jquery.com/)

[`jquery.com/api`](http://jquery.com/api)

## jQuery API Browser

*Jörn Zaeferrer* 制作了一个方便的 jQuery API 树形浏览器，具有搜索功能和按字母顺序或类别排序：

[`jquery.bassistance.de/api-browser/`](http://jquery.bassistance.de/api-browser/)

## Visual jQuery

这款由*Yehuda Katz*设计的 API 浏览器既美观又方便。它还提供了对许多 jQuery 插件的快速查看方法：

[`www.visualjquery.com/`](http://www.visualjquery.com/)

## Web Developer Blog

*Sam Collet* 在他的博客上保存了一个 jQuery 文档的主列表，包括可下载版本和备忘单，以及其他博客上经过验证的 JavaScript 资源：

[`webdevel.blogspot.com/2007/01/jquery-documentation.html`](http://webdevel.blogspot.com/2007/01/jquery-documentation.html)

# JavaScript Reference

## Mozilla Developer Center

该网站提供了全面的 JavaScript 参考资料，JavaScript 编程指南，有用工具的链接等等：

[`developer.mozilla.org/en/docs/JavaScript/`](http://developer.mozilla.org/en/docs/JavaScript/)

## Dev.Opera

虽然主要关注自己的浏览器平台，但 *Opera* 的网站也包括一些有关 JavaScript 的有用文章：

[`dev.opera.com/articles/`](http://dev.opera.com/articles/)

## Quirksmode

*Peter-Paul Koch* 的 Quirksmode 网站是理解浏览器实现各种 JavaScript 函数以及许多 CSS 属性差异的绝佳资源：

[`www.quirksmode.org/`](http://www.quirksmode.org/)

## JavaScript Toolbox

*Matt Kruse's JavaScript Toolbox* 提供了大量自制的 JavaScript 库，以及有关 JavaScript 最佳实践的可靠建议和其他地方验证过的 JavaScript 资源集合：

[`www.javascripttoolbox.com/`](http://www.javascripttoolbox.com/)

# JavaScript Code Compressors

## Packer

This JavaScript compressor/obfuscator by *Dean Edwards* is used to compress the jQuery source code. It's available as a web-based tool or as a free download. The resulting code is very efficient in file size, at a cost of a small increase in execution time:

[`dean.edwards.name/packer/`](http://dean.edwards.name/packer/)

[`dean.edwards.name/download/#packer`](http://dean.edwards.name/download/#packer)

## JSMin

Created by *Douglas Crockford, JSMin* is a filter that removes comments and unnecessary white space from JavaScript files. It typically reduces file size by half, resulting in faster downloads:

[`www.crockford.com/javascript/jsmin.html`](http://www.crockford.com/javascript/jsmin.html)

## Pretty Printer

This tool *prettifies* JavaScript that has been compressed, restoring line breaks and indentation where possible. It provides a number of options for tailoring the results:

[`www.prettyprinter.de/`](http://www.prettyprinter.de/)

# (X)HTML Reference

## W3C Hypertext Markup Language Home Page

The *World Wide Web Consortium (W3C)* sets the standard for (X)HTML, and the HTML home page is a great launching point for its specifications and guidelines:

[`www.w3.org/MarkUp/`](http://www.w3.org/MarkUp/)

# CSS Reference

## W3C Cascading Style Sheets Home Page

The W3C's CSS home page provides links to tutorials, specifications, test suites, and other resources:

[`www.w3.org/Style/CSS/`](http://www.w3.org/Style/CSS/)

## Mezzoblue CSS Cribsheet

*Dave Shea* provides this helpful *CSS cribsheet* in an attempt to make the design process easier, and provide a quick reference to check when you run into trouble:

[`mezzoblue.com/css/cribsheet/`](http://mezzoblue.com/css/cribsheet/)

## Position Is Everything

This site includes a catalog of CSS browser bugs along with explanations of how to overcome them:

[`www.positioniseverything.net/`](http://www.positioniseverything.net/)

# XPath Reference

## W3C XML Path Language Version 1.0 Specification

Although jQuery's XPath support is limited, theW3C's *XPath Specification* may still be useful for those wanting to learn more about the variety of possible XPath selectors:

[`www.w3.org/TR/xpath`](http://www.w3.org/TR/xpath)

## TopXML XPath Reference

The *TopXML* site provides helpful charts of axes, node tests, and functions for those wanting to learn more about XPath:

[`www.topxml.com/xsl/XPathRef.asp`](http://www.topxml.com/xsl/XPathRef.asp)

## MSDN XPath Reference

The *Microsoft Developer Network* website has information on XPath syntax and functions:

[`msdn2.microsoft.com/en-us/library/ms256115.aspx`](http://msdn2.microsoft.com/en-us/library/ms256115.aspx)

# Useful Blogs

## The jQuery Blog

*John Resig, et al.*, the official jQuery blog posts announcements about new versions and other initiatives among the project team, as well as occasional tutorials and editorial pieces.

[`jquery.com/blog/`](http://jquery.com/blog/)

## 学习 jQuery

*Karl Swedberg、Jonathan Chaffer、Brandon Aaron 等* 运行着一个提供 jQuery 教程、示例和公告的博客：

[`www.learningjquery.com/`](http://www.learningjquery.com/)

## Jack Slocum 的博客

*Jack Slocum*，受欢迎的 *EXT 套件* JavaScript 组件的作者，写了关于他的工作和 JavaScript 编程的博客：

[`www.jackslocum.com/blog/`](http://www.jackslocum.com/blog/)

## 具有想象力的 Web 标准

*Dustin Diaz* 的博客专注于网页设计和开发的文章，重点放在 JavaScript 上：

[`www.dustindiaz.com/`](http://www.dustindiaz.com/)

## Snook

*Jonathan Snook* 的一般编程/网页开发博客：

[`snook.ca/`](http://snook.ca/)

## 等我来

*Christian Heilmann* 的三个网站提供了与 JavaScript 和网页开发相关的博客文章、示例代码和长篇文章：

[`www.wait-till-i.com/`](http://www.wait-till-i.com/)

[`www.onlinetools.org/`](http://www.onlinetools.org/)

[`icant.co.uk/`](http://icant.co.uk/)

## DOM 脚本化

*Jeremy Keith* 的博客继续了广受欢迎的 DOM 脚本书留下的内容——一个非常好的关于非侵入式 JavaScript 的资源：

[`domscripting.com/blog/`](http://domscripting.com/blog/)

## 随着时间的流逝

*Stuart Langridge* 试验了浏览器 DOM 的高级用法：

[`www.kryogenix.org/code/browser/`](http://www.kryogenix.org/code/browser/)

## 一个不同寻常的列表

*A List Apart* 探讨了网页内容的设计、开发和含义，特别关注网页标准和最佳实践：

[`www.alistapart.com/`](http://www.alistapart.com/)

## Particletree

*Chris Campbell、Kevin Hale 和 Ryan Campbell* 开设了一个博客，提供了许多网页开发方面的有价值信息：

[`particletree.com/`](http://particletree.com/)

## JavaScript 的奇怪禅意

*Scott Andrew LePera* 的博客关于 JavaScript 的怪癖、注意事项、奇怪的黑客技巧、奇闻异事和积累的智慧。专注于 Web 应用程序开发的实际用途：

[`jszen.blogspot.com/`](http://jszen.blogspot.com/)

# 使用 jQuery 的 Web 开发框架

随着开源项目的开发者意识到 jQuery，许多人将 JavaScript 库纳入自己的系统中。以下是一些早期采用者的简要列表：

+   Drupal：[`drupal.org/`](http://drupal.org/)

+   Joomla 扩展：[`extensions.joomla.org/`](http://extensions.joomla.org/)

+   Pommo：[`pommo.org/`](http://pommo.org/)

+   SPIP：[`www.spip.net/`](http://www.spip.net/)

+   Trac：[`trac.edgewall.org/`](http://trac.edgewall.org/)

要获取更完整的列表，请访问 *使用 jQuery 的网站* 页面：

[`docs.jquery.com/Sites_Using_jQuery`](http://docs.jquery.com/Sites_Using_jQuery)


# 附录 B. 开发工具

> 当问题来临时
> 
> 你必须鞭打它
> 
> —Devo，
> 
> "鞭打它"

文档可以帮助解决我们 JavaScript 应用程序的问题，但没有好的软件开发工具来替代。幸运的是，有许多可用于检查和调试 JavaScript 代码的软件包，其中大多数都可以免费获取。

# Firefox 工具

Mozilla Firefox 是大多数 Web 开发人员首选的浏览器，因此拥有一些最全面和备受尊敬的开发工具。

## Firebug

用于 jQuery 开发的*Firebug*扩展不可或缺：

[`www.getfirebug.com/`](http://www.getfirebug.com/)

Firebug 的一些功能包括：

+   一个出色的 DOM 检查器，用于查找文档片段的名称和选择器

+   CSS 操作工具，用于查找页面外观原因并进行更改

+   一个交互式 JavaScript 控制台

+   一个 JavaScript 调试器，可以监视变量和跟踪代码执行

## Web 开发者工具栏

这不仅在 DOM 检查方面与 Firebug 重叠，还包含用于常见任务的工具，如 cookie 操作，表单检查和页面调整。您还可以使用此工具栏快速轻松地为站点禁用 JavaScript，以确保在用户的浏览器功能较差时功能优雅降级：

[`chrispederick.com/work/web-developer/`](http://chrispederick.com/work/web-developer/)

## Venkman

*Venkman*是 Mozilla 项目的官方 JavaScript 调试器。它提供了一个类似于用于调试其他语言编写的程序的 GDB 系统的故障排除环境。

[`www.mozilla.org/projects/venkman/`](http://www.mozilla.org/projects/venkman/)

## 正则表达式测试器

用于在 JavaScript 中匹配字符串的正则表达式可能难以编写。这个 Firefox 扩展允许使用界面轻松地尝试正则表达式以输入搜索文本：

[`sebastianzartner.ath.cx/new/downloads/RExT/`](http://sebastianzartner.ath.cx/new/downloads/RExT/)

# Internet Explorer 的工具

网站在 IE 中的行为通常与其他 Web 浏览器不同，因此对于该平台具有调试工具是重要的。

## 微软 Internet Explorer 开发者工具栏

*开发者*工具栏主要提供了网页的 DOM 树视图。可以通过视觉定位元素，并通过新的 CSS 规则即时修改。它还提供其他杂项开发辅助工具，如用于测量页面元素的标尺：

[`www.microsoft.com/downloads/details.aspx?FamilyID=e59c3964-672d-4511-bb3e-2d5e1db91038`](http://www.microsoft.com/downloads/details.aspx?FamilyID=e59c3964-672d-4511-bb3e-2d5e1db91038)

## 微软 Visual Web Developer

*微软的 Visual Studio*软件包可用于检查和调试 JavaScript 代码：

[`msdn.microsoft.com/vstudio/express/vwd/`](http://msdn.microsoft.com/vstudio/express/vwd/)

要在免费版本（Visual Web Developer Express）中交互式运行调试器，请按照此处概述的过程进行操作：

[`www.berniecode.com/blog/2007/03/08/how-to-debug-javascript-with-visual-web-developer-express/`](http://www.berniecode.com/blog/2007/03/08/how-to-debug-javascript-with-visual-web-developer-express/)

## DebugBar

*DebugBar* 提供了 DOM 检查器以及用于调试的 JavaScript 控制台：

[`www.debugbar.com/`](http://www.debugbar.com/)

## Drip

JavaScript 代码中的内存泄漏可能会导致 Internet Explorer 的性能和稳定性问题。*Drip* 有助于检测和隔离这些内存问题：

[`Sourceforge.net/projects/ieleak/`](http://Sourceforge.net/projects/ieleak/)

# Safari 的工具

Safari 作为开发平台仍处于起步阶段，但仍然可以为代码在此浏览器中的行为与其他地方不同的情况提供可用的工具。

## Web Inspector

Safari 的 Nightly 构建版本包括检查单个页面元素并收集有关每个元素应用的 CSS 规则的信息的功能。

[`trac.webkit.org/projects/webkit/wiki/Web%20Inspector`](http://trac.webkit.org/projects/webkit/wiki/Web%20Inspector)

## Drosera

*Drosera* 是 Safari 和其他基于 WebKit 的应用程序的 JavaScript 调试器。它启用了断点、变量监视和交互式控制台。

# 其他工具

## Firebug Lite

虽然 Firebug 扩展本身仅限于 Firefox web 浏览器，但一些功能可以通过在网页上包含 *Firebug Lite* 脚本来复制。此包模拟了 Firebug 控制台，包括允许调用 `console.log()` 的功能，通常会导致其他浏览器中抛出 JavaScript 错误：

[`www.getfirebug.com/lite.html`](http://www.getfirebug.com/lite.html)

**TextMate jQuery Bundle**

这个为流行的 Mac OS X 文本编辑器 *TextMate* 提供了语法高亮显示 jQuery 方法和选择器、方法代码完成以及代码内快速 API 参考。该包还与 *E* 文本编辑器兼容（适用于 Windows）：

[`www.learningjquery.com/2006/09/textmate-bundle-for-jquery`](http://www.learningjquery.com/2006/09/textmate-bundle-for-jquery)

## Charles

在开发 AJAX 密集型应用程序时，查看浏览器和服务器之间发送的确切数据可能很有用。*Charles* web 调试代理显示两个点之间的所有 HTTP 流量，包括正常的 web 请求、HTTPS 流量、Flash 远程和 AJAX 响应：

[`www.xk72.com/charles/`](http://www.xk72.com/charles/)
