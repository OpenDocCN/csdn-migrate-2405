# jQuery 参考指南（二）

> 原文：[`zh.annas-archive.org/md5/0AC785FD3E3AB038A029EF6BA3FEE889`](https://zh.annas-archive.org/md5/0AC785FD3E3AB038A029EF6BA3FEE889)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章： DOM 操作方法

> 洗手不干拯救灾厄
> 
> 他让自己处于一种改变的状态。
> 
> -Devo，
> 
> “机械狂热男孩”

本章中的所有方法都以某种方式操作 DOM。其中一些只是改变元素的某个属性，而另一些则设置元素的样式属性。还有一些修改了整个元素（或元素组）本身-插入、复制、删除等等。

这些方法中的一些，如`.attr()`、`.html()`和`.val()`，也充当**获取器**，从 DOM 元素中检索信息以供以后使用。

# 通用属性

## .attr(attribute)

| 获取匹配元素集合中第一个元素的属性值。

```js
.attr(attribute)

```

|

### 参数

+   属性：要获取的属性名称

### 返回值

包含属性值的字符串。

### 描述

我们可以利用原生 JavaScript 函数`getAttribute`非常容易地获取元素的任何属性，而无需使用 jQuery。此外，这些属性中的大多数都可以通过 JavaScript 作为 DOM 节点属性使用。其中一些更常见的属性是：

+   `className`

+   `标签名`

+   `id`

+   `href`

+   `title`

+   `rel`

+   `src`

让我们考虑以下链接：

```js
<a id="myid" href="/archives/jquery-links.htm" title="A few jQuery links from long ago">old jQuery links</a>

```

使用 jQuery 的`.attr`方法获取元素的属性有两个主要优点：

1.  **便利性**：它可以链接到 jQuery 对象。

1.  **跨浏览器一致性**：`.attr`方法始终获取实际的属性文本，而不管使用哪个浏览器。另一方面，当使用`getAttribute()`获取诸如`href、src`和`cite`等属性时，一些浏览器（如正确地）获取属性文本，而另一些浏览器获取绝对 URL，而不管属性是绝对 URL 还是相对 URL。

为了使用`getAttribute()`或元素的任何属性替换`.attr()`，我们需要确保我们使用的是 DOM 节点，而不是 jQuery 对象。要将 jQuery 对象中表示的第一个元素转换为 DOM 节点，我们可以使用`[0]`或`.get(0)`。

以下所有用`getAttribute('title')`获取其`title`属性：

1.  `document.getElementById('myid').getAttribute('title')`

1.  `$('#myid').get(0).getAttribute('title')`

1.  `$('#myid')[0].getAttribute('title')`

通过任何这些选项，我们都可以用`.title`替换`.getAttribute('title')`。

## .attr()

| 设置匹配元素集合中一个或多个属性。

```js
.attr(attribute, value)
.attr(map)
.attr(attribute, function)

```

|

### 参数（第一个版本）

+   属性：要设置的属性名称

+   值：要为属性设置的值

### 参数（第二个版本）

+   映射：要设置的属性-值对映射

### 参数（第三个版本）

+   属性：要设置的属性名称

+   函数：返回要设置的值的函数

### 返回值

jQuery 对象，用于链接目的。

### 描述

`.attr`方法是一种方便而强大的设置属性值的方式，尤其是在设置多个属性或函数返回的值时。我们来考虑以下图片：

```js
<img id="greatphoto" src="img/brush-seller.jpg" alt="brush seller" />

```

### .attr(attribute, value)

我们通过在`.attr`方法的括号内放置`'alt'`后跟逗号和新值来更改`alt`属性：

```js
$('#greatphoto').attr('alt', 'Beijing Brush Seller');

```

我们可以通过相同的方式*添加*一个属性：

```js
$('#greatphoto').attr('title', 'Beijing Brush Seller photo by Kelly Clark');

```

### `.attr({map})`

要同时更改`alt`属性并添加`title`属性，我们可以将名字和值的两套都一次传递到方法中，使用映射（JavaScript 对象语法）。我们用冒号将每个属性连接到其值，并用逗号分隔每对：

```js
$('#greatphoto').attr({alt:'Beijing Brush Seller', title: 'Beijing Brush Seller photo by Kelly Clark'});

```

在设置多个属性时，围绕属性名称的引号是可选的。

### `.attr(属性, 函数)`

通过使用函数设置属性，我们可以将新值与现有值连接起来：

```js
$('#greatphoto').attr({alt: function() {return 'Beijing ' + this.alt}, title: function() {return 'Beijing ' + this.alt + ' photo by Kelly Clark'}});

```

当我们将属性应用于多个元素时，函数的这种用法甚至更有用。

## `.removeAttr()`

| 从匹配元素集中的每个元素中删除一个属性。

```js
.removeAttr(attribute)

```

|

### 参数

+   属性：属性

### 返回值

用于链式调用的 jQuery 对象。

### 描述

`.removeAttr`方法使用 JavaScript 的`removeAttribute`函数，但它具有可以链接到 jQuery 选择器表达式的优势。

# 样式属性

## `.css(属性)`

| 获取匹配元素集中第一个元素的样式属性值。

```js
.css(property)

```

|

### 参数

+   属性：CSS 属性

### 返回值

包含 CSS 属性值的字符串。

### 描述

`.css`方法是一种方便的方法，可以从第一个匹配的元素中获取样式属性，尤其是考虑到不同浏览器对某些属性使用不同术语的情况。例如，Internet Explorer 的 DOM 实现将`float`属性称为`styleFloat`，而基于 Mozilla 的浏览器将其称为`cssFloat`。`.css`方法考虑到这些差异，无论我们使用哪个术语，都会产生相同的结果。例如，一个向左浮动的元素将为以下三行中的每行返回字符串`left`：

1.  `$('div.left').css('float')`;

1.  `$('div.left').css('cssFloat')`;

1.  `$('div.left').css('styleFloat')`;

同样，jQuery 可以同样解释多词属性的 CSS 和 DOM 格式。例如，jQuery 能正确理解和返回`.css('background-color')`和`.css('backgroundColor')`的正确值。

## `.css()`

| 设置匹配元素集的一个或多个 CSS 属性。

```js
.css(property, value)
.css(map)
.css(property, function)

```

|

### 参数（第一个版本）

+   属性：CSS 属性名称

+   值：要设置的值

### 参数（第二个版本）

+   map：要设置的属性值对的映射

### 参数（第三个版本）

+   属性：CSS 属性名称

+   函数：返回要设置的值

### 返回值

用于链式调用的 jQuery 对象。

### 描述

与`.attr`方法一样，`.css`方法使得设置元素属性变得快速而简便。这个方法可以接受以逗号分隔的键值对或以冒号分隔的键值对的映射（JavaScript 对象表示法）。

此外，jQuery 可以同样解释多词属性的 CSS 和 DOM 格式。例如，jQuery 理解并返回了 `.css({'background-color':'#ffe', 'border-left': '5px solid #ccc'})` 和 `.css({backgroundColor:'#ffe', borderLeft: '5px solid #ccc'})` 两者的正确值。请注意，使用 DOM 标记，属性名称周围的引号是可选的，但使用 CSS 标记时，由于名称中的连字符，它们是必需的。

由于 `.css` 方法在内部调用 `.attr` 方法，我们也可以将函数作为属性值传递：

```js
$('div.example').css('width', function(index) {
  return index * 50;
});
```

此示例将匹配元素的宽度设置为逐渐增大的值。

## .height()

| 获取匹配元素集中第一个元素的当前计算高度。

```js
.height()

```

|

### 参数

无。

### 返回值

元素的高度，以像素为单位。

### 描述

`.css('height')` 和 `.height()` 之间的区别在于后者返回无单位的像素值（例如，`400`），而前者返回单位完整的值（例如，`400px`）。当需要在数学计算中使用元素的高度时，推荐使用 `.height` 方法。

## .height(value)

| 设置匹配元素集中每个元素的 CSS 高度。

```js
.height(value)

```

|

### 参数

+   value: 表示像素数量的整数，或附加了可选计量单位的整数

### 返回值

用于链接目的的 jQuery 对象。

### 描述

与 `.css('height','value')` 不同，使用 `.height('value')`，值可以是字符串（数字和单位）或数字。如果只提供了数字作为值，则 jQuery 假定为像素单位。

## .width()

| 获取匹配元素集中第一个元素的当前计算宽度。

```js
.width()

```

|

### 参数

无。

### 返回值

元素的宽度，以像素为单位。

### 描述

`.css(width)` 和 `.width()` 之间的区别在于后者返回无单位的像素值（例如，`400`），而前者返回单位完整的值（例如，`400px`）。当需要在数学计算中使用元素的宽度时，推荐使用 `.width` 方法。

## .width(value)

| 设置匹配元素集中每个元素的 CSS 宽度。

```js
.width(value)

```

|

### 参数

+   value: 表示像素数量的整数，或附加了可选计量单位的整数

### 返回值

用于链接目的的 jQuery 对象。

### 描述

与 `.css('width','value')` 不同，使用 `.width('value')`，值可以是字符串（数字和单位）或数字。如果只提供了数字作为值，则 jQuery 假定为像素单位。

# 类属性

## .addClass()

| 向匹配元素集中的每个元素添加一个或多个类。

```js
.addClass(class)

```

|

### 参数

+   class: 要添加到每个匹配元素的 class 属性的一个或多个类名

### 返回值

用于链接目的的 jQuery 对象。

### 描述

需要注意的是，此方法不会 *替换* 类；它只是 *添加* 类。

可以一次添加多个类，以空格分隔，到匹配元素集，例如：`$('p').addClass('myclass yourclass')`。

这种方法通常与`.removeClass()`一起使用，以将元素的类从一个类切换到另一个类，如下所示：

```js
$('p').removeClass('myclass noclass').addClass('yourclass')

```

在这里，所有段落中都将删除`myclass`和`noclass`类，而添加`yourclass`类。

## .removeClass()

| 从匹配元素集的每个元素中删除一个或所有类。

```js
.removeClass([class])

```

|

### 参数

+   类（可选）：要从每个匹配元素的类属性中删除的类名

### 返回值

用于链式操作的 jQuery 对象。

### 描述

如果在参数中包含类名，则只从匹配元素集中删除该类。如果在参数中未指定类名，则将删除所有类。

可以一次从匹配元素集中删除多个类，例如：`$('p').removeClass('myclass yourclass')`。

这种方法通常与`.addClass()`一起使用，以将元素的类从一个类切换到另一个类，例如：

```js
$('p').removeClass('myclass').addClass('yourclass')

```

在这里，所有段落都将删除`myclass`类，而添加`yourclass`类。

要用另一个类替换所有现有类，可以使用`.attr('class','new-class')`。

## .toggleClass()

| 如果类存在，`.toggleClass()` 将删除它从匹配元素集中的每个元素；如果不存在，它将添加该类。

```js
.toggleClass(class)

```

|

### 参数

+   class: 在匹配集合中的每个元素的类属性中要切换的类名

### 返回值

用于链式操作的 jQuery 对象。

### 描述

此方法以其参数作为一个或多个类名。如果匹配集中的元素已经具有该类，则删除它；如果元素没有该类，则添加它。例如，我们可以将`.toggleClass()`应用到一个简单的`<div>`上：

```js
<div class="tumble">Some text.</div>

```

第一次应用`$('div.tumble').toggleClass('bounce')`后，我们得到以下结果：

```js
<div class="tumble bounce">Some text.</div>

```

第二次应用`$('div.tumble').toggleClass('bounce')`后，`<div>`类返回到单个的`tumble`值：

```js
<div class="tumble">Some text.</div>

```

对同一个`<div>`应用`.toggleClass('bounce spin')`可交替呈现`<div class="tumble bounce spin'>`和`<div class="tumble'>`。

# DOM 替换

## .html()

| 获取匹配元素集中第一个元素的 HTML 内容。

```js
.html()

```

|

### 参数

无。

### 返回值

包含元素的 HTML 表示的字符串。

### 描述

此方法不适用于 XML 文档。

在 HTML 文档中，我们可以使用`.html`方法来获取任何元素的内容。如果我们的选择器表达式匹配多个元素，则只返回第一个元素的 HTML 内容。考虑以下代码：

```js
$('div.demo-container').html();

```

要检索以下 `<div>` 标记的内容，它必须是文档中的第一个标记：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div>
</div>
```

结果如下所示：

```js
<div class="demo-box">Demonstration Box</div>

```

## .html(HTML)

| 设置匹配元素集中每个元素的 HTML 内容。

```js
.html(HTML)

```

|

### 参数

+   HTML: 要设置为每个匹配元素的内容的 HTML 字符串

### 返回值

jQuery 对象，用于链接目的。

### 描述

`.html(HTML)` 在 XML 文档中不可用。

当我们使用 `.html(HTML)` 来设置元素内容时，任何已在这些元素中的内容都会完全被新内容替换。考虑以下 HTML：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div>
</div>
```

我们可以这样设置 `<div class="demo-container">` 的 HTML 内容：

```js
$('div.demo-container'>.html('<p>All new content. <em>You bet!</em>');

```

那行代码将会替换 `<div class="demo-container">` 中的所有内容：

```js
<div class="demo-container"><p>All new content. <em>You bet!</em></div>

```

## `.text()`

| 获取匹配元素集合中每个元素及其后代的组合文本内容。

```js
.text()

```

|

### 参数

无。

### 返回值

包含匹配元素的组合文本内容的字符串。

### 描述

与 `.html` 方法不同，`.text` 方法可用于 XML 和 HTML 文档中。`.text` 方法的结果是一个包含所有匹配元素的组合文本的字符串。考虑以下 HTML：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div>
  <ul>
    <li>list item 1</li>
    <li>list <strong>item</strong> 2</li>
  </ul>
</div>
```

代码 `$('div.demo-container').text()` 将产生以下结果：

```js
Demonstration Boxlist item 1list item 2

```

## .text(text)

| 设置匹配元素集合中每个元素的内容为指定文本。

```js
.text(text)

```

|

### 参数

+   text: 要设置为每个匹配元素内容的文本字符串

### 返回值

jQuery 对象，用于链接目的。

### 描述

与 `.html(html)` 方法不同，`.text(text)` 方法可用于 XML 和 HTML 文档中。

我们需要注意，此方法将`<`和`>`分别替换为`&lt`;和`&gt`;。考虑以下 HTML：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div>
  <ul>
    <li>list item 1</li>
    <li>list <strong>item</strong> 2</li>
  </ul>
</div>
```

代码 `$('div.demo-container').text('<p>This is a test.</p>')` 将产生以下 HTML：

```js
<div class="demo-container">&lt;p&gt;This is a test.&lt;/p&gt;</div>

```

在渲染的页面上，它会呈现为标签被暴露的样子，就像这样：

```js
<p>This is a test</p>

```

## `.val()`

| 获取匹配元素集合中第一个元素的当前值。

```js
.val()

```

|

### 参数

无。

### 返回值

包含元素值的字符串。

### 描述

`.val` 方法主要用于获取表单元素的值。

## .val(value)

| 设置匹配元素集合中每个元素的值。

```js
.val(value)

```

|

### 参数

+   value: 要设置为每个匹配元素值属性的文本字符串

### 返回值

jQuery 对象，用于链接目的。

### 描述

这个方法通常用于设置表单字段的值。

# DOM 插入，内部

## .prepend()

| 在匹配元素集合中的每个元素的开头插入指定参数指定的内容。

```js
.prepend(content)

```

|

### 参数

+   content: 要在匹配元素集合中的每个元素的开头插入的元素、HTML 字符串或 jQuery 对象

### 返回值

jQuery 对象，用于链接目的。

### 描述

`.prepend` 和 `.prependTo` 方法执行相同的任务。唯一的区别在于语法，具体来说是在内容和目标的放置上。使用 `.prepend()` 方法，方法之前的选择器表达式是插入内容的容器。另一方面，`.prependTo()` 的语法则相反，内容出现在方法之前，可以是选择器表达式，也可以是即时创建的标记，在目标容器中插入。

考虑以下 HTML：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div> 
</div>
```

两个 `<div>`，加上一点 CSS，呈现在页面右侧，如下所示：

![关于.prepend()的描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_01.jpg)

我们可以将 HTML 结构插入到 `<div class="demo-box">` 的开头，如下所示：

```js
$('div.demo-box').prepend('<div class="insertion">This text was <strong>inserted</strong></div>');

```

新的 `<div>` 和 `<strong>` 元素以及文本节点是动态创建的并添加到 DOM 中。结果是一个新的 `<div>` 位于 **演示框** 文本之前：

![关于.prepend()的描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_02.jpg)

已经存在于页面上的元素（或元素数组）也可以移动到 `<div class="demo-box">` 的开头。例如，以下代码通过使用 jQuery 对象将文档的第一个段落移动到目标位置：

```js
$('div.demo-box').prepend( $('p:eq(0)') );

```

## `.prependTo()`

| 将匹配元素集合中的每个元素插入到目标的开头。

```js
.prependTo(target)

```

|

### 参数

+   target: 选择器、元素、HTML 字符串或 jQuery 对象；匹配的元素集将插入到由此参数指定的元素的开头

### 返回值

用于链式操作的 jQuery 对象。

### 描述

`.prepend` 和 `.prependTo` 方法执行相同的任务。唯一的区别在于语法 - 具体来说，在内容和目标的放置方面。使用 `.prepend()`，在方法之前的选择器表达式是要插入内容的容器。另一方面，使用 `.prependTo()`，*内容* 在方法之前，可以是选择器表达式，也可以是动态创建的标记，它被插入到目标容器中。

考虑以下 HTML：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div> 
</div>
```

两个 `<div>`，加上一点 CSS，呈现在页面右侧，如下所示：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_03.jpg)

使用 `.prependTo()`，我们可以将 HTML 结构插入到 `<div class="demo-box">` 的开头，如下所示：

```js
$('<div class="insertion">This text was <strong>inserted</strong> </div>').prependTo('div.demo-box');

```

新的 `<div>` 和 `<strong>` 元素，以及文本节点，是动态创建的并添加到 DOM 中。结果是一个新的 `<div>` 位于 **演示框** 文本之前：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_04.jpg)

已经存在于页面上的元素（或元素数组）也可以移动到 `<div class="demo-box">` 的开头。例如，以下代码通过使用选择器表达式将文档的第一个段落移动到目标位置：

```js
$('p:eq(0)').prependTo('div.demo-box');

```

## `.append()`

| 将参数指定的内容插入到匹配元素集合中每个元素的末尾。

```js
.append(content)

```

|

### 参数

+   content: 要插入到匹配元素集合中每个元素末尾的选择器、元素、HTML 字符串或 jQuery 对象。

### 返回值

用于链式操作的 jQuery 对象。

### 描述

`.append` 和 `.appendTo` 方法执行相同的任务。唯一的区别在于语法——具体来说，是内容和目标的放置位置。使用 `.append()`，方法前面的选择器表达式是要插入内容的容器。另一方面，使用 `.appendTo()`，*内容*在方法之前，可以是选择器表达式，也可以是即时创建的标记，然后插入到目标容器中。

考虑以下的 HTML：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div> 
</div>
```

两个 `<div>`，通过一点 CSS，呈现在页面的右侧如下：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_05.jpg)

我们可以像这样将 HTML 结构插入到 `<div class="demo-box">` 的末尾：

```js
$('div.demo-box').append('<div class="insertion">This text was <strong>inserted</strong></div>');

```

新的 `<div>` 和 `<strong>` 元素，以及文本节点，是即时创建的并添加到 DOM 中。结果是一个新的 `<div>` 定位在 **演示框** 文本之后：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_06.jpg)

页面上已经存在的元素（或元素数组）也可以移动到 `<div class="demo-box">` 的末尾。例如，下面的代码通过使用 jQuery 对象来移动文档的第一个段落：

```js
$('div.demo-box').append( $('p:eq(0)') );

```

## .appendTo()

| 在匹配元素集的每个元素之后插入到目标中。

```js
.appendTo(target)

```

|

### 参数

+   目标：选择器、元素、HTML 字符串或 jQuery 对象；匹配的元素集将插入到由此参数指定的元素的末尾

### 返回值

jQuery 对象，用于链接目的。

### 描述

`.append` 和 `.appendTo` 方法执行相同的任务。唯一的区别在于语法——具体来说，是内容和目标的放置位置。使用 `.append()`，方法前面的选择器表达式是要插入内容的容器。另一方面，使用 `.appendTo()`，*内容*在方法之前，可以是选择器表达式，也可以是即时创建的标记，然后插入到目标容器中。

考虑以下的 HTML：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div> 
</div>
```

两个 `<div>`，通过一点 CSS，呈现在页面的右侧如下：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_07.jpg)

使用 `.appendTo()`，我们可以像这样将 HTML 结构插入到 `<div class="demo-box">` 的末尾：

```js
$('<div class="insertion">This text was <strong>inserted</strong> </div>').appendTo('div.demo-box');

```

新的 `<div>` 和 `<strong>` 元素，以及文本节点，是即时创建的并添加到 DOM 中。结果是一个新的 `<div>` 定位在 **演示框** 文本之后：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_08.jpg)

页面上已经存在的元素（或元素数组）也可以移动到 `<div class="demo-box">` 的末尾。例如，下面的代码通过使用选择器表达式来移动文档的第一个段落：

```js
$('p:eq(0)').appendTo('div.demo-box');

```

# DOM 插入，外部

## .before()

| 在匹配元素集的每个元素之前插入参数指定的内容。

```js
.before(content)

```

|

### 参数

+   内容：要在匹配元素集的每个元素之前插入的元素、HTML 字符串或 jQuery 对象

### 返回值

jQuery 对象，用于链式调用。

### 描述

`.before`和`.insertBefore`方法执行相同的任务。唯一的区别在于语法——具体来说，在内容和目标的放置方面不同。对于`.before()`，在方法之前的选择器表达式是要插入内容的容器。而对于`.insertBefore()`，另一方面，*内容*在方法之前，可以作为选择器表达式或即时创建的标记插入，并且它会在目标容器之前插入。

考虑以下 HTML：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div> 
</div>
```

两个`<div>`经过一点 CSS 处理后，在页面的右侧呈现如下：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_09.jpg)

我们可以这样在`<div class="demo-box">`之前插入一个 HTML 结构：

```js
$('div.demo-box').before('<div class="insertion">This text was <strong>inserted</strong></div>');

```

新的`<div>`和`<strong>`元素以及文本节点是即时创建的，并添加到 DOM 中。结果是一个新的`<div>`被定位在`<div class="demo-box">`的外部，就在它之前：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_10.jpg)

已经存在于页面上的一个元素（或元素数组）也可以移动到 DOM 位置，就在`<div class="demo-box">`之前。例如，以下代码通过使用 jQuery 对象移动文档的第一个段落：

```js
$('div.demo-box').before( $('p:eq(0)') );

```

## `.insertBefore()`

| 在参数中指定的一组元素之前插入匹配元素集合中的每个元素。

```js
.insertBefore(content)

```

|

### 参数

+   内容：要插入的一组匹配元素之前的选择器或元素

### 返回值

jQuery 对象，用于链式调用。

### 描述

`.before`和`.insertBefore`方法执行相同的任务。唯一的区别在于语法——具体来说，在内容和目标的放置方面不同。对于`.before()`，在方法之前的选择器表达式是要插入内容的容器。而对于`.insertBefore()`，另一方面，*内容*在方法之前，可以作为选择器表达式或即时创建的标记插入，并且它会在目标容器之前插入。

考虑以下 HTML：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div> 
</div>
```

两个`<div>`经过一点 CSS 处理后，在页面的右侧呈现如下：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_11.jpg)

我们可以这样在`<div class="demo-box">`之前插入一个 HTML 结构：

```js
$('<div class="insertion">This text was <strong>inserted</strong> </div>').insertBefore('div.demo-box');

```

新的`<div>`和`<strong>`元素以及文本节点是即时创建的，并添加到 DOM 中。结果是一个新的`<div>`被定位在`<div class="demo-box">`的外部，就在它之前：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_12.jpg)

已经存在于页面上的一个元素（或元素数组）也可以移动到 DOM 位置，就在`<div class="demo-box">`之前。例如，以下代码通过使用 jQuery 对象移动文档的第一个段落：

```js
$('p:eq(0)').insertBefore('div.demo-box');

```

## `.after()`

| 在匹配元素集合中的每个元素后插入参数指定的内容。

```js
.after(content)

```

|

### 参数

+   内容：要在一组匹配元素中的每个元素后插入的元素、HTML 字符串或 jQuery 对象。

### 返回值

jQuery 对象，用于链式调用。

### 描述

`.after` 和 `.insertAfter` 方法执行相同的任务。唯一的区别在于语法，具体来说，在内容和目标的放置上有所不同。对于 `.after()`，方法之前的选择器表达式是将内容插入的容器。另一方面，对于 `.insertAfter()`，*内容*在方法之前，可以是选择器表达式，也可以是即时创建的标记，它被插入到目标容器之后。

考虑以下 HTML：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div> 
</div>
```

两个 `<div>`，稍加 CSS 处理，渲染在页面的右侧，如下所示：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_13.jpg)

我们可以在 `<div class="demo-box">`之后插入 HTML 结构，如下所示：

```js
$('div.demo-box').after('<div class="insertion">This text was <strong>inserted</strong></div>');

```

新的 `<div>` 和 `<strong>` 元素，以及文本节点，都是即时创建并添加到 DOM 中的。结果是一个新的 `<div>`，在 `<div class="demo-box">`之外，紧接着它之后：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_14.jpg)

将页面上已经存在的元素（或元素数组）移动到 DOM 位置后面的`<div class="demo-box">`也是可以的。例如，以下代码通过使用 jQuery 对象将文档的第一个段落移动：

```js
$('div.demo-box').after( $('p:eq(0)') );

```

## `.insertAfter()`

| 将匹配元素集合中的每个元素插入到指定参数中的元素集合之后。

```js
.insertAfter(content)

```

|

### 参数

+   content: 一个选择器或元素，用于指定将要插入的匹配元素集合之后

### 返回值

用于链式调用的 jQuery 对象。

### 描述

`.after` 和 `.insertAfter` 方法执行相同的任务。唯一的区别在于语法，具体来说，在内容和目标的放置上有所不同。对于 `.after()`，方法之前的选择器表达式是将内容插入的容器。另一方面，对于 `.insertAfter()`，*内容*在方法之前，可以是选择器表达式，也可以是即时创建的标记，它被插入到目标容器之后。

考虑以下 HTML：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div> 
</div>
```

两个 `<div>`，稍加 CSS 处理，渲染在页面的右侧，如下所示：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_15.jpg)

使用 `.insertAfter()`，我们可以在 `<div class="demo-box">`之后插入 HTML 结构，如下所示：

```js
$('<div class="insertion">This text was <strong>inserted</strong> </div>').insertAfter('div.demo-box');

```

新的 `<div>` 和 `<strong>` 元素，以及文本节点，都是即时创建并添加到 DOM 中的。结果是一个新的 `<div>`，在 `<div class="demo-box">`之外，紧接着它之后：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_16.jpg)

将页面上已经存在的元素（或元素数组）移动到 DOM 位置后面的`<div class="demo-box">`也是可以的。例如，以下代码通过使用 jQuery 对象将文档的第一个段落移动：

```js
$('p:eq(0)').insertAfter('div.demo-box');

```

# DOM 插入，环绕

## `.wrap()`

| 将一系列元素的结构包装在匹配元素集合中的每个元素周围。

```js
.wrap(html)
.wrap(element)

```

|

### 参数（第一版本）

+   html: 一串 HTML 标记，用于围绕匹配元素集合

### 参数（第二版本）

+   element: 一个现有的元素，用于围绕匹配元素集合

### 返回值

jQuery 对象，用于链式调用。

### 描述

注意：HTML 必须仅包含格式正确、有效的元素结构。如果包含任何文本，或者任何标签未关闭，`.wrap()` 将失败。

考虑以下 HTML：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div> 
</div>
```

两个 `<div>`，通过一些 CSS，呈现在页面的右侧如下：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_17.jpg)

使用`.wrap()`，我们可以在 `<div class="demo-box">` 周围插入 HTML 结构，如下所示：

```js
$('div.demo-box').wrap('<div class="insertion"> </div>');

```

新的 `<div>` 元素是即时创建的，并添加到 DOM 中。结果是一个新的 `<div>` 包裹在 `<div class="demo-box">` 周围：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_18.jpg)

使用 DOM 节点作为我们的参数，我们可以将新的 `<div>` 包装在具有 `id="demo-box1"` 的元素周围，如下所示：

```js
$(document.getElementById('demo-box1')).wrap(' <div class="insertion"> </div>');

```

# DOM 复制

## .clone()

| 创建匹配元素集的副本。

```js
.clone([deep])

```

|

### 参数

+   deep（可选）：布尔值。默认为`true`。如果设置为`false`，`.clone`方法仅复制匹配的元素本身，而不包括任何子/后代元素和文本。

### 返回值

一个新的 jQuery 对象，引用了创建的元素。

### 描述

当与其中一种插入方法结合使用时，`.clone`方法是在页面上复制元素的便捷方式。考虑以下 HTML：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div> 
</div>
```

两个 `<div>`，通过一些 CSS，呈现在页面的右侧如下：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_19.jpg)

要复制`<div class="demo-box">`并将该副本粘贴到原始内容之后，我们可以编写以下内容：

```js
$('div.demo-box:last').clone().insertAfter('div.demo-box:last');

```

现在我们有两个**演示框**：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_20.jpg)

请注意，我们在这里使用`:last`选择器，以确保只复制(`.clone()`)并粘贴(`.insertAfter()`)一次。我们需要注意潜在的意外克隆或插入超出我们意图的数量，并采取必要的预防措施防止发生这种情况。

### 提示

使用`.clone`方法，我们可以在将克隆的元素或其内容插入文档之前修改它们。

可选的 `deep` 参数接受一个布尔值 — `true` 或 `false`。由于在大多数情况下，我们希望克隆子节点，而默认值为`true`，因此该参数很少被使用。但是，想象一下我们想要复制**演示框**而不带其文本，然后将段落附加到每个 `<div class="demo-box">`。我们可以使用以下代码实现这一点：

```js
$('div.demo-box:last').clone(false).insertAfter('div.demo-box:last');
$('div.demo-box').append('<p>New Message</p>);

```

现在两个框看起来像这样：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_21.jpg)

第一个框现在既有原始**演示框**文本，又有额外的**新消息**文本，而新克隆的框只有额外的文本。

# DOM 删除

## .empty()

| 从 DOM 中删除匹配元素集的所有子节点。

```js
.empty()

```

|

### 参数

无。

### 返回值

jQuery 对象，用于链式调用。

### 描述

此方法不仅会移除子元素（和其他后代元素），还会移除匹配元素集合中的任何文本。这是因为根据 DOM，元素内的任何文本字符串被视为该元素的子节点。考虑以下 HTML：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div> 
</div>
```

两个 `<div>` 经过一点 CSS 处理后，显示在页面的右侧如下：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_22.jpg)

如果我们对其应用 `$('div.demo-box').empty()`;，则**演示框**文本字符串被移除：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_23.jpg)

如果我们在 `<div class="demo-box">` 内有任意数量的嵌套元素，它们也会被移除。

## .remove()

| 从 DOM 中移除一组匹配的元素。

```js
.remove([selector])

```

|

### 参数

+   选择器（可选）：用于筛选要移除的一组匹配元素

### 返回值

用于链接目的的 jQuery 对象。

### 描述

与 .empty 类似，`.remove` 方法将元素从 DOM 中移除。我们使用 `.remove()` 当我们想要移除元素本身以及其中的所有内容。考虑以下 HTML：

```js
<div class="demo-container">
  <div class="demo-box">Demonstration Box
  </div> 
</div>
```

两个 `<div>` 经过一点 CSS 处理后，显示在页面的右侧如下：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_24.jpg)

如果我们对其应用 `$('div.demo-box').remove()`，整个 `<div class="demo-box>` 以及其中的所有内容都会被移除：

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_04_25.jpg)

我们还可以将选择器作为可选参数包含在内。例如，我们可以将前面的 DOM 移除代码重写为：`$('div').remove('.demo-box')`。或者，如果我们有多个具有相同类名的元素，并且只想移除第一个带有 `id="temporary-demo-box"` 的元素，我们可以这样编写：

```js
$('div.demo‑box').remove('#temporary-demo-box ').

```


# 第五章：事件方法

> 女人，我与你结缘
> 
> 我会做什么？
> 
> —— Devo，
> 
> “绳子之歌”

在本章中，我们将依次仔细研究每个可用的事件方法。这些方法用于在用户与浏览器进行交互时注册行为，并进一步操作这些注册的行为。

# 事件处理程序附加

以下方法是 jQuery 事件处理模块的构建块。

## .bind()

| 为元素附加事件处理程序

```js
.bind(eventType[, eventData], handler)

```

|

### 参数

+   eventType：包含 JavaScript 事件类型的字符串，如 `click` 或 `submit`。

+   eventData（可选）：将传递给事件处理程序的数据映射

+   处理程序：每次触发事件时执行的函数

### 返回值

jQuery 对象，用于链接目的。

### 描述

`.bind()` 方法是将行为附加到文档的主要方法。所有 JavaScript 事件类型都允许用于 *eventType*；以下是跨平台和推荐的：

+   `blur`

+   `change`

+   `click`

+   `dblclick`

+   `error`

+   `focus`

+   `keydown`

+   `keypress`

+   `keyup`

+   `load`

+   `mousedown`

+   `mousemove`

+   `mouseout`

+   `mouseover`

+   `mouseup`

+   `resize`

+   `scroll`

+   `select`

+   `submit`

+   `unload`

jQuery 库提供了绑定每种事件类型的快捷方法，例如 `.click()` 用于 `.bind('click')`。每种事件类型的描述可以在其快捷方法的描述中找到。

当事件到达元素时，绑定到该元素的该事件类型的所有处理程序都会被触发。如果有多个处理程序已注册，则它们将始终按照绑定它们的顺序执行。在所有处理程序执行完毕后，事件会沿着正常的事件传播路径继续。有关事件传播的完整讨论，请参阅 *Learning jQuery* 或 [`www.w3.org/TR/DOM-Level-2-Event/`](http://www.w3.org/TR/DOM-Level-2-Event/) 上的 W3C 规范。`.bind()` 的基本用法如下：

```js
$('#foo').bind('click', function() {
  alert('User clicked on "foo."');
});
```

此代码将导致具有 `foo` ID 的元素对 `click` 事件做出响应；以后用户点击此元素内部时，警报将显示。

**事件处理程序**

`handler` 参数采用回调函数，如所示；在处理程序内部，关键字 `this` 设置为处理程序绑定的 DOM 元素。要在 jQuery 中使用该元素，可以将其传递给正常的 `$()` 函数。例如：

```js
$('#foo').bind('click', function() {
  alert($(this).text());
});
```

执行此代码后，当用户点击具有 `foo` ID 的元素内部时，其文本内容将显示为警报。

**事件对象**

回调函数接受一个参数；当处理程序被调用时，JavaScript 事件对象将通过它传递。

事件对象通常是不必要的，参数被省略，因为当处理程序绑定时通常可用足够的上下文来准确知道触发处理程序时需要执行什么操作。但是，有时需要收集有关用户在事件发生时环境的更多信息。JavaScript 提供了诸如`.shiftKey`（是否在按下*shift*键时按住）、`.offsetX`（元素内鼠标光标的*x*坐标）和`.type`（事件类型）等信息。

事件对象的一些属性和方法在每个平台上都不可用。但是，如果事件由 jQuery 事件处理程序处理，那么库会标准化某些属性，以便它们可以在任何浏览器上安全使用。特别是：

+   `.target`: 此属性表示触发事件的 DOM 元素。通常比较`event.target`和`this`很有用，以确定事件是否由于事件冒泡而处理。

+   `.pageX`: 此属性包含鼠标光标相对于页面左边缘的*x*坐标。

+   `.pageY`: 此属性包含鼠标光标相对于页面顶部边缘的*y*坐标。

+   `.preventDefault()`: 如果调用此方法，则不会触发事件的默认操作。例如，点击的锚点不会将浏览器带到新的 URL。

+   `.stopPropagation()`: 这个方法阻止事件冒泡到 DOM 树上寻找更多的事件处理程序来触发。

返回`false`表示处理程序相当于在事件对象上调用`.preventDefault()`和`.stopPropagation()`。

在处理程序中使用事件对象看起来像这样：

```js
$(document).ready(function() {
  $('#foo').bind('click', function(event) {
    alert('The mouse cursor is at (' + event.pageX + ', ' + event.pageY + ')');
  });
});
```

注意添加到匿名函数的参数。此代码将导致对具有 ID `foo` 的元素的`click`报告单击时鼠标光标的页面坐标。

### 传递事件数据

可选的*eventData*参数并不常用。提供时，此参数允许我们向处理程序传递附加信息。此参数的一个方便的用途是解决闭包引起的问题。例如，假设我们有两个事件处理程序，两者都引用相同的外部变量：

```js
var message = 'Spoon!';
$('#foo').bind('click', function() {
  alert(message);
});
message = 'Not in the face!';
$('#bar').bind('click', function() {
  alert(message);
});
```

因为处理程序都是闭包，两者的环境中都有`message`，所以触发时都会显示消息`Not in the face!`变量的值已更改。为了规避这种情况，我们可以在`eventData`中传递消息：

```js
var message = 'Spoon!';
$('#foo').bind('click', {msg: message}, function(event) {
  alert(event.data.msg);
});
message = 'Not in the face!';
$('#bar').bind('click', {msg: message}, function(event) {
  alert(event.data.msg);
});
```

这次变量不直接在处理程序中引用；相反，值通过`eventData`传递，这将在绑定事件时固定值。第一个处理程序现在将显示`Spoon!`，而第二个处理程序将警告`Not in the face!`

如果*eventData*存在，则它是`.bind()`方法的第二个参数；如果不需要向处理程序发送其他数据，则回调作为第二个和最后一个参数传递。

### 注意

请参阅 `.trigger()` 方法参考，了解在事件发生时传递数据给处理程序的方法，而不是绑定处理程序时。

## `.unbind()`

| 从元素中删除先前附加的事件处理程序。

```js
.unbind([eventType[, handler]])
.unbind(event)

```

|

### 参数（第一个版本）

+   eventType：包含 JavaScript 事件类型的字符串，例如`click`或`submit`

+   处理程序：不再执行的函数

### 参数（第二个版本）

+   事件：作为传递给事件处理程序的 JavaScript 事件对象

### 返回值

jQuery 对象，用于链接目的。

### 描述

使用 `.bind()` 绑定的任何处理程序都可以使用 `.unbind()` 删除。 在最简单的情况下，没有参数，`.unbind()` 删除附加到元素的所有处理程序：

```js
$('#foo').unbind();

```

这个版本无论类型如何都会删除处理程序。 要更精确，我们可以传递一个事件类型：

```js
$('#foo').unbind('click');

```

通过指定“click”事件类型，只会解绑该事件类型的处理程序。 但是，如果其他脚本可能将行为附加到同一元素，则此方法仍可能具有负面影响。 出于这个原因，健壮且可扩展的应用程序通常要求使用两个参数的版本：

```js
var handler = function() {
  alert('The quick brown fox jumps over the lazy dog.');
};
$('#foo').bind('click', handler);
$('#foo').unbind('click', handler);
```

通过命名处理程序，我们可以确保没有其他函数被捕获。 请注意，以下内容 *不* 工作：

```js
$('#foo').bind('click', function() {
  alert('The quick brown fox jumps over the lazy dog.');
});

$('#foo').unbind('click', function() {
  alert('The quick brown fox jumps over the lazy dog.');
});
```

尽管这两个函数在内容上是相同的，但它们是分开创建的，因此 JavaScript 可以将它们保留为不同的函数对象。 要解绑特定的处理程序，我们需要一个对该函数的引用，而不是对做同样事情的其他处理程序的引用。

### 使用事件对象

当我们希望在内部解绑处理程序时，使用此方法的第二种形式。 例如，假设我们希望仅触发事件处理程序三次：

```js
var timesClicked = 0;
$('#foo').bind('click', function(event) {
  alert('The quick brown fox jumps over the lazy dog.');
  timesClicked++;
  if (timesClicked >= 3) {
    $(this).unbind(event);
  }
});
```

在这种情况下，处理程序必须接受一个参数，以便我们可以捕获事件对象并在第三次单击后使用它来解绑处理程序。 事件对象包含对于 `.unbind()` 知道要删除的处理程序的上下文是必要的。

这个例子也是闭包的一个例证。 由于处理程序引用了在函数外部定义的 `timesClicked` 变量，因此增加变量的效果甚至在处理程序调用之间都会产生影响。

## `.one()`

| 为元素附加事件处理程序。 处理程序最多执行一次。

```js
.one(eventType[, eventData], handler)

```

|

### 参数

+   eventType：包含 JavaScript 事件类型的字符串，例如`click`或`submit`

+   eventData（可选）：将传递给事件处理程序的数据映射

+   处理程序：在触发事件时执行的函数

### 返回值

jQuery 对象，用于链接目的。

### 描述

此方法与 `.bind()` 相同，只是在第一次调用后解绑处理程序。 例如：

```js
$('#foo').one('click', function() {
  alert('This will be displayed only once.');
});
```

执行代码后，单击具有 ID `foo` 的元素将显示警报。 后续单击将不起作用。

这段代码等效于：

```js
$('#foo').bind('click', function(event) {
  alert('This will be displayed only once.');
  $(this).unbind(event);
});
```

换句话说，从常规绑定处理程序内部显式调用 `.unbind()` 具有完全相同的效果。

## `.trigger()`

| 执行附加到元素的所有事件处理程序的处理程序。

```js
.trigger(eventType[, extraParameters])

```

|

### 参数

+   eventType：包含 JavaScript 事件类型的字符串，例如`click`或`submit`

+   extraParameters：传递给事件处理程序的额外参数数组

### 返回值

jQuery 对象，用于链式调用。

### 描述

任何使用`.bind()`或其快捷方法之一附加的事件处理程序在相应事件发生时触发。但是，可以通过`.trigger()`方法手动触发它们。调用`.trigger()`会按照与用户自然触发事件相同的顺序执行处理程序：

```js
$('#foo').bind('click', function() {
  alert($(this).text());
});
$('#foo').trigger('click');
```

虽然`.trigger()`模拟了事件激活，包括合成的事件对象，但它并不能完美地复制自然发生的事件。不会发生事件冒泡，因此必须在实际附加了事件处理程序的元素上调用`.trigger()`。默认行为也不可靠地调用，因此必须使用诸如`.submit()`之类的方法手动调用 DOM 元素上的默认行为。

当我们使用`.bind()`方法定义自定义事件类型时，`.trigger()`的第二个参数会变得有用。例如，假设我们已经将处理程序绑定到自定义事件而不是之前绑定到内置的`click`事件的元素上：

```js
$('#foo').bind('custom', function(event, param1, param2) {
  alert(param1 + "\n" + param2);
});
$('#foo').trigger('custom', ['Custom', 'Event']);
```

事件对象始终作为第一个参数传递给事件处理程序，但是如果像这样在`.trigger()`调用期间指定了额外的参数，那么这些参数也将被传递给处理程序。

注意这里传递的额外参数与`.bind()`方法的`eventData`参数之间的区别。两者都是向事件处理程序传递信息的机制，但是`.trigger()`的`extraParameters`参数允许在触发事件时确定信息，而`.bind()`的`eventData`参数要求在绑定处理程序时已经计算好信息。

# 文档加载

这些事件涉及页面加载到浏览器中。

## $()

| 指定在 DOM 完全加载后执行的函数。

```js
$(document).ready(handler)
$().ready(handler)
$(handler)

```

|

### 参数

+   处理程序：在 DOM 准备就绪后执行的函数

### 返回值

jQuery 对象，用于链式调用。

### 描述

尽管 JavaScript 提供了`load`事件来执行在页面渲染时运行的代码，但是此事件直到所有资源（例如图像）完全接收完毕才会触发。在大多数情况下，脚本可以在 DOM 层次结构完全构建后立即运行。传递给`.ready()`的处理程序保证在 DOM 准备就绪后执行，因此这通常是附加所有其他事件处理程序并运行其他 jQuery 代码的最佳位置。

在代码依赖于加载的资产（例如，如果需要图像的尺寸）的情况下，代码应该放在`load`事件的处理程序中。

`.ready()` 方法通常与 `<body onload="">` 属性不兼容。如果必须使用 `load`，则要么不使用 `.ready()`，要么使用 jQuery 的 `.load()` 方法将 `load` 事件处理程序附加到窗口或更具体的项目，如图像。

所提供的三种语法是等效的。`.ready()` 方法只能在与当前文档匹配的 jQuery 对象上调用，因此可以省略选择器。

`.ready()` 方法通常与匿名函数一起使用：

```js
$(document).ready(function() {
  alert('Ready event was triggered.');
});
```

将此代码放置后，页面加载时将显示一个警报。

当使用另一个 JavaScript 库时，我们可能希望调用 `$.noConflict()` 来避免命名空间的困扰。当调用此函数时，`$` 快捷方式不再可用，强制我们在通常会写 `$` 的地方写 `jQuery`。但是，传递给 `.ready()` 方法的处理程序可以接受一个参数，该参数传递给全局 jQuery 对象。这意味着我们可以在我们的 `.ready()` 处理程序的上下文中重命名对象而不影响其他代码：

```js
jQuery(document).ready(function($) {
  // Code using $ as usual goes here.
});
```

如果在 DOM 初始化后调用 `.ready()`，则传入的新处理程序将立即执行。

## `.load()`

| 将事件处理程序绑定到加载 JavaScript 事件。

```js
.load(handler)

```

|

### 参数

+   handler: 当事件触发时要执行的函数

### 返回值

用于链接目的的 jQuery 对象。

### 描述

此处理程序是 `.bind('load', handler)` 的快捷方式。

当它和所有子元素都完全加载时，`load` 事件被发送到元素。此事件可以发送到与 URL 相关的任何元素 - 图像、脚本、框架以及文档本身的主体。

例如，考虑以下 HTML：

```js
<img class="target" src="img/hat.gif" width="80" height="54" alt="Hat" />

```

事件处理程序可以绑定到图片上：

```js
$('.target').load(function() {
  $(this).log('Load event was triggered.');
});
```

现在一旦图片加载完成，消息将被显示。

一般来说，等待所有图像完全加载是不必要的。如果代码可以更早执行，则通常最好将其放置在发送到 `.ready()` 方法的处理程序中。

### 注意

AJAX 模块还有一个名为 `.load()` 的方法。触发哪一个取决于传递的参数集合。

## `.unload()`

| 将事件处理程序绑定到卸载 JavaScript 事件。

```js
.unload(handler)

```

|

### 参数

+   handler: 当事件触发时要执行的函数。

### 返回值

用于链接目的的 jQuery 对象。

### 描述

此处理程序是 `.bind('unload', handler)` 的快捷方式。

当用户导航离开页面时，`unload` 事件被发送到 `window` 元素。这可能意味着许多事情之一。用户可能点击链接离开页面，或者在地址栏中键入新 URL。前进和后退按钮将触发事件。关闭浏览器窗口将导致事件触发。甚至页面重新加载也会首先创建 `unload` 事件。

任何 `unload` 事件处理程序都应绑定到 `window` 对象上：

```js
$(window).unload(function() {
  alert('Unload event was triggered.');
});
```

执行此代码后，每当浏览器离开当前页面时将显示警报。

使用 `.preventDefault()` 无法取消 `unload` 事件。提供此事件是为了在用户离开页面时脚本可以执行清理操作。

## .error()

| 将事件处理程序绑定到错误 JavaScript 事件。

```js
.error(handler)

```

|

### 参数

+   handler：当事件触发时执行的函数

### 返回值

jQuery 对象，用于链式操作。

### 描述

此处理程序是 `.bind('error', handler)` 的快捷方式。

`error` 事件被发送到可以接收 `load` 事件的相同元素。如果元素加载不正确，则会调用该事件。

例如，考虑以下 HTML：

```js
<img class="target" src="img/missing.gif" width="80" height="54" alt="Missing Image" />

```

可以将事件处理程序绑定到图像上：

```js
$('.target').error(function() {
  $(this).log('Error event was triggered.');
});
```

如果图像无法加载（例如，因为它不存在于提供的 URL 中），则会显示消息。

当页面本地提供服务时，可能不会正确触发此事件。由于 `error` 依赖于正常的 HTTP 状态代码，因此通常不会在 URL 使用 `file：` 协议时触发。

# 鼠标事件

这些事件是由鼠标移动和按钮按下触发的。

## .mousedown()

| 将事件处理程序绑定到鼠标按下 JavaScript 事件，或者在元素上触发该事件。

```js
.mousedown(handler)
.mousedown()

```

|

### 参数（第一个版本）

+   handler：每次触发事件时执行的函数

### 返回值

jQuery 对象，用于链式操作。

### 描述

此处理程序是第一个变体中的 `.bind('mousedown', handler)` 的快捷方式，以及第二个变体中的 `.trigger('mousedown')`。

当鼠标指针位于元素上并按下鼠标按钮时，会向元素发送 `mousedown` 事件。任何 HTML 元素都可以接收此事件。

例如，考虑以下 HTML：

```js
<div class="target button">Click Here</div>
<div class="trigger button">Trigger</div>

```

可以将事件处理程序绑定到目标按钮上：

```js
$('.target').mousedown(function() {
  $(this).log('Mousedown event was triggered.');
});
```

现在，如果我们点击目标按钮，消息就会显示出来。我们还可以在第二个按钮被点击时触发事件：

```js
$('.trigger').click(function() {
  $('.target').mousedown();
});
```

执行此代码后，点击触发按钮也会显示消息。

当任何鼠标按钮被单击时，会发送 `mousedown` 事件。为了仅对特定按钮执行操作，我们可以在 Mozilla 浏览器中使用事件对象的 `which` 属性（左键为 1，中键为 2，右键为 3），或者在 Internet Explorer 中使用 `button` 属性（左键为 1，中键为 4，右键为 2）。这对于确保使用主按钮开始拖动操作非常有用；如果忽略，当用户尝试使用上下文菜单时可能会产生奇怪的结果。虽然这些属性可以检测到中间和右键，但这不是可靠的。例如，在 Opera 和 Safari 中，默认情况下无法检测到右键单击。

如果用户点击一个元素，然后将鼠标指针移开或释放按钮，则仍将计为 `mousedown` 事件。在大多数用户界面中，这一系列操作被视为对按钮按下的取消，因此通常最好使用 `click` 事件，除非我们知道 `mousedown` 事件在特定情况下更可取。

## .mouseup()

| 将事件处理程序绑定到 mouseup JavaScript 事件，或在元素上触发该事件。

```js
.mouseup(handler)
.mouseup()

```

|

### 参数（第一个版本）

+   handler：每次触发事件时执行的函数

### 返回值

用于链接目的的 jQuery 对象。

### 描述

此处理程序是第一个变体中 `.bind('mouseup', handler)` 的快捷方式，以及第二个变体中 `.trigger('mouseup')` 的快捷方式。

当鼠标指针悬停在元素上并且鼠标按钮被释放时，`mouseup` 事件被发送到元素。任何 HTML 元素都可以接收此事件。

例如，考虑以下 HTML 代码：

```js
<div class="target button">Click Here</div>
<div class="trigger button">Trigger</div>

```

事件处理程序可以绑定到目标按钮上：

```js
$('.target').mouseup(function() {
  $(this).log('Mouseup event was triggered.');
});
```

现在，如果我们点击目标按钮，消息就会显示出来。我们还可以在第二个按钮被点击时触发事件：

```js
$('.trigger').click(function() {
  $('.target').mouseup();
});
```

执行此代码后，点击**触发**按钮也会显示消息。

如果用户在元素外部单击，拖动到元素上并释放按钮，则此仍被视为 `mouseup` 事件。在大多数用户界面中，此操作序列不被视为按钮按下，因此通常最好使用 `click` 事件，除非我们知道对于特定情况来说，`mouseup` 事件更合适。

## .click()

| 将事件处理程序绑定到点击 JavaScript 事件，或在元素上触发该事件。

```js
.click(handler)
.click()

```

|

### 参数（第一个版本）

+   handler：每次触发事件时执行的函数

### 返回值

用于链接目的的 jQuery 对象。

### 描述

此处理程序是第一个变体中 `.bind('click', handler)` 的快捷方式，以及第二个变体中 `.trigger('click')` 的快捷方式。

当鼠标指针悬停在元素上并且鼠标按钮被按下并释放时，`click` 事件被发送到元素。任何 HTML 元素都可以接收此事件。

例如，考虑以下 HTML 代码：

```js
<div class="target button">Click Here</div>
<div class="trigger button">Trigger</div>

```

事件处理程序可以绑定到目标按钮上：

```js
$('.target').click(function() {
  $(this).log('Click event was triggered.');
});
```

现在，如果我们点击目标按钮，消息就会显示出来。我们还可以在第二个按钮被点击时触发事件：

```js
$('.trigger').click(function() {
  $('.target').click();
});
```

执行此代码后，点击触发按钮也会显示消息。

`click` 事件仅在以下确切的事件序列之后触发：

+   当指针位于元素内部时按下鼠标按钮。

+   当鼠标指针位于元素内部时释放鼠标按钮。

在执行操作之前，这通常是期望的顺序。如果不需要这样做，则 `mousedown` 或 `mouseup` 事件可能更合适。

## .dblclick()

| 将事件处理程序绑定到 `dblclick` JavaScript 事件，或在元素上触发该事件。

```js
.dblclick(handler)
.dblclick()

```

|

### 参数（第一个版本）

+   handler：每次触发事件时执行的函数

### 返回值

用于链接目的的 jQuery 对象。

### 描述

此处理程序是第一个变体中 `.bind('dblclick', handler)` 的快捷方式，以及第二个变体中 `.trigger('dblclick')` 的快捷方式。

当元素被双击时，`dblclick` 事件被发送到元素。任何 HTML 元素都可以接收此事件。

例如，考虑以下 HTML 代码：

```js
<div class="target button">Click Here</div>
<div class="trigger button">Trigger</div>

```

事件处理程序可以绑定到目标按钮上：

```js
$('.target').dblclick(function() {
  $(this).log('Dblclick event was triggered.');
});
```

现在，如果我们双击目标按钮，消息将被显示。我们还可以在点击第二个按钮时触发事件：

```js
$('.trigger').click(function() {
  $('.target').dblclick();
});
```

执行此代码后，单击 **Trigger** 按钮也会显示消息。

`dblclick` 事件仅在以下确切事件序列之后触发：

+   鼠标按钮在指针位于元素内时被按下。

+   鼠标按钮在指针位于元素内时释放。

+   在指针位于元素内，且在系统相关的时间窗口内再次按下鼠标按钮。

+   鼠标按钮在指针位于元素内时释放。

不建议为同一元素同时绑定 `click` 和 `dblclick` 事件处理程序。触发的事件序列因浏览器而异，有些会收到两个 `click` 事件，而其他则只会收到一个。如果无法避免需要对单击和双击做出不同反应的界面，则应在 `click` 处理程序内模拟 `dblclick` 事件。我们可以通过在处理程序中保存时间戳，然后在后续点击时将当前时间与保存的时间戳进行比较来实现这一点。如果差异足够小，则可以将单击视为双击。

## .toggle()

| 将两个事件处理程序绑定到匹配的元素上，以在交替点击时执行。

```js
.toggle(handlerEven, handlerOdd)

```

|

### 参数

+   handlerEven: 每次偶数次点击元素时执行的函数。

+   handlerOdd: 每次单数次点击元素时执行的函数。

### 返回值

jQuery 对象，用于链式操作。

### 描述

`.toggle()` 方法绑定了一个 `click` 事件处理程序，因此这里也适用于 `click` 触发的规则。

例如，考虑以下 HTML：

```js
<div class="target button">Click Here</div>

```

可以将事件处理程序绑定到此按钮：

```js
$('.target').toggle(function() {
  $(this).log('Toggle event was triggered (handler 1).');
}, function() {
  $(this).log('Toggle event was triggered (handler 2).');
});
```

第一次单击按钮时，将执行第一个处理程序。第二次，将执行第二个处理程序。后续点击将在两个处理程序之间循环。

`.toggle()` 方法提供了方便。手动实现相同的行为相对简单，如果 `.toggle()` 内置的假设限制了操作，则可能需要手动实现。例如，如果两次将 `.toggle()` 应用于同一元素，那么不能保证其正确工作。由于 `.toggle()` 内部使用 `click` 处理程序来完成其工作，因此我们必须解绑 `click` 以移除使用 `.toggle()` 附加的行为，以便其他 `click` 处理程序不会受到影响。该实现还在事件上调用了 `.preventDefault()`，因此如果在元素上调用了 `.toggle()`，则链接将不会被跟随，按钮也不会被点击。

## .mouseover()

| 将事件处理程序绑定到 `mouseover` JavaScript 事件，或在元素上触发该事件。

```js
.mouseover(handler)
.mouseover()

```

|

### 参数（第一版）

+   handler: 每次触发事件时执行的函数

### 返回值

jQuery 对象，用于链式操作。

### 描述

这个处理程序是第一种情况下`.bind('mouseover', handler)`的简写，以及第二种情况下`.trigger('mouseover')`的简写。

当鼠标指针进入元素时，会向元素发送`mouseover`事件。任何 HTML 元素都可以接收到这个事件。

举个例子，考虑一下 HTML：

```js
<div class="target button">Move Here</div>
<div class="trigger button">Trigger</div>

```

这个事件处理程序可以绑定到目标按钮上：

```js
$('.target').mouseover(function() {
  $(this).log('Mouseover event was triggered.');
});
```

当鼠标指针移过目标按钮时，消息被显示出来。我们还可以在第二个按钮被点击时触发事件：

```js
$('.trigger').click(function() {
  $('.target').mouseover();
});
```

在这段代码执行后，点击**Trigger**按钮也将显示消息。

这种事件类型可能会由于事件冒泡而引起许多麻烦。当鼠标指针移过嵌套元素时，`mouseover`事件将发送给该元素，然后向上冒泡到层次结构中。这可能会在不适当的时候触发我们绑定的`mouseover`处理程序。通过使用`.hover()`方法，我们可以避免这个问题。

## .mouseout()

| 绑定一个事件处理程序到**mouseout** JavaScript 事件，或在元素上触发该事件。

```js
.mouseout(handler)
.mouseout()

```

|

### 参数（第一个版本）

+   handler: 每次事件被触发时要执行的函数

### 返回值

jQuery 对象，用于链式调用。

### 描述

这个处理程序是第一种情况下`.bind('mouseout', handler)`的简写，以及第二种情况下`.trigger('mouseout')`的简写。

当鼠标指针离开元素时，会向元素发送`mouseout`事件。任何 HTML 元素都可以接收到这个事件。

举个例子，考虑一下 HTML：

```js
<div class="target button">Move Here</div>
<div class="trigger button">Trigger</div>

```

这个事件处理程序可以绑定到目标按钮上：

```js
$('.target').mouseout(function() {
  $(this).log('Mouseout event was triggered.');
});
```

当鼠标指针移出目标按钮时，消息被显示出来。我们还可以在第二个按钮被点击时触发事件：

```js
$('.trigger').click(function() {
  $('.target').mouseout();
});
```

在这段代码执行后，点击**Trigger**按钮也将显示消息。

这种事件类型可能会由于事件冒泡而引起许多麻烦。当鼠标指针移出嵌套元素时，`mouseout`事件将发送给该元素，然后向上冒泡到层次结构中。这可能会在不适当的时候触发我们绑定的`mouseout`处理程序。通过使用`.hover()`方法，我们可以避免这个问题。

## .hover()

| 绑定两个事件处理程序到匹配的元素上，在鼠标指针进入和离开元素时执行。

```js
.hover(handlerIn, handlerOut)

```

|

### 参数

+   handlerIn: 鼠标指针进入元素时执行的函数

+   handlerOut: 鼠标指针离开元素时执行的函数

### 返回值

jQuery 对象，用于链式调用。

### 描述

`.hover()`方法绑定了对`mouseover`和`mouseout`事件的处理程序。我们可以使用它简单地在鼠标在元素内部时应用行为。考虑一下 HTML：

```js
<div class="target button">Move Here</div>

```

现在我们可以在一个方法调用中绑定进入元素和离开元素的处理程序：

```js
$('.target').hover(function() {
  $(this).log('Hover event was triggered (entering).');
}, function() {
  $(this).log('Hover event was triggered (leaving).');
});
```

现在，当鼠标指针进入元素时，第一条消息将被显示，当鼠标指针离开时，第二条消息将被显示。

对于`mouseover`和`mouseout`事件，由于事件冒泡而常常会收到错误的响应。当鼠标指针穿过嵌套元素时，事件会生成并冒泡到父元素。`.hover()`方法中包含代码以检查此情况并不执行任何操作，因此在使用`.hover()`快捷方式时，我们可以放心地忽略此问题。

## .mousemove()

| 绑定事件处理程序到 mousemove JavaScript 事件，或在元素上触发该事件。

```js
.mousemove(handler)
.mousemove()

```

|

### 参数（第一个版本）

+   处理程序：每次触发事件时执行的函数

### 返回值

为了链式调用的 jQuery 对象。

### 描述

这个处理程序是第一个变体中`.bind('mousemove', handler)`的快捷方式，以及第二个变体中`.trigger('mousemove')`的快捷方式。

当鼠标指针在元素内移动时，将发送`mousemove`事件给该元素。任何 HTML 元素都可以接收此事件。

例如，考虑以下 HTML：

```js
<div class="target button">Move Here</div>
<div class="trigger button">Trigger</div>

```

事件处理程序可以绑定到目标按钮上：

```js
$('.target').mousemove(function() {
  $(this).log('Mousemove event was triggered.');
});
```

现在当鼠标指针在目标按钮内移动时，消息将被显示。我们还可以在点击第二个按钮时触发该事件：

```js
$('.trigger').click(function() {
  $('.target').mousemove();
});
```

这段代码执行后，点击**触发**按钮也会显示消息。

在跟踪鼠标移动时，通常需要明确知道鼠标指针的实际位置。传递给处理程序的事件对象包含一些有关鼠标坐标的信息。诸如`.clientX, .offsetX`和`.pageX`等属性是可用的，但它们在浏览器之间的支持有所不同。幸运的是，jQuery 对`.pageX`和`.pageY`属性进行了标准化，以便它们可以在所有浏览器中使用。这些属性提供了鼠标指针相对于页面左上角的`X`和`Y`坐标。

我们需要记住，无论鼠标指针移动多少像素，都会触发`mousemove`事件。这意味着在非常短的时间内可能会生成数百个事件。如果处理程序必须执行任何重要的处理，或者如果存在多个事件处理程序，这可能会严重影响浏览器的性能。因此，尽可能优化`mousemove`处理程序，并在不再需要时解绑它们非常重要。

一个常见的模式是在`mousedown`处理程序中绑定`mousemove`处理程序，并从相应的`mouseup`处理程序中解绑它。如果实现这个事件序列，请记住`mouseup`事件可能被发送到与`mousemove`事件不同的 HTML 元素。为了解决这个问题，`mouseup`处理程序通常应该绑定到 DOM 树中的一个高级元素，比如`<body>`。

# 表单事件

这些事件涉及`<form>`元素及其内容。

## .focus()

| 绑定事件处理程序到 focus JavaScript 事件，或在元素上触发该事件。

```js
.focus(handler)
.focus()

```

|

### 参数（第一个版本）

+   处理程序：每次触发事件时执行的函数

### 返回值

jQuery 对象，用于链式目的。

### 描述

此处理程序是第一种变体中的`.bind('focus', handler)`的快捷方式，以及第二种变体中的`.trigger('focus')`。

当元素获得焦点时，会发送`focus`事件给该元素。最初，此事件仅适用于表单元素，如`<input>`。在最近的浏览器中，事件的范围已扩展到包括所有元素类型。元素可以通过键盘命令（例如*Tab*键）或通过鼠标点击元素来获得焦点。

浏览器通常会以某种方式突出显示具有焦点的元素，例如用虚线包围元素。焦点用于确定哪个元素首先接收与键盘相关的事件。

例如，考虑 HTML：

```js
<form>
  <input class="target" type="text" value="Field 1" />
  <input type="text" value="Field 2" />
</form>
<div class="trigger button">Trigger</div>
```

事件处理程序可以绑定到第一个输入字段：

```js
$('.target').focus(function() {
  $(this).log('Focus event was triggered.');
});
```

现在，如果我们单击第一个字段，或者从另一个字段*Tab*到它，消息将显示。我们可以在单击按钮时触发事件：

```js
$('.trigger').click(function() {
  $('.target').focus();
});

```

执行此代码后，单击**触发**按钮也会显示消息。

### 注意

触发对隐藏元素的焦点会导致 Internet Explorer 出错。请小心，只在可见元素上调用`.focus()`而不带参数。

## .blur()

| 将事件处理程序绑定到 blur JavaScript 事件，或在元素上触发该事件。

```js
.blur(handler)
.blur()

```

|

### 参数（第一个版本）

+   handler：每次触发事件时执行的函数

### 返回值

jQuery 对象，用于链式目的。

### 描述

此处理程序是第一种变体中的`.bind('blur', handler)`的快捷方式，以及第二种变体中的`.trigger('blur')`。

当元素失去焦点时，会发送`blur`事件给该元素。最初，此事件仅适用于表单元素，如`<input>`。在最近的浏览器中，事件的范围已扩展到包括所有元素类型。元素可以通过键盘命令（例如*Tab*键）或通过在页面上的其他位置点击鼠标来失去焦点。

例如，考虑 HTML：

```js
<form>
  <input class="target" type="text" value="Field 1" />
  <input type="text" value="Field 2" />
</form>
<div class="trigger button">Trigger</div>
```

事件处理程序可以绑定到第一个输入字段：

```js
$('.target').blur(function() {
  $(this).log('Blur event was triggered.');
});
```

现在，如果我们单击第一个字段，然后单击或切换到其他位置，消息将显示。我们可以在单击按钮时触发事件：

```js
$('.trigger').click(function() {
  $('.target').blur();
});
```

执行此代码后，单击**触发**按钮也会显示消息。

## .change()

| 将事件处理程序绑定到 change JavaScript 事件，或在元素上触发该事件。

```js
.change(handler)
.change()

```

|

### 参数（第一个版本）

+   handler：每次触发事件时执行的函数

### 返回值

jQuery 对象，用于链式目的。

### 描述

此处理程序是第一种变体中的`.bind('change', handler)`的快捷方式，以及第二种变体中的`.trigger('change')`。

当元素的值更改时，`change`事件将被发送到元素。此事件仅限于`<input type="text">`字段，`<textarea>`框和`<select>`元素。对于选择框，当用户使用鼠标进行选择时，事件会立即触发，但对于其他元素类型，事件会延迟到元素失去焦点时才触发。

例如，考虑以下 HTML：

```js
<form>
  <input class="target" type="text" value="Field 1" />
  <select class="target">
    <option value="option1" selected="selected">Option 1</option>
    <option value="option2">Option 2</option>
  </select>
</form>
<div class="trigger button">Trigger</div>
```

事件处理程序可以绑定到文本输入和选择框：

```js
$('.target').change(function() {
  $(this).log('Change event was triggered.');
});
```

现在当从下拉菜单中选择第二个选项时，消息将被显示。如果我们更改字段中的文本，然后单击其他位置，消息也将显示。但是，如果字段失去焦点而内容未更改，则不会触发事件。当单击按钮时，我们可以手动触发事件：

```js
$('.trigger').click(function() {
  $('.target').change();
});
```

执行此代码后，点击触发按钮也会显示消息。消息将显示两次，因为处理程序已绑定到两个表单元素上的`change`事件。

## .select()

| 将事件处理程序绑定到选择 JavaScript 事件，或在元素上触发该事件。

```js
.select(handler)
.select()

```

|

### 参数（第一个版本）

+   处理程序：每次触发事件时执行的函数

### 返回值

用于链式调用目的的 jQuery 对象。

### 描述

此处理程序是第一种情况中`.bind('select', handler)`的快捷方式，以及第二种情况中的`.trigger('select')`。

当用户在其中进行文本选择时，`select`事件将被发送到元素。此事件仅限于`<input type="text">`字段和`<textarea>`框。

例如，考虑以下 HTML：

```js
<form>
  <input class="target" type="text" value="The quick brown fox jumps over the lazy dog." />
</form>
<div class="trigger button">Trigger</div>
```

事件处理程序可以绑定到文本输入： 

```js
$('.target').select(function() {
  $(this).log('Select event was triggered.');
});
```

现在当文本的任何部分被选中时，消息将被显示。仅设置插入点的位置不会触发事件。当单击按钮时，我们可以手动触发事件：

```js
$('.trigger').click(function() {
  $('.target').select();
});
```

执行此代码后，单击**触发**按钮也会显示消息。此外，字段上的默认`select`操作将被触发，因此整个文本字段将被选中。

## .submit()

| 将事件处理程序绑定到提交 JavaScript 事件，或在元素上触发该事件。

```js
.submit(handler)
.submit()

```

|

### 参数（第一个版本）

+   处理程序：每次触发事件时执行的函数

### 返回值

用于链式调用目的的 jQuery 对象。

### 描述

此处理程序是第一种情况中`.bind('submit', handler)`的快捷方式，以及第二种情况中的`.trigger('submit')`。

当用户尝试提交表单时，`submit`事件将被发送到元素。它只能附加到`<form>`元素上。表单可以通过点击显式的`<input type="submit">`按钮提交，或者当表单元素具有焦点时按**Enter**。

### 注意

根据浏览器的不同，*Enter*键可能仅在表单中有一个文本字段时触发表单提交，或者只有在存在提交按钮时才触发。界面不应依赖于此键的特定行为，除非通过观察`keypress`事件来强制解决*Enter*键的问题。

例如，考虑 HTML：

```js
<form class="target" action="foo.html">
  <input type="text" />
  <input type="submit" value="Go" />
</form>
<div class="trigger button">Trigger</div>
```

事件处理程序可以绑定到表单：

```js
$('.target').submit(function() {
  $(this).log('Submit event was triggered.');
});
```

现在，当表单提交时，将显示消息。这发生在实际提交之前，因此我们可以通过在事件上调用`.preventDefault()`或从处理程序中返回`false`来取消提交操作。当单击按钮时，我们可以手动触发事件：

```js
$('.trigger').click(function() {
  $('.target').submit();
});
```

执行此代码后，单击**触发**按钮也会显示消息。此外，表单上的默认提交操作也将触发，因此将提交表单。

# 键盘事件

这些事件是由键盘上的键触发的。

## `.keydown()`

| 将事件处理程序绑定到 keydown JavaScript 事件，或在元素上触发该事件。

```js
.keydown(handler)
.keydown()

```

|

### 参数（第一个版本）

+   处理程序：每次触发事件时执行的函数

### 返回值

jQuery 对象，用于链式调用。

### 描述

此处理程序是第一个变体中`.bind('keydown', handler)`的快捷方式，并且是第二个变体中`.trigger('keydown')`的快捷方式。

当用户首次在键盘上按下键时，将向元素发送`keydown`事件。它可以附加到任何元素，但事件只会发送到具有焦点的元素。可获取焦点的元素在各个浏览器中可能不同，但表单元素始终可以获取焦点，因此是此事件类型的合理候选对象。

例如，考虑 HTML：

```js
<form>
  <input class="target" type="text" />
</form>
<div class="trigger button">Trigger</div>
```

事件处理程序可以绑定到输入字段：

```js
$('.target').keydown(function() {
  $(this).log('Keydown event was triggered.');
});
```

现在，当插入点位于字段内部且按下键时，将显示消息。当单击按钮时，我们可以手动触发事件：

```js
$('.trigger').click(function() {
  $('.target').keydown();
});
```

执行此代码后，单击**触发器**按钮也会显示消息。

如果需要捕获任何地方的按键（例如，在页面上实现全局快捷键），将此行为附加到`document`对象是很有用的。由于事件冒泡，除非明确停止，所有按键都会向上冒泡到`document`对象。

要确定按下了哪个键，我们可以检查传递给处理程序函数的事件对象。`.keyCode`属性通常保存此信息，但在一些较旧的浏览器中，`.which`存储键码。JavaScript 的`String`对象具有`.fromCharCode()`方法，可用于将此数值代码转换为包含字符的字符串，以进行进一步处理。

`fix_events.js`插件进一步标准化了不同浏览器中的事件对象。使用此插件，我们可以在所有浏览器中使用`.which`来检索键码。

## `.keypress()`

| 将事件处理程序绑定到 keypress JavaScript 事件，或在元素上触发该事件。

```js
.keypress(handler)
.keypress()

```

|

### 参数（第一个版本）

+   handler：每次触发事件时要执行的函数

### 返回值

jQuery 对象，用于链式调用。

### 描述

此处理程序是第一个版本中 `.bind('keypress', handler)` 的快捷方式，第二个版本中是 `.trigger('keypress')` 的快捷方式。

`keypress` 事件在浏览器注册键盘输入时发送到元素。这类似于 `keydown` 事件，但在按键重复的情况下不同。如果用户按住键不放，`keydown` 事件会触发一次，但每个插入的字符都会触发单独的 `keypress` 事件。此外，修改键（例如*Shift*）会引发 `keydown` 事件，但不会引发 `keypress` 事件。

可以将 `keypress` 事件处理程序附加到任何元素，但事件只会发送到具有焦点的元素。可获得焦点的元素在浏览器之间可能有所不同，但表单元素总是可以获得焦点的，因此是此事件类型的合理候选对象。

例如，考虑以下 HTML：

```js
<form>
  <input class="target" type="text" />
</form>
<div class="trigger button">Trigger</div>
```

可以将事件处理程序绑定到输入字段上：

```js
$('.target').keypress(function() {
  $(this).log('Keypress event was triggered.');
});
```

现在，当插入点位于字段内并按下键时，消息会显示出来。如果按住键不放，消息会重复显示。当按钮被点击时，我们可以手动触发事件：

```js
$('.trigger').click(function() {
  $('.target').keypress();
});
```

执行此代码后，点击**触发**按钮也会显示消息。

如果需要捕获任何地方的按键（例如，在页面上实现全局快捷键），将此行为附加到 `document` 对象是有用的。除非明确因为事件冒泡而被停止，否则所有按键都会向上 DOM 到达 `document` 对象。

要确定按下了哪个键，我们可以检查传递给处理程序函数的事件对象。`.keyCode` 属性通常保存此信息，但在一些较旧的浏览器中，`.which` 存储键码。JavaScript 的 `String` 对象具有 `.fromCharCode()` 方法，可用于将此数值代码转换为包含字符的字符串，以供进一步处理。

请注意，`keydown` 和 `keyup` 提供指示按下哪个键的代码，而 `keypress` 指示输入了哪个字符。例如，小写字母 "a" 将被 `keydown` 和 `keyup` 报告为 65，但被 `keypress` 报告为 97。大写字母 "A" 在所有事件中都报告为 97。这可能是决定使用哪种事件类型的主要动机。

## .keyup()

| 将事件处理程序绑定到 keyup JavaScript 事件，或在元素上触发该事件。

```js
.keyup(handler)
.keyup()

```

|

### 参数（第一个版本）

+   handler：每次触发事件时要执行的函数

### 返回值

jQuery 对象，用于链式调用。

### 描述

此处理程序是第一个版本中 `.bind('keyup', handler)` 的快捷方式，第二个版本中是 `.trigger('keyup')` 的快捷方式。

当用户释放键盘上的按键时，`keyup`事件将发送到元素。它可以附加到任何元素，但事件仅发送到具有焦点的元素。可聚焦元素在不同浏览器之间可能有所不同，但表单元素始终可以获得焦点，因此是此事件类型的合理候选者。

例如，请考虑以下 HTML：

```js
<form>
  <input class="target" type="text" />
</form>
<div class="trigger button">Trigger</div>
```

事件处理程序可以绑定到输入字段上：

```js
$('.target').keyup(function() {
  $(this).log('Keyup event was triggered.');
});
```

现在当插入点位于字段内并按下并释放键时，消息将显示。当点击按钮时，我们可以手动触发事件：

```js
$('.trigger').click(function() {
  $('.target').keyup();
});
```

执行此代码后，点击**Trigger**按钮也将显示消息。

如果需要捕获任何地方的按键（例如，在页面上实现全局快捷键），将此行为附加到`document`对象是有用的。所有按键都会通过 DOM 上升到`document`对象，除非由于事件冒泡而明确停止。

要确定按下了哪个键，我们可以检查传递给处理程序函数的事件对象。`.keyCode`属性通常保存此信息，但在一些较旧的浏览器中，`.which`存储键码。JavaScript 的`String`对象有一个`.fromCharCode()`方法，可以用来将这个数值代码转换为包含字符的字符串以进行进一步处理。

# 浏览器事件

这些事件与整个浏览器窗口相关。

## .resize()

| 绑定一个事件处理程序到 resize JavaScript 事件，或在元素上触发该事件。

```js
.resize(handler)
.resize()

```

|

### 参数（第一个版本）

+   处理程序：每次触发事件时执行的函数

### 返回值

用于链式调用的 jQuery 对象。

### 描述

此处理程序是第一种情况下`.bind('resize', handler)`的快捷方式，以及第二种情况下的`.trigger('resize')`。

当浏览器窗口的大小改变时，`resize`事件将发送到`window`元素：

```js
$(window).resize(function() {
  alert('Resize event was triggered.');
});
```

现在每当浏览器窗口的大小改变时，消息将显示。

在`resize`处理程序中的代码永远不应该依赖于处理程序被调用的次数。根据实现方式，`resize`事件可以在调整大小正在进行时持续发送（在 Internet Explorer 中的典型行为），或者仅在调整大小操作结束时发送一次（在 FireFox 中的典型行为）。

## .scroll()

| 绑定一个事件处理程序到 scroll JavaScript 事件，或在元素上触发该事件。

```js
.scroll(handler)
.scroll()

```

|

### 参数

+   处理程序：每次触发事件时执行的函数

### 返回值

用于链式调用的 jQuery 对象。

### 描述

此处理程序是第一种情况下`.bind('scroll', handler)`的快捷方式，以及第二种情况下的`.trigger('scroll')`。

当用户滚动到元素的不同位置时，`scroll`事件将发送到该元素。它不仅适用于`window`对象，还适用于可滚动的框架和具有`overflow: scroll`CSS 属性的元素。

例如，请考虑以下 HTML：

```js
<div class="target" style="overflow: scroll; width: 200px; height: 100px;">
  Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
</div>
<div class="trigger button">Trigger</div>
```

样式定义存在是为了使目标元素足够小，以便滚动。可以将`scroll`事件处理程序绑定到此元素上：

```js
$('.target').scroll(function() {
  $(this).log('Scroll event was triggered.');
});
```

现在，当用户将文本向上或向下滚动时，消息会被显示出来。当点击按钮时，我们可以手动触发事件：

```js
$('.trigger').click(function() {
  $('.target').scroll();
});
```

执行此代码后，点击**触发器**按钮也会显示消息。

每当元素的滚动位置发生变化时，都会发送`scroll`事件，而不管原因是什么。鼠标点击或拖动滚动条，在元素内拖动，按箭头键，或使用鼠标滚轮都可能引起此事件。
