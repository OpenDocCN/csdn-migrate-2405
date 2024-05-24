# jQueryUI 1.10：jQuery 的用户界面库（二）

> 原文：[`zh.annas-archive.org/md5/67D4BB507B37025C38972681032F3C25`](https://zh.annas-archive.org/md5/67D4BB507B37025C38972681032F3C25)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：手风琴小部件

手风琴小部件是另一个 UI 小部件，允许您将内容分组到可以通过访问者交互打开或关闭的单独面板中。因此，大部分内容最初都是从视图中隐藏的，就像我们在上一章中看到的选项卡小部件一样。

每个容器都有一个与之关联的标题元素，用于打开容器并显示内容。当单击标题时，其内容将以动画形式滑入视图下方。当前可见的内容被隐藏，当我们单击手风琴标题时，新内容被显示。

在本章中，我们将涵盖以下主题：

+   手风琴小部件的结构

+   手风琴的默认实现

+   添加自定义样式

+   使用可配置的选项来设置不同的行为

+   使用控制手风琴的方法

+   内置的动画类型

+   自定义手风琴事件

手风琴小部件是一个强大且高度可配置的小部件，允许您通过在任何时候仅显示单个内容面板来节省网页空间。

下图显示了手风琴小部件的一个示例：

![手风琴小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_04_01.jpg)

对于我们的访问者来说易于使用，对于我们来说易于实现。它具有一系列可配置的选项，可用于自定义其外观和行为，并公开一系列方法，允许您以编程方式控制它。它还带有丰富的交互事件集，我们可以用来挂钩我们的访问者与小部件之间的关键交互。

手风琴容器元素的高度将自动设置，以便在标题之外还有足够的空间来显示最高的内容面板。此外，默认情况下，小部件的大小将保持固定，因此在打开或关闭内容面板时不会将页面上的其他元素推到一边。

# 结构化手风琴小部件

让我们花点时间熟悉一下手风琴的基本标记。在外部容器内是一系列链接。这些链接是手风琴内的标题，每个标题都会有一个对应的内容面板，在点击标题时打开。

值得记住的是，在使用手风琴小部件时一次只能打开一个内容面板。在文本编辑器中的空白页上，创建以下页面：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Accordion</title>  
  <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
  <script src="img/jquery-2.0.3.js"></script>
  <script src="img/jquery.ui.core.js"></script>
  <script src="img/jquery.ui.widget.js"> </script>  
  <script src="img/jquery.ui.accordion.js"> </script>
  <script>
    $(document).ready(function($) {
      $("#myAccordion").accordion();
    });
  </script>
</head>
<body>
  <div id="myAccordion">
    <h2><a href="#">Header 1</a></h2>
    <div>Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean sollicitudin. Sed interdum pulvinar justo.
    Nam iaculis volutpat ligula. Integer vitae felis quis diam laoreet ullamcorper.</div>

    <h2><a href="#">Header 2</a></h2>
    <div>Etiam tincidunt est vitae est. Ut posuere, mauris at sodales rutrum, turpis tellus fermentum metus, ut
    bibendum velit enim eu lectus. Suspendisse potenti.</div>

    <h2><a href="#">Header 3</a></h2>
    <div>Donec at dolor ac metus pharetra aliquam. Suspendisse purus. Fusce tempor ultrices libero. Sed
    quis nunc. Pellentesque tincidunt viverra felis. Integer elit mauris, egestas ultricies, gravida vitae,
    feugiat a, tellus.</div>
  </div>
</body>
</html>
```

将文件保存为`accordion1.html`，放在`jqueryui`文件夹中，并在浏览器中尝试运行。该小部件应该与本章开头的屏幕截图一样，完全皮肤化并准备好使用。

以下列表显示了小部件所需的依赖关系：

+   `jquery.ui.all.css`

+   `jquery-2.0.3.js`

+   `jquery.ui.core.js`

+   `jquery.ui.widget.js`

+   `jquery.ui.accordion.js`

正如我们在标签小部件中看到的，每个小部件都有其自己的源文件（尽管它可能依赖于其他文件来提供功能）；这些必须按正确的顺序引用，以使小部件正常工作。 jQuery 库必须始终首先出现，然后是`jquery.ui.core.js`文件。之后，必须跟随包含所需依赖项的文件。这些文件应在引用小部件的 on-script 文件之前出现。如果文件没有按正确的顺序加载，则库组件将无法按预期的方式工作。

用于手风琴的底层标记是灵活的，小部件可以由各种不同的结构构建。在这个例子中，手风琴标题由包裹在`<h2>`元素中的链接组成，内容面板是简单的`<div>`元素。

要使手风琴正常工作，每个内容面板应该直接出现在其对应的标题之后。所有小部件的元素都被封装在一个`<div>`容器中，该容器被`accordion()`小部件方法所选中。

在从库中获取所需的脚本依赖项之后，我们使用自定义`<script>`块将底层标记转换为手风琴。

要初始化小部件，我们使用一个简单的 ID 选择器`$("#myAccordion")`，指定包含小部件标记的元素，然后在选择器后面链式调用`accordion()`小部件方法来创建手风琴。

在这个例子中，我们在标签标题元素中使用空片段（`#`）作为`href`属性的值，例如：

```js
<h2><a href="#">Header 1</a></h2>
```

你应该注意，默认情况下，单击手风琴标题时不会跟随任何为手风琴标题提供的 URL。

与我们在上一章中看到的标签小部件类似，当小部件被初始化时，被转换为手风琴的底层标记具有一系列的类名添加到其中。

一些组成小部件的不同元素被赋予`role`和`aria-`属性。

### 注意

**可访问的丰富互联网应用程序**（**ARIA**）是确保丰富互联网应用程序对辅助技术保持可访问性的 W3C 推荐。

最初从视图中隐藏的手风琴面板被赋予`aria-expanded="false"`属性，以确保屏幕阅读器不会丢弃或无法访问使用`display: none`隐藏的内容。这使得手风琴小部件高度可访问；它阻止读者不必要地浏览可能被隐藏的大量内容，并告诉用户他们也可以展开或折叠面板，具体取决于`aria-expanded`属性的当前值。

# 为手风琴添加样式

ThemeRoller 是选择或创建手风琴小部件主题的推荐工具，但有时我们可能希望在 ThemeRoller 无法实现的情况下，大幅改变小部件的外观和样式。在这种情况下，我们可以自定义样式我们自己的手风琴—在我们的示例中，我们将拉平样式效果，添加边框，并从手风琴小部件中的一些元素中移除角落。

在您的文本编辑器中的新文件中添加以下代码：

```js
#myAccordion { width: 400px; border: 1px solid #636363; padding-bottom: 1px; }
#myAccordion .ui-state-active { background: #fff; } 
.ui-accordion-header { border: 1px solid #fff; font-family:
  Georgia; background: #e2e2e2 none; }
.ui-widget-content { font-size: 70%; border: none; }
.ui-corner-all { border-radius: 0; }
.ui-accordion .ui-accordion-header { margin: 0 0 -1px; } 
```

将此文件保存为`accordionTheme.css`，放在 css 文件夹中，并在`accordion1.html`的`<head>`元素中的 jQuery UI 样式表之后链接到它：

```js
<link rel="stylesheet" href="css/accordionTheme.css">
```

将新文件保存为`accordion2.html`，放在`jqueryui`文件夹中，并在浏览器中查看。它应该看起来像下面这样：

![为手风琴设置样式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_04_02.jpg)

如前面的截图所示，我们已禁用了主题文件添加的内置圆角，并设置了替代字体、背景颜色和边框颜色。我们并没有大幅度更改小部件，但我们也没有使用许多样式规则。通过这种方式继续覆盖规则来构建一个更复杂的自定义主题将会很容易。

# 配置手风琴

手风琴具有一系列可配置选项，允许我们更改小部件的默认行为。下表列出了可用选项、它们的默认值，并简要描述了它们的用法：

| 选项 | 默认值 | 使用 |
| --- | --- | --- |
| `active` | `first child`（第一个面板是打开的） | 在页面加载时设置活动标题。 |
| `animate` | `{}` | 控制面板的动画效果。 |
| `collapsible` | `false` | 允许同时关闭所有内容面板。 |
| `disabled` | `false` | 禁用小部件。 |
| `event` | `"click"` | 指定触发打开抽屉的标题上的事件。 |
| `header` | `"> li >:first-child,> :not(li):even"` | 设置标题元素的选择器。尽管看起来复杂，但这是一个标准的 jQuery 选择器，只是简单地针对每个奇数`<li>`元素中的第一个子元素。 |
| `heightStyle` | `"auto"` | 控制手风琴和每个面板的高度 |
| `icons` | `'header': 'ui-icontriangle-1-e', 'headerSelected': 'uiicon- triangle-1-s'` | 指定标题元素和选定状态的图标。 |

# 更改触发事件

大多数选项都是不言自明的，它们接受的值通常是布尔值、字符串或元素选择器。让我们使用其中一些，以便我们可以探索它们的功能。将`accordion2.html`中的最后一个`<script>`元素更改为如下所示：

```js
<script>
  $(document).ready(function($) {
 var accOpts = {
 event:"mouseover"
 }
    $("#myAccordion").accordion(accOpts);
  });
</script>
```

我们不再需要在`accordion2.html`中添加的自定义样式表，所以继续从代码中删除以下行：

```js
  <link rel="stylesheet" href="css/accordionTheme.css">
```

将这些更改保存为`accordion3.html`。首先，我们创建一个名为`accOpts`的新对象字面量，其中包含`event`键和`mouseover`值，这是我们希望用来触发打开手风琴面板的事件。我们将这个对象作为参数传递给`accordion()`方法，并且它覆盖了小部件的默认选项，即`click`。

`mouseover`事件通常用作替代触发事件。也可以使用其他事件，例如，我们可以将`keydown`设置为事件，但是为了使其工作，我们希望打开的手风琴面板必须已经聚焦。您应该注意，您还可以在小部件方法中使用内联对象设置选项，而不需要创建单独的对象。使用以下代码同样有效，并且通常是编码的首选方式，这是我们在本书的其余部分中将使用的方式：

```js
<script>
  $(function() {
 $("#myAccordion").accordion({ 
 event: "mouseover" 
 });
  });
</script>
```

# 更改默认活动头

默认情况下，手风琴的第一个标题在小部件呈现时将被选中，并显示其内容面板。我们可以使用`active`选项在页面加载时更改选定的标题。将`accordion3.html`中的配置`<script>`块更改为以下内容：

```js
  <script>
    $(document).ready(function($) {
      $("#myAccordion").accordion({
        active: 2
      });
    });
  </script>
```

将此版本保存为`accordion4.html`。我们将`active`选项设置为整数`2`，以默认打开第三个内容面板，并且与我们在上一章中看到的选项标题类似，手风琴的标题使用从零开始的索引。除了整数，此选项还接受 jQuery 选择器或原始 DOM 元素。

我们还可以使用布尔值`false`来配置手风琴，以使默认情况下不打开任何内容面板。再次更改配置对象如下：

```js
  <script>
    $(document).ready(function($) {
      $("#myAccordion").accordion({
 collapsible: true, 
 active: false
      });
    });
  </script>
```

### 注意

如果使用`active: false`选项，必须还包括`collapsible`选项，该选项必须设置为`true`才能使`active`正确工作。

将此保存为`accordion5.html`。现在当页面加载时，所有内容面板都被隐藏了：

![更改默认活动标题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_04_03.jpg)

手风琴将保持关闭状态，直到选择其中一个标题，该标题将保持打开状态，除非单击活动标题；在此时，其关联的内容面板将关闭。为了便于使用，最好避免在同一实现中同时配置此选项和`mouseover`事件选项，因为即使用户无意中将鼠标移到其上并再次移动，打开的面板也会关闭。

# 填充其容器的高度

如果设置了`heightStyle`选项，它将强制手风琴占据其容器的全部高度。到目前为止，我们的示例中，手风琴的容器一直是页面的主体，而页面主体的高度只能是其最大元素的高度。我们需要使用一个具有固定高度的新容器元素来查看此选项的效果。

在`accordion5.html`的`<head>`元素中，添加以下`<style>`元素：

```js
<style>
  #container { height: 600px; width: 400px; }
</style>
```

然后，将手风琴的所有底层标记包装在一个新的容器元素中，如下所示：

```js
<div id="container">
  <div id="myAccordion">
    <h2><a href="#">Header 1</a></h2>
    <div>Lorem ipsum dolor sit amet, consectetuer adipiscing   elit. Aenean sollicitudin. Sed interdum pulvinar justo. Nam iaculis volutpat ligula. Integer vitae felis quis diam laoreet ullam corper.</div>
    <h2><a href="#">Header 2</a></h2>
    <div>Etiam tincidunt est vitae est. Ut posuere, mauris at 
sodales rutrum, turpis tellus fermentum metus, ut bibendum 
velit enim eu lectus. Suspendisse potenti.</div>
     <h2><a href="#">Header 3</a></h2>
     <div>Donec at dolor ac metus pharetra aliquam. Suspendisse purus. Fusce tempor ultrices libero. Sed quis nunc. Pellentesque tincidunt viverra felis. Integer elit mauris, egestas ultricies, gravida vitae, feugiat a, tellus.</div>
  </div>
</div>

```

最后，更改我们自定义 `<script>` 元素中的配置对象，使其如下所示：

```js
  <script>
    $(document).ready(function($) {
      $("#myAccordion").accordion({
 heightStyle: "fill" 
      });
    });
  </script>
```

将更改保存为 `accordion6.html`。使用页面 `<head>` 元素中指定的 CSS 为新容器指定了固定的高度和宽度。

### 注意

在大多数情况下，您将希望创建一个单独的样式表。对于我们的目的，只有一个选择器和两个规则，使用 HTML 文件中的样式标记最为方便。

选项 `heightStyle` 强制手风琴占据整个容器的高度，限制容器的宽度自然也会减小小部件的宽度。这个页面应该显示如下：

![填充其容器的高度](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_04_04.jpg)

# 使用手风琴动画

手风琴小部件附带了默认启用的内置幻灯片动画，在我们所有的示例中都存在。禁用此动画只需将 `animate` 选项的值设为 `false` 即可。从页面的 `<head>` 元素中删除 `<style>` 标签，在 `accordion6.html` 中删除额外的容器 `<div>`，然后更改配置对象，使其如下所示：

```js
  <script>
    $(document).ready(function($) {
      $("#myAccordion").accordion({
 animate: false
      });
    });
  </script>
```

将其保存为 `accordion7.html`。这将导致每个内容面板立即打开，而不是在单击标头时漂亮地滑动打开。

小部件中还构建了另一种备用动画——`EaseOutBounce` 动画。然而，要使用这个备用动画，我们需要在 `jquery.ui.effect.js` 文件中添加一个链接。

在 `<head>` 元素顶部的 `jquery.ui.accordion.js` 链接后，添加以下一行代码：

```js
<script src="img/jquery.ui.effect.js"></script>
```

现在，更改我们自定义 `<script>` 元素中的配置对象，使其如下所示：

```js
  <script>
    $(document).ready(function($) {
      $("#myAccordion").accordion({
 animate: {
 duration: 600,
 down: {
 easing: "easeOutBounce",
 duration: 1000
 }
 }
      });
    });
  </script>
```

将这些更改保存为 `accordion8.html`。尽管手风琴面板的关闭方式与之前的示例完全相同，但在打开时，它们会在动画结束时反弹几次。这是使动画更有趣的好方法，正如我们在这个示例中看到的那样，使用起来非常简单。

除了两个预配置的动画之外，我们还可以使用 `jquery.ui.effect.js` 文件中定义的任何不同的缓动效果，包括以下内容：

+   `easeInQuad`

+   `easeInCubic`

+   `easeInQuart`

+   `easeInQuint`

+   `easeInSine`

+   `easeInExpo`

+   `easeInCirc`

+   `easeInElastic`

+   `easeInBack`

+   `easeInBounce`

这些缓动方法的每一个都有相应的 `easeOut` 和 `easeInOut` 对应方法。完整列表，请参见 `jquery.ui.effect.js` 文件，或参考 第十四章 中的缓动表，*UI Effects*。

### 注意

在 [`jqueryui.com/accordion/`](http://jqueryui.com/accordion/) 查看 jQuery UI 演示站点，以了解一些很棒的手风琴效果示例。这些效果可以应用于任何可以进行动画处理的小部件，例如手风琴、选项卡、对话框或日期选择器。

缓动效果不会改变底层动画，仍然基于幻灯片动画。但它们确实改变了动画的进展方式。例如，我们可以通过在配置对象中使用 `easeInOutBounce` 缓动效果来使内容面板在动画开始和结束时都跳动：

```js
<script>
  $(document).ready(function($) {
    $("#myAccordion").accordion({
      animate: {
        duration: 600,
        down: {
 easing: "easeInOutBounce",
          duration: 1000
        }
      }
    });
  });
</script>
```

将此文件保存为 `accordion9.html` 并在浏览器中查看。大多数缓动效果都有相反的效果，例如，我们可以使用 `easeInBounce` 缓动效果使内容面板在动画开始时跳动，而不是在动画结束时跳动。

对动画产生影响的另一个选项是 `heightStyle` 属性，在每次动画后重置 `height` 和 `overflow` 样式。请记住，默认情况下启用动画，但此选项不会启用。将 `accordion9.html` 中的配置对象更改为以下内容：

```js
$(document).ready(function($) {
  $("#myAccordion").accordion({
 heightStyle: "content",
    animate: {
      duration: 600,
      down: {
 easing: "easeOutBounce",
        duration: 1000
      }
    }
  });
});
```

将此保存为 `accordion10.html`。现在运行页面时，手风琴不会保持固定尺寸；它将根据每个面板中的内容量而增长或缩小。在这个示例中并没有什么区别，但是在使用动态内容时，该属性确实会发挥作用，因为在面板内容频繁更改时，我们可能并不总是知道每个面板中会有多少内容。

# 列出手风琴事件

手风琴公开了三个自定义事件，列在下表中：

| 事件 | 触发时... |
| --- | --- |
| `activate` | 活动标题已更改。 |
| `beforeActivate` | 活动标题即将更改 |
| `create` | 小部件已创建 |

每次活动标题（及其关联的内容面板）更改时触发 `activate` 事件。它在内容面板打开动画结束时触发，或者如果禁用动画，则立即触发（但仍在激活面板更改后）。

`beforeActivate` 事件在选择新标题后立即触发（即在打开动画之前），或者如果动画被禁用，则在激活面板已更改之前触发。`create` 事件在小部件初始化后立即触发。

# 使用 change 事件

让我们看看如何在我们的手风琴实现中使用这些事件。在 `accordion10.html` 中，将配置对象更改为如下所示：

```js
$(document).ready(function($) {
  var statustext;
  $("#myAccordion").accordion({
    activate: function(e, ui) {
      $(".notify").remove();
      Statustext = $("<div />", {
        "class": "notify",
         text: [
           ui.newHeader.find("a").text(), "was activated,",
           ui.oldHeader.find("a").text(), "was closed"
         ].join(" ")
      });
      statusText.insertAfter("#myAccordion").fadeOut(2000, function(){
        $(this).remove();
      });
    }
  });
});
```

将此保存为 `accordion11.html`。在此示例中，我们使用 `activate` 配置选项来指定一个匿名回调函数，该函数每当活动面板更改时都会执行。此函数会自动接收两个对象作为参数。第一个对象是 `event` 对象，其中包含原始的浏览器 `event` 对象。

第二个参数是一个对象，其中包含有关小部件的有用信息，例如激活了哪个标题元素（`ui.newHeader`）和被关闭的标题（`ui.oldHeader`）。第二个对象是一个 jQuery 对象，因此我们可以直接在它上面调用 jQuery 方法。

在此示例中，我们导航到标题中的`<a>`元素，并在信息框中显示其文本内容，然后将其附加到页面并在短时间后使用淡入动画移除。

供参考，`ui`对象还提供了有关内容面板的信息，以`ui.newPanel`和`ui.oldPanel`属性的形式。

一旦激活了标题并显示了其内容面板，将生成通知：

![使用 change 事件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_04_05.jpg)

# 配置 beforeActivate 事件

`beforeActivate`事件可以以完全相同的方式使用，并且我们使用此事件指定的任何回调函数也会收到`e`和`ui`对象以使用。

将上一个示例中的配置对象更改为如下所示：

```js
$(document).ready(function($) {
  var statusText;
  $("#myAccordion").accordion({
 beforeActivate: function(e, ui) {
      statusText = $("<div />", {
        "class": "notify",
        text: [ui.newHeader.find("a").text(),
          "was activated,", ui.oldHeader.find("a").text(),
          "was closed"].join(" ");
      });
      statusText.insertAfter("#myAccordion")
        .fadeOut(2000, function() {
          $(this).remove();
      });
    }
  });
});
```

将此保存为`accordion12.html`。唯一更改的是我们使用配置对象定位的属性。当我们运行页面时，我们应该发现一切都与之前完全相同，只是我们的通知是在内容面板动画之前而不是之后产生的。

还有诸如`accordionactivate`和`accordionbeforeactivate`之类的事件，可与标准 jQuery `on()` 方法一起使用，以便我们可以指定在手风琴配置之外执行的回调函数。使用此方式的事件处理程序可以让我们精确地响应特定事件而触发它，而不是在页面渲染在屏幕上时触发。

例如，让我们重新设计刚刚创建的演示的脚本块，以使用`accordionbeforeactivate`事件处理程序。如果您想改用此格式，只需用以下脚本替换`accordion12.html`中的`<script>`块-您可以在代码中看到主要更改已突出显示：

```js
<script>
  $(document).ready(function($) {
    var statusText;
    $("#myAccordion").accordion();

 $(document).on( "accordionbeforeactivate", function(e, ui) {
      statusText = $("<div />", {
        "class": "notify",
        text: [ui.newHeader.find("a").text(), "was activated, ", ui.oldHeader.find("a").text(), "was closed"].join(" ")
      });
      statusText.insertAfter("#myAccordion")
        .fadeOut(2000, function() {
        $(this).remove();
      });
 });
  });
</script>
```

在此示例中，我们将`beforeActivate`事件处理程序从主配置调用中移出到 Accordion，并将其绑定到了文档对象；我们同样可以将其绑定到页面上的按钮或超链接等对象上。

# 解释手风琴方法

手风琴包括一系列方法，允许您以编程方式控制和操作小部件的行为。一些方法对库的每个组件都是通用的，例如每个小部件都使用的`destroy`方法。以下表列出了手风琴小部件的唯一方法：

| 方法 | 用途 |
| --- | --- |
| `refresh` | 重新计算手风琴面板的高度；结果取决于内容和`heightStyle`选项 |

## 标题激活

`option`方法可用于以编程方式显示或隐藏不同的抽屉。我们可以使用文本框和新按钮轻松测试此方法。在`accordion12.html`中，直接在手风琴后面添加以下新标记：

```js
<label for="activateChoice">Enter a header index to activate   </label>
<input id="activateChoice">
<button type="button" id="activate">Activate</button>
```

现在将`<script>`元素更改为以下内容： 

```js
<script>
  $(document).ready(function($) {
    var drawer = parseInt($("#activateChoice").val(), 10);

 $("#myAccordion").accordion();
 $("#activate").click(function() {
 $("#myAccordion").accordion("option", "active", drawer);
 });
  });
</script>
```

将新文件保存为`accordion13.html`。`option`方法需要两个额外的参数。它期望接收要使用的选项的名称，以及要激活的标题元素的索引（从零开始的）编号。在本示例中，我们通过返回文本输入的值来获得要激活的标题。我们使用 JavaScript 的`parseInt()`函数将其转换为整数，因为`val()` jQuery 方法返回字符串。

如果指定了不存在的索引号，则不会发生任何事情。如果未指定索引，则将激活第一个标题。如果指定了除整数以外的值，则不会发生任何事情；脚本将静默失败，而不会出现任何错误，并且手风琴将继续正常工作。

# 添加或删除面板

在 1.10 版本之前，更改手风琴中面板数量的唯一方法是销毁它并重新初始化一个新实例。虽然这样做可以，但这不是实施任何更改的满意方式，考虑到这一点，jQuery 团队努力介绍了一种新方法，该方法使其与其他小部件保持一致，这些小部件不需要重新创建即可更改任何已配置的选项。让我们使用输入按钮来测试这种方法，以创建我们的新面板。

在`accordion13.html`中，将手风琴下面的标记更改为以下代码：

```js
<p>
 <button type="button" id="addAccordion">Add Accordion</button>
</p>
```

修改`<script>`块，使其如下所示：

```js
<script>
  $(document).ready(function($) {
    $("#myAccordion").accordion();
 $('#addAccordion').click( function() {
 var newDiv = "<h2><a ref='#'>New Header</a></h2><div>New Content</div>";
 $("#myAccordion").append(newDiv).accordion("refresh"); 
 });
  });
</script>
```

将新文件保存为`accordion14.html`。在本示例中，我们已经为新的手风琴面板创建了额外的标记内容，并将其分配给`newDiv`变量。然后我们将其附加到`myAccordion` `<div>`，然后使用手风琴的`refresh`方法刷新它。这不需要任何参数。

### 注意

我们已指定在每个手风琴面板的标记中使用的默认文本。只要保持相同的标记，就可以轻松修改为包含所需文本，这是可以的。

页面加载时，我们可以单击**Add Accordion**以添加任意数量的新手风琴面板，如下图所示：

![添加或删除面板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_04_06.jpg)

但是，如果我们需要删除手风琴面板，则需要更多的工作 - 标记分为两部分（标题和面板），因此我们必须分别删除两者。修改手风琴下面的标记：

```js
<p>  
  <label>Enter a tab to remove:</label>
  <input for="indexNum" id="indexNum">
  <button type="button" id="remove">Remove!</button>
</p>
```

现在将`<script>`块更改如下：

```js
<script>
  $(document).ready(function($) {
    function removeDrawer(removeIndex) {
      $("#myAccordion").find("h2").eq(removeIndex).remove();
      $("#myAccordion").find("div").eq(removeIndex).remove();
      $("#myAccordion").accordion("refresh");   
    }
    $("#myAccordion").accordion();
    $("#remove").click(function(event, ui) {
      var removeIndex = $("#indexNum").val();
      removeDrawer(removeIndex);
    });
  });
</script>
```

将新文件保存为`accordion15.html`；页面加载时，输入`1`并单击**Remove**以删除中间标题及其面板：

![添加或删除面板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_04_07.jpg)

在本示例中，我们通过返回文本输入的值来获取要删除的手风琴。如果指定了不存在的索引号，则不会发生任何事情。

然后，我们使用`eq()`根据给定的值查找要删除的标题和面板，一旦找到，它们就会被删除。最后一步是`refresh`手风琴，以便然后可以选择新的标题和面板。

# 调整手风琴面板的大小

修改`accordion10.html`中手风琴小部件的基础标记，以便第三个标题指向一个远程文本文件，第三个面板为空。标题元素还应该有一个`id`属性：

```js
<div id="myAccordion">
  <h2><a href="#">Header 1</a></h2>
  <div>Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean sollicitudin. Sed interdum pulvinar justo. Nam iaculis volutpat ligula. Integer vitae felis quis diam laoreet ullamcorper.</div>
  <h2><a href="#">Header 2</a></h2>
  <div>Etiam tincidunt est vitae est. Ut posuere, mauris at sodales rutrum, turpis tellus fermentum metus, ut bibendum velit enim eu lectus. Suspendisse poten-ti.</div>
 <h2 id="remote"><a href="remoteAccordion.txt">Remote</a></h2>
 <div></div>
</div>
```

您将在代码中看到，我们已经引用了一个文本文件，该文件将托管我们的远程内容。在编辑器中新建一个文件，添加一些虚拟文本，并将其保存为`remoteAccordion.txt`。 （此书附带的代码下载中提供了此文件的副本）。

然后将最终的`<script>`元素更改为以下形式：

```js
$(document).ready(function($) {
  $("#myAccordion").accordion({
    beforeActivate: function(e, ui) {
      if (ui.newHeader.attr("id") === "remote") {
        $.get(ui.newHeader.find("a").attr("href"),
        function(data) {
          ui.newHeader.next().text(data);
        });
      }
    },
    activate: function(e, ui) {      
      ui.newHeader.closest("#myAccordion").accordion("refresh");
    }
  });
});
```

将此文件保存为`accordion16.html`。要正确查看此示例，您需要安装本地 Web 服务器，如 WAMP（对于 PC）或 MAMP（Mac），否则将不会呈现`remoteAccordion.txt`文件的内容。

在我们的配置对象中，我们使用`beforeActivate`事件来检查元素的`id`是否与我们给远程手风琴标题的`id`匹配。

如果是这样，我们使用 jQuery 的`get()`方法获取`<a>`元素的`href`属性中指定的文本文件的内容。如果请求成功返回，我们在标题之后将文本文件的内容添加到空面板中。所有这些都发生在面板打开之前。

然后我们使用`activate`事件在面板打开后调用手风琴的`refresh`方法。

当我们在浏览器中运行页面时，远程文本文件的内容应足以导致内容面板内出现滚动条。调用`refresh`方法可以使小部件重新调整自身，以便它可以容纳所有新添加的内容而不显示滚动条。

从代码中可以看出，我们在两个地方使用了`newHeader`属性；一个是作为加载内容的一部分，另一个是刷新面板一旦内容被添加后。让我们探讨一下这一点，因为这是我们如何访问任何手风琴中的内容的关键部分。

`ui`对象包含四个属性，允许我们访问已添加到页面上的任何手风琴的标题或面板中的内容。完整列表如下：

| 标题 | …中的内容访问 |
| --- | --- |
| `ui.newHeader` | 刚刚激活的标题 |
| `ui.oldHeader` | 刚刚停用的标题 |
| `ui.newPanel` | 刚刚激活的面板 |
| `ui.oldPanel` | 刚刚停用的面板 |

一旦我们引用了相关的面板或标题，我们就可以自由地自行操作内容。

# 手风琴的互操作性

手风琴小部件是否与库中的其他小部件很好地协作？让我们看一看手风琴是否可以与上一章的小部件——选项卡小部件结合使用。

修改手风琴的基础标记，以便第三个内容面板现在包含选项卡的标记，并且第三个标题不再指向远程文本文件：

```js
<div id="myAccordion">
  <h2><a href="#">Header 1</a></h2>
  <div>Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean sollicitudin. Sed interdum pulvinar justo.Nam iaculis volutpat ligula. Integer vitae felis quis diam laoreet ullamcorper.</div>
  <h2><a href="#">Header 2</a></h2>
  <div>Etiam tincidunt est vitae est. Ut posuere, mauris at sodales rutrum, turpis tellus fermentum metus, ut bibendum velit enim eu lectus. Suspendisse potenti.</div>
  <h2><a href="#">Header 3</a></h2>
  <div>
 <div id="myTabs">
 <ul>
 <li><a href="#0"><span>Tab 1</span></a></li>
 <li><a href="#1"><span>Tab 2</span></a></li>
 </ul>
 <div id="0">This is the content panel linked to the first tab, it is shown by default.</div>
 <div id="1">This content is linked to the second tab and will be shown when its tab is clicked.</div>
 </div>
  </div>
</div>
```

我们还应该在手风琴的源文件之后链接到选项卡小部件的源文件；在您的代码中，在对`jquery.ui.widget.js`的调用下方立即添加此行：

```js
<script src="img/jquery.ui.tabs.js"></script>  
```

接下来，将最后一个`<script>`元素更改为以下内容：

```js
  <script>
    $(document).ready(function($) {
 $("#myAccordion").accordion();
 $("#myTabs").tabs();
    });
  </script>
```

将此文件保存为`accordion17.html`。我们对此文件所做的所有操作只是向手风琴的一个内容面板添加了一个简单的选项卡结构。在页面末尾的`<script>`元素中，我们只调用手风琴和选项卡的小部件方法。不需要额外或特殊的配置。

当第三个手风琴标题被激活时，页面应该如下所示：

![手风琴互操作性](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_04_08.jpg)

小部件也是兼容的，也就是说，我们可以在选项卡的内容面板中包含一个手风琴而不会产生任何负面影响。

## 使用多个手风琴

我们已经看到如何在页面上轻松使用手风琴与其他小部件。那么在同一页上使用多个手风琴呢？同样也不是问题；我们可以在同一页上拥有多个手风琴，只要我们正确地配置对手风琴的调用(s)即可。

在您的文本编辑器中，在`accordion1.html`的现有块之下立即添加以下标记：

```js
  <p>
  <div class="myAccordion two">
    <h2><a href="#">Header 1</a></h2>
    <div>Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean sollicitudin. Sed interdum pulvinar justo. Nam iaculis volutpat ligula. Integer vitae felis quis diam laoreet ullamcorper.
    </div>
    <h2><a href="#">Header 2</a></h2>
    <div>Etiam tincidunt est vitae est. Ut posuere, mauris at sodales rutrum, turpis tellus fermentum metus, ut bibendum velit enim eu lectus. Suspendisse potenti.
</div>
    <h2><a href="#">Header 3</a></h2>
    <div>Donec at dolor ac metus pharetra aliquam. Suspendisse purus. Fusce tempor ultrices libero. Sed quis nunc. Pellentesque tincidunt viverra felis. Integer elit mauris, egestas ultricies, gravida vitae,
    feugiat a, tellus.</div>
  </div>  
```

我们需要在我们的代码中允许第二个手风琴小部件，因此请按如下方式调整`<script>`块：

```js
  <script>
    $(document).ready(function($) {
 $(".myAccordion").accordion();
 $( ".two" ).accordion( "option", "icons", { "header": "ui-icon-plus", "activeHeader": "ui-icon-minus" } ); 
    });
  </script>
```

将文件保存为`accordion18.html`。如果我们在浏览器中预览结果，应该会看到如下内容：

![使用多个手风琴](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_04_09.jpg)

我们所做的只是复制第一个手风琴的现有标记；关键是如何在我们的脚本中启动第二个手风琴功能。

在本书中，我们已经使用选择器 ID 来启动我们的手风琴；这是完美的，特别是当页面上只有一个手风琴时。如果在同一页（甚至是同一个网站）上有多个手风琴，这可能会变得笨拙，因为我们不必要地重复代码。

我们可以通过切换到使用类来解决这个问题，而不是使用选择器 ID，手风琴可以很容易地使用两种方法中的任何一种。在我们的示例中，我们为两个手风琴都分配了一个类名`.myAccordion`。然后，我们在脚本中使用它来初始化对`.accordion()`的调用。这允许我们在多个手风琴中共享通用功能，而不会重复代码。

如果我们需要覆盖其中一个或多个手风琴的配置，我们可以通过将第二个单独的类添加到我们的标记中来实现这一点，在这种情况下，我们希望更改第二个手风琴以使用**+**和**–**图标，而不是箭头。

为了实现这一点，第二个手风琴被分配了`.myAccordion .two`类。然后，第二个类被用作调用第二个`accordion()`实例的基础；这会覆盖原始配置，但仅适用于那些被分配了额外`.two`类的手风琴。然后，我们可以通过向手风琴的标记中添加第二个类来扩展这个原则，以使任何其他应具有不同功能的手风琴也适用于此原则。

# 摘要

我们首先了解了手风琴的作用以及它如何被 CSS 框架所针对。然后，我们继续查看了可配置选项，这些选项可用于更改手风琴的行为，比如指定默认打开的替代标题，或设置触发内容抽屉打开的事件。

除了可配置选项，我们还发现手风琴暴露了几个自定义事件。通过使用它们，我们可以在配置期间指定回调函数，或者在配置后绑定到它们，以在小部件发生不同事情时执行额外功能。

接下来，我们看了手风琴的默认动画以及如何使用缓动效果来实现内容面板的展开动画。我们发现，要使用非标准的动画或缓动效果，需要将`jquery.ui.effect.js`文件与所需的自定义效果文件一起包含进来。

除了查看这些选项之外，我们还发现手风琴可以调用一系列方法来在程序中控制它的行为。在下一章中，我们将开始使用对话框小部件，这使我们能够创建一个灵活的、高度可配置的浮动层，该层浮动在页面上方并显示我们指定的任何内容。


# 第五章：对话框

传统上，显示简短消息或询问访问者问题的方法是使用 JavaScript 的本机对话框之一（如`alert`或`confirm`），或者打开一个具有预定义大小且样式设计成对话框样式的新网页。

不幸的是，我相信你也清楚，这些方法对于我们作为开发人员并不特别灵活，对我们的访问者也不特别引人入胜。它们解决了一些问题，但通常也会引入几个新问题。

对话框小部件可以让我们显示消息、补充内容（如图像或文本）甚至交互式内容（如表单）。也很容易添加按钮，例如简单的**确定**和**取消**按钮，并为它们定义回调函数以便对它们的点击作出反应；对话框也可以是模态的或非模态的。

在本章中，我们将涵盖以下主题：

+   创建基本对话框

+   使用对话框选项

+   模态性

+   启用内置动画

+   向对话框添加按钮

+   使用对话框回调

+   控制对话框的程序化方法

以下截图显示了对话框小部件及其所包含的不同元素：

![对话框](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_05_01.jpg)

# 创建基本对话框

对话框具有许多内置的默认行为，但只需要少量方法来程序化地控制它，使其成为一个易于使用的小部件，同时也具有高度可配置性和强大性。

生成小部件很简单，只需要最小的底层标记结构。以下页面包含实现对话框小部件所需的最小标记：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Dialog</title>
  <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
  <script src="img/jquery-2.0.3.js"></script>
  <script src="img/jquery.ui.core.js"></script>
  <script src="img/jquery.ui.widget.js"> </script>
  <script src="img/jquery.ui.position.js"> </script>
  <script src="img/jquery.ui.dialog.js"> </script>
  <script src="img/jquery.ui.button.js"> </script>
  <script>
    $(document).ready(function($){
      $("#myDialog").dialog();
    });
  </script>
</head>
<body>
  <div id="myDialog" title="This is the title!">
  Lorem ipsum dolor sit amet, consectetuer adipiscing elit.
Aenean sollicitudin. Sed interdum pulvinar justo. Nam iaculis volutpat ligula. Integer vitae felis quis diam laoreet ullamcorper. Etiam tincidunt est vitae est.
  </div>
</body>
</html>
```

将此文件保存为`dialog1.html`，放在`jqueryui`项目文件夹中。要使用对话框，需要以下依赖项：

+   `jquery.ui.all.css`

+   `jquery.ui.core.js`

+   `jquery.ui.widget.js`

+   `jquery.ui.position.js`

+   `jquery.ui.dialog.js`

+   `jquery.ui.button.js`

可选地，我们还可以包含以下文件来使对话框可拖动和可调整大小：

+   `jquery.ui.mouse.js`

+   `jquery.ui.draggable.js`

+   `jquery.ui.resizable.js`

对话框小部件的初始化方式与我们已经了解的其他小部件相同，通过调用小部件的插件方法。

当您在浏览器中运行此页面时，您应该看到默认的对话框小部件，如下截图所示：

![创建基本对话框](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_05_02.jpg)

与我们之前介绍的小部件一样，CSS 框架中的各种类名被添加到小部件中的不同元素中，以使它们具有各自元素的适当样式，并且所需的任何附加元素都是即时创建的。

第一个示例中的对话框在大小和位置上都是固定的，并且将被定位在视口的中心。我们可以很容易地使小部件可拖动、可调整大小或两者兼具。我们只需要在`<head>`的末尾与其他`<script>`资源一起包含可拖动和可调整大小组件的源文件，以及鼠标工具。

不重要的是，在对话框的源文件之前将可拖动和可调整大小的文件包含在页面中。它们可以出现在对话框的源文件之前或之后，小部件仍将继承这些行为。任何所需的样式，例如出现在对话框左下角的调整大小指示器，将自动从主 CSS 文件中捡取。

在`dialog1.html`的关闭`</head>`标签之前直接添加以下三个`<script>`元素：

```js
<script src="img/jquery.ui.mouse.js">
</script>
<script src="img/jquery.ui.draggable.js">
</script>
<script src="img/jquery.ui.resizable.js">
</script>
```

将其保存为`dialog2.html`并在浏览器中查看。现在对话框应该是可拖动的，并且可以移动到视口的任何部分，但是如果小部件移动到边缘，它不会导致滚动。

对话框还应该是可调整大小的——通过单击并按住任何角落并拖动，可以使小部件变大或变小。如果对话框比视口大，它将导致窗口滚动。

# 列出对话框选项

选项对象可用于对话框的小部件方法中配置各种对话框选项。让我们来看看可用的选项：

| 选项 | 默认值 | 描述 |
| --- | --- | --- |
| `appendTo` | `"body"` | 确定对话框（和遮罩，如果是模态的）应追加到哪个元素。 |
| `autoOpen` | `true` | 当设置为`true`时，调用`dialog()`方法时立即显示对话框。 |
| `buttons` | `{}` | 提供一个包含要与对话框一起使用的按钮的对象。每个键都成为`<button>`元素上的文本，每个值都是一个回调函数，在单击按钮时执行。 |
| `closeOnEscape` | `true` | 如果设置为`true`，则按下*Esc*键时对话框将关闭。 |
| `dialogClass` | `""` | 为对话框设置额外的类名以进行主题设置。 |
| `draggable` | `true` | 使对话框可拖动（需要使用`jquery.ui.draggable.js`）。 |
| `height` | `auto` | 设置对话框的起始高度。 |
| `hide` | `null` | 设置对话框关闭时要使用的效果。 |
| `maxHeight` | `false` | 设置对话框的最大高度。 |
| `maxWidth` | `false` | 设置对话框的最大宽度。 |
| `minHeight` | `150` | 设置对话框的最小高度。 |
| `minWidth` | `150` | 设置对话框的最小宽度。 |
| `modal` | `false` | 在对话框打开时启用模态。 |
| `position` | `center` | 设置对话框在视口中的起始位置。它可以接受一个字符串、一个字符串数组或包含对话框偏离视口顶部和左侧的确切坐标的数组（需要使用`jquery.ui.position.js`）。 |
| `resizable` | `true` | 使对话框可调整大小（还需要`jquery.ui.resizable.js`）。 |
| `show` | `null` | 设置对话框打开时要使用的效果。 |
| `title` | `""` | 替代在小部件的基础容器元素上指定标题属性。 |
| `width` | `300` | 设置对话框的起始宽度。 |

如您所见，我们有各种可配置的选项可供在实现对话框时使用。其中许多选项是布尔值、数值或基于字符串的，使它们易于在您的代码中获取和设置。

## 显示对话框

到目前为止，我们的示例中，对话框在页面加载后立即显示。 `autoOpen` 选项默认设置为 `true`，因此对话框将在初始化时立即显示。

我们可以更改这样，以便在发生其他事情时打开对话框，比如通过将 `autoOpen` 选项设置为 `false` 来点击按钮。将 `dialog2.html` 底部的最终 `<script>` 元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
 $("#myDialog").dialog({
 autoOpen: false 
 });
  });
</script>
```

将此保存为 `dialog3.html`。小部件仍然被创建；底层标记被从页面中移除，转换为小部件，然后重新附加到 `<body>` 的末尾。它将保持隐藏，直到调用 `open` 方法为止。我们稍后在本章中查看 `open` 方法时会回到这个选项。

## 设置对话框标题

选项表显示一个 `title` 选项，我们可以使用它来控制标题在小部件上的显示方式；如果将 `draggable` 属性设置为 `false`，则可以将其设置为可选择。虽然可以直接在代码中设置它，但在配置选项中设置它要容易得多，因为这样可以更好地控制标题在小部件中的显示方式。

默认情况下，对话框小部件的标题文本将显示为纯文本；我们可以通过向 `.ui-dialog-title` 类添加自定义样式来覆盖此设置。

在浏览器中，将 `dialog3.html` 中对话框的 `<script>` 块修改如下：

```js
<script>
  $(document).ready(function($){
 $("#myDialog").dialog({
      draggable: false, 
      open: function() {
        $(".ui-dialog-title").addClass("customtitle");
      }
    });
  });
</script>
```

将文件保存为 `dialog4.html`。我们现在可以为对话框的标题栏添加一些样式 - 在一个单独的文件中添加以下代码，并将其保存为 `dialogOverrides.css`，在链接到 jQuery UI 样式表后：

```js
.customtitle { color: #800080; }
```

如果我们在浏览器中预览结果，您可以清楚地看到标题现在以不同的颜色显示：

![设置对话框标题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_05_10.jpg)

要查看代码的效果，我们可以查看脚本如何覆盖基本代码，使用 DOM 检查器如 Firebug：

```js
<span id="ui-id-1" class="ui-dialog-title customtitle">This is the title!</span>
```

我们可以在样式表中手动为对话框元素设置样式，但这将是通过反复试验；简单地使用 jQuery 添加一个新类，然后我们可以根据自己的喜好进行样式设置，这会更容易得多！

### 小贴士

如果未提供值给 `title` 属性，则将使用对话框源元素上的属性。

## 配置模态选项

对话框的最大优势之一是模态性。此功能在对话框打开时创建一个覆盖在对话框下方的底层页面的覆盖层。一旦对话框关闭，覆盖层就会被移除。在对话框打开时，无法以任何方式操纵底层页面内容。

这个功能的好处是它确保对话框在基础页面再次变得交互之前关闭，并为访问者提供清晰的视觉指示，表明必须与对话框交互，然后才能继续。

修改`dialog4.html`中的配置对象如下所示：

```js
    $(document).ready(function($){
      $("#myDialog").dialog({
        modal: true
      });
    });
```

此文件可以保存为`dialog5.html`。以下截图显示了模态效果（您可能需要向页面添加一些虚假内容，以充分体验模态效果）：

![配置模态选项](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_05_03.jpg)

添加模态的唯一属性是`modal`选项。当您在浏览器中查看页面时，您将立即看到模态效果。用于创建覆盖图像的重复背景图像完全由 CSS 框架样式化，因此可以通过**ThemeRoller**工具进行完全主题化。如果需要，我们还可以使用自己的图像。`ui-widget-overlay`类名称会被添加到覆盖层中，因此这是需要覆盖的选择器，如果需要自定义的话。

# 添加按钮

`button`选项接受一个对象文字，用于指定对话框上应存在的不同`<button>`元素。每个`property: value`对表示一个单个按钮。让我们向我们的对话框添加一些`<button>`元素。

修改`dialog5.html`中的最终`<script>`元素，使其如下所示：

```js
<script>
  $(document).ready(function($){
    $("#myDialog").dialog({
 buttons: { Ok: function() { }, Cancel: function() { } },
 draggable: false
    });
  });
</script>
```

将文件保存为`dialog6.html`。`buttons`对象中每个属性的关键是将形成`<button>`标签的文本，值是单击按钮时要执行的回调函数的名称。`buttons`选项可以采用对象，如此示例中的示例，也可以采用对象数组。在这个例子中，`execute()`和`cancel()`函数什么都不做；我们很快就会回到这个例子并填充它们。

以下截图显示了我们的新`<button>`元素将如何显示：

![添加按钮](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_05_04.jpg)

小部件将在对话框底部的自己容器中添加我们的新按钮，并且如果对话框被调整大小，此容器将保持其原始尺寸。`<button>`元素是完全可主题化的，并且将根据使用的主题进行样式设置。

## 向对话框按钮添加图标

直到现在，关闭对话框通常意味着必须点击标题栏中的关闭图标-它对此目的非常有效，但并不为我们提供任何机会从浏览我们网站或在线应用程序的人那里获得响应。

在前面的示例中添加按钮有助于消除这一限制，并允许我们从最终用户处接受各种响应-我们可以通过添加图标进一步提供按钮的视觉支持。

在您的文本编辑器中，修改`dialog6.html`中的`<script>`块如下：

```js
<script>
  $(document).ready(function($){
    $("#myDialog").dialog({
 buttons: [ { 
 text: "Ok",
 icons: { primary: "ui-icon-check", secondary: "ui-icon-circle-check" },
 click: function() { }
 }, {
 text: "Cancel",
 icons: { primary: "ui-icon-closethick", secondary: "ui-icon-circle-close" },
 click: function() { }
 } ],
      draggable: false
    });
  });
</script>
```

将此保存为`dialog7.html`。在这里，我们使用了按钮选项来指定文本、图标以及当单击按钮时应该执行的操作。您会注意到，与前一个示例相比，我们还使用了一种不同的方式来指定每个选项。两种方法都同样有效；我们需要在添加图标时使用这种方法，否则您可能会发现出现没有文本的按钮！

如果我们在浏览器中预览结果，我们现在可以看到在对话框底部出现的带有额外图标的按钮：

![在对话框按钮中添加图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_05_11.jpg)

图标的样式将根据使用的主题进行设置。在我们的示例中，我们指定了主要和次要图标；前者位于按钮文本的左侧，而后者位于右侧。然而，在您的应用程序或网站中，您可能只需要根据您的需求指定一个图标。

# 启用对话框动画

对话框为我们提供了一个内置效果，可以应用于小部件的打开或关闭（或两者）。我们只能使用一个效果，即缩放效果的实现（我们将在第十三章中更详细地介绍这一点，“使用 jQuery UI 进行选择和排序”）。将`dialog7.html`中的最终`<script>`元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
    $("#myDialog").dialog({
 show: true,
 hide: true
    });
  });
</script>
```

将此保存为`dialog8.html`。我们将`hide`和`show`选项都设置为布尔值`true`。这将启用内置效果，逐渐减小对话框的大小和不透明度，直到它优雅地消失。以下截图显示了效果正在进行中：

![启用对话框动画](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_05_05.jpg)

我们可以使用布尔值分别启用或禁用显示或隐藏动画，就像我们在此示例中所做的那样。我们还可以通过提供指定要使用的效果名称的字符串来指定要使用的动画类型：

```js
<script>
  $(document).ready(function($){
    $("#myDialog").dialog({
      show: {effect: "fadeIn", duration: 1000},
      hide: {effect: "fadeOut", duration: 1000}
    });
  });
</script>
```

我们甚至可以更进一步，使用一些效果，比如弹跳或爆炸，尽管这些效果只有在适当时才应添加！我们稍后将在 jQuery UI 中介绍效果，第十四章中可以找到更多详细信息，“UI 效果”。您还可以在[`api.jqueryui.com/category/effects/`](http://api.jqueryui.com/category/effects/)上查看更多细节。

# 配置对话框的尺寸

与对话框大小以及其可以调整到的最小和最大尺寸相关的选项有几个。我们可以将所有这些选项添加到下一个示例中，因为它们都是相关的，以节省逐个查看它们的时间。将`dialog8.html`中的配置对象更改为以下内容：

```js
$("#myDialog").dialog({
 width: 500,
 height: 300,
 minWidth: 150,
 minHeight: 150,
 maxWidth: 600,
 maxHeight: 450
});
```

将此文件保存为`dialog9.html`。这些选项对小部件的影响很简单；`width`和`height`选项定义了对话框在首次打开时的大小，而`min-`和`max-`选项分别定义了对话框可以调整到的最小或最大尺寸。

### 提示

另外一点需要注意的是，如果对话框过小，辅助技术和键盘用户可能会发现内容难以导航。有一个可用性原则坚持认为对话框应该始终是不可调整大小的，而窗口应该始终是可调整大小的。

虽然我认为这不是一条黑白分明、铁板一块的规则，但是将小型、信息性、基于文本的对话框保持固定大小可能是明智的，而允许包含图像和文本的内容丰富的对话框可以调整大小。我们将在第十二章中介绍如何将调整大小手柄添加到任何合适的元素（如对话框），*调整大小组件*中。

# 设置对话框的 z-index 顺序

对话框被设置为出现在任何现有页面内容的上方。我们可以使用 CSS 更改其 z-index 设置，或者通过确保正确将其附加到其父元素来提高它，以覆盖我们的现有内容。但是如果页面上有两个对话框怎么办？我们是否需要分别为每个对话框定义`zIndex`？焦点如何考虑？

让我们看看是否可以通过查看另一个示例来回答这些问题；将`dialog7.html`的`<body>`标记更改为具有两个对话框：

```js
<div id="dialog1" title="Dialog 1">
  Lorem ipsum dolor sit amet, consectetuer adipiscing elit.
Aenean sollicitudin. Sed interdum pulvinar justo. Nam aculis
volutpat ligula. Integer vitae felis quis diam laoreet ullamcorper. Etiam tincidunt est vitae est.
</div>
<div id="dialog2" title="Dialog 2">
  Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean sollicitudin. Sed interdum pulvinar justo. Nam iaculis volutpat ligula. Integer vitae felis quis diam laoreet ullamcorper. Etiam tincidunt est vitae est.
</div>
```

现在将最终的`<script>`元素更改为如下所示：

```js
<script>
  $(document).ready(function($){
 $("#dialog1, #dialog2").dialog();
  });
</script>
```

将此文件保存为`dialog10.html`。我们在页面上添加了另一个对话框，它基本上只是原始对话框的一个克隆，具有不同的`id`和`title`属性。在`<script>`中，我们只需在两个底层对话框容器上调用`widget`方法。

由于`widget`方法在第二个对话框上被最后调用，因此它接收焦点，第二个对话框将自动具有较高的 z-index 值。这意味着我们不需要担心单独配置它。对话框在底层标记中出现的顺序无关紧要；决定每个对话框 z-index 值的是 widget 方法的顺序。

### 提示

**覆盖 z-index 值**

如果需要覆盖 z-index 值，可以（并且应该）使用 CSS 来执行此操作-您需要使用`!important`属性来覆盖现有值。

由于两个对话框都没有显式设置其位置，所以当我们的示例页面加载时，只有第二个对话框会可见。然而，两者都是可拖动的，我们可以通过将第二个对话框拖离来将它们对齐，使它们略微重叠。如果我们点击第一个对话框框，它将接收焦点，因此它将显示在第二个框上方。

## 控制焦点

在打开对话框时，接收焦点的元素由匹配以下条件的项目确定：

+   对话框中具有 autofocus 属性的第一个元素

+   对话框内容中的第一个`:tabbable`元素

+   对话框按钮面板中的第一个`:tabbable`元素

+   对话框的关闭按钮

+   对话框本身

以下代码摘录最能说明这一点，我们已经将`autofocus`属性添加到“是”单选按钮中：

```js
  <div id="myDialog" title="Best Widget Library">
    <p>Is jQuery UI the greatest JavaScript widget library?</p>
    <label for="yes">Yes!</label>
 <input type="radio" autofocus="autofocus" id="yes" value="yes" name="question" checked="checked"><br>
    <label for="no">No!</label>
    <input type="radio" id="no" value="no" name="question">
  </div>
```

“是”单选按钮首先接收焦点；然后我们可以通过标签切换到小部件内的其他元素。一旦对话框关闭，焦点将自动返回到对话框打开之前具有焦点的元素。

# 处理对话框的事件回调

对话框小部件为我们提供了广泛的回调选项，我们可以使用这些选项在任何对话框交互中的不同点执行任意代码。以下表格列出了我们可以使用的选项：

| 事件 | 描述 |
| --- | --- |
| `beforeClose` | 当对话框即将关闭时触发此事件 |
| `close` | 当对话框关闭时触发此事件 |
| `create` | 当对话框初始化时触发此事件 |
| `drag` | 当对话框被拖动时触发此事件 |
| `dragStart` | 当对话框开始拖动时触发此事件 |
| `dragStop` | 当对话框停止拖动时触发此事件 |
| `focus` | 当对话框获得焦点时触发此事件 |
| `open` | 当对话框打开时触发此事件 |
| `resize` | 当对话框被调整大小时触发此事件 |
| `resizeStart` | 当对话框开始调整大小时触发此事件 |
| `resizeStop` | 当对话框停止调整大小时触发此事件 |

这些回调中的一些仅在特定情况下可用，例如当包含可拖动和可调整大小的 jQuery UI 组件时，才会有`drag`和`resize`回调。在本章中，我们不会讨论这些回调选项，因为它们将分别在 第十一章、“拖放” 和 第十二章、“可调整大小组件” 中详细介绍。

其他回调，例如`beforeClose`、`create`、`open`、`close`和`focus`将在任何实现中可用。让我们看一个使用这些回调选项的例子。

在 `dialog10.html` 页面中删除第二个对话框，然后在第一个对话框后面直接添加以下新的标记：

```js
<div id="status" class="ui-widget ui-dialog ui-corner-all ui-widget-content">
  <div class="ui-widget-header ui-dialog-titlebar ui-corner-all">Dialog Status</div>
  <div class="ui-widget-content ui-dialog-content"></div>
</div>
```

现在将最终的 `<script>` 元素更改为以下内容：

```js
<script>
  $(document).ready(function($){  
    $("#dialog1").dialog({
 open: function() {
 $("#status").children(":last").text("The dialog is open");
 },
 close: function() {
 $("#status").children(":last").text("The dialog is closed");
 },
 beforeClose: function() {
 if ($(".ui-dialog").css("width") > "300") {
 return false;
 }
 }
 });
  });
</script>
```

将此保存为 `dialog11.html`。该页面包含一个新的状态框，用于报告对话框是打开还是关闭。我们已经给状态框的各个元素添加了几个 CSS 框架类，以使它们与正在使用的主题相适应。

我们的配置对象使用了 `open`、`close` 和 `beforeClose` 选项来指定简单的回调函数。`open` 和 `close` 回调简单地相应地设置状态框的文本。在 **Close** 按钮在对话框上被点击之后（但在实际关闭之前）触发的 `beforeClose` 回调用于确定是否关闭对话框。

我们使用简单的`if`语句来检查对话框的宽度；如果对话框宽度大于 300 像素，则从回调中返回`false`，对话框保持打开状态。当然，这种行为通常在可用性方面通常是不可接受的，但它确实突出了我们如何使用`beforeClose`回调来阻止对话框被关闭。

页面加载时，对话框显示，并执行`open`回调，状态框应显示一条消息。当对话框关闭时，如下图所示，会显示不同的消息：

![处理对话框的事件回调](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_05_06.jpg)

我应该澄清的一件事是，对话框小部件只将一个对象（原始事件对象）传递给回调函数。虽然它确实将第二个`ui`对象传递到处理程序函数中，但在该库的此版本中，此对象不包含任何属性。

# 以编程方式控制对话框

对话框直观且易于使用，与库中的其他组件一样，它提供了一系列方法，用于在初始化后以编程方式控制小部件。我们可以在对话框上调用的所有方法的完整列表如下：

| 方法 | 描述 |
| --- | --- |
| `close` | 这用于关闭或隐藏对话框。 |
| `destroy` | 这用于永久禁用对话框。至于对话框的`destroy`方法，它与我们之前见过的其他小部件的工作方式略有不同。它不仅仅是将底层 HTML 返回到其原始状态，还会隐藏对话框。 |
| `isOpen` | 这用于确定对话框是否打开。 |
| `moveToTop` | 这用于将指定的对话框移动到堆栈顶部。 |
| `open` | 这用于打开对话框。 |
| `option` | 这用于在对话框初始化后获取或设置任何可配置选项。 |
| `widget` | 这用于返回调用了`dialog()`小部件方法的外部元素。 |

## 切换对话框

首先我们来看看如何以编程方式控制小部件的打开，可以简单地使用`open`方法实现。让我们重新访问`dialog3.html`，其中`autoOpen`选项设置为`false`，因此当页面加载时对话框不会打开。在页面上添加以下`<button>`：

```js
<button type="button" id="toggle">Toggle dialog!</button>
```

然后将以下点击处理程序添加到代码顶部的`<script>`块中：

```js
$("#toggle").click(function() {
  if(!$("#myDialog").dialog("isOpen")) {
    $("#myDialog").dialog("open");
  } else {
    $("#myDialog").dialog("close");
  }
});
```

将此文件保存为`dialog12.html`。在页面上，我们添加了一个简单的`<button>`，可以用来打开或关闭对话框，具体取决于其当前状态。在`<script>`元素中，我们为`<button>`元素添加了一个点击处理程序，检查`isOpen`方法的返回值；感叹号的使用意味着我们要查看对话框是否没有打开。如果语句返回`true`，则对话框未打开，因此我们调用其`open`方法，否则我们调用`close`方法。

`open` 和 `close` 方法都会触发任何适用的事件；例如，`#toggle` 单击处理程序方法首先触发 `beforeClose` 然后是 `close` 事件。调用 `close` 方法类似于点击对话框上的关闭按钮。

# 从对话框获取数据

因为小部件是底层页面的一部分，所以传递数据到它和从它获取数据都很简单。对话框可以像页面上的任何其他标准元素一样对待。让我们看一个基本的例子。

在本章的早些时候，我们看过一个例子，其中向对话框添加了一些 `<button>` 元素。那个例子中的回调函数没有做任何事情，但是下面的例子给了我们使用它们的机会。将 `dialog8.html` 中的现有对话框标记替换为以下内容：

```js
<div id="myDialog" title="Best Widget Library">
  <p>Is jQuery UI the greatest JavaScript widget library?</p>
  <label for="yes">Yes!</label>
  <input type="radio" id="yes" value="yes" name="question" checked="checked"><br>
  <label for="no">No!</label>
  <input type="radio" id="no" value="no" name="question">
</div>
```

现在将最终的 `<script>` 元素更改如下：

```js
<script>
$(document).ready(function($){
  var execute = function(){
 var answer = $("#myDialog").find("input:checked").val();
 $("<p>").text("Thanks for selecting " + answer).
 appendTo($("body"));
 $("#myDialog").dialog("close");
 }
 var cancel = function() {
 $("#myDialog").dialog("close");
 }
  $("#myDialog").dialog({
    buttons: {
      "Ok": execute,
      "Cancel": cancel
    }
  });
});
</script>
```

将此保存为 `dialog13.html`。我们的对话框小部件现在包含一组单选按钮，一些 `<label>` 元素和一些文本。在这个例子中，当对话框关闭时，我们将获取所选单选按钮的结果，然后执行一些操作。

我们通过填写 `execute` 函数来开始 `<script>` 元素，该函数将作为按钮对象中 `Ok` 属性的值附加，稍后在脚本中。因此，每次点击 **Ok** 按钮时都会执行它。

在这个函数中，我们使用 `:checked` 过滤器来确定哪个单选按钮被选中。我们将 `answer` 变量的值设置为单选按钮的值，然后创建一个简短的消息，并将其附加到页面的 `<body>` 元素中。映射到 **Cancel** 按钮的回调函数很简单；我们所做的就是使用 `close` 方法关闭对话框。

这个例子的重点在于看到从对话框获取数据就像从页面上的任何其他元素获取数据一样简单。如果你在浏览器中预览它，你会首先看到左边的对话框；点击按钮会给出相应的响应，如下面的截图所示：

![从对话框获取数据](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_05_12.jpg)

# 探索对话框的互操作性

在以前的章节中，我们已经组合了多个小部件，以便我们可以看到它们如何很好地一起工作，本章也不例外。我们可以轻松地将其他 UI 小部件放入对话框中，例如我们在上一章中看到的折叠小部件。在文本编辑器中的新文件中，创建以下页面：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Dialog</title>
  <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
  <script src="img/jquery-2.0.3.js"></script>
  <script src="img/jquery.ui.core.js"></script>
  <script src="img/jquery.ui.widget.js"></script>
  <script src="img/jquery.ui.position.js"></script>
  <script src="img/jquery.ui.dialog.js"></script>
  <script src="img/jquery.ui.button.js"></script>
  <script src="img/jquery.ui.accordion.js"> 
  </script>
  <script src="img/jquery.ui.mouse.js"></script>
  <script src="img/jquery.ui.draggable.js"></script>
  <script src="img/jquery.ui.resizable.js"></script>
  <script>
    $(document).ready(function($){
      $("#myDialog").dialog();
         $("#myAccordion").accordion();
    });
  </script>
</head>
<body>
  <div id="myDialog" title="An Accordion Dialog">
    <div id="myAccordion">
      <h2><a href="#">Header 1</a></h2>
      <div>Lorem ipsum dolor sit amet, consectetuer adipiscing elit. Aenean sollicitudin.</div>
      <h2><a href="#">Header 2</a></h2>
      <div>Etiam tincidunt est vitae est. Ut posuere, mauris at so dales rutrum, turpis.</div>
      <h2><a href="#">Header 3</a></h2>
      <div>Donec at dolor ac metus pharetra aliquam. Suspendisse pu rus.</div>
    </div>
  </div>
</body>
</html>
```

将此文件保存为 `dialog14.html`。折叠小部件的基本标记被放置到对话框的容器元素中，我们只需在 `<script>` 元素中调用每个组件的小部件方法。

### 提示

在这个例子中，我们使用了相当多独立的 `<script>` 资源。值得记住的是，对于生产，我们应该使用组合和缩小的脚本文件，其中包含我们在下载构建器中选择的所有组件。

组合小部件应该像这样显示：

![探索对话框的互操作性](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_05_07.jpg)

# 创建一个动态基于图像的对话框

对话框部件背后的类是紧凑的，适用于一小部分专业行为，其中大部分我们已经了解过了。我们仍然可以通过一个动态对话框来玩一些有趣的东西，这个对话框根据触发它的元素加载不同的内容。

在文本编辑器中的新页面中，添加以下代码：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Dialog</title>
  <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
  <link rel="stylesheet" href="css/dialogTheme.css">
  <script src="img/jquery-2.0.3.js"></script>
  <script src="img/jquery.ui.core.js"></script>
  <script src="img/jquery.ui.widget.js"></script>
  <script src="img/jquery.ui.position.js"></script>
  <script src="img/jquery.ui.dialog.js"></script>
  <script src="img/jquery.ui.button.js"></script>
  <script src="img/jquery.ui.accordion.js"></script>
  <script src="img/jquery.ui.mouse.js"></script>
  <script src="img/jquery.ui.draggable.js"></script>
  <script src="img/jquery.ui.resizable.js"></script>
</head>
<body>
   <div id="thumbs" class="ui-corner-all">
     <div class="ui-widget-header ui-corner-top">
       <h2>Some Common Flowers</h2>
       </div>
       <p>(click a thumbnail to view a full-size image)</p>
       <div class="thumb ui-helper-clearfix ui-widget-content">
         <a href="img/haFull.jpg" title="Helianthus annuus"><img src="img/haThumb.jpg" alt="Helianthus annuus"></a>
         <h3>Helianthus annuus</h3>
         <p>Sunflowers (Helianthus annuus) are annual plants native to the Americas, that possess a large flowering head</p>
       </div>
       <div class="thumb ui-helper-clearfix ui-widget-content">
         <a href="img/lcFull.jpg" title="Lilium columbianum"> <img src="img/lcThumb.jpg" alt="Lilium columbianum"></a>
         <h3>Lilium columbianum</h3>
         <p>The Lilium columbianum is a lily native to western North America. It is also known as the Columbia Lily or Tiger Lily</p>
       </div>
         <div class="thumb ui-helper-clearfix ui-widget-content">
         <a href="img/msFull.jpg" title="Myosotis scorpioides"> <img src="img/msThumb.jpg" alt="Myosotis scorpioides"></a>
         <h3>Myosotis scorpioides</h3>
         <p>The Myosotis scorpioides, or Forget-me-not, is a herbaceous perennial plant of the genus Myosotis.</p>
       </div>
       <div class="thumb ui-helper-clearfix ui-widget-content last">
         <a href="img/nnFull.jpg" title="Nelumbo nucifera"><img src="img/nnThumb.jpg" alt="Nelumbo nucifera"></a>
         <h3>Nelumbo nucifera</h3>
         <p>Nelumbo nucifera is known by a number of names including; Indian lotus, sacred lotus, bean of India, or simply lotus.</p>
       </div>
   </div>
   <div id="dialog"></div>
</body>
</html>
```

将此文件保存为`dialog15.html`。以下截图显示了在浏览器中预览时的结果：

![创建动态基于图像的对话框](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_05_08.jpg)

页面相对简单——我们有一个外部容器，它包围着所有内容，以及一个我们给予了类名`ui-widget-header`的元素。我们使用后者是为了从正在使用的主题中获取一些默认样式。

在此之后，我们有一些解释性文本，然后是一系列容器。这些容器被赋予了几个类名，其中一些是为了我们能够对其进行样式设置，而另一些（如`ui-helper-clearfix`）则是为了获取框架或主题样式。

在每个容器中都有一个图像，包裹在一个锚点内，一个副标题和一些描述性文本。在外部容器之后，是一个空的`<div>`元素，用于创建对话框。在这个例子中，我们不使用可调整大小的功能。每个缩略图都包裹在一个锚点内，以便即使禁用了 JavaScript，页面也能正常工作。在这种情况下，对话框部件不会显示，但访问者仍然可以看到每个图像的全尺寸版本。这种渐进增强形式在这种类型的应用程序中至关重要，我们始终可以查看内容。添加对话框部件的调用是为了增强对访问者的整体视图，同时确保即使禁用了 JavaScript，内容仍将显示出来！

现在，在闭合的`</head>`标记之前直接添加以下`<script>`块：

```js
<script>
  $(document).ready(function($){
    var filename, titleText, dialogOpts = {
      modal: true,
      width: 388,
      height: 470,
      autoOpen: false,
      open: function() {
        $("#dialog").empty();
        $("<img />", { src: filename }).appendTo("#dialog");
        $("#dialog").dialog("option", "title", titleText);
      }
    };
    $("#dialog").dialog(dialogOpts);
    $("#thumbs").find("a").click(function(e) {
      e.preventDefault();
      filename = $(this).attr("href");
      titleText = $(this).attr("title");
      $("#dialog").dialog("open");
    });
  });
</script>
```

我们首先定义了三个变量；第一个变量用于添加被点击的缩略图的全尺寸图像的路径，第二个用于存储用作部件标题文本的图像标题，第三个是对话框的配置对象。我们已经看到了所有的配置选项都已经在实际操作中使用过了，所以我就不会详细介绍大部分选项了。

`open`回调，在对话框打开之前直接调用，是我们向对话框添加全尺寸图像的地方。我们首先清空对话框，然后创建一个新的`<img>`元素，并将其`src`设置为`filename`变量的值。然后将新的`<img>`附加到对话框的内部内容区域。

然后，我们使用`option`方法将标题选项设置为`titleText`变量的值。一旦定义了`open`回调，我们就像平常一样调用对话框的部件方法。

我们可以使用包装器`<a>`元素作为打开对话框的触发器。在我们的点击处理程序中，我们首先调用`e.preventDefault()`来阻止点击的默认操作，然后使用被点击的链接的`href`和`title`属性设置我们的`filename`和`titleText`变量的内容。然后，我们调用对话框的`open`方法来显示对话框，这将触发`open`选项中指定的回调函数。

### 提示

如果我们省略`e.preventDefault()`，这将覆盖对话框，浏览器将呈现每个图像，就像点击了链接一样。

对于此示例，我们还需要一个新的样式表。在文本编辑器的新页面中，添加以下代码：

```js
#thumbs { width:342px; padding: 10px 0 10px 10px; border:1px 
   solid #ccc; background-color:#eee; }
#thumbs p { width: 330px; font-family: Verdana; font-size: 9px; 
   text-align: center; }
.thumb { width: 310px; height: 114px; padding: 10px; 
   border:1px solid #ccc; border-bottom: none; }
.last { border-bottom: 1px solid #ccc; }
.thumb img { border: 1px solid #ccc; margin-right: 10px; 
   float: left; cursor: pointer; }
.thumb h3 { margin: 0; float: left; width:198px; }
#thumbs .thumb p { width: 310px; margin:0; font-family: 
   Verdana; font-size: 13px; text-align: left; }
#thumbs .ui-widget-header { width: 330px; text-align: center; }
```

在前面的示例中已经使用了许多这些样式，但是为其他页面元素添加一些新规则使我们可以在实际环境中看到对话框。将此保存为`dialogTheme.css`，并放入`css`文件夹中。我们在此示例中还使用了一些图像，这些图像可以在本书的附带代码下载的`img`文件夹中找到。

这样现在应该给我们提供了前面截图中看到的页面，当点击缩略图时，将显示相同图像的完整尺寸版本：

![创建基于图像的动态对话框](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_05_09.jpg)

# 概要

对话框小部件是专门设计的，用于在悬浮面板中显示消息或问题，该面板位于页面内容之上。高级功能，如拖动和调整大小，已直接内置，并且仅需要为每个功能包含额外的脚本文件。其他功能，如出色的模态和覆盖层，易于配置。

我们首先看了默认实现，它与迄今为止我们看过的其他小部件一样简单。然后，我们检查了对话框 API 公开的一系列可配置选项。我们可以利用它们来启用或禁用内置行为，例如模态，或设置小部件的尺寸。它还为我们提供了广泛的回调，允许我们在交互期间通过小部件触发的自定义事件中挂钩。

然后，我们简要介绍了与对话框一起使用的内置打开和关闭效果，然后继续查看我们可以调用的基本方法，以执行对话框执行操作的任务，例如打开或关闭。

在下一章中，我们将继续查看滑块和进度条小部件，它们允许我们创建交互式表单小部件，用于从预定义范围中选择值并在屏幕上显示结果。


# 第六章：滑块和进度条小部件

滑块组件允许我们实现一个引人入胜且易于使用的小部件，我们的访问者应该会发现它吸引人且直观易用。它的基本功能很简单。滑块轨道表示一系列由沿着轨道拖动的手柄选择的值。

进度条部件用于显示任意过程的完成百分比。这是一个简单易用的组件，具有极其紧凑的 API，为访问者提供了出色的视觉反馈。

在本章中，我们将涵盖以下主题：

+   默认的滑块实现

+   滑块的自定义样式

+   更改配置选项

+   创建垂直滑块

+   设置最小值、最大值和默认值

+   启用多个手柄和范围

+   滑块的内置事件回调

+   滑块方法

+   进度条的默认实现

+   可配置的选项

+   小部件公开的事件 API

+   进度条公开的唯一方法

+   进度条的一些真实世界示例

在我们卷起袖子开始创建滑块之前，让我们看一下它由哪些不同的元素组成。以下图示显示了一个典型的滑块小部件：

![滑块和进度条小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_06_01.jpg)

正如您所见，这是一个简单的小部件，只由两个主要元素组成——**滑块手柄**（有时称为拇指）和**滑块轨道**。

# 引入滑块部件

创建默认的基本滑块所需的代码与我们迄今为止看过的任何其他小部件一样少。所需的基本 HTML 标记也很少。现在让我们创建一个基本的滑块。在文本编辑器的新页面中，添加以下代码：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Slider</title>
  <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
  <script src="img/jquery-2.0.3.js"></script>
  <script src="img/jquery.ui.core.js"></script>
  <script src="img/jquery.ui.widget.js"></script>
  <script src="img/jquery.ui.mouse.js"></script>
  <script src="img/jquery.ui.slider.js"></script>
  <script>
    $(document).ready(function($){
      $("#mySlider").slider();
    });
  </script>
</head>
<body>
  <div id="mySlider"></div>
</body>
</html>
```

将此文件保存为`slider1.html`并在浏览器中查看。页面上有一个简单的容器元素；该元素将由小部件转换为滑块轨道。在代码的`<head>`部分中的`<script>`内，我们选择此元素并在其上调用`slider`方法。用于滑块手柄的`<a>`元素将由小部件自动创建。

当我们在浏览器中运行`slider1.html`文件时，我们应该会看到类似于上一个图示的东西。我们为默认实现使用了几个库资源，包括以下文件：

+   `jquery.ui.all.css`

+   `jquery-2.0.3.js`

+   `jquery.ui.core.js`

+   `jquery.ui.widget.js`

+   `jquery.ui.mouse.js`

+   `jquery.ui.slider.js`

基本滑块的默认行为简单而有效。可以通过用鼠标指针拖动拇指或使用键盘上的左/下或右/上箭头键，在 x 轴上沿轨道的任何像素移动拇指。使用鼠标左键单击轨道上的任何位置将立即将手柄移动到该位置。

# 自定义样式

由于其简单性，很容易为滑块小部件创建自定义主题。使用 ThemeRoller 是其中一种主题化的方法：我们只需下载一个新主题，然后将其放入主题文件夹，并在代码中更改对新主题的引用名称。与所有其他小部件一样，滑块将被重新设计为使用新主题。

要完全改变小部件的外观和感觉，我们可以轻松创建自己的主题文件。在您的文本编辑器中创建以下样式表：

```js
.background-div {
  height: 50px; width: 217px; padding: 36px 0 0 24px;
  background:  url(../img/slider_outerbg.gif) no-repeat;
}
#mySlider {
  background: url(../img/slider_bg.gif) no-repeat; height: 23px;
  width: 184px; border: none; top: 4px; position: relative; 
  left: 4px;
 }
#mySlider .ui-slider-handle {
  width: 14px; height: 30px; top: -4px;
  background: url(../img/slider_handle.gif) no-repeat;
}
```

将此文件保存为`sliderTheme.css`，放在`css`目录中。在`slider1.html`中，在页面的`<head>`标签中添加一个链接到样式表（在 jQuery UI 样式表之后），并将底层滑块元素包裹在一个新容器中：

```js
<div class="background-div">
  <div id="mySlider"></div>
</div>

```

将此文件保存为`slider2.html`。只需最少量的 CSS 和几张图片（这些可以在代码下载中找到），我们就可以轻松但显著地修改小部件的外观，如下面的屏幕截图所示：

![自定义样式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_06_02.jpg)

让我们转向如何配置滑块小部件，使用一些选项。

# 配置基本滑块

还可以使用对象文字配置额外的功能，例如垂直滑块、多个手柄和步进，这些功能在初始化滑块时传递到小部件方法中。可以与滑块小部件一起使用的选项列在以下表格中：

| 选项 | 默认值 | 用法 |
| --- | --- | --- |
| `animate` | `false` | 当单击轨道时启用滑块手柄的平滑动画。 |
| `disabled` | `false` | 当初始化小部件时禁用小部件。 |
| `max` | `100` | 设置滑块的最大值。 |
| `min` | `0` | 设置滑块的最小值。 |
| `orientation` | `auto` | 设置滑块手柄移动的轴。这可以接受字符串垂直或水平。 |
| `range` | `false` | 在它们之间创建一个可定制样式的元素范围。 |
| `step` | `1` | 设置手柄沿轨道移动的步距。最大值必须能够被提供的数字整除。 |
| `value` | `0` | 在初始化小部件时设置滑块手柄的值。 |
| `values` | `null` | 接受一个值数组。每个提供的整数将成为滑块手柄的值。 |

## 创建一个垂直滑块

要创建一个垂直滑块，我们只需将`orientation`选项设置为`vertical`；小部件将为我们完成其余工作。

在`slider1.html`中，更改最后的`<script>`元素，使其如下所示：

```js
<script>
  $(document).ready(function($){
 $("#mySlider").slider({
 orientation: "vertical"
 });
  });
</script>
```

将此文件保存为`slider3.html`。我们只需要设置这个单一选项就可以将滑块放入`vertical`模式。当我们启动页面时，我们会看到滑块的操作与以前完全相同，只是现在它沿着 y 轴移动，如下图所示：

![创建一个垂直滑块](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_06_03.jpg)

小部件默认高度为`100px`，除非我们在样式表中为`.ui-slider-vertical`提供自己的 CSS 规则。

## 设置最大值和最小值

默认情况下，滑块的最小值为`0`，最大值为`100`，但是我们可以使用`min`和`max`选项轻松更改这些值。将`slider3.html`中的配置对象更改为以下代码：

```js
$("#mySlider").slider({
 min: -50,
 max: 50
});
```

将此文件保存为`slider4.html`。我们只需指定我们希望设置为起始和结束值的整数。`value`和`values`方法是滑块专有的，并且用于获取或设置单个或多个手柄的值。由于`value`选项默认设置为`0`，当我们运行`slider4.html`文件时，滑块拇指将从轨道中间开始，在`-50`和`50`之间。

在此示例中，当滑块手柄位于最小值时，`value`方法将返回`-50`，正如我们所期望的那样。为了证明这一点，我们可以修改`slider4.html`以在警报中显示此值。在滑块配置对象的下方立即添加以下代码：

```js
$("#getValue").click(function(){
  var value = $("#mySlider").slider("value");
  alert("Value of slider is " + value);
});
```

在`<body>`标记中，将其更改如下：

```js
  <div id="mySlider"></div>
<p>
<button id="getValue">Get value of slider</button>

```

如果我们现在尝试在浏览器中预览更改，当您将手柄移动到滑块的最左端时，将会弹出一个警报。我们将在本章的*使用滑块方法*部分中探讨`value`选项。

## 使用滑块小部件进行步进

`step`选项是指滑块手柄在从轨道的最小位置移动到最大位置时跳跃的步数和位置。了解此选项如何工作的最佳方法是将其实际操作，因此将`slider4.html`中的配置对象更改为以下代码：

```js
$("#mySlider").slider({
 step: 25
});
```

将此文件保存为`slider5.html`。在此示例中，我们将`step`选项设置为`25`。我们尚未设置`min`或`max`选项，因此它们将采用默认值`0`和`100`。因此，通过将`step`设置为`25`，我们的意思是沿着轨道的每一步应该是轨道长度的四分之一，因为`100`（最大值）除以`25`（步长值）等于`4`。因此，手柄将沿着轨道从头到尾走四步。

滑块的`max`值应该被设置为`step`选项设置的任何值的整数倍；除此之外，我们可以自由选择任何值。`step`选项对于将访问者选择的值限制在一组预定义值中非常有用。

如果我们在这个例子中将`step`选项的值设置为`27`而不是`25`，滑块仍然可以工作，但手柄跳转到的轨道上的点将不相等。

## 对滑块小部件进行动画处理

滑块小部件配有内置动画，每当单击滑块轨道时，该动画会将滑块手柄平滑地移动到新位置。此动画默认情况下是禁用的，但我们可以通过将`animate`选项设置为`true`来轻松启用它。更改`slider5.html`中的配置对象，使其如下所示：

```js
$("#mySlider").slider({
 animate: true
});
```

将此文件保存为`slider6.html`。这个简单的改变可以让滑块感觉更加精致；当点击轨道时，滑块手柄不再立即移动到新位置，而是平滑地滑动到那里。

如果将`step`选项配置为`1`之外的值，并启用`animate`选项，则拇指将滑动到轨道上最近的步骤标记处。这可能意味着滑块拇指移动超过了被点击的点。

## 设置滑块的值

`value`选项，当在配置对象中设置为`true`时，确定滑块拇指的起始值。根据我们想要滑块表示的内容，手柄的起始值可能不是`0`。如果我们想要在轨道的中间开始而不是在开头，我们可以使用以下配置对象：

```js
$("#mySlider").slider({
 value: 50
});
```

将此文件保存为`slider7.html`。当在浏览器中加载文件时，我们可以看到手柄从轨道中间开始，而不是从开头开始，就像我们之前设置`min`和`max`选项时一样。我们也可以在初始化后设置此选项，以编程方式设置新值。

## 使用多个手柄

我之前提到过滑块可能有多个手柄；可以使用`values`选项添加额外的手柄。它接受一个数组，数组中的每个项都是一个手柄的起始点。我们可以指定尽可能多的项，直到`max`值（考虑到步骤）：

```js
$("#mySlider").slider({
 values: [25, 75]
});
```

将此文件保存为`slider8.html`。这是我们需要做的一切；我们不需要提供任何额外的底层标记。小部件已为我们创建了两个新手柄，正如您将看到的，它们的功能都与标准单手柄完全相同。

下面的截图显示了我们的双手柄滑块：

![使用多个手柄](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_06_04.jpg)

我们可以利用双手柄滑块创建时间窗口以供日程安排使用。一个很好的例子是在旅行预订表格上。通常你需要手动输入日期，这可能有点笨拙。

相反，您可以使用双手柄滑块选择日期；用户只需将每个手柄向左或向右滑动以更改日期窗口。然后，我们可以使用本章前面描述的*设置最小值和最大值*部分中描述的方法来获取每个滑块手柄的位置值。

### 提示

当滑块有两个或更多手柄时，每个手柄都可以无障碍地移动到其他手柄之后；如果需要阻止此情况发生，可能需要考虑设置一个`range`。

## 使用范围选项

当使用多个手柄时，我们可以将`range`选项设置为`true`。这将在两个手柄之间添加一个样式化的范围元素。在`slider8.html`中，更改配置对象如下：

```js
$("#mySlider").slider({
  values: [25, 75],
 range: true
});
```

将此文件保存为`slider9.html`。当页面加载时，我们应该看到一个样式化的`<div>`元素现在连接了我们的两个手柄，如下面的截图所示：

![使用范围选项](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_06_05.jpg)

当使用两个手柄和一个范围时，两个手柄将无法在轨道上交叉。

最多可以使用两个手柄与`range`选项一起使用，但我们也可以仅启用一个手柄将上一个示例中的配置对象更改为以下内容：

```js
$("#mySlider").slider({
 range: "min"
});
```

将此文件保存为`slider10.html`。除了布尔值`true`，我们还可以提供字符串值`min`或`max`中的一个，但仅当仅使用一个手柄时。

在这个例子中，我们将其设置为`min`，所以当我们沿着轨道移动滑块手柄时，范围元素将从轨道的起点延伸到滑块手柄。如果我们将选项设置为`max`，范围将从手柄延伸到轨道的末端。

如果您想要捕获手柄在刻度上的位置，我们可以通过使用`slide`事件处理程序来实现。在这种情况下，我们只需要获取一个值（因为我们只有一个手柄），但是如果配置了第二个手柄，同样的原则也适用。

在`slider4.html`中，将以下函数添加到我们滑块的配置对象的上方：

```js
function slideValues(event, ui){
  var val0 = $("#mySlider").slider("values", 0),
    endValue = parseInt(val0, 10);

  $("#rangeValues").text("Range: 0 - " + endValue);
}:
```

然后，我们需要修改配置对象，以在适当的时候调用我们的`slideValues`事件处理程序：

```js
$("#mySlider").slider({
  range: "min",
 slide: slideValues
});
```

因此，我们可以在现有标记的`<body>`部分下方添加以下内容以在屏幕上显示结果：

```js
<div id="rangeValues"></div>
```

然后，我们可以按照我们的意愿操作该值；如果你预览结果，你将看到右侧的值发生变化；左侧的值将始终保持为`0`，因为这是我们代码中`min`选项的默认值。

# 使用滑块的事件 API

除了我们之前看到的选项外，还有另外五个选项用于定义在滑块交互期间不同时间执行的函数。我们使用的任何回调函数都会自动传递标准事件对象和表示滑块的对象。以下表格列出了我们可以使用的事件选项：

| 事件 | 触发时… |
| --- | --- |
| `change` | 滑块的手柄停止移动并且其值已更改。 |
| `create` | 滑块已创建 |
| `slide` | 滑块的手柄移动。 |
| `start` | 滑块的手柄开始移动。 |
| `stop` | 滑块的手柄停止移动。 |

连接到这些内置的回调函数很容易。让我们组合一个基本示例来看看。将`slider10.html`中的配置对象更改为如下所示：

```js
$("#mySlider").slider({
 start: function() {
 $("#tip").fadeOut(function() {
 $(this).remove();
 });
 },
 change: function(e, ui) {
 $("<div></div>", {
 "class": "ui-widget-header ui-corner-all",
 id: "tip",
 text: ui.value + "%",
 css: { left: e.pageX-35 }
 }).appendTo("#mySlider");
 }
});
```

将此文件保存为`slider11.html`。在这个例子中，我们使用了两个回调选项——`start`和`change`。在`start`函数中，如果存在，我们选择提示工具元素，并使用 jQuery 的`fadeOut()`方法将其淡出。一旦从视图中隐藏，它将从页面中移除。

每次滑块手柄的值更改时都将执行`change`函数；当调用该函数时，我们创建工具提示并将其附加到滑块上。我们将其定位，使其出现在滑块手柄的中心上方，并给它一些框架类名称，以便根据使用的主题对其进行样式化。

在几个地方，我们使用传递给回调函数的第二个对象，即包含滑块有用信息的准备好的`ui`对象。在这个例子中，我们使用对象的`value`选项来获取滑块手柄的新值。

对于这个例子，我们还需要一个非常小的自定义样式表。在文本编辑器中，添加以下代码：

```js
#mySlider { margin: 60px auto 0; }
#tip { position: absolute; display: inline; padding: 5px 0; width: 50px; text-align: center; font: bold 11px Verdana; top: -40px }
```

将此文件保存为`css`文件夹中的`sliderTheme2.css`，并从`slider11.html`的`<head>`中添加一个链接。当显示时，我们的工具提示应该如下图所示：

![使用滑块的事件 API](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_06_06.jpg)

当所有事件选项一起使用时，事件将按以下顺序触发：

+   `create`

+   `start`

+   `slide`

+   `stop`

+   `change`

`slide`回调可能是一个相当密集的事件，因为它在每次选择手柄时都会触发鼠标移动，但它也可以通过从回调函数返回`false`来防止在某些情况下滑动。当同时使用`stop`和`change`回调时，`change`回调可能会覆盖`stop`回调。

与库中的所有组件一样，每个事件也可以在 jQuery 的`on()`方法中使用，只需在事件名前加上`slider`一词即可，例如，`sliderstart`。

## 使用滑块方法

滑块很直观，与库中的其他组件一样，它还配备了一系列方法，用于在初始化后以编程方式控制小部件。滑块特有的方法显示在下表中：

| 方法 | 用法 |
| --- | --- |
| `value` | 将单个滑块手柄设置为新值。这将自动将手柄移动到轨道上的新位置。此方法接受一个参数，即表示新值的整数。 |
| `values` | 当使用多个手柄时，设置指定手柄移动到新值。此方法与`value`方法相同，只是它接受两个参数——手柄的索引号，后跟新值。 |

`destroy`、`disable`、`enable`、`option`和`widget`方法对所有组件都是通用的，并且与我们期望的滑块的方式相同地工作。

正如我们在本章早些时候看到的，`value`和`values`方法是专门针对滑块的，并且可以用于获取或设置单个或多个手柄的值。当然，我们也可以使用`option`方法来实现这一点，所以这两种方法只是为了满足常见的实现需求而设置的快捷方式。让我们看看它们的作用。首先让我们看看`value`方法如何使用。

在`slider11.html`中，删除对`sliderTheme2.css`的`<link>`并在页面上的滑块容器后直接添加一个新的`<button>`元素：

```js
<p><button type="button" id="setMax">Set to max value</button></p>
```

现在，更改最终的`<script>`元素，使其如下所示：

```js
<script>
  $(document).ready(function($){
 $("#mySlider").slider();
 $("#setMax").click(function() {
 var maxVal = $("#mySlider").slider("option", "max");
 $("#mySlider").slider("value", maxVal);
 });
  });
</script>
```

将此文件保存为`slider12.html`。我们为新的`<button>`添加了一个点击处理程序；每当它被点击时，此方法将首先确定滑块的最大值，方法是通过将一个变量设置为`option`方法的结果来指定我们想要获取的选项为`max`。一旦我们有了最大值，然后我们调用`value`方法，传入包含最大值的变量作为第二个参数；我们的变量将被用作新值。每当按钮被点击时，滑块手柄将立即移动到轨道的末端。

### 提示

**将值作为选项或方法使用**

在本章的许多示例中，我们提到了`value`（或`values`）作为选项或方法。这可能有点令人困惑；把`value`方法看作是在代码中使用值选项作为 getter 的快捷方式。

使用多个手柄同样简单，但涉及略有不同的方法。

在`slider12.html`中删除`setMax`按钮，并直接在滑块元素后添加以下两个按钮：

```js
<p>
<button type="button" class="preset" id="low">Preset 1 (low) </button>
<button type="button" class="preset" id="high">Preset 2 (high) </button>
```

现在将`<head>`末尾的最后一个`<script>`元素更改为以下代码：

```js
<script>
  $(document).ready(function($){
 $("#mySlider").slider({ 
 values: [25, 75] 
 });

 $(".preset").click(function() {
 if (this.id === "low") {
 $("#mySlider").slider("values", 0, 0).slider("values", 1, 25);
 } else {
 $("#mySlider").slider("values", 0, 75).slider("values" , 
 1, 100);
 }
 });
  });
</script>
```

将此文件保存为`slider13.html`。要触发多个手柄，我们在配置对象中指定了两个手柄的值。当页面上的两个`<button>`元素中的任何一个被点击时，我们会确定是单击了**预设 1**还是**预设 2**，然后根据点击的按钮设置手柄为低值或高值。

### 提示

你也可以使用数组表示法来设置滑块中的值；这将为所有手柄设置相同的值，而不管存在多少手柄。

`values`方法接受两个参数。第一个参数是我们想要更改的手柄的索引号，第二个参数是我们希望手柄设置的值。以下截图显示了在单击第二个按钮后页面应该显示的样子：

![使用滑块方法](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_06_07.jpg)

# 实际用途

HTML5 元素可能特别适合滑块小部件的实现是`<audio>`元素。此元素将自动添加控件，使访问者可以播放、暂停和调整正在播放的媒体的音量。

但是，默认控件无法进行样式化；如果我们希望改变它们的外观，就需要创建我们自己的控件。当然，滑块小部件是默认音量控制的绝佳替代品。让我们看看如何添加一个，作为你自己项目的基础，你可以在其中进一步发展。

在文本编辑器中创建以下新代码：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Slider</title>
  <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
  <link rel="stylesheet" href="css/sliderTheme3.css">
  <script src="img/jquery-2.0.3.js"></script>
  <script src="img/jquery.ui.core.js"></script>
  <script src="img/jquery.ui.widget.js"></script>
  <script src="img/jquery.ui.mouse.js"></script>
  <script src="img/jquery.ui.slider.js"></script>
  <script>
    $(document).ready(function($){
      var audio = $("audio")[0];
      audio.volume = 0.5;
      audio.play();
      $("#volume").slider({
        value: 5,
        min: 0,
        max: 10,
        change: function() {
          var vol = $(this).slider("value") / 10;
          audio.volume = vol;
        }
      });
    });
  </script>
</head>
<body>
  <audio id="audio" controls="controls" src="img/prelude.mp3">
    Your browser does not support the <code>audio</code> element.
  </audio>
  <div id="volume"></div>
</body>
</html>
```

将此文件保存为`slider14.html`。我们还需要添加一些样式来调整显示。在文本编辑器中的新页面中添加以下内容，并将其保存为`sliderTheme3.css`：

```js
#volume { padding-top: 5px; }
#volume.ui-slider { width: 300px; }
.ui-slider-horizontal .ui-slider-handle { margin-left: -0.6em; top: -0.1em; }
```

不要忘记从主页添加到`sliderTheme3.css`的链接：

```js
<link rel="stylesheet" href="css/sliderTheme3.css">
```

在`slider14.html`页面上，我们有一个`<audio>`标记，其`src`属性设置为来自互联网档案馆的音频剪辑。我们还有一个空的容器元素用于我们的音量控制。

### 注意

这个示例使用了 Jan Morgenstern 为大兔子电影创建的音乐配乐文件之一；你可以在 [`archive.org/details/JanMorgenstern-BigBuckBunny`](https://archive.org/details/JanMorgenstern-BigBuckBunny) 下载它以及收藏中的其他文件。

在脚本中，我们首先使用标准的 jQuery 语法选择`<audio>`元素，并从 jQuery 对象中检索实际的 DOM 元素，以便我们可以从`<audio>`API 中调用方法。

接下来，我们为我们的滑块定义配置对象并设置初始最小和最大值。然后，我们添加一个用于更改当前播放音轨音量的`change`事件处理程序，使用`volume`属性方法。每当滑块被更改时，我们都会得到一个新的滑块值，并将其转换为所需的`volume`属性格式，方法是将滑块值除以`10`。一旦我们的变量被定义，我们就设置音频剪辑的音量，并立即使用`play()`方法播放音频剪辑。

当我们在支持的浏览器中运行此示例时，我们可以暂停或播放音频剪辑；如果移动滑块手柄，则剪辑的音量应该增加或减少，如下图所示：

![实际应用](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_06_08.jpg)

# 创建一个颜色滑块

在某些应用程序中非常有用的滑块小部件的有趣实现是颜色滑块。让我们将学到的关于此小部件的知识付诸实践，制作一个基本的颜色选择工具。以下屏幕截图显示了我们将要制作的页面：

![创建颜色滑块](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_06_09.jpg)

在你的文本编辑器中，将`slider1.html`中的`<body>`标记更改为以下代码：

```js
<div id="container" class="ui-widget ui-corner-all ui-widget-content ui-helper-clearfix">
  <label>R:</label>
  <div id="rSlider"></div><br>
  <label>G:</label>
  <div id="gSlider"></div><br>
  <label>B:</label>
  <div id="bSlider"></div>
  <div id="colorBox" class="ui-corner-all ui-widget-content"></div>
  <label for="output" id="outputLabel">Color value:</label>
  <input id="output" type="text" value="rgb(255,255,255)">
</div>
```

现在让我们为我们的演示添加`script`功能，所以请继续移除最后一个`<script>`元素的内容，并添加以下代码：

```js
<script>
  $(document).ready(function($){
    $("#rSlider, #gSlider, #bSlider").slider({
      min:0,
      max: 255,
      value: 255,
      slide: function() {
        var r = $("#rSlider").slider("value"),
        g = $("#gSlider").slider("value"),
        b = $("#bSlider").slider("value");
        var rgbString = ["rgb(", r, ",", g, ",", b, ")"].join("");
        $("#colorBox").css({
          backgroundColor: rgbString
        });
        $("#output").val(rgbString);
      }
    });
  });
</script>
```

将此文件保存为`slider15.html`。页面本身非常简单。我们有一些主要用于显示颜色滑块的不同组件的元素，以及将被转换为滑块小部件的各个容器元素。我们为我们的颜色选择器使用了三个滑块，每个滑块对应一个 RGB 通道。

我们还需要一些 CSS 来完善我们小部件的整体外观。在你的文本编辑器中新建一个页面，创建以下样式表：

```js
#container { width: 426px; height: 146px; padding: 20px 20px 0; position: relative; font-size: 11px; background: #eee; }
#container label { float: left; text-align: right; margin: 0 30px 26px 0; clear: left; }
.ui-slider { width: 240px; float: left; }
.ui-slider-handle { width: 15px; height: 27px; }
#colorBox { width: 104px; height: 94px; float: right; margin: -83px 0 0 0; background: #fff; }
#container #outputLabel { float: right; margin: -14px 34px 0 0; }
#output { width: 100px; text-align: center; float: right; clear: both; margin-top: -17px; }
```

将此文件保存为`colorSliderTheme.css`在`css`文件夹中；别忘了在主文件中调用 jQuery UI 样式表后立即添加对此文件的链接：

```js
<link rel="stylesheet" href="css/colorSliderTheme.css">
```

在我们的代码中，我们给容器和颜色框元素分配了来自 CSS 框架的类名，这样我们就可以利用诸如圆角之类的效果，以减少我们自己编写的 CSS 量。

关注 JavaScript 代码，我们首先设置配置对象。由于 RGB 颜色值范围从`0`到`255`，我们将`max`选项设置为`255`，将`value`选项也设置为`255`，这样小部件手柄就会在正确的位置开始（页面加载时，颜色框将具有白色背景）。

`slide`回调是行动发生的地方。每当移动一个手柄时，我们都会使用`value`方法更新`r`、`g`和`b`变量的值，然后从我们的变量值构造一个新的 RGB 字符串。这是必要的，因为我们不能直接将变量传递给 jQuery 的`css()`方法。我们还会更新`<input>`字段中的值。

运行示例时，我们应该发现一切都按预期工作。一旦我们开始移动任何一个滑块手柄，颜色框就开始变色，而`<input>`也会更新。

### 注意

`slide`事件在选定手柄后的每次鼠标移动时触发；这是一个潜在的密集型事件，在旧浏览器或慢速计算机上可能会引起问题。因此，在生产环境中使用时应谨慎，以使事件处理程序中的不必要操作最小化。

# 引入进度条小部件

小部件只由两个嵌套的`<div>`元素组成——一个外部`<div>`容器和一个内部`<div>`容器，用于突出显示当前进度。下图显示了一个完成 50%的进度条：

![引入进度条小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_06_10.jpg)

让我们来看看最基本的进度条实现。在文本编辑器中的新文件中，创建以下代码：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Progressbar</title>
  <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
  <script src="img/jquery-2.0.3.js"></script>
  <script src="img/jquery.ui.core.js"></script>
  <script src="img/jquery.ui.widget.js"></script>
  <script src="img/jquery.ui.progressbar.js"></script>
  <script>
    $(document).ready(function($){
      $("#myProgressbar").progressbar();
    });
  </script>
</head>
<body>
  <div id="myProgressbar"></div>
</body>
</html>
```

将此文件保存为`jqueryui`项目文件夹中的`progressbar1.html`。没有配置时，进度条当然是空的。我们的示例应该看起来像第一张截图，但没有显示任何进度（容器为空）。

进度条依赖以下组件：

+   `jquery.ui.all.css`

+   `jquery-2.0.3.js`

+   `jquery-ui.core.js`

+   `jquery-ui.progressbar.js`

页面上所需的全部就是一个简单的容器元素。在这种情况下，我们使用了一个`<div>`元素，但是其他块级元素，比如`<p>`，也可以使用。小部件会在初始化时向指定的容器元素添加一个表示进度条值的嵌套`<div>`元素。

此小部件与其他一些小部件（如手风琴）一样，会自然填满其容器的宽度。其他也以类似方式工作的小部件包括标签页、手风琴、滑块和菜单——每个都需要某种形式的容器来限制其在屏幕上的大小。组件会给容器和内部`<div>`元素分别添加一系列属性和类名。类名从正在使用的`theme`文件中获取样式，并且组件完全支持 ThemeRoller。支持 ThemeRoller 意味着你选择的主题可以轻松地更改为另一个 jQuery ThemeRoller 主题，并且小部件将继续正常工作，无需对样式进行任何更改。

添加到小部件的其他属性符合 ARIA 规范，使小部件对使用辅助技术的访问者完全可访问。**ARIA**（**Accessible Rich Internet Applications**）定义了使 Web 内容对使用辅助技术（如屏幕阅读器）的人更具可访问性的方法。所有 jQuery 小部件都对 ARIA 有不同程度的支持，包括进度条；这是通过在代码中出现其他标签来提供的，例如以下代码中突出显示的标签：

```js
<div id="myProgressbar" class="ui-progressbar ui-widget ui-widget-content ui-corner-all" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="20">

```

这些帮助将代码转换为辅助技术将理解的内容；没有它们，代码实际上是隐藏的，这会影响最终用户将看到或听到的内容。

## 列出进度条的选项

写作时，进度条有三个配置选项：

| 选项 | 默认值 | 用法 |
| --- | --- | --- |
| `disabled` | `false` | 禁用小部件 |
| `Max` | `100` | 进度条的最大值 |
| `Value` | `0` | 设置小部件的值（以百分比表示） |

## 设置进度条的值

更改`progressbar1.html`中的最终`<script>`元素，使其显示如下：

```js
<script>
  $(document).ready(function($){
     $("#myProgressbar").progressbar({
       value: 50
    });
  });
</script>
```

将此文件保存为`progressbar2.html`。`value`选项接受一个整数，并将小部件的内部`<div>`的宽度设置为相应的百分比。此更改将使小部件显示为本章第一个屏幕截图中的样子，进度条填充了一半。

## 进度条的事件 API

进度条公开了三个自定义事件，如下表所示：

| 事件 | 当...时触发 |
| --- | --- |
| `create` | 初始化小部件 |
| `change` | 小部件的值更改 |
| `complete` | 小部件的值达到 100％ |

与其他小部件一样，我们可以在配置对象中以匿名回调函数的形式提供这些事件的值，组件将自动为我们调用该函数，每次事件发生时。

要在`progressbar2.html`页面中看到此事件的实际效果，请添加以下`<button>`：

```js
<p><button id="increase">Increase by 10%</button>
```

接下来，将最终的`<script>`块更改为以下内容：

```js
<script>
  $(document).ready(function($){
    var progress = $("#myProgressbar"),
      progressOpts = {
        change: function() {
          var val = $(this).progressbar("option", "value");
          if (!$("#value").length) {
          $("<span />", { text: val + "%", id: "value"}).appendTo(progress);
      } else {
        $("#value").text(val + "%");
      }
    }
  };
    progress.progressbar(progressOpts);
    $("#increase").click(function() {
      var currentVal = progress.progressbar("option", "value"),
    newVal = currentVal + 10;
    progress.progressbar("option", "value", newVal);
    });
  });
</script>
```

将此文件保存为`progressbar3.html`。我们还需要为我们的进度条添加一些样式，因此请添加以下内容到一个新文件，并将其保存为`progressIncrease.css`：

```js
#value { margin-top: -28px; margin-right: 10px; float: right; }
```

不要忘记从页面的`<head>`中添加链接到新样式表（在标准 jQuery UI 样式表之后）：

```js
<link rel="stylesheet" href="css/progressIncrease.css">
```

在我们的示例中，我们首先缓存了进度条的选择器，然后为`change`事件定义了一个事件处理程序。在这个回调函数中，我们首先获取进度条的当前值，这个值将对应于其上次更新后的值。当在事件处理程序内部时，我们可以使用`$(this)`选择进度条。

假设值小于或等于 100（百分比），我们检查页面上是否已经存在具有`id`为`value`的元素。如果元素不存在（即其值没有长度），我们创建一个新的`<span>`元素，并将其文本设置为当前值。我们还给它一个`id`属性并将其定位，以便它出现在进度条内。如果元素已经存在，我们只需将其文本更新为新值。

### 提示

**使用自关闭快捷标签选择器**

您可能已经在代码中看到了`$("<span />")`的使用；这是 jQuery 用于生成标签的完整版本的快捷方式；在这种情况下，它会将其传递的任何内容封装在`<span>`…`</span>`标签中。

我们还为页面上添加的按钮添加了点击处理程序。每当按钮被点击时，我们首先使用`getter`模式中的`option`方法获取进度条的当前值。然后，在将值增加`10`之后，我们使用`setter`模式中的`option`方法将内部`<div>`的值增加`10`个百分点。将该值添加到`<span>`元素中以指示进度。

点击按钮的结果如下所示：

![进度条事件 API](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_06_11.jpg)

在本例中，每当**增加 10%**按钮被点击时，我们都手动设置进度条的值；我们使用标准的`option`方法，该方法适用于所有 UI 库组件，以检索有关进度条当前状态的信息。

不要忘记，像其他库组件一样，此事件也可以通过在事件名称上添加小部件名称前缀来使用 jQuery 的`on()`方法，例如，`progressbarchange`。

## 使用进度条方法

除了所有库组件都公开的常见 API 方法（如`destroy`、`disable`、`enable`、`widget`和`option`）之外，滑块 API 还公开了`value`方法，该方法是使用`option`方法设置进度条值的快捷方式。

我们可以完全像上一个示例中所做的那样，但代码更少，使用`value`方法。更改`progressbar3.html`中的最后一个`<script>`元素，使其如下所示：

```js
<script>
  $(document).ready(function($){
    var progress = $("#myProgressbar");
 progress.progressbar();
    $("#increase").click(function() {
      var currentVal = progress.progressbar("option", "value"), newVal = currentVal + 10;
 progress.progressbar("value", newVal);
 if (!$("#value").length) {
 $("<span />", { text: newVal + "%", id: "value" 
 }).appendTo(progress);
 } else {
 $("#value").text(newVal + "%");
 }
    });
  });
</script>
```

将此文件保存为`progressbar4.html`。在这个例子中，我们丢失了配置对象，因为它不是必需的。

使用`value`方法增加值的逻辑已经移到了`<button>`元素的点击处理程序中。在事件处理程序中，我们获取`currentVal`的值，然后加上`10`，并将其赋值给`newVal`。进度条小部件的`value`属性被更新为新值；进行检查以查看百分比计数文本是否存在。如果不存在（即`#value`的长度为零），则我们添加一个新的实例，其中包含更新后的数字，并在屏幕上显示此数字。

但随着更新代码移动到事件处理程序中，我们看到这使我们能够以更简洁的格式执行与上一个示例相同的操作。

## 添加不定支持

到目前为止，我们已经看到了在更新其结果时如何控制进度条应该使用的百分比值。但是，在某些情况下可能无法始终这样做 - 为了解决这个问题，可以使用一个不定选项。在 jQuery UI 1.10 中添加了这个选项，它允许在不能更新值的情况下使用。这是一个示例，如下图所示：

让我们看一些例子来比较设置已知值和不确定值之间的差异。在`progressbar4.html`中，将`<script>`元素更改为以下代码：

```js
<script>
  $(document).ready(function($){
 $("#myprogressbar").progressbar({ value: false });
 $("button").on("click", function(event) {
 var target = $(event.target), progressbar = $("#myprogressbar"), progressbarValue = progressbar.find(".ui-progressbar-value");
 if (target.is("#numButton")) { 
 progressbar.progressbar("option", { value: Math.floor(Math.random() * 100) });
 } else if (target.is("#falseButton")) {
 progressbar.progressbar("option", "value", false);
 }
 });
});
</script>
```

在代码的`<body>`元素中，将 HTML 更改为以下代码：

```js
<div id="myprogressbar"></div>
<p>
<button id="numButton">Random Value - Determinate</button>
<button id="falseButton">Indeterminate</button>
```

将此文件另存为`progressbar5.html`。点击**不定**按钮的结果如下截图所示：

![添加不定支持](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_06_12.jpg)

虽然在纸质版本中很难看到它的实际效果，但上一个例子显示了一个持续移动的进度条达到 100%，点击**不定**按钮会将`value`属性设置为`false`，告诉进度条假定值为 100%。在这种情况下，自动设置为 100%，表示我们正在取得进展。由于我们无法准确地得出在每个点上取得了多少进展，进度条小部件会自动假定该值为 100%。

相比之下，如果我们知道进度条应该使用的值，我们可以设置该值。点击**随机值 - 确定**按钮，在本章的示例中以类似的方式显示设置这样一个值的效果，如下截图所示：

![添加不定支持](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_06_13.jpg)

# 响应用户交互

在其最基本的层面上，我们可以在响应用户交互时手动更新进度条。例如，我们可以指定一种向导式表单，其中有几个步骤要完成。在这个示例中，我们将创建一个如下截图所示的表单：

![响应用户交互](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_06_14.jpg)

在每个步骤期间，我们可以手动递增进度条，以让用户知道他们进行到了多远的进程。在 `progressbar5.html` 中，用以下代码替换进度条容器和按钮：

```js
<div class="form-container ui-helper-clearfix ui-corner-all">
  <h1>Registration Form</h1>
  <p>Progress:</p>
  <div id="myProgressbar"></div>
  <label id="amount">0%</label>
  <form action="serverScript.php">>
    <div class="form-panel">
      <h2>Personal Details</h2>
      <fieldset class="ui-corner-all">
        <label for="name">Name:</label>
        <input id="name" type="text">
        <label for="dob">D.O.B:</label>
        <input id="dob" type="text">
        <label for="passwrd1">Choose password:</label>
        <input id="passwrd1" type="password">
        <label for="passwrd2">Confirm password:</label>
        <input id="passwrd2" type="password">
      </fieldset>
    </div>
    <div class="form-panel ui-helper-hidden">
      <h2>Contact Details</h2>
      <fieldset class="ui-corner-all">
        <label for="email">Email:</label>
        <input id="email" type="text">
        <label for="tel">Telephone:</label>
        <input id="tel" type="text">
        <label for="address">Address:</label>
        <textarea id="address" rows="3" cols="25"></textarea>
    </fieldset>
  </div>
  <div class="form-panel ui-helper-hidden">
    <h2>Registration Complete</h2>
    <fieldset class="ui-corner-all">
      <p>Thanks for registering!</p>
    </fieldset>
  </div>
  </form>	
  <button id="next">Next</button>
  <button id="back" disabled="disabled">Back</button>
</div>
```

将此文件保存为 `progressbar6.html`。在 `<head>` 部分，我们添加了一个链接到框架主题文件，就像我们在本章的其他示例中所做的那样，并且将需要添加一个链接到稍后添加的自定义样式表：

```js
<link rel="stylesheet" href="css/progressTheme.css">
```

页面的 `<body>` 元素包含一些布局元素和一些文本节点，但主要元素是进度条的容器和 `<form>`。`<form>` 部分使用 `<div>` 和 `<fieldset>` 元素分隔为几个不同的部分。这样做的原因是我们可以隐藏表单的部分，使其看起来好像跨越了几个页面。

我们在进度条旁边添加了一个段落和一个 `<label>` 参数。我们将对它们进行定位，使它们出现在小部件内部。段落包含一个简单的文本字符串。标签将用于显示当前进度值。

外部容器被赋予几个类名；第一个是我们可以对元素应用一些自定义样式，但下一个两个是为了针对 jQuery UI CSS 框架的不同特性。`ui-helper-clearfix` 类用于自动清除浮动元素，并且是减少 `<div>` 元素的额外和不必要的清除混乱的好方法。在创建自己的小部件时，请不要忘记显式使用此类和其他框架类。

### 提示

我们在第二章中介绍了一些核心 CSS 类；CSS 框架 API 的更多详细信息可在[`learn.jquery.com/jquery-ui/theming/api/`](http://learn.jquery.com/jquery-ui/theming/api/)上找到。

`ui-corner-all` 类用于给容器元素（以及进度条本身，它们自动具有这些特性，以及我们的 `<fieldset>` 元素）添加圆角，使用了几个专有的样式规则。这些现在被大多数现代浏览器支持。我们还有一个**下一个**按钮来在每个面板之间前进，并且一个默认情况下被禁用的**返回**按钮。

我们在表单中使用 CSS 框架的另一个类。页面首次加载时需要隐藏多个面板；因此，我们可以使用 `ui-helper-hidden` 类来确保它们设置为 `display: none`。当我们想要显示它们时，我们只需删除此类名。

现在让我们添加 JavaScript。更改页面底部的最后一个 `<script>` 元素，使其显示如下：

```js
$(document).ready(function($){
  var prog = $("#myProgressbar"), progressOpts = {
    change: function() {
      prog.next().text(prog.progressbar("value") + "%");
    }
  };
  prog.progressbar(progressOpts);
  $("#next, #back").click(function() {
    $("button").attr("disabled", true);
    if (this.id == "next") {
      prog.progressbar("option", "value",
      prog.progressbar("option", "value") + 50);
      $("form").find("div:visible").fadeOut().next()
        .fadeIn(function(){
        $("#back").attr("disabled", false);
        if (!$("form").find("div:last").is(":visible")) {
          $("#next").attr("disabled", false);
        }
      });
    } else {
      prog.progressbar("option", "value", prog.progressbar("option", "value") - 50);
      $("form").find("div:visible").not(".buttons").fadeOut() .prev().fadeIn(function() {
        $("#next").attr("disabled", false);
        if (!$("form").find("div:first").is(":visible")) {
          $("#back").attr("disabled", false);
        }
      });
    }
  });
});
```

我们首先缓存进度条的选择器，并定义我们的配置对象，利用`change`事件来指定一个匿名回调函数。每次事件被触发时，我们将使用`value`方法获取进度条的当前值，并将其设置为直接在进度条元素之后的`<label>`参数的文本。事件在更改发生后触发，因此我们获得的值将始终是新值。

一旦进度条被初始化，我们为表单后的按钮添加一个点击处理程序。在此处理程序函数内，我们首先禁用两个按钮，以防止重复点击`<button>`导致表单破坏。然后，我们使用`if`语句运行稍微不同的代码分支，具体取决于所点击的按钮。

如果点击了**下一步**按钮，则通过将`value`选项设置为当前值加上`50`％来将进度条的值增加`50`％。然后，我们淡出当前可见的面板，并淡入下一个面板。我们使用回调函数作为`fadeIn()`方法的参数，该函数将在动画结束时执行。

在此功能内，我们重新启用**返回**按钮（因为点击了**下一步**，所以第一个面板不可见，因此应该启用此按钮），并确定是否启用**下一步**按钮，只要最后一个面板不可见，就可以完成此操作。

外部`if`语句的第二个分支处理了点击**返回**按钮的情况。在这种情况下，我们将进度条减少`50`％，启用**下一步**按钮，并检查是否应启用**返回**按钮。

这现在是我们所需的所有 JavaScript 代码。现在我们所要做的就是添加一些基本的 CSS 来布置示例；在文本编辑器中的新文件中添加以下代码：

```js
h1, h2 { font-family: Tahoma; font-size: 140%; margin-top: 0;}
h2 { margin: 20px 0 10px; font-size: 100%; text-align: left; }
p { margin: 0; font-size: 95%; position: absolute; left: 30px; top: 60px; font-weight: bold; }
#amount { position: absolute; right: 30px; top: 60px; font-	size: 80%; font-weight: bold; }
#thanks { text-align: center; }
#thanks p { margin-top: 48px; font-size: 160%; position: relative; left: 0; top: 0; }
form { height: 265px; position: relative; }
.form-container { width: 400px; margin: 0 auto; position: relative; font-family: Verdana; font-size: 80%; padding: 20px; background-color: #C5DBEC; border: 1px solid #2E6E9E; }
.form-panel { width: 400px; height: 241px; position: absolute; top: 0; left: 0; } 
fieldset { width: 397px; height: 170px; margin: 0 auto; 	padding: 22px 0 0; border: 1px solid #abadac; background-color: #ffffff; }
label { width: 146px; display: block; float: left; text-align: right; padding-top: 2px; margin-right: 10px; }input, textarea { float: left; width: 200px; margin-bottom: 13px; }
button { float: right; }
```

将此保存为 `progressTheme.css` 在 `css` 目录中。现在，我们应该有一个带有已连接的进度条的工作页面。当我们运行页面时，我们应该发现我们可以浏览表单的每个面板，并且进度条将相应地更新自身。

我们仍然依赖用户交互来设置进度条的值，在这个示例中，这是由访问者通过每个面板进行导航驱动的。

# 使用带有进度条的丰富上传

不再依赖用户交互来增加进度条的值，从而完成指定的任务，我们可以依赖系统来更新它，只要有可用的东西可以准确地更新它。

在我们最终的进度条示例中，我们可以整合 HTML5 文件 API，以便异步上传文件，并可以使用`onprogress`事件来在文件上传时更新进度条。

### 提示

此时，您可能想获取伴随本书的代码下载副本，以便您可以在学习示例的同时查看代码。

这个示例只有在安装了并配置了 PHP 的完整 Web 服务器时才能正常工作。在这个示例中，我们不会查看上传过程的服务器端部分；我们只对一旦上传完成，根据从系统收到的反馈来更新进度条感兴趣。

修改`progressbar6.html`中的`<body>`，使其包含以下元素：

```js
<div id="container">
  <h1>HTML5 File Reader API</h1>
  <form id="upload" action="upload.php" method="POST" enctype="multipart/form-data">
    <fieldset>
      <legend>Image Upload</legend>
      <input type="hidden" id="MAX_FILE_SIZE" name="MAX_FILE_SIZE"value="300000" />
      <div>
        <label for="fileselect">Image to upload:</label>
        <input type="file" id="fileselect" name="fileselect[]"multiple="multiple" />
      </div>
      <div id="progress"></div>
    </fieldset>
  </form>
  <div id="messages"></div>
</div>
```

在页面上，我们有一个`file`类型的`<input>`元素，后面跟着进度条的容器，就像往常一样。接下来，让我们添加脚本；将`<head>`末尾的最后一个`<script>`元素更改为以下代码：

```js
$("document").ready(function($) {
  if (window.File && window.FileList && window.FileReader) {
    $("#fileselect").on("change", function(e) {
      var files = e.target.files || e.dataTransfer.files;
      for (var i = 0, f; f = files[i]; i++) {
        ParseFile(f);
        UploadFile(f);
      }
    });
  }
});
```

将此文件保存为`progressbar7.html`。将以下代码添加到一个新文档中，并保存为`uploads.js`：

```js
function ParseFile(file) {
  $("#messages").html(
    "<p>File information: <strong><br>" +
    "</strong> type: <strong>" + file.type + "<br>" +
    "</strong> size: <strong>" + file.size + 
    "</strong> bytes</p>"
  );

  if (file.type.indexOf("image") === 0) {
    var reader = new FileReader();
    reader.onload = function(e) {
      $("#messages").prepend(
        "<br>Image:<br><strong>" + file.name + "</strong><br />" +
        '<img class="preview" src="img/' + e.target.result + '" /></p>'
      );
    };
    reader.readAsDataURL(file);
  }
}

function UploadFile(file) {
  $("#progress").progressbar();
  var xhr = new XMLHttpRequest();
  xhr.upload.onprogress = function updateProgress(e) {
    var fileloaded = (e.loaded / e.total);
    $("#progress").progressbar("value", Math.round(fileloaded * 100));
  };

  xhr.upload.onload = function() {
    $("#progress").progressbar("value", 100);
  };

  xhr.open("POST", $("#upload").action, true);
  xhr.setRequestHeader("X_FILENAME", file.name);
  xhr.send(file);
}
```

最后，在文档的`<head>`元素下方立即添加以下内容：

```js
<script type="text/javascript" src="img/uploads.js"></script>
```

首先，在`progressbar7.html`中，我们进行检查以确认浏览器是否支持 File API；如果可以，我们就会启动一个事件处理程序，该处理程序会在点击`fileselect`按钮时立即触发。

在更改处理程序中，我们获取所选文件的详细信息并将其保存到数组中；然后，我们调用`ParseFile()`函数（在`uploads.js`中）来首先启动输出消息，然后使用`FileReader()`加载和读取图像的副本，并将图像的副本输出到屏幕。同时，我们显示图像名称的详细信息。

继续到`uploads.js`，然后我们调用`UploadFile`函数，这就是真正的魔法发生的地方。我们首先初始化一个进度条的实例，给它一个`progress` ID，并使用一个`<div>`元素作为其容器。然后，代码设置了一个`XMLHttpRequest()`的实例，并打开了一个`POST`连接以上传文件。在这种情况下，文件实际上只上传到服务器上的一个测试文件夹（或在这种情况下，您的个人电脑上），称为 uploads；在这一点上，您将创建一个上传脚本，该脚本将把文件重定向到远程服务器上的适当位置。

每当`XMLHttpRequest`参数更新时，它都会触发`onprogress`事件处理程序来更新进度条；我们计算总文件大小与已上传内容之间的差异，然后将其转换为百分比，并用此百分比来更新进度条。一旦上传完成，我们就会触发`onload()`事件处理程序，以确保它显示 100% 完成。

对于这个示例，我们还需要一些 CSS；在一个新的文本文件中添加以下代码：

```js
body { font-family: "Segoe UI", Tahoma, Helvetica, Freesans, sans-serif; font-size: 90%; margin: 10px; color: #333; background-color: #fff; }
#container { margin-left: auto; margin-right: auto; width: 430px;  }
#messages { padding: 0 10px; margin: 1em 0; border: 1px solid #999; width: 400px; clear: both; height: 275px; }
#messages p { position: absolute; float: left; margin-left: 275px; width: 150px; }
#progress { margin-top: 3px; width: 390px; left: -2px; }
h1 { font-size: 1.5em; font-weight: normal; }
legend { font-weight: bold; color: #333; }
.preview { height: 60%; width: 60%; float: left; }
fieldset { width: 400px; }
```

此文件可以保存在`css`文件夹中，命名为`uploads.css`。大部分样式只是定位各个元素并设置进度条的宽度。我们也不需要链接到`progressTheme.css`，因此也可以将其删除。

当我们运行这个文件时，我们应该看到一旦选择了文件，它就会自动开始上传，并且进度条将开始填充。如果在本地进行测试，速度会相当快，所以最好使用相当大的文件进行测试。

以下屏幕截图显示了上传完成后的页面：

![使用进度条实现丰富上传](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_06_15.jpg)

# 总结

在本章中，我们看了两个界面小部件，它们都可以提供某种形式的视觉反馈，无论是作为操作的结果还是设置特定的值。我们看到了如何快速、简单地将滑块小部件放在页面上，并且它需要最少的底层标记和仅一行代码来初始化。

我们探讨了可以设置的不同选项，以控制滑块的行为以及在初始化后如何配置它，同时提供可以在交互期间的重要时间执行代码的回调。我们还介绍了可以用于以编程方式与滑块进行交互的方法，包括用于设置手柄值的方法，或在初始化后获取和设置配置选项的方法。

我们还查看了具有紧凑 API 的进度条小部件，它在进程进行时提供了必要的访问者反馈。然后我们研究了在初始化之前或小部件正在使用时可以用来配置小部件的各种选项。我们还研究了可用于与进度条小部件一起工作的方法，看看我们如何可以轻松地对进度更改做出反应，或者在小部件完成后做出反应。

我们还看了进度条如何包含对不确定进度指示器的支持，用于在当前进程状态无法精确确定时使用。

在下一章中，我们将看到日期选择器小部件，它拥有库中所有小部件中最大、功能最丰富的 API，并包含完整的国际化支持。
