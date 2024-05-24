# jQueryUI 1.10：jQuery 的用户界面库（五）

> 原文：[`zh.annas-archive.org/md5/67D4BB507B37025C38972681032F3C25`](https://zh.annas-archive.org/md5/67D4BB507B37025C38972681032F3C25)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：第 13 章：使用 jQuery UI 进行选择和排序

如果你花费了任何时间与列表（比如 Microsoft Excel 这样的应用程序）打交道，那么你可能需要选择并按照某种逻辑顺序对项目进行排序，类似于在计算机桌面上选择和排序图标的方式。

jQuery UI 中的可选择和可排序交互辅助程序允许您定义一系列可以通过拖动选择方框来选择的元素，然后重新排序为新顺序。

此部分将涵盖的主题包括：

+   创建默认的可选择实现

+   可选择类名称如何反映可选择元素的状态

+   过滤可选择元素

+   使用内置回调函数处理可选择的元素

+   查看可选择元素的方法

+   创建默认的可排序小部件

+   基本可配置属性

+   可排序的各种内置事件处理程序和方法

+   将排序结果提交到服务器

+   将拖动元素添加到可排序中

选择和排序长期以来一直是现代操作系统的标准部分。例如，如果你想要选择和排序桌面上的一些图标，你可以在桌面的空白部分按住鼠标按钮并在你想要选择的图标周围画一个方框，或者从桌面中选择**自动排列图标**选项。

可选择和可排序的交互辅助程序将相同的功能添加到我们的网页中，这样我们就可以构建更加用户友好的界面，而无需使用外部环境，如 Flash 或 Silverlight。

# 介绍可选择小部件

我们首先要做的是调用默认实现，以了解此组件提供的基本功能。

在文本编辑器中的新文件中添加以下代码：

```js
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="utf-8">
    <title>Selectable</title>
    <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
    <script src="img/jquery-2.0.3.js"></script>
    <script src="img/jquery.ui.core.js"></script>
    <script src="img/jquery.ui.widget.js"></script>
    <script src="img/jquery.ui.mouse.js"></script>
    <script src="img/jquery.ui.selectable.js"></script>
    <script>
      $(document).ready(function($){
        $("#selectables").selectable();
      });  
    </script> 
  </head>
  <body>
<ul id="selectables">
  <li> This is selectable list item 1</li>
  <li> This is selectable list item 2</li>
  <li> This is selectable list item 3</li>
  <li> This is selectable list item 4</li>
  <li> This is selectable list item 5</li>
</ul>
  </body>
</html>
```

将其保存为`jqueryui`文件夹中的`selectable1.html`。我们只需在父`<ul>`元素上调用`selectable`小部件方法，然后所有子`<li>`元素都可以选择。这允许通过点击或使用选择方框（就像你在桌面上做的那样）进行选择。

请注意，与可选择组件相关联的样式是不存在的。默认行为包括单击单个元素只会选择它们，并单击所选元素中的一个以取消选择它们。按住*Ctrl*键将启用多选。以下截图显示了选项方框包围的列表项：

![介绍可选择小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_01.jpg)

我们用于可选择实现的最小一组库文件如下：

+   `jquery-2.0.3.js`

+   `jquery.ui.core.js`

+   `jquery.ui.widget.js`

+   `jquery.ui.mouse.js`

+   `jquery.ui.selectable.js`

除了从列表项构建可选择项之外，我们还可以从其他元素构建可选择项，例如一组`<div>`元素。将以下链接添加到`selectable1.html`文件的`<head>`中：  

```js
<link rel="stylesheet" href="css/selectable.css">
```

此外，用以下代码替换`selectable1.html`中的列表元素：

```js
<div id="selectables">
  <div>This is selectable list item 1</div>
  <div>This is selectable list item 2</div>
  <div>This is selectable list item 3</div>
  <div>This is selectable list item 4</div>
  <div>This is selectable list item 5</div> 
</div>
```

将此保存为`selectable2.html`。一切基本上与以前相同。

我们只是基于不同元素的示例。然而，由于这些元素的性质，我们应该添加一些基本的样式，以便我们可以看到我们正在处理的内容。

在文本编辑器中的新文件中添加以下代码：

```js
#selectables div { width: 170px; height: 25px; padding: 5px 0 0 10px; margin: 10px 0 0 10px; border: 1px solid #000; }
```

将此保存为`selectable.css`在`css`文件夹中。虽然不多，但它有助于澄清示例中的各个可选择项，如下图所示：

![介绍可选择小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_02.jpg)

# 介绍 Selectee 类名

所有可选择的元素最初都被赋予`ui-selectee`类，包含它们的父元素被赋予`ui-selectable`类。当元素被选择时，它们被赋予`ui-selected`类。

当选择方块围绕可选择元素时，它们被赋予`ui-selecting`类，并且在取消选择元素时，元素被赋予`ui-unselecting`类。这些类名纯粹是为了我们的方便，这样我们就可以突出显示可选择的不同状态。

这个广泛的类系统使得非常容易添加自定义样式来显示元素是正在被选择还是已被选择。现在让我们添加一些额外的样式来反映选择和已选择的状态。将以下新的选择器和规则添加到`selectable.css`中：

```js
#selectables div.ui-selecting { border: 1px solid #fe2f2f; }
#selectables div.ui-selected { background: #fe2f2f; color: #fff; }
```

将此`selectableStates.css`保存在`css`文件夹中。更改`selectable2.html`的`<head>`中的样式表引用链接，然后将此文件保存为`selectable3.html`：

```js
<link rel="stylesheet" href="css/selectableStates.css">
```

借助这个非常简单的 CSS，我们可以为当前选择的元素添加视觉提示，无论是在选择过程中还是在选择交互后。以下屏幕截图显示了左侧正在被选择的一些元素，以及右侧已被选择的相同元素：

![介绍 Selectee 类名](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_03.jpg)

# 配置可选择组件

`selectable` 类相当紧凑，与我们之前查看的一些其他组件相比，具有相对较少的可配置选项。

下列选项可供配置：

| 选项 | 默认值 | 用于... |
| --- | --- | --- |
| `autoRefresh` | `True` | 在选择交互开始时自动刷新每个可选择项的大小和位置。 |
| `cancel` | `":input, option"` | 防止通过单击选择指定的元素。默认字符串包含`：input`jQuery 过滤器，它匹配所有`<input>`、`<textarea>`、`<select>`和`<button>`元素以及标准选项元素选择器。 |
| `delay` | `0` | 设置在选择元素之前的毫秒延迟。必须在元素上按住鼠标按钮，然后选择才会开始。 |
| `disabled` | `false` | 当页面首次加载时禁用选择。 |
| `distance` | `0` | 设置鼠标指针必须移动的距离（按住鼠标按钮），然后选择才会开始。 |
| `filter` | `"*"` | 指定要使可选择的子元素。 |
| `tolerance` | `"touch"` | 设置选择框的容差。可能的值是`touch`或`fit`。如果指定了`fit`，则元素必须完全位于选择框内，才会被选中。 |

## 筛选可选择项

可能存在这样的情况，即我们不希望允许目标容器中的所有元素都可选择。在这种情况下，我们可以使用`filter`选项来指定我们希望启用选择的特定元素，基于 CSS 选择器。在`selectable3.html`中，更改`<div>`元素的集合，使其如下所示：

```js
<div id="selectables">
 <div> This is unselectable list item 1</div>
 <div> This is unselectable list item 2</div>
  <div class="selectable">This is selectable list item 3</div>
  <div class="selectable">This is selectable list item 4</div>
  <div class="selectable">This is selectable list item 5</div>
</div>
```

然后将最后一个`<script>`元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
    $("#selectables").selectable({
 filter: ".selectable"
    });
  });  
</script> 
```

每个可选择项的宽度需要增加，所以在`selectableStates.css`中，将`#selectables div`规则的宽度更改为 190 像素。

将此版本保存为`selectable4.html`。在底层标记中，我们为每个元素除第一个元素外都添加了一个类。在 JavaScript 中，我们定义了一个包含`filter`选项的配置对象。此选项的值是我们希望可选择的元素的类选择器；没有此类名称的元素将被过滤出选择：

![筛选可选择项](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_04.jpg)

如前面的屏幕截图所示，选择框位于不可选择的元素上方，但它并没有像其他元素那样捕获`ui-selecting`类。该组件完全忽略了被过滤的可选择项，并且它不会成为选择的一部分。

## 取消选择

除了间接地使用`filter`选项使元素不可选择之外，我们还可以直接使用`cancel`选项使元素不可选择。这个选项也是我们在第十二章中看到的交互助手暴露出来的，*可调整大小的组件*，尽管我们没有详细研究它。现在是与它互动的绝佳机会。

在`selectable4.html`中的容器中向第一个和第二个元素添加类名`unselectable`：

```js
<div class="unselectable"> This is unselectable list item 1</div>
<div class="unselectable">This is unselectable list item 2</div>
```

将上一个示例中的配置对象更改为使用`cancel`选项：

```js
$("#selectables").selectable({
 cancel: ".unselectable"
})
```

将其保存为`selectable5.html`。我们不是将可选择元素的类名传递给配置对象，而是将不可选择元素的类名传递给它。当我们运行示例时，我们可以看到具有类名`unselectable`的第一个元素仍然被赋予了类`ui-selectee`。然而，它只能通过选择框进行选择；即使按住*Ctrl*键，也无法通过单击选择。

# 处理可选择项事件

除了可配置的标准可选 API 选项外，还有一系列事件回调选项，可以用来指定在选择交互期间特定时间点执行的函数。这些选项列在以下表中：

| Option | 触发时机 |
| --- | --- |
| `selecte` | 选择交互结束，并且每个添加到选择中的元素都触发回调。 |
| `selecting` | 每个选定的元素在选择交互期间触发回调函数。 |
| `start` | 选择交互开始。 |
| `stop` | 选择操作结束。 |
| `unselected` | 在交互期间未被选中的任何元素都将触发此回调。 |
| `unselecting` | 在选择交互期间取消选择的元素将触发此事件。 |

选择真正变得有用的是一旦元素被选中后发生的事情，这就是事件模型发挥作用的地方。让我们使用其中一些回调函数来工作，以便我们能够欣赏它们的用途。

替换`selectable5.html`中的配置对象，使其包含以下代码：

```js
$("#selectables").selectable({
  selected: function(e, ui) {
    $(ui.selected).text("I have been selected!");
  },
  unselected: function(e, ui) {
    $(ui.unselected).text("This div was selected");
  },
  start: function(e) {
    if (!$("#tip").length) {
      $("<div />", {
        "class": "ui-corner-all ui-widget ui-widget-header",
        id: "tip",
        text: "Drag the lasso around elements, or click to select",
        css: {
          position: "absolute",
          padding: 10,
          left: e.pageX,
          top: e.pageY - 30,
          display: "none"
        }
      }).appendTo("body").fadeIn();
    } 
  },
  stop: function(e) {
    $("#tip").fadeOut("slow", function() {
      $(this).remove();
    });
  }
});
```

将此保存为`selectable6.html`。在`<script>`中，我们添加了选定、未选定、开始和停止选项的函数。这些函数将在交互期间的适当时间执行。

与其他组件一样，这些函数会自动传递两个对象。第一个是原始的浏览器事件对象（通常称为`e`），另一个是包含所选元素的有用属性的对象（通常称为`ui`）。然而，并不是所有的回调函数都能成功地使用第二个对象，例如 start 和 stop。在我们的例子中，我们省略了`ui`对象；没有必要包含它，因为它将是空的。

当选择一个`<div>`时，我们使用`selected`事件回调将其内部文本更改以反映选择。我们可以使用`selected`属性获取被选中的元素，以便将其文本内容更改为新消息。当一个元素被取消选择时，我们使用相同的技术将文本设置为`The div was selected`。

我们还可以使用`unselected`事件更改以前选中的任何可选择项的文本。

在任何交互开始时，我们创建一个工具提示，将其附加到页面的`<body>`中，略微偏离鼠标指针，使用`start`事件。我们使用基本条件来检查工具提示是否已经存在，以防止重复提示。我们可以利用框架类`ui-corner-all`、`ui-widget`和`ui-widget-header`大部分样式处理。我们使用`css()`方法添加了主题未提供的少量样式。我们可以使用传递给我们回调函数的第一个参数`e`（事件）对象获取指针坐标，以定位工具提示。在选择结束时，我们使用`stop`属性移除工具提示。以下屏幕截图显示了不同交互的结果：

![处理可选事件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_05.jpg)

`selecting`和`unselecting`回调选项的工作方式与我们刚刚查看的选项完全相同，但是在添加或移除元素时触发。要看到其实际操作，将`selectable6.html`中的配置对象中的`selected`和`unselected`选项替换为以下内容：

```js
  selecting: function(e, ui) {
    $(ui.selecting).text("I am part of the selection");
  },
  unselecting: function(e, ui) {
    $(ui.unselecting).text("I was part of the selection");
  },
```

将您的工作保存为`selectable7.html`。这次，我们使用`selecting`和`unselecting`属性来指定回调函数，再次在交互过程中的特定时间更改元素的文本内容。我们重复上一个示例中的过程，这次我们只是使用不同的回调和传递给它们的对象的属性。

传递给任何可选回调的第二个对象包含与自定义事件类型相关的属性。例如，选择的回调接收一个带有`selected`属性的对象，该属性可用于获取有关添加到选定项中的元素的信息。所有回调都有相匹配的属性可用于此种方式。

## 处理大量可选元素

jQuery UI 库与 jQuery 本身一样，已经非常高效。它使用高效的**Sizzle 选择器引擎**（通过 jQuery），并且每个组件都已尽可能地进行了优化。

### 注

Sizzle 是 jQuery 使用的纯 JavaScript CSS 选择器引擎，它允许您在 CSS 选择器上使用 JavaScript，例如`$("<div>")`。如果您想了解更多，请访问项目网站[`sizzlejs.com/`](http://sizzlejs.com/)。

然而，库的创建者们只能做这么多。到目前为止，我们使用了最多五个可选元素，这实际上并不多。如果我们要使用 500 个又会怎样呢？

当使用大量可选元素时，仍然有一些事情可以做，以确保选择交互尽可能高效。默认情况下，`autoRefresh`选项设置为`true`，这会导致页面上所有可选择元素的大小和位置在每次交互开始时重新计算。

当页面上有许多可选择元素时，这可能会导致延迟，因此当处理大量元素集合时，可以将 `autoRefresh` 选项设置为 `false`。我们还可以在适当的时候使用 `refresh` 方法手动刷新可选择元素，以提高交互的速度和响应性。在大多数页面上，我们不需要担心配置此选项，可以将其保留为默认设置。

让我们看看在某些情况下，此选项如何帮助我们的页面。在 `selectable7.html` 的 `<head>` 中，将自定义样式表的 `<link>` 更改为以下内容：

```js
<link rel="stylesheet" href="css/selectableMany.css ">
```

然后修改可选择元素容器元素，使其显示如下：

```js
<div id="selectables" class="ui-helper-clearfix">
 <div class="selectable">Selectable</div>
</div>
```

我们将使用一点 jQuery 来自动创建我们的可选择元素，因此将 `document.ready()` 块中的现有脚本替换为以下代码：

```js
    var $selectable = $(".selectable");
   for(var I = 0; I < 100; i++) {
     $selectable.parent().append($selectable.clone());
   }
   $("#selectables").selectable({
     autoRefresh: false
   });
```

将此页面保存为 `selectable8.html`。我们的页面现在应该包含 `100` 个单独的可选择元素在可选择元素容器内。我们还为外部容器添加了一个类名，以便在浮动可选择元素时正确清除容器（我们稍后会这样做）。如果容器没有正确清除，选择框将无法工作。我们在可选择的 `div` 中添加了 `.ui-helper-clearfix` 类来帮助解决此问题。

我们还需要一个新的样式表示例，代码如下：

```js
#selectables div { width: 70px; height: 25px; padding: 5px 0 0 10px; border: 1px solid #000; margin: 10px 0 0 10px; float: left; }
.ui-selected { background-color: #fe2f2f; }
```

将其保存在 `css` 文件夹中，命名为 `selectableMany.css`。它纯粹用于布局目的，所以我们不需要进一步讨论它。

我们可以使用类似 Chrome 的开发者工具来分析所有 `100` 个可选择元素的选择情况，分别启用和禁用 `autoRefresh` 选项；它默认是启用的，所以我们的示例会将其禁用。测试结果可能会有所不同，但你会发现，将 `autoRefresh` 设置为禁用时，性能剖析结果（以毫秒和调用次数表示）通常会更低。

### 小贴士

**如何剖析 JavaScript 性能？**

关于如何在 Chrome 等浏览器中进行性能剖析的详细信息，您可以在 [`developers.google.com/chrome-developer-tools/docs/cpu-profiling`](https://developers.google.com/chrome-developer-tools/docs/cpu-profiling) 上查看一个有用的教程。

# 使用可选择元素方法

我们可以使用类似其他交互式辅助工具中找到的方法来控制代码中的可选择元素组件，使用模式相同。可选择元素组件唯一公开的唯一方法列在下面：

| 方法 | 用法 |
| --- | --- |
| `刷新` | 手动刷新所有可选择元素的位置和大小。当 `autoRefresh` 设置为 `false` 时应使用。 |

除了这个独特的方法之外，可选择元素组件（像每个其他组件一样）还使用了通用的 API 方法 `destroy`、`disable`、`enable`、`option` 和 `widget`。

## 刷新可选择元素

将 `autoRefresh` 属性设置为 `false` 可以在页面上有许多可选择项时提高性能，特别是在 Internet Explorer 中。然而，仍然会有时候需要刷新可选择项的大小和位置，比如当此组件与可拖动组件结合使用时。

让我们看看 `refresh` 方法，因为它完美地延续了上一个示例。直接在可选择的容器后添加以下新的 `<button>` 元素：

```js
<button id="refresh">Refresh</button>
```

对于此示例，我们还需要链接到可拖动源文件：

```js
<script src="img/jquery.ui.draggable.js">
</script>
```

然后更改最终的 `<script>` 元素，使其如下所示：

```js
<script>
  $(document).ready(function($){
    var $selectable = $(".selectable");
    for(var i = 0; i < 100; i++) {
      $selectable.parent().append($selectable.clone());
    }
    $("#selectables").selectable({
      autoRefresh: false
    });
    $("#selectables div").draggable();
    $("#refresh").click(function() {
      $("#selectables").selectable("refresh");
    });
  });  
</script> 
```

将此保存为 `selectable9.html`。我们在页面上添加了一个新的 `<button>`，现在我们链接到了可拖动源文件以及可选择的源文件。这 100 个元素都可以同时拖动和选择。

我们附加到 `<button>` 的点击处理程序将在可选择项容器上手动调用 `refresh` 方法。当我们在浏览器中运行页面时，我们应该首先选择一些但不是所有的可选择小部件。然后我们应该取消选择元素并移动其中一些元素。我们还可以将未选择的其他元素移动到选择组中。真的要将它们混在一起！

当我们尝试再次选择相同的组时，我们发现选择了错误的元素：

![刷新可选择项](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_06.jpg)

组件没有刷新可选择项的位置，所以它仍然认为所有可选择项的位置与第一次选择时的位置相同。如果我们点击 **refresh** 按钮并进行第三次选择，则现在将选择正确的元素。

# 创建可选择的图像查看器

在我们的最终可选择示例中，我们将制作一个基本的图像查看器。通过选择相应的缩略图来选择图像进行查看。尽管这听起来像是一个相对容易的成就，除了显示所选图像的实际机制之外，我们还需要考虑如何处理多个选择。

以下屏幕截图显示了我们将要完成的示例：

![创建可选择的图像查看器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_07.jpg)

让我们开始编码。在文本编辑器中的新页面中，添加以下页面：

```js
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="utf-8">
    <title>The Selectables Component</title>
    <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
    <link rel="stylesheet" href="css/selectableViewer.css">
    <script src="img/jquery-2.0.3.js"></script>
    <script src="img/jquery.ui.core.js"></script>
    <script src="img/jquery.ui.widget.js"></script>
    <script src="img/jquery.ui.mouse.js"></script>
    <script src="img/jquery.ui.selectable.js"></script>
    <script src="img/jquery.ui.tabs.js"></script>
    <script>  
    </script> 
  </head>
  <body>
    <div id="imageSelector"
      class="ui-widget ui-corner-all ui-helper-clearfix">
      <div id="status" class="ui-widget-header ui-corner-all">Crab</div>
      <div id="viewer"><img src="img/crab.jpg"></div>
      <div id="thumbs">
        <img class="ui-selected" id="crab" src="img/crab.jpg">
        <img class="right" id="orion" src="img/orion.jpg">
        <img id="omega" src="img/omega.jpg">
        <img class="right" id="egg" src="img/egg.jpg">
        <img id="triangulum" src="img/triangulum.jpg">
        <img class="right" id="rosette" src="img/rosette.jpg">
        <img id="ring" src="img/ring.jpg">
        <img class="right" id="boomerang" src="img/boomerang.jpg">
      </div>
    </div>
  </body>
</html>
```

将此保存为 `imageSelector.html`。在页面上，我们有一个父级 `<div>`，其 `id` 为 `imageSelector`，其中包含我们的所有其他元素。

在父元素内，我们有一个 `<div>` 作为状态栏来显示单独选择的图像的名称，和一个 `<div>` 作为查看面板，并显示图像的全尺寸版本。最后，我们有缩略图图像，将可以选择。

## 添加行为

接下来我们需要添加使图像选择器工作的脚本，因此在最后一个`<script>`元素之后直接添加以下代码；在本节中，我们将逐块地解析这段代码，从选择项的配置对象开始：

```js
  $(document).ready(function($){
    $("#thumbs").selectable({
      stop: function(e, ui) {
        $("#imageSelector").children().not("#thumbs")
.remove();
        $("<div />", { 
          id: "viewer"
        }).insertBefore("#thumbs");
        if ($(".ui-selected", "#thumbs").length == 1) {
          singleSelect();
        } else {
          multiSelect();
        }
      }
    });
```

我们使用`stop callback`函数执行一些准备工作，例如删除图像选择器容器的内容（除了缩略图）并创建一个空的查看器容器。然后我们使用一个`if`条件来调用`singleSelect()`或`multiSelect()`函数中的一个。

```js
function singleSelect() {
      var id = $(".ui-selected", "#thumbs").attr("id");
      $("<div />", {
        id: "status",
        text: id,
        "class": "ui-widget-header ui-corner-all"
      }).insertBefore("#viewer");
        $("<img />", {
          src: "img/" + id + ".jpg",
          id: id
        }).appendTo("#viewer");
      }
```

然后我们定义两个函数中的第一个，即`singleSelect()`。这将在每次选择单个缩略图时调用。我们首先缓存所选元素的`id`；我们将多次引用它，因此将其存储在一个变量中更有效。

接下来我们创建一个新的状态栏，并将其`innerText`设置为片刻前缓存的`id`值，该值将是所选缩略图的`id`属性。我们为新元素添加了一些框架类以样式化该元素，然后将其插入到图像选择器容器中。

在这个函数中我们做的最后一件事是创建缩略图的全尺寸版本。为此，我们创建一个新的图像，并将其`src`属性设置为所选缩略图的大尺寸版本（每个图像的大尺寸和缩略图版本具有相同的文件名）。然后将全尺寸图像插入到查看器容器中。

```js
function multiSelect() {
       $("<div />", {
         id: "tabs"
       }).insertBefore("#viewer");
       var tabList = $("<ul />", {
         id: "tabList"
       }).appendTo("#tabs");   
```

接下来我们定义`multiSelect()`函数，当选择多个缩略图时调用该函数。这次我们首先创建一个新的`<div>`元素，为其设置一个`id`为 tabs，并在查看器容器之前插入它。在此之后，我们创建一个新的`<ul>`元素，因为这是标签小部件的必需组件（我们在第三章中讨论过标签小部件，*使用标签小部件*）。此元素被附加到我们刚刚创建的标签容器中。

```js
 $(".ui-selected", "#thumbs").each(function() {
    var id = $(this).attr("id"),
      tabItem = $("<li />").appendTo(tabList),
        tabLink = $("<a />", {
          text: id,
          href: "#tabpanel_" + id
        }).appendTo(tabItem),
        panel = $("<div />", {
          id: "tabpanel_" + id
        }).appendTo("#viewer");
        $("<img />", { src: "img/" + id + ".jpg",
          id: id
        }).appendTo(panel);
      });
      $("#viewer").css("left", 0).appendTo("#tabs");
      $("#tabs").tabs();
    }
  });  
```

然后我们使用 jQuery 的`each()`方法迭代所选择的每个缩略图。对于每个项目，我们创建一系列变量，用于保存组成选项卡标题的不同元素。我们缓存每个图像的`id`属性并创建一个新的`<li>`和一个新的`<a>`元素。链接将形成可点击的选项卡标题，并将缩略图的`id`作为其文本内容。

然后我们创建与我们刚刚创建的选项卡标题匹配的新选项卡面板。注意，我们根据缩略图的`id`属性和一些硬编码的文本创建了内容面板的唯一`id`。注意，`id`将精确匹配我们在`<a>`元素上设置的`href`属性。每个新图像都是以与`singleSelect()`函数相同的方式创建的。

在`each()`方法之后，我们设置了一个 CSS 属性来整理查看器容器的外观，然后将其附加到选项卡容器。最后，在选项卡容器上调用了`tabs()`方法，将其转换为选项卡小部件。在脚本的末尾，缩略图可以被选择。

## 设置图像选择器的样式

我们的示例还严重依赖 CSS 来提供其整体外观。在您的文本编辑器中的新文件中，创建以下新样式表：

```js
#imageSelector { width: 676px; height: 497px; border: 1px solid #adadad; margin: 0 auto; position: relative; background-color: #dfdede; }
#status { width: 380px; height: 21px; padding: 10px; position: absolute; left: 17px; top: 17px; font-size: 19px; text-align: center; background-color: #adadad; border: 1px solid #adadad; text-transform: capitalize; }
#viewer { width: 400px; height: 400px; border: 1px solid #fff; position: absolute; left: 17px; top: 78px; }
#thumbs { width: 222px; height: 460px; position: absolute; right: 17px; top: 17px; }
#thumbs img { width: 100px; height: 100px; float: left; margin: 0 18px 18px 0; cursor: pointer; border: 1px solid #fff; }
#thumbs img.right { margin-right: 0; } 
#thumbs img.ui-selected { border: 1px solid #99ff99; }
#tabs { padding: 0; border: none; position: absolute; left: 17px; background: none; }
#tabs .ui-tabs-panel { padding: 0; }
#tabs .ui-tabs-nav { padding: 0; border: none; position: relative; top: 54px; background: none; }
#tabs .ui-tabs-nav li { margin: 0; }
#tabs .ui-tabs-nav li a { padding: 5px 4px; font-size: 11px; text-transform: capitalize; }
#tabs .ui-tabs-nav li.ui-tabs-selected a,
#tabs .ui-tabs-nav li.ui-state-disabled a,
#tabs .ui-tabs-nav li.ui-state-processing a { font-weight: bold; }
```

将其保存在`css`文件夹中，命名为`selectableViewer.css`。大部分样式是任意的，纯粹用于布局或视觉外观。我们在标记中使用了一些框架类来添加圆角，因此我们需要编写的 CSS 量很小。最后几个选择器是为了覆盖某些选项卡小部件的默认样式而必需的。

当我们在浏览器中运行示例时，应该会看到与前一截图类似的内容。当选择单个缩略图时，将显示图像的全尺寸版本。当选择了多个图像时，将在查看器顶部重新创建选项卡，这些选项卡允许显示所有选定的图像：

![设置图像选择器的样式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_08.jpg)

# 开始使用 sortable 小部件

我们要查看的最终交互助手是 sortable 小部件。此组件允许我们定义一个或多个元素列表（不一定是实际的`<ul>`或`<ol>`元素），其中列表中的个别项目可以通过拖动重新排序。sortable 组件类似于拖放的专门实现，具有非常具体的角色。它有一个广泛的 API，适用于各种行为。

可以通过不需要额外配置来启用基本的可排序列表。首先，让我们这样做，以便您可以了解此组件启用的行为。在您的文本编辑器中的新文件中，添加以下代码：

```js
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="utf-8">
    <title>Sortable</title>
    <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
    <script src="img/jquery-2.0.3.js"></script>
    <script src="img/jquery.ui.core.js"></script>
    <script src="img/jquery.ui.widget.js"></script>
    <script src="img/jquery.ui.mouse.js"></script>
    <script src="img/jquery.ui.sortable.js"></script>
    <script>
    $(document).ready(function($){
      $("#sortables").sortable();
    });  
    </script> 
  </head>
  <body>
    <ul id="sortables">
    <li>Sortable 1</li>
    <li>Sortable 2</li>
    <li>Sortable 3</li>
    <li>Sortable 4</li>
    <li>Sortable 5</li>
    </ul>
  </body>
</html>
```

将其保存为`sortable1.html`。在页面上，我们有一个简单的无序列表，其中有五个列表项。由于 sortable 组件的存在，我们应该发现可以将单个列表项拖动到列表中的不同位置，如下截图所示：

![开始使用 sortable 小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_8A.jpg)

代码上，默认实现与其他组件的实现相同。我们只需在要排序的列表项的父`<ul>`元素上调用 sortable 小部件方法即可。

页面添加了许多行为以适应此功能。当我们将列表项中的一个上下拖动时，其他项目会自动让路，为当前正在排序的项目创建一个放置位置。

另外，当可排序项目被放置时，它将快速而平滑地滑动到列表中的新位置。基本实现所需的库文件如下：

+   `jquery-2.0.3.js`

+   `jquery.ui.core.js`

+   `jquery.ui.widget.js`

+   `jquery.ui.mouse`

+   `jquery.ui.sortable.js`

正如我之前提到的，可排序组件是库的一个灵活的补充，可以应用到许多不同类型的元素上。例如，我们可以使用一系列 `<div>` 元素作为可排序列表项，而不是前面示例中的 `<ul>` 元素：

```js
<div id="sortables" class="ui-widget">
  <div class="ui-widget-header ui-corner-all">Sortable 1</div>
  <div class="ui-widget-header ui-corner-all">Sortable 2</div>
  <div class="ui-widget-header ui-corner-all">Sortable 3</div>
  <div class="ui-widget-header ui-corner-all">Sortable 4</div>
  <div class="ui-widget-header ui-corner-all">Sortable 5</div>
</div>
```

这可以保存为`sortable2.html`。正如你所看到的，这个版本展示的行为与以前完全一样。改变的只是底层标记。我们添加了一些 CSS 框架类，以添加一些基本样式到我们的元素，我们也可以使用自定义样式表添加一些额外的样式。

创建一个新文件，并添加以下样式：

```js
#sortables { width: 300px; }
#sortables div { padding: 2px 0 2px 4px; margin-bottom: 8px; }
```

将此保存在 `css` 文件夹中，命名为 `sortable.css`。在 `sortable2.html` 的 `<head>` 中链接到 CSS 文件：

```js
<link rel="stylesheet" href="css/sortable.css">
```

使用我们的新样式表，页面现在应该如下所示：

![使用可排序小部件入门](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_09.jpg)

# 为可排序小部件设置样式

现在我们已经为我们的第一组可排序元素设置了样式，这是我们在旅程中的一个好时机，可以检查可排序小部件使用的样式类。

可排序小部件使用了许多样式。它们在下面的表格中显示：

| 类名 | 用于… |
| --- | --- |
| `ui-widget ui-sortable` | 用于容器元素；首先设置来自 `ui-widget` 的通用类，然后是 `ui-sortable` 中的类。 |
| `ui-widget-header` | 为每个可排序元素设置样式；这是默认的带有圆角的，使用 `ui-corner-all` 样式。 |
| `ui-sortable-helper –` | 在拖动过程中显示被排序元素的克隆。 |
| `ui-sortable-placeholder –` | 作为占位符元素，准备接受正在排序的元素。默认情况下，它是隐藏的，但可以根据需要更改，我们将在本章后面看到。 |

# 配置可排序选项

可排序组件有大量可配置的选项，比任何其他交互组件都多（但不及一些小部件多）。

以下表格显示了我们可以使用的范围内的各种选项：

| 选项 | 默认值 | 用于… |
| --- | --- | --- |
| `appendTo` | `"parent"` | 在排序期间，设置助手要附加到的元素。 |
| `axis` | `false` | 限制可排序元素在一个轴上的移动。可能的值是字符串 x 或 y。 |
| `cancel` | `":input, button"` | 指定不能排序的元素，如果它们是正在排序的元素。 |
| `connectWith` | `false` | 启用从当前列表到指定列表的单向排序。 |
| `containment` | `false` | 在排序过程中将排序限制在它们的容器中。值可以是字符串的 parent、window 或 document，也可以是一个 jQuery 选择器或元素节点。 |
| `cursor` | `"auto"` | 定义拖动可排序元素时要应用的 CSS 光标。 |
| `cursorAt` | `false` | 指定在进行排序时鼠标指针应该在的坐标。接受一个带有键 `top`、`right`、`bottom` 或 `left` 以及整数值的对象。 |
| `delay` | `0` | 设置在可排序项被点击（鼠标按键按住）后开始排序之前的时间延迟，以毫秒为单位。 |
| `disabled` | `false` | 在页面加载时禁用小部件。 |
| `distance` | `1` | 设置左键按下后在排序开始之前鼠标指针应该移动的像素距离。 |
| `dropOnEmpty` | `true` | 允许从链接的可排序项被放置到空槽中。 |
| `forceHelperSize` | `false` | 当设置为 `true` 时，强制 `helper` 具有大小。 |
| `forcePlaceholderSize` | `false` | 当设置为 `true` 时，强制 `placeholder` 具有大小。占位符是可排序项可以放置的空白空间。 |
| `grid` | `false` | 设置可排序项目在拖动时捕捉到网格。接受一个包含两个项目的数组——网格线之间的 x 和 y 距离。 |
| `handle` | `false` | 指定要用作可排序项上拖动手柄的元素。可以是选择器或元素节点。 |
| `helper` | `original"` | 指定在元素被排序时将用作代理的助手元素。可以接受返回元素的函数。 |
| `items` | `">*"` | 指定应该进行排序的项目。默认情况下，所有子项都可以进行排序。 |
| `opacity` | `false` | 指定被排序元素的 CSS 不透明度。值应为从 `0.01` 到 `1` 的整数，`1` 表示完全不透明。 |
| `placeholder` | `false` | 指定要添加到空槽中的 CSS 类。 |
| `revert` | `false` | 在可排序项被放置到新位置后启用动画。 |
| `scroll` | `true` | 当可排序项被移动到视口边缘时，启用页面滚动。 |
| `scrollSensitivity` | `20` | 设置在像素中可排序项必须靠近视口边缘，然后滚动应该开始的距离。 |
| `scrolSpeed` | `20` | 设置在灵敏度范围内拖动可排序项时视口应该滚动的像素距离。 |
| `tolerance` | `"intersect"` | 控制必须重叠其他元素的被排序元素的多少，然后占位符被移动。另一个可能的值是字符串 pointer。 |
| `zIndex` | `1000` | 在拖动期间设置 `sortable` 或 `helper` 的 CSS `zIndex`。 |

让我们将其中一些属性融入到我们之前的示例中，以便了解它们对组件行为的影响。首先，在一个新的`<div>`中包装`#sortables`容器：

```js
<div id="container">
  <div id="sortables" class="ui-widget">
    <div class="ui-widget-header ui-corner-all">Sortable 1</div>
    <div class="ui-widget-header ui-corner-all">Sortable 2</div>
    <div class="ui-widget-header ui-corner-all">Sortable 3</div>
    <div class="ui-widget-header ui-corner-all">Sortable 4</div>
    <div class="ui-widget-header ui-corner-all">Sortable 5</div>
  </div>
</div>

```

然后将 `sortable2.html` 中的最终 `<script>` 元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
    $("#sortables").sortable({
      axis: "y",
      containment: "#container",
      cursor: "ns-resize",
      distance: 30
    });
  });  
</script> 
```

将此保存为 `sortable3.html`。我们还需要为新容器元素添加一点内边距。更新 `sortable.css`，使其包含以下新代码：

```js
#container { padding: 10px 0 20px; }
```

将此文件另存为`sortableContainer.css`，并在`sortable3.html`的`<head>`中更新`<link>`，使其指向新样式表。

在我们的配置对象中使用了四个选项：`axis`、`containment`、`resize`和`distance`。让我们看看它们的作用：

+   `axis`选项设置为`y`，以限制当前被拖动的可排序元素的运动只在上下方向。

+   `containment`选项指定了可排序元素应该被包含在其中的元素，以限制它们的移动范围。

+   `cursor`选项会自动添加 CSS `ns-resize`光标。与我们在第十一章中讨论的拖放组件*拖放*类似，光标实际上直到排序开始才显示。

+   `distance`选项配置为`30`，表示鼠标指针在排序开始之前应该移动`30`像素。它与可拖动的元素一样工作，非常适合防止不必要的排序，但在实践中，我们可能会使用比 30 像素更低的阈值。

### 提示

**可排序的间距**

在使用`containment`选项时应格外小心。这就是为什么我们在样式表中为容器元素添加了一些填充的原因。没有这些填充，第一个可排序元素与容器顶部贴合，最后一个元素与底部贴合。为了能够将一个可排序元素挤开，必须在它上面或下面留出一些空间。

让我们看看更多的选项。在这个示例中，我们将从`sortable3.html`中的代码调整，以限制每个项目的操作手柄到特定的部分。我们还将阻止 jQuery UI 在一定时间过去之前允许排序。

修改`sortable3.html`中的基础`<div>`元素，使其显示如下：

```js
<div id="sortables" class="ui-widget">
  <div class="ui-widget-header ui-corner-all">Sortable 1
    <span class="ui-icon ui-icon-triangle-2-n-s"></span>
  </div>
  <div class="ui-widget-header ui-corner-all">Sortable 2
    <span class="ui-icon ui-icon-triangle-2-n-s"></span>
  </div>
  <div class="ui-widget-header ui-corner-all">Sortable 3
    <span class="ui-icon ui-icon-triangle-2-n-s"></span>
  </div>
  <div class="ui-widget-header ui-corner-all">Sortable 4
    <span class="ui-icon ui-icon-triangle-2-n-s"></span>
  </div>
  <div class="ui-widget-header ui-corner-all">Sortable 5
    <span class="ui-icon ui-icon-triangle-2-n-s"></span>
  </div>
</div>
```

对于这个示例，我们可以去掉`#container`元素。我们还需要一个修改过的样式表。修改`sortable.css`，使其包含以下新样式：

```js
#sortables span { margin: 2px 2px 0 0; float: right; }
```

将新的样式表另存为`sortableHandles.css`在`css`文件夹中，并更新`<link>`元素指向新样式表。

最后，将配置对象修改如下：

```js
$("#sortables").sortable({
 revert: "slow",
 handle: "span",
 delay: 1000,
 opacity: 0.5
});
```

另存为`sortable4.html`。我们对页面进行了轻微的更改。在每个可排序元素内部是一个新的`<span>`元素，将用作排序操作手柄。我们给这个元素添加了一些 CSS 框架类，以减少我们需要手动添加的 CSS。

`revert`选项的默认值为`true`，但也可以采用我们在其他组件的其他动画选项中见过的速度整数或字符串值（`slow`、`normal`或`fast`）。

`delay`选项接受一个以毫秒为单位的值，组件应该在允许排序开始之前等待的时间。如果鼠标指针在按住左键的同时移动到手柄以外，排序仍将在指定的时间后发生。然而，如果释放鼠标按钮，则排序将被取消。

`opacity`选项的值用于指定在排序进行时正在排序的元素的 CSS 不透明度。该值应为介于`0`和`1`之间的浮点数，其中`1`对应于完全不透明，`0`指定不透明度为零。

我们使用的另一个选项是`handle`选项，它允许我们定义一个在可排序内必须用于启动排序的区域。在可排序的其他部分拖动将不会导致排序开始。

您可以在以下屏幕截图中看到手柄的外观：

![配置可排序选项](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_10.jpg)

### 提示

**使我的手柄更大**

出于可用性原因，我们可能应该使用比上一个示例中使用的更大的手柄。

## 占位符

占位符定义了在将一个可排序元素移动到新位置的过程中留下的空白区域或插槽。占位符位置不是固定的。它将动态移动到任何被正在排序的可排序元素的移动所取代的可排序元素。

有两个选项专门涉及占位符，非常贴切地命名为`placeholder`选项和`forcePlaceholderSize`选项。让我们看看这两个选项是如何运作的。从`sortable4.html`中的可排序`<div>`元素中删除`<span>`元素，然后更改配置对象，使其显示如下：

```js
$("#sortables").sortable({
 placeholder: "empty ui-corner-all",
 forcePlaceholderSize: true
});
```

将此保存为`sortable5.html`。接下来，我们应该将新的选择器和规则添加到一个 CSS 文件中。修改`sortable.css`，使其包含以下样式：

```js
.empty {border: 1px solid #4297D7; background-color: #c5dbec;}
```

将此保存为`css`文件夹中的`sortablePlaceholder.css`。

`placeholder`选项允许我们定义一个应该添加到占位符元素的 CSS 类。这是一个我们在实现中经常可以使用的有用属性。请记住这是一个类名，而不是类选择器，因此字符串开头不使用句点。它可以接受多个类名。

`forcePlaceholderSize`选项确保占位符与实际可排序元素的大小相同。如果我们将此选项保持默认值`false`，在这个示例中，占位符将只是由我们应用于可排序`<div>`元素的填充组成的一条细线。

当我们在浏览器中运行新的 HTML 文件时，应该能够看到指定的样式应用于占位符，在排序进行时：

![占位符](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_11.jpg)

## 可排序助手

在本书前面看可拖动组件时，我们已经了解了助手/代理元素。助手也可以为可排序元素定义，其功能方式与可拖动组件的方式类似，尽管在此实现中存在一些细微差异。

使用可排序组件时，原始的可排序元素在排序交互开始时被隐藏，而是拖动原始元素的克隆。因此，使用可排序组件时，助手是一个固有的特性。

与可拖动项一样，可排序的`helper`选项可能将函数作为其值。当使用时，该函数将自动接收`event`对象和包含来自可排序元素的有用属性的对象作为参数。

函数必须返回要用作助手的元素。虽然与可拖动助手示例非常相似，但让我们快速看一下在与可排序一起使用时。在`sortable5.html`中，更改最后一个`<script>`块，使其如下所示：

```js
<script>
  $(document).ready(function($){
    var buildHelper = function(e, ui) {
      return $("<div />", {
        text: $(ui).text(),
        "class": "ui-corner-all",
        css: {
          opacity: 0.5,
          border: "4px dashed #cccccc",
          textAlign: "center"
        }
      });
    },
    $("#sortables").sortable({
      helper: buildHelper
    });
  });  
</script> 
```

将此文件保存为`sortable6.html`。我们定义了一个`helperMaker`函数，该函数创建并返回在排序进行时要使用的元素。我们在新元素上设置了一些基本的 CSS 属性，这样我们就不需要在样式表中提供额外的规则了。

下面的屏幕截图显示了排序进行时助手的外观：

![可排序助手](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_12.jpg)

## 可排序项

默认情况下，调用该方法的元素的所有子元素都会变成可排序。虽然这是组件的一个有用功能，但有时我们不一定希望所有子元素都变为可排序。

`items`选项控制应将指定元素的哪些子元素设置为可排序。它使用字符串`>*`作为其默认值使所有子元素可排序，但我们可以更改此值以指定我们想要的元素。更改`sortable6.html`中的可排序`<div>`元素，以便最后一个元素具有新的类名：

```js
<div class="ui-widget-header ui-corner-all unsortable">
  Sortable 5
</div>
```

然后，更改配置对象以利用`items`选项：

```js
$("#sortables").sortable({
 items: ">:not(.unsortable)"
});
```

将此保存为`sortable7.html`。在`<script>`中，我们指定了选择器`">:not(.unsortable)"`作为`items`选项的值，因此具有类名`unsortable`的元素将不会被设置为可排序，而其他`<div>`元素将会被设置为可排序。

当我们在浏览器中运行页面时，我们应该发现集合中的最后一个项目无法排序，并且其他可排序项目无法移动到最后一个项目占用的空间中。

## 连接列表

到目前为止，我们所看到的示例都集中在单个可排序项目列表上。当我们想要有两个可排序项目列表时会发生什么，更重要的是，我们是否可以将项目从一个列表移动到另一个列表？

当然，拥有两个可排序列表非常容易，只需要简单地定义两个容器及其子元素，然后将对每个容器的引用传递给`sortable()`方法即可。

允许单独的可排序列表交换和共享可排序项也非常容易。这要归功于 `connectWith` 选项，它允许我们定义一个可排序容器数组，这些容器可以共享它们的可排序内容。

让我们看看它是如何起作用的。更改页面上的底层标记，使其如下所示：

```js
<div id="sortablesA" class="ui-widget">
  <div class="ui-widget-header ui-corner-all">Sortable 1A</div>
  <div class="ui-widget-header ui-corner-all">Sortable 2A</div>
  <div class="ui-widget-header ui-corner-all">Sortable 3A</div>
  <div class="ui-widget-header ui-corner-all">Sortable 4A</div>
  <div class="ui-widget-header ui-corner-all">Sortable 5A</div>
</div>
<div id="sortablesB" class="ui-widget">
  <div class="ui-widget-header ui-corner-all">Sortable 1B</div>
  <div class="ui-widget-header ui-corner-all">Sortable 2B</div>
  <div class="ui-widget-header ui-corner-all">Sortable 3B</div>
  <div class="ui-widget-header ui-corner-all">Sortable 4B</div>
  <div class="ui-widget-header ui-corner-all">Sortable 5B</div>
</div>
```

页面上的一切与我们之前使用的内容非常相似。对于此示例，我们还需要一个新的样式表。在一个新文件中，添加以下样式：

```js
#sortablesA, #sortablesB { width: 300px; margin-right: 50px; float: left; }
.ui-widget div { padding: 2px 0 2px 4px; margin-bottom: 8px; }
```

将此保存为 `sortableConnected.css` 在 `css` 文件夹中。不要忘记在新页面的 `<head>` 中指向新样式表。最后，更改最后一个 `<script>` 元素，使其如下所示：

```js
<script>
  $(document).ready(function($){
    $("#sortablesA, #sortablesB").sortable({
 connectWith: ["#sortablesA", "#sortablesB"]
    });
  });  
</script> 
```

将此保存为 `sortable8.html`。我们仍然定义一个单一的配置对象，可以在两组可排序元素之间共享。`connectWith` 选项能够接受多个选择器，如果它们作为数组传递，正是这个选项允许我们在两个可排序容器之间共享个别可排序项。

此配置选项仅提供可排序的单向传输，因此如果我们只使用配置对象与 `sortablesA` 并仅指定选择器 `#sortablesB`，我们只能从 `sortablesA` 移动项目到 `sortablesB`，而不能反之。

在选项中同时指定可排序的 `id` 属性，并在调用 `sortable()` 方法时选择两个容器，允许我们在两个元素之间移动项目，并且可以减少编码量。

在浏览器中运行页面时，我们发现不仅可以对各个项目在各自的元素中进行排序，还可以在元素之间移动项目，如下面的屏幕截图所示：

![连接列表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_13.jpg)

# 对可排序事件作出反应

除了在可排序类中已定义的可配置选项的大列表外，还有更多的事件回调形式的选项，它们可以作为函数传递，在可排序交互的不同点执行。这些列在下表中列出：

| 事件 | 当……时触发 |
| --- | --- |
| `activate` | 在连接的列表上开始排序。 |
| `beforeStop` | 排序已停止，但原始插槽仍然可用。 |
| `change` | 可排序的 DOM 位置已更改，排序仍在进行中。 |
| `create` | 小部件已初始化。 |
| `deactivate` | 在连接的列表上停止排序。 |
| `out` | 可排序已从连接的列表中移出。 |
| `over` | 可排序是指与连接列表一起使用。这在排序进行时提供视觉反馈非常有用。 |
| `receive` | 从连接的列表中接收到可排序。 |
| `remove` | 可排序从连接的列表中移动。 |
| `sort` | 排序正在进行。 |
| `start` | 开始排序。 |
| `stop` | 结束排序。 |
| `update` | 排序已结束，DOM 位置已更改。 |

我们在前面章节中查看的每个组件都定义了自己一套自定义事件，并且可排序组件也不例外。

在任何单个排序交互过程中，许多这些事件都会触发。以下列表显示了它们触发的顺序：

+   start

+   sort

+   change

+   beforeStop

+   stop

+   update

一旦拿起其中一个可排序项，就会触发 `start` 事件。随后，在每次鼠标移动时，都会触发 `sort` 事件，使此事件非常密集。

一旦当前可排序项排开了另一个项目，就会触发 `change` 事件。一旦可排序项被放下，就会触发 `beforeStop` 和 `stop` 事件，如果可排序项现在处于不同位置，则最后触发 `update` 事件。

在接下来的几个示例中，我们将把其中一些事件处理选项整合到之前的示例中，从 `start` 和 `stop` 事件开始。将 `sortable8.html` 中的配置对象更改为以下内容：

```js
var sortOpts = {
  connectWith: ["#sortablesA", "#sortablesB"],
  start: function(e, ui) {
    $("<p />", {
      id: "message",
      text: ui.helper.text() + " is active",
      css: { clear:"both" }
    }).appendTo("body");
  },
  stop: function() {
    $("#message").remove();
  }
};
```

将此保存为 `sortable9.html`。我们在此示例中对事件的使用很少。当排序开始时，我们只需创建一个新的段落元素并向其添加一些文本，其中包括正在排序的元素的文本内容。然后将文本消息追加到页面的 `<body>`。当排序结束时，我们将删除文本。如您所见，使用传递给回调函数的第二个对象非常容易。该对象本身指的是父级可排序的容器，`helper` 属性指的是实际被排序的项目（或其辅助程序）。由于这是一个 jQuery 对象，因此我们可以在其上调用 jQuery 方法，例如 `text`。

当我们运行页面时，消息应该会在排序结束之前短暂出现，然后被移除。

![对可排序事件的反应](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_14.jpg)

让我们在继续查看与连接的可排序项一起使用的附加回调函数之前，再看一个这样简单的回调函数。在我们的下一个示例中，我们将看看如何跟踪可排序项在列表之间的移动，并使用回调函数将结果显示在屏幕上。

将 `sortable9.html` 中的最终 `<script>` 元素更改为以下内容：

```js
<script>
     $(document).ready(function($){
        var getPlaces = function(e, ui) {
          var extraMessage = (e.type === "sortreceive") ? " in a new list" : "";
          $("#message").remove();
          $("<p />", {
            id: "message",
            text: [ 
              "Item now at position ",
              (ui.item.index() + 1).toString(),
              extraMessage
            ].join(" "),
            css: {
              clear: "both"
            }
          }).appendTo("body");
        };
        $("#sortablesA, #sortablesB").sortable({
          connectWith: ["#sortablesA", "#sortablesB"],
          beforeStop: getPlaces,
          receive: getPlaces
        });
      });    
    </script> 
```

将此保存为 `sortable10.html`。在此示例中，我们使用 `receive` 和 `beforeStop` 回调来提供一条消息，指示可排序项移动到列表中的位置，以及它位于哪个列表中。我们还利用了自动传递给事件使用的任何回调函数的对象的 `ui.item` 属性。

我们首先定义一个名为 `extraMessage` 的变量，最初将其设置为空字符串。然后我们定义一个名为 `getPlaces` 的函数。该函数将用作可排序事件的回调函数，并因此会自动接收 `e` 和 `ui` 对象。

在函数内部，我们首先检查事件对象的 `type` 属性是否具有值 `sortreceive`；如果是，则我们知道可排序已经移动到其他列表中，因此可以设置消息的额外部分。

然后我们移除任何现有消息，然后创建一个新的 `<p>` 元素并设置一条消息，指示其在列表中的新位置。我们可以使用传递给我们回调函数的第二个对象的 `item` 属性以及 jQuery 的 `index()` 方法获取已排序元素的新位置，然后将其转换为字符串并连接成一条消息。

在我们的配置对象中，我们使用与之前相同的 `connectWith` 选项连接两个列表，并利用 `receive` 和 `beforeStop` 选项，它们都指向我们的 `getPlaces` 函数。

仅当可排序容器从连接列表接收到新的可排序元素时，`receive` 事件才会触发。在事件顺序方面，在此示例中，`beforeStop` 事件首先触发，然后是 `receive` 事件。

仅当可排序元素移动到新的可排序容器时，`receive` 事件才会触发。以下截图显示了在排序交互后页面应该呈现的样子：

![对可排序事件的反应](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_15.jpg)

# 连接回调

六个可用的回调函数可以与连接的可排序元素一起使用。这些事件在交互过程中的不同时间触发，与我们已经查看过的事件一起触发。

像标准未连接的事件一样，不是所有连接的事件都会在任何单个交互中触发。某些事件，如 `over`、`off`、`remove` 和 `receive`，只有在排序项目移动到新列表时才会触发。

其他事件，如 `activate` 和 `deactivate`，将在所有执行中触发，无论排序项是否更改列表。此外，一些连接事件，如 `activate` 和 `deactivate`，将为页面上的每个连接列表触发。只要至少有一个项目在列表之间移动，事件将按以下顺序触发：

1.  开始

1.  激活

1.  排序

1.  更改

1.  停止前

1.  停止

1.  删除

1.  更新

1.  接收

1.  停用

现在让我们看看这些连接事件如何发挥作用。将 `sortable10.html` 中的最后一个 `<script>` 元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
    var activateSortable = function() {
      $("<p />", {
        text: $(this).attr("id") + " has been activated",
        css: { clear:"both" }
      }).appendTo("body");
    }

    var deactivateSortable = function() {
      $("<p />", {
        text: $(this).attr("id") + " has been deactivated",
        css: { clear:"both" }
      }).appendTo("body");
    }

    var receiveSortable = function(e, ui) {
      var senderAttr = ui.sender.attr("id");
      var receiverAttr = $(this).attr("id");
      $("<p />", {
        text: [ ui.item.text(), "was moved from", senderAttr, "into", receiverAttr ].join(" "),
        css: { clear:"both" }
      }).appendTo("body");
    }

    $("#sortablesA, #sortablesB").sortable({
      connectWith: ["#sortablesA", "#sortablesB"],
      activate: activateSortable,
      deactivate: deactivateSortable,       
      receive: receiveSortable
    });
  });  
</script> 
```

将其保存为 `sortable11.html`。`activate` 和 `deactivate` 事件会在任何排序交互开始时为每个连接的列表触发。在我们的回调函数中，`$(this)` 指的是每个可排序容器。我们可以使用传递给我们函数的第二个对象的 `sender` 属性轻松确定项目源自哪个可排序列表。

当我们在浏览器中运行页面时，我们会看到一旦排序开始，两个可排序元素都被激活，当排序结束时，它们都被停用。如果一个项目在列表之间移动，`receive` 回调生成的消息如下截图所示：

![连接回调](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_16.jpg)

# 列出可排序方法

可排序组件提供了一套通常用于使组件执行操作的方法。与之前查看过的可选择组件一样，它还定义了一些其他组件中没有的独特方法。以下表格列出了可排序的独特方法：

| 方法 | 用途 |
| --- | --- |
| `cancel` | 取消排序并使元素返回到原始位置。 |
| `refresh` | 重新加载可排序集合。 |
| `refreshPositions` | 触发可排序集合的缓存刷新。 |
| `serialize` | 构造一个查询字符串，可用于将新的排序顺序发送到服务器进行进一步处理或存储。 |
| `toArray` | 将可排序序列化为字符串数组。 |

## 序列化

`serialize` 和 `toArray` 方法非常适合存储可排序的新顺序。让我们看看这是如何实现的。我们将创建一系列可排序元素，然后设置 Sortable 来显示它们的顺序。每次移动其中一个元素时，屏幕上将更新显示这个顺序。

更改 `sortable11.html` 页面的 `<body>` 下面的底层标记如下：

```js
<div id="sortablesA" class="ui-widget">
  <div id="sortablesA_1" class="ui-widget-header ui-corner-all">Sortable 1A</div>
  <div id="sortablesA_2" class="ui-widget-header ui-corner-all">Sortable 2A</div>
  <div id="sortablesA_3" class="ui-widget-header ui-corner-all">Sortable 3A</div>
  <div id="sortablesA_4" class="ui-widget-header ui-corner-all">Sortable 4A</div>
  <div id="sortablesA_5" class="ui-widget-header ui-corner-all">Sortable 5A</div>
</div>
```

然后更改最后的 `<script>` 元素，使其显示如下：

```js
<script>
  $(document).ready(function($){
    $("#sortablesA").sortable({
      stop: function(e, ui) {
        var order = $("#sortablesA").sortable("serialize");
        $("#message").remove();
        $("<p />", {
          id: "message",
          text: order,
          css: { clear:"both" }
        }).appendTo("body");
      }
    });
  });  
</script> 
```

将此保存为 `sortable12.html`。在此示例中，我们删除了第二组可排序，并为每个可排序项目添加了以父可排序名称和数字以下划线分隔的 `id` 属性。

我们使用 `stop` 事件在每次排序交互后执行匿名函数。

在此函数内，我们将 `serialize` 方法的结果存储在 `order` 变量中，然后在页面上的新 `<p>` 元素中显示此变量：

![序列化](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_17.jpg)

正如您所见，序列化字符串的格式非常简单明了。可排序项目按照它们在页面上出现的顺序排列，并用和号分隔。每个序列化的项目由两部分组成：每个可排序项目的 `id` 属性的哈希，后跟表示项目新顺序的整数。

在前面的示例中，我们只是在页面上显示了序列化的字符串，但该字符串的格式非常适合与 jQuery 的 `ajax` 方法一起使用，以将其传递给服务器进行进一步处理。

`serialize` 方法还能接受一个配置对象以定制序列化的方式。我们可以配置的选项列在下表中：

| 选项 | 默认值 | 用途 |
| --- | --- | --- |
| `attribute` | `id` | 指定用于解析可排序列表中每个项目并生成哈希的属性。 |
| `connected` | `false` | 包括所有连接列表在序列化中。 |
| `expression` | `"(.+)-=_"` | 指定用于解析可排序列表的正则表达式。 |
| `key` | `每个可排序项的 id 属性的第一部分` | 指定在序列化输出中每个项目的第一部分要使用的字符串。 |

`toArray`方法的工作方式与`serialize`类似，不同之处在于`toArray`的输出不是一个字符串，而是一组字符串的数组。

# 探索小部件兼容性

在上一章中，我们看到可调整大小和可选组件与选项卡小部件一起工作得很好（我们已经知道对话框和可调整大小组件是多么完美的组合）。可排序组件也与其他小部件高度兼容。让我们看一个基本的例子。在你的文本编辑器中新建一个文件，添加如下代码：

```js
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="utf-8">
    <title>Sortable Tabs</title>
    <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
    <script src="img/jquery-2.0.3.js"></script>
    <script src="img/jquery.ui.core.js"></script>
    <script src="img/jquery.ui.widget.js"></script>
    <script src="img/jquery.ui.mouse.js"></script>
    <script src="img/jquery.ui.sortable.js"></script>
    <script src="img/jquery.ui.tabs.js"> </script>
    <script>
      $(document).ready(function($){
        $("#tabs").tabs().sortable({
          axis: "x",
          items: "li"
        });
      });  
    </script> 
  </head>
  <body>
    <div id="tabs">
      <ul>
        <li><a href="#0"><span>Sort Tab 1</span></a></li>
        <li><a href="#1"><span>Sort Tab 2</span></a></li>
        <li><a href="#2"><span>Sort Tab 3</span></a></li>
      </ul>
      <div id="0">The first tab panel</div>
      <div id="1">The second tab panel</div>
      <div id="2">The third tab panel</div>
    </div>
  </body>
</html>
```

将此页面保存为`sortable13.html`。在代码中没有什么是我们之前没有见过的，所以我们不会详细解释。请注意，`tabs()`和`sortable()`方法仅在相同的元素上调用——外部包含`<div>`元素。

当我们在浏览器中运行页面时，应该会发现组件的工作方式正是我们想要的。选项卡可以按水平顺序排序，但由于选项卡通过`href`链接到它们的面板，所以当被选中时，它们仍会显示正确的面板。

对选项卡进行排序在`mousedown`事件上工作，而选择选项卡在`mouseup`事件上工作，因此不存在事件冲突，也不会在您想要选择选项卡的时候却最终对其进行排序的情况发生。以下屏幕截图展示了排序后选项卡的外观：

![探索小部件兼容性](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_18.jpg)

## 添加可拖动元素

当我们在本书前面看过可拖动和可放置组件时，我们看到了可拖动组件的`connectToSortable`配置选项。现在我们已经介绍了可排序组件的基本知识，让我们来看一下这个选项。在这个例子中，我们将创建一个可排序的任务列表，可以将新任务拖放进去。

结果页面将如下所示：

![添加可拖动元素](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_19.jpg)

在你的文本编辑器中新建一个文件，添加如下代码：

```js
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="utf-8">
    <title>Sortable</title>
    <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
    <link rel="stylesheet" href="css/sortableTasks.css">
    <script src="img/jquery-2.0.3.js"></script>
    <script src="img/jquery.ui.core.js"></script>
    <script src="img/jquery.ui.widget.js"></script>
    <script src="img/jquery.ui.mouse.js"></script>
    <script src="img/jquery.ui.sortable.js"></script>
    <script src="img/jquery.ui.draggable.js"></script>
  </head>
  <body>
    <ul id="drag">
      <li>Click here to add a new task...</li>
    </ul>
    <a id="add" href="#"></a>
    <div id="taskList">
      <ul id="tasks">
        <li>Design new site</li>
        <li>Call client</li>
        <li>Order pizza</li>
      </ul>
    </div>
  </body>
</html>
```

将其保存为`sortable14.html`。在页面中，我们有两个`<ul>`元素：第一个包含一项指示访问者的指令，第二个是任务列表。第二个列表被包裹在一个`<div>`容器中，大部分是为了样式目的。

我们还需要为这个例子使用一个新的样式表。将以下代码添加到文本编辑器中的新页面：

```js
#drag { padding: 0 0 0 11px; margin: 0; float: left; }
#drag li { font-style: italic; color: #999; }
#drag li input { width: 175px; }
#taskList { width: 250px; height: 400px; clear: both; background: url(../img/paper.jpg) no-repeat; }
#tasks { width: 170px; padding: 89px 0 0; margin: 0; float: right; }
#tasks li, #drag li { height: 28px; padding-top: 5px; list-style-type: none; }
#add { display: none; width: 24px; height: 24px;  position: absolute; left: 218px; top: 13px; background: url(../img/add.png) no-repeat; }
#add.down { background: url(../img/down.png) no-repeat; }
```

将其保存为`sortableTasks.css`，放在`css`文件夹中。大部分都是用于示例装饰和表面上的东西。

最后，我们可以添加连接所有内容的脚本。在库资源之后添加以下`<script>`元素：

```js
<script>
  $(document).ready(function($){
```

我们首先缓存了一些我们脚本中将经常使用的选择器：

```js
    var dragItem = $("#drag li"), addButton = $("#add"), taskItems = $("#tasks");
```

然后我们定义和初始化可排序的配置对象。排序被限制在垂直轴上，并为`stop`事件指定了一个回调函数。

在此函数内部，我们隐藏了`add`按钮，并重置了添加到可拖动元素的任何文本，然后使用可拖动的`option`方法禁用了元素的拖动，以便文本标签无法拖动到任务列表中。

此外，当我们设置可拖动的`disabled`选项时，它会添加一个 CSS 框架类，降低可拖动元素的不透明度。对于我们的示例来说，这是不必要的，因此我们还将删除此类名：

```js
    taskItems.sortable({
      axis: "y",
      stop: function() {
        addButton.css("display", "none");
        dragItem.text("Click here to add new task...");
        dragItem.draggable("option", "disabled", true);
        dragItem.removeClass("ui-state-disabled");
      }
    });
```

在此之后，我们定义并初始化了可拖动的配置对象，并将`connectToSortable`选项设置为与父排序容器匹配的`id`选择器，将`helper`选项设置为克隆。拖动最初被禁用：

```js
    dragItem.draggable({
      connectToSortable: "#tasks",
      helper: "clone",
      disabled: true
    });
```

我们需要创建两个辅助函数：第一个函数用于计算列表中的项目数量，第二个函数用于判断`<input>`字段是否有任何内容：

```js
    function countItems(x) {
      return x === taskItems.children().length;
    }

    function addNewItem(y) {
      return y === $("#drag input").val();
    }
```

我们使用 jQuery 的`on()`方法为可拖动的元素添加了点击处理程序。当点击可拖动的`<li>`时，它会检查列表中是否有太多的任务，如果没有，它将在第一个`<ul>`中创建一个新的`<input>`字段并将其附加到`<li>`中。隐藏的`add`按钮也会显示出来。然后访问者可以输入新任务并使新任务可拖动，方法是点击按钮：

```js
    dragItem.on("click", function() {
      if (countItems(7)) {
        $("#drag").tooltip({ 
          content: "too many tasks already!", 
          items: "ul" 
        });
      } else {
        var input = $("<input />", { id: "newTask" });
        $(this).text("").append(input);
        input.focus();
        addButton.removeClass("down").css("display", "block");
      }
    });
```

我们还为我们创建的`add`按钮添加了一个点击处理程序，再次使用 jQuery 的`on()`方法。该函数检查`<input>`包含一些文本，并在它确实包含时获取文本，然后删除`text`字段。然后，将文本添加到可拖动的`<li>`元素中，并通过将`disabled`选项设置为`false`来使`<li>`可拖动。最后，移除`<input>`，并将消息和按钮设置回其原始状态。

```js
     addButton.on("click", function(e) {
       e.preventDefault();
       if (!addNewItem("")) {
         dragItem.text($("#newTask").val())
           .draggable("option", "disabled", false);
         $("#drag input").remove();
         addButton.addClass("down").
           attr("title", "drag new task into the list");
      }
    });
  });
</script> 
```

文本框和图标将显示如下截图所示：

![添加可拖动元素](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_13_20.jpg)

我们还为我们创建的`add`按钮添加了一个点击处理程序，再次使用 jQuery 的`on()`方法。该函数检查`<input>`包含一些文本，并在它确实包含时获取文本，然后删除`text`字段。然后，将文本添加到可拖动的`<li>`元素中，并通过将`disabled`选项设置为`false`来使`<li>`可拖动。最后，移除`<input>`，并将消息和按钮设置回其原始状态。

# 摘要

我们已经完成了对库的交互组件的巡回，通过查看可选择和可排序的组件。与之前查看的其他模块类似，这两个模块都具有广泛的属性和方法，允许我们在简单和更复杂的实现中配置和控制其行为和外观。

我们从查看了一个简单的默认可选择实现开始，该实现没有进行任何配置，以查看组件添加的最基本功能水平。

我们首先看了可选择内容的默认实现，然后继续研究了可配置选项，以及许多回调属性，这些属性可用于在交互过程中的不同时间执行不同的操作。

接下来，我们看了页面上有大量可选择内容时如何改善页面的性能，以及组件公开的单个唯一方法`refresh`的使用。

最后，我们看了一个有趣的例子，将本章学到的内容结合起来，将可选择组件与选项卡组件结合起来，创建了一个能够处理单个或多个选择的图像查看器。

然后，我们继续研究了一些可排序的不同元素，并向页面添加了一些基本样式。

在此之后，我们看了可排序 API 公开的一系列可配置选项。列表很长，提供了各种可以轻松启用或禁用的功能。

我们继续研究了此组件使用的广泛事件模型，这使我们能够对不同事件做出反应，因为它们在由访问者发起的任何排序操作中发生。

连接列表提供了在列表或可排序集合之间交换可排序项目的能力。我们看到了专门与连接的可排序列表一起使用的附加选项和事件。

在本章的最后部分，我们看了一下可与可排序组件一起使用的方法，并重点关注了非常有用的`serialize`方法，并快速了解了它与 jQuery UI 库中其他成员的兼容性，例如可排序标签示例。我们现在已经查看了库中找到的所有当前交互式组件。在接下来的最后一章中，我们将看看 jQuery UI 带来的所有不同动画效果。


# 第十四章：UI 效果

到目前为止，我们已经看过一系列非常有用的小部件和交互式辅助工具。所有这些都易于使用，但同时功能强大，且高度可配置。一些细微的细节需要在实现过程中加以考虑和思考。

另外，库提供的效果大多非常紧凑，几乎没有学习的选项，也没有方法。我们可以快速、轻松地使用这些效果，最小化配置。

本章中我们将要看的效果如下：

+   强调

+   弹跳

+   摇晃

+   转移

+   比例

+   爆炸

+   膨胀

+   脉动

+   幻灯片

+   百叶窗

+   剪辑

+   折叠

# 使用核心效果文件

就像单独的组件本身一样，效果也需要一个单独的核心文件来提供必要的功能，如创建包装元素和控制动画。大多数效果都有自己的源文件，它们在核心基础上添加了特定于效果的功能。

要使用效果，我们只需在页面中包含核心文件（`jquery.ui.effect.js`），位于效果源文件之前。然而，与`jquery.ui.core.js`文件不同，`jquery.ui.effect.js`文件在设计上可以部分完全独立使用。

## 使用颜色动画

如果我们单独使用核心效果文件，我们可以利用颜色动画。这包括将元素的背景颜色更改为另一种颜色（不仅仅是突然变化，而是平滑地将一种颜色变成另一种颜色），类别转换和高级缓动动画。

### 注意

jQuery UI 1.10 使用 jQuery Color 库的 2.0.0 版本作为库中大部分颜色支持的基础。如果您想了解更多关于 jQuery Color 的信息，请访问[`github.com/jquery/jquery-color`](https://github.com/jquery/jquery-color)项目页面。

jQuery UI 中的核心效果插件添加了使用`rgb()`，`rgba()`，十六进制值甚至诸如水蓝色的颜色名称到 jQuery 核心的能力。我们所需要做的就是包含 jQuery UI 效果核心文件，jQuery 的`.animate()`将支持颜色。

让我们看看如何创建颜色动画。首先，创建以下新页面：

```js
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="utf-8">
    <title>Color Animations</title>
    <link rel="stylesheet" href="css/effectColor.css">
    <script src="img/jquery-2.0.3.js"></script>
    <script src="img/jquery.ui.effect.js"></script>
  </head>
  <script>
  <body>
    <form action="#">
      <div>
        <label for="name">Name: </label>
        <input id="name" type="text">
      </div>
      <div>
        <label for="age">Age: </label>
        <input id="age" type="text">
      </div>
      <div>
        <label for="email">Email: </label>
        <input id="email" type="text">
      </div>
      <button type="submit">Submit</button>
    </form>
  </body>
</html>
```

将页面保存为`effectColor.html`。在最后的`<script>`块中，添加以下代码，为每个字段提供视觉反馈：

```js
    $(document).ready(function($){
      function Validate(fieldname, response)   {
        var bgColor, brdrColor;

        switch(response) {
          case "invalid" : 
            bgColor = "#ff9999";
            brdrColor = "#ff0000";
            break;
          case "valid" : 
            bgColor = "#ccffcc";
            brdrColor = "#00ff00";
            break;
        }

        fieldname.animate({
          backgroundColor: bgColor,
          borderTopColor: brdrColor,
          borderRightColor: brdrColor,
          borderBottomColor: brdrColor,
          borderLeftColor: brdrColor
        });
      }

      $("form").submit(function() {
        ($("#name").val().length == 0) ? Validate($("#name"), "invalid") : Validate($("#name"), "valid");
        ($("#age").val().length == 0) ? Validate($("#age"), "invalid") : Validate($("#age"), "valid");
        ($("#email").val().length == 0) ? Validate($("#email"), "invalid") : Validate($("#email"), "valid"); 
      });
    });
```

如你所见，我们所需要的只是 jQuery 和`jquery.ui.effect.js`文件，就可以创建吸引人的颜色过渡效果。在页面上，我们有一个简单的`<form>`元素围绕着三个容器元素和三组`<label>`和`<input>`元素。`animate`方法是 jQuery 的一部分，而不是特别是 jQuery UI 的，但`jquery.ui.effect.js`文件通过允许它专门处理颜色和类别，扩展了 jQuery 的`animate`方法。

当单击**提交**按钮时，我们只需使用`animate`方法根据文本输入框是否已填写来将一系列新的 CSS 属性应用于目标元素。如果已经填写，我们将它们着色为绿色；如果没有填写，我们将其着色为红色。在此示例中，我们还使用了基本样式表。在文本编辑器中的另一页中，添加以下基本选择器和规则：

```js
div { margin-bottom: 5px; }
label { display: block; width: 100px; float: left; }
input { border: 1px solid #000000; }
```

将此保存为`effectColor.css`，并放在`css`文件夹中。当我们在浏览器中查看此页面时，我们应该看到任何留空的字段在单击**提交**按钮时平滑变为红色，而不为空的字段在单击时平滑变为绿色。但是，当一个字段从红色变为绿色时最具吸引力。

下图显示了在单击**提交**按钮后页面的情况：

![使用颜色动画](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_14_01.jpg)

### 注意

需要注意的关键点是我们在代码中使用了`backgroundColor`作为属性；这样做的原因是，jQuery 默认情况下不能动画显示`background-color` CSS 样式，除非我们使用 jQuery Color 插件。让我们更详细地看一下这些属性。

可以应用颜色动画的样式属性如下所示：

+   `backgroundColor`

+   `borderTopColor`

+   `borderRightColor`

+   `borderBottomColor`

+   `borderLeftColor`

+   `color`

+   `outlineColor`

颜色可以使用 RGB、十六进制（格式为`#xxx[xxx]`）甚至标准颜色名称来指定。建议在可能的情况下使用 RGB 或十六进制颜色，因为浏览器并不总是一致地识别颜色名称。

### 注意

Color 插件的默认构建仅包括对基本颜色名称的支持。如果您需要使用其他颜色名称，可以从 [`github.com/jquery/jquery-color#readme`](https://github.com/jquery/jquery-color#readme) 下载支持此功能的版本。

## 使用类过渡

除了对单个颜色属性进行动画处理外，`jquery.ui.effect.js` 还赋予了我们强大的能力，可以在整个类之间进行动画处理。这使我们能够在不出现突然刺耳变化的情况下平滑无缝地切换样式。让我们在以下示例中看一下文件使用的这个方面。

将`effectColor.html`的`<head>`元素中的`<link>`标签更改为指向一个新样式表：

```js
<link rel="stylesheet" href="css/effectClass.css">
```

然后更改最后一个 `<script>` 元素，使其显示如下：

```js
<script>
  $(document).ready(function($){
    var obj;

    function showValid(obj) {
      (obj.val().length == 0) ? null : obj.switchClass("error", "pass", 2000);
    }

    function showInvalid(obj) {
      (obj.val().length != 0) ? null : obj.switchClass("pass", "error", 2000);
    }

    function showEither(obj) {
      (obj.val().length == 0) ? obj.addClass("error", 2000) : obj.addClass("pass", 2000);
    }

    $("form").submit(function(e) {
      $("input").each(function() {
        var cssStyle = $(this).attr('class');
        if (cssStyle == "error") { showValid($(this)); }; 
        if (cssStyle == "pass") { showInvalid($(this)); } 
        if (cssStyle == null) { showEither($(this)); }           
      })
    });  
  });
</script>
```

将此保存为`effectClass.html`。`jquery.ui.effect.js` 文件通过允许我们指定应用新类名的持续时间来扩展了 jQuery 类 API，而不仅仅是立即切换它。我们还可以指定缓动效果。

当字段已经具有其中一个类名并且需要更改为不同的类名时，`jquery.ui.effect.js` 文件的 `switchClass` 方法被使用。`switchClass` 方法需要几个参数；我们指定要移除的类名，然后是要添加的类名。我们还将持续时间指定为第三个参数。

本质上，页面的功能与以前相同；但是，使用这种类型的类别转换还允许我们使用非基于颜色的样式规则，因此我们可以调整宽度、高度或许多其他样式属性。请注意，无法以这种方式过渡背景图像。

与上一个示例一样，我们附加了一个样式表。本质上与上一个示例相同，只是为我们的两个新类别添加了一些样式。

在`effectColor.css`的底部添加以下选择器和规则：

```js
.error { border: 1px solid #ff0000; background-color: #ff9999; }
.pass { border: 1px solid #00ff00; background-color: #ccffcc; }
```

将更新后的文件另存为`css`文件夹中的`effectClass.css`。

## 高级缓动

标准 jQuery 中的`animate`方法内置了一些基本的缓动功能，但是要使用更高级的缓动，您必须包含额外的缓动插件（由 GSGD 移植到 jQuery）。

### 注意

有关更多信息，请参阅缓动插件的项目页面[`gsgd.co.uk/sandbox/jquery/easing/`](http://gsgd.co.uk/sandbox/jquery/easing/)。

`jquery.ui.effect.js`文件中内置了所有这些高级缓动选项，因此无需包含其他插件。在本节中我们不会详细讨论它们；但是，我们将在本章后面的某些示例中使用它们，在“页面上缩放元素”部分。

# 高亮指定的元素

高亮效果会临时将被调用的任何元素变成浅黄色（该效果也被称为**黄色渐变技术**（**YFT**））。让我们一起来举个简单的例子，这样我们就能看到效果的实际作用：

```js
<link rel="stylesheet" href="css/effectHighlight.css">
```

`<script>`元素引用效果的源文件，以便使用`jquery.effects.highlight.js`文件：

```js
<script src="img/jquery.ui.effect-highlight.js"></script>
```

然后从页面的`<body>`元素中删除`<form>`元素，并用以下标记替换它：

```js
<h1>Choose the correct download below:</h1>
<a id="win" href="#"><img src="img/iconWin.png"></a>
<a id="mac" href="#"><img src="img/iconMac.png"></a>
<a id="linux" href="#"><img src="img/iconLinux.png"></a>
<button id="hint">Hint</button>
```

最后，将最终的`<script>`元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
    var ua = navigator.userAgent.split(" ");
    $("#hint").click(function() {
      var el = ua[1].toLowerCase().substring(1);
      $("#" + el).effect("highlight");
    });    
  });
</script>
```

将此页面保存为`effectHighlight.html`。调用高亮效果的代码与其他库组件的形式相同。调用`effect`方法，并将实际效果指定为方法的字符串参数。

我们只需检查`userAgent`字符串，看是否搜索 Windows、Mac 或 Linux 返回了正整数。如果找到正整数，则`userAgent`字符串包含搜索词；如果返回了`-1`，则未找到搜索词。

我们还需要创建新的样式表，不是为了让效果起作用，而是为了稍微整理一下。在文本编辑器的新页面中，添加以下选择器和规则：

```js
a { padding: 10px; float: left; }
a img { display: block; border: none; }
button { display: block; position: relative; top: 10px; clear: both; }
```

将此文件另存为`css`文件夹中的`effectHighlight.css`。

查看示例，点击**提示**按钮。应该会短暂地突出显示你正在使用的操作系统的图标：

![高亮指定的元素](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_14_02.jpg)

虽然我们的示例可能看起来有些刻意，但很容易看出这种效果作为前端辅助工具的潜力。每当有需要按特定顺序完成一系列操作时，高亮效果都可以立即向访问者提供关于下一步需要完成的步骤的视觉提示。

## 添加额外的效果参数

每个 `effect` 方法，以及指定实际应用的效果的参数，都可以使用三个额外的参数来控制效果的工作方式。所有这些参数都是可选的，包括以下内容（按列出的顺序）：

+   包含额外配置选项的对象

+   一个表示效果持续时间的毫秒数的整数，或指定 `slow`、`normal` 或 `fast` 中的一个的字符串

+   当效果结束时执行的回调函数

`highlight` 效果只有一个可配置选项，可以在作为第二个参数传递的对象中使用，那就是高亮颜色。

让我们将一些这些额外的参数添加到我们的高亮示例中，以澄清它们的用法。将 `effect` 方法在 `effectHighlight.html` 最后的 `<script>` 元素中的调用更改为以下内容：

```js
$(el).effect("highlight", {}, function() {
  $("<p />", {
    text: "That was the highlight"
  }).appendTo("body").delay(2000).fadeOut();
});
```

将此保存为 `effectHighlightCallback.html`。我们新代码最引人注目的特点也许是作为第二个参数传递的空对象。在这个示例中，我们不使用任何额外的可配置选项，但我们仍然需要传递空对象以便访问第三个和第四个参数。

作为第三个参数传递的回调函数，可能是 JavaScript 历史上最没用的回调函数之一，但它确实说明了在效果后如何轻松安排额外的代码执行。

# 弹跳

我们可以用很少的配置来使用另一个简单的效果，那就是弹跳效果。要看到这个效果的实际效果，请将 `effectHighlight.html` 中 `<body>` 元素的内容更改为以下内容：

```js
<div id="ball">
  <img src="img/ball.png">
</div>
```

我们还需要使用弹跳效果的源文件；修改对 `jquery.ui.effect-highlight.js` 文件的引用，使其指向 `bounce.js` 源文件：

```js
<script src="img/jquery.ui.effect-bounce.js"></script>
```

将此保存为 `effectBounce.html`。我们需要添加一点样式才能真正看到效果，但可能不值得创建一个全新的样式表，所以只需将页面的 `<head>` 元素中的 `<link>` 元素替换为以下内容即可：

```js
<style>
  #ball { position: relative; top: 150px; }
</style>
```

最后，修改最终的 `<script>` 元素，使其如下所示：

```js
<script>
  $(document).ready(function($){
    $("#ball").click(function() {
      $(this).effect("bounce", { distance: 140 });
    });
  });
</script>
```

在此示例中使用弹跳效果显示了添加此简单但引人注目的效果有多容易。我们配置 `distance` 选项以设置元素移动的距离。可以配置的其他选项列在下表中：

| 选项 | 默认值 | 用途 |
| --- | --- | --- |
| `direction` | `"up"` | 设置弹跳方向 |
| `distance` | `20` | 设置第一次弹跳的像素距离 |
| `times` | `5` | 设置元素应该弹跳的次数 |

当你运行示例时，你会注意到弹跳效果中内置了一个缓出缓入的特性，因此随着动画的进行，弹跳的距离会自动减小。

### 注

这里使用的默认缓动效果是`swing`；这是库中可以使用的许多缓动特性之一。缓动函数控制动画在不同点处进行的速度；可以在[`api.jqueryui.com/easings/`](http://api.jqueryui.com/easings/)上看到可用的完整的缓动特性列表。

值得注意的是，对于大多数不同的效果，包括弹跳效果（但不是我们之前看到的亮点效果），实际上并未应用于指定的元素。相反，创建了一个包装元素，并且效果所针对的元素被附加到包装器的内部。实际效果然后应用于包装器。

这是一个要注意的重要细节，因为如果你需要在动画进行中操纵具有应用效果的元素，那么包装器将需要被定位，而不是原始元素。一旦效果的动画完成，包装器就从页面中移除。

# 抖动元素

抖动效果与弹跳效果非常相似，但关键区别是没有内置的缓动。因此，目标元素会在指定的次数内以相同的距离抖动，而不是每次减小（尽管在动画结束时会平稳停止）。

让我们修改前面的示例，使其使用抖动效果而不是弹跳效果。修改`effectBounce.html`以使用`shake.js`源文件而不是弹跳源文件：

```js
<script src="img/jquery.ui.effect-shake.js"></script>
```

然后修改最终`<body>`元素底部的最后一个`<script>`元素中的点击处理程序，使其如下所示：

```js
$("#ball").click(function() {
 $(this).effect("shake", { direction: "up" }, 100);
});
```

将此保存为`effectShake.html`。这次我们使用了`direction`配置选项和持续时间参数。配置选项控制了抖动的方向。我们将其设置为覆盖该选项的默认设置，即`left`。我们使用的持续时间加快了动画。

这种效果与弹跳效果共享相同的选项，尽管默认设置略有不同。选项列在下表中：

| 选项 | 默认值 | 用途 |
| --- | --- | --- |
| `direction` | `"left"` | 设置抖动的方向 |
| `distance` | `20` | 设置抖动的距离（像素） |
| `times` | `3` | 设置元素应该抖动的次数 |

## 转移元素的轮廓

转移效果与其他效果不同，因为它不直接影响目标元素。相反，它将指定元素的轮廓转移到另一个指定元素上。要看到此效果的实际操作，请将`effectShake.html`的`<body>`元素更改为包含以下元素：

```js
<div id="container">
  <div id="basketContainer">
    <div id="basket"></div>
    <p>Basket total: <span id="total">0</span></p>
  </div>      
  <div id="productContainer">
    <img alt="GTX 280" src="img/gcard.png"></img>
    <p>BFG GTX 280 OC 1GB GDDR3 Dual DVI HDTV Out PCI-E Graphics Card</p>
    <p id="price">Cost: $350</p>

  </div>
  <div id="purchase"><button id="buy">Buy</button></div>
</div>
```

将此保存为`effectTransfer.html`。我们创建了一个基本的产品列表；当点击**购买**按钮时，转移效果会给人一种产品被移入篮子的印象。为了实现这一点，将最后的`<script>`元素更改为包含以下代码： 

```js
<script>
  $(document).ready(function($){
    $("#buy").click(function() {
      $("#productContainer img").effect("transfer", {
        to:"#basket"
      }, 750, function() {
        var currentTotal = $("#total").text(),
        numeric = parseInt(currentTotal, 10);
        $("#total").text(numeric + 1);
      });
    });
  });
</script>
```

当然，一个适当的购物车应用程序会比这复杂得多，但我们确实可以看到转移效果的全部荣耀。不要忘记更新效果的源文件：

```js
<script src="img/jquery.effects.transfer.js"></script>
```

对于这个示例，我们还需要一些 CSS，所以创建以下新样式表：

```js
body { font-family: "Lucida Grande",Arial,sans-serif; }
#container { width: 707px; margin: 0 auto; }
#productContainer img { width:  92px; height: 60px; border: 2px solid #000000; position: relative; float: left; }
#productContainer p { width: 340px; height: 50px; padding: 5px; border: 2px solid #000; border-left: none; margin: 0; font-family: Verdana; font-size: 11px; font-weight: bold; float: left; }
p#price { height: 35px; width: 70px; padding-top: 20px; float: left; }
#purchase { height: 44px; width: 75px; padding-top: 16px; border: 2px solid #000; border-left: none; float: left; text-align: center; }
#basketContainer { width: 90px; margin-top: 100px; float: right; }
#basketContainer p { width:  100px; }
#basket { width: 65px; height: 50px; position: relative; left: 13px; background: url(img/shopping.png) no-repeat; }
.ui-effects-transfer { border: 2px solid #66ff66; }
```

将此保存为`effectTransfer.css`在`css`文件夹中。我们新样式表中的关键规则是针对具有类`ui-effects-transfer`的元素的规则。

这个元素是由效果创建的，与我们的样式一起产生绿色轮廓，该轮廓从产品转移到篮子中。

在浏览器中运行文件。我想你会同意，这是一个很好的效果，无论在哪个页面使用都会增加价值。在转移发生时，它应该是这样的：

![转移元素的轮廓](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_14_03.jpg)

转移效果只有两个可配置选项，其中一个是必需的，我们已经看到了。供参考，两者均列在以下表中：

| 选项 | 默认值 | 用途 |
| --- | --- | --- |
| `className` | `"ui-effects-transfer"` | 将自定义类名应用于效果辅助元素。 |
| `to` | `"none"` | 设置效果将转移到的元素。此属性是必需的。 |

到目前为止，我们已经看过的四种效果都有一个共同点-它们只能与`effect`方法一起使用。其余的效果不仅可以与`effect`方法一起使用，还可以与 jQuery 的切换和`show`/`hide`方法一起使用。

让我们来看看。

# 在页面上缩放元素

缩放效果是高度可配置的，用于缩小元素。当用于隐藏元素时非常有效。在这个示例中，我们将使用`hide()`方法触发效果，而不是使用`effect`方法。

在这个示例中，我们将使用一些 CSS 框架类，以及一些自定义样式；所以将两个新的`<link>`元素添加到`effectTransfer.html`的`<head>`元素中：

```js
<link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
<link rel="stylesheet" href="css/effectScale.css">
```

然后，将`<body>`元素中的底层标记替换为以下内容：

```js
<div class="ui-widget ui-widget-content ui-corner-all">
  <div class="ui-widget-header ui-corner-all">
    A dialog box
    <a id="close" class="ui-icon ui-icon-closethick" href="#">
    Close
    </a>
  </div>
  <div class="content">Close the dialog to see the scale effect</div>
</div>
```

不要忘记将效果的`<script>`元素更改为缩放效果的源文件：

```js
<script src="img/jquery.ui.effect-scale.js"></script>
```

最后，替换最后一个`<script>`元素，使其显示如下：

```js
<script>
  $(document).ready(function($){
    $("#close").click(function(e) {
      $("#close").click(function(e) {
        e.preventDefault();
        $(this).closest(".ui-widget").hide("scale", {}, 900);
      });
    });
  });
</script>
```

将新页面保存为`effectScale.html`。我们使用的自定义样式表如下：

```js
.ui-widget { padding: 3px; width: 300px; }
.ui-widget-header, .content { padding: 5px 10px; }
.ui-widget-header a { margin-top: 2px; float: right; }
```

将此文件保存为`effectScale.css`，并将其放入`css`文件夹中。这些样式用于使示例具有模糊对话框样式的外观。

在脚本中，我们简单地为关闭图标添加了一个点击处理程序，并在对话框外容器上调用了`effect()`方法。空对象作为方法的第二个参数传递，并且相对较长的持续时间作为第三个参数传递，因为此效果进行得相当迅速。以下截图显示了效果正在进行的情况：

![页面上元素的缩放](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_14_04.jpg)

在本示例中，使用`hide()`方法而不是`effect()`方法对我们是有利的，因为我们希望对话框在效果完成后保持隐藏。当使用`effect()`方法时，动画结束时，部件仍然可见。

### 提示

**何时应配置百分比选项？**

当与缩放效果一起使用`effect()`方法时，必须配置`percent`配置选项。

有几个配置选项可用于缩放；这些如下表所列：

| 选项 | 默认值 | 用途 |
| --- | --- | --- |
| `direction` | `"both"` | 设置元素进行缩放的方向。可以是指定水平、垂直或两者的字符串。 |
| `from` | `{}` | 设置要缩放的元素的起始高度和宽度。 |
| `origin` | `["middle","center"]` | 设置消失点，与显示/隐藏动画一起使用。 |
| `percent` | `0` | 设置缩放元素的最终大小。 |

# 在页面上爆炸元素

爆炸效果真是令人惊叹。目标元素被真正地爆炸成指定数量的碎片，然后完全消失。这是一个简单的效果，几乎没有配置属性，但是这个效果的视觉冲击力很大，为很少的代码提供了很多效果。让我们看一个基本的例子。

创建以下新页面：

```js
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="utf-8">
    <title>Explode</title>
    <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
    <style>
      body { width: 200px; margin-left: auto; margin-right: auto; }
    </style>
    <script src="img/jquery-2.0.3.js"></script>
    <script src="img/jquery.ui.effect.js"></script>
    <script src="img/jquery.ui.effect-explode.js"></script>
  </head>
  <script>
    $(document).ready(function($){
      $("#theBomb").click(function() {
        $(this).hide("explode");
      });
    });
  </script>
  <body>
    <p>Click the grenade to pull the pin!</p>
    <img id="theBomb" src="img/nade.jpg">
  </body>
</html>
```

将此保存为`effectExplode.html`。正如你所见，代码非常简单，可以完全开箱即用，无需额外配置。此效果仅有一个可配置属性，即`pieces`属性，它决定了元素爆炸成多少个碎片。默认值为九。该效果在使用`effect()`方法和`hide()`方法时同样有效。

一旦指定的元素被爆炸，它将通过将其`style`属性设置为`display: none`来隐藏。这是默认行为。但是，它仍然会保留在页面的 DOM 中。以下截图显示了爆炸正在进行的情况：

![页面上元素的爆炸](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_14_05.jpg)

物理学家有时会推测为什么时间之箭似乎只指向前方。他们总是会问自己诸如“我们为什么不会看到手榴弹从一大团碎片中自发形成？”这样的哲学问题。（实际上，物体通常是一个鸡蛋，但我认为基于鸡蛋的例子可能没有产生同样的影响！）

jQuery UI 不能帮助我们理解熵，但它可以向我们展示手榴弹自发重新组装的样子。我们需要隐藏`<img>`标签以显示它。最简单的方法是使用内联`style`属性：

```js
<img id="theBomb" src="img/nade.jpg" style="display:none">

```

然后，将最后一个`<script>`元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
    $("#theBomb").show("explode");
  });
</script>
```

将此变体保存为`effectExplodeShow.html`。这次我们使用`show()`方法而不是`hide()`方法来触发动画，该动画在页面加载完成后发生。

动画是相同的，只是它是反向显示的，这次手榴弹在动画结束后不会被隐藏。与其他效果一样，爆炸也可以使用特定的持续时间和回调函数。

# 创建一个膨胀效果

类似于爆炸效果，但略微更加微妙的是“膨胀”效果，它会导致元素在淡出之前略微增长。与爆炸效果类似，我们只需关注少量配置选项。

考虑一个页面上正在发生 AJAX 操作的情况。提供一个显示访问者正在发生某些事情的加载图像是有用的。当操作完成时，我们不仅可以隐藏这样的图像，还可以使其消失。

删除先前示例中的`<p>`元素，并更改`<img>`元素，使其指向一个新的图像：

```js
<img id="loader" src="img/ajax-loader.gif">
```

然后将效果的源文件更改为缩放效果：

```js
<script src="img/jquery.ui.effect-scale.js">
</script>
```

最后，将最后一个`<script>`元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
    $("#loader").click(function() {
      $(this).hide("puff");
    });
  });
</script>
```

将其保存为`effectPuff.html`。在这个示例中，我们实际上并没有检测给定过程是否已经加载完成。这将需要太多的工作，仅仅是为了看到我们正在关注的效果。相反，我们将效果的执行绑定到一个简单的点击处理程序中。

你会注意到我们为这个效果使用了`jquery.ui.effect-scale.js`源文件。

膨胀效果是唯一没有自己源文件的效果，而是作为非常密切相关的缩放效果的源文件的一部分。

与我们在上一节中查看的爆炸效果类似，此效果只有一个配置选项，可以将其作为第二个参数传递给`effect`方法的对象。这是`percent`选项，用于控制图像放大到的尺寸。默认值为 150%。与爆炸效果一样，动画结束后，目标元素被隐藏不再可见。无论是使用`effect()`还是`hide()`，都会发生这种情况。

该效果拉伸了目标元素（如果有的话，还有它的子元素），同时降低其不透明度。它适用于适当的图像、背景颜色和边框，但要注意，它与由 CSS 指定的背景图像不太适用。尽管如此，这个效果非常棒。

以下屏幕截图显示了它的具体操作：

![创建膨胀效果](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_14_06.jpg)

# 使用脉动效果工作

脉动效果是另一个与指定元素的不透明度配合运作的效果。这个效果暂时降低不透明度，指定次数，使元素看起来有脉动。

在以下基本示例中，我们将创建一个简单的倒计时时间，从`15`开始倒数。当显示时间达到 10 秒时，它将开始变成红色。在`effectPuff.html`中，更改页面的`<head>`元素中的链接，指向一个新样式表：

```js
<link rel="stylesheet" href="css/effectPulsate.css">
```

然后从页面中删除加载的`<img>`元素，并用以下元素替换它：

```js
<div id="countdown">15</div>
```

接下来，更改效果的源文件，使用`jquery.ui.effect-pulsate.js`文件：

```js
<script src="img/jquery.ui.effect-pulsate.js"></script>
```

最后，删除现有的最后一个`<script>`元素，并将其替换为以下内容：

```js
<script>
  $(document).ready(function($){
    var age = 15, countdown = $("#countdown"),
      adjustAge = function() {
        countdown.text(age--);
        if (age === 0) {
          clearInterval(timer);
        } else if (age < 10) {
          countdown.css({
          backgroundColor: "#ff0000",
          color: "#fff"
        }).effect("pulsate", { times: 1 });
      }
    },
    timer = setInterval(function() { adjustAge() }, 1000);
  });
</script>
```

将此保存为`effectPulsate.html`。页面本身仅包含一个简单的`<div>`元素，其中包含文本`15`。代码首先设置一个计数器变量，然后缓存`<div>`元素的选择器。然后我们定义`adjustAge()`函数。

此函数首先减少倒计时元素的文本内容，并同时减少计数器变量的值。然后检查计数器变量是否已经达到零；如果是，则清除即将设置的间隔。

如果计数器变量大于 0 但小于 11，则函数将元素应用红色背景和白色文本内容，并运行脉动效果。

我们使用`times`配置选项来指定元素应该脉动多少次。因为我们将每秒执行一次该方法，所以可以将其设置为每次脉动一次。这是唯一的可配置选项。

在我们的`adjustAge`函数之后，我们使用 JavaScript 的`setInterval`函数启动间隔。这个函数将在指定的间隔之后重复执行指定的函数，在这个例子中是 1000 毫秒，或 1 秒。我们避免使用`window`对象，而是使用匿名函数调用我们的命名函数。

新样式表非常简单，包括以下代码：

```js
#countdown { width: 100px; border: 1px solid #000; margin: 10px auto 0; font-size: 60px; text-align: center; }
```

将此保存在`css`文件夹中，命名为`effectPulsate.css`。

# 向元素添加下降效果

下降效果很简单。元素看起来掉下（或掉入）页面，这是通过调整元素的`position`和`opacity`值来模拟的。

这个效果公开了以下可配置选项：

| 选项 | 默认值 | 用途 |
| --- | --- | --- |
| `direction` | `"left"` | 设置下降的方向 |
| `distance` | 元素的外宽度或高度（取决于方向）除以 2 | 设置元素下落的距离 |
| `easing n` | `one` | 设置动画期间使用的缓动函数 |
| `mode` | `"hide"` | 设置元素是隐藏还是显示 |

有许多情况下，投放效果会很有用，但我立即想到的是创建自定义工具提示时。我们可以很容易地创建一个在按钮被点击时出现的工具提示，但我们可以将其投放到页面上。在本示例中，我们将使用按钮小部件和`position`实用程序，以及效果。

在`effectPulsate.html`的`<head>`元素中添加一个链接到 CSS 框架文件，并更改样式表链接：

```js
<link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
<link rel="stylesheet" href="css/effectDrop.css">
```

从页面中删除倒计时`<div>`元素，并改为添加以下元素：

```js
<a id="button" href="#" title="This button does nothing">
  Click me!
</a>
```

现在我们需要更改效果的源文件并添加位置和按钮小部件的源文件：

```js
<script src="img/jquery.ui.effect-drop.js">
</script>
<script src="img/jquery.ui.core.js">
</script>
<script src="img/jquery.ui.widget.js">
</script>
<script src="img/jquery.ui.position.js">
</script>
<script src="img/jquery.ui.button.js">
</script>
```

最后，更改最后一个`<script>`元素，使其如下所示：

```js
<script>
  $(document).ready(function($){
    $("#button").button().click(function() {
      var button = this, tip = $("<span />", {
        id: "tip",
        text: button.title
      }),
      tri = $("<span />", {
        id: "tri"
      }).appendTo(tip);
      tip.appendTo("body").position({
        of: button,
        my: "right-35 center",
        at: "left center",
        offset: "-30 0"
      });
      tip.show("drop", { direction: "up" }, function() {
        $(this).delay(1000).fadeOut();
      });
    });
  });
</script>
```

将此文件保存为`effectDrop.html`。当单击按钮时，我们首先存储按钮的 DOM 节点的引用。然后，我们添加一个`position`实用程序的配置对象，以便将我们的工具提示定位在按钮的右侧。

然后我们创建一个新的`<span>`元素作为工具提示，其文本内容设置为按钮的标题文本。我们还创建另一个用于创建三角形 CSS 形状以给工具提示添加指针的元素。此元素附加到工具提示上。

创建后，工具提示附加到页面的`<body>`元素上，然后使用投放效果显示。`direction`配置选项用于使工具提示显示为下拉式；我们必须在此指定相反的方向，因为我们的工具提示是绝对定位的。

除了 CSS 框架提供的样式之外，此示例还需要一些最小的 CSS 来为工具提示设置样式。创建以下样式表：

```js
#tip { display: none; padding: 10px 20px 10px 10px;
position: absolute; background-color: #cecece; }
#tri { border-top: 20px solid transparent; border-right: 30px solid #cecece; border-bottom: 20px solid transparent; position: absolute; left:- 30px; top: 0; }
```

将其保存在`css`文件夹中，命名为`effectDrop.css`。这里的样式纯粹是为了美观。

在浏览器中运行文件时，您应该看到您的工具提示，如以下截图所示：

![将投放效果添加到元素](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_14_07.jpg)

# 实现滑动效果

jQuery UI 库的剩余效果都通过以不同方式显示和隐藏元素来工作，而不是像我们已经看过的大多数效果那样使用不透明度。

滑动效果也不例外，并通过将元素滑动到（或滑出）视图中来显示（或隐藏）元素。它类似于我们刚刚看到的投放效果。主要区别在于它不使用不透明度。

滑动效果包含以下配置选项：

| 选项 | 默认值 | 用途 |
| --- | --- | --- |
| `direction` | `"left"` | 设置滑动的方向 |
| `distance` | 元素的外部宽度或高度（取决于方向） | 设置元素滑动的距离 |
| `easing` | `none` | 设置动画期间使用的缓动函数 |
| `mode` | `"show"` | 设置元素是隐藏还是显示 |

这些是我们在前面示例中看到的放置效果使用的相同配置选项，只是某些默认值不同。

对于我们的下一个示例，我们可以创建完全相同类型的功能。在`effectDrop.html`中，将页面`<head>`元素中的`<link>`元素从`effectDrop.css`更改为`effectSlide.css`：

```js
<link rel="stylesheet" href="css/effectSlide.css">
```

然后，从页面的`<body>`元素中删除`<a>`元素，并添加以下 HTML 代码：

```js
<aside id="basket" class="ui-widget">
  <h1 class="ui-widget-header ui-corner-all">
    Basket
    <a id="toggle" title="Show basket contents" class="ui-icon ui-icon-circle-triangle-s" href="#">
      Open
    </a>
  </h1>
  <div class="ui-widget-content ui-corner-bottom">
    <ul>
      <li>
        <img src="img/placeholder.gif">
        <h2>Product name</h2>
        <h3>Brief descriptive subtitle</h3>
        <span>£xx.xx</span>
      </li>
      <li>
        <img src="img/placeholder.gif">
        <h2>Product name</h2>
        <h3>Brief descriptive subtitle</h3>
        <span>£xx.xx</span>
      </li>
      <li>
        <img src="img/placeholder.gif">
        <h2>Product name</h2>
        <h3>Brief descriptive subtitle</h3>
        <span>£xx.xx</span>
      </li>
    </ul>
  </div>
</aside>
```

此集合中的外部元素是`<aside>`，这是一个完美的小购物篮小部件，位于站点右侧列中。在此元素中，我们有一个作为购物篮标题的`<h1>`元素。标题包含一个链接，该链接将用于显示或隐藏篮子的内容。篮子的内容将包括容器`<div>`内的产品无序列表。

不要忘记更改效果源文件的`<script>`元素，以使用`jquery.ui.effect-slide.js`，并删除`jquery.ui.core.js`、`jquery.ui.widget.js`、`jquery.ui.position.js`和`jquery.ui.button.js`的`<script>`文件：

```js
<script src="img/jquery.ui.effect-slide.js">
</script>
```

最终的`<script>`元素需要更改为以下代码：

```js
  <script>
    $(document).ready(function($){
      $("#toggle").on("click", function(e) {
        var slider = $("#basket").find("div"),
          header = slider.prev();
        if (!slider.is(":visible")) {
          header.addClass("ui-corner-top")
            .removeClass("ui-corner-all");
        }
        slider.toggle("slide", {
          direction: "up"
        }, "slow", function() {
          if (slider.is(":visible")) {
            header.find("a").switchClass("ui-icon-circle-triangle-s", "ui-icon-circle-triangle-n");
          } else {
            header.switchClass("ui-corner-all", "ui-corner-top");
            header.find("a").switchClass("ui-icon-circle-triangle-n", "ui-icon-circle-triangle-s");
          }
        });
      });
    });
  </script>
```

将此文件保存为`effectSlide.html`。所有功能都驻留在一个点击处理程序中，我们将其附加到篮子标题中的图标上。当单击此元素时，我们首先初始化`slider`和`header`变量，因为这些是我们将要操作的元素。

然后，我们检查`slider`（即篮子内容容器）是否隐藏；如果隐藏，我们知道它即将打开，因此从`header`底部移除圆角。这样，即使在滑动打开时，滑块元素也能与`header`底部齐平。

然后，我们使用 jQuery 的`toggle()`方法调用效果，我们使用方法的第一个参数指定效果。然后，我们将配置选项`direction`设置为作为第二个参数传递的对象中。使用字符串`slow`作为第三个参数延长动画的持续时间，并使用匿名回调函数作为第四个参数。此函数将在滑动动画结束时执行。

在此函数内部，我们检查`slider`的状态，以查看它是否隐藏或打开。如果在动画结束时它是打开的，我们将从`header`底部移除边框，然后更改`header`中的图标，以便它指向上方，表示可以通过再次单击图标关闭篮子。

如果`slider`现在关闭，我们再次为`header`添加底部边框和圆角，并将图标更改回指向下的箭头。

我们在这个例子中也使用了一点 CSS。 创建以下样式表：

```js
#basket { width: 380px; float: right; }
#basket h1 { padding: 5px 10px; margin: 0; }
#basket h1 a { float: right; margin-top: 8px; }
#basket div { display: none; }
#basket ul { margin: 0; padding: 0; list-style-type: none; }
#basket li { padding: 10px; border-bottom: 1px solid #aaa; }
#basket li:last-child { border-bottom: none; }
#basket li:after { content: ""; display: block; width: 100%; height: 0; visibility: hidden; clear: both; }
#basket img { float: left; height: 75px; margin: 2px 10px 0; width: 105px; }
#basket h2 { margin: 0 0 10px; font-size: 14px; }
#basket h3 { margin: 0; font-size: 12px; }
#basket span { margin-top: 6px; float: right; }
```

将此保存为`effectSlide.css`在`css`文件夹中。 在这个例子中，我们不需要太多的 CSS，因为我们使用 CSS 框架类。

进行中的效果应如以下屏幕截图所示：

![实现滑动效果](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_14_08.jpg)

在这个例子中，我们可以很容易地只使用 jQuery 的本机`slideToggle()`方法；使用 jQuery UI 的滑动效果的主要好处是我们还可以左右滑动。

## 使用缓动

如前所述，`jquery.ui.effect.js`文件具有与效果无缝使用缓动的内置功能。 让我们看看实现这个有多简单。 更改`effectSlide.html`中的最后一个`<script>`元素，使其如下所示：

```js
<script>
  $(document).ready(function($){
    $("#toggle").on("click", function(e) {
      var slider = $("#basket").find("div"),
 header = slider.prev(),
 easing = (slider.is(":visible")) ?
 "easeOutQuart" :
 "easeOutBounce";
        if (!slider.is(":visible")) {
          header.addClass("ui-corner-top")
            .removeClass("ui-corner-all");
        }
        slider.toggle("slide", {
 direction: "up",
 easing: easing
        }, "slow", function() {
        if (slider.is(":visible")) {
          header.find("a").switchClass("ui-icon-circle-triangle-s", "ui-icon-circle-triangle-n");
        } else {
          header.switchClass("ui-corner-all", "ui-corner-top")
          header.find("a").switchClass("ui-icon-circle-triangle-n", "ui-icon-circle-triangle-s");
        }
      });
    });
  });
</script>
```

将此保存为`effectsSlideEasing.html`。 看到有多简单吗？ 我们所需要做的就是在效果的配置对象中添加`easing`选项，并将一个或多个缓动方法定义为选项值。

在这个例子中，我们通过设置一个变量来为每个切换状态指定不同的缓动方法，该变量使用 JavaScript 三元条件来设置缓动函数，具体取决于滑块是否可见。

当篮子滑下时，它在动画结束时会稍微弹跳，使用`easeOutBounce`。 当它向上滑动时，它会在动画过程中逐渐减速，使用`easeOutQuart`。

### 注意

我们可以在 jQueryUI 网站上的一个很好的页面上看到所有缓动方法的完整范围，并且可以在[`jqueryui.com/demos/effect/easing.html`](http://jqueryui.com/demos/effect/easing.html)上查看。

# 了解盲效果

盲效果实际上与滑动效果几乎相同。 在视觉上，元素似乎做了相同的事情，两个效果的代码文件也非常相似。 我们需要担心的两个效果之间的主要区别是，使用此效果，我们只能指定效果的轴，而不能指定实际的方向。

盲效果具有以下配置选项：

| 选项 | 默认值 | 使用 |
| --- | --- | --- |
| `direction` | `"vertical"` | 设置运动的轴 |
| `easing` | `none` | 设置动画过程中使用的缓动函数 |
| `mode` | `"hide"` | 设置元素是隐藏还是显示 |

此效果使用的`direction`选项仅接受值`horizontal`或`vertical`进行配置。 我们将在最后一个示例的基础上构建，以查看盲效果的实际效果。 将`effectSlide.html`中盲效果的`<script>`资源更改，使其引用`jquery.ui.effect-blind.js`文件：

```js
<script src="img/jquery.ui.effect-blind.js"></script>
```

现在更改`toggle()`方法，使其使用盲效果，并更改`direction`配置选项的值：

```js
slider.toggle("blind", {
 direction: "vertical"
}, "slow", function() {
  if (slider.is(":visible")) {
    header.css("borderBottomWidth", 0).find("a")
      .addClass("ui-icon-circle-triangle-n")
      .removeClass("ui-icon-circle-triangle-s");
  } else {
    header.css("borderBottomWidth", 1)
      .addClass("ui-corner-all")
      .removeClass("ui-corner-top").find("a")
      .addClass("ui-icon-circle-triangle-s")
      .removeClass("ui-icon-circle-triangle-n");
  }
});
```

将此保存为 `effectBlind.html`。实际上，我们只改变了指定效果的字符串，本例中为 `blind`，以及 `direction` 属性的值，从 `up` 更改为 `vertical`。当我们在文件中查看时，注意在滑动元素和将其盲目地收起之间的细微差别。

当登录表单向上滑动时，元素的底部始终可见，就好像整个篮子正在向上或向下移动到标题栏中一样。然而，使用盲效果时，元素会从底部开始显示或隐藏，就像窗帘打开或关闭一样。

# 剪裁元素

剪裁效果与滑动效果非常相似。主要区别在于，剪裁效果不是将目标元素的一个边缘向另一个边缘移动，以给出元素滑出视野的效果，而是将目标元素的两个边缘都向中心移动。

剪裁效果具有与盲效果相同的配置选项，并且这些选项具有相同的默认值。

在第五章的最后，*对话框*中，我们创建了一个示例，当点击缩略图图像时，在对话框中显示了一个全尺寸图像。当按下对话框上的关闭按钮时，对话框会立即从页面中移除。

我们可以很容易地使用剪裁效果来关闭我们的对话框。

在 `dialog14.html` 中，在现有库文件之后添加剪裁效果的源文件：

```js
<script src="img/jquery.ui.effect.js"></script>
<script src="img/jquery.ui.effect-clip.js"></script>
```

然后，更改对话框配置对象，使其如下所示：

```js
dialogOpts = {
  modal: true,
  width: 388,
  height: 470,
  autoOpen: false,
  open: function(event, ui) {
  $("#dialog").empty();
    $("<img>").attr("src", filename).appendTo("#dialog");
    $("#dialog").dialog("option", "title", titleText);
  },
  hide: {
    effect: "clip"
  }
};
```

将此保存为 `effectClip.html`。在现有文件的这个简单添加中，我们将剪裁效果与 `close` 事件回调结合使用，以隐藏对话框。对于 `direction` 选项，默认配置值 `vertical` 和正常速度都很好，所以我们只需调用 `hide` 方法，指定剪裁而没有额外的参数。

下面的截图显示了被剪裁的对话框：

![剪裁元素](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_14_09.jpg)

# 折叠元素

折叠是一个很好的效果，它使应用于它的元素看起来像是被折叠起来，就像一张纸一样。它通过将指定元素的底边从顶部向上移动最多 15 像素，然后将右边缘完全移动到左边缘来实现这一点。

在这个效果的 API 中，第一部分元素被缩小到距离顶部的距离是作为一个可配置属性暴露出来的。因此，这是我们可以根据实现的需要调整的东西。该属性是一个整数。

我们可以通过再次修改对话框示例来看到这个效果。在 `effectClip.html` 中，将剪裁的效果源文件更改为折叠：

```js
<script src="img/jquery.ui.effect-fold.js"></script>
```

然后将 `hide` 事件回调更改为以下内容：

```js
hide: {
  effect: "fold",
  size: 200,
  duration: 1000
}
```

将此保存为`effectFold.html`。这次我们利用大小配置选项使效果停在第一个折叠处，距离对话框顶部 200 像素处。我们还稍微减慢了动画速度，将持续时间设置为 1000 毫秒。这是一个非常好的效果；以下截图显示了动画的第二部分：

![折叠元素](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_14_10.jpg)

# 摘要

在本章中，我们已经涵盖了 jQuery UI 库中可用的完整 UI 效果范围。我们看到了如何使用`jquery.ui.effect.js`基本组件构建引人注目的颜色动画和平滑的类转换是多么容易。

我们还看到以下效果可以与简单效果 API 一起使用：

+   弹跳

+   突出显示

+   摇动

+   转移

重要的一点是，大多数单独效果不仅可以与效果 API 一起使用，还可以利用`show`/`hide`和`toggle`逻辑，使它们非常灵活和健壮。以下效果可以与此高级 API 一起使用：

+   盲

+   剪辑

+   掉落

+   爆炸

+   折叠

+   膨胀

+   脉动

+   规模

+   滑动

我们还看到了 jQuery UI 效果核心文件还包括了在我们没有使用 jQuery UI 时必须使用的`jquery.easing.js`插件中使用的所有缓动函数。

现在我们来到了本章的结束。有一句话我相信你们几乎都听过。那就是“授人以鱼……”的说法。我希望在本书的过程中，我教会了你们如何捕鱼，而不只是给了你们一条鱼。
