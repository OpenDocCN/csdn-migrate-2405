# jQueryUI 1.10：jQuery 的用户界面库（四）

> 原文：[`zh.annas-archive.org/md5/67D4BB507B37025C38972681032F3C25`](https://zh.annas-archive.org/md5/67D4BB507B37025C38972681032F3C25)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：工作中的工具提示

作为 HTML 3 标准的一部分引入，并使用 title 属性作为其文本，工具提示是用于在页面中提供上下文的常见元素。您可能会在各种情况下找到它们的用法，尽管最有可能的情况是在提供帮助以纠正表单提交中的错误时发现它们（特别是涉及产品支付时！）。

jQuery 团队在库的版本 1.9 中引入了他们的**工具提示**的版本；它被设计为直接替换所有浏览器中使用的标准工具提示。然而，这里的区别在于，尽管无法样式化标准工具提示，但 jQuery UI 的替代品旨在具有可访问性、可主题化和完全可定制化。它被设置为不仅在控件获得焦点时显示，而且当你悬停在该控件上时也会显示，这使得它更容易用于键盘用户。

在本章中，我们将讨论以下主题：

+   默认的小部件实现

+   CSS 框架如何定位工具提示小部件

+   如何应用自定义样式

+   使用它们的选项配置工具提示

+   使用它们的方法控制工具提示

+   程序化地显示工具提示

+   在工具提示中显示不同类型的内容

+   工具提示的内置过渡效果

+   AJAX 工具提示

# 实现一个默认的工具提示

工具提示是为了直接替换浏览器的本机工具提示而构建的。它们将识别标签中 title 属性的默认标记，并使用它自动添加小部件所需的附加标记。但是，可以使用工具提示的 items 和 content 选项定制目标选择器；您将在本章后面看到一个例子。让我们首先看一下实现工具提示所需的基本结构。

在文本编辑器中的新文件中，创建以下页面：

```js
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="utf-8">
    <title>Tooltip</title>
    <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
    <style>
    p { font-family: Verdana, sans-serif; }
    </style>
    <script src="img/jquery-2.0.3.js"></script>
    <script src="img/jquery.ui.core.js"></script>
    <script src="img/jquery.ui.widget.js"></script>
    <script src="img/jquery.ui.position.js"></script>
    <script src="img/jquery.ui.tooltip.js"></script>
    <script>
      $(document).ready(function($){
      $(document).tooltip();
      });  
    </script>        
  </head>
  <body>
 <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla blandit mi quis imperdiet semper. Fusce vulputate venenatis fringilla. Donec vitae facilisis tortor. Mauris dignissim nibh ac justo ultricies, nec vehicula ipsum ultricies. Mauris molestie felis ligula, id tincidunt urna consectetur at. Praesent <a href="http://www.ipsum.com" title="This was generated from www.ipsum.com">blandit</a> faucibus ante ut semper. Pellentesque non tristique nisi. Ut hendrerit tempus nulla, sit amet venenatis felis lobortis feugiat. Nam ac facilisis magna. Praesent consequat, risus in semper imperdiet, nulla lorem aliquet nisi, a laoreet nisl leo rutrum mauris.</p>
  </body>
</html>
```

将代码保存为`jqueryui`工作文件夹中的`tooltip1.html`。让我们回顾一下使用了什么。以下脚本和 CSS 资源是默认工具提示小部件配置所需的：

+   `jquery.ui.all.css`

+   `jquery-2.0.3.js`

+   `jquery.ui.core.js`

+   `jquery.ui.widget.js`

+   `jquery.ui.tooltip.js`

在底层 HTML 中使用 title 元素创建工具提示所需的脚本可以简单地如下所示，这应该添加在您的代码中的最后一个`<script>`元素之后，如前面的示例所示：

```js
<script>
  $(document).ready(function($){
    $(document).tooltip();
  });  
</script>        
```

在此示例中，当悬停在链接上时，库会将屏幕阅读器所述的必需 aria 添加到 HTML 链接中。然后，小部件动态生成工具提示的标记，并将其附加到文档中，就在结束的`</body>`标记之前。一旦目标元素失去焦点，这将自动删除。

### 注：

**ARIA**，或**可访问的丰富互联网应用程序**，提供了使内容对残障人士更加可访问的方式。你可以在 [`developer.mozilla.org/en-US/docs/Accessibility/ARIA`](https://developer.mozilla.org/en-US/docs/Accessibility/ARIA) 了解更多关于这个倡议的信息。

添加工具提示时并不必限制只使用 `$(document)` 元素。工具提示同样适用于类或选择器 ID；使用选择器 ID，将会给出更精细的控制能力，正如我们将在本章稍后所看到的。

# 探索工具提示 CSS 框架类

使用 Firefox 的 Firebug（或其他通用的 DOM 探查器），我们可以看到特定的类名被添加到创建工具提示小部件的底层 HTML 元素中。让我们简要地审查这些类名，看看它们如何为小部件的整体外观做出贡献。

| 类名 | 目的 |
| --- | --- |
| `ui-tooltip` | 工具提示的外部容器 |
| `ui-tooltip-content` | 工具提示的内容 |
| `ui-widget-content` | 将内容容器样式应用于元素及其子文本、链接和图标 |
| `ui-corner-all` | 应用圆角半径到元素的四个角 |

与其他小部件不同，工具提示几乎没有增加样式的方式——大多数样式是在创建工具提示时添加的，如下面的截图所示：

![探索工具提示 CSS 框架类](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_02.jpg)

# 覆盖默认样式

在为工具提示小部件设置样式时，我们不仅限于仅使用提供的预构建主题（关于这一点，我们将在下一节进行讨论），我们始终可以选择用我们自己的样式覆盖现有样式。在下一个示例中，我们将看到如何通过对来自 `tooltip1.html` 的示例进行一些微小更改来轻松实现这一点。

在一个新文档中，添加以下样式，并将其保存为 `tooltipOverride.css`，放在 `css` 文件夹中：

```js
p { font-family: Verdana, sans-serif; }
.ui-tooltip { background: #637887; color: #fff; }
```

不要忘记从文档的 `<head>` 元素中链接到新的样式表：

```js
<link rel="stylesheet" href="css/tooltipOverride.css">
```

### 提示

在我们继续之前，值得说明一种在将结果提交到代码之前对工具提示进行样式设置的好技巧。

如果你使用的是 Firefox，你可以下载并安装 Firefox 的 **Toggle JS** 插件，该插件可以从 [`addons.mozilla.org/en-US/firefox/addon/toggle-js/`](https://addons.mozilla.org/en-US/firefox/addon/toggle-js/) 下载。这使我们可以按页面关闭 JavaScript；然后我们可以将鼠标悬停在链接上以创建工具提示，然后在 Firebug 中展开标记并随心所欲地进行样式设置。

将你的 HTML 文档保存为 `tooltip2.html`。当我们在浏览器中运行页面时，当鼠标悬停在文本中的链接上时，你应该看到修改后的工具提示出现：

![覆盖默认样式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_03.jpg)

## 使用预构建主题

如果手工创建全新的样式对你的需求来说太过繁琐，你可以选择使用 jQuery UI 网站提供的预构建主题之一进行下载。

这是一个非常容易的变更。我们首先需要下载替换主题的副本；在我们的示例中，我们将使用一个称为**Excite Bike**的主题。让我们开始浏览[`jqueryui.com/download/`](http://jqueryui.com/download/)，然后取消选择**Toggle All**选项：

![使用预置主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_04.jpg)

我们不需要下载整个库，只需要在底部更改主题选项以显示**Excite Bike**，然后单击**Download**：

![使用预置主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_05.jpg)

接下来，打开`tooltip2.html`的一个副本，然后找到这一行：

```js
<link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
```

您会注意到上述行中的突出显示的单词。这是现有主题的名称。将其更改为`excite-bike`，然后将文档保存为`tooltip3.html`，然后删除`tooltipOverride.css`链接，就可以了。以下是我们替换主题的示例：

![使用预置主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_06.jpg)

通过更改一个单词，我们可以在 jQuery UI 可用的任何预置主题之间切换（甚至其他人在网上提供的任何自定义主题），只要您已经下载并复制了主题到相应的文件夹中。

但是，可能会有一些情况，我们需要微调设置。这使我们既可以集中精力进行所需的更改，又可以兼顾两全其美。让我们看看如何使用 ThemeRoller 修改现有主题。

## 使用 ThemeRoller 创建自定义主题

如果我们浏览到[`jqueryui.com/themeroller/`](http://jqueryui.com/themeroller/)，我们可以修改用于样式化此页面上的**Tooltip**示例的一些设置。在**Content**下修改**Background color & texture**选项，然后将**Border**选项更改为**#580000**，如下截图所示：

![使用 ThemeRoller 创建自定义主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_07.jpg)

移动到**Clickable: active state**部分，然后将**Background color & texture**选项更改为**#ccb2b2**，**Border**选项更改为**#580000**。其余部分保持不变：

![使用 ThemeRoller 创建自定义主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_08.jpg)

如果您滚动到页面底部的**Tooltip**示例，然后将鼠标悬停在任一图像上，您应该会看到我们更改的效果：

![使用 ThemeRoller 创建自定义主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_09.jpg)

虽然我知道这些颜色可能不会赢得任何风格奖，但您可以看到改变颜色是多么容易。当您选择完颜色后，您可以从下载页面下载最终版本。本书附带的代码下载中也提供了自定义主题的副本；看看`jquery`文件夹中的`tooltip4.html`，以查看我们的新样式表的示例。

### 注意

我们甚至可以使用 HTML 进一步操作。不过，请注意，这将给您的页面引入安全风险，应谨慎使用！请查看本章后面标记为 *Working with HTML in tooltips* 的部分，以了解您如何真正改变工具提示样式的示例。

# 配置工具提示选项

库中的每个不同组件都有一系列选项，控制着小部件默认启用的功能。可以将对象文字或对象引用传递到 `tooltip()` 小部件方法中以配置这些选项。

在下表中显示了配置非默认行为的可用选项：

| 选项 | 默认值 | 用于… |
| --- | --- | --- |
| `content` | `function returning the title attribute` | 设置工具提示的内容 —— 如果设置了此选项，则很可能您还需要更改 items 选项。 |
| `disabled` | `false` | 禁用工具提示。 |
| `hide` | `null` | 确定是否以及如何动画隐藏工具提示。 |
| `items` | `[title]` | 设置指示应显示工具提示的项的选择器。如果您计划使用除了 title 属性以外的内容作为工具提示内容，或者需要为事件委托设置不同的选择器，则可以自定义此内容。 |
| `position` | `{ my: "left top+15", at: "left bottom", collision: "flipfit" }` | 确定工具提示相对于关联目标元素的位置。 |
| `show` | `null` | 确定是否以及如何动画显示工具提示。 |
| `tooltipClass` | `null` | 向可以显示不同工具提示类型的小部件添加类，例如错误或警告。 |
| `track` | `false` | 确定工具提示是否应跟踪（跟随）鼠标。 |

# 精确定位工具提示

jQuery UI 工具提示最有用的功能之一是能够精确调整它们在屏幕上的位置。可能会有需要它们出现的情况，但不能以隐藏网站或应用程序的重要功能为代价！让我们看一下 `position` 属性的工作原理，以一个具有自定义样式的带指针的工具提示为例。

在文本编辑器中，按照以下代码更改 `tooltip4.html` 的最后一个 `<script>` 块：

```js
<script>
  $(document).ready(function($){
    $('a').tooltip({
      position: { 
        my: 'center+30 bottom', 
        at: 'center top-8',
        of: '#tip'
      }
    });                  
    $('a').tooltip('option', 'tooltipClass', 'top');
  });  
</script>        
```

我们需要更改标记，以包括我们刚刚在工具提示调用中引用的选择器 ID：

```js
<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla blandit mi quis imperdiet semper. Fusce vulputate venenatis fringilla. Donec vitae facilisis tortor. Mauris dignissim nibh ac justo ultricies, nec vehicula ipsum ultricies. Mauris molestie felis ligula, id tincidunt urna consectetur at. Praesent <a href="http://www.ipsum.com" id="tip" title="This was generated from www.ipsum.com">blandit</a> faucibus ante ut semper. Pellentesque non tristique nisi. Ut hendrerit tempus nulla, sit amet venenatis felis lobortis feugiat. Nam ac facilisis magna. Praesent consequat, risus in semper imperdiet, nulla lorem aliquet nisi, a laoreet nisl leo rutrum mauris.</p>
```

在文本编辑器中新建一个文件，创建以下小样式表：

```js
body { margin-top: 75px; }
.ui-tooltip { background: #c99; color: white; border: none; padding: 0; opacity: 1; border-radius: 8px; border: 3px solid #fff; width: 245px; }
.ui-tooltip-content { position: relative; padding: 1em; }
.ui-tooltip-content::after { content: ''; position: absolute; border-style: solid; display: block; width: 0; }
.right .ui-tooltip-content::after { top: 18px; left: -10px; border-color: transparent #c99; border-width: 10px 10px 10px 0; }
.left .ui-tooltip-content::after { top: 18px; right: -10px; border-color: transparent #c99; border-width: 10px 0 10px 10px; }
.top .ui-tooltip-content::after { bottom: -10px; left: 72px; border-color: #c99 transparent; border-width: 10px 10px 0; }
.bottom .ui-tooltip-content::after { top: -10px; left: 72px; border-color: #c99 transparent; border-width: 0 10px 10px; }
```

将其保存为 `tooltipPointer.css`。从 `tooltip4.html` 中删除现有的样式，然后将以下引用添加到 <head> 中，并将其重新保存为 `tooltip5.html`：

```js
<link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
<link rel="stylesheet" href="css/tooltipPointer.css">
```

在此示例中，我们使用了许多伪选择器来设置工具提示的样式；这样做的额外好处是不需要任何图像来生成工具提示。如果在浏览器中查看新页面，它应该类似于以下截图：

![精确定位工具提示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_10.jpg)

## 使用位置小部件

在我们的示例中，您可能已经注意到我们调整了窗口大小以实现前一个屏幕截图中显示的效果。如果将窗口扩展到全屏，工具提示很可能会移动；为了防止这种情况发生，重要的是要使用`of`属性，以便工具提示（在这种情况下）保持在我们标记中添加到的原始链接旁边。

使用位置属性（以及小部件）可能有点难以掌握，但值得努力确保您的小部件定位在您希望它们出现的位置。

### 注意

*Chris Coyier* 来自 CSS Tricks [(http://www.css-tricks.com](http://(http://www.css-tricks.com)) 展示了一个很好的示例，说明了位置实用程序的工作原理，您可以在 [`css-tricks.com/jquery-ui-position-function/`](http://css-tricks.com/jquery-ui-position-function/) 上查看。

简而言之，诸如以下代码的`position`小部件的示例用法：

```js
$("#move-me").position({
  "my": "right top",
  "at": "left bottom",
  "of":  $("#thing")
});
```

…将在以下插图中翻译：

![使用位置小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_11.jpg)

### 注意

来源：[`css-tricks.com/jquery-ui-position-function`](http://css-tricks.com/jquery-ui-position-function)/

# 使用工具提示跟踪鼠标移动

到目前为止，我们已经看过如何向页面添加工具提示，并涵盖了在屏幕上对其进行样式和定位的一些可能性。我们可以对我们的工具提示进行一个小的增强，使它们在激活时可以跟随您的鼠标光标移动。

这是一个简单的更改；更改`tooltip5.html`的主体，使其包含以下元素：

```js
<div id="content">
  <p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla blandit mi quis imperdiet semper. Fusce vulputate venenatis fringilla. Donec vitae facilisis tortor. Mauris <a href="#" rel="tooltip1"title="This is a tooltip hovering over a link">dignissim</a> nibh ac justo ultricies, nec vehicula ipsum ultricies. Mauris molestie felis ligula, id tincidunt urna consectetur at. Praesent blandit faucibus ante ut semper. <a href="#" rel="tooltip2" title="Here is another tooltip">Pellentesque non tristique</a> nisi. Ut hendrerit tempus nulla, sit amet venenatis felis lobortis feugiat. Nam ac facilisis magna. Praesent consequat, risus in semper imperdiet, nulla lorem aliquet nisi, a laoreet nisl leo rutrum mauris.
  <p>Tooltips are also useful for form elements, to show some additional information in the context of each field.</p>
  <p>
    <label for="textinput">First text input:</label>
    <input id="test" title="Please enter text in this field." />
  </p>
</div>
<p>Hover over the input field or links to see the tooltips in action.</p>
```

我们需要添加跟踪功能，因此请将最终的`<script>`块更新如下：

```js
<script>
  $(document).ready(function($){
 $(document).tooltip({ track: true });
  });     
</script>        
```

将更新后的文档保存为`tooltip6.html`。现在让我们添加一些最终的调整，以便内容正确显示在屏幕上。将以下内容添加到新文档中，并将其保存为`tooltipTrack.css`，放在`css`文件夹中：

```js
p { font-family: Verdana, sans-serif; font-size: 0.8em; font-style: italic; }
label { display: inline-block; width: 8.5em; }
#content { border: 2px solid #42505a; padding: 5px; border-radius: 4px; }
#content p { font-style: normal; }
```

不要忘记从页面的`<head>`中链接到新样式表（通过替换对`tooltipPointer.css`的现有引用）：

```js
<link rel="stylesheet" href="css/tooltipTrack.css">
```

以下屏幕截图显示了预览结果时页面的外观：

![使用工具提示跟踪鼠标移动](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_12.jpg)

我们现在已将工具提示设置为在悬停在目标元素上时随光标移动。在我们的示例中，这包括两个链接或输入元素之一。在设置跟踪时，我们不限于这些元素；可以在任何有效的 HTML 元素上使用此功能，例如单选按钮、按钮，甚至标签。

虽然我们无法在印刷品中轻松显示它，但您应该发现，只要光标仍悬停在目标元素上，工具提示将跟随它移动。

# 显示特定的工具提示

到目前为止，我们已经将所有的工具提示都分配给了使用`$(document)`对象工作；虽然这样做完全没有问题，但这意味着我们的工具提示将始终遵循相同的格式，并以相同的方式工作，因为配置将应用于页面上的所有工具提示。

我们可以轻松地进行更改；然而，jQuery UI 的工具提示将与任何 jQuery 选择器一样良好地工作，就像与文档对象一样。为了证明这一点，让我们看看如何配置工具提示以与特定元素一起工作。

在`tooltip2.html`中，将最后一个`<script>`元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
    $("#input").tooltip();
  });  
</script>        
```

我们不需要 CSS 重写样式，因此从文档的`<head>`中删除此行：

```js
<link rel="stylesheet" href="css/tooltipOverride.css">
```

我们还需要在现有标记下面添加以下代码：

```js
<p>Tooltips are also useful for form elements, to show some additional information in the context of each field.</p>
<label for="input">Please enter some text:</label>
<input type="text" id="input" title="I am a tooltip!">
```

将此文件保存为`jqueryui`文件夹中的`tooltip7.html`。在本示例中，我们已删除了对文档的引用，并将其替换为分配给文本框的`id`，如以下屏幕截图所示：

![显示特定的工具提示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_13.jpg)

与我们之前看到的相同的样式类仍然会被应用，但这次它们只会在悬停在文本框上时出现，而不是在文本中的链接上出现。

# 在工具提示中显示 AJAX 内容

在本章的大部分内容中，我们都使用了在页面上可以找到的任何标签的 title 属性中存储的文本来显示内容的标准技术。

然而，jQuery UI 的工具提示能够使用 AJAX 引用内容；这允许您动态生成工具提示，而不仅仅是限于在您的标记中显示的内容。在我们的示例中，我们将使用内容属性将纯文本传递给小部件；您也可以将回调函数作为内容的值传递给工具提示。

在您的文本编辑器中，删除`tooltip7.html`中现有的最后一个`<script>`块，并将其替换为以下代码：

```js
$(document).ready(function($){
  var url = "ajax.html"; 
  $("#ajaxTip").load(url);
  $('a').tooltip({
    content: '... waiting on ajax ...',
    open: function(evt, ui) {
      var elem = $(this);
      var data = $("#ajaxTip").text();
      $.ajax().always(function(event, ui) {
        elem.tooltip('option', 'content', data);
      });
    }
  }); 
}); 
```

接下来，删除`<label>`和`<input>`代码，然后在`<body>`部分的标记中立即添加以下内容：

```js
<div id="ajaxTip" style="display:none;"></div>
```

我们还需要创建一些将使用 AJAX 导入到页面中的内容，因此在一个新文档中添加以下代码，并将其保存为`ajax.html`：

```js
Lorem ipsum dolor sit amet, consectetur adipiscing elit.
```

将文件保存为`tooltip8.html`。在这种情况下，您需要通过 web 服务器查看此文件，以便 AJAX 效果能够正常工作；如果您无法访问在线 Web 空间，则可以在本地使用 WAMP Server（适用于 PC，可从 [`www.wampserver.com/en/`](http://www.wampserver.com/en/) 下载）或 MAMP（适用于 Mac，可从 [`www.mamp.info/en/mamp/`](http://www.mamp.info/en/mamp/) 下载），它们同样有效。

当悬停在链接上时，将显示一个工具提示，但内容是导入的 HTML 文件的内容，如以下屏幕截图所示：

![在工具提示中显示 AJAX 内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_14.jpg)

由于我们正在拉取基于 HTML 的内容，因此您应确保正确处理内容，以最大程度地减少对您网站的攻击风险。在本示例中，我们只是从我们的测试 HTML 文件中导入了纯文本，但是使用此方法确实允许您以很大的效果导入任何 HTML（在合理范围内）。

### 提示

本章后面，我们将更详细地讨论在工具提示中使用 HTML；您可能会考虑使用该方法的样式和内容，但是使用 AJAX 代替全部导入更好。

## 我们如何知道它是否起作用？

通过在 DOM 检查器的**控制台**选项卡中检查它，您可以最轻松地判断您的内容是否已成功导入，例如 Firebug。

### 注意

DOM 检查器可用于检查、浏览和编辑任何网页的**文档模型对象**（**DOM**），用于许多目的，例如确定加载缓慢的对象或源，或在提交到代码之前预览 CSS 样式的更改。

在这里，您可以清楚地看到来自`test.html`的调用（从 Firebug 中获取），该调用返回了一个值为`200`的值，表示成功：

![我们如何知道它是否起作用？](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_15.jpg)

# 在工具提示中使用效果

您可能已经注意到，在本章的每个示例中，每个工具提示默认都会逐渐淡入和淡出。工具提示不仅限于仅使用此淡入或淡出效果；您可能更喜欢在屏幕上显示时显示更多影响的内容。

在我们的下一个示例中，我们将看看如何修改代码以使用不同的效果，以实现此效果。将以下代码行立即添加到`tooltip7.html`中最后一次调用 jQuery UI 库之后：

```js
<script src="img/jquery.ui.effect.js"></script>
<script src="img/jquery.ui.effect-bounce.js"></script>
<script src="img/jquery.ui.effect-explode.js"></script>
```

接下来，从现有标记中删除这两行：

```js
<label for="input">Please enter some text:</label>
<input type="text" id="input" title="I am a tooltip!">
```

更改最终的`<script>`元素以包含新的效果，如下所示：

```js
<script>
  $(document).ready(function($){
    $(document).tooltip({
      show: { effect: "bounce", duration: 800 },
      hide: { effect: "explode", duration: 800 }
    });
  });  
</script>        
```

将文档保存为`tooltip9.html`。如果我们将页面加载到浏览器中，并在文本中的链接上悬停，您将看到在移开时工具提示会爆炸，如以下屏幕截图所示：

![在工具提示中使用效果](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_16.jpg)

# 在工具提示中使用 HTML

到目前为止，我们已经介绍了如何在页面上设置工具提示以及对其进行样式设置。然而，后者给我们带来了一个小困境，因为我们必须依赖 jQuery 来以编程方式添加 CSS 样式，如果我们的目标是保持渐进式的增强样式，这可能会有所损害。有一个解决办法；虽然它涉及一定的 jQuery 元素，但它确实允许我们使用 HTML 来生成我们的工具提示，这对我们的需求更加灵活。

### 提示

**在您的工具提示中使用 HTML**

在我们继续之前，我应该指出，使用这种方法会给您的代码引入安全风险；因此，默认情况下，内容的使用方式已从允许 HTML 更改为仅允许纯文本。请自行承担风险！

删除`tooltip9.html`中标记的内容，并添加以下内容：

```js
<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit. Nulla blandit mi quis imperdiet semper. Fusce vulputate venenatis fringilla. Donec vitae facilisis tortor. Mauris <a href="#" rel="tooltip1">dignissim</a> nibh ac justo ultricies, nec vehicula ipsum ultricies. Mauris molestie felis ligula, id tincidunt urna consectetur at. Praesent blandit faucibus ante ut semper. Pellentesque non tristique nisi. Ut hendrerit tempus nulla, sit amet venenatis felis lobortis feugiat. Nam ac facilisis magna. Praesent consequat, risus in semper imperdiet, nulla lorem aliquet nisi, a laoreet nisl leo rutrum mauris.
</p>
```

接下来，修改最终的`<script>`块，如以下代码所示：

```js
<script>
  $(document).ready(function($){
 var tooltiptext = "<div id='tooltip'><div id='title'>Test Tooltip </div><div id='content'>This is a random tooltip with some text</div></div>";
 $("a[rel=tooltip]").tooltip({
 items: "a",
 content: function() {
 return tooltiptext;
 }
 });
  });     
</script>   
```

将此另存为`tooltip10.html`。现在我们有一个工作的工具提示，但它看起来不太吸引人。创建一个新样式表，并添加以下基本样式：

```js
p { font-family: Verdana, sans-serif; }
#tooltip { width: 100px; border: 1px solid #F1D031; font-family: Verdana, sans-serif; font-size: 10px; }
#title { width: 94px; background-color: #FFEF93; font-weight: bold; padding: 3px; }
#content { width: 94px; background-color: #FFFFA3; height: 50px; padding: 3px; }
```

将此另存为`tooltipSelector.css`到您的`css`文件夹中。不要忘记从我们页面的`<head>`中链接到新样式表（在链接到标准 jQuery UI 样式表之后）：

```js
<link rel="stylesheet" href="css/tooltipSelector.css">
```

在此示例中，我们将不使用来自我们 redmond 主题的预构建样式，因此删除以下链接：

```js
<link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
```

我们还需要从先前的演示中删除效果调用，因此从您的文档的`<head>`中删除以下链接：

```js
<script src="img/jquery.ui.effect.js"></script>
<script src="img/jquery.ui.effect-bounce.js"></script>
<script src="img/jquery.ui.effect-explode.js"></script>
```

将我们更改后的文档保存为`tooltip10.html`。如果我们在浏览器中运行此页面，则会在悬停在链接上时看到工具提示**Test tooltip**出现，如下截图所示：

![在工具提示中使用 HTML](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_17.jpg)

正如您所看到的，我们已完全改变了我们的工具提示所使用的样式；这种方法需要比设置工具提示的常规方法更多的工作，但只要做得正确，它就是值得的！

## 使用 HTML 工作的危险

在上一个示例中，我们看了一下如何将 HTML 整合到您的工具提示中，这在显示工具提示中可以显示令人满意的内容方面开启了一些强大的机会。然而，在使用 HTML 工具提示时存在固有的风险；在库的以前版本中，您可以在设置工具提示时在`<title>`标签中包含 HTML。但是，在 UI 1.10 中，这已经更改为修复跨站点脚本（XSS）漏洞的版本 1.9 中存在的版本，在该漏洞中，攻击者可以在页面上的工具提示小部件中插入（或注入）客户端脚本，通常是恶意的。您仍然可以使用 HTML，但需要像前面的示例中所述使用内容选项。您可以在[`en.wikipedia.org/wiki/Cross-site_scripting`](http://en.wikipedia.org/wiki/Cross-site_scripting)了解有关跨站点脚本的更多信息，以及如何减少威胁。

### 注意

由于内容选项覆盖了默认行为，因此您应始终确保正确转义（或清理）内容以最小化跨站点脚本的风险。

# 使用工具提示方法

Tooltip widget 包含一些方法，允许我们以编程方式使用它并更改其默认行为。让我们看一下这些方法，它们在以下表格中列出：

| 方法 | 用途 |
| --- | --- |
| `close` | 关闭工具提示；仅应用于非委托工具提示。 |
| `destroy` | 完全删除工具提示功能。 |
| `disable` | 禁用工具提示。 |
| `enable` | 启用工具提示。 |
| `open` | 以编程方式打开工具提示。这仅适用于非委托工具提示。 |
| `option` | 获取或设置与指定的`optionName`关联的值 |
| `widget` | 返回包含原始元素的 jQuery 对象。 |

# 启用和禁用工具提示

我们可以利用`enable`或`disable`方法以编程方式启用或禁用特定的工具提示。这将有效地打开任何最初被禁用的工具提示或关闭当前活动的工具提示。让我们利用`enable`和`disable`方法来打开或关闭一个工具提示，我们将配置它在页面加载到浏览器时处于禁用状态。

在`tooltip10.html`的工具提示部件的现有标记之后直接添加以下新的`<button>`元素：

```js
    <label for="input">Please enter some text:</label>
    <input type="text" id="tooltip2" title="I am a tooltip!">
    <p>
      <button id="turnon">Enable Tooltip 1</button>
      <button id="turnoff">Disable Tooltip 1</button>
    <p>
  </body>
```

接下来，更改最后的`<script>`元素，使其如下所示：

```js
<script>
  $(document).ready(function($){
    $("#tooltip").tooltip({ disabled: true });
    $("#turnon").click(function(){
      $("#tooltip").tooltip("enable");
    })

    $("#turnoff").click(function(){
      $("#tooltip").tooltip("disable");
    })
  });  
</script>
```

将更改的文件保存为`tooltip11.html`。在页面上，我们添加了两个新的`<button>`元素。一个用于启用已禁用的工具提示，另一个用于再次禁用它。如果我们将页面加载到浏览器中，我们将看到类似以下截图：

![启用和禁用工具提示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_18.jpg)

在 JavaScript 中，我们使用`启用工具提示`按钮的`click`事件来调用`tooltip()`小部件方法。为此，我们将字符串`enable`作为第一个参数传递给`tooltip()`方法。另外，我们将要启用的标签的索引号作为第二个参数传递。jQuery UI 中的所有方法都是以这种方式调用的。我们指定要调用的方法的名称作为小部件方法的第一个参数；`disable`方法也是以相同的方式使用的。

### 注意

不要忘记，如果将`$(document)`设置为工具提示所在的元素，则我们可以在不需要额外参数的情况下使用这两种方法，以启用或禁用该页面上的所有工具提示。

# 程序化显示工具提示

除了以编程方式启用或禁用工具提示之外，我们同样可以通过点击屏幕上的按钮或适当的链接随意显示或隐藏工具提示。让我们现在使用这两种方法之一，在下一个示例中随意显示或隐藏其中一个工具提示。

在`tooltip11.html`中，按指示修改现有标记的最后几行：

```js
<label for="input">Please enter some text:</label>
<input type="text" id="tooltip2" title="I am a tooltip!">
<p>
 <button id="showtip">Show (open) Tooltip</button>
 <button id="hidetip">Hide (close) Tooltip</button>
</p>
```

接下来，让我们更改最后的`<script>`元素，以包含新添加的按钮所分配的新事件处理程序：

```js
<script>
  $(document).ready(function($){
 $("#tooltip").tooltip();

 $("#showtip").click(function(){
 $("#tooltip").tooltip("open");
 })
 $("#hidetip").click(function(){
 $("#tooltip").tooltip("close");
 })
  });  
</script>        
```

将已更改的文件保存为`tooltip12.html`。在将页面加载到浏览器并单击**显示（打开）工具提示**按钮时，您将会看到工具提示的出现：

![程序化显示工具提示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_19.jpg)

在 JavaScript 中，我们使用**显示（打开）工具提示**按钮的`click`事件来调用工具提示小部件并显示工具提示。为此，我们只需要将一个属性，即字符串`open`，传递给`tooltip()`方法。当我们需要隐藏（或关闭）工具提示时，我们可以以类似的方式通过调用工具提示小部件来传递字符串`close`。

# 处理工具提示事件

Tooltip 小部件定义了三个事件，允许您添加回调函数以执行不同的操作，当检测到小部件暴露的某些事件时。以下表格列出了能够在事件上接受可执行函数的配置选项：

| 事件 | 当...时触发 |
| --- | --- |
| `close` | 当焦点离开或鼠标移出时，提示关闭或触发 |
| `create` | 提示已创建 |
| `open` | 当焦点移入或鼠标悬停时，提示显示或触发 |

每个库组件都有回调选项（如前面表格中的选项），这些选项被调整为在任何访问者交互的关键时刻查找。我们在这些回调中使用的任何函数通常在更改发生之前执行。因此，您可以从回调中返回`false`，防止操作发生。

在我们的下一个示例中，我们将看看如何轻松地对显示的特定提示做出反应，使用标准的非绑定技术。将`tooltip12.html`中的最后一个 `<script>` 元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
    $("#tooltip").tooltip({
      open: function(event, ui) {
        $("#console").append("Tooltip activated" + "<br>");
      },
      close: function(event, ui) {
        $("#console").append("Tooltip closed" + "<br>");
      }
    });
    $("#tooltip").tooltip();
  });  
</script>
```

保存为`tooltip13.html`。我们还需要更改我们的标记，所以删除现有标记底部的两个按钮，并插入一个新的 History `<div>` 如下所示：

```js
 <div id="history">
 <b>History:</b> 
 <div id="console"></div>
 </div>
</body>
```

最后，我们需要添加一些样式使显示看起来漂亮。在一个新文档中，添加以下内容：

```js
#history { border-radius: 4px; border: 1px solid #c4c4c4; width: 250px; padding: 3px; margin-top: 15px; }
```

将此保存在`css`文件夹中为`tooltipEvents.css`。不要忘记从页面的`<head>`中链接到新样式表（在链接到标准 jQuery UI 样式表之后）：

```js
<link rel="stylesheet" href="css/tooltipEvents.css">
```

如果我们在浏览器中预览结果，然后几次移动到提示链接上。我们可以开始看到历史记录的建立，如此屏幕截图所示：

![处理提示事件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_19B.jpg)

在这个示例中，我们同时使用了`open`和`close`回调，尽管对于也可以由提示触发的创建自定义事件，原理是相同的。回调函数的名称作为我们配置对象中`open`和`close`属性的值提供。

当我们定义的回调函数被执行时，小部件将自动传递两个参数给它们。这些是原始的`event`对象和包含有用的属性的自定义`ui`对象，来自显示的提示。

## 绑定到提示事件

使用每个组件公开的事件回调是处理交互的标准方式。但是，除了上一个表格中列出的回调之外，我们还可以研究另一组在不同时间由每个组件触发的事件。

我们可以使用标准的 jQuery `on()` 方法来将事件处理程序绑定到由 Tooltip 小部件触发的自定义事件上，方式与我们可以绑定到标准 DOM 事件（例如点击）相同。

以下表格列出了 Tooltip 小部件的自定义绑定事件及其触发器：

| 事件 | 当...时触发 |
| --- | --- |
| `tooltipcreate` | 提示已创建 |
| `tooltipopen` | 工具提示显示或在`focusin`或`mouseover`上触发 |
| `tooltipclose` | 工具提示关闭或在`focusout`或`mouseleave`上触发 |

第一个事件在工具提示创建后立即触发；剩下的两个事件取决于工具提示是否已获得焦点。

让我们看看此类事件如何运作；将`tooltip13.html`中的最后一个`<script>`元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
    $("#tooltip").tooltip();
    $("#tooltip").on("tooltipopen", function(event, ui) {
      $("#console").append("Tooltip activated" + "<br>");
    })

    $("#tooltip").on("tooltipclose", function(event, ui) {
      $("#console").append("Tooltip closed" + "<br>");
    })
  });  
</script>
```

将此更改保存为`tooltip14.html`。以这种方式绑定到`tooltipopen`和`tooltipclose`事件处理程序，会产生与上一个示例中使用`open`和`close`回调函数相同的结果。与上次一样，每次将鼠标悬停在文本中的工具提示上时，控制台日志都应更新。

所有部件公开的所有事件都可以使用`on()`方法，只需在事件的名称前加上部件的名称即可。

# 播放视频

到目前为止，我们已经涵盖了大量关于使用 jQuery UI 的工具提示的理论；在这个例子和下一个例子中，我们将看看一些实用的工具提示的实际用法，您可以将其用作您自己项目的起点。在继续之前，请确保您可以获得代码下载的副本，因为我们将在本练习中使用其中的文件。

工具提示的一种可能用法是模仿您可能在社交媒体网站上找到的喜欢或不喜欢按钮，例如 YouTube，在那里您可以注册对您喜欢观看的视频的偏好。让我们看看您如何在自己的项目中复制此功能，但是使用我们在本书中到目前为止已经涵盖的一些其他 jQuery UI 部件和工具提示。

### 注意

此演示使用了来自开源项目*The Big Buck Bunny*的视频，该项目由*Blender Foundation*创建，并可从[`www.bigbuckbunny.org`](http://www.bigbuckbunny.org)获取。

从代码下载中提取`tooltipVideo.js`的副本；这将提供将按钮和工具提示添加到视频底部的功能。不要忘记从我们页面的`<head>`中链接到新的 JavaScript 文件（在链接到 jQuery UI 按钮部件之后）：

```js
<script src="img/tooltipVideo.js"></script>
```

我们还需要在我们页面的`<head>`中添加对 Button 部件的引用：

```js
<script src="img/jquery.ui.button.js"></script>
```

接下来，更改`<body>`，使其包含以下元素：

```js
<div class="player">
  <video controls="controls">
      <source src="img/big_buck_bunny.mp4" />
      <source src="img/big_buck_bunny.webm" />
    </video>
  </div>
  <p>
  <div class="tools">
    <span class="set">
      <button data-icon="ui-icon-circle-arrow-n" title="I like this">Like</button>
      <button data-icon="ui-icon-circle-arrow-s">I dislike this</button>
    </span>
    <div class="set">
      <button data-icon="ui-icon-circle-plus" title="Add to Watch Later">Add to</button>
      <button class="menu" data-icon="ui-icon-triangle-1-s">Add to favorites or playlist</button>
    </div
    <button title="Share this video">Share</button>
    <button data-icon="ui-icon-alert">Flag as inappropiate</button>
</div>

```

最后但同样重要的是，我们还需要添加一些样式，以确保工具提示正确显示。将以下内容添加到文本编辑器中的新文档中：

```js
.player { width: 642px; height: 362px; border: 2px groove gray; background: rgb(200, 200, 200); text-align: center; line-height: 300px; }
.ui-tooltip { border: 1px solid white; background: rgba(20, 20, 20, 1); color: white; }
.set { display: inline-block; }
.notification { position: absolute; display: inline-block; font-size: 2em; padding: .5em; box-shadow: 2px 2px 5px -2px rgba(0,0,0,0.5); }
```

将此文件保存为`tooltipVideo.css`，放入`css`文件夹中 - 不要忘记从主文档中添加一个链接，紧跟在链接到 jQuery UI 样式表之后：

```js
<link rel="stylesheet" href="css/tooltipVideo.css">
```

将您修改后的页面保存为`tooltip15.html`。以下截图显示了在浏览器中预览视频时页面的外观：

![播放视频](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_20.jpg)

以这种方式使用按钮允许我们向我们的站点添加一些真正强大的功能。在我们的示例中，按钮实际上并不执行任何操作（除了显示工具提示），但在现实生活中，它们将用于维护观看视频并希望注册对其喜欢（或不喜欢）的人的运行总数。

# 填写和验证表单

本章中，我们已经涵盖了很多关于如何实现工具提示，并根据我们的需求配置它们在我们网站中的用法。然而，我们不能在没有对站点的最重要（或常见？）用途之一 - 表单验证进行检查的情况下结束本章。

我相信多年来，你很可能在网上填写过表格；也许是作为购买某物的一部分，并且在填写过程中犯过错误。工具提示的美妙之处在于我们可以利用它们向访问者提供反馈，以确保他们正确填写字段，并且不会向您的表单输入无效值。

在您的文本编辑器中，按照下面的代码更改`tooltip14.html`的最终`<script>`块：

```js
$(document).ready(function($){
  $("button").button();
  var $tooltips = $('#signup [title]').tooltip({
    position: { my: "left+15 center", at: "right center" }
  });
  $("#open").on('click', function() {
    $tooltips.tooltip('open');
  });
  $("#close").on('click', function() {
    $tooltips.tooltip('close');
  });
});
```

由于在本示例中我们使用了 JQuery UI 的 Button 小部件，所以我们需要在 jQuery UI 库中添加一个到该小部件的链接：

```js
<script src="img/jquery.ui.button.js"></script>
```

接下来，我们需要添加我们表单的标记 - 删除现有标记，并用以下标记替换它：

```js
<form id="signup">
  <fieldset>
    <legend>Sign Up Now</legend>   
    <div>        
      <label for="username">Username:</label>
      <input type="text" name="username" id="username" title="User name must be between 8 and 32 characters."><br>
    </div>
    <div>
      <label for="password">Password:</label>
      <input type="password" name="password" title="Password must contain at least one number.">
    </div>
    <div>
      <label for="password2">Confirm Password:</label>
      <input type="password" name="password2" title="Please re-type your password for confirmation.">
    </div>
  </fieldset>
</form>
  <button id="open">Open Help</button>
  <button id="close">Close Help</button>
```

将其保存为`tooltip16.html`。我们还需要一些 CSS 来完成这个示例。在我们刚创建的页面的`<head>`中，添加以下`<link>`元素：

```js
<link rel="stylesheet" href="css/tooltipForm.css">
```

然后在您的文本编辑器中添加一个新页面，加入以下代码：

```js
body { font-family: verdana, sans-serif; width: 430px; }
label { display: inline-block; width: 11em; }
button { float: right; margin: 2px; }
fieldset { width: 400px; border: 3px solid black; border-radius: 4px; margin: 3px; border-color: #7c96a9; font-size: 1.1em;}
fieldset div { margin-bottom: 1.2em; }
fieldset .help { display: inline-block; }
.ui-tooltip { width: 300px; font-size: 0.7em; }
```

将其保存为`tooltipForm.css`在`css`文件夹中。如果我们在浏览器中预览页面，您将看到在悬停在它们上方时每个工具提示都会出现，或者当点击**打开帮助**按钮时它们都会显示，如下面的截图所示：

![填写和验证表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_10_21.jpg)

在本示例中，我们已将 jQuery UI 设置为显示每个字段的`[title]`属性上的工具提示。然而，由于我们将工具提示方法处理程序分配给了`$tooltips`变量，我们能够使用它来为每个按钮创建一个点击处理程序，根据按下的按钮是哪个来显示或隐藏所有工具提示。当发生错误时，我们还可以向用户显示消息；例如，如果密码输入错误，我们可以使用输入字段的`blur`事件处理程序在屏幕上打开一个工具提示。

# 总结

哎呀！对于这样一个小小的小部件，我们确实涵盖了很多内容！

工具提示小部件是传达短信息的绝佳方式，比如错误或警报，可以甚至用它作为迷你帮助系统；让我们回顾一下本章讨论的内容。

我们首先看了一下，只需一点基础的 HTML 和一行 jQuery 风格的 JavaScript，我们就可以实现默认的提示小部件。然后，我们看到了通过使用预设计的 ThemeRoller 主题或我们自己的主题，轻松地为提示小部件设置样式的方法；这样它的外观就会改变，但行为不会改变。

然后，我们继续，看了一下提示小部件 API 暴露的一系列可配置选项，以及如何使用这些选项来控制小部件提供的选项。在可配置选项之后，我们介绍了一些方法，我们可以使用这些方法来以编程方式使提示小部件执行不同的操作，比如启用或禁用特定的提示。

我们简要地看了一下提示小部件支持的一些更复杂的功能，比如基于 AJAX 的提示，以及为表单提供上下文。这两种技术都很容易使用，并且可以为任何实现增加价值。

我们现在已经完成了 UI 小部件的探索，所以让我们将注意力转向库中可用的一些交互，从拖动小部件开始。


# 第十一章：拖拽功能

到目前为止，在本书中，我们已经涵盖了完全发布的完整范围的界面小部件，并在接下来的四章中，我们将把重点转向核心交互辅助工具。这些是为小部件提供基于鼠标的交互的小部件，我们可以在网站上执行选择、拖动或调整小部件等操作。一个完美的例子是可调整大小的小部件，我们将在第十二章中进行讨论，*可调整大小的组件*。这些库的交互组件与我们已经查看过的组件不同，因为它们不是页面上存在的物理对象或小部件。

这些是低级交互组件，与本书第一部分我们查看的高级小部件相对。它们帮助您页面上使用的元素更具吸引力和互动性，为您的访问者增添价值，可以帮助使您的 Web 应用程序看起来更专业。它们还有助于模糊浏览器和桌面之间的区别，提供更大的可用性，使 Web 应用程序更加高效、有效和自然。

在本章中，我们将讨论两个非常相关的组件—**可拖动**和**可放置物品**。可拖动的 API 将任何指定的元素转换为您的访问者可以用鼠标指针拾起并在页面上拖动的东西。公开的方法允许您限制拖动物品的移动，使其在放下后返回到起始点，以及更多功能。

在本章中，我们将介绍以下主题：

+   如何使元素可拖动

+   可配置可拖动对象的选项

+   如何使一个元素在拖动结束后返回到起始点

+   如何在交互的不同点使用事件回调

+   拖动助手的作用

+   包含可拖动物品

+   如何使用组件的方法控制可拖动性

+   将元素转换为放置目标

+   定义接受的可拖动物品

+   使用可放置类名

+   定义放置容忍度

+   对可拖动物品和可放置物品之间的交互做出反应

可放置的 API 允许您定义页面的区域或某种容器，使人们可以将可拖动物品拖放到其中以触发其他操作，例如，将产品添加到购物篮中。可放置小部件触发的一系列事件让我们对任何拖动交互的最有趣时刻做出反应。

# 处理可拖动和可放置物品的交易

拖放行为总是相辅相成。一个找到，另一个总是附近。在网页上拖曳元素是非常不错的，但如果没有地方可以将该元素拖拽到，那么整个操作通常是没有意义的。

您可以独立使用`draggable`类，而不使用`droppable`类，因为纯粹的拖动可能会有其用途，例如对话框组件。但是，您不能在没有`draggable`类的情况下使用`droppable`类。当然，您不需要使用任何可拖动的方法，但是没有任何东西可放置在其上的可拖放对象是毫无价值的。

与小部件一样，显然可以将一些交互帮助程序组合起来；拖动和放置显然是一起的。但是，拖动器还可以与可排序的一起使用，正如我们将在第十三章所见，*使用 jQuery UI 进行选择和排序*，以及可调整大小的内容。

# 使用可拖拽小部件入门

可拖拽组件用于使任何指定的元素或元素集合可拖动，以便访问者可以将它们拾取并在页面上移动。可拖拽性是一个很棒的效果，是一个可以以多种方式用于改进网页界面的功能。

使用 jQuery UI 意味着我们不必担心最初使网页上的可拖动元素实现和维护成为一场噩梦的各种棘手的浏览器之间的差异。

## 实现基本拖动

让我们通过首先使简单的`<div>`元素可拖动来查看默认实现。我们不会进行任何其他配置。因此，此代码将允许您使用鼠标指针拾取元素并在视口周围拖动它。

在文本编辑器中的新文件中添加以下代码：

```js
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="utf-8">
    <title>Draggable</title>
    <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
    <link rel="stylesheet" href="css/autocompleteTheme.css">
    <script src="img/jquery-2.0.3.js"></script>
    <script src="img/jquery.ui.core.js"></script>
    <script src="img/jquery.ui.widget.js"></script>
    <script src="img/jquery.ui.mouse.js"></script>
    <script src="img/jquery.ui.draggable.js "></script>
    <script>
      $(document).ready(function($){
        $("#drag").draggable();
      });
    </script> 
  </head>
  <body>
    <div id="drag"></div>
  </body>
</html>
```

将此保存为`draggable1.html`文件到您的`jqueryui`文件夹中。与 jQuery UI 的基于小部件的组件一样，可以使用一行代码启用可拖拽组件。这会调用可拖拽的构造方法：`draggable`，并将指定的元素转换为拖动对象。

我们需要从库中获取以下文件，以在元素上启用可拖拽性：

+   `jquery-2.0.3.js`

+   `jquery.ui.core.js`

+   `jquery.ui.widget.js`

+   `jquery.ui.mouse.js`

+   `jquery.ui.draggable.js`

我们正在使用在页面的`<head>`标签中链接到的 CSS 文件中指定的带背景图像的普通`<div>`元素。使用以下样式表作为拖动元素：

```js
#drag { width: 114px; height: 114px; cursor: move; background: url(../img/draggable.png) no-repeat; }
```

将此保存为`draggable.css`文件到`css`文件夹中。当您在浏览器中查看页面时，您将看到图像可以在可拖动区域内移动，如以下屏幕截图所示：

![实现基本拖动](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_11_01.jpg)

# 配置可拖拽选项

可拖拽组件具有广泛的可配置选项，使我们对其添加的行为具有非常细微的控制。以下表格列出了我们可以操作以配置和控制我们的拖动元素的选项：

| 选项 | 默认值 | 用途 |
| --- | --- | --- |
| `addClasses` | `true` | 向拖动对象添加`ui-draggable`类。将其设置为`false`以防止添加此类。 |
| `appendTo` | `"parent"` | 为带有附加辅助元素的拖动对象指定容器元素。 |
| `axis` | `false` | 将拖动对象约束于一个运动轴。接受字符串`x`和`y`作为值，或者布尔值`false`。 |
| `cancel` | `":input, option"` | 防止匹配指定元素选择器的某些元素被拖动。 |
| `connectToSortable` | `false` | 允许将拖动对象放置到可排序列表中并成为排序元素之一。 |
| `containment` | `false` | 防止拖动对象被拖出其父元素的边界。 |
| `cursor` | `"auto"` | 指定指针在拖动对象上时使用的 CSS 光标。 |
| `cursorAt` | `false` | 指定拖动对象在拖动时相对于拖动对象出现的默认位置。 |
| `delay` | `0` | 指定延迟拖动交互开始的时间（以毫秒为单位）。 |
| `disabled` | `false` | 禁用可拖动的拖动对象。 |
| `distance` | `1` | 指定在鼠标按钮按住拖动对象时指针应该移动的像素距离，以便开始拖动。 |
| `grid` | `false` | 使拖动对象吸附到页面上的虚拟网格。接受包含网格的`x`和`y`像素值的数组。 |
| `handle` | `false` | 定义用于保持指针以便拖动的拖动对象的特定区域。 |
| `helper` | `"original"` | 定义一个伪拖动元素，该元素代替拖动对象进行拖动。可以接受字符串值 original 或 clone，也可以接受返回辅助元素的函数。 |
| `iframeFix` | `false` | 在拖动进行时阻止页面上的所有`<iframe>`元素捕获鼠标事件。 |
| `opacity` | `false` | 设置辅助元素的不透明度。 |
| `refreshPositions` | `false` | 在拖动进行中计算所有放置对象的位置。 |
| `revert` | `false` | 将拖动对象设置为`true`时，拖动对象在拖动结束时返回其起始位置。还可以接受 valid 和 invalid 字符串，其中 revert 仅在拖动对象放置在有效的放置对象上，或者反之亦然时应用。 |
| `revertDuration` | `500` | 拖动对象返回到其起始位置所需的毫秒数。 |
| `scope` | `"default"` | 设置拖动对象相对于对其有效的放置对象的范围。 |
| `scroll` | `true` | 在拖动对象移动到视口边缘的阈值内时，使视口自动滚动。 |
| `scrollSensitivity` | `20` | 定义拖动对象在接近视口边缘多少像素之前开始滚动。 |
| `scrollSpeed` | `20` | 设置视口滚动的速度。 |
| `snap` | `false` | 导致拖动对象捕捉到指定元素的边缘。 |
| `snapMode` | `"both"` | 指定拖动对象将对元素的哪些边缘进行捕捉。可以设置为`inside`、`outside`或`both`。 |
| `snapTolerance` | `20` | 设置拖动对象应达到的与捕捉元素的距离，之后才会发生捕捉。 |
| `stack` | `false` | 确保当前拖动对象始终位于同一组中其他拖动对象的顶部。接受包含`group`和/或`min`属性的对象。 |
| `zIndex` | `false` | 设置助手元素的`zIndex`。 |

## 使用配置选项

让我们将其中一些选项投入使用。它们可以以与我们在之前章节中看到的小部件暴露的选项完全相同的方式进行配置，并且通常具有获取器和设置器模式。

在刚才的第一个示例中，我们使用 CSS 指定当指针悬停在可拖动的`<div>`上时应使用移动光标。让我们改变一下，改为使用拖动组件的`cursor`选项。

从 draggable.css 中删除`cursor: move`，并重新保存为`draggableNoCursor .css`。同时将`draggable1.html`中的`<link>`标签更改为引用新文件：

```js
<link rel="stylesheet" href="css/draggableNoCursor.css">
```

然后将最后一个`<script>`元素更改为以下内容：

```js
<script>
 $(document).ready(function($){
 $("#drag").draggable({
 cursor: "move"
 });
 });
</script>
```

将此保存为`draggable2.html`，在浏览器中尝试一下。关于此选项的一个重要注意事项是，我们指定的移动光标直到实际开始拖动才会应用。在使用此选项替代简单 CSS 时，也许应该提供一些其他的视觉提示，表明元素是可拖动的。

让我们看看可拖动组件的许多配置选项中的更多。将`draggable2.html`中的配置对象更改为以下内容：

```js
$("#drag").draggable({
 cursor: "move",
 axis: "y",
 distance: "30",
 cursorAt: { top: 0, left: 0 }
});
```

可以将此保存为`draggable3.html`。我们配置的第一个新选项是`axis`选项，这个选项限制了可拖动元素只能在页面上向上或向下移动，而不能横跨页面从一侧到另一侧。

接下来，我们已将`distance`选项的值指定为`30`。这意味着在按住鼠标按钮的情况下，光标必须横穿拖动对象`30`像素，拖动才会开始。

最终的选项`cursorAt`是使用对象文字配置的，其属性可以是`top`、`right`、`bottom`或`left`。我们选择使用的属性所提供的值是光标在进行拖动时在拖动对象相对于的数值。

然而，您会注意到在此示例中，`left`选项的值似乎被忽略了。这是因为我们已经配置了`axis`选项。当我们开始拖动时，拖动对象将自动移动，以使光标距元素顶部`0`像素，但它不会移动，以使光标距离左侧边缘`0`像素，因为我们已经指定了拖动对象不能向左移动。

让我们看看一些可拖动选项的更多实际操作。更改 `draggable3.html`，使配置对象如下所示：

```js
$("#drag").draggable({
 delay: 500,
 grid: [100,100]
});
```

将文件保存为 `draggable4.html`。`delay` 选项接受以毫秒为单位的值，指定必须将鼠标按钮保持在拖动对象上的时间长度，然后才能开始拖动。

`grid` 选项的用法类似于滑块小部件的 `steps` 选项。它使用一个表示拖动元素在每个 `axis` 上应跳跃的像素数的数组进行配置。此选项可以安全地与 `axis` 选项一起使用。

## 重置拖动的元素

非常容易配置拖动对象，使其在放置后返回到其原始起始位置，并且有几个选项可用于控制此行为。更改我们用于 `draggable4.html` 的配置对象，使其如下所示：

```js
$("#drag").draggable({
 revert: true
});
```

将此文件保存为 `draggable5.html`。通过将 `revert` 选项的值设置为 `true`，我们导致拖动对象在任何拖动交互结束时返回到其起始位置。但是，您会注意到拖动元素不会立即弹回其起始位置。相反，它会平滑地动画返回，无需额外的配置。

另一个与恢复相关的选项是 `revertDuration` 选项，我们可以使用它来控制恢复动画的速度。更改 `draggable5.html` 中的配置对象，使其如下所示：

```js
$("#drag").draggable({
 revert: true,
 revertDuration: 100
});
```

将此文件保存为 `draggable6.html`。`revertDuration` 选项的默认值是 `500` 毫秒，因此将其降低到 `100`，动画的相对速度大大增加。

动画的实际速度将根据从放置点到起点的距离实时确定。`revertDuration` 选项只是定义了动画长度的目标时间。

## 添加拖动句柄支持

`handle` 选项允许我们定义可以用于拖动对象的拖动区域。不能使用其他区域来拖动对象。一个简单的类比是 `dialog` 小部件。只有在标题栏上点击并按住时，才能拖动对话框。标题栏是拖动句柄。

在以下示例中，我们将为拖动对象添加一个简单的拖动句柄。在拖动元素内部放置一个新的空 `<div>` 元素：

```js
<div id="drag">
  <div id="handle"></div>
</div>
```

然后，将配置对象更改为以下内容：

```js
$("#drag").draggable({
 handle: "#handle"
});
```

将此文件保存为 `draggable7.html`。我们给新的 `<div>` 加了一个 `id` 属性，然后在配置对象中将此 `id` 指定为 `handle` 选项的值。

句柄使用几个简单的样式规则进行样式化。将以下新样式添加到 `draggableNoCursor.css`：

```js
#handle {
  width:30px; height:30px; border-bottom:2px solid #ff0000;
  border-left:2px solid #ff0000; position:absolute;
  right:10px; top:10px; cursor:move;
}
```

将此文件保存为 `dragHandle.css` 在 `css` 文件夹中。不要忘记从 `draggable7.html` 的 `<head>` 部分链接到新样式表：

```js
<link rel="stylesheet" href="css/dragHandle.css">
```

当我们在浏览器中预览页面时，我们看到原始拖动对象仍然可拖动，但仅当使用指针选择手柄时才可见，如下截图所示：

![添加拖动手柄支持](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_11_02.jpg)

## 添加助手元素

几个配置选项与拖动助手直接相关。助手是一个替代元素，用于在拖动进行中显示对象在屏幕上的位置，而不是移动实际可拖动的元素。

助手可以是实际拖动对象的非常简单的对象。它可以帮助减少拖动操作的强度，减轻访问者处理器的负载。拖动完成后，实际元素可以移动到新位置。

让我们看看助手如何在以下示例中使用。删除我们用于`handle`的`<div>`元素，并恢复到`draggable7.html`中的`draggable.css`样式表，然后将配置对象更改为以下内容：

```js
$("#drag").draggable({
 helper: "clone"
});
```

将此文件保存为`draggable8.html`。我们还需要调整 CSS，以便在适当的时候更改光标以指示我们正在移动图像。如下更改`draggable.css`中的 CSS：

```js
#drag, .ui-draggable { width: 114px; height: 114px; background: url(../img/draggable.png) no-repeat; }
.ui-draggable-dragging { cursor: move; }
```

对于`helper`选项的值`clone`会创建原始拖动对象的精确副本，并将其用作可拖动对象。因此，原始对象始终保持在其起始位置。这也会导致`clone`对象恢复到其起始位置，即使通过提供`false`作为`revert`选项的值也无法更改此效果。以下截图显示了`clone`选项的效果：

![添加助手元素](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_11_03.jpg)

除了字符串`clone`和默认的`original`之外，我们还可以使用函数作为此选项的值。这使我们能够指定我们自己的自定义元素用作助手。

将`draggable8.html`中的最终`<script>`元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
 function helperMaker() {
 return $("<div />", {
 css: {
 border: "4px solid #ccc",
 opacity: 0.5,
 height: 110,
 width: 120
 }
 });
 } 
 $("#drag").draggable({
 helper: helperMaker
 });
  });
</script>
```

将此文件保存为`draggable9.html`。我们的`helperMaker()`函数使用标准的 jQuery 功能创建一个新的`<div>`元素，然后在其上设置一些 CSS 属性以定义其外观。然后，重要的是返回新元素。在将函数作为`helper`选项的值时，该函数必须返回一个元素（可以是 jQuery 对象，如本例中，也可以是实际的 DOMNode）。

现在当拖动开始时，我们的自定义助手成为拖动对象。由于自定义元素比原始拖动对象简单得多，因此可以帮助改善所使用的应用程序的响应性和性能。

### 提示

确保在使用助手（克隆）元素时使用具有类而不是 ID 的元素，因为 ID 在 DOM 中必须是唯一的，并且克隆将其复制。

以下截图显示了我们的自定义助手：

![添加助手元素](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_11_04.jpg)

### 提示

**助手不透明度**

我们在创建自定义助手时在本示例中使用了 `css` jQuery 方法。但是，我们还可以使用拖动对象的 `opacity` 选项来设置助手元素的不透明度，作为跨平台解决方案。

## 限制拖动

拖动场景的另一个方面是 containment（包含性）。到目前为止，我们的示例中，页面的`<body>`元素一直是拖动对象的容器。我们还可以配置选项，以指定拖动对象在与另一个容器元素相关时的行为。

我们将在接下来的示例中查看这些内容，从`containment`选项开始，该选项允许我们为拖动对象指定一个容器元素。在`draggable9.html`的`<head>`标签中，添加以下链接到我们在本示例中将使用的样式表：

```js
<link rel="stylesheet" href="css/draggableContainer.css">
```

然后将拖动元素包装在一个容器 `<div>` 中，如下所示：

```js
<div id="container">
  <div id="drag"></div>
</div>
```

然后将配置对象更改为以下内容：

```js
$("#drag").draggable({
 containment: "parent"
});
```

将此变体保存为 `draggable10.html`。在页面上，我们添加了一个新的 `<div>` 元素作为现有拖动元素的父级。在代码中，我们使用了 `containment` 选项的值 `parent`，因此直接父级拖动对象的元素（在本示例中是具有 `id` 为 `container` 的 `<div>` 元素）将被用作容器。

父级 `<div>` 需要一些基本样式以给它尺寸，并且可以在页面上看到。将以下代码添加到 `draggable.css` 中，并将文件另存为 `draggableContainer.css`。记住，这个字符串不是元素的 `id` 或 jQuery 选择器（尽管选择器也受支持）。

```js
#container { height: 250px; width: 250px; border: 2px solid #ff0000; }
```

当你在浏览器中运行页面时，你会发现拖动对象不能超出其容器的边界。

除了我们在本示例中使用的字符串 `parent` 外，我们还可以指定一个选择器，例如：

```js
$("#drag").draggable({
 containment: "#container"
});
```

有三个与容器内拖动对象相关的额外选项，这些选项都与滚动相关。但是，你应该注意，这些选项仅适用于文档是容器时。

`scroll` 选项的默认值是 `true`，但是当我们将 `<div>` 元素拖动到容器的边缘时，它不会滚动。你可能已经注意到在以前的示例中，拖动对象没有在指定的容器内时，视口会自动滚动。如果需要，我们可以通过在样式表中设置 CSS `overflow` 样式为 `auto` 来解决这个问题。

## 吸附

通过配置吸附，可以赋予拖动元素几乎磁性的特性。此功能会导致拖动的元素在拖动过程中与指定的元素对齐。

在下一个示例中，我们将查看吸附对拖动对象行为的影响。删除我们在前一个示例中添加的容器，并直接在拖动元素之后添加一个新的空 `<div>` 元素，如下所示：

```js
<div id="drag"></div>
<div id="snapper"></div>

```

然后，将配置对象更改为以下内容：

```js
$("#drag").draggable({
 snap: "#snapper",
 snapMode: "inner",
 snapTolerance: 50
});
```

把这个保存为`draggable11.html`。我们还需要一些额外的样式；在`draggable.css`底部添加以下代码：

```js
#snapper {
  width: 300px; height: 300px; border: 1px solid #ff0000;
}
```

把这个文件保存为`draggableSnap.css`，放在`css`目录下。别忘了在页面的`<head>`元素中添加一个指向新样式表的链接：

```js
<link rel="stylesheet" href="css/draggableSnap.css">
```

我们在配置对象中将`snap`选项的值设为`#snapper`选择器，同时在页面中添加了一个匹配的`<div>`元素和一个相同的`id`。因此，在拖动对象时，我们的拖动对象将会吸附到页面上的这个元素。

我们还将`snapMode`选项设置为`inner`（其他可能的值为`outer`和`both`），因此吸附将发生在我们的`snapper`元素的内部边缘上。如果我们将元素拖向`snapper`元素的外边缘，并在容差范围内，元素将会吸附到内边缘。

最后，我们将`snapTolerance`设置为`50`，这是拖动对象在吸附到`snapper`元素之前的最大距离（以像素为单位）。一旦拖动对象位于此范围内，它就会吸附到该元素。

当我们将图像拖动到`snapper`元素边缘的`50`像素范围内时，拖动对象会自动对齐到该边缘，如下截图所示：

![吸附](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_11_05.jpg)

# 可拖动事件回调

除了我们已经看过的选项外，还有三个可以用作回调函数的选项，以在特定的自定义事件发生后执行代码。

这些事件列在下表中：

| 事件 | 当…时触发 |
| --- | --- |
| `drag` | 拖动时鼠标移动 |
| `start` | 拖动开始 |
| `stop` | 拖动停止 |

在定义回调函数以利用这些事件时，函数将始终自动接收两个参数：第一个参数是原始事件对象，第二个对象包含以下属性：

| 属性 | 用途 |
| --- | --- |
| `helper` | 一个代表助手元素的 jQuery 对象。 |
| `position` | 一个包含属性 `top` 和 `left` 的嵌套对象，表示助手元素相对于原始拖动元素的位置。 |
| `offset` | 一个包含属性 `top` 和 `left` 的嵌套对象，表示助手元素相对于页面的位置。 |

使用回调函数和传递的两个对象非常容易。我们可以看一个简单的示例来突出它们的用法。在`draggable11.html`中删除吸附器`<div>`，并将配置对象更改如下：

```js
$("#drag").draggable({
 start: function(e, ui) {
 ui.helper.addClass("up");
 },
 stop: function(e, ui) {
 ui.helper.removeClass("up");
 }
});
```

把这个保存为`draggable12.html`。我们还需要一个新的样式表作为示例；在`draggable.css`中添加以下代码：

```js
#drag.up {
  width: 120px; height: 121px;
  background: url(../img/draggable_on.png) no-repeat;
}
```

把这个版本的样式表保存为`draggableEvents.css`，放在`css`目录下，并且别忘了更新页面`<head>`元素中的链接指向新样式表。

在本示例中，我们的配置对象仅包含两个选项——`start` 和 `stop` 回调函数。我们将文字函数作为这些选项的值。在此示例中，所有函数的功能都是分别添加或删除类名。

类名添加了一个稍微不同的背景图片到可拖动元素，当应用时，效果如下所示的前后截图：

![可拖动事件回调](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_11_06.jpg)

让我们继续进行稍微复杂一点的示例，其中我们可以利用传递给我们回调函数的第二个对象。我们需要页面上的一些新元素；更改页面的 `<body>` 元素，以使其包含以下元素：

```js
<div id="container">
  <div id="drag"></div>
</div>
<div id="results"></div>

```

然后更改最后的 `<script>` 元素，使其如下所示：

```js
<script>
  $(document).ready(function($){
    $("#drag").draggable({
      stop: function(e, ui) {
        var rel = $("<p />", {
          text: "The helper was moved " + ui.position.top +  
          "px down, and " + ui.position.left + "px to the 
          left of its original position."
        }),
        offset = $("<p />", {
          text: "The helper was moved " + ui.offset.top + "px 
          from the top, and " + ui.offset.left + "px to the 
          left relative to the viewport."
        });
        $("#results").empty().append(rel).append(offset);
      }
    });
  });
</script>
```

将此保存为 `draggable13.html`。我们已将回调函数定义为 `stop` 选项的值，因此每次拖动交互停止时都会执行它。我们的回调函数接收事件对象（我们不需要，但必须指定以便访问第二个对象）和包含有关可拖动助手的有用信息的 `ui` 对象。

我们的函数所需做的就是创建两个新的 `<p>` 元素，将 `ui` 对象中找到的值连接起来：`ui.position.top`、`ui.position.left`、`ui.offset.top` 和 `ui.offset.left`。然后，将新元素插入到结果 `<div>` 中。

在可拖动元素被拖动后，页面应该是这样的：

![可拖动事件回调](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_11_07.jpg)

# 可拖动的方法

可拖动交互助手本身不公开任何独特的方法，只公开了常用的 API 方法，这些方法是 `destroy`、`disable`、`enable`、`option` 和 `widget`。

# 开始使用 droppable 小部件

简而言之，jQuery UI 的 droppables 组件给了我们一个放置拖动对象的地方。页面的一个区域被定义为可放置的区域，当一个拖动对象被放置到该区域时，会触发其他事件。您可以通过该组件提供的广泛事件模型非常容易地对有效目标的放置做出反应。

让我们从默认的 droppable 实现开始。在文本编辑器中的新文件中，添加以下页面：

```js
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="utf-8">
    <title>Droppable</title>
    <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
    <link rel="stylesheet" href="css/droppable.css">
    <script src="img/jquery-2.0.3.js"></script>
    <script src="img/jquery.ui.core.js"></script>
    <script src="img/jquery.ui.widget.js"></script>
    <script src="img/jquery.ui.mouse.js"></script>
    <script src="img/jquery.ui.draggable.js"></script>
    <script src="img/jquery.ui.droppable.js"></script>
    <script>
       $(document).ready(function($){
       $("#drag").draggable();
       $("#target").droppable();
      });
    </script>
  </head>
  <body>
    <div id="drag"></div>
    <div id="target"></div>
  </body>
</html>
```

将此保存为 `droppable1.html`。在本示例中链接的极其基本的样式表只是 `draggable.css` 的更新版本，如下所示：

```js
#drag { width:114px; height:114px; margin-bottom:5px; z-index:2; cursor:move; background:url(../img/draggable.png) no-repeat; }
#target { width:200px; height:200px; border:3px solid #000;
position:absolute; right:20px; top:20px; z-index:1; }
```

将其保存为 `droppable.css` 在 `css` 文件夹中。当页面在浏览器中运行时，它应该看起来像以下的截图：

![开始使用 droppable 小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_11_08.jpg)

在本示例中，droppable 被创建；我们可以看到这一点，因为在页面加载时将类名 `ui-droppable` 添加到指定的元素中。

虽然我们尚未向脚本添加任何额外的逻辑，但在交互过程中，事件会在拖动对象和放置目标上触发。在本章稍后的部分，我们将更详细地查看这些事件，以了解如何钩入它们，以便对成功的放置做出反应。

我们用于这个基本可放置实现的文件如下：

+   `jquery-2.0.3.js`

+   `jquery.ui.core.js`

+   `jquery.ui.widget.js`

+   `jquery.ui.mouse.js`

+   `jquery.ui.draggable.js`

+   `jquery.ui.droppable.js`

如您所见，可放置组件是拖动组件的扩展，而不是完全独立的组件。因此，除了其自身的源文件外，它还需要`jquery.ui.draggable.js`文件。我们的可放置对象无所作为的原因是因为我们尚未配置它，所以让我们接下来做这件事。

# 配置可放置对象

`droppable`类比`draggable`类要小得多，并且我们可以玩耍的可配置选项较少。以下表格列出了我们可以使用的这些选项：

| 选项 | 默认值 | 用于… |
| --- | --- | --- |
| `accept` | `"*"` | 设置可放置对象将接受的可拖动元素。 |
| `activeClass` | `false` | 设置应用于可放置对象的类，当接受的拖动对象正在被拖动时。 |
| `addClasses` | `true` | 向可放置对象添加`ui-droppable`类。 |
| `disabled` | `false` | 禁用可放置对象。 |
| `greedy` | `false` | 当拖动对象被放置在嵌套的可放置对象上时，停止放置事件冒泡。 |
| `hoverClass` | `false` | 设置应用于可放置对象的类，当接受的拖动对象在可放置对象的边界内时。 |
| `scope` | `"default"` | 定义拖动对象和放置目标的集合。 |
| `tolerance` | `"intersect"` | 设置触发接受拖动对象被认为在可放置对象上的模式。 |

## 配置已接受的可拖动元素

为了从可放置对象中获得可见的结果，我们将在以下示例中一起使用一些可配置选项，当与接受的拖动对象交互时，它们将突出显示放置目标。修改页面中的元素`droppable1.html`，使其如下所示：

```js
<div class="drag" id="drag1"></div>
<div class="drag" id="drag2"></div>
<div id="target"></div>
```

接下来，将最后的`<script>`元素更改为以下内容：

```js
<script>
 $(document).ready(function($){
 $(".drag").draggable();
 $("#target").droppable({
 accept: "#drag1",
 activeClass: "activated"
 });
  });
</script> 
```

将此保存为`droppable2.html`。`accept`选项接受选择器。在本例中，我们指定只有具有`id`为`drag1`的拖动对象应被可放置对象接受。

我们还指定了激活的类名作为`activeClass`选项的值。当接受的拖动对象开始被拖动时，此类名将被应用到可放置对象上。`hoverClass`选项可以以完全相同的方式使用，当接受的拖动对象位于可放置对象上时，添加样式。

对于这个示例，我们需要一个新的样式表；修改`droppable.css`使其如下所示：

```js
.drag { width: 114px; height: 114px; margin-bottom: 5px; z-index:2; 
cursor: move; background: url(../img/draggable.png) no-repeat; }
#target { width: 200px; height: 200px; border: 3px solid #000;
position: absolute; right: 20px; top: 20px; z-index: 1; }
.activated { border: 3px solid #339900; background-color: #fe2e2e;}

```

将此文件保存为`droppableActive.css`在`css`文件夹中，并在页面的`<head>`元素中链接到它：

```js
<link rel="stylesheet" href="css/droppableActive.css">
```

当我们在浏览器中查看此页面时，应该发现当我们移动第一个被定义为接受的拖动对象时，可放置区域会接收到`activated`类并变红。然而，当移动第二个拖动对象时，放置目标不会响应。以下截图显示了页面在第一个拖动对象被拖动到方块上方时的外观：

![配置接受的可拖动对象](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_11_09.jpg)

除了字符串值之外，`accept`选项还可以采用函数作为其值。该函数将针对页面上的每个拖动对象执行一次。函数必须返回`true`，表示接受拖动对象，或返回`false`表示不接受。

要查看`accept`选项的功能值，请将`droppable2.html`中的最终`<script>`元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
    $(".drag").draggable();
 function dragEnrol(el) {
 return (el.attr("id") === "drag1") ? true : false;
 }
 $("#target").droppable({
 accept: dragEnrol,
 activeClass: "activated"
      });
    });
  });
</script>
```

将此变体保存为`droppable3.html`。从表面上看，该页面与上一个示例中的工作方式完全相同。但是这次，可接受性是由`dragEnrol`函数中的 JavaScript 三元语句确定的，而不是简单的选择器。

### 注意

请注意，我们与`accept`选项一起使用的函数已自动将表示拖动对象的 jQuery 对象作为参数传递，因此我们可以在此对象上调用 jQuery 方法。这使得很容易获取有关其的信息，例如其`id`，就像这个示例中一样。当需要超出选择器的高级过滤时，此回调非常有用。

# 配置放置容差

放置容差指的是可放置区域检测拖动对象是否位于其上的方式。默认值为`intersect`。以下表格列出了此选项可以配置的模式：

| 模式 | 实现 |
| --- | --- |
| `fit` | 拖动对象必须完全位于可放置区域的边界内才能被视为在其上方。 |
| `intersect` | 在至少有 25%的拖动对象位于可放置区域边界内之前，它被视为在其上方。 |
| `pointer` | 拖动对象被视为位于可放置区域之上之前，鼠标指针必须触及可放置边界。 |
| `touch` | 只要拖动对象的边缘触碰到可放置区域的边缘，拖动对象就位于可放置区域上方。 |

到目前为止，我们所有的可放置示例都使用了 intersect，这是`tolerance`选项的默认值。让我们看看该选项的其他值对组件实现的影响。从`droppable2.html`中的相应元素中恢复到`#drag`和`#target`的 ID，然后使用以下配置对象：

```js
$("#target").droppable({
 hoverClass: "activated",
 tolerance: "pointer"
});
```

将此保存为`droppable4.html`。这次我们使用`hoverClass`选项来指定添加到可放置区域的类名。然后，我们使用`tolerance`选项来指定使用哪种容差模式。

在这个例子中，拖动对象的一部分位于可放置对象上是不相关的；在拖动进行时，必须越过可放置对象的边界，才会触发我们的 `activated` 类：

![配置放置容忍度](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_11_10.jpg)

# 理解可放置回调选项

到目前为止，我们已经查看了配置可放置对象的各种操作特性的选项。除了这些选项之外，还有几乎同样多的回调选项，这样我们就可以定义对可放置对象及其被接受的拖动对象发生不同事情的反应的函数。这些选项列在以下表中：

| 回调选项 | 被调用时… |
| --- | --- |
| `activate` | 一个被接受的拖动对象开始拖动。 |
| `deactivate` | 一个被接受的拖动对象停止被拖动。 |
| `drop` | 一个被接受的拖动对象被放置到可放置对象上。 |
| `out` | 一个被接受的拖动对象移出可放置对象的边界（包括容忍度）。 |
| `over` | 一个被接受的拖动对象在可放置对象的边界内（包括容忍度）移动。 |

让我们组合一个基本的示例，利用这些回调选项。我们将在我们的可放置对象上添加一个状态栏，报告拖动对象和可放置对象之间不同交互的状态。在 `droppable4.html` 中，在 `target` 元素之后直接添加以下新元素：

```js
<div id="status"></div>
```

然后，将最终的 `<script>` 元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
    $("#drag").draggable();
 $("#target").droppable({
 accept: "#drag",
 activate: eventCallback,
 deactivate: eventCallback,
 drop: eventCallback,
 out: eventCallback,
 over: eventCallback
 },
 eventMessages = {
 dropactivate: "A draggable is active",
 dropdeactivate: "A draggable is no longer active",
 drop: "An accepted draggable was dropped on the droppable",
 dropout: "An accepted draggable was moved off the droppable",
 dropover: "An accepted draggable is over the droppable"
 });
 function eventCallback(e) {
 var message = $("<p />", {
 id: "message",
 text: eventMessages[e.type]
 });
 $("#status").empty().append(message);
    }
  });
</script>
```

将此文件保存为 `droppable5.html`。我们还需要一些新的样式来进行这个示例。在文本编辑器中创建一个新的样式表，并添加以下选择器和规则：

```js
#drag { width: 114px; height: 114px; margin-bottom: 5px; z-index: 2; cursor: move; background: url(../img/draggable.png) no-repeat; }
#target { width: 250px; height: 200px; border: 3px solid #000; position: absolute; right: 20px; top: 20px; z-index: 1; }
#status { width: 230px; padding: 10px; border: 3px solid #000; position: absolute; top: 223px; right: 20px; color: #000; }
#message { margin: 0px; font-size: 80%; }
```

将此文件保存为 `droppableEvents.css`，放在 `css` 目录中。不要忘记更新页面 `<head>` 元素中的 `<link>`，指向新的样式表：

```js
<link rel="stylesheet" href="css/droppableEvents.css">
```

页面的 `<body>` 元素包含一个新的状态栏，以及可放置对象，在这种情况下是一个简单的 `<div>` 元素。在脚本中，我们定义了可配置的选项，指定了当检测到每个事件时应执行 `eventCallback` 函数。

接下来，我们定义一个对象字面量，在其中，每个属性的键设置为可能触发的事件类型之一。每个属性的值是我们希望为任何给定事件显示的消息。

然后，我们定义我们的回调函数。与其他组件一样，用于 droppables 组件的回调函数自动传递两个对象：`event` 对象和表示拖动元素的对象。

我们使用 `event` 对象的 `type` 属性从 `eventMessages` 对象中检索适当的消息。然后，我们使用标准的 jQuery 元素创建和操作方法将消息添加到状态栏中。

以下是交互后状态栏的外观：

![理解可放置回调选项](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_11_12.jpg)

玩了一会儿页面后，可能会出现我们的一个消息没有显示的情况。当拖动对象放置在 droppable 上时，我们的 drop 消息不显示。

实际上，消息是显示出来的，但因为`drop`事件之后立即触发`deactivate`事件；`drop`消息立即被覆盖。我们可以想到许多解决方法；当然，最简单的方法就是不同时使用`drop`和`deactivate`选项。

尽管在此示例中我们仅使用事件对象（`e`），但第二个对象也会自动传递给我们在事件选项中使用的任何回调函数。

该对象包含与 droppable 相关的信息，例如以下内容：

| 属性 | 值 |
| --- | --- |
| `ui.draggable` | 当前拖动对象。 |
| `ui.helper` | 当前拖动助手。 |
| `ui.position` | 辅助程序的当前相对位置。 |
| `ui.offset` | 辅助程序的当前绝对位置。 |

## 设置 droppable 的范围选项

拖动对象和 droppables 都具有`scope`配置选项，允许我们轻松定义拖动对象和放置目标的组。在下一个示例中，我们可以看看如何配置这些选项以及配置它们的影响。在这个示例中，我们将链接到另一个新的样式表，所以在`droppable5.html`的`<head>`元素中，将`<link>`元素更改为以下方式：

```js
<link rel="stylesheet" href="css/droppableScope.css">
```

对于这个示例，我们需要一些新元素。将`droppable5.html`页面中的`<body>`元素更改为包含以下元素：

```js
<div id="target_a">A</div>
<div id="target_b">B</div>
<div id="group_a">
  <p>A</p>
  <div id="a1" class="group_a">a1</div>
  <div id="a2" class="group_a">a2</div>
  <div id="a3" class="group_a">a3</div>
</div>
<div id="group_b">
  <p>B</p>
  <div id="b1" class="group_b">b1</div>
  <div id="b2" class="group_b">b2</div>
  <div id="b3" class="group_b">b3</div>
</div>
```

要使这些元素正确工作，请将最后一个`<script>`元素更改为如下所示：

```js
<script>
  $(document).ready(function($){
 var dragOpts_a = { scope: "a" },
 dragOpts_b = { scope: "b" },
 dropOpts_a = { hoverClass: "over", scope: "a" },
 dropOpts_b = { hoverClass: "over", scope: "b" };
 $(".group_a").draggable(dragOpts_a);
 $(".group_b").draggable(dragOpts_b);
 $("#target_a").droppable(dropOpts_a);
 $("#target_b").droppable(dropOpts_b);
  });
</script> 
```

将此文件保存为`droppable6.html`。接下来，我们需要创建一个新的 CSS 文件；在文本编辑器中的新页面中添加以下代码：

```js
#target_a, #target_b, #group_a, #group_b { width: 150px; height: 
150px; padding: 50px; margin: 0 20px 20px 0; border: 2px solid black; 
float: left;
font-family: Georgia; font-size: 100px; color: red; text-align: 
center; }
#group_a, #group_b { width: 518px; height: 115px; padding: 5px 0 5px 5px; margin-bottom: 20px; clear: both; }
p { float: left; margin: 0 20px 0; }
.group_a, .group_b { width: 94px; height: 94px; padding: 20px 0 0 20px;
.group_a, .group_b { width: 94px; height: 94px; padding: 20px 0 0 
20px; margin-right: 20px; float: left; font-family: arial; font-size: 14px; color: red; text-align: left;
background: url(../img/draggable.png) no-repeat; }
.over { background-color: #fe2e2e; }
```

将此保存为`droppableScope.css`在`css`文件夹中。

页面有两个放置目标和两组三个拖动对象，它们都带有标签以显示它们所属的组。在脚本中，我们为两组 dragable 定义了两个配置对象，并为 drop 目标定义了两个配置对象。在每个配置对象中，我们设置了`scope`选项。

我们为每个放置目标的`scope`选项设置的值与每个拖动对象的`scope`匹配。因此，如果我们想使用`scope`选项，必须为拖动对象和放置目标都定义它。如果我们尝试设置 droppable 的`scope`，但没有至少为同一`scope`提供一个拖动对象，就会引发错误。

设置`scope`选项给了我们另一种定义哪些拖动对象被哪些放置目标接受的技术，但它是作为`accept`选项的一个替代提供的；这两个选项不应该一起使用。

以下屏幕截图显示了页面的外观：

![设置 droppable 的范围选项](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_11_13.jpg)

## 配置贪婪选项

我们将要与可拖放组件一起查看的最后一个选项是`greedy`选项。此选项在有一个可拖放区域嵌套在另一个可拖放区域中的情况下非常有用。如果我们不使用此选项，某些交互期间两个可拖放区域都会触发事件。

`greedy`选项是避免事件冒泡问题的一种简单方法，而且在效率和跨浏览器方面都很有效。让我们通过一个例子来更仔细地研究这个选项。

修改`droppable6.html`中的`<link>`元素，使其链接到一个新的样式表：

```js
<link rel="stylesheet" href="css/droppableNesting.css">
```

然后将`<body>`修改为包含以下元素：

```js
<div id="drag"></div>
  <div class="target" id="outer">
  <div class="target" id="inner"></div>
</div>
<div id="status"></div>
```

最后，修改最后一个`<script>`元素，使其如下所示：

```js
<script>
  $(document).ready(function($){
    $(".target").css({ opacity:"0.5" });
    $("#drag").draggable({ zIndex: 3 });
    $(".target").droppable({
      drop: dropCallback,
      greedy: true
    });
    function dropCallback(e) {
      var message = $("<p></p>", {
        id: "message",
        text: "The firing droppable was " + e.target.id
      });
      $("#status").append(message);
    }
  });
</script>
```

将此示例保存为`droppable7.html`。此示例的 CSS 简单，基于之前示例的 CSS 构建。

```js
#drag { width: 114px; height: 114px; margin-bottom: 5px; cursor: move; background: url(../img/draggable.png) no-repeat; float: left; }
#outer { width: 300px; height: 300px; border: 3px solid #000; float: right; background-color: #fe2e2e; }
#inner { width: 100px; height: 100px; border: 3px solid #000; position: relative; top: 100px; left: 100px; background-color: #FFFF99; }
#status {width: 280px; padding: 10px; border: 3px solid #000; float: right; clear: right; color: #000; } 
#message { margin: 0px; font-size: 80%; }
```

将此示例保存为`droppableNesting.css`在`css`文件夹中。

在这个例子中，我们有一个较小的可拖放区域嵌套在一个较大的可拖放区域中。它们的不透明度是使用标准的 jQuery 库的`css()`方法设置的。

在这个例子中，这是必要的，因为如果我们修改元素的`zIndex`选项，使得拖动对象出现在嵌套的可拖放区域上方，目标元素不会被正确报告。

在这个例子中，我们使用了拖动组件的`zIndex`选项来在拖动进行时将拖动对象显示在可拖放区域的上方。`dropCallback`函数用于向状态栏添加一个简单的消息，通知我们拖动对象被放置在哪个可拖放区域上。

我们的可拖放配置对象使用`drop`选项来连接我们的回调函数。然而，关键选项是`greedy`选项，它使得可拖动对象放置在其上时阻止事件逃逸到其他目标。

如果你运行页面并将拖动对象放置到可拖放区域之一，你应该会看到类似以下截图所示的情况：

![配置`greedy`选项](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_11_14.jpg)

将`greedy`选项设置为`true`的净效果是，内部可拖放区域阻止事件传播到外部可拖放区域并再次触发。

如果你注释掉`greedy`选项并将可拖动对象放置在内部可拖放区域上，状态消息将会被插入两次，一次是由内部可拖放区域，另一次是由外部可拖放区域。

# 可拖放方法

像可拖动组件一样，可拖放组件只有所有库组件共享的通用 API 方法。这是另一个主要由选项驱动的组件。可用于我们的方法与可拖动对象公开的方法相同，即所有库组件共享的标准方法，这些方法是`destroy`、`disable`、`enable`、`option`和`widget`。

# 使用小部件创建迷宫游戏

现在我们已经达到了可以通过将我们学到的关于这两个组件的知识放入一个完全工作的示例中来玩耍的地步。在我们最终的拖放示例中，我们将结合这两个组件来创建一个简单的迷宫游戏。

游戏将由一个可拖动的标记组成，需要通过一个简单的迷宫导航到迷宫的另一端指定的可拖放位置。我们可以使事情变得更具挑战性，以便如果标记触碰到任何迷宫墙壁，它将返回到起始位置。

以下屏幕截图显示我们将要构建的内容：

![使用小部件创建迷宫游戏](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_11_15.jpg)

让我们从标记开始。在文本编辑器中的新页面中添加以下代码：

```js
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="utf-8">
    <title>Droppable</title>
    <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
    <script src="img/jquery-2.0.3.js"></script>
    <script src="img/jquery.ui.core.js"></script>
    <script src="img/jquery.ui.widget.js"></script>
    <script src="img/jquery.ui.mouse.js"></script>
    <script src="img/jquery.ui.draggable.js" ></script>
    <script src="img/jquery.ui.droppable.js" ></script>
    <script>
    </script>
  </head>
  <body>
    <div id="maze">
      <div id="drag"></div>
      <div id="start"></div>
      <div id="end"></div>
    </div>
  </body>
</html>
```

将此文件保存为`dragMaze.html`。在页面上，我们有一个外部容器，我们给了一个名为迷宫的`id`。我们有用于起始和结束位置以及用于拖动标记的`<div>`元素。我们的地图将需要墙壁。与手工编写我们将使用的地图模式所需的 46 个墙壁不同，我想我们可以使用 jQuery 来为我们完成这项工作。

我们在页面底部留下了一个空的`<script>`元素。让我们用以下代码填充它：

```js
$(document).ready(function($){
  var dragOpts = {
    containment: "#maze"
  },
  dropOpts = {
    tolerance: "touch",
    over: function(e, ui) {
      $("#drag").draggable("destroy").remove();
      $("<div />", {
        id: "drag",
        css: {
          left: 0,
          top: 0
        }
      }).appendTo("#maze");
      $("#drag").draggable(dragOpts);
    }   
  },
  endOpts = {
    over: function(e, ui) {
      $("#drag").draggable("destroy").remove();
      alert("Woo! You did it!");
    }
  };
  for (var x = 1; x < 47; x++) {
    $("<div />", {
      id: "a" + x,
      class: "wall"
    }).appendTo("#maze");
  }
  $("#drag").draggable(dragOpts);
  $(".wall").droppable(dropOpts);
  $("#end").droppable(endOpts);
});
```

我们还需要为迷宫的墙壁进行样式处理，但我们不能使用任何简单的 JavaScript 模式。不幸的是，我们必须将它们硬编码。在文本编辑器中的另一个新文件中，添加以下选择器和规则：

```js
#maze { width: 441px; height: 441px; border: 10px solid #000000; position: relative; background-color: #ffffff; }
#drag { width: 10px; height: 10px; z-index: 1; background-color: #0000FF; } 
#start { width: 44px; height: 10px; background-color: #00CC00; position: absolute; top: 0; left: 0; z-index: 0; }
#end { width: 44px; height: 10px; background-color: #FF0000; position: absolute; top: 0; right: 130px; }
.wall { background-color: #000000; position: absolute; }
#a1 { width: 10px; height: 133px; left: 44px; top: 0; }
#a2 { width: 44px; height: 10px; left: 0; top: 167px; }
#a3 { width: 44px; height: 10px; left: 44px; top: 220px; }
#a4 { width: 89px; height: 10px; left: 0; bottom: 176px; }
#a5 { width: 94px; height: 10px; left: 0; bottom: 88px; }
#a6 { width: 10px; height: 41px; left: 40px; bottom: 0; }
#a7 { width: 10px; height: 48px; left: 88px; top: 44px; }
#a8 { width: 78px; height: 10px; left: 54px; top: 123px; }
#a9 { width: 10px; height: 97px; left: 88px; top: 133px }
#a10 { width: 10px; height: 45px; left: 40px; bottom: 98px; }
#a11 { width: 88px; height: 10px; left: 89px; bottom: 132px; }
#a12 { width: 10px; height: 97px; left: 132px; bottom: 35px; }
#a13 { width: 10px; height: 44px; left: 89px; bottom: 142px; }
#a14 { width: 92px; height: 10px; left: 40px; bottom: 35px; }
#a15 { width: 89px; height: 10px; left: 88px; top: 34px; }
#a16 { width: 10px; height: 145px; left: 132px; top: 76px; }
#a17 { width: 44px; height: 10px; left: 132px; top: 220px; }
#a18 { width: 133px; height: 10px; left: 132px; bottom: 175px; }
#a19 { width: 10px; height: 107px; left: 176px; bottom: 35px; }
#a20 { width: 10px; height: 150px; left: 176px; top: 34px; }
#a21 { width: 35px; height: 10px; left: 186px; top: 174px }
#a22 { width: 35px; height: 10px; left: 186px; bottom: 88px; }
#a23 { width: 122px; height: 10px; left: 186px; top: 88px; }
#a24 { width: 10px; height: 44px; left: 220px; top: 0px; }
#a25 { width: 10px; height: 55px; left: 220px; top: 174px; }
#a26 { width: 10px; height: 45px; left: 220px; bottom: 130px; }
#a27 { width: 133px; height: 10px; right: 88px; top: 44px; }
#a28 { width: 10px; height: 168px; right: 166px; top: 98px; }
#a29 { width: 44px; height: 10px; right: 176px; top: 130px; }
#a30 { width: 10px; height: 98px; right: 166px; bottom: 35px; }
#a31 { width: 133px; height: 10px; right: 88px; bottom: 35px; }
#a32 { width: 10px; height: 133px; right: 78px; top: 44px; }
#a33 { width: 44px; height: 10px; right: 88px; top: 128px; }
#a34 { width: 131px; height: 10px; right: 35px; top: 171px; }
#a35 { width: 43px; height: 10px; right: 123px; top: 220px; }
#a36 { width: 10px; height: 91px; right: 123px; bottom: 85px; }
#a37 { width: 131px; height: 10px; right: 35px; bottom: 123px; }
#a38 { width: 10px; height: 55px; right: 79px; top: 220px; }
#a39 { width: 44px; height: 10px; right: 0; top: 122px; }
#a40 { width: 10px; height: 54px; right: 79px; bottom: 35px; }
#a41 { width: 79px; height: 10px; right: 0; bottom: 79px; }
#a42 { width: 10px; height: 45px; right: 35px; top: 44px; }
#a43 { width: 43px; height: 10px; right: 35px; top: 88px; }
#a44 { width: 79px; height: 10px; right: 0; top: 220px; }
#a45 { width: 10px; height: 44px; right: 35px; bottom: 132px; }
#a46 { width: 10px; height: 50px; right: 35px; bottom: 0; }
```

将此文件保存为`dragMaze.css`，放在`css`文件夹中。

让我们回顾一下新代码的作用。首先，我们为拖动对象定义了一个简单的配置对象。我们唯一需要配置的选项是`containment`选项，它将可拖动的标记元素限制在迷宫内。

接下来，我们为墙壁定义配置对象。每堵墙都被视为一个可放置的物品。我们将`tolerance`选项的值指定为`touch`，并将回调函数添加到`over`选项中。因此，每当拖动对象触碰到墙壁时，函数将被执行。

在此函数中，我们所做的一切就是销毁当前拖动对象并将其从页面中移除。

然后，我们在起始位置创建一个新的拖动对象，并再次使其可拖动。没有`cancelDrag`方法会使拖动对象像已被放置并返回到起始位置一样操作，但我们可以很容易地自己复制这种行为。

现在，我们添加另一个可拖放配置对象，用于配置迷宫的结束点。我们为此可拖放配置的唯一配置是一个函数，当可拖放物品位于此可拖放位置时执行。在这个函数中，我们再次移除拖动对象，并向用户显示一个祝贺的警报。

然后，我们使用简单的`for`循环来将墙壁添加到我们的迷宫中。我们结合 jQuery 使用普通的`for`循环创建 46 个`<div>`元素，并在将它们附加到`maze`容器之前为每个元素添加`id`和`class`属性。最后，我们使拖动对象可拖动，而墙壁和结束目标可放置。

现在我们可以尝试通过将标记拖动穿过迷宫来从起点到终点进行导航。如果触碰到任何墙壁，标记将返回到起点。我们可以增加难度（增加额外障碍物来导航），但为了与 jQuery UI 的可拖动和可放置功能一起玩耍，我们在这里的工作已经完成。

# 总结

在本章中，我们看到了两个非常有用的库组件——可拖动组件和可放置组件。正如我们所见，可拖动和可放置是非常密切相关的，并且它们被设计为相互配合使用，让我们能够创建高级且高度交互的界面。

在本章中，我们涵盖了大量材料，让我们回顾一下我们所学到的内容。我们看到可拖动行为可以被添加到页面上的任何元素而不需要任何配置。也许有些实现情况下这是可以接受的，但通常我们会想使用该组件广泛的可配置选项中的一个或多个。

在本章的第二部分中，我们看到`droppables`类使我们能够轻松地在页面上定义可放置可拖动物品的区域，并且可以响应有物品放置在上面的情况。我们还可以利用一系列可配置的`droppable`选项来实现更高级的可放置行为。

这两个组件都具有一个有效的事件模型，用于钩取任何拖放交互的有趣时刻。我们的最终示例展示了如何将可拖动和可放置组件一起使用以创建一个有趣和交互的游戏。尽管这个游戏在现代游戏标准下非常基本，但它仍然提供了一个坚实的基础，我们可以轻易地构建以添加功能。

在下一章中，我们将看看可调整大小的组件，该组件允许用户使用熟悉的基于拖动的界面来调整所选元素的大小。


# 第十二章：可调整大小组件

当我们在本书前面查看对话框小部件时，我们已经简要地看到了可调整大小的效果。在本章中，我们将直接关注它。然而，对话框是一个很好的例子，说明了在实际应用中可调整大小的组件可以有多么有用。

可调整大小小部件添加了与在 WebKit 浏览器（如 Safari 或 Chrome）或较新版本的 Firefox 中自动添加到 `<textarea>` 元素中的相同功能。在这些浏览器中，会添加一个调整大小的手柄到右下角，允许调整元素的大小。使用 jQuery UI 可调整大小组件，我们可以将此行为添加到页面上几乎任何元素中。

在本章中，我们将关注该组件的以下方面：

+   实现基本的可调整大小

+   可用于使用的可配置选项

+   指定要添加的调整大小手柄

+   管理可调整大小的最小和最大尺寸

+   调整大小帮助器和幽灵的角色

+   查看内置的调整大小动画

+   如何响应调整大小事件

+   确定可调整大小的新尺寸

+   与其他库小部件一起使用可调整大小

可调整大小小部件是一个灵活的组件，可以与各种不同的元素一起使用。在本章的示例中，我们将主要使用简单的 `<div>` 元素，以便将重点放在组件上，而不是底层的 HTML 上。我们还将在本章末尾看一些简短的示例，使用 `<img>` 和 `<textarea>` 元素。

可调整大小的组件与其他组件配合得很好，并且经常与可拖动的组件一起使用。然而，虽然你可以轻松地使可拖动的组件可调整大小（比如对话框），但是这两个类别并没有任何关联。

# 实现基本的可调整大小小部件

让我们实现基本的可调整大小，这样我们就可以看到当你使用 jQuery UI 作为页面的驱动力时，使元素可调整大小是多么容易的事情。在文本编辑器中的一个新文件中添加以下代码：

```js
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="utf-8">
    <title>Resizable</title>
    <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
    <link rel="stylesheet" href="css/resize.css">
    <script src="img/jquery-2.0.3.js"></script>
    <script src="img/jquery.ui.core.js"></script>
    <script src="img/jquery.ui.widget.js"></script>
    <script src="img/jquery.ui.mouse.js"></script>
  <script src="img/jquery.ui.resizable.js"></script>
  </head>
  <script>
    $(document).ready(function($){
      $("#resize").resizable();
    });
  </script>
  <body>
    <div id="resize"></div>
  </body>
</html>
```

将此文件保存为`resizable1.html`。默认实现中使用的基本小部件方法没有参数，其使用与库的其余部分相同的简化语法。这只需要一行代码即可使示例工作。

除了我们需要用于任何可调整大小实现的 CSS 框架文件外，我们还使用自定义样式表为我们的可调整大小的 `<div>` 添加了基本的尺寸和边框。在文本编辑器中的一个新文件中使用以下 CSS：

```js
#resize { width: 200px; height: 200px; margin: 30px 0 0 30px;
border: 1px solid #7a7a7a; }
```

将此文件保存为`resize.css`，放在`css`文件夹中。我们在 CSS 中指定了调整大小的 `<div>` 的尺寸，因为如果没有这些尺寸，`<div>` 元素将拉伸到屏幕的宽度。我们还指定了一个边框来清晰地定义它，因为默认实现只会在目标元素的右下角添加一个调整大小的手柄。下面的截图显示了在 `<div>` 元素调整大小后我们的基本页面应该是什么样子的：

![实现基本的可调整大小小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_12_01.jpg)

可调整大小组件所需的文件如下：

+   `jquery-2.0.3.js`

+   `jquery.ui.core.js`

+   `jquery.ui.widget.js`

+   `jquery.ui.mouse.js`

+   `jquery.ui.resizable.js`

该组件自动添加了三个必需的拖动手柄元素。尽管唯一可见的调整大小手柄是右下角的手柄，但底部和右侧边缘都可以用于调整大小小部件。

# 列出可调整大小选项

下表列出了我们在使用可调整大小组件时可以使用的可配置选项：

| 选项 | 默认值 | 用于… |
| --- | --- | --- |
| `alsoResize` | `false` | 自动调整指定的元素以与可调整大小元素同步。 |
| `animate` | `false` | 将可调整大小元素动画到其新大小。 |
| `animateDuration` | `slow` | 设置动画的速度。值可以是整数，指定毫秒数，或者是字符串值 `slow`，`normal` 或 `fast`。 |
| `animateEasing` | `swing` | 为调整大小动画添加缓动效果。 |
| `aspectRatio` | `false` | 保持调整大小元素的纵横比。除了布尔值之外，还接受数字自定义纵横比。 |
| `autoHide` | `false` | 隐藏调整大小手柄，直到鼠标指针悬停在可调整大小元素上。 |
| `cancel` | `':input, option'` | 阻止指定元素可调整大小。 |
| `containment` | `false` | 将可调整大小限制在指定容器元素的边界内。 |
| `delay` | `0` | 设置从单击可调整大小手柄到开始调整大小之间的延迟时间（以毫秒为单位）。 |
| `disabled` | `false` | 在页面加载时禁用组件。 |
| `distance` | `1` | 设置鼠标指针在按住鼠标按钮的情况下必须移动的像素数，然后调整大小开始。 |
| `ghost` | `false` | 在调整大小时显示半透明的辅助元素。 |
| `grid` | `false` | 在调整大小时将调整大小捕捉到虚拟网格线。 |
| `handles` | `'e, se, s'` | 定义用于调整大小的手柄。接受包含以下任意值的字符串：`n`，`ne`，`e`，`se`，`s`，`sw`，`w`，`nw`，或所有。该字符串也可以是一个对象，其属性是前述任何值，值是与用作手柄的元素匹配的 jQuery 选择器。 |
| `helper` | `false` | 在调整大小期间应用于辅助元素的类名。 |
| `maxHeight` | `null` | 设置可调整大小的最大高度。 |
| `maxWidth` | `null` | 设置可调整大小的最大宽度。 |
| `minHeight` | `null` | 设置可调整大小的最小高度。 |
| `minWidth` | `null` | 设置可调整大小的最小宽度。 |

## 配置调整大小手柄

感谢`handles`配置选项，指定我们希望添加到目标元素的 handles 非常容易。在`resizable1.html`中，将最后的`<script>`元素更改为以下内容：

```js
  <script>
    $(document).ready(function($){
      $("#resize").resizable({ handles: "all" });
    });
  </script>
```

将此文件保存为`resizable2.html`。当你在浏览器中运行示例时，你会发现尽管组件看起来和以前一样，但现在我们可以使用任何边缘或角来调整`<div>`元素的大小。

## 添加额外的 handle 图片

你会立即注意到的一件事是，尽管元素沿任何轴都是可调整大小的，但没有视觉提示来使这一点明显；该组件会自动将调整大小条添加到右下角，但我们需要自己添加其他三个角。

有几种不同的方法可以做到这一点。虽然这种方法不会在其他三个角添加图片，但它会插入具有 class 名称的 DOM 元素，因此我们可以轻松地用 CSS 来定位它们并提供我们自己的图片。这就是我们接下来要做的。

在文本编辑器中新建一个页面，并添加以下样式规则：

```js
#resize {width: 200px; height: 200px; margin: 30px 0 0 30px; border: 1px solid #7a7a7a;}
.ui-resizable-sw, .ui-resizable-nw, .ui-resizable-ne {width: 12px; height: 12px; background: url(../img/handles.png) no-repeat 0 0;}
.ui-resizable-sw {left: 0; bottom: 0;} 
.ui-resizable-nw {left: 0; top: 0; background-position: 0 -12px;}
.ui-resizable-ne {right: 0; top: 0; background-position: 0 -24px;}
```

将此文件保存在`css`文件夹中，文件名为`resizeHandles.css`。我们提供了一个示例图片，其中包含了标准右下角图片的翻转和镜像拷贝（可在代码下载中找到）。然后，我们可以通过在 CSS 样式规则中设置 background-position 属性来引用它们。使用单个图片或精灵图可以减少缓存多个图片的需求；我们所使用的所有单独图片实际上都是来自一个更大的文件的片段。

### 提示

Chris Coyier 撰写了一篇有用的文章，解释了如何实现精灵图，可以在[`css-tricks.com/css-sprites/`](http://css-tricks.com/css-sprites/)找到。

我们的选择器会目标自动添加到 handle 元素的 class 名称。在`resizable2.html`的`<head>`元素中链接到新样式表，并将其另存为`resizable3.html`：

```js
<link rel="stylesheet" href="css/resizeHandles.css">
```

新样式表应使我们的元素呈现如下外观：

![添加额外的 handle 图片](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_12_02.jpg)

与调整大小 handles 和它们的显示方式相关的另一个配置选项是`autoHide`。让我们下面快速看一下这个选项。将`resizable3.html`中的配置对象更改为以下内容：

```js
$("#resize").resizable({
  handles: "all",
 autoHide: true
});
```

将此版本保存为`resizable4.html`。在这个示例中，我们已添加了`autoHide`选项并将其值设置为`true`。配置此选项会隐藏所有的调整大小 handles，直到鼠标指针移动到可调整大小的元素上。当可调整大小的元素中有图片内容时，这对于最小干扰额外的 DOM 元素是非常有益的。

## 定义尺寸限制

通过四个可配置选项，限制目标元素可以调整的最小或最大尺寸变得非常容易。它们分别是`maxWidth`、`maxHeight`、`minWidth`和`minHeight`。我们将在下一个示例中看到它们的作用。为了这个示例最好在容器中添加一些内容，所以在我们的可调整大小的`<div>`中的`<p>`元素中添加一些布局文本在`resizable4.html`中：

```js
<p>Lorem ipsum etc, etc…</p>
```

将我们在`resizable4.html`中使用的配置对象更改为如下所示：

```js
$("#resize").resizable({
 maxWidth: 500,
 maxHeight: 500,
 minWidth: 100,
 minHeight: 100
});
```

将其保存为`resizable5.html`。这次，配置对象使用了与尺寸边界有关的选项，以指定可调整大小元素的最小和最大高度和宽度。这些选项的值是简单的整数。

当我们运行这个示例时，我们可以看到可调整大小的元素现在遵循我们指定的尺寸，而在以前的示例中，可调整大小元素的最小尺寸是其调整大小手柄的组合尺寸，而最大尺寸是没有限制的。

到目前为止，我们的可调整大小元素一直是一个空的`<div>`元素，你可能会想知道，当目标元素内有内容时，可调整大小如何处理最小和最大尺寸。约束条件是保持的，但我们需要在 CSS 中添加`overflow: hidden`。否则，如果内容太多，最小尺寸无法处理，内容可能会溢出可调整大小的区域。

当然，当内容太多时，我们还可以使用`overflow: auto`来添加滚动条，有时这可能是期望的行为。

## 调整大小的幽灵元素

幽灵元素是半透明的辅助元素，非常类似于我们在上一章中看到的拖动组件时使用的代理元素。通过配置一个选项就可以启用幽灵元素。让我们看看如何实现这一点。

将我们在`resizable5.html`中使用的配置对象更改为以下内容：

```js
$("#resize").resizable({ ghost: true });
```

将其保存为`resizable6.html`。启用调整大小幽灵元素所需的全部内容就是将`ghost`选项设置为`true`。可调整大小的幽灵元素的效果非常微妙。它基本上是现有可调整大小元素的克隆，但是只有四分之一的不透明度。这就是为什么在可调整大小元素中留下了上一个示例中的布局文本的原因。

在这个示例中，我们还链接到一个新的样式表，其与`resize.css`完全相同，只是指定了背景色：

```js
#resize { width: 200px; height: 200px; margin: 30px 0 0 30px;
border: 1px solid #7a7a7a; overflow: hidden; background-color: #999; }
```

将其保存为`resizeGhosts.css`在`css`文件夹中。下一张截图显示了可调整大小的幽灵元素在被拖动时的可见外观：

![调整大小的幽灵元素](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_12_03.jpg)

### 注意

在某些版本的 Internet Explorer 中，当透明 PNG 图像位于可调整大小元素中时，幽灵元素可能会导致问题。如果您发现情况是如此，那么可以在[`www.pixelthemestudio.ca/news-and-updates/156-fixing-that-png-image-optimization-for-ie`](http://www.pixelthemestudio.ca/news-and-updates/156-fixing-that-png-image-optimization-for-ie)上找到一篇有用的文章，详细介绍了如何使用 TweakPNG 解决这些问题。

ghost 元素只是一个已被制成半透明的辅助元素。如果这不合适，并且需要进一步控制助手元素的外观，则可以使用 `helper` 选项来指定要添加到助手元素的类名，然后我们可以使用该类名来为其设置样式。更改 `resizable6.html` 中的配置对象，使其如下所示：

```js
$("#resize").resizable({
  ghost: true,
 helper: "my-ui-helper"
});
```

将此修订保存为 `resizable7.html`。我们只是指定了我们希望添加为 `helper` 选项值的类名。我们可以从 CSS 文件中定位新的类名。打开 `resize.css` 并将以下代码添加到其中：

```js
.my-ui-helper { background-color:#FFFF99; }
```

将新样式表保存为 `resizeHelper.css`，并不要忘记在 `resizable7.html` 的顶部链接它：

```js
<link rel="stylesheet" href="css/resizeHelper.css">
```

在此示例中，我们唯一做的就是给助手添加了一个简单的背景颜色，这种情况下是黄色。当新页面运行并且调整大小动作正在进行时，它的外观如下所示：

![调整大小的虚像](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_12_04.jpg)

`ghost` 和 `helper` 选项不必一起使用；我们可以分别使用其中一个，但如果我们使用 `helper` 选项而不使用 `ghost` 选项，则无法获得调整大小助手内的半透明内容。

## 包含调整大小

可调整大小组件使得确保调整大小的元素被包含在其父元素中变得容易。如果我们在页面上有其他内容，我们不希望在调整大小交互期间随意移动，这将非常有用。在 `resizable7.html` 中，更改页面上的元素，使其如下所示：

```js
<div class="container">
  <img id="resize" src="img/moon.jpg" alt="Moon Landing">
</div>
```

最后，将 `configuration` 对象更改为使用 `containment` 选项：

```js
$("#resize").resizable({
 containment: ".container"
});
```

将此文件保存为 `resizable8.html`。在页面上，我们为可调整大小添加了一个容器元素，并已从使用 `<div>` 元素更改为使用图像作为可调整大小的元素。

再次，对于此示例，我们需要一些略有不同的 CSS。在文本编辑器中的新文件中，添加以下代码：

```js
.container { width: 600px; height: 600px; border: 1px solid #7a7a7a; padding: 1px 0 0 1px; }
#resize { width: 300px; height: 300px; }
```

将此保存为 `resizeContainer.css` 在 `css` 文件夹中，并将页面的 `<head>` 元素中的 `<link>` 从 `resizeHelper.css` 更改为新样式表：

```js
<link rel="stylesheet" href="css/resizeContainer.css">
```

`containment` 选项允许我们指定可调整大小的容器，这将限制可调整大小的大小，强制它保持在其边界内。

我们将一个 jQuery 选择器指定为此选项的值。当我们查看页面时，应该看到图像无法调整大小以大于其容器的尺寸。

## 处理纵横比

除了保持可调整大小元素的纵横比之外，我们还可以手动定义它。让我们看看这种交互给我们调整大小带来了什么控制。将 `resizable8.html` 中使用的配置对象更改为以下内容：

```js
$("#resize").resizable({
  containment: ".container",
 aspectRatio: true
});
```

将此文件保存为 `resizable9.html`。将 `aspectRatio` 选项设置为 `true` 可确保我们的图像保持其原始纵横比。因此，在此示例中，图像将始终是一个完美的正方形。

为了更好地控制，我们可以指定可调整大小应保持的实际宽高比：

```js
$("#resize").resizable({
  containment: ".container",
 aspectRatio: 0.5
});
```

通过指定`0.5`的浮点值，我们要说的是当图像调整大小时，图像的 x 轴应该正好是 y 轴的一半。

### 注意

当偏离任何图像的宽高比时，应谨慎； 最好尝试保持元素和容器大小成比例，否则您可能会发现对象未调整到其容器的全部大小，就像我们的示例中发生的那样。 如果将`aspectRatio`更改为`1`，则会发现它会正确地调整为容器的全尺寸。

## 可调整大小的动画

可调整大小的 API 公开了与动画相关的三个配置选项：`animate`，`animateDuration`和`animateEasing`。 默认情况下，在可调整大小的实现中关闭了动画。 但是，我们可以轻松地启用它们以查看它们如何增强此组件。

在此示例中，将标记从前面的几个示例更改为可调整大小的元素返回到普通的`<div>`：

```js
<div id="resize"></div>
```

我们还应该切换回`resizeGhosts.css`样式表：

```js
<link rel="stylesheet" href="css/resizeGhost.css">
```

现在，将配置对象更改为使用以下选项：

```js
$("#resize").resizable({
  ghost: true,
 animate: true,
 animateDuration: "fast"
});
```

将此保存为`resizable10.html`。 我们在此示例中使用的配置对象以`ghost`选项开头。

### 注意

在使用动画时，可调整大小的元素在交互结束后才被调整大小，因此显示幽灵作为视觉提示是有用的，以表示元素将被调整大小。

要启用动画，我们只需将`animate`选项设置为`true`。 就是这样； 不需要进一步配置。 我们可以更改的另一个选项是动画的速度，在此示例中，我们通过设置`animateDuration`选项来完成。 这可以接受与 jQuery 的`animate()`方法一起使用的任何标准值。

当我们在浏览器中运行此页面时，我们应该发现`resize` div 将平滑地动画到其新大小，一旦我们松开鼠标按钮。

## 同时调整大小

我们可以通过将对它们的引用传递给可调整大小的小部件方法，轻松地使同一页上的几个元素单独可调整大小。 但是，除此之外，我们还可以使用`alsoResize`属性来指定额外的要作为组一起调整大小的元素，每当实际可调整大小的元素被调整大小时。 让我们看看如何做到这一点。

首先，我们需要再次引用新的样式表：

```js
<link rel="stylesheet" href="css/resizeSimultaneous.css">
```

接下来，我们需要将页面的`<body>`中的元素更改为如下所示：

```js
<div id="mainResize">
  <p>I am the main resizable!</p>
</div>
<div id="simultaneousResize">
  <p>I will also be resized when the main resizable is resized!</p>
</div>
```

然后将配置对象更改为以下内容：

```js
$("#resize").resizable({
 alsoResize: "#simultaneousResize"
});
```

将此文件保存为`resizable11.html`。 我们以第二个`<div>`元素的值作为`alsoResize`选项的值，以便目标第二个`<div>`元素。 次要元素将自动获取实际可调整大小的可调整大小属性。

因此，如果我们将可调整大小限制为仅具有`e`手柄，则次要元素也将仅在此方向上调整大小。

此示例中引用的新样式表应包含以下代码：

```js
#mainResize { width: 100px; height: 100px; margin: 0 0 30px;
border: 2px solid #7a7a7a; text-align: center; }
#simultaneousResize { width: 150px; height: 150px; border: 2px solid #7a7a7a; text-align: center; }
p { font-family: arial; font-size: 15px; }
```

将此文件另存为`css`文件夹中的`resizeSimultaneous.css`。运行文件时，我们应该看到第二个`<div>`元素与第一个同时调整大小：

![同时调整大小](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_12_05.jpg)

## 防止不必要的调整大小

有时，我们可能希望使一个元素可以调整大小，但它还具有其他功能，或许它也监听点击事件。在这种情况下，除非绝对需要调整大小，否则最好防止调整大小，这样我们就可以轻松区分点击和真正的拖动。我们可以使用两个选项来实现这一点。

首先，在`resizable10.html`中，恢复原始样式表`resize.css`：

```js
<link rel="stylesheet" href="css/resize.css">
```

我们还可以返回到简单的空可调整大小的`<div>`：

```js
<div id="resize"></div>
```

然后将配置对象更改为以下内容：

```js
$("#resize").resizable({ 
 delay: 1000
});
```

将此版本另存为`resizable12.html`。`delay`选项接受一个整数，代表在点击调整大小手柄后保持鼠标按下状态的毫秒数。

在这个例子中，我们使用了`1000`作为值，相当于一秒。试一试，您会发现，如果您在点击调整大小手柄后太快放开鼠标按钮，调整大小就不会发生。

除了延迟调整大小，我们还可以使用`distance`选项来指定鼠标指针必须在单击调整大小手柄后保持按下的状态下移动一定数量的像素，然后调整大小才会发生。

更改`resizable12.html`中的配置对象，使其如下所示：

```js
$("#resize").resizable({
 distance: 30
});
```

将此保存为`resizable13.html`。现在当页面运行时，鼠标指针需要在鼠标按钮按下的状态下移动`30`个像素，然后调整大小才会发生。

这两个选项都会带来一定的可用性问题，特别是当设置为高值时，就像这些例子一样。它们都会使元素沿多个轴方向同时调整大小更加困难。应尽可能少地使用它们，并尽可能使用低值。

# 定义可调整大小事件

与库的其他组件一样，可调整大小定义了一系列自定义事件，并允许我们在这些事件发生时轻松执行功能。这充分利用了您的访问者和页面元素之间的交互。

可调整大小定义了以下回调选项：

| 选项 | 触发时… |
| --- | --- |
| `create` | 可调整大小已初始化 |
| `resize` | 可调整大小正在进行中 |
| `start` | 调整大小交互开始 |
| `stop` | 调整大小交互结束 |

对于可调整大小的自定义方法的钩子就像我们之前看过的库的其他组件一样容易。

让我们来探索一个基本的例子来突出这一事实，以下屏幕截图显示了在`<div>`消失之前我们的页面将如何展示：

![定义可调整大小事件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_12_06.jpg)

在`resizable13.html`中，将第二个`<link>`更改为指向一个新样式表，如下所示：

```js
<link rel="stylesheet" href="css/resizeStop.css">
```

然后将最终的`<script>`元素更改为如下所示：

```js
<script>
  $(document).ready(function($){
    function reportNewSize(e, ui) {
      var width = Math.round(ui.size.width),
      height = Math.round(ui.size.height);
      $("<div />", {
        "class": "message",
        text: "New size: " + height + "px high, " + width + "px wide",
        width: width
      }).appendTo("body").fadeIn().delay(2000).fadeOut();
    }
    $("#resize").resizable({
      stop: reportNewSize
    });
  });
</script>
```

将此保存为`resizable14.html`。在`resize.css`中，添加以下选择器和规则：

```js
.message { display: none; border: 1px solid #7a7a7a; margin-top: 5px; position: absolute; left: 38px;fontSize: 80%; font-weight: bold; text-align: center; }
```

将此保存为`resizeStop.css`在`css`文件夹中。

我们定义了一个名为`reportNewSize`的函数；这个函数（以及所有其他事件处理程序）会自动传递两个对象。第一个是事件对象，第二个是一个包含有关可调整大小的有用信息的对象。

我们可以使用第二个对象的`size`属性来查找可调整大小已更改为的`width`和`height`。这些值被存储为函数内的变量。我们使用 JavaScript 的`Math.round()`函数确保我们得到一个整数。

然后，我们创建一个新的`<div>`元素并为其设置一个样式类名。我们还设置新元素的文本以显示`width`和`height`变量以及简短消息。我们还将新元素的宽度设置为与可调整大小相匹配。创建后，我们将消息附加到页面，然后使用 jQuery 的`fadeIn()`方法淡入它。然后，我们使用`delay()`方法暂停`2`秒，然后再次淡出消息。

# 查看可调整大小的方法

此组件与库中所有交互组件具有的四种基本方法一起提供，即`destroy`、`disable`、`enable`和`option`方法。与大多数其他组件不同，可调整大小组件没有其独有的自定义方法。有关这些基本 API 方法的澄清，请参阅第一章*介绍 jQuery UI*中的 API 介绍部分。

# 创建可调整大小的标签页

在我们最终的可调整大小示例中，让我们看看如何将此组件与我们之前查看的小部件之一结合起来。这将帮助我们了解它与库中其余部分的兼容性。我们将在以下示例中使用标签页组件。以下屏幕截图显示了我们最终会得到的页面：

![创建可调整大小的标签页](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_12_07.jpg)

在你的文本编辑器中，将以下`CSS`样式添加到一个新文件中，并将其保存为`resizeTabs.css`：

```js
#resize { width: 200px; height: 200px; margin: 30px 0 0 30px; border: 1px solid #7a7a7a; }
#myTabs { width: 400px; height: 170px; }
```

接下来，将以下代码添加到一个新文件中：

```js
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="utf-8">
    <title>Resizable</title>
    <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
    <link rel="stylesheet" href="css/resizeTabs.css">
    <script src="img/jquery-2.0.3.js"></script>
    <script src="img/jquery.ui.core.js"></script>
    <script src="img/jquery.ui.widget.js"></script>
    <script src="img/jquery.ui.tabs.js"></script>
    <script src="img/jquery.ui.mouse.js"></script>
  <script src="img/jquery.ui.resizable.js"></script>
    <script>
      $(document).ready(function($){
        var tabs = $("#myTabs").tabs(), resizeOpts = {
          autoHide: true,
          minHeight: 170,
          minWidth: 400
        };
        tabs.resizable(resizeOpts);
      });
    </script>
  </head>
  <body>
    <div id="myTabs">
      <ul>
        <li><a href="#a">Tab 1</a></li>
        <li><a href="#b">Tab 2</a></li>
      </ul>
      <div id="a">
        This is the content panel linked to the first tab; it is shown by default.
      </div> 
      <div id="b">
        This content is linked to the second tab and will be shown when its tab is clicked.
      </div>
    </div>
  </body>
</html>
```

将此保存为`resizable15.html`。使标签页小部件可调整大小非常容易，只需在标签页的底层`<ul>`上调用可调整大小方法即可。

在本示例中，我们使用了单个配置对象。标签页组件可以初始化而无需任何配置。除了在我们的配置对象中将可调整大小的`autoHide`选项设置为`true`外，我们还为了可用性目的定义了`minWidth`和`minHeight`值。

# 摘要

在本章中，我们介绍了可调整大小的组件。这是一个组件，可以让我们轻松调整屏幕上的任何元素。它会动态地向目标元素的指定边添加调整大小手柄，并为我们处理所有棘手的 DHTML 调整，将行为整洁地封装到一个简洁易用的类中。

然后，我们看了一些可用于小部件的可配置选项，比如如何指定要添加到可调整大小的手柄，以及如何限制元素的最小和最大尺寸。

我们简要讨论了如何保持图像的宽高比，或者在调整大小时如何使用自定义比例。我们还探讨了如何使用幻影、助手和动画来改善可调整大小组件的可用性和外观。

我们还看了组件 API 公开的事件模型以及我们如何以简单有效的方式对元素的调整作出反应。我们的最终示例探讨了可调整大小组件与库中其他组件的兼容性。在下一章中，我们将学习如何使用可选择和可排序的小部件选择、过滤和排序对象。
