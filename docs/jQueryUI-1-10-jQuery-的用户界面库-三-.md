# jQueryUI 1.10：jQuery 的用户界面库（三）

> 原文：[`zh.annas-archive.org/md5/67D4BB507B37025C38972681032F3C25`](https://zh.annas-archive.org/md5/67D4BB507B37025C38972681032F3C25)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：日期选择器小部件

jQuery UI 日期选择器小部件可能是 jQuery 库中最精细和文档化的小部件。它具有最大的**应用程序编程接口**（**API**），可能提供了所有小部件中最多的功能。它不仅可以立即使用，而且还可以高度配置和健壮。

简单地说，日期选择器小部件提供了一个界面，让您网站或应用的访问者选择日期。无论何处需要填写日期的表单字段，都可以添加日期选择器小部件。这意味着您的访问者可以使用一个吸引人并且交互性强的小部件，而您可以得到您期望的日期格式。

在本节中，我们将讨论以下主题：

+   默认日期选择器的实现

+   探索可配置选项

+   实现触发按钮

+   配置替代动画

+   `dateFormat`选项

+   简单的本地化

+   多月日期选择器

+   数据范围选择

+   日期选择器小部件的方法

+   使用 AJAX 与日期选择器

内置到日期选择器中的其他功能包括自动打开和关闭动画以及使用键盘导航小部件界面的能力。在按住*Ctrl*键（或 Mac 上的命令键）时，键盘上的箭头可以用来选择新的日期单元格，然后可以使用返回键进行选择。

尽管易于创建和配置，但日期选择器是一个由各种底层元素组成的复杂小部件，如下图所示：

![日期选择器小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_01.jpg)

### 注意

尽管存在这种复杂性，但我们可以只用一行代码来实现默认日期选择器，就像我们迄今为止介绍的库中的其他小部件一样简单。

# 实现日期选择器小部件

要创建默认日期选择器，请在文本编辑器中的新页面中添加以下代码：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset = "utf-8">
  <title>Datepicker</title>
  <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
  <script src="img/jquery-2.0.3.js"></script>
  <script src="img/jquery.ui.core.js"></script>
  <script src="img/jquery.ui.widget.js"></script>  
<script src="img/jquery.ui.datepicker.js"> </script>
  <script>  
    $(document).ready(function($){
      $("#date").datepicker();
    });
  </script>
</head> 
<body>
  <label for="date">Enter a date:</label>
  <input id="date" />
</body>
</html>
```

将此保存为`jqueryui`项目文件夹中的`datePicker1.html`。我们页面上只有一个`<label>`和一个标准文本`<input>`元素。我们不需要为了渲染日期选择器小部件而指定任何空容器元素，因为创建小部件所需的标记会被库自动添加。

### 提示

尽管在您的`<input>`语句中使用 HTML5 的`type="date"`属性可能很诱人，但不建议这样做——这可能会导致冲突，即同时显示 jQuery UI 日期选择器和本机 HTML5 版本。

当您在浏览器中运行页面并聚焦于`<input>`元素时，默认日期选择器应该出现在输入框下方。除了一个`<input>`元素外，日期选择器也可以附加到一个`<div>`元素上。

除了外观漂亮之外，默认日期选择器还带有许多内置功能。当日期选择器打开时，它会平滑地从零到全尺寸进行动画，并且将自动设置为当前日期。选择日期将自动将日期添加到 `<input>` 并关闭日历（再次使用漂亮的动画）。

如果没有额外的配置并且只有一行代码，我们现在已经拥有了一个完全可用且具有吸引力的小部件，使日期选择变得容易。如果您只想让人们选择一个日期，这就是您所需要的全部。默认日期选择器所需的源文件如下：

+   `jquery-2.0.3.js`

+   `jquery.ui.core.js`

+   `jquery.ui.widget.js`

+   `jquery.ui.datepicker.js`

## 使用内联日历选择日期

我们创建了一个基本的日期选择器小部件，将其链接到一个普通的文本 `<input>` 框中。虽然这样做完全没问题，但有时您可能不想使用普通输入框，而只需在页面中显示已打开的日历。

幸运的是，使用日期选择器小部件很容易实现。更改 HTML 代码以使用 `<div>` 元素，如下代码所示：

```js
<body>
 Enter a date: <div id="date"></div>
</body>
```

如果在浏览器中预览结果，您会注意到输入文本框已经消失，并且日历已经完全显示出来：

![使用内联日历选择日期](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_02.jpg)

# 日期选择器的可配置选项

日期选择器具有大量可配置的选项（目前确切为 50 个）。以下表格列出了基本选项、它们的默认值，并简要描述了它们的用法：

| 选项 | 默认值 | 用法 |
| --- | --- | --- |
| `altField` | `""` | 指定替代 `<input>` 字段的 CSS 选择器，其中还添加了所选日期。 |
| `altFormat` | `""` | 指定要添加到替代 `<input>` 中的日期的替代格式。有关此选项接受的值的澄清，请参见后面部分中的 `dateFormat` 选项。 |
| `appendText` | `""` | 在日期选择器 `<input>` 后添加文本以显示所选日期的格式。 |
| `autoSize` | `false` | 自动设置 `<input>` 元素的宽度，以便根据指定的 `dateFormat` 容纳日期。 |
| `beforeShow` | `null` | 允许日期选择器配置对象在调用之前更新日期选择器。 |
| `beforeShowDay` | `null` | 接受日期作为参数，并返回值以指示该日期是否可选择，要添加到日期单元格的类名，以及日期的（可选）弹出工具提示。该函数在日期选择器中的每一天显示之前调用。 |
| `buttonImage` | `""` | 指定用于触发 `<button>` 的图像的路径。 |
| `buttonImageOnly` | `false` | 设置为 `true` 以使用图像而不是触发按钮。 |
| `buttonText` | `"..."` | 提供要显示在触发 `<button>` 上的文本（如果存在）。 |
| `calculateWeek` | `$.datepicker. iso8601Week` | 接受一个函数，用于计算指定日期的一年中的周数。 |
| `changeMonth` | `false` | 显示月份更改下拉列表。 |
| `changeYear` | `false` | 显示年份更改下拉列表。 |
| `closeText` |   |  |
| `constrainInput` | `true` | 将 `<input>` 元素限制为小部件指定的日期格式。 |
| `currentText` | `"今天"` | 用于当前日期链接的显示文本。必须与 `showButtonPanel` 属性一起使用才能显示此按钮。 |
| `dateFormat` |   | 用于解析和显示日期的格式。在本章后面的 *更改日期格式* 部分显示了完整的格式列表。 |
| `dayNames` | `[ "星期日", "星期一", "星期二", "星期三", "星期四", "星期五", "星期六" ]` | 用于与 `dateFormat` 属性结合使用的长日期名称列表。 |
| `dayNamesMin` | `[ "日", "一", "二", "三", "四", "五", "六" ]` | 包含在日期选择器小部件中列标题上显示的最小化日期名称的数组。这可以是本地化的，我们将在本章后面看到。 |
| `dayNamesShort` | `[ "周日", "周一", "周二", "周三", "周四", "周五", "周六" ]` | 用于小部件的 `dateFormat` 属性的缩写日期名称列表。 |
| `defaultDate` | `null` | 设置日期选择器打开时将突出显示的日期，当 `<input>` 元素为空时。 |
| `duration` | `"normal"` | 设置日期选择器打开的速度。 |
| `firstDay` | `0` | 设置一周的第一天，从星期日的 `0` 开始，到星期六的 `6` 结束。 |
| `gotoCurrent` | `false` | 将当前日期链接设置为将日期选择器小部件移动到当前选择的日期，而不是今天。 |
| `hideIfNoPrevNext` | `false` | 当不需要时隐藏上一个/下一个链接，而不是禁用它们。 |
| `isRTL` | `false` | 控制所使用的语言是否从右到左绘制。 |
| `maxDate` | `null` | 设置可选择的最大日期。接受日期对象或相对数字。例如：`+7`，或 `+6m` 等字符串。 |
| `minDate` | `null` | 设置可选择的最小日期。接受数字、日期对象或字符串。 |
| `monthNames` | `月份名称数组，例如 [ "一月", "二月", "三月"…]` | 设置用于小部件中 `dateFormat` 属性的完整月份名称列表。 |
| `monthNamesShort` | `缩写月份名称数组，例如["一月", "二月", "三月"…]` | 设置日期选择器小部件中每个月头部使用的缩写月份名称列表，由 `dateFormat` 属性指定。 |
| `navigationAsDateFormat` | `false` | 允许我们使用前一个、下一个和当前链接来指定月份名称。 |
| `nextText` | `"下一个"` | 设置用于下一个月链接的显示文本。 |
| `numberOfMonths` | `1` | 设置在单个日期选择器小部件上显示的月份数。 |
| `onChangeMonthYear` | `Function` | 当日期选择器移到新的月份或年份时调用。 |
| `onClose` | `Function` | 当日期选择器小部件关闭时调用，无论是否选择了日期。 |
| `onSelect` | `Function` | 在选择日期选择器小部件后调用。 |
| `prevText` | `"Prev"` | 设置上一个月链接的显示文本。 |
| `selectOtherMonths` | `false` | 允许选择在当前月面板上显示的上一个月或下一个月的日期（参见`showOtherMonths`选项）。 |
| `shortYearCutoff` | `"+10"` | 在使用年份表示时确定当前世纪；小于此数的数字被视为当前世纪。 |
| `showAnim` | `"show"` | 设置日期选择器小部件显示时使用的动画。 |
| `showButtonPanel` | `false` | 显示一个日期选择器小部件的按钮面板，包括关闭和当前链接。 |
| `showCurrentAtPos` | `0` | 在多月份日期选择器中设置当前月的位置。 |
| `showOn` | `"focus"` | 设置触发显示日期选择器的事件。 |
| `showOptions` | `{}` | 包含控制配置动画的选项的对象文本。 |
| `showOtherMonths` | `false` | 显示前一个月和下一个月的最后一天和第一天。 |
| `showWeek` | `false` | 显示一个显示年周的列。使用`calculateWeek`选项确定周。 |
| `stepMonths` | `1` | 使用上一个和下一个链接导航的月份数。 |
| `weekHeader` | `"Wk"` | 设置要显示为年周列标题的文本。 |
| `yearRange` | `"-10:+10"` | 指定年份下拉菜单中的年份范围。 |

我们将在本章中详细探讨其中一些选项。

## 使用基本选项

将`datepicker1.html`中的最终`<script>`元素更改为以下内容：

```js
<script>  
  $(document).ready(function($){
 $("#date").datepicker({
 appendText: "  (mm/dd/yy)",
 defaultDate: "+5",
 showOtherMonths: true
 });
  });
</script>
```

将此保存为`datePicker2.html`。下面的屏幕截图显示了在配置了这些选项之后小部件的外观：

![使用基本选项](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_03.jpg)

我们在这个示例中使用了许多选项，只因为有这么多的选项可供选择。在日期选择器甚至显示之前的初始页面的外观可以使用`appendText`选项进行更改。这将使用`<span>`元素直接在`<input>`字段后面添加指定的文本字符串，与选择器关联。这有助于访问者澄清将用于日期的格式。

为了样式的目的，我们可以使用`.ui-datepicker-append`类名来定位新的`<span>`元素。

`defaultDate`选项设置了在日期选择器初始打开时突出显示的日期，而`<input>`元素为空。在这个示例中，我们使用了相对的`+5`字符串，因此当日期选择器小部件初始打开时，选择了距当前日期五天的日期。按下键盘上的*Enter*键将选择突出显示的日期。

除了相对字符串，我们还可以将 `null` 作为 `defaultDate` 的值来供应，将其设置为当前日期（主观上的今天），或者使用标准的 JavaScript 日期对象。

正如我们在上一个截图中所看到的那样，日期选择器小部件中当前日期的样式与显示默认日期的样式不同。这将因主题而异，但供参考的是，当前日期以粗体显示，并用浅色（橙色）显示，而所选日期具有比正常日期更深的边框与默认主题。

一旦选择了日期，随后再次打开日期选择器小部件时，将显示所选日期作为默认日期，这再次具有不同的样式（在 redmond 主题下，预选日期将为浅蓝色）。

通过将 `showOtherMonths` 选项设置为 `true`，我们已经向日期表格的开始和结束的空方块中添加了来自上个月和下个月的灰色（不可选择）日期。这些在上一个截图中可见，并且呈现为比可选择日期要浅得多的颜色。

# 最小和最大日期

默认情况下，日期选择器将无限制地向前或向后，没有上限或下限。如果我们想要将可选择的日期限制在特定范围内，我们可以轻松地使用 `minDate` 和 `maxDate` 选项来实现。将 `datePicker2.html` 中的配置对象更改为以下内容：

```js
$("#date").datepicker({
 minDate: new Date(),
 maxDate: "+10"
});
```

将此保存为 `datePicker3.html`。在本例中，我们向 `minDate` 选项提供了一个标准的未修改的 JavaScript 日期对象，这将使过去的任何日期都无法选择。

对于 `maxDate` 选项，我们使用相对文本字符串 `+10`，这将使只有当前日期和接下来的 10 个日期可选择。您可以看到这些选项如何影响小部件的外观在以下截图中：

![最小和最大日期](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_04.jpg)

### 注意

`minDate` 和 `maxDate` 选项也可以采用诸如 `+6w`，`-10m` 或 `1y` 的字符串，分别代表周、月和年。您可以在 [`api.jqueryui.com/datepicker/#option-minDate`](http://api.jqueryui.com/datepicker/#option-minDate) 和 [`api.jqueryui.com/datepicker/#option-maxDate`](http://api.jqueryui.com/datepicker/#option-maxDate) 上找到有关如何设置这些选项的更多详细信息。

# 更改日期选择器界面中的元素

日期选择器 API 公开了许多与在日期选择器中添加或删除额外 UI 元素直接相关的选项。要显示 `<select>` 元素，让访客选择月份和年份，我们可以使用 `changeMonth` 和 `changeYear` 配置选项：

```js
$("#date").datepicker({
 changeMonth: true,
 changeYear: true
});
```

将此保存为 `datePicker4.html`。使用月份和年份的 `<select>` 元素，为用户提供了一个更快的方式来导航到可能遥远的日期。以下截图显示了启用这两个选项后小部件的外观：

![更改日期选择器 UI 中的元素](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_05.jpg)

默认情况下，年份选择框将包括上一个和下一个 10 年，总共涵盖 20 年的范围。我们可以使用前/后箭头链接进一步导航，但如果我们事先知道访问者可能会选择非常久远或未来的日期，我们可以使用`yearRange`选项更改年份范围：

```js
$("#date").datepicker({
  changeMonth: true,
  changeYear: true,
 yearRange: "-25:+25"
});
```

将其保存为`datePicker5.html`。这次运行页面时，我们应该发现年份范围现在总共覆盖了 50 年。

我们还可以对日期选择器的 UI 进行另一个更改，以启用按钮面板，这将在小部件底部添加两个按钮。让我们看看它实际操作时的效果。

更改`datepicker5.html`中的配置对象，使其如下所示：

```js
$("#date").datepicker({ showButtonPanel: true })
```

将其保存为`datePicker6.html`。添加到小部件底部的按钮与对话框小部件中的按钮完全相同，您可以在下图中看到：

![更改日期选择器 UI 中的元素](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_06.jpg)

**今天**按钮将立即将日期选择器导航回显示当前日期的月份，而**完成**按钮将在不选择日期的情况下关闭小部件。

我们还可以更改**今天**按钮，使其转到所选日期而不是当前日期，方法是将其添加到小部件的配置对象中，如下所示：

```js
$("#date").datepicker({
  showButtonPanel: true,
 gotoCurrent: true 
});
```

如果您选择一个日期，然后滚动几个月，您可以通过点击**今天**按钮返回到所选日期。

## 添加一个触发按钮

默认情况下，当与其关联的`<input>`元素接收焦点时，日期选择器会打开。然而，我们可以非常轻松地更改这一点，使得日期选择器在按钮被点击时打开。最基本类型的`<button>`可以通过`showOn`选项仅启用。将`datePicker6.html`中的配置对象更改为以下内容：

```js
$("#date").datepicker({ 
 showOn: "button" 
});
```

将其保存为`datePicker7.html`。在我们的配置对象中将`showOn`选项设置为`true`将会在关联的`<input>`元素后自动添加一个简单的`<button>`元素。我们还可以将此选项设置为`both`，这样当`<input>`聚焦时以及当`<button>`被点击时都会打开。

现在，日期选择器仅在点击`<button>`时打开，而不是在`<input>`聚焦时。此选项还接受字符串值"both"，当`<input>`聚焦时和当`<button>`被点击时打开小部件。新的`<button>`如下图所示：

![添加一个触发按钮](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_07.jpg)

可以通过将新字符串提供为`buttonText`选项的值来轻松更改`<button>`上显示的默认文本（一个省略号）；将之前的配置对象更改为以下内容：

```js
$("#date").datepicker({
  showOn: "button",
  buttonText: "Open Calendar"
});
```

将其保存为`datePicker8.html`。现在，`<button>`上的文本应该与我们设置的`buttonText`选项的值匹配：

![添加触发按钮](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_08.jpg)

我们可以使用图像而不是文本作为`<button>`元素的标签。这是使用`buttonImage`选项配置的：

```js
$("#date").datepicker({
  showOn: "button",
  buttonText: "Open Calendar",
 buttonImage: "img/cal.png"
});
```

将此保存为`datePicker9.html`。`buttonImage`选项的值是一个字符串，由我们想要在按钮上使用的图像的路径组成。请注意，在此示例中，我们还设置了`buttonText`选项。之所以这样做的原因是，`buttonText`选项的值会自动用作`<img>`元素的`title`和`alt`属性，也就是添加到`<button>`中。

我们的触发按钮现在应该如下截图所示：

![添加触发按钮](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_09.jpg)

### 提示

在这个例子中，我们故意没有在这一点上为按钮设置样式，而是专注于添加一个标志。但是，您可以使用 jQuery UI 对其进行样式设置，正如我们将在第八章中看到的*按钮和自动完成小部件*。

如果我们不想使用按钮，我们根本不需要使用按钮；我们可以将`<button>`元素替换为`<img>`元素。因此，将`datePicker9.html`中的配置对象更改为以下内容：

```js
$("#date").datepicker({
  showOn: "button",
  buttonImage: "img/date-picker/cal.png",
  buttonText: "Open Calendar",
 buttonImageOnly: true
});
```

将此保存为`datePicker10.html`。这应该为您提供一个漂亮的仅图片按钮，如下截图所示：

![添加触发按钮](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_10.jpg)

# 配置替代动画

日期选择器小部件带有一个吸引人的内置打开动画，使小部件看起来从无到完整大小。其灵活的 API 还公开了几个与动画相关的选项。这些是`duration`、`showAnim`和`showOptions`配置选项。

我们可以设置的最简单的动画配置是小部件打开和关闭的速度。要做到这一点，我们所要做的就是更改`duration`选项的值。此选项需要一个简单的字符串，可以采用字符串值`slow`、`normal`（默认值）或`fast`，或者表示以毫秒为单位的持续时间的数字。

将`datePicker10.html`中的配置对象更改为以下内容：

```js
$("#date").datepicker({
 duration: "fast"
});
```

将此变体保存为`datePicker11.html`。当我们在浏览器中运行此页面时，应该会发现打开动画明显更快。

除了更改动画的速度之外，我们还可以使用`showAnim`选项更改动画本身。默认使用的动画是简单的显示动画，但我们可以更改为使用库中包含的任何其他显示/隐藏效果之一（请参阅第十四章，*UI 效果*）。将前一个示例中的配置对象更改为以下内容：

```js
$("#date").datepicker({
 showAnim: "drop",
 showOptions: {direction: "up"}
});
```

将其保存为`datePicker12.html`。我们还需要使用两个新的`<script>`资源来使用替代效果。 这些是`jquery.ui.effect.js`和我们希望使用的效果源文件，在本例中为`jquery.ui.effect-drop.js`。 我们将在第十四章中更详细地讨论这两种效果，但它们对于此示例的工作至关重要。 确保将它们添加到文件中，在日期选择器的源文件之后：

```js
<script src="img/jquery.ui.datepicker.js">
</script>
<script src="img/jquery.ui.effect.js"></script>
<script src="img/jquery.ui.effect-drop.js"></script>

```

我们简单的配置对象通过`showAnim`选项配置了下落动画，并使用`showOptions`设置了效果的`direction`选项，由于日期选择器的绝对定位，这是必需的。 当您运行此示例时，日期选择器应该会下降到位，而不是打开。 其他效果可以以相同的方式实现。

## 显示多个月

到目前为止，我们所有的示例都只涵盖了单月日期选择器，一次只显示一个月。 但是，如果我们希望，我们可以很容易地通过一些配置选项来调整显示不同数量的月份。 在`datePicker12.html`中在配置对象之前删除效果源文件，并更改配置对象，以使其如下所示：

```js
$("#date").datepicker({
  numberOfMonths: 3
});
```

将其保存为`datePicker13.html`。 `numberOfMonths`选项接受一个整数，表示我们希望在任何时候在部件中显示的月份数。 我们的日期选择器现在应该看起来像这样：

![显示多个月](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_11.jpg)

### 注

可显示的月份数量没有上限；然而，随着每个额外月份的显示，部件的性能会降低。 在将焦点放在`<input>`上并显示部件之间还有明显的延迟。

此外，各个月份面板是并排的，由于它们的大小，很快将超出视口，导致出现水平滚动条。 但是，一旦使用滚动条，日期选择器将关闭，使得超出屏幕边界的月份无法使用。 出于这些原因，最好将显示的月份数量保持在最低限度。

还有几个与多月份日期选择器相关的配置选项。 `stepMonths`选项控制在使用上一个或下一个链接时更改多少个月份。

`stepMonths`的默认值为`1`，因此在我们先前的示例中，部件以当前月份显示为开始，接着显示接下来的两个月份。 每次单击**上一个**或**下一个**图标时，面板向左或向右移动一个空间。

如果我们将`stepMonths`设置为`3`，与显示的月份数相同，每次单击上一个或下一个链接时，每个月将向左或向右移动三个空间，因此每次单击时都会显示全新的面板。

`showCurrentAtPos` 选项指定了在显示日期选择器时当前月份显示的位置。在我们之前的例子中，当前月份显示为第一个月面板。每个月面板都有一个从零开始的索引号，所以如果我们希望当前月份显示在小部件的中间，我们会将此选项设置为 `1`。

## 以垂直方式显示日期选择器

在前面的示例中，注意到应将使用多个月份的情况保持在最低限度，因为如果日历向右滚动太远，我们无法更改用于宽度的样式。

我们可以通过调整 `numberofMonths` 选项来在一定程度上缓解这个问题。它接受两个属性：第一个是控制我们显示的月份数量，第二个是要使用的列数。如果我们根据 `datepicker13.html` 中的示例设置，将其设置为在单列中显示两个月，它可能如下所示：

![以垂直方式显示日期选择器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_12.jpg)

要实现此效果，我们只需更改 `datepicker13.html` 中的配置对象如下所示：

```js
$("#date").datepicker({
 numberOfMonths: [2, 1]
});
```

您会发现日期选择器现在仅显示两个日历月份，并且现在以垂直格式显示。然后，我们可以使用一点 jQuery 来获取窗口的大小，并根据返回的大小设置 `numberOfMonths` 属性：

```js
function responsive(){
  var winWidth = $(window).width();
   if((winWidth < 991)&&(winWidth >= 768)) { 
    // tablet
    $("#date").datepicker("option", "numberOfMonths", [ 2, 1 ]);
  } else {
    //desktop
    $("#date").datepicker("option", "numberOfMonths", 2 );
  }
}
```

### 注意

无法手动使用 CSS 实现相同的效果；虽然大多数样式可以更改，但容器宽度是硬编码到库中的，无法更改。

## 更改日期格式

`dateFormat` 选项是我们可以使用的高级日期选择器区域设置之一。设置此选项可以让您快速轻松地设置选定日期的格式（显示在 `<input>` 中）使用各种简写引用。日期格式可以是以下任何字符的组合（它们区分大小写）：

+   **d**: 这是月份中的日期（适用时为单个数字）

+   **dd**: 这是月份中的日期（两位数字）

+   **m**: 这是年份中的月份（适用时为单个数字）

+   **mm**: 这是年份中的月份（两位数字）

+   **y**: 这是年份（两位数字）

+   **yy**: 这是年份（四位数字）

+   **D**: 这是缩写的星期几名称

+   **DD**: 这是完整的星期几名称

+   **M**: 这是缩写的月份名称

+   **MM**: 这是完整的月份名称

+   **'...'**: 这是任何文本字符串

+   **@**: 这是 UNIX 时间戳（自 1970 年 1 月 1 日起的毫秒数）

我们可以使用这些简写代码快速配置我们喜欢的日期格式，如以下示例所示。将 `datePicker13.html` 中的配置对象更改为以下内容：

```js
$("#date").datepicker({
 dateFormat:"d MM yy"
});
```

将新文件保存为 `datePicker14.html`。我们使用 `dateFormat` 选项来指定一个包含我们首选日期格式的字符串。我们设置的格式是日期的月份（尽可能使用单个数字）为 `d`，月份的全名为 `MM`，四位数的年份为 `yy`。

当选择日期并将其添加到相关的 `<input>` 中时，它们将按照配置对象中指定的格式，如下面的屏幕截图所示：

![更改日期格式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_13.jpg)

在将字符串用作配置日期的选项值时，我们还可以指定整个文本字符串。但是，如果我们这样做，而字符串中的任何字母都是用作简写的字母，则需要使用单引号对其进行转义。

例如，要将字符串 `Selected:` 添加到日期的开头，我们需要使用字符串 `Selecte'd':`，以避免将小写 `d` 作为月份格式的简写格式：

```js
$("#date").datepicker({
 dateFormat:"Selecte'd': d MM yy"
});
```

将此更改保存为 `datePicker15.html`。请注意，我们如何使用单引号将字符串 `Selected` 中的小写 `d` 转义起来。现在，当选择日期时，我们的文本字符串将被添加到格式化日期的前缀：

![更改日期格式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_14.jpg)

### 提示

**为 <input> 标签添加样式**

您可能希望将 `width: 15em` 添加为输入框的样式，以便您可以清楚地看到整个文本。我已经将这个添加到了附带本书的下载文件中。

还有一些内置的预配置日期格式，对应于常见的标准或 RFC 注释。这些格式作为常量添加到组件中，并可以通过 `$.datepicker` 对象访问。例如，让我们根据 ATOM 标准格式化日期：

```js
$("#date").datepicker({
 dateFormat: $.datepicker.ATOM
});
```

将此保存为 `datePicker16.html`。在此示例中选择日期时，输入到 `<input>` 中的值应该是如下屏幕截图所示的格式：

![更改日期格式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_15.jpg)

### 注意

ATOM 格式或技术上称为 RFC 3339/ISO 8601，是一个国际标准，旨在为日期和时间提供清晰的格式，以避免误解，特别是在数据在使用不同日期格式的国家之间传输时。

预定义日期格式的完整集合列在以下表中：

| 选项值 | 简写 | 格式为… |
| --- | --- | --- |
| `$.datepicker.ATOM` | `"yy-mm-dd"` | **2013-07-25** |
| `$.datepicker.COOKIE` | `"D, dd M y"` | **星期三, 25 七月 2013** |
| `$.datepicker.ISO_8601` | `"yy-mm-dd"` | **2013-07-25** |
| `$.datepicker.RFC_822` | `"D, d M y"` | **星期三, 25 七月 11** |
| `$.datepicker.RFC_850` | `"DD, dd-M-y"` | **星期三, 25-七月-11** |
| `$.datepicker.RFC_1036` | `"D, d M y"` | **星期三, 25 七月 11** |
| `$.datepicker.RFC_1123` | `"D, d M yy"` | **星期三, 25 七月 2013** |
| `$.datepicker.RFC_2822` | `"D, d M yy"` | **星期三, 25 七月 2013** |
| `$.datepicker.RSS` | `"D, d M y"` | **星期三, 25 七月 13** |
| `$.datepicker.TIMESTAMP` | `@ (UNIX 时间戳)` | **1302649200000** |
| `$.datepicker.W3C` | `"yy-mm-dd"` | **2013-07-25** |

# 更新额外的输入元素

有时我们可能想要使用所选日期更新两个 `<input>` 元素，也许以显示不同的日期格式。`altField` 和 `altFormat` 选项可用于满足此要求。在 `datepicker16.html` 页面中添加第二个 `<input>` 元素，其 `id` 属性为 `dateAltDisplay`，然后将配置对象更改为以下内容：

```js
$("#date").datepicker({
 altField: "#dateAltDisplay",
 altFormat: $.datepicker.TIMESTAMP
});
```

将此保存为 `datePicker17.html`。`altField` 选项接受标准的 jQuery 选择器作为其值，并允许我们选择在主 `<input>` 更新时更新的额外 `<input>` 元素。`altFormat` 选项可以接受与 `dateFormat` 选项相同的格式。下面的截图显示了使用日期选择器选择日期后页面应该显示的方式：

![更新额外的输入元素](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_16.jpg)

# 更改日期格式

当使用日期选择器部件时，您可能已经注意到通过 `getDate` 方法（请参阅 *日期选择方法* 部分）以编程方式返回的日期遵循默认的 GMT 日期和时间标准。为了更改 API 返回的日期格式，应使用 `$.datepicker.formatDate()` 实用程序方法。让我们看看如何使用此功能。

在 `datePicker17.html` 中，将日期配置对象更改如下：

```js
      $("#date").datepicker({
 dateFormat: 'yy-mm-dd',
 onSelect: function(dateText, inst) {
 var d = new Date(dateText);
 var fmt2 = $.datepicker.formatDate("DD, d MM, yy", d);
 $("#selecteddate").html("Selected date: " + fmt2);
 }
      });
```

将此保存为 `datePicker18.html`。我们需要添加一个额外的 CSS 样式规则，以便我们可以看到在部件中选择日期的结果。将以下内容添加到我们文件的 `<head>` 中：

```js
<style type="text/css"> 
  #selecteddate { margin-top: 250px; } 
</style>
```

如果我们在浏览器中预览结果，您会发现在配置对象中使用 `dateFormat` 属性设置初始 `<input>` 字段中使用的日期格式；这被设置为 `dd-mm-yy`。在 `onSelect` 事件处理程序中，我们使用 `$.datepicker.formatDate` 将所选日期更改为以下截图中显示的日期：

![更改日期格式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_17.jpg)

## 本地化日期选择器部件

除了已列出的选项外，还有一系列本地化选项。它们可用于提供自定义区域设置支持，以便以替代语言显示日期选择器，或更改英语单词的默认值。

针对特定本地化使用的选项列在下表中：

| 选项 | 默认值 | 用途 |
| --- | --- | --- |
| `closeText` | `"关闭"` | 关闭按钮上显示的文本。 |
| `currentText` | `"今天"` | 当天链接显示的文本。 |
| `dateFormat` | `"mm/dd/yy"` | 当添加到 `<input>` 中时所选日期应采用的格式。 |
| `dayNames` | `["星期日", "星期一","星期二",``"星期三", "星期四", "星期五","星期六"]` | 一周中每天的名称数组。 |
| `dayNamesMin` | `["Su", "Mo", "Tu","We", "Th", "Fr", "Sa"]` | 一周内两个字母的日名称数组。 |
| `dayNamesShort` | `["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"]` | 一周内缩写的星期几名称数组。 |
| `firstDay` | `0` | 指定日期选择器中的第一列天。 |
| `isRTL` | `false` | 将日历格式设置为从右到左。 |
| `monthNames` | `["January", "February",``"March", "April",``"May", "June", "July,``"August", "September",``"October", "November",``"December"]` | 月份名称数组。 |
| `monthNamesShort` | `["Jan", "Feb", "Mar",``"Apr", "May", "Jun",``"Jul", "Aug", "Sep",``"Oct", "Nov", "Dec"]` | 月份缩写名称数组。 |
| `nextText` | `"Next"` | 在下一个链接上显示的文本。 |
| `prevText` | `"Prev"` | 显示在上一个链接上的文本。 |
| `showMonthAfterYear` | `false` | 在小部件标题中将月份显示在年份后面。 |
| `yearSuffix` | `""` | 显示在月份标题中年份后面的附加文本字符串。 |

已经提供了大量不同的翻译，并存储在`development-bundle/ui`目录中的`i18n`文件夹中。每种语言翻译都有自己的源文件，要更改默认语言，我们只需包含替代语言的源文件即可。

在`datePicker17.html`中，在链接到`jquery.ui.datepicker.js`之后直接添加以下新的`<script>`元素：

```js
<script src="img/jquery.ui.datepicker-fr.js">
</script>
```

移除配置对象的`altField`和`altFormat`属性：

```js
$("#date").datepicker();
```

将此保存为`datePicker19.html`，并在浏览器中查看结果：

![本地化日期选择器小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_18.jpg)

通过一个新资源的单个链接，我们已经将日期选择器中的所有可见文本更改为另一种语言，而且我们甚至不需要设置任何配置选项。如果我们想要真正国际化日期选择器，甚至有一个包含所有替代语言的汇总文件，我们可以使用它，而不需要包含多个语言文件。

在`datepicker19.html`中，将`<head>`中的`jquery.ui.datepicker-fr.js`的链接更改为以下代码：

```js
<script src="img/jquery-ui-i18n.js">
</script>
```

接下来，将 datepicker 的配置对象更改为以下内容：

```js
$(document).ready(function($){
  $("#date").datepicker();
  $("#date").datepicker("option", $.datepicker.regional["ar"]); 
});
```

将文件保存为`datepicker20.html`。如果我们在浏览器中预览结果，您将看到它以阿拉伯语显示小部件。我们使用了日期选择器的选项属性将`$.datepicker.regional`设置为`ar`，这是 jQuery UI 对阿拉伯语的代码：

![本地化日期选择器小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_19.jpg)

我们将在本章后面的*动态本地化日期选择器*示例中重新讨论本地化汇总文件。

## 实施自定义本地化

自定义本地化也非常容易实现。这可以使用包含配置的标准配置对象来完成，这些配置是上表选项的配置值。通过这种方式，可以实现未包含在汇总文件中的任何替代语言。

例如，要实现一个`Lolcat`日期选择器，删除`datePicker20.html`的现有配置对象，并添加以下代码：

```js
$("#date").datepicker({
  closeText: "Kthxbai",
  currentText: "Todai",
  nextText: "Fwd",
  prevText: "Bak",
  monthNames: ["January", "February", "March", "April", "Mai", "Jun", "July", "August", "Septembr", "Octobr", "Novembr", "Decembr"],
  monthNamesShort: ["Jan", "Feb", "Mar", "Apr", "Mai", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
  dayNames: ["Sundai", "Mondai", "Tuesdai", "Wednesdai", "Thursdai", "Fridai", "Katurdai"],
  dayNamesShort: ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Kat"],
  dayNamesMin: ["Su", "Mo", "Tu", "We", "Th", "Fr", "Ka"],
  dateFormat: 'dd/mm/yy',
  firstDay: 1,
  isRTL: false,
  showButtonPanel: true
});
```

将此更改保存为`datePicker21.html`。大多数选项用于提供简单的字符串替换。但是，`monthNames`、`monthNamesShort`、`dayNames`、`dayNamesShort`和`dayNamesMin`选项需要数组。

请注意，`dayNamesMin`选项和其他与日期相关的数组应从`星期日`（或相应的本地化）开始；在这里，我们使用`firstDay`选项将`星期一`设置为首先出现的选项。我们的日期选择器现在应该看起来像这样：

![实现自定义本地化](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_20.jpg)

### 注意

对于那些好奇“Lolcat”一词的人，它是一个始于 2006 年的术语，但基于 20 世纪初创作的一系列图像。它用于表示一系列具有（尽管语法不正确或独特）短语的猫图片，旨在制造幽默。您可以在[`en.wikipedia.org/wiki/Lolcat`](http://en.wikipedia.org/wiki/Lolcat)了解更多关于这种独特幽默形式的信息。

## 实现回调

最终的配置选项集与小部件公开的事件模型相关。它由一系列回调函数组成，我们可以使用这些函数在与日期选择器的交互期间的不同时间点指定要执行的代码。

这些列在以下表格中列出：

| 事件 | 当...时触发 |
| --- | --- |
| `beforeShow` | 日期选择器即将打开。 |
| `beforeShowDay` | 在日期选择器中呈现每个单独的日期。可用于确定日期是否可选择。 |
| `onChangeMonthYear` | 当前月份或年份发生变化。 |
| `onClose` | 日期选择器已关闭。 |
| `onSelect` | 选择了一个日期。 |

为了突出这些回调属性有多有用，我们可以将前一个国际化示例扩展为创建一个页面，让访问者可以选择`i18n`捆绑文件中找到的任何可用语言。

## 通过捆绑动态本地化日期选择器

本书早期，我们简要介绍了如何使用捆绑文件更改日期选择器显示的语言。这样可以避免引用多个语言文件，从而有助于减少对服务器的 HTTP 请求；不过，缺点是日期选择器小部件将始终以硬编码到小部件属性中的语言显示。

不过我们可以改变这一点。让我们看看如何通过添加语言选择下拉菜单来使用`beforeShow`回调，以显示选择的语言中的日期选择器。

在`datePicker21.html`中，向页面添加以下新的`<select>`框，并使用以下`<option>`元素。出于简洁起见，我仅在此处包含了一部分；您可以在本书附带的代码下载中看到完整的列表：

```js
<select id="language">
<option id="en-GB">English</option>
<option id="ar">Arabic</option>
<option id="ar-DZ">Algerian Arabic</option>
<option id="az">Azerbaijani</option>
<option id="bg">Bulgarian</option>
<option id="bs">Bosnian</option>
<option id="ca">Catalan</option>
<option id="cs">Czech</option>
...
<option id="en-NZ">English/New Zealand</option>
<option id="en-US">English/United States</option>
<option id="eo">Esperanto</option>
<option id="es">Spanish</option>
<option id="et">Estonian</option>
<option id="zh-HK">Chinese</option>
<option id="zh-TW">Taiwanese</option>
</select>
```

接下来，如下链接到`i18n.js`捆绑文件：

```js
<script src="img/jquery-ui-i18n.js">
</script>
```

现在更改最后一个`<script>`元素，使其如下所示：

```js
<script>  
  $(document).ready(function($){
 $("#date").datepicker({
 beforeShow: function() {
 var lang = $(":selected", $("#language")).attr("id");
 $.datepicker.setDefaults($.datepicker.regional[lang]);
 }
 });
 $.datepicker.setDefaults($.datepicker.regional['']);
  });
</script>
```

将此文件保存为`datePicker22.html`。我们使用`beforeShow`回调来指定每次日期选择器显示在屏幕上时执行的函数。

在该函数内部，我们获取选定的`<option>`元素的`id`属性，然后将其传递给`$.datepicker.regional`选项。使用`$.datepicker.setDefaults()`实用方法来设置此选项。

当页面首次加载时，`<select>`元素不会有选定的`<option>`子元素，由于`i18n` roll-up 文件的顺序，日期选择器将设置为台湾语。为了将其设置为默认的英语，我们可以在日期选择器初始化后将`regional`实用程序设置为空字符串。

下图显示了在`<select>`元素中选择另一种语言之后的日期选择器：

![通过 rollup 动态本地化日期选择器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_21.jpg)

我们可以进一步发展这一点；您可能已经注意到，语言直到点击`<input>`字段内部显示小部件之前都不会改变。

代码可以运行，但感觉有点笨拙；相反，如果我们改变如何显示小部件，我们就可以消除需要点击`<input>`字段内部的必要性。我已经在代码下载中包含了如何做到这一点的示例，命名为`datepickerXX.html`。

# 引入实用方法

在前面例子中，我们使用了日期选择器中可用的实用方法之一，`setDefaults`用于在所有日期选择器实例上设置配置选项。除此之外，还有几种其他实用方法可供我们使用；这些显示在下表中：

| 实用 | 用于... |
| --- | --- |
| `formatDate` | 将`date`对象转换为指定格式的字符串。使用`dateFormat`选项时，使用`formatDate`方法以指定格式返回日期。此方法接受三个参数—转换日期的格式（见选择器的可配置选项中的`dateFormat`），要转换的`date`对象以及包含附加设置的可选配置对象。可以提供以下选项：`dayNamesShort`、`dayNames`、`monthNamesShort`和`monthNames`。 |
| `iso8601Week` | 根据 ISO 8601 日期和时间标准返回指定日期所在的周数。该方法接受一个参数—要显示周数的日期。 |
| `noWeekends` | 使周末日期不可选择。可以传递给`beforeShowDay`事件。 |
| `parseDate` | 对`formatDate`的反操作，将格式化的日期字符串转换为日期对象。它还接受三个参数—要解析的日期的预期格式，要解析的日期字符串以及包含以下选项的可选设置对象：`shortYearCutoff`、`dayNamesShort`、`dayNames`、`monthNamesShort`和`monthNames`。 |
| `regional` | 设置日期选择器的语言。 |
| `setDefaults` | 在所有日期选择器上设置配置选项。此方法接受包含新配置选项的对象文字。 |

所有这些方法都是在`$.datepicker`管理器对象的单例实例上调用的，该对象在初始化时自动创建并用于与日期选择器的实例进行交互。无论在页面上创建了多少个日期选择器作为 jQuery 对象，它们始终会引用在该页面上创建的日期选择器小部件的第一个实例的属性和方法。

# 列出日期选择器方法

除了我们可以使用的广泛的配置选项之外，还定义了许多有用的方法，使得与日期选择器一起工作变得轻松自如。

除了在第一章中讨论的共享 API 方法 *Introducing jQuery UI*，如`destroy`、`disable`、`enable`、`option`和`widget`之外。日期选择器 API 还公开了以下独特的方法：

| 方法 | 用于… |
| --- | --- |
| `dialog` | 在对话框小部件中打开日期选择器。 |
| `getDate` | 获取当前选择的日期。 |
| `hide` | 以编程方式关闭日期选择器。 |
| `isDisabled` | 确定日期选择器是否已禁用。 |
| `refresh` | 重绘日期选择器。 |
| `setDate` | 以编程方式选择日期。 |
| `show` | 以编程方式显示日期选择器。 |

让我们更详细地了解一些这些方法，首先是以编程方式选择日期。

## 以编程方式选择日期

有时（例如在动态、客户端 - 服务器网站上），我们希望能够在程序逻辑中设置特定日期，而无需访问者以通常的方式使用日期选择器小部件。让我们看一个基本示例。

在`datePicker22.html`中删除`<select>`元素，并直接在`<input>`元素之后添加以下`<button>`：

```js
<button id="select">Select +7 Days</button>
```

现在将最后一个`<script>`元素更改为如下所示：

```js
<script>  
  $(document).ready(function($){
 $("#date").datepicker();
 $("#select").click(function() {
 $("#date").datepicker("setDate", "+7");
 });
  });
</script>
```

将其保存为`datePicker23.html`。`setDate`函数接受一个参数，即要设置的日期。与`defaultDate`配置选项一样，我们可以提供一个相对字符串（就像在此示例中所做的那样）或一个日期对象。

### 提示

您可以在[`api.jqueryui.com/datepicker/#utility-formatDate`](http://api.jqueryui.com/datepicker/#utility-formatDate)中查看设置日期对象的一些选项。

如果我们被迫使用字符串作为我们日期选择器的源，我们可以轻松将它们转换为日期对象；为了实现这一点，我们可以使用众多的日期 JavaScript 库，如`Moment.js`。我在本书的附带代码下载中包含了如何使用此库生成我们的日期对象的简单示例。

## 在对话框中显示日期选择器

`dialog`方法产生相同易于使用且有效的日期选择器窗口部件，但它将其显示在一个浮动的对话框中。该方法易于使用，尽管它影响日期选择器对话框的放置；对话框将显示为与日期输入字段分离，我们将会看到。

从页面中删除`<button>`并将`datepicker23.html`中的最终`<script>`元素更改为以下代码：

```js
<script>  
  $(document).ready(function($){
    function updateDate(date) {
      $("#date").val(date);
    }
    $("#date").focus(function() {
      $(this).datepicker("dialog", null, updateDate);
    });
  });
</script>
```

将此保存为`datePicker24.html`。首先我们定义一个名为`updateDate`的函数。当在日期选择器中选择日期时，将自动将所选日期传递给我们页面上的`<input>`元素。

我们使用`focus`事件调用`dialog`方法，该方法接受两个参数。在本例中，我们将第一个参数设为`null`，因此日期选择器默认为当前日期。

第二个参数是一个在选择日期时执行的回调函数，它映射到我们的`updateDate`函数。

我们还可以提供额外的第三和第四个参数；第三个是日期选择器的配置对象，第四个用于控制包含日期选择器的对话框的位置。默认情况下，它将在屏幕中央渲染对话框。

### 提示

您可以在[`api.jqueryui.com/datepicker/#method-dialog`](http://api.jqueryui.com/datepicker/#method-dialog)了解更多关于如何配置这些选项的信息。

# 实现启用 AJAX 的日期选择器

对于我们最终的日期选择器示例，我们将在其中加入一些魔法，并创建一个与远程服务器通信的日期选择器，以查看是否有任何不能选择的日期。然后，这些日期将在日期选择器窗口部件中被标记为不可选择的日期。

更改`datepicker24.html`的`<body>`，使其包含以下标记：

```js
<div id="bookingForm" class="ui-widget ui-corner-all">
  <div class="ui-widget-header ui-corner-top">
    <h2>Booking Form</h2>
  </div>
  <div class="ui-widget-content ui-corner-bottom">
    <label for "date">Appointment date:</label>
    <input id="date">
  </div>
</div>
<script>  
  $(document).ready(function($){
    var months = [], days = [], x; 
    $.getJSON("http://www.danwellman.co.uk/bookedDates.php?
     jsoncallback=?", function(data) {
      for (x = 0; x < data.dates.length; x++) {
        months.push(data.dates[x].month);
        days.push(data.dates[x].day);
      }
    });

    function disableDates(date) { 
      for (x = 0; x < days.length; x++) {
        if (date.getMonth() == months[x] - 1 && date.getDate() == days[x]) {
          return [false, "preBooked"];
        }
      }
      return [true, ""];
    }

    function noWeekendsOrDates(date) {
      var noWeekend = jQuery.datepicker.noWeekends(date);
      return noWeekend[0] ? disableDates(date) : noWeekend;
    }

    $("#date").datepicker({
      beforeShowDay: noWeekendsOrDates,
      minDate: "+1"
    });
  });
</script>
```

我们脚本的第一部分最初声明了两个空数组，然后执行一个请求，从一个 PHP 文件获取 JSON 对象。JSON 对象包含一个名为 dates 的选项。该选项的值是一个数组，其中每个项也是一个对象。

每个子对象都包含月份和日期属性，表示应该使其不可选择的一个日期。月份或日期数组由 JSON 对象中的值填充，以供脚本稍后使用。

接下来，我们定义了在`beforeShowDay`事件上调用的`noWeekendsOrDates`回调函数。该事件对日期选择器中的 35 个单独日期方块中的每一个都会触发一次。甚至空白的方块也包括在内！

每个日期方块的日期都传递给此函数，该函数必须首先确定所选日期是否不是周末，使用 jQuery UI 的`$.datepicker.noWeekends()`函数。如果是，则它会自动传递给`disableDates`函数，否则将被标记为被禁用的。

如果将值传递给`disableDates`函数，则会将从`noWeekendsOrDates`函数发送到它的每个方块的日期传递给它，并且必须返回一个包含最多两个项的数组。

第一个是一个布尔值，指示该日期是否可选择，第二个是可选的日期给出的类名。我们的函数循环遍历我们的月份和日期数组中的每个项目，以查看传递给回调函数的任何日期是否与数组中的项目匹配。如果月份和日期项目都与日期匹配，数组将以`false`和自定义类名作为其项目返回。如果日期不匹配，则返回包含`true`以指示日期可选择的数组。这使我们能够指定日期选择器中无法选择的任意数量的日期。

最后，我们为日期选择器定义一个配置对象。对象的属性只是用于使 JSON 对象中指定的日期不可选择的回调函数，以及将设置为相对值`+1`的`minDate`选项，因为我们不希望人们选择过去的日期或当前日期。

除了 HTML 页面之外，我们还需要一些自定义样式。在您的编辑器中的一个新页面中，创建以下样式表：

```js
#date { width: 302px; }
#bookingForm { width: 503px; }
#bookingForm h2 { margin-left: 20px; }
#bookingForm .ui-widget-content { padding: 20px 0; border-top:  none; }
label { margin: 4px 20px 0; font-family: Verdana; font-size: 80%;
float: left; }
.ui-datepicker .preBooked span { color: #ffffff;
background: url(../img/red_horizon.gif) no-repeat; }
```

将其保存为`datepickerTheme.css`在`css`文件夹中。我们使用 PHP 来响应页面发出的请求并提供 JSON 对象。如果您不想在您的 Web 服务器上安装和配置 PHP，您可以使用我在示例中指定的 URL 放置的文件。对于任何有兴趣的人，使用的 PHP 如下所示：

```js
<?php
  header('Content-type: application/json');
  $dates = "({
    'dates':[
      {'month':12,'day':2},
      {'month':12,'day':3},
      etc...
    ] 
  })";
  $response = $_GET["jsoncallback"] . $dates;
  echo $response;
?>
```

这可以保存为主`jqueryui`项目文件夹中的`bookedDates.php`。

预订日期只是硬编码到 PHP 文件中。同样，在一个适当的实现中，您可能需要一种更健壮的方式来存储这些日期，比如在数据库中。

当我们在浏览器中运行页面并打开日期选择器时，PHP 文件指定的日期应该根据我们的`preBooked`类进行样式设置，并且还应完全不响应，如下面的截图所示：

![实现 AJAX 启用的日期选择器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_07_22.jpg)

# 摘要

在本章中，我们看了一下由 jQuery UI 库中最大的 API 之一支持的日期选择器小部件。这为我们提供了大量可供使用的选项和从中接收数据的方法。我们首先看了默认实现以及小部件自动添加了多少行为。

我们看了日期选择器暴露的丰富 API，其中包括比任何其他组件更多的可配置选项。我们还看到了如何使用日期选择器管理器对象特有的实用函数。

我们看到了小部件是如何轻松实现国际化的。我们还看到，小部件已经被翻译成了其他**34 种语言**。每种语言都被打包成一个模块，可以与日期选择器轻松配合使用，以添加对其他语言的支持。我们还看到了如何创建自定义的语言配置。

我们介绍了在日期选择器交互过程中触发的一些事件，并查看了在代码中可用于处理和控制日期选择器的一系列方法。

在下一章中，我们将看到该库中两个较新的添加，即按钮小部件和自动完成小部件。


# 第八章：按钮和自动完成小部件

按钮和自动完成小部件是库中较新的添加项之一，并随版本 1.8 发布。

传统上，在所有浏览器和平台上一致地为表单元素设置样式是棘手的，并且使情况更加复杂的是，大多数浏览器和平台都以独特的方式呈现表单控件。本章介绍的这两个小部件用于改进 Web 上使用的一些传统表单元素。

按钮小部件允许我们从元素创建外观引人注目且高度可配置的按钮，包括`<button>`、`<input>`和`<a>`元素，可以使用 ThemeRoller 生成的主题进行样式设置。支持的`<input>`元素类型包括`submit`、`radio`和`checkbox`。还可以使用附加功能，如图标、按钮集和分割按钮来进一步增强底层控件。

自动完成小部件附加到标准文本`<input>`上，并用于提供上下文选择菜单。当访客开始在`<input>`元素中输入时，将显示与输入控件中输入的字符匹配的建议。

通过键盘输入，自动完成可以完全访问，允许使用箭头键导航建议列表，使用**Enter**键进行选择，并使用*Esc*键关闭菜单。当使用箭头键导航建议列表时，每个建议都将添加到`<input>`元素中，然后才能进行选择。如果在导航列表后使用*Esc*键关闭菜单，则`<input>`元素的值将恢复为访客输入的文本。

在本章中，我们将介绍以下主题：

+   标准按钮实现

+   可配置选项

+   添加图标

+   按钮事件

+   按钮集

+   按钮方法

+   使用自动完成与本地数据源

+   自动完成的可配置选项

+   自动完成事件

+   自动完成的独特方法

+   使用远程数据源与自动完成

+   在自动完成建议菜单中使用 HTML

# 介绍按钮小部件

按钮小部件用于为一系列元素和输入类型提供一致的、完全主题化的样式。小部件可以从几种不同的元素创建，并且所得到的小部件的 DOM 以及可用的特性将根据使用的元素略有不同。

一个标准的按钮小部件，可以通过`<button>`、`<a>`或`<input>`元素构建，其类型为`button`、`submit`或`reset`，将显示如下：

![介绍按钮小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_08_01.jpg)

## 实现标准按钮

由于按钮可以从几种不同的元素构建，因此我们可以使用一些微小的底层代码变化。 当使用<a>、<button>或<span>元素创建按钮时，小部件将自动创建并嵌套在底层元素内。 这个新的<span>将包含按钮的文本标签。  

要创建链接按钮，请使用以下代码：  

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Button</title>
  <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
  <script src="img/jquery-2.0.3.js"></script>
  <script src="img/jquery.ui.core.js"></script>
  <script src="img/jquery.ui.widget.js"></script>
  <script src="img/jquery.ui.button.js"></script>
</head>
<body>
  <a href="some_other_page.html" id="myButton">A link button</a>
</body>
</html>
```

将此文件保存为`button1.html`。 使用<a>元素作为底层 HTML 时创建按钮所需的脚本可能像这样简单，应该在先前代码的最后一个<script>元素之后添加：  

```js
<script>  
  $(document).ready(function($){
    $("#myButton").button();
  });
</script>  
```

在这种情况下，生成的按钮没有添加任何特殊行为；<a>元素只会将访问者发送到锚点的新页面或指定的页面。 在这种情况下，小部件只是与页面或站点中可能使用的其他 jQuery UI 小部件一致地进行主题设置。 在浏览器中编译时，小部件会自动添加标记——如果您使用像 Firebug 这样的 DOM 检查器，您将看到`button1.html`的以下代码：  

```js
<a href="some_other_page.html" id="myButton" class="ui-button ui-widget ui-state-default ui-corner-all ui-button-text-only" role="button" aria-disabled="false"><span class="ui-button-text">A link button</span></a>
```

按钮小部件需要以下库资源：  

+   `jquery.ui.all.css`  

+   `jquery-2.0.3.js`  

+   `jquery.ui.core.js`  

+   `jquery.ui.widget.js`  

+   `jquery.ui.button.js`  

### 使用<input>或<button>标签创建按钮  

我们不仅限于使用超链接创建按钮；按钮小部件也可以与<input>或<button>标签一起使用。  

在使用`<input>`时，必须设置元素的`type`属性，以便按钮的外观与从其他底层元素创建的按钮的外观相匹配。 对于标准的单个按钮小部件，可以将`type`属性设置为`submit`、`reset`或`button`。  

从<button>元素创建按钮与在`button1.html`中使用的代码相同（只是我们不向<button>标签添加 href 属性）:  

```js
<button id="myButton">A &lt;button&gt; button</button>
```

使用<input>元素创建按钮也非常相似，只是我们使用`value`属性来设置按钮上的文本，而不是将文本内容添加到<input>标记中：  

```js
<input type="button" id="myButton" value="An &lt;input&gt; button">
```

## 主题化  

像所有小部件一样，按钮也有各种添加到它上面的类名，这些类名有助于其整体外观。 当然，如果希望提供自定义样式，我们可以在自己的样式表中使用主题的类名来覆盖正在使用的主题的默认外观。 对于主题按钮，ThemeRoller 通常仍然是最佳工具。  

## 探索可配置选项  

按钮小部件具有以下配置选项：  

| 选项 | 默认值 | 用途 |   |
| --- | --- | --- | --- |
| --- | --- | --- |   |
| `disabled` | `false` | 禁用按钮实例。   |
| `icons` | `{primary: null, secondary: null}` | 设置按钮实例的图标。   |
| `label` | `底层元素或值属性的内容` | 设置按钮实例的文本。   |
| `text` | `true` | 在仅使用图标的实例时隐藏按钮的文本。   |

在我们的第一个示例中，`<a>`元素的文本内容被用作按钮的标签。我们可以通过使用`label`选项轻松覆盖此内容。将`button1.html`中的最终`<script>`元素更改为以下内容：

```js
<script>  
  $(document).ready(function($){
    $("#myButton").button({
      label: "A configured label"
    });
  });
</script>
```

将此文件保存为`button2.html`。正如我们所预期的那样，当我们在浏览器中运行此文件时，我们看到按钮部件内的`<span>`采用配置的文本作为其标签，而不是`<a>`元素的文本内容。

## 添加按钮图标

我们可以轻松地配置我们的按钮，以便在大多数情况下具有最多两个图标。每当`<a>`或`<button>`元素被用作按钮的底层元素时，我们可以使用图标的配置选项来指定一个或两个图标。

要查看图标的效果，请修改`button2.html`中的配置对象，使其显示如下：

```js
$("#myButton").button({
 icons: {
 primary: "ui-icon-disk",
 secondary: "ui-icon-triangle-1-s"
 }
});
```

将此文件保存为`button3.html`。`icons`属性接受一个最多有两个键的对象；`primary`和`secondary`。这些选项的值可以是`jquery.ui.theme.css`文件中找到的任何`ui-icon-`类。我们设置的图标显示如下所示的屏幕截图：

![添加按钮图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_08_02.jpg)

图标是通过额外的`<span>`元素添加到部件中的，这些元素是由部件自动创建并插入的。`primary`图标显示在按钮文本的左侧，而`secondary`图标显示在文本的右侧。

要生成一个只有图标而没有文本标签的按钮，将`button3.html`中的配置对象更改为以下代码：

```js
$("#myButton").button({
  icons: {
    primary: "ui-icon-disk",
    secondary: "ui-icon-triangle-1-s"
  },
 text: false
});
```

将此文件保存为`button4.html`。当我们在浏览器中查看此变体时，我们看到按钮只显示了两个图标，如下面的屏幕截图所示：

![添加按钮图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_08_03.jpg)

## 输入图标

由于子`<span>`元素用于显示指定的图标，所以当使用`<input>`元素作为按钮实例的底层标记时，我们无法使用图标。当使用`<input>`元素时，我们可以通过添加额外的容器、必需的`<span>`元素和一些自定义 CSS 来添加我们自己的图标。

将`button4.html`的`<body>`更改为包含以下元素：

```js
<div class="iconic-input ui-button-text-icons ui-state-default  uicorner-all">
  <span class="ui-button-icon-primary ui-icon ui-icon-disk"></span>
  <input id="myButton" type="button" value="Input icons"class="ui-button-text">
  <span class="ui-button-icon-secondary ui-icon ui-icon-triangle-1-s"></span>
</div>
```

将此文件保存为`button5.html`。我们还需要覆盖一些按钮的样式以供本示例使用。创建一个新的样式表，并将以下基本样式添加到其中：

```js
.iconic-input { display: inline-block; position: relative; }
.ui-icon { z-index: 2; }
.iconic-input input { border: none; margin: 0; }
```

### 注意

在较旧版本的 Internet Explorer 中，`display: inline-block`样式将不会被应用。为了防止按钮占用其容器的整个宽度，我们需要将其浮动，或者显式地设置宽度。

将此文件保存在`css`目录中，名称为`buttonTheme.css`。不要忘记从我们页面的`<head>`元素中链接到新样式表（在标准 jQuery UI 样式表之后）：

```js
<link rel="stylesheet" href="css/buttonTheme.css">
```

从视觉上看，我们基于自定义`<input>`的小部件已经完成，但实际上它还没有完全完成；图标没有正确地捕获悬停状态（这是因为小部件已经将所需的类名应用到了底层的`<input>`元素而不是我们的自定义容器）。我们可以使用 jQuery 添加所需的行为，就像我们已经添加了容器和`<span>`元素一样。更改最终的`<script>`元素中的代码，使其如下所示：

```js
$(document).ready(function($){
 $("#myButton").button().hover(function() {
 $(this).parent().addClass("ui-state-hover");
 }, function() {
 $(this).parent().removeClass("ui-state-hover");
 });
});
```

现在我们的按钮应该按预期工作了。正如上一个示例所示，虽然从技术上讲手动添加元素是可行的，但要将图标添加到从`<input>`元素构建的按钮所需的样式和行为，在大多数情况下，使用`<a>`或`<button>`元素会更容易且更有效。

## 添加按钮事件

由`<a>`元素构建的按钮将按预期方式工作，无需我们进一步干预——浏览器将简单地按照我们期望的方式跟随`href`——只要`<button>`或`<input>`元素位于`<form>`元素内，并设置了相关的类型属性。这些元素将以标准方式提交表单数据。

如果需要更现代的任何`<form>`数据的 AJAX 提交，或者按钮要触发某些其他操作或流程，我们可以使用标准的 jQuery 点击事件处理程序来对按钮的单击做出反应。

在下一个示例中，我们使用以下底层标记构建按钮小部件：

```js
<button type="button" id="myButton">A button</button>
```

按钮小部件公开了一个事件，即`create`事件，该事件在按钮实例最初创建时触发。我们可以使用此事件每次创建按钮实例时运行其他代码。例如，如果我们希望按钮最初被隐藏（以便稍后显示，之后发生其他事情），我们可以使用`.css()`将`display`属性设置为`none`。

将`button5.html`中的`document.ready()`代码替换为以下代码：

```js
$(document).ready(function($){
  $("#myButton").button({
    create: function() {
      $(this).css("display", "none")
    }
  });
});
```

将此文件保存为`button6.html`。在事件处理程序中，`$(this)`指的是按钮实例，使用 jQuery 的`css()`方法隐藏了它。

为了使按钮实现其主要目的，即在单击时执行某些操作，我们应该手动将处理程序附加到按钮上。例如，我们可能希望从访问者那里收集一些注册信息，并使用按钮将此信息发送到服务器。

将`button6.html`中的`<button>`替换为以下代码：

```js
<form method="post" action="serverscript.php">
  <label for="name">Name:
    <input type="text" id="name" name="name">
  </label>
  <label for="email">Email:
    <input type="text" id="email" name="email">
  </label>
  <p>
    <input type="submit" id="myButton" value="Register" />
  </p>
</form>
```

将最终的`<script>`元素更改为以下代码：

```js
<script>  
  $(document).ready(function($){
    var form = $("form"), formData = {
      name: form.find("#name").val(),
      email: form.find("#email").val()
    };

    $("#myButton").button();
    $("#myButton").click(function(e) {
      e.preventDefault();
      form.find("label").remove();
      $("#myButton").button("option", "disabled", true);

      $.post("register.php",$.post("register.php", formData, function() {
        $("<label />", { text: "Thanks for registering!"}).prependTo(form);
      });
    });
  });
</script>
```

将此文件保存为`button7.html`。底层的`<button>`元素现在是一个简单的`<form>`的一部分，该`<form>`只为访问者提供文本输入，他们的姓名和电子邮件地址。在脚本中，我们首先初始化按钮小部件，然后创建一个`click`事件处理程序。这样可以防止浏览器的默认操作，即以传统的非 AJAX 方式提交表单。

然后我们收集输入字段中输入的姓名和电子邮件地址，并使用 jQuery 的`post()`方法异步地将数据发送到服务器。在请求的成功处理程序中，我们使用小部件的`option`方法来禁用按钮，然后创建并显示感谢消息。

在这个例子中，我们不关心服务器端的事情，也不包括任何验证（尽管后者应该在生产中包含），但是你可以看到使用标准的 jQuery 功能来对按钮点击作出反应有多么容易。要看示例的工作方式，我们需要通过 Web 服务器运行该页面，并且应该在与页面相同目录中添加一个与请求中指定名称相同的 PHP 文件（这个文件不需要包含任何内容）。以下截图显示了点击按钮后页面应该显示的样子：

![添加按钮事件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_08_04.jpg)

## 创建按钮组

按钮组件还可以与单选按钮和复选框一起使用。按钮组件在 jQuery UI 中是独一无二的，因为它不止有一个，而是有两个小部件方法。它有我们已经介绍过的`button()`方法，还有用于基于单选按钮和复选框创建按钮组的`buttonset()`方法。

### 复选框按钮组

更改`button7.html`的`<body>`元素，使其包含以下代码：

```js
<div id="buttons">
  <h2>Programming Languages</h2>
  <p>Select all languages you know:</p>
  <label for="js">JavaScript</label>
  <input id="js" type="checkbox">
  <label for="py">Python</label>
  <input id="py" type="checkbox">
  <label for="cSharp">C#</label>
  <input id="cSharp" type="checkbox">
  <label for="jv">Java</label>
  <input id="jv" type="checkbox">
</div>
```

现在更改最终的`<script>`元素，使其如下所示：

```js
$(document).ready(function($){
  $("#buttons").buttonset();
});
```

将此文件保存为`button8.html`。我们只需要在包含`<label>`和`<input>`元素的容器上调用`buttonset()`方法。

当我们在浏览器中运行此文件时，我们会看到复选框被隐藏，`<label>`元素被转换为按钮，并在水平的组中进行可视化分组，如下截图所示：

![复选框按钮组](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_08_05.jpg)

虽然实际的复选框本身被隐藏在按钮后面，但是每当选择按钮时，底层复选框的`checked`属性将被更新，所以我们仍然可以轻松地从脚本中获取状态。

当点击复选框按钮时，小部件会将选定状态应用于它，以便访问者可以轻松地看到它已被选择。正如我们所期望的那样，可以同时选择多个按钮。

在创建复选框按钮时，我们需要遵守一些规则。在 HTML5 中，通常在其关联的`<label>`元素内嵌表单控件（我们在之前的示例中这样做了），但是在使用按钮小部件时，这是不被允许的。需要使用`for`属性与`<label>`元素。

### 单选按钮组

基于单选按钮的按钮与基于复选框的按钮在外观上是相同的；它们的行为不同。同一时间只能选择一个按钮，而使用复选框时可以选择多个按钮。

让我们在`button8.html`中看到这种行为的效果；将`<body>`中的元素更改为以下代码：

```js
<div id="buttons">
  <h2>Programming Languages</h2>
  <p>Select your most proficient languages:</p>
  <label for="js">JavaScript</label>
  <input id="js" type="radio" name="lang">
  <label for="py">Python</label>
  <input id="py" type="radio" name="lang">
  <label for="cSharp">C#</label>
  <input id="cSharp" type="radio" name="lang">
  <label for="jv">Java</label>
  <input id="jv" type="radio" name="lang">
</div>
```

将此文件保存为`button9.html`。初始化单选按钮的脚本相同：我们只需在容器上调用`buttonset()`方法。除了将`type`指定为`radio`之外，底层标记的唯一区别是这些`<input>`元素必须设置`name`属性。

## 使用按钮方法

默认情况下，按钮小部件带有`destroy`、`disable`、`enable`、`widget`和`option`方法，这些方法对所有小部件都是通用的。除了这些方法之外，按钮小部件还公开了一个自定义方法，即`refresh`方法。如果以编程方式更改复选框和单选按钮的状态，可以使用此方法。通过结合前面的一些示例，我们可以看到此方法的作用。

更改`button8.html`的`<body>`，使其包含两个新的`<button>`元素，如下所示的代码：

```js
<div id="buttons">
  <h2>Programming Languages</h2>
  <p>Select all languages you know:</p>
  <label for="js1">JavaScript</label>
  <input id="js1" type="checkbox">
  <label for="py1">Python</label>
  <input id="py1" type="checkbox">
  <label for="cSharp1">C#</label>
  <input id="cSharp1" type="checkbox">
  <label for="jv1">Java</label>
  <input id="jv1" type="checkbox">
</div>
<p>
 <button type="button" id="select">Select All</button>
 <button type="button" id="deselect">Deselect All</button>
</p>

```

在这个示例中，我们已经恢复到复选框，以便我们可以以编程方式选择或取消选择它们作为一组。现在更改最终的`<script>`元素，使其如下所示：

```js
$("#buttons").buttonset();
function buttonSelected(buttonState){
 $("#buttons").find("input").prop("checked", buttonState);
 $("#buttons").buttonset("refresh"); 
}

$("#select").click(function() {
 buttonsSelected(true);
});

$("#deselect").button().click(function() {
 buttonsSelected(false);
});

```

将此文件保存为`button10.html`。如果我们在浏览器中预览结果，您可以通过单击下图所示的**全选**按钮来看到效果：

![使用按钮方法](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_08_06a.jpg)

在这个示例中，我们有一个**全选**按钮和一个**取消全部**按钮。当单击**全选**按钮时，我们将复选框的`checked`属性设置为`true`。这将检查底层（以及隐藏的）复选框，但不会对被样式化为按钮的`<label>`元素执行任何操作。为了更新这些按钮的状态，使它们显示为选定状态，我们调用`refresh`方法。

**取消全部**按钮将`checked`属性设置为`false`，然后再次调用`refresh`方法以从每个按钮中移除所选状态。

# 介绍自动完成小部件

自 jQuery UI 1.8 重新引入的自动完成小部件比以往任何时候都要好。这是我在库中最喜欢的小部件之一，尽管它还没有第一次版本中拥有的全部行为集合，但它仍然提供了丰富的功能集，以增强期望来自预定义范围的简单文本输入的功能。

一个很好的例子是城市；您在页面上有一个标准的`<input type="text">`，询问访问者的城市。当他们在`<input>`元素中开始输入时，将显示包含访问者已键入字母的所有城市。访问者可以输入的城市范围是有限的，并且受限于访问者所在国家（这要么由开发人员假设，要么已被访问者先前选择）。

以下屏幕截图显示了此小部件的外观：

![介绍自动完成小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_08_06.jpg)

像其他小部件一样，在小部件初始化时会以编程方式添加一系列元素和类名。

## 使用本地数据源

要使用本地数组作为数据源实现基本的自动完成，请在新文件中创建以下代码：

```js
<html>
  <head>
  <meta charset="utf-8">
  <title>Autocomplete</title>
    <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
    <script src="img/jquery-2.0.3.js"></script>
    <script src="img/jquery.ui.core.js"></script>
    <script src="img/jquery.ui.widget.js"></script>
    <script src="img/jquery.ui.position.js"></script>
    <script src="img/jquery.ui.menu.js"></script>
    <script src="img/jquery.ui.autocomplete.js"></script>
  </head>
  <body>
    <label>Enter your city:</label>
    <input id="city">
  </body>
</html>
```

在页面上我们所需的只是一个标准的`<input>`元素的`text`类型。自动完成所需的初始化略多于其他组件所需的初始化；在自动完成源文件之后添加以下`<script>`元素：

```js
<script>
  $(document).ready(function($){
    $("#city").autocomplete({ source: [ "Aberdeen", "Armagh", "Bangor", "Bath", "Canterbury", "Cardiff", "Derby", "Dundee", "Edinburgh", "Exeter", "Glasgow", "Gloucester", "Hereford", "Inverness", "Leeds", "London", "Manchester", "Norwich", "Newport", "Oxford", "Plymouth", "Preston", "Ripon", "Southampton", "Swansea", "Truro", "Wakefield", "Winchester", "York" ]});
  });
</script>
```

将此文件保存为`autocomplete1.html`。在我们的自动完成的配置对象中，我们使用`source`选项来指定一个本地字符串数组。`source`选项是强制的，并且必须被定义。然后将该对象传递给`autocomplete`方法，在提供了 autocomplete 关联的城市`<input>`上调用该方法。

当我们在浏览器中运行这个文件时，应该发现当我们开始在`<input>`元素中输入时，将会显示包含我们已输入的字母的源数组中定义的城市的下拉菜单。

为了使自动完成小部件正常工作，需要以下文件：

+   `jquery.ui.all.css`

+   `jquery-2.0.3.js`

+   `jquery.ui.core.js`

+   `jquery.ui.widget.js`

+   `jquery.ui.position.js`

+   `jquery.ui.menu.js`

+   `jquery.ui.autocomplete.js`

## 使用对象数组作为数据源

除了提供一个字符串数组外，我们还可以提供一个对象数组作为数据源，这样我们就可以更灵活地控制菜单中从列表中选择建议时添加到`<input>`的文本。修改`autocomplete1.html`中的配置对象，使其如下所示：

```js
$("#city").autocomplete({
  source: [
 { value: "AB", label: "Aberdeen" },
 { value: "AR", label: "Armagh" },
 { value: "BA", label: "Bangor" },
 { value: "BA", label: "Bath" },
 { value: "CA", label: "Canterbury" },
 { value: "CD", label: "Cardiff" },
 { value: "DE", label: "Derby" },
 { value: "DU", label: "Dundee" },
 { value: "ED", label: "Edinburgh" },
 { value: "EX", label: "Exeter" },
 { value: "GL", label: "Glasgow" },
 { value: "GO", label: "Gloucester" },
 { value: "HE", label: "Hereford" },
 { value: "IN", label: "Inverness" },
 { value: "LE", label: "Leeds" },
 { value: "LO", label: "London" },
 { value: "MA", label: "Manchester" },
 { value: "NO", label: "Norwich" },
 { value: "NE", label: "Newport" },
 { value: "OX", label: "Oxford" },
 { value: "PL", label: "Plymouth" },
 { value: "PR", label: "Preston" },
 { value: "RI", label: "Ripon" },
 { value: "SO", label: "Southampton" },
 { value: "SW", label: "Swansea" },
 { value: "TR", label: "Truro" },
 { value: "WA", label: "Wakefield" },
 { value: "WI", label: "Winchester" },
 { value: "YO", label: "York" }
  ]
});
```

将此文件保存为`autocomplete2.html`。我们现在正在使用作为数据源的数组中的每个项目都是一个对象，而不是一个简单的字符串。每个对象有两个键：`value`和`label`。`value`键的值是从建议列表中选择一个建议时添加到`<input>`元素中的文本。`label`的值是在建议列表中显示的内容。也可以使用其他键存储自定义数据。

如果数组中的每个对象只包含一个属性，则该属性将被用作`value`和`label`键。在这种情况下，我们可能会使用字符串数组而不是对象数组，但值得注意的是本地数据的另一种格式。

# 可配置的自动完成选项

可以设置以下选项来修改小部件的行为：

| 选项 | 默认值 | 用途 |
| --- | --- | --- |
| `appendTo` | `"body"` | 指定将小部件附加到哪个元素。 |
| `autofocus` | `false` | 在显示建议列表时，使列表中的第一个建议获得焦点。 |
| `delay` | `300` | 指定在访客开始在`<input>`中输入后，小部件应在显示建议列表之前等待的毫秒数。 |
| `disabled` | `false` | 禁用小部件。 |
| `minLength` | `1` | 指定访问者需要在`<input>`中输入的字符数，然后建议列表才会显示出来。可以设置为`0`以使部件在菜单中显示所有建议。 |
| `position` | `{ my: "left top", at: "left bottom", collision: "none" }` | 指定建议列表相对于`<input>`元素应该定位的方式。该选项使用方式与我们之前在本书中看到的`position`实用程序完全相同，接受相同的值。 |
| `source` | `Array, String or Function` | 指定用于填充建议列表的数据源。此选项是强制性的，必须进行配置。它将数组、字符串或函数作为其值。 |

## 配置最小长度

`minLength` 选项允许我们指定在建议列表显示之前必须在关联的`<input>`元素中键入的最小字符数。默认情况下，部件显示的建议只包含键入到`<input>`元素中的字母，而不仅仅是以输入字母开头的字母，这可能会导致显示比必要更多的建议。

将`minLength`选项设置为比默认值`1`更高的数字可以帮助缩小建议列表，当处理大型远程数据源时，这可能更加重要。

更改我们在`autocomplete1.html`中使用的配置对象（暂时回到使用字符串数组作为数据源），使其显示如下：

```js
$("#city").autocomplete({
  minLength: 2,
  source: [
    "Aberdeen", "Armagh", "Bangor", "Bath", "Canterbury",
    "Cardiff", "Derby", "Dundee", "Edinburgh", "Exeter","Glasgow", "Gloucester", "Hereford", "Inverness", "Leeds","London", "Manchester", "Norwich", "Newport", "Oxford", "Plymouth", "Preston", "Ripon", "Southampton", "Swansea", "Truro", "Wakefield", "Winchester", "York" 
  ]
});
```

将此文件保存为`autocomplete3.html`。当在浏览器中运行此文件时，我们应该发现需要在`<input>`中键入两个字符，只有包含连续顺序字符的城市才会显示出来，这大大减少了建议的数量。

尽管在这个基本示例中，好处并不明显，但这可以大大减少远程数据源返回的数据量。

## 将建议列表附加到另一个元素

默认情况下，使用自动补全部件时，建议列表会附加到页面的`<body>`中。我们可以更改这一点，并指定列表应添加到页面上的另一个元素。然后自动补全部件使用`position`实用程序来定位列表，使其看起来附加到与其关联的`<input>`元素。我们可以使用`appendTo`选项更改这一点，并指定列表应添加到页面上的另一个元素。

在`autocomplete3.html`中，将基础的`<label>`和`<input>`包装在容器`<div>`中：

```js
<div id="container">
  <label>Enter your city:</label>
  <input id="city">
</div>

```

然后将最终`<script>`元素中的配置对象更改为以下代码：

```js
$("#city").autocomplete({
 appendTo: "#container",
  source: [ "Aberdeen", "Armagh", "Bangor", "Bath", "Canterbury", "Cardiff", "Derby", "Dundee", "Edinburgh", "Exeter", "Glasgow", "Gloucester", "Hereford", "Inverness", "Leeds", "London", "Manchester", "Norwich", "Newport", "Oxford", "Plymouth", "Preston", "Ripon", "Southampton", "Swansea", "Truro", "Wakefield", "Winchester", "York" ]
});
```

将此文件保存为`autocomplete4.html`。通常，建议列表被添加到代码的`<body>`元素的最底部。`appendTo`选项接受一个 jQuery 选择器或实际的 DOM 元素作为其值。

在这个例子中，我们看到列表被附加到我们的`<div>`容器而不是`<body>`元素，我们可以使用 Firebug 或另一个 DOM 浏览器进行验证。

# 处理自动完成事件

自动完成小部件公开了一系列独特的事件，允许我们对与小部件的交互做出程序化反应。这些事件列在下面：

| 事件 | 在...时触发 |
| --- | --- |
| `change` | 从列表中选择了一个建议。此事件在列表关闭并且`<input>`失去焦点后触发。 |
| `close` | 关闭建议菜单。 |
| `create` | 小部件的一个实例已创建。 |
| `focus` | 键盘用于聚焦列表中的建议。 |
| `open` | 显示建议菜单。 |
| `search` | 即将发出建议请求。 |
| `select` | 从列表中选择了一个建议。 |

当我们使用对象数组作为数据源并且除了我们之前使用的`label`和`value`属性之外还有其他数据时，`select`事件非常有用。对于下一个示例，删除我们在上一个示例中使用的`<div>`容器，然后更改配置对象，使其如下所示：

```js
$("#city").autocomplete({
  source: [
    { value: "AB", label: "Aberdeen", population: 212125 },
    { value: "AR", label: "Armagh", population: 54263 }, 
    { value: "BA", label: "Bangor", population: 21735 },
    { value: "BA", label: "Bath", population: 83992 },
    { value: "CA", label: "Canterbury", population: 43432 },
    { value: "CD", label: "Cardiff", population: 336200 },
    { value: "DE", label: "Derby", population: 233700 },
    { value: "DU", label: "Dundee", population: 152320 },
    { value: "ED", label: "Edinburgh", population: 448624 },
    { value: "EX", label: "Exeter", population: 118800 },
    { value: "GL", label: "Glasgow", population: 580690 },
    { value: "GO", label: "Gloucester", population: 123205 },
    { value: "HE", label: "Hereford", population: 55700 },
    { value: "IN", label: "Inverness", population: 56660 },
    { value: "LE", label: "Leeds", population: 443247 },
    { value: "LO", label: "London", population: 7200000 },
    { value: "MA", label: "Manchester", population: 483800 },
    { value: "NO", label: "Norwich", population: 259100 },
    { value: "NE", label: "Newport", population: 137011 },
    { value: "OX", label: "Oxford", population: 149300 },
    { value: "PL", label: "Plymouth", population: 256700 },
    { value: "PR", label: "Preston", population: 114300 },
    { value: "RI", label: "Ripon", population: 15922 },
    { value: "SO", label: "Southampton", population: 236700 },
    { value: "SW", label: "Swansea", population: 223301 },
    { value: "TR", label: "Truro", population: 17431 },
    { value: "WA", label: "Wakefield", population: 76886 },
    { value: "WI", label: "Winchester", population: 41420 },
    { value: "YO", label: "York", population: 182000 }
  ],
  select: function(e, ui) {
    if ($("#pop").length) {
      $("#pop").text(ui.item.label + "'s population is: " + ui.item.population);
    } else {
      $("<p></p>", {
        id: "pop",
        text: ui.item.label + "'s population is: " + ui.item.
          population
      }).insertAfter("#city");
    }
  }
});
```

将此文件保存为`autocomplete5.html`。我们在数组数据源的每个对象中添加了一个额外的属性——每个城市的人口。当选择了一个城市时，我们使用`select`事件获取标签和我们的额外属性，并在页面上写入它们。

我们传递给`select`事件的事件处理程序接受`event`对象和所选数据源中的对象。`.length`测试用于确定页面上是否存在`pop`元素。如果存在，我们只需用更新后的语句替换其中的文本。如果没有，则创建一个具有`pop`的`id`的新`<p>`元素，并将其立即插入到`city`输入字段之后。我们可以以标准方式访问对象中定义的任何属性。

选择了一个城市后，页面应该如下截图所示：

![处理自动完成事件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_08_07.jpg)

# 自动完成方法

除了所有小部件共享的标准方法之外，自动完成还为我们提供了两种允许我们启动某些操作的独特方法。这些独特的方法列在下面：

| 方法 | 用法 |
| --- | --- |
| `close` | 关闭建议菜单。 |
| `search` | 请求从数据源中获取建议列表，并将搜索词作为可选参数指定。 |

`close`方法非常容易使用，我们只需调用`autocomplete`小部件方法，并将`close`指定为参数：

```js
$("#associated_input").autocomplete("close");
```

这将导致关闭建议菜单，并触发`close`事件。关闭事件处理程序的一个可能用法是在用户选择的条目有问题时向用户发出警告；如果它与预定义列表中的条目不匹配，则可以向用户标记这一点。

`search`方法稍微复杂一些，因为它可以接受一个附加参数，尽管这不是强制的。如果调用搜索方法而没有传递参数（这可能是默认行为），则关联的`<input>`元素的值将用作搜索项。或者，术语可以作为参数提供给该方法。

## 处理远程数据源

到目前为止，在这个例子中，我们已经使用了一个相当小的本地数据数组。当处理远程数据源时，自动完成小部件真正发挥其作用，这也是当数据源很大时使用该小部件的推荐方式。

### 根据输入检索内容

在下一个例子中，我们将使用 Web 服务来检索国家列表，而不是使用我们的本地数组。将`autocomplete5.html`中的`<input>`元素更改为以下内容：

```js
<label>Enter your country:</label>
<input id="country">
```

然后改变最后的`<script>`元素，使得配置对象定义如下：

```js
$("#country").autocomplete({
 source: "http://danwellman.co.uk/countries.php?callback=?"
});
```

将此文件保存为`autocomplete6.html`。在这个例子中，我们改变了`<input>`元素，因为我们请求的是访客的国家，而不是城市。

在这个例子中，我们已经将一个字符串指定为源配置对象的值。当将字符串提供给此选项时，字符串应包含指向远程资源的 URL。小部件假定该资源将输出 JSON 数据，并且假定 JSON 数据将以我们之前使用对象数组作为源时看到的格式输出。

因此，当使用简单字符串作为`source`选项的值时，返回的数据应该是一个对象数组，其中每个对象至少包含一个名为`label`的键。对于跨域请求，数据可以是 JSON 或 JSONP 格式。小部件将自动添加查询字符串`term=`，后跟输入到`<input>`元素中的任何内容。

在这个例子中，我指定了自己网站的一个 URL。这个 URL 上的资源将以正确的格式输出数据，所以你可以从你的台式电脑上运行这个例子（甚至不需要一个 Web 服务器），并看到如下屏幕截图中所示的正确行为：

![根据输入检索内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_08_08.jpg)

我应该指出的一个重要点是关于我使用的 PHP 文件。它只会返回以键入到`<input>`元素中的字母开头的条目，而不包含像小部件默认的字母。我想澄清的是，这是我在服务器级别实现的变化，而不是小部件表现出的行为。

因此，在我们控制返回数据的 Web 服务以及数据本身时，将字符串用作`source`选项的值是有用且方便的，因为这通常是当我们控制返回数据的 Web 服务以及数据本身时的情况。如果我们试图从我们无法控制的公共 Web 服务中提取数据，则可能不是这种情况。在这些情况下，我们将需要将函数作为`source`选项的值，并手动解析数据。

## 将函数作为源选项传递

将函数传递给`source`选项，而不是本地数组或字符串，是使用小部件的最强大方式。在这种情况下，我们完全控制请求以及在将数据传递给小部件显示在建议菜单中之前对数据进行处理的方式。

在此示例中，我们将使用返回不符合自动完成预期格式的不同数据的不同 PHP 文件。我们将使用函数来请求和处理数据，然后将其传递给小部件。示例的上下文将是类似于 Facebook 的消息系统的前端，在此自动完成建议可能的消息接收者，但在被选择并添加到`<input>`元素后也可以将其删除。我们将得到的页面将如下截图所示：

![将函数作为源选项传递](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_08_09.jpg)

首先，更改`autocomplete6.html`的`<body>`，使其包含以下标记：

```js
<div id="formWrap">
  <form id="messageForm" action="#">
  <fieldset>
    <legend>New message form</legend>
    <span>New Message</span>
    <label id="toLabel" for="friends">To:</label>
    <div id="friends" class="ui-helper-clearfix">
    <input id="to" type="text">
    </div>
    <label>Subject:</label>
    <input id="subject" name="subject" type="text">
    <label>Message:</label>
    <textarea id="message" name="message" rows="5" cols="50"></textarea>
    <button type="button" id="cancel">Cancel</button>
    <button type="submit" id="send">Send</button>
    </fieldset>
  </form>
</div>
```

然后将最终的`<script>`元素更改为以下内容：

```js
$(document).ready(function($){
  var suggestions = [];

  var getData = function(req, resp){
    $.getJSON("http://danwellman.co.uk/contacts.php?callback=?", req, function(data) {
      var suggestions = [];
      $.each(data, function(i, val){
        suggestions.push(val.name);
      });
      resp(suggestions);
    });
  };

  var selectEmail = function(e, ui) {
    var removeLink = $("<a>").addClass("remove").attr({href: "javascript:", title: "Remove " + friend}); 
    var friend = ui.item.value,
    span = $("<span>").text(friend),
    a = removeLink.text("x").appendTo(span);
    span.insertBefore("#to");
  }

  $("#to").autocomplete({
    source: getData,
    select: selectEmail,
    change: function() {
      $("#to").val("").css("display", 2);
    }
  });

  $("#friends").click(function(){
    $("#to").focus();
  });

  $("#to").click(function(){
    if (this.length != 0) {
      $("#to").val('');
    }
  });

  $(".remove", document.getElementById("friends")).on("click", function(){
  $(this).parent().remove();
  if($("#friends span").length === 0) {
    $("#to").css("top", 0);
    }
  });
});
```

将此文件保存为`autocomplete7.html`。在页面上，我们有一些基本的表单标记和必要的元素，以重新创建类似 Facebook 样式的消息对话框。为了测试效果，尝试在文本框中输入 Admiral Ozzel、Fode 或 Han Solo，然后在自动完成显示其条目时选择其名称。

### 注

自动完成参数只会显示特定的名称；如果您想查看可能的选项，则建议浏览至[`danwellman.co.uk/contacts.php`](http://danwellman.co.uk/contacts.php)。

我们使用一个被样式化的`<div>`元素，看起来就像一个没有样式的实际`<input>`元素，内部包含一个完全没有样式的实际`<input>`。

实际的`<input>`是必需的，以便访问者可以在其中输入，并且可以与自动完成相关联。我们使用`<div>`元素，因为我们无法将构成每个联系人的`<span>`元素插入`<input>`元素中。我们还有一个隐藏的`<input>`元素，将用于存储实际的电子邮件地址。

在脚本中，我们使用`getData`函数作为我们`source`选项的值；每次更新`<input>`字段中的文本时都会调用此函数。我们首先向包含数据的 PHP 文件发出 JSON 请求，然后迭代请求返回的 JSON 对象中的每个项目。

每个新创建的对象都被添加到`suggestions`数组中，一旦返回数据的每个项目都被处理，`suggestions`数组就被传递给`resp`回调函数，该函数作为第二个参数传递给`source`函数。

然后，我们为自动完成的`select`事件定义了`selectEmail`处理程序；此函数将自动传递给两个参数，一个是`event`对象，另一个是包含所选建议的`ui`对象。我们使用这个函数创建一个`<span>`元素来格式化并保存文本，并且一个可以用来移除收件人的锚元素。格式化的`<span>`然后直接插入在伪装的`<input>`元素之前。

最后，我们为`#friends`字段添加了一个点击处理程序，以便在任何人点击它时获得焦点。还为`#to`字段添加了一个点击处理程序，以便如果您在其中单击，它将自动删除先前输入的内容。

我们还需要为这个示例添加一个样式表；在一个新文件中添加以下 CSS：

```js
#formWrap { padding: 10px; position: absolute; float: left; background-color: #000; background: rgba(0,0,0,.5); -moz-border-radius: 10px; -webkit-border-radius: 10px; border-radius: 10px; }
#messageForm { width: 326px; border: 1px solid #666; background-color: #eee; }
#messageForm fieldset { padding: 0; margin: 0; position: relative; border: none; background-color: #eee; }
#messageForm legend { visibility: hidden; height: 0; }
#messageForm span { display: block; width: 326px; padding: 10px 0; margin: 0 0 20px; text-indent: 20px; background-color: #bbb; border-bottom: 1px solid #333; font: 18px Georgia, Serif; color: #fff; }
#friends { width: 274px; padding: 3px 3px 0; margin: 0 auto; border: 1px solid #aaa; background-color: #fff; cursor: text; }
#messageForm #to { margin: 0 0 2px 0; padding: 0 0 3px; position: relative; top: 0; float: left; }
#messageForm input, #messageForm textarea { display: block; width: 274px; padding: 3px; margin: 0 auto 20px; border: 1px solid #aaa; }
#messageForm label { display: block; margin: 20px 0 3px; text-indent: 22px; font: bold 11px Verdana, Sans-serif; color: #666; }
#messageForm #toLabel { margin-top: 0; }
#messageForm button { float: right; margin: 0 0 20px 0; }
#messageForm #cancel { margin-right: 20px; }
#friends span { display: block; width: auto; height: 10px; margin: 0 3px 3px 0; padding: 3px 20px 4px 8px; position: relative; float: left; text-indent: 0; background-color: #eee; border: 1px solid #333; -moz-border-radius: 7px; -webkit-border-radius: 7px; border-radius: 7px; color: #333; font: normal 11px Verdana, Sans-serif; }
#friends span a { position: absolute; right: 8px; top: 2px; color: #666; font: bold 12px Verdana, Sans-serif; text-decoration: none; }
#friends span a: hover { color: #ff0000; }
.ui-menu .ui-menu-item { white-space: nowrap; padding: 0 10px 0 0; }
```

将此文件另存为`autocompleteTheme.css`，放在`css`文件夹中，并且在我们新页面的`<head>`中链接到新文件：

```js
<link rel="stylesheet" href="css/autocompleteTheme.css">
```

当我们在浏览器中运行页面时，我们应该发现我们可以在`<input>`元素中输入，从建议菜单中选择一个名字，并且得到一个格式化和样式良好的名字添加到假输入中。

# 在建议列表中显示 HTML

默认情况下，自动完成小部件将只显示建议列表中每个建议的纯文本。当然，这些纯文本在小部件创建的 HTML 元素内，但是如果我们尝试在数据源中使用 HTML，那么它将被剥离并被忽略。然而，jQuery UI 的当前项目领导者斯科特·冈萨雷斯编写了一个扩展，允许我们在需要时使用 HTML 代替纯文本来显示建议列表中每个建议。

如果我们想要突出显示与访问者在`<input>`元素中输入的内容匹配的建议部分，这可能很方便。我们需要扩展这个示例，可以在[`github.com/scottgonzalez/jquery-ui-extensions/blob/master/src/autocomplete/jquery.ui.autocomplete.html.js`](https://github.com/scottgonzalez/jquery-ui-extensions/blob/master/src/autocomplete/jquery.ui.autocomplete.html.js)找到。

文件可以保存在我们本地`js`目录中，并且在页面中添加对它的引用，放在自动完成源文件后：

```js
<script src="img/jquery.ui.autocomplete.html.js"></script>
```

在我们开始编码之前，让我们看一下在浏览器中预览时的效果：

![在建议列表中显示 HTML](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_08_10.jpg)

在我们的下一个示例中，我们将使用斯科特的插件与自动完成小部件，让用户搜索一些城市名称。如果匹配成功，选择下拉列表中的每个字母将开始改变颜色，只要该字母与文本框中输入的字符匹配。

更改`autocomplete5.html`中的最后一个`<script>`元素，使其如下所示：

```js
$(document).ready(function($){
  var data = [
    { value: "Aberdeen", label: "Aberdeen" },
    { value: "Armagh", label: "Armagh" },
    { value: "Bangor", label: "Bangor" },
    { value: "Bath", label: "Bath" },
    { value: "Canterbury", label: "Canterbury" },
    { value: "Cardif", label: "Cardif" },
    { value: "Derby", label: "Derby" },
    { value: "Dundee", label: "Dundee" },
    { value: "Edinburgh", label: "Edinburgh" },
    { value: "Exeter", label: "Exeter" },
    { value: "Glasgow", label: "Glasgow" },
    { value: "Gloucester", label: "Gloucester" },
    { value: "Hereford", label: "Hereford" },
    { value: "Inverness", label: "Inverness" },
    { value: "Leeds", label: "Leeds" },
    { value: "London", label: "London" },
    { value: "Manchester", label: "Manchester" },
    { value: "Norwich", label: "Norwich" },
    { value: "Newport", label: "Newport" },
    { value: "Oxford", label: "Oxford" },
    { value: "Plymouth", label: "Plymouth" },
    { value: "Preston", label: "Preston" },
    { value: "Ripon", label: "Ripon" },
    { value: "Southampton", label: "Southampton" },
    { value: "Swansea", label: "Swansea" },
    { value: "Truro", label: "Truro" },
    { value: "Wakefield", label: "Wakefield" },
    { value: "Winchester", label: "Winchester" },
    { value: "York", label: "York" }
  ];

  $("#city").autocomplete({
    html: true,
    source: function(req, resp) {
      var suggestions = [], 	
        chosenTerm = "<span>" + req.term + "</span>",
        regEx = new RegExp("^" + req.term, "i");

    $.each(cityList, function(i, val){
      if (val.label.match(regEx)) {
        var obj = {};
        obj.value = val.value;
        obj.label = val.label.replace(regEx, chosenTerm);
        suggestions.push(obj);
        }
      });
      resp(suggestions);
    }
  });
});
```

将此文件保存为`autocomplete8.html`。我们还需要在代码中添加一个样式规则；将其添加到您文件的`<head>`中：

```js
<style>
  span { color:green !important; }
</style>
```

虽然这个例子看起来很简短，但这里有一些关键点需要注意；让我们更详细地探讨我们在代码中使用的内容。

在这个例子中，我们又回到了使用本地对象数组`cityList`。每个对象中的`value`和`label`属性最初保存相同的数据。

在我们的配置对象中，我们指定了一个新的`html`选项，它与 HTML 扩展一起使用。我们将此选项的值设置为`true`，如以下代码所示：

```js
$("#city").autocomplete({
    html: true,
```

在此示例中，我们将一个函数作为`source`选项的值使用。在函数中，我们首先创建一个新的空数组，并定义一个新的正则表达式对象。这将在字符串的开头不区分大小写地匹配`<input>`中键入的任何内容：

```js
source: function(req, resp) {
  var suggestions = [], 
  chosenTerm = "<span>" + req.term + "</span>",
  regEx = new RegExp("^" + req.term, "i");
```

然后，我们遍历数据数组中的每个对象，并测试我们的正则表达式是否与数组中的对象的`label`值匹配。如果有任何项匹配，我们将创建一个新对象并给它`value`和`label`属性。`value`属性（在选择建议时添加到`<input>`元素中）只是来自我们数据数组的相应值，而`label`（显示在建议菜单中的内容）是一个新的字符串，其中包含一个将输入到`<input>`元素中的文本包装在`<span>`元素中的文本：

```js
    $.each(cityList, function(i, val){
      if (val.label.match(regEx)) {
        var obj = {};
        obj.value = val.value;
        obj.label = val.label.replace(regEx, chosenTerm);
        suggestions.push(obj);
      }
```

最后，我们调用`resp`回调，传入新构造的建议数组。我们应该始终确保调用此回调，因为这是小部件所必需的。建议数组为空并不重要，重要的是调用回调。

```js
resp(suggestions);
```

现在，建议菜单中的每个项目都将有一个`<span>`元素，将输入到`<input>`元素中的文本包装起来。我们可以使用它轻微不同地样式化这个文本，比如我们在示例中添加的绿色文本`<style>`。

# 总结

我们在本章中介绍了两个小部件；它们都是库中相对较新的，都与某种形式的`<form>`元素一起使用。按钮小部件可用于将`<a>`、`<button>`和`<input>`（类型为`button`、`submit`或`reset`）转换为具有吸引力和一致样式的丰富小部件。

自动完成小部件附加到一个`text`类型的`<input>`元素上，并在访客开始在`<input>`元素中输入时显示建议列表。该小部件预配置为与本地数据数组或以预期格式输出数据的 URL 一起工作。它还可以配置为处理不符合预期格式的数据。在将数据传递给小部件之前，我们必须先处理要显示的数据，使其成为一个非常灵活和强大的小部件。

我们已经快接近结束覆盖可见小部件的章节，接下来将专注于 jQuery UI 提供的交互助手；让我们在接下来的几章中一起看看库中的两个最新添加，从菜单小部件开始。


# 第九章：创建菜单

菜单小部件，以前是自动完成小部件的一部分，从库的 1.9 版本开始成为一个独立的插件，允许在其他组件中重新使用它。它可以单独使用，将超链接列表转换为可使用键盘或鼠标控制的可主题化菜单，尽管当与其他组件如按钮一起使用时，它真正发挥作用。

每个菜单都有许多与之关联的菜单项，当选择时将将访问者定向到站点的任何部分。当您点击顶级菜单时，一些子菜单项将滑入视图；这些可能具有额外的装饰，如图标，或者如果在访问菜单选项时要阻止访问，则会被禁用。

在本章中，我们将涵盖以下主题：

+   如何将列表转换为具有或不具有子菜单的菜单

+   配置菜单的可用选项

+   为菜单添加样式

+   用图标和分隔符操纵菜单项

+   使用方法

+   以编程方式启用和禁用菜单选项

+   响应事件

+   创建水平和上下文菜单

+   使用 jQuery UI 的菜单扩展`<select>`框

# 实现基本菜单小部件

导航是网页设计的关键元素；一个设计不佳的菜单将永远减少良好内容的吸引力。良好的导航必须既具有美学魅力又具有可用性。使用 jQuery UI 菜单小部件，我们可以为您的网站创建完美的导航。

虽然我们可以使用各种不同的元素来创建我们的菜单，但`<ul>`元素是迄今为止最常用的一个。菜单可以从任何有效的标记创建，只要元素具有严格的父子关系，每个菜单都有自己的锚点。在第一个例子中，我们将采用一系列欧洲城镇并将其转换为基本菜单，我们将进一步探讨结构。

在文本编辑器中新建一个文件，创建以下页面：

```js
<!DOCTYPE HTML>
<html>
  <head>
    <meta charset="utf-8">
    <title>Menu</title>
    <link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
    <style>
      .ui-menu { width: 150px; }
    </style>
    <script src="img/jquery-2.0.3.js"></script>
    <script src="img/jquery.ui.core.js"></script>
    <script src="img/jquery.ui.widget.js"></script>
    <script src="img/jquery.ui.position.js"></script>
    <script src="img/jquery.ui.menu.js"></script>
    <script>
     $(document).ready(function($){
       $("#myMenu").menu();
     });    
    </script>        
  </head>
  <body>
   <ul id="myMenu">
     <!-- Top level menu -->
     <li class="ui-state-disabled"><a href="#">London</a></li>
     <li><a href="#">Antwerp</a></li>
     <li><a href="#">Belgium</a>
       <ul>
         <!-- Second level menu -->         
         <li class="ui-state-disabled"><a href="#">Antwerp </a></li>
         <li><a href="#">Brussels</a></li>
         <li><a href="#">Bruges</a></li>
       </ul>
     </li>
     <!-- Top level menu -->
     <li><a href="#">Brussels</a></li>
     <li><a href="#">Bruges</a>
       <ul>
         <li><a href="#">Belgium</a>
           <ul>
             <li><a href="#">Antwerp</a></li>
             <li><a href="#">Brussels</a></li>
             <li><a href="#">Bruges</a></li>
           </ul>
         </li>
         <!-- Second level menu -->        
         <li><a href="#">Belgium</a>
         <ul>
           <!—Third level menu -->
           <li><a href="#">Antwerp</a></li>
           <li><a href="#">Brussels</a></li>
           <li><a href="#">Bruges</a></li>
         </ul>
       </li>
       <li><a href="#">Paris</a></li>
     </ul>
   </li>
   <li class="ui-state-disabled"><a href="#">Amsterdam</a> </li>
   </ul>
  </body>
</html>      
```

将代码保存为`menu1.html`在您的`jqueryui`工作文件夹中。让我们花点时间熟悉一下制作菜单所需的标记的代码。

我们需要从库中获取以下文件，以从我们选择的元素创建菜单：

+   `jquery-2.0.3.js`

+   `jquery.ui.core.js`

+   `jquery.ui.widget.js`

+   `jquery.ui.position.js`

+   `jquery.ui.menu.js`

当您在浏览器中查看页面时，您会发现我们已经将我们的无序列表转换为一个简单的菜单。在我们的示例中，我们添加了一个额外的样式，与其他库组件不同，菜单小部件需要一些额外的样式，否则它将默认占用其容器的 100%，这将是屏幕。您可以在以下截图中看到结果：

![实现基本菜单小部件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_09_02.jpg)

菜单小部件通常由几个按特定方式排列的标准 HTML 元素构成：

+   调用`menu()`方法的外部容器元素（可以是`<ul>`或`<ol>`元素）

+   每个菜单项中的`<li>`元素内的`<a>`元素

+   每个菜单项的标题元素

### 注：

这些元素可以是硬编码到页面中的，也可以是动态添加的，或者可以根据要求混合使用。

页面上我们所需要的只是一个列表，可以使用`<ul>`或`<ol>`标签。在我们的示例中，我们创建了一个更复杂的示例，jQuery UI 将其转换为具有两级子菜单的菜单。

在首先链接到 jQuery 核心库后，我们链接到所有基于 UI 的组件所需的`jquery.ui.core.js`和`jquery.ui.widget.js`文件，然后链接到文件，最后链接到`jquery.ui.position.js`。然后我们链接到组件的源文件，这在本例中是`jquery.ui.menu.js`。然后我们转到我们的自定义`<script>`元素，在其中添加创建菜单的代码。一旦文档对象模型（DOM）加载并准备就绪，就会立即执行此代码。

在此函数内部，我们只需在代表菜单容器元素的 jQuery 对象上调用`menu()`小部件方法（具有`myTabs` id 的`<ul>`元素）。当我们在浏览器中运行此文件时，应该会看到选项卡的外观与本章第一张截图中的外观相同（当然没有注释）。

# 探索菜单 CSS 框架类

使用 Firefox 的 Firebug（或另一个通用 DOM 浏览器），我们可以看到一系列类名被添加到构成菜单小部件的不同底层 HTML 元素中。

让我们简要回顾一下这些类名，并看看它们如何对小部件的整体外观产生影响。对于外部容器`<ul>`，添加了以下类名：

| 类名 | 应用/应用于 |
| --- | --- |
| `ui-menu` | 菜单的外部容器。 |
| `ui-widget` | 所有小部件的外部容器。它设置小部件的字体系列和字体大小。 |
| `ui-widget-content` | 将内容容器样式应用于元素及其子文本、链接和图标（适用于标题的父元素或同级元素）。 |
| `ui-corner-all` | 将元素的四个角的角半径应用于所有四个角。 |
| `ui-menu-icons` | 通过在初始化菜单时设置的`icons`选项设置的子菜单图标。 |

容器内的第一个元素是`<li>`元素。该元素接收以下类名：

| 类名 | 目的 |
| --- | --- |
| `ui-state-disabled` | 将已禁用的 UI 元素的不透明度变暗。这应该添加到已经有样式的元素中。 |
| `ui-menu-item` | 单个菜单项的容器。 |
| `ui-menu-divider` | 如果添加到`<li>`元素，则在菜单项之间应用分隔符。 |

最后，每个`<li>`元素中的`<a>`元素被赋予以下类名：

| 类名 | 目的 |
| --- | --- |
| `ui-state-focus` | 将可点击焦点容器样式应用于元素及其子文本、链接和图标。 |
| `ui-state-active` | 将可点击的活动容器样式应用于元素及其子文本、链接和图标。 |
| `ui-icon` | 将基础类应用于图标元素。将尺寸设置为 16px 的方块，隐藏内部文本，并将背景图像设置为内容状态精灵图像。此类的背景图像将受父容器的影响；例如，`ui-state-default`容器内的`ui-icon`元素将根据`ui-state-default`的图标颜色进行着色。 |
| `ui-icon-xxx-xxx` | 应用作第二个类来描述图标的类型。图标类的语法通常遵循`.ui-icon-{图标类型}-{图标子描述}-{方向}`的格式。对于指向右侧的单个三角形图标，格式将为`.ui-icon-triangle-1-e`。有关更多图标名称示例，请将鼠标悬停在[ThemeRoller](http://jqueryui.com/themeroller/)中的图标上。 |

大多数这些类名是自动添加到 HTML 元素中的基础库，但显示图标或菜单分隔符的类除外；后者应作为设计菜单结构的一部分添加。有关更多 CSS 类名示例，请查看[CSS 框架](http://api.jqueryui.com/theming/css-framework/)，其中详细介绍了框架中可用的所有 CSS 类，这些类可应用于 jQuery UI 库中的大多数（如果不是全部）小部件。

### 提示

您可能想要查看该链接，该链接详细介绍了构建菜单的一些良好实践：[`developer.apple.com/library/mac/documentation/UserExperience/Conceptual/AppleHIGuidelines/Menus/Menus.html#//apple_ref/doc/uid/TP30000356-TP6`](https://developer.apple.com/library/mac/documentation/UserExperience/Conceptual/AppleHIGuidelines/Menus/Menus.html#//apple_ref/doc/uid/TP30000356-TP6)

# 配置菜单选项

每个库中的不同组件都有一系列选项，这些选项控制了小部件的哪些特性默认启用。可以将对象字面量或对象引用传递给`menu()`小部件方法以配置这些选项。

可用于配置非默认行为的选项如下表所示：

| 选项 | 默认值 | 用途 |
| --- | --- | --- |
| `disabled` | `false` | 如果设置为`true`，则禁用菜单。 |
| `icons` | `{submenu: "ui-icon-carat-1-e"}` | 设置用于子菜单的图标，与 jQuery UI CSS 框架提供的图标匹配。 |
| `menus` | `"ul"` | 为作为菜单容器的元素（包括子菜单）分配选择器。 |
| `position` | `{ my: "left top", at: "right top" }` | 识别与关联的父菜单项相关的子菜单的位置。`of`选项默认为父菜单项，但您可以指定另一个元素来定位。有关如何使用定位小部件的更多详细信息，请参见第二章，*CSS 框架和其他实用工具*。 |
| `role` | `"menu"` | 自定义菜单和菜单项所使用的**可访问丰富互联网应用**（**ARIA**）角色。角色一旦初始化后就无法更改：任何现有的菜单、子菜单或菜单项在创建后将不会更新。 |

# 菜单样式

jQuery UI 库中所有基于 UI 的小部件——菜单小部件也不例外——都可以使用[`jqueryui.com/download/`](http://jqueryui.com/download/)上可用的预建主题之一或使用[`jqueryui.com/themeroller/`](http://jqueryui.com/themeroller/)上的 ThemeRoller 工具进行自定义。您只需要下载您的主题，然后修改代码中的以下行，以反映正在使用的新主题的名称即可：

```js
<link rel="stylesheet" href="development-bundle/themes/redmond/jquery.ui.all.css">
```

如果愿意，甚至可以切换到使用 CDN 连接托管的主题。关键是选择最适合您的开发工作流程和环境的那个。

## 使用图标显示所选菜单选项的状态

在我们的下一个示例中，我们将看到如何通过添加图标来增强所选菜单项的外观。

在你的文本编辑器中，删除`<body>`标签之间的现有标记，并用以下内容替换它：

```js
<body>
  <ul id="myMenu">
    <li><a href="#">File</a></li>
    <li><a href="#"><span class="ui-icon ui-icon-zoomin"></span>Read email</a></li>
    <li><a href="#"><span class="ui-icon ui-icon-zoomout"></span>Move to folder...</a></li>
    <li class="ui-state-disabled"><a href="#"><span class="ui-icon ui-icon-print"></span>Print...</a></li>      
    <li><a href="#"><span class="ui-icon ui-icon-contact"></span> Address Book</a></li>
    <li>
      <a href="#">Edit</a>
      <ul>
      <li><a href="#"><span class="ui-icon ui-icon-pencil"></span>Compose email</a></li>
      <li><a href="#"><span class="ui-icon ui-icon-bookmark"></span>Mark email</a></li>
      <li><a href="#"><span class="ui-icon ui-icon-trash"></span>Send to trash</a></li>
      </ul>
    </li>
  </ul>
</body>
```

我们需要稍微调整一下样式，所以在一个单独的文件中添加以下内容，并将其保存为`menuIcons.css`—不要忘记从你的页面中添加一个链接：

```js
.ui-menu { width: 150px; }
.ui-widget { font-size: 1em; }
```

在`menu1.html`的`<head>`标记中添加对这个新样式表的引用，并重新保存文件为`menu2.html`。我们也可以移除现有的样式，因为这不再需要。当页面在浏览器中加载时，我们现在可以看到已应用到所选菜单项的图标，就像下面的截图中显示的那样：

![使用图标显示所选菜单选项的状态](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_09_03.jpg)

我们甚至可以更进一步，假设我们不喜欢用来指示子菜单存在的图标，并希望更改它。这很容易做到。如下所示，修改上一个示例中的`<script>`块：

```js
<script>
  $(document).ready(function($){
    $("#menu").menu({ 
      icons: { submenu: "ui-icon-circle-triangle-e" }
    });
  });
</script>
```

将此保存为`menu3.html`。如果你现在加载到浏览器中，你会发现图标已经变成了一个圆圈里面的箭头。虽然这已经完美运行了，但稍微调整一下位置会更好。将以下内容添加到`menuIcons.css`样式表中，并保存为`menuIconsOverrides.css`：

```js
.ui-menu-icon { margin-top: 5px; }
```

不要忘记在您的代码中更新 CSS 链接：

```js
<link rel="stylesheet" type="text/css" href="css/menuIconsOverrides.css">
```

让我们在浏览器中预览一下。你会发现图标现在位置更好了，就像这张截图中显示的那样：

![使用图标显示所选菜单选项的状态](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_09_04.jpg)

## 向菜单添加分隔符

到目前为止，我们已经看到如何设置基本菜单并添加图标，您可能经常看到但目前还不具备的一个功能是使用分隔符。菜单分隔符有助于将相关项目分组在一起，或者可以用来将固定菜单项与可能更改的菜单项分开，比如最近的项目列表。

你有两种方法可以实现这个目标：

+   将`class="ui-menu-divider"`添加到`<li>`项。

+   在菜单项之间插入`<li>-</li>`。这些不应该被包含在任何其他标签中，比如`<a>`链接标签。

任何一个选项都可以完美地工作并产生相同的结果，但它们基于不同的原理并具有不同的优点。CSS 选项可能是最具描述性的，但需要更多的标记与您的代码主体。

在`menu2.html`的副本中，按以下方式更改标记：

```js
<ul id="menu">
  <li><a href="#">File</a></li>
 <li class="ui-menu-divider"></li>
  <li><a href="#"><span class="ui-icon ui-icon-zoomin"></span>Read email</a></li>
```

将此保存为`menu4.html`。当加载到您的浏览器中时，您会看到一个菜单分隔符出现，紧跟在**File**菜单选项后面：

![向菜单添加分隔符](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_09_05.jpg)

你也可以通过使用`<li>-</li>`路线来实现这一点；这需要更少的标记，并且更类似于那些习惯于在代码中编程的人使用的方法，比如 C#。在`Address Book`选项后立即更改代码如下：

```js
<li><a href="#"><span class="ui-icon ui-icon-contact"></span>Address Book</a></li>
<li>-</li>
<li><a href="#">Edit</a>
```

样式将由 jQuery UI 自动应用以将其转换为分隔符。

# 使用菜单方法

菜单小部件包含许多不同的方法，除了核心方法如`destroy`、`disable`、`enable`、`option`和`widget`之外，这意味着它具有丰富的不同行为。它还支持实现高级功能，使我们能够以编程方式与之一起工作。让我们看看下表中列出的方法：

| 选项 | 使用 |
| --- | --- |
| `blur` | 从菜单中移除焦点，重置任何活动元素样式，并触发菜单的`blur`事件。 |
| `collapse` | 关闭当前活动的子菜单。 |
| `collapseAll` | 关闭所有打开的子菜单。 |
| `expand` | 打开当前活动项目下方的子菜单（如果存在）。 |
| `focus` | 激活特定菜单项，开始打开任何子菜单（如果存在），并触发菜单的`focus`事件。 |
| `isFirstItem` | 返回一个布尔值，指示当前活动项目是否是菜单中的第一个项目。 |
| `isLastItem` | 返回一个布尔值，指示当前活动项目是否是菜单中的最后一个项目。 |
| `next` | 将活动状态移至下一个菜单项。 |
| `nextPage` | 将活动状态移至滚动菜单底部下方的第一个菜单项，如果菜单不可滚动，则移至最后一个项目。 |
| `option` | 在小部件初始化后获取或设置任何属性。 |
| `previous` | 将活动状态移至前一个菜单项。 |
| `previousPage` | 将活动状态移至可滚动菜单顶部的第一个菜单项上方或如果不可滚动，则移至第一个菜单项。 |
| `refresh` | 初始化尚未初始化的子菜单和菜单项，一旦添加了新项或内容。 |
| `select` | 选择当前活动的菜单项，折叠所有子菜单，并触发菜单的`select`事件。 |

让我们在接下来的几节中看一下其中一些选项，从启用和禁用菜单选项开始。

# 以编程方式启用和禁用菜单选项

使用菜单时的常见需求是根据它是否符合特定条件来启用或禁用选项，例如，如果不可用打印功能，则可能禁用打印选项。

人们希望在菜单小部件内有一个可用的选项来执行此操作。可惜！没有。唯一可用的方法是禁用或启用整个菜单，而不是特定的菜单项。不过没关系，我们可以使用`ui-state-disabled`类和一点点 jQuery 魔法来达到相同的效果。

直接在`menu2.html`的菜单小部件的现有标记后添加以下新的`<button>`元素：

```js
<p>
  <form>
    <input type="button" id="disableprint" value="Disable printing" />
    <input type="button" id="enableprint" value="Enable printing" />
  </form>
<p>
```

接下来，将`<script>`元素更改为以下内容：

```js
<script>  
  $(document).ready(function($){
    $("#myMenu").menu();

 $("#disableprint").click(function() {
 $("ul li:nth-child(4)").addClass("ui-state-disabled ui-menu-item");
 });

 $("#enableprint").click(function() {
 $("ul li:nth-child(4)").removeClass("ui-state-disabled");
 });
  });
</script>
```

将更改后的文件保存为`menu5.html`。在 jQuery 中，我们使用了伪选择器来查找第四个元素（而不是第三个——计数从 0 开始，而不是 1），然后使用`removeClass`或`addClass`根据需要添加或删除`ui-state-disabled`类。

你会注意到在禁用菜单项时，我们删除了所有类，这纯粹是为了当我们添加 CSS 样式来标记项目为禁用时，它以正确的顺序添加 CSS 样式。你可以在两种情况下都使用`.removeClass()`选项，但是 CSS 标记顺序将不匹配已禁用的**打印...**选项！

![以编程方式启用和禁用菜单选项](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_09_06.jpg)

# 添加和删除菜单项

除了以编程方式启用或禁用菜单项之外，我们还可以动态添加或删除菜单项。在`menu2.html`中，在现有标记后立即添加以下代码：

```js
<p>
  <form>
    <input type="button" id="additem" value="Add menu item" />
  </form>
</p>
```

然后将最后的`<script>`元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
    $("#myMenu").menu();
 $("#additem").click(function() {
 $("<li><a href='#'>New item</a></li>").appendTo("#myMenu");
 $("#myMenu").menu("refresh");
 });
  });
</script>
```

将更改保存为`menu6.html`。在此页面上，我们添加了一个新的`<input>`元素，我们将使用它来添加一个新的菜单项。

在`<script>`元素中，我们的函数通过首先构建所需的标记来处理添加菜单项。然后我们将其附加到`myMenu`菜单中，然后调用菜单的`refresh()`方法来更新显示。添加几个菜单项后，页面应该看起来像这样：

![添加和删除菜单项](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_09_07.jpg)

为了不逊色，我们可以使用相同的 `refresh()` 方法来移除一个菜单项，尽管我们需要使用的过程来查找要移除的项目会发生变化。让我们来看看如何做到这一点，修改 `<form>` 标记的内容，如下所示：

```js
<form>
 <input type="button" id="removeitem" value="Remove menu item" />
</form>
```

接下来，按照以下方式更改 `menu6.html` 中的 `<script>` 元素：

```js
<script>
  $(document).ready(function($){
    $("#myMenu").menu();
    $("#removeitem").click(function() {
      $("#ui-id-3").remove();
      $("#myMenu li:nth-child(3)").remove();
      $("#myMenu").menu("refresh");
    });
  });
</script>
```

将更改保存为 `menu7.html`。如果我们在浏览器中加载页面，并点击 **Remove menu item** 按钮，您将发现 **Move to folder…** 菜单选项已被移除：

![添加和移除菜单项](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_09_08.jpg)

# 处理菜单事件

菜单小部件定义了一系列有用的选项，允许您在检测到小部件公开的某些事件时添加回调函数以执行不同的操作。以下表格列出了能够在事件上接受可执行函数的配置选项：

| 事件 | 触发时... |
| --- | --- |
| `blur` | 菜单失去焦点 |
| `create` | 菜单已创建 |
| `focus` | 当菜单获得焦点或任何菜单项被激活时 |
| `select` | 选择了一个菜单项 |

库的每个组件都有回调选项（例如前面表格中的选项），这些选项被调整为在任何访问者交互的关键时刻进行查找。我们在这些回调中使用的任何函数通常会在更改发生之前执行。因此，您可以从回调中返回 `false` 并阻止操作发生。

下面是我们的下一个示例，我们将看看使用标准的非绑定技术来对特定菜单项的选择做出反应是多么容易。在 `menu1.html` 中删除最后的 `<script>` 元素，并将其替换为以下内容：

```js
<script>
  $(document).ready(function($){
    var menuarray;    
    $("#myMenu").menu({
      select: function(event, ui) {
        $('.selected', this).removeClass('selected');
        ui.item.addClass('selected');
        menuarray = ui.item.text().split(" ");
        $("#menutext").").text("You clicked on: " + menuarray[0]);
      },
      focus: function(event, ui) {
        if ($("#menutext").text() != "") {
          $("#menutext").removeClass("normaltext").
addClass("hilitetext");
        }        
      },
      blur: function(event, ui) {
        $("#menutext").removeClass("hilitetext").
addClass("normaltext");
       }
    });
  });      
</script>
```

在最终的 `</ul>` 标记之后，添加以下内容：

```js
<div id="menutext"></div>
```

将此文件保存为 `menu8.html`。我们还需要一些 CSS 来完成此示例；在您的文本编辑器中的新页面中，添加以下代码：

```js
#menutext { width: 150px; font-family: Lucida Grande,Lucida
   Sans,Arial,sans-serif; text-align: center; }
.ui-menu { width: 150px; }
.hilitetext { background-color:  #a6c9e2; padding: 3px; border-radius: 4px; margin-top: 6px; }
.normaltext { background-color: #fff; padding: 3px; margin-
  top: 6px; }
.selected { background-color : #313c43;  border-radius: 4px; }
.selected a { color: #fff; }
```

将此文件保存为 `menuEvents.css`，并放入 `css` 文件夹中。在我们刚刚创建的页面的 `<head>` 元素中，添加以下 `<link>` 元素：

```js
<link rel="stylesheet" href="css/menuEvents.css">
```

如果我们预览结果，当在菜单中导航时，我们将看到以下屏幕截图中显示的内容。注意菜单下方显示的选定菜单项：

![处理菜单事件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_09_09.jpg)

在我们的示例中，我们使用了三个回调函数— `select`、`focus` 和 `blur`；对于库中其他小部件触发的任何其他回调，原则上基本相同。

当小部件执行回调函数时，将自动传递两个参数。这些是原始事件对象和包含有用属性的自定义对象，该对象来自于所选菜单。

在我们的示例中，我们使用 `select` 回调来确定所选菜单项的标题，然后为其分配 `.selected` 类以指示已选中；`blur` 和 `focus` 回调用于在我们的菜单中导航时提供悬停功能。

# 绑定到事件

使用每个组件提供的事件回调是处理交互的标准方式。然而，除了前面表格中列出的回调之外，我们还可以在不同时间钩入到每个组件触发的另一组事件中。

我们可以使用标准的 jQuery `on()`方法将事件处理程序绑定到由菜单小部件触发的自定义事件，就像我们可以绑定到标准的 DOM 事件一样，比如点击事件。

以下表格列出了菜单的自定义绑定事件及其触发条件：

| 事件 | 触发条件 |
| --- | --- |
| `Menucreate` | 菜单被创建 |
| `Menuselect` | 选择了菜单项 |
| `Menufocus` | 菜单获得焦点或任何菜单项被激活时 |
| `Menublur` | 菜单失去焦点 |

第一个事件`menucreate`被触发，一旦菜单对象被初始化；接下来的三个事件将根据用户是否选择了菜单项而被触发。

让我们看看这种事件使用在实际中的情况；将`menu8.html`中最后一个`<script>`元素更改为以下内容：

```js
<script>
  $(document).ready(function($){
    var menuarray;  
    $("#myMenu").menu();

 $("#myMenu").on("menuselect", function( event, ui ) {
      $('.selected', this).removeClass('selected');
      ui.item.addClass('selected');  
      menuarray = ui.item.text().split(" ");
      $("#menutext").text("You clicked on: " + menuarray[0]);
 }); 

 $("#myMenu").on("menufocus", function( event, ui ) {
      if ($("#menutext").text() != "") {
        $("#menutext").removeClass("normaltext")       .addClass("hilitetext");
      }  
 });

 $("#myMenu").on("menublur", function( event, ui ) {
      $("#menutext").removeClass("hilitetext")
.addClass("normaltext");
 });
  });      
</script> 
```

将这个更改保存为`menu9.html`。以这种方式绑定到`menuselect`事件会产生与上一个示例相同的结果，使用`select`回调函数。与上次一样，选择菜单项时应该出现确认文本。

所有小部件暴露的事件都可以使用`on()`方法，只需将小部件的名称前缀添加到事件的名称即可。

# 创建水平菜单

你注意到了吗？在本章中，所有的菜单示例都是垂直的。这不是偶然，而是因为在写作时，菜单小部件还没有创建水平菜单的选项。

不过，这并不是问题，因为使用位置小部件的功能和一些额外的样式很容易创建水平菜单。在这个例子中，我们将看看如何实现这个效果，并将其更新为 jQuery 版本 2。

### 注意

许多人尝试过这样做，成功的程度不同——我个人最喜欢的是*Aurélien Hayet*制作的版本，我们将在本例中使用。如果你想看到*Aurélien Hayet*的原始文章（法语），可以在[`aurelienhayet.com/2012/11/03/ comment-realiser-un-menu-horizontal-a-laide-de-jquery-ui/`](http://aurelienhayet.com/2012/11/03/ comment-realiser-un-menu-horizontal-a-laide-de-jquery-ui/)中找到。

删除`menu2.html`中现有的菜单标记，并用以下内容替换，将其保存为`menu10.html`：

```js
<body> 
  <ul id="menu"> 
    <li><a href="#">Item A</a></li> 
    <li><a href="#">Item B</a></li> 
    <li><a href="#">Item C</a> 
      <ul> 
        <li><a href="#">Item C-1</a></li> 
        <li><a href="#">Item C-2</a></li> 
        <li><a href="#">Item C-3</a></li> 
        <li><a href="#">Item C-4</a> 
         <ul> 
           <li><a href="#">Item C-4-1</a></li> 
           <li><a href="#">Item C-4-2</a></li> 
           <li><a href="#">Item C-4-3</a></li> 
           <li><a href="#">Item C-4-4</a></li> 
           <li><a href="#">Item C-4-5</a></li> 
         </ul> 
       </li> 
       <li><a href="#">Item C-5</a></li> 
     </ul> 
    </li> 
    <li><a href="#">Item D</a></li> 
    <li><a href="#">Item E</a></li> 
  </ul> 
</body> 
```

将最后一个`<script>`元素修改如下：

```js
<script> 
  $(document).ready(function($){
    $("#menu").menu({ position: { using: setSubMenu} }); 
    $("#menu > li > a > span.ui-icon-carat-1-e").removeClass("ui-icon-carat-1-e").addClass("ui-icon-carat-1-s"); 
    function setSubMenuposition, elements) { 
      var options = { of: elements.target.element }; 
      if (elements.element.element.parent().parent().attr("id") === "menu") { 
        options.my = "center top"; 
        options.at = "center bottom"; 
      } else { 
        options.my = "left top"; 
        options.at = "right top"; 
      } 
     elements.element.element.position(options); 
    }; 
  });
</script> 
```

我们需要稍微调整样式才能将其转换为水平菜单，因此将以下内容添加到一个新文档中，并将其保存为`css`文件夹中的`menuHorizontal.css`。不要忘记从主文档中添加链接：

```js
.ui-menu { width: 100px; font-size: 12px; min-height: 22px; } 
 ul#menu { width: 500px; }   ul#menu > li { width: 100px; float: left; }
```

在加载到浏览器中时，页面应该看起来像这样：

![创建水平菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_09_10.jpg)

在写作时应该注意，MenuBar 小部件正在制作中；您可以在[`view.jqueryui.com/menubar/demos/menubar/default.html`](http://view.jqueryui.com/menubar/demos/menubar/default.html)看到一个版本。在这个开发版本上仍然有一些需要解决的错误和要完成的功能，但它仍然是一个可用的小部件，您可以自行下载并尝试使用，但需自担风险。

# 与其他小部件结合

现在让我们换个方式，看一下您如何使用菜单小部件的更多深入示例，首先是将其与按钮一起使用。

你可能会说这是一个奇怪的组合，但实际上并非如此；我们可以使用这两者来构建一个带有下拉菜单的不错的分割按钮！

### 注意

幸运的是，*Mike Cantrell*已经创建了一个插件；我们将在我们的示例中使用这个插件。您可以从 Github（[`gist.github.com/mcantrell/1255491`](https://gist.github.com/mcantrell/1255491)）下载该插件的副本；我已经更新了代码下载中用于 jQuery 2.0 和 UI 1.10.3 的版本。

在`menu2.html`中的链接到`jquery.ui.menu.js`之后，添加以下内容：

```js
<script src="img/jquery.ui.button.js"></script>
<script src="img/jquery.ui.splitbutton.js"></script>
```

将最后一个`<script>`元素修改如下：

```js
<script>
  $(document).ready(function($){
 $("#split-button").splitButton();
  });     
</script>        
```

用以下内容替换`<body>`标签之间的现有标记：

```js
<div>
  <a href="http://www.packtpub.com" id="split-button">Edit</a>
  <a href="#">Menu</a>
</div>
<ul style="display:none;">
  <li><a href="#">Print</a></li>
  <li><a href="#">Copy</a></li>
  <li><a href="#">Delete</a></li>
</ul>  
```

将文档保存为`menu11.html`。我们需要添加一些魔法，将我们的菜单和文档组合在一起，所以在一个新文档中添加以下内容，并将其保存为`jquery.ui.splitbutton.js`，放在`js`文件夹中：

```js
(function($) {
  $.fn.splitButton = function(options) {
    var menu = null;
    var settings = {
      selected: function(event, ui) {
        document.location = ui.item.children()[0];
      },
      showMenu: function() {
        if (menu) menu.hide();
        menu = $(this).parent().next().show().position({
          my: "left top", at: "left bottom", of: $(this).prev()
        });
        $(document).one("click", function() { menu.hide(); });
        return false;
      }
    };
    if (options) { $.extend(settings, options); }
    var buttonConfig = { text: false, icons: { primary: "ui-icon-triangle-1-s" }};
    return this.button().next().button(buttonConfig).click(settings
     .showMenu).parent().buttonset().next().menu({select: settings.selected});
   };
})(jQuery);
```

为了完成效果，我们需要稍微调整 CSS 样式，所以将以下内容添加到一个新文档中，并将其保存为`menuSplit.css`，放在`css`文件夹中：

```js
#menutext { width: 150px; font-family: Lucida Grande,Lucida Sans,Arial,sans-serif; text-align: center; }
.ui-menu { width: 150px; }
```

不要忘记在您的代码中添加一个指向`menuSplit.css`的链接。如果我们将页面加载到浏览器中，您应该会看到类似于以下截图的内容：

![与其他小部件结合](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_09_11.jpg)

虽然这个例子中的**Edit**文本不会改变，但您可以轻松地根据自己的需求进行调整，为下拉菜单列表中的每个选项添加有效链接。

# 设计上下文菜单

目前，jQuery UI 尚不支持的一个菜单格式是上下文菜单；越来越多的应用程序依赖于上下文菜单，以快速访问选项，例如格式化内容。

然而，在 jQuery 中复制这种相对简单的配置是相对容易的。在我们的下一个示例中，我们重用了主 UI 网站的一些标准 HTML 标记，并将其转换为上下文菜单。这表明，借助一点 jQuery 魔法，标记实际上并不需要改变 —— 一笔交易！

### 注意

对于这个练习和下一个练习，您将需要本书附带的代码下载副本。我们将使用代码下载中的一些文件。

创建好页面后，我们可以通过右键单击图像在浏览器中查看结果。它应该类似于以下截图：

![设计上下文菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_09_12.jpg)

### 注意

图片可以在[`upload.wikimedia.org/wikipedia/commons/2/25/Coffee_Roasting.jpg`](http://upload.wikimedia.org/wikipedia/commons/2/25/Coffee_Roasting.jpg)找到。

让我们从代码下载中提取`menu2.html`的副本，并将其保存到`jqueryui`文件夹中。接下来，将最后的`<script>`元素更改为如下所示：

```js
<script>
  $(document).ready(function($){
    $("#myMenu").menu({
      select: function (event, ui) {
        $("#myMenu").hide();
        alert("Menu element clicked!");
      }
    });
    $("#contextMenu").on("contextmenu", function (event) {
      $("#myMenu").show();
      $("#myMenu").position({ collision: "none", my: "left top",
        of: event });
      return false;
    });
    $("#contextMenu").click(function (event) {
      $("#myMenu").hide();
    });
    $("#myMenu").on("contextmenu", function (event) { return false; });
  });
</script>
```

将更改后的文件保存为`jqueryui`文件夹中的`menu12.html`。我们需要稍微调整样式，因此将以下内容添加到新文档中，并将其保存在`css`文件夹中为`menuContext.css`：

```js
body { color: #fff; font-family: 'Doppio One', sans-serif; text-shadow: 0 1px 0 rgba(0,0,0,.3); line-height: 1.5; -webkit-font-smoothing: antialiased; }
.ui-menu { width: 150px; }
#menu { position: absolute; display: none; }
#contextMenu { color: #000; }
```

将此文件保存为`css`文件夹中的`menuContext.css`，并在`menu12.html`的`<head>`部分的 jQuery UI 样式表之后链接到它：

```js
<link rel="stylesheet" type="text/css" href="menuContext.css"> 
```

通过使用菜单的位置属性和一点额外的 jQuery 魔法，我相信您会同意这产生了一个非常好的结果！

# 增强选择菜单

在我们最终的菜单示例中，让我们看看如何使用菜单小部件的功能来增强`<select>`菜单。本书的原始作者*丹·韦尔曼*提供了一个很好的示例，演示了如何使用一些额外的 jQuery 和我们在本书中早些时候已经介绍过的技术来实现这一点。我已经更新了它，使其适用于 jQuery 2.03 和 UI 1.10.3。

用以下内容替换`menu2.html`中的现有标记：

```js
<body>
 <select id="selectmenu">
 <option>Option 1</option>
 <option>Option 2</option>
 <option>Option 3</option>
 <option>Option 4</option>
 <option>Option 5</option>
 </select>
</body>
```

从本书附带的代码下载中提取`menuSelect.js`文件的副本，然后将其保存在`js`文件夹中，并在最后的 jQuery UI 库引用`jquery.ui.menu.js`之下立即链接到它。

在`menu2.html`中，将第二个`<link>`更改为指向一个新的样式表，如下所示：

```js
<link rel="stylesheet" href="css/menuSelect.css">
```

在`menuSelect.css`中添加以下内容：

```js
.ui-menu-container { width: 200px; height: 26px; padding: 4px 0 0
   4px; position: relative; cursor: pointer; }
.ui-menu { position: absolute; right: 0; top: 100%; }
.ui-menu .ui-menu-item a { padding: 2px 20px; }
.ui-menu-trigger { padding: 0 3px; margin: -1px 3px; float: right; text-decoration: none; }
```

将页面保存为`menu13.html`。如果我们将页面加载到浏览器中并进行预览，您将看到类似于此屏幕截图的内容：

![增强选择菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-110/img/2209OS_09_13.jpg)

在这个例子中，我们使用了相当多的 jQuery；这将使它适合成为一个插件，可以包含在页面中，并用于增强现有的`<select>`菜单。如果编写正确，它将使用渐进增强技术工作，同时保持原始基础代码在没有 jQuery 可用的情况下的可用性。

# 摘要

菜单小部件是一种极好的节省页面空间的方法，通过组织相关（甚至完全不相关）的内容部分，您的访问者可以通过简单的点击输入来显示或隐藏这些内容。

让我们回顾一下本章涵盖的内容。我们首先看了一下如何仅使用一点点基础 HTML 和一行 jQuery 风格的 JavaScript 就可以实现默认菜单小部件。然后，我们看了一下可供您使用的 CSS 类和菜单选项，以自定义菜单以满足您的需求，并且在样式化菜单时如何使用其中一些属性来产生良好的效果。我们还介绍了我们可以使用的方法和事件范围，以执行操作或对菜单小部件触发的事件做出反应。

我们以查看一些示例结束，展示了如何完全改变菜单的外观，同时仍保留原始标记。我们使用了三个示例来自定义一个`<select>`菜单，增强一个按钮，以及将菜单转换为上下文菜单。

在下一章中，我们将继续研究工具提示小部件，我们可以使用它来指出元素上的注释点，例如字段或图像，或设置为为您网站的访问者提供一些选项的迷你菜单。
