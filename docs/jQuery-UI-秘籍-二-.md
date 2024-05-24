# jQuery UI 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/6053054F727DA7F93DC0A95B33107695`](https://zh.annas-archive.org/md5/6053054F727DA7F93DC0A95B33107695)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：开发日期选择器

在本章中，我们将涵盖：

+   处理不同的日期格式

+   制作全尺寸的日历小部件

+   显示月度效果

+   预约提醒作为工具提示

+   限制日期范围

+   隐藏输入字段

+   附加数据和控件

# 介绍

**日期选择器**小部件通过提供日期选择实用工具来增强典型的文本输入表单元素。我们现在在 Web 上到处都可以看到这些类型的输入。日期选择器的图形化性质对大多数用户来说是直观的，因为它与物理日历非常相似。日期选择器小部件还解决了处理一致日期格式的挑战，这是用户无需担心的。

# 处理不同的日期格式

日期选择器小部件支持各种日期字符串格式。当用户进行选择时，日期字符串是填充在文本输入中的值。通常情况下，应用程序会尝试在整个用户界面中遵循相同的日期格式以保持一致性。因此，如果您不满意小部件提供的默认格式，我们可以在创建小部件时使用`dateFormat`选项进行更改。

## 如何做...

我们将从创建两个`input`字段开始，其中我们需要用户输入日期：

```js
<div>
    <label for="start">Start:</label>
    <input id="start" type="text" size="30"/>
</div>

<div>
    <label for="stop">Stop:</label>
    <input id="stop" type="text" size="30"/>
</div>
```

接下来，我们将使用前面的`input`字段并指定我们的自定义格式来创建两个日期选择器小部件。

```js
$(function() {

    $( "input" ).datepicker({
        dateFormat: "DD, MM d, yy"
    });

});
```

## 它是如何工作的...

当我们在日期选择器小部件中做出选择时，您会注意到文本`input`值会更改为所选日期，使用我们选择的格式。日期格式字符串本身，`"DD, MM d, yy"`，是根据大多数其他编程语言中找到的格式而建模的，也就是说，日期选择器没有本机 JavaScript 日期格式化工具可用。当用户在日期选择器的下拉日历中进行选择时，将创建一个`Date`对象。然后小部件使用`dateFormat`选项来格式化`Date`对象，并将文本输入填充为结果。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_04_01.jpg)

## 还有更多...

如果我们正在构建一个相当大的用户界面，我们可能会在几个不同的地方使用几个日期选择器小部件。为了保持日期格式的一致性，我们将不得不每次创建日期选择器小部件时指定`dateFormat`选项。我们可能会有几个调用创建小部件的调用使用不同的选择器，因此总是指定相同的`dateFormat`选项有点烦人，而它应该只是默认值。

在这种情况下，最好只是将默认的`dateFormat`值更改为我们的应用程序遍布的内容。这比一遍又一遍地指定相同的格式要好，同时保留了根据情况更改日期格式的能力。

我们将使用与之前相同的 HTML 结构-两个`input`字段是我们的日期选择器占位符。但让我们修改 JavaScript 如下：

```js
(function( $, undefined ) {

$.widget( "ui.datepicker", $.ui.datepicker, {
    options: $.extend(
        $.ui.datepicker.prototype.options,
        { dateFormat: "DD, MM d, yy" }
    ),
});

})( jQuery );

$(function() {

    $( "#start" ).datepicker();
    $( "#stop" ).datepicker();

});
```

现在，如果你运行这个修改过的 JavaScript，你会得到与之前相同的日期选择器行为。然而，你会注意到，我们现在要调用两次 `datepicker()` 构造函数。都没有指定 `dateFormat` 选项，因为我们通过定制 `datepicker` 小部件和扩展 `options` 来改变了默认值。我们仍然可以为每个单独的小部件提供自定义日期格式的选项，这样做可以为我们节省大量潜在的重复 `dateFormat` 选项。

# 制作一个全尺寸的日历小部件

`datepicker` 小部件的典型用法是增强标准表单输入字段。当字段获得焦点时，我们希望为用户显示实际的日期选择器。如果我们遵循小部件的标准使用模式——选择日期，那么这就是有道理的。毕竟，这就是为什么它被称为日期选择器的原因。

但是，我们可以利用主题框架提供的一些灵活性，并对日期选择器进行一些微小的调整，以显示一个更大的日历。不一定是为了作为输入选择日期的目的，而是作为一个大窗口来显示与日期/时间相关的信息。我们需要对小部件进行的更改仅仅是将内联显示的尺寸放大。

## 准备工作

日期选择器小部件已经知道如何在内联中显示自己。我们只需要在 `div` 元素上调用日期选择器构造函数，而不是在 `input` 元素上。所以我们将使用这个基本的标记：

```js
<div class="calendar"></div>
```

还有一个普通的 `datepicker()` 调用：

```js
$(function() {
    $( ".calendar" ).datepicker();
});
```

其余的工作是在主题调整中完成的。

## 如何操作...

调整日期选择器 CSS 的目标是使其尺寸放大。想法是使小部件看起来更像一个日历，而不像一个表单输入字段助手。日历已经以内联方式显示了，所以让我们在页面上包含这个新的 CSS。

```js
.ui-datepicker {
    width: 500px;
}

.ui-datepicker .ui-datepicker-title {
    font-size: 1.3em;
}

.ui-datepicker table {
    font-size: 1em;
}

.ui-datepicker td {
    padding: 2px;
}

.ui-datepicker td span, .ui-datepicker td a {
    padding: 1.1em 1em;
}
```

有了这个，我们就有了一个缩放的日历小部件，作为一个日期选择器仍然可以完美地运行，因为我们没有改变小部件的任何功能。

![操作步骤...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_04_02.jpg)

## 工作原理...

我们对这些新的样式声明所做的第一件事是增加日历显示的宽度为`500px`。这可以是我们选择的任何数字，最适合我们正在开发的用户界面。接下来，我们将增加标题部分——月份和年份的字体大小。我们还增加了所有星期几和月份数字的字体大小，并在月份日槽之间提供了更多的填充。我们现在有了空间，我们可能会用到它。最后，设置在 `td span` 和 `td a` 元素上的 `padding` 修复了整个日历的高度；否则，纵横比将会非常不协调。这是另一个我们希望根据每个应用程序进行微调的数字，以便正确设置。

# 显示月度效果

当日期选择器选择器显示时，我们通常为用户每次显示一个月。如果用户需要向后导航时间，则使用上个月按钮。同样，他们可以使用下个月按钮向前导航时间。当发生这种情况时，日期选择器小部件仅清空日期选择器`div`，然后重新生成一些 HTML 以用于日历，并插入其中。这一切都发生得非常快，对于用户来说，基本上是瞬间的。

让我们通过向日期选择器内部注入一些效果来使这个月份导航更加生动。

## 准备工作

这个实验可以使用任何日期选择器小部件，但直接使用内联日期选择器显示可能更简单，而不是使用文本`input`。这样，当页面加载时，日期选择器就在那里，我们不需要打开它。内联日期选择器是使用`div`元素创建的。

```js
<div class="calendar"></div>
```

## 如何做...

我们将扩展日期选择器小部件，以允许在我们调整当前月份时应用 jQuery 的`fadeIn()`和`fadeOut()`函数。

```js
(function( $, undefined ) {

$.extend( $.datepicker, {

    _updateDatepicker: function( inst ) {

        var self = this,
            _super = $.datepicker.constructor.prototype;

        inst.dpDiv.fadeOut( 500, function() {
            inst.dpDiv.fadeIn( 300 );
            _super._updateDatepicker.call( self, inst );
        });

    }

});

})( jQuery );

$(function() {
    $( ".calendar" ).datepicker();
});
```

现在，当用户单击日历顶部的下一个或上一个箭头按钮时，我们会看到小部件淡出，并淡入具有新日历月份布局的界面。

## 它的工作原理...

你会注意到这段代码的第一件事是它没有使用典型的小部件工厂机制扩展日期选择器小部件。这是因为日期选择器的默认实现尚未转移到新的小部件工厂方式进行操作。但这并不妨碍我们根据需要扩展小部件。

### 提示

日期选择器小部件很复杂——比框架内的大多数其他小部件都要复杂得多。在引入如此重大变化之前，核心 jQuery UI 团队必须考虑许多因素。截至撰写本文时的计划是，日期选择器小部件将在将来的版本中像其他小部件一样成为小部件工厂的产品。

我们在`$.datepicker`对象上使用了 jQuery `extend()`函数。该对象是`Datepicker`类的单例实例，这是我们为了简洁而感兴趣的内容。`_updateDatepicker()`方法是我们在此自定义中的目标。默认的日期选择器实现使用此方法来更新日期选择器`div`的内容。因此，我们想要重写它。在我们版本的方法中，我们使用`fadeOut()`隐藏了`inst.dpDiv`。一旦完成，我们调用`fadeIn()`。`_super`变量是对用于定义小部件的`Datepicker`类的引用。由于`$.datepicker`是一个实例，因此访问`Datepicker`原型的唯一方法是通过`$.datepicker.constructor.prototype`。我们需要`Datepicker`原型的原因是，这样我们才能在我们完成了效果后调用原始的`_updateDatepicker()`方法，因为它执行了与配置显示相关的其他几个任务。

# 将预约提醒显示为工具提示

日期选择器小部件帮助用户为`input`字段选择正确的日期，或者作为基本显示。在任何一种情况下，如果我们能为用户提供更多的上下文信息，那么这不是很有用吗？也就是说，如果我正在使用日期选择器来选择表单中的日期，那么当我将鼠标指针移到日历中的某一天时，知道那天有些事情要做会很有帮助。也许我应该选择其他日期。

在本节中，我们将研究扩展日期选择器小部件的能力，以允许指定作为工具提示出现的提醒。这些作为选项传递给日期选择器构造函数，并且可能在应用程序内部产生，可能是从数据库中的用户资料中获得的。

## 如何实现...

我们将使用一个简单的内联日期选择器作为示例，目标标记为`<div class="calendar"></div>`。

让我们通过接受提醒对象数组并为它们创建工具提示来扩展日期选择器的功能。提醒对象只是一个带有`date`和`text`字段的普通 JavaScript 对象。日期告诉日期选择器工具提示应该放在日历中的何处。

```js
(function( $, undefined ) {

$.extend( $.datepicker, {

    _updateDatepicker: function( inst ) {

        var settings = inst.settings,
            days = "td[data-handler='selectDay']",
            $target = inst.dpDiv,
            _super = $.datepicker.constructor.prototype;

        _super._updateDatepicker.call( this, inst )

        if ( !settings.hasOwnProperty( "reminders" ) ) {
            return;
        }

        $target.find( days ).each( function( i, v ) {

            var td = $( v ),
                currentDay = new Date(
                    td.data( "year" ),
                    td.data( "month" ),
                    td.find( "a" ).html()
                );

            $.each( settings.reminders, function( i, v ) {

                var reminderTime = v.date.getTime(),
                    reminderText = v.text,
                    currentTime = currentDay.getTime();

                if ( reminderTime == currentTime ) {
                    td.attr( "title", reminderText ).tooltip();
                }

            });

        });

    }

});

})( jQuery );

$(function() {
    $( ".calendar" ).datepicker({
        reminders: [
            {
                date: new Date(2013, 0, 1),
                text: "Happy new year!"
            },
            {
                date: new Date(2013, 0, 14),
                text: "Call in sick, case of the Mondays"
            },
            {
                date: new Date(2013, 1, 14),
                text: "Happy Valentine's Day!"
            }
        ]
    });
});
```

现在，当您将鼠标指针移到日期选择器小部件中提供的提醒日期上时，您应该会看到所提供的文本作为工具提示显示出来：

![如何实现...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_04_03.jpg)

## 工作原理...

让我们退一步，思考传递给提醒参数的数据以及我们对其进行了什么处理。传递的值是一个对象数组，每个对象都有`date`和`text`属性。文本是我们想要显示在工具提示中的内容，而日期告诉日期选择器在何处放置工具提示。因此，我们取得这个值并将其与日期选择器日历中呈现的日期进行比较。

所有定制工作都在我们自己的`_updateDatepicker()`方法的实现中完成。每次渲染日历时都会调用此方法。这包括从一个月切换到另一个月。我们使用对原始日期选择器实现的引用`_super`来调用`_updateDatepicker()`方法。一旦完成了这一点，我们就可以执行我们的自定义。我们首先检查是否已提供提醒参数，否则我们的工作已经完成。

接下来，我们查找并迭代当前显示的月份中表示一天的每个`td`元素。对于每一天，我们构造一个代表表格单元格的 JavaScript`Date`对象——我们将需要这个对象来与每个提醒条目进行比较。最后，我们在`reminders`参数中迭代每个提醒对象。如果我们在应该显示此提醒的日期上，我们在设置`td`元素的`title`属性之后构造工具提示小部件。

# 限制日期范围

您的应用程序可能需要限制可选日期，限制日期范围。也许这是基于某些其他条件为真或事件被触发的。谢天谢地，我们有足够的灵活性来处理小部件的最常见的受限选择配置。

## 准备工作...

我们将使用基本输入元素标记来创建我们的日期选择器小部件：

```js
<div>
    <label for="start">Start:</label>
    <input id="start" type="text" size="30"/>
</div>
```

## 如何做...

我们将使用`minDate`和`maxDate`选项创建我们的日期选择器小部件。

```js
$(function() {

    $( "input" ).datepicker({
        minDate: new Date(),
        maxDate: 14
    });

});
```

当我们通过单击`input`字段激活日期选择器小部件时，您会注意到仅有特定范围的日期可选择。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_04_04.jpg)

## 工作原理...

`minDate`和`maxDate`选项都接受各种格式。 在我们的示例中，我们给`minDate`选项一个代表今天的`Date`对象。 这意味着用户不能选择今天之前的任何日期。 此外，我们不希望允许用户选择任何日期超过未来两周。 通过给`maxDate`选项提供`14`天的增量，这很容易指定。

## 还有更多...

给定日期选择器实例的受限日期范围不一定要静态定义。 实际范围可能取决于 UI 中的某些动态内容，例如另一个日期选择器的选择。

让我们看看我们如何限制日期范围，取决于选择另一个日期。 我们将创建两个日期选择器小部件。 当用户在第一个小部件中选择日期时，将使用更新的范围限制启用第二个小部件。 用户不能在第一个日期选择器之前选择日期。

这是我们将用于两个日期选择器的标记：

```js
<div>
    <label for="start">Start:</label>
    <input id="start" type="text" size="30"/>
</div>

<div>
    <label for="start">Stop:</label>
    <input id="stop" type="text" size="30"/>
</div>
```

这是创建两个日期选择器小部件的代码：

```js
$(function() {

    function change ( e ) {

        var minDate = $( this ).datepicker( "getDate" );

        $( "#stop" ).datepicker( "enable" );
        $( "#stop" ).datepicker( "option", "minDate", minDate );

    }

    $( "#start" ).datepicker()
                 .change( change );

    $( "#stop" ).datepicker( { disabled: true } );

});
```

默认情况下，`＃stop`日期选择器被禁用，因为我们需要知道`minDate`值应该是什么。

![更多内容... ](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_04_05.jpg)

但是一旦用户在`＃start`日期选择器中做出选择，我们就可以在`＃stop`日期选择器中做出选择-我们只是不能在`＃start`日期选择器中的选择之前选择任何内容。

![更多内容...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_04_06.jpg)

`#start`日期选择器在进行选择时启用并更新`#stop`日期选择器。 它启用小部件并将`getDate`的值作为`minDate`选项传递。 这基于先前选择进行单向强制用户。

# 隐藏输入字段

日期选择器小部件的目标是在用户进行选择后填充文本`input`元素。 因此，小部件对于`input`元素有两种用途。 首先，它监听`input`元素上的`focus`事件。 这是它知道何时显示日历选择器的方式。 其次，一旦做出选择，`input`元素的值会更新以反映所选格式的日期。

向用户呈现一个 `input` 元素在大多数情况下都可以正常工作。但也许由于某些原因，输入框并不适合您的 UI。也许我们需要一种不同的方法来显示日历并存储/显示选择。

在本节中，我们将探讨一种替代方法，而不仅仅使用日期选择器 `input` 元素。我们将使用一个 **button** 小部件来触发日历显示，并且我们将伪装 `input` 元素，使其看起来像是其他东西。

## 准备就绪

让我们使用以下 HTML 示例。我们将布置四个日期部分，用户需要按按钮才能与日期选择器小部件交互。

```js
<div>

    <div class="date-section">
        <label>Day 1:</label>
        <button>Day 1 date</button>
        <input type="text" readonly />
    </div>

    <div class="date-section">
        <label>Day 2:</label>
        <button>Day 2 date</button>
        <input type="text" readonly />
    </div>

    <div class="date-section">
        <label>Day 3:</label>
        <button>Day 3 date</button>
        <input type="text" readonly />
    </div>

    <div class="date-section">
        <label>Day 4:</label>
        <button>Day 4 date</button>
        <input type="text" readonly />
    </div>

</div>
```

## 如何做...

我们使日期部分按预期工作的第一件事是一些 CSS。这不仅对于布置我们正在构建的 UI 非常重要，还对于伪装 `input` 元素很重要，以便用户不知道它在那里。

```js
div.date-section {
    padding: 5px;
    border-bottom: 1px solid;
    width: 20%;
}

div.date-section:last-child {
    border-bottom: none;
}

div.date-section label {
    font-size: 1.2em;
    font-weight: bold;
    margin-right: 2px;
}

div.date-section input {
    border: none;
}
```

现在我们将编写 JavaScript 代码来实例化日期选择器和按钮小部件。

```js
$(function() {

    var input = $( "div.date-section input" ),
        button = $( "div.date-section button" );

    input.datepicker({
        dateFormat: "DD, MM d, yy"
    });

    button.button({
        icons: { primary: "ui-icon-calendar" }, 
        text: false
    });

    button.click( function( e ) {
        $( this ).next().datepicker( "show" )
    });

});
```

有了这些，现在我们有了四个日期部分，用户可以单击标签右侧的日期按钮来显示日历。他们选择一个日期，然后日历就会隐藏起来。您会注意到我们的 CSS 样式已经隐藏了 `input` 元素。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_04_07.jpg)

## 工作原理...

此示例中的大多数 CSS 样式规则用于布局 UI 组件、`label`、`buttons` 和 `input`。您会注意到，在选择日期之前，输入框是不可见的。这是因为它尚无文本值，而且因为我们已经在我们的 `div.date-section` 输入 CSS 选择器中删除了 `border`。

我们的 JavaScript 代码在页面加载时首先为每个输入元素创建日期选择器小部件。我们还将自定义字符串传递给 `dateFormat` 选项。对于每个日期部分，我们都有一个按钮。我们在此处使用按钮小部件来创建一个日历图标按钮，当单击时显示日历。我们通过调用 `datepicker( "show" )` 来实现这一点。

# 附加的日历数据和控件

日期选择器小部件有各种附加数据和控件选项，开发人员可以使用该小部件公开这些选项。这些都是简单的布尔配置选项，用于打开数据或控件。

## 入门指南

让我们准备两个 `div` 元素，用它们可以创建两个内联日期选择器实例。

```js
<div>
    <strong>Regular:</strong>
    <div id="regular"></div>
</div>

<div>
    <strong>Expanded:</strong>
    <div id="expanded"></div>
</div>
```

## 如何做...

让我们创建两个日期选择器小部件。我们创建两个小部件，以便我们可以对比普通日期选择器和具有扩展数据和控件的日期选择器之间的差异。

```js
$(function() {

    $( "#regular" ).datepicker();

    $( "#expanded" ).datepicker({
        changeYear: true,
        changeMonth: true,
        showButtonPanel: true,
        showOtherMonths: true,
        selectOtherMonths: true,
        showWeek: true
    });

});
```

现在您可以看到两个渲染的日期选择器之间的差异。后者已经通过附加的控件和数据进行了扩展。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_04_08.jpg)

## 工作原理...

我们对扩展的 `datepicker` 实例所做的所有工作都是打开一些默认关闭的功能。具体如下：

+   `changeYear`: 这样可以启用年份下拉菜单。

+   `changeMonth`: 这样可以启用月份下拉菜单。

+   `showButtonPanel`：这会在日历底部启用**今天**和**完成**按钮。

+   `showOtherMonths`：这会显示来自相邻月份的日期。

+   `showWeek`：这会在日历中启用一周中的列。


# 第五章：添加对话框

在本章中，我们将介绍以下示例：

+   对对话框组件应用效果

+   等待 API 数据加载

+   在对话标题中使用图标

+   向对话框标题添加操作

+   对对话框调整交互应用效果

+   用于消息的模态对话框

# 介绍

对话框小部件为 UI 开发人员提供了一个工具，他们可以在不中断当前页面内容的情况下向用户呈现表单或其他信息片段；对话框创建了一个新的上下文。开箱即用，开发人员可以使用对话框选项做很多事情，并且其中许多功能默认情况下是打开的。这包括调整对话框的大小并在页面上移动它的能力。

在本章中，我们将解决在任何 Web 应用程序中典型对话框使用中的一些常见问题。通常需要调整对话框的控件和整体外观；我们将涉及其中一些。我们还将看看如何与 API 数据交互使对话框使用变得复杂以及处理方法。最后，我们可以通过查看如何以各种方式将效果应用于它们来为对话框小部件添加一些亮点。

# 对对话框组件应用效果

在开箱即用的情况下，对话框小部件允许开发人员在打开对话框时显示动画，以及在关闭时隐藏动画。此动画应用于整个对话框。因此，例如，如果我们指定`show`选项是`fade`动画，则整个对话框将对用户淡入视图。同样，如果`hide`选项是`fade`，则对话框会淡出视图，而不是立即消失。为了活跃这种`show`和`hide`行为，我们可以对各个对话框组件进行操作。也就是说，我们可以将显示和隐藏效果应用于小部件内部的各个部分，如标题栏和按钮窗格，而不是将它们应用于整个对话框。

## 怎么做……

我们要创建的对话框在内容上非常简单。也就是说，在 HTML 中我们只会为对话框指定一些基本的`title`和内容字符串。

```js
<div title="Dialog Title">
    <p>Basic dialog content</p>
</div>
```

为了将对话框组件的逐个动画化的想法变为现实，我们需要在几个地方扩展对话框小部件。特别是，我们将动画化小部件顶部的标题栏以及底部的按钮窗格。下面是 JavaScript 代码的样子：

```js
(function( $, undefined ) {

$.widget( "ab.dialog", $.ui.dialog, {

    _create: function() {

        this._super();

        var dialog = this.uiDialog;

        dialog.find( ".ui-dialog-titlebar" ).hide();
        dialog.find( ".ui-dialog-buttonpane" ).hide();

    },

    open: function() {

        this._super();

        var dialog = this.uiDialog;

        dialog.find( ".ui-dialog-titlebar" ).toggle( "fold", 500 );
        dialog.find( ".ui-dialog-buttonpane" ).toggle( "fold", 500 );

    },

    close: function( event, isCallback ) {

        var self = this,
            dialog = this.uiDialog;

        if ( isCallback ) {
            this._super( event );
            return;
        }

        dialog.find( ".ui-dialog-titlebar" ).toggle( "fold", 500 );
        dialog.find( ".ui-dialog-buttonpane" ).toggle( "fold", 500, function(){
            self.element.dialog( "close", event, true );
        });

    }

});

})( jQuery );

$(function() {

    $( "div" ).dialog({
        show: "fade", 
        hide: "scale",
        buttons: {
            Cancel: function() {
                $( this ).dialog( "close" );
            }
        }
    });

});
```

当你打开页面时，你会看到独立于我们为对话指定的整体`fade`动画的各个对话框组件淡入视图。一旦可见，对话框应该看起来像这样：

![怎么做……](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_05_01.jpg)

你还会注意到，直到标题栏和按钮窗格应用`fade`效果之后，`scale`效果才会被应用。

## 它是如何工作的……

这段代码是规则的例外之一，我们没有提供关闭新扩展功能的机制。也就是说，我们在某些对话框方法的自定义实现中硬编码了更改，无法通过提供选项值来关闭。然而，这个例外是为了在复杂性和所需功能之间进行权衡。很可能这种自定义动画工作会作为特定项目需求的一部分进行，而不是对话框小部件功能的广泛扩展。

我们更改默认对话框实现的第一件事是在`_create()`方法中，我们隐藏了`.ui-dialog-titlebar`和`.ui-dialog-buttonpane`组件。这是在调用`_super()`方法之后完成的，该方法负责创建基本对话框组件。即使对话框设置为使用`autoOpen`选项自动打开，`_create()`方法也不会实际显示它。因此，我们可以在用户没有注意到的情况下隐藏标题栏和按钮面板。

我们隐藏这两个组件的原因是因为我们希望在对话框打开时应用显示效果。下一个我们重写的方法`open()`就是这样做的。它首先调用`_super()`方法，该方法启动显示对话框的效果（在我们的情况下，我们告诉它在显示时淡入）。然后我们在标题栏和按钮面板上使用`fold`效果。

您会注意到我们在开始下一个动画之前不等待任何动画完成。对话框显示动画开始，然后是标题栏和按钮面板。这三个动画可能同时执行。我们之所以这样做是为了保持对话框的正确布局。我们要重写的最后一个方法是`close()`方法。这引入了一个有趣的解决方法，我们必须使用它来使得 `_super()` 在回调中起作用。即使在封闭范围内有 `self` 变量，我们在回调中调用 `_super()` 方法时也会遇到问题。因此，我们使用小部件元素，并假装我们是从小部件外部调用`.dialog("close")`一样。`isCallback`参数告诉`close()`方法调用 `_super()`，然后返回。我们之所以需要回调是因为我们实际上不想在完成按钮面板动画之前执行对话框隐藏动画。

# 等待 API 数据加载

通常情况下，对话框小部件需要从 API 加载数据。也就是说，并非所有对话框都由静态 HTML 构成。它们需要从 API 获取数据以使用 API 数据构建某些元素，例如`select`元素选项。

从 API 加载数据并构建结果元素并不是问题；我们一直在做这件事。挑战出现在我们尝试在对话上下文中执行这些活动时。我们不一定希望在从 API 加载数据并且用于显示对话框组件内部的 UI 组件已构建之前显示对话框，并且理想情况下，我们应该阻止对话框显示，直到对话框显示的组件准备好。

这在远程 API 功能中尤其棘手，因为不可能预测延迟问题。此外，对话框可能依赖于多个 API 调用，每个调用在对话框中填充自己的 UI 组件。

## 准备...

要为 API 数据问题实现解决方案，我们将需要一些基本的 HTML 和 CSS 来定义对话框及其内容。我们将在对话框中有两个空的 `select` 元素。这是 HTML 的样子：

```js
<div id="dialog" title="Genres and Titles">
    <div class="dialog-field">
        <label for="genres">Genres:</label>
        <select id="genres"></select>
        <div class="ui-helper-clearfix"></div>
    </div>

    <div class="dialog-field">
        <label for="titles">Titles:</label>
        <select id="titles"></select>
        <div class="ui-helper-clearfix"></div>
    </div>
</div>
```

而且，这是上述代码的支持 CSS：

```js
.dialog-field {
    margin: 5px;
}

.dialog-field label {
    font-weight: bold;
    font-size: 1.1em;
    float: left;
}

.dialog-field select {
    float: right;
}
```

## 如何做...

我们将给对话框小部件增加一个新选项来阻止在等待 API 请求时阻塞。此选项将允许我们传递一个延迟承诺的数组。承诺是用于跟踪单个 Ajax 调用状态的对象。通过一组承诺，我们能够使用简单的代码实现复杂的阻塞行为，如下所示：

```js
(function( $, undefined ) {

$.widget( "ab.dialog", $.ui.dialog, {

    options: { 
        promises: []
    },

    open: function( isPromise ) {

        var $element = this.element,
            promises = this.options.promises;

        if ( promises.length > 0 && !isPromise ) {

            $.when.apply( $, promises ).then( function() {
                $element.dialog( "open", true );
            });

        }
        else {

            this._super();

        }

    },

});

})( jQuery );

$(function() {

    var repos = $.ajax({
        url: "https://api.github.com/repositories",
        dataType: "jsonp",
        success: function( resp ) {
            $.each( resp.data, function( i, v ) {
                $( "<option/>" ).html( v.name )
                                .appendTo( "#repos" );
            });
        },
    });

    var users = $.ajax({
        url: "https://api.github.com/users",
        dataType: "jsonp",
        success: function( resp ) {
            $.each( resp.data, function( i, v ) {
                $( "<option/>" ).html( v.login )
                                .appendTo( "#users" );
            });
        }
    });

    $( "#dialog" ).dialog({
        width: 400,
        promises: [
            repos.promise(),
            users.promise()
        ]
    });

});
```

一旦 API 数据返回，对于这两个调用，对话框将被显示，并且应该看起来像这样：

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_05_02.jpg)

## 它是如何工作的...

让我们首先看一下文档准备好的处理程序，在这里我们实际上是在实例化对话框小部件。这里定义的前两个变量 `repos` 和 `users` 是 `$.Deferred` 对象。这代表了我们正在向 GitHub API 发送的两个 API 调用。这些调用的目的是分别填充 `#repos` 和 `#users` `select` 元素。这些 `select` 元素构成了我们的 `#dialog` 内容的一部分。在每个 Ajax 调用中指定的 `success` 选项是一个回调，它执行创建 `option` 元素并将它们放置在 `select` 元素中的工作。

如果不自定义对话框小部件，这两个 API 调用将正常工作。对话框将打开，最终，选项将出现在 `select` 元素中（在对话框已经打开之后）。但是，您会注意到，我们正在向对话框传递一个 `deferred.promise()` 对象数组。这是我们赋予对话框小部件的新功能。延迟对象简单来说允许开发人员推迟某些可能需要一段时间才能完成的操作的后果，例如 Ajax 调用。承诺是我们从延迟对象中得到的，它允许我们组合一些条件，说出一个复杂的序列，例如进行多个 Ajax 调用，何时完成。

我们已添加到对话框小部件的自定义`promises`选项是在我们的`open()`方法的实现中使用的。在这里，我们可以利用这些承诺。基本上，我们正在将一个或多个承诺对象传递给对话框，一旦它们全部完成或解析为使用 jQuery 术语，我们就可以打开对话框。我们通过将承诺对象数组传递给`$.when()`函数来实现这一点，该函数在对话框上调用`open()`方法。但是，这里出现了一个我们必须处理的复杂情况。我们无法在回调函数内部调用`_super()`，因为核心小部件机制不知道如何找到父小部件类。

所以，我们必须假装我们是从小部件外部调用`open()`。我们通过使用`self.element`和额外的`isPromise`参数来做到这一点，指示我们自定义的`open()`实现如何行为。

# 在对话框标题中使用图标

对于某些对话框，根据应用程序的性质和对话框本身的内容，可能有益于在对话框标题旁边放置一个图标。这可能有利于用户提供额外的上下文。例如，编辑对话框可能具有铅笔图标，而用户个人资料对话框可能包含人物图标。

## 准备好了...

为了说明在对话框小部件的标题栏中添加图标，我们将使用以下内容作为我们的基本 HTML：

```js
<div id="dialog" title="Edit">
    <div>
        <label>Field 1:</label>
        <input type="text"/>
    </div>
    <div>
        <label>Field 2:</label>
        <input type="text"/>
    </div>
</div>
```

## 如何操作...

我们需要定义的第一件事是一个自定义的 CSS 类，用于在将其放置在对话框标题栏中时正确对齐图标。CSS 如下所示：

```js
.ui-dialog-icon {
    float: left;
    margin-right: 5px;
}
```

接下来，我们有我们的 JavaScript 代码来通过添加新的`icon`选项来自定义对话框小部件，以及使用我们的 HTML 作为源代码创建小部件的实例：

```js
(function( $, undefined ) {

$.widget( "ab.dialog", $.ui.dialog, {

    options: {
        icon: false
    },

    _create: function() {

        this._super();

        if ( this.options.icon ) {

            var iconClass = "ui-dialog-icon ui-icon " + 
                            this.options.icon;

            this.uiDialog.find( ".ui-dialog-titlebar" )
                         .prepend( $( "<span/>" ).addClass( iconClass ));

        }

    },

});

})( jQuery );

$(function() {

    $( "#dialog" ).dialog({
        icon: "ui-icon-pencil",
        buttons: {
            Save: function() { $( this ).dialog( "close" ) }
        }
    });

});
```

打开时产生的对话框应该看起来像下面这样：

![如何操作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_05_03.jpg)

## 它是如何工作的...

对于这个特定的对话框实例，我们想显示铅笔图标。我们已添加到对话框小部件的`icon`选项允许开发人员从主题框架中指定图标类。在这种情况下，它是`ui-icon-pencil`。新的`icon`选项具有默认值`false`。

我们正在覆盖`_create()`方法的默认对话框实现，以便我们可以在对话框标题栏中插入一个新的`span`元素，如果提供了`icon`选项。这个新的`span`元素得到了作为新选项值传递的图标类，以及`ui-dialog-icon`类，该类用于定位我们之前定义的图标。

# 将操作添加到对话框标题

默认情况下，对话框小部件为用户提供了一个不需要开发者干预的操作——标题栏中的关闭按钮。这是一个几乎适用于任何对话框的通用操作，因为用户期望能够关闭它们。此外，关闭对话框操作按钮是一个位于对话框右上角的图标，这并不是偶然的。这是一个标准的位置和动作，在图形窗口环境中以及其他操作中也是如此。让我们看看如何扩展放置在对话框小部件标题栏中的操作。

## 如何操作...

对于这个演示，我们只需要以下基本的对话框 HTML：

```js
<div id="dialog" title="Dialog Title">
    <p>Basic dialog content</p>
</div>
```

接下来，我们将实现我们的对话框特化，添加一个新选项和一些创建使用该选项的新对话框实例的代码：

```js
(function( $, undefined ) {

$.widget( "ab.dialog", $.ui.dialog, {

    options: {
        iconButtons: false
    },

    _create: function() {

        this._super();

        var $titlebar = this.uiDialog.find( ".ui-dialog-titlebar" );

        $.each( this.options.iconButtons, function( i, v ) {

            var button = $( "<button/>" ).text( v.text ),
                right = $titlebar.find( "[role='button']:last" )
                                 .css( "right" );

            button.button( { icons: { primary: v.icon }, text: false } )
                  .addClass( "ui-dialog-titlebar-close" )
                  .css( "right", (parseInt(right) + 22) + "px" )
                  .click( v.click )
                  .appendTo( $titlebar );

        });

    }

});

})( jQuery );

$(function() {

    $( "#dialog" ).dialog({
        iconButtons: [
            {
                text: "Search",
                icon: "ui-icon-search",
                click: function( e ) {
                    $( "#dialog" ).html( "<p>Searching...</p>" );
                }
            },
            {
                text: "Add",
                icon: "ui-icon-plusthick",
                click: function( e ) {
                    $( "#dialog" ).html( "<p>Adding...</p>" );
                }
            }
        ]
    });

});
```

当打开此对话框时，我们将在右上角看到我们传递给对话框的新操作按钮，如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_05_04.jpg)

## 它是如何工作的...

我们为对话框创建了一个名为`iconButtons`的新选项。这个新选项期望一个对象数组，其中每个对象都有与操作按钮相关的属性。像文本、图标类以及在用户打开对话框并单击按钮时执行的点击事件等。

在这个定制中，大部分工作都是在我们版本的`_create()`方法中进行的。在这里，我们遍历`iconButtons`选项中提供的每个按钮。在将新按钮插入标题栏时，我们首先创建`button`元素。我们还使用`.ui-dialog-titlebar [role='button']:last`选择器获取最后一个添加的操作按钮的宽度（这是需要计算操作按钮的水平位置的）。

接下来，我们按照按钮配置绑定`click`事件。对于我们添加的数组中的每个按钮，我们希望它放置在前一个按钮的左侧。因此，当我们首次开始遍历`iconButtons`数组时，默认的关闭操作是标题栏中的最后一个按钮。由于 CSS 结构需要一个固定的右值，我们必须计算它。为了做到这一点，我们需要列表中最后一个按钮的值。

# 将效果应用到对话框调整大小交互

默认情况下，对话框小部件允许用户通过拖动调整大小。实际的调整大小功能是由对话框在`resizable`选项为`true`时内部设置的`resizable()`交互小部件提供的。让我们看看如何访问内部可调整大小组件，以便我们可以使用`animate`特性。当设置在可调整大小组件上时，此选项会延迟重新绘制调整大小的组件，直到用户停止拖动调整大小手柄。

## 准备工作...

对于这个演示，我们只需要简单的对话框 HTML，如下所示：

```js
<div id="dialog" title="Dialog Title">
    <p>Basic dialog content</p>
</div>
```

## 如何操作...

让我们为对话框小部件添加一个名为`animateResize`的新选项。当此选项为`true`时，我们将打开内部可调整大小交互小部件的`animate`选项。

```js
(function( $, undefined ) {

$.widget( "ab.dialog", $.ui.dialog, {

    options: { 
        animateResize: false 
    },

    _makeResizable: function( handles ) {
        handles = (handles === undefined ? this.options.resizable : handles);
        var that = this,
            options = this.options,
            position = this.uiDialog.css( "position" ),
            resizeHandles = typeof handles === 'string' ?
                handles:
                "n,e,s,w,se,sw,ne,nw";

        function filteredUi( ui ) {
            return {
                originalPosition: ui.originalPosition,
                originalSize: ui.originalSize,
                position: ui.position,
                size: ui.size
            };
        }

        this.uiDialog.resizable({
            animate: this.options.animateResize,
            cancel: ".ui-dialog-content",
            containment: "document",
            alsoResize: this.element,
            maxWidth: options.maxWidth,
            maxHeight: options.maxHeight,
            minWidth: options.minWidth,
            minHeight: this._minHeight(),
            handles: resizeHandles,
            start: function( event, ui ) {
                $( this ).addClass( "ui-dialog-resizing" );
                that._trigger( "resizeStart", event, filteredUi( ui ) );
            },
            resize: function( event, ui ) {
                that._trigger( "resize", event, filteredUi( ui ) );
            },
            stop: function( event, ui ) {
                $( this ).removeClass( "ui-dialog-resizing" );
                options.height = $( this ).height();
                options.width = $( this ).width();
                that._trigger( "resizeStop", event, filteredUi( ui ) );
                if ( that.options.modal ) {
                    that.overlay.resize();
                }
             }
        })
        .css( "position", position )
        .find( ".ui-resizable-se" )
        .addClass( "ui-icon ui-icon-grip-diagonal-se" );
    }

});

})( jQuery );

$(function() {

    $( "#dialog" ).dialog({
        animateResize: true
    });

});
```

当创建并显示此对话框时，您将能够调整对话框的大小，观察到实际的调整现在是动画的。

## 它是如何工作的...

我们已经向对话框添加了`animateResize`选项，并为其提供了默认值`false`。要实际执行此功能，我们已经完全重写了对话框小部件在对话框创建时内部使用的`_makeResizable()`方法。事实上，我们已经采取了`_makeResizable()`的内部代码，并仅更改了一件事情——`animate: this.options.animateResize`。

这有点多余，复制所有这些代码来打开一个简单的功能，比如动画化对话框调整交互。事实上，这不是理想的解决方案。一个更好的方法是调用`_makeResizable()`的`_super()`版本，然后只需通过调用`this.uiDialog.resizable( "option", "animate", true )`打开动画即可。但在撰写本文时，这不符合预期。尽管我们的替代路径涉及多余的代码，但它只是展示了小部件工厂的灵活性。如果这种动画质量是用户界面的真实要求，我们很快就找到了一个可以忽略的折衷方案。

# 使用模态对话框进行消息传递

对话框小部件有一个保留的`modal`选项，用于当我们需要将用户的注意力集中在一件事上时。此选项显示对话框，同时防止用户与其余用户界面进行交互。他们别无选择，只能注意到。不言而喻，模态对话框应该节俭使用，特别是如果您想要用它来向用户广播消息。

让我们看看如何简化对话框以构建一个通用的通知工具在我们的应用程序中。本质上是一个模态对话框，用于那些我们不能让用户继续正在做的事情而不确保他们已经看到我们的消息的情况。

## 准备就绪...

这是这个示例所需的 HTML 看起来像。请注意，`#notify` `div`，它将成为一个对话框小部件，没有内容，因为我们的新通知小部件将提供一些内容。

```js
<div id="notify"></div>

<button id="show-info">Show Info</button>
<button id="show-error">Show Error</button>
```

## 如何做...

让我们继续定义一个新的通知小部件，能够向用户显示错误和信息消息，就像这样：

```js
(function( $, undefined ) {

$.widget( "ab.notify", $.ui.dialog, {

    options: { 
        modal: true,
        resizable: false,
        draggable: false,
        minHeight: 100,
        autoOpen: false,
        error: false
    },

    open: function() {

        var error = this.options.error,
            newClass = error ? "ui-state-error" : 
                               "ui-state-highlight",
            oldClass = error ? "ui-state-highlight" :
                               "ui-state-error";

        this.element.html( this.options.text );

        this.uiDialog.addClass( newClass )
                     .removeClass( oldClass )
                     .find( ".ui-dialog-titlebar" )
                     .removeClass( "ui-widget-header ui-corner-all" );

        this._super();

    },

});

})( jQuery );

$(function() {

    $( "#notify" ).notify();

    $( "#show-info, #show-error" ).button();

    $( "#show-info" ).click( function( e ) {

        $( "#notify" ).notify( "option", {
            error: false,
            text: "Successfully completed task"
        });

        $( "#notify" ).notify( "open" );

    });

    $( "#show-error" ).click(function( e ) {

        $( "#notify" ).notify( "option", {
            error: true,
            text: "Failed to complete task"
        });

        $( "#notify" ).notify( "open" );

    })
```

我们在这里创建的两个按钮用于演示通知小部件的功能。如果您点击`#show-info`按钮，您将看到以下信息消息：

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_05_05.jpg)

如果您点击`#show-error`按钮，您将看到此错误消息：

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_05_06.jpg)

## 它是如何工作的...

我们刚刚创建的`notify`小部件继承了对话框小部件的所有功能。在我们的小部件中，我们首先定义的是可用选项。在这种情况下，我们扩展了对话框小部件的`options`对象，并添加了一些新选项。您还会注意到，我们提供了一些更新后的对话框选项的默认值，例如打开`modal`并关闭`draggable`。每个 notify 实例都将共享这些默认值，因此没必要每次都要定义它们。

`open()`方法属于对话框小部件，我们在这里进行了重写，以实现将通知消息的文本插入对话框内容的自定义功能。我们还根据`error`选项设置对话框的状态。如果这是一个错误消息，我们将整个对话框应用`ui-state-error`类。如果`error`选项为`false`，我们应用`ui-state-highlight`类。最后，对话框标题栏组件被简化，删除了一些类，因为我们在消息显示中没有使用它。

在应用程序代码中，我们首先创建的是 notify 小部件的实例。然后我们创建了演示按钮，并将`click`事件绑定到将显示错误消息或信息性消息的功能，具体取决于点击了哪个按钮。


# 第六章：制作菜单

在本章中，我们将涵盖：

+   创建可排序的菜单项

+   高亮显示活动菜单项

+   使用效果与菜单导航

+   动态构建菜单

+   控制子菜单的位置

+   对子菜单应用主题

# 介绍

jQuery UI **菜单**小部件接受链接列表，并通过处理子菜单中的导航，以及应用主题框架中的类，将它们呈现为一个连贯的菜单。我们可以使用默认提供的选项来定制菜单到一定程度。在其他情况下，例如当我们希望菜单项可排序时，我们可以轻松地扩展小部件。

# 创建可排序的菜单项

默认情况下，菜单小部件保留用于创建菜单项的列出元素的顺序。这意味着如果在菜单小部件中使用的 HTML 的创建者更改了排序方式，这将反映在渲染的菜单中。这对开发人员来说很好，因为它让我们控制如何向用户呈现项目。但是，也许用户对菜单项的排序有更好的想法。

通过将菜单小部件与**sortable 交互**小部件相结合，我们可以为用户提供这种灵活性。然而，有了这种新的能力，我们将不得不解决另一个问题；保留用户选择的顺序。如果他们可以按自己的意愿安排菜单项，那就太好了，但是如果他们每次加载页面都必须重复相同的过程，那就不太好了。因此，我们还将看看如何在 cookie 中保存排序后的菜单顺序。

## 准备工作

让我们使用以下 HTML 代码为我们的菜单小部件。这将创建一个具有四个项目的菜单，所有项目都在同一级别： 

```js
<ul id="menu">
    <li id="first"><a href="#">First Item</a></li>
    <li id="second"><a href="#">Second Item</a></li>
    <li id="third"><a href="#">Third Item</a></li>
    <li id="fourth"><a href="#">Fourth Item</a></li>
</ul>
```

## 如何做到…

现在让我们看一下用于扩展菜单小部件以提供可排序行为的 JavaScript。

```js
(function( $, undefined ) {

$.widget( "ab.menu", $.ui.menu, {

    options: {
        sortable: false
    },

    _create: function() {

        this._super();

        if ( !this.options.sortable ) {
            return;
        }

        var $element = this.element,
            storedOrder = $.cookie( $element.attr( "id" ) ),
            $items = $element.find( ".ui-menu-item" );
        if ( storedOrder ) {

            storedOrder = storedOrder.split( "," );

            $items = $items.sort( function( a, b ) {

                var a_id = $( a ).attr( "id" ),
                    b_id = $( b ).attr( "id" ),
                    a_index = storedOrder.indexOf( a_id ),
                    b_index = storedOrder.indexOf( b_id );

                return a_index > b_index;

            });

            $items.appendTo( $element );

        }

        $element.sortable({

            update: function( e, ui ) {

                var id = $( this ).attr( "id" ),
                    sortedOrder = $( this ).sortable( "toArray" )
                                           .toString();

                $.cookie( id, sortedOrder );

            }

        });

    },

});

})( jQuery );

$(function() {
    $( "#menu" ).menu( { sortable: true } );
});
```

如果您在浏览器中查看此菜单，您会注意到您可以将菜单项拖到任何您喜欢的顺序中。此外，如果您刷新页面，您会看到顺序已经被保留了。

![如何做到…](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_06_01.jpg)

## 工作原理...

在本示例中创建的菜单实例被赋予了一个`sortable`选项值为`true`。这是我们添加到菜单小部件的新选项。我们大部分的扩展工作是在我们自己的`_create()`方法的重新呈现中执行的。我们在这里要做的第一件事是调用方法的原始实现，因为我们希望菜单像往常一样创建；我们通过使用`_super()`方法来做到这一点。从这里开始，我们将保持菜单项的排序顺序。

如果`sortable`选项的评估结果不为`true`，我们将退出，没有任何事情可做。如果此选项为`true`，且我们需要对菜单项目进行排序，我们尝试加载一个 Cookie，使用此菜单的 ID。此 Cookie 的值存储在一个名为`storedOrder`的变量中，因为它恰好代表了存储的用户排序。如果用户已经对菜单进行了排序，我们将菜单项目的顺序存储在 Cookie 中。例如，Cookie 值可能类似于`second,fourth,first,third`。这些是菜单项目的 ID。在我们分割逗号分隔列表时，我们得到了一个以正确顺序排列的菜单项目数组。

最后，我们必须将可排序交互小部件应用于菜单。我们将可排序配置传递给在更新排序顺序时使用的函数。使用可排序小部件的`toArray()`方法序列化菜单项目的排序顺序，并在此处使用菜单 ID 更新 Cookie 值。

关于此示例中使用 Cookie 有两件事情需要注意。首先，我们使用了 Cookie jQuery 插件。此插件体积小，在互联网上广泛使用。然而，值得一提的是，该插件不随 jQuery 或 jQuery UI 一起发布，您的项目将需要管理此依赖项。

第二个需要注意的事情是关于本地主机域。在所有浏览器中，Cookie 存储功能在本地将无法正常工作。换句话说，通过网络服务器查看时会正常工作。如果您真的需要在 Google Chrome 浏览器中测试此代码，您可以像我一样使用 Python 绕过它。在操作系统控制台中，运行以下代码：

```js
python -m SimpleHTTPServer
```

# 高亮显示活动菜单项目

对于菜单小部件，根据项目的配置方式，唯一能判断项目是否激活的方法是页面 URL 由于点击项目而改变。菜单项目不会明显地指示任何实际发生的事情。例如，菜单中的项目一旦被点击，可能会改变可视状态。如果开发人员在用户界面中使用菜单小部件作为导航工具，这将特别有帮助。让我们看看如何扩展菜单小部件的功能，以便使用主题框架的部分提供此功能。

## 准备就绪

我们将在这里使用以下 HTML 代码作为我们的菜单示例。请注意，此特定菜单具有嵌套子菜单：

```js
<ul id="menu">
    <li><a href="#first">First Item</a></li>
    <li><a href="#second">Second Item</a></li>
    <li><a href="#third">Third Item</a></li>
    <li>
      <a href="#forth">Fourth Item</a>
      <ul>
        <li><a href="#fifth">Fifth</a></li>
        <li><a href="#sixth">Sixth</a></li>
      </ul>
    </li
</ul>
```

## 如何做...

为了突出显示活动菜单项目，我们将需要通过一些额外规则扩展主题框架。

```js
.ui-menu .ui-menu-item {
    margin: 1px 0;
    border: 1px solid transparent;
}

.ui-menu .ui-menu-item a.ui-state-highlight { 
    font-weight: normal; 
    margin: -px; 
}
```

接下来，我们将通过新的`highlight`选项和必要的功能扩展菜单小部件本身。

```js
(function( $, undefined ) {

$.widget( "ab.menu", $.ui.menu, {

    options: {
      highlight: false
    },

    _create: function() {

      this._super();

        if ( !this.options.highlight ) {
          return;
        }

        this._on({
          "click .ui-menu-item:has(a)": "_click"
        });

    },

    _click: function( e ) {

      this.element.find( ".ui-menu-item a" )
        .removeClass( "ui-state-highlight" );

        $( e.target ).closest( ".ui-menu-item a" )
          .addClass( "ui-state-highlight ui-corner-all" );

    }

});

})( jQuery );

$(function() {
    $( "#menu" ).menu( { highlight: true });
});
```

如果您查看此菜单，您会注意到一旦选择了一个菜单项目，它会保持高亮状态。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_06_02.jpg)

## 工作原理...

我们在这里定义的 CSS 规则是为了使 `ui-state-highlight` 类在应用于菜单项时能够正常运行。首先，使用 `.ui-menu` `.ui-menu-item` 选择器，我们将 `margin` 设置为在应用 `ui-state-highlight` 类后适当对齐菜单项的内容。我们还给每个菜单项一个不可见的 `border`，以防止鼠标进入和鼠标离开事件将菜单项挤出位置。接下来的选择器，`.ui-menu` `.ui-menu-item` `a.ui-state-highlight`，适用于我们将 `ui-state-highlight` 类应用于菜单项后。这些规则还控制了定位，并防止菜单失去对齐。

切换到 JavaScript 代码，您可以看到我们为菜单部件提供了一个新的 `highlight` 选项。在我们自定义的 `_create()` 方法中，我们调用相同方法的原始实现，然后再添加我们的事件处理程序。由 jQuery UI 基础部件定义的 `_on()` 方法在这里用于将我们的事件处理程序绑定到 `click .ui-menu-item:has(a)` 事件；这个事件在 `menu` 部件内部也使用。在这个处理程序内部，我们从任何已经应用 `ui-state-highlight` 类的菜单项中删除它。最后，我们将 `ui-state-highlight` 类添加到刚刚点击的菜单项上，还添加了 `ui-corner-all` 类，该类通过主题属性定义了圆角元素。

# 使用菜单导航效果

在应用效果到菜单部件时，我们可以采取几种方法。我们在菜单部件中哪些地方可以应用效果？用户将鼠标指针悬停在菜单项上，这会导致状态更改。用户展开子菜单。这两个动作是我们可以通过一些动画来提升视觉效果的主要交互。让我们看看如何使用尽可能少的 JavaScript 来解决这些效果，而不是使用 CSS 过渡。过渡是一个新兴的 CSS 标准，迄今为止，并非所有浏览器都支持它们使用标准语法。然而，按照渐进增强的思路，以这种方式应用 CSS 意味着即使在不支持它的浏览器中，基本的菜单功能也会正常工作。我们可以避免编写大量 JavaScript 来对菜单导航进行动画处理。

## 准备工作

对于这个示例，我们可以使用任何标准的菜单 HTML 代码。理想情况下，它应该有一个子菜单，这样我们就可以观察到它们展开时应用的过渡效果。

## 如何做...

首先，让我们定义所需的 CSS 过渡，以便在菜单项和子菜单在状态更改时应用。

```js
.ui-menu-animated > li > ul {
    left: 0;
    transition: left 0.7s ease-out;
    -moz-transition: left .7s ease-out;
    -webkit-transition: left 0.7s ease-out;
    -o-transition: left 0.7s east-out;
}

.ui-menu-animated .ui-menu-item a {
    border-color: transparent;
    transition: font-weight 0.3s,
      color 0.3s,
      background 0.3s,
      border-color 0.5s;
    -moz-transition: font-weight 0.3s,
       color 0.3s,
       background 0.3s,
       border-color 0.5s;
    -webkit-transition: font-weight 0.3s,
       color 0.3s,
       background 0.3s,
       border-color 0.5s;
    -o-transition: font-weight 0.3s,
       color 0.3s,
       background 0.3s,
       border-olor 0.5s;
}
```

接下来，我们将介绍对菜单部件本身的一些修改，以控制任何给定菜单实例的动画功能。

```js
(function( $, undefined ) {

$.widget( "ab.menu", $.ui.menu, {

    options: {
        animate: false
    },

    _create: function() {

        this._super();

        if ( !this.options.animate ) {
            return;
        }

        this.element.find( ".ui-menu" )
                     .addBack()
                     .addClass( "ui-menu-animated" );

    },

  _close: function( startMenu ) {

        this._super( startMenu );

        if ( !this.options.animate ) {
            return;
        }

        if ( !startMenu ) {
            startMenu = this.active ? this.active.parent() : this.element;
        }

        startMenu.find( ".ui-menu" ).css( "left", "" );

          }

});

})( jQuery );

$(function() {
    $( "#menu" ).menu( { animate: true } );
});
```

现在，如果你在浏览器中查看这个菜单并开始与它交互，你会注意到应用悬停状态时的平滑过渡。你也会注意到，展开子菜单时，应用的过渡似乎将它们向右滑动。

## 它是如何工作的...

首先，让我们考虑一下定义了我们所看到应用到`menu`部件的过渡的 CSS 规则。`.ui-menu-animated > li > ul`选择器将过渡应用到子菜单上。声明的第一个属性`left: 0`只是一个初始化程序，允许某些浏览器更好地与过渡配合。接下来的四行定义了左属性的过渡。菜单部件在展开子菜单时，使用的是位置实用程序部件，它在子菜单上设置了`left`CSS 属性。我们在这里定义的过渡将在`0.7`秒的时间跨度内对`left`属性进行更改，并且会在过渡结束时减缓。

我们有多个过渡定义的原因是一些浏览器支持它们自己的供应商前缀版本的规则。因此，我们从通用版本开始，然后是特定于浏览器的版本。这是一个常见的做法，当浏览器特定的规则变得多余时，我们可以将其删除。

接下来是`.ui-menu-animated .ui-menu-item a`选择器，适用于每个菜单项。你可以看到这里的过渡涉及几个属性。在这个过渡中，每个属性都是`ui-state-hover`的一部分，我们希望它们被动画化。由于我们的调整，`border-color`过渡的持续时间稍长。

现在让我们看看将这个 CSS 运用到 JavaScript 的方法。我们通过添加一个新的`animate`选项来扩展菜单部件，该选项将上述定义的过渡应用到部件上。在我们的`_create()`方法版本中，我们调用了原始的`_create()`实现，然后将`ui-menu-animated`类应用到主`ul`元素和任何子菜单上。

延伸`_close()`方法的原因只有一个。这是在关闭子菜单时调用的。然而，当首次显示子菜单时，`left` CSS 属性是由`position`实用程序计算的。下一次显示时，它不必计算`left`属性。这是一个问题，因为很明显，如果我们尝试对`left`属性值进行动画更改，这会成为显而易见的问题。因此，我们只需要在关闭菜单时将`left`属性设置回`0`。

# 动态构建菜单

经常情况下，菜单在与用户交互时会发生变化。换句话说，我们可能需要在菜单实例化后扩展菜单的结构。或者在构建最终成为菜单部件的 HTML 时，可能并没有所有必要的信息可用；例如，菜单数据可能只以**JavaScript 对象表示法**（**JSON**）格式可用。让我们看看如何动态构建菜单。

## 准备

我们将从以下基本菜单 HTML 结构开始。我们的 JavaScript 代码将扩展这个结构。

```js
<ul id="menu">
    <li><a href="#">First Item</a></li>
    <li><a href="#">Second Item</a></li>
    <li><a href="#">Third Item</a></li>
</ul>
```

## 如何做...

让我们创建菜单小部件，然后我们将扩展菜单 DOM 结构。

```js
$(function() {

    var $menu = $( "#menu" ).menu(),
        $submenu = $( "<li><ul></ul></li>" ).appendTo( $menu );

    $submenu.prepend( $( "<a/>" ).attr( "href", "#" )
                                 .text( "Fourth Item" ) );

    $submenu.find( "ul" ).append( 
$( "<li><a href='#'>Fifth Item</a>" ) )
                                      .append( $( "<li><a href='#'>Sixth Item</a>" ) );

    $menu.menu( "refresh" );

});
```

当您查看这个菜单时，不再只有我们最初的三个项目，而是现在呈现了我们刚刚添加的三个新项目。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_06_03.jpg)

## 工作原理是什么...

如果我们在 JavaScript 代码中不断添加新的菜单项，我们只会看到最初的三个项目。但是，我们正在使用核心 jQuery DOM 操纵工具来构建和插入一个子菜单。之后，我们必须调用 `refresh()` 菜单方法，它会为新的菜单项添加适当的 CSS 类和事件处理程序。例如，如果我们将 DOM 插入代码移到 `menu` 小部件被实例化之前，则没有理由调用 `refresh()`，因为菜单构造函数会直接调用它。

## 还有更多...

上述方法在菜单中插入新项目确实有其缺点。一个明显的缺点是实际构建新菜单项和子菜单的 DOM 插入代码不易维护。我们的示例已经将结构硬编码了，而大多数应用程序通常不这样做。相反，我们通常至少有一个数据源，可能来自 API。如果我们可以传递给菜单小部件一个标准格式的数据源，那就太好了。菜单小部件将负责我们上面实现的底层细节。

让我们尝试修改代码，以便更多的责任移到菜单小部件本身。我们将以与上面的代码完全相同的结果为目标，但我们将通过扩展菜单小部件，并传入代表菜单结构的数据对象来实现。我们将使用完全相同的 HTML 结构。以下是新的 JavaScript 代码:

```js
(function( $, undefined ) {

$.widget( "ab.menu", $.ui.menu, {

    options: {
        data: false
    },

    _create: function() {

        this._super();

        if ( !this.options.data ) {
            return;
        }

        var self = this;

        $.each( this.options.data, function( i, v ) {
            self._insertItem( v, self.element );
        });

        this.refresh();

    },

    _insertItem: function( item, parent ) {

        var $li = $( "<li/>" ).appendTo( parent );

        $( "<a/>" ).attr( "id", item.id )
                   .attr( "href", item.href )
                   .text( item.text )
                   .appendTo( $li );

        if ( item.data ) {

            var $ul = $( "<ul/>" ).appendTo( $li ),
                self = this;

            $.each( item.data, function( i, v ) {
                self._insertItem( v, $ul );
            });

        }

    }

});

})( jQuery );

$(function() {

    $( "#menu" ).menu({
        data: [
            {
                id: "fourth",
                href: "#",
                text: "Fourth Item"
            },
            {
                id: "fifth",
                href: "#",
                text: "Fifth Item",
                data: [
                    {
                        id: "sixth",
                        href: "#",
                        text: "Sixth Item"
                    },
                    {
                        id: "seventh",
                        href: "#",
                        text: "Seventh Item"
                    }
                ]
            }
        ]
    });

});
```

如果您运行这段修改后的代码，您会发现结果与我们上面编写的原始代码没有任何变化。这种改进纯粹是一种重构，将难以维护的代码变成了更长寿的东西。

我们在这里引入的新选项 `data` 期望一个菜单项数组。该项是一个带有以下属性的对象：

+   `id`：它是菜单项的 id

+   `href`：它是菜单项链接的 href

+   `text`：它是项目标签的项

+   `data`：它是一个嵌套的子菜单

最后一个选项只是表示子菜单的菜单项嵌套数组。我们对 `_create()` 方法的修改将遍历数据选项数组（如果提供），并在每个对象上调用 `_insertItem()`。 `_insertItem()` 方法是我们引入的新东西，并不会覆盖任何现有的菜单功能。在这里，我们正在为传入的菜单数据创建必要的 DOM 元素。如果这个对象有一个嵌套的数据数组，也就是子菜单，那么我们会创建一个 `ul` 元素，并递归调用 `_inserItem()`，将 `ul` 作为父元素传递进去。

我们传递给菜单的数据比以前的版本更易读和可维护。 例如，现在传递 API 数据所需的工作相对较少。

# 控制子菜单的位置

菜单小部件使用位置小部件来控制任何子菜单在可见时的目的地。 默认情况下，将子菜单的左上角放置在展开子菜单的菜单项的右侧。 但是，根据我们的菜单大小、子菜单的深度和 UI 中围绕大小的其他约束，我们可能希望使用不同的默认值来设置子菜单的位置。

## 准备工作

我们将使用以下 HTML 结构来进行子菜单定位演示：

```js
<ul id="menu">
            <li><a href="#first">First Item</a></li>
            <li><a href="#second">Second Item</a></li>
            <li><a href="#third">Third Item</a></li>
            <li>
              <a href="#forth">Fourth Item</a>
              <ul>
                <li><a href="#fifth">Fifth</a></li>
                <li>
                  <a href="#sixth">Sixth</a>
                  <ul>
                    <li><a href="#">Seventh</a></li>
                    <li><a href="#">Eighth</a></li>
                    </ul>
                  </li>
                </ul>
            </li>
        </ul
```

## 如何做...

当我们实例化此菜单时，我们将传递一个`position`选项，如下所示：

```js
<ul id="menu">
            <li><a href="#first">First Item</a></li>
            <li><a href="#second">Second Item</a></li>
            <li><a href="#third">Third Item</a></li>
            <li>
                <a href="#forth">Fourth Item</a>
                <ul>
                    <li><a href="#fifth">Fifth</a></li>
                    <li>
                        <a href="#sixth">Sixth</a>
                        <ul>
                            <li><a href="#">Seventh</a></li>
                            <li><a href="#">Eighth</a></li>
                        </ul>
                    </li>
                </ul>
            </li>
        </ul>
```

当所有子菜单展开时，我们的菜单将与下图所示类似：

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_06_04.jpg)

## 如何运作...

在前面的示例中，我们向菜单小部件传递的`position`选项与我们直接传递给位置小部件的选项相同。 位置小部件期望的`of`选项是活动菜单项或子菜单的父项。 所有这些选项都传递给`_open()`方法中的位置小部件，该方法负责展开子菜单。

# 将主题应用于子菜单

当菜单小部件显示子菜单时，外观上没有明显的区别。 也就是说，在视觉上，它们看起来就像是主菜单。 我们希望向用户展示主菜单和其子菜单之间的一点对比；我们可以通过扩展小部件以允许将自定义类应用于子菜单来实现这一点。

## 准备工作

让我们使用以下标记来创建带有几个子菜单的菜单小部件：

```js
<ul id="menu">
            <li><a href="#">First Item</a></li>
            <li><a href="#">Second Item</a></li>
            <li><a href="#">Third Item</a></li>
            <li>
                <a href="#">Fourth Item</a>
                <ul>
                    <li><a href="#">Fifth</a></li>
                    <li>
                        <a href="#">Sixth</a>
                        <ul>
                            <li><a href="#">Seventh</a></li>
                            <li><a href="#">Eighth</a></li>
                        </ul>
                    </li>
                </ul>
            </li>
        </ul>
```

## 如何做...

我们将通过添加一个新的`submenuClass`选项并将该类应用于子菜单来扩展菜单小部件，如下所示：

```js
(function( $, undefined ) {

$.widget( "ab.menu", $.ui.menu, {

    options: {
      submenuClass: false
    },

    refresh: function() {

      if ( this.options.submenuClass ) {

        this.element.find( this.options.menus + ":not(.ui-menu)" )
          .addClass( this.options.submenuClass );

        }

        this._super();

    }

});

})( jQuery );

$(function() {
    $( "#menu" ).menu( { submenuClass: "ui-state-highlight } );
});
```

下面是子菜单的外观：

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_06_05.jpg)

## 如何运作...

在这里，我们使用一个新的`submenuClass`选项扩展了菜单小部件。 我们的想法是，如果提供了这个类，我们只想将它应用于小部件的子菜单。 我们通过重写`refresh()`菜单方法来实现这一点。 我们查找所有子菜单并将`submenuClass`应用于它们。 您会注意到，在调用原始实现此方法的`_super()`方法之前，我们应用了这个类。 这是因为我们正在寻找尚未具有`ui-menu`类的菜单。 这些是我们的子菜单。


# 第七章：进度条

在本章中，我们将涵盖以下主题：

+   显示文件上传进度

+   动画化进度变化

+   创建进度指示器小部件

+   使用状态警告阈值

+   给进度条添加标签

# 介绍

**progressbar** 小部件相当简单——因为它没有太多的移动部分。事实上，它只有一个移动部分，即值栏。但是简单并不意味着进度条比其他小部件功能更弱。我们将看看如何在本章中利用这种简单性。进度条可以表达从文件上传进度到服务器端进程再到容量利用率的任何内容。

# 显示文件上传进度

如果有一种简单直接的方法可以使用进度条小部件显示文件上传的进度就好了。不幸的是，我们没有这样的奢侈。文件的上传发生在页面转换之间。然而，使用进度条小部件显示上传进度所需的必要技巧，由于现代标准和浏览器的发展，已经变得更加简洁。让我们看看如何利用**Ajax**请求中 XML HTTP 请求对象的 `onprogress` 事件。

## 准备工作

为了演示，我们将创建一个带有简单文件字段的简单表单。在表单内部，我们将创建一些用于显示进度条小部件的 HTML。它将在用户启动文件上传之前被隐藏。

```js
<form action="http://127.0.0.1:8000/" method="POST">
    <input type="file" name="fileupload"/>
    <br/>
    <input type="submit" value="Upload"/>
    <div id="upload-container" class="ui-helper-hidden">
        <strong id="upload-value">Uploading...</strong>
        <div id="upload-progress"></div>
    </div>
</form>
```

## 操作方法...

更新文件上传过程中更新进度条小部件所需的大部分工作实际上是在 Ajax 请求机制和 `onprogress` 事件处理程序中完成的。以下代码很好地说明了为什么小部件设计者应该以简单为目标。生成的小部件适用于各种情境。

```js
$(function() {

    $( "#upload-progress" ).progressbar();

    $( "form" ).submit( function( e ) {

        e.preventDefault();

        $.ajax({
            url: $( this ).attr("action"),
            type: "POST",
            data: new FormData( this ), 
            cache: false,
            contentType: false,
            processData: false,
            xhr: function() {

                xhr = $.ajaxSettings.xhr();

                if ( xhr.upload ) {
                    xhr.upload.onprogress = onprogress;
                }

                return xhr;

            }

        });

        return false;

    });

    var onprogress = function( e ) {

        var uploadPercent = ( e.loaded / e.total * 100 ).toFixed();

        $( "#upload-container" ).show();
        $( "#upload-value" ).text( "Uploading..." + uploadPercent + "%" );
        $( "#upload-progress" ).progressbar( "option", "max", e.total )
                               .progressbar( "value", e.loaded );

    }; 

});
```

如果您运行此示例并在本地上传文件到 `http://127.0.0.1:` `8000/`，您会希望使用一个较大的文件。较小的文件上传速度太快，时间太短。较大的文件上传将使您能够在上传过程中看到以下内容。

![操作方法...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_07_01.jpg)

### 注意

本书中的代码附带了一个最小的 Python 服务器，用于提供此演示上传页面并处理文件上传请求。该示例可以很容易地重新排列以与任何上传服务器配合使用，但是提供的 Python 服务器只需要安装 Python 即可。再次强调，这不是一个要求，但如果您渴望看到客户端代码运行的话，这只是一个方便的服务器。

## 工作原理...

该示例的目标是实时更新进度条小部件，随着文件上传进度的改变而改变。有几个插件可以提供这种功能，但如果您正在编写 jQuery UI 应用程序，最好统一使用进度条小部件。一旦文档准备就绪，我们首先创建用于显示文件上传进度的进度条小部件。 `#upload-container` 最初使用`ui-helper-hidden`类隐藏，因为我们不需要在上传正在进行之前显示上传进度。

接下来，我们设置我们上传表单的`submit`事件的事件处理程序。在执行任何其他操作之前，此处理程序防止默认表单提交。本质上，我们用我们自己的行为替换了浏览器实现的默认表单提交。我们需要覆盖此行为的原因是为了留在页面上，并对我们的进度条小部件应用更新。

接下来，我们设置实际将我们选定的文件发送到服务器的`$.ajax()`调用。我们从表单本身获取`url`参数。接下来的几个参数是发送多部分表单数据的先决条件，包括作为 Ajax 请求的一部分的选定文件。 `xhr` 选项是我们提供返回`xhr`对象的函数，内部由`$.ajax()`函数使用。这是我们截取`xhr`对象并附加其他行为的机会。我们主要感兴趣的是向`onprogress`事件添加新行为。

确保上传对象`XMLHttpRequestUpload`实际存在后，我们可以定义我们的`onprogress`事件处理程序函数。

首先，我们使用事件的`loaded`和`total`属性计算实际上传百分比。接下来，我们显示进度容器，并使用`uploadPercent`中的值更新百分比标签。最后，我们确保上传进度条小部件的`max`选项设置为`total`，并使用`value()`方法设置进度条的当前值。

# 动画化进度变化

进度条小部件在设置`value`或`max`选项时会改变其视觉外观。例如， `value` 的默认值为`0`， `max` 的默认值为`100`。因此，当以这些值显示进度条小部件时，我们实际上并不看到图形化的条，然而这表示了进度百分比。但是，设置`value`选项将更新此条。如果条已经可见，则`value`选项的更改会导致进度条的宽度改变。使用默认进度条实现，这些更改会立即改变小部件。让我们看看如何修改小部件以支持进度条值之间的平滑过渡。

## 如何做...

我们将使用以下简单的标记作为我们进度条小部件实例的基础：

```js
<div id="progress"></div>
```

这里是用于定制进度条小部件以支持动画更改进度的 JavaScript 代码：

```js
(function( $, undefined ) {

$.widget( "ab.progressbar", $.ui.progressbar, {

    options: {
        animate: false
    },

    _refreshValue: function() {

        if ( !this.options.animate ) {
            return this._super();
        }

        var value = this.value(),
            percentage = this._percentage();

        if ( this.oldValue !== value ) {
            this.oldValue = value;
            this._trigger( "change" );
        }

        this.valueDiv.toggle( value > this.min )               .toggleClass( "ui-corner-right",
value === this.options.max )
                             .stop( true, true )
                             .animate( { width: percentage.toFixed( 0 ) + "%" }, 200 );

              this.element.attr( "aria-valuenow", value );

    }

});

})( jQuery );

$(function() {

    $( "#progress" ).progressbar( { animate: true } );

    var timer;

    var updater = function() {

        var value = $( "#progress" ).progressbar( "value" ) + 10,
            maximum = $( "#progress" ).progressbar( "option", "max" );

        if ( value >= maximum ) {
            $( "#progress" ).progressbar( "value", maximum );
            return;
        }

        $( "#progress" ).progressbar( "value", value );
        timer = setTimeout( updater, 700 );

    };

    timer = setTimeout( updater, 700 );

});
```

此示例包括一个更新器，将每 0.7 秒的间隔递增进度条值。您会注意到随着值的变化应用的平滑宽度过渡。与默认行为相比较，将`animate`选项设置为`false`，您现在将真正注意到每次更新值时进度条所做的视觉跳跃。

## 它是如何工作的...

我们的示例代码通过添加一个新的`animate`选项来扩展进度条小部件。新的`animate`选项默认为`false`。我们向进度条小部件引入的另一个更改是`_refreshValue()`方法的新实现，该方法在`value`选项更改时由小部件内部调用。此方法负责使`div`元素`progress`上的可视宽度发生变化。这代表了`value`和`max`之间的进度。

很多这段代码都是从`_refreshValue()`的原始实现中借鉴而来的，因为我们只做了些微的修改。首先，我们检查了我们添加到小部件中的`animate`选项是否为`true`值。如果不是，则我们继续使用原始实现。否则，我们使用相同的代码，但对应用宽度的方式进行了轻微调整。然后，我们调用`stop(true, true)`来完成当前动画并清除动画队列。接下来，我们不再像原始实现那样使用`width()`函数，而是通过调用`animate()`来设置宽度。

## 这还不是全部...

与往常一样，我们不局限于使用 jQuery 的`animate()`函数来对进度条值之间的视觉过渡应用效果。除了`animate()`函数之外，我们还可以将 CSS 过渡应用于进度条值。当然，缺点是并非所有浏览器都支持 CSS 过渡，并且我们涉及到特定于供应商的样式规则。尽管如此，让我们将先前的方法与使用 CSS 样式来动画进度条进行比较。

我们将使用相同的标记，但我们将向页面引入以下样式：

```js
.ui-progressbar-animated > .ui-progressbar-value {
    transition: width 0.7s ease-out;
    -moz-transition: width .7s ease-out;
    -webkit-transition: width 0.7s ease-out;
    -o-transition: width 0.7s east-out;
}
```

这里是 JavaScript 代码的必要更改。它看起来与之前的代码类似。

```js
(function( $, undefined ) {

$.widget( "ab.progressbar", $.ui.progressbar, {

    options: {
        animate: false
    },

    _create: function() {

        this._super();

        if ( !this.options.animate ) {
            return;
        }

        this.element.addClass( "ui-progressbar-animated" );

    }

});

})( jQuery );

$(function() {

    $( "#progress" ).progressbar( { animate: true } );

    var timer;

    var updater = function() {

        var value = $( "#progress" ).progressbar( "value" ) + 10,
            maximum = $( "#progress" ).progressbar( "option", "max" );

        if ( value >= maximum ) {
            $( "#progress" ).progressbar( "value", maximum );
            return;
        }

        $( "#progress" ).progressbar( "value", value );
        timer = setTimeout( updater, 700 );

    };

    timer = setTimeout( updater, 700 );

});
```

运行此示例将与先前的`animate`选项实现看起来并无太大不同。过渡行为将基本相同。这里的关键区别在于我们正在扩展主题框架。我们为进度条小部件引入了一个新的 CSS 类——`ui-progressbar-animated`。选择器`.ui-progressbar-animated > .ui-progressbar-value，`适用于进度条值`div`，即宽度发生变化的元素。而我们的新样式正是如此。它们在 0.7 秒的时间段内过渡宽度属性值的变化。

这种方法的主要受益者是 JavaScript 代码，因为进度条小部件的变化较少。例如，我们不再覆盖`_refreshValue()`方法。相反，我们正在覆盖`_create()`方法，并且如果`animated`选项为`true`，则在元素中添加`ui-progressbar-animated`类。这是我们新样式如何生效的方式。其余实例化小部件和值更新器的 JavaScript 与前一个示例没有任何不同。

# 创建进度指示器小部件

进度条小部件旨在显示某个过程的进度。最终目标是在创建小部件时指定的`max`选项，默认为`100`。如果我们事先知道正在处理的数据的大小，我们将使用`max`选项来反映此最终目标。但是，有时我们面临的情况是在客户端执行一些处理；或者，我们正在等待某个后端进程完成并将响应发送回客户端。例如，用户使用 API 启动了后端任务，现在他们正在等待响应。关键是，我们希望向用户说明正在进行进度，而不知道已经完成了多少进度。

为了显示进度正在进行，尽管不知道有多少进度，我们需要一个指示器小部件。我们可以编写自己的小部件来实现这一点，扩展进度条小部件，因为我们可以在那里重用许多组件。

## 如何做…

对于我们的进度指示器小部件，我们将使用与基本进度条小部件相同的 HTML。

```js
<div id="indicator"></div>
```

接下来，我们需要对进度条的 CSS 样式进行一些轻微的调整。这些应用于进度条`div`内部的值栏。我们去掉了`border`和`margin`，因为在来回滑动值栏时这样看起来更好。

```js
.ui-progressbar > .ui-progressbar-value {
    border: none;
    margin: 0px;
}
```

现在，我们来实现进度指示器小部件。此代码还将创建我们的进度指示器小部件的实例。

```js
(function( $, undefined ) {

$.widget( "ab.progressindicator", $.ui.progressbar, {

    _create: function() {

        this._super();
        this.value( 40 );
        this.element.removeClass( "ui-corner-all" );
        this.valueDiv.removeClass( "ui-corner-right ui-corner-left" );

        var self = this,
            margin = ( this.element.innerWidth() - this.valueDiv.width() ) + "px";

        var _right = function() {

            self.valueDiv.animate(
                { "margin-left": margin },
                { duration: 1000, complete: _left }
            );

        };

        var _left = function() {

            self.valueDiv.animate(
                { "margin-left": "0px" },
                { duration: 1000, complete: _right }
            );

        };

        _right();

    },

    _destroy: function() {

        this.valueDiv.stop( true, true );
        this._super();

    }

});

})( jQuery );

$(function() {

    $( "#indicator" ).progressindicator();

});
```

如果您在浏览器中查看此进度指示器小部件，您将看到它通过来回滑动进度条小部件的值栏来进行动画处理，表示正在发生某事。

![如何做…](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_07_02.jpg)

## 它的工作原理…

我们创建了一个新的进度指示器小部件，继承了进度条小部件的功能。进度指示器小部件的目标是获取进度值栏`div`，在其中设置宽度，并在进度条容器`div`内滑动。视觉上，这表示幕后正在发生某事。这种图形化描述活动是对用户普遍令人放心的，因为它给人一种正在发生某事的感觉，并且应用程序没有崩溃。

在新进度指示器小部件的定义中，我们要重写的第一个方法是进度条的`_create()`方法。在这里，我们调用进度条小部件的原始构造函数，因为我们在开始进行更改之前需要所有的 UI 组件就位。接下来，我们使用`value()`方法为值条`div`设置宽度。我们在`progressindicator()`构造函数中硬编码了此值，只是因为使用此小部件的开发人员没有必要更改它；我们只需要设置元素的宽度。为了进一步简化此小部件，我们从元素中删除了角类。我们可以留下它们，但是在动画条时我们将不得不处理几种角例，因为我们追求的是一个简单的小部件，一个不需要开发人员进行配置的小部件。

仍然在`_create()`方法内部，我们定义了两个用于执行动画的实用函数。正如你可能猜到的那样，`_right()`函数将进度值条向右滑动，而`_left()`函数将其向左滑动。我们在该小部件的`valueDiv`属性上调用了`animate()`jQuery 函数。`_right()`函数通过更新`margin-left`值将值`div`向右滑动。您会注意到，`margin`变量在`_create()`内部局部定义。这是通过计算我们在值`div`右侧有多少空间来完成的，这意味着我们将此值设置为`margin-left`以将其向右滑动。要再次将其向左滑动，我们只需在`_left()`函数中将`margin-left` CSS 属性设置回`0px`。

通过在`_create()`方法的底部调用`_right()`来引导动画。通过将`_left()`作为初始动画的回调传递，进度指示器动画循环发生。同样，在`_left()`函数内部将`_right()`作为动画完成回调传递。此过程将继续直到小部件被销毁。我们的小部件重写了`_destroy()`方法，只是为了确保所有动画立即停止。这包括任何等待执行的排队动画。然后，我们通过调用原始的`_destroy()`实现来继续销毁小部件。

## 还有更多...

我们的进度指示器小部件的一个优点是它提供了一个非常简单的 API。您可以根据需要创建和销毁小部件，而无需处理任何中间步骤。理想情况下，这个小部件的寿命会非常短，可能只有一秒钟（刚好足够看到一个动画循环）。然而，有时候可能需要更长一点。如果这个小部件要长时间显示，它可能会对应用程序造成问题。jQuery 的`animate()`函数并不是设计成无限循环运行动画的。我们的小部件也不是设计成长时间显示的。问题在于`animate()`使用计时器，可能会大幅消耗客户端的 CPU 周期。这不仅可能对我们的应用程序造成破坏，还可能对在用户机器上运行的其他应用程序造成影响。

尽管这是一个相对较小的问题，让我们来看看我们的进度指示器小部件的另一种实现方式，即使用 CSS 动画。以下是我们如何在 CSS 中定义动画的方式：

```js
.ui-progressindicator > .ui-progressbar-value {
    border: none;
    margin: 0px;
    animation: indicator 2s ease-in-out infinite;
    -moz-animation: indicator 2s ease-in-out infinite;
    -webkit-animation: indicator 2s ease-in-out infinite;
}

@keyframes indicator {
    0%   { margin-left: 0px; }
    50%  { margin-left: 108px; }
    100% { margin-left: 0px; }
}

@-moz-keyframes indicator {
    0%   { margin-left: 0px; }
    50%  { margin-left: 108px; }
    100% { margin-left: 0px; }
}

@-webkit-keyframes indicator {
    0%   { margin-left: 0px; }
    50%  { margin-left: 108px; }
    100% { margin-left: 0px; }
}

@-o-keyframes indicator {
    0%   { margin-left: 0px; }
    50%  { margin-left: 108px; }
    100% { margin-left: 0px; }
}
```

并且，这是我们的`progressindicator`小部件的修改后的 JavaScript 实现，它知道如何利用先前的 CSS：

```js
(function( $, undefined ) {

$.widget( "ab.progressindicator", $.ui.progressbar, {

  _create: function() {

        this._super();
        this.value( 40 );
        this.element.addClass( "ui-progressindicator" )
                    .removeClass( "ui-corner-all" );
        this.valueDiv.removeClass( "ui-corner-right ui-corner-left" );

    },

    _destroy: function() {

        this.element.removeClass( "ui-progressindicator" );
        this._super();

    }

});

})( jQuery );

$(function() {

    $( "#indicator" ).progressindicator();

});
```

现在，如果你在浏览器中查看这个小部件的修改版本，你应该会发现与以前的实现相比几乎完全一样的结果。当然，关键的区别在于动画是在 CSS 中指定并直接由浏览器执行。与基于 JavaScript 的对应物相比，浏览器可以更有效地处理这些类型的 CSS 动画。浏览器只需要一次读取动画规范，然后在内部运行动画，使用本机代码而不是执行 JavaScript 并直接操作 DOM。我们可以让这个版本运行一整天，浏览器会愉快地继续运行。

但是这个版本的进度指示器并不是没有缺点的。首先，让我们仔细看看 CSS。事实上，我们依赖 CSS 动画本身并不是最好的选择，因为不同浏览器对其支持存在差异。在这里，通过我们的样式，我们将自己陷入了浏览器厂商前缀混乱的困境。总的来说，支持还不错，因为只有 IE 不支持 CSS 动画；但是动画的定义很直接。在`.ui-progressindicator > .ui-progressbar-value`选择器中，我们指定了指示器动画将运行`2`秒，并且会无限重复。`@keyframes`指示器动画指定了`margin-left`属性本身的变化方式。

在 JavaScript 中，你会注意到代码本身要简单得多。这是因为它现在负责的事情要少得多。主要是，在创建时需要将 `ui-progressindicator` 类添加到小部件的 DOM 元素上，并在销毁时删除该类。你还会注意到，在实现小部件的 JavaScript 代码中不再进行边距计算。相反，我们将这些数字移到了定义小部件动画的 CSS 中作为硬编码值。再次强调，这只是小部件设计者必须考虑的一个权衡。我们在 CSS 中交换了更高的维护成本以获得更高效的动画，并为我们的小部件提供了更简单的 JavaScript，以牺牲可疑的浏览器支持。

# 使用状态来警告阈值

进度条小部件不仅限于标记朝某个结束点的进展。它还可以用作某些资源利用的标记。例如，你的应用程序可能允许用户存储 100 MB 的图像数据。显示当前使用了多少容量可能是有意义的。进度条小部件是图形化显示此类资源利用情况的理想解决方案。更进一步，我们可能还希望警告用户关于使用阈值。也就是说，在某个百分比下，资源接近容量，但用户仍然有时间对此做出反应。

## 准备工作

为了演示，我们将为要显示的两个进度条小部件创建两个简单的 `div` 元素：

```js
<span>CPU:</span>
<div id="cpu-utilization"></div>
<span>Memory:</span>
<div id="memory-utilization"></div>
```

## 如何做...

下面是扩展进度条小部件的 JavaScript 代码，提供了一个新的选项来指定阈值：

```js
(function( $, undefined ) {

$.widget( "ab.progressbar", $.ui.progressbar, {

    options: {
        threshold: 0
    },

  _percentage: function() {

        var percentage = this._super(),
            threshold = this.options.threshold;

        if ( threshold <= 0 ) {
            return percentage;
        }

        if ( percentage > threshold ) {
            this.valueDiv.addClass( "ui-state-error" );
        }
        else {
            this.valueDiv.removeClass( "ui-state-error" );
        }

        return percentage;

  },

});

})( jQuery );

$(function() {

    $( "#cpu-utilization" ).progressbar( { threshold: 80 } );
    $( "#memory-utilization" ).progressbar( { threshold: 85 } );

    setInterval(function() {
        var cpu = Math.floor( ( Math.random() * 100 ) + 1 ),
            memory = Math.floor( ( Math.random() * 100 ) +1 );

        $( "#cpu-utilization" ).progressbar( "value", cpu );
        $( "#memory-utilization" ).progressbar( "value", memory );

    }, 1300);

});
```

我们在这里实例化了两个进度条小部件，并启动了一个基本的定时器间隔，每 1.30 秒更改一次两个进度条小部件的值。如果你在浏览器中查看此示例，你会注意到一个或两个进度条小部件将进入错误状态，因为值已超过提供的阈值。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_07_03.jpg)

## 工作原理...

我们添加到进度条小部件的新 `threshold` 选项是一个以百分比表示的数字。这是进度条的阈值，在这个阈值上，状态会改变以向用户发出视觉警告。这是通过重写 `_percentage()` 方法来实现的。在这里，我们通过调用 `_percentage()` 的原始实现并将其存储在 `percentage` 中来获得实际的百分比值。然后，我们确保 `threshold` 值非零，并且计算出的百分比大于 `threshold` 值。每次更新值时，进度条小部件都会内部调用 `_percentage()` 方法，并且视觉显示会发生变化。因此，在我们的 `_percentage()` 实现中，如果超过阈值，我们将 `ui-state-error` 类添加到 `valueDiv` 元素中，该元素是进度条内部移动的图形条。否则，我们低于阈值，并且必须确保删除 `ui-state-error` 类。

一旦我们创建了两个小部件，我们就使用 `setInterval()` 不断为两个进度条分配一个随机值。您可以坐下来观看进度条小部件如何根据输入的数据是否跨越我们指定的阈值而改变状态。在这种情况下，`#cpu-utilization` 进度条的阈值为 `80`%，而 `#memory-utilization` 进度条的阈值为 `85%`。

# 给进度条添加标签

反映进度百分比变化宽度的图形条表现得很好。进度条小部件的强大之处在于一眼就能看到已经完成了多少进度，或者正在利用多少资源。但有时候我们可能需要一些关于百分比的准确度，即显示底层百分比的标签。

进度条小部件具有在进度条容器内显示标签的功能，这比在小部件外部显示百分比标签更直观。让我们看看如何扩展主题 CSS，为小部件提供额外的标记，并扩展进度条以利用这些新的附加功能来显示标签。

## 如何操作...

我们首先为我们的两个进度条小部件创建 HTML。

```js
<span>Network:</span>
<div id="network-utilization">
    <div class="ui-progressbar-label"></div>
</div>
<span>Storage:</span>
<div id="storage-utilization">
    <div class="ui-progressbar-label"></div>
</div>
```

接下来，我们将添加进度条标签所需的 CSS 类。

```js
.ui-progressbar-label {
    float: left;
    width: 100%;
    text-align: center;
    margin-top: 5px;
    font-weight: bold;
}
```

最后，我们将扩展进度条小部件本身，将这个新的 HTML 和新的 CSS 绑定在一起。

```js
(function( $, undefined ) {

$.widget( "ab.progressbar", $.ui.progressbar, {

    _create: function() {
        this.$label = this.element.find( ".ui-progressbar-label" );
        this._super();

    },

    _destroy: function() {

        this.$label.remove();

        this._super();

    },

  _refreshValue: function() {
        this.$label.text( this._percentage().toFixed( 0 ) + "%" );
        this._super();

  },

});

})( jQuery );

$(function() {

    $( "#network-utilization" ).progressbar({
        value: 746586112,
        max: 1073741824
    });

    $( "#storage-utilization" ).progressbar({
        value: 24696061952,
        max: 107374182400
    });

});
```

您现在可以在浏览器中查看这两个进度条，您会注意到两个标签显示百分比值的位置位于小部件的中心。

![如何操作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_07_04.jpg)

## 它是如何工作的...

默认情况下，进度条小部件不支持标签，因此我们必须将标签 `div` 放在进度条 `div` 中。我们还给这个新的标签 `div` 添加了 `ui-progressbar-label` 类，这与 jQuery UI 主题命名规范一致。这个类实际上有两个作用：在我们引入的小部件自定义中，我们使用这个类来搜索标签 `div` 并应用标签样式。

在 `ui-progressbar-label` 中指定的 CSS 规则有助于将标签文本定位在进度条元素的中间。我们给标签 `div` 一个宽度为 `100%`，并使用 `text-align` 属性水平对齐文本。最后，我们使标签的 `font-weight` 为 `bold` 以使其突出显示；否则，在进度条的背景下很难看到它。

我们在这里介绍的进度条小部件的自定义 JavaScript 实现覆盖了 `_create()` 方法。我们创建了一个称为 `labelDiv` 的新实例变量，它存储对我们新元素的引用。然后我们调用原始的 `_create()` 实现，构造函数继续正常进行，创建我们的新标签元素旁边的值 `div`。我们还重写了 `_refreshValue()` 方法以更新 `labelDiv` 的内容。`_refreshValue()` 方法在任何时候内部被小部件调用，当值改变并且进度条小部件需要更新值显示时，会更新 `labelDiv` 的值。我们通过在恢复 `_refreshValue()` 的原始实现之前使用 `_percentage()` 数字来扩展此行为。

## 还有更多...

我们实施进度条标签的这种方法可能遇到的一个潜在问题是，我们必须改变 HTML 结构。这违反了 DRY 原则，因为我们为每个创建的进度条小部件添加的每个标签 `div` 都是完全相同的。此外，我们可能希望为已存在于应用程序中的进度条小部件应用标签。改变已经正常工作的小部件的 HTML 不是最好的方法。让我们想想如何改进之前的代码。

我们创建的用于定位和样式化标签元素的 CSS 是可以的。它遵循正确的命名约定，并适用于所有进度条小部件实例。我们想要更改的是用于实例化带有显示的标签的进度条小部件的必要标记。问题是如何。理想情况下，通过一个选项，让开发人员切换标签的显示和隐藏。然后小部件本身将负责在必要时插入标签 `div`，因为它对于小部件的所有实例都是相同的，这反过来意味着最小的 JavaScript 代码。

让我们看一下简化的标记，遵循与之前相同的例子:

```js

<span>Network:</span>
<div id="network-utilization"></div>
<span>Storage:</span>
<div id="storage-utilization"></div>
```

我们现在回到了进度条小部件在我们引入修改之前期望的原始标记。 现在让我们更新小部件代码以利用这个标记，通过添加一个新选项。

```js
(function( $, undefined ) {

$.widget( "ab.progressbar", $.ui.progressbar, {

    options: {
        label: false
    },

    _create: function() {

        if ( !this.options.label ) {
            return this._super();
        }

        this.$label = $( "<div/>" ).addClass( "ui-progressbar-label" )
                                   .appendTo( this.element );

        this._super();

    },

    _destroy: function() {

        if ( !this.options.label ) {
            return this._super();
        }

        this.$label.remove();

        this._super();

    },

    _refreshValue: function() {

        if ( !this.options.label ) {
            return this._super();
        }

        this.$label.text( this._percentage().toFixed( 0 ) + "%" );

        this._super();

    },

});

})( jQuery );

$(function() {

    $( "#network-utilization" ).progressbar({
        value: 746586112,
        max: 1073741824,
        label: true
    });

    $( "#storage-utilization" ).progressbar({
        value: 24696061952,
        max: 107374182400
    });

});
```

在这里，我们通过新的`label`选项扩展了进度条小部件，该选项默认为`false`。 思路是当这个值为`true`时，我们将`label div`插入到进度条容器中。 我们对`_create()`和`_refreshValue()`方法的修改基本与先前的代码相同，只是现在我们在执行自定义行为之前检查`label`选项是否已打开。 正如您所看到的，我们将这个新的标签选项提供给了`#network-utilization` div，但没有提供给`#storage-utilization` div。

![更多内容请参考...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_07_05.jpg)
