# jQuery UI 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/6053054F727DA7F93DC0A95B33107695`](https://zh.annas-archive.org/md5/6053054F727DA7F93DC0A95B33107695)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用滑块

在本章中，我们将涵盖：

+   控制滑块手柄的大小

+   移除焦点轮廓

+   使用主滑块和子滑块

+   标记步进增量

+   获取范围值

+   更改滑块方向

# 介绍

**滑块**部件几乎就像一个用户可以操纵的进度条。滑块给用户一个手柄，可以沿平面拖动以产生所需值。这在处理表单值时尤其有用。滑块部件默认具有有用的选项，如更改方向的能力和允许用户选择值范围。在本章中，我们将看看通过添加新选项或附加事件处理函数来调整滑块部件的各种方法。我们还将研究一些视觉调整以及滑块实例如何相互通信。

# 控制滑块手柄的大小

用于控制滑块位置的**滑块手柄**，由鼠标拖动，是一个正方形。也就是说，宽度与高度相同，而我们可能想要不同形状的滑块手柄。在**水平滑块**的情况下，即默认方向，让我们看看如何通过覆盖部件 CSS 样式来改变滑块手柄的形状，以满足我们应用程序的需求。

## 准备好...

我们将创建的 HTML 是两个滑块部件。我们还将为它们添加标签，并将它们各自包装在容器 div 元素中以控制布局。

```js
<div class="slider-container">
    <span>Treble:</span>
    <div id="treble"></div>
</div>
<div class="slider-container">
    <span>Bass:</span>
    <div id="bass"></div>
</div>
```

## 如何做...

这是用于自定义滑块手柄的 CSS。这覆盖了部件 CSS 中定义的值，因此应包含在 jQuery UI 样式表之后的页面中：

```js
.ui-slider-horizontal .ui-slider-handle {
    width: 0.8em;
    height: 1.6em;
    top: -0.48em;
}
```

以下是用于创建两个滑块部件实例的 JavaScript 代码：

```js
$(function() {

    $( "#treble" ).slider();
    $( "#bass" ).slider();

});
```

作为参考，这是应用我们自定义 CSS 前两个滑块部件的外观：

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_08_01.jpg)

这是应用我们自定义 CSS 后的相同两个滑块部件：

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_08_02.jpg)

## 它的工作原理...

如您所见，手柄变得更高，延伸到滑块边界之外。这为用户提供了更大的点击和拖动滑块手柄的表面积。我们引入的确切尺寸变化是任意的，可以根据每个应用程序进行调整。

`.ui-slider-horizontal .ui-slider-handle` 选择器覆盖了部件 CSS 中定义的三个属性。宽度被改变为 `0.8em`，使其略微变细。`height` 属性的值被改为 `1.6em`，使其变得更高。当我们使用 `height` 属性使手柄变高时，我们将其向下推，以使其不再与滑块对齐。为了弥补高度变化，我们通过减少 `top` 值来将其拉回上来，直到 `-0.48em`。

# 移除焦点轮廓

大多数浏览器在接收到焦点时在元素周围显示虚线或实线**轮廓**。这不是用户界面样式的一部分，而是浏览器内置的辅助功能特性。例如，滑块手柄周围的这种强制视觉显示并不总是理想的。让我们看看我们如何取消滑块手柄的默认浏览器行为。

## 如何做到...

我们可以使用任何基本的`div`元素来构建我们的示例滑块小部件。所以让我们直接跳转到我们的自定义滑块小部件 CSS。

```js
.ui-slider-handle-no-outline {
    outline: 0;
}
```

现在，我们已经有了我们的滑块小部件的自定义实现和我们自定义滑块的一个实例。

```js
(function( $, undefined ) {

$.widget( "ab.slider", $.ui.slider, {

    options: { 
        handleOutline: true
    },

    _create: function() {

        this._super();

        if ( this.options.handleOutline ) {
            return;
        }

        this.handles.addClass( "ui-slider-handle-no-outline" );

    }

});

})( jQuery );

$(function() {

    $( "#slider" ).slider({
        handleOutline: false,
    });

});
```

在对滑块小部件应用我们的更改之前，拖动手柄后轮廓看起来如下所示：

![如何做到...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_08_03.jpg)

在对滑块小部件应用我们的更改后，拖动手柄后我们的滑块实例如下所示：

![如何做到...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_08_04.jpg)

## 工作原理...

我们已经为滑块小部件添加了一个名为`handleOutline`的新选项。我们将此选项默认设置为`true`，因为始终支持原生浏览器行为是一个好主意。当此选项设置为`false`时，该选项会关闭此原生边框轮廓功能。它通过向滑块中的每个手柄元素添加`ui-slider-handle-no-outline`类来实现。一个滑块中可以有很多手柄，例如，一个范围滑块。因此，在`_create()`方法中，我们检查`handleOutline`选项是否为`true`，如果是，我们使用存储为该小部件属性的`handles` jQuery 对象来应用我们创建的新类。

类本身很简单，因为它只改变了一个属性。事实上，我们可以简单地将`outline`属性添加到`ui-slider-handle`类中，值为`0`，而不是创建一个新类。但是，我们选择的方法允许我们保持本地小部件样式不变，这样可以让轮廓浏览器功能为我们的小部件的每个实例切换打开或关闭。您还会注意到，即使没有本地浏览器轮廓，手柄也不会失去任何可访问性，因为 jQuery UI 状态类为我们处理了这个问题。

# 使用主滑块和子滑块

应用程序可能会使用一些可以进一步分解为较小值的数量。此外，用户可能需要控制这些较小值，而不仅仅是聚合值。如果我们决定使用滑块小部件来实现这个目的，我们可以想象子滑块观察主滑块的变化值。让我们看看如何实现这样一组滑块。我们将设计一个界面，允许我们分配该应用程序可以使用多少 CPU。这是**主滑块**。我们假设一个四核架构，因此我们将有四个依赖于主 CPU 滑块并观察主 CPU 滑块的子滑块。

## 如何做到...

这里是用于定义我们的五个滑块布局的 HTML。每个滑块都有自己的 `div` 容器，主要用于定义宽度和边距。在 `div` 容器内，我们有每个 CPU 的标签，它们的当前 MHz 分配和最大值。这也是放置每个滑块小部件的地方。

```js
<div class="slider-container">
    <h2 class="slider-header">CPU Allocation:</h2>
    <h2 class="slider-value ui-state-highlight"></h2>
    <div class="ui-helper-clearfix"></div>
    <div id="master"></div>
</div>

<div class="slider-container">
    <h3 class="slider-header">CPU 1:</h3>
    <h3 class="slider-value ui-state-highlight"></h3>
    <div class="ui-helper-clearfix"></div>
    <div id="cpu1"></div>
</div>

<div class="slider-container">
    <h3 class="slider-header">CPU 2:</h3>
    <h3 class="slider-value ui-state-highlight"></h3>
    <div class="ui-helper-clearfix"></div>
    <div id="cpu2"></div>
</div>

<div class="slider-container">
    <h3 class="slider-header">CPU 3:</h3>
    <h3 class="slider-value ui-state-highlight"></h3>
    <div class="ui-helper-clearfix"></div>
    <div id="cpu3"></div>
</div>

<div class="slider-container">
    <h3 class="slider-header">CPU 4:</h3>
    <h3 class="slider-value ui-state-highlight"></h3>
    <div class="ui-helper-clearfix"></div>
    <div id="cpu4"></div>
</div>
```

接下来，我们有一些 CSS 样式来帮助对齐和定位这些组件。

```js
.slider-container { 
    width: 200px;
    margin: 5px;
}

.slider-header {
    float: left;
}

.slider-value {
    float: right;
}
```

最后，我们有我们的 JavaScript 代码，该代码扩展了滑块小部件，为使用它的开发人员提供了两个新选项，`parent` 和 `percentage`。文档加载时，我们实例化了我们的 CPU 滑块小部件，并利用我们的新滑块功能来建立它们之间的适当关系。

```js
(function( $, undefined ) {

$.widget( "ui.slider", $.ui.slider, {

    options: {
        parent: null,
        percentage: null
    },

    _create: function() {

        this._super();

        var parent = this.options.parent,
            percentage = this.options.percentage,
            $parent;

        if ( !( parent && percentage ) ) {
            return;
        }

        $parent = $( parent );

        this._reset( $parent.slider( "value" ) );

        this._on( $parent , { 
            slidechange: function( e, ui ) {
                this._reset( ui.value );
            }
        });

    },

    _reset: function( parentValue ) {

        var percentage = ( 0.01 * this.options.percentage ),
            newMax = percentage * parentValue,
            oldMax = this.option( "max" ),
            value = this.option( "value" );

        value = ( value / oldMax ) * newMax;

        this.option( "max", newMax );
        this.option( "value", value );

    }

});

})( jQuery );

$(function() {

    function updateLabel( e, ui ) {

        var maxValue = $( this ).slider( "option", "max" )
                                .toFixed( 0 ),
            value = $( this ).slider( "value" )
                             .toFixed( 0 ) + " MHz" +
                                             " / " + 
                                             maxValue + 
                                             "MHz";

        $( this ).siblings( ".slider-value" ).text( value );

    }

    $( "#master" ).slider({
        range: "min",
        value: 379,
        min: 1,
        max: 2400,
        create: updateLabel,
        change: updateLabel
    });

    $( "#cpu1" ).slider({
        parent: "#master",
        percentage: 25,
        range: "min",
        min: 0,
        create: updateLabel,
        change: updateLabel
    });

    $( "#cpu2" ).slider({
        parent: "#master",
        percentage: 35,
        range: "min",
        min: 0,
        create: updateLabel,
        change: updateLabel
    });

    $( "#cpu3" ).slider({
        parent: "#master",
        percentage: 15,
        range: "min",
        min: 0,
        create: updateLabel,
        change: updateLabel
    });

    $( "#cpu4" ).slider({
        parent: "#master",
        percentage: 25,
        range: "min",
        min: 0,
        create: updateLabel,
        change: updateLabel
    });

});
```

在浏览器中查看结果滑块小部件，并调整一些子 CPU 值。您会注意到标签更新已经改变，并且每个 CPU 都有其自己的 CPU 分配。

![操作步骤...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_08_05.jpg)

现在，保持 CPU 值不变，尝试调整主 CPU 分配滑块。您会注意到每个子 CPU 滑块的当前值和最大值都会改变，但比例是保持不变的。这意味着如果我们设置 CPU 1 使用总体 CPU 分配的 10%，即使总体分配增加或减少，它仍将继续使用 10%。

![操作步骤...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_08_06.jpg)

## 工作原理...

在我们为 CPU 滑块创建的每个容器 `div` 元素中，我们都有一个名为 `slider-value` 的头部，用于显示滑块的当前值以及最大值。这是一个需要在大多数情况下考虑的重要补充，而滑块小部件则非常适合让用户更改值，但他们需要特定的反馈来显示他们操作的结果。在这个例子中，更改主滑块会更新五个标签，进一步凸显了在用户能够看到的滑块外部标记特定滑块值的必要性。

我们在滑块小部件中新增了两个选项，`parent` 和 `percentage`。这两个选项彼此相关，基本上可以理解为"此滑块的最大值是其父级滑块值的百分比"。在 `_create()` 方法中，我们在继续之前会检查这两个选项是否有实际值，因为它们默认为`null`。如果没有值，我们已经使用 `_super()` 方法调用了原始滑块构造函数，因此我们可以安全地返回。

另一方面，如果我们已经得到了一个父级滑块小部件和一个百分比，我们将调用`_reset()`方法，并将当前值传递给我们的父级滑块。这将可能更新此小部件的最大值和当前值。完成这些操作后，我们设置了一个观察者，用于观察父级滑块的更改。这是使用`_on()`方法完成的，我们在其中传递`parent`作为我们正在监听事件的元素以及配置对象。该对象具有一个`slidechange`事件，这是我们感兴趣的事件，以及回调函数。在回调函数内部，我们只是使用来自父级的更新值简单地调用了我们的`_reset()`方法。值得注意的是，我们必须使用`_on()`来注册我们的事件处理程序。如果销毁了子滑块，事件处理程序将从父级中删除。

`_reset()`方法接受来自父级滑块的值，并重置此子滑块的`值`和`最大`选项。我们在首次创建子元素和父元素值更改时都使用此方法。目标是保持当前值/最大值比率。这就是`percent`选项发挥作用的地方。由于这作为整数传递给小部件，我们必须将其乘以`0.01`。这是我们计算出该子级的新最大值的方法。一旦我们有了新的最大值，我们就可以将当前值放大或缩小。

最后，在文档准备就绪的事件处理程序中，我们实例化了五个滑块小部件，在其中定义了一个用于更新每个 CPU `div` 中标签的通用回调函数。这个函数被传递给了每个滑块小部件的创建和更改选项。我们还在这里使用了我们新定义的选项的值。每个子滑块都有一个独特的总 CPU 分配的`百分比`值，并且每个子元素都使用`#master`作为其`父级`。

# 标记步长增量

滑块小部件可以传递一个步长值，该值确定用户可以滑动手柄的增量。如果未指定，`步长`选项为`1`，手柄会平滑地来回滑动。另一方面，如果`步长`值更加明显，比如`10`，我们会注意到随着移动手柄而手柄会吸附到位置。让我们看看我们如何扩展滑块小部件以使用户更好地感受到这些增量的位置。我们将使用刻度来在视觉上标记增量。

## 如何做...

我们将直接进入用于此小部件增强的自定义 CSS。用于滑块元素的基础`div`元素可以简单地是`<div></div>`。

```js
.ui-slider-tick {
    position: absolute;
    width: 2px;
    height: 15px;
    z-index: -1;
}
```

这是我们的 JavaScript 代码，扩展了滑块并使用新的`ticks`选项创建了小部件的实例：

```js
(function( $, undefined ) {

$.widget( "ab.slider", $.ui.slider, {

    options: {
        ticks: false
    },

    _create: function() {

        this._super();

        if ( !this.options.ticks || this.options.step < 5 ) {
            return;
        }

        var maxValue = this.options.max,
            cnt = this.options.min + this.options.step,
            background = this.element.css( "border-color" ),
            left;

        while ( cnt < maxValue ) {

            left = ( cnt / maxValue * 100 ).toFixed( 2 ) + "%";

            $( "<div/>" ).addClass( "ui-slider-tick" )
                         .appendTo( this.element )
                         .css( { left: left,
                                 background: background } );

            cnt += this.options.step;

        }

    }

});

})( jQuery );

$(function() {

    $( "#slider" ).slider({
        min: 0,
        max: 200,
        step: 20,
        ticks: true
    });

});
```

查看此滑块小部件，我们可以看到我们指定的`步长`值`20`在滑块下方使用刻度标记来表示。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_08_07.jpg)

## 工作原理...

让我们检查我们已经引入到滑块小部件中的附加功能。我们添加了`ticks`布尔选项，默认情况下关闭。当这个选项为真时，告诉小部件使用刻度标记显示步进增量。在`_create()`方法中，我们使用`_super()`调用了原始的`_create()`实现，因为我们希望滑块按照正常方式构造。然后，我们检查`ticks`选项是否已打开，以及`step`值是否大于`5`。如果已打开`ticks`选项并且我们有一个小于`5`的`step`值，它们将看起来彼此靠近；所以我们简单地不显示它们。

计数器变量`cnt`控制着我们的刻度渲染循环，并初始化为`min`选项上方的第一个`step`。同样，循环在`max`选项值之前退出。这是因为我们不想在滑块的开头或结尾渲染刻度标记，而只想在中间部分显示。变量`background`用于从滑块小部件中提取`border-color` CSS 属性。我们实际上在这里所做的是将主题设置传递给我们要添加到小部件中的新元素。这允许主题被交换，刻度标记的颜色也会相应更改。

在`while`循环内，我们正在创建代表刻度标记的`div`元素。`left` CSS 属性被计算为实际定位`div`，使其与用户移动手柄时的滑块手柄对齐。我们将`ui-slider-tick` CSS 类添加到`div`元素中，配置每个刻度标记的公共属性，包括`z-index`，将`div`的一部分推到主滑块栏的后面。

# 获取范围数值

滑块小部件可用于控制范围值。因此，用户不是在滑块轴上来回移动一个固定点，即手柄，而是在两个手柄之间来回移动。这两个点之间的空间表示范围值。但是我们如何计算这个数字呢？滑块小部件给我们提供了原始数据，即用户选择的上限和下限。我们可以在我们的事件处理程序中使用这些值来计算范围值。

## 准备工作...

我们将仅使用基本的滑块进行演示，但我们需要一些支持的 CSS 和 HTML 来包围滑块，以便在更改时显示范围值。以下是 CSS：

```js
.slider-container { 
    width: 180px;
    margin: 20px;
}

.slider-container .slider-label {
    margin-bottom: 10px;
    font-size: 1.2em;
}
```

这是 HTML 代码：

```js
<div class="slider-container">
    <div class="slider-label">
        <span>Range Value: </span>
        <strong id="range-value"></strong>
    </div>
    <div id="slider"></div>
</div>
```

## 操作方法...

我们将使用以下 JavaScript 代码创建`slider`实例。请注意，我们传递了支持范围选择的特定选项。

```js
$(function() {

    $( "#slider" ).slider({
        min: 0,
        max: 600,
        values: [280, 475],
        range: true,
        create: function( e, ui ) {
            var values = $( this ).data( "uiSlider" ).values();
            $( "#range-value" ).text( values[1] - values[0] );
        },
        change: function( e, ui ) {
            $( "#range-value" ).text( ui.values[1] - ui.values[0] );
        }
    });

});
```

现在，当您在浏览器中查看此滑块时，您会注意到范围值显示为小部件外的标签。而且，如果您移动滑块手柄中的任何一个，标签将反映更改的范围值。

![操作方法...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_08_08.jpg)

## 工作原理...

在这个例子中，我们正在创建一个简单的滑块小部件，它使用一系列值而不是单个值。我们通过将值数组传递给小部件构造函数，并将`range`值传递给构造函数，以此来实现。这就是小部件知道要使用两个手柄而不是一个，并填充它们之间的空间的方式。我们还将滑块构造函数与两个事件回调函数一起传递：一个用于`create`事件，另一个用于`change`事件。

这两个回调函数执行相同的操作：它们计算范围值并将其显示在我们的`#range-value`标签中。然而，这两个回调函数以稍微不同的方式实现相同的逻辑。`create`回调函数不包含`ui`对象的`values`数组，该数组用于保存小部件数据。因此，在这里我们的解决方法是使用`uiSlider`数据，该数据保存了 JavaScript 滑块小部件实例，以便访问`values()`方法。这将返回传递给 change 事件回调函数的`ui`对象中找到的相同数据。

我们在这里计算的数字只是第一个手柄的值减去第二个手柄的值。例如，如果我们在表单中使用这样的滑块，API 可能不关心由两个滑块手柄表示的两个值，而只关心由这两个数字导出的范围值。

# 更改滑块方向

默认情况下，滑块小部件将水平呈现。我们可以通过`orientation`选项轻松将滑块方向更改为垂直布局。

## 操作步骤...

我们将使用以下 HTML 来定义我们的两个小部件。第一个滑块将是垂直的，而第二个则使用默认的水平布局：

```js
<div class="slider-container">
    <div id="vslider"></div>
</div>

<div class="slider-container">
    <div id="hslider"></div>
</div>
```

接下来，我们将使用以下 JavaScript 代码实例化这两个小部件：

```js
$(function() {

    $( "#vslider" ).slider({
        orientation: "vertical",
        range: "min",
        min: 1,
        max: 200,
        value: 128
    });

    $( "#hslider" ).slider({
        range: "min",
        min: 0,
        max: 200,
        value: 128
    });

});
```

如果您在浏览器中查看这两个滑块，您可以看到垂直布局和默认水平布局之间的对比：

![操作步骤...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_08_09.jpg)

## 工作原理...

我们在这里创建的两个滑块小部件，`#vslider`和`#hslider`，在内容上是相同的。唯一的区别是`#vslider`实例是使用`orientation`选项设置为`vertical`创建的。`#hslider`实例没有指定`orientation`选项，因此使用默认的`horizontal`。它们之间的关键区别在于布局，正如我们的示例中明显的那样。布局本身由`ui-slider-vertical`和`ui-slider-horizontal`CSS 类控制，这两个类是互斥的。

控制滑块的方向是有价值的，这取决于你想把小部件放在 UI 上下文中的位置。例如，包含元素可能没有太多的水平空间，所以在这里使用垂直方向选项可能是个不错的选择。然而，要小心动态改变滑块的方向。手柄有时会从滑块条中脱离。因此，在设计时最好确定方向。


# 第九章：使用旋转器

在本章中，我们将涵盖：

+   移除输入焦点轮廓

+   为本地文化格式化货币

+   为本地文化格式化时间

+   控制值之间的步骤

+   指定旋转溢出

+   简化旋转器按钮

# 介绍

在本章中，我们将使用旋转器。 **旋转器** 只不过是文本`input`元素上的装饰品。但与此同时，它还有很多其他用途。例如，旋转器在本章中将有助于将数字格式化为本地文化。我们还将探讨旋转器小部件提供的一些选项，以及如何扩展和改进这些选项。最后，我们将看一些修改旋转器小部件外观和感觉的方法。

# 移除输入焦点轮廓

大多数浏览器在用户从中获得焦点时，将自动在`input`元素周围应用输入焦点轮廓。当用户单击`input`元素或通过标签到达时，元素会获得焦点。旋转器小部件本质上是一个带有装饰的`input`元素。这包括利用 CSS 主题框架中的内在 jQuery 状态类的能力。虽然浏览器的自动聚焦行为对于单独的`input`元素可能效果很好，但是这些焦点环可能会使旋转器看起来有点凌乱。让我们看看如何删除自动焦点轮廓，同时保持相同的可访问性水平。

## 如何做...

对于这个示例，我们将创建一个简单的`input`元素。以下是 HTML 结构的样子。

```js
<div class="spinner-container">
    <input id="spinner"/>
</div>
```

这是与我们的小部件修改一起使用的自定义 CSS，以移除焦点轮廓。

```js
.ui-spinner-input-no-outline {
    outline: 0;
}
```

最后，这是我们的 JavaScript 代码，它修改了旋转器小部件的定义，并创建了一个实例，浏览器不会自动应用任何轮廓。

```js
(function( $, undefined ) {

$.widget( "ab.spinner", $.ui.spinner, {

    options: {        
inputOutline: true    
},

    _create: function() {

        this._super();

        if ( this.options.inputOutline ) {            
return;        
}

        this.element.addClass( "ui-spinner-input-no-outline" );
        this._focusable( this.uiSpinner );

    }
});

})( jQuery );

$(function() {

    $( "#spinner" ).spinner( { inputOutline: false } );

});
```

为了让您更好地了解我们引入的更改，这就是我们在对旋转器定义进行修改之前创建的旋转器小部件的外观。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_09_01.jpg)

在这里，您可以清楚地看到`input`元素具有焦点，但是我们可以不使用双重边框，因为它与我们的主题不太匹配。以下是在引入我们的更改后处于焦点状态的相同小部件的修改版本。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_09_02.jpg)

我们不再有焦点轮廓，当小部件获得焦点时，小部件仍然会在视觉上更改其状态。只是现在，我们正在使用 CSS 主题中的状态类更改外观，而不是依赖浏览器为我们完成。

## 它是如何工作的...

处理移除轮廓的 CSS 类，`ui-spinner-input-no-outline`类，非常容易理解。我们只需将`outline`设置为`0`，这将覆盖浏览器的默认操作方式。我们自定义的旋转器小部件知道如何利用这个类。

我们已经向旋转器小部件添加了一个新的`inputOutline`选项。如果设置为`false`，此选项将向`input`元素应用我们的新 CSS 类。但是，默认情况下，`inputOutline`默认为`true`，因为我们不希望默认情况下覆盖默认浏览器功能。此外，我们也不一定想要默认情况下覆盖默认的旋转器小部件功能。相反，最安全的方式是提供一个选项，当显式设置时，改变默认设置。在我们的`_create()`方法的实现中，我们调用旋转器构造函数的原始实现。然后，如果`inputOutline`选项为`true`，我们应用`ui-spinner-input-no-outline`类。

再次，请注意，我们最后要做的事情是将`this.uiSpinner`属性应用于`_focusable()`方法。原因是，我们需要弥补失去的可访问性；浏览器不再应用轮廓，因此当小部件获得焦点时，我们需要应用`ui-state-focus`类。`_focusable()`方法是在基本小部件类中定义的一个简单辅助方法，因此对所有小部件都可用，使传递的元素处理焦点事件。这比自己处理事件设置和撤消要简单得多。

# 格式化本地文化的货币

可以将旋转器小部件与**Globalize** jQuery 库一起使用。 Globalize 库是 jQuery 基金会的一项努力，旨在标准化 jQuery 项目根据不同文化格式化数据的方式。文化是根据文化规范格式化字符串、日期和货币的一组规则。例如，我们的应用程序应该将德语日期和货币与法语日期和货币区分对待。这就是我们能够向旋转器小部件传递`culture`值的方式。让我们看看如何使用 Globalize 库与旋转器小部件将货币格式化为本地文化。

## 操作步骤...

当我们的应用程序在多个区域设置中运行时，第一件需要做的事情就是包含`globalize`库。每种文化都包含在自己的 JavaScript 文件中。

```js
<script src="img/globalize.js"
  type="text/javascript"></script>
<script src="img/globalize.culture.de-DE.js"
  type="text/javascript"></script>
<script src="img/globalize.culture.fr-CA.js"
  type="text/javascript"></script>
<script src="img/globalize.culture.ja-JP.js"
  type="text/javascript"></script>
```

接下来，我们将定义用于显示文化选择器的 HTML，由单选按钮组成，并且用于显示货币的旋转器小部件。

```js
<div class="culture-container"></div>
<div class="spinner-container">
    <input id="spinner"/>
</div>
```

最后，我们有用于填充`culture`选择器、实例化旋转器小部件并将更改事件绑定到文化选择器的 JavaScript 代码。

```js
$(function() {

    var defaultCulture = Globalize.cultures.default;

    $.each( Globalize.cultures, function( i, v ) {

      if ( i === "default" ) {
        return;
      }

       var culture = $( "<div/>" ).appendTo( ".culture-container" );

       $( "<input/>" ).attr( "type", "radio" )
          .attr( "name", "cultures" )
          .attr( "id", v.name )
          .attr( "checked", defaultCulture.name === v.name )
          .appendTo( culture );

       $( "<label/>" ).attr( "for", v.name )
           .text( v.englishName )
           .appendTo( culture );

    });

    $( "#spinner" ).spinner({
        numberFormat: "C",
        step: 5,
        min: 0,
        max: 100,
        culture: $( "input:radio[name='cultures']:checked" )
          .attr( "id" )
    });

    $( "input:radio[name='cultures']" ).on
      ( "change", function( e ) {
        $( "#spinner" ).spinner( "option", "culture",
          $( this ).attr( "id" ) );
    });

});
```

当您首次在浏览器中查看此用户界面时，您会注意到**英语**是选定的文化，并且旋转器将相应地格式化货币。

![操作步骤...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_09_03.jpg)

但是，文化的更改会导致旋转器小部件中的货币格式发生变化，如前所述。

![操作步骤...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_09_04.jpg)

## 工作原理...

在 JavaScript 代码中，一旦 DOM 准备就绪，我们首先使用 `Globalize.cultures` 对象填充 `culture` 选择器。 Globalize 库根据可用的文化构建此对象；你会注意到可用文化选项与页面中包含的文化脚本之间存在直接关联。 我们将文化的名称存储为 `id` 属性，因为这是我们稍后传递给微调器小部件的内容。 `Globalize.cultures` 对象还具有默认文化，我们使用此值来确定页面首次加载时选择了哪个选项。

我们创建的微调器实例使用了一个 `numberFormat` 选项值为 `C`。 这个字符串实际上在渲染微调器值时直接传递给 `Globalize.format()` 函数。 接下来的三个选项，`step`、`min` 和 `max`，与任何数字微调器实例一样。 我们将 `culture` 选项设置为所选的默认文化，告诉微调器小部件如何格式化货币。 最后，我们设置了一个事件处理程序，每当文化选择更改时触发。 此处理程序将更新微调器小部件以使用新选择的文化。

# 为本地文化格式化时间

微调器小部件利用了 Globalize jQuery 项目；这是一项根据本地文化标准化数据格式的工作。 微调器小部件利用此库来格式化其值。 例如，指定 `numberFormat` 和 `culture` 选项允许我们使用微调器小部件根据本地文化显示货币值。 然而，货币只是我们喜欢本地格式化的一个值； 时间是另一个值。 我们可以在微调器小部件中使用内置的 Globalize 功能来显示时间值。 我们需要在我们自己的部分上做更多工作来扩展小部件以正确地允许时间值。 实际上，让我们基于微调器创建我们自己的时间小部件。

## 如何实现...

首先，让我们看一下创建两个时间小部件所需的标记，我们将在其中显示多伦多时间和伦敦时间。 我们在这里不展示时区计算能力，只是在同一个 UI 中展示两种不同的文化。

```js
<div class="spinner-container">
    <h3>Toronto</h3>
    <input id="time-ca" value="2:30 PM"/>
</div>

<div class="spinner-container">
    <h3>London</h3>
    <input id="time-gb" value="7:30 PM"/>
</div>
```

接下来，让我们看一下用于定义新时间小部件并创建两个实例的 JavaScript 代码。

```js
( function( $, undefined ) {

$.widget( "ab.time", $.ui.spinner, {

    options: {
        step: 60 * 1000,
        numberFormat: "t"
    },

    _parse: function( value ) {

        var parsed = value;

        if ( typeof value === "string" && value !== "" ) {

            var format = this.options.numberFormat,
                culture = this.options.culture;

            parsed = +Globalize.parseDate( value, format );

            if ( parsed === 0 ) {
                parsed = +Globalize.parseDate( value,
                  format, culture );
            }

        }

        return parsed === "" || isNaN( parsed ) ? null : 
          parsed;

    },

    _format: function( value ) {
        return this._super( new Date( value ) );
    }

});

})( jQuery );

$(function() {

    $( "#time-ca" ).time({
        culture: "en-CA"
    });

    $( "#time-gb" ).time({
        culture: "en-GB"
    });

});
```

在浏览器中查看两个时间小部件，我们可以看到它们已按其各自的本地文化格式化。

![如何实现...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_09_05.jpg)

## 工作原理...

让我们首先看一下用于定义时间小部件实例的两个输入元素。 注意 `value` 属性，它们都具有默认时间，使用相同的格式表示。 现在，让我们跳转到新时间小部件的定义。

你在这里首先注意到的是，我们使用小部件工厂在 `ab` 命名空间下定义了时间小部件。您还会注意到，我们正在扩展微调器小部件。这是因为实质上我们正在构建的是一个微调器，在这里有一些小但重要的区别。这实际上是一个很好的例子，说明了当设计从标准小部件集派生的 jQuery UI 小部件自定义时，您必须考虑的一些事情。在这种情况下，您应该保留原始小部件名称，即微调器，还是应该叫它其他名称，比如时间？可以帮助您指导这个决定的唯一事情是思考此小部件的使用方式。例如，我们本可以保持微调器小部件不变以显示这些受文化影响的时间值，但这意味着引入新的选项，并可能让使用该小部件的开发人员感到困惑。我们已经决定这里的用例很简单，我们应该尽可能少地允许时间以尽可能少的选项显示。

我们在此定义的选项并不是新的；`step` 和 `numberFormat` 选项已经由微调器小部件定义，我们只是将它们设置为适合我们时间小部件的默认值。`step` 值将针对一个 `timestamp` 值递增，因此我们给它一个默认值，以秒为步长。`numberFormat` 选项指定微调器在解析和格式化输出时所期望的格式。

我们对微调器的扩展，`_parse()` 方法，是我们直接使用 Globalize 库解析时间字符串的地方。请记住，我们的输入具有相同的字符串格式。如果我们尝试解析一个格式不可识别的值，这就成为了一个问题。因此，我们尝试在不指定值所属文化的情况下解析时间值。如果这样不起作用，我们就使用附加到此小部件的文化。通过这种方式，我们可以使用一个格式指定初始值，就像我们在这里做的一样，并且我们可以动态更改文化；一切仍将正常工作。我们的`_format()`方法的版本很简单，因为我们知道值始终是一个时间戳数字，我们只需将一个新的 `Date` 对象传递回原始的微调器`_format()`方法即可。

最后，我们有两个时间小部件实例，其中一个传递了 `en-CA` 的文化，另一个传递了 `en-GB`。

# 控制值之间的步长

有几种方法可以控制微调器小部件中的步骤。步骤是微调器小部件用来向上或向下移动其数字的值。例如，您经常会看到循环代码，它会增加一个计数器 `cnt ++`。在这里，步骤是一，这是微调器步骤值的默认值。更改微调器中的此选项很简单；我们甚至可以在创建小部件后更改此值。

我们可以采取其他措施来控制旋转器的步进行为。让我们看看增量选项，并看看这如何影响旋转器。

## 如何做...

我们将创建三个旋转器部件来演示增量选项的潜力。以下是 HTML 结构：

```js
<div class="spinner-container">
    <h3>Non-incremental</h3>
    <input id="spin1" />
</div>

<div class="spinner-container">
    <h3>Doubled</h3>
    <input id="spin2" />
</div>

<div class="spinner-container">
    <h3>Faster and Faster</h3>
    <input id="spin3" />
</div>
```

下面是用于创建三个旋转器实例的 JavaScript 代码：

```js
$(function() {

    $( "#spin1" ).spinner({
        step: 5,
        incremental: false
    });

    $( "#spin2" ).spinner({
        step: 10,
        incremental: function( spins ) {
            if ( spins >= 10 ) {
                return 2;
            }
            return 1;
        }
    });

    $( "#spin3" ).spinner({
        step: 15,
        incremental: function( spins ) {
            var multiplier = Math.floor( spins / 100 ),
                limit = Math.pow( 10, 10 );
            if ( multiplier < limit && multiplier > 0 ) {
                return multiplier;
            }
            return 1;
        }
    });

});
```

在您的浏览器中，这三个旋转器部件应该看起来是这样的。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_09_06.jpg)

## 工作原理...

我们创建了三个不同的旋转器实例，它们在用户按住其中一个旋转按钮时的行为不同。`#spin1`旋转器的步长值为`5`，并且将始终将旋转器值递增`5`。您可以通过按住旋转按钮来尝试这一点。您会注意到这将花费您很长时间才能达到一个较大的整数值。

`incremental`选项接受一个布尔值，就像我们在第一个旋转器中看到的那样，但它还接受一个`callback`函数。`#spin2`旋转器的步长值为`10`，但它将根据我们传递给增量选项的函数而改变。我们定义的这个`incremental callback`函数通过用户按住旋转按钮的旋转次数传递。我们从这里正常开始，前`10`次旋转，然后我们从那时起加速返回`2`而不是`1`。当我们返回`2`时，我们的步长值变为`20`，因为该函数的返回值是一个乘数。但它只在用户按住旋转按钮时使用；此函数不会永久改变`step`选项。

我们的最后一个旋转器实例，`#spin3`，也使用了一个`incremental callback`函数。然而，这个函数会随着用户持续旋转而使用一个逐渐变大的值。每旋转一百次，我们就增加乘数，也增加步长。后者的递增函数在旋转器值本身变大时非常有用，我们可以控制步长变化的速度。

## 更多内容...

我们刚刚看到了如何控制旋转器部件的值步进。`step`选项决定了在给定旋转时值在任一方向上移动的距离。当用户按住旋转按钮时，我们可以使用`incremental`选项来计算步长值。这有助于加快或减慢旋转到给定目标值所需的时间。

另一种方法是改变旋转之间的实际时延。如果您想要在用户按住旋转按钮时减慢旋转速度，这可能会很方便。让我们看一个如何改变旋转延迟的例子。以下是 HTML 结构：

```js
<div class="spinner-container">
    <h3>Default delay</h3>
    <input id="spin1" />
</div>

<div class="spinner-container">
    <h3>Long delay</h3>
    <input id="spin2" />
</div>

<div class="spinner-container">
    <h3>Longer delay</h3>
    <input id="spin3" />
</div>
```

这是自定义旋转器部件定义，以及使用不同旋转值的三个实例。

```js
( function( $, undefined ) {

$.widget( "ab.spinner", $.ui.spinner, {

    options: {
        spinDelay: 40
    },

    _repeat: function( i, steps, event ) {

        var spinDelay = this.options.spinDelay;

        i = i || 500;

        clearTimeout( this.timer );
        this.timer = this._delay(function() {
            this._repeat( spinDelay, steps, event );
        }, i );

        this._spin( steps * this.options.step, event );

     }

});

})( jQuery );

$(function() {

    $( "#spin1" ).spinner();

    $( "#spin2" ).spinner({
        spinDelay: 80
    });

    $( "#spin3" ).spinner({
        spinDelay: 120
    });

});
```

您可以在浏览器中尝试这些旋转器中的每一个，并观察旋转延迟的对比。

![更多内容...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_09_07.jpg)

我们已将`spinDelay`选项添加到微调器小部件中，以便可以指定延迟的毫秒数。为了实际使用此选项，我们必须对其中一个核心微调器小部件方法进行一些更改。当用户按住微调器按钮时，内部使用`_repeat()`方法。它实际上使用很少的代码执行了大量工作。基本上，目标是重复给定的事件，直到用户松开按钮并且旋转应该停止。但是，我们不能仅仅重复调用`_spin()`，而不添加任何延迟，否则用户每次更新文本输入时都会看到模糊的内容。因此，微调器正好利用`_delay()`方法来实现此目的。`_delay()`方法为过去的函数设置延迟执行，并在`基本小部件`类中定义；所有小部件都可以访问`_delay()`。

我们的`_repeat()`方法版本与原始版本几乎相同，除了我们现在不再硬编码旋转之间的延迟；我们现在从`spinDelay`选项中获取它。

# 指定旋转溢出

微调器小部件将愉快地让用户无限地旋转。当达到 JavaScript 整数限制时，它甚至会将显示更改为使用指数表示法，这没问题。几乎没有应用程序需要担心这些限制。事实上，最好为应用程序制定一些有意义的限制。也就是说，指定`min`边界和`max`边界。

这很有效，但是如果我们在处理溢出的微调器中插入一些逻辑，它甚至可以工作得更好，当用户想要超出边界时。与默认行为停止旋转不同，我们只是将它们发送到相反的边界，但是以相同的方向开始旋转。最好的方法是将这些约束想象成默认情况下，微调器的最小 - 最大边界就像一条直线。我们想让它看起来更像一个圆。

## 如何做...

我们将有两个微调器小部件，第一个使用默认边界约束逻辑，第二个使用我们自己定义的行为。以下是用于创建这两个小部件的 HTML 结构：

```js
<div class="spinner-container">
    <h3>Default</h3>
    <input id="spin1" />
</div>

<div class="spinner-container">
    <h3>Overflow</h3>
    <input id="spin2" />
</div>
```

这里是文档加载后用于实例化两个微调器的 JavaScript 代码：

```js
$(function() {

    $( "#spin1" ).spinner({
        min: 1,
        max: 100
    });

    $( "#spin2" ).spinner({
        minOverflow: 1,
        maxOverflow: 100,
        spin: function( e, ui ) {

            var value = ui.value,
              minOverflow = $( this ).spinner
                ( "option", "minOverflow" ),
                  maxOverflow = $( this ).spinner
                    ( "option", "maxOverflow" );

            if ( value > maxOverflow ) {
                $( this ).spinner( "value", minOverflow );
                return false;
            }
            else if ( value < minOverflow ) {
                $( this ).spinner( "value", maxOverflow );
                return false;
            }

        }
    });

});
```

以下是浏览器中的两个微调器。您将看到，后一个微调器处理边界溢出的方式与默认实现不同。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_09_08.jpg)

## 工作原理...

当`#spin1`微调器达到边界之一，即`1`或`100`时，旋转将停止。另一方面，`#spin2`微调器将从另一端开始旋转。您会注意到我们在这里传递了两个非标准的微调器选项；`minOverflow`和`maxOverflow`。这些实际上不会像`min`和`max`一样约束微调器的边界。我们之所以故意添加这些新选项，是因为我们不希望常规约束逻辑触发。

我们为这个小部件提供的`spin`回调函数在每次旋转时都会被调用。如果我们使用传统的旋转`min`和`max`选项，我们就永远不会知道是否出现了溢出，因为`min`会小于`1`，而`max`永远不会大于`100`。因此，我们使用新的选项根据方向重定向值。如果值超过了`100`，那么我们将值设置回`minOverflow`。或者如果值低于`1`，那么我们将值设置为`maxOverflow`。

## 还有更多...

你可能会决定，当我们将用户带到旋转器边界的另一侧时，溢出行为并不完全符合你的期望。你可能只想在达到边界时停止旋转。然而，我们仍然可以通过禁用旋转按钮来改进小部件。这只是对旋转器溢出的另一种方法，我们只是为用户提供更好的反馈，而不是像之前那样改变业务逻辑。让我们看看如何做出这个改变。以下是用于简单旋转器小部件的 HTML 结构：

```js
<div class="spinner-container">
    <input id="spin" value=10 />
</div>
```

这是我们在页面加载时用到的 JavaScript，用于创建小部件。

```js
$(function() {

    $( "#spin" ).spinner({
        min: 1,
        max: 100,
        spin: function( e, ui ) {
            var value = ui.value,
                buttons = $( this ).data( "uiSpinner" ).buttons,
                min = $( this ).spinner( "option", "min" ),
                max = $( this ).spinner( "option", "max" );

            if ( value === max ) {
                buttons.filter( ".ui-spinner-up:not
                  (.ui-state-disabled)" )
                       .button( "disable" );
            }
            else if ( value === min ) {
                buttons.filter( ".ui-spinner-down:not
                  (.ui-state-disabled)" )
                       .button( "disable" );
            }
            else {
                buttons.filter( ".ui-state-disabled" )
                .button( "enable" );
            }
        }
    });

});
```

当你在浏览器中开始与这个小部件交互时，你会注意到当你达到`min`选项值时，即`1`，下旋转按钮会被禁用。

![还有更多...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_09_09.jpg)

同样，当你达到了`max`，这里是`100`，上旋转按钮会被禁用。

![还有更多...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_09_10.jpg)

通过向构造函数传递一个`spin`回调函数，我们引入了这种新的旋转器行为，该函数在每次旋转时执行。在这个回调中，我们将两个旋转按钮的引用都保存在`buttons`变量中。然后我们检查是否达到了`max`值，或者达到了`min`值。然后我们禁用适当的按钮。如果我们处于`min`和`max`之间，那么我们就简单地启用这些按钮。你还会注意到我们在这里有一些额外的过滤；`not(.ui-state-disabled)` 和 `.ui-state-disabled`。这是必要的，因为旋转器小部件触发旋转事件的方式。禁用按钮可能会触发旋转，导致无限循环。因此，我们必须小心地只禁用那些尚未被禁用的按钮。

# 简化旋转器按钮

spinner 小部件中实现的默认旋转按钮可能有点过多，具体取决于上下文。例如，您可以清楚地看到这些是作为子组件添加到滑块中的按钮小部件。当我们开始使用较小的小部件构建较大的小部件时，这完全有效。这更多地是一种审美偏好。也许如果单独的向上和向下旋转按钮没有悬停状态，也没有背景或边框，那么 spinner 会看起来更好。让我们尝试从滑块按钮中去除这些样式属性，并使它们看起来更紧密集成。

## 如何做...

这是作为我们 `spinner` 小部件基础的基本 HTML 结构：

```js
<div class="spinner-container">
    <input id="spin" />
</div>
```

这是我们将使用的 CSS，用于移除我们不再感兴趣的按钮样式：

```js
.ui-spinner-basic > a.ui-button {
    border: none;
    background: none;
    cursor: pointer;
}
```

`input` 元素尚未成为一个小部件，而我们创建的新 CSS 类也尚未成为 spinner 小部件的一部分。以下是完成这两件事情的 JavaScript 代码的样子：

```js
 (function( $, undefined ) {

$.widget( "ab.spinner", $.ui.spinner, {

    options: {
        basic: false
    },

    _create: function() {

        this._super();

        if ( this.options.basic ) {
            this.uiSpinner.addClass( "ui-spinner-basic" );
        }

    }

});

})( jQuery );

$(function() {

    $( "#spin" ).spinner({
        basic: true
    });

});
```

如果您在浏览器中查看我们创建的 spinner，您会注意到 spinner 按钮的边框和背景已经被去除。现在它看起来更像一个整体小部件。您还会注意到，当用户将鼠标悬停在任一按钮上时，鼠标指针使用指针图标，这有助于表明它们是可点击的。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_09_11.jpg)

## 工作原理...

我们刚刚创建的新 CSS 类 `ui-spinner-basic` 通过在 spinner 上下文中覆盖按钮小部件样式来工作。具体来说，我们从按钮小部件中移除了 `border` 和 `background`。此外，我们将 `cursor` 属性设置为 `pointer`，以便给用户一种箭头是可点击的印象。我们还稍微定制了 spinner 小部件本身的定义。我们通过添加一个新的 `basic` 选项来实现这一点，当 `true` 时，将新的 `ui-spinner-basic` 类应用于小部件。当小部件被销毁时，我们不需要显式地移除此类，因为它被添加到 spinner 小部件创建的一个元素中。此元素会被基本 spinner 实现自动移除，因此我们的代码不必担心它。


# 第十章：使用标签

在本章中，我们将涵盖：

+   处理远程标签内容

+   为标签添加图标

+   简化标签主题

+   将标签用作 URL 导航链接

+   在标签转换之间创建效果

+   使用可排序交互来排序标签

+   使用 href 设置活动标签

# 介绍

**标签** 小部件是用于组织页面内容的容器。它是整理页面内容的绝佳方式，因此只显示相关项目。用户具有简单的导航机制来激活内容。标签小部件可以应用于较大的导航上下文中，其中标签小部件是页面的主要顶级容器元素。它还可以作为特定页面元素的较小组件使用，用于简单地拆分两个内容部分。

最新的 jQuery UI 版本中的标签小部件为开发人员提供了一套一致的选项，以调整小部件的行为。我们将看看如何组合这些选项，以及如何充分利用标签小部件的导航功能。我们还将探讨如何对标签转换应用效果，并使标签对用户可排序。

# 处理远程标签内容

标签小部件知道如何将给定的标签面板填充为远程内容。关键在于我们如何指定标签链接。例如，指向 `#tab-content-home` 的 `href` 属性将使用该元素中找到的 HTML 加载内容。但是，如果我们指向另一个页面而不是指向已存在的元素，则标签小部件将按需将内容加载到适当的面板中。

在不传递选项给标签的情况下，这样可以按预期运行，但是如果我们想要以任何方式调整 Ajax 请求的行为，可以使用 `beforeLoad` 选项。让我们来看看我们可以如何使用标签小部件处理远程内容的一些方法。

## 如何操作...

首先，我们将创建标签小部件的 HTML，其中包括四个链接。前三个链接指向现有资源，而第四个链接不存在，因此 Ajax 请求将失败。

```js
<div id="tabs">
    <ul>
        <li><a href="ajax/tab1.html">Tab 1</a></li>
        <li><a href="ajax/tab2.html">Tab 2</a></li>
        <li><a href="ajax/tab3.html">Tab 3</a></li>
        <li><a href="doesnotexist.html">Tab 4</a></li>
    </ul>
</div>
```

接下来，我们有用于创建标签小部件实例的 JavaScript，以及指定一些自定义行为以修改 Ajax 请求。

```js
$(function() {

    function tabLoad( e, ui ) {

        if ( ui.panel.html() !== "" ) {

            ui.jqXHR.abort();

        }
        else {

            ui.jqXHR.error(function( data ) {

                $( "<p/>" ).addClass( "ui-corner-all ui-state-error" )
                           .css( "padding", "4px" )
                           .text( data.statusText )
                           .appendTo( ui.panel );
            });

        }

    }

    $( "#tabs" ).tabs({
        beforeLoad: tabLoad
    });

});
```

为了查看此演示中实现的 Ajax 行为，您需要将 web 服务器放在前面。最简单的方法是安装 Python 并从包含主 HTML 文件的目录以及 Ajax 内容文件 `tab1.html`、`tab2.html` 和 `tab3.html` 运行 `python -m SimpleHTTPServer`。以下是 `tab1.html` 文件的示例：

```js
<!doctype html>
<html lang="en">
    <body>
        <h1>Tab 1</h1>
        <p>Tab 1 content</p>
    </body>
</html>
```

当您在浏览器中加载此标签小部件时，默认情况下选择第一个标签。因此，小部件将立即执行加载第一个标签内容的 Ajax 请求。您应该看到类似于以下内容：

![如何操作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_10_01.jpg)

切换到第二个和第三个选项卡将执行必要的 Ajax 请求以获取内容。另一方面，第四个选项卡将导致错误，因为链接的资源不存在。在该面板中不会显示内容，而是显示了我们为 Ajax 请求添加的自定义行为显示的错误消息。

![如何实现...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_10_02.jpg)

关于这个示例的最后一点要注意的是我们对 Ajax 请求的另一个修改。如果你重新访问第一个选项卡，我们不会发送另一个 Ajax 请求，因为我们已经有了面板内容。

## 工作原理...

当文档加载完成时，我们将从 `#tabs` div 创建一个选项卡部件。我们传递 `beforeLoad` 一个回调函数 `tabLoad()`，之前定义的。`tabLoad` 函数在分派用于获取选项卡面板内容的 Ajax 请求之前被调用。这给了我们一个机会来更新 `jqXHR` 对象的状态。

### 提示

`$.ajax()` 返回的 `jqXHR` 对象是 JavaScript 中原生 `XMLHTTPRequest` 类型的扩展。开发者很少与这个对象交互，但偶尔也会有需要，正如我们在这里看到的。

在这个示例中，我们首先检查选项卡面板是否有任何内容。`ui.panel` 对象代表最终将动态 Ajax 内容放置的 `div` 元素。如果是空字符串，我们继续加载内容。另一方面，如果已经有内容，我们会中止请求。如果服务器没有生成动态内容，而我们只是使用选项卡部件的此功能作为结构组合的手段，那么这是有用的。当我们已经拥有内容时，重复请求相同的内容是没有意义的。

我们还将行为附加到 `jqXHR` 对象上，以处理 Ajax 请求失败的情况。我们使用 `ui-state-error` 和 `ui-corner-all` 类对服务器返回的状态文本进行格式化，然后更新选项卡内容。

## 还有更多...

前面的例子将从远程资源检索的 HTML 放置到选项卡面板中。但现在我们决定选项卡内容中的 `h1` 标签是多余的，因为活动选项卡具有相同的作用。我们可以直接从我们用于构建选项卡内容的远程资源中删除这些标签，但如果我们在应用程序的其他地方使用该资源，可能会出现问题。相反，我们可以在用户实际看到它之前，仅仅通过加载事件修改选项卡内容。这是我们选项卡部件实例的修改版本：

```js
$(function() {

    function beforeLoad( e, ui ) {

        ui.jqXHR.error(function( data ) {

            ui.panel.empty();

            $( "<p/>" ).addClass( "ui-corner-all ui-state-error" )
                       .css( "padding", "4px" )
                       .text( data.statusText )
                       .appendTo( ui.panel );
        });

    }

    function afterLoad( e, ui ) {
        $( "h1", ui.panel ).remove();
    }

    $( "#tabs" ).tabs({
        beforeLoad: beforeLoad,
        load: afterLoad
    });

});
```

现在看，你会发现选项卡面板内不再有标题了。我们在构造函数中传递给选项卡的 `load` 回调将查找并删除任何 `h1` 标签。`load` 事件在 Ajax 调用返回并将内容插入面板后触发。我们无需担心在我们的代码运行之后出现 `h1` 标签。

![还有更多...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_10_03.jpg)

# 给选项卡添加图标

选项卡小部件使用锚元素，点击时激活各种选项卡面板以显示其内容。默认情况下，此锚元素仅显示文本，这在绝大多数情况下足够好。然而，在其他一些情况下，选项卡链接本身可能受益于图标。例如，一个房子图标有助于快速提示面板内容是什么，然后再激活它。让我们看看如何扩展选项卡的功能以支持将图标和文本作为选项卡按钮使用。

## 如何做...

我们将创建一个支持我们小部件的基本`tabs` div，如下所示：

```js
<div id="tabs">
    <ul>
        <li data-icon="ui-icon-home">
            <a href="#home">Home</a>
        </li>
        <li data-icon="ui-icon-search">
            <a href="#search">Search</a>
        </li>
        <li data-icon="ui-icon-wrench">
            <a href="#settings">Settings</a>
        </li>
    </ul>
    <div id="home">
        <p>Home panel...</p>
    </div>
    <div id="search">
        <p>Search panel...</p>
    </div>
    <div id="settings">
        <p>Settings panel...</p>
    </div>
</div>
```

接下来，我们有我们的 JavaScript 代码，包括对了解如何利用我们在标记中包含的`new data-icon`属性的选项卡小部件的扩展。

```js
(function( $, undefined ) {

$.widget( "ab.tabs", $.ui.tabs, {

    _processTabs: function() {

        this._super();

        var iconTabs = this.tablist.find( "> li[data-icon]" );

        iconTabs.each( function( i, v ) {

            var $tab = $( v ),
                iconClass = $tab.attr( "data-icon" ),
                iconClasses = "ui-icon " +
                              iconClass + 
                              " ui-tabs-icon",
                $icon = $( "<span/>" ).addClass( iconClasses ),
                $anchor = $tab.find( "> a.ui-tabs-anchor" ),
                $text = $( "<span/>" ).text( $anchor.text() );

            $anchor.empty()
                   .append( $icon )
                   .append( $text );

        });
    },

    _destroy: function() {

        var iconTabs = this.tablist.find( "> li[data-icon]" );

        iconTabs.each( function( i, v ) {

            var $anchor = $( v ).find( "> a.ui-tabs-anchor" ),
                text = $anchor.find( "> span:not(.ui-icon)" )
                              .text();

            $anchor.empty().text( text );

        });

        this._super();

    }

});

})( jQuery );

$(function() {

    $( "#tabs" ).tabs();

});
```

如果您在浏览器中查看此选项卡小部件，您会注意到每个选项卡按钮现在在按钮文本的左侧有一个图标。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_10_04.jpg)

## 运作原理...

这个选项卡小部件的自定义之处在于，我们通过代表选项卡按钮的`li`元素传递数据。由于任何给定的选项卡小部件实例可能有任意数量的选项卡，通过`options`对象来指定哪个选项卡获取哪个图标是困难的。相反，我们简单地通过使用`data-icon`数据属性传递这些选项。该值是我们想要从主题框架中使用的图标类。

我们实现的更改实际上可以在标记本身手动完成，因为我们只是向小部件添加新元素和新类。但是，这种思维方式存在两个问题。首先，有大量手动注入的标记，可以根据一个数据属性的值生成，这违反了 DRY 原则，特别是如果您为多个选项卡小部件遵循这种模式。其次，我们将引入默认小部件实现不了解的新标记。这可能效果很好，但当事情停止按预期工作时，这可能很难诊断。因此，我们最好扩展选项卡小部件。

我们正在重写的`_processTabs()`方法将迭代具有`data-icon`属性的每个`li`元素，因为这些是我们需要操作的元素。`data-icon`属性存储要从主题框架中使用的图标类。我们构造一个使用`ui-icon`类与特定图标类一起使用的`span`元素。它还得到我们新的`ui-tabs-icon`类，正确定位元素在链接内。然后，我们获取选项卡按钮的原始文本并将其包装在一个`div`中。原因是，插入图标`span`，然后是文本`span`更容易。

# 简化选项卡主题

有时，我们的选项卡小部件的上下文对主题有重要的影响。当小部件位于文档顶部附近时，选项卡小部件的默认视觉组件效果最佳，也就是说，大部分页面内容都嵌套在选项卡面板中。相反，可能存在着一些既有的页面元素，可以通过选项卡小部件进行组织。这就是挑战所在——将诸如选项卡这样的顶级小部件塞入较小的块中可能会显得尴尬，除非我们能够找到一种方法来从选项卡中剥离一些不必要的主题组件。

## 如何做...

让我们首先创建一些标记以便基于选项卡小部件。它应该看起来像下面这样：

```js
<div id="tabs-container">
    <div id="tabs">
        <ul>
            <li><a href="#tab1">Tab 1</a></li>
            <li><a href="#tab2">Tab 2</a></li>
            <li><a href="#tab3">Tab 3</a></li>
        </ul>
        <div id="tab1">
            <h3>Tab 1...</h3>
            <ul>
                <li>Item 1</li>
                <li>Item 2</li>
                <li>Item 3</li>
            </ul>
        </div>
        <div id="tab2">
            <h3>Tab 2...</h3>
            <ul>
                <li>Item 4</li>
                <li>Item 5</li>
                <li>Item 6</li>
            </ul>
        </div>
        <div id="tab3">
            <h3>Tab 3...</h3>
            <ul>
                <li>Item 7</li>
                <li>Item 8</li>
                <li>Item 9</li>
            </ul>
        </div>
    </div>
</div>
```

接下来，我们将定义一些由选项卡小部件和选项卡小部件容器使用的 CSS。

```js
div.ui-tabs-basic {
    border: none;
    background: none;
}

div.ui-tabs-basic > ul.ui-tabs-nav {
    background: none;
    border-left: none;
    border-top: none;
    border-right: none;
}

#tabs-container {
    width: 22%;
    background: #f7f7f7;
    padding: 0.9em;
}
```

接下来是我们的 JavaScript 代码，它在文档准备就绪后创建选项卡小部件。

```js
$(function() {

    $( "#tabs" ).tabs({
        create: function( e, ui ) {
            $( this ).addClass( "ui-tabs-basic" )
                     .find( "> ul.ui-tabs-nav" )
                     .removeClass( "ui-corner-all" );
        }
    });

});
```

## 它是如何工作的...

我们正在传递给选项卡构造函数的`create`函数在小部件创建后触发。这是我们添加自定义类`ui-tabs-basic`的地方，该类用于覆盖`background`和`border`设置。这些是我们希望被移除的组件，因此我们只需将它们设置为`none`。我们还从选项卡导航部分中移除了`ui-corner-all`类，因为我们保留了底部边框，保留此类看起来不合适。

通常情况下创建此小部件，也就是不传递我们的`create`函数，则选项卡小部件将如下所示：

![它的工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_10_05.jpg)

如您所见，选项卡小部件似乎是毫无考虑地塞入了`#tabs-container`元素中。在引入我们的简化之后，选项卡在其新上下文中呈现出更自然的外观。

![它的工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_10_06.jpg)

## 还有更多...

如果您在整个 UI 中的多个位置使用此精简版本的选项卡小部件，则多次定义要传递给选项卡构造函数的函数回调可能会很麻烦。您可以一次定义回调函数并在构造函数中传递其引用，但是然后您仍然需要将回调函数暴露在外。从设计的角度来看，我们可能希望将此行为封装在选项卡小部件中，并通过小部件选项将其暴露给外部世界。以下是对此示例进行的修改：

```js
(function( $, undefined ) {

$.widget( "ab.tabs", $.ui.tabs, {

    options: {
        basic: false
    },

    _create: function() {

        this._super();

        if ( !this.options.basic ) {
            return;
        }

        $( this.element ).addClass( "ui-tabs-basic" )
                         .find( "> ul.ui-tabs-nav" )
                         .removeClass( "ui-corner-all" );

    }

});

})( jQuery );

$(function() {

    $( "#tabs" ).tabs({
        basic: true
    });

});
```

在这里，我们将之前在回调中的功能移至选项卡构造函数中，但仅当`basic`选项设置为`true`时才执行，并且默认为`false`。

# 将选项卡用作 URL 导航链接

选项卡小部件不仅限于使用预加载的 div 元素或通过进行 Ajax 调用来填充选项卡面板。一些应用程序已经构建了许多组件，并且有大量内容要显示。如果您正在更新一个网站或应用程序，特别是如果您已经在使用 jQuery UI 小部件，则选项卡小部件可能作为主要的导航形式是有用的。那么我们需要的是一些通用的东西，可以应用于每个页面，而开发人员使用小部件的努力不多。尽管选项卡小部件并不是为这样的目的而设计的，但我们不会让这阻止我们，因为稍加调整，我们就可以创建一个能够给我们带来所需功能的通用组件。

## 如何做...

我们将首先查看应用程序中一个页面上的内容。HTML 定义了选项卡小部件结构以及活动选项卡下显示的内容。

```js
<div id="nav">
    <ul>
        <li>
            <a href="tab1.html">Tab 1</a>
        </li>
        <li>
            <a href="tab2.html">Tab 2</a>
        </li>
        <li>
            <a href="tab3.html">Tab 3</a>
        </li>
    </ul>
    <div>
        <p>Tab 1 content...</p>
    </div>
</div>
```

您会注意到此应用程序中有三个页面，并且它们都使用相同的小部件 HTML 结构；唯一的区别是选项卡内容段落。接下来，我们将定义我们的新导航小部件并在页面上创建它。相同的 JavaScript 代码包含在应用程序的每个页面中。

```js
(function( $, undefined ) {

$.widget( "ab.nav", $.ui.tabs, {

    _initialActive: function() {

        var path = location.pathname,
            path = path.substring( path.search( /[^\/]+$/ ) ),
            tabs = this.tabs,
            $active = tabs.find( "> a[href$='" + path + "']" );

        return tabs.find( "a" )
                   .index( $active );

    },

    _eventHandler: function( event ) {

        window.open( $( event.target ).attr( "href" ), "_self" );

    },

    _createPanel: function( id ) {

        var panel = this.element.find( "> div:first" );

        if ( !panel.hasClass( "ui-tabs-panel" ) ) {
            panel.data( "ui-tabs-destroy", true )
                 .addClass( "ui-tabs-panel " +
                            "ui-widget-content " +
                            "ui-corner-bottom" );

        }

        return panel;

    },

    _getPanelForTab: function( tab ) {

        return this.element.find( "> div:first" );

    },

    load: $.noop

});

})( jQuery );

$(function() {

    $( "#nav" ).nav();

});
```

现在，当您与此导航小部件交互时，您会看到每次激活一个新的选项卡时，浏览器都会重新加载页面以指向选项卡的`href`；例如，`tab3.html`。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_10_07.jpg)

## 它是如何工作的...

让我们先看看我们创建的新`nav`小部件之前的 HTML 结构。首先要注意的是，我们在这里提供的 HTML 结构与选项卡小部件所期望的不同。我们有一个不带 ID 的`div`元素，用于保存页面的主要内容，因此没有任何选项卡链接可以引用它。但不用担心，这是有意为之的。`nav`小部件是为具有多个页面的站点或应用程序设计的——我们不会在此小部件中嵌入多个选项卡面板内容。由于我们对小部件使用的 HTML 进行了这种结构性变更，最好的做法是创建一个全新的小部件，而不仅仅是扩展选项卡小部件。这种方法将避免对选项卡小部件的 HTML 结构应该是什么样子产生混淆。

我们的`nav`小部件的目标，基于选项卡小部件，是激活适当的选项卡并将`div`元素呈现为所选的选项卡面板。当单击选项卡链接时，我们不执行任何常规的选项卡活动，只是跟随`href`。

在 `nav` 小部件的定义中覆盖的所有方法都来自标签小部件，而且在大多数情况下，我们都替换了不需要的标签功能。第一个方法是 `_initialActive()`，它确定小部件首次创建时的活动选项卡。在这里，我们将此决定基于位置对象中的路径。我们将其与选项卡的 `href` 属性进行比较。接下来是 `_eventHandler()` 方法。当用户激活选项卡时，将调用此方法。在这里，我们只执行与默认浏览器链接相同的操作，并遵循选项卡链接的 `href` 属性。由于我们在 `_eventHandler()` 方法中执行此操作，因此用于切换选项卡的 `keypress` 事件仍将按预期工作。接下来，当标签小部件需要创建和插入选项卡面板时，将调用 `_createPanel()` 方法。标签小部件调用此方法的原因是在进行 Ajax 调用时需要面板。由于我们在 `nav` 小部件中不进行任何 Ajax 调用，因此此方法现在将使用具有页面内容的默认 `div`。我们对内容 `div` 做的唯一更改是添加了适当的选项卡面板 CSS 类。最后，我们有 `_getPanelForTab()` 方法，该方法返回我们的内容 `div`，对于此小部件，这是唯一重要的内容 `div`，并且 `load()` 方法是 `$.noop`。这样做可以防止小部件在首次创建时尝试加载 Ajax 内容。

# 在选项卡之间创建效果

标签小部件允许开发人员指定在选项卡之间进行转换时运行的效果。具体来说，我们能够告诉标签小部件在显示选项卡时运行特定效果，并在隐藏选项卡时运行另一个效果。当用户点击选项卡时，如果指定了这两个效果，则会运行它们。首先是隐藏效果，然后是显示效果。让我们看看如何结合这两个选项卡选项来增强小部件的互动性。

## 如何做到这一点...

首先，我们将创建我们构建选项卡小部件所需的 HTML 结构。它应该看起来类似于以下内容，生成三个选项卡：

```js
<div id="tabs">
    <ul>
        <li><a href="#tab1">Tab 1</a></li>
        <li><a href="#tab2">Tab 2</a></li>
        <li><a href="#tab3">Tab 3</a></li>
    </ul>
    <div id="tab1">
        <p>Tab 1 content...</p>
        <button>Tab 1 Button</button>
    </div>
    <div id="tab2">
        <p>Tab 2 content...</p>
        <strong>Tab 2 bold text</strong>
    </div>
    <div id="tab3">
        <p>Tab 3 content...</p>
        <p>...and more content</p>
    </div>
</div>
```

下面的 JavaScript 代码实例化了标签小部件，其中 `show` 和 `hide` 效果选项传递给小部件构造函数。

```js
$(function() {

    $( "#tabs" ).tabs({
        show: {
            effect: "slide",
            direction: "left"
        },
        hide: {
            effect: "drop",
            direction: "right"
        }
    });

});
```

## 它是如何工作的...

当您在浏览器中查看此选项卡小部件并点击选项卡时，您会注意到当前选项卡的内容向右滑动，同时淡出。一旦此效果执行完毕，当前活动选项卡的 `show` 效果就会运行，在这种情况下，内容从左侧滑入。这两种效果相辅相成——结合在一起，它们产生了新内容将旧内容推出面板的幻觉。

我们在这里选择的两种效果实际上非常相似。`drop`效果实际上只是`slide`效果，额外加上了在滑动时的淡入淡出。它们协作的关键是我们传递给每个`effect`对象的`direction`属性。我们告诉`hide`效果在运行时向右移动。同样，我们告诉`show`效果从左侧进入。

# 使用可排序交互进行标签排序

当我们在用户界面中实现标签时，我们可能会简短地考虑标签的默认排序。显然，我们希望最相关的标签按照用户最能理解的顺序进行访问。但通常我们无法以让所有人满意的方式做到这一点。那么为什么不让用户自行安排标签的顺序呢？让我们看看能否通过在标签小部件中提供这种功能来利用可排序交互小部件来提供帮助。

## 如何实现...

我们将使用以下 HTML 作为驱动我们标签实例的示例：

```js
<div id="tabs">
    <ul>
        <li><a href="#tab1">Tab 1</a></li>
        <li><a href="#tab2">Tab 2</a></li>
        <li><a href="#tab3">Tab 3</a></li>
    </ul>
    <div id="tab1">
        <p>Tab 1 content...</p>
    </div>
    <div id="tab2">
        <p>Tab 2 content...</p>
    </div>
    <div id="tab3">
        <p>Tab 3 content...</p>
    </div>
</div>
```

接下来，我们将在标签小部件中实现新的`sortable`选项。我们还需要扩展小部件的行为以利用这个新选项。

```js
(function( $, undefined ) {

$.widget( "ab.tabs", $.ui.tabs, {

    options: {
        sortable: false
    },

    _create: function() {

        this._super();

        if ( !this.options.sortable ) {
            return;
        }

        this.tablist.sortable({
            axis: "x",
            stop: $.proxy( this, "_stopped" )
        });

    },

    _destroy: function() {

        if ( this.options.sortable ) {
            this.tablist.sortable( "destroy" );
        }

        this._super();

    },

    _stopped: function( e, ui ) {
        this.refresh();
    }

});

})( jQuery );

$(function() {

    $( "#tabs" ).tabs({
        sortable: true
    });

});
```

现在当您沿着 x 轴拖动标签按钮时，放下它们将重新排列它们的顺序。例如，拖动第一个标签会看起来像这样：

![如何实现...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_10_08.jpg)

如果我们将第一个标签放在末尾并激活 **Tab 2**，现在第一个标签，你应该看到类似这样的东西：

![如何实现...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_10_09.jpg)

## 它是如何工作的...

我们已经向标签小部件添加了一个新选项，`sortable`，当设置为 true 时，将使用可排序交互小部件来启用标签按钮的可排序行为。我们通过在`options`对象中将默认`sortable`值设置为`false`来添加了这个选项。该对象将与默认标签选项合并。在`_create()`方法中，标签构造函数中，我们调用原始的标签小部件构造函数，因为默认小部件构造不存在特殊情况。接下来，在`_create()`内部，我们检查`sortable`选项是否为`true`，如果是，就创建可排序小部件。我们使用`tablist`属性来创建可排序小部件，这是一个包含标签按钮的`ul`元素。这就是为什么我们在这里调用它，我们想让它的子元素在 x 轴上可以进行排序。

我们还将可排序小部件的`stop`选项传递给一个回调函数，这种情况下是`_stopped()`方法的代理。这里使用了`$.proxy()`实用程序，这样我们可以像实现标签的常规方法一样实现`_stopped()`。请注意在`_stopped()`的实现中，这是小部件实例，而没有代理，它会是`ul`元素。

最后，在这里重写了`_destroy()`方法以确保可排序小部件被销毁。如果不这样做，我们就无法可靠地销毁并重新创建标签小部件。

## 更多信息...

当将`sortable`选项设置为`true`时，我们可以进一步增强选项卡小部件的用户交互。首先，让我们在用户拖动选项卡时修改`cursor`，以便使用标准的移动图标。接下来，我们将激活放置的选项卡。这是我们为修改后的光标所需的 CSS；我们将保持先前的 HTML 结构不变：

```js
.ui-tabs .ui-tabs-nav li.ui-tab-move > a {
    cursor: move;
}
```

这是修改后的 JavaScript 代码：

```js
(function( $, undefined ) {

$.widget( "ab.tabs", $.ui.tabs, {

    options: {
        sortable: false
    },

    _create: function() {

        this._super();

        if ( !this.options.sortable ) {
            return;
        }

        this.tablist.sortable({
            axis: "x",
            start: $.proxy( this, "_started" ),
            stop: $.proxy( this, "_stopped" )
        });

    },

    _destroy: function() {

        if ( this.options.sortable ) {
            this.tablist.sortable( "destroy" );
        }

        this._super();

    },

    _started: function( e, ui ) {
        ui.item.addClass( "ui-tab-move" );
    },

    _stopped: function( e, ui ) {

        ui.item.removeClass( "ui-tab-move" );
        this.refresh();
        this._activate( ui.item.index() );

    }

});

})( jQuery );

$(function() {

    $( "#tabs" ).tabs({
        sortable: true
    });

});
```

现在，当您对这些选项卡进行排序时，您会注意到新的光标如以下截图所示。`ui-tab-move`类定义了`cursor`的 CSS 属性，此类被添加到可排序小部件的`start`事件处理程序中的`li`元素中。在`stop`处理程序中随后删除。您还会注意到当放置选项卡时会激活选项卡。这是通过获取`li`元素的索引并将其传递给`activate()`方法来完成的。

![还有更多...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_10_10.jpg)

# 使用 href 设置活动选项卡

选项卡小部件允许开发人员通过将零基索引值传递给`active`选项来以编程方式设置活动选项卡。这可以通过在选项卡构造函数中设置此选项来完成，告诉小部件默认激活哪个选项卡，或者可以在之后设置，从而可能改变活动选项卡。使用此选项更改活动选项卡实质上与用户点击选项卡按钮激活面板是相同的。然而，我们可以改进此界面，让使用选项卡小部件的开发人员传递`href`值而不是索引值。这样，您就不必记住选项卡的顺序—哪个数字代表哪个链接，等等。

## 如何实现...

让我们首先设置此演示中使用的 HTML 作为选项卡小部件的基础。

```js
<div id="tabs">
    <ul>
        <li><a href="#tab1">Tab 1</a></li>
        <li><a href="#tab2">Tab 2</a></li>
        <li><a href="#tab3">Tab 3</a></li>
    </ul>
    <div id="tab1">
        <p>Tab 1 content...<a class="tab-link" href="#tab2">tab 2</a></p>
    </div>
    <div id="tab2">
        <p>Tab 2 content...<a class="tab-link" href="#tab3">tab 3</a></p>
    </div>
    <div id="tab3">
        <p>Tab 3 content...<a class="tab-link" href="#tab1">tab 1</a></p>
    </div>
</div>
```

下面是修改后的选项卡小部件实现，使我们可以通过将字符串`"#tab2"`传递给`active`选项来激活第二个选项卡。

```js
(function( $, undefined ) {

$.widget( "ab.tabs", $.ui.tabs, {

    _findActive: function( index ) {
        return this._super( this._getIndex( index ) );
    },

    _initialActive: function() {

        this.options.active = this._getIndex( this.options.active );
        return this._super();

    }

});

})( jQuery );

$(function() {

    $( "#tabs" ).tabs({
        active: "#tab2"
    });

    $( ".tab-link" ).on( "click", function( e ) {
        e.preventDefault();
        $( "#tabs" ).tabs( "option", "active", $( this ).attr( "href" ) );
    });

});
```

## 它是如何运作的...

当您在浏览器中查看此选项卡小部件时，您会注意到第二个选项卡默认处于激活状态，因为我们传递了字符串`"#tab2"`。还会注意到每个选项卡面板的内容都指向另一个选项卡的链接。

![它是如何运作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_10_11.jpg)

我们正在扩展选项卡小部件，以便我们可以重写一些选项卡方法。第一个方法是`_findActive()`，在原始实现中期望一个整数。我们已经改变了这一点，使用了根据选项卡按钮的`href`属性返回索引的`_getIndex()`方法，也就是说，除非它得到传递给它的整数值，否则它只返回那个数字。简而言之，我们已经改变了`_findActive()`，以接受零基索引号，或`href`字符串。

下一个方法是 `_initialActive()`，当标签小部件首次实例化时调用。我们在这里要做的是在调用 `_initialActive()` 的原始实现之前，将活动选项设置为适当的索引值。这是为了支持构造函数中的 `href` 字符串作为 `active` 选项值。

最后，我们使用 `href` 字符串创建我们的标签小部件，并将事件处理程序绑定到标签面板中的每个标签链接上。在这里，我们仅基于链接的 `href` 属性激活标签，所以你可以看到我们引入的这种新 `href` 功能的价值。

## 还有更多...

在前面的示例中，我们利用了标签按钮链接的 `href` 属性。但是，我们没有利用浏览器的位置哈希。换句话说，当激活标签时，浏览器 URL 中的位置哈希不会更改。支持这种方法有几个优点。首先，我们可以使用返回按钮浏览我们的活动标签。另一个好处是，标签内容面板中的链接不再需要事件处理程序；它们可以直接指向标签 `href`。

这里是修改后的 JavaScript，支持与上一个示例相同的功能。唯一的区别是，每次激活标签时，URL 哈希都会更改。

```js
(function( $, undefined ) {

$.widget( "ab.tabs", $.ui.tabs, {

    _create: function() {

        this._super();

        this._on( window, { 
            hashchange: $.proxy( this, "_hashChange" )
        });

    },

    _hashChange: function( e ) {

        if ( this.active.attr( "href" ) === location.hash ) {
            return;
        }

        this._activate( this._getIndex( location.hash ) );

    },

    _eventHandler: function( e ) {

        this._super( e );  

        var href = $( e.target ).attr( "href" );

        if ( href === location.hash ) {
            return;
        }

        if ( href.indexOf( "#" ) === 0 ) {
            location.hash = href;
        }
        else {
            location.hash = "";
        }

    }

});

})( jQuery );

$(function() {
    $( "#tabs" ).tabs();
});
```

现在，当你在浏览器中与此标签小部件交互时，你会注意到在导航标签时 URL 中的哈希会更改。这是通过在调用 `_create()` 的原始实现后向该方法添加事件处理程序来完成的。我们使用 `_on()` 实用程序方法订阅窗口的 `hashchange` 事件。接下来，我们添加的 `_hashChange()` 方法是此事件的处理程序。首先，我们检查 URL 哈希，存储在 `location.hash` 变量中，是否已经指向活动标签。如果没有，我们根据当前 URL 哈希值激活标签。这是我们支持指向 URL 哈希的标签面板内容中的链接所需的全部内容。但是，当用户直接单击标签按钮时，哈希值不会更改。这对我们没有帮助，因为我们无法跟踪标签导航历史记录。

这就是为什么我们实现了 `_eventHandler()` 方法的自定义。我们首先调用方法的原始实现，然后再处理 URL 哈希的具体情况。如果 URL 哈希已经指向活动标签，我们在这里没有任何操作；否则，我们更新 URL 哈希。
