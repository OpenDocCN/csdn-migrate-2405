# jQuery UI 秘籍（一）

> 原文：[`zh.annas-archive.org/md5/6053054F727DA7F93DC0A95B33107695`](https://zh.annas-archive.org/md5/6053054F727DA7F93DC0A95B33107695)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

创造令人兴奋的用户体验是一项有趣而有价值的工作。实质上，您正在改善许多人的生活。大多数 UI 开发人员的目光都在终点上，看着他们的产品被使用。我们越快到达终点线而不牺牲质量，就越好。我们用来帮助我们达到这个目标的工具可能会产生世界上的所有差异。

jQuery 框架在开发人员中如此受欢迎的部分原因在于“少写，做得更多”的口号，在 jQuery UI 中也有体现。现代版本的 HTML 和 CSS 标准具有组装健壮，响应迅速的用户界面所需的工具。当这个想法破灭时——浏览器的不一致性以及跨项目的开发惯例和模式的缺乏——jQuery UI 介入。jQuery UI 的目标不是重新发明我们编写 Web 应用程序的方式，而是填补空白，并逐步增强现有的浏览器组件。

与任何框架一样，jQuery UI 并不适用于所有人，也不完全适合使用它的人。框架接受了这一事实，并为您可能遇到的大多数情况提供了可扩展性机制。我写这本书的目标是与您分享我在使用 jQuery UI 小部件时的一些经验。我尽可能地进行了扩展，并在必要时进行了修改。我相信您会发现本书中的大多数技巧都很有用，无论您构建什么类型的应用程序。

# **本书涵盖内容**

第一章, *创建手风琴*，帮助您学习如何在手风琴小部件之间拖放。此外，您还将学习如何扩展手风琴主题。

第二章, *包含自动完成*，解释了自动完成小部件，显示如何使用多个数据源。还涵盖了将选择选项转换为自动完成小部件以及远程数据源过滤的内容。

第三章, *制作按钮*，解释了如何修改我们应用程序中的按钮。按钮可以简单，修改文本和图标选项。或者，按钮可以更复杂，比如处理按钮集时。我们将研究间距问题，以及如何应用效果。

第四章, *开发日期选择器*，讨论了日期选择器，这是最广泛使用的小部件，但利用率最低的。我们将通过使用一些技巧来更好地将日期选择器集成到您的应用程序中，发掘小部件的一些潜力。

第五章, *添加对话框*，讨论了对话框小部件，这些小部件通常依赖于 API 数据。我们将研究加载数据和对话框显示问题。我们还涵盖了更改对话框标题栏以及对小部件应用效果的内容。

第六章, *制作菜单*，帮助您学习如何制作可排序的菜单项。我们还将解决主题问题以及突出显示活动菜单项的问题。

第七章，*进度条*，展示了如何向进度条添加标签。我们还将扩展进度条以创建加载小部件。

第八章，*使用滑块*，介绍了不显示步进增量的滑块小部件。在这里，您将扩展小部件以提供此功能。我们还将研究更改滑块手柄的视觉显示。

第九章，*使用微调器*，解释了微调器，通常用于表单中。因此，我们在本章中处理了本地货币和日期的微调器值的格式化。我们还将研究处理小部件的主题问题。

第十章，*使用选项卡*，介绍了在处理选项卡时使用一些新技术，即使用每个选项卡作为普通 URL 链接。我们还涵盖了一些更高级的选项卡导航用法——动态加载和读取浏览器哈希值。

第十一章，*使用工具提示*，解释了工具提示，可以应用于页面上的几乎任何内容。在本章中，我们将向您展示如何将效果应用于工具提示，更改工具提示状态，并将工具提示应用于所选文本。

第十二章，*小部件和更多！*，讨论了小部件，它们不是独立存在的。它们是更大应用程序的一部分。本章涵盖了更大的 jQuery UI 开发画面。这包括从头开始构建小部件、构建自己的开发工具以及使用 Backbone。

# 本书需要什么

您将需要以下内容：

+   用于运行示例的现代 Web 浏览器。

+   一个用于阅读和调整示例的文本编辑器。

+   所有 JavaScript 依赖项都包含在示例下载中。

+   Python（可选）；一些示例需要 Web 服务器，并在示例中使用内置的 Python Web 服务器。示例可以使用任何具有适当调整的 Web 服务器。

# 本书适用于谁

本书适用于希望改进其现有应用程序、为其新应用程序提取想法或更好地理解整体小部件架构的 jQuery UI 开发人员。读者至少应具有初步的了解什么是 jQuery UI，并编写了一些使用 jQuery UI 的代码。本书中的配方面向中级 jQuery UI 开发人员。根据您的需求，每个配方都足够独立以在自身上有用，但又足够连接以引导您到其他内容。

# 约定

在本书中，您将找到一些样式的文本，用于区分不同类型的信息。以下是这些样式的一些示例，以及它们的含义解释。

文本中的代码词如下所示：“在这种情况下，我们最好只是将默认的 `dateFormat` 值更改为我们的应用程序在整个过程中使用的某些内容。”

代码块设置如下：

```js
$(function() {
    $( ".calendar" ).datepicker();
});
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以此类样式显示在文本中：“单击**no icons**链接将导致按钮图标被移除，并用它们的文本替换。”

### 注意

警告或重要说明会以此类样式显示在框中。

### 提示

贴士和技巧显示为此类样式。


# 第一章：创建手风琴

在本章中，我们将涵盖以下配方：

+   使用 Tab 键进行部分导航

+   动态更改高度样式

+   可调整大小的内容部分

+   使用主题控制间距

+   排序手风琴部分

+   在手风琴之间进行拖放

# 介绍

在本章中，我们将探讨多种方法，以扩展**手风琴**小部件，以适应多种情况。手风琴小部件提供了很多开箱即用的功能。例如，没有任何配置，我们就得到了一个主题化的容器小部件，将内容分组到部分中。

我们将专注于揭示手风琴小部件内部工作原理的用例。键盘事件是导航页面的一种方式，我们可以增强手风琴对这些事件的支持。在展开时，每个部分的高度会发生一些神奇的变化。我们将看到我们如何处理这些配置，特别是当部分高度在飞行中改变时。

此外，在高度方面，我们可以让用户控制各个部分的高度，或者从主题的角度来看，我们可以控制手风琴组件之间的空间。最后，我们将看一些更高级的手风琴用法，其中我们让用户自由地对手风琴部分进行排序，并将部分从一个手风琴拖到另一个手风琴中。

# 使用 Tab 键进行部分导航

在大多数桌面环境中，*Tab* 键是导航中的秘密武器——许多用户习惯使用的一个工具。同样，我们可以使用 `tabindex` 属性在 HTML5 应用程序中利用 *Tab* 键。这告诉浏览器每次按下该键时焦点元素的顺序。

不幸的是，使用手风琴小部件并不像看起来那么简单。我们不能在每个部分标题中指定 `tabindex` 值，并期望 *Tab* 键事件按预期工作。相反，默认小部件实现提供了一种不同类型的键导航——*上* 和 *下* 箭头键。理想情况下，给用户使用他们熟悉的 *Tab* 键通过手风琴部分导航的能力是有用的，同时保留小部件提供的默认键导航。

## 准备工作

要开始，我们需要一个基本的手风琴；理想情况下，是一些简单的内容，每个部分都有基本的内容，这样我们就可以在实现自定义事件之前和之后直观地看到 *Tab* 键的行为如何工作。

作为指南，这是我的基本手风琴标记：

```js
<div id="accordion">
    <h3>Section 1</h3>
    <div>
        <p>Section 1 content</p>
    </div>
    <h3>Section 2</h3>
    <div>
        <p>Section 2 content</p>
    </div>
    <h3>Section 3</h3>
    <div>
        <p>Section 3 content</p>
    </div>
    <h3>Section 4</h3>
    <div>
        <p>Section 4 content</p>
    </div>
</div>
```

并且，这是用于实例化手风琴小部件的代码：

```js
$(function() {

    $( "#accordion" ).accordion({
        collapsible: true
    });

});
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了此书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册以直接将文件发送到您的电子邮件。

现在我们有一个基本的可折叠手风琴小部件，我们可以在浏览器中查看。我们在这里添加`collapsible`选项的原因是为了可以实验按键导航——当所有部分都折叠时，我们可以更好地看到哪个部分处于焦点状态。您可以看到*up*和*down*箭头键允许用户遍历手风琴部分，而*Tab*键没有任何效果。让我们改变一下。

## 如何做...

我们将扩展手风琴小部件以包括一个`keypress`事件的事件处理程序。默认的手风琴实现有处理*up*、*down*、*left*、*right*和*Enter*键的`keypress`事件。我们不需要改变这一点。相反，我们添加了一个理解当按下*Tab*键和*Shift* + *Tab*键时该做什么的自定义处理程序。

看一下以下代码：

```js
(function( $, undefined ) {

$.widget( "ab.accordion", $.ui.accordion, {

    _create: function () {

        this._super( "_create" );
        this._on( this.headers, { keydown: "_tabkeydown" } );

    },

    _tabkeydown: function ( event ) {

        if ( event.altKey || event.ctrlKey ) {
            return;
         }

        if ( event.keyCode !== $.ui.keyCode.TAB ) {
            return;
        }

        var headers = this.headers,
            headerLength = headers.length,
            headerIndex = headers.index( event.target ),
            toFocus = false;

        if ( event.shiftKey && headerIndex - 1 >= 0 ) {
            toFocus = headers[ headerIndex - 1 ];
        }

        if ( !event.shiftKey && headerIndex + 1 < headerLength ) {
            toFocus = headers[ headerIndex + 1 ];
        }

        if ( toFocus ) {

            $( event.target ).attr( "tabIndex", -1 );
            $( toFocus ).attr( "tabIndex", 0 );
            toFocus.focus();
            event.preventDefault();

        }

    }

});

})( jQuery );

$(function() {

    $( "#accordion" ).accordion({
        collapsible: true
    });

});
```

## 它是如何工作的...

我们在这里通过扩展默认的手风琴小部件来创建一个新的手风琴小部件。扩展手风琴小部件的优势在于我们不会去修改小部件的实例；所有手风琴实例都将获得这种新的行为。

`_create()`方法被我们的新实现所取代。在这个替代方法中，我们首先调用原始的`_create()`方法。我们不想阻止手风琴小部件的默认设置操作发生。因此，使用`_super()`我们能够做到这一点。接下来我们绑定了我们的新的`tabkeydown()`事件处理程序到`keydown`事件上。

`tabkeydown()`处理程序是原始手风琴实现中提供的`keydown`事件处理程序的简化版本。如果*Alt*或*Ctrl*键与其他键组合按下，则我们忽略事件。如果按下的键不是*Tab*，我们也会忽略事件，因为我们只对当手风琴标题处于焦点时改变*Tab*键行为感兴趣。

处理程序的要点在于确定*Tab*键按下时应该发生什么。我们应该将手风琴标题焦点移动到哪个方向？何时忽略事件并让默认浏览器行为接管？诀窍在于确定我们当前的索引位置。如果我们在第一个标题上，并且用户按下*Shift* + *Tab*，意味着他们想向后遍历，则我们不做任何操作。同样，如果我们在最后一个标题上，并且用户按下*Tab*，我们将控制权交给浏览器，以便不干扰预期功能。

# 动态改变高度样式

手风琴是用于组织和显示其他 UI 元素的容器。将每个手风琴部分视为静态内容是一个错误。手风琴部分的内容确实会发生变化。例如，用户触发的事件可能会导致在部分内创建新元素。很可能，部分内的组件会动态改变大小，这是我们需要注意的部分。为什么关注手风琴内容变化大小很重要？因为这是一个手风琴，我们可能会有几个部分（或至少有一些）。让它们都具有统一的高度有意义吗？在某个部分的高度增加到非常大的程度时，它就不再具有统一的高度了。当发生这种情况时，我们需要查看手风琴部分高度的变化，并在必要时动态调整一些高度设置。

## 准备就绪

让我们使用以下标记创建手风琴小部件：

```js
<div id="accordion">
    <h3>Section 1</h3>
    <div>
        <p>Section 1 content</p>
    </div>
    <h3>Section 2</h3>
    <div>
        <p>Section 2 content</p>
    </div>
    <h3>Section 3</h3>
    <div>
        <p>Section 3 content</p>
    </div>
    <h3>Section 4</h3>
     <div>
        <ul>
            <li>First item</li>
            <li>Second item</li>
            <li>Third item</li>
            <li>Fourth item</li>
        </ul>
     </div>
</div>
```

我们将使用所有默认选项值创建手风琴如下：

```js
$(function() {
    $("#accordion").accordion();
});
```

现在，我们会注意到一个关于高度的轻微不一致性。以下是第一部分的样子。它内容很少，但却使用了比所需更多的空间。

![准备就绪](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_01_01.jpg)

这是由于`heightStyle`选项的默认值造成的，该选项规定手风琴中每个部分的高度将等于最高部分的高度。因此，我们在第一部分浪费了空间。让我们看看以下屏幕截图中的第四部分，以了解为什么会发生这种情况：

![准备就绪](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_01_02.jpg)

我们可以看到，第一部分与第四部分一样高。这是由于`heightStyle`的`auto`值造成的。在这个特定的例子中，差异并不是那么大。也就是说，第一部分没有浪费太多的空白空间。因此，保持每个部分具有相同高度的手风琴配置可能是有意义的。

当我们处理动态向特定手风琴部分提供内容的应用程序时，挑战就出现了，在某个临界点达到时，保持自动`heightStyle`配置就不再有意义了。

## 如何做...

将`heightStyle`设置为`auto`可以为我们解决问题，因为每个部分只会使用必要的高度来显示内容。但是，如果能够在内容自身的高度发生变化时更改手风琴的此属性，那就更好了。

```js
(function( $, undefined ) {

$.widget( "ab.accordion", $.ui.accordion, {

    refresh: function() {

        this._super( "refresh" );

        if ( this.options.heightStyle !== "content" ) {
            return;
        }

        this.headers.next().each( function() {

            if ( $( this ).css( "height" ) ) {
                $( this ).css( "height", "" );
            }

        });

    }

});

})(jQuery);

$(function() {

    $( "#accordion" ).accordion();

    for ( var i=0; i<20; i++ ){
        $( "ul" ).append( "<li>nth item</li>" );
    }

    $( "#accordion" ).accordion( "option", "heightStyle", "content" )
                     .accordion( "refresh" );

});
```

## 它是如何工作的...

我们在这里所做的是扩展手风琴小部件的`refresh()`方法，以允许在运行时将`heightStyle`选项更改为内容。默认实现不允许此操作。为了说明这个想法，请考虑上面的代码，我们正在创建手风琴小部件，并向最后一个内容部分添加 20 个新项。我们在这里使用的是默认部分高度，即`auto`。因此，如果我们没有扩展`refresh()`方法来允许此行为在填充第四部分后，我们会看到一个滚动条。

# 可调整大小的内容部分

可调整大小的内容部分允许用户通过拖动部分底部来调整高度。这是一种很好的选择，而不是依赖于`heightStyle`属性。因此，如果手风琴的每个部分都可以由用户调整，则他们可以自由地定制手风琴布局。例如，如果手风琴有一个高的部分，在底部浪费了空间，用户可能会选择缩小该部分的高度，以更好地查看手风琴以及 UI 的其他组件。

## 如何操作...

我们将通过使用可调整大小的交互小部件使手风琴内的每个内容的`div`可调整大小来扩展默认手风琴的`_create()`方法。

```js
( function( $, undefined ) {

$.widget( "ab.accordion", $.ui.accordion, {

    _create: function () {

        this._super( "_create" );

        this.headers.next()
                    .resizable( { handles: "s" } )
                    .css( "overflow", "hidden" );

    },

    _destroy: function () {

        this._super( "_destroy" );

        this.headers.next()
                    .resizable( "destroy" )
                    .css( "overflow", "" );

    }

});

})( jQuery );

$( function() {

    $( "#accordion" ).accordion();

});
```

您将看到类似以下的内容。请注意，第二节已被向下拖动，并带有调整大小的鼠标光标。

![如何操作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_01_03.jpg)

## 工作原理...

我们的`_create()`方法的新版本首先调用默认手风琴的`_create()`方法。完成后，我们找到手风琴的所有内容部分，并应用`resizable()`小部件。您还会注意到，我们告诉可调整大小的小部件仅显示一个`south`手柄。这意味着用户只能使用部分底部的光标将手风琴的任何给定内容部分向上或向下拖动。

这个手风琴的特殊化还提供了一个新的`_delete()`方法的实现。再次，我们在调用原始手风琴的`_delete()`之后，清理我们添加的新可调整大小组件。这包括删除`overflow`CSS 属性。

## 还有更多...

我们可以通过提供关闭它的手段来扩展手风琴中的可调整大小行为。我们将在手风琴中添加一个简单的`resizable`选项，用于检查是否使手风琴部分可调整大小。

```js
(function( $, undefined ) {

$.widget( "ab.accordion", $.ui.accordion, {

    options: {
        resizable: true
    },

    _create: function () {

        this._super( "_create" );

        if ( !this.options.resizable ) {
            return;
        }

        this.headers.next()
                    .resizable( { handles: "s" } )
                    .css( "overflow", "hidden" );
    },

    _destroy: function () {

        this._super( "_destroy" );

        if ( !this.options.resizable ) {
            return;
        }

        this.headers.next()
                    .resizable( "destroy" )
                    .css( "overflow", "" );

    },

});

})( jQuery );

$(function() {

    $( "#accordion" ).accordion( { resizable: false } );

});
```

# 使用主题控制间距

手风琴部分之间的间距由 CSS 主题框架控制。特别是，手风琴的视觉结构由一组 CSS 规则定义，可以修改以控制手风琴部分之间的间距。我们可以覆盖手风琴主题 CSS 以调整部分之间的间距。

## 如何操作...

我们将为我们的 UI 提供一个额外的 CSS 模块，它将覆盖我们目前正在使用的主题中提供的手风琴结构。然而，无需担心，我们的更改很简单。我们将更新`margin-top`属性。在一个名为`theme.accordion.css`的新 CSS 文件中，让我们添加以下样式规则：

```js
.ui-accordion .ui-accordion-header {
    margin-top: 4px;
}
```

现在我们有了 CSS，我们需要将其包含在我们的 HTML 头部。它应该类似于这样：

![操作步骤...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_01_04.jpg)

## 工作原理...

我们复制了与任何 jQuery UI 主题中找到的相同的 CSS 选择器。我们刚刚更改的特定属性改变了手风琴部分之间的间距。由于我们覆盖了默认主题值，所以将我们的 CSS 文件包含在默认主题文件之后非常重要。这样我们就可以覆盖默认主题，而不是默认主题覆盖我们的修改。

# 对手风琴部分进行排序

使用可排序交互式小部件，我们能够将静态手风琴部分布局转换为用户指定的内容。也就是说，可排序交互式小部件接受一个容器元素，并允许对所有子元素进行就地排序。用户通过将元素拖动到所需顺序来执行此操作。

我们将看看如何扩展手风琴功能，以便在创建时可以通过配置选项打开可排序部分功能。

## 操作步骤...

当手风琴小部件创建时，以及销毁手风琴时，我们必须执行几个操作。以下是我们如何扩展小部件的方式：

```js
( function( $, undefined ) {

$.widget( "ab.accordion", $.ui.accordion, {

    options: {
        sortable: false
    },

    _create: function () {

        this._super( "_create" );

        if ( !this.options.sortable ) {
            return;
        }

        this.headers.each( function() {
            $( this ).next()
                     .addBack()
                     .wrapAll( "<div/>" );
        });

        this.element.sortable({
            axis: "y",
            handle: "h3",
            stop: function( event, ui ) {
                ui.item.children( "h3" )
                       .triggerHandler( "focusout" );
            }
        });        

    },

    _destroy: function () {

        if ( !this.options.sortable ) {
            this._super( "_destroy" );
            return;
        }

        this.element.sortable( "destroy" );

        this.headers.each( function () {
            $( this ).unwrap( "<div/>" );
        });

        this._super( "_destroy" );

    }

});

})( jQuery );

$( function() {

    $( "#accordion" ).accordion( { sortable: true } );

});
```

有了我们新的标记为`sortable`的手风琴小部件，用户现在可以在手风琴内拖动头部部分。例如，如果第一个手风琴部分属于底部，用户只需将其拖到底部。

![操作步骤...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_01_05.jpg)

## 工作原理...

借助`sortable()`交互式小部件的帮助，我们能够扩展默认手风琴小部件实现，以包括排序功能。与任何 jQuery UI 小部件增强一样，我们实际上不需要扩展所讨论的小部件；新功能始终可以在小部件实例化后附加。然而，正如您将在本书中看到的，最佳实践是封装自定义内容并将其作为一组选项呈现给小部件客户端。

我们在此扩展了可用的手风琴选项集，包括一个`sortable`选项。这是我们打开或关闭自定义的方式（它是一个布尔值）。我们实现的自定义`_create()`版本将调用手风琴的`_create()`方法的默认版本。之后，我们将查看可排序行为是否被关闭（在这种情况下我们无需做任何事情，所以返回）。同样，我们的自定义`_delete()`函数在调用原始删除功能后检查可排序行为是否已打开。

实现可排序手风琴部分的棘手部分在于我们必须在手风琴元素内进行轻微的 DOM 操作。这是为了使用可排序交互小部件所必需的。手风琴小部件的标记结构化，使得所有部分都相邻。也就是说，我们有一个 `h3` 元素，后面跟着一个 `div` 元素。这是一个部分，并且后面跟着另一个 `h3` 和另一个 `div`，依此类推。这是一个平面结构。有两种处理方式：修改创建小部件所需的标记，或者注入一些轻微的 DOM 修改，并且小部件客户端对此一无所知。我们选择后一种方式，不要求客户端更改其代码。这是另一个最佳实践，即在提供定制时保持现有小部件客户端代码的功能性。

在我们定制的 `_create()` 版本中，我们正在迭代每个手风琴标题，并将标题元素和相应的内容元素包装在一个 `div` 元素中，以便将它们捆绑在一起。这样，可排序小部件就知道如何移动这个捆绑包了。如果我们没有这样做，用户只能移动标题部分，从而将其与内容分开。最后，我们正在创建可排序小部件，将移动限制为*y*轴，并将可移动手柄设置为手风琴标题。

我们定制的 `_destroy()` 函数在调用原始的 `_destroy()` 方法之前撤消我们的修改。这意味着取消包装我们的新 `div` 元素并销毁可排序小部件。

# 在手风琴之间拖放

一些应用程序需要比其他更流畅的布局，不仅从屏幕分辨率的角度来看，而且从功能的角度来看也是如此。手风琴小部件是一个静态分组组件，用于将较小的组件组织成部分。我们只需展开感兴趣的部分，就可以隐藏所有不相关的材料。正如我们在*排序手风琴部分*的示例中看到的那样，我们可以提供一个手风琴，用户可以通过拖放来操作其结构。实际上，这已经成为用户大规模预期的事情——通过拖放进行 UI 配置。

可排序手风琴专注于单个手风琴。当然，在应用程序的范围内给予用户自由的精神下，我们为什么不试着看看我们是否能支持将手风琴部分移动到一个新的手风琴中呢？

## 准备就绪

对于这个实验，我们需要两个基本的手风琴。标记应该假设如下所示的形式：

```js
<div id="target-accordion" style="width: 30%">
    <h3>Section 1</h3>
    <div>
        <p>Section 1 content</p>
    </div>
    <h3>Section 2</h3>
    <div>
        <p>Section 2 content</p>
    </div>
    <h3>Section 3</h3>
    <div>
        <p>Section 3 content</p>
    </div>
</div>
<p></p>
<div id="accept-accordion" style="width: 30%">
    <h3>Section 4</h3>
    <div>
        <p>Section 4 content</p>
    </div>
    <h3>Section 5</h3>
    <div>
        <p>Section 5 content</p>
    </div>
    <h3>Section 6</h3>
    <div>
        <p>Section 6 content</p>
    </div>
</div>
```

## 如何做...

有了这个，让我们将这个标记转换为两个手风琴。我们首先将手风琴小部件扩展为带有一些花哨的拖放行为。意图是允许用户将第一个小部件的手风琴部分拖到第二个小部件中。下面是具体操作：

```js
(function( $, undefined ) {

$.widget( "ui.accordion", $.ui.accordion, {

    options: {
         target: false,
         accept: false,
         header: "> h3, > div > h3"
    },

    _teardownEvents: function( event ) {

        var self = this,
            events = {};

        if ( !event ) {
            return;
        }

        $.each( event.split(" "), function( index, eventName ) {
            self._off( self.headers, eventName );
        });

    },

    _createTarget: function() {

        var self = this,
            draggableOptions = {
                handle: "h3",
                helper: "clone",
                connectToSortable: this.options.target,
            };

        this.headers.each( function() {
            $( this ).next()
                     .addBack()
                     .wrapAll( "<div/>" )
                     .parent()
                     .draggable( draggableOptions );
        });
    },

    _createAccept: function() {

        var self = this,
            options = self.options,
            target = $( options.accept ).data( "uiAccordion" );

        var sortableOptions = {

            stop: function ( event, ui ) {

                var dropped       = $(ui.item),
                    droppedHeader = dropped.find("> h3"),
                    droppedClass  = "ui-draggable",
                    droppedId;

                if ( !dropped.hasClass( droppedClass ) ) {
                    return;
                }

                // Get the original section ID, reset the cloned ID.
                droppedId = droppedHeader.attr( "id" );
                droppedHeader.attr( "id", "" );

                // Include dropped item in headers
                self.headers = self.element.find( options.header )

                // Remove old event handlers
                self._off( self.headers, "keydown" );
                self._off( self.headers.next(), "keydown" );
                self._teardownEvents( options.event );

                // Setup new event handlers, including dropped item.
                self._hoverable( droppedHeader );
                self._focusable( droppedHeader );
                self._on( self.headers, { keydown: "_keydown" } );
                self._on( self.headers.next(), { keydown: "_panelKeyDown" } );
                self._setupEvents( options.event );
```

```js
                // Perform cleanup
                $( "#" + droppedId ).parent().fadeOut( "slow", function() {
                    $( this ).remove();
                    target.refresh();
                });

                dropped.removeClass( droppedClass );

            }

        };

        this.headers.each( function() {
            $(this).next()
                   .addBack()
                   .wrapAll( "<div/>" );
        });

        this.element.sortable( sortableOptions );

    },

    _create: function() {

        this._super( "_create" );

        if ( this.options.target ) {
            this._createTarget();
        }

        if ( this.options.accept ) {
            this._createAccept();
        }

    },

    _destroy: function() {

        this._super( "_destroy" );

        if ( this.options.target || this.options.accept ) {

            this.headers.each( function() {
                $( this ).next()
                         .addBack()
                         .unwrap( "<div/>" );
            });
        }
    }

});

})( jQuery );

$(function() {

    $( "#target-accordion" ).accordion({
        target: "#accept-accordion"
    });

    $( "#accept-accordion" ).accordion({
        accept: "#target-accordion" 
    });

});
```

现在我们有了两个看起来基本的手风琴小部件。然而，如果用户愿意，他们可以将第一个手风琴的部分拖到第二个手风琴中。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_01_06.jpg)

## 它是如何运作的......

乍一看，这可能看起来是很多的代码，但是只需要很少的工作（约 130 行左右），我们就能够将手风琴部分从一个手风琴拖放到另一个手风琴。让我们进一步解析一下。

我们通过这个小部件扩展添加了两个手风琴选项：`target` 和 `accept`。目标允许我们指定手风琴的部分目的地。在这个例子中，我们将第二个手风琴作为第一个手风琴的目标，这意味着我们可以从`target-accordion`拖放到`accept-accordion`。但是，为了实现这一点，必须告诉第二个手风琴从哪里接受部分；在这种情况下，它是`target-accordion`。我们基本上使用这两个选项在两个小部件之间建立拖放合同。

这个例子使用了两个交互式小部件：draggable 和 sortable。`target-accordion`使用了 draggable。如果指定了`target`选项，将调用`_createTarget()`方法。`_createTarget()`方法将浏览手风琴部分，将它们包装在`div`元素中，并创建一个`draggable()`小部件。这就是我们能够从第一个手风琴拖动部分的方法。

如果指定了`accept`选项，将调用`_createAccept()`方法。这遵循将每个手风琴标题与其内容包装在`div`元素中的相同模式。但在这里，我们使整个手风琴小部件`sortable()`。

这可能看起来反直觉。为什么我们要使希望接受新部分的第二个手风琴可排序？使用 droppable 不是更合理吗？我们可以选择这条路线，但这将涉及大量使用`connectToSortable`选项的工作。这是在`_createTarget()`中指定的`draggable`选项，我们在其中说我们想把这些可拖动的项放到一个可排序的小部件中。在这个例子中，可排序的是第二个手风琴。

这解决了关于相对于其他部分在哪里放置手风琴部分的问题（可排序小部件知道如何处理）。然而，在这种方法中的一个有趣的约束是，我们必须克隆拖动的项目。也就是说，最终被放置到新手风琴中的部分只是一个克隆，而不是原件。因此，我们必须在放置时处理这个问题。

在`_createAccept()`中定义的排序选项的一部分，我们提供了一个`stop`回调。当我们将新的手风琴部分放入手风琴时，将触发这个回调函数。实际上，这对于任何排序活动都会触发，包括新的部分被放置。因此，我们必须小心检查我们实际上正在处理什么。我们通过检查项目是否附有`draggable`类来做到这一点，如果是，我们可以假设我们正在处理一个新的手风琴部分。

请记住，这个新添加的折叠菜单部分只是原始部分的克隆，因此在我们开始将其插入折叠菜单之前，需要发生一些有趣的事情。首先，这个新部分具有与原始部分相同的 ID。最终，我们将从第一个折叠菜单中删除原始部分，因此我们存储了该 ID 以供以后使用。一旦我们获得了它，我们就可以摆脱被删除部分的 ID，以避免重复。

确保完成这一步之后，我们已经在适当的位置放置了新的 DOM 元素，但是折叠菜单部件对此一无所知。这就是我们重新加载标题的地方，包括新添加的标题。新的折叠菜单部分仍然不可用，因为它没有正确处理事件，所以，例如，展开新部分将不起作用。为了避免奇怪的行为，我们关闭所有事件处理程序并重新绑定它们。这样就将新的折叠菜单放在了新的上下文中，而事件则保持开启状态。

现在，我们在 `accept-accordion` 中有了一个新的部分。但是我们不能忘记原来的部分。它仍然需要被移除。回想一下，我们存储了原始部分的 DOM ID，现在我们可以安全地移除该部分并刷新折叠菜单以调整高度。


# 第二章：包括自动完成

在本章中，我们将涵盖:

+   用主题样式化默认输入

+   使用选择选项构建数据源

+   使用多个数据源

+   远程自动完成过滤

+   自定义数据和分类

+   将效果应用于下拉菜单

# 介绍

**自动完成**小部件的主要目的是增强标准 HTML 表单`input`元素的功能。用户不必每次输入字段的完整值，自动完成小部件会提供可能的值作为建议。例如，假设您正在添加一个新产品。产品字段可以是文本输入、选择输入等等。在这种情况下，一个人会使用系统中现有的产品作为自动完成小部件的来源。很有可能，输入产品的用户，或者其他用户，之前已经输入过该产品。通过自动完成，用户可以确保他们提供的是有效的输入。

# 用主题样式化默认输入

默认的自动完成实现不会改变输入元素的任何视觉效果。从功能上讲，我们不希望更改输入元素。我们只需要在用户开始输入时出现下拉组件。但让我们看看是否可以使用小部件框架和主题框架中的组件改变自动完成输入元素的虚拟外观。

## 准备工作

我们将使用以下标记作为我们的示例，一个简单的`label`元素和一个简单的`input`元素：

```js
<div>
    <label for="autocomplete">Items: </label>
    <input id="autocomplete"/>
</div>
```

## 如何做...

我们将使用以下代码使用主题框架中的 CSS 类来扩展自动完成小部件。我们正在引入一个关于焦点事件的微小行为调整。

```js
( function( $, undefined ) {

$.widget( "ab.autocomplete", $.ui.autocomplete, {

    inputClasses: "ui-widget ui-widget-content ui-corner-all",

    _create: function() {

        this._super( "_create" );
        this._focusable( this.element );
        this.element.addClass( this.inputClasses );

    },

    _destroy: function() {

        this._super( "_destroy" );
        this.element.removeClass( this.inputClasses );

    }

});

})( jQuery );

$( function() {

    var source = [
        'First Item',
        'Second Item',
        'Third Item',
        'Fourth Item'
    ];

    $( "#autocomplete" ).autocomplete( { source: source } );

});
```

完成我们自动完成`input`元素的样式要求的最后一件事是使用一些规则的新 CSS 样式表。样式表应该在定义输入标记的主 HTML 中包含。

```js
input.ui-autocomplete-input {
    padding: 2px;
}

input.ui-autocomplete-input:focus {
    outline: none;
}
```

这是我们新样式的自动完成小部件在没有焦点时的样子。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_02_01.jpg)

这是自动完成在有焦点时的样子，并且下拉菜单已展开。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_02_02.jpg)

## 它是如何工作的...

文档加载时，我们正在创建一个简单的自动完成使用`#autocomplete` 输入元素。

你会注意到的第一件事是`inputClasses`属性。这个字符串代表了我们想要应用到小部件的主题框架的三个类：`ui-widget`、`ui-widget-content` 和 `ui-corner-all`。`ui-widget`类除了处理字体外并没有太多作用，将这个类应用到主题化的元素是一个好的做法。 `ui-widget-content` 类为我们修复了输入的边框，而 `ui-corner-all` 类为我们应用了漂亮的圆角。我们将这个字符串定义为小部件的属性的原因是因为这些类在两个地方使用，这样易于维护。

我们在这里覆盖的`_create()`方法只是调用了自动完成的`_create()`方法的原始实现。一旦这完成，我们通过调用`_focusable()`使`input`元素可聚焦。这是小部件工厂定义的一个方便的实用方法，并且被所有小部件继承。它通过在元素聚焦时从主题框架中应用`ui-state-focus`CSS 类来处理使元素可聚焦。当元素失去焦点时，它也会移除类。也许，`_focusable()`最好的部分是小部件工厂机制将在小部件销毁时清理任何焦点事件处理程序。我们自定义的`_create()`实现的最后一个任务是将`inputClasses`的 CSS 类添加到输入元素中。

一如既往，当我们从自动完成小部件中借用完成后，我们需要确保清理干净。这意味着扩展`_delete()`以确保从输入元素中删除`inputClasses`属性。

我们使用的微小 CSS 规则有两个作用。第一个改变是给`input`元素添加一点填充——这纯粹是出于美观考虑，因为我们做的其他改变使得文本在输入框中显得有点紧凑。第二个改变是在焦点集中时删除围绕`input`元素的轮廓。这仅适用于某些浏览器，如 Chrome，在其中会自动应用轮廓。

### 注意

通常，不建议移除轮廓，因为这会影响可访问性。但是，我们的改动已经考虑到了焦点输入，所以这样做是可以的。

# 使用选择选项构建数据源

有时，将数组用作自动完成小部件的数据源并不是最佳选择。例如，如果我们的用户界面中已经有一个`select`元素，那么重用该元素中的选项来创建自动完成会是个明智的选择。否则，我们不仅需要设计一些新代码来构建数组数据源，还需要删除现有的`select`元素。

## 准备工作

让我们为这个例子编写一些基本的标记。通常，自动完成小部件期望一个`input`作为其元素。相反，我们将给它一个带有一些简单选项的`select`元素。

```js
<div>
    <label for="autocomplete">Items: </label>
    <select id="autocomplete">
        <option>First Item</option>
        <option>Second Item</option>
        <option>Third Item</option>
        <option>Fourth Item</option>
    </select>
</div>
```

## 操作步骤...

我们将扩展自动完成小部件的功能，使其知道如何处理`select`元素。之后，我们就能够使用自动完成小部件来定位我们的`select`元素了。

```js
( function( $, undefined ) {

$.widget( "ab.autocomplete", $.ui.autocomplete, {

    inputClasses: "ui-widget ui-widget-content ui-corner-all",

    _create: function() {

        if ( this.element.is( "select" ) ) {

            var self = this;
            this.original = this.element.hide();
            this.element = $( "<input/>" ).insertAfter( this.original );

            this.options.source = function( request, response ) {

                var filter = $.ui.autocomplete.filter,
                    options = self.original.find( "option" ),
                    result = options.map( function() {
                        return $( this ).val();
                    });

                response( filter( result, request.term ) );

            };

        }

        this._super( "_create" );

    },

    _destroy: function() {

        this._super( "_destroy" );
        this.element.remove();
        this.original.show();

    }

});

})( jQuery );

$( function() {
    $( "#autocomplete" ).autocomplete();
});
```

现在你应该看到的是一个看起来像是普通的自动完成——看不到`select`元素。此外，如果你尝试使用自动完成，你会发现呈现的选项与`select`元素的选项相同。

![操作步骤...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_02_03.jpg)

## 工作原理...

在这里，我们需要为 `select` 元素添加对自动完成小部件的支持；我们在自定义的 `_create()` 实现的开始时执行此操作。如果我们处理的是 `select` 元素，则我们要做的第一件事是隐藏它并将其引用存储在 `original` 属性中。记住，我们只对 `select` 元素通过其 `options` 提供的数据源感兴趣 - 我们不希望实际显示 `select`。相反，我们将 `select` 替换为一个 `input` 元素，因为这是用户键入的方式，而小部件则完成。

自动完成小部件的 `source` 选项是我们能够指定返回要使用的源数据的自定义函数的方式。在我们的例子中，我们提供了一个函数，该函数从每个选择 `option` 获取值。回想一下，`select` 元素先前存储在 `original` 属性中。我们在这里使用 jQuery `map()` 实用程序函数将 `select` 选项转换为自动完成可以使用的数组。`filter()` 函数被应用，并且 `response()` 函数被发送到下拉菜单。

当小部件被销毁时，我们希望恢复原始的 `select` 元素，因为这是我们替换的元素。在我们自定义的 `_delete()` 实现中，原始元素再次显示 - 这是在调用原始的 `_delete()` 方法执行常规清理任务后发生的。我们创建的 `input` 元素也在这里销毁。

# 使用多个数据源

有时，自动完成小部件不直接映射到一个数据源。以视频为例。想象一下用户需要选择一个视频，但是两个数据源是 DVD 和蓝光。如果我们要使用自动完成选择视频，我们需要一种方法来分配多个数据源。此外，该机制需要足够灵活，以支持添加更多数据源，特别是因为每隔一年就会诞生一种新的视频格式。

## 怎么做...

自动完成小部件的默认实现期望一个单一的数据源 - 一个数组或一个 API 端点字符串。我们将给小部件添加一个新的 `sources` 选项来允许这种行为。这就是我们将扩展自动完成并创建一个具有两个视频数据源的小部件实例 - 一个用于 DVD，一个用于蓝光光盘。

```js
( function( $, undefined ) {

$.widget( "ab.autocomplete", $.ui.autocomplete, {

    options: { 
        sources: []    
    },

    _create: function() {

        var sources = this.options.sources;

        if ( sources.length ) {

            this.options.source = function ( request, response ) {

                var merged = [],
                    filter = $.ui.autocomplete.filter;

                $.each( sources, function ( index, value ) {
                    $.merge( merged, value );
                });

                response( filter( merged, request.term ) );

            };

        }

        this._super( "_create" );

    },

    _destroy: function() {
        this._super( "_destroy" );
    }

});

})( jQuery );

$( function() {
    var s1 = [
            "DVD 1",
            "DVD 2",
            "DVD 3"
        ],
        s2 = [
            "Blu-ray 1",
            "Blu-ray 2",
            "Blu-ray 3"
        ];

    $( "#autocomplete" ).autocomplete({
        sources: [s1, s2]
    });
});
```

![怎么做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_02_04.jpg)

如您所见，如果您开始搜索视频 `1`，您将在下拉菜单中从每个数据源获得版本。

## 工作原理...

我们不是在将我们的两个数据源合并到传递给自动完成之前，而是扩展了小部件的功能来处理这项任务。特别是，我们添加了一个新的 `sources` 选项，该选项可以接受多个数组。在示例中，我们将 DVD 和蓝光源都传递给我们的小部件。

我们的定制版本的`_create()`通过检查`sources`选项的长度来看是否已经提供了多个数据源。如果有多个数据源，我们使用`merge()`jQuery 实用函数创建一个新数组，并对其应用`filter()`函数。这种方法的一个很好的特点是它不在乎有多少个数据源——我们以后可以传递更多数据源到我们的实现中。这些数据源的合并被封装在小部件后面。

# 远程自动完成过滤

自动完成过滤功能并不仅限于默认实现，它搜索数组数据源中的对象。我们可以指定一个自定义`source()`函数，该函数将仅检索用户正在寻找的数据。如果您希望在包含数千个项目的数据源上使用自动完成，这是理想的方法。否则，在浏览器上过滤要求会变得过于苛刻——下载大型数据集，然后对每次按键进行大型数组搜索。

## 如何做...

我们将使用 GitHub API 作为自动完成小部件的数据源。这是一个很好的例子，因为它太大了，无法在浏览器内存中使用。

```js
$( function() {
  $( "#autocomplete" ).autocomplete({
        minLength: 3,
        source: function( request, response ) {
            $.ajax({
                url: "https://api.github.com/legacy/repos/search/:" + request.term,
                dataType: "jsonp",
                success: function( resp ) {
                    var repositories = resp.data.repositories.splice( 0, 10 );
                    var items = $.map( repositories, function ( item ) {
                        return { 
                            label: item.name + " (" + 
                                      item.language + ")",
                            value: item.name
                        };
                    });
                    response( items );
                }
            });
        }
    });
});
```

现在，如果您在浏览器中查看结果小部件并开始输入，您将在下拉菜单中看到 Github 仓库数据。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_02_05.jpg)

## 它是如何工作的...

由于我们使用了一个大型数据源，我们告诉这个特定的自动完成小部件，只有在至少有三个字符时才应执行项目的搜索。这是使用`minLength`选项来实现的。否则，我们将要求服务器基于一个或两个字符进行查询，这不是我们想要的。

在我们的示例中，`source`选项指定了我们将要使用的数据源——Github API。我们传递给`source`的函数执行了一个对 Github API 的`$.ajax()`调用。我们使用`jsonp`作为格式，这意味着 API 的回调函数将被发送回来。我们还向 API 传递了一些查询数据。

一旦 API 响应了数据，我们的成功回调函数就会执行。然后,我们通过`$.map()`实用程序函数将这些数据传递，以便生成自动完成小部件可以理解的数组。我们的成功函数对数据进行简单的`$.map()`，将其转换为自动完成可以使用的对象数组。

## 还有更多内容...

我们可以通过在小部件中引入术语缓存来进一步减少网络通信开销。**术语缓存**，顾名思义，会在本地存储执行远程过滤操作的结果。这样，当用户不可避免地在他们的按键中执行完全相同的操作时，我们不会再次执行相同的任务，并发出远程 API 调用,因为我们已经在小部件中缓存了结果。

```js
( function( $, undefined ) {

$.widget( "ab.autocomplete", $.ui.autocomplete, {

    _cache: {},

    _search: function( value ) {

        var response = this._response(),
            cache = this._cache;

    this.pending++;
    this.element.addClass( "ui-autocomplete-loading" );
    this.cancelSearch = false;

        if ( value in cache ) {
            response( cache[value] );
        }
        else {
            this.source( { term: value }, response );
        }

    }

});

})( jQuery );

$( function() {
  $( "#autocomplete" ).autocomplete({
        minLength: 3,
        source: function( request, response ) {
            var self = this;
            $.ajax({
                url: "https://api.github.com/legacy/repos/search/:" + request.term,
                dataType: "jsonp",
                success: function( resp ) {
                    var repositories = resp.data.repositories.splice( 0, 10 );
                    var items = $.map( repositories, function ( item ) {
                        return { 
                            label: item.name + " (" + 
                                      item.language + ")",
                            value: item.name
                        };
                    });
                    self._cache[request.term] = items;
                    response( items );
                }
            });
        }
    });
});
```

您可以在前面的代码中看到我们所做的更改以支持缓存从 HTTP 请求返回的项目。现在我们正在扩展小部件以添加新的 `_cache` 属性。我们还扩展了 `_search()` 函数，该函数负责检查缓存值。如果找到一个，就使用缓存版本的数据调用渲染响应。`source()` 函数负责存储缓存结果，但这只是一个简单的一行代码。

# 自定义数据和类别

分离两个自动完成数据类别的一种方法可能是拥有两个不同的字段，每个字段都有自己的自动完成小部件。另一种方法是在小部件本身引入类别的概念。当下拉菜单出现为用户建议项目时，他们还将看到项目所属的类别。要在自动完成小部件中执行此操作，我们需要更改小部件如何理解源数据以及如何呈现菜单项。

## 如何做...

我们将扩展自动完成小部件，以改变菜单项的渲染方式。我们还需要考虑传递给小部件的数据作为源。

```js
( function( $, undefined ) {

$.widget( "ab.autocomplete", $.ui.autocomplete, {

    _renderMenu: function( ul, items ) {

        var that = this,
            currentCategory = "";

        items.sort(function( a, b ) {
            return a.cat > b.cat 
        });

        $.each( items, function( index, item ) {

            if ( item.cat != currentCategory ) {
                that._renderCategory( ul, item );
                currentCategory = item.cat;
            }

            that._renderItemData( ul, item );

        });

    },

    _renderCategory: function( ul, item ) {
        return $( "<li>" ).addClass( "ui-autocomplete-category" )
                          .html( item.cat )                          
                          .appendTo( ul );
    },

    _renderItem: function( ul, item ) {
        return $( "<li>" ).addClass( "ui-autocomplete-item" )
                          .append( $( "<a>" )
                          .append( $( "<span>" ).html( item.label ) )
                          .append( $( "<span>" ).html( item.desc ) ) )
                          .appendTo( ul );
    }

});

})( jQuery );

$( function() {

    var items = [
        {
            value: "First Item",
            label: "First Item",
            desc: "A description of the first item goes here",
            cat: "Completed"
        },
        {
            value: "Second Item",
            label: "Second Item",
            desc: "A description of the second item goes here",
            cat: "In Progress"
        },
        {
            value: "Third Item",
            label: "Third Item",
            desc: "A description of the third item goes here",
            cat: "Completed"
        }
    ];

    $( "#autocomplete" ).autocomplete( {source: items} );

});
```

我们差不多完成了。我们对菜单所做的更改不会神奇地起作用，我们需要应用一些样式。以下 CSS 代码应包含在页面中：

```js
.ui-autocomplete-category {
    font-weight: bold;
    padding: .2em .4em;
    margin: .8em 0 .2em;
    line-height: 1.5;
}

.ui-autocomplete-item > a > span {
    display: block;
}

.ui-autocomplete-item > a > span + span {
    font-size: .9em;
}
```

现在，如果您开始在自动完成中输入，您会注意到下拉菜单与我们所习惯的大不相同，因为它包含类别和描述信息。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_02_06.jpg)

## 如何工作...

此小部件扩展的目标是接受自定义源数据并在下拉菜单的显示中使用该数据。具体而言，我们正在处理的新数据是类别和描述。类别是一对多关系，因此我们传递给小部件的几个项目可能具有相同的类别字符串。我们的工作是弄清楚任何给定类别下的项目，并在下拉菜单中表示此结构。此外，项目的描述是一对一关系，因此此处需要的工作较少，但我们仍然希望在下拉菜单中包含描述。

我们覆盖的原始实现的第一种方法是 `_renderMenu()`。`_renderMenu()` 的工作是每次向用户提出建议时更改底层 HTML 结构。我们使用 `currentCategory` 跟踪当前类别。然后我们使用 `_renderItem()` 渲染每个项目。

`_renderCategory()` 函数将类别文本呈现为 `<li>`。它还添加了 `ui-autocomplete-category` 类。同样，我们的 `_renderItem()` 函数呈现项目文本，并在这里我们还使用 `desc` 属性。项目还具有 `ui-autocomplete-item` 类。

我们在用户界面中包含的新 CSS 样式是我们创建的新版本自动完成功能的必要组成部分。没有它们，描述将与项目标签具有相同的字体大小并显示在同一行上。同样，类别需要新添加的样式以突出显示为其他项目分组的类别，而不仅仅是另一个项目。

## 还有更多...

每当我们扩展自动完成小部件使用的数据时，我们都必须告诉小部件如何使用它。在这里，我们告诉自动完成如何在下拉菜单中显示新数据。或者，我们可以告诉小部件在用户实际上从未在下拉菜单中看到的一些数据字段上执行过滤。或者我们可以将两者结合起来。

这是我们在用户开始输入时如何同时使用类别和描述两个非标准字段进行过滤的方法。

```js
$.ui.autocomplete.filter = function( array, term ) {

    var matcher = new RegExp( $.ui.autocomplete.escapeRegex( term ), "i" );

    return $.grep( array, function( value ) {
        return matcher.test( value.cat ) || 
               matcher.test( value.desc ) ||
               matcher.test( value.label )
    });

};
```

在这里，我们正在用我们自己的实现替换自动完成使用的`filter()`函数。这两者很相似，我们只是将`RegExp.test()`调用适应于`desc`和`cat`字段。我们将这段代码放在自动完成的自定义小部件声明的下方。之所以在自定义规范之外执行这些操作，是因为`autocomplete.filter()`有点像一个静态方法。在其他方法中，我们是根据每个实例进行覆盖。

# 对下拉菜单应用效果

默认情况下，我们得到一个相当简单的下拉菜单的呈现，其中包含基于我们输入的内容的建议。菜单只是简单地显示，没有太多的麻烦。这样做是可以的，它可以可靠地完成工作。但另一方面，我们总是可以做一些事情来使界面看起来更加精致。它可能只是将您应用程序中的自动完成小部件更改为在转换为可见状态时使用一些微妙的效果。

## 准备工作

由于我们这里追求的实际上更多是小部件的视觉呈现方面，我们可能可以安全地使用小部件的任何现有实例。

## 如何操作...

让我们在自动完成小部件的默认实现基础上增加一些微妙的动画效果。

```js
( function( $, undefined ) {

$.widget( "ab.autocomplete", $.ui.autocomplete, {

    _suggest: function( items ) {

        this._resetMenu();
        this._renderMenu( this.menu.element, items );
        this.menu.refresh();

        this._resizeMenu();
        this._positionMenu();

    },

    _resetMenu: function() {

        this.menu.element
                 .empty()
                 .zIndex( this.element.zIndex() + 1 );

    },

    _positionMenu: function() {

        var pos = $.extend( { of: this.element }, this.options.position );
        this.menu.element.position( pos );

    },

    _resizeMenu: function() {

        var menu = this.menu,
            exclude = 0;
            target = Math.max(
                menu.element.width( "" ).outerWidth() + 1,
                this.element.outerWidth()
            ),
            excludeCSS = [
                'borderLeftWidth',
                'borderRightWidth',
                'paddingLeft',
                'paddingRight'
            ];

        if( menu.element.is( ":hidden" ) ) {
            menu.element.css( { display: "block", opacity: 0 } );
        }

        $.each( excludeCSS , function( index, item ) {
            exclude += parseFloat( menu.element.css( item ) );
        });

        if ( menu.element.css( "opacity" ) == 0 ) {
            menu.element.animate({
                width: target - exclude,
                opacity: 1
            }, 300);
        }
        else{
            menu.element.width( target - exclude );
        }

    },

    _close: function( event ) {

        var menu = this.menu;

        if ( menu.element.is( ":visible" ) ) {

            menu.element.fadeOut();
            menu.blur();
            this.isNewMenu = true;
            this._trigger( "close", event );

        }

    }

});

})( jQuery );

$(function() {
    var source = [
        "First Item",
        "Second Item",
        "Third Item",
        "Fourth Item"
    ];
    $( "#autocomplete" ).autocomplete({
        source: source,
    });
});
```

如果您开始在输入元素中使用此自动完成小部件，您会注意到下拉菜单会平滑地滑入视图，而不是突然弹出。此外，当不再需要菜单时，它会渐渐消失。

## 工作原理...

在这里扩展自动完成功能，以便我们可以注入我们自定义的动画功能。但是这一次，变化要复杂一些，我们不仅仅是用几行代码扩展`_create()`。在自动完成代码中有一些深藏的方法需要我们扩展。我们还在自动完成小部件中引入了一些我们自己的新方法。

我们要覆盖的第一个方法是`_suggest()`。当用户键入了最小长度的字符以执行搜索时，自动完成小部件会调用`_suggest()`方法。原始方法负责渲染和显示下拉菜单的各个操作。在我们的方法版本中，我们只是调用小部件的其他方法。`_suggest()`方法的工作是协调搜索发生时发生的所有操作。这里有两个逻辑步骤。首先，使用新内容渲染菜单。接下来，显示、调整大小和定位菜单。后者是动画发生的地方。

我们不会深入讨论`_resetMenu()`和`_positionMenu()`方法的细节，因为这些代码片段大部分是从原始实现中取出的。它们只是分别清空并定位菜单。

`_resizeMenu()`方法是菜单显示时实际动画发生的地方。这是一个较长的方法，因为我们必须执行一些计算以传递给`animate()`。`_resizeMenu()`的原始实现使用`outerWidth()` jQuery 函数来设置菜单的宽度。这是为了与`input`元素正确对齐。然而，我们想要动画改变`width`。因此，我们必须手动计算内部宽度。外部宽度值放在排除变量中。内部宽度为`目标 - 排除`。

在实际显示菜单之前，我们会检查菜单是否已经显示，并在动画显示之前进行检查。如果元素不可见，我们会更改`display` CSS 属性，但将`opacity`属性设置为`0`。我们这样做的原因是我们需要元素的框模型尺寸以便定位它。但是，我们仍未将动画效果应用于菜单。在这里，我们检查菜单的`opacity`属性是否为`0`。如果不是，则表示菜单已经显示，现在重新对其进行动画化是没有意义的。否则，我们执行宽度和不透明度动画。

最后，`_close()`方法替换了原始的自动完成`_close()`实现。代码几乎与原始代码相同，只是在关闭菜单时我们做了一个基本的`fadeOut()`，而不是简单地隐藏它。

### 注意

这个自动完成功能的扩展并没有实现关闭此行为的选项。这没关系，因为这个扩展只做一件事情——对下拉菜单应用效果。因此，要禁用这些效果，我们只需禁用扩展。小部件的扩展是在调用自身的函数内定义的。当脚本首次加载时，会调用该函数，并使用新的行为对小部件进行扩展。我们可以禁用调用自身的函数的行为部分。

```js
(function( $, undefined ) {
    // Code that extends a jQuery UI widget...
}); //( jQuery );
```


# 第三章：制作按钮

在本章中，我们将涵盖:

+   制作简单清单

+   控制按钮集内的间距

+   自动填充空间按钮

+   对组内按钮进行排序

+   使用按钮悬停状态的效果

+   按钮图标和隐藏文本

# 介绍

**按钮**小部件是装饰用户界面中的 HTML 按钮和链接元素的简便方法。通过对按钮小部件进行简单调用，我们能够使用 jQuery UI 中的主题框架装饰标准元素。此外，有两种类型的按钮。一种是单一的按钮概念，是更受欢迎的用例。但还有一个**按钮集**的概念——用于装饰典型 HTML 表单中的复选框和单选按钮的情况。

在本章中，我们将更仔细地查看按钮所包含的内容，通过示例涵盖一些使用场景。我们将从简单的用法开始，比如创建一个清单和排序按钮，到更高级的用法，比如应用效果和自动填充空间。沿途，你将了解到小部件框架如何支持开发人员在小部件不能完全满足他们需求时扩展按钮。

# 制作简单清单

在纯 HTML 中做清单非常简单，你真正需要的只是一些复选框和旁边的一些标签。然而，如果你使用诸如 jQuery UI 之类的小部件框架，我们可以轻松地增强该列表。按钮小部件知道在应用于`input`类型的`checkbox`元素时如何行为。因此，让我们从一个基本列表开始，看看我们如何将按钮小部件应用于`input`元素。我们还将看到我们是否可以通过一些状态和图标增强来进一步提高用户交互性。

## 准备工作

让我们从创建一个简单的 HTML `div` 开始来容纳我们的清单。在内部，每个项目由一个`input`元素表示，类型为`checkbox`，以及一个用于元素的`label`。

```js
<div>
    <input type="checkbox" id="first" />
    <label for="first">Item 1</label>
    <input type="checkbox" id="second" />
    <label for="second">Item 2</label>
    <input type="checkbox" id="third" />
    <label for="third">Item 3</label>
    <input type="checkbox" id="fourth" />
    <label for="fourth">Item 4</label>
</div>
```

有了这个标记，实际上我们已经拥有了一个可用的清单 UI，尽管不够可用。我们可以使用 jQuery UI 按钮小部件的切换功能将`label`和`checkbox`封装在一起作为清单项。

## 如何做...

我们将介绍以下 JavaScript 代码来收集我们的`checkbox`输入，并使用它们的`labels`来组装**切换按钮**小部件。

```js
$(function() {

    $( "input" ).button( { icons: { primary: "ui-icon-bullet" } } );

    $( "input" ).change( function( e ) {

        var button = $( this );

        if ( button.is( ":checked" ) ) {

            button.button( "option", {
                icons: { primary: "ui-icon-check" } 
            });

        }
        else {

            button.button( "option", {
                icons: { primary: "ui-icon-bullet" } 
            });

        }

    });

});
```

有了这个，你就有了一个切换按钮清单，完整的图标可辅助传达状态。当用户点击切换按钮时，它进入“开”状态，这通过背景颜色的变化和其他主题属性来表示。我们还添加了与按钮状态一起切换的图标。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_03_01.jpg)

## 工作原理...

我们的事件处理程序在 DOM 准备就绪时触发，只需要一行代码就可以将页面上的 `input` 元素转换为切换按钮。在按钮构造函数中，我们指定要使用的默认图标是主题框架中的 `ui-icon-bullet` 图标类。按钮小部件知道我们正在创建一个切换按钮，因为底层 HTML 元素。由于这些是复选框，所以当单击按钮时，小部件会更改其行为——在 `复选框` 的情况下，我们希望按钮看起来像切换打开和关闭一样。此外，按钮小部件根据 `for` 属性知道哪个 `label` 属于哪个按钮。例如，`for="first"` 的标签将分配给 `id="first"` 的按钮。

接下来，我们将 `change` 事件处理程序应用于所有按钮。此处理程序对于每个按钮都相同，因此我们可以一次绑定它们所有按钮。此处理程序的工作是更新按钮图标。我们不必更改按钮状态的任何其他内容，因为默认按钮实现将为我们完成。在我们的事件处理程序中，我们只需要检查 `复选框` 本身的状态。如果选中，则显示 `ui-icon-check` 图标。否则，我们显示 `ui-icon-bullet` 图标。

# 使用 buttonset 控制间距

jQuery UI 工具包为开发人员提供了一个用于处理按钮组的容器小部件，称为**buttonset**。您可以将 buttonset 用于诸如复选框组或单选按钮组之类的东西——形成一个协同集合的东西。

buttonset 的默认外观是统一整体的。也就是说，目标是将几个按钮形成一个看似单一的小部件。默认情况下，buttonset 小部件对于开发人员没有间距控制。默认情况下，集合中的按钮都紧靠在一起。这可能不是我们想要的，这取决于 buttonset 小部件在整个用户界面中的上下文。

## 准备就绪

为了更好地说明我们所面临的间距约束，让我们构建一个按钮集小部件，然后再尝试解决这个问题之前看一下结果。我们将使用以下一组单选按钮作为我们的标记：

```js
<div>
    <input type="radio" id="first" name="items" />
    <label for="first">Item 1</label>
    <input type="radio" id="second" name="items" />
    <label for="second">Item 2</label>
    <input type="radio" id="third" name="items" />
    <label for="third">Item 3</label>
    <input type="radio" id="fourth" name="items"/>
    <label for="fourth">Item 4</label>
</div>
```

我们将按如下方式创建 buttonset 小部件：

```js
$(function() {
    $( "div" ).buttonset();
});
```

这是我们的 buttonset 的外观。请注意，此小部件仍然具有单选按钮功能。这里选择了第三个项目，但如果我在小部件中点击其他位置，它将变为未选中状态。

![准备就绪](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_03_02.jpg)

## 如何做...

现在，buttonset 小部件的默认呈现方式没有任何问题。我们可能面临的唯一潜在挑战是，如果我们在应用程序的其他地方有一个间距主题——小部件的堆叠在一起的外观可能不适合从美学角度看。我们可以通过相对较少的努力通过使用选项来扩展小部件来解决此问题，该选项允许我们“爆破”按钮，使它们不再接触。

我们将通过扩展按钮集小部件并添加一个新选项来实现这种新的爆炸式`buttonset`功能，该选项将启用这种行为。HTML 与以前相同，但这是新的 JavaScript 代码。

```js
(function( $, undefined ) {

$.widget( "ab.buttonset", $.ui.buttonset, {

    options: {
        exploded: false
    },

    refresh: function() {

        this._super("refresh");

        if ( !this.options.exploded ) {
            return;
        }

        var buttons = this.buttons.map(function() {
            return $( this ).button( "widget" )[ 0 ];
        });

        this.element.addClass( "ui-buttonset-exploded" );

        buttons.removeClass( "ui-corner-left ui-corner-right" )
               .addClass( "ui-corner-all" );

    }

});

})( jQuery );

$(function() {
    $( "div" ).buttonset( { exploded: true } );
});
```

我们希望在页面中包括以下 CSS——通过新样式表的方式包含它是推荐的做法：

```js
.ui-buttonset-exploded .ui-button {
    margin: 1px;
}
```

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_03_03.jpg)

## 它是如何工作的...

我们对按钮集小部件的扩展添加了`exploded`选项，允许使用该小部件的程序员指定他们是否希望将各个按钮分开还是不分开。我们还在这里重写了`refresh()`方法，以便在`exploded`选项为`true`时修改显示。

为此，我们创建代表按钮集中所有单独按钮的 jQuery 对象。这里我们使用`map()`的原因是因为`checkbox`和`radio`按钮需要一个解决方法。`ui-buttonset-exploded`类添加了我们在按钮之间寻找的`margin`，它将它们向外扩展。接下来，我们移除任何按钮的`ui-corner-left`和`ui-corner-right`类，并将`ui-corner-all`类添加到每个按钮上，使它们各自具有独立的边框。

# 自动填充空间的按钮

任何给定按钮小部件的宽度由其中的内容控制。这相当于主要或次要图标，或二者都没有，再加上文本。按钮本身的实际呈现宽度没有具体规定，而是由浏览器确定。当然，这是任何小部件的令人满意的特性——依赖浏览器计算尺寸。这种方法在需要考虑界面中有很多小部件，以及需要考虑有很多浏览器分辨率配置的情况下，很好地实现了比例缩放。

然而，有一些情况下，浏览器自动设置的宽度并不理想。想象一下在同一上下文中的几个按钮，也许是一个`div`元素。很可能，这些按钮不会呈现为具有相同宽度，而这实际上是一种期望的属性。仅仅因为组中有一个按钮具有稍多或稍少的文本，并不意味着我们不希望它们共享一致的宽度。

## 做好准备

这里的目标是将按钮组中最宽的按钮视为目标宽度。当添加新按钮时，按钮组的同级按钮会收到通知，如果它是最宽的话，可能会创建一个新的目标宽度。让我们通过查看默认按钮功能以及它在宽度方面的含义来更详细地说明问题。

以下是我们将使用来创建按钮小部件的 HTML。

```js
<div>
    <button style="display: block;">Button 1</button>
    <button style="display: block;">Button 2</button>
    <button style="display: block;">Button with longer text</button>
</div>
```

我们明确将每个按钮标记为块级元素，这样我们就可以轻松地对比宽度。同时请注意，按钮都是同级的。

以下 JavaScript 将每个按钮元素转换为按钮小部件。

```js
$(function() {
    $( "button" ).button();
});
```

您可以看到，前两个按钮的长度相同，而最后一个按钮使用更多文本且最宽。

![准备就绪](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_03_04.jpg)

## 如何做...

现在让我们通过一些新行为扩展按钮小部件，允许开发人员在组内同步每个按钮的宽度。扩展按钮小部件的修改后的 JavaScript 代码如下：

```js
(function( $, undefined ) {

$.widget( "ab.button", $.ui.button, {

    options: {
        matchWidth: false
    },

    _create: function() {

        this._super( "create" );

        if ( !this.options.matchWidth ) {
            return;
        }

        this.element.siblings( ":" + this.widgetFullName )
                    .addBack()
                    .button( "refresh" );

    },

    refresh: function() {

        this._super( "refresh" );

        if ( !this.options.matchWidth ) {
            return;
        }

        var widths = this.element
                         .siblings( ":" + this.widgetFullName )
                         .addBack()
                         .children( ".ui-button-text" )
                         .map(function() {
                            return $( this ).width();
                         }),
            maxWidth = Math.max.apply( Math, widths ),
            buttonText = this.element.children( ".ui-button-text" );

        if ( buttonText.width() < maxWidth ) {
            buttonText.width( maxWidth );
        }

    }

});

})( jQuery );

$(function() {
    $( "button" ).button( { matchWidth: true } );
});
```

在这里，您可以看到按钮彼此通信，以确定组内每个同级元素的正确宽度。换句话说，前两个按钮由于添加到组中的最后一个按钮而改变宽度。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_03_05.jpg)

## 工作原理...

我们刚刚添加的按钮小部件的扩展创建了一个新的 `matchWidth` 选项，如果为 `true`，将会根据需要将此按钮的宽度更改为该组中最宽的按钮的宽度。

我们的 `_create()` 方法的扩展调用了默认的 `_create()` 按钮实现，然后我们告诉所有的同级元素去 `refresh()`。我们通过使用 `addBack()` 将此按钮包含在同级元素列表中——原因是，如果已经有人比我们更大，我们可能必须调整自己的宽度。或者，如果我们现在是最宽的同级元素，我们必须通知每个人，以便他们可以调整自己的宽度。

`refresh()` 方法调用基本的 `refresh()` 实现，然后确定是否应更新此按钮的宽度。第一步是为组中的所有同级元素（包括自己）生成一个宽度数组。有了宽度数组，我们可以将其传递给 `Math.max()` 来获取最大宽度。如果此按钮的当前宽度小于组中最宽的按钮的宽度，则调整为新宽度。

请注意，我们实际上并没有收集或更改按钮元素本身的宽度，而是 `span` 元素内部。这个 `span` 具有 `ui-button-text` 类，并且是我们感兴趣的可变宽度元素。如果我们采取了简单地测量按钮宽度的方法，我们可能会遇到一些混乱的边距问题，使我们处于比起始状态更糟糕的状态。

## 还有更多...

在前面的示例中，您会注意到调整大小的按钮文本保持居中。如果愿意的话，我们可以在更改按钮宽度时引入一些小的 CSS 调整，以保持按钮文本对齐。

```js
(function( $, undefined ) {

$.widget( "ab.button", $.ui.button, {

    options: {
        matchWidth: false
    },

    _create: function() {

        this._super( "create" );

        if ( !this.options.matchWidth ) {
            return;
        }

        this.element.siblings( ":" + this.widgetFullName )
                    .addBack()
                    .button( "refresh" );

    },

    _destroy: function() {
        this._super();
        this.element.css( "text-align", "" );
    },

    refresh: function() {

        this._super( "refresh" );

        if ( !this.options.matchWidth ) {
            return;
        }

        var widths = this.element
                         .siblings( ":" + this.widgetFullName )
                         .addBack()
                         .children( ".ui-button-text" )
                         .map(function() {
                            return $( this ).width();
                         }),
            maxWidth = Math.max.apply( Math, widths ),
            buttonText = this.element.children( ".ui-button-text" );

        if ( buttonText.width() < maxWidth ) {
            buttonText.width( maxWidth );
            this.element.css( "text-align", "left" );
        }

    }

});

})( jQuery );

$(function() {
    $( "button" ).button( { matchWidth: true } );
});
```

在 `_refresh()` 方法中，请注意我们现在指定了 `text-align` CSS 属性为 `left`。此外，我们必须添加一个新的 `_destroy()` 方法，在销毁按钮时清除该属性。最终结果与我们之前的示例相同，只是现在按钮文本是对齐的。

![还有更多...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_03_06.jpg)

# 对组内排序的按钮

我们可以使用 `sortable()` 交互小部件为用户提供一些灵活性。为什么不让用户移动按钮呢？尤其是考虑到它所需的代码量很少。

## 准备就绪

我们将使用列表来组织我们的按钮，如下所示：

```js
<ul>
    <li><a href="#">Button 1</a></li>
    <li><a href="#">Button 2</a></li>
    <li><a href="#">Button 3</a></li>
</ul>
```

我们将使用以下 CSS 来修复列表布局，以更好地显示按钮小部件。

```js
ul {
    list-style-type: none;
    padding: 0;
}

li {
    margin: 4px;
}
```

## 如何操作...

使此功能生效的 JavaScript 代码实际上非常小——我们创建按钮，然后应用可排序的交互小部件。

```js
$(function() {
    $( "a" ).button();
    $( "ul" ).sortable({
        opacity: 0.6
    });
});
```

到目前为止，我们能够拖放按钮——但只能在指定的容器元素内，此处为`ul`。

![如何操作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_03_07.jpg)

## 工作原理...

在这个示例中，一旦文档准备就绪，我们首先要做的事情是创建按钮小部件。我们使用锚点作为底层元素，它与`button`元素一样有效。您还会注意到，我们将按钮小部件结构化在无序列表中显示在页面上。页面添加的样式只是移除了列表的缩进和项目符号。但是我们的目标是`ul`元素，用于可排序的交互。默认情况下，可排序小部件查找所有子元素并将它们作为可排序项目，在我们的情况下，这些是`li`元素。示例中指定的`opacity`选项告诉`sortable`改变正在拖动的元素的视觉不透明度。

# 使用按钮悬停状态的效果

按钮小部件利用了 jQuery UI 主题框架中找到的各种状态。例如，当用户悬停在按钮小部件上时，此事件会触发按钮小部件内的处理程序，将`ui-state-hover`类应用于元素，从而更改其外观。同样，当鼠标离开小部件时，另一个处理程序会移除该类。

按钮小部件的默认功能很好用——它只是使用`addClass()`和`removeClass()` jQuery 函数来应用悬停类。当用户四处移动并考虑下一步要做什么时，鼠标可能会在按钮小部件上移进移出；这就是我们通过提供一些微妙的效果来调整体验的地方。

## 准备工作

在这个示例中，我们将创建三个简单的按钮元素，它们将作为按钮小部件。这样，我们就可以尝试将鼠标指针移动到几个按钮上。

```js
<div>
    <button>Button 1</button>
    <button>Button 2</button>
    <button>Button 3</button>
</div>
```

## 如何操作...

让我们扩展默认按钮小部件的功能，包括一个名为`animateHover`的新选项，当设置为`true`时，会对`ui-state-hover`类的添加和移除进行动画处理。

```js
(function( $, undefined ) {

$.widget( "ab.button", $.ui.button, {

    options: {
        animateHover: false 
    },

    _create: function() {

        this._super( "create" );

        if ( !this.options.animateHover ) {
            return;
        }

        this._off( this.element, "mouseenter mouseleave" );

        this._on({
            mouseenter: "_mouseenter",
            mouseleave: "_mouseleave"
        });

    },

    _mouseenter: function( e ) { 
        this.element.stop( true, true )
                    .addClass( "ui-state-hover", 200 );
    },

    _mouseleave: function( e ) {
        this.element.stop( true, true )
                    .removeClass( "ui-state-hover", 100 );
    }

});

})( jQuery );

$(function() {
    $( "button" ).button( { animateHover: true } );
});
```

## 工作原理...

我们为按钮小部件添加了一个名为`animateHover`的新选项。当设置为`true`时，按钮将对`ui-state-hover`类的添加或移除进行动画处理。这是通过覆盖首次实例化按钮小部件时调用的`_create()`方法来完成的。在这里，我们检查`animateHover`选项是否为`false`，然后在调用执行常规按钮初始化任务的原始`_create()`方法之后执行。

如果设置了该选项，首先要做的工作是解绑按钮上原始的`mouseenter`和`mouseleave`事件处理程序。这些处理程序默认情况下只是添加或删除悬停类。这正是我们想要改变的，因此一旦删除了原始处理程序，我们就可以自由地使用`_on()`注册我们自己的处理程序。这是我们使用`stop()`、`addClass()`和`removeClass()`函数的地方。如果在类名后给出了持续时间，jQuery UI 效果扩展将应用于`addClass()`和`removeClass()`函数，我们在这里已经这样做了。我们希望添加`ui-state-hover`类需要`200`毫秒，并且删除类需要`100`毫秒，因为用户更容易注意到初始悬停。最后，`stop( true, true )`调用是 jQuery 中确保动画不重叠并导致用户视角中出现抖动行为的常用技巧。

# 按钮图标和隐藏文本

开发人员可以选择仅呈现图标按钮。通过告诉按钮我们不希望显示文本，就可以实现这一点。这很容易做到，并且适用于许多用例——通常情况下，根据上下文，一个图标就足以解释它的操作。此外，我们随时可以通过简单的选项更改重新添加按钮标签。这是因为按钮文本是底层 HTML 组件的一部分。然而，对于图标，情况就变得有点棘手了，因为它们是按钮上的装饰。我们不能像处理文本那样打开和关闭图标——整个图标规范需要再次应用。

那么，一个值得考虑的方法是在按钮构造函数中指定图标，但在关闭后记住它们。这样，图标就会表现得好像它们是原始 DOM 元素的一部分。

## 准备工作

我们将从创建三个图标按钮所需的结构开始。我们还将介绍两个链接，用于改变每个按钮的状态。

```js
<div>
    <button class="play">Play</button>
    <button class="pause">Pause</button>
    <button class="stop">Stop</button>
</div>

<div>
    <br/>
    <a href="#" class="no-icons">no icons</a>
    <br/>
    <a href="#" class="icons">icons</a>
</div>
```

## 如何做...

通过添加一个新的`icon`选项，我们将为按钮小部件提供图标切换功能。记住，我们的想法是提供与`text`选项相同的功能，只是用于图标。

```js
(function( $, undefined ) {

$.widget( "ab.button", $.ui.button, {

    options: {
        icon: true
    },

    _hiddenIcons: {},

    _setOption: function( key, value ) {

        if ( key != "icon" ) {
            this._superApply( arguments );
            return;
        }

        if ( !value && !$.isEmptyObject( this.options.icons ) ) {
            this._hiddenIcons = this.options.icons;
            this._super( "text", true );
            this._super( "icons", {} );
        }
        else if ( value && $.isEmptyObject( this.options.icons ) ) {
            this._super( "icons", this._hiddenIcons );
        }

    },

    _create: function() {

        if ( !this.options.icon ) {
            this._hiddenIcons = this.options.icons;
            this.options.icons = {};
        }

        this._superApply( arguments );

    }

});

})( jQuery );

$(function() {

    $( "a.no-icons" ).click( function( e ) {
        e.preventDefault();
        $( "button" ).button( "option", "icon", false );
    });

    $( "a.icons" ).click( function( e ) {
        e.preventDefault();
        $( "button" ).button( "option", "icon", true );
    });

    $( "button" ).button( {text: false} );

    $( ".play" ).button( "option", {
        icons: { primary: "ui-icon-play" }
    });

    $( ".pause" ).button( "option", {
        icons: { primary: "ui-icon-pause" }
    });

    $( ".stop" ).button( "option", {
        icons: { primary: "ui-icon-stop" } 
    });

});
```

## 工作原理...

最初，尽管按钮文本仍然作为底层 DOM 元素的一部分存在，但三个按钮都已禁用`text`。接下来，我们为三个按钮设置`icon`选项。当页面首次加载时，你应该只看到图标按钮。

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_03_08.jpg)

页面上的两个链接，**no icons**和**icons**分别删除和添加按钮小部件的图标。每个链接的功能回调是通过为我们添加到`button`小部件的自定义`icon`选项设置一个值来完成的。点击**no icons**链接将导致删除按钮图标，并用它们的文本替换。

![工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_03_09.jpg)

通过点击**图标**链接，我们重新启用了先前为每个按钮设置的`icons`选项。这是通过更改我们的自定义`icon`按钮完成的，因此现在如果我们点击该链接，我们可以看到我们的图标已恢复，而无需指定使用了哪些图标。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_03_10.jpg)

您会注意到，通过将`icon`值设置为`true`，我们没有隐藏文本，这在按钮的原始状态下是这样的。我们仍然可以通过手动将`text`设置为`false`来做到这一点，但这应该是一个手动过程，而不是我们的按钮扩展修改。

我们的扩展添加了一个新的`_hiddenIcons`属性，用于在`icon`选项设置为`false`时存储`icons`选项的值。我们的大部分工作都在`_setOption()`中进行，这是在开发人员想要在小部件上设置选项时调用的。我们只关心我们添加的新`icon`选项。首先，我们检查是否禁用了图标，如果是，则将`icons`选项的副本存储在`_hiddenIcons`属性中，以便以后可以恢复它。我们还将`text`选项设置为`true`，这样如果隐藏了文本，文本就会显示。同时隐藏按钮图标和文本是一个坏主意。最后，我们通过取消设置`icons`选项来实际隐藏图标。

另一方面，如果我们启用了图标，我们需要在`_hiddenIcons`属性中查找它们，并将它们设置为`icons`按钮选项。我们在这里覆盖的`_create()`实现只是将图标设置存储在`_hiddenIcons`中，并在首次创建小部件时隐藏它们（如果已指定）。
