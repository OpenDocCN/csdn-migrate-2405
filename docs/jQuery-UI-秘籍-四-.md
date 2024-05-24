# jQuery UI 秘籍（四）

> 原文：[`zh.annas-archive.org/md5/6053054F727DA7F93DC0A95B33107695`](https://zh.annas-archive.org/md5/6053054F727DA7F93DC0A95B33107695)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：使用工具提示

在本章中，我们将涵盖:

+   改变工具提示状态

+   在工具提示中使用自定义标记

+   显示鼠标移动

+   对工具提示显示应用效果

+   选定文本的工具提示

# 介绍

在本章中，我们将探讨用于向用户提供上下文信息的**工具提示**小部件的各个方面。工具提示小部件与现有代码配合得很好，因为默认情况下，它使用标准的 HTML 属性来设置工具提示的文本。此外，只需一行代码就可以为整个用户界面创建工具提示实例，非常容易。

超越简单用例，我们将研究我们可以传递到小部件中的不同类型的内容，以及如何动态生成内容。我们还将探讨工具提示如何作为工具来辅助开发过程，以及开发人员如何操纵可用的效果来显示和隐藏小部件。

# 改变工具提示状态

工具提示小部件的视觉显示有一个默认状态。也就是说，默认情况下，该小部件经过精心设计，使用了主题框架中的元素。然而，我们可能会根据应用程序中某些资源的状态而进行更改。例如，由于权限更改而对用户新的按钮可能希望工具提示状态在页面上与其他工具提示有视觉上的差异。同样，如果存在损坏的资源，并且用户将鼠标悬停在其组件上，则显示的工具提示应处于错误状态。当然，当更改工具提示的状态时，我们应该记住状态应该与实际工具提示的上下文和语气相匹配。例如，不要在读取“一切都准备就绪！”的工具提示上放置错误状态。让我们看看自定义工具提示的一个快速而简单的入口点。我们将使用一个标准的工具提示选项来传递状态 CSS 类。

## 如何做...

我们将使用以下 HTML 为我们的工具提示小部件。这里有三个按钮，每个按钮都有自己的状态和工具提示实例。

```js
<div class="button-container">
    <button class="tt-default" title="I'm using the default tooltip state">Default</button>
</div>
<div class="button-container">
    <button class="tt-highlight" title="I'm using the highlight tooltip state">Highlight</button>
</div>
<div class="button-container">
    <button class="tt-error" title="I'm using the error tooltip state">Error</button>
</div>
```

接下来，我们将使用以下 JavaScript 为其各自的按钮创建工具提示小部件:

```js
$(function() {

    $( "button" ).tooltip();

    $( "button.tt-highlight" ).tooltip( "option", { 
        tooltipClass: "ui-state-highlight" 
    });

    $( "button.tt-error" ).tooltip( "option", {
        tooltipClass: "ui-state-error"
    });

});
```

在浏览器中悬停在每个按钮上会显示默认状态、高亮状态和错误状态，如下图所示:

+   默认状态:![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_11_01.jpg)

+   高亮状态:![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_11_02.jpg)

+   错误状态:![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_11_03.jpg)

## 工作原理...

对于这个特定的例子，我们使用`tooltipClass`选项将主题框架中的状态 CSS 类传递给小部件。首先，我们简单地将页面上的每个按钮都设置为提示小部件。调用提示构造函数后，我们有三个使用默认状态的提示实例。接下来，我们找到带有`tt-highlight`类的按钮，并将`tooltipClass`选项的值设为`ui-state-highlight`。最后，我们找到带有`tt-error`类的按钮，并使用`tooltipClass`选项将该提示小部件分配给`ui-state-error`类。

## 还有更多...

我们之前使用的方法有一些缺点。首先，用户无法知道有什么问题，直到他们将鼠标移到元素上并看到提示处于错误状态。在更现实的情况下，如果按钮有什么问题，它可能会自身应用错误状态。因此，为了应用错误状态，我们不得不发明自己的类名，并在创建提示时确定使用哪个类。

一个更健壮的解决方案将围绕在元素上使用框架的实际状态而不是发明我们自己的状态。此外，提示小部件应该足够智能，以根据应用的元素的状态更改其类。换句话说，如果按钮应用了`ui-state-error`类，则应该将此类用作`tooltipClass`选项。让我们为提示小部件添加一个`inheritState`选项，以打开此行为。

这是修改后的 HTML 源代码：

```js
<div class="button-container">
    <button title="I'm using the default tooltip state">Default</button>
</div>
<div class="button-container">
    <button class="ui-state-highlight" title="I'm using the highlight tooltip state">Highlight</button>
</div>
<div class="button-container">
    <button class="ui-state-error" title="I'm using the error tooltip state">Error</button>
</div>
```

下面是包含新选项的提示小部件扩展的定义：

```js
(function( $, undefined ) {

$.widget( "ab.tooltip", $.ui.tooltip, {

    options: {
        inheritState: false
    },

    _create: function() {

        var self = this,
            options = this.options,
            states = [
                "ui-state-highlight",
                "ui-state-error"
            ];

        if ( !options.inheritState || options.tooltipClass ) {
            return this._super();
        }

        $.each( states, function( i, v ) {

            if ( self.element.hasClass( v ) ) {
                self.options.tooltipClass = v;
            }

        });

        this._super();

    }

});

})( jQuery );

$(function() {

    $( "button" ).tooltip({
        inheritState: true
    });

});
```

这个版本的代码应该与第一个版本的行为完全相同。当然，区别在于按钮本身具有可见状态，我们希望提示小部件能够捕捉到这一点。我们通过将`inheritState`选项设置为`true`来告诉它这样做。

![还有更多...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_11_04.jpg)

我们的新选项`inheritState`被添加到提示小部件的默认`options`对象中，该对象由提示小部件的原始实现设置。在`_create()`方法中，小部件构造函数中，我们检查`inheritState`选项是否为`true`，或者`tooltipClass`选项是否已设置。在任何一种情况下，我们都返回，调用原始实现。否则，我们检查元素是否具有`states`数组中的任何状态，如果是，则将该类设置为`tooltipClass`。

# 在提示中使用自定义标记

我们不限于使用`title`属性来提供基本文本字符串以供工具提示内容使用。有时，工具提示部件的内容需要格式化。例如，标题部分的字体样式将与主文本部分不同。工具提示部件允许开发人员通过`content`选项传递自定义内容。这可以是原始字符串，也可以是返回我们想要显示的内容的函数。让我们看看如何在您的应用程序中使用此选项。

## 操作步骤...

我们将创建两个`button`元素；每个都有一个`title`属性，其中的文本将用于工具提示。我们还将添加按钮的名称作为工具提示标题。

```js
<div class="button-container">
    <button title="Logs the user in by establishing a new session.">Login</button>
</div>
<div class="button-container">
    <button title="Deactivates the session, and logs the user out.">Logout</button>
</div>
```

接下来，让我们创建格式化我们的工具提示的基本 CSS 样式。

```js
.ui-tooltip-title {
    font-weight: bold;
    font-size: 1.1em;
    margin-bottom: 5px;
}
```

最后，我们将使用自定义内容函数创建工具提示部件来格式化工具提示内容。

```js
$(function() {

    $( "button" ).tooltip({
        content: function() {

            var $content = $( "<div/>" );

            $( "<div/>" ).text( $( this ).text() )
                         .addClass( "ui-tooltip-title" )
                         .appendTo( $content );

            $( "<span/>" ).text( $( this ).attr( "title" ) )
                          .appendTo( $content );

            return $content;

        }

    });

});
```

当我们悬停在其中一个`button`元素上时，工具提示应该看起来像以下屏幕截图一样。注意格式化的标题部分。

![操作步骤...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_11_05.jpg)

## 工作原理...

我们向每个工具提示部件传递的`content`函数将内容包装成一个`div`元素，存储在`$content`变量中。目的是将标题和主文本元素存储在此`div`中，这样我们就可以简单地从函数中返回`$content`变量。标题`div`使用按钮文本或其名称。这个`div`得到了我们之前定义的`ui-tooltip-title`类，它只是修改了字体，并在元素底部添加了一些空间。接下来，我们添加了主内容`span`元素，它只是使用元素的`title`属性。

## 还有更多...

我们刚刚检查过的修改工具提示的方法是自由形式的——函数可以返回几乎任何它想要的东西。让我们看看修改工具提示内容的更结构化的方法。我们将修改工具提示部件，使其接受特定的内容部分选项。为了演示这一点，我们将利用**Rotten Tomatoes API**。我们唯一需要的 HTML 是一个简单的`div`元素，看起来像`<div class="titles"></div>`。现在让我们定义标题的 CSS 样式，我们将要列出的标题，以及特定的工具提示内容部分。

```js
.titles { 
    margin: 20px;
}

.titles img {
    padding: 10px;
}

.ui-tooltip-header {
    font-weight: bold;
    font-size: 1.4em;
}

.ui-tooltip-body {
    margin: 7px 0 7px 0;
    font-size: 1.2em;
}

.ui-tooltip-footer {
    font-weight: bold;
    border-top: solid 1px;
    padding-top: 7px;
}
```

这是自定义的工具提示部件声明，它添加了新的内容选项。当文档加载时，我们调用 Rotten Tomatoes API，并在我们的容器`div`中显示五张图片。每张图片也是一个工具提示，它使用了我们已添加到部件的新特定内容选项。

```js
(function( $, undefined ) {

$.widget( "ab.tooltip", $.ui.tooltip, {

    options: {
        header: null,
        body: null,
        footer: null
    },

    _create: function() {

        this._super();

        var header = this.options.header,
            body = this.options.body,
            footer = this.options.footer;

        if ( !header && !body && !footer ) {
            return;
        }

        this.options.content = $.proxy( this, "_content" );

    },

    _content: function() {

        var header = this.options.header,
            body = this.options.body,
            footer = this.options.footer,
            $content = $( "<div/>" );

        if ( header ) {

            $( "<div/>" ).text( header )
                         .addClass( "ui-tooltip-header" )
                         .appendTo( $content );

        }

        if ( body ) {

            $( "<div/>" ).text( body )
                         .addClass( "ui-tooltip-body" )
                         .appendTo( $content );

        }

        if ( footer ) {

            $( "<div/>" ).text( footer )
                         .addClass( "ui-tooltip-footer" )
                         .appendTo( $content );

        }

        return $content;

    }

});

})( jQuery );

$(function() {

    var apikey = "2vnk...",  // Your Rotten Tomatoes API key goes here
        apibase = "http://api.rottentomatoes.com/api/public/v1.0";

    $.ajax({
        url: apibase + "/lists/movies/in_theaters.json",
        dataType: "jsonp",
        data: {
            apikey: apikey,
            page_limit: "5",
        },
        success: function( data ) {

            $.each( data.movies, function( i, v ) {

                var $logo = $( "<img/>" );

                $logo.attr( "src", v.posters.thumbnail )
                     .appendTo( ".titles" );

                $logo.tooltip({
                    header: v.title,
                    body: v.synopsis.substring( 0, 150 ) + "...",
                    footer: v.year + " (" + v.mpaa_rating + ")",
                    items: "img"
                });

            });

        }

    });

});
```

在浏览器中查看此页面应该会用五张图片填充标题`div`，当您将鼠标悬停在每个图片上时，您应该会看到我们的自定义工具提示内容。

![还有更多...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_11_06.jpg)

让我们首先查看当文档加载完成时我们正在向 Rotten Tomatoes API 发出的 API 调用。我们要获取的仅是正在上映的目录中的前五部电影。然后，我们创建一个 `img` 元素并将 `src` 属性设置为相应电影的缩略图。这就是你在示例中看到的图片是如何呈现的。我们还对每个图像调用工具提示构造函数，并向其传递我们定义的新选项。具体来说，这些是工具提示内容的部分，`header`、`body` 和 `footer`。请注意，我们必须告诉工具提示这是一个 `img` 元素，它不会在通常的位置找到工具提示内容 - 这是使用 `items` 选项完成的。

现在看看我们在工具提示小部件中实现的自定义内容，我们可以看到选项是通过向 `options` 属性分配新选项来定义的 - 这些选项会合并到默认工具提示 `options` 对象中。接下来，我们有一个 `_create()` 方法的自定义实现，当工具提示被实例化时会调用该方法。这里的目标是检查是否已指定了三个内容部分之一，如果没有，则我们无事可做，简单地退出。 `_create()` 方法的原始版本是使用 `_super()` 调用的，因此在此时，小部件已经被创建。构造函数中的我们的最后一项工作是将 `content` 选项分配给生成工具提示内容的函数。在这种情况下，它是一个代理到 `_content()` 方法的函数。

`_content()` 方法将其返回的 HTML 包装在一个 `div` 元素中，这存储在 `$content` 变量中。然后，我们根据选项将指定的内容添加到 `div` 元素中。每个内容部分都是一个 `div` 元素，并且它们被赋予相应的 CSS 类来控制外观 - `ui-tooltip-header`、`ui-tooltip-body` 和 `ui-tooltip-footer`。

# 显示鼠标移动

在开发过程中，我们可以使用工具提示小部件作为辅助工具，但不一定要将其作为最终产品的一部分。例如，我们可以使用工具提示小部件来跟踪鼠标移动并显示 X 和 Y 坐标。这有助于我们在组装 UI 组件时诊断一些棘手的鼠标行为。我们将研究跟踪特定元素的鼠标坐标，但请记住，重要的是概念。我们可以使用此技术来显示任意数量的事件属性 - 当不再需要时，我们只需丢弃调用。

## 如何做到…

首先我们将创建所需的 CSS。这些简单地定位我们希望跟踪鼠标移动的 `div` 元素。

```js
.mouse-tracker {
    margin: 20px;
    background-image: none;
    padding: 3px;
}

.mouse-tracker p {
    font-size: 1.2em;
}

.mouse-tracker-page {
    width: 180px;
    height: 170px;
}

.mouse-tracker-relative {
    width: 150px;
    height: 140px;
}
```

接下来是 HTML 本身，两个我们正在设计中的 `div` 元素。我们希望我们的鼠标跟踪实用程序在用户将鼠标移动到这些元素上时显示出发生了什么。

```js
<div class="ui-widget-content mouse-tracker mouse-tracker-page">
    <p>Page mouse movement</p>
</div>
<div class="ui-widget-content ui-state-default mouse-tracker mouse-tracker-relative">
    <p>Element mouse movement</p>
</div>
```

最后但同样重要的是，我们将实现我们的跟踪器工具。这是一个名为跟踪器的小部件，它扩展了提示小部件。我们称其为其他内容，以免将其与我们可能在生产系统中使用的现有提示小部件混淆。

```js
(function( $, undefined ) {

$.widget( "ab.tracker", $.ui.tooltip, {

    options: {
        track: true,
        items: ".ui-tracker",
        relative: false
    },

    _create: function() {

        this.element.addClass( "ui-tracker" );

        this._super();

        this.options.content = $.proxy( this, "_content" );

    },

    _content: function() {

        var $content = $( "<div/>" ),
            relative = this.options.relative,
            xlabel = relative ? "Element X: " : "Page X: ",
            ylabel = relative ? "Element Y: " : "Page Y: ";

        $( "<div/>" ).append( $( "<strong/>" ).text( xlabel ) )
                     .append( $( "<span/>" ).attr( "id", "ui-tracker-x" ) )
                     .appendTo( $content );

        $( "<div/>" ).append( $( "<strong/>" ).text( ylabel ) )
                     .append( $( "<span/>" ).attr( "id", "ui-tracker-y" ) )
                     .appendTo( $content );

        return $content;

    },

    _mousemove: function( e ) {

        var $target = $( e.target ).closest( this.options.items ),
            offset,
            offsetLeft = 0
            offsetTop = 0;

        if ( this.options.relative ) {
            offset = $target.offset();
            offsetLeft = offset.left;
            offsetTop = offset.top;
        }

        $( "#ui-tracker-x" ).text( e.pageX - offsetLeft );
        $( "#ui-tracker-y" ).text( e.pageY - offsetTop );

    },

    open: function( e ) {

        this._super( e );

        var $target = $( e.target ).closest( this.options.items );

        this._on( $target, {
            mousemove: $.proxy( this, "_mousemove" )
        });

    }

});

})( jQuery );

$(function() {

    $( ".mouse-tracker-page" ).tracker();
    $( ".mouse-tracker-relative" ).tracker({
        relative: true
    });

});
```

在浏览器中查看这两个`div`元素，您应该会看到类似以下的内容：

![操作步骤...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_11_07.jpg)

## 工作原理...

我们刚刚定义的跟踪器小部件通过填充一些新的默认选项以及提供一个新选项来扩展提示小部件。`track`提示选项告诉小部件相对于鼠标移动定位自己。由于我们正在实现鼠标坐标跟踪器，将其默认打开是有道理的。我们希望更改的下一个提示选项值是`items`选项。这告诉提示哪些目标元素可以成为有效的提示，而在我们的情况下，我们希望它是赋予我们跟踪器小部件的类—`ui-tracker`。`relative`选项是我们要添加到小部件中的新内容。这告诉跟踪器，当为`true`时，将坐标显示为相对于问题元素，而不是相对于页面，默认情况下是相对于页面的。

接下来，我们要扩展提示小部件的`_create()`方法，这是构造函数。在调用构造函数的原始实现之前，我们要做的第一件事是将跟踪小部件类添加到元素中。这是必要的，以便元素被视为有效的跟踪器—参见`items`选项。一旦我们完成了`_super()`方法，我们就会将`content`选项分配给回调函数，这是对此小部件的`_callback()`方法的代理。`_callback()`方法只是返回我们想要显示在提示中的模板内容。这包括鼠标事件的 X 和 Y 坐标。根据`relative`选项，我们必须弄清楚标签是应该是一个页面，还是应该是一个元素。

我们重写`open()`方法来设置我们的`mousemove`事件处理。通常，这将在`_create()`方法中完成。但是当提示未打开时，没有必要跟踪鼠标移动，而且触发回调会浪费宝贵的 CPU 周期。我们使用`_on()`实用程序方法将代理处理程序绑定到此小部件的`_mousemove()`方法。`_mousemove()`方法负责更新提示的内容。具体来说，它设置由我们的`_content()`方法生成的`#ui-tracker-x`和`#ui-tracker-y`标签的文本值。X 和 Y 坐标的值将基于事件的`pageX`和`pageX`属性的值，或者与偏移值结合，具体取决于`relative`选项。

跟踪器小部件的实例化方式与提示小部件相同。当我们不再需要显示这些值时，例如，当我们准备好上线时，这些小部件调用将被删除。

# 对提示显示应用效果

工具提示小部件附带了控制元素显示和隐藏动作的选项。这些分别是`show`和`hide`选项，每个选项都接受指定动画选项的对象。由于`show`和`hide`选项控制小部件显示的不同方面，我们可以自由使用不同的设置，例如显示和隐藏操作的延迟。或者，我们可以彻底改变，对动画使用两种完全不同的效果。让我们探索工具提示小部件中可用的各种`show`和`hide`选项。

## 如何操作...

首先，让我们创建一些按钮元素，我们将用它们来显示工具提示。

```js
<div class="button-container">
    <button class="drop" title="I'm using the drop effect">Drop</button>
</div>
<div class="button-container">
    <button class="slide" title="I'm using the slide effect">Slide</button>
</div>
<div class="button-container">
    <button class="explode" title="I'm using the clip/explode effect">Explode</button>
</div>
```

接下来，我们将为每个按钮实例化一个工具提示小部件，传递我们自定义的`show`和`hide`动画选项。

```js
$(function() {

    $( "button" ).tooltip();

    $( "button.drop" ).tooltip( "option", {
        show: {
            effect: "drop",
            delay: 150,
            duration: 450,
            direction: "up",
        },
        hide: {
            effect: "drop",
            delay: 100,
            duration: 200,
            direction: "down"
        }
    });

    $( "button.slide" ).tooltip( "option", {
        show: {
            effect: "slide",
            delay: 250,
            duration: 350,
            direction: "left"
        },
        hide: {
            effect: "slide",
            delay: 150,
            duration: 350,
            direction: "right",
        }
    });

    $( "button.explode" ).tooltip( "option", {
        show: {
            effect: "clip",
            delay: 150,
            duration: 450
        },
        hide: {
            effect: "explode",
            delay: 200,
            duration: 1000
        }
    });

});
```

在您的网络浏览器中查看三个按钮，并将鼠标移到每个按钮上。您会注意到它们以独特的方式显示和隐藏工具提示。例如，这是最后一个工具提示，正在被隐藏时的中爆炸。

![如何操作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_11_08.jpg)

## 它是如何工作的...

有些效果接受其他效果不接受的选项，例如方向。`button.drop`工具提示小部件同时对显示和隐藏操作使用`drop`效果。然而，`show`指定了`direction`为`up`，而`hide`操作指定了`direction`为`down`。这意味着工具提示将以向上的方式进入页面，并以向下的方式退出页面。相同的概念也适用于`button.slide`小部件，其中我们使用`slide`效果。工具提示将从左侧滑入，并从右侧滑出。

`button.explode`工具提示使用两种不同的效果类型——`show`使用`clip`效果，而`hide`使用`explode`效果。一般来说，像这样混合效果是可以的，但通常需要一些时间进行尝试和错误，找到两种互补而不是看起来不合适的效果类。最后，我们将`delay`和`duration`选项应用于我们创建的工具提示的`show`和`hide`选项。`delay`选项推迟工具提示的实际显示，而`duration`控制动画的运行时间。

# 选定文本的工具提示

大多数应用程序使用用户首次遇到的术语。因此，提供类似词汇表的东西是有帮助的，这样他们可以查找新术语的含义。但是，在用户界面中放置这个词汇表的位置是一件大事。例如，如果我正在执行某项任务，我不想中断去查找某些内容。这就是工具提示的帮助之处——用户会得到某些内容的上下文解释。

默认情况下，工具提示在应用于页面上特定元素（例如按钮或进度条）时效果很好。但是对于一段文字呢？让我们看看如何允许用户选择一些文本，并使用工具提示小部件显示所选内容的上下文定义。

## 如何操作...

我们将设计一个新的词典小部件，基于提示小部件，用于处理文本。这个小部件将通过显示提示（如果找到）来处理文本选择。首先，这里是我们将使用的段落，取自前一节。

```js
<p>
    Most applications use terms that the user is encountering for the first 
    time.  And so, it's helpful to provide a glossary of sorts so they may 
    lookup the meaning of a new term.  However, deciding on where to put this 
    glossary inside the user interface is a big deal.  For example, if I'm 
    performing some task, I don't want to drop it to go look something up.  
    This is where tooltips help – the user gets a contextual explanation 
    of something.
</p>

<p>
    Out of the box, tooltips work great when applied to a specific element on 
    the page, such as a button or a progressbar. But what about paragraphs of 
    text?  Let's look at how we could allow the user to select some text, and 
    display some contextual definition for the selection using the tooltip 
    widget.
</p>
```

这里是词典小部件的实现以及如何将其应用于我们的两段文本。

```js
( function( $, undefined ) {

$.widget( "ab.dictionary", {

    options: {
        terms: []
    },

    ttPos: $.ui.tooltip.prototype.options.position,

    _create: function() {

        this._super();

        this._on({
            mouseup: this._tip,
            mouseenter: this._tip
        });

    },

    _destroy: function() {
        this._super();
        this._destroyTooltip();
    },

    _tip: function( e ) {

        var text = this._selectedText(),
            term = this._selectedTerm( text );

        if ( text === undefined || term === undefined ) {
            this._destroyTooltip();
            return;
        }

        if ( this.element.attr( "title" ) !== term.tip ) {
            this._destroyTooltip();
        }

        this._createTooltip( e, term );

    },

    _selectedText: function() {

        var selection, range, fragment;

        selection = window.getSelection();

        if ( selection.type !== "Range" ) {
            return;
        }

        range = selection.getRangeAt( 0 ),
        fragment = $( range.cloneContents() );

        return $.trim( fragment.text().toLowerCase() );

    },

    _selectedTerm: function( text ) {

        function isTerm( v ) {
            if ( v.term === text || v.term + "s" === text ) {
                return v;
            }
        }

        return $.map( this.options.terms, isTerm )[ 0 ];

    },

    _createTooltip: function( e, term ) {

        if ( this.element.is( ":ui-tooltip" ) ) {
            return;
        }

        var pos = $.extend( this.ttPos, { of: e } );

        this.element.attr( "title", term.tip )
                    .tooltip( { position: pos } )
                    .tooltip( "open" );
    },

    _destroyTooltip: function() {

        if ( !this.element.is( ":ui-tooltip" ) ) {
           return;
        }

        this.element.tooltip( "destroy" )
                    .attr( "title", "");

    }

});

})( jQuery );

$(function() {

    var dict = [
        {
            term: "tooltip",
            tip: "A contextual widget providing information to the user"
        },
        {
            term: "progressbar",
            tip: "A widget illustrating the progress of some task"
        },
        {
            term: "element",
            tip: "An HTML element on the page"
        },
        {
            term: "user interface",
            tip: "Components on the screen the user interacts with"
        }
    ];

    $( "p" ).dictionary({
        terms: dict
    });

});
```

如果您在浏览器中打开此页面并使用鼠标指针选择“tooltips”，您应该会得到如下屏幕截图所示的提示。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_11_09.jpg)

## 工作原理...

我们的新词典小部件增加了用户选择段落文本并获取其上下文定义的功能（如果存在）。该小部件接受一个`terms`选项，这只是一个术语和提示的数组。这是用于选择文本时执行查找的词典数据。`ttPos`属性是对默认提示`position`设置对象的引用。我们保持这个便于使用，因为每次用户选择文本并显示提示小部件时都需要使用它。在实例化小部件时调用的`_create()`方法设置了事件处理。特别是，我们对`mouseup`和`mouseenter`事件感兴趣，这两个事件根据许多因素显示提示小部件。`_destroy()`方法确保我们使用的提示小部件也通过调用`_destroyTooltip()`销毁。

`_tip()`方法可谓是此小部件的主程序，因为它将具有特定责任的所有方法联系在一起。我们使用`_selectedText()`方法获取所选文本。我们使用字典中的选定文本获取所选术语。现在，这些值中的任何一个可能是未定义的—当调用`_tip()`时，用户可能未选择任何内容，或者用户选择的文本在字典中不存在。如果任何一种情况为真，我们必须确保销毁提示。另一方面，如果找到了术语，我们使用`_createTooltip()`方法创建和显示提示。

`_createTooltip()`方法接受一个事件对象以及一个术语对象。事件对象用于在打开提示时定位提示。回想一下，我们将提示的默认位置选项存储在`ttPos`属性中。我们通过扩展该属性与事件创建一个新的`position`对象。这意味着我们可以将提示相对于用户选择文本的位置进行定位。现在我们已经设置了提示的位置，我们只需将段落的`title`属性设置为我们希望在提示内显示的文本。这是传递给方法的所选术语的`tip`属性。`_destroyTooltip()`负责销毁提示小部件，但仅在该元素实际上是提示时，并还原`title`属性。

最后需要注意的是，您会注意到我们将简单的字符串传递给字典实例。但我们能够在给定的用户选择中找到几个变体的术语。例如，“tooltips”会找到术语“tooltip”，因为我们在原始字符串之外添加了“s”。我们还会对选择两侧的空白进行标准化，以及忽略大小写。

## 还有更多...

我们使用字典小部件的方法的缺点是，用户必须选择文本才能获得单词的上下文定义。例如，示例中的两个段落共定义了四个术语。要使此工作，用户必须猜测哪些文本实际上被定义。此外，选择段落文本是直观的，但仅当您经常在使用的应用程序中执行此操作时——大多数用户并不这样做。

让我们通过引入一个新的模式——`hover`来增强我们的字典小部件。当此模式为`true`时，我们将实际操作段落文本，以使字典中定义的术语突出显示。这些术语看起来像链接，包含定义的工具提示会像您典型的工具提示一样工作。首先，让我们添加这个简单的 CSS 规则，我们将应用于段落中的每个术语。

```js
.ui-dictionary-term {
    text-decoration: underline;
    cursor: help;
}
```

我们将保留先前使用的相同两个段落，并使用新的`mode`选项实例化字典，我们还将修改小部件定义以使用此新选项。以下是新的 JavaScript 代码：

```js
( function( $, undefined ) {

$.widget( "ab.dictionary", {

    options: {
        terms: [],
        mode: "select"
    },

    ttPos: $.ui.tooltip.prototype.options.position,

    _create: function() {

        this._super();

        if ( this.options.mode === "select" ) {

            this._on({
                mouseup: this._tip,
                mouseenter: this._tip
            });

        }
        else if ( this.options.mode === "hover" ) {

            this._formatTerms();
            this._createTooltip();

        }

    },

    _destroy: function() {

        this._super();
        this._destroyTooltip();

        if ( this.options.mode === "hover" ) {
            this._unformatTerms();
        }

    },

    _tip: function( e ) {

        var text = this._selectedText(),
            term = this._selectedTerm( text );

        if ( text === undefined || term === undefined ) {
            this._destroyTooltip();
            return;
        }

        if ( this.element.attr( "title" ) !== term.tip ) {
            this._destroyTooltip();
        }

        this._createTooltip( e, term );

    },

    _selectedText: function() {

        var selection, range, fragement;

        selection = window.getSelection();

        if ( selection.type !== "Range" ) {
            return;
        }

        range = selection.getRangeAt( 0 ),
        fragment = $( range.cloneContents() );

        return $.trim( fragment.text().toLowerCase() );

    },

    _selectedTerm: function( text ) {

        function isTerm( v ) {
            if ( v.term === text || v.term + "s" === text ) {
                return v;
            }
        }

        return $.map( this.options.terms, isTerm )[ 0 ];

    },

    _createTooltip: function( e, term ) {

        if ( this.options.mode === "hover" ) {
            this.element.find( ".ui-dictionary-term" ).tooltip();
            return;
        }

        if ( this.element.is( ":ui-tooltip" ) ) {
            return;
        }

        var pos = $.extend( this.ttPos, { of: e } );

        this.element.attr( "title", term.tip )
                    .tooltip( { position: pos } )
                    .tooltip( "open" );

    },

    _destroyTooltip: function() {

        if( this.options.mode === "hover" ) {
            this.element.find( ".ui-dictionary-term" )
                        .tooltip( "destroy" );
            return;
        }

        if ( !this.element.is( ":ui-tooltip" ) ) {
            return;
        }

        this.element.tooltip( "destroy" )
                    .attr( "title", "");

    },

    _formatTerms: function() {

        function getTerm( v ) {
            return v.term;
        }

        var text = this.element.html(),
            terms = $.map( this.options.terms, getTerm );

        $.each( this.options.terms, function( i, v ) {

            var t = v.term,
                ex = new RegExp( "(" + t + "s|" + t + ")", "gi" ),
                termClass = "ui-dictionary-term",
                formatted = "<span " +
                            "class='" + termClass + "'" +
                            "title='" + v.tip + "'" +
                            ">$1</span>";

            text = text.replace( ex, formatted );

        });

        this.element.html( text );

    },

    _unformatTerms: function() {

        var $terms = this.element.find( ".ui-dictionary-term" );

        $terms.each( function( i, v ) {
            $( v ).replaceWith( $( v ).text() );
        });

    }

});

})( jQuery );

$(function() {

    var dict = [
        {
            term: "tooltip",
            tip: "A contextual widget providing information to the user"
        },
        {
            term: "progressbar",
            tip: "A widget illustrating the progress of some task"
        },
        {
            term: "element",
            tip: "An HTML element on the page"
        },
        {
            term: "user interface",
            tip: "Components on the screen the user interacts with"
        }
    ]

    $( "p" ).dictionary({
        terms: dict,
        mode: "hover"
    });

});
```

现在，当您在浏览器中查看两个段落时，您会注意到我们在字典数据中定义的术语已被下划线标记。因此，当用户将鼠标指针悬停在术语上时，他们将获得带有工具提示的帮助光标图标。

![还有更多...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186_11_10.jpg)

我们向字典小部件引入的新`mode`选项接受字符串值，可以是`select`或`hover`，默认为`select`，这是我们在此示例中最初实现的行为。在小部件构造函数`_create()`方法中，我们检查`mode`值。如果我们处于`hover`模式，则调用`_formatTerms()`方法，该方法会更改段落内术语的视觉外观。接下来，我们调用`_createTooltip()`，与原始实现中使用的相同方法，只是现在也具有模式感知性。`_formatTerms()`存储给定元素的文本，然后遍历字典术语。对于每个术语，它构建一个正则表达式，并用用于创建工具提示的`span`元素替换找到的任何术语。


# 第十二章：小部件和更多！

在本章中，我们将介绍以下配方：

+   从折叠到标签，再返回

+   从头开始构建自定义小部件

+   构建一个观察者小部件

+   使用 Backbone 应用程序的小部件

# 介绍

到目前为止，本书中的每一章都专注于使用 jQuery UI 附带的特定小部件进行工作。在本章中，我们更感兴趣的是大局观。毕竟，您正在构建一个应用程序，而不是一个演示。因此，对于使用 jQuery UI 的开发人员来说，重要的是不仅要意识到每个单独小部件在其自身上的工作方式，还要意识到它们在其环境中的行为方式，以及它们如何与其他小部件和框架交互。

我们还将通过使用小部件工厂从头开始构建一个小部件来解决框架的基本知识。通过通用小部件机制，您可以编写一些与默认小部件无关的小部件。尽管这些自定义小部件没有继承太多功能，但它们的行为类似于 jQuery UI 小部件，仅这一点就值得付出努力——将一层一致性固化到您的应用程序中。

# 从折叠到标签，再返回

折叠和标签小部件都是容器。也就是说，它们在应用程序的上下文中的典型用途是组织子组件。这些子组件可能是其他小部件，或者任何其他 HTML 元素。因此，这两个小部件符合容器的通用描述，即具有不同部分的小部件。显然，这个描述有一些微妙之处；例如，折叠不支持远程 Ajax 内容。此外，用户遍历部分的方式也大不相同。但它们本质上是可以互换的。为什么不在两个小部件之间引入切换的能力，特别是在运行时，用户可以设置自己的偏好并在两个容器之间切换的情况下？事实证明，我们可以实现这样的东西。让我们看看我们将如何做到这一点。我们需要两个小部件之间的双向转换。这样，标签小部件可以转换为折叠小部件，反之亦然。

## 如何做...

要实现我们在这里讨论的两种不同小部件之间的转换，我们将不得不扩展折叠和标签小部件。我们将为每个小部件添加一个新方法，将小部件转换为其对应的小部件。这是我们需要使此示例发生的 HTML 结构：

```js
<button class="toggle">Toggle</button>

<div id="accordion">
    <h3>Section 1</h3>
    <div>
        <p>Section 1 content...</p>
    </div>
    <h3>Section 2</h3>
    <div>
        <p>Section 2 content...</p>
    </div>
    <h3>Section 3</h3>
    <div>
        <p>Section 3 content...</p>
    </div>
</div>

<button class="toggle">Toggle</button>

<div id="tabs">
    <ul>
        <li><a href="#section1">Section 1</a></li>
        <li><a href="#section2">Section 2</a></li>
        <li><a href="#section3">Section 3</a></li>
    </ul>
    <div id="section1">
        <p>Section 1 content...</p>
    </div>
    <div id="section2">
        <p>Section 2 content...</p>
    </div>
    <div id="section3">
        <p>Section 3 content...</p>
    </div>
</div>
```

在这里，我们有两个切换按钮，一个折叠 `div` 和一个标签 `div`。切换按钮将使其对应的容器小部件变形为另一种小部件类型。以下是 JavaScript 代码：

```js
( function( $, undefined ) {

$.widget( "ab.accordion", $.ui.accordion, {

    tabs: function() {

        this.destroy();

        var self = this,
            oldHeaders = this.headers,
            newHeaders = $( "<ul/>" );

        oldHeaders.each( function( i, v ) {

            var id = self.namespace + "-tabs-" + self.uuid + "-" + i,
                header = $( "<li/>" ).appendTo( newHeaders );

            $( "<a/>" ).text( $( v ).text() )
                       .attr( "href", "#" + id )
                       .appendTo( header );

            oldHeaders.next().eq( i ).attr( "id", id );

        });

        newHeaders.prependTo(this.element);

        this.headers.remove();
        return this.element.tabs();

    }

});

$.widget( "ab.tabs", $.ui.tabs, {

    accordion: function() {

        this.destroy();

        var self = this;

        this.tabs.each( function( i, v ) {

            var $link = $( v ).find( "a" ),
                id = $link.attr( "href" ),
                text = $link.text();

            $( "<h3/>" ).text( text )
                        .insertBefore( id );

        });

        this.tablist.remove();
        return this.element.accordion();

    },

});

})( jQuery );

$(function() {

    $( "button.toggle" ).button().on( "click", function( e ) {

        var $widget = $( this ).next();

        if ( $widget.is( ":ab-accordion" ) ) {
            $widget.accordion( "tabs" );
        }
        else if ( $widget.is( ":ab-tabs" ) ) {
            $widget.tabs( "accordion" );
        }

    });

    $( "#accordion" ).accordion();
    $( "#tabs" ).tabs();

});
```

## 它是如何工作的...

当页面首次加载并且所有 DOM 元素都准备就绪时，我们创建切换按钮小部件、折叠小部件和标签小部件。如下截图所示：

![它的工作原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_12_01.jpg)

现在，点击顶部的切换按钮将把手风琴部件转换为标签部件。另外，第二个切换按钮将标签部件转换为手风琴。点击每个切换按钮一次的结果如下：

![它的运行原理...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_12_02.jpg)

切换按钮的工作原理是使用 jQuery 的`next()`函数来获取下一个部件，无论是`#accordion`还是`#tabs`，具体取决于所点击的按钮。然后将其存储在`$widget`变量中，因为我们会多次访问它。首先，我们检查部件是否是手风琴，如果是，我们在手风琴上调用`tabs()`方法。同样地，如果`$widget`是标签，我们调用`accordion()`方法来转换它。请注意，我们正在使用内置的部件选择器，部件工厂为每个部件创建，以确定元素是什么类型的部件。另外，请注意，命名空间是`ab`，而不是`ui`，这是编写自己的部件或自定义现有部件时的推荐做法，就像这里一样。在这里，我选择了我的缩写作为命名空间。在实践中，这将是一个与应用程序相关的标准约定。

现在让我们把注意力转向我们已经添加到手风琴部件的`tabs()`方法。这个新方法的基本工作是销毁手风琴部件，操作 DOM 元素，使其呈现出标签部件将识别的形式，然后实例化标签部件。所以，我们首先调用`destroy()`方法。然而，请注意，我们仍然可以访问手风琴部件的一些属性，比如`headers`。销毁部件主要涉及删除任何由于首次创建部件而引入到 DOM 中的装饰，以及删除事件处理程序。在 JavaScript 级别上，销毁我们在这里使用的部件对象并不太关心。

此时，我们有一个`oldHeaders`变量，它指向原始手风琴的`h3`元素。接下来，我们有`newHeaders`，它是一个空的`ul`元素。`newHeaders`元素是标签部件期望找到的新元素的起点。接下来，我们必须构建指向标签的内容面板的`li`元素。对于每个标题，我们向`newHeaders` `ul`添加一个链接。但是，我们还必须使用将标题链接到的`id`更新面板 ID。我们首先使用选项卡的位置以及部件本身的`uuid`构建一个 ID 字符串。虽然 uuid 并不是必需的；然而，确保唯一的选项卡 ID 仍然是一个好主意。

最后，我们将新的标题添加到元素中，并删除旧的标题。此时，我们有足够的内容来实例化标签部件。而且我们确实这样做了。请注意，我们返回了新创建的对象，以便如果在代码的其他地方引用它，可以用此方法替换它，例如，`myTabs = myAccordion.accordion( "tabs" )`。

我们添加到标签小部件的 `accordion()` 方法遵循了上述 `tabs()` 方法中应用的相同原则——我们想要销毁小部件，操作 DOM，并创建折叠小部件。为了实现这一点，我们需要在相应的内容面板之前插入 `h3` 标题元素。然后，我们删除 `tablist` 元素和标签 `ul`，然后调用实例化并返回折叠小部件。

# 从头开始构建自定义小部件

jQuery UI 最强大的部分并不是随附的预构建小部件，而是用于构建这些小部件的机制。每个小部件都共享一个称为小部件工厂的公共基础设施，并且该基础设施对开发人员使用该框架是可见的。小部件工厂提供了一种让开发人员定义自己的小部件的方式。我们在本书中已经多次看到小部件工厂的实际应用。我们一直在使用它来扩展任何给定小部件的功能。本节的重点是以不同的角度来看待小部件工厂。也就是说，我们如何利用它从零开始构建自己的小部件？

嗯，我们不想从零开始，因为那样会违背小部件工厂的整个目的。相反，构建任何小部件的目标是利用基础小部件类提供的通用功能。此外，开发人员在创建小部件时应该尽量遵循一些基本的设计原则。例如，您的小部件在销毁时应该进行清理，删除属性、事件处理程序，并基本上将元素恢复到原始状态。小部件还应该提供简单的 API，并且对于使用您的小部件的开发人员来说，它应该清楚该小部件做什么，更重要的是，它不做什么。在开始之前和设计小部件时，请记住一些原则：

+   **保持简单**：随着 jQuery UI 的最新版本，一些标准小部件经历了重大的重构工作，以简化其界面。在设计您的小部件时，借鉴这个教训，并将其责任最小化。在实现小部件的过程中，可能会有添加另一个 API 方法的冲动，甚至可能有几个。在这样做之前，请认真考虑，因为扩展 API 通常会导致难以维护和保持稳定的小部件。而这正是小部件背后的整个理念，一个小而可靠的模块化组件，可以在各种上下文中使用而不会出现问题。话虽如此，一个不满足应用程序需求的小部件也毫无价值。

+   **可扩展性设计**：在简洁保持原则的基础上构建的是可扩展性。同样，正如我们在本书中所见，可扩展性通常是赋予小部件额外功能以执行其工作所需的关键。这些可以是简单的自定义，也可以是方法的完全重写。无论如何，假设您的小部件将被修改，并且它将有观察者监听事件。换句话说，一个好的小部件将以合理的粒度提供功能在实现它的方法之间的分布。每个方法都是专门化的入口点，因此潜在的入口点应该是一个有意识的关注点。小部件触发的事件将小部件的状态传达给外界。因此，当您的小部件的状态发生变化时，请务必让其他人知道。

## 如何做...

足够的说了，现在，让我们来构建一个检查表小部件。它真的就像听起来的那么简单。我们将基于一个`ul`元素构建小部件，该元素将每个`li`元素转换为检查表项。但是，检查表不会孤立存在；我们将添加一些外部组件来与我们的小部件进行交互。我们将需要一个按钮来添加新的检查表项，一个按钮来删除一个项目，以及一个用于跟踪我们列表进度的进度条。用户与小部件本身的主要交互集中在检查和取消检查项目上。

这是我们在本示例中将使用的 HTML：

```js
<div class="container">
    <button id="add">Add</button>
    <button id="remove">Remove</button>
</div>
<div class="container">
    <ul id="checklist">
        <li><a href="#">Write some code</a></li>
        <li><a href="#">Deploy some code</a></li>
        <li><a href="#">Fix some code</a></li>
        <li><a href="#">Write some new code</a></li>
    </ul>
</div>
<div class="container">
    <div id="progressbar"></div>
</div>
```

接下来，我们将添加我们的检查表小部件所需的 CSS。

```js
.ui-checklist {
    list-style-type: none;
    padding: 0.2em;
}

.ui-checklist li {
    padding: 0.4em;
    border: 1px solid transparent;
    cursor: pointer;    
}

.ui-checklist li a {
    text-decoration: none;
    outline: none;
}

.ui-checklist-checked {
    text-decoration: line-through;
}
```

最后，我们将使用以下 JavaScript 代码添加我们的小部件定义。此代码还创建了本示例中使用的两个按钮小部件和进度条小部件。

```js
( function( $, undefined ) {

$.widget( "ab.checklist", {

    options: {
        items: "> li",
        widgetClasses: [
            "ui-checklist",
            "ui-widget",
            "ui-widget-content",
            "ui-corner-all"
        ],
        itemClasses: [
            "ui-checklist-item",
            "ui-corner-all"
        ],
        checkedClass: "ui-checklist-checked"
    },

    _getCreateEventData: function() {

        var items = this.items,
            checkedClass = this.options.checkedClass;

        return {
            items: items.length,
            checked: items.filter( "." + checkedClass ).length
        }

    },

    _create: function() {

        this._super();

        var classes = this.options.widgetClasses.join( " " );

        this.element.addClass( classes );

        this._on({
            "click .ui-checklist-item": this._click,
        });

        this.refresh();

    },

    _destroy: function() {

        this._super();

        var widgetClasses = this.options.widgetClasses.join( " " ),
            itemClasses = this.options.itemClasses.join( " " ),
            checkedClass = this.options.checkedClass;

        this.element.removeClass( widgetClasses );

        this.items.removeClass( itemClasses )
                  .removeClass( checkedClass )
                  .removeAttr( "aria-checked" );

    },

    _click: function( e ) {

        e.preventDefault();
        this.check( this.items.index( $( e.currentTarget ) ) );

    },

    refresh: function() {

        var trigger = true,
            items,
            newItems;

        if ( this.items === undefined ) {
            trigger = false;
            this.items = $();
        }

        items = this.element.find( this.options.items )
        newItems = items.not( this.items );

        items.addClass( this.options.itemClasses.join( " " ) );

        this._hoverable( newItems );
        this._focusable( newItems );

        this.items = items;

        if ( trigger ) {
            this._trigger( "refreshed",
                           null,
                           this._getCreateEventData() );
        }

    },

    check: function( index ) {

        var $item = this.items.eq( index ),
            checked;

        if ( !$item.length ) {
            return;
        }

        checked = $item.attr( "aria-checked" ) === "true" ?
                  "false" : "true";

        $item.toggleClass( this.options.checkedClass )
             .attr( "aria-checked", checked );

        this._trigger( "checked", null, this._getCreateEventData());

    }

});

})( jQuery );

$(function() {

    $( "#add" ).button({
        icons: {
            primary: "ui-icon-plus"
        },
        text: false
    });

    $( "#add" ).on( "click", function( e ) {

        var $checklist = $( "#checklist" ),
            $item = $( "<li/>" ).appendTo( checklist );

        $( "<a/>" ).attr( "href", "#" )
                   .text( "Write some documentation" )
                   .appendTo( $item );

        $checklist.checklist( "refresh" );

    });

    $( "#remove" ).button({
        icons: {
            primary: "ui-icon-minus"
        },
        text: false
    });

    $( "#remove" ).on( "click", function( e ) {

        var $checklist = $( "#checklist" ),
            $item = $checklist.find( ".ui-checklist-item:last" );

        $item.remove();
        $checklist.checklist( "refresh" );

    });

    $( "#progressbar" ).progressbar();

    $( "#checklist" ).checklist({
        create: function( e, ui ) {
            $( "#progressbar" ).progressbar( "option", {
                max: ui.items,
                value: ui.checked
            });
        },
        refreshed: function( e, ui ) {
            $( "#progressbar" ).progressbar( "option", {
                max: ui.items,
                value: ui.checked
            });
        },
        checked: function( e, ui ) {
            $( "#progressbar" ).progressbar( "value", ui.checked );
        }
    });

});
```

当您首次加载页面时，检查表组件以及页面上的其他组件应该看起来像这样：

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_12_03.jpg)

您可以看到，这些是 HTML 结构中指定的默认检查表项。悬停状态按预期工作，但进度条为 0。这是因为检查表没有任何选定的项目。让我们勾选一些项目，并添加一些项目。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_12_04.jpg)

您可以看到，每次添加或删除检查表项以及单独检查或取消检查一个项目时，进度条都会更新。

## 工作原理...

让我们首先讨论检查表小部件的 HTML 结构以及显示它所需的新 CSS。然后，我们将将小部件的定义和实例化分成几个部分，并解决这些部分。此示例中使用的 HTML 分为三个主要容器`div`元素。第一个元素保存我们的添加和删除项目按钮。第二个是检查表小部件，最后一个是进度条。这是一般布局。

HTML 结构的最重要方面是`#container`元素，它是我们清单小部件的基础。每个项目都存储在一个`li`元素内。请注意，项目的文本也包装在一个`a`元素中。这使得在用户通过页面元素时处理单个项目的焦点变得更加简单。清单的主要样式由`ui-checklist`类控制。这个类在小部件第一次创建时被应用于元素，并对列表执行一些标准样式操作，比如移除项目符号图片。我们需要处理的另一件事是边框间距，当用户悬停在项目上时，`ui-state-hover`被添加和移除。包装项目文本的`a`元素不需要任何文本装饰，因为我们不将它们用作标准链接。最后，`ui-checklist-checked`类与单个清单项目的状态相关，并在视觉上标记项目为已选中。它还在我们需要收集所有已选中项目时作为查询辅助工具。

现在让我们把注意力转向小部件的定义，以及我们是如何实例化和使用它的。

+   **选项**: 我们的小部件首先定义的是它的选项，每个选项都有一个默认值。始终确保您向小部件添加的任何选项都有一个默认值，因为我们永远不能指望在创建时提供一个选项。我们在这里为我们的清单小部件定义的选项非常简单，很少会被开发人员更改。例如，我们查找的项目通常总是`li`元素。而且，我们在这里定义的类，应用于小部件本身，可能永远不会更改。然而，它们需要在某个地方声明，所以我们可以硬编码它，或者将它们放在开发人员可以访问的地方。把选项想象成小部件对象的属性或属性。

+   **私有方法**: 按照惯例，私有方法或不构成对用户可见的 API 的方法以下划线作为前缀。我们的第一个私有方法是`_getCreateEventData()`方法。当小部件的创建事件被触发时，此方法会被基础小部件类在内部调用。这个方法是一个钩子，允许我们向创建事件处理程序提供自定义数据。我们在这里做的一切就是传递一个对象，该对象具有存储在项目属性中的项目数，以及存储在已检查属性中的已检查项目数。

+   **create 方法**：`_create()`方法可能是任何小部件的最常见方法，因为它是由小部件工厂作为小部件构造函数调用的。我们使用`_super()`实用方法为我们调用基础小部件构造函数，它为我们执行一些样板初始化工作。接下来，我们使用`widgetClasses`选项将相关的小部件 CSS 类应用于元素。然后，我们使用`_on()`方法为点击事件设置事件处理程序。请注意，在事件名后面我们传递了一个委托选择器`.ui-checklist-item`。我们这样做的原因是因为可以向清单中添加项目，也可以从清单中删除项目，因此使用这种方法比手动管理每个项目的点击事件更合理。

+   **destroy 方法**：`_destroy()`方法是必不可少的，如前所述，用于执行清理任务。我们在这里使用`_super()`调用基础小部件`_destroy()`方法，该方法将清理我们使用`_on()`创建的任何事件处理程序。然后，我们只需要删除我们在小部件的生命周期中添加的任何类和属性。最后一个私有方法是`_click()`方法，这是当小部件首次创建时绑定到点击事件的事件处理程序。此方法的工作是更改所点击项目的状态，我们通过调用`check()`方法来实现这一点，该方法是向开发人员公开的 API 的一部分。我们还希望在这里阻止链接点击的默认操作，因为它们有可能重新加载页面。

+   **API**：秉承保持小部件简单的精神，暴露的 API 仅包括两种方法。第一个是`refresh()`方法，它负责定位构成我们清单的项目。这些项目存储在小部件对象的`items`属性中，这是一个不通过 API 公开的示例。`items`属性仅在内部使用；然而，如果开发人员要扩展我们的小部件，他们的自定义方法将是可访问的，甚至可能很有用。`refresh()`方法在发现新项目时更改小部件的状态，这就是为什么它会触发刷新事件的原因。但是，在某些情况下，我们不希望触发此事件，即当第一次实例化小部件时。这在`trigger`变量中进行跟踪（如果我们尚未存储任何项目，则可以安全地假定我们正在创建而不是刷新）。我们不希望与创建事件冲突的原因是，这对使用小部件的开发人员非常具有误导性。我们还在每个新发现的项目上使用了`_hoverable()`和`_focusable()`方法。这是小部件内用户与之交互的项目的标准模式。

+   **check 方法**：`check()`方法是检查清单 API 的另一半，它也会更改小部件的状态。它触发一个 changed 事件，其中包含有关项目计数和已检查计数的数据，与创建事件数据相同。您会注意到，此方法确保处理适当的`aria`属性，就像标准的 jQuery UI 小部件一样。`aria`标准促进了可访问性，这就是为什么 jQuery UI 框架使用它的原因，而我们的小部件也不应该有所不同。最后，该方法的工作是使用存储在`checkedClass`选项中的值切换此项目的类。

+   **主要应用程序**：页面加载时，我们首先做的是创建两个按钮小部件：`#add`和`#remove`。点击`#add`按钮时，会将新项目的 DOM 元素添加到检查清单中。然后，它使用`refresh()`方法更新小部件的状态，并触发任何事件。同样，`#remove`按钮会移除一个 DOM 元素，并调用`refresh()`方法，触发任何状态更改行为。进度条小部件在不包含任何选项的情况下实例化，因为它对我们的检查清单小部件一无所知。

最后，我们的检查清单小部件是用三个选项创建的。这些都是事件处理程序，它们都承担着相同的责任——更新`#progressbar`小部件。例如，小部件首先被创建，然后进度条根据在 DOM 中找到的项目进行更新（尚未检查任何项目）。当从列表中添加或删除新项目时，将触发`refreshed`事件；我们也希望在这里更新进度条。每当用户选中或取消选中项目时，都会触发`checked`事件处理程序，在这里，我们只关心更新进度条的值，因为项目的总数是相同的。

# 构建观察者小部件

处理由 jQuery UI 小部件触发的事件的典型方法是将事件处理程序绑定到该事件名称，直接传递到构造函数中。这是典型的方法，因为它易于做到，并且通常解决了我们遇到的特定问题。例如，假设当我们的手风琴小部件的某个部分展开时，我们希望更新另一个 DOM 元素。为此，在构造手风琴时将事件处理程序函数分配给激活事件。

这种方法非常适用于小型、单一用途的作业，适用于给定小部件的单个实例。然而，大多数有意义的应用程序有许多小部件，都触发着自己的事件。小部件工厂用小部件的名称前缀每个事件，这通常意味着即使在小部件上下文之外，我们也知道我们在处理什么。当我们想要将事件处理程序绑定到小部件事件时，长时间之后，小部件已经被创建了，这一点尤其有帮助。

让我们构建一个**观察者**小部件，帮助我们可视化应用程序中发生的所有潜在小部件事件。观察者小部件能够绑定到单个小部件、一组小部件或整个文档。我们将看看后一种情况，在那里观察者甚至会捕获未来创建的小部件的事件。

## 如何做...

让我们首先看一下观察者小部件使用的 CSS 样式：

```js
.ui-observer-event {
    padding: 1px;
}

.ui-observer-event-border {
    border-bottom: 1px solid;
}

.ui-observer-event-timestamp {
    float: right;
}
```

现在，让我们看一下用于创建一个基本页面和几个示例小部件的 HTML。这些小部件将触发我们试图用观察者捕获的事件。

```js
<div class="container">
    <h1 class="ui-widget">Accordion</h1>
    <div id="accordion">
        <h3>Section 1</h3>
        <div>
            <p>Section 1 content</p>
        </div>
        <h3>Section 2</h3>
        <div>
            <p>Section 2 content</p>
        </div>
    </div>
</div>
<div class="container">
    <h1 class="ui-widget">Menu</h1>
    <ul id="menu">
        <li><a href="#">Item 1</a></li>
        <li><a href="#">Item 2</a></li>
        <li><a href="#">Item 3</a></li>
    </ul>
</div>
<div class="container">
    <h1 class="ui-widget">Tabs</h1>
    <div id="tabs">
        <ul>
            <li><a href="#tab1">Tab 1</a></li>
            <li><a href="#tab2">Tab 2</a></li>
            <li><a href="#tab3">Tab 3</a></li>
        </ul>
        <div id="tab1">
            <p>Tab 1 content</p>
        </div>
        <div id="tab2">
            <p>Tab 2 content</p>
        </div>
        <div id="tab3">
            <p>Tab 3 content</p>
        </div>
    </div>
</div>
```

最后，这是小部件的实现方式，以及在此页面上使用的四个小部件实例：

```js
( function( $, undefined ) {

$.widget( "ab.observer", {

    options: {

        observables: [
            {
                widget: $.ui.accordion,
                events: [
                    "activate",
                    "beforeActivate",
                    "create"
                ]
            },
            {
                widget: $.ui.menu,
                events: [
                    "blur",
                    "create",
                    "focus",
                    "select"
                ]
            },
            {
                widget: $.ui.tabs,
                events: [
                    "activate",
                    "beforeActivate",
                    "create"
                ]
            }
        ]

    },

    _getEvents: function() {

        var events = {};

        $.each( this.options.observables, function ( i, v ) {

            var prefix = v.widget.prototype.widgetEventPrefix;

            $.each( v.events, function( i, v ) {
                events[ prefix + v.toLowerCase() ] = "_event";
            });

        });

        return events;

    },

    _create: function() {

        this._super();

        var dialogId = "ui-observer-dialog-" + this.uuid,
            dialogSettings = {
                minHeight: 300,
                maxHeight: 300,
                position: {
                    my: "right top",
                    at: "right top"
                },
                title: this.element.selector
            };

        this.dialog = $( "<div/>" ).attr( "id", dialogId )
                                   .attr( "title", "Observer" )
                                   .addClass( "ui-observer" )
                                   .appendTo( "body" )
                                   .dialog( dialogSettings );

        this._on( this.element, this._getEvents() );

    },

    _event: function( e, ui ) {

        var eventClasses = "ui-observer-event " +
                           "ui-observer-event-border",
            $event = $( "<div/>" ).prependTo( this.dialog )
                                  .addClass( eventClasses ),
            time = new Date( e.timeStamp ).toLocaleTimeString();

        $( "<span/>" ).html( e.type )
                      .appendTo( $event );

        $( "<span/>" ).html( time )
                      .addClass( "ui-observer-event-timestamp" )
                      .appendTo( $event );

        this.dialog.find( ".ui-observer-event:last" )
                   .removeClass( "ui-observer-event-border" );

    },

    _destroy: function() {

        this._super();
        this.dialog.dialog( "destroy" )
                   .remove();

    }

});

})( jQuery );

$(function() {

    $( document ).observer();

    $( "#accordion" ).accordion();
    $( "#menu" ).menu();
    $( "#tabs" ).tabs();

});
```

在浏览器中查看此页面时，基本小部件布局如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_12_05.jpg)

甚至只是创建这些小部件也会触发事件。例如，当页面首次加载时，您会看到观察者小部件创建的对话框已经填充了事件。

![如何做...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_12_06.jpg)

## 工作原理...

在这个例子中，可观察小部件应用于`document`元素。这意味着它将捕获冒泡到该级别的任何小部件事件。可观察小部件定义了一个`observables`选项，一个我们想要监听其事件的小部件数组。在这种情况下，为了简洁起见，我们只包括了三个小部件。这可以根据应用程序的需要随时扩展，因为它是一个选项。

`_getEvents()` 方法的目的是读取`observables`选项并构建一个我们可以使用它来将这些事件绑定到`_event()`方法的对象。请注意，我们在这里自动将小部件前缀值添加到事件名称——这在小部件原型的`widgetEventPrefix`属性中是可用的。`_create()`方法的工作是将`div`元素插入到`body`元素中，然后它成为一个对话框小部件。我们将其定位在页面的右上角，以便不妨碍用户。最后，我们使用由`_getEvents()`返回的对象使用`_on()`方法开始监听事件。

`_event()` 方法是我们监听的任何小部件事件触发时使用的单个回调函数。它简单地将事件记录到观察者对话框中。它还记录事件的时间；因此，这个工具对于尝试任何 jQuery UI 应用程序都是有用的，无论是大还是小，因为它可以突出显示实际发生的事件以及它们的顺序。该小部件还负责销毁它之前创建的对话框小部件。

# 在 Backbone 应用程序中使用小部件

由于 JavaScript 环境的变化多端，您可能会发现自己在不同的环境中工作，最好接受这一事实，不是所有事情都是按照 jQuery UI 的方式完成的。如果您发现自己在一个项目中渴望使用 jQuery UI 小部件，因为使用案例很多，那么您将不得不花费必要的时间来理解 jQuery UI 与另一个框架混合的后果。

对于任何开发人员来说，将完全不同的小部件框架混合在一起通常是不明智的，因此希望这是可以轻松避免的事情。当然，您必须处理其他自制的 HTML 和 CSS 组合，但这很正常。这并不是太糟糕，因为您可以控制它（其他开源框架很难做到）。那么，如果不是其他小部件框架，我们可能要考虑使用哪些其他框架？

**Backbone** 是一个通用框架，它基于较低级别的 `underscore.js` 实用库，用于为 Web 应用程序客户端添加结构。在 Backbone 应用程序中，您会找到模型、集合和视图等概念。对 Backbone 库的全面介绍远远超出了本书的范围。但是，将 Backbone 视为应用程序的脚手架很有帮助，这部分不会改变。无论是否使用 jQuery UI 小部件，它都会以相同的方式运行。但是，由于我们感兴趣的是使用 jQuery UI，让我们构建一个使用 jQuery UI 小部件的小型 Backbone 应用程序。

## 如何操作...

应用程序的目标是显示一个自动完成小部件，用户可以过滤编程语言名称。当进行选择时，会显示有关该语言的一些详细信息，包括一个删除按钮，该按钮从集合中删除语言。简单吧？让我们开始吧。

在页面页眉中，我们将做一些不同的事情——包括一个模板。模板只是一串文本，由 Backbone 视图渲染。我们将其类型设为 `text/template`，这样浏览器就不会将其解释为模板之外的东西（比如 JavaScript 代码）。它有一个 `id`，这样在渲染模板时我们可以稍后引用模板文本。

```js
<script type="text/template" id="template-detail">
    <div>
        <strong>Title: </strong>
        <span><%= title %></span>
    </div>
    <div>
        <strong>Authors: </strong>
        <span><%= authors %></span>
    </div>
    <div>
        <strong>Year: </strong>
        <span><%= year %></span>
    </div>
    <div>
        <button class="delete">Delete</button>
    </div>
</script>
```

接下来，是此 UI 使用的最小 CSS——简单的字体和布局调整。

```js
.search, .detail {
    margin: 20px;
}

.detail {
    font-size: 1.4em;
}

.detail button {
    font-size: 0.8em;
    margin-top: 5px;
}
```

接下来，我们有用户界面使用的实际标记。请注意 `detail` 类 `div` 是多么简洁。这是因为它只是一个模板的容器，由视图渲染，我们马上就会看到。

```js
<div class="search">
    <label for="search">Search:</label>
    <input id="search"/>
</div>
<div class="detail"></div>
```

最后，我们有实际使用自动完成和按钮 jQuery UI 小部件的 Backbone 应用程序。

### 注意

为了简洁起见，在此处我们将削减代码清单的大部分内容，试图只显示必需的内容。完全运作的 Backbone 代码可供下载，以及本书中的所有其他示例。

```js
$(function() {

    // Model and collection classes

    var Language,
        LanguageCollection;

    // View classes

    var AutocompleteView,
        LanguageView;

    // Application router

    var AppRouter;

    // Collection instance

    var languages;

    // Application and view instances

    var app,
        searchView,
        detailView;

    /**
     *
     * Class definitions
     *
     **/

    Language = Backbone.Model.extend({        
       // ...
    });

    LanguageCollection = Backbone.Collection.extend({
       // ...
    });

    AutocompleteView = Backbone.View.extend({        
       // ...
    });

    LanguageView = Backbone.View.extend({        
       // ...
    });

    AppRouter = Backbone.Router.extend({

    });

    /**
     *
     * Collection, view, and application instances
     *
     **/

    languages = new LanguageCollection([        
        // …
    ]);

    searchView = new AutocompleteView({
        // ….
    });

    detailView = new LanguageView({
        // …
    });

    app = new AppRouter();

    Backbone.history.start();

});
```

运行此示例将向用户显示一个自动完成 `input` 元素。所选语言的详细信息如下截图所示：

![如何操作...](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqui-cb/img/2186OS_12_07.jpg)

## 工作原理...

我们整个 Backbone 应用程序都在文档就绪的回调函数中声明。一旦完成，一切都是基于事件的。让我们逐步了解应用程序组件。您将注意到的第一件事是，我们在顶部声明了变量，并为它们提供了简要的分类解释。当我们与超过一小撮的变量共享相同的命名空间时，这通常是有帮助的。类别如下：

+   **模型和集合类**：我们应用程序中用于定义数据模型的类。

+   **视图类**：我们应用程序中用于为用户提供数据模型不同视图的类。

+   **应用程序路由器**：一个类似于控制器的单个类，用于操作浏览器地址，并在路径更改时执行相关功能。

+   **集合实例**：集合实例代表应用程序数据 - 一组模型实例。

+   **应用程序和视图实例**：单个应用程序以及该应用程序用于呈现数据的各种视图。

鉴于此，请让我们现在深入了解每个 Backbone 类的工作原理。应用程序只有一个模型类，即`Language`。我们在这里可以看到，`Language`声明在实例化时为属性定义了一些默认值。接下来，`LanguageCollection`类是 Backbone Collection 类的扩展。这是所有我们的`Language`实例的地方。请注意，我们正在指定模型属性指向`Language`类。由于我们没有 RESTful API，我们必须告诉集合，任何同步操作都应在本地执行。我们必须在 Backbone 中包含本地存储插件，以使此操作生效。这实际上是在真正的后端完全成形之前启动 UI 开发的理想方式。

接下来，我们有我们的第一个视图类，`AutocompleteView`，它专门针对自动完成 jQuery UI 小部件。我们将其命名为这样是因为我们在这里尽力使其足够通用，以便与另一个自动完成小部件一起使用。我们在视图类中有一些语言特定的硬编码内容，但这些内容如果有需要的话可以轻松改进。在这个类中定义的第一个属性是`events`对象。这些大多与自动完成小部件事件相关。每个回调事件处理程序在下面被定义为一个视图方法。`initialize()`方法是视图构造函数，在这里我们调用`delegateEvents()`来为当前元素以及未来元素激活我们的事件处理程序。然后构造函数创建自动完成小部件，并监听其连接以获取销毁事件。

`autocompleteCreate()`方法在创建自动完成小部件后触发，并将小部件的`source`选项分配给小部件。这是对此视图的`autocompleteSource`方法的代理。`autocompleteSelect`方法在用户选择项目并导航到适当路由时触发。`autocompleteChange()`方法在自动完成小部件失去焦点并且项目不同的情况下触发。我们这样做是为了在用户删除其先前选择但尚未模糊自动完成焦点时更新路径。最后，`autocompleteSearch()`方法是用户开始输入时自动完成小部件填充项目的方法。首先，我们使用集合上的 underscore `filter()`方法执行过滤，然后我们使用集合上的 underscore `map()`方法进行映射。映射是必要的以返回自动完成小部件期望的格式。

应用程序的下一个关键部分是`LanguageView`类，负责渲染编程语言的详细信息。和之前的视图一样，这个视图使用`events`属性设置事件处理程序。我们还在构造函数中列出了该视图的集合上的一些事件。需要注意的一个事件是`change:selected`事件。这只有在`selected`属性更改时才会触发，这很好，因为这是我们感兴趣的。

`render()`方法负责渲染模板，但仅在实际选择了相应的模型时才执行。一旦渲染完成，我们就可以实例化此视图使用的按钮小部件。但是，请注意，由于在首次创建视图时已经委托了单击事件处理程序，因此不会再次绑定事件处理程序。

`AppRouter`类是应用程序控制器，因为它负责对 URL 路径的更改做出反应。`routeLang()`方法响应特定语言并将其标记为选定。`routeDefault()`方法处理所有其他请求。它的唯一工作是确保没有语言被标记为选定，并且作为副作用，任何先前选定的语言都将从 UI 中移除，因为`LanguageView`正在监听`selected`属性的更改。

最后，我们在集合实例中创建我们模型的实例，然后创建我们的视图和应用程序路由器。
