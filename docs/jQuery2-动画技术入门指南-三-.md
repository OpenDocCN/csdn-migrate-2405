# jQuery2 动画技术入门指南（三）

> 原文：[`zh.annas-archive.org/md5/71BE345FA56C4A075E859338F3DCA6DA`](https://zh.annas-archive.org/md5/71BE345FA56C4A075E859338F3DCA6DA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：自定义动画

*迄今为止我们已经看过的预定义效果在执行它们的任务时非常出色，但它们只能满足非常具体的需求，有时在需要更复杂的动画时可能会不够用。*

*在这些情况下，我们可以使用 jQuery 的`animate()`方法，它允许我们轻松定义自定义动画，可以像任务所需的那样复杂和专业化。这是我们将在本章中探讨的内容。*

本章我们将涵盖的主题包括：

+   使用`animate()`方法创建自定义动画

+   向方法传递参数

+   动画化元素的尺寸

+   动画化元素的位置

+   创建 jQuery 动画插件

+   使用我们创建的 jQuery 插件

# 动画方法

jQuery 的所有自定义动画都由`animate()`方法驱动。尽管该方法可以动画化几乎任何具有数值的样式属性，但该方法使用简单，只需几个参数。该方法可以如下使用：

```js

$(elements).animate( properties [,duration] [,easing] [,complete] );

```

第一个参数应采用对象的形式，其中对象的每个属性都是我们想要动画的样式，与我们使用 jQuery 的`css()`方法非常相似。

正如我之前提到的，这可以是任何接受纯数值参数的 CSS 样式（颜色除外，尽管使用 jQuery UI 库，我们也可以动画化颜色。有关 jQuery UI 更多信息，请参见第六章，*使用 jQuery UI 进行扩展动画*）。jQuery 无法本机地动画化背景位置，但手动动画化此属性非常容易；有关此技术的更多信息，请参见第三章，*背景动画*。

持续时间、缓动和回调参数的格式与本书中早期的淡入淡出方法使用的格式相同（第二章，*图像动画*），并且使用方式完全相同。

## 逐属性缓动

自 jQuery 版本 1.4 起，您可以在单个`animate()`调用中设置逐属性缓动函数。因此，例如，如果我们正在动画元素的`宽度`和`高度`参数，我们可以对`宽度`动画使用`线性`缓动，对`高度`动画使用`摆动`缓动。这适用于 jQuery 内置的标准缓动函数，或我们在上一章中讨论的任何缓动函数（第六章，*使用 jQuery UI 进行扩展动画*）。

为了在每个属性的基础上为`animate()`方法提供缓动类型，我们需要提供一个数组作为我们正在动画化的属性的值。可以使用以下语法完成此操作：

```js

$(elements).animate({

属性：[值，缓动类型]

});

```

## 一个 animate() 的替代语法

与单独使用持续时间、缓动和回调参数不同，我们可以将以下配置选项的配置对象传递给 `animate()` 方法，而不是单独使用这些参数：

+   `duration`

+   `easing`

+   `complete`

+   `step`

+   `queue`

+   `specialEasing`

前三个选项（`duration`、`easing` 和 `complete`）与以标准方式将它们传递到方法中时的参数相同。然而，最后三个选项（`step`、`queue` 和 `specialEasing`）是有趣的，因为我们没有其他任何方式可以访问它们。

+   `step` 选项允许我们指定一个在动画的每一步上执行的回调函数。

+   `queue` 选项接受一个布尔值，控制动画是立即执行还是放入所选元素的队列中。

+   `specialEasing` 选项允许我们为正在进行动画处理的每个单独样式属性指定一个缓动函数，使用以下替代语法使我们能够基于每个属性进行缓动。

    ```js

    第二种用法的模式如下：$(elements).animate(properties [,configuration]);

    ```

像大多数（但不是全部）jQuery 方法一样，`animate()` 方法返回一个 jQuery 对象，以便可以将其他方法链接到它。像其他效果方法一样，对同一元素多次调用 `animate()` 将导致为该元素创建一个动画队列。如果我们想同时动画两个不同的样式属性，我们可以将所有所需属性都传递给 `animate()` 方法的第一个参数所传递的对象中。

# 动画一个元素的位置

`animate()` 方法能够动画处理对具有数值的任何 CSS 样式属性所做的更改，但颜色和背景位置除外。在此示例中，我们将使用 `animate()` 方法创建一个内容查看器，通过滑动它们的方式将不同的内容面板显示在视图中。

这种类型的小部件通常用于作品集或展示网站，是一种吸引人的方式来显示大量内容，而不会使单个页面混乱不堪。在此示例中，我们将会动画显示元素的位置。

# 行动时间 - 创建一个动画内容查看器

我们将重新开始添加底层标记和样式：

1.  应该使用我们的模板文件将内容查看器的底层标记添加如下：

    ```js

    <div id="slider">

    <div id="viewer">

        <img id="image1" src="img/amstrad.jpg" alt="Amstrad CPC 472">

        <img id="image2" src="img/atari.jpg" alt="Atari TT030">

        <img id="image3" src="img/commodore16.jpg" alt="Commodore 64">

        <img id="image4" src="img/commodore128.jpg" alt="Commodore 128">

        <img id="image5" src="img/spectrum.jpg" alt="Sinclair ZX Spectrum +2">

    </div>

    <ul id="ui">

        <li class="hidden" id="prev"><a href="" title="Previous">«</a></li>

        <li><a href="#image1" title="Image 1" class="active">图像 1</a></li>

        <li><a href="#image2" title="Image 2">图像 2</a></li>

        <li><a href="#image3" title="Image 3">图像 3</a></li>

        <li><a href="#image4" title="Image 4">图像 4</a></li>

        <li><a href="#image5" title="Image 5">图像 5</a></li>

        <li class="hidden" id="next"><a href="" title="下一页">»</a></li>

    </ul>

    </div>

    ```

1.  将文件保存为 `animate-position.html`。

1.  接下来，我们应该创建基本的 CSS。我指的是我们应该添加的 CSS，这些 CSS 对于内容查看器的正常运行至关重要，而不是给小部件添加主题或皮肤的样式。在创建插件时，将样式分离出来是一个很好的做法，这样小部件就与 jQuery UI 的 ThemeRoller 主题化机制兼容。

1.  在文本编辑器中的新文件中，添加以下代码：

    ```js

    #slider {

    width:500px;

    position:relative;

    }

    #viewer {

    width:400px;

    height:300px;

    margin:auto;

    position:relative;

    overflow:hidden;

    }

    #slider ul {

    width:295px;

    margin:0 auto;

    padding:0;

    list-style-type:none;

    }

    #slider ul:after {

    content:".";

    visibility:hidden;

    display:block;

    height:0;

    clear:both;

    }

    #slider li {

    margin-right:10px;

    float:left;

    }

    #prev, #next {

    position:absolute;

    top:175px;

    }

    #prev { left:20px; }

    #next {

    right:10px;

    }

    .hidden { display:none; }

    #slide {

    width:2000px;

    height:300px;

    position:absolute;

    top:0;

    left:0;

    }

    #slide img { float:left; }

    #title {

    margin:0;

    text-align:center;

    }

    ```

1.  将此文件保存在 `css` 文件夹中，文件名为 `animate-position.css`，并不要忘记从我们页面的 `<head>` 标签中链接到新样式表。现在在浏览器中运行页面，然后再我们进入脚本之前，看一下小部件在没有附带脚本的情况下的行为。您会发现，任何图像都可以通过单击其相应的链接来查看，仅使用 CSS 即可，在任何浏览器中都可以使用。前进和后退箭头会被我们的 CSS 隐藏，因为这些箭头在关闭 JS 时根本不起作用，并且当不显示图像标题时，但是小部件的核心功能仍然完全可访问。这被称为**渐进增强**，被许多人认为是 Web 开发的最佳实践。

## *刚刚发生了什么？*

这个示例中的基本 HTML 构造非常简单。我们有一个用于内容查看器的外部容器，然后在其中，我们有一个用于内容面板（在此示例中是简单的图像）的容器，以及一个导航结构，允许查看不同面板。

我们在 CSS 文件中为一些元素添加了样式规则，这些元素并没有硬编码到基本标记中，但将在需要时根据需要创建。以这种方式做可以确保即使访问者禁用了 JavaScript，内容查看器仍然可用。

一个重要的要点是，我们创建并围绕图片包装的 `#slide` 包装元素具有等于单个图片的 `height` 参数和等于所有图片宽度之和的 `width` 参数。另一方面，`#viewer` 元素具有等于单个图片的 `width` 和 `height` 参数，因此一次只能看到一张图片。

当 JavaScript 被禁用时，图片将看起来像是堆叠在一起，但一旦创建了 `#slide` 包装元素，图片就会被设置为浮动以水平堆叠。

在这个示例中，我们将使用缓动效果；因此，请确保在 `<body>` 标记末尾的 jQuery 引用后直接链接到 jQuery UI：

```js

<script src="img/jquery-ui.js"></script>

```

# 行动时间 – 初始化变量并准备小部件

首先，我们需要准备底层的标记并存储一些元素选择器。在我们新创建的 HTML 文件中的匿名函数之间添加以下代码：

```js

$("#viewer").wrapInner("<div id=\"slide\"></div>");

var container = $("#slider"),

prev = container.find("#prev"),

prevChild = prev.find("a"),

next = container.find("#next").removeClass("hidden"),

nextChild = next.find("a"),

slide = container.find("#slide"),

key = "image1",

details = {

    image1: {

    position: 0, title: slide.children().eq(0).attr("alt")

    },

    image2: {

    position: -400, title: slide.children().eq(1).attr("alt")

    },

    image3: {

    position: -800, title: slide.children().eq(2).attr("alt")

    },

    image4: {

    position: -1200, title: slide.children().eq(3).attr("alt")

    },

    image5: {

    position: -1600, title: slide.children().eq(4).attr("alt")

    }

};

$("<h2>", {

id: "title",

text: details[key].title

}).prependTo("#slider");

```

## *刚刚发生了什么？*

首先，我们将所有图片放在一个新的容器 `#viewer` 中。我们将使用此容器来动画显示面板的移动。我们给这个新容器一个 `id` 属性，这样我们就可以在需要时轻松地从**文档对象模型**（**DOM**）中选择它。

这是我们稍后将要动画显示的元素。

接下来，我们缓存一些经常需要操作的元素的选择器。我们创建一个指向外部 `#slider` 容器的单个 jQuery 对象，然后使用 jQuery 的 `find()` 方法选择我们要缓存的所有元素，如上一页和下一页箭头。

还初始化了一个 `key` 变量，它将用于跟踪当前显示的面板。最后，我们创建了一个 `details` 对象，其中包含内容查看器中每个图像的信息。我们可以存储 `slide` 容器必须以像素为单位进行动画显示任何给定面板的 `left` 位置，并且我们还可以存储每个内容面板的标题。

每个面板的标题是从每个图像的`alt`属性中读取的，但如果我们使用其他元素，我们可以选择`title`属性，或者使用 jQuery 的 data 方法来设置和检索内容的标题。

`<h2>`元素用于标题是通过 JS 创建并插入到内容查看器中的，因为我们没有办法在不使用 JavaScript 的情况下更改它。因此，当访问者禁用 JS 时，标题是无用的，并且最好根本不显示。

在代码的第一部分中，我们做的最后一件事是从下一个按钮中移除`hidden`类名，以便显示它。

前一个链接（我指的是让访问者移动到序列中上一个图像的链接）最初不显示，因为第一个内容面板始终是页面加载时可见的面板，因此没有上一个面板可移动到。

# 行动时间 - 定义一个动画后的回调

接下来，我们需要一个函数，每次动画结束时都可以执行。在我们之前添加的代码下面添加以下代码：

```js

function postAnim(dir) {

var keyMatch = parseInt(key.match(/\d+$/));

(parseInt(slide.css("left")) < 0) ? prev.show() : prev.hide();

(parseInt(slide.css("left")) === -1600) ? next.hide() : next.show();

if (dir) {

    var titleKey = (dir === "back") ? keyMatch - 1 : keyMatch + 1;

    key = "image" + titleKey;

}

container.find("#title").text(details[key].title);

container.find(".active").removeClass("active");

container.find("a[href=#" + key + "]").addClass("active");

};

```

## *刚刚发生了什么？*

在代码的第二部分中，我们定义了一个函数，该函数在动画结束后调用。这用于进行一些可能需要重复执行的各种事务处理；因此，将它们捆绑到单个函数中比在事件处理程序中单独定义它们更有效。这是`postAnim()`函数，它可能接受一个参数，该参数指示滑块移动的方向。

这个函数中我们要做的第一件事是使用 JavaScript 的`match()`函数与正则表达式`/\d+$/`来从保存在`key`变量中的字符串中解析面板编号，我们在代码的第一部分中初始化了`key`变量，它始终指向当前可见的面板。

我们的`postAnim()`函数可能在使用数字链接选择面板时调用，也可能在使用上一个/下一个链接时调用。但是，当使用上一个/下一个链接时，我们需要`key`变量来知道当前显示的是哪个面板，以便移动到下一个或上一个面板。

然后我们检查第一个面板是否当前正在显示，方法是检查`#slide`元素的`left` CSS 样式属性。如果`#slide`元素为`0`，我们知道第一个面板是可见的，所以隐藏上一个链接。如果`left`属性小于`0`，我们显示上一个链接。我们进行类似的测试来检查最后一个面板是否可见，如果是，则隐藏下一个链接。只有当前隐藏的上一个和下一个链接才会显示。

然后我们检查是否已向函数提供了`dir`（方向）参数。如果有，我们必须通过阅读我们之前创建的`keyMatch`变量来确定当前显示的面板是哪个，然后根据`dir`参数是`back`还是`forward`来减去`1`或加上`1`。

结果保存回`key`变量，然后用于更新`<h2>`标题元素。当前面板的标题文本从我们的`details`对象中使用`key`变量获取。最后，我们将`active`类名添加到与可见面板对应的数字链接中。

虽然不是必要的，但在我们添加小部件皮肤时会用到。我们使用属性选择器选择正确的链接，该选择器与当前链接的`href`属性匹配。请注意，在此函数中我们不会创建任何新的 jQuery 对象；我们使用我们缓存的`container`对象和`find()`方法来获取我们需要的元素。

# 行动时间 - 为 UI 元素添加事件处理程序

现在滑块已经创建好了，我们可以添加驱动功能的事件处理程序了。将以下代码插入我们刚刚添加的`postAnim`函数下方：

```js

$("#ui li a").not(prevChild).not(nextChild).click(function(e){

e.preventDefault();

key = $(this).attr("href").split("#")[1];

slide.animate({

    left: details[key].position

}, "slow", "easeOutBack", postAnim);

});

nextChild.add(prevChild).click(function(e){

e.preventDefault();

var arrow = $(this).parent();

if (!slide.is(":animated")) {

    slide.animate({

    left: (arrow.attr("id") === "prev") ? "+=400" : "-=400"

    }, "slow", "easeOutBack", function(){

    (arrow.attr("id") === "prev") ? postAnim("back") : postAnim("forward")

    });

}

});

```

## *刚刚发生了什么？*

第一个处理程序绑定到用于显示不同面板的主链接上，使用 jQuery 的`not()`方法排除了上一个和下一个链接。我们首先使用`preventDefault()`方法停止浏览器跟随链接。

然后，我们从链接的`href`属性中提取面板名称来更新`key`变量。我们使用 JavaScript 的`split()`方法仅获取面板`id`而不是`#`符号。

最后，我们通过将其`left` CSS 样式属性设置为从`details`对象中提取的值来对滑动元素进行动画处理。我们使用`key`变量来访问`position`属性的值。

作为动画的一部分，我们将持续时间配置为 `slow`，将缓动配置为 `easeOutBack`，并将我们的 `postAnim` 函数指定为动画结束时要执行的回调函数。

最后，我们需要为用于导航到下一个或上一个图片的上一个/下一个链接添加点击处理程序。这两个链接可以共享一个单击处理程序。我们可以使用之前缓存的选择器 `nextChild` 和 `prevChild`，以及 jQuery 的 `add()` 方法来选择这两个链接，将它们都添加到一个 jQuery 对象中，以便将处理程序函数附加到这两个链接上。

我们再次使用 `preventDefault()` 阻止浏览器跟随链接。然后，我们使用 `arrow` 变量缓存对已点击链接的父级的引用，以便我们稍后可以轻松地引用它。这是因为在 `animate()` 方法的回调函数中，`$(this)` 关键字的作用域将是 `#slide` 元素，而不是被点击的链接。

然后，我们检查 `#slide` 元素是否正在进行动画处理，使用 `:animated` 过滤器进行检查。此检查很重要，因为它防止了查看器在重复点击其中一个链接时出现错误。

如果尚未进行动画处理，我们执行动画处理并将幻灯片元素向后或向前移动 `400` 像素（单个内容面板的 `width` 参数）。我们可以通过查看 `arrow` 变量引用的元素的 `id` 属性来检查点击了哪个箭头。

我们在动画方法中指定与之前相同的持续时间和缓动值，但是我们不是将 `postAnim` 函数的引用作为回调参数传递，而是传递一个匿名函数。在这个匿名函数中，我们确定点击了哪个链接，然后使用适当的参数调用 `postAnim` 函数。记住，这是必要的，以获取 `details` 对象的正确键，因为上一个链接和下一个链接都没有指向图片的 `href` 属性。

此时在浏览器中尝试页面，你会发现点击任何链接，包括上一个和下一个链接，都可以查看图片。这是小部件在此阶段应该出现的样子：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642_07_01.jpg)

前一个屏幕截图显示了小部件处于未经过皮肤处理的状态，只有为其功能所需的 JavaScript。

# 为小部件添加皮肤

曾经有人说过，“杀鸡焉用牛刀”，这适用于小部件，也适用于猫。最后，让我们给小部件添加一些自定义样式，看看如何轻松地使小部件既有吸引力，又具有功能性。这些样式可以轻松更改，以重新设计小部件，赋予它完全不同的外观。

# 行动时间——添加新皮肤

在 `animate-position.css` 文件的底部，添加以下代码：

```js

a { outline:0 none; }

#slider {

border:1px solid #999;

-moz-border-radius:8px;

-webkit-border-radius:8px;

border-radius:8px;

background-color:#ededed;

-moz-box-shadow:0 2px 7px #aaa;

-webkit-box-shadow:0 2px 7px #aaa;

box-shadow:0 2px 7px #aaa;

}

#title, #slider ul {

margin-top:10px;

margin-bottom:12px;

}

#title {

font:normal 22px "Nimbus Sans L", "Helvetica Neue",

"Franklin Gothic Medium", Sans-serif;

color:#444;

}

#viewer {

border:1px solid #999;

background-color:#fff;

}

#slider ul { width:120px; }

#slider ul li a {

display:block;

width:10px;

height:10px;

text-indent:-5000px;

text-decoration:none;

border:2px solid #666;

-moz-border-radius:17px;

-webkit-border-radius:17px;

border-radius:17px;

background-color:#fff;

text-align:center;

}

#slider #prev, #slider #next {

margin:0;

text-align:center;

}

#slider #prev { left:10px; }

#slider #prev a, #slider #next a {

display:block;

height:28px;

width:28px;

line-height:22px;

text-indent:0;

border:1px solid #666;

-moz-border-radius:17px;

-webkit-border-radius:17px;

border-radius:17px;

background-color:#fff;

}

#prev a, #next a {

font:bold 40px "Trebuchet MS", sans-serif;

color:#666;

}

#slider ul li a.active { background-color:#F93; }

```

## *刚刚发生了什么？*

使用此代码，我们可以在不干扰任何控制其工作的内容的情况下为部件的所有视觉方面添加样式。我们为它添加了一些漂亮的圆角，并向部件添加了一个阴影，将数字链接变成了可点击的小图标，并为上一个和下一个链接设置了样式。颜色和字体也在此部分设置，因为它们显然也高度依赖于主题。

这些样式为部件添加了基本的中性主题，如下面的屏幕截图所示：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642_07_02.jpg)

我们用来创建主题的样式是纯粹任意的，仅用于示例目的。它们可以根据需要在任何给定的实现中更改，以适应页面上的其他元素或站点的整体主题。

## 快速测验 - 创建一个动画内容查看器

Q1\. `animate()` 方法可能传递哪些参数？

1.  数组，其中数组项是要进行动画处理的元素、持续时间、缓动以及回调函数

1.  第一个参数是一个包含要进行动画处理的样式属性的对象，可选地跟随着持续时间、缓动类型和回调函数

1.  一个对象，其中每个属性都指向要进行动画的样式属性、持续时间、缓动以及回调函数

1.  必须返回要进行动画处理的样式属性、持续时间、缓动以及回调函数的函数

Q2\. `animate()` 方法返回什么？

1.  包含已进行动画处理的样式属性的数组

1.  已进行动画处理的元素的数组

1.  用于链接目的的 jQuery 对象

1.  一个布尔值，指示动画是否成功完成

## 有一个尝试的英雄 - 使图像查看器更具可伸缩性

在我们的动画内容查看器中，有固定数量的图片和硬编码的导航结构来访问它们。扩展内容查看器，使其能够使用不确定数量的图片。要做到这一点，您需要完成以下任务：

+   在运行时确定内容查看器中的图像数量，并根据图像数量设置`#slide`包装元素的`width`参数

+   根据图像数量动态构建导航链接

+   动态创建`details`对象，根据图像数量设置正确的`left`属性来显示每个图像

# 动画元素大小

就像在本章开头提到的那样，几乎任何包含纯数值的样式属性都可以使用`animate()`方法进行动画处理。

我们先看了如何通过操纵`left`样式属性来动画元素的位置，现在让我们继续看看如何通过操纵`height`和`width`样式属性来动画元素的大小。

在这个例子中，我们将创建图像包装器，可以通过操纵元素的大小来显示页面上任何图像的大尺寸版本。

# 时间行动 - 创建基础页面和基本样式

首先，我们将创建示例运行的基础页面。

1.  将以下 HTML 代码添加到我们模板文件的`<body>`标签中：

    ```js

    <article>

    <h1>文章标题</h1>

    <p><img id="image1-thumb" class="expander" alt="An ASCIIZebra" src="img/ascii.gif" width="150" height="100">Lorem

        ipsum dolor...</p>

    <p><img id="image2-thumb" class="expander" alt="An ASCII

    Zebra" src="img/ascii2.gif" width="100" height="100">Lorem

    ipsum dolor...</p>

    </article>

    ```

1.  将示例页面保存为`animate-size.html`。在这个示例中，我们将保持样式轻巧；在您的文本编辑器中的新文件中，添加以下代码：

    ```js

    article {

    display:block;

    width:800px;

    margin:auto;

    z-index:0;

    font:normal 18px "Nimbus Sans L", "Helvetica Neue",

        "Franklin Gothic Medium", sans-serif;

    }

    article p {

    margin:0 0 20px;

    width:800px;

    font:15px Verdana, sans-serif;

    line-height:20px;

    }

    article p #image2-thumb {

    float:right;

    margin:6px 0 0 30px;

    }

    img.expander {

    margin:6px 30px 1px 0;

    float:left;

    }

    .expander-wrapper {

    position:absolute;

    z-index:999;

    }

    .expander-wrapper img {

    cursor:pointer;

    margin:0;

    position:absolute;

    }

    .expander-wrapper .expanded { z-index:9999; }

    ```

1.  将此文件保存为`animate-size.css`放在`css`文件夹中。

## *刚才发生了什么？*

HTML 可以是任何简单的博客文章，由一些文本和几张图片组成。要注意的是，每个图片都被赋予了一个`id`属性，以便可以轻松引用，并且每个图片实际上都是图片的全尺寸版本，通过`width`和`height`属性进行缩放。

所使用的样式纯粹是为了布置示例；实际上，使示例工作的代码很少。`expander-wrapper` 样式是为了正确定位叠加的图片而需要的，除此之外，样式完全是任意的。

我们把第二张图片向右浮动。再次强调，这并不是绝对必要的；仅仅是为了让示例更有趣一点。

# 行动时间 - 定义图片的完整大小和小尺寸

首先，我们需要指定每张图片的完整大小和小尺寸。将下面的代码放入我们刚刚创建的 HTML 文件内的匿名函数中：

```js

var dims = {

image1: {

    small: { width: 150, height: 100 },

    big: { width: 600, height: 400 }

},

image2: {

    小图：{ width: 100, height: 100 }，

    big: { width: 400, height: 400 }

}

},

webkit = ($("body").css("-webkit-appearance") !== "" && $("body").css("-webkit-appearance") !== undefined) ? true : false;

```

## *刚刚发生了什么？*

我们创建了一个包含与每张图片文件名匹配的属性的对象。每个属性中包含另一个嵌套对象，其中包含 `small` 和 `big` 属性以及相关整数作为值。这是一种方便的存储结构化信息的方式，可以很容易地在脚本的不同点访问。

我们还创建了一个名为 `webkit` 的变量。在基于 WebKit 的浏览器中，向右浮动的图片的处理存在轻微错误。这个变量将保存一个布尔值，指示是否使用了 WebKit。

执行了一个测试，尝试读取 `-webkit-appearance` CSS 属性。在 WebKit 浏览器中，测试将返回 `none`，因为该属性未设置，但其他浏览器将返回空字符串或值 `undefined`。

# 行动时间 - 创建叠加图片

接下来，我们应该在页面上创建每张图片的一个几乎完全相同的副本，以用作叠加层。将以下代码添加到我们刚刚添加到 HTML 文件中的代码下方：

```js

$(".expander").each(function(i) {

var expander = $(this)，

    coords = expander.offset()，

    复制 = $("<img>", {

    id: expander.attr("id").split("-")[0],

    src：expander.attr("src")，

    宽度：expander.width()，

    高度：expander.height()

    });

```

## *刚刚发生了什么？*

在这个 `<script>` 标签的一部分，我们选择页面上的每张图片，并使用 jQuery 的 `each()` 方法对它们进行处理。我们设置了一些变量，缓存了对当前图片的引用，并使用 jQuery 的 `offset()` 方法将其相对于文档的坐标存储在页面上。

然后，我们为页面上的每张现有图片创建一个新的图片，为其增加一个 `id` 属性，与它重叠的图片配对，原始图片的 `src` 变量以及原始图片的 `width` 和 `height` 参数。当设置新图片的 `id` 属性时，我们使用 JavaScript 的 `split()` 函数去掉字符串中标有 `thumb` 的部分。

### 注意事项

请注意，上述代码不代表完整的完全功能代码片段。`each()`方法传递给的外部函数尚未关闭，因为我们需要在这些变量之后添加一些额外的代码。

# 行动时间-创建覆盖包装器

现在我们需要为每个覆盖图像创建包装器（请注意，此代码仍在`each()`方法内，因此将为具有`expanded`类名的每个图像执行此代码）。直接在我们刚刚添加的`each`函数的最后一行下面添加以下代码：

```

$("<div></div>", {

    "class": "expander-wrapper",

    css: {

    top: coords.top,

    left: (webkit === true && expander.css("float") === "right") ? (coords.left + expander.width()) : coords.left,direction: (expander.css("float") === "right") ? "rtl" : "ltr"

    },

    html: copy,

    width: expander.width(),

    height: expander.height(),

    click: function() {

    var img = $(this).find("img"),

        id = img.attr("id");

    if (!img.hasClass("expanded")) {

        img.addClass("expanded").animate({

        width: dims[id].big.width,

        height: dims[id].big.height

        }, {

        queue: false

        });

    } else {

        img.animate({

        width: dims[id].small.width,

        height: dims[id].small.height

        }, {

        queue: false,

        complete: function() {

            $(this).removeClass("expanded");

        }

        });

    }

    }

}).appendTo("body");

```

## *刚刚发生了什么?*

在此代码部分中，我们为新图像创建包装器元素。我们给它一个新的类名，以便可以正确定位。

### 提示

**引用类属性**

我们需要在`class`属性名称周围使用引号，因为它是 JavaScript 中的保留字，如果不这样做可能会引发脚本错误。

我们使用`css`属性和从`offset()`方法中获取的坐标来设置包装器元素的位置。

设置包装器元素的`left`位置时，我们需要检查我们的`webkit`变量，以查看是否正在使用 Safari 或 Chrome。如果此变量设置为`true`，并且图像被浮动到右侧，我们将根据原始图像的`width`参数以及`cords.left`值定位覆盖层。如果`webkit`变量为`false`，或者原始图像浮动到`left`，我们只需将包装器的`left`位置设置为存储在`coords.left`中的值。

我们还需要设置任何浮动到右侧的图像的`direction`属性。我们检查`float`样式属性，并设置`direction`为`rtl`如果图像浮动到右侧，或者如果没有，则设置为`ltr`。这是使用 JavaScript，三元条件完成的。

这个检查是为了在图像浮动`right`时，使包装器从右向左扩展。如果我们没有设置这个，包装器将从左向右打开，这可能导致全尺寸图像溢出视口，或者内容容器出现滚动条。

通过将对其的引用传递到 jQuery 的`html()`方法中，我们将新图像添加到包装器中，并将包装器的`width`参数设置为原始（和新）图像的`width`参数。这对于正确定位覆盖在任何向右浮动的图像上是必要的。

接下来，我们向包装器添加一个点击处理程序。在作为`click()`方法值传递的匿名函数内部，我们首先缓存了在包装器中被点击的图像的引用，并为方便起见获取了图像的`id`属性。请记住，覆盖图像的`id`属性将与其覆盖的原始图像相同，减去文本字符串`-thumb`。

然后，我们检查图像是否具有类名`expanded`。如果没有，我们添加类名，然后使用`animate()`方法的第二种格式将图像动画变为其全尺寸。我们将两个对象作为参数传递给该方法；第一个包含我们希望动画的 CSS 属性，在本例中是图像的`width`和`height`参数。

获取要增加图像的正确`width`和`height`参数是使用被点击的图像的`id`属性作为键从`dims`对象中检索的。在传递给`animate()`方法的第二个对象中，我们将`queue`属性设置为`false`。这与直接在`animate()`方法之前使用`stop()`方法具有相同的效果，并确保在重复点击叠加包装器时不会发生任何不好的事情。

如果图像已经具有类名`expanded`，我们将图像动画变回其小尺寸。同样，我们使用`animate()`方法的两个对象格式，将`false`作为`queue`属性的值，并在传递给`complete`属性的匿名回调函数中删除类名`expanded`。创建包装器后，我们将其附加到页面的`<body>`标签。

在这一点上，我们编写的代码将按预期工作 - 单击图像将导致扩展版本动画变为其全尺寸。但是，如果页面被调整大小，叠加将不再覆盖其图像。

# 行动时间 - 维护叠加位置

由于叠加位置是绝对定位的，我们需要防止它们在窗口调整大小时错位：

```js

$(window).resize(function() {

$("div.expander-wrapper").each(function(i) {

    var newCoords = $("#image" + (i + 1) + "-thumb").offset();

    $(this).css({

    top: newCoords.top,

    left: newCoords.left

    });

});

});

```

## *刚刚发生了什么？*

我们所需要做的就是确保叠加图像在页面调整大小时直接位于原始图像的顶部，我们可以通过将调整事件的处理程序绑定到`window`对象来实现。在处理程序函数中，我们只需获取底层图像的新坐标，并相应地设置包装器的`top`和`left`属性。请注意，我们不会对叠加层的重新定位进行动画处理。

保存文件并在浏览器中预览。我们应该发现，我们可以点击任一图像，它都会展开显示图像的全尺寸版本，第一个图像展开到右侧，第二个图像展开到左侧：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642_07_03.jpg)

在前一个截图中，我们看到第一个图像展开到了它的全尺寸。

## 突击测验——创建展开图像

Q1\. 在这个例子中，我们使用了一个不同的格式来传递给 `animate()` 方法的参数。这些参数采用了什么样的格式？

1.  两个数组，第一个数组包含要动画的元素的选择器，第二个数组包含持续时间、缓动、`specialEasing` 字符串和回调函数

1.  包含要动画的样式属性、持续时间、缓动和 `specialEasing` 字符串，以及 `step` 和 `complete` 回调函数的单个对象

1.  必须返回要动画的样式属性、持续时间和缓动字符串以及回调函数的函数

1.  两个对象，第一个对象包含要动画的样式属性，第二个对象包含持续时间、缓动和 `specialEasing` 字符串，一个布尔值指示是否排队重复调用 `animate()`，以及步进和完成的回调函数

Q2\. 动画的回调函数中的关键字 `this` 被限定在哪个范围？

1.  被动画的元素

1.  当前窗口

1.  被动画的元素的容器

1.  事件对象

## 挑战英雄——消除硬编码的 dims 对象

在前一个例子中，我们在脚本顶部硬编码了一个图像，用于告诉 `animate()` 方法应该将图像动画到什么大小。虽然这在例子中是可以的，但作为长期解决方案，它并不是一个很好的扩展方式，因为我们必须记住每次使用脚本时都要设置它（或者确保我们的图像始终是固定大小的）。

问题在于我们没有办法从单个图像中编程方式获取全尺寸和缩略图尺寸。好消息是，任何可以存储在 JavaScript 对象中的数据也可以作为 JSON 对象传递到网络上供消费。扩展此示例，使页面加载时将页面上图像的 `src` 属性传递到服务器，服务器返回包含小图像和大图像尺寸的 JSON 对象。在这里，图像处理库，如 PHP 的 GD 或 ImageMagick，ImageResizer，或者 .NET 中的 `System.Drawing.Image` 类型，将是你的朋友。

# 创建一个 jQuery 动画插件

插件是将功能打包成易于部署和共享的代码模块的绝佳方式。jQuery 提供了 `fn.extend()` 方法来实现这一目的，使得创建强大而有效的插件变得轻而易举，这些插件可以轻松分发和使用。

创建 jQuery 插件时应遵循一些准则。具体如下：

+   新方法应像其他 jQuery 方法一样调用，例如，`$(elements).newMethod()`，应该附加到 `fn` 对象，而新函数，例如，`$.myFunction()`，应该附加到 `jQuery` 对象

+   当插件被压缩时，新方法和函数应始终以分号（`;`）结尾以保持功能性。

+   在方法内部，`this` 关键字始终指向当前元素的选择，并且方法应始终返回 `this` 以保留链式调用

+   除非使用带有别名 `$` 对象的匿名函数，否则始终将新方法和函数附加到 `jQuery` 对象，而不是 `$` 别名

在本节中，我们将创建一个插件，用于在显示一系列图像时创建高级转换效果。完成的小部件在某些方面类似于我们之前创建的图像查看器，但不会对图像本身进行动画处理。相反，它将在显示它们之间应用转换效果。

# 行动时间 - 创建一个测试页面并添加一些样式

再次，我们将首先创建示例页面和基本样式，然后最后再添加脚本。

1.  此示例的底层 HTML 非常简洁。在模板文件的 `<body>` 标记中，我们只需要以下元素：

    ```js

    <div id="frame">

        <img class="visible" src="img/F-35_Lightning.jpg" alt="F-35 Lightning">

        <img src="img/A-12_Blackbird.jpg" alt="A-12 Blackbird">

        <img src="img/B-2_Spirit.jpg" alt="B-2 Spirit">

        <img src="img/SR-71_Blackbird.jpg" alt="SR-71 Blackbird">

        <img src="img/F-117_Nighthawk.jpg" alt="F-117 Nighthawk">

    </div>

    ```

1.  将此页面保存为 `advanced-transitions.html`。

1.  像标记一样，我们为插件依赖的 CSS 也应尽可能简洁。幸运的是，我们的小型元素集合所需的 CSS 不多。

1.  将以下代码添加到文本编辑器中的新文件中：

    ```js

    #frame {

    位置：相对;

    宽度：520 像素;

    高度：400 像素;

    层级：0;

    }

    #frame img {

    位置：绝对;

    顶部：0;

    左：0;

    层级：1;

    }

    #frame img.visible { 层级：2; }

    #frame a {

    显示：块;

    宽度：50%;

    高度：100%;

    位置：绝对;

    顶部：0;

    层级：10;

    颜色：透明;

    背景图片：url(transparent.gif);

    滤镜：alpha(opacity = 0);

    文本对齐：居中;

    文本装饰：无;

    字体：90 像素 "Palatino Linotype"，"Book Antiqua"，

        帕拉蒂诺，衬线;

    行高：400%;

    }

    #frame a:hover {

    颜色：#fff;

    文本阴影：0 0 5 像素 #000;

    滤镜：alpha(opacity=100);

    滤镜：阴影（颜色=#000，方向=0）;

    }

    #frame a:focus { 轮廓：无; }

    #prev { 左：0; }

    #next { 右：0; }

    #overlay {

    宽度：100%;

    高度：100%;

    位置：绝对;

    左：0;

    顶部：0;

    层级：3;

    }

    #overlay div { 位置：绝对; }

    ```

1.  将其保存在 `css` 文件夹中，命名为 `advanced-transitions.css`。

## *刚发生了什么？*

我们在基础页面上唯一拥有的就是我们希望在容器内进行转换的图像。最好尽可能简化插件的标记要求，以便其他人可以轻松使用，并且不会对他们想要使用的元素或结构施加不必要的限制。

图像在容器内通过 CSS 绝对定位，使它们彼此叠加，并且我们在第一个元素上设置了`visible`类，以确保其中一个图像位于堆栈的顶部。

大多数样式都用于上一个和下一个锚点，我们将使用插件创建这些锚点。这些被设置为每个锚点将占据容器的一半，并且被定位为并排显示。我们设置这些链接的`z-index`属性，使它们显示在所有图像的上方。`font-size`属性被大幅提高，过多的`line-height`意味着我们不需要使用`padding`来使文本居中。

在大多数浏览器中，我们只需将锚点的`color`属性设置为`transparent`，即可隐藏它们。然后，我们在`hover`状态下将`color`属性设置为白色。然而，在 IE 中，这种方法效果不佳，因此我们最初将链接设置为透明，并使用 Microsoft 的`opacity` `filter`，然后在`hover`状态下将其设置为完全不透明，其目的相同。

### 注意

**另一个针对 IE 的修复**

IE 也给我们带来了另一个问题：由于链接的绝对定位，其可点击区域仅会延伸到其中的文本高度。我们可以通过设置背景图像的引用来克服这一问题。

最好的部分是即使图像不存在也可以使修复工作（因此您在书籍的附带代码包中找不到对应的`transparent.gif`文件）。该修复对于正常浏览器没有不利影响。

# 创建插件

现在，让我们创建插件本身。与我们看过的大多数其他示例代码不同，我们插件的代码将放入自己的单独文件中。

# 行动时间 – 添加许可证和定义可配置选项

在新文件中，创建插件的以下外部结构，并将其保存在名为`jquery.tranzify.js`的`js`文件夹中：

```js

/*

插件名称 jQuery 插件版本 1.0

版权所有（c）日期版权所有者

许可证

*/

;(function($) {

$.tranzify = {

    defaults: {

    transitionWidth: 40,

    transitionHeight: "100%",

    containerID: "overlay",

    transitionType: "venetian",

    prevID: "prev",

    nextID: "next",

    visibleClass: "visible"

    }

};

})(jQuery);

```

## *刚刚发生了什么？*

所有插件都应包含插件名称、版本号、版权所有者（通常为代码的作者）以及发布的许可证或许可证链接的条款信息。

插件被封装在一个匿名函数中，以便其变量受到在其部署的页面上可能正在使用的其他代码的保护。它还在其前面放置了一个分号，以确保在潜在的缩小之后它仍然保持为一个离散的代码块，并且以防它与比我们自己不那么严谨的其他代码一起使用。

我们还将`$`字符别名为安全地在我们的函数中使用，以确保它不会被页面上运行的任何其他库劫持，并保留 jQuery 的`noConflict()`方法的功能。

将插件尽可能地可配置是一个好习惯，以便最终用户可以根据自己的需求进行调整。为了方便起见，我们应该为任何可配置选项提供一组默认值。在决定将什么内容设为可配置时，一个好的经验法则是将除了纯逻辑之外的所有内容都硬编码到插件中。因此，ID、类名之类的东西应该可配置。

我们为插件设置的默认值存储在一个对象中，该对象本身作为传递给函数的`jQuery`对象的属性存储。添加到`jQuery`对象的属性称为`tranzify`，这是我们插件的名称，并将用于存储我们创建的属性、函数和方法，以便我们所有的代码都在一个单一的命名空间中。

我们的默认属性包含在一个名为`defaults`的单独对象中，该对象位于`tranzify`对象内部。我们设置了过渡元素的`width`和`height`参数，创建的容器的`id`属性，默认过渡效果，上一个和下一个链接的`id`属性，以及我们给当前显示的图像的类名。

正如我提到的，如果可能的话最好不要将任何`id`值或类名硬编码到插件中。实施插件的人可能已经在页面上有一个`id`属性为`overlay`的元素，因此我们应该给他们更改的选项。

# 行动时间 - 将我们的插件方法添加到 jQuery 命名空间

接下来，我们可以添加代码，将我们的插件插入到 jQuery 命名空间中，以便像其他 jQuery 方法一样调用它。在我们刚刚添加的代码的最后一行之上直接添加以下代码：

```js

$.fn.extend({

tranzify: function(userConfig) {

    var config = (userConfig) ? $.extend({}, $.tranzify.defaults, userConfig) : $.tranzify.defaults;

    config.selector = "#" + this.attr("id");

    config.multi = parseInt(this.width()) / config.transitionWidth;

    $.tranzify.createUI(config);

    return this;

}

});

```

## *刚刚发生了什么？*

jQuery 专门提供了`fn.extend()`方法来添加可以链接到`jQuery()`函数的新方法，这是大多数插件创建的方式。我们将一个函数定义为传递给`extend()`方法的对象的唯一属性的值。我们还指定该方法可能会接受一个参数，这个参数可能是由使用插件的人传递给方法的配置对象，以改变我们设置的默认属性。

我们的方法首先要做的是检查是否有配置对象传入方法中。如果有，我们使用`extend()`方法（不过这里不是`fn.extend()`）来将用户的配置对象与我们自己的`defaults`对象合并。

通过合并这两个对象创建的结果对象，存储在变量`config`中，以方便我们的函数访问。在`userConfig`对象中找到的任何属性将覆盖存储在`defaults`对象中的属性。在`defaults`对象中找到但在`userConfig`对象中找不到的属性将被保留。如果未传递`userConfig`对象到方法中，我们简单地将`defaults`对象赋值给`config`变量。

接下来，我们建立了一个`id`选择器，用来匹配被调用的方法的元素，并将其作为额外的属性添加到`config`对象中，这样在整个插件中使用起来更加方便。我们不能将这个作为默认属性存储，因为它很可能在插件使用的每个页面上都是不同的，而且我们也不能期望插件的用户每次使用插件时都要在配置对象中定义这个。

我们需要创建的过渡元素的数量将取决于图像的大小和过渡元素的宽度（定义为可配置属性），因此我们根据图像的宽度计算出一个快速乘数，然后配置过渡宽度以便稍后使用。

接着，我们调用将创建前/后链接的函数（我们将很快定义它），并传递函数，`config`对象，以便它可以读取用户配置的任何属性。

最后，我们返回 jQuery 对象（它会自动分配给插件方法内的`this`关键字的值）。这是为了保留链接，以便用户在调用我们的插件后可以调用其他 jQuery 方法。

# 行动时间–创建 UI

接下来，我们需要创建在图像上方叠加的前一个和后一个链接，让访问者可以浏览图像。在刚刚添加的`$.fn.extend()`部分下面，添加以下代码块：

```js

$.tranzify.createUI = function(config) {

var imgLength = $(config.selector).find("img").length,

    prevA = $("<a></a>", {

    id: config.prevID,

    href: "#",

    html: "«",

    click: function(e) {

    e.preventDefault();

    $(config.selector).find("a").css("display", "none");

    $.tranzify.createOverlay(config);

    var currImg = $("." + config.visibleClass, $(config.selector));

    if(currImg.prev().filter("img").length > 0) {

        currImg.removeClass(config.visibleClass).prev().addClass(config.visibleClass);

    } else {

        currImg.removeClass(config.visibleClass);

        $(config.selector).find("img").eq(imgLength - 1).addClass(config.visibleClass);

    }

    $.tranzify.runTransition(config);

    }

}).appendTo(config.selector),

nextA = $("<a></a>", {

    id: config.nextID,

    href: "#",

    html: "»",

    click: function(e) {

    e.preventDefault();

    $(config.selector).find("a").css("display", "none");

    $.tranzify.createOverlay(config);

    var currImg = $("." + config.visibleClass, $(config.selector));

    if(currImg.next().filter("img").length > 0) {

        currImg.removeClass(config.visibleClass).next().addClass(config.visibleClass);

    } else {

        currImg.removeClass(config.visibleClass);

        $(config.selector).find("img").eq(0).addClass(config.visibleClass);

    }

    $.tranzify.runTransition(config);

    }

}).appendTo(config.selector);

};

```

## *刚刚发生了什么？*

这是到目前为止我们的最大函数，处理创建前后链接以及在创建时使用 jQuery 语法定义它们的点击处理程序。我们要做的第一件事是获得容器中的图像数量，因为我们添加的点击处理程序需要知道这一点。

我们为上一个链接创建了锚点，并在作为第二个参数传递的对象中定义了`id`属性（使用来自`config`对象的值）、一个虚拟的`href`、一个 HTML 实体作为其`innerHTML`以及一个点击处理程序。

在点击处理程序中，我们使用`preventDefault()`方法阻止浏览器跟随链接，然后隐藏上一个和下一个链接，以保护小部件免受多次点击的影响，因为这会破坏过渡效果。

接下来，我们调用我们的`createOverlay()`函数，传递`config`对象，以创建叠加容器和过渡元素。我们还使用存储在`config`对象中的类名缓存对当前选择的图像的引用。

然后我们测试是否有另一个图像元素位于可见图像之前。如果有，我们从当前具有该类的元素中删除该类，并将其给予前一个图像，以将其移到堆栈顶部。如果在当前图像之前没有更多图像，则从当前图像中删除`visible`类，并移至容器中的最后一个图像以显示该图像。

一旦我们定义了所需的一切，我们就可以将新的锚点附加到指定的容器中。我们还在当前函数内创建了下一个链接，给它一个非常相似的一组属性和一个点击处理程序。在这个点击处理程序中唯一不同的是，我们测试当前图像后面是否有图像，并且如果没有图像，则移动到容器中的第一个图像。

# 行动时间 - 创建过渡覆盖

我们的下一个函数将处理创建叠加层和过渡元素：

```js

$.tranzify.createOverlay = function(config) {

var posLeftMarker = 0,

    bgHorizMarker = 0

overlay = $("<div></div>", {

    id: config.containerID

});

for (var x = 0; x < config.multi; x++) {

    $("<div></div>", {

    width: config.transitionWidth,

    height: config.transitionHeight,

    css: {

        backgroundImage: "url(" + $("." + config.visibleClass, $(config.selector)).attr("src") + ")",

        backgroundPosition: bgHorizMarker + "px 0",

        left: posLeftMarker,

        top: 0

    }

    }).appendTo(overlay);

    bgHorizMarker -=config.transitionWidth;

    posLeftMarker +=config.transitionWidth;

}

overlay.insertBefore("#" + config.prevID);

};

```

## *刚刚发生了什么？*

我们之前的函数处理了创建遮罩容器和将提供过渡动画的过渡元素。插件将需要分别设置每个过渡元素的 `position` 和 `background-position` 属性，以便水平堆叠元素。我们将需要一些计数器变量来实现这一点，因此我们在函数开始时对它们进行初始化。

然后，我们创建了遮罩容器 `<div>`，并且只给它设置了一个 `id` 属性，以便我们在运行过渡时可以轻松选择它。

接下来，我们创建过渡元素。为此，我们使用标准的 JavaScript `for` 循环，根据脚本中之前设置的乘数执行若干次。在循环的每次迭代中，我们创建一个新的 `<div>`，根据存储在配置对象中的属性设置其 `width` 和 `height` 参数。

我们使用 `css()` 方法将遮罩的 `backgroundImage` 属性设置为当前可见图像，并根据当前的 `bgHorizMarker` 计数器变量的值设置 `backgroundPosition` 属性。我们还设置 `left` 属性以正确地根据 `posLeftMarker` 变量定位新元素，并将 `top` 属性设置为 `0` 以确保正确的定位。

创建完成后，我们将新元素附加到容器并增加计数器变量。一旦循环退出，并且我们已经创建并附加了所有过渡元素到容器中，我们就可以将容器附加到页面上调用该方法的元素上。

# 行动时间 - 定义过渡

最终的函数将执行实际的过渡：

```js

$.tranzify.runTransition = function(config) {

var transOverlay = $("#" + config.containerID),

    transEls = transOverlay.children(),

    len = transEls.length - 1;

    switch(config.transitionType) {

    case "venetian":

    transEls.each(function(i) {

        transEls.eq(i).animate({

        width: 0

        }, "slow", function() {

        if (i === len) {

            transOverlay.remove();

            $(config.selector).find("a").css("display", "block");

        }

        });

    });

    break;

    case "strip":

    var counter = 0;

    function strip() {

    transEls.eq(counter).animate({

        height: 0

    }, 150, function() {

        if (counter === len) {

        transOverlay.remove();

        $(config.selector).find("a").css("display", "block");

        } else {

        counter++;

        strip();

        }

    });

    }

    strip();

}

};

```

## *刚刚发生了什么？*

我们的最后一个函数处理实际运行的过渡。 在这个例子中，只有两种不同类型的过渡，但我们可以很容易地扩展它以添加更多的过渡效果。

这个函数还需要一些变量，所以我们在函数的开头设置这些变量以供以后使用。 我们缓存对覆盖容器的引用，因为我们将多次引用它。 我们还存储了过渡元素的集合和过渡元素的数量。 我们从子项的数量中减去`1`，因为这个数字将与 jQuery 的`eq()`方法一起使用，该方法是基于零的。

为了确定我们要运行哪个过渡，我们使用 JavaScript 的`switch`语句并检查`config.transitionType`属性的值。 第一个过渡是一种**威尼斯百叶窗**效果。 要运行此过渡，我们只需使用 jQuery 的`each()`方法将每个元素的`width`参数动画化为`0`。 我们指定为此方法的参数的函数自动接收当前元素的索引，我们使用`i`来访问它。

对于每个动画的回调函数，我们检查`i`是否等于过渡元素的`length`，如果是，则移除覆盖层并再次显示上一个和下一个链接。

第二个过渡一次一个条带地移除旧图像。 为此，我们使用一个简单的`counter`变量和一个标准的 JavaScript 函数。 这次我们不能使用`each()`方法，否则所有的过渡元素将同时下滑，但我们希望每个元素都自己下滑。

在函数内部，我们将当前过渡元素的高度动画化为`0`，并设置一个相当低的持续时间，以便它发生得相当快。 如果动画太慢，它会破坏效果。 在回调函数中，我们检查我们的`counter`变量是否等于过渡元素的数量，如果是，则移除覆盖层并再次显示链接。 如果此时`counter`变量尚未达到最后一个元素，则递增`counter`变量并再次调用该函数。

将此文件保存为`jquery.tranzify.js`，并将其放在`js`文件夹中。 这是 jQuery 插件的标准命名约定，应遵循。

# 使用插件

要使用该插件，我们只需像调用任何其他 jQuery 方法一样调用它，在我们的 ready 函数或匿名函数内部，如下所示：

```js

<script>

$(function() {

    $("#frame").tranzify();

});

</script>

```

在这种形式下，将使用默认属性。 如果我们想要更改其中一个属性，我们只需提供一个配置对象，例如：

```js

$("#frame").tranzify({

transitionType: "strip"

});

```

默认动画应该运行如下：

![使用插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642_07_04.jpg)

在上一张截图中，我们看到过渡元素同时缩小到`0` `width`，产生了一种威尼斯百叶窗被打开以显示新图像的效果。

使用这个插件很简单；只需要记住一点。所有图像的大小都应该相同，并且每个图像的`width`参数都应该能够被`transitionWidth`属性完整地除尽。由于我们已经将`transitionWidth`属性公开为可配置属性，我们应该能够使用任何大小的图像，并相应地进行设置。

供参考，第二个过渡效果是这样运行的，旧图像的条纹滑开以显示新图像：

![使用该插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642_07_05.jpg)

在前面的截图中，我们可以看到第二种过渡类型的效果，旧图像被剥去以显示新图像。

## 爆笑测验 - 创建插件

Q1\.插件方法和函数有什么区别？

1.  在概念上和实践上，它们是一样的，没有区别

1.  方法可以接受参数，而函数不行

1.  方法执行更快

1.  方法附加到`fn`对象上，并像现有的 jQuery 方法一样使用，而函数直接附加到 jQuery 对象上，并像任何普通函数一样调用

Q2\.每个新方法必须返回什么？

1.  包含所选元素的`id`属性的字符串

1.  包含所选元素的`id`属性的数组

1.  `this`对象指向当前选择的元素

1.  什么都不应该被返回

## 有一个尝试英雄 - 扩展插件

我们的插件目前只包含了两种过渡效果（百叶窗和条纹）。扩展插件以包括自己设计的更多过渡效果。插件目前创建了一些与每个图像高度相同的过渡元素。

通过将现有的`for`循环包裹在另一个`for`循环中，并添加一些新的计数变量来控制`top`位置和垂直`background-position`，可以比较容易地以棋盘风格添加正方形过渡元素，这样就可以实现更复杂和更有吸引力的过渡效果。做到这一点。

# 总结

在本章中，我们看了一些`animate()`方法的常见用法，这是我们在 jQuery 中创建自定义动画的手段，当内置效果不能满足我们的要求时。这个方法强大、易于使用，并使复杂的动画变得轻而易举。

当简单的滑动或淡出不能满足我们的要求时，我们可以退而使用`animate()`方法来制作我们自己的高质量自定义动画。我们学到了关于`animate()`方法的以下要点：

+   `animate()`方法可用于动画化任何数字类型的 CSS 属性（除了颜色，需要使用 jQuery UI）。

+   传递到方法中的参数可以采用两种格式之一。第一种允许我们传递一个包含要执行动画的 CSS 属性的对象，以及单独的持续时间、缓动和回调参数。第二种格式允许我们传递两个对象，第一个对象允许我们像以前一样指定要执行动画的 CSS 属性，而第二个对象允许我们指定附加选项，比如持续时间、缓动和回调。第二种选项让我们可以访问一些在第一种格式中无法访问的特殊参数，比如`specialEasing`和`step`回调。

+   所有在第一个对象中指定的 CSS 属性将同时执行。

+   如何实现涉及元素位置或其尺寸的动画。

我们还研究了如何通过插件形式扩展 jQuery 库的全新功能和方法。插件是将代码封装起来以便轻松部署和共享的绝佳方式。

现在我们已经看过了所有 jQuery 的动画方法，在下一章中，我们将看看其他流行的动画，比如添加鼠标和键盘事件以及动画化帖子链接。


# 第八章：其他热门动画

*此章将遵循与上一章类似的格式，并由一系列示例式的示例组成，展示动画在实际操作中的实现。我们不会约束自己—一切皆有可能！*

我们将在本章中查看以下示例：

+   接近动画，其中动画是对鼠标指针接近目标元素或页面区域的反应

+   一个动画的页眉元素

+   文本滚动的跑马灯组件

# 理解近性动画

常按近性动画，这通常由鼠标指针相对于页面上一个元素或一系列元素的位置驱动，是一种令人敬畏的效果。虽然并非适用于所有网站和所有环境，但在特定情况下使用时，它可以增加真正的魅力。

这种效果通常并不非常实用，并且基本上关闭了非鼠标用户的大门，但它可以作为额外的奖励（通常称为渐进增强）实施给能够利用它的访客，同时提供其他更可访问的交互形式。

在本示例中，我们将创建一个图像滚动器，当鼠标指针进入其容器时将触发。图像滚动的速度将由鼠标指针与容器中心的距离决定。移动指针将相应地减慢或加快动画速度。

# 行动时间—创建和样式化页面

在本示例的这一部分中，我们将创建动画将在其上运行的基础页面，并添加样式。

1.  首先，我们将创建默认页面，并添加示例的 CSS。将以下元素添加到模板文件的`<body>`元素中：

    ```js

    <div id="proximity">

    <img src="img/proximity1.jpg" alt="CH-47 Chinook">

    <img src="img/proximity2.jpg" alt="Mi-24W">

    <img src="img/proximity3.jpg" alt="Mil Mi-24A">

    <img src="img/proximity4.jpg" alt="AH-1J Cobra">

    <img src="img/proximity5.jpg" alt="Mi-24P">

    <img src="img/proximity6.jpg" alt="AH-1Z Viper">

    <img src="img/proximity7.jpg" alt="AH-1W Cobra">

    <img src="img/proximity8.jpg" alt="UH-1Y Huey">

    <img src="img/proximity9.jpg" alt="AH-64 Apache">

    <img src="img/proximity10.jpg" alt="AH-1W Super Cobra">

    <img src="img/proximity11.jpg" alt="MI-28 Havoc">

    <img src="img/proximity12.jpg" alt="AH-1W Super Cobra">

    <img src="img/proximity13.jpg" alt="AH-1W Cobra">

    <img src="img/proximity14.jpg" alt="Mi-24 HIND E">

    <img src="img/proximity15.jpg" alt="AH-1W Super Cobra">

    <img src="img/proximity16.jpg" alt="UH-1N Huey">

    <img src="img/proximity17.jpg" alt="AH-64D Apache">

    <img src="img/proximity18.jpg" alt="UH-1N Huey">

    <img src="img/proximity19.jpg" alt=" Lempira Bell 412">

    <img src="img/proximity20.jpg" alt="UH-60L Blackhawk">

    </div>

    ```

1.  将此文件另存为`proximity.html`。接下来，我们将添加一些 CSS。在新文件中，添加以下代码：

    ```js

    /* 基础类（已禁用脚本） */

    #proximity {

    width:960px;

    margin:auto;

    border:1px solid #000;

    -moz-border-radius:8px;

    -webkit-border-radius:8px;

    border-radius:8px;

    }

    #proximity img { border:1px solid #000; }

    /* scripting enabled classes */

    #proximity.slider {

    width:550px;

    height:250px;

    position:relative;

    overflow:hidden;

    }

    .slider #scroller {

    position:absolute;

    left:0;

    top:0;

    }

    .slider #scroller img:

    display:block;

    width:150px;

    height:150px;

    margin:50px 0 0 50px;

    float:left;

    color:#fff;

    background-color:#000;

    }

    .slider #scroller img:first-child { margin-left:0; }

    #message {

    width:100%;

    height:30px;

    padding-top:10px;

    margin:0;

    -moz-border-radius:0 0 8px 8px;

    -webkit-border-bottom-radius:8px;

    -webkit-border-bottom-right-radius:8px;

    border-radius:0 0 8px 8px;

    position:absolute;

    bottom:0;

    left:0;

    background-color:#000;

    color:#fff;

    text-align:center;

    font:18px "Nimbus Sans L", "Helvetica Neue",

        "Franklin Gothic Medium", Sans-serif;

    }

    ```

1.  将其保存在`css`文件夹中，命名为`proximity.css`，并不要忘记从 HTML 页面的`<head>`中链接到它。

## *刚才发生了什么？*

保持 HTML 尽可能简单和轻便，我们只需将要显示的图像添加到一个容器元素中。我们需要的任何额外元素都可以以渐进增强的方式动态添加。

CSS 文件中有两个部分。第一部分是基本样式的集合，如果页面由禁用 JavaScript 的访问者加载，则使用这些样式。这确保所有图像都是可见的，因此可访问 - 没有隐藏或其他遮挡。

第二部分改变了容器元素的外观，并为动态添加的元素或类添加了样式，以改变滑块的外观，前提是启用了 JavaScript。

我们设置容器的`height`和`width`，以便任何时候只有三个图像可见，并将其`overflow`样式属性设置为`hidden`，以便所有其他图像都被隐藏，准备滚动到视图中。

我们还为具有`id`为`scroller`的元素添加了定位。此元素尚不存在，将由稍后查看的脚本添加。此元素还需要一个`width`，但我们可以根据容器中的图像数量动态分配。

我们还改变了图像本身的样式，将它们设置为块级元素，并将它们向左浮动，以便它们在一行中水平堆叠，而不会换行到两行，因为这样会破坏滚动条的功能。浮动图像并设置容器的`width`，允许它们按水平方向堆叠。我们将添加一个告诉访客如何使用滚动条的消息，因此我们还包括了一些用于此目的的样式。

以下截图显示了页面在禁用脚本时的外观：

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642_08_01.jpg)

在前面的图像中，我们可以看到所有图像都是可见的。这不太好看，但非常易于访问，并且在客户端禁用脚本时不会隐藏内容。

# 开始行动-为滑动功能准备页面

当脚本启用时，我们可以增强页面以添加近距离滑块所需的附加元素。将以下代码添加到 HTML 页面底部的空函数中：

```js

var prox = $("#proximity"),

scroller = $("<div></div>", {

    id: "scroller"

}),

pointerText = "使用指针滚动，移动到"+

    "边缘滚动更快！",

keyboardMessage = "使用箭头键滚动图像！",

message = $("<p></p>", {

    id: "message",

    text: keyboardMessage

});

prox.addClass("slider").wrapInner(scroller).append(message);

var middle = prox.width() / 2;

scroller = $("#scroller");

scroller.width(function() {

var total = 0;

scroller.children().each(function(i, val) {

    var el = $(this);

    total = total + (el.outerWidth() + parseInt(el.css("marginLeft")));

});

return total;

}).css("left", "-" + (scroller.width() / 2 - middle) + "px");

```

## *刚刚发生了什么？*

首先，我们缓存了近距离容器的选择器，在这段代码中我们会使用几次，在脚本稍后的地方还会使用几次。接下来，我们创建一个新的 `<div>` 元素，并给它一个 `id` 属性，这样我们在需要时可以轻松地再次选择它。我们还使用这个 `id` 进行样式处理。

接下来，我们为了方便起见，将一些文本字符串存储在变量中。这些将用作在不同点显示给访问者的消息。我们还创建一个新的段落元素作为消息文本的容器，为元素设置一个 ID（再次是为了选择的目的），并使用 jQuery 的`text()`方法设置其`innerText`为其中一个文本字符串。然后，我们在传递给元素创建 jQuery 方法格式的第二个参数的对象上使用`text`属性，它会自动映射到`text()`方法。

接下来，我们向外部近距离容器添加一个类名。请记住，这个类名用于区分脚本启用和禁用，以便我们可以添加所需的样式。我们还将近距离容器的内容（20 个 `<img>` 标签）包装在我们新创建的滚动条元素中，并将消息附加到近距离容器。

接下来，我们设置一个变量，它等于近距离容器的 `width` 除以二。这给了我们元素的水平中心，这将是我们需要在一些计算中使用的，以定位滚动条元素，并计算鼠标指针相对于近距离容器的位置。

我们可以很容易地设置`middle`变量需要包含的数字，而不是以这种方式计算它。接近容器的`width`（启用脚本）在我们的 CSS 文件中设置，并且与此特定示例高度任意。但是，如果我们直接在变量中设置数字而不是通过程序计算它，那么如果更改了其`width`，脚本将中断。尽量避免将“魔术”数字硬编码到脚本中是最好的。

此时，我们还需要缓存对滚动条元素的引用，因为它已附加到页面上。我们不能使用我们在脚本开始时创建的`scroller`变量的内容，因此我们通过再次从页面中选择该元素来用新引用覆盖它。

现在，我们需要设置`scroller`元素的`width`，以便它足够宽以容纳单行中的所有图像。为此，我们将一个函数传递给 jQuery 的`width()`方法，该函数返回要设置的`width`。

该函数通过迭代每个图像并将其`width`和水平`margin`相加到`total`变量中来计算此数字。这意味着可以使用不确定数量的图像而无需更改脚本，并且可以使用具有不同宽度和间距的图像。

设置了`scroller`元素的`width`后，我们需要将其定位，以使滚动条的中心位于接近容器的中心。这样，当页面加载时，访问者可以将其向左或向右移动，这取决于他们移动鼠标指针的位置或按下哪个箭头键。

如果此时在浏览器中加载页面，我们应该发现页面上元素的外观已更改。

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642_08_02.jpg)

在前一个屏幕截图中，我们可以看到接近容器已调整大小，并且`scroller`元素居中于其中。我们还可以看到接近容器底部的默认消息。

# 行动时间 - 动画滚动条

代码的下一部分涉及基于鼠标指针相对于外部接近容器的位置实际动画化`scroller`元素。在`}).css("left", "-" + (scroller.width()`行下面添加以下代码：

```js

function goAnim(e) {

var offset = prox.offset(),

    resetOffset = e.pageX - offset.left - middle,

    normalizedDuration = (resetOffset > 0) ? resetOffset :  -resetOffset,

    duration = (middle - normalizedDuration) * 50;

    scroller.stop().animate({

    left: (resetOffset < 0) ? 0 : "-" + (parseInt(scroller.width()) - parseInt(prox.width()))

    }, duration, "linear");

}

```

## *刚刚发生了什么？*

在 `goAnim()` 函数内部，我们首先获取接近容器的 `offset` 值，以便了解其相对于文档的位置。然后我们计算鼠标指针相对于接近容器中心的位置。这意味着在数值上，当鼠标指针位于中心时，指针偏移量将为 `0`。

如果鼠标指针位于接近容器的左半部分，`resetOffset` 变量中的数字将为负数。这将导致我们在函数后面的计算出现错误，因此我们需要检查 `resetOffset` 变量是否大于 `0`，如果不是，我们使用其负值来取反。

最终，我们希望随着指针移向接近容器的任一端，滚动条的速度增加，并且当指针移向中心时减速。换句话说，动画的速度需要与指针距离接近容器中心的距离成反比。

此时我们遇到的问题是，表示指针距离接近容器中心的数字随着指针移向边缘而增大，因此如果将此数字用作动画的持续时间，动画将减速而不是加速。

为了取反存储在 `normalizedDuration` 变量中的值，我们将其从表示接近容器中心的值中减去，然后将得到的数字乘以 `50`。持续时间参数以毫秒为单位，因此如果我们不使用乘数（`50` 是通过反复试验得出的），动画将发生得太快。

现在我们可以启动动画了。我们使用 JavaScript 三元运算符来测试 `resetOffset` 数字是否小于 `0`，如果是的话，我们知道要让滚动条向右滑动，只需将滚动条元素的 `left` 样式属性设置为 `0`。

如果变量大于 `0`，我们必须将滚动条元素向负方向移动（向左）以显示右侧隐藏的图像。为了使滚动条 `<div>` 元素的右边缘与接近容器的右边缘对齐，我们将动画的终点设置为滚动条 `<div>` 元素的 `width` 减去接近容器的 `width`。

# 行动时间 - 添加鼠标事件

现在，我们需要添加触发动画的鼠标事件。以下代码将添加在我们之前添加的两行代码下面：

```js

}, duration, "linear");

}

```

在上述代码的下面添加以下代码行：

```js

prox.mouseenter(function(e) {

message.text(pointerText).delay(1000).fadeOut("slow");

goAnim(e);

prox.mousemove(function(ev) {

    goAnim(ev);

});

});

prox.mouseleave(function() {

scroller.stop();

prox.unbind("mousemove");

});

```

## *刚刚发生了什么？*

首先，我们设置一个 `mouseeenter` 事件处理程序，以便我们可以检测指针最初进入接近容器的时候。当这种情况发生时，我们更改消息文本，以便显示指针该如何操作，然后在一秒的延迟后缓慢淡出消息。

我们然后调用我们的 `goAnim()` 函数来开始动画。此时，我们设置了一个 `mousemove` 事件，以便在接近容器内移动指针时增加或减少动画的速度。每次指针移动时，我们再次调用 `goAnim()` 函数。每次调用此函数时，我们都会传入事件对象。

我们还在接近容器上设置了一个 `mouseleave` 事件处理程序，以便我们可以检测指针何时完全离开此元素。当发生这种情况时，我们会停止当前正在运行的动画并解绑 `mousemove` 事件处理程序。

此时，我们应该有一个完全可用的接近滑块。稍早，我们讨论了接近效果仅对鼠标用户有用，因此让我们向脚本中添加一个键盘事件处理程序，以便键盘用户也可以导航滚动条。

# 行动时间 - 添加键盘事件

现在，我们将启用键盘驱动的动画。我们将专门为键盘上的左右箭头键添加触发器。

在我们刚刚在前一节中添加的 `prox.mouseleave` 函数下方添加以下代码：

```js

$(document).keydown(function(e) {

//37 = 左箭头 | 39 = 右箭头

if (e.keyCode === 37 || e.keyCode === 39) {

    message.fadeOut("slow");

    if (!scroller.is(":animated")) {

    scroller.stop().animate({

        left: (e.keyCode === 37) ? 0 : -(scroller.width() - prox.width())

    }, 6000, "linear");

    }

}

}).keyup(function() {

scroller.stop();

});

```

## *刚刚发生了什么?*

我们将 `keydown` 事件处理程序附加到 `document` 对象上，以便访问者不必以某种方式聚焦接近容器。在匿名函数内部，我们首先检查左箭头键或右箭头键是否被按下。

按键码 `37` 指的是左箭头键，而代码 `39` 指的是右箭头键。jQuery 规范化了 `keyCode` 属性，以便所有浏览器都可以访问，该属性将包含按下的任何键的代码，但我们只想对按下的这两个键中的任何一个做出反应。

当按下这两个键中的任何一个时，我们首先淡出消息，然后检查滚动条是否已经在使用 jQuery 的 `is()` 方法与 `:animated` 过滤器结合使用。

只要 `scroller` 元素尚未被动画化（在条件开始处使用 `!` 符号表示），我们就会对其进行动画处理。我们再次使用 JavaScript 三元条件来检查 `keyCode` 属性，以便根据按下的键移动滚动条的方向。

最后，我们添加了一个`keyup`事件处理程序，一旦释放键就停止滚动动画。这提高了动画的互动性，因为它允许访问者在希望时直观地停止滚动器。

## 尝试一下英雄 – 扩展接近动画

扩展我们示例的明显方法是在垂直轴上触发动画。我们可以有一个图像网格而不是单行，并且还可以向上和向下以及向左和向右移动网格。

扩展示例的一件事情是添加额外的键盘功能。例如，检查额外的键，如 home 和 end 键，这些键可以相应地导航到`scroller`元素的开头或结尾。

## 突击测验 – 实施接近动画

Q1\. 我们在上一个示例中通过添加键盘可导航性提供了额外的功能;为什么？

1.  为了好玩

1.  为了看起来好

1.  为了提供另一种内容被非使用鼠标的用户探索的方式

1.  当使用鼠标事件时，必须绑定键盘事件

Q2\. 为什么我们应该避免在脚本中硬编码'魔法'数字？

1.  为了使我们的代码更易读

1.  这样我们的脚本就不那么依赖于它们所操作的内容了

1.  编写硬编码的整数需要更长时间来处理

1.  因为 jQuery 更喜欢使用字符串

# 动画页面标题

另一种非常时尚的技术是在主页加载时在页面的页眉中运行动画。有时动画在站点的每一页上持续运行；在主页上只运行一次。

这种技术是使您的网站脱颖而出的一种简单有效的方式，它们不需要复杂或非常明显的动画；一个简短、微妙的动画就足以增加惊叹号！的因素。

本书的前面部分中，我们研究了在与一个预先编写的文件一起使用**cssHooks**的情况，该文件利用了 cssHooks，它扩展了 jQuery 的`css()`方法，以允许对元素的`background-position`样式属性进行动画处理。在这个例子中，我们将看看如何在不使用插件的情况下手动实现这一点。

设计良好的插件可以是一种有效且简便的解决方案，但有时插件添加的功能远远超出我们实际需要的范围，因此会增加页面的脚本开销。重复造轮子并不经常是必要或明智的，但有时编写一个只做我们需要的事情的自定义脚本是有益的。

# 行动时间 – 创建一个动画页眉

此示例的基础页面将相对简单，只有一个放置在`<body>`标签中的空的`<header>`元素，我们将手动对其`background-position`进行动画处理：

1.  示例页面的页眉将只包括一个空的`<header>`元素，放置在`<body>`标签内部：

    ```js

    <header>

    </header>

    ```

1.  将此保存为`animated-header.html`。CSS 更简单，只有一个选择器和几条规则：

    ```js

    header {

    display:block;

    width:960px;

    height:200px;

    margin:auto;

    background:url(../img/header.jpg) repeat 0 0;

    }

    ```

1.  将此保存为 `animated-header.css`。我们需要从我们刚创建的页面的 `<head>` 链接到该文件。

1.  脚本本身也非常简单。将以下代码添加到 `<body>` 元素末尾的函数中：

    ```js

    var header = $("header");

    header.css("backgroundPosition", "0 0");

    var bgscroll = function() {

    var current = parseInt(header.css(

        "backgroundPosition").split(" ")[1]),

        newBgPos = "0 " + (current - 1) + "px";

    header.css("backgroundPosition", newBgPos);

    };

    setInterval(function() { bgscroll() }, 75);

    ```

1.  当我们在浏览器中运行该文件时，应该会发现用于 `<header>` 的背景图片会缓慢滚动。

## *刚刚发生了什么？*

在脚本中，我们在主函数之外缓存 `header` 选择器以提高效率，这样我们不会在每次函数执行时都创建新的 jQuery 对象。虽然 `<header>` 元素在函数之外以变量形式缓存，但变量仍然可以被函数访问。

在函数中，我们首先获取 `header` 元素当前的垂直 `background-position`，使用 JavaScript 的 `split()` 函数提取我们需要的字符串部分。我们还使用 `parseInt` 将字符串转换为整数。

接着我们递减整数一次。这意味着背景图片会向上滚动。这并不重要。当然，图片也可以向下滚动，我个人只是偏好向上移动的动作。最后，我们使用 jQuery 的 `css()` 方法设置新的 `background-position`。

在函数定义之后，我们使用 JavaScript 的 `setInterval()` 方法每 75 毫秒调用一次函数。这相对来说很快，但非常顺滑，如果速度更快，动画会开始有点卡顿。然而，不同的背景图片可能不需要以如此快的速度运行。

## 尝试一下英雄 - 扩展动态页眉

由于示例太简单，可以进行许多延伸。根据所使用的背景图片，可以扩展为沿水平轴移动，甚至可能同时移动，也许朝西北方向对角线移动。

# 使用 marquee 效果实现文本动画

`<marquee>` 元素的使用在许多年前就已经消失了，但是最近几年，由于在知名网站上的应用，如新闻网站标题的滚动字幕和旧版 Twitter 首页上的动态热门话题，使用 JavaScript 创建的类似效果重新出现。

这是一种有效和吸引人的方式，可以向访问者呈现潜在相关的内容，而不会占用太多内容空间。当然，并不适用于所有网站，但适度使用，并尽可能不引人注意，可以产生很好的效果。

# 行动时间 - 创建和设计基础页面

在这个示例中，我们可以看到多么容易地抓取一系列文本字符串并以平滑滚动的走马灯样式显示它们。我们将使用 jQuery 内置的 AJAX 功能从我的博客的最新帖子中抓取一个 JSON 文件。让我们开始吧。

1.  在模板文件的 `<body>` 元素中添加以下标记：

    ```js

    <div id="outer">

    <header>

        <hgroup>

        <h1>网站标题</h1>

        <h2>网站描述</h2>

        </hgroup>

        <nav>主站导航在这里</nav>

    </header>

    <article>

        <h1>一篇博客文章标题</h1>

        <p>帖子内容</p>

    </article>

    <aside>

        <div>

        <h2>广告</h2>

        <p>可能有一堆广告在这里，占用旁白的合理部分垂直空间</p>

        </div>

        <div>

        <h2>热门文章</h2>

        <p>这里有一些链接到其他帖子的链接，这些帖子可能与当前帖子相关，也可能不相关，但基于评论数量，它们被认为是热门的</p>

        </div>

        <div>

        <h2>相关帖子</h2>

        <p>这里有一些链接到其他帖子的链接，这些链接与当前帖子肯定相关，基于帖子标签</p>

        </div>

        <div>

        <h2>Twitter 动态流</h2>

        <p>也许这里有一个显示最近推文或其他内容的 Twitter 动态流。现在旁白可能已经相当长了。</p>

        </div>

    </aside>

    </div>

    ```

1.  将新页面保存为 `marquee.html`。

1.  此时，我们还可以添加一些基本的 CSS 来以一种可接受的通用方式布局示例。在您的文本编辑器中的新文件中，添加以下代码：

    ```js

    #outer {

    width:960px;

    margin:auto;

    color:#3c3c3c;

    font:normal 17px "Palatino Linotype", "Book Antiqua",

        Palatino, serif;

    }

    header {

    display:block;

    padding:0 20px 0;

    margin-bottom:40px;

    border:3px solid #d3d1d1;

    background-color:#e5e5e5;

    }

    hgroup { float:left; }

    h1,

    h2 { margin-bottom:10px; }

    nav {

    display:block;

    width:100%;

    height:40px;

    clear:both;

    text-align:right;

    }

    article {

    width:700px;

    height:900px;

    border:3px solid #d3d1d1;

    background-color:#e5e5e5;

    float:left;

    }

    article h1,

    article p { margin:20px; }

    p, nav{

    font:normal 17px "Nimbus Sans L", "Helvetica Neue",

        "Franklin Gothic Medium", Sans-serif;

    }

    p { margin-top:0; }

    [旁白](https://example.org/aside) {

    width:220px;

    height:900px;

    border:3px solid #d3d1d1;

    background-color:#e5e5e5;

    float:right;

    }

    aside div { padding:0 20px 20px; }

    ```

1.  将此文件保存为 `marquee.css` 在 `css` 目录中。从我们刚刚创建的页面的 `<head>` 元素链接到这个样式表。

## *刚刚发生了什么？*

底层 HTML 表示一个典型的博客。我们添加了一系列元素有两个原因，主要是为了在这里插入走马灯，但也是为了我们能够看到为什么这种方法是必要的。

最新帖子在网站顶部滚动，确保此内容立即被看到，并且它是动画的事实也有助于吸引访问者的注意。

迄今为止所使用的 CSS 纯粹是为了以准确而略微美学的方式布局示例元素，为我们提供通用布局和轻微的外观设计。稍后我们将在示例中添加更多 CSS，用于我们动态创建的走马灯。此时，页面应该如下所示：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642_08_03.jpg)

记住，前一个屏幕截图中的所有元素都是为了插入跑马灯而存在的。它们不是特别必需的，并且仅用于此示例。

# 行动时间 - 检索和处理帖子列表

现在，我们已经准备好检索最新帖子列表并处理它们，使它们准备好作为跑马灯中的项目显示。为了从另一个域通过互联网访问这些数据，我们需要使用 **JSONP**，它代表 **JSON with Padding**，并涉及动态创建和注入 `<script>` 元素到页面中，尽管实际上是 jQuery 为我们处理了这个方面。

### 注意

更多关于 JSONP 的信息可以在这些精彩文章中找到：[`remysharp.com/2007/10/08/what-is-jsonp`](http://remysharp.com/2007/10/08/what-is-jsonp) 和 [`jquery4u.com/json/jsonp-examples`](http://jquery4u.com/json/jsonp-examples)

1.  jQuery 提供了对 JSONP 的原生支持，并允许我们绕过浏览器的同源安全策略。为了以正确的格式输出 JSON，我正在使用 WordPress 驱动的博客上的 JSON API ([`wordpress.org/plugins/json-api`](http://wordpress.org/plugins/json-api)) 插件，该插件以以下格式输出 JSON：

    ```js

    {

    "status": "ok",

    "count": 1,

    "count_total": 1,

    "pages": 1,

    "posts": [

        {

        "id": 1,

        等等...

        },

        {

        "id": 2,

        等等...

        }

        ]

    }

    ```

1.  在前一个代码块中显示的 `posts` 数组中还有更多的属性，以及外部对象中的其他数组和属性，但是前面的代码片段应该给您一个关于我们将要处理的数据结构的概念。

1.  将以下代码添加到我们 HTML 页面的匿名函数中：

    ```js

    $.getJSON("http://adamculpepper.net/blog?json=1&count=10&callback=?", function(data) {

    var marquee = $("<div></div>", {

        id: "marquee"

    }),

    h2 = $("<h2></h2>", {

        text: "最近的帖子："

    }),

    fadeLeft = $("<div></div>", {

        id: "fadeLeft"

    }),

    fadeRight = $("<div></div>", {

        id: "fadeRight"

    });

    for(var x = 0, y = data.count; x < y; x++) {

        $("<a></a>", {

            href: data.posts[x].url,

            title: data.posts[x].title,

            html: data.posts[x].title

        }).appendTo(marquee);

        }

    marquee.wrapInner("<div></div>").prepend(h2).append(fadeLeft).append(fadeRight).insertAfter("header").slideDown("slow");

    $("#marquee").find("div").eq(0).width(function() {

        var width = 0;

        $(this).children().each(function() {

        var el = $(this);

        width += el.width() + parseInt(el.css("marginRight"));

        });

        return width;

    });

    marquee.trigger("marquee-ready");

    });

    ```

1.  我们还可以添加一些更多的 CSS 样式，这次是为新创建的元素。在 `marquee.css` 的底部添加以下代码：

    ```js

    #marquee {

    display:none;

    height:58px;

    margin:-20px 0 20px;

    border:3px solid #d3d1d1;

    position:relative;

    overflow:hidden;

    background-color:#e5e5e5;

    }

    #marquee h2 {

    margin:0;

    position:absolute;

    top:10px;

    left:20px;

    }

    #marquee a {

    display:block;

    margin-right:20px;

    float:left;

    font:normal 15px "Nimbus Sans L", "Helvetica Neue",

        "Franklin Gothic Medium", Sans-serif;

    }

    #marquee div:

    margin:20px 0 0 210px;

    overflow:hidden;

    }

    #marquee div:after {

    content:"";

    display:block;

    height:0;

    visibility:hidden;

    clear:both;

    }

    #fadeLeft,

    #fadeRight {

    width:48px;

    height:21px;

    margin:0;

    position:absolute;

    top:17px;

    left:210px;

    background:url(../img/fadeLeft.png) no-repeat;

    }

    #fadeRight {

    left:906px;

    background:url(../img/fadeRight.png) no-repeat;

    }

    ```

1.  当我们现在运行页面时，我们应该看到新的滚动条元素及其链接被插入到页面中。![执行动作的时间 - 检索和处理帖子列表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq2-ani-tech-bgd/img/9642_08_04.jpg)

之前的截图显示了新滚动条部分中的元素，包括标题、链接本身和仅用于美观的淡出元素。

## *刚刚发生了什么？*

我们所有的 JavaScript 都包含在 jQuery 的`getJSON()`方法中，该方法使用 jQuery 的 AJAX 功能向指定为方法第一个参数的 URL 发出请求。第二个参数是一个匿名函数，如果请求成功，则执行该函数。返回的 JSON 数据会自动传递给此函数。

在函数内部，我们首先创建一些组成我们滚动条的元素，包括外部容器、标题和两个纯粹用于在链接行的开头和结尾添加左右淡出效果的`<div>`元素。所有这些元素都存储在变量中，以便在需要时轻松访问。

接下来，我们处理传递给函数的 JSON 对象。请记住，该对象包含一系列属性，其中一些属性的值是数组，比如`posts`数组，它包含每个返回的帖子作为其数组项中的对象。

我们使用`for`循环遍历返回的`posts`数组中的每个对象。此对象包含一个名为`count`的属性，其中以整数形式存储了返回的帖子数，因此我们可以使用这个来告诉`for`循环执行多少次，这比计算`posts`数组中的对象稍微容易一些。

对于返回的每个帖子，我们创建一个新的`<a>`元素，将其`href`设置为当前对象的`url`属性，将元素的`title`和`text`设置为当前对象的`title`属性，然后将新的`<a>`元素附加到我们一分钟前创建的`marquee`元素中。

一旦我们为每个帖子创建并附加了一个链接，我们就会将滚动条元素（链接）的内容包裹在一个新的`<div>`元素中，将`<h2>`元素前置到滚动条的开头，并将淡出的`<div>`元素追加到`marquee`元素的末尾。然后我们将滚动条附加到页面，然后使用`slideDown()`方法将其滑入视图中。

在这一点上，我们需要在我们刚刚包裹链接的容器的`<div>`元素上设置一个`width`。这样，链接就可以排成一行。我们需要考虑每个链接的`width`值，加上它的任何`margin`（我们在 CSS 中设置的）。

我们使用一个函数作为 jQuery 的`width()`方法的值，来迭代每个链接，并将其`width`和`margin`添加到一个运行总数中。直到滚动字幕被添加到页面上，我们才能执行此操作，因为在此时每个元素实际上才具有我们可以检索的`width`或`margin`。

我们在`getJSON()`方法的回调函数中最后要做的一件事是，使用`trigger()` jQuery 方法触发一个自定义事件。自定义事件称为`marquee-ready`，用于告诉我们的脚本`marquee`已被添加到页面中。我们将很快使用这个自定义事件来对帖子链接进行动画处理。

我们还在样式表中添加了一些新的 CSS。其中一些代码是为了给我们的`marquee`元素提供与页面其余部分相同的浅色皮肤。但其中的其他部分，比如浮动链接，并将 marquee 的`overflow`属性设置为`hidden`，是为了使链接排成一行，并且大多数链接都是隐藏的，准备好滚动到视图中。我们还将淡入的图片添加到`marquee`元素内的最后两个`<div>`元素中。

# 行动时间 - 动画化帖子链接

我们现在准备开始在 marquee 中滚动帖子链接。我们可以使用我们的自定义事件来完成这个任务。

1.  在`getJSON()`方法之后，向页面添加以下代码：

    ```js

    $("body").on("marquee-ready", "#marquee", function() {

    var marquee = $(this),

        postLink = marquee.find("a").eq(0);

        width = postLink.width() + parseInt(postLink.css("marginRight")),

        time = 15 * width;

    postLink.animate({

        marginLeft: "-=" + width

    }, time, "linear", function() {

        $(this).css({

        marginLeft: 0

        }).appendTo(marquee.find("div").eq(0));

        marquee.trigger("marquee-ready");

    });

    });

    ```

1.  我们的示例现在已经完成。当我们此时运行页面时，帖子应该会从左向右滚动。

## *刚发生了什么？*

我们使用 jQuery 的`on()`方法将事件处理程序绑定到我们的自定义`marquee-ready`事件上。我们需要使用`on()`事件来实现这一点，因为当此部分代码被执行时，JSON 响应不太可能返回，因此`marquee`元素甚至都不存在。将事件处理程序附加到页面的`<body>`元素是准备页面准备好`marquee`元素时的一种简单方法。

在匿名事件处理函数内部，我们首先使用`this`对象（作用域限于我们的`marquee`元素）缓存了对 marquee 元素的引用。然后，我们选择滚动字幕中的第一个链接，并确定其包括`margin`在内的总`width`。

我们还计算了动画的有效速度。jQuery 动画使用持续时间来确定动画运行的速度，但这给我们带来的问题是，标题较长的帖子将移动得更快，因为它们在相同时间内需要动画的距离更长。

为了解决这个问题，我们计算出一个持续时间，以传递给动画方法，该持续时间基于任意速度`15`乘以当前`<a>`元素的`宽度`。这确保了每篇文章无论有多长，都以相同的速度滚动。

一旦我们获得了总`width`和`duration`，我们就可以在`marquee`中运行动画，使用我们的`width`和`time`变量来配置动画。我们通过设置第一个链接的负`margin`来动画帖子链接，这将所有其他链接一起拉动。

一旦动画完成，我们从链接中删除`margin-left`，将其重新附加到`marquee`元素中的`<div>`的末尾，并再次触发`marquee-ready`事件以重复此过程。这一过程反复发生，创建了持续的动画，将我们带到了这个示例的结尾。

## 尝试一下 - 扩展跑马灯滚动器

对我们的用户肯定有益处的一个功能是，如果鼠标指针悬停在帖子标题上时，帖子标题停止动画。当鼠标指针再次移开标题时，动画可以重新启动。尝试自己添加此功能。这一点一点也不难，只需添加`mouseenter`和`mouseleave`事件处理程序即可。

您需要计算任何给定链接已经在跑马灯的可见区域之外的部分有多少，以确保动画以与停止时相同的速度重新启动，但这应该与我们在本例中计算持续时间的方式非常相似。看看你能做到什么。

## 快速测验 - 创建跑马灯滚动器

Q1\. 为什么我们创建了一个动态持续时间变量（时间），而不是使用 jQuery 的预定义持续时间之一？

1.  因为使用整数更快，即使必须计算该整数，也比使用其中一个持续时间字符串更快

1.  因为这更有趣

1.  确保链接在被动画后附加到正确的元素上

1.  为了确保所有链接无论有多长都以相同的速度进行动画

# 摘要

在本章中，我们的第二个重点是基于实例而不是理论的章节，我们看了一些在网络上越来越常见的动画。具体来说，我们看了以下类型的动画：

+   一个基于接近距离的图像滚动器，其中图像根据鼠标指针的移动方向和速度滚动

+   背景位置动画，在此我们只需几行代码手动创建了一个连续的页眉动画

+   一个文本跑马灯，其中一系列的头条新闻从实时互联网源中抓取，并显示在滚动的跑马灯式横幅中。

在下一章中，我们将开始研究一些纯 CSS 动画，这些动画是由 CSS3 引入的，以及如何使用 jQuery 来增强它们，并通常使与它们一起工作更容易。
