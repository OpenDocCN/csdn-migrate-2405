# jQuery3 学习手册（三）

> 原文：[`zh.annas-archive.org/md5/B3EDC852976B517A1E8ECB0D0B64863C`](https://zh.annas-archive.org/md5/B3EDC852976B517A1E8ECB0D0B64863C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用插件

在本书的前六章中，我们审视了 jQuery 的核心组件。这样做已经说明了 jQuery 库可以用来完成各种任务的许多方法。尽管库在其核心处非常强大，但其优雅的**插件架构**使开发人员能够扩展 jQuery，使其功能更加丰富。

jQuery 社区创建了数百个插件——从小的选择器辅助工具到完整的用户界面部件。现在，您将学习如何利用这一庞大资源。

在本章中，我们将介绍：

+   下载和设置插件

+   调用插件提供的 jQuery 方法

+   使用由 jQuery 插件定义的自定义选择器查找元素

+   使用 jQuery UI 添加复杂的用户界面行为

+   使用 jQuery Mobile 实现移动友好功能

# 使用插件

使用 jQuery 插件非常简单。我们只需要获取插件代码，从我们的 HTML 中引用插件，并从我们自己的脚本中调用新的功能。

我们可以使用 jQuery **Cycle** 插件轻松演示这些任务。这个由 Mike Alsup 制作的插件可以快速地将静态页面元素集合转换为交互式幻灯片。像许多流行的插件一样，它可以很好地处理复杂的高级需求，但当我们的需求更为简单时，它也可以隐藏这种复杂性。

# 下载并引用 Cycle 插件

要安装任何 jQuery 插件，我们将使用 `npm` 包管理器。这是声明现代 JavaScript 项目的包依赖关系的事实上的工具。例如，我们可以使用 `package.json` 文件声明我们需要 jQuery 和一组特定的 jQuery 插件。

要获取有关安装 `npm` 的帮助，请参阅 [`docs.npmjs.com/getting-started/what-is-npm`](https://docs.npmjs.com/getting-started/what-is-npm)。要获取有关初始化 `package.json` 文件的帮助，请参阅 [`docs.npmjs.com/getting-started/using-a-package.json`](https://docs.npmjs.com/getting-started/using-a-package.json)。

一旦在项目目录的根目录中有了 `package.json` 文件，您就可以开始添加依赖项了。例如，您可以从命令控制台如下添加 `jquery` 依赖项：

```js
npm install jquery --save

```

如果我们想要使用 `cycle` 插件，我们也可以安装它：

```js
npm install jquery-cycle --save

```

我们在此命令中使用 `--save` 标志的原因是告诉 `npm` 我们始终需要这些包，并且它应该将这些依赖项保存到 `package.json`。现在我们已经安装了 `jquery` 和 `jquery-cycle`，让我们将它们包含到我们的页面中：

```js
<head> 
  <meta charset="utf-8"> 
  <title>jQuery Book Browser</title> 
  <link rel="stylesheet" href="07.css" type="text/css" /> 
  <script src="img/jquery.js"></script> 
  <script src="img/index.js"></script> 
  <script src="img/07.js"></script> 
</head>

```

我们现在已经加载了我们的第一个插件。正如我们所看到的，这不再比设置 jQuery 本身更复杂。插件的功能现在可以在我们的脚本中使用了。

# 调用插件方法

Cycle 插件可以作用于页面上的任何一组兄弟元素。为了展示它的运行过程，我们将设置一些简单的 HTML，其中包含书籍封面图像和相关信息的列表，并将其添加到我们 HTML 文档的主体中，如下所示：

```js
<ul id="books"> 
  <li> 
    <img src="img/jq-game.jpg" alt="jQuery Game Development  
      Essentials" /> 
    <div class="title">jQuery Game Development Essentials</div> 
    <div class="author">Salim Arsever</div> 
  </li> 
  <li> 
    <img src="img/jqmobile-cookbook.jpg" alt="jQuery Mobile  
      Cookbook" /> 
    <div class="title">jQuery Mobile Cookbook</div> 
    <div class="author">Chetan K Jain</div> 
  </li> 
  ... 
</ul>

```

在我们的 CSS 文件中进行轻量级样式处理，按照以下截图所示，依次显示书籍封面：

![图片](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_07_001-3.jpg)

Cycle 插件将会在此列表上发挥其魔力，将其转换为一个引人注目的动画幻灯片。通过在 DOM 中适当的容器上调用 `.cycle()` 方法，可以调用此转换，如下所示：

```js
$(() => { 
  $('#books').cycle(); 
});

```

列表 7.1

这种语法几乎没有更简单的了。就像我们使用任何内置的 jQuery 方法一样，我们将 `.cycle()` 应用于一个 jQuery 对象实例，该实例又指向我们要操作的 DOM 元素。即使没有向它提供任何参数，`.cycle()` 也为我们做了很多工作。页面上的样式被修改以仅呈现一个列表项，并且每 4 秒使用淡入淡出的转换显示一个新项：

![图片](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_07_002-1.jpg)

这种简单性是写得很好的 jQuery 插件的典型特征。只需简单的方法调用就能实现专业且有用的结果。然而，像许多其他插件一样，Cycle 提供了大量的选项，用于定制和微调其行为。

# 指定插件方法参数

将参数传递给插件方法与使用原生 jQuery 方法没有什么不同。在许多情况下，参数被传递为一个键值对的单个对象（就像我们在第六章中看到的 `$.ajax()`，*使用 Ajax 发送数据*）。提供的选项选择可能会令人生畏；`.cycle()` 本身就有超过 50 个潜在的配置选项。每个插件的文档详细说明了每个选项的效果，通常还附有详细的示例。

Cycle 插件允许我们改变幻灯片之间的动画速度和样式，影响何时以及如何触发幻灯片转换，并使用回调函数来响应完成的动画。为了演示其中一些功能，我们将从 *列表 7.1* 的方法调用中提供三个简单的选项，如下所示：

```js
$(() => { 
  $('#books').cycle({ 
    timeout: 2000, 
    speed: 200, 
    pause: true 
  }); 
});

```

列表 7.2

`timeout` 选项指定了在每个幻灯片转换之间等待的毫秒数（2,000）。相比之下，`speed` 决定了转换本身需要花费的毫秒数（200）。当设置为 `true` 时，`pause` 选项会导致幻灯片秀在鼠标位于循环区域内时暂停，当循环项可点击时尤其有用。

# 修改参数默认值

即使没有提供参数，Cycle 插件也是令人印象深刻的。为了实现这一点，当没有提供选项时，它需要一个合理的默认设置来使用。

一种常见的模式，也是 Cycle 遵循的模式，是将所有默认值收集到一个单一对象中。在 Cycle 的情况下，`$.fn.cycle.defaults` 对象包含所有默认选项。当插件将其默认值收集在像这样的公开可见位置时，我们可以在我们自己的脚本中修改它们。这样可以使我们的代码在多次调用插件时更加简明，因为我们不必每次都指定选项的新值。重新定义默认值很简单，如下面的代码所示：

```js
$.fn.cycle.defaults.timeout = 10000; 
$.fn.cycle.defaults.random = true; 

$(() => { 
  $('#books').cycle({ 
    timeout: 2000, 
    speed: 200, 
    pause: true 
  }); 
});

```

列表 7.3

在这里，我们在调用`.cycle()` 之前设置了两个默认值，`timeout` 和 `random`。由于我们在`.cycle()` 中声明了 `timeout` 的值为 2000，我们的新默认值 10000 会被忽略。另一方面，`random` 的新默认值为 `true` 生效，导致幻灯片以随机顺序过渡。

# 其他类型的插件

插件不仅仅限于提供额外的 jQuery 方法。它们可以在许多方面扩展库甚至改变现有功能的功能。

插件可以改变 jQuery 库的其他部分操作的方式。例如，一些插件提供新的动画缓动样式，或者在用户操作响应中触发额外的 jQuery 事件。Cycle 插件通过添加一个新的自定义选择器来提供这样的增强功能。

# 自定义选择器

添加自定义选择器表达式的插件会增加 jQuery 内置选择器引擎的功能，使我们可以以新的方式在页面上查找元素。Cycle 添加了这种类型的自定义选择器，这给了我们一个探索这种功能的机会。

通过调用`.cycle('pause')` 和 `.cycle('resume')`，Cycle 的幻灯片可以暂停和恢复。我们可以轻松地添加控制幻灯片的按钮，如下面的代码所示：

```js
$(() => {
  const $books = $('#books').cycle({
    timeout: 2000,
    speed: 200,
    pause: true
  });
  const $controls = $('<div/>')
    .attr('id', 'books-controls')
    .insertAfter($books);

  $('<button/>')
    .text('Pause')
    .click(() => {
      $books.cycle('pause');
    })
    .appendTo($controls);
  $('<button/>')
    .text('Resume')
    .click(() => {
      $books.cycle('resume');
    })
    .appendTo($controls);
});

```

列表 7.4

现在，假设我们希望我们的“恢复”按钮恢复页面上任何暂停的 Cycle 幻灯片，如果有多个的话。我们想要找到页面上所有暂停的幻灯片的`<ul>` 元素，并恢复它们所有。Cycle 的自定义`:paused` 选择器使我们可以轻松做到这一点：

```js
$(() => { 
  $('<button/>')
    .text('Resume')
    .click(() => {
      $('ul:paused').cycle('resume');
    })
    .appendTo($controls);
});

```

列表 7.5

使用 Cycle 加载，`$('ul:paused')` 将创建一个 jQuery 对象，引用页面上所有暂停的幻灯片，以便我们可以随意进行交互。像这样由插件提供的选择器扩展可以自由地与任何标准的 jQuery 选择器结合使用。我们可以看到，选择适当的插件，jQuery 可以被塑造以满足我们的需求。

# 全局函数插件

许多流行的插件在`jQuery`命名空间中提供新的全局函数。当插件提供的功能与页面上的 DOM 元素无关，因此不适合标准的 jQuery 方法时，这种模式是常见的。例如，Cookie 插件（[`github.com/carhartl/jquery-cookie`](https://github.com/carhartl/jquery-cookie)）提供了一个界面，用于在页面上读取和写入 cookie 值。这个功能是通过`$.cookie()`函数提供的，它可以获取或设置单个 cookie。

比如说，例如，我们想要记住用户什么时候按下我们幻灯片的暂停按钮，以便如果他们离开页面然后过后回来的话我们可以保持它暂停。加载 Cookie 插件之后，读取 cookie 就像在下面代码中一样简单：只需将 cookie 的名称作为唯一参数使用即可。

```js
if ($.cookie('cyclePaused')) { 
  $books.cycle('pause'); 
}

```

列表 7.6

在这里，我们寻找`cyclePaused` cookie 的存在；对于我们的目的来说，值是无关紧要的。如果 cookie 存在，循环将暂停。当我们在调用`.cycle()`之后立即插入这个条件暂停时，幻灯片会一直保持第一张图片可见，直到用户在某个时候按下“恢复”按钮。

当然，因为我们还没有设置 cookie，幻灯片仍在循环播放图片。设置 cookie 和获取它的值一样简单；我们只需像下面这样为第二个参数提供一个字符串：

```js
$(() => {
  $('<button/>')
    .text('Pause')
    .click(() => {
      $books.cycle('pause');
      $.cookie('cyclePaused', 'y');
    })
    .appendTo($controls);
  $('<button/>')
    .text('Resume')
    .click(() => {
      $('ul:paused').cycle('resume');
      $.cookie('cyclePaused', null);
    })
    .appendTo($controls);
});

```

列表 7.7

当按下暂停按钮时，cookie 被设置为`y`，当按下恢复按钮时，通过传递`null`来删除 cookie。默认情况下，cookie 在会话期间保持（通常直到浏览器标签页关闭）。同样默认情况下，cookie 与设置它的页面相关联。要更改这些默认设置，我们可以为函数的第三个参数提供一个选项对象。这是典型的 jQuery 插件模式，也是 jQuery 核心函数。

例如，为了使 cookie 在整个站点上可用，并在 7 天后过期，我们可以调用`$.cookie('cyclePaused', 'y', { path: '/', expires: 7 })`。要了解在调用`$.cookie()`时可用的这些和其他选项的信息，我们可以参考插件的文档。

# jQuery UI 插件库

虽然大多数插件，比如 Cycle 和 Cookie，都专注于一个单一的任务，jQuery UI 却面对着各种各样的挑战。实际上，虽然 jQuery UI 的代码常常被打包成一个单一的文件，但它实际上是一套相关插件的综合套件。

jQuery UI 团队创建了许多核心交互组件和成熟的小部件，以帮助使网络体验更像桌面应用程序。交互组件包括拖放、排序、选择和调整项的方法。目前稳定的小部件包括按钮、手风琴、日期选择器、对话框等。此外，jQuery UI 还提供了一套广泛的高级效果，以补充核心的 jQuery 动画。

完整的 UI 库过于庞大，无法在本章中充分覆盖；事实上，有整本书专门讨论此主题。幸运的是，该项目的主要焦点是其功能之间的一致性，因此详细探讨几个部分将有助于我们开始使用其余的部分。

所有 jQuery UI 模块的下载、文档和演示都可以在此处找到

[`jqueryui.com/`](http://jqueryui.com/)。下载页面提供了一个包含所有功能的组合下载，或者一个可定制的下载，可以包含我们需要的功能。可下载的 ZIP 文件还包含样式表和图片，我们在使用 jQuery UI 的交互组件和小部件时需要包含它们。

# 效果

jQuery UI 的效果模块由核心和一组独立的效果组件组成。核心文件提供了颜色和类的动画，以及高级缓动。

# 颜色动画

将 jQuery UI 的核心效果组件链接到文档中后，`.animate()` 方法被扩展以接受额外的样式属性，例如 `borderTopColor`、`backgroundColor` 和 `color`。例如，我们现在可以逐渐将元素从黑色背景上的白色文本变为浅灰色背景上的黑色文本：

```js
$(() => {
  $books.hover((e) => {
    $(e.target)
      .find('.title')
      .animate({
        backgroundColor: '#eee',
        color: '#000'
      }, 1000);
  }, (e) => {
    $(e.target)
      .find('.title')
      .animate({
        backgroundColor: '#000',
        color: '#fff'
      }, 1000);
  }); 
});

```

清单 7.8

现在，当鼠标光标进入页面的书籍幻灯片区域时，书名的文本颜色和背景颜色都会在一秒钟（1000 毫秒）的时间内平滑动画过渡：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_07_003-1.jpg)

# 类动画

我们在前几章中使用过的三个 CSS 类方法--`.addClass()`、`.removeClass()` 和 `.toggleClass()`--被 jQuery UI 扩展为接受可选的第二个参数，用于动画持续时间。当指定了这个持续时间时，页面的行为就像我们调用了 `.animate()`，并直接指定了应用于元素的类的所有样式属性变化一样：

```js
$(() => {
  $('h1')
    .click((e) => {
      $(e.target).toggleClass('highlighted', 'slow');
    });
});

```

清单 7.9

通过执行 *清单 7.9* 中的代码，我们已经导致页面标题的点击添加或删除 `highlighted` 类。但是，由于我们指定了 `slow` 速度，结果的颜色、边框和边距变化会以动画形式展现出来，而不是立即生效：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_07_04.png)

# 高级缓动

当我们指示 jQuery 在指定的持续时间内执行动画时，它并不是以恒定的速率执行。例如，如果我们调用 `$('#my-div').slideUp(1000)`，我们知道元素的高度将需要整整一秒钟才能达到零；但是，在该秒的开始和结束时，高度将缓慢变化，在中间时将快速变化。这种速率变化被称为**缓动**，有助于动画看起来平滑自然。

高级缓动函数变化加速和减速曲线，以提供独特的结果。例如，`easeInExpo`函数呈指数增长，以多倍于开始时的速度结束动画。我们可以在任何核心 jQuery 动画方法或 jQuery UI 效果方法中指定自定义缓动函数。这可以通过添加参数或将选项添加到设置对象中来完成，具体取决于使用的语法。

要查看此示例，请按照以下方式将`easeInExpo`作为我们刚刚介绍的*第 7.9 部分*中的`.toggleClass()`方法的缓动样式提供：

```js
$(() => { 
  $('h1')
    .click((e) => {
      $(e.target)
        .toggleClass(
          'highlighted',
          'slow',
          'easeInExpo'
        );
    });
});

```

第 7.10 部分

现在，每当单击标题时，通过切换类属性修改的样式都会逐渐出现，然后加速并突然完成过渡。

查看缓动函数的效果

完整的缓动函数集合演示可在

[`api.jqueryui.com/easings/`](http://api.jqueryui.com/easings/)。

# 其他效果

包含在 jQuery UI 中的单独效果文件添加了各种转换，其中一些可以比 jQuery 本身提供的简单滑动和淡出动画复杂得多。通过调用由 jQuery UI 添加的`.effect()`方法来调用这些效果。如果需要，可以使用`.show()`或`.hide()`来调用导致元素隐藏或显示的效果。

jQuery UI 提供的效果可以用于多种用途。其中一些，比如`transfer`和`size`，在元素改变形状和位置时非常有用。另一些，比如`explode`和`puff`，提供了吸引人的隐藏动画。还有一些，包括`pulsate`和`shake`，则将注意力吸引到元素上。

查看效果的实际效果

所有 jQuery UI 效果都在[`jqueryui.com/effect/#default`](http://jqueryui.com/effect/#default)展示。

`shake`行为特别适合强调当前不适用的操作。当简历按钮无效时，我们可以在页面上使用这个效果：

```js
$(() => {
  $('<button/>')
    .text('Resume')
    .click((e) => {
      const $paused = $('ul:paused');
      if ($paused.length) {
        $paused.cycle('resume');
        $.cookie('cyclePaused', null);
      } else {
        $(e.target)
          .effect('shake', {
            distance: 10
          });
      }
    })
    .appendTo($controls);
});

```

第 7.11 部分

我们的新代码检查`$('ul:paused')`的长度，以确定是否有任何暂停的幻灯片秀要恢复。如果是，则像以前一样调用 Cycle 的`resume`操作；否则，执行`shake`效果。在这里，我们看到，与其他效果一样，`shake`有可用于调整其外观的选项。在这里，我们将效果的`distance`设置为比默认值小的数字，以使按钮在点击时快速来回摇摆。

# 交互组件

jQuery UI 的下一个主要功能是其交互组件，这是一组行为，可以用来制作复杂的交互式应用程序。例如，其中一个组件是**Resizable**，它可以允许用户使用自然的拖动动作改变任何元素的大小。

对元素应用交互就像调用带有其名称的方法一样简单。例如，我们可以通过调用`.resizable()`来使书名可调整大小，如下所示：

```js
(() => {
  $books
    .find('.title')
    .resizable();
});

```

列表 7.12

在文档中引用了 jQuery UI 的 CSS 文件后，此代码将在标题框的右下角添加一个调整大小的手柄。拖动此框会改变区域的宽度和高度，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_07_004-1.jpg)

正如我们现在可能期望的那样，这些方法可以使用大量选项进行定制。例如，如果我们希望将调整大小限制为仅在垂直方向上发生，我们可以通过指定应添加哪个拖动手柄来实现如下：

```js
$(() => {
  $books
    .find('.title')
    .resizable({ handles: 's' });
});

```

列表 7.13

只在区域的南（底部）侧有一个拖动手柄，只能改变区域的高度：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_07_005-1.jpg)

其他交互组件

其他 jQuery UI 交互包括可拖动的、可投放的和可排序的。与可调整大小一样，它们是高度可配置的。我们可以在[`jqueryui.com/`](http://jqueryui.com/)上查看它们的演示和配置选项。

# 小部件

除了这些基本交互组件外，jQuery UI 还包括一些强大的用户界面小部件，它们的外观和功能像桌面应用程序中我们习惯看到的成熟元素一样。其中一些非常简单。例如，**按钮**小部件通过吸引人的样式和悬停状态增强了页面上的按钮和链接。

将此外观和行为授予页面上的所有按钮元素非常简单：

```js
$(() => {
  $('button').button(); 
});

```

列表 7.14

当引用 jQuery UI 平滑主题的样式表时，按钮将具有光滑、有倾斜的外观：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_07_07.png)

与其他 UI 小部件和交互一样，按钮接受几个选项。例如，我们可能希望为我们的两个按钮提供适当的图标；按钮小部件带有大量预定义的图标供我们使用。为此，我们可以将我们的`.button()`调用分成两部分，并分别指定每个图标，如下所示：

```js
$(() => {
  $('<button/>')
    .text('Pause')
    .button({
      icons: { primary: 'ui-icon-pause' }
    })
    .click(() => {
      // ...
    })
    .appendTo($controls);
  $('<button/>')
    .text('Resume')
    .button({
      icons: { primary: 'ui-icon-play' }
    })
    .click((e) => {
      // ...
    })
    .appendTo($controls);
});

```

列表 7.15

我们指定的`primary`图标对应于 jQuery UI 主题框架中的标准类名。默认情况下，`primary`图标显示在按钮文本的左侧，而`secondary`图标显示在右侧：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_07_08.png)

另一方面，其他小部件要复杂得多。**滑块**小部件引入了一个全新的表单元素，类似于 HTML5 的范围元素，但与所有流行的浏览器兼容。这支持更高程度的自定义，如下面的代码所示：

```js
$(() => {
  $('<div/>')
    .attr('id', 'slider')
    .slider({
      min: 0,
      max: $books.find('li').length - 1
    })
    .appendTo($controls);
});

```

列表 7.16

对`.slider()`的调用将一个简单的`<div>`元素转换为滑块小部件。该小部件可以通过拖动或按箭头键来控制，以帮助实现可访问性：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_07_09.png)

在 *清单 7.16* 中，我们为滑块指定了一个最小值 `0`，并为幻灯片展示中的最后一本书的索引设置了最大值。我们可以将这个作为幻灯片的手动控制，通过在它们各自的状态改变时在幻灯片和滑块之间发送消息。

为了对滑块值的变化做出反应，我们可以将处理程序绑定到由滑块触发的自定义事件上。这个事件，`slide`，不是一个原生的 JavaScript 事件，但在我们的 jQuery 代码中表现得像一个。然而，观察这些事件是如此常见，以至于我们可以不需要显式地调用 `.on()`，而是可以直接将我们的事件处理程序添加到 `.slider()` 调用本身，如下面的代码所示：

```js
$(() => {
  $('<div/>')
    .attr('id', 'slider')
    .slider({
      min: 0,
      max: $books.find('li').length - 1,
      slide: (e, ui) => {
        $books.cycle(ui.value);
      }
    })
    .appendTo($controls);
});

```

清单 7.17

每当调用 `slide` 回调时，它的 `ui` 参数就会填充有关小部件的信息，包括其当前值。通过将这个值传递给 Cycle 插件，我们可以操作当前显示的幻灯片。

我们还需要在幻灯片向前切换到另一个幻灯片时更新滑块小部件。为了在这个方向上进行通信，我们可以使用 Cycle 的 `before` 回调，在每次幻灯片转换之前触发：

```js
$(() => {
  const $books = $('#books').cycle({
    timeout: 2000,
    speed: 200,
    pause: true,
    before: (li) => {
      $('#slider')
        .slider(
          'value',
          $('#books li').index(li)
        );
    }
  });
});

```

清单 7.18

在 `before` 回调中，我们再次调用 `.slider()` 方法。这一次，我们将 `value` 作为它的第一个参数调用，以设置新的滑块值。在 jQuery UI 的术语中，我们将 `value` 称为滑块的 *方法*，尽管它是通过调用 `.slider()` 方法而不是通过自己的专用方法名称来调用的。

其他小部件

其他 jQuery UI 小部件包括 Datepicker、Dialog、Tabs 和 Accordion。每个小部件都有几个相关的选项、事件和方法。完整列表，请访问

[jQuery UI](http://jqueryui.com/).

# jQuery UI ThemeRoller

jQuery UI 库最令人兴奋的功能之一是 ThemeRoller，这是一个基于 Web 的交互式主题引擎，用于 UI 小部件。ThemeRoller 使得创建高度定制、专业外观的元素变得快速简单。我们刚刚创建的按钮和滑块都应用了默认主题；如果没有提供自定义设置，这个主题将从 *ThemeRoller* 输出：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_07_10.png)

生成完全不同风格的样式只需简单访问

[`jqueryui.com/themeroller/`](http://jqueryui.com/themeroller/)，根据需要修改各种选项，然后按下下载主题按钮。然后，可以将样式表和图像的 `.zip` 文件解压缩到您的站点目录中。例如，通过选择几种不同的颜色和纹理，我们可以在几分钟内为我们的按钮、图标和滑块创建一个新的协调外观，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_07_11.png)

# jQuery Mobile 插件库

我们已经看到 jQuery UI 如何帮助我们组装即使是复杂 web 应用程序所需的用户界面特性。它克服的挑战是多样且复杂的。然而，当为移动设备设计我们的页面以进行优雅的呈现和交互时，存在一组不同的障碍。为了创建现代智能手机和平板电脑的网站或应用程序，我们可以转向 jQuery Mobile 项目。

与 jQuery UI 一样，jQuery Mobile 由一套相关组件组成，可以*单独使用*，但可以无缝地一起工作。该框架提供了一个基于 Ajax 的导航系统、移动优化的交互元素和高级触摸事件处理程序。与 jQuery UI 一样，探索 jQuery Mobile 的所有功能是一个艰巨的任务，因此我们将提供一些简单的示例，并参考官方文档了解更多细节。

jQuery Mobile 的下载、文档和演示可在以下位置找到：

[`jquerymobile.com/`](http://jquerymobile.com/).

我们的 jQuery Mobile 示例将使用 Ajax 技术，因此需要网页服务器软件才能尝试这些示例。更多信息可在第六章中找到，*使用 Ajax 发送数据*。

# HTML5 自定义 data 属性

到目前为止，在本章中我们看到的代码示例都是使用 JavaScript API 暴露的插件来调用插件功能。我们已经看到了 jQuery 对象方法、全局函数和自定义选择器是插件向脚本提供服务的一些方式。jQuery Mobile 库也有这些入口点，但与其进行交互的最常见方式是使用 HTML5 data 属性。

HTML5 规范允许我们在元素中插入任何我们想要的属性，只要属性以 `data-` 为前缀。在呈现页面时，这些属性将完全被忽略，但在我们的 jQuery 脚本中可以使用。当我们在页面中包含 jQuery Mobile 时，脚本会扫描页面寻找一些 `data-*` 属性，并将移动友好的特性添加到相应的元素。

jQuery Mobile 库会寻找几个特定的自定义 data 属性。我们将在第十二章中检查在我们自己的脚本中使用此功能的更一般的方法，*高级 DOM 操作*。

由于这种设计选择，我们将能够演示 jQuery Mobile 的一些强大特性，而无需自己编写任何 JavaScript 代码。

# 移动导航

jQuery Mobile 最显著的特性之一是它能够将页面上链接的行为简单地转变为 Ajax 驱动的导航。这种转变会为此过程添加简单的动画，同时保留了标准浏览器历史导航。为了看到这一点，我们将从一个呈现有关几本书信息的链接的文档开始（与我们之前用于构建幻灯片放映的相同内容），如下所示：

```js
<!DOCTYPE html>  
<html>  
<head>  
  <title>jQuery Book Browser</title>  
  <link rel="stylesheet" href="booklist.css" type="text/css" /> 
  <script src="img/jquery.js"></script> 
</head>  
<body>  

<div> 
  <div> 
    <h1>Selected jQuery Books</h1> 
  </div> 

  <div> 
    <ul> 
      <li><a href="jq-game.html">jQuery Game Development  
        Essentials</a></li> 
      <li><a href="jqmobile-cookbook.html">jQuery Mobile  
        Cookbook</a></li> 
      <li><a href="jquery-designers.html">jQuery for  
        Designers</a></li> 
      <li><a href="jquery-hotshot.html">jQuery Hotshot</a></li> 
      <li><a href="jqui-cookbook.html">jQuery UI Cookbook</a></li> 
      <li><a href="mobile-apps.html">Creating Mobile Apps with  
        jQuery Mobile</a></li> 
      <li><a href="drupal-7.html">Drupal 7 Development by  
        Example</a></li> 
      <li><a href="wp-mobile-apps.html">WordPress Mobile  
        Applications with PhoneGap</a></li> 
    </ul> 
  </div> 
</div> 

</body> 
</html>

```

在本章的可下载代码包中，可以在名为`mobile.html`的文件中找到完成的 HTML 示例页面。

到目前为止，我们还没有介绍 jQuery Mobile，页面呈现出默认的浏览器样式，正如我们所预期的那样。以下是屏幕截图：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_07_006-1.jpg)

我们的下一步是更改文档的`<head>`部分，以便引用 jQuery Mobile 及其样式表，如下所示：

```js
<head>  
  <title>jQuery Book Browser</title>  
  <meta name="viewport" 
    content="width=device-width, initial-scale=1">  
  <link rel="stylesheet" href="booklist.css"  
    type="text/css" /> 
  <link rel="stylesheet" 
    href="jquery.mobile/jquery.mobile.css" type="text/css" /> 
  <script src="img/jquery.js"></script> 
  <script src="img/jquery-migrate.js"></script>
  <script src="img/jquery.mobile.js"></script> 
</head>

```

请注意，我们还引入了一个定义页面视口的`<meta>`元素。这个声明告诉移动浏览器按照完全填充设备宽度的方式缩放文档的内容。

我们必须在页面中包含 jquery-migrate 插件，因为如果没有它，最新稳定版本的 jQuery 就不能与最新稳定版本的 jQuery Mobile 一起工作。想想这个问题。无论如何，一旦这两者正式配合起来，你可以简单地从页面中删除 jquery-migrate 插件。

jQuery Mobile 样式现在应用于我们的文档，显示出更大的无衬线字体，更新颜色和间距，如下图所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_07_007-1.jpg)

为了正确处理导航，jQuery Mobile 需要理解我们页面的结构。我们通过使用`data-role`属性来提供这些信息：

```js
<div data-role="page"> 
  <div data-role="header"> 
    <h1>Selected jQuery Books</h1> 
  </div> 

  <div data-role="content"> 
    <ul> 
      <li><a href="jq-game.html">jQuery Game Development  
        Essentials</a></li> 
      <li><a href="jqmobile-cookbook.html">jQuery Mobile  
        Cookbook</a></li> 
      <li><a href="jquery-designers.html">jQuery for  
        Designers</a></li> 
      <li><a href="jquery-hotshot.html">jQuery Hotshot</a></li> 
      <li><a href="jqui-cookbook.html">jQuery UI Cookbook</a></li> 
      <li><a href="mobile-apps.html">Creating Mobile Apps with  
        jQuery Mobile</a></li> 
      <li><a href="drupal-7.html">Drupal 7 Development by  
        Example</a></li> 
      <li><a href="wp-mobile-apps.html">WordPress Mobile  
        Applications with PhoneGap</a></li> 
    </ul> 
  </div> 
</div>

```

现在页面加载时，jQuery Mobile 注意到我们有一个页面标题，并在页面顶部渲染出一个标准的移动设备标题栏：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_07_008-1.jpg)

当文本过长时超出标题栏，jQuery Mobile 会截断它，并在末尾添加省略号。在这种情况下，我们可以将移动设备旋转到横向方向以查看完整标题：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_07_009-1.jpg)

更重要的是，为了产生 Ajax 导航，这就是所需的全部内容。在从此列表链接到的页面上，我们使用类似的标记：

```js
<div data-role="page"> 
  <div data-role="header"> 
    <h1>WordPress Mobile Applications with PhoneGap</h1> 
  </div> 
  <div data-role="content"> 
    <img src="img/wp-mobile-apps.jpg" alt="WordPress Mobile  
      Applications with PhoneGap" /> 
    <div class="title">WordPress Mobile Applications with  
      PhoneGap</div> 
    <div class="author">Yuxian Eugene Liang</div> 
  </div> 
</div>

```

当点击到这个页面的链接时，jQuery Mobile 使用 Ajax 调用加载页面，抓取带有`data-role="page"`标记的文档部分，并使用淡入过渡显示这些内容：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_07_010-1.jpg)

# 在一个文档中提供多个页面

除了提供用于加载其他文档的 Ajax 功能外，jQuery Mobile 还提供了在单个文档中包含所有内容时提供相同用户体验的工具。为了实现这一点，我们只需使用标准的`#`符号将页面中的锚点链接起来，并将页面的那些部分标记为`data-role="page"`，就像它们在单独的文档中一样，如下所示：

```js
<div data-role="page"> 
  <div data-role="header"> 
    <h1>Selected jQuery Books</h1> 
  </div> 

  <div data-role="content"> 
    <ul> 
      <li><a href="#jq-game">jQuery Game Development  
        Essentials</a></li> 
      <li><a href="#jqmobile-cookbook">jQuery Mobile  
        Cookbook</a></li> 
      <li><a href="#jquery-designers">jQuery for  
        Designers</a></li> 
      <li><a href="#jquery-hotshot">jQuery Hotshot</a></li> 
      <li><a href="#jqui-cookbook">jQuery UI Cookbook</a></li> 
      <li><a href="#mobile-apps">Creating Mobile Apps with jQuery  
        Mobile</a></li> 
      <li><a href="#drupal-7">Drupal 7 Development by  
        Example</a></li> 
      <li><a href="wp-mobile-apps.html">WordPress Mobile  
        Applications with PhoneGap</a></li> 
    </ul> 
  </div> 
</div> 

<div id="jq-game" data-role="page"> 
  <div data-role="header"> 
    <h1>jQuery Game Development Essentials</h1> 
  </div> 
  <div data-role="content"> 
    <img src="img/jq-game.jpg" alt="jQuery Game Development  
      Essentials" /> 
    <div class="title">jQuery Game Development Essentials</div> 
    <div class="author">Salim Arsever</div> 
  </div> 
</div>

```

我们可以根据自己的方便选择这两种技术。将内容放在单独的文档中允许我们延迟加载信息，直到需要时，但这会增加一些开销，因为需要多个页面请求。

# 交互元素

jQuery Mobile 提供的功能主要是用于页面上的特定交互元素。这些元素增强了基本的网页功能，使页面组件在触摸界面上更加用户友好。其中包括手风琴式可折叠部分、切换开关、滑动面板和响应式表格。

jQuery UI 和 jQuery Mobile 提供的用户界面元素有很大的重叠。不建议在同一页上同时使用这两个库，但由于最重要的小部件都被两者提供，所以很少有这样的需要。

# 列表视图

由于它们的小型垂直屏幕布局，智能手机应用程序通常是以列表为主导的。我们可以使用 jQuery Mobile 轻松地增强页面上的列表，使它们的行为更像这些常见的本地应用程序元素。再次，我们只需引入 HTML5 自定义数据属性：

```js
<ul data-role="listview" data-inset="true"> 
  <li><a href="#jq-game">jQuery Game Development  
    Essentials</a></li> 
  <li><a href="#jqmobile-cookbook">jQuery Mobile Cookbook</a></li> 
  <li><a href="#jquery-designers">jQuery for Designers</a></li> 
  <li><a href="#jquery-hotshot">jQuery Hotshot</a></li> 
  <li><a href="#jqui-cookbook">jQuery UI Cookbook</a></li> 
  <li><a href="#mobile-apps">Creating Mobile Apps with jQuery  
    Mobile</a></li> 
  <li><a href="#drupal-7">Drupal 7 Development by Example</a></li> 
  <li><a href="wp-mobile-apps.html">WordPress Mobile Applications  
    with PhoneGap</a></li> 
</ul>

```

添加 `data-role="listview"` 告诉 jQuery Mobile 将此列表中的链接设为大号，并且易于在触摸界面中用手指激活，而 `data-inset="true"` 则为列表提供了一个漂亮的边框，将其与周围内容分隔开来。结果是一个熟悉的、具有本地外观的控件，如下所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_07_011-1.jpg)

现在，我们有了大型触摸目标，但我们可以再进一步。移动应用程序中的类似列表视图通常会与搜索字段配对，以缩小列表中的项目。我们可以通过引入 `data-filter` 属性来添加这样一个字段，如下所示：

```js
<ul data-role="listview" data-inset="true" data-filter="true">

```

结果是一个带有适当图标的圆角输入框，放置在列表上方：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_07_012-1.jpg)

尽管我们没有添加任何自己的代码，但这个搜索字段看起来不仅本地化，而且行为也是正确的：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_07_013-1.jpg)

# 工具栏按钮

另一个由 jQuery Mobile 增强的用户界面元素是简单按钮。就像 jQuery UI 允许我们标准化按钮外观一样，jQuery Mobile 增加了按钮的大小并修改了外观，以优化它们用于触摸输入。

在某些情况下，jQuery Mobile 甚至会为我们创建适当的按钮，在以前没有的情况下。例如，在移动应用程序的工具栏中通常有按钮。一个标准按钮是屏幕左上角的返回按钮，允许用户向上导航一级。如果我们为页面的 `<div>` 元素添加 `data-add-back-btn` 属性，我们就可以在不进行任何脚本工作的情况下获得此功能：

```js
<div data-role="page" data-add-back-btn="true">

```

一旦添加了这个属性，每次导航到一个页面时，都会在工具栏上添加一个标准的返回按钮：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_07_014-1.jpg)

可以在 [`jquerymobile.com/`](http://jquerymobile.com/) 找到用于初始化和配置 jQuery Mobile 小部件的完整 HTML5 数据属性列表。

# 高级功能

随着我们的移动页面需要更多定制设计元素和更复杂的交互，jQuery Mobile 提供了强大的工具来帮助我们创建它们。所有功能都在 jQuery Mobile 网站上有文档记录 ([`jquerymobile.com/`](http://jquerymobile.com/))。虽然这些功能在此处详细讨论起来既过于高级又过于繁多，但还是值得简要提及一些：

+   **移动友好事件**：当在页面上引用 jQuery Mobile 时，我们的 jQuery 代码可以访问许多特殊事件，包括 `tap`、`taphold` 和 `swipe`。对于这些事件的处理程序可以与任何其他事件一样使用`.on()` 方法进行绑定。特别是对于 `taphold` 和 `swipe`，它们的默认配置（包括触摸持续时间）可以通过访问`$.event.special.taphold` 和 `$.event.special.swipe` 对象的属性进行修改。除了基于触摸的事件外，jQuery Mobile 还提供了对滚动、方向更改以及其页面导航的各个阶段以及一组虚拟化鼠标事件的特殊事件的支持，这些事件对鼠标和触摸都做出反应。

+   **主题化**：与 jQuery UI 一样，jQuery Mobile 提供了一个 ThemeRoller。

    ([`jquerymobile.com/themeroller/`](http://jquerymobile.com/themeroller/)) 用于自定义小部件的外观和感觉。

+   **PhoneGap 集成**：使用 jQuery Mobile 构建的站点可以轻松转换为原生移动应用程序，使用 PhoneGap（Cordova），可访问移动设备 API（如相机、加速计和地理位置）和应用商店。`$.support.cors` 和 `$.mobile.allowCrossDomainPages` 属性甚至可以允许访问不包含在应用程序中的页面，例如远程服务器上的页面。

# 总结

在本章中，我们探讨了如何将第三方插件整合到我们的网页中。我们仔细研究了 Cycle 插件、jQuery UI 和 jQuery Mobile，并在此过程中学习了我们将在其他插件中反复遇到的模式。在下一章中，我们将利用 jQuery 的插件架构开发一些不同类型的插件。

# 练习

1.  将循环转换持续时间增加到半秒，并更改动画，使每个幻灯片在下一个幻灯片淡出之前淡入。参考循环文档以找到启用此功能的适当选项。

1.  将`cyclePaused` cookie 设置为持续 30 天。

1.  限制标题框只能以十个像素为增量调整大小。

1.  让滑块在幻灯片播放时从一个位置平稳地动画到下一个位置。

1.  不要让幻灯片播放循环无限，使其在显示最后一张幻灯片后停止。当发生这种情况时，禁用按钮和滑块。

1.  创建一个新的 jQuery UI 主题，具有浅蓝色小部件背景和深蓝色文本，并将主题应用到我们的示例文档中。

1.  修改`mobile.html`中的 HTML，使得列表视图按照书名的首字母分隔。详细信息请参阅 jQuery Mobile 文档中关于`data-role="list-divider"`的部分。


# 第八章：开发插件

可用的第三方插件提供了丰富的选项来增强我们的编码体验，但有时我们需要更进一步。当我们编写可以被其他人甚至只是我们自己重复使用的代码时，我们可能希望将其打包为一个新的插件。幸运的是，开发插件的过程与编写使用它的代码并没有太大区别。

在本章中，我们将介绍：

+   在`jQuery`命名空间中添加新的全局函数

+   添加 jQuery 对象方法以允许我们对 DOM 元素进行操作

+   使用 jQuery UI 小部件工厂创建小部件插件

+   分发插件

# 在插件中使用美元（$）别名

当我们编写 jQuery 插件时，必须假设 jQuery 库已加载。但是我们不能假设美元（$）别名可用。回顾一下第三章中的内容，*事件处理*，`$.noConflict()`方法可以放弃对这个快捷方式的控制。为了解决这个问题，我们的插件应该始终使用完整的 jQuery 名称调用 jQuery 方法，或者在内部定义`$`自己。

尤其是在较大的插件中，许多开发人员发现缺少美元符号（`$`）快捷方式使得代码更难阅读。为了解决这个问题，可以通过定义一个函数并立即调用它来为插件的范围定义快捷方式。这种定义并立即调用函数的语法，通常被称为**立即调用函数表达式**（**IIFE**），看起来像这样：

```js
(($) => { 
  // Code goes here 
})(jQuery); 

```

包装函数接受一个参数，我们将全局`jQuery`对象传递给它。参数被命名为`$`，所以在函数内部我们可以使用美元（$）别名而不会出现冲突。

# 添加新的全局函数

jQuery 的一些内置功能是通过我们一直称为全局函数的方式提供的。正如我们所见，这些实际上是 jQuery 对象的方法，但从实际操作上来说，它们是`jQuery`命名空间中的函数。

这种技术的一个典型例子是`$.ajax()`函数。`$.ajax()`所做的一切都可以通过一个名为`ajax()`的常规全局函数来实现，但是这种方法会使我们容易遇到函数名冲突。通过将函数放置在`jQuery`命名空间中，我们只需要担心与其他 jQuery 方法的冲突。这个`jQuery`命名空间还向那些可能使用插件的人们表明，需要 jQuery 库。

jQuery 核心库提供的许多全局函数都是实用方法；也就是说，它们为经常需要但不难手动完成的任务提供了快捷方式。数组处理函数`$.each()`、`$.map()`和`$.grep()`就是这样的好例子。为了说明创建这种实用方法，我们将向其中添加两个简单的函数。

要将函数添加到`jQuery`命名空间中，我们只需将新函数作为`jQuery`对象的属性赋值即可：

```js
(($) => { 
  $.sum = (array) => { 
    // Code goes here 
  }; 
})(jQuery); 

```

列表 8.1

现在，在使用此插件的任何代码中，我们可以写：

```js
$.sum(); 

```

这将像基本函数调用一样工作，并且函数内部的代码将被执行。

这个`sum`方法将接受一个数组，将数组中的值相加，并返回结果。我们插件的代码相当简洁：

```js
(($) => {
  $.sum = array =>
    array.reduce(
      (result, item) =>
        parseFloat($.trim(item)) + result,
      0
    );
})(jQuery); 

```

**清单 8.2**

要计算总和，我们在数组上调用`reduce()`，它简单地迭代数组中的每个项，并将其添加到`result`中。在前面的代码中，有两个返回值的回调函数。它们都没有`return`语句，因为它们是箭头函数。当我们不包括花括号（`{}`）时，返回值是隐式的。

为了测试我们的插件，我们将构建一个简单的带有杂货清单的表格：

```js
<table id="inventory"> 
  <thead> 
    <tr class="one"> 
      <th>Product</th> <th>Quantity</th> <th>Price</th> 
    </tr> 
  </thead> 
  <tfoot> 
    <tr class="two" id="sum"> 
      <td>Total</td> <td></td> <td></td> 
    </tr> 
    <tr id="average"> 
      <td>Average</td> <td></td> <td></td> 
    </tr> 
  </tfoot> 
  <tbody> 
    <tr> 
      <td><a href="spam.html" data-tooltip-text="Nutritious and        
      delicious!">Spam</a></td> <td>4</td> <td>2.50</td> 
    </tr> 
    <tr> 
      <td><a href="egg.html" data-tooltip-text="Farm fresh or        
      scrambled!">Egg</a></td> <td>12</td> <td>4.32</td> 
    </tr> 
    <tr> 
      <td><a href="gourmet-spam.html" data-tooltip-text="Chef        
      Hermann's recipe.">Gourmet Spam</a></td> <td>14</td> <td>7.89         
      </td> 
    </tr> 
  </tbody> 
</table> 

```

获取示例代码

您可以从以下 GitHub 存储库访问示例代码：[`github.com/PacktPublishing/Learning-jQuery-3`](https://github.com/PacktPublishing/Learning-jQuery-3)。

现在，我们将编写一个简短的脚本，将适当的表格页脚单元格填充为所有数量的总和：

```js
$(() => {
  const quantities = $('#inventory tbody')
    .find('td:nth-child(2)')
    .map((index, qty) => $(qty).text())
    .get();
  const sum = $.sum(quantities);

  $('#sum')
    .find('td:nth-child(2)')
    .text(sum);
});

```

**清单 8.3**

查看呈现的 HTML 页面可验证我们的插件是否正常工作：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_08_01.png)

# 添加多个函数

如果我们的插件需要提供多个全局函数，我们可以独立声明它们。在这里，我们将修改我们的插件，添加一个计算数字数组平均值的函数：

```js
(($) => {
  $.sum = array =>
    array.reduce(
      (result, item) =>
        parseFloat($.trim(item)) + result,
      0
    );

  $.average = array =>
    Array.isArray(array) ?
      $.sum(array) / array.length :
      '';
})(jQuery); 

```

**清单 8.4**

为了方便和简洁，我们使用`$.sum()`插件来辅助我们返回`$.average()`的值。为了减少错误的几率，我们还检查参数以确保其是一个数组，然后再计算平均值。

现在定义了第二种方法，我们可以以相同的方式调用它：

```js
$(() => {
  const $inventory = $('#inventory tbody');
  const prices = $inventory
    .find('td:nth-child(3)')
    .map((index, qty) => $(qty).text())
    .get();
  const average = $.average(prices);

  $('#average')
    .find('td:nth-child(3)')
    .text(average.toFixed(2));
});

```

**清单 8.5**

平均值现在显示在第三列中：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_08_02.png)

# 扩展全局 jQuery 对象

我们还可以使用`$.extend()`函数以定义我们的函数的另一种语法：

```js
(($) => {
  $.extend({
    sum: array =>
      array.reduce(
        (result, item) =>
          parseFloat($.trim(item)) + result,
        0
      ),
    average: array =>
      Array.isArray(array) ?
        $.sum(array) / array.length :
        ''
  });
})(jQuery); 

```

**清单 8.6**

这样调用时，`$.extend()`添加或替换全局 jQuery 对象的属性。因此，这与先前的技术产生相同的结果。

# 在命名空间内隔离函数

现在，我们的插件在`jQuery`命名空间内创建了两个单独的全局函数。在这里，我们面临一种不同类型的命名空间污染风险；虽然我们仍然可能与其他 jQuery 插件中定义的函数名冲突。为了避免这种情况，最好将给定插件的所有全局函数封装到单个对象中：

```js
(($) => {
  $.mathUtils = {
    sum: array =>
      array.reduce(
        (result, item) =>
          parseFloat($.trim(item)) + result,
        0
      ),
    average: array =>
      Array.isArray(array) ?
        $.mathUtils.sum(array) / array.length :
        ''
  };
})(jQuery); 

```

**清单 8.7**

此模式实质上为我们的全局函数创建了另一个命名空间，称为`jQuery.mathUtils`。虽然我们仍然非正式地称这些函数为全局函数，但它们现在是`mathUtils`对象的方法，后者本身是全局 jQuery 对象的属性。因此，在我们的函数调用中，我们必须包含插件名称：

```js
$.mathUtils.sum(array); 
$.mathUtils.average(array); 

```

通过这种技术（和足够独特的插件名称），我们可以在全局函数中避免命名空间冲突。这样，我们就掌握了插件开发的基础知识。将我们的函数保存在名为`jquery.mathutils.js`的文件中后，我们可以包含此脚本，并在页面上的其他脚本中使用这些函数。

选择命名空间

对于仅供个人使用的功能，将其放置在我们项目的全局命名空间中通常更合理。因此，我们可以选择暴露我们自己的一个全局对象，而不是使用`jQuery`。例如，我们可以有一个名为`ljQ`的全局对象，并定义`ljQ.mathUtils.sum()`和`ljQ.mathUtils.average()`方法，而不是`$.mathUtils.sum()`和`$.mathUtils.average()`。这样，我们完全消除了选择包含的第三方插件发生命名空间冲突的可能性。

因此，我们现在已经了解了 jQuery 插件提供的命名空间保护和保证库的可用性。然而，这些仅仅是组织上的好处。要真正发挥 jQuery 插件的威力，我们需要学会如何在单个 jQuery 对象实例上创建新方法。

# 添加 jQuery 对象方法

大多数 jQuery 内置功能是通过其对象实例方法提供的，插件的具有同样出色的表现。每当我们要编写作用于 DOM 一部分的函数时，可能更适合创建一个**实例方法**。

我们已经看到，添加全局函数需要使用`jQuery`对象扩展新方法。添加实例方法是类似的，但我们要扩展`jQuery.fn`对象：

```js
jQuery.fn.myMethod = function() { 
  alert('Nothing happens.'); 
}; 

```

`jQuery.fn`对象是`jQuery.prototype`的别名，用于简洁性。

然后，我们可以在使用选择器表达式后，从我们的代码中调用这个新方法：

```js
$('div').myMethod(); 

```

当我们调用方法时，我们的警报显示（对于文档中的每个`<div>`都会显示一次）。不过，我们既然没有以任何方式使用匹配的 DOM 节点，我们可能也可以编写一个全局函数。一个合理的方法实现会作用于其上下文。

# 对象方法上下文

在任何插件方法中，关键字`this`被设置为当前的 jQuery 对象。因此，我们可以在`this`上调用任何内置的 jQuery 方法，或者提取其 DOM 节点并对它们进行操作。为了检查我们可以用对象上下文做什么，我们将编写一个小插件来操作匹配元素上的类。

我们的新方法将接受两个类名，并交换每次调用时应用于每个元素的类。虽然 jQuery UI 有一个强大的`.switchClass()`方法，甚至允许动画地改变类，但我们将提供一个简单的实现作为演示目的：

```js
(function($) {
  $.fn.swapClass = function(class1, class2) {
    if (this.hasClass(class1)) {
      this
        .removeClass(class1)
        .addClass(class2);
    } else if (this.hasClass(class2)) {
      this
        .removeClass(class2)
        .addClass(class1);
    }
  };
})(jQuery);

$(() => {
  $('table')
    .click(() => {
      $('tr').swapClass('one', 'two');
    });
});

```

图 8.8

在我们的插件中，我们首先测试匹配元素上是否存在`class1`，如果存在则用`class2`替换。否则，我们测试是否存在`class2`，如果必要则切换为`class1`。如果当前没有任何类，则我们不执行任何操作。

在使用插件的代码中，我们将`click`处理程序绑定到表格上，在单击表格时对每一行调用`.swapClass()`。我们希望这将把标题行的类从`one`更改为`two`，并将总和行的类从`two`更改为`one`。

然而，我们观察到了不同的结果：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_08_03.png)

每一行都收到了`two`类。要解决这个问题，我们需要正确处理具有多个选定元素的 jQuery 对象。

# 隐式迭代

我们需要记住，jQuery 选择器表达式总是可以匹配零个、一个或多个元素。在设计插件方法时，我们必须考虑到这些情况中的任何一种。在这种情况下，我们正在调用`.hasClass()`，它仅检查第一个匹配的元素。相反，我们需要独立地检查每个元素并对其采取行动。

无论匹配的元素数量如何，保证正确行为的最简单方法是始终在方法上下文中调用`.each()`；这强制执行隐式迭代，这对于保持插件和内置方法之间的一致性至关重要。在`.each()`回调函数中，第二个参数依次引用每个 DOM 元素，因此我们可以调整我们的代码来分别测试和应用类到每个匹配的元素：

```js
(function($) {
  $.fn.swapClass = function(class1, class2) {
    this
      .each((i, element) => {
        const $element = $(element);

        if ($element.hasClass(class1)) {
          $element
            .removeClass(class1)
            .addClass(class2);
        } else if ($element.hasClass(class2)) {
          $element
            .removeClass(class2)
            .addClass(class1);
        }
      });
  };
})(jQuery); 

```

列表 8.9

现在，当我们点击表格时，切换类而不影响没有应用任何类的行：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_08_04.png)

# 启用方法链

除了隐式迭代之外，jQuery 用户还应该能够依赖链接行为。这意味着我们需要从所有插件方法中返回一个 jQuery 对象，除非该方法明确用于检索不同的信息片段。返回的 jQuery 对象通常只是作为`this`提供的一个。如果我们使用`.each()`来迭代`this`，我们可以直接返回其结果：

```js
(function($) {
  $.fn.swapClass = function(class1, class2) {
    return this
      .each((i, element) => {
        const $element = $(element);

        if ($element.hasClass(class1)) {
          $element
            .removeClass(class1)
            .addClass(class2);
        } else if ($element.hasClass(class2)) {
          $element
            .removeClass(class2)
            .addClass(class1);
        }
      });
  };
})(jQuery); 

```

列表 8.10

之前，当我们调用`.swapClass()`时，我们必须开始一个新语句来处理元素。然而，有了`return`语句，我们可以自由地将我们的插件方法与内置方法链接起来。

# 提供灵活的方法参数

在第七章 *使用插件* 中，我们看到了一些插件，可以通过参数进行微调，以达到我们想要的效果。我们看到，一个构造巧妙的插件通过提供合理的默认值来帮助我们，这些默认值可以被独立地覆盖。当我们制作自己的插件时，我们应该以用户为重心来遵循这个例子。

为了探索各种方法，让插件的用户自定义其行为，我们需要一个具有多个可以进行调整和修改的设置的示例。作为我们的示例，我们将通过使用更为武断的 JavaScript 方法来复制 CSS 的一个特性--这种方法更适合于演示而不是生产代码。我们的插件将通过在页面上不同位置叠加部分透明的多个副本来模拟元素上的阴影：

```js
(function($) {
  $.fn.shadow = function() {
    return this.each((i, element) => {
      const $originalElement = $(element);

      for (let i = 0; i < 5; i++) {
        $originalElement
          .clone()
          .css({
            position: 'absolute',
            left: $originalElement.offset().left + i,
            top: $originalElement.offset().top + i,
            margin: 0,
            zIndex: -1,
            opacity: 0.1
          })
          .appendTo('body');
      }
    });
  };
})(jQuery); 

```

代码清单 8.11

对于每个调用此方法的元素，我们会制作多个元素的克隆，并调整它们的不透明度。这些克隆元素被绝对定位在原始元素的不同偏移量处。目前，我们的插件不接受参数，因此调用该方法很简单：

```js
$(() => { 
  $('h1').shadow(); 
}); 

```

此方法调用会在标题文本上产生一个非常简单的阴影效果：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_08_05.png)

接下来，我们可以为插件方法引入一些灵活性。该方法的操作依赖于用户可能希望修改的几个数值。我们可以将它们转换为参数，以便根据需要进行更改。

# 选项对象

我们在 jQuery API 中看到了许多示例，其中`options`对象被提供为方法的参数，例如`.animate()`和`$.ajax()`。这可以是向插件用户公开选项的更友好的方式，而不是我们刚刚在`.swapClass()`插件中使用的简单参数列表。对象文字为每个参数提供了可视标签，并且使参数的顺序变得无关紧要。此外，每当我们可以在我们的插件中模仿 jQuery API 时，我们都应该这样做。这将增加一致性，从而提高易用性：

```js
(($) => {
  $.fn.shadow = function(options) {
    return this.each((i, element) => {
      const $originalElement = $(element);

      for (let i = 0; i < options.copies; i++) {
        $originalElement
          .clone()
          .css({
            position: 'absolute',
            left: $originalElement.offset().left + i,
            top: $originalElement.offset().top + i,
            margin: 0,
            zIndex: -1,
            opacity: options.opacity
          })
          .appendTo('body');
      }
    });
  };
})(jQuery);

```

代码清单 8.12

现在可以自定义制作的副本数量及其不透明度。在我们的插件中，每个值都作为函数的`options`参数的属性访问。

现在调用此方法需要我们提供包含选项值的对象：

```js
$(() => {
  $('h1')
    .shadow({ 
      copies: 3, 
      opacity: 0.25 
    }); 
}); 

```

可配置性是一种改进，但现在我们必须每次都提供两个选项。接下来，我们将看看如何允许我们的插件用户省略任一选项。

# 默认参数值

随着方法的参数数量增加，我们不太可能总是想要指定每个参数。合理的默认值集合可以使插件接口更加易用。幸运的是，使用对象传递参数可以帮助我们完成这项任务；简单地省略对象中的任何项并用默认值替换它是很简单的：

```js
(($) => {
  $.fn.shadow = function(opts) {
    const defaults = {
      copies: 5,
      opacity: 0.1
    };
    const options = $.extend({}, defaults, opts); 

    // ... 
  }; 
})(jQuery); 

```

代码清单 8.13

在这里，我们定义了一个名为`defaults`的新对象。 实用函数`$.extend（）`允许我们使用提供的`opts`对象作为参数，并使用`defaults`在必要时创建一个新的`options`对象。 `extend（）`函数将传递给它的任何对象合并到第一个参数中。 这就是为什么我们将空对象作为第一个参数传递的原因，以便我们为选项创建一个新对象，而不是意外地销毁现有数据。 例如，如果默认值在代码的其他位置定义，并且我们意外地替换了其值呢？

我们仍然使用对象字面量调用我们的方法，但现在我们只能指定需要与其默认值不同的参数：

```js
$(() => { 
  $('h1')
    .shadow({ 
      copies: 3 
    }); 
}); 

```

未指定的参数使用其默认值。 `$.extend（）`方法甚至接受 null 值，因此如果默认参数都可接受，则我们的方法可以在不产生 JavaScript 错误的情况下调用：

```js
$(() => { 
  $('h1').shadow(); 
}); 

```

# 回调函数

当然，有些方法参数可能比简单的数字值更复杂。 我们在整个 jQuery API 中经常看到的一种常见参数类型是回调函数。 回调函数可以为插件提供灵活性，而无需在创建插件时进行大量准备。

要在我们的方法中使用回调函数，我们只需将函数对象作为参数接受，并在我们的方法实现中适当地调用该函数。 例如，我们可以扩展我们的文本阴影方法，以允许用户自定义阴影相对于文本的位置：

```js
(($) => {
  $.fn.shadow = function(opts) {
    const defaults = {
      copies: 5,
      opacity: 0.1,
      copyOffset: index => ({
        x: index,
        y: index
      })
    };
    const options = $.extend({}, defaults, opts);

    return this.each((i, element) => {
      const $originalElement = $(element);

      for (let i = 0; i < options.copies; i++) {
        const offset = options.copyOffset(i);

        $originalElement
          .clone()
          .css({
            position: 'absolute',
            left: $originalElement.offset().left + offset.x,
            top: $originalElement.offset().top + offset.y,
            margin: 0,
            zIndex: -1,
            opacity: options.opacity
          })
          .appendTo('body');
      }
    });
  };
})(jQuery);

```

列表 8.14

阴影的每个片段与原始文本的偏移量不同。 以前，此偏移量仅等于副本的索引。 但是，现在，我们正在使用`copyOffset（）`函数计算偏移量，该函数是用户可以覆盖的选项。 因此，例如，我们可以为两个维度的偏移提供负值：

```js
$(() => { 
  $('h1').shadow({ 
    copyOffset: index => ({
      x: -index,
      y: -2 * index
    }) 
  }); 
}); 

```

这将导致阴影向左上方投射，而不是向右下方：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_08_06.png)

回调函数允许简单修改阴影的方向，或者如果插件用户提供了适当的回调，则允许更复杂的定位。 如果未指定回调，则再次使用默认行为。

# 可定制的默认值

通过为我们的方法参数提供合理的默认值，我们可以改善使用插件的体验，正如我们所见。 但是，有时很难预测什么是合理的默认值。 如果脚本作者需要多次调用我们的插件，并且需要不同于我们设置的默认值的参数集，那么自定义这些默认值的能力可能会显着减少需要编写的代码量。

要使默认值可定制，我们需要将它们从我们的方法定义中移出，并放入可由外部代码访问的位置：

```js
(() => { 
  $.fn.shadow = function(opts) { 
    const options = $.extend({}, $.fn.shadow.defaults, opts); 
    // ... 
  }; 

  $.fn.shadow.defaults = { 
    copies: 5, 
    opacity: 0.1, 
    copyOffset: index => ({
      x: index,
      y: index
    }) 
  }; 
})(jQuery); 

```

列表 8.15

默认值现在在阴影插件的命名空间中，并且可以直接使用 `$.fn.shadow.defaults` 引用。现在，使用我们的插件的代码可以更改所有后续对 `.shadow()` 的调用所使用的默认值。选项也仍然可以在调用方法时提供：

```js
$(() => { 
  $.fn.shadow.defaults.copies = 10;
  $('h1')
    .shadow({
      copyOffset: index => ({
        x: -index,
        y: index
    })
  });
}); 

```

这个脚本将使用 `10` 个元素的副本创建一个阴影，因为这是新的默认值，但也会通过提供的 `copyOffset` 回调将阴影投射到左侧和向下：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_08_07.png)

# 使用 jQuery UI 小部件工厂创建插件。

正如我们在第七章中看到的，*使用插件*，jQuery UI 有各种各样的小部件--呈现特定类型的 UI 元素的插件，如按钮或滑块。这些小部件向 JavaScript 程序员提供一致的 API。这种一致性使得学习使用其中一个变得容易。当我们编写的插件将创建一个新的用户界面元素时，通过使用小部件插件扩展 jQuery UI 库通常是正确的选择。

小部件是一段复杂的功能，但幸运的是我们不需要自己创建。jQuery UI 核心包含一个名为 `$.widget()` 的 `factory` 方法，它为我们做了很多工作。使用这个工厂将有助于确保我们的代码符合所有 jQuery UI 小部件共享的 API 标准。

使用小部件工厂创建的插件具有许多不错的功能。我们只需很少的努力就能得到所有这些好处（以及更多）：

+   插件变得 **有状态**，这意味着我们可以在应用插件后检查、修改或甚至完全撤销插件的效果。

+   用户提供的选项会自动与可定制的默认选项合并。

+   多个插件方法被无缝地合并为单个 jQuery 方法，接受一个字符串来标识调用哪个子方法。

+   插件触发的自定义事件处理程序可以访问小部件实例的数据。

实际上，这些优势非常好，以至于我们可能希望使用小部件工厂来构建任何合适复杂的插件，无论是 UI 相关的还是其他的。

# 创建一个小部件。

以我们的示例为例，我们将制作一个插件，为元素添加自定义工具提示。一个简单的工具提示实现会为页面上每个要显示工具提示的元素创建一个 `<div>` 容器，并在鼠标光标悬停在目标上时将该容器定位在元素旁边。

jQuery UI 库包含其自己内置的高级工具提示小部件，比我们将在这里开发的更为先进。我们的新小部件将覆盖内置的 `.tooltip()` 方法，这不是我们在实际项目中可能做的事情，但它将允许我们演示几个重要的概念而不会增加不必要的复杂性。

每次调用`$.widget()`时，小部件工厂都会创建一个 jQuery UI 插件。此函数接受小部件的名称和包含小部件属性的对象。小部件的名称必须被命名空间化；我们将使用命名空间`ljq`和插件名称`tooltip`。因此，我们的插件将通过在 jQuery 对象上调用`.tooltip()`来调用。

第一个小部件属性我们将定义为`._create()`：

```js
(($) => {
  $.widget('ljq.tooltip', {
    _create() {
      this._tooltipDiv = $('<div/>')
        .addClass([
          'ljq-tooltip-text',
          'ui-widget',
          'ui-state-highlight',
          'ui-corner-all'
        ].join(' '))
        .hide()
        .appendTo('body');
      this.element
        .addClass('ljq-tooltip-trigger')
        .on('mouseenter.ljq-tooltip', () => { this._open(); })
        .on('mouseleave.ljq-tooltip', () => { this._close(); });
    }
  });
})(jQuery); 

```

列表 8.16

此属性是一个函数，当调用`.tooltip()`时，小部件工厂将每匹配一个元素在 jQuery 对象中调用一次。

小部件属性，如`_create`，以下划线开头，被认为是私有的。我们稍后将讨论公共函数。

在这个创建函数内部，我们设置了我们的提示以便未来显示。为此，我们创建了新的`<div>`元素并将其添加到文档中。我们将创建的元素存储在`this._tooltipDiv`中以备后用。

在我们的函数上下文中，`this`指的是当前小部件实例，我们可以向该对象添加任何属性。该对象还具有一些内置属性，对我们也很方便；特别是，`this.element`给了我们一个指向最初选定的元素的 jQuery 对象。

我们使用`this.element`将`mouseenter`和`mouseleave`处理程序绑定到提示触发元素上。我们需要这些处理程序在鼠标开始悬停在触发器上时打开提示，并在鼠标离开时关闭它。请注意，事件名称被命名空间化为我们的插件名称。正如我们在第三章中讨论的*处理事件*，命名空间使我们更容易添加和删除事件处理程序，而不会影响其他代码也想要绑定处理程序到元素上。

接下来，我们需要定义绑定到`mouseenter`和`mouseleave`处理程序的`._open()`和`._close()`方法：

```js
(() => { 
  $.widget('ljq.tooltip', { 
    _create() { 
      // ... 
    }, 

    _open() {
      const elementOffset = this.element.offset();
      this._tooltipDiv
        .css({
          position: 'absolute',
          left: elementOffset.left,
          top: elementOffset.top + this.element.height()
        })
        .text(this.element.data('tooltip-text'))
        .show();
    },

    _close() { 
      this._tooltipDiv.hide(); 
    } 
  }); 
})(jQuery); 

```

列表 8.17

`._open()`和`._close()`方法本身是不言自明的。这些不是特殊名称，而是说明我们可以在我们的小部件中创建任何私有函数，只要它们的名称以下划线开头。当提示被打开时，我们用 CSS 定位它并显示它；当它关闭时，我们只需隐藏它。

在打开过程中，我们需要填充提示信息。我们使用`.data()`方法来做到这一点，它可以获取和设置与任何元素关联的任意数据。在这种情况下，我们使用该方法来获取每个元素的`data-tooltip-text`属性的值。

有了我们的插件，代码`$('a').tooltip()`将导致鼠标悬停在任何锚点上时显示提示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_08_08.png)

到目前为止，插件并不是很长，但是密集地包含了复杂的概念。为了让这种复杂性发挥作用，我们可以做的第一件事就是使我们的小部件具有状态。小部件的状态将允许用户根据需要启用和禁用它，甚至在创建后完全销毁它。

# 销毁小部件

我们已经看到，小部件工厂创建了一个新的 jQuery 方法，在我们的案例中称为 `.tooltip()`，可以不带参数调用以将小部件应用于一组元素。不过，这个方法还可以做更多的事情。当我们给这个方法一个字符串参数时，它会调用相应名称的方法。

内置方法之一称为 `destroy`。调用 `.tooltip('destroy')` 将从页面中删除提示小部件。小部件工厂会完成大部分工作，但如果我们在 `._create()` 中修改了文档的某些部分（正如我们在这里所做的，通过创建提示文本 `<div>`），我们需要自己清理：

```js
(($) => {
  $.widget('ljq.tooltip', { 
    _create() { 
      // ... 
    }, 

    destroy() {
      this._tooltipDiv.remove();
      this.element
        .removeClass('ljq-tooltip-trigger')
        .off('.ljq-tooltip');
      this._superApply(arguments);
    },

    _open() { 
      // ... 
    }, 

    _close() { 
      // ... 
    } 
  }); 
})(jQuery); 

```

列表 8.18

这段新代码被添加为小部件的一个新属性。该函数撤销了我们所做的修改，然后调用原型的 destroy 版本，以便自动清理发生。 `_super()` 和 `_superApply()` 方法调用了同名的基础小部件方法。这样做总是一个好主意，这样基础小部件中的适当初始化操作就会执行。

注意 destroy 前面没有下划线；这是一个 `public` 方法，我们可以用 `.tooltip('destroy')` 调用它。

# 启用和禁用小部件

除了完全销毁之外，任何小部件都可以被暂时禁用，稍后重新启用。基础小部件方法 `enable` 和 `disable` 通过将 `this.options.disabled` 的值设置为 `true` 或 `false` 来帮助我们。我们所要做的就是在我们的小部件采取任何行动之前检查这个值：

```js
_open() {
  if (this.options.disabled) {
    return;
  }

  const elementOffset = this.element.offset();
  this._tooltipDiv
    .css({
      position: 'absolute',
      left: elementOffset.left,
      top: elementOffset.top + this.element.height()
    })
    .text(this.element.data('tooltip-text'))
    .show();
}

```

列表 8.19

在这个额外的检查放置后，一旦调用 `.tooltip('disable')`，提示就停止显示，并且在调用 `.tooltip('enable')` 之后再次显示。

# 接受小部件选项

现在是时候使我们的小部件可定制了。就像我们在构建 `.shadow()` 插件时看到的那样，为小部件提供一组可定制的默认值并用用户指定的选项覆盖这些默认值是友好的。几乎所有这个过程中的工作都是由小部件工厂完成的。我们所需要做的就是提供一个 `options` 属性：

```js
options: { 
  offsetX: 10, 
  offsetY: 10, 
  content: element => $(element).data('tooltip-text') 
}, 

```

列表 8.20

`options` 属性是一个普通对象。我们的小部件的所有有效选项都应该被表示出来，这样用户就不需要提供任何强制性的选项。在这里，我们为提示相对于其触发元素的 x 和 y 坐标提供了一个函数，以及一个为每个元素生成提示文本的函数。

我们代码中唯一需要检查这些选项的部分是 `._open()`：

```js
_open() {
  if (this.options.disabled) {
    return;
  }

  const elementOffset = this.element.offset();
  this._tooltipDiv
    .css({
      position: 'absolute',
      left: elementOffset.left + this.options.offsetX,
      top:
        elementOffset.top +
        this.element.height() +
        this.options.offsetY
    })
    .text(this.options.content(this.element))
    .show();
} 

```

列表 8.21

在`_open`方法内部，我们可以使用`this.options`访问这些属性。通过这种方式，我们总是能够得到选项的正确值：默认值或者用户提供的覆盖值。

我们仍然可以像`.tooltip()`这样无参数地添加我们的小部件，并获得默认行为。现在我们可以提供覆盖默认行为的选项：`.tooltip({ offsetX: -10, offsetX: 25 })`。小部件工厂甚至让我们在小部件实例化后更改这些选项：`.tooltip('option', 'offsetX', 20)`。下次访问选项时，我们将看到新值。

对选项更改做出反应

如果我们需要立即对选项更改做出反应，我们可以在小部件中添加一个`_setOption`函数来处理更改，然后调用`_setOption`的默认实现。

# 添加方法

内置方法很方便，但通常我们希望向插件的用户公开更多的钩子，就像我们使用内置的`destroy`方法所做的那样。我们已经看到如何在小部件内部创建新的私有函数。创建公共方法也是一样的，只是小部件属性的名称不以下划线开头。我们可以利用这一点很简单地创建手动打开和关闭工具提示的方法：

```js
open() { 
  this._open(); 
},
close() { 
  this._close(); 
}

```

列表 8.22

就是这样！通过添加调用私有函数的公共方法，我们现在可以使用`.tooltip('open')`打开工具提示，并使用`.tooltip('close')`关闭它。小部件工厂甚至会为我们处理一些细节，比如确保链式调用继续工作，即使我们的方法不返回任何东西。

# 触发小部件事件

一个优秀的插件不仅扩展了 jQuery，而且还为其他代码提供了许多扩展插件本身的机会。提供这种可扩展性的一个简单方法是支持与插件相关的一组自定义事件。小部件工厂使这个过程变得简单：

```js
_open() {
  if (this.options.disabled) {
    return;
  }

  const elementOffset = this.element.offset();
  this._tooltipDiv
    .css({
      position: 'absolute',
      left: elementOffset.left + this.options.offsetX,
      top:
        elementOffset.top +
        this.element.height() +
        this.options.offsetY
    })
    .text(this.options.content(this.element))
    .show();
  this._trigger('open');
},

_close: function() { 
  this._tooltipDiv.hide(); 
  this._trigger('close'); 
} 

```

列表 8.23

在我们的函数中调用`this._trigger()`允许代码监听新的自定义事件。事件的名称将以我们的小部件名称为前缀，因此我们不必过多担心与其他事件的冲突。例如，在我们的工具提示打开函数中调用`this._trigger('open')`，每次工具提示打开时都会发出名为`tooltipopen`的事件。我们可以通过在元素上调用`.on('tooltipopen')`来监听此事件。

这只是揭示了一个完整的小部件插件可能具有的潜力，但给了我们构建一个具有 jQuery UI 用户所期望的功能和符合标准的小部件所需的工具。

# 插件设计建议

现在，我们已经研究了通过创建插件来扩展 jQuery 和 jQuery UI 的常见方式，我们可以回顾并补充我们学到的内容，列出一些建议：

+   通过使用`jQuery`或将`$`传递给 IIFE 来保护`$`别名免受其他库的潜在干扰，以便它可以用作局部变量。

+   无论是扩展 jQuery 对象与 `$.myPlugin` 还是扩展 jQuery 原型与 `$.fn.myPlugin`，都不要向 `$` 命名空间添加超过一个属性。额外的公共方法和属性应添加到插件的命名空间中（例如，`$.myPlugin.publicMethod` 或 `$.fn.myPlugin.pluginProperty`）。

+   提供包含插件默认选项的对象：`$.fn.myPlugin.defaults = {size: 'large'}`。

+   允许插件用户选择性地覆盖所有后续调用方法的默认设置（`$.fn.myPlugin.defaults.size = 'medium';`）或单个调用的默认设置（`$('div').myPlugin({size: 'small'});`）。

+   在大多数情况下，当扩展 jQuery 原型时（`$.fn.myPlugin`），返回 `this` 以允许插件用户将其他 jQuery 方法链接到它（例如，`$('div').myPlugin().find('p').addClass('foo')`）。

+   当扩展 jQuery 原型时（`$.fn.myPlugin`），通过调用 `this.each()` 强制隐式迭代。

+   在适当的情况下使用回调函数，以允许灵活修改插件的行为，而无需更改插件的代码。

+   如果插件需要用户界面元素或需要跟踪元素状态，请使用 jQuery UI 小部件工厂创建。

+   使用像 QUnit 这样的测试框架为插件维护一组自动化单元测试，以确保其按预期工作。有关 QUnit 的更多信息，请参见附录 A。

+   使用诸如 Git 等版本控制系统跟踪代码的修订。考虑在 GitHub（[`github.com/`](http://github.com/)）上公开托管插件，并允许其他人贡献。

+   如果要使插件可供他人使用，请明确许可条款。考虑使用 MIT 许可证，jQuery 也使用此许可证。

# 分发插件

遵循前述建议，我们可以制作出符合经过时间考验的传统的干净、可维护的插件。如果它执行一个有用的、可重复使用的任务，我们可能希望与 jQuery 社区分享。

除了按照早前定义的方式正确准备插件代码之外，我们还应该在分发之前充分记录插件的操作。我们可以选择适合我们风格的文档格式，但可能要考虑一种标准，比如 JSDoc（在 [`usejsdoc.org/`](http://usejsdoc.org/) 中描述）。有几种自动文档生成器可用，包括 docco（[`jashkenas.github.com/docco/`](http://jashkenas.github.com/docco/)）和 dox（[`github.com/visionmedia/dox`](https://github.com/visionmedia/dox)）。无论格式如何，我们都必须确保我们的文档涵盖了插件方法可用的每个参数和选项。

插件代码和文档可以托管在任何地方；npm（[`www.npmjs.com/`](https://www.npmjs.com/)）是标准选项。有关将 jQuery 插件发布为 npm 软件包的更多信息，请查看此页面：[`blog.npmjs.org/post/112064849860/using-jquery-plugins-with-npm`](http://blog.npmjs.org/post/112064849860/using-jquery-plugins-with-npm)。

# 摘要

在本章中，我们看到 jQuery 核心提供的功能不必限制库的功能。除了我们在第七章*使用插件*中探讨的现成插件外，我们现在知道如何自己扩展功能菜单。

我们创建的插件包含各种功能，包括使用 jQuery 库的全局函数、用于操作 DOM 元素的 jQuery 对象的新方法以及复杂的 jQuery UI 小部件。有了这些工具，我们可以塑造 jQuery 和我们自己的 JavaScript 代码，使其成为我们想要的任何形式。

# 练习

挑战练习可能需要使用[`api.jquery.com/`](http://api.jquery.com/)上的官方 jQuery 文档。

1.  创建名为`.slideFadeIn()`和`.slideFadeOut()`的新插件方法，将`.fadeIn()`和`.fadeOut()`的不透明度动画与`.slideDown()`和`.slideUp()`的高度动画结合起来。

1.  扩展`.shadow()`方法的可定制性，以便插件用户可以指定克隆副本的 z-index。

1.  为工具提示小部件添加一个名为`isOpen`的新子方法。该子方法应该在工具提示当前显示时返回`true`，否则返回`false`。

1.  添加监听我们小部件触发的`tooltipopen`事件的代码，并在控制台中记录一条消息。

1.  **挑战**：为工具提示小部件提供一个替代的`content`选项，该选项通过 Ajax 获取锚点的`href`指向页面的内容，并将该内容显示为工具提示文本。

1.  **挑战**：为工具提示小部件提供一个新的`effect`选项，如果指定了，将应用指定的 jQuery UI 效果（比如`explode`）来显示和隐藏工具提示。


# 第九章：高级选择器和遍历

2009 年 1 月，jQuery 的创始人约翰·雷西格（**John Resig**）推出了一个名为**Sizzle**的新开源 JavaScript 项目。作为一个独立的**CSS 选择器引擎**，Sizzle 的编写旨在让任何 JavaScript 库都能够在几乎不修改其代码库的情况下采用它。事实上，jQuery 自从 1.3 版本以来一直在使用 Sizzle 作为其自己的选择器引擎。

Sizzle 是 jQuery 中负责解析我们放入`$()`函数中的 CSS 选择器表达式的组件。它确定要使用哪些原生 DOM 方法，因为它构建了一个我们可以用其他 jQuery 方法操作的元素集合。Sizzle 和 jQuery 的遍历方法集合的结合使得 jQuery 成为查找页面元素的非常强大的工具。

在第二章，*选择元素*中，我们查看了 jQuery 库中每种基本类型的选择器和遍历方法，以便我们了解在 jQuery 库中可用的内容。在这个更高级的章节中，我们将涵盖：

+   使用选择器以各种方式查找和过滤数据

+   编写添加新选择器和 DOM 遍历方法的插件

+   优化我们的选择器表达式以获得更好的性能

+   了解 Sizzle 引擎的一些内部工作 ings

# 选择和遍历重访

为了更深入地了解选择器和遍历，我们将构建一个脚本，提供更多选择和遍历示例以进行检查。对于我们的示例，我们将构建一个包含新闻项列表的 HTML 文档。我们将这些项目放在一个表格中，以便我们可以以几种方式选择行和列进行实验：

```js
<div id="topics"> 
  Topics: 
  <a href="topics/all.html" class="selected">All</a> 
  <a href="topics/community.html">Community</a> 
  <a href="topics/conferences.html">Conferences</a> 
  <!-- continued... --> 
</div> 
<table id="news"> 
  <thead> 
    <tr> 
      <th>Date</th> 
      <th>Headline</th> 
      <th>Author</th> 
      <th>Topic</th> 
    </tr> 
  </thead> 
  <tbody> 
    <tr> 
      <th colspan="4">2011</th> 
    </tr> 
    <tr> 
      <td>Apr 15</td> 
      <td>jQuery 1.6 Beta 1 Released</td> 
      <td>John Resig</td> 
      <td>Releases</td> 
    </tr> 
    <tr> 
      <td>Feb 24</td> 
      <td>jQuery Conference 2011: San Francisco Bay Area</td> 
      <td>Ralph Whitbeck</td> 
      <td>Conferences</td> 
    </tr> 
    <!-- continued... --> 
  </tbody> 
</table> 

```

获取示例代码

您可以从以下 GitHub 存储库访问示例代码：[`github.com/PacktPublishing/Learning-jQuery-3`](https://github.com/PacktPublishing/Learning-jQuery-3)。

从这个代码片段中，我们可以看到文档的结构。表格有四列，代表日期、标题、作者和主题，但是一些表格行包含一个日历年的副标题，而不是这四个项目：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_09_001-1.jpg)

在标题和表格之间，有一组链接，代表着表格中的每个新闻主题。对于我们的第一个任务，我们将更改这些链接的行为，以*原地*过滤表格，而不需要导航到不同的页面。

# 动态表格过滤

为了使用主题链接来过滤表格，我们需要阻止其默认的链接行为。我们还应该为当前选择的主题给用户提供一些反馈：

```js
$(() => {
  $('#topics a')
    .click((e) => {
      e.preventDefault();
      $(e.target)
        .addClass('selected')
        .siblings('.selected')
        .removeClass('selected');
    });
}); 

```

列表 9.1

当点击其中一个链接时，我们会从所有主题链接中删除`selected`类，然后将`selected`类添加到新主题上。调用`.preventDefault()`可以阻止链接被跟踪。

接下来，我们需要实际执行过滤操作。作为解决此问题的第一步，我们可以隐藏表格中不包含主题文本的每一行：

```js
$(() => {
  $('#topics a')
    .click((e) => {
      e.preventDefault();
      const topic = $(e.target).text();

      $(e.target)
        .addClass('selected')
        .siblings('.selected')
        .removeClass('selected');

      $('#news tr').show();
      if (topic != 'All') {
        $(`#news tr:has(td):not(:contains("${topic}"))`)
          .hide();
      }
    });
}); 

```

列表 9.2

现在我们将链接的文本存储在常量`topic`中，以便我们可以将其与表格中的文本进行比较。首先，我们显示所有的表行，然后，如果主题不是全部，我们就隐藏不相关的行。我们用于此过程的选择器有点复杂：

```js
#news tr:has(td):not(:contains("topic")) 

```

选择器从简单开始，使用`#news tr`定位表中的所有行。然后我们使用`:has()`自定义选择器来过滤这个元素集。这个选择器将当前选定的元素减少到那些包含指定后代的元素。在这种情况下，我们正在消除要考虑的标题行（如日历年份），因为它们不包含`<td>`单元格。

一旦我们找到了表的行，其中包含实际内容，我们就需要找出哪些行与所选主题相关。`:contains()`自定义选择器仅匹配具有给定文本字符串的元素；将其包装在`:not()`选择器中，然后我们就可以隐藏所有不包含主题字符串的行。

这段代码运行得足够好，除非主题恰好出现在新闻标题中，例如。我们还需要处理一个主题是另一个主题子串的可能性。为了处理这些情况，我们需要对每一行执行代码：

```js
$(() => {
  $('#topics a')
    .click((e) => {
      e.preventDefault();
      const topic = $(e.target).text();

      $(e.target)
        .addClass('selected')
        .siblings('.selected')
        .removeClass('selected');

      $('#news tr').show();
      if (topic != 'All') {
        $('#news')
          .find('tr:has(td)')
          .not((i, element) =>
            $(element)
              .children(':nth-child(4)')
              .text() == topic
          )
          .hide();
      }
    });
}); 

```

列表 9.3

这段新代码通过添加 DOM 遍历方法消除了一些复杂的选择器表达式文本。`.find()`方法的作用就像之前将`#news`和`tr`分开的空格一样，但是`.not()`方法做了`：not()`不能做的事情。就像我们在第二章中看到的`.filter()`方法一样，`.not()`可以接受一个回调函数，每次测试一个元素时调用。如果该函数返回`true`，则将该元素从结果集中排除。

选择器与遍历方法

使用选择器或其等效的遍历方法的选择在性能上也有影响。我们将在本章后面更详细地探讨这个选择。

在`.not()`方法的过滤函数中，我们检查行的子元素，找到第四个（也就是`Topic`列中的单元格）。对这个单元格的文本进行简单检查就能告诉我们是否应该隐藏该行。只有匹配的行会被显示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_09_002-1.jpg)

# 条纹表行

在第二章中，我们的选择器示例之一演示了如何将交替的行颜色应用于表格。我们看到，`:even`和`:odd`自定义选择器可以轻松完成这项任务，CSS 本地的`:nth-child()`伪类也可以完成：

```js
$(() => { 
  $('#news tr:nth-child(even)')
    .addClass('alt'); 
}); 

```

列表 9.4

这个直接的选择器找到每个表行，因为每年的新闻文章都放在自己的`<tbody>`元素中，所以每个部分都重新开始交替。

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_09_003-1.jpg)

对于更复杂的行条纹挑战，我们可以尝试一次给两行设置`alt`类。前两行将收到类，然后接下来的两行将不会，以此类推。为了实现这一点，我们需要重新审视**过滤函数**：

```js
$(() => { 
  $('#news tr')
    .filter(i => (i % 4) < 2)
    .addClass('alt'); 
}); 

```

列表 9.5

在第二章中的我们的`.filter()`示例中，*选择元素*，以及*列表 9.3*中的`.not()`示例中，我们的过滤函数会检查每个元素，以确定是否将其包含在结果集中。但是，在这里，我们不需要关于元素的信息来确定是否应该包含它。相反，我们需要知道它在原始元素集合中的位置。这些信息作为参数传递给函数，并且我们将其称为`i`。

现在，`i`参数保存了元素的从零开始的索引。有了这个，我们可以使用取模运算符（`%`）来确定我们是否在应该接收`alt`类的一对元素中。现在，我们在整个表中有两行间隔。

然而，还有一些松散的地方需要清理。因为我们不再使用`:nth-child()`伪类，所以交替不再在每个`<tbody>`中重新开始。另外，我们应该跳过表头行以保持一致的外观。通过进行一些小的修改，可以实现这些目标：

```js
$(() => {
  $('#news tbody')
    .each((i, element) => {
      $(element)
        .children()
        .has('td')
        .filter(i => (i % 4) < 2)
        .addClass('alt');
    });
}); 

```

列表 9.6

为了独立处理每组行，我们可以使用`.each()`调用对`<tbody>`元素进行循环。在循环内部，我们像在*列表 9.3*中那样排除子标题行，使用`.has()`。结果是表被分成两行的一组进行条纹处理：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_09_004-1.jpg)

# 结合过滤和条纹

我们的高级表格条纹现在工作得很好，但在使用主题过滤器时行为奇怪。为了使这两个函数协调良好，我们需要在每次使用过滤器时重新为表添加条纹。我们还需要考虑当前行是否隐藏，以确定在哪里应用`alt`类：

```js
$(() => {
  function stripe() {
    $('#news')
      .find('tr.alt')
      .removeClass('alt')
      .end()
      .find('tbody')
      .each((i, element) => {
        $(element)
          .children(':visible')
          .has('td')
          .filter(i => (i % 4) < 2)
          .addClass('alt');
      });
  }
  stripe();

  $('#topics a')
    .click((e) => {
      e.preventDefault();
      const topic = $(e.target).text();

      $(e.target)
        .addClass('selected')
        .siblings('.selected')
        .removeClass('selected');

      $('#news tr').show();
      if (topic != 'All') {
        $('#news')
          .find('tr:has(td)')
          .not((i, element) =>
            $(element)
              .children(':nth-child(4)')
              .text() == topic
          )
          .hide();
      }

      stripe();
    });
}); 

```

列表 9.7

将*列表 9.3*中的过滤代码与我们的行条纹例程结合起来，这个脚本现在定义了一个名为`stripe()`的函数，当文档加载时调用一次，每当点击主题链接时再次调用。在函数内部，我们负责从不再需要它的行中删除`alt`类，以及将所选行限制为当前显示的行。我们使用`:visible`伪类来实现这一点，它（以及它的对应项`:hidden`）尊重元素是否由于各种原因而隐藏，包括具有`display`值为`none`，或`width`和`height`值为`0`。

我们现在可以过滤我们表的行而保留我们的行条纹：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_09_05.png)

# 更多选择器和遍历方法

即使在我们看到的所有示例之后，我们也没有接近探索使用 jQuery 在页面上找到元素的每一种方式。我们有数十个选择器和 DOM 遍历方法可用，并且每个方法都有特定的实用性，我们可能需要调用其中的某一个。

要找到适合我们需求的选择器或方法，我们有许多资源可用。本书末尾的快速参考列出了每个选择器和方法，并简要描述了每个选择器和方法。然而，对于更详细的描述和用法示例，我们需要更全面的指南，比如在线 jQuery API 参考。该网站列出了所有选择器在 [`api.jquery.com/category/selectors/`](http://api.jquery.com/category/selectors/)，以及遍历方法在 [`api.jquery.com/category/traversing/`](http://api.jquery.com/category/traversing/)。

# 自定义和优化选择器

我们看到的许多技术都为我们提供了一个工具箱，可用于找到我们想要处理的任何页面元素。然而，故事并没有结束；有很多关于如何有效执行我们的元素查找任务的知识需要学习。这种效率可以以编写和阅读更简单的代码，以及在 web 浏览器内更快执行的代码形式呈现。

# 编写自定义选择器插件

提高可读性的一种方法是将代码片段封装在可重用组件中。我们通过创建函数一直在做这件事。在 第八章，*开发插件* 中，我们通过创建 jQuery 插件来为 jQuery 对象添加方法来扩展这个想法。然而，插件不仅仅可以帮助我们重用代码。插件还可以提供额外的**选择器表达式**，比如 Cycle 在 第七章，*使用插件* 中给我们的 `:paused` 选择器。

要添加的最简单类型的选择器表达式是**伪类**。这是以冒号开头的表达式，比如 `:checked` 或 `:nth-child()`。为了说明创建选择器表达式的过程，我们将构建一个名为 `:group()` 的伪类。这个新选择器将封装我们用来找到表格行以执行条纹化的代码，就像 *列表 9.6* 中一样。

当使用选择器表达式查找元素时，jQuery 会在内部对象 `expr` 中查找指令。这个对象中的值的行为类似于我们传递给 `.filter()` 或 `.not()` 的过滤函数，包含导致每个元素包含在结果集中的 JavaScript 代码，仅当函数返回 `true` 时才会包含。我们可以使用 `$.extend()` 函数向这个对象添加新的表达式：

```js
(($) => {
  $.extend($.expr[':'], {
    group(element, index, matches) {
      const num = parseInt(matches[3], 10);

      return Number.isInteger(num) &&
        ($(element).index() - 1) % (num * 2) < num;
    }
  });
})(jQuery); 

```

列表 9.8

这段代码告诉 jQuery `group` 是一个有效的字符串，可以跟在选择器表达式的冒号后面，当遇到它时，应调用给定的函数来确定是否应将元素包含在结果集中。

这里评估的函数传递了四个参数：

+   `element`：要考虑的 DOM 元素。大多数选择器都需要这个，但我们的不需要。

+   `index`：结果集中的 DOM 元素的索引。不幸的是，这总是 0，我们不能依赖它。这里包括它的唯一原因是因为我们需要对匹配参数进行位置访问。

+   `matches`：包含用于解析此选择器的正则表达式结果的数组。通常，`matches[3]`是数组中唯一相关的项目；在形式为`:group(2)`的选择器中，`matches[3]`项包含`2`，即括号内的文本。

伪类选择器可以使用这三个参数中的部分或全部信息来确定元素是否属于结果集。在这种情况下，我们只需要`element`和`matches`。实际上，我们确实需要传递给此函数的每个元素的索引位置。由于无法依赖`index`参数，因此我们简单地使用`.index()` jQuery 方法来获取索引。

有了新的`:group`选择器，我们现在有了一种灵活的方式来选择交替的元素组。例如，我们可以将选择器表达式和`.filter()`函数从*列表 9.5*合并为一个单一的选择器表达式：`$('#news tr:group(2)')`，或者我们可以保留*列表 9.7*中的每节行为，并将`:group()`作为一个表达式在`.filter()`调用中使用。我们甚至可以通过简单地在括号内更改数字来更改要分组的行数：

```js
$(() => { 
  function stripe() {
    $('#news')
      .find('tr.alt')
      .removeClass('alt')
      .end()
      .find('tbody')
      .each((i, element) => {
        $(element)
          .children(':visible')
          .has('td')
          .filter(':group(3)')
          .addClass('alt');
      });
  }

  stripe(); 
}); 

```

列表 9.9

现在我们可以看到，行条纹以三个一组交替：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_09_006-1.jpg)

# 选择器性能

在规划任何 web 开发项目时，我们需要记住创建网站所需的时间、我们可以维护代码的轻松程度和速度，以及用户与网站交互时的性能。通常，这些关注点中的前两个比第三个更重要。特别是在客户端脚本编写方面，开发者很容易陷入**过早优化**和**微优化**的陷阱。这些陷阱会导致我们花费无数小时微调我们的代码，以从 JavaScript 执行时间中削减毫秒，即使一开始没有注意到性能滞后。

一个很好的经验法则是认为开发者的时间比计算机的时间更宝贵，除非用户注意到我们应用程序的速度变慢。

即使性能是一个问题，定位我们的 jQuery 代码中的瓶颈也可能很困难。正如我们在本章前面提到的，某些选择器通常比其他选择器快，将选择器的一部分移到遍历方法中可以帮助加快在页面上查找元素所需的时间。因此，选择器和遍历性能通常是开始检查我们的代码以减少用户与页面交互时可能遇到的延迟量的良好起点。

关于选择器和遍历方法的相对速度的任何判断都可能随着发布更新、更快的浏览器和新版本 jQuery 引入的聪明速度调整而过时。在性能方面，经常质疑我们的假设，并在使用像**jsPerf**（[`jsperf.com`](http://jsperf.com)）这样的工具进行测量后优化代码是个好主意。

在这种情况下，我们将检查一些简单的指南，以生成优化的 jQuery 选择器代码。

# Sizzle 选择器实现

正如本章开始时所指出的，当我们将选择器表达式传递给`$()`函数时，jQuery 的 Sizzle 实现会解析表达式并确定如何收集其中表示的元素。在其基本形式中，Sizzle 应用最有效的本地**DOM 方法**，浏览器支持以获取`nodeList`，这是一个 DOM 元素的本机类似数组对象，jQuery 最终会将其转换为真正的数组，并将其添加到`jQuery`对象。以下是 jQuery 内部使用的 DOM 方法列表，以及支持它们的最新浏览器版本：

| **方法** | **选择** | **支持者** |
| --- | --- | --- |
| `.getElementById()` | 与给定字符串匹配的唯一元素的 ID。 | 所有浏览器 |
| `.getElementsByTagName()` | 所有标签名称与给定字符串匹配的元素。 | 所有浏览器 |
| `.getElementsByClassName()` | 具有其中一个类名与给定字符串匹配的所有元素。 | IE9+，Firefox 3+，Safari 4+，Chrome 4+，和 Opera 10+ |
| `.querySelectorAll()` | 所有匹配给定选择器表达式的元素。 | IE8+，Firefox 3.5+，Safari 3+，Chrome 4+，和 Opera 10+ |

如果选择器表达式的某个部分不能由这些方法之一处理，Sizzle 会回退到循环遍历已经收集的每个元素，并针对表达式的每个部分进行测试。如果选择器表达式的*任何*部分都不能由 DOM 方法处理，Sizzle 就会以`document.getElementsByTagName('*')`表示的文档中*所有*元素的集合开始，并逐个遍历每个元素。

这种循环和测试每个元素的方法在性能上要比任何本地 DOM 方法昂贵得多。幸运的是，现代桌面浏览器的最新版本都包括本地的`.querySelectorAll()`方法，并且当它不能使用其他更快的本地方法时，Sizzle 会使用它--只有一个例外。当选择器表达式包含像`:eq()`或`:odd`或`:even`这样没有 CSS 对应的自定义 jQuery 选择器时，Sizzle 就别无选择，只能循环和测试。

# 测试选择器速度

要了解 `.querySelectorAll()` 和 *循环测试* 过程之间的性能差异，可以考虑一个文档，其中我们希望选择所有 `<input type="text">` 元素。我们可以用两种方式编写选择器表达式：`$('input[type="text"]')`，使用 *CSS 属性选择器*，或者 `$('input:text')`，使用 *自定义 jQuery 选择器*。为了测试我们在这里感兴趣的选择器部分，我们将移除 `input` 部分，并比较 `$('[type="text"]')` 和 `$(':text')` 的速度。JavaScript 基准测试网站 [`jsperf.com/`](http://jsperf.com/) 让我们可以进行这种比较，得出戏剧性的结果。

在 jsPerf 测试中，每个测试用例会循环执行，以查看在一定时间内可以完成多少次，因此数字越高越好。在支持 `.querySelectorAll()` 的现代浏览器（Chrome 26、Firefox 20 和 Safari 6）中进行测试时，能够利用它的选择器比自定义的 jQuery 选择器要快得多：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_09_07.png)

图 9.1

但是，在不支持 `.querySelectorAll()` 的浏览器中，例如 IE 7，这两个选择器的性能几乎相同。在这种情况下，这两个选择器都会强制 jQuery 循环遍历页面上的每个元素，并分别测试每个元素：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_09_08.png)

图 9.2

当我们查看 `$('input:eq(1)')` 和 `$('input') .eq(1)` 时，使用原生方法和不使用原生方法的选择器之间的性能差异也是显而易见的：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_09_09.png)

图 9.3

尽管每秒操作次数在不同浏览器之间有很大差异，但所有测试的浏览器在将自定义的 `:eq()` 选择器移出到 `.eq()` 方法时都显示出显著的性能提升。使用简单的 `input` 标签名称作为 `$()` 函数的参数允许快速查找，然后 `.eq()` 方法简单地调用数组函数来检索 jQuery 集合中的第二个元素。

作为一个经验法则，我们应尽可能使用 CSS 规范中的选择器，而不是 jQuery 的自定义选择器。但在更改选择器之前，先确认是否需要提高性能是有意义的，然后使用诸如 [`jsperf.com`](http://jsperf.com) 这样的基准测试工具测试更改能够提升多少性能。

# 在幕后进行 DOM 遍历

在第二章中，*选择元素*，以及本章的开头，我们讨论了通过调用 DOM 遍历方法从一个 DOM 元素集合到另一个 DOM 元素集合的方法。我们（远非详尽）的调查包括简单到达相邻单元格的简单方法，例如 `.next()` 和 `.parent()`，以及更复杂的组合选择器表达式的方式，例如 `.find()` 和 `.filter()`。到目前为止，我们应该对这些一步步从一个 DOM 元素到另一个 DOM 元素的方法有相当牢固的掌握。

每次我们执行其中一步时，jQuery 都会记录我们的行程，留下一串面包屑，如果需要的话，我们可以按照这些面包屑回到家里。在那一章中我们简要提及的几个方法，`.end()` 和 `.addBack()`，利用了这种记录。为了能够充分利用这些方法，并且一般来说编写高效的 jQuery 代码，我们需要更多地了解 DOM 遍历方法如何执行它们的工作。

# jQuery 遍历属性

我们知道，通常通过将选择器表达式传递给 `$()` 函数来构造 jQuery 对象实例。在生成的对象内部，存在一个包含与该选择器匹配的每个 DOM 元素引用的数组结构。不过，我们没有看到对象中隐藏的其他属性。例如，当调用 DOM 遍历方法时，`.prevObject` 属性保存了对调用该遍历方法的 jQuery 对象的引用。

jQuery 对象用于暴露 `selector` 和 `context` 属性。由于它们对我们没有提供任何价值，在 jQuery 3 中已经被移除。

要查看 `prevObject` 属性的作用，我们可以突出显示表格的任意单元格并检查其值：

```js
$(() => { 
  const $cell = $('#release');
    .addClass('highlight'); 
  console.log('prevObject', $cell.prevObject); 
}); 

```

列表 9.10

此代码段将突出显示所选单个单元格，如下图所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_09_10.png)

我们可以看到 `.prevObject` 未定义，因为这是一个新创建的对象。但是，如果我们将遍历方法添加到混合中，情况就会变得更加有趣：

```js
$(() => { 
  const $cell = $('#release')
    .nextAll()
    .addClass('highlight'); 
  console.log('prevObject', $cell.prevObject); 
}); 

```

列表 9.11

此更改改变了高亮显示的单元格，如下图所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_09_11.png)

现在，我们最初选择的单元格后面的两个单元格被突出显示。在 jQuery 对象内部，`.prevObject` 现在指向 `.nextAll()` 调用之前的原始 jQuery 对象实例。

# DOM 元素栈

由于每个 jQuery 对象实例都有一个 `.prevObject` 属性，指向前一个对象，我们有了一个实现 **栈** 的链表结构。每次遍历方法调用都会找到一组新的元素并将此集合推入堆栈。只有在我们可以对此堆栈执行某些操作时，才有用，这就是 `.end()` 和 `.addBack()` 方法发挥作用的地方。

`.end()` 方法简单地从堆栈的末尾弹出一个元素，这与获取 `.prevObject` 属性的值相同。我们在第二章中看到了一个示例，*选择元素*，在本章后面我们还会看到更多。然而，为了得到更有趣的例子，我们将研究 `.addBack()` 如何操作堆栈：

```js
$(() => { 
  $('#release')
    .nextAll()
    .addBack()
    .addClass('highlight'); 
}); 

```

列表 9.12

再次，高亮显示的单元格已更改：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_09_12.png)

当调用 `.addBack()` 方法时，jQuery 回顾栈上的上一步并将两个元素集合合并起来。在我们的例子中，这意味着突出显示的单元格包括 `.nextAll()` 调用找到的两个单元格和使用选择器定位的原始单元格。然后，这个新的、合并的元素集合被推到栈上。

这种栈操作方式非常有用。为了确保在需要时这些技术能够发挥作用，每个遍历方法的实现都必须正确更新栈；这意味着如果我们想提供自己的遍历方法，我们需要了解系统的一些内部工作原理。

# 编写 DOM 遍历方法插件

和任何其他 jQuery 对象方法一样，遍历方法可以通过向 `$.fn` 添加属性来添加到 jQuery 中。我们在第八章中看到，我们定义的新的 jQuery 方法应该在匹配的元素集合上操作，然后返回 jQuery 对象，以便用户可以链式调用其他方法。当我们创建 DOM 遍历方法时，这个过程是类似的，但是我们返回的 jQuery 对象需要指向一个新的匹配元素集合。

举个例子，我们将构建一个插件，找到与给定单元格相同列的所有表格单元格。首先我们将完整地查看插件代码，然后逐个地分析它，以了解它的工作原理：

```js
(($) => {
  $.fn.column = function() {
    var $cells = $();

    this.each(function(i, element) {
      const $td = $(element).closest('td, th');

      if ($td.length) {
        const colNum = $td[0].cellIndex + 1;
        const $columnCells = $td
          .closest('table')
          .find('td, th')
          .filter(`:nth-child(${colNum})`);

        $cells = $cells.add($columnCells);
      }
    });

    return this.pushStack($cells);
  };
})(jQuery); 

```

第 9.13 节

我们的 `.column()` 方法可以在指向零个、一个或多个 DOM 元素的 jQuery 对象上调用。为了考虑到所有这些可能性，我们使用 `.each()` 方法循环遍历元素，逐个将单元格列添加到变量 `$cells` 中。这个 `$cells` 变量一开始是一个空的 jQuery 对象，但随后通过 `.add()` 方法扩展到需要的更多 DOM 元素。

这解释了函数的外部循环；在循环内部，我们需要理解 `$columnCells` 如何填充表列中的 DOM 元素。首先，我们获取正在检查的表格单元格的引用。我们希望允许在表格单元格上或表格单元格内的元素上调用 `.column()` 方法。`.closest()` 方法为我们处理了这个问题；它在 DOM 树中向上移动，直到找到与我们提供的选择器匹配的元素。这个方法在事件委托中会非常有用，我们将在第十章中重新讨论，*高级事件*。

有了我们手头的表格单元格，我们使用 DOM 的 `.cellIndex` 属性找到它的列号。这给了我们一个基于零的单元格列的索引；我们在稍后的一个基于一的上下文中使用它时加上 `1`。然后，从单元格开始，我们向上移动到最近的 `<table>` 元素，再返回到 `<td>` 和 `<th>` 元素，并用 `:nth-child()` 选择器表达式过滤这些单元格，以获取适当的列。

我们正在编写的插件仅限于简单的、非嵌套的表格，因为 `.find('td, th')` 调用。要支持嵌套表格，我们需要确定是否存在 `<tbody>` 标签，并根据适当的数量在 DOM 树中上下移动，这将增加比这个示例适当的更多复杂性。

一旦我们找到了列中的所有单元格，我们需要返回新的 jQuery 对象。我们可以从我们的方法中直接返回 `$cells`，但这不会正确地尊重 DOM 元素堆栈。相反，我们将 `$cells` 传递给 `.pushStack()` 方法并返回结果。该方法接受一个 DOM 元素数组，并将它们添加到堆栈中，以便后续对 `.addBack()` 和 `.end()` 等方法的调用能够正确地工作。

若要查看我们的插件运行情况，我们可以对单元格的点击做出反应，并突出显示相应的列：

```js
$(() => { 
  $('#news td')
    .click((e) => {
      $(e.target)
        .siblings('.active')
        .removeClass('active')
        .end()
        .column()
        .addClass('active');
    });
}); 

```

第 9.14 节

`active` 类将添加到所选列，从而导致不同的着色，例如，当点击其中一位作者的姓名时：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_09_13.png)

# DOM 遍历性能

关于选择器性能的经验法则同样适用于 DOM 遍历性能：在可能的情况下，我们应该优先考虑代码编写和代码维护的便利性，只有在性能是可测量的问题时才会为了优化而牺牲可读性。同样，诸如 [`jsperf.com/`](http://jsperf.com/) 这样的网站有助于确定在给定多个选项的情况下采取最佳方法。

虽然应该避免过早地优化，但最小化选择器和遍历方法的重复是一个良好的实践。由于这些可能是昂贵的任务，我们做这些任务的次数越少越好。避免这种重复的两种策略是**链式操作**和**对象缓存**。

# 使用链式操作来改进性能

我们现在已经多次使用了链式操作，它使我们的代码保持简洁。链式操作也可能带来性能上的好处。

我们来自*第 9.9 节*的 `stripe()` 函数只定位了一次具有 ID `news` 的元素，而不是两次。它需要从不再需要的行中移除 `alt` 类，并将该类应用于新的行集。使用链式操作，我们将这两个想法合并成一个，避免了这种重复：

```js
$(() => {
  function stripe() {
    $('#news')
      .find('tr.alt')
      .removeClass('alt')
      .end()
      .find('tbody')
      .each((i, element) => {
        $(element)
          .children(':visible')
          .has('td')
          .filter(':group(3)')
          .addClass('alt');
      });
  }

  stripe();
}); 

```

第 9.15 节

为了合并两次使用 `$('#news')`，我们再次利用了 jQuery 对象内部的 DOM 元素堆栈。第一次调用 `.find()` 将表行推送到堆栈上，但然后 `.end()` 将其从堆栈中弹出，以便下一次 `.find()` 调用再次操作 `news` 表。这种巧妙地操作堆栈的方式是避免选择器重复的便捷方式。

# 使用缓存来改进性能

缓存只是简单地存储操作的结果，以便可以多次使用而不必再次运行该操作。在选择器和遍历性能的背景下，我们可以将 jQuery 对象缓存到常量中以供以后使用，而不是创建一个新的对象。

回到我们的示例，我们可以重写 `stripe()` 函数，以避免选择器重复，而不是链接：

```js
$(() => { 
  const $news = $('#news');

  function stripe() {
    $news
      .find('tr.alt')
      .removeClass('alt');
    $news
      .find('tbody')
      .each((i, element) => {
        $(element)
          .children(':visible')
          .has('td')
          .filter(':group(3)')
          .addClass('alt');
      });
  }

  stripe();
}); 

```

清单 9.16

这两个操作再次是分开的 JavaScript 语句，而不是链接在一起。尽管如此，我们仍然只执行了一次 `$('#news')` 选择器，通过将结果存储在 `$news` 中。这种缓存方法比链接更繁琐，因为我们需要单独创建存储 jQuery 对象的变量。显然，在代码中创建更多的常量比链接函数调用更不理想。但有时，链接简单地太复杂了，像这样缓存对象是更好的选择。

因为通过 ID 在页面上选择元素非常快，所以这些示例都不会对性能产生很大的影响，实际上我们会选择看起来最易读和易于维护的方法。但是当性能成为一个关注点时，这些技术是有用的工具。

# 总结

在本章中，我们更深入地了解了 jQuery 在查找文档中的元素方面的广泛功能。我们看了一些关于 Sizzle 选择器引擎如何工作的细节，以及这对设计有效和高效代码的影响。此外，我们还探讨了扩展和增强 jQuery 选择器和 DOM 遍历方法的方式。

# 进一步阅读

在本书的 附录 B、“快速参考” 中或在官方 jQuery 文档中，提供了一份完整的选择器和遍历方法列表。

# 练习

挑战性练习可能需要在 [`api.jquery.com/`](http://api.jquery.com/) 官方 jQuery 文档中使用。

1.  修改表格行条纹的例程，使其不给第一行任何类，第二行给予 `alt` 类，第三行给予 `alt-2` 类。对每组三行的行重复此模式。

1.  创建一个名为 `:containsExactly()` 的新选择器插件，它选择具有与括号内放置的内容完全匹配的文本内容的元素。

1.  使用这个新的 `:containsExactly()` 选择器来重写 *清单 9.3* 中的过滤代码。

1.  创建一个名为 `.grandparent()` 的新 DOM 遍历插件方法，它从一个或多个元素移动到它们在 DOM 中的祖父元素。

1.  **挑战**：使用 [`jsperf.com/`](http://jsperf.com/)，粘贴 `index.html` 的内容并比较使用以下内容查找 `<td id="release">` 的最近祖先表元素的性能：

+   `.closest()` 方法

+   `.parents()` 方法，将结果限制为找到的第一个表格

1.  **挑战**：使用 [`jsperf.com/`](http://jsperf.com/)，粘贴 `index.html` 的内容并比较使用以下内容查找每一行中最后一个 `<td>` 元素的性能：

+   `:last-child` 伪类

+   `:nth-child()` 伪类

+   每行内的`.last()`方法（使用`.each()`循环遍历行）

+   每行内的`:last`伪类（使用`.each()`循环遍历行）
