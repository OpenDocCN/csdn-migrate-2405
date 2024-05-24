# 精通 jQuery（三）

> 原文：[`zh.annas-archive.org/md5/0EE28037989D2E7006D982EBB8295FFE`](https://zh.annas-archive.org/md5/0EE28037989D2E7006D982EBB8295FFE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使用 jQuery 效果

在任何网站上添加事件处理程序是一个必要的步骤；毕竟，我们需要一些方式来响应我们代码中的合法事件。

另一方面，添加效果的反面是，如果做得好，它们可以带来巨大的回报，尽管其中一些新奇感可能会消失，特别是如果你已经过度使用了所有的核心效果！通过新的自定义效果使你的网站焕发活力 - 我们将在本章中看到如何做到这一点，以及如何管理生成的队列。在接下来的几页中，我们将涵盖以下主题：

+   重温基本效果

+   添加回调

+   构建自定义效果

+   创建和管理效果队列

感兴趣吗？让我们开始吧...

# 重温效果

一个问题 - 你多少次访问网站，看到内容平稳地向上滑动，或逐渐淡化至无？

我相信你当然会认出这些代码中提供的效果；这些可以是从简单的向上滑动到内容逐渐从一幅图像或元素淡入另一幅图像或元素的任何内容。

创建效果是任何网站的重要考虑因素。我们在本书的早些时候已经涉及了一些方法，在第六章中，*使用 jQuery 进行动画*。我相信我们都很熟悉淡入淡出或切换元素的基本代码。毫无疑问，在开发网站时，你会无数次地使用诸如`$("blockquote").fadeToggle(400);`或`$("div.hidden").show(1250);`这样的代码。

看起来很熟悉？在接下来的几页中，我们将介绍一些额外的技巧，可以帮助我们在添加效果时取得更好的效果，并考虑使用 jQuery 提供这些效果的一些影响。在此之前，有一个重要的问题需要澄清，那就是探索简单动画和向元素添加效果之间的关键区别。

## 探索动画和效果之间的差异

也许有些人会认为我们在第六章中讨论动画时已经涵盖了效果的提供，这是正确的，它们之间确实有一些重叠；快速查看 jQuery 效果的 API 列表将显示`.animate()`作为有效的效果方法。

然而，有一个重要的区别 - 我们已经讨论过的内容是关于*移动*元素的，而提供效果将专注于控制内容的*可见性*。不过，很棒的是，我们可以将这两者联系在一起。`.animate()`方法可以用来在代码中实现移动和效果。

现在这个小区别已经澄清了，让我们开始行动吧。我们将首先看一下如何向我们的效果添加自定义缓动函数。

# 创建自定义效果

如果你使用过`.animate()`或其快捷方法，比如`.fadeIn()`、`.show()`或`.slideUp()`对动画元素应用效果，那么你很可能都使用过它们。所有这些方法都遵循类似的格式，至少需要提供一个持续时间、缓动类型，还有可能需要提供一个回调函数，在动画完成时执行一个任务，或者在控制台中记录一些内容。

然而，我们在决定时往往会坚持使用标准值，比如`slow`、`fast`，或者可能是一个数值，比如`500`：

```js
$("button").click(function() {
  $("p").slideToggle("slow");
});
```

使用这种方法绝对没错，只是非常无聊，而且只能发挥出了很小一部分可能性。

在接下来的几页中，我们将探索一些技巧，用来拓宽我们在应用效果时的知识，了解到我们并不总是必须坚持已经验证过的方法。在我们探索这些技巧之前，不妨先了解一下这些效果在 Core jQuery 库中是如何处理的。

## 探索`animate()`方法作为效果的基础

如果你被要求使用预配置的效果，比如`hide()`或`slideToggle()`，那么你可能期望在 jQuery 内部使用一个命名函数。

### 注意

注意，本节中给出的行号适用于未压缩版本的 jQuery 2.1.3，可从[`code.jquery.com/jquery-2.1.3.js`](http://code.jquery.com/jquery-2.1.3.js)获取。

好吧，这是对的，但只是部分正确：jQuery 内部预配置的函数都是指向`animate()`的简写指针，就像在**6829**至**6840**行附近所示的那样。它们经过了两个阶段的处理：

+   第一阶段是向`genFX()`方法传递三个值，即`show`、`hide`或`toggle`。

+   这之后传递给`animate()`方法来产生最终效果，在**6708**至**6725**行。

代码中快速查看每个可用的值以及它们如何传递给`.animate()`：

![探索`animate()`方法作为效果的基础](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00406.jpeg)

我们在第六章 *使用 jQuery 进行动画* 中详细介绍了`animate()`的用法。以下是关于在我们的代码中使用`animate()`的几个关键要点：

+   只能支持取数值的属性，虽然有一些例外情况。一些值，比如`backgroundColor`，没有插件的情况下是无法进行动画的（jQuery Color – [`github.com/jquery/jquery-color`](https://github.com/jquery/jquery-color), 或 jQuery UI – [`www.jqueryui.com`](http://www.jqueryui.com)），还有一些属性可以取多个值，比如`background-position`。

+   可以通过使用适用的任何标准 CSS 单位来对 CSS 属性进行动画 – 完整列表可在[`www.w3schools.com/cssref/css_units.asp`](http://www.w3schools.com/cssref/css_units.asp)中查看。

+   元素可以使用相对值移动，这些相对值在属性值前加上`+=`或`-=`。如果设置了持续时间为`0`，则动画将立即将元素设置为它们的最终状态。

+   作为快捷方式，如果传递了`toggle`的值，动画将简单地从当前位置反转，并动画到目标位置。

+   通过单个`animate()`方法设置的所有 CSS 属性将同时进行动画处理。

现在我们已经看到了库中如何处理自定义效果，让我们探索创建一些新的效果，这些效果结合了库中已经可用的效果。

## 将自定义效果付诸实践

如果我们花费时间开发代码，限制在使用 jQuery 中可用的默认效果，我们很快就会超出它所能做的限制。

为了防止这种情况发生，值得花时间去研究我们真正想使用的效果，并看看我们是否可以从 jQuery 内部构建一些东西来复制它们。为了证明这一点，我们将深入一些示例；我们的第一个示例是基于点击选定元素产生一个切换效果。

### 创建一个 clickToggle 处理程序

我们三个示例中的第一个的灵感不来自在线评论，而是来自 jQuery 本身。核心库有一个可用的切换函数（如[`api.jquery.com/toggle-event/`](http://api.jquery.com/toggle-event/)所示），在版本 1.8 中已弃用，在 1.9 中已移除。

我们将探讨如何添加类似的功能，使用一个小型插件，想法是根据插件中设置的值的状态运行两个函数中的一个：

![创建 clickToggle 处理程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00407.jpeg)

让我们看看需要什么：

1.  我们将从本书的代码下载中提取相关文件开始。对于此演示，我们需要`clicktoggle.css`、`jquery.min.js`和`clicktoggle.html`文件。将 CSS 文件放在`css`子文件夹中，jQuery 库放在`js`子文件夹中，并将标记文件放在项目区域的根目录下。

1.  在一个新文件中，我们需要创建我们的`clicktoggle()`事件处理程序，所以继续并添加以下代码，并将其保存为`clicktoggle.js`：

    ```js
    $.fn.clicktoggle = function(a, b) {
      return this.each(function() {
        var clicked = false;
        $(this).on("click", function() {
          if (clicked) {
            clicked = false;
            return b.apply(this, arguments);
          }
          clicked = true;
          return a.apply(this, arguments);
        });
      });
    };
    ```

    ### 注意

    `apply()`函数用于调用函数的上下文 - 更多细节，请参阅[`api.jquery.com/Types/#Context.2C_Call_and_Apply`](http://api.jquery.com/Types/#Context.2C_Call_and_Apply)。

1.  在`clicktoggle`事件处理程序的下方立即添加以下函数：

    ```js
    function odd() {
      $("#mydiv").append("Your last number was: odd<br>");
    }

    function even() {
      $("#mydiv").append("Your last number was: even<br>");
    }

    $(document).ready(function() {
      $("#mydiv").clicktoggle(even, odd);
    });  
    The first two look after adding the appropriate response on screen, with the third firing off the event handler when text has been clicked.
    ```

1.  如果一切顺利，我们应该看到与练习开始时显示的屏幕截图类似的东西，在那里我们可以看到文本已经被点击了几次。

    ### 注意

    许多人已经产生了类似版本的代码 - 请参阅[`gist.github.com/gerbenvandijk/7542958`](https://gist.github.com/gerbenvandijk/7542958)作为一个例子；这个版本使用了`data-`标签并将处理函数合并到一个调用中。

好的，让我们继续，看看另一个示例：在这个示例中，我们将创建一个滑动淡入淡出切换效果。这将使用与前面示例相似的原理，我们将检查元素的状态。这次，我们将使用 `:visible` 伪选择器来确认应该在屏幕上呈现哪个回调消息。

### 注意

作为一个想法，为什么不尝试将这个插件与 [Toggles 插件](http://simontabor.com/labs/toggles/)结合使用呢？这可以用来制作一些漂亮的开关按钮。我们然后可以触发由本例中创建的 `clickToggle` 插件处理的事件。

### 使用滑动淡入淡出切换内容

在我们之前的示例中，我们的效果在屏幕上出现得非常突然 - 要么是一个声明，要么是另一个声明，但没有中间状态！

从视觉效果来看，这并不总是理想的；如果我们能让过渡更平滑，那会给人留下更柔和的印象。这就是滑动淡入淡出切换插件的作用。让我们看看如何创建它：

1.  我们将像往常一样，从附带本书的代码下载中提取我们需要的相关文件。对于这个演示，我们将需要常见的 `jquery.min.js`，以及 `slidefade.css` 和 `slidefade.html`。JavaScript 文件需要放在 `js` 子文件夹中，样式表需要放在 `css` 子文件夹中，HTML 标记文件需要放在我们项目区域的根目录中。

1.  在一个新文件中，让我们继续创建 `slideFadeToggle` 效果。将以下行添加到文件中，将其保存为 `slidefade.js`，并将其放在 `js` 子文件夹中：

    ```js
    jQuery.fn.slideFadeToggle = function(speed, easing, callback) {
      return this.animate({opacity: 'toggle', height: 'toggle'}, speed, easing, callback);
    };

    $(document).ready(function() {
      $("#sfbutton").on("click", function() {
        $(this).next().slideFadeToggle('slow', function() {
          var $this = $(this);
          if ($this.is(':visible')) {
            $this.text('Successfully opened.');
          } else {
            $this.text('Successfully closed.');
          }
        });
      });
    });
    ```

1.  如果一切顺利，那么当我们在浏览器中预览结果时，我们应该看到黑灰色的方块在我们单击按钮后淡出，这在以下图片中显示：![滑动淡入淡出切换内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00408.jpeg)

代码创建了一个漂亮的警告效果 - 它可以用来在您的网站内向访问者显示适当的消息，因为它滑入视图。我们的插件是基于在两个状态之间切换。如果您的首选是仅仅使用 `fadeIn()` 或 `fadeOut()` 状态的等效值，那么我们可以根据需要轻松地使用其中任何一个函数：

```js
$.fn.slideFadeIn  = function(speed, easing, callback) {
  return this.animate({opacity: 'show', height: 'show'}, speed, easing, callback);
};

$.fn.slideFadeOut  = function(speed, easing, callback) {
  return this.animate({opacity: 'hide', height: 'hide'}, speed, easing, callback);
};
```

好的，让我们继续。我们已经创建了一些自定义效果，但感觉还是缺了点什么。啊，是的 - 我知道了：从一个状态到另一个状态的缓动怎么样？（是的，绝对是双关语！）

我们可以添加一个缓动功能，不仅可以简单地设置慢速、快速、正常速度甚至是数字值来控制效果的持续时间，还可以增加一个缓动功能，使效果更具动感。让我们深入了解一下涉及到的内容。

# 对效果应用自定义缓动函数

如果有人对你提到 "缓动" 这个词，我敢打赌会发生两件事中的一件：

+   你很可能会认为你需要使用 jQuery UI，这可能会向页面添加相当大的代码块

+   你可能会逃跑，一想到要解决一些可怕的数学问题！

不过，这里的讽刺是，对于两者的答案可能是肯定的也可能是否定的（至少对于第二个评论的前半部分而言）。等等，怎么回事？

之所以如此，是因为你绝对不需要 jQuery UI 提供特殊的缓动函数。当然，如果你已经在使用它，那么使用其中包含的效果是有道理的。虽然你可能需要计算一些数学问题，但这只有在你真正想要深入研究复杂的公式时才是必要的。感兴趣吗？让我解释一下。

将缓动添加到代码中不必超过一个简单的函数，该函数使用下表中的五个不同值之一，如下表所示：

| 值 | 目的 |
| --- | --- |
| `x` | `null`请注意，虽然始终包含 `x`，但几乎总是设置为 null 值。 |
| `t` | 经过的时间。 |
| `b` | 初始值 |
| `c` | 变化的量 |
| `d` | 持续时间 |

在正确的组合中，它们可以用来产生一个缓动效果，例如 jQuery UI 中可用的 `easeOutCirc` 效果：

```js
$.easing.easeOutCirc= function (x, t, b, c, d) {
  return c * Math.sqrt(1 - (t=t/d-1)*t) + b;
}
```

进一步说，我们总是可以计算出自己的自定义缓动函数。一个很好的例子在 [`tumblr.ximi.io/post/9587655506/custom-easing-function-in-jquery`](http://tumblr.ximi.io/post/9587655506/custom-easing-function-in-jquery) 中概述，其中包括使其在 jQuery 中运行所需的评论。作为替代方案，你也可以尝试 [`gizma.com/easing/`](http://gizma.com/easing/)，其中列出了几个类似效果的例子。

我认为现在是我们实践的时候了。让我们深入其中，利用这些值来创建自己的缓动函数。我们将从为我们之前的示例添加一个预定义的缓动开始，然后将其剥离并替换为自定义创建。

## 添加自定义缓动到我们的效果中

当然，我们可以使用像 Easing 插件这样的工具，可以从 [`gsgd.co.uk/sandbox/jquery/easing/`](http://gsgd.co.uk/sandbox/jquery/easing/) 下载，或者甚至使用 jQuery UI 本身。但其实并不需要。添加基本的缓动效果只需要几行代码。

尽管涉及的数学可能不容易，但添加特定的缓动值却很容易。让我们看一些例子：

1.  对于这个演示，我们将从本书附带的代码下载中提取相关文件。我们需要 `slidefade.html`、`slidefade.js`、`jquery.min.js` 和 `slidefade.css` 文件。这些文件需要保存到我们项目区域的相应文件夹中。

1.  在 `slidefade.js` 的副本中，我们需要添加我们的缓动效果。在 `slideFadeToggle()` 函数之前，立即在文件开始处添加以下代码：

    ```js
    $.easing.easeOutCirc= function (x, t, b, c, d) {
      return c * Math.sqrt(1 - (t=t/d-1)*t) + b;
    }
    ```

1.  尽管我们已经添加了缓动效果，但我们仍然需要告诉我们的事件处理程序去使用它。为此，我们需要修改代码如下所示：

    ```js
    $(document).ready(function() {
      $("#sfbutton").on("click", function() {
        $(this).next().slideFadeToggle(1000, 'easeOutCirc');
      });
    });
    ```

1.  将文件保存为`slidefadeeasing.html`、`slidefadeeasing.css`和`slidefadeeasing.js`，然后在浏览器中预览结果。如果一切正常，我们应该注意到`<div>`元素在收缩和渐隐过程中有所不同。

在这个阶段，我们已经有了创建自定义缓动函数的完美基础。为了测试这一点，请尝试以下操作：

1.  浏览到位于[`www.madeinflex.com/img/entries/2007/05/customeasingexplorer.html`](http://www.madeinflex.com/img/entries/2007/05/customeasingexplorer.html)的自定义缓动函数资源管理器网站，然后使用滑块设置以下值：

    +   `Offset: 420`

    +   `P1: 900`

    +   `P2: -144`

    +   `P3: 660`

    +   `P4: 686`

    +   `P5: 868`

1.  这将生成以下方程函数：

    ```js
    function(t:Number, b:Number, c:Number, d:Number):Number {
      var ts:Number=(t/=d)*t;
      var tc:Number=ts*t;
      return b+c*(21.33482142857142*tc*ts +  - 66.94196428571428*ts*ts + 75.26785714285714*tc +  - 34.01785714285714*ts + 5.357142857142857*t);
    }
    ```

1.  就目前而言，我们的方程在代码中使用时不会起作用；我们需要编辑它。删除所有`:Number`的实例，然后在参数中的`t`之前添加一个`x`。当编辑后，代码将如下所示 – 我给它赋了一个缓动名称：

    ```js
    $.easing.alexCustom = function(x, t, b, c, d) {
      var ts=(t/=d)*t;
      var tc=ts*t;
      return b+c*(21.33482142857142*tc*ts +  - 66.94196428571428*ts*ts + 75.26785714285714*tc +  - 34.01785714285714*ts + 5.357142857142857*t);
    }
    ```

1.  将其放入`slidefade.js`，然后修改`document.ready()`块中使用的缓动名称，并运行代码。如果一切正常，我们将在动画`<div>`元素时使用新的自定义缓动。

这开启了许多可能性。手动编写我们刚生成的函数是可行的，但需要大量的努力。最好的结果是使用缓动函数生成器为我们生成结果。

现在，我们可以继续使用像我们在这里检查的两个函数一样的函数，但这似乎是一个很难解决的难题，每次我们想要为动画元素提供一些变化时！我们也可以懒惰一些，简单地从 jQuery UI 中导入效果，但这也会带来很多不必要的负担；jQuery 应该是提供轻量级方法的！

相反，我们可以使用一种更简单的选项。虽然许多人最初可能会害怕使用贝塞尔曲线，但有些善良的人已经为我们完成了大部分繁重的工作，这使得在创建效果时使用起来非常轻松。

## 在效果中使用贝塞尔曲线

一个问题 – 请举手，如果您能猜出雷诺和雪铁龙除了是两个竞争对手汽车制造商之外，还有什么共同之处？答案是我们下一个话题的主题 – 贝塞尔曲线！

是的，也许很难相信，但贝塞尔曲线曾在 1962 年用于雷诺的汽车设计中，尽管在此之前雪铁龙就已经使用了，早在 1959 年。

但是，我岔开了话题 – 我们在这里是来看如何在 jQuery 中使用贝塞尔曲线的，例如下一个示例：

![在效果中使用贝塞尔曲线](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00409.jpeg)

### 提示

您可以在[`cubic-bezier.com/#.25,.99,.73,.44`](http://cubic-bezier.com/#.25,.99,.73,.44)查看此示例。

这些默认不受支持；尝试过将其支持整合进去，但没有成功。相反，包含它们最简单的方法是使用 Bez 插件，可从[`github.com/rdallasgray/bez`](https://github.com/rdallasgray/bez)获取。为了看到它的易用性，让我们看看它的实际效果。

### 添加贝塞尔曲线支持

有许多在线网站展示了缓动函数的示例；我的个人喜爱是[`easings.net/`](http://easings.net/)和[`www.cubic-bezier.com`](http://www.cubic-bezier.com)。

前者是 Andrey Sitnik 创建的，我们在第六章*使用 jQuery 进行动画*中介绍过。其中提供了 jQuery 可用的所有缓动函数的工作示例。如果我们点击其中一个，可以看到它们可以被创造或在 jQuery 中以不同方式使用的各种方法。

提供支持的最简单方法是使用前面提到的 Bez 插件。现在是进行一个简短演示的时候了：

1.  对于这个演示，我们将从随本书附带的代码下载中提取相关文件。我们需要`blindtoggle.html`、`jquery.min.css`、`blindtoggle.css`和`jquery.bez.min.js`文件。这些文件需要存储在项目区域的相应子文件夹中。

1.  在一个新文件中，让我们继续创建 jQuery 效果。在这种情况下，将以下内容添加到一个新文件中，并将其保存为`blindtoggle.js`，放置在项目区域的`js`子文件夹中：

    ```js
    jQuery.fn.blindToggle = function(speed, easing, callback) {
      var h = this.height() + parseInt(this.css('paddingTop')) +
        parseInt(this.css('paddingBottom'));
      return this.animate({
        marginTop: parseInt(this.css('marginTop')) <0 ? 0 : -h}, 
        speed, easing, callback
      );
    };

    $(document).ready(function() {
      var $box = $('#box').wrap('<div id="box-outer"></div>');
      $('#blind').click(function() {
        $box.blindToggle('slow', $.bez([.25,.99,.73,.44]));
      });
    });
    ```

1.  如果我们在浏览器中预览结果，可以看到文本首先向上滚动，然后很快出现棕色背景，如下图所示：![添加贝塞尔曲线支持](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00410.jpeg)

这似乎是相当多的代码，但这个演示的真正关键在于以下一行：

```js
$box.blindToggle('slow', $.bez([.25,.99,.73,.44]));
```

我们正在使用`$.bez`插件从 cubic-bezier 值创建我们的缓动函数。这样做的主要原因是避免同时提供基于 CSS3 和基于 jQuery 的 cubic-bezier 函数的需求；这两者不是相互兼容的。插件通过允许我们提供缓动函数作为 cubic-bezier 值来解决这个问题，以匹配可以在样式表中使用的值。

在我们的代码中添加 cubic-bezier 支持打开了无限的可能性。以下是一些启发的链接，让你开始：

+   想要替换标准的 jQuery 效果，比如`easeOutCubic`吗？没问题 - [`rapiddg.com/blog/css3-transiton-extras-jquery-easing-custom-bezier-curves`](http://rapiddg.com/blog/css3-transiton-extras-jquery-easing-custom-bezier-curves)提供了一组 cubic-bezier 值，可以使用 CSS 提供等效功能。

+   如果你使用诸如 Less 之类的 CSS 预处理器，那么 Kirk Strobeck 为 Less 提供了一组缓动函数列表，可在[`github.com/kirkstrobeck/bootstrap/blob/master/less/easing.less`](https://github.com/kirkstrobeck/bootstrap/blob/master/less/easing.less)找到。

+   我们简要讨论了位于[`www.cubic-bezier.com`](http://www.cubic-bezier.com)的工具，用于计算坐标值。你可以阅读这个令人敬畏的工具的灵感来源，创作者 Lea Verou 的文章，网址是[`lea.verou.me/2011/09/a-better-tool-for-cubic-bezier-easing/`](http://lea.verou.me/2011/09/a-better-tool-for-cubic-bezier-easing/)。还有另一个工具可供选择，位于[`matthewlein.com/ceaser/`](http://matthewlein.com/ceaser/)，虽然这个工具不太容易使用，而且更倾向于 CSS 值。

值得花时间熟悉使用 cubic-bezier 值。提供它们非常简单，所以现在轮到你创建一些真正酷炫的效果了！

## 使用纯 CSS 作为替代方案

在使用 jQuery 进行开发时，很容易陷入认为效果必须由 jQuery 提供的陷阱中。这是一个完全可以理解的错误。

成为一个更全面的开发者的关键是了解使用 jQuery 提供这样一个效果的影响。

在旧版浏览器上，我们可能没有选择。然而，在新版浏览器上，我们有选择。不要仅仅使用诸如`slideDown()`这样的效果，考虑是否可以使用 CSS 来实现相同（或非常相似）的效果。例如，作为`slideDown()`的替代方案，可以尝试以下操作：

```js
.slider {transition: height 2s linear; height: 100px;
background: red;( )}
.slider.down { height: 500px; }
```

然后，我们可以将重点放在简单地更改分配的 CSS 类上，如下所示：

```js
$('.toggler').click(function(){ 
  $('.slider').toggleClass('down');
});
```

啊，但是——这是一本关于精通 jQuery 的书，对吧？我们为什么要避免使用 jQuery 代码呢？嗯——引用莎士比亚《哈姆雷特》中的波洛尼斯——“……虽然这有点疯狂，但其中确有方法。”或者，换句话说，遵循这一原则有一个非常明智的理由。

jQuery 是一个本质上较重的库，对于默认的版本 2.1.3 的最小化副本来说，它的体积为 82 KB。当然，正在做一些工作来移除冗余功能，是的，我们总是可以移除我们不需要的元素。

但是，jQuery 资源消耗大，这给你的站点增加了不必要的负担。相反，更明智的做法是使用诸如`toggleClass()`这样的功能，就像我们在这里做的一样，来切换类。然后我们可以通过将 CSS 类存储在样式表中来保持分离。

这一切都取决于你的需求。例如，如果你只需要产生一些效果，那么将 jQuery 引入此任务中就没有太多意义。相反，我们可以使用 CSS 来创建这些效果，并将 jQuery 留给在站点本身提供大部分价值的地方。

### 注意

为了证明一点，在伴随本书的代码下载中查看`replacejquery.html`演示。你还需要提取`replacejquery.css`文件，以使其正常工作。这段代码创建了一个非常基本但功能齐全的滑块效果。仔细观察，你应该看不到任何 jQuery 的影子……！

现在，别误会。可能有一些情况下必须使用 jQuery（例如支持旧版本浏览器），或者情况要求使用该库能提供一个更整洁的选择（我们不能在纯 CSS 中进行链式操作）。在这些情况下，我们必须接受额外的负担。

为了证明这应该是例外而不是规则，以下是一些吸引你的例子：

+   看一看 Dan Eden 创作的著名库 `animate.css`（在[`daneden.github.io/animate.css/`](http://daneden.github.io/animate.css/)可用）。其中包含许多仅使用 CSS 的动画可以导入到你的代码中。如果确实需要使用 jQuery，那么 Animo jQuery 插件在[`labs.bigroomstudios.com/libraries/animo-js`](http://labs.bigroomstudios.com/libraries/animo-js)也值得一看——它使用了 `animate.css` 库。

+   看一看[`rapiddg.com/blog/css3-transiton-extras-jquery-easing-custom-bezier-curves`](http://rapiddg.com/blog/css3-transiton-extras-jquery-easing-custom-bezier-curves)。在表格的中间位置左右，有一个关于大部分（如果不是全部的话）使用 jQuery 时可用的缓动效果的贝塞尔曲线等价列表。这里的诀窍是不使用我们在之前例子中创建的额外函数，而是简单地使用 `animate()` 和 Bez 插件。后者将被缓存，有助于减少服务器的负载！

+   使用 CSS3 提供简单图像淡入的一个简单而有效的例子可以在[`cssnerd.com/2012/04/03/jquery-like-pure-css3-image-fade-in/`](http://cssnerd.com/2012/04/03/jquery-like-pure-css3-image-fade-in/)找到。淡入过渡可能需要稍长的时间，但它展示了效果。

这里的关键信息是并不总是需要使用 jQuery —— 成为更好的开发者的一部分是要弄清楚何时应该以及何时不应该使用大锤来解决问题！

好了，该继续了（抱歉，开了个玩笑）。让我们快速看看如何添加回调，以及如何改变思维方式，用一个更好的替代方案来替换它，使其更容易在 jQuery 中使用。

# 在我们的效果中添加回调

好的，我们已经创建了我们的效果，并设置了运行方式。如果我们希望在完成时或者失败时得到提醒呢？很简单！只要我们提供一个回调函数（带参数或不带参数都可以）。然后我们可以要求 jQuery 在效果完成后执行一个动作，就像下面的例子所示：

```js
  $(document).ready(function() {
    $("#myButton").on("click", function () {
      $('#section').hide(2000, 'swing', function() {
 $(this).html("Animation Completed");
 });
    });
  });
```

这是一个完全可行的通知方式，而且实现起来非常轻松。但它并不是没有缺点。其中两个主要缺点是无法控制回调何时以及如何执行，以及只能运行一个回调。

庆幸的是，我们不必使用标准的回调函数，因为 jQuery 的 Deferreds 来拯救我们了。我们在第五章 *集成 AJAX*中曾提及过它的使用。Deferreds 和 Promises 的美妙之处在于它们可以应用于任何 jQuery 功能；事件特别适用于此目的。让我们看看在效果的上下文中我们如何利用这个功能。

# 用 jQuery 的 Promises 控制内容

Promises，promises - 我想我已经听到这个短语多少次了。

与现实生活不同，承诺经常被违背，我们可以保证 jQuery 中的 Promises 最终会得到满足。当然，答案可能并不总是积极的，但是，是的，至少会有对 Promise 的响应。

不过，我听到你在问一个问题 - 如果大多数事件已经内置了回调选项，那么为什么我们需要使用 jQuery 的 `.promises()`？

简单的答案是，我们可以更好地控制构建和读取 Promises。例如，我们可以设置一个单一的回调，可以应用于多个 Promises；我们甚至可以设置一个 Promise 只在需要时触发一次！但美妙之处在于使用 Promises 更容易阅读代码，并链接多个方法在一起：

```js
var myEvent = function(){
  return $(selector).fadeIn('fast').promise();
};
$.when( myEvent()).done( function(){
  console.log( 'Task completed.' );
});
```

我们甚至可以将主要效果分离到一个单独的函数中，然后将该函数链接到 Promise 中，以确定在我们的代码中如何处理它。

为了看到如何简单地结合两者，让我们花点时间考虑下面的简单示例，它使用 jQuery 中的 `slideUp()` 效果：

![用 jQuery 的 Promises 控制内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00411.jpeg)

1.  我们将从 `promises.html`、`promises.css` 和 `jquery.min.js` 文件中提取出来。继续将它们存储在我们项目区域的相关文件夹中。

1.  在一个新文件中，添加以下代码—这包含了一个点击处理程序，用于我们标记文件中的按钮，当完成时首先滑动 `<li>` 项，然后在屏幕上显示通知。

    ```js
    $(document).ready(function() {
      $('#btn').on("click", function() {
        $.when($('li').slideUp(500)).then(function() {
          $("p").text("Finished!");
        });
      });
    });
    ```

1.  尝试在浏览器中运行演示。如果一切顺利，当点击屏幕上的按钮时，我们应该看到三个列表项被卷起，就像本节开头的截图中所示。

这个简单的演示完美地说明了我们如何使用 Promises 使我们的代码更易读。如果你期望更多的话，很抱歉让你失望了！但这里的关键并不一定是提供回调的 *技术能力*，而是使用 Promises 带来的 *灵活性* 和 *可读性*。

### 注意

值得注意的是，在这个示例中，我们使用了 jQuery 对象的 `promise()` 方法 - 在这种情况下，我们最好使用不同的对象作为 Promise 的基础。

要真正了解 Promises 如何使用，请查看 [`jsfiddle.net/6sKRC/`](http://jsfiddle.net/6sKRC/)，该链接显示了在 JSFiddle 中的一个工作示例。一旦动画完成，此示例将扩展`slideUp()`方法以完全删除元素。

应该注意，虽然这显示了扩展此效果的一个很好的方法，但代码本身可以从一些调整中受益，以使其更易读。例如，`this. slideUp(duration).promise()`可以轻松地分解成一个变量，这将使该行更短，更易读！

### 注意

如果您想了解更多关于使用 jQuery 的 Promises 和 Deferreds 的信息，则在线上有许多关于这两个主题的文章。两篇可能感兴趣的文章可以在 [`code.tutsplus.com/tutorials/wrangle-async-tasks-with-jquery-promises--net-24135`](http://code.tutsplus.com/tutorials/wrangle-async-tasks-with-jquery-promises--net-24135) 和 [`tutorials.jenkov.com/jquery/deferred-objects.html`](http://tutorials.jenkov.com/jquery/deferred-objects.html) 找到。如果您以前没有使用过`promises()`，那么花点时间来理解这个主题肯定是值得的！

我们接近本章的结束，但在总结之前，还有一个重要的主题要讨论。我们已经考虑了以某种形式使用 CSS 而不只是依赖 jQuery 的好处。如果情况要求必须使用后者，那么我们至少应该考虑管理队列以最大程度地从使用效果中获益。让我们花点时间更详细地探讨一下这个问题。

# 创建和管理效果队列

排队，排队 - 谁喜欢排队呢，我想知道？

尽管我们中并不是所有人都喜欢排队，比如排队买午餐或去银行，但排队对于成功运行动画至关重要。无论我们使用`.slideUp()`、`.animate()`甚至`.hide()`，都无关紧要 - 如果我们链接太多动画，就会达到动画无法运行的点。

要释放动画，我们需要明确调用`.dequeue()`，因为方法是成对出现的。请考虑一下来自[`cdmckay.org/blog/2010/06/22/how-to-use-custom-jquery-animation-queues/`](http://cdmckay.org/blog/2010/06/22/how-to-use-custom-jquery-animation-queues/)的以下示例：

想象一下，你正在制作一款游戏，你希望一个对象从`top:100px`开始，然后在 2000 毫秒内向上浮动。此外，你希望该对象在完全透明 1000 毫秒之前保持完全不透明，在剩余的 1000 毫秒内逐渐变得完全透明：

| 时间（毫秒） | 顶部 | 不透明度 |
| --- | --- | --- |
| 0 | 100px | 1.0 |
| 500 | 90px | 1.0 |
| 1000 | 80px | 1.0 |
| 1500 | 70px | 0.5 |
| 2000 | 60px | 0.0 |

乍一看，似乎`animate`命令可以处理这个问题，如下面的代码所示：

```js
$("#object").animate({opacity: 0, top: "-=40"}, {duration: 2000});
```

不幸的是，这段代码将使对象在 2000 毫秒内淡出，而不是等待 1000 毫秒，然后在剩余的 1000 毫秒内淡出。延迟也无济于事，因为它也会延迟上升浮动。此时，我们可以要么纠结于超时，要么，你猜对了，使用队列。

考虑到这一点，下面是修改后使用`.queue()`和`.dequeue()`的代码：

```js
$("#object")
  .delay(1000, "fader")
  .queue("fader", function(next) {
    $(this).animate({opacity: 0},
      {duration: 1000, queue: false});
      next();
  })
 .dequeue("fader")
 .animate({top: "-=40"}, {duration: 2000})
```

在这个例子中，我们有两个队列：`fx`队列和`fader`队列。首先，我们设置了`fader`队列。由于我们想要在淡化前等待`1000`毫秒，我们使用了带有`1000`毫秒延迟命令。

接下来，我们排队进行一个动画，在`1000`毫秒内将对象淡出。请特别注意我们在动画命令中设置的`queue: false`选项。这是为了确保动画不使用默认的`fx`队列。最后，我们使用`dequeue`释放队列，并立即使用`animate`调用在顶部对象上移`40`像素的常规`fx`队列。

我们甚至可以将对`.queue()`和`.dequeue()`的使用转化为插件。鉴于两者都需要使用，将其转化为在代码中更易于阅读的形式是有意义的。考虑下一个例子：

```js
$.fn.pause = function( delay ) {
  return this.queue(function() {
    var elem = this;
    setTimeout(function() {
      return $( elem ).dequeue();
    }, delay );
  });
};
$(".box").animate({height: 20}, "slow" ).pause( 1000 ).slideUp();
```

在上一个例子中，我们首先对`.box`的高度进行动画变化，然后暂停，然后上滑`.box`元素。

需要注意的关键点是，`queue()`和`dequeue()`都是基于 jQuery 中的`fx`对象的。由于这已经在默认情况下设置，因此在我们的插件中没有必要指定它。

### 提示

如果您对`queue()`和`dequeue()`的用途感到不确定，那么不妨看一看[`learn.jquery.com/effects/uses-of-queue-and-dequeue/`](http://learn.jquery.com/effects/uses-of-queue-and-dequeue/)，其中概述了一些有用的案例示例。

使用`.queue()`及其对应的`.dequeue()`提供了一种优雅的动画控制方式。它的使用可能更适合于多个、复杂的动画，特别是需要实现动画时间轴的情况。但如果我们只是使用了少量的简单动画，那么附加插件的重量可能就是不必要的。相反，我们可以简单地增加`.stop()`来提供类似的效果。参考以下内容：

```js
$(selector).stop(true,true).animate({...}, function(){...});
```

使用`.stop()`可能不太优雅，但确实改善了动画的外观！

# 总结

哇，我们在过去的几页中涵盖了很多内容。肯定是紧张的！让我们来喘口气，回顾一下我们学到的内容。

我们首先回顾了 jQuery 的基本效果，以回顾我们可以在 jQuery 中使用的内容，然后探讨了标准动画和特效之间的关键区别。接着我们转向创建自定义效果，了解了所有效果的基础，然后在代码中创建了两个自定义效果的例子。

然后，我们把焦点转向了添加自定义缓动效果，并探讨了我们在本书前面看到的那些效果如何同样适用于 jQuery 效果。我们通过一个例子来说明，即添加基于贝塞尔曲线的缓动支持，然后探讨如何仅使用 CSS 就可以实现类似的效果。我们随后简要介绍了向我们的效果添加回调，然后探讨了如何通过使用 jQuery 的 Deferreds / Promises 选项来更好地控制回调，作为标准回调的替代方案。

我们接着以管理效果队列的方式结束了本章。这是一个很好的机会来探讨仔细管理队列的好处，这样我们在使用 jQuery 时就可以避免任何混乱或意外的结果。

然后，我们迅速进入了一些真正有趣的内容！在接下来的几章中，我们将探讨两个你可能不会立即与 jQuery 关联起来的主题；我们将从探索页面可见性 API 开始，你会发现编写大量复杂代码并不一定是件好事。


# 第九章：使用 Web 性能 API

您有多少次打开了带有多个选项卡的浏览器会话？作为开发人员，我希望那几乎是正常情况，对吗？

现在，如果当您切换选项卡时，内容仍然在原始选项卡上播放会怎样？真的很烦人，对吧？当然，我们可以停止它，但是嘿，我们是忙碌的人，有更重要的事情要做...！

幸运的是，这不再是问题 - 在移动时代，资源的保护变得更加重要，我们可以采用一些技巧来帮助节省资源的使用。本章将介绍如何使用页面可见性 API，并向您展示如何通过一些简单的更改，可以显著减少您的站点使用的资源。接下来的几页中，我们将涵盖以下主题：

+   介绍页面可见性和 requestAnimationFrame API

+   检测并添加支持，使用 jQuery

+   使用 API 控制活动

+   将支持合并到实际应用中

准备好开始了吗？很好！让我们开始吧...

# 页面可见性 API 简介

请暂时考虑一下这种情景：

您正在 iPad 上浏览一个内容丰富的网站，该网站已设置为预渲染内容。这开始大量使用设备上的资源，导致电池电量迅速耗尽。你能做些什么？好吧，在那个站点上，可能不行 - 但如果是您拥有的站点，那么是的。欢迎使用**页面可见性 API**。

页面可见性 API 是一个巧妙的小 API，用于检测浏览器选项卡中的内容是否可见（即正在查看）或隐藏。为什么这很重要？简单 - 如果浏览器选项卡隐藏，那么在站点上播放媒体或频繁轮询服务就没有意义了，对吧？

使用此 API 的净影响旨在减少资源使用（因此）节省电力。毕竟，如果您的访问者因访问媒体密集型站点而耗尽电池电量，他们是不会感谢您的！

在接下来的几页中，我们将详细了解这个库，并看看如何与 jQuery 结合使用它。让我们从查看 API 的浏览器支持开始。

# 支持 API

与其他 API 不同，所有主要浏览器对此库的支持非常好。与许多 API 一样，页面可见性经历了通常的过程，需要供应商前缀，然后在 2013 年 10 月底达到推荐阶段。目前，最新的浏览器（IE8 之后）都不需要供应商前缀才能运行。

使用纯 JavaScript 时，使用页面可见性 API 的典型代码片段如下所示：

```js
var hidden, state, visibilityChange;
if (typeof document.hidden !== "undefined") {
  hidden = "hidden", 
  visibilityChange = "visibilitychange",
  state = "visibilityState";
}
```

我们稍后会研究在本章中使用 jQuery。

在代码中实现它是微不足道的，所以没有理由不这样做。为了证明这一点，让我们看看演示的效果。

# 实现页面可见性 API

到目前为止，我们已经介绍了页面可见性 API，并介绍了在内容不可见时使用它暂停内容的好处。 值得花一点时间看看我们如何在代码中实现它，以及这样一个简单的改变如何带来巨大的好处。

我们将先从普通 JavaScript 开始，然后在本章稍后再看看如何使用 jQuery：

1.  让我们从附带本书的代码下载中提取我们需要的标记文件。 对于此演示，我们将需要 `basicuse.html` 和 `basicuse.css`。 将文件分别保存到我们项目区域的根目录和 `css` 子文件夹中。

1.  接下来，在一个新文件中添加以下代码：

    ```js
    function log(msg){
      var output = document.getElementById("output");
      output.innerHTML += "<li>" + msg + "</li>";
    }

    window.onload = function() {
      var hidden, visibilityState, visibilityChange;
      if (typeof document.hidden !== "undefined") {
        visibilityChange = "visibilitychange";
      }
      document.addEventListener(visibilityChange, function() {
        log(document.visibilityState]);
      });
    };
    ```

1.  这是我们演示的关键，使用页面可见性 API 来确定选项卡是可见还是隐藏的。 将其保存在我们项目区域的 `js` 子文件夹中，命名为 `basicuse.js`。

1.  如果一切顺利，那么当我们在浏览器中预览结果时，我们应该看到类似于以下截图的内容 - 这显示了切换到新选项卡然后再切换回来后的结果：![实现页面可见性 API](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00412.jpeg)

## 拆解 API

快速查看前一个演示中的代码应该会发现两个值得注意的属性 - 它们是 `document.visibilityState` 和 `document.hidden`。

这些构成了页面可见性 API。 如果我们首先更详细地查看 `document.visibilityState`，它可以返回以下四个不同的值之一：

+   `hidden`：页面在任何屏幕上都不可见

+   `prerender`：页面已加载到屏幕外，准备供访问者查看

+   `visible`：页面可见

+   `unloaded`：页面即将卸载（用户正在从当前页面导航离开）

我们还使用 `document.hidden` 属性 - 它是一个简单的布尔属性，如果页面可见，则设置为 `false`，如果页面隐藏，则设置为 `true`。

结合 `visibilitychange` 事件，我们可以很容易地在页面可见性更改时收到通知。 我们将使用类似于以下代码的内容：

```js
document.addEventListener('visibilitychange', function(event) {
  if (!document.hidden) {
    // The page is visible.
  } else {
   // The page is hidden.
  }
});
```

这将适用于大多数浏览器，但并非所有。 尽管它只是少数，但我们仍然必须允许它。 要了解我的意思，请尝试在 IE8 或更低版本中运行演示 - 它不会显示任何内容。 显示空白不是一个选项； 相反，我们可以提供一个优雅降级的路径。 因此，让我们看看如何避免代码崩溃成一堆。 

# 检测对页面可见性 API 的支持

尽管 API 在大多数现代浏览器中都可以很好地工作，但在有限的几个浏览器中会失败； IE8 就是一个很好的例子。 为了解决这个问题，我们需要提供一个根本性的方式来优雅地降级，或者使用一个回退机制； 这个过程的第一步是首先弄清楚我们的浏览器是否支持该 API。

这样做的方法有很多种。我们可以使用 Modernizr 的`Modernizr.addTest`选项（来自[`www.modernizr.com`](http://www.modernizr.com)）。相反，我们将使用 Matthias Bynens 的一个插件，其中包含了对旧浏览器的支持检查。原始版本可以从[`github.com/mathiasbynens/jquery-visibility`](https://github.com/mathiasbynens/jquery-visibility)获取。代码下载中包含的版本是一个简化版，删除了对旧浏览器的支持。

### 注意

代码下载中包含使用 Modernizr 的此演示版本。提取并运行`usemodernizr.html`文件，查看其运行方式。

现在我们已经看到了页面可见性如何被整合到我们的代码中，我们将切换到使用 jQuery 进行这个演示。

让我们开始：

1.  我们需要从附带本书的代码下载中下载标记和样式文件。继续并提取以下副本：`usingjquery.html`，`usingjquery.css`，`jquery.min.js`和`jquery-visibility.js`。将 CSS 文件保存到`css`子文件夹，将 JS 文件保存到`js`子文件夹，将 HTML 文件保存到我们项目文件夹的根目录。

1.  在一个新文件中，添加以下代码 - 这包含了检查可见性和确认浏览器是否支持 API 所需的代码：

    ```js
    $(document).ready(function() {
      var $pre = $('pre');
      var $p = $('p')
      var supported = 'The Page Visibility API is natively 
      supported in this browser.'
      var notsupported = 'The Page Visibility API is not 
      natively supported in this browser.'
      $('p').first().html(
        $.support.pageVisibility ? log($p, supported) : log($p, 
        notsupported)
      );
      function log(obj, text) { obj.append(text + '<br>'); }
      $(document).on({
        'show.visibility': function() {
        log($pre, 'The page gained visibility; the 
        <code>show</code> event was triggered.');
      },
      'hide.visibility': function() {
        log($pre, 'The page lost visibility; the 
        <code>hide</code> event was triggered.');
      }
      });
    });
    ```

1.  将文件保存为`usingjquery.js`，放在项目区域的`js`子文件夹中。如果我们在 IE9 或更高版本上运行演示，我们将看到它在我们在标签之间切换时呈现出变化。参考以下图片：![检测页面可见性 API 的支持](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00413.jpeg)

1.  尝试将浏览器更改为 IE8 - 可以使用 IE 开发者工具栏，或切换到浏览器的本地副本。我们还需要更改所使用的 jQuery 版本，因为我们的演示是面向更新的浏览器的。将 jQuery 链接更改为以下内容：

    ```js
    <script src="img/jquery-1.11.2.min.js"> </script>
    ```

1.  现在尝试刷新浏览器窗口。它会显示它不支持页面可见性 API，但也不会因意外错误而崩溃。参考下一张图片：![检测页面可见性 API 的支持](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00414.jpeg)

有了备用选项，我们现在有两个选择：

+   当浏览器不被支持时，我们可以提供一条优雅降级的路径。这是完全可以接受的，但首先应该考虑一下。

+   我们还可以提供备用支持，以允许旧浏览器仍然可以使用。

假设我们使用后一种方式。我们可以使用许多插件中的任何一种; 我们将使用 Andrey Sitnik 创建的`visibility.js`插件，为此目的。

## 提供备用支持

为任何应用程序提供备用支持是任何开发者的噩梦。我失去了对我想开发一些打破新领域的东西而不断出错的次数的计数。我必须为那些简单无法兼容新技术的旧浏览器提供支持！

幸运的是，这不是 Page Visibility API 的问题 – 浏览器覆盖非常好，尽管少数浏览器版本仍需要一些回退支持。有许多插件可用于此目的 – 也许最著名的是 Mathias Bynens 制作的，可在 [`github.com/mathiasbynens/jquery-visibility`](https://github.com/mathiasbynens/jquery-visibility) 获取。我们在上一个演示中看到了如何使用定制版本。

对于此演示，我们将使用 Andrey Sitnik 的类似插件，可从 [`github.com/ai/visibilityjs`](https://github.com/ai/visibilityjs) 获取。这包含额外的功能，包括一个定时器，用于显示页面可见的时间；我们将在以下演示中使用它。

## 安装 visibility.js

在我们开始演示之前，值得注意的是 `visibility.js` 插件可以通过几种方式引用：

+   我们可以从 GitHub 链接 [`github.com/ai/visibilityjs`](https://github.com/ai/visibilityjs) 下载原始文件

+   它可通过 Bower 获取。要做到这一点，您需要安装 Node 和 Bower。完成后，运行以下命令下载并安装插件：

    ```js
     bower install --save visibilityjs

    ```

+   它甚至可以通过 CDN 链接引用，目前是 [`cdnjs.cloudflare.com/ajax/libs/visibility.js/1.2.1/visibility.min.js`](http://cdnjs.cloudflare.com/ajax/libs/visibility.js/1.2.1/visibility.min.js)。

为了这个演示的目的，我假设您正在使用 CDN 版本（其中包含额外的定时器功能），但保存为本地副本。

### 注意

注意 – 如果您不使用此方法，则需要下载所有四个可见性 JavaScript 文件，网址为 [`github.com/ai/visibilityjstree/master/lib`](https://github.com/ai/visibilityjstree/master/lib)，因为这些文件提供了压缩 CDN 版本中可用的回退和定时器功能。

## 构建演示

好的，现在我们已经安装了插件，接下来是我们将演示的屏幕截图：

![构建演示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00415.jpeg)

让我们开始吧：

1.  从附带本书的代码下载中提取相关的标记文件。在这个练习中，我们需要 [fallback.html](http://fallback.html) 和 [fallback.css](http://fallback.css) 文件。将它们存储在项目区域的根目录和 `css` 文件夹中。

1.  我们还需要 `visibility.min.js` 插件文件 – 它们都在代码下载文件中。将其提取并保存到我们项目区域的 `js` 子文件夹中。

1.  接下来，将以下内容添加到一个新文件中，将其保存为项目区域的 `js` 子文件夹中的 `fallback.js`：

    ```js
    $(document).ready(function() {
      if ( Visibility.isSupported() ) {
        $("#APIsupported").html('is supported');
      } else {
        $("#APIsupport").html('isn't supported');
      }

      document.title = Visibility.state();
      Visibility.change(function (e, state) {
        document.title = state;
      });

      var sec = 0;
      Visibility.every(1000, function () {
        $("#APIcounter").html(sec++);
      });
    });
    ```

1.  此代码包含我们演示所需的魔法。

1.  保存文件。如果我们在浏览器中预览结果，可以期望看到类似练习开始时的屏幕截图。如果我们切换到不同的选项卡，如下一个屏幕截图所示，则计时器计数将暂停，并相应地更新原始选项卡的标题：![构建演示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00416.jpeg)

那么，发生了什么？这是一个非常简单的演示，但我们首先启动了一个检查，以确保我们的浏览器能够支持这个 API。在大多数情况下，这不是问题，除了 IE8 或更低版本。

我们随后在窗口的标题区域显示了窗口的初始状态；每次从演示切换到不同的标签页然后再切换回来时，都会更新这一状态。作为额外奖励，我们利用了主插件附带的`visibility.timer.js`插件，显示了窗口可见时间的计数。当然，每次我们切换到不同的浏览器窗口然后再切换回来时，这个计时就会停止！

不过，与之前的演示不同的是，这个插件即使我们使用 IE8 或更低版本仍然可以工作；我们可能需要修改演示中的代码以确保其样式正确，但这只是一个小问题。

让我们继续。既然我们已经了解了如何使用页面可见性 API 的基础知识，我相信你一定会问：我们如何在实际场景中使用它？没问题 - 让我们看一些可能的用例。

# 在实际场景中使用 API

这个 API 可以在各种不同的上下文中使用。经典的用法通常是帮助控制视频或音频的播放，尽管它也可以与其他 API 一起使用，比如电池 API，以防止在电量过低时显示内容。

让我们花点时间深入研究一些实际示例，这样我们就可以看到实现 API 有多么简单。

## 暂停视频或音频

API 最常见的用途之一是控制音频或视频等媒体的播放。在我们的第一个示例中，我们将使用 API 在切换标签时播放或暂停视频。让我们深入了解一下。

对于这个演示，我们将使用一些额外的内容 - 动态网站图标库，可以从[`softwareas.com/dynamic-favicons/`](http://softwareas.com/dynamic-favicons/)获取。虽然这个库已经有几年了，但仍然可以与当前版本的 jQuery 正常工作。视频来自大黄蜂项目网站，网址为[`peach.blender.org`](https://peach.blender.org)。

### 注意

这个演示的视频来自 Blender 基金会，版权为 2008 年，Blender 基金会/ [www.bigbuckbunny.org](http://www.bigbuckbunny.org)。

好了！让我们开始吧：

1.  像往常一样，我们需要从某个地方开始。对于这个演示，继续从本书附带的代码下载中提取`pausevideo`演示文件夹。

1.  打开`pausevideo.js`文件。其中包含使用`jquery-visibility`插件播放或暂停视频的代码。参考以下代码：

    ```js
    var $video = $('#videoElement');

    $(document).on('show.visibility', function() {
      console.log('Page visible');
      favicon.change("img/playing.png");
      $video[0].play();
    });

    $(document).on('hide.visibility', function() {
      console.log('Page hidden');
      favicon.change("img/paused.png");
      $video[0].pause();
    });
    ```

1.  这个插件非常简单。它公开了两种方法，即`show.visibility`和`hide.visibility`。现在试运行演示。如果一切正常，我们应该看到大黄蜂视频播放；当我们切换标签时，它会暂停。以下是视频的截图：![暂停视频或音频](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00417.jpeg)

1.  另外，使用`favicon.js`库更新窗口标题。当我们切换选项卡时，它显示一个暂停符号，如下图所示：![暂停视频或音频](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00418.jpeg)

那很容易，对吧？这就是 API 的美妙之处。它非常简单，但可以与各种不同的工具一起使用。让我们通过将 API 的支持纳入**内容管理系统**（**CMS**）（如 WordPress）来证明这一点。

## 为 CMS 添加支持

到目前为止，我们已经看到了在静态页面站点中支持标准是多么容易 - 那么对于 CMS 系统，例如 WordPress，我听到你在问什么？

好了，API 也可以在这里轻松使用。与其谈论它，不如看看我们如何添加它。对于这个演示，我将使用 WordPress，尽管原理同样适用于其他 CMS 系统，如 Joomla。我将使用的插件是我自己创建的。

应该注意，您应该有一个可用的 WordPress 安装，可以是在线的，也可以是自托管版本，并且您对安装插件有一些了解。

### 注意

请注意 - `jquery-pva.php`插件仅用于*开发目的*；在将其用于生产环境之前，还需要进一步的工作。

好的，让我们开始：

1.  我们需要对主题中的`functions.php`文件进行更改。为此，我将假设您正在使用 Twenty Fourteen 主题。打开`functions.php`，然后添加以下代码：

    ```js
    function pausevideos() {
      wp_register_script('pausevideo', plugins_url( '/jquery- pva/pausevideo.js'), array('jquery'),'1.1', true);
      wp_enqueue_script('pausevideo');
    }

    add_action( 'wp_enqueue_scripts', 'pausevideos' );
    ```

1.  从附带本书的代码下载中，找到并提取`jquery-pva`文件夹，然后将其复制到您的 WordPress 安装中；它需要放在`plugins`文件夹中。返回您的 WordPress 安装，然后以通常的方式激活插件。

1.  接下来，登录您的 WordPress 管理区域，然后点击**Settings** | **PVA Options**，输入您想使用的 jQuery 版本号。我将假设已选择 2.1.3。点击**Save Changes**以生效。参考以下图片：![为 CMS 添加支持](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00419.jpeg)

此时，我们可以开始使用库了。如果我们上传一个视频并将其添加到帖子中，当我们开始播放时，它将显示已经过的时间；当我们切换选项卡时，它将暂停：

![为 CMS 添加支持](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00420.jpeg)

要确认它是否工作正常，值得查看源代码，使用 DOM 检查器。如果一切正常，我们应该会看到以下链接。第一个链接将确认引用了 Page Visibility 库，如下所示：

![为 CMS 添加支持](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00421.jpeg)

第二个链接将确认我们的脚本被调用了，如下图所示：

![为 CMS 添加支持](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00422.jpeg)

如我们所见，API 确实有其用处！在本章中，我尽量使代码相对简单，以便容易理解。现在轮到你来实验和进一步探索了 - 也许我可以给你一些启发？

## 探索示例的想法

页面可见性 API 的基本原理很容易实现，因此我们所能做到的复杂程度仅受想象力的限制。在我的研究中，我找到了一些灵感的想法——希望以下内容能让你了解可能的一些情况：

+   动画！有时，如果标签页没有活动，我们可能会遇到同步动画的问题。[`greensock.com/forums/topic/9059-cross-browser-to-detect-tab-or-window-is-active-so-animations-stay-in-sync-using-html5-visibility-api/`](http://greensock.com/forums/topic/9059-cross-browser-to-detect-tab-or-window-is-active-so-animations-stay-in-sync-using-html5-visibility-api/) 探讨了一些可用的提示，以帮助解决其中一些问题。

+   接下来这个可能会让你吓一跳，或者只是单纯地让人烦躁——看一下[`blog.frankmtaylor.com/2014/03/07/page-visibility-and-speech-synthesis-how-to-make-web-pages-sound-needy/`](http://blog.frankmtaylor.com/2014/03/07/page-visibility-and-speech-synthesis-how-to-make-web-pages-sound-needy/)，作者混合了页面可见性和语音合成 API。请注意——他警告不要混合使用这两个 API；让我们只说这很可能会更让人反感！（它仅出于技术原因被包含在这里——并不是因为我们应该这样做。）

+   一种更有用的技术是使用页面可见性 API 来减少对新邮件或新闻源的检查次数。该 API 将检查标签页是否隐藏，并减少请求更新的频率，直到标签页再次活动起来。开发者 Raymond Camden 探索了执行此操作所需的基本知识，请前往他的网站了解更多信息，网址为[`www.raymondcamden.com/2013/05/28/Using-the-Page-Visibility-API`](http://www.raymondcamden.com/2013/05/28/Using-the-Page-Visibility-API)。

+   为了真正混合一些东西，我们可以同时使用页面可见性、Web 通知和震动 API 来启动一些有用的通知。在[`www.binpress.com/tutorial/building-useful-notifications-with-html5-apis/163`](http://www.binpress.com/tutorial/building-useful-notifications-with-html5-apis/163)中，您可以了解如何在站点或应用程序中混合这三个 API 的想法。

好的，我认为现在是改变的时候了。让我们继续并看看另一个与页面可见性 API 大约在同一时间创建的 API，它使用类似的原理来帮助减少资源需求。

我当然是指 requestAnimationFrame API。让我们深入探讨一下，看看它是什么，是什么原因让它运行起来，以及为什么这样一个简单的 API 对我们开发者来说会是一个真正的福音。

# 介绍 requestAnimationFrame API

过去几年转向在线工作导致了对性能浏览器的巨大需求增加，同时减少了资源消耗和电池功耗。

有了这个想法，浏览器厂商和微软联合创建了三个新的 API。我们已经探讨了其中一个，以页面可见性 API 的形式；我们要看的另一个是**requestAnimationFrame**。三者（第三个是**setImmediate**）都是为了提高性能和增加功耗效率而设计的。

## 探索概念

那么，requestAnimationFrame 是什么？简单——如果你花了一些时间使用 jQuery 创建动画，你肯定使用过`setInterval`方法（甚至是`clearInterval`），对吧？requestAnimationFrame（和 clearAnimationFrame）分别被设计为替代它们。

我们为什么要使用它？在下一节中，我们将探讨使用 requestAnimationFrame 的好处，但首先让我们了解它的本质。

大多数动画在绘制动画时都使用小于 16.7 毫秒的基于 JavaScript 的定时器，即使显示器只能以 16.7 毫秒（或 60Hz 频率）显示，如下图所示：

![探索概念](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00423.jpeg)

这为什么重要？关键在于，典型的`setInterval`或`setTimeout`频率通常约为 10 毫秒。这意味着每第三次监视器的绘制不会被观看者看到，因为在显示刷新之前会发生另一次绘制。请参考下一个图表：

![探索概念](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00424.jpeg)

这会导致显示不连贯，因为会丢帧。电池寿命可能会降低高达 25％，这是一个显著的损失！

浏览器厂商意识到了这一点，因此提出了 requestAnimationFrame API。这告诉应用程序浏览器何时需要更新屏幕，以及浏览器何时需要刷新。这导致资源使用减少，丢帧较少，因为帧速率与代码相比更一致。

### 注意

开发者 Paul Irish 在他的博客[`www.paulirish.com/2011/requestanimationframe-for-smart-animating/`](http://www.paulirish.com/2011/requestanimationframe-for-smart-animating/)中对此做了完美的总结，他指出这使得浏览器能够“将并行动画优化到单个回流和重绘周期中，从而实现更高保真度的动画。”

## 查看 API 的实际效果

几乎总是这样，看到实际效果要比阅读有用得多。对我来说，移动演示有助于深化概念！

为了帮助理解，本书附带的代码下载中有两个演示——`requestAnimationFrame.html`和`cancelAnimationFrame.html`文件。它们包含了两个 API 的简单示例。我们将在本章末尾探讨 API 的更多实际用途。

## 使用 requestAnimationFrame API

虽然从上一节末尾引用的简单演示中可能并不立即明显，但使用 requestAnimationFrame 有一些明显的好处，下面列出了这些值得注意的好处：

+   requestAnimationFrame 与浏览器合作，在重绘转换期间将动画组合到单个重绘中，使用屏幕刷新率来决定何时应该发生这些操作。

+   如果浏览器标签处于非活动或隐藏状态，动画会被暂停，这会减少刷新屏幕的请求，从而降低移动设备的内存消耗和电池使用。

+   浏览器通过优化动画，而不是通过代码 - 较低的帧刷新率会导致更平滑、更一致的外观，因为较少的帧将被丢弃。

+   该 API 在大多数移动设备上都受支持。目前唯一不支持的平台是 Opera Mini 8.0。CanIUse 网站（[`www.caniuse.com`](http://www.caniuse.com)）显示全球使用率仅为 3%，因此这不太可能造成太大问题。

值得注意的是，cancelAnimationFrame（作为 requestAnimationFrame 的姐妹 API）可用于暂停动画。如果电池电量太低，我们可以潜在地将其与诸如 Battery API 等东西一起使用，以阻止动画（或媒体，如视频）的启动。

### 提示

要查看 requestAnimationFrame 与 setTimeout 之间的区别，请访问 [`jsfiddle.net/calpo/H7EEE/`](http://jsfiddle.net/calpo/H7EEE/)。尽管演示非常简单，但您可以清楚地看到两者之间的区别！

需要注意的一个关键点是，有些情况下，requestAnimationFrame 并不总是比使用 jQuery 更好。David Bushell 在 [`dbushell.com/2013/01/15/re-jquery-animation-vs-css/`](http://dbushell.com/2013/01/15/re-jquery-animation-vs-css/) 上有一篇有用的文章，概述了这个问题，并指出 requestAnimationFrame 最适合用于基于 `<canvas>` 的动画。

基于 requestAnimationFrame（以及 cancelAnimationFrame）创建动画非常简单。开发者 Matt West 在 CodePen 上创建了一个 JavaScript/jQuery 示例，可在 [`codepen.io/matt-west/full/bGdEC`](http://codepen.io/matt-west/full/bGdEC) 查看。他还编写了一篇配套教程，可在 Team Treehouse 的博客上查看，链接为 [`blog.teamtreehouse.com/efficient-animations-with-requestanimationframe`](http://blog.teamtreehouse.com/efficient-animations-with-requestanimationframe)。

这让我们顺利过渡到下一个主题。现在我们已经看到如何使用 JavaScript 操纵 API，让我们看看如何使用类似技术的 jQuery。

## 向 jQuery 进行的更改改造

到目前为止，我们已经介绍了如何使用 requestAnimationFrame 及其姐妹 API cancelAnimationFrame 的基础知识；我们已经看到如何使用纯 JavaScript 实现它。

但值得注意的是，jQuery 目前不包含原生支持。在 1.8 版本之前尝试将其添加到 jQuery 中，但由于主要浏览器供应商的支持问题而将其删除。

幸运的是，供应商支持现在比以前好得多；并且计划在 jQuery 2.2 或 1.12 中添加`requestAnimationFrame`支持。您可以按如下方式查看需要进行的更改，以及历史记录：

+   提交：[`gitcandy.com/Repository/Commit/jQuery/72119e0023dcc0d9807caf6d988598b74abdc937`](https://gitcandy.com/Repository/Commit/jQuery/72119e0023dcc0d9807caf6d988598b74abdc937)

+   可从[`github.com/jquery/jquery/blob/master/src/effects.js`](https://github.com/jquery/jquery/blob/master/src/effects.js)引用的`effect.js`中的更改。

+   包含`requestAnimationFrame`在 jQuery 核心中的一些历史：[`github.com/jquery/jquery/pull/1578`](https://github.com/jquery/jquery/pull/1578)；[`bugs.jquery.com/ticket/15147`](http://bugs.jquery.com/ticket/15147)

作为临时措施（如果您仍然需要支持 jQuery 的早期版本），您可以尝试使用 Corey Frang 的插件，[`github.com/gnarf/jquery-requestAnimationFrame`](https://github.com/gnarf/jquery-requestAnimationFrame)，该插件为 1.8 版本后的 jQuery 版本添加了支持。

但是，如果您感到更有冒险精神，那么直接将`requestAnimationFrame`支持添加到使用它的库中就很容易。让我们花点时间看看涉及转换的内容。

### 更新现有代码

进行更改相对直接。关键在于使更改模块化，这样一旦 jQuery 支持`requestAnimationFrame`，就可以轻松地将其替换回来。

如果您使用的库中存在对`setInterval`或`clearInterval`的代码引用，可以进行更改。例如，考虑以下代码摘录：

```js
var interval = setInterval(doSomething, 10)
var progress = 0
function doSomething() {
  if (progress != 100){
  // do something here
  }
  else {
  clearInterval(interval)
  }
}
```

它将被更新为以下代码摘录，将对`setInterval`的引用替换为`requestAnimationFrame`（并添加`clearInterval`的等效替换）：

```js
var requestAnimationFrame = window.requestAnimationFrame;
var cancelAnimationFrame = window.cancelAnimationFrame;

// your code here

var progress = 0;

function doSomething() {
  if (progress != 100) {
    // do something here
 var myAnimation = requestAnimationFrame(doSomething);
  } else {
    cancelAnimationFrame(myAnimation);
  }
}
```

在前面的代码示例中，粗体突出显示的代码指示了更新代码所需的更改类型。我们将在本章稍后使用此技术，为现有库添加支持。这将是我们将探讨的两个演示之一，它们使用`requestAnimationFrame`。

# 一些使用`requestAnimationFrame`的示例

到目前为止，我们已经了解了使用`requestAnimationFrame`的理论，并覆盖了我们可能需要对现有代码进行的典型更改。

这是一个很好的起点，但不一定易于理解概念；在实际操作中更容易理解！考虑到这一点，我们将查看一些利用 API 的演示。第一个将为现有支持添加支持，而第二个已经在代码中包含了支持。

## 创建可滚动效果

对于我们的第一个演示，我们将来看看更新经典的可滚动 UI 元素的示例。我们将使用来自[`github.com/StarPlugins/thumbelina`](https://github.com/StarPlugins/thumbelina)的 Thumbelina 插件。虽然已经有几年了，但它仍然可以完美运行，即使使用最新版本的 jQuery！

在这个演示中，我们将在插件中替换`setInterval`调用，改用`requestAnimationFrame`。让我们开始：

1.  让我们从这本书附带的代码下载中提取`thumbelina`演示文件夹的副本。如果我们运行`scrollable.html`文件，我们应该会看到一个具有兰花图片的可滚动内容，如下图所示：![创建可滚动效果](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00425.jpeg)

1.  Thumbelina 插件目前使用`setInterval`来管理动画之间的时间间隔。我们将修改它，改为使用新的`requestAnimationFrame`。

1.  打开 thumbelina.js，然后在`$.fn.Thumbelina = function(settings) {`下面立即添加以下代码，该行在第 16 行处：

    ```js
      var start = new Date().getTime(),
      handle = new Object();
      function loop() {
        var current = new Date().getTime(),
        delta = current - start;
        if(delta >= delay) {
          fn.call();
          start = new Date().getTime();
        }
        handle.value = 
        window.requestAnimationFrame(loop);
      };
      handle.value = window.requestAnimationFrame(loop);
      return handle;
    }
    ```

1.  向下滚动到以下行，该行将在第 121 行左右：

    ```js
    setInterval(function(){
    ```

1.  按照下面的修改，使它使用我们刚刚添加的新的`requestInterval()`函数：

    ```js
    requestInterval(function() {
      animate();
      },1000/60);
    };
    ```

1.  保存该文件。如果我们运行演示，应该不会看到任何视觉上的差异；真正的差异发生在后台。

### 提示

尝试在 Google Chrome 中运行演示，然后在时间轴中查看结果。如果你进行前后对比，应该会看到显著的差异！如果你不确定如何对演示进行分析，那就前往[`developer.chrome.com/devtools/docs/timeline`](https://developer.chrome.com/devtools/docs/timeline)获取完整详情。

## 动画化谷歌地图标记

本章的最终演示将使用众所周知的 Google Maps 服务，以动画化地图上指示特定位置的标记：

![动画化谷歌地图标记](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00426.jpeg)

在这个例子中，我们将使用 Robert Gerlach 创建的演示，该演示可从[`robsite.net/google-maps-animated-marker-move/`](http://robsite.net/google-maps-animated-marker-move/) 获取。我已经调整了他的`markerAnimate.js`插件文件中的代码，以去掉厂商前缀，因为这些不再需要。

他创造了一个漂亮的效果，为看似十分枯燥的内容增添了些活力。尽管如此，它仍然需要相当数量的代码！由于空间限制，我们无法在印刷品中探索所有内容，但我们可以探讨一些更重要的概念：

1.  让我们从这本书附带的代码下载中提取`googlemap`演示文件夹。这包含了我们演示的样式、JavaScript 库和标记。

1.  在浏览器中运行`googlemap.html`。如果一切正常，我们应该会看到指针位于英国伯明翰，那里是 Packt Publishing 的英国办公室所在地。

尝试在地图的其他位置单击 - 注意它是如何移动的？它利用了 jQuery Easing 插件中提供的一些缓动效果，我们在 第六章 中使用过的，*jQuery 动画*。

我们可以通过简单地更改右下角下拉框中显示的值来选择要使用的缓动效果。这甚至可以包括我们自己制作的自定义动画，以 第六章 中给出的示例为基础。只要将自定义动画函数包含在我们的代码中，并在下拉框中添加适当的名称，我们就可以使用它。

实际上要注意的重点在于 `markeranimate.js` 文件。如果我们打开它并滚动到第 **64** - **71** 行，我们可以看到 `requestAnimationFrame` 的使用方法。如果浏览器支持该 API，则使用它，否则使用 `setTimeout`，如下面的截图所示：

![Google 地图标记的动画效果](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00427.jpeg)

结合使用缓动效果和调用 `requestAnimationFrame` 会产生一个很酷的效果，同时也减少了对资源的需求 - 如果您的网站有很多动画效果，那就很棒！

### 提示

要更容易地替换`setInterval`、`clearInterval`（以及`setTimeout` / `clearTimeout`），请使用 Joe Lambert 的替换函数，可在 [`gist.github.com/joelambert/1002116`](https://gist.github.com/joelambert/1002116) 获取。

## 探索灵感来源

在过去的几页中我们已经涵盖了很多内容 - 完全理解 requestAnimationFrame（以及其姊妹函数 clearAnimationFrame）的工作原理可能需要一些时间，但随着 jQuery 的即将更改，值得花时间熟悉这些 API 及其为我们开发带来的好处。

在我们结束本章之前，下面列出了一些可能对你有用的灵感来源：

+   requestAnimationFrame 绝不仅限于播放视频、音乐或类似的用途。甚至可以用于开发在线游戏！看看 [`www.somethinghitme.com/2013/01/09/creating-a-canvas-platformer-tutorial-part-one/`](http://www.somethinghitme.com/2013/01/09/creating-a-canvas-platformer-tutorial-part-one/) - 希望你能认出一些经典作品！

+   更严肃的话题，对于那些使用视差滚动效果的网站，实现可能还有改进的空间。Krister Kari 写了一篇详细的博客文章，通过一个典型的例子来讨论，并概述了可以用于修复问题的一些技术。你可以在 [`kristerkari.github.io/adventures-in-webkit-land/blog/2013/08/30/fixing-a-parallax-scrolling-website-to-run-in-60-fps/`](http://kristerkari.github.io/adventures-in-webkit-land/blog/2013/08/30/fixing-a-parallax-scrolling-website-to-run-in-60-fps/) 上阅读。

还有很多其他资源可用 - 接下来就看你的想象力带你去哪里！

# 总结

探索新的 API 总是很有趣的。即使它们可能在本质上很简单（例如，查看振动 API），它们也可以证明是任何人工具箱中真正有用的补充。在本章节中，我们详细探讨了其中的两个。让我们花点时间回顾一下我们所涵盖的内容。

我们以介绍页面可见性 API 开始。我们查看了 API 的浏览器支持情况，然后实施了一个基本示例。我们进一步讨论了如何检测并提供备用支持，然后查看了一些实际示例。

接下来我们来看一下 requestAnimationFrame API，我们了解了一些与页面可见性 API 的相似之处。我们探讨了它的基本原理，然后看了一些实际用途以及如何添加支持到 jQuery 本身。然后我们用两个例子总结了这一章节；一个是基于使用 API 进行转换的，而另一个则是从零开始构建的。

进入下一章节，我们将探讨网站的另一个关键元素，即图片。我们将探讨如何使用 jQuery 操纵图片，以产生一些非常有趣的效果。


# 第十章：操纵图像

常常有人说图像胜过千言万语 – 网站也不例外。

我们使用图像来说明一个过程，帮助强化信息，或者为原本可能被视为非常普通的内容应用一些视觉身份。图像在任何网站中都起着关键作用；图像的质量会决定一个站点的成败。

使用 jQuery 操纵图像的一小部分是我们如何应用滤镜，或者操纵图像中的颜色。在本章中，我们将探讨如何使用 jQuery 操纵图像，然后探索几个以捕获图像作为进一步操纵基础的真实世界示例。在本章中，我们将涵盖以下主题：

+   使用 CSS 和 jQuery 应用滤镜

+   使用插件编辑图像

+   使用 jQuery 和 canvas 创建一个简单的签名板

+   捕获和操纵网络摄像头图像

让我们开始吧…！

# 操纵图像中的颜色

一个问题 – 你多久以为操纵图像的唯一方式是使用像 Photoshop 或者 GIMP 这样的软件？我打赌不止一次 – 如果我说这些广为人知的重量级应用程序在某些情况下是多余的，而你只需要一个文本编辑器和一点点 jQuery 呢？

此时，你可能想知道我们可以用 jQuery 如何操纵图像。别担心！我们有几个绝招。在接下来的几页中，我们将逐个看看，发现虽然我们可以使用可能是开发人员最常用的 JavaScript 库之一，但并不总是正确的做法。

为了理解我的意思，让我们快速回顾一下我们可以使用的方法，它们是：

+   使用 CSS3 滤镜，并使用 jQuery 切换它们的使用与否

+   使用 HTML5 `<canvas>` 元素，jQuery 和 `getImageData` 方法处理程序的混合方式来操作每个图像的颜色元素，然后将其重新绘制到画布上。

在本章中，我们将依次看看每一个，并探讨为什么即使我们可以使用 jQuery 创建复杂的滤镜，它也并不总是正确的答案。希望通过我们的一些绝招，能让我们成为更好的开发人员。让我们从简单的 CSS3 滤镜开始，看看我们如何轻松地将它们应用到我们的 jQuery 代码中。

# 使用 CSS3 添加滤镜

至少在主流桌面浏览器中，滤镜支持已经有一段时间了，尽管我们仍然需要使用 `-webkit-` 厂商前缀支持，因为我们还不完全是无前缀的：

![使用 CSS3 添加滤镜](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00428.jpeg)

### 注意

关于前面图像的信息来自 CanIUse 网站，网址为 [`caniuse.com/#feat=css-filters`](http://caniuse.com/#feat=css-filters)。

使用这些方法的美妙之处在于它们非常简单易行；如果客户决定改变主意，我们不必花费数小时重新制作图像！我们可以轻松地使用 jQuery 应用和移除样式，这有助于将样式与我们的标记分开。

操纵图像可能变得非常复杂 – 实际上，要涵盖所涉及的数学，我们可能需要写一本专门的书！相反，我们将从简单回顾使用 CSS3 滤镜开始，然后转向创建更复杂的滤镜，并以帮助从两个不太可能的源捕获图像的几个演示结束。

感兴趣吗？在本章末尾一切都会变得清晰起来，但我们首先将从一个简单的练习开始，重新熟悉应用 CSS3 滤镜。

## 准备工作

在开始练习之前，我强烈建议您在这些演示中使用 Firefox 或 IE；如果您使用 Chrome，那么在本地运行时，某些演示将显示跨源错误。

一个很好的例子是跨平台应用程序 XAMPP（可从[`www.apachefriends.org`](http://www.apachefriends.org)获取），或者您可以尝试 WAMPServer（适用于 PC，从[`www.wampserver.com/en`](http://www.wampserver.com/en)获取），或者 MAMP（适用于 Mac，从[`www.mamp.info`](http://www.mamp.info)获取）。我将假设您是从 Web 服务器中运行演示。

## 创建我们的基页

在本章的第一个演示中，我们将从简单回顾使用 `addClass` 方法开始，将特定的滤镜应用到页面上的图像。我们将使用加拿大开发者 Nick La 开发的拍立得效果，并且可以从[`webdesignerwall.com/demo/decorative-gallery-2/`](http://webdesignerwall.com/demo/decorative-gallery-2/)获取。`.addClass()` 方法是您几乎肯定以前使用过无数次的方法；我们在这里使用它是为了引入本章后面更复杂效果的介绍。让我们开始：

1.  让我们从从伴随本书的代码下载中下载并提取以下文件开始：

    +   `cssfilters.html`

    +   `cssfilters.css`

    +   `jquery.min.js`

    +   `cssfilters.js`

1.  将 HTML 标记文件放入项目区域的根目录，将 JavaScript 和 CSS 文件放入项目区域的相关子文件夹中。

1.  在一个新文件中，添加以下简单的代码块 – 这是按钮的事件处理程序，我们将用它来更改滤镜状态：

    ```js
    $(document).ready(function(){
      $("input").on("click", function(){
        $("img").toggleClass("change-filter");
      })
    });
    ```

1.  在这个阶段，尝试在浏览器中预览结果。如果一切正常，我们应该看到一张蓝色花朵的图片，设置在拍立得效果的背景中。参考以下图片：![创建我们的基页](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00429.jpeg)

1.  在 `cssfilters.css` – 屏幕底部附近仔细查看。我们应该看到以下内容：

    ```js
    .change-filter {
      filter: blur(5px);
      -webkit-filter: blur(5px); 
    }
    ```

    紧接着这个区块：

    ```js
    img { -webkit-transition: all 0.7s ease-in-out; transition: all 0.7s ease-in-out; }
    ```

1.  现在点击**使用 CSS 更改滤镜**按钮。如果一切正常，我们的图像应该逐渐变模糊，如下图所示：![创建我们的基页](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00430.jpeg)

一个简单的演示 - 在目前阶段没有太多困难，考虑到我们在本书中已经涵盖了一些更复杂的主题！

### 小贴士

小贴士 - 如果你发现在某些版本的 Firefox 中滤镜显示不出来，那么请检查**about:config**中的**layout.css.filters.enabled**属性。在 34 版或更早的版本中，默认情况下未启用；这一点是从 35 版开始改变的：

![创建我们的基本页面](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00431.jpeg)

当然，这个演示的关键是使用`.addClass()`方法处理程序。当点击按钮时，我们只是将一个新的，预设的类应用于图像。但在这里美妙的是，我们可以访问许多快速、简单的滤镜，可以减少（甚至消除）对 PhotoShop 或 GIMP 的使用。为了看到切换有多容易，让我们现在做出这个改变，切换到使用亮度滤镜。

## 更改亮度级别

下一个演示是对我们刚刚工作过的`cssfilters.css`文件进行快速简单的更改。以下是我们将要制作的屏幕截图：

![更改亮度级别](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00432.jpeg)

在继续下面列出的步骤之前，请确保你有这个文件可用：

1.  在`cssfilters.css`中，查找并修改`.change-filter`规则如下所示：

    ```js
    .change-filter { filter: brightness(170%); -webkit-filter: brightness(170%); }
    ```

1.  现在点击**使用 CSS 更改滤镜**。如果一切正常，我们应该会发现图像变得更加明亮。

同样 - 在这里没有太多困难；希望在本书中我们所涵盖的一些内容后，这是一个放松的时刻！我们可以使用一些 CSS3 滤镜；由于空间限制，我们不能在这里涵盖它们所有，但至少我们可以再看一种滤镜。在接下来的练习后面，我们将介绍可供使用的其他滤镜。

## 向我们的图像添加深褐色滤镜

与以前一样，我们需要恢复更改`cssfilters.css`，所以确保你已经准备好了这个文件。让我们看看我们需要做什么：

1.  恢复到`cssfilters.css`，然后按如下所示修改这一行：

    ```js
    .change-filter { filter: sepia(100%); -webkit-filter: sepia(100%); }
    ```

1.  现在点击**使用 CSS 更改滤镜**。如果一切正常，我们应该会发现图像现在应用了一种深褐色滤镜，如此屏幕截图所示：![向我们的图像添加深褐色滤镜](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00433.jpeg)

这就是我喜欢使用 CSS3 滤镜的地方 - 尽管有些纯粹主义者可能会说的，但并不总是必要回到使用图形软件包；在 CSS 中简单更改一个值就足够了。

如果需要，我们可以手动更改该值，但是现在我们也可以以编程方式灵活地进行更改，对性能几乎没有影响。这一点非常重要，因为我们将在本章后面看到。使用 jQuery 创建复杂滤镜来操纵图像是一个资源消耗大的过程，因此不宜频繁进行。

## 探索其他滤镜

在我们继续探讨不同的图像处理方法之前，下表展示了不同滤镜的风格；所有这些滤镜都可以使用 jQuery 进行设置，就像我们在之前的练习中所概述的那样：

| 滤镜名称 | 使用示例 |
| --- | --- |
| `contrast()` |

```js
.change-filter { filter: contrast(170%); -webkit-filter: contrast(170%); }
```

|

| `hue-rotate()` |
| --- |

```js
.change-filter { filter: hue-rotate(50deg); -webkit-filter: hue-rotate(50deg); }
```

|

| `grayscale()` |
| --- |

```js
.change-filter { filter: grayscale(100%); -webkit-filter: grayscale(100%); }
```

|

| `invert()` |
| --- |

```js
.change-filter { filter: invert(100%); -webkit-filter: invert(100%); }
```

|

| `Saturate()` |
| --- |

```js
.change-filter { filter: saturate(50%); -webkit-filter: saturate(50%);}
```

|

要查看这些滤镜的实际示例，值得上网查看一下——有很多示例可供参考。作为一个起点，可以查看约翰尼·辛普森在[`www.inserthtml.com/2012/06/css-filters/`](http://www.inserthtml.com/2012/06/css-filters/)上的文章；虽然这篇文章已经有几年了，而且有些设置已经进行了调整，但仍然可以对 CSS3 滤镜的可能性提供有用的了解。

让我们换个方式来思考——虽然我们可以使用简单的 CSS3 滤镜来调整对比度和亮度等方面，但我们也可以使用另一种方法：背景混合。

# 使用 CSS3 合并图像

在某些情况下，我们可能更喜欢不直接处理图像，而是改变背景图像。在 PhotoShop 中可以很容易地在静态图像中实现类似的效果，但在互联网上较少见。

幸运的是，我们可以在 CSS 中使用`background-blend`模式来实现相同的效果——这样可以让我们将两张图像合并在一起。使用`background-blend`模式（在桌面浏览器中的浏览器支持良好）可以避免手动编辑每张照片的需求，因此如果任何照片更改了，同样的效果可以轻松应用到它们的替代品上。

与我们已经检查过的那些滤镜一样，我们会在 CSS 中应用这些滤镜。然后我们可以随心所欲地使用 jQuery 打开或关闭它们。我不会重新介绍所需的 jQuery 代码，因为我们已经在本章的早些时候见过了；简单地说，我们会应用`background-blend`模式，使用以下示例：

```js
  <style>
    .blend { width: 389px; height: 259px; background:#de6e3d url("img/flowers.jpg") no-repeat center center; }
    .blend.overlay { background-blend-mode: overlay; }
  </style>
</head>
```

在这个例子中，我们使用了`overlay`滤镜。这个复杂的滤镜会根据背景色值来乘以颜色。它的净效果是让浅色变得更浅，让深色变得更深，如下一个截图所示：

![使用 CSS3 合并图像](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00434.jpeg)

### 提示

代码下载包中有两个示例，其中包括`overlay.html`和`multiply.html`文件中的这种混合模式的示例。 

有很多滤镜选项可供选择，比如乘法、变亮、避免和颜色燃烧——这些都旨在产生类似于 PhotoShop 中使用的效果，但不需要昂贵的应用程序。所有滤镜都遵循类似的格式。在谷歌上搜索滤镜的示例很值得，比如在[`www.webdesignerdepot.com/2014/07/15-css-blend-modes-that-will-supercharge-your-images/`](http://www.webdesignerdepot.com/2014/07/15-css-blend-modes-that-will-supercharge-your-images/)上展示的那些。

### 注意

如果您想了解更多信息，请访问 Mozilla 的开发者网站[`developer.mozilla.org/en-US/docs/Web/CSS/background-blend-mode`](https://developer.mozilla.org/en-US/docs/Web/CSS/background-blend-mode)。要获取此滤镜的真正有用的示例（以及与 jQuery 结合的灵感来源），请查看 2016 年美国总统候选人演示[`codepen.io/bennettfeely/pen/rxoAc`](http://codepen.io/bennettfeely/pen/rxoAc)。

好了，是时候真正投入一些 jQuery 的时间了！让我们转向使用插件，并看看我们可以使用什么可用的东西来实现一些效果。我们将从使用 CamanJS 作为示例开始，然后深入探讨手动创建滤镜，并看看为什么这并不总是实现所需效果的最佳方式！

# 使用 CamanJS 应用滤镜

到目前为止，我们已经使用 CSS3 应用了滤镜。这对于轻量级解决方案来说是完美的，但在某些情况下，我们可能需要做更多，而 CSS3 则不够。

进入 jQuery！在接下来的几页中，我们将简要介绍如何使用 CamanJS 作为我们示例 jQuery 插件来应用滤镜。然后，我们将继续看看如何轻松（或复杂）地手动创建相同的效果，而不需要依赖第三方插件。

## 介绍 CamanJS 作为插件

CamanJS 是为 jQuery 提供的几个插件之一，它允许我们应用任意数量的滤镜；我们可以从库中提供的预设滤镜中选择，或者创建我们自己的组合。

该插件可以从[`camanjs.com/`](http://camanjs.com/)获得，并可以从 GitHub 下载[`github.com/meltingice/CamanJS`](https://github.com/meltingice/CamanJS)。另外，我们可以使用 NodeJS 或 Bower 来安装该库。该插件还可以通过 CDN 在[`www.cdnjs.com`](http://www.cdnjs.com)获得 - 搜索 CamanJS 以获取在您的项目中使用的最新 URL。

值得注意的是，可以使用两种方法之一来应用滤镜 - 第一种是作为 HTML 数据属性：

```js
<img data-caman="saturation(-10) brightness(20) vignette('10%')" src="img/image.jpg">
```

第二种方法是使用 jQuery，正如我们将在下一个演示中看到的；我们将在我们的示例中一直使用这种方法。有了这个想法，让我们开始动手，并看看如何使用 CamanJS 来应用滤镜，就像我们下一个演示中展示的那样。

## 构建一个简单的演示

在这个演示中，我们将使用 CamanJS 库来对我们在本章节中一直在使用的花朵图像应用三个滤镜中的任何一个。

### 注意

记住 - 如果您使用 Chrome，请在本地 Web 服务器内运行此演示，如“准备就绪”部分所建议的那样。

让我们开始：

1.  首先，从附带本书的代码下载中提取以下文件。对于这个演示，我们需要以下文件：`caman.html`，`flowers.jpg`，`usecaman.js`，`jquery.min.js`和`usecaman.css`。将 JavaScript 文件存储在`js`子文件夹中，将 CSS 文件存储在`css`子文件夹中，将图像存储在`img`子文件夹中，并将 HTML 标记存储在项目文件夹的根目录中。

1.  运行`caman.html`演示文件。如果一切顺利，我们应该看到以下图片出现：![构建一个简单的演示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00435.jpeg)

1.  让我们探索操作演示所需的 jQuery。如果我们查看`usecaman.js`，我们会看到以下代码。这用于获取我们标记中`<canvas>`元素的句柄，然后在其上绘制`flowers.jpg`图像。

    ```js
      var canvas = $('#canvas');
      var ctx = canvas[0].getContext("2d");
      var img = new Image();
      img.src = "img/flowers.jpg";
      ctx.drawImage(img, 0, 0);
    ```

1.  深入挖掘一下，我们应该看到以下方法——这个方法处理了`<canvas>`元素恢复到其原始状态的重置；请注意使用的`drawImage()`方法，这是使用不同滤镜操作图像的关键：

    ```js
      $reset.on('click', function(e){
        e.preventDefault();
        var img = new Image();
        img.src = "img/flowers.jpg";
        ctx.save();
        ctx.setTransform(1, 0, 0, 1, 0, 0);
        ctx.clearRect(0, 0, canvas[0].width, canvas[0].height);
        ctx.restore();
        ctx.drawImage(img, 0, 0);
        Caman('#maincanvas', 'img/flowers.jpg', function(){
          this.revert(false).render();
        });
      });
    ```

1.  然后，我们再加上三个不同的事件处理程序——这些应用了相应的 CamanJS 滤镜：

    ```js
    $noise.on('click', function(e) {
      e.preventDefault();
      Caman('#maincanvas', 'img/flowers.jpg', function() {
        this.noise(10).render();
      });
    });
    ```

我们的简单演示只是展示了使用 CamanJS 可能性的冰山一角。详细查看该网站，了解使用该库可以实现的效果是非常值得的。作为灵感的来源，请查看 Carter Rabasa 的文章，他使用该库创建了一个基于著名的 Instagram 网站的 Phonestagram 应用程序；该文章位于[`www.twilio.com/blog/2014/11/phonestagram-fun-with-photo-filters-using-node-hapi-and-camanjs.html`](https://www.twilio.com/blog/2014/11/phonestagram-fun-with-photo-filters-using-node-hapi-and-camanjs.html)。

### 注意

值得注意的是，CamanJS 能够轻松处理 HiDPI 图像——我们只需在代码中设置`data-caman-hidpi`属性。如果检测到设备支持高分辨率图像，Caman 将自动切换到使用高分辨率版本。但要注意，由于使用了额外的像素，渲染时间会更长。

## Getting really creative

回想一下本章开头提到的地方，我提到 CSS3 滤镜提供了一个方便且轻量级的手段来操作图像。它们的使用意味着我们可以减少编辑图像所需的工作量，并且如果图像的大小或内容发生变化，更新它们会更容易。

然而，使用 CSS3 滤镜只能做到这一点——这就是 jQuery 接管的地方。要了解原因，请让我们通过另一个演示来进行工作。这一次，我们将使用 CamanJS 附带的更高级的预设滤镜之一，如果仅使用 CSS3 滤镜就很难实现。

记住——如果您使用的是 Chrome，请从本地 Web 服务器中运行此演示，如“准备就绪”部分所建议的那样。让我们开始：

1.  对于这个演示，我们需要从本书配套的代码下载中获取一些文件。它们是：`caman-advanced.css`，`caman-advanced.html`，`caman.full.js`，`jquery.min.js`和`flowers.jpg`。将每个文件放在相关的子文件夹中，而将 HTML 标记文件放在项目区的根目录。

1.  在一个新文件中，添加以下代码以配置 CamanJS 对象以使用库提供的针孔滤镜；将其保存为`caman-advanced.js`，放在`js`子文件夹中。

    ```js
    $(document).ready(function() {
      $("input").on("click", function() {
        Caman("#caman-image", function () {
          this.pinhole().render();
        });
      })
    });
    ```

1.  如果我们预览演示，可以看到点击**更改滤镜**按钮时，图像现在显示为针孔相机效果。参考下面的图片：![Getting really creative](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00436.jpeg)

在 CamanJS 网站上有许多更不寻常滤镜的示例。前往[`camanjs.com/examples/`](http://camanjs.com/examples/)查看使用该库可能出现的情况。

尽管我们集中在使用 CamanJS 作为示例（部分是因为这个库的广泛可能性），但是还有其他可用的库，提供类似的滤镜功能，但并非所有库都能达到 CamanJS 的水平。以下是一些可供探索的例子，让你开始：

+   **VintageJS**：[`github.com/rendro/vintageJS`](https://github.com/rendro/vintageJS)

+   **Hoverizr**：[`github.com/iliasiovis/Hoverizr`](https://github.com/iliasiovis/Hoverizr)

+   **PaintbrushJS**：[`mezzoblue.github.com/PaintbrushJS`](http://mezzoblue.github.com/PaintbrushJS)

+   **Colorimazer**：[`colorimazer.tacyniak.fr/`](http://colorimazer.tacyniak.fr/)

对于那些不喜欢使用开源软件的人，一个你可能喜欢探索的例子是 JSManipulation 库，这个库可以在 CodeCanyon 网站上以出售的方式获得，网址为：[`codecanyon.net/item/jsmanipulate-jquery-image-manipulation-plugin/428234`](http://codecanyon.net/item/jsmanipulate-jquery-image-manipulation-plugin/428234)。

好的，让我们继续，并且真正投入到一些事情中去。目前为止，我们已经使用了大多数情况下适用的插件。但是在一些情况下，我们可能会发现需要手动创建自己的滤镜，因为现有的滤镜不适用于我们的需求。让我们看看一些例子，以了解涉及到的内容。

### 小贴士

要了解使用 Caman 时可能出现的情况，请查看 Martin Angelov 在[`tutorialzine.com/2013/02/instagram-filter-app/`](http://tutorialzine.com/2013/02/instagram-filter-app/)的这篇文章。他通过使用 jQuery，CamanJS 和 jQuery Mousewheel 来构建一个 Instagram 滤镜应用程序。

# 手动创建简单的滤镜

创造我们自己的滤镜的关键（也与许多预构建的插件一样）是使用`<canvas>`元素，并熟悉`getImageData`方法。我们可以使用后者来操纵每个图像中的颜色通道，以产生所需的效果。

我们可以花时间详细讨论如何使用此方法，但我认为亲自尝试会更好。所以让我们深入了解并使用它手动创建一些滤镜，首先是将图像转换为灰度。

## 将图像转换为灰度

对于三个演示中的第一个演示，我们将对我们在本章中一直使用的`flowers.jpg`图像的颜色进行去饱和处理。这将使其呈现出灰度外观。

### 注意

如果在本地运行此演示，您可能会遇到跨域错误。我建议按照*准备工作*部分的建议在本地 Web 服务器上运行它。

让我们看看我们需要做什么：

1.  让我们从附带本书代码下载中提取`flowers.jpg`的副本、`jquery.min.js`、`manual-grayscale.html`和`manual-grayscale.css`。将图像存储在`img`子文件夹中，JavaScript 文件存储在`js`子文件夹中，样式表存储在`css`子文件夹中；HTML 标记需要存储在我们项目文件夹的根目录下。

1.  在一个新文件中，继续添加以下代码，并将其保存为`manual-grayscale.js` - 这将查找每个设置了图片类名为 picture 的图像集，然后调用`grayscale`函数执行魔术：

    ```js
    $(window).load(function(){
      $('.picture').each(function(){
        this.src = grayscale(this.src);
      });
    });
    ```

1.  将以下函数添加到`$(window).load`方法的下方 - 这将用等效的灰度重写图像：

    ```js
    function grayscale(src){
      var i, avg;
      var canvas = document.createElement('canvas');
      var ctx = canvas.getContext('2d');
      var imgObj = new Image();
      imgObj.src = src;
      canvas.width = imgObj.width;
      canvas.height = imgObj.height;
      ctx.drawImage(imgObj, 0, 0);
      var imgPixels = ctx.getImageData(0, 0, canvas.width, canvas.height);
      for(var y = 0; y < imgPixels.height; y++){
        for(var x = 0; x < imgPixels.width; x++){
          i = (y * 4) * imgPixels.width + x * 4;
          avg = (imgPixels.data[i] + imgPixels.data[i + 1] + imgPixels.data[i + 2]) / 3;
          imgPixels.data[i] = avg;
          imgPixels.data[i + 1] = avg;
          imgPixels.data[i + 2] = avg;
        }
      }
      ctx.putImageData(imgPixels, 0, 0, 0, 0, imgPixels.width, imgPixels.height);
      return canvas.toDataURL();
    }
    ```

1.  如果我们此时运行演示，我们应该会看到一张带有极化效果边框的图像的副本，但这次，它已经被转换成了灰度等效图像，接着是截图本身：![将图像转换为灰度](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00437.jpeg)

在我们继续进行下一个演示之前，有一些关键点需要注意，与我们刚刚使用的代码相关。所以让我们花点时间详细介绍一下这些：

+   我们所做的大部分工作都使用了`<canvas>`元素 - 这使我们能够以比使用普通的 JPG 或 PNG 格式图像更细致的细节来操作图像。

+   在这种情况下，我们使用纯 JavaScript 使用语句 `document.createElement('canvas')` 创建了 canvas 元素。有些人可能会认为将纯 JavaScript 与 jQuery 混合使用是不好的做法。在这种情况下，我个人认为它提供了更清洁的解决方案，因为使用 jQuery 动态创建的`<canvas>`元素不会自动添加上下文。

+   作为一种方法，`getImageData()`是使用此路由操作任何图像的关键。然后，我们可以处理每个颜色通道，即红色、绿色和蓝色，以产生所需的效果。

我们可以使用这个过程来生成任意数量的不同滤镜 - 比如说一个棕褐色调的滤镜？让我们看看我们如何手动创建这样一个滤镜。在这种情况下，我们将进一步将其转换为一个小插件，以便以后重复使用。

## 添加棕褐色调

我们已经看到了从头开始制作一个彩色滤镜是多么简单 – 那么创建不同类型的滤镜呢？我们可以使用类似的技术来制作其他滤镜，所以让我们继续创建一个基于棕褐色的滤镜，以补充本章早些时候使用的 CSS3 版本。

### 注意

记住 – 如果您使用的是 Chrome，请从本地 Web 服务器中运行此演示，如“准备就绪”部分所建议的那样。

让我们开始吧：

1.  我们将像往常一样从随书代码下载中提取相关文件。对于这一个，我们需要以下文件：`jquery.min.js`、`flowers.jpg`、`manual-sepia.css`和`manual-sepia.html`。将它们存储在我们项目文件夹的相应子文件夹中。

1.  在一个新文件中，我们需要创建我们的棕褐色插件，所以继续添加以下代码，从设置调用开始，以找到所有类名为`.sepia`的图像：

    ```js
    jQuery.fn.sepia = function () {
      $(window).load(function () {
        $('.sepia').each(function () {
          var curImg = $(this).wrap('<span />');
          curImg.attr("src", grayImage(this));
        });
      });
    ```

1.  下一个非常重要的函数是`grayImage`函数，它接收图像，将其绘制到画布上，然后操纵图像中的每个颜色通道，最后将其渲染回屏幕：

    ```js
      function grayImage(image) {
        var canvas = document.createElement("canvas");
        var ctx = canvas.getContext("2d");
        canvas.width = image.width;
        canvas.height = image.height;
        ctx.drawImage(image, 0, 0);
        var imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);

        for (var y = 0; y < imgData.height; y++) {
          for (var x = 0; x < imgData.width; x++) {
            var pos = (y * 4) * imgData.width + (x * 4);
            var mono = imgData.data[pos] * 0.32 + imgData.data[pos + 1] * 0.5 + imgData.data[pos + 2] * 0.18;
            imgData.data[pos] = mono + 50;
            imgData.data[pos + 1] = mono;
            imgData.data[pos + 2] = mono - 50;
          }
        }
        ctx.putImageData(imgData, 0, 0, 0, 0, imgData.width, imgData.height);
        return canvas.toDataURL();
      }
    };
    $.fn.sepia();
    ```

1.  让我们在浏览器中预览结果。如果一切顺利，我们应该会看到我们的图像具有漂亮的棕褐色调，如下图所示：![添加棕褐色调](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00438.jpeg)

这个滤镜版本在我们使用的代码方面可能看起来略有不同，但其中大部分是由于将其重新配置为插件以及一些变量名称的更改。如果我们仔细观察，就会发现两个示例中都使用了相同的原理，但产生了两个不同版本的同一图像。

### 提示

如果您想要了解更多关于使用`getImageData()`方法的信息，请查看 W3School 的教程，可在[`www.w3schools.com/tags/canvas_getimagedata.asp`](http://www.w3schools.com/tags/canvas_getimagedata.asp)上找到。

## 图像混合

对于我们的第三个和最后一个演示，并且为了证明`getImageData()`的多功能性，我们将在本章中一直使用的同一张花朵图像上添加一种色调。

这个演示相对而言比较简单。我们已经有了一个框架，以插件的形式存在；我们只需要将嵌套的`for…`块替换为我们的新版本即可。让我们开始吧：

1.  在`manual-sepia.js`的副本中，查找大约在第**17**行左右的以下行：

    ```js
    for (var y = 0; y < imgData.height; y++) {
    ```

1.  将高亮显示的内容删除直到第**25**行。用以下代码替换它：

    ```js
        var r_weight = 0.44;
        var g_weight = 0.5;
        var b_weight = 0.16;
        var r_intensity = 255;
        var g_intensity = 1;
        var b_intensity = 1;

        var data = imgData.data;
        for(var i = 0; i < data.length; i += 4) {
          var brightness = r_weight * data[i] + g_weight * data[i + 1] + b_weight * data[i + 2];
          data[i] = r_intensity * brightness; // red
          data[i + 1] = g_intensity * brightness; // green
          data[i + 2] = b_intensity * brightness; // blue
        }
        ctx.putImageData(imgData, 0, 0);
    ```

1.  现在，将文件保存为`manual-sepia.js`，然后在浏览器中预览`manual-sepia.html`。如果一切正常，我们应该会看到图像出现，但这次有了红色色调，如下图所示：![图像混合](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00439.jpeg)

这个演示中使用的数学看起来很简单，但可能需要一点解释。这是一个两阶段过程，我们首先使用`_weight`变量来计算亮度级别，然后使用`_intensity`变量来计算相关的强度级别，然后再将其重新应用于适当的颜色通道。

掌握使用这种方法构建滤镜所需的数学可能需要一些时间（这超出了本书的范围），但一旦你理解了数学，它就会带来一些真正的可能性！

### 注意

为了方便起见，我在这个演示中重新使用了相同的文件，以证明我们可以应用特定的颜色色调。在实践中，我们需要重新命名插件名称，以更好地反映正在使用的颜色（而且在这种情况下，不会是 sepias！）。

当然，我们还可以更进一步。这样做可能需要一些强大的数学，因此不适合胆怯的人！如果你喜欢挑战，那么一个很好的起点是学习使用**卷积掩模**，它看起来类似于以下内容（这个是用于图像模糊的）：

```js
    [.1, .1, .1],
    [.1, .2, .1],
    [.1, .1, .1],
```

这将使我们能够创建一些非常复杂的滤镜，比如 Sobel 滤镜（[`en.wikipedia.org/wiki/Sobel_operator`](http://en.wikipedia.org/wiki/Sobel_operator)），甚至是 Laplace 滤镜（[`en.wikipedia.org/wiki/Discrete_Laplace_operator#Implementation_in_Image_Processing`](http://en.wikipedia.org/wiki/Discrete_Laplace_operator#Implementation_in_Image_Processing)）- 警告：这数学真的很强大！为了将它变得简单一点，请看看 Google。以下是一些有用的起点：

+   [`halfpapstudios.com/blog/2013/01/canvas-convolutions/`](http://halfpapstudios.com/blog/2013/01/canvas-convolutions/)

+   [`thiscouldbebetter.wordpress.com/2013/08/14/filtering-images-with-convolution-masks-in-javascript/`](https://thiscouldbebetter.wordpress.com/2013/08/14/filtering-images-with-convolution-masks-in-javascript/)

+   [`beej.us/blog/data/convolution-image-processing/convolution.js`](http://beej.us/blog/data/convolution-image-processing/convolution.js)

让我们换个方式！我们已经使用不同的方法对我们的图像应用了一些滤镜，但有没有人注意到效果有多突然？一个更令人愉悦的路线是动画过渡过程。让我们看看如何使用**cssAnimate**库实现这一点。

# 使用滤镜来实现图像动画

好的，我们已经讨论了许多不同的方法来应用滤镜来操作图像的外观。在我们继续并查看一些实际示例之前，让我们停顿一下。

有没有人注意到，当使用 jQuery 时，我们失去了逐渐从一个状态过渡到另一个状态的能力？过渡只是提供状态变化的一种方式之一 - 毕竟，逐渐改变状态比看到突然切换更容易接受！

我们可以花时间从头开始使用 jQuery 创造一个解决方案。然而，更明智的解决方案是使用一个专门用于此目的的插件。

## 引入 cssAnimate

进入 cssAnimate！这个小宝石由 Clemens Damke 制作，它生成了必要的 CSS3 样式来动画地更改状态，但如果不支持，则退回到使用 jQuery 的 `animate()` 方法处理程序。该插件可从 [`cortys.de/cssAnimate/`](http://cortys.de/cssAnimate/) 下载。尽管该网站指出了 jQuery 1.4.3 或更高版本的最低要求，但在与 jQuery 2.1 一起使用时，它可以无明显问题地运行。

让我们看一下我们即将产生的截图：

![引入 cssAnimate](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00440.jpeg)

让我们开始吧：

1.  我们将从随本书附带的代码下载中提取以下文件开始：`cssanimate.html`、`cssanimate.css`、`flowers.jpg`、`jquery.min.js` 和 `jquery.cssanimate.min.js`。

1.  将 JavaScript 文件保存到 `js` 子文件夹中，将图像保存到 `img` 文件夹中，将 CSS 文件保存到 `css` 子文件夹中，并将 HTML 标记保存到我们项目区域的根文件夹中。

1.  在一个单独的文件中，添加以下代码，该代码将动画更改为 `hue-rotate` 滤镜：

    ```js
    $(document).ready(function(){
      $("input[name='css']").on("click", function(){
        $("img").cssAnimate({filter: hue-rotate(50deg), -webkit- filter: hue-rotate(50deg)}, 500, "cubic-bezier(1,.55,0,.74)");
      })
    });
    ```

1.  如果一切顺利，当点击**使用 CSS 更改滤镜**按钮时，我们应该看到花朵似乎变成深粉色，就像我们练习开始时所示。

乍一看，我们唯一能看到的变化是图像变为深粉色。然而，真正的变化将在我们使用 DOM 检查器（例如 Firebug）检查代码时显示出来：

![引入 cssAnimate](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00441.jpeg)

这个库的美妙之处在于，尽管它已经有几年了，但似乎仍然可以很好地与现代版本的 jQuery 配合使用。这为我们开辟了一些真正可以探索的途径，就我们可以使用的过渡动画而言。

### 注意

过渡支持在主要浏览器中几乎达到了 100%，除了 Opera Mini。要获取最新的情况，值得查看 Can I Use 网站 [`caniuse.com/#feat=css-transitions`](http://caniuse.com/#feat=css-transitions)。

尽管 cssAnimate 中内置的动画数量有限，但至少它包括对 cubic-bezier 值的支持。Matthew Lein 制作了一个文件，其中包含一些著名缓动效果的 cubic-bezier 等效值；这可以从 [`github.com/matthewlein/Ceaser/blob/master/developer/ceaser-easings.js`](https://github.com/matthewlein/Ceaser/blob/master/developer/ceaser-easings.js) 获取。我们可以使用这个来提供可以放入我们动画中以产生期望效果的值。或者，我们可以使用像 [`cubic-bezier.com`](http://cubic-bezier.com) 这样的网站设计自己的 cubic-bezier 缓动效果 - 这提供了可以用于我们动画的类似值。

### 注意

顺便说一下 - 当我为这本书进行研究时，我发现了这个简洁的演示：[`codepen.io/dudleystorey/pen/pKoqa`](http://codepen.io/dudleystorey/pen/pKoqa)。我想知道我们是否可以使用 cssAnimate 来产生类似的效果？

好了 - 目前足够使用滤镜了！让我们转换焦点，深入一些更实际的内容。你们有多少人曾经在线签署过某物，使用电子签名？如果情况需要，这是一个很棒的效果。我们将看看如何实现，但是扩展它，以便我们可以保存图像供以后使用。

# 创建签名板并导出图像

现在我们已经看到了如何操作图像，让我们把注意力转向更基础的事情；捕捉绘制在画布元素上的图像。

随着我们越来越多地进入数字化世界，会有一些场合需要我们用电脑电子签署文件。这并不意味着我们不应该在狂欢一晚之后的早晨签署任何文件，但更糟糕的事情可能会发生...！考虑到这一点，让我们看看在文档签署后如何捕捉图像。

对于此演示，我们将使用 Thomas Bradley 的 jQuery Signature Pad 插件。该插件可从[`thomasjbradley.ca/lab/signature-pad`](http://thomasjbradley.ca/lab/signature-pad)获取。我们将进一步进行 - 不仅仅是签署我们的名字，而且还将提供一个选项，使用`canvas.toDataURL()`方法将输出保存为 PNG 文件。

### 注意

记住 - 如果你使用 Chrome，请从本地网络服务器中运行此演示，正如 *准备就绪* 部分建议的那样。

让我们开始：

1.  我们将从附带本书的代码下载中下载所需的 CSS 和 HTML 标记文件，开始这个演示。继续并提取签名板文件夹并将其保存到项目区域。

1.  接下来，将以下代码添加到一个新文件中 - 将其保存为`signaturepad.js`，放在我们演示文件夹的`js`子文件夹中：

    ```js
    $(document).ready(function() {
      $('.sigPad').signaturePad();
      var canvas = $('#canvas')[0], ctx = canvas.getContext('2d');

      $('#download').on('click', function() {
        saveImage();
        downloadCanvas(this, 'canvas', 'signature.png');
      });

      function saveImage() {
        var api = $('.sigPad').signaturePad();
        var apitext = api.getSignatureImage();
        var imageObj = new Image();
        imageObj.src = apitext;
        imageObj.onload = function() {
          ctx.drawImage(imageObj, 0, 0);
        };
      }

      function downloadCanvas(link, canvasId, filename) {
        link.href = $(canvasId)[0].toDataURL();
        link.download = filename;
      }
    });
    ```

    ### 注意

    代码下载中已经有这个文件的一个版本；提取并将`signaturepad-completed.js`重命名为`signaturepad.js`，然后按照本演示中所述的方法将其存储在相同的`js`文件夹中。

1.  如果我们在浏览器中预览结果，应该会看到一个签名板显示，如下面的屏幕截图所示：![创建签名板并导出图像](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00442.jpeg)

在此屏幕截图中，我已经添加了我的名字。尝试点击**绘制**然后画出你的名字 - 小心，需要手脚稳！接下来，点击链接。如果一切正常，我们将被提示打开或保存名为`signature.png`的文件。在适当的图形软件中打开它确认签名已正确保存。参考以下图像：

![创建签名板并导出图像](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00443.jpeg)

尽管这只是一个相对简单的演示，但它开启了一些真正的可能性。除了我们使用的签名插件之外，这个演示的关键在于两个方面：使用`<canvas>`元素来捕获绘制的签名，以及使用`.toDataURL()`方法将画布元素的内容转换为数据 URI，其中包含以 PNG 格式表示的图像（默认情况下）。

我们首先获取一个句柄，然后将图像绘制到一个 canvas 元素上。一旦下载事件处理程序被触发，它就会将图像转换为数据 URI 表示形式，然后将其呈现为我们可以保存以供以后使用的格式。

### 注意

如果您想了解更多关于`toDataURL()`方法的信息，那么 Mozilla 的开发者实验室有一篇很好的文章，可以在[`developer.mozilla.org/en-US/docs/Web/API/HTMLCanvasElement.toDataURL`](https://developer.mozilla.org/en-US/docs/Web/API/HTMLCanvasElement.toDataURL)找到。

让我们将这个技术应用到实践，并将其与本章开头涵盖的摄像头和图像操作技术相结合。这使我们可以变得非常疯狂；想要玩一些捕捉和更改网络摄像头图像的有趣内容吗？

# 捕获和操作网络摄像头图像

在本章的第二个也是最后一个演示中，我们将通过网络摄像头玩一些有趣的东西 - 我们可以从笔记本电脑或独立摄像头中获取和操作图像的方式之一。

这个演示的关键在于使用`getUserMedia`，它允许我们控制音频或视频源。这是一个相对年轻的 API，需要使用供应商前缀来确保完全支持。与其他 API 一样，它们的需求会随着时间的推移而消失，因此定期检查[`caniuse.com/#search=getusermedia`](http://caniuse.com/#search=getusermedia)是值得的，以查看是否已更新支持并删除了前缀的需求。

这个演示将汇集我们探讨过的一些概念，比如应用过滤器、将画布图像保存到文件以及控制网络摄像头。为了正确运行这个演示，我们将需要从 HTTP 协议地址而不是`file://.`运行它。为此，您将需要一些可用的网络空间，或者使用像 WAMP（适用于 PC - [`www.wampserver.com/en`](http://www.wampserver.com/en)）或 MAMP（适用于 Mac，现在也适用于 PC，来自[`www.mamp.info/en/`](http://www.mamp.info/en/)）。

好的，假设这一切都就绪，让我们开始吧：

1.  我们将从与本书附带的代码下载中提取`webcam demo`文件夹开始。它包含了为本演示所需的样式、标记和 jQuery 库的副本。

1.  一旦提取出来，将整个文件夹上传到您的网络空间。我将假设您正在使用 WAMPServer，所以这将是`/www`文件夹；如果您使用的是其他内容，请相应地进行更改。

1.  我们需要添加使此演示工作所需的 jQuery 魔法。在一个新文件中，继续添加以下代码；我们将逐节介绍它，从分配变量和过滤器数组开始：

    ```js
    $(document).ready(function() {
      var idx = 0;
      var filters = ['grayscale', 'sepia', 'blur', 'saturate', ''];

      var canvas = $("canvas")[0], context = canvas.getContext("2d"),
      video = $("video")[0], localStream, videoObj = { "video": true }, errBack = function(error) {
          console.log("Video capture error: ", error.code);
        };
    ```

1.  第一个函数处理通过过滤器的分页。我们循环遍历存储在过滤器数组中的过滤器名称。如果样式表中有相应的样式规则，则将以下内容应用于画布图像：

    ```js
      function changeFilter(e) {
        var el = e.target;
        el.className = '';
        var effect = filters[idx++ % filters.length];
        if (effect) {
          el.classList.add(effect);
        }
      }
    ```

1.  接下来，我们需要获取`getUserMedia`的实例，我们将用它来控制网络摄像头。由于这仍然是一个相对年轻的 API，我们必须使用供应商前缀：

    ```js
      navigator.getUserMedia = (navigator.getUserMedia || navigator.webkitGetUserMedia || navigator.mozGetUserMedia || navigator.msGetUserMedia);
    ```

1.  第一个事件处理程序中，`#startplay`按钮是最重要的。在这里，我们捕获网络摄像头源，然后将其分配给视频对象，并生成引用我们内容的 URL。一旦分配完成，我们开始播放视频，这样我们就可以在屏幕上查看内容：

    ```js
      $("#startplay").on("click", function(e) {
        if (navigator.getUserMedia) {
          navigator.getUserMedia(videoObj, function(stream) {
            video.src = window.URL.createObjectURL(stream);
            localStream = stream;
            video.play();
          }, errBack);
        }
      });
    ```

1.  然后，我们需要分配一些事件处理程序。按顺序，以下处理程序处理请求以拍摄图像快照，停止视频，更改过滤器，并下载快照图像的副本：

    ```js
      $("#snap").on("click", function() {
        context.drawImage(video, 0, 0, 320, 240);
      });

      $("#stopplay").on("click", function(e, stream) {
        localStream.stop();
      });

      $('#canvas').on('click', changeFilter);

      $("#download").on('click', function (e) {
        var dataURL = canvas.toDataURL('image/png');
        $("#download").prop("href", dataURL);
      });
    });
    ```

1.  将文件保存为`webcam.js`，并放在我们之前在此演示中上传的`webcam demo`文件夹的`js`子文件夹中。

1.  此时，我们可以尝试在浏览器中运行演示。如果一切正常，我们将首先收到一个请求，询问浏览器是否可以访问网络摄像头（出于安全原因），如下图所示：![捕捉和操作网络摄像头图像](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00444.jpeg)

1.  然后是摄像头的初始化。它以一个占位符图像开始，如下图所示；几秒钟后，这将显示实时视频：![捕捉和操作网络摄像头图像](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00445.jpeg)

在这一点上，我们可以玩得很开心。尝试点击**拍照**以拍摄自己的照片快照；这将显示在实时视频的右侧。如果单击此图像，它将在样式表中设置的几个过滤器之间进行循环，并在`webcam.js`中引用：

```js
  var filters = ['grayscale', 'sepia', 'blur', 'saturate', ''];
```

等一下 - 有人注意到单击**下载照片**按钮后得到的图像有什么不同吗？你们中敏锐的人很快就会注意到，这是原始图像的副本，在应用过滤器之前。

原因是这些过滤器在 CSS 中设置 - 当在浏览器窗口中显示时，它们才会产生任何效果！为了解决这个问题，我们需要修改我们的下载事件处理程序。我们可以使用我们之前探索过的 CamanJS 库来应用一些基本的过滤器，例如库中提供的日出效果。

为此，请修改`#download`事件处理程序以显示以下代码：

```js
  $("#download").on('click', function (e) {
    e.preventDefault();
    Caman('#canvas', function(){
      this.sunrise();
      this.render(function() { this.save("webcam-photo.png"); });
    });
  });
```

现在尝试保存截图的副本。虽然它不会强制下载到您的桌面，但它仍然会在浏览器中显示一个图像，显示应用了日出滤镜的图像。

当使用`getUserMedia`时，我们只是触及了可能性的表面——在线学习更多是非常值得的。一个很好的起点是 Mozilla 开发者网络上的文章，可在[`developer.mozilla.org/en-US/docs/NavigatorUserMedia.getUserMedia`](https://developer.mozilla.org/en-US/docs/NavigatorUserMedia.getUserMedia)找到。注意——`getUserMedia`不支持 IE11 或更低版本，因此您需要使用像 Addy Osmani 的`getUserMedia.js`这样的 polyfill 库，可在[`github.com/addyosmani/getUserMedia.js`](https://github.com/addyosmani/getUserMedia.js)下载。

### 注意

顺便说一句，我曾考虑在这本书中加入使用 reveal.js 库来控制一个简单图像画廊的手势控制内容展示，就像在[`www.chromeexperiments.com/detail/gesture-based-revealjs/`](http://www.chromeexperiments.com/detail/gesture-based-revealjs/)中展示的那样。不幸的是，代码不够稳固，而且已经有一段时间没有更新了。我很想听听你的想法。这是展示一种流畅呈现内容的好方法，但需要更多的工作！

# 收尾工作

在我们总结这一章之前，值得暂停一下，考虑一下我们在本章中涵盖的一些技术带来的影响。

纯粹主义者可能会质疑使用 jQuery 应用过滤器的必要性，特别是如果我们所需要做的只是使用诸如`.addClass()`或者甚至`.toggleClass()`这样的方法来应用或移除特定的过滤器。另一方面，这本书当然是关于 jQuery 的，我们应该集中精力使用它，即使这意味着显示我们使用的一些过滤效果的明显延迟。

这个问题的简短答案取决于你——任何人都可以在某种程度上编写 jQuery 代码，但一般和优秀开发者的区别不仅仅在于编写代码。

真正的区别部分在于做出正确选择。jQuery 经常被视为简单的选择，特别是因为它提供了最广泛的支持范围。我们可以创建任何类型的过滤器来满足我们的需求，但这总是以处理能力为代价——我们无法摆脱操作画布元素需要大量资源的事实，因此完成速度很慢。如果使用高清图像（正如我们在*使用 CamanJS 应用过滤器*部分中注意到的那样）——事实上，速度会更慢，因为需要处理更多像素！

结论是，我们需要仔细考虑我们需要应用哪些过滤器，以及我们是否可以简单地使用 CSS3 过滤器来满足我们的需求。没错，这些可能无法解决我们所有的需求，但是支持正在变化。我们应该真正考虑在延迟不是问题的情况下使用 jQuery 过滤器，并且应用程序不会在移动平台上使用（由于处理每个像素所需的资源！）。

# 总结

操纵图像是 jQuery 中的一个悖论——我们可以使用 CSS3 滤镜轻松产生简洁的效果，但受到 CSS3 滤镜能够提供的限制；或者我们可以产生任何我们想要的滤镜，但以像素级别操作图像所需的处理资源为代价！在本章中，我们涵盖了大量信息，让我们花一点时间回顾我们学到的东西。

我们以添加 CSS3 滤镜开始，看到了将这些应用到图像上是多么容易。然后，我们转而研究了使用 CSS3 混合图像的不同技术，然后将注意力转向了检查 jQuery 图像插件。

我们花了一些时间探索一些应用滤镜的基本选项，然后创建了我们自己的基于 jQuery 的滤镜。然后我们转而研究如何通过动画过渡到使用滤镜，以帮助提供更流畅的过渡，最后看一下使用签名板和网络摄像头创建基本演示的方法，作为使用 jQuery 捕获图像的手段。

然后，我们总结了本章关于何时应该使用 CSS3 滤镜或 jQuery 的一些最终想法，强调任何人都可以编写代码，但好的开发人员知道在开发过程中何时使用正确的工具。

在下一章中，我们将扩展插件的使用，并探讨将插件开发技能提升到下一个水平。


# 第十一章：编写高级插件

在整本书中，一个共同的主题是使用插件——现在是创建一个插件的时候了！

可供使用的插件数量之多简直令人难以置信，从只有几行代码的插件到数百行的插件不等。我非常相信“有志者，事竟成”这句话——可以说插件满足了这种意愿，并为用户提供了解决需求或问题的途径。

在接下来的几页中，我们将从头到尾看一下如何开发一个高级插件。我们不仅关注构建本身，还将探讨一些技巧和窍门，以帮助我们在使用插件时进一步提高开发技能。我们将涵盖最佳实践，并查看一些可以提高当前编码技能的领域。在接下来的几页中，我们将涵盖以下主题：

+   最佳实践和原则

+   检测插件开发不佳的迹象

+   为 jQuery 插件创建设计模式

+   设计一个高级插件并使其可供使用

准备好了吗？

# 检测插件开发不佳的迹象

想象一下场景，如果你愿意——你花几周时间开发一个复杂的插件，它几乎包含了所有功能，让所有看到的人都惊叹不已。

听起来像是完美的理想境界，不是吗？你把它发布到 GitHub 上，创建一个很棒的网站，等待用户踊跃下载你的最新作品。你等待着……等待着……但最后一位用户也没有。好吧……怎么回事？

正如我经常说的，任何人都可以编写代码。成为更好的 jQuery 插件开发者的关键是理解什么是好的插件，以及如何将其付诸实践。为了帮助理解，让我们花点时间看一下一些指标，可以用来判断一个插件是否可能失败：

+   你没有在做一个插件！通行的做法是使用少数几种插件模式之一。如果你没有使用其中一种模式（如下所示的模式），那么你的插件被接受的可能性很低。

    ```js
    (function($, window, undefined) {
      $.fn.myPlugin = function(opts) {
        var defaults = {
        // setting your default values for options
      }
      // extend the options from defaults with user's options
      var options = $.extend(defaults, opts || {});
      return this.each(function(){ // jQuery chainability
        // do plugin stuff
      });
    })(jQuery, window);
    ```

+   虽然我们在参数中定义了`undefined`，但我们只在自调用函数中使用了 `$` 和 `window`。这可以防止恶意传递`undefined`的值到插件中，因为它在插件内部将保持为`undefined`。

+   你花时间编写代码，但忽略了其中一个关键元素——准备文档！我一次又一次地看到插件的文档非常少或根本不存在。这使得理解插件的构成和如何充分利用它变得困难。关于文档编写没有硬性规定，但普遍认为，文档越多越好，而且应该是内联和外部的（以 readme 或 wiki 的形式）。

+   在缺乏合适文档主题上继续进行，开发人员会因为插件具有硬编码的样式或者过于不灵活而感到不满。我们应该考虑所有可能的需求，但要确定我们是否会为特定需求提供解决方案。应用于插件的任何样式都应该通过插件选项提供，或者作为样式表中的特定类或选择器 ID – 将其放在行内被认为是不良实践。

+   如果你的插件需要太多配置，那么这很可能会让人们失去兴趣。虽然一个更大、更复杂的插件应该明确地为最终用户提供更多的选项，但提供的内容也是有限度的。相反，每个插件至少应该设置一个不带参数的默认行为；用户不会喜欢为了使插件工作而设置多个值！

+   对最终用户来说，插件不提供任何形式的示例是很让人失望的。至少应该提供一个基本的“hello world”类型的示例，其中定义了最小配置。提供更多涉及的示例，甚至与其他插件一起工作的示例，可能会吸引更多的人。

+   一些插件失败的原因很基础。这些包括：没有提供变更日志或使用版本控制，不能在多个浏览器中工作，使用过时的 jQuery 版本或在实际上不需要时包含它（依赖性太低），或者没有提供插件的缩小版本。使用 Grunt 就没有借口了！我们可以自动化大部分开发人员所期望的基本管理任务，如测试、缩小插件或维护版本控制。

+   最后，插件可能因为两个简单的原因而失败：要么它们太聪明，试图实现太多（使得调试困难），要么太简单，jQuery 作为库的依赖性不足以保证包含它。

很多事情需要考虑！虽然我们无法预测插件是否会成功，或者使用情况会不会低，但我们至少可以尝试通过将这些提示中的一些（或全部）纳入我们的代码和开发工作流程中来最小化失败的风险。

从更实际的角度来看，我们可以选择遵循许多设计模式中的任何一种，以帮助我们的插件给予结构和一致性。我们在第三章中提到过这一点，*组织您的代码*。美妙之处在于我们可以自由地在 jQuery 插件中使用类似的原则！让我们在使用其中一个来开发一个简单插件之前，花一点时间考虑一些可能的例子。

# 介绍设计模式

如果你在 jQuery 中开发代码花费了任何时间，那么很可能你创建了一个或多个插件；从技术上讲，这些插件可以只有几行代码，也可以更加实质性。

随着时间的推移，修改插件中的代码可能会导致内容变得笨重且难以调试。解决这个问题的一种方法是使用设计模式。我们在第三章中介绍了这一点，*组织您的代码*。许多相同的原则同样适用于插件，尽管模式本身当然会有所不同。让我们考虑一些例子。

最基本的模式是**轻量级起步**，适合那些以前开发过插件但对遵循特定模式的概念尚不熟悉的人。这种特定模式基于常见的最佳实践，例如在调用函数之前使用分号；它会传递标准参数，如`window`、`document`和`undefined`。它包含一个基本的默认对象，我们可以扩展它，并在构造函数周围添加一个包装器以防止多个安装引起的问题。

相反，我们也可以尝试使用**完整小部件工厂**。尽管它被用作 jQuery UI 的基础，但它也可以用来创建标准的 jQuery 插件。这种模式非常适合创建复杂的、基于状态的插件。它包含了所有使用的方法的注释，以确保逻辑符合你的插件。

我们还介绍了命名空间的概念，即添加特定名称以避免与全局命名空间中的其他对象或变量发生冲突。虽然我们可能在代码中使用命名空间，但我们也可以同样将其应用于插件。这种模式的好处在于我们可以检查其现有实例；如果名称不存在，则我们可以自由添加它，否则我们可以使用相同命名空间扩展现有插件。

这些是可供使用的三种插件模式之一；但我确信会有一个问题，那就是使用哪一个？和许多事情一样，没有对错答案；这将取决于具体情况。

### 注意

最常见的插件设计模式列表可在[`github.com/jquery-boilerplate/jquery-patterns`](https://github.com/jquery-boilerplate/jquery-patterns)找到。

## 创建或使用模式

如果你是第一次使用插件设计模式，那么**轻量级起步**是开始的最佳位置。使用任何插件模式或设计自己的插件模式有三个关键方面：

+   **架构**：这定义了组件之间应如何交互的规则。

+   **可维护性**：任何编写的代码都应易于扩展和改进。它不应从一开始就被锁定。

+   **可重用性**：你现有的代码可以多频繁地重用？它可以多频繁地重用，节省的时间就越多，维护起来也会更容易。

使用模式的重要之处在于没有一个单一的正确答案。关键在于哪种模式最符合你的需求。最好的方法是尝试它们。随着时间的推移，经验将为您提供一个明确的指示，哪种模式对于特定情景效果最佳。

### 提示

关于使用特定插件模式的利弊的讨论，请移步到 Smashing Magazine 的文章[`www.smashingmagazine.com/2011/10/11/essential-jquery-plugin-patterns/`](http://www.smashingmagazine.com/2011/10/11/essential-jquery-plugin-patterns/)。虽然已经有几年了，但其中许多观点仍然具有价值。

无论如何，让我们回到现在吧! 没有比现在更好的时间来获得经验了，所以让我们看一看 jQuery 轻量级样板模式。这实现了 Singleton/Module 设计模式。它帮助开发人员编写封装代码，可以远离污染全局命名空间。

在接下来的几页中，我们将开发一个提示框插件。我们将从一个不使用任何模式的典型构建开始，然后修改它以使用轻量级样板格式。然后我们将深入探讨一些小贴士和技巧，这将帮助我们考虑更大的画面，并希望使我们成为更好的开发者。

# 设计一个高级插件

好了——不要再闲聊了! 让我们深入研究一些代码吧! 在接下来的几页中，我们将花一些时间开发一个在页面上显示简单提示框的插件。

好吧，在你们都喊叫说“不要再一个提示框插件了……!”之前，选择这个功能有一个很好的理由。一旦我们开发了插件的第一个版本，一切都会变得清晰。让我们开始吧——我们将从简要介绍创建我们的插件开始:

1.  对于这个演示，我们将需要这本书附带的代码下载中这一章的整个代码文件夹。继续并提取它，保存到我们的项目区域。

1.  在文件夹中，运行`tooltipv1.html`文件，其中包含一个由六幅图像组成的网格，以及一些虚拟文本。依次将鼠标悬停在图像上。如果一切正常，它会显示一个提示框:![设计一个高级插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00446.jpeg)

此刻你可能在想所有代码是如何串联在一起的。这是一个合理的问题……但我们将打破传统，不去审视它。相反，我想专注于重新设计代码，使用样板格式，这将有助于使其更易于阅读、调试和扩展。让我们考虑一下这对我们的插件意味着什么。

## 使用样板重建我们的插件

如果您对样板编制还不熟悉，请举手？有可能您已经遇到了一些例子，如 Bootstrap（[`www.getbootstrap.com`](http://www.getbootstrap.com)），或者甚至 HTML5 Boilerplate（[`html5boilerplate.com/`](https://html5boilerplate.com/)）。为了帮助您熟悉这个术语，它基于一个简单的想法：使用模板来帮助构建代码结构。这并不意味着它会为我们编写代码（可惜——我们可以因此无所作为而赚取数百万，哈哈！），但它通过重用框架来快速开发代码，比如完整的网站或者甚至 jQuery 插件，有助于节省时间。

对于我们的下一个演示，我们将使用来自[`github.com/jquery-boilerplate/jquery-patterns`](https://github.com/jquery-boilerplate/jquery-patterns)的 jQuery Boilerplate 模板重新设计我们的插件。与互联网一样，某种善良的灵魂已经创建了一个使用这种技术的良好的工具提示示例，因此我们将根据我们的需要进行调整。

### 提示

如果您对学习更多关于 jQuery Boilerplate 插件模式的内容感兴趣，您可能会喜欢查看 Jonathan Fielding 的《*Instant jQuery Boilerplate for Plugins*》，该书由 Packt Publishing 出版。

我们将使用的插件示例是由法国网页开发者 Julien G 提供的。原始版本可通过 JSFiddle 在[`jsfiddle.net/molokoloco/DzYdE/`](http://jsfiddle.net/molokoloco/DzYdE/)上找到。

1.  让我们开始（像往常一样），从代码下载中提取本章的代码文件夹的副本。如果您已经从上一个练习中拥有它，那么我们可以使用它。

1.  导航至`version 2`文件夹，然后在浏览器中预览`tooltipv2.html`。如果一切顺利，我们应该看到与前一个示例中相同的一组图像，并且工具提示应用了相同的样式。

乍看之下，似乎什么也没有改变——这本身实际上是成功的一个很好的指标！真正的变化在于`tooltipv2.js`中，在`version 2`文件夹下的`js`子文件夹中。让我们逐步进行，从声明变量开始：

1.  我们首先声明了 jQuery、`document`、`window`和`undefined`的属性。你可能会问为什么我们要传入`undefined`——这是一个很好的问题：这个属性是可变的（意味着它可以被更改）。虽然在 ECMAScript 5 中它被设置为不可写，但在我们的代码中不使用它意味着它可以保持未定义并防止恶意代码的尝试。传递剩下的三个属性可以使我们在代码中更快地引用它们：

    ```js
    (function($, window, document, undefined) {
      var pluginName = 'tooltip', debug = false;
    ```

1.  下一步是内部方法。我们将它们创建为`internal`对象中的方法；第一个负责将工具提示定位在屏幕上，而`show`和`hide`控制工具提示的可见性：

    ```js
    var internal = {
      reposition: function(event) {
        var mousex = event.pageX, mousey = event.pageY;

        $(this)
        .data(pluginName)['tooltip']
        .css({top: mousey + 'px', left: mousex + 'px'});
      },

      show: function(event) {
        if (debug) console.log(pluginName + '.show()');
        var $this  = $(this), data = $this.data(pluginName);

        data['tooltip'].stop(true, true).fadeIn(600);
        $this.on('mousemove.' + pluginName, internal.reposition);
      },

      hide: function(event) {
        if (debug) console.log(pluginName + '.hide()');
        var $this = $(this), data  = $this.data(pluginName);
        $this.off('mousemove.' + pluginName, internal.reposition);
        data['tooltip'].stop(true, true).fadeOut(400);
      }
    };
    ```

1.  我们继续外部方法。首先在`external`对象内部，`init`函数首先出现，用于初始化我们的插件并在屏幕上呈现它。然后在移动到带有`.tooltip`类实例的元素时，我们调用`internal.show`和`internal.hide`内部方法：

    ```js
    var external = {
      init: function(options) {
        if (debug) console.log(pluginName + '.init()');

        options = $.extend(
          true, {},
          $.fn[pluginName].defaults,
          typeof options == 'object' &&  options
        );

        return this.each(function() {
          var $this = $(this), data = $this.data(pluginName);
          if (data) return;

          var title = $this.attr('title');
          if (!title) return;
          var $tooltip = $('<div />', {
            class: options.class,
            text:  title
          }).appendTo('body').hide();

          var data = {
            tooltip:   $tooltip,
            options:   options,
            title:     title
          };

          $this.data(pluginName, data)
            .attr('title', '')
            .on('mouseenter.' + pluginName, internal.show)
            .on('mouseleave.' + pluginName, internal.hide);
          });
        },
    ```

1.  第二个外部方法处理了更新提示文本，使用`.data()`方法：

    ```js
        update: function(content) {
          if (debug) console.log(pluginName + '.update(content)', content);
          return this.each(function() {
            var $this = $(this), data  = $this.data(pluginName);
            if (!data) return;
            data['tooltip'].html(content);
          });
        },
    ```

1.  我们将我们的插件中可用的方法圆满地结束了，包括`destroy()`处理程序。这样可以阻止所选提示显示，并将元素从代码中删除：

    ```js
        destroy: function() {
          if (debug) console.log(pluginName + '.destroy()');

          return this.each(function() {
            var $this = $(this), data  = $this.data(pluginName);
            if (!data) return;

            $this.attr('title', data['title']).off('.' + pluginName)
              .removeData(pluginName);
              data['tooltip'].remove();
          });
        }
      };
    ```

1.  最后，但同样重要的是我们的插件启动器。这个函数简单地将方法名映射到我们插件中的有效函数，或者在它们不存在时进行优雅降级：

    ```js
    $.fn[pluginName] = function(method) {
      if (external[method]) return external[method]
      apply(this, Array.prototype.slice.call(arguments, 1));
      else if ($.type(method) === 'object' || !method) 
      return external.init.apply(this, arguments);
      else $.error('Method ' + method + ' does not exist on
      jQuery.' + pluginName + '.js');
    };
      $.fn[pluginName].defaults = {
      class: pluginName + 'Element'
      };
    })(window.jQuery);
    ```

不过，从这个演示中最重要的要点不是我们可以使用的具体功能，而是用于生成我们的插件的格式。

任何人都可以写代码，但使用像我们在这里使用的样板模式将有助于提高可读性，使调试更容易，并在以后的扩展或升级功能时增加机会。记住，如果你编写了一个插件，并且在一段时间内没有回顾它（比如说 6 个月）；那么酸测试是你能从良好结构化的代码中解决多少问题，而不需要大量文档。如果你做不到这一点，那么你需要重新审视你的编码！

让我们继续。还记得我提到选择使用提示插件作为我们例子基础的一个很好的原因吗？现在是时候揭示为什么了...

# 自动将动画转换为使用 CSS3

我们建立了一个提示插件，它在悬停在标记有`.tooltip`类的元素上时使用一点动画淡入淡出。那没错 - 代码完全正常运行，是一种可以接受的显示内容的方式...对吗？错！正如你现在应该知道的，我们绝对可以做得更好。这就是为什么我选择了提示作为我们的例子的原因。

还记得我在第六章中提到过的，在 jQuery 中进行动画，我们应该考虑使用 CSS3 样式来控制我们的动画吗？好吧，这里有一个完美的例子：我们可以轻松地改变我们的代码，强制 jQuery 尽可能使用 CSS3，或者在旧版本的浏览器中回退到使用库。

其中的诀窍在于一行代码：

```js
<script src="img/jquery.animate-enhanced.min.js"></script>
```

要看看有多简单，请按照以下步骤操作：

1.  在`tooltipv2.html`的副本中，按照提示添加这行：

    ```js
      <script src="img/jquery.min.js"></script>
     <script src="img/jquery.animate-enhanced.min.js"></script>
      <script src="img/jquery-ui.min.js"></script>
      <script src="img/jquery.quicktipv2.js"></script>
      <script src="img/tooltipv2.js"></script>
    ```

1.  在浏览器中预览结果。如果一切顺利，我们应该看到提示反应方式稍有改变。然而，当在像 Firebug 这样的 DOM 检查器中查看提示代码时，真正的改变就显而易见了：![自动将动画转换为使用 CSS3](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00447.jpeg)

如果我们在 Firebug 的计算样式一半查看，我们可以看到样式被分配给提示元素：

![自动将动画转换为使用 CSS3](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00448.jpeg)

这是一个简单的变化，但希望我们能看到在性能上有显著改进。在这种情况下，我们使用一个插件来强制 jQuery 使用 CSS3 样式代替标准的 jQuery 基础动画。

但在这里的关键信息是，作为开发人员，我们不应感到受限于使用 jQuery 来提供我们的动画。尽管对于管理复杂动作可能是一种必要之恶，但我们仍应考虑在那些不太华丽的情况下使用它。

## 使用基于 CSS 的动画

嗯 - 此时脑海中浮现一个问题：如果我们使用现代浏览器，为什么还需要依赖基于 jQuery 的动画呢？

答案很简单 - 简而言之，这取决于具体情况。但长话短说，对于现代浏览器，我们不需要依赖使用 jQuery 来提供我们的动画。只有在我们被迫为旧版浏览器版本（如 IE6）提供支持时，我们才需要使用 jQuery。

但是可能性应该很低。如果有必要的话，我们真的应该问自己我们是否在做正确的事情，或者是否应该逐渐降低支持，使用类似 Modernizr 这样的工具。

尽管如此 - 让我们通过以下步骤来理解我们需要做什么才能使用 CSS3 代替基于 jQuery 的动画：

1.  在 `tooltipv2.css` 的副本中，在文件底部添加以下 CSS 样式 - 这将是我们的工具提示的过渡效果：

    ```js
    div.arrow_box { transition-property: all; transition- duration: 2s; transition-timing-function: cubic-bezier(0.23, 1, 0.32, 1); }
    ```

1.  打开 `jquery.quicktipv2.js` 的副本，然后首先注释掉以下行：

    ```js
    data['tooltip'].stop(true, true).fadeIn(600);
    ```

    在原位添加以下行：

    ```js
    data['tooltip'].css('display', 'block');
    ```

1.  重复相同的过程，但这次是针对以下行：

    ```js
    data['tooltip'].stop(true, true).fadeOut(400);
    ```

    将下一行作为替换添加：

    ```js
    data['tooltip'].css('display', 'none');
    ```

1.  保存文件。如果我们在浏览器中预览变化的结果，应该看到工具提示滑动并悬停在所选图像上。

效果看起来非常流畅。虽然它不会淡入淡出，但仍然为工具提示的出现方式带来了有趣的变化。这确实引发了一个有趣的问题 - 我们应该使用什么效果？让我们暂停一下，考虑一下进行这种变化的影响。

## 考虑变化的影响

在我们的示例中使用 CSS3 样式提出了一个重要的问题 - 哪种效果效果最好？我们可以选择经典的线性或摆动效果，但这些已经被用得厌了。我们可以轻松地用更原创的东西替换它。在我们的示例中，我们使用了 `cubic-bezier(0.23, 1, 0.32, 1)`，这是 `easeOutQuint` 函数的 CSS3 等效函数。

解决这些效果可能会耗费时间。相反，我们可以使用 Lea Verou 创建的一个很棒的工具，它可以在 [`www.cubic-bezier.com`](http://www.cubic-bezier.com) 上使用。

![考虑变化的影响](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00449.jpeg)

要查看我们选择的效果在实际中的样子，前往 [`cubic-bezier.com/#.23,1,.32,1`](http://cubic-bezier.com/#.23,1,.32,1)。 该网站有一个我们可以运行的示例，以查看效果如何工作。 该网站的好处在于我们可以使用图表来微调我们的效果，这会自动转换为我们可以转移到我们的代码中的相关值。

这打开了进一步的可能性——我们提到了来自 [`github.com/rdallasgray/bez`](http://github.com/rdallasgray/bez) 的 Bez 插件的使用；这很容易在这里代替标准的 `.css()` 方法，来提供我们的动画。

### 提示

对于众所周知的缓动函数（如 `easeInQuint`），其 CSS 等效函数都列在 [`gist.github.com/tzachyrm/cf83adf77246ec938d1b`](https://gist.github.com/tzachyrm/cf83adf77246ec938d1b) 上；我们可以在 [`www.easings.net`](http://www.easings.net) 上看到它们的效果。

不过，重要的是，当在 DOM Inspector 中查看 CSS 时，我们可以看到的变化是：

![考虑到变化的影响](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00450.jpeg)

与其内联应用（如 *自动将动画转换为使用 CSS3* 部分所示），我们可以保持关注点分离原则，将 CSS 样式保留在样式表中，将 HTML 用于组织我们的网页内容。

## 回退到 jQuery 动画

到目前为止，我们使用 CSS 样式来创建我们的动画效果。 这引发了一个问题，即我们是否应该将此技术用于我们所有的动画需求，还是应该使用 jQuery 效果。

一切都归结为两个关键点——动画有多复杂，以及你是否需要支持旧版浏览器？ 如果答案是肯定的（或两者都是肯定的），那么 jQuery 很可能会胜出。 但是，如果你只有一个简单的动画，或者你不需要支持旧版浏览器，那么使用 CSS 应该值得认真考虑。

到目前为止，我们使用的动画的一个很棒的地方是，我们可以使用两种方法提供相同的效果——即 CSS 和 jQuery。 jQuery 中缓动函数的一个很好的来源是 [`github.com/gdsmith/jquery.easing`](https://github.com/gdsmith/jquery.easing) - 这里列出了所有标准的、在诸如 jQuery UI 等库中可用的众所周知的缓动函数。 为了证明我们可以实现相同的效果，让我们继续对我们的代码进行快速更改，使用已经使用过的动画的 jQuery 等效方法。 按照以下步骤进行：

1.  我们首先要编辑 `quickTip` 插件文件的副本。 继续找到 `jquery.quicktipv2.js` 的副本，然后在变量声明之后立即添加以下代码块：

    ```js
    $.extend($.easing, {
      easeInQuint: function (x, t, b, c, d) {
        return c*(t/=d)*t*t*t*t + b;
      },

      easeOutQuint: function (x, t, b, c, d) {
        return c*((t=t/d-1)*t*t*t*t + 1) + b;
      }
    });
    ```

1.  现在我们需要调整我们的动画以利用缓动函数，所以继续修改 `fadeIn` 方法，如下所示的代码行：

    ```js
    data['tooltip'].stop(true, true).fadeIn(600, 
      'easeInQuint');
      $this.on('mousemove.' + pluginName, internal.reposition);
    },
    ```

1.  没有 `fadeIn` 就不能有其姐妹 `fadeOut()`，因此我们也需要更改这个调用，如下所示：

    ```js
    $this.off('mousemove.' + pluginName, internal.reposition);
      data['tooltip'].stop(true, true).fadeOut(400, 
      'easeInQuint');
    }
    ```

1.  将文件保存为`jquery.quicktipv2.easing.js`。不要忘记在`tooltipv2.html`中修改原始插件引用！我们还需要在`tooltipv2.css`文件中取消`div.arrow_box`的过渡样式，因此请继续并注释掉这段代码。

在这一点上，我们已经使用 jQuery 实现了一个可行的解决方案。如果我们在浏览器中预览结果，工具提示将显示为应该显示的样子。不过，缺点是我们失去了所使用的样式的可见性，并且（如果 JavaScript 在浏览器中被禁用的话）动画就不会播放了。

还有一个重要的观点是 jQuery 动画已经消耗了更多资源，我们在第六章中也提到过，*在 jQuery 中进行动画*。那么，在这些情况下，为什么我们要求在这里使用 jQuery 动画，而不是 CSS？再一次，这是成为更好的开发者的一部分 - 容易诉诸于使用 jQuery; 在考虑所有替代方案之前考虑这一点是正确的！

### 提示

如果您设计了自定义缓动，并希望使用 CSS 等效-添加我们之前使用的 jQuery 动画增强插件的链接。这将使用贝塞尔曲线值提供 CSS 等效。然后我们可以使用之前的 Bez 插件，或者甚至使用来自[`github.com/gre/bezier-easing`](https://github.com/gre/bezier-easing)的 bezier-easing 将其添加回作为基于贝塞尔曲线的动画。

现在让我们转移重点并继续前进。到目前为止，我们的插件中提供了有限的选项；如果我们想要扩展它怎么办？我们可以尝试深入代码并进行调整；尽管在某些情况下，这可能对我们的需求来说有些过度。一个更好的选择可能是将其简单地封装为一个新插件的实例。让我们来看看涉及到什么。

# 扩展我们的插件

使用插件时常见的问题是找到完全符合我们要求的插件；发生这种情况的可能性可能比中彩票还要小！

为了解决这个问题，我们可以扩展我们的插件，以在不影响现有方法的情况下加入额外的功能。这样做的好处是，我们可以覆盖现有的方法或合并额外的功能，帮助使插件更接近我们的需求。要了解这在实际应用中是如何工作的，我们将向我们现有的插件添加一个方法和额外的变量。有许多方法可以实现这一点，但我使用的方法也很有效。让我们按照以下步骤进行：

1.  我们将从编辑`tooltipv2.js`的副本开始。在`#getValue`点击处理程序的下面，继续添加以下代码：

    ```js
      (function($) {
        var extensionMethods = {
          fadeInValue: 600,
          showDebug: function(event) {
            console.log("This is a test");
          }
        }
        $.extend($.fn.quicktip, extensionMethods);
      })(jQuery);
    ```

1.  保存文件。如果我们在浏览器中预览`tooltipsv2.html`，然后通过 DOM 检查器深入渲染的代码，我们应该会看到类似于以下截图的内容：![扩展我们的插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00451.jpeg)

在这个例子中，我们添加了一个并不真正执行很多功能的方法；关键不是它做了什么，而是*我们如何添加它*。在这里，我们将其作为现有对象的附加方法提供。将以下内容添加到 `tooltipsv2.js` 的末尾：

```js
  $('#img-list li a.tooltips').on("mouseover", function() {
    $('#img-list li a.tooltips').quicktip.showDebug();
  })
```

如果现在刷新浏览器会话，我们可以在浏览器的 **控制台** 区域看到它的运行情况，如下一个截图所示：

![扩展我们的插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00452.jpeg)

我们可以做更多的事情，值得花时间在线研究。扩展的关键是确保您了解 `$.fn.extend` 和 `$.extend` 之间的区别。它们看起来可能相同，但请相信我 - 它们的作用是不同的！

# 使用 Bower 打包我们的插件

好了 - 在这个说明下，我们现在有一个可工作的插件，它已准备好使用。

此时，我们可以直接发布它，但明智的选择是将其打包以供像 Bower 或 NPM 这样的管理器使用。这样做的优点是下载并安装所有所需的包，而无需浏览到各个站点并手动下载每个版本。

### 提示

我们甚至可以进一步自动化我们的开发工作流程，使用诸如 Gulp 和 Grunt 这样的构建工具 - 有关如何的示例，请访问 [`www.codementor.io/bower/tutorial/beginner-tutorial-getting-started-bower-package-manager`](https://www.codementor.io/bower/tutorial/beginner-tutorial-getting-started-bower-package-manager)。

现在，让我们快速看一下自动创建 Bower 包的步骤：

1.  为了进行这个演示，我们需要安装 NodeJS。所以请访问 [`nodejs.org/`](http://nodejs.org/)，下载适当的二进制或包，并安装，接受所有默认设置。

1.  接下来，我们需要安装 Bower。启动已安装的 NodeJS 命令提示符，并在命令行输入以下内容：

    ```js
    npm install –g bower

    ```

1.  Bower 将通过一系列问题提示我们有关插件的信息，然后显示它将为我们创建的 `bower.json` 文件。在这个例子中，我使用了工具提示插件作为我们示例的基础。对于您创建并想要使用 Bower 分发的任何插件，相同的问题都将适用，如下图所示：![使用 Bower 打包我们的插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00453.jpeg)

1.  最后一步，确认我们对所创建的 `bower.json` 文件没有问题，就是在 Bower 中注册插件。在命令提示符下，运行以下命令：

    ```js
    bower register <name of plugin>

    ```

1.  Bower 将在最终确认插件可通过 Bower 使用之前经历多个阶段。

此时，我们将可提供插件供任何人下载。因为它必须链接到有效的 GitHub 帐户，我们现在可以将插件上传到这样的帐户，并通过 Bower 使其对任何人都可下载。作为奖励，我们现在可以利用 NodeJS 和 Grunt 来帮助自动化整个过程。不妨看看 grunt-bump（[`github.com/vojtajina/grunt-bump`](https://github.com/vojtajina/grunt-bump)），作为一个起点？

### 小贴士

Bower 还有很多我们无法在这里覆盖到的功能。为了获得灵感，不妨阅读[`bower.io/`](http://bower.io/)上的文档。

# 自动化文档的提供

发展我们的插件技能的最后阶段是提供文档。任何编码人员都可以生成文档，但更好的开发人员的标志是可以产生高质量的文档，而不必花费大量时间。

进入 JSDoc！它可从[`github.com/jsdoc3/jsdoc`](https://github.com/jsdoc3/jsdoc)获取。如果您尚未熟悉它，这是创建不仅外观良好而且可以轻松使用 Node 自动化的文档的好方法。让我们花点时间安装它，并看看它如何工作。需要执行以下步骤：

1.  这次我们将从使用 NodeJS 安装 JSDoc 开始。为此，我们需要打开一个 NodeJS 命令提示符；如果您使用 Windows 8，则可以在**程序**菜单中找到其图标，或者从**开始**页面找到。

1.  在命令提示符下，将位置更改到您的项目文件夹，然后输入以下命令：

    ```js
    npm install –g jsdoc

    ```

1.  在确认完成该过程之前，Node 将运行安装过程。

要生成文档，需要在我们的代码中输入注释，例如：

![自动化文档的提供](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00454.jpeg)

添加后，可以通过在插件文件夹中运行以下命令来编译文档：

```js
jsdoc <name of plugin>

```

我们会看到一个名为 out 的文件夹出现；里面包含了我们可以逐步建立的文档。如果我们对内联注释进行了更改，我们需要重新运行编译过程。这可以通过 Node 的`grunt-contrib-watch`插件来自动化。如果我们在 out 文件夹中看一下，就会看到文档出现。它会看起来类似于以下截图提取：

![自动化文档的提供](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00455.jpeg)

还有很多内容可以进行覆盖，以了解可以用来指导文档如何呈现的某些参数的感觉，不妨阅读[`usejsdoc.org/about-getting-started.html`](http://usejsdoc.org/about-getting-started.html)上的广泛文档。有很多可能性可供选择！

# 从我们的插件返回值

创建插件的关键部分是 - 我们能从插件中得到什么信息？有时我们无法从中获取信息，但这可能仅是我们试图通过插件实现的目标的局限性。在我们的情况下，我们应该能够获取内容。让我们看看如何使用我们的快速提示插件来实现这一点。

在深入代码之前，我们先来看一下我们要创建的东西：

![从我们的插件返回值](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00456.jpeg)

1.  我们需要从某个地方开始，所以最好的地方就是标记。在`tooltipv2.html`的副本中，在关闭`<div>`标签之前添加以下突出显示的代码：

    ```js
     <input type="submit" id="getValue" value="Get text from first tooltip" />
     <div id="dialog" title="Basic dialog">
      </div>
    ```

1.  在`tooltipv2.js`的副本中，我们需要暴露我们在标记中实现的`data-`标签。继续添加`tiptag`的配置选项，如下所示：

    ```js
    $(document).ready(function() {
      $('#img-list li a.tooltips').quicktip({
        class: 'arrow_box', tiptag: "title"
      });
    });
    ```

1.  这部分的最后一步是修改我们的标记。我们将使用`data-`标签替换标准的`title=""`标签，以提供更多的灵活性。在`tooltipv2.html`的副本中，搜索所有`title`的实例，然后用`data-title`替换它们。

1.  接下来，我们需要添加一个链接到 jQuery UI CSS 样式表中。这纯粹是为了创建一个对话框，显示我们从其中一个工具提示中获取文本的结果：

    ```js
    <link rel="stylesheet" type="text/css" 
    href="http://code.jquery.com/ui/1.10.4/themes/humanity/jquery-ui.css">
    <link rel="stylesheet" type="text/css" href="css/tooltipv2.css">
    ```

1.  要使 jQuery UI CSS 起作用，我们需要添加对 jQuery UI 库的引用。所以继续添加一个。为了方便起见，我们将使用 CDN 链接，但是在生产环境中，我们将考虑生成一个定制的缩小版本：

    ```js
    <script src="img/jquery-ui.js"> </script>
    <script src="img/jquery.quicktipv2.data.js"></script>
    ```

1.  在`tooltip.js`的副本中，删除其中的所有代码，并用以下代码替换：

    ```js
    $(document).ready(function() {
      $('#img-list li a.tooltips').quicktip({ 
        class: 'arrow_box', 
        tiptag: "title"
      });

      $('#getValue').on("click", function(event){
        var tipText = $('a.tooltips').eq(0).data().title;
        $("#dialog").text(tipText);
        $("#dialog").dialog({
          title: "Text from the first tooltip",
          modal: true,
          buttons: {
            Ok: function() { $(this).dialog("close"); }
          }
        });
      });
    });
    ```

1.  保存所有文件。如果我们切换到像 Firebug 这样的 DOM 检查器，我们可以看到通过输入第 6 步中突出显示的代码行返回的文本：![从我们的插件返回值](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00457.jpeg)

1.  在同一个浏览器会话中，单击**从第一个工具提示获取文本**按钮。如果一切正常，我们应该看到一个温和的覆盖效果出现，然后是一个对话框，显示在本练习开始时显示的文本。

诚然，我们的示例有点牵强，我们应该尽量不将获取文本的依赖硬编码在内，而是通过选择我们想要的任何工具提示中的文本来实现。关键在于，我们可以同样轻松地自定义用于文本的标签，并使用`.data()`方法检索该内容。

# 探索最佳实践和原则

在过去的几页中，我们已经涵盖了一些概念和技巧，可以帮助我们进一步发展插件技能。还有一些值得考虑的额外因素，我们还没有涵盖。值得花几分钟来探索这些因素：

+   **质量和代码风格**：你有考虑通过 JSHint ([`www.jshint.com`](http://www.jshint.com)) 或 JSLint ([`www.jslint.com`](http://www.jslint.com)) 对插件代码进行 linting 吗？遵循写 jQuery 最佳实践是确保成功的一种方式，比如遵循一致的代码风格或者在 [`contribute.jquery.org/style-guide/js/`](http://contribute.jquery.org/style-guide/js/) 上发布的指南？如果没有，那你的代码有多清理和可读？

+   **兼容性**：你的插件与哪个版本的 jQuery 兼容？这个库多年来已经进行了重大更改。你是打算提供对旧浏览器的支持（需要使用 1.x 分支的 jQuery），还是保持与更现代的浏览器兼容（使用库的 2.x 版本）？

+   **可靠性**：你应该考虑提供一组单元测试。这些测试可以帮助证明插件的工作情况，并且很容易产生。如果你想了解如何在 QUnit 中执行这些测试，可以看看 Dmitry Sheiko 编著的 *Instant Testing with QUnit*，这本书由 Packt Publishing 出版。

+   **性能**：一个运行速度慢的插件会让潜在用户望而却步。考虑使用 [JSPerf.com](http://JSPerf.com) ([`www.jsperf.com`](http://www.jsperf.com)) 作为测试段的基准，评估插件的工作情况以及是否需要进一步优化任何部分。

+   **文档**：给你的插件文档是必须的。文档的程度通常会决定插件的成功与失败。插件是否包含开发者需要了解的任何怪癖？它支持哪些方法和选项？如果代码有内联注释，那也会有帮助，虽然最好为生产使用提供一个压缩版本。如果开发人员可以很好地导航你的代码库来使用或改进它，那么你已经完成了一份不错的工作。

+   **维护**：如果我们发布一个东西到公众面前，就必须考虑支持机制。我们需要提供多少时间进行维护和支持？提前清楚地说明对问题的回答、解决问题和持续改进代码的期望是至关重要的。

哎呀 – 需要考虑的事情还真不少！创建一个插件可能会是一次有益的经历。希望这些建议能帮助你提高技能，使你成为更全面的开发者。记住，任何人都可以编写代码，就像我经常说的那样。成为更好的开发者的关键在于理解什么是一个好的插件，并知道如何付诸实践。

### 注意

Learn jQuery 网站有一些额外的提示值得探索，地址是 [`learn.jquery.com/plugins/advanced-plugin-concepts/`](http://learn.jquery.com/plugins/advanced-plugin-concepts/)。

# 摘要

如果有人问你学习 jQuery 的一个关键主题的名称，很可能插件会在答案中占据重要地位！为了帮助写作，我们在本章中涵盖了许多技巧和窍门。让我们花五分钟回顾一下我们学到的内容。

我们的起点是讨论如何检测开发不良的插件的迹象，作为学习如何通过使用插件模式来改进我们的开发的先导。然后，我们开始设计和构建一个高级插件，首先创建基本版本，然后重新排序以使用样板模板。

接下来我们详细研究了转换到使用 CSS3 动画，在书中早些时候我们讨论的一些论点，考虑到使用 CSS3 来更好地管理动画，而不是诉诸于 jQuery。

然后，我们开始研究如何在我们的插件中扩展功能，然后学习如何通过 Bower 打包它以便通过 GitHub 使用。然后我们涵盖了自动提供文档的功能，以及如何从我们的插件中返回值，最后总结了一些我们可以在开发中采用的最佳实践和原则。

好的 - 我们继续前进！在下一章中，我们将混合使用 jQuery（包括一些插件），HTML5 标记和 CSS，并制作一个网站。好的，没有什么特别的 - 那是非常正常的。但是，这里有一个转折：怎么样在*离线*状态下运行整个网站？是的，你没听错……离线……而且，看不到 USB 键或 DVD……
