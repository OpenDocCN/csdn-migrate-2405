# jQuery3 学习手册（四）

> 原文：[`zh.annas-archive.org/md5/B3EDC852976B517A1E8ECB0D0B64863C`](https://zh.annas-archive.org/md5/B3EDC852976B517A1E8ECB0D0B64863C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：高级事件

要构建交互式的 Web 应用程序，我们需要观察用户的活动并对其做出响应。 我们已经看到，jQuery 的事件系统可以简化此任务，而且我们已经多次使用了这个事件系统。

在第三章，*处理事件*，我们提到了 jQuery 提供的一些用于对事件做出反应的功能。 在这一更高级的章节中，我们将涵盖：

+   事件委托及其带来的挑战

+   与某些事件相关的性能陷阱以及如何解决它们

+   我们自己定义的自定义事件

+   jQuery 内部使用的特殊事件系统用于复杂的交互。

# 重新审视事件

对于我们的示例文档，我们将创建一个简单的照片画廊。 画廊将显示一组照片，并在点击链接时显示额外的照片。 我们还将使用 jQuery 的事件系统在鼠标悬停在照片上时显示每个照片的文本信息。 定义画廊的 HTML 如下所示：

```js
<div id="container"> 
  <h1>Photo Gallery</h1> 

  <div id="gallery"> 
    <div class="photo"> 
      <img src="img/skyemonroe.jpg"> 
      <div class="details"> 
        <div class="description">The Cuillin Mountains, 
          Isle of Skye, Scotland.</div> 
        <div class="date">12/24/2000</div> 
        <div class="photographer">Alasdair Dougall</div> 
      </div> 
    </div> 
    <div class="photo"> 
      <img src="img/dscn1328.jpg"> 
      <div class="details"> 
        <div class="description">Mt. Ruapehu in summer</div> 
        <div class="date">01/13/2005</div> 
        <div class="photographer">Andrew McMillan</div> 
      </div> 
    </div> 
    <div class="photo"> 
      <img src="img/024.JPG"> 
      <div class="details"> 
        <div class="description">midday sun</div> 
        <div class="date">04/26/2011</div> 
        <div class="photographer">Jaycee Barratt</div> 
      </div> 
    </div> 
    <!-- Code continues --> 
  </div> 
  <a id="more-photos" href="pages/1.html">More Photos</a> 
</div> 

```

获取示例代码

您可以从以下 GitHub 存储库访问示例代码：[`github.com/PacktPublishing/Learning-jQuery-3`](https://github.com/PacktPublishing/Learning-jQuery-3).

当我们对照片应用样式时，将它们排列成三行将使画廊看起来像以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_10_01.png)

# 加载更多数据页面

到目前为止，我们已经是对于页面元素点击的常见任务的专家了。当点击“更多照片”链接时，我们需要执行一个 Ajax 请求以获取下一组照片，并将它们附加到 `<div id="gallery">` 如下所示：

```js
$(() => {
  $('#more-photos')
    .click((e) => {
      e.preventDefault();
      const url = $(e.target).attr('href');

      $.get(url)
        .then((data) => {
          $('#gallery')
            .append(data);
        })
        .catch(({ statusText }) => {
          $('#gallery')
            .append(`<strong>${statusText}</strong>`)
        });
    });
});

```

列表 10.1

我们还需要更新“更多照片”链接的目标，以指向下一页照片：

```js
$(() => {
  var pageNum = 1;

  $('#more-photos')
    .click((e) => {
      e.preventDefault();
      const $link = $(e.target);
      const url = $link.attr('href');

      if (pageNum > 19) {
        $link.remove();
        return;
      }

      $link.attr('href', `pages/${++pageNum}.html`);

      $.get(url)
        .then((data) => {
          $('#gallery')
            .append(data);
        })
        .catch(({ statusText }) => {
          $('#gallery')
            .append(`<strong>${statusText}</strong>`)
        });
    });
});

```

列表 10.2

我们的 `.click()` 处理程序现在使用 `pageNum` 变量来跟踪要请求的下一页照片，并使用它来构建链接的新 `href` 值。 由于 `pageNum` 在函数外部定义，因此它的值在链接的点击之间保持不变。 当我们到达最后一页照片时，我们会删除该链接。

我们还应考虑使用 HTML5 历史记录 API，以允许用户标记我们加载的 Ajax 内容。 您可以在 Dive into HTML5 ([`diveintohtml5.info/history.html`](http://diveintohtml5.info/history.html)) 了解有关此 API 的信息，并使用 History 插件 ([`github.com/browserstate/history.js`](https://github.com/browserstate/history.js)) 很容易地实现它。

# 在悬停时显示数据

我们想要在此页面上提供的下一个功能是，当用户的鼠标位于页面的该区域时，显示与每张照片相关的详细信息。 对于显示此信息的首次尝试，我们可以使用 `.hover()` 方法：

```js
$(() => {
  $('div.photo')
    .hover((e) => {
      $(e.currentTarget)
        .find('.details')
        .fadeTo('fast', 0.7);
  }, (e) => {
      $(e.currentTarget)
        .find('.details')
        .fadeOut('fast');
  });
}); 

```

列表 10.3

当光标进入照片的边界时，相关信息以 70% 的不透明度淡入，当光标离开时，信息再次淡出：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_10_02.png)

当然，执行此任务的方法有多种。由于每个处理程序的一部分是相同的，因此可以将两个处理程序合并。我们可以通过用空格分隔事件名称来同时绑定处理程序到`mouseenter`和`mouseleave`，如下所示：

```js
 $('div.photo')
   .on('mouseenter mouseleave', (e) => {
     const $details = $(e.currentTarget).find('.details');

     if (e.type == 'mouseenter') {
       $details.fadeTo('fast', 0.7);
     } else {
       $details.fadeOut('fast');
     }
   });

```

列表 10.4

对于两个事件都绑定了相同处理程序，我们检查事件的类型以确定是淡入还是淡出详情。然而，定位`<div>`的代码对于两个事件是相同的，因此我们可以只写一次。

坦率地说，这个例子有点做作，因为此示例中的共享代码如此简短。但是，在其他情况下，这种技术可以显著减少代码复杂性。例如，如果我们选择在`mouseenter`上添加一个类，并在`mouseleave`上删除它，而不是动画化透明度，我们可以在处理程序内部用一个语句解决它，如下所示：

```js
$(e.currentTarget)
  .find('.details') 
  .toggleClass('entered', e.type == 'mouseenter'); 

```

无论如何，我们的脚本现在正在按预期工作，除了我们还没有考虑用户点击更多照片链接时加载的附加照片。正如我们在第三章中所述，*处理事件*，事件处理程序仅附加到在我们进行`.on()`调用时存在的元素上。稍后添加的元素，例如来自 Ajax 调用的元素，不会具有行为。我们看到解决此问题的两种方法是在引入新内容后重新绑定事件处理程序，或者最初将处理程序绑定到包含元素并依赖事件冒泡。第二种方法，*事件委托*，是我们将在这里追求的方法。

# 事件委托

请记住，为了手动实现事件委托，我们会检查事件对象的`target`属性，以查看它是否与我们想要触发行为的元素匹配。事件目标表示接收事件的最内部或最深嵌套的元素。然而，这次我们的示例 HTML 提出了一个新的挑战。`<div class="photo">`元素不太可能是事件目标，因为它们包含其他元素，比如图像本身和图像详情。

我们需要的是`.closest()`方法，它会从父级元素向上遍历 DOM，直到找到与给定选择器表达式匹配的元素为止。如果找不到任何元素，则它会像任何其他 DOM 遍历方法一样，返回一个新的空 jQuery 对象。我们可以使用`.closest()`方法从任何包含它的元素中找到`<div class="photo">`，如下所示：

```js
$(() => { 
  $('#gallery')
    .on('mouseover mouseout', (e) => {
      const $target = $(e.target)
        .closest('div.photo');
      const $related = $(e.relatedTarget)
        .closest('div.photo');
      const $details = $target
        .find('.details');

      if (e.type == 'mouseover' && $target.length) {
        $details.fadeTo('fast', 0.7);
      } else if (e == 'mouseout' && !$related.length) {
        $details.fadeOut('fast');
      }
    });
}); 

```

列表 10.5

请注意，我们还需要将事件类型从`mouseenter`和`mouseleave`更改为`mouseover`和`mouseout`，因为前者仅在鼠标首次进入画廊`<div>`并最终离开时触发，我们需要处理程序在鼠标进入该包装`<div>`内的任何照片时被触发。但后者引入了另一种情况，即除非我们包含对`event`对象的`relatedTarget`属性的附加检查，否则详细信息`<div>`将重复淡入和淡出。即使有了额外的代码，快速重复的鼠标移动到照片上和移出照片时的处理也不令人满意，导致偶尔会出现详细信息`<div>`可见，而应该淡出。

# 使用 jQuery 的委托能力

当任务变得更加复杂时，手动管理事件委托可能会非常困难。幸运的是，jQuery 的`.on()`方法内置了委托，这可以使我们的生活变得更加简单。利用这种能力，我们的代码可以回到*第 10.4 编列*的简洁性：

```js
$(() => { 
  $('#gallery')
    .on('mouseenter mouseleave', 'div.photo', (e) => {
      const $details = $(e.currentTarget).find('.details');

      if (e.type == 'mouseenter') {
        $details.fadeTo('fast', 0.7);
      } else {
        $details.fadeOut('fast');
      }
    });
}); 

```

第 10.6 编列

选择器`#gallery`与*第 10.5 编列*保持不变，但事件类型返回到*第 10.4 编列*的`mouseenter`和`mouseleave`。当我们将`'div.photo'`作为`.on()`的第二个参数传入时，jQuery 将`e.currentTarget`映射到`'#gallery'`中与该选择器匹配的元素。

# 选择委托范围

因为我们处理的所有照片元素都包含在`<div id="gallery">`中，所以我们在上一个示例中使用了`#gallery`作为我们的委托范围。然而，任何一个所有照片的祖先元素都可以用作这个范围。例如，我们可以将处理程序绑定到`document`，这是页面上所有内容的公共祖先：

```js
$(() => {
  $(document)
    .on('mouseenter mouseleave', 'div.photo', (e) => {
      const $details = $(e.currentTarget).find('.details');

      if (e.type == 'mouseenter') {
        $details.fadeTo('fast', 0.7);
      } else {
        $details.fadeOut('fast');
      }
    });
}); 

```

第 10.7 编列

在设置事件委托时，将事件处理程序直接附加到`document`可能会很方便。由于所有页面元素都是从`document`继承而来的，我们不需要担心选择正确的容器。但是，这种便利可能会带来潜在的性能成本。

在深度嵌套的元素 DOM 中，依赖事件冒泡直到多个祖先元素可能是昂贵的。无论我们实际观察的是哪些元素（通过将它们的选择器作为`.on()`的第二个参数传递），如果我们将处理程序绑定到`document`，那么页面上发生的任何事件都需要被检查。例如，在*第 10.6 编列*中，每当鼠标进入页面上的任何元素时，jQuery 都需要检查它是否进入了一个`<div class="photo">`元素。在大型页面上，这可能会变得非常昂贵，特别是如果委托被大量使用。通过在委托上下文中更加具体，可以减少这种工作。

# 早期委托

尽管存在这些效率问题，但仍有理由选择将`document`作为我们的委托上下文。一般来说，我们只能在 DOM 元素加载后绑定事件处理程序，这就是为什么我们通常将代码放在`$(() => {})`内的原因。但是，`document`元素是立即可用的，因此我们无需等待整个 DOM 准备就绪才能绑定它。即使脚本被引用在文档的`<head>`中，就像我们的示例中一样，我们也可以立即调用`.on()`，如下所示：

```js
(function($) { 
  $(document)
    .on('mouseenter mouseleave', 'div.photo', (e) => {
      const $details = $(e.currentTarget).find('.details');

      if (e.type == 'mouseenter') {
        $details.fadeTo('fast', 0.7);
      } else {
        $details.fadeOut('fast');
      }
    }); 
})(jQuery); 

```

图 10.8

因为我们不是在等待整个 DOM 准备就绪，所以我们可以确保`mouseenter`和`mouseleave`行为将立即适用于所有页面上呈现的`<div class="photo">`元素。

要看到这种技术的好处，考虑一个直接绑定到链接的`click`处理程序。假设此处理程序执行某些操作，并且还阻止链接的默认操作（导航到另一个页面）。如果我们等待整个文档准备就绪，我们将面临用户在处理程序注册之前单击该链接的风险，从而离开当前页面而不是得到脚本提供的增强处理。相比之下，将委托事件处理程序绑定到`document`使我们能够在不必扫描复杂的 DOM 结构的情况下提前绑定事件。

# 定义自定义事件

浏览器的 DOM 实现自然触发的事件对于任何交互式 Web 应用程序都至关重要。但是，在我们的 jQuery 代码中，我们不仅限于此事件集合。我们还可以添加自己的自定义事件。我们在第八章中简要介绍了这一点，*开发插件*，当我们看到 jQuery UI 小部件如何触发事件时，但在这里，我们将研究如何创建和使用自定义事件，而不是插件开发。

自定义事件必须由我们的代码手动触发。从某种意义上说，它们就像我们定义的常规函数一样，我们可以在脚本的另一个地方调用它时执行一块代码。对于自定义事件的`.on()`调用的行为类似于函数定义，而`.trigger()`调用的行为类似于函数调用。

但是，事件处理程序与触发它们的代码是解耦的。这意味着我们可以在任何时候触发事件，而无需预先知道触发时会发生什么。常规函数调用会导致执行单个代码块。但是，自定义事件可能没有处理程序，一个处理程序或许多处理程序绑定到它。无论如何，当事件被触发时，所有绑定的处理程序都将被执行。

为了说明这一点，我们可以修改我们的 Ajax 加载功能以使用自定义事件。每当用户请求更多照片时，我们将触发一个`nextPage`事件，并绑定处理程序来监视此事件并执行以前由`.click()`处理程序执行的工作：

```js
$(() => { 
  $('#more-photos')
    .click((e) => {
      e.preventDefault();
      $(e.target).trigger('nextPage');
    });
}); 

```

列表 10.9

`.click()` 处理程序现在几乎不做任何工作。它触发自定义事件，并通过调用 `.preventDefault()` 阻止默认的链接行为。重要的工作转移到了对 `nextPage` 事件的新事件处理程序中，如下所示：

```js
(($) => { 
  $(document)
    .on('nextPage', (e) => {
      $.get($(e.target).attr('href'))
        .then((data) => {
          $('#gallery')
            .append(data);
        })
        .catch(({ statusText }) => {
          $('#gallery')
            .append(`<strong>${statusText}</strong>`)
        });
    });

  var pageNum = 1;

  $(document)
    .on('nextPage', () => {
      if (pageNum > 19) {
        $('#more-photos').remove();
        return;
      }

      $('#more-photos')
        .attr('href', `pages/${++pageNum}.html`);
    });
})(jQuery); 

```

列表 10.10

自从 *列表 10.2* 以来，我们的代码并没有太多改变。最大的区别在于，我们将曾经的单个函数拆分为两个。这只是为了说明单个事件触发器可以导致多个绑定的处理程序触发。单击“更多照片”链接会导致下一组图片被追加，并且链接的 `href` 属性会被更新，如下图所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_10_001-1.jpg)

随着 *列表 10.10* 中的代码更改，我们还展示了事件冒泡的另一个应用。 `nextPage` 处理程序可以绑定到触发事件的链接上，但我们需要等到 DOM 准备就绪才能这样做。相反，我们将处理程序绑定到文档本身，这个文档立即可用，因此我们可以在 `$(() => {})` 外部进行绑定。这实际上是我们在 *列表 10.8* 中利用的相同原理，当我们将 `.on()` 方法移到了 `$(() => {})` 外部时。事件冒泡起作用，只要另一个处理程序不停止事件传播，我们的处理程序就会被触发。

# 无限滚动

正如多个事件处理程序可以对同一触发的事件作出反应一样，同一事件可以以多种方式触发。我们可以通过为页面添加无限滚动功能来演示这一点。这种技术允许用户的滚动条管理内容的加载，在用户达到到目前为止已加载内容的末尾时，获取更多内容。

我们将从一个简单的实现开始，然后在后续示例中改进它。基本思想是观察 `scroll` 事件，测量滚动时的当前滚动条位置，并在需要时加载新内容。以下代码将触发我们在 *列表 10.10* 中定义的 `nextPage` 事件：

```js
(($) => { 
  const checkScrollPosition = () => {
    const distance = $(window).scrollTop() +
      $(window).height();

    if ($('#container').height() <= distance) {
      $(document).trigger('nextPage');
    }
  }

  $(() => {
    $(window)
      .scroll(checkScrollPosition)
      .trigger('scroll');
  }); 
})(jQuery); 

```

列表 10.11

我们在这里介绍的 `checkScrollPosition()` 函数被设置为窗口 `scroll` 事件的处理程序。此函数计算文档顶部到窗口底部的距离，然后将此距离与文档中主容器的总高度进行比较。一旦它们达到相等，我们就需要用额外的照片填充页面，因此我们触发 `nextPage` 事件。

一旦我们绑定了 `scroll` 处理程序，我们立即通过调用 `.trigger('scroll')` 触发它。这启动了这个过程，因此如果页面最初未填充照片，则立即进行 Ajax 请求以附加更多照片：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_10_002-1.jpg)

# 自定义事件参数

当我们定义函数时，我们可以设置任意数量的参数，以在实际调用函数时填充参数值。同样，当触发自定义事件时，我们可能想向任何注册的事件处理程序传递额外信息。我们可以通过使用自定义事件参数来实现这一点。

任何事件处理程序定义的第一个参数，正如我们所见，是 DOM 事件对象，由 jQuery 增强和扩展。我们定义的任何额外参数都可供自行决定使用。

要看到此功能的实际效果，我们将在 *清单 10.10* 的`nextPage`事件中添加一个新选项，允许我们向下滚动页面以显示新添加的内容：

```js
(($) => { 
  $(document)
    .on('nextPage', (e, scrollToVisible) => {
      if (pageNum > 19) {
        $('#more-photos').remove();
        return;
      }

      $.get($('#more-photos').attr('href'))
        .then((data) => {
          const $data = $('#gallery')
            .append(data);

          if (scrollToVisible) {
            $(window)
              .scrollTop($data.offset().top);
          }

          checkScrollPosition();
    })
    .catch(({ statusText }) => {
      $('#gallery')
        .append(`<strong>${statusText}</strong>`)
    });
  }); 
})(jQuery); 

```

清单 10.12

现在，我们已经为事件回调添加了一个`scrollToVisible`参数。该参数的值决定了我们是否执行新功能，该功能包括测量新内容的位置并滚动到该位置。使用`.offset()`方法来进行测量非常容易，该方法返回新内容的顶部和左侧坐标。要向页面下移，我们调用`.scrollTop()`方法。

现在，我们需要向新参数传递一个参数。所需的一切就是在使用`.trigger()`调用事件时提供额外的值。当通过滚动触发`newPage`时，我们不希望出现新行为，因为用户已经直接操作了滚动位置。另一方面，当点击更多照片链接时，我们希望新添加的照片显示在屏幕上，因此我们将一个值为`true`传递给处理程序：

```js
$(() => { 
  $('#more-photos')
    .click((e) => {
      e.preventDefault();
      $(e.target).trigger('nextPage', [true]);
    });
}); 

```

清单 10.13

在调用`.trigger()`时，我们现在提供了一个值数组以传递给事件处理程序。在这种情况下，值`true`将被传递到 *清单 10.12* 中事件处理程序的`scrollToVisible`参数。

请注意，自定义事件参数在交易的双方都是可选的。我们的代码中有两个对`.trigger('nextPage')`的调用，其中只有一个提供了参数值；当调用另一个时，这不会导致错误，而是处理程序中的每个参数都具有值`undefined`。同样，一个`.on('nextPage')`调用中缺少`scrollToVisible`参数也不是错误；如果在传递参数时不存在参数，那么该参数将被简单地忽略。

# 事件节流

我们在 *清单 10.10* 中实现的无限滚动功能的一个主要问题是性能影响。虽然我们的代码很简洁，但`checkScrollPosition()`函数确实需要做一些工作来测量页面和窗口的尺寸。这种努力可能会迅速积累，因为在一些浏览器中，`scroll`事件在滚动窗口时会重复触发。这种组合的结果可能是不流畅或性能低下。

几个本地事件有可能频繁触发。常见的罪魁祸首包括 `scroll`、`resize` 和 `mousemove`。为了解决这个问题，我们将实现**事件节流**。这种技术涉及限制我们的昂贵计算，使其仅在一些事件发生之后才发生，而不是每次都发生。我们可以更新我们的代码，以实现这种技术，如下所示：

```js
$(() => { 
  var timer = 0;

  $(window)
    .scroll(() => {
      if (!timer) {
        timer = setTimeout(() => {
          checkScrollPosition();
          timer = 0;
        }, 250);
      }
    })
    .trigger('scroll');
}); 

```

清单 10.14

我们不直接将 `checkScrollPosition()` 设置为 `scroll` 事件处理程序，而是使用 JavaScript 的 `setTimeout` 函数将调用推迟了 `250` 毫秒。更重要的是，在做任何工作之前，我们首先检查是否有正在运行的计时器。由于检查一个简单变量的值非常快，我们的大多数事件处理程序调用几乎立即返回。`checkScrollPosition()` 调用只会在定时器完成时发生，最多每 250 毫秒一次。

我们可以轻松调整 `setTimeout()` 的值，以达到舒适的数值，从而在即时反馈和低性能影响之间取得合理的折中。我们的脚本现在是一个良好的网络公民。

# 其他执行节流的方式

我们实施的节流技术既高效又简单，但这并不是唯一的解决方案。根据节流的操作的性能特征和与页面的典型交互，我们可能需要建立页面的单个定时器，而不是在事件开始时创建一个定时器：

```js
$(() => { 
  var scrolled = false;

  $(window)
    .scroll(() => {
      scrolled = true;
    });

  setInterval(() => {
    if (scrolled) {
      checkScrollPosition();
      scrolled = false;
    }
  }, 250);

  checkScrollPosition();
}); 

```

清单 10.15

与我们以前的节流代码不同，这种轮询解决方案使用一次 JavaScript `setInterval()` 函数调用来开始每`250`毫秒检查 `scrolled` 变量的状态。每次发生滚动事件时，`scrolled` 被设置为 `true`，确保下次间隔经过时将调用 `checkScrollPosition()`。其结果类似于*清单 10.14*。

限制在频繁重复事件期间执行的处理量的第三种解决方案是**去抖动**。这种技术以电子开关发送的重复信号需要处理后的名字命名，确保即使发生了很多事件，也只有一个单一的最终事件被执行。我们将在第十三章*高级 Ajax*中看到这种技术的示例。

# 扩展事件

一些事件，如 `mouseenter` 和 `ready`，被 jQuery 内部指定为**特殊事件**。这些事件使用 jQuery 提供的复杂事件扩展框架。这些事件有机会在事件处理程序的生命周期中的各个时刻采取行动。它们可能会对绑定或解绑的处理程序做出反应，甚至可以有可阻止的默认行为，如点击链接或提交表单。事件扩展 API 允许我们创建类似于本机 DOM 事件的复杂新事件。

我们为*Listing 10.13*中的滚动实现的节流行为是有用的，我们可能想要将其推广到其他项目中使用。我们可以通过在特殊事件钩子内封装节流技术来实现这一点。

要为事件实现特殊行为，我们向`$ .event.special`对象添加一个属性。这个添加的属性本身是一个对象，它的键是我们的事件名称。它可以包含在事件生命周期中许多不同特定时间调用的回调函数，包括以下内容：

+   `add`: 每当为该事件的处理程序绑定时调用

+   `remove`: 每当为事件的处理程序解绑时调用

+   `setup`: 当为事件绑定处理程序时调用，但仅当没有为元素绑定该事件的其他处理程序时

+   `teardown`: 这是`setup`的反义词，当从元素解绑事件的最后一个处理程序时调用

+   `_default`: 这将成为事件的默认行为，在事件处理程序阻止默认操作之前调用

这些回调函数可以以一些非常有创意的方式使用。一个相当普遍的情景，我们将在我们的示例代码中探讨，就是根据浏览器条件自动触发事件。如果没有处理程序监听事件，监听状态并触发事件是很浪费的，所以我们可以使用`setup`回调仅在需要时启动这项工作：

```js
(($) => { 
  $.event.special.throttledScroll = { 
    setup(data) { 
      var timer = 0; 
      $(this).on('scroll.throttledScroll', () => { 
        if (!timer) { 
          timer = setTimeout(() => { 
            $(this).triggerHandler('throttledScroll'); 
            timer = 0; 
          }, 250); 
        } 
      }); 
    }, 
    teardown() { 
      $(this).off('scroll.throttledScroll'); 
    } 
  }; 
})(jQuery); 

```

Listing 10.16

对于我们的滚动节流事件，我们需要绑定一个常规的`scroll`处理程序，该处理程序使用与我们在*Listing 10.14*中开发的相同的`setTimeout`技术。每当计时器完成时，将触发自定义事件。由于我们每个元素只需要一个计时器，因此`setup`回调将满足我们的需求。通过为`scroll`处理程序提供自定义命名空间，我们可以在调用`teardown`时轻松地移除处理程序。

要使用这种新行为，我们只需为`throttledScroll`事件绑定处理程序。这极大地简化了事件绑定代码，并为我们提供了一个非常可重用的节流机制，如下所示：

```js
(($) => {
  $.event.special.throttledScroll = {
    setup(data) {
      var timer = 0;
      $(this)
        .on('scroll.throttledScroll', () => {
          if (!timer) {
            timer = setTimeout(() => {
              $(this).triggerHandler('throttledScroll');
              timer = 0;
            }, 250);
          }
        });
    },
    teardown() {
      $(this).off('scroll.throttledScroll');
    }
  };

  $(document)
    .on('mouseenter mouseleave', 'div.photo', (e) => {
      const $details = $(e.currentTarget).find('.details');

      if (e.type == 'mouseenter') {
        $details.fadeTo('fast', 0.7);
      } else {
        $details.fadeOut('fast');
      }
    });

  var pageNum = 1;

  $(document)
    .on('nextPage', (e, scrollToVisible) => {
      if (pageNum > 19) {
        $('#more-photos').remove();
        return;
      }

      $.get($('#more-photos').attr('href'))
        .then((data) => {
          const $data = $(data)
            .appendTo('#gallery');

          if (scrollToVisible) {
            $(window)
              .scrollTop($data.offset().top);
          }

          checkScrollPosition();
        })
       .catch(({ statusText }) => {
         $('#gallery')
           .append(`<strong>${statusText}</strong>`)
       });
    });

    $(document)
      .on('nextPage', () => {
        if (pageNum < 20) {
          $('#more-photos')
            .attr('href', `pages/${++pageNum}.html`);
        }
      });

    const checkScrollPosition = () => {
      const distance = $(window).scrollTop()
        + $(window).height();

      if ($('#container').height() <= distance) {
        $(document).trigger('nextPage');
      }
    };

  $(() => {
    $('#more-photos')
      .click((e) => {
        e.preventDefault();
        $(e.target).trigger('nextPage', [true]);
      });

    $(window)
      .on('throttledScroll', checkScrollPosition)
      .trigger('throttledScroll');
  });
})(jQuery);

```

Listing 10.17

# 关于特殊事件的更多信息

虽然本章涵盖了处理事件的高级技术，但事件扩展 API 确实非常先进，详细的调查超出了本书的范围。前面的`throttledScroll`示例涵盖了该功能的最简单和最常见的用法。其他可能的应用包括以下内容：

+   修改事件对象，以便事件处理程序可以获得不同的信息

+   导致在 DOM 中的一个位置发生的事件触发与不同元素相关联的行为

+   对不是标准 DOM 事件的新的和特定于浏览器的事件做出反应，并允许 jQuery 代码对其做出反应，就像它们是标准的一样

+   改变事件冒泡和委托的处理方式

这些任务中的许多都可能非常复杂。要深入了解事件扩展 API 提供的可能性，我们可以查阅 jQuery 学习中心的文档[`learn.jquery.com/events/event-extensions/`](http://learn.jquery.com/events/event-extensions/)。

# 总结

如果我们选择充分利用 jQuery 事件系统，它可以非常强大。在本章中，我们已经看到了系统的几个方面，包括事件委托方法、自定义事件和事件扩展 API。我们还找到了绕过委托和频繁触发事件相关问题的方法。

# 进一步阅读

本书的附录 B，*快速参考*中提供了完整的事件方法列表，或者在官方的*jQuery 文档*中查看[`api.jquery.com/`](http://api.jquery.com/)。

# 练习

以下挑战练习可能需要使用官方 jQuery 文档[`api.jquery.com/`](http://api.jquery.com/)。

1.  当用户点击照片时，在照片`<div>`上添加或删除`selected`类。确保即使是使用下一页链接后添加的照片，这种行为也能正常工作。

1.  添加一个名为`pageLoaded`的新自定义事件，当新的图像集已添加到页面上时触发。

1.  使用`nextPage`和`pageLoaded`处理程序，仅在加载新页面时在页面底部显示一个加载消息。

1.  将一个`mousemove`处理程序绑定到照片上，记录当前鼠标位置（使用`console.log()`）。

1.  修改此处理程序，以使日志记录不超过每秒五次。

1.  挑战：创建一个名为`tripleclick`的新特殊事件，当鼠标按钮在 500 毫秒内点击三次时触发。为了测试该事件，将一个`tripleclick`处理程序绑定到`<h1>`元素上，该处理程序隐藏和显示`<div id="gallery">`的内容。


# 第十一章：高级效果

自从了解了 jQuery 的动画功能以来，我们发现了许多用途。我们可以轻松地隐藏和显示页面上的对象，我们可以优雅地调整元素的大小，我们可以平滑地重新定位元素。这个效果库是多功能的，包含的技术和专业能力甚至比我们迄今看到的还要多。

在第四章中，*样式和动画*，您学习了 jQuery 的基本动画功能。在这个更高级的章节中，我们将涵盖：

+   收集关于动画状态的信息的方法

+   中断活动动画的方法

+   全局效果选项，可以一次性影响页面上的所有动画

+   Deferred 对象允许我们在动画完成后执行操作

+   缓动，改变动画发生的速率

# 动画再访

为了刷新我们关于 jQuery 效果方法的记忆，我们将在本章中建立一个基线，从一个简单的悬停动画开始构建。使用带有照片缩略图的文档，当用户的鼠标悬停在上面时，我们将使每张照片略微*增大*，并在鼠标离开时恢复到原始大小。我们将使用的 HTML 标签目前还包含一些暂时隐藏的文本信息，稍后在本章中将使用：

```js
<div class="team"> 
  <div class="member"> 
    <img class="avatar" src="img/rey.jpg" alt="" /> 
    <div class="name">Rey Bango</div> 
    <div class="location">Florida</div> 
    <p class="bio">Rey Bango is a consultant living in South Florida,        
    specializing in web application development...</p> 
  </div> 
  <div class="member"> 
    <img class="avatar" src="img/scott.jpg" alt="" /> 
    <div class="name">Scott González</div> 
    <div class="location">North Carolina</div> 
    <div class="position">jQuery UI Development Lead</div> 
    <p class="bio">Scott is a web developer living in Raleigh, NC...       </p> 
  </div> 
  <!-- Code continues ... --> 
</div> 

```

获取示例代码

您可以从以下 GitHub 存储库访问示例代码：[`github.com/PacktPublishing/Learning-jQuery-3`](https://github.com/PacktPublishing/Learning-jQuery-3)。

每张图像相关联的文本最初由 CSS 隐藏，通过将每个 `<div>` 移动到其 `overflow: hidden` 容器的左侧来实现：

```js
.member { 
  position: relative; 
  overflow: hidden; 
} 

.member div { 
  position: absolute; 
  left: -300px; 
  width: 250px; 
} 

```

HTML 和 CSS 一起产生一个垂直排列的图像列表：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_11_01.png)

为了改变图像的大小，我们将把其高度和宽度从 `75` 像素增加到 `85` 像素。同时，为了保持图像居中，我们将其填充从 `5` 像素减少到 `0` 像素：

```js
$(() => {
  $('div.member')
    .on('mouseenter mouseleave', ({ type, target }) => {
      const width = height = type == 'mouseenter' ?
        85 : 75;
      const paddingTop = paddingLeft = type == 'mouseenter' ?
        0 : 5;

      $(target)
        .find('img')
        .animate({
          width,
          height,
          paddingTop,
          paddingLeft
        });
    });
}); 

```

清单 11.1

在这里，我们重复了我们在第十章中看到的一种模式，*高级事件*，因为当鼠标进入区域时，我们执行的大部分工作与离开时相同；我们将 `mouseenter` 和 `mouseleave` 的处理程序合并为一个函数，而不是使用两个单独的回调调用 `.hover()`。在这个处理程序内部，我们根据触发的两个事件中的哪一个来确定 `size` 和 `padding` 的值，并将这些属性值传递给 `.animate()` 方法。

当您看到将对象字面量表示法包围在函数参数 `({ type, target})` 周围时，这被称为**对象解构**。这只是一种方便的方法，可以从事件对象中获取我们需要的确切属性，从而在函数本身中编写更简洁的代码。

现在当鼠标光标位于图像上时，它比其他图像稍大：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_11_02.png)

# 观察和中断动画

我们的基本动画已经显示出一个问题。只要每次`mouseenter`或`mouseleave`事件后有足够的时间完成动画，动画就会按预期进行。然而，当鼠标光标快速移动并且事件被快速触发时，我们会看到图像在最后一个事件被触发后仍然反复变大和缩小。这是因为，如第四章所述，给定元素上的动画被添加到队列中并按顺序调用。第一个动画立即调用，按分配的时间完成，然后从队列中移除，此时下一个动画变为队列中的第一个，被调用，完成，被移除，依此类推，直到队列为空。

有许多情况下，jQuery 中称为`fx`的动画队列会引起期望的行为。但在我们这样的悬停动作中，需要绕过它。

# 确定动画状态

避免动画不良排队的一种方法是使用 jQuery 的自定义`:animated`选择器。在`mouseenter`/`mouseleave`事件处理程序中，我们可以使用该选择器来检查图像并查看它是否正在动画中：

```js
$(() => {
  $('div.member')
    .on('mouseenter mouseleave', ({ type, target }) => {
      const width = height = type == 'mouseenter' ?
        85 : 75;
      const paddingTop = paddingLeft = type == 'mouseenter' ?
        0 : 5;

      $(target)
        .find('img')
        .not(':animated')
        .animate({
          width,
          height,
          paddingTop,
          paddingLeft
        });
      });
});

```

清单 11.2

当用户的鼠标进入成员`<div>`时，图像只有在没有被动画化时才会进行动画。当鼠标离开时，动画将无论其状态如何都会发生，因为我们始终希望最终将图像恢复到其原始尺寸和填充状态。

我们成功地避免了在*清单 11.1*中发生的无限动画，但是动画仍然需要改进。当鼠标快速进入和离开`<div>`标记时，图像仍然必须完成整个`mouseenter`动画（增大）才会开始`mouseleave`动画（缩小）。这肯定不是理想的情况，但是`:animated`伪类的测试引入了一个更大的问题：如果鼠标在图像*缩小*时进入`<div>`标记，那么图像将无法再次增大。只有在动画停止后，下一个`mouseleave`和`mouseenter`动画才会执行另一个动画。在某些情况下使用`:animated`选择器可能很有用，但在这里并没有帮助太多。

# 停止运行的动画

幸运的是，jQuery 有一个方法可以帮助我们解决*清单 11.2*中显而易见的两个问题。`.stop()`方法可以立即停止动画。要使用它，我们可以将代码恢复到*清单 11.1*中的样子，然后在`.find()`和`.animate()`之间简单地插入`.stop()`：

```js
$(() => {
  $('div.member')
    .on('mouseenter mouseleave', ({ type, currentTarget }) => {
      const width = height = type == 'mouseenter' ?
        85 : 75;
      const paddingTop = paddingLeft = type == 'mouseenter' ?
        0 : 5;

      $(currentTarget)
        .find('img')
        .stop()
        .animate({
          width,
          height,
          paddingTop,
          paddingLeft
        });
    });
});

```

清单 11.3

值得注意的是，在进行新动画之前我们会在当前动画*之前*停止它。现在当鼠标重复进入和离开时，我们之前尝试的不良效果消失了。当前动画总是立即完成，因此`fx`队列中永远不会超过一个。当鼠标最终停下时，最终动画完成，因此图像要么完全增长（`mouseenter`），要么恢复到其原始尺寸（`mouseleave`），这取决于最后触发的事件。

# 停止动画时要小心

由于`.stop()`方法默认在当前位置停止动画，当与速记动画方法一起使用时可能会导致意外结果。在动画之前，这些速记方法确定最终值，然后对该值进行动画处理。例如，如果在其动画过程中使用`.stop()`停止`.slideDown()`，然后调用`.slideUp()`，那么下一次在元素上调用`.slideDown()`时，它只会滑动到上次停止的高度。为了减轻这种问题，`.stop()`方法可以接受两个布尔值（`true`/`false`）参数，第二个称为`goToEnd`。如果我们将此参数设置为`true`，则当前动画不仅停止，而且立即跳转到最终值。尽管如此，`goToEnd`功能可能会使动画看起来*不流畅*，因此更好的解决方案可能是将最终值存储在变量中，并显式地使用`.animate()`进行动画处理，而不是依赖 jQuery 来确定该值。

另一个 jQuery 方法`.finish()`可用于停止动画。它类似于`.stop(true, true)`，因为它清除所有排队的动画，并将当前动画跳转到最终值。但是，与`.stop(true, true)`不同，它还会将所有*排队的*动画跳转到它们的最终值。

# 使用全局效果属性

jQuery 中的效果模块包含一个方便的`$.fx`对象，当我们想要全面改变动画特性时可以访问该对象。虽然该对象的一些属性未记录，并且只能在库内部使用，但其他属性则作为工具提供，用于全局改变动画运行方式。在以下示例中，我们将看一些已记录属性。

# 禁用所有效果

我们已经讨论了如何停止当前正在运行的动画，但是如果我们需要完全禁用所有动画怎么办？例如，我们可能希望默认情况下提供动画，但是在低资源设备（动画可能看起来断断续续）或对于发现动画分散注意力的用户中禁用这些动画。为此，我们只需将`$.fx.off`属性设置为`true`。为了演示，我们将显示一个之前隐藏的按钮，以允许用户切换动画的开启和关闭：

```js
$(() => {
  $('#fx-toggle')
    .show()
    .on('click', () => {
      $.fx.off = !$.fx.off;
    });
}); 

```

列表 11.4

隐藏按钮显示在介绍段落和随后的图像之间：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_11_03.png)

当用户点击按钮将动画切换关闭时，随后的动画，如我们的放大和缩小图像，将立即发生（持续时间为`0`毫秒），然后立即调用任何回调函数。

# 定义效果持续时间

`$.fx`对象的另一个属性是`speeds`。该属性本身是一个对象，由 jQuery 核心文件证实，由三个属性组成：

```js
speeds: { 
  slow: 600, 
  fast: 200, 
  // Default speed 
  _default: 400 
} 

```

您已经学会了 jQuery 的所有动画方法都提供了一个可选的速度或持续时间参数。查看`$.fx.speeds`对象，我们可以看到字符串`slow`和`fast`分别映射到 600 毫秒和 200 毫秒。每次调用动画方法时，jQuery 按照以下顺序执行以下步骤来确定效果的持续时间：

1.  它检查`$.fx.off`是否为`true`。如果是，它将持续时间设置为`0`。

1.  它检查传递的持续时间是否为数字。如果是，则将持续时间设置为该数字的毫秒数。

1.  它检查传递的持续时间是否匹配`$.fx.speeds`对象的属性键之一。如果是，则将持续时间设置为属性的值。

1.  如果持续时间未由上述任何检查设置，则将持续时间设置为`$.fx.speeds._default`的值。

综合这些信息，我们现在知道，传递除`slow`或`fast`之外的任何字符串持续时间都会导致持续时间为 400 毫秒。我们还可以看到，添加我们自己的自定义速度就像添加另一个属性到`$.fx.speeds`一样简单。例如，如果我们写`$.fx.speeds.crawl = 1200`，我们可以在任何动画方法的速度参数中使用`'crawl'`以运行动画 1200 毫秒，如下所示：

```js
$(someElement).animate({width: '300px'}, 'crawl'); 

```

尽管键入`'crawl'`不比键入`1200`更容易，但在较大的项目中，当许多共享某个速度的动画需要更改时，自定义速度可能会派上用场。在这种情况下，我们可以更改`$.fx.speeds.crawl`的值，而不是在整个项目中搜索`1200`并仅在表示动画速度时替换每个值。

虽然自定义速度可能很有用，但也许更有用的是能够更改默认速度的能力。我们可以通过设置`_default`属性来做到这一点：

```js
$.fx.speeds._default = 250; 

```

列表 11.5

现在，我们已经定义了一个新的更快的默认速度，除非我们覆盖它们的持续时间，否则任何新添加的动画都将使用它。为了看到这个过程，我们将向页面引入另一个交互元素。当用户点击其中一个肖像时，我们希望显示与该人物相关联的详细信息。我们将通过将它们从肖像下面移出到最终位置来创建详细信息从肖像中*展开*的错觉：

```js
$(() => { 
  const showDetails = ({ currentTarget }) => {
    $(currentTarget)
      .find('div')
      .css({
        display: 'block',
        left: '-300px',
        top: 0
      })
      .each((i, element) => {
        $(element)
          .animate({
            left: 0,
            top: 25 * i
          });
      });
  }; 
  $('div.member').click(showDetails); 
}); 

```

列表 11.6

当点击成员时，我们使用`showDetails()`函数作为处理程序。该函数首先将详细信息`<div>`元素设置在成员肖像的下方的起始位置。然后将每个元素动画到其最终位置。通过调用`.each()`，我们可以计算每个元素的单独最终`top`位置。

动画完成后，详细信息文本可见：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_11_04.png)

由于`.animate()`方法调用是在不同的元素上进行的，所以它们是同时进行的，而不是排队进行的。而且，由于这些调用没有指定持续时间，它们都使用了新的默认持续时间 250 毫秒。

当点击另一个成员时，我们希望隐藏先前显示的成员。我们可以轻松地通过类来跟踪当前屏幕上显示的详细信息：

```js
 const showDetails = ({ currentTarget }) => {
   $(currentTarget)
     .siblings('.active')
     .removeClass('active')
     .children('div')
     .fadeOut()
     .end()
     .end()
     .addClass('active')
     .find('div')
     .css({
       display: 'block',
       left: '-300px',
       top: 0
     })
     .each((i, element) => {
       $(element)
         .animate({
           left: 0,
           top: 25 * i
         });
     });
}; 

```

列表 11.7

哎呀！十个函数链接在一起？等等，这其实可能比拆分它们更好。首先，像这样链接调用意味着不需要使用临时变量来保存中间的 DOM 值。相反，我们可以一行接一行地读取以了解发生了什么。现在让我们逐个解释一下这些：

+   `.siblings('.active')`: 这会找到活动的`<div>`兄弟元素。

+   `.removeClass('active')`: 这会移除`.active`类。

+   `.children('div')`: 这会找到子`<div>`元素。

+   `.fadeOut()`: 这会将它们移除。

+   `.end()`: 这会清除`.children('div')`查询结果。

+   `.end()`: 这会清除`.siblings('.active')`查询结果。

+   `.addClass('active')`: 这会将`.active`类添加到事件目标，即容器`<div>`上。

+   `.find('div')`: 这会找到所有子`<div>`元素以显示。

+   `.css()`: 这会设置相关的显示 CSS。

+   `.each()`: 这会向`top`和`left`CSS 属性添加动画。

请注意，我们的`.fadeOut()`调用也使用了我们定义的更快的 250 毫秒持续时间。默认值适用于 jQuery 的预打包效果，就像它们适用于自定义`.animate()`调用一样。

# 多属性缓动

`showDetails()`函数几乎实现了我们想要的展开效果，但由于`top`和`left`属性以相同的速率进行动画，它看起来更像是一个滑动效果。我们可以通过仅为`top`属性更改缓动方程式为`easeInQuart`来微妙地改变效果，从而使元素沿着曲线路径而不是直线路径移动。但请记住，除了`swing`或`linear`之外的任何缓动都需要插件，例如 jQuery UI 的效果核心（[`jqueryui.com/`](http://jqueryui.com/)）。

```js
.each((i, element) => {
  $(element)
    .animate({
      left: 0,
      top: 25 * i
    },{
      duration: 'slow',
      specialEasing: {
        top: 'easeInQuart'
      }
    });
 });

```

列表 11.8

`specialEasing`选项允许我们为每个正在动画化的属性设置不同的加速曲线。如果选项中不包括的属性，则将使用`easing`选项的方程式（如果提供）或默认的`swing`方程式。

现在我们有了一个引人注目的动画，展示了与团队成员相关的大部分细节。但我们还没有展示成员的传记。在这之前，我们需要稍微偏离一下话题，谈谈 jQuery 的延迟对象机制。

# 使用延迟对象

有时，我们会遇到一些情况，我们希望在过程完成时采取行动，但我们并不一定知道这个过程需要多长时间，或者是否会成功。为了处理这些情况，jQuery 为我们提供了**延迟对象**（promises）。延迟对象封装了需要一些时间来完成的操作。

可以随时通过调用`$.Deferred()`构造函数创建一个新的延迟对象。一旦我们有了这样的对象，我们可以执行长时间运行的操作，然后在对象上调用`.resolve()`或`.reject()`方法来指示操作是否成功或失败。然而，手动这样做有点不寻常。通常，我们不是手动创建自己的延迟对象，而是 jQuery 或其插件会创建对象，并负责解决或拒绝它。我们只需要学习如何使用创建的对象。

我们不打算详细介绍`$.Deferred()`构造函数的操作方式，而是在这里重点讨论 jQuery 效果如何利用延迟对象。在第十三章中，*高级 Ajax*，我们将进一步探讨在 Ajax 请求的背景下的延迟对象。

每个延迟对象都承诺向其他代码提供数据。这个承诺作为另一个具有自己一套方法的对象来表示。从任何延迟对象，我们可以通过调用它的`.promise()`方法来获得它的 promise 对象。然后，我们可以调用 promise 的方法来附加处理程序，当 promise 被履行时执行：

+   `.then()`方法附加了一个处理程序，当延迟对象成功解决时调用。

+   `.catch()`方法附加了一个处理程序，当延迟对象被拒绝时调用。

+   `.always()`方法附加了一个处理程序，当延迟对象完成其任务时被调用，无论是被解决还是被拒绝。

这些处理程序非常类似于我们提供给`.on()`的回调函数，因为它们是在某个事件发生时调用的函数。我们还可以附加多个处理程序到同一个承诺上，所有的会在适当的时候被调用。然而，这里也有一些重要的区别。承诺处理程序只会被调用一次；延迟对象无法再次解决。如果在我们附加处理程序时延迟对象已经被解决，那么承诺处理程序也会立即被调用。

在第六章中，*使用 Ajax 发送数据*，我们看到了一个非常简单的例子，说明了 jQuery 的 Ajax 系统如何使用延迟对象。现在，我们将再次利用这个强大的工具，通过研究 jQuery 动画系统创建的延迟对象来使用它。

# 动画的承诺

每个 jQuery 集合都有一组延迟对象与其关联，用于跟踪集合中元素的排队操作的状态。通过在 jQuery 对象上调用 `.promise()` 方法，我们得到一个在队列完成时解析的 promise 对象。特别是，我们可以使用此 promise 在任何匹配元素上运行的所有动画完成时采取行动。

就像我们有一个 `showDetails()` 函数来显示成员的名称和位置信息一样，我们可以编写一个 `showBio()` 函数来显示传记信息。但首先，我们将向 `<body>` 标签附加一个新的 `<div>` 标签并设置两个选项对象：

```js
$(() => {
  const $movable = $('<div/>')
    .attr('id', 'movable')
    .appendTo('body');

  const bioBaseStyles = {
    display: 'none',
    height: '5px',
    width: '25px'
  }

  const bioEffects = {
    duration: 800,
    easing: 'easeOutQuart',
    specialEasing: {
      opacity: 'linear'
    }
  };
});

```

[11.9 清单](https://wiki.example.org/11.9_listing)

这个新的可移动 `<div>` 元素是我们实际上将要动画化的元素，在注入了传记副本后。像这样拥有一个包装元素在动画化元素的宽度和高度时特别有用。我们可以将其 `overflow` 属性设置为 `hidden`，并为其中的传记设置显式的宽度和高度，以避免在我们动画化传记 `<div>` 元素本身时持续不断地重新排列文本。

我们将使用 `showBio()` 函数根据点击的成员图像确定可移动 `<div>` 的起始和结束样式。请注意，我们使用 `$.extend()` 方法将保持不变的一组基本样式与根据成员位置变化的 `top` 和 `left` 属性进行合并。然后，只需使用 `.css()` 设置起始样式和 `.animate()` 设置结束样式：

```js
const showBio = (target) => {
  const $member = $(target).parent();
  const $bio = $member.find('p.bio');
  const startStyles = $.extend(
    {},
    bioBaseStyles,
    $member.offset()
  );
  const endStyles = {
    width: $bio.width(),
    top: $member.offset().top + 5,
    left: $member.width() + $member.offset().left - 5,
    opacity: 'show'
  };

  $movable
    .html($bio.clone())
    .css(startStyles)
    .animate(endStyles, bioEffects)
    .animate(
      { height: $bio.height() },
      { easing: 'easeOutQuart' }
    );
}; 

```

[11.10 清单](https://wiki.example.org/11.10_listing)

我们排队了两个 `.animate()` 方法，以便传记首先从左侧飞出并变宽和完全不透明，然后在到位后向下滑动到其完整高度。

在 第四章，*样式和动画* 中，我们看到 jQuery 动画方法中的回调函数在集合中每个元素的动画完成时被调用。我们希望在其他 `<div>` 元素出现后显示成员的传记。在 jQuery 引入 `.promise()` 方法之前，这将是一项繁重的任务，需要我们在每次执行回调时从总元素数倒计时，直到最后一次，此时我们可以执行动画化传记的代码。

现在我们可以简单地将 `.promise()` 和 `.then()` 方法链接到我们的 `showDetails()` 函数内部的 `.each()` 方法中：

```js
const showDetails = ({ currentTarget }) => {
  $(currentTarget)
    .siblings('.active')
    .removeClass('active')
    .children('div')
    .fadeOut()
    .end()
    .end()
    .addClass('active')
    .find('div')
    .css({
      display: 'block',
      left: '-300px',
      top: 0
    })
    .each((i, element) => {
      $(element)
        .animate({
          left: 0,
          top: 25 * i
        },{
          duration: 'slow',
          specialEasing: {
            top: 'easeInQuart'
          }
        });
    })
    .promise()
    .then(showBio);
}; 

```

[11.11 清单](https://wiki.example.org/11.11_listing)

`.then()` 方法将我们的 `showBio()` 函数的引用作为其参数。现在，点击图像将以吸引人的动画序列将所有成员信息显示出来：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/Image5297_11_05-1.png)

自 jQuery 3.0 起，`promise()` 方法返回的 promises 与原生 ES 2015 promises 完全兼容。这意味着在可能的情况下，我们应该使用相同的 API。例如，使用 `then()` 代替 `done()`。它们做的是一样的事情，你的异步代码将与其他异步代码保持一致。

# 对动画进行细粒度控制

即使我们已经研究了许多高级功能，jQuery 的效果模块还有很多可以探索的地方。jQuery 1.8 的重写为这个模块引入了许多高级开发者调整各种效果甚至更改驱动动画的底层引擎的方法。例如，除了提供 `duration` 和 `easing` 等选项外，`.animate()` 方法还提供了一些回调选项，让我们在动画的每一步检查和修改动画：

```js
$('#mydiv').animate({ 
  height: '200px', 
  width: '400px' 
}, { 
  step(now, tween) { 
   // monitor height and width 
   // adjust tween properties 
  }, 
  progress(animation, progress, remainingMs) {} 
}); 

```

`step()` 函数，每次动画属性动画期间大约每 13 毫秒调用一次，允许我们根据传递的 `now` 参数的当前值调整 `tween` 对象的属性，如结束值、缓动类型或实际正在动画的属性。例如，一个复杂的演示可能会使用 `step()` 函数来检测两个移动元素之间的碰撞，并根据碰撞调整它们的轨迹。

`progress()` 函数在动画的生命周期中被多次调用：

+   它与 `step()` 不同之处在于，它每一步仅在每个元素上调用一次，而不管正在动画多少个属性

+   它提供了动画的不同方面，包括动画的 promise 对象、进度（一个介于 `0` 和 `1` 之间的数字）以及动画中剩余的毫秒数。

所有 jQuery 的动画都使用一个名为 `setTimeout()` 的 JavaScript 计时器函数来重复调用函数 —— 默认情况下每 13 毫秒一次 —— 并在每个时刻改变样式属性。然而，一些现代浏览器提供了一个新的 `requestAnimationFrame()` 函数，它相对于 `setTimeout()` 有一些优势，包括增加了精度（因此动画的平滑度更高）和改善了移动设备的电池消耗。

在 jQuery 的动画系统的最低级别上，有它的 `$.Animation()` 和 `$.Tween()` 函数。这些函数及其对应的对象可以用来调整动画的每一个可能的方面。例如，我们可以使用 `$.Animation` 来创建一个动画**预处理**。这样的预处理可以采用一个

特别

基于传递给 `.animate()` 方法的 `options` 对象中的属性的存在，在动画结束时执行动作：

```js
$.Animation.prefilter(function(element, properties, options) { 
  if (options.removeAfter) { 
    this.done(function () { 
      $(element).remove(); 
    }); 
  } 
}); 

```

使用这段代码，调用 `$('#my-div').fadeOut({ removeAfter: true })` 将在淡出完成后自动从 DOM 中删除 `<div>`。

# 摘要

在本章中，我们进一步研究了几种可以帮助我们制作对用户有用的漂亮动画的技术。我们现在可以单独控制我们正在动画化的每个属性的加速度和减速度，并在需要时单独或全局停止这些动画。我们了解了 jQuery 的效果库内部定义的属性，以及如何更改其中一些属性以适应我们的需求。我们初次涉足了 jQuery 延迟对象系统，我们将在第十三章 *高级 Ajax*中进一步探索，并且我们品尝到了调整 jQuery 动画系统的许多机会。

# 进一步阅读

本书附录 B 中提供了完整的效果和动画方法列表，或者您可以在[官方 jQuery 文档](http://api.jquery.com/)中找到。

# 练习

挑战练习可能需要使用[官方 jQuery 文档](http://api.jquery.com/)。

1.  定义一个名为`zippy`的新动画速度常数，并将其应用于传记显示效果。

1.  更改成员详细信息的水平移动的缓动，使其反弹到位。

1.  向 promise 添加一个第二个延迟回调函数，将`highlight`类添加到当前成员位置的`<div>`中。

1.  挑战：在动画传记之前添加两秒的延迟。使用 jQuery 的`.delay()`方法。

1.  挑战：当点击活动照片时，折叠生物详细信息。在执行此操作之前停止任何正在运行的动画。


# 第十二章：高级 DOM 操作

在本书中，我们已经使用了 jQuery 强大的 DOM 操作方法来改变文档的内容。我们已经看到了几种插入新内容、移动现有内容或完全删除内容的方法。我们也知道如何更改元素的属性和属性以满足我们的需求。

在第五章 *操作 DOM* 中，我们介绍了这些重要技术。在这个更高级的章节中，我们将涵盖：

+   使用 `.append()` 排序页面元素

+   附加自定义数据到元素

+   读取 HTML5 数据属性

+   从 JSON 数据创建元素

+   使用 CSS 钩子扩展 DOM 操作系统

# 排序表格行

在本章中，我们正在研究的大多数主题都可以通过对表格行进行排序来演示。这个常见的任务是帮助用户快速找到他们所需信息的有效方法。当然，有许多方法可以做到这一点。

# 在服务器上排序表格

数据排序的常见解决方案是在服务器上执行。表格中的数据通常来自数据库，这意味着从数据库中提取数据的代码可以请求以给定的排序顺序（例如，使用 SQL 语言的 `ORDER BY` 子句）提取数据。如果我们有服务器端代码可供使用，那么从一个合理的默认排序顺序开始是很简单的。

但是，当用户可以确定排序顺序时，排序就变得最有用了。这方面的常见用户界面是将可排序列的表头(`<th>`)转换为链接。这些链接可以指向当前页面，但附加了一个查询字符串来指示按哪一列排序，如下面的代码片段所示：

```js
<table id="my-data"> 
  <thead> 
    <tr> 
      <th class="name"> 
        <a href="index.php?sort=name">Name</a> 
      </th> 
      <th class="date"> 
        <a href="index.php?sort=date">Date</a> 
      </th> 
    </tr> 
  </thead> 
  <tbody> 
    ... 
  </tbody> 
</table> 

```

服务器可以通过返回数据库内容的不同顺序来响应查询字符串参数。

# 使用 Ajax 排序表格

这个设置很简单，但是每次排序操作都需要页面刷新。正如我们所见，jQuery 允许我们通过使用 *Ajax* 方法来消除这种页面刷新。如果我们像以前一样将列标题设置为链接，我们可以添加 jQuery 代码来将那些链接转换为 Ajax 请求：

```js
$(() => { 
  $('#my-data th a')
    .click((e) => { 
      e.preventDefault(); 
      $('#my-data tbody')
        .load($(e.target).attr('href')); 
    }); 
}); 

```

当锚点被点击时，现在 jQuery 会向服务器发送一个 Ajax 请求以获取相同的页面。当 jQuery 用于使用 Ajax 发送页面请求时，它会将 `X-Requested-With` HTTP 头设置为 `XMLHttpRequest`，以便服务器可以确定正在进行 Ajax 请求。当此参数存在时，服务器代码可以编写为仅在回送 `<tbody>` 元素本身的内容，而不是周围的页面。通过这种方式，我们可以使用响应来替换现有 `<tbody>` 元素的内容。

这是**渐进增强**的一个例子。页面即使没有任何 JavaScript 也能正常工作，因为仍然存在用于服务器端排序的链接。但是，当 JavaScript 可用时，我们会劫持页面请求，允许排序而无需完全重新加载页面。

# 在浏览器中排序表

但是有时候，当我们在排序时不想等待服务器响应或者没有服务器端脚本语言可用时。在这种情况下，一个可行的替代方法是完全在浏览器中使用 JavaScript 和 jQuery 的 DOM 操作方法进行排序。

为了演示本章中的各种技术，我们将设置三个单独的 jQuery 排序机制。每个都将以独特的方式完成相同的目标。我们的示例将使用以下方法对表进行排序：

+   从 HTML 内容中提取的数据

+   HTML5 自定义数据属性

+   表数据的 JSON 表示

我们将要排序的表具有不同的 HTML 结构，以适应不同的 JavaScript 技术，但每个表都包含列出书籍、作者姓名、发布日期和价格的列。第一个表具有简单的结构：

```js
<table id="t-1" class="sortable"> 
  <thead> 
    <tr> 
      <th></th> 
      <th class="sort-alpha">Title</th> 
      <th class="sort-alpha">Author(s)</th> 
      <th class="sort-date">Publish Date</th> 
      <th class="sort-numeric">Price</th> 
    </tr> 
  </thead> 
  <tbody> 
    <tr> 
      <td><img src="img/2862_OS.jpg" alt="Drupal 7"></td> 
      <td>Drupal 7</td> 
      <td>David <span class="sort-key">Mercer</span></td> 
      <td>September 2010</td> 
      <td>$44.99</td> 
    </tr> 
    <!-- code continues --> 
  </tbody> 
</table> 

```

获取示例代码

您可以从以下 GitHub 代码库访问示例代码：[`github.com/PacktPublishing/Learning-jQuery-3`](https://github.com/PacktPublishing/Learning-jQuery-3)。

在我们用 JavaScript 增强表格之前，前几行如下所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_12_01.png)

# 移动和插入元素的再次访问

在接下来的示例中，我们将构建一个灵活的排序机制，可以在每一列上工作。为此，我们将使用 jQuery 的 DOM 操作方法来插入一些新元素并将其他现有元素移动到 DOM 中的新位置。我们将从最简单的部分开始--链接表头。

# 在现有文本周围添加链接

我们想将表头转换为按其各自列排序数据的链接。我们可以使用 jQuery 的 `.wrapInner()` 方法来添加它们；我们回想起 [第五章](https://cdp.packtpub.com/learning_jquery_3_0/wp-admin/post.php?post=37&action=edit#post_30) *DOM 操作* 中，`.wrapInner()` 将一个新元素（在本例中为 `<a>` 元素） *插入* 匹配的元素内，但在*周围*子元素：

```js
$(() => {
  const $headers = $('#t-1')
    .find('thead th')
    .slice(1);

  $headers
    .wrapInner($('<a/>').attr('href', '#'))
    .addClass('sort');
});

```

列表 12.1

我们跳过了每个表的第一个 `<th>` 元素（使用 `.slice()`）因为它除了空格之外没有文本，因此没有必要对封面照片进行标记或排序。然后，我们对剩余的 `<th>` 元素添加了一个 `sort` 类，以便在 CSS 中将其与不可排序的元素区分开。现在，标题行如下所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_12_02.png)

这是渐进增强的对应，**优雅降级**的一个例子。与前面讨论的 Ajax 解决方案不同，这种技术在没有 JavaScript 的情况下无法工作；我们假设服务器在这个例子中没有可用于目的的脚本语言。由于 JavaScript 是必需的，以使排序工作，我们只通过代码添加 `sort` 类和锚点，从而确保界面只在脚本运行时表明可以排序。而且，由于我们实际上是创建链接而不仅仅是添加视觉样式以指示标题可以点击，因此我们为需要使用键盘导航到标题的用户提供了额外的辅助功能（通过按*Tab*键）。页面**退化**为一个仍然可以使用但无法进行排序的页面。

# 对简单的 JavaScript 数组进行排序

为了进行排序，我们将利用 JavaScript 的内置`.sort()`方法。它对数组进行原地排序，并可以接受一个**比较器函数**作为参数。此函数比较数组中的两个项目，并根据应该在排序后的数组中排在前面的项目返回正数或负数。

例如，取一个简单的数字数组：

```js
const arr = [52, 97, 3, 62, 10, 63, 64, 1, 9, 3, 4]; 

```

我们可以通过调用 `arr.sort()` 来对该数组进行排序。之后，项目的顺序如下：

```js
[1, 10, 3, 3, 4, 52, 62, 63, 64, 9, 97] 

```

默认情况下，如我们在这里看到的，项目按**字母顺序**（按字母顺序）排序。在这种情况下，可能更合理地按*数字*排序。为此，我们可以向 `.sort()` 方法提供一个比较函数：

```js
arr.sort((a, b) => a < b ? -1 : (a > b ? 1 : 0)); 

```

此函数如果 `a` 应该在排序后的数组中排在 `b` 之前，则返回负数；如果 `b` 应该在 `a` 之前，则返回正数；如果项目的顺序无关紧要，则返回零。有了这些信息，`.sort()` 方法可以适当地对项目进行排序：

```js
[1, 3, 3, 4, 9, 10, 52, 62, 63, 64, 97] 

```

接下来，我们将这个`.sort()`方法应用到我们的表格行上。

# 对 DOM 元素进行排序

让我们对表格的 `Title` 列执行排序。请注意，虽然我们将 `sort` 类添加到它和其他列，但此列的标题单元格已经有一个由 HTML 提供的 `sort-alpha` 类。其他标题单元格根据每个排序类型接受了类似的处理，但现在我们将专注于 `Title` 标题，它需要一个简单的按字母顺序排序：

```js
$(() => {
  const comparator = (a, b) => a < b ? -1 : (a > b ? 1 : 0);
  const sortKey = (element, column) => $.trim($(element)
    .children('td')
    .eq(column)
    .text()
    .toUpperCase()
  );

  $('#t-1')
    .find('thead th')
    .slice(1)
    .wrapInner($('<a/>').attr('href', '#'))
    .addClass('sort')
    .on('click', (e) => {
      e.preventDefault();

      const column = $(e.currentTarget).index();

      $('#t-1')
        .find('tbody > tr')
        .get()
        .sort((a, b) => comparator(
          sortKey(a, column),
          sortKey(b, column)
        ))
        .forEach((element) => {
          $(element)
            .parent()
            .append(element);
        });
    });
}); 

```

列表 12.2

一旦我们找到了点击的标题单元格的索引，我们就会检索所有数据行的数组。这是一个很好的例子，说明了`.get()`如何将 jQuery 对象转换为 DOM 节点数组；尽管 jQuery 对象在许多方面都像数组一样，但它们并没有所有可用的本机数组方法，比如`.pop()`或`.shift()`。

在内部，jQuery 实际上定义了一些类似原生数组方法的方法。例如，`.sort()`、`.push()` 和 `.splice()` 都是 jQuery 对象的方法。然而，由于这些方法是内部使用的，并且没有公开文档记录，我们不能指望它们在我们自己的代码中以预期的方式运行，因此应避免在 jQuery 对象上调用它们。

现在我们有了一个 DOM 节点数组，我们可以对它们进行排序，但要做到这一点，我们需要编写一个适当的比较器函数。我们想根据相关表格单元格的文本内容对行进行排序，因此这将是比较器函数要检查的信息。我们知道要查看哪个单元格，因为我们使用 `.index()` 调用捕获了列索引。我们使用 jQuery 的 `$.trim()` 函数去除前导和尾随空格，然后将文本转换为大写，因为 JavaScript 中的字符串比较是区分大小写的，而我们的排序应该是不区分大小写的。

现在我们的数组已经排序了，但请注意，对 `.sort()` 的调用并没有改变 DOM 本身。要做到这一点，我们需要调用 DOM 操作方法来移动行。我们一次移动一行，将每行重新插入表格中。由于 `.append()` 不会克隆节点，而是*移动*它们，因此我们的表格现在已经排序了：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_12_001-1.jpg)

# 将数据存储在 DOM 元素旁边

我们的代码可以运行，但速度相当慢。问题在于比较器函数，它执行了大量的工作。在排序过程中，这个比较器将被调用多次，这意味着它需要很快。

数组排序性能

JavaScript 使用的实际排序算法没有在标准中定义。它可能是一个简单的排序，比如**冒泡排序**（在计算复杂度方面的最坏情况是 Θ(*n*²)），或者更复杂的方法，比如**快速排序**（平均情况下是 Θ(*n* log *n*)）。不过可以肯定的是，将数组中的项数翻倍将会使比较器函数被调用的次数增加超过两倍。

解决我们慢比较器的方法是**预先计算**比较所需的键。我们可以在初始循环中完成大部分昂贵的工作，并使用 jQuery 的 `.data()` 方法将结果存储起来，该方法用于设置或检索与页面元素相关联的任意信息。然后我们只需在比较器函数中检查这些键，我们的排序就会明显加快：

```js
$('#t-1')
  .find('thead th')
  .slice(1)
  .wrapInner($('<a/>').attr('href', '#'))
  .addClass('sort')
  .on('click', (e) => {
    e.preventDefault();

    const column = $(e.currentTarget).index();

    $('#t-1')
      .find('tbody > tr')
      .each((i, element) => {
        $(element)
          .data('sortKey', sortKey(element, column));
      })
      .get()
      .sort((a, b) => comparator(
        $(a).data('sortKey'),
        $(b).data('sortKey')
      ))
      .forEach((element) => {
        $(element)
          .parent()
          .append(element);
      });
  }); 

```

列表 12.3

`.data()` 方法和它的补充 `.removeData()` 提供了一个数据存储机制，它是一种方便的替代方案，用于**扩展属性**，或者直接添加到 DOM 元素的非标准属性。

# 执行额外的预计算

现在我们希望将相同类型的排序行为应用于我们表格的作者一栏。因为表头单元格具有`sort-alpha`类，作者一栏可以使用我们现有的代码进行排序。但理想情况下，作者应该按照姓氏而不是名字排序。由于一些书籍有多位作者，有些作者列出了中间名或缩写，我们需要外部指导来确定要用作排序键的文本部分。我们可以通过在单元格中包装相关部分来提供这些指导：

```js
<td>David <span class="sort-key">Mercer</span></td> 

```

现在我们必须修改我们的排序代码，以考虑这个标记，而不影响`Title`列的现有行为，因为它已经运行良好。通过将标记排序键放在之前计算过的键的前面，我们可以先按照姓氏排序，如果指定的话，但是在整个字符串上作为后备进行排序：

```js
const sortKey = (element, column) => {
  const $cell = $(element)
    .children('td')
    .eq(column);
  const sortText = $cell
    .find('span.sort-key')
    .text();
  const cellText = $cell
    .text()
    .toUpperCase();

  return $.trim(`${sortText} ${cellText}`);
}; 

```

列表 12.4

现在按照作者一栏对提供的键进行排序，从而按照姓氏排序：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_12_002-1.jpg)

如果两个姓氏相同，则排序会使用整个字符串作为定位的决定因素。

# 存储非字符串数据

我们的用户应该能够不仅按照标题和作者一栏进行排序，还可以按照发布日期和价格一栏进行排序。由于我们简化了比较函数，它可以处理各种类型的数据，但首先计算出的键需要针对其他数据类型进行调整。例如，在价格的情况下，我们需要去掉前导的`$`字符并解析剩余部分，以便我们可以进行数字比较：

```js
var key = parseFloat($cell.text().replace(/^[^\d.]*/, '')); 
if (isNaN(key)) { 
  key = 0; 
} 

```

此处使用的正则表达式除了数字和小数点以外的任何前导字符，将结果传递给`parseFloat()`。然后需要检查`parseFloat()`的结果，因为如果无法从文本中提取数字，将返回`NaN`（**不是一个数字**）。这可能对`.sort()`造成严重影响，所以将任何非数字设为`0`。

对于日期单元格，我们可以使用 JavaScript 的 `Date` 对象：

```js
var key = Date.parse(`1 ${$cell.text()}`); 

```

此表中的日期仅包含月份和年份； `Date.parse()`需要一个完全规定的日期。为了适应这一点，我们在字符串前面加上`1`，这样`September 2010`就变成了`1 September 2010`。现在我们有了一个完整的日期，`Date.parse()`可以将其转换为**时间戳**，可以使用我们正常的比较器进行排序。

我们可以将这些表达式放入三个单独的函数中，以便稍后可以根据应用于表头的类调用适当的函数：

```js
const sortKeys = {
  date: $cell => Date.parse(`1 ${$cell.text()}`),
  alpha: $cell => $.trim(
    $cell.find('span.sort-key').text() + ' ' +
    $cell.text().toUpperCase()
  ),
  numeric($cell) {
    const key = parseFloat(
      $cell
        .text()
        .replace(/^[^\d.]*/, '')
    );
    return isNaN(key) ? 0 : key;
  }
};

$('#t-1')
  .find('thead th')
  .slice(1)
  .each((i, element) => {
    $(element).data(
      'keyType',
      element.className.replace(/^sort-/,'')
    );
  })
  // ...

```

列表 12.5

我们已修改脚本，为每个列头单元格存储基于其类名的`keyType`数据。我们去掉类名的`sort-`部分，这样就剩下`alpha`、`numeric`或`date`。通过将每个排序函数作为`sortKeys`对象的方法，我们可以使用**数组表示法**，并传递表头单元格的`keyType`数据的值来调用适当的函数。

通常，当我们调用方法时，我们使用**点符号**。事实上，在本书中，我们调用 jQuery 对象的方法就是这样的。例如，要向`<div class="foo">`添加一个`bar`类，我们写`$('div.foo').addClass('bar')`。因为 JavaScript 允许以点符号或数组符号表示属性和方法，所以我们也可以写成`$('div.foo')'addClass'`。大多数情况下这样做没有太多意义，但这可以是一种有条件地调用方法而不使用一堆`if`语句的好方法。对于我们的`sortKeys`对象，我们可以像这样调用`alpha`方法`sortKeys.alpha($cell)`或`sortKeys'alpha'`或者，如果方法名存储在一个`keyType`常量中，`sortKeyskeyType`。我们将在`click`处理程序内使用这种第三种变体：

```js
// ...
.on('click', (e) => {
  e.preventDefault();

  const column = $(e.currentTarget).index();
  const keyType = $(e.currentTarget).data('keyType');

  $('#t-1')
    .find('tbody > tr')
    .each((i, element) => {
      $(element).data(
        'sortKey',
        sortKeyskeyType
            .children('td')
            .eq(column)
        )
      );
    })
    .get()
    .sort((a, b) => comparator(
      $(a).data('sortKey'),
      $(b).data('sortKey')
    ))
    .forEach((element) => {
      $(element)
        .parent()
        .append(element);
    });
}); 

```

列表 12.6

现在我们也可以按发布日期或价格排序：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_12_003-1.jpg)

# 交替排序方向

我们的最终排序增强是允许**升序**和**降序**排序顺序。当用户点击已经排序的列时，我们希望反转当前的排序顺序。

要反转排序，我们只需反转比较器返回的值。我们可以通过简单的`direction`参数来做到这一点：

```js
const comparator = (a, b, direction = 1) =>
  a < b ?
    -direction :
    (a > b ? direction : 0);

```

如果`direction`等于`1`，那么排序将与之前相同。如果它等于`-1`，则排序将被反转。通过将这个概念与一些类结合起来以跟踪列的当前排序顺序，实现交替排序方向就变得简单了：

```js
// ...
.on('click', (e) => {
  e.preventDefault();

  const $target = $(e.currentTarget);
  const column = $target.index();
  const keyType = $target.data('keyType');
  const sortDirection = $target.hasClass('sorted-asc') ?
    -1 : 1;

  $('#t-1')
    .find('tbody > tr')
    .each((i, element) => {
      $(element).data(
        'sortKey',
        sortKeyskeyType
            .children('td')
            .eq(column)
        )
      );
    })
    .get()
    .sort((a, b) => comparator(
      $(a).data('sortKey'),
      $(b).data('sortKey'),
      sortDirection
    ))
    .forEach((element) => {
      $(element)
        .parent()
        .append(element);
    });

    $target
      .siblings()
      .addBack()
      .removeClass('sorted-asc sorted-desc')
      .end()
      .end()
      .addClass(
        sortDirection == 1 ?
          'sorted-asc' : 'sorted-desc'
      );
}); 

```

列表 12.7

作为一个额外的好处，由于我们使用类来存储排序方向，我们可以将列标题样式化以指示当前顺序：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/image_12_004-1.jpg)

# 使用 HTML5 自定义数据属性

到目前为止，我们一直依赖表格单元格内的内容来确定排序顺序。虽然我们已经通过操作内容来正确排序行，但我们可以通过以**HTML5 数据属性**的形式从服务器输出更多的 HTML 来使我们的代码更高效。我们示例页面中的第二个表格包含了这些属性：

```js
<table id="t-2" class="sortable"> 
  <thead> 
    <tr> 
      <th></th> 
      <th data-sort='{"key":"title"}'>Title</th> 
      <th data-sort='{"key":"authors"}'>Author(s)</th> 
      <th data-sort='{"key":"publishedYM"}'>Publish Date</th> 
      <th data-sort='{"key":"price"}'>Price</th> 
    </tr> 
  </thead> 
  <tbody> 
    <tr data-book='{"img":"2862_OS.jpg", 
      "title":"DRUPAL 7","authors":"MERCER DAVID",       
      "published":"September 2010","price":44.99,       
      "publishedYM":"2010-09"}'> 
      <td><img src="img/2862_OS.jpg" alt="Drupal 7"></td> 
      <td>Drupal 7</td> 
      <td>David Mercer</td> 
      <td>September 2010</td> 
      <td>$44.99</td> 
    </tr> 
    <!-- code continues --> 
  </tbody> 
</table> 

```

请注意，每个`<th>`元素（除了第一个）都有一个`data-sort`属性，每个`<tr>`元素都有一个`data-book`属性。我们在第七章中首次看到自定义数据属性，*使用插件*，在那里我们提供了插件代码使用的属性信息。在这里，我们将使用 jQuery 自己来访问属性值。要检索值，我们将`data-`后的属性名部分传递给`.data()`方法。例如，我们写`$('th').first().data('sort')`来获取第一个`<th>`元素的`data-sort`属性的值。

当我们使用 `.data()` 方法获取数据属性的值时，如果 jQuery 确定它是其中一种类型，它会将值转换为数字、数组、对象、布尔值或 null。对象必须使用 JSON 语法表示，就像我们在这里做的一样。因为 JSON 格式要求其键和字符串值使用双引号括起来，所以我们需要使用单引号来包围属性值：

```js
<th data-sort='{"key":"title"}'> 

```

由于 jQuery 会将 JSON 字符串转换为对象，因此我们可以简单地获取我们想要的值。例如，要获取`key`属性的值，我们写：

```js
$('th').first().data('sort').key 

```

一旦以这种方式检索了自定义数据属性，数据就被 jQuery 内部存储起来，HTML `data-*` 属性本身不再被访问或修改。

在这里使用数据属性的一个很大的好处是，存储的值可以与表格单元格内容不同。换句话说，我们在第一个表格中必须做的所有工作以调整排序--将字符串转换为大写，更改日期格式，将价格转换为数字--已经处理过了。这使我们能够编写更简单、更高效的排序代码：

```js
$(() => {
  const comparator = (a, b, direction = 1) =>
    a < b ?
      -direction :
      (a > b ? direction : 0);

  $('#t-2')
    .find('thead th')
    .slice(1)
    .wrapInner($('<a/>').attr('href', '#'))
    .addClass('sort')
    .on('click', (e) => {
      e.preventDefault();

      const $target = $(e.currentTarget);
      const column = $target.index();
      const sortKey = $target.data('sort').key;
      const sortDirection = $target.hasClass('sorted-asc') ?
        -1 : 1;

      $('#t-2')
        .find('tbody > tr')
        .get()
        .sort((a, b) => comparator(
          $(a).data('book')[sortKey],
          $(b).data('book')[sortKey],
          sortDirection
        ))
        .forEach((element) => {
          $(element)
            .parent()
            .append(element);
        });

      $target
        .siblings()
        .addBack()
        .removeClass('sorted-asc sorted-desc')
        .end()
        .end()
        .addClass(
          sortDirection == 1 ?
            'sorted-asc' : 'sorted-desc'
        );
    });
}); 

```

第 12.8 节

这种方法的简单性是显而易见的：`sortKey`常量被设置为`.data('sort').key`，然后用它来比较行的排序值和`$(a).data('book')[sortKey]`以及`$(b).data('book')[sortKey]`。其效率表现在无需先循环遍历行，然后每次在调用`sort`函数之前调用`sortKeys`函数之一。通过这种简单和高效的结合，我们还提高了代码的性能并使其更易于维护。

# 使用 JSON 排序和构建行

到目前为止，在本章中，我们一直在朝着将更多信息从服务器输出到 HTML 中的方向前进，以便我们的客户端脚本尽可能保持简洁和高效。现在让我们考虑一个不同的情景，即在 JavaScript 可用时显示一整套新的信息。越来越多的 Web 应用程序依赖于 JavaScript 传递内容以及一旦内容到达后对其进行操作。在我们的第三个表格排序示例中，我们将做同样的事情。

我们将首先编写三个函数：

+   `buildAuthors()`: 这个函数用于构建作者名称的字符串列表。

+   `buildRow()`: 这个函数用于构建单个表格行的 HTML。

+   `buildRows()`: 这个函数通过映射`buildRow()`构建的行来构建整个表格的 HTML。

```js
const buildAuthors = row =>
  row
    .authors
    .map(a => `${a.first_name} ${a.last_name}`)
    .join(', ');

const buildRow = row =>
  `
    <tr>
      <td><img src="img/${row.img}"></td>
      <td>${row.title}</td>
      <td>${buildAuthors(row)}</td>
      <td>${row.published}</td>
      <td>$${row.price}</td>
    </tr>
  `;

const buildRows = rows =>
  rows
    .map(buildRow)
    .join(''); 

```

第 12.9 节

对于我们的目的，我们可以使用一个函数来处理这两个任务，但是通过使用三个独立的函数，我们留下了在其他时间点构建和插入单个行的可能性。这些函数将从对 Ajax 请求的响应中获取它们的数据：

```js
Promise.all([$.getJSON('books.json'), $.ready])
  .then(([json]) => {
    $('#t-3')
      .find('tbody')
      .html(buildRows(json));
  })
  .catch((err) => {
    console.error(err);
  }); 

```

第 12.10 节

在进行 Ajax 调用之前，我们不应该等待 DOM 准备就绪。在我们可以使用 JSON 数据调用`buildRows()`之前，有两个 promise 需要解决。首先，我们需要来自服务器的实际 JSON 数据。其次，我们需要确保 DOM 已准备好进行操作。因此，我们只需创建一个新的 promise，在这两件事发生时解决它，使用`Promise.all()`。`$.getJSON()`函数返回一个 promise，而`$.ready`是一个在 DOM 准备就绪时解决的 promise。

还值得注意的是，我们需要以不同方式处理`authors`数据，因为它作为一个具有`first_name`和`last_name`属性的对象数组从服务器返回，而其他所有数据都作为字符串或数字返回。我们遍历作者数组--尽管对于大多数行，该数组只包含一个作者--并连接名字和姓氏。然后，我们使用逗号和空格将数组值连接起来，得到一个格式化的姓名列表。

`buildRow()`函数假设我们从 JSON 文件中获取的文本是安全可用的。由于我们将`<img>`、`<td>`和`<tr>`标签与文本内容连接成一个字符串，我们需要确保文本内容没有未转义的`<`、`>`或`&`字符。确保 HTML 安全字符串的一种方法是在服务器上处理它们，将所有的`<`转换为`&lt;`，`>`转换为`&gt;`，并将`&`转换为`&amp;`。

# 修改 JSON 对象

我们对`authors`数组的处理很好，如果我们只计划调用`buildRows()`函数一次的话。然而，由于我们打算每次对行进行排序时都调用它，提前格式化作者信息是个好主意。趁机我们也可以对标题和作者信息进行排序格式化。与第二个表格不同的是，第三个表格检索到的 JSON 数据只有一种类型。但是，通过编写一个额外的函数，我们可以在到达构建表格函数之前包含修改后的排序和显示值：

```js
const buildAuthors = (row, separator = ', ') =>
  row
    .authors
    .map(a => `${a.first_name} ${a.last_name}`)
    .join(separator);

const prepRows = rows =>
  rows
    .map(row => $.extend({}, row, {
      title: row.title.toUpperCase(),
      titleFormatted: row.title,
      authors: buildAuthors(row, ' ').toUpperCase(),
      authorsFormatted: buildAuthors(row)
    }));

```

列表 12.11

通过将我们的 JSON 数据传递给这个函数，我们为每一行的对象添加了两个属性：`authorsFormatted`和`titleFormatted`。这些属性将用于显示的表格内容，保留原始的`authors`和`title`属性用于排序。用于排序的属性也转换为大写，使排序操作不区分大小写。我们还在`buildAuthors()`函数中添加了一个新的分隔符参数，以便在这里使用它。

当我们立即在 `$.getJSON()` 回调函数内调用这个 `prepRows()` 函数时，我们将修改后的 JSON 对象的返回值存储在 `rows` 变量中，并将其用于排序和构建。这意味着我们还需要改变 `buildRow()` 函数以利用我们提前准备的简便性：

```js
const buildRow = row =>
  `
    <tr>
      <td><img src="img/${row.img}"></td>
      <td>${row.titleFormatted}</td>
      <td>${row.authorsFormatted}</td>
      <td>${row.published}</td>
      <td>$${row.price}</td>
    </tr>
  `;

Promise.all([$.getJSON('books.json'), $.ready])
  .then(([json]) => {
    $('#t-3')
      .find('tbody')
      .html(buildRows(prepRows(json)));
  })
  .catch((err) => {
    console.error(err);
  });

```

清单 12.12

# 根据需要重建内容

现在，我们已经为排序和显示准备好了内容，我们可以再次实现列标题修改和排序例程：

```js
Promise.all([$.getJSON('books.json'), $.ready])
  .then(([json]) => {
    $('#t-3')
      .find('tbody')
      .html(buildRows(prepRows(json)));

    const comparator = (a, b, direction = 1) =>
      a < b ?
        -direction :
        (a > b ? direction : 0);

    $('#t-3')
      .find('thead th')
      .slice(1)
      .wrapInner($('<a/>').attr('href', '#'))
      .addClass('sort')
      .on('click', (e) => {
        e.preventDefault();

        const $target = $(e.currentTarget);
        const column = $target.index();
        const sortKey = $target.data('sort').key;
        const sortDirection = $target.hasClass('sorted-asc') ?
          -1 : 1;
        const content = buildRows(
          prepRows(json).sort((a, b) => comparator(
            a[sortKey],
            b[sortKey],
            sortDirection
          ))
        );

        $('#t-3')
          .find('tbody')
          .html(content);

        $target
          .siblings()
          .addBack()
          .removeClass('sorted-asc sorted-desc')
          .end()
          .end()
          .addClass(
            sortDirection == 1 ?
              'sorted-asc' : 'sorted-desc'
          );
      });
})
.catch((err) => {
  console.error(err);
}); 

```

清单 12.13

`click` 处理程序中的代码与*清单 12.8*中第二个表格的处理程序几乎相同。唯一显著的区别是，这里我们每次排序只向 DOM 中插入一次元素。在表格一和表格二中，即使经过其他优化，我们也是对实际的 DOM 元素进行排序，然后逐个循环遍历它们，将每一个依次附加以达到新的顺序。例如，在*清单 12.8*中，表格行是通过循环重新插入的：

```js
.forEach((element) => {
  $(element)
    .parent()
    .append(element);
}); 

```

这种重复的 DOM 插入在性能上可能是相当昂贵的，特别是当行数很大时。与我们在*清单 12.13*中的最新方法相比：

```js
$('#t-3')
  .find('tbody')
  .html(content);

```

`buildRows()` 函数返回表示行的 HTML 字符串，并一次性插入，而不是移动现有行。

# 重新审视属性操作

到现在，我们已经习惯于获取和设置与 DOM 元素相关的值。我们使用了简单的方法，例如 `.attr()`、`.prop()` 和 `.css()`，方便的快捷方式，例如 `.addClass()`、`.css()` 和 `.val()`，以及复杂的行为捆绑，例如 `.animate()`。即使是简单的方法，它们也在幕后为我们做了很多工作。如果我们更好地理解它们的工作原理，我们可以更有效地利用它们。

# 使用简写元素创建语法

我们经常通过将 HTML 字符串提供给 `$()` 函数或 DOM 插入函数来在我们的 jQuery 代码中创建新元素。例如，我们在*清单 12.9*中创建一个大的 HTML 片段以产生许多 DOM 元素。这种技术快速而简洁。在某些情况下，它并不理想。例如，我们可能希望在使用文本之前对特殊字符进行转义，或者应用浏览器相关的样式规则。在这些情况下，我们可以创建元素，然后链式附加额外的 jQuery 方法来修改它，就像我们已经做过很多次一样。除了这种标准技术之外，`$()` 函数本身提供了一种实现相同结果的替代语法。

假设我们想在文档中的每个表格之前引入标题。我们可以使用 `.each()` 循环来遍历表格并创建一个适当命名的标题：

```js
$(() => {
  $('table')
    .each((i, table) => {
      $('<h3/>', {
        'class': 'table-title',
        id: `table-title-${i}`,
        text: `Table ${i + 1}`,
        data: { index: i },
        click(e) {
          e.preventDefault();
          $(table).fadeToggle();
        },
        css: { glowColor: '#00ff00', cursor: 'pointer' }
      }).insertBefore(table);
    });
}); 

```

清单 12.14

将选项对象作为第二个参数传递给 `$()` 函数与首先创建元素然后将该对象传递给 `.attr()` 方法具有相同的效果。正如我们所知，这个方法让我们设置 DOM 属性，如元素的 `id` 值和其 `class`。

我们示例中的其他选项包括：

+   元素内的文本

+   自定义额外数据

+   点击处理程序

+   包含 CSS 属性的对象

这些不是 DOM 属性，但它们仍然被设置。简写的 `$()` 语法能够处理这些，因为它首先检查给定名称的 jQuery 方法是否存在，如果存在，则调用它而不是设置该名称的属性。

因为 jQuery 会将方法优先于属性名称，所以在可能产生歧义的情况下，我们必须小心；例如，`<input>` 元素的 `size` 属性，因为存在 `.size()` 方法，所以不能以这种方式设置。

这个简写的 `$()` 语法，连同 `.attr()` 函数，通过使用**钩子**可以处理更多功能。

# DOM 操作钩子

许多 jQuery 方法可以通过定义适当的钩子来扩展特殊情况下的获取和设置属性。这些钩子是在 jQuery 命名空间中的数组，名称如 `$.cssHooks` 和 `$.attrHooks`。通常，钩子是包含一个 `get` 方法以检索请求的值和一个 `set` 方法以提供新值的对象。

钩子类型包括：

| **钩子类型** | **修改的方法** | **示例用法** |
| --- | --- | --- |
| `$.attrHooks` | `.attr()` | 阻止更改元素的 `type` 属性。 |
| `$.cssHooks` | `.css()` | 为 Internet Explorer 提供 `opacity` 的特殊处理。 |
| `$.propHooks` | `.prop()` | 修正了 Safari 中 `selected` 属性的行为。 |
| `$.valHooks` | `.val()` | 允许单选按钮和复选框在各个浏览器中报告一致的值。 |

通常这些钩子执行的工作对我们完全隐藏，我们可以从中受益而不用考虑正在发生什么。不过，有时候，我们可能希望通过添加自己的钩子来扩展 jQuery 方法的行为。

# 编写 CSS 钩子

*列表 12.14* 中的代码将一个名为 `glowColor` 的 CSS 属性注入到页面中。目前，这对页面没有任何影响，因为这样的属性并不存在。相反，我们将扩展 `$.cssHooks` 以支持这个新发明的属性。当在元素上设置 `glowColor` 时，我们将使用 CSS3 的 `text-shadow` 属性在文本周围添加柔和的辉光：

```js
(($) => {
  $.cssHooks.glowColor = {
    set(elem, value) {
      elem.style.textShadow = value == 'none' ?
        '' : `0 0 2px ${value}`;
    }
  };
})(jQuery);

```

列表 12.15

钩子由元素的 `get` 方法和 `set` 方法组成。为了尽可能简洁和简单，我们目前只定义了 `set`。

有了这个钩子，现在我们在标题文本周围有一个 2 像素的柔和绿色辉光：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_12_07.png)

虽然新的钩子按照广告展示的效果工作，但它缺少许多我们可能期望的功能。其中一些缺点包括：

+   辉光的大小不可定制

+   这个效果与 `text-shadow` 或 `filter` 的其他用法是互斥的

+   `get` 回调未实现，所以我们无法测试属性的当前值

+   该属性无法进行动画处理

只要付出足够的工作和额外的代码，我们就能克服所有这些障碍。然而，在实践中，我们很少需要定义自己的钩子；有经验的插件开发人员已经为各种需要创建了钩子，包括大多数 CSS3 属性。

寻找钩子

插件的形势变化很快，所以新的钩子会不断出现，我们无法希望在这里列出所有的钩子。要了解可能的一些内容，请参阅 Brandon Aaron 的 CSS 钩子集合。

[`github.com/brandonaaron/jquery-cssHooks`](https://github.com/brandonaaron/jquery-cssHooks)。

# 总结

在本章中，我们用三种不同的方式解决了一个常见问题--对数据表进行排序--并比较了每种方法的优点。这样做的过程中，我们练习了我们之前学到的 DOM 修改技术，并探索了 `.data()` 方法，用于获取和设置与任何 DOM 元素相关联的数据，或者使用 HTML5 数据属性附加。我们还揭开了几个 DOM 修改例程的面纱，学习了如何为我们自己的目的扩展它们。

# 进一步阅读

本书的 *附录 C* 中提供了完整的 DOM 操作方法列表，或者在官方 jQuery 文档中查看 [`api.jquery.com/`](http://api.jquery.com/)。

# 练习

挑战性练习可能需要使用官方 jQuery 文档 [`api.jquery.com/`](http://api.jquery.com/)。

1.  修改第一个表的关键计算，使标题和作者按长度而不是字母顺序排序。

1.  使用第二个表中的 HTML5 数据计算所有书的价格总和，并将这个总和插入到该列的标题中。

1.  更改用于第三个表的比较器，使包含单词 jQuery 的标题首先按标题排序。

1.  挑战：为 `glowColor` CSS 钩子实现 `get` 回调。
