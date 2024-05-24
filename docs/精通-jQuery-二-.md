# 精通 jQuery（二）

> 原文：[`zh.annas-archive.org/md5/0EE28037989D2E7006D982EBB8295FFE`](https://zh.annas-archive.org/md5/0EE28037989D2E7006D982EBB8295FFE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：集成 AJAX

一个问题 - **Deferreds**、**Promises**和/**ˈeɪdʒæks**/有什么共同点？

答案很简单 - 至少其中两个是工作与 AJAX 的实用程序；第三个实际上是 AJAX 的国际音标拼写。

在互联网的历史上，我们作为最终用户被迫忍受页面刷新 - 您必须强制刷新页面才能显示新内容。现在不一样了 - 我们可以在不需要清除页面的情况下刷新内容，利用了 AJAX 的力量，但并非没有问题。进入延迟和承诺 - 不适合初学者，但一旦了解其工作原理就是有用的工具！

在接下来的几页中，我们将研究与使用 jQuery 进行 AJAX 相关的一些主题。这些主题包括：

+   详述 AJAX 最佳实践

+   通过静态站点提高数据加载速度

+   使用回调处理多个 AJAX 请求

+   使用 jQuery Deferreds 和 Promises 增强您的代码

+   看 Deferreds 和 Promises 的实际效果

让我们开始吧...！

# 重新审视 AJAX

有没有人还记得点击链接或按钮会强制刷新页面的日子，无论我们在哪个网站上？那些日子，当您知道要订购披萨外卖或从在线书店订购书籍时，意味着要点击许多页面...真无聊！

幸运的是，AJAX 在 2006 年作为一种标准的出现已经结束了这种需要。今天，我们不再受到完全刷新页面的限制；我们可以轻松地异步更新页面的内容。好吧 - 所以我们不需要刷新页面，但是...AJAX？那不是上个世纪的某种老技术，早就消亡了吗？

答案是否定的 - 尽管 jQuery 的魔力使我们能够异步更新页面，但 AJAX 仍然起着重要的作用。互联网的惊人崛起意味着我们会有需要从另一个站点获取页面的情况。众所周知，大多数浏览器中的安全设置将阻止对内容的访问，如果违反了**跨域资源共享**（**CORS**）策略，如下图所示：

![重新审视 AJAX](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00374.jpeg)

为了规避与 CORS 相关的安全控制，我们可以使用 AJAX。在我们涉足更复杂的用法之前，让我们花点时间回顾一下 AJAX 是什么，以及我们如何在实践中使用它。

### 注意

要看到这种效果的实际情况，您可以运行本书附带的代码下载中提供的`ajaxblocked`演示。

## 定义 AJAX

如果您花费了一些时间使用 AJAX，毫无疑问您会遇到一种或多种变体，例如 AHAH、AJAH 或 AJAJ，它们使用相似的原理。但数据的交换有所不同；例如，AJAH 使用 HTML，AJAJ 使用 JSON，而 AHAH 是基于 HTML 的。

无论使用哪种变体，这组相互关联的技术可能已经成熟，但它仍然在向最终用户呈现数据方面发挥着重要作用。在本章的整个过程中，我们将与可以说是它们中的鼻祖的 AJAX 一起工作。作为提醒，它由以下各个技术组成：

+   用于演示的 HTML（或 XHTML）和 CSS

+   用于动态显示和与数据交互的**文档对象模型**（**DOM**）

+   用于数据的交换和操作的 XML 和**可扩展样式表语言转换**（**XSLT**）

+   用于异步通信的 `XMLHttpRequest` 对象

+   JavaScript 将这些技术结合起来

当在 jQuery 中使用时，我们可以使用 `$.ajax` 对象轻松配置 AJAX。有许多可用的选项，但我们可能经常使用的一些包括：

| 配置选项 | 目的 |
| --- | --- |
| `url` | 请求的内容的 URL。 |
| `data` | 要发送到服务器的数据。 |
| `error` | 在请求失败时调用此函数 - 函数将传递三个参数：`jqXHR` 对象，描述错误的字符串以及（如果生成了一个）可选异常对象。 |
| `dataType` | 这描述了您期望从服务器返回的数据类型。默认情况下，jQuery 将尝试自动解决此问题，但它可能是以下之一：XML、JSON、脚本或 HTML。 |
| `Success` | 如果请求成功，则调用的函数。 |
| `type` | 发送的请求类型，例如，'POST'，'GET' 或 'PUT' - 默认为 'GET'。 |

### 提示

还有许多其他选项可用。作为提醒，值得浏览 [`api.jquery.com/jQuery.ajax/`](http://api.jquery.com/jQuery.ajax/) 以获取更多详细信息。

足够的理论 - 至少暂时够了！让我们继续并看看如何使用 AJAX 和 jQuery 开发一个示例。

## 使用 AJAX 创建一个简单的示例

在我们开始编写代码并推动我们所能做的边界之前，让我们花一点时间了解典型的 AJAX 代码在实际中是什么样子的。

在依赖导入内容的典型应用程序中，我们可能会遇到类似以下摘录的内容：

```js
var jqxhr = $.ajax({
  url: url,
  type: "GET",
  cache: true,
  data: {},
  dataType: "json",
  jsonp: "callback",
  statusCode: {
    404: handler404,
    500: handler500
  }
});
jqxhr.done(successHandler);
jqxhr.fail(failureHandler);
```

这是一个用于 AJAX 启用代码的标准配置对象。让我们更详细地看看其中一些配置选项：

| 选项 | 注释 |
| --- | --- |
| `url` | URL 的 |
| `type` | 默认为 `GET`，但如果需要，可以使用其他动词代替 |
| `cache` | 默认为 `true`，但对于 `'script'` 和 `'jsonp'` 数据类型为 `false`，因此必须根据具体情况进行设置 |
| `data` | 任何请求参数都应设置在 `data` 对象中 |
| `datatype` | 应将 `datatype` 设置为将来参考 |
| `jsonp` | 只需指定此项以匹配你的 API 期望的 JSONP 请求的回调参数的名称，这些请求是对托管在不同域中的服务器发起的 |
| `statusCode` | 如果您想处理特定的错误代码，请使用状态代码映射设置 |

### 提示

jQuery Core 站点上有大量文档 - 值得一读！一个好的起点是主要的 `ajax()` 对象，位于 [`api.jquery.com/jQuery.ajax/`](http://api.jquery.com/jQuery.ajax/)。

我们可以将其用于生成一个简单的演示，比如从 XML 文件或者甚至是纯 HTML 中显示信息，如下一张截图所示：

![使用 AJAX 创建一个简单示例](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00375.jpeg)

让我们更详细地看看这个演示：

1.  从随书附带的代码下载中，提取 `basicajax.html`、`content.html` 和 `basicajax.css` 文件的副本 - 将 HTML 文件放入我们项目文件夹的根目录，样式表放入 `css` 子文件夹。

1.  接下来，将以下代码添加到一个新文件中，将其保存为 `basicajax.js`，并将其放入我们项目区域的 `js` 子文件夹中：

    ```js
    $(document).ready(function(){
    });
    ```

1.  在声明的 `$description` 变量的下方，添加以下辅助函数来控制我们在屏幕上提取的文本的呈现：

    ```js
       var displaytext = function(data) {
         var $response = $(data), $info = $("#info");
         var $title = $('<h1>').text($response.find(".title") .text());
         $info.append($title);
         $response.find(".description").each(function(){
           $(this).appendTo($info);
         });
       };
    ```

1.  接下来是我们的 jQuery 代码的核心部分 - 对 `$.ajax` 的调用。立即在辅助函数下面添加以下事件处理程序：

    ```js
    $('#action-button').click(function() {
      $.ajax({
        url: 'content.html',
        data: { format: 'html' },
        error: function() {
            $('#info').html('<p>An error has occurred</p>');
        },
        dataType: 'html',
        success: displaytext,
        type: 'GET'
      });
    });
    ```

1.  如果我们在浏览器中预览结果，我们可以看到点击按钮时内容出现，就像在这个演示开始时所示的截图中一样。

在这个实例中，我们创建了一个简单的演示。它首先引用了 `content.html` 文件，使用 HTML 格式将其导入到我们的页面中。我们的 jQuery 代码然后提取内容并将其分配给 `$response`，然后首先提取标题，然后每个段落，并将它们附加到 `#info` div 中。

此时值得注意的是，我们可以使用类似以下语句引用每个提取的段落：

```js
var $description1 = $('<p>').text($response.find(".description:eq(0)").text());
```

然而，这是提取文本的一种低效方式 - 我们必须多次运行代码来引用后续的值，这会给我们的服务器带来不必要的负载。

# 提高静态站点加载数据的速度

现在我们已经看到了一个 AJAX 示例的实际操作，也许让你惊讶的是，即使在我们在屏幕上显示的少量文本中，使用的代码并不 *技术上* 是尽可能高效的。

嗯？我听到你在问 - 我们真的不能改进这样一个简单的演示吗？好吧，尽管可能有些奇怪，但我们确实可以做出改进。让我们看看我们可以使用哪些技巧来减少代码中的任何缓慢 - 并不是所有的技巧都只是简单地改变我们的代码：

+   减少 AJAX 请求的数量 - 不，我没有疯掉；改善我们的代码并不总是意味着改变代码本身！如果我们考虑每次 AJAX 请求何时发出，可能会有机会减少数量，如果重新排序意味着我们可以达到相同的结果。例如，如果我们有一个基于定时器发出的 AJAX 请求，我们可以设置一个标志来指示仅在进行更改时才执行 AJAX 请求。

+   如果我们需要获取内容，那么简单地使用 GET 往往更有效，而不是 POST - 前者只是检索内容，而后者会导致服务器反应，例如更新数据库记录。如果我们不需要执行操作，则使用 GET 完全足够了。

+   当更新页面内容时，请确保只更新少量内容；如果我们的页面设置为更新大量内容而不是定义的部分，则会影响 AJAX 性能。

+   减少要传输的数据量 - 记得我说过我们的代码可以做出改变吗？这就是我们可以做出改变的地方 - 虽然我们不需要限制我们检索的内容，但我们可以从使用 HTML 格式更改为纯文本。这允许我们删除标记标签，从而减少我们的内容。当然，我们也可以完全反向，转而使用 XML，但这不会不增加数据大小！

+   我们还应该检查我们的服务器是否已正确配置 - 要检查的两个关键领域是使用 ETags（或实体标签），以及服务器是否设置为发送正确的过期或 Cache-Control 头用于提供的内容，如下例所示：![通过静态网站改善数据加载速度](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00376.jpeg)

+   简而言之，如果服务器检测到某个 URL 的 ETags 没有更改，它将不会发送任何响应。

    ### 小贴士

    如果您想了解更多关于 ETags 及其在浏览器中的工作方式，请访问 [`en.wikipedia.org/wiki/HTTP_ETag`](http://en.wikipedia.org/wiki/HTTP_ETag)。

+   我们可以通过在正确的时间仅创建和销毁 `XMLHttpRequest` 来进一步限制 AJAX 请求的影响 - 如果它们只在某些情况下需要，那么这将对 AJAX 性能产生显著影响。例如，如果我们的代码没有活动类，我们可能只会启动 AJAX 请求：

    ```js
    if (!($this).hasClass("active")) {
    ...perform our ajax request here...
    }
    ```

+   确保您的回调函数设置正确 - 如果我们的代码已更新，那么我们需要告诉我们的用户，并且不要让他们等待；毕竟，我们最不想做的事情就是陷入回调地狱的陷阱！（本章后面我们将更详细地介绍这个问题。）

我们甚至可以进一步！我们可以通过缓存内容来减少对服务器的不必要调用。但是，在你说“我知道”的之前，我还没说在哪里呢！

是的——在这种情况下，*where* 是关键，而 *where* 是 - localStorage。这是内置在每个浏览器中的，可以用来消除不断击中服务器的需要。虽然您可以存储的量因浏览器而异（通常为 5 MB，但最高可达 20 MB），但对于每个浏览器，它使用相同的原则工作——内容必须存储为文本，但可以包括图像和文本（在合理范围内！）。

有兴趣吗？使用一个简单的插件并对代码进行一些小修改，我们可以快速实现一个可行的解决方案——让我们重新审视一下我们之前的基本 AJAX 演示，并立即进行这些更改。

# 使用 localStorage 缓存 AJAX 内容

使用 AJAX 需要仔细考虑——重要的是在适当的点获取正确数量的内容，而不是对服务器进行太多不必要的请求，这一点很重要。

我们已经看到了一些可以帮助减少 AJAX 请求影响的技巧。其中一种更为冒险的方式是将内容存储在每个浏览器的 **localStorage** 区域中——我们可以使用 AJAX 预过滤器来实现这一点。开发者 Paul Irish 已经将完成此操作所需的代码封装在一个插件中，该插件可在 [`github.com/paulirish/jquery-ajax-localstorage-cache`](https://github.com/paulirish/jquery-ajax-localstorage-cache) 获取。

我们将使用它来修改我们之前的 `basicajax` 演示。让我们看看我们将如何做到这一点：

1.  让我们从随附本书代码下载中提取 `basicajax` 演示文件夹的副本，并将其保存到我们的项目区域。

1.  接下来，我们需要下载插件——这可以在 [`github.com/paulirish/jquery-ajax-localstorage-cache/archive/master.zip`](https://github.com/paulirish/jquery-ajax-localstorage-cache/archive/master.zip) 获取。从 zip 文件中提取 `jquery-ajax-localstorage-cache.js`，并将其保存到 `basicajax` 中的 `js` 子文件夹中。

1.  我们需要对 JavaScript 和 HTML 标记进行一些更改。让我们首先更改 JavaScript。在 `basicajax.js` 中，按如下所示添加以下两行：

    ```js
     localCache: true,
       error: function() {
     cacheTTL: 1,

    ```

1.  在 `basicajax.html` 中，我们需要引用新的插件，因此继续修改脚本调用，如下所示：

    ```js
      <script src="img/basicajax.js"></script>
      <script src="img/jquery-ajax-localstorage-cache.js"></script>
    </head>
    ```

1.  如果我们重新运行演示并点击按钮加载内容，从视觉上不应该看到任何不同；如果我们启动 Firebug，切换到 **Net** 选项卡，然后点击 **JavaScript**，则更改将显而易见：![使用 localStorage 缓存 AJAX 内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00377.jpeg)

1.  如果我们进一步探索，现在我们可以看到我们的 AJAX 内容被存储在浏览器的 **localStorage** 区域中的迹象：![使用 localStorage 缓存 AJAX 内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00378.jpeg)

    ### 提示

    如果您想要查看所有 localStorage 设置，请尝试下载并安装 FireStorage Plus! 插件，该插件可以从 [`addons.mozilla.org/en-US/firefox/addon/firestorage-plus/`](https://addons.mozilla.org/en-US/firefox/addon/firestorage-plus/) 获取。

现在我们可以使用 jQuery 和`localStorage.getItem`或`localStorage.clearItem`方法来操纵该区域中的所有内容。如果你想了解更多，可以参考我的书*HTML5 Local Storage How-to*，该书可在 Packt Publishing 上获得。

### 注意

本书附带的代码下载中有这段代码的可运行版本，位于`basicajax-localstorage`文件夹中。

也许有时候你会发现你想将缓存 TTL 值减少到几分钟（甚至几秒钟？）。你可以通过修改`jquery-ajax-localstorage-cache.js`中的第 70 到 72 行，并删除一个乘数来实现，留下以下内容：

```js
if ( ! ttl || ttl === 'expired' ) {
  localStorage.setItem( cacheKey  + 'cachettl', +new Date() + 1000 * 60 * hourstl );
}
```

让我们改变方向。我们先前提到当处理 AJAX 时，提高性能的一种方法是确保我们尽量减少请求的数量。如果我们的代码包含多个请求，将对性能产生不利影响，特别是如果我们必须等待每个请求完成后才能开始下一个请求。

我们可能会使用 localStorage 来减少影响，通过在浏览器内请求内容，而不是从服务器请求；这样做是可行的，但可能不适用于每种类型的请求。相反，正如我们将在后面看到的，有更好的替代方法可以轻松处理多个请求。让我们更详细地探讨一下这个问题，首先从使用回调来处理多个请求的影响开始。

# 使用回调处理多个 AJAX 请求

当使用 AJAX 时，我们可以使用`$.Callbacks`对象来管理回调列表—可以使用`callbacks.add()`方法添加回调，使用`.fire()`触发，使用`.remove()`方法移除。

如果我们决定在需要的时候才出现内容，而不是一直存在的情况下，通常我们会启动一个单一的 AJAX 请求。这样做没有错—这是一种完全有效的工作方式，可以减少页面刷新的需求。

但是，如果我们决定必须同时执行多个请求，并且需要每个请求都完成后才能继续，那么情况将变得混乱。

```js
// Get the HTML, then get the CSS and JavaScript
$.get("/feature/", function(html) {
  $.get("/assets/feature.css", function(css) {
    $.getScript("/assets/feature.js", function() {

      // All is ready now, so...add CSS and HTML to the page
      $("<style />").html(css).appendTo("head");
      $("body").append(html);
    });
  });
});
```

我们可能需要等一会儿！

这里的问题是当处理多个请求时响应速度很慢，尤其是如果所有请求都必须在我们继续之前完成。我个人肯定不想等待一个响应速度慢的页面完成！

为了避免许多人喜欢称之为**回调地狱**的情况，我们可以使用另一种方法——jQuery 的 Deferreds 和 Promises。这可以被视为一种特殊形式的 AJAX。在接下来的几页中，我们将深入探讨这项技术的奥秘，并通过一个简单的示例来演示，你可以将其作为将来开发自己想法的基础。

### 提示

甚至有一个专门讨论回调地狱的网站—你可以在[`callbackhell.com/`](http://callbackhell.com/)上查看它—绝对值得一读！

让我们看看 Deferreds 和 Promises 如何在 jQuery 中工作，以及如何使用它来增强我们的代码。

# 用 jQuery Deferreds 和 Promises 增强你的代码

尽管 Deferreds 和 Promises 听起来像是一种相对新的技术，但它们早在 1976 年就已经可用了。简而言之：

+   Deferred 代表了一个尚未完成的任务

+   Promise 是一个尚未知晓的值

如果我们必须使用标准 AJAX，那么我们可能必须等待每个请求完成才能继续。这在使用 Deferreds / Promises 时是不必要的。当使用 Deferreds / Promises 时，我们不必等待每个请求被处理。我们可以通过`jQuery.Deferred()`对象排队多个请求以同时触发它们，并单独或一起管理它们，即使每个请求可能需要不同的时间来完成。

如果您的应用程序使用了 AJAX 启用的请求，或者可能受益于使用它们，那么花时间熟悉 Deferreds 和 Promises 是值得的。

在使用标准 AJAX 时，一个关键的缺陷是缺乏来自任何 AJAX 调用的 *标准* 反馈 - 很难判断何时完成了某事。jQuery AJAX 现在创建并返回一个 Promise 对象，该对象将在与之绑定的所有操作都完成时返回一个 promise。使用 jQuery，我们会使用`when()`、`then()`和`fail()`方法来实现以下方式：

```js
$.when($.get("content.txt"))
  .then(function(resp) {
    console.log("third code block, then() call");
    console.log(resp);
  })
  .fail(function(resp) { console.log(resp); });
```

我们可以使用以下图表来表示使用 Deferreds 和 Promises 的工作原理：

![用 jQuery Deferreds 和 Promises 增强你的代码](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00379.jpeg)

使用 Deferreds 的关键好处是我们可以开始链接多个函数，而不仅仅是一次调用一个函数（这是标准 AJAX 的情况）。然后，我们可以从`jQuery.Deferred`列表内部`.resolve()`或`.reject()`单个 Deferreds，并使用`.success()`、`.fail()` 或 `error()` 事件处理程序提供一致的机制来确定如果 Deferreds 成功或失败应该发生什么。

最后，我们可以调用`.done()`事件处理程序来确定在与我们的 Promise 绑定的操作完成后应该发生什么。

### 注意

如果您想了解更多关于 Deferreds 和 Promises 的内部工作原理的信息，请查阅 [`github.com/promises-aplus/promises-spec`](https://github.com/promises-aplus/promises-spec)，尽管它可能会让人感觉有些枯燥（无意冒犯！）。

现在我们已经了解了 Deferreds 和 Promises 的基础知识，让我们改变一下方向，看看如何在实际中使用这两者，并概述为什么值得花时间了解它们背后的概念。

# 使用 Deferreds 和 Promises

切换到使用 Deferreds 和 Promises 需要一些时间，但值得花费精力去理解它们的工作原理。为了感受使用 Deferreds 和 Promises 的好处，让我们来看看将它们融入我们的代码中的一些优势：

+   **更清晰的方法签名和统一的返回值**：我们可以将决定任何请求结果如何处理的代码分离出来，这样读起来更清晰，如果需要，还可以进行链式调用，如下所示：

    ```js
      $.ajax(url, settings);
      settings.success(data, status, xhr);
      settings.error(data, status, errorThrown);
      settings.always(xhr, status)
    ```

+   **容易组合在一起**：我们不需要在每个请求中加入复杂的函数来管理处理；这意味着启动每个请求所需的核心代码大大简化，如下面的示例所示：

    ```js
      function getEmail(userEmail, onSuccess, onError) {
         $.ajax("/email?" + userEmail, {
           success: onSuccess,
           error: onError
         });
       }
    ```

+   **容易链式调用语句**：Deferred / Promise 的架构允许我们将多个事件处理程序链接在一起，这样我们就可以通过单个操作触发多个方法，如下所示：

    ```js
      $("#button").clickDeferred()
         .then(promptUserforEmail)
         .then(emailValidate)
    ```

+   **Promises 总是异步执行**：它们甚至可以在我们不知道哪些回调函数将使用 Promises 生成的值之前就被触发，而不管任务是否完成。Promises 将存储生成的值，我们可以从现有的回调函数中调用该值，或者在生成 Promise 后添加任何回调函数时调用。

+   **异常式错误传递**：通常在 AJAX 中，我们需要使用一系列的 `if…then…else` 语句，这样做会使工作方式复杂（有时还会脆弱）。使用 Promises，我们只需链式连接一个或多个 `.then()` 语句来处理任何结果，如下所示：

    ```js
    getUser("Alex")
      .then(getFriend, ui.error)
      .then(ui.showFriend, ui.error)
    ```

    ### 提示

    关于 Promises，有很多内容我们无法在这里详细介绍。关于将 Promises 与标准 AJAX 请求进行比较的有用讨论，请查看[此处的讨论](http://stackoverflow.com/a/22562045)。

还记得我们之前审查的关于*使用回调函数处理多个 AJAX 请求*的代码吗？使用多个回调函数的主要缺点是结果混乱（最终影响了我们网站的性能）——显然我们需要一个更好的替代方案！

Deferreds 和 Promises 的美妙之处在于它允许我们重构代码，使其更易于阅读。这不仅包括我们需要作为请求的一部分运行的命令，还包括成功或失败时发生的情况。让我们重新审视一下之前的代码片段，并看看当重写为使用 Deferreds / Promises 时会是什么样子：

```js
$.when(
  // Get the HTML, CSS and JS
  $.get("/feature/", function(html) {
    globalStore.html = html;
  }),
  $.get("/assets/feature.css", function(css) {
    globalStore.css = css;
  }),
  $.getScript("/assets/feature.js")
).then(function() {
  // All is ready now, so...add the CSS and HTML to the page
  $("<style />").html(globalStore.css).appendTo("head");
  $("body").append(globalStore.html);
});
```

希望您会同意，它看起来明显更清晰了，现在我们可以从单个过程中运行多个请求，而不必等待每个请求完成后再进行下一个请求！

现在是编写一些代码的时候了，我认为——让我们利用 Deferreds 和 Promises，并构建一个使用 AJAX 的演示。我们将看到如何使用它来响应表单提交，而无需刷新页面。

# 修改我们的高级联系表单

在我们的实际示例的第一部分中，我们将重新使用并开发本章前面创建的基本 AJAX 表单，并从第四章中的 *使用 jQuery 开发高级文件上传表单* 演示中获取，*与表单一起工作*。我们将调整它以使用 AJAX 显示提交确认，并且确认也会显示为电子邮件。

对于这个练习，我们需要准备一些工具：

+   使用默认设置安装本地 Web 服务器 - 选项包括 WAMP（适用于 PC - [`www.wampserver.de`](http://www.wampserver.de) 或 [`www.wampserver.com/en/`](http://www.wampserver.com/en/)），或者 MAMP（适用于 Mac，[`www.mamp.info/en/`](http://www.mamp.info/en/)）。Linux 用户可能已经作为其发行版的一部分拥有可用的工具。您需要确保您的 PHP 版本为 5.4 或更高，因为代码依赖于如果使用较旧版本将会中断的功能。您也可以尝试跨平台解决方案 XAMPP，可从 [`www.apachefriends.org/index.html`](https://www.apachefriends.org/index.html) 获取（请注意，如果使用此选项则不需要测试邮件工具 - 电子邮件支持已包含在 XAMPP 中）。

+   免费的测试邮件服务器工具（仅限 Windows），可从 [`www.toolheap.com/test-mail-server-tool/`](http://www.toolheap.com/test-mail-server-tool/) 获取。从本地 Web 服务器发送电子邮件可能很难设置，因此这个出色的工具监视端口 25 并提供本地发送电子邮件的功能。对于 Mac，您可以尝试[`discussions.apple.com/docs/DOC-4161`](https://discussions.apple.com/docs/DOC-4161)中的说明；Linux 用户可以尝试遵循[`cnedelcu.blogspot.co.uk/2014/01/how-to-set-up-simple-mail-server-debian-linux.html`](http://cnedelcu.blogspot.co.uk/2014/01/how-to-set-up-simple-mail-server-debian-linux.html)中概述的步骤。

+   访问正在使用的个人电脑或笔记本电脑的电子邮件包 - 这是接收使用测试邮件服务器工具发送的电子邮件所必需的。

好的 - 工具已经准备就绪，让我们开始吧：

1.  我们将从打开附带本书的代码下载的副本开始，并提取`ajaxform`文件夹；这个文件夹包含我们演示的标记、样式和各种文件。我们需要将该文件夹保存到 Web 服务器的`WWW`文件夹中，对于 PC（通常为`C:\wamp\www`）。

1.  标记相对简单，并且与本章中我们已经看到的非常相似。

1.  我们需要对`mailer.php`文件进行一个小小的更改 - 在您选择的文本编辑器中打开它，然后查找以下行：

    ```js
            $recipient = "<ENTER EMAIL HERE>";
    ```

    将`<ENTER EMAIL HERE>`更改为您可以用来检查邮件是否出现的有效电子邮件地址。

1.  这个演示的魔法发生在`ajax.js`中，所以现在让我们来看一下，首先设置一些变量：

    ```js
      $(function() {
         var form = $('#ajaxform');
         var formMessages = $('#messages');
    ```

1.  当按下**发送**按钮时，我们开始了真正的魔术。我们首先阻止表单提交（因为它的默认操作），然后将表单数据序列化为一个字符串以进行提交：

    ```js
    $(form).submit(function(e) {
      e.preventDefault();
      var formData = $(form).serialize();
    ```

1.  接下来是此表单的 AJAX 操作的核心。此函数设置要执行的请求类型，内容将被发送到哪里，以及要发送的数据：

    ```js
    $.ajax({
      type: 'POST',
      url: $(form).attr('action'),
      data: formData
    })
    ```

1.  然后我们添加了两个函数来确定接下来该发生什么 - 第一个处理表单成功提交的情况：

    ```js
    .done(function(response) {
      $(formMessages).removeClass('error');
      $(formMessages).addClass('success');
      $(formMessages).text(response);
      $('#name').val('');
      $('#email').val('');
      $('#message').val('');
    })
    ```

1.  接下来是处理表单提交失败结果的函数：

    ```js
    .fail(function(data) {
      $(formMessages).removeClass('success');
      $(formMessages).addClass('error');
      if (data.responseText !== '') {
        $(formMessages).text(data.responseText);
      } 
      else {
        $(formMessages).text('Oops! An error occured and your 
        message could not be sent.');
      }
      });
      });
    });
    ```

1.  双击启动电子邮件测试服务器工具。如果我们在浏览器中预览表单，并填写一些有效的详细信息，当提交时我们应该会看到以下图片：![修改我们的高级联系表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00380.jpeg)

我们的表单现在已经就位，并且能够提交，确认邮件将在几分钟内出现。在下一章中，我们将更深入地讨论 jQuery 中的 AJAX 使用；现在让我们继续开发我们的表单。

## 使用 AJAX 添加文件上传功能

添加文件上传功能相对简单；它需要客户端和服务器端组件才能正常运行。

在我们的示例中，我们将更专注于客户端功能。为了演示目的，我们将上传文件到项目区域内的一个虚拟文件夹。以下是我们将构建的内容示例的屏幕截图：

![使用 AJAX 添加文件上传功能](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00381.jpeg)

为了帮助我们进行这个演示，我们将使用 BlueImp 文件上传插件；它超过 1300 行代码，是一个非常全面的插件！这个插件与 BlueImp 的基于 PHP 的文件处理插件以及一些额外的 jQuery UI 一起，将有助于创建一个可用的文件上传设施。

### 注意

插件文件的副本可在伴随本书的代码下载中找到，也可以在[`github.com/blueimp/jQuery-File-Upload`](https://github.com/blueimp/jQuery-File-Upload)上找到。

让我们开始吧：

1.  我们将首先提取伴随本书的代码下载中`ajaxform-files`文件夹的副本 - 这个文件夹中包含了 BlueImp 文件上传插件，以及一些额外的自定义 CSS 和 JavaScript 文件。

1.  将`ajaxform-files`文件夹中的文件添加到存储在 web 服务器文件夹内的`ajaxform`文件夹中；JavaScript 文件应放在`js`文件夹中，CSS 样式表应放在`css`文件夹中，而 2 个 PHP 文件可以放在我们的`ajaxform`文件夹的根目录中。

1.  接下来，我们需要打开上一个练习中的`ajaxform.html`文件的副本 - 我们首先需要添加一个链接到`fileupload.css`，其中包含了我们上传表单的一些额外样式：

    ```js
      <link rel="stylesheet" href="css/bootstrap.min.css">
      <link rel="stylesheet" href="css/styles.css">
     <link rel="stylesheet" href="css/fileupload.css">

    ```

1.  我们同样需要引用我们刚刚下载的额外 JavaScript 文件 - 将以下突出显示的链接添加到`ajax.js`的引用下面，如下所示：

    ```js
    <script src="img/ajax.js"></script>
    <script src="img/jquery.ui.widget.js"></script>
    <script src="img/jquery.iframe-transport.js"></script>
    <script src="img/jquery.fileupload.js"></script>
    <script src="img/uploadfiles.js"></script>

    ```

1.  接下来是对`index.html`的一些标记更改。因此，在`ajaxform.html`中，首先按照下面的步骤更改标题：

    ```js
    <div id="formtitle"><h2>AJAX File Upload Demo</h1></div>
    <div id="form-messages"></div>
    ```

1.  现在我们需要添加文件上传代码，所以在消息字段的`</div>`标签关闭后立即添加以下代码：

    ```js
    <div class="container">
      Click the button to select files to send:
      <span class="btn btn-success fileinput-button">
        <span>Select files...</span>
        <input id="fileupload" type="file" name="files[]" multiple>
      </span> 
      <p>Upload progress</p>
      <div id="progress" class="progress progress-success progress-striped">
       <div class="bar"></div>
      </div>
      <p>Files uploaded:</p>
      <ul id="files"></ul>
    </div>
    ```

1.  保存所有文件。—如果我们使用本地 Web 服务器预览结果，那么我们应该期望看到更新后的表单，现在在表单底部显示一个文件上传区域。

### 提示

如果您想看到已经进行了更改的版本，那么在随附本书的代码下载中的`ajaxform-completed`文件夹中有一个完成的代码版本。

## 检查演示中使用 Promises 和 Deferreds

尽管我们在此演示的第二部分中所做的更改相对简单，但它们隐藏了丰富的功能。要了解 AJAX 的使用方式，有必要详细查看`jquery.fileupload.js`插件的源代码。

如果我们打开`ajax.js`的副本，我们可以清楚地看到 jQuery 的 Deferred 对象的使用，形式为`.done()`，如下所示的摘录：

```js
.done(function(response) {
  $(formMessages).removeClass('error');
  ....
})
```

然而，如果我们的 AJAX 代码失败了，jQuery 将执行`.fail()`事件处理程序中概述的方法或函数：

```js
.fail(function(data) {
  $(formMessages).removeClass('success');
  ....
});
```

如果我们转而查看`uploadfiles.js`中的代码，我们可能会认为它根本没有使用 AJAX。相反，AJAX 被使用了，但是在`jquery.fileupload.js`插件中。

如果我们在文本编辑器中打开插件文件，我们可以看到很多 Deferreds 和 Promises 的实例。让我们看一些摘录作为示例：

+   从`upload`方法 - 第 762-766 行：

    ```js
      jqXHR = ((that._trigger('chunksend', null, o) !== false && $.ajax(o)) || that._getXHRPromise(false, o.context))
         .done(function (result, textStatus, jqXHR) {
    ```

+   在同一方法中，但这次是从第 794-804 行：

    ```js
          .fail(function (jqXHR, textStatus, errorThrown) {
            o.jqXHR = jqXHR;
            o.textStatus = textStatus;
    ```

+   这次，从私有的`_onSend`方法，在第 900-904 行：

    ```js
      ).done(function (result, textStatus, jqXHR) {
         that._onDone(result, textStatus, jqXHR, options);
       }).fail(function (jqXHR, textStatus, errorThrown) {
         that._onFail(jqXHR, textStatus, errorThrown, options);
       }).always(function (jqXHRorResult, textStatus, jqXHRorError) {
    ```

这些只是一些示例，说明了我们如何使用 Deferreds 和 Promises 来增强我们的代码。希望这给您留下了一些可能性的味道，以及我们如何显着改善代码的可读性以及项目的性能。

# 详细介绍 AJAX 最佳实践

在本章中，我们重新访问了基础知识，并探讨了一些可以用来提升 AJAX 知识的技巧 - 关键不仅仅是编码，还有一些提示和技巧，可以帮助我们成为更全面的开发人员。

在“使用 Deferreds 和 Promises”部分，我们探讨了使用 jQuery 的 Deferreds 和 Promises 的基础知识，以及在使用它们时架构的变化如何导致性能显著提高。在我们总结本章之前，有一些额外的最佳实践，我们应该尽可能遵循。以下列表解释了它们：

1.  没有必要直接调用`.getJson()`或`.get()`。这些在使用`$.ajax()`对象时默认调用。

1.  调用请求时不要混合协议。最好尽可能使用无模式请求。

1.  如果您只是进行 GET 请求，请尽量避免将请求参数放在 URL 中 - 而是使用 `data` 对象设置来发送它们，如下所示：

    ```js
    // Less readable
    $.ajax({
        url: "something.php?param1=test1&param2=test2",
        ....
    });

    // More readable
    $.ajax({
        url: "something.php",
     data: { param1: test1, param2: test2 }
    });
    ```

1.  尝试指定 `dataType` 设置，以便更容易知道您正在处理的数据类型。例如，请参考本章前一节中的 *使用 AJAX 创建简单示例*。

1.  使用委托事件处理程序将事件附加到使用 AJAX 加载的内容。委托事件可以处理稍后添加到文档中的后代元素的事件：

    ```js
    $("#parent-container").on("click", "a", delegatedClickHandler);
    ```

### 提示

要了解更多，请参阅[`api.jquery.com/on/#direct-and-delegated-events`](http://api.jquery.com/on/#direct-and-delegated-events)。

# 摘要

AJAX 作为一种技术已经存在多年。可以说它是一个改变游戏规则的技术，在这里，JavaScript 的使用消除了在浏览器中不断刷新页面内容的需求。jQuery 已经帮助增强了这一系列技术。在本章中，我们重新审视了一些基础知识，然后探讨了如何更好地提升我们的开发技能。让我们回顾一下我们学到的内容：

我们首先简要回顾了 AJAX 是什么，并提醒自己构建 jQuery 中 AJAX 请求的基础知识。

接下来，我们看了一些可以用来提高静态站点加载速度的技巧；我们学到了一项额外的技巧，即使用 localStorage 缓存内容。然后，我们讨论了如何实现回调可能会使代码混乱和缓慢，然后转而看到 Deferreds 和 Promises 如何改进我们的代码，最终改进了我们的站点的性能。

最后，我们看了一个演示，在这个演示中，我们借用了第四章中的一个表单，*与表单一起工作*，并通过首先添加基于 AJAX 的通知，然后利用 BlueImp 插件来扩展它，以实现一个文件上传功能，该功能利用了 Deferreds 和 Promises。

在下一章中，我们将深入研究我个人最喜欢的一个主题。是时候加入动画了，我们将看看如何使用 jQuery 为我们的网站元素赋予生命。


# 第六章 在 jQuery 中进行动画

举手喜欢静态网站的人？想不到吧，为网站添加动画效果能赋予其生命；但过度使用可能会带来灾难性的后果！

我们经常用来为网站注入生命力的两个常见效果是 AJAX 和动画；我们在前一章节详细介绍了前者。在本章中，我们将探讨何时使用 jQuery 而不是 CSS（或反之），如何更好地管理队列，以及如何实现一些漂亮的自定义动画效果。您还将看到如何轻松创建一些有用的自定义缓动效果，作为将来转换为 CSS 等效的基础。在本章中，我们将涵盖以下主题：

+   何时使用 CSS 而不是 jQuery

+   管理或避免 jQuery 动画队列

+   设计自定义动画

+   实现一些自定义动画

+   在响应式网站中进行动画

准备好开始了吗？让我们开始吧……

# 选择 CSS 还是 jQuery

让我们从一个问题开始这个话题。

看一看 Dia do Baralho 网站，托管在 [`www.diadobaralho.com.br`](http://www.diadobaralho.com.br) - 你们中有多少人认为你在那里看到的动画是仅使用 jQuery 创建的？

如果您认为是的话，那么很抱歉让您失望了；实际上答案是不是！如果您仔细查看源代码，您会发现有些地方同时使用了 CSS3 动画和 jQuery。现在，您可能会想：为什么我们在谈论掌握 jQuery 的书籍时要讨论 CSS3 动画呢？

这是有道理的；还记得我之前在书中提到过的，拥有正确技能的任何个体都可以编写 jQuery 吗？普通编码人员和优秀开发人员的区别在于：为什么我会使用 jQuery？现在，这听起来可能让人觉得我疯了，但我没有。让我解释一下我的意思，如下所示：

+   CSS3 动画不依赖于外部库；考虑到 jQuery 仍然有一定的大小，少一个资源请求总是一件好事！

+   对于简单轻量的动画，如果 CSS3 动画足够，引用 jQuery 是没有好处的。尽管需要提供相同语句的供应商前缀版本（并且不使用 jQuery），但所需的代码量可能比使用 jQuery 少。

使用 jQuery 会有性能影响，这使得使用 CSS 动画更加诱人，原因有几个：

+   这个库从来没有被设计成一个高性能的动画引擎；它的代码库必须服务于许多目的，这可能导致布局抖动。

+   jQuery 的内存消耗通常意味着我们需要进行垃圾收集，这可能会导致动画短暂冻结

+   jQuery 使用 `setInterval` 而不是 `requestAnimationFrame` 来管理动画（尽管这是由于即将推出的 jQuery 版本的更改）

同样有许多理由支持我们使用 jQuery；尽管它作为一个库有其局限性，但在某些情况下，我们可能需要在原生 CSS3 动画的位置使用 jQuery，如下所述：

+   CSS 动画对 GPU 负荷较大，在浏览器负载较高时可能会导致卡顿和色带效应——这在移动设备上尤为普遍。

    ### 注意

    有关硬件加速和 CSS3 的影响的讨论，请访问[`css-tricks.com/myth-busting-css-animations-vs-javascript/`](http://css-tricks.com/myth-busting-css-animations-vs-javascript/)。

+   大多数浏览器都支持 CSS3 动画，但 IE9 或更低版本除外；对于这种情况，必须使用 jQuery。

+   CSS3 动画目前（还）不及 jQuery 的灵活——它们一直在不断发展，因此总会有一天两者变得非常相似。例如，在使用 CSS3 时，我们不能在关键帧中使用不同的缓动方式；整个关键帧必须应用相同的缓动方式。

这里的关键点是，我们有自由选择的权利；事实上，正如开发者 David Walsh 所指出的，当我们只需要简单的状态更改时，使用 CSS3 动画更为明智。他的论点是基于能够在样式表中保留动画逻辑，并从多个 JavaScript 库中减少页面的臃肿。

但要注意，如果您的需求更复杂，则 jQuery 是前进的道路；开发者 Julian Shapiro 认为，使用动画库可以保持每个动画的性能，并使我们的工作流程易于管理。

### 注意

要查看使用 JavaScript 或 CSS 对多个对象进行动画效果的效果，请转到[`css3.bradshawenterprises.com/blog/jquery-vs-css3-transitions/`](http://css3.bradshawenterprises.com/blog/jquery-vs-css3-transitions/)，该网站展示了一个非常启发性的演示！

只要我们在使用 CSS 方面小心谨慎，对于简单的、自包含的状态动画，更明智的做法是使用原生 CSS3，而不总是依赖 jQuery 来解决我们所有的需求。

顺便提一句，值得注意的是，有一个相对较新的 API 正在考虑中：Web Animations API。该 API 旨在使用 JavaScript 创建效率与原生 CSS3 动画相同的动画。鉴于我们在使用 jQuery 时存在的固有问题，这值得关注；截至撰写本文时，该 API 的支持仅限于 Chrome 和 Opera。

### 提示

要了解 Web Animations API 的支持细节，请查看 [Can I use 网站](http://caniuse.com/#search=Web%20animation)；[`updates.html5rocks.com/2014/05/Web-Animations---element-animate-is-now-in-Chrome-36`](http://updates.html5rocks.com/2014/05/Web-Animations---element-animate-is-now-in-Chrome-36) 上也发布了一篇有用的教程——不过这只适用于 Chrome！

足够的理论，让我们进行一些编码！假设我们需要使用 jQuery 来进行我们的动画项目，那么一个主要的问题很可能会困扰开发者：在任何使用动画的功能中设置了可以设置的排队动画的快速循环。让我们深入了解一下这意味着什么，以及我们可以采取什么措施来减少或消除这个问题。

# 控制 jQuery 动画队列

如果你花费了一些时间使用 jQuery 进行开发，毫无疑问，当你在处理动画时，你会遇到一个关键问题：当你切换到另一个浏览器窗口然后再切换回来时，你看到浏览器循环执行多个排队的动画多少次？

我敢打赌，答案是相当多次；这个问题的关键在于 jQuery 排队执行所有被要求执行的动画。如果发生了太多的初始化，那么 jQuery 的动画队列就会混乱，因此它似乎会变得疯狂！在解决问题之前，让我们先看看问题是如何出现的：

1.  从附带本书的代码下载中提取 `blockedqueue.html` 和 `blockedqueue.css` 文件，它们将提供一些简单的标记以说明我们的排队问题。

1.  在文本编辑器中，将以下内容添加到一个新文件中，并将其保存为我们项目区域的 `js` 子文件夹中的 `blockedqueue.js`：

    ```js
    $(document).ready(function() {
      $(".nostop li").hover(
        function () { $(this).animate({width:"100px"},500); },
        function () { $(this).animate({width:"80px"},500); } 
      );
    });
    ```

1.  如果我们现在运行我们的演示，那么当我们重复将鼠标移动到每个条形图上时，我们可以看到它们全部快速地增加或减少，下一个条形图在前一个动画完成之前就会改变，如下图所示：![控制 jQuery 动画队列](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00382.jpeg)

显然，这种行为是不希望出现的；如果这个演示被自动化并与 `requestAnimationFrame` 结合使用（我们稍后会在第九章中介绍，*使用 Web 性能 API*），那么当我们切换到一个标签并返回到原来的标签时，我们会看到一系列动画被完成。

## 解决问题

我们如何解决这个问题？很简单；我们只需要在语句链中添加 `.stop()` 方法；这将在开始下一个动画之前清除前面的动画。让我们看看这在实践中意味着什么，通过执行以下步骤：

1.  在 `blockedqueue.html` 文件的副本中，按照以下方式修改 `<head>` 部分：

    ```js
    <title>Demo: Clearing the animation queue</title>
      <link rel="stylesheet" href="css/blockedqueue.css">
      <script src="img/jquery.min.js"></script>
     <script src="img/unblockqueue.js"></script>
    </head>
    ```

1.  我们需要在演示的主体中稍微更改标记，所以按照以下代码进行修改：

    ```js
    <div id="container">
     <ul class="stop">
        <li></li>
    ```

1.  将其保存为 `unblockqueue.html`。在一个新文件中，添加以下代码，然后将其保存为我们项目区域的 `js` 子文件夹中的 `unblockedqueue.js`。这包含了修改后的标记，以及添加了 `.stop()`：

    ```js
    $(document).ready(function() {
      $(".stop li").hover(
        function () {
          $(this).stop().animate({width:"100px"},500);
        },
        function () {
          $(this).stop().animate({width:"80px"},500);
        }
      );
    });
    ```

1.  如果我们现在运行演示，然后快速地依次移动到每个条形图上，我们应该看到条形图会依次增加和减少，但是下一个条形图在前一个条形图返回到原始大小之前不会改变，如下所示：![解决问题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00383.jpeg)

希望您同意添加`.stop()`已经显著改善了我们的代码——添加`.stop()`将终止前一个动画但排队下一个动画，准备就绪。

## 让过渡更加顺畅

我们还可以进一步。仔细查看`.stop()`可用的属性，我们可以使用`clearQueue`和`jumpToEnd`在匹配的元素上停止运行动画，从而产生更干净的过渡，如下图所示：

![让过渡更加顺畅](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00384.jpeg)

### 提示

有关使用`.stop()`的更多信息，请参阅主要的 jQuery 文档 [`api.jquery.com/stop/`](http://api.jquery.com/stop/)。

让我们修改我们的 jQuery 代码，看看这在实践中意味着什么，通过执行以下步骤：

1.  返回到`unblockedqueue.js`文件，然后按如下所示修改代码：

    ```js
      function () {
        $(this).stop(true, false).animate({width:"100px"},500);
      },
      function () {
        $(this).stop(true, false).animate({width:"80px"},500);
      }
    ```

1.  保存您的工作，然后在浏览器中预览演示的结果。如果一切顺利，您应该看不到条形图本身的任何变化，但当您将鼠标悬停在每个条形图上时，动画效果会更加顺畅。

在这个阶段，我们应该有一个仍然工作但过渡更加顺畅的动画——值得注意的是，这个技巧只适用于动画。如果您的项目使用其他函数队列，则需要使用`.clearQueue()`清除这些队列。

### 注意

为了比较使用`.stop()`的不同方式，值得看看 Chris Coyier 的演示，网址为 [`css-tricks.com/examples/jQueryStop/`](http://css-tricks.com/examples/jQueryStop/)——这产生了一些有趣的效果！类似的解释也可以在 [`www.2meter3.de/code/hoverFlow/`](http://www.2meter3.de/code/hoverFlow/) 找到。

## 使用纯 CSS 解决方案

好的，所以我们在 jQuery 中有我们的动画；对于一个简单的动画，如果我们改用纯 CSS 会是什么样子呢？虽然我们无法复制`.stop()`的相同效果，但我们可以非常接近。让我们看看这在实践中意味着什么，以`unblockedqueue.html`作为我们演示的基础：

1.  首先移除两个 JavaScript 链接，一个指向`unblockqueue.js`，另一个指向 jQuery 本身。

1.  在`blockedqueue.css`底部添加以下内容——这包含了我们演示所需的动画样式规则：

    ```js
    li { width: 50%; transition: width 1s ease-in, padding-left 1s ease-in, padding-right 1s ease-in; }
    li:hover { width: 100%; transition: width 1s ease-out, padding-left 1s ease-out, padding-right 1s ease-out; }
    ```

此时，如果我们在浏览器中预览结果，我们应该看不到动画列表元素的 *可见* 差异；真正的变化可以在使用 Google Chrome 的开发者工具栏监视时间线时看到。让我们看看这种变化是什么样子的。

1.  启动 Google Chrome。按 *Shift* + *Ctrl* + *I* 召唤**开发者工具栏**（或 *Option* + *Cmd* + *I* 适用于苹果 Mac）。

1.  单击 **Timeline** 标签，然后单击放大镜下方的灰色圆圈——圆圈将变为红色。

1.  依次将鼠标悬停在列表项上；Chrome 将监视并收集执行的操作的详细信息。

1.  几分钟后，单击红色圆圈以停止生成配置文件；您将得到类似这样的结果：![使用纯 CSS 解决方案](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00385.jpeg)

我们清楚地看到，仅 CSS 解决方案几乎不会影响浏览器的性能。相比之下，当我们运行 `unblockedqueue.html` 演示时，看一下相同的时间轴：

![使用纯 CSS 解决方案](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00386.jpeg)

注意到区别了吗？虽然这只是一个快速的非科学性测试，但当我们查看详细数字时，我们可以清楚地看到差异。

在大约 3 秒的时间内，Google Chrome 在运行仅 CSS 解决方案时花费了 33 毫秒进行渲染和 48 毫秒进行绘制。运行 `unblockedqueue.html` 显示数字几乎翻了一番：脚本 107 毫秒，渲染 78 毫秒，绘制 76 毫秒！这绝对是需要考虑的事情...

# 改进 jQuery 动画

从前面的部分，我们可以很容易地看出，在浏览器中渲染 CSS 时具有明显的优势——尽管演示中使用了某种程度上不科学的方法！

但关键点在于，尽管在使用 jQuery 时我们在灵活性和全面的浏览器支持方面获得了一些好处，但我们在速度上失去了——jQuery 从未被设计为在渲染动画时性能良好。

为了帮助提高性能，您可以探索几个插件选项：

+   **Velocity.js**：这个插件对 `$.animate()` 进行了重新设计以提供更快的性能，并且可以与或无需 jQuery 一同使用；这包括 IE8。该插件可以从 [`julian.com/research/velocity/`](http://julian.com/research/velocity/) 下载。这还包含了一些预先注册的效果——我们将在本章稍后介绍更多关于创建自定义缓动效果的内容。

+   **jQuery-animate-enhanced**：这个插件会自动检测和重新设计动画，以使用原生的 CSS 过渡效果，适用于 WebKit、Mozilla 和 IE10 或更高版本。可以从这里下载 [`playground.benbarnett.net/jquery-animate-enhanced/`](http://playground.benbarnett.net/jquery-animate-enhanced/)。

我们还可以进一步探讨使用 jQuery 在动画完成时通知我们的方法，使用 `transitionend` 事件。虽然这可能无法解决动画队列积压的原始问题，但使用 jQuery 将允许您将动画效果与您的 jQuery 逻辑分开。

### 注意

对于一个有趣的文章和演示，关于使用 `transitionend`（及其供应商前缀版本），请查看 Treehouse 网站上的一篇文章，链接在这里 [`blog.teamtreehouse.com/using-jquery-to-detect-when-css3-animations-and-transitions-end`](http://blog.teamtreehouse.com/using-jquery-to-detect-when-css3-animations-and-transitions-end)。

现在我们已经看到了如何使我们的动画更流畅，让我们继续看看如何生成定制动画；理论是我们可以利用一些知识来创建更复杂和有趣的动画，同时减少我们在运行队列时看到的一些问题。

但是，在这样做之前，我想给你留下两个有用的建议，可以帮助您改善您的动画：

+   看看[`blog.teamtreehouse.com/create-smoother-animations-transitions-browser`](http://blog.teamtreehouse.com/create-smoother-animations-transitions-browser)；它探讨了我们在动画和过渡中遇到的一些问题，以及这些问题如何影响性能。

+   该文章在[`developer.telerik.com/featured/trimming-jquery-grunt/`](http://developer. example.org/jqtrim/)探讨了如何修剪我们的 jQuery 版本，以去除不需要的功能（因此在运行动画时减少了服务器的负荷）。

让我们开始设计这些定制动画，首先看一下如何使用缓动函数。

# 介绍缓动函数

在页面上动画化任何对象或元素时，我们可以简单地将其上下滑动或从一个地方移动到另一个地方。这些都是完全有效的效果，但缺乏实际感，例如在打开抽屉时可能得到的效果。

动画并不总是以恒定的速度运动；相反，如果我们弹跳一个球或者打开抽屉时会有一些反弹，或者会有一些减速。为了实现这种效果，我们需要使用缓动函数，它们控制变化的速率。在互联网上有很多例子——一个很好的起点是[`www.easings.net`](http://www.easings.net)——或者我们可以观看一些网站上的效果，比如[`matthewlein.com/ceaser/`](http://matthewlein.com/ceaser/)。在接下来的几页中，我们将更详细地探讨这些，并且看一些技巧，可以帮助我们将动画技能推向新的高度。

# 设计定制动画

如果您花费过任何时间开发 jQuery 代码来动画页面上的对象或元素，无疑您曾使用过 jQuery UI 或者可能是插件，比如由 George Smith 创建的 jQuery Easing（[`gsgd.co.uk/sandbox/jquery/easing/`](http://gsgd.co.uk/sandbox/jquery/easing/)）。

这两种方法都是在页面上动画化对象的绝佳方法，使用缓动方法如`easeIn()`或`easeOutShine()`。问题在于两者都需要使用插件，这为我们的代码增添了不必要的负担；它们也是实现我们需要的效果的一种非常安全的方法。如果我说我们两者都不需要，只需使用 jQuery 本身就可以产生相同的效果呢？

在我介绍如何做到这一点之前，让我们看一个展示这一点的工作演示：

1.  让我们开始吧，从附带本书的代码下载中提取相关文件——对于这个演示，我们将需要以下文件的副本：

    +   `customanimate.html`：将此文件保存在项目文件夹的根区域

    +   `customanimate.css`：将此文件保存在项目文件夹的`css`子文件夹中

    +   `customanimate.js`：将此文件保存在项目文件夹的`js`子文件夹中

    打开 Sans 字体；将其保存在项目文件夹的`font`文件夹中；或者，该字体可以在[`www.fontsquirrel.com/fonts/open-sans`](http://www.fontsquirrel.com/fonts/open-sans)获取。

1.  如果你在浏览器中预览`customanimate.html`文件，然后运行演示，你应该会看到类似于这个屏幕截图的东西，其中`<div>`标签正在运行动画的中途：![设计自定义动画](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00387.jpeg)

那么，这里发生了什么？嗯，我们所用的不过是一个标准的`.animate()`，用来增加`<div>`标签的大小并将其移动到新位置。

这里没有什么新鲜的，对吧？错了，这里的“新鲜”之处实际上在于我们如何构建缓动！如果你看一下`customanimate.js`，你会找到这段代码：

```js
$(document).ready(function() {
  $.extend(jQuery.easing, {
    easeInBackCustom: function(x,t,b,c,d) {
      var s;
      if (s == undefined) s = 2.70158;
      return c*(t/=d)*t*((s+1)*t - s) + b;
    }
  })
```

我们所做的就是取得实现相同效果所需的数学，并将其包装在一个扩展了`$.easing`的 jQuery 对象中。然后我们可以在我们的代码中引用新的缓动方法，如下所示：

```js
  $("#go").click(function() {
    $("#block").animate({
     ...
    }, 1500, 'easeInBackCustom');
  });
})
```

这打开了很多可能性；然后我们可以用我们自己的创意替换自定义的缓动函数。在互联网上搜罗了很多可能性，比如这两个例子：

```js
$.easing.easeOutBack = function(t) {
  return 1 - (1 - t) * (1 - t) * (1 - 3*t);
};

$.easing.speedInOut = function(x, t, b, c, d) {
  return (sinh((x - 0.5) * 5) + sinh(-(x - 0.5)) + (sinh(2.5) + Math.sin(-2.5))) / (sinh(2.5) * 1.82);
};
```

要真正深入了解缓动函数是如何工作的，超出了本书的范围——如果你对其背后的数学感兴趣，那么互联网上有几个网站可以更详细地解释这个问题。

### 注意

两个使用缓动函数的示例包括[`upshots.org/actionscript/jsas-understanding-easing`](http://upshots.org/actionscript/jsas-understanding-easing)和[`www.brianwald.com/journal/creating-custom-jquery-easing-animations`](http://www.brianwald.com/journal/creating-custom-jquery-easing-animations)—注意，它们看起来确实有点枯燥！

简而言之，获得缓动函数的最佳来源是 jQuery 的源代码，我们可以查看每个所需的计算，并将其用作创建自己的缓动效果的基础。

这一切都很好；这是一个很好的方式来实现良好的动画，而不会产生难以理解或调试的复杂代码。但是……你知道的，我认为我们仍然可以做得更好。怎么做？很简单，如果我们能够在 jQuery 中复制一些我们可能在 CSS 过渡中看到的缓动效果呢？

## 转换为与 jQuery 一起使用

在这一点上，你可能认为我现在真的疯了；CSS 过渡使用贝塞尔曲线，当与 jQuery 的`animate()`方法一起使用时不受支持。那么，我们如何实现相同的效果呢？

答案总是在一个插件之中—尽管这与我们在以前的演示中所讨论的有所不同！然而，存在一个区别：这个插件在压缩后的大小为 0.8 KB；这明显比使用 jQuery UI 或 Easing 插件要小得多。

我们打算使用的插件是 Robert Grey 开发的 Bez 插件，网址为[`github.com/rdallasgray/bez`](https://github.com/rdallasgray/bez)；这将使我们能够使用三次贝塞尔的值，比如`0.23, 1, 0.32, 1`，这相当于`easeOutQuint`。让我们看看它的效果：

1.  我们首先需要下载并安装 Bez 插件—可以从 GitHub 上下载，网址为[`github.com/rdallasgray/bez`](https://github.com/rdallasgray/bez)；然后将其引用于`customanimate.html`，就在对 jQuery 的引用下面。

1.  接下来，打开一份`customanimate.js`的副本；然后按照下面显示的方式更改这一行，替换我们之前使用的`easeInBackCustom`动作：

    ```js
      }, 1500, $.bez([0.23, 1, 0.32, 1]));
    ```

保存这两个文件；如果您在浏览器中预览结果，您将看到与前面示例中所见不同的操作。

那么，我们是如何做到这一点的呢？这背后的诀窍是结合插件和 easings.net 网站。以`easeOutQuint`作为我们的示例缓动效果，如果我们首先访问[`easings.net/#easeOutQuint`](http://easings.net/#easeOutQuint)，我们可以看到产生我们效果所需的三次贝塞尔值：`0.86, 0, 0.07, 1`。我们所需要做的就是将它们插入到对 Bez 插件的调用中，就完成了：

```js
}, 1500, $.bez([0.86, 0, 0.07, 1]));
```

如果我们想要创建自己的三次贝塞尔效果，我们可以使用[cubic-bezier.com](http://cubic-bezier.com)来创建我们的效果；这将给我们提供需要使用的数值，如下面的截图所示：

![转换为 jQuery 使用](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00388.jpeg)

然后，我们可以像在上一个例子中那样将这些值插入到我们的对象调用中。使用这种方法的美妙之处在于，以后如果我们决定减少对 jQuery 的使用，我们可以轻松地将动画转换为 CSS3 的等效动画。

### 注意

要了解更多有关贝塞尔曲线背后理论的知识，请参阅维基百科上的文章，网址为[`en.wikipedia.org/wiki/B%C3%A9zier_curve`](http://en.wikipedia.org/wiki/B%C3%A9zier_curve)。

好的，所以我们已经学会了如何创建自己的动画缓动函数；如果我们想要使用现有库中可用的效果该怎么办？没问题，互联网上有一些很好的示例，包括以下内容：

+   [`daneden.github.io/animate.css/`](http://daneden.github.io/animate.css/)：这是 Animate.css 库的主页；我们可以使用[`github.com/jQueryKeyframes/jQuery.Keyframes`](https://github.com/jQueryKeyframes/jQuery.Keyframes)上提供的`jQuery.Keyframes`插件来复制此库中的效果。

+   [`github.com/yckart/jquery-custom-animations`](https://github.com/yckart/jquery-custom-animations)：这个库包含了许多不同的效果，以类似于 jQuery UI 的风格创建；可以轻松使用并以类似于本章前面 *设计自定义动画* 演示中的方式引用效果。

+   [`github.com/ThrivingKings/animo.js`](https://github.com/ThrivingKings/animo.js)：Animo.JS 采用了不同的方法；它不使用 jQuery 的 `animate()` 函数，而是使用自己的 `animo()` 方法来对对象进行动画处理。它使用了 `Animate.css` 库中的效果，该库由 Dan Eden 创建——虽然有人可能会争论是否值得额外开销，但它仍然值得一看，可能是你项目中动画的可能来源之一。

+   [`lvivski.com/anima/`](http://lvivski.com/anima/)：值得仔细查看这个库；源代码中包含了 `easings.js` 源文件中的许多三次贝塞尔值。如果需要的话，这些可以轻松地移植到你自己的代码项目中，或者可以为你自己的示例提供灵感。

是时候将我们所学到的动画概念投入到实践中了；让我们继续，看看如何在我们自己的项目中使用动画的一些例子。

# 实现一些自定义动画

在本章中，我们探讨了使用 jQuery 对对象进行动画处理，并看到了这与基于 CSS 的动画的比较；我们还看到了如何创建一些自定义的缓动模式，以控制元素在屏幕上的移动方式。

够了解理论，让我们深入一些实际应用吧！在接下来的几页中，我们将看一些元素动画的例子；我们将包括一些响应式网站的示例，因为这是一个热门话题，随着移动设备用于访问互联网内容的增加。

让我们开始吧，看看如何对一个简单的元素进行动画处理，以按钮的形式——注意演示结束时的转折！

## 对按钮进行动画处理

谦逊的按钮必须是任何网站上最重要的元素之一；按钮有各种形状和大小，并且可以通过标准的 `<button>` HTML 元素或使用 `<input>` 字段创建。

在这个演示中，我们将使用 jQuery 不仅来滑入和滑出按钮图标，还将同时旋转它们。但是等等——我们都知道 jQuery 不支持元素的旋转，对吗？

我们可以使用插件，例如 QTransform（[`github.com/puppybits/QTransform`](https://github.com/puppybits/QTransform)），甚至是 jQuery Animate Enhanced（[`playground.benbarnett.net/jquery-animate-enhanced/`](http://playground.benbarnett.net/jquery-animate-enhanced/)），但这样会增加负担，我们采用不同的方式。相反，我们将使用 Monkey Patch 直接改造支持；为了证明它有效，我们将更新**Codrops**演示，该演示在其网站上有原始版本的滚动按钮，现在将使用 jQuery 2.1。

### 注意

此演示的原始版本可在[`tympanus.net/codrops/2010/04/30/rocking-and-rolling-rounded-menu-with-jquery/`](http://tympanus.net/codrops/2010/04/30/rocking-and-rolling-rounded-menu-with-jquery/)找到。

让我们看看演示：

1.  从本书附带的代码下载中提取相关文件；对于此演示，我们需要以下文件：

    +   `rollingbuttons.html`：将此文件保存在项目区域的根子文件夹中

    +   `style.css`：将此文件保存在项目区域的`css`子文件夹中

    +   `jquery-animate-css-rotate-scale.js`：将此文件保存在项目区域的`js`子文件夹中

    +   `rollingbuttons.js`：将此文件保存在项目区域的`js`子文件夹中

    +   `img`：将此文件夹复制到项目区域

    ### 注意

    此 Monkey Patch 的原始版本可在[`www.zachstronaut.com/posts/2009/08/07/jquery-animate-css-rotate-scale.html`](http://www.zachstronaut.com/posts/2009/08/07/jquery-animate-css-rotate-scale.html)找到；它是为 jQuery 1.3.1+开发的，但是当我将其与 jQuery 2.1 一起使用时，我没有看到任何不良影响。

1.  在浏览器中运行演示，然后尝试悬停在一个或多个按钮上。如果一切运行正常，我们将看到绿色图标图像开始向左旋转，而灰色背景扩展形成一个长的药片，其中包含链接，如下图所示：![Animating rollover buttons](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00389.jpeg)

### 更详细地探索代码

此演示产生了一个巧妙的效果，同时还节省了空间；访问者只有在需要查看信息时才会暴露，而在其他时间都是隐藏的。

但是，如果我们更仔细地查看代码，就会发现一个有趣的概念：jQuery 在使用`.animate()`时不提供旋转元素的本地支持，就像在此演示开始时提到的那样。

那么，我们怎样才能解决这个问题呢？我们可以使用插件，但相反，我们使用一个 Monkey Patch（由开发者 Zachary Johnson 创建）来给 jQuery 添加支持。值得注意的是，使用补丁总是有风险的（如第二章所述，“自定义 jQuery”），但在这种情况下，尽管更新到了 jQuery 2.1，似乎没有明显的不良影响。

如果你想看到在使用补丁时的差异，请在运行演示之前激活 DOM 检查器，如 Firebug。将鼠标悬停在其中一个图标上，你应该会看到类似于这张截图的东西：

![更详细地探索代码](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00390.jpeg)

如果你想深入了解`matrix()`的工作原理，请访问 Mozilla 的笔记，网址为[`developer.mozilla.org/en-US/docs/Web/CSS/transform`](https://developer.mozilla.org/en-US/docs/Web/CSS/transform)。

让我们继续并查看我们的下一个动画示例。我相信你以某种形式使用过覆盖层，但我们将看一个采用全新方法且摒弃了大多数覆盖层中典型的灰色遮罩的覆盖层。

## 动画覆盖效果

如果你在互联网上浏览网站花费了一些时间，你肯定会遇到一些使用某种形式覆盖层的网站，对吧？

你知道这套流程：它们首先用半透明的覆盖层将屏幕变黑，然后开始显示图像或视频的放大版本。这是在全球数千个网站上找到的典型效果，如果使用得当，可以非常有效。

然而，你比这更了解我；我喜欢将事情推向更深层次！如果我们打破传统，做一个不显示图像但显示全屏展示的覆盖层，会怎么样？感兴趣吗？让我们看看我指的是什么：

![动画覆盖效果](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00391.jpeg)

对于这个演示，我们将运行覆盖效果的一个版本，显示在[`tympanus.net/Tutorials/ExpandingOverlayEffect/`](http://tympanus.net/Tutorials/ExpandingOverlayEffect/)。

1.  让我们从与本书附带的代码下载中提取以下文件开始；将它们保存在项目区域内的相应文件夹中：

    +   `jquery.min.js`: 将此文件保存在项目区域的`js`子文件夹中

    +   `fittext.js`：将此文件保存在项目区域的`js`子文件夹中

    +   `boxgrid.js`：将此文件保存在项目区域的`js`子文件夹中

    +   `default.css`、`component.css`和`climacons.css`：将这些文件保存在项目区域的`css`子文件夹中

    +   `overlayeffect.html`：将此文件保存在项目区域的根目录中

1.  运行`overlayeffect.html`然后尝试点击其中一个彩色框。

注意发生了什么？它显示了一个覆盖效果，就像你期望的那样，但这个效果覆盖了整个浏览器窗口，并且没有常见的传统覆盖效果中经常显示的遮罩效果。

在这个演示中，我们使用了一些 HTML 来生成我们的初始网格；`fittext.js`插件用于帮助确保文本（因此是覆盖层）被调整大小以填充屏幕；覆盖效果是使用我们的代码内的`boxgrid.js`插件产生的。

魔法发生在`boxgrid.js`中——这包含了由 Louis Remi 开发的`jquery.debouncedresize.js`插件；尽管这已经有 2 年历史了；但在现代浏览器中仍然完美运行。您可以从[`github.com/louisremi/jquery-smartresize/blob/master/jquery.debouncedresize.js`](https://github.com/louisremi/jquery-smartresize/blob/master/jquery.debouncedresize.js)下载原始插件。

让我们改变焦点，继续看一看如何将 jQuery 动画应用于响应式网站。在两个演示中的第一个中，您将看到如何结合使用 CSS3、jQuery 和`history.pushState`来创建一些令人愉悦的转换效果，这些效果可以将一个多页面站点转变为一个看似是单页面应用程序。

# 在响应式网站中进行动画处理

您有多少次访问了一个站点，结果发现您必须在每个页面加载之间等待很长时间？听起来熟悉吗？

过去几年来，我们对页面转换的期望已经发生了变化——页面上元素重新排列的笨拙副作用已经不够了；我们对网站有了更多期望。基于 JavaScript 的**单页面应用程序**（**SPA**）框架通常被视为答案，但是要以使用冗长的代码为代价。

我们可以做得比这更好。我们可以介绍 smoothState.js，这是由 Miguel Ángel Pérez 创建的一个有用的插件，它允许我们添加转换效果，使整个体验对访问者更加平滑和愉快。在这个示例中，我们将使用插件作者提供的演示的修改版本；一些代码已经从原始代码中重新组织和清理。

让我们看看插件的实际效果，并看看它如何使体验更加流畅。要做到这一点，请执行以下步骤：

1.  从附带本书的代码下载中，提取以下文件的副本：

    +   `smoothstate.html`和`smoothstate.css`：将这些文件分别保存在您项目文件夹的根目录和`css`子文件夹中。

    +   `jquery.smoothstate.js`：将其保存在项目区域的`js`子文件夹中；最新版本可从[`github.com/miguel-perez/jquery.smoothState.js`](https://github.com/miguel-perez/jquery.smoothState.js)下载。

    +   `jquery.min.js`：将其保存在项目区域的`js`子文件夹中。

    +   `animate.css`：将其保存在项目区域的`css`子文件夹中；最新版本可在[`daneden.github.io/animate.css/`](http://daneden.github.io/animate.css/)下载。

    +   Roboto 字体：使用的两种字体的副本在附带本书的代码下载中。或者，它们可以从 Font Squirrel 网站下载，网址为[`www.fontsquirrel.com/fonts/roboto`](http://www.fontsquirrel.com/fonts/roboto)。我们只需要选择 WOFF 字体；我们将在演示中使用字体的轻和常规版本。

1.  在浏览器中运行`smoothstate.html`文件；尝试点击三个链接中的中间链接，看看会发生什么。注意它如何显示下一个页面，即`transitions.html`。smoothState.js 将网站视为单页面应用程序，而不是加载新页面时经常出现的暂停。您应该看到一个非常简单的页面显示，如下图所示：![在响应式网站中进行动画处理](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00392.jpeg)

传统上，面对这个问题时，许多人可能会诉诸于 SPA 框架，以解决问题并改善过渡外观。采用这种方法确实有效，但会以使用不显眼代码获得的好处为代价。

相反，我们可以使用 jQuery、CSS3、`history.pushState()`和渐进增强的混合来实现相同的效果，从而为我们的最终用户带来更好的体验。

### 注意

值得一提的是，可以查看网站文档，位于[`weblinc.github.io/jquery.smoothState.js/index.html`](http://weblinc.github.io/jquery.smoothState.js/index.html)。在 CSS-Tricks 网站上有一个有用的教程，位于[`css-tricks.com/add-page-transitions-css-smoothstate-js/`](https://css-tricks.com/add-page-transitions-css-smoothstate-js/)。

维护良好的用户体验应始终是任何开发人员心中的首要任务——在处理响应式网站时，这更为重要。其中一个关键部分应该是监控我们动画的性能，以确保我们在用户体验和对服务器的需求之间取得良好的平衡。

在处理基于 jQuery 的动画在响应式网站上使用时，我们可以使用一些技巧来帮助提高性能。让我们来看看其中的一些问题以及我们如何缓解或解决它们。

## 考虑响应式网站上的动画性能

在这个可以从任何设备访问互联网的现代时代，对用户体验的重视比以往任何时候都更为关键——使用 jQuery 并不会帮助这一点。作为最低公共分母，它有助于简化处理内容（特别是复杂动画），但并不为其使用进行了优化。

在使用 jQuery 进行内容动画时，我们会遇到一些问题——我们在本章早些时候已经讨论过其中一些，在*选择 CSS 还是 jQuery*中介绍过；它们同样适用于响应式网站。此外，还有其他一些需要我们注意的问题，包括以下内容：

+   使用 jQuery 的动画将消耗大量资源；再加上可能不适合移动环境的内容（由于其量），将导致桌面体验缓慢。在笔记本电脑和移动设备上情况会更糟！

+   移动设备上的最终用户通常只对获取所需信息感兴趣；动画可能使网站看起来很好，但通常不针对移动设备进行优化，并且可能会减慢访问速度并导致浏览器崩溃。

+   jQuery 的垃圾收集进程经常会导致问题；它使用`setInterval()`而不是`requestAnimationFrame()`会导致高帧率，使得体验可能会出现卡顿和高帧丢失率。

    ### 提示

    在撰写本文时，有计划使用`requestAnimationFrame`（及`clearAnimationFrame`）替换 jQuery 中的`setInterval`（及`clearInterval`）。

+   如果我们使用动画——无论是 jQuery 还是纯 CSS——在一些平台上，我们经常需要启用硬件加速。虽然这可以提高移动设备的性能，但也可能导致闪烁，如果硬件加速的元素与不是硬件加速的其他元素重叠。在本章稍后的*改善动画外观*部分，我们将介绍如何启用 3D 渲染。

+   jQuery 的`.animate`在每帧动画都会增加元素的`style`属性；这会迫使浏览器重新计算布局，导致持续刷新。这在响应式网站上尤为严重，每个元素需要在屏幕调整大小时重新绘制；这会对服务器资源产生额外的需求并影响性能。如果需要的话，可以使用 jQuery Timer Tools ([`github.com/lolmaus/jquery.timer-tools`](https://github.com/lolmaus/jquery.timer-tools))等插件来限制或延迟操作，这样它们只会在必要时执行，或者多次重复调用能够被有效地合并成一次执行。

+   如果改变元素的显示状态（使用`display`...或`display: none`），那么这会导致向 DOM 添加或移除元素。如果您的 DOM 中有大量的元素，则这可能会对性能产生影响。

+   使用 jQuery 会在 DOM 中留下特异性很高的内联样式，这样会覆盖我们精心维护的 CSS。如果视口被调整大小并触发了不同的断点，这是一个大问题。

    ### 注意

    CSS 特异性是浏览器决定哪些属性值对元素最相关并作为结果应用的地方——查看[`css-tricks.com/specifics-on-css-specificity/`](https://css-tricks.com/specifics-on-css-specificity/)了解更多细节。

+   顺便说一句，在编写 JavaScript 文件时，我们丢失了关注点的分离（或者为我们的代码定义独立的部分）。

有可能减少或解决这些问题吗？有可能，但这可能需要一些牺牲；这将取决于您的需求是什么以及需要支持的目标设备。让我们花点时间考虑我们可以做出哪些改变：

+   在实际情况下，考虑在移动网站中使用 CSS 来取代 jQuery；大多数浏览器（除了 Opera Mini）支持 CSS 关键字，如`translate`或`transform`。由于它们是浏览器的本机支持，这消除了对引用额外代码的依赖，从而节省了资源和带宽的使用。

+   如果使用 jQuery 无法实现动画效果，或者所需的工作量超过了所获得的收益，则考虑使用插件，如 Velocity.js（可从[`github.com/julianshapiro/velocity`](https://github.com/julianshapiro/velocity)获取），因为该插件已经优化了对内容进行动画处理。

    ### 注意

    值得注意的是，正在讨论将 Velocity.js 集成到 jQuery 中——有关更多详细信息，请参阅[`github.com/jquery/jquery/issues/2053`](https://github.com/jquery/jquery/issues/2053)。也有一篇帖子值得阅读，详细讨论了 Velocity 的使用情况，请参见[`www.smashingmagazine.com/2014/09/04/animating-without-jquery/`](http://www.smashingmagazine.com/2014/09/04/animating-without-jquery/)。

+   更好的选择是使用 jQuery.Animate-Enhanced 插件或 jQuery++ 中的 animate 助手；两者都会默认将动画转换为使用 CSS3 等效果，在支持的情况下。

那么，在使用 jQuery 处理响应式网站上的动画请求时，我们该如何做呢？有几种方法可以做到这一点；让我们更详细地探讨这个关键问题。

# 处理响应式网站上的动画请求

在使用 jQuery 处理响应式网站内的内容动画时，最好的方法可能似乎有点反常：除非绝对必要，否则不要使用 jQuery！此时，您可能认为我完全疯了，但以下是一些很好的理由：

+   jQuery 不是为动画效果进行优化的；样式表、HTML 和 JavaScript 之间的分界线将开始模糊，这意味着我们失去了对内容样式的控制。

+   在移动设备上，使用 jQuery 进行动画效果不佳；为了提高性能，必须使用额外的 CSS 样式。

+   由于 CSS 的特异性，我们失去了对特定元素应用哪些规则的控制——将样式保持在 CSS 样式表中意味着我们可以保留控制。

+   默认情况下，jQuery 动画会消耗资源。在简单的网站上，这将产生很小的影响，但在较大的网站上，影响将显著更大。

+   使用纯 CSS 方法的一个额外好处是它允许您使用 CSS 预处理器，如**SASS**或 Less，来处理媒体查询。这种缩写 CSS 可以让您更有效地编写样式，同时仍保持最终期望的输出。

有了这个想法，让我们来看看我们可以用来处理响应式网站上动画请求的一些指针：

+   首先考虑移动端。如果你正在使用 CSS，那么首先基于最小的屏幕进行布局，然后添加额外的媒体查询来处理在越来越大的设备上查看时布局的变化。考虑使用 CSS 媒体查询样板，比如由开发者 Paul Lund 在[`www.paulund.co.uk/boilerplate-css-media-queries`](http://www.paulund.co.uk/boilerplate-css-media-queries)创建的样板；然后我们可以在适当的断点内插入动画规则。

+   避免在你的 jQuery 代码中使用`.css`语句，而是使用`.addClass()`或`.removeClass()`方法—这样可以保持内容和表现层之间的清晰分隔。如何使用这个的一个很好的例子（对于那些不确定的人）可以在 Justin Aguilar 的 Animation Cheat Sheet 网站上找到，网址为[`www.justinaguilar.com/animations/`](http://www.justinaguilar.com/animations/)。这会产生各种不同的动画，所有这些都可以使用`.addClass()`添加。

+   基于在代码中使用无前缀版本的属性，并使用自动添加任何供应商前缀的自动添加器。当使用 Grunt 和插件（例如 grunt-autoprefixer）时，这变得非常简单。

+   考虑尽可能使用 jQuery.Animate-Enhanced 插件（可在[`github.com/benbarnett/jQuery-Animate-Enhanced`](https://github.com/benbarnett/jQuery-Animate-Enhanced)获取）。虽然它有几年历史了，但仍然可以与当前版本的 jQuery 一起使用；它将`$.animate()`扩展为检测转换并用 CSS 等效项替换它们。

    ### 提示

    值得一看的另一个插件是 Animsition，可在[`git.blivesta.com/animsition`](http://git.blivesta.com/animsition)获取。

+   关键在于不要将其视为网站的永久部分，而是将其视为用 CSS 等效样式替换现有 jQuery 动画的工具。你能够转向使用 CSS 的越多，对页面的影响就越小，因为对服务器资源的需求将会减少。

+   时刻关注[`www.caniuse.com`](http://www.caniuse.com)。虽然浏览器对 CSS3 转换和过渡的支持非常好，但仍然有一些情况需要使用 WebKit 前缀，即适用于 Safari 和 iOS Safari（移动端）。

+   尽可能在你的动画中使用`requestAnimationFrame`（和`clearAnimationFrame`）。这将有助于在动画不可见时保护资源。这将需要使用 jQuery，但由于我们应该将其保留用于最复杂的动画，因此使用库的影响将会减小。

+   看一看诸如 [`cssanimate.com/`](http://cssanimate.com/) 这样的网站 —— 这些网站可以生成复杂的基于关键帧的动画，可以直接嵌入到您现有的代码中。如果您担心现有内容无法进行动画处理，那么这个网站可能会帮助您消除一些疑虑。

+   问问自己这个问题：“如果我的动画真的很复杂，它是否会有效？”如果动画做得好，它们可以视觉上令人惊叹，但这并不意味着它们必须复杂。通常，简单而经过深思熟虑的动画效果比它们的复杂、资源消耗大的等效效果更好。

这里需要考虑的重要一点是，使用 jQuery 来执行动画不应完全被排除在外；随着浏览器对 CSS 动画的支持不断发展，这更支持了以后大多数动画的基础是使用 CSS。

jQuery 团队意识到 jQuery 从未被设计用于高效地对内容进行动画处理。在撰写本书时，关于引入 Velocity.js 版本的讨论仍在进行中；原则上，这可能会改善使用 jQuery 来对内容进行动画处理的效果，但这距离成为现实还有很长的路要走！

与此同时，我们应该仔细考虑所使用的 jQuery 与 CSS 动画之间的平衡，并且如果可以使用 CSS 动画的话，就应该避免使用 jQuery 动画。

### 注意

为了证明一点，Chris Coyier 制作了一个 CodePen 示例，展示了一个相当简单的网站如何实现响应式并包含基于 CSS 的动画效果，您可以在 [`codepen.io/chriscoyier/pen/tynas`](http://codepen.io/chriscoyier/pen/tynas) 上查看。

好的，让我们继续。我们将继续讨论动画主题，但这次我们将看看如何在移动设备上实现动画效果。我们需要注意一些问题；让我们更详细地看看这些。

# 为移动设备创建动画内容

到目前为止，我们已经考虑了使用 jQuery 在响应式网站上对内容进行动画处理，但是移动平台呢？越来越多的非台式设备（如笔记本电脑和智能手机）用于查看内容。这带来了一些额外的考虑因素，我们需要考虑如何在移动设备上获得最佳性能。

在移动平台上进行动画处理与编写代码关系不大，更多的是关于决定使用哪些技术；在大多数情况下，简单地编写 jQuery 代码就可以工作，但效果可能不如预期的那么好。

获得最佳体验的秘诀在于使用智能手机的**GPU**或**图形处理单元**；为此，我们可以通过启用 3D 渲染来卸载标准的 jQuery 动画（速度较慢）。

### 提示

虽然此浏览器应该在所有台式机和移动设备上都能正常工作，但在基于 WebKit 的浏览器（例如 Google Chrome）中，您将获得最佳效果。

让我们通过一个启用了 3D 渲染的简单示例来更详细地探讨一下：

1.  对于这个演示，我们需要三个文件。从代码下载中提取`mobileanimate.html`、`mobileanimate.css`和`jquery.min.js`，并将它们保存在项目区域的相应文件夹中。

1.  在一个新文件中，添加以下代码。它处理我们的下拉框的动画。我们将逐步详细介绍它，首先是为我们的代码分配所需变量的数量：

    ```js
    var thisBody = document.body || document.documentElement,
        thisStyle = thisBody.style,
        transitionEndEvent = 'webkitTransitionEnd transitionend',
        cssTransitionsSupported = thisStyle.transition !== undefined,
        has3D = ('WebKitCSSMatrix' in window && 'm11' in new WebKitCSSMatrix());
    ```

1.  接下来是初始检查，如果浏览器支持 CSS3 变换，则在`ul`对象中添加`accordion_css3_support`类：

    ```js
    // Switch to CSS3 Transform 3D if supported & accordion element exist
    if(cssTransitionsSupported && has3D ) {
      if($('.children').length > 0) { 
        $('.children').addClass("accordion_css3_support");
      }
    }
    ```

1.  这个事件处理程序发生了神奇的事情。如果不支持 CSS3 过渡效果，则下拉框将使用`slideToggle`方法来打开或关闭；否则，它将使用 CSS3 变换：

    ```js
    $('.parent a').on('touchstart click', function(e) {
      e.preventDefault();
      // If transitions or 3D transforms are not supported
      if(!cssTransitionsSupported || !has3D ) {
        $(this).siblings('.children').slideToggle(500);
      }
      else {
        $(this).siblings('.children').toggleClass("animated");
      }
    });
    ```

1.  将文件保存为`mobileanimate.js`。如果一切顺利，你将看到一个样式化的下拉框准备好打开，如下所示：![为移动设备动画内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00393.jpeg)

尝试点击下拉箭头。乍看之下，我们的下拉框似乎与其他任何下拉框没有区别；它以与任何其他下拉框相同的方式展开和收缩。实际上，我们的代码使用了两个重要的技巧来帮助管理动画；让我们花点时间来了解在使用 jQuery 时两者的重要性。

## 改善动画外观

如果我们仔细看代码，我们对两个地方感兴趣；第一个在 jQuery 代码中：

```js
if(!cssTransitionsSupported || !has3D ) {
  $(this).siblings('.children').slideToggle(500);
}
else {
  $(this).siblings('.children').toggleClass("animated");
}
```

第二个在 CSS 样式表中两个地方显示：

```js
.accordion_css3_support { display: block; max-height: 0;
  overflow: hidden; transform: translate3d(0,0,0);
  transition: all 0.5s linear; -webkit-backface-visibility: hidden; -webkit-perspective: 1000; }
.children.animated { max-height: 1000px; transform: translate3d(0,0,0); }
```

“为什么这些重要呢？”，我听到你问。答案很简单。在大多数情况下，我们可能会使用`slideToggle()`事件处理程序。这没有什么不对，除了动画不是硬件加速的（还需要你将其转换为 CSS），因此不会充分利用平台的功能。此外，它模糊了代码和样式之间的界线；如果我们既在代码中又在样式表中拥有它们，那么在调试样式时就更难了。

更好的选择是先弄清楚浏览器是否支持 CSS3 变换（或类似的功能），然后应用一个新的类，我们可以在样式表中进行样式设计。如果浏览器不支持变换，则我们简单地回退到在 jQuery 中使用`slideToggle()`方法。前者的好处是 CSS 样式将减少运行动画所需的资源，并有助于节省资源。

### 提示

如果还必须使用 jQuery，则值得测试设置给`jQuery.fx.interval`的值——尝试大约 12fps 左右，看看是否有助于提高性能；更多细节请参阅主文档[`api.jquery.com/jquery.fx.interval/`](http://api.jquery.com/jquery.fx.interval/)。

第二个值得关注的点可能显得不太明显；如果我们对包含动画的任何 CSS 规则应用变换`translate3d(0,0,0)`，那么这足以启用 3D 渲染，并允许浏览器通过将动画卸载到 GPU 上来提供流畅的体验。在某些浏览器（如 Google Chrome）中，我们可能会遇到闪烁的情况；我们可能需要添加以下代码来消除不需要的闪烁：

```js
-webkit-backface-visibility: hidden; -webkit-perspective: 1000;
```

也有可能`translate3d(x, y, z)`不能为某些平台（如 iOS 6）启用硬件加速；我们可以改用`–webkit-transform: translate (0)`。

最终，虽然可能有些情况下我们需要（或更喜欢）使用 jQuery 来动画内容，但应考虑是否它真的是正确的工具，以及是否可以使用 CSS 动画来替代它。

一个很好的例子是在 JSFiddle（[`jsfiddle.net/ezanker/Ry6rb/1/`](http://jsfiddle.net/ezanker/Ry6rb/1/)）上展示的，它使用了来自 Dan Eden 的 Animate.css 库来处理动画，将 jQuery 作为 jQuery Mobile 的依赖项留给了演示中使用的版本。诚然，jQuery 的版本有点旧，但原理仍然非常合理！

### 小贴士

Treehouse 团队发布了一篇探讨动画和过渡如何影响性能的好博文，值得一读；你可以在[`blog.teamtreehouse.com/create-smoother-animations-transitions-browser`](http://blog.teamtreehouse.com/create-smoother-animations-transitions-browser)找到它。

让我们转移焦点，继续前进吧。有多少人访问过具有视差滚动效果的网站？视差…滚动…不确定这到底是什么？没问题，在接下来的几页中，我们将看看这是如何成为网页设计中最热门的技术之一的，但如果在我们的项目中没有正确实现它，同样也可能适得其反。

# 实现响应式视差滚动

视差滚动到底是什么？简单来说，它涉及在向下滚动页面时，以比前景更慢的速度移动背景，以创建三维效果。

最初由 Ian Coyle 于 2011 年为耐克创建，视差滚动是一种流行的技术。它可以提供微妙的深度元素，但如果不正确使用，同样也可能会让人感到不知所措！

想要了解可能性的话，可以看看 Creative Bloq 网站上的文章，链接为[`www.creativebloq.com/web-design/parallax-scrolling-1131762`](http://www.creativebloq.com/web-design/parallax-scrolling-1131762)。

目前已经有数十款视差滚动插件可用，比如来自 PixelCog 的 parallax.js 插件（位于[`pixelcog.github.io/parallax.js/`](http://pixelcog.github.io/parallax.js/)）或 Mark Dalgleish 的 Stellar.js 可以在[`markdalgleish.com/projects/stellar.js/`](http://markdalgleish.com/projects/stellar.js/)找到。可以说，最著名的插件是 Skrollr，可以从[`github.com/Prinzhorn/skrollr`](https://github.com/Prinzhorn/skrollr)下载——这将构成我们下一个演示的基础。

## 构建一个视差滚动页面

如果你在网上花时间做一些研究，毫无疑问你会看到很多关于如何给网站添加视差滚动效果的教程。在接下来的几页中，我们将以澳大利亚前端开发者 Petr Tichy 的教程为基础，进行我们的下一个练习。毕竟，试图重复造轮子是没有意义的，对吧？

### 注意

这个原始教程可以查看：[`ihatetomatoes.net/how-to-create-a-parallax-scrolling-website/`](https://ihatetomatoes.net/how-to-create-a-parallax-scrolling-website/)。

我们的下一个演示将使用广为人知的 Skrollr 库（位于[`github.com/Prinzhorn/skrollr`](https://github.com/Prinzhorn/skrollr)）来构建一个简单的页面，其中可以滚动查看五张图片，同时还将使用一些效果来控制图片在页面上的滚动方式：

![构建视差滚动页面](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00394.jpeg)

现在我们已经看到我们的演示将会产生的效果，接下来让我们按照以下步骤来实施：

1.  我们将从本书附带的代码下载中提取`parallax`文件夹，并将整个文件夹保存到你的项目区域。

1.  我们的演示需要一些额外的插件才能工作，所以去下载以下插件：

    +   **ImagesLoaded**：[`raw.githubusercontent.com/desandro/imagesloaded/master/imagesloaded.pkgd.js`](https://raw.githubusercontent.com/desandro/imagesloaded/master/imagesloaded.pkgd.js)；把文件保存为`imagesloaded.js`

    +   **Skrollr**：[`raw.githubusercontent.com/Prinzhorn/skrollr/master/src/skrollr.js`](https://raw.githubusercontent.com/Prinzhorn/skrollr/master/src/skrollr.js)

    +   **ViewPortSize**：[`github.com/tysonmatanich/viewportSize`](https://github.com/tysonmatanich/viewportSize)

    把全部这些插件都保存在 `parallax` 文件夹中的 `js` 子文件夹中。

1.  在一个新文件中，添加以下代码；这个代码处理 Skrollr 插件的初始化。让我们详细地介绍一下，从设置一系列变量以及使用 ImagesLoaded 插件预加载图像开始，然后调整它们的大小并在每个部分淡入：

    ```js
    $(document).ready(function($) {
      // Setup variables
      $window = $(window);
      $slide = $('.homeSlide');
      $slideTall = $('.homeSlideTall');
      $slideTall2 = $('.homeSlideTall2');
      $body = $('body');

      //FadeIn all sections
      $body.imagesLoaded( function() {
        setTimeout(function() {
          // Resize sections
          adjustWindow();

      // Fade in sections
      $body.removeClass('loading').addClass('loaded');
      }, 800);
    });
    ```

1.  在 DOM 函数下面、闭合括号前，添加以下代码。这个代码处理每个幻灯片的调整大小，使其适应窗口高度或至少`550px`的最小高度，以确保更佳的显示：

    ```js
    function adjustWindow(){
      var s = skrollr.init();  // Init Skrollr
      winH = $window.height(); // Get window size

      // Keep minimum height 550
      if(winH <= 550) { winH = 550; } 

      // Resize our slides
      $slide.height(winH);
      $slideTall.height(winH*2);
      $slideTall2.height(winH*3);

      // Refresh Skrollr after resizing our sections
      s.refresh($('.homeSlide'));
    }
    ```

1.  如果一切顺利，当您预览结果时，图像将在我们向上或向下滚动时从一个图像交叉到另一个图像，如此屏幕截图所示：![构建视差滚动页面](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00394.jpeg)

视差滚动作为一种技术，当使用得当时可以产生一些真正令人惊叹的效果。一些很好的例子，请参阅 Costa Coffee 的网站，网址为[`www.costa.co.uk`](http://www.costa.co.uk)，或 Sony 的 Be Moved 网站，网址为[`www.sony.com/be-moved/`](http://www.sony.com/be-moved/)。很难相信这样原创的设计是基于视差滚动的！

### 提示

查看彼得的一个关于如何使视差滚动响应式的教程，网址为[`ihatetomatoes.net/make-parallax-website-responsive/`](https://ihatetomatoes.net/make-parallax-website-responsive/)。

## 考虑视差滚动的影响

尽管很难相信使用视差滚动可以创建如此漂亮的网站，但必须提出警告：这种技术并不是没有问题的。当然，大多数（如果不是全部）问题都可以通过一些注意和关注来解决；然而，如果在设计和实施过程中不注意，这些问题可能会使任何设计师遇到困难。让我们更详细地探讨一些这些问题：

+   最大的问题是，视差滚动默认情况下不友好于 SEO。有一些可用的技术可以解决这个问题，例如 jQuery 或多个页面，但它们会影响分析或服务器资源。数字营销策略师卡拉·道森撰写了一篇关于这些解决方案的优点的优秀文章，可在[`moz.com/blog/parallax-scrolling-websites-and-seo-a-collection-of-solutions-and-examples`](http://moz.com/blog/parallax-scrolling-websites-and-seo-a-collection-of-solutions-and-examples)找到——值得一读！

+   视差滚动（自然地）需要访客滚动；关键在于确保我们不要创建滚动时间过长的单个页面。这可能会影响移动用户的性能并使访客失去兴趣。

+   使用 jQuery 来创建基于这种技术的效果本身就可能是一个缺点；jQuery 会影响页面加载时间，因为必须计算页面上每个元素的位置。我们可以通过使用我们在第一章中介绍的技术来自定义我们的 jQuery 的副本来在一定程度上减轻这种影响，但在使用库时性能总会有所降低。

+   视差滚动可能会揭示许多可用性问题。如果视觉吸引力与内容和易访问性的平衡不均匀，布局对最终用户可能显得杂乱无章。在某些情况下，视差滚动将是合适的选择，例如你可能希望访客仅浏览您的网站一次，或者为公司展示他们的能力。但在你为产品或业务做推介的情况下，这可能会产生负面影响。

+   在许多情况下，您会发现视差滚动在移动设备上无效；这主要是由于动画在最后执行时会破坏视差滚动。已经尝试解决此问题，但成功的程度各不相同。以下是一些成功尝试的例子：

    +   使用 Stellar.js jQuery 视差插件，可在[`markdalgleish.com/projects/stellar.js/`](http://markdalgleish.com/projects/stellar.js/)获取；搭配 Scrollability 插件，可在[`joehewitt.github.com/scrollability/`](http://joehewitt.github.com/scrollability/)获取，可实现触摸友好的视差滚动效果。该插件在桌面和移动浏览器中都适用，因此应该考虑检查触摸支持并根据情况切换方法。插件作者 Mark Dalgleish 通过[`markdalgleish.com/presentations/embracingtouch/`](http://markdalgleish.com/presentations/embracingtouch/)解释了如何使用 iScroll.js 来实现这一点。

    +   Keith Clark 提供了一个纯 CSS 版本，可在[`codepen.io/keithclark/pen/JycFw`](http://codepen.io/keithclark/pen/JycFw)获取——他在自己的网站上[`keithclark.co.uk/articles/pure-css-parallax-websites/`](http://keithclark.co.uk/articles/pure-css-parallax-websites/)详细解释了所使用的原理。

视差滚动的关键信息是不要仓促行事；的确有一些站点成功地创建了一些令人惊叹的视差滚动示例，但在构建示例时必须经过深思熟虑的规划和规划，以便性能好，满足 SEO 的要求，并为访问者呈现可用的体验。

# 总结

如果做得好，项目中的内容动画会非常令人满意；这不仅取决于我们使用正确的代码，还要决定 jQuery 是否是正确的工具，或者 CSS 动画是否更适合我们的需求。在过去的几页中，我们涵盖了很多内容，让我们花一点时间来回顾一下我们学到了什么。

我们以讨论使用 jQuery 或 CSS 的优点开始，并讨论了在何时使用其中一种而不是另一种以及使用 CSS 的好处，情况可能决定使用 jQuery。

然后，我们开始讨论了困扰 jQuery 开发人员的经典问题，即控制动画队列；我们看到了如何实施一个快速而简单的修复方法，并随后改进以减少或消除这个问题。

接下来讨论了使用缓动函数的问题；我们看到不仅可以依赖于诸如 jQuery UI 之类的经过验证的源，还可以开发扩展核心 jQuery 的简单动作。我们看了一下如何构建我们自己的自定义缓动函数，然后将我们可能在 CSS 中看到的函数转换为 jQuery 等效函数。

接着，我们通过一些动画示例来结束本章，例如对按钮进行动画处理，实现带有特效的覆盖效果以及在响应式网站上对内容进行动画处理。

在下一章中，我们将深入研究高级事件处理。在大多数情况下，人们使用`.on()`或`.off()`，但正如我们将看到的，这只是 jQuery 可能性的冰山一角。


# 第七章：高级事件处理

你有多少次访问网站执行一个操作？它可能是在线银行业务，或者从亚马逊购买东西；在这两种情况下，网站将检测到正在发生的动作，并作出相应的反应。

使用 jQuery 的一部分是知道何时以及如何响应不同类型的事件。在大多数情况下，人们可能会使用`.on()`或`.off()`事件处理程序来处理它们。虽然这样做完全没问题，但它只是触及了事件处理的表面。在本章中，我们将探讨一些可以帮助我们扩展事件处理技能的技巧和窍门。我们将涵盖以下主题：

+   事件委托

+   使用`$.proxy`函数

+   创建和解耦自定义事件类型

+   事件命名空间

有兴趣吗？那我们就开始吧！

# 介绍事件处理

一个问题 - 你多久上线执行一项任务？我敢打赌这是每周都会发生的事情；它可能是任何事情，从在线银行业务到点击亚马逊购买最新的 DVD（DVD - 谁会下载它们，我想知道？）

话虽如此，我们无法避免必须点击链接或按钮来通过流程。在大多数情况下，事件背后的代码可能是普遍存在的点击处理程序，或者甚至可能是`.change()`或`.hover()`。所有这些都是`.on()`（甚至`.off()`）事件处理程序的简写形式，并且当然与以下内容的功能等效：

```js
$('a').on('click', function(){
  $(this).css('background-color','#f00');
});
```

这将使所选元素变成一个漂亮的红色。然而，事件处理不仅仅是在已知元素上定义一个操作。在接下来的几页中，我们将（引用一个航海术语）冒险一试，并查看一些可以帮助我们进一步发展技能的提示和技巧。我们将从事件委托开始。

# 事件委托

有人曾经说过，成为一名优秀的经理的艺术就是知道什么时候委派任务。我希望这不是他们把一个可怕的工作推卸给下属的借口，尽管愤世嫉俗的人可能会说另外一种看法！

撇开风险，事件委托遵循着 jQuery 中相同的原则。如果我们需要创建一个需要将某种形式的事件处理程序绑定到大量相同类型元素的应用程序，那么我们可以考虑编写事件处理程序来覆盖每个元素。

它在某种程度上是有效的，但非常浪费资源。如果列表很大，那么事件将绑定到其中所有的元素，这会比所需的内存更多。我们可以通过使用**事件委托**来解决这个问题，我们可以将一个事件处理程序绑定到一个祖先元素，该元素为多个后代服务，或者为新创建的元素启用事件处理。

有一些技巧可以帮助我们更好地使用委托来管理事件。在我们看看它们之前，让我们快速回顾一下事件委托的基本原理。

## 重新审视事件委托的基础

一个问题——你在使用 jQuery 编写事件处理程序时有多少次使用过`.on()`，甚至`.off()`？我敢打赌答案可能是无数次。如果你之前没有使用过事件委托，那么你已经无意中使用了一半！

事件委托依赖于使用**事件传播**，有时也称为事件冒泡。这是理解委托工作原理的关键。让我们通过一个快速的示例来说明。

想象一下，我们正在使用以下 HTML 代码作为列表的基础：

```js
<div id="container">
  <ul id="list">
    <li><a href="http://domain1.com">Item #1</a></li>
    <li><a href="/local/path/1">Item #2</a></li>
    <li><a href="/local/path/2">Item #3</a></li>
    <li><a href="http://domain4.com">Item #4</a></li>
  </ul>
</div>
```

这里没有什么特别的——这是一个简单的示例。每当我们的锚点标签之一被点击时，都会触发一个点击事件。事件在三个阶段之一中分派：**捕获**，**目标**和**冒泡**。

它将被捕获到文档根，在命中目标（`li`标签）之前向下工作，然后冒泡回文档根，如下所示：

+   文档根

+   `<html>`

+   `<body>`

+   `<div #container>`

+   `<ul #list>`

+   `<li>`

+   `<a>`

哎呀！这意味着每次点击链接时，实际上都在点击整个文档！不好！这会消耗资源，即使我们使用如下代码添加了额外的列表项：

```js
$("#list").append("<li><a href='http://newdomain.com'>Item #5</a></li>");
```

我们会发现上述的点击处理程序不适用于这些项目。

### 提示

这里使用的冒泡示例有些简化，并没有显示所有的各种阶段。要进行有用的讨论，请前往 Stack Overflow 上发布的评论 [`stackoverflow.com/questions/4616694/what-is-event-bubbling-and-capturing`](http://stackoverflow.com/questions/4616694/what-is-event-bubbling-and-capturing)。

### 重新调整我们的代码

我们可以利用事件传播来重新调整我们的处理程序，监听**后代**锚点，而不是仅绑定到现有锚点标签。这可以在以下代码中看到：

```js
$("#list").on("click", "a", function(event) {
  event.preventDefault();
  console.log($(this).text());
});
```

代码中唯一的区别是我们将`a`选择器移动到`.on()`方法的第二个参数位置。这将创建一个针对`#list`的单个事件处理程序，事件从`a`向上冒泡到`#list`。事件委托消除了创建多个事件处理程序的需要，这是一种浪费资源的做法——代码将同样适用于`#list`内现有的锚点标签，以及将来添加的任何锚点标签。

### 提示

如果您想了解更多关于事件委托的信息，建议查看 jQuery API 文档，网址是 [`learn.jquery.com/events/event-delegation/`](http://learn.jquery.com/events/event-delegation/)。jQuery 文档还有一个关于在委托事件中使用`.on()`的有用部分，网址是 [`api.jquery.com/on/`](http://api.jquery.com/on/)。

### 支持旧版浏览器

一个小提示 - 如果你需要重构旧代码，那么你可能会看到`.bind()`、`.live()`或`.delegate()`作为事件处理程序。在 jQuery 1.7 之前，所有这些都用于委托事件，但现在应该替换为`.on()`。事实上，第一个`.bind`是一个调用`.on`（及其伴侣`.off()`）的单行函数：

![支持旧版浏览器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00395.jpeg)

同样适用于`.delegate()`及其配对事件处理器`.undelegate()`：

![支持旧版浏览器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00396.jpeg)

应该注意`.on()`模仿了使用`.bind()`或`.delegate()`时发现的行为。前者非常耗资源，因为它会附加到每个可以匹配的元素；后者仍然需要确定要调用哪个事件处理程序。然而，与使用`.bind()`方法相比，这种情况的范围应该较小。

现在我们已经深入了解了`.on()`的内部工作原理，让我们将其付诸实践，并创建一个简单的演示来提醒自己 jQuery 中事件委托的工作方式。

## 探索一个简单的演示

现在是行动的时候了，让我们快速回顾一下在使用 jQuery 时事件委托是如何工作的：

1.  让我们从伴随本书的代码下载中提取我们需要的文件。对于这个演示，我们需要`simpledelegation.html`、`simpledelegation.css`和`jquery-ui.min.css`文件。

1.  将 CSS 文件保存在项目区域的`css`子文件夹中。HTML 标记需要存储在项目文件夹的根目录中。

1.  在一个新文件中，添加以下代码 - 将文件保存为`simpledelegation.js`，并将其存储在项目区域的`js`子文件夹中：

    ```js
    $(document).ready(function(event){
      var removeParent = function(event) {
        $('#list').parent('li').remove();
      }

      var removelistItem = function(event) {
        $(event.target).parent().remove();
      }

      $('li.ui-widget-content').children().on("click", removeParent);

      $('ul').on("click", "li", removelistItem);
    });
    ```

1.  如果一切正常，当在浏览器中预览结果时，我们应该看到以下项目列表：![探索一个简单的演示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00397.jpeg)

1.  尝试点击一些链接 - 如果你点击任何一个移除链接，那么列表项将被移除；点击其中一个列表项将会移除列表中的所有项。

这个演示的关键在于以下一行：

```js
$('ul').on("click", "li", removelistItem);
```

尽管列表中有多个项目，但我们创建了一个单一的委托事件处理程序。它冒泡到我们点击的`<li>`项的父级，然后将其移除。在这种情况下，我们将触发事件时调用的函数分开了出来；这很容易可以合并到处理程序中。

现在我们重新审视了事件委托的基础知识，让我们看看事件委托为何可以在处理许多相似元素时提高性能。

## 探索使用事件委托的影响

在直接等效物代替委托事件的关键好处是减少内存使用量，避免代码中存在多个事件处理程序时的内存泄漏。通常，我们需要为需要发生某些事情的每个实例实现一个事件处理程序。

### 注意

使用事件委托的真正影响在于内部数据结构中存储事件处理程序定义所带来的内存使用量节约。

相反，减少事件处理程序的数量意味着我们可以减少内存泄漏，改善性能（通过减少需要解析的代码量）。只要我们小心绑定事件处理程序的位置，就有潜力显著减少对 DOM 的影响和由此产生的内存使用量，特别是在更大的应用程序中。好处是，如果已实施事件委托，它将同样适用于已定义的现有元素，以及尚未创建的元素。直接应用的事件处理程序将不起作用；它们只能应用于在代码中调用事件处理程序之前已经存在的元素。

处理已存在和尚未发生的事件的能力听起来是件好事。毕竟，如果一个事件处理程序可以处理多个事件，那么为什么要重复自己呢？绝对可以 - 只要我们小心管理！如果我们在特定元素上触发事件，例如一个锚点标签，那么这将被允许首先处理事件。事件会冒泡直到达到文档级别，或者更低级别的事件处理程序决定停止事件传播。这最后一部分很关键 - 没有控制，我们可能会得到意外的结果，其中事件处理程序的响应与预期相反，可能也没有被触发。

### 提示

要看详细的解释可以发生什么，可以看看[`css-tricks.com/capturing-all-events/`](http://css-tricks.com/capturing-all-events/)。它包含了指向 CodePen 上很好地说明了这个问题的示例的链接。

为了帮助减少事件冒泡引起事件处理程序无序触发的影响，我们使用诸如`event.stopPropagation()`之类的方法。这不是我们唯一能使用的技巧，因此让我们花点时间来探讨在使用事件委托时可用的一些选项。

## 控制委托

利用事件冒泡增加了我们在代码中实现的事件处理程序数量的减少的范围；缺点在于出现意外行为的实例，其中事件处理程序可能在期望的点上没有被触发。

要控制哪些元素可能触发委托事件处理程序，我们可以使用以下两种技巧之一：`event.stopPropagation()`，或者捕获事件目标并确定它是否符合给定的一组条件（例如特定类或`data-`名称）。

让我们首先来看看这第二个选项 - 一个代码块的例子可能如下所示：

```js
$("ul.my-list").click(function(event) {
  if ( $( event.target).hasClass("my-item") ) {
    handleListItemAction(event.target);
  }
else if ( $( event.target).hasClass("my-button") ) {
    handleButtonClickedAction(evt.target);
  }
});
```

那是一种笨拙的做事方式！相反，我们可以简单地对类名进行检查，使用下面显示的委托事件处理程序的变体：

```js
$("ul.my-list").on("click",".my-item", function(evt) {
  //do stuff
});
```

这是一个非常简单的技巧，我们可以使用它 - 它非常简单，可能不算是一个技巧！为了看到改变有多容易，让我们现在快速进行一个演示：

1.  从代码下载中，我们需要提取`propagation-css.html`和`propagation.html`文件。这些文件包含了一些简单的标记和样式，用于我们的基本列表。将 CSS 文件保存在我们项目区域的`css`子文件夹中，将 HTML 标记保存在同一区域的根目录中。

1.  接下来，我们需要创建事件处理程序，当条件匹配时将触发。继续添加以下内容到一个新文件中，并将其保存为`propagation-css.js`，保存在我们项目区域的`js`子文件夹中：

    ```js
        $(document).ready(function() {
          $('#list').on('click', '.yes', function eventHandler(e) {
            console.log(e.target);
          });
        });
    ```

此时，如果我们在浏览器中预览结果，我们将得到一个简单的列表，其中列表项在我们悬停在特定项上时会变暗。这没什么特别的 - 它只是从 jQuery UI 中借用了一些样式。

但是，如果我们启动一个 DOM 检查器，比如 Firebug，然后悬停在每个项目上，我们可以看到每次悬停在一个类为`.yes`的项目上时都会添加控制台输出：

![控制委托](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00398.jpeg)

因此，我们不像*探索一个简单的演示*中那样提供选择器，我们简单地使用了一个类名；只有当事件处理程序函数与指定的类名匹配时，事件处理程序函数才会被触发。

### 提示

我们甚至可以使用`data-`标签作为我们的检查：

```js
$(document).on('keypress', '[data-validation="email"]', function(e) {
  console.log('Keypress detected inside the element');
})
```

### 作为替代方法使用 stopPropagation()方法

作为替代方法，我们可以使用一个全 jQuery 的解决方案，形式为`stopPropagation()`。这可以防止事件冒泡到 DOM 树，并阻止任何父处理程序被通知事件。

这一行代码的实现非常简单，尽管使用它的关键在于确保我们将其添加到我们代码的正确位置。如果你以前没有使用过它，那么它需要放在事件处理程序内，在处理程序的最后一个命令之后立即添加（如下面的片段中所突出显示的那样）：

```js
document.ready(function ($) {
  $('div'). on("click", function (event) {
    console.log('You clicked the outer div');
  });
  $('span').on("click", function (event) {
    console.log('You clicked a span inside of a div element');
    event.stopPropagation();
  });
})
```

作为快速检查，尝试从附带本书的代码下载中提取`propagation-js`文件。将它们保存在我们项目区域内的相关文件夹中。如果我们在浏览器中预览它们，我们会看到一个简单的**span**包含在**div**内。参考下面的图片：

![作为替代方法使用 stopPropagation()方法](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00399.jpeg)

这个演示的关键在于 DOM 检查器。尝试点击灰褐色的外环，或其中的 span，我们将看到我们选择的结果出现在控制台日志中，如下所示：

![作为替代方法使用 stopPropagation()方法](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00400.jpeg)

如果你在代码中注释掉`event.stopPropagation()`行，那么附加到`div`的点击事件也将被调用。

### 提示

除非必要，否则不应该停止事件传播。有一篇有用的文章位于[`css-tricks.com/dangers-stopping-event-propagation/`](https://css-tricks.com/dangers-stopping-event-propagation/)，其中讨论了如果停止传播可能遇到的问题。

好的，让我们改变焦点，转到事件处理程序中的另一个关键概念。是时候看看使用 `$.proxy` 函数了，以及为什么需要它，如果事件委托不能满足我们的需要。

# 使用 `$.proxy` 函数

到目前为止，我们已经介绍了如何利用事件冒泡可以帮助我们减少大量事件处理程序的需求；只要我们仔细管理冒泡，委托就可以成为使用 jQuery 进行开发的非常有用的工具。

另一面的情况是，在某些情况下，我们可能需要帮助 jQuery；当它的传播不足够高！起初这可能不合理，所以让我解释一下我的意思。

假设我们有一个作为对象创建的事件处理程序，并且当点击链接时，我们想调用它：

```js
var evntHandlers = {
  myName : 'Homer Simpson',

  clickHandler : function(){
    console.log('Hello, ' + this.myName);
  }
};

$("a").on('click',evntHandlers.clickHandler);
```

如果我们在浏览器中运行这个代码，您期望在控制台日志区域看到什么？

### 提示

要找出答案，请尝试从随本书附带的代码下载中提取 `proxy-before.html` 文件。确保您安装了 DOM 检查器！

如果您期望看到 **你好，霍默·辛普森**，那我将让您失望；答案不会是您期望的，而是 **你好，未定义**，如下图所示：

![使用 `$.proxy` 函数](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00401.jpeg)

好的，这是怎么回事？

原因是所使用的上下文位于 `clickHandler` 事件中，而不是 `evntHandler` 对象中；我们在 `clickHandler` 事件中没有 `myName` 属性。

幸运的是，这有一个简单的解决方法。我们可以使用 `$.proxy` 强制更改上下文，如下所示：

```js
var evntHandlers = {
  myName : 'Homer Simpson',
  clickHandler : function(){
    console.log('Hello, ' + this.myName);
  }
};

$("a").on('click',$.proxy(evntHandlers.clickHandler,evntHandlers));
```

要看到这种情况的效果，请从随本书附带的代码下载中提取 `proxy-before.html` 和 `proxy-after.html` 文件。如果在浏览器中运行它们，你将看到与下图中显示的相同的结果：

![使用 `$.proxy` 函数](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00402.jpeg)

这是一个简单的改变，但它打开了各种可能性。这是一种设定闭包上下文的简易方法。当然，我们也可以使用纯 JavaScript 的`.bind()`方法。但是，使用 `$.proxy` 确保传入的函数是实际上是一个函数，并且向该函数传递了唯一的 ID。如果我们给我们的事件添加命名空间，我们可以确保解绑正确的事件。`$.proxy` 函数被视为 jQuery 中的单个函数，即使它被用来绑定不同的事件。使用命名空间而不是特定的代理函数将避免在代码中解绑错误的处理程序。

### 注意

如果您想了解更多关于使用 `$.proxy` 的内容，那么值得阅读主要 jQuery 网站上的文档，可以在[`api.jquery.com/jquery.proxy/`](http://api.jquery.com/jquery.proxy/)上找到。

为了让我们真正了解可能性，考虑一下这个问题：你有多少次最终以三到四层深度嵌套的函数结束了？考虑以下代码：

```js
MyClass = function () {
  this.setupEvents = function () {
    $('a').click(function (event) {
      console.log($(event.target));
    });
  }
}
```

而不是使用上述代码，我们可以通过使用`$.proxy`来重构代码以增加可读性，如下所示：

```js
MyClass = function () {
  this.setupEvents = function () {
    $('a').click( $.proxy(this, 'clickFunction'));
  }

  this.clickFunction = function (event) {
    console.log($(event.target));
  }
}
```

我认为你会同意这样更容易阅读，对吧？

好的 - 让我们继续吧。我相信我们都很熟悉在 jQuery 中创建事件处理程序。但是，很可能你正在使用标准事件处理程序。这些可以很好地工作，但我们仍然受限于我们所能做的事情。

那么，让我们改变这一点。使用 jQuery，我们可以创建打破我们知道可能性的常规的自定义事件，并且允许我们创建各种事件处理程序。让我们看看我们如何在实际操作中做到这一点。

# 创建和解耦自定义事件类型

如果你花了一些时间开发 jQuery，那么我相信你对我们可以使用的标准事件类型非常熟悉，比如`.click()`、`.hover()`或`.change()`等。

这些都有用途，但都有一个共同点 - 我们在使用它们时受到了一些限制！我们的代码将受到这些处理程序可以做到的程度的限制。如果我们能打破这种限制，创建*任何*类型的自定义事件处理程序会怎样呢？

当然，我们始终可以将多个事件组合在一起，由同一个函数来处理：

```js
$('input[type="text"]').on('focus blur', function() {
  console.log( 'The user focused or blurred the input' );
});
```

但这仍然局限于那些现成的事件处理程序。我们需要的是打破常规，在设计我们自己的处理程序时发挥创意。

没问题 - 我们可以使用 jQuery 的特殊事件功能构建几乎任何类型的事件以满足我们的需求。这打开了一个真正的可能性世界，可能需要一本专门的书来介绍。在接下来的几页中，我们将介绍一些概念，以帮助您开始创建事件。

### 小贴士

要深入了解创建自定义事件，请参阅 learn jQuery 网站上的一篇有用的文章，网址为[`learn.jquery.com/events/introduction-to-custom-events/`](http://learn.jquery.com/events/introduction-to-custom-events/)。

事件的好处是它们的行为就像它们的标准版本一样，包括在 DOM 中冒泡：

```js
$('p').bind('turnGreen', function() { 
  $(this).css('color', '#00ff00');
});

$('p:first').trigger('turnGreen');
```

那么，特殊事件的组成是什么？特殊事件通常采用插件的形式；格式可能类似，但我们经常会看到几个**fixHooks**中的任何一个，我们用它来控制 jQuery 中事件处理的行为。

### 注意

jQuery 特殊事件钩子是一组按事件名称分组的函数和属性，允许代码控制 jQuery 内部事件处理的行为。

让我们花一点时间来看一下特殊事件插件的典型组成，然后再深入介绍一个这样的插件的示例。

## 创建自定义事件

fixHooks 接口提供了规范或扩展将覆盖本机浏览器事件对象的路径。我们通常会看到类似以下格式的事件插件被使用：

```js
jQuery.event.special.myevent = {
  noBubble: false;
  bindType: "otherEventType",
  delegateType: "otherEventType",
  handle: function ($event, data { 
    // code
  },
  setup: function( data, namespaces, eventHandle ) {
    // code
  },
  teardown: function( namespaces ) {
    // code
  },
  add: function( handleObj ) {
    // code
  },
  remove: function( handleObj ) {
    // code
  },
  _default: function( event ) {
    // code
  }
};
```

值得注意的是，在创建特殊事件类型时，我们经常会使用两种方法 - `.on()`，用于绑定事件，以及`.trigger()`，用于在需要时手动触发特定事件。此外，特殊事件插件将公开许多有用的关键方法，值得学习。让我们来探索一下：

| 方法/属性名称 | 目的 |
| --- | --- |
| `noBubble: false` | 布尔类型，默认值为`false`。指示如果调用`.trigger()`方法，是否应用冒泡到此事件类型。 |
| `bindType` | 当定义时，这些字符串属性指定应该如何处理特殊事件类型，直到事件被传递。对于直接附加的事件，请使用`bindType`，对于已委托的事件，请使用`delegateType`。在这两种情况下，这些都应该是标准的 DOM 类型，例如`.click()`。 |
| `handle: function(event: jQuery.Event, data: Object)` | 当事件发生时调用处理程序钩子，jQuery 通常会调用用户通过`.on()`或其他事件绑定方法指定的事件处理程序。 |
| `setup: function(data: Object, namespaces, eventHandle: function)` | 第一次将特定类型的事件附加到元素时调用。这提供了一个机会，可以处理将应用于该元素上此类型的所有事件的处理。 |
| `teardown: function()` | 当特定类型的最终事件从元素中移除时调用。 |
| `add: function(handleObj)``remove: function(handleObj)` | 当通过`.on()`等 API 向元素添加事件处理程序时调用，或者在使用`.off()`时移除时调用。 |
| `_default: function(event: jQuery.Event, data: Object)` | 当从代码中使用`.trigger()`或`.triggerHandler()`方法触发特殊类型事件时调用，而不是由浏览器内部发起的事件。 |

如果您在开发中使用 jQuery Mobile，了解这些方法非常重要。移动端依赖特殊事件来产生事件，如`tap`，`scrollstart`，`scrollstop`，`swipe`或`orientationchange`。

### 提示

要了解每种方法的更多细节，请查看[`gist.github.com/cowboy/4674426`](https://gist.github.com/cowboy/4674426)上的 Ben Alman 的 Gist。

如果您正在使用特殊事件来覆盖标准事件行为，那么就需要更深入地了解这些特殊事件。如果想要更多地了解内部工作原理，值得阅读 jQuery Learning Site 上的这篇文章：[`learn.jquery.com/events/event-extensions/`](http://learn.jquery.com/events/event-extensions/)。请注意 - 这可能会变得非常复杂！

现在我们已经看到了一个特殊事件插件的一些内部工作原理，现在是时候投入使用并看到它在实际中的效果了。为此，我们将使用由 James Greene 制作的 jQuery Multiclick 插件，以展示捕获例如三次点击并将其用于执行操作的简单性。

## 使用多次点击事件插件

创建自定义事件可以简单也可以复杂。对于此演示，我们将使用 James Greene 的 jQuery Multiclick 事件插件。该插件可从[`jamesmgreene.github.io/jquery.multiclick/`](http://jamesmgreene.github.io/jquery.multiclick/)获取。我们将使用它在屏幕上发布一些消息，并且在每三次点击时更改消息。参考以下图片：

![使用多次点击事件插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00403.jpeg)

让我们看一下涉及的内容：

1.  让我们从附带本书的代码下载中提取以下文件。对于此演示，我们将需要`jquery.multiclick.js`、`jquery.min.js`、`multiclick.css`和`multiclick.html`文件。将每个文件存储在项目区域内的相应子文件夹中。

1.  在一个新文件中，添加以下代码，并保存为`multiclick.js`：

    ```js
    $(document).ready(function() {
      var addText = "Click!<br>";
      var addBoom = "Boom...!<br>";

      $("button").on("click", function($event) {
        $("p").append(addText);
      });

      $("button").on("multiclick", { clicks: 3 }, function($event) {
        $("p").append(addBoom);
      });
    });
    ```

1.  这是配置多次点击插件所必需的，并在鼠标点击时触发相应的响应。

1.  尝试在浏览器中运行演示。如果一切正常，一旦我们点击**Click me!**按钮几次，我们应该会看到与练习开始时显示的屏幕截图类似的东西。

尽管可能必须说这并不完全代表一个真实世界的例子，但所涉及的技术仍然是相同的。插件绑定到标准的点击处理程序，并且如果达到的点击次数是插件配置选项中指定值的倍数，则会触发。

# 事件命名空间

到目前为止，我们已经看到了如何委托事件并创建可以接受自定义触发器的处理程序。如果我们有一个单击事件处理程序，那么这些方法就非常完美，但是如果我们需要有多个点击处理程序呢？

好在，这里有一个简单的解决方案：给事件添加一个命名空间！而不是讨论它的工作原理，让我们快速看一下以下示例：

```js
$("#element")
  .on("click", doSomething)
  .on("click", doSomethingElse);
```

这段代码是完全可接受的 - 没有任何问题！当然，这可能不像一些人所希望的那样可读，但我们现在并不担心这一点！

这里的关键点是如果我们调用：

```js
$("#element").off("click");
```

然后我们不仅会丢失第一个点击处理程序，还会丢失第二个点击处理程序。这不是理想的。我们可以通过添加命名空间或标识符来修复此问题，如下所示：

```js
$("#element")
  .on("click.firsthandler", doSomething)
  .on("click.secondhandler", doSomethingElse);
```

如果我们现在运行相同的`.off`命令，显然两个事件处理程序都不会被移除。但是 - 假设我们做出以下更改：

```js
$("#element").off("click.firsthandler");
```

现在我们可以安全地移除第一个事件处理程序，而不会移除第二个。

### 注意

如果我们写的是 `$("#element").off(".firsthandler")`，那么它将删除所有拥有该命名空间的事件处理程序。这在开发插件时非常有用。

理解这是如何工作的最好方法，就是看它在实际中的表现。现在让我们来看下面这个简单的例子吧：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Demo: Adding namespaces to jQuery events</title>
  <script src="img/jquery.min.js"></script>
</head>
<body>
  <button>display event.namespace</button>
  <p></p>
  <script>
    $("p").on("test.something", function (event) {
      $("p").append("The event namespace used was: <b>" +
event.namespace + "</b>");
    });
    $("button").click(function(event) {
      $("p").trigger("test.something");
    });
  </script>
</body>
</html>
```

### 注意

此演示的代码可在随书附带的代码下载中找到，名为 `namespacing.html` 文件。您需要提取它以及 jQuery 的副本才能运行演示。

在这里，我们分配了两个调整大小的函数。然后我们使用命名空间删除第二个，这将完全不影响第一个，如下图所示：

![事件命名空间](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00404.jpeg)

如果我们使用 DOM Inspector 来检查代码，我们可以清楚地看到分配的命名空间；要做到这一点，设置一个断点在第 12 行，然后展开右侧的列表，如下图所示：

![事件命名空间](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00405.jpeg)

起初，这可能看起来像是一个非常简单的改变，但我非常相信 KISS 这个短语 - 你懂的！

### 提示

使用的命名空间的深度或数量没有限制；例如，`resize.layout.headerFooterContent`。命名空间也可以与标准事件或自定义事件处理程序一样使用。

添加命名空间标识符是我们可以应用于任何事件处理程序的一个非常快速简便的方法。它使我们对任何事件处理程序都有完美的控制，特别是在我们的代码中为多个实例分配函数到相同事件类型时。

### 注意

如果您经常创建复杂的事件处理程序，则可能值得查看 Mark Dalgleish 的 Eventralize 库，该库可从 [`markdalgleish.com/projects/eventralize/`](http://markdalgleish.com/projects/eventralize/) 获取。注意，它已经有 2-3 年没有更新了，但测试一下看它是否有助于整合和简化您的事件可能是值得的。

# 摘要

事件处理对于任何网站或在线应用的成功至关重要。如果处理正确，可以打造一个引人入胜的用户体验；而处理不当则可能导致一些意想不到的结果！在过去的几页中，我们已经研究了一些概念，以帮助我们发展事件处理技能；让我们花点时间回顾一下我们学到的东西。

我们先快速介绍了事件处理，然后迅速转移到探讨事件委托作为我们能够从中受益的工具之一。我们首先看了事件委派的基础知识，然后检查了使用它的影响，并学习了如何在我们的代码中控制它。

接下来是查看 `$.proxy`，在那里我们看到 jQuery 有时需要帮助，以确保在我们的代码意味着事件没有在足够高的位置传播时，事件在正确的上下文中被触发。

然后，我们将注意力转向简要介绍创建自定义事件类型和处理程序，然后探讨这些事件处理程序是如何构建的。然后，我们以 jQuery Multiclick 插件作为示例，展示了如何创建这些自定义事件处理程序，最后以使用命名空间来确保我们能够在代码中绑定或解除绑定正确的事件处理程序来结束本章。

在下一章中，我们将看一些视觉方式如何增强我们的网站 - 我们将看到如何应用效果，并管理结果效果队列如何帮助我们的网站的成功与否。
