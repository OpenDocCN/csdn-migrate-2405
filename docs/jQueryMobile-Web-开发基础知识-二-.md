# jQueryMobile Web 开发基础知识（二）

> 原文：[`zh.annas-archive.org/md5/9E8057489CB5E1187C018B204539E747`](https://zh.annas-archive.org/md5/9E8057489CB5E1187C018B204539E747)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：jQuery Mobile 配置、实用工具和 JavaScript 方法

在本章中，我们将看看如何使用 JavaScript 进一步配置和增强 jQuery Mobile 网站。到目前为止，我们已经使用 HTML 和 CSS 来生成所有内容。现在我们将看看额外的脚本，为您的网站添加额外的功能。

在本章中，我们将：

+   解释了如何通过 JavaScript 配置 jQuery Mobile 网站

+   讨论了使用 jQuery Mobile 的各种 JavaScript 实用工具以及它们的使用方式

+   解释了用于处理增强的 jQuery Mobile 表单和小部件控件的 API

# 配置 jQuery Mobile

jQuery Mobile 对您做了许多事情 - 从改善页面导航到改变表单控件的工作方式。所有这些都是为了让您的内容在移动环境中更好地运行。然而，有时您并不希望 jQuery Mobile 做某些事情，或者也许您只是想微调框架的行为。这就是配置的作用所在。

要配置 jQuery Mobile 网站，您首先需要编写代码来监听`mobileinit`事件。这可以使用普通的 jQuery 事件处理程序来监听，类似以下代码片段：

```js
$(document).bind("mobileinit", function() {
//your customization here
});

```

为了捕获此事件，您必须在 jQuery Mobile 实际加载之前对其进行配置。最简单的方法，也是 jQuery Mobile 文档建议的方法，就是将此代码放在加载 jQuery Mobile JavaScript 库之前的脚本中。以下代码片段显示了我们文件标头的典型样式：

```js
<!DOCTYPE html>
<html>
<head>
<title>Dialog Test</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>

```

请注意，jQuery Mobile 库是最后一个加载的。我们可以简单地在其之前添加一个新的脚本标签：

```js
<!DOCTYPE html>
<html>
<head>
<title>Dialog Test</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/config.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>

```

配置 jQuery Mobile 就像更新`$.mobile`对象一样简单。以下代码片段是一个简单的示例：

```js
$(document).bind("mobileinit", function() {
$.mobile.someSetting="some value here";
});

```

此对象包含一组可配置的各种设置的键/值对。实际上不需要创建它 - 它在运行事件处理程序时已经存在。另一个选项是利用 jQuery 的`extend()`功能，如下面的代码片段所示：

```js
$(document).bind("mobileinit", function() {
$.extend($.mobile, {
someSetting:"some value here"
});
});

```

两种表单都可以，并且完全相同。可以使用您觉得更舒适的任何一种。现在，让我们看看各种配置选项：

| 设置 | 使用 |
| --- | --- |
| `ns` | 这是用于数据属性的命名空间值。默认为空。如果要为 jQuery Mobile-recognized 数据属性添加前缀，则可以在此处指定值。因此，例如，如果要使用`data-jqm-role="page"`而不是`data-role="page"`，则可以将`ns`值配置为`jqm`。 |
| `activeBtnClass` | 这只是设置在活动状态下按钮使用的类名。默认值为`ui-btn-active`。 |
| `activePageClass` | 这设置了当前正在查看的页面的类名。默认值为`ui-page-active`。 |
| `ajaxEnabled` | 我们之前讨论过 Ajax 既用于页面加载，也用于表单提交。如果你希望禁用此功能，请将此值设置为 `false`。默认情况下是`true`。 |
| `allowCrossDomainPages` | 一个默认值为 false 的安全设置，将其设置为 true 允许通过 `$.mobile.loadPage` 加载来自另一个服务器的远程页面。通常仅在需要从另一个服务器加载内容的 PhoneGap 应用程序中需要。 |
| `autoInitializePage` | 通常情况下，jQuery Mobile 在加载时会运行 `$.mobile.initializePage`。这会显示渲染页面。（目前，这个特定功能并没有得到很好的文档记录。）如果你希望禁用此默认值，请将`autoInitializePage`设置为 `false`。你需要手动运行`$.mobile.initializePage`。 |
| `defaultDialogTransition` | 指定显示或隐藏对话框时使用的过渡效果。默认值为 `pop`。可能的值包括：`fade, flip, pop, slide, slidedown` 和 `slideup`。 |
| `defaultPageTransition` | 类似于前一个选项，这个设置用于页面加载时的过渡效果。默认值为 `slide`，可能的选项与前一个选项类似。 |
| `gradea` | 用于确定什么才是一个“好”浏览器。这由 jQuery Mobile 处理，但如果你想否决框架，或定义必须满足的其他条件，你可以在这里提供一个返回布尔值（true 或 false）的函数。 |
| `hashListeningEnabled` | 指的是监听浏览器的 `location.hash` 属性的能力。jQuery Mobile 通常会处理这个，但如果将值设置为 `false`，你可以编写自己的代码来响应这些变化。 |
| `ignoreContentEnabled` | 通常情况下，jQuery Mobile 会自动增强任何可能的东西。你可以在某些情况下在控件级别禁用该功能，但也可以通过添加 `data-enhance=true` 告诉 jQuery Mobile 忽略特定容器内的所有内容。如果你使用了这个功能，那么你的配置必须设置 `ignoreContentEnabled` 为 `true`。这告诉 jQuery Mobile 寻找并遵守该特定标志。默认情况下设置为 `false`，可以让 jQuery Mobile 更快地完成它的工作。 |
| `linkBindingEnabled` | jQuery Mobile 通常会监听所有链接点击。如果你希望全局禁用这个功能，可以通过这个设置来实现。 |
| `loadingMessage` | 这指定了页面加载时使用的文本。通常是“loading”，但你可能会在此处使用自定义代码来检查用户的语言环境，并使用特定的本地化版本。然而，消息通常是隐藏的。有关更多信息，请参阅下一个设置。 |
| `loadingMessageTextVisible` | 当页面由 jQuery Mobile 加载时，只会使用一个加载图形。如果你希望显示一条消息，将这个值设置为 `true`。默认值为 `false`。 |
| `loadingMessageTheme` | 用于页面加载对话框的主题。默认值为 `a`。 |
| `minScrollBack` | 当用户返回到页面时，jQuery Mobile 将尝试记住您在页面中滚动的位置。这在用户在访问另一个页面后返回到的大页面上可能很有用。默认情况下，如果滚动超过默认值 `150`，则会记住滚动位置。 |
| `pageLoadErrorMssage` | 如果加载页面时发生错误，则向用户显示的消息。默认为 **Error Loading Page**，但出于本地化原因（或其他任何原因），可能会更改。 |
| `pageLoadErrorMessageTheme` | 显示页面加载错误对话框时要使用的主题。默认值为 `e`。 |
| `pushStateEnabled` | 告诉 jQuery Mobile 使用 HTML5 `pushState` 功能而不是基于哈希的方式进行页面导航。默认值为 `true`。 |
| `subPageUrlKey` | jQuery Mobile 支持一个文件中的多个页面。为了使这些“虚拟”页面可书签化，jQuery Mobile 将在 URL 中追加一个值，该值包含前缀 `ui-page`。例如，`ui-page=yourpage`。此设置允许您自定义前缀。 |

这是相当多的选项，但通常您只需要配置其中一个或两个设置。让我们看一个简单的示例，其中使用了其中几个设置。`Listing 8-1` 是应用程序的主页。请注意，使用额外的脚本标签加载我们的配置：

```js
Listing 8-1: test1.html
<!DOCTYPE html>
<html>
<head>
<title>Page Transition Test</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.6.4.min.js"></script>
<script src="img/config.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="first">
<div data-role="header">
<h1>Dialog Test</h1>
</div>
<div data-role="content">
<p>
<a href="#page2">Another Page</a><br/>
<a href="test2.html">Yet Another Page</a><br/>
</p>
</div>
</div>
<div data-role="page" id="page2">
<div data-role="header">
<h1>The Second</h1>
</div>
<div data-role="content">
<p>
This is the Second. Go <a href="#first">first</a>.
</p>
</div>
</div>
</body>
</html>

```

文件包含两个页面，并链接到另一个 `test2.html`。该页面只提供一个返回链接，因此不会包含在文本中。现在让我们看看 `config.js:`

```js
Listing 8-2: config.js
$(document).bind("mobileinit", function() {
$.mobile.defaultPageTransition = "fade";
$.mobile.loadingMessage="Fetching page...";
});

```

在 `config.js` 中，修改了两个设置 - 默认页面转换和页面加载消息。

在前一章中，我们讨论了表单以及 jQuery Mobile 如何自动增强控件。虽然您可以在 HTML 中禁止对控件的此增强，但还可以告诉 jQuery Mobile 一系列永远不要增强的控件。要设置此列表，请为 `$.mobile.page.prototype.options.keepnative` 指定一个值。该值应为一个选择器列表。与其中一个选择器匹配的任何字段都将*不会*被增强。

# 使用 jQuery Mobile 实用程序

现在我们已经讨论了 jQuery Mobile 的配置，请让我们看一下可用于您的应用程序的实用程序。这些是框架提供的实用程序，可在任何应用程序中使用。您可能不需要它们（或其中任何一个）在您的网站上，但知道它们存在可以帮助您节省将来的时间。

## 页面方法和实用程序

让我们开始查看与页面和页面之间导航相关的方法和实用程序：

+   `$.mobile.activePage:` 此属性是对当前页面的引用。

+   `$.mobile.changePage(page,options):` 此方法用于切换到另一个页面。第一个参数 page 可以是一个字符串（URL），也可以是 jQuery DOM 对象。`options` 参数是一个可选的键/值对对象。这些选项包括：

    +   `allowSamePageTransition:` 通常情况下，jQuery Mobile 不会允许您转换到相同的页面，但如果设置为 `false`，则会允许这样做。

    +   `changeHash:` 确定 URL 是否应该更改。

    +   `data:` 传递给下一页的值的字符串或对象。

    +   `data-url:` 用于浏览器中的 URL 的值。通常由用户要发送到的页面设置。你可以在这里覆盖它。

    +   `pageContainer:` jQuery Mobile 将页面放置在作为所有页面的 *包* 的 DOM 项中。你可以绕过此自动收集并使用 DOM 中的另一个项。

    +   `reloadPage:` 如果页面已经存在于浏览器中，jQuery Mobile 将从内存中获取它。将此设置为 `true` 将强制 jQuery Mobile 重新加载页面。

    +   `role:` jQuery Mobile 通常会查找加载的页面的 `data-role` 属性。要指定另一个角色，请设置此选项。

    +   `showLoadMsg:` 通常当页面被获取时，jQuery Mobile 会显示一个加载消息。你可以通过将此值设置为 `false` 来禁用此功能。

    +   `transition:` 使用什么过渡效果。请记住，这可以在全局级别进行配置。

    +   `type:` 我们之前提到过，jQuery Mobile 通过基于 Ajax 的请求加载新页面。`type` 选项允许你指定用于加载页面的 HTTP 方法。默认为 `get`。

+   `$.mobile.loadPage(page,options):` 这是一个更低级别的函数，当 `$.mobile.changePage` 被传递一个字符串 URL 来加载时使用。它的第一个参数与 `$.mobile.changePage` 相同，但其选项限于 `data, loadMsgDelay, pageContainer, reloadPage, role` 和 `type`。这些选项与前一个选项中列出的相同，除了 `loadMsgDelay`。此值为框架尝试首先通过缓存获取页面提供时间。

+   `$.mobile.showPageLoadingMsg()` 和 `$.mobile.hidePageLoadingMsg():` 显示或隐藏页面加载消息。`showPageLoadingMsg` 函数允许自定义文本、主题和仅图标视图。

在 `listing 8-2` 中，演示了 `$.mobile.changePage` 的一个简单示例：

```js
Listing 8-2: test3.html
<!DOCTYPE html>
<html>
<head>
<title>Page Tester</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="third">
<div data-role="header">
<h1>Test</h1>
</div>
<div data-role="content">
<input type="button" id="pageBtn" value="Go to page">
</div>
</div>
<script>
$("#pageBtn").click(function() {
$.mobile.changePage("test2.html", {transition:"flip"});
});
</script>
</body>
</html>

```

页面只包含一个按钮。文件底部是一个 jQuery 事件监听器，用于监听该按钮。当点击时，使用 `$.mobile.changePage` 加载 `test2.html`，同时使用翻转过渡效果。

## 与路径和 URL 相关的实用程序

这些实用程序与应用程序的当前位置、URL 或路径相关：

+   `$.mobile.path.isAbsoluteUrl` 和 `$.mobile.path.isRelativeUrl:` 这两个函数查看一个 URL 并允许你检查它们是完整的、绝对的 URL 还是相对的 URL。

+   `$.mobile.path.isSameDomain(first url, second url):` 允许你比较两个 URL，并确定它们是否在同一个域中。此方法将注意到 http 与 https 并正确地将它们视为不同的域。

+   `$.mobile.path.makePathAbsolute(relative path, absolute path):` 获取一个相对路径，将其与一个绝对路径进行比较，并返回相对路径的绝对路径版本。

+   `$.mobile.path.makeUrlAbsolute(relative url, absolute url):` 这个工具与前一个函数稍有不同，它处理绝对 URL。

+   `$.mobile.path.parseUrl(url):` URL 由许多不同的部分组成。此函数将接受完整或相对 URL，并返回一个包含以下属性的对象：hash、host、hostname、href、pathname、port、protocol 和 search。除了这些相当典型的 URL 属性外，该函数还返回以下属性：

    +   `authority:` 包含用户名、密码和主机属性。

    +   `directory:` 给定 URL 的路径部分，这将只返回目录。

    +   `domain:` 包含 URL 的授权和协议部分。

    +   `filename:` 返回 URL 的文件名部分。

    +   `hrefNoHash:` 给定带有哈希的 URL，返回除哈希外的 href。

    +   `hrefNoSearch:` 给定带有搜索属性的 URL，返回除搜索值外的 href。

    +   `username` 和 `password:` 包含 URL 中的用户名和密码（如果有）。

`Listing 8-3` 是一个 *测试* 应用程序。它包含表单字段，允许您测试先前讨论过的所有方法：

```js
Listing 8-3: test4.html
<!DOCTYPE html>
<html>
<head>
<title>Path Tester</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.6.4.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="third">
<div data-role="header">
<h1>Test</h1>
</div>
<div data-role="content">
<form>
<div data-role="fieldcontain">
<label for="isabsurl">Is Absolute URL?</label>
<input type="text" name="isabsurl" id="isabsurl" value="" />
<div id="isabsurlresult"></div>
</div>
<div data-role="fieldcontain">
<label for="isrelurl">Is Relative URL?</label>
<input type="text" name="isrelurl" id="isrelurl" value="" />
<div id="isrelurlresult"></div>
</div>
<div data-role="fieldcontain">
<label for="issamedomain">Is Same Domain?</label>
<input type="text" name="issamedomain" id="issamedomain" value="" />
<input type="text" name="issamedomain2" id="issamedomain2" value="" />
<div id="issamedomainresult"></div>
</div>
<div data-role="fieldcontain">
<label for="makepath">Make Path Absolute</label>
<input type="text" name="makepath" id="makepath" value="" placeholder="Relative Path" />
<input type="text" name="makepath2" id="makepath2" value="" placeholder="Absolute Path" />
<div id="makepathresult"></div>
</div>
<div data-role="fieldcontain">
<label for="makeurl">Make URL Absolute</label>
<input type="text" name="makeurl" id="makeurl" value="" placeholder="Relative URL" />
<input type="text" name="makeurl2" id="makeurl2" value="" placeholder="Absolute URL" />
<div id="makeurlresult"></div>
</div>
<div data-role="fieldcontain">
<label for="parseurl">Parse URL</label>
<input type="text" name="parseurl" id="parseurl" value="" />
<div id="parseurlresult"></div>
</div>
</form>
</div>
</div>
<script>
$("#isabsurl").keyup(function() {
var thisVal = $(this).val();
var isAbsUrl = $.mobile.path.isAbsoluteUrl(thisVal);
$("#isabsurlresult").text(isAbsUrl);
});
$("#isrelurl").keyup(function() {
var thisVal = $(this).val();
var isRelUrl = $.mobile.path.isRelativeUrl(thisVal);
$("#isrelurlresult").text(isRelUrl);
});
$("#issamedomain,#issamedomain2").keyup(function() {
var domainVal1 = $("#issamedomain").val();
var domainVal2 = $("#issamedomain2").val();
var isSameDomain = $.mobile.path.isSameDomain(domainVal1,domainVal2);
$("#issamedomainresult").text(isSameDomain);
});
$("#makepath,#makepath2").keyup(function() {
var pathVal1 = $("#makepath").val();
var pathVal2 = $("#makepath2").val();
var makePathResult = $.mobile.path.makePathAbsolute(pathVal1,pathVal2);
$("#makepathresult").text(makePathResult);
});
$("#makeurl,#makeurl2").keyup(function() {
var urlVal1 = $("#makeurl").val();
var urlVal2 = $("#makeurl2").val();
var makeUrlResult = $.mobile.path.makeUrlAbsolute(urlVal1,urlVal2);
$("#makeurlresult").text(makeUrlResult);
});
$("#parseurl").keyup(function() {
var thisVal = $(this).val();
var parsedUrl = $.mobile.path.parseUrl(thisVal);
var s = "";
for (k in parsedUrl) {
s+= k+"="+parsedUrl[k]+"<br/>";
}
$("#parseurlresult").html(s);
});
</script>
</body>
</html>

```

`Listing 9-4` 有点长，但实际上非常简单。每个 `fieldcontain` 块都由路径方法和实用工具的一个特定测试组成。在模板的下半部分，您可以看到我们已经使用 `keyup` 事件侦听器来监视这些字段的更改并运行每个测试。您可以使用此模板来查看这些方法如何根据不同的输入而反应。以下截图显示了一个示例：

![路径和 URL 相关的实用工具](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_08_04.jpg)

## 杂项实用程序

还有一些您可能想了解的其他实用程序：

+   `$.mobile.fixedToolbars.hide()` 和 `$.mobile.fixedToolbars.show():` 显示或隐藏固定工具栏。这两个实用程序都可以接受一个布尔参数，指定隐藏（或显示）动作是否立即发生。如果未指定（或传递 false），则工具栏将在隐藏或显示时进行动画处理。

+   `$.mobile.silentScroll(position):` 将页面滚动到特定的 y 位置。这里的 `silent` 一词指的是此方法*不*会触发任何监听滚动事件的代码。

+   `jqmData()` 和 `jqmRemoveData():` 由于 jQuery Mobile 大量使用数据属性进行各种功能，因此应该用这些替代 jQuery 的数据函数的“常规”用法。它们处理识别对默认命名空间的任何更新。

# jQuery 小部件和表单实用工具

我们已经多次提到，jQuery Mobile 会自动更新各种项目并支持诸如列表和可折叠内容之类的功能。但是，您可能会遇到的一件事是尝试使 jQuery Mobile 与页面渲染*后*加载的内容一起工作。因此，例如，想象一下列表视图，通过一些 JavaScript 代码向其添加数据。`Listing 8-4` 展示了一个简单的示例。它有一个 `listview`，其中包含一些项目，但也有一个人可以通过其中一个表单添加新条目的表单：

```js
Listing 8-4: test5.html
<!DOCTYPE html>
<html>
<head>
<title>List Updates</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="third">
<div data-role="header">
<h1>List Updates</h1>
</div>
<div data-role="content">
<ul id="theList" data-role="listview" data-inset="true">
<li>Initial</li>
<li>Item</li>
</ul>
<form>
<div data-role="fieldcontain">
<label for="additem">New Item</label>
<input type="text" name="additem" id="additem" value="" />
</div>
<input type="button" id="testBtn" value="Add It">
</form>
</div>
</div>
<script>
$("#testBtn").click(function() {
var itemToAdd = $.trim($("#additem").val());
if(itemToAdd == "") return;
$("#theList").append("<li>"+itemToAdd+"</li>");
});
</script>
</body>
</html>

```

最初加载时，请注意一切似乎都很正常：

![jQuery 小部件和表单实用工具](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_08_01.jpg)

但是，以下屏幕截图显示了将项目添加到列表末尾时发生的情况：

![jQuery 小部件和表单实用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_08_02.jpg)

正如您所见，新项目确实被添加到了列表的末尾，但是没有正确地绘制。这提出了一个关键问题。jQuery Mobile 仅对数据属性解析您的代码并一次性检查表单字段。在这样做之后，它认为自己的工作完成了。幸运的是，这些 UI 项更新有一种标准方法。对于我们的`listview`，只需在列表本身上调用`listview`方法就可以了。`listview`方法可用于将新列表转换为`listview`，或刷新现有的`listview`。要刷新我们的`listview`，我们只需修改代码，如下面的代码片段所示：

```js
<script>
$("#testBtn").click(function() {
var itemToAdd = $.trim($("#additem").val());
if(itemToAdd == "") return;
$("#theList").append("<li>"+itemToAdd+"</li>");
$("#theList").listview("refresh");
});
</script>

```

您可以在`test6.html`中找到前一个代码片段。以下屏幕截图显示了应用程序如何处理新项目：

![jQuery 小部件和表单实用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_08_03.jpg)

那个`listview`方法也可以用于全新的列表。考虑以下代码片段`清单 8-5：`

```js
Listing 8-5: test7.html
<!DOCTYPE html>
<html>
<head>
<title>List Updates</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="third">
<div data-role="header">
<h1>List Updates</h1>
</div>
<div data-role="content" id="contentDiv">
<input type="button" id="testBtn" value="Add A List">
</div>
</div>
<script>
$("#testBtn").click(function() {
$("#contentDiv").append("<ul data-role='listview' data- inset='true' id='theList'><li>Item One</li><li>Item Two</li></ul>");
$("#theList").listview();
});
</script>
</body>
</html>

```

在这个例子中，一个全新的列表被附加到`div`标签上。请注意，我们仍然包含适当的`data-role`。但是，仅此而已是不够的。我们在 HTML 插入后紧跟着调用`listview`方法来增强刚添加的列表。

对于其他字段也存在类似的 API。例如，添加到页面的新按钮可以通过在其上调用`button()`方法来增强。一般来说，假设对增强控件的任何更改都需要通过它们各自的 JavaScript API 进行更新。

# 概要

在本章中，我们（终于！）深入了解了一些 JavaScript。我们看了一下您如何配置各种 jQuery Mobile 设置，存在哪些实用程序，以及如何处理对增强控件的后渲染更新。

在下一章中，我们将继续使用 JavaScript，并查看您的代码可以监听的各种事件。


# 第九章：处理事件

在本章中，我们将看看 jQuery Mobile 中事件是如何工作的。虽然开发人员显然可以访问常规事件（按钮点击等），但 jQuery Mobile 也为开发人员提供了自己的事件来使用。

在本章中，我们将：

+   讨论触摸、滑动、滚动和其他物理事件

+   讨论页面事件

# 处理物理事件

在本章的第一部分，我们将专注于“物理”事件，或者与使用设备时的触摸和其他操作相关的事件。

### 提示

对于那些一直在使用常规浏览器测试 jQuery Mobile 的人，请注意，以下一些示例在桌面浏览器上可能无法正常工作。如果愿意，可以下载并安装各种手机模拟器。例如，Android 有一个支持创建虚拟移动设备的 SDK。苹果也有一种模拟 iOS 设备的方法。设置和安装这些模拟器超出了本章的范围，但这当然是一种选择。当然，您也可以使用真实的硬件设备。

物理事件包括以下内容：

+   `tap` 和 `taphold: tap` 表示其听起来就像 — 网页上的快速物理触摸。 `taphold` 是一个较长时间的触摸。许多应用程序将使用两种不同的操作 — 一个用于 `tap`，另一个用于 `taphold`。

+   `swipe, swipeleft` 和 `swiperight:` 这些表示滑动，或者对大多数设备的手指移动。 `swipe` 事件是通用事件，而 `swipeleft` 和 `swiperight` 表示特定方向的滑动。不支持向上或向下的滑动事件。

+   `scrollstart` 和 `scrollstop:` 分别处理页面滚动的开始和结束。

+   `orientationchange:` 当设备方向改变时触发。

+   `vclick、vmousedown、vmouseup、vmousemove、vmousecancel` 和 `vmouseover:` 所有这些都是“虚拟”事件，旨在屏蔽对触摸或鼠标点击事件的检查。由于这些主要只是点击和触摸事件的别名，因此不会进行演示。

现在我们已经列出了基本的物理事件，让我们开始看一些示例。 `清单 9-1` 演示了 `tap` 和 `taphold` 事件的一个简单示例：

```js
Listing 9-1: test1.html
<!DOCTYPE html>
<html>
<head>
<title>Tap Tests</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="first">
<div data-role="header">
<h1>Tap Tests</h1>
</div>
<div data-role="content">
<p>
Tap anywhere on the page...
</p>
<p id="status"></p>
</div>
</div>
<script>
$("body").bind("tap", function(e) {
$("#status").text("You just did a tap event!");
});
$("body").bind("taphold", function(e) {
$("#status").text("You just did a tap hold event!");
});
</script>
</body>
</html>

```

该模板相当简单。页面上有一些解释性文本，要求用户点击它。其下是一个空段落。请注意，文档末尾有两个绑定。一个监听 `tap`，另一个监听 `taphold`。用户可以执行任一操作，并显示不同的状态消息。尽管相当简单，但这给了您一个很好的想法，即根据用户按住手指的时间长短做出不同的响应。（`taphold` 事件触发的时间大约为一秒）：

![处理物理事件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_9_1.jpg)

现在让我们来看 `清单 9-2`，一个关于滑动事件的示例：

```js
Listing 9-2: test2.html
<!DOCTYPE html>
<html>
<head>
<title>Swipe Tests</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/ jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="first">
<div data-role="header">
<h1>Swipe Tests</h1>
</div>
<div data-role="content">
<p>
Swipe anywhere on the page...
</p>
<p id="status"></p>
</div>
</div>
<script>
$("body").bind("swipe", function(e) {
$("#status").append("You just did a swipe event!<br/>");
});
$("body").bind("swipeleft", function(e) {
$("#status").append("You just did a swipe left event!<br/>");
});
$("body").bind("swiperight", function(e) {
$("#status").append("You just did a swipe right event!<br/>");
});
</script>
</body>
</html>

```

这个例子与前一个例子非常相似，只是现在我们的事件处理程序监听`swipe, swipeleft`和`swiperight`。一个重要的区别是我们附加到状态 div 而不是简单地设置它。为什么呢？`swiperight`或`swipeleft`事件自动是一个滑动事件。如果我们简单地设置段落中的文本，一个将覆盖另一个。下面的截图显示了设备在几次滑动后的外观：

![使用物理事件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_9_2.jpg)

更复杂的例子呢？考虑以下代码片段，`9-3 清单`：

```js
Listing 9-3: test3.html
<!DOCTYPE html>
<html>
<head>
<title>Swipe Tests</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="first">
<div data-role="header">
<h1>First</h1>
</div>
<div data-role="content">
<p>
Swipe to navigate
</p>
</div>
</div>
<div data-role="page" id="second">
<div data-role="header">
<h1>Second</h1>
</div>
<div data-role="content">
<p>
Swipe to the right...
</p>
</div>
</div>
<script>
$("body").bind("swipeleft swiperight", function(e) {
var page = $.mobile.activePage[0];
var dir = e.type;
if(page.id == "first" && dir == "swipeleft") $.mobile.changePage("#second");
if(page.id == "second" && dir == "swiperight") $.mobile.changePage("#first");
});
</script>
</body>
</html>

```

在这个例子中，我们有一个包含两个单独页面的文件，一个页面的 id 为`first`，另一个页面的 id 为`second`。注意我们没有链接。那么我们如何导航呢？用滑动！我们的事件处理程序现在同时监听`swipeleft`和`swiperight`。我们首先使用`$.mobile.activePage`获取活动页面，如第八章 *jQuery Mobile 中的 JavaScript 配置和实用工具*中所述，关于方法和实用工具。末尾的`[0]`表示该值实际上是一个 jQuery 选择器。使用`[0]`会获取实际的 DOM 项。事件类型将是`swipeleft`或`swiperight`。一旦我们知道了这一点，我们就可以根据用户当前所在的页面和他们滑动的方向积极地移动用户。

现在让我们来看一下滚动。你可以检测滚动何时开始以及何时结束。`9-4 清单`是另一个这样操作的简单示例：

```js
Listing 9-4: test4.html
<!DOCTYPE html>
<html>
<head>
<title>Scroll Tests</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="first">
<div data-role="header">
<h1>Scroll Tests</h1>
</div>
<div data-role="content">
<p>
Scroll please....<br/>
<br/>
<br/>
(Many <br/> tags removed to save space!)
<br/>
<br/>
</p>
<p id="status"></p>
</div>
</div>
<script>
$("body").bind("scrollstart", function(e) {
$("#status").append("Start<br/>");
});
$("body").bind("scrollstop", function(e) {
$("#status").append("Done!<br/>");
});
</script>
</body>
</html>

```

这个模板与`test1.html`，即点击测试器非常相似，只是现在我们监听了`scrollstart`和`scrollstop`。还要注意`<br/>`标签的列表。在真实的源文件中，这些标签有很多。这将确保在测试时页面确实是可滚动的。当滚动开始和结束时，我们只是将其附加到另一个状态`div`。（请注意，当前将 DOM 操作列为在监听`scrollstart`时存在错误。前面的例子在 iOS 上可能无法工作，但在 Android 上工作正常。）

现在让我们来看一下方向。虽然前面的例子大部分可以在你的桌面上测试，但你肯定需要一个真实的移动设备来测试下一个例子：

```js
Listing 9-5: test5.html
<!DOCTYPE html>
<html>
<head>
<title>Orientation Tests</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="first">
<div data-role="header">
<h1>Orientation Tests</h1>
</div>
<div data-role="content">
<p>
Tilt this sideways!
</p>
<p id="status"></p>
</div>
</div>
<script>
$(window).bind("orientationchange", function(e,type) {
$("#status").html("Orientation changed to "+e.orientation);
});
</script>
</body>
</html>

```

前一个代码清单的关键部分是最后的 JavaScript，特别是用于更改方向的事件侦听器。这实际上不是 jQuery Mobile 支持的事件，而是浏览器本身支持的事件。一旦事件侦听器被附加，你可以根据设备的方向进行任何操作。以下截图是演示：

![使用物理事件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_9_3.jpg)

# 处理页面事件

现在我们已经讨论了物理类型事件，是时候将注意力转向页面事件了。请记住，jQuery Mobile 有自己的页面概念。为了在 jQuery Mobile 中给开发人员更多控制页面工作的能力，支持了许多页面事件。并非所有事件都一定在日常开发中有用。一般来说，页面事件可以分为以下几类：

+   load：这些是与页面加载相关的事件。它们是`pagebeforeload，pageload`和`pageloadfailed。pagebeforeload`在请求页面之前触发。您的代码可以根据逻辑批准或拒绝此请求。如果加载页面，则会触发`pageload`。相反，`pageloadfailed`将在任何未完成的加载上触发。

+   change：这些事件与从一个页面更改到另一个页面有关。它们是：`pagebeforechange，pagechange`和`pagechangefailed`。与以前一样，`pagebeforechange`函数充当编程方式拒绝事件的一种方式。如果完成，将触发`pagechangefailed`事件。`pagebeforechange`在`pagebeforeload`事件之前触发。`pagechange`将在显示页面后触发。

+   transition：与从一个页面转换到另一个页面相关的事件。它们是：`pagebeforeshow，pageshow，pagebeforehide，pagehide`。`pagebeforeshow`和`pagebeforehide`在其相关事件之前运行，但与`pagebeforeload`和`pagebeforechange`不同，它们实际上不能阻止下一个事件的发生。

+   init：正如本书中多次显示的那样，jQuery Mobile 对基本 HTML 执行多次更新，以使其优化为移动显示。这些是与初始化相关的事件。您可以监听的事件是：`pagebeforecreate，pagecreate`和`pageinit。pagebeforecreate`在您的控件上的任何自动更新触发之前触发。这允许您在布局由 jQuery Mobile 更新之前通过 Javascript 操纵您的 HTML。`pagecreate`在页面内容存在于 DOM 中之后触发，但仍然在 jQuery Mobile 更新布局之前触发。官方文档建议这是进行任何自定义小部件处理的地方。最后，`pageinit`将在初始化完成后运行。

+   remove：此类别有一个事件`pageremove`。在 jQuery Mobile 从 DOM 中删除非活动页面之前触发此事件。您可以监听此事件以防止框架删除页面。

+   layout：最后一个类别与布局相关，有一个事件`updatelayout`。这通常是由其他布局更改触发的一种方式，用于通知页面需要更新自身。

这还真是不少啊！看待这些事件的一个简单方法就是简单地听取它们的全部。在`列表 9-6`中，我们有一个这样的简单示例：

```js
Listing 9-6: test_page.html
<!DOCTYPE html>
<html>
<head>
<title>Page Event Tests</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="first">
<div data-role="header">
<h1>Page Event Tests</h1>
</div>
<div data-role="content">
<p>
<a href="#page2" data-role="button">Go to Page 2</a>
<a href="test_pagea.html" data-role="button"> Go to Page 3</a>
<a href="test_pageb.html" data-role="button"> Go to Page 4</a>
<a href="test_pageDOESNTEXIST.html" data-role="button"> Go to Page Failed</a>
</p>
</div>
</div>
<div data-role="page" id="page2">
<div data-role="header">
<h1>Page Event Tests</h1>
</div>
<div data-role="content">
<p>
<a href="#first" data-role="button">Go to Page 1</a>
<a href="test_pagea.html" data-role="button"> Go to Page 3</a>
<a href="test_pageb.html" data-role="button"> Go to Page 4</a>
</p>
</div>
</div>
<script>
$(document).bind("pagebeforeload pageload pageloadfailed pagebeforechange pagechange pagechangefailed pagebeforeshow pagebeforehide pageshow pagehide pagebeforecreate pagecreate pageinit pageremove updatelayout", function(e) {
console.log(e.type);
});
</script>
</body>
</html>

```

这个模板是一个四页、三文件的简单应用程序的一部分，它有按钮链接到其他每一页。其他页面可以在你下载的 ZIP 文件中找到。为了测试这个应用程序，你**应该**使用支持控制台的桌面浏览器。任何版本的 Chrome，最近的 Firefox 浏览器（或带有 Firebug 的 Firefox）和最新的 Internet Explorer。浏览器控制台的完整说明无法在本章中适用，但你可以把它看作是一个隐藏的调试日志，用于记录事件和其他消息。在这种情况下，我们已经告诉 jQuery 监听我们所有的 jQuery Mobile 页面事件。然后我们将特定的事件类型记录到控制台。点击了一些东西之后，以下屏幕截图显示了在 Chrome 浏览器中控制台日志的样子：

![处理页面事件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_9_4.jpg)

在 Chrome 中打开控制台很简单。点击浏览器右上角的扳手图标。选择**工具**然后选择**JavaScript 控制台**。在测试这些文件之前打开控制台，你可以实时监控页面事件的发生情况。

## `$(document).ready`怎么样？

如果你是一个 jQuery 用户，你可能会好奇`$(document).ready`在 jQuery Mobile 站点中是如何发挥作用的。几乎所有的 jQuery 应用程序都使用`$(document).ready`进行初始化和其他重要的设置操作。然而，在 jQuery Mobile 应用程序中，这样做效果不佳。由于使用 Ajax 加载页面，`$(document).ready`只对*第一个*页面有效。因此，在过去使用`$(document).ready`的情况下，应该使用`pageInit`事件。

## 创建一个真实的例子

那么真实的例子呢？我们的下一组代码将演示如何创建一个简单但动态的 jQuery Mobile 网站。内容将通过 Ajax 加载。通常这将是动态数据，但出于我们的目的，我们将使用简单的静态 JSON 数据文件。JSON，代表 JavaScript 对象表示法，是一种将复杂数据表示为简单字符串的方法。`列表 9-7`是应用的首页：

```js
Listing 9-7: test_dyn.html
<!DOCTYPE html>
<html>
<head>
<title>Test Dynamic</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/ jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="homepage">
<div data-role="header">
<h1>Dynamic Pages</h1>
</div>
<div data-role="content">
<ul id="peopleList" data-role="listview" data-inset="true"></ul>
</div>
</div>
<script>
$("#homepage").bind("pagebeforecreate", function(e) {
//load in our people
$.get("people.json", {}, function(res,code) {
var s = "";
for (var i = 0; i < res.length; i++) {
s+="<li><a href='test_people.html ?id="+res[i].id+"'>"+res[i].name+"</a></li>";
}
$("#peopleList").html(s).listview("refresh");
}, "json");
});
$("#personpage").live("pagebeforeshow", function(e) {
var thisPage = $(this);
var thisUrl = thisPage.data("url");
var thisId = thisUrl.split("=")[1];
$.get("person"+thisId+".json", {}, function(res, code) {
$("h1",thisPage).text(res.name);
s = "<p>"+res.name +" is a "+res.gender+" and likes "+res.hobbies+"</p>";
$("#contentArea", thisPage).html(s);
}, "json");
});
</script>
</body>
</html>

```

这个 jQuery Mobile 页面的第一印象是，实际内容几乎不存在。至少在 jQuery Mobile 页面的内容块中是这样的。有一个`listview`但实际内容却不存在。那么内容从哪里来呢？在页面底部，你可以看到两个事件监听器。现在让我们只关注第一个。

这里的代码绑定到了 jQuery Mobile 为页面触发的`pagebeforecreate`事件。我们已经告诉 jQuery Mobile 在创建页面之前运行此事件。这个事件将运行一次且仅运行一次。在这个事件中，我们使用 jQuery 的`get`功能对文件`people.json`进行了一个 Ajax 请求。该文件只是一个以 JSON 格式表示的名字数组。

```js
[{"id":1,"name":"Raymond Camden"},{"id":2,"name":"Todd Sharp"},{"id":3,"name":"Scott Stroz"},{"id":4,"name":"Dave Ferguson"},{"id":5,"name":"Adam Lehman"}]

```

每个名称都有一个 ID 和实际的名称值。当通过 jQuery 加载时，这将转换为一组实际的简单对象。回顾事件处理程序，您会发现我们只需循环遍历此数组并创建表示一组`li`标签的字符串。请注意，每个都有一个指向`test_people.html`的链接，以及一个动态名称。还请注意链接本身是动态的。它们包括从 JSON 字符串中检索到的每个人的 ID 值：

![创建一个真实的例子](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_9_5.jpg)

早些时候提到过，但请注意调用`listview("refresh")`：

```js
$("#peopleList").html(s).listview("refresh");

```

没有`listview("refresh")`部分，我们添加到列表视图的项目将无法正确设置样式。

让我们快速看看下一个`test_people.html`：

```js
Listing 9-8: test_people.html
<!DOCTYPE html>
<html>
<head>
<title>Test Dynamic</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery- 1.7.1.min.js"></script>
<script src="img/ jquery.mobile.min.js"></script>
</head>
<body>
<div data-role="page" id="personpage">
<div data-role="header">
<h1></h1>
</div>
<div data-role="content" id="contentArea">
</div>
</div>
</body>
</html>

```

与我们的上一页一样，这一页几乎没有内容。请注意，标题和内容区域都是空白的。但是，如果您记得`test_dyn.html`中的第二个事件处理程序，我们支持在这里加载内容。这次我们使用了`pagebeforeshow`事件。为什么？我们希望在每次显示页面之前运行此代码。我们需要知道要加载的特定人员是谁。如果您记得，人员的 ID 是通过 URL 传递的。我们可以通过页面对象上存在的数据属性`url`获取它。这返回完整的 URL，但我们只关心它的末尾，即我们的 ID。因此，我们拆分字符串并抓取最后一个值。一旦我们有了，我们就可以为每个人加载特定的 JSON 文件。此文件名的形式为`personX.json`，其中`X`是 1 到 5 的数字。以下代码行是一个示例：

```js
{"name":"Raymond Camden","gender":"male","hobbies":"Star Wars"}

```

显然，真实的人物对象会有更多的数据。一旦我们获取了这个字符串，我们就可以解析它并将结果布局在页面上：

![创建一个真实的例子](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_9_6.jpg)

# 总结

在本章中，我们研究了 jQuery Mobile 应用程序可以监听和响应的事件。这些事件包括物理类型（滚动、方向、触摸）和基于页面的事件。

在下一章中，我们将看看 jQuery Mobile 站点如何主题化 - 包括开箱即用的主题和自定义主题。


# 第十章：进一步了解 Notekeeper 移动应用程序

在这一章中，我们将开始将迄今为止学到的关于列表、表单、页面和内容格式化的所有内容组合成一个可用的“移动应用程序”；即 Notekeeper 应用程序。

在本章中，我们将：

+   使用表单接受用户输入

+   使用 HTML5 localStorage 功能在本地存储用户输入的数据

+   演示如何动态地向页面添加、编辑和删除项目

# 什么是移动应用程序？

在编写我们的第一个移动应用程序之前，也许我们应该定义一下什么是移动应用程序。维基百科说，移动应用程序是*为小型低功耗手持设备开发的软件，如个人数字助理、企业数字助理或移动电话*。虽然 jQuery Mobile 应用程序是用 HTML、CSS 和 JavaScript 编写的，但这并不妨碍它们成为复杂的软件。它们肯定是针对移动设备开发的。

一些评论家可能会指出，除非“安装”，否则它实际上不能成为软件。正如您将在本书的后面看到的，与开源库 PhoneGap 配合使用时，jQuery Mobile 应用程序实际上可以安装在各种设备上（包括 iOS、Android 和 Windows Mobile）。这意味着您将能够兼得。您可能会问自己，使用 jQuery Mobile 编写的代码是否可以被视为软件，正如您将在本章中了解到的那样，答案是肯定的。

# 设计您的第一个移动应用程序

任何软件的目标都是满足需求。Gmail 通过让用户摆脱单一计算机并让他们可以从任何 Web 浏览器检查电子邮件来满足需求。Photoshop 通过允许用户以前所未有的方式操纵照片来满足需求。我们的 Notekeeper 应用程序通过允许我们记录简单的笔记以供以后参考来满足需求。我知道，与之相比有点令人失望，但我们必须从某个地方开始对吧？

在构建软件时，最好花时间事先撰写项目的规格说明：它将做什么，它将是什么样子，以及它应该具有什么。记住，如果你不知道你在构建什么，你怎么会知道它是否完成了？

## 列出要求

我们已经知道我们的应用想要做什么，记笔记。问题在于有很多种方式可以构建一个笔记应用，因此必须勾勒出我们想要的功能。不多不少，但目前足够。对开发人员来说，一个事实是我们的应用永远不会“完成”，它们只是暂时“完成”。对于 Notekeeper，我们决定我们想要用我们的应用程序做以下三件事：

+   添加笔记

+   显示笔记列表

+   查看笔记/删除笔记

在决定我们的应用程序需要完成哪些任务之后，我们需要决定它将如何完成这些任务。最简单的方法就是简单地将这些事情写成一个列表。通过将每个部分细分为更小的部分，我们使它更容易理解，并且看到我们需要做些什么才能让它工作。这就像得到去你最喜欢的餐厅的指南一样；这里拐个弯，那里转个圈，你转眼间就坐在餐桌前了。让我们看看我们希望 Notekeeper 做什么，以及下面的部分和部件：

+   添加一个注释（表单）

    +   一个表单容器。所有用户输入的小部件都被包装成一个表单。

    +   一个标题，注释的名称。这也将用于显示现有的注释。

    +   注释本身。注释的内容或主体。

    +   保存按钮。这个按钮会触发实际的保存操作。

+   显示注释列表的能力（列表视图）

    +   包含注释标题的行项。此行应该是指向包含注释主体的页面的链接。

    +   一个部分标题行可能很好。

+   查看注释的能力，并删除注释（标签，段落，按钮）

    +   标题的标签

    +   包含注释内容的段落

    +   一个标有**删除**的按钮

    +   返回按钮

### 制作线框图

现在我们已经列出了我们的应用程序的功能，那么我们如何勾画出每一部分，以便我们知道我们想要的是什么样子？如果你的艺术功底不好，或者你连一个竖直线都画不出来，不要担心。如果你有尺子，可以使用尺子，或者考虑使用微软 Excel 或 PowerPoint。你只需要能够画一些框和一些文本标签。

### 设计添加注释线框图

现在，添加注释部分怎么样？我们决定它需要一个标题，一个注释框和一个提交按钮。表单是一个不可见的容器，所以我们不需要画出来：

![设计添加注释线框图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/Image4946.jpg)

### 显示注释框架

列表视图是移动开发的一个重要部分。这是将类似项目简单地分组在一起的最简单方法，另外它还提供了许多额外的功能，比如滚动和内置图片链接。我们将使用列表视图来显示我们的注释列表：

![显示注释框架](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/Image4953.jpg)

### 查看注释/删除按钮框架

最后，一旦我们添加了一个注释，我们需要能够删除证据，我是说清除旧注释以为新注释腾出空间。请注意，我们还勾画了一个返回按钮。一旦你开始看到事情摆放出来，你会发现你忘记了一些非常重要的事情（比如能够返回到上一页）：

![查看注释/删除按钮框架](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/Image4962.jpg)

## 编写 HTML

现在我们的线框图已经完成，我们对它们感到满意，是时候将铅笔画变成 1 和 0 了。由于我们的应用程序相对简单，HTML 中的任何内容都不应该难倒你。毕竟，你已经过了书的一半了，而且你应该能够做到这些事情。

你所提出的 HTML 应该看起来与下面的代码片段非常相似。让我们一起来检查一下：

```js
Listing 10-1: notekeeper.html
<!DOCTYPE html>
<html>
<head>
<title>Notekeeper</title>
<meta name="viewport" content="width=device-width, initial- scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<script src="img/jquery-1.6.4.js"></script>
<script src="img/ jquery.mobile.min.js"></script>
<script src="img/application.js"></script>
</head>
<body>
<div data-role="page">
<div data-role="header">
<h1>Notekeeper</h1>
</div>
<div data-role="content">
<form>
<div>
<input id="title" type="text" placeholder="Add a note" />
</div>
<div>
<textarea id="note" placeholder="The content of your note"></textarea>
</div>
<div class="ui-grid-a">
<div class="ui-block-a">
<input id="btnNoThanks" type="submit" value="No Thanks" />
</div>
<div class="ui-block-b">
<input id="btnAddNote" type="button" value="Add Note" />
</div>
</div>
</form>
<ul id="notesList" data-role="listview" data-inset="true">
<li data-role="list-divider">Your Notes</li>
<li id="noNotes">You have no notes</li>
</ul>
</div>
<div data-role="footer" class="footer-docs">
<h5>Intro to jQuery Mobile</h5>
</div>
</div>
</body>
</html>

```

我们的笔记管理应用程序将使用单个 HTML 文件（`notekeeper.html`）和单个 JavaScript 文件（`application.js`）。直到这一点，您编写的代码都不需要 JavaScript，但是一旦您开始编写更复杂的应用程序，JavaScript 就会成为必需品。在您的网络浏览器中预览 `列表 10-1` 中的 HTML，您应该会看到类似以下截图的内容：

![编写 HTML](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/Image4970.jpg)

请注意，我们在同一个页面上显示**添加笔记**表单和查看笔记。在移动应用程序开发中，尽可能压缩东西是个好主意。不要将这个作为硬性规则，但由于我们的应用程序很简单，把这两部分放在一起是可以接受的决定，只要它们清晰地标记出来。你可以看到，这个页面满足了我们为添加笔记和显示现有笔记设定的所有要求。它有一个标题输入字段，一个笔记输入字段，一个保存按钮，并且整个东西都包裹在一个表单容器中。它还有一个列表视图，用于显示我们添加笔记后的笔记。这里看不到的是一个删除按钮，但一旦我们添加了第一个笔记并查看详细页面，它就会显示出来。

# 使用 JavaScript 添加功能

正如本书所提到的，您不需要编写任何 JavaScript 就能从 jQuery Mobile 中获得物有所值。但是随着您在 jQuery Mobile 中的经验不断增加，您将开始看到 JavaScript 可以为您的项目增加多少附加值。在我们查看代码之前，让我们谈谈它将如何结构化。如果您有任何网络设计或开发经验，您可能已经看到过 JavaScript。毕竟，它从 1995 年就开始存在了。问题是，JavaScript 有很多种不同的方法来做同样的事情，而不是所有方法都是好的。

这个应用程序中的 JavaScript 代码将使用所谓的设计模式。这只是一个花哨的术语，用来指定代码的某种结构。使用现有设计模式的主要原因有三个：

+   它帮助我们的代码保持组织和整洁。

+   它防止我们编写的变量和函数被我们可能添加的任何其他代码意外覆盖或更改。也许是一个 jQuery 插件，或者是从第三方网站加载的代码。

+   它将帮助未来的开发人员更快地适应你的代码。你在开发下一个 Facebook 的时候有考虑到未来的开发人员吗？

在我们深入了解完整代码之前，让我们先来看一个非常简单的实现这个设计模式的示例：

```js
Listing 10-2: kittyDressUp.js
$(document).ready(function(){
// define the application name
var kittyDressUp = {};
(function(app){
// set a few variables which can be used within the app
var appName = 'Kitty Dress Up';
var version = '1.0';
app.init = function(){
// init is the typical name that developers give for the
// code that runs when an application first loads
// use whatever word you prefer
var colors = app.colors();
}
app.colors = function(){
var colors = ['red','blue','yellow','purple'];
return colors;
}
app.init();
})(kittyDressUp);
});

```

如果您熟悉 JavaScript 或 jQuery，您可能会看到一些您熟悉的元素。对于那些不熟悉 jQuery 或 JavaScript 的读者，我们将逐行审查这个示例。`KittyDressUp.js` 以 jQuery 的最好朋友开头。包含在花括号内的任何代码都会等到文档或 HTML 页面完全加载后再执行。这意味着您，开发人员，可以确保您的代码在页面上需要的一切都加载完成后才运行：

```js
$(document).ready({
// I'm ready captain!
});

```

简单来说，下一行创建了一个名为 `kittyDressUp` 的变量，并将其赋值为空对象的值。但是，在我们的代码中，这个新对象将包含我们的整个应用程序：

```js
// define the application name
var kittyDressUp = {};

```

下面的声明是 Kitty Dress Up 应用程序的核心。它创建了一个接受单个参数的函数，然后立即调用自身，并传入我们在前一行中创建的空对象。这个概念称为自执行函数，它是使外部代码无法干扰我们的应用程序的方法。

```js
(function(app){
// define the app functionality
})(kittyDressUp);

```

接下来的两行设置了一些只能从我们应用程序的上下文或范围中访问的变量：

```js
// set a few variables which can be used within the app
var appName = 'Kitty Dress Up';
var version = '1.0';

```

最后，最后几行设置了两个在应用程序中可用的函数。您可以看到每个函数都被分配了一个在更大应用程序范围内的名称。`app` 变量是函数所在的地方，. 后面的单词是函数名称。请注意，在 `init` 函数内部，我们正在调用同一应用程序内的另一个函数，`app.colors()`。我们也可以引用我们在顶部定义的任何变量。

```js
app.init = function(){
// init is the typical name that developers give for the
// code that runs when an application first loads
// use whatever word you prefer
var colors = app.colors();
}
app.colors = function(){
var colors = ['red','blue','yellow','purple'];
return colors;
}
app.init();

```

请记住，`app` 是传递给自执行函数的参数名称，其值为空对象。作为整体，这几行代码创建了一个名为 `kittyDressUp` 的对象，其中包含两个变量（`appName` 和 `version`），以及两个函数（`init` 和 `colors`）。这个示例以及 Notekeeper 的代码都是简单的示例，但它们说明了您可以如何将代码包装成离散包以用于更大应用程序的各个部分。事实上，在 `kittyDressUp.js` 运行之后，您甚至可以将 `kittyDressUp` 传递到另一组代码中以供使用。

哎呀... 大家休息五分钟，你们赚了它。

## 存储 Notekeeper 数据

现在我们从五分钟的休息中回来了，是时候卷起袖子开始为我们的应用程序添加功能了。虽然我们已经讨论了我们希望 Notekeeper 的行为方式，但我们还没有讨论到存储笔记数据的核心问题。有几种可能性，都有利弊。让我们列出它们：

+   **数据库（MySQL、SQL Server、PostgreSQL）：** 虽然数据库是理想的解决方案，但它对我们的应用程序来说有点复杂，它需要互联网连接，并且您需要一个服务器端组件（ColdFusion、PHP、.NET）作为中间人将笔记保存到数据库中。

+   **文本文件：** 文本文件非常棒，因为它们占用的空间很小。问题在于作为 Web 应用程序，Notekeeper 无法将文件保存到用户的设备上。

+   **localStorage：** localStorage 相对较新，但它迅速成为一个很好的选择。它以键/值对的形式存储信息在用户的设备上。它有大小限制，但对于纯文本来说相当大，大多数现代浏览器都支持它，并且可以在离线模式下使用。

### 使用 localStorage

为了本章的目的，我们将选择`localStorage`作为我们的首选方法。让我们快速看一下其行为，这样当你看到它时，你就会熟悉它。如前所述，`localStorage`的工作原理是存储键/值对中的数据。将值保存到`localStorage`有两种方式，无论你选择哪一种，都很容易：

```js
localStorage.setItem('keyname','this is the value I am saving');

```

或

```js
localStorage['keyname'] = 'this is the value I am saving';

```

选择哪个版本完全取决于个人偏好，但因为输入较少，我们将使用第二种方法，方括号。我们将遇到的一个问题是，`localStorage`无法存储如数组或对象之类的复杂数据。它只能存储字符串。这是一个问题，因为我们将把所有数据存储在一个变量中，以便始终知道其位置。别担心，我们可以欺骗`localStorage`，使用一个名为`stringify()`的内置函数将我们的复杂对象转换为其自身的字符串表示。

以下代码片段显示了它是如何工作的：

```js
// create our notes object
var notes = {
'note number one': 'this is the contents of note number one', 'make conference call': 'call Evan today'
}
// convert it to a string, then store it.
localStorage['Notekeeper'] = JSON.stringify(Notekeeper);

```

检索值与设置值一样简单，并且也提供两个选项。通常需要定义一个变量来接收`localStorage`变量的内容。

```js
var family = localStorage.getItem('my family');

```

或

```js
var family = localStorage['my family'];

```

如果您正在检索复杂的值，则必须在使用变量内容之前执行另一步。正如我们刚才提到的，要存储复杂的值，您必须首先使用`stringify()`函数，它有一个称为`parse()`的相对应函数。`parse()`函数接受包含该复杂对象的字符串，并将其转换回纯粹的 JavaScript。它的用法如下：

```js
var myFamily = ['andy', 'jaime', 'noelle', 'evan', 'mason'];
localStorage['family'] = JSON.stringify(myFamily);
var getFamily =JSON.parse(localStorage['family']);

```

最后，如果你想完全删除该密钥，那么你可以在单行代码中完成，有两种选择：

```js
localStorage.removeItem('my family');

```

或

```js
delete localStorage[my family'];

```

值得注意的是，如果您尝试检索在`localStorage`中不存在的密钥，JavaScript 不会引发错误。它只会返回“未定义”，这是 JavaScript 表示“抱歉，什么也没有”的方式。以下代码片段是一个示例：

```js
var missing = localStorage['yertl the turtle'];
console.log(missing);
// returns undefined

```

## 有效使用样板文件

在我们开始构建 JavaScript 文件之前，还有一件事情。在我们的应用程序中，我们只会有一个 JavaScript 文件，它将包含整个代码库。这对于像我们这样的小型应用程序来说是可以的，但对于更大的应用程序来说不是一个好主意。最好将项目分解为不同的部分，然后将每个部分放入它们自己的文件中。这样做可以使开发团队更容易地协同工作（例如，Noelle 负责登录流程，而 Mason 则负责供应商列表）。它还使每个文件变得更小且更容易理解，因为它只涉及整体的一部分。当您希望应用程序的所有部分具有相似的结构和设计时，最好的方法是从一个模板开始每个部分。我们将为我们应用程序的唯一文件使用一个模板（你可以在以下代码片段中看到，`Listing 10-3`）。你可能会注意到它看起来非常类似于 `kittyDressUp` 示例，你是对的：

```js
Listing 10-3: application.js
$(function(){
// define the application
var Notekeeper = {};
(function(app){
// variable definitions go here
app.init = function(){
// stuff in here runs first
}
app.init();
})(Notekeeper);
});

```

## 构建添加注释功能

最后，我们可以开始构建了！由于要显示不存在的笔记列表很困难，更不用说删除笔记了，我们将首先编写 `添加注释` 功能。用户要能够添加注释，他们必须输入标题、注释内容，然后点击提交按钮。所以我们从那里开始。

### 添加绑定

我们将在 `app.init()` 函数定义下创建一个新的、空的函数块。它应该看起来类似于以下代码行：

```js
app.bindings = function(){
}

```

绑定函数将包含在我们的应用程序中当用户执行某些操作时需要触发的任何代码片段，例如点击提交按钮或删除按钮。我们将这些代码片段组合在一起以便组织。在 `bindings()` 函数内部，我们将添加以下行。这将在用户单击 `添加注释` 表单的提交按钮时触发：

```js
// set up binding for form
$('#btnAddNote').bind('click', function(e){
e.preventDefault();
// save the note
app.addNote(
$('#title').val(),
$('#note').val()
);
});

```

jQuery 的 `val()` 函数是一个简写方法，用于获取任何表单输入字段的当前值。

关于这个新添加的一些说明：

+   当使用 jQuery 时，总会有更多的方法来完成某件事情，在大多数情况下，你只需选择自己喜欢的方法即可（它们通常具有相同的性能）。你可能更熟悉 `$('#btnAddNote').click()`，那也完全可以。

+   请注意，`click` 函数接受一个参数：`e`，它是事件对象（在本例中是点击事件）。我们调用 `e.preventDefault()` 来阻止在此元素上发生标准点击事件，但仍允许其余代码继续运行。你可能已经看到其他开发人员使用 `return false`，但 jQuery 最佳实践建议使用 `e.preventDefault()`。

+   在点击绑定中，我们调用 `addNote` 函数，并将用户输入的标题和注释传递给它。空白不重要，仅仅是为了更容易看到我们在做什么。

即使我们已经将绑定添加到我们的代码中，如果你现在运行应用程序，当你点击**添加笔记**按钮时什么也不会发生。原因是还没有任何东西调用`bindings()`函数。在`init()`函数内添加以下行，然后你就可以准备好了：

```js
app.init = function(){
app.bindings();
}

```

### 收集和存储数据

接下来，在`app.bindings`下面添加另一个新的空函数块：

```js
app.addNote = function(title, note){
}

```

现在，因为我们将所有的笔记都存储在`localStorage`的一个键中，我们首先需要检查是否已经存在任何笔记。从`localStorage`中检索 Notekeeper 键，将其保存到一个变量中，然后进行比较。如果我们要求的键的值是一个空字符串或`undefined`，我们将需要创建一个空对象。如果有一个值，那么我们将取出该值并使用`parse()`函数将其转换为 JavaScript：

```js
var notes = localStorage['Notekeeper'];
if (notes == undefined || notes == '') {
var notesObj = {};
} else {
var notesObj = JSON.parse(notes)
}

```

注意我们期望将两个变量传递给`addNote()`函数，`title`和`note`。接下来，我们用破折号替换标题中的任何空格，这样某些浏览器更容易理解文本字符串。然后我们将键值对放入我们新创建的笔记对象中：

```js
notesObj[title.replace(/ /g,'-')] = note;

```

JavaScript 的`replace`方法使字符串操作非常简单。它作用于一个字符串，接受一个搜索项和一个替换项。搜索项可以是一个简单的字符串，也可以是一个复杂的正则表达式。

下一步是将我们的`notesObj`变量`stringify()`并放入`localStorage`中。然后我们清除两个输入字段的值，以便用户更轻松地输入另一个笔记。在构建软件时，一般在添加或删除内容后将界面恢复到原始状态是一个不错的举措：

```js
localStorage['Notekeeper'] = JSON.stringify(notesObj);
// clear the two form fields
$note.val('');
$title.val('');
//update the listview
app.displayNotes();

```

所有这些变量定义对你来说应该很熟悉，也许有一个例外，我们应该指出。许多 jQuery 开发人员喜欢为包含 jQuery 对象的变量使用传统命名。

具体来说，它们在变量名前面加上了`$`符号，就像在 jQuery 中一样。这让他们或者未来的开发者知道变量中包含的是什么。让我们继续在我们的应用程序顶部添加这些定义。在读取`// 变量定义放在这里`后面的一行，添加以下行。它们分别指的是标题输入字段和笔记文本区域字段：

```js
var $title = $('#title');
var $note = $('#note');

```

作为这个函数的最后一步，我们调用`app.displayNotes()`来更新笔记列表。由于该函数尚不存在，接下来我们来创建它。

### 构建显示笔记功能

在编写上一节时，你可能已经测试了`添加笔记`功能。这意味着你至少已经在`localStorage`中保存了一个笔记，用于测试`显示笔记`功能。到现在为止，你已经熟悉了我们在任何新节的第一步。继续添加你的空白`displayNotes()`函数来保存我们的代码：

```js
app.displayNotes = function(){
}

```

接下来，我们需要从`localStorage`中检索所有的笔记：

```js
// get notes
var notes = localStorage['Notekeeper'];
// convert notes from string to object
return JSON.parse(notes);

```

你可能会注意到我们的许多函数都有一个模式，几乎所有这些函数都以从 `localStorage` 中检索笔记开始。虽然只需要两行代码来执行此任务，但我们不需要在每次需要获取笔记时重复这两行代码。所以我们将编写一个包含这两行代码的快速辅助函数。它看起来类似于以下代码片段：

```js
app.getNotes = function(){
// get notes
var notes = localStorage['Notekeeper'];
// convert notes from string to object
return JSON.parse(notes);
}

```

有了我们的新辅助函数，我们可以像下面的代码片段中所示，在 `displayNotes()` 函数中使用它：

```js
app.displayNotes = function(){
// get notes
var notesObj = app.getNotes();
}

```

现在我们有了包含我们笔记数据的 `notesObj` 变量，我们需要循环遍历该数据包并输出内容：

```js
// create an empty string to contain html
var html = '';
// loop over notes
for (n in notesObj) {
html += li.replace(/ID/g,n.replace(/-/g,' ')).replace(/LINK/g,n);
}
$ul.html(notesHdr + html).listview('refresh');

```

对于 `for` 循环内的一行具有多个替换语句可能看起来有些奇怪，但是 JavaScript 的性质允许方法链式调用。链式调用指的是返回其操作结果的整个结果的方法。添加额外的方法调用只是简单地重复该过程。

这个代码块中可能有一些新概念，所以让我们仔细看看。名为 `html` 的变量并不特别，但我们如何使用它可能是特别的。当我们遍历现有的笔记时，我们将新信息存储到 `html` 变量中，以及其他任何内容。我们通过使用 `+=` 运算符来实现这一点，该运算符允许我们同时赋值和追加。

第二件你可能注意到的事情是赋值右边的 `li`。它从哪里来？那是一个尚未创建的单个列表项的模板。让我们在谈论它之前就做这件事。在你的 `app.js` 文件顶部，在读取 `// 变量定义在此` 之后的一行之后，添加以下两行代码：

```js
var $ul = $('#notesList');
var li = '<li><a href="#pgNotesDetail?title=LINK">ID</a></li>';

```

你应该已经熟悉了在变量前加`$`来表示一个 jQuery 对象的约定。这就是我们在 `$ul` 变量中所做的事情。第二个变量，`li` 有些不同。它包含了一个单独的列表项的 HTML，用于显示一个笔记标题。最好的做法是尽可能避免在 JavaScript 中混合使用 HTML 或 CSS。我们现在将其声明为一个模板，以防将来决定在多个地方使用它。

另一个可能感兴趣的部分是我们如何使用 `li` 变量。在调用字符串替换函数时，我们正在查找单词 LINK 的所有出现，并用笔记的标题替换它。因为 JavaScript 是大小写敏感的语言，所以我们可以安全地假设我们不会遇到该单词的自然出现。

## 动态添加笔记到我们的列表视图

在我们的笔记显示在页面上之前，还有最后一件事情要安排。您可能已经注意到，唯一调用`displayNotes()`函数的地方出现在`addNote()`函数内部。这是一个很好的地方，但它不能是唯一的地方。我们需要在页面首次加载时运行某些内容。这个地方最好是在`init()`函数中，并且这就是我们要放置它的地方。

不过，有一个问题，我们不能只加载我们的笔记然后运行，如果没有笔记会发生什么？我们需要向用户显示一个友好的消息，以便他们不会认为出了什么问题。让我们创建一个名为`app.checkForStorage()`的新函数来处理所有这些：

```js
app.checkForStorage = function(){
// are there existing notes?
if (localStorage['Notekeeper']) {
// yes there are. pass them off to be displayed
app.displayNotes();
} else {
// nope, just show the placeholder
$ul.html(notesHdr + noNotes).listview('refresh');
}
}

```

到现在为止，所有这些对你来说应该都很熟悉：检查`localStorage`是否有笔记，并在找到它们时调用`displayNotes()`函数。不过，第二部分有一些新内容。当我们为`$ul`jQuery 对象设置 html 时，我们调用了两个新变量。一个是列表视图的标题，另一个是如果我们没有任何笔记时的情况。让我们现在添加这两个变量定义。在`// 变量定义在此处`下面，添加以下两行：

```js
var notesHdr = '<li data-role="list-divider">Your Notes</li>';
var noNotes = '<li id="noNotes">You have no notes</li>';

```

行的最后一部分通常可能会被忽视，但我们不会让它被忽视。这真的很重要。jQuery Mobile 为开发人员提供了选择。一种选择是使用静态 HTML 代码，在页面加载时已经存在；jQuery Mobile 还提供了在运行时添加 HTML 代码的选项。这确实给开发人员带来了很大的灵活性，但同时也提出了一个独特的挑战。按设计，jQuery Mobile 在页面加载之前将 HTML 转换为时尚的按钮。这意味着在此之后添加的任何 HTML 将以没有任何样式的方式呈现给用户。

然而，jQuery Mobile 也提供了一种方法来解决这个问题，即内置刷新每个转换的元素的功能。大多数元素都有一个与元素名称对应的内置函数；在我们的情况下，它是`listview()`函数。实际上，这种方法提供了向页面添加一个全新列表视图的能力。在我们的情况下，我们只关心刷新我们已经拥有的列表视图，因此我们只需添加`refresh`关键字，jQuery Mobile 就会将你的纯文本列表视图转换。试着省略最后一部分，看看 jQuery Mobile 能为你节省多少工作量。也许你应该将 jQuery Mobile 团队加入你的圣诞卡列表？

最后，我们必须实际调用我们的最新函数。在`init()`函数中添加以下行。然后重新加载页面，看看你的笔记如何加载。

```js
app.checkForStorage();

```

## 查看笔记

此时，我们应该能够创建一个新的笔记，并且该笔记会立即显示在我们的列表视图中。事实上，列表视图中的行已经是链接，它们只是不起作用，让我们立即更改它。

### 使用 Live 函数

将以下行添加到`bindings()`函数中：

```js
$('#notesList a').live('click',function(e){
e.preventDefault();
var href = $(this)[0].href.match(/\?.*$/)[0];
var title = href.replace(/^\?title=/,'');
app.loadNote(title);
});

```

这个新的绑定有一些新概念，所以让我们来解析一下。首先，我们不使用 `bind` 函数，而是使用 jQuery 的 `live`函数。区别在于 `bind` 仅适用于现有的页面元素，而 `live` 是主动的。它既适用于现有元素，也适用于应用绑定后创建的元素。

绑定的第二行和第三行可能看起来有点混乱，但它们只做一件事。它们从被点击的链接的 href 属性中检索 URL。我们在本章前面定义的 `li` 模板包含每个列表项的以下 URL：

```js
#pgNotesDetail?title=LINK

```

`displayNote()` 函数运行后，URL 看起来像这样（将鼠标悬停在每个列表项上，以查看其在浏览器窗口底部的链接）：

```js
#pgNotesDetail?title=the-title-of-the-note

```

最后，我们告诉我们的代码运行一个名为 `app.loadNote()` 的新函数。

## 动态创建一个新页面

如果你还没有为我们的新 `loadNote()` 函数创建一个新的空函数块，现在就去做吧。记住，我们要传入要查看的笔记的标题，所以确保在 `loadNote()` 函数中添加这个作为参数：

```js
app.loadNote = function(title){
}

```

然后将以下两行放在函数的顶部：

```js
// get notes
var notes = app.getNotes();
// lookup specific note
var note = notes[title];

```

第一行检索我们的笔记对象，而第二行提取用户请求的具体笔记。下一个变量定义打破了我们之前在本章提到的关于混合 HTML 和 JavaScript 的规则，但每个规则都有例外。我们在这里定义它，而不是在我们的 JS 文件的标题，因为它只在这里需要。这仍然可以保持文档的组织性。

```js
var page = '<div data-role="page" data-url="details" data-add-back- btn="true">\
<div data-role="header">\
<h1>Notekeeper</h1>\
<a id="btnDelete" href ="" data-href="http://ID data-role="button" class="ui-btn-right">Delete</a>\
</div>\
<div data-role="content"><h3>TITLE</h3><p>NOTE</p></div>\
</div>';

```

`page` 变量现在包含了显示"笔记详情"页面所需的所有 HTML。你还记得我们的应用只有一个 HTML 文件吗？我们实际上正在使用先前的 HTML 代码从头开始创建整个页面。其中也有一些值得指出的细节：

+   默认情况下 jQuery Mobile 不为页面提供返回按钮。然而，你可以在每个页面上使用 `data-add-back-btn="true"` 属性来启用返回按钮，该属性需要添加在带有 `data-role="page"` 属性的任何 `div` 标签上。

+   `data-url` 属性是 jQuery Mobile 使用的标识符，以便可以跟踪生成的多个页面。

现在我们在一个变量中包含了整个页面，我们可以对它做什么？我们可以将它转换为 jQuery 对象。通过用 `$()` 将任何独立的 HTML 块包装起来，我们就可以将其转换为一流的 jQuery 对象：

```js
var newPage = $(page);

```

然后我们可以取出新创建页面的 HTML，并用我们选择的笔记的值替换部分内容。

```js
//append it to the page container
newPage.html(function(index,old){
return old
.replace(/ID/g,title)
.replace(/TITLE/g,title
.replace(/-/g,' '))
.replace(/NOTE/g,note)
}).appendTo($.mobile.pageContainer);

```

从版本 1.4 开始，jQuery 提供了在某些函数内部使用**回调**的选项。这些函数包括`.html()`、`.text()`、`.css()`等几个。该函数期望两个参数，第二个参数包含当前匹配元素中包含的完整 HTML。这意味着我们可以对`newPage`变量内包含的 HTML 进行微调，而不必完全更改它。太棒了，不是吗？

接下来，我们将整个`newPage`变量追加到当前页面的末尾，这里通过`$.mobile.pageContainer`常量引用。最后，因为我们取消了绑定中的默认点击操作，所以我们必须告诉链接执行一个操作，即将用户转到这个新创建的页面。jQuery Mobile 提供了内置的方法来实现这一点：

```js
$.mobile.changePage(newPage);

```

现在是大揭示的时刻。如果你在浏览器中加载`notekeeper.html`，你应该能够在一个浏览器窗口内添加、显示和最终查看笔记。jQuery Mobile 是不是很棒？

![动态创建新页面](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/Image5068.jpg)

## 删除笔记

回顾我们应用程序的需求，我们做得相当不错。我们编写了设置文档结构的 HTML 代码，允许我们添加笔记、显示笔记和查看笔记。剩下的只是删除一个笔记，它始于我们在`bindings()`函数中设置的最后一个绑定。现在就让我们添加它：

```js
$('#btnDelete').live('click',function(e){
e.preventDefault();
var key = $(this).data('href');
app.deleteNote(key);
});

```

在这个绑定中，可能有一个对你来说是新的项目，那就是 jQuery 的`.data()`函数的使用。HTML 5 允许你通过使用以`data-`为前缀的属性直接在任何 HTML 元素上存储任意数据，而这种能力是 jQuery Mobile 功能的核心。任何你看到`data-role="something"`的地方，你都在看 HTML 5 数据的作用。此外，jQuery 允许你通过使用`.data()`函数并传入你想查看的项目的键来检索任何`data-`值。在上面的情况中，我们将笔记的标题存储到了查看页面中的删除按钮上的`data-href`属性中。因为我们正在添加的绑定是一个分配给删除按钮的点击处理程序，所以我们可以通过调用`$(this).data('href')`来检索笔记的标题。太棒了！

这将是我们在本章中添加的最后一个函数。你难过吗？这确实是一个令人难忘的时刻，但是在你成为一名成功的 jQuery Mobile 开发人员之后，我们可以怀着美好的回忆回顾这一刻。再次，我们从一个接受单个参数，即我们要删除的笔记的标题的空函数开始。

```js
app.deleteNote = function(key){
}

```

随后是我们用于检索笔记的辅助函数的函数定义：

```js
// get the notes from localStorage
var notesObj = app.getNotes();

```

然后我们删除笔记。你已经在我们审阅`localStorage`时看到了它的作用，所以应该对你来说很熟悉：

```js
// delete selected note
delete notesObj[key];
// write it back to localStorage
localStorage['Notekeeper'] = JSON.stringify(notesObj);

```

删除备注紧随其后的是将剩余备注重新写入`localStorage`。`deleteNote()`函数中的最后两行将我们带回到应用程序的主页面，即备注列表。它们还会触发原始的`checkForStorage()`函数。

```js
// return to the list of notes
$.mobile.changePage('notekeeper.html');
// restart the storage check
app.checkForStorage();

```

最后一行可能对你来说有些奇怪，但请记住，我们事先不知道是否还有任何备注。运行存储检查允许我们显示占位文本，以防没有备注。养成这种习惯很好，因为它有助于减少我们的应用程序出现错误的可能性。

# 摘要

在本章中，我们使用 jQuery Mobile 构建了一个活生生的移动应用程序。停下来给自己一个赞。我们通过列出应用程序的要求、构建线框图和编写 HTML 的过程来完成了这一过程。我们学习了关于 HTML 5 的`localStorage`，使用模板进行文本替换，以及 jQuery Mobile 的一些更酷的功能，包括动态添加和刷新页面上的元素。

在下一章中，你将学习如何为 jQuery Mobile 设置全局配置选项，如何在 jQuery Mobile 中使用其他 API 来处理表单和内容块。


# 第十一章：增强 jQuery Mobile

在本章中，我们将学习如何增强 jQuery Mobile，如何通过创建主题和图标来改善应用程序的外观和功能，使您的移动应用程序真正脱颖而出。

在本章中，我们将：

+   了解 jQuery Mobile 的构建模块

+   使用 ThemeRoller 创建我们自己的 jQuery Mobile 主题

+   为我们的应用设计并实现自定义图标

# 有什么可能？

当许多开发人员第一次使用 jQuery Mobile 时，他们的反应是对其易于实现丰富、引人入胜的移动网站感到敬畏。它轻松将普通 HTML 转换为美观、可用的按钮和列表视图。表单元素非常容易处理。jQuery Mobile 团队甚至随包提供了五种设计良好、吸引人的主题和 18 个常用图标。他们甚至建立了一个工具，供我们使用来构建自己的主题；**ThemeRoller**。

在使用 jQuery Mobile 一段时间后，开发人员可能会问"我还可以用这个做什么*别的*吗？" 就像 60 年代和 70 年代的肌肉车一样。它们已经很棒了，但调整者和发烧友还想做更多。如果你有这种心态，那么本章就是为你准备的。

关于 jQuery Mobile 的美妙之处在于，因为它全部是普通的 CSS 和 HTML，我们几乎可以用很少的工作做任何我们想做的事情。在本章中，我们将使用 ThemeRoller 为 jQuery Mobile 从头开始创建自己的主题。我们将设计按钮并编写必要的 CSS 代码来实现低分辨率和高分辨率版本。我们还将探讨如何扩展 jQuery Mobile 中已有的样式和类，并制作出不同和独特的东西。那么，让我们开始吧？

# jQuery Mobile 的视觉构建模块

正如你已经看到的，jQuery Mobile 非常用户友好且外观令人愉悦。它充分利用了圆角、微妙的渐变、投影来突出元素与周围环境的区别，以及其他*技巧*，这些技巧多年来一直是平面设计师在印刷品中使用的。但在网络上，这些效果只能通过使用图片或复杂且支持不佳的插件和小程序来实现。

随着 Web 2.0 和 CSS 3 的出现，所有这些选项都已提供给我们，即普通的网页开发人员。只需记住，权力越大，责任越大。jQuery Mobile 基于渐进增强的原则运作。这个繁琐的短语只是意味着您应该为理解这些增强的浏览器开发，并为理解它们的浏览器提供增强。

幸运的是，这些样式上的附加几乎纯粹是装饰性的。如果浏览器不理解`border-radius`声明，那么它将简单地显示方形边角。渐变和阴影也是如此。虽然 jQuery Mobile 默认为您的应用程序添加这些效果，但了解如何自己添加它们也是值得的。

## 圆角

圆角可以是最优雅和吸引人的效果之一，也是最简单的效果之一。开发人员需要了解此效果和其他效果的一些注意事项。虽然 W3C 推荐了`border-radius`的规范，但事实证明，每个主要浏览器制造商对其支持的方式略有不同。最终结果是相同的，但路径不同。让我们来看一下最基本的`border-radius`声明，以下屏幕截图是其结果：

```js
#rounded {
border-radius: 10px;
}

```

![圆角](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_1.jpg)

您还可以选择仅使某些角变圆，以及调整值，使角不是完美的四分之一圆。让我们看几个更多的示例。以下代码片段和屏幕截图演示了一个示例，以获得两个圆角：

```js
#topLeftBottomRight {
border-radius: 15px 0 15px 0;
}

```

![圆角](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_2.jpg)

以下代码片段和屏幕截图演示了一个示例，以获得一个圆角：

```js
#bottomLeft {
border-top-left-radius: 100px 40px;
}

```

![圆角](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_3.jpg)

遗憾的是，目前情况并不像这么简单。因为每个浏览器供应商都对此效果有自己独特的渲染，像谷歌或 Mozilla 这样的软件开发者已经开始创建自己的版本，通常称为**厂商前缀**。为了使先前的样式声明具有最广泛的覆盖范围，您需要添加以下代码行：

```js
#rounded {
-webkit-border-radius: 10px;
-moz-border-radius: 10px;
border-radius: 10px;
}
#topLeftBottomRight {
-webkit-border-top-left-radius: 15px;
-webkit-border-bottom-right-radius: 15px;
-moz-border-radius-topleft: 15px;
-moz-border-radius-bottomright: 15px;
border-top-left-radius: 15px;
border-bottom-right-radius: 15px;
/* mozilla and webkit prefixes require you to define each corner individually when setting different values */
}
#bottomLeft {
-webkit-border-top-left-radius: 100px 40px;
-moz-border-radius-topleft: 100px 40px;
border-top-left-radius: 100px 40px;
}

```

## 应用投影阴影

CSS 中的投影阴影有两种形式：文本阴影（应用于文本）和框阴影（应用于其他所有内容）。与`border-radius`一样，如果您查看 W3C 规范，投影阴影也相对简单。

### 使用 text-shadow

让我们先看一下`text-shadow`：

```js
p {
text-shadow: 2px 2px 2px #000000;
/* horizontal, vertical, blur, color */
}

```

![使用 text-shadow](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_4.jpg)

该属性还通过在逗号分隔的列表中添加附加声明来支持多个阴影，如以下代码片段和输出所示：

```js
p {
text-shadow: 0px 0 px 4px white,
0 px -5px 4px #ffff33,
2px -10px 6px #ffdd33,
-2px -15px 11px #ff8800,
2px -25px 18px #ff2200
}

```

![使用 text-shadow](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_5.jpg)

与`border-radius`属性不同，`text-shadow`属性不需要厂商前缀。这并不意味着所有浏览器都支持它，这只是意味着支持此属性的浏览器会按预期显示，而不支持此属性的浏览器则会看不到任何内容。

### 使用 box-shadow

Box-shadow 遵循与 text-shadow 非常相似的模型，只是增加了一个关键词`inset`，允许内部阴影。让我们看一些示例。第一个示例显示了标准外部阴影：

```js
#A {
-moz-box-shadow: -5px -5px #888888;
-webkit-box-shadow: -5px -5px #888888;
box-shadow: -5px -5px #888888; /* horizontal, vertical, color */
}
#B {
-moz-box-shadow: -5px -5px 5px #888888;
-webkit-box-shadow: -5px -5px 5px #888888;
box-shadow: -5px -5px 5px #888888;
/* horizontal, vertical, blur, color */
}
#C {
-moz-box-shadow: 0 0 5px 5px #888888;
-webkit-box-shadow: 0 0 5px 5px #888888;
box-shadow: 0 0 5px 5px #888888;
/* horizontal, vertical, blur, spread, color */
}

```

![使用 box-shadow](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_6.jpg)

现在，在以下示例中，看看这些内部阴影。很酷，对吧？

```js
#D {
-moz-box-shadow: inset -5px -5px #888888;
-webkit-box-shadow: inset -5px -5px #888888;
box-shadow: inset -5px -5px #888;}
#E {
-moz-box-shadow: inset -5px -5px 5px #888888;
-webkit-box-shadow: inset -5px -5px 5px #888888;
box-shadow: inset 0px 0px 10px 20px #888888;
}
#F {
-moz-box-shadow: inset -5px -5px 0 5px #888888;
-webkit-box-shadow: inset -5px -5px 0 5px #888888;
box-shadow: inset 0 0 5px 5px #888888;
}

```

![使用 box-shadow](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_7.jpg)

值得一提的是，阴影和文本阴影都可以使用不常用的 `rgb` 和 `rgba` 声明来设置它们的颜色。这使得开发者可以使用更熟悉的 RGB 值的约定来设置颜色。`rgba` 声明还允许设置颜色的不透明度从 `0` 到 `1`。修改的代码如下所示：

```js
#opacity {
box-shadow: inset 0 0 5px 5px rgb(0,0,0); /* black */
}
#transparent {
box-shadow: inset 0 0 5px 5px rgba(0,0,0,.5);
/* black with 50% transparency */
}

```

### CSS 渐变

CSS 渐变是向你的网站添加美感和冲击力的绝佳方式。选项包括线性渐变（从右到左，从上到下等等），以及径向渐变（从中心向外）。默认情况下，渐变由起始颜色和结束颜色组成。CSS 渐变也可以使用颜色停止来添加额外的色调。

然而，老版本浏览器对 CSS 渐变的支持并不完美，特别是在 Internet Explorer 中。好消息是，有办法解决 IE 的问题，可以让开发者可靠地在开发中使用渐变。坏消息是，支持该功能的代码*非常复杂*。让我们来看一下最简单的渐变声明：

```js
div {
width: 500px;
height: 100px;
background: linear-gradient(left, #ffffff 0%,#000000 100%);
}

```

渐变声明可能相当复杂，所以让我们用一个信息图来分解它：

![CSS 渐变](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_8.jpg)

现在关键来了......在撰写本文时，没有浏览器支持使用实际属性的 W3C 规范。让我们来看一下支持多个浏览器的代码，你会更加喜欢 jQuery Mobile：

```js
div {
width: 500px;
height: 100px;
border: 1px solid #000000;
/* Old browsers */
background: #ffffff;
/* FF3.6+ */
background: -moz-linear-gradient(left, #ffffff 0%, #000000 100%);
/* Chrome10+,Safari5.1+ */
background: -webkit-linear-gradient(left, #ffffff 0%,#000000 100%);
/* Opera 11.10+ */
background: -o-linear-gradient(left, #ffffff 0%,#000000 100%);
/* IE10+ */
background: -ms-linear-gradient(left, #ffffff 0%,#000000 100%);
/* W3C spec*/
background: linear-gradient(left, #ffffff 0%,#000000 100%);
/* IE6-9 */
filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#ffffff', endColorstr='#000000',GradientType=1 );
}

```

![CSS 渐变](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_9.jpg)

你可以通过添加额外的逗号分隔声明来将多种颜色添加到你的渐变中。例如，以下代码：

```js
div {
width: 500px;
height: 100px;
border: 1px solid #000000;
/* Old browsers */
background: #ffffff;
/* FF3.6+ */
background: -moz-linear-gradient(left, #ffffff 0%, #000000 35%, #a8a8a8 100%);
/* Chrome10+,Safari5.1+ */
background: -webkit-linear-gradient(left, #ffffff 0%,#000000 35%,#a8a8a8 100%);
/* Opera 11.10+ */
background: -o-linear-gradient(left, #ffffff 0%,#000000 35%,#a8a8a8 100%);
/* IE10+ */
background: -ms-linear-gradient(left, #ffffff 0%,#000000 35%,#a8a8a8 100%);
/* W3C */
background: linear-gradient(left, #ffffff 0%,#000000 35%,#a8a8a8 100%);
/* IE6-9 */
filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#ffffff', endColorstr='#a8a8a8',GradientType=1 );
}

```

结果显示在以下渐变中：

![CSS 渐变](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_10.jpg)

正如你在阅读最近几页后可能猜到的那样，jQuery Mobile 为你做了很多繁重的工作。它不仅添加了漂亮的渐变页面背景，还必须跟踪可能阻止甜美的阴影出现的所有浏览器怪癖。当我们进入下一节时，你可能会对它处理主题和色板的方式更为印象深刻。

# jQuery Mobile 主题的基础知识

在 jQuery Mobile 中进行主题设置对开发者来说是直接简单易用的，但是在幕后却相当复杂。幸运的是，很少有时候你需要知道为你所做的一切。然而，花点时间了解它的工作原理也是值得的。

jQuery Mobile 的开箱即用版本包含了一个由五种颜色色板组成的主题集，每个与 A-E 中的一个字母相关联。该主题包含了一系列基本的 CSS 类，可以随意应用于几乎任何元素，并且它们包含了宽度、高度、边框半径、阴影的全局设置。各个色板包含了有关颜色、字体等方面的具体信息。

可以将额外的样本添加到来自 F-Z 的五个原始样本中，或者可以随意替换或覆盖原始样本。这个系统允许共有 26 个不同的样本，从而可以产生数百万种主题颜色、样式和图案的可能组合。您可以通过添加一个`data-theme`属性和所需主题的字母来将 jQuery Mobile 主题应用于所选元素：

![jQuery Mobile 主题的基础知识](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_11.jpg)

开发人员通常会选择使用`data-theme`属性方法来应用样式，但也可以直接将 CSS 类名附加到页面元素以获得更精细的控制。有几个主要前缀允许这种灵活性。

## 条（.ui-bar-?）

bar 前缀通常应用于标题、页脚和其他重要区域：

![条（.ui-bar-?）](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_12.jpg)

## 内容块（.ui-body-?）

内容块通常应用于预期出现段落文本的区域。它的颜色有助于确保文本颜色与其放置在其上的文本颜色之间具有最大的可读性：

![内容块（.ui-body-?）](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_13.jpg)

## 按钮和列表视图（.ui-btn-?）

按钮和列表视图是 jQuery Mobile 库中最重要的两个元素，您可以放心地知道团队花了很多时间来完善它们。`.ui-btn`前缀还包括用于上升、下降、悬停和活动状态的样式：

![按钮和列表视图（.ui-btn-?）](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_14.jpg)

## 混搭样本

jQuery Mobile 中主题的一个好处是，除非另有说明，否则子元素会从其父元素继承。这意味着，如果您在页眉或页脚栏中放置一个没有自己`data-theme`属性的按钮，该按钮将使用与其父元素相同的主题。酷，对吧？

![混搭样本](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_15.jpg)

在一个元素中使用一个样本并在另一个元素的子元素中使用另一个样本也是完全可以接受甚至是鼓励的。这可以帮助元素更加突出，或者与应用程序的不同部分匹配，或者开发人员选择的任何其他原因。这是可能的，而且更重要的是，它很容易。只需将按钮（或其他元素）放置在页眉栏内，并为其分配自己的`data-theme`属性：

![混搭样本](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_16.jpg)

## 全站活动状态

jQuery Mobile 还为所有元素应用了一个全局 *活动* 状态。此活动状态用于按钮、表单元素、导航等任何需要指示当前选择的地方。更改此颜色值的唯一方法是通过 CSS 设置（或覆盖）它。活动状态的 CSS 类名是`.ui-btn-active`：

![全站活动状态](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_17.jpg)

## 默认图标

jQuery Mobile 集中包含了 18 个图标，涵盖了开发人员广泛的需求。图标集是白色的透明图标，jQuery Mobile 在半透明的黑色圆圈上覆盖以提供与所有样品的对比度。要添加图标，请使用所需图标的名称指定 `data-icon` 属性：

![默认图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_18.jpg)

jQuery Mobile 还提供了使用 `data-iconpos="[top, right, bottom, left]"` 属性在按钮的顶部、右侧、底部或左侧放置图标的功能，其中左侧是默认位置。开发人员还可以通过指定 `data-iconpos="notext"` 来仅显示图标而不显示文本：

![默认图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_19.jpg)

部署自定义图标也是可能的，将在本章后面进行讨论。

# 创建和使用自定义主题

我们已经讨论过 jQuery Mobile 中主题设置的强大功能。它使得用简单而优雅的样式开发丰富的移动网站变得轻而易举。更强大的是，您可以创建自己的样品库，以使您的应用程序或网站真正独特。可以通过以下两种方式之一来处理自己的主题开发：

1.  下载并打开现有的 jQuery Mobile CSS 文件，并按自己的意愿进行编辑。

1.  将您的网络浏览器指向 jQuery Mobile 的 ThemeRoller：[`jquerymobile.com/themeroller/`](http://jquerymobile.com/themeroller/)。

我们将专注于第二种选择，因为说实话，为什么要费劲地浏览所有的 CSS 呢？您可以在 10 分钟内使用指点、点击和拖放的方式创建一个充满样品的新主题。让我们了解一下 ThemeRoller 是什么。

## 什么是 ThemeRoller？

ThemeRoller for jQuery Mobile 是为 jQuery UI 项目编写的一个基于 Web 的应用程序的扩展。它允许用户使用拖放颜色管理在几分钟内快速组装一个充满样品的主题。它具有交互式预览功能，因此您可以立即看到您的更改如何影响您的主题。它还具有内置的检查器工具，可帮助您深入了解细节（如果您需要）。它还集成了 Adobe® Kuler®，一个颜色管理工具。您可以在完成后下载您的主题，可以通过自定义 URL 与他人共享，也可以重新导入过去的主题进行最后的微调。它是一个强大的工具，是 jQuery Mobile 的完美补充。

五个默认样品的特点之一是，jQuery Mobile 团队花了相当多的时间来改善可读性和可用性。这些样品的对比度从最高（A）到最低（E）不等。在单个主题中，对比度最高的区域是页面上最突出的区域。这包括页眉（和列表视图的标题）和按钮。在创建自己的主题时，牢记这一点是个好主意。我们总是希望专注于应用程序的可用性，对吗？如果由于颜色选择不当而无法阅读，那么漂亮的应用有什么用呢？

### 使用 ThemeRoller

当你加载 ThemeRoller 时，第一件事就是看到一个看起来很漂亮的启动屏幕，然后是一个有用的**入门**屏幕：

![使用 ThemeRoller](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_20.jpg)

**入门**屏幕上有一些有用的提示，所以在点击**开始**按钮之前一定要看一眼：

![使用 ThemeRoller](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_21.jpg)

当所有的启动屏幕都结束后，你将会看到主要界面：

![使用 ThemeRoller](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_22.jpg)

ThemeRoller 分为四个主要区域：预览、颜色、检查员和工具。每个区域都包含了我们需要审查的重要功能。我们将从预览部分开始。

### 预览

除非你正在加载现有主题，否则预览区域将呈现三个完整、相同且交互式的 jQuery 移动页面，上面装满了各种小部件：

![预览](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_23.jpg)

将鼠标移到上面，你会发现每个页面都是功能性的。每个页面的页眉包含了一个字母，指示了哪个色板控制了它的外观。

## 颜色

在页面顶部，你会看到一系列颜色芯片，以及两个滑块控件和一个切换按钮。右边更远处，你会看到另外十个颜色芯片，应该是空白的。这些专门用于最近使用的颜色，直到你选择了颜色为止：

![颜色](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_24.jpg)

在颜色芯片下面有两个标有**亮度**和**饱和度**的滑块。亮度滑块调整了一系列色板的明亮和暗色调，而饱和度使颜色更加鲜艳或柔和。综合在一起，用户应该能够近似于他们选择的任何颜色。要使用 Kuler®的颜色，点击标有**Adobe Kuler 色板**的文本链接。

每个颜色芯片都可以拖放到预览区域内的任何元素上。这使得色板集的开发非常容易。请注意，许多 jQuery Mobile 样式重叠，比如页顶的标题栏与列表视图的标题接收到相同的样式。根据需要调整颜色，然后将每个色片拖放到页面上的元素上。请记住，每个单独的页面都是自己的色板，所以在选择混合颜色时要小心。

### 检查员

界面最左侧是检查员面板，分为两部分。顶部包含了一系列按钮，允许开发者下载他们的主题，导入现有主题，并分享他们的主题链接。还有一个**帮助**链接给那些没有购买这本书的人：

![检查员](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_25.jpg)

底部区域包含一系列标有**全局, A, B, C**和**+**的标签。每个标签都包含一个手风琴面板，其中包含了单个色板的所有值，除了全局标签，它适用于所有色板。

选择**全局**选项卡，然后点击**活动状态**，手风琴面板将展开，显示整个主题的活动状态设置。选项包括文本颜色、文本阴影、背景和边框。在全局更改值会导致每个当前（和将来的）色板都反映新的设置。

可以通过两种方式向主题添加额外的色板。点击检查器顶部的**+**选项卡会在你的主题中的最后位置添加一个新的色板。你也可以通过点击预览区域底部的**添加色板**按钮来添加一个新的色板。通过选择要删除的色板的选项卡，然后单击该色板名称右侧的**删除**链接来删除色板。请注意，从堆栈顶部删除色板会导致其余色板被重命名。

### 工具

页面顶部有一系列按钮。这些按钮允许你执行各种任务，我们马上就会介绍，但首先，仔细看看这些按钮本身：

![工具](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_25-2.jpg)

你会注意到以下按钮：一个切换按钮，允许你在当前 1.1 版本和 1.0.1 版本之间切换，撤销/重做，以及检查器的切换按钮。将此切换打开可以检查预览区域中的任何小部件。将鼠标悬停在小部件上会用蓝框突出显示该元素。单击该元素将导致检查器区域的手风琴菜单展开，显示特定于该元素的设置。

还有四个额外的按钮，允许你下载你的主题，导入或升级先前创建的主题，与他人分享你的主题，以及一个帮助按钮。

## 创建 Notekeeper 的主题

现在我们熟悉了 ThemeRoller 的界面，那么我们何不继续创建我们的第一个主题呢？与其在抽象中构建一个主题，不如创建一个我们实际将在之前构建的 Notekeeper 应用程序中使用的主题。让我们简单地开始，通过修改 jQuery Mobile 随附的现有主题之一。团队很友好地让用户导入默认主题作为新主题的起点，所以我们首先要去那里。点击窗口左上角的**导入**按钮，然后你会得到一个框，允许你粘贴现有主题的内容：

![为 Notekeeper 创建主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_26.jpg)

在右上角点击链接，适当命名为**导入默认主题**来导入默认主题。在文本区域填充 CSS 后，点击**导入**。预览区域将重新加载并显示从 **A** 到 **E** 的色板。

我们将集中精力改变白色色板 **D**，因为它最接近我们的最终目标。由于我们更愿意使用色板 **A** 作为名称，让我们删除其他色板，以便只剩下 **D**。请记住，当你删除色板 **A** 时，ThemeRoller 会将其他色板重命名。这意味着当你删除色板 **A** 时，色板 **B** 变成 **A**，色板 **C** 变成 **D**，依此类推。

继续进行，直到原来是**D**的样本现在位于**A**位置。最后，删除样本 **B**（原来是样本 **E**），这样我们就只剩下样本 **A：**

![为 Notekeeper 创建主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_26_02.jpg)

这个样本看起来不错，但有点单调。让我们通过将页眉改为漂亮的绿色来注入一点色彩。确定任何元素的哪些值应该更改的最简单方法是使用检查器。在顶部切换检查器到**On**，然后点击主题 **A** 的页眉的任何地方。如果左侧选择了 **A** 选项卡，并且**页眉/页脚栏**面板展开，你就会知道你做对了：

![为 Notekeeper 创建主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_27.jpg)

你可以通过几种方式之一改变颜色。你可以直接将一个颜色芯片从顶部拖到背景上。你也可以将一个颜色芯片拖到输入字段上。最后，你可以手动输入值。注意，当你点击包含颜色值的字段时，你会看到一个时髦的颜色选择器。继续，并将此面板中的输入字段中的值更改为上一张截图中显示的值。

看起来不错，但现在主题活动状态的蓝色与我们的绿色不搭配。使用检查器工具，在 On/Off 切换栏的**On**部分单击一次。这将导致**全局**选项卡内的**活动状态**面板展开。我们将把蓝色改成一个漂亮的暖灰色。全局面板现在应该看起来类似于以下截图：

![为 Notekeeper 创建主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_28.jpg)

我们新主题唯一的不足之处是段落顶部的蓝色文本链接。回到我们可靠的检查器，让我们直接点击链接，这将展开**内容主体**面板，位于**A**选项卡内。现在，对于那些已经熟悉 CSS 的人来说，你知道你不能简单地改变链接颜色而不改变悬停状态，`visited:hover` 和活动状态。问题在于没有选项可以进行这些更改，但是 ThemeRoller 为你提供了解决方案。点击**链接颜色**输入字段右侧的**+**以显示其他选项，然后根据以下截图更改颜色：

![为 Notekeeper 创建主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_29.jpg)

就是这样。随时在探索检查器区域时进行其他主题的额外更改。无论你喜欢什么，都可以更改，现在只是位和字节而已。但请记住，目前没有撤销选项。如果你真的喜欢某些东西，请考虑写下值，以免丢失它们，或者将其导出为它是什么。说到…

### 导出你的主题

在我们实际导出主题之前，必须注意一件事。还记得带有“有用”信息的闪屏页面吗？事实证明，有一条不是建议，而是要求的。

**我们建议用至少 3 个样本（A-C）来构建主题**。

为了使我们的主题正确应用到我们的 Notekeeper 应用程序中，我们需要将我们的单个色板（字母 **A**）复制到色板 **B** 和 **C** 中。幸运的是，这是一件很容易的事情。在检查器顶部选择 **A** 选项卡，然后点击两次 **+** 选项卡。你应该会看到三个相同的色板，现在我们完成了。

现在我们已经完成了我们的主题，我们将导出它以在我们的 Notekeeper 应用中使用。这是一个简单的过程，从页面中间顶部的**下载主题**按钮开始。你将看到一个框，允许你为主题命名，一些关于如何应用主题的信息，以及一个标记为**下载 Zip**的按钮。在将我们的主题命名为 Notekeeper 后，点击**下载 Zip**按钮，你将在下载文件夹中收到一个美味的小东西。

解压缩 ZIP 文件的内容，你将看到以下的目录结构：

+   index.html

+   themes/

    +   `Notekeeper.css`（你的主题的未压缩版本）

    +   `Notekeeper.min.css`（压缩版本。在生产中使用此版本）

    +   images/

        +   `ajax-loader.gif`

        +   `icons-18-black.png`

        +   `icons-18-white.png`

        +   `icons-36-black.png`

        +   `icons-36-white.png`

树顶部的 HTML 文件包含了如何实现你的主题的信息，以及一些小部件来确认主题是否有效。示例文件中的所有链接都是相对的，因此你应该能够将其拖放到任何浏览器窗口中并查看结果。

关于主题的下载和实施的一些注意事项：

1.  jQuery 团队之所以向你提供此 ZIP 文件中的按钮图标是有原因的。主题要求这些图像与 CSS 文件相关联。这意味着，除非你已经在使用默认主题，否则在将你的主题上传到网站时，你还需要包含图像文件夹，否则图标将不会显示出来。

1.  **牢记你的主题的未压缩版本**。虽然由于体积原因你不希望在生产中使用它，但是如果你希望在 ThemeRoller 中编辑它，你将需要它。截止到撰写本文时，ThemeRoller 无法导入被压缩的 CSS 文件。

# 创建和使用自定义图标

我们已经看到了使用 ThemeRoller 向 jQuery Mobile 添加自己的主题是多么简单。现在我们将通过创建一个自定义图标为我们的 Notekeeper 应用增添一些趣味。本节中的说明将专门针对 Photoshop，但任何能够导出透明 PNG 文件的图形应用程序都应该是可以接受的。

## CSS 精灵

在我们创建和使用图标之前，我们应该先了解 jQuery Mobile 如何使用图标并应用它们。在你刚刚创建的主题中有几个图像文件（themes/images）。打开 `icons-18-black.png` 和 `icons-36-black.png`，在你选择的图形编辑器中将它们放大到 400% 或更多，你应该会看到与以下图像非常相似的东西：

![CSS 精灵](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_30.jpg)

当打开这些文件时，你可能会注意到每个图像都包含所有图标。这是因为 jQuery Mobile 利用了一种称为 **CSS 雪碧图** 的技术，它本身利用了 CSS 允许开发人员通过指定其容器内的位置来 *裁剪* 背景图像的事实，并隐藏通常显示在该容器外部的背景的任何其他部分。它的主要优点包括以下几点：

1.  减少浏览器发出的请求数量。请求越少，通常意味着页面加载速度会更快。

1.  图片位置居中。所有图标都可以在一个位置找到。

以下截图是该技术的简单说明：

![CSS 雪碧图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_31.jpg)

浏览器始终从图像的左上角引用图像。在 CSS 语言中，即 `0,0`。要实现此效果，您将背景图像设置在一个容器上，然后简单地调整 `X` 和 `Y` 坐标，直到图像的位置与您的设计匹配。然后设置容器的溢出以裁剪或隐藏图像的其余部分。请记住，您正在 *移动* 图像到左侧，因此对于 `X` 位置，您将使用负数。使用前面的示例作为参考，以下代码片段用于实现此效果：

```js
<html>
<head>
<title></title>
<style>
div {
background: url("icons-36-black.png");
background-position: -929px 4px;
background-repeat: no-repeat;
border: 1px solid #000000;
height: 44px;
overflow: hidden;
width: 44px;
}
</style>
</head>
<body>
<div></div>
</body>
</html>

```

## 设计你的第一个图标

我们只会创建一个单一图标，所以我们不需要图标周围的所有空白空间。让我们先决定我们想要描绘什么。我们的应用叫做 Notekeeper，它创建笔记。也许一个描绘纸张的图标会起作用？这样做的额外好处是在小尺寸下相对容易表示。在你选择的图像编辑器中创建一个新文档，尺寸为 `36x36` 像素，分辨率为 `72` dpi。将其命名为 `notekeeper-icon-black-36.png`：

![设计你的第一个图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_32.jpg)

尽管文档的尺寸是 36x36 像素，但图标的有效区域只有 22x22 像素。这是为了与 jQuery Mobile 团队提供的图标保持一致，以确保我们的图标看起来不奇怪。为了更容易地保持在线条内，使用矩形选择工具在 22px 处绘制一个正方形，然后将其位置设置在文档的顶部边缘和左侧边缘各 7px 处。

接下来，沿着每条边绘制指南线，使得你的文档看起来类似以下截图：

![设计你的第一个图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_33.jpg)

在绘制图标时，你需要考虑所描绘事物的尺寸和属性。你不可能表现出所有细节，但你需要传达事物的精神。一张纸比它宽高比更高，并且上面有线条。让我们从这两点开始，看看我们能得出什么。此套图标中的其他图标都有较粗的感觉，以便它们能在背景中显眼。让我们填充一个实心形状，然后删除页面的线条，以便图标具有相同的粗糙感。我们将用黑色绘制线条，以便它们在书中更好地打印出来，但我们的图标需要是白色的。确保你相应调整你的设计：

![设计你的第一个图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_34.jpg)

这个图标似乎符合我们所有的标准。它比宽高比更高，并且像纸一样有线条。它还有一个活泼的小翻页，给它一些态度。这不就是每个人在他们的纸图标上寻找的东西吗？确保图标的线条是白色的，然后保存它。jQuery Mobile 图标已保存为透明的 PNG-8 文件。这类似于 GIF 格式，但不是必需的。如果你愿意，可以使用透明 GIF 或透明 PNG-24。

当我们创建第一个图标时，我们创建了高分辨率版本。 为了简洁起见，我们将快速浏览创建低分辨率图标的步骤：

1.  创建一个新的图像文档，尺寸为 18x18 像素。将其命名为`notekeeper-icon-18`。

1.  这个图标的活动区域将是 12x12 像素。绘制一个 12px 的正方形选择区域，然后将其位置设置为距离顶部 3px，距离左侧 3px。

1.  绘制你的辅助线，然后草图出图标，使用以前的版本作为参考。在这么小的空间里画图标确实很难，不是吗？

1.  你的最终结果应该类似于以下截图：![设计你的第一个图标](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jqmobi-webdev-ess/img/7263_11_35.jpg)

将两个图像与你的 Notekeeper 主题一起保存并关闭 Photoshop。

## 高分辨率和低分辨率

分辨率是可以显示在给定区域内的点数或像素数。来自网络世界的你们通常将所有东西都以 72dpi 进行测量，因为大多数显示器都显示这个分辨率。如果你有很多移动设备的经验，你可能知道每个设备的分辨率可能与其旁边的设备不同。这样做的问题在于，分辨率更高的设备在屏幕上只是显示更多的像素。这意味着在高分辨率屏幕上显示的图像将比在低分辨率屏幕上显示的同一图像要小。

jQuery Mobile 通过为高分辨率和低分辨率设备提供两个版本的每个图标以及两套代码来解决此问题。在下一节中，我们将为我们的 Notekeeper 应用程序应用自定义主题和自定义图标。

# 更新 Notekeeper 应用程序

是时候将所有这些松散的端点联系在一起了。我们有一个使用 ThemeRoller 构建的自定义主题，我们有我们漂亮的自定义图标，现在是时候将所有的片段组合在一起了。您需要以下内容来完成：

1.  你在 Notekeeper 章节末尾完成的代码。

1.  您在本章前面创建的自定义主题。

1.  您的自定义图标；白色；分别为 18px 和 36px 尺寸。

## 添加我们的自定义主题

让我们从最简单的部分开始。添加我们的自定义主题非常简单。打开`notekeeper.html`（在您的浏览器中，并在您选择的文本编辑器中）。查找`<head>`标签并添加以下行：

```js
<title>Notekeeper</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="stylesheet" href="http://code.jquery.com/mobile/ latest/jquery.mobile.min.css" />
<link rel="stylesheet" href ="themes/Notekeeper.min.css" />
<link rel="stylesheet" href ="styles.css" />
<script src="img/jquery-1.6.4.js"></script>
<script src="img/jquery.mobile.min.js"></script>
<script src="img/application.js"></script>

```

第一行新加入了我们创建的新主题。第二行目前指向一个缺失的文件（因为我们还没有创建它）。即使像 jQuery Mobile 这样拥有丰富主题系统的系统，我们仍然会为各种事物编写一些自定义 CSS。`styles.css`是我们将放置各种样式的地方，特别是我们自定义图标的定义。

顺便说一句，您可以重新加载浏览器窗口，看看我们的新主题是如何运行的。是不是很漂亮？当我们的自定义图标出现时，它会看起来更加漂亮。

## 添加我们的自定义图标

接着，在你的 Notekeeper 应用代码的根目录下创建`styles.css`，然后打开它。我们将首先添加我们的 18px 图标的声明。它是低分辨率的，将在您的桌面浏览器中看到。高分辨率图标目前只在 iPhone 4 和 iPhone 4S 上显示。

要添加我们的自定义图标，我们遵循 jQuery Mobile 设定的模式。它使用`.ui-icon`前缀为按钮和其他元素应用图标。这意味着为了使我们的图标在框架中起作用，我们必须将我们的 CSS 类命名为以下内容：

```js
.ui-icon-notekeeper-note {
background-image: url("themes/images/notekeeper-icon-white-18.png");
}

```

然后，将图标添加到我们的“添加笔记”按钮中就像添加一个`data-icon`属性一样简单，如下所示的代码行所示：

```js
<div class="ui-block-b">
<input id="btnAddNote" type="button" value="Add Note" data- icon="notekeeper-note" />
</div>

```

请记住，字符串`notekeeper-note`可以是任何东西，只要它与您之前创建的 CSS 类的后半部分匹配即可。最后让我们为我们的应用程序添加剩下的一部分，即高分辨率图标。

jQuery Mobile 的一个显著特点是它对**媒体查询**的支持。媒体查询本质上允许您查询给定设备的各种信息，基于其媒体类型：屏幕、打印、电视、手持设备等。对这个查询的回答允许开发人员对 CSS 代码进行分支，并为桌面浏览器（屏幕）显示页面的一种方式，为电视（电视）显示页面的另一种方式。对于我们的图标，我们想要询问任何视图设备，其类型为屏幕，是否支持一个名为`-webkit-min-device-pixel-ratio`的属性，以及该属性的值是否为`2`。在低分辨率图标的声明之后，将以下行添加到`styles.css`中：

```js
@media only screen and (-webkit-min-device-pixel-ratio: 2) {
.ui-icon-notekeeper-note {
background-image: url("themes/images/notekeeper-icon-white-36.png");
background-size: 18px 18px;
}
}

```

除了媒体查询代码之外，这个唯一与众不同的是`background-size`属性。它允许开发人员指定给定背景应按指定大小（18x18 像素）缩放，而不是其原始大小 36x36 像素。由于 iPhone 4 和 4S 上的分辨率恰好是低分辨率设备的两倍，这意味着我们将两倍的像素打包到与较小图标相同的空间中。最终结果是图标看起来更加清晰和锐利。如果您拥有其中一款设备，请将您的代码上传到服务器并查看它。您的耐心将会得到回报。

# 总结

在本章中，我们学习了对于 jQuery Mobile 体验至关重要的高级 CSS 技术，以及 jQuery Mobile 如何利用它们为最终用户提供丰富的界面。我们深入探讨了 jQuery Mobile 主题化的基础知识以及它的工作原理。我们使用 ThemeRoller 工具构建了一个自定义主题，用我们自己的双手创建了一个自定义图标，并学习了如何将所有这些东西联系在一起并在我们的应用程序中实现它们。

在下一章中，您将学习如何运用过去 11 章学到的原则，并创建一个可以在 iOS 和 Android 平台上运行的本机应用程序（以及其他几个平台），使用 Phonegap 开源库。
