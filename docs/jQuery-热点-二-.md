# jQuery 热点（二）

> 原文：[`zh.annas-archive.org/md5/80D5F95AD538B43FFB0AA93A33E9B04F`](https://zh.annas-archive.org/md5/80D5F95AD538B43FFB0AA93A33E9B04F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：jQuery Mobile 单页面应用程序

jQuery mobile 是一个令人兴奋的项目，它将 jQuery 的强大功能带入了手持设备和移动体验的世界。与 jQuery UI 类似，它在 jQuery 核心基础上构建和扩展了一系列 UI 小部件和辅助工具。在这种情况下，这些小部件被优化用于移动显示和触摸界面。

我们还将使用 JsRender，这是 jQuery 的官方模板解决方案，也是 jQuery 模板插件 `tmpl` 的后继者。

# 任务简报

在本项目中，我们将构建一个简单的应用程序，该应用程序寻找在堆栈溢出上有未颁发奖励的问题。我们将其称为赏金猎人。它将只包含一些单独的页面，但将被制作成感觉像是一个本地应用程序，而不是一个标准的网站。

虽然使用 jQuery Mobile 构建的站点和应用程序在笔记本电脑或台式机上运行得很好，但 jQuery Mobile 坚持采用先移动的理念，先构建最小的布局。

这是我们在整个项目中将重点关注的布局。如果您没有智能手机或其他功能强大的移动设备，我们将构建的示例应用程序仍将在普通桌面浏览器中正常工作。

在本项目中，我们将构建的应用程序将如下截图所示：

![任务简报](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_04_01.jpg)

## 它为什么如此令人敬畏？

jQuery Mobile 提供了对所有主要现代智能手机和平板电脑的全面支持，并且非常重要的是提供了一致性。它还向更广泛范围的常见但可能更老、功能更差的移动设备提供了有限支持。它建立在 jQuery 本身稳固的基础之上，并且从 jQuery UI 那里借鉴了许多最佳实践，特别是在小部件如何初始化和配置方面。

jQuery Mobile 提供了两种小部件初始化的方式；我们可以使用广泛的 HTML5 `data-` 属性系统，它将自动触发小部件的初始化，无需任何额外的配置，或者我们可以动态创建小部件，并纯粹通过脚本调用它们。

这两种技术各有优缺点，我们将在本项目中学习这两种技术，这样您就可以决定哪种方式最适合您。

## 您的炫目目标

这些是本项目将分解成的任务：

+   构建欢迎屏幕

+   添加第二个页面

+   创建脚本包装器

+   获得一些赏金

+   添加一个 JsRender 模板

+   构建列表视图

+   构建一个项目视图

+   处理分页

## 任务清单

jQuery Mobile 网站提供了一个页面模板，可用作使用该框架进行开发时的起点。我们可以将该模板用作此项目的基础。要设置，请访问 [`jquerymobile.com/demos/1.2.0/docs/about/getting-started.html`](http://jquerymobile.com/demos/1.2.0/docs/about/getting-started.html)。

复制“创建基本页面模板”部分显示的模板，并将其另存为 `bounty-hunter.html` 在我们的主工作目录中。 此模板包含我们启动所需的一切。

在这一点上，我们还应该链接到 JsRender； 在我们刚刚保存的模板中的链接到 jQuery Mobile 的 `<script>` 元素之后直接添加以下代码：

```js
<script src="img/jsrender.js">
</script>
```

### 注意

在撰写时，当前版本的 jQuery Mobile 与 jQuery 1.9 不兼容。 我们将从 jQuery Mobile 网站获取的模板将链接到兼容版本的 jQuery，并且一旦 jQuery Mobile 达到 1.3 里程碑，1.9 支持将很快可用。

为了测试我们的移动应用，我们还应该为该项目使用 Web 服务器，以便使用适当的 `http://` URL 而不是 `file:///` URL 查看测试页面。 您可能已经在计算机上安装了开源 Web 服务器，例如 Apache，如果有，那就没问题了。

如果您尚未安装和配置 Web 服务器，我建议下载并安装微软的 **Visual Web Developer Express**（**VWDE**）。 这是微软行业标准 IDE Visual Studio 的免费版本，除了包含内置的开发 Web 服务器外，还是一个非常强大的 IDE，具有 JavaScript 和 jQuery 的 Intellisense 支持以及一系列面向前端开发者的功能。

对于更喜欢开源软件的开发人员，Apache Web 服务器以及 PHP 和 MySQL 可以安装在 Mac 和 Windows 系统上。 为了使安装和配置更加简单，已经创建了一系列软件包，这些软件包一起安装软件并自动配置，例如 XAMPP。

### 注意

VWDE 可以通过访问 [`www.microsoft.com/visualstudio/en-us/products/2010-editions/visual-web-developer-express`](http://www.microsoft.com/visualstudio/en-us/products/2010-editions/visual-web-developer-express) 进行安装。

XAMPP 下载可在 [`www.apachefriends.org/en/xampp.html`](http://www.apachefriends.org/en/xampp.html) 获取。

# 构建欢迎页面

许多应用程序都有一个欢迎或主屏幕，用户可以返回以选择常见操作。 在这个项目的第一个任务中，我们将构建欢迎屏幕，它将包含一些简单的页面家具，如标题，页脚，徽标，并将包含一个搜索框和按钮，用于触发对 Stack Exchange API 的调用。

## 准备起飞

在此时，我们可以创建项目中将使用的其他资源。 我们应该在 `css` 文件夹中创建一个名为 `bounty-hunter.css` 的新样式表，以及一个名为 `bounty-hunter.js` 的新脚本文件。

我们应该在页面的 `<head>` 中添加一个 `<link>` 元素来链接样式表。 以下代码应该直接添加在 jQuery 移动样式表之后（jQuery 移动 `<script>` 元素之前）：

```js
<link rel="stylesheet" href="css/bounty-hunter.css" />
```

我们可以将 `<script>` 元素添加到通常的位置，就在关闭的 `</body>` 标签之前：

```js
<script src="img/bounty-hunter.js"></script>
```

### 注意

由于 jQuery Mobile 提供了自己的基线样式，其中包括重置和排版默认值，因此在此示例中，我们不需要链接到我们的`common.css`文件。

## 启动推进器

我们下载的 jQuery Mobile 模板包含了大多数 jQuery Mobile 页面应该构建的推荐基本结构。我们将使用推荐的结构，但会向现有标记添加一些额外的属性。

我们应该在`bounty-hunter.html`中具有`data-role="page"`属性的`<div>`元素中添加一个`id`属性；将`id`属性设置为`welcome`：

```js
<div data-role="page" id="welcome">
```

接下来，我们应该修改原始标记，使其显示如下。首先，我们可以添加一个标题区域：

```js
<div data-role="header">
    <h1>Bounty Hunter</h1>
</div>
```

接下来，我们可以直接在标题区域后面添加主要内容区域：

```js
<div data-role="content">
    <p>
        Enter tag(s) to search for bounties on. 
        Separate tags with a semi-colon, or leave blank to get
        all bounties. 
    </p>
    <div class="filter-form">
        <label for="tags" class="ui-hidden-accessible">
            Search by tag(s):
        </label>
        <input id="tags" placeholder="Tag(s)" />
        <button data-inline="true" data-icon="search">
            Search
        </button>
    </div>
</div>
<img src="img/boba.png" alt="Bounty Hunter" />
```

最后，我们可以在主要内容区域后面添加一个页脚区域：

```js
<div data-role="footer" data-position="fixed" 
    data-id="footer">

    <small>&copy; 2012 Some Company Inc.</small>
    <a href="bounty-hunter-about.html" data-icon="info" 
        data-role="button" data-transition="slide">About</a>

</div>
```

我们还可以为欢迎屏幕添加一些样式。将以下选择器和规则添加到`bounty-hunter.css`中：

```js
.filter-form .ui-btn { margin:10px 0 0 0; float:right; }

.ui-footer small { display:block; margin:10px; float:left; }
.ui-footer .ui-btn { margin:2px 10px 0 0; float:right; }
```

## 目标完成 - 迷你总结

首先，我们更新了具有`data-role="header"`属性的容器`<div>`内部`<h1>`元素中的文本。

然后我们向内容容器添加了一些内容，包括一段简介文字和一个容器`<div>`。容器内部我们添加了`<label>`、`<input>`和`<button>`元素。

出于可访问性原因，jQuery Mobile 建议为所有`<input>`元素使用具有有效`for`属性的`<label>`元素，因此我们添加了一个，但然后使用`ui-hidden-accessible`类将其隐藏。这将允许辅助技术仍然看到它，而不会在视觉上混淆页面。

`<input>`只是一个带有`id`属性的简单文本字段，用于从脚本中轻松选择，以及一个`placeholder`属性，该属性将指定的文本添加到`<input>`内部作为占位符文本。这很好地用于在标签被隐藏时提供视觉提示，但在较旧的浏览器中可能不受支持。

`<button>`元素具有几个自定义的 jQuery Mobile`data-`属性，并且在页面初始加载时将由框架自动增强。jQuery Mobile 根据元素类型和任何`data-`属性自动增强一系列不同的元素。增强通常包括将原始元素包装在容器中或添加其他附加元素以与之并列。

`data-inline="true"`属性将包围`<button>`的容器设置为`inline-block`，以便它不会占据视口的全部宽度。`data-icon="search"`属性为其添加了一个搜索图标。

我们在原始模板中为容器`<div>`元素添加了一些额外的`data-`属性，其中包括`data-role="footer"`属性。`data-position="fixed"`属性与`data-id="footer"`属性配合使用，将元素固定在视口底部，并确保在页面更改时不进行过渡。

在页脚容器内，我们添加了一个 `<small>` 元素，其中包含一些虚假的版权信息，通常在网页的页脚中找到。我们还添加了一个新的 `<a>` 元素，链接到另一个页面，我们将在下一个任务中添加。

该元素还具有几个自定义 `data-` 属性。`data-icon="info"` 属性为增强元素提供了一个图标。`data-role="button"` 属性通过框架触发增强，并赋予这个简单链接类似按钮的外观。`data-transition="slide"` 属性在导航到新页面时使用幻灯片转换。

最后，我们为这个项目的样式表添加了一些基本的样式。我们将搜索按钮浮动到右边，并通过 jQuery Mobile 更改了给它的边距。样式是使用我们添加到容器的类和框架添加的类添加的。我们需要同时使用这两个类来确保我们的选择器比框架使用的选择器更具特异性。

我们还对页脚元素进行了样式设置，使它们左右浮动并按需定位。我们必须再次击败 jQuery Mobile 主题中默认选择器的特异性。

到目前为止，我们应该能够在浏览器中运行页面，并在顶部和底部分别看到带有标题和页脚的主页，简单的搜索表单以及给应用程序提供基本身份的大橙色图像。

## 机密情报

jQuery Mobile 是建立在自定义 `data-` 属性系统之上的，我们可以给元素添加特定属性，并让框架基于这些属性初始化小部件。这个自定义 `data-` 属性框架并非强制性；如果需要的话，我们可以手动初始化和配置小部件。

但是使用属性很方便，让我们能够专注于添加我们想要的行为的自定义脚本代码，而不用担心我们想要使用的 jQuery Mobile 小部件的设置和初始化。

# 添加第二个页面

在这个任务中，我们将添加一个页面，**关于** 超链接，我们在欢迎页面的页脚容器中添加了链接到它。这使我们能够通过仅通过 `data-` 属性系统配置来体验 jQuery Mobile 转换的效果。

### 注意

有关更多信息，请参阅 jQuery Mobile `data-` 属性参考文档：[`jquerymobile.com/demos/1.2.0/docs/api/data-attributes.html`](http://jquerymobile.com/demos/1.2.0/docs/api/data-attributes.html)。

## 为起飞做准备

保存一个新的 jQuery Mobile 页面模板，我们在上一个任务中使用过，但这次将其命名为 `bounty-hunter-about.html`，并将其保存在主项目目录中（与 `bounty-hunter.html` 页面并列）。

我们还需要像之前一样链接到我们的 `bounty-hunter.css` 文件，我们的 `bounty-hunter.js` 文件以及 JsRender。

### 注意

有关 JsRender 的更多信息，请参阅文档：[`github.com/BorisMoore/jsrender`](https://github.com/BorisMoore/jsrender)。

## 启动推进器

在我们的新`bounty-hunter-about.html`页面中，将`<div>`内的标记更改为带有`data-role="page"`的以下内容：

```js
<div data-role="header">
    <a href="bounty-hunter.html" data-icon="home" 
    data-shadow="false" data-iconpos="notext" 
    data-transition="slide" data-direction="reverse" 
    title="Home"></a>

    <h1>About Bounty Hunter</h1>
</div>

<div data-role="content">
    <p>
        Bounty Hunter is an educational app built for the  
        jQuery Hotshots book by Dan Wellman
    </p>
    <a href="http://www.danwellman.co.uk">
        danwellman.co.uk
    </a>
</div>

<div data-role="footer" data-position="fixed" 
    data-id="footer">

    <small>&copy; 2013 Some Company Inc.</small>
    <a class="ui-disabled" href="#" data-icon="info" 
        data-role="button">About</a>

</div>
```

## 目标完成 - 迷你总结

这一次，除了在标题容器内的`<h1>`中设置一些不同的文本之外，我们还添加了一个新链接。这个链接返回到应用程序的欢迎画面，并使用了几个自定义`data-`属性。

`data-icon`，如前所述，设置了按钮应该使用的图标。我们可以使用`data-shadow="false"`禁用应用于图标外部容器元素的默认阴影，并设置`data-iconpos="notext"`属性使按钮成为只有图像的按钮。

我们还指定了`data-transition="slide"`属性，这样页面就可以很好地转换回欢迎页面，但是这次我们还设置了`data-direction="reverse"`属性，这样页面看起来就好像是*倒退*（也就是说，它以相反的方向滑动）到主页。因为我们将此链接放在`<h1>`元素之前，所以它将自动按照框架的设置向左浮动。

我们在`content`容器中添加了一些基本内容。这并不重要，正如您所看到的，我在这里为我的个人网站做了一些无耻的宣传。然而，这个外部链接并不完全无用，因为它表明，当一个链接以`http://`作为前缀时，jQuery Mobile 知道它是一个外部链接，并且不会劫持点击并尝试将其转换成视图。

您会注意到页脚容器与之前的`data-`属性相同，包括相同的`data-id="footer"`属性。这就是页脚容器具有持久性的原因。当页面转换到视图时，页脚将出现在转换区域之外，并固定在页面底部。

我们稍微修改了页脚容器中的`<a>`元素。我们删除了`data-transition`属性，并改为添加`ui-disabled`类。我们还将`href`更改为简单的哈希。因为我们已经在关于页面上，所以**关于**链接将不会做任何事情，所以我们将其禁用以避免在点击时重新加载页面。

## 机密情报

jQuery Mobile 通过劫持任何相对链接来添加它美丽的页面到页面的过渡效果。当点击相对链接时，jQuery mobile 将通过 AJAX 获取页面，将其插入到当前页面的 DOM 中，并将其转换为视图。

通常在使用 jQuery Mobile 站点时，您永远不会离开起始页面，因为框架会悄悄地劫持同域链接，并动态地将内容插入页面。因此，您可能认为每个页面都不需要链接到所有的 CSS 和脚本资源。

然而事实并非如此 - 如果有人直接访问内部页面会发生什么呢？或者如果点击外部链接后，访问者使用浏览器的返回按钮返回呢？在这两种情况下，他们将看到一个未增强、失效的页面，看起来和预期看到的页面完全不一样。

现在我们应该能够重新加载主页，然后点击页脚的**关于**按钮，看到关于页面。

# 创建脚本包装器

我们不会使用 jQuery 的`$(document).ready() { }`函数（或`$(function() { })`快捷方式）在页面加载完成时执行我们的代码。然而，我们仍然需要保护我们的顶层变量和函数免受全局范围的影响，因此我们仍然需要某种包装器。在这个任务中，我们将创建这个包装器，以及我们的顶层变量。

## 启动推进器

在空的`bounty-hunter.js`文件中，我们可以首先添加以下代码：

```js
(function() {

    var tags = "",
          getBounties = function(page, callback) {

        $.ajax({
            url: "https://api.stackexchange.com/2.0/questions/featured",
            dataType: "jsonp",
            data: {
                page: page,
                pagesize: 10,
                tagged: tags,
                order: "desc",
                sort: "activity",
                site: "stackoverflow",
                filter: "!)4k2jB7EKv1OvDDyMLKT2zyrACssKmSCX
                eX5DeyrzmOdRu8sC5L8d7X3ZpseW5o_nLvVAFfUSf"
            },
            beforeSend: function () {
                $.mobile.loadingMessageTextVisible = true;
                $.mobile.showPageLoadingMsg("a", "Searching");
            }
        }).done(function (data) {

            callback(data);

        });
    };

}());
```

## 目标完成 - 小型总结

我们的脚本包装器由一个自执行的匿名函数组成（或者如果你喜欢的话，它也可以是一个立即调用的函数表达式）。这个外部函数被括号包裹着，并且在末尾有一个额外的方括号对，它使匿名函数立即执行并立即返回。这是一个已经在大型应用程序中经常使用的 JavaScript 模式。

这创建了一个封闭环境，将其中的所有代码封装起来，并使它远离全局命名空间，这使得代码更健壮，当与其他库或插件一起使用时更不容易出错或失败。

### 注意

如果你不确定闭包是什么，或者它能做什么，可以在 Stack Overflow 网站上找到关于它的很好的讨论（[`stackoverflow.com/questions/111102/how-do-javascript-closures-work`](http://stackoverflow.com/questions/111102/how-do-javascript-closures-work)）。

它也允许我们几乎在文档加载完成后立即运行代码。因为它所在的`<script>`元素就在`<body>`的底部，所以它将等到浏览器解析完页面的其余部分后才会被执行。

在匿名外部函数中，我们首先定义了一些变量。第一个叫做`tags`，将在项目的整个过程中在各种函数中使用，所以它需要在任何地方都能访问。最初它可以被设置为空字符串。

接下来的变量是一个名为`getBounties()`的函数，我们同样在顶层范围内定义它，这样它就可以在代码的其他地方被调用而不会出现问题。我们将使用这个函数在应用程序的生命周期的不同节点发出 AJAX 请求，而且大多数请求的参数都不需要更改。

我们使用 jQuery 的`ajax()`方法向 Stack Exchange API 发出 AJAX 请求。这个方法是 jQuery 的默认用于发出 AJAX 请求的方法，也是该库的辅助方法（如`getJSON()`）所代理的方法。

`ajax()` 方法接受一个对象字面量，该字面量可用于配置 jQuery 支持的任何标准 AJAX 选项，以控制请求的执行方式。

`url` 属性设置了请求所发出的 URL，我们将其设置为我们想要使用的 Stack Exchange API 的入口点。我们将 `dataType` 设置为 `JSONP`，以便我们可以从 Stack Exchange 域获取数据，而不触发浏览器的跨域安全限制。

**JSON**（**JavaScript 对象表示法**）是一种数据格式，其语法与 JavaScript 中的对象字面量非常相似，用于在不同平台或系统之间交换数据。**JSONP**（带填充的 JSON）是一种技术，它动态将新脚本注入页面，将 JSON 数据暴露给浏览器中的 JavaScript 解析器。这是必要的，因为浏览器的同源安全策略限制了数据可以从当前域加载的域。

Stack Exchange API 可以通过使用标准查询字符串参数以非常特定的方式配置，并过滤我们收到的数据，以启用或禁用特定功能。我们可以使用 jQuery 的 `data` AJAX 属性来添加我们希望设置的查询字符串参数。

### 注意

有关 Stack Exchange API 的更多信息，请参阅[`api.stackexchange.com/`](https://api.stackexchange.com/) 的文档。

我们使用 `page` 参数指定我们想要获取结果的哪一页，这将作为参数传递给函数。我们将返回的问题数量设置为 `10`，以将一次显示的数据量分页。这是使用 `pagesize` 参数设置的。

`tagged` 参数使用标签变量的值，我们可以在项目后期需要时操纵它。如果我们发送此参数而没有值，Stack Exchange API 不会抱怨，因此我们可以安全地设置它，而不管实际上是否有任何标签。

我们指定希望结果按降序排列，并按活动排序，因此最近活动的问题将首先列出。`site` 设置为 `stackoverflow`，以便仅从 Stack Exchange 网站的整个网络中接收问题。

最后一个配置属性是我已经在 Stack Exchange 上创建并保存的预定义过滤器。当浏览任何 API 方法时，都包含了用于执行此操作的工具。过滤器的目的是精确控制在响应中返回哪些字段，以确保我们不会收到比我们需要的更多数据。

### 注意

在此示例中，我们仅匿名使用 Stack Exchange API。对于完全生产就绪、供公众使用的应用程序，我们必须始终在 Stack Applications 中注册应用程序，并在进行任何请求时使用 API 密钥。

我们想要的一些字段未包含在默认过滤器中（如果在发出请求时未提供过滤器，则使用默认过滤器），而返回了许多我们不需要的字段。我们将在此处使用的过滤器仅提供了我们此项目所需的字段，并且不需要身份验证即可使用。

这些是我们需要为此请求设置的大多数 AJAX 选项；目前不知道的选项可以在调用函数时传递。我们将在下一个任务中看到如何做到这一点。

我们可以利用 jQuery 的`beforeSend`AJAX 事件，在发出请求之前直接显示 jQuery Mobile 的 AJAX 旋转器。每次转换页面时，jQuery Mobile 都会使用旋转器，但是我们可以在进行 AJAX 请求时将其曲解为自己的要求。

框架将自动将`mobile`对象附加到当前页面上运行的 jQuery 实例上。此对象包含用于配置 jQuery Mobile 环境的各种属性，以及用于触发框架中不同行为的各种方法。我们现在可以使用其中的一些。

为了确保我们希望添加的消息被显示出来，因为默认情况下旋转器使用不可访问的文本，我们将`mobile`对象的`loadingMessageTextVisible`属性设置为`true`。

### 注意

在页面加载时，jQuery Mobile 创建了一个名为`mobile`的对象，其中包含一系列有用的属性和方法。

要实际显示旋转器，我们可以使用 jQuery Mobile 的`showPageLoadingMsg()`方法。此方法将主题色作为第一个参数，本例中我们可以将其设置为默认主题`a`，并将要在旋转器内显示的文本作为第二个参数。

在`ajax()`方法之后，我们链式调用`done()`方法。这是自 jQuery 1.8 起处理成功的 AJAX 请求的新方法，取代了 jQuery 的`success()`方法。我们将一个匿名函数传递给此方法，以在请求对象返回时执行，此函数接收响应作为参数。在此函数中，我们只需调用将作为第二个参数传递给`getBounties()`的`callback()`函数，将数据从响应传递给它。

## 机密情报

在这个任务中，我们使用了`done()`方法来处理来自 Stack Exchange API 的成功响应，而不是更常见的`success()`方法。这现在是处理成功响应的首选方法（截至 jQuery 1.8）。任何 jQuery 的 AJAX 方法返回的`jqXHR`对象的`error()`和`complete()`回调方法已经被弃用，改用`fail()`和`always()`。

自 jQuery 1.5 起，AJAX 方法套件已将`jqXHR`对象作为 promise 或 deferred 对象返回，因此此 API 的更改将 AJAX 方法与 jQuery 中其他实现的 promise API 同步。

# 获取一些赏金

在这个任务中，我们需要从堆栈溢出获取一些赏金。一旦我们的应用程序的欢迎页面初始化完成，我们将希望初始化我们脚本的一部分。一旦这种情况发生，我们就可以附加一个处理程序到页面上的`<button>`，以触发使用我们在上一部分中添加的`getBounties()`函数进行 AJAX 请求。

## 启动推进器

在`bounty-hunter.js`中的外部函数内，但在`getBounties()`函数之后，添加以下代码：

```js
$(document).on("pageinit", "#welcome", function () {

    $("#search").on("click", function () {

        $(this).closest(".ui-btn")
                  .addClass("ui-disabled");

        tags = $("tags").val();

        getBounties(1, function(data) {

            data.currentPage = 1;

            localStorage.setItem("res", JSON.stringify(data)); 

            $.mobile.changePage("bounty-hunter-list.html", {
                transition: "slide"
            });
        });
    });
});
```

我们还可以在刚刚添加的代码之后直接为`pageshow`事件添加处理程序：

```js
$(document).on("pageshow", "#welcome", function () {
    $("#search").closest(".ui-btn")
                        .removeClass("ui-disabled");
});
```

## 完成目标 - 小结

我们使用`pageinit`事件在页面第一次初始化时执行代码。由于新页面被拉入现有页面的 DOM 并显示的 AJAX 性质，因此在使用 jQuery Mobile 时，此事件比`document ready`更可靠。

我们使用 jQuery 的`on()`方法将此事件的事件处理程序绑定到文档对象，并将方法的第一个参数设置为`pageinit`事件。因为我们的脚本将用于每个页面，但是我们在此处添加的代码仅在欢迎页面上相关，所以我们使用方法的第二个参数来确保事件处理程序（我们将其添加为第三个参数）仅在事件起源于欢迎页面时执行。

然后，我们使用 jQuery 的`on()`方法将`click`事件的处理程序绑定到搜索`<button>`，再次使用。在处理程序中，我们首先向外部`<button>`容器添加`ui-disabled`类，以阻止进一步发起请求。然后，我们使用 jQuery 的`val()`方法获取可能在文本字段中输入的任何标签。这将返回文本输入的值，然后我们将其存储在我们的顶级`tags`变量中。

接下来，我们可以调用上一任务中添加的`getBounties()`函数。由于请求是由欢迎页面发起的，所以我们需要获取结果的第一页，因此将`1`作为第一个参数传递给该函数。

我们将一个匿名函数作为`getBounties()`的第二个参数。请记住，我们为`done()`方法添加的处理程序将执行该函数，并自动将响应中的数据传递给它。

在这个功能中，我们首先需要向我们的`data`对象添加一个新属性来存储当前页码。然后，我们可以存储`data`对象，以便在下一页中使用。我们可以使用`localStorage`来实现这一点，但是因为`localStorage`只能存储数组和原始类型，所以我们需要使用浏览器的原生`JSON.stringify()`方法将对象转换为 JSON 字符串。

然后，我们使用 jQuery Mobile 的`changePage()`方法将当前页面更改为我们将显示响应的页面。该方法的第一个参数是要更改到的页面的 URL，第二个参数是一个配置对象。

我们使用此配置对象来设置显示新页面时要使用的转换，该转换选项我们设置为`slide`。

在`pageinit`处理程序之后，我们还添加了一个`pageshow`事件的事件处理程序。每次显示页面时都会分派此事件，与仅在给定页面初始化时分派的`pageinit`事件不同。

我们再次将事件绑定到`document`对象，并再次通过`#welcome`选择器过滤事件，以确保代码仅在显示欢迎页面时运行。在事件处理程序内部，我们只是从外部的`<button>`容器中移除`ui-disabled`类。如果我们返回到欢迎页面，那可能是因为我们想执行一个新的搜索，也许使用不同的标签。

# 添加一个 JsRender 模板

在上一个任务结束时，我们使用`changePage()`方法调用了一个新页面，所以现在我们需要创建该页面。我们可以在新页面中添加我们的 JsRender 模板，准备好在下一个任务中构建列表视图时使用。

## 为升空做准备

再次使用 jQuery Mobile 的起始模板创建一个新页面。将其命名为`bounty-hunter-list.html`并将其保存在项目文件夹的根目录中。将`data-role="page"`包装器的`id`属性更改为`list`。

在标题`<div>`中的`<h1>`可以更改为类似于`Active Bounties`的内容，并且我们可以像在关于页面上那样再次添加主页图标。页脚可以与欢迎页面上的相同。内容`<div>`可以一开始为空。

## 启动推进器

在我们刚刚创建的新页面底部，页面容器内，添加以下 JsRender 模板：

```js
<script id="listTemplate" type="text/x-jquery-tmpl">
    <ul data-role="listview">

        {{for items}}
            <li data-shadow="false" data-icon="arrow-r" 
            data-iconpos="right">

                <a href="#" id="item-{{:#index}}">
                    <div class="bounty">
                        <span>+{{:bounty_amount}}</span>
                        <span class="expires">Expires on: 
                            <span class="value">
                                {{:bounty_closes_date}}
                            </span>
                        </span>
                    </div>
                    <h1 class="title">{{:title}}</h1>
                    <div class="meta">
                        <span>Answers: 
                            <span class="value">
                                {{:answer_count}}
                            </span>
                        </span>
                        <span class="activity">
                            Last activity on: 
                            <span class="value">
                                {{:last_activity_date}}
                            </span>
                        </span> 
                    </div>
                </a>
            </li>
        {{/for}}
    </ul>
</script>
```

## 目标完成 - 小型总结

包含模板的`<script>`元素具有一个非标准的`type`属性，以阻止浏览器解析脚本。它还具有一个`id`属性，以便我们在想要将模板与数据进行插值并呈现到页面时轻松选择它。

在`<script>`元素内，我们首先创建一个`<ul>`元素，这将由 jQuery Mobile 转换为 Listview 小部件。我们给这个元素一个`data-role`属性为`listview`。然后我们使用 JsRender 的循环结构`{{for}}`，它接受要循环遍历的对象或数组。在这种情况下，我们对`data`对象中的`items`数组感兴趣，该数组是在上一个任务结束时保存在 localStorage 中的一部分，并且将被传递给呈现模板的模板函数。

我们在`{{for}}`循环内添加的代码将针对`items`数组中的每个项目重复执行，该数组将由一系列来自 Stack Overflow 的问题组成。当我们稍后调用 JsRender 的`template()`方法时，将传递模板将迭代的对象到循环中。

我们添加的第一个元素是 `<li>`，因为这应该自然地是外部 `<ul>` 列表的子元素。我们为 `<li>` 元素添加了几个 `data-` 属性，包括 `data-shadow="false"` 以在每个 `<li>` 下禁用阴影，`data-icon="arrow-r"` 以给每个列表项添加右指向箭头图标，`data-iconpos="right"` 以将图标定位在元素的右侧。

### 贴士

**Listitem 图标**

为了让我们添加到列表项的图标显示出来，每个项目应包含一个链接。如果初始化小部件时在项目内找不到 `<a>` 元素，就不会添加图标。

在列表项内部，我们添加一个 `<a>` 元素并为其添加一个唯一的 `id`，以便在以后显示该项视图时使用。我们可以使用模板的循环索引创建唯一的 `id`，这在循环中作为 `#index` 对我们可用。

在 `<a>` 元素内部，我们还有其他几个元素。第一个是当前问题上提供的悬赏的容器。在这个容器内，我们有另一个 JsRender 令牌，它将被替换为我们正在迭代的对象的数据。为了在我们的模板中访问对象的属性，我们使用 `{{:`，后跟属性名称，最后以 `}}` 结束。在开头的双大括号内的冒号表示不应执行任何 HTML 编码。Stack Exchange API 将为我们清理数据，所以我们可以直接使用它。

我们还可以使用一些嵌套的 `<span>` 元素显示一些文本和悬赏过期的日期，其中一个具有用于特定样式的 `class`，还有我们数据对象的另一个属性。

我们可以使用 `<h1>` 元素输出问题的标题，另外还有另一个 JsRender 模板标记，从 `data` 对象内提取出当前项的 `title` 属性。

最后，我们可以显示有关问题的一些元信息，比如它有多少答案以及上次有活动的时间。这些信息与以前一样添加，使用 `<span>` 元素和 JsRender 模板标记的组合来显示从我们的数据对象中提取出的各种属性。

# 构建列表视图

现在，我们的应用程序应该已经收到了需要进行格式化和显示的数据。我们还添加了一个准备好用于构建 Listview 小部件的 Listitem 元素的 JsRender 模板。

现在，我们只需渲染模板并在小部件中显示结果。我们还可以向小部件添加一些额外的控件，让访问者在分页结果中导航，尽管目前我们还不会使这些控件功能实现。

## 启动推进器

首先，我们可以为列表页面的内容容器（`bounty-hunter-list.html`）添加一些附加标记：

```js
<div class="ui-bar ui-bar-c">
    <a href="#" data-role="button" data-icon="back" 
    data-inline="true" data-mini="true" class="ui-disabled">
    Prev
    </a>

    <h2>Page 
        <span class="num"></span> of <span class="of"></span>
    </h2>

    <a href="#" data-role="button" data-icon="forward" 
        data-iconpos="right" data-inline="true" 
        data-mini="true" class="ui-disabled">
        Next
    </a>
</div>

<div id="results"></div>

<div class="ui-bar ui-bar-c footer-bar">
    <a href="#" data-role="button" data-icon="back" 
    data-inline="true" data-mini="true" class="ui-disabled">
    Prev
    </a>

  <h2>Page 
    <span class="num"></span> of <span class="of"></span>
  </h2>

    <a href="#" data-role="button" data-icon="forward" 
    data-iconpos="right" data-inline="true" 
    data-mini="true" class="ui-disabled">
    Next
    </a>
</div>
```

接下来，我们需要更新我们的脚本以渲染模板并显示数据。在 `bounty-hunter.js` 中，在 `pageshow` 事件的事件处理程序后直接添加以下代码：

```js
$(document).on("pageinit", "#list", function () {

    var data = JSON.parse(localStorage.getItem("res")),
          total = parseInt(data.total, 10),
          size = parseInt(data.page_size, 10),
          totalPages = Math.ceil(total / size),
          months = [
            "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", 
            "Aug", "Sep", "Oct", "Nov", "Dec"
    ];

    var createDate = function (date) {
        var cDate = new Date(date * 1000),
              fDate = [
                cDate.getDate(), months[cDate.getMonth()], 
                cDate.getFullYear()
        ].join(" ");

        return fDate;
    }

    $.views.helpers({ CreateDate: createDate });

    $("#results").append($("#listTemplate")
                 .render(data))
                 .find("ul")
                 .listview();

    var setClasses = function () {
        if (data.currentPage > 1) {
            $("a[data-icon='back']").removeClass("ui-disabled");
        } else {
            $("a[data-icon='back']").addClass("ui-disabled");
        }

        if (data.currentPage < totalPages) {
            $("a[data-icon='forward']").removeClass("ui-disabled");
        } else {
            $("a[data-icon='forward']").addClass("ui-disabled");
        }
    };

    $("span.num").text(data.currentPage);
    $("span.of").text(totalPages);

    if (totalPages > 1) {
        $("a[data-icon='forward']").removeClass("ui-disabled");
    }
});
```

我们还需要稍微改变我们的模板。我们的模板中有两个地方显示日期属性；这两个地方都需要改变，以便它们显示如下：

```js
{{:~CreateDate(bounty_closes_date)}}
```

并：

```js
{{:~CreateDate(last_activity_date)}}
```

最后，我们需要为我们的新元素添加一些额外样式，以及将添加到 Listview 小部件中的条目。在`bounty-hunter.css`底部添加以下样式：

```js
.ui-bar { margin:0 -15px 14px -15px; text-align:center; }
.ui-bar a:first-child { margin-left:-5px; float:left; }
.ui-bar a:last-child { margin-right:-5px; float:right; }
.ui-bar h2 { margin-top:10px; font-size:14px; }
.footer-bar { margin-top:14px; }

.bounty { 
    width:24%; border-radius:3px; margin-right:5%; float:left;
    text-align:center; font-size:90%; line-height:1.5em; 
    font-weight:bold; color:#fff; background-color:#07d; 
    text-shadow:none; 
}
.bounty span { display:block; }
.expires { 
    font-size:70%; font-weight:normal; line-height:1em; 
}
.expires .value { 
    display:block; font-size:110%; font-weight:bold; 
    line-height:1.5em; 
}
.title { 
    width:70%; margin-top:-.25em; float:left; 
    white-space:normal; font-size:80%; line-height:1.25em; 
    color:#07d; 
}
.meta { clear:both; }
.meta span { 
    width:24%; margin-right:5%; float:left; font-size:70%; 
    font-weight:normal; color:#999; 
}
.meta .value { 
    width:70%; margin-right:0; float:none; font-size:90%; 
    font-weight:bold; 
}
```

## 完成目标 - 小结

在这项任务的第一步中，我们在页面的内容容器中添加了一些新的 HTML 元素。

我们添加的第一个元素将用作位于 Listview 小部件上方的工具栏。工具栏中含有用于让访问者在不同结果页之间导航的链接。这个工具栏将从 jQuery Mobile 中继承许多样式，因为我们为它添加了`ui-bar`和`ui-theme`类名。

由于它们具有`data-role="button"`属性，链接会被 jQuery Mobile 增强为 Button 小部件。我们还使用`data-icon`属性为它们添加图标，使用`data-inline`属性使它们成为`inline-block`，并使用`data-mini`属性使它们比标准按钮小。

最后，我们最初给按钮添加了`ui-disabled`类名。我们可以根据我们所在的页面以及是否有前一页或后一页可导航来启用每个按钮。

除了按钮外，工具栏还包含一个`<h2>`元素，告诉访问者他们在哪一页，以及总共有多少页。该元素的内容分成带有`id`属性的 span，以便我们稍后可以轻松更新它们。

我们还在页面上添加了一个空的容器`<div>`，它的`id`为 results。这个容器将成为我们渲染 Listview 小部件的元素。

我们直接在空 Listview 容器后添加的第二个工具栏与第一个工具栏在所有方面都是相同的，只是它多了一个`footer-bar`的额外类。我们用这个类添加了一些仅需要在底部工具栏中使用的 CSS。

在我们的脚本中，我们首先为列表页的`pageinit`事件添加了一个新的事件处理程序。这与之前使用 jQuery 的`on()`方法绑定方式相同。

在事件处理程序中，我们首先设置一系列变量。我们在代码中的各个地方存储了之前任务中存储在 localStorage 中的数据的引用，以及`data`对象的`total`结果和`page_size`属性。

我们还根据刚刚保存的`total`和`size`变量计算出总页数，并创建一个包含缩写月份名称的数组，我们在格式化 Stack Exchange 返回的日期时会用到这个数组。

接下来，我们需要添加一个新方法，作为模板内部的辅助函数使用。我们将这个方法称为`createDate`，并指定该方法可以接受一个日期字符串作为参数。

在这个方法中，我们首先使用传递给该方法的日期字符串创建一个新的日期。这将以 UNIX 时代格式呈现，因此需要将其乘以 1000，以便与 JavaScript 的`Date()`构造函数一起使用。

`Date()`构造函数返回的日期字符串将是完整的 UTC 日期字符串，对于显示在我们的小奖励框中来说太长了，所以接下来我们定义一个新的数组，数组中的每个项目都是我们希望将现有字符串格式化为的日期字符串的一部分。

我们可以使用`getDay()`函数获取月份的天数。`getMonth()`函数将返回一个从零开始的数字，因此我们可以使用它从我们先前创建的数组中提取正确的缩写月份名称。最后，我们使用`getFullYear()`函数获取四位数的年份。一旦数组填充完毕，我们立即使用空格字符作为连接字符连接它，并从方法中返回结果字符串。

接下来，我们需要将我们的新方法注册为帮助函数，以便我们正在使用的模板可以访问它。这是使用 JsRender 创建的`views`对象的`helpers()`方法完成的，并将其附加到 jQuery 上。该方法以对象作为其参数，对象中的每个键是帮助方法的名称，每个值是我们希望用作帮助器的实际函数。在这个例子中，我们将`CreateDate`帮助方法映射到我们刚刚定义的`createDate`函数。

然后，我们使用其`id`选取 Listview 小部件，并向其附加已渲染的模板。模板是使用 JsRender 的`render()`方法呈现的，它接受包含要呈现的数据的对象作为参数。

接下来，我们定义另一个简单的函数，它将根据我们在`data`对象上存储的`currentPage`属性添加或删除按钮上的`ui-disabled`类名。

我们现在可以更新标题，显示当前页和总页数。我们可以使用 jQuery 的`text()`方法来做到这一点，并显示我们之前存储的`data.currentPage`和`totalPages`变量。

因为这只是列表页面加载的第一次，我们知道只有**下一页**按钮需要启用。我们使用属性选择器仅基于它们的`data-icon`属性选择两个前进按钮。我们将在下一个和最后一个任务中添加使该按钮工作的功能。

我们脚本中的最后一件事是启用前进按钮，以便查看下一页，但仅在要显示更多页面时才能这样做，这可以通过再次检查`totalPages`变量来确定。

添加脚本后，我们然后更新了模板，以利用我们创建的新的日期格式化辅助方法。要在模板中使用辅助方法，我们只需要使用`~`字符，后跟方法的注册名称。需要传递的任何参数，例如模板迭代中的每个项目的`bounty_closes_date`和`last_activity_date`属性，都是使用括号传递的，就像调用普通 JavaScript 函数一样。

渲染模板后，我们需要初始化 Listview。首先，我们通过获取容器内的新`<ul>`元素，然后使用其小部件方法，在这种情况下是`listview()`，将其增强为一个 Listview 小部件。

最后，我们添加了一些额外的 CSS 样式来微调 jQuery Mobile 中默认主题应用的样式。我们需要使工具栏与 Listview 小部件匹配，这可以通过使用负边距来实现，与 Listview 小部件本身一样简单。

Listview 的`top`和`bottom`属性以及其`left`和`right`属性具有负边距，因此我们需要通过为顶部工具栏添加一些正边距来抵消这一点，并为底部工具栏添加一些正`top`边距。

我们还可以将后退和前进按钮分别浮动到左侧和右侧，并将标题文本居中。我们还将标题文本的大小缩小了几个像素，以确保它不会干扰我们的按钮。

Listview 内的元素样式几乎完全是为了视觉效果而添加的。Listview 本身将继承大量框架的样式，所以我们只需要担心每个 Listitem 内的元素。

一旦点击了赏金按钮并返回了结果，列表视图页面应该看起来像下面的截图：

![目标完成 - 小结](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_04_02.jpg)

## 机密情报

与 jQuery UI 一样，jQuery Mobile 小部件可以完全从脚本初始化，而不使用底层标记中的任何硬编码`data-`属性。我们也可以像在标记中保留外部`<ul>`元素一样，完全从脚本构建整个 Listview 小部件。

要初始化小部件，我们只需调用其小部件方法。如果我们正在创建一个 Listview，则小部件方法就是`listview()`。其他小部件可以以相同的方式初始化。与 jQuery UI 小部件类似，jQuery Mobile 小部件可以接受配置选项和事件处理程序，并且具有可以从脚本调用的方法。

# 构建项目视图

列表视图为每个包含问题的列表项提供链接。在这个任务中，我们可以添加当其中一个问题被选中时显示的页面。这将是单个问题的更详细视图，所以我们可以利用 Stack Exchange 返回给我们的其他一些属性。这次，我们不是链接到现有页面，而是动态创建一个新页面并将其注入到应用程序中。

## 启动推进器

我们将使用另一个模板来渲染项目视图，因为它非常方便；直接在`bounty-hunter-list.html`中的列表模板后面添加以下代码。我们可以从添加外部`<script>`包装器、外部页面容器和标题开始：

```js
<script id="itemTemplate" type="text/x-jquery-tmpl">
    <div data-role="page" id="{{:pageid}}" class="item-view">
        <div data-role="header" data-position="fixed">
            <a href="bounty-hunter-list.html" 
            data-shadow="false" data-icon="arrow-l" 
            data-transition="slide" 
            data-direction="reverse" 
            title="Back to list view">
            Back
            </a>

            <h1>{{:title}}</h1>

        </div>
    </div>
</script>
```

接下来，我们可以添加内容区域包装器和内容标题。这应该放在页面容器中，在标题区域之后：  

```js
<div data-role="content">
    <header class="ui-helper-clearfix">
        <div class="bounty">
            <span>+{{:bounty_amount}}</span>
      <span class="expires">
        Expires on: 
        <span class="value">
          {{:~CreateDate(bounty_closes_date)}}
        </span>
      </span>
    </div>

    <div class="meta">
        <span>Asked on: 
            <span class="value">
                {{:~CreateDate(creation_date)}}
            </span>
         </span>
        <span>Answers: 
            <span class="value">
                {{:answer_count}}
            </span>
        </span>
        <span class="activity">Last activity on: 
            <span class="value">
                {{:~CreateDate(last_activity_date)}}
            </span>
        </span> 
    </div>

    <h1 class="title">{{:title}}</h1>
    <ul class="tags">
        {{for tags}}
            <li>{{:#data}}</li>
            {{/for}}
    </ul>

    <div class="owner">
        <a href="{{:owner.link}}" 
            title="{{:owner.display_name}}">
                <img src="img/{{:owner.profile_image}}" 
                     alt="{{:owner.display_name}}" />
            <div>
                <h3>{{:owner.display_name}}</h3>
                <span>
                    {{:owner.accept_rate}}% accept rate
                </span>
            </div>
        </a>
    </div>
    <a data-role="button" data-icon="gear" 
    data-inline="true" href="{{:link}}" 
    title="Answer on Stack Overflow">
    Answer on Stack Overflow
    </a>

  </header>

</div>
```

接下来，我们可以添加问题和答案列表。这应该直接放在我们刚刚添加的标题元素之后（但仍然在内容`<div>`内）：

```js
<div class="question">{{:body}}</div>

<h2>Answers</h2>
<ul class="answer">
    {{for answers}}
        <li data-shadow="false">
            <h3>Answered by: 
                <span class="answer-name">
                    {{:owner.display_name}}
                </span>, on 
                <span class="answer-date">
                    {{:~CreateDate(creation_date)}}
                </span>
            </h3>

            <div>{{:body}}</div>
        </li>
      {{/for}}
</ul>
```

最后，我们可以为页面添加页脚。这应该直接放在内容区域之后，但仍然在外部页面容器内：

```js
<div data-role="footer" data-position="fixed" 
    data-id="footer">

    <small>&copy; 2012 Some Company Inc.</small>
    <a href="bounty-hunter-about.html" 
    data-icon="info" data-role="button" 
    data-transition="slide">
    About
    </a>
</div>
```

我们还需要添加一些脚本来渲染模板并处理页面更改行为。我们可以在我们在上一个任务中添加的列表页面的`pageinit`处理程序中执行此操作：

```js
$("#results").on("click", "li", function () {

    var index = $(this).find("a").attr("id").split("-")[1],
          question = data.items[index];

    question.pageid = "item-view-" + index;

    $("body").append($("#itemTemplate").render(question));

    var page = $("#item-view-" + index);

    page.attr("data-external-page", true).on
    ("pageinit", $.mobile._bindPageRemove);

    $.mobile.changePage(page, {
        transition: "slide"
    });
});
```

最后，我们需要一些用于我们添加的模板中新元素的 CSS。在`bounty-hunter.css`中，在文件的末尾添加以下代码：

```js
header { 
    padding:15px; border-bottom:1px solid #fff; 
    margin:-15px -15px 0 -15px; 
    box-shadow:0 1px 10px rgba(0,0,0,.3); 
}
header:after { 
    content:""; display:block; clear:both; visibility:hidden;
}
header .bounty { margin-bottom:.75em; }
header .meta { width:70%; float:left; clear:none; }
header .meta span { width:100%; }
header .title { 
    width:auto; margin:0; float:none; clear:both; 
    font-size:125%; 
}
.tags { padding:0; }
.tags li { 
    padding:.5%; border-right:1px solid #7f9fb6; 
    border-bottom:1px solid #3e6d8e; margin-right:1%; 
    margin-bottom:1%; float:left; list-style-type:none; 
    font-size:90%; color:#4a6b82; background-color:#e0eaf1;
}
header a { 
    margin-left:0; float:left; clear:both;
    text-decoration:none; 
}
.owner { 
    padding:2.5%; margin:15px 0; float:left; clear:both; 
    font-size:70%; background-color:#e0eaf1; 
}
.owner img { width:25%; margin-right:5%; float:left; }
.owner div { width:70%; float:left; }
.owner h3 { margin:-.25em 0 0; }
.owner span { font-size:90%; color:#508850; }

.question { 
    padding:15px; border-bottom:1px solid #000; 
    margin:-15px -15px 0 -15px;
}
.question img { max-width:100%; }

.answer { padding:0; list-style-type:none; }
.answer li { border-bottom:1px solid #000; font-size:80%; }
.answer h1, .answer h2, .answer h4 { font-size:100%; }
.item-view pre { 
    max-width:95%; padding:2.5%; border:1px solid #aaa; 
    background-color:#fff; white-space:pre-wrap;
}
```

## 目标完成 - 小结。

我们首先添加了一个新模板，用于显示单个问题的页面。这个模板比我们添加的第一个模板要大得多，原因有几个。主要是因为我们使用这个模板来构建整个页面，而且因为我们使用这个模板显示了更多的内容。这是问题的详细视图，所以我们自然希望显示比列表视图中显示的摘要更多的内容。

我们指定的外部页面容器被赋予一个`id`，我们将在我们的脚本中添加，以便我们可以轻松地选择正确的页面以显示它。除此之外，我们在我们的模板中添加了一些与我们在实际页面中一直添加的相同元素，例如标题、内容和页脚容器。

大部分操作都在内容容器内部进行，尽管我们使用的模板方式与之前完全相同 - 定义 HTML 元素并使用传递给`render()`方法的对象的属性进行插值。

在此模板中唯一的新技巧是创建标签列表。我们使用`for`结构来迭代标签列表，但这次我们迭代的属性是一个平面字符串数组，而不是对象。由于在模板标签中没有可用于获取值的键，我们可以使用特殊值`#data`，它将给我们当前正在迭代的数组中的当前项目。

我们添加到脚本中的所有代码都包含在一个单击处理函数中，我们将其绑定到页面上显示的结果列表上，因为我们希望对单个列表项的点击做出反应。

在处理函数中，我们首先设置一个变量，该变量将包含被点击的列表项的`id`属性的数字部分。我们可以通过使用 JavaScript 的`split()`函数，并指定连字符作为分隔符，轻松获取数字部分。

当我们渲染模板时，我们只想显示单个项目，因此我们不需要传递从 AJAX 请求中接收到的整个对象。相反，我们使用刚刚设置的`index`变量，从`data`对象内的`items`数组中仅获取表示我们感兴趣的问题的对象。

一旦我们存储了要传递给模板以进行渲染的对象，我们需要向其添加一个新属性，该属性作为模板中页面容器的`id`属性添加。这就是我们在`question`对象上设置的`pageid`属性。

接下来，我们再次使用 JsRender 的`render()`方法呈现我们的模板。我们将刚刚准备好的`question`对象传递给它，这一次模板呈现到页面的主体上。因为它被呈现在页面容器之外，所以不会立即可见。

一旦模板呈现到页面上，我们选择外部页面容器，并将其引用存储在`page`变量中。当动态创建一个新页面并将其附加到页面上时，jQuery Mobile 将保持其标记在页面中，即使我们离开页面也是如此。

要阻止这种情况发生，我们需要做两件事：首先，我们需要将页面的`data-external-page`属性设置为`true`。其次，我们需要为动态页面的`pageinit`事件设置处理程序。一旦新页面已初始化，当访问者使用内部 jQuery Mobile `_bindPageRemove`方法导航离开页面时，我们将其标记为删除。

一旦完成这一步，我们可以使用`changePage()`方法转到新页面。我们将之前存储的页面元素传递给该方法，并使用配置对象设置转换。

因为我们将`changePage()`方法传递了一个 DOM 元素而没有指定 URL，所以浏览器的地址栏不会更新，并且浏览器的历史记录中不会留下条目。

此时，我们应该能够在智能手机或平板电脑上运行页面，单击列表视图页面上的其中一个列表项，并查看项目视图，如下图所示：

![目标完成 - 迷你总结](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_04_03.jpg)

# 处理分页

对于我们的最后一个任务，我们将查看如何连接之前添加的分页元素。Stack Exchange API 使得以分页格式获取结果变得很容易，因此我们可以利用这一点。

从 Stack Exchange 请求所有可用数据并节省一次性大量数据的代价是，我们在用户发起更多数据请求时会发出更小的请求。

## 启动推进器

在我们为 Listview 内的`<li>`元素添加的`click`处理程序之后，添加以下代码：

```js
$("a[data-icon='forward'], a[data-icon='back']").on("click", function () {

    var button = $(this),
        dir = button.attr("data-icon"),
        page = parseInt($("span.num").eq(0).text(), 10);

    if (dir === "forward") {
        page++;
    } else {
        page--;
    }

    getBounties(page, function (newData) {

        data = newData;
        data.currentPage = page;
        localStorage.setItem("res", JSON.stringify(newData));

        $.mobile.hidePageLoadingMsg();

        $("#results").empty()
                     .append($("#listTemplate")
                     .render(newData))
                     .find("ul")
                     .listview();

        $("span.num").text(page);

        setClasses();
    });
});
```

## 目标完成 - 小结

我们再次使用`data-icon`属性为所有四个按钮附加监听器，以便从页面中选择它们。不要忘记，这只会在第一次加载列表页面时完成一次。

然后，我们将引用存储到被点击的按钮、被点击按钮的`data-icon`属性的值以及当前页面。然后我们检查`dir`属性的值，如果等于`forward`，则增加当前页面，否则减少当前页面。

然后，我们可以再次调用我们的`getBounties()`方法，传递更新后的`page`变量和请求后执行的处理程序函数。

在此处理程序函数中，我们首先通过使用最近一次调用`getBounties()`返回的新对象更新`data`变量来更新存储的数据。我们再次向`data`对象添加一个`currentpage`属性，并更新我们在 localStorage 中的副本。

然后，我们可以使用`hidePageLoadingMsg()`jQuery Mobile 方法手动隐藏旋转器，然后使用新数据重新渲染列表模板。完成后，我们可以更新显示当前页面的显示，并调用我们的`setClasses()`实用函数分别启用或禁用前进和后退按钮。

# 任务完成

此时，我们应该拥有一个完全可工作的 jQuery Mobile 应用程序，可在桌面和移动设备上运行。这是一个简单的应用程序，但我们已经探索了相当数量的框架。还有很多东西要学习，但是看到我们在这个项目中使用的一些部分应该足以激发你深入研究框架及其提供的功能。

# 你准备好全力以赴了吗？一个高手的挑战

在这个项目中，到目前为止我们还没有研究过 jQuery Mobile 的主题能力。像 jQuery UI 一样，jQuery Mobile 受益于 Themeroller 的高级主题能力。

你在这个项目中的挑战是前往[`jquerymobile.com/themeroller/`](http://jquerymobile.com/themeroller/)，为已完成的应用程序构建一个自定义主题。


# 第五章：jQuery 文件上传器

现在可以仅使用一些最新的 HTML5 API 和 jQuery 创建一个功能齐全的文件上传小部件。我们可以轻松添加对高级功能的支持，例如多个上传和拖放界面，而且只需稍微借助 jQuery UI，我们还可以添加引人入胜的 UI 功能，例如详细的文件信息和进度反馈。

# 任务简报

在本项目中，我们将使用 HTML5 文件 API 提供核心行为构建一个高级多文件上传小部件，并使用 jQuery 和 jQuery UI 构建一个引人入胜的界面，访问者将乐于使用。

我们将构建小部件作为 jQuery 插件，因为这是我们可能想要封装的东西，这样我们就可以将其放入许多页面中，并且只需进行一些配置即可使其工作，而不是每次都需要构建自定义解决方案。

## 为什么很棒？

jQuery 提供了一些出色的功能，使编写可重复使用的插件变得轻而易举。在本项目中，我们将看到打包特定功能和生成所有必要标记以及添加所有所需类型行为的机制是多么容易。

在客户端处理文件上传为我们提供了许多增强体验功能的机会，包括有关每个选择的上传文件的信息，以及一个丰富的进度指示器，使访问者了解上传可能需要多长时间。

我们还可以允许访问者在上传过程中取消上传，或在上传开始之前删除先前选择的文件。这些功能纯粹使用服务器端技术处理文件上传是不可用的。

在此项目结束时，我们将制作以下小部件：

![为什么很棒？](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_05_01.jpg)

## 你的热门目标

要完成项目，我们需要完成以下任务：

+   创建页面和插件包装器

+   生成基础标记

+   添加接收要上传文件的事件处理程序

+   显示所选文件列表

+   从上传列表中删除文件

+   添加 jQuery UI 进度指示器

+   上传所选文件

+   报告成功并整理工作

## 任务清单

与我们以前的一些项目一样，除了使用 jQuery，我们还将在本项目中使用 jQuery UI。我们在书的开头下载的 jQuery UI 副本应该已经包含我们需要的所有小部件。

像以前的项目一样，我们还需要在此项目中使用 Web 服务器，这意味着使用正确的 `http://` URL 运行页面，而不是 `file:///` URL。有关兼容的 Web 服务器信息，请参阅以前的项目。

# 创建页面和插件包装器

在此任务中，我们将创建链接到所需资源的页面，并添加我们的插件将驻留在其中的包装器。

## 为起飞做准备

在这一点上，我们应该创建这个项目所需的不同文件。首先，在主项目文件夹中保存一个模板文件的新副本，并将其命名为 `uploader.html`。我们还需要一个新的样式表，应该保存在 `css` 文件夹中，命名为 `uploader.css`，以及一个新的 JavaScript 文件，应该保存在 `js` 文件夹中，命名为 `uploader.js`。

新页面应链接到 jQuery UI 样式表，以便获取进度条小部件所需的样式，并且在页面的 `<head>` 中，直接在现有的对 `common.css` 的链接之后，添加该项目的样式表：

```js
<link rel="stylesheet" href="css/ui-lightness/jquery-ui-1.10.0.custom.min.css" />

<link rel="stylesheet" href="css/uploader.css" />
```

我们还需要链接到 jQuery UI 和此示例的 JavaScript 文件。我们应该在现有的用于 jQuery 的 `<script>` 元素之后直接添加这两个脚本文件：

```js
<script src="img/jquery-ui-1.10.0.custom.min.js"></script>
<script src="img/uploader.js"></script>
```

## 启动推进器

我们的插件只需要一个容器，小部件就可以将所需的标记渲染到其中。在页面的 `<body>` 中，在链接到不同 JavaScript 资源的 `<script>` 元素之前，添加以下代码：

```js
<div id="uploader"></div>
```

除了链接到包含我们的插件代码的脚本文件之外，我们还需要调用插件以初始化它。在现有的 `<script>` 元素之后，直接添加以下代码：

```js
<script>
    $("#uploader").up();
</script>
```

插件的包装器是一个简单的结构，我们将用它来初始化小部件。在 `uploader.js` 中，添加以下代码：

```js
;(function ($) {

    var defaults = {
        strings: {
            title: "Up - A jQuery uploader",
            dropText: "Drag files here",
            altText: "Or select using the button",
            buttons: {
                choose: "Choose files", 
                upload: "Upload files" 
            },
            tableHeadings: [
                "Type", "Name", "Size", "Remove all x"
            ]
        }
    }

    function Up(el, opts) {

        this.config = $.extend(true, {}, defaults, opts);
        this.el = el;
        this.fileList = [];
        this.allXHR = [];
    }

    $.fn.up = function(options) {
        new Up(this, options);
        return this;
    };

}(jQuery));
```

## 目标完成 - 迷你简报

构建 jQuery 插件时，我们能做的最好的事情就是使我们的插件易于使用。根据插件的用途，最好尽可能少地有先决条件，因此，如果插件需要复杂的标记结构，通常最好让插件渲染它需要的标记，而不是让插件的用户尝试添加所有必需的元素。

鉴于此，我们将编写我们的插件，使得页面上只需要一个简单的容器，插件就可以将标记渲染到其中。我们在页面上添加了这个容器，并为其添加了一个 `id` 属性以便于选择。

使用我们的插件的开发人员将需要一种调用它的方法。jQuery 插件通过向 `jQuery` 对象添加附加方法来扩展 `jQuery` 对象，我们的插件将向 jQuery 添加一个名为 `up()` 的新方法，该方法像任何其他 jQuery 方法名称一样被调用 - 在被 jQuery 选择的一组元素上。

我们在 `<body>` 元素底部添加的额外 `<script>` 元素调用了我们的插件方法，以调用插件，这就是使用我们的插件的人会调用它的方式。

在我们的脚本文件中，我们以一个分号和一个立即调用的匿名函数开始。分号支持 jQuery 插件的模块化特性，并保护我们的插件免受其他不正确停止执行的插件的影响。

如果页面上另一个插件的最后一条语句或表达式没有以分号结束，而我们的插件又没有以分号开始，就可能导致脚本错误，从而阻止我们的插件正常工作。

我们使用一个匿名函数作为我们插件的包装器，并立即在函数体之后用一组额外的括号调用它。我们还可以通过在我们的插件中局部范围限定`$`字符并将`jQuery`对象传递给匿名函数作为参数，确保我们的插件与 jQuery 的`noConflict()`方法一起工作。

在匿名函数内部，我们首先定义一个称为`defaults`的对象字面量，该对象将用作我们插件的配置对象。该对象包含另一个称为`strings`的对象，其中我们存储了在各种元素中显示的所有不同文本部分。

为了使我们的插件易于本地化，我们使用配置对象来处理文本字符串，这样非英语母语的开发者就可以更容易地使用。尽可能使插件灵活是增加插件吸引力的一个好方法。

在`defaults`对象之后，我们定义了一个构造函数，该函数将生成我们的小部件的实例。插件称为 Up，我们将其名称的第一个字母大写，因为这是应该使用`new`关键字调用的函数的一般约定。

构造函数可以接受两个参数；第一个是一个 jQuery 元素或元素集合，第二个是由使用我们的插件的开发者定义的配置对象。

在构造函数内部，我们首先向实例附加一些成员。第一个成员叫做`config`，它将包含由 jQuery 的`extend()`方法返回的对象，该方法用于合并两个对象，与大多数 jQuery 方法不同，它是在`jQuery`对象本身上而不是 HTML 元素集合上调用的。

它接受四个参数；第一个参数指示`extend()`方法深复制要合并到 jQuery 对象中的对象，这是我们需要做的，因为`defaults`对象包含其他对象。

第二个参数是一个空对象；任何其他对象都将被合并在一起，并将它们自己的属性添加到此对象中。这是方法将返回的对象。如果我们没有传递一个空对象，那么方法中传递的第一个对象将被返回。

下面的两个参数是我们要合并的对象。这些是我们刚刚定义的`defaults`对象和在调用构造函数时可能传递的`opts`对象。

这意味着如果开发者希望传递一个配置对象，他们可以覆盖我们在`defaults`对象中定义的值。未使用此配置对象覆盖的属性将被设置为默认值。

我们还将对元素或元素集合的引用作为实例的成员存储，以便我们可以在代码的其他部分轻松操作这些元素。

最后，我们添加了一对空数组，用于存储要上传的文件列表和进行中的 XHR 请求。我们将在项目的后期看到这些属性如何使用，所以现在不用太担心它们。

jQuery 提供了`fn`对象作为其原型的快捷方式，这是我们如何用我们的插件方法扩展 jQuery 的。在这种情况下，该方法被称为`up()`，并且是我们在`uploader.html`底部使用`<script>`元素调用的方法。我们指定该方法可能接受一个参数，该参数是包含插件使用者可能想要提供的配置选项的对象。

在方法内部，我们首先使用`new`关键字与我们的构造函数结合创建了一个上传器的新实例。我们将构造函数传递给方法所调用的元素（或元素集合）和`options`对象。

最后我们从方法中返回了`this`。 在添加到 jQuery 原型的方法中，`this`对象指的是 jQuery 集合。非常重要的是，为了保持链接，返回调用方法的元素集合。

## 机密情报

链接是 jQuery 的一个固有特性，使用它的开发人员来期望。重要的是满足开发人员对他们使用的编程样式的期望。使用我们的插件的人们希望在调用我们的插件方法后能够添加额外的 jQuery 方法。

现在我们通过返回`this`对象返回元素集合，开发人员可以做这样的事情：

```js
$("#an-element").up().addClass("test");
```

所以这是一个简单的示例，但它应该说明为什么从插件中始终返回`this`是重要的。

# 生成底层标记

在这个任务中，我们将向我们的插件添加一个初始化方法，该方法将生成小部件所需的标记。

## 启动推进器

首先，我们应该直接在`uploader.js`中`Up()`构造函数之后添加以下代码：

```js
Up.prototype.init = function() {
    var widget = this,
          strings = widget.config.strings,
          container = $("<article/>", {
            "class": "up"
          }),
    heading = $("<header/>").appendTo(container),
    title = $("<h1/>", {
        text: strings.title
    }).appendTo(heading),
    drop = $("<div/>", {
        "class": "up-drop-target",
        html: $("<h2/>", {
            text: strings.dropText
        })
    }).appendTo(container),
    alt = $("<h3/>", {
        text: strings.altText
    }).appendTo(container),
    upload = $("<input/>", {
        type: "file"
    }).prop("multiple", true).appendTo(container),
    select = $("<a/>", {
        href: "#",
        "class": "button up-choose",
        text: strings.buttons.choose
    }).appendTo(container),
    selected = $("<div/>", {
        "class": "up-selected"
    }).appendTo(container),
    upload = $("<a/>", {
        href: "#",
        "class": "button up-upload",
        text: strings.buttons.upload
    }).appendTo(container);

    widget.el.append(container);

}
```

我们还需要调用这个新的`init()`方法。修改添加到 jQuery 的`fn`对象的方法，使其如下所示：

```js
$.fn.up = function(options) {
 new Up(this, options).init();
    return this;
};
```

我们还可以在插件生成的标记中添加 CSS。在`uploader.css`中，添加以下样式：

```js
article.up { width:90%; padding:5%; }
article.up input { display:none; }
.up-drop-target { 
    height:10em; border:5px dashed #ccc; border-radius:5px; 
    margin-bottom:1em; text-align:center; 
}
.up-drop-target h2 { 
    margin-top:-.5em; position:relative; top:50%; 
}
.up-selected { margin:1em 0; border-bottom:1px solid #ccc; }
```

## 完成目标 - 迷你总结

我们可以通过将其添加到构造函数的`prototype`中来添加一个`init()`方法，该方法负责创建和注入小部件所构建的标记。构造函数创建的所有对象都将继承该方法。

我们首先存储了`this`对象，该对象在我们的`init()`方法中仍然指的是元素的 jQuery 集合，以便我们可以在下一个任务中轻松地在事件处理程序中引用它。

我们还将`strings`属性本地化作用域，以使解析稍微更快，因为我们经常引用此属性以将可见的文本字符串添加到小部件的可见 UI 中。

接下来，我们创建新的 HTML 元素并将它们存储在变量中。这意味着我们可以创建容器并将所有所需元素附加到其中，而它仍然在内存中，并且然后将整个小部件一次性注入到页面的 DOM 中，而不是重复地修改 DOM 并逐个添加元素。

小部件的外部容器是一个 `<article>` 元素，它具有一个易于样式化的类名。HTML5 规范描述了 `<article>` 作为一个独立的交互式小部件，所以我觉得这是我们小部件的完美容器。虽然同样相关，但 `<article>` 并不局限于我们传统上描述的“文章” - 例如，博客/新闻文章或编辑样式的文章。

我们有一个 `<header>` 元素来包含小部件的主标题，在其中我们使用一个标准的 `<h1>`。我们还在小部件内部使用两个 `<h2>` 元素来显示不同的部分（拖放区域和更传统的文件 `<input>`）。

`<input>` 元素具有 `type` 属性为 `file`，并且还给定了 `multiple` 属性，使用 jQuery 的 `prop()` 方法，以便在支持的浏览器中上传多个文件。目前的 IE 版本（9 及以下）不支持此属性。

我们还在 `<input>` 之后直接添加了一个 `<a>` 元素，我们将用它来打开用于选择要上传的文件的打开对话框。标准的 `file` 类型 `<input>` 的问题在于没有标准！

几乎每个浏览器都以不同的方式实现 `file` 类型的 `<input>`，一些浏览器显示一个 `<input>` 以及一个 `<button>`，而一些浏览器只显示一个 `<button>` 和一些文本。还不可能对由控件生成的 `<input>` 或 `<button>` 进行样式设置，因为它们是 **shadow DOM** 的一部分。

### 注意

有关影子 DOM 的更多信息，请参见 [`glazkov.com/2011/01/14/what-the-heck-is-shadow-dom/`](http://glazkov.com/2011/01/14/what-the-heck-is-shadow-dom/)。

为了解决这些跨浏览器的差异，我们将用 CSS 隐藏 `<input>`，并使用 `<a>` 元素，样式化为一个吸引人的按钮，来打开对话框。

我们还添加了一个空的 `<div>` 元素，我们将用它来列出所选文件并显示每个文件的一些信息，然后是另一个 `<a>` 元素，它将被样式化为按钮。这个按钮将用于启动上传。

我们使用了标准的 jQuery 1.4+ 语法来创建新的 HTML 元素，并为大多数我们创建的元素提供了配置对象。大多数元素都给定了一个类名，有些还会获得文本或 HTML 内容。我们使用的类名都受到合理前缀的限制，以避免与页面上已使用的现有样式潜在冲突。

我们添加的 CSS 主要是用于呈现。重要的方面是我们隐藏了标准的文件 `<input>`，并且给了拖放目标一个固定大小，以便文件可以轻松地放置在上面。

此时，我们应该能够在浏览器中运行页面（通过 web 服务器），并查看插件的基本元素和布局。页面应该与该项目的第一个截图中的样子一样。

# 添加接收要上传文件的事件处理程序

我们可以使用我们在上一个任务中添加的 `init()` 方法来附加小部件将需要处理的文件被选择上传的事件处理程序。这可能发生在文件被拖放到拖放目标上，或者使用按钮选择它们时。

## 启动推进器

在`uploader.js`中的`init()`方法中向容器附加新的 HTML 元素之后（但仍在`init()`方法内部），添加以下代码：

```js
widget.el.on("click", "a.up-choose", function(e) {
    e.preventDefault();

    widget.el.find("input[type='file']").click();
});

widget.el.on("drop change dragover", "article.up", function(e) {

    if (e.type === "dragover") {
        e.preventDefault();
        e.stopPropagation();
        return false;
    } else if (e.type === "drop") {
        e.preventDefault();
        e.stopPropagation();
        widget.files = e.originalEvent.dataTransfer.files;
    } else {
        widget.files = widget.el
        .find("input[type='file']")[0]
        .files;
    }

    widget.handleFiles();
});
```

## 目标完成 - 迷你总结

我们首先使用 jQuery 的 `on()` 方法，在事件委托模式下，将事件处理程序附加到小部件的外部容器上。我们将 `click` 事件指定为第一个参数，并将匹配我们带有类名 `up-choose` 的按钮的选择器指定为第二个参数。

在传递给 `on()` 的处理程序函数内部，我们首先使用 JavaScript 的 `preventDefault()` 阻止浏览器的默认行为，然后触发一个用于选择要上传的文件的隐藏`<input>`元素的`click`事件。这将导致文件对话框在浏览器中打开，允许选择文件。

然后，我们附加了另一个事件处理程序。这次我们正在寻找`drop`、`dragover`或`change`事件。当文件被拖放到拖放区域时，将触发`drop`事件；当文件被悬停在拖放区域上时，将触发`dragover`事件；如果文件被移除，将触发`change`事件。

所有这些事件将从拖放区域（带有类名`up`的`<article>`）或隐藏的`<input>`中冒泡，并通过绑定事件处理程序的小部件的外部容器传递。

在这个处理程序函数内部，我们首先检查它是否是`dragover`事件；如果是，我们再次使用`preventDefault()`和`stopPropagation()`阻止浏览器的默认行为。我们还需要从条件的这个分支返回`false`。

`if`的下一个分支检查触发处理程序的事件是否是`drop`事件。如果是，我们仍然需要使用`preventDefault()`和`stopPropagation()`，但这次我们还可以使用 jQuery 创建和传递给处理程序函数的事件对象获取所选文件的列表，并将它们存储在小部件实例的属性中。

如果这两个条件都不为`true`，我们就从`<input>`元素中获取文件列表。

我们需要的属性是 jQuery 封装到自己的事件对象中的`originalEvent`对象的一部分。然后，我们可以从`dataTransfer`对象中获取`files`属性。如果事件是`change`事件，我们只需获取隐藏的`<input>`的`files`属性。

无论使用哪种方法，用于上传的文件集合都存储在小部件实例的 `files` 属性下。这只是一个临时属性，每次选择新文件时都会被覆盖，不像小部件的 `filelist` 数组，它将存储所有文件以进行上传。

最后我们调用 `handleFiles()` 方法。在下一个任务中，我们将把这个方法添加到小部件的 `prototype` 中，所以一旦完成了这个任务，我们就能在这里调用这个方法而不会遇到问题。

将两个事件组合起来，并以这种方式检测发生的事件要比附加到单独的事件处理程序要好得多。这意味着我们不需要两个分开的处理程序函数，它们都本质上做同样的事情，并且无论是用按钮和标准对话框选择文件，还是通过将文件拖放到拖放目标中选择文件，我们仍然可以获取文件列表。

此时，我们应该能够将文件拖放到拖放区域，或者点击按钮并使用对话框选择文件。然而，会抛出一个脚本错误，因为我们还没有添加我们插件的 `handleFiles()` 方法。

# 显示已选文件列表

在这个任务中，我们可以填充我们创建的 `<div>`，以显示已选择用于上传的文件列表。我们将构建一个表格，在表格中，每一行列出一个文件，包括文件名和类型等信息。

## 启动推进器

在 `uploader.js` 中的 `init()` 方法之后，添加以下代码：

```js
Up.prototype.handleFiles = function() {

    var widget = this,
          container = widget.el.find("div.up-selected"),
          row = $("<tr/>"),
          cell = $("<td/>"),
          remove = $("<a/>", {
             href: "#"
          }),
    table;

    if (!container.find("table").length) {
        table = $("<table/>");

        var header = row.clone().appendTo(table),
              strings = widget.config.strings.tableHeadings;

        $.each(strings, function(i, string) {
                var cs = string.toLowerCase().replace(/\s/g, "_"),
                      newCell = cell.clone()
                                            .addClass("up-table-head " + cs)
                                            .appendTo(header);

                if (i === strings.length - 1) {
                    var clear = remove.clone()
                                                 .text(string)
                                                .addClass("up-remove-all");

                    newCell.html(clear).attr("colspan", 2);
                } else {
                    newCell.text(string);
                }
            });
        } else {
            table = container.find("table");
        }

        $.each(widget.files, function(i, file) {
        var fileRow = row.clone(),
              filename = file.name.split("."),
              ext = filename[filename.length - 1],
              del = remove.clone()
                                   .text("x")
                                   .addClass("up-remove");

        cell.clone()
              .addClass("icon " + ext)
              .appendTo(fileRow);

        cell.clone()
              .text(file.name).appendTo(fileRow);
        cell.clone()
             .text((Math.round(file.size / 1024)) + " kb")
             .appendTo(fileRow);

        cell.clone()
              .html(del).appendTo(fileRow);
        cell.clone()
              .html("<div class='up-progress'/>")
              .appendTo(fileRow);

        fileRow.appendTo(table);

        widget.fileList.push(file);
    });

    if (!container.find("table").length) {
        table.appendTo(container);
    }
}
```

我们还可以为我们创建的新标记添加一些额外的 CSS。将以下代码添加到 `upload.css` 的底部：

```js
.up-selected table {
    width:100%; border-spacing:0; margin-bottom:1em;
}
.up-selected td {
    padding:1em 1% 1em 0; border-bottom:1px dashed #ccc;
    font-size:1.2em;
}
.up-selected td.type { width:60px; }
.up-selected td.name { width:45%; }
.up-selected td.size { width:25%; }
.up-selected td.remove_all_x { width:20%; }

.up-selected tr:last-child td { border-bottom:none; }
.up-selected a {
    font-weight:bold; text-decoration:none;
}
.up-table-head { font-weight:bold; }
.up-remove-all { color:#ff0000; }
.up-remove {
    display:block; width:17px; height:17px;
    border-radius:500px; text-align:center;
    color:#fff; background-color:#ff0000;
}
.icon { 
    background:url(../img/page_white.png) no-repeat 0 50%; 
}
.doc, .docx { 
    background:url(../img/doc.png) no-repeat 0 50%; 
}
.exe { background:url(../img/exe.png) no-repeat 0 50%; }
.html { background:url(../img/html.png) no-repeat 0 50%; }
.pdf { background:url(../img/pdf.png) no-repeat 0 50%; }
.png { background:url(../img/png.png) no-repeat 0 50%; }
.ppt, .pptx { 
    background:url(../img/pps.png) no-repeat 0 50%; 
}
.txt { background:url(../img/txt.png) no-repeat 0 50%; }
.zip { background:url(../img/zip.png) no-repeat 0 50%; }
```

## 目标完成 - 迷你总结

我们开始时将 `handleFiles()` 方法添加到小部件的 `prototype` 中，使得我们在上一个任务的最后添加的方法调用 `widget.handleFiles()` 起作用。它的添加方式与之前的 `init()` 方法完全相同，并且就像在 `init()` 内部一样，`this` 对象指向了小部件实例内部。这使得在页面上的元素、配置选项和选定文件列表都易于访问。

在方法内部，我们首先创建了一系列变量。就像在 `init()` 方法中一样，我们创建了一个名为 widget 的局部变量，用于存储 `this` 对象。虽然我们不会向这个方法添加任何事件处理程序，所以我们并不一定非要这样做，但我们确实多次访问对象，所以把它缓存在一个变量中是有道理的。

我们还使用 `widget.el` 缓存了选定的文件容器 - 不要忘记 `el` 已经引用了外部小部件容器的 jQuery 封装实例，所以我们可以直接在其上调用 jQuery 方法，如 `find()`，而无需重新封装它。

接下来，我们创建了一系列新的 DOM 元素，准备在循环内克隆它们。这是一种更好的创建元素的方法，特别是在循环内部，避免了不断创建新的 jQuery 对象。

我们还定义了一个名为`table`的变量，但我们并没有立即初始化它。相反，我们使用`if`条件来检查容器是否已经包含了一个`<table>`元素，通过检查 jQuery 的`find("table")`是否返回一个具有`length`的集合。

如果`length`等于`false`，我们知道没有选择任何`<table>`元素，因此我们使用 jQuery 创建了一个新的`<table>`元素，并将其赋给`table`变量。然后，我们为`<table>`创建了一个标题行，用于为新表的每一列添加标题。

此时，`<table>`元素只存在于内存中，因此我们可以将新行添加到其中，而不会修改页面的 DOM。我们还缓存了我们配置对象中使用的`strings`对象的`tableHeadings`属性的引用。

然后，我们使用 jQuery 的`each()`实用工具来创建用作表标题的所有`<td>`元素。除了能够在从页面选中的元素集合上调用`each()`之外，我们还可以调用`each()`在 jQuery 对象上，以便迭代一个纯 JavaScript 数组或对象。

`each()`方法接受要迭代的数组或对象。在这种情况下，它是一个数组，因此对数组中的每个项目调用的迭代函数接收到当前项目的索引和当前项目的值作为参数。

在迭代器内部，我们首先创建一个可以用作类名的新字符串。`class`这个词在 JavaScript 中是一个**保留字**，因此我们改用`cs`作为变量名。为了创建类名，我们只需使用 JavaScript 的`toLowerCase()`函数将当前字符串转换为小写，然后使用 JavaScript 的`replace()`函数删除任何空格。

### 注意

有关 JavaScript 中保留字的完整列表，请参阅 MDN 文档[`developer.mozilla.org/en-US/docs/JavaScript/Reference/Reserved_Words`](https://developer.mozilla.org/en-US/docs/JavaScript/Reference/Reserved_Words)。

`replace()`函数将正则表达式作为第一个参数匹配，将替换字符串作为第二个参数。我们可以使用字符串`" "`作为第一个参数，但那样只会删除第一个空格，而使用带有`g`标志的正则表达式允许我们移除所有空格。

然后，我们通过克隆在任务开始时创建并存储在变量中的元素之一来创建一个新的`<td>`元素。我们为了样式的目的给它一个通用的类名，以及我们刚刚创建的唯一类名，这样每一列都可以在需要时独立样式化，然后将它直接添加到我们刚刚创建的标题行中。

然后，我们通过检查当前索引是否等于数组长度减 1 来检查我们是否迭代了数组中的最后一项。如果是最后一项，我们通过克隆我们在任务开始时创建和缓存的`<a>`元素来添加一个清除所有链接。

我们将新`<td>`元素的文本设置为当前数组项的值，并添加`up-remove-all`类以进行样式设置，以便我们可以过滤由它分发的事件。我们还可以使用 jQuery 的`attr()`方法将`colspan`属性设置为`2`到这个`<td>`。然后，新的`<a>`元素被添加为新的`<td>`元素的 HTML 内容。

如果它不是数组中的最后一个项目，我们只需将新`<td>`元素的文本内容设置为当前数组项的值。

所有这些都是在外部`if`语句的第一个分支中完成的，当表不存在时发生。如果容器已经包含`<table>`元素，我们仍然通过选择页面上的`<table>`来初始化表变量。

不要忘记，我们所在的`handleFiles()`方法将在选择文件后被调用，所以现在我们需要为每个选择的文件在表中构建一行新行。

再次使用 jQuery 的`each()`方法，这次是为了迭代小部件的`files`属性中存储的文件集合。对于每个选择的文件（通过拖放到拖放区域或使用按钮），我们首先通过克隆我们的`row`变量创建一个新的`<tr>`。

然后，我们在当前文件的`name`属性上使用`.`字符进行分割。通过获取`split()`函数创建的数组中的最后一个项目，我们存储文件的扩展名。

在这一点上，我们还创建一个删除链接，可以用来从要上传的文件列表中删除单个文件，方法是克隆我们在任务开始时创建的`<a>`元素。它被赋予文本`x`和类名`up-remove`。

接下来，我们通过再次克隆缓存的`cell`变量中的`<td>`来创建一系列新的`<td>`元素。第一个`<td>`被赋予一个通用的类名`icon`，以及当前文件的扩展名，这样我们就可以为可以上传的不同文件类型添加图标，并将其附加到新行上。

第二个`<td>`元素显示文件的名称。第三个`<td>`元素显示文件的大小（以千字节为单位）。如果我们知道可能上传大文件，我们可以转换为兆字节，但对于这个项目的目的，千字节就足够了。

第四个`<td>`元素使用 jQuery 的`html()`方法添加了新的删除链接，最后一个`<td>`元素添加了一个空的`<div>`元素，我们将使用它来放置 jQuery UI 进度条小部件。

一旦新单元格被创建并附加到新行上，新行本身就被附加到表中。我们还可以将当前文件添加到我们的`fileList`数组中，准备上传。

最后，我们需要再次检查所选文件容器是否已经包含一个`<table>`元素。如果没有，我们将新建的`<table>`追加到容器中。如果它已经包含`<table>`，新行将已经添加到其中。

我们在这一部分添加的 CSS 纯粹是为了呈现。我做的一件事是添加一些类，以便显示可能选择上传的不同文件类型的图标。我只是添加了一些作为示例；您实际需要的会取决于您期望用户上传的文件类型。还为与我们添加的选择器不匹配的类型创建了通用图标。

### 注意

此示例中使用的图标属于 Farm Fresh 图标包。我已经为了简洁性而重命名了这些文件，并且可以在本书附带的代码下载中找到。这些图标可以在 Fat Cow 网络主机上获得 ([`www.fatcow.com/free-icons`](http://www.fatcow.com/free-icons))。

在这一点上，我们应该能够在浏览器中运行页面，选择一些文件进行上传，并看到我们刚刚创建的新`<table>`：

![完成目标 - 小型总结](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_05_02.jpg)

## 机密情报

在这个例子中，我们手动创建了显示所选文件列表所需的元素。另一种方法是使用模板引擎，比如 jsRender 或 Dust.js。这样做的好处是比我们手动创建更快更高效，能够使我们的插件代码更简单更简洁，文件也更小。

当然，这将给我们的插件增加另一个依赖，因为我们需要包含模板引擎本身，以及一个存储在 JavaScript 文件中的预编译模板。在这个例子中，我们并没有创建太多元素，所以可能不值得再添加另一个依赖。当需要创建许多元素时，添加依赖的成本被它增加的效率所抵消。

写 jQuery 插件时，这种事情需要根据具体情况逐案考虑。

# 从上传列表中移除文件

在这个任务中，我们将添加事件处理程序，使新文件列表中的**删除**和**全部删除**链接起作用。我们可以将事件处理程序附加到我们之前添加其他事件处理程序的地方，以保持事情的井然有序。

## 启动推进器

在`upload.js`中，在小部件的`init()`方法中，并且直接在现有的 jQuery `on()`方法调用之后，添加以下新代码：

```js
widget.el.on("click", "td a", function(e) {

    var removeAll = function() {
        widget.el.find("table").remove();
        widget.el.find("input[type='file']").val("");
        widget.fileList = [];
    }

    if (e.originalEvent.target.className == "up-remove-all") {
        removeAll();
    } else {
        var link = $(this),
              removed,
              filename = link.closest("tr")
                                     .children()
                                     .eq(1)
                                     .text();

        link.closest("tr").remove();

        $.each(widget.fileList, function(i, item) {
        if (item.name === filename) {
            removed = i;
        }
    });
    widget.fileList.splice(removed, 1);

    if (widget.el.find("tr").length === 1) {
        removeAll();
    } 
  }
}); 
```

## 完成目标 - 小型总结

我们使用 jQuery 的`on()`方法再次添加了一个`click`事件。我们将它附加到小部件的外部容器，就像我们添加其他事件一样，这次我们根据选择器`td a`过滤事件，因为事件只会源自`<td>`元素内的`<a>`元素。

在事件处理程序内，我们首先阻止浏览器的默认行为，因为我们不希望跟随链接。然后，我们定义了一个简单的帮助函数，从小部件中移除`<table>`元素，清除文件`<input>`的值，并清除`fileList`数组。

我们需要清除`<input>`，否则如果我们选择了一些文件，然后将它们从文件列表中移除，我们将无法重新选择相同的一组文件。这是一个边缘情况，但这个简单的小技巧可以让它起作用，所以我们也可以包含它。

接下来，我们检查触发事件的元素的`className`属性是什么。我们可以使用传递给处理程序函数的 jQuery 事件对象中包含的`originalEvent`对象的`target`属性来查看此属性。我们还可以使用 jQuery 事件对象的`srcElement`属性，但这在当前版本的 Firefox 中不起作用。

当`className`属性匹配`up-remove-all`时，我们简单地调用我们的`removeAll()`辅助函数来移除`<table>`元素并清除`<input>`和`fileList`数组。

如果`className`属性与**全部移除**链接不匹配，我们必须仅移除包含被点击的`<a>`的`<table>`元素的行。我们首先缓存触发事件的`<a>`的引用，这在处理程序函数内部被设置为`this`。

我们还定义了一个名为`removed`的变量，我们将很快初始化一个值。最后，我们存储了我们将要移除的行所代表的文件的`filename`。

一旦我们设置了变量，我们首先要做的是移除我们可以使用 jQuery 的`closest()`方法找到的行，该方法找到与传递给该方法的选择器匹配的第一个父元素。

然后我们使用 jQuery 的`each()`方法来迭代`fileList`数组。对于数组中的每个项目，我们将项目的`name`属性与我们刚初始化的`filename`变量进行比较。如果两者匹配，我们将`index`号（由 jQuery 自动传递给迭代器函数）设置为我们的`removed`变量。

一旦`each()`方法完成，我们就可以使用 JavaScript 的`splice()`函数来移除当前`<tr>`所代表的文件。`splice()`函数接受两个参数（它可以接受更多，但我们这里不需要），第一个参数是要开始移除的项目的索引，第二个参数是要移除的项目数。

最后，我们检查`<table>`元素是否还有多于一行的行。如果只剩下一行，这将是标题行，所以我们知道所有文件都已删除。因此，我们可以调用我们的`removeAll()`辅助函数来整理并重置一切。

现在当我们已经将文件添加到上传列表中时，我们应该能够使用内联**x**按钮逐个删除文件，或者使用**全部移除**链接清除列表。

# 添加一个 jQuery UI 进度指示器

在这个任务中，我们将添加 jQuery UI 进度条小部件所需的元素和初始化代码。小部件实际上还不会执行任何操作，因为在下一个任务中我们不会上传任何东西，但我们需要连接好一切准备就绪。

## 启动推进器

我们将向小部件的原型添加一个`initProgress()`方法，用于选择我们添加到`<table>`元素中的`<div>`元素，并将它们转换为进度条小部件。我们还可以添加用于更新进度条的方法。

在`handleFiles()`方法之后，直接添加以下代码：

```js
Up.prototype.initProgress = function() {

    this.el.find("div.up-progress").each(function() {
        var el = $(this);

        if (!el.hasClass("ui-progressbar")) {
            el.progressbar();
        }
    });
}
```

接下来，我们需要在向`<table>`添加新行后调用此方法。在`handleFiles()`方法的末尾直接添加以下调用：

```js
widget.initProgress();
```

现在我们可以添加更新进度条的代码了。在我们刚刚添加的`initProgress()`方法后面直接添加以下代码：

```js
Up.prototype.handleProgress = function(e, progress) {

    var complete = Math.round((e.loaded / e.total) * 100);

    progress.progressbar("value", complete);
}
```

我们还需要为新的进度条添加一点 CSS。将以下代码添加到`uploader.css`的末尾：

```js
.up-progress { 
    height:1em; width:100px; position:relative; top:4px; 
}
```

## 目标完成 - 迷你总结

这个任务比我们到目前为止在项目中涵盖的一些任务更短，但同样重要。我们添加了新方法的方式与为插件添加大部分功能的方式相同。

在这个方法中，我们首先选择所有类名为`up-progress`的`<div>`元素。不要忘记我们可以使用`this.el`访问小部件的容器元素，并且作为 jQuery 对象，我们可以在其上调用 jQuery 方法，比如`find()`。

然后，我们使用 jQuery 的`each()`方法遍历选择中的每个元素。在此任务中，我们使用标准的`each()`方法，其中集合中的当前元素在迭代函数中设置为`this`。

在迭代函数中，我们首先缓存当前元素。然后我们检查它是否具有 jQuery UI 类名`ui-progressbar`，如果没有，我们将使用 jQuery UI 方法`progressbar()`将元素转换为进度条。

这样做意味着无论是选择要上传的初始文件集，还是将其他文件添加到现有的`<table>`中，进度条都将始终被创建。

在`handleFiles()`方法末尾，我们还添加了对新的`initProgress()`方法的调用，每当选择新文件上传时都会调用该方法。

接下来，我们添加了`handleProgress()`方法，我们将在下一个任务中将其绑定到一个事件。该方法将传递两个参数，第一个是事件对象，第二个是一个已包装的 jQuery 对象，表示一个单独的进度条。

在方法中，我们首先计算已上传文件的比例。我们可以通过将事件对象的`loaded`属性除以`total`属性得出，然后除以 100 得出迄今为止已上传文件的百分比。

`loaded`和`total`属性是特殊属性，当浏览器触发进度事件时会将它们添加到事件对象中。

一旦我们有了百分比，我们就可以调用进度条小部件的`value`方法，以便将值设置为百分比。这是一个 jQuery UI 方法，因此以特殊的方式调用。我们不直接调用`value()`，而是调用`progressbar()`方法，并将要调用的方法的名称`value`作为第一个参数传递。所有 jQuery UI 方法都是以这种方式调用的。

最后，我们添加了一些漂亮的 CSS 样式，以微调默认的 jQuery UI 主题提供的默认样式。现在，当我们添加要上传的文件时，我们应该在`<table>`中的每个文件后看到一个空的进度条。

# 正在上传所选文件

现在，我们有了附加到我们插件实例的文件列表，准备好上传。在这个任务中，我们将做到这一点，并使用 jQuery 异步上传文件。此行为将与我们添加到插件生成的标记中的**上传文件**按钮相关联。

我们还可以使用此任务来更新我们的进度条，显示每个正在上传的文件的当前进度。

## 启动推进器

由于这是另一个事件处理程序，我们将在`init()`方法中添加它，以及所有其他事件处理程序，以便它们都保持在一个地方。在现有的事件处理程序之后，在`init()`方法的末尾添加以下代码：

```js
widget.el.on("click", "a.up-upload", function(e) {
    e.preventDefault();

  widget.uploadFiles();
}); 
```

接下来，添加新的`uploadFiles()`方法。这可以在我们在上一个任务中添加的与进度相关的方法之后进行：

```js
Up.prototype.uploadFiles = function() {
    var widget = this,
    a = widget.el.find("a.up-upload");

    if (!a.hasClass("disabled")) {

        a.addClass("disabled");

        $.each(widget.fileList, function(i, file) {
            var fd = new FormData(),
                  prog = widget.el
                                        .find("div.up-progress")
                                        .eq(i);

            fd.append("file-" + i, file);

            widget.allXHR.push($.ajax({
                type: "POST",
                url: "/upload.asmx/uploadFile",
                data: fd,
                contentType: false,
                processData: false,
                xhr: function() {

                    var xhr = jQuery.ajaxSettings.xhr();

                    if (xhr.upload) {
                        xhr.upload.onprogress = function(e) {
                            widget.handleProgress(e, prog);
                        }
                    }

                    return xhr;
                }
            }));
        });     
    }
}
```

## 完成目标 - 迷你总结

在我们的`uploadFiles()`方法中，我们首先存储对小部件的引用，就像我们在添加的其他一些方法中所做的那样。我们还存储对**上传文件**按钮的引用。

接下来要做的是检查按钮是否没有`disabled`类名。如果它确实具有此类名，这意味着已为所选文件启动了上传，因此我们希望避免重复请求。如果按钮没有`disabled`类，则意味着这是第一次单击按钮。因此，为了防止重复请求，我们随后添加`disabled`类。

接下来，我们遍历我们收集到的文件列表，该列表存储在小部件实例的`fileList`属性中。对于数组中的每个文件，我们首先创建一个新的`FormData`对象。

`FormData`是新的 XMLHttpRequest (XHR) level 2 规范的一部分，它允许我们动态创建一个`<form>`元素，并使用 XHR 异步提交该表单。

一旦我们创建了一个新的`FormData`对象，我们还会存储与当前文件关联的进度条小部件的引用。然后，我们使用`FormData`的`append()`方法将当前文件附加到新的`FormData`对象中，以便将文件编码并发送到服务器。

接下来，我们使用 jQuery 的`ajax()`方法将当前的`FormData`对象发布到服务器。`ajax()`方法将返回请求的`jqXHR`对象。这是 jQuery 增强了额外方法和属性的 XHR 对象的特殊版本。我们需要存储这个`jqXHR`对象，以便稍后使用。

我们将在下一个任务中详细介绍它的使用方式，但现在只需了解`ajax()`方法返回的`jqXHR`对象被推送到我们在项目开始时存储为小部件实例成员的`allXHR`数组中即可。

`ajax()`方法接受一个配置对象作为参数，允许我们控制请求的方式。我们使用`type`选项将请求设置为`POST`，并使用`url`选项指定要发布到的 URL。我们使用 data 选项将`FormData`对象添加为请求的有效载荷，并将`contentType`和`processData`选项设置为`false`。

如果我们不将`contentType`选项设置为`false`，jQuery 将尝试猜测应该使用哪种内容类型进行请求，这可能正确也可能不正确，这意味着一些上传将正常工作，而另一些上传将失败，看起来毫无明显原因。请求的`content-type`将默认设置为`multipart/form-data`，因为我们使用的是附加有文件的`FormData`。

将`processData`选项设置为`false`将确保 jQuery 不会尝试将文件转换为 URL 编码的查询字符串。

我们需要修改用于发出请求的基础 XHR 对象，以便我们可以将处理程序函数附加到进度事件上。在请求发出之前，必须将处理程序绑定到事件上，目前唯一的方法是使用`xhr`选项。

该选项接受一个回调函数，我们可以使用它来修改原始的 XHR 对象，然后返回给请求。在回调函数中，我们首先存储原始的 XHR 对象，可以从 jQuery 的`ajaxSettings`对象中获取它。

然后，我们检查对象是否具有`upload`属性，如果有，我们将匿名函数设置为`onprogress`的值。在此函数中，我们只需调用我们在上一个任务中添加的小部件的`handleProgress()`方法，将进度事件对象和我们在本任务开始处存储的 Progressbar 小部件传递给它。

# 报告成功并整理

在此任务中，我们需要显示每个文件何时完成上传。我们还需要清除小部件中的`<table>`，并在所有上传完成后重新启用上传按钮。

## 启动推进器

我们可以使用 jQuery 的`done()`方法显示每个单独文件上传完成的时间，我们可以在上一个任务中添加的`ajax()`方法之后链接此方法：

```js
.done(function() {

    var parent = prog.parent(),
    prev = parent.prev();

    prev.add(parent).empty();
    prev.text("File uploaded!");
});
```

为了在上传后进行整理，我们可以利用 jQuery 的`when()`方法。我们应该在`uploadFiles()`方法中的`each()`方法之后直接添加以下代码：

```js
$.when.apply($, widget.allXHR).done(function() {
    widget.el.find("table").remove();
    widget.el.find("a.up-upload").removeClass("disabled");
});
```

## 目标完成 - 迷你总结

因为 jQuery 的 `ajax()` 方法返回一个 `jqXHR` 对象，而且因为这个对象是一个称为**promise 对象**的特殊对象，我们可以在其上调用某些 jQuery 方法。`done()` 方法用于在请求成功完成时执行代码。

### 注意

你可能更习惯于使用 jQuery 的 `success()` 方法来处理成功的 AJAX 请求，或者 `error()` 或 `complete()` 方法。这些方法在版本 1.9 中已从库中移除，因此我们应该使用它们的替代品 `done()`、`fail()` 和 `always()`。

在这个函数中，我们只需要移除清除按钮和刚刚完成上传的文件的进度条小部件。我们可以通过从当前进度条小部件导航到它们来轻松找到需要移除的元素。

我们在上一个任务中存储了每个单独的进度条的引用，并且因为 `done()` 方法链接到了 `ajax()` 方法，所以在请求完成后仍然可以使用这个变量访问这个元素。

注意，在 `done()` 方法的末尾似乎有一个额外的闭合括号。这是因为它仍然位于我们在先前任务中添加的 `push()` 方法内部。关键是 `done()` 方法被添加到正确的位置——它必须链接到 `push()` 方法内部的 `ajax()` 方法。

一旦这些元素被移除，我们添加一个简单的消息，表示文件已完成上传。

一旦所有请求都完成，我们还需要从页面中移除 `<table>` 元素。这就是我们在上一个任务中上传文件时存储了所有生成的 `jqXHR` 对象的原因。我们可以使用 jQuery 的 `when()` 方法来做到这一点。

`when()` 方法可以接受一系列 promise 对象，并在它们全部解决时返回。然而，这个方法不接受数组，这就是为什么我们使用 JavaScript 的 `apply()` 方法调用它，而不是正常调用它。

我们可以再次使用 `done()` 方法来添加一个回调函数，一旦 `when()` 方法返回，就会调用该回调函数。在这个回调中，我们所做的就是移除显示已上传文件的 `<table>` 元素，并通过移除 `disabled` 类重新启用上传按钮。

这就是我们实际上需要做的，上传所选文件并分别接收每个文件的进度反馈，如下面的截图所示：

![目标完成 - 迷你简报](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_05_03.jpg)

### 提示

**查看示例文件**

要查看此项目的运行情况，您需要使用 Web 服务器查看我们创建的页面（在您自己的计算机上使用 `http://localhost`）。如果您在资源管理器或查找器中双击打开文件，它将无法正常工作。

# 任务完成

我们已经完成了项目。在这一点上，我们应该有一个易于使用并在支持的浏览器中提供丰富功能的上传插件，例如多个文件、文件信息、可编辑的上传列表和上传进度报告。

### 提示

并非所有浏览器都能使用此小部件旨在利用的功能。例如，Opera 浏览器认为通过程序触发文件对话框存在安全风险，因此不允许它。

此外，Internet Explorer 的旧版本（任何版本 10 之前的版本）根本无法处理此代码。

支持不兼容或遗留浏览器超出了此示例的范围，但添加一个备用方案是相对直接的，可以利用其他技术，比如 Flash，以支持我们的插件所展示的部分行为。

或者有一系列旧的 jQuery 插件，利用 `<iframe>` 元素来模拟通过 AJAX 上传文件。我选择关注支持的浏览器可以做什么，而不是专注于不支持的功能。

# 你准备好大干一场了吗？挑战高手

通过逐个上传文件，我们能够添加一个事件处理程序来监视正在上传的文件的进度。这也打开了取消上传单个文件的可能性。

对于这个挑战，为什么不试试看能否添加一个取消上传文件的机制。我们已经有了用于在上传之前删除文件的移除按钮。这些按钮可以很容易地更新，以便在上传进行中取消上传。

可以像附加进度事件处理程序一样向 XHR 对象添加取消事件的处理程序，因此这应该很容易实现。


# 第六章：使用 jQuery 扩展 Chrome

为 Chrome（或任何可以通过插件和扩展进行扩展的其他浏览器）构建一个扩展是创建自定义行为或附加工具以增强我们的浏览体验的简单方法。

Chrome 允许我们利用我们的 Web 开发技能扩展其浏览器界面，使用我们已经熟悉的技术，如 HTML、CSS 和 JavaScript，以及您可以使用 JavaScript 的地方通常也可以使用 jQuery。

# 任务简报

在这个项目中，我们将构建一个 Chrome 扩展，突出显示页面上用`Schema.org` **微数据**标记的元素。微数据是一种用于指定有关各种不同实体（如企业、位置或人员）的描述性信息的方式，使用标准 HTML 属性，并据传言将成为 Google 排名算法中的重要因素。

每当我们访问包含联系方式描述的页面时，我们可以从页面中获取它们并将其存储在我们的扩展中，这样我们就可以逐渐建立起一个人们使用或制作我们喜爱的东西的联系信息目录。

在这个项目中，我们还可以使用模板化使创建重复的元素组更加高效，以及更易于维护。我们在上一个项目中使用了 JsRender，所以我们可以再次使用它，但这次我们需要以稍微不同的方式使用它。完成后，我们的扩展将类似于以下截图所示：

![任务简报](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_06_01.jpg)

## 为什么很棒？

微数据用于描述网页中包含的信息，以促进搜索引擎蜘蛛和 HTML 文档之间的更好互操作性。

当页面上的不同元素被描述为公司、人员、产品或电影时，它允许诸如搜索引擎之类的东西更好地理解页面上包含的信息。

微数据在 Web 上迅速变得更加普遍，并且在 Google 为搜索结果生成的结果中扮演着越来越重要的角色，因此现在是利用它的绝佳时机。

## 你的热门目标

这个项目分解成的任务如下：

+   设置基本扩展结构

+   添加一个清单并安装扩展

+   添加一个沙箱 JsRender 模板

+   将消息发布到沙盒

+   添加内容脚本

+   为微数据抓取页面

+   添加保存微数据的机制

# 设置基本扩展结构

在这个任务中，我们将创建扩展所需的基础文件。扩展使用的所有文件都需要位于同一个目录中，因此我们将设置它并确保它包含我们需要的所有文件。

## 为起飞做准备

有一件事我应该指出，尽管希望你已经意识到 - 在该项目期间，我们将需要 Chrome 浏览器。如果你尚未安装它，作为一个网页开发人员，你真的应该安装它，至少是为了测试目的，立即下载并安装。

### 注意

Chrome 的最新版本可以从[`www.google.com/intl/en/chrome/browser/`](https://www.google.com/intl/en/chrome/browser/)下载。

我们将把这个项目的所有文件保存在一个单独的目录中，所以现在在项目文件夹中建立一个目录，命名为`chrome-extension`。扩展将从与大多数其他项目使用的基本代码文件构建; 唯一的区别是所有文件都需要是扩展本地的。

我们需要一个 JsRender 的副本，所以我们也应该下载一个副本，并将其放在`chrome-extension`目录中。上次我们使用 JsRender 时我们链接到了在线托管的版本。这次我们将下载它。

### 注意

JsRender 的最新版本可以从[`github.com/BorisMoore/jsrender/`](https://github.com/BorisMoore/jsrender/)下载。

我们可以使用用于启动其他项目的模板文件，但是我们应该确保指向 jQuery、JavaScript 文件和样式表的路径都指向同一个目录中的文件。Chrome 扩展使用的所有文件都必须在同一个文件夹中，这就是为什么我们下载脚本而不是链接到在线版本。

我们应该将 jQuery、JsRender 和`common.css`样式表的副本放入新目录中。我们还需要创建一个名为`popup.js`的新 JavaScript 文件和一个名为`popup.css`的新样式表，并将这些文件也保存到新目录中。

最后，我们可以创建一个名为`popup.html`的新 HTML 页面。这个文件也应该保存在`chrome-extension`目录中，并且应该包含以下代码：

```js
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="utf-8" />
        <title>jQuery-Powered Chrome Extension</title>
        <link rel="stylesheet" href="common.css" />
        <link rel="stylesheet" href="popup.css" />
    </head>
    <body>
        <script src="img/jquery-1.8.0.min.js"></script>
        <script src="img/jsrender.js"></script>
        <script src="img/popup.js"></script>
    </body>
</html>
```

## 启动推进器

我们刚刚创建的 HTML 文件将被用作扩展的弹出窗口。这是当单击工具栏中扩展图标时显示为弹出窗口的页面。在这个项目中，我们将创建一种称为**浏览器操作**的扩展类型，它会自动向 Chrome 的工具栏添加一个按钮，用于打开弹出窗口。

弹出窗口将显示一个按钮，用于触发对当前页面的微数据进行扫描，并显示任何先前保存的联系人。任何先前存储的联系人都将使用 localStorage API 检索，并且我们可以使用模板来渲染它们。

首先，我们可以向页面添加一般的标记; 在`popup.html`中，将以下代码添加到页面的`<body>`中：

```js
<section role="main">
    <header>
        <h1>Web Contacts</h1>
    </header>
    <ul id="contacts"></ul>
</section>
<iframe id="poster" src="img/template.html"></iframe>
```

我们还可以为这些元素添加一些基本样式。在 `popup.css` 中，添加以下代码：

```js
body { width:32em; padding:0 2em; }
header { padding-top:2em; }
ul { padding:0 0 1em; font-size:1.5em; }
iframe { display:none; }
```

## 目标完成 - 小结

Chrome 扩展使用与我们习惯使用的相同文件构建 - HTML、CSS 和 JavaScript。该扩展将在工具栏中添加一个按钮，当单击此按钮时，将显示一个弹出窗口。我们在此任务中添加的 HTML 页面是此弹出窗口的基础。

我们创建页面的方式与创建任何其他标准 HTML5 页面的方式相同。我们像往常一样链接到 CSS 和 JavaScript 文件，然后添加一个小的`<section>`容器，它将用作任何先前保存的联系人的容器。最初不会有任何联系人，当有联系人时，我们将使用模板来呈现它们。

我们已经添加了一个包含`<h1>`的`<header>`，为保存的联系人添加了一个标题，并添加了一个空的`<ul>`元素，我们将很快用脚本填充它。

最后，我们在页面中添加了一个`<iframe>`，它将被隐藏。稍后我们将使用这个来与扩展的另一部分通信。元素的`src`属性设置为我们想要发送消息的页面。

我们添加的 CSS 纯粹是为了演示，并仅以简单的布局放置了初始元素。我们还链接到每个其他项目都使用的公共 CSS 文件，但不要忘记，扩展使用的所有文件都必须在扩展的目录中。

## 机密情报

因为我们正在创建浏览器操作，所以我们将在 Chrome 的工具栏中添加一个新按钮，只要加载了未打包的扩展，它就可见。默认情况下，它将具有标准扩展图标 - 一个拼图块，但我们可以用我们自己创建的图标替换它。

我们还可以创建其他类型的扩展，这些扩展不会将按钮添加到工具栏。我们可以创建页面操作而不是浏览器操作，该操作将在地址栏中添加一个图标而不是工具栏。

该图标是否在所有页面上可见取决于扩展的行为方式。例如，如果我们想要在每次页面在浏览器中加载时运行我们的扩展，但只在页面上找到`Schema.org`微数据时显示图标，我们可以使用页面操作。

浏览器操作，例如我们将在此创建的操作，在查看的页面不受影响时始终可访问。我们使用浏览器操作而不是页面操作，因为我们扩展的用户可能希望能够查看他们以前发现并保存的联系人，因此浏览器操作非常适合通过扩展存储的任何数据。

# 添加清单并安装扩展

为了实际安装我们的扩展并看到我们迄今为止的劳动成果，我们需要创建一个清单文件。这个特殊的文件以 JSON 格式保存，控制扩展的某些方面，例如它使用的页面以及它可以运行的内容脚本。

## 准备起飞

在新文件中添加以下代码：

```js
{
    "name": "Web Contacts",
    "version": "1.0",
    "manifest_version": 2,
    "description": "Scrape web pages for Schema.org micro-data",
    "browser_action": {
        "default_popup": "popup.html"
    }
}
```

将此文件保存在我们在任务开始时在主项目目录中创建的`chrome-extension`目录中，文件名为`manifest.json`。

### 注意

如果您使用的文本编辑器在**另存为类型：**（或相似）下没有显示**.json**，请选择**所有类型 (*)**选项，并在**文件名：**输入字段中键入完整的文件名`manifest.json`。

## 启动推进器

要查看当前的扩展程序，需要将其加载到 Chrome 中作为扩展程序。为此，您应该转到**设置** | **工具** | **扩展程序**。

### 注意

在最近的 Chrome 版本中，通过点击具有三条杠图标的按钮（位于浏览器窗口右上角）来访问**设置**菜单。

当扩展程序页面加载时，应该会有一个按钮来**加载未打包的扩展程序…**。如果没有，请选中**开发者模式**复选框，然后该按钮将出现。

点击按钮，然后选择`chrome-extension`文件夹作为扩展目录。这样应该会安装扩展程序，并为我们添加浏览器操作按钮到工具栏。

## 目标完成 - 迷你总结

在扩展程序加载到浏览器之前，需要一个简单的清单文件。当前版本的 Chrome 仅允许至少为 Version 2 的清单。扩展程序必须具有清单，否则将无法运行。这是一个简单的文本文件，以 JSON 格式编写，用于向浏览器提供有关扩展程序的一些基本信息，例如名称、作者和当前版本。

我们可以指定我们的扩展程序是一个浏览器操作，它将一个按钮添加到 Chrome 的工具栏上。我们还可以使用清单指定在弹出窗口中显示的页面。

单击我们扩展的新按钮时，将会在扩展程序弹出窗口中显示我们在上一个任务中添加的 HTML 页面（`popup.html`），如下面的屏幕截图所示：

![目标完成 - 迷你总结](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-htst/img/9106OS_06_02.jpg)

# 添加一个沙盒化的 JsRender 模板

在这个任务中，我们可以添加 JsRender 将用于显示已保存联系人的模板。此时，我们还没有保存任何联系人，但我们仍然可以准备好它，并且当我们有了一些联系人时，它们将被渲染到弹出窗口中，而无需任何麻烦。

## 准备起飞

Chrome 使用**内容安全策略**（**CSP**）来防止大量常见的**跨站脚本**（**XSS**）攻击，因此我们不允许执行使用`eval()`或`new Function()`的任何脚本。

像许多其他流行库和框架一样，JsRender 模板库在编译模板时使用`new Function()`，因此不允许直接在扩展程序内部运行。我们可以通过两种方式解决这个问题：

+   我们可以转换到一个提供模板预编译的模板库，比如流行的 `Dust.js`。然后我们可以在浏览器外部编译我们的模板，并在扩展内部链接到包含模板编译成的函数的 JavaScript 文件。使用 `new Function()` 创建的函数甚至在扩展安装之前就已经被创建了，然后模板可以在扩展内部呈现，并与扩展内部提供的任何数据插值。

+   或者，Chrome 的扩展系统允许我们在指定的沙盒内部使用某些文件。由于代码与浏览器中的扩展数据和 API 访问隔离，因此允许在沙盒中运行不安全的字符串到函数特性，例如 `eval()` 或 `new Function()`。

在这个示例中，我们将使用沙盒功能，以便我们可以继续使用 JsRender。

## 启动推进器

首先，我们必须设置沙盒，这是通过使用我们之前创建的清单文件指定要沙盒化的页面来完成的。将以下代码直接添加到 `manifest.json` 中，直接在最终闭合大括号之前：

```js
"sandbox": {
    "pages": ["template.html"]
}
```

### 提示

不要忘记在 `browser_action` 属性的最终闭合大括号之后直接添加逗号。

我们已将 `template.html` 指定为沙盒页面。创建一个名为 `template.html` 的新文件，并将其保存在 `chrome-extension` 目录中。它应包含以下代码：

```js
<!DOCTYPE html>

<html lang="en">
    <head>
        <meta charset="utf-8" />
        <script id="contactTemplate" type="text/x-jsrender">
            {{for contacts}}
                <li>
                    <article>
                        <div class="details">
                            <h1>{{:name}}</h1>
                            {{if url}}
                                <span>website: {{url}}</span>
                            {{/if}}
                            {{if jobTitle}}
                                <h2>{{:jobTitle}}</h2>
                            {{/if}}
                            {{if companyName}}
                                <span class="company">
                                    {{:companyName}}
                                </span>
                            {{/if}}
                            {{if address}}
                                <p>{{:address}}</p>
                            {{/if}}
                            {{if contactMethods}}
                                <dl>
                                    {{for ~getMembers(contactMethods)}}
                                        <dd>{{:key}}</dd>
                                        <dt>{{:val}}</dt>
                                    {{/for}}
                                </dl>
                           {{/if}}
                        </div>
                    </article>
                </li>
            {{/for}}
        </script>
        <script src="img/jquery-1.9.0.min.js"></script>
        <script src="img/jsrender.js"></script>
        <script src="img/template.js"></script>
    </head>
</html>
```

模板页面还引用了 `template.js` 脚本文件。我们应该在 `chrome-extension` 目录中创建此文件，并将以下代码添加到其中：

```js
(function () {
    $.views.helpers({
        getMembers: function (obj) {
            var prop,
                 arr = [];

            for (prop in obj) {
                if (obj.hasOwnProperty(prop)) {
                    var newObj = {
                        key: prop,
                        val: obj[prop]
                     }

                    arr.push(newObj);
                }
            }

            return arr;
        }
    });
} ());
```

## 完成目标 - 迷你总结

我们首先向扩展添加了一个新的 HTML 页面。名为 `template.html` 的页面类似于常规网页，只是没有 `<body>`，只有一个 `<head>`，它链接到一些 JavaScript 资源，并包含我们将使用的模板的 `<script>` 元素。

### 提示

通常在 Chrome 扩展中，CSP 阻止我们运行任何内联脚本 - 所有脚本都应驻留在外部文件中。在 `<script>` 元素上使用非标准的 `type` 属性允许我们规避这一点，以便我们可以将我们的模板存储在页面内，而不是使用另一个外部文件。

新页面的主体是模板本身。`Schema.org` 微数据允许人们添加大量附加信息以描述页面上的元素，因此扩展中可能存储各种不同的信息。

因此，我们的模板利用了很多条件来显示如果它们存在的东西。扩展程序应始终显示名称，但除此之外，它可能显示图像、工作标题和公司、地址或各种联系方式，或者它们的任何组合。

模板中最复杂的部分是`getMembers()`辅助函数。我们将使用 JsRender 的`{{for}}`标记为`contactMethods`对象中的每个对象调用此辅助函数，该标记使用波浪号（~）字符调用辅助函数。在循环内，我们将能够访问辅助函数返回的值，并将这些值插入到相关元素中。

接下来，我们添加了`template.js`脚本文件。此时，我们需要添加到此脚本文件的所有内容只是模板用于呈现任何联系方式的辅助方法。这些将采用`{ email: me@me.com }`的格式。

使用 JsRender 的`helpers()`方法注册辅助程序。此方法接受一个对象，其中指定辅助程序的名称为键，应调用的函数为值。

函数接收一个对象。我们首先创建一个空数组，然后使用标准的`for in`循环迭代对象。我们首先使用 JavaScript 的`hasOwnProperty()`函数检查正在迭代的属性是否属于对象，且不是从原型继承的。

然后，我们只需创建一个新对象，并将键设置为名为`key`的属性，将值设置为名为`val`的属性。这些是我们在模板中使用的模板变量，用于在我们的模板中的`<dl>`中插入。

然后，将此新对象推送到我们创建的数组中，并且一旦对传递给辅助函数的对象进行了迭代，我们将该数组返回给模板，以便`{{for}}`循环进行迭代。

# 在沙盒中发布消息

在此任务中，我们将建立我们的弹出窗口与沙盒模板页面之间的通信，以查看如何在打开弹出窗口时让模板进行呈现。

## 启动推进器

首先，我们可以添加将消息发送到沙盒页面以请求模板进行呈现的代码。在`popup.js`中，添加以下代码：

```js
var iframe = $("#poster"),
    message = {
        command: "issueTemplate",
        context: JSON.parse(localStorage.getItem("webContacts"))
    };
    iframe.on("load", function () {
        if (message.context) {
            iframe[0].contentWindow.postMessage(message, "*");
        } else {
            $("<li>", {
                text: "No contacts added yet"
            }).appendTo($("#contacts"));
        }
    });

window.addEventListener("message", function (e) {
    $("#contacts").append((e.data.markup));
});
```

接下来，我们需要添加响应初始消息的代码。将以下代码直接添加到`template.js`中，放在我们上一个任务中添加的辅助方法之后：

```js
var template = $.templates($("#contactTemplate").html());

window.addEventListener("message", function (e) {
    if (e.data.command === "issueTemplate") {

        var message = {
            markup: template.render(e.data.context)
        };

        e.source.postMessage(message, event.origin);
    }
});
```

## 目标完成 - 小型总结

首先，我们在`popup.js`中设置了初始消息传递。我们在变量中缓存了来自弹出窗口的`<iframe>`元素，然后编写了一条消息。消息是以对象文字的形式，具有`command`属性和`context`属性。 

`command`属性告诉在`<iframe>`中运行的代码要执行什么操作，而`context`包含要渲染到模板中的数据。我们将要渲染的数据存储在 localStorage 的`webContacts`键下，并且数据将以 JSON 格式存储，因此我们需要使用`JSON.parse()`将其转换回 JavaScript 对象。

然后，我们使用 jQuery 的`on()`方法为`<iframe>`元素添加加载处理程序。传递给`on()`的匿名函数中包含的代码将在`<iframe>`的内容加载完成后执行。

一旦发生这种情况，我们检查 `message` 对象的 `context` 属性是否具有真值。如果是，我们使用 `<iframe>` 的 `contentWindow` 属性的 `postMessage()` 函数将 `message` 对象发布到 `<iframe>`。

`postMessage()` 函数接受两个参数 - 第一个是要发布的内容，在这种情况下是我们的 `message` 对象，第二个参数指定哪些文件可以接收此消息。我们将其设置为通配符 `*`，这样任何文件都可以订阅我们的消息。

如果没有存储的联系人，则我们 `message` 对象的 `context` 属性将具有假值 `null`。在这种情况下，我们只需创建一个新的 `<li>` 元素，其中包含一条文本消息，说明没有保存的联系人，并将其直接附加到 `popup.html` 中硬编码的空 `<ul>` 中。

我们的脚本文件 `popup.js` 也需要接收消息。我们使用标准的 JavaScript `addEventListener()` 函数将一个监听器附加到 `window` 上的 `message` 事件上。默认情况下，jQuery 不处理 `message` 事件。

`popup.js` 收到的消息将是包含要渲染的 HTML 标记的沙盒页面的响应。标记将包含在事件对象的 `data` 属性中的名为 `markup` 的属性中。我们简单地选择 `popup.html` 中的 `<ul>` 元素，并附加我们收到的标记。

我们还在 `template.js` 中添加了一些代码，该脚本文件被我们 `<iframe>` 内的页面引用。我们在这里再次使用 `addEventListener()` 函数来订阅消息事件。

这次我们首先检查发送消息的对象的 `command` 属性是否等于 `issueTemplate`。如果是，然后我们创建并渲染数据到我们的 JsRender 模板中，并构建一个包含渲染模板标记的新 `message` 对象。

创建了消息对象后，我们将其发布回 `popup.js`。我们可以使用事件对象的 `source` 属性获取 `window` 对象发送消息，并且可以使用事件对象的 `origin` 属性指定哪些文件可以接收消息。

这两个属性非常相似，除了 `source` 包含一个 `window` 对象，而 `origin` 包含一个文件名。文件名将是一个特殊的 Chrome 扩展名。在这一点上，我们应该能够启动弹出窗口，并看到**没有联系人**消息，因为我们还没有保存任何联系人。

# 添加一个内容脚本

现在，一切都已准备就绪以显示存储的联系人，因此我们可以专注于实际获取一些联系人。为了与用户在浏览器中导航的页面交互，我们需要添加一个内容脚本。

内容脚本就像一个常规脚本一样，只是它与浏览器中显示的页面进行交互，而不是与组成扩展的文件进行交互。我们会发现，我们可以在这些不同区域之间（浏览器中的页面和扩展）发送消息，方法与我们发送消息到我们的沙盒类似。

## 启动推进器

首先，我们需要向 `chrome-extension` 目录中添加一些新文件。我们需要一个名为 `content.js` 的 JavaScript 文件和一个名为 `content.css` 的样式表。我们需要告诉我们的扩展使用这些文件，因此我们还应该在此项目之前创建的清单文件（`manifest.json`）中添加一个新部分：

```js
"content_scripts": [{
    "matches": ["*://*/*"],
    "css": ["content.css"],
    "js": ["jquery-1.9.0.min.js", "content.js"]
}]
```

这个新的部分应该直接添加到我们之前添加的沙盒部分之后（像以前一样，在`sandbox`属性后别忘了添加逗号）。

接下来，我们可以向 `content.js` 添加所需的行为：

```js
(function () {

    var people = $("[itemtype*='schema.org/Person']"),
        peopleData = [];

    if (people.length) {

        people.each(function (i) {

            var person = microdata.eq(i),
                data = {},
                contactMethods = {};

            person.addClass("app-person");

        });
    }
} ());
```

我们还可以添加一些基本样式，用 `content.css` 样式表突出显示包含微数据属性的任何元素。现在更新此文件，使其包含以下代码：

```js
.app-person { 
    position:relative; box-shadow:0 0 3px rgba(0,0,0, .5); 
    background-color:#fff;
}
```

## 目标完成 - 迷你总结

首先，我们更新了清单文件以包括内容脚本。正如我之前提到的，内容脚本用于与浏览器中显示的可见页面进行交互，而不是与扩展使用的任何文件进行交互。

我们可以使用清单中的 `content_script` 规则来启用内容脚本。我们需要指定内容脚本应加载到哪些页面中。我们在 URL 的 `protocol`、`host` 和 `path` 部分使用通配符（`*`）以便在访问任何页面时加载脚本。

使用 `Schema.org` 微数据来描述人物时，存在的不同信息被放置在一个容器内（通常是一个 `<div>` 元素，尽管任何元素都可以被使用），该容器具有特殊属性 `itemtype`。

此属性的值是一个 URL，指定了它包含的元素描述的数据。所以，要描述一个人，这个容器将具有 URL [`schema.org/Person`](http://schema.org/Person)。这意味着容器中的元素可能有描述特定数据的附加属性，比如姓名或职务。容器内的元素上的这些附加属性将是 `itemprop`。

在这种情况下，我们使用了一个 jQuery 属性包含选择器（`*=`）来尝试从页面中选择包含此属性的元素。如果属性选择器返回的数组长度（因此不为空），我们就知道页面上至少存在一个这样的元素，因此可以进一步处理该元素。

具有此属性的元素集合存储在名为 `people` 的变量中。我们还在变量 `peopleData` 中创建了一个空数组，准备存储页面上找到的所有人的所有信息。

然后，我们使用 jQuery 的`each()`方法来迭代从页面选择的元素。在我们的`each()`循环中，不使用`$(this)`，我们可以使用我们已经从页面中选择的元素集合，与当前循环的索引一起使用 jQuery 的`eq()`方法来引用每个元素，我们将其存储在名为`person`的变量中。

我们还创建一个空对象并将其存储在名为`data`的变量中，准备存储每个人的微数据，以及一个名为`contactMethods`的空对象，因为任何电话号码或电子邮件地址的微数据都需要添加到我们的模板可消耗的子对象中。

此时我们所做的就是向容器元素添加一个新的类名。然后，我们可以使用`content.css`样式表向元素添加一些非常基本的样式，以引起用户的注意。

# 抓取页面的微数据

现在，我们已经安装好了我们的内容脚本，我们可以与扩展程序的用户访问的任何网页进行交互，并检查它是否具有任何微数据属性。

此时，任何包含微数据的元素都会被用户突出显示，因此我们需要添加功能，允许用户查看微数据并在愿意的情况下保存，这就是我们将在此任务中介绍的内容。

## 启动推进器

在`content.js`中为每个具有`itemtype`属性的元素容器添加类名之后，添加以下代码：

```js
person.children().each(function (j) {

    var child = person.children().eq(j),
        iProp = child.attr("itemprop");

    if (iProp) {

        if (child.attr("itemscope") !== "") {

            if (iProp === "email" || iProp === "telephone") {
                contactMethods[iProp] = child.text();
            } else {
                data[iProp] = child.text();
            }
        } else {

            var content = [];

            child.children().each(function (x) {
                content.push(child.children().eq(x).text());
            });

            data[iProp] = content.join(", ");
        }
    }
});

var hasProps = function (obj) {
    var prop,
    hasData = false;

    for (prop in obj) {
        if (obj.hasOwnProperty(prop)) {
            hasData = true;
            break;

        }
    }

    return hasData;
};

if (hasProps(contactMethods)) {
    data.contactMethods = contactMethods;
}

peopleData.push(data);
```

## 目标完成 - 小结

在上一个任务中，我们为每个标记了微数据的元素容器添加了一个类名。在此任务中，我们仍处于处理每个容器的`each()`循环的上下文中。

因此，在这个任务中添加的代码中，我们首先再次调用`each()`，这次是在容器元素的直接子元素上；我们可以使用 jQuery 的`children()`方法轻松获取这些子元素。

在这个`each()`循环中，我们首先使用传递给我们迭代函数的循环计数器（`j`）作为 jQuery 的`eq()`方法的参数来获取现有缓存的`person`变量中的当前项目。这样可以避免在我们的循环中创建一个全新的 jQuery 对象。

我们还将当前元素的`itemprop`属性的值存储在一个名为`iProp`的变量中，因为我们需要多次引用它，并且使用一个漂亮的短变量意味着我们需要输入更少的内容。

此时我们不知道我们是否正在处理常规元素还是包含微数据的元素，因此我们使用一个`if`语句来检查我们刚刚设置的`iProp`变量是否具有真值。如果元素没有`itemprop`属性，则此变量将保存一个空字符串，该空字符串为假值，如果元素只是常规元素，则停止代码进一步进行。

在此条件语句内部，我们知道我们正在处理包含微数据的元素，但数据可能采用不同的格式。例如，如果元素包含地址，它将不直接包含任何内容，而是将包含数据的自己的子元素。在这种情况下，元素将具有一个`itemscope`属性。首先，我们希望处理不包含`itemscope`属性的元素，因此我们嵌套条件的第一个分支检查通过选择`itemscope`属性返回的值是否不是空字符串。

如果记得我们的模板，我们设置了一个帮助函数，使用对象显示联系信息。为了创建这个新对象而不是创建`data`对象的新属性，我们使用另一个嵌套的`if`语句来检查`iProp`变量是否包含电子邮件或电话号码。

如果是这样，我们将`iProp`变量的值作为`contactMethods`对象的键，元素的文本作为值添加。如果`iProp`变量不包含电子邮件地址或电话号码，我们将`iProp`变量设置为`data`对象的键，并将其值设置为元素的内容。

第二个嵌套`if`语句的下一个分支是对具有`itemscope`属性的元素的。在这种情况下，我们首先定义一个空数组，并将其存储在名为`content`的变量中。然后，我们使用 jQuery 的`each()`方法迭代子元素，并将每个元素的文本内容推入`content`数组。

一旦我们遍历了子元素并填充了数组，我们就可以将当前的`iProp`变量和`content`数组中的数据添加到我们的`data`对象中。任何具有`itemscope`属性的元素仍应该具有`itemprop`属性，因此这应该仍然有效。

因此，在这一点上，我们的数据对象应该是对我们主容器内部元素设置的微数据的准确表示。但在对它们进行任何操作之前，我们需要检查`contentMethods`对象是否已填充，并且如果已填充，则将其添加到我们的`data`对象中。

我们可以使用`hasProps()`函数来检查对象是否具有自己的属性。该函数将接收要测试的对象作为参数。在函数内部，我们首先定义`hasData`变量，将其设置为`false`。

然后，我们使用`for in`循环来迭代对象的每个属性。对于每个属性，我们检查该属性是否实际存在于对象上，并且未使用 JavaScript 的`hasOwnProperty()`函数继承。如果属性确实属于对象，我们将`hasData`设置为`true`，然后使用`break`退出循环。

然后，我们通过将其传递给我们的`hasProps()`函数来检查`contactMethods`对象是否有任何属性，如果有，我们将其添加到`data`对象中。最后，一旦所有这些处理都完成，我们将`data`对象添加到我们在代码开头定义的`peopleData`数组中。

# 添加一个保存微数据的机制

在这一点上，如果 Chrome 中显示的页面包含任何个人微数据，我们将有一个包含一个或多个包含微数据和描述其文本的对象的数组。在此任务中，我们将允许用户存储该数据（如果他/她愿意）。

因为我们的内容脚本在网页的上下文中运行而不是在我们的扩展中，所以我们需要再次使用消息传递来将任何收集到的数据传递回扩展以进行存储。

## 准备升空

为了在我们的内容脚本和扩展之间设置消息传递，我们需要添加一个背景页。背景页在扩展被安装和启用时持续运行，这将允许我们设置处理程序来监听并响应从内容脚本发送的消息。

背景页面可以是 HTML 或 JavaScript。在本项目中，我们将使用 JavaScript 版本。现在创建一个新文件，并将其保存在 `chrome-extension` 目录中为 `background.js`。我们还需要通过向 `manifest.json` 文件中添加一个新的 `background` 部分来将此文件注册为背景脚本：

```js
"background": {
    "scripts": ["jquery-1.9.0.min.js", "background.js"]
}
```

这段代码应该直接放在列出 `content_scripts` 的数组之后。再次提醒，不要忘记数组后面的逗号。

## 启动推进器

首先，我们将向我们的背景页面添加所需的行为。在 `background.js` 中，添加以下代码：

```js
chrome.extension.onConnect.addListener(function (port) {

    port.onMessage.addListener(function (msg) {

        if (msg.command === "getData") {

            var contacts = localStorage.getItem("webContacts")
|| '{ "message": "no contacts" }',
                  jsonContacts = JSON.parse(contacts);

            port.postMessage(jsonContacts);

        } else if (msg.command === "setData") {

          localStorage.setItem("webContacts", 
JSON.stringify({ 
              contacts: msg.contacts 
        }));

            port.postMessage({ message: "success" });
        }
    });
});
```

接下来，在 `content.js` 中，在我们将 `data` 对象推入 `peopleData` 数组之后，直接添加以下代码：

```js
$("<a/>", {
    href: "#",
    "class": "app-save",
    text: "Save"
}).on("click", function (e) {
    e.preventDefault();

    var el = $(this),
          port = chrome.extension.connect(),
          contacts;

    if (!el.hasClass("app-saved")) {

        port.postMessage({ command: "getData" });
        port.onMessage.addListener(function (msg) {

            if (msg.message === "no contacts") {

                contacts = [peopleData[i]];

                port.postMessage({ 
                    command:"setData", 
                    contacts:contacts 
                });
            } else if (msg.contacts) {

                contacts = msg.contacts;
                contacts.push(peopleData[i]);

                port.postMessage({ 
                    command: "setData", 
                    contacts: contacts 
            });

        } else if (msg.message === "success") {

            el.addClass("app-saved")
               .text("Contact information saved");

        port.disconnect();

            }
        });
    }
}).appendTo(person);
```

最后，我们可以为我们刚刚添加的新保存链接添加一些样式。在 `content.css` 中，在文件底部添加以下代码：

```js
.app-save { position:absolute; top:5px; right:5px; }
.app-saved { opacity:.5; cursor:default; }
```

## 目标完成 - 小型简报

在这个任务中，我们添加了相当多的代码，因为我们更新了几个不同的文件，以使扩展的不同部分进行通信。

### 添加通信模块

首先，我们更新了我们在任务开始时添加的行为页面。我们将使用 localStorage 来存储扩展收集的保存的联系人，但是只有运行在用户查看的网页上下文中的内容脚本才能访问给定页面的 localStorage 区域，但我们需要访问扩展本身的 localStorage 区域。

为了实现这一点，我们的 `background.js` 文件将充当一个中介，它将访问扩展的 localStorage 区域，并在内容脚本和扩展之间传递数据。

首先，我们添加了一个监听器到 `onConnect` 事件，我们可以通过 Chrome 的 `extension` 实用模块访问。当内容脚本与扩展建立连接时，浏览器将自动打开一个端口。表示此端口的对象将自动传递给我们的处理程序函数。

我们可以使用端口来添加一个消息事件的处理程序。与项目早期的简单 `<iframe>` 通信一样，此处理程序函数将自动传递触发事件的消息。

在消息处理程序内部，我们检查消息的`command`属性是否等于`getData`。如果是，我们首先创建一个`contacts`对象，该对象将由 localStorage `getItem()`方法获取的联系人或者仅包含消息`no contacts`的非常简单的 JSON 对象组成，我们可以手动创建。

一旦我们有了这两个 JSON 对象之一，我们就可以使用 Chrome 的原生 JSON `parse()`方法将其解析为一个真正的 JavaScript 对象。然后，我们可以使用`postMessage()`方法将此对象传回端口。每当建立一个新的连接时，一个新的端口将被打开，所以消息将自动传回到正确的端口，无需我们进行额外的配置。

如果`msg`对象的`command`属性不等于`getData`，它可能会等于`setData`。如果是，我们想要将一个或多个新的联系人存储到 localStorage。在这种情况下，我们将要存储的联系人作为`msg`对象的`contacts`属性中的对象传递，所以我们可以简单地在这个属性的对象上使用`stringify()`方法作为`setItem()`方法的第二个参数。

然后，我们再次使用`port`对象的`postMessage()`方法传回一条简短的消息，确认数据保存成功。

### 更新内容脚本

其次，我们更新了`content.js`文件，以便收集和存储访问者在网页上找到的任何联系信息。

我们首先添加一个新的`<a>`元素，该元素将用作保存联系信息的按钮，并且将添加到包含微数据的任何元素中。我们为新元素添加了一个简单的`# href`属性，一个用于样式目的的类名，以及文本`保存`。

大多数新功能都包含在使用 jQuery 的`on()`方法创建新的`<a>`元素时直接附加到每个元素上的单击事件处理程序中。

在这个事件处理程序中，我们首先使用`preventDefault()`停止浏览器的默认行为，就像我们通常在将事件处理程序附加到`<a>`元素时一样。然后，我们通过将`$(this)`存储在一个名为`el`的变量中来缓存对当前`<a>`元素的引用。还使用`extension`模块的`connect()`方法打开一个新的端口来处理我们的通信需求。声明了一个名为`contacts`的变量，但没有立即定义。

代码的其余部分位于一个条件语句内，该条件语句检查元素是否已经具有类名`app-saved`，这将有助于防止同一页面上同一人的重复条目被保存到本地存储中。

在条件语句中，我们首先需要获取先前存储的联系人，因此我们通过向我们刚刚打开的端口发送消息来请求行为页面上的保存联系人。我们将一个具有`command`属性设置为`getData`的对象作为消息发送。

然后，我们使用`addListener()`方法对此消息的响应添加了一个处理程序，该方法在`onMessage`事件上。我们的其余代码位于此处理程序中，其中包含根据响应消息不同而有不同反应的另一个条件语句。

条件语句的第一个分支处理响应`msg`的`message`属性包含字符串`no contacts`的情况。在这种情况下，我们创建一个新数组，其中包含从点击的保存链接中收集的联系人信息。我们已经在`peopleData`数组中有这些信息，并且由于我们仍处于更新每个人的循环中，因此我们可以使用`i`变量来存储正确的人员。

然后，我们可以将此数组发送到行为页面，以永久存储在扩展程序的本地存储区域中。

如果`msg`对象没有`message`属性，可能有`contacts`属性。此属性将包含先前存储的联系人数组，因此我们可以将数组保存到变量中，并在将更新后的数组发送回行为页面进行永久存储之前将新联系人添加到此数组中。

条件语句的最后一个分支处理了联系人成功保存的情况。在这种情况下，`msg`对象的`message`属性将包含`success`字符串。在这种情况下，我们将类名`app-saved`添加到`<a>`元素，并将文本更改为`联系信息已保存`。由于不再需要端口，我们可以使用`port`对象的`disconnect()`方法关闭它。

### 添加简单的样式

最后，我们为保存链接添加了一些非常简单的样式。一旦用户发起的操作完成，显示反馈非常重要。

在这个例子中，我们通过改变链接的文本简单地使用 CSS 使其更加不透明，使其看起来好像不再可点击，这是因为我们在脚本中使用的`if`语句的情况。

现在，我们应该能够浏览到包含微数据并保存联系信息的页面。当单击浏览器操作按钮时，我们将看到弹出窗口，其中应显示保存的联系人，如项目开始时的屏幕截图所示。

## 机密情报

在测试内容脚本时，重要的是要意识到每当内容文件更改时，这在本例中意味着 JavaScript 文件或样式表，都必须重新加载扩展程序。

要重新加载扩展程序，在 Chrome 的**扩展程序**页面中列出的扩展程序下方有一个**重新加载**（*Ctrl* + *R*）链接。我们需要点击此链接以应用对任何内容文件所做的更改。扩展程序的其他部分，例如弹出窗口文件，不需要重新加载扩展程序。

扩展程序员的另一个有用工具是开发者工具，它可以专门打开以监视后台页面中的代码。在使用后台页面时，进行故障排除和脚本调试时，这可能非常有用。

# 任务完成

在这个项目中，我们涵盖了构建 Chrome 扩展的大部分基础知识。我们介绍了创建一个浏览器操作，当点击它时触发弹出窗口，以显示保存的联系人。

我们还了解了如何安全地对需要运行危险代码（如`eval()`或`new Function`）的页面进行沙盒化，以保护我们的扩展不受 XSS 攻击的影响，并且我们如何使用简单的消息传递 API 向包含沙盒化页面的`<iframe>`元素发送消息并接收响应。

我们看到，除了定义在扩展上下文中运行的脚本之外，还可以添加在浏览器中显示的网页上下文中运行的内容脚本。我们还学会了如何使用`manifest.json`文件来指定扩展的这些不同区域。

我们还看到可以使用更高级的消息传递系统，允许我们打开允许进行更复杂双向消息传递的端口。通过端口通信，我们可以从扩展的不同区域发送并接收尽可能多的消息，以完成保存数据到扩展 localStorage 区域等特定任务。

我们还了解了可以使用`Schema.org`微数据描述的数据类型，以及可以添加到元素中进行描述的 HTML 属性。除了能描述人以外，还有用于描述地点、公司、电影等等的`Schema.org`格式。

我们学到了很多关于在 Chrome 中创建扩展，但是我们还使用了大量 jQuery 方法，以简化我们编写的脚本，以驱动扩展程序。

# 你准备好全力以赴了吗？一个热门挑战

当我们的扩展保存新联系人时，包含微数据的突出显示元素将被赋予新的 CSS 类名，并且会对它们进行一些非常简约的额外样式修改。

这样做是可以的，但确认成功的更好方法是利用 Chrome 的桌面通知系统，生成类似 Growl 风格的弹出式通知来确认成功。

访问[`developer.chrome.com/extensions/notifications.html`](http://developer.chrome.com/extensions/notifications.html)查看通知文档，并查看是否可以更新扩展以包括此功能。
