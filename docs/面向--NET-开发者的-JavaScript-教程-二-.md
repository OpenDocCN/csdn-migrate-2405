# 面向 .NET 开发者的 JavaScript 教程（二）

> 原文：[`zh.annas-archive.org/md5/9D370F6C530A09D4B2BBB62567683DDF`](https://zh.annas-archive.org/md5/9D370F6C530A09D4B2BBB62567683DDF)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：使用 jQuery 在 ASP.NET 中

我们将从这个章节开始，先对 jQuery 作一个简短的介绍。jQuery 是一个 JavaScript 库，旨在通过编写更少的代码来提供更好的开发体验和更快的编程体验，与纯 JavaScript 相比，它可以更快地执行复杂操作。然而，当编写特定原因的自定义脚本时，JavaScript 仍然存在。因此，jQuery 可以帮助你进行 DOM 操作，根据类、元素名称等选择元素，并提供一个更好的事件处理模型，使开发者在他们的日常项目中使用更为简单。

与 JavaScript 相比，另一个优点是跨浏览器问题。它提供了跨浏览器的 consistent behavior。另一方面，每个浏览器对 JavaScript 的实现都不一样。此外，为了在 JavaScript 中处理跨浏览器问题，开发者倾向于编写一些条件逻辑来检查 JavaScript 正在运行的浏览器版本并相应地处理；而 jQuery 处理了浏览器的所有重活，并提供了 consistent behavior。

在本章中，我们将讨论 jQuery 的一些强大功能，如下：

+   使用选择器

+   操作 DOM 元素

+   处理事件

# 开始使用 jQuery

jQuery 库可以从[`jquery.com`](http://jquery.com)下载。jQuery 的最新版本是 3.0.0，如果你目标是现代浏览器，例如，IE 9 和 Microsoft Edge 支持这个版本，你可以使用这个库。对于较旧版本—例如，IE 6-8—你可以下载 jQuery 1.x。

一旦 jQuery 被下载，你可以将其添加到你的项目中并引用，如下所示：

```js
<head>
  <script src="img/jquery.js"></script>
</head>
<body>
</body>
```

## 使用内容交付网络

Instead of loading jQuery from your server, we can also load it from some other server, such as the Microsoft server or Google server. These servers are called the **content delivery network** (**CDN**) and they can be referenced as shown here:

+   引用微软 CDN：

    ```js
    <script src="img/jquery-2.0.js">
    </script>
    ```

+   引用谷歌 CDN：

    ```js
    <script src="img/jquery.min.js"></script>
    ```

### 使用 CDN

实际上，这些 CDN 非常普遍，大多数网站已经在使用它们。当运行任何引用 CDN 的应用程序时，有可能其他网站也使用了微软或谷歌的同一个 CDN，相同的文件可能会在客户端缓存。这提高了页面渲染性能。另外，再次从本地服务器下载 jQuery 库时，使用的是 CDN 的缓存版本。而且，微软和谷歌提供了不同地区的服务器，用户在使用 CDN 时也能获得一些速度上的好处。

然而，有时 CDN 可能会宕机，在这种情况下，你可能需要参考并从你自己的服务器下载脚本。为了处理这种场景，我们可以指定回退 URL，它检测是否已经从 CDN 下载；否则，它从本地服务器下载。我们可以使用以下脚本来指定回退：

```js
<script src="img/jquery.min.js"></script>

<script>if (!window.jQuery) { document.write('<script src="img/jquery"><\/script>'); }
</script>
```

`window.jQuery` 实例告诉我们 jQuery 是否已加载；否则，它在 DOM 上写入脚本，指向本地服务器。

或者，在 ASP.NET Core 中，我们可以使用 `asp-fallback-src` 属性来指定回退 URL。ASP.NET Core 1.0 提供了一系列广泛的标签助手。与 HTML 助手相比，这些助手可以通过向页面元素添加 HTML 属性来使用，并为开发者提供与编写前端代码相同的体验。

在 ASP.NET 中可以用一种简单的方式编写代码来处理回退场景：

```js
<script src="img/jquery-2.1.4.min.js"
  asp-fallback-src="img/jquery.min.js"
  asp-fallback-test="window.jQuery">
</script>
```

在 ASP.NET Core 中，还有一个标签助手 `<environment>`，可以用来根据 `launchSettings.json` 文件中设置的当前环境加载脚本：

![CDN 的使用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00013.jpeg)

根据项目配置文件中设置的当前环境，我们可以加载脚本来满足调试和生产场景的需求。例如，在生产环境中，最好指定 JavaScript 库的压缩版本，因为它移除了所有空白字符并将变量重命名为更紧凑的尺寸，以便快速加载。然而，就开发体验而言，标准的非压缩版本对于调试目的来说要好得多。因此，我们可以使用以下代码所示的环境标签助手，在开发应用程序时加载生产环境和标准版本：

```js
<environment names="Development">
  <script src="img/jquery.js"></script>
  <script src="img/bootstrap.js"></script>
  <script src="img/site.js" asp-append-version="true"></script>
</environment>
<environment names="Staging,Production">
  <script src="img/jquery-2.1.4.min.js"
    asp-fallback-src="img/jquery.min.js"
    asp-fallback-test="window.jQuery">
  </script>
  <script src="img/bootstrap.min.js"
    asp-fallback-src="img/bootstrap.min.js"
    asp-fallback-test="window.jQuery && window.jQuery.fn && window.jQuery.fn.modal">
  </script>
  <script src="img/site.min.js" asp-append-version="true"></script>
</environment>
```

## 文档就绪事件

jQuery 库可以通过一个 `$` 符号或者简单地写 `jQuery` 来访问。然而，最好是由开发者使用美元符号访问。它还提供了一种在 DOM 层次结构完全加载时捕获事件的方法。这意味着一旦 DOM 结构加载完成，你可以捕获这个事件来执行不同的操作，如将 CSS 类与控件关联和操作控件值。当页面加载时，DOM 层次结构不依赖于图像或 CSS 文件，并且无论图像或 CSS 文件是否下载，`document ready` 事件都会并行触发。

我们可以使用文档就绪事件，如这段代码所示：

```js
<html>
  <head>
    <script src="img/jquery-1.12.0.min.js"></script>
    <script>
      $(document).ready(function () {
        console.log("Document is lo	aded");
      });
    </script>
  </head>
</html>
```

如前所述的代码解释，`$` 是访问 jQuery 对象的方式。它需要一个作为参数传递的 `document` 对象，而 `ready` 则是检查一旦文档对象模型层次结构完全加载。最后，它接受一个匿名函数，我们可以在其中编写所需的操作。在前面的例子中，当 DOM 层次结构加载时，我们只是显示一个简单的文本消息。

## jQuery 选择器

对于 DOM 操作，jQuery 选择器起着重要作用，并提供了一种更简单、易行的一行方法来选择 DOM 中的任何元素并操作其值和属性，例如，使用 jQuery 选择器更容易搜索具有特定 CSS 类的元素列表。

jQuery 选择器可以用美元符号和括号来书写。我们可以使用 jQuery 选择器根据元素的 ID、标签名、类、属性值和输入节点来选择元素。在下一节中，我们将逐一通过实际例子来看这些元素。

### 通过 ID 选择 DOM 元素

以下示例展示了选择具有 ID 的`div`元素的方法：

```js
<!DOCTYPE html>
<html>
  <head>
    <script src="img/jquery-1.12.0.min.js"></script>
    <script>
      $(document).ready(function () {
        $('#mainDiv').html("<h1>Hello World</h1>");

      });
    </script>
  </head>  
  <body>
    <div id="mainDiv">

    </div>
  </body>
</html>
```

选择元素后，我们可以调用各种方法来设置值。在给定示例中，我们调用了`html()`方法，该方法接受`html`字符串并设置第一个标题为`Hello World`。另一方面，可以通过调用此代码来检索`html`内容：

```js
<script>
  $(document).ready(function () {
    var htmlString= $('#mainDiv').html();

  });
</script>
```

### 通过 TagName 选择 DOM 元素

在 JavaScript 中，我们可以通过调用`document.getElementsByTagName()`来检索 DOM 元素。这个函数返回与标签名匹配的元素数组。在 jQuery 中，这种方式可以更简单实现，并且语法相当简单。

考虑以下示例：

```js
$('div') //returns all the div elements 
```

让我们通过以下示例来阐明我们的理解：

```js
<!DOCTYPE html>
<html>
  <head>
    <script src="img/jquery-1.12.0.min.js"></script>
    <script>
      $(document).ready(function () {
        $('div').css('text-align, 'left');
      });
    </script>
  </head>  
  <body>
    <div id="headerDiv">
      <h1>Header</h1>
    </div>
    <div id="mainDiv">
      <p>Main</p>
    </div>
    <div id="footerDiv">
      <footer>Footer</footer>
    </div>
  </body>
</html>
```

之前的示例将所有`div`子控件的对齐设置为左对齐。如果你注意这里，我们并没有必要遍历所有的`div`控件来设置背景颜色，而且样式已经应用于`all`。然而，在某些情况下，你可能需要根据每个元素的索引设置不同的值，这可以通过在`div`上使用`each()`函数来实现。例如，下面的脚本展示了如何使用`each`函数为每个`div`控件分配一个`index`值作为`html`字符串：

```js
<script>
  $(document).ready(function () {
    $('div').each(function (index, element) {
      $(element).html(index);
    });
  });
</script>
```

每个函数都带有一个参数，该参数是一个带有索引和元素的函数。我们可以使用美元符号访问每个元素，如前代码所示，并通过调用`html`方法将索引设置为内容。输出将类似于以下屏幕截图：

![通过 TagName 选择 DOM 元素](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00014.jpeg)

让我们来看另一个示例，它将在控制台窗口中显示每个`div`控件的内容。在这里，`each()`函数不需要参数，每个循环中的项目可以通过`this`关键字访问：

```js
<!DOCTYPE html>
<html>
  <head>
    <script src="img/jquery-1.12.0.min.js"></script>
    <script>
      $(document).ready(function () {
        $('div').each(function () {
          alert($(this).html());
        });
      });
    </script>
  </head>  
  <body>
    <div id="headerDiv">
      <h1>Demo </h1>
    </div>
    <div id="mainDiv">
      <p>This is a demo of using jQuery for selecting elements</p>
    </div>
    <div id="footerDiv">
      <footer> Copyright - JavaScript for .Net Developers </footer>
    </div>
  </body>
</html>
```

输出如下：

![通过 TagName 选择 DOM 元素](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00015.jpeg)

还有其他各种方法可供使用，您可以在 jQuery 文档中查阅。因此，使用选择器，我们可以更快、更高效地搜索 DOM 中的任何元素。

另一个例子是使用标签名选择多个元素，如下所示。

```js
<html>
  <head>
    <script src="img/jquery-1.12.0.min.js"></script>
    <script>
      $(document).ready(function () {
        $('div, h1, p, footer').each(function () {
          console.log($(this).html());
        });
      });
    </script>
  </head>  
  <body>
    <div id="headerDiv">
      <h1>Demo </h1>
    </div>
    <div id="mainDiv">
      <p>This is a demo of using jQuery for selecting elements</p>
    </div>
    <div id="footerDiv">
      <footer> Copyright - JavaScript for .Net Developers </footer>
    </div>
  </body>
</html>
```

```js
bootstrap theme and apply different classes to the buttons. With the help of the class name selector, we can select controls and update the class name. The following example will return two elements based on the selection criteria specified:
```

```js
<!DOCTYPE html>
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="Content/bootstrap.css" />
    <script src="img/jquery-1.12.0.min.js"></script>
    <script>
      $(document).ready(function () {
        var lst = $('.btn-primary');
        alert(lst.length);
      });
    </script>
  </head>  
  <body>
    <div class="container">
      <p></p>
      <button type="button" class="btn btn-primary active">Edit </button>
      <button type="button" class="btn btn-primary disabled">Save</button>
      <button type="button" class="btn btn-danger" value="Cancel">Cancel</button>
    </div>
  </body>
</html>
```

与访问类名不同，我们可以通过在点号和类名之前指定标签名来限制搜索。您可以使用`$('button.active')`来查找所有激活的按钮。

### 通过属性值选择

在某些情况下，您可能需要根据属性或其值来选择元素。jQuery 库提供了一种非常简洁的方式来根据属性及其值搜索元素。

使用此选择器的语法是先指定元素名称，然后是包含属性名称和值的方括号，这是可选的：

```js
$(elementName[attributeName=value])
```

例如，以下代码选择所有具有`type`属性的元素：

```js
<!DOCTYPE html>
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="Content/bootstrap.css" />
    <script src="img/jquery-1.12.0.min.js"></script>
    <script>
      $(document).ready(function () {
        var lst = $('input[type]');
        console.log(lst.length);
      });
    </script>
  </head>  
  <body>

    <div class="container">
      <p></p>
      <input type="text" value="hello world" />
      <input type="text" value="this is a demo" />
      <input type="button" value="Save" />
    </div>
  </body>
</html>
```

在这个例子中，我们有三个具有`type`属性的输入控件。所以，结果将是`3`。同样，如果您想搜索具有等于`hello world`的值的元素，我们可以使用以下代码：

```js
<script>
  $(document).ready(function () {
    var lst = $('input[value="hello world"]');
    alert(lst.length);
  });
</script>
```

需要注意的是，属性值是大小写敏感的，因此，在使用此表达式时，您应该考虑属性值的确切大小写。然而，还有其他方法，那就是使用`^`来搜索包含、开始或结束特定文本的值。

让我们来看一个基于搜索以表达式开始的值的`alert`例子：

```js
<!DOCTYPE html>
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="Content/bootstrap.css" />
    <script src="img/jquery-1.12.0.min.js"></script>
    <script>
      $(document).ready(function () {
        var lst = $('input[value^="Pr"]');
        alert(lst.length);
      });
    </script>
  </head>
  <body>

    <div class="container">
      <p></p>
      <input type="text" value="Product 1" />
      <input type="text" value="This is a description" />
      <input type="button" value="Process" />
    </div>
  </body>
</html>
```

另一方面，我们也可以使用`$`符号来搜索以文本结尾的值。以下是搜索以`1`结尾的文本的代码：

```js
<script>
  $(document).ready(function () {
    var lst = $('input[value$="1"]');
    alert(lst.length);
  });
</script>
```

最后，搜索包含某些文本的文本可以使用`*`实现，以下是运行此例子的代码：

```js
<script>
  $(document).ready(function () {
    var lst = $('input[value*="ro"]');
    alert(lst.length);
  });
</script>
```

### 选择输入元素

HTML 中的输入控件有很多不同的控件。`textarea`、`button`、`input`、`select`、`image`和`radio`等控件都是输入控件。这些控件通常用于基于表单的应用程序中。因此，jQuery 专门提供了基于不同标准的输入控件的选择选项。

这个选择器以美元符号和`input`关键词开头，后跟属性和值：

```js
$(':input[attributeName=value]);
```

然而，在上一节中，我们已经看到了如何搜索具有属性名称和值的任何元素。所以，如果我们想要搜索所有类型等于文本的输入控件，这是可以实现的。

这个选择器在某些场景下性能效率较低，它搜索出所有输入组中的控件，并找到属性及其值；然而，这个选择器只会搜索输入控件。在编写程序时，如果有什么东西专门针对输入控件属性，使用这种方法是一个更好的选择。

让我们来看一个在 ASP.NET Core MVC 6 中的例子，该例子在文档完全加载后应用 CSS 属性：

```js
@model WebApplication.ViewModels.Book.BookViewModel
@{
  ViewData["Title"] = "View";
}
<script src="img/jquery-1.12.0.min.js"></script>
<script>
  $(document).ready(function () {
    $(':input').each(function () {
      $(this).css({ 'color': 'darkred', 'background-color': 'ivory', 'font-weight': 'bold' });    });
  });
</script>
<form asp-action="View" class="container">
  <br />
  <div class="form-horizontal">
    <div class="form-group">
      <label asp-for="Name" class="col-md-2 control-label"></label>
      <div class="col-md-10">
        <input asp-for="Name" class="form-control" />
        <span asp-validation-for="Name" class="text-danger" />
      </div>
    </div>
    <div asp-validation-summary="ValidationSummary.ModelOnly" class="text-danger"></div>
    <div class="form-group">
      <label asp-for="Description" class="col-md-2 control-label"></label>
      <div class="col-md-10">
        <textarea asp-for="Description" class="form-control" ></textarea>
        <span asp-validation-for="Description" class="text-danger" />
      </div>
    </div>
    <div class="form-group">
      <div class="col-md-offset-2 col-md-10">
        <input type="submit" value="Save" class="btn btn-primary" />
      </div>
    </div>
  </div>
</form>

<div>
  <a asp-action="Index">Back to List</a>
</div>
```

### 选择所有元素

**jQuery 库**为您提供了一个特殊的选择器，它能够获取 DOM 中定义的所有元素的集合。除了标准控件之外，它还会返回诸如`<html>`、`<head>`、`<body>`、`<link>`和`<script>`之类的元素。

获取所有元素语法是`$("*")`，下面的例子在浏览器的控制台中列出了 DOM 的所有元素：

```js
<!DOCTYPE html>
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="Content/bootstrap.css" />
    <script src="img/jquery-1.12.0.min.js"></script>
    <script>
      $(document).ready(function () {
        $("*").each(function () {
          console.log($(this).prop('nodeName'));
        });    
      });
    </script>
  </head>  
  <body>
    <form class="container">
      <div class="form-group">
        <label>Name</label>
        <input type="text" class="form-control"/>
      </div>
    </form>  
  </body>
</html>
```

在前面的代码中，我们使用了`prop`方法，该方法需要属性名来显示元素名称。在这里，`prop`方法可以使用`tagName`或`nodeName`来显示名称类型。最后，在浏览器的控制台中，将显示一个登录页面，如下所示：

![选择所有元素](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00018.jpeg)

### 选择第一个和最后一个子元素

**jQuery 库**提供了特殊的选择器来选择它们父元素的所有第一个或最后一个元素。

选择所有父元素的第一个子元素的语法如下：

```js
$(elementName:first-child);
```

选择所有父元素的最后一个子元素的语法如下：

```js
$(elementName:last-child);
```

下面的例子向您展示了更改选择选项的第一个和最后一个孩子的字体样式的方法：

```js
<!DOCTYPE html>
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="Content/bootstrap.css" />
    <script src="img/jquery-1.12.0.min.js"></script>
    <script>
      $(document).ready(function () {
        $('option:first-child').css('font-style', 'italic');
        $('option:last-child').css('font-style', 'italic');
        alert(lst.length);
      });
    </script>
  </head>
  <body>
    <select>
      <option>--select--</option>
      <option>USA</option>
      <option>UK</option>
      <option>Canada</option>
      <option>N/A</option>
    </select>
  </body>
</html>
```

输出结果如下：

![选择第一个和最后一个子元素](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00019.jpeg)

### jQuery 中的**包含选择器**

`contains`选择器用于查找 HTML 容器元素中的文本，如`<div>`和`<p>`。这个选择器搜索特定类型的所有元素，并找到传递给`contains()`函数的参数的文本。下面显示了包含`div`元素文本的代码示例。这个选择器区分大小写，因此在搜索时请确保大小写正确。

下面的代码将显示一个带有值`2`的警告框，因为它找到了两个包含文本`demo`的`div`元素：

```js
<!DOCTYPE html>
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="Content/bootstrap.css" />
    <script src="img/jquery-1.12.0.min.js"></script>
    <script>
      $(document).ready(function () {
        var lst = $('div:contains("demo")');
        alert(lst.length);
      });
    </script>

  </head>
  <body>
    <div>
      This is a sample demo for contains selector
    </div>
    <div>
      Demo of the selector 
    </div>
    <div>
      Sample demo
    </div>
  </body>
</html>
```

### 选择偶数行和奇数行的选择器

这类选择器适用于表格中的行，通常用于通过将每行奇数行的颜色改变为灰色，使其看起来更像网格。我们可以使用以下语法类型的选择器：

```js
$('tr:even');
$('tr:odd');
```

让我们来看一个将表格中所有行颜色改为灰色的例子：

```js
<!DOCTYPE html>
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="Content/bootstrap.css" />
    <script src="img/jquery-1.12.0.min.js"></script>
    <script>
      $(document).ready(function () {
        $('tr:odd').css('background-color', 'grey');
      });
    </script>

  </head>
  <body>
    <table>
      <thead>
        <tr><th>Product Name</th><th>Description</th><th>Price</th></tr>
      </thead>
      <tbody>
        <tr><td>Product 1</td><td>This is Product 1</td><td>$100</td></tr>
        <tr><td>Product 2</td><td>This is Product 2</td><td>$500</td></tr>
        <tr><td>Product 3</td><td>This is Product 3</td><td>$330</td></tr>
        <tr><td>Product 4</td><td>This is Product 4</td><td>$50</td></tr>
        <tr><td>Product 5</td><td>This is Product 5</td><td>$1000</td></tr>
        <tr><td>Product 6</td><td>This is Product 6</td><td>$110</td></tr>
        <tr><td>Product 7</td><td>This is Product 7</td><td>$130</td></tr>
        <tr><td>Product 8</td><td>This is Product 8</td><td>$160</td></tr>
        <tr><td>Product 9</td><td>This is Product 9</td><td>$20</td></tr>
        <tr><td>Product 10</td><td>This is Product 10</td><td>$200</td></tr>
      </tbody>
    </table>
  </body>
</html>
```

## 操作 DOM

在本文档的这一部分，我们将通过 jQuery 方法看到一些操作 DOM 的例子。jQuery 库提供了一个广泛的库，可以对 DOM 元素执行不同的操作。我们可以轻松地修改元素属性、应用样式，以及遍历不同的节点和属性。我们在上一节中已经看到了一些例子，这一节将专门关注 DOM 操作。

### 修改元素的属性

当使用客户端脚本语言时，修改元素属性和读取它们是一项基本任务。使用普通的 JavaScript，这可以通过编写几行代码来实现；然而，使用 jQuery，可以更快、更优雅地实现。

选定要修改的元素的任何属性都可以通过前面章节列出的各种选项来完成。下表中列出的每个属性都提供了`get`和`set`选项，设置时需要参数，而读取时不需要参数。

在 jQuery 中，有一些可用于修改元素的常见方法，例如`html`、`value`等。要了解更多信息，可以参考[`api.jquery.com/category/manipulation/`](http://api.jquery.com/category/manipulation/)。

| 获取方法 | 设置方法 | 描述 |
| --- | --- | --- |
| `.val()` | `.val('any value')` | 这个方法用于读取或写入 DOM 元素的任何值。 |
| `.html()` | `.html('any html string')` | 这个方法用于读取或写入 DOM 元素的任何 HTML 内容。 |
| `.text()` | `.text('any text')` | 这个方法用于读取或写入文本内容。在这个方法中不会返回 HTML。 |
| `.width()` | `.width('any value')` | 这个方法用于更新任何元素的宽度。 |
| `.height()` | `.height('any value')` | 这个方法用于读取或修改任何元素的高度。 |
| `.attr()` | `.attr('attributename', 'value')` | 这个方法用于读取或修改特定元素属性的值。 |
| `.prop()` | `.prop()` | 这个方法与`attr()`相同，但在处理返回当前状态的`value`属性时更高效。例如，`attr()`复选框提供默认值，而`prop()`给出当前状态，即`true`或`false`。 |
| `.css('style-property')` | `.css({'style-property1': value1, 'style-property2': value2, 'style-propertyn':valueN }` | 这个方法用于设置特定元素的样式属性，如字体大小、字体家族和宽度。 |

让我们来看一下下面的例子，它使用了`html()`、`text()`和`css()`修饰符，并使用`html`、`text`和`increaseFontSize`更新了`p`元素：

```js
<!DOCTYPE html>
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="Content/bootstrap.css" />
    <script src="img/jquery-1.12.0.min.js"></script>
    <script>
      function updateHtml() {
        $('p').html($('#txtHtml').val());
      }

      function updateText() {
        $('p').text($('#txtText').val());
      }

      function increaseFontSize() {
        var fontSize = parseInt($('p').css('font-size'));
        var fontSize = fontSize + 1 +"px";
        $('p').css({'font-size': fontSize});
      }
    </script>
  </head>
  <body >
    <form class="form-control">
      <div class="form-group">
        <p>this is a book for JavaScript for .Net Developers</p>

      </div>
      <div class="form-group">
        Enter HTML: <input type="text" id="txtHtml" />
        <button onclick="updateHtml()">Update Html</button>
      </div>
      <div class="form-group">
        Update Text: <input type="text" id="txtText" />
        <button onclick="updateText()">Update Text</button>
      </div>
      <div class="form-group">
        <button onclick="increaseFontSize()">Increase Font Size</button>
      </div>
    </form>
  </body>
</html>
```

前面 HTML 代码的结果如下：

![修改元素的属性](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00020.jpeg)

你可以通过点击**更新 Html**按钮来更新 HTML，通过点击**更新文本**按钮来更新纯文本：

![修改元素的属性](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00021.jpeg)

最后，可以通过点击**增加字体大小**按钮来增加字体大小：

![修改元素的属性](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00022.jpeg)

### 创建新元素

jQuery 库提供了一种创建新元素的智慧方式。可以使用相同的`$()`方法并传递`html`作为参数来创建元素。创建元素后，除非将其添加到 DOM 中，否则它无法显示。有各种方法可用于附加、插入后或插入前任何元素等。下面表格展示了用于将新元素添加到 DOM 的所有方法：

| 获取方法 | 描述 |
| --- | --- |
| `.append()` | 此方法用于向调用它的元素中插入 HTML 内容 |
| `.appendTo()` | 此方法用于将每个元素插入到调用它的末尾 |
| `.before()` | 此方法用于在调用它的元素之前插入 HTML 内容 |
| `.after()` | 此方法用于在调用它的元素之后插入 HTML 内容 |
| `.insertAfter()` | 此方法用于在调用它的每个元素之后插入 HTML 内容 |
| `.insertBefore()` | 此方法用于在调用它的每个元素之前插入 HTML 内容 |
| `.prepend()` | 此方法用于在调用它的元素的起始位置插入 HTML 内容 |
| `.prepend()` | 此方法用于向每个元素的开始位置插入 HTML 内容 |

以下示例创建了一个包含两个字段（`Name`和`Description`）和一个按钮来保存这些值表单：

```js
<!DOCTYPE html>
<html>
  <head>
    <link rel="stylesheet" type="text/css" href="Content/bootstrap.css" />
    <script src="img/jquery-1.12.0.min.js"></script>
    <script>
      $(document).ready(function () {
        var formControl = $("<form id='frm' class='container' ></form>");
        $('body').append(formControl);
        var nameDiv = $("<div class='form-group'><label id='lblName'>Enter Name: </label> <input type='text' id='txtName' class='form-control' /></div>");
        var descDiv = $("<div class='form-group'><label id='lblDesc'>Enter Description: </label> <textarea class='form-control' type='text' id='txtDescription' /></div>");
        var btnSave = $("<button class='btn btn-primary'>Save</button>")
        formControl.append(nameDiv);
        formControl.append(descDiv);
        formControl.append(btnSave);      
      });
      </script>
    </head>       
  <body>
  </body>
</html>
```

这段代码将产生以下输出：

![创建新元素](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00023.jpeg)

### 删除元素和属性

在使用不同的方法来创建和渲染 DOM 中的元素时，jQuery 还提供了一些用于从 DOM 中删除元素的方法。以下表格是我们可以用来删除特定元素、一组元素或所有子节点的方法的列表：

| 方法 | 描述 |
| --- | --- |
| `.empty()` | 此方法从元素中移除内部 HTML 代码 |
| `.detach()` | 此方法从 DOM 中删除一组匹配的元素 |
| `.remove()` | 此方法从 DOM 中删除一组匹配的元素 |
| `.removeAttr()` | 此方法从元素中移除特定的属性 |
| `.removeClass()` | 此方法从元素中移除一个类 |
| `.removeProp()` | 此方法从元素中移除一个属性 |

`remove()`和`detach()`的区别在于，`remove`永久性地从 DOM 中删除内容；这意味着如果元素有特定的事件或数据关联，这些事件或数据也将被删除。然而，`detach`只是将元素从 DOM 中分离并返回你可以保存在某个变量中以供以后附着的内容：

```js
@model WebApplication.ViewModels.Book.BookViewModel
@{
  ViewData["Title"] = "View";
}
<script src="img/jquery-1.12.0.min.js"></script>
<script>
  var mainDivContent=undefined
  $(document).ready(function () {
    $('button').click(function () {
      if (mainDivContent) {
        mainDivContent.appendTo('#pageDiv');
        mainDivContent = null;
      } else {
        mainDivContent = $('#mainDiv').detach();
      }
    });
  });
</script>
<div id="pageDiv" class="container">
  <br />
  <div id="mainDiv" class="form-horizontal">
    <div class="form-group">
      <label asp-for="Name" class="col-md-2 control-label"></label>
      <div class="col-md-10">
        <input asp-for="Name" class="form-control" />
      </div>
    </div>
  </div>
  <div class="form-group">
    <div class="col-md-offset-2 col-md-10">
      <button class="btn btn-primary"> Detach/Attach</button>
    </div>
  </div>
</div>
```

在分离后，输出将如下所示：

![删除元素和属性](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00024.jpeg)

在附着后，输出将类似于以下屏幕截图：

![删除元素和属性](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00025.jpeg)

## jQuery 中的事件处理

jQuery 事件模型为处理 DOM 元素上的事件提供了更好的方法。程序化地，如果开发者想要注册用户操作的任何事件；例如，按钮的点击事件当使用纯 JavaScript 时可能是一个繁琐的过程。这是因为不同的浏览器有不同的实现，并且语法彼此之间有所不同。另一方面，jQuery 库提供了一个更简洁的语法，开发人员不必处理跨浏览器问题。

### jQuery 中注册事件

在 jQuery 中，有许多快捷方式可以注册事件到不同的元素上。下面的表格展示了所有这些事件及其具体的描述：

| 事件 | 描述 |
| --- | --- |
| `click()` | 此事件在鼠标点击时使用 |
| `.dblclick()` | 此事件在双击时使用 |
| `.mousedown()` | 此事件在鼠标任何按钮被按下时使用 |
| `.mouseup()` | 此事件在鼠标任何按钮被释放时使用 |
| `.mouseenter()` | 此事件在鼠标进入区域时使用 |
| `.mouseleave()` | 此事件在鼠标离开区域时使用 |
| `.keydown()` | 此事件在键盘按键被按下时使用 |
| `.keyup()` | 此事件在键盘按键被释放时使用 |
| `.focus()` | 此事件在元素获得焦点时使用 |
| `.blur()` | 此事件在元素失去焦点时使用 |
| `.change()` | 此事件在项目被更改时使用 |

还有许多其他事件，您可以在[`api.jquery.com/category/events`](http://api.jquery.com/category/events)上查看。

使用 jQuery 注册事件相当简单。首先，必须通过选择任何选择器来选择元素，然后通过调用特定的事件处理程序来注册事件；例如，以下代码片段将为按钮注册点击事件：

```js
$(document).ready(function({
  $('#button1').click(function(){
    console.log("button has been clicked");
  });
)};
```

在前面的示例代码之后，注册`.asp.net`按钮的点击事件，并调用 ASP.NET 中`Home`控制器的`Contact`动作：

```js
<script src="img/jquery-1.12.0.min.js"></script>
<script>
  var mainDivContent=undefined
  $(document).ready(function () {
    $('#btnSubmit').click(function () {
      window.location.href = '@Url.Action("Contact", "Home")';  
    });
  });
</script>
<div id="pageDiv" class="container">
  <br />

  <div class="form-group">
    <div class="col-md-offset-2 col-md-10">
      <button id="btnSubmit" class="btn btn-primary"> Submit</button>
    </div>
  </div>
</div>
```

在前面的示例中，我们通过 Razor 语法使用了 HTML 助手`Url.Action`，生成了 URL 并将其设置为窗口当前位置的`href`属性。现在，点击下面屏幕截图中的按钮：

![jQuery 中注册事件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00026.jpeg)

以下联系页面将被显示：

![jQuery 中注册事件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00027.jpeg)

这里的一个示例将改变所有输入控件的背景颜色到`aliceblue`，当控件获得焦点时，并在它失去焦点时恢复为白色：

```js
@model WebApplication.ViewModels.Book.BookViewModel
@{
  ViewData["Title"] = "View";
}
<script src="img/jquery-1.12.0.min.js"></script>
<script>
  var mainDivContent=undefined
  $(document).ready(function () {
    $('#btnSubmit').click(function () {
      window.location.href = '@Url.Action("Contact", "Home")';  
    });

    $('input').each(function () {
      $(this).focus(function () {
        $(this).css('background-color', 'aliceblue');
      })
      $(this).blur(function () {
        $(this).css('background-color', 'white');

      });
    });
  });
</script>
<div id="pageDiv" class="container">
  <br />
  <div id="mainDiv" class="form-horizontal">
    <div class="form-group">
      <label asp-for="Name" class="col-md-2 control-label"></label>
      <div class="col-md-10">
        <input asp-for="Name"  class="form-control" />
      </div>
    </div>
    <div class="form-group">
      <label asp-for="Description" class="col-md-2 control-label"></label>
      <div class="col-md-10">
        <input asp-for="Description" class="form-control" />
      </div>
    </div>
  </div>
  <div class="form-group">
    <div class="col-md-offset-2 col-md-10">
      <button id="btnSubmit" class="btn btn-primary"> Submit</button>
    </div>
  </div>
</div>
```

### 使用 on 和 off 注册事件

除了直接通过调用事件处理程序来注册事件，我们还可以使用`on`和`off`来注册它们。这些事件为特定元素注册和注销事件。

这是一个使用`on`绑定点击事件到按钮的简单示例：

```js
$(document).ready(function () {
  $('#btnSubmit').on('click', function () {
    window.location.href = '@Url.Action("Contact", "Home")';
  });
});
```

这是一个非常实用的技术，可以在你希望注销任何事件的情况下使用。例如，商务应用程序大多数与表单处理相关，而表单可以通过某个按钮提交请求到某个服务器。在某些条件下，我们必须限制用户在第一次请求处理完成前多次提交。为了解决这个问题，我们可以使用`on()`和`off()`事件在用户第一次点击时注册和注销它们。以下是一个在第一次点击时注销按钮点击事件的示例：

```js
<script src="img/jquery-1.12.0.min.js"></script>
<script>
  $(document).ready(function () {
    $('#btnSubmit').on('click', function () {
      $('#btnSubmit').off('click');       
    });
  });
</script>
```

`preventDefault()`事件就是我们以前在.NET 中使用的取消事件。这个事件用于取消事件的执行。它可以像下面这样使用：

```js
<script src="img/jquery-1.12.0.min.js"></script>
<script>
  $(document).ready(function () {
    $('#btnSubmit').on('click', function (event) {
      event.preventDefault();
    });
  });
</script>
```

`on()`方法与以前版本 jQuery 中使用的`delegate()`方法等效。自 jQuery 1.7 起，`delegate()`已被`on()`取代。

还有一个重载方法`on`，它接受四个参数：

```js
$(element).on(events, selector, data, handler);
```

在这里，`element`是控件名称，`events`是你想要注册的事件，`selector`是一个新东西，可以是父控件的子元素。例如，对于一个表格元素选择器，它可能是`td`；而且在每个`td`的点击事件上，我们可以做如下操作：

```js
@model IEnumerable<WebApplication.ViewModels.Book.BookViewModel>
<script src="img/jquery-1.12.0.min.js"></script>
<script>
  $(document).ready(function () {
    $('table').on('click','tr', null, function() {
      $(this).css('background-color', 'aliceblue');
    });
  });
</script>

<p>
  <a asp-action="Create">Create New</a>
</p>
<table class="table">
  <tr>
    <th>
      @Html.DisplayNameFor(model => model.Description)
    </th>
    <th>
      @Html.DisplayNameFor(model => model.Name)
    </th>
    <th></th>
  </tr>

  @foreach (var item in Model) {
    <tr>
      <td>
        @Html.DisplayFor(modelItem => item.Description)
      </td>
      <td>
        @Html.DisplayFor(modelItem => item.Name)
      </td>
      <td>
        <a asp-action="Edit" asp-route-id="@item.Id">Edit</a> |
        <a asp-action="Details" asp-route-id="@item.Id">Details</a> |
        <a asp-action="Delete" asp-route-id="@item.Id">Delete</a>
      </td>
    </tr>
  }
</table>
```

```js
 output would be similar to the following screenshot. When the user clicks on any row, the background color will be changed to Alice blue:
```

![使用 on 和 off 绑定事件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00028.jpeg)

### 使用 hover 事件

我们可以利用鼠标悬停在特定元素上或离开时的 hover 事件。它可以通过在 DOM 的任何元素上调用`hover()`方法来使用。调用此方法的语法如下：

```js
$(selector).hover(mouseEnterHandler, mouseExitHandler);
```

以下示例在鼠标悬停在输入文本控件上时改变边框颜色：

```js
@{
  ViewData["Title"] = "View";
}
<script src="img/jquery-1.12.0.min.js"></script>
<02>
  $(document).ready(function () {
    $("input[type = 'text']").hover(function () {
      $(this).css('border-color', 'red');
    },
    function () {
      $(this).css('border-color', 'black');
    }
  });
  </script>
  <div id="pageDiv" class="container">
    <br />

  <div id="mainDiv" class="form-horizontal">
    <div class="form-group">
      <label asp-for="Name" class="col-md-2 control-label"></label>
      <div class="col-md-10">
        <input asp-for="Name" class="form-control" />
      </div>
    </div>
    <div class="form-group">
      <label asp-for="Description" class="col-md-2 control-label"></label>
      <div class="col-md-10">
        <input asp-for="Description" class="form-control" />
      </div>
    </div>
  </div>
  <div class="form-group">
    <div class="col-md-offset-2 col-md-10">
      <button id="btnSubmit" class="btn btn-primary"> Submit</button>
    </div>
  </div>
</div>
```

# 总结

在本章中，你学习了 jQuery 的基础知识以及如何在 Web 应用程序中使用它们，特别是在 ASP.NET 核心 1.0 中。这是一个非常强大的库。它消除了跨浏览器问题，并在所有浏览器中提供一致的行为。这个库提供了简单易用的方法来选择元素、修改属性、附加事件以及通过编写更干净、更精确的代码来执行复杂操作。在下一章中，我们将探讨使用 jQuery 和纯 JavaScript 进行 Ajax 请求的各种技术以执行服务器端操作。


# 第四章．Ajax 技术

使网页应用程序具有响应性的核心特征之一就是 Ajax。在服务器端回发传统方式中，无论用户执行任何操作，表单中提供的信息都会发送回服务器，并且同一页面会再次加载，包含在客户端重新加载的所有图像、CSS 和 JavaScript 文件。这种方法在客户端和服务器之间发送的请求和响应大小方面相当沉重。因此，应用程序变得不那么响应式，用户每次执行任何操作时都必须等待页面刷新。在本章中，我们将讨论如何通过 Ajax 简化整个过程，并避免沉重的服务器端回发。

# 介绍 Ajax

**Ajax**代表**异步 JavaScript 和 XML**；它能在不重新发送和渲染整个页面的情况下，在服务器端创建异步请求，而它只发送需要发送到服务器的少量信息，并以特定格式接收响应，通过 JavaScript 更新特定部分或 DOM 元素。这使得开发者能够开发响应式网页应用程序，并动态更新页面内容，而无需每次特定动作时重新加载页面。例如，在主从页面关系中，子内容依赖于父项的选择；而采用传统方法，每次选择父项时，页面都会被发送回服务器端，服务器端执行一些后端任务来填充子部分，并返回 HTML 代码，然后客户端对其进行渲染。通过 Ajax，这可以通过异步请求发送所选信息并更新页面内容的指定部分来实现。

## Ajax 如何工作

Ajax 使用**XMLHttpRequest**（**XHR**）对象异步调用服务器端方法。XHR 是由微软开发的，最初在 Internet Explorer 5 中提供。最初通过调用`ActionXObject`实例来创建一个实例；然而，在现代版本中，每个浏览器都支持通过`XMLHttpRequest`对象初始化 XHR 对象。

以下图表展示了 Ajax 工作的架构视图：

![Ajax 如何工作](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00030.jpeg)

传统上，当客户端执行任何操作时，整个数据都会发送回服务器，一旦收到响应，数据会在客户端重新加载。除非实现了某种缓存机制，否则需要更新的数据（包括所有静态文件，如 CSS、JavaScript 和图片）会从服务器重新加载并在客户端呈现，而不是更新实际需要更新的数据。使用 Ajax，我们可以以 JSON 字符串或 XML 的形式发送数据，并根据服务器返回 JSON、XML、HTML 或其他格式的响应。我们还可以在发送请求时使用请求头，如`Accept`，因此服务器知道客户端接受什么；根据格式化器，它还可以将数据序列化为特定格式。在 ASP.NET MVC 6 中，默认实现了两个格式化器，分别为 JSON 和 XML 发送数据，根据请求的`Accept`头序列化对象。还可以在服务器级别实现自定义格式化器来处理特定场景。

### 使用经典的 XHR 对象进行 Ajax 请求

所有浏览器，包括 Internet Explorer、Chrome、Firefox 和 Safari，都提供这个对象，可以从 JavaScript 中使用它来执行 Ajax 请求。

在 JavaScript 中，我们可以如下初始化`XMLHttpRequest`对象：

```js
var xhr = new XMLHttpRequest();
```

每个请求都可能是`GET`或`POST`请求。一旦从服务器收到响应，一些属性会填充，事件处理程序会被调用，这些事件处理程序在执行 Ajax 请求时可以配置为 XHR 对象。

让我们深入了解 XHR 对象提供的方法、属性和事件。

#### XHR 方法

XHR 对象提供了各种方法，但启动 Ajax 化请求最重要的两个方法是`open()`和`send()`：

+   **发送请求**：

    请求可以是`GET`或`POST`。在执行任何请求时，我们首先必须调用`open`方法并指定 HTTP 方法，如`GET`或`POST`，以及服务器的 URL。其余参数，如`async`位、`user`和`password`，是可选的。

    `open`方法的字段如下：

    ```js
    void Open(

      DOMString method, 
      DOMString URL, 
      optional boolean async, 
      optional DOMString user?, 
      optional DOMString password

    );
    ```

    `send`方法用于将请求发送到服务器。这是实际的方法，它接受各种格式的数据并向服务器发送请求。

    以下表格展示了`send`方法的可重载方法：

    | 方法 | 描述 |
    | --- | --- |
    | `void send()` | 此方法用于发送`GET`请求 |
    | `void send (DOMString? Data)` | 当以字符串形式传递数据时使用此方法 |
    | `void send(Document data)` | 当传递文档数据时使用此方法 |
    | `void send(Blob data)` | 此方法用于传递 blob 数据或二进制数据 |
    | `void send(FormData data)` | 此方法用于传递整个表单 |

+   **取消请求**：

    在某些情况下，开发者可能需要取消当前请求。这可以通过调用 XHR 对象的`abort()`函数来实现：

    ```js
    var xhr = new XMLHttpRequest();
    xhr.abort();
    ```

+   **设置请求头部**：

    XHR 提供了几种 Ajax 请求的方法。这意味着在根据服务器实现需要发送 JSON、XML 或某种自定义格式的数据时，存在一些情况。例如，当与 ASP.NET MVC 6 一起工作时，有两种默认格式化器实现，分别是 JSON 和 XML，如果你想要实现自己的自定义格式化器，这也是可能的。当发送特定格式的数据时，我们需要通过请求头部告诉服务器该格式。这有助于服务器识别必须加载以序列化响应和处理请求的格式化器。

    以下表格显示了可以与 Ajax 请求一起提供的默认头部：

    | 头部 | 描述 |
    | --- | --- |
    | `Cookie` | 此头部指定客户端设置的任何 cookie |
    | `Host` | 此头部指定页面的域名 |
    | `Connection` | 此头部指定连接的类型 |
    | `Accept` | 此头部指定客户端可以处理的内容类型 |
    | `Accept-charset` | 此头部指定客户端可以显示的字符集 |
    | `Accept-encoding` | 此头部指定客户端可以处理的编码 |
    | `Accept-language` | 此头部指定作为响应接受的首选自然语言 |
    | `User-Agent` | 此头部指定一个用户代理字符串 |
    | `Referer` | 此头部指定页面的 URL |

    通过 XHR 对象，我们可以使用`setRequestHeader()`函数设置请求头部，如下面的代码所示：

    ```js
    var xhr= new XMLHttpRequest();
    xhr.setRequestHeader('Content-Type', 'application/json');
    ```

+   **获取响应头部**：

    当服务器返回响应时，我们可以使用以下两种方法来读取响应头部：

    ```js
    var xhr= new XMLHttpRequest();
    function callback(){
      var arrHeaders = xhr.getAllResponseHeaders();
      //or
      var contentType = xhr.getResponseHeader('Content-Type');
    }
    ```

    `getAllResponseHeaders()`函数返回所有响应头部的列表，而`getResponseHeader()`函数接受头部名称并返回提供的头部名称的值。

#### XHR 事件

在 XHR 对象中最有用的事件处理程序，当`readystate`属性的值发生变化时调用，是`onreadystatechange`事件。在初始化请求时，我们可以将函数与这个事件处理程序关联并读取响应：

```js
var xhr= new XMLHttpRequest();
xhr.onreadystatechange = callback;

function callback(){
  //do something
}
```

另一个核心事件处理程序是`ontimeout`，可以在处理请求超时场景时使用。在初始化 XHR 请求时，有一个`timeout`属性，通过该属性可以将超时设置为毫秒，如果请求超过超时值，将调用`ontimeout`事件处理程序。例如，将超时设置为 5,000 毫秒，如果超过`timeout`属性，将调用`timeout`处理函数，如下所示：

```js
var xhr = new XMLHttpRequest();
xhr.timeout = 5000; 
xhr.ontimeout = timeouthandler;
function timeouthandler(){
  //do something
}
```

#### XHR 属性

以下是为`XMLHttpRequest`对象可用的属性列表：

+   **GET 请求状态**：

    这个属性返回关于响应的状态信息。它通常用于根据请求状态采取行动：

    ```js
     var xhr=new XMLHttpRequest();
     xhr.readystate;
    ```

    以下表格给出了可用于`readystate`属性的状态及其含义的列表：

    | 状态值 | 状态 | 描述 |
    | --- | --- | --- |
    | `0` | `UNSENT` | 在此状态下，创建了`XMLHttpRequest`对象，但未调用`open()`方法 |
    | `1` | `OPENED` | 在此状态下，调用`open`方法 |
    | `2` | `HEADERS_RECEIVED` | 在调用`send()`并接收到头部时发生此状态 |
    | `3` | `LOADING` | 当响应正在下载时发生此状态 |
    | `4` | `DONE` | 当响应完成时发生此状态 |

+   **获取响应数据**：

    可以通过调用`response`或`responseText`属性来检索响应。这两个属性的区别在于，`responseText`属性返回响应作为一个字符串，而`response`属性返回响应作为一个`response`对象。`response`对象可以是一个文档、blob 或 JavaScript 对象：

    ```js
    var xhr= new XMLHttpRequest();
    xhr.response;
    //or 
    xhr.responseText;
    ```

+   **获取响应状态**：

    可以通过调用`status`或`statusText`属性来检索响应状态。这两个属性的区别在于，`status`属性返回数值值，例如，如果服务器成功处理了请求，则返回`200`；而`statusText`属性包括完整的文本，例如`200 OK`等：

    ```js
    var xhr= new XMLHttpRequest();
    xhr.status;
    or 
    xhr.statusText;
    ```

让我们来看一个使用 ASP.NET MVC 6 中的 XHR 对象进行表单`POST`请求的例子。以下表单有两个字段，**Name**和**Description**：

![XHR 属性](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00031.jpeg)

以下代码片段使用 XHR 对象将请求发送到服务器端。这个例子发送的是 JSON 数据：

```js
@model WebApplication.ViewModels.Book.BookViewModel
@{
  ViewData["Title"] = "View";
}
<script>
  var xhr = null;
  function submit() {
    xhr = new XMLHttpRequest();
    xhr.open("POST", '/Book/SaveData');
    var name = document.getElementById("Name").value;
    var description = document.getElementById("Description").value;
    var data =
    {
      "Name": name,
      "Description": description
    };
    xhr.setRequestHeader('Content-Type', 'application/json; charset=utf-8');
    xhr.onreadystatechange = callback;
    xhr.send(JSON.stringify(data));
  }

  function callback() {
    if (xhr.readyState == 4) {
      var msg = xhr.responseText;r 
      document.getElementById("msg").innerHTML = msg;
      document.getElementById("msgDiv").style.display = 'block';
    }
  }
</script>

<form asp-action="SaveData" id="myForm">
  <p> </p>
  <div id="msgDiv" style="display:none" class="alert alert-success">
    <a href="#" class="close" data-dismiss="alert" aria-label="close">&times;</a>
    <strong>Success!</strong> <label id="msg"></label>
  </div>
  <div id="pageDiv" class="container">
    <br />
    <div id="mainDiv" class="form-horizontal">
      <div class="form-group">
        <label asp-for="Name" class="col-md-2 control-label"></label>
        <div class="col-md-10">
          <input asp-for="Name" class="form-control" />
        </div>
      </div>
      <div class="form-group">
        <label asp-for="Description"  class="col-md-2 control-label"></label>
        <div class="col-md-10">
          <textarea asp-for="Description" class="form-control" ></textarea>
        </div>
      </div>
    </div>
    <div class="form-group">
      <div class="col-md-offset-2 col-md-10">
        <button id="btnSubmit" onclick="submit()" type="submit" class="btn btn-primary"> Submit</button>
      </div>
    </div>
  </div>
</form>
```

在 ASP.NET Core 中，对于 JSON 和 XML，我们必须显式地为复杂类型添加`[FromBody]`属性。这是因为 MVC 6 首先在不管它是复杂类型还是基本类型的情况下搜索查询字符串中的值。对于 JSON 和 XML 数据，我们需要显式地将方法参数添加`[FromBody]`属性，以便数据可以没有任何问题地轻松绑定：

```js
public IActionResult SaveData([FromBody]BookViewModel bookViewModel)
{
  return Content("Data saved successfully"); 
}
```

```js
document.getElementById and then made a JSON string to pass the form data in a JSON format.
```

输出将如下所示：

![XHR 属性](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00032.jpeg)

然而，谷歌提供了一个库，通过调用`serialize()`函数来序列化表单数据。唯一的区别是设置请求头`'Content-Type'`为`'application/x-www-form-urlencoded'`，并添加以下脚本文件：

```js
<script src=http://form-serialize.googlecode.com/svn/trunk/serialize-0.2.min.js />
```

以下代码是`submit`函数的修订版，它通过`serialize()`函数序列化表单数据，并将数据作为表单编码值发送：

```js
function submit() {
  xhr = new XMLHttpRequest();
  xhr.open('POST', '/Book/SaveData');
  xhr.setRequestHeader('Content-Type', 'application/x-www-form-urlencoded');
  var html = serialize(document.forms[0]);
  xhr.onreadystatechange = callback;
  xhr.send(html);
}
```

对于表单编码的值，我们将删除`[FromBody]`属性。这是因为表单编码的值作为查询字符串中的名称值对发送：

```js
public IActionResult SaveData(BookViewModel bookViewModel)
{
  return Content("Data saved successfully"); 
}
```

在 ASP.NET Web API 的前几个版本中，如果 Web API 控制器的`action`方法包含一个复杂类型，Web API 框架会自动绑定请求体中的值。而随着 ASP.NET Core 的出现，Web API 和 MVC 已经合并为一个统一的框架，模型绑定不再与我们在 Web API 前几个版本中的那样相等。

在前面的例子中，我们看到了如何轻松地发送一个`POST`请求并发送 JSON 和表单编码的值。现在，让我们看一个例子，在这个例子中，我们将根据从服务器发送的 JSON 响应加载部分视图。

以下屏幕截图是包含一个按钮以在表格中加载书籍列表的 ASP.NET 页面：

![XHR 属性](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00033.jpeg)

以下是主页的代码片段：

```js
@model WebApplication.ViewModels.Book.BookViewModel
@{
  ViewData["Title"] = "Books";
}
<script>
  var xhr = null;
  function loadData() {
    xhr = new XMLHttpRequest();
    xhr.open('GET', '/Book/Books',true);
    xhr.onreadystatechange = callback;
    xhr.send();
  }
  function callback() {
    if (xhr.readyState == 4) {
      var msg = xhr.responseText;
      document.getElementById("booksDiv").innerHTML = msg;
    }
  }
</script>
<div class="container">  
  <button id="btnLoad" onclick="loadData()" type="submit" class="btn btn-primary">Load</button>
  <hr />
  <div id="booksDiv">
  </div>
</div>
```

以下是一个显示书籍列表的表格的部分视图：

```js
@{ 
  Layout = null;
}
@model IEnumerable<WebApplication.ViewModels.Book.BookViewModel>
<script src="img/jquery-1.12.0.min.js"></script>
<script>
  $(document).ready(function () {
    $('table').on('click','tr', null, function() {
      $(this).css('background-color', 'aliceblue');
    });
  });
</script>

<p>
  <a asp-action="Create">Create New</a>
</p>
<table class="table">
  <tr>
    <th>
      @Html.DisplayNameFor(model => model.Description)
    </th>
    <th>
      @Html.DisplayNameFor(model => model.Name)
    </th>
    <th></th>
  </tr>

@foreach (var item in Model) {
  <tr>
    <td>
      @Html.DisplayFor(modelItem => item.Description)
    </td>
    <td>
      @Html.DisplayFor(modelItem => item.Name)
    </td>
    <td>
      <a asp-action="Edit" asp-route-id="@item.Id">Edit</a> |
      <a asp-action="Details" asp-route-id="@item.Id">Details</a> |
      <a asp-action="Delete" asp-route-id="@item.Id">Delete</a>
    </td>
  </tr>
}
</table>
```

```js
Books controller that contains the Books action method that returns a list of books:
```

```js
public class BookController : Controller
{
  // GET: /<controller>/
  public IActionResult Index()
  {
    return View();
  }

  public IActionResult Books()
  {
    List<BookViewModel> books = new List<BookViewModel>();
    books.Add(new BookViewModel { Id = 1, Name = "JavaScript for .Net Developers", Description = "Book for .NET Developers" });
    books.Add(new BookViewModel { Id = 1, Name = "Beginning ASP.NET Core 1.0", Description = "Book for beginners to learn ASP.NET Core 1.0" });
    books.Add(new BookViewModel { Id = 1, Name = "Mastering Design Patterns", Description = "All about Design Patterns" });
    return View(books);
  }

  public IActionResult Create()
  {
    return View();
  }
}
```

所以，有了这个设置，当用户点击`加载`按钮时，请求将被发送到服务器，ASP.NET MVC 控制器`Books`动作方法将被调用，它返回一个`视图`，该视图渲染部分视图，该视图将在主页上的`booksDiv`元素内渲染：

![XHR 属性](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00034.jpeg)

### 使用 jQuery 发送 Ajax 请求

在前几节中，我们讨论了如何使用普通的`XMLHttpRequest`对象发送 Ajax 请求，这在所有浏览器中都是可用的。在本节中，我们将了解 jQuery 在发送 Ajax 请求方面提供了什么，以及如何通过 jQuery 对象使用 HTTP `GET`和`POST`请求。

#### jQuery.ajax()

此方法用于发送`GET`和`POST`异步请求。以下代码是此方法的签名，它接受两个参数：`URL`和`options`。`URL`参数是实际的服务器 URL，而`options`以 JSON 表示形式传递配置请求头和其他属性：

```js
$.([URL],[options]);
$.( [options]);
```

以下示例显示了如何对 MVC 控制器进行异步请求，并在从服务器成功返回响应时显示一个警告框：

```js
<script src="img/jquery-1.12.0.min.js"></script>
<script>
  $(document).ready(function () {
    $.ajax('/Book/Books', {
      success: function (data) {
        $('#booksDiv').html(data);
      },
      error: function (data) {
        $('#booksDiv').html(data);
      }
    });
  });
</script>
```

`Books`动作方法返回 ASP.NET MVC 视图，其中传递了将在`booksDiv` DOM 元素内填充的书籍列表：

![jQuery.ajax()](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00035.jpeg)

### Ajax 属性

以下表格显示了您可以指定的一些核心属性，以配置 Ajax 请求：

| 名称 | 类型 | 描述 |
| --- | --- | --- |
| `accepts` | `PlainObject` | 此属性告诉服务器客户端将接受哪种类型的响应。 |
| `async` | `Boolean` | 默认情况下，此属性为`true`（用于异步请求），但它可以设置为`false`（同步）。 |
| `cache` | `Boolean` | 如果将此属性设置为`false`，浏览器将不会缓存强制请求的页面。 |
| `contents` | `PlainObject` | 此属性用于指定解析响应的正则表达式。 |
| `contentType` | `String` 或 `Boolean` | 这个属性告诉服务器传入请求的数据类型。默认值是`application/x-www-form-urlencoded; charset=UTF-8`。 |
| `crossDomain` | `Boolean` | 如果您想强制执行跨域请求，则将此属性设置为`true`。 |
| `data` | `PlainObject`、`String` 或 `Array` | 这个属性可以用来以 JSON、XML 或其他任何格式传递数据。 |
| `dataType` | `String` | 这个属性指定了期望从服务器返回的数据类型。一些核心数据类型包括 XML、JSON、脚本和 HTML。 |

#### 预过滤 Ajax 请求

这是一个很好的功能，可以在发送之前过滤现有的请求选项和配置属性。它提供了两个重载方法：一个接收一个函数，该函数注入`options`、`originalOptions`和`jqXHR`对象，另一个接收一个字符串，您可以在此字符串中过滤出特定请求的配置属性，后面跟着接受`options`、`originalOptions`和`jqXHR`参数的函数。下面是这两个重载方法的签名：

```js
$.ajaxPrefilter(function(options, originalOptions, jqXHR){
  //Modify options, originalOptions and store jqXHR
}
$.ajaxPrefilter('dataType', function(options, originalOptions, jqXHR){
  //Modify options, originalOptions and store jqXHR
}
```

前面的代码中的对象如下解释：

+   `options`：这些对象与 Ajax 请求中提供的请求选项相同，但可以被覆盖和相应地过滤。

+   `originalOptions`：这些对象提供了 Ajax 请求中实际传递的选项。它们可以用来引用，但不能修改。任何配置的更改都可以通过使用`options`对象来实现。

+   `jqXHR`：这个对象与 jQuery 中的`XMLHttpRequest`对象相当。

让我们来看一下以下示例，该示例通过添加`fromAjax`参数来告诉 MVC 控制器请求是从 JavaScript 执行的：

```js
<script>
  $(document).ready(function () {

    $.ajaxPrefilter(function (options, originalOptions, jqXHR) {
      options.url += ((options.url.indexOf('?') < 0) ? '?' : '&')+ 'fromAjax=true';
    });

    $.ajax('/Book/Books', {
      success: function (data) {
        $('#booksDiv').html(data);
      },
      error: function (data) {
        $('#booksDiv').html(data);
      }
    });
  });
</script>
```

下面的代码是控制器动作方法，如果请求是 Ajax 请求，则返回书籍列表：

```js
public IActionResult Books(bool fromAjax)
{
  if (fromAjax)
  {
    List<BookViewModel> books = new List<BookViewModel>();
    books.Add(new BookViewModel { Id = 1, Name = "JavaScript for .Net Developers", Description = "Book for .NET Developers" });
    books.Add(new BookViewModel { Id = 1, Name = "Beginning ASP.NET Core 1.0", Description = "Book for beginners to learn ASP.NET Core 1.0" });
    books.Add(new BookViewModel { Id = 1, Name = "Mastering Design Patterns", Description = "All about Design Patterns" });
    return View(books);
  }
  return Content("Request to this method is only allowed from Ajax");
}
```

有关选项的各个属性，您可以在[`api.jquery.com`](http://api.jquery.com)上参考。

#### 为所有未来的 Ajax 请求设置默认值

使用`$.ajax.setup`函数，我们可以为通过`$.ajax()`或`$.get()`函数进行的所有未来请求设置配置值。这可以用来在调用`$.ajax()`函数之前设置默认设置，`ajax`函数将选择在`$.ajaxSetup()`函数中定义的设置。

调用`$.ajax.setup`的签名如下：

```js
$.ajaxSetup({name:value, name:value, name:value, …});
```

下面的示例设置了通过`$.ajax`函数进行的`ajax`请求的默认 URL：

```js
<script>
  $(document).ready(function () {

    $.ajaxSetup({ url: "/Book/Books"});

    $.ajax({
      success: function (data) {
        $('#booksDiv').html(data);
      },
      error: function (data) {
        $('#booksDiv').html(data);
      }
    });
  });
</script>
```

### 通过 jQuery 的 get 函数加载数据

jQuery 库提供了不同的函数，用于从服务器检索数据。例如`$.get()`函数，可以用来通过 HTTP `GET`请求加载数据，而`$.getJSON()`专门用来加载编码为 JSON 的数据，`$.getScript()`用来加载并执行来自服务器的 JavaScript。

#### 使用 jQuery.get()

`$.get()` 函数是 `$.ajax()` 的简写函数，只允许 `GET` 请求。它将大多数配置值抽象为默认值。与 `$.ajax()` 函数类似，它将数据返回给 `callback` 函数，但不提供错误回调。因此，如果在请求处理过程中发生任何错误，它无法被追踪。

它接受四个参数，`URL`、`data`、`callback` 和 `type`。其中 URL 是请求发送到的地址，data 是一个在请求时发送到服务器的字符串，callback 指的是当请求成功时执行的函数，type 指定了从服务器期望的数据类型，如 XML、JSON 等。

`$.get()` 函数的以下是其签名：

```js
$.get('URL',data, callback, type);
```

以下示例加载包含 `net` 字符串在其标题中的书籍：

```js
<script>
  $(document).ready(function () {

    $.get('/Book/Books', {filter : "net"}, function (data) {
        $('#booksDiv').html(data);
      }
    );

  });
</script>
```

#### 使用 jQuery.getJSON()

`jQuery.getJSON()` 函数用于从服务器加载 JSON。可以通过调用 `$.getJSON()` 函数来使用它：

```js
$.getJSON('URL', {name:value, name:value, name:value,…});
```

以下示例通过调用一个 `action` 方法来加载 JSON，该方法返回 JSON 响应并在 `booksDiv` 元素中显示书名：

```js
<script>
  $(document).ready(function () {

    $.getJSON('/Book/Books', function (data) {
      $.each(data, function (index, field) {
        $('#booksDiv').append(field.Name + "<br/> ");
      });
    }
  );
</script>
```

`Action` 方法如下返回 JSON 响应：

```js
public IActionResult Books()
{
  List<BookViewModel> books = new List<BookViewModel>();
  books.Add(new BookViewModel { Id = 1, Name = "JavaScript for .Net Developers", Description = "Book for .NET Developers" }
  books.Add(new BookViewModel { Id = 1, Name = "Beginning ASP.NET Core 1.0", Description = "Book for beginners to learn ASP.NET Core 1.0" });
  books.Add(new BookViewModel { Id = 1, Name = "Mastering Design Patterns", Description = "All about Design Patterns" });
  return Json(books);

}
```

页面上的书籍标题将按如下截图所示呈现：

![使用 jQuery.getJSON()](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00036.jpeg)

#### 使用 jQuery.getScript()

`jQuery.getScript()` 函数是 `$.ajax()` 的简写，专门用于从服务器加载脚本。以下是 `$.getScript()` 函数的签名：

```js
$.getScript(url, callback);
```

以下示例在文档加载完成后加载自定义 `.js` 文件：

```js
<script>
  $(document).ready(function () {

  $.getScript("/wwwroot/js/custom.js");
</script>
```

### 使用 post 函数 将数据发送到服务器

与 `$.get()` 函数类似，jQuery 还提供了一个 `$.post()` 函数，它是 `$.ajax()` 的简写，专门用于仅发送 HTTP `POST` 请求。

以下是 `$.post()` 函数的签名：

```js
$.post(url, data, callback, type);
```

以下示例使用 `$.post()` 函数提交表单数据：

```js
<script>

  function submit() {
    $.post('/Book/SaveData', $("form").serialize(), function (data) {
      alert("form submitted");

    });
  }
</script>
```

```js
Book controller's SaveData action method that takes the object and returns the response as a string:
```

```js
public IActionResult SaveData(BookViewModel bookViewModel)
{
  //call some service to save data 
  return Content("Data saved successfully")
}
```

同样，我们可以通过指定类型为 `json` 来传递 JSON 数据：

```js
<script>
  function submit() {
    $.post('/Book/SaveData', {Name:"Design Patterns", Description: "All about design patterns"}, function (data) {
    },'json' );
  }
</script>
```

### Ajax 事件

Ajax 事件分为本地事件和全局事件。当使用 `$.ajax` 函数进行 Ajax 请求时可以声明本地事件，如 `success` 和 `error` 这样的事件被称为本地事件，而全局事件则与页面中执行的每个 Ajax 请求一起工作。

#### 本地事件

以下是本地事件列表，它与 `$.ajax()` 函数特别相关。其他简写函数，如 `$.get()` 和 `$.post()`，没有这些方法可用，因为每个函数都有特定的参数传递和配置属性值：

+   `beforeSend`：在 `ajax` 请求发送之前触发此事件。

+   `success`：当从服务器成功响应时发生此事件。

+   `error`：在 `ajax` 请求过程中发生错误时触发此事件。

+   `complete`：当请求完成时发生此事件。它不检查是否发生错误或者响应是否成功，而是在请求完成后执行。

#### 全局事件

以下是全局事件列表，它与其他缩写函数一起工作，例如`$.post()`、`$.get()`和`$.getJSON`：

+   `ajaxStart`：当管道中没有`ajax`请求且第一个`ajax`请求正在启动时使用此事件。

+   `ajaxSend`：当向服务器发送`ajax`请求时使用此事件。

+   `ajaxSuccess`：当服务器返回的任何成功响应时使用此事件。

+   `ajaxError`：当任何`ajax`请求发生错误时，此事件将被触发。

+   `ajaxComplete`：当任何`ajax`请求完成时使用此事件。

以下是一个 ASP.NET 简单的示例代码，它调用`BookController`的`Books`动作方法，返回书籍列表并触发全局和局部事件：

```js
@model WebApplication.ViewModels.Book.BookViewModel
@{
  ViewData["Title"] = "Books";
}
<script src="img/jquery-1.12.0.min.js"></script>
<script>

  $(document).ready(function () {

    $(document).ajaxComplete(function (e) {
      alert("Ajax request completed");
    }).ajaxSend(function () {
      alert("Ajax request sending");
    }).ajaxSend(function () {
      alert("Ajax request sent to server");
    }).ajaxStop(function () {
      alert("Ajax request stopped");
    }).ajaxError(function () {
      alert("Some error occurred in Ajax request");
    }).ajaxSuccess(function () {
      alert("Ajax request was successful");
    })
    $('#btnLoad').click(function(){
      $.ajax('/Book/Books', {
        success: function (data) {
          $('#booksDiv').html(data);
        },
        error: function (data) {
          $('#booksDiv').html(data);
        }
      });

    });

  });
</script>
<div class="container">
  <br />
  <h4>Books View</h4>
  <h5>Click on the button to load all the books</h5>
  <button id="btnLoad" type="submit" class="btn btn-primary">Load</button>
  <hr />
  <div id="booksDiv">
  </div>
</div>
```

## 跨源请求

```js
geo service and specifies a callback parameter, which points to the jsonCallback function defined in the script. This script will be loaded when the page loads and executes the src URL, which finally calls the jsonCallback method and passes the response.
GET request that uses the Bing API to get the location information based on the latitude and longitude values provided:
```

```js
<script>
  var scrpt = document.createElement('script');

  scrpt.setAttribute('src',' http://dev.virtualearth.net/REST/v1/Locations/latitudeNo,longitudeNo?o=json&key=BingMapsKey);
  document.body.appendChild(scrpt);
  function jsonCallback(data) {
    alert("Cross Origin request got made");
  }
</script>
```

另一方面，使用 jQuery 时，可以通过在`$.ajax`调用中指定`dataType`属性为`jsonp`和`crossDomain`为`true`来发起跨源请求：

```js
$.ajax({
  url: serviceURL,
  type: "GET",
  dataType: "jsonp",
  method:"GetResult",
  crossDomain: true,
  error: function () {
    alert("list failed!");
  },
  success: function (data) {
    alert(data);
  }
});
```

### CORS

另外，当发起跨源请求时，CORS 是更为推荐的方式。它是一个 W3C 标准，允许服务器从任何域发送跨源请求。这需要在服务器端启用。

ASP.NET Core 为在服务器端启用 CORS 提供了简单的方法，这可以通过通过`NuGet`添加`Microsoft.AspNet.WebApi.Cors`，或者通过修改`project.json`并添加以下依赖项来完成：

```js
"Microsoft.AspNet.Cors": "6.0.0-rc1-final"
```

使用`Startup`类中的`ConfigureServices`方法启用 CORS 服务：

```js
public void ConfigureServices(IServiceCollection services
{
  services.AddCors();
}
```

在`Configure`方法中使用`UseCors()`方法添加 CORS 中间件。`UseCors`方法提供两个重载方法：一个接受 CORS 策略，另一个接受委托，可以作为构建器来构建策略。

### 注意

请注意，在`UseMVC`之前应添加`UseCors()`。

通过 CORS 策略，我们可以定义允许的源、头和方式。CORS 策略可以在定义中间件时的`ConfigureServices`或`Configure`方法中定义。

#### 在服务级别指定 CORS 策略

本节将介绍在`ConfigureServices`方法中定义策略并在添加中间件时引用的方法。`AddPolicy`方法有两个参数：策略的名称和一个`CorsPolicy`对象。`CorsPolicy`对象允许链式调用方法，并允许您使用`WithOrigins`、`WithMethods`和`WithHeaders`方法定义源、方法和头。

以下是一个允许所有源、方法和头的示例代码片段。所以无论请求的源（域）和 HTTP 方法或请求头是什么，请求都将被处理：

```js
public void ConfigureServices(IServiceCollection services)
{     
  services.AddCors(options => {
    options.AddPolicy("AllowAllOrigins", builder => builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
  });

}
```

在前面的代码中，`Origins`代表域名，`Method`代表 HTTP 方法，`Header`代表 HTTP 请求头。它可以在`Configure`方法中简单使用，如下所示：

```js
public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory
{

  app.UseCors("AllowAllOrigin");
}
```

我们还可以定义多个策略，如下所示：

```js
public void ConfigureServices(IServiceCollection services)
{
  services.AddCors(options => {
    options.AddPolicy("AllowAllOrigins", builder => builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
      options.AddPolicy("AllowOnlyGet", builder => builder.WithMethods("GET").AllowAnyHeader().AllowAnyOrigin());
  });
```

#### 在 Configure 方法上启用 CORS

另外，我们可以在`Configure`方法本身定义 CORS 策略。`UseCors`方法有两个重载方法：一个接受已经在`ConfigureServices`方法中定义的策略名称，另一个是`CorsPolicyBuilder`，通过它可以在`UseCors`方法本身直接定义策略：

```js
public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
{
  app.UseCors(policyBuilder => policyBuilder.WithHeaders("accept,content-type").AllowAnyOrigin().WithMethods("GET, POST"));
}
```

在`ConfigureMethod`类上定义 CORS 策略可以使整个应用程序都应用 CORS 策略。 instead of using the `EnableCors` attribute, we can specifically define the policy name per controller, and action level as well, and use the policy defined in the `ConfigureServices` method.

通过特性定义是一个替代方案，它从`ConfigureServices`方法中引用策略名称，并忽略中间件级别定义的策略。以下是在控制器、操作和全局级别启用 CORS 的方法：

+   在控制器级别启用 CORS：

    下面的代码在 MVC 控制器级别启用了 CORS 策略：

    ```js
    [EnableCors("AllowAllOrigins")]
    public class BookController : Controller
    {
      //to do
    }
    ```

+   在操作级别启用 CORS：

    下面的代码在 MVC 操作方法级别启用了 CORS 策略：

    ```js
    [EnableCors("AllowAllOrigins")]
    public IActionResult GetAllRecords(
    {
      //Call some service to get records
      return View();
    }
    ```

+   全局启用 CORS：

    全局来说，可以通过在中间件级别定义来启用 CORS，正如我们在`Configure`方法中看到的那样。否则，如果它是在`ConfigureServices`级别定义的，可以通过使用`CorsAuthorizationFilterFactory`对象在全局启用它，如下所示：

    ```js
    public void ConfigureServices(IServiceCollection services)
    {
      services.AddCors(options => {
        options.AddPolicy("AllowAllOrigins", builder => builder.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
        options.AddPolicy("AllowOnlyGet", builder => builder.WithMethods("GET").AllowAnyHeader().AllowAnyOrigin());
      });

      services.Configure<MvcOptions>(options =>
      {
        options.Filters.Add(new CorsAuthorizationFilterFactory("AllowOnlyGet"));
      });
    }
    ```

```js
AllowAllOrigins and AllowOnlyGet, and through CorsAuthorizationFilterFactory, we can pass the AllowOnlyGet policy as the policy name and make it global.
```

# 从 JavaScript 调用 WCF 服务

为了从 JavaScript 调用 WCF 服务方法，我们需要将它们作为接受和返回 JSON 或 XML 格式的 RESTful 服务方法公开。这有助于开发人员像使用 REST 服务一样轻松地使用 WCF 服务，并使用 jQuery `$.ajax`或`$.getJSON`（`$.ajax`的简写方法）方法。为了将 WCF 服务公开为 REST 服务，我们需要使用`WebGet`或`WebInvoke`属性注解 WCF 服务方法。`WebGet`属性主要用于任何 HTTP `GET`请求，而`WebInvoke`用于所有 HTTP 请求方法。

下面的代码展示了在 WCF 操作合同上使用`WebGet`属性，根据方法调用期间传递的`productCode`返回产品的表示：

```js
[OperationContract]
[WebGet(ResponseFormat = WebMessageFormat.Json, BodyStyle = WebMessageBodyStyle.Wrapped, UriTemplate = "json/{productCode}")]
Product GetProduct(string productCode);
```

我们也可以使用`WebInvoke`来表示相同的方法，如下面的代码所示：

```js
[OperationContract]
  [WebInvoke(Method ="GET",  ResponseFormat = WebMessageFormat.Json, BodyStyle = WebMessageBodyStyle.Wrapped, UriTemplate = "products/{productCode}")]
Product GetProduct(string productCode);
```

下面的代码展示了使用`WebInvoke`对 HTTP `POST`请求的表示：

```js
[OperationContract]
[WebInvoke(Method = "POST", ResponseFormat = WebMessageFormat.Json, RequestFormat = WebMessageFormat.Json, BodyStyle = WebMessageBodyStyle.Wrapped, UriTemplate = "products /SaveProduct")]
bool SaveProduct(Product product);
```

如果你注意到了，`POST`方法包含`RequestFormat`和`ResponseFormat`属性，这两个属性告诉服务器在执行任何 HTTP `POST`请求时提供数据的类型以及根据定义的`ResponseFormat`类型返回响应。

当与 RESTful 服务一起工作时，请确保绑定设置为`webHttpBinding`，如下面的屏幕截图所示。此外，与.NET 框架 4 及以上版本，微软引入了另一个属性，称为`crossDomainScriptAccessEnabled`，可以设置为`true`以处理跨源请求：

![从 JavaScript 调用 WCF 服务](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00037.jpeg)

此外，为了启用 CORS，你可以在`system.serviceModel`下如下的屏幕截图中指定`standardEndpoints`：

![从 JavaScript 调用 WCF 服务](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00038.jpeg)

如下添加自定义头。指定星号（`*`）允许一切，而出于安全目的，原点、头信息和请求方法可以被明确地定义为用逗号分隔的具体值：

![从 JavaScript 调用 WCF 服务](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-dnet-dev/img/00039.jpeg)

下面的表格显示了每个访问控制键的描述：

| 访问控制键 | 描述 |
| --- | --- |
| `Access-Control-Allow-Origin` | 此键用于允许从何处调用服务的客户端域 |
| `Access-Control-Allow-Headers` | 此键用于指定当客户端发起请求时允许的头信息 |
| `Access-Control-Allow-Method` | 使用此键，当客户端发起请求时允许的 HTTP 方法 |
| `Access-Control-Max-Age` | 此键采用秒为单位值，以查看响应预检请求可以在不发送另一个预检请求的情况下缓存多久 |

要调用`SaveProduct`方法，我们可以使用 jQuery 的`$.ajax()`方法，并提供以下参数，如以下代码所示。如果你注意到了，我们还定义了`contentType`以及`dataType`。区别在于`contentType`是用来告诉服务器客户端发送的数据类型的，而`dataType`是用来让服务器知道客户端期望在响应中接收的数据类型的。`dataType`的值可以是`json`、`jsonp`、`xml`、`html`或`script`：

```js
function SaveProduct(){
  var product = {
    "ProductName":"Product1",
    "ProductDescription":"This is Product A"
  };

  $.ajax({
    type:"POST",
    url:"http://localhost/products/SaveProduct",
    data:JSON.stringify(product),
    contentType: "application/json",
    dataType:"json",
    processData:true,
    success: function(data, status, xhr){
      alert(data);

    },
    error: function(error){
      alert(error);

    }

  });
}
```

为了调用另一个域，我们可以使用`jsonp`，所以服务器将 JSON 数据包裹在一个 JavaScript 函数中，这被称为一个`callback`函数，当响应返回给客户端时，它会自动调用`success`方法。处理跨源请求的前述方法的修改版本如下所示。

在此代码中，我们修改了 URL，并把`callback=?`查询字符串作为参数传递。此外，`crossDomain`属性用来确保请求是`crossDomain`。当服务器响应时，`?`在`callback`查询中指定，字符串将由函数名替换，例如`json43229182_22822992`，并将调用`success`方法：

```js
function SaveProduct(){
  var product = {
    "ProductName":"Product1",
    "ProductDescription":"This is Product A"
  };

  $.ajax({
    type:"POST",
    url:" http://localhost:4958/ProductService.svc/products/SaveProduct?callback=?",
    data:JSON.stringify(product),
    contentType: "application/json",
    dataType:"jsonp",
    crossDomain: true, 
    processData:true,
    success: function(data, status, xhr){
      alert(data);

    },
    error: function(error){
      alert(error);

    }

  });
}
```

同样，我们也可以按照如下代码调用`GetProduct`方法：

```js
(function () {
  var productCode= "Prod-001";
  var webServiceURL = "http://localhost:4958/ProductService.svc/products/GetProduct/"+productCode;
  $.ajax({
    type: "GET",
    url: webServiceURL,
    dataType: "json",
    processData: false,
    success: function (data) {
      alert(data);
    },
    error: function (error) {
      alert(error);
    }
  });
});
```

对于跨域，可以按照如下方式修改：

```js
(function () {
  var productCode= "Prod-001";
  var webServiceURL = "http://localhost:4958/ProductService.svc/products/GetProduct/"+productCode;
  $.ajax({
    type: "GET",
    url: webServiceURL+"?callback=?",
    dataType: "jsonp",
    crossDomain:true,   
    processData: false,
    success: function (data) {
      alert(data);
    },
    error: function (error) {
      alert(error);
    }
  });
});
```

Alternatively, for the preceding solution, we can also override the `callback` function name in a `jsonp` request, and the value specified in `jsonpCallback` will be used instead of `callback=?` passed in a URL. The following code snippet calls your local function whose name is specified in the `jsonpCallback` value:

```js
function callbackFn(data){

}

(function () {
  var productCode= "Prod-001";
  var webServiceURL = "http://localhost:4958/ProductService.svc/products/GetProduct/"+productCode;
  $.ajax({
    type: "GET",
    url: webServiceURL,
    dataType: "jsonp",
    crossDomain:true,   
    processData: false,
    jsonpCallback: callbackFn,
    success: function (data) {
      alert(data);
    },
    error: function (error) {
      alert(error);
    }
  });
});
```

# 总结

在本章中，我们讨论了 Ajax 技术以及使用`XMLHttpRequest`对象的概念。我们已经了解了 Ajax 请求的基本处理架构以及它提供的事件和方法。同样，我们还讨论了 jQuery 提供了什么以及它拥有的广泛库，用于执行不同类型的 HTTP `GET`和`POST`请求。在下一章中，我们将讨论`TypeScript`的基础知识，以及最受欢迎的客户端框架之一，Angular 2。我们还将通过使用 ASP.NET Core MVC 6 和 Angular 2 作为前端框架以及 Entity Framework 7 进行后端操作来开发一个简单的应用程序。
