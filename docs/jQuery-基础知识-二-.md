# jQuery 基础知识（二）

> 原文：[`zh.annas-archive.org/md5/9E8057489CB5E1187C018B204539E747`](https://zh.annas-archive.org/md5/9E8057489CB5E1187C018B204539E747)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：与服务器交谈

在第六章中，我们学会了如何让 jQuery 帮助我们为用户制作更好的表单。一旦表单被填写，我们将需要使用 jQuery 将其发送回服务器并获取新鲜数据。我们生活在单页面，流动应用的世界。互联网上大多数顶级网站通过 Ajax 以无缝方式更新需要更改的页面部分，这对用户来说比通过提交按钮发布数据并加载新页面的老式方式更好。jQuery 准备好在这里帮助我们。我们可以使用它从服务器动态获取新鲜数据。

在本章中，我们将涵盖以下主题：

+   jQuery 之前的时代

+   今天 jQuery 如何帮助我们

+   帮助方法

+   Ajax 事件

为了理解 jQuery 如何帮助我们与服务器通信，我们应该先退一步，探索 jQuery 之前的世界。在那个时候，网站有两种向服务器发送数据的方式：`<form>` 和 `<a>` 标签。

# jQuery 之前

HTML 的`<form>`标签是将数据发送到服务器的元素。它有两个处理发送数据到服务器的属性。首先是`method`属性，它让它指定如何将数据发送回服务器。它有两个可能的值：`get`或`post`。

将`method`属性设置为`get`，它会将表单数据附加到请求的末尾发送到由`action`属性指定的服务器页面。表单将发送所有已启用的具有定义的`name`元素的表单元素的数据。`get`方法只应用于小部分不敏感数据。通过`get`发送的所有数据都可以从浏览器的 URL 栏中看到。

将`method`属性设置为`post`被认为比`get`更安全，因为它将其数据发送在消息正文中，所以在查询字符串中不可见；但不要被愚弄以为数据是安全的，它只是不那么明显。当你需要向服务器发送新数据时，`post`应该是你首选的方法。

`<form>`标签包含了在单击提交按钮时将发送到服务器的所有表单数据元素。请记住，只有有效的元素才会被发送。为了有效，一个元素必须是启用的，并且有一个`name`属性。`name`属性是服务器上将赋予值的名称。与`id`属性不同，`name`值可以重复，但如果它们在一个表单内重复，那么你就需要弄清楚哪一个是哪一个。

另一种有时被忽视的向服务器发送小量信息的方式是通过设置`<a>`标签的`href`属性的查询参数。诚然，它只能发送小片段的信息，但当你需要从一个页面发送数据到下一个页面时，它可以非常有用。

`<form>` 和 `<a>` 标记都会导致页面刷新，但在 jQuery 之前就已经可以使用 Ajax 了。许多人不知道自从 1990 年代后期以来，Microsoft 浏览器就已经支持 Ajax。它们是使用 Microsoft 的专有 ActiveX 对象实现的，但这种功能的有用性并没有被其他浏览器制造商忽略，他们将其作为浏览器的一个对象，即 `XMLHTTPRequest` 对象，简称 XHR。

不幸的是，编写支持这个功能的代码并不容易。就像我们过去在浏览器编程中看到的许多事情一样，相似功能的不同实现使我们开发人员不得不在开始编写功能代码之前编写大量的管道代码。让我们看看 jQuery 带给 Ajax 派对的东西。

# jQuery 如何帮助我们

jQuery 帮助我们的一种方式是通过简化 Ajax 的痛苦。用户不再愿意等待点击提交，页面变空，然后加载新内容的循环。像 Facebook、Gmail 和 Twitter 这样的网站向用户展示了 Web 可以非常像应用程序。尽管 jQuery 是一个库，而不是像 AngularJS 或 Ember 那样的编程框架，但它可以轻松地实现获取和发送服务器数据而无需重新加载页面。

### 提示

为了演示本章中的代码片段，您需要设置一个 Web 服务器。但是，设置 Web 服务器超出了本书的范围。一种简单的方法是使用包含内置 Web 服务器的编辑器/IDE。JetBrains WebStorm 和 Adobe 的 Brackets 就是这样的编辑器。它们都适用于 Windows、Mac OS X 和 Linux。

## 加载 HTML – `.load()`

我们想让我们的网站能够做的第一件事情之一是在页面上加载新的 HTML 标记。这就是 `.load()` 方法派上用场的地方。它使用 Ajax 从服务器的 URL 下载 HTML，并将其插入到指定位置的页面上。如果您需要创建一个简单的单页应用程序，这个方法会让它变得容易。在底层，`.load()` 使用 `HTTP GET` 方法，这是浏览器加载 HTML 时使用的方法。让我们看一些代码：

```js
<!DOCTYPE html>
<html>
<head lang="en">
    <meta charset="UTF-8">
    <script src="img/"></script>
    <title>Chapter07-AJAX</title>
    <style type="text/css">
        .output-region {
            border: 2px dashed lightblue;
            width: 100%;
            height: 200px;
        }
    </style>
</head>
<body>
<div>
    <div class="output-region" id="outputRegion"></div>
    <form id="myForm">
        <select name="greeting">
            <option selected value="Mr.">Mr.</option>
            <option value="Mrs.">Mrs.</option>
            <option value="Ms.">Ms.</option>
            <option value="Miss">Miss.</option>
            <option value="Dr.">Dr.</option>
        </select>
        <input name="firstName" value="Abel"/>
        <!-- is disabled -->
        <input name="middleName" disabled value="Middle"/>
        <input name="lastName" value="Alpha"/>
        <!-- doesn't have a name attribute -->
        <input id="suffix" value="Suffix"/>
        <input name="age" value="42"/>
    </form>
    <div id="dataTransfer" style="display: none;"><hr/>Data transfer in progress...</div>
    <hr/>
    <button type="button" class="load-page" data-page="page1">Get Page 1</button>
    <button type="button" class="load-page" data-page="page2">Get Page 2</button>
    <button type="button" class="load-page" data-page="page3">Get Page 3</button>
    <button type="button" id="get-javascript">Get JavaScript</button>
    <button type="button" id="get-json">Get JSON</button>
    <button type="button" id="get-get">Get Get Data</button>
    <button type="button" id="get-post">Get Post Data</button>
    <button type="button" id="jq-param">Create Param</button>
    <button type="button" id="serialize">Serialize</button>
    <button type="button" id="serializeArray">Serialize Array</button>
</div>
<script type="text/javascript">
    (function (window, $, undefined) {
        "use strict";

        // Hook the document ready event and
        $(document).ready(function () {
            // error display
            function showError(err) {
                alert('ERROR: ' + err.status + ' - ' + err.statusText);
            }

            function showJsonMessage(data, erase) {
                if(erase){
                    $('#outputRegion').text("");
                }
                $('#outputRegion').append($("<div>").text(JSON.stringify(data)));
            }
            // load new HTML markup code
            $('.load-page').click(function (event) {
                var fileToLoad = $(this).attr("data-page") + ".html";
                $('#outputRegion').load(fileToLoad);
            });
        });
    }());
</script>
</body>
</html>
```

上面的代码分为三个部分。第一部分是 `<head>` 标记中的所有内容。这里唯一重要的是我们从在线仓库加载 jQuery，并包含一些内联 CSS 来标明我们最终将注入标记和 JSON 数据的位置。

下一节是我们的 HTML 标记。我们有一个大的 `<div>`，`id`为 `output-region`，它将保存我们代码的结果。在 `<form>` 标记中，有几个表单元素将为表单提供一些数据。HTML 的最后一行是一系列按钮，将激活我们的每个代码片段。

文件的最后一节是我们的 JavaScript。最初，我们只有一个函数，但随着我们在本章的进展，我们将添加更多的代码。让我们从检查 `load-page` 点击事件处理程序开始。

我们已经看到了很多事件处理程序代码，在这里没有什么新的。 前三个按钮在点击时都使用此处理程序。 处理程序将获取所点击按钮的`data-page`属性。 `data-page`属性告诉代码要加载哪个页面，并将其附加扩展名`.html`。 这将传递给`.load()`方法，它将用它从服务器中抓取的新标记写入到由选择器指定的位置。 如果`.load()`成功检索到 HTML，它将写入到指定的选择器中， 在我们的例子中是具有`outputRegion`ID 的`<div>`。

## 加载 JSON 数据 – .getJSON()

`.getJSON()`方法从传递的 URL 加载 JSON 数据，并调用一个返回数据的成功函数，或者将错误对象传递给一个失败函数。 像 jQuery 1.5 及更高版本中的大多数 Ajax 方法一样，它还返回一个 jQuery promise。

### 提示

promise 是表示异步操作最终结果的对象。 它可以有三种状态：挂起，履行和拒绝。 当它刚创建且尚未解决时，状态为挂起。 如果承诺成功解决，其状态将更改为履行。 如果承诺失败，其状态将更改为拒绝。 一旦承诺的状态从挂起变化，它就永远不会再次更改。

有了 jQuery promise，我们可以将一个`then`函数链接到`$.getJSON`方法。 `then`函数接受两个参数。 第一个是在承诺被成功履行时要调用的函数。 第二个参数是在出现错误时要调用的函数。 如果一切顺利， JSON 数据将被转换为 JavaScript 对象并传递给`success`函数，然后会在警报提示中显示一条消息； 否则，错误对象的内容将被显示。

```js
// load JSON data
$('#get-json').click(function (event) {
    $.getJSON('data.json').then(function(data){
        alert(data.message);
    }, function(err){
        alert('ERROR:' + JSON.stringify(err));
    });
}0029;
```

# 加载和执行 JavaScript – getScript()

大多数 Ajax 方法会从服务器获取某种数据。 `.getScript()`方法有所不同。 它从服务器检索 JavaScript，解析，然后执行它。 像其他 Ajax 方法一样，它返回一个 promise，但在这种情况下，`success`函数不会传递任何数据。

```js
// load and run javascript
$('#get-javascript').click(function (event) {
    $.getScript('script.js').then(function () {
        alert("getScript() was successful.");
    }, function(err){
        alert('ERROR:' + JSON.stringify(err));
    });
});
```

执行`.getScript()`方法加载的代码在执行后仍然可用，但除非您保留对其的引用，否则没有简便的方法来再次调用该代码。在示例代码中，我们将`incrementer`函数分配给 window 对象，以便以后可以调用它。

```js
// wrap the code in a function for information hiding
(function () {
    "use strict"

    // we show a message to the user
    alert("We're from another script file, trust us");

    // bind the function to the window global object so I can call it if I need it.
    window.incrementer = (function () {
        var lastNum = 0;
        return function (num) {
            lastNum += num;
            return lastNum;
        }
    }());
}());
```

## 读取和写入数据：jQuery.get() 和 jQuery.post()

最后两个快捷方法是`$.get()`和`$.post()`方法。 我们将它们一起描述，因为这两种方法都是`jQuery.ajax()`方法的快捷方式。 请记住，任何使用快捷方法完成的任务也可以通过调用`$.ajax()`来完成。 快捷方法会处理大量冗长的`ajax`调用工作。 让我们看一些代码：

```js
// load JSON via $.ajax
$('#get-get').click(function (event) {
    $.ajax({
     method: "GET",url: "data1.json",
     success: function (data) {
       showJsonMessage(data);
    });
});
```

该代码使用`HTTP GET`方法加载数据。`$.get()`快捷方法允许我们将其重写为：

```js
// load JSON via $.get
$('#get-get').click(function (event) {
    $.get("data1.json", function (data) {
        showJsonMessage(data);
    });
});
```

我们只向`$.get()`方法传递了两个参数：数据的 URL 和一个成功函数；我们甚至都没有费心传递错误处理函数。请记住，没有错误处理程序，浏览器将悄无声息地吞掉任何错误。上述代码演示了如何使用带有回调函数的`$.get()`方法。让我们通过演示如何使用 promise 链来使事情更加有趣。

```js
// load JSON via $.get with promise chaining
$('#get-get2').click(function (event) {
    $.get("data1.json").
        then(function (data) {
            showJsonMessage(data, true);
            return $.get("data2.json");
        }).
        then(function (data) {
            showJsonMessage(data);
            return $.get("data3.json");
        }).
        then(function (data) {
            showJsonMessage(data);
            return $.get("data4.json");
        }).
        then(function (data) {
            showJsonMessage(data);
        }, showError);
});
```

上述代码对服务器进行了四个顺序调用。每个调用请求不同的 JSON 数据块，并通过`showJsonMethod()`函数呈现。如果其中任何一个调用失败，则调用最后一个`then()`方法的`showError()`函数，并且不会进行进一步的 Ajax 请求。每个成功的调用都返回下一个调用，因此可以将承诺链接在一起。

一个潜在的缺点是调用是顺序执行的。大多数浏览器至少可以同时进行两个 HTTP 请求，有些甚至可以进行更多。如果性能是一个问题，并且调用的顺序不重要，我们可以同时进行所有的 HTTP 请求，并让浏览器确定它可以处理多少个。幸运的是，jQuery 的承诺有一个`$.when()`方法。它接受您希望等待的所有承诺作为参数。一旦所有承诺都被解决或拒绝，就会调用`.then()`方法。发送给每个承诺的数据作为参数按照承诺在`.when()`方法中列出的顺序发送。

```js
// load JSON via $.get with concurrent promises
$('#get-con').click(function (event) {
    var data1 = $.get("data1.json"),
        data2 = $.get("data2.json"),
        data3 = $.get("data3.json"),
        data4 = $.get("data4.json");
    $.when(data1, data2, data3, data4).then(function(d1, d2, d3, d4){
        showJsonMessage(d1, true);
        showJsonMessage(d2);
        showJsonMessage(d3);
        showJsonMessage(d4);
    }, showError);
});
```

在上述代码中，进行了四个相同的 HTTP 请求，只是现在它们同时进行。每次调用返回数据的顺序是不确定的，但是代码将等待所有四个调用完成后再继续。如果任何调用失败，整个操作将被视为失败，并调用失败方法。这与我们顺序调用代码时不同。每个 HTTP 请求都可能返回数据，但一旦有一个失败，就会调用失败方法，并且不会再进行其他请求。

到目前为止，所有的请求都是使用`$.get()`方法进行的；我们完全忽略了`$.post()`方法。不用担心，这两种方法都是`$.ajax()`方法的快捷方式。我们几乎可以在任何地方使用`$.post()`代替`$.get()`方法。所以让我们替换第一个演示中的`$.get()`方法。

```js
// load JSON via $.post
,/. $('#get-post').click(function (event) {
    $.post("data1.json", function (data) {
        showJsonMessage(data, true);
    });
});
```

如果这些方法可以相互交换，为什么还要两者都有呢？公平地说，我们一直没有按照它们的用途来使用它们。四个主要的 HTTP 动词是 get、post、put 和 delete。Get 用于从数据库中检索一个或多个项目。Post 用于在数据库中创建新记录。Put 用于更新现有记录。最后，delete 从数据库中删除记录。正确使用这些动词是 RESTful 服务 API 的核心所在，这有点超出了本书的主题范围。

# 辅助方法

jQuery 为我们提供了一些 Ajax 辅助方法。只有三个函数，每个都很容易使用，并为我们消除了一些苦差事。

## 创建查询数据 - $.param()

Ajax 请求通常将数据编码为查询字符串形式传递到服务器。查询字符串跟随 URL 并以问号 "?" 开头。每个参数由一个等号分隔的名称和值组成。生成参数数据并不困难，但是有一些编码规则需要正确遵循，否则您的请求可能会失败。`$.param()` 将我们的数据编码成查询字符串格式。

```js
// converts an array of objects to an encoded query string
$('#jq-param').click(function (event) {
    var testData = [
        {name: "first", value: "Troy"},
        {name: "last", value: "Miles"},
        {name: "twitter", value: "@therockncoder"}
    ];
    var myParam = $.param(testData);
    $('#outputRegion').text(myParam);
});
```

在上述代码中，我们编码了一个名为 `testData` 的对象数组。每个对象都有一个 name 和一个 value 属性。这些属性将是编码字符串的名称和值。我们将数组传递给 `$.param()` 方法，并将结果字符串存储在 `myParam` 中，然后将其写入输出 `<div>`。

注意 `$.param()` 方法是如何为我们处理编码的。第三个数组参数包含一个 at 符号 `@`，它被正确编码为 `%40`。它还将编码其他符号和空格。这些符号必须被编码，否则您的 Ajax 请求将失败。或者更糟糕的是，它可能看起来正常工作，但发送和存储的数据却是不正确的。

`$.param()` 方法仅在手动创建 URL 时才必要。如果调用 `$.get()` 或 `$.post()` 方法并向它们传递数据，它们将正确编码并附加到 URL 或消息主体中。

## 从表单创建查询数据 - .serialize()

下一个助手方法 `serialize()`，与 `$.param()` 方法类似，只是它不是传递数据，而是使用由选择器指示的 `<form>` 标记来从所有有效的表单元素中提取数据。

```js
$('#serialize').click(function (event) {
    var myParam = $('#myForm').serialize();
    $('#outputRegion').text(myParam);
});
```

前面的代码在单击 Serialize 按钮时将 `myForm <form>` 标记中的所有表单元素序列化并呈现到页面上。请记住，只有有效的表单元素才会被序列化。如果一个元素被禁用或没有 name 属性，它将不会被序列化。这个方法允许您用 jQuery 替代老式的 HTML 表单提交。

## 从表单数据创建对象 - .serializeArray()

Ajax 助手的最后一个成员是 `.serializeArray()` 方法。与先前描述的 `.serialize()` 方法类似，它从指定 `<form>` 标记内的所有表单元素中获取数据。它只使用有效的表单元素，这些元素必须启用并具有名称元素。这个方法和 `.serialize()` 方法的区别在于数据的编码方式。`.serializeArray()` 方法将表单数据编码为 JavaScript 对象的数组。每个对象由一个 name 和一个 value 属性组成。name 是元素的 name 属性的内容，value 是元素的值。我们可以用这个方法代替 `.serialize()` 方法。

```js
// serialze the form data as an array of objects
$('#serializeArray').click(function (event) {
    var myParam = $('#myForm').serializeArray();
    $('#outputRegion').text(JSON.stringify(myParam));
});
```

对 `.serializeArray()` 调用的结果是一个 JavaScript 对象数组。我们将结果放在变量 `myParam` 中，然后将其发送到 JSON `stringify()` 方法以便显示。

# Ajax 事件

有时，你的应用程序希望知道各种 Ajax 事件何时发生。也许你的应用程序想要显示一个图标，表示数据正在被发送到服务器或从服务器接收，并在请求完成后隐藏该图标。幸运的是，jQuery 为我们提供了全局 Ajax 事件。这些事件使我们能够知道任何 Ajax 活动何时开始、停止、发送数据、错误或成功。这些事件是全局的，所以它们必须挂钩文档元素。让我们将它们添加到我们当前的示例代码中。

```js
var $doc = $(document);
// when an ajax request begins
$doc.ajaxStart(function () {
    console.info("<<<< Triggered ajax start handler.");
    $('#dataTransfer').show('fast');
});
// once all ajax request complete,
$doc.ajaxStop(function () {
    console.info(">>>> Triggered ajax stop handler.");
    $('#dataTransfer').hide('slow');
});
// called at the beginning of each request
$doc.ajaxSend(function (event, jqxhr, settings) {
    console.info("#### Triggered ajaxSend handler for: " + settings.url);
});
// called every time a request succeeds
$doc.ajaxSuccess(function (event, jqxhr, settings) {
    console.info("#### Triggered ajaxSuccess handler for: " + settings.url);
});
// called every time a request fails
$doc.ajaxError(function (event, jqxhr, settings) {
    console.info("#### Triggered ajaxError handler for: " + settings.url);
});
// called at the end of every request whether it succeeds or fails
$doc.ajaxComplete(function (event, jqxhr, settings) {
    console.info("#### Triggered ajaxComplete handler for: " + settings.url);
});
```

在示例代码中，我们挂钩了三个 Ajax 事件：`ajaxStart`、`ajaxStop`和`ajaxSend`。

## 当 Ajax 请求开始时 – .ajaxStart()

当第一个 Ajax 请求开始时触发`.ajaxStart()`方法。如果另一个请求已经在进行中，该事件不会被触发。在示例代码中，我们在此事件的处理程序中使隐藏的`<div>`与消息*数据传输正在进行中……*可见。

## 当 Ajax 请求完成时 – .ajaxStop()

`.ajaxStop()`方法会在所有 Ajax 请求完成后触发。与`.ajaxStart()`方法类似，它智能地在适当时候触发，允许我们将它们配对使用以隐藏和显示消息。

在本地运行代码时，你会发现`stop`事件在`start`事件之后很快就触发了。为了让消息能够被看到，我们给`hide`方法传递了一个`slow`参数。没有这个参数，用户很难读到消息。

## 当 Ajax 请求发送数据时 – .ajaxSend()

在发送 Ajax 数据之前，将调用`.ajaxSend()`处理程序。如果需要区分哪个 Ajax 请求触发了`.ajaxSend()`，它会向你的处理程序函数发送三个参数：`event`、`jqxhr`和`settings`。settings 参数是一个对象，包含两个重要属性：`url`和`type`。`url`属性是一个字符串，保存着请求调用的 URL。`type`是请求使用的 HTTP 动词。通过检查这两个属性，你应该能够确定哪个 Ajax 请求触发了该事件。

## 当 Ajax 请求失败时 – .ajaxError()

如果请求失败，将触发`.ajaxError()`处理程序。jQuery XHR 对象，参数`jqxhr`，将保存错误信息。状态码将在 status 属性中，错误消息将在`statusText`属性中。

## 当 Ajax 请求成功时 – .ajaxSuccess()

如果请求成功，将触发`.ajaxSuccess()`处理程序。jQuery XHR 对象将保存状态信息。同样，状态码在`status`属性中，状态文本在`statusText`属性中。

## 当 Ajax 请求完成时 – .ajaxComplete()

每当 Ajax 请求完成时，都会调用`.ajaxComplete()`处理程序。无论请求成功还是失败，此方法始终会被调用。它总是在成功或错误事件之后调用。

对于单个请求调用的事件顺序始终相同。首先是开始事件，然后是发送事件，接着是成功或错误事件，然后是完成事件，最后是停止事件。如果进行多个请求，则事件触发的顺序变得不确定。唯一可以保证的是开始是第一个事件，而停止是最后一个。

# 总结

现代 Web 应用必须能够与服务器顺畅地发送和检索数据。jQuery 帮助我们与服务器无缝交互，并消除了需要进行完整页面刷新的需要。

在本章中，我们学习了如何从服务器拉取新数据、JavaScript 和 HTML。还学习了如何在不进行页面刷新的情况下向服务器提交数据。我们还学习了一些 jQuery 提供的帮助方法，这些方法使我们更容易地正确打包数据以进行传输。

一个关于 jQuery 的主要批评并不是针对库本身，而是使用它编写的应用往往很快变得难以控制。在下一章中，我们将看看如何保持我们的代码不像意大利面条一样混乱。


# 第八章：写出稍后可读的代码

jQuery 真的帮助我们用更少的代码做更多的事情，但有一件事它没有解决，那就是如何组织我们的代码。起初这可能不是一个问题，但随着您的应用程序在年龄和功能上的增长，它的组织（或者说缺乏组织）会成为一个问题。

在本章中，我们将介绍一些组织 JavaScript 的成熟方法。在本章中我们将：

+   学习一些面向对象的技术，使我们的代码易于理解和维护

+   使用事件解耦我们的代码，并确保不相关的部分不需要直接相互通信

+   快速了解编写 JavaScript 单元测试，特别是使用 Jasmine，这是一个用于测试 JavaScript 代码的行为驱动开发框架

# 关注点分离

软件架构模式，比如**模型-视图-控制器**（**MVC**），主要因为它们直接解决了代码组织的问题而变得流行起来。模型-视图-控制器将应用程序分成三个主要部分。模型部分处理应用程序的数据。控制器从模型获取数据并将其提供给视图，同时它从视图获取用户输入并将其反馈给模型。关于此模式最重要的一点是您永远不应该混合责任。模型永远不包含控制器代码，控制器永远不包含视图，依此类推。这被称为**关注点分离**，或 SoC。如果应用程序的任何部分违反了此规则，您的应用程序将陷入紧密耦合、相互依赖的代码的烂摊子。

我们不需要完全采用 MVC 来获得一些好处。我们可以将其用作指导我们开发的方法。首先，它帮助我们回答这个问题：这段代码应该放在哪里？让我们看一个例子。我们收到的要求是编写代码从我们的 Web 服务中检索会员数据并将其呈现给用户以供选择。我们应该如何进行？您的第一反应可能是编写类似以下的代码：

```js
<!DOCTYPE html>
<html>
<head lang="en">
  <meta charset="UTF-8">
  <script src="img/"></script>
  <title>Chapter08-Clean Code</title>
</head>
<body>
<div>Super Coding Club Members</div>
<hr/>
<ul id="myList"></ul>
<hr/>

<script type="text/javascript">
  // Hook the document ready event and
  $(document).ready(function () {
    // get the user data
    $.getJSON('users.json', function (members) {
      var index, htmlTemplate = '';
      // make sure there are some members
      if (members && members.length) {
        // create the markup
        for (index = 0; index < members.length; index += 1) {
          htmlTemplate += '<li>' + members[index].name.first + '</li>';
        }
        // render the member names
        $('#myList').html(htmlTemplate);
      }
      return members;
    }).fail(function (error) {
      alert("Error: " + error.status + ": " + error.statusText);
    });
  });
</script>
</body>
</html>
```

这段代码实现了我们的需求，但存在几个问题。首先，没有关注点分离。虽然我们并不是在努力创建一个 MVC 应用程序，但我们至少应该努力让函数按照模型、视图和控制器的方式分解。在本例中，我们的模型由`$.getJSON()`方法调用表示。它直接绑定到我们的控制器代码，该控制器代码在此示例中获取模型数据并将其创建为 HTML 模板。最后，我们的视图代码使用`$.html()`方法呈现 HTML 模板。

这段代码也是紧耦合的一个例子。代码的每个部分直接依赖于下一个部分，并且没有办法将它们分开。紧密耦合的代码更难测试。没有简单的方法来测试这段代码的功能。只要看看它。代码位于文档准备好事件内；你必须模拟该事件才能开始测试代码的功能。一旦你模拟了文档准备好事件，你还需要以某种方式模拟`getJSON()`方法，因为代码的其余部分都被深埋在其中。

# 将代码分解成逻辑单元

使前面的代码示例难以理解的原因之一是它没有被分解成逻辑单元。在 JavaScript 中，我们没有像其他面向对象语言那样的类，但我们有对象，甚至有文件来将逻辑相关的代码单元组合在一起。

我们从函数开始分解代码。与其拥有一个做所有事情的函数，不如努力拥有许多函数，每个函数只做一件事。当函数做了太多事情时，它们变得难以理解。注释可能有助于解释代码正在做什么，但编写良好的代码应该能够自我注释。函数有助于清晰地分离不同功能的各个部分。

也许你会想知道为什么这些都很重要，尤其是因为我们有实现我们需求的可工作代码。这很重要，因为典型的程序花费的时间在维护而不是编写上更多。所以，编写易于维护的代码是很重要的。让我们再试一次：

```js
<script type="text/javascript">
  function showHttpError(error) {
    alert("Error: " + error.status + ": " + error.statusText);
  }

  function getMembers(errorHandler) {
    return $.getJSON('users.json').fail(errorHandler);
  }

  function createMemberMarkup(members) {
    var index, htmlTemplate = '';
    members.forEach(function (member) {
      htmlTemplate += '<li>' + member.name.first + '</li>';
    });
    return htmlTemplate;
  }

  function renderMembers($ptr, membersMarkup) {
    $ptr.html(membersMarkup);
  }

  function showMembers() {
    getMembers(showHttpError)
      .then(function (members) {
        renderMembers($('#members'), createMemberMarkup(members));
      });
  }

  // Hook the document ready event
  $(document).ready(function () {
    showMembers();
  });
</script>
```

代码的第二个版本比原始版本更长，即使它缺乏注释，它也更易读。将代码分成单独的函数使得理解它在做什么变得容易。

在完整的 MVC 应用程序中，我们可能会为每个关注点创建单独的类，然后将每个函数移动到它所属的类中。但我们不需要如此正式。首先，我们在 JavaScript 中没有类，但我们有非常强大的对象可以包含函数。所以这一次让我们再试一次，这次使用 JavaScript 对象来捆绑我们的代码：

```js
<script type="text/javascript">
  var members = {
      showHttpError: function (error) {
        alert("Error: " + error.status + ": " + error.statusText);
      },

      get: function (errorHandler) {
        return $.getJSON('users.json').fail(errorHandler);
      },

      createMarkup: function (members) {
        var index, htmlTemplate = '';
        members.forEach(function (member) {
          htmlTemplate += '<li>' + member.name.first + '</li>';
        });
        return htmlTemplate;
      },

      render: function ($ptr, membersMarkup) {
        $ptr.html(membersMarkup);
      },

      show: function () {
        var that = this;
        that.get(that.showHttpError)
          .then(function (members) {
            that.render($('#members'), that.createMarkup(members));
          });
      }
    };

  // Hook the document ready event
  $(document).ready(function () {
    members.show();
  });
</script>

```

在这个版本中，我们将所有代码捆绑到了成员对象中。这样做可以轻松移动我们的代码，并帮助我们将其视为一个单一的、连贯的单位。将代码放入对象中也使得使用`this`构造成为可能。这是否是一种改进还有争议。我见过许多 JavaScript 开发人员将所有对象名称都写出来，只是为了避免考虑`this`。注意，我们还缩短了大多数方法的名称。在许多方法名称中使用`member`这个词是多余的，因为对象的名称是`member`。此外，请注意，我们现在将我们的函数称为“方法”。当一个函数是类或对象的一部分时，它就是一个方法。

# 使用事件解耦代码

通过本书，我们一直在使用事件，但它们总是被 jQuery 或浏览器触发，而不是由我们触发。现在，这将发生变化。事件对于代码的解耦非常有用。想象一下这样一个场景：你和另一个开发者一起在一个应用程序上工作。另一个开发者将向你的代码提供数据。这些数据——让我们称之为数据源——将会间歇性地可用，不像之前通过单个 Ajax 调用提供数据的示例那样。当数据可用时，你的代码，即数据读取器，将把数据呈现到页面上。有几种方法可以做到这一点。

数据源可以提供一个轮询方法供我们调用。我们会重复调用此方法，直到数据源为我们提供一些新数据为止。然而，我们知道轮询是低效的。大多数时候，我们调用轮询服务时，都不会有任何新数据，我们将浪费 CPU 周期而没有返回任何新数据。

我们可以为数据源提供一个方法，每当它有新数据时就调用。这解决了效率问题，因为我们的代码只会在有新数据时被调用。想象一下，如果我们这样做会引入多么糟糕的维护噩梦。当只有一个依赖模块需要数据源提供数据时，似乎很容易。但如果第二个或第三个模块也需要数据源，我们就必须不断更新数据源模块。如果任何数据读取器模块发生变化，数据源也可能需要更新。我们该怎么办呢？

我们可以使用自定义事件。使用自定义事件可以减少耦合度。双方都不直接调用对方。相反，当数据源有新数据时，它会触发自定义事件。任何想要新数据的数据读取器只需注册一个自定义事件的处理程序。

使用自定义事件有一些好处。首先，耦合度较低。其次，可以注册监听器的数据读取器数量没有限制。第三，如果事件被触发而没有监听器，不会发生任何错误。最后，如果有一堆读取器注册但新数据从未到来，也不会发生错误。

使用自定义事件时，我们必须注意记得在使用完毕后释放事件处理程序。如果我们忘记了会发生两件事。首先，我们可能会导致内存泄漏。内存泄漏是指 JavaScript 无法释放一块内存，因为某些东西——在我们的情况下是一个事件处理程序——仍然持有对它的引用。

随着时间的推移，浏览器会在最终崩溃之前开始变得越来越迟缓，因为它开始耗尽内存。其次，我们的事件处理程序可能会被调用太多次。当钩子事件的代码被调用超过一次而事件从未被释放时，就会发生这种情况。在你意识到之前，事件处理程序会被调用两次、三次，甚至更多次，而不是只被调用一次。

自定义事件的最后一个好处是我们已经知道我们需要的大部分内容以实现它们。代码与我们学习的用于执行常规浏览器事件的代码仅略有不同。让我们首先看一个简单的例子：

```js
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <script src="img/jquery-2.1.1.js"></script>
  <title>Chapter 8 Simple Custom Events</title>
</head>
<body>
<button id="eventGen">Trigger Event</button>
<button id="releaseEvent">Release Event Handlers</button>
<div id="console-out" style="width: 100%">
</div>

<script>
  var customEvent = "customEvent";

  function consoleOut(msg){
    console.info(msg);
    $('#console-out').append("<p>" + msg + "</p>");
  }

  function customEventHandler1(eventObj) {
    return consoleOut("Custom Event Handler 1");
  }

  function customEventHandler2(eventObj) {
    return consoleOut("Custom Event Handler 2");
  }

  $(document).ready(function () {
    // Notice we can hook the event before it is called
    $(document).on(customEvent, customEventHandler1);
    $(document).on(customEvent, customEventHandler2);

    // generate a new custom event for each click
    $('#eventGen').on('click', function () {
      $.event.trigger(customEvent);
    });
    // once we release the handlers, they are not called again
    $('#releaseEvent').on('click', function () {
      consoleOut("Handlers released");
      $(document).off(customEvent, customEventHandler1);
      $(document).off(customEvent, customEventHandler2);
    });
  });
</script>
</body>
</html>
```

在这个例子中，我们在页面上放置了两个按钮。第一个按钮触发一个事件，第二个按钮释放事件处理程序。在按钮下方是一个宽的`<div>`，用于显示消息。

在脚本标记内的代码首先创建一个名为`customEvent`的变量，它保存自定义事件的名称。事件的名称由您决定，但我建议使用包含公司反向域名的名称，因为您不希望将来的浏览器发布破坏您的代码，因为它使用了相同的事件名。然后，我们有两个不做任何特别有趣的事件处理程序。

最后，在文档准备就绪事件处理程序中，我们两次挂接了自定义事件。我们使用第一个按钮的点击事件来触发自定义事件，第二个按钮的点击事件来释放处理程序。

在这个例子中我们没有展示的一件事是如何将数据传递给自定义事件处理程序代码。幸运的是，这并不难，所以让我们用另一个例子来展示如何：

```js
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <script src="img/jquery-2.1.1.js"></script>
  <title>Chapter 8 Custom Events 2</title>
</head>
<body>
<div>&nbsp;<button id="stop">Stop Polling</button>&nbsp;<span id="lastNewUser"></span></div>
<hr/>
<div id="showUsers">
</div>
<script>
  var users = [];
  var newUser = "com.therockncoder.new-user";
  function showMessage(msg) {
    $('#lastNewUser').show().html(msg + ' welcome to the group!').fadeOut(3000);
  }
    function init() {
    function getUserName(user) {
      return user.name.first + " " + user.name.last;
    }
    function showUsers(users) {
      var ndx, $ptr = $('#showUsers');
      $ptr.html("");
      for (ndx = 0; ndx < users.length; ndx += 1) {
        $ptr.append('<p>' + getUserName(users[ndx]) + '</p>')
		}
    }
    function addNewNameToList(eventObj, user, count) {
      console.info("Add New Name to List = " + getUserName(user));
      users.push(user);
      showUsers(users);
    }
    function welcomeNewUser(eventObj, user) {
      var name = getUserName(user);
      showMessage(name);
      console.info("got New User " + name);
    }
    $(document).on(newUser, addNewNameToList);
    $(document).on(newUser, welcomeNewUser);}
  function startTimer() {
    init();
    var handleId = setInterval(function () {
      $.getJSON('http://api.randomuser.me/?format=json&nat=us').success(function (data) {
        var user = data.results[0].user;
        $.event.trigger(newUser, [user]);
      });
    }, 5000);
    $('#stop').on('click', function(){
      clearInterval(handleId);
      showMessage('Cancelled polling');
    });
  }
  $(document).ready(startTimer);
 </script>
</body>
</html>
```

让我们逐步走过代码，以确保我们理解它在做什么。

用户界面由一个标有**停止**的单个按钮和一条水平规则组成。会员将出现在水平规则下方，并且消息将出现在按钮旁边。

在脚本标记内，代码通过创建一个空数组来为用户准备和一个字符串来保存我们自定义事件的名称开始。代码包括三个主要函数：`showMessage`，`init`和`startTimer`。当文档准备就绪事件触发时，它调用`init`方法，然后调用`startTimer`方法。

`startTimer`方法每 5 秒重复调用一次随机用户 Web 服务。每次调用它都会给我们一个新的随机用户。在`init`方法中，我们为我们的自定义事件建立了两个处理程序：`addNewNameToList`和`welcomeNewUser`。每个方法都获取事件提供的用户数据，并对其执行不同的操作。要停止示例程序，请单击**停止**按钮，它将清除间隔计时器。

# 使用单元测试

单元测试是一个有趣的主题。似乎每个人都认同编写测试是好的，但很少有人真的这样做。对单元测试的完整检查需要一本完整的书来完成，但希望我们可以涵盖关于单元测试的足够内容，以向您展示如何将其添加到您的代码中，并解释为什么您应该这样做。

我偏爱的单元测试框架是 Jasmine，[`jasmine.github.io/`](http://jasmine.github.io/)。这并不是贬低其他优秀的可用框架，但 Jasmine 可以在前端和后端工作，在浏览器和命令行中工作，正在积极维护，并且提供了一个测试框架所需的所有功能。请记住，虽然这段代码是为 Jasmine 编写的，但这些原则可以应用到任何 JavaScript 单元测试框架上。在我们学习如何编写单元测试之前，我们应该先讨论为什么要编写单元测试。

## 到底为什么要编写单元测试呢？

起初，网站中极少使用 JavaScript。当使用时，只是做一些如果禁用 JavaScript 也能生存下去的小事情。所以，需要 JavaScript 的事物清单很少，主要是客户端表单验证和简单动画。

如今，事情已经改变了。许多网站在禁用 JavaScript 时根本无法运行。其他一些网站在有限功能下可以运行，并通常会显示缺少 JavaScript 的警告。因此，我们如此严重地依赖于它，测试它是有意义的。

我们编写单元测试有三个主要原因：验证我们的应用程序是否正常运行，验证修改后它是否继续正常运行，最后，当使用**测试驱动开发**（**TDD**）或**行为驱动开发**（**BDD**）时，指导我们的开发。我们将专注于第一个原因，验证我们的应用程序是否正常运行。为此，我们将使用 Jasmine 行为驱动的 JavaScript 测试框架。Jasmine 可以从命令行或浏览器运行。我们将只从浏览器中使用它。

为了保持我们的示例简短，我们将运行典型的单元测试示例：一个算术计算器。它将能够对两个数字进行加、减、乘和除运算。为了测试计算器，我们将需要三个文件：`SpecRunner.html`、`calculator.js`和`calculator-spec.js`。`SpecRunner.html`加载其他两个文件和 Jasmine 框架。这是`SpecRunner.html`文件：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Jasmine Spec Runner v2.2.0</title>
  <!-- Jasmine files -->
  <link rel="shortcut icon" type="image/png" href="../libs/jasmine-2.3.4/jasmine_favicon.png">
  <link rel="stylesheet" href="../libs/jasmine-2.3.4/jasmine.css">
  <script src="img/jasmine.js"></script>
  <script src="img/jasmine-html.js"></script>
  <script src="img/boot.js"></script>

  <!-- System Under Test -->
  <script src="img/calculator.js"></script>

  <!-- include spec files here... -->
  <script src="img/calculator-spec.js"></script>
</head>
<body>
</body>
</html>
```

`SpecRunner.html`中没有特别具有挑战性的地方。除了 Jasmine 运行所需的文件之外，你还需要放置你的应用程序——不是全部，只需要单元测试能够运行的必要部分和单元测试文件。按照传统，单元测试文件的名称与它们测试的文件相同，只是在末尾加上了`-spec`。

这是`calculator.js`文件：

```js
var calculator = {
  add: function(a, b){
    return a + b;
  },
  subtract: function(a, b){
    return a -b;
  },
  multiply: function(a, b){
    return a * b;
  },
  divide: function(a, b){
    return a / b;
  }
};
```

我们的计算器简单易懂。它是一个 JavaScript，有四个功能：加法、减法、乘法和除法。测试其功能应该同样简单，实际上也是如此。这是测试计算器的`spec`文件：

```js
describe("Calculator", function() {

  it("can add numbers", function(){
    expect(calculator.add(12, 3)).toEqual(15);
    expect(calculator.add(3000, -100)).toEqual(2900);
  });

  it("can subtract numbers", function(){
    expect(calculator.subtract(12, 3)).toEqual(9);
  });

  it("can multiply numbers", function(){
    expect(calculator.multiply(12, 3)).toEqual(36);
  });

  it("can divide numbers", function(){
    expect(calculator.divide(12, 3)).toEqual(4);
  });
});
```

Jasmine 的单元测试框架围绕三种方法工作：`describe`、`it` 和 `expect`。`describe` 是一个全局函数，用于保存一个测试套件。它的第一个参数是一个字符串，表示测试套件的名称。第二个参数是一个作为测试套件的函数。接下来是 `it`。

与 `describe` 类似，`it` 是 Jasmine 中的全局函数，`it` 包含一个规范或 spec。传递给 `it` 的参数也是一个字符串和一个函数。按照传统，字符串的编写应该使得当与 `it` 一起阅读时，它完整描述了规范。函数使用一个或多个期望进行测试。

期望是使用 `expect` Jasmine 函数创建的。`expect` 相当于其他单元测试框架中的 `assert`。它被传递一个参数，即要测试的值，该值调用 Jasmine 中的实际值。在期望之后链接的是 `matcher` 函数。`matcher` 函数被传递了期望的值。

Jasmine 中 `expect` 和 `matcher` 函数的组合是其最美丽的之一。当编写正确时，它们的阅读就像一句英文句子。这使得编写测试和以后阅读测试都很容易。Jasmine 还提供了大量的匹配器，这有助于您编写出您想要的期望。还有一个 `not` 运算符，它将反转任何 `matcher` 函数的逻辑。

要运行示例测试，只需启动 `SpecRunner.html` 页面。它将加载 Jasmine，我们要测试的代码部分以及规范。按照单元测试的传统，页面要么是绿色的，这意味着我们的所有规范都已通过，要么是红色的，这意味着至少有一个规范失败了。

Jasmine 的目标是帮助我们找到并修复破碎的测试。例如，如果我们的添加规范失败了，我们将在红色中看到测试套件的名称和失败的规范一起显示："计算器可以添加数字。"下面是失败的期望。它将向我们展示它的值以及我们期望的值。

在示例代码中，我们使用 `describe` 方法创建我们的测试套件。我们有规范，每个规范测试我们的计算器的一个方面。请注意我们如何使我们的规范的措辞读起来像句子。我们的第一个规范是“它可以添加数字”。当我们的测试通过时，我们将看到测试套件显示单词“计算器”以及下面列出的每个规范，开始测试什么。

Jasmine 还具有 `setup` 和 `teardown` 函数。`setup` 函数在测试套件中的每个规范运行之前执行。`teardown` 函数在每个规范运行后执行。在示例代码中我们没有使用它们，但在更复杂的测试中它们可能非常有用，特别是当需要准备和清理对象之后。

Jasmine 是一个完整的单元测试框架。我们只是揭开了它的冰山一角。还要记住，虽然从浏览器运行 Jasmine 很方便，但是从命令行运行它会更加强大。那样，它就能够集成到你的网站构建流程中。但这只是一个介绍；要完全体会 Jasmine 如何帮助你编写更干净的代码，并帮助你测试 jQuery，你需要在你的代码中尝试它。

# 摘要

在本章中，我们涵盖了很多思想。开发者经常忘记 JavaScript 是一种面向对象的语言，但它不是一种基于类的语言。要牢记的最重要的事情之一是关注点分离的技术。这是保持你的代码易于理解和可维护的基石。学习关于 SoC 的知识引导我们进入了将代码分解为逻辑单元和使用事件来解耦我们的代码的主题。我们在本章结束时学习了如何使用流行的开源工具 Jasmine 对我们的代码进行单元测试。

现在我们已经学会了如何组织我们的代码，是时候把注意力转向与 jQuery 相关的其他人抱怨的事情了：性能。在下一章中，我们将学习如何衡量我们代码的性能以及可以做些什么简单的事情来加快它的速度。相当多的博客文章似乎认为 jQuery 是许多网站速度缓慢的原因。如果你不了解 JavaScript 或 jQuery，很容易得出这个结论。幸运的是，学习一些经验法则并不难，这些法则可以极大地提高你的 jQuery 代码的速度。


# 第九章：加速 jQuery

jQuery 的批评者有两个合理的抱怨。第一个抱怨是 jQuery 会创建难以阅读的、纷乱的代码。在上一章中，我们通过展示如何编写既易于阅读又易于维护的代码来解决了这个问题。第二个抱怨是 jQuery 会创建慢速的代码。这也是一个合理的抱怨。jQuery 或任何其他库的问题在于，如果你不理解它，很容易选择错误的方式来做某事。在本章中，我们将解决第二个抱怨：慢速的 jQuery 代码。

当然，jQuery 本身是用高度性能调优的 JavaScript 编写的；事实上，我强烈建议你研究它的源代码。jQuery 的性能问题通常在于不理解它的工作原理。正是这种缺乏理解导致程序员编写了低效的代码。但幸运的是，jQuery 并不难理解，当我们将这种理解与性能测量工具结合起来时，我们可以轻松提高代码的性能。

在本章中，我们将：

+   学习如何测量我们的 JavaScript 代码的速度

+   测量不同 jQuery 代码片段的性能

+   学会何时不使用 jQuery，而是使用纯 JavaScript

# 编写性能测试

在我们担心如何提高应用程序的性能之前，我们应该先学习如何衡量它。简单地说“应用程序感觉迟缓”是不够的。要想提高应用程序的性能，必须在改进之前能够对其进行测量。幸运的是，过去几年我们的浏览器已经有了许多改进。其中一项改进是用户计时 API。虽然它只是 W3C 的建议，不是所有浏览器的官方组成部分，但现代版本的所有主要浏览器都支持它，除了 Safari。我们不会将测量代码与应用程序一起部署，因此缺少 Safari 支持虽然令人遗憾，但并不致命。

我知道有些人想知道为什么我们需要一种新的时间测量方式。自从 2009 年 ECMAScript 5.1 引入以来，我们就有了 `Date.now()`，之前是 `new Date().getTime()`。问题在于分辨率；最好的情况下，`Date.now()` 的准确度只有 1 毫秒，这显然是不够好的。计算机可以在 1 毫秒内执行大量的 JavaScript 指令。

用户定时 API 易于使用。我们不打算解释其所有功能。我们只会展示足够的内容来帮助我们编写性能测量代码。我们需要了解的第一个函数是`performance.now()`。它类似于`Date.now()`，因为它返回当前系统时间，但它在两个重要方面有所不同：首先，它返回一个浮点值，而不是像`Date.now()`一样返回整数值。浮点值表示 1 微秒或千分之一毫秒的精度。其次，`performance.now()`是单调递增的，这是一个花哨的说法，意味着它总是增加的。这意味着每当连续调用时，第二次调用的值总是大于第一次调用的值。这是`Date.now()`无法保证的。这可能看起来很奇怪，但`Date.now()`不是单调递增的。`Date.now()`基于时间，大多数系统都有一个进程，通过每 15 或 20 分钟调整`Date.now()`几毫秒来保持时间同步。因为`Date.now()`的分辨率最好是毫秒级，所以在比它更短的时间内发生的任何事情都会被舍入为 0。一个简单的例子会更好地解释这个问题：

```js
  function dateVsPerformance() {
    var dNow1 = Date.now();
    var dNow2 = Date.now();
    var pNow1 = performance.now();
    var pNow2 = performance.now();

    console.info('date.now elapsed: ' + (dNow2 - dNow1));
    console.info('performance.now elapsed: ' + (pNow2 - pNow1));
  }
```

前面的代码非常简单。我们连续调用了`Date.now()`和`performance.now()`，然后显示经过的时间。在大多数浏览器中，`Date.now()`的经过时间将为零，我们本能地知道这不可能是真的。无论你的计算机有多快，执行每条指令总是需要一定的时间。问题在于分辨率：`Date.now()`以毫秒分辨率运行，而 JavaScript 指令需要微秒级别的执行时间。

### 提示

1 毫秒等于 1,000 微秒。

幸运的是，`performance.now()`具有微秒分辨率；它总是显示任意两次调用之间的差异。连续调用时，它通常处于次毫秒级别。

`Performance.now()`是一个非常有用的方法，但它并不是性能工具箱中的唯一工具。用户定时 API 的创建者意识到我们大多数人都会测量我们应用的性能，所以他们编写了方法来简化操作。首先，有`performance.mark()`方法；当传递一个字符串时，它将使用传递的字符串作为键内部存储`performance.now()`的值：

```js
performance.mark('startTask1');
```

上面的代码存储了一个名称为`startTask1`的性能标记。

接下来是`performance.measure()`。它将创建一个命名的时间测量。它有三个字符串作为参数。第一个字符串是测量的名称。第二个字符串是起始性能标记的名称，最后一个字符串是结束性能标记的名称：

```js
performance.measure('task', 'startTask1', 'endTask1');
```

用户定时 API 将使用名称作为键在内部存储测量值。为了查看我们的性能测量，我们只需要请求它们。最简单的方法是请求所有测量值，然后循环显示每个测量值。以下代码演示了这种技术：

```js
<!DOCTYPE html>
<html>
<head lang="en">
  <meta charset="UTF-8">
  <script src="img/"></script>
  <title>Chapter09 - User Timing API</title>
</head>
<body>
<script>
  function showMeasurements() {
    console.log('\n');
    var entries = performance.getEntriesByType('measure');
    for (var i = 0; i < entries.length; i++) {
      console.log('Name: ' + entries[i].name +' Start Time: ' + entries[i].startTime +' Duration: ' + entries[i].duration + '\n');
    }
  }
  function delay(delayCount) {
    for (var ndx = 0; ndx < delayCount; ndx++) {
    }
  }
  function init() {
    performance.mark('mark1');
    delay(1000);
    performance.mark('mark2');
    delay(10);
    performance.mark('mark3');
    performance.measure('task1', 'mark1', 'mark2');
    performance.measure('task2', 'mark2', 'mark3');
    showMeasurements();
    performance.clearMeasures();
  }
  $(document).ready(init);
 </script>
</body>
</html>
```

### 提示

前面的代码将所有结果显示在浏览器控制台上；不会显示到文档中。

操作始于代码挂钩文档就绪事件，调用 `init()` 函数。调用 `performance.mark()` 创建了一个 `mark1` 标记。然后我们调用 `delay()`，计数器值为 1,000，模拟一个有用任务的性能，然后再次调用 `performance.mark()`，创建另一个性能标记 `mark2`。同样，我们调用 `delay()`，这次计数器为 10，创建另一个性能标记 `mark3`。

现在我们有了三个性能标记。为了确定每个模拟任务花费了多长时间，我们需要使用 `performance.measure()` 方法来测量标记。它需要三个参数：测量名称、初始标记名称和最终标记名称。每个测量将被记录并存储在性能对象的内部。为了查看测量值，我们调用 `showMeasurements()` 方法。

`showMeasurements()` 方法首先调用 `performance.getEntriesByType('measure')`。这个方法返回一个数组，其中包含由 performance 对象记录的所有性能测量。数组中的每个项目都是一个包含性能测量名称、开始时间和持续时间的对象。它还包含其性能类型，但我们不显示它。

我们最后要做的事情是调用 `performance.clearMeasures()`。请记住，性能对象在内部存储所有的标记和测量值。如果偶尔不清除它们，你的测量列表可能会变得非常长。当调用 `performance.clearMeasures()` 时没有参数，它会清除所有保存的测量值。它还可以用测量名称调用以清除。你可以通过调用 `performance.clearMarks()` 来清除已保存的标记。不带参数调用会清除所有保存的标记，带有标记名称的调用会清除标记。

## 测量 jQuery

现在我们有了一种测量 JavaScript 性能的方法，让我们测量一些 jQuery：

```js
<!DOCTYPE html>
<html>
<head lang="en">
  <meta charset="UTF-8">
  <link href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css" rel="stylesheet"/>
  <script src="img/jquery.js"></script>
  <script src="img/bootstrap.min.js"></script>
  <title>Chapter 9 - Measure jQuery</title>
</head>
<body>
<nav class="navbar navbar-inverse navbar-fixed-top">
  <div class="container">
    <div class="navbar-header">
      <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar"
              aria-expanded="false" aria-controls="navbar">
        <span class="sr-only">Toggle navigation</span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
      </button>
      <a class="navbar-brand" href="#">Measuring jQuery</a>
    </div>
    <div id="navbar" class="navbar-collapse collapse">
      <form class="navbar-form navbar-right">
        <div class="form-group">
          <input type="text" placeholder="Email" class="form-control">
        </div>
        <div class="form-group">
          <input type="password" placeholder="Password" class="form-control">
        </div>
        <button type="submit" class="btn btn-success">Sign in</button>
      </form>
    </div>
  </div>
</nav>
```

在上述代码中，实际上没有什么复杂的。它使用 Bootstrap 和 jQuery 创建一个导航栏。`nav` 栏并不完全功能；它只是让我们的 jQuery 代码遵循一些标记来解析：

```js
<!-- Main jumbotron for a primary marketing message or call to action -->
<div class="jumbotron">
  <div class="container">
    <h1>Chapter 9</h1>

    <p>This is a template for a simple marketing or informational website. It includes a large callout called a
      jumbotron and three supporting pieces of content. Use it as a starting point to create something more
      unique.</p>

    <p><a class="btn btn-primary btn-lg" href="#" role="button">Learn more "</a></p>
  </div>
</div>

<div class="container">
  <!-- Example row of columns -->
  <div class="row">
    <div class="col-md-4 bosco">
      <h2>First</h2>

      <p>I am the first div. Initially I am the on the left side of the page. </p>

      <p><a class="btn btn-default" href="#" role="button" name="alpha">View details "</a></p>
    </div>
    <div id="testClass" class="col-md-4 ">
      <h2>Second</h2>

      <p>I am the second div. I begin in-between the other two divs. </p>

      <p><a id='find-me' class="btn btn-default find-me" href="#" role="button" name="beta">View details "</a></p>
    </div>
    <div class="col-md-4">
      <h2>Third</h2>

      <p>I am the third div. Initially I am on the right side of the page</p>

      <p><a class="btn btn-default" href="http://www.google.com" role="button" name="delta">View details "</a></p>
    </div>
  </div>

  <hr>
  <form class="myForm">
    <div class="input-group">
      <select id="make" class="form-control">
        <option value="buick">Buick</option>
        <option value="cadillac">Cadillac</option>
        <option value="chevrolet">Chevrolet</option>
        <option value="chrysler">Chrysler</option>
        <option value="dodge">Dodge</option>
        <option value="ford">Ford</option>
      </select>
    </div>
    <div class="input-group">
      <select id="vehicleOptions" multiple class="form-control">
        <option selected value="airConditioning">air conditioning</option>
        <option value="cdPlayer">CD player</option>
        <option selected value="satelliteRadio">satellite radio</option>
        <option value="powerSeats">power seats</option>
        <option value="navigation">navigation</option>
        <option value="moonRoof">moon roof</option>
      </select>
    </div>
    <div class="input-group">
      <label for="comments" class="">Comments:</label>
      <textarea id="comments" class="form-control"></textarea>
    </div>
    <div class="input-group">
      <input type="text" id="firstName" class="form-control" placeholder="first name" value="Bob"/>
      <input type="text" id="lastName" class="form-control" value="" placeholder="last name"/>
    </div>
  </form>
  <hr>

  <footer>
    <p>© Company 2015</p>
  </footer>
</div>
```

前面的标记是主要内容。同样，我们只是给自己一些丰富的 HTML 来解析：

```js
<script type="text/javascript">
  function showMeasurements() {
    console.log('\n');
    var entries = performance.getEntriesByType('measure');
    for (var i = 0; i < entries.length; i++) {
      console.log('Name: ' + entries[i].name +
        ' Duration: ' + entries[i].duration + '\n');
    }
  }

  function init() {
    var ptr1, ptr2;

    performance.mark('mark1');
    ptr1 = $('#testClass > .find-me');
    performance.mark('mark2');
    ptr2 = $('#testClass').find('#find-me');
    performance.mark('mark3');

    performance.measure('with selectors', 'mark1', 'mark2');
    performance.measure('selector+find ', 'mark2', 'mark3');
    showMeasurements();
    performance.clearMeasures();
  }

  $(document).ready(init);
</script>
</body>
</html>
```

上述代码测量了两种不同的 jQuery 代码片段的速度。这两个片段返回一个指向相同元素的 jQuery 对象：具有类名 `find-me` 的唯一锚点标签。有更快的方法来查找元素，我们稍后会介绍这些方法，但现在，我们希望解决我们测量技术中的一个问题。

当代码运行时，它在控制台中显示两个测量值。第一个测量值是使用选择器查找 jQuery 对象所花费的时间。第二个测量值是使用 `id` 选择器结合 `find()` 方法的时间。第二种方法更加优化，应该更快。

当你重复运行测试代码时，问题最明显。每次运行的时间都会有所不同，但它们的变化可以很大，有时，本应更快的代码却更慢。再次运行计时代码，突然间它就变快了。怎么回事？嗯，虽然 JavaScript 是单线程的，我们无法中断我们的代码，但浏览器不是单线程的，操作系统也不是。有时，在我们的测试代码运行时，另一个线程上可能会发生其他事情，导致它看起来变慢。我们能做些什么来解决这个问题呢？

答案是利用平均法则，执行足够多次代码以消除偶尔的小问题。考虑到这一点，这是我们计时代码的改进版本。标记与之前版本相同；只有`<script>`标签中的代码发生了变化：

```js
<script type="text/javascript">
  function showMeasurements() {
    console.log('\n');
    var entries = performance.getEntriesByType('measure');
    for (var i = 0; i < entries.length; i++) {
      console.log('Name: ' + entries[i].name +
        ' Duration: ' + entries[i].duration + '\n');
    }
  }

  function multiExecuteFunction(func) {
    var ndx, counter = 50000;
    for (ndx = 0; ndx < counter; ndx += 1) {
      func();
    }
  }

  function init() {     performance.mark('mark1');
    multiExecuteFunction(function () {
      var ptr1 = $('#testClass > .find-me');
    });
    performance.mark('mark2');

    multiExecuteFunction(function () {
      var ptr2 = $('#testClass').find('#find-me');
    });
    performance.mark('mark3');

    performance.measure('with selectors', 'mark1', 'mark2');
    performance.measure('selector+find ', 'mark2', 'mark3');
    showMeasurements();
    performance.clearMeasures();
  }

  $(document).ready(init);
</script>
```

在代码的新版本中，我们唯一改变的是调用 jQuery 代码的方式。我们不再只调用一次，而是将其传递给一个调用它数千次的函数。代码应该被调用的实际次数取决于你。我喜欢在 10,000 到 100,000 次之间调用它。

现在我们有了一个相当直接和精确的方法来测量我们代码的速度。请记住，我们不应该将性能测量代码与我们的生产网站一起部署。让我们深入了解 jQuery 选择器，以便我们可以理解如何使用正确的选择器可以显著提高我们代码的性能。

# jQuery 选择器

关于选择器的第一件事情是，它们是对浏览器的文档对象模型（DOM）的调用，而所有与 DOM 的交互都很慢。即使是了解 DOM 很慢的开发人员有时也不明白 jQuery 像所有代码一样使用 DOM，它将标记呈现到浏览器页面。选择器是 jQuery 的核心，选择器中的小差异可能导致代码速度的巨大差异。重要的是我们要了解如何编写快速有效的选择器。

## 使用 ID 而不是其他选择器

最快的选择器是基于最快的底层 DOM 代码的选择器。一个快速的基于 DOM 的元素查找方法是 `document.getElementById()`，所以最快的 jQuery 选择器是基于 `id` 选择器的那个。

这并不意味着你应该在你的标记上给每个元素都标上 ID。当有必要时，你应该继续在元素上使用 ID，并使用`id`选择器快速找到它们或靠近它们的元素。

## 缓存你的选择器

对 jQuery 进行选择器评估的每次调用都是一个很大的处理时间投资。jQuery 必须首先解析选择器，调用 DOM 方法执行选择器，最后将结果转换为 jQuery 对象。记住，DOM 很慢。幸运的是，你可以缓存你的选择器。虽然你的代码第一次被调用时会有一个时间惩罚，但随后的调用速度会像他们能达到的那样快。

只要你不进行大量的 DOM 操作，这种方法就可以。通过大量，我是指在页面中添加或删除元素或使缓存选择器失效的其他操作。

## 选择器优化

所有的选择器并不都是平等的。选择正确的选择器可以对你的应用程序性能产生很大的影响，但选择正确的选择器可能会有些棘手。以下是一些提示，可以帮助你创建正确的选择器。请记住，如果对性能感到不确定，请进行测量。

### 从右到左

在 jQuery 的核心深处是 Sizzle 选择器引擎。Sizzle 从右往左读取。所以，你最具体的选择器应该在右边。想象一下，我们正在尝试找到一个具有`bubble`类的`<p>`标签。我们如何优化选择器呢？让我们看一个例子：

```js
var unoptimized = $('div.col-md-4 .bubble');
```

我们的第一个尝试看起来很好。但我们知道最具体的选择器应该在最右边，所以我们在第二个例子中稍微改变了一下：

```js
var optimized = $('.col-md-4 p.bubble');
```

在大多数浏览器中，这样做比第一个例子稍微快一些。在以前的 jQuery 版本中，差异更大。但不要担心；我们还有更多的优化。

### 减少过于具体的选择器

作为开发者，有时候我们会过度做一些事情。尤其在定义选择器时。如果你添加比所需更多的选择器来找到你要找的元素，你会让 jQuery 做更多的工作。尽量减少你的选择器，只留下必需的部分。

让我们看一个例子：

```js
// Too specific – don't do this
var overlySpecific = $('div.container div.row div.col-md-4 p.bubble');
```

这个选择器比以前的例子慢了。你的选择器应该足够具体，可以找到所需的元素，但不要过于具体。

### 缩小你的搜索范围

默认情况下，jQuery 将搜索整个文档，寻找与你的查询匹配的内容。通过缩小你的搜索范围，来帮助它进行搜索。

如果我们想要更快，而不在标记上加入过多的 ID 会怎么样？我们可以利用最近具有 ID 的父标签来执行如下操作：

```js
var fastOptimized = $('#testClass').find('.bubble');
```

## 其他 jQuery 优化

将要来的优化可能最好称为经验法则。它们会让你的代码变得更快，但不会有很大的变化。而且幸运的是，它们很容易遵循。

### 更新到最新版本

更新到最新版本可能是加快 jQuery 代码速度最简单的事情之一。在升级到新版本 jQuery 时，应该始终谨慎，但升级通常会带来提高的速度，以及新功能。现在您知道如何测量代码的性能，您可以在更改版本之前和之后进行测量，看看是否有改进。

不要期望性能有巨大变化，并阅读发布说明，看看是否有任何破坏性的改变。

### 使用正确的版本 jQuery

目前，jQuery 有两个分支：1.x 分支和 2.x 分支。如果您需要支持旧版本的 Internet Explorer，应该只使用 1.x 分支。如果您的网站只在现代浏览器上运行，并且 Internet Explorer 9 是您需要支持的最旧版本，那么您应该切换到 2.x 分支的 jQuery。

jQuery 的 2.x 分支不再支持 Internet Explorer 6、7 和 8，以及与此相关的所有麻烦。这使得代码执行更快，并且使库文件更小，下载速度更快。

### 不要使用已弃用的方法

废弃的方法是 jQuery 开发团队决定在将来版本中删除的方法。该方法实际上可能需要多年才会被移除。您应该尽快将这些方法从代码中删除。方法被弃用的原因可能不是性能问题，但您可以确信 jQuery 团队不会浪费时间优化被标记为弃用的方法。

### 在适当的时候使用 preventDefault()

最快的代码是不运行的代码。一旦事件被处理，其默认行为是向父元素传递，然后再传递给其父元素，一直到达根文档为止。所有这些冒泡都需要时间，如果您已经完成了所有必需的处理，这段时间可能就白白浪费了。

幸运的是，通过在事件处理程序中调用 `event.preventDefault()`，很容易阻止这种默认行为。这样可以阻止不必要的代码执行，并加快您的应用程序速度。

### 永远不要在循环中修改 DOM

永远记住，访问 DOM 是一个缓慢的过程。在循环中进行访问会加剧问题。最好将 DOM 的部分复制到 JavaScript 中，进行修改，然后再将其复制回去。在此示例中，我们将修改一个 DOM 元素，然后与几乎完全相同的修改不在 DOM 中的元素进行比较：

```js
  function showMeasurements() {
    console.log('\n');
    var entries = performance.getEntriesByType('measure');
    for (var i = 0; i < entries.length; i++) {
      console.log('Name: ' + entries[i].name +
        ' Duration: ' + entries[i].duration + '\n');
    }
  }

  function multiExecuteFunction(func) {
    var ndx, counter = 50000;
    for (ndx = 0; ndx < counter; ndx += 1) {
      func();
    }
  }

  function measurePerformance() {
    console.log('\n');
    var entries = performance.getEntriesByType('measure');
    for (var i = 0; i < entries.length; i++) {
      console.log('Name: ' + entries[i].name +
        ' Duration: ' + entries[i].duration + '\n');
    }
  }

  function init() {

    // unoptimized, modifying the DOM in a loop

    var cnt = 0;
    performance.mark('mark1');

    var $firstName = $('.myForm').find('#firstName');
    multiExecuteFunction(function () {
      $firstName.val('Bob ' + cnt);
      cnt += 1;
    });
    performance.mark('mark2');

    // Second optimized, modifying a detached object  

    var myForm = $('.myForm');
    var parent = myForm.parent();
    myForm.detach();
    cnt = 0;

    var $firstName = $('.myForm').find('#firstName');
    multiExecuteFunction(function () {
      $firstName.val('Bob ' + cnt);
      cnt += 1;
    });

    parent.append(myForm);
    performance.mark('mark3');

    performance.measure('DOM mod in loop ', 'mark1', 'mark2');
    performance.measure('Detached in loop', 'mark2', 'mark3');
    measurePerformance();
  }

  $(document).ready(init);
```

在前面的代码中，所有操作都在 `init()` 方法中。我们正在修改一个 `<input>` 标签的值。在第一个未经优化的处理过程中，我们在循环中修改了 DOM。我们做了一些聪明的事情，例如在循环开始之前将选择器缓存到变量中。这段代码一开始看起来速度还挺快的。

在第二次遍历时，在开始操纵元素之前，我们会将元素从 DOM 分离。实际上，我们必须编写更多的代码来做到这一点。首先，我们将表单缓存到名为 `myForm` 的变量中。然后，我们也将其父级缓存到一个变量中。接下来，我们使用 jQuery 的 `detach()` 方法将 `myForm` 从 DOM 中分离。

循环中的代码与我们的第一个版本相同。一旦退出循环，我们将 `myForm` 添加到其父级以恢复 DOM。虽然第二个版本中有更多的 JavaScript 代码，但比第一个版本快了约 5 倍。这就是一直值得追求的性能提升。

# jQuery 并不总是答案

jQuery 是有史以来最流行的 JavaScript 开源库。它在前 100,000 个网站中使用率超过了 60%。但这并不意味着你总是应该使用 jQuery；有时纯 JavaScript 是更好的选择。

## 使用 document.getElementById

当你要查找具有 ID 的 DOM 元素时，调用 `document.getElementById()` DOM 方法比使用 jQuery 更快。为什么？因为这正是 jQuery 在解释你的选择器后会做的事情。如果你不需要一个 jQuery 对象，只想要元素，那就节省几微秒的时间，自己调用 DOM。

```js
var idName = document.getElementById('idName');

```

该方法接受一个参数：`id` 元素的名称。请注意，名称前面没有井号。这不是 jQuery。如果找到元素，则返回对元素对象的引用。如果找不到，则返回 `null`。再次提醒，返回的值不是 jQuery 对象，因此不会附加 jQuery 方法。

还有其他可用的原生浏览器方法，总的来说，它们比用 JavaScript 编写的代码更快，无论是 jQuery、你自己的代码，还是其他库中的代码。另外两种方法是 `document.getElementsByTag()` 和 `document.getElementsByClassName()`。它们返回一个 `HTMLCollection` 对象，这是任何类似数组的元素集合。如果没有匹配，集合为空，长度为零。

### 提示

旧版浏览器，如 Internet Explorer 8，没有 `document.getElementsByClassName()`。因此，如果你需要支持旧版浏览器，在使用它之前应该检查此方法是否存在。如果存在浏览器的原生版本，jQuery 足够智能以使用它，如果缺少则使用自己的代码。

## 使用 CSS

jQuery 和 JavaScript 对许多事情是有用的，但并不应该被用于一切。诸如对元素进行动画、旋转、变换和平移等操作通常可以更顺畅更快捷地使用 CSS。jQuery 有一些使用 CSS 的方法。然而，通过编写自己的 CSS，你可以获得符合自己需求的结果。CSS 可以利用主机系统的**图形处理单元**（**GPU**）来生成无法用任何 jQuery/JavaScript 复制的结果。

# 总结

我们从学习如何测量代码性能开始这一章节。然后，我们将这些知识应用到实践中，测量不同选择器的速度，同时学习如何编写更好、更快的选择器。我们还学习了一些改进代码速度的 jQuery 最佳实践。最后，我们意识到 jQuery 并不总是答案。有时，更好的代码来自于使用普通的 JavaScript 或 DOM 方法。

在最后一章中，我们将介绍 jQuery 插件。插件是一些令人惊叹的功能，全部包装在易于使用的包中。函数使我们能够轻松地将图形小部件，例如日历、滑块和图片轮播，添加到我们的应用中。我们将学习如何使用插件，如何找到它们，最后，如何编写我们自己的插件。


# 第十章：利用插件充分利用他人的工作

在上一章中，我们学习了如何计时我们的代码，然后了解了如何改进我们的 jQuery 代码的性能。完成这些后，让我们把注意力转向第十章，关于 jQuery 插件的第十章。插件坚持 jQuery 的口号“写得更少，做得更多”。它们使您能够利用他人的工作，并轻松地将他们的工作插入到您的应用程序中。

在本章中，我们将学习关于 jQuery 插件的知识。jQuery 的核心是其原型对象。插件是一个扩展了 jQuery 原型对象的对象，使得所有 jQuery 对象都能够获得新的功能。jQuery 有一个官方支持的一组 UI 插件，称为 jQuery UI。有数千个免费插件可用，但要找到好的插件需要耐心和谨慎。在本章中，我们将涵盖以下内容：

+   查找和安装插件

+   jQuery UI

+   编写您自己的插件

+   插件最佳实践

# 查找插件

如果你在 jQuery 的任何网站上点击**插件**菜单，你将被带到 jQuery 插件注册页面。虽然该网站确实有很多插件，但它们都很老旧，多年未更新。不用担心，jQuery Foundation 的人们决定鉴于他们有限的资源，没有必要自己打包插件。互联网已经有几个流行的包管理器；其中两个比较流行的是 npm 和 Bower。jQuery 团队建议插件发布者切换到使用 npm。

Node Package Manager，或者 npm，最初只是为 Node.js web 框架提供包。但它们易于使用和原生跨平台的能力使得 npm 被广泛应用为各种应用程序的包管理器。许多命令行工具、移动框架和其他实用程序应用程序都以 npm 模块的形式实现。难怪 jQuery 团队将其作为 jQuery 插件的首选包管理器。

查找 jQuery 插件在 npm 上很容易。只需转到[`www.npmjs.com/`](https://www.npmjs.com/)网站。在搜索框中，输入`jquery-plugin`。在撰写本文时，已有超过 1200 个 jQuery 插件可用。找到插件很容易；难的是决定使用哪个插件。

想象一下你正在寻找一个工具提示插件。忽略，以本例为例，jQuery UI 库中是否有插件。你首先要做的事情是在 npm 搜索栏中输入`jquery-plugin tooltip`。在决定在你的代码中使用插件之前，你应该问自己哪些问题？首先可能是项目是否正在积极维护？其他问题可能包括它是否具有通过的单元测试？源代码是否干净且写得好？它是否依赖于其他插件？是否有清晰的带有示例代码的文档？它使用何种许可证？是否有任何未解决的问题？如果源代码在 GitHub 上，是否有任何星标？

只有在你做了尽职调查并确信这是一个高质量的插件后，才应该在你的代码中使用它。向 npm 添加插件的门槛非常低，所以有很多糟糕的插件。有些构建得很差，有些是老旧的且未被维护，甚至可能有一些恶意的。

### 提示

npm 管理的是包，而不是插件。jQuery 插件是一种特殊类型的 npm 包。在本章中，我将使用“插件”这个词，但实际上指的是一个包含 jQuery 插件的 npm 包。

# 安装插件

你已经找到了一个或两个喜欢的插件，那么接下来呢？通过 npm 安装插件也很容易，但首先你需要确保你的应用程序根目录下有一个 `package.json` 文件。这是 npm 要求的一个 JSON 文件。如果没有 `package.json` 文件，npm 将不会安装你的插件。以下是一个相当简约的 `package.json` 文件的示例：

```js
{
  "name": "plugins",
  "version": "1.0.0",
  "description": "A demo of using and writing plugins",
  "repository": "none",
  "license": "MIT",
  "dependencies": {
    "tipso": "¹.0.6"
  }
}

```

请注意它是一个 JSON 文件，而不是 JavaScript 对象。第一个字段是应用程序的名称。名称是一个必需的字段；如果没有，npm 将不会安装包。如果你正在创建一个插件并计划将其上传到 npm，那么名称必须是唯一的。

第二个字段是应用程序的版本号。这也是必需的。在创建自己的插件时，放置在这里的值非常重要。是否升级插件是基于 npm 存储的此字段值与用户本地副本进行比较而确定的。

接下来的三个字段不是必需的，但如果在安装插件时缺少它们，将会生成警告。第一个是描述字段，它是描述应用程序的简短语句。然后是存储库字段。如果存在有效的存储库，它将包含一个子对象，其中包含两个字段：类型和 URL。类型标识使用的源控制类型，如 `git` 和 `svn`。最后，有许可证字段，它是插件发布的软件许可证类型。在你的应用程序根目录下创建一个 `package.json` 文件。

在安装 npm 包之前，你需要安装 Node.js。npm 已经包含在 Node.js 中，所以请前往 [`nodejs.org/`](https://nodejs.org/) 下载并安装适合你系统的版本。安装完 Node 后，你会想要升级 npm。我知道这看起来很奇怪，但 Node 和 npm 是不同的发布周期，Node 自带的 npm 版本通常已经过时了。

要升级 npm，请输入：

```js
npm install npm -g

```

在 Mac 和 Linux 系统上，你可能需要使用 `sudo` 命令。安装并升级完 npm 后，你终于准备好安装一个插件了。在终端或命令提示符下输入以下内容：

```js
npm install <name of package> --save

```

示例`package.json`文件显示了另一个字段：dependencies。这是一个键值对的字典。键是您的应用程序依赖的软件包的名称，而值通常是它的版本号。在安装软件包时，如果在命令的末尾加上`--save`，此字段会自动生成。

使用`sudo`命令时需要特别小心。它以 root 权限执行命令。如果要执行的命令有恶意意图，它可以做几乎任何事。您可以将自己的帐户设置为 npm 安装软件包的目录（/user/local）的所有者，而不使用`sudo`命令。只需执行以下命令：

```js
sudo chown –R $USER /usr/local

```

这是更改所有者（`chown`）命令。它会将您的帐户设置为`/usr/local 目录`的所有者。`–R`告诉`chown`递归遍历所有子目录，使您的帐户也成为它们的所有者。

## 更新插件

偶尔，您的应用程序所依赖的软件包将得到改进。为了升级所有依赖项，您可以运行升级命令，而不指定软件包。

```js
npm update --save

```

此命令将检查`package.json`文件中的每个软件包，并更新所有过时的软件包。完成后，它还将使用新的版本号更新`package.json`文件。

如果您希望对使用更新命令更有针对性一些，可以提供要更新的软件包的名称。

```js
npm update <name of package> --save

```

此命令将仅更新命令中指定的软件包。如果更新了软件包，它将在`package.json`文件中更新其版本号。

## 卸载插件

如果您需要删除插件，可以使用`uninstall`命令。`uninstall`命令将通过从`node_modules`中删除所有相关文件并更新`package.json`文件来删除一个软件包。在执行此命令之前请三思，因为此操作不可逆转。如果使用`–save`选项，它还将更新`package.json`文件。

```js
npm uninstall <package-name> --save

```

## 添加插件

现在我们知道如何安装、更新和移除 npm 软件包了，让我们为我们的应用程序添加流行的`m-popup`插件。它是一个创建轻量级和可定制模态弹出窗口的插件。您可以在[npm](https://www.npmjs.com/package/m-popup)上找到它。这是插件的主页，您会在这里找到有关插件的大量信息。通常包含作者的姓名、许可证类型、编码示例和安装说明。安装说明通常在右上角。要安装`m-popup`，输入以下命令：

```js
npm install m-popup

```

请注意从应用程序的根目录执行该命令，并请注意这里没有`–g`。`–g`选项仅在全局安装软件包时使用，但这里不适用。安装插件时，是从位于`package.json`文件的根目录进行操作的。

在安装期间，npm 会创建一个目录，`node_modules`，如果之前不存在的话。在其中，将创建另一个目录，`m-popup`。目录的名称始终是包的名称。这也是为什么 npm 包必须具有唯一名称的部分原因。

每个包的内容都不同，因此您可能需要四处探索以找到您需要的文件；通常它们将位于名为 `dist` 或可能是名为 `src` 的目录中。我们正在寻找需要添加到我们的应用程序中的插件工作所需的文件。包页面上的说明通常会告诉我们文件的名称，但不会告诉我们它们所在的目录。在我们的情况下，我们需要两个文件，一个 CSS 和一个 JS，它们都在 `dist` 目录中。

```js
<!DOCTYPE html>
<html>
<head lang="en">
  <meta charset="UTF-8">
  <link href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css" rel="stylesheet"/><script src="img/jquery.js"></script>
  <script src="img/bootstrap.min.js"></script>
  <!-- These are the includes for the popup, one for CSS the other for JS -->
  <link rel="stylesheet" href="node_modules/m-popup/dist/mPopup.min.css"/>
  <script src="img/mPopup.jquery.min.js"></script>
  <style>
    .mPopup {
      /* popup modal dimensions */
      width: 60%;height: 300px;
    }
  </style>
  <title>Chapter 10 - Adding a Plugin</title>
</head>
<body>
<div class="jumbotron">
  <div class="container">
    <h1>Chapter 10</h1>
    <p>Adding a jQuery plugin is an easy way to add more functionality to your site.</p>
    <p><a id="displayPopup" class="btn btn-primary btn-lg" href="#" role="button">Display Popup</a></p>
  </div>
</div>
<!-- this is the popup's markup -->
<div id="sample1" class="mPopup">
  <button class="mPopup-close">×</button>
  <div class="popup-header">Popup title</div>
  <div class="popup-body">
    Content goes here.
    Dismiss popup by clicking the close x in the upper right corner or by clicking on the greyed out background.</div>
</div>
<script type="text/javascript">
  function init() {
    var popup = $('#sample1').mPopup();
    var button = $('#displayPopup').on('click',function(){
      popup.mPopup('open');
    });
  }
  $(document).ready(init);
</script>
</body>
</html>
```

此代码链接了 m-popup 的 CSS 文件和其 JavaScript 文件，然后创建了一个 CSS 类，该类设置了弹出模态框的宽度和高度。最好将 CSS 移动到自己的文件中。接下来，我们在标记的末尾添加了一些 HTML，就在脚本标记之前。

这是定义弹出窗口的 HTML。类 `mPopup` 还使标记在页面上最初处于隐藏状态。该插件定义了两个部分，标题和正文，分别由类 `popup-header` 和 `popup-body` 表示。

激活插件的代码非常简单。

代码等待文档就绪事件，然后调用 `init` 方法。在 `init` 方法中，我们获取对我们的弹出窗口的引用，并钩住按钮的点击事件。当单击按钮时，我们使用字符串 `open` 调用 `mPopup` 方法，这是我们调用的 `popup` 方法的名称。要退出模态框，请单击模态框右上角的 **close** 按钮或在灰色覆盖层的任何位置。

此插件还可以执行许多其他操作。要了解更多信息，请阅读 npm 上的插件包页面。您甚至可能想要研究其源代码。

# jQuery UI

jQuery 团队管理着称为 jQuery UI 的一组 UI 小部件、交互、效果和主题。该集合是一组插件。jQuery UI 的主页是 [`jqueryui.com/`](http://jqueryui.com/)。让我们快速了解一下 jQuery UI 是什么以及如何使用它。

jQuery UI 由四个主要组件组成：交互（interactions）、小部件（widgets）、效果（effects）和核心（core）。只有核心是必需的，因此下载系统允许您仅选择您想要的组件，以创建自定义版本。

## jQuery UI 交互

交互是使页面元素活跃并能够以新方式移动的方法。例如，您可以使可拖放的 div。其他交互方式包括：可调整大小的、可选择的和可排序的。交互可以单独或组合使用，并帮助您使您的网站流动和交互式。与大多数 jQuery UI 一样，交互很容易使用。让我们看看有多容易：

```js
<!DOCTYPE html>
<html>
<head lang="en">
  <meta charset="UTF-8">
  <link href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css" rel="stylesheet"/><script src="img/jquery.js"></script>
  <script src="img/bootstrap.min.js"></script>
  <link href="jquery-ui/jquery-ui.min.css" rel="stylesheet">
  <script src="img/jquery-ui.min.js"></script>
  <title>Chapter 10 - jQuery UI Widget Factory</title>
  <style>
    .box {
      width: 100px;
	  height: 100px;
	  background-color: pink;
	  margin: 5px;
    }
  </style>
</head>
<body>
<div class="jumbotron">
  <div class="container">
    <h1>Chapter 10</h1>
    <p>Interactions allow you to create an interactive and fluid site. Click and drag the boxes around the page.</p>
      <div class="box"><h1>1</h1></div>
      <div class="box"><h1>2</h1></div>
      <div class="box"><h1>3</h1></div>
      <div class="box"><h1>4</h1></div>
  </div>
</div>
<script type="text/javascript">
  function init() {
    $('.box').draggable();
  }
  $(document).ready(init);
</script>
</body>
</html>
```

让我们通过这个示例走一遍，并确保我们理解它在做什么。为了使用 jQuery UI，我们包含它的 CSS 和 JavaScript 文件。然后我们对 div 进行内联 `<style>`，使其看起来像粉色框。

在 body 部分，我们布局我们的页面，在一个容器 div 内创建了四个粉色框。尽管它是一个容器 div，在我们拖动它们时，它不会包含这些框。这些框只受浏览器窗口的约束。

在 JavaScript 中，我们等待文档就绪事件；我们调用 `init()` 方法，然后对每个类为 `box` 的 div 调用 `draggable`。在浏览器中呈现时，此示例允许您将带编号的框移动到浏览器窗口内的任何位置。

## jQuery UI 小部件

小部件是交互式和可自定义的 UI 元素。jQuery UI 自带 12 个小部件。与 HTML 元素不同，jQuery UI 的所有小部件都可以进行主题化，这意味着它们可以被设计成与您网站的设计相匹配的样式和颜色。按字母顺序排列，它们是：手风琴、自动完成、按钮、日期选择器、对话框、菜单、进度条、选择菜单、滑块、微调器、标签页和工具提示。

jQuery UI 小部件的一个好处是，与 HTML 元素不同，它们是可自定义和主题化的。你可以让所有 jQuery UI 小部件匹配。一个可能的问题是，并不是每个元素都有一个 jQuery UI 的等效物。一个明显的缺失是输入元素。但幸运的是，解决这个遗漏并不困难。

```js
<!DOCTYPE html>
<html>
<head lang="en">
  <meta charset="UTF-8">
  <link href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css" rel="stylesheet"/>
  <script src="img/jquery.js"></script>
  <script src="img/bootstrap.min.js"></script>
  <link href="jquery-ui/jquery-ui.min.css" rel="stylesheet">
  <link href="jquery-ui/jquery-ui.theme.min.css" rel="stylesheet">
  <script src="img/jquery-ui.min.js"></script>
  <style>
    label {
      display: block;
      margin: 30px 0 0 0;
    }

    .form-width {
      width: 200px;
    }

    /* fixes the issues with the input that the button causes */
    .styled-input {
      color: inherit;
      cursor: text;
      font: inherit;
      text-align: inherit;
    }
  </style>
  <title>Chapter 10 - jQuery UI Widgets</title>
</head>
<body>
<div class="jumbotron">
  <div class="container">
    <h1>Chapter 10</h1>
    <p>Widgets give your site a unified themed looked.</p>

    <fieldset>
      <label for="form-select">Salutation</label>
      <select name="form-select" id="form-select" class="form-width">
        <option selected="selected">Mr.</option>
        <option>Miss</option>
        <option>Mrs.</option>
        <option>Ms.</option>
        <option>Dr.</option>
      </select>

      <label for="form-input">Last Name</label>
      <input id="form-input" class="styled-input form-width" name="value">

      <label for="form-button">Submit Form</label>
      <button type="submit" id="form-button" class="form-width">Submit</button>
    </fieldset>
  </div>
</div>
<script type="text/javascript">
  function init() {
    $("#form-select").selectmenu();
    $("#form-button").button();
    // make the input a jQuery UI widget so that it matches our theme
    $("#form-input").button();
  }
  $(document).ready(init);
</script>
</body>
</html>
```

前面的代码创建了三个元素。两个 jQuery UI 元素：select 和 button。还创建了一个输入元素。虽然没有 jQuery UI 输入小部件，但这对我们来说不是问题。我们在输入上使用按钮的创建方法。这基本上有效，但有一些不愉快的副作用。按钮的标签居中，所以这也使我们的输入居中。此外，按钮使用指针光标样式，但输入通常具有文本插入符光标。我们用一个类 "styled-text" 修复这些以及其他几个小问题。最后，我们有三个样式化的输入框，全部与我们网站的主题相匹配。

## jQuery UI 小部件工厂

在下一节中，我们将只使用 jQuery 和 JavaScript 编写自己的 jQuery 插件，但在我们这样做之前，让我们看一看另一种编写插件的方法，使用 jQuery UI 小部件工厂。小部件，与常规的 jQuery 插件不同，对它们强制执行标准结构。这是好的，因为它使它们更容易编写，但缺点是为了使用它们，用户必须同时拥有 jQuery 和 jQuery UI 核心，而不只是拥有 jQuery。

您通过将它们传递给小部件工厂来创建小部件。小部件是 JavaScript 对象。它们必须有一个名为`_create`的属性，该属性必须是一个函数。这将是用于实例化小部件的函数。`create`函数被传递一个`this`对象，该对象有两个属性：`this.element`是指向当前元素的 jQuery 对象。它还传递了`this.options`，这是一个保存当前所有选项值的对象。为了让这更清晰些，让我们看一些代码：

```js
<!DOCTYPE html>
<html><head lang="en">
  <meta charset="UTF-8">
  <link href="//maxcdn.bootstrapcdn.com/bootstrap/3.3.2/css/bootstrap.min.css" rel="stylesheet"/><script src="img/jquery.js"></script>
  <script src="img/bootstrap.min.js"></script>
  <link href="jquery-ui/jquery-ui.min.css" rel="stylesheet">
  <script src="img/jquery-ui.min.js"></script>
  <title>Chapter 10 - jQuery UI Widget Factory</title>
</head>
<body>
<nav class="navbar navbar-inverse navbar-fixed-top">
  <div class="container">
    <div class="navbar-header">
      <button type="button" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar"aria-expanded="false" aria-controls="navbar">
        <span class="sr-only">Toggle navigation</span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
        <span class="icon-bar"></span>
      </button>
      <a class="navbar-brand" href="#">Measuring jQuery</a>
    </div>
    <div id="navbar" class="navbar-collapse collapse">
      <form class="navbar-form navbar-right">
        <div class="form-group">
          <input type="text" placeholder="Email" class="form-control">
        </div>
        <div class="form-group">
          <input type="password" placeholder="Password" class="form-control">
        </div>
        <button type="submit" class="btn btn-success">Sign in</button>
      </form>
    </div>
  </div>
</nav>
<div class="jumbotron">
  <div class="container">
    <h1>Chapter 10</h1>
    <p>Writing your own jQuery UI widget is pretty easy. The extra benefit is that you can use your widget in all ofyour apps or give it to the community.</p>
    <p><a class="btn btn-primary btn-lg" href="#" role="button">Learn more "</a></p>
  </div>
</div>
<div class="container">
  <!-- Example row of columns --><div class="row">
    <div class="col-md-4 bosco">
      <h2>First</h2>
      <p>I am the first div. Initially I am the on the left side of the page. </p>
      <p><a class="btn btn-default" href="#" role="button" name="alpha">View details "</a></p>
    </div>
    <div id="testClass" class="col-md-4 ">
      <h2>Second</h2>
      <p>I am the second div. I begin in-between the other two divs. </p>
      <p><a id='find-me' class="btn btn-default find-me" href="#" role="button" name="beta">View details "</a></p>
    </div>
    <div class="col-md-4">
      <h2>Third</h2>
      <p>I am the third div. Initially I am on the right side of the page</p>
      <p><a class="btn btn-default" href="http://www.google.com" role="button" name="delta">View details "</a></p>
    </div>
  </div>
</div>
<script type="text/javascript">
  function init() {
    // create the yada yada widget
    $.widget("rnc.yadayada", {
      // default optionsoptions: {len: 99,min: 50,message: 'yada yada ' // the default message},
      // passed the this context pointing to the element_create: function () {// we only operate if the element has no children and has a text functionif (!this.element.children().length && this.element.text) {
          var currentLength = this.element.text().length;currentLength = currentLength == 0 ? this.options.min : currentLength;
          var copy = this._yadaIt(this.options.message, currentLength);
          this.element.text(copy);
          this.options.len = copy.length;
        }
      },
      _yadaIt: function (message, count) {
        var ndx, output = "", msgLen = message.length;
        for (ndx = 0; ndx < count; ndx += 1) {
          output = output.concat(message.substr(ndx % msgLen, 1));}
        console.log("output = " + output);
        return output;
      },// Create a public method.
      len: function (newLen) {
        console.log("len method");
        // No value passed, act as a getter.
        if (newLen === undefined) {
          return this.options.len;
        }
        // Value passed, act as a setter.
        this.options.len = newLen;
      },
      // begin the name with the '_' and it is private and// can't be called from the outside_privateLen: function(){
        console.log('_privateLen method');
        return this.options.len;}
    });
    // convert the <a> tags to yadas
    $('a').yadayada();
    // get the length of the second yada
    var len = $('a').eq(2).yadayada('len');
    console.log('len = ' + len);
    // this code won't work
    //len = $('a').eq(2).yadayada('_privateLen');
    //console.log('private len = ' + len);
  }
  $(document).ready(init);
</script>
</body>
</html>
```

程序通过等待文档准备就绪事件来启动。一旦接收到该事件，它就会调用其`init`方法。我们通过调用`$.widget()`来创建小部件，这是小部件工厂。在对象内部，我们必须定义一个`_create()`方法。`create`方法使用`this`上下文持有两个值：元素和选项。元素是指向当前元素的 jQuery 对象。重要的是要注意，这始终是单个元素。即使原始选择器引用了多个元素，小部件工厂也会一次将它们传递给我们。选项包含您小部件的默认值，如果您创建了它并且用户没有覆盖它们。

小部件可能定义其他方法。私有方法必须以下划线开头。私有方法在小部件外部不可见。尝试调用私有方法将生成错误。任何方法如果没有下划线作为第一个字符，则为公共方法。公共方法以一种相当不寻常的方式被调用。方法名称以字符串形式传递给小部件函数，如下所示：

```js
var len = $('a').eq(2).yadayada('len');
```

示例中的小部件有点儿异想天开。它用短语`yada yada`替换元素中的文本。只有在元素没有任何子元素并且具有文本函数的情况下才会如此操作。用户可以用更个性化的信息替换`yada yada`。该小部件还具有一个名为`len`的公共方法，该方法将返回渲染消息的长度。

小部件工厂可能是编写插件的最简单方法。具有更严格结构的工厂比常规插件更易于安装和使用，我们将在下面看到。

## 编写自己的插件

如果您想编写一个可以与全世界共享的插件，您最好创建一个常规的 jQuery 插件。它比 jQuery UI 小部件稍微复杂一些，但不需要 jQuery UI，可以轻松上传到 npm，并与世界共享。所以让我们将我们的`yada yada`小部件变成一个插件。

### 准备工作

在我们真正开始之前，我们需要一些工具等待；其中之一是 Node.js。如果之前没有安装它，现在应该这样做，同时要确保更新 npm。安装完成后，您需要登录。首先，查看 npm 是否显示您已登录：

```js
npm whoami

```

如果 npm 显示您的用户名，则说明没问题。如果没有，则需要添加自己：

```js
npm adduser

```

您将被要求输入用户名、密码和电子邮件地址。电子邮件地址将是公开的。浏览 npm 网站的任何人都将能够看到它。您应该只需要执行一次此操作。您的凭据将存储在一个隐藏文件中以供将来参考。准备工作完成后，让我们制作我们的插件然后发布它。

### 插件

插件的结构与 jQuery UI 小部件的结构非常不同。首先，让我们看看代码，然后我们将逐步进行，以便我们可以理解它在做什么。

```js
;(function ($) {
  //
  $.fn.yadayada = function (options) {
    var settings = $.extend({
      min: 13,
      message: 'yada yada '
    }, options);

    return this.each(function () {
      var $element = $(this);
      if (!$element.children().length && $element.text) {
        var currentLength = $element.text().length;
        currentLength = currentLength == 0 ? settings.min : currentLength;
        var copy = yadaIt(settings.message, currentLength);
        $element.text(copy);
      }
    });
  };

  //
  function yadaIt(message, count) {
    var ndx, output = "", msgLen = message.length;

    for (ndx = 0; ndx < count; ndx += 1) {
      output = output.concat(message.substr(ndx % msgLen, 1));
    }
    console.log("output = " + output);
    return output;
  }

}(jQuery));
```

插件通常以分号开头。这是一种安全预防措施。如果插件用于被缩小的网站，并且在它之前的文件忘记添加终止分号，那么两个文件中的代码将以不可预测但不好的方式合并在一起。如果存在此问题，则添加分号会修复此问题，如果不存在则不会造成任何伤害。

整个插件都包装在 IIFE（即立即调用的函数表达式）中。IIFE 允许我们保护我们的代码免受调用的任何环境的影响。除了通过预定义的接口之外，IIFE 外部的任何东西都不能影响它。在这种情况下，接口是我们传递的单个变量，即 jQuery 变量。请注意，我们将其拼写出来，而不仅仅是假设它被分配给美元符号；它可能不是。通过传递它，我们可以将其分配给美元符号，用于我们的插件。

我们只使用一次 jQuery 变量来创建我们的插件。传统上，插件只将一个函数分配给 jQuery 原型。虽然没有什么能阻止你这样做，但这被认为是不好的。

插件的实际代码内部，我们首先处理选项。在 jQuery UI 小部件中，框架会做将用户选项合并到您的选项中的繁重工作。在插件中，我们必须自己处理。幸运的是，我们可以通过使用`$.extend()`方法让 jQuery 来处理繁重的工作。在这里，我们创建我们的默认值，然后将用户的值与它们合并。参数的顺序非常重要；项目从右向左复制。

接下来，我们设置返回`this`对象。如果我们不返回`this`，用户将无法链式使用我们的插件。小部件工厂每次向我们发送一个元素进行操作。不幸的是，对于插件，我们没有这么幸运：我们必须自己迭代。同样，我们让 jQuery 来处理繁重的工作。我们使用`$.each()`方法。此方法每次向我们发送一个元素。这些元素是实际的 DOM 元素，因此我们将它们转换为 jQuery 对象，因为代码最初是为它们编写的。剩下的大部分代码基本上与小部件中的代码相同。

如前所述，`package.json`文件是必需的。名称和版本号字段是必需的，但您应尽可能填写更多字段。这将帮助用户决定这是否是适合他们的正确插件。这是我们的`package.json`文件：

```js
{
  "name": "yada-yada",
  "version": "0.0.1",
  "description": "An example of writing a jquery plugin",
  "repository": "none",
  "license": "MIT",
  "author":"Troy Miles",
  "main":"jquery.yada-yada.js",
  "keywords": "jquery-plugin,ecosystem:jquery,yada-yada",
}
```

除了我们包含的必需字段，我们还包括`description`、`repository`、`license`、`author`、`main`，这样用户就可以知道`main`文件是什么，以及`keywords`，这样我们可以被寻找到想要找 jQuery 插件的人。

现在我们既有代码又有`package.json`文件，让我们将工作发布到 npm。请记住，如果你决定发布此代码，我已经声明了`yada-yada`这个名字，所以你不能使用它。你必须想出一个独特的名字。进入包含你的插件和`package.json`文件的目录。为了发布，只需输入：

```js
npm publish

```

如果你做得一切正确，在几分钟后 npm 会显示你插件的名称和版本号，就这样。然后转到[`www.npmjs.com/`](https://www.npmjs.com/)，在搜索框中输入你的插件名称，它应该出现在结果列表中。

### 最佳实践

如果一切顺利，你的插件可能会被世界各地的很多人使用，所以重要的是它是精心编写的。以下是一些提示，可以帮助你的插件发挥全部潜力。

#### 保留链接

链接是 jQuery 最好的特性之一。它允许开发人员以一个整洁的包进行一切操作。每个 jQuery 开发者都在使用它，所以如果你破坏了链接，他们就不会喜欢你的插件。

#### 使用一个 IIFE

你不可能知道你的插件将在什么样的环境中使用。将代码包裹在 IIFE 中可能看起来是不必要的，但它有助于保持你的代码不影响其他代码，反之亦然。

#### 在 jQuery 中只添加一个函数

你的插件可能是自瑞士军刀以来最了不起的东西，但你还是只能使用一个函数。即使我们的小示例插件不需要额外的函数，你也只能使用一个函数。如果你需要更多的函数，就像其他插件一样，传入函数的名称作为字符串，并在插件内调用处理程序。

#### 让用户主题化

jQuery 非常注重自定义；你的插件也应该是。这个示例插件允许用户通过选项更改消息。这个概念可以扩展到包括样式和类。你的插件可能非常有用，但如果它与用户站点的其余部分不匹配，他们就不会使用它。

#### 测试，测试，测试

在将其发布到外部之前，确保你的插件能够胜任任务。在你能找到的每个浏览器上测试，考虑像`BrowserStack`这样的服务，不要忘记请朋友和同事们来试试。

#### 记录它

如果开发者无法理解你的插件，他们就不会使用它。你应该尽可能详细地记录它。将代码发布到 GitHub 之类的公共位置。在你的`package.json`文件中添加内容，以使你的 npm 页面尽可能完整。一定要包含尽可能多的使用代码示例。

#### 最小化它

要像 jQuery 一样。它提供了压缩和未压缩两个版本。开发者喜欢检查未压缩版本中的内容，并使用压缩版本。

# 总结

插件是最受欢迎的 jQuery 功能之一。在本章中，我们了解了插件从 jQuery 插件存储库切换到新的 npm 存储方式的过程。然后我们学习了如何在我们的应用程序中安装、更新和移除插件，甚至了解了 `--save` 选项的用途。

从 npm，我们转向了 jQuery UI，这是官方支持的 UI 小部件库。我们学习了如何使用这些小部件，并创建了一个自定义下载，只包含我们想要的小部件。

我们最后讨论的主题是如何编写我们自己的插件。我们解释了创建插件所需的每个步骤，并解释了为什么我们应该让 jQuery 处理大部分繁重的工作。最后，我们展示了如何将我们的插件上传到 npm，以便他人可以从我们的工作中受益。

我们从学习为什么创建 jQuery 开始了这本书：为了让跨浏览器的 Web 开发更容易。在 第二章 中，*jQuery 选择器和过滤器*，我们使用了 jQuery 的选择器和过滤器来找到页面上的元素，然后在接下来的章节中操作了这些元素。我们使用事件使我们的网站变得交互式，并使用动画使其更加华丽。我们学习了如何获取经过验证的表单数据并将其发送到服务器。我们学习了在 第八章，*编写以后可以阅读的代码*，和 第九章，*更快的 jQuery* 中编写干净和快速代码的技巧。最后，我们学习了如何使用和编写插件。

jQuery 仍然是现代网页开发中的重要组成部分。虽然多年来浏览器在遵循 Web 标准方面做得更好了，但 jQuery 仍然能让开发变得更简单。唯一一点 jQuery 无法帮助的是编写大型 Web 应用程序。在编写大型 Web 应用程序时，Angular 或 Ember 这样的框架，或者像 React 这样的库是更好的选择。
