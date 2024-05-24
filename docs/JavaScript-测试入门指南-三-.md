# JavaScript 测试入门指南（三）

> 原文：[`zh.annas-archive.org/md5/BA61B4541373C00E412BDA63B9F692F1`](https://zh.annas-archive.org/md5/BA61B4541373C00E412BDA63B9F692F1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：测试更复杂的代码

> 欢迎来到第六章。在这一章中，我们将了解更多关于 JavaScript 测试的内容。更具体地说，我们将学习如何测试更复杂的代码，其中实体之间会有更多的交互。到目前为止，我们一直在对相对简单的代码进行测试，使用的是相对直接的技术。

更具体地说，我们将涵盖以下内容：

+   组合脚本时可能发生的错误类型

+   如何处理组合脚本时发生的错误

+   目前互联网上可用的各种 JavaScript 库，以及我们在测试它们时需要考虑的问题。

+   如何测试 GUI、库的控件插件以及其他考虑因素

+   如何使用控制台日志

+   使用 JavaScript 内置对象进行异常处理

+   使用 JavaScript 内置对象测试应用程序

让我们从覆盖组合脚本时可能发生的错误类型的基本概念开始。

# 组合脚本的问题

到目前为止，我们一直专注于在 HTML 文档中编写和测试只有一段 JavaScript 代码。考虑一下现实生活中的情况，我们通常使用外部的 JavaScript；如果我们使用多个 JavaScript 文件会发生什么？如果我们使用多个外部 JavaScript 文件，我们可能会遇到什么问题？我们在下面的子节中都会覆盖到。我们首先从第一个问题开始——组合事件处理器。

## 组合事件处理器

你可能意识到了，也可能没有意识到，但自从第三章《语法验证》以来，我们就一直在处理事件处理器。实际上，我们在《第一章，什么是 JavaScript 测试》中提到了事件。JavaScript 通过添加交互性，使我们的网页充满生机。事件处理器是交互性的心跳。例如，我们点击一个按钮，一个弹出窗口就会出现，或者我们的光标移动到 HTML `div`元素上，元素的颜色会改变以提供视觉反馈。

为了了解我们可以如何组合事件处理器，请考虑以下示例，该示例在文件`combine-event-handlers.html`和`combine-event-handlers.js`中，如以下代码所示：

在`combine-event-handlers.html`中，我们有：

```js
<html>
<head>
<title>Event handlers</title>
<script type="text/javascript" src="combine-event-
handlers.js"></script>
</head>
<body>
<div id="one" onclick="changeOne(this);"><p>Testing One</p></div>
<div id="two" onclick="changeTwo(this);"><p>Testing Two</p></div>
<div id="three" onclick="changeThree(this);"><p>Testing Three</p></div>
</body>
</html>

```

请注意，每个`div`元素都由不同的函数处理，分别是`changeOne()`、`changeTwo()`和`changeThree()`。事件处理器在`combine-event-handlers.js`中：

```js
function changeOne(element) {
var id = element.id;
var obj = document.getElementById(id);
obj.innerHTML = "";
obj.innerHTML = "<h1>One is changed!</h1>";
return true;
}
function changeTwo(element) {
var id = element.id;
var obj = document.getElementById(id);
obj.innerHTML = "";
obj.innerHTML = "<h1>Two is changed!</h1>";
return true;
}
function changeThree(element) {
var id = element.id;
var obj = document.getElementById(id);
obj.innerHTML = "";
obj.innerHTML = "<h1>Three is changed!</h1>";
return true;
}

```

你可能想接着测试程序。随着你点击文本，内容会根据函数中的定义发生变化。

然而，我们可以重写代码，使得所有事件都由一个函数处理。我们可以将`combine-event-handlers.js`重写为如下：

```js
function combine(element) {
var id = element.id;
var obj = document.getElementById(id);
if(id == "one"){
obj.innerHTML = "";
obj.innerHTML = "<h1>One is changed!</h1>";
return true;
}
else if(id == "two"){
obj.innerHTML = "";
obj.innerHTML = "<h1>Two is changed!</h1>";
return true;
}
else if(id == "three"){
obj.innerHTML = "";
obj.innerHTML = "<h1>Three is changed!</h1>";
return true;
}
else{
; // do nothing
}
}

```

当我们使用`if else`语句检查我们正在处理的`div`元素的`id`，并相应地改变 HTML 内容时，我们可以节省很多行代码。请注意，我们已经将函数重命名为`combine()`。

因为我们对 JavaScript 代码做了一些改动，所以我们还需要对我们的 HTML 进行相应的改动。所以`combine-event-handlers.html`将被重写如下：

```js
<html>
<head>
<title>Event handlers</title>
<script type="text/javascript" src="img/combine-event- handlers.js"></script>
</head>
<body>
<div id="one" onclick="combine(this);"><p>Testing One</p></div>
<div id="two" onclick="combine(this);"><p>Testing Two</p></div>
<div id="three" onclick="combine(this);"><p>Testing Three</p></div>
</body>
</html>

```

请注意，现在`div`元素由同一个函数`combine()`处理。这些重写的示例可以在`combine-event-handlers-combined.html`和`combine-event-handlers-combined.js`中找到。

## 名称冲突

处理名称冲突是我们需要解决的下一个问题。与事件处理程序组合的问题类似，名称冲突发生在两个或更多变量、函数、事件或其他对象具有相同名称时。尽管这些变量或对象可以包含在不同的文件中，但这些名称冲突仍然不允许我们的 JavaScript 程序正常运行。请考虑以下代码片段：

在`nameclash.html`中，我们有以下代码：

```js
<html>
<head>
<title>testing</title>
<script type="text/javascript" src="img/nameclash1.js"></script>
</head>
<body>
<div id="test" onclick="change(this);"><p>Testing</p></div>
</body>
</html>

```

在`nameclash1.js`中，我们有以下代码：

```js
function change(element) {
var id = element.id;
var obj = document.getElementById(id);
obj.innerHTML = "";
obj.innerHTML = "<h1>This is changed!</h1>";
return true;
}

```

如果你通过在浏览器中打开文件并点击文本**Testing**来运行此代码，HTML 内容将按预期更改。然而，如果我们在这段代码后面添加`<script type="text/javascript" src="img/nameclash2.js"></script>`，并且`nameclash2.js`的内容如下：

```js
function change(element) {
alert("so what?!");
}

```

然后我们将无法正确执行代码。我们将看到警告框，而不是 HTML 内容被改变。如果我们改变外部 JavaScript 的位置，那么`div`元素的内容将被改变，我们将无法看到警告框。

由于这些名称冲突，我们的程序变得不可预测；解决这个问题的方法是在你的函数、类或事件中使用独特的名称。如果你有一个相对较大的程序，建议使用命名空间，这是 YUI 和 jQuery 等几个 JavaScript 库中常见的策略。

# 使用 JavaScript 库

现在有很多 JavaScript 库可供使用。一些最常用的如下：

+   JQuery ([`jquery.com`](http://jquery.com))

+   YUI (Yahoo!用户界面 JavaScript 库) ([`developer.yahoo.com/yui/`](http://developer.yahoo.com/yui/))

+   Dojo ([`dojotoolkit.org/`](http://dojotoolkit.org/))

+   原型([`www.prototypejs.org/`](http://www.prototypejs.org/))

+   Mootools ([`mootools.net/`](http://mootools.net/))

+   Script.aculo.us ([`script.aculo.us/`](http://script.aculo.us/))

还有更多的 JavaScript 库。要查看完整的列表，请随时访问[`en.wikipedia.org/wiki/List_of_JavaScript_libraries.`](http://en.wikipedia.org/wiki/List_of_JavaScript_libraries.)

- 如果您考虑使用 JavaScript 库，您可能已经了解到使用 JavaScript 库的好处。事件处理以及令人望而生畏的跨浏览器问题使得考虑使用 JavaScript 库变得必要。但是，您可能想知道作为初学者 JavaScript 程序员在选择 JavaScript 库时应注意什么。这里有一份需要考虑的事项列表：

+   - 可用支持的级别，以文档形式表示。

+   - 是否提供教程，以及它们是免费还是付费。这有助于加快编程过程。

+   - 插件和附加组件的可用性。

+   - 库是否有内置的测试套件？这对于我们的目的来说非常重要。

## - 您是否需要测试别人编写的库？

- 首先，当我们学习 JavaScript 测试时，我认为对于初学者学习 JavaScript 编程，可能不建议测试别人编写的 JavaScript 库。这是因为我们需要理解代码才能进行准确测试。能够进行客观（且准确）测试的是 JavaScript 专家，而虽然您正在成为其中的一员，但您可能还没有达到那个水平。

- 其次，从实际角度考虑，已经为我们完成了许多这样的测试。您需要做的就是在互联网上搜索它们。

- 但为了学习目的，让我们简要了解一下通常针对库代码运行哪些测试。

## - 针对库代码应运行哪些测试

- 通常，作为各种 JavaScript 库的用户，我们最常进行性能测试和性能测试。

### - 性能测试

- 性能测试，顾名思义，是关于测试您的代码性能。这包括以手动方式测试您的代码（在各种浏览器上）的速度，或使用某些工具（如 Firebug 或其他工具）（更多此类工具将在第八章中介绍）。

- 通常，为了生成性能测试的准确结果，您需要针对所有流行平台测试您的代码（最理想的是使用工具和测试套件）。例如，对 JavaScript 代码进行性能测试的常见方法是在 Firefox 中安装 Firebug 并使用它进行测试。但是从实际角度考虑，Firefox 用户只占互联网用户的约四分之一（最多三分之一）。为了确保您的代码达到标准，您还需要针对其他平台（如 Internet Explorer）进行测试。我们将在第八章中介绍更多内容。

### - 性能测试

剖析测试与性能测试类似，不同之处在于它关注的是代码中的瓶颈，而不是整体性能。瓶颈通常是低效代码的主要罪魁祸首。修复瓶颈（几乎）是提高代码性能的确定方法。

## 图形用户界面（GUI）和控件插件以及如何测试它们的相关考虑

如果你查看了我向你指出的各种 JavaScript 库的列表，你可能会注意到一些 JavaScript 库也提供了用户界面或控件插件。这些旨在增强你的应用程序的用户界面，最重要的是，通过实现常用的用户界面组件（如对话框、颜色选择器等）来帮助你节省时间和精力。

但是问题就从这里开始——我们如何测试这些用户界面和控件插件呢？我们可以采取很多方法来完成这件事，但最简单的方法（或许也是最繁琐的）莫过于 visually 和 manually 进行测试。例如，如果我们期望一个对话框会出现在屏幕的左上角，并且具有某种颜色、宽度和高度，如果它没有以我们期望的方式出现，那么就出错了。

同样，如果我们看到了我们预期看到的东西，那么我们可以说它是正确的——至少在视觉上是这样。

然而，需要进行更严格的测试。测试用户界面可能是一项艰巨的任务，因此我建议你使用像 Sahi 这样的测试工具，它允许我们用任何编程语言编写自动化网页应用界面测试。像 Sahi 这样的工具超出了本章的范围。我们将在第八章详细介绍 Sahi。与此同时，如果你急于了解 Sahi，可以随时访问他们的网站：[`sahi.co.in`](http://sahi.co.in)。

# 故意抛出自己的 JavaScript 错误

在本节中，我们将学习如何抛出自己的 JavaScript 错误和异常。我们将简要介绍错误函数和命令的语法。这时给你语法可能有点难以理解，但这是必要的。一旦你理解了如何使用这些命令和保留字，你将了解如何利用它们提供更具体的信息（从而获得更多控制权）来控制你可以在下一节中捕获和创建的错误类型。那么让我们从第一个保留字——`throw`开始吧。

## 抛出语句

`throw`是一个允许你创建异常或错误的语句。它有点像`break`语句，但`throw`允许你跳出任何作用域。通常，我们用它来字面意思上抛出一个错误。语法如下：

```js
throw(exception);

```

我们可以用`throw(exception)`以下方式：

```js
throw "This is an error";

```

或者：

```js
throw new Error("this is an error");

```

`Error`是一个内置对象，通常与`throw`语句一起使用；我们稍后会介绍`Error`。现在要理解的重要一点是语法，以及`throw`也经常与`try, catch`和`finally`一起使用，这将帮助你控制程序流程并创建准确的错误信息。现在让我们继续讲解`catch`。

## 尝试，捕获和最后语句

`try, catch`和`finally`语句是 JavaScript 的异常处理机制，如前所述，它帮助你控制程序流程，同时捕获你的错误。`try, catch`和`finally`语句的语法如下：

```js
try {
// exceptions are handled here
}
catch (e) {
// code within the catch block is executed if any exceptions are caught in the try block
}
finally {
// code here is executed no matter what happens in the try block
}

```

请注意`try`后面跟着`catch`，然后可选地使用`finally`。通常，`catch`语句捕获`try`语句中发生的异常。异常是一个错误。只要`try`或`catch`语句终止，`finally`语句就会执行。

既然我们已经介绍了故意抛出 JavaScript 错误的基本命令和保留字，那么让我们来看一个`try, catch`和`finally`一起使用的例子。下面的代码可以在*第六章*的`source code`文件夹中的 HTML 文档`try-catch-finally-correct-version.html`中找到。查看下面的代码：

```js
<html>
<head>
<script>
function factorial(x) {
if(x == 0) {
return 1;
}
else {
return x * factorial(x-1);
}
}
try {
var a = prompt("Enter a positive integer", "");
var f = factorial(a);
alert(a + "! = " + f);
}
catch (error) {
// alert user of the error
alert(error);
alert(error.message);
}
finally {
alert("ok, all is done!");
}
</script>
</head>
<body>
</body>
</html>

```

你可以将上面的代码复制并粘贴到你最喜欢的文本编辑器中，保存它，然后在浏览器中运行。或者你可以运行样本文件`try-catch-finally-correct-version.html`。

你将看到一个提示窗口，要求你输入一个正整数。接着输入一个正整数，比如**3**，然后你会收到一个警告窗口，告诉你**3! = 6**。之后，你应该会收到另一个警告窗口，其中包含消息**好的，一切都完成了！**，因为`finally`块将在`try`或`catch`终止后执行。

现在，输入一个负数，比如**-1**。如果你使用的是 Firefox，你会收到一个提示窗口，告诉你有太多的递归。如果你使用的是 Internet Explorer，你会收到一个**[object Error]**消息。

在第一个弹出窗口之后，你将收到第二个弹出窗口。如果你使用的是 Firefox，你会看到一个**InternalError: Too much recursion**消息。如果你使用的是 Internet Explorer，你会收到一个**Out of stack space**消息。

最后，你应该会看到一个最终的警告窗口，其中包含消息**好的，一切都完成了！**，因为`finally`块将在`try`或`catch`终止后执行。虽然确实我们遇到了一个错误，但错误信息并不是我们真正需要的，因为它没有告诉我们我们输入了非法值。

这就是`throw`发挥作用的地方。`throw`可以用来控制程序流程，并为每种错误给出正确的响应。查看下面的代码，也可以在`source code`文件夹中的文件`try-catch-finally-throw-correct-version.html`找到。

```js
<html>
<head>
<script>
function factorial(x) {
if(x == 0) {
return 1;
}
else {
return x * factorial(x-1);
}
}
try {
var a = prompt("Please enter a positive integer", "");
if(a < 0){
throw "negative-error";
}
else if(isNaN(a)){
throw "not-a-number";
}
var f = factorial(a);
alert(a + "! = " + f);
}
catch (error) {
if(error == "negative-error") {
alert("value cannot be negative");
}
else if(error == "not-a-number") {
alert("value must be a number");
}
else
throw error;
}
finally {
alert("ok, all is done!");
}
</script>
</head>
<body>
</body>
</html>

```

现在请执行程序，输入正确的值、负值和非字母数字值。根据你的输入，你应该会收到正确的错误消息。

注意之前代码行中我们使用`throw`语句来控制要显示给用户的错误消息类型。这是`throw`语句可以使用的几种方式之一。请注意，在`throw`之后定义的字符串用于创建程序逻辑，以决定应调用哪些错误消息。

如果你想知道这种异常处理机制还有哪些其他功能，请从`try-catch-finally-correct-version.html`中删除`factorial`函数。或者，你可以打开文件`try-catch-finally-wrong-version.html`并运行程序。然后尝试输入任何值。你应该会收到一个警告消息，告诉你`factorial`函数未定义，之后你将收到另一个警告框，显示**好的，一切都完成了**。请注意，在这种情况下，我们不需要编写任何形式的消息；`catch`足够强大，可以告诉我们出了什么问题。

需要注意的是，如果不对异常编写处理程序，JavaScript 运行时可能会捕获异常。

既然我们已经介绍了异常处理机制的基本知识，接下来让我们具体了解一下——处理错误的内置对象。

# 使用内置对象捕获错误

在本节中，我们将简要介绍每种内置对象是什么，以及它们的语法，然后展示每个内置对象如何工作的示例。请注意，我们将在示例中适度使用警告消息，这些消息是基于 Firefox 浏览器。如果你在 Internet Explorer 上尝试代码，你可能会看到不同的错误消息。

## 错误对象

`Error`是一个通用的异常，它接受一个可选的消息，提供异常的详细信息。我们可以使用`Error`对象，使用以下语法：

```js
new Error(message); // message can be a string or an integer

```

以下是一个显示`Error`对象动作的示例。这个示例的源代码可以在文件`error-object.html`中找到。

```js
<html>
<head>
<script type="text/javascript">
function factorial(x) {
if(x == 0) {
return 1;
}
else {
return x * factorial(x-1);
}
}
try {
var a = prompt("Please enter a positive integer", "");
if(a < 0){
var error = new Error(1);
alert(error.message);
alert(error.name);
throw error;
}
else if(isNaN(a)){
var error = new Error("it must be a number");
alert(error.message);
alert(error.name);
throw error;
}
var f = factorial(a);
alert(a + "! = " + f);
}
catch (error) {
if(error.message == 1) {
alert("value cannot be negative");
}
else if(error.message == "it must be a number") {
alert("value must be a number");
}
else
throw error;
}
Error objectworkingfinally {
alert("ok, all is done!");
}
</script>
</head>
<body>
</body>
</html>

```

你可能注意到了，这个代码的结构与之前的例子相似，我们在其中演示了`try, catch, finally`和`throw`。在这个例子中，我们利用了我们所学的知识，并没有直接抛出错误，而是使用了`Error`对象。

我需要你关注上面给出的代码。注意我们已经将整数和字符串作为`var error`的消息参数，分别是`new Error(1)`和`new Error("it must be a number")`。请注意我们可以使用`alert()`创建一个弹出窗口，以通知用户发生的错误和错误的名称，因为它是`Error`对象，所以名称是**Error**。同样，我们可以使用消息属性来为适当的错误消息创建程序逻辑。

了解`Error`对象是如何工作的很重要，因为以下我们要学习的内置对象的工作方式与`Error`对象的工作方式相似。（我们可能能够展示如何在这些错误中使用控制台日志。）

## **RangeError 对象**

当一个数字超出其适当的范围时，会发生`RangeError`。这个语法与我们之前看到的`Error`对象相似。这是`RangeError`的语法：

```js
new RangeError(message);

```

`message` 可以是字符串或整数。

我们从一个简单的例子开始，展示这是如何工作的。查看以下代码，可以在`source code`文件夹中的`rangeerror.html`文件找到：

```js
<html>
<head>
<script type="text/javascript">
try {
var anArray = new Array(-1);
// an array length must be positive
}
catch (error) {
alert(error.message);
alert(error.name);
}
finally {
alert("ok, all is done!");
}
</script>
</head>
<body>
</body>
</html>

```

当你运行这个例子时，你应该会看到一个警告窗口，通知你数组长度无效。在此警告窗口之后，你应该会收到另一个警告窗口，告诉你**错误是 RangeError**，因为这是一个`RangeError`对象。如果你仔细查看代码，你会看到我故意创建了这个错误，给数组长度一个负值（数组长度必须是正数）。

## **引用错误**

当你引用的变量、对象、函数或数组不存在时，会发生`引用错误`。到目前为止你看到的语法相似，如下所示：

```js
new ReferenceError(message);

```

`message` 可以是字符串或整数。

因为这个问题很简单，所以我直接进入下一个例子。以下例子的代码可以在`source code`文件夹中的`referenceerror.html`文件找到。

```js
<html>
<head>
<script type="text/javascript">
try {
x = y;
// notice that y is not defined
// an array length must be positive 
}
catch (error) {
alert(error);
alert(error.message);
alert(error.name);
}
finally {
alert("ok, all is done!");
}
</script>
</head>
<body>
</body>
</html>

```

注意`y`未定义，我们期望在`catch`块中捕获这个错误。现在在你的 Firefox 浏览器中尝试之前的例子。你应该会收到四个关于错误的警告窗口，每个窗口都会给你不同的消息。消息如下：

+   **引用错误: y 未定义**

+   **y 未定义**

+   **引用错误**

+   **好的，一切都完成了**

如果你在使用 Internet Explorer，你会收到稍微不同的消息。你会看到以下消息：

+   **[object Error] message**

+   **y 是未定义的**

+   **TypeError**

+   **好的，一切都完成了**

## **TypeError 对象**

当尝试访问类型不正确的值时，会抛出一个`TypeError`。语法如下：

```js
new TypeError(message); // message can be a string or an integer and it is optional

```

`TypeError`的一个例子如下：

```js
<html>
<head>
<script type="text/javascript">
try {
y = 1
var test = function weird() {
var foo = "weird string";
}
y = test.foo(); // foo is not a function
}
catch (error) {
alert(error);
alert(error.message);
alert(error.name);
}
finally {
alert("ok, all is done!");
}
</script>
</head>
<body>
</body>
</html>

```

如果你尝试在 Firefox 中运行此代码，你应该会收到一个警告框，指出它是一个`TypeError`。这是因为`test.foo()`不是一个函数，这导致了一个`TypeError`。JavaScript 能够找出捕获了哪种类型的错误。同样，你可以通过取消注释代码来使用传统的抛出自定义`TypeError()`的方法。

以下内置对象使用较少，所以我们快速浏览一下内置对象的语法。

## **SyntaxError 对象**

当你在语法上出错时，会发生`语法错误`。`SyntaxError`的语法如下：

```js
new SyntaxError([message,[,,[,filename[, lineNumber]]]); // message can be a string or an integer and it is optional

```

请注意`filename`和`lineNumber`参数是非标准的，如果可能的话应避免使用它们。

## `URIError`对象

`URIError`是在遇到格式不正确的 URI 时发生的。该语法的格式如下：

```js
new URIError([message,[,filename[, lineNumber]]]);

```

类似于`SyntaxError`，请注意`filename`和`lineNumber`参数是非标准的，如果可能的话应避免使用它们。

## `EvalError`对象

`EvalError`是在使用不正确或包含其他错误的`eval`语句时发生的。

```js
new EvalError([message,[,filename[, lineNumber]]]);// message can be a string or an integer and it is optional

```

类似于`SyntaxError`和`URIError`，请注意`filename`和`lineNumber`参数是非标准的，如果可能的话应避免使用它们。

# 使用错误控制台记录信息

Firefox 的控制台是一个足够强大的工具，可以让你记录 JavaScript 消息。你可以记录内置对象的错误信息，也可以编写你自己的信息。

## 错误信息

我们在本节中看到的错误信息是在 Firefox 错误控制台中生成的，并记录在错误控制台的日志中。在开始之前，我需要你打开你的 Firefox 浏览器，点击菜单栏上的**工具**，然后选择**错误控制台**。确保你没有打开其他标签页。

现在，打开你的代码编辑器，并在新文档中输入以下代码：

```js
<html>
<head>
<script type="text/javascript">
try {
var anArray = new Array(-1););
}
catch (error) {
throw error;
}
finally {
alert("ok, all is done!");
}
</script>
</head>
<body>
</body>
</html>

```

将文档保存为`.html`文件，然后在你的 Firefox 浏览器中运行该文件。或者，你可以使用位于`source code`文件夹中的源代码与 HTML 文档一起使用，文档名为：`error-message-console.html`。如果你现在查看你的控制台，你应该会收到以下错误信息：**无效的数组长度**。这是因为我们在上面的代码中定义了一个负长度的数组。

这里的技巧是使用`throw`语句来抛出错误信息。请注意，Firefox 的错误控制台不会显示错误的`name`。

现在我们将看看如何创建自定义错误信息。

## 编写你自己的消息

让我们继续创建我们自己的错误信息。完整的代码可以在`source code`文件夹中的`test-custom.html`文件找到。

再次打开你的代码编辑器，创建一个新文档，并输入以下代码：

```js
<html>
<head>
<script type="text/javascript">
function factorial(x) {
if(x == 0) {
return 1;
}
else {
return x * factorial(x-1);
}
}
try {
var a = prompt("Please enter a positive integer", "");
if(a < 0){
throw new Error("Number must be bigger than zero"); 
}
else if(isNaN(a)){
throw new Error("You must enter a number"); 
}
var f = factorial(a);
alert(a + "! = " + f);
}
catch (error) {
throw error; 
}
</script>
</head>
<body>
</body>
</html>

```

我们所做的是在`try`块中抛出两个带有自定义消息的新`Error`对象，然后在`catch`块中再次抛出`Error`对象。在`try`块中，我们创建了一个自定义的`Error`对象，而在`catch`块中，我们将消息抛向**错误控制台**。

请注意突出显示的行。我们在`Error`对象中定义了我们自己的消息。保存文件，然后打开你的 Firefox 浏览器。转到**工具 | 错误控制台**。在**错误控制台**中，确保你在**所有**标签或**错误**标签。现在在你的 Firefox 浏览器中运行你的代码。如果你输入非数字输入，你将在错误控制台收到**你必须输入一个数字**的消息。如果你输入的数字小于零，你将收到**数字必须大于零**的消息。关键在于利用提供的方法和属性来抛出你自己的错误信息。

# 修改脚本和测试

既然我们已经介绍了使用内置对象抛出和捕获错误的基本模块，以及使用控制台抛出错误消息，是时候学习我们如何可以将所学应用到一个简单的应用程序上了。

# 行动时间——编码、修改、抛出和捕获错误

在这一部分，我需要你集中注意力，因为我们将会应用我们之前创建第一个应用程序时学到的所有知识。之后，我们将尝试生成我们自己的错误，并在测试过程中抛出各种错误信息。

我们将要创建的是一个模拟电影预订系统。我不知道你们是否注意到了，但我注意到服务台的工作人员使用某种电影预订系统，它有一个 GUI 来帮助他们的预订过程。我们不仅会创建那个系统，还会添加更多功能，比如购买与电影票一起的食品和饮料。

以下是电影票预订系统的详细信息：当你点击每个座位时，你正在执行一个预订动作。如果座位已被预订，点击它将执行一个取消预订动作。

其他重要的设计规则如下：你不能购买比你预订的门票更多的餐点。例如，如果你预订了四张门票，你只能购买最多四份餐点，无论是热狗套餐还是爆米花套餐。同样，你每购买一份餐点，你可以购买一个 Sky Walker。这意味着如果你购买了三份餐点，你只能购买最多三个 Sky Walker。另外，你只能用百元钞票支付。这意味着你只能在**请用 100 美元钞票支付**输入框中输入百位数的数字。

如果您在想各种商品的价格，门票每张 10 美元。热狗套餐 6 美元，爆米花套餐 4 美元。Sky Walker 每个 10 美元。

清楚这些规则了吗？如果你清楚这些规则，我们首先开始创建这个应用程序。之后，我们将把异常捕获机制作为最后一步。顺便说一下，这个例子完成的代码可以在第六章的`cinema-incomplete`文件夹中找到。

1.  打开代码编辑器，创建一个新文件。将以下代码输入到你的文件中。

    ```js
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html >
    <head>
    <title>JavaScript Cinema</title>
    </head>
    <body>
    </body>
    </html>

    ```

    这将构成我们程序的骨架。现在，它不会做任何事情，也不会在您的网页上显示任何设计。因此，我们将从创建我们应用程序的布局开始。

1.  在您的 HTML 文档的`<body>`标签内输入以下代码。

    ```js
    <div id="container">
    <div id="side-a">
    <h1>Welcome to JavaScript Cinema </h1>
    <div class="screen">
    <p> Screen is located here. </p>
    </div>
    <div class="wrapper" id="tickets">
    <p>You have booked 0 tickets</p>
    </div>
    <div class="wrapper">
    <p>Click on the seats above to make your booking.</p>
    </div>
    </div>
    <div id="side-b">
    <div class="menuRight">
    <h4>Meal Pricing</h4>
    <p>Hotdog Meal : $6 <br />Popcorn Meal : $4</</p>
    <form name="foodForm" onsubmit="return checkForm()">
    <!-- total number of meals cannot exceed total number of tickets purchased -->
    # of Hotdog Meal ($6/meal): <input type="text" name="hotdogQty" length="3" size="3px"/>
    <br />
    # of Popcorn Meal ($4/meal): <input type="text" name="popcornQty" length="3" size="3px" />
    <p class="smalltext">Total # of meals cannot exceed total number of tickets purchases</p>
    <br />
    <!-- here's some specials to go with -->
    <p>Here's the special deal of the day:</p>
    Sky Walker($10):<input type="text" name="skywalker" length="3" size="3px"/>
    <p class="smalltext">You can only buy 1 Sky Walker for every meal you've purchased.</p>
    <br />
    <!-- show total price here -->
    Please pay in $100 notes
    <input type="text" name="hundred" length="3" size="3px" />
    <br />
    <input type="submit" value="Order Now">
    </form>
    </div>
    <div id="orderResults"> </div>
    </div>
    </div>

    ```

    这段代码构成了我们电影票预订应用程序的基本控制。您可能已经注意到有各种带有 wrapper 类的`div`元素。这些元素将用于创建一个类似网格的用户界面，代表影院的座位。所以现在我们将开始创建用于表示座位的网格。

1.  首先，我们将构建网格的第一行。首先，在具有 wrapper 类的第一个`div`元素内输入以下代码：

    ```js
    <div class="left1" id="a1" name="seats" onclick="checkBooking(this);">
    <p>Available</p>
    </div>
    <div class="left2" id="a2" name="seats" onclick="checkBooking(this);">
    <p>Available</p>
    </div>
    <div class="left8" id="a8" name="seats" onclick="checkBooking(this);">
    <p>Available</p>
    </div>
    <div class="left9" id="a9" name="seats" onclick="checkBooking(this);">
    <p>Available</p>
    </div>

    ```

    请注意，您在具有 wrapper 类的第一个`div`元素内输入的每个`<div>`元素都有一个`class`和`id`属性。通常，第一个`div`将有一个`left1`类和一个`a1`ID。下一个`div`元素将有一个`left2`类和`a2`ID，依此类推。这是我们设计网格的方式。现在，让我们进行下一步。

1.  与步骤 3 类似，我们将构建网格的下一行。在第二个具有 wrapper 类的`div`元素内输入以下代码：

    ```js
    <div class="left1" id="b1" name="seats" onclick="checkBooking(this);">
    <p>Available</p>
    </div>
    <div class="left2" id="b2" name="seats" onclick="checkBooking(this);">
    <p>Available</p>
    </div>
    <div class="left8" id="b8" name="seats" onclick="checkBooking(this);">
    <p>Available</p>
    </div>
    <div class="left9" id="b9" name="seats" onclick="checkBooking(this);">
    <p>Available</p>
    </div>

    ```

    注意，构成网格第二行的`div`元素具有以"b"开头的 ID，与第一行的"a"开头形成对比。这是我们将继续用来命名和构建网格的方式。这意味着下一行将具有以"c"开头的 ID，第四行将以"d"开头，依此类推。

    总共我们将创建五行。这意味着我们还有三行要做。

1.  现在我们将构建网格的下一三行。将上一步给出的代码输入到剩余的`div`元素中，但请记住根据行号更改每个元素的`id`。同时，记得包含`onclick="checkBooking(this)"`，因为这将用于执行我们的 JavaScript 函数。

    完成 HTML 后，是时候添加 CSS 以创建我们应用程序的正确设计和布局。

1.  对于这个例子，我们将使用外部 CSS。因此，在`<title>`标签之后插入以下代码。

    ```js
    <link rel="stylesheet" type="text/css" href="cinema.css" />

    ```

1.  现在我们将创建一个 CSS 文件。打开一个新文档，将其保存为`cinema.css`，因为这是我们步骤 6 中提到的。接下来，将以下代码输入到`cinema.css`中：

    ```js
    body{
    border-width: 0px;
    padding: 0px;
    padding-left: 20px;
    margin: 0px;
    font-size: 90%;
    }
    #container {
    text-align: left;
    margin: 0px auto;
    padding: 0px;
    border:0;
    width: 1040px;
    }
    #side-a {
    float: left;
    width: 840px;
    }
    #side-b {
    margin: 0;
    float: left;
    margin-top:100px;
    width: 200px;
    height: 600px;
    background-color: #cccc00;
    }

    ```

    这是用于构建应用程序框架的 CSS 类和 ID 选择器的代码。如果您忘记了 CSS 是如何工作的，您可能想回到第一章，*什么是 JavaScript 测试*，复习一下。

    现在，我们将决定网格上*座位*的大小和其他重要属性。

1.  我们将定义座位的宽度、高度、背景颜色和文本颜色。将以下代码添加到`cinema.css`中：

    ```js
    #a1,#a2,#a3,#a4,#a5,#a6,#a7,#a8,#a9,
    #b1,#b2,#b3,#b4,#b5,#b6,#b7,#b8,#b9,
    #c1,#c2,#c3,#c4,#c5,#c6,#c7,#c8,#c9,
    #d1,#d2,#d3,#d4,#d5,#d6,#d7,#d8,#d9,
    #e1,#e2,#e3,#e4,#e5,#e6,#e7,#e8,#e9
    {
    background:#e5791e;
    color:#000000;
    width: 71px;
    height: 71px;
    }

    ```

    之前的代码为我们的电影院中的所有“座位”定义了大小、颜色和背景。现在我们在创建应用程序的布局和设计方面迈出了最后一步。

1.  现在我们将定义包含我们的座位的网格的布局和颜色。完成的 CSS 代码可以在`cinema-incomplete`文件夹的`source code`文件夹中的`cinema.css`文件中找到。将以下代码添加到`cinema.css`中：

    ```js
    .wrapper{
    position: relative;
    float: left;
    left: 0px;
    width: 840px;
    margin-bottom: 20px;
    background-color: #cccccc
    }
    ...
    .left1{
    position: relative;
    float: left;
    left: 10px;
    z-index:0;
    }
    .left2{
    position: relative;
    float: left;
    left: 30px;
    width: 71px;
    height: 71px;
    }
    ... ...
    .left8{
    position: relative;
    float: left;
    left: 150px;
    }
    .left9{
    position: relative;
    float: left;
    left: 170px;
    }

    ```

    这段 CSS 代码基本上定义了网格的每一列。一旦你完成了这个，将其保存为`cinema.css`和`cinema.html`。确保这些文件在同一个文件夹中。打开`cinema.html`在你的网页浏览器中，你应该会看到类似以下屏幕截图的东西：

    ![行动时间—编码、修改、抛出和捕获错误](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_06_01.jpg)

    如果你发现有什么不对劲的地方，你可能想比较一下你的代码和在`cinema-incomplete`文件夹中找到的示例源代码。

    现在我们已经完成了应用程序的设计和布局，是时候为我们添加应用程序的行为了。以下部分的完整代码示例可以在*第六章*的`cinema-complete`文件夹中找到。

1.  我们将使用一个外部的 JavaScript 文件。所以让我们在`</head>`标签之前添加以下代码片段：

    ```js
    <script type="text/javascript" src="img/cinema.js"></script>

    ```

1.  现在让我们创建一个新的文件，命名为`cinema.js`。我们将专注于创建票务预订机制。因为我们将通过点击座位来预订票，所以我们需要一个处理点击事件的机制。因为我们在 HTML 代码中已经包含了`onclick="checkBooking(this)"`，我们现在需要做的是创建一个处理点击事件的函数。将以下代码添加到`cinema.js`中：

    ```js
    function checkBooking(element) {
    var id = element.id;
    var status = document.getElementById(id).innerHTML;
    // "<P>Available</P>" is for an IE quirks
    if(status === "<p>Available</p>" || status === "<P>Available</P>" )
    addBooking(id);
    else
    removeBooking(id);
    //alert(id);
    return true;
    }

    ```

    请注意，之前的代码检查了`div`元素的`innerHTML`，并检查它是否为`<p>Available</p>`。如果是，这意味着座位是可用的，我们可以继续预订座位。如果不是，座位已被预订，点击`div`元素将导致取消座位的预订。

    带着这个想法，我们需要再写两个函数，以帮助我们进行座位预订和取消预订。

1.  我们现在将创建两个更多的函数，用于预订或取消座位的预订。在`cinema.js`前添加以下代码：

    ```js
    var counterNumReservations = 0;
    function addBooking(id) {
    // add 1 to counterNumReservations when a user clicks on the seating
    // alert("addBooking");
    document.getElementById(id).style.backgroundColor = "#000000";
    document.getElementById(id).style.color = "#ffffff";
    document.getElementById(id).innerHTML = "<p>Booked!</p>";
    counterNumReservations = counterNumReservations + 1;
    document.getElementById("tickets").innerHTML = "<p>You have booked " + counterNumReservations + " tickets</p>">";
    return true;
    }
    function removeBooking(id) {
    // minus 1 from counterNumReservations when a user clicks on a seating that is already booked
    // alert("removeBooking");
    document.getElementById(id).style.backgroundColor = "#e5791e";
    document.getElementById(id).style.color = "#000000";
    document.getElementById(id).innerHTML = "<p>Available</p>";
    counterNumReservations = counterNumReservations - 1;
    document.getElementById("tickets").innerHTML = "<p>You have booked " + counterNumReservations + " tickets</p>">";
    return true;
    }

    ```

    我们使用了一个全局变量来跟踪预订的票数或座位数。之前的函数所做的就是它们将增加或减少（如适当）`counterNumReservations`，同时改变`div`元素的内容，以反映预订过程的状态。在这种情况下，被预订的座位将是黑色的。

    现在，保存你的文件，点击座位。你应该能够收到关于预订过程的视觉反馈。

    我们将转移到表单处理机制。

1.  表单处理机制基本上处理以下内容：计算总消费、总餐量、用户支付的金额、找零（如有）、以及其他可能的错误或条件，如是否支付了足够的金额、是否使用了百元大钞等。有了这个思路，我们将创建以下函数：

    ```js
    function checkForm(){
    var mealPrice;
    var special;
    var hundred;
    var change;
    var ticketPrice
    if(calculateMealQty() == 1 && checkHundred() == 1 && checkSpecial() == 1 && checkMoney() == 1) {
    alert("passed! for checkForm");
    mealPrice = calculateMealPrice();
    special = specialOffer();
    ticketPrice = calculateTicketPrice();
    change = parseInt(amountReceived()) - parseInt((mealPrice + special + ticketPrice));
    alert(change);
    success(change);
    }
    else
    alert("there was something wrong with your order.");
    return false;
    }

    ```

    为了创建模块化的代码，我们将功能划分为单独的函数。例如，`success()`和`failure()`用于创建 HTML 内容，显示预订过程的状态。

    同样地，注意我们将需要为计算餐量、检查总消费金额等创建其他函数。这些函数是基于我们从*第一章*到*第五章*所学习的内容创建的，所以我将快速进行。现在，让我们创建这些函数。

1.  我们现在将为计算餐量、总餐价、总票价等创建各种函数。我们从计算餐量开始：

    ```js
    function calculateMealQty() {
    var total = parseInt(document.foodForm.hotdogQty.value) + parseInt(document.foodForm.popcornQty.value);
    alert("you have ordered " + total + " meals");
    if(total > counterNumReservations) {
    alert("you have ordered too many meals!");
    failure("you have ordered too many meals!");
    return 0;
    }
    else {
    alert("ok proceed!");
    return 1;
    }
    }

    ```

    现在，我们将编写用于计算餐价的函数：

    ```js
    function calculateMealPrice() {
    // add up total price
    var price = 6*parseInt(document.foodForm.hotdogQty.value) + (4*parseInt(document.foodForm.popcornQty.value));
    alert("meal price is " + price);
    return price;
    }

    ```

    接下来是用于计算票价的函数：

    ```js
    function calculateTicketPrice() {
    var price = counterNumReservations * 10;
    alert("ticket price is " + price);
    return price;
    }

    ```

    我们现在将编写用于计算用户在天行者套餐上花费的函数：

    ```js
    function specialOffer() {
    // for more ordering offers
    var skywalker = 10 * parseInt(document.foodForm.skywalker.value);
    alert("skywalker price is " + skywalker);
    return skywalker;
    }

    ```

    完成这一步后，我们将编写一个小函数来核对收到的金额：

    ```js
    function amountReceived() {
    var amount = parseInt(document.foodForm.hundred.value);
    alert("I received "+ amount);
    return amount;
    }

    ```

    既然我们已经完成了大部分计算的功能函数，是时候编写用于检查用户是否点了过多的天行者套餐的函数了：

    ```js
    function checkSpecial() {
    if(parseInt(document.foodForm.skywalker.value) > (parseInt(document.foodForm.hotdogQty.value) + parseInt(document.foodForm.popcornQty.value))){
    alert("you have ordered too many sky walker");
    failure("you have ordered too many sky walker");
    return 0;
    }
    else {
    return 1;
    }
    }

    ```

    完成上一步后，是时候检查用户是否支付了太少的钱：

    ```js
    function checkMoney() {
    var mealPrice = calculateMealPrice();
    var special = specialOffer();
    var ticketPrice = calculateTicketPrice();
    var change = amountReceived() - (mealPrice + special + ticketPrice);
    alert("checkMoney :" + change);
    if(change < 0) {
    alert("you have paid too little money!");
    failure("you have paid too little money!");
    return 0;
    }
    else
    return 1;
    }

    ```

    正如一开始所规定的，我们还需要检查用户是否使用了百元大钞支付。这样做如下：

    ```js
    function checkHundred() {
    // see if notes are in hundreds
    var figure = parseInt(document.foodForm.hundred.value);
    if((figure%100) != 0) {
    alert("You did not pay in hundreds!");
    failure("You did not pay in hundreds!");
    return 0;
    }
    // can use error checking here as well
    else {
    alert("checkHundred proceed");
    return 1;
    }
    }

    ```

    最后，创建反映预订状态的 HTML 内容的函数如下：

    ```js
    function failure(errorMessage) {
    document.getElementById("orderResults").innerHTML = errorMessage;
    }
    function success(change) {
    document.getElementById("orderResults").innerHTML = "Your order was successful.";
    document.getElementById("orderResults").innerHTML += "Your change is " + change + " and you have purchased " + counterNumReservations + " tickets.";
    }

    ```

    哇！编写了不少代码！你可能想保存你的文件并在浏览器中测试你的应用程序。你应该有一个完整运行的应用程序，前提是你正确输入了代码。至此阶段的完整代码可以在`cinema-complete`文件夹中找到。

    虽然我们刚刚经历了一个繁琐的过程，但这是一个必要的过程。你可能会问为什么我们首先要编写代码而不是立即测试。我的回答是，首先，在真实的企业世界中，我们很可能会先编写代码然后再测试我们编写的代码。其次，如果我要创建一个教程并让你测试代码，而不知道代码是什么，这可能会让你处于困境，因为你可能不知道要测试什么。最重要的是，我们采取的方法允许你练习编程技能并理解代码的内容。

    这将帮助你理解如何在代码中应用`try`、`catch`和其他内置异常对象；我们现在就会进行这个操作。

1.  我们现在将创建一个函数，用于通过使用内置对象抛出和捕获我们的错误。现在，打开`cinema.js`并在文档顶部添加以下代码：

    ```js
    function catchError(elementObj) {
    try {
    // some code here
    }
    catch (error) {
    if(error instanceof TypeError){
    alert(error.name);
    alert(error.message);
    return 0;
    }
    else if(error instanceof ReferenceError){
    alert(error.name);
    alert(error.message);
    return 0;
    }
    ... ...
    else if(error instanceof EvalError){
    alert(error.name);
    alert(error.message);
    return 0;
    }
    else {
    alert(error);
    return 0;
    }
    }
    finally {
    alert("ok, all is done!");
    }
    }

    ```

    之前的代码将构成我们的`catchError()`函数的框架。基本上，这个函数所做的就是捕获错误（或潜在的错误），并测试它是什么类型的错误。在这个例子中，我们将看到这个函数的两个示例用法。

    第一个例子是一个简单的例子，展示我们如何在其他函数中使用`catchError()`，以便我们可以捕获任何实际或潜在的错误。在第二个例子中，我们将使用`catchError()`抛出和捕获一个`TypeError`。

    这个阶段的完整代码可以在`cinema-error-catching`文件夹中找到。请注意，除了添加`catchError()`和`addBooking()`函数的一些小改动外，大部分代码都没有改变。

1.  我们将现在尝试通过在`try`块中添加以下代码片段来捕获一个`ReferenceError`（如果你使用的是 Internet Explorer，则为`TypeError`）：

    ```js
    x = elementObj;

    ```

    接下来，在函数`addBooking()`顶部添加以下代码：

    ```js
    var test = catchError((counterNumReservations);
    if(test == 0)
    return 0; // stop execution if an error is catched;

    ```

    我们在这里试图做的是，如果我们发现任何错误，就停止 JavaScript 代码的执行。在上面的代码片段中，我们向`catchError()`传递了一个变量，`counterNumReservations`，作为示例。

    现在，保存文件并测试程序。程序应该正常工作。然而，如果你现在将`try`块中的代码更改为：

    ```js
    var x = testing;

    ```

    在测试未定义的地方，当你执行你的应用程序时，你将收到一个`ReferenceError`（如果你使用的是 Firefox 浏览器）或`TypeError`（如果你使用的是 Internet Explorer）。

    之前的简单示例显示，你可以向`catchError()`函数中传递变量，以检查它是否是你想要的。

    现在，让我们来做一些更难的事情。

1.  我们将现在尝试抛出和捕获一个`TypeError`。首先，移除上一个示例中我们所做的更改。我们在这里所做的就是检查传递到`addBooking()`函数中的对象是否是我们想要的`nodeType`。通过在`addBooking()`函数顶部添加以下代码，我们可以实现这一点：

    ```js
    var test = document.getElementById(id);
    // alert(test.nodeName); // this returns a DIV -> we use nodeName as it has more functionality as compared to tagName
    var test = catchError(test.nodeType);
    // nodeType should return a 1
    if(test == 0)
    return 0; // stop execution if an error is catched;

    ```

请注意上述代码行。我们所做的是获取`id`元素的`nodeType`。这个结果将被用作`catchError()`函数的参数。关于`nodeType`的一些基本细节，请访问[`www.w3schools.com/htmldom/dom_nodes_info.asp`](http://www.w3schools.com/htmldom/dom_nodes_info.asp)。

现在，移除你对`catchError()`所做的任何更改，并在`try`块中添加以下代码：

```js
var y = elementObj;
// var correct is the type of element we need.
var correct = document.getElementById("a1").nodeType;
alert("Correct nodeType is: " + correct);
var wrong = 9; // 9 represents type Document
if(y != correct){
throw new TypeError("This is wrong!");
}

```

请注意，我们通过检查结果整数来测试`nodeType`。任何不正确的东西（`correct`变量是 1）都会导致错误，如`if`语句块所示。

保存文件，然后运行你的示例。你应该首先收到一个警告框，告诉你**正确的 nodeType 是 1**，然后是消息**TypeError**。接下来，你会看到消息**这是错误的**（这是一个个性化消息）和最后的消息**好的，一切都完成了**，表示`catchError()`函数的结束。

我们所做的是针对不同的错误类型抛出自定义错误。在我们的案例中，我们想要确保我们传递了正确的`nodeType`。否则，这是一个错误，我们可以抛出自定义错误。

有了这些，我们将结束这个示例。

## 有勇气尝试的英雄——使用 catchError 函数检查输入

既然你已经覆盖了不少代码并获得了一些新知识，你可能想尝试一下：使用`catchError()`函数来检查用户输入的正确性。你会怎么进行呢？以下是一些帮你开始的想法：

+   你可能想确保输入的值在传递给其他函数之前经过`catchError()`。

+   你会在其他函数中实现`catchError()`吗？还是输入时立即传递给`catchError()`的值，然后传递给其他函数？

# 总结

在本章中我们已经覆盖了不少概念。最重要的是使用内置对象通过 JavaScript 的异常处理机制，以及这些对象与`try, catch`和`finally`语句一起使用。然后我们尝试将这些概念应用到我们创建的电影票预订应用程序中。

我们还学习了以下主题：

+   当使用脚本一起时发生的问题，如名称冲突和组合事件处理程序以使代码更加紧凑。

+   为什么我们需要使用 JavaScript 库，以及需要考虑的问题，如文档的可用性、教程、插件和测试套件。

+   我们如何利用像 Selenium 这样的工具来测试库的 GUI 和小部件插件（这些将在第八章中详细介绍）。

+   我们如何可以编写错误消息，或者我们自己的消息，到控制台日志。

+   如何通过使用 JavaScript 内置对象进行异常处理，并使用这些对象与`try, catch`和`finally`语句一起使用。

+   如何在示例应用程序中使用 JavaScript 的异常处理机制。

到目前为止，我们已经使用手动方式测试我们的代码，尽管现在使用更先进的测试方法。在下一章中，我们将学习如何使用不同的调试工具来使调试更容易，这将是测试的一部分。这将包括使用如 IE8 开发者工具、Firefox 的 Firebug 扩展、Google Chrome 网络浏览器检查器以及 JavaScript 调试器等工具。

这些工具之所以强大，是因为它们允许我们以一种不那么侵扰的方式进行测试；例如，我们通常无需使用`alert()`，因为我们可以将这些工具的内置控制台作为日志输出窗口。这能节省大量时间，并使我们的测试过程更加顺畅。我们将在接下来的课程中学习这些不同的调试工具。


# 第七章：调试工具

> 在本章中，我们将学习一些可以使我们的生活更轻松的调试工具。我们将使用市场上主要浏览器（如 Internet Explorer、Firefox、Google Chrome 和 Safari）提供的调试工具。
> 
> 我明白互联网上有详尽的文档，因此你可以在这一章期待的是我会非常简要地介绍一下特性，然后通过一个简单的例子说明如何利用调试功能让生活变得更轻松。

通常，你会了解到每个浏览器中提到的调试工具的以下主题：

+   获取调试工具的位置和方式

+   如何使用工具调试 HTML、CSS 和 JavaScript

+   高级调试，如设置断点和观察变量

+   如何使用调试工具进行性能分析

那么让我们开始吧。

# IE 8 开发者工具（以及为 IE6 和 7 设计的开发者工具栏插件）

本节我们将重点介绍 Internet Explorer 8 的开发者工具栏。

### 注意

如果你正在使用 Internet Explorer 6 或 7，以下是你如何可以为 Internet Explorer 6 或 7 安装开发者工具栏的方法。

你需要访问 [`www.microsoft.com/downloads/details.aspx?familyid=e59c3964-672d-4511-bb3e-2d5e1db91038&displaylang=en`](http://www.microsoft.com/downloads/details.aspx?familyid=e59c3964-672d-4511-bb3e-2d5e1db91038&displaylang=en) 并下载开发者工具栏。如果你阅读的是这本书的纸质版，无法复制和粘贴上述 URL，那么就谷歌“IE6 或 IE7 的开发者工具栏”，你应该会来到你需要的下载页面。

请注意，上述网页上的工具栏与 Internet Explorer 8 不兼容。

如果你不想单独安装开发者工具，我建议你安装 Internet Explorer 8；IE8 预装了他们的开发者工具，与为 IE6 或 IE7 单独安装开发者工具相比，它更为方便。

从这一刻起，我将涵盖使用 Internet Explorer 8 内置工具的开发者工具。

# 使用 IE 开发者工具

因为我们已经获得了插件，现在是时候通过一个例子来了解它是如何工作的了。我为此章节准备了`source code`文件夹中的示例代码；转到文件夹并在浏览器中打开名为`IE-sample.html`的文件。这个示例基本上要求你输入两个数字，然后对这两个数字进行加法、减法、乘法和除法。结果将显示在表单右侧的框中。

现在给它一个测试，完成后我们开始学习如何使用 IE8 的调试工具调试这个网页。

## 打开

我假设文件仍然在你的浏览器中打开。如果不是，请在浏览器中打开`IE-sample.html`（当然，使用 Internet Explorer）。一旦示例打开，您需要打开调试工具。您可以导航到**工具**，然后点击**开发者工具**。或者，您可以通过按键盘上的*Shift* + *F12*来访问调试工具。

## 用户界面的简要介绍

在我们进入实际的调试过程之前，我将简要关注 IE 调试工具的关键特性。

![用户界面简介](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_21.jpg)

1.  HTML：**HTML**标签显示您当前查看的脚本或网页的源代码。当你点击这个标签时，你会在右侧得到相关标签，如图所示。

1.  CSS：**CSS**标签显示了当前您正在查看的网页所使用的 CSS 样式表。

1.  脚本：**脚本**标签是您执行 JavaScript 调试任务的地方。当你点击这个标签时，你会得到一些与调试任务相关的特性，比如**控制台、断点、局部变量**和**监视**。

1.  **Profiler**：**Profiler**标签显示了网页的剖析数据，如果您选择进行剖析的话。

## IE 调试工具的基本调试

通常，我们可以用 IE 的调试工具两种方式：

+   在一个单独的窗口中

+   在浏览器内停靠

您可以通过点击调试窗口右上角的钉子图标将调试工具停靠在浏览器内。在我的情况下，我更喜欢将其停靠在我的浏览器中，这样我屏幕上就有更多的查看空间。而且，由于示例代码相当小，将其停靠在您的浏览器上应该就足够了。

通常，调试面板的左侧是 IE 团队所说的**主要内容**面板。这个面板显示了网页的文档对象模型；这个面板让我们从程序化的角度 overview 网页的源代码。

以下是一些使用 IE 调试工具进行调试的基本知识。

# 行动时间——使用 IE8 开发者工具调试 HTML

1.  要检查网页的 HTML 元素，请点击**主要内容面板**中的**HTML**标签。我们可以点击位于**主要内容面板**第一行上的**+**图标。

1.  一旦你点击了**+**图标，你应该会看到`<head>`和`<body>`在`<html>`标签展开后立即出现；再次点击它们将会显示`<head>`和`<body>`标签包含的其他元素。例如，让我们点击具有`id wrap`的`div`元素。

1.  点击`div`元素后，您可以立即看到与`wrap`相关的各种属性，如其父元素、继承的 HTML 和 CSS，以及属于`wrap`的 CSS 属性。

    我们可以通过点击调试窗口中**属性面板**上的各种命令来进一步检查：

    +   **样式**：**样式**命令通过提供适用于选定元素的的所有规则列表，改善了 CSS 的调试。规则按优先级顺序显示；所以最后应用的规则出现在底部，任何被另一个属性覆盖的属性都会被划掉，让你能快速理解 CSS 规则如何影响当前元素，而不需要手动匹配选择器。您可以通过切换规则旁边的复选框，快速开启或关闭 CSS 规则，动作将立即在您的页面上生效。在我们这个案例中，你会看到我们的`#wrap`元素有两个继承：body 和 HTML。你可以通过点击属性值并输入`#eee`，将颜色属性更改为`#eee`。完成后，按下*Enter*，您可以看到变化立即生效。

    +   **追踪样式**：这个命令包含了与**样式**相同的信息，只不过它按照属性对样式进行了分组。如果你正在寻找关于某个特定属性的信息，切换到**追踪样式**命令。只需找到你感兴趣的属性，点击加号（+）图标，就能看到设置该属性的所有规则列表——再次按照优先级顺序排列。

    +   **布局**：**布局**命令提供了盒模型信息，如元素的偏移、高度和内边距。在调试元素的定位时使用这个命令。

    +   **属性**：**属性**命令允许你查看选定元素的的所有定义属性。这个命令还允许你编辑、添加或删除选定元素的属性。

# 行动时间——使用 IE8 开发者工具调试 CSS

现在让我们将注意力重新转移到**主要内容面板**。

1.  点击**CSS**标签，以便我们可以访问所有的 CSS（外部或内部）文件。一旦你这样做，你会看到我们网页上使用的相同的 CSS。

1.  现在我想要你点击**BODY**中的一项样式属性，比如**color**，并将其更改为**#ccc**。你将立即看到我们网页上文本颜色的变化。

## 刚才发生了什么？

我们刚刚完成了调试的基本操作，这为我们提供了在使用 IE 的调试工具调试 JavaScript 之前所需的知识。

我们上面执行的简单例子，就是我们所说的实时编辑源；我们可以编辑任何 HTML 或 CSS 属性，而无需回到我们的源代码，更改它，保存它，然后在浏览器中重新加载文件。在我看来，这样的功能是我们使用调试工具的关键原因之一。

然而，请注意，你所做的更改只存在于 Internet Explorer 对网站的内部表示中。这意味着刷新页面或导航离开会恢复原始网站。

然而，有些情况下你可能想保存更改，为了做到这一点，你可以点击**保存**按钮，将当前的 HTML 或 CSS 保存到文件中。这是为了防止意外覆盖你的原始源代码。

让我们继续学习 JavaScript。

## 调试 JavaScript

现在该学习如何使用 IE 的开发者工具调试 JavaScript 了。

# 行动时间——使用 IE8 开发者工具进行更多 JavaScript 调试

以下是开始调试的步骤：

1.  点击在**主内容面板**中找到的**脚本**标签。

1.  接下来，点击写着**开始调试**的按钮。

1.  点击**开始调试**后，你将拥有一个完整调试器的所有功能。

    如果你希望在调试过程中的任何一点停止调试，请点击**停止调试**。

    现在让我们看看我们可以使用调试工具的各种功能做什么。让我们从第一个开始：设置断点。

    我们通常设置断点以控制执行。在前几章中，我们通常依赖于`alert()`或其他函数来控制程序执行。

    然而，通过使用 IE 的调试工具，你只需设置断点就可以控制程序执行；在这个过程中，你可以节省很多`alert()`，或其他自定义函数。

    现在，让我们通过使用断点来控制执行。

1.  你可以通过右键点击行号并选择**插入断点**来设置断点。在我们的案例中，让我们去包含`buildContent(answerB, "minus")`;的那一行，右键点击它，然后选择**插入断点**。

1.  现在尝试在浏览器中输入一些值到输入字段中。你会看到，动态内容不会在右侧的**黑色正方形**上创建。这是因为代码执行在`buildContent(answerB, "minus")`;处停止了。

    我们通常使用断点来检查变量；我们需要知道我们的代码是否以我们希望的方式执行，以确保它是正确的。现在，让我们看看如何设置断点和检查变量。

    我们通过使用监视功能来检查变量。继续上一个示例，我们可以通过点击监视窗格来使用监视功能。另外，你也可以点击本地变量，它提供了类似的功能，允许我们看到一组变量。这可以用来监视自定义变量列表，也可以检查变量的当前状态。

    要执行我们刚刚描述的操作，我们需要执行以下步骤：

1.  点击**开始调试**，并为包含`var answerA = add(numberA, number)`;和`buildContent(answerA, "add")`;的行设置断点。

1.  现在，运行示例，分别为输入字段输入**5**和**3**。然后点击**提交**。

1.  现在转到你的 **调试器** 面板，点击 **局部变量**。你会看到以下截图的输出：![行动时间—使用 IE8 开发者工具进行更多 JavaScript 调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_01.jpg)

    +   这个面板显示的是与设置断点的函数相关的局部变量列表

        注意到 **answerA**, **answerB**, **answerC**, 和 **answerD** 目前都是未定义的，因为我们还没有为它们执行任何计算，因为我们已经在 `var answerA = add(numberA, number)` 处设置了断点。

1.  接下来，点击 **监视**。现在你可以添加你想要检查的变量。你可以通过输入变量的名称来实现这一点。输入 **answerA** 和 **numberB**，然后按 *Enter*。你会看到一个类似于以下截图的屏幕：![行动时间—使用 IE8 开发者工具进行更多 JavaScript 调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_02.jpg)

    +   如前所述，**answerA** 目前还没有定义，因为它还没有被我们的程序计算出来。另外，因为我们已经为 **numberA** 和 **numberB** 输入了值，所以 **numberB** 自然是有定义的。

    ### 注意

    你注意到我们的输入类型不正确了吗？这是因为我们使用了 `.value` 方法来访问输入字段的值。作为一个优秀的 JavaScript 程序员，我们应该使用 `parseFloat()` 将值转换为浮点数。

    +   我们可以在调试模式下继续执行代码（在调试窗口中）通过执行 Continue、Step In、Step Over 和 Step Out 操作。

        我们将快速进入示例，看看 Continue、Step In、Step Over 和 Step Out 是如何工作的。继上面的例子继续：

1.  点击绿色的 **Continue** 按钮，它看起来像一个 "**播放**" 按钮。立即，你会看到代码将执行到下一个断点。这意味着之前未定义的变量现在将被定义。如果你点击 **局部变量**，你会看到类似于下一个截图的输出：![行动时间—使用 IE8 开发者工具进行更多 JavaScript 调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_03.jpg)

1.  点击 **监视**，你会看到一个类似于下一个截图的屏幕：![行动时间—使用 IE8 开发者工具进行更多 JavaScript 调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_04.jpg)

    这意味着 Continue 的效果是执行从第一个断点到最后一个断点的代码。如果没有第二个断点，代码将执行到末尾。

    你可能想尝试 Step In、Step Over 和 Step Out。

    通常，它们就是这样做的：

    +   步入（Step In）：这会跟踪代码的执行。例如，您可以执行上述示例中的步骤，只是点击**步入**而不是**继续**。您会注意到，您实际上正在跟踪代码。接下来，您可以查看**局部变量**和**监视**窗口，您会注意到 previously-undefined 变量将在代码执行过程中被定义。

    +   步过（Step Over）：这会直接跳到下一行代码，而不是像步入（Step In）那样跳进其他函数。

    +   步出（Step Out）：这会“步出”当前断点，直到下一个断点。它与**继续**类似。如果您在步入（Step In）之后使用步出（Step Out），它将继续到下一个断点（如果有）。

        现在让我们继续了解下一个有用功能，即在遇到错误时停止代码。

        要启用此功能，您需要点击**在错误时中断**按钮，或者您可以简单地按*Ctrl* + *Shift* + *E*。一旦您开始调试，此功能应该会自动启用。

        这个功能的作用是如果在执行代码时发现任何错误，就停止执行。例如，取消注释说：`buildContent(noSuchThing, "add");` 这行代码，并在调试模式下运行代码。您将在调试窗口的控制台中看到以下屏幕截图：

    ![行动时间—使用 IE8 开发者工具进行更多 JavaScript 调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_05.jpg)

    使用调试器的一个酷炫之处在于，它可以帮助您在运行时发现错误，这样您就可以快速识别您犯的错误。

    现在我们已经对 IE 调试工具的一些更高级功能有了基本的了解和认识，是时候关注我们 JavaScript 程序的性能了。

    Internet Explorer 调试工具附带一个内置分析器，名为 JavaScript 分析器，通过提高性能帮助您的网站达到一个新的水平。

    通常，分析器会为您提供您网站的 JavaScript 方法以及内置 JavaScript 函数中花费的时间数据。这就是如何使用这个功能。

1.  使用浏览器中的示例源代码，打开**开发**工具并点击**分析**标签。然后点击**开始分析**，以开始一个会话。

1.  打开您的浏览器，输入一些示例值。例如，我输入了**5** 和 **3**。输入示例值后，转到您的调试窗口并点击**停止分析**。将显示以下屏幕截图的类似屏幕：![行动时间—使用 IE8 开发者工具进行更多 JavaScript 调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_06.jpg)

+   请注意，Jscript Profiler 包括每个函数花费的时间（每个函数的名称也给出）。每个函数的使用次数也给出，如计数栏所示。您可能注意到我们每个函数的时间都是 0.00；这是因为我们的示例程序相对较小，所以所需时间接近零。

## 刚才发生了什么？

我们刚刚介绍了 Internet Explorer 的开发者工具，它帮助我们从更流畅的方式执行调试任务。

以防你想知道手动调试与使用调试工具之间的区别，我可以根据经验 safely tell you that the amount of time saved by using a debugging tool alone is a good enough reason for us to use debugging tools.

你可能知道，在为 Internet Explorer 开发时会有各种怪癖；使用其内置的调试工具可以帮助你更有效地找出这些怪癖。

带着这个想法，让我们继续介绍下一个工具。

# Safari 或 Google Chrome 网络检查器和 JavaScript 调试器

在本节中，我们将学习 Safari 和 Google Chrome 中使用的 JavaScript 调试器。尽管两者有相似的代码基础，但存在微妙的差异，因此让我们先了解 Safari 和 Google Chrome 之间的区别。

## Safari 与 Google Chrome 之间的差异

如果你是苹果粉丝，你无疑会认为 Safari 可能是地球上最好的浏览器。然而，Google Chrome 和 Safari 都源自一个名为 WebKit 的开源项目。

Safari 和 Google Chrome 使用不同的 JavaScript 引擎。从**Safari 4.0**开始，Safari 使用了一种名为 SquirrelFish 的新 JavaScript 引擎。Google Chrome 使用 V8 JavaScript 引擎。

然而，在使用 Google Chrome 和 Safari 提供的内置调试器进行 JavaScript 调试时，两者几乎完全相同，甚至界面也很相似。

在接下来的部分，我将使用 Chrome 来解释示例。

## Chrome 中的调试

对于 Google Chrome，我们无需下载任何外部工具即可执行调试任务。调试工具随浏览器本身一起提供。所以现在，我们将看到如何使用`sample.html`开始我们的调试会话。

打开和启用：我们首先需要在 Chrome 中打开和启用调试。在 Google Chrome 中，您可以使用两个工具来帮助您为 Web 应用程序执行调试任务：网络检查器和 JavaScript 调试器。

网络检查器：谷歌浏览器的网络检查器主要用于检查您的 HTML 和 CSS 元素。要使用网络检查器，只需在网页上的任何组件上右键单击即可启动网络检查器。您将能够看到您点击的组件的相关元素和资源，包括 DOM 的层次视图和一个 javascript 控制台。要使用网络检查器，请在谷歌浏览器中打开`example.html`。将鼠标移至侧边栏上写着**列 2**的地方。在**列 2**上右键单击，您将看到一个弹出菜单。选择**检查元素**。一个新的窗口被打开。这就是网络检查器。

现在我们将进入 javascript 调试器。

javascript 调试器：要使用谷歌浏览器的 javascript 调试器，选择**页面菜单**图标，该图标位于**URL**输入字段的右侧，然后单击**开发者** | **调试 javascript 控制台**。你也可以通过按下*Ctrl* + *Shift* + *J* 来启动 javascript 调试器。如果您使用的是 Safari，您需要首先通过点击位于**页面**图标右侧的**显示设置**图标来启用开发者菜单，选择**偏好设置**，然后单击**高级**。在此屏幕上，启用**在菜单栏中显示开发菜单**选项。然后，您可以通过点击**页面**图标并选择**开发者**和**开始调试 javascript**来访问这个菜单栏。这个界面与我们在谷歌浏览器中看到的基本相同。

请注意，打开 javascript 调试器后，您将打开与网络检查器中看到的相同的窗口。然而，现在的默认标签页是**脚本**。在这个标签页中，您可以查看前一小节中提到的我们例子的源代码。

这是我们将要用来执行我们的调试任务的主屏幕。在接下来的会话中，我们将开始做一些基本的调试，让我们的手指稍微脏一些。

如果您已经完成了我们在使用 Internet Explorer 开发者工具的调试会话，您将要执行的大部分任务和行动在概念上应该是相似的。

我们刚刚探索了打开和开始网络检查器和 javascript 调试器的基本操作。现在让我们简要介绍一下用户界面，以便让您跟上进度。

## 用户界面的简要介绍

以下是对您如何在谷歌浏览器调试工具中找到关键功能的简要说明，如图所示：

![用户界面的简要介绍](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_22.jpg)

1.  元素：**元素**标签页显示您当前正在显示的脚本或网页的源代码。当你点击**元素**图标时，你会得到一些相关标签页（如前一个屏幕快照中所示的**计算样式**）。

1.  脚本：**脚本**标签是你将执行你的 JavaScript 调试任务的地方。当你点击**脚本**图标时，你会得到一个与调试相关的功能的列表，比如**监视表达式、调用栈、作用域变量**和**断点**。

1.  配置文件：**配置文件**标签显示了你选择进行配置时网页的配置数据。

# 行动时间—使用 Chrome 进行调试

1.  我们现在将学习如何使用控制台并利用断点来简化我们的调试会话。我们从控制台开始。

1.  控制台基本上显示了你在调试会话中做了什么。我们首先看到如何访问控制台。

1.  首先，在你的 Google Chrome 浏览器中打开`sample.html`文件，如果你还没有这么做的话。一旦你完成了这个，按照以下步骤进行操作，以显示控制台：

1.  打开你的 JavaScript 调试器，通过选择**页面菜单**图标 ![行动时间—使用 Chrome 进行调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_07.jpg)，该图标可以在**URL**输入字段的右侧找到，然后前往**开发者** | **调试 JavaScript**。你也可以按*Ctrl* + *Shift* + *J* 启动 JavaScript 调试器。

1.  完成第 4 步后，点击控制台图标，该图标可以在 JavaScript 调试器的底部找到。完成后，你会看到一个类似于以下屏幕截图的屏幕：![行动时间—使用 Chrome 进行调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_08.jpg)

    现在我们已经打开了控制台，我们将继续学习调试器的最常用功能。在这个过程中，你也将看到控制台如何记录我们的行动。

    我们现在将继续学习如何设置断点。

    如前所述，设置断点是调试过程的重要部分。所以我们实际调试过程的起点就是设置一个断点。

1.  在 Google Chrome 中打开`sample.html`，开始你的调试器，并确保你处于**脚本**标签。你可以通过点击我们想要设置断点的行号来设置断点。让我们尝试点击包含`buildContent(answerB, "minus")`的行；然后点击行号。你会看到一个类似于以下屏幕截图的屏幕：![行动时间—使用 Chrome 进行调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_09.jpg)

    注意现在**第 130 行**有一个蓝色箭头（突出显示的行），在源代码面板的右侧，你会看到断点面板。现在它包含了我们刚刚设置的断点。

1.  运行示例，在浏览器中输入一些值到输入字段中。我希望你在第一个输入字段中输入**4**，在第二个输入字段中输入**3**。然后点击**提交**。你会看到动态内容不会在右边的黑色正方形中创建。这是因为代码已经停止在`buildContent(answerB, "minus")`；.

1.  现在回到你的调试器，你会看到你的源代码右侧下一个屏幕截图，类似于下面的示例：![行动时间—使用 Chrome 进行调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_10.jpg)

    你会看到**调用栈**和**作用域变量**现在正在用值填充，而监视表达式没有。我们将在接下来的几段中详细介绍这些内容。但现在，我们首先从**调用栈**和**作用域变量**开始。

    正如上一个屏幕截图所示，当我们执行程序时，**调用栈**和**作用域变量**现在正在用值填充。一般来说，**调用栈**包含了正在执行的函数的序列，而**作用域变量**显示了可用直到断点或执行结束的变量的值。

    当我们点击**提交**按钮时，会发生以下情况：首先执行的是`formSubmit()`函数，在这个函数内部，计算了`var answerA`、`var answerB`、`var answerC`和`var answerD`。这就是**作用域变量**如何用我们的值进行填充的。

    通常，这就是 Google Chrome 中**调用栈**和**作用域变量**的工作方式。现在，让我们关注一下我们心中一直存在的问题，**监视表达式**。

    在解释**监视表达式**之前，最好我们先看看它如何行动。回到上一个屏幕截图，你会注意到此时**监视表达式**还没有被填充。我们现在尝试通过执行以下步骤来填充监视表达式：

1.  刷新你的浏览器，回到你的调试器。

1.  在**监视表达式**面板上，点击**添加**，并输入以下内容：`document.sampleform.firstnumber.value`和`document.getElementById("dynamic")`。

1.  回到你的浏览器，输入**4**和**3**作为输入值。点击**提交**。假设你没有在上一个部分中移除我们设置的断点，你将在**监视表达式**面板上看到下一个屏幕截图中的信息：![行动时间—使用 Chrome 进行调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_11.jpg)

    **监视表达式**现在被填充了。`document.sampleform.firstnumber.value`和`document.getElementById("dynamic")`是从我们的 JavaScript 程序中复制的代码行。如果你追踪代码，你会注意到`document.sampleform.firstnumber.value`用于推导第一个输入字段的值，而`document.getElementById("dynamic")`用于引用`div`元素。

    截至目前，你已经理解了**监视表达式**用于检查表达式。你只需要添加你想要看到的表达式，在执行程序后，你将看到该表达式的意思、指向的内容，或者它当前的值。这允许你在程序执行时监视表达式的更新。你不需要完成程序就能看到变量的值。

    现在该转到调试窗口中的继续（Continue）、步进（Step In）、步过（Step Over）和步出（Step Out）操作了。

    这里的概念与我们之前在 Internet Explorer 开发者工具中看到的内容非常相似。如果你想知道执行这些操作的按钮在哪里，你可以发现在**观察表达式（Watch Expression）**面板上方。以下是每个操作的相关概念：

    +   步进（Step In）：这会在代码执行时跟踪代码。假设你仍然在我们的示例中，你可以点击带有向下箭头的图标。你会看到你实际上正在跟踪代码。继续点击**步进（Step In）**，你会看到**作用域变量（Scope Variables）**和**调用栈（Call Stack）**中的值发生变化。这是因为代码的不同点会有各种变量或表达式的不同值。

    +   步出（Step Out）：这仅仅是移动到代码的下一行，而不跳入其他函数，与步进（Step In）类似。

    +   步过（Step Over）：这仅仅是移动到代码的下一行。

        在本节最后，我们将重点介绍如何暂停在异常处。这意味着程序将在遇到问题的那行停止。我们将做什么来看它的实际作用：

1.  打开`sample.html`文件，在编辑器中搜索`buildContent (noSuchThing, "add")`这一行；取消注释它。保存文件并在 Google Chrome 中打开。

1.  打开**调试器**。点击带有暂停标志的按钮 ![行动时间—使用 Chrome 进行调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_25.jpg)，该按钮位于**显示控制台（Show Console）**按钮的右侧。这将在遇到错误时使调试器停止执行。

1.  像往常一样，为输入字段输入一些值。点击**提交**。完成后，回到你的调试器，你会看到以下屏幕截图中的信息：![行动时间—使用 Chrome 进行调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_12.jpg)

+   如果你启用了暂停异常功能，通常你会得到这种视觉信息。

## 刚才发生了什么？

我们已经介绍了使用 Google Chrome 的基础知识。如果你遵循了之前的教程，你将学会如何使用控制台、设置、步进、步出和越过断点、在异常时暂停以及观察变量。

通过使用上述功能的组合，你将能够快速嗅出并发现不意的 JavaScript 错误。你甚至可以跟踪你的 JavaScript 代码是如何执行的。

在接下来的几节中，你将开始注意到大多数工具都有非常相似的功能，尽管有些可能有不同术语表示相同的功能。

现在该转向另一个工具，即 Opera JavaScript 调试器了。

# Opera JavaScript 调试器（Dragonfly）

Opera 的 JavaScript 调试器被称为 Dragonfly。为了使用它，你所需要做的就是下载最新版本的 Opera；Dragonfly 已经包含在最新版本的 Opera 中。

既然你已经安装了必要的软件，是时候进行调试任务了。

## 使用 Dragonfly

我们首先从我们的`example.html`文件开始。在 Opera 浏览器中打开这个文件。现在我们将了解如何启动 Dragonfly。

### 启动 Dragonfly

要访问 Dragonfly，请转到菜单选项**工具**。选择**高级**，然后点击**开发者工具**。一旦你这样做，Dragonfly 就会出现。像往常一样，我们将从工具的用户界面简介开始。

#### 用户界面简介

以下是我们将使用的一些最重要功能的简要概述，如图所示：

![用户界面简介](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_23.jpg)

1.  **DOM:** 这个标签页用于检查 HTML 和 CSS 元素

1.  **脚本:** 当我们调试 JavaScript 时使用此标签页

1.  **错误控制台:** 这个标签页在调试 JavaScript 时显示各种错误信息。

我们现在开始调试`example.html`。

# 行动时间—使用 Opera Dragonfly 进行调试

1.  在本节中，我们将学习如何使用 Dragonfly 的调试功能。我们将从设置断点开始。

    这就是我们在 Dragonfly 中设置断点的方法：

1.  在 Opera 中打开`sample.html`，启动 Dragonfly，然后点击**脚本**标签页。您可以通过点击我们想要设置断点的行号来设置断点。让我们尝试转到包含`buildContent(answerB, "minus")`;的行，然后点击行号。

1.  打开你的浏览器，执行`example.html`。输入**5**和**3**作为输入值。点击**提交**按钮。像往常一样，你不会看到任何动态生成的内容。程序的断点在包含`buildContent(answerB, "minus")`;的位置。

1.  现在回到龙 fly，你会注意到**调用堆栈**和**检查**面板现在已填充。如果你输入与我相同的值，你应该会看到与下一个截图相似的值：![行动时间—使用 Opera Dragonfly 进行调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_14.jpg)

+   在**检查**和**调用堆栈**中显示的值是在断点之前的计算和执行的值和函数。

## 刚才发生了什么？

我们刚刚使用 Dragonfly 设置了一个断点，当我们执行我们的 JavaScript 程序时，我们看到了 Dragonfly 的各种字段是如何填充的。现在我们将详细介绍每个字段。

## 检查和调用堆栈

如前一个截图所示，当我们执行程序时，**调用堆栈**和**检查**会填充值。一般来说，**调用堆栈**显示特定函数调用时的运行时环境性质—已经调用了什么，以及以什么顺序调用。检查面板列出了当前调用的所有属性值及其他信息。堆栈帧是**调用堆栈**中的特定部分。检查的概念与在 Google Chrome 中看到的**作用域变量**相似。

## 线程日志

线程日志：这个面板显示了穿过你当前正在调试的脚本的各个线程的详细信息。

现在我们将继续深入了解龙翼的功能。

## 继续、步入、单步跳过、单步跳出和错误停止

我们还可以在调试代码时执行通常的继续、步入、单步跳过和单步跳出的任务。下面是一个截图，显示我们如何找到前面提到的功能：

![继续、步入、单步跳过、单步跳出和错误停止](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_15.jpg)

1.  继续：在停止在断点后继续当前选中的脚本。如果有的话，这将继续到下一个断点，或者它将继续到脚本的末尾。

1.  步入：这允许你在包含断点的当前函数之后的下一个函数中步入。它有效地追踪代码的执行。假设你仍然在我们的示例中，你可以点击带有向下箭头的**步入**图标。你会发现你实际上正在追踪代码。继续点击**步入**，你会看到**检查**和**调用栈**中的值发生变化。这是因为代码的不同点会有各种变量或表达式的不同值。

1.  单步跳过：这允许你在设置断点的行之后跳到下一行——你可以多次使用这个功能来跟随脚本的执行路径。

1.  单步跳出：这将使你跳出函数。

1.  错误停止：这允许你在遇到错误时停止执行你的脚本。为了看到这个功能，请在你的编辑器中打开`example.html`文件，并查找写着`buildContent(noSuchThing, "add")`的行；然后取消注释。保存文件，然后再次使用 Opera 打开它。打开龙翼，点击图标。现在在 Opera 中执行你的程序并输入一些示例值。完成后，你将在龙翼中看到以下截图：![继续、步入、单步跳过、单步跳出和错误停止](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_16.jpg)

注意，在**46**行有一个指向右边的黑色箭头。这意味着这行代码有一个错误。

在我们结束龙翼节段之前，我们再来看一个重要的功能：设置功能。

## 设置

OPERA 的龙翼有一个让我们为我们的调试任务创建不同设置的巧妙功能。这一系列设置很多，所以我不会全部介绍。但我将重点介绍那些对你的调试会话有用的设置。

+   脚本：在这个面板中，选中窗口后自动重新加载文档是一个巨大的时间节省功能，尤其是当你有多个 JavaScript 文件需要调试时，因为它将帮助你自动重新加载文档。

+   控制台：此面板允许你在调试会话中控制你想看到的信息。从 XML 到 HTML，你可以启用或禁用消息，以看到最重要的信息。

有了这个，我们将结束 Dragonfly 部分，继续学习 Firefox 和 Venkman 扩展。

# Firefox 和 Venkman 扩展

我们知道 Firefox 有很多插件和工具，其中一些是专为网页开发而设计的。在本节中，我们将学习 Mozilla 的 JavaScript 调试器 Venkman 扩展。

## 使用 Firefox 的 Venkman 扩展

我们将先获得扩展；我们将假设您已经安装了 Firefox。在我的情况下，我正在使用 Firefox 3.6.3。

### 获得 Venkman JavaScript 调试器扩展

为了获得 Venkman JavaScript 调试器扩展，请前往[`addons.mozilla.org/en-US/Firefox/addon/216/`](http://https://addons.mozilla.org/en-US/Firefox/addon/216/)并点击**添加到 Firefox**。安装后，Firefox 将提示您重新启动 Firefox 以使更改生效。

### 打开 Venkman

为了开始调试，让我们在 Firefox 中打开文件`example.html`。在这里，我们可以现在开始 Venkman。点击**工具**并选择**JavaScript 调试器**。如果你使用的是 Firefox 的旧版本，可以通过前往**工具** | **网页开发** | **JavaScript 调试器菜单**来访问它。

现在我们将对 Venkman 的用户界面进行简要介绍。

### 用户界面的简要介绍

下一张截图显示了 Venkman 扩展的用户界面：

![用户界面的简要介绍](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_24.jpg)

1.  已加载脚本：**已加载脚本**面板显示了您可以用于调试的脚本列表。加载脚本后，你将在**源代码**面板中看到它。

1.  局部变量和观察：**局部变量**面板显示在执行调试任务时可用的局部变量。如果您点击**观察**标签，您将看到**观察**面板。您将使用这个来输入您想要观察的表达式。

1.  断点和调用堆栈：**断点**面板允许您添加一系列断点，而**调用堆栈**面板按顺序显示执行的函数或变量。

1.  源代码：**源代码**面板显示您当前正在调试的源代码。

1.  互动会话：**互动会话**面板是此调试器的控制台。

现在我们将使用 Venkman 扩展开始调试：

# 是时候行动了——使用 Firefox 的 Venkman 扩展进行调试

我们将先设置断点，然后再详细说明：

与其他所有调试器一样，我们可以通过以下步骤设置断点：

1.  首先，在 Firefox 中打开文件`example.html`。

1.  打开 JavaScript 调试器，调试器窗口将显示出来。

1.  当你看到调试器窗口时，转到**加载脚本**面板，你将在其中看到文件`example.html`。点击它，你将在**源代码**面板上看到代码被加载。

1.  设置断点时，点击你想要设置断点的行。例如，我在包含以下代码的行**130**上设置了断点：`buildContent(answer, "minus")`；你应该会看到类似以下截图的内容：![行动时刻—使用 Firefox 的 Venkman 扩展进行调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_17.jpg)

## 刚才发生了什么？

首先要注意的是，在之前的截图中，有一个**白色 B**在一个红色矩形内。这表示已经设置了一个断点。

在 Venkman 中，有时你会看到一个**白色 F**在一个黄色盒子内；这表示 Venkman 只能设置一个未来的断点。当你的选择行没有源代码，或者如果该行代码已经被 JavaScript 引擎卸载（顶级代码有时在执行完成后不久就会被卸载）。

未来断点意味着 Venkman 现在无法设置一个硬断点，但如果文件稍后加载，并且在选择的行号有可执行代码，Venkman 将自动设置一个硬断点。

要关注的第二件事是**断点**面板。这个面板包含了我们在这个调试会话中设置的所有断点。

现在，在我们将要进入以下小节之前，我需要你通过打开浏览器输入我们示例应用程序的输入。在我的案例中，我在第一个和第二个输入框中分别输入了**5**和**3**。完成输入后，点击**提交**。

再次，你会注意到原来空白的面板现在充满了值。我们将在以下小节中介绍这个。

## 断点或调用栈

在前一个小节中我们已经简要介绍了断点。如果你看看**断点**面板，你会注意到在那个面板的右侧，有一个名为**调用栈**的标签页。

点击**调用栈**，你应该在这个新面板中看到一些数据。假设你已经输入了相同的输入和同样的断点，你会看到一个与下一个截图示例相似的屏幕：

![断点或调用栈](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_18.jpg)

通常，**调用栈**显示了在特定函数调用时的运行环境性质—调用什么，以及调用顺序。在 Venkman 中，它显示函数名、文件名、行号和 pc（程序计数器）。

## 局部变量和监视器

现在让我们关注**局部变量**和**监视器**。**局部变量**和**监视器**的面板位于**断点**和**调用栈**面板之上。如果你一直按照我的指示操作，并且输入完全相同的输入，你应在**局部变量**面板中看到以下内容：

![本地变量和观察](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_19.jpg)

**本地变量** 面板简单地显示了具有值（由于代码执行）的变量的值，直到断点，或者程序结束，根据它们创建或计算的顺序。

我们想要讨论的下一个面板是 **Watches** 面板。**Watches** 面板的作用和我们之前为其他浏览器做的 watch 表达式一样。然而，因为我们还没有为 **Watches** 面板添加任何内容，所以让我们采取一些行动来看看 **Watches** 面板是如何工作的：

# 是时候行动了——使用 Venkman 扩展进行更多调试

在本节中，我们将介绍更多的调试功能，比如观察、停止、继续、单步进入、单步跳过、单步退出、边缘触发和抛出触发。但首先，让我们执行以下步骤，以便看到 **Watches** 面板的实际作用：

1.  点击 **Watches** 标签。

1.  在 **Watches** 面板内部右键点击，选择 **添加观察**。

1.  输入 `document.sampleform.firstnumber.value`。

1.  重复步骤 2 和 3，这次输入 `document.getElementById("dynamic")`。

    完成后，你会看到以下屏幕截图的输出：

    ![是时候行动了——使用 Venkman 扩展进行更多调试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_07_20.jpg)

    **Watches** 面板的作用是允许我们添加一个表达式列表，以便我们跟踪这些表达式，并且还能显示这些表达式的值。

    现在让我们来看看停止和继续功能。

    Venkman 提供了一些有用的功能，包括停止和继续。停止功能基本上会在下一个 JavaScript 语句处停止，而继续功能则继续代码的执行。

    你可以让 Venkman 在下一行 JavaScript 语句处停止。

1.  点击工具栏上较大的红色 **X**，或者你可以去菜单选择 **调试**，然后选择 **停止**。

    有时没有执行 JavaScript。如果出现这种情况，你会在工具栏上的 **X** 上看到省略号（...），菜单项会被勾选。当遇到下一行 JavaScript 时，调试器将停止。你可以通过点击 **X** 或再次选择 **停止** 来取消这个操作。

    除了停止和继续功能，Venkman 还提供了标准的单步进入、单步跳过和单步退出功能。

    +   单步执行：这会执行一行 JavaScript 代码，然后停止。你可以通过点击写着 **Step Into** 的图标来尝试这个功能。如果你多次点击它，你会注意到局部变量在变化，你将能够看到代码被执行的情况，就像你在追踪代码一样。

    +   单步跳过：用于跳过即将到来的函数调用，并在调用返回时将控制权返回给调试器。如果你点击 **单步跳过**，你会发现新内容正在你的浏览器中创建。对于文件 `example.html`，假设你从断点点击 **单步跳过**，你会看到内容是从 `buildContent(answer, "minus")` 创建的；。

    +   步出：执行直到当前函数调用退出。

        我们将看到如何使用错误触发器和抛出触发器。

        错误触发器用于让 Venkman 在下一个错误处停止，而抛出触发器用于让 Venkman 在下一个异常抛出时停止。

        为了看到它的实际效果，我们将执行以下操作：

1.  在你的编辑器中打开`example.html`文件，再次搜索到`buildContent(noSuchThing, "add")`这一行，并取消注释。保存文件后再次打开，使用 Firefox。

1.  在 Firefox 中打开文件后，打开 Venkman。

1.  一旦你打开了 Venkman，点击**调试**|**错误触发器**，选择**在错误处停止**。然后，再次点击**调试**|**抛出触发器**，选择**在错误处停止**。

1.  打开你的浏览器，为输入字段输入任意两个数字——比如说分别是**5**和**3**。点击**提交**。

1.  返回 Venkman，你会发现`buildContent(noSuchThing, "add")`这一行被突出显示，在交互式会话（或控制台）面板中，你会看到一个错误信息，写着**X 错误。noSuchThing 未定义**。

    既然我们已经看到了 Venkman 在遇到错误时如何停止我们的程序，现在让我们转到它的剖析功能。

    正如我们在前一章节中提到的，剖析是用来测量脚本的执行时间的。要启用剖析：

1.  点击工具栏上的**剖析**按钮。当剖析被启用时，你会在工具栏按钮上看到一个绿色的勾选标记。

1.  一旦你启用了剖析，打开你的浏览器并输入一些示例值。我还是用**5**和**3**吧。然后点击**提交**。

1.  回到 Venkman，点击**文件**，选择**另存为配置数据**。我已经包含了一个例子，展示了我们刚刚做了什么，并将其保存为`data.txt`文件。你可以打开这个文件，查看剖析会话的内容。你可以在`data.txt`文件中通过搜索`example.html`来找到`sample.html`的剖析数据。

1.  完成剖析后，点击**剖析**再次停止收集数据。

    在剖析被启用时，Venkman 将为每个调用的函数收集调用次数、最大调用持续时间、最小调用持续时间和总调用持续时间。

    你也可以使用**清除剖析数据**菜单项清除所选脚本的剖析数据。

## 刚才发生了什么？

我们已经介绍了 Venkman 扩展的各种功能。像停止、继续、步进、步出和断点步进这些功能，在现阶段对你来说应该不再陌生，因为它们与我们之前介绍的工具概念上是相似的。

那么现在让我们转移到最后一个工具，Firebug 扩展程序。

# Firefox 和 Firebug 扩展程序

我个人认为 Firebug 扩展无需进一步介绍。它可能是市场上最受欢迎的 Firefox 调试工具之一（如果不是最流行的话）。Firebug 是免费和开源的。

它具有以下功能：

+   通过在网页上点击和指向来检查和编辑 HTML

+   调试和分析 JavaScript

+   快速发现 JavaScript 错误

+   记录 JavaScript

+   执行飞行的 JavaScript

Firebug 或许是互联网上最好的文档化调试工具之一。所以我们将查看你可以访问的 URL，以便利用这个免费、开源且强大的调试工具：

+   要安装 Firebug，请访问：[`getFirebug.com`](http://getFirebug.com)

+   要查看完整的常见问题解答列表，请访问：[`getFirebug.com/wiki/index.php/FAQ`](http://getFirebug.com/wiki/index.php/FAQ)

+   要查看完整的教程列表，请访问：[`getFirebug.com/wiki/index.php/Main_Page`](http://getFirebug.com/wiki/index.php/Main_Page)。如果你希望了解更多关于每个特定功能的信息，请在网页的左侧寻找**面板**。

# 总结

我们终于到了本章的结尾。我们已经介绍了可用于我们的调试任务的各个浏览器的特定工具。

具体来说，我们已经介绍了以下主题：

+   用于 Internet Explorer 的开发者工具

+   Google Chrome 和 Safari 的 JavaScript 调试器和 Web 检查器

+   Opera 的 Dragonfly

+   Firefox 的 Venkman 扩展

+   Firebug 资源

如果你需要更多关于每个特定工具的信息，你可以通过在本书中提到的工具和功能后添加关键词“教程”来使用 Google 搜索。

我们已经介绍了可以帮助你开始调试 JavaScript 应用程序的工具的最重要功能。在我们最后一章中，我们将重点介绍各种测试工具，这些工具可以在你的测试需求不能手动满足时使用。


# 第八章：测试工具

> 在最后一章中，我们将介绍一些高级工具，您可以使用它们来测试您的 JavaScript。我们将介绍一些可以帮助您进一步自动化测试和调试任务的工具，并向您展示如何测试您的用户界面。
> 
> 我理解您有很多选择，因为市面上有很多可供您选择用于测试任务的工具。但我会关注那些通常免费、跨浏览器和跨平台的工具；您是 Safari、IE、Chrome 或其他浏览器的粉丝并不重要。根据[`w3schools.com/browsers/browsers_stats.asp`](http://w3schools.com/browsers/browsers_stats.asp)，大约 30%的网页浏览器使用 Internet Explorer，46%使用 Firefox 浏览器，其余的使用 Chrome、Safari 或 Opera。这意味着您使用的工具将满足这些统计数据。尽管有些应用程序是为只有一个浏览器开发的，但我们学习如何为不同的浏览器编写代码是一个好的实践和学习经验。
> 
> 更重要的是，我将详细介绍的工具是我个人认为更容易上手的工具；这将帮助您对测试工具有一个大致的了解。

以下工具将详细介绍：

+   Sahi 是一个跨浏览器自动化测试工具。我们将用它来执行 UI 测试。

+   QUnit 是一个 JavaScript 测试套件，可以用来测试几乎任何 JavaScript 代码。我们将用它来执行 JavaScript 代码的自动化测试。

+   JSLitmus，一个用于创建即兴 JavaScript 基准测试的轻量级工具。我们将使用这个工具进行一些基准测试。

除了前面提到的工具，我还将介绍一些重要的测试工具，我认为这些工具对您的日常调试和测试任务很有用。所以，一定要查看这一部分。

# Sahi

我们简要讨论了测试由 JavaScript 库提供的用户界面小部件的问题。在本节中，我们将开始测试使用 JavaScript 库小部件构建的用户界面。同样的技术也可以用于测试自定义用户界面。

Sahi 是一个使用 Java 和 JavaScript 的浏览器无关的自动化测试工具。我们将关注这个工具，因为它与浏览器无关，我们不能总是忽视 IE 用户。

Sahi 可以用来执行各种测试任务，但我想要强调的一个功能是它能够记录测试过程并在浏览器中回放。

您将看到使用 Sahi 执行用户界面测试是多么有用。

# 行动时间—使用 Sahi 进行用户界面测试

我们将向您展示 Sahi 的记录和回放功能，并了解如何使用它来测试由 JavaScript 库（如 jQuery）提供的用户界面小部件。

1.  我们首先安装 Sahi。访问[`sahi.co.in`](http://sahi.co.in)并下载最新版本。在我写下这段文字的时候，最新版本是 V3 2010-04-30。下载后，解压到`C:`驱动器。

1.  打开 Internet Explorer（我在这篇教程中使用的是 IE8），然后访问[`jqueryui.com/themeroller/`](http://jqueryui.com/themeroller/)。我们将使用这个用户界面进行演示。

1.  为了使用 Sahi，我们需要首先导航到`C:\sahi_20100430\sahi\bin`并查找`sahi.bat`。点击它，这样我们就可以启动 Sahi。

1.  现在，是时候设置你的浏览器，以便它能与 Sahi 一起使用。打开你的浏览器，前往**工具** | **Internet 选项** | **连接**，然后点击**局域网设置**。点击**代理服务器**并输入以下屏幕截图中的信息:![行动时刻—使用 Sahi 进行用户界面测试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_08_01.jpg)

    完成操作后，关闭此窗口以及与工具相关的所有其他窗口。

1.  完成上一步后，让我们回到浏览器中。为了在浏览器中使用 Sahi，你需要按*Ctrl* + *Alt*，同时双击网页上的任何元素（[`jqueryui.com/themeroller/`](http://jqueryui.com/themeroller/)）。你应该看到一个新的窗口，如下下一个屏幕截图所示:![行动时刻—使用 Sahi 进行用户界面测试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_08_02.jpg)

1.  如果你看到了上面截图中的窗口，那么你已经正确设置了并启动了 Sahi。现在，让我们来了解它的自动化测试功能，记录和回放功能。

1.  在**脚本名称**输入字段中输入**jquery_testing**，然后在显示在前一个屏幕截图中的窗口中点击**记录**。这将开始记录过程。

1.  现在，让我们点击几个用户界面元素。在我的情况下，我点击了**第二部分，第三部分，打开对话框**和**字体设置**。这可以在左侧菜单找到。

1.  导航到`C:\sahi_20100430\sahi\userdata\scripts`，你会看到一个名为`jquery_testing.sah`的文件。用 WordPad 打开这个文件，你将看到我们刚刚创建的行动列表，记录在这个文件中。

1.  进入 Sahi 窗口，点击**停止**。现在，我们已经停止了记录过程。

1.  在 WordPad 中打开`jquery_testing.sah`，并更改代码，使其如下所示：

    ```js
    function jquery_testing() {
    _click(_link("Section 2"));
    _click(_link("Section 2"));
    _click(_link("Section 3"));
    _click(_link("Section 3"));
    _click(_link("Open Dialog"));
    _click(_link("Font Settings"));
    }
    jquery_testing();

    ```

    我定义了一个名为`jquery_testing()`的函数来包含我们创建的行动列表。然后，我把`jquery_testing()`添加到文件的末尾。这一行是为了在我们激活回放功能时调用这个函数。

1.  现在让我们进入 Sahi 窗口，点击**回放**。然后，输入如下下一个屏幕截图中的信息:![行动时刻—使用 Sahi 进行用户界面测试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_08_03.jpg)

    点击**设置**，等待页面刷新。

1.  页面刷新后，点击**播放**。在浏览器中，我们将看到我们执行的操作按照前面提到的步骤重复进行。您还将在 **声明** 面板中收到一个 **成功** 消息，这意味着我们的测试过程是成功的。

## 刚才发生了什么？

我们刚刚使用 Sahi 完成了一个简单的用户界面测试过程。Sahi 的回放过程和记录功能使我们能够轻松地测试用户界面。

请注意，Sahi 允许我们以视觉方式进行测试。与前面章节中看到的其他手动测试方法相比，除了为回放功能定义一个函数外，并没有太多编码工作。

现在，让我们关注与 Sahi 相关的其他重要且相关的话题。

## 使用 Sahi 进行更复杂的测试

如本节开头所述，Sahi 可以与任何浏览器一起使用，执行各种任务。它甚至可以用来进行断言测试。

查看[`sahi.co.in/static/sahi_tutorial.html`](http://sahi.co.in/static/sahi_tutorial.html)，了解如何在您的测试过程中使用断言。

### 注意

在本节结束后，请确保您回到**工具** | **Internet 选项** | **连接**，点击 LAN 设置，取消勾选**代理服务器**，以便您的浏览器可以像往常一样工作。

# QUnit

QUnit 是一个 jQuery 测试套件，但它可以用来测试我们编写的 JavaScript 代码。这意味着代码不必依赖于 jQuery。通常，QUnit 可以用来进行断言测试和异步测试。此外，断言测试有助于预测您代码的返回结果。如果预测失败，那么您的代码中很可能会出错。异步测试简单地指的是同时测试 Ajax 调用或函数。

让我们立即行动来看看它是如何工作的。

# 是时候进行行动测试 JavaScript with QUnit

在本节中，我们将更深入地了解 QUnit，通过编写一些代码，也学习 QUnit 支持的各种测试。我们将编写正确的测试和错误的测试，以了解它是如何工作的。本节的源代码可以在 `source code` 文件夹的 `qunit` 中找到。

1.  打开您的编辑器，将文件保存为 `example.html`。在其中输入以下代码：

    ```js
    <!DOCTYPE html>
    <html>
    <head>
    <title>QUnit Example</title>
    <link rel="stylesheet" href="http://github.com/jquery/qunit/raw/master/qunit/qunit.css" type="text/css" media="screen">
    <script type="text/javascript" src="img/qunit.js"></script> 
    <script type="text/javascript" src="img/codeToBeTested.js"></script>
    <script type="text/javascript" src="img/testCases.js"></script>
    </head>
    <body>
    <h1 id="qunit-header">QUnit Test Results</h1>
    <h2 id="qunit-banner"></h2>
    <div id="qunit-testrunner-toolbar"></div>
    <h2 id="qunit-userAgent"></h2>
    <ol id="qunit-tests"></ol>
    </body>
    </html>

    ```

    之前的代码所做的就是简单地为测试设置代码。注意突出显示的行。前两行 simply point to the hosted version of the QUnit testing suite (both CSS and JavaScript)，最后两行是您的 JavaScript 代码和测试用例所在的地方。

    `codeToBeTested.js` 只是指您编写的 JavaScript 代码，而 `testCases.js` 是您编写测试用例的地方。在接下来的步骤中，您将看到这两个 JavaScript 文件是如何一起工作的。

1.  我们将从在`codeToBeTested.js`中编写代码开始。创建一个 JavaScript 文件，并将其命名为`codeToBeTested.js`。首先，我们将编写一个简单的函数，用于测试输入的数字是否是奇数。带着这个想法，输入以下代码：

    ```js
    codeToBeTest.js:
    function isOdd(value){
    return value % 2 != 0;
    }

    ```

    `isOdd()`接收一个参数值，并检查它是否是奇数。如果是，这个函数将返回 1。

    现在让我们为我们的测试用例编写一段代码。

1.  创建一个新的 JavaScript 文件，并将其命名为`testCases.js`。现在，将其输入以下代码：

    ```js
    test('isOdd()', function() {
    ok(isOdd(1), 'One is an odd number');
    ok(isOdd(7), 'Seven is an odd number');
    ok(isOdd(-7), 'Negative seven is an odd number');
    })

    ```

    注意我们使用 QUnit 提供的方法编写测试用例的方式。首先，我们定义一个函数调用`test()`，它构建了测试用例。因为我们要测试`isOdd()`函数，所以第一个参数是一个将在结果中显示的字符串。第二个参数是一个包含我们断言的回调函数。

    我们使用断言语句，通过使用`ok()`函数。这是一个布尔断言，它期望它的第一个参数为真。如果是真，测试通过，如果不是，测试失败。

1.  现在保存所有你的文件，并在你喜欢的任何浏览器中运行`example.html`。根据你的机器，你会收到一个类似于以下示例的屏幕截图：![Time for action testing JavaScript with QUnitQunitworking](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_08_04.jpg)

    通过点击`isOdd()`，你可以查看测试的详细信息，并将看到它的结果。输出如前一个屏幕截图所示。

    现在让我们模拟一些失败的测试。

1.  回到`testCases.js`，在`test()`的最后一行添加以下代码：

    ```js
    // tests that fail
    ok(isOdd(2), 'So is two');
    ok(isOdd(-4), 'So is negative four');
    ok(isOdd(0), 'Zero is an even number');

    ```

    保存文件并刷新你的浏览器。你现在将在浏览器中看到一个类似于以下示例的屏幕截图：

    ![Time for action testing JavaScript with QUnitQunitworking](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_08_05.jpg)

现在你可以看到测试**4, 5**和**6**失败了，它们是红色的。

在这个时候，你应该看到 QUnit 的好处在于，它很大程度上自动化了我们的测试过程，我们不需要通过点击按钮、提交表单或使用`alert()`来进行测试。使用这样的自动化测试无疑可以节省我们大量的时间和精力。

## 刚才发生了什么？

我们刚刚使用了 QUnit 对自定义的 JavaScript 函数进行了自动化测试。这是一个简单的例子，但足以让你入门。

## 在现实生活中的 QUnit 应用

你可能想知道如何在现实生活中的情况下使用这些测试来测试你的代码。我会说，你很可能会用`ok()`来测试你的代码。例如，你可以测试真值，如果用户输入是字母数字，或者用户输入了无效值。

## 各种情况的断言测试更多

另一个你可以注意的事情是`ok()`并不是唯一你可以执行的断言测试。你还可以执行其他测试，比如比较断言和相同断言。让我们看一个关于比较的短例子。

在本节中，我们将学习使用另一个断言语句，`equals()`。

1.  打开你的编辑器，打开`testCases.js`。注释掉你之前写的代码，并在文件中输入以下代码：

    ```js
    test('assertions', function(){
    equals(5,5, 'five equals to five');
    equals(3,5, 'three is not equals to five');
    })

    ```

    这段代码与您注释掉的代码具有相同的结构。但是请注意，我们使用的是`equals()`函数而不是`ok()`。`equals()`函数的参数如下：

    +   第一个参数是实际值

    +   第二个参数是期望的值

    +   第三个参数是自定义消息

    我们使用了两个`equals()`函数，其中第一个测试将通过，但第二个不会，因为三和五不相等。

1.  保存文件并打开`example.html`在浏览器中。你会看到以下截图：![各种情况的更多断言测试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_08_06.jpg)

# JSLitmus

根据 JSLitmus 主页的介绍，JSLitmus 是一个用于创建临时 JavaScript 基准测试的轻量级工具。在我看来，这绝对是正确的。使用 JSLitmus 非常简单，尤其是当它支持所有流行浏览器，如 Internet Explorer、Firefox、Google Chrome、Safari 等时。同时，它完全免费，包含我们在这里提到的产品。

在本节中，我们将快速举一个例子，展示如何创建临时 JavaScript 基准测试。

# 行动时刻—创建临时 JavaScript 基准测试

现在我们将看到使用 JSLitmus 创建临时 JavaScript 基准测试是多么简单。但首先，让我们安装 JSLitmus。顺便说一下，本节的所有源代码可以在本章的`source code`文件夹中找到，在`jslitmus`文件夹下。

1.  访问[`www.broofa.com/Tools/JSLitmus/`](http://www.broofa.com/Tools/JSLitmus/) 并下载`JSlitmus.js`。

1.  打开你的编辑器，在`JSLitmus.js`相同的目录下创建一个名为`jslitmus_test.html`的新 HTML 文件。

1.  将以下代码输入`jslitmus_test.html:`

    ```js
    <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
    "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
    <html  xml:lang="en" lang="en">
    <head>
    <meta http-equiv="Content-Type"
    content="text/html;charset=utf-8" />
    <title>JsLitmus Testing Example</title>
    <script type="text/javascript" src="img/JSLitmus.js"></script>
    <script type="text/javascript">
    function testingLoop(){
    var i = 0;
    while(i<100)
    ++i;
    return 0;
    }
    JSLitmus.test('testing testingLoop()',testingLoop);
    </script>
    </head>
    <body>
    <p>Doing a simple test using JsLitmus.</p>
    <div id="test_element" style="overflow:hidden; width: 1px;
    height:1px;"></div>
    </body>
    </html>

    ```

    实际上，我这段代码是从 JSLitmus 官网提供的官方示例中摘取的。我会以稍微不同于官方示例的方式进行测试，但无论如何，它仍然展示了我们如何使用 JSLitmus 的语法。

    上面的代码片段包含了用户定义的函数`testingLoop()`，而`JSLItmus.test('testing testingLoop()', testingLoop);`是用 JSlitmus 的语法测试`testingLoop()`的 JavaScript 代码行。

    让我解释一下语法。通常，我们是这样使用 JSLitmus 的：

    ```js
    JSlitmus.test('some string in here', nameOfFunctionTested);

    ```

    第一个参数是你可以输入的字符串，第二个参数是你打算测试的函数的名称。只需确保这段代码位于你的函数定义之后的地方。

1.  现在我们已经设置了我们的测试，是时候运行它，看看结果如何。保存`jslitmus_test.html`并在浏览器中打开这个文件。你应该在浏览器中看到以下内容：![创建临时 JavaScript 基准测试的行动时刻](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_08_07.jpg)

    注意在测试列下，它显示了我们作为`JSLItmus.test()`的第一个参数输入的文本。

1.  点击**运行测试**按钮。你应该在浏览器中收到以下结果：![行动时刻—创建即兴 JavaScript 基准测试](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_08_08.jpg)

+   它基本上显示了执行代码所需的时间和其他相关信息。你甚至可以通过访问动态生成的 URL 来查看图表形式的性能。如果你收到了与之前截图类似的的东西，那么你已经完成了一个即兴基准测试。

### 注意

如果你在 Internet Explorer 上运行此测试，并且恰好收到以下（或类似）信息：“**脚本执行时间过长**”，那么你需要调整你的 Windows 注册表，以便允许测试运行。访问[`support.microsoft.com/default.aspx?scid=kb;en-us;175500`](http://support.microsoft.com/default.aspx?scid=kb;en-us;175500)以了解如何调整你的 Windows 注册表设置。

## 刚才发生了什么？

我们刚刚使用 JSLitmus 创建了一个即兴基准测试。注意使用 JSLitmus 执行即兴基准测试是多么简单。JSLitmus 的酷之处在于它的简单性；没有其他工具，没有需要打开的窗口等等。你所需要做的就是编写`JSLItmus.test()`并输入你想测试的函数的信息和名称。

## 使用 JSLitmus 进行更复杂的测试

上面的例子是一个非常简单的例子，帮助你入门。如果你对执行更复杂的测试感兴趣，可以随意查看[`www.broofa.com/Tools/JSLitmus/demo_test.html`](http://www.broofa.com/Tools/JSLitmus/demo_test.html)并查看其源代码。你将看到使用 JSLitmus 的不同风格的测试，在其带有注释的源代码中。

现在我们已经介绍了与浏览器无关的工具，是时候快速介绍其他类似的测试工具，这些工具可以帮助你调试 JavaScript。

# 你应该查看的其他测试工具

现在我们即将结束这一章节，我会留给你一个简单的测试工具列表，你可以查看用于测试目的：

+   塞利姆（Selenium）：**Selenium**是一个自动化测试工具，只能记录在 Firefox 上，并且在其他浏览器中回放时可能会超时。还有其他版本的 Selenium 可以帮助你在多个浏览器和平台上进行测试。Selenium 使用 Java 和 Ruby。获取更多信息，请访问[`seleniumhq.org`](http://seleniumhq.org)。要查看一个简单的介绍，请访问[`seleniumhq.org/movies/intro.mov`](http://seleniumhq.org/movies/intro.mov)。

+   Selenium Server：也称为 Selenium 远程控制，**Selenium Server**是一个允许你用任何编程语言编写自动化 Web 应用程序 UI 测试的工具，针对任何 HTTP 网站，使用任何主流的 JavaScript 支持浏览器。你可以访问[`seleniumhq.org/projects/remote-control/`](http://seleniumhq.org/projects/remote-control/)。

+   Watir：**Watir**是一个作为 Ruby 宝石的自动化测试工具。Watir 有详细的文档，可以在[`wiki.openqa.org/display/WTR/Project+Home`](http://wiki.openqa.org/display/WTR/Project+Home)找到。

+   **断言单元框架**：**断言单元框架**是一个基于断言的单元测试框架。截至编写本文时，文档似乎有限。但是你可以通过访问[`jsassertunit.sourceforge.net/docs/tutorial.html`](http://jsassertunit.sourceforge.net/docs/tutorial.html)来学习如何使用它。你可以访问[`jsassertunit.sourceforge.net/docs/index.html`](http://jsassertunit.sourceforge.net/docs/index.html)获取其他相关信息。

+   **JsUnit**是一个从最流行的 Java 单元测试框架 JUnit 移植过来的单元测试框架。JsUnit 包括一个平台，用于在不同的浏览器和不同的操作系统上自动执行测试。你可以在[`www.jsunit.net/`](http://www.jsunit.net/)获得 JsUnit。

+   FireUnit：**FireUnit**是一个设计在 Firebug 中运行的 Firefox 单元测试框架。它也是 Firefox 的一个流行调试工具，网上有大量的关于它的教程和文档。你可以在[`fireunit.org/`](http://fireunit.org/)获得 FireUnit。

+   JSpec：**JSpec**是一个使用自定义语法和预处理器的 JavaScript 测试框架。它还可以以多种方式使用，例如通过终端，通过浏览器使用 DOM 或控制台格式化器，等等。你可以在[`visionmedia.github.com/jspec/`](http://visionmedia.github.com/jspec/)获得 JSpec。

+   TestSwarm：**TestSwarm**为 JavaScript 提供分布式、持续集成测试。它最初是由 John Resig 为支持 jQuery 项目而开发的，现在已成为官方 Mozilla 实验室项目。请注意，它仍然处于严格测试中。你可以在[`testswarm.com/`](http://testswarm.com/)获得更多信息。

# 总结

我们已经终于完成了这一章的结尾。我们覆盖了可用于我们调试任务的各个浏览器的特定工具。

具体来说，我们涵盖了以下主题：

+   Sahi：一个使用 Java 和 JavaScript 的浏览器无关的自动化测试工具

+   QUnit：一个可以用来测试 JavaScript 代码的 jQuery 测试套件

+   JsLitmus：创建即兴 JavaScript 基准测试的轻量级工具

+   你可以查看的工具列表

最后，我们终于来到了本书的结尾。我希望你从这本书中学到了很多关于 JavaScript 测试的知识。我想感谢你花费时间和精力阅读这本书，同时也想感谢 Packt 出版社的支持。
