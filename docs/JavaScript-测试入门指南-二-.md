# JavaScript 测试入门指南（二）

> 原文：[`zh.annas-archive.org/md5/BA61B4541373C00E412BDA63B9F692F1`](https://zh.annas-archive.org/md5/BA61B4541373C00E412BDA63B9F692F1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：语法验证

> 为了巩固我们之前学到的知识，我们现在将转向一个稍微困难的话题——验证 JavaScript。在本章中，你可以期待两个主要话题——围绕 JavaScript 代码验证和测试的问题，以及如何使用 JSLint 和 JavaScript Lint（这是一个免费的 JavaScript 验证器）来检查你的 JavaScript 代码，以及如何调试它们。我会明确地展示如何使用 JSLint 发现验证错误，然后，如何修复它们。
> 
> 我们将简要介绍验证和测试 JavaScript 之间的区别以及你在验证或测试代码时可能需要考虑的一些问题。你还将了解有效的 HTML 和 CSS 与 JavaScript 之间的关系，以及如何尝试编写高质量的代码以帮助你减少 JavaScript 代码中的错误。更重要的是，我们将学习到两个常用于验证 JavaScript 代码的免费工具，如何利用它们检查你的代码，以及最重要的是，如何修复检测到的验证错误。

在本章中，我们将学习以下主题：

+   验证和测试之间的区别

+   一个好的代码编辑器如何帮助你发现验证错误

+   什么使代码质量高

+   为什么在开始操作 JavaScript 之前需要确保 HTML 和 CSS 是有效的

+   为什么嵌入在 HTML 中的 JavaScript 可能会被报告为无效

+   通过验证检测到的常见 JavaScript 错误

+   JSLint 和 JavaScript Lint——如何使用它们检查你的代码

+   产生验证警告的有效代码结构

+   如何修复由 JSLint 发现的验证错误

那么，不再赘述，让我们开始讨论一个较轻松的话题——验证和测试之间的区别。

# 验证和测试之间的区别

有效验证和测试之间有一条细微的界限。如果你对集合（如数学中的集合）有一些了解，我会说验证可以导致更好的测试结果，而测试不一定导致有效代码。

让我们考虑这样一个场景——你编写了一个 JavaScript 程序，并在 Internet Explorer 和 Firefox 等主要浏览器上进行了测试，并且它运行正常。在这种情况下，你已经测试了代码，以确保它是功能性的。

然而，你所创建的同一代码可能有效也可能无效；有效代码类似于具有以下特点的代码：

+   格式良好

+   具有良好的编码风格（如适当的缩进、注释良好的代码、适当的间距）

+   符合语言规范（在我们这个案例中，是 JavaScript）

### 注意

在某个时间点，你可能会注意到良好的编码风格是非常主观的——有各种验证器可能对所谓的“良好编码风格”有不同的意见或标准。因此，如果你用不同的验证器来验证你的代码，当你看到不同的编码风格建议时，不要惊慌。

这并不意味着有效的代码会导致具有功能的代码（如你所见）以及具有功能的代码会导致有效的代码，因为两者有不同的比较标准。

然而，有效的代码通常会导致更少的错误，既有功能又是有效的代码通常是高质量代码。这是因为编写一段既有效又正确的 JavaScript 代码，比仅仅编写正确的代码要困难得多。

测试通常意味着我们试图让代码正确运行；而验证则是确保代码在语法上是正确的，有良好的风格，并且符合语言规范。虽然良好的编码风格可能是主观的，但通常有一种被大多数程序员接受的编码风格，例如，确保代码有适当的注释、缩进，并且没有全局命名空间的污染（尤其是在 JavaScript 的情况下）。

为了使情况更清晰，以下是三个你可以考虑的情况：

## 代码是有效的但却是错误的——验证并不能找到所有的错误。

这种错误形式很可能是由 JavaScript 中的逻辑错误引起的。考虑我们之前学到的内容；逻辑错误可能在语法上是正确的，但可能在逻辑上是错误的。

一个典型的例子可能是一个无限`for`循环或无限`while`循环。

## 代码是无效的但却是正确的

这很可能是大多数功能性代码的情况；一段 JavaScript 可能是功能上正确并且运行正常，但它可能是无效的。这可能是由于编码风格不良或有效代码中缺失的其他特征引起的。

在本章后面，你将看到一个完整的、有效的 JavaScript 代码示例。

## 无效且错误的代码——验证可以找到一些可能用其他方法难以发现的错误

在这种情况下，代码错误可能由第一章中提到的 JavaScript 错误的三个形式引起，*什么是 JavaScript 测试*，加载错误，运行时错误和逻辑错误。虽然由语法错误引起的错误可能更容易被好的验证器发现，但也有可能一些错误深深地隐藏在代码中，以至于使用手动方法很难发现它们。

既然我们已经对验证和测试有了共同的理解，那么让我们继续下一部分，讨论围绕高质量代码的问题。

# 代码质量

虽然关于高质量代码有很多观点，我个人认为有一些公认的标准。一些最常提到的标准可能包括代码的可读性，易于扩展，效率，良好的编码风格，以及符合语言规范等。

在这里，我们将关注使代码有效的一些因素——编码风格和符合规范。一般来说，良好的编码风格几乎可以保证代码高度可读（甚至对第三方也是如此），这将有助于我们手动发现错误。

最重要的是，良好的编码风格使我们能够快速理解代码，特别是如果我们需要团队合作或需要独立进行代码调试时。

你会注意到，我们将重点关注代码有效性对于测试目的的重要性。但现在，让我们从质量代码的第一个构建块开始——有效的 HTML 和 CSS。

## 在开始 JavaScript 之前，HTML 和 CSS 需要是有效的

在第一章中，我们有一个共同的理解，JavaScript 通过操作 HTML 文档的文档对象模型**（DOM）**为网页注入生命力。这意味着在 JavaScript 可以操作 DOM 之前，DOM 必须存在于代码中。

### 注意

这里有一个与 HTML、CSS 和浏览器直接相关的重要事实，相比 C 或 Python 等语言的编译器，浏览器对无效的 HTML 和 CSS 代码更加宽容。这是因为，所有浏览器需要做的就是解析 HTML 和 CSS，以便为用户渲染网页。另一方面，编译器通常对无效代码毫不留情。任何缺失的标签、声明等都会导致编译错误。因此，编写无效的或甚至是含有错误的 HTML 和 CSS 是可以的，但仍能得到一个“通常”外观的网页。

根据之前的解释，我们应该明白，为了创建高质量的 JavaScript 代码，我们需要有效的 HTML 和 CSS。

以下是我根据个人经验总结的，在开始学习 JavaScript 之前，为什么需要具备有效的 HTML 和 CSS 知识的原因：

+   有效的 HTML 和 CSS 有助于确保 JavaScript 按预期工作。例如，考虑这样一种情况，你可能有两个具有相同`id`的`div`元素（在之前的章节中，我们已经提到`div id`属性是给每个 HTML 元素提供唯一 ID 的），而你的 JavaScript 包含了一段预期对具有上面提到的 ID 的 HTML 元素工作的代码。这将导致意想不到的结果。

+   有效的 HTML 和 CSS 有助于提高你的网页行为的可预测性；试图用 JavaScript 修复错误的 HTML 或 CSS 是没有意义的。如果你从一开始就使用有效的 HTML 和 CSS，然后应用 JavaScript，你很可能会得到更好的结果。

+   无效的 HTML 和 CSS 可能会导致不同浏览器中出现不同的行为。例如，一个未闭合的 HTML 标签在不同浏览器中可能会有不同的显示效果。

总之，创建高质量 JavaScript 代码最重要的构建块之一是拥有有效的 HTML 和 CSS。

### 如果你不验证你的代码会发生什么

你可能会不同意我上文关于为什么 HTML 和 CSS 应该有效的观点。一般来说，验证有助于你防止与编码风格和规格相关的错误。然而，请注意，使用不同的验证器可能会给你不同的结果，因为验证器可能在代码风格方面有不同的标准。

如果你在想无效的代码是否会影响你的 JavaScript 代码，我会建议你尽可能让代码有效；无效的代码可能会导致棘手的问题，比如跨浏览器不兼容、代码难以阅读等。

无效代码意味着你的代码可能不是万无一失的；在互联网的早期，有些网站依赖于早期 Netscape 浏览器的怪癖。回想一下，当 Internet Explorer 6 被广泛使用时，也有许多网站以怪癖模式工作以支持 Internet Explorer 6。

现在，大多数浏览器都支持或正在支持网络标准（尽管有些细微的差异，但它们以微妙的方式支持），编写有效的代码是确保你的网站按预期工作和工作表现的最佳方式之一。

#### 如何通过验证简化测试

虽然无效的代码可能不会导致你的代码功能失效，但有效的代码通常可以简化测试。这是因为有效代码关注编码风格和规格，符合规格的有效代码通常更可能正确，且更容易调试。考虑以下风格上无效的代码：

```js
function checkForm(formObj){
alert(formObj.id)
//alert(formObj.text.value);
var totalFormNumber = document.forms.length;
// check if form elements are empty and are digits
var maxCounter = formObj.length; // this is for checking for empty values
alert(totalFormNumber);
// check if the form is properly filled in order to proceed
if(checkInput(formObj)== false){
alert("Fields cannot be empty and it must be digits!");
// stop executing the code since the input is invalid
return false;
}
else{
;
}
var i = 0;
var formID;
while(i < totalFormNumber){
if(formObj == document.forms[i]){
formID = i;alert(i);
}
i++;
}
if(formID<4){
formID++;
var formToBeChanged = document.forms[formID].id;
// alert(formToBeChanged);
showForm(formToBeChanged);
}
else{
// this else statement deals with the last form
// and we need to manipulate other HTML elements
document.getElementById("formResponse").style.visibility = "visible";
}
return false;
}

```

你熟悉之前的代码吗？还是没有意识到之前的代码片段来自第二章，《JavaScript 中的即兴测试与调试》？

之前的代码是代码风格不佳的一个极端例子，尤其是在缩进方面。想象一下，如果你必须手动调试你之前看到的第二个代码片段！我敢肯定，你会觉得检查代码很沮丧，因为你几乎无法从视觉上了解发生了什么。

更重要的是，如果你在团队中工作，你将被要求编写可读的代码；总之，编写有效的代码通常会导致代码更具可读性，更容易理解，因此错误更少。

#### 验证可以帮助你调试代码

如上文所述，浏览器通常对无效的 HTML 和 CSS 比较宽容。虽然这是真的，但可能会有一些错误没有被捕捉到，或者没有正确或优雅地渲染。这意味着虽然无效的 HTML 和 CSS 代码在某个平台或浏览器上可能看起来没问题，但在其他平台上可能不受支持。

这意味着使用有效的代码（有效的代码通常意味着由国际组织如 W3C 设定的标准代码集）将使你的网页在不同的浏览器和平台上正确渲染的概率大大增加。

有了有效的 HTML 和 CSS，您可以安全地编写您的 JavaScript 代码并期望它按预期工作，前提是您的 JavaScript 代码同样有效且无错误。

#### 验证帮助您使用好的编程实践

有效的代码通常需要使用好的编程实践。正如本章中多次提到的，好的实践包括适当闭合标签，合适的缩进以提高代码可读性等。

如果您需要更多关于使用 JavaScript 的良好实践的信息，请随时查看 JSLint 的创建者，Douglas Crockford，在 [`crockford.com`](http://crockford.com)。或者您可以阅读 John Resigs 的博客（JQuery 的创建者）在 [`ejohn.org/`](http://ejohn.org/)。他们都是很棒的人，知道什么是伟大的 JavaScript。

#### 验证

总结以上各节，DOM 由 HTML 提供，CSS 和 JavaScript 都应用于 DOM。这意味着如果存在无效的 DOM，那么操作 DOM 的 JavaScript（有时包括 CSS）可能会导致错误。

带着这个总结在心中，我们将重点关注如何使用颜色编码编辑器来发现验证错误。

## 颜色编码编辑器—您的编辑器如何帮助您发现验证错误

如果您是一个有经验的程序员，您可以跳过这一节；如果不是，您可能想了解一个好的编程编辑器的价值。

总的来说，一个好的编辑器可以帮助您防止验证错误。基于我们对验证的理解，您应该明白，您的编辑器应该执行以下活动：

+   突出显示匹配的括号

+   多种语法高亮

+   关键字、括号等之后的自动缩进

+   自动补全语法

+   自动补全您已经输入的单词

您可能注意到了，我遗漏了一些要点，或者增加了一些要点，关于好的编辑器应该做什么。但总的来说，前面列出的要点是为了帮助您防止验证错误。

### 注意

作为一个开始，您可以考虑使用微软的 SharePoint Designer 2007，这是一个免费、功能丰富的 HTML、CSS 和 JavaScript 编辑器，可在 [`www.microsoft.com/downloads/details.aspx?displaylang=en&FamilyID=baa3ad86-bfc1-4bd4-9812-d9e710d44f42`](http://www.microsoft.com/downloads/details.aspx?displaylang=en&FamilyID=baa3ad86-bfc1-4bd4-9812-d9e710d44f42)获得

例如，突出显示匹配的括号是为了确保您的代码用括号正确闭合，自动缩进是为了确保您为代码块使用了统一的空格。

尽管 JavaScript 代码块通常用花括号表示，但使用缩进来 visually 显示代码结构非常重要。考虑以下代码片段：

```js
function submitValues(elementObj){
var digits = /^\d+$/.test(elementObj.value);
var characters = /^[a-zA-Z\s]*$/.test(elementObj.value);
if(elementObj.value==""){
alert("input is empty");
return false;
}
else if(elementObj.name == "enterNumber" && digits == false){
alert("the input must be a digit!");
debuggingMessages(arguments.callee.name, elementObj, "INPUT must be digit");
return false;
}
else if(elementObj.name == "enterText" && characters == false){
alert("the input must be characters only!");
return false;
}
else{
elementObj.disabled = true;
return true;
}
}

```

下一个代码片段如下：

```js
function submitValues(elementObj)
{
var digits = /^\d+$/.test(elementObj.value);
var characters = /^[a-zA-Z\s]*$/.test(elementObj.value);
if(elementObj.value=="")
{alert("input is empty");
return false;
}
else if(elementObj.name == "enterNumber" && digits == false)
{alert("the input must be a digit!");
return false;
}else if(elementObj.name == "enterText" && characters == false)
{alert("the input must be characters only!");
return false;
}
else
{
elementObj.disabled = true;
return true;
}
}

```

我非常确信，您会认为第二个代码片段很乱，因为它的缩进不一致，您可能会遇到分辨哪个语句属于哪个条件块的问题。

从风格上讲，第二个代码示例就是我们所说的“糟糕的代码风格”。您可能会惊讶这可能会导致验证错误。

### 注意

如果您想知道`/^[a-zA-Z\s]*$/`和`/^\d+$/`是什么，它们实际上是正则表达式对象。正则表达式起源于 Perl（一种编程语言），由于它们的实用性，许多编程语言现在都有自己的正则表达式形式。大多数它们的工作方式相同。如果您想了解更多关于 JavaScript 正则表达式的信息，请随时访问[`www.w3schools.com/jsref/jsref_obj_regexp.asp`](http://www.w3schools.com/jsref/jsref_obj_regexp.asp)以了解正则表达式是如何工作的简要介绍。

# JavaScript 中常见的错误，将由验证工具检测到

我会简要提到一些由验证器检测到的最常见的验证错误。以下是它们的简短列表：

+   不一致的空格或缩进

+   缺少分号

+   缺少闭合括号

+   使用在调用或引用时未声明的函数或变量

### 注意

您可能已经注意到，一些验证错误并不是 exactly "错误"——就像语法错误——而是风格上的错误。如前所述，编码风格上的差异不一定导致功能错误，而是导致风格错误。但良好的编码风格的一个好处是，它通常会导致更少的错误。

至此，您可能很难想象这些常见错误实际上看起来是什么样子。但不要担心，当我们引入 JavaScript 验证工具时，您将能看到这些验证错误的实际操作。

# JSLint—在线验证器

JSLint 是我们将重点介绍的第一种 JavaScript 验证代码。通过访问这个 URL：[`www.jslint.com`](http://www.jslint.com)，您可以访问 JSLint。JSLint 在线验证器是由道格拉斯·克罗克福德创建的工具。

### 注意

道格拉斯·克罗克福德（Douglas Crockford）在雅虎！担任 JavaScript 架构师。他还是设计 JavaScript 未来版本的委员会成员。他在 JavaScript 风格和编程实践方面的观点普遍受到认可。您可以在他的网站上了解更多关于他和他的想法：[`www.crockford.com`](http://www.crockford.com)。

总的来说，JSLint 是一个在线 JavaScript 验证器。它帮助验证您的代码。同时，JSLint 足够智能，可以检测到一些代码错误，比如无限循环。JSLint 网站并不是一个特别大的网站，但无论如何，您必须阅读的两个重要链接如下：

+   基本操作说明，请访问[`www.jslint.com/lint.html`](http://www.jslint.com/lint.html)

+   要查看消息列表，请访问[`www.jslint.com/msgs.html`](http://www.jslint.com/msgs.html)

我不会试图向你描述 JSLint 是关于什么以及如何使用它；我个人认为应该亲自动手试试。因此，首先，我们将测试我们在第二章中编写的代码，*Ad Hoc Testing and Debugging in JavaScript*，看看会出现哪些验证错误（如果有的话）。

# 是行动的时候了——使用 JSLint 查找验证错误

正如前面提到的，我们将测试我们在第二章中编写的代码，*Ad Hoc Testing and Debugging in JavaScript*，看看我们会得到哪些验证错误。请注意，这个示例的完整验证代码可以在`source code`文件夹的`第三章`中找到，文件名为`perfect-code-for-JSLint.html`。

1.  打开你的网页浏览器，导航至[`www.jslint.com`](http://www.jslint.com)。你应该会看到一个带有巨大文本区域的首页。这就是你将要复制和粘贴你的代码的地方。

1.  请前往`第二章`的`source code`文件夹，打开名为：`getting-values-in-right-places-complete.html`的文件。然后，将源代码复制并粘贴到步骤 1 中提到的文本区域。

1.  现在点击名为**JSLint**的按钮。

    你的页面应该会立即刷新，并且你会收到一些形式的反馈。你可能会注意到你收到了很多（是的，很多）验证错误。而且，很可能会有一些对你来说是不懂的。然而，你应该能够识别出一些验证错误是在关于常见 JavaScript 验证错误的章节中引入的。

    现在，向下滚动，你应该在反馈区域看到以下短语：

    ```js
    xx % scanned
    too many errors

    ```

    这告诉你 JSLint 只是扫描了代码的一部分，并停止了扫描代码，因为错误太多了。

    我们能对此做些什么呢？如果验证错误太多，你一次无法找出所有的错误怎么办？

    不要担心，因为 JSLint 是健壮的，并且有选项设置，这些设置可以在[`www.jslint.com/#JSLINT_OPTIONS`](http://www.jslint.com/#JSLINT_OPTIONS)找到（这实际上位于 JSLint 主页的底部）。需要你输入的一个选项是**最大错误数**。在我们的例子中，你可能想输入一个巨大的数字，比如 1,000,000。

1.  输入一个巨大的数字作为**最大错误数**的输入框后，点击**The good parts**按钮。你会看到有几个复选框被选中了。

    在步骤 4 之后，你现在正式选择了被称为“The Good Parts”的选项，这是由本工具的作者设定的。这是一个设置，它会自动设置作者认为最重要的验证检查。

    这些选项包括：严格空格，每个函数允许一个 var 声明等等。

1.  现在点击**JSLint**按钮。你的浏览器将显示新的验证结果。现在你可以看看 JSLint 检测到的验证错误类型。

## 刚才发生了什么？

你刚才使用了 JSLint 来查找验证错误。这是 JSLint 的一个简单过程：将你的代码复制粘贴到文本区域，然后点击**JSLint**。不要对出现的这么多验证错误感到惊讶；我们才刚刚开始，我们将学习如何修复和避免这些验证错误。

### 注意

你可能注意到了，嵌入在 HTML 表单中的 JavaScript 导致了一个错误，提示**缺少 use strict 语句**。这个错误源于 JSLint 相信使用**use strict**语句，这使得代码能够在严格条件下运行。你将在本章的后部分学习如何修复和避免这类问题。

你将继续看到许多错误。在我看来，这是验证代码不容易实现的一个证据；但这是我们将在下一节实现的内容。

正如你所看到的，有各种各样的验证选项，在这个阶段，我们只要能让代码通过**好部分**的设定要求就足够了。因此，我们接下来将重点放在如何修复这些验证错误上。但在那之前，我会简要讨论产生验证警告的有效代码结构。

# 产生验证警告的有效代码结构

你可能注意到了，尽管我们的代码结构是有效的，但它产生了验证警告。你可能在想是否应该修复这些问题。以下是一些基本讨论，帮助你做出决定。

## 你应该修复产生验证警告的有效代码结构吗？

这取决于你的目标。如我在第一章中提到的，《什么是 JavaScript 测试？》，代码至少应该是正确的，按我们的意图工作。因此，如果你的目标是仅创建功能上正确的代码，那么你可能不想花时间和精力来修复这些验证警告。

然而，因为你正在阅读这本书，你很可能会想知道如何测试 JavaScript，正如你在本章后面将看到的，验证是测试 JavaScript 的重要部分。

## 如果你不修复它们会发生什么

无效代码的主要问题是，它将使代码的维护变得更为困难，在可读性和可扩展性方面。当团队合作时，这个问题会变得更严重，因为其他人必须阅读或维护你的代码。

有效的代码促进了良好的编程实践，这将帮助你避免将来出现的问题。

# 如何修复验证错误

本节将继续讨论上一节中提到的错误，并尝试一起修复它们。在可能的情况下，我会解释为什么某段代码会被认为是无效的。同时，编写有效且功能性的代码整个过程可能会很繁琐。因此，我会先从更容易修复的校验错误开始，然后再逐步转向更难的错误。

### 注意

在我们修复上一节中看到的校验错误的过程中，你可能会意识到修复校验错误可能需要在编写代码的方式上做出一些妥协。例如，你会了解到在代码中谨慎使用`alert()`并不是一种好的编程风格，至少根据 JSLint 的说法是这样的。在这种情况下，你必须将所有的`alert()`声明合并到一个函数中，同时仍保持代码的功能性。更重要的是，你也会意识到（或许）编写有效代码的最佳方式是从代码的第一行开始就编写有效的代码；你会看到修复无效代码是一个极其繁琐的过程，有时你只能尽量减少校验错误。

在修复代码的过程中，你将有机会练习重要的 JavaScript 函数，并学习如何编写更好的代码风格。因此，这可能是本章最重要的部分，我鼓励你和我一起动手实践。在开始修复代码之前，我首先总结一下 JSLint 发现的错误类型。

+   缺少“use `strict`”声明。

+   意外使用了`++`。

+   在`), value, ==, if, else, +`后面缺少空格。

+   函数名（如 debuggingMessages）未定义或在使用定义之前就使用了函数。

+   `var`声明过多。

+   使用了`===`而不是`==`。

+   `alert`未定义。

+   使用了`<\/`而不是`</`。

+   使用了 HTML 事件处理程序。

不再多说，我们直接开始讲解第一个校验错误：`use strict`。

## 缺少“use strict”声明的错误。

`use strict`语句是 JavaScript 中相对较新的特性，它允许我们的 JavaScript 在严格环境中运行。通常，它会捕获一些鲜为人知的错误，并“强制”你编写更严格、有效的代码。JavaScript 专家 John Resig 就此话题写了一篇很好的总结，你可以通过这个链接阅读它：[`ejohn.org/blog/ecmascript-5-strict-mode-json-and-more/`](http://ejohn.org/blog/ecmascript-5-strict-mode-json-and-more/)。

# 行动时间——修复"use strict"错误。

这个错误非常容易修复。但小心；如果代码无效，启用`use strict`可能会导致你的代码无法正常工作。以下是修复这个校验错误的方法：

1.  打开你的文本编辑器，复制并粘贴我们一直在使用的相同代码，并在你的 JavaScript 代码的第一行添加以下代码片段：

    ```js
    "use strict";

    ```

1.  保存你的代码并在 JSLint 上测试它。你会发现，现在错误已经消失了。

你可能会注意到还有一个关于你的 HTML 表单的另一个缺失的`use strict`错误；不要担心，我们会在本章的稍后部分解决这个问题。现在让我们继续下一个错误。

## 错误—意外使用++

这段代码在程序上没有问题。我们使用`++`的目的是在调用函数`addResponseElement()`时递增`globalCounter`。

然而，JSLint 认为使用`++`有问题。以下代码片段为例：

```js
var testing = globalCounter++ + ++someValues;
var testing2 = ++globalCounter + someValues++;

```

之前的陈述对大多数程序员来说可能看起来很困惑，因此被认为是坏的风格。更重要的是，这两个陈述在程序上是不同的，产生不同的结果。出于这些原因，我们需要避免使用`++`、`--`等这样的语句。

# 行动时间—修复"意外使用++"的错误

这个错误相对容易修复。我们只需要避免使用`++`。所以，导航到`addResponseElement()`函数，寻找`globalCounter++`。然后将`globalCounter++`更改为`globalCounter = globalCounter + 1`。所以，现在你的函数已经从这个样子：

```js
function addResponseElement(messageValue, idName){
globalCounter++; 
var totalInputElements = document.testForm.length;
debuggingMessages( addResponseElement","empty", "object is a value");
var container = document.getElementById('formSubmit');
container.innerHTML += "<input type=\"text\" value=\"" +messageValue+ "\"name=\""+idName+"\" /><br>";
if(globalCounter == totalInputElements){
container.innerHTML += "<input type=\"submit\" value=\"Submit\" />";
}
}

```

变成了这个样子：

```js
function addResponseElement(messageValue, idName) {
globalCounter = globalCounter + 1; 
debuggingMessages( "addResponseElement", "empty", "object is a value");
document.getElementById('formSubmit').innerHTML += "<input type=\"text\" value=\"" + messageValue + "\"name = \"" + idName + "\" /><br>";
if (globalCounter === 7) {
document.getElementById('formSubmit').innerHTML += "<input type=\"submit\" value=\"Submit\" />";
}
}

```

比较突出显示的行，你会看到代码的变化。现在让我们继续下一个错误。

## 错误—函数未定义

这个错误是由 JavaScript 引擎和网页在浏览器中渲染的方式引起的。我们在第一章*什么是 JavaScript 测试？*中简要提到，网页（和 JavaScript）在客户端从上到下解析。这意味着出现在顶部的东西将被首先阅读，然后是底部的东西。

# 行动时间—修复"函数未定义"的错误

1.  由于这个错误是由 JavaScript 函数的不正确流程引起的，我们需要改变函数的顺序。我们在第二章*即兴测试和调试 JavaScript*中做的是先写了我们将要使用的函数。这可能是错误的，因为这些函数可能需要的是只在 JavaScript 代码的后部分定义的数据或函数。这是一个非常简单的例子：

    ```js
    <script>
    function addTWoNumbers() {
    return numberOne() + numberTwo();
    }
    function numberOne(x, y) {
    return x + y;
    }
    function numberTwo(a, b){
    return a + b;
    }
    </script>

    ```

    基于之前的代码片段，你将意识到`addTwoNumbers()`需要从`numberOne()`和`numberTwo()`返回的数据。这里的问题在于，JavaScript 解释器在阅读`addTwoNumbers()`之前会先阅读`numberOne()`和`numberTwo()`。然而，`numberOne()`和`numberTwo()`都是由`addTwoNumbers()`调用的，导致代码流程不正确。

    这意味着，为了使我们的代码正确运行，我们需要重新排列函数的顺序。继续使用之前的例子，我们应该这样做：

    ```js
    <script>
    function numberOne(x, y) {
    return x + y;
    }
    function numberTwo(a, b){
    return a + b;
    }function addTWoNumbers() {
    return numberOne() + numberTwo();
    }
    </script>

    ```

    在之前的代码片段中，我们已经重新安排了函数的顺序。

1.  现在，我们将重新排列函数的顺序。对我们来说，我们只需要将我们的函数安排成这样：原来在代码中的第一个函数现在是最后一个，最后一个函数现在是第一个。同样，原来在 JavaScript 代码中出现的第二个函数现在是倒数第二个。换句话说，我们将反转代码的顺序。

1.  一旦您改变了函数的顺序，保存文件并在 JSLint 上测试代码。您应该注意到与函数未定义相关的验证错误现在消失了。

现在，让我们继续下一个验证错误。

## 太多的 var 声明

根据 JSLint，我们使用了太多的`var`声明。这意味着什么？这意味着我们在每个函数中使用了不止一个`var`声明；在我们的案例中，我们显然在每个函数中都使用了不止一个`var`声明。

这是怎么发生的呢？如果你滚动到底部并检查 JSLint 的设置，你会看到一个复选框被选中，上面写着**每个函数只允许一个 var 声明**。这意味着我们最多只能使用一个`var`。

为什么这被认为是好的风格呢？虽然许多程序员可能认为这是繁琐的，但 JSLint 的作者可能认为一个好的函数应该只做一件事。这通常意味着只操作一个变量。

当然，有很多讨论的空间，但既然我们都在这里学习，让我们动手修复这个验证错误。

# 行动时间——修复使用太多 var 声明的错误

为了修复这个错误，我们将需要进行某种代码重构。尽管代码重构通常意味着使您的代码更加简洁（即，更短的代码），您可能意识到将代码重构以符合验证标准是一项艰巨的工作。

1.  在本节中，我们将更改（几乎）所有将值保存到函数中的单个`var`声明。

    负责这个特定验证错误的代码是在`checkForm`函数中找到的。我们需要重构的语句如下：

    ```js
    var totalInputElements = document.testFormResponse.length;
    var nameOfPerson = document.testFormResponse.nameOfPerson.value;
    var birth = document.testFormResponse.birth.value;
    var age = document.testFormResponse.age.value;
    var spending = document.testFormResponse.spending.value;
    var salary = document.testFormResponse.salary.value;
    var retire = document.testFormResponse.retire.value;
    var retirementMoney = document.testFormResponse.retirementMoney.value;
    var confirmedSavingsByRetirement;
    var ageDifference = retire - age;
    var salaryPerYear = salary * 12;
    var spendingPerYear = spending * 12;
    var incomeDifference = salaryPerYear - spendingPerYear;

    ```

1.  现在我们将开始重构我们的代码。对于每个定义的变量，我们需要定义一个具有以下格式的函数：

    ```js
    function nameOfVariable(){
    return x + y; // x + y represents some form of calculation
    }

    ```

    我将从一个例子开始。例如，对于`totalInputElements`，我将这样做：

    ```js
    function totalInputElements() {
    return document.testFormResponse.length;
    }

    ```

1.  基于之前的代码，对您即将看到的内容做类似的事情：

    ```js
    /* here are the function for all the values */
    function totalInputElements() {
    return document.testFormResponse.length;
    }
    function nameOfPerson() {
    return document.testFormResponse.nameOfPerson.value;
    }
    function birth() {
    return document.testFormResponse.birth.value;
    }
    function age() {
    return document.testFormResponse.age.value;
    }
    function spending() {
    return document.testFormResponse.spending.value;
    }
    function salary() {
    return document.testFormResponse.salary.value;
    }
    function retire() {
    return document.testFormResponse.retire.value;
    }
    function retirementMoney() {
    return document.testFormResponse.retirementMoney.value;
    }
    function salaryPerYear() {
    return salary() * 12;
    }
    function spendingPerYear() {
    return spending() * 12;
    }
    function ageDifference() {
    return retire() - age();
    }
    function incomeDifference() {
    return salaryPerYear() - spendingPerYear();
    }
    function confirmedSavingsByRetirement() {
    return incomeDifference() * ageDifference();
    }
    function shortChange() {
    return retirementMoney() - confirmedSavingsByRetirement();
    }
    function yearsNeeded() {
    return shortChange() / 12;
    }
    function excessMoney() {
    return confirmedSavingsByRetirement() - retirementMoney();
    }

    ```

现在，让我们继续下一个错误。

## 期待<\/而不是<\

对我们大多数人来说，这个错误可能是最有趣的。我们之所以有这个验证错误，是因为 HTML 解析器与 JavaScript 解释器略有不同。通常，额外的反斜杠被 JavaScript 编译器忽略，但不被 HTML 解析器忽略。

这样的验证错误可能看起来不必要，但 Doug Crockford 知道这对我们的网页有一定的影响。因此，让我们继续解决这个错误的方法。

# 行动时间—解决期望的'<\/'而不是'</'错误

尽管这个错误是最引人入胜的，但它是最容易解决的。我们所需要做的就是找到所有包含`</`的 JavaScript 语句，并将它们更改为`<\/`。主要负责这个错误的功能是`buildFinalResponse()`。

1.  滚动到`buildFinalResponse()`函数，将所有含有`</`的语句更改为`<\/`。完成后，你应该有以下代码：

    ```js
    function buildFinalResponse(name, retiring, yearsNeeded, retire, shortChange) {
    debuggingMessages( buildFinalResponse", -1, "no messages");
    var element = document.getElementById("finalResponse");
    if (retiring === false) {
    element.innerHTML += "<p>Hi <b>" + name + "<\/b>,<\/p>";
    element.innerHTML += "<p>We've processed your information and we have noticed a problem.<\/p>";
    element.innerHTML += "<p>Base on your current spending habits, you will not be able to retire by <b>" + retire + " <\/b> years old.<\/p>";
    element.innerHTML += "<p>You need to make another <b>" + shortChange + "<\/b> dollars before you retire inorder to acheive our goal<\/p>";
    element.innerHTML += "<p>You either have to increase your income or decrease your spending.<\/p>";
    }
    else {
    // able to retire but....
    //alertMessage("retiring === true");
    element.innerHTML += "<p>Hi <b>" + name + "<\/b>,<\/p>";
    element.innerHTML += "<p>We've processed your information and are pleased to announce that you will be able to retire on time.<\/p>";
    element.innerHTML += "<p>Base on your current spending habits, you will be able to retire by <b>" + retire + "<\/b>years old.<\/p>";
    element.innerHTML += "<p>Also, you'll have' <b>" + shortChange + "<\/b> amount of excess cash when you retire.<\/p>";
    element.innerHTML += "<p>Congrats!<\/p>";
    }
    }

    ```

注意所有`</`都已更改为`<\/`。你可能还想检查代码，看看是否有这样的错误残留。

现在，解决了这个错误后，我们可以继续解决下一个验证错误。

## 期望'==='但找到'=='

在 JavaScript 和大多数编程语言中，`==`和`===`有显著的区别。一般来说，`===`比`==`更严格。

### 注意

JavaScript 中`===`和`==`的主要区别在于，`===`是一个严格等于运算符，只有当两个操作数相等且类型相同时，它才会返回布尔值`true`。另一方面，`==`运算符如果两个操作数相等，即使它们类型不同，也会返回布尔值`true`。

根据 JSList，当比较变量与真理值时应使用`===`，因为它比`==`更严格。在代码严格性方面，JSLint 确保代码质量是正确的。因此，现在让我们纠正这个错误。

# 行动时间—将`==`更改为`===`

由于前面提到的原因，我们现在将所有`==`更改为`===`，用于需要比较的语句。尽管这个错误相对容易解决，但我们需要了解这个错误的重要性。`===`比`==`严格得多，因此使用`===`而不是`==`更为安全和有效。

回到你的源代码，搜索所有包含`==`的比较语句并将它们更改为`===`. `==`主要出现在`if`和`else-if`语句中，因为它们用于比较。

完成后，你可能想测试一下你的更新后的代码是否通过了 JSLint，并看看你是否清除了所有这类错误。

现在，让我们继续处理另一个繁琐的错误："Alert is not defined"。

## Alert is not defined

通常，单独使用`alert`会导致全局命名空间的"污染"。尽管它很方便，但根据 JSLint，这是一种不好的代码实践。因此，我们将要使用的解决这个验证错误的方法是再次进行某种代码重构。

在我们的代码中，你应该注意到我们主要使用`alert()`来提供关于函数名、错误消息等方面的反馈。我们需要使我们的`alert()`能够接受各种形式的消息。

# 行动时间—解决"Alert is not defined"错误

我们将做的是将所有的`alert()`语句合并到一个函数中。我们可以向该函数传递一个参数，以便根据情况改变警告框中的消息。

1.  回到你的代码，在`<script>`标签的顶部定义以下函数：

    ```js
    function alertMessage(messageObject) {
    alert(messageObject);
    return true;
    }

    ```

    +   `messageObject`是我们将用来保存我们消息的参数。

1.  现在，将所有的`alert()`语句更改为`alertMessage()`，以确保`alert()`的消息与`alertMessage()`的消息相同。完成后，保存文件并再次运行 JSLint 代码。

如果你尝试运行你的代码在 JSLint 中，你应该看到`alert()`造成的“损害”已经减少到只有一次，而不是十到二十次。

在这种情况下，我们可以做的是最小化`alert()`的影响，因为对于我们来说，没有一个现成的替代方案可以在警告框中显示消息。

现在是避免 HTML 事件处理程序的下一个错误的时候了。

## 避免使用 HTML 事件处理程序

良好的编码实践通常指出需要将编程逻辑与设计分离。在我们的案例中，我们在 HTML 代码中嵌入了事件处理程序（JavaScript 事件）。根据 JSLint，这种编码可以通过完全避免 HTML 事件处理程序来改进。

### 注意

尽管理想情况下是将编程逻辑与设计分离，但在使用 HTML 内置事件处理程序方面并没有什么功能上的问题。你可能需要考虑这是否值得（在时间、可维护性和可扩展性方面），坚持（几乎）完美的编码实践。在本节的后部分，你会发现尝试验证（并功能正确）代码可能会很繁琐（甚至令人烦恼）。

为了解决这个验证错误，我们将需要使用事件监听器。然而，由于事件监听器的兼容性问题，我们将使用 JavaScript 库来帮助我们处理事件监听器支持的不一致性。在这个例子中，我们将使用 JQuery。

JQuery 是一个由 John Resig 创建的 JavaScript 库。你可以通过访问这个链接下载 JQuery：[`jquery.com`](http://jquery.com)。正如这个网站所描述的，“JQuery 是一个快速和简洁的 JavaScript 库，它简化了 HTML 文档遍历、事件处理和动画，以及 Ajax 交互，用于快速网页开发。”在我的个人经验中，JQuery 确实通过修复许多棘手问题（如 DOM 不兼容性、提供内置方法创建动画等）使生活变得更容易。我当然建议你通过访问以下链接跟随一个入门教程：[`docs.jquery.com/Tutorials:Getting_Started_with_jQuery`](http://docs.jquery.com/Tutorials:Getting_Started_with_jQuery)

# 行动时间—避免 HTML 事件处理程序

在本节中，你将学习如何通过不同的编码方式避免 HTML 事件处理程序。在这种情况下，我们不仅删除了每个 HTML 输入元素中嵌入的 JavaScript 事件，还需要为我们的 JavaScript 应用程序编写新函数，使其以相同的方式工作。此外，我们将使用一个 JavaScript 库，帮助我们删除与事件处理和事件监听器相关的所有复杂内容。

1.  打开同一文档，滚动到`<body>`标签。删除在表单中找到的所有 HTML 事件处理程序。在你删除了所有的 HTML 事件处理程序后，你的表单源代码应该看起来像这样：

    ```js
    <form name="testForm" >
    <input type="text" name="enterText" id="nameOfPerson" size="50" value="Enter your name"/><br>
    <input type="text" name="enterText" id="birth" size="50" value="Enter your place of birth"/><br>
    <input type="text" name="enterNumber" id="age" size="50" maxlength="2" value="Enter your age"/><br>
    <input type="text" name="enterNumber" id="spending" size="50" value="Enter your spending per month"/><br>
    <input type="text" name="enterNumber" id="salary" size="50" value="Enter your salary per month"/><br>
    <input type="text" name="enterNumber" id="retire" size="50" maxlength="3" value="Enter your the age you wish to retire at" /><br>
    <input type="text" name="enterNumber" id="retirementMoney" size="50" value="Enter the amount of money you wish to have for retirement"/><br>
    </form>

    ```

1.  现在滚动到`</style>`标签。在`</style>`标签之后，输入以下代码片段：

    ```js
    <script src="img/jquery.js">
    </script>

    ```

    在前一行中，你正在使 JQuery 在你的代码中生效。这将允许你在修复代码时使用 JQuery 库。现在该写一些 JQuery 代码了。

1.  为了维持我们代码的功能，我们将需要使用 JQuery 提供的`.blur()`方法。滚动到你的 JavaScript 代码的末尾，添加以下代码片段：

    ```js
    jQuery(document).ready(function () {
    jQuery('#nameOfPerson').blur(function () {
    submitValues(this);
    });
    jQuery('#birth').blur(function () {
    submitValues(this);
    });
    jQuery('#age').blur(function () {
    submitValues(this);
    });
    jQuery('#spending').blur(function () {
    submitValues(this);
    });
    jQuery('#salary').blur(function () {
    submitValues(this);
    });
    jQuery('#retire').blur(function () {
    submitValues(this);
    });
    jQuery('#retirementMoney').blur(function () {
    submitValues(this);
    });
    jQuery('#formSubmit').submit(function () {
    checkForm(this);
    return false;
    });
    });

    ```

    以下是对 JQuery 工作方式的简短解释：`jQuery(document).ready(function ()`用于启动我们的代码；它允许我们使用 JQuery 提供的方法。为了选择一个元素，我们使用`jQuery('#nameOfPerson')`。如前所述，我们需要保持代码的功能，所以我们将使用 JQuery 提供的`.blur()`方法。为此，我们将`.blur()`添加到`jQuery('#nameOfPerson')`中。我们需要调用`submitValues()`，因此我们需要将`submitValues()`包含在`.blur()`中。因为`submitValues()`是一个函数，所以我们将它这样包含：

    ```js
    jQuery('#nameOfPerson').blur(function () {
    submitValues(this);
    });

    ```

+   在此时，我们应该已经完成了必要的修正，以实现有效和功能的代码。我在下一节中简要总结一下这些修正。

## 我们所做修正的总结

现在，我们将通过快速回顾我们所做以修复验证错误的步骤来刷新我们的记忆。

首先，我们将原始代码粘贴到 JSLint 中，并注意到我们有大量的验证错误。幸运的是，这些验证错误可以分组，这样相同的错误可以通过修正一个代码错误来解决。

接下来，我们开始了修正过程。一般来说，我们试图从那些看起来最容易的验证错误开始修复。我们修复的第一个验证错误是缺少`use strict`声明的错误。我们所做的是在我们的 JavaScript 代码的第一行输入`use strict`，这样就修复了错误。

我们修复的第二个验证错误是“函数未定义错误”。这是由于 JavaScript 函数的不正确流程造成的。因此，我们将函数的流程从这：

```js
function submitValues(elementObj){
/* some code omitted */
}
function addResponseElement(messageValue, idName){
/* some code omitted */
function checkForm(formObj){
/* some code omitted */
}
function buildFinalResponse(name,retiring,yearsNeeded,retire, shortChange){
/* some code omitted */
}
function debuggingMessages(functionName, objectCalled, message){
/* some code omitted */
}

```

到这个程度：

```js
function debuggingMessages(functionName, objectCalled, message) {
/* some code omitted */
}
function checkForm(formObj) {
/* some code omitted */
function addResponseElement(messageValue, idName) {
/* some code omitted */
}
function submitValues(elementObj) {
/* some code omitted */
}

```

请注意，我们只是简单地反转了函数的顺序来修复错误。

然后我们转向了一个非常耗时的错误——在函数内使用太多的`var`声明。总的来说，我们的策略是将几乎所有的`var`声明重构为独立的函数。这些独立函数的主要目的是返回一个值，仅此而已。

接下来，我们又转向了另一个耗时的验证错误，那就是"expected`<\/` instead of`</`。一般来说，这个错误是指闭合的 HTML 标签。所以我们所做的就是将所有的闭合 HTML 标签中的`/>`更改为`\/>`。例如，我们将以下代码更改为：

```js
function buildFinalResponse(name,retiring,yearsNeeded,retire, shortChange){
debuggingMessages( buildFinalResponse", -1,"no messages");
var element = document.getElementById("finalResponse");
if(retiring == false){
//alert("if retiring == false");
element.innerHTML += "<p>Hi <b>" + name + "</b>,<p>";
element.innerHTML += "<p>We've processed your information and we have noticed a problem.</p>";
element.innerHTML += "<p>Base on your current spending habits, you will not be able to retire by <b>" + retire + " </b> years old.</p>";
element.innerHTML += "<p>You need to make another <b>" + shortChange + "</b> dollars before you retire inorder to acheive our goal</p>";
element.innerHTML += "<p>You either have to increase your income or decrease your spending.</p>";
}
else{
// able to retire but....
alert("retiring == true");
element.innerHTML += "<p>Hi <b>" + name + "</b>,</p>";
element.innerHTML += "<p>We've processed your information and are pleased to announce that you will be able to retire on time.</p>";
element.innerHTML += "<p>Base on your current spending habits, you will be able to retire by <b>" + retire + "</b>years old.
</p>";
element.innerHTML += "<p>Also, you'll have' <b>" + shortChange + "</b> amount of excess cash when you retire.</p>";
element.innerHTML += "<p>Congrats!<p>";
}
}

```

到这个：

```js
function buildFinalResponse(name, retiring, yearsNeeded, retire, shortChange) {
debuggingMessages( buildFinalResponse", -1, "no messages");
var element = document.getElementById("finalResponse");
if (retiring === false) {
element.innerHTML += "<p>Hi <b>" + name + "<\/b>,<\/p>";
element.innerHTML += "<p>We've processed your information and we have noticed a problem.<\/p>";
element.innerHTML += "<p>Base on your current spending habits, you will not be able to retire by <b>" + retire + " <\/b> years old.<\/p>";
element.innerHTML += "<p>You need to make another <b>" + shortChange + "<\/b> dollars before you retire inorder to achieve our goal<\/p>";
element.innerHTML += "<p>You either have to increase your income or decrease your spending.<\/p>"; 
}
else {
// able to retire but....
//alertMessage("retiring === true");
element.innerHTML += "<p>Hi <b>" + name + "<\/b>,<\/p>";
element.innerHTML += "<p>We've processed your information and are pleased to announce that you will be able to retire on time.<\/p>";
element.innerHTML += "<p>Base on your current spending habits, you will be able to retire by <b>" + retire + "<\/b>years old.<\/p>";
element.innerHTML += "<p>Also, you'll have' <b>" + shortChange + "<\/b> amount of excess cash when you retire.<\/p>";
element.innerHTML += "<p>Congrats!<\/p>"; 
}
}

```

请注意，高亮的行是我们将`/>`更改为`\/>`的地方。

在修复上一个错误后，我们转向了一个概念上更难以理解，但容易解决的错误。那就是，"expected `===` instead of saw `==`"。根据 JSLint，使用`===`比使用`==`更严格，更安全。因此，我们需要将所有的`==`更改为`===`。

下一个错误，"Alert is not defined"，在概念上与"Too many `var` statement"错误相似。我们需要做的是将所有的`alert()`声明重构为接受参数`messageObject`的`alertMessage()`函数。这使我们能够在几乎整个 JavaScript 程序中只使用一个`alert()`。每当我们需要使用一个警告框时，我们只需要向`alertMessage()`函数传递一个参数。

最后，我们转向修复一个最棘手的验证错误："避免使用 HTML 事件处理程序"。由于事件监听器的复杂性，我们得到了流行的 JavaScript 库 JQuery 的帮助，并编写了一些 JQuery 代码。首先，我们从我们的 HTML 表单中移除了所有的 HTML 事件处理程序。我们的 HTML 表单从这样变成了：

```js
<form name="testForm" >
<input type="text" name="enterText" id="nameOfPerson" onblur="submitValues(this)" size="50" value="Enter your name"/><br>
<input type="text" name="enterNumber" id="age" onblur="submitValues(this)" size="50" maxlength="2" value="Enter your age"/><br>
<input type="text" name="enterText" id="birth" onblur="submitValues(this)" size="50" value="Enter your place of birth"/><br>
<input type="text" name="enterNumber" id="spending" onblur="submitValues(this)" size="50" value="Enter your spending per month"/><br>
<input type="text" name="enterNumber" id="salary" onblur="submitValues(this)" size="50" value="Enter your salary per month"/><br>
<input type="text" name="enterNumber" id="retire" onblur="submitValues(this)" size="50" maxlength="3" value="Enter your the age you wish to retire at" /><br>
<input type="text" name="enterNumber" id="retirementMoney" onblur="submitValues(this)" size="50" value="Enter the amount of money you wish to have for retirement"/><br>
</form>

```

到这个：

```js
<form name="testForm" >
<input type="text" name="enterText" id="nameOfPerson" size="50" value="Enter your name"/><br>
<input type="text" name="enterText" id="birth" size="50" value="Enter your place of birth"/><br>
<input type="text" name="enterNumber" id="age" size="50" maxlength="2" value="Enter your age"/><br>
<input type="text" name="enterNumber" id="spending" size="50" value="Enter your spending per month"/><br>
<input type="text" name="enterNumber" id="salary" size="50" value="Enter your salary per month"/><br>
<input type="text" name="enterNumber" id="retire" size="50" maxlength="3" value="Enter your the age you wish to retire at" /><br>
<input type="text" name="enterNumber" id="retirementMoney" size="50" value="Enter the amount of money you wish to have for retirement"/><br>
</form>

```

为了支持新的 HTML 表单，我们链接了 JQuery 库，并添加了一些代码来监听 HTML 表单事件，像这样：

```js
<script type="text/javascript"> src="img/jquery.js"></script>
<script type="text/javascript">
/* some code omitted */
jQuery(document).ready(function () {
jQuery('#nameOfPerson').blur(function () {
submitValues(this);
});
jQuery('#birth').blur(function () {
submitValues(this);
});
jQuery('#age').blur(function () {
submitValues(this);
});
jQuery('#spending').blur(function () {
submitValues(this);
});
jQuery('#salary').blur(function () {
submitValues(this);
});
jQuery('#retire').blur(function () {
submitValues(this);
});
jQuery('#retirementMoney').blur(function () {
submitValues(this);
});
jQuery('#formSubmit').submit(function () {
checkForm(this);
return false;
});
});
</script>

```

完成的代码可以在`source code`文件夹下的`Chapter 3`中找到，文件名为`perfect-code-for-JSLint.html`。你可以将这个与你编辑的代码进行比较，看看你是否理解了我们试图做什么。现在，你可能想将代码复制粘贴到 JSLint 中看看效果如何。你将只会看到与 Jquery 使用相关的错误，一个关于使用`alert()`的验证错误，以及另一个关于使用太多`var`声明的错误。

## 刚才发生了什么？

我们已经纠正了大部分的验证错误，从极其大量的验证错误减少到少于十个验证错误，其中只有两个或三个与我们的代码相关。

### 注意

你可能会注意到`jQuery not defined`错误。尽管 JSLint 捕获了外部链接的 JQuery 库，但它并不显式阅读代码，因此导致了`jQuery not defined`错误。

现在我们已经修复了验证错误，让我们接下来使用另一个免费的验证工具——JavaScript Lint。

# JavaScript Lint—一个你可以下载的工具。

JavaScript Lint 可以在[`www.javascriptlint.com`](http://www.javascriptlint.com)下载，其工作方式与 JSLint 类似。主要区别在于，JavaScript Lint 是一个可下载的工具，而 JSLint 作为一个基于网页的工具运行。

与 JSLint 一样，JavaScript Lint 能够找出以下常见错误：

+   行尾缺少分号：在每行末尾都要加上分号。

+   没有`if, for`和`while`的括号。

+   不执行任何操作的语句。

+   在 switch 语句中的 case 语句将小数点转换为数字。

您可以通过访问其主页[`www.javascriptlint.com`](http://www.javascriptlint.com)了解更多关于它的功能。

要了解如何使用 JavaScript Lint，您可以跟随网站上找到的教程。

+   如果您使用 Windows，您可能需要阅读在[`www.javascriptlint.com/docs/running_from_windows_explorer.htm`](http://www.javascriptlint.com/docs/running_from_windows_explorer.htm)找到的设置说明。

+   如果您使用基于 Linux 的操作系统，您可以查看在[`www.javascriptlint.com/docs/running_from_the_command_line.htm`](http://www.javascriptlint.com/docs/running_from_the_command_line.htm)找到的说明。

+   最后，如果您希望将 JavaScript Lint 集成到您的 IDE（如 Visual Studio）中，您可以通过访问[`www.javascriptlint.com/docs/running_from_your_ide.htm`](http://www.javascriptlint.com/docs/running_from_your_ide.htm)了解更多有关如何执行此操作的信息。

我们不会讨论如何修复由 JavaScript Lint 发现的验证错误，因为这些原则与 JSLint 相似。然而，我们挑战你修复剩余的错误（除了由 JQuery 引起的错误）。

## 挑战自己——修复 JSLint 发现的剩余错误。

好的，这是我将向您提出的第一个挑战。修复 JSLint 发现的剩余错误，具体如下：

+   **"alert is not defined"：** 此错误在`alertMessage()`函数中找到。

+   **太多的 var 声明：** 此错误在`submitValues()`函数中找到。

以下是一些供您开始的想法：

+   在我们的 JavaScript 应用程序中，有没有办法避免使用`alert()`？我们如何显示能吸引观众注意力的信息，同时又是有效的？

+   对于在`submitValues()`函数中发现的错误，我们如何重构代码，使得函数中只有一个`var`声明？我们可以将`var`声明重构为一个函数，并让它返回一个布尔值吗？

好的，现在你可能想试试，但要注意，你所提出的或打算使用的解决方案可能会导致其他验证错误。所以你可能会在实施之前考虑一下你的解决方案。

# 总结

我们终于完成了这一章的结尾。我首先开始总结我们用来编写有效代码的一些策略和小贴士，然后概述了章节的其余部分。

我们用来编写有效代码（根据 JSLint）的某些策略如下：

+   适当间距你的代码，特别是在数学符号后，`if, else, ( )`等地方

+   每个函数中只使用一个`var`声明

+   考虑你的程序流程；编写代码时，确保所需数据或函数位于程序顶部

+   谨慎使用`alert()`函数。相反，将你的`alert()`函数合并成一个函数

+   使用`===`而不是`==`；这确保了你的比较语句更加准确

+   避免使用 HTML 事件处理程序，而是使用监听器。另外，你可以借助 JavaScript 库（如 JQuery）提供事件监听器给你的代码。

最后，我们讨论了以下主题：

+   测试与验证之间的区别

+   验证如何帮助我们写出好代码

+   如果我们不验证代码，可能会出现什么问题——如果我们不验证代码，它可能不具备可扩展性，可读性较差，并可能导致意外错误

+   如何使用 JSLint 和 JavaScript Lint 验证我们的代码

既然我们已经学习了如何通过验证工具测试 JavaScript，你可能想考虑一下当我们打算测试代码时可以采用的策略。正如本章中的示例所示，编写有效代码（或修正无效代码）是一个非常繁琐的过程。更重要的是，有些验证警告或错误并不影响我们程序的整个运行。在这种情况下，你认为验证代码值得花费精力吗？还是认为我们应该追求完美，写出完美的代码？这很大程度上取决于我们的测试计划，这将决定测试的范围、要测试的内容以及其他许多内容。这些主题将在下一章第四章，*计划测试*中介绍。所以，我将在本章结束，下章再见。


# 第四章：测试计划

> 欢迎来到第四章。在我们进入更正式的测试过程之前，我们首先必须了解测试是关于什么的。在本章中，我们将学习如何为你的 JavaScript 程序制定测试计划。我们将学习你应该知道的各种测试概念，之后我会向你提供一个简短的指南，它将作为下一章的基础。

在我们进入各种测试概念之前，我们首先需要建立对以下问题的简要理解：

+   我们真的需要一个测试计划来进行测试吗？

+   我们应该什么时候为我们的代码开发测试计划？

+   我们的程序需要多少测试？

在覆盖上述问题之后，我们将学习以下测试概念和想法：

+   黑盒测试、白盒测试及相关概念

+   边界条件

+   单元测试

+   网页功能测试

+   集成测试

+   非功能性测试，如性能测试

+   可用性测试

+   测试顺序——我们首先进行上述哪些测试？

+   回归测试——通常在我们更改代码时进行

为了更好地了解测试在何时何地发挥作用，我们首先从软件生命周期的非常简要介绍开始。

# 软件生命周期的非常简要介绍

了解软件生命周期将帮助你更深入地了解软件开发过程，更重要的是，了解测试将在何时何地进行。

一般来说，软件生命周期有以下阶段：

1.  分析

1.  设计

1.  实施

1.  测试

1.  部署

1.  维护

在第一阶段，我们通常进行分析以了解干系人的需求。例如，如果你为客户进行定制项目，你需要理解用户需求、系统需求和业务目标。一旦你理解了需求，你需要设计软件。这个阶段需要做的事情包括绘制数据流程图、设计数据库等。下一阶段是实施阶段。我们可以将此视为实际的编码过程。

接下来是测试，这是本书的主要关注点。在本章中，我们将学习如何根据各种测试概念来规划我们的测试。在测试阶段之后，我们将部署项目，最后我们维护项目。因为这是一个循环，理论上我们在维护阶段期间或之后会回到分析阶段。这是因为软件或程序是进化的；随着需求和需求的变化，我们的软件也在变化。

尽管术语和阶段可能与你在其他相关内容中看到的有稍许不同，但过程通常是一样的。这里的主要收获是，测试通常在实施之后进行。

## 敏捷方法

你可能听说过敏捷方法论，它包括敏捷软件开发方法论，当然还有敏捷测试方法。

一般来说，敏捷软件开发和测试方法通常是以最终用户或客户为目标进行的。通常文档很少，专注于短暂的软件开发周期，通常为一周到四周。

那么这和你们在上一部分读到的软件开发周期有什么关系呢？总的来说，测试不是一个独立的阶段，而是与开发过程紧密集成，从客户的角度进行代码测试，尽可能早，当代码足够稳定以进行测试时。

### 敏捷方法和软件周期在行动

可能你们很难想象之前的理论是如何应用的。为这本书创建示例代码的过程 closely mimics 软件生命周期和敏捷方法论。所以我打算非常简要地分享一下我根据我们学到的理论为这本书创建代码示例时的经历。

### 分析和设计

从技术角度来说，分析和设计阶段发生在我思考什么样的代码示例能够满足书籍目标的时候。我认为代码应该足够简单，便于理解，最重要的是能够展示 JavaScript 的各种特性。代码应该为后续章节的代码测试搭建好舞台。

### 实施和测试

实施阶段发生在我编写代码示例的时候。当我为代码片段创建函数时，我尽可能地进行测试，并问自己代码是否能够展示 JavaScript 的使用并便于后续的测试目的。

所以，这里发生的事情是我在尽可能多地进行测试时使用了一种敏捷测试方法。

### 部署

在商业世界中，代码的部署通常发生在代码传输给最终用户之后。然而，在我的情况下，部署涉及到将我的代码示例发送给编辑。

### 维护

维护阶段发生在我提交代码后，编辑发现并修复了 bug 的时候。尽管有意愿，但代码并不总是无懈可击的。

# 你需要一个测试计划才能进行测试吗？

你很可能会需要一个测试计划来执行测试。这是因为计划帮助你保持清晰的测试目标。它还帮助你确定你想对你的程序进行什么样的测试。

最重要的是，正如您将意识到的，为了进行彻底的测试，您将需要实施各种测试，包括基于白盒测试和黑盒测试的概念测试，网页测试，单元测试，集成测试等。测试计划还作为测试数据，错误，测试结果以及您程序可能的解决方案的记录。这意味着，为了确保不遗漏任何内容，最好有一个明确的计划，了解要测试什么，何时测试以及如何测试您的程序。

# 何时制定测试计划

理论上，如果您查看软件开发周期，您会发现测试是在实施之后进行的。测试计划在您完成程序的实际编码过程（实施）之后应该进行。这是因为只有在这个时候，您才确认了您有哪些功能，方法和模块；基于您已经完成的内容来规划要测试的内容是有商业意义的，因为您知道要关注什么。

然而，在实践中，建议在实施过程之前开始规划。根据您的具体情况，当然有可能您可以制定一个高级测试计划（HLTP）或高级测试用例（HLTC）。如果您正在开发一个大型复杂的系统，需要 HLTP 来解决整体需求。其他支持性测试计划用于解决系统的详细内容。高级测试用例（HLTC）与高级测试计划（HLTP） somewhat 相似，不同之处在于它覆盖了与系统整体需求直接相关的主要功能测试用例。

您应该注意的另一个要点是，在实践中，测试计划可以广泛地分为系统测试和用户验收测试。系统测试涵盖所有形式的的功能测试和非功能测试（您稍后了解），而用户验收测试是一个阶段，在这个阶段，测试是由最终用户在移交所有权之前进行的。

# 需要进行多少测试？

你可能急于确定需要测试什么以及不需要测试什么。关于需要进行多少测试有很多不同的观点，但我个人认为，您程序中列出的以下部分内容应该定义您的测试计划范围。

## 代码意图做什么？

首先，您需要了解代码的意图。例如，我们之前章节中代码的业务需求是为了根据用户的输入计算用户是否能够按时退休，这些输入包括他的当前年龄，他希望退休的年龄，他当前的支出，当前的薪水等等。因此，我们创建了满足业务需求的代码。一旦我们知道我们的代码意图做什么，我们就可以测试代码是否满足我们的业务需求。

## 测试代码是否满足我们的需求

通过测试代码以查看它是否满足我们的业务需求，我们的意思是对于每个输入，我们需要得到正确的输出。回到我们在第二章，*JavaScript 中的即兴测试和调试*和第三章，*语法验证*中提到的例子，如果剩余可支配收入总额小于用于退休的资金量，输出将应该是“无法退休”，至少在字面上是这样的。从测试角度来看，我们需要确保当提到的情况为真时，输出将是“无法退休”。

这可以通过一种称为白盒测试的概念来实现，其中测试是基于测试者知道代码内容的假设进行的。我将在接下来的章节中详细介绍白盒测试和其他测试概念。为了给你一个提示，你将遇到的一些测试概念包括单元测试，你以小单元测试代码，以及边界值测试，你测试代码的最大或最小可接受值。

接下来，我们需要考虑的是如何测试或检测用户无效行为。

## 测试用户无效行为

在开发网页时，我们最常听到的一句话是“永远不要信任用户”。这是因为可能存在恶意的用户，他们试图通过输入无效数据来“破坏”你的应用程序。以前面章节中的例子为例，姓名输入框只能接受字符和空格，而年龄和工资输入框只能接受数字，不能接受字符。然而，如果有人试图将字符输入年龄或工资字段，这将是一种无效行为。

我们的程序必须足够健壮，能够测试或检查无效行为；错误的输入会导致错误的输出。

## 上述问题的简要总结

通过了解你的代码旨在做什么以及它应该做什么，并理解检测用户无效行为的需求，你已经定义了测试计划的范围。你的测试应该围绕这些标准进行。

现在我们可以转向你将在测试的不同方面使用的各种测试概念，以及测试计划的构建块——主要测试概念和策略。

# 主要测试概念和策略

在本节中，我们将介绍不同类型的测试概念和策略。我不会试图详细解释每个概念，而是需要你掌握其大意，并了解这些概念的来源。熟悉这些概念后，我们将着手制定实际的测试计划。作为一个开始，我将从开发者遵循的业务策略讲起（无论你为外部或内部客户执行项目），这样你可以对测试的进行有一个高层次的了解。总之，无论你信仰哪种测试概念、方法论或理念，你都将面临以下测试用例：

+   功能性需求测试

+   非功能性需求测试

+   验收测试

## 功能性需求测试

功能性需求测试旨在测试软件系统中的代码、功能或模块。例如，回到我们为前几章编写的代码，功能性需求包括以下内容：

1.  检查用户输入的有效性。

1.  如果步骤 1 的输入有效，一个新的输入框将在当前输入框的右侧出现，当用户将鼠标移至下一个输入框时。

1.  根据用户输入提供正确的计算输出。例如，如果用户退休时需要 1,000,000 美元，而他到退休时只有 500,000 美元，那么他将无法退休。

本章涵盖的功能性需求测试示例如下：

+   网页测试

+   边界测试

+   等价类划分

## 非功能性需求测试

非功能性需求测试指的是与软件的功能或特定行为无关的需求。相反，这是一个指定了可以用来评判软件运行情况的标准的需求。

例如，功能性需求可能是我们的软件应该能够存储用户输入的值，而非功能性需求是数据库应该实时更新。

另一个与前几章示例代码相关的例子是，功能性需求可能是软件能够计算用户是否能够按时退休，而非功能性需求可能是我们的用户界面应该直观。你现在看到非功能性需求与功能性需求之间的区别了吗？

本章涵盖的非功能性需求测试示例如下：

+   性能测试

+   可用性测试

+   集成测试

你作为一名软件开发者在职业生涯中可能会遇到的其它非功能性需求如下：

+   页面快速加载

+   搜索引擎优化网页

+   创建的软件文档

+   系统的效率

+   软件的可靠性

+   你生产的软件代码的互操作性。例如，你可以在主要浏览器上编写 JavaScript

## 验收测试

验收测试通常是整个测试过程的最后一个阶段。这通常在软件最终被客户接受之前进行。验收测试可以进一步分为两部分。首先由软件供应商进行验收测试，然后由最终用户（称为用户验收测试）进行验收测试。

验收测试是客户（或最终用户）将在您创建的软件上进行实际测试（类似于实际使用系统）的时间。一个典型的过程将包括最终用户创建反映软件商业使用的测试用例。

如果你使用敏捷测试方法，这些测试用例通常被称为故事。这取决于客户在商业环境中如何使用它们。在用户验收测试之后，你将把产品的所有权移交给客户。

在最常见的测试场景涵盖之后，我们将进入测试概念的具体内容。我们将从最常听到的测试概念之一，即黑盒测试概念开始。

## 黑盒测试

黑盒测试属于“箱子方法”，其中一款软件被视为一个箱子，箱子包含各种功能、方法、类等。比喻来说，“黑盒”通常意味着我们无法看到箱子里面有什么。这意味着我们不知道程序的内部结构而实施测试；我们从程序的外部视角出发，使用有效和无效的输入以确定输出是否正确。

因为我们不知道程序的内部结构和代码，所以我们只能从用户的角度来测试程序。在这种情况下，我们可能试图确定主要功能是什么，然后尝试根据这些功能实施我们的测试。

黑盒测试的主要优点是，测试结果往往是独立的，因为测试人员不知道代码。然而，缺点是，因为测试人员不知道代码是关于什么的，测试人员可能会创建或执行重复的测试，或者测试未能测试软件最重要的方面。更糟糕的是，测试人员可能会漏掉整个功能或方法。

这就是为什么在现实世界中，测试用例会在开发周期的早期阶段准备好的原因，这样我们就不会遗漏某些需求。优点是测试人员将能够访问所需的测试用例，但同时，测试人员无需具备完整的代码知识。

黑盒测试的一些例子包括可用性测试、边界测试和公测。

### 可用性测试

简单来说，可用性测试通常涉及从用户的角度进行测试，以查看我们创建的程序是否易于使用。这里的关键目标是观察用户使用我们的程序，以发现错误或需要改进的地方。可用性测试通常包括以下方面：

+   **性能：**特别是在用户完成特定任务所需的点击（或操作）次数方面，例如注册为会员，或从网站上购买产品等。

+   **召回率：**用户在一段时间没有使用程序后，还能记得如何使用程序吗？

+   **准确性：**我们的程序设计是否导致了最终用户的错误？

+   **反馈：**反馈无疑是 AJAX 相关应用最重要的一个问题之一。例如，在提交 AJAX 表单后，用户通常会等待某种形式的反馈（以视觉反馈的形式，如成功消息）。但是想象一下，如果没有视觉反馈或成功消息，用户怎么知道他是否成功或失败地提交了表单呢？

### 边界测试

边界测试是一种测试方法，其中测试最大和最小值。边界测试有时包括测试错误值和典型值。

例如，在前几章的程序中，我们允许输入名字的最大字符数是 20 个字符。

### 等价划分

等价划分测试是一种将数据范围划分为分区，从而导出测试用例的技术。例如，对于接受用户年龄的输入框，它应该表现出以下分区：

![等价划分](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_04_04.jpg)

请注意，在我们的示例中，只接受正数值来输入用户的年龄，因为一个人的年龄技术上应该是正数。因此，任何负值都是不可接受的值。

对于小于**-231**且大于**231-1**的范围内，由于硬件和 EMCA 操作符的要求，整数只能持有**-231**到**231-1**之间的值。

### 公测

公测已经被当前流行的 Web 2.0 公司，如谷歌，普及，在这些公司中，网络应用程序通常会发布给除了核心编程团队之外的其他有限受众。公测在 alpha 测试之后进行，此时大多数的错误和故障已经被检测并修复。公测通常被用作获取潜在用户反馈的一种方式。

这样的过程在开源项目中很常见，比如 Ubuntu（一个基于 Linux 的开源操作系统）、jQuery（一个 JavaScript 库）和 Django（一个基于 Python 的网页框架）。这些开源项目或软件通常有一系列的内测和公测版本。它们在发布软件或项目的主要版本之前，通常也会有发布候选版本。

## 白盒测试

白盒测试也被称为透明盒测试、玻璃盒测试或透明测试。白盒测试可以被视为黑盒测试的对立面；我们在了解程序的内部结构的情况下测试程序。我们从程序的内部视角来看待问题，并在实施我们的测试计划时使用这种视角。

白盒测试通常发生在测试可以访问程序的内部代码和数据结构的情况下。因为我们从程序的内部视角来看待问题，并且了解我们的源代码，所以我们的测试计划是基于我们的代码来设计的。

我们可能会发现自己追踪代码的执行路径，并找出程序中各种函数或方法的各种输入和输出值。

白盒测试的一些例子包括分支测试和 Pareto 测试。

### 分支测试

分支测试是一个概念，它要求代码中的每个分支至少测试一次。这意味着编写的一切功能或代码都应该被测试。在软件测试中，有一个度量标准称为代码覆盖率，它指的是程序的源代码中有多少已经被测试过。分支测试覆盖的一些更重要的类型包括以下内容：

+   功能覆盖：确保代码中的每个功能都已经被调用（测试）

+   决策覆盖：每个`if else`语句都已经被测试过。可能存在这样的情况，代码的`if`部分可以工作，但`else`部分却不能，反之亦然。

### Pareto 测试

Pareto 测试我个人称之为“现实世界”的测试，并在严格的时间和金钱约束下进行。这是因为 Pareto 测试只关注最常用的功能；最经常使用的功能是最重要的，因此我们应该把时间和精力集中在测试这些功能上。另外，我们可以将 Pareto 测试看作是大多数错误来自于我们程序中少数几个功能的情况；因此，通过发现这些功能，我们可以更有效地测试我们的程序。

### 注意

Pareto 测试源自一个被称为“帕累托原则”的想法，也许更广为人知的是“80-20 原则”。帕累托原则指出，大约 80% 的效果来自于 20% 的原因。例如，80% 的销售收入可能来自于 20% 的销售团队或客户。或者另一个例子是，世界上 80% 的财富是由世界上 20% 的人口控制的。应用在我们的案例中，我们可以认为 80% 的错误或程序错误来自于 20% 的代码，因此我们应该专注于这部分代码的测试。或者，我们可以说程序的 80% 的使用活动来自于 20% 的代码。同样，我们可以专注于这部分代码的测试。顺便说一下，Pareto 测试可以被视为一个一般的测试原则，而不仅仅是白盒测试的一种形式。

## 单元测试

单元测试将代码分成逻辑块进行测试，通常一次关注一个方法。单元可以被视为代码的最小可能块，例如一个函数或方法。这意味着在理想情况下，每个单元应该与其他所有单元独立。

当我们执行单元测试时，我们尝试在完成每个函数或方法时进行测试，以确保我们拥有的代码在继续下一个函数或方法之前能够正常工作。

这有助于减少错误，您可能已经注意到，在开发前几章中的 JavaScript 程序时，我们以某种方式应用了单元测试的概念。每当创建一个函数时，我们尽可能地进行测试。

单元测试的一些好处包括最小化错误，以及便于变更，因为每个函数或方法都是单独在隔离环境中测试的，并且在很大程度上简化了集成。

我认为主要好处是单元测试灵活，便于文档记录。这是因为当我们编写和测试新函数时，我们可以轻松地记录下问题所在，以及代码是否能正确工作。实际上，我们是在进行逐步记录——在测试的同时记录结果。

单元测试也是集成测试的一个组成部分，尤其是在自下而上的方法中，因为我们从最小的可能单元开始测试，然后逐步测试更大的单元。例如，在我为第二章创建代码时，*JavaScript 中的即兴测试与调试*，我实际上进行了非正式的单元测试。我将每个函数视为独立的单元，并使用相关的 HTML 输入字段测试每个 JavaScript 函数，以确保得到正确的输出。这种技术可以看作是在编写新代码时执行持续集成的一部分。

持续集成是一个过程，在这个过程中，开发者频繁地集成他们的代码，以防止集成错误。这通常需要自动构建代码（包括测试）来检测集成测试。当我们创建新代码时，确保与现有代码集成非常重要，以防止出现兼容性问题或新旧错误。持续集成越来越受欢迎，因为它集成了单元测试、版本控制和构建系统。

## 网页测试

如前所述，网页测试是一种功能测试，通常指的是从用户角度测试用户界面。对于我们在这里的目的，我们将测试我们的 JavaScript 程序与 HTML 和 CSS 结合使用。

网页测试还包括不同浏览器和平台上的正确性测试。我们至少应该关注像 Internet Explorer 和 Firefox 这样的主要网络浏览器，并检查在不同浏览器下的表现和 JavaScript 程序是否正常工作。

要了解浏览器使用情况，你可能想去 [`www.w3schools.com/browsers/browsers_stats.asp`](http://www.w3schools.com/browsers/browsers_stats.asp) 查看哪些浏览器受欢迎、正在下降或正在崛起。

### 注意

看起来 Google Chrome 正在迅速增加势头，它有很大的机会成为一个受欢迎的网络浏览器；根据 w3schools 提供的统计数据，不到两年的时间，Google Chrome 的市场份额从 3.15% 增加到 14.5%。这种受欢迎程度的部分原因在于其 JavaScript 引擎性能。

网页测试的另一个主要焦点也包括检查最常用的用户行为，比如非法与合法值、登录、登出、用户错误行为、SQL、HTML 注入、HTML 链接检查、图像、机器人攻击的可能性等等。

由于 SQL、HTML 注入和机器人攻击超出了本书的范围，我们将关注其他问题，比如确保网页在不同浏览器下能够工作、检查非法与合法值、错误行为以及频繁行为等。

## 性能测试

性能测试包括负载测试、压力测试、耐力测试、隔离测试、尖峰测试等多种类型。我不会试图让你陷入细节之中。相反，我将重点关注 JavaScript 程序员可能会面临的两个更常见的问题。

首先，性能可以指客户端下载一段 JavaScript 所需的时间。你可能会认为下载时间取决于互联网连接。但有一件简单的事情你可以做，那就是压缩你的 JavaScript 代码，而不需要重构或重写它。一个很好的例子就是我们在 第三章，*语法验证* 中介绍的 JQuery 库。如果你访问 JQuery 的官方网站 [`jquery.com`](http://jquery.com)，你可能注意到了 JQuery 分为两种形式——生产版本和开发版本。生产版本是最小化的，文件大小为 24KB，而开发版本则是 155KB。显然，生产版本的文件大小更小，因此在下载 JavaScript 方面提高了性能。

### 注意

压缩你的代码——或者最小化你的代码——指的是你删除代码中所有不必要的空白和行，以减小文件大小。一些代码最小化工具会自动删除注释、替换函数、变量，甚至采用不同的编码方式。

其次，性能也可以指执行特定代码的速度，对于给定的输入量而言。通常，我们需要使用外部库或工具来帮助我们找出我们代码中相对较慢的部分，或者瓶颈所在。相关工具以及我们如何可以应用性能测试，将在第六章，*测试更复杂的代码*中介绍。

## 集成测试

集成测试是验收测试之前的测试过程中的最后一步。因为我们已经确保程序的基本构建模块作为单独的单位正确工作，我们现在需要确保它们能否一起工作。

集成测试指的是我们程序的所有不同组件的测试。不同的组件可以指的是我们迄今为止谈论的各种单元。集成测试的主要目标是确保功能、性能和可靠性要求得到满足。我们也一起测试不同的单元，看看它们是否能工作；我们需要检查在组合单元时是否有任何异常。

集成测试可以采取不同的形式，例如自顶向下和自底向上的方法。

在自顶向下的方法中，我们首先从最高级别的集成模块开始，然后是每个模块的子模块或函数。另一方面，自底向上的测试从最低级别的组件开始，然后逐步过渡到更高级别的组件。

基于我们迄今为止看到的示例代码，很难理解集成测试是如何工作的。通常，如果我们把 HTML 代码视为一个单元、CSS 作为一个单元、每个单独的 JavaScript 函数作为一个单元，我们可以看到集成测试将包括测试所有三个在一起并确保它是正确的。

在自底向上的方法中，我们从代码的基本单元开始测试。随着我们测试代码的基本单元，我们逐步测试更大单元的代码。这个过程与单元测试类似。

## 回归测试——在做出更改后重复先前的测试

回归测试专注于在程序被修改或升级时揭示程序中的错误。在现实情况下，我们倾向于对一个程序进行更改——无论是升级它、添加新功能等等。关键是，当我们对程序进行更改时，我们需要测试新组件，看看它们是否能与旧组件一起工作。

我们需要执行回归测试，因为研究和经验表明，在程序被修改时，新的或旧的错误可能会出现。例如，当添加新功能时，可能会重新引入之前修复过的旧错误，或者新功能本身可能包含影响现有功能的错误。这就是回归测试发挥作用的地方：我们执行之前的测试，以确保旧的组件仍然运行良好，并且没有旧的错误再次出现。我们用旧的组件测试新功能，以确保整个系统正常工作。有时，为了节省时间和资源，我们可能只对与旧组件结合的新功能进行测试。在这种情况下，我们可以应用影响分析来确定应用程序通过添加或修改代码的影响区域。

回归测试是最真实的部分。这是因为随着程序的增长，你更改代码的可能性很大。在你更改代码的过程中，可能会引入程序中的错误或不兼容。回归测试帮助你发现这些错误。

# 测试顺序

我们已经介绍了所需的基础知识，所以是时候了解我们应该从哪种测试开始。我们进行测试的顺序取决于我们是要实施自下而上的测试还是自上而下的测试。测试的顺序没有问题，但我个人更喜欢自下而上的测试：我通常首先从单元测试开始，然后是其他类型的测试（取决于程序的性质），最后是集成测试。

采取这种方法的主要原因是因为单元测试允许我们更早地发现代码中的错误；这防止了错误或缺陷的累积。此外，它提供了在记录测试结果方面更大的灵活性。

然而，如果你喜欢自上而下的方法，你总是可以先以最终用户的角度来测试程序。

在现实世界中，特别是在测试网络应用程序方面，很难区分（至少在概念上）自下而上的测试和自上而下的测试。这是因为尽管用户界面和编程逻辑是分开的，但我们确实需要同时测试两者，以了解它是否按照我们的预期工作。

然而，测试顺序应该以用户验收测试结束，因为最终用户是我们代码的使用者。

在下一节中，我们将向您展示如何编写测试计划。你会注意到，我们将从用户的角度进行测试。现在，是编写我们的测试计划的时候了。

# 编写你的测试计划

既然我们已经覆盖了必要的测试概念，是时候学习如何创建测试计划了。同时，我们将记录我们的测试计划；这将作为本章下一部分的依据，我们将应用测试。

## 测试计划

我们的测试计划将包含我们之前覆盖的一些概念，例如网页测试、边界测试、集成测试等。因为我们正在对第二章中使用的代码进行测试(*Ad Hoc Testing and Debugging in Javascript*)，我们知道代码是关于什么的。因此，我们可以设计我们的测试过程，使其能够包含来自黑盒测试和白盒测试的思想。

你可能想前往`源代码`文件夹并打开`sample_test_plan.doc`文件，这是我们的示例测试计划。这是一个非常简单和非正式的测试计划，只包含所需组件的最少量。如果你为自己的文档编写参考资料，使用简单的文档可以节省时间和精力。然而，如果你为客户准备测试计划，你需要一个更详细的文档。为了简单起见，我们将使用`source code`文件夹中提供的示例文档来帮助你快速理解计划过程。我将简要概述我们的测试计划的组件，同时，我将向您介绍我们测试计划的主要组件。

### 版本控制

在第一个组件中，你会注意到有一个版本表，记录了测试计划的变化。在现实世界中，计划会变化，因此，跟踪已经变化的事情是一个好习惯。

### 注意

另一种使版本控制更容易维护的方法是使用版本控制软件，如 Git 或 BitBucket。这样的版本工具记录了你代码中的变化；这将使你能够追踪你所做的变化，这使得创建测试计划变得容易得多。你可以访问[`git-scm.com/`](http://git-scm.com/)了解更多信息关于 Git，以及[`bitbucket.org/`](http://bitbucket.org/)了解关于 BitBucket 的信息。

### 测试策略

下一个重要的组成部分是你应该注意的测试策略。测试策略表示我们将用于测试计划的主要思想和想法。你会看到我们同时采用了白盒测试和黑盒测试，以及单元测试和集成测试。由于我们的 JavaScript 程序是基于网络的，我们隐式地执行了一种网页测试，尽管这在章节的后续部分没有提到。对于测试的每个阶段，我们将决定所需的测试值。另外，如果你查看`sample_test_plan.doc`，你会发现我添加了，以预期值的简短描述形式，每个测试部分的结果或响应。

#### 通过白盒测试测试预期和可接受值

我们将要做的第一件事是使用单元测试进行白盒测试。由于我们对代码和用户界面（HTML 和 CSS 代码）有深入的了解，我们将把测试应用到用户界面级别。这意味着我们将通过输入我们已经决定的各个测试值来测试程序。

在此例中，我们将像在第二章*JavaScript 中的即兴测试和调试*和第三章*语法验证*中一样使用程序，看看程序是否如我们所预期的那样工作。我们将在此处使用预期和可接受的数据值。

输入将是程序要求我们输入的内容—对于需要我们输入姓名、出生地等内容的输入字段，我们将向其输入字符。需要数字作为输入的输入字段，如年龄、我们希望退休的年龄、薪水、开支等，我们将输入数字。

输入的详细信息如下（输入值仅为演示目的）：

| 输入字段 | 输入值（案例 1） | 输入值（案例 2） |
| --- | --- | --- |
| ---- | ---- | ---- |
| 姓名 | Johnny Boy | Billy Boy |
| 出生地 | 旧金山 | 旧金山 |
| 年龄 | 25 | 25 |
| 每月开支 | 1000 | 1000 |
| 每月薪水 | 100000 | 2000 |
| 你希望退休的年龄 | 55 | 55 |
| 到退休年龄我想要的钱 | 1000000 | 1000000 |

对于每个输入值，我们期望相应的输入字段在屏幕中间、**响应**标题下动态创建，同时，原始输入字段将被禁用。这被称为测试的预期输出、结果或响应。这对于第一个表单的其余输入字段也是如此。动态创建的字段的示例如下所示：

![通过白盒测试测试预期和可接受值](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_04_01.jpg)

请注意，在屏幕中间，在**响应**标题下，有两个输入字段。这些输入字段是动态创建的。

#### 通过黑盒测试测试预期和不可接受值

我们将要做的第二件事是使用边界值测试进行黑盒测试。这个测试分为两部分：首先，我们将测试程序的边界值，以查看输出是否正确。输入与白盒测试中使用的输入类似，不同之处在于我们将每个输入使用异常大的数字或异常大的字符长度。我们还将单个数字和单个字符作为输入的一部分。每个输入的输出应与白盒测试中看到的输出相似。

更具体地说，我们将使用以下测试值（请注意，这些测试值仅用于演示目的；当你创建你的程序时，你必须决定应该使用哪些合适的边界值）：

| 输入字段 | 最小值 | 常见值 | 最大值 | 注释 |
| --- | --- | --- | --- | --- |
| 姓名 | 一个字符，例如'a' | Eugene | 一个非常长的字符串，不超过 255 个字符。 | 值的范围（X）：一个字符 1 <= X <= 255 个字符 |
| 出生地 | 一个字符，例如 a | 纽约市 | 一个非常长的字符串，不超过 255 个字符。 | 值的范围（X）：一个字符 1 <= X <= 255 个字符 |
| 年龄 | 1 | 25 | 不会超过 200 岁 | 值的范围（X）：1 <= X <= 200 |
| 每月支出 | 1 | 2000 | 1000000000 | 值的范围（X）：1 <= X <= 1000000000 |
| 每月工资 | 2 | 5000 | 1000000000 | 注意到我们假设用户挣得比花得多。值的范围（X）：1 <= X <= 1000000000 |
| 你希望在退休时的年龄 | 这个年龄应该大于现在的年龄 | 这个年龄应该大于现在的年龄 | 这个年龄应该大于现在的年龄 | 值的范围（X）：1 <= X <= 200 |
| 到退休年龄时我想要的钱 | 我们将使用 1 这里 | 一个合适的数字，比如 1000000 | 不会超过一万亿美元 | 值的范围（X）：1 <= X <= 1000000000 |

如果你参考了`sample test`文档，你就会发现我为每个输入字段提供了一个测试值的样本范围。

### 注意

记住我们之前提到等价划分了吗？在实际操作中，给定一个边界值，我们会测试与给定测试值相关的三个值。例如，如果我们想测试一个边界值'50'，那么我们会测试 49、50 和 51。然而为了简化，我们只会测试预期的值。这是因为下一章我们将对给定的值进行实际测试；这可能会变得重复和单调。我只是想让你知道真正的世界实践是什么。

这部分测试的第二部分是我们将测试预期的非法值。在第一种情景中，我们将使用既被接受又被拒绝的值。输入将类似于我们在白盒测试阶段所使用的值，不同的是，我们将数字作为需要数字的字段的输入，反之亦然。每次我们输入一个不被接受的值时，预期的输出是会出现一个警告框，告诉我们输入了错误的值。

具体细节，请查看以下表格：

| 输入字段 | 输入值 | 输入值案例 1 | 输入值案例 2 | 输入值案例 3 |
| --- | --- | --- | --- | --- |
| 姓名 | 数字或空值 | 1 | ~!@#$%^&*()" | 测试 |
| 出生地 | 数字或空值 | 1 | ~!@#$%^&*()" | 测试 |
| 年龄 | 字符和空值 | a | ~!@#$%^&*()" | -1 |
| 每月支出 | 字符和空值 | a | ~!@#$%^&*()" | -1 |
| 每月工资 | 字符和空值 | a | ~!@#$%^&*()" | -1 |
| 你希望在多少岁时退休 | 字符和空值 | a | ~!@#$%^&*()" | -1 |
| 我希望在退休年龄拥有多少钱 | 字符和空值 | a | ~!@#$%^&*()" | -1 |

通常情况下，对于每个预期的非法值，我们应期待我们的程序会通过一个警告框来提醒我们，告诉我们我们输入了错误类型的值。

在第二个测试场景中，我们将尝试输入非字母数字值，例如感叹号、星号等。

在第三个测试场景中，我们将测试输入字段中数字的负值。第三个测试场景的输入值如下：我们使用-1 来节省一些打字时间；所以像-100000 这样的负值没有区别。

#### 测试程序逻辑

在这一部分的测试计划中，我们将尝试测试程序逻辑。确保程序逻辑的一部分是确保输入是我们需要和想要的。然而，程序逻辑的某些方面不能仅仅通过验证输入值来保证。

例如，我们对用户有一个隐含的假设，即我们认为用户将输入一个比他当前年龄大的退休年龄。虽然这个假设在逻辑上是合理的，但用户可能根据传统假设输入值，也可能不输入。因此，我们需要通过确保退休年龄大于当前年龄来确保程序逻辑是正确的。

这个测试的输入值如下：

| 输入字段 | 第一份表单的输入值 |
| --- | --- |
| 姓名 | Johnny Boy |
| 出生地 | 旧金山 |
| 年龄 | 30 |
| 每月支出 | 1000 |
| 每月工资 | 2000 |
| 你希望在多少岁时退休 | 25 |
| 我希望在退休年龄拥有多少钱 | 1000000 |

这里需要注意的是，“你希望在多少岁时退休”的值比“年龄”的值要小。

我们应该期待我们的程序能够发现这个逻辑错误；如果它没有发现，我们需要修复我们的程序。

#### 集成测试和测试意外值

最后一个阶段是集成测试，在这个阶段中，我们测试整个程序，看它是否能协同工作，这包括第一个表单、由第一个表单派生出的第二个表单，等等。

在第一个测试场景中，我们开始时缓慢而稳定，通过测试预期和可接受的值。第一个测试场景的输入值如下（输入值仅用于演示目的）：

| 输入字段 | 输入值（情况 1） | 输入值（情况 2） | 输入值（情况 3） | 输入值（情况 4） |
| --- | --- | --- | --- | --- |
| 姓名 | Johnny Boy | Johnny Boy | Johnny Boy | Johnny boy |
| 出生地 | 旧金山 | 旧金山 | 旧金山 | 旧金山 |
| 年龄 | 25 | 25 | 25 | 25 |
| 每月支出 | 1000 | 1000 | 1000 | 1000 |
| 每月工资 | 100000 | 2000 | 2000 | 100000 |
| 希望退休的年龄 | 55 | 55 | 28 | 28 |
| 到退休年龄我想要的钱的数量 | 2000000 | 2000000 | 1000000 | 100000 |

请注意下划线的输入值。这些输入值是为了确定我们是否能根据输入得到正确的响应。例如，在输入所有值并提交动态生成的第二表单后，案例 1 和案例 3 的输入值将导致输出表明用户无法按时退休，而案例 2 和 4 的输入值将导致输出表明用户可以按时退休。

这是一个截图，展示了如果用户能够按时退休，输出会是什么样子：

![集成测试和测试意外值](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_04_02.jpg)

下一个截图展示了如果用户不能按时退休的输出：

![集成测试和测试意外值](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_04_03.jpg)

请注意两个不同案例文本的区别。

为了查看测试案例结果的详细信息，请打开`sample_test_plan.doc`文件，该文件可在本章的`source code`文件夹中找到。

现在是第二个测试场景的时间。在第二个测试场景中，我们首先填写第一个表单的值。在我们提交由动态创建的第二表单之前，我们将尝试更改值。输入值将包括我们用于白盒测试和黑盒测试的值。第一个测试场景的输入值如下：

| 输入字段 | 第一表单的输入值 | 第二表单的输入值（随机值） |
| --- | --- | --- |
| 姓名 | Johnny Boy | 25 |
| 出生地 | 旧金山 | 100 |
| 年龄 | 25 | Johnny Boy |
| 每月支出 | 1000 | 一些字符 |
| 每月工资 | 100000 | 更多字符 |
| 希望退休的年龄 | 20 | 更多信息 |
| 到退休年龄我想要的钱的数量 | 1000000 | 1000000 |

这个测试阶段的目的是测试第二表单的健壮性，这一点我们到目前为止还没有验证。如果第二表单失败，我们将需要更改我们的代码以增强我们程序的健壮性。

现在我们将进入我们测试计划的下一个部分——发现的错误或 bug。

### 错误表单

最后一个部分帮助我们记录我们找到的 bug。这个区域允许我们记录错误是什么，它们是由什么引起的，以及这些错误发生的功能或特性。通常，无论我们发现什么错误，我们都需要记录导致错误的确切功能，并评论可能的解决方案。

## 测试计划的总结

上面介绍的组件是测试计划中最重要的组件之一。通常对于测试的每个阶段，我们都明确指出了我们的测试数据和预期输出。请注意，我们使用这份文档作为一种非正式的方式提醒我们需要做哪些测试，所需的输入、预期的输出，更重要的是我们发现的缺陷。这份样本文档没有提到的是对于发现那些缺陷需要执行的操作，这将在下一章节中介绍。

# 总结

我们有效地完成了测试计划的规划过程。尽管我们的测试计划是非正式的，我们看到了如何应用各种测试概念，结合不同的测试数据值来测试我们之前章节中创建的程序。

具体来说，我们涵盖了以下主题：

+   我们首先从对软件工程关键方面的简要介绍开始。我们了解到测试发生在实现（编码）阶段之后。

+   我们已经学会了如何通过询问我们的代码应该做什么来定义测试范围，确保它做它应该做的事情，最后通过测试用户无效行为来测试。

+   接下来我们介绍了各种测试概念，如白盒测试、黑盒测试、单元测试、网页测试、性能测试、集成测试和回归测试。

+   我们还学会了我们需要从不同的方面测试我们的程序，从而增强程序的健壮性。

+   尽管这一章节中介绍的测试概念在某些方面可能有所不同，我们可以将它们归类为：测试预期但可接受的值、预期但不可接受的值和一般意义上的意外值。我们还学会了根据对编写代码的理解来测试逻辑错误。

+   最后我们规划并记录了我们的测试计划，其中包括测试过程描述、测试值、预期输出等重要的组成部分，如版本控制和缺陷表单。

尽管测试方法可以根据组织类型和应用程序类型有显著不同，但这里列出的一些方法通常更适合轻量级的网页应用。然而，这些概念也是构建大规模、复杂的网页应用的基础。

这一章节标志着测试计划工作的结束。现在请准备好，我们将继续进入下一章节，在那里我们将执行测试计划。


# 第五章：将测试计划付诸行动

> 欢迎来到第五章。这一章相当直接；我们基本上把在第四章，计划测试中讨论的计划付诸行动。
> 
> 我们将如何实施我们的测试计划的步骤如下：首先开始测试预期和可接受的值，接着测试预期但不可接受的值。接下来，我们将测试程序的逻辑。最后，我们将执行集成测试和测试意外值或行为。

除了执行上述测试之外，我们还将在本章涵盖以下内容：

+   回归测试实战—你将学习如何通过修复 bug 然后再次测试你的程序来执行回归测试

+   客户端测试与服务器端测试的区别

+   如何使用 Ajax 对测试产生影响

+   当测试返回错误结果时该怎么办

+   如果访客关闭了 JavaScript 会发生什么

+   如何通过压缩你的 JavaScript 代码来提高性能

那么让我们动手开始测试吧。

# 应用测试计划：按顺序运行你的测试

在本节中，我们将简单地将测试计划应用于我们的程序。为了简单起见，我们将记录任何在上一节中提供的示例测试计划中的缺陷或错误。除此之外，在每次测试结束时，我们将在`sample_text_plan.doc`中记录一个通过或失败的文本，我们是在上一章中创建的。然而，请注意，在现实世界中（尤其是如果你为你的客户做一个定制的项目），记录结果非常重要，即使你的测试是正确的。这是因为，很多时候，产生正确的测试结果是向客户交付代码的一部分。

顺便提醒一下—我们即将使用的测试计划是在上一章创建的。你可以在第四章的`source code`文件夹中找到测试计划，文件名为`sample_test_plan.doc`。如果你急于想看一个完整的测试计划，其中已经执行了所有测试，请前往第五章的`source code`文件夹，并打开`sample-testplan-bug-form-filled.doc`。

如果你不想翻页或打开电脑只是为了查看测试列表，测试列表如下：

+   测试用例 1

    +   测试用例 1a：白盒测试

    +   测试用例 1b：黑盒测试

        +   测试用例 1bi：边界值测试

        +   测试用例 1bii：测试非法值

+   测试用例 2：测试程序的逻辑

+   测试用例 3：集成测试

    +   测试用例 3a：使用预期值测试整个程序

    +   测试用例 3b：测试第二个表单的健壮性。

带着这个想法，让我们开始第一次测试。

## 测试用例 1：测试预期和可接受的值

测试预期和可接受值指的是白盒测试阶段。我们现在将按照计划执行测试（这是第一个测试场景）。

# 行动时间—测试案例 1a：通过白盒测试测试预期和可接受值

在此部分，我们将通过使用在规划阶段预先确定的值来开始我们的测试。您在本章节中使用的源代码是`perfect-code-for-jslint.html`，该代码可在第三章的`source code`文件夹中找到。我们在此将输入预期的和可接受的数据值。我们将从使用输入值案例 1 的输入值开始测试，正如我们的示例测试文档所规划的那样。

1.  用您最喜欢的网络浏览器打开源代码。

1.  当您在网络浏览器中打开您的程序时，焦点应该在第一个输入字段上。按照我们的计划输入名字**Johnny Boy**。在您在第一个输入字段中输入**Johnny Boy**后，继续下一个字段。

    当您将焦点转移到下一个字段时，您会在原始输入字段的右侧看到一个新的输入字段出现。如果出现这种情况，那么您为第一个输入收到了正确和预期的输出。如果您不理解这意味着什么，请随时参考第四章，*测试计划*，并查看给出的预期输出的屏幕截图。

1.  对于第二个输入，我们需要输入出生地。按照计划输入**旧金山**。点击（或使用标签）转到下一个字段。

    与第一个输入字段类似，在您移动到下一个字段后，您会看到一个包含您输入值的新输入字段。这意味着您此刻已经有了正确的输出。

1.  这个步骤与上述步骤类似，不同之处在于输入值现在是一个数字。输入您的年龄**25**。然后继续到下一个字段。您还应该在右侧看到一个新的输入字段。

1.  现在，请对左侧表单的剩余字段重复上述步骤。重复此操作，直到您在屏幕中间看到一个**提交**按钮。

    如果为您的每个输入动态创建了一个新的输入字段，并且每个动态创建的新输入字段都包含您输入的确切内容，那么您就得到了正确的输出。如果不是这样，测试失败。然而，根据我们的测试，我们得到了正确的输出。

1.  现在，在您的浏览器中刷新页面，并为在输入值案例 2 中找到的输入值重复测试。您也应该收到正确的输出。

    假设两个测试案例都产生了正确的输出，那么恭喜你，在这个测试阶段没有发现任何错误或 bug。这个部分的测试并没有什么特别或繁琐的地方，因为我们已经知道，基于我们的输入，我们会收到预期的输出。现在，我们将进行更加令人兴奋的测试——测试预期但不可接受的数据。

## 测试用例 1b：使用黑盒测试测试预期但不可接受的值

在这个部分，你将继续执行我们的测试计划。随着测试的进行，你会发现我们的程序还不够健壮，存在一些固有错误。你会了解到，你需要记录下这些信息；这些信息将在我们调试程序时使用（这是第二个测试场景）。

# 行动时间——测试用例 1bi：使用边界值测试测试预期但不可接受的值

在这个测试部分，我们将继续使用前一部分相同的源代码。我们将开始进行边界值测试。因此，我们将首先使用“最小值”，然后是“最大值”进行测试。我们将跳过常见值测试用例，因为那与之前的测试相似。

1.  再次刷新你的网页浏览器。

1.  首先，为**姓名**输入字段输入一个字符**a**。输入值后，用鼠标点击下一个输入字段。你应该看到在第一个输入字段的右侧动态创建了一个输入字段，与之前的测试一样。

    这个测试的输出与你在前一个测试中看到和经历的情况类似。我们试图测试的是程序是否接受一个最小值。在这个测试阶段，我们天真地选择接受一个字符作为可接受的输入。因为这是可接受的，我们应该看到一个动态生成的值出现在原始输入字段的右侧。如果你看到了这个，那么你得到了正确的输出。

1.  同样，为**出生地**输入字段输入一个字符**a**。输入值后，用鼠标点击下一个输入字段。你会看到在第一个输入字段的右侧动态创建了一个输入字段，正如之前的测试所看到的那样。

    你应该对这个输入值也收到正确的输出。现在让我们继续下一个输入值。

1.  现在，我们将按计划为输入字段年龄输入数字 1。同样，输入值后，将焦点移动到下一个输入字段。

1.  我们将按照计划重复进行测试。

    在此阶段的测试中，我们通常不应该收到任何错误。与之前进行的第一次测试类似，我们应该对每个输入都看到熟悉的输出。然而，我想指出这个测试阶段的一个重要点：

    我们天真地选择了一个可能不切实际的最小值。考虑一下接受单个字符值的各个输入字段。在很大程度上，我们的原始程序逻辑似乎并不适合实际世界的情况。通常，我们应该期望对于接受字符值的输入字段至少有两个或三个字符。因此，我们将此视为程序中的一个错误，并在我们的“错误报告表”上记录这一点。您可以打开`sample-testplan-bug-form-filled.doc`文件，看看我们如何记录这个缺陷。

    既然我们已经通过了最小值测试用例，现在是时候转到下一个测试用例——最大值。

1.  像往常一样，刷新您的网页浏览器以清除之前输入的所有值。我们现在将开始输入超过 255 个字符的极长字符串。

    正如早前所解释的，我们还应该收到类似的输出——一个动态生成的输入字段，其中包含我们的输入值。

1.  同样，使用长字符串或大数值为剩余的输入字段输入值。你不应该遇到任何错误。

    虽然我们没有明显的错误，但您可能已经注意到我们遇到了之前经历过的类似问题。我们的程序也没有最大值边界值。看起来如果你尝试输入大于最大值的价值，程序仍然会接受它们，只要这些值不是非法的。同样，如果你尝试输入超过 200 个字符的字符串，程序仍然会接受它，因为它是一个合法值。这意味着我们的程序没有限制用户可以输入的最大字符数。这可以被视为一个错误。我们将在“错误报告表”中记录这个编程错误。您可能想去看看我们是如何记录这个错误的。既然我们已经完成了预期和不可接受值的第一阶段测试，现在是时候进行这个测试的第二阶段——测试预期非法值。

# 行动时间——测试用例 1bii：使用非法值测试期望但不可接受的价值

此阶段的测试有三种输入情况。在测试的第一个情况中，我们将为需要字符输入的输入字段输入数值，反之亦然。

#### 输入用例 1：

1.  我们将再次刷新浏览器以清除旧的值。接下来，我们开始输入预期的非法值。对于“name”输入字段，我们将输入一个数字。这可以是任何数字，比如“1”。继续测试。在您输入数字后，尝试将鼠标光标移动到下一个输入字段。

    当你试图将焦点移到下一个输入字段时，你应该看到一个警告框，告诉你输入了错误的类型值。如果按照我们的测试计划看到警告框，那么此刻就没有错误。

1.  为了测试下一个字段，我们需要在继续之前输入第一个字段的正确值。另一种方法是刷新浏览器并直接跳到第二个字段。假设您使用第一种方法，让我们输入一个假设的名字，**史蒂夫·乔布斯**，然后继续输入下一个字段。同样，我们尝试为**出生地**输入一个数字。在您为输入字段输入数字后，尝试移动到下一个字段。

    再次，您将看到一个警告框，告诉您您输入了无效的输入，需要输入文本输入。到目前为止还不错；没有错误或错误，我们可以继续到下一个字段。

1.  我们需要刷新浏览器并直接跳到第三个字段，或者我们需要在继续到第三个字段之前为**姓名**和**出生地**字段输入有效值。无论使用哪种方法，我们将尝试为**年龄**字段输入字符串。完成此操作后，尝试移动到下一个输入字段。

    您将再次收到警告框，告诉您您输入了错误的类型。这是按照计划，也是预期的。因此，还没有错误或错误。

1.  对剩下的字段重复上述步骤，在输入预期但非法值时尝试移动到下一个字段。

    对于所有剩余的字段，您应该收到警告框，告诉您您输入了错误的类型，这是我们期望和计划的内容。

#### 输入案例 2：

既然我们已经完成了第一个测试场景，是时候进行第二个测试场景了，在那里我们尝试输入非字母数字值。

1.  测试过程与第一个测试相当相似。我们首先刷新浏览器，然后立即为第一个输入字段输入非字母数字值——**姓名**输入字段。按照我们的计划，我们将输入**~!@#$%^&*()**作为输入，然后尝试移动到下一个输入字段。

    对于第一个输入字段，需要字符输入，您应该看到一个警告框，告诉您只能输入文本。如果您看到这个，那么我们的程序按计划工作。现在让我们进行下一步。

1.  对于下一个输入字段，我们将重复上一步，我们期望得到相同的输出。

1.  现在，对于第三个输入字段，我们继续输入相同的非字母数字输入值。预计这一步的区别只是警告，它告诉我们我们输入了错误的输入，会告诉我们需要输入数字而不是文本。

1.  我们对剩余的字段重复上述步骤，通常我们应该期望看到一个警告框，告诉我们需要输入文本或数字，这取决于哪个输入字段。如果是这样，那么一切顺利；这个测试场景中没有相关的错误或错误。

#### 输入案例 3：

现在是我们执行第三个测试场景的时候，我们在需要数字输入的输入字段中输入负值。

1.  再次，我们将刷新浏览器以清除旧值。我们将按计划输入前两个输入字段。我们将输入**Johnny Boy**和**San Francisco**作为**姓名**和**出生地**的输入字段。

1.  完成上一个步骤后，输入剩余字段的**-1**。当你为这些字段输入**-1**时，你应该看到我们的程序没有检测到负值。相反，它给出了一个错误的响应，告诉我们应该输入数字。

    实际上，我们的程序应该足够健壮，能够识别负值。然而，如前述测试所示，我们的程序对非法值似乎有错误的响应。我们的程序确实发现了错误，但它返回了一个错误的响应。给出的响应是一个警告框，告诉您输入必须是数字。这在技术上是错误的，因为我们的输入是一个数字，尽管是一个负数。

    这意味着我们的程序确实发现了负值，但它返回了一个错误的响应。这意味着我们这里有一个严重的错误。我们需要在我们的样本文档中注意这个错误，通过在“错误报告表单”上记录这个错误来 document this error。你可以看看我在`sample test plan`文档中是如何记录这个的。

    哇！这个小节有点长和无聊。没错，测试可以是无聊的，到现在你应该看到我们在这个部分测试的问题都会包含在一个好的程序设计中。你会注意到，至少对我们在这里的目的来说，检查输入值以确保输入是我们需要的，对我们程序的成功是基本的；如果输入值错误，测试剩下的程序就没有意义，因为我们几乎可以确定会因为错误的输入而得到错误的输出。

## 测试用例 2：测试程序逻辑

在本小节中，我们将尝试在程序逻辑方面测试程序的健壮性。虽然我们已经通过确保输入正确 somewhat 测试了程序逻辑，但根据我们的测试计划，还有一方面我们需要测试，那就是现在的年龄和退休年龄。

# 行动时间——测试程序逻辑

通常，我们将尝试输入一个比当前年龄小的退休年龄。现在让我们测试程序的健壮性：

1.  让我们刷新浏览器，然后按照我们的计划输入值。首先输入**Johnny Boy**，然后输入**San Francisco**作为**姓名**和**出生地**的输入字段。

1.  现在，请注意这个步骤：我们将现在输入**30**作为**年龄**，并继续其他字段。

1.  当你到达**希望退休的年龄**输入字段时，你将想输入一个小于**年龄**字段的值。根据我们的测试计划，我们将输入**25**。之后，我们将尝试移动到下一个字段。

    因为我们成功移动到了下一个字段，这意味着我们的程序还不够健壮。我们的程序不应该接受小于当前年龄值的退休年龄值。因此，即使我们的程序确实产生了最终结果，我们也可以确定输出不是我们想要的，因为逻辑已经是错误的。

    因此，我们需要注意在这个测试阶段发现的逻辑错误。我们再次在错误报告表上记录这个错误。现在我们将进行我们测试的最后阶段。

## 测试案例 3：集成测试和测试意外值

我们已经完成了测试的最后阶段。在这一小节中，我们将先使用预期和可接受值测试整个程序，然后通过更改第二个表单的值来中断表单提交流程。

# 行动时间——测试案例 3a：使用预期值测试整个程序

第一组测试共有四组数据。通常情况下，我们会输入所有的值，然后提交表单，看看我们是否能得到预期的响应：输入案例 1 和输入案例 3 的输入值将导致输出显示用户无法按时退休，而输入案例 2 和输入案例 4 的输入值将导致输出显示用户将能够按时退休。有了这个想法，让我们从第一组输入值开始：

1.  回到你的网页浏览器，刷新你的程序，或者如果你关闭了程序，重新打开源代码。我们按照计划输入值：**Johnny Boy** 和 **San Francisco** 作为**姓名**和**出生地**。

1.  接下来，我们将输入**25**作为**年龄**，然后输入**1000**作为**每月支出**。我们将重复这些步骤，直到我们在第二个表单上看到动态生成的**提交**按钮。

1.  一旦你看到**提交**按钮，点击按钮提交值。你应该在**最终响应**框中看到一些文本被生成。如果你看到输出包含姓名、退休年龄、退休所需金额的正确输出值，更重要的是，响应**你将在 55 岁时退休**，如下面的屏幕截图所示，那么程序中没有错误！![行动时间—测试案例 3a：使用预期值测试整个程序](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_05_01.jpg)

1.  现在让我们继续输入案例 2 的值。同样，我们将刷新浏览器，然后开始输入所有计划中的值。

1.  当你看到动态创建的**提交**按钮时，点击该按钮以提交表单。在这个测试案例中，你会看到用户将**无法按时退休**，如下面的屏幕截图所示:![行动时间—测试用例 3a：使用预期值测试整个程序](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_05_02.jpg)

    如果你收到前一张截图中的输出，那么到目前为止没有错误。所以让我们继续第三种情况的输入值。

1.  再次刷新你的浏览器，然后按照计划开始输入值。需要注意的值包括**每月工资**和**你想退休的年龄**。通常，我们已经设定了这些值，以测试我们是否能够创建输出，以便能够按时退休或不按时退休。

1.  继续输入值，直到你看到动态生成的**提交**按钮。点击**提交**按钮以提交表单。你会看到如下截图所示的输出:![行动时间—测试用例 3a：使用预期值测试整个程序](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_05_03.jpg)

    如果你收到了之前的输出，那么到目前为止没有错误或故障。

1.  现在，让我们进入最后一个案例——案例 4。我们基本上会重复之前的步骤。我只需要你注意**每月工资**的输入值。注意输入值是**100000**，退休年龄没有改变。我们试图模拟用户能够按时退休的情况。

1.  继续输入值，直到你看到动态生成的**提交**按钮。点击**提交**按钮以提交表单。你会看到如下截图所示的输出:![行动时间—测试用例 3a：使用预期值测试整个程序](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_05_04.jpg)

+   再次，如果你收到了前一张截图中的输出，那么你已经收到了正确的输出。有了这一点，我们已经完成了这个测试阶段的 第一部分。

    通常，我们已经测试了整个程序，以查看我们是否得到了预期的输出。我们使用了不同的值生成了两种可能的输出：能够按时退休或无法按时退休。我们不仅已经收到了正确的输出，我们还测试了在计算结果方面的函数的健壮性。

    考虑到之前的因素，是时候进入测试的第二阶段了——测试第二个表单的健壮性。

# 行动时间—测试用例 3b：测试第二个表单的健壮性

如果你从第一章就开始跟随我，你可能会注意到我们只是禁用了左侧表单的输入字段，而没有禁用右侧的输入字段。除了故意这样做以向您展示 JavaScript 编程的不同方面外，我们还设置它可以向我们展示集成测试的其他方面。所以现在，我们将尝试更改动态生成的表单的值看看会发生什么。

1.  首先刷新浏览器，然后按照计划开始输入输入值。在您输入完所有值之后，根据测试计划更改第二表单中的值。

1.  现在，提交表单，您将看到如下截图的输出：![行动时间—测试用例 3b：测试第二个表单的健壮性](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-test-bgd/img/0004_05_05.jpg)

+   哎呀！显然，我们的程序有一个致命的缺陷。我们的第二个表单没有检查机制，或者说是没有。第二个表单在我们的用户可能想要更改值的情况下存在。从一开始，我们天真地选择相信用户会在第二个表单上输入合法和可接受的值，如果他们选择更改输入。现在我们知道这可能不是事实，我们在“缺陷报告表”上记录这一点。

## 刚才发生了什么？

通常，我们已经执行了整个测试计划。在这个过程中，我们发现了一些后来要修复的错误。您可能会觉得步骤重复；这是真的，测试有时会重复。但是幸运的是，我们的程序相当小，因此测试它是可以管理的。

现在我们已经完成了测试，是时候考虑我们如何处理那些错误了。我们将在下一部分开始讨论这个问题。

## 当测试返回意外结果时应该做什么

通常，当测试返回意外或错误的结果时，意味着我们的程序中有一个错误或缺陷。根据我们的测试，您肯定已经注意到我们的程序中有薄弱环节。导致测试返回意外结果的薄弱环节或错误如下：

+   我们的程序不支持负值

+   我们编写的代码不支持边界值（最大和最小值）。

+   第二个表单不检查输入值的正确性；如果我们更改第二个表单中的任何值，程序就会失败。

这些观点意味着我们的代码不够健壮，我们需要修复它；我们将在下一节立即进行。

# 回归测试在行动

在本节中，我们将通过执行回归测试来亲自动手。我们将尝试通过编写修复我们最初应用测试计划时找到的错误的代码来模拟需要回归测试的情况。编写代码后，我们首先测试编写的代码，然后测试整个应用程序以查看它是否协同工作。

# 行动时间——修复错误并进行回归测试

我们将逐一修复我们发现的每个错误。我们将从编写一个允许我们的程序支持边界值的函数开始。修复所有错误的完整源代码在`source code`文件夹的第五章中，文件名为`perfect-code-for-JSLInt-enhanced.html`。

在我们开始第一个错误的实际编码过程之前，让我们考虑一下我们可以做什么来支持边界值。

首先，如果我们回到我们的示例测试计划，你会注意到在我们的“Bug 报告表单”中，我们已经记录了我们可以尝试更改检查表单输入的函数，使其可以检查最小和最大值。为了简单起见，我们将通过检查输入的长度来启用边界值。例如，“Neo”意味着有三个输入字符，“1000”将有四个数字输入字符。

其次，因为第一个表单的输入检查是在`submitValues()`中完成的，我们将尝试添加这个函数所需的检查机制。有了这个想法，我们可以开始编码过程：

1.  打开我们在第三章，*语法验证*中编写的原始源代码，在你的最喜欢的源代码编辑器中，寻找`submitValues()`函数。接下来，在`debuggingMessages()`函数之后添加以下代码：

    ```js
    // this is the solution for checking the length of the input
    // this will allow us to enable boundary values
    // starting with minimum values: we will accept character
    // length of more than or equal than 3
    // and less than 100 characters
    if (elementObj.name === 'enterText') {
    if (elementObj.value.length <= 3) {
    alertMessage("Input must be more than 3 characters!");
    var element = document.getElementById(elementObj.id);
    jQuery(element).focus(); 
    return true;
    }
    if (elementObj.value.length >= 100) {
    alertMessage("Input must be less than 100 characters!");
    var element = document.getElementById(elementObj.id);
    jQuery(element).focus();
    return true;;
    }
    }
    // now for checking the maximum value of digits
    // upper boundary is set at 10 digits
    if (elementObj.name === 'enterNumber') {
    if (elementObj.value.length >= 10) {
    alertMessage("Input must be less than 10 digits!");
    var element = document.getElementById(elementObj.id);
    jQuery(element).focus();
    return true;
    }
    }

    ```

    在之前的代码中发生的事情是我们添加了一些`if`语句。这些语句通过`.name`属性检查输入的类型，然后检查它是否大于最小输入或小于最大输出。我们设置了一个最小输入长度为三个字符和一个最大输入长度小于 100 个字符的文本输入。对于需要数字输入的输入，我们设置了最大输入长度为 10 位数字。由于用户可能没有收入，我们没有设置最小输入长度。

1.  保存你的文件并测试程序。尝试输入少于三个字符或超过 100 个字符。你应该会收到一个警告框，显示你的输入过大或过小。同样，测试需要数字输入的输入字段，并查看程序是否检测到超过 10 位数字的输入长度。如果你为每个不同情况收到了正确的警告框，那么你已经修复了错误。

    现在我们已经修复了与边界值有关的问题，是时候继续处理我们在“Bug 报告表单”上记录的下一个错误了，这是我们在`sample-testplan-bug-form-filled.doc`中发现的第三个错误（错误编号 3），它与负值有关。

    错误在于，我们的程序将负数输入视为非数字值，并产生错误的输出信息，提示输入必须是数字。因此，在这种情况下，我们需要通过追溯到问题的源头——负责检查输入的函数来修复这个错误。

    请注意，检查输入的函数是`submitValues()`。现在，让我们进入实际的编程过程：

1.  回到你的源代码，从`submitValues()`函数开始。我们需要一个检查负数输入的机制，并返回正确的输出，提示**输入必须是正数**。所以我们可以这样做：

    ```js
    // this is the solution for checking negative values
    // this only applies to input fields that requires numeric inputs
    if (elementObj.name === 'enterNumber') {
    if (elementObj.value < 0) {
    alertMessage("("Input must be positive!");
    var element = document.getElementById(elementObj.id);
    jQuery(element).focus(); 
    return true;
    }
    }

    ```

    通过添加上述代码，你将能够检查负值。上述代码应放置在`submitValues()`函数中，在检查输入长度的`if`语句之前。

1.  保存你的程序并测试它。在遇到需要数字输入的表单字段时，尝试输入一个负值，比如**-1**。如果你收到一个警告框，提示**输入必须是正数**，那么我们就做对了。

    `submitValues()`的代码应该包括以下行：

    ```js
    function submitValues(elementObj) {
    // code above omitted
    // this is the solution for checking negative values
    // this only applies to input fields that requires numeric inputs
    if (elementObj.name === 'enterNumber') {
    if (elementObj.value < 0) {
    alertMessage("Input must be positive!");
    var element = document.getElementById(elementObj.id);
    jQuery(element).focus();
    return false;
    }
    }
    // code below is omitted
    }

    ```

    上述片段中的行是我们在这个小节中添加的。因为我们已经确保了我们的频率相同，所以我们可以继续讨论第四个错误（我们`sample_test_plan.doc`中的第 4 个 bug）。这个错误与程序逻辑有关。

    本章开始时，我们发现程序没有检测到退休年龄可能小于用户当前年龄的情况。这对我们的程序可能是致命的。因此，我们需要添加一个确保退休年龄大于用户当前年龄的机制。

    因为问题在于输入的检查，我们需要关注`submitValues()`。

1.  让我们回到源代码，在`submitValues()`中添加以下代码：

    ```js
    // this is to make sure that the retirement age is larger than present age
    if (elementObj.id === 'retire') {
    if (elementObj.value < document.getElementById('age').value) {
    alertMessage('Retirement age must be higher than age');
    var element = document.getElementById(elementObj.id);
    jQuery(element).focus();
    return false;
    }
    }

    ```

    你应该在这段代码之前输入上述代码。

    现在，测试你的代码。尝试输入一个小于当前年龄的退休年龄。你应该会收到一个警告消息，提示退休年龄必须大于年龄。

    如果你收到了这个警告，那么恭喜你，你做对了！再次总结这个部分，以确保我们意见一致，`submitValues()`应该包括以下所示的代码行：

    ```js
    function submitValues(elementObj) {
    // code above omitted
    // this is to make sure that the retirement age is larger than present age
    if (elementObj.id === 'retire') {
    if (elementObj.value < document.getElementById('age').value){
    alertMessage('retirement age must be larger than age');
    var element = document.getElementById(elementObj.id);
    jQuery(element).focus();
    return true;
    }
    }
    // code below omitted
    }

    ```

    现在让我们继续讨论通过检查第二个表单发现的最后一个错误（我们`sample-testplan-bug-form-filled.doc`中的第 5 个 bug）。

    我们已经创建了一个 JavaScript 程序，这样当我们为每个输入字段输入值时，会动态创建一个新的输入字段。这意味着在所有输入字段都完成后，会创建一个新的表单。你可能没有注意到，新创建的输入字段允许用户更改它们的值。

    这里的问题在于，用户可能会在新表单中更改输入值，这可能会导致致命错误，因为我们没有检查机制来检查第二表单中的值。所以，我们天真地选择相信用户会相应地行动，只输入有效的值。但显然，我们错了。

    因此，为了检查第二表单，我们很可能需要创建一个新的函数来检查第二表单。

    尽管第二表单是动态生成的，但我们可以通过到目前为止学到的方法获取这些字段内的值。记住，因为 JavaScript 在第二表单中创建了字段，这些字段在技术上存在于内存中，因此仍然可以访问。

    有了这个想法，我们需要创建一个适用于这些字段的函数。

1.  打开源代码，滚动到最后一个使用 jQuery 语句的函数。在这个函数之前，创建以下函数：

    ```js
    function checkSecondForm(elementObj) {
    // some code going here
    }

    ```

1.  首先，开始检查空值。因此，我们可以这样做来检查空值：

    ```js
    if(document.testFormResponse.nameOfPerson.value === "") {
    alertMessage("fields must be filled!");
    return false;
    }
    if(document.testFormResponse.birth.value === "") {
    alertMessage("fields must be filled!");
    return false;
    }
    if(document.testFormResponse.age.value === "") {
    alertMessage("fields must be filled!");
    return false;
    }
    if(document.testFormResponse.spending.value === "") {
    alertMessage("fields must be filled!");
    return false;
    }
    if(document.testFormResponse.salary.value === "") {
    alertMessage("fields must be filled!");
    return false;
    }
    if(document.testFormResponse.retire.value === "") {
    alertMessage("fields must be filled!");
    return false;
    }
    if(document.testFormResponse.retirementMoney.value === "") {
    alertMessage("fields must be filled!");
    return false;
    }

    ```

    通常，我们应用第三章中学到的知识，使用`===`而不是`==`来检查空值。我们基本上检查在动态生成的字段中找到的值，并检查它们是否为空。

    现在我们已经有了检查字段是否为空的代码，是时候编写检查输入正确类型的代码了。

1.  我们可以应用在第三章中学到的技术*语法验证*来检查输入的正确性。通常，我们使用正则表达式，像前几章一样，来检查输入的类型。我们可以这样做：

    ```js
    var charactersForName = /^[a-zA-Z\s]*$/.test(document.testFormResponse.nameOfPerson.value);
    var charactersForPlaceOfBirth = /^[a-zA-Z\s]*$/.test(document.testFormResponse.birth.value);
    var digitsForAge = /^\d+$/.test(document.testFormResponse.age.value);
    var digitsForSpending = /^\d+$/.test(document.testFormResponse.spending.value);
    var digitsForSalary = /^\d+$/.test(document.testFormResponse.salary.value);
    var digitsForRetire = /^\d+$/.test(document.testFormResponse.retire.value);
    var digitsForRetirementMoney = /^\d+$/.test(document.testFormResponse.retirementMoney.value);
    // input is not relevant; we need a digit for input elements with name "enterNumber"
    if (charactersForName === false || charactersForPlaceOfBirth === false) {
    alertMessage("the input must be characters only!");
    debuggingMessages( checkSecondForm", elementObj, "wrong input");
    return false;
    }
    else if (digitsForAge === false || digitsForSpending === false || digitsForSalary === false || digitsForRetire === false || digitsForRetirementMoney === false ){
    alertMessage("the input must be digits only!");
    debuggingMessages( checkSecondForm", elementObj, "wrong input");
    return false;
    }
    // theinput seems to have no problem, so we'll process the input
    else {
    checkForm(elementObj);
    alert("all is fine");
    return false;
    }

    ```

    要查看完整版本的先前代码，请查看*第五章*的`source code`文件夹，并参考`perfect-code-for-JSLInt-enhanced.html`文件。

    然而，记住，在早期的调试会话中，我们已经创建了新的检查机制，以支持边界值、防止负值，并确保退休年龄大于用户的当前年龄。

    因为第二表单可能会被更改，之前的错误也可能在第二表单中发生。因此，我们还需要添加那些检查机制。为了看看你是否做得正确，请查看`source code`文件夹中名为`perfect-code-for-JSLInt-enhanced.html`的文件中的`checkSecondCode()`函数。以下是`checkSecondCode()`的代码片段：

    ```js
    // above code omitted
    if (elementObj.id === 'retire') {
    if (elementObj.value < document.getElementById('age').value) {
    alertMessage('retirement age must be larger than age');
    var element = document.getElementById(elementObj.id);
    jQuery(element).focus();
    return true;
    }
    }
    // this is the solution for checking negative values
    // this only applies to input fields that requires numeric inputs
    if (elementObj.name === 'enterNumber') {
    if (elementObj.value < 0) {
    alertMessage("Input must be positive!");
    var element = document.getElementById(elementObj.id);
    jQuery(element).focus();
    return true;
    }
    }
    if (elementObj.name === 'enterText') {
    if (elementObj.value.length <= 3) {
    alertMessage("Input must be more than 3 characters!");
    var element = document.getElementById(elementObj.id);
    jQuery(element).focus(); 
    return true;
    }
    if (elementObj.value.length >= 100) {
    alertMessage("Input must be less than 100 characters!");
    var element = document.getElementById(elementObj.id);
    jQuery(element).focus(); 
    return true;
    }
    }
    if (elementObj.name === 'enterNumber') {
    if (elementObj.value.length >= 10) {
    alertMessage("Input must be less than 10 digits!");
    var element = document.getElementById(elementObj.id);
    jQuery(element).focus(); 
    return true;
    }
    }
    // remaining code omitted
    }

    ```

## 刚才发生了什么？

我们已经完成了整个测试计划，包括回归测试。注意，在编码过程的每个阶段，我们都进行了小测试，以确保我们的解决方案正确工作；我们在回归测试过程中再次使用了单元测试。

请注意，我们还测试了程序逐步；我们测试了每个新函数或我们创建的代码，并确保它正确工作，在我们修复下一个错误之前。

通过这个过程，我们将有更好的机会创建好的程序，并避免将新的错误引入我们的代码。

除了在我们程序变化的过程中进行回归测试之外，关于我们程序的测试还有其他重要的问题。让我们转到第一个重要问题——性能问题。

## 性能问题——压缩你的代码以使其加载更快

如我在第四章中提到的，*计划测试*，我们编写的代码的性能取决于各种因素。性能通常指的是你代码的执行速度；这取决于你为代码使用的算法。由于算法问题超出了本书的范围，让我们专注于更容易实现的事情，比如通过压缩你的代码来提高程序的性能。

通常，压缩你的代码后，你的代码文件大小会更小，因此降低了在执行前需要缓存存储代码的磁盘使用量。它还减少了将 JavaScript 文件从 Web 服务器传输到客户端所需的带宽。所以现在，让我们看看我们如何压缩我们的 JavaScript 代码。

我们可以采取两种方式来做这件事：

1.  我们可以压缩整个程序，这意味着我们将压缩我们的 CSS、HTML 和 JavaScript 在一起。

1.  我们可以将所有的本地 JavaScript 移到一个外部文件中，然后只压缩这个外部 JavaScript 文件。为了保持简单，我将先使用第一种方法。

首先，我想让你访问[`jscompress.com/`](http://jscompress.com/)，并将我们的源代码粘贴到输入框中。有一个选项叫做"**Minify (JSMin)**"。这个选项将会一起压缩 HTML、CSS 和 JavaScript。一旦你将代码复制到输入框中，点击**压缩 JavaScript**。

然后你会看到页面刷新，并将在输入框中显示压缩后的代码。将这段代码复制粘贴到一个新文件中，然后将其保存为`testing-compressed.html`。

如果你去到`source code`文件夹，你会注意到我已经为你完成了压缩过程。检查`testing-compressed.html`文件和我们之前编写的代码的大小。根据我们所有的源代码，压缩后的版本是 12KB，而原始版本是 18KB。

现在让我们尝试第二种方法——将所有的 JavaScript 放在一个外部的 JavaScript 文件中并压缩这个文件。我们将这样做：

1.  剪切掉`<head>`和`</head>`标签之间的所有 JavaScript，并将其粘贴到一个新的名为`external.js`的文件中。

1.  保存`external.js`，并将 HTML 文档的更改也保存下来。

1.  回到你的 HTML 文档，转到`<head>`和`</head>`标签之间，插入以下内容：`<script type="text/javascript" src="img/external.js">`。然后保存文件。

这样一来，你的代码就被压缩了，从而使得从服务器加载到客户端的速度更快。

看来我们成功地通过压缩代码来减小了文件大小。当然，由于我们的代码不多，所以区别并不明显。然而，在实际中，代码可以增加到数千甚至数万行，正如我们看到的 jQuery 库一样。在这种情况下，代码压缩将有助于提高性能。

### 注意

如果你是一个在保密协议（NDA）下工作的开发者，你可能不允许使用我之前提到的任何外部服务。如果是这种情况，你可能想考虑使用雅虎的 YUI 压缩器，它允许你直接从命令行工作。更多信息，请访问[`developer.yahoo.com/yui/compressor/#using`](http://developer.yahoo.com/yui/compressor/#using)。

## 使用 Ajax 会有所不同吗？

让我先简要解释一下使用 Ajax 时会发生什么。JavaScript 是 Ajax 方程的一部分；JavaScript 的执行负责发送信息和从服务器加载信息。这是通过使用`XMLHttpRequest`对象来实现的。

当使用 Ajax 进行发送和加载数据时，测试责任是不同的；你不仅要测试我们前面章节中涵盖的各种错误，还要测试每个错误是否导致了信息的成功发送和加载以及对用户的正确视觉响应。

然而，由于你需要和服务器之间发送和接收请求，你可能需要进行某种形式的服务器端测试。这让我们来到了话题的下一部分——JavaScript 测试与服务器端测试的区别。

## 与服务器端测试的区别

如前一部分所述，当你在进行 Ajax 测试时，可能需要进行服务器端测试。通常，到目前为止你在书中所学的概念也可以应用于服务器端测试。因此，从概念上讲，JavaScript 测试和服务器端测试之间应该没有太大区别。

然而，请注意，服务器端测试通常包括服务器端代码，并且很可能包括 MySQL、PostgreSQL 等数据库。这意味着与 JavaScript 测试相比，服务器端测试的复杂性可能会有所不同。

尽管如此，你还是需要对所使用的服务器端语言、数据库等有深入了解。这是你开始规划测试的最基本要求。

### 注意

如果你在进行 Ajax 测试的服务器端测试，你肯定想了解一下超文本传输协议（HTTP）响应状态码。这些状态码是确定你的请求是否成功的一种方式。它们甚至告诉你是否发生了任何错误。更多信息请访问：[`www.w3.org/Protocols/rfc2616/rfc2616-sec10.html`](http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html)。

## 如果访客关闭了 JavaScript 会发生什么

我们已经简要讨论了是否应该为关闭 JavaScript 的用户编写应用程序的问题。虽然关于是否应该支持这类用户存在不同的观点，但在我看来，最好的方法之一是至少告知我们的用户他们的浏览器不支持 JavaScript（或者 JavaScript 已被关闭），他们可能会错过一些内容。为了实现这一点，我们可以使用以下代码片段：

```js
<html>
<body>
<script type="text/javascript">
document.write("Your browser supports JavaScript, continue as usual!");
// do some other code as usual since JavaScript is supported
</script>
<noscript>
Sorry, your browser does not support JavaScript! You will need to enable JavaScript in order to enjoy the full functionality and benefits of the application
</noscript>
</body>
</html>

```

+   请注意，我们使用了`<noscript>`标签，这是在 JavaScript 被关闭或不被支持时显示用户的替代内容的途径。

    既然我们已经接近本章的尾声，你可能已经掌握了要领。让我们看看你是否能通过尝试以下练习来提高你的技能。

## 尝试英雄——提升我们程序的可用性

既然你已经走到了这一步，你可能想尝试这个任务——通过以下方式提升这个程序的可用性：

+   确保用户从第一个字段到最后一个字段输入所需信息。

    我们程序可能遇到的另一个问题是，用户可能会点击第一个以外的任何输入字段并开始输入信息。尽管这可能不会直接影响我们程序的正确性，但有可能结果不是我们预期的。

+   关于第二个表单，你有什么方法能告知你的用户哪些输入字段有错误的输入？用户可以更改错误的输入吗？

    当我们修复与第二个表单相关的错误时，我们只是创建了检测第二个表单输入正确性的机制。然而，如果用户在第二个表单中输入了错误的值，用户可能不会立即知道哪些字段输入错误。

以下是一些帮助你开始这项练习的提示：

+   从一开始，你可以禁用所有除了第一个以外的输入字段。然后当第一个字段获得正确的输入时，你可以启用第二个输入字段。同样，当第二个输入字段正确完成时，第三个输入字段被启用，依此类推。

+   对于第二个问题，你可能想查看我们的代码，看看你是否能编辑`checkSecondForm()`函数中`if else`语句中的条件。我所做的是将所有可能性合并成一个`if`或`else if`语句，从而使无法检测出哪个字段出了问题。你可以尝试将条件拆分，使得每个`if`和`else if`语句只包含一个条件。这样，如果出现问题，我们就能为第二表单中的每个输入字段创建一个自定义响应。

# 总结

哇，我们在这一章节中涵盖了大量的知识。我们执行了测试计划并发现了 bug。接下来我们成功地修复了我们发现的问题。在修复每个 bug 后，我们执行了回归测试，以确保保留了原始功能，并且没有在程序中引入新的 bug。

具体来说，我们讨论了以下主题：

+   如何执行测试计划以及如何记录我们发现的问题

+   修复每个错误后如何执行回归测试

+   如何压缩代码以提高性能

+   如果我们使用 Ajax，测试差异如何

+   客户端测试与服务器端测试的区别

前面提到的学习点可能看起来很小，但既然你已经阅读了这一章节，你应该知道执行测试计划和随后修复 bug 可能会很繁琐。

现在我们已经讨论了测试计划的执行，是时候讨论稍微复杂一些的内容——测试更复杂的代码。请注意，我们一直以一种一维的方式处理 JavaScript：我们将所有的 JavaScript 放在我们的 HTML 文件中，还包括 CSS。我们一直将 JavaScript 代码开发成这样，因为我们只使用这一段 JavaScript 代码。但是，实际上，通常可以看到 web 应用程序使用不止一段 JavaScript 代码；这段额外的代码通常通过外部 JavaScript 文件附上。

更重要的是，这并不是我们在现实世界中唯一会面临的问题。随着我们的代码变得更加复杂，我们将需要使用更复杂的测试方法，甚至可能需要使用内置控制台等工具，以更有效、更高效地帮助我们进行测试。

在下一章中，我们将讨论之前提到的 issues，第六章，*测试更复杂的代码*。在那里见！
