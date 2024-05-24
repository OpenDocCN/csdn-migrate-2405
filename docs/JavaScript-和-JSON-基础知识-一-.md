# JavaScript 和 JSON 基础知识（一）

> 原文：[`zh.annas-archive.org/md5/256179285D6D80D91E6E7DA046AC4F3E`](https://zh.annas-archive.org/md5/256179285D6D80D91E6E7DA046AC4F3E)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

《JavaScript 和 JSON 基础》是一个一站式资源，可用于理解和实现各种 Web 应用中的 JSON。本书全面介绍了如何实现和集成 JSON 到您的应用程序中。尽管 JSON 是最流行的数据交换格式之一，但描述 JSON 并帮助读者构建实时解决方案的书籍数量并不多。本书是 JSON 的全面指南，从 JavaScript 基础知识开始，讨论 JSON 的历史，然后逐步使用 JSON 构建由 JSON 数据驱动的实时 Web 应用程序。

# 本书涵盖的内容

第一章，“JavaScript 基础”，是对常见 JavaScript 概念的基本复习。

第二章，“开始使用 JSON”，向观众介绍了 JSON，讨论了 JSON 的历史，概述了支持 JSON 的流行编程语言，在 JSON 中启动了一个 Hello World 程序，并编写了包含不同数据类型的基本程序。

第三章，“使用实时 JSON”，向观众介绍了复杂的 JSON。本章中使用的 JSON 将包含多种数据类型和多个对象，并且将是多维的。

第四章，“使用 JSON 数据进行 AJAX 调用”，介绍了成功通过 HTTP 传输 JSON 的要求，因为在现实世界的场景中，JSON 数据必须通过 HTTP 进行传输。

第五章，“跨域异步请求”，向观众介绍了跨域进行异步调用的概念。由于数据在不同域之间传输，用户将了解 JSON 与填充的概念。

第六章，“构建轮播应用程序”，讨论了轮播应用程序的概念以及所需的设置和依赖项，如 jQuery 库和 jQuery Cycle 插件。

第七章，“JSON 的替代实现”，讨论了 JSON 的非 Web 开发实现，如依赖管理器、元数据存储和配置存储。讨论将继续并谈论 JSON 相对于 XML 和 YAML 的优势。

第八章，“调试 JSON”，介绍了可用于调试、验证和格式化 JSON 的强大工具。随着对象数量的增加，JSON 的长度也会增加，这使得肉眼难以验证 JSON。

# 您需要为本书做好的准备

JSON 是语言和平台无关的，因此读者可以使用自己选择的操作系统。要提供实时 JSON，我们需要一个实时 Web 服务器。大多数流行的服务器端语言都有解析器可用；读者可以使用诸如 Apache、Tomcat、IIS 或任何其他 Web 服务器，并可以选择自己喜欢的文本编辑器。

# 本书的读者对象

本书旨在满足各个级别开发者的需求。本书包含了许多工作示例、提示和注释，将指导用户完成所有章节。虽然不是必需的，但了解 HTML 和 JavaScript 会很有帮助。对于服务器端语言（如 PHP、C#或 Python）的一些了解将是更好的选择，但不是必需的。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

代码和代码生成的输出将作为屏幕截图添加到本书中。文件名将显示如下：

`json_helloworld.html`

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，菜单或对话框中出现的单词会以这样的形式出现在文本中：“在网页浏览器中加载文件，页面上应该加载一个带有文本**Hello World!**的弹出框”。

### 注意

警告或重要提示会以这样的框出现。

### 提示

提示和技巧会显示在这样的形式下。


# 第一章：JavaScript 基础知识

JavaScript 最初由 Netscape Communications Corp 作为 LiveScript 引入，近年来取得了长足的发展。JavaScript 最初是为了使网页更具交互性，并控制页面的行为而开发的。JavaScript 程序通常嵌入在 HTML 文件中。HTML 是一种标记语言，一旦加载，就不会操纵页面的行为。使用 JavaScript，Web 开发人员可以设置规则并验证是否遵循了规则，避免任何远程服务器资源进行输入验证或复杂的数字计算。今天，JavaScript 不仅用于基本的输入验证；它还用于访问浏览器的`Document`对象，对 Web 服务器进行异步调用，并使用诸如`Node.JS`等软件平台开发端到端的 Web 应用程序，该平台由 Google 的 v8 JavaScript 引擎提供支持。

JavaScript 被认为是创建交互式网页所需的三个构建块之一；它是 HTML、CSS 和 JavaScript 中唯一的编程语言。JavaScript 是一种区分大小写且不敏感空格的语言，与 Python 和 Ruby 不同。JavaScript 程序是一系列语句，这些语句必须包含在`<script>`标签内。

![JavaScript Basics](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_01.jpg)

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

JavaScript 必须从另一个应用程序（如浏览器）中调用。浏览器有一个内置的 JavaScript 引擎，用于解释和执行网页上的 JavaScript。JavaScript 的解释是从上到下，从左到右。SpiderMonkey 和 Rhino 是早期由不同浏览器实现的几个 JavaScript 引擎，如 Netscape Navigator 和 Mozilla Firefox。

接下来是我们简单的 Hello World 程序；JavaScript 程序位于 head 部分的`<script>`标签之间。脚本标签可以添加到 head 标签或 body 标签中。由于 JavaScript 是非阻塞的，脚本会阻止页面加载直到它们被加载。通常可以看到脚本被加载到末尾；如果没有依赖其他文件或元素，这将起作用。一个这样的依赖的例子是从不同位置使用的库。我们将在后面的章节中看到很多这样的例子。我们将在以后讨论无侵入式 JavaScript 的作用。对于我们的 Hello World 程序，使用您选择的文本编辑器，并将此程序保存为 HTML 扩展名。在 Web 浏览器中加载文件，应该在页面上加载一个带有文本**Hello World!**的弹出框。

以下代码片段是`first_script.html`文件：

![JavaScript Basics](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_02.jpg)

输出如下：

![JavaScript Basics](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_03.jpg)

# JavaScript 中的变量

现在我们已经建立了一个 Hello World 程序，让我们迈出下一步，对两个数字进行一些算术运算。

### 注意

分号（`;`）是一个语句终止符，它告诉 JavaScript 引擎语句已经结束。

让我们再看一个程序，`alert_script.html`：

![JavaScript 中的变量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_04.jpg)

以前的程序将运行并产生四个弹出窗口，依次显示它们的各自值。这里一个明显的问题是我们在多个地方重复使用相同的数字。如果我们必须对不同的数字集执行这些算术运算，我们将不得不在多个位置进行替换。为了避免这种情况，我们将这些数字分配给临时存储位置；这些存储位置通常被称为变量。

关键字`var`用于在 JavaScript 中声明变量，后面跟着变量的名称。然后，该名称将隐式提供计算机内存的一部分，我们将在整个程序执行过程中使用它。让我们快速看一下变量如何使之前的程序更加灵活：

![JavaScript 中的变量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_05.jpg)

### 注意

代码注释可以通过两种方式进行：一种是单行，另一种是多行。

单行注释：

```js
//This program would alert the sum of 5 and 3;
alert(5+3);
```

多行注释：

```js
/* This program would generate two alerts, the first alert would display the sum of 5 and 3, and the second alert would display the difference of 5 and 3 */
alert(5+3);
alert(5-3);
```

让我们继续进行程序：

![JavaScript 中的变量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_06.jpg)

现在让我们将值从`5`改为`6`；我们将在这里进行的更改量是最小的。我们将值`6`赋给变量`a`，这样就完成了剩下的过程；不像我们之前的脚本在多个位置进行了更改。如下所示：

### 注意

代码注释是任何应用程序开发生命周期中经常发生且非常重要的一步。必须用来解释代码中包含的任何假设和/或任何依赖关系。

![JavaScript 中的变量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_07.jpg)

在 JavaScript 中，我们使用关键字`var`声明变量，直到为其分配一个值，变量的值将被隐式设置为`undefined`；该值在变量初始化时被覆盖。

# 数组

变量很适合保存单个值，但对于变量应该包含多个值的情况，我们必须依赖数组。JavaScript 数组是根据其索引顺序排列的项目集合。数组中的每个项目都是一个元素，并且具有用于访问该元素的索引。数组就像一个书架，可以放置多本书；每本书都有其独特的位置。数组使用数组文字表示法`[]`声明。

让我们看一个简单的数组声明：

![数组](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_08.jpg)

### 注意

JavaScript 中的数组是从零开始的。

让我们初始化数组：

![数组](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_09.jpg)

要访问特定元素的值，使用该元素的引用索引。一旦确定了引用索引，就可以使用 alert 语句输出它，如下面的屏幕截图所示：

![数组](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_10.jpg)

与变量不同，数组没有类型，因此可以包含各种类型的数据，如下面的屏幕截图所示：

![数组](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_11.jpg)

JavaScript 数组的一个更复杂的例子是多维数组，其中数组内部有数组的组合，如下面的屏幕截图所示：

![数组](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_12.jpg)

要从多维数组中检索元素，我们必须使用与该数组中级别相同的索引。如果多维数组包含一个包含我们要访问的值的数组，我们将不得不选择数组元素存在的索引，然后选择要搜索的数组内部值的索引。要从`multidimensionalArray`示例中检索字符串`Three`，我们首先必须找到包含值`Three`的数组的索引，然后找到该数组内部值`Three`的索引。如下所示：

![数组](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_13.jpg)

### 注意

使用`Array`类声明数组的第二种方法。

```js
var bookshelf = new Array()
```

# 对象

对象是处理数据的另一种方式。在数组中，索引通常是数字；对象为我们提供了一种强大的方式来分配和检索数据。对象源自面向对象编程的概念；这是一种非常流行的编程范式。对象是实时数据的虚拟表示；它们允许我们通过属性和方法将数据组织成逻辑组。属性描述对象的状态，而方法描述对象的行为。属性是保存信息的键值对。看一下下面的例子：

![对象](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_14.jpg)

在前面的例子中，我们实例化了一个`person`对象，然后添加了描述该对象的`firstname`和`lastname`属性。我们通过创建一个名为`getFullName`的方法为对象添加了行为，该方法访问了对象的属性，检索数据，并将输出警报到屏幕上。在这个例子中，属性是通过点表示法访问的；我们也可以通过将属性名称放在方括号中类似于数组来访问属性，但这并不常见。如下所示：

![对象](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_15.jpg)

创建对象的第二种方式是使用大括号。在这里，我们介绍了`this`关键字，它提供了对对象属性和方法的引用，如下所示：

![对象](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_01_16.jpg)

# Carousel 应用程序

我们将致力于开发一个由 JSON 提供支持的 Carousel 应用程序。我们将使用 HTML、JavaScript 和 JSON 来构建这个应用程序。这个应用程序将有自己的导航系统，配合后台的定时器事件，以在给定的间隔内旋转项目。我们还将讨论用户体验在开发这样一个应用程序中扮演的重要角色。

# 摘要

本章是对我们将在掌握 JSON 的过程中利用的 JavaScript 原则的基本介绍。变量、数组和对象在跨网络传递数据中扮演着非常重要的角色。如果这是你第一次接触 JavaScript，请再看一遍例子并加以练习。我们需要一个坚实的基础才能建立对 JSON 的深刻理解，以及它如何在实时网络应用中使用。


# 第二章：JSON 入门

JSON 或 JavaScript 对象表示法是一种非常流行的数据交换格式。它是由 Douglas Crockford 开发的。JSON 是基于文本的，轻量级的，用于客户端和服务器之间的数据交换的人类可读格式。JSON 源自 JavaScript，并与 JavaScript 对象非常相似，但不依赖于 JavaScript。JSON 是与语言无关的，并且所有流行语言都支持 JSON 数据格式，其中一些是 C＃，PHP，Java，C ++，Python 和 Ruby。

### 注意

JSON 是一种格式，而不是一种语言。

JSON 可以用于 Web 应用程序进行数据传输。在 JSON 出现之前，XML 被认为是选择的数据交换格式。XML 解析需要客户端上的 XML DOM 实现，该实现将接收 XML 响应，然后使用 XPath 查询响应以访问和检索数据。这使得生活变得繁琐，因为数据查询必须在两个级别上执行：首先在服务器端，从数据库中查询数据，然后在客户端使用 XPath 进行第二次查询。JSON 不需要任何特定的实现；浏览器中的 JavaScript 引擎处理 JSON 解析。

XML 消息往往很沉重和冗长，在通过网络连接发送数据时占用大量带宽。一旦检索到 XML 消息，就必须将其加载到内存中进行解析；让我们看看 XML 和 JSON 中的`students`数据源。

以下是 XML 中的一个示例：

![JSON 入门](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_01.jpg)

让我们看看 JSON 中的示例：

![JSON 入门](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_02.jpg)

正如我们注意到的，与其 JSON 对应物相比，XML 消息的大小要大得多，这仅仅是两条记录。实时数据源将以几千条开始，并不断增加。还要注意的一点是服务器必须生成并通过互联网传输的数据量已经很大，而 XML 由于冗长而使其变得更大。考虑到我们处于移动设备时代，智能手机和平板电脑日益受到欢迎，通过较慢的网络传输如此大量的数据会导致页面加载缓慢、卡顿和用户体验差，从而使用户远离网站。JSON 已成为首选的互联网数据交换格式，以避免前面提到的问题。

由于 JSON 用于在互联网上传输序列化数据，我们需要注意其 MIME 类型。**MIME**（多用途互联网邮件扩展）类型是互联网媒体类型，是正在通过互联网传输的内容的两部分标识符。MIME 类型通过 HTTP 请求和 HTTP 响应的 HTTP 头传递。MIME 类型是服务器和浏览器之间的内容类型通信。通常，MIME 类型将有两个或更多部分，其中包含有关正在发送的数据类型的信息，无论是在 HTTP 请求中还是在 HTTP 响应中。JSON 数据的 MIME 类型是`application/json`。如果未通过浏览器发送 MIME 类型头，它将将传入的 JSON 视为纯文本。

# JSON 的 Hello World 程序

现在我们对 JSON 有了基本的了解，让我们来编写我们的 Hello World 程序。如下图所示：

![JSON 的 Hello World 程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_03.jpg)

当从浏览器中调用时，上述程序将在屏幕上警告 World。让我们密切关注`<script>`标签之间的脚本。

![JSON 的 Hello World 程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_04.jpg)

在第一步中，我们创建一个 JavaScript 变量，并用 JavaScript 对象初始化变量。与从 JavaScript 对象中检索数据的方式类似，我们使用键值对来检索值。简而言之，JSON 是一个键值对的集合，其中每个键都是对计算机上存储值的内存位置的引用。现在让我们退一步，分析为什么我们需要 JSON，如果我们所做的只是分配 JavaScript 对象，这些对象已经可用。答案是，JSON 是一个完全不同的格式，不像 JavaScript 是一种语言。

### 注意

JSON 的键和值必须用双引号括起来，如果其中任何一个用单引号括起来，我们将收到一个错误。

现在，让我们快速看一下 JSON 和普通 JavaScript 对象之间的相似之处和不同之处。如果我们要创建一个类似于之前示例中的`hello_world` JSON 变量的 JavaScript 对象，它将看起来像接下来的 JavaScript 对象：

![带有 JSON 的 Hello World 程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_05.jpg)

这里的一个重大区别是键没有用双引号括起来。由于 JSON 键是一个字符串，我们可以使用任何有效的字符串作为键。我们可以在键中使用空格、特殊字符和连字符，这在普通的 JavaScript 对象中是无效的。

![带有 JSON 的 Hello World 程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_06.jpg)

当我们在键中使用特殊字符、连字符或空格时，我们在访问它们时必须小心。

![带有 JSON 的 Hello World 程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_07.jpg)

前面的 JavaScript 语句无法工作的原因是 JavaScript 不接受带有特殊字符、连字符或字符串的键。因此，我们必须使用一种方法来处理 JSON 对象，将其作为具有字符串键的关联数组来处理。这在接下来的截图中显示：

![带有 JSON 的 Hello World 程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_08.jpg)

两者之间的另一个区别是 JavaScript 对象可以包含函数，而 JSON 对象不能包含任何函数。接下来的示例中有一个`getName`属性，它有一个函数，当被调用时会弹出名字`John Doe`：

![带有 JSON 的 Hello World 程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_09.jpg)

最后，最大的区别是 JavaScript 对象从未打算成为数据交换格式，而 JSON 的唯一目的是将其用作数据交换格式。

# JSON 中的数据类型

现在，让我们看一个更复杂的 JSON 示例。我们还将介绍 JSON 支持的所有数据类型。JSON 支持六种数据类型：字符串、数字、布尔值、数组、对象和 null。

![JSON 中的数据类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_10.jpg)

在上面的例子中，我们有五个不同数据类型的键值对。现在让我们仔细看看每个这些键值对：

![JSON 中的数据类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_11.jpg)

`"id"`引用的值的数据类型是数字。

![JSON 中的数据类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_12.jpg)

在这里，`"name"`引用的值的数据类型是字符串。

![JSON 中的数据类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_13.jpg)

在上面的截图中，`"isStudent"`引用的值的数据类型是布尔值。

![JSON 中的数据类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_14.jpg)

这里`"scores"`引用的值的数据类型是数组。

![JSON 中的数据类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_15.jpg)

这里，`"courses"`引用的值的数据类型是对象。

我们知道 JSON 支持六种数据类型；它们是字符串、数字、布尔值、数组、对象和 null。是的，JSON 支持 null 数据，实时业务实现需要准确的信息。可能有情况下 null 被替换为空字符串，但这是不准确的。让我们快速看一下以下示例：

![JSON 中的数据类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_16.jpg)

### 注意

数组和 null 值在 JavaScript 中是对象。

在前面的例子中，我们使用了`typeof`运算符，它接受一个操作数，并返回该操作数的数据类型。在第 4 行，我们确定了空字符串的类型，而在第 8 行，我们确定了空值的类型。

现在，让我们在页面中实现我们的 JSON 对象并检索值，如下面的屏幕截图所示：

![JSON 中的数据类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_17.jpg)

要从变量`complexJson`中检索`id`，我们需要执行以下操作：

![JSON 中的数据类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_18.jpg)

要从变量`complexJson`中检索`name`，请查看所示的屏幕截图：

![JSON 中的数据类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_19.jpg)

查看以下屏幕截图，以从变量`complexJson`中检索`isStudent`：

![JSON 中的数据类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_20.jpg)

从数组和对象中检索数据有点棘手，因为我们必须遍历数组或对象。让我们看看如何从数组中检索值：

![JSON 中的数据类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_21.jpg)

在上面的例子中，我们从`scores`数组中检索了第二个元素。尽管`scores`是`complexJson`对象内的一个数组，但它仍然被视为常规键值对。当访问键时，处理方式不同；解释器在访问键时首先要评估的是获取其值的数据类型。如果检索到的值是字符串、数字、布尔值或空值，则不会对该值执行任何额外的操作。但如果它是一个数组或对象，则会考虑值的依赖关系。

要从 JSON 对象内部检索元素，我们必须访问作为该值引用的键，如下所示：

![JSON 中的数据类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_22.jpg)

由于对象没有数值索引，JavaScript 可能会重新排列对象内部项目的顺序。如果您注意到在初始化 JSON 对象时键值对的顺序与访问数据时不同，那就没什么好担心的。数据没有丢失；JavaScript 引擎只是重新排列了您的对象。

# 支持 JSON 的语言

到目前为止，我们已经看到 JavaScript 中的解析器如何支持 JSON。还有许多其他编程语言提供了 JSON 的实现。诸如 PHP、Python、C＃、C ++和 Java 等语言对 JSON 数据交换格式提供了很好的支持。所有支持面向服务的流行编程语言都理解了 JSON 及其用于数据传输的重要性，因此它们对 JSON 提供了很好的支持。让我们暂时离开 JavaScript 中 JSON 的实现，看看 JSON 在其他语言中的实现，比如 PHP 和 Python。

## PHP

PHP 被认为是构建 Web 应用程序的最流行语言之一。它是一种服务器端脚本语言，允许开发人员构建可以在服务器上执行操作、连接到数据库执行 CRUD（创建、读取、更新、删除）操作，并为实时应用程序提供稳定环境的应用程序。JSON 支持已经内置到 PHP 核心中，从 PHP 5.2.0 开始；这有助于用户避免进行任何复杂的安装或配置。鉴于 JSON 只是一种数据交换格式，PHP 包含两个函数。这些函数处理通过请求传入的 JSON，或者生成将通过响应发送的 JSON。PHP 是一种弱类型语言；在本例中，我们将使用存储在 PHP 数组中的数据，并将该数据转换为 JSON 字符串，以便用作数据源。让我们在 PHP 中重新创建我们在前面部分中使用的学生示例，并将其转换为 JSON。

### 注意

此示例仅旨在向您展示如何使用 PHP 生成 JSON。

![PHP](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_23.jpg)

### 注意

要运行 PHP 脚本，我们需要安装 PHP。要通过浏览器运行 PHP 脚本，我们需要一个 Web 服务器，如 Apache 或 IIS。当我们使用 AJAX 时，我们将在第四章中进行安装，*使用 JSON 数据进行 AJAX 调用*。

这个脚本首先初始化一个变量，并分配一个包含学生信息的关联数组。然后将变量`$students`传递给一个名为`json_encode()`的函数，该函数将变量转换为 JSON 字符串。当运行此脚本时，它将生成一个有效的响应，可以将其公开为 JSON 数据源，供其他应用程序利用。

以下是输出结果：

![PHP](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_24.jpg)

我们已经成功通过一个简单的 PHP 脚本生成了我们的第一个 JSON 数据源；让我们看一下如何解析通过 HTTP 请求传入的 JSON 的方法。对于进行异步 HTTP 请求的 Web 应用程序来说，以 JSON 格式发送数据是很常见的。

### 注意

这个例子只是为了向你展示 JSON 如何被引入到 PHP 中。

![PHP](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_25.jpg)

以下是输出结果：

![PHP](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_26.jpg)

## Python

Python 是一种非常流行的脚本语言，广泛用于执行字符串操作和构建控制台应用程序。它可以用于从 JSON API 中获取数据，一旦检索到 JSON 数据，它将被视为 JSON 字符串。为了对该 JSON 字符串执行任何操作，Python 提供了 JSON 模块。JSON 模块是许多强大函数的综合，我们可以使用它们来解析手头的 JSON 字符串。

### 注意

这个例子只是为了向你展示如何使用 Python 生成 JSON。

![Python](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_27.jpg)

在这个例子中，我们使用了复杂的数据类型，如元组和字典，分别存储分数和课程；由于这不是 Python 课程，我们不会深入研究这些数据类型。

### 注意

要运行这个脚本，需要安装 Python2，它预装在任何*nix 操作系统上。

以下是输出结果：

![Python](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_28.jpg)

键可能会根据数据类型重新排列；我们可以使用`sort_keys`标志来检索原始顺序。

现在，让我们快速看一下在 Python 中如何执行 JSON 解码。

### 注意

这个例子只是为了向你展示 JSON 如何被引入到 Python 中。

![Python](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_29.jpg)

在这个例子中，我们将 JSON 字符串存储在`student_json`中，并使用 Python 中 JSON 模块提供的`json.loads()`方法。

以下是输出结果：

![Python](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_02_30.jpg)

# 摘要

本章向我们介绍了 JSON 的基础知识。我们了解了 JSON 的历史，并理解了它相对于 XML 的优势。我们创建了我们的第一个 JSON 对象并成功解析了它。此外，我们还了解了 JSON 支持的所有数据类型。最后，我们还介绍了一些关于如何在其他编程语言中实现 JSON 的示例。随着我们在这个旅程中前进，我们会发现本章中所积累的知识将为我们在后面章节中将要学习的更复杂的概念奠定坚实的基础。


# 第三章：使用实时 JSON

在上一章中，我向您介绍了基本的 JSON，以及如何将 JSON 对象嵌入到 HTML 文件中，以及如何在简单的 JSON 对象上执行访问键等基本操作。现在让我们向前迈进一步，使用更大、更复杂且更接近我们在实时情况下使用的 JSON 对象。在现实世界的应用中，JSON 可以作为异步请求的响应或来自 JSON 源的检索。网站使用 HTML、CSS 和 JavaScript 提供视觉上美观的用户界面。但也有一些情况，数据供应商只关注获取数据。数据源满足了他们的目的；数据源是一种提供数据的粗糙方式，以便他人可以重用它来在其网站上显示数据或摄取数据并在其上运行算法。这些数据源体积庞大，不能直接嵌入到`script`标签中。让我们看看如何在 HTML 文件中包含外部 JavaScript 文件。

以下截图显示了`external-js.html`文件的代码：

![使用实时 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_01.jpg)

在这个例子中，我们包含了一个外部 JavaScript 文件`example.js`。

![使用实时 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_02.jpg)

要从`external-js.html`文件中访问`example.js`文件中的变量`x`，我们在 HTML 文件的`script`标签中编写我们的程序。

这个文件必须在与`external-js.html`相同的文件夹中创建。遵循给定的文件夹结构：

![使用实时 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_03.jpg)

# 访问 JSON 中的对象

现在我们了解了如何调用脚本来获取外部 JavaScript 文件，让我们使用相同的技术来导入 JSON 源。我生成了一个包含 100 条记录的测试`employee` JSON 数据源。要遍历任何 JSON 源，重要的是要注意数据的排列方式。这个数据源中的键是基本的员工信息，如员工编号、出生日期、名字、姓氏、性别、入职日期、他们担任的职务以及他们担任这些职务的日期。一些员工在任期内担任相同的职务，而有些员工则担任了多个职务。

### 注意

这个 JSON 文件将成为练习的代码文件的一部分。

![访问 JSON 中的对象](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_04.jpg)

由于我们正在处理复杂的 JSON 数据源，让我们将数据源保存到一个文件中。在`data_json_feed.html`文件中，我们导入了与 HTML 文件位于同一文件夹中的`data.json`文件。值得注意的是，JSON 源已分配给一个名为`data_json`的变量，要访问 JSON 源，我们将在`data_json_feed.html`文件中使用这个变量：

![访问 JSON 中的对象](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_05.jpg)

还要注意的一件事是使用一个称为`console.log`的新方法。像 Mozilla Firefox、Google Chrome 和 Apple Safari 这样的浏览器为运行时 JavaScript 开发和调试提供了一个控制台面板。由于其突兀的行为，不建议使用 JavaScript 函数`alert`。另一方面，`console.log`是不突兀的，并将其消息记录到控制台中。从现在开始，我们将避免使用`alert`方法，而是使用`console.log`将数据打印到控制台窗口。Google Chrome 和 Apple Safari 已经安装了开发者工具；要查看控制台，右键单击页面，然后单击**检查元素**。它们都有一个**控制台**选项卡，允许我们使用日志记录。Firefox 依赖于 Firebug；在第八章中，*调试 JSON*，我将指导您完成 Firebug 的安装步骤。

![访问 JSON 中的对象](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_06.jpg)

当我们将`data_json_feed.html`文件加载到 Firefox 浏览器中，打开控制台窗口，并点击**DOM**选项卡，我们将看到一个包含 100 个`employee`对象的列表。如果我们的对象很小并且有一两个子对象，我们会更喜欢使用它们的数字索引来访问它们；在这种情况下，由于我们有大量的子对象，根据静态索引来定位对象是不现实的。

![访问 JSON 中的对象](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_07.jpg)

# 执行复杂操作

为了处理一个对象数组，我们必须以迭代的方式处理它们。我们将不得不提出一个迭代解决方案，其中我们一次只针对一个对象；一旦访问了对象，我们就不会再次访问该对象。这使我们能够保持数据的完整性，因为我们可以避免多次访问相同的对象，从而避免任何冗余。JavaScript 中的循环语句是`while`循环和`for`循环。让我们快速看一下如何使用这些循环技术来遍历我们的员工数组。

![执行复杂操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_08.jpg)

在`while_employees_traversal.html`文件中，我们导入了在上一节中检查过的`data.js`文件。`data.js`文件中的`data_json`变量包含了一个对象数组，这些对象被导入到这个 HTML 页面中。在`script`标签中，我们设置了两个变量：`i`变量用于保存起始计数器，`employeeCount`变量用于保存`data_json`中对象的总数。要检索数组中存在的项目数，我们可以使用 JavaScript 提供的`.length`属性。`while`循环有三个重要的支持块：条件、`while`循环中的语句，以及根据条件的增量或减量操作。让我们分别快速看一下这三个：

![执行复杂操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_09.jpg)

我们将变量`i`初始化为零，并且我们要查找的条件是如果零小于变量`data_json`中的项目数，则继续进入循环。

![执行复杂操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_10.jpg)

如果条件为真，则循环内的语句将被执行，直到它们达到增量条件：

![执行复杂操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_11.jpg)

一旦增量运算符接近，变量`i`的值将增加 1，并且它将返回到`while`循环的初始步骤。在初始步骤中，再次验证条件，以检查`i`是否仍然小于`data_json`中的项目数。如果是真的，它将再次进入循环并执行语句。这个过程会一直重复，直到变量`i`的值等于`employeeCount`的值。在那一点上，`while`循环的执行就完成了，并且`while`循环内的语句会作为日志保留在浏览器的控制台窗口中。在运行 HTML 文件`while_employees_traversal.html`之前，请验证`data.json`文件是否与 HTML 文件在同一个目录中。将这个 HTML 文件加载到您选择的浏览器中（推荐使用 Chrome，Firefox 或 Safari），通过右键单击网页并点击**检查元素**来打开控制台窗口，如果您使用的是 Chrome 或 Safari。员工编号应该显示在控制台窗口中：

![执行复杂操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_12.jpg)

为了检索员工的名字和姓氏，我们将连接`employee`对象中的`first_name`和`last_name`键：

![执行复杂操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_13.jpg)

我们可以使用相同的技术来检索其余的键，比如`birth_date`、`gender`和`hire_date`，除了`titles`。快速浏览 JSON 数据可以解释，与其余的键不同，`titles`是一个对象或对象数组。`titles`对象包含员工自加入公司以来担任的所有职称。一些员工只有一个职称，而另一些员工有多个；因此前者将是一个独立的对象，而后者将是一个包含`title`对象的对象数组。为了处理这种情况，我们需要检查员工是否只有一个职称或多个职称。如果这个人只有一个职称，我们应该打印数据，如果这个人有多个职称，我们需要遍历`title`对象的数组，打印员工拥有的所有职称。

![执行复杂操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_14.jpg)

`script`标签中的现有代码必须用之前提供的代码替换，以检索员工的职称。在这个脚本中，我们使用了之前脚本中的变量`i`和`employeeCount`。我们引入了一个新的条件来检查特定员工的`titles`键是否是`Array`对象。这个条件获取循环传递的值的类型，并验证它是否是`Array`对象的实例。让我们识别一下检查实例类型的条件：

![执行复杂操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_15.jpg)

一旦满足这个条件，就会执行条件内的语句。在成功条件内，我们声明了三个变量。第一个变量`j`将保存第二个`while`循环的计数器，该循环将迭代`titles`。第二个变量是`titleCount`，它将存储`titles`数组中可用项目的数量。最后一个变量是`titles`，它被初始化为空字符串。这个变量将保存员工拥有的所有职称。它将职称列表作为由`&`分隔的列表存储：

![执行复杂操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_16.jpg)

在这个`while`循环中，正在构建员工的职称；每次添加一个职称到`titles`变量中。一旦职称被添加到`titles`变量中，`j`的值就会增加，循环会继续直到所有的`title`对象都被迭代。如果`titles`键不是一个数组，执行会进入`else`块，并执行`else`块中的语句。由于该员工只有一个职称，数据会直接打印到控制台上。现在让我们看一下相同的例子，并使用`for`循环。与`while`循环类似，`for`循环也遍历`data_json`变量中的员工数组。无论使用何种循环技术，业务逻辑都保持不变。让我们使用`for`循环重新创建相同的例子：

![执行复杂操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_17.jpg)

与`while`循环不同，我们不需要额外的计数变量来保存当前索引和数组的长度，`for`循环会处理这些计数器。除了语法上的基本变化，业务逻辑保持不变，就像我之前指出的那样。现在我们已经了解了如何访问对象并执行复杂操作来提取数据，在下一节中，让我们看看如何修改 JSON 数据。

# 修改 JSON

从 JSON 数据源中检索到的 JSON 始终是只读的；因此，数据源不提供从未经验证的来源修改其数据的功能。有许多情况下，我们希望从外部数据源摄取数据，然后根据我们的需求修改内容。一个例子是，一家公司正在使用数据供应商提供的数据源，但提供的数据远远超出了公司的需求。在这种情况下，公司不会使用整个数据源，而是只提取其中的一部分，执行某些操作以根据他们的需求修改它，并重用新的 JSON 对象。让我们以我们的`employee` JSON 数据源为例。假设公司在不同时期的公司名称不同。我们想要根据员工加入公司的时间将员工分组到公司名称下。在 1987 年之前加入公司的员工属于公司 1，而在 1987 年或之后加入公司的员工属于公司 2。为了表示这种变化，我们向我们的 JSON 数据源添加了`company`键：

![修改 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_18.jpg)

在`for_employee_company.html`文件中，我们正在遍历`employee`对象数组，并提取员工加入的年份。我们将其从字符串转换为整数，以便我们可以将年份值用于比较。我们将解析后的年份赋给`join_year`变量：

![修改 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_19.jpg)

在下面的截图中，我们正在检查员工是否在 1987 年之前加入了公司；如果他们在 1987 年之前加入了，我们将`company`属性添加到`employee`对象中，并赋予值`Company1`。如果他们在 1987 年或之后加入了，我们将赋予值`Company2`：

![修改 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_20.jpg)

在为新添加的属性`company`分配值之后，我们构建了一个通用消息，适用于所有员工，无论他们属于哪家公司。我们提取员工编号、员工加入的年份和公司名称来生成该消息：

![修改 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_21.jpg)

当从 Web 浏览器运行`for_employee_company.html`时，将运行执行修改的脚本，并将输出记录到控制台：

![修改 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_03_22.jpg)

# 总结

本章介绍了如何处理静态 JSON 数据源的核心概念。我们首先将外部 JSON 对象导入到我们的 HTML 文件中，循环遍历复杂的对象数组以解析和提取所需的数据。我们使用`while`和`for`循环来遍历数组，并使用条件来定位我们的搜索。我们通过在本地修改现有的 JSON 数据源并添加一个新属性`employee`对象来完成本章。现在我们已经掌握了从静态文件中访问 JSON 的方法，是时候开始进行一些异步调用，以从 HTTP 获取一些活动的 JSON 数据了。


# 第四章：使用 JSON 数据进行 AJAX 调用

JSON 被认为是当今最流行的数据交换格式。在上一章中，我们看到了一个使用 JSON feed 作为数据存储的示例。在本章中，让我们使数据更加动态。HTML、客户端 JavaScript 和 CSS 分别提供结构、行为和表现方面。动态网页开发涉及两方之间的数据传输，即客户端和服务器。我们使用诸如 Web 服务器、数据库和服务器端编程语言等程序来获取和存储动态数据。让我们来看看在幕后促成数据成功操作的过程。

当用户打开 Web 浏览器并输入`http://www.packtpub.com/`时，浏览器会向**互联网服务提供商**（**ISP**）发出请求，通过提供域名执行 IP 地址的反向查找。一旦检索到 IP 地址，请求就会被转发到拥有该 IP 地址的机器。此时，有一个 Web 服务器在等待处理请求；Web 服务器可以是顶级 Web 服务器之一，如 Apache、IIS、Tomcat 和 Nginx。Web 服务器接收请求并查看 HTTP 请求的一部分——头部；这些头部传递了有关向 Web 服务器发出的请求的信息。一旦 Web 服务器解析了这些头部，它就会将请求路由到负责处理此请求的服务器端编程应用程序。该应用程序可以是用 PHP、C#/ASP.NET、Java/JSP 等编写的。这个负责的服务器端语言接受请求，理解它，并执行必要的业务逻辑来完成请求。这样的 HTTP 请求的一些例子包括加载网页和在网站上点击**联系我们**链接。也可能存在复杂的 HTTP 请求，其中数据必须经过验证、清洗和/或从数据存储应用程序（如数据库、文件服务器或缓存服务器）中检索。

这些 HTTP 请求可以通过两种方式进行——同步和异步。同步请求是一种阻塞请求，所有事情都必须按顺序进行，一步接一步，后续步骤必须等待前一步完成执行。假设网页加载时有四个独立的组件；如果其中一个组件执行时间很长，页面的其余部分将等待直到其执行完成。如果执行失败，页面加载也会失败。另一个例子是网页上有一个投票和评分组件；如果用户选择回答投票并给出评分来满足这些请求，如果我们采用同步请求机制，就必须依次发送两个请求。

为了解决同步请求的问题，开发社区逐渐在异步 HTTP 请求领域取得了进展。第一个允许异步请求的产品是由微软推出的 IFrame 标签；它们通过 Internet Explorer 使用 IFrames 来异步加载内容。在 IFrame 之后，接下来改变互联网的是 XML HTTP ActiveX 控件。后来，所有浏览器都在新名称 XMLHTTPRequest JavaScript 对象下采用了这个控件，它是 XMLHTTPRequest API 的一部分。XMLHTTPRequest API 用于向 Web 服务器发出 HTTP（或 HTTPS）调用。它可以用于进行同步和异步调用。异步请求允许开发人员将网页分成彼此独立的多个组件，从而通过按需发送数据节省大量内存。

*杰西·詹姆斯·加勒特*将这种现象称为“AJAX”。在**AJAX**（**异步 JavaScript 和 XML**）中，通过 JavaScript 进行网络请求，数据交换最初是在 XML 中进行的。 AJAX 中的“X”最初被认为是 XML，但今天它可以是任何数据交换格式，例如 XML，JSON，文本文件，甚至 HTML。用于数据传输的数据格式必须在 MIME 类型标头中提到。在第二章中，*使用 JSON 入门*，我们已经强调了为什么 JSON 是首选的数据交换格式。让我们快速看一下我们需要使用 JSON 数据进行第一个 AJAX 调用的内容。

基本上，Web 开发人员可以使用 AJAX 的原则按需获取数据，使网站更具响应性和交互性；了解是什么产生了这种需求非常重要。这种数据需求的触发器通常是在网页上发生的事件。**事件**可以被描述为对执行的操作的反应，例如，敲响铃会在铃内产生振动，产生声音。在这里，敲响铃是事件，而产生的声音是对事件的反应。网页上可能有多个事件；一些常见的事件包括点击按钮，提交表单，悬停在链接上，以及从下拉菜单中选择选项。当这些事件发生时，我们必须想出一种以编程方式处理它们的方法。

# AJAX 的要求

AJAX 是浏览器（被视为客户端）与通过 HTTP（或 HTTPS）与实时网络服务器之间的异步双向通信。我们可以在本地运行实时服务器，例如在 Windows 上运行 Apache 或 IIS，或在 Linux 和 Mac OS 上运行 Apache。我将带领我们在 Linux 环境中设置 Apache Web 服务器，并同时解释如何使用 Microsoft Visual Studio 开发环境构建 Web 应用程序。对于这门 AJAX 课程，让我们选择 PHP 和 MySQL 作为我们的主要服务器端语言和数据库。

在本章中，我将带您完成两个设置；第一个是在 Linux 机器上设置 Apache 和 PHP 以开发服务器端程序，而第二个是在 Windows 上运行由.NET 驱动的 Web 应用程序。微软的.NET 框架需要安装.NET 框架和 Visual Studio IDE 中的库。我假设您已经执行了这两个步骤；现在我们将在 ASP.NET 中设置一个由 C#驱动的 Web 应用程序。

Linux 是一个开源操作系统，已经成为非微软编程和脚本语言开发界的选择操作系统，例如 PHP，Python，Java 和 Ruby。在 Linux 操作系统上使用 PHP，Perl 或 Python 时的开发环境通常被称为 LAMP 环境。**LAMP**代表**Linux**，**Apache**，**MySQL**和**PHP**（或**Python**或**Perl**）。`tasksel`软件包允许我们一次性安装 Apache，MySQL 和 PHP。让我们快速看一下安装 LAMP 堆栈所需的步骤。在您的 Linux 操作系统上，打开终端并键入`sudo apt-get install tasksel`。根据您的用户权限，操作系统可能会提示您输入密码；输入密码后，按*Enter*。

![AJAX 的要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_01.jpg)

由于我们正在在操作系统上安装软件包，因此操作系统将显示正在安装的软件包和软件包的依赖信息，并提示用户检查是否为目标软件包。在键盘上按*Y*键表示“是”；然后操作系统将转到存储库并获取要安装的软件包。安装后，我们可以使用`tasksel`来安装 LAMP 服务器。为此，我们将不得不通过使用命令`sudo tasksel`从终端调用`tasksel`程序，如下面的屏幕截图所示：

![AJAX 的要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_02.jpg)

### 注意

`sudo`是必需的，以执行安装操作，因为普通用户可能没有所需的权限。

调用`tasksel`后，我们将获得可安装的软件包列表，例如 LAMP 服务器、Tomcat 服务器和 DNS 服务器；我们将选择 LAMP 服务器。在`tasksel` shell 内导航，我们将使用箭头键上下移动，并使用空格键选择要安装的程序。

![AJAX 的要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_03.jpg)

选择**LAMP 服务器**后，继续按*Enter*确认安装。安装完成后，我们就可以编写我们的第一个服务器端程序来生成和托管实时 JSON 数据。为此，我们将导航到文档根文件夹，这将是 Apache 可用的唯一文件夹。文档根文件夹是放置网站或 Web 应用程序文件的文件夹。只有像 Apache、Tomcat、IIS 和 Nginx 这样的 Web 服务器才能访问这些文件夹，因为未经验证的匿名用户可能会通过网站访问这些文件。Linux 中 Apache 的默认文档根文件夹是`/var/www`文件夹。要导航到`/var/www`，我们将使用`cd`命令，该命令用于更改目录。

![AJAX 的要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_04.jpg)

一旦我们在`www`文件夹中，我们可以开始创建我们的服务器端脚本。Apache 已经为我们提供了一个测试 HTML 页面（在该文件夹中）来测试 Apache 是否正在运行；它被命名为`index.html`。要执行此操作，我们应该在 Linux 操作系统中打开浏览器并访问`http://localhost/index.html`；然后我们应该收到一个成功的消息。

![AJAX 的要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_05.jpg)

一旦我们收到这条消息，我们就可以确保我们的 Apache Web 服务器正在运行。现在让我们使用 Windows 操作系统和 C#或 ASP.NET 设置类似的架构。

![AJAX 的要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_20.jpg)

Microsoft Visual Studio 是开发使用 ASP.NET 和 C#的服务器端程序或 Web 应用程序的选择环境。导航到**文件** | **新建** | **网站**。Visual Studio 自带自己的开发服务器，用于在开发过程中运行网站。

![AJAX 的要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_21.jpg)

一旦我们点击**新建网站**选项，我们将不得不选择我们正在构建的网站类型；由于这只是一个虚拟网站，让我们简单地选择**ASP.NET 网站**，然后点击**确定**。如前面的屏幕截图所示。

![AJAX 的要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_22.jpg)

默认的 ASP.NET 网站带有一些基本的 HTML，可用于测试；继续点击**调试**旁边的绿色按钮。这用于运行网站；请记住，C#或 ASP.NET 程序必须在运行之前进行编译，而不像 PHP 或 Python 那样是解释性语言。

![AJAX 的要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_23.jpg)

这是我们的 Hello World 网站应用程序，由 C#/ASP.NET 提供支持。Web 应用程序可以用任何语言构建，并且 JSON 可以用作任何服务器端堆栈支持的 Web 应用程序之间的数据交换语言。让我们利用这些服务器端编程知识，继续我们的旅程，以便我们可以在强大的 Web 应用程序中实现这一点。

# 托管 JSON

在这一部分，我们将创建一个 PHP 脚本，允许我们在成功请求时向用户发送 JSON 反馈。让我们看看完成这个任务的`index.php`文件：

![托管 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_06.jpg)

在这个 PHP 脚本中，我们创建了一个基本的`students`数组，并为该数组生成了 JSON 数据源。`students`数组包含基本的学生信息，如名字、姓氏、学生 ID 以及学生已注册的课程。

这个文件必须放在`www`文件夹中，并且应该与 LAMP 安装附带的默认`index.html`文件在同一级别。请参考以下截图中的文件夹结构：

![托管 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_08.jpg)

现在我们的`index.php`在文档根文件夹中，我们可以通过我们的 Web 服务器加载这个文件。要通过我们的 Apache Web 服务器访问这个文件，请导航到`http://localhost/index.php`。

![托管 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_07.jpg)

如前面的截图所示，当使用 Apache web 服务器运行文件时，服务器接受请求，解析 PHP 代码，并输出提供学生数据的 JSON 数据源。

# 进行第一个 AJAX 调用

现在我们有了一个活跃的 JSON 数据源，是时候进行我们的第一个 AJAX 调用了。我们将看两种不同时期的 AJAX 调用方法。第一种方法将使用基本的 JavaScript，以便我们了解在进行 AJAX 调用时发生了什么。一旦我们理解了 AJAX 的概念，我们将使用流行的 JavaScript 库来进行相同的 AJAX 调用，但代码更简单。让我们看看我们使用基本 JavaScript 的第一种方法：

![进行第一个 AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_09.jpg)

我们将从我们的基本`index.html`文件开始，它加载一个外部 JavaScript 文件。这个 JavaScript 文件执行 AJAX 调用来获取`students`的 JSON 数据源。

让我们看看`index.js`：

![进行第一个 AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_10.jpg)

这是向实时网络服务器发出 AJAX 调用的原始方式；让我们将这个脚本分解成片段，并逐个调查它。

![进行第一个 AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_11.jpg)

在上面的代码片段中，我们创建了一个`XMLHttpRequest`对象的实例。`XMLHttpRequest`对象让我们可以对服务器进行异步调用，从而允许我们将页面中的部分视为单独的组件。它具有强大的属性，如`readystate`、`response`、`responseText`，以及方法，如`open`、`onuploadprogress`、`onreadystatechange`和`send`。让我们看看如何使用我们创建的`request`对象来打开一个 AJAX 请求：

![进行第一个 AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_12.jpg)

`XMLHttpRequest`默认打开一个异步请求；在这里，我们将指定联系实时数据源的方法。由于我们不会传递任何数据，我们选择使用 HTTP `GET`方法将数据发送到我们的实时网络服务器。在处理异步请求时，我们不应该有阻塞脚本；我们可以通过设置回调来处理这个问题。**回调**是一组脚本，它们将等待响应，并在接收到响应时触发。这种行为有助于非阻塞代码。

我们正在设置一个回调，并将回调分配给一个名为`onreadystatechange`的方法，如下截图所示：

![进行第一个 AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_13.jpg)

占位符方法`onreadystatechange`查找请求对象中名为`readyState`的属性；每当`readyState`的值发生变化时，就会触发`onreadystatechange`事件。`readyState`属性跟踪所做的`XMLHttpRequest`的进度。在前面的屏幕截图中，我们可以看到回调具有一个条件语句，用于验证`readyState`的值是否为`4`，这意味着服务器已经接收到客户端发出的`XMLHttpRequest`，并且准备好响应。让我们快速看一下`readyState`的可用值：

| `readyState` | 描述 |
| --- | --- |
| `0` | 请求尚未初始化 |
| `1` | 服务器连接已建立 |
| `2` | 服务器已接收请求 |
| `3` | 服务器正在处理请求 |
| `4` | 请求已处理，响应准备就绪 |

在之前的屏幕截图中，我们还在寻找另一个名为`status`的属性；这是从服务器返回的 HTTP 状态码。状态码`200`表示成功的交易，而状态码`400`是一个错误的请求，`404`表示页面未找到。其他常见的状态码是`401`，表示用户请求了一个只有授权用户才能使用的页面，以及`500`，表示内部服务器错误。

我们已经创建了`XMLHttpRequest`对象并打开了连接；我们还添加了一个回调来在请求成功时执行事件。需要记住的一件事是，请求尚未发出；我们只是为请求奠定了基础工作。我们将使用`send()`方法将请求发送到服务器，如下所示：

![进行第一次 AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_14.jpg)

在我们的`onreadystateChange`回调中，我们将发送的响应记录到控制台窗口中。让我们快速看一下响应是什么样子的：

![进行第一次 AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_15.jpg)

确认这是一个 AJAX 请求的一种方法是查看控制台中的第一个请求，在那里会对`index.php`文件进行异步调用，响应返回的 HTTP 状态码为`200 OK`。由于 HTTP `status`值为`200`，回调的执行将是成功的，并且将`students` JSON feed 输出到控制台窗口。

随着强大的 JavaScript 库的出现，如 jQuery、Scriptaculous、Dojo 和 ExtJS，我们已经摆脱了制作 AJAX 请求的古老过程。需要记住的一件事是，尽管我们不使用这个过程，但这些库仍然会在幕后使用这个过程；因此了解`XMLHttpRequest`对象的工作原理非常重要。jQuery 是一个非常受欢迎的 JavaScript 库；它有一个庞大的开发者社区。由于 jQuery 库是根据 MIT 许可证分发的，因此允许用户免费使用该库。

jQuery 是一个非常简单、强大的库，具有出色的文档和强大的用户社区，使开发者的生活变得非常容易。让我们快速绕个弯，用 jQuery 编写我们的传统的 Hello World 程序：

![进行第一次 AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_16.jpg)

在前面的屏幕截图中，我们将 jQuery 库导入到我们的 HTML 文件中，在第二组脚本标签中，我们使用特殊字符`$`或 jQuery。类似于面向对象编程中的命名空间的概念，`jQuery`功能默认命名空间为特殊字符`$`。jQuery 一直是不显眼的 JavaScript 的倡导者。在`$`之后，我们调用`document`对象，并检查它是否已加载到页面上；然后我们分配一个回调函数，该函数将在文档完全加载时触发。这里的“`document`”是保存 HTML 元素结构的`document`对象。这个程序的输出将是`Hello World!`字符串，它将被输出到我们的控制台窗口中。

# 解析 JSON 数据

```js
document object. We have a div element that has an empty unordered list. The aim of this script is to populate the unordered list with list items on the click of a button. The input button element has an id with the value "getFeed", and the click event handler will be tied to this button. Since AJAX is asynchronous and as we are tying a callback to this button, no AJAX calls are made to our live server when the document object is loaded. The HTML structure alone is loaded onto the page, and the events are tied to these elements.
```

当按钮被点击时，我们使用`getJSON`方法向实时网络服务器发出 AJAX 调用，以检索 JSON 数据。由于我们得到了一个学生数组，我们将传入检索到的数据到 jQuery 的`each`迭代器中，以便逐个检索元素。在迭代器内部，我们正在构建一个字符串，该字符串作为列表项附加到`"feedContainerList"`无序列表元素上。

![解析 JSON 数据](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_18.jpg)

在文档加载时，由于我们只将事件绑定到 HTML 元素，除非我们点击按钮，否则不会有任何行为变化。一旦我们点击按钮，无序列表将被填充。

![解析 JSON 数据](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_04_19.jpg)

# 摘要

自`XMLHttpRequest`对象的流行以来，它已成为 Web 开发人员的福音。在本章中，我们从基础知识开始，比如我们需要进行 AJAX 请求。一旦我们分析了 AJAX 所需的基本软件堆栈，我们就会继续了解`XMLHttpRequest`对象如何负责发出异步请求的基本概念。然后，我们跨入了最强大的 JavaScript 库之一，jQuery，使用 jQuery 执行 AJAX 操作。这只是我们进入 AJAX 之旅的开始；在下一章中，我们将看到更复杂的情况，其中使用 AJAX 的情况，跨域异步请求失败的情况，以及 JSON 通过允许我们进行跨域异步调用来挽救一天。


# 第五章：跨域异步请求

在上一章中，我们使用了 jQuery 的`getJSON`方法来获取`students` JSON 数据；在本章中，我们将迈出一步，将请求参数发送到服务器。数据源通常提供大量数据；这些数据通常是通用的，对于目标搜索来说可能太重了。例如，在`students` JSON 数据中，我们公开了可用的所有学生信息列表。对于寻找已注册某些课程的学生或居住在特定邮政编码区域以雇佣他们为实习生的数据供应商来说，这个数据源将是通用的。通常可以看到开发团队构建**应用程序编程接口**或**API**，为这样的数据供应商提供多种方式来定位他们的搜索。这对于数据供应商和拥有信息的公司来说都是双赢的，因为数据供应商只获取他们正在寻找的信息，数据供应商只发送请求的数据，从而节省了大量带宽和服务器资源。

# 使用 JSON 数据进行 GET 和 POST AJAX 调用

重要的是要理解同步和异步调用都是通过 HTTP 进行的，因此数据传输过程是相同的。从客户端机器到服务器机器传输数据的常用方法是`GET`和`POST`。HTTP 中最常见的请求方法是`GET`。当客户端请求网页时，Web 服务器使用 URL 处理 HTTP 请求。附加到 URL 的任何其他参数都作为从客户端发送到服务器的数据。由于参数是 URL 的一部分，因此很重要明确区分何时使用何时不使用`GET`请求方法。`GET`方法应该用于传递幂等信息，例如页面编号、链接地址或分页的限制和偏移量。请记住，通过`GET`请求方法可以传输多少数据存在大小限制。

`POST`请求方法通常用于发送大量数据和非平凡数据。与`GET`方法不同，数据通过 HTTP 消息主体传输；我们可以使用诸如 Fiddler 和浏览器中可用的开发者工具来跟踪通过 HTTP 消息主体传出的数据。通过`POST`方法传递的数据不能被书签或缓存，不同于`GET`方法。`POST`方法通常用于在使用表单时发送数据。在本章的示例中，让我们使用 jQuery 的`ajax`方法以 JSON 格式将数据发送到服务器。我们将使用修改后的`students` API，在那里我们将能够查询完整的学生信息—他们居住的邮政编码、他们所上的课程等，并使用组合搜索来找到居住在某个地区并上某个课程的学生。我们 API 的一个新功能是通过`POST`请求添加学生；学生信息必须以 JSON 对象的形式发送。

### 注意

这个 API 是用 PHP 和 MySQL 构建的。PHP 和 MySQL 文件将在代码包中的`scripts-chap5`文件夹中提供。

在我们开始构建脚本进行异步调用之前，让我们先看一下我们的`students` API 提供的 URL。第一个 API 调用将是通用搜索，将检索数据库中所有学生的信息。

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_01.jpg)

由于我们还没有开始我们的目标搜索，因此 URL 已保留为通用搜索。现在让我们看看我们第一个目标搜索的 URL—按邮政编码搜索。这个 API 调用将返回居住在给定邮政编码区域的所有学生。

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_02.jpg)

在这个例子中，该 URL 将返回所有居住在`08810`邮政编码的学生的信息。让我们将搜索条件从 ZIP 码切换到学生已经报名的课程。

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_03.jpg)

在这个例子中，该 URL 将返回所有已经报名参加`经济学`课程的学生的信息。现在我们有了通过 ZIP 码和课程来定位搜索的能力，让我们来看看我们的 API 中另一个调用，通过用户所在的 ZIP 码和他或她已经报名的课程来检索信息。

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_04.jpg)

在这个例子中，对 URL 的调用将返回所有已经报名参加`会计学`课程并居住在`77082`邮政编码的学生的信息。

到目前为止，这些调用都是使用 HTTP `GET`方法从客户端向服务器传输数据。我们 API 中的最后一个调用是使用 HTTP `POST`方法来添加学生。这个调用需要大量的数据输入，因为用户可以有多个 ZIP 码和多个地址，并且可以报名多个课程。

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_05.jpg)

```js
get-students.html:
```

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_06.jpg)

在这个调用中，我们首先导入 jQuery 库；我们可以开始使用`$`变量，因为页面上有 jQuery。我们首先添加一个回调函数，当文档准备就绪时触发。我们在这个例子中使用`ajax`方法，因为它允许我们进行`GET`和`POST`请求，并且在需要时，我们可以修改`ajax`调用中的`datatype`属性为`JSONP`，以进行异步跨域调用。

### 注意

不需要明确说明类型为 GET 时，但这有助于我们构建代码的一致性。

在我们的`ajax`调用中，我们首先将`url`属性设置为检索学生信息的 API 调用链接；我们指定这将通过 HTTP `GET`方法执行。我们设置的第四个属性是`dataType`属性；这用于指定我们期望返回的数据类型。因为我们正在处理`students`数据，所以我们必须将`dataType`属性设置为 JSON。重要的是要注意`done`回调，当服务器发送响应到我们的异步请求时触发。我们将从服务器发送的数据作为响应传递，并启动回调。

### 注意

`done`与`readyState=4`和`request.status=200`是相同的；我们在第四章中已经看过这个，*使用 JavaScript 进行异步调用*。

以下是输出：

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_07.jpg)

在控制台窗口中，我们可以查看从服务器返回的 JSON 数据。这个 JSON 数据包含了很多信息，因为它获取了所有学生的数据。现在让我们根据 ZIP 码获取学生记录。在这个例子中，我们将使用`zip_code`参数，并将通过 HTTP `GET`方法异步地将一个值传递给服务器。这个 API 调用将为希望在特定地区搜索实习生的数据供应商提供服务。

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_08.jpg)

在前面的例子中，我们首先导入了 jQuery 库，并绑定了一个回调函数来准备文档加载时触发的事件。重要的是要注意，我们在第 12 行使用`data`属性发送了一个 ZIP 码的键值对。

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_09.jpg)

一旦调用被触发，我们就会将响应记录到控制台窗口。邮政编码`08810`匹配了一个用户，并且学生信息通过 JSON 反馈传递回来。定向搜索帮助我们缩小结果范围，从而为我们提供我们正在寻找的数据；下一个目标搜索将是使用学生注册的特定课程来检索数据。

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_10.jpg)

前面的例子与使用邮政编码的定向搜索相同；在这里，我们用课程信息替换了邮政编码信息。我们正在检索所有已经注册`经济学`课程的学生。

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_11.jpg)

针对性搜索返回了已经注册经济课程的学生信息。现在让我们用课程和邮政编码的组合来定位我们的搜索。

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_12.jpg)

在前面的例子中，我们添加了课程和邮政编码的键值对，以向服务器发送多个搜索参数。

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_13.jpg)

这个调用检索了已经注册`会计`课程并居住在邮政编码`77082`的学生信息。我们已经看到了通过 HTTP `GET`方法进行异步调用的多个例子；现在是时候将数据推送到服务器，以便使用我们的 API 添加学生。我们将使用我们的`addUser`调用来实时添加学生。这有助于开发团队从外部资源向我们的数据库添加学生信息。例如，我们是学生信息聚合器，我们将整合的学生信息卖给多个数据供应商。为了整合所有这些信息，我们可能会通过蜘蛛进行整合，其中脚本将访问网站并获取数据，或者通过外部资源进行整合，其中数据将是非结构化的。因此，我们将构造我们的数据并使用`addUser` API 调用将结构化的学生数据信息摄入到我们的数据存储中。同时，我们可以向信任的数据供应商公开这种方法，他们希望将我们没有的学生信息存储在远程位置，从而帮助他们将我们的数据存储成为单一数据位置。这对两家公司来说都是双赢，因为我们获得了更多的学生信息，而我们的数据供应商可以将他们的学生信息存储在远程位置。现在让我们看看这个`addUser`的 POST 调用将如何进行。

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_14.jpg)

在这个调用中，我们正在做多件事情；我们首先声明一些变量来保存本地数据。我们有本地变量来保存学生的名字和姓氏的字符串值，还有保存课程、邮政编码和地址的数组变量，就像超人需要在几分钟内出现在多个地方一样。在我们的`ajax`调用中，要注意的第一个变化是`type`属性；因为我们正在推送大量用户数据，通常会使用 HTTP `POST`方法。`data`属性将使用为名字、姓氏、地址、邮政编码和课程声明的本地变量。从 API 中，当用户成功添加到数据库时，我们会发送一个成功消息作为响应，并将其记录到我们的控制台窗口中。

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_15.jpg)

现在，为了验证新学生是否已经添加到我们的数据库中，我们可以运行我们的`getStudents` API 调用，以查看所有用户的列表。

![使用 JSON 数据进行 GET 和 POST AJAX 调用](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_16.jpg)

`students` feed 中的最后一个学生是`Kent Clark`；测试我们的代码以确保一切都按预期工作是非常重要的。因为我们正在处理动态数据，因此保持数据完整性非常重要。每当对用户或其依赖项执行 CRUD 操作时，都必须通过查看检索到的数据并执行数据验证检查来验证该数据存储的数据完整性。

# 跨域 AJAX 调用的问题

到目前为止，我们所做的所有异步调用都是在同一个服务器上。有时我们会希望从不同的域加载数据，比如从其他 API 获取数据。服务器端程序被设计来处理这些调用；我们可以使用 cURL 来对不同的域进行 HTTP 调用以获取这些数据。这增加了我们对服务器端程序的依赖，因为我们需要对我们的服务器进行调用，然后服务器再对另一个域进行调用以获取数据，然后返回给客户端程序。这可能看起来是一个微不足道的问题，但我们在我们的 Web 架构中增加了一个额外的层。为了避免进行服务器端调用，让我们尝试看看是否可以对不同的域进行异步调用。在这个例子中，让我们使用 Reddit 的 JSON API 来获取数据。

![跨域 AJAX 调用的问题](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_17.jpg)

这类似于我们之前所做的异步调用，用于从我们的`students` API 中检索数据。重要的是要理解，在以前的情况下，我们不必在 URL 中提到整个 URL，因为我们是在同一个域中进行调用。

![跨域 AJAX 调用的问题](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_18.jpg)

Reddit 网站提供了一个出色的 JSON API，我们可以在 URL 后面添加`.json`，就可以获取到该聚合网页的 JSON 源，前提是该页面是 Reddit 的一部分。让我们来看看当我们跨域进行这个异步调用时生成的输出。

![跨域 AJAX 调用的问题](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_19.jpg)

在我们的异步调用中，如果请求成功，数据将被记录到控制台窗口，但我们在控制台窗口中看到了一个错误。错误显示`XMLHTTPRequest`对象无法加载我们提供的 URL，因为它不是源自我们的[www.training.com](http://www.training.com)域的。**同源策略**是 Web 浏览器遵循的安全措施，以防止一个域访问另一个域上的信息。Web 应用程序使用 cookie 来存储有关用户会话的基本信息，以便在用户再次请求同一网页或请求同一域上的不同网页时提供直观的用户体验。为了防止外部网站窃取这些信息，Web 浏览器遵循**同源策略**。

同源策略在传入请求中寻找三样东西；它们是主机、端口和协议。如果其中任何一个与现有域不同，请求将无法完成，会返回跨域错误。

| 变体 http://www.training.com | 结果 |
| --- | --- |
| `http://www.training.com/index.php` | 通过 |
| `https://www.training.com/index.php` | 失败（协议） |
| `http://www.training:81.com/index.php` | 失败（端口） |
| `http://test.training.com.com/index.php` | 失败（主机） |
| `http://www.differentsite.com/index.php` | 失败（主机） |

# JSONP 介绍

为了绕过同源策略，我们将使用 JSONP，即带填充的 JSON。同源策略的一个例外是`<script>`标签，因此可以跨域传递脚本。JSONP 利用这个例外来将数据作为脚本传递到不同的域，通过添加填充使 JSON 对象看起来像一个脚本。在 JavaScript 中，当调用带有参数的函数时，我们调用函数并添加参数。使用 JSONP，我们将 JSON 数据流作为参数传递给一个函数；因此，我们将我们的对象填充到一个函数回调中。必须在客户端使用这个填充了 JSON 数据流的函数来检索 JSON 数据流。让我们快速看一个 JSONP 的例子。

![JSONP 简介](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_20.jpg)

在这个例子中，我们将`students`对象填充到`myCallback`函数中，并且我们必须重用`myCallback`函数以检索`students`对象。现在我们了解了 JSONP 的工作原理，让我们使用 Reddit 的 JSON API 来获取数据。我们需要对访问数据的方式进行一些更改——我们需要找到一种方式将数据流填充到一个可以在客户端使用的回调中。Reddit 网站提供了一个`jsonp` `GET`参数，该参数将获取回调的名称以提供数据。

![JSONP 简介](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_21.jpg)

# 实现 JSONP

我们正在使用与之前相同的 URL 来获取数据，但是我们已经添加了`jsonp`参数，并将其设置为`getRedditData`；重要的是要注意，现在该数据流已经填充到我们的回调`getRedditData`中。现在让我们替换之前脚本中的 URL 属性，创建一个新的脚本来获取 JSON 数据流。

![实现 JSONP](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_22.jpg)

一些属性，如`url`和`dataType`已经被修改，一些新属性，如`contentType`和`jsonpCallback`已经被添加。我们已经讨论了`url`属性的更改，现在让我们看看其他属性。

![实现 JSONP](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_23.jpg)

早先，`dataType`属性被设置为`json`，因为传入的数据流是`json`类型，但是现在 JSON 数据流被填充到一个回调中，因此必须进行切换，以便浏览器期望的是回调而不是 JSON 本身。已添加的新属性是`contentType`和`jsonpCallback`；`contentType`属性指定要发送到 Web 服务器的内容类型。`jsonpCallback`获取填充了 JSON 数据流的回调函数的名称。

![实现 JSONP](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_05_24.jpg)

当脚本被触发时，从`getRedditData`回调中检索到的数据被传递到`success`属性中，将我们的 JSON 对象记录到控制台窗口中。一个重要的事实需要注意，JSONP 调用是一个脚本调用，而不是 XHR 请求，因此 JSONP 调用将在`JS`或`<scripts>`标签中可用，而不是在控制台窗口的`XHR`标签中。

# 总结

HTTP `GET`和`POST`请求方法是用于从客户端向服务器传输数据的最流行的 HTTP 方法之一。本章深入了解了如何使用异步请求来传输数据的`GET`和`POST`请求方法。然后，我们继续研究跨域异步请求的问题；我们利用`<script>`标签的例外来执行我们的 JSONP 异步脚本调用，以从不同的域获取数据。在下一章中，我们将构建我们的照片库应用程序。


# 第六章：构建 Carousel 应用程序

我们在掌握 JavaScript 和 JSON 的旅程中走了很长一段路；现在是时候忙起来，构建一个由 JSON 驱动的端到端项目。在我们的旅程中，我们遇到了各种概念，如 JavaScript、JSON、服务器端编程的使用、AJAX 和 JSONP。在这个照片库应用程序中，让我们把所有这些都用起来。我们将构建一个旋转通知板应用程序，它应该显示本月的顶尖学生。这个应用程序应该提供 Carousel 功能，如导航按钮、自动播放内容、在给定点显示单个项目，并跟踪第一个和最后一个内容。

# 设置应用程序

让我们开始建立一个文件夹，用于保存这个应用程序的文件。这个应用程序将需要一个包含 Carousel 的 HTML 文件；它将需要一些库，如 jQuery 和 jQuery Cycle。我们将不得不导入这些库；我们还需要一个包含这个练习数据的 JSON 文件。要下载 jQuery 文件，请访问[`www.jquery.com`](http://www.jquery.com)。正如我们已经观察到的，jQuery 是开发人员可用的最流行的 JavaScript 库。有一个日益增长的开发者社区，他们使 jQuery 变得越来越受欢迎。我们将使用 jQuery Cycle 库来驱动我们的 Carousel 应用程序。jQuery Cycle 是最受欢迎和轻量级的循环库之一，具有众多功能；它可以从[`malsup.github.io/jquery.cycle.all.js`](http://malsup.github.io/jquery.cycle.all.js)下载。

这些文件必须在文档根目录内的一个文件夹中；在这个项目中，我们将使用一个实时 Apache 服务器，并且我们将通过 AJAX 摄取 JSON feed。以下是文件添加后文件夹应该看起来的示例：

![设置应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_06_01.jpg)

现在我们已经在文档根目录中安排好了库，让我们来制作一个基本的 HTML 文件，将这些文件导入到网页中，如下面的截图所示：

![设置应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_06_02.jpg)

index-v1.html

这是我们的初始索引网页，将 JavaScript 文件加载到网页上。当通过 Web 浏览器启动此文件时，必须加载两个 JavaScript 库，并且`ready`应该打印到控制台窗口。现在，让我们继续构建我们的 Carousel 应用程序。接下来的要求是数据文件；它将类似于我们在之前章节中使用的`students` JSON feed。我们将把它们加载到旋转应用程序中，而不是将它们全部打印在一行中。

# 为 Carousel 应用程序构建 JSON 文件

让我们假设我们是一所教育机构，我们有一个传统，即每月承认我们学生的努力。我们将挑选每个课程的顶尖学生，并在我们的通知板旋转应用程序上显示他们的名字。这个通知板旋转应用程序经常作为其他学生的动力，他们总是希望自己能上榜。这是我们教育机构鼓励学生在课程中表现良好的方式。示例 JSON feed 将如下截图所示：

![为 Carousel 应用程序构建 JSON 文件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_06_03.jpg)

对于我们的通知板旋转应用程序，我们将需要基本的学生信息，如名字、姓氏、当前教育水平和他们擅长的课程。

![为 Carousel 应用程序构建 JSON 文件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_06_04.jpg)

index-v2.html

在上述截图中，我们使用 jQuery 的`getJSON()`函数将 JSON 数据引入文档中。当`index-v2.html`文件加载到浏览器中时，`students` JSON 对象数组将加载到控制台窗口上。现在是时候开始从 JSON 对象中提取数据，并开始将其嵌入到 DOM 中。让我们使用 jQuery 的`each()`函数循环遍历`students` JSON 数据并将数据加载到页面上。

jQuery 中的`each()`函数类似于流行的服务器端语言中提供的`foreach()`迭代循环，以及原生 JavaScript 中提供的`for in()`迭代循环。`each()`迭代器将数据作为其第一个参数，并将该数据中的每个项作为单个键值对迭代地传递到回调函数中。这个回调是一系列在该键值对上执行的脚本。在这个回调中，我们正在构建将附加到 DOM 上的`div`元素的 HTML 文件。我们使用这个回调来迭代地构建`students` JSON 对象中存在的所有元素的 HTML 文件。

![为 Carousel 应用程序构建 JSON 文件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_06_05.jpg)

index-v3.html

在`index-v3.html`文件中，我们使用 jQuery 的`each()`函数来遍历`students` JSON 数据，并构建将显示学生信息的 HTML 文件，例如名字，姓氏，大学年级和所注册的课程。我们正在构建动态 HTML 并将其分配给`html`变量。`html`变量中的数据将稍后添加到 ID 为`students`的`div`元素中。如下截图所示：

![为 Carousel 应用程序构建 JSON 文件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_06_06.jpg)

上述截图显示了`index-v3.html`主体的输出：

![为 Carousel 应用程序构建 JSON 文件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_06_07.jpg)

当脚本加载到 Web 浏览器中时，脚本会检查文档是否准备就绪。一旦文档准备就绪，就会向服务器发出 AJAX 调用以检索 JSON 数据。检索到 JSON 数据后，`students` JSON 对象数组中的每个对象都将传递到生成带有`student`类的 HTML `div`元素的回调函数中。这将重复，直到在最后一个元素上执行回调，一旦在最后一个元素上执行回调，此 HTML 文件将附加到具有 ID 为`students`的 HTML 中的`div`元素中。

# 使用 jQuery Cycle 创建 Carousel 应用程序

我们已经开发了一个网页，将所有学生数据加载到 HTML 文件中；现在是时候使用这些数据构建 Carousel 应用程序了。我们将使用 jQuery Cycle 插件来在我们的公告板应用程序上旋转学生信息。jQuery Cycle 是一个幻灯片插件，支持多种类型的过渡效果在多个浏览器上。可用的效果包括`fade`、`toss`、`wipe`、`zoom`、`scroll`和`shuffle`。该插件还支持有趣的悬停暂停功能；还支持点击触发和响应回调。

对于我们的 Carousel 示例，让我们保持简单，使用基本选项，例如淡入淡出效果来旋转学生，启用暂停，以便用户悬停在循环上时，旋转应用程序会暂停以显示当前学生的信息。最后，我们将设置速度和超时值，以确定从一个学生过渡到另一个学生需要多长时间。

![使用 jQuery Cycle 创建 Carousel 应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_06_08.jpg)

index-v4.html

在上面的截图中，我们设置了`cycle`插件，并将`cycle`插件添加到`students`的`div`元素中。`cycle`插件以 JSON 对象作为其参数，以向`div`元素添加旋转功能。在这个 JSON 对象中，我们添加了四个属性：`fx`、`pause`、`speed`和`timeout`。`fx`确定在`html`元素上执行的效果。`fade`是`cycle`插件中常用的效果。jQuery Cycle 插件支持的其他流行效果包括 shuffle、zoom、turndown、scrollRight 和 curtainX。我们使用的第二个属性是`pause`属性，它确定当用户悬停在`rotator`元素上时旋转是否已停止；它接受一个 true 和 false 值来确定旋转是否可以暂停。我们可以提供布尔值，如 True 或 False，或传递一个表示 True 和 False 的 1 或 0。接下来的两个属性是`speed`和`timeout`；它们确定旋转发生的速度以及在显示下一项之前需要多长时间。当包含更新脚本的网页加载到 Web 浏览器中时，整个`students`对象被解析为本地 JavaScript 字符串变量，并附加到 DOM，只有该旋转对象中的第一个元素被显示，而其余元素被隐藏。这个功能由`cycle`插件在后台处理。下面的截图显示了从之前的代码示例生成的 Carousel：

![使用 jQuery Cycle 创建 Carousel 应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_06_09.jpg)

让我们通过添加早期和后续处理程序来增强此页面的用户体验，以便为用户提供自定义控制器来处理旋转功能，如下面的截图所示：

![使用 jQuery Cycle 创建 Carousel 应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_06_10.jpg)

index-v5.html

在`cycle`对象中，我们添加了两个名为`prev`和`next`的新属性。`prev`和`next`属性的值将是 DOM 上存在的元素的 HTML `id`属性。为了处理这一变化，HTML 文件必须修改如下：

![使用 jQuery Cycle 创建 Carousel 应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_06_11.jpg)

在上面的截图中，我们添加了两个`id`值为`prev`和`next`的锚元素，这些元素在`cycle`对象中被引用。

![使用 jQuery Cycle 创建 Carousel 应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_06_12.jpg)

在上面的截图中显示的**Prev**和**Next**链接将处理我们的公告板旋转应用程序的旋转。这是使用 jQuery 和 JSON 构建 Carousel 应用程序的快速方法。这个示例可以用来构建更复杂的 Carousel 应用程序，可以分别包含图片和视频，用于照片和视频库 Carousel 应用程序。

# 总结

在本章中，我们将 JavaScript、jQuery 和 JSON 知识付诸实践，构建了一个整洁的 Carousel 公告板旋转应用程序。我们逐步进行了数据源的摄取、从数据源动态生成模板、将数据源附加到`div`元素，然后将`div`元素绑定到`cycle`插件。这个公告板旋转应用程序为我们提供了一个洞察更大的 Carousel 项目，可以用很少的开发工作来开发。在下一章中，我们将看看 JSON 的替代实现。


# 第七章：JSON 的替代实现

在之前的章节中，我们已经将 JSON 作为 HTTP 数据交换格式进行了处理；现在让我们看看 JSON 被使用的流行替代方法。在过去的几年中，各种编程和脚本语言中的软件模块和包的数量急剧增加。众包软件开发一直在上升。像 SourceForge、Pastebin 和 GitHub 这样的基于网络的托管服务在过去几年中变得越来越受欢迎，并为开发人员合作和回馈社区打开了大门。这些模块和包可以独立集成，也可以作为现有软件框架的依赖程序使用。这种行为在开源社区中是一种常见做法，开发人员可以独立工作，贡献增强他们正在使用的框架的软件包。

诸如 PHP、Python 和 JavaScript 之类的脚本语言拥有大量的贡献软件包和模块。这里的优势是使用预构建的软件包，它提供了某些功能，并且已经经过社区的大量测试。引入单个框架或多个框架到软件项目中的反面是必须了解这些框架如何加载到项目中，它们如何从当前项目的不同部分访问，这些框架是否有任何依赖关系，最后，它们如何影响整个项目。这些问题可以通过使用**依赖管理器**来解决。

依赖管理器是一个软件程序，它跟踪所有必要的基本程序，这些程序是依赖程序运行所必需的。在软件开发生命周期中的一个常见做法是使用单元测试框架进行单元测试；单元测试框架可能需要安装一些基本库，或者可能需要一些设置来启用该框架的使用。

这些操作通常通过编写快速脚本来处理，但随着项目规模的增长，依赖项也随着项目的增长而增加。同样，跟踪这些变化并确保不同团队在项目上的更新，这是通过脚本完成的，是一项艰巨的任务。通过引入依赖管理器，我们将自动化整个过程，这将增加一致性并节省时间。

# 依赖管理

依赖管理通常有点困难，对于新加入的开发人员来说，将新框架添加到他们的项目中，设置项目并使其运行可能是令人生畏的。像 Composer for PHP 这样的依赖管理器解决了这个问题。它被认为是所有项目之间的“粘合剂”，这是有充分理由的。Composer 使用 JSON 来跟踪给定项目的所有依赖关系。Composer 的主要工作是从远程位置下载库并将其存储在本地。为了告诉 Composer 我们需要哪些库，我们需要设置`composer.json`文件。这个文件跟踪所有特定的库、它们的版本以及给定库应该部署到的环境。例如，一个单元测试框架库永远不应该进入生产环境。在一个旧公司中，有一个同事随机测试我们的生产实例，通过运行一个单元测试删除了整个用户表；我们不得不从前一晚的数据库备份中恢复整个用户表。

让我们快速深入了解 JSON 是如何用于处理依赖管理的。

![依赖管理](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_07_01.jpg)

composer.json

在`composer.json`文件中，我们添加了两个要求，以安装特定版本的 PHP 和 PHPUnit。一旦文件添加到项目中，我们可以使用 Composer 的`install`命令来安装这些依赖项。Composer 还带有一个`update`命令，负责对给定包进行的任何更新。

### 注意

有关 Composer 的更多信息，请访问[`www.getcomposer.org`](http://www.getcomposer.org)。

`Node.js`是一个流行的软件平台，使用 JSON 数据格式来跟踪依赖关系。**Node Packaged Modules**（**NPM**）是开发人员用于安装和集成外部模块到他们的代码中的包管理器。对于每个`Node.js`项目，在文档根目录中都有一个`package.json`文件，用于跟踪所有元数据，如项目名称、作者名称、版本号、运行该项目所需的必需模块，以及运行该项目所需的底层守护程序或引擎。让我们来看一个我`Node.js`项目中的`package.json`文件的示例。

![依赖管理](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_07_02.jpg)

package.json

`package.json`文件是一个大的 JSON 对象，用于跟踪元数据，如项目的名称、作者的详细信息和所需的模块。

### 注意

有关 NPM 的更多信息，请访问[`www.npmjs.org`](https://www.npmjs.org)。

# 存储元数据的 JSON

与依赖管理器相同，JSON 也用于存储软件项目的元数据。在 JSON 变得流行之前，配置和元数据要么存储在文本文件中，要么存储在特定于语言的文件中，例如 PHP 的`config.php`，Python 的`config.py`和 JavaScript 的`config.js`。所有这些现在都可以被一个与语言无关的`config.json`文件替代；对于非 JavaScript 库，请使用 JSON 库来解析它。让我们快速看一个示例`config.json`文件：

![用于存储元数据的 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_07_03.jpg)

config.json

在`config.json`文件中，我们将元数据存储为 JSON 对象。我们指定了一些重要信息，如项目名称，项目的环境（根据文件所在的服务器而变化），在引导应用程序期间必须自动加载的任何类，以及我们想要排除的任何类或文件夹。最后，使用`RECURSIVE`键，我们还指定了有文件夹和这些文件夹有文件。

### 注意

引导是应用程序的启动过程，在这个过程中，我们准备该应用程序以实现其目的。

一旦我们有了`config.json`文件，我们可以使用 Python 中的`json.loads`方法，或者我们可以使用 PHP 中的`json_decode`方法来解析配置对象以检索数据。JSON 对象也可以用来存储数据库模式；这有助于开发团队的其他成员在团队中的一个开发人员对数据库进行更改时更新他们的数据库模式。处理这个的一个聪明方法是在`schema.json`文件上编写一个触发器，如果该文件有更新，数据库中的模式必须通过数据库迁移脚本反映新的更改。让我们快速看一个示例`schema.json`文件。

![用于存储元数据的 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_07_04.jpg)

schema.json

在`schema.json`示例中，我们正在构建将存储数据库模式信息的模式 JSON 对象。`client`是我们模式中表的名称。`client`表有三列——客户端的 ID、名称和状态，即客户端是否启用或禁用。每个列都包含列 JSON 对象，提供模式信息，如列的数据类型和大小，是否具有默认值或主键约束。

# 与 YAML 的比较

YAML 是另一种软件语言无关的数据交换格式，正在逐渐流行起来。**YAML**是**YAML Ain't Markup Language**的递归缩写，通常用于存储配置、模式和属性等元数据。YAML 被认为是一种人类可读的数据序列化标准，依赖于空格、定位和简单字符作为行终止符，类似于流行的脚本语言如 Ruby 和 Python。YAML 对元素之间的间距要求很严格，不友好地使用制表符。与 JSON 类似，YAML 的键/值对由冒号分隔。与文本格式类似，使用连字符来表示列表项，不同于 JSON，其中列表项放在数组或子对象中。由于 YAML 是软件语言无关的，我们需要解析器来理解文件中的内容。大多数流行的语言，如 PHP、Python、C++、Ruby 和 JavaScript，都有这样的解析器。让我们构建一个 YAML 格式的`config.json`文件来了解 YAML 是什么。

![与 YAML 的比较](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_07_05.jpg)

config.yaml

与我们的 config JSON 对象类似，YAML 文件包含所有数据；不同之处在于数据的排列方式——作为一系列项目——以及如何使用间距和定位来排列数据列表。互联网上有多个 YAML 资源可用于验证、序列化和反序列化 YAML 数据。

### 注意

有关 YAML 的更多信息，请访问[`www.yaml.org`](http://www.yaml.org)，该网站以 YAML 格式表示。

# 摘要

JSON 迅速成为互联网上最流行的数据交换格式，但它并不仅限于数据交换。我们还可以使用 JSON 来存储依赖管理器、包管理器、配置管理器和模式数据存储的元数据。我们介绍了 YAML，它被认为是 JSON 的一种替代方案。在下一章中，我们将看看可以用来调试、验证和格式化 JSON 的不同资源。


# 第八章：调试 JSON

JSON 在过去几年里取得了长足的发展，因此有大量免费资源可供我们了解我们正在使用的 JSON 对象。正如我们之前讨论过的，JSON 可以用于多种目的，重要的是要了解可能破坏 JSON 的简单事情，比如忽略双引号，或在 JSON 对象中的最后一项上使用尾随逗号，或者 Web 服务器发送错误的内容类型。在本章中，让我们讨论一下我们可以调试、验证和格式化 JSON 的不同方法。

# 使用开发者工具

几乎所有主流浏览器，如 Mozilla Firefox，Google Chrome，Safari 和 Internet Explorer，都有强大的调试工具，帮助我们了解正在进行的请求和返回的响应。JSON 可以是请求的一部分，也可以是响应的一部分。Google Chrome，Safari 和较新版本的 Internet Explorer 都内置了开发者工具。Firebug 是一个非常受欢迎的 Web 开发工具包，适用于 Mozilla Firefox。Firebug 是一个外部插件，必须安装在浏览器上；它是最早为了帮助 Web 开发人员使用 Firefox 而构建的 Web 开发工具包之一。

### 注意

要安装 Firebug，请访问[`getfirebug.com/`](http://getfirebug.com/)，并在登陆页面上点击**安装 Firebug**。

这些开发者工具提供对 HTML DOM 树的访问，并实时了解 HTML 元素在页面上的排列方式。开发者工具配备了一个网络（或**Net**）选项卡，允许我们跟踪所有资源，如图像、JavaScript 文件、CSS 文件、Flash 媒体以及客户端正在进行的任何异步调用。控制台窗口是开发者工具中的另一个受欢迎的功能。顾名思义，这个窗口为我们提供了一个运行时 JavaScript 控制台，用于测试任何即时脚本。要在 Firefox 上启动开发者工具，加载网页到浏览器中，右键单击网页；这将给我们一个选项列表，选择**使用 Firebug 检查元素**。要在 Google Chrome 和 Safari 上加载开发者工具，右键单击网页，然后从选项列表中选择**检查元素**。在使用 Safari 时，请记住必须启用开发者工具；要启用开发者工具，点击**Safari**菜单项，选择**首选项**，然后点击**高级**选项卡，并勾选**在菜单栏中显示开发菜单**以查看开发者工具。在 Internet Explorer 上，按下键盘上的*F12*键即可启动开发者工具窗口。在第四章中，我们首次对一个实时 Web 服务器进行了异步调用，以请求 JSON 数据使用 jQuery。让我们使用该程序并使用开发者工具调试数据；在本例中，我们将使用 Firefox 网页浏览器：

！使用开发者工具

jquery-ajax.html

在页面加载时，当用户右键单击并选择**使用 Firebug 检查元素**选项时，默认加载**HTML**选项卡，并且用户可以看到 HTML DOM。在我们的示例中，我们已经将`click`事件处理程序绑定到**获取 Feed**按钮。让我们看看在点击按钮后控制台输出的内容；要在控制台窗口中查看输出，点击**控制台**选项卡：

！使用开发者工具

一旦收到响应，JSON 源将被记录到控制台窗口的**Response**选项卡中。了解 JSON 源以解析它是很重要的，开发人员工具的控制台窗口为我们提供了分析 JSON 源的简单方法。让我们继续研究开发人员工具，并访问 Firefox 中的**Net**选项卡，以了解客户端和服务器如何通信以及客户端期望的数据内容类型：

![使用开发人员工具](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_08_03.jpg)

在 Net 窗口中，我们应该首先点击异步调用的 URL，该调用是向`index.php`发出的。一旦点击了该链接，在**Headers**部分，我们应该观察到**Accept**头部，它期望`application/json`的**MIME**类型，以及**X-Requested-With**头部是**XMLHttpRequest**，这表明这是一个异步请求。Net 窗口中的**Response**选项卡与控制台窗口中的**Response**选项卡相同，它将显示此请求的 JSON 源。在本书中，我们广泛使用了`console.log`方法，该方法将数据打印到控制台窗口，这是开发人员工具的另一个有用功能。

# 验证 JSON

与我们的调试资源类似，有很多流行的网络工具可以帮助我们验证我们构建的 JSON。**JSONLint**是最受欢迎的网络工具之一，可用于验证我们的 JSON 源。

### 注意

当我们使用诸如 PHP、Python 或 Java 之类的服务器端程序时，内置的 JSON 编码库会生成 JSON 源，通常该源将是有效的 JSON 源。

JSONLint 具有非常直观的界面，允许用户粘贴要验证的 JSON，并根据我们粘贴的 JSON 源返回成功消息或错误消息。让我们从验证一个错误的 JSON 开始，看看会返回什么错误消息，然后让我们修复它以查看成功消息。在这个例子中，我将复制上一个例子中的`students`源，并在第二个元素的末尾添加一个逗号：

![验证 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_08_04.jpg)

请注意，我们在 JSON 对象的最后一项中添加了一个逗号，而 JSONLint 最好的部分是提供了描述性的错误消息。我们遇到了一个**解析错误**，为了简化生活，消息还告诉我们错误可能出现的行号。解析器期望一个字符串、一个数字、一个空值或一个布尔值，因为我们没有提供任何值，所以我们遇到了这个错误。为了修复这个错误，我们要么必须向该 JSON 对象添加一个新项以证明逗号的存在，要么就必须去掉逗号，因为后面没有任何项了。

![验证 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_08_05.jpg)

一旦我们去掉了末尾的逗号并进行验证，我们就会收到成功消息。易用性和描述性消息使 JSONLint 成为 JSON 验证的首选网站之一。

### 注意

要使用 JSONLint，请访问[`www.jsonlint.com`](http://www.jsonlint.com)。

# 格式化 JSON

JSONLint 不仅是一个在线 JSON 验证器，它还可以帮助我们格式化 JSON 并使其看起来漂亮。通常 JSON 源的大小都很大，提供树形结构以遍历 JSON 对象的在线编辑器总是很有帮助。**JSON Editor Online**是我最喜欢的在线编辑器之一，它提供了一个易于导航的树形结构，可以处理和格式化大型 JSON 对象。

![格式化 JSON](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-json-ess/img/6034OS_08_06.jpg)

### 注意

要使用 JSON Editor Online，请访问[`www.jsoneditoronline.org`](http://www.jsoneditoronline.org)。

我们首先将我们的 JSON 示例代码粘贴到左侧窗口中，然后点击中间的右箭头按钮生成我们的树结构。一旦我们对树结构进行更改，我们可以点击左箭头按钮格式化我们的数据，使其准备在其他地方使用。

# 总结

调试、验证和格式化是开发人员永远不能忽视的三件事。在本章中，我们看了一些资源，比如用于浏览器的开发者工具包进行调试，以及如何利用这些开发者工具包，还了解了如何使用 JSONLint 进行验证和 JSON Editor Online 进行格式化。

这是*JavaScript 和 JSON 基础*的结尾，旨在为您提供关于数据如何以 JSON 数据格式存储和传输的深入了解。我们已经亲身体验了在同一域内通过 HTTP 异步请求传输 JSON，以及跨域的 HTTP 异步请求。我们还研究了 JSON 数据格式的替代实现。这是理解 JSON 并开发交互式和响应式网络应用的长期旅程的坚实开端。
