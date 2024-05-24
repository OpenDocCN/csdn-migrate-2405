# JavaScript JSON 秘籍（一）

> 原文：[`zh.annas-archive.org/md5/7BFA16E9EEE620D98CFF9D2379355647`](https://zh.annas-archive.org/md5/7BFA16E9EEE620D98CFF9D2379355647)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

JavaScript 对象表示法（JSON）迅速成为 Web 上结构化文档交换的通用语言，在很多领域中超越了 XML。这个成功的三个原因是很明显的：它与 JavaScript 配合良好，它简单，而且它 just works。然而，它成功的其他原因也很多。正如你将在本书的页面中看到的，它得到了各种语言和库的广泛支持，使得在各种场景下使用它变得非常容易。

在本书中，我提供了 JSON 常见用途的菜谱。你可以从头到尾阅读这本书，了解 JSON 在构建网络和独立应用程序中的所有用途。然而，它被组织成一本菜谱书，这样你可以快速查找解决当前问题的章节或菜谱。我建议快速浏览一下序言，了解内容分布，根据你的兴趣快速浏览第一章，*客户端 JSON 的读写*，或第二章，*服务器端 JSON 的读写*，然后直接跳到你最感兴趣的菜谱。

# 本书涵盖内容

第一章，*客户端 JSON 的读写*，提供了在多种客户端环境中读写 JSON 的菜谱，包括 JavaScript、C#、C++、Java、Perl 和 Python。

第二章，*服务器端 JSON 的读写*，采取了相反的视角，审视了 Clojure、C#、Node.js、PHP 和 Ruby 等典型服务器端语言中的 JSON。当然，你也可以用这些语言编写客户端应用程序，正如你也可以用 C#或 Java 编写服务器一样。因此，这些章节之间菜谱的划分有些任意性；选择一种语言，深入研究！

第三章，*在简单的 AJAX 应用程序中使用 JSON*，向你展示了如何将 JSON 应用于当今浏览器的数据交换。

第四章，*使用 JSON 在 jQuery 和 AngularJS 的 AJAX 应用程序中*，讨论了如何使用 JSON 与两个流行的网络框架，jQuery 和 Angular。

第五章，*使用 JSON 与 MongoDB*，向你展示了 MongoDB，一种流行的 NoSQL 数据库，如何使用 JSON 作为其存储文档格式，并提供了使用 MongoDB 作为网络应用程序中的 REST 服务的菜谱。

第六章，*使用 JSON 与 CouchDB*，向你展示了 CouchDB，另一种流行的 NoSQL 数据库，如何使用 JSON，以及如何在你的网络应用程序中使用 CouchDB 作为独立的 REST 服务。

第七章, *以类型安全的方式使用 JSON*, 探讨了你如何可以适应 JSON 的无类型性质，利用 C#，Java 和 TypeScript 等语言提供的类型安全，以减少你应用程序中的编程错误。

第八章, *使用 JSON 进行二进制数据传输*, 展示了你如何能够使用 JSON，即使它是一个基于文本的文档格式，如果你需要这样做，你仍然可以使用它来移动二进制数据。

第九章, *使用 JSONPath 和 LINQ 查询 JSON*, 有关于如何针对 JSON 文档编写查询，以获取你正在寻找的数据片段的菜谱。这与第五章, *使用 JSON 与 MongoDB* 和 第六章, *使用 JSON 与 CouchDB* 的菜谱结合时尤其强大。

第十章, *JSON 在移动平台上的应用*, 展示了使用 Android，iOS 和 Qt 的移动应用程序中使用 JSON 的菜谱。

# 本书你需要什么

与许多其他技术书籍不同，这本书专注于在其示例中涵盖广泛的支持技术。我不期望你立即就有经验或工具来尝试这本书中的每一个示例，尤其是。然而，列出几件事情是有帮助的。

你应该有一些编程经验，最好是 JavaScript。除非一个菜谱针对特定的编程语言，如 C#，这本书中的菜谱都是用 JavaScript 编写的。我这样做有两个原因。首先，因为 JSON 中的"J"代表 JavaScript（尽管它广泛适用于其他语言），而且，在当今时代，每个程序员至少应该对 JavaScript 有一个基本的了解。

就软件环境而言，一开始，你应该能够访问一个好的网络浏览器，如 Chrome，或者最近版本的 Safari，Firefox 或 Internet Explorer。你可以使用这些浏览器中的 JavaScript 运行时来尝试 JSON 并开始入门。

其次，很多客户端-服务器示例都使用了 Node.js。我选择 Node.js 进行服务器端示例编程，因为它也是 JavaScript，这意味着你在客户端和服务器之间移动时不需要跳过不同的语言语法。Node.js 在 Windows，Mac OS X 和 Linux 上运行得也很好，所以你应该不会遇到设置问题。

如果你对使用 JSON 与数据库感兴趣，CouchDB 或 MongoDB 是你的最佳选择，我在本书中讨论了这两者。你选择哪一个真的取决于你的领域和个人喜好。我在各种项目中使用了 5 年的 MongoDB，但最近喜欢上了 CouchDB 的一些功能和它对 RESTful 服务的集成支持。

最后，如果你是微软开发者，你可能会想特别注意本书中使用 Newtonsoft 的 Json.NET 的 C#示例。Json.NET 就是 C#中 JSON 应该的样子，它绝对值得你关注。

# 本书适合谁

如果你正在编写将结构化数据从一个地方移动到另一个地方的应用程序，这本书就是为你准备的。这尤其正确，如果你一直在使用 XML 来完成工作，因为完全有可能你用更少的代码和更少的数据开销在 JSON 中完成同样的工作。

尽管本书的章节在应用程序的客户端和服务器方面做了一些区分，但如果你是前端、后端或全栈开发者，都没有关系。使用 JSON 的原则适用于客户端和服务器，事实上，理解方程两边的开发人员通常会创建最好的应用程序。

# 章节

在本书中，你会找到几个经常出现的标题（准备，如何做，如何工作，还有更多，以及也见）。

为了清楚地说明如何完成一个食谱，我们按照以下方式使用这些节：

## 准备

本节告诉你食谱中会有什么内容，以及如何设置食谱所需的任何软件或任何初步设置。

## 如何做到…

本节包含遵循食谱所需的步骤。

## 它是如何工作的…

本节通常包括对上一节发生事情的详细解释。

## 还有更多…

本节包括关于食谱的额外信息，以使读者更加了解食谱。

## 也见

本节提供了对食谱其他有用信息的帮助性链接。

# 约定

在本书中，你会找到一些区分不同信息种类的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码字、数据库表名、文件夹名、文件名、文件扩展名、路径名、假 URL、用户输入和 Twitter 处理方式如下所示："让我们进一步看看`loads`和`dumps`。"

代码块如下所示：

```js
function doAjax() {
var xmlhttp;
  if (window.XMLHttpRequest)
  {
    // code for IE7+, Firefox, Chrome, Opera, Safari
    xmlhttp=new XMLHttpRequest();
  }
}
```

当我们希望将你的注意力吸引到代码块的某个特定部分时，相关的行或项目将被设置为粗体：

```js
function doAjax() {
var xmlhttp;
  if (window.XMLHttpRequest)
  {
    // code for IE7+, Firefox, Chrome, Opera, Safari
 xmlhttp=new XMLHttpRequest();
  }
}
```

任何命令行输入或输出如下所示：

```js
# cp /usr/src/asterisk-addons/configs/cdr_mysql.conf.sample
 /etc/asterisk/cdr_mysql.conf

```

**新术语**和**重要词汇**以粗体显示。例如在菜单或对话框中看到的屏幕上的词，在文本中如下所示："然后，你可能想要去**更多工具** | **JavaScript 控制台**。"

### 注意

警告或重要说明以这样的框出现。

### 技巧

技巧和窍门像这样出现。

# 读者反馈

来自我们读者的反馈总是受欢迎的。让我们知道您对这本书的看法——您喜欢或不喜欢什么。读者反馈对我们来说很重要，因为它帮助我们开发出您会真正从中受益的标题。

要向我们发送一般性反馈，只需发送电子邮件`<feedback@packtpub.com>`，并在消息主题中提及书籍的标题。

如果您在某个话题上有专业知识，并且有兴趣撰写或为书籍做出贡献，请查看我们的作者指南：[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

现在您已经成为 Packt 书籍的骄傲拥有者，我们有很多事情可以帮助您充分利用您的购买。

## 下载示例代码

您可以从[`www.packtpub.com`](http://www.packtpub.com)下载您购买的所有 Packt Publishing 书籍的示例代码文件。如果您在其他地方购买了此书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便将文件直接通过电子邮件发送给您。

## 错误

虽然我们已经尽一切努力确保我们的内容的准确性，但错误确实会发生。如果您在我们的某本书中发现错误——可能是文本或代码中的错误——我们将非常感谢您能向我们报告。这样做，您可以节省其他读者的挫折感，并帮助我们改进本书的后续版本。如果您发现任何错误，请通过访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**错误提交****表单**链接，并输入您错误的详细信息。一旦您的错误得到验证，您的提交将被接受，错误将被上传到我们的网站，或添加到该标题的错误部分现有的错误列表中。

要查看以前提交的错误，请前往[`www.packtpub.com/books/content/support`](https://www.packtpub.com/books/content/support)，在搜索框中输入书籍名称。所需信息将在**错误**部分出现。

## 版权侵犯

版权材料的网上侵犯是一个持续存在的问题，涵盖所有媒体。在 Packt，我们非常重视我们版权和许可证的保护。如果您在互联网上以任何形式发现我们作品的非法副本，请立即提供给我们地址或网站名称，以便我们可以寻求解决方案。

如果您发现有疑似侵犯版权的材料，请通过`<copyright@packtpub.com>`联系我们。

我们感谢您在保护我们的作者和我们提供有价值内容的能力方面所提供的帮助。

## 问题

如果您与此书有任何问题，您可以联系`<questions@packtpub.com>`我们，我们会尽力解决问题。


# 第一章 客户端读写 JSON

在本章中，我们将介绍以下菜谱：

+   在 JavaScript 中读写 JSON

+   在 C++ 中读写 JSON

+   在 C# 中读写 JSON

+   在 Java 中读写 JSON

+   在 Perl 中读写 JSON

+   在 Python 中读写 JSON

除了在 Python 中读写 JSON 之外，我们首先向您展示 JSON 格式的简要回顾，以帮助为本书后续内容奠定基础。

# 简介

**JSON** 代表 **JavaScript Object Notation**（JavaScript 对象表示法）。它是一种开放标准，用于将数据表示为带值的属性。最初来源于 JavaScript 语法（因此得名）用于作为更冗长和结构化的 **Extensible Markup Language**（**XML**）的替代，在网页应用程序中使用，现在它被用于许多独立和网络应用程序中的数据序列化和传输。

JSON 提供了在客户端和服务器之间封装数据的理想方式。在本章中，你将学习如何在章节开始时指定的语言中使用 JSON。

这些语言通常用于客户端开发，这正是我们将要关注的内容。我们将在第二章中更多地了解服务器端语言，*服务器端读写 JSON*。

让我们来看一下由 web API 返回的 JSON 数据，该 API 的网址是 [`www.aprs.fi`](http://www.aprs.fi)，我对其进行了少许修改以使示例更清晰（在后面的第四章中，*使用 JSON 在 jQuery 和 AngularJS 的 AJAX 应用程序中*，你将学习如何使用网络浏览器和 JavaScript 自己获取这些数据）：

```js
{
  "command":"get",
  "result":"ok",
  "what":"loc",
  "found":2,
  "entries":[
    {
      "class":"a",
      "name":"KF6GPE",
      "type":"l",
      "time":"1399371514",
      "lasttime":"1418597513",
      "lat":37.17667,
      "lng":-122.14650,
      "symbol":"\/-",
      "srccall":"KF6GPE",
    },
    {
      "class":"a",
      "name":"KF6GPE-7",
      "type":"l",
      "time":"1418591475",
      "lasttime":"1418591475",
      "lat":37.17633,
      "lng":-122.14583,
      "symbol":"\\K",
      "srccall":"KF6GPE-7",
    }
  ]
}
```

### 提示

**下载示例代码**

你可以从 [`www.packtpub.com`](http://www.packtpub.com) 下载你购买的所有 Packt Publishing 书籍的示例代码文件。如果你在其他地方购买了这本书，你可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 并注册，以电子邮件方式直接接收这些文件。

这个例子有几个需要注意的地方：

+   数据组织成属性和值，每个属性由冒号分隔。（注意，JSON 文档也可以是一个单独的值，比如字符串、浮点数、整数或布尔值。）

+   属性作为双引号括起来的字符串出现在冒号的左侧。

+   值位于冒号的右侧，可以是以下内容：

    +   字符串（用双引号括起来的，例如 `KF6GPE`

    +   数字（整数或浮点数），例如 `2` 或 `37.17667`

    +   数组（由逗号分隔的值，包含在方括号中），例如 `entries` 的值

    +   由更多属性和值组成的全局对象，例如 `entries` 值中的两个数组值

    +   另外（虽然这个例子没有显示），布尔值 `true` 和 `false`

+   请注意，许多其他类型的值，如日期/时间对或单个字符，JSON 是不支持的。

+   虽然这个例子不完全清楚，但空格是无关紧要的。例如，没有必要将每一对都放在单独的一行上，缩进是完全任意的。

JSON 的属性名-属性值属性，以及嵌套值和表示数组的能力，赋予了 JSON 很大的灵活性。你可以使用 JSON 表示很多常见的对象，包括大多数不包含大量二进制数据的对象（有关如何使用 JavaScript 和 JSON 表示二进制数据的思路，请参见第八章，*使用 JSON 进行二进制数据传输*）。这包括原始值（自文档化，因为每个值都伴随着一个属性），具有简单值的平面对象，包括地图，以及简单或复杂对象的数组。

JSON 的自文档化特性使其成为数据传输的理想选择，即便它不支持 XML 中可能找到的注释。它所具有的纯文本特性使其在网络上使用诸如`gzip`这样的流行压缩方案进行压缩变得容易，而且与更冗长的 XML 相比，它的格式对人类阅读更为友好。

### 提示

请注意，JSON 文档本质上是一种树结构，因此，它不支持循环数据结构，比如图，其中节点指向数据结构中的另一个节点。

如果你使用编程语言的本地区域表示创建此类数据结构，并尝试将其转换为 JSON，你会得到一个错误。

# 在 JavaScript 中读写 JSON

JSON 最初是一种在 Web 服务器和 JavaScript 之间传输数据的手段，因此让我们从一个简单的代码片段开始，该代码片段在 Web 浏览器中使用 JavaScript 读写 JSON。我们将在第四章，*使用 JSON 在 AJAX 应用程序中与 jQuery 和 AngularJS 一起使用*中展示一个使用 AJAX 和 JSON 的 Web 应用程序的全部内容；以下是如何从 JSON 获取 JavaScript 对象以及如何从 JavaScript 对象创建 JSON 字符串。

## 准备就绪

你需要一种方法来编辑 JavaScript 并在浏览器中运行它。在本例中，以及本书中的几乎所有示例，我们将使用 Google Chrome 来完成这个任务。你可以在[`www.google.com/chrome/browser`](https://www.google.com/chrome/browser)下载 Google Chrome。一旦你安装了 Google Chrome，你希望通过点击右侧的**定制和控制 Doodle Chrome**图标来激活 JavaScript 控制台，它看起来像这样：

![准备就绪](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-json-cb/img/B04206_01_01.jpg)

然后，你需要前往**更多工具 | JavaScript 控制台**。你应该能在网页的侧面看到一个 JavaScript 控制台，就像这样：

![准备就绪](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-json-cb/img/B04206_01_02.jpg)

如果你喜欢使用快捷键，你也可以在 Windows 和 Linux 上使用*Ctrl* + *Shift* + *J*，或者在 Macintosh 上使用*control* + *option* + *J*。

从这里开始，你可以在右下角输入 JavaScript 代码并按下*Enter*键（在 Mac OS X 系统上为*return*键）来执行 JavaScript。

## 如何做到...

现代网页浏览器，如 Chrome，在 JavaScript 运行时定义了一个 JSON 对象，该对象可以将包含 JSON 的字符串数据转换为 JavaScript 对象，反之亦然。这是一个简单的示例：

```js
>var json = '{"call":"KF6GPE","type":"l","time":
"1399371514","lasttime":"1418597513","lat":37.17667,"lng":
-122.14650,"result" : "ok" }';
<- "{ "call":"KF6GPE","type":"l","time":"1399371514",
"lasttime":"1418597513","lat":37.17667,"lng":-122.14650,
"result" : "ok" }"
>var object = JSON.parse(json);
<- Object {call:"KF6GPE",type:"l",time:"1399371514",
lasttime:"1418597513",lat:37.17667, lng:-122.14650,result: "ok"}
> object.result
<- "ok"
>var newJson = JSON.stringify(object);
<- "{ "call":"KF6GPE","type":"l","time":"1399371514",
"lasttime":"1418597513","lat": 37.17667,"lng": -122.14650,
"result" : "ok" }"
```

### 注意

在此及随后的 JavaScript 示例中，你在 JavaScript 控制台输入的文本前面有一个`>`符号，而 JavaScript 控制台打印的内容是以`<-`符号开头的。

## 它是如何工作的...

Chrome 和其他现代网页浏览器定义了`JSON`对象，该对象具有将包含 JSON 的字符串和 JavaScript 对象之间相互转换的方法。

在前一个示例中，我们首先将`json`变量的值设置为一个包含一个名为`result`的属性的简单 JSON 表达式，其值为`ok`。JavaScript 解释器返回变量`json`的结果值。

下一行使用了`JSON`对象的`parse`方法，将`json`引用的 JSON 字符串转换为 JavaScript 对象：

```js
>var object = JSON.parse(json);
<- Object { call:"KF6GPE", type:"l", time:"1399371514", lasttime:"1418597513", lat:37.17667, lng:-122.14650, result: "ok"}
```

然后，你可以像访问任何其他 JavaScript 对象一样访问对象中的任何一个值；毕竟，它就是一个对象：

```js
> object.result;
<- "ok"
```

最后，如果你需要将一个对象转换成 JSON 格式，你可以使用`JSON`对象的`stringify`方法来实现：

```js
>var newJson = JSON.stringify(object);
<- "{ "call":"KF6GPE","type":"l","time":"1399371514",
"lasttime":"1418597513","lat": 37.17667,"lng": -122.14650,
"result" : "ok" }"
```

## 还有更多内容...

关于这些方法，你应该知道两件事情。首先，如果传递给 parse 的 JSON 格式不正确，或者根本不是 JSON，它会抛出一个异常：

```js
>JSON.parse('{"result" = "ok" }')
<- VM465:2 Uncaught SyntaxError: Unexpected token =
```

错误信息不是很有帮助，但如果你在调试由不完全符合规范且未经调试的 JSON 编码器发送的 JSON，这总比没有强。

第二，非常旧的网页浏览器可能没有包含这些方法的 JSON 对象。在这种情况下，你可以使用 JavaScript 函数`eval`，在将 JSON 用括号括起来后再对其进行处理，像这样：

```js
>eval('('+json+')')
<- Object {result: "ok"}
```

`eval`函数评估你传递给它的 JavaScript 字符串，而 JSON 表示实际上只是 JavaScript 的一个子集。然而，尽管理论上你可以避免使用`eval`，但有几个原因建议你这么做。首先，它通常比`JSON`对象提供的方法慢。其次，它不安全；你传递的字符串可能包含恶意的 JavaScript，这可能会导致你的 JavaScript 应用程序崩溃或被其他方式破坏，这绝不是轻视的威胁。尽可能使用`JSON`对象。第三，你可以使用`parse`和`stringify`方法来处理简单值，比如布尔值、数字和字符串；你不仅仅限于前一个示例中的键值对。如果我只想传递一个布尔值（比如"交易成功！"），我可能会直接写如下内容：

```js
var jsonSuccess = 'true';
<- "true"
> var flag = JSON.parse(jsonSuccess);
```

最后，值得指出的是，JSON 的`parse`和`stringify`方法都接受一个可选的替换函数，该函数在序列化或反序列化被序列化或反序列化的对象中的每个键和值时被调用。你可以使用这个函数在 JSON 被解析时进行实时数据转换；例如，你可以使用它将日期字符串表示和自纪元开始以来午夜的秒数之间进行转换，或者纠正字符串的大小写。我可以在以下代码中使用替换函数进行转换，使调用字段小写：

```js
> var object = JSON.parse(json, function(k, v) {
  if ( k == 'call') return v.toLowerCase();
});
<- Object { call:"kf6gpe", type:"l", time:"1399371514",
lasttime:"1418597513", lat:37.17667, lng:-122.14650, result: "ok"}
```

你还可以返回`undefined`以从结果中移除一个项目；为了从生成的 JSON 中省略类型字段，我可以执行以下操作：

```js
> var newJson = JSON.stringify(object, function (k, v) {
  if k == 'type') return undefined;
});
<- "{ "call":"KF6GPE","time":"1399371514","lasttime":
"1418597513","lat": 37.17667,"lng": -122.14650, "result" : "ok" 
}"
```

# 在 C++中读写 JSON

C++是一种早在 JSON 出现之前就存在的语言，但对于许多项目来说仍然相关。C++中没有对 JSON 的原生支持，但有许多库提供了对 JSON 工作的支持。或许最广泛使用的是**JsonCpp**，可在 GitHub 上找到[`github.com/open-source-parsers/jsoncpp`](https://github.com/open-source-parsers/jsoncpp)。它的许可证为 MIT 许可证或如果你愿意的话为公共领域，所以它的使用几乎没有限制。

## 准备

要使用 JsonCpp，你首先需要前往网站下载包含整个库的压缩文件。一旦你这么做，你需要将其与你的应用程序源代码集成。

你将它在应用程序源代码中集成的方法因平台而异，但一般过程是这样的：

1.  使用网站上的说明创建库的合并源和头文件。为此，你需要下载 JsonCpp 并安装 Python 2.6 或更高版本。从 JsonCpp 的顶级目录运行`python amalgamate.py`。

1.  在任何你想使用 JsonCpp 库的文件中包含`dist/json/json.h`头文件。

1.  在你的项目 Makefile 或构建系统中包含源文件`dist/jsoncpp.cpp`。

一旦你这样做，你应该在任何包含`json/json.h`头文件的文件中访问 JsonCpp 接口。

## 如何进行操作...

下面是一个简单的 C++应用程序，它使用 JsonCpp 将包含一些简单 JSON 的`std::string`和 JSON 对象之间进行转换：

```js
#include <string>
#include <iostream>
#include "json/json.h"

using namespace std;

int main(int argc, _TCHAR* argv[])
{
  Json::Reader reader;
  Json::Value root;

  string json = "{\"call\": \"KF6GPE\",\"type\":\"l\",\"time\":
  \"1399371514\",\"lasttime\":\"1418597513\",\"lat\": 37.17667,
  \"lng\": -122.14650,\"result\":\"ok\"}";

  bool parseSuccess = reader.parse(json, root, false);

  if (parseSuccess)
  {
    const Json::Value resultValue = root["result"];
    cout << "Result is " << resultValue.asString() << "\n";
  }

  Json::StyledWriter styledWriter;
  Json::FastWriter fastWriter;
  Json::Value newValue;
  newValue["result"] = "ok";

  cout << styledWriter.write(newValue) << "\n";
  cout << fastWriter.write(newValue) << "\n";

  return 0;
}
```

## 它是如何工作的...

这个例子开始于包含必要的包含文件，包括定义 JsonCpp 接口的`json/json.h`。我们明确引用`std`命名空间以简化问题，尽管对于`Json`命名空间，其中 JsonCpp 定义了所有其接口，不要这样做。

JsonCpp 实现定义了 `Json::Reader` 和 `Json::Writer`，分别指定 JSON 读取器和写入器的接口。实践中，`Json::Reader` 接口也是 JSON 类的实现，可以读取 JSON，将其值返回为 `Json::Value`。`Json::Writer` 变量只是定义了一个接口；你可能需要使用其子类，如 `Json::FastWriter` 或 `Json::StyledWriter`，从 `Json::Value` 对象创建 JSON。

前一个列表首先定义了 `Json::Reader` 和 `Json::Value`；我们将使用读取器读取我们接下来定义的 JSON，并将其值存储在 `Json::Value` 变量 `root` 中。（假设你的 C++ 应用程序会从其他来源获取 JSON，比如网络服务或本地文件。）

解析 JSON 只需调用读取器的 `parse` 函数，将 JSON 和将要写入 JSON 值的 `Json::Value` 传递给它。它返回一个布尔值，如果 JSON 解析成功，则为 `true`。

`Json::Value` 类将 JSON 对象表示为树；个别值通过原始 JSON 的属性名称来引用，这些值是这些键的值，可以通过诸如 `asString` 之类的方法访问，该方法将对象的值作为本地 C++ 类型返回。`Json::Value` 这些方法包括以下内容：

+   `asString`, 它返回 `std::string`。

+   `asInt`, 它返回 `Int`。

+   `asUInt`, 它返回 `UInt`。

+   `asInt64`, 它返回 `Int64`。

+   `asFloat`, 它返回 `float`。

+   `asDouble`, 它返回 `double`。

+   `asBool`, 它返回 `bool`。

此外，这个类还提供了 `operator[]`，让你访问数组元素。

你可以 also 查询一个 `Json::Value` 对象，使用这些方法之一来确定它的类型：

+   `isNull`, 如果值是 `null` 则返回 `true`。

+   `isBool`, 如果值是 `bool` 类型则返回 `true`。

+   `isInt`, 如果值是 `Int` 则返回 `true`。

+   `isUInt`, 如果值是 `UInt` 则返回 `true`。

+   `isIntegral`, 如果值是整数则返回 `true`。

+   `isDouble`, 如果值是 `double` 则返回 `true`。

+   `isNumeric`, 如果值是数字则返回 `true`。

+   `isString`, 如果值是字符串则返回 `true`。

+   `isArray`, 如果值是一个数组则返回 `true`。

+   `isObject`, 如果值是另一个 JSON 对象（你可以使用另一个 `Json::Value` 值对其进行分解）则返回 `true`。

无论如何，我们的代码使用 `asString` 来获取作为 `result` 属性的 `std::string` 值，并将其写入控制台。

代码然后定义了`Json::StyledWriter`和`Json::FastWriter`来创建一些格式化的 JSON 和未格式化的 JSON 字符串，以及一个`Json::Value`对象来包含我们的新 JSON。赋值给 JSON 值很简单，因为它用适当的实现覆盖了`operator[]`和`operator[]=`方法，以将标准 C++类型转换为 JSON 对象。因此，以下代码创建了一个带有`result`属性和`ok`值的单个 JSON 属性/值对（尽管这段代码没有显示，但你可以通过将 JSON 对象分配给其他 JSON 对象来创建 JSON 属性值树）：

```js
newValue["result"] = "ok";
```

我们首先使用`StyledWriter`，然后使用`FastWriter`来编码`newValue`中的 JSON 值，将每个字符串写入控制台。

当然，你也可以将单个值传递给 JsonCpp；如果你只是想传递一个双精度数，没有理由不执行以下代码。

```js
Json::Reader reader;
Json::Value piValue;

string json = "3.1415";
bool parseSuccess = reader.parse(json, piValue, false);
  double pi = piValue.asDouble();
```

## 也请参阅

对于 JsonCpp 的文档，你可以从[`www.stack.nl/~dimitri/doxygen/`](http://www.stack.nl/~dimitri/doxygen/)安装 doxygen，并将其运行在 JsonCpp 主要分布的`doc`文件夹上。

还有其他针对 C++的 JSON 转换实现。要查看完整的列表，请参阅[`json.org/`](http://json.org/)上的列表。

# 在 C#中读写 JSON

C#是一种常见的客户端语言，用于编写丰富应用程序的客户端实现，以及运行在 ASP.NET 上的 Web 服务的客户端实现。.NET 库在 System.Web.Extensions 程序集中包括 JSON 序列化和反序列化。

## 准备

这个例子使用了 System.Web.Extensions 程序集中的内置 JSON 序列化和反序列化器，这是许多可用的.NET 库之一。如果你安装了最近版本的 Visual Studio（请参阅[`www.visualstudio.com/en-us/downloads/visual-studio-2015-downloads-vs.aspx`](https://www.visualstudio.com/en-us/downloads/visual-studio-2015-downloads-vs.aspx)），它应该是可以使用的。要使用这个程序集，你所需要做的就是在 Visual Studio 中通过右键点击你的项目中的**引用**项，选择**添加引用**，然后在**框架程序集**列表中滚动到底部找到**System.Web.Extensions**。

## 如何做到...

这是一个简单的应用程序，它反序列化了一些 JSON，作为属性-对象对的字典：

```js
using System;
using System.Collections.Generic;
using System.Web.Script.Serialization;

namespace JSONExample
{
    public class SimpleResult
    {
        public string result;
    }

    class Program
    {
        static void Main(string[] args)
        {
            JavaScriptSerializer serializer = 
            new System.Web.Script.Serialization.
            JavaScriptSerializer();

            string json = @"{ ""call"":""KF6GPE"",""type"":
""l"",""time"":""1399371514"",""lasttime"":""1418597513"",
""lat"": 37.17667,""lng\": -122.14650,""result"": ""ok"" }";

dynamic result = serializer.DeserializeObject(json);
            foreach (KeyValuePair<string, object> entry in result)
            {
                var key = entry.Key;
                var value = entry.Value as string;
Console.WriteLine(String.Format("{0} : {1}", 
key, value));
            }
            Console.WriteLine(serializer.Serialize(result));

            var anotherResult = new SimpleResult { result="ok" };
            Console.WriteLine(serializer.Serialize(
            anotherResult));
        }
    }
}
```

## 它是如何工作的...

System.Web.Extensions 程序集提供了`System.Web.Script.Serialization`名称空间中的`JavaScriptSerializer`类。这段代码首先定义了一个简单的类`SimpleResult`，我们将在示例中将其编码为 JSON。

`Main`方法首先定义了一个`JavaScriptSerializer`实例，然后定义了一个包含我们 JSON 的`string`。解析 JSON 只需调用`JavaScriptSerializer`实例的`DeserializeObject`方法，该方法根据传递的 JSON 在运行时确定返回对象的类型。

### 提示

你也可以使用`DeserializeObject`以类型安全的方式解析 JSON，然后返回对象的类型与传递给方法的类型匹配。我将在第七章*使用 JSON 进行类型安全操作*中向你展示如何做到这一点。

`DeserializeObject`返回一个键值对的`Dictionary`；键是 JSON 中的属性，值是表示这些属性值的对象。在我们示例中，我们简单地遍历字典中的键和值，并打印出来。因为我们知道 JSON 中值的类型，所以我们可以使用 C#的`as`关键字将其转换为适当的类型（在这个例子中是`string`）；如果不是`string`，我们将收到`null`值。你可以使用`as`或 C#的类型推导来确定 JSON 中未知对象的类型，这使得解析缺乏严格语义的 JSON 变得容易。

`JavaScriptSerializer`类还包括一个`Serialize`方法；你可以将其作为属性-值对的字典传递，就像我们对反序列化结果所做的那样，或者你可以将其作为 C#类的实例传递。如果你将其作为类传递，它将尝试通过内省类字段和值来序列化类。

## 还有更多...

微软提供的 JSON 实现对于许多目的来说已经足够了，但不一定最适合你的应用程序。其他开发者实现了更好的版本，这些版本通常使用与微软实现相同的接口。一个不错的选择是 Newtonsoft 的 Json.NET，你可以从[`json.codeplex.com/`](http://json.codeplex.com/)或者从 Visual Studio 的 NuGet 获取。它支持更广泛的.NET 平台（包括 Windows Phone），LINQ 查询，对 JSON 的 XPath-like 查询，并且比微软实现更快。使用它与使用微软实现类似：从 Web 或 NuGet 安装包，将程序集引用添加到你的应用程序中，然后使用`NewtonSoft.Json`命名空间中的`JsonSerializer`类。它定义了与微软实现相同的`SerializeObject`和`DeserializeObject`方法，使得切换到这个库变得容易。*Json.NET*的作者*James Newton-King*将其置于 MIT 许可下。

与其他语言一样，你也可以在反序列化和序列化过程中传递原始类型。例如，在评估以下代码后，动态变量`piResult`将包含一个浮点数，3.14：

```js
string piJson = "3.14";
dynamic piResult = serializer.DeserializeObject(piJson);
```

## 也参见

如我之前所暗示的，你可以以一种类型安全的方式进行操作；我们将在第七章*使用 JSON 进行类型安全操作*中讨论更多内容。你将通过使用泛型方法`DeserializeObject<>`，传入你想要反序列化的类型变量来实现。

# 在 Java 中读写 JSON

Java，像 C++一样，早于 JSON。甲骨文目前正致力于为 Java 添加 JSON 支持，但与此同时，网上有多个提供 JSON 支持的实现。与本章前面看到的 C++实现类似，你可以使用第三方库将 JSON 和 Java 之间进行转换；在这个例子中，作为一个 Java 归档（JAR）文件，其实现通常将 JSON 对象表示为命名的对象的树。

也许最好的 JSON 解析 Java 实现是 Gson，可以从谷歌的[`code.google.com/p/google-gson/`](http://code.google.com/p/google-gson/)获取，在 Apache 许可证 2.0 下发布。

## 准备开始

首先，你需要获取 Gson；你可以通过使用以下命令，用 SVN 通过 HTTP 进行只读检出仓库来完成这个操作：

```js
svn checkout http://google-gson.googlecode.com/svn/trunk/google-gson-read-only

```

当然，这假设你已经安装了一个 Java 开发工具包（[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)）和 SVN（Windows 上的 TortoiseSVN 是一个好的客户端，可在[`tortoisesvn.net/downloads.html`](http://tortoisesvn.net/downloads.html)获得）。许多 Java IDE 包括对 SVN 的支持。

一旦你检查了代码，按照随附的说明构建吉森 JAR 文件，并将 JAR 文件添加到你的项目中。

## 如何做到…

开始之前，你需要创建一个`com.google.gson.Gson`对象。这个类定义了你将用来在 JSON 和 Java 之间转换的接口：

```js
Gson gson = new com.google.gson.Gson(); 
String json = "{\"call\": \"KF6GPE\", \"type\": \"l\", \"time\":
\"1399371514\", \"lasttime\": \"1418597513\", \"lat\": 37.17667,
\"lng\": -122.14650,\"result\":\"ok\"}";
com.google.gson.JsonObject result = gson.fromJson(json, 
JsonElement.class).getAsJsonObject(); 
```

`JsonObject`类定义了包含 JSON 对象的顶级对象；你使用它的`get`和`add`方法来获取和设置属性，像这样：

```js
JsonElement result = result.get("result").getAsString();
```

吉森库使用`JsonElement`类来封装单个 JSON 值；它有以下方法，可以让您将`JsonElement`中的值作为普通的 Java 类型获取：

+   `getAsBoolean`，返回值为`Boolean`

+   `getAsByte`，返回值为`byte`

+   `getAsCharacter`，返回值为`char`

+   `getAsDouble`，返回值为`double`

+   `getAsFloat`，返回值为`float`

+   `getAsInt`，返回值为`int`

+   `getAsJsonArray`，返回值为`JsonArray`

+   `getAsJsonObject`，返回值为`JsonObject`

+   `getAsLong`，返回值为`long`

+   `getAsShort`，返回值为`short`

+   `getAsString`，返回值为`String`

你也可以使用以下方法之一了解`JsonElement`中的类型：

+   `isJsonArray`，如果元素是一个对象数组则返回`true`

+   `isJsonNull`，如果元素为 null 则返回`true`

+   `isJsonObject`，如果元素是一个复合对象（另一个 JSON 树）而不是单个类型则返回`true`

+   `isJsonPrimitive`，如果元素是基本类型，如数字或字符串，则返回`true`

## 还有更多…

你也可以直接将类的实例转换为 JSON，像这样编写代码：

```js
public class SimpleResult {
    public String result;
}

// Elsewhere in your code…
Gson gson = new com.google.gson.Gson(); 
SimpleResult result = new SimpleResult;
result.result = "ok";
String json = gson.toJson(result);	
```

这定义了一个`SimpleResult`类，我们用它来创建一个实例，然后使用`Gson`对象实例将转换为包含 JSON 的字符串，使用`Gson`方法的`toJson`。

最后，因为`JsonElement`封装了一个单独的值，你也可以处理表示为 JSON 的简单值，比如这样：

```js
Gson gson = new com.google.gson.Gson(); 
String piJson = "3.14";
double result = gson.fromJson(piJson, 
JsonElement.class).getAsDouble(); 
```

这会将 JSON 中的原始值`3.14`转换为 Java `double`。

## 也见

与 C#示例类似，你可以直接从 JSON 转换为普通的旧 Java 对象（POJO），并以类型安全的方式进行转换。你将在第七章 *以类型安全的方式使用 JSON*中看到如何做到这一点。

还有其他针对 Java 的 JSON 转换实现。要获取完整列表，请查看[`json.org/`](http://json.org/)上的列表。

# 在 Perl 中读写 JSON。

Perl 早于 JSON，尽管 CPAN 有一个很好的 JSON 转换实现，即综合 Perl 存档网络（Comprehensive Perl Archive Network）。

## 如何做到...

首先，从 CPAN 下载 JSON 模块并安装它。通常，你会下载文件，解压它，然后在已经配置了 Perl 和 make 的系统上运行以下代码：

```js
perl Makefile.PL 
make 
make install
```

这是一个简单示例：

```js
use JSON;
use Data::Dumper;
my $json = '{ "call":"KF6GPE","type":"l","time":"1399371514",
"lasttime":"1418597513","lat": 37.17667,"lng": -122.14650,
"result" : "ok" }';
my %result = decode_json($json);
print Dumper(result);
print encode_json(%result);
```

让我们来看看 JSON 模块提供的接口。

## 它是如何工作的...

CPAN 模块定义了`decode_json`和`encode_json`方法来分别解码和编码 JSON。这些方法在 Perl 对象（如字面值和关联数组）和包含 JSON 的字符串之间进行相互转换。

代码首先导入了 JSON 和`Data::Dumper`模块。接下来，它定义了一个单一字符串`$json`，其中包含我们要解析的 JSON。

有了 JSON 中的`$json`，我们定义`%result`为包含 JSON 中定义的对象的关联数组，并在下一行倾倒散列中的值。

最后，我们将散列重新编码为 JSON，并将结果输出到终端。

## 也见

要获取更多信息并下载 JSON CPAN 模块，请访问[`metacpan.org/pod/JSON`](https://metacpan.org/pod/JSON)。

# 在 Python 中读写 JSON。

从 Python 2.6 开始，Python 就拥有对 JSON 的本地支持，通过`json`模块。使用该模块就像使用`import`语句导入模块一样简单，然后通过它定义的`json`对象访问编码器和解码器。

## 准备好了

只需在源代码中输入以下内容，就可以引用 JSON 功能：

```js
import json
```

## 如何做到...

以下是从 Python 解释器中的一个简单示例：

```js
>>> import json
>>>json = '{ "call":"KF6GPE","type":"l","time":"1399371514",
"lasttime":"1418597513","lat": 37.17667,"lng": -122.14650,
"result" : "ok" }'
u'{"call":"KF6GPE","type":"l","time":"1399371514",
"lasttime":"1418597513","lat": 37.17667,"lng": -122.14650,
"result": "ok" }'
>>>result = json.loads(json)
{u'call':u'KF6GPE',u'type':u'l',u'time':u'1399371514',
u'lasttime':u'1418597513',u'lat': 37.17667,u'lng': -122.14650,u'result': u'ok'}
>>> result['result']
u'ok'
>>> print json.dumps(result)
{"call":"KF6GPE","type":"l","time":"1399371514",
"lasttime":"1418597513","lat": 37.17667,"lng": -122.14650,
"result":"ok"}
>>> print json.dumps(result, 
...                  indent=4)
{
"call":"KF6GPE",
"type":"l",
"time":"1399371514",
"lasttime":"1418597513",
"lat": 37.17667,
"lng": -122.14650,
    "result": "ok"
}
```

让我们更深入地看看`loads`和`dumps`。

## 它是如何工作的...

**Python** 语言通过其对象层次结构对关联数组提供了很好的支持。`json` 模块提供了一个 `json` 对象以及 `loads` 和 `dumps` 方法，这些方法可将文本字符串中的 JSON 转换为关联数组，反之亦然。如果你熟悉 Python 的 `marshal` 和 `pickle` 模块，这个接口是相似的；你使用 `loads` 方法从其 JSON 表示中获取 Python 对象，使用 `dumps` 方法将一个对象转换为其 JSON 等价物。

之前的列表正是这样做。它定义了一个变量 `j` 来包含我们的 JSON 数据，然后使用 `json.loads` 获得一个 Python 对象 `result`。JSON 中的字段作为命名的对象在生成的 Python 对象中是可访问的。（注意我们不能将我们的 JSON 字符串命名为 `json`，因为这会遮蔽模块接口的定义。）

要转换为 JSON，我们使用 `json.dumps` 方法。默认情况下，`dumps` 创建一个紧凑的、机器可读的 JSON 版本，最小化空白；这最适合用于网络传输或文件存储。当你在调试你的 JSON 时，使用缩进和分隔符周围的一些空白来美化打印它是有帮助的；你可以使用可选的 `indent` 和 `separators` 参数来实现。`indent` 参数指定了每个嵌套对象在字符串中应缩进的空格数，而 `separators` 参数指定了每个对象之间以及每个属性和值之间的分隔符。

## 另见

关于 `json` 模块的更多文档，请参阅 Python 文档中的 [`docs.python.org/2/library/json.html`](https://docs.python.org/2/library/json.html)。


# 第二章：服务器端的读写 JSON

在前一章中，我们查看了一些最常见的客户端环境中的 JSON 处理。在本章中，我们将注意力转向服务器端的 JSON 编码和解码。我们将查看以下环境中的食谱：

+   在 Clojure 中读写 JSON

+   在 F#中读写 JSON

+   在 Node.js 中读写 JSON

+   在 PHP 中读写 JSON

+   在 Ruby 中读写 JSON

一些语言，如 C++和 Java，既用于客户端又用于服务器端；对于这些语言，请参考第一章，*客户端的读写 JSON*（一个例外是关于 Node.js 中的 JSON 讨论，因为 Node.js 在这本书的后续章节中扮演重要角色）。

# 在 Clojure 中读写 JSON

Clojure 是一种运行在 Java 和 Microsoft **公共** **语言运行时**（**CLR**）平台之上的现代 Lisp 变体。因此，你可以使用我们在第一章中讨论的设施，在本地运行时将 JSON 和对象之间进行转换，但有一个更好的方法，那就是 Clojure 的`data.json`模块，可在[`github.com/clojure/data.json`](https://github.com/clojure/data.json)找到。

## 准备

首先，你需要在你`data.json`模块中指定你的依赖。你可以用以下依赖在你的 Leiningen 文件中这样做：

```js
[org.clojure/data.json "0.2.5"]
```

如果你使用 Maven，你会需要这个：

```js
<dependency>
<groupId>org.clojure</groupId>
<artifactId>data.json</artifactId>
<version>0.2.5</version>
</dependency>
```

### 提示

当然，`data.json`的版本可能会在我写这篇和你在项目中作为依赖包含它之间发生变化。查看 data.json 项目以获取当前版本。

最后，你需要在你的代码中包含`data.json`模块，在一个像`json`这样的命名空间中：

```js
(ns example
  (:require [clojure.data.json :as json])
```

这使得`data.json`模块的实现通过`json`命名空间可用。

## 如何做到...

将 Clojure 映射编码为 JSON 很容易，只需调用`json/write-str`。例如：

```js
(json/write-str {:call "KF6GPE",:type "l",:time 
"1399371514":lasttime"1418597513",:lat 37.17667,:lng
-122.14650: :result "ok"})
;;=>"{\"call\": \"KF6GPE\", \"type\": \"l\", \"time\":
\"1399371514\", \"lasttime\": \"1418597513\", \"lat\": 37.17667,
\"lng\": -122.14650,\"result\":\"ok\"}"
```

如果你有一个实现`java.io.Writer`的流，你想向其写入 JSON，你也可以使用`json/write`：

```js
(json/write {:call "KF6GPE",:type "l", :time 
"1399371514":lasttime "1418597513",:lat 37.17667, :lng 
-122.14650: result "ok" }  stream)
```

阅读是写作的相反过程，它将 JSON 读取到关联数组中，你可以进一步处理：

```js
(json/read-str "{\"result\":\"ok\"}")
;;=> {"result" "ok"}
```

还有`json/read`，`json/write`的对应物，它接收一个流，你可以从中读取并返回解析后的 JSON 映射。

## 还有更多...

这些方法都接受两个可选参数，一个`:key-fn`参数，模块将其应用于每个 JSON 属性名称，和一个`:value-fn`参数，模块将其应用于属性值。例如，你可以使用`:key-fn keyword`将 JSON 转换为更传统的 Clojure 关键词映射，像这样：

```js
(json/read-str "{\"call\": \"KF6GPE\", \"type\": \"l\", \"time\":
\"1399371514\", \"lasttime\": \"1418597513\", \"lat\": 37.17667,
\"lng\": -122.14650,\"result\":\"ok\"}:key-fn keyword)
;;=> {:call "KF6GPE",:type "l", :time 
"1399371514":lasttime "1418597513",:lat 37.17667, :lng 
-122.14650: :result "ok"}
```

或者，你可以提供一个 lambda，比如以下这个，它将键转换为大写：

```js
(json/write-str {:result "OK"}
                :key-fn #(.toUpperCase %))
;;=> "{\"RESULT\":"OK"}"
```

这里有一个来自 `data.json` 文档的很好例子，它使用 `value-fn` 将 ISO 日期字符串转换为 Java `Date` 对象，当你解析 JSON 时：

```js
(defn my-value-reader [key value]
  (if (= key :date)
    (java.sql.Date/valueOf value)
    value))

(json/read-str "{\"result\":\"OK\",\"date\":\"2012-06-02\"}"
               :value-fn my-value-reader
               :key-fn keyword) 
;;=> {:result"OK", :date #inst "2012-06-02T04:00:00.000-00:00"}
```

上述代码执行以下操作：

1.  定义了一个辅助函数 `my-value-reader`，它使用 JSON 键值对的关键字来确定其类型。

1.  给定一个 JSON 键值 `:date`，它将该值视为一个字符串，传递给 `java.sql.Date` 方法的 `valueOf`，该方法返回一个从它解析的字符串中获取值的 `Date` 实例。

1.  调用 `json/read-str` 来解析一些简单的 JSON 数据，它包括两个字段：一个 `result` 字段和一个 `date` 字段。

1.  **JSON 解析器**解析 JSON 数据，将 JSON 属性名转换为关键字，并使用我们之前定义的值转换器将日期值转换为它们的 `java.sql.Date` 表示形式。

# 在 F# 中读写 JSON

F# 是一种运行在 CLR 和 .NET 之上的语言，擅长于函数式和面向对象编程任务。因为它建立在 .NET 之上，所以你可以使用诸如 `Json.NET`（在 第一章，*客户端的 JSON 读写* 中提到）等第三方库来将 JSON 与 CLR 对象进行转换。然而，还有一个更好的方法：开源库 F# Data，它创建了本地的数据类型提供程序来处理多种不同的结构化格式，包括 JSON。

## 准备开始

首先，获取库的副本，可在 [`github.com/fsharp/FSharp.Data`](https://github.com/fsharp/FSharp.Data) 找到。下载后，你需要构建它；你可以通过运行随分发提供的 `build.cmd` 构建批处理文件来完成此操作（有关详细信息，请参见 F# Data 网站）。或者，你可以在 NuGet 上找到相同的包，通过从 **项目** 菜单中选择 **管理 NuGet 包** 并搜索 F# Data。找到后，点击 **安装**。我更喜欢使用 NuGet，因为它会自动将 `FSharp.Data` 程序集添加到你的项目中，省去了你自己构建源代码的麻烦。另一方面，源分发可以让你离线阅读文档，这也很有用。

一旦你获得了 F# 数据，你只需要在源文件中打开它，你打算用它时使用 `open` 指令，像这样：

```js
open FSharp.Data
```

## 如何进行...

以下是一些示例代码，它实现了 JSON 与 F# 对象之间的转换，然后又从另一个 F# 对象创建了新的 JSON 数据：

```js
open FSharp.Data

type Json = JsonProvider<""" { "result":"" } """>
let result = Json.Parse(""" { "result":"OK" } """)
let newJson = Json.Root( result = "FAIL")

[<EntryPoint>]
let main argv = 
    printfn "%A" result.Result
    printfn "%A" newJson
    printfn "Done"
```

让我们看看它是如何工作的。

## 它是如何工作的...

首先，重要的是要记住 F#是强类型的，并且从数据中推断类型。理解这一点对于理解 F# Data 库是如何工作的至关重要。与我们在前面章节中看到的例子不同，在那里转换器将 JSON 映射到键值对，F# Data 库从您提供的 JSON 中推断出整个数据类型。在许多方面，这既结合了其他转换器在转换 JSON 时采取的动态集合导向方法，也结合了我在第七章 *以类型安全的方式使用 JSON*中要展示的类型安全方法。这是因为您不需要辛苦地制作要解析的 JSON 的类表示，而且您还能在编写的代码中获得编译时类型安全的所有优势。更妙的是，F# Data 创建的类都支持 Intellisense，所以您在编辑器中就能直接获得工具提示和名称补全！

让我们逐段看看之前的示例并了解它做了什么：

```js
open FSharp.Data
```

第一行使 F# Data 类可用于您的程序。 among other things, 这定义了`JsonProvider`类，该类从 JSON 源创建 F#类型：

```js
type Json= JsonProvider<""" { "result":"" } """>
```

这行代码定义了一个新的 F#类型`Json`，该类型的字段和字段类型是从您提供的 JSON 中推断出来的。在底层，这做了很多工作：它推断出成员名称、成员的类型，甚至处理诸如混合数值（比如说您有一个同时包含整数和浮点数的数组，它能正确推断出类型为数值类型，这样你就可以表示任一类型）以及复杂的记录和可选字段等事情。

您可以向`JsonProvider`传递以下三个之一：

1.  一个包含 JSON 的字符串。这是最简单的情况。

1.  一个包含 JSON 文件的路径。库将打开文件并读取内容，然后对内容进行类型推断，最后返回一个能够表示文件中 JSON 的类型。

1.  一个 URL。库将获取 URL 处的文档，解析 JSON，然后对内容进行相同的类型推断，返回一个代表 URL 处 JSON 的类型。

下一行解析一个单独的 JSON 文档，如下所示：

```js
let result = Json.Parse(""" { "result":"OK" } """)
```

这可能一开始看起来有点奇怪：为什么我们要把 JSON 同时传递给`JsonProvider`和`Parse`方法呢？回想一下，`JsonProvider`是从您提供的 JSON 中创建一个类型。换句话说，它不是为了解析 JSON 的值，而是为了解析它所表示的数据类型，以便制作一个能够模拟 JSON 文档本身的类。这一点非常重要；对于`JsonProvider`来说，您想要传递一个具有字段和值的代表性 JSON 文档，这个文档是您的应用程序可能遇到的某一特定类型的所有 JSON 文档的共通之处。然后，您将一个特定的 JSON 文档（比如说，一个 web 服务结果）传递给`JsonProvider`创建的类的`Parse`方法。相应地，`Parse`返回了一个您调用`Parse`的方法的实例。

现在你可以访问类`Parse`返回实例中的字段；例如，稍后，我将在应用程序的`main`函数中打印出`result.Result`的值。

创建 JSON，你需要一个表示要序列化数据的类型的实例。在下一行，我们使用刚刚创建的`Json`类型来创建一个新的 JSON 字符串：

```js
let newJson = Json.Root( result = "FAIL")
```

这创建了一个`Json`类型的实例，并将结果字段设置为字符串`FAIL`，然后将该实例序列化为一个新的字符串。

最后，程序的其余部分是程序的入口点，并只是打印出解析的对象和创建的 JSON。

## 还有更多...

F#数据库支持远不止只是 JSON；它还支持**逗号分隔值**（**CSV**）、HTML 和 XML。这是一个非常适合进行各种结构化数据访问的优秀库，如果你在 F#中工作，那么熟悉它绝对是件好事。

# 使用 Node.js 读写 JSON

Node.js 是一个基于与 Google 为 Chrome 构建的高性能 JavaScript 运行时相同的高性能和异步编程模型的 JavaScript 环境，由 Joyent 支持。它高性能和异步编程模型使它成为一个优秀的自定义 Web 服务器环境，并且它被包括沃尔玛在内的许多大型公司用于生产环境。

## 准备

因为我们在接下来的两章中也会使用 Node.js，所以值得向你指出如何下载和安装它，即使你的日常服务器环境更像 Apache 或 Microsoft IIS。你需要访问[`www.nodejs.org/`](http://www.nodejs.org/)，并从首页下载安装程序。这将安装运行 Node.js 和 npm（Node.js 使用的包管理器）所需的一切。

### 提示

在 Windows 上安装后，我必须重新启动计算机，才能使 Windows 外壳正确找到 Node.js 安装程序安装的 node 和 npm 命令。

一旦你安装了 Node.js，我们可以通过在 Node.js 中启动一个简单的 HTTP 服务器来测试安装。为此，将以下代码放入一个名为`example.js`的文件中：

```js
var http = require('http');
http.createServer(function(req, res) {
   res.writeHead(200, {'Content-Type': 'text/plain'});
   res.end('Hello world\n');
}).listen(1337, 'localhost');
console.log('Server running at http://localhost:1337');
```

这段代码加载了 Node.js 的`http`模块，然后创建了一个绑定在本地机器上端口`1337`的 Web 服务器。你可以在创建文件的同一目录下，通过命令提示符输入以下命令来运行它：

```js
node example.js
```

一旦这样做，将你的浏览器指向 URL`http://localhost:1337/`。如果一切顺利，你应该在网页浏览器中看到“Hello world”的消息。

### 提示

你可能需要告诉你的系统防火墙，以启用对由`node`命令服务的端口的访问。

## 怎么做...

由于 Node.js 使用 Chrome 的 V8 JavaScript 引擎，因此 Node.js 中处理 JSON 与 Chrome 中的处理方式相同。JavaScript 运行时定义了`JSON`对象，该对象为您提供了 JSON 解析器和序列化器。

解析 JSON，你所需要做的就是调用`JSON.parse`方法，像这样：

```js
var json = '{ "call":"KF6GPE","type":"l","time":
"1399371514","lasttime":"1418597513","lat": 37.17667,"lng":
-122.14650,"result" : "ok" }';
var object = JSON.parse(json);
```

这将解析 JSON，返回包含数据的 JavaScript 对象，我们在这里将其分配给变量 object。

当然，你可以做相反的操作，使用`JSON.stringify`，像这样：

```js
var object = { 
call:"KF6GPE",
type:"l",
time:"1399371514",
lasttime:"1418597513",
lat:37.17667,
lng:-122.14650,
result: "ok"
};

var json = JSON.stringify(object);
```

## 也见

关于在 JavaScript 中解析和创建 JSON 的更多信息，请参阅第一章中的*在客户端读写 JSON*一节，以及*读写客户端 JSON*。

# 在 PHP 中读写 JSON

PHP 是一个流行的服务器端脚本环境，可以轻松与 Apache 和 Microsoft IIS 网络服务器集成。它具有内置的简单 JSON 编码和解码支持。

## 如何做到...

PHP 提供了两个函数`json_encode`和`json_decode`，分别用于编码和解码 JSON。

你可以将原始类型或自定义类传递给`json_encode`，它将返回一个包含对象 JSON 表示的字符串。例如：

```js
$result = array(
"call" =>"KF6GPE",
"type" =>"l",
"time" =>"1399371514",
"lasttime" =>"1418597513",
"lat" =>37.17667,
"lng" =>-122.14650,
"result" =>"ok");
$json = json_encode($result);
```

这将创建一个包含我们关联数组的 JSON 表示的字符串`$json`。

`json_encode`函数接受一个可选的第二个参数，让你指定编码器的参数。这些参数是标志，所以你可以用二进制或`|`操作符来组合它们。你可以传递以下标志的组合：

+   `JSON_FORCE_OBJECT`：这个标志强制编码器将 JSON 编码为对象。

+   `JSON_NUMERIC_CHECK`：这个标志检查传入结构中的每个字符串的内容，如果它包含一个数字，则在编码之前将字符串转换为数字。

+   `JSON_PRETTY_PRINT`：这个标志将 JSON 格式化为更容易供人类阅读的形式（不要在生产环境中这样做，因为这会使 JSON 变大）。

+   `JSON_UNESCAPED_SLASHES`：这个标志指示编码器不要转义斜杠字符。

最后，你可以传递一个第三个参数，指定编码器在编码你传递的值时应遍历表达式的深度。

`json_encode`的补数是`json_decode`，它接受要解码的 JSON 和一个可选参数集合。其最简单的用法可能像这样：

```js
$json = '{ "call":"KF6GPE","type":"l","time":
"1399371514","lasttime":"1418597513","lat": 37.17667,"lng":
-122.14650,"result" : "ok" }';
$result = json_decode($json);
```

`json_decode`函数最多接受三个可选参数：

+   第一个参数，当为真时，指定结果应该以关联数组的形式返回，而不是`stdClass`对象。

+   第二个参数指定一个可选的递归深度，以确定解析器应深入解析 JSON 的深度。

+   第三个参数可能是选项`JSON_BIGINT_AS_STRING`，当设置时表示应该将溢出整数值的整数作为字符串返回，而不是转换为浮点数（这可能会失去精度）。

这些函数在成功时返回`true`，在出错时返回`false`；你可以通过检查`json_last_error`的返回值来使用 JSON 确定上一次错误的的原因。

# 在 Ruby 中读写 JSON

Ruby 提供了`json`宝石用于处理 JSON。在 Ruby 的早期版本中，你必须自己安装这个宝石；从 Ruby 1.9.2 及以后版本开始，它成为基础安装的一部分。

## 准备

如果你正在使用比 Ruby 1.9.2 更早的版本，首先需要使用以下命令安装 gem：

```js
gem install json

```

请注意，Ruby 的实现是 C 语言，因此安装 gem 可能需要 C 编译器。如果您系统上没有安装，您可以使用以下命令安装 gem 的纯 Ruby 实现：

```js
gem install json_pure

```

无论你是否需要安装 gem，你都需要在代码中包含它。要做到这一点，请包含`rubygems`和`json`或**json/pure**，具体取决于你安装了哪个 gem；使用`require`，像这样：

```js
require 'rubygems'
require 'json'
```

前面的代码处理了前一种情况，而下面的代码处理了后一种情况：

```js
require 'rubygems'
require 'json/pure'
```

## 如何做到...

该 gem 定义了 JSON 对象，其中包含`parse`和`generate`方法，分别用于序列化和反序列化 JSON。使用它们正如你所期望的那样。创建一个对象或一些 JSON，调用相应的函数，然后查看结果。例如，要使用 JSON.generate 创建一些 JSON，你可以执行以下操作：

```js
require 'rubygems'
require 'json'
object = { 
"call" =>"KF6GPE",
"type" =>"l",
"time" =>"1399371514",
"lasttime" =>"1418597513",
"lat" => 37.17667,
"lng" => -122.14650,
"result" =>"ok"
}
json = JSON.generate(object)
```

这包括必要的模块，创建一个具有单个字段的关联数组，然后将其序列化为 JSON。

反序列化工作方式与序列化相同：

```js
require 'rubygems'
require 'json'
json = '{ "call":"KF6GPE","type":"l","time":
"1399371514","lasttime":"1418597513","lat": 37.17667,"lng":
-122.14650,"result" : "ok" }'
object = JSON.parse(object)
```

`parse`函数可以接受一个可选的第二个参数，一个具有以下键的哈希，表示解析器的选项：

+   `max_nesting`表示允许在解析的数据结构中嵌套的最大深度。它默认为 19，或者可以通过传递`:max_nesting => false`来禁用嵌套深度检查。

+   `allow_nan`，如果设置为真，则允许 NaN、Infinity 和-Infinity，这与 RFC 4627 相悖。

+   `symbolize_names`，当为真时，返回 JSON 对象中属性名的符号；否则，返回字符串（字符串是默认值）。

## 另见

JSON Ruby gem 的文档可以在网上找到，网址为[`flori.github.io/json/doc/index.html`](http://flori.github.io/json/doc/index.html)。


# 第三章：使用 JSON 的简单 AJAX 应用程序

在本章中，我们将探讨 JSON 在提供比旧网页更好的响应性的异步 JavaScript 和 XML（AJAX）应用程序中所扮演的角色，这些应用程序通过动态按需加载网页的片段来实现。

在本章中，您将找到以下食谱：

+   创建`XMLHttpRequest`对象

+   为数据发起异步请求

+   将 JSON 发送到你的 Web 服务器

+   使用 Node.js 接受 JSON

+   获取异步请求的进度

+   解析返回的 JSON

+   使用 Node.js 发起 Web 服务请求

# 引言

AJAX 是一组用于网络开发的客户端技术，用于创建异步网络应用程序——能够从不同的服务器获取内容的网络页面，一旦加载了基本内容。AJAX 中的“X”代表 XML，但今天的 AJAX 应用程序通常使用 JSON 来封装客户端和服务器之间的数据。

AJAX 的基础组件实际上 quite old，可以追溯到 1998 年由 Microsoft 在 Internet Explorer 中引入的 ActiveX 组件。

然而，这项技术实际上在 2005 年得到了广泛的应用，当时*杰西·加勒特*（Jesse Garrett）撰写了一篇题为《Ajax:一种新的网络应用程序方法》的文章。2006 年 4 月，万维网联盟发布了`XMLHttpRequest`对象的第一个草案标准，这是当今所有现代浏览器中所有 AJAX 应用程序的底层对象。

在本章中，我们将构建一个简单的 AJAX 应用程序，该程序通过**自动数据包报告系统**（**APRS**）网络返回一个业余无线电台报告的纬度和经度，这些数据由[`www.aprs.fi/`](http://www.aprs.fi/)网站进行缓存，这是一个在业余无线电台社区中广受欢迎的网站。我们将使用 HTML 和 JavaScript 为 Google Chrome 和 Internet Explorer 构建客户端，并使用 Node.js 构建服务器端。

### 提示

首先，请确保你按照第二章，*在服务器上读写 JSON*，中的*使用 Node.js 读写 JSON*部分安装了 Node.js。你还需要安装 Node.js 的 request 模块。在安装 Node.js 后，通过命令提示符运行`npm install request`来实现。

## 设置服务器

我们将从一个骨架服务器开始。为你的 node 应用程序创建一个目录，并将以下内容保存到`json-encoder.js`中：

```js
var http = require('http');
var fs = require('fs');
var url = require('url');

http.createServer(function(req, res) {
if (req.method == 'POST') {
  console.log('POST');
  var body = '';
  req.on('data', function(data) {
    body += data;
  });
  req.on('end', function() {     
    res.writeHead(200, 
     {'Content-Type': 'application/json'});
    res.end("null");
    });
  } 
  elseif (req.method == 'GET')
  {
    console.log('GET');
    var urlParts = url.parse(req.url);
    if (urlParts.pathname == "/favicon.ico")
    {
      res.end("");
      return;
    }

    res.writeHead(200, {'Content-Type': 'text/plain'});

    var html = fs.readFileSync('./public' + urlParts.pathname);
    res.writeHead(200, {'Content-Type': 'text/html'});
    res.end(html); 
    return;    
  }
}).listen(1337, 'localhost');
console.log('Server running at http://127.0.0.1:1337');
```

这段代码处理两种 HTTP 请求：`POST` 请求和 `GET` 请求。它首先分配了 `http`、`filesystem` 和 `url` 操作对象，然后在本地的 `1337` 端口上注册了一个 HTTP 服务器。它的服务器根据请求类型进行切换。对于 `POST` 请求，它目前返回一个空的 JSON 体，忽略其传入的内容。对于 `GET` 请求，它尝试从当前工作目录下面的 `public` 子目录中加载 URL 指示的文件，并将其作为 HTML 文档返回给客户端。如果传入的请求是针对 favicon 的，它将忽略该请求。

这个服务器很原始但足以满足我们的需求。如果你对学习更多关于 Node.js 的内容感兴趣，你可能会想为以下目的扩展它：

+   正确确定返回文档的 MIME 类型，并根据文档的 MIME 类型发送适当的 `Content-Type` 头部。

+   如果找不到给定的文档，不要抛出异常并杀死服务器，而是返回一个 404 页面未找到错误。

我们将在本章中扩展服务器端的 JavaScript。

## 设置客户端页面

在 `json-encoder.js` 中创建一个子目录，并将其命名为 `public`。在这个目录中，创建一个包含以下 HTML 的 HTML 文件，并将其命名为 `json-example.html`：

```js
<!DOCTYPE html>
<html>
<head>

</head>
<body onload="doAjax()">

<p>Hello world</p>
<p>
<div id="debug"></div>
</p>
<p>
<div id="json"></div>
</p>
<p>
<div id="result"></div>
</p>

<p>Powered by <a href="http://www.aprs.fi">aprs.fi</a></p>

<script type="text/javascript">
var debug = document.getElementById('debug');

function doAjax() {
  document.getElementById("result").innerHTML = 
    "loaded... executing.";
}
</script>
</body>
</html>
```

这是一个包含三个 `div` 标签的简单 HTML 文档，我们将从异步请求中填充这些标签的数据：`debug` 用于显示调试信息；`json` 用于显示原始 JSON；`result` 用于显示实际结果，这将显示从解析 JSON 的 JavaScript 对象中获取的格式化数据。页面底部有一个脚本 `doAjax`，浏览器在加载所有 HTML 后通过 `body` 标签的 `onload` 属性调用它。

在 Chrome 中使用开发者工具激活加载网页，你应该看到类似这样的内容：

![设置客户端页面](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-json-cb/img/6902OS_03_01.jpg)

我们将在本章中扩展 HTML。

# 创建 XMLHttpRequest 对象

所有现代网络浏览器都提供了一个 `XMLHttpRequest` 类，你可以在代码中实例化它，你可以使用它发出异步调用以通过 HTTP 获取内容。你将在客户端的 JavaScript 中使用 `new` 操作符创建一个或多个这样的实例。

## 如何进行...

你希望在 JavaScript 页面加载后尽早创建这个类的实例，如下面的代码所示：

```js
function doAjax() {
var xmlhttp;
if (window.XMLHttpRequest)
  {
    // code for IE7+, Firefox, Chrome, Opera, Safari
    xmlhttp=new XMLHttpRequest();
  }
}
```

## 它是如何工作的…

上述代码测试了根级别的 JavaScript `window` 对象是否具有 `XMLHttpRequest` 类，如果浏览器定义了该类，则为我们创建了该类的实例，以便在制作异步请求时使用。

## 参见

如果你正在使用一个非常旧的 Internet Explorer 版本，你可能需要使用一个 `Microsoft.XMLHTTP` ActiveX 对象。在这种情况下，`window.XMLHttpRequest` 的测试将失败。

# 制作数据异步请求

您使用创建的`XMLHttpRequest`类的实例来请求数据。您可以使用任何 HTTP 方法来请求数据；通常您会使用 GET 或 POST。GET 很好，如果您不需要传递任何参数，或者如果参数已编码在服务 URL 中；POST 是必要的，如果您需要将 JSON 作为服务器端脚本的参数提交给服务器。

## 如何做到...

继续增强我们的客户端页面脚本`doAjax`函数，以下是如何发起异步请求，修改之前的示例：

```js
function doAjax() {
  var xmlhttp;
  if (window.XMLHttpRequest)
  {
    // code for IE7+, Firefox, Chrome, Opera, Safari
    xmlhttp=newXMLHttpRequest();

    xmlhttp.open("POST","/", true);
    xmlhttp.send("");
  }
}
```

## 它是如何工作的…

`XMLHttpRequest`类有两个用于发起请求的方法：`open`和`send`。您使用`open`方法来开始发出请求的过程，如果需要发送数据（例如，与`POST`请求一起）供服务器处理，则使用`send`方法。

`open`方法接受三个参数：HTTP 方法、URL（相对于包含脚本的页面）和一个布尔值，指示请求是否应为同步（由值`false`表示）或异步（由值`true`表示）。在前面的代码中，我们向 web 服务器的根提交了一个`POST`请求，并请求浏览器以异步方式处理请求，因此页面将被渲染，用户可以与页面交互。

`send`方法接受一个参数，一个包含您希望发送给服务器的数据的字符串。在这个例子中，我们不发送任何东西；我们将使用这个方法来发送我们的参数的 JSON。

## 也见

这个菜谱与下一个菜谱*向你的 web 服务器发送 JSON*非常相关，我们在其中实际上创建了一个 JavaScript 对象，将其字符串化，并使用`send`方法发送它。

# 向你的 web 服务器发送 JSON

有些 AJAX 请求只需要从 URL 获取数据。这种情况下，服务器为所有客户端更新一个对象，或者当一个对象的 URL 唯一地标识该对象时（在设计使用**代表性状态转移**（**REST**）的服务时很常见）。其他时候，您可能希望将 JavaScript 数据传递给服务器，例如当您有一个复杂的查询需要服务器处理时。为此，创建您的 JavaScript 对象，然后将其字符串化，并将包含 JSON 的字符串传递给`XMLHttpRequest`对象的`send`方法。

## 如何做到...

省略创建`XMLHttpRequest`对象的代码，您使用以下代码向服务器发送 JSON：

```js
function doAjax() {
  // … create XMLHTTPObject as before

    var request = { 
    call: "kf6gpe-7"
  };

xmlhttp.open("POST","/", true);
xmlhttp.setRequestHeader("Content-Type","application/json");
xmlhttp.send(JSON.stringify(request));
}
```

请注意，我们这里使用了一个 HTTP `POST`请求，它将 JSON 文档作为 HTTP 对象主体提交给服务器。

## 它是如何工作的…

这段代码创建了一个具有单个字段：call 的 JavaScript 对象请求。call 字段的值设置为我们寻找的车站，服务器在处理请求时会使用它。

当你向服务器传递数据时，你应该正确设置 Content-Type 头，HTTP 使用这个头来指示服务器正在传输的数据类型。JSON 的 MIME 类型是 application/json；然而，一些网络应用程序开发者选择了其他表示形式，如`text/x-json`、`text/x-javascript`、`text/javascript`或`application/x-javascript`。除非你有充分的理由（想想服务器上无法修复的遗留代码），否则你应该使用`application/json`。你通过使用`setRequestHeader`方法设置一个请求头来自定义内容类型。这个方法有两个参数：要设置的头的名称及其值。请注意，头名称是大小写敏感的！

一旦设置了请求头，最后要做的就是调用`send`并传递字符串化的 JavaScript 对象。我们在前面的示例的最后一行这样做。

# 使用 Node.js 接受 JSON

不同的网络服务器系统以不同的方式接受客户端提交的数据。话说回来，在大多数情况下，你按片读取来自客户端的数据，一旦 POST 请求完成，就将其作为一批数据处理。以下是使用 Node.js 进行处理的方法。

## 如何做到这一点...

在我们的案例中，我们通过 HTTP `POST`请求接受客户端提交的 JSON。为此，我们需要从客户端读取数据，将其汇总成字符串，当所有数据到达服务器时，将数据从 JSON 字符串转换为 JavaScript 对象。在 json-encoder.js 中，我们将其修改为如下所示：

```js
 // … beginning of script is the same as in the introduction
    if (req.method == 'POST') {
 console.log('POST');
 var body = '';
 req.on('data', function(data) {
 body += data;
 });
 req.on('end', function() { 
 var json = JSON.parse(body);
 json.result = 'OK';
 res.writeHead(200, 
 {'Content-Type': 'application/json'});

 res.end(JSON.stringify(json));
 });
  }
  // and script continues with the GET if statement and code
```

## 它是如何工作的…

前面的代码扩展了本章介绍中的服务器端 Node.js 脚本。这段代码首先检查`POST`请求方法。如果我们收到一个`POST`请求，我们创建一个空字符串`body`来包含请求的主体。Node.js 是事件驱动的；为了从`POST`请求中读取数据，我们向请求添加了一个`'data'`事件处理程序，该处理程序将新读取的数据连接到变量`body`所引用的值。

在某个时刻，`POST`请求结束，这导致请求引发`'end'`事件。我们为这个事件注册一个事件处理程序，该处理程序使用`JSON.parse`解析传入的 JSON。然后，我们在结果对象中设置一个额外的字段，即结果字段，并将其值设为**'** `OK`**'**。最后，我们使用`writeHead`和`end`方法分别设置内容类型头和向客户端写入代表该对象的 JSON。

## 也请参阅

如引言中所建议，你如何在服务器上读取已提交的数据很大程度上取决于服务器环境和服务器端脚本语言。如果你以前没做过这件事，去一个搜索引擎，比如 Bing 或 Google，是很有必要的。一旦你这样做，准备好取出的字符串数据，并在你的服务器端脚本语言中使用其中一个食谱将其转换为对象，这个食谱来自第二章，*阅读和编写服务器端的 JSON*。

# 获取异步请求的进度

我们的请求相当轻量级，但这种情况在你的应用程序中并不总是如此。此外，在移动网络应用程序中，特别是在移动设备可能进入和退出网络覆盖并遭受暂时性网络中断时，进度的监控尤为重要。一个健壮的应用程序将测试进度状态和错误，并重试重要的请求。

`XMLHttpRequest`对象提供了事件，用于通知你有关待处理请求的进度。这些事件如下：

+   `load`: 此事件在你打开一个连接后立即执行。

+   `loadstart`: 此事件在加载开始时执行。

+   `progress`: 此事件在加载过程中定期执行。

+   `error`: 在发生网络错误的情况下执行此事件。

+   `abort`: 在网络交易被取消的情况下执行此事件（例如，用户导航离开发出请求的页面）。

## 如何实现...

对于这些事件中的每一个，你都希望注册一个以某种方式处理事件的函数。例如，`error`处理程序应该通知用户发生了错误，而`abort`处理程序应该在请求被放弃的情况下清理任何客户端数据。

以下是一个如何实现此功能的示例，它报告了这些事件的调试信息；这将是我们的示例 HTML 文件底部`<script>`标签中的内容：

```js
// Add the following functions to the script in the HTML…
function progress(evt){
  debug.innerHTML += "'progress' called...<...<br/>";/>";
}

function abort(evt){
  debug.innerHTML += "'abort' called...<br />";
}

function error(evt){
  debug.innerHTML += "'error' called...<br />";
}

function load(evt){
  debug.innerHTML += "'load' called...<br />";
}

function loadstart(evt){
  debug.innerHTML += "'loadstart' called<br />;
}

function doAjax() {
  // create xmlhttp object as usual

  var request = { 
    call: "kf6gpe-7"
  };

 xmlhttp.addEventListener("loadstart", loadstart, false);
 xmlhttp.addEventListener("progress", progress, false); 
 xmlhttp.addEventListener("load", load, false);
 xmlhttp.addEventListener("abort", abort, false);
 xmlhttp.addEventListener("error", error, false);

  // issue request in the usual way…
}
```

## 如何工作...

`XMLHttpRequest`对象提供了`addEventListener`方法，你可以用它来注册对象在特定事件发生时应该调用的函数。向这个方法传递事件名称、要在事件上执行的函数（或闭包）以及是否应该捕获事件（通常不捕获）的布尔值。在前面的示例中，我们对每个事件调用该方法，传递我们编写来处理事件的函数。我们的每个函数只是记录了事件在 HTML 内容中的 debug div 中已接收的事实。

## 还有更多...

`XMLHttpResult`对象定义了一个属性`onreadystatechange`，你可以向其分配一个函数，该对象在请求运行期间会定期调用此函数。下一个食谱，《解析返回的 JSON》描述了如何使用此功能来监控请求的状态。

这些事件的行为在不同的浏览器之间以及浏览器版本之间都有所不同。例如，微软 Internet Explorer 的早期版本（版本 9 之前）根本不支持这些事件。如果你的网页应用程序要在多个浏览器上运行，特别是如果它们是不同版本的情况下，你应该采取最低公倍数的方法来处理这些事件。

## 另见

由于对这些事件的支持因浏览器和浏览器版本而异，因此在使用这些事件方面使用像 jQuery 或 AngularJS 这样的 JavaScript 框架确实很有帮助。这些框架抽象了特定的浏览器差异。第四章讨论了使用这些框架进行 AJAX 的方法。

请参阅第四章中的*使用 jQuery 和 AngularJS 获取异步请求的进度*和*使用 AngularJS 获取异步请求的进度*，了解响应这些事件的浏览器无关方法。

# 解析返回的 JSON 数据

一旦服务器返回结果，你需要一种方法从 `XMLHttpRequest` 对象中获取该结果，并将结果从字符串转换为 JavaScript 对象。

## 如何做到...

`XMLHttpRequest` 对象定义了 `onreadystatechange` 属性，你将一个函数分配给它，这个函数在整个请求的生命周期中定期被调用。以下是完整的 `doAjax` 函数，包括分配给这个属性的一个函数，用于监视请求的完成情况：

```js
function doAjax() {
  var xmlhttp;
  xmlhttp = new XMLHttpRequest();

  var request = { 
    call: "kf6gpe-7"
  };

  xmlhttp.addEventListener("loadstart", loadstart, false);
  xmlhttp.addEventListener("progress", progress, false);  
  xmlhttp.addEventListener("load", load, false);
  xmlhttp.addEventListener("abort", abort, false);
  xmlhttp.addEventListener("error", error, false);

 xmlhttp.onreadystatechange = function() {
 if (xmlhttp.readyState == 4 &&xmlhttp.status == 200)
 {
 var result = JSON.parse(xmlhttp.responseText);
 document.getElementById("json").innerHTML = 
 xmlhttp.responseText;
 document.getElementById("result").innerHTML = result.call + ":" 
+ result.lat + ", " + result.lng;
 }
 };

xmlhttp.open("POST","/", true);
xmlhttp.setRequestHeader("Content-type","application/json");
xmlhttp.send(JSON.stringify(request));
}
```

## 它是如何工作的…

在添加了各种事件监听器之后，我们将一个函数分配给 `onreadystatechange` 属性。每当请求对象的状态发生变化时，这个函数就会被调用；每次调用时，我们测试请求对象的 `readyState` 字段及其状态。`readyState` 字段表示请求的状态；我们关注的状态是 4，它表示请求已完成。一旦请求完成，我们可以在请求的 `status` 字段中找到请求的 HTTP 状态；HTTP 状态码 200 表示从服务器读取内容的成功状态。

一旦我们得到 `readyState` 4 和 HTTP 状态 200，我们定义了一个新变量 `result` 作为由服务器返回的 JSON 解析后的对象，该对象可从请求的 `responseText` 字段中获得。你可以随意处理结果对象；我们将 JSON 复制到 `jsondiv`，这样你就可以看到 JSON 并在创建 `resultdiv` 的内容时读取 JavaScript 对象的几个字段。

## 还有更多...

`XMLHttpRequest` 类定义了以下就绪状态：

+   0 表示请求尚未初始化

+   1 表示请求已设置

+   2 表示请求已发送

+   3 表示请求正在进行中

+   4 表示请求已完成

在实际应用中，你通常应该只使用最后一个值，并用事件进行其他进度报告。

HTTP 结果代码在 HTTP 请求的注释中定义，互联网 RFC 2616；您对此感兴趣的部分位于[`www.w3.org/Protocols/rfc2616/rfc2616-sec10.html`](http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html)。200 系列的结果表示事务成功；您如何处理其他通知将取决于您 Web 应用程序的业务逻辑。

最终的 Node.js 服务器看起来像这样：

```js
var http = require('http');
var fs = require('fs');
var url = require('url');
var request = require("request");

console.log("Starting");

http.createServer(function(req, res) {
  if (req.method == 'POST') {
    console.log('POST');
    var body = '';
    req.on('data', function(data) {
      body += data;
    });
    req.on('end', function() {         
      var json = JSON.parse(body);
      var apiKey = "<<key>>";
      var serviceUrl = "http://api.aprs.fi/api/get?name=" + 
      json.call + "&what=loc&apikey=" + apiKey + "&format=json"; 
      request(serviceUrl, function(error, response, body) {
        var bodyObject = JSON.parse(body);
        if (bodyObject.entries.length>0)
        {
          json.call = bodyObject.entries[0].name;
          json.lat = bodyObject.entries[0].lat;
          json.lng = bodyObject.entries[0].lng;
          json.result = "OK";
        }
        else
        {
          json.result = "ERROR";
        }
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify(json));
      });
    });
  } 
  elseif (req.method == 'GET') 
  {
    console.log('GET');
    var urlParts = url.parse(req.url);
    if (urlParts.pathname == "/favicon.ico")
    {
      res.end("");
      return;
    }
    res.writeHead(200, {'Content-Type': 'text/plain'});
    var html = fs.readFileSync('./public' + urlParts.pathname);
    res.writeHead(200, {'Content-Type': 'text/html'});
    res.end(html); 
    return;    
  }
}).listen(1337, 'localhost');
console.log('Server running at http://localhost:1337');
```

# 使用 Node.js 发出 Web 服务请求

到目前为止，我们的服务器对`POST`请求的响应不做太多事情；它所做的就是返回“OK”并将客户端的 JSON 返回给客户端。通常，您的服务器需要对您提供的 JSON 做些事情，例如，进行 Web 或数据库查询，或者执行计算。我们的示例查询位于[`www.aprs.fi/`](http://www.aprs.fi/)的 Web 服务 JSON 端点，让您了解如何使用 Node.js 进行服务器到服务器的 Web 服务请求。

## 准备

如果您想亲自运行示例，首先需要去[`www.aprs.fi`](http://www.aprs.fi)注册一个账户，并获得一个 API 密钥。按照页面上的链接进行操作，并将随后的示例中的文本`"—key-"`替换为您的 API 密钥。

## 如何做到...

我们的 Node.js 代码将构建一个包含我们感兴趣的车站标识符和我们的 API 密钥的 URL，并代表客户端发出额外的 HTTP 请求。它看起来像这样：

```js
var request = require('server');

///...

if (req.method == 'POST') {
  console.log('POST');
  var body = '';
  req.on('data', function(data) {
    body += data;
  });
  req.on('end', function() {     
     var json = JSON.parse(body);
 var apiKey = "—key-";
 var serviceUrl = "http://api.aprs.fi/api/get?name=" + 
 json.call + 
 "&what=loc&apikey=" + apiKey + 
 "&format=json";

 request(serviceUrl, function(error, response, body) {
 var bodyObject = JSON.parse(body);
 if (bodyObject.entries.length>0)
 {
 json.call = bodyObject.entries[0].name;
 json.lat = bodyObject.entries[0].lat;
 json.lng = bodyObject.entries[0].lng;
 json.result = "OK";
 }
 else
 {
 json.result = "ERROR";
        }
        res.writeHead(200, 
          {'Content-Type': 'application/json'});

        res.end(JSON.stringify(json));
      });
    });
  } 
  elseif (req.method == 'GET')
  {
    // …Original GET handling code here…
  }
}).listen(1337, 'localhost');
console.log('Server running at http://127.0.0.1:1337');
```

## 它是如何工作的…

在将客户端 JSON 转换为 JavaScript 对象后，代码创建了一个包含请求车站标识符、API 密钥以及我们想要为结果获取 JSON 的 Web 请求 URL。然后我们使用`request`方法向该 URL 发出简单的`GET`请求，并传递一个 Node.js 将在请求成功时调用的函数。

Node.js 用错误指示器、包含 HTTP 响应详情的响应对象以及请求返回的正文调用我们的回调函数。在此示例中，我们假设成功以节省篇幅，并使用`JSON.parse`将结果正文从 JSON 转换为 JavaScript 对象。结果对象是一个类似于您在*介绍*部分看到的第一章，*在客户端读写 JSON*中的 JavaScript 对象。它有一个 entries 数组，有零个或多个记录，指示记录中的`lat`和`lng`字段中每个车站的位置。我们提取返回的第一个结果并将相关数据复制到我们将返回给原始客户端的 JavaScript 对象中。

## 还有更多...

大多数服务器端框架提供了各种修改 Web 服务请求语义的方法，包括指定头部和发出请求时使用的 HTTP 方法。Node.js 的请求模块也不例外。

首先，请求方法可以接受一个 JavaScript 对象，而不是一个 URL，其中有多个字段允许您自定义请求。如果您传递一个对象，您应该将请求应发送到的 URL 放在 URI 或 URL 属性中。您还可以指定以下内容：

+   要使用的 HTTP 方法，通过 method 参数传入

+   要发送的 HTTP 头，作为具有每个头属性-值对的 JavaScript 对象，在 attribute headers 中传入每个头

+   对于`PATCH`、`POST`和`PUT`方法请求，要传递给客户端的正文，在 body 属性中传入

+   超时时间，在超时属性中以毫秒为单位表示等待多长时间

+   是否对响应进行 gzip 压缩，通过设置 gzip 属性为`true`来指示

还有其他选项可供选择。详情请参阅 Node.js 文档，网址为[`nodejs.org/api/index.html`](https://nodejs.org/api/index.html)。

## 另见

Node.js 请求模块的文档在 GitHub 上，网址为[`github.com/request/request`](https://github.com/request/request)


# 第四章．使用 jQuery 和 AngularJS 在 AJAX 应用程序中使用 JSON

在本章中，我们将探讨 JSON 在提供比旧网页更好的响应性的异步 JavaScript 和 XML（AJAX）应用程序中所起的作用。在本章中，您将找到以下食谱：

+   在您的网页中添加 jQuery 依赖关系

+   使用 jQuery 请求 JSON 内容

+   使用 jQuery 将 JSON 发送到您的网络服务器

+   使用 jQuery 获取请求的进度

+   使用 jQuery 解析返回的 JSON

+   在您的网页中添加 AngularJS 依赖关系

+   使用 AngularJS 请求 JSON 内容

+   使用 AngularJS 将 JSON 发送到您的网络服务器

+   使用 AngularJS 获取请求的进度

+   使用 AngularJS 解析返回的 JSON

# 简介

在上一章中，您看到了展示如何使用`XMLHttpRequest`来制作交换 JSON 的 AJAX 请求的食谱。在实际中，处理不同浏览器中的所有特殊情况使得这项工作变得繁琐且容易出错。幸运的是，大多数客户端 JavaScript 框架为您包装了这个对象，为您提供了一种与浏览器无关的方法来做同样的事情。通常，这个界面也更容易使用——正如您即将看到的，在 AngularJS 的情况下，您不需要做任何特别的事情就可以使用 JSON 在对象之间移动；该框架甚至为您处理 JSON 的序列化和反序列化！

both AngularJS 和 jQuery 都是使开发网络应用程序更简单的客户端 JavaScript 框架。jQuery 是第一个也是最受欢迎的框架之一；AngularJS 是较新的，并且具有提供使用**模型-视图-控制器**（**MVC**）范式的额外优势，使您的代码结构更加清晰。

### 提示

MVC 是一种设计模式，可以追溯到几十年以前，最初是在 20 世纪 70 年代的 Smalltalk 中引入的。这种模式将您的代码分为三个不同的部分：模型，包含用户想要操作的数据；视图，显示模型的内容；控制器，接受事件并在接受的事件发生时更改模型。

在本章中，我们将使用我们在上一章的食谱中基于的 Node.js 服务器，并扩展支持提供客户端 JavaScript 以及 HTML。以下是本节的代码，逐步分解如下：

```js
var http = require('http');
var fs = require('fs');
var url = require('url');
var request = require("request");
```

这四行包括了我们的服务器需要的接口——处理 HTTP 服务器模块、文件系统模块、URL 解析模块以及一个简单的模块来发送 HTTP 请求。

接下来，我们记录服务器启动的情况，并创建一个 HTTP 服务器，它用一个函数回调接受所有请求：

```js
console.log("Starting");
http.createServer(function(req, res) {
```

我们的服务器处理两种类型的请求：`POST`请求和`GET`请求。`POST`请求处理程序需要读取被发送到服务器的传入数据，我们通过将其与一个最初为空的`body`缓冲区连接起来来实现：

```js
  if (req.method == 'POST') {
    console.log('POST');
    var body = '';
    req.on('data', function(data) {
      body += data;
    });
```

我们注册了一个函数，当 Node.js 完成 HTTP POST 请求时会调用它，该函数解析 JSON 并对远程服务器发起`GET`请求以获取我们的数据，模拟中间件服务器可能会执行的操作：

```js
    req.on('end', function() {         
      var json = JSON.parse(body);

      var apiKey = " --- api key here --- ";
      var serviceUrl = "http://api.aprs.fi/api/get?name=" + 
        json.call + "&what=loc&apikey=" + apiKey + "&format=json";
```

这个请求本身有一个回调，它解析来自远程服务器的传入 JSON，在结果条目属性中查找数组的第一个元素，并构造一个 JSON 对象以返回给 Web 客户端。如果我们没有得到有效的响应，我们设置一个错误值，以便客户端可以对错误做些什么。我们通过将 JavaScript 对象转换为 JSON 并将其写入客户端来返回这个：

```js
      request(serviceUrl, function(error, response, body) {
        var bodyObject = JSON.parse(body);
        if (bodyObject.entries.length>0)
        {
          json.call = bodyObject.entries[0].name;
          json.lat = bodyObject.entries[0].lat;
          json.lng = bodyObject.entries[0].lng;
          json.result = "OK";
        }
        else
        {
          json.result = "ERROR";
        }
        res.writeHead(200, {'Content-Type': 'application/json'});
        res.end(JSON.stringify(json));
      });
    });
  } 
```

如果我们处理的不是`POST`请求，那它可能是一个`GET`请求。以下是上一章的新代码。我们需要确定传入的 URL 是否表示要获取的内容是 HTML 文件（其扩展名为`.html`或`.htm`）还是 JavaScript 文件（其扩展名为`.js`）。首先，我们检查是否正在请求一个 favicon；Chrome 总是这样做，我们只是返回一个空的对象体。假设请求的不是 favicon，我们检查传入的 URL 如何结束，以便我们可以写出适当的内容类型头（text/html 或 application/json）。如果不是这些，我们假设是纯文本，并发送一个 text/plain 内容类型头：

```js
  else if (req.method == 'GET') 
  {
    console.log('GET');
    var urlParts = url.parse(req.url);
    if (urlParts.pathname == "/favicon.ico")
    {
      res.end("");
      return;
    }

    if (urlParts.pathname.lastIndexOf(".html") == 
          urlParts.pathname.length - 5 ||
        urlParts.pathname.lastIndexOf(".htm") == 
          urlParts.pathname.length - 4)
    {
      res.writeHead(200, {'Content-Type': 'text/html'});
    }
    else if (urlParts.pathname.lastIndexOf(".js") == 
      urlParts.pathname.length - 3)
    {
      res.writeHead(200, {'Content-Type': 'application/json'});
    }
    else
    {
      res.writeHead(200, {'Content-Type': 'text/plain'});            
    }
```

接下来，我们从 Node.js 服务器源下面的公共目录中读取内容并返回给客户端：

```js
    var c = fs.readFileSync('./public' + urlParts.pathname);
    res.end(c); 
    return;    
  }
```

最后，这个大函数作为监听 HTTP 服务器注册在本地主机的端`1337`上，我们记录服务器已启动：

```js
}).listen(1337, 'localhost');
console.log('Server running at http://localhost:1337');
```

### 提示

一个真正的服务器可能不应该通过查看传入的 URL 来猜测返回数据的 MIME 类型，而应该实际上嗅探出去的数据并做出关于 MIME 类型的决定。有一个 Node.js 模块 magic 可以做到这一点；如果您稍微不那么偏执，可以使用磁盘上的文件名后缀，并希望内容提供商正确地命名文件。

这就是服务器的内容，您可以在随书附带的样本 ZIP 文件中找到它。

# 向您的网页添加 jQuery 依赖

jQuery 是一个流行的客户端框架，用于 AJAX 应用程序，它为您提供了浏览器无关的支持，用于搜索和操作**文档对象模型**（**DOM**）和**层叠样式表**（**CSS**），执行 AJAX 查询，以及包括几个可以使用 CSS 样式的 HTML 控件。您需要在您的页面中包含 jQuery 的源代码，要么通过指向 jQuery 内容分发网络（CDN）上的发布版本，要么通过访问[`www.jquery.com`](http://www.jquery.com)并下载框架的副本，以便与您自己的应用程序一起使用。

## 如何做到这一点...

您需要通过开始一个新的 json-example.html 文件来包含 jQuery 库，像这样：

```js
<!doctype HTML>
<html>
<head>
  <script type="text/javascript"
    src="img/jquery-1.11.2.min.js"></script>
</head>
```

## 它是如何工作的…

这两行包含了两个包含从 jquery.com CDN 获取的 jQuery 客户端库压缩版本的脚本。这可能正是你在生产应用程序中想要做的事情；压缩的 jQuery 实现比完整的库要小，所以客户端下载更快，使用 CDN 上的版本提供的性能可能比你自己能提供的性能还要快，除非你在像 Amazon Web Services 或 Microsoft Azure 这样的主要云服务提供商上托管多个服务器。

## 还有更多…

如果你不想包含压缩版本——这通常在你深入开发周期并希望调试代码时发生——你可以从你的服务器上提供标准版本。只需从[`www.jquery.com/`](http://www.jquery.com/)下载必要的文件，并从你的服务器上提供它们。

jQuery 有两个版本：1.x 版本，支持较老的浏览器，包括 Microsoft Internet Explorer 6 及以上版本，而 2.x 版本至少需要 Microsoft Internet Explorer 9。我们的示例将使用 jQuery 1.x，但不用担心；我们讨论的 API 在 jQuery 2.x 中也是一样的。

## 参见

前往[`www.jquery.com`](http://www.jquery.com)下载 jQuery 或了解更多关于它的信息。如果你正在寻找一个 JavaScript 框架，也许值得查看 jQuery 学习中心在[`learn.jquery.com/`](http://learn.jquery.com/)的内容，或者也许可以看看 Packt Publishing 的书籍，《学习 jQuery – 第四版》，作者是 Jonathan Chaffer 和 Karl Swedberg。

# 使用 jQuery 请求 JSON 内容

jQuery 定义了变量`$`，暴露了你想要与界面做的所有方法的接口。（有一种方法可以重命名该变量，比如说如果你正在与其他使用相同变量的 JavaScript 环境一起工作，但我建议不要这样做）。`$`暴露的方法之一是`ajax`方法，你可以用它来发起 AJAX 查询。让我们来看看它是如何做到的。

## 如何做到…

这是一个整页的 AJAX 请求。AJAX 代码是粗体的：

```js
<!doctype HTML>
<html>
<head>
<script  type="text/javascript"
  src="img/"></script>
</head>
<body>

<p>Hello world</p>
<p>
  <div id="debug"></div>
</p>
<p>
  <div id="json"></div>
</p>
<p>
  <div id="result"></div>
</p>

<p>Powered by <a href="http://www.aprs.fi">aprs.fi</a></p>

<script>
$(function () {
 $('#debug').html("loaded... executing.");

 var request = { 
 call: "kf6gpe-7"
 };

 $.ajax({
 type: "POST",
 url: "/",
 dataType:"json"  });
});

</script>
</body>
</html>
```

这个例子中的 HTML 很简单。它包含了 jQuery 模块，然后为 AJAX 请求定义了三个`div`区域，在请求完成后更新。让我们更详细地看看 JavaScript 函数`doAjax`。

## 它是如何工作的…

`doAjax`函数，在页面加载完成后调用，首先将名为`debug`的`div`的 HTML 内容设置为文本"`loaded… executing.`"。`$()`语法是 jQuery 用来在 DOM 中查找项目的语法；你可以通过在名称前加上`#`（哈希）符号来找到项目，就像 CSS 选择器一样。返回的值不是实际的 DOM 元素，而是一个包含简单方法如`html`以获取或设置项目 HTML 内容的 jQuery 类，该类包装了 DOM 元素。

接下来，我们定义一个 JSON 对象，其中包含我们请求的详细信息，就像前章的食谱中所做的那样。它有一个属性，`call`，包含我们感兴趣的站的呼号。

接下来，我们调用$的`ajax`方法，传递一个具有我们请求语义的 JavaScript 对象。它应该包含以下字段：

+   `type`字段，表示请求的 HTTP 方法（如`POST`或`GET`）。

+   `url`字段，表示请求应提交的 URL。

+   `data`字段，包含要发送到服务器的请求（如果有）的字符串数据。我们将在下一个食谱中看到它的使用。

+   `dataType`字段，表示你期望从服务器获得的数据类型；一个可选字段，可以是`xml`、`json`、`script`或`html`。

## 参见 also

好奇的读者应该查阅 jQuery `ajax`方法文档，该文档可在[`api.jquery.com/jQuery.ajax/`](http://api.jquery.com/jQuery.ajax/)找到。

# 使用 jQuery 将 JSON 发送到你的网络服务器

使用 jQuery 将 JSON 发送到你的服务器是很容易的。只需获取 JSON 格式的数据，并使用`ajax`方法参数的`data`字段指定它。

## 如何做到…

让我们再次看看`doAjax`，这次修改以发送我们的 JSON 请求：

```js
function doAjax() {
  $('#debug').html("loaded... executing.");

  var request = { 
    call: "kf6gpe-7"
  };

  $.ajax({
    type: "POST",
    url: "/",
    data: JSON.stringify(request),
    dataType:"json"
  });
}

</script>
</body>
</html>
```

## 它是如何工作的…

上一列表中的魔法行被突出显示；它是传递给`ajax`方法的参数中的以下行：

```js
    data: JSON.stringify(request),
```

当然，我们使用`JSON.stringify`将 JavaScript 对象编码为 JSON，然后将其分配给 data 字段。

# 使用 jQuery 获取请求进度的方法

jQuery 以一种与平台无关的方式抽象化了底层`XMLHttpRequest`对象的各个进度报告机制，赋予您确定您的请求是否成功或失败的能力。您通过注册函数来实现，这些函数将在发生错误或结果成功加载时由 jQuery AJAX 处理程序调用。

## 如何做到…

下面是`doAjax`重写以支持在失败时获取通知的代码，无论事件成功还是失败：

```js
function doAjax() {
  $('#debug').html("loaded... executing.");

  var request = { 
    call: "kf6gpe-7"
  };

  $.ajax({
    type: "POST",
    url: "/",
    data: JSON.stringify(request),
    dataType:"json",
  })
 .fail(function() {
 $('#debug').append("<br/>failed");
 })
 .always(function() {
 $('#debug').append("<br/>complete");
 });
}
```

这里的新方法是`fail`和`always`方法。

## 它是如何工作的…

jQuery 使用一种称为*链式调用*的模式，其中大多数方法返回一个实例，您可以对该实例应用其他方法。因此，像`fail`和`always`这样的方法在同一个对象上操作，并返回相同的对象，该对象使用链式调用封装了`$.ajax`方法调用的返回值，使得代码更易读、更易写。在`$.ajax`的情况下，返回的是一个 jQuery `XMLHttpRequest`对象的实例，其字段是浏览器返回的`XMLHttpRequest`对象的超集。

在这里，我在`$.ajax`的返回值上设置了两个事件处理程序：一个是用于失败情况的，即请求因某些原因失败；另一个是用于始终情况的。请注意，由于链式调用的存在，我可以将这些处理程序颠倒过来，将始终情况的处理程序放在前面，将失败情况的处理程序放在后面。究竟哪个在前完全取决于你的个人喜好。

`always`和`failure`方法都接受一个函数，该函数可以接受多达三个参数。在这种情况下，我没有使用任何可用的参数，只是将一些文本添加到具有`id`为 debug 的`div`区域的 HTML 中。当请求成功完成时，jQuery 将`failure`事件处理程序传递给 jQuery `XMLHttpRequest`对象，以及与失败相关的文本状态消息和错误代码，而将`always`方法传递给错误情况下的这些参数，或者传递给数据、文本状态消息和 jQuery `XMLHttpRequest`对象。

## 还有更多…

如果你愿意，你可以在`$.ajax`的初始 JavaScript 对象参数的名为 error 的属性中指定失败事件处理程序作为一个函数。同样，你也可以在初始 JavaScript 对象的名为`complete`的属性中指定始终事件处理程序作为一个函数。虽然这样可以将在一个地方放置所有代码，但我个人认为这样更难读，因为缩进可能会很快变得难以控制。

# 使用 jQuery 解析返回的 JSON

最后，是时候看看如何从服务器获取返回的 JSON 并使用它了。你会通过在`$.ajax`上注册一个事件处理程序来接收结果的 JavaScript 对象，jQuery 会为你从 JSON 中很乐意地反序列化这个对象。

## 如何做到…

为了从 AJAX 请求中获取结果，我们需要在 jQuery `XMLHttpRequest`对象的`done`事件上添加一个事件处理程序，如下所示：

```js
function doAjax() {
  $('#debug').html("loaded... executing.");

  var request = { 
    call: "kf6gpe-7"
  };

  $.ajax({
    type: "POST",
    url: "/",
    data: JSON.stringify(request),
    dataType:"json",
  })
  .fail(function() {
    $('#debug').html( $('#debug').html() + "<br/>failed");
  })
  .always(function() {
    $('#debug').html( $('#debug').html() + "<br/>complete");
  })
 .done(function(result) {
 $('#json').html(JSON.stringify(result));
 $('#result').html(result.call + ":" + 
 result.lat + ", " + result.lng);
 });
}
```

## 它是如何工作的…

jQuery 在请求成功完成时调用`done`事件处理程序，并将结果数据作为参数传递。因为我们已经在对`$.ajax`的初始调用中指定了数据类型为`json`，jQuery 很乐意使用`JSON.parse`来解析返回值，并传递我们感兴趣的 JavaScript 对象，从而省去了我们自己的`parse`调用。

我们的`done`事件处理程序做两件事：它将对象的字符串化 JSON（由浏览器串行化，而不是服务器返回）放入 ID 为`json`的`div`字段中，并将结果`div`更新为从结果数据中获取的电台呼号、纬度和经度。这样我们就得到了一个看起来像这样的网页：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-json-cb/img/B04206_04_01.jpg)

## 还有更多…

如果你愿意，可以通过将事件处理程序作为初始请求的`success`字段传递给`$.ajax`来注册事件处理程序。像`fail`和`always`一样，我更喜欢使用链式调用来显式设置它，因为我认为这样更易读。

# 向你的网页添加 AngularJS 依赖项

就像其他的 JavaScript 框架一样，您需要在您的 HTML 中包含 AngularJS。正如您在本节中将要看到的，为了设置还需要做一些其他不同的事情。首先，确保您创建了一个新的 HTML 文件，比如`json-example-angular.html`。

## 如何做到…

以下是我们的应用程序的完整 HTML：

```js
<!doctype HTML>
<html>
  <head>
  </head>

<body ng-app="aprsapp">
  <div ng-controller="AprsController">
    <button ng-click="doAjax()">Send AJAX Request</button>
    <div>{{debug}}</div>
    <div>{{json}}</div>
	 <br/>
        <div>{{message}}<div>
  </div>

  <p>Powered by <a href="http://www.aprs.fi">aprs.fi</a></p>
<script type="text/javascript"
src="img/angular.min.js"></script>
<script src="img/json-example-angularjs.js"></script>
</body>
</html>
```

让我们更仔细地看看这个 HTML，看看有什么不同。

## 它是如何工作的…

首先，请注意`body`标签具有`ng-app`属性，其设置为`aprsapp`。AngularJS 应用程序被赋予了定义好的名称，你在实现应用程序逻辑的 JavaScript 中引用这些名称。

接下来，请注意包含我们 UI 的`div`区域具有`ng-controller`属性，它标识了负责处理该 UI 部分事件的具体控制器模块。我们马上就会看到它是如何与 JavaScript 相链接的。在那个`div`中有其他`div`区域，其内容包含在双括号中，定义了一个文档模板，Angular.js 为您填充。这是 AngularJS 中的一个变量；在控制器加载时，HTML 中的这些变量将被控制器设置的内容所替换。每个都是一个*模型*，包含要显示的数据。

最后，我们需要包含 AngularJS 模块本身以及我们的 JavaScript。在使用 AngularJS 时，习惯上将您的应用程序的 JavaScript 保存在单独的文件中，因为这有助于您强制执行良好的应用程序外观（包含在您的 HTML 和 CSS 中）和实现（包含在您的 JavaScript 中）之间的分离。

现在，让我们看看我们页面的 JavaScript 骨架，我们将其放在`json-examnple-angular.js`文件中：

```js
var app = angular.module("aprsapp", []);

app.controller("AprsController", , ["$scope",
  function($scope) {
  $scope.json = "";
  $scope.message = "Loaded..."; 
}]);
```

这段代码定义了一个单独的 AngularJS 应用程序，名为`aprsapp`。请注意，这个名字必须与您 body 标签中`ng-app`属性的名称相匹配。代码然后为应用程序注册了一个控制器，名为`AprsController`。控制器是一个函数，至少有一个参数，即控制器的范围，您在那里定义您的数据模型和其他变量。在我们的控制器范围内，我们设置了两个模型的初始值：`json`和`message`。

## 参见 also

要开始使用 AngularJS，请查看其网站[`angularjs.org`](https://angularjs.org)，或者由*Rodrigo Branas*编写、*Packt Publishing*出版的*AngularJS Essentials*一书。

# 使用 AngularJS 请求 JSON 内容

Angular 定义了一个核心对象`$http`，您使用它对远程服务器进行 HTTP 请求。当你初始化它的时候，它会传递给你的控制器。

## 如何做到…

让我们扩展我们的控制器，以添加对`$http`对象的引用并使用它来发送请求：

```js
var app = angular.module("aprsapp", []);

app.controller("AprsController", ["$scope", "$http",
function($scope, $http) {
  $scope.json = "";
  $scope.message = "Loaded..."; 
  $scope.doAjax = function()
  {
    $scope.debug = "Fetching...";    
    $scope.json= "";
    $scope.message = "";

    var promise = $http({
      url: "/", 
      method: "POST",
    });
  };
}]);
```

在这里，我们在我们的范围内定义了一个函数`doAjax`，它将执行异步 HTTP 请求。它更新了我们的模型，使`debug`模型包含一个状态消息，而`json`和`message`模型为空字符串。让我们更详细地看看`$http`对象。

## 它是如何工作的…

查看控制器定义函数，你可以看到我们不仅传递了控制器的范围，还传递了`$http`对象。它定义了一个函数，接受一个参数，一个定义 HTTP 请求参数的 JavaScript 对象。在我们的示例中，我们通过将`method`字段设置为`POST`并将`url`字段设置为`/`，请求向服务器的根发送一个`POST`请求。

`$http`方法的参数可以包括这些属性：

+   `method`属性，指示要使用的 HTTP 方法。

+   `url`属性，指示方法应该发送到的 URL。

+   `params`属性是一个字符串或对象的映射，用于发送到服务器；如果值不是字符串，它将被编码为 JSON（关于这一点将在下一个食谱中详细介绍）；`params`属性被附加到 URL 上。

+   `data`属性，是要发送到远程服务器的数据。

+   `headers`属性，是一个要发送到远程服务器的标题和标题值的映射。

+   `timeout`属性，指示等待响应的时间长度。

`$http()`方法返回一个*承诺*，当你成功发送数据时，你会在这个对象上调用其他方法来注册事件处理程序来检测错误和处理数据。（我们将在食谱《使用 AngularJS 获取请求进度》和《使用 AngularJS 解析返回的 JSON》中进一步讨论承诺。）

## 还有更多...

`$http`对象还定义了单独的方法`get`、`post`、`put`、`delete`和`patch`，用于发出适当的 HTTP 请求。如果你愿意，你可以使用它们代替`$http()`方法，省略`method`属性。像`$http()`一样，它们都返回一个承诺。

## 参见

有关`$http()`方法和 AngularJS 对 AJAX 的支持的文档，请参阅[`docs.angularjs.org/api/ng/service/$http`](https://docs.angularjs.org/api/ng/service/$http)。

# 使用 AngularJS 向你的 Web 服务器发送 JSON

使用 AngularJS 发送 JSON 就像在`$http()`方法调用中提供`data`属性一样简单。AngularJS 甚至会为你编码对象为 JSON。

## 如何做到这一点...

像以前一样，我们将发起一个 AJAX 请求。这次，我们包含了一个`data`属性：

```js
var app = angular.module("aprsapp", []);

app.controller("AprsController", ["$scope", "$http",
function($scope, $http) {
  $scope.json = "";
  $scope.message = "Loaded..."; 
  $scope.doAjax = function()
  {
    $scope.debug = "Fetching...";    
    $scope.json= "";
    $scope.message = "";
 var request = { 
 call: "kf6gpe-7"
 };
    var promise = $http({
      url: "/", 
      method: "POST",
 data: request
    });
  };
}]);
```

## 它是如何工作的…

我们像过去例子中一样定义 JavaScript 对象请求，单个调用属性包含我们感兴趣的站的呼号。通过将这个值作为数据属性传递给`$http()`的参数，AngularJS 将对象转换为 JSON 并发送给服务器。

## 还有更多...

如果你使用`$http.post()`这样的方法，将数据作为第二个参数传递，像这样：

```js
$http.post("/", request);
```

你还可以通过第三个参数传递一个可选的配置参数。这样的配置对象将包含我在前一个食谱中描述的请求对象的属性。

# 使用 AngularJS 获取请求进度

`$http()`方法返回一个承诺，这是您确定请求状态的方式。它定义了方法，您可以将 JavaScript 函数传递给这些方法，当底层网络事务状态改变时，这些函数作为事件处理程序运行。

## 如何做到…

返回的承诺定义了`success`和`error`方法，这些方法需要事件处理程序。要使用它们，我们编写以下代码：

```js
var app = angular.module("aprsapp", []);

app.controller("AprsController", ["$scope", "$http",
function($scope, $http) {
  $scope.json = "";
  $scope.message = "Loaded..."; 
  $scope.doAjax = function()
  {
    $scope.debug = "Fetching...";    
    $scope.json= "";
    $scope.message = "";
    var request = { 
      call: "kf6gpe-7"
    };
    var promise = $http({
      url:"/", 
      method: "POST",
      data: request
    });
    promise.success(function(result, status, headers, config) {
      // handle success here
    });
    promise.error(function(data, status, headers, config) {
      alert("AJAX failed!");
    });
}]);
```

## 它是如何工作的…

在成功时，AngularJS 使用`success`方法调用您注册的承诺函数，并传递结果数据、HTTP 状态、HTTP 头和与请求关联的配置。在这里，您将处理网络事务的结果，我们将在下一个菜谱中更详细地讨论。在任何类型的失败时，AngularJS 都会调用您用`error`方法注册的回调，并传递相同的数据显示。

请注意`success`和`error`方法又返回了承诺，所以如果您愿意，可以链接这些请求。

# 使用 AngularJS 解析返回的 JSON

使用 AngularJS 处理返回的数据很容易，因为它为您解析返回的 JSON，并将结果对象传递给您注册的事件处理程序。

## 如何做到…

以下是我们的 AngularJS 应用程序完整的客户端代码。`success`承诺的回调只是用我们从结果中获取的对象字段更新模型：

```js
var app = angular.module("aprsapp", []);

app.controller("AprsController", function($scope, $http) {
  $scope.json = "";
  $scope.message = "Loaded..."; 
  $scope.doAjax = function()
  {
    $scope.debug = "Fetching...";    
    $scope.json= "";
    $scope.message = "";
    var request = { 
      call: "kf6gpe-7"
    };

    var promise = $http({
      url:"/", 
      method: "POST",
      data: request
    });
    promise.success(function(result, status, headers, config) {
      $scope.debug = "Loaded.";    
      $scope.json = result;
      $scope.message = result.call + ":" + result.lat + ", " + 
        result.lng;
    });
    promise.error(function(data, status, headers) {
      alert("AJAX failed!");
    });
}]);
```

## 它是如何工作的…

由于 AngularJS 处理 JSON 解析，因此在填充消息模型中的文本时，我们可以直接反引用的返回 JSON 中的值。注意，我们还可以将 JSON 模型分配给结果对象，当显示此对象时，它将显示结果对象本身的 JSON。

如果您在 Chrome 中加载 HTML 和 JavaScript 并按下调用`doAjax`的按钮，您应该会看到类似这样的内容：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-json-cb/img/B04206_04_02.jpg)
