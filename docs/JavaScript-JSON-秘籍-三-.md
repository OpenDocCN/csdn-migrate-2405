# JavaScript JSON 秘籍（三）

> 原文：[`zh.annas-archive.org/md5/7BFA16E9EEE620D98CFF9D2379355647`](https://zh.annas-archive.org/md5/7BFA16E9EEE620D98CFF9D2379355647)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：使用 JSONPath 和 LINQ 查询 JSON

有时，您可能只想从一些 JSON 格式的数据中提取一两个字段，而不是将 JSON 块解析为一个类并处理其所有字段。使用 JSONPath 或 LINQ（使用 Json.NET），您可以做到这一点。在这里，您会找到以下食谱：

+   使用 JSONPath 点表示法查询 JSON 文档

+   使用 JSONPath 方括号表示法查询 JSON 文档

+   使用 JSONPath 脚本构建更复杂的查询

+   在您的 Web 应用程序中使用 JSONPath

+   在您的 Node.js 应用程序中使用 JSONPath

+   在您的 PHP 应用程序中使用 JSONPath

+   在您的 Python 应用程序中使用 JSONPath

+   在您的 Java 应用程序中使用 JSONPath

+   使用 SelectToken 在您的 C#应用程序中查询 JSONPath 表达式

+   使用 Json.NET 和 LINQ 在您的 C#应用程序中查询 JSON

# 引言

XML 最大的优点之一是 XPath，它是一种查询语言，用于查询 XML 文档的子部分。Stefan Goessner 提出了 JSONPath 查询语言，这是一种与 XPath 类似具有相似特性的语言，可以让您提取 JSON 文档中应用程序需要的部分。

请注意，仍然有人在解析东西：没有免费的午餐，JSONPath 实现需要至少具有相似内存和运行时特性的 JSON 解析。然而，如果您的平台上有 JSONPath 库，那么 JSONPath 可以使代码更易读，因为您不需要模拟整个类仅仅是为了提取一个或两个字段，或者是在一系列 JSON 值中对某个字段进行汇总。

如果您习惯于为 Microsoft 平台开发，您肯定知道 Microsoft 的**语言独立查询**（**LINQ**）语言，它允许您对可枚举数据结构编写声明式查询。尽管.NET 实现的 JSON 解析只提供基本的 LINQ 支持，但不屈不挠的 Json.NET 库的实现支持 LINQ 以及 JSONPath，让您可以使用流畅的或语句语法对 JSON 文档进行声明式查询。

要使用 JSONPath 或 LINQ，您需要一个支持它们的库。在我写这篇文章的时候，有支持 JavaScript 的 JSONPath 库，支持 Node.js 的 JavaScript，以及支持 PHP、C#、Python 和 Java 的库。当然，如果您想要使用 LINQ，您需要在.NET 平台上运行您的应用程序，使用 C#、F#或 Visual Basic 等语言。因此，接下来的大多数食谱都有两个步骤：第一步是下载一个支持 JSONPath 的库，然后是实际在应用程序中调用 JSONPath 代码的步骤。

大多数 JSONPath 示例都使用了 Goessner 的示例文档，该文档包含了假设书店的记录，在本章中，我们将同样使用这个示例。我们的 JSON 文档看起来是这样的：

```js
{ "store": {
    "book": [ 
        { "category": "reference",
        "author": "Nigel Rees",
        "title": "Sayings of the Century",
        "price": 8.95
      },
        { "category": "fiction",
        "author": "Evelyn Waugh",
        "title": "Sword of Honour",
        "price": 12.99
      },
        { "category": "fiction",
        "author": "Herman Melville",
        "title": "Moby Dick",
        "isbn": "0-553-21311-3",
        "price": 8.99
      },
        { "category": "fiction",
        "author": "J. R. R. Tolkien",
        "title": "The Lord of the Rings",
        "isbn": "0-395-19395-8",
        "price": 22.99
      }
    ],
    "bicycle": {
      "color": "red",
      "price": 19.95
    }
  }
}
```

正如您所看到的，我们有一个商店对象，它有一个书籍集合和一个单一的自行车。每本书都有一个类别、一个作者、一个标题和一个价格。像这样表示 JSON 文档作为一个类将很困难，因为书籍记录的结构与自行车记录的结构非常不同；您可以使用我们在第一章和第二章中讨论的不安全查询方法来解析这样的文档并遍历它的文档，尽管对于大多数应用程序来说，JSONPath 是一个更好的选择，您很快就会看到。让我们从如何查询文档中的单个字段开始。

# 使用 JSONPath 点表示法查询 JSON 文档

JSONPath 使用点表示法或方括号表示法编写表达式，以表示 JSON 文档中的字段遍历。点分隔字段名称，就像它们是对象属性一样。

## 如何做到这一点…

以下是一些点表示法的示例：

```js
$.store.book[0].title
$.store.book[*].title
$.store..price
$..book[3]
```

## 它是如何工作的…

在第一行中，我们引用了商店中的第一个书籍（从零开始计数），返回标题字段。第二行类似，只不过它返回了所有书籍的标题集合。第三个例子返回了商店集合中所有记录的价格字段集合。第四个例子找到了商店中的第四本书项。

该表示法相当直观，除了 `..` 和 `*` 的使用。这些都是 JSONPath 用来表示文档中切片的一些特殊字符的例子。

## 还有更多…

JSONPath 定义了以下特殊字符，您在编写查询时可以使用：

+   `$` 符号指的是根对象或元素。

+   `@` 符号指的是当前对象或元素。

+   `.` 操作符是点子操作符，您使用它来指定当前元素的子元素。

+   `[]` 操作符是下标操作符，您使用它来指定当前元素的子元素（按名称或索引）。

+   `*` 操作符是一个通配符，返回所有对象或元素，而不管它们的名称是什么。

+   `,` 操作符是并集操作符，它返回所指示的子项或索引的并集。

+   `:` 操作符是数组切片操作符，因此您可以使用语法 `[start:end:step]` 来返回集合的一个子集。

+   `()` 操作符允许您在底层实现的脚本语言中传递一个脚本表达式。然而，并非所有的 JSONPath 实现都支持它。

## 也见

JSONPath 的权威文档可以在 Goessner 的网站上找到，网址为 [`goessner.net/articles/JsonPath/`](http://goessner.net/articles/JsonPath/)。当然，您应该查看您选择的 JSONPath 的文档，以了解特定的实现细节。

网络上的一个方便的功能是一个 JSONPath 表达式测试器；[`jsonpath.curiousconcept.com/`](http://jsonpath.curiousconcept.com/)就是这样一个网站。通过在测试器中粘贴 JSON 和 JSONPath 表达式，你可以评估 JSONPath 并查看结果是什么。这是你在最初开始时动态调试你的 JSONPath 表达式的一个非常简单的方法。这是一个例子：

![参见](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-json-cb/img/B04206_09_01.jpg)

# 使用 JSONPath 方括号表示法查询 JSON 文档

JSONPath 提供了一种替代表示法，即方括号表示法，它与点表示法一样用于查询字段。这个语法让你想起了如何访问关联数组中的字段，你只需要将字段名作为选择器传递给`operator[]`，以获取命名字段中的值。

## 如何做到…

在方括号表示法中，我们将之前的例子的公式写作如下：

```js
$['store']['book'][0].['title']
$['store']['book'][*].['title']
$['store']..['price']
$..['book'][3]
```

## 它是如何工作的…

如前所见，第一个例子提取了对象中名为 store 的字段中的第一个书籍的标题。第二个例子提取了商店中所有书籍的标题。第三个例子返回了商店中每个项目的所有价格字段的一个集合，第四个例子返回了商店中的第四本书。

# 使用 JSONPath 脚本构建更复杂的查询

有时候，你真正想做的事情是查询满足某些条件的所有项目，比如那些超过特定阈值的项目。JSONPath 提供了`?()`谓词，它可以让你执行 JSONPath 中单个字段的简单比较脚本。

## 如何做到…

这是一个查询所有价格低于`10`货币单位的书籍的例子：

```js
$.store.book[?(@.price < 10)].title
```

## 它是如何工作的…

查询从指定商店中的所有书籍项目开始；`?()`谓词然后使用`@`选择器获取当前项目的值，然后选择价格低于`10`的项目。最后提取结果项目的标题字段。这个查询产生了以下结果：

```js
[ 
    "Sayings of the Century",
    "Moby Dick"
]
```

这样的查询并不是所有 JSONPath 实现都能工作的。在[`jsonpath.curiousconcept.com/`](http://jsonpath.curiousconcept.com/)检查 JSONPath 表达式测试器，我发现它使用 flow communications JSONPath 0.1.1 工作，但 Goessner 在版本 0.8.3 中的 JSONPath 实现不能工作。

任何返回布尔值的表达式都可以用在`?()`谓词中。这是一个查询我们集合中所有小说类别的书籍的另一个例子：

```js
$.store.book[?(@.category == "fiction")].title
```

开始的部分是一样的，那就是选择所有书籍；不是通过价格筛选并返回价格低于`10`的书籍，而是返回集合中某个特定书籍集合中的特定项目类别字段等于小说的所有项目。

# 在您的网络应用程序中使用 JSONPath

在您的网络应用程序中使用 JSONPath 与 JavaScript 结合是非常简单的。你只需要在你的应用程序中包含`jsonpath.js`实现，然后使用它的`jsonPath`函数。

## 准备

在开始之前，你需要从[`code.google.com/p/jsonpath/`](https://code.google.com/p/jsonpath/)下载 JavaScript `jsonpath`库，并使用 script 标签将其包含在 HTML 页面使用的脚本中，像这样：

```js
<html>
<head>
<title>…</title>
<script type="text/javascript" src="img/jsonpath.js"></script>
</head>
```

`jsonPath`函数接受一个 JSON 对象（不是作为字符串，而是作为 JavaScript 对象）并对内容应用路径操作，返回匹配的值或规范化的路径。让我们看一个例子。

## 如何做到…

以下是一个示例，它从我在引言中展示的 JSON 对象中返回一个标题列表：

```js
var o = { /* object from the introduction */ };
var result = jsonPath(o, "$..title");
```

请注意，如果你有对象作为字符串，你将需要首先使用`JSON.parse`解析它：

```js
var json = "…";
var o = JSON.parse(json);
var result = jsonPath(o, "$..title");
```

## 如何工作…

前面的代码使用`jsonPath`函数从当前传递的对象中提取所有标题。`jsonPath`函数接受一个 JavaScript 对象、路径和一个可选的结果类型，指示返回值应该是值还是值的路径。当然，传入的对象可以是结构化对象或数组。

## 也见

Goessner 关于 JSONPath 原始实现的原始文档在[`goessner.net/articles/JsonPath/`](http://goessner.net/articles/JsonPath/)。

# 在你的 Node.js 应用程序中使用 JSONPath

有一个 npm 包可用，其中包含 JavaScript JSONPath 实现的实现，所以如果你想在 Node.js 中使用 JSONPath，你只需要安装 JSONPath 模块并直接调用它。

## 准备好了

要安装`JSONPath`模块，运行以下命令将模块包含在你的当前应用程序中：

```js
npm install JSONPath

```

或者，你可以运行以下命令将其包括在你系统上的所有项目中：

```js
npm install –g JSONPath

```

接下来，你需要在你的源代码中要求模块，像这样：

```js
var jsonPath = require('JSONPath');
```

这将`JSONPath`模块加载到你的环境中，并将引用存储在`jsonPath`变量中。

## 如何做到…

Node.js 的 JSONPath 模块定义了一个单一的方法`eval`，该方法接受一个 JavaScript 对象和一个要评估的路径。例如，为了获得我们示例文档中的标题列表，我们需要执行以下代码：

```js
var jsonPath = require('JSONPath');

var o = { /* object from the introduction */ };
var result = jsonPath.eval(o, "$..title");
```

如果你打算将路径应用于以字符串形式的 JSON，请确保先解析它：

```js
var jsonPath = require('JSONPath');

var json = "…";
var o = JSON.parse(json);
var result = jsonPath.eval(o, "$..title");
```

## 如何工作…

`JSONPath`模块的`eval`方法接受一个 JavaScript 对象（不是包含 JSON 的字符串）并应用你传递的路径以返回对象中的对应值。

## 也见

关于 Node.js 的 JSONPath 模块的文档，请参阅[`www.npmjs.com/package/JSONPath`](https://www.npmjs.com/package/JSONPath)。

# 在你的 PHP 应用程序中使用 JSONPath

在你的 PHP 应用程序中使用 JSONPath 需要你包含位于[`code.google.com/p/jsonpath/`](https://code.google.com/p/jsonpath/)的 JSONPath PHP 实现，并在应用你想要用`jsonPath`函数从其中提取数据的 JSONPath 路径之前，将 JSON 字符串解析为 PHP 混合对象。

## 准备好了

你需要从[code.google.com](http://code.google.com)下载`jsonpath.php`，位于[`code.google.com/p/jsonpath/`](https://code.google.com/p/jsonpath/)，并通过`require_once`指令将其包含在你的应用程序中。你还需要确保你的 PHP 实现包括了`json_decode`。

## 如何做到…

这是一个简单的例子：

```js
<html>
<body>
<pre>
<?php
  require_once('jsonpath.php');
  $json = '…'; // from the introduction to this chapter
  $object = json_decode($json);
  $titles = jsonPath($object, "$..title");
  print($titles);
?>
</pre>
</body>
</html>
```

## 它是如何工作的…

上述代码首先引入了 PHP JSONPath 实现，该实现定义了`jsonPath`函数。然后使用`json_decode`解码 JSON 字符串，再提取`json_decode`返回的混合 PHP 对象中的标题。

与 JavaScript 版本的`jsonPath`类似，PHP 版本接受三个参数：要执行提取的对象、要提取的路径以及一个可选的第三个参数，用于指定是返回数据还是返回数据结构的路径。

## 也见

有关 PHP 实现 JSONPath 的更多信息，请参阅 Stefan Goessner 的网站[`goessner.net/articles/JsonPath/`](http://goessner.net/articles/JsonPath/)。

# 在你的 Python 应用程序中使用 JSONPath

也为 Python 提供了几个 JSONPath 实现。最好的是`jsonpath-rw`库，它提供了语言扩展，使路径成为一等语言对象。

## 准备中

你需要使用 pip 安装`jsonpath-rw`库：

```js
pip install jsonpath-rw

```

当然，你还需要在使用它们时包含库所需的部分：

```js
fromjsonpath_rw import jsonpath, parse

```

## 如何做到…

这是一个简单的例子，使用存储在变量`object`中的介绍中的商店内容：

```js
>>> object = { … }

>>>path = parse('$..title') 

>>> [match.value for match in path.find(object)]
['Sayings of the Century','Sword of Honour', 'Moby Dick', 'The Lord of the Rings']
```

## 它是如何工作的…

使用这个库处理路径表达式有点像匹配正则表达式；你解析出 JSONPath 表达式，然后使用路径的`find`方法将其应用于你想要切片的 Python 对象。这段代码定义了对象，然后创建了一个路径表达式将其存储在路径中，解析获取所有标题的 JSONPath。最后，在传递给路径的你要切片的对象中创建了一个由路径找到的值的数组。

## 也见

Python JSONPath 库的文档位于[`pypi.python.org/pypi/jsonpath-rw`](https://pypi.python.org/pypi/jsonpath-rw)。

# 在你的 Java 应用程序中使用 JSONPath

还有一个为 Java 编写的 JSONPath 实现，由**Jayway**编写。它可以从 GitHub 获取，或者如果你的项目使用 Maven 构建系统，你还可以通过**中央 Maven 仓库**获取。它与原始 JSONPath API 相匹配，为 JSON 对象中的字段返回 Java 对象和集合。

## 准备中

你需要从 GitHub 上下载代码[`github.com/jayway/JsonPath`](https://github.com/jayway/JsonPath)，或者，如果你使用 Maven 作为你的构建系统，请包含以下依赖项：

```js
<dependency>
<groupId>com.jayway.jsonpath</groupId>
<artifactId>json-path</artifactId>
<version>2.0.0</version>
</dependency>
```

## 如何做到…

Java 实现解析你的 JSON，并导出一个`JsonPath`类，该类有一个`read`方法，用于读取 JSON，解析它，然后提取你传递的路径的内容：

```js
String json = "...";

List<String>titles = JsonPath.read(json,
"$.store.book[*].title");
```

## 它是如何工作的…

读取方法解析传递给它的 JSON，然后将传递给它的路径应用于提取 JSON 中的值。如果你需要从同一文档中提取多个路径，最好只解析文档一次，然后对解析后的文档调用读取方法，如下所示：

```js
String json = "...";

Object document = 
Configuration.defaultCConfiguration().jsonProvider().parse(json));

List<String>titles = JsonPath.read(document,
  "$.store.book[*].title");
List<String>authors = JsonPath.read(document,
  "$.store.book[*].author");
```

## 还有更多…

Java JSONPath 库还提供了一种流畅的语法，其中读取和其他方法的实现返回一个上下文，你可以继续调用其他 JSONPath 库方法。例如，为了获取价格超过`10`的书籍列表，我还可以执行以下代码：

```js
List<Map<String, Object>>expensiveBooks = JsonPath
                            .using(configuration)
                            .parse(json)
                            .read("$.store.book[?(@.price > 10)]", 
                              List.class);
```

这配置了`JsonPath`，使用了配置，解析了传递给它的 JSON，然后使用路径选择器调用`read`，选择所有价格超过值`10`的书籍对象。

Java 中的 JsonPath 库试图将结果对象转换为你期望的基本类：列表、字符串等等。一些路径操作—`..`、`?()`和`[number:number:number]`—总是返回一个列表，即使结果值是一个单一的对象。

## 参见

关于 Java JSONPath 实现的文档，请参阅[`github.com/jayway/JsonPath`](https://github.com/jayway/JsonPath)。

# 使用 JSONPath 和 SelectToken 在 C#应用程序中查询 JSONPath 表达式

如果你使用的是.NET 环境中的 Newonsoft Json.NET，你可以使用其`SelectToken`实现对 JSON 文档进行 JSONPath 查询。首先，你需要将 JSON 解析为`JObject`，然后进行查询。

## 准备

你需要在你的应用程序中包含 Json.NET 库。为此，请按照*如何使用 Json.NET 反序列化对象*食谱中的*准备*部分中的第七章*使用类型安全的 JSON*中的步骤操作。

## 如何进行…

以下是提取所有书籍标题的步骤以及得到的第一结果：

```js
using System;
using System.Collections.Generic;
using System.Linq;
   using Newtonsoft.Json.Linq;

// …

static void Main(string[] args)
{
  var obj = JObject.Parse(json);

  var titles = obj.SelectTokens("$.store.book[*].title");

  Console.WriteLine(titles.First());
} 
```

## 它是如何工作的…

`JObject`的`SelectTokens`方法接受一个 JSONPath 表达式，并将其应用于对象。在这里，我们提取匹配顶级`$.store.book`路径的每个项目的`JObject`实例列表，然后调用`Values`方法获取每个返回的`JObject`实例中的每个标题字段的强制字符串值。当然，原始 JSON 需要解析，我们使用`JObject.parse`进行解析。

请注意`SelectTokens`返回一个可枚举的集合，你可以使用 LINQ 表达式进一步处理，就像我们在这里通过调用`First`一样。严格来说，`SelectTokens`返回`IEnumberable<JToken>`，其中每个`JToken`都是单个 JSON 集合。JObject 还提供`SelectToken`方法，返回一个实例。

然而，要小心不要混淆`SelectToken`和`SelectTokens`。前者*只能*返回一个`JToken`，而后者在你想要返回 JSONPath 查询中的项目集合时是必需的。

也支持过滤。例如，为了获得包含关于书籍*Moby Dick*的数据的`JObject`，我可能会写：

```js
var book = obj.SelectToken(
"$.store.book[?(@.title == 'Moby Dick')]");
```

此选择从`store`字段中的`book`集合中选择标题匹配"`Moby Dick`"的文档。

## 请也参阅

参阅 Jason Newton-King 网站上关于`SelectToken`和`SelectTokens`的文档和更多示例，网址为[`james.newtonking.com/archive/2014/02/01/json-net-6-0-release-1-%E2%80%93-jsonpath-and-f-support`](http://james.newtonking.com/archive/2014/02/01/json-net-6-0-release-1-%E2%80%93-jsonpath-and-f-support)，或者 Json.NET 文档[`www.newtonsoft.com/json/help/html/QueryJsonSelectToken.htm`](http://www.newtonsoft.com/json/help/html/QueryJsonSelectToken.htm)。

# 使用 Json.NET 和 LINQ 查询 C#应用程序中的 JSON

如果你正在为.NET 开发，你可能想完全跳过 JSONPath，并使用 Json.NET 的支持基于字段名称进行订阅，并支持 LINQ。Json.NET 内置支持 LINQ，让你可以针对你的 JSON 使用流畅或语句语法编写任何查询。

## 准备

与之前的食谱一样，你的.NET 项目需要使用 Json.NET。要将在项目中包含 Json.NET，请按照我在第七章*以类型安全的方式使用 JSON*中的*入门*部分所示的步骤操作，该章节为*如何使用 Json.NET 反序列化对象*食谱。

## 如何做到…

你将解析 JSON 以`JObject`，然后你可以针对结果`JObject`评估 LINQ 表达式，如下所示：

```js
using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json.Linq;

static void Main(string[] args)
{
  var obj = JObject.Parse(json);
  var titles = from book in obj["store"]["book"] 
      select (string)book["title"];

  Console.WriteLine(titles.First());
}
```

当然，因为是 LINQ，也支持流畅语法：

```js
using System;
using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json.Linq;

static void Main(string[] args)
{
  var sum = obj["store"]["book"]
             .Select(x => x["price"])
             .Values<double>().Sum();

  Console.WriteLine(sum);
}
```

## 它是如何工作的…

第一个示例选择所有的`title`对象，每个`book`字段中的一个，返回结果之前将每个对象转换为字符串。第二个示例对所有`book`的`price`字段进行选择，将结果值转换为双精度浮点数，并在列表上调用`Sum`方法，以获得所有书籍的总价格。

要留心的是，Json.NET LINQ 查询中的子字段的通常返回类型是`JObject`，所以你在使用流畅语法编写表达式时，必须使用`JObject`模板的`Value`和`Values`方法来获取这些对象的价值。你第一次尝试计算总和可能如下所示：

```js
var s = obj["store"]["book"].
  Select(x =>x["price"]).Sum();
```

然而，这不会起作用，因为选择返回的值是一个`JObject`对象的列表，不能直接相加。

### 提示

当编写 LINQ 表达式时，LINQPad（[`www.linqpad.net`](http://www.linqpad.net)）非常有帮助。如果你做大量的 LINQ 和 JSON，投资开发人员或高级版本可能是明智的，因为这些版本支持与 NuGet 的集成，让你可以将 Json.NET 直接包含在你的测试查询中。

## 请也参阅

关于 LINQ 和 Json.NET 的更多信息，请参阅位于[`www.newtonsoft.com/json/help/html/LINQtoJSON.htm`](http://www.newtonsoft.com/json/help/html/LINQtoJSON.htm)的 Json.NET 文档。


# 第十章：JSON 在移动平台上的应用

当今的移动应用程序非常流行——像平板电脑和智能手机这样的设备在世界许多地方都超过了 PC 的销量。这些设备由 iOS 和 Android 等平台提供支持，并包括用于创建和解析 JSON 的 API，作为平台的一部分，使得作为应用程序开发者的你的生活变得稍微容易一些。在本章中，有你需要的食谱：

+   在 Android 上解析 JSON

+   在 Android 上生成 JSON

+   使用 Objective-C 在 iOS 上解析 JSON

+   使用 Objective-C 在 iOS 上生成 JSON

+   使用 Swift 在 iOS 上解析 JSON

+   使用 Swift 在 iOS 上生成 JSON

+   使用 Qt 解析 JSON

+   使用 Qt 生成 JSON

# 简介

正如我们在前一章中讨论的那样，JSON 是一种出色的媒介，用于与 Web 服务和服务器通信，无论客户端是 Web 应用程序还是传统应用程序。这对于移动应用程序尤其正确，许多移动应用程序运行在低带宽广域网上，在这种情况下，JSON 与 XML 相比的简洁性使得整体数据负载更小，从而确保远程查询的响应时间更快。

当今领先的移动平台是 Android 和 iOS。Android 运行 Linux 的一个变体，支持用 Java 进行软件开发，并在`org.json`命名空间中包括一个 JSON 处理器。iOS 从 Mach 和 BSD 中衍生而来，支持使用 Objective-C、Swift、C 和 C++进行软件开发，尽管对于大多数应用程序开发，你使用 Objective-C 或 Swift，每种语言都包含对`NSJSONSerialization`类的绑定，该类实现 JSON 解析和 JSON 序列化。

移动开发者的另一个选择是使用跨平台工具包，如 Qt，进行应用程序开发。Qt 在多种平台上运行，包括 Android、iOS 和 BlackBerry。Qt 定义了`QJsonDocument`和`QJsonObject`类，你可以使用它们来实现映射和 JSON 之间的相互转换。Qt 是一个存在已久的开源框架，不仅运行在移动平台上，还运行在 Mac OS X、Windows 和 Linux 上，以及其他许多平台。

我们接下来要讨论的 JSON 与前几章使用的类似，并像这样看起来像一个文档：

```js
{
  'call': 'kf6gpe-7',
  'lat': 37.40150,
  'lng': -122.03683
  'result': 'ok'
}
```

在接下来的讨论中，我假设你已经正确地为目标平台设置了软件开发环境。描述为 Android、iOS 和 Qt 设置软件环境的流程会比这本书允许的空间要大。如果你对为特定的移动平台开发软件感兴趣，你可能想要查阅 Android 或 iOS 的开发者资源：

+   你可以访问苹果公司为 iOS 开发者提供的开发者网站[`developer.apple.com`](https://developer.apple.com)。

+   你可以访问谷歌公司为 Android 开发者提供的开发者网站[`developer.android.com/index.html`](http://developer.android.com/index.html)。

+   你可以访问[`www.qt.io`](http://www.qt.io)获取关于 Qt 的信息。

# 在 Android 上解析 JSON

Android 提供了 `JSONObject` 类，该类让你通过一个与地图概念上相似的接口来表示 JSON 文档的键值对，并包括通过访问器方法进行序列化和反序列化，这些方法可以访问 JSON 对象的命名字段。

## 如何做到…

你首先通过用你想要解析的 JSON 初始化 `JSONObject`，然后使用其各种 `get` 方法来获取 JSON 字段的值：

```js
Import org.json.JSONObject;

String json = "…";
JSONObject data = new JSONObject(data);

String call = data.getString("call");
double lat = data.getDouble("lat");
double lng = data.getDouble("lng");
```

## 它是如何工作的…

`JSONObject` 构造函数接收要解析的 JSON，并提供访问器方法来访问 JSON 字段。在这里，我们使用 `getString` 和 `getDouble` 访问器分别访问 JSON 的 `call`、`lat` 和 `lng` 字段。

`JSONObject` 类定义了以下访问器：

+   `get` 方法，返回一个子类 `java.lang.Object`，其中包含命名槽中的值。

+   `getBoolean` 方法，如果槽中包含 `Boolean` 类型数据，则返回一个 `Boolean` 类型数据。

+   `getDouble` 方法，如果槽中包含 `double` 类型数据，则返回一个 `double` 类型数据。

+   `getInt` 方法，如果槽中包含 `int` 类型数据，则返回一个 `int` 类型数据。

+   `getJSONArray` 方法，如果槽中包含数组，则返回一个 `JSONArray` 实例，这是一个处理数组的 JSON 解析类。

+   `getJSONObject` 方法，如果槽中包含另一个映射，则返回一个 `JSONObject` 实例。

+   `getLong` 方法，如果槽中包含 `long` 类型数据，则返回一个 `long` 类型数据。

+   `getString` 方法，如果槽中包含 `String` 类型数据，则返回一个 `String` 类型数据。

该类还定义了 `has` 和 `isNull` 方法。这些方法接收一个槽的名字，如果字段中有值，或者没有该字段名或者值为 `null`，则返回 `true`。

`JSONArray` 与 `JSONObject` 类似，只不过它处理数组而不是映射。它有相同的访问器方法，这些方法采用集合中的整数索引，返回对象、布尔值、字符串、数字等等。

## 还有更多内容…

`JSONObject` 类还定义了 `keys` 方法，该方法返回 JSON 中的键的 `Iterator<String>`。你还可以通过调用 `names` 获得 JSON 中的名称的 `JSONArray`，或者通过调用 `length` 获得 JSON 中的键值对的数量。

## 也见

关于 `JSONObject` 的更多信息，请参阅 Android 文档中的 [`developer.android.com/reference/org/json/JSONObject.html`](http://developer.android.com/reference/org/json/JSONObject.html)。关于 `JSONArray` 的更多信息，请参阅 [`developer.android.com/reference/org/json/JSONArray.html`](http://developer.android.com/reference/org/json/JSONArray.html)。

# 在 Android 上生成 JSON

`JSONObject` 类还支持设置器方法来初始化 JSON 映射中的数据。利用这些方法，你可以将数据分配给一个 JSON 对象，然后通过调用其 `toString` 方法来获取 JSON 表示形式。

## 如何做到…

下面是一个简单示例：

```js
import org.JSON.JSONObject;

JSONObject data = new JSONObject();
data.put("call", "kf6gpe-7");
data.put("lat", 37.40150);
data.put("lng", -122.03683);
String json = data.toString();
```

## 它是如何工作的…

多态的 put 方法可以接受整数、长整数、对象、布尔值或双精度浮点数，将你命名的槽分配给你指定的值。

`JSONObject`类定义了`toString`方法，它接受一个可选的空格数来缩进嵌套结构以进行美观的 JSON 打印。如果你不传递这个缩进，或者传递 0，实现尽可能地将 JSON 编码成最紧凑的形式。

## 还有更多…

还有一个`putOpt`方法，它接受任何`Object`的子类，如果名称和非空值都不为空，则将值放入名称中。

你可以通过传递`JSONArray`或将另一个`JSONObject`作为要设置的值来将槽分配给值数组。`JSONArray`定义了一个类似的 put 方法，它以数组中的整数索引作为第一个参数，而不是槽名。例如，使用前面示例中的数据对象，我可以使用以下代码添加一个在站点的测量电压数组（也许来自无线电的电池）：

```js
import org.JSON.JSONObject;

JSONArray voltages = new JSONArray();
voltages.put(3.1);
voltages.put(3.2);
voltages.put(2.8);
voltages.put(2.6);
data.put("voltages", voltages);
```

你也可以直接传递`java.util.Collection`和`java.util.Map`实例，而不是传递`JSONArray`或`JSONObject`实例。之前的代码也可以写成：

```js
import org.JSON.JSONObject;
import org.JSON.JSONArray;
import java.util.Collection;

Collection<double> voltages = new Collection<double>();
voltages.put(3.1);
voltages.put(3.2);
voltages.put(2.8);
voltages.put(2.6);
data.put("voltages", voltages);
```

这使得在构建更复杂的 JSON 对象时稍微容易一些，因为你不必将每个 Java 集合或映射包装在一个相应的 JSON 对象中。

## 另见

关于`JSONObject`的更多信息，请参阅 Android 文档中的[`developer.android.com/reference/org/json/JSONObject.html`](http://developer.android.com/reference/org/json/JSONObject.html)。关于`JSONArray`的更多信息，请参阅[`developer.android.com/reference/org/json/JSONArray.html`](http://developer.android.com/reference/org/json/JSONArray.html)。

# 在 iOS 上用 Objective-C 解析 JSON

对象 C 的类库定义了`NSJSONSerialization`类，它可以进行 JSON 的序列化和反序列化。它将 JSON 转换为`NSDictionary`对象的值，这些对象的键是 JSON 中的槽名，值是它们的 JSON 值。它在 iOS 5.0 及以后的版本中可用。

## 如何做到…

这是一个简单的例子：

```js
NSError* error;
NSDictionary* data = [ NSJSONSerialization
  JSONObjectWithData: json
  options: kNilOptions
  error: &error ];

NSString* call = [ data ObjectForKey: @"call" ];
```

## 它是如何工作的…

`NSJSONSerialization`类有一个方法`JSONObjectWithData:options:error`，它接受一个`NSString`、解析选项和一个记录错误的地方，并执行 JSON 解析。它可以接受顶层为数组或字典的 JSON，分别返回`NSArray`或`NSDictionary`结果。所有值必须是`NSString`、`NSNumber`、`NSArray`、`NSDictionary`或`NSNull`的实例。如果顶层对象是数组，该方法返回`NSArray`；否则，它返回`NSDictionary`。

## 还有更多…

默认情况下，此方法返回的数据是不可变的。如果你需要可变的数据结构，你可以传递选项`NSJSONReadingMutableContainers`。要解析不是数组或字典的顶层字段，请传递选项`NSJSONReadingAllowFragments`。

## 另见

关于类的 Apple 文档位于 [`developer.apple.com/library/ios/documentation/Foundation/Reference/NSJSONSerialization_Class/index.html`](https://developer.apple.com/library/ios/documentation/Foundation/Reference/NSJSONSerialization_Class/index.html)。

# 使用 Objective-C 在 iOS 上生成 JSON

您还可以使用 `NSJSONSerializer` 类序列化 `NSDictionary` 或 `NSArray`；只需使用 `dataWithJSONObject` 方法。

## 如何进行…

这是一个简单的例子，假设数据是您想要转换为 JSON 的`NSDictionary`：

```js
NSError *error;
NSData* jsonData = [NSJSONSerialization
dataWithJSONObject: data
options: NSJSONWritingPrettyPrinted
error: &error];
```

## 它是如何工作的…

`dataWithJSONObject:options:error` 方法可以接受 `NSArray` 或 `NSDictionary` 并返回一个包含您传递的集合编码 JSON 的 `NSData` 数据块。如果您传递 `kNilOptions`，JSON 将以紧凑的方式编码；要获取格式化的 JSON，请改为传递 `NSJSONWritingPrettyPrinted` 选项。

## 参见

关于 `NSJSONSerialization` 类的 Apple 文档位于 [`developer.apple.com/library/ios/documentation/Foundation/Reference/NSJSONSerialization_Class/index.html`](https://developer.apple.com/library/ios/documentation/Foundation/Reference/NSJSONSerialization_Class/index.html)。

# 使用 Swift 在 iOS 上解析 JSON

相同的 `NSJSONSerialization` 类在 Swift 中可用，这是 Apple 为 iOS 开发推出的新语言。

## 如何进行…

这是一个如何调用 `NSJSONSerialization` 类的 `JSONObjectWithData` 方法的 Swift 示例：

```js
import Foundation
var error: NSError?
Let json: NSData = /* the JSON to parse */
let data = NSJSONSerialization.JSONObjectWithData(json, 
  options: nil, 
  error: &error);
```

## 它是如何工作的…

Swift 中的方法调用看起来像函数调用，参数以可选命名的逗号分隔的形式传递，这与 C++或 Java 中的调用类似。`JSONObjectWithData` 方法的参数与 Objective-C 版本中的方法参数相同。

# 使用 Swift 在 iOS 上生成 JSON

当然，您也可以从 Swift 调用 `NSJSONSerialization.dataWithJSONObject` 方法，该方法返回一个 `NSData` 对象，您可以将其转换为字符串。

## 如何进行…

这是一个简单的例子：

```js
var error: NSError?
var data: NSJSONSerialization.dataWithJSONObject(
  dictionary, 
  options: NSJSONWritingOptions(0),
  error: &error);
var json: NSString(data: data, encoding: NSUTF8StringEncoding); 
```

## 它是如何工作的…

`dataWithJSONObject` 方法的工作方式与其 Objective-C 对应方法相同。一旦我们收到包含字典 JSON 编码版本的 `NSData`，我们使用 `NSString` 构造函数将其转换为 `NSString`。

# 使用 Qt 解析 JSON

Qt 实现的 JSON 解析在其接口上实际上与 Android 版本非常相似。Qt 定义了 `QJsonObject` 和 `QJsonArray` 类，分别可以包含 JSON 映射和 JSON 数组。解析本身是由 `QJsonDocument` 类完成的，该类有一个静态的 `fromJson` 方法，接受 JSON 并执行必要的解析。

## 如何进行…

这是一个简单的例子：

```js
QString json = "{ 'call': 'kf6gpe-7', 'lat': 37.40150, 'lng': -122.03683, 'result': 'ok'}";
QJsonDocument document = QJsonDocument.fromJson(json);
QJsonObject data = document.object;
QString call = data["call"].toString();
```

## 它是如何工作的…

解析是两步操作：首先，代码使用 `QJsonDocument` 解析 JSON，然后使用结果的 `QJsonObject` 访问数据。

`QJsonObject` 类作为 `QJsonValue` 对象的映射，每个对象都可以使用以下方法之一转换为其基本类型：

+   `toArray`: 这个方法转换为 `QJsonArray`。

+   `toBool`：这个方法转换为布尔值

+   `toDouble`：这个方法转换为双精度浮点数

+   `toInt`：这个方法转换为整数

+   `toObject`：这个方法转换为另一个`QJsonObject`，让你嵌套`QJsonObject`的映射

+   `toString`：这个方法转换为`QString`

## 还有更多内容…

你还可以使用 Qt 的`foreach`宏或者`begin`、`constBegin`和`end`迭代方法遍历`QJsonObject`中的键。此外，还有一个`contain`方法，它接受一个槽的名字，如果映射中包含你寻找的槽，则返回 true。

## 参见

参见 Qt 文档中关于 JSON 解析的部分：[`doc.qt.io/qt-5/json.html`](http://doc.qt.io/qt-5/json.html)。

# 使用 Qt 生成 JSON

`QJsonDocument`类还有一个`toJson`方法，该方法将引用的对象转换为 JSON。

## 如何做到…

以下是一个示例，它将 JSON 转换为另一种 JSON，并在转换过程中格式化 JSON：

```js
QString json = "{ 'call': 'kf6gpe-7', 'lat': 37.40150, 'lng': -122.03683, 'result': 'ok'}";
QJsonDocument document = QJsonDocument.fromJson(json);
QJsonObject data = document.object;
QByteArrayprettyPrintedJson = 
document.toJson(QJsonDocumented::Indented);    
```

## 它是如何工作的…

`QJsonDocument`类有一个`toJson`方法，该方法将引用的文档或数组转换为 JSON。你可以通过传递`QJsonDocument::Indented`来请求格式化后的 JSON 版本，或者通过传递`QJsonDocument::Compact`来请求紧凑的 JSON 版本。

## 参见

关于`QJsonDocument`的更多信息，请参阅 Qt 文档：[`doc.qt.io/qt-5/qjsondocument.html`](http://doc.qt.io/qt-5/qjsondocument.html)。
