# 使用 Danfo.js 构建数据驱动应用（二）

> 原文：[`zh.annas-archive.org/md5/074CFA285BE35C0386726A8DBACE1A4F`](https://zh.annas-archive.org/md5/074CFA285BE35C0386726A8DBACE1A4F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：开始使用 Danfo.js

与其他编程语言相比，**Python**数据科学和机器学习生态系统非常成熟，但在数据呈现和客户端方面，**JavaScript**占据主导地位。从其强大的数据呈现工具到其在浏览器中的易用性，JavaScript 总是被推荐的。

在本章中，我们将向您介绍 Danfo.js 库，为您提供 JavaScript 中高效的数据分析和操作工具。我们将介绍 Danfo.js 的核心数据结构——DataFrames 和 Series。我们将向您展示如何将不同类型的文件（如 JSON、Excel 和 CSV）加载到 Danfo.js 中，最后，您将了解一些在 JavaScript 中使数据分析和预处理更容易的重要函数。

在本章中，我们将涵盖以下主题：

+   为什么你需要 Danfo.js

+   安装 Danfo.js

+   介绍 Series 和 DataFrames

+   Danfo.js 中的重要函数和方法

+   数据加载和处理不同的文件格式

# 技术要求

为了跟随本章，您应该具备以下条件：

+   现代浏览器，如 Chrome、Safari、Opera 或 Firefox

+   在您的系统上安装了 Node.js、Danfo.js 和 Dnotebook

本章的代码在这里可用：[`github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter03`](https://github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter03)。

注意

对于大多数代码片段，您可以使用在线提供的 Dnotebook：[`playnotebook.jsdata.org/`](https://playnotebook.jsdata.org/)。

# 为什么你需要 Danfo.js

要成功地将用 Python 编写的机器学习项目带到 Web 上，需要执行许多过程和任务，例如模型部署、使用 Flask、FastAPI 或 Django 等框架创建 API 路由，然后使用 JavaScript 向模型发送 HTTP 请求。您可以清楚地观察到该过程涉及大量 JavaScript。如果我们能够仅使用 JavaScript 执行所有这些过程，那将是非常棒的，不是吗？好消息是我们可以。

在过去的几年里，浏览器的计算能力稳步增加，并且可以支持高强度的计算，因此在处理数据密集型任务时，JavaScript 具有挑战 Python 的优势。

借助 Node.js，JavaScript 可以访问本地计算机上可用的 GPU，使我们能够使用 Node.js 进行全栈机器学习项目，并使用纯 JavaScript 进行前端开发。

使用 JavaScript 的好处之一是可以轻松地在客户端进行推断，因此数据不必离开客户端到服务器。此外，JavaScript 使我们的程序具有跨平台支持，并且借助内容传送网络（CDN），所有用于应用程序开发的 JavaScript 包都可以轻松使用，而无需安装它们。

随着 TensorFlow.js 和 Danfo.js 等工具的引入，我们看到 JavaScript 在数据科学和机器学习生态系统中得到了更多支持。

想象一下在 Web 上拥有强大的数据处理库，比如 Python pandas（[`pandas.pydata.org/`](https://pandas.pydata.org/)），并考虑将这样的工具融入 JavaScript 中流行的现代框架，如 Vue 或 React；可能性是无限的。这就是 Danfo.js 带给 Web 的力量。

JavaScript 开发人员已经做出了各种尝试，将 pandas 的数据处理能力带到 Web 上。因此，我们有诸如`pandas-js`、`dataframe-js`、`data-forge`和`jsdataframe`等库。

将 Python pandas 移植到 JavaScript 的需求主要是因为需要在浏览器中执行数据预处理和操作任务。

这是一个关于 **Stack Overflow** 的讨论串 ([`stackoverflow.com/questions/30610675/python-pandas-equivalent-in-JavaScript/43825646`](https://stackoverflow.com/questions/30610675/python-pandas-equivalent-in-JavaScript/43825646))，其中详细介绍了 JavaScript 中用于数据预处理和操作的不同工具，但大多数这些工具因为以下两个原因而失败，如串中所述：

+   缺乏将多个库合并为单个库的协作（许多库试图执行不同的任务）

+   大多数库都没有 pandas 的主要功能，如：[`github.com/pandas-dev/pandas#main-features`](https://github.com/pandas-dev/pandas#main-features)

除了这里列出的两个原因，我们在尝试大多数现有工具时观察到的另一个问题是缺乏像 Python 的 pandas 那样良好的用户体验。pandas 非常受欢迎，由于大多数使用 JavaScript 创建的工具都模仿 pandas，因此最好拥有与 pandas 相当相似的用户体验。

Danfo.js 的构建是为了弥补现有数据处理库所面临的差距和问题。API 经过精心设计，模仿了 pandas API，并且为从 Python 背景而来的人提供了类似的体验，同时也为 JavaScript 开发人员提供了简单直观的 API。

除了简单且熟悉的 API 外，由于 TensorFlow.js 的支持，Danfo.js 更快。Danfo.js 在 JavaScript 数据科学社区中备受欢迎，在不到一年的时间里在 GitHub 上获得了超过 1500 颗星，同时也得到了 Google 的 TensorFlow.js 团队的认可 ([`blog.tensorflow.org/2020/08/introducing-danfo-js-pandas-like-library-in-JavaScript.html`](https://blog.tensorflow.org/2020/08/introducing-danfo-js-pandas-like-library-in-JavaScript.html))。另外，值得一提的是 Danfo.js 得到了积极贡献者的大力维护和不断发展，他们确保其始终保持最新和稳定。

除了前述原因，我们决定撰写这本关于 Danfo.js 的书籍还有许多其他原因，以便为您提供在 JavaScript 中执行数据操作任务所需的技能和知识。在下一节中，我们将首先学习如何在浏览器中安装和导入 Danfo.js，同时也在 Node.js 环境中进行。

# 安装 Danfo.js

Danfo.js 在浏览器和 Node.js 环境中都可以轻松获取。要在浏览器中使用 Danfo.js，可以将 `script` 标签添加到 `HTML` 文件的头部，如下所示：

```js
<head>
      ...
     <script src="img/bundle.min.js"></script>
      ...
</head>
```

在撰写本文时，浏览器环境中 Danfo.js 的最新版本为 0.2.7。这很可能已经改变，但请放心，本书中使用的所有代码和片段将在未来版本中起作用。

注意

要安装或获取 Danfo.js 的最新版本，可以在官方文档的发布页面 [`danfo.jsdata.org/release-notes`](https://danfo.jsdata.org/release-notes) 中查看。

在 Node.js 环境中，可以使用 `yarn` 安装 Danfo.js，如下所示：

```js
//NPM
npm install danfojs-node
// Yarn
yarn add danfojs-node
```

安装完成后，可以使用以下任一命令导入 Danfo.js：

```js
//Common js style
const dfd = require("danfojs-node")
// ES6 style
import * as dfd from 'danfojs-node'
```

注意

为了练习，您可以始终使用 [`playnotebook.jsdata.org/`](https://playnotebook.jsdata.org/)，如前一章所述。有了这个，您可以在线访问 Dnotebook 进行快速实验。要在 Dnotebook 中使用 Danfo.js 的最新版本，您可以始终使用 `load_package` 函数。

Danfo.js 的浏览器和 Node.js 版本遵循相同的 API 设计。主要区别在于在浏览器中，Danfo.js 被添加到全局范围下的名称 `dfd`。因此，`dfd` 变量可用于所有 JavaScript 或 HTML 文件。

现在我们安装完成后，我们将继续下一节，讨论 Danfo.js 和 Series 中提供的主要数据结构和方法。

# 介绍 Series 和 DataFrames

Danfo.js 公开了两种主要数据结构，Series 和 DataFrames，可以轻松进行所有数据操作。DataFrames 和 Series 为不同类型的数据提供了通用表示，因此可以将相同的数据处理过程应用于具有不同格式的数据集。

在本节中，我们将看到创建 Series 和 DataFrames 的不同方法。我们将了解如何处理 DataFrame 和 Series 格式的数据。我们还将研究不同的 DataFrame 和 Series 方法来处理数据。

我们将从处理 Series 数据结构的数据开始本节。

## Series

Series 提供了处理一维数据的入口，例如具有相同数据类型的一系列值的单个数组。

在本节中，我们将熟悉以下 Series 方法的 Series 数据结构：

```js
 *  table() and print() method:let sdata= new dfd.Series([1,3,5,7,9,11])
table( sdata) // Displays the table in Dnotebook
```

上述代码给出了以下输出表：

![图 3.1 – Series 表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_1.jpg)

图 3.1 – Series 表

在上述代码片段中，我们使用 `table()` 来打印 Series 表。这是因为我们在本章的大部分代码中都在使用 Dnotebook。要在浏览器或 Node.js 控制台中打印 DataFrames 或 Series，可以始终调用 `print()` 如下：

```js
 sdata.print() // will give us same output as table( sdata)
```

在随后的代码中，我们将始终使用 `table()` 函数，这允许我们在浏览器网页上打印 DataFrame。

+   `.index` 属性: 默认情况下，Series 表的列名始终为 0，除非另有指定。还要注意，Series 表的索引范围为数据的 `0` 到 `n – 1`，其中 `n` 是数据的长度。索引也可以通过以下方式获取：

```js
console.log(sdata.index) // [0,1,2,3,4,5]
```

+   `.dtype` 和 `astype()`: 有时传入 Series 的数据可能不是同质的，并且可能包含混合数据类型的字段，如下所示：

```js
let sdata = new dfd.Series([1,2,3, "two:","three"])
console.log(sdata.dtype)
// string
```

`dtype` 输出了 `string`，而数据是不同的数据类型，因此我们可以始终像以下代码一样更改 `dtype`：

```js
sdata.astype('int32')
```

上述代码更改了 Series 的数据类型，但实际上并没有将数据中的字符串转换为 `int32`。因此，如果对数据执行数值操作，将会引发错误。

+   `.tensor` 属性: Series 中的数据可以以两种主要格式获取 – 作为 JavaScript `series.tensor` 是一个有效的 TensorFlow.js 张量，因此可以对其执行所有支持的张量操作。例如，在以下代码中，我们对 Series `tensor` 对象调用指数函数：

```js
sdata.tensor.exp(2).arraySync()
// [3,7,20,55,148]
```

在上述代码中，我们能够打印出 Series 数据的指数，因为我们可以访问底层张量。`arraySync` 方法返回张量的数组格式。让我们来看一下 `set_index()` 方法。

+   `set_index()` 方法: 在创建 Series 数据结构时可以指定索引。我们在以下代码中演示了这一点：

```js
series = new dfd.Series([1,2,3,4,5], {index: ["one","two", "three", "four", "five"]})
table(series)
```

这将设置 Series 的索引并替换默认的数值索引，如下所示：

![图 3.2 – 具有命名索引的 Series](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_2.jpg)

图 3.2 – 具有命名索引的 Series

我们可以始终更改 Series 的默认索引值，如以下代码所示：

```js
sdata = new dfd.Series(["Humans","Life","Meaning","Fact","Truth"])
new_series = sdata.set_index({ "index": ["H", "L", "M","F","T"] })
table(new_series)
```

`sdata.set_index()` 重置索引并返回一个新的 Series，如 *图 3.2* (*左*) 所示，而不会改变原始 Series。我们可以将 `set_index()` 设置为实际更新原始 Series 的索引并且不返回新的 Series，方法是将 `inplace` 键设置为 `true`：

```js
sdata.set_index({ index: ["H", "L", "M","F","T"] , inplace: true })
```

现在我们来看一下 `.apply()` 方法。

+   `.apply()` 方法: 由于 Series 是单维数组，因此可以轻松应用类似于在 JavaScript 中处理数组的操作。Series 有一个名为 `.apply` 的方法，可以在 Series 数据的每个值上应用任何函数：

```js
sdata = new dfd.Series(["Humans","Life","Meaning","Fact","Truth"])
series_new = sdata.apply((x) => {
 return x.toLocaleUpperCase()
})
table(series_new)
```

这通过在每个值上应用 `x.toLocaleUpperCase()` 将 Series 中的每个字符串转换为大写。下图显示了在应用 `x.toLocaleUpperCase` 之前和之后的表输出：

![图 3.3 - 左：将索引设置为字符串。右：使用 apply 将所有字符串转换为大写](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_3.jpg)

图 3.3 - 左：将索引设置为字符串。右：使用 apply 将所有字符串转换为大写

`.apply`方法也非常适用于对 Series 数据的每个值执行数值操作：

```js
sf = new dfd.Series([1, 2, 3, 4, 5, 6, 7, 8])
sf_new = sf.apply(Math.log)
table(sf_new)
```

我们使用`.apply`函数找到了 Series 中每个值的对数。对于所有其他数学运算也是一样的。

上述代码输出以下表格：

![图 3.4 - 对 Series 的每个值应用数学运算（Math.log）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_4.jpg)

图 3.4 - 对 Series 的每个值应用数学运算（Math.log）

Series 数据结构还包含`.map`方法，类似于`.apply`。该方法将 Series 的每个值映射到另一个值：

```js
sf = new dfd.Series([1,2,3,4])
map = { 1: "ok", 2: "okie", 3: "frit", 4: "gop" }
sf_new = sf.map(map)
table(sf_new)
```

map 接受对象和函数作为参数。在上述代码中，我们创建了一个名为`map`的对象，其中包含 Series 中的值作为键，以及每个键应映射到的值。

上述代码输出以下表格：

![图 3.5 - 在 Series 值上使用 map](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_5.jpg)

图 3.5 - 在 Series 值上使用 map

接下来，我们将看一下`.isna()`方法。

+   `.isna()`方法：到目前为止，我们传递到 Series 中的数据似乎都没有问题，不包含缺失值或未定义值，但在处理真实数据时，我们总会有`NaN`或未定义的值。我们可以随时检查我们的 Series 中是否存在这样的值：

```js
sf_nan = new dfd.Series([1,2, NaN, 20, undefined, 100])
table(sf_nan)
```

作为测试，我们创建了一个包含`NaN`和一个未定义变量的 Series。我们得到以下输出：

![图 3.6 - 包含 NaN 值的 Series 框架的表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_6.jpg)

图 3.6 - 包含 NaN 值的 Series 框架的表

让我们检查包含`NaN`和未定义值的行；对于这些行中的每一行，我们输出`true`，如果没有，则显示为`false`，如下面的代码所示：

```js
table(sf_nan.isna())
```

我们得到以下输出：

![图 3.7 - Series 数据的 isna 表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_7.jpg)

图 3.7 - Series 数据的 isna 表

`.add()`方法如下。

+   `.add()`方法：Series 数据结构还支持 Series 之间的逐元素操作（如加法、减法、乘法和除法），在此操作之后，索引会自动对齐：

```js
sf1  = new dfd.Series([2,20,23,10,40,5])
sf2  = new dfd.Series([30,20,40,10,2,3])
sf_add = sf1.add(sf2)
table(sf_add)
```

我们有以下输出：

图 3.8 - 添加两个 Series

](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_8.jpg)

图 3.8 - 添加两个 Series

上述代码片段将`sf2` Series 添加到`sf1`，并且每个值都是按元素逐行添加的。

还要注意，可以将单个值传递给`sf1.add`，这将向`sf1` Series 中的每个元素添加一个常量值：

```js
table(sf1.add(10))
```

以下是上述代码的输出：

![图 3.9 - 向 Series 元素添加常量值](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_9.jpg)

图 3.9 - 向 Series 元素添加常量值

先前显示的操作也适用于所有其他数学运算以及 Series。

在下一小节中，我们将研究数据框的操作，如何创建数据框以及如何使用数据框操作处理数据。

## 数据框

数据框表示一组 Series，尽管与 Series 不同，它基本上是数据的二维表示（尽管它也可以表示更高的维度），包含多列和多行。

数据框基本上可以使用 JavaScript 对象构建，如下面的代码所示：

```js
data = {
  artist: ['Drake','Rihanna','Gambino', 'Bellion', 'Paasenger'],
  rating: [5, 4.5, 4.0, 5, 5],
  dolar: [ '$1m', '$2m','$0.1m', '$2.5m','$3m']
}
df = new dfd. DataFrame (data)
table(df) 
// print out the  DataFrame 
```

生成的数据框应如下所示：

![图 3.10 - 数据框表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_10.jpg)

图 3.10 - 数据框表

在上述代码中，创建了包含键和值的 JavaScript 对象数据。请注意 JavaScript 对象的以下内容：

+   每个键包含一个列表值，表示每列的数据。

+   每个键代表列和列名。

+   每个键必须具有相同长度的列表值。

以下是处理数据框数据结构的常见方法：

+   `head()`和`tail()`方法：有时，在处理大型数据集时，您可能需要查看数据的前几行（可能是前 5 行或前 30 行，只要您喜欢的数量），以及数据的最后几行。

由于我们的 DataFrame 包含五行，让我们打印表的前两行：

```js
table(df.head(2))
```

`head()`方法默认打印 DataFrame 的前五行，但我们可以指定`2`，因为我们的数据很小。

以下表显示了前述代码的结果：

![图 3.11 - 用于 df.head(2)的表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_11.jpg)

图 3.11 - 用于 df.head(2)的表

此外，要查看 DataFrame 中的最后一组行，我们使用`tail()`方法。默认情况下，`tail`方法会打印出 DataFrame 中的最后五行：

```js
table(df.tail(2))
```

`tail`函数接受一个值，该值指定要从 DataFrame 表末尾打印的行数，如下所示：

![图 3.12 - 打印最后两行](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_12.jpg)

图 3.12 - 打印最后两行

+   `data`变量包含数据，表示为数组的数组。数据数组中的每个数组按行排列的值将在 DataFrame 表中表示为`[Drake, 5, $1m]`表示 DataFrame 中的一行，而每个值（`Drake`，`5`，`$1m`）表示不同的列。`Drake`属于`artist`列，`$1m`属于`dollar`列，如下图所示：

![图 3.13 - DataFrame 表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_13.jpg)

图 3.13 - DataFrame 表

回想一下，我们说过 DataFrame 是 Series 的集合，因此可以像访问 JavaScript 对象元素的方式一样从 DataFrame 中访问这些 Series。下面是如何做到这一点的：

```js
table(df.artist)
```

请注意，`artist`是 DataFrame 中的列名，因此如果我们将 DataFrame 视为对象，则`artist`是键，键的值是 Series。前述代码应输出以下表：

![图 3.14 - 列系列](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_14.jpg)

图 3.14 - 列系列

`artist`列也可以通过`df['artist']`访问：

```js
table(df['dollar'])
```

此方法也输出与使用初始`df.dollar`方法相同的结果：

![图 3.15 - 访问列值](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_15.jpg)

图 3.15 - 访问列值

除了通过类似对象的方法访问列值之外，我们还可以按以下方式更改列数据：

```js
df['dollar'] = ['$20m','$10m', '$40m', '$35m', '$10m']
```

如果我们要打印`df.dollar`，我们将获得以下输出：

![图 3.16 - 更改列值](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_16.jpg)

图 3.16 - 更改列值

也可以通过创建一个 Series 框架，然后将其分配给 DataFrame 中的列来更改列数据，如下所示：

```js
rating = new dfd.Series([4.9,5.0, 7.0, 3.0,2.0])
df['rating'] = rating
table(df['rating'])
```

前述代码更改了列评分的值，并输出了以下表：

![图 3.17 - 使用 Series 值更改列数据](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_17.jpg)

图 3.17 - 使用 Series 值更改列数据

在处理与时间相关的列时，使用 Series 数据来更新列数据的方法非常方便。我们可能需要提取日期列中的小时或月份，并用提取的信息（小时或月份）替换列。 

让我们向 DataFrame 添加一个日期列：

```js
date = [ "06-30-02019", "07-29-2019", "08-28-2019", "09-12-2019","12-03-2019" ]
df.addColumn({column: "date", value: date})
```

我们使用`addColumn`方法向 DataFrame 添加新列。`addColumn`方法接受一个必须包含以下键的对象参数：

a) 要添加的“列”的名称

b) 列的新“值”

前述代码应输出以下表：

![图 3.18 - 添加新列](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_18.jpg)

图 3.18 - 添加新列

创建的新列是一个日期时间列，因此我们可以将此列转换为时间序列数据结构，然后提取列中每个数据点的月份名称：

```js
date_series = df['date']
df['date'] = date_series.dt.month_name()
```

我们提取日期列并将其分配给`date_series`变量。从`date_series`（实际上是一个 Series 数据结构）中，我们提取每个值的月份名称。Series 数据结构包含`dt`方法，它将 Series 结构转换为时间序列结构，然后使用`month_name()`方法提取月份名称。

上述代码输出了以下表格：

![图 3.19 – 提取月份名称](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_19.jpg)

图 3.19 – 提取月份名称

我们将要查看的下一个方法是`.values`和`.tensor`。

+   `.values`和`.tensor`：DataFrame 的值，即每个列值，可以使用`df.values`作为一个巨大的数组获得：

```js
df.values
//output
[[Drake,4.9,$20m,Jun],[Rihanna,5,$10m,Jul],[Gambino,7,$40m,Aug],[Bellion,3,$35m,Sep],[Passenger,2,$10m,Dec]]
```

有时，我们可能希望将 DataFrame 作为张量获得用于机器学习操作，因此以下显示了如何将 DataFrame 作为张量值获得：

```js
df.tensor
//output
{"kept":false,"isDisposedInternal":false,"shape":[5,4],"dtype":"string","size":20,"strides":[4],"dataId":{},"id":28,"rankType":"2"}
```

`tensor`属性返回了一个 TensorFlow.js 张量数据结构。由于张量必须始终包含唯一的数据类型，因此我们 DataFrame 中的所有数据点都转换为`dtype`字符串。

+   `.transpose()`方法：由于我们声称 DataFrame 是数据的二维表示，因此我们应该能够对 DataFrame 进行转置：

```js
df.transpose()
```

`df.transpose()`将列列表作为索引，将索引作为列，如下表所示：

![图 3.20 – 转置 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_20.jpg)

图 3.20 – 转置 DataFrame

我们可以获取 DataFrame 的索引并查看列是否现在是当前索引：

```js
df2 = df.transpose()
console.log(df2.index) 
// [artist,rating,dollar,date]
```

上述代码是转置 DataFrame 的索引。在前面的示例中，索引始终是数值，但是通过这个示例，可以看到索引也可以是字符串。

+   `.set_index()`方法：使用 DataFrame 本身，在对其进行转置之前，让我们将 DataFrame 的索引从整数更改为字符串索引：

```js
df3 = df.set_index({key:["a","b","c","d","e"]})
```

使用 DataFrame 中的`set_index`方法使用给定的键值设置索引。`set_index`还接受`inplace`键（`inplace`键是一个布尔键，它接收`true`或`false`作为值，但默认值为`false`）来指定 DataFrame 是否应该更新或返回包含更新的新 DataFrame。

以下表格显示了上述代码的结果：

![图 3.21 – 设置 DataFrame 的索引](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_21.jpg)

图 3.21 – 设置 DataFrame 的索引

由于索引可以是任何内容，因此我们也可以将 DataFrame 的索引设置为 DataFrame 中的一列：

```js
df4 = df.set_index({key:"artist"})
```

这一次，`set_index`接受一个值而不是一个提议的索引值数组。如果将单个值作为键索引传递，`set_index`认为它应该作为 DataFrame 中的列可用。

`artist`列中的值用于替换默认索引。还要注意`inplace`的默认值为`false`，因此会创建并返回一个包含更新索引的新 DataFrame。

以下显示了创建的 DataFrame 的输出：

![图 3.22 – 将索引设置为艺术家列](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_22.png)

图 3.22 – 将索引设置为艺术家列

到目前为止，您应该已经了解如何创建 Series 和 DataFrame 以及如何利用它们各自的方法进行数据处理。

在下一节中，我们将研究一些在 Danfo.js 中常用于数据分析和处理的基本函数和方法。

# Danfo.js 中的基本函数和方法

在本节中，我们将介绍与 Series 和 DataFrames 相关的一些重要函数和方法。每个数据结构中的方法都很多，我们可以随时查看文档以获取更多方法。本节将只提到一些最常用的方法：

+   `loc`和`iloc`索引

+   排序：`sort_values`和`sort_index`方法

+   `过滤器`

+   算术运算，如`add`，`sub`，`div`，`mul`和`cumsum`

## loc 和 iloc 索引

使用`loc`和`iloc`方法更容易地访问 DataFrame 的行和列；这两种方法都允许您指定要访问的行和列。对于那些来自 Python 的 pandas 库的人来说，Danfo.js 中实现的`loc`和`iloc`格式应该是熟悉的。

使用`loc`方法访问具有非数字索引的 DataFrame，如下所示：

```js
df_index = df4.loc({rows:['Bellion','Rihanna','Drake']})
```

利用上一节中更新的 DataFrame，我们使用`loc`方法从 DataFrame 中获取特定的行索引。这个索引值在`rows`关键元素中指定：

![图 3.23-访问特定的行索引值](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_23.jpg)

图 3.23-访问特定的行索引值

此外，`loc`和`iloc`方法使我们能够对数组进行切片。这对于 Python 用户来说应该是熟悉的。如果你不知道它是什么，不要担心；下面的例子将展示它的含义和如何做到这一点。

为了获得一系列的索引，我们可以指定非数字索引的上限和下限：

```js
df_index = df4.loc({rows:["Rihanna:Bellion"]})
```

当 DataFrame 的列名和索引是字符串时，使用`loc`方法。对于上述代码，我们指定要提取`Rihanna`行索引和`Bellion`行索引之间的数据值。

这个冒号有助于指定范围边界。以下表格显示了上述代码的输出：

![图 3.24-字符串索引](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_24.jpg)

图 3.24-字符串索引

除了对行进行索引，我们还可以提取特定的列：

```js
df_index = df4.loc({rows:["Rihanna:Bellion"], columns:["rating"]})
```

将`columns`键传递到`loc`中以提取名为`rating`的列。

以下表格显示了上述代码的结果：

![图 3.25-列和行索引](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_25.jpg)

图 3.25-列和行索引

我们还可以指定索引列的范围，如下所示：

```js
df_loc= df4.loc({rows:["Rihanna:Bellion"], columns:["rating:date"]})
```

这应该返回一个类似于以下的表：

![图 3.26-列范围](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_26.jpg)

图 3.26-列范围

从上表中，我们可以看到范围与行索引相比是完全不同的；列索引排除了上限。

DataFrame 中的`loc`方法使用字符来索引行数据和列数据。`iloc`也是一样，但是使用整数来索引行和列。

使用如下表格中显示的初始 DataFrame，我们将使用`iloc`方法进行索引：

![图 3.27-艺术家表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_27.jpg)

图 3.27-艺术家表

让我们使用`iloc`来访问*图 3.27*中显示的表的索引`2`到`4`：

```js
t_df = df.iloc({rows:['2:4']})
table(t_df)
```

`iloc`方法接受与`loc`方法相同的关键字：`rows`和`columns`关键字。数字被包装在字符串中，因为我们想执行`loc`方法。

以下表格显示了上述代码的结果：

![图 3.28-使用封闭上限从 2 到 4 索引表行](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_28.jpg)

图 3.28-使用封闭上限从 2 到 4 索引表行

切片数组（花式索引）

对于那些来自 Python 的人来说，切片数组将是熟悉的。在 Python 中，可以使用一系列值对数组进行索引，例如，`test = [1,2,3,4,5,6,7] test [2:5] => [3,4,5]`。JavaScript 没有这个属性，因此 Danfo.js 通过将范围作为字符串传递，并从字符串中提取上限和下限来实现这一点。

与在前面的例子中对行进行的相同的切片操作也可以对列进行：

```js
column_df = df.iloc({columns:['1:']})
table(column_df)
```

`df.iloc({columns:['1:']})`用于提取从索引 1（表示`rating`列）到最后一列的列。对于整数索引，当未指定上限时，它会选择最后一列作为上限。

在本节中，我们讨论了对 DataFrame 进行索引和不同的索引方法。在下一节中，我们将讨论如何按列值和行索引对 DataFrame 进行排序。

## 排序

Danfo.js 支持两种排序数据的方法 - 按索引或按列值。此外，Series 数据只能按索引排序，因为它是一个只有单列的 DataFrame 对象。DataFrame 有一个名为`sort_values`的方法，它使您能够按特定列对数据进行排序，因此通过对特定列进行排序，我们正在对其他所有列进行排序。

让我们创建一个包含数字的 DataFrame：

```js
data = {"A": [-20, 30, 47.3],
         "B": [ -4, 5, 6],
         "C": [ 2, 3, 30]}
df = new dfd. DataFrame (data)
table(df)
```

这将输出以下表格：

![图 3.29 – 数字 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_29.jpg)

图 3.29 – 数字 DataFrame

现在，让我们按列`B`中的值对 DataFrame 进行排序：

```js
df.sort_values({by: "C", inplace: true, ascending: false})
table(df)
```

`sort_values`方法接受以下关键字参数：

+   `by`：用于对 DataFrame 进行排序的列的名称。

+   `inplace`：是否应更新原始 DataFrame（`true`或`false`）。

+   `ascending`：列是否应按升序排序。默认值始终为`false`。

在上面的代码片段中，我们指定按列`C`对 DataFrame 进行排序，并将`inplace`设置为`true`，因此 DataFrame 被更新，并且列也按降序排序。以下表格显示了输出：

![图 3.30 – 按列值排序的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_30.jpg)

图 3.30 – 按列值排序的 DataFrame

有时我们可能不想更新原始 DataFrame 本身。这就是`inplace`关键字的影响所在：

```js
sort_df = df.sort_values({by: "C", inplace:false, ascending: false})
table(sort_df)
```

在上面的代码中，DataFrame 按列排序。让我们尝试按其索引对相同的 DataFrame 进行排序：

```js
index_df = sort_df.sort_index({ascending:true})
table(index_df)
```

`sort_index`还接受关键字参数：`ascending`和`inplace`。我们将`ascending`关键字设置为`true`，这应该会给我们一个按升序排列的 DataFrame。

以下是获得的输出：

![图 3.31 – 排序索引 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_31.jpg)

图 3.31 – 排序索引 DataFrame

在 Series 中进行排序需要一个非常简单的方法；通过调用`sort_values`方法来进行排序，如下所示：

```js
data1 = [20, 30, 1, 2, 4, 57, 89, 0, 4]
series = new dfd.Series(data1)
sort_series = series.sort_values()
table(sort_series)
```

`sort_values`方法还接受关键字参数`ascending`和`inplace`。默认情况下，`ascending`设置为`true`，`inplace`设置为`false`。

以下表格显示了上述代码的结果：

![图 3.32 – 按值排序 Series](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_32.jpg)

图 3.32 – 按值排序 Series

请注意，`sort_values`和`sort_index`方法也适用于包含字符串的列和索引。

使用我们的`artist` DataFrame，让我们尝试按以下方式对一个列进行排序：

```js
sort_df = df.sort_values({by: "artist", inplace:false, ascending: false})
table(sort_df)
```

DataFrame 使用`artist`列按降序排序。这将导致一个表，其中`Rihanna`在第一行，其后是`Passenger`，基于第一个字符：

![图 3.33 – 按字符串列排序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_33.jpg)

图 3.33 – 按字符串列排序

在本节中，我们看到了如何按列值和行索引对 DataFrame 进行排序。在下一节中，我们将看到如何过滤 DataFrame 值。

## 过滤

根据列中的某些特定值过滤 DataFrame 的行在数据操作和处理过程中大多数时间都很方便。Danfo.js 有一个名为`query`的方法，用于根据列中的值过滤行。

`query`方法接受以下关键字参数：

+   `column`：列名

+   `is`：指定要使用的逻辑运算符（`>，<，>=，<=，==`）

+   `to`：用于过滤 DataFrame 的值

+   `inplace`：更新原始 DataFrame 或返回一个新的

以下是`query`方法的工作示例。

首先，我们创建一个 DataFrame：

```js
data = {"A": [30, 1, 2, 3],
        "B": [34, 4, 5, 6],
        "C": [20, 20, 30, 40]}

df = new dfd. DataFrame (data)
```

以下图显示了表格：

![图 3.34 – DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_34.jpg)

图 3.34 – DataFrame

让我们按列`B`中的值对 DataFrame 进行排序：

```js
query_df = df.query({ column: "B", is: ">", to: 5 })
table(query_df)
```

在这里，我们通过大于 5 的值来过滤列`B`。这将导致返回包含列`B`中大于 5 的值的行，如下所示：

![图 3.35 – 按列 B 中大于 5 的值过滤](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_35.jpg)

图 3.35 – 按列 B 中大于 5 的值过滤

让我们通过检查列`C`中的值是否等于`20`来过滤 DataFrame：

```js
query_df = df.query({ column: "C", is: "==", to: 20})
table(query_df)
```

通过这样，我们得到了以下输出：

![图 3.36 – 在 C 列值等于 20 的情况下进行过滤](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_36.jpg)

图 3.36 – 在 C 列值等于 20 的情况下进行过滤

在本节中，我们看到了如何通过列值过滤 DataFrame。在下一节中，我们将看到如何执行不同的算术运算。

## 算术运算

在本小节中，我们将研究不同的算术运算以及如何使用它们来预处理我们的数据。

可以在以下之间进行加法、减法、乘法和除法等算术运算：

+   一个 DataFrame 和一个 Series

+   一个 DataFrame 和一个数组

+   一个 DataFrame 和一个`标量`值

我们首先进行了 DataFrame 和`标量`值之间的算术运算：

```js
data = {"Col1": [10, 45, 56, 10], 
        "Col2": [23, 20, 10, 24]}
ar_df = new dfd. DataFrame (data)
//add a scalar variable
add_df = ar_df.add(20)
table(add_df)
```

`add`方法用于在 DataFrame 的每一行上添加一个`标量`变量 20。`add`方法接受两个参数：

+   `other`：这表示 DataFrame、Series、数组或`标量`。

+   `axis`：指定操作是按行还是按列应用的。行轴用`0`表示，列轴用`1`表示。默认为`0`。

对于`标量`操作，我们得到了以下结果：

![图 3.37 – 左：原始 DataFrame。右：进行标量加法后的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_37.jpg)

图 3.37 – 左：原始 DataFrame。右：进行标量加法后的 DataFrame

让我们创建一个 Series 并将其传递给`add`方法：

```js
add_series = new dfd.Series([20,30])
add_df = ar_df.add(add_series, axis=1)
table(add_df)
```

创建了一个包含两行元素的 Series。这两行元素等于`ar_df` DataFrame 中的列数，这意味着`add_series`的第一行值属于`ar_df`的第一列，就像第二行值对应于`ar_df`的第二列一样。

前面段落中的解释意味着`20`将用于乘以`Col1`，`30`将用于乘以`Col2`。为了实现这一点，我们指定轴为`1`，这告诉 add 操作按列进行操作，正如我们在下表中所看到的：

![图 3.38 – DataFrame 和 Series 之间的加法操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_38.jpg)

图 3.38 – DataFrame 和 Series 之间的加法操作

DataFrame 和 Series 之间的加法操作与 DataFrame 和普通 JavaScript 数组之间的操作相同，因为 Series 只是具有一些扩展功能的 JavaScript 数组。

让我们看看两个 DataFrame 之间的操作：

```js
data = {"Col1": [1, 4, 5, 0], 
         "Col2": [2, 0, 1, 4]}

data2 = {"new_col1": [1, 5, 20, 10],
         "new_Col2": [20, 2, 1, 2]}
df = new dfd.DataFrame(data)
df2 = new dfd.DataFrame(data2)

df_new = df.add(df2)
```

首先，我们创建两组 DataFrame，然后将它们相加；但是我们必须确保两个 DataFrame 具有相同数量的列和行。此外，此操作是逐行进行的。

该操作实际上并不关心两个 DataFrame 是否具有相同的列名，但是结果列名是我们要添加到前一个 DataFrame 的 DataFrame 的列名。

以下表显示了前面代码中创建的 DataFrame 的结果：

![图 3.39 – 从左到右：DataFrame df 和 df2 的表格以及 df 和 df2 之间的加法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_39.jpg)

图 3.39 – 从左到右：DataFrame df 和 df2 的表格以及 df 和 df2 之间的加法

使用 add 操作进行的示例与`sub()`、`mul()`、`div()`、`pow()`和`mod()`方法相同。

此外，对于 DataFrame 和 Series，还有一组称为累积的数学运算，其中包括以下方法：

+   累积求和：`cumsum()`

+   累积最小值：`cummin()`

+   累积最大值：`cummax()`

+   累积乘积：`cumprod()`

这些操作中的每一个在传递参数方面都是相同的。它们都接受操作应该在哪个轴上执行的参数：

```js
data = [[11, 20, 3], [1, 15, 6], [2, 30, 40], [2, 89, 78]]
cols = ["A", "B", "C"]
df = new dfd. DataFrame (data, { columns: cols })
new_df = df.cumsum({ axis: 0 })
```

我们通过指定其数据和列来创建一个 DataFrame，然后沿着`0`轴执行累积求和。

以下表显示了前面代码中创建的 DataFrame 的结果：

![图 3.40 – 左：cumsum()之前的 DataFrame。右：cumsum()之后的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_40.jpg)

图 3.40 - 左：cumsum()之前的 DataFrame。右：cumsum()之后的 DataFrame

让我们沿着 DataFrame 的轴`1`执行`cumsum`操作：

```js
new_df = df.cumsum({ axis: 1 })
```

这给我们以下表格：

![图 3.41 - 沿轴 1 的累积和](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_41.jpg)

图 3.41 - 沿轴 1 的累积和

相同的累积操作也可以应用于 Series。让我们将相同的累积和应用于 Series 数据：

```js
series = new dfd.Series([2,3,4,5,6,7,8,9])
c_series = series.cumsum()
table(c_series)
```

Series 中的`cumsum`不接受任何参数。通过前面的操作，我们得到了以下表格*图 3.42*，即在应用累积 Series 之前的原始 Series。

以下表格显示了在前面代码中`series.cumsum()`操作的结果：

![图 3.42 - 累积和 Series](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_42.jpg)

图 3.42 - 累积和 Series

所有其他累积操作，如`cumprod`、`cummin`和`cummax`，都与前面`cumsum`示例中所示的方式相同。

在本节中，我们研究了不同的算术操作以及如何利用这些操作来预处理数据。在下一节中，我们将深入研究逻辑操作，例如如何在 DataFrame 和 Series、数组和`标量`值之间执行逻辑操作。

## 逻辑操作

在本节中，我们将看到如何执行逻辑操作，例如比较 DataFrame 和 Series、数组和标量值之间的值。

逻辑操作的调用和使用方式与算术操作的工作方式非常相似。逻辑操作可以在以下之间进行：

+   一个 DataFrame 和一个 Series

+   一个 DataFrame 和一个数组

+   一个 DataFrame 和一个标量值

实施了以下逻辑操作：

+   等于（`==`）：`.eq()`

+   大于（`>`）：`gt()`

+   小于（`<`）：`lt()`

+   不等于（`!=`）：`ne()`

+   小于或等于（`<=`）：`le()`

+   大于或等于（`>=`）：`ge()`

所有这些方法都接受相同的参数，即`other`和`axis`。使用`lt()`方法，让我们看看它们是如何工作的：

```js
data = {"Col1": [10, 45, 56, 10],
        "Col2": [23, 20, 10, 24]}
df = new dfd. DataFrame (data)
df_rep = df.lt(20)
table(df_rep)
```

代码检查 DataFrame 中的每个值是否小于 20。结果可以在下图中看到：

![图 3.43 - 左：df 的 DataFrame。右：df_rep 的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_43.jpg)

图 3.43 - 左：df 的 DataFrame。右：df_rep 的 DataFrame

同样的操作也可以在 DataFrame 和 Series 之间进行，如下所示：

```js
series = new dfd.Series([45,10])
df_rep = df.lt(series, axis=1)
table(df_rep)
```

DataFrame 与 Series 的`series`操作是按列进行的。以下表格是结果：

![图 3.44 - DataFrame 和 Series 之间的逻辑操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_44.jpg)

图 3.44 - DataFrame 和 Series 之间的逻辑操作

让我们在两个 DataFrame 之间执行逻辑操作，如下所示：

```js
data = {"Col1": [10, 45, 56, 10],
         "Col2": [23, 20, 10, 24]}
data2 = {"new_col1": [10, 45, 200, 10],
         "new_Col2": [230, 200, 110, 24]}

df = new dfd.DataFrame (data)
df2 = new dfd.DataFrame (data2)

df_rep = df.lt(df2)
table(df_rep)
```

代码输出了以下结果：

![图 3.45 - DataFrame 之间的逻辑操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_45.jpg)

图 3.45 - DataFrame 之间的逻辑操作

在本节中，我们研究了一些重要的 DataFrame 操作，例如如何按列值过滤 DataFrame。我们还看到了如何按列值和行索引对 DataFrame 进行排序。此外，本节还深入研究了使用`loc`和`iloc`对 DataFrame 进行索引，最后，我们研究了算术和逻辑操作。

在下一节中，我们将深入研究如何处理不同的数据格式，如何将这些文件解析为 Danfo.js，并将它们转换为 DataFrame 或 Series。

# 数据加载和处理不同的文件格式

在本节中，我们将看看如何处理不同的文件格式。Danfo.js 提供了一种处理三种不同文件格式的方法：CSV、Excel 和 JSON。以这些格式呈现的数据可以轻松地被读取并呈现为 DataFrame。

每种文件格式所需的方法如下：

+   `read_csv()`: 读取 CSV 文件

+   `read_json()`: 读取 JSON 文件

+   `read_excel()`: 读取以`.xslx`格式呈现的 Excel 文件

这些方法中的每一个都可以在本地和互联网上读取数据。此外，在`Node.js`环境中，这些方法只能访问本地文件。在网络上，这些方法可以读取提供的文件（CSV、JSON 和`.xslx`文件），只要这些文件在互联网上可用。

让我们看看如何在 Node.js 环境中读取本地文件：

```js
const dfd = require("Danfo.Js-node")
dfd.read_csv('titanic.csv').then(df => {
  df.head().print()
})
```

首先，我们导入 Node.js 版本的 Danfo.js，然后调用`read_csv()`来读取同一目录中可用的`titanic.csv`文件。请注意，如果要读取的文件不在同一目录中，您需要指定路径。

`df.head().print()`在 Node.js 控制台中打印 DataFrame 表的前五行；`print()`函数类似于我们在 Dnotebook 中使用的`table()`函数。我们从前面的代码中得到以下表格：

![图 3.46 – 从 CSV 文件读取的 DataFrame 表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_46.jpg)

图 3.46 – 从 CSV 文件读取的 DataFrame 表

同样，可以在网络上进行相同的操作，但我们将使用`http`链接，这样相同的数据就可以在线使用：

```js
csvUrl =
      "https://storage.googleapis.com/tfjs-examples/multivariate-linear-regression/data/boston-housing-train.csv";
dfd.read_csv(csvUrl).then((df) => {
  df.print()
});
```

这与前一个代码块产生相同的结果。对所有其他文件格式方法也是一样的：

```js
const dfd = require("Danfo.Js-node")

dfd.read_excel('SampleData.xlsx', {header_index: 7}).then(df => {
  df.head().print()
})
```

`read_excel()`方法接受一个可选的配置参数，确保正确解析 Excel 文件：

+   `source`：字符串、URL 或本地文件路径，用于检索 Excel 文件。

+   `sheet_name`（可选）：要解析的工作表的名称。默认为第一个工作表。

+   `header_index`（可选）：int，表示标题列的行索引。

+   `data_index`（可选）：int，指示数据开始的行索引。

在前面的代码块中，我们将`header_index`的值指定为`7`，因为标题列位于那里，因此我们得到以下结果：

![图 3.47 – 从 Excel 文件读取的 DataFrame 表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_47.jpg)

图 3.47 – 从 Excel 文件读取的 DataFrame 表

`read_json()`方法在传递参数方面与`read_csv()`非常相似；该方法只接受指向 JSON 文件的 URL 或 JSON 文件所在目录路径：

```js
const dfd = require("Danfo.Js-node")
dfd.read_json('book.json').then(df => {
  df.head().print()
})
```

这读取了同一目录中名为`book.json`的文件，并输出了以下内容：

![图 3.48 – 从 JSON 文件读取的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_3_48.jpg)

图 3.48 – 从 JSON 文件读取的 DataFrame

此外，Danfo.js 包含一个名为`reader`的终极表格文件读取方法；该方法可以读取 CSV 和 Excel。它还可以读取其他文件，如[`frictionlessdata.io/`](https://frictionlessdata.io/)中 Frictionless 规范中指定的`Datapackage`。

`reader`方法使用名为`Frictionless.js`的包在[`github.com/frictionlessdata/frictionless-js`](https://github.com/frictionlessdata/frictionless-js)中读取本地或远程文件。

`reader`方法与`read_csv`和`read_excel`具有相同的 API 设计，只是它可以读取两种文件类型，如下面的代码所示：

```js
const dfd = require("Danfo.Js-node")
// for reading csv
dfd.read('titanic.csv').then(df => {
  df.head().print()
})
```

从前面的代码中，我们输出了与*图 3.48*中显示的相同的表格。

## 将 DataFrame 转换为另一种文件格式

经过一系列数据处理后，我们可能希望将最终的 DataFrame 转换为文件格式以便保存。Danfo.js 实现了一种将 DataFrame 转换为 CSV 格式的方法。

让我们将迄今为止创建的 DataFrame 转换为 CSV 文件。请注意，这只适用于 Node.js 环境：

```js
df.to_csv("/home/link/to/path.csv").then((csv) => {
    console.log(csv);
}).catch((err) => {
    console.log(err);
})
```

这（`df.to_csv()`）将 DataFrame 保存为 CSV 文件，保存在指定的路径目录中，并赋予给它的名称（path.csv）。

在本节中，我们研究了在 Danfo.js 中可用的不同格式的文件，如 CSV、JSON 和 Excel。我们研究了读取这些文件的不同方法，还研究了一种更通用的读取这些文件格式的方法。

我们还看到了如何将 DataFrame 转换为用户指定的文件格式。

# 总结

在本章中，我们讨论了为什么需要 Danfo.js，然后深入了解了 Series 和 DataFrames 的实际含义。我们还讨论了 Danfo.js 中一些基本功能，并在 DataFrames 和 Series 中实现了这些功能。

我们还看到了如何使用 DataFrames 和 Series 方法来处理和预处理数据。我们学会了如何根据列值筛选 DataFrame。我们还按行索引和列值对 DataFrame 进行了排序。本章使我们能够执行日常数据操作，如以不同格式读取文件、转换格式，并将预处理后的 DataFrames 保存为理想的文件格式。

在下一章中，我们将深入研究数据分析、数据整理和转换。我们将进一步讨论数据处理和预处理，并了解如何处理缺失的数字，以及如何处理字符串和时间序列数据。


# 第五章：数据分析、整理和转换

**数据分析**、**整理**和**转换**是任何数据驱动项目的重要方面，作为数据分析师/科学家，您大部分时间将花在进行一种形式的数据处理或另一种形式上。虽然 JavaScript 是一种灵活的语言，具有良好的用于操作数据结构的功能，但编写实用程序函数来执行数据整理操作非常繁琐。因此，我们在 Danfo.js 中构建了强大的数据整理和转换功能，这可以大大减少在此阶段花费的时间。

在本章中，我们将向您展示如何在真实数据集上实际使用 Danfo.js。您将学习如何加载不同类型的数据集，并通过执行操作（如处理缺失值、计算描述性统计、执行数学运算、合并数据集和执行字符串操作）来分析它们。

在本章中，我们将涵盖以下主题：

+   转换数据

+   合并数据集

+   Series 数据访问器

+   计算统计数据

# 技术要求

要跟随本章，您应该具备以下条件：

+   现代浏览器，如 Chrome、Safari、Opera 或 Firefox

+   Node.js、Danfo.js 和 Dnotebook 已安装在您的系统上

+   稳定的互联网连接用于下载数据集

Danfo.js 的安装说明可以在*第三章*中找到，*开始使用 Danfo.js*，而 Dnotebook 的安装步骤可以在*第二章*中找到，*Dnotebook – JavaScript 的交互式计算环境*。

注意

如果您不想安装任何软件或库，可以使用 Dnotebook 的在线版本[`playnotebook.jsdata.org/`](https://playnotebook.jsdata.org/)。但是，在使用任何功能之前，请不要忘记安装最新版本的 Danfo.js！

# 转换数据

数据转换是根据定义的步骤/过程将数据从一种格式（主格式）转换为另一种格式（目标格式）的过程。数据转换可以是简单的或复杂的，取决于数据集的结构、格式、最终目标、大小或复杂性，因此重要的是要了解 Danfo.js 中用于进行这些转换的功能。

在本节中，我们将介绍 Danfo.js 中用于进行数据转换的一些功能。在每个子节下，我们将介绍一些函数，包括`fillna`、`drop_duplicates`、`map`、`addColumns`、`apply`、`query`和`sample`，以及用于编码数据的函数。

## 替换缺失值

许多数据集都存在缺失值，为了充分利用这些数据集，我们必须进行某种形式的数据填充/替换。Danfo.js 提供了`fillna`方法，当给定 DataFrame 或 Series 时，可以自动用指定的值填充任何缺失字段。

当您将数据集加载到 Danfo.js 数据结构中时，所有缺失值（可能是未定义的、空的、null、none 等）都存储为`NaN`，因此`fillna`方法可以轻松找到并替换它们。

### 替换 Series 中的值

`Series`对象的`fillna`方法的签名如下：

```js
Series.fillna({value, inplace})
```

`value`参数是您想要用于替换缺失值的新值，而`inplace`参数用于指定是直接对对象进行更改还是创建副本。让我们看一个例子。

假设我们有以下 Series：

```js
sdata = new dfd.Series([NaN, 1, 2, 33, 4, NaN, 5, 6, 7, 8])
sdata.print() //use print to show series in browser or node environment 
table(sdata) //use table to show series in Dnotebook environment
```

在您的 Dnotebook 环境中，`table(sdata)`将显示如下图所示的表格：

![图 4.1 – 具有缺失值的 Series](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_01.jpg)

图 4.1 – 具有缺失值的 Series

注意

如果您在浏览器或 Node.js 环境中工作，可以在控制台中查看`print`函数的输出。

要替换缺失值（`NaN`），我们可以这样做：

```js
sdata_new = sdata.fillna({ value: -999})
table(sdata_new) 
```

打印输出给我们以下表格：

![图 4.2 – 带有缺失值的 Series](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_02.jpg)

图 4.2 – 带有缺失值的 Series

你也可以原地填充缺失值，也就是说，你可以直接改变对象，而不是创建一个新的对象。这可以在以下代码中看到：

```js
sdata.fillna({ value: -999, inplace: true})
table(sdata)
```

在某些情况下，原地填充可以帮助减少内存使用，特别是在处理大型 DataFrame 或 Series 时。

### 替换 DataFrame 中的值

`fillna` 函数也可以用于填充 DataFrame 中的缺失值。DataFrame 对象的 `fillna` 方法的签名如下：

```js
DataFrame.fillna({columns, value, inplace})
```

首先，让我们了解参数：

+   `columns`: `columns` 参数是要填充的列名数组。

+   `values`: `values` 参数也是一个数组，必须与 `columns` 的大小相同，保存你想要替换的相应值。

+   `inplace`: 这指定我们是否应修改当前的 DataFrame 还是返回一个新的 DataFrame。

现在，让我们看一个例子。

假设我们有以下 DataFrame：

```js
data = {"Name":["Apples", "Mango", "Banana", undefined],
            "Count": [NaN, 5, NaN, 10], 
            "Price": [200, 300, 40, 250]}

df = new dfd.DataFrame(data)
table(df)
```

代码的输出如下图所示：

![图 4.3 – 带有缺失值的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_03.jpg)

图 4.3 – 带有缺失值的 DataFrame

在填充缺失值方面，我们可以采取两种方法。首先，我们可以用单个值填充所有缺失字段，如下面的代码片段所示：

```js
df_filled = df.fillna({ values: [-99]})
table(df_filled)
```

代码输出如下图所示：

![图 4.4 – 用单个值填充 DataFrame 中的所有缺失值](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_04.jpg)

图 4.4 – 用单个值填充 DataFrame 中的所有缺失值

在处理 DataFrame 时，用同一个字段填充所有缺失值的情况并不可取，甚至没有用，因为你必须考虑到不同字段具有不同类型的值，这意味着填充策略会有所不同。

为了处理这种情况，我们可以指定要填充的列及其相应的值的列表，如下所示。

使用前面例子中使用的相同 DataFrame，我们可以指定 `Name` 和 `Count` 列，并用 `Apples` 和 `-99` 值填充它们，如下所示：

```js
data = {"Name":["Apples", "Mango", "Banana", undefined],
            "Count": [NaN, 5, NaN, 10], 
            "Price": [200, 300, 40, 250]}

df = new dfd.DataFrame(data)
df_filled = df.fillna({columns: ["Name", "Count"], values: ["Apples", -99]})
table(df_filled)
```

代码的输出如下图所示：

![图 4.5 – 用特定值填充 DataFrame 中的缺失值](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_05.jpg)

图 4.5 – 用特定值填充 DataFrame 中的缺失值

注意

在数据分析中，常用填充值如-9、-99 和-999 来表示缺失值。

让我们看看如何在下一节中删除重复项。

## 删除重复项

在处理 Series 或 DataFrame 中的列时，重复字段是常见的情况。例如，看一下以下代码中的 Series：

```js
data = [10, 45, 56, 10, 23, 20, 10, 10]
sf = new dfd.Series(data)
table(sf)
```

代码的输出如下图所示：

![图 4.6 – 带有重复字段的 Series](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_06.jpg)

图 4.6 – 带有重复字段的 Series

在上图中，你可以看到值 `10` 出现了多次。如果有需要，你可以使用 `drop_duplicates` 函数轻松删除这些重复项。`drop_duplicates` 函数的签名如下：

```js
Series.drop_duplicates({inplace, keep)
```

`drop_duplicates` 函数只有两个参数，第一个参数（`inplace`）非常直观。第二个参数 `keep` 可以用于指定要保留哪个重复项。你可以保留 Series 中的第一个或最后一个重复项。这有助于在删除重复项后保持 Series 中的结构和值的顺序。

让我们看看这个实例。在下面的代码块中，我们正在删除所有重复的值，只保留第一次出现的值：

```js
data1 = [10, 45, 56, 10, 23, 20, 10, 10, 20, 20]
sf = new dfd.Series(data1)
sf_drop = sf.drop_duplicates({keep: "first"})
table(sf_drop)
```

代码的输出如下图所示：

![图 4.7 – 在 keep 设置为 first 的情况下删除重复项后的 Series](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_07.jpg)

图 4.7 – 在 keep 设置为 first 的情况下删除重复项后的 Series

从前面的输出中，您可以看到保留了重复项的第一个值，而其他值被丢弃。相反，让我们将`keep`参数设置为`last`，并观察字段的顺序变化：

```js
sf_drop = sf.drop_duplicates({keep: "last"})
table(sf_drop)
```

代码的输出如下图所示：

![图 4.8 - 在保留最后一个重复项的情况下删除重复项后的 Series](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_08.jpg)

图 4.8 - 在保留最后一个重复项的情况下删除重复项后的 Series

请注意，保留了最后的`10`和`20`重复字段，并且顺序与我们将`keep`设置为`first`时不同。下图将帮助您理解在删除重复项时`keep`参数的含义：

![图 4.9 - 当 keep 设置为 first 或 last 时的输出差异](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_09.jpg)

图 4.9 - 当 keep 设置为 first 或 last 时的输出差异

从上图中，您会注意到将`keep`设置为`first`或`last`的主要区别是生成值的顺序。

在下一小节中，我们将使用`map`函数进行数据转换。

## 使用`map`函数进行数据转换

在某些情况下，您可能希望对 Series 或 DataFrame 列中的每个值应用转换。当您有一些自定义函数或映射并希望轻松应用它们到每个字段时，这通常很有用。Danfo.js 提供了一个称为`map`的简单接口，可以在这里使用。让我们看一个例子。

假设我们有一个包含物品及其对应的重量（以克为单位）的 DataFrame，如下面的代码所示：

```js
df = new dfd.DataFrame({'item': ['salt', 'sugar', 'rice', 'apple', 'corn', 'bread'],
'grams': [400, 200, 120, 300, 70.5, 250]})
table(df)
```

代码的输出如下图所示：

![图 4.10 - DataFrame 中物品及其对应的重量（以克为单位）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_10.jpg)

图 4.10 - DataFrame 中物品及其对应的重量（以克为单位）

我们想要创建一个名为`kilograms`的新列，其值是相应的克数，但转换为千克。在这里，我们可以这样做：

1.  创建一个名为`convertToKg`的函数，代码如下：

```js
function convertToKg(gram){
  return gram / 1000
}
```

1.  在`grams`列上调用`map`函数，如下面的代码块所示：

```js
kilograms = df['grams'].map(convertToKg)
```

1.  使用`addColumn`函数将新的`kilograms`列添加到 DataFrame 中，如下面的代码所示：

```js
df.addColumn({ "column": "kilograms", "value": kilograms  });
```

将所有这些放在一起，我们有以下代码：

```js
df = new dfd.DataFrame({'item': ['salt', 'sugar', 'rice', 'apple', 'corn', 'bread'],
'grams': [400, 200, 120, 300, 70.5, 250]})
function convertToKg(gram){
  return gram / 1000
} 
kilograms  = df['grams'].map(convertToKg)
df.addColumn({ "column": "kilograms", "value": kilograms  });
table(df)
```

代码的输出如下图所示：

![图 4.11 - DataFrame 中物品及其对应的重量（以克为单位）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_11.jpg)

图 4.11 - DataFrame 中物品及其对应的重量（以克为单位）

当您将一个对象与键值对传递给`map`函数时，`map`函数也可以执行一对一的映射。这可用于诸如编码、快速映射等情况。让我们看一个例子。

假设我们有以下 Series：

```js
sf = new dfd.Series([1, 2, 3, 4, 4, 4])
```

在这里，我们想要将每个数字值映射到其对应的名称。我们可以指定一个`mapper`对象并将其传递给`map`函数，如下面的代码所示：

```js
mapper = { 1: "one", 2: "two", 3: "three", 4: "four" }
sf = sf.map(mapper)
table(sf)
```

代码的输出如下图所示：

![图 4.12 - 数值映射为字符串名称的 Series](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_12.jpg)

图 4.12 - 数值映射为字符串名称的 Series

`map`函数在处理 Series 时非常有用，但有时您可能希望将函数应用于特定轴（行或列）。在这种情况下，您可以使用另一个 Danfo.js 函数，称为`apply`函数。

在下一节中，我们将介绍`apply`函数。

## 使用`apply`函数进行数据转换

`apply`函数可用于将函数或转换映射到 DataFrame 中的特定轴。它比`map`函数稍微高级和强大，我们将解释原因。

首先是我们可以在指定的轴上应用张量操作的事实。让我们看一个包含以下值的 DataFrame：

```js
data = [[1, 2, 3], [4, 5, 6], [20, 30, 40], [39, 89, 78]]
cols = ["A", "B", "C"]
df = new dfd.DataFrame(data, { columns: cols })
table(df)
```

代码的输出如下图所示：

![图 4.13 - 具有三列的示例 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_13.jpg)

图 4.13 - 具有三列的示例 DataFrame

现在，我们可以在指定的轴上应用任何兼容的张量操作。例如，在以下代码中，我们可以对 DataFrame 中的每个元素应用`softmax`函数（[`en.wikipedia.org/wiki/Softmax_function`](https://en.wikipedia.org/wiki/Softmax_function)）：

```js
function sum_vals(x) {
    return x.softmax()
}
let df_new = df.apply({axis: 0, callable: sum_vals })
table(df_new)
```

代码的输出如下图所示：

![图 4.14-在逐个元素应用 softmax 函数后的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_14.jpg)

图 4.14-在逐个元素应用 softmax 函数后的 DataFrame

注意

我们将轴设置为`0`以进行逐个元素的张量操作。这是因为一些张量操作无法逐个元素执行。您可以在[`js.tensorflow.org/api/latest/`](https://js.tensorflow.org/api/latest/)上阅读有关支持的操作的更多信息。

让我们看另一个示例，应用一个既可以在列（axis=1）上工作，也可以在行（axis=0）上工作的函数。

我们将使用 TensorFlow 的`sum`函数进行操作，如下面的代码所示。首先，让我们在行轴上应用它：

```js
data = [[1, 2, 3], [4, 5, 6], [20, 30, 40], [39, 89, 78]] 
cols = ["A", "B", "C"] 
df = new dfd.DataFrame(data, { columns: cols })
function sum_vals(x) { 
    return x.sum() 
} 
df_new = df.apply({axis: 0, callable: sum_vals }) 
table(df_new)
```

打印`df_new` DataFrame 的结果如下输出：

![图 4.15-在行（0）轴上应用 sum 函数后的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_15.jpg)

图 4.15-在行（0）轴上应用 sum 函数后的 DataFrame

使用与之前相同的 DataFrame，将轴更改为`1`以进行列操作，如下面的代码片段所示：

```js
df_new = df.apply({axis: 1, callable: sum_vals }) 
table(df_new)
```

打印 DataFrame 的结果如下输出：

![图 4.16-在列（1）轴上应用 sum 函数后的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_16.jpg)

图 4.16-在列（1）轴上应用 sum 函数后的 DataFrame

自定义 JavaScript 函数也可以与`apply`函数一起使用。这里唯一的注意事项是，您不需要指定轴，因为 JavaScript 函数是逐个元素应用的。

让我们看一个使用 JavaScript 函数的`apply`的示例。在以下代码块中，我们将`toLowerCase`字符串函数应用于 DataFrame 中的每个元素：

```js
data = [{ short_name: ["NG", "GH", "EGY", "SA"] },
             { long_name: ["Nigeria", "Ghana", "Eqypt", "South Africa"] }]
df = new dfd.DataFrame(data)
function lower(x) {
    return '${x}'.toLowerCase()
}
df_new = df.apply({ callable: lower })
table(df_new)
```

打印 DataFrame 的结果如下输出：

![图 4.17-在逐个元素应用 JavaScript 函数后的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_17.jpg)

图 4.17-在逐个元素应用 JavaScript 函数后的 DataFrame

`apply`函数非常强大，可以用于在 DataFrame 或 Series 上应用自定义转换到列或行。在下一小节中，我们将看一下过滤和查询 DataFrame 和 Series 的不同方法。

## 过滤和查询

当我们需要获取满足特定布尔条件的数据子集时，过滤和查询非常重要。我们将在以下示例中演示如何在 DataFrame 和 Series 上使用`query`方法进行过滤和查询。

假设我们有一个包含以下列的 DataFrame：

```js
data = {"A": [30, 1, 2, 3],
         "B": [34, 4, 5, 6],
         "C": [20, 20, 30, 40]}
cols = ["A", "B", "C"]
df = new dfd.DataFrame(data, { columns: cols })
table(df)
```

打印 DataFrame 的结果如下输出：

![图 4.18-用于查询的示例值的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_18.jpg)

图 4.18-用于查询的示例值的 DataFrame

现在，让我们过滤 DataFrame，并仅返回`B`列的值大于`5`的行。这应该返回行`0`和`3`。我们可以使用`query`函数来实现，如下面的代码所示：

```js
df_filtered = df.query({ column: "B", is: ">", to: 5})
table(df_filtered)
```

这给我们以下输出：

![图 4.19-查询后的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_19.jpg)

图 4.19-查询后的 DataFrame

`query`方法接受所有 JavaScript 布尔运算符（`>`,`<`,`>=`,`<=`和`==`），并且也适用于字符串列，如下面的示例所示。

首先，让我们创建一个具有字符串列的 DataFrame：

```js
data = {"A": ["Ng", "Yu", "Mo", "Ng"],
            "B": [34, 4, 5, 6], 
            "C": [20, 20, 30, 40]}

df = new dfd.DataFrame(data)
table(df)
```

输出如下图所示：

![图 4.20-应用字符串查询之前的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_20.jpg)

图 4.20-应用字符串查询之前的 DataFrame

接下来，我们将使用等于运算符（`"=="`）运行一个查询：

```js
query_df = df.query({ column: "A", is: "==", to: "Ng"})
table(query_df)
```

这将产生以下输出：

![图 4.21-应用字符串查询后的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_21.jpg)

图 4.21 - 应用字符串查询后的数据框

在大多数情况下，您查询的数据框很大，因此可能希望执行就地查询。这可以通过将`inplace`指定为`true`来完成，如下面的代码块所示：

```js
data = {"A": [30, 1, 2, 3],
         "B": [34, 4, 5, 6],
         "C": [20, 20, 30, 40]}

cols = ["A", "B", "C"]
df = new dfd.DataFrame(data, { columns: cols })
df.query({ column: "B", is: "==", to: 5, inplace: true })
table(df)
```

打印数据框的结果如下：

![图 4.22 - 执行就地查询后的数据框](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_22.jpg)

图 4.22 - 执行就地查询后的数据框

`query`方法非常重要，在通过特定属性过滤数据时经常使用它。使用`query`函数的另一个好处是它允许`inplace`功能，这意味着它对于过滤大型数据集非常有用。

在下一个子节中，我们将看看另一个有用的概念，称为随机抽样。

## 随机抽样

从数据框或系列中进行**随机抽样**在需要随机重新排序行时非常有用。这在**机器学习**（**ML**）之前的预处理步骤中非常有用。

让我们看一个使用随机抽样的例子。假设我们有一个包含以下值的数据框：

```js
data = [[1, 2, 3], [4, 5, 6], [20, 30, 40], [39, 89, 78]] 
cols = ["A", "B", "C"] 
df = new dfd.DataFrame(data, { columns: cols }) 
table(df)
```

这导致以下输出：

![图 4.23 - 随机抽样前的数据框](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_23.jpg)

图 4.23 - 随机抽样前的数据框

现在，让我们通过在数据框上调用`sample`函数来随机选择两行，如下面的代码所示：

```js
async function load_data() {
  let data = {
    Name: ["Apples", "Mango", "Banana", "Pear"],
    Count: [21, 5, 30, 10],
    Price: [200, 300, 40, 250],
  };

  let df = new dfd.DataFrame(data);
  let s_df = await df.sample(2);
  s_df.print();

}
load_data()
```

这导致以下输出：

![图 4.24 - 随机抽取两行后的浏览器控制台中的数据框](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_24.jpg)

图 4.24 - 随机抽取两行后的浏览器控制台中的数据框

在上述代码中，您会注意到代码被包装在一个`async`函数中。这是因为`sample`方法返回一个 promise，因此我们必须等待结果。上述代码可以在浏览器或 node.js 环境中按原样执行，但是它需要一点调整才能在 Dnotebook 中工作。

如果您想在 Dnotebook 中运行确切的代码，可以像这样调整它：

```js
var sample;
async function load_data() {
  let data = {
    Name: ["Apples", "Mango", "Banana", "Pear"],
    Count: [21, 5, 30, 10],
    Price: [200, 300, 40, 250],
  };

  let df = new dfd.DataFrame(data);
  let s_df = await df.sample(2);
  sample = s_df

}
load_data()
```

在上述代码中，您可以看到我们明确使用`var`定义了`sample`。这使得`sample`变量对所有单元格都可用。在这里改用`let`声明将使变量仅对定义它的单元格可用。

接下来，在一个新的单元格中，您可以使用`table`方法打印样本数据框，如下面的代码所示：

```js
table(sample)
```

这导致以下输出：

![图 4.25 - 在 Dnotebook 中随机抽取两行后的数据框](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_25.jpg)

图 4.25 - 在 Dnotebook 中随机抽取两行后的数据框

在下一节中，我们将简要介绍 Danfo.js 中提供的一些编码特性。

## 编码数据框和系列

**编码**是在应用于 ML 或**统计建模**之前可以应用于数据框/系列的另一个重要转换。这是在将数据馈送到模型之前始终执行的重要数据预处理步骤。

ML 或统计模型只能使用数值，因此所有字符串/分类列必须适当地转换为数值形式。有许多类型的编码，例如**独热编码**，**标签编码**，**均值编码**等，选择编码可能会有所不同，这取决于您拥有的数据类型。

Danfo.js 目前支持两种流行的编码方案：*标签*和*独热编码器*，在接下来的部分中，我们将解释如何使用它们。

### 标签编码器

标签编码器将列中的类别映射到列中唯一类别的整数值之间的值。让我们看一个在数据框上使用这个的例子。

假设我们有以下数据框：

```js
data = { fruits: ['pear', 'mango', "pawpaw", "mango", "bean"] ,
            Count: [20, 30, 89, 12, 30],
            Country: ["NG", "NG", "GH", "RU", "RU"]}
df = new dfd.DataFrame(data)
table(df)
```

打印数据框的结果如下：

![图 4.26 - 编码前的数据框](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_26.jpg)

图 4.26 - 编码前的数据框

现在，让我们使用`LabelEncoder`对`fruits`列进行编码，如下面的代码块所示：

```js
encode = new dfd.LabelEncoder() 
encode.fit(df['fruits']) 
```

在前面的代码块中，您会注意到我们首先创建了一个`LabelEncoder`对象，然后在列（`fruits`）上调用了`fit`方法。`fit`方法简单地学习并存储编码器对象中的映射。稍后可以用它来转换任何列/数组，我们很快就会看到。

调用`fit`方法后，我们必须调用`transform`方法来应用标签，如下面的代码块所示：

```js
sf_enc = encode.transform(df['fruits']) 
table(sf_enc)
```

打印 DataFrame 的结果如下：

![图 4.27 - 标签编码前的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_27.jpg)

图 4.27 - 标签编码前的 DataFrame

从前面的输出中，您可以看到为每个标签分配了唯一的整数。在调用`transform`时，如果列中有一个在`fit`（学习）阶段不可用的新类别，则用值`-1`表示。让我们看一个例子，使用前面示例中的相同编码器：

```js
new_sf = encode.transform(["mango","man", "car", "bean"])
table(new_sf)
```

打印 DataFrame 的结果如下：

![图 4.28 - 应用 transform 后的新类别数组的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_28.jpg)

图 4.28 - 应用 transform 后的新类别数组的 DataFrame

在前面的示例中，您可以看到我们在一个具有新类别（`man`和`car`）的数组上调用了训练过的编码器。请注意，输出中用`-1`代替了这些新类别，正如我们之前解释的那样。

接下来，让我们谈谈独热编码。

### 独热编码

独热编码主要应用于数据集中的有序类别。在这种编码方案中，使用二进制值`0`（热）和`1`（冷）来编码唯一类别。

使用与前一节相同的 DataFrame，让我们创建一个独热编码器对象，并将其应用于`country`列，如下面的代码块所示：

```js
encode = new dfd.OneHotEncoder()  
encode.fit(df['country']) 
sf_enc = encode.transform(df['country']) 
table(sf_enc)
```

打印 DataFrame 的结果如下：

![图 4.29 - 应用独热编码后的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_29.jpg)

图 4.29 - 应用独热编码后的 DataFrame

从前面的输出中，您可以看到对于每个唯一类别，一系列 1 和 0 被用来替换类别，并且现在我们生成了两列额外的列。以下图表直观地展示了每个唯一类别如何映射到独热编码：

![图 4.30 - 三个类别的独热编码映射](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_30.jpg)

图 4.30 - 三个类别的独热编码映射

Danfo.js 中的最后一个可用编码特性是`get_dummies`函数。这个函数的工作方式与独热编码函数相同，但主要区别在于您可以在整个 DataFrame 上应用它，并且它将自动编码找到的任何分类列。

让我们看一个使用`get_dummies`函数的例子。假设我们有以下 DataFrame：

```js
data = { fruits: ['pear', 'mango', "pawpaw", "mango", "bean"] ,
            count: [20, 30, 89, 12, 30],
            country: ["NG", "NG", "GH", "RU", "RU"]}
df = new dfd.DataFrame(data)
table(df)
```

打印 DataFrame 的结果如下：

![图 4.31 - 应用`get_dummies`函数前的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_31.jpg)

图 4.31 - 应用`get_dummies`函数前的 DataFrame

现在，我们可以通过将 DataFrame 传递给`get_dummies`函数一次性编码所有分类列（`fruits`和`country`），如下面的代码块所示：

```js
df_enc = dfd.get_dummies({data: df})
table(df_enc)
```

打印 DataFrame 的结果如下：

![图 4.32 - 三个类别的独热编码映射](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_32.jpg)

图 4.32 - 三个类别的独热编码映射

从前面的图中，您可以看到`get_dummies`函数自动检测到了`fruits`和`country`分类变量，并对它们进行了独热编码。列是自动生成的，它们的名称以相应的列和类别开头。

注意

您可以指定要编码的列，以及为每个编码列命名前缀。要了解更多可用选项，请参考官方 Danfo.js 文档：[`danfo.jsdata.org/`](https://danfo.jsdata.org/)。

在下一节中，我们将看看组合数据集的各种方法。

# 组合数据集

数据框和序列可以使用 Danfo.js 中的内置函数进行组合。存在诸如`danfo.merge`和`danfo.concat`之类的方法，根据配置的不同，可以帮助您使用熟悉的类似数据库的连接方式以不同形式组合数据集。

在本节中，我们将简要讨论这些连接类型，从`merge`函数开始。

## 数据框合并

`merge`操作类似于数据库中的`Join`操作，它在对象中执行列或索引的连接操作。`merge`操作的签名如下：

```js
danfo.merge({left, right, on, how}) 
```

让我们了解每个参数的含义：

+   `left`：要合并到左侧的数据框/序列。

+   `right`：要合并到右侧的数据框/序列。

+   `on`：要连接的列的名称。这些列必须在左侧和右侧的数据框中都找到。

+   `how`：`how`参数指定如何执行合并。它类似于数据库风格的连接，可以是`left`、`right`、`outer`或`inner`。

Danfo.js 的`merge`函数与 pandas 的`merge`函数非常相似，因为它执行类似于关系数据库连接的内存中连接操作。以下表格提供了 Danfo 的合并方法和 SQL 连接的比较：

![图 4.33 – 比较 Danfo.js 合并方法和 SQL 连接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_33.jpg)

图 4.33 – 比较 Danfo.js 合并方法和 SQL 连接（来源：pandas 文档：https://pandas.pydata.org/pandas-docs/stable/user_guide/merging.html#brief-primer-on-merge-methods-relational-algebra）

在接下来的几节中，我们将提供一些示例，帮助您了解何时以及如何使用`merge`函数。

### 通过单个键进行内部合并

在单个共同键上合并数据框默认会导致内连接。内连接要求两个数据框具有匹配的列值，并返回两者的交集；也就是说，它返回一个只包含具有共同特征的行的数据框。

假设我们有两个数据框，如下所示：

```js
data = [['K0', 'k0', 'A0', 'B0'], ['k0', 'K1', 'A1', 'B1'],
            ['K1', 'K0', 'A2', 'B2'], ['K2', 'K2', 'A3', 'B3']]
data2 = [['K0', 'k0', 'C0', 'D0'], ['K1', 'K0', 'C1', 'D1'],
            ['K1', 'K0', 'C2', 'D2'], ['K2', 'K0', 'C3', 'D3']]
colum1 = ['Key1', 'Key2', 'A', 'B']
colum2 = ['Key1', 'Key2', 'A', 'D']

df1 = new dfd.DataFrame(data, { columns: colum1 })
df2 = new dfd.DataFrame(data2, { columns: colum2 })
table(df1)
```

打印第一个数据框的结果如下：

![图 4.34 – 执行合并操作的第一个数据框](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_34.jpg)

图 4.34 – 执行合并操作的第一个数据框

现在我们将打印第二个数据框，如下所示：

```js
table(df2)
```

这将导致以下输出：

![图 4.35 – 执行合并操作的第二个数据框](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_35.jpg)

图 4.35 – 执行合并操作的第二个数据框

接下来，我们将执行内连接，如下面的代码所示：

```js
merge_df = dfd.merge({left: df1, right: df2, on: ["Key1"]})
table(merge_df)
```

打印数据框的结果如下：

![图 4.36 – 在单个键上对两个数据框进行内部合并](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_36.jpg)

图 4.36 – 在单个键上对两个数据框进行内部合并

从前面的输出中，您可以看到在`Key1`上的内连接导致了一个包含来自数据框 1 和数据框 2 的所有值的数据框。这也被称为两个数据框的**笛卡尔积**。

我们可以进一步合并多个键。我们将在下一节中讨论这个问题。

### 在两个键上进行内部合并

在两个键上执行内部合并还将返回两个数据框的交集，但它只会返回在数据框的左侧和右侧都找到的键的行。

使用我们之前创建的相同数据框，我们可以在两个键上执行内部连接，如下所示：

```js
merge_mult_df = dfd.merge({left: df1, right: df2, on: ["Key1", "Key2"]})
table(merge_mult_df)
```

打印数据框的结果如下：

![图 4.37 – 在两个键上进行内部合并](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_37.jpg)

图 4.37 – 在两个键上进行内部合并

从前面的输出中，您可以看到在两个键上执行内部合并会导致一个只包含在数据框的左侧和右侧中都存在的键的数据框。

### 通过单个键进行外部合并

外部合并，正如我们在前面的表中所看到的，执行两个数据框的并集。也就是说，它返回在两个数据框中都存在的键的值。在单个键上执行外部连接将返回与在单个键上执行内部连接相同的结果。

使用前面的相同数据框，我们可以指定`how`参数来将合并行为从其默认的`inner`连接更改为`outer`，如下面的代码所示：

```js
merge_df = dfd.merge({ left: df1, right: df2, on: ["Key1"], how: "outer"})
table(merge_df)
```

打印数据框的结果如下：

![图 4.38 - 两个数据框在单个键上的外部合并](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_38.jpg)

图 4.38 - 两个数据框在单个键上的外部合并

从前面的图表中，您可以看到具有键（`K0`，`K0`，`K1`，`K2`）的第一个数据框和具有键（`K0`，`K1`，`K1`，`K2`）的第二个数据框的并集是（`K0`，`K0`，`K1`，`K1`，`K2`）。然后使用这些键来对数据框进行并集操作。在这样做之后，我们收到了前面表格中显示的结果。

我们还可以在两个键上执行外部连接。这将与在两个键上执行内部连接不同，正如我们将在以下子节中看到的。

### 在两个键上的外部合并

仍然使用前面的相同数据框，我们可以添加第二个键，如下面的代码所示：

```js
merge_df = dfd.merge({ left: df1, right: df2, on: ["Key1", "Key2"], how: "outer"})
table(merge_df)
```

打印数据框的结果如下：

![图 4.39 - 两个数据框在两个键上的外部合并](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_39.jpg)

图 4.39 - 两个数据框在两个键上的外部合并

在前面的输出中，我们可以看到返回的行始终具有`Key1`和`Key2`中的键。如果第一个数据框中存在的键不在第二个数据框中，则值始终填充为`NaN`。

注意

在 Danfo.js 中进行合并不支持一次在两个以上的键上进行合并。这可能会在将来发生变化，因此，如果您需要支持这样的功能，请务必查看官方 Danfo.js GitHub 存储库的*讨论*部分（[`github.com/opensource9ja/danfojs`](https://github.com/opensource9ja/danfojs)）。

在接下来的几节中，我们将简要介绍左连接和右连接，这在执行合并时也很重要。

### 右连接和左连接

右连接和左连接非常简单；它们只返回具有指定`how`参数中存在的键的行。例如，假设我们将`how`参数指定为`right`，如下面的代码所示：

```js
merge_df = dfd.merge({ left: df1, right: df2, on: ["Key1", "Key2"], how: "right"})
table(merge_df)
```

打印数据框的结果如下：

![图 4.40 - 两个数据框在两个键上的右连接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_40.jpg)

图 4.40 - 两个数据框在两个键上的右连接

结果图表仅显示了右侧数据框中存在的键的行。这意味着在执行合并时，右侧数据框被赋予了更高的优先级。

如果我们将`how`设置为`left`，那么左侧数据框将更偏好，并且我们只会看到键存在于左侧数据框中的行。下面的代码显示了执行`left`连接的示例：

```js
merge_df = dfd.merge({ left: df1, right: df2, on: ["Key1", "Key2"], how: "left"})
table(merge_df)
```

打印数据框的结果如下：

![图 4.41 - 两个数据框在两个键上的左连接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_41.jpg)

图 4.41 - 两个数据框在两个键上的左连接

从前面的输出中，我们可以确认结果行更偏向于左侧数据框。

Danfo.js 的`merge`函数非常强大和有用，在开始使用具有重叠键的多个数据集时会派上用场。在下一节中，我们将介绍另一个有用的函数，称为**连接**，用于转换数据集。

## 数据连接

连接数据是另一种重要的数据组合技术，正如其名称所示，这基本上是沿着一个轴连接、堆叠或排列数据。

在 Danfo.js 中用于连接数据的函数被公开为`danfo.concat`，该函数的签名如下：

```js
danfo.concat({df_list, axis}) 
```

让我们了解每个参数代表什么：

+   `df_list`：`df_list`参数是要连接的 DataFrames 或 Series 的数组。

+   `axis`：`axis`参数可以接受行（0）或列（1），并指定对象将对齐的轴。

接下来，我们将介绍一些示例，这些示例将帮助您了解如何使用`concat`函数。首先，我们将学习如何沿行轴连接三个 DataFrames。

### 沿行轴（0）连接 DataFrames

首先，让我们创建三个 DataFrames，如下面的代码所示：

```js
df1 = new dfd.DataFrame( 
    { 
           "A": ["A_0", "A_1", "A_2", "A_3"], 
           "B": ["B_0", "B_1", "B_2", "B_3"], 
           "C": ["C_0", "C_1", "C_2", "C_3"] 
        },
        index=[0, 1, 2], 
  ) 
df2 = new dfd.DataFrame( 
       { 
          "A": ["A_4", "A_5", "A_6", "A_7"], 
          "B": ["B_4", "B_5", "B_6", "B_7"], 
          "C": ["C_4", "C_5", "C_6", "C_7"], 
       }, 
       index=[4, 5, 6], 
    ) 
df3 = new dfd.DataFrame( 
    { 
          "A": ["A_8", "A_9", "A_10", "A_11"], 
           "B": ["B_8", "B_9", "B_10", "B_11"], 
           "C": ["C_8", "C_9", "C_10", "C_11"]
       }, 
       index=[8, 9, 10], 
   )
table(df1)
table(df2)
table(df3)
```

使用 Node.js 和浏览器中的`print`函数或 Dnotebook 中的`table`函数打印每个 DataFrame，将给我们以下输出。

`df1` DataFrame 的输出如下：

![图 4.42 - 要连接的第一个 DataFrame（df1）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_42.jpg)

图 4.42 - 要连接的第一个 DataFrame（df1）

`df2` DataFrame 的输出如下：

![图 4.43 - 要连接的第二个 DataFrame（df2）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_43.jpg)

图 4.43 - 要连接的第二个 DataFrame（df2）

最后，`df3` DataFrame 的输出如下：

![图 4.44 - 要连接的第三个 DataFrame（df3）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_44.jpg)

图 4.44 - 要连接的第三个 DataFrame（df3）

现在，让我们使用`concat`函数组合这些 DataFrames，如下面的代码所示：

```js
df_frames = [df1, df2, df3]
combined_df = dfd.concat({df_list: df_frames, axis: 0})
table(combined_df)
```

这导致以下输出：

![图 4.45 - 沿行轴（0）连接三个 DataFrames 的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_45.jpg)

图 4.45 - 沿行轴（0）连接三个 DataFrames 的结果

在这里，您可以看到`concat`函数简单地沿列轴组合每个 DataFrame（`df1`，`df2`，`df3`）；也就是说，它们在`df_list`中第一个 DataFrame 的下方堆叠，以创建一个巨大的组合。

此外，索引看起来不同。这是因为在内部，Danfo.js 为组合生成了新的索引。如果您需要数字索引，那么可以使用`reset_index`函数，如下面的代码所示：

```js
combined_df.reset_index(true)
table(combined_df)
```

这导致以下输出：

![图 4.46 - 重置组合 DataFrames 的索引](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_46.jpg)

图 4.46 - 重置组合 DataFrames 的索引

现在，使用相同的 DataFrames 进行沿列轴的连接会是什么样子？我们将在下一节中尝试这个。

### 沿列轴（1）连接 DataFrames

使用我们之前创建的相同 DataFrames，只需在`concat`代码中将`axis`更改为`1`，如下面的代码所示：

```js
df_frames = [df1, df2, df3]
combined_df = dfd.concat({df_list: df_frames, axis: 1})
table(combined_df)
```

打印 DataFrame 的结果如下：

![图 4.47 - 沿列轴（0）应用 concat 到三个 DataFrames 的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_47.jpg)

图 4.47 - 沿列轴（0）应用 concat 到三个 DataFrames 的结果

连接也适用于 Series 对象。我们将在下一节中看一个例子。

### 沿指定轴连接 Series

Series 也是 Danfo.js 数据结构，因此`concat`函数也可以在它们上面使用。这与连接 DataFrames 的方式相同，我们很快将进行演示。

使用上一节的 DataFrames，我们将创建一些 Series 对象，如下面的代码所示：

```js
series_list = [df1['A'], df2['B'], df3['D']]
```

请注意，我们正在使用 DataFrame 子集来从 DataFrames 中抓取不同的列作为 Series。现在，我们可以将这些 Series 组合成一个数组，然后将其传递给`concat`函数，如下面的代码所示：

```js
series_list = [df1['A'], df2['B'], df3['D']]
combined_series = dfd.concat({df_list: series_list, axis: 1})
table(combined_series)
```

打印 DataFrame 的结果如下：

![图 4.48 - 沿行轴（0）应用 concat 到三个 Series 的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_48.jpg)

图 4.48 - 沿行轴（0）应用 concat 到三个 Series 的结果

将轴更改为行（0）也可以工作，并返回一个有很多缺失条目的 DataFrame，如下图所示：

![图 4.49 - 沿列轴（1）应用 concat 到三个 Series 的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_49.jpg)

图 4.49 - 沿列轴（1）应用 concat 到三个 Series 的结果

现在，您可能想知道为什么在生成的组合中有很多缺失的字段。这是因为当对象沿指定轴组合时，有时对象的位置/长度与第一个 DataFrame 不对齐。使用`NaN`进行填充以返回一致的长度。

在本小节中，我们介绍了两个重要的函数（`merge`和`concat`），它们可以帮助您对 DataFrame 或 Series 执行复杂的组合。在下一节中，我们将讨论另一种不同但同样重要的内容，即**字符串/文本操作**。

# Series 数据访问器

Danfo.js 在各种访问器下提供了特定于数据类型的方法。**访问器**是 Series 对象内的命名空间，只能应用/调用特定数据类型。目前为字符串和日期时间 Series 提供了两个访问器，在本节中，我们将讨论每个访问器并提供一些示例以便理解。

### 字符串访问器

DataFrame 中的字符串列或具有`dtype`字符串的 Series 可以在`str`访问器下访问。在这样的对象上调用`str`访问器会暴露出许多用于操作数据的字符串函数。我们将在本节中提供一些示例。

假设我们有一个包含以下字段的 Series：

```js
data = ['lower boy', 'capitals', 'sentence', 'swApCaSe']
sf = new dfd.Series(data)
table(sf)
```

打印此 Series 的结果如下图所示：

![图 4.50 - 沿列轴（1）将三个 Series 应用 concat 的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_50.jpg)

图 4.50 - 沿列轴（1）将三个 Series 应用 concat 的结果

从前面的输出中，我们可以看到 Series（`sf`）包含文本，并且是字符串类型。您可以使用`dtype`函数来确认这一点，如下面的代码所示：

```js
console.log(sf.dtype)
```

输出如下：

```js
string
```

现在我们有了我们的 Series，它是字符串数据类型，我们可以在其上调用`str`访问器，并使用各种 JavaScript 字符串方法，如`capitalize`、`split`、`len`、`join`、`trim`、`substring`、`slice`、`replace`等，如下例所示。

以下代码将`capitalize`函数应用于 Series：

```js
mod_sf = sf.str.capitalize() 
table(mod_sf)
```

打印此 Series 的结果如下：

![图 4.51 - 将 capitalize 应用于字符串 Series 的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_51.jpg)

图 4.51 - 将 capitalize 函数应用于字符串 Series 的结果

以下代码将`substring`函数应用于 Series：

```js
mod_sf = sf.str.substring(0,3) //returns a substring by start and end index
table(mod_sf)
```

打印此 Series 的结果如下：

![图 4.52 - 将 substring 函数应用于字符串 Series 的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_52.jpg)

图 4.52 - 将 substring 函数应用于字符串 Series 的结果

以下代码将`replace`函数应用于 Series：

```js
mod_sf = sf.str.replace("lower", "002") //replaces a string with specified value
table(mod_sf)
```

打印此 Series 的结果如下：

![图 4.53 - 将 replace 函数应用于字符串 Series 的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_53.jpg)

图 4.53 - 将 replace 函数应用于字符串 Series 的结果

以下代码将`join`函数应用于 Series：

```js
mod_sf = sf.str.join("7777", "+") // joins specified value to Series
table(mod_sf)
```

打印此 Series 的结果如下图所示：

![图 4.54 - 将 join 函数应用于字符串 Series 的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_54.jpg)

图 4.54 - 将 join 函数应用于字符串 Series 的结果

以下代码将`indexOf`函数应用于 Series：

```js
mod_sf = sf.str.indexOf("r") //Returns the index where the value is found else -1
table(mod_sf)
```

打印此 Series 的结果如下：

![图 4.55 - 将 indexOf 函数应用于字符串 Series 的结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_55.jpg)

图 4.55 - 将 indexOf 函数应用于字符串 Series 的结果

注意

`str`访问器提供了许多公开的字符串方法。您可以在 Danfo.js 文档中的完整列表中查看（[`danfo.jsdata.org/api-reference/series#string-handling`](https://danfo.jsdata.org/api-reference/series#string-handling)）。

### 日期时间访问器

Danfo.js 在系列对象上公开的第二个访问器是日期时间访问器。这可以在`dt`命名空间下访问。从日期时间列中处理和提取不同的信息，如日期、月份和年份，是进行数据转换时的常见过程，因为日期时间的原始格式几乎没有用处。

如果您的数据有一个日期时间列，则可以在其上调用`dt`访问器，这将公开各种函数，可用于提取信息，如年份、月份、月份名称、星期几、小时、秒和一天中的分钟数。

让我们看一些在具有日期列的系列上使用`dt`访问器的示例。首先，我们将创建一个具有一些日期时间字段的系列：

```js
timeColumn = ['12/13/2016 15:00:20', '10/20/2019 18:30:00', '1/1/2020 12:00:00', '1/30/2020 16:20:00', '11/12/2019 22:00:30'] 
sf = new dfd.Series(timeColumn, {columns: ["times"]})
table(sf)
```

打印此系列的结果如下：

![图 4.56 - 具有日期时间字段的系列](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_56.jpg)

图 4.56 - 具有日期时间字段的系列

现在我们有了一个具有日期字段的系列，我们可以提取一些信息，例如一天中的小时数、年份、月份或星期几。我们需要做的第一件事是使用`dt`访问器将系列转换为 Danfo.js 的日期时间格式，如下面的代码所示：

```js
dateTime = sf['times'].dt  
```

`dateTime`变量现在公开了不同的方法来提取日期信息。利用这一点，我们可以做以下任何一项：

+   获取一天中的小时作为新系列：

```js
dateTime = sf.dt 
hours = dateTime.hour()
table(hours)
```

这给我们以下输出：

![图 4.57 - 显示提取的一天中的小时的新系列](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_57.jpg)

图 4.57 - 显示提取的一天中的小时的新系列

+   获取年份作为新系列：

```js
dateTime = sf.dt 
years = dateTime.year()
table(years)
```

这给我们以下输出：

![图 4.58 - 显示提取的年份的新系列](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_58.jpg)

图 4.58 - 显示提取的年份的新系列

+   获取月份作为新系列：

```js
dateTime = sf.dt 
month_name = dateTime.month_name()
table(month_name)
```

这给我们以下输出：

![图 4.59 - 显示提取的月份名称的新系列](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_59.jpg)

图 4.59 - 显示提取的月份名称的新系列

+   获取星期几作为新系列：

```js
dateTime = sf.dt  
weekdays = dateTime.weekdays() 
table(weekdays)
```

这给我们以下输出：

![图 4.60 - 显示提取的星期几的新系列](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_60.jpg)

图 4.60 - 显示提取的星期几的新系列

`dt`访问器公开的一些其他函数如下：

+   `Series.dt.month`：这将返回一个整数月份，从 1（一月）到 12（十二月）。

+   `Series.dt.day`：这将返回一周中的天数作为整数，从 0（星期一）到 6（星期日）。

+   `Series.dt.minutes`：这将返回一天中的分钟数作为整数。

+   `Series.dt.seconds`：这将返回一天中的秒数作为整数。

恭喜您完成了本节！数据转换和聚合是数据分析的非常重要的方面。有了这些知识，您可以正确地转换和整理数据集。

在下一节中，我们将向您展示如何使用 Danfo.js 对数据集进行描述性统计。

# 计算统计数据

Danfo.js 带有一些重要的统计和数学函数。这些函数可以用于生成整个数据框或单个系列的摘要或描述性统计。在数据集中，统计数据很重要，因为它们可以为我们提供更好的数据洞察。

在接下来的几节中，我们将使用流行的泰坦尼克号数据集，您可以从以下 GitHub 存储库下载：[`github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/blob/main/Chapter03/data/titanic.csv`](https://github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/blob/main/Chapter03/data/titanic.csv)。

首先，让我们使用`read_csv`函数将数据集加载到 Dnotebook 中，如下面的代码所示：

```js
var df //using var so df is available to all cells
load_csv("https://raw.githubusercontent.com/plotly/datasets/master/finance-charts-apple.csv")
.then((data)=>{
  df = data
})
```

上述代码从指定的 URL 加载泰坦尼克号数据集，并将其保留在`df`变量中。

注意

我们在这里使用`load_csv`和`var`声明，因为我们在 Dnotebook 中工作。正如我们一直提到的，你不会在浏览器或 Node.js 脚本中使用这种方法。

现在，在一个新的单元格中，我们可以打印加载数据集的头部：

```js
table(df.head())
```

打印 DataFrame 的结果如下：

![图 4.61 - 泰坦尼克号数据集的前五行](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_61.jpg)

图 4.61 - 泰坦尼克号数据集的前五行

我们可以对整个数据调用`describe`函数，快速获取所有列的描述统计信息，如下面的代码所示：

```js
table(df.describe())
```

打印 DataFrame 的结果如下：

![图 4.62 - 在泰坦尼克号数据集上使用 describe 函数的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_62.jpg)

图 4.62 - 在泰坦尼克号数据集上使用 describe 函数的输出

在上面的代码中，我们调用了`describe`函数，然后用`table`打印了输出。`describe`函数只适用于数值数据类型，并且默认情况下只会自动选择`float32`或`int32`类型的列。

注意

默认情况下，在进行计算之前，所有的统计和数学计算都会删除`NaN`值。

`describe`函数提供了以下内容的描述性统计信息：

+   `NaN`值。

+   **均值**：一列中的平均值。

+   **标准差**（**std**）：一组值的变化或离散程度的度量。

+   **最小值**（**min**）：一列中的最小值。

+   **中位数**：一列中的中间值。

+   **最大值**（**max**）：一列中的最大值。

+   **方差**：值从平均值的传播程度的度量。

## 按轴计算统计信息

`describe`函数虽然快速且易于应用，但在需要沿特定轴计算统计信息时并不是很有帮助。在本节中，我们将介绍一些最流行的方法，并向您展示如何根据指定的轴计算统计信息。

可以在指定轴上对 DataFrame 调用诸如均值、众数和中位数等中心趋势。这里，轴`0`代表`行`，而轴`1`代表`列`。

在下面的代码中，我们正在计算泰坦尼克号数据集中数值列的均值、众数和中位数：

```js
df_nums = df.select_dtypes(['float32', "int32"]) //select all numeric dtype columns
console.log(df_nums.columns)
[AAPL.Open,AAPL.High,AAPL.Low,AAPL.Close,AAPL.Volume,AAPL.Adjusted,dn,mavg,up]
```

在上面的代码中，我们选择了所有的数值列，以便可以应用数学运算。接下来，我们将调用`mean`函数，默认情况下返回列轴（`1`）上的均值：

```js
col_mean = df_nums.mean()
table(col_mean)
```

打印 DataFrame 的结果如下：

![图 4.63 - 在数值列上调用均值函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_63.png)

图 4.63 - 在数值列上调用均值函数

前面输出中显示的精度看起来有点太长了。我们可以将结果四舍五入到两位小数，使其更具可呈现性，如下面的代码所示：

```js
col_mean = df_nums.mean().round(2)
table(col_mean)
```

打印 DataFrame 的结果如下：

![图 4.64 - 在数值列上调用均值函数并将值四舍五入到两位小数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_64.jpg)

图 4.64 - 在数值列上调用均值函数并将值四舍五入到两位小数

将结果四舍五入到两位小数后，输出看起来更清晰。接下来，让我们计算沿着行轴的`mean`：

```js
row_mean = df_nums.mean(axis=0)
table(row_mean)
```

这给我们以下输出：

![图 4.65 - 在行轴上调用均值函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_4_65.jpg)

图 4.65 - 在行轴上调用均值函数

在上面的输出中，您可以看到返回的值具有数值标签。这是因为行轴最初具有数值标签。

使用相同的思路，我们可以计算众数、中位数、标准差、方差、累积和、累积均值、绝对值等统计信息。以下是 Danfo.js 当前可用的统计函数：

+   `abs`：返回每个元素的绝对数值的 Series/DataFrame。

+   `count`：计算每列或每行的单元格数，不包括`NaN`值。

+   `cummax`：返回 DataFrame 或 Series 的累积最大值。

+   `cummin`：返回 DataFrame 或 Series 的累积最小值。

+   `cumprod`：返回 DataFrame 或 Series 的累积乘积。

+   `cumsum`：返回 DataFrame 或 Series 的累积和。

+   `describe`：生成描述性统计。

+   `max`：返回所请求轴的最大值。

+   `mean`：返回所请求轴的平均值。

+   `median`：返回所请求轴的中位数。

+   `min`：返回所请求轴的最小值。

+   `mode`：返回沿所选轴的元素的众数。

+   `sum`：返回所请求轴的值的总和。

+   `std`：返回所请求轴的标准偏差。

+   `var`：返回所请求轴的无偏方差。

+   `nunique`：计算所请求轴上的不同元素的数量。

注意

支持的函数列表可能会发生变化，并且会添加新的函数。因此，最好通过查看[`danfo.jsdata.org/api-reference/dataframe#computations-descriptive-stats`](https://danfo.jsdata.org/api-reference/dataframe#computations-descriptive-stats)来跟踪新的函数。

描述性统计非常重要，在本节中，我们成功介绍了一些重要的函数，这些函数可以帮助您在 Danfo.js 中有效地基于指定轴计算统计数据。

# 摘要

在本章中，我们成功介绍了 Danfo.js 中可用的数据转换和整理函数。首先，我们向您介绍了用于替换值、填充缺失值和检测缺失值的各种整理函数，以及应用和映射方法，用于将自定义函数应用于数据集。掌握这些函数和技术可以确保您具有构建数据驱动产品所需的基础，以及从数据中获取见解的能力。

接下来，我们向您展示了如何在 Danfo.js 中使用各种合并和连接函数。最后，我们向您展示了如何对数据集进行描述性统计。

在下一章中，我们将进一步介绍如何使用 Danfo.js 的内置绘图功能以及集成第三方绘图库来制作美丽而惊人的图表/图形。
