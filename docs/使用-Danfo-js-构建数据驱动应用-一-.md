# 使用 Danfo.js 构建数据驱动应用（一）

> 原文：[`zh.annas-archive.org/md5/074CFA285BE35C0386726A8DBACE1A4F`](https://zh.annas-archive.org/md5/074CFA285BE35C0386726A8DBACE1A4F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

大多数数据分析师使用 Python 和 pandas 进行数据处理和操作，这得益于这些库提供的便利性和性能。然而，JavaScript 开发人员一直希望浏览器中也能实现**机器学习**（**ML**）。本书重点介绍了 Danfo.js 如何将数据处理、分析和 ML 工具带给 JavaScript 开发人员，以及如何充分利用这个库来开发数据驱动的应用程序。

本书从 JavaScript 概念和现代 JavaScript 的介绍开始。然后，您将使用 Danfo.js 和 Dnotebook 进行数据分析和转换，这是 JavaScript 的交互式计算环境。之后，本书涵盖了如何加载不同类型的数据集，并通过执行操作（如处理缺失值、合并数据集和字符串操作）来分析它们。您还将专注于数据绘图、可视化、数据聚合和组合操作，通过将 Danfo.js 与 Plotly 结合使用。随后，您将使用 Danfo.js 创建一个无代码数据分析和处理系统。然后，您将介绍基本的 ML 概念，以及如何使用 Tensorflow.js 和 Danfo.js 构建推荐系统。最后，您将使用 Danfo.js 构建由 Twitter 驱动的分析仪表板。

通过本书，您将能够在服务器端 Node.js 或浏览器中构建和嵌入数据分析、可视化和 ML 功能的 JavaScript 应用程序。

# 这本书是为谁准备的

本书适用于数据科学初学者、数据分析师和希望使用各种数据集探索数据分析和科学计算的 JavaScript 开发人员。如果您是数据分析师、数据科学家或 JavaScript 开发人员，并希望在 ML 工作流程中实现 Danfo.js，您也会发现本书很有用。对 JavaScript 编程语言、数据科学和 ML 的基本理解将有助于您理解本书涵盖的关键概念；然而，本书的第一章和附录中提供了 JavaScript 的入门部分。

# 本书涵盖的内容

第一章，现代 JavaScript 概述，讨论了 ECMA 6 语法和`import`语句、类方法、`extend`方法和构造函数的使用。它还深入解释了`Promise`方法的使用，`async`和`await`函数的使用，以及`fetch`方法。它还介绍了如何建立支持现代 JavaScript 语法的环境，以及适当的版本控制，以及如何编写单元测试。

第二章，Dnotebook-用于 JavaScript 的交互式计算环境，深入探讨了 Dnotebook。对于来自 Python 生态系统的读者来说，这类似于 Jupyter Notebook。我们讨论了如何使用 Dnotebook，如何创建和删除单元格，如何在其中编写 Markdown，以及如何保存和共享您的笔记本。

第三章，使用 Danfo.js 入门，介绍了 Danfo.js 以及如何创建数据框架和系列。它还介绍了一些数据分析和处理的基本方法。

第四章，数据分析、整理和转换，探讨了 Danfo.js 在实际数据集中的实际应用。在这里，您将学习如何加载不同类型的数据集，并通过执行操作（如处理缺失值、计算描述性统计、执行数学运算、合并数据集和字符串操作）来分析它们。

第五章，使用 Plotly.js 进行数据可视化，介绍了数据绘图和可视化。在这里，您将学习数据可视化和绘图的基础知识，以及如何使用 Plotly.js 进行基本绘图。

*第六章**，使用 Danfo.js 进行数据可视化*，介绍了使用 Danfo.js 进行数据绘图和可视化。在这里，您将学习如何在 DataFrame 或 series 上直接使用 Danfo.js 创建图表。您还将学习如何自定义 Danfo.js 图表。

*第七章**，数据聚合和分组操作*，介绍了分组操作以及如何使用 Danfo.js 执行这些操作，包括如何按一个或多个列进行分组，如何使用提供的分组-聚合函数，以及如何使用`.apply`创建自定义聚合函数。我们还展示了分组操作的内部工作原理。

*第八章**，创建无代码数据分析/处理系统*，展示了 Danfo.js 可以让我们做什么。在本章中，我们将创建一个无代码数据处理和分析环境，用户可以在其中上传他们的数据，然后进行艺术化的分析和处理。

*第九章**，机器学习基础*，以简单的术语介绍了机器学习。它还向您展示了如何在浏览器中借助一些 ML JavaScript 工具进行机器学习。

*第十章**，TensorFlow.js 简介*，介绍了 TensorFlow.js。它还展示了如何执行基本的数学运算以及如何创建、训练、保存和重新加载 ML 模型。本章还展示了如何有效地集成 Danfo.js 和 Tensorflow.js 来训练模型。

*第十一章**，使用 Danfo.js 和 TensorFlow.js 构建推荐系统*，向您展示了如何使用 TensorFlow.js 和 Danfo.js 构建电影推荐系统。它向您展示了如何在 Node.js 中训练模型以及如何将其与客户端集成。它还展示了 Danfo.js 如何使数据预处理变得简单。

*第十二章**，构建 Twitter 分析仪表盘*，您将在此构建一个使用 Danfo.js 作为前端和后端的 Twitter 分析仪表盘；目标是展示在数据分析应用中使用同一库的简易性，相比于例如在后端使用 Python 和在前端使用 JavaScript。

*第十三章**，附录：JavaScript 基本概念*，介绍了 JavaScript 编程语言。在这里，我们向初学者介绍了变量定义、函数创建以及在 JavaScript 中执行计算的不同方式。

# 充分利用本书

在本书中，您需要对 JavaScript 有基本的了解，并且了解 Next.js、React.js、TensorFlow.js 和 tailwindcss 等框架将是一个优势。

![](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_Preface_Table_RK.jpg)

**如果您使用的是本书的数字版本，我们建议您自己输入代码或从书的 GitHub 存储库中访问代码（链接在下一节中提供）。这样做将帮助您避免与复制和粘贴代码相关的任何潜在错误。**

# 下载示例代码文件

您可以从 GitHub 上下载本书的示例代码文件，链接为[`github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js`](https://github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js)。如果代码有更新，将在 GitHub 存储库中进行更新。

我们还提供了来自我们丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快去看看吧！

# 下载彩色图片

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图和图表的彩色图片。您可以在这里下载：[`static.packt-cdn.com/downloads/9781801070850_ColorImages.pdf`](https://static.packt-cdn.com/downloads/9781801070850_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`文本中的代码`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如："在`financial_df` DataFrame 的情况下，当我们使用`read_csv`函数下载数据集时，索引是自动生成的。"

代码块设置如下：

```js
const df = new DataFrame({...})
df.plot("my_div_id").<chart type>
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目以粗体显示：

```js
…        
var config = {
            displayModeBar: true,
            modeBarButtonsToAdd: [
…
```

任何命令行输入或输出都以以下方式编写：

```js
npm install @tensorflow/tfjs
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词以**粗体**显示。例如："在 Microsoft Edge 中，打开浏览器窗口右上角的 Edge 菜单，然后选择**F12 开发人员工具**。"

提示或重要说明

像这样。


# 第一部分：基础知识

本节介绍了 JavaScript 和 Node.js 框架。这些概念是为了充分理解和使用 Danfo.js 而需要的。它还介绍了如何使用 Babel 和 Node.js 设置现代 JavaScript 环境，还教读者一些代码测试的基础知识。

本节包括以下章节：

+   *第一章**，现代 JavaScript 概述*


# 第二章：现代 JavaScript 概述

在这一章中，我们将讨论一些核心的 JavaScript 概念。如果你是 JavaScript 的新手，需要介绍的话，请查看*第十三章*，*附录*：*基本 JavaScript 概念*。

理解一些现代 JavaScript 概念并不是使用 Danfo.js 的先决条件，但是如果您是 JavaScript 的新手或者来自 Python 背景，我们建议您阅读本章，原因是在使用 Danfo.js 构建应用程序时，我们将使用这里介绍的大部分概念。另外，值得一提的是，这里介绍的许多概念通常会帮助您编写更好的 JavaScript。

本章将向您介绍一些现代 JavaScript 概念，到最后，您将学习并理解以下概念：

+   理解`let`和`var`之间的区别

+   解构

+   展开语法

+   作用域和闭包概述

+   理解数组和对象方法

+   理解 this 属性

+   箭头函数

+   Promises 和 async/await

+   面向对象编程和 JavaScript 类

+   使用转译器设置现代 JavaScript 环境

+   使用 Mocha 和 Chai 进行单元测试

# 技术要求

主要要求是已安装 Node.js 和 NPM。您可以按照官方安装指南在[`nodejs.org/en/download/`](https://nodejs.org/en/download/)上安装适用于您操作系统的 Node。本章的代码可以在 GitHub 仓库中找到：[`github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter01`](https://github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter01)。

我们将从理解`let`和`var`之间的区别开始，以及为什么您应该更频繁地使用`let`。

# 理解`let`和`var`之间的区别

在 ECMA 6 之前，创建变量的常见方式是使用`var`。然而，使用`var`有时会引入在运行时出现的错误，以及在运行时未显现但可能影响代码运行方式的错误。

如前段提到的，`var`的一些属性会引入错误，如下所示：

+   `var`允许变量的重新声明。

+   `var`不是块级作用域；因此，它要么附加到全局作用域，要么附加到函数作用域。

让我们详细讨论上面列出的两个属性。

## var 允许变量的重新声明

`var`允许用户在代码中重新声明变量，因此覆盖了之前同名的变量。如果没有被捕获，这个特性可能不会显示错误，但肯定会影响代码的行为：

```js
var population_count = 490; 
var new_count = 10; 

//along the line; you mistakenly re-declare the variable 
var population_count = "490"

//do some arithmetic operation with the variable 
var total_count = population_count + new_count 

//output: "49010" 
```

在前面的代码片段中，不会出现任何错误，但是代码的主要目标会因为`var`没有警告我们已经声明了这样一个变量而被改变。

假设我们用`let`替换`var`，如下所示：

```js
let population_count = 490;
// ...some other code goes here 
let population_count = "490"

//output: Error: Identifier population count as already being declared 
```

从前面的错误输出中可以看出，`let`与`var`不同，不允许在同一命名空间中声明变量两次。

接下来，让我们看看使用`var`声明的变量的作用域属性。

## var 不是块级作用域

使用`var`声明的变量具有以下属性：

+   它们在定义的作用域内是立即可用的。

+   它们在被声明的作用域内是可用的。

在下面的代码中，我们将检查使用`var`声明的`estimate`变量在变量声明作用域内的所有作用域中都是可访问的：

```js
var estimate = 6000;
function calculate_estimate() {
  console.log(estimate);
}
calculate_estimate() // output 6000

if(true){
 console.log(estimate);
}
```

现在，对于像`if`、`while`循环和`for`循环这样的块级作用域，块级作用域内的代码应该在作用域可用时运行。同样，变量应该只在作用域可用时存在，一旦作用域再次不可用，变量就不应该被访问。

使用`var`声明变量会使前面的语句不可能。在下面的代码中，我们使用`var`声明一个变量，并调查其在所有可能的作用域中的可用性：

```js
if(true){
 var estimate = 6000;
}
console.log(estimate)
```

这将输出估计值为`6000`。该变量不应存在于`if`块之外。使用`let`有助于解决这个问题：

```js
if(true){
 let estimate = 6000;
}
console.log(estimate)
//output: ReferenceError: estimate is not defined
```

这表明使用`let`声明变量有助于减少代码中的意外错误。在下一节中，我们将讨论另一个重要概念，称为解构。

# 解构

`20`，`John`，`Doe`和`2019`分配到指定的变量中：

```js
let data2 = [20, "John", "Doe", "2019"];
let [ age1, firstName1, lastName1, year1] = data2
```

解构使得可以将数组的元素分配给一个变量，而不是像在下面的代码中所示的旧的常规方法访问数组元素：

```js
//Old method of accessing an array
let data = [20, "John", "Doe", "2019"];

let firstName = data[1];
let age = data[0];
let lastName = data[2];
let year = data[3];
```

解构也适用于对象，就像在下面的代码中所示的那样：

```js
let data3 = {
    age: 20,
    firstName: "john",
    lastName: "Doe",
    year: 2019
}
let { age2, firstName2, lastName2, year2 } = data3
```

在对象解构中，请注意我们使用`{}`而不是`[]`，就像用于数组的一样。这是因为左侧的类型必须与右侧的类型相同。

重要提示

如果我们在解构对象时使用`[]`，我们会收到一个错误，显示`{}`。对于数组解构，你可能不会得到任何错误，但变量将是未定义的。

在接下来的部分，我们将看一下展开语法。

# 展开语法

**展开语法**是可迭代元素的另一种解构形式，例如字符串和数组。展开语法可以在涉及数组和对象的许多情况下使用。在本节中，我们将快速查看展开语法的一些用例。

## 将可展开的可迭代对象展开或解包到数组中。

可迭代对象可以展开/解包成数组。在下面的示例中，我们将展示如何使用展开运算符来解包字符串变量：

```js
let name = "stephen"
let name_array = [...name];
```

该代码将`name`字符串展开为`name_array`，因此，`name_array`将具有以下值：[`'s'，'t'，'e'，'p'，'h'，'e'，'n'`]。

在将字符串元素展开为数组的同时，我们可以添加其他值，就像在下面的代码中所示的那样：

```js
let name = "stephen"
let name_array = [...name, 1,2,3]
console.log(name_array)
// output ['s', 't', 'e','p', 'h', 'e','n',1,2,3]
```

请记住，任何可迭代对象都可以展开成数组。这表明我们也可以展开一个数组到另一个数组中，就像在下面的代码中演示的那样：

```js
let series = [1,2,3,4,5,6,7,8]
let new_array = [...series, 100, 200]
console.log(new_array)
// output [1, 2, 3, 4, 5,6, 7, 8, 100, 200]
```

接下来，我们将把展开运算符应用到对象上。

## 从现有对象创建新对象

从现有对象创建新对象遵循与**展开**运算符相同的模式：

```js
Let data = {
  age: 20,
  firstName: "john",
  lastName: "Doe",
  year:  2019
}
let  new_data = {...data}
```

这将创建一个具有与前一个对象相同属性的新对象。在将前一个对象展开为新对象时，可以同时添加新属性：

```js
let data = {
    age: 20,
    firstName: "john",
    lastName: "Doe",
    year: 2019
}

let new_data = { ...data, degree: "Bsc", level: "expert" }
console.log(new_data)
//output 
// {
//     age: 20,
//     Degree: "Bsc",
//     FirstName: "John",
//     lastName: "Doe",
//     Level: "expert",
//     Year: 2019
// }
```

## 函数参数

对于需要许多参数的函数，展开语法可以帮助一次性传递许多参数到函数中，从而减少逐个填充函数参数的压力。

在下面的代码中，我们将看到如何将参数数组传递给函数：

```js
function data_func(age, firstName, lastName, year) {
    console.log(`Age: ${age}, FirstName: ${firstName}, LastName: ${lastName}, Year: ${year}`);
}
let data = [30, "John", "Neumann", '1948']
data_func(...data)
//output Age: 30, FirstName: John, LastName: Neumann, Year: 1984
Age: 30, FirstName: John, LastName: Neumann, Year: 1984
```

在前面的代码中，首先，我们创建了一个名为`data_func`的函数，并定义了要传递的一组参数。然后我们创建了一个包含要传递给`data_func`的参数列表的数组。

通过使用展开语法，我们能够传递数据数组并将数组中的每个值分配为参数值–`data_func(...data)`。每当一个函数需要许多参数时，这将变得非常方便。

在下一节中，我们将看一下作用域和闭包，以及如何使用它们更好地理解您的 JavaScript 代码。

# 作用域和闭包概述

在*理解 let 和 var 之间的区别*部分，我们讨论了作用域，并谈到了`var`在全局作用域和函数作用域中都可用。在本节中，我们将更深入地了解作用域和闭包。

## 作用域

为了理解作用域，让我们从下面的代码开始：

```js
let food = "sandwich" 
function data() {
}
```

`food`变量和`data`函数都分配给了全局作用域；因此，它们被称为**全局变量**和**全局函数**。这些全局变量和函数始终对 JavaScript 文件中的每个其他作用域和程序都是可访问的。

本地范围可以进一步分为以下几类：

+   **函数范围**

+   **块范围**

函数范围仅在函数内部可用。也就是说，在函数范围内创建的所有变量和函数在函数外部是不可访问的，并且只有在函数范围可用时才存在，例如：

```js
function func_scope(){
// function scope exist here
}
```

块范围仅存在于特定上下文中。例如，它可以存在于花括号`{ }`内，以及`if`语句、`for`循环和`while`循环中。下面的代码片段中还提供了另外两个例子：

```js
if(true){
// if block scope
}
```

在前面的`if`语句中，您可以看到块范围仅存在于花括号内部，并且在`if`语句内声明的所有变量都是局部变量。另一个例子是`for`循环，如下面的代码片段所示：

```js
for(let i=0; i< 5; i++){
//for loop's block scope
}
```

块范围还存在于`for...`循环的花括号内。在这里，您可以访问`i`计数器，并且无法在块外部访问内部声明的任何变量。

接下来，让我们了解闭包的概念。

## 闭包

**闭包**利用了函数内部作用域的概念。请记住，我们同意在函数范围内声明的变量在函数范围外部是不可访问的。闭包使我们能够利用这些私有属性（或变量）。

假设我们想创建一个程序，该程序将始终将值`2`和`1`添加到表示人口估计的`estimate`变量中。可以使用以下代码的一种方法：

```js
let estimate = 6000;
function add_1() {
    return estimate + 1
}
function add_2() {
    return estimate + 2;
}
console.log(add_1()) // 60001 
console.log(add_2()) // 60002
```

前面的代码没有问题，但是随着代码库变得非常庞大，我们可能会迷失`estimate`值，也许在某个时候需要一个函数来更新该值，并且我们可能还希望通过将全局`estimate`变量设置为局部变量来清理全局范围。

因此，我们可以创建一个函数范围来为我们执行此操作，并最终清理全局范围。以下是下面代码片段中的一个示例：

```js
function calc_estimate(value) { 
  let estimate = value; 
  function add_2() { 
    console.log('add two', estimate + 2); 
  } 
  function add_1() { 
    console.log('add one', estimate + 1) 
  } 
  add_2(); 
  add_1(); 
}
calc_estimate(6000) //output: add two 60002 , add one 60001
```

前面的代码片段与我们定义的第一个代码片段类似，只是有一个小差异，即函数接受`estimate`值，然后在`calc_estimate`函数内部创建`add_2`和`add_1`函数。

使用前面的代码更好地展示闭包的一种方法是能够在任何时候更新估计值，而不是在调用函数的实例中。让我们看一个例子：

```js
function calc_estimate(value) { 
  let estimate = value; 
  function add_2() { 
    estimate += 2 
    console.log('add 2 to estimate', estimate); 
  } 
  return add_2; 
}
let add_2 = calc_estimate(50);
// we have the choice to add two to the value at any time in our code 
add_2() // add 2 to estimate 52 
add_2() // add 2 to estimate 54 
add_2() // add 2 to estimate 56
```

在前面的代码片段中，内部函数`add_2`将值`2`添加到`estimate`变量中，从而改变了值。调用`calc_estimate`并将其分配给变量`add_2`。因此，每当我们调用`add_2`时，我们都会将估计值更新为`2`。

我们更新`calc_estimate`内部的`add_2`函数，以接受一个值，该值可用于更新`estimate`值：

```js
function calc_estimate(value){ 
  let estimate = value; 
  function add_2(value2){ 
    estimate +=value2 
    console.log('add 2 to estimate', estimate); 
  } 
  return add_2; 
}
let add_2 = calc_estimate(50);
// we have the choice to add two to the value at any time in our code

add_2(2) // add 2 to estimate 52
add_2(4) // add 2 to estimate 56
add_2(1) // add 2 to estimate 5
```

现在您已经了解了作用域和闭包，我们将在下一节中讨论数组、对象和字符串方法。

进一步阅读

要更详细地了解闭包，请查看*Ved Antani*的书《精通 JavaScript》。

# 理解数组和对象方法

**数组**和**对象**是 JavaScript 中最重要的两种数据类型。因此，我们专门设置了一个部分来讨论它们的一些方法。我们将从数组方法开始。

## 数组方法

我们无法讨论如何构建数据驱动的产品而不讨论数组方法。了解不同的数组方法使我们能够访问我们的数据并创建工具来操作/处理我们的数据。

数组可以以两种不同的形式创建：

```js
let data = []
// or
let data = new Array()
```

`[ ]`方法主要用于初始化数组，而`new Array()`方法主要用于创建大小为*n*的空数组，如下面的代码片段所示：

```js
let data = new Array(5)
console.log(data.length) // 5 
console.log(data) //  [empty × 5]
```

创建的空数组可以稍后用值填充，如下面的代码所示：

```js
data[0] = "20"
data[1] = "John"
data[2] = "Doe"
data[3] = "1948"
console.log(data) // ["20", "John","Doe","1948", empty] 
// try access index 4  
console.log(data[4]) //  undefined
```

创建这样一个空数组不仅限于使用`new Array()`方法。它也可以使用`[ ]`方法创建，如下面的代码片段所示：

```js
let data = [] 
data.length = 5; // create an empty array of size 5
console.log(data)  // [empty × 5]
```

您可以看到我们在创建后明确设置了长度，因此`new Array()`方法更方便。

现在让我们看一些常见的数组方法，这些方法将用于构建一些数据驱动的工具。

### Array.splice

删除和更新数组值始终是数据驱动产品中的基本操作之一。JavaScript 有一个`delete`关键字，用于删除数组中特定索引处的值。该方法实际上并不删除值，而是用空值或 undefined 值替换它，如下面的代码所示：

```js
let data = [1,2,3,4,5,6];
delete data[4];
console.log(data) // [1,2,3,4 empty, 6]
```

在`data`变量中，如果我们尝试访问索引`4`处的值，我们会发现它返回`undefined`：

```js
console.log(data[4]) // undefined
```

但是，每当我们使用`splice`删除数组中的一个值时，数组的索引会重新排列，如下面的代码片段所示：

```js
let data = [1,2,3,4,5,6]
data.splice(4,1) // delete index 4
console.log(data) // [1,2,3,4,6]
```

`Array.splice`接受以下参数，`start,[deleteCount, value-1,......N-values]`。在前面的代码片段中，由于我们只是删除，所以我们使用了`start`和`deleteCount`。

`data.splice(4,1)`命令删除从索引`4`开始的值，只有一个计数，因此它删除了索引`5`处的值。

如果我们将`data.splice(4,1)`中的值`1`替换为`2`，结果为`data.splice(4,2)`，将从索引`4`开始删除`data`数组中的两个值（`5`和`6`），如下面的代码块所示：

```js
let data = [1,2,3,4,5,6]
data.splice(4,0,10,20) // add values between 5 and 6
console.log(data) // [1,2,3,4,5,10,20,6]
```

`data.splice(4,0,10, 20);`指定从索引`4`开始，`0`指定不删除任何值，同时在`5`和`6`之间添加新值（`10`和`20`）。

### Array.includes

这种方法用于检查数组是否包含特定值。我们在下面的代码片段中展示了一个例子：

```js
let data = [1,2,3,4,5,6]
data.includes(6) // true
```

### Array.slice

`Array.slice`用于通过指定范围获取数组元素；`Array.slice(start-index, end-index)`。让我们在下面的代码中看一个使用这种方法的例子：

```js
let data = [1,2,3,4,5,6]
data.slice(2,4) 
//output [3,4]
```

前面的代码从索引`2`（具有元素`3`）开始提取元素，直到索引`5`。请注意，数组没有输出`[3,4,5]`，而是[`3,4]`。`Array.splice`总是排除结束索引值，因此它使用一个闭区间。

### Array.map

`Array.map`方法遍历数组的所有元素，对每次迭代应用一些操作，然后将结果作为数组返回。下面的代码片段是一个例子：

```js
let data = [1,2,3,4,5,6]
let data2 = data.map((value, index)=>{
return value + index;
});
console.log(data2) // [1,3,5,7,9,11]
```

`data2`变量是通过使用`map`方法迭代每个数据元素创建的。在`map`方法中，我们将数组的每个元素（值）添加到其索引中。

### Array.filter

`Array.filter`方法用于过滤数组中的一些元素。让我们看看它的运行方式：

```js
let data = [1,2,3,4,5,6]
let data2 = data.filter((elem, index)=>{
return (index %2 == 0)
})
console.log(data2) // [1,3,5]
```

在前面的代码片段中，使用`2`的模数（%）过滤掉了数据中每个偶数索引的数组元素。

有很多数组方法，但我们只涵盖了这些方法，因为它们在数据处理过程中总是很方便，我们无法覆盖所有方法。

但是，如果在本书的后续章节中使用了任何新方法，我们肯定会提供解释。在下一节中，我们将讨论对象方法。

## 对象

**对象**是 JavaScript 中最强大和重要的数据类型，在本节中，我们将介绍一些重要的对象属性和方法，使得与它们一起工作更容易。

### 访问对象元素

访问对象中的键/值很重要，因此存在一个特殊的`for...in`循环来执行这个操作：

```js
for (key in object) {
  // run some action with keys
}
```

`for...in`循环返回对象中的所有键，这可以用于访问对象值，如下面的代码所示：

```js
let user_profile = { 
  name: 'Mary', 
  sex: 'Female', 
  age: 25, 
  img_link: 'https://some-image-link.png', 
}
for (key in user_profile) {
    console.log(key, user_profile[key]);
}
//output:
// name Mary
// sex Female
// age 25
// img_link https://some-image-link.png
```

在下一节中，我们将展示如何测试属性的存在。

### 测试属性是否存在

要检查属性是否存在，可以使用`"key"` `in`对象语法，如下面的代码片段所示：

```js
let user_profile = { 
  name: 'Mary', 
  sex: 'Female', 
  age: 25, 
  img_link: 'https://some-image-link.png', 
}
console.log("age" in user_profile)
//outputs: true 

if ("rank" in user_profile) {
    console.log("Your rank is", user_profile.rank)
} else {
    console.log("rank is not a key")
}
//outputs: rank is not a key
```

### 删除属性

在对象属性之前使用`delete`关键字将从对象中删除指定的属性。看看下面的例子：

```js
let user_profile = {
    name: 'Mary',
    sex: 'Female',
    age: 25,
    img_link: 'https://some-image-link.png',
}
delete user_profile.age
console.log(user_profile)
//output:
// {
//     img_link: "https://some-image-link.png",
//     name: "Mary",
//     sex: "Female"
// }
```

您可以看到`age`属性已经成功地从`user_profile`对象中删除。接下来，让我们看看如何复制和克隆对象。

### 复制和克隆对象

将旧对象分配给新对象只是创建对旧对象的引用。也就是说，对新对象的任何修改也会影响旧对象。例如，在下面的例子中，我们将`user_profile`对象分配给一个新变量`new_user_profile`，然后删除`age`属性：

```js
let user_profile = {
    name: 'Mary',
    sex: 'Female',
    age: 25,
    img_link: 'https://some-image-link.png',
}
let new_user_profile = user_profile
delete new_user_profile.age

console.log("new_user_profile", new_user_profile)
console.log("user_profile", user_profile)
//output:
// "new_user_profile" Object {
//     img_link: "https://some-image-link.png",
//     name: "Mary",
//     sex: "Female"
// }

// "user_profile" Object {
//     img_link: "https://some-image-link.png",
//     name: "Mary",
//     sex: "Female"
// }
```

您会注意到从`user_profile`对象中删除`age`属性也会从`new_user_profile`中删除。这是因为复制只是对旧对象的引用。

为了将对象复制/克隆为新的独立对象，您可以使用`Object.assign`方法，如下面的代码所示：

```js
let new_user_profile = {}
Object.assign(new_user_profile, user_profile)

delete new_user_profile.age

console.log("new_user_profile", new_user_profile)
console.log("user_profile", user_profile)

//output
"new_user_profile" Object {
  img_link: "https://some-image-lik.png",
  name: "Mary",
  sex: "Female"
}
"user_profile" Object {
  age: 25,
  img_link: "https://some-image-lik.png",
  name: "Mary",
  sex: "Female"
}
```

`Object.assign`方法也可以用于一次从多个对象中复制属性。我们在下面的代码片段中提供了一个示例：

```js
let user_profile = {
  name: 'Mary',
  sex: 'Female',
  age: 25,
  img_link: 'https://some-image-lik.png',
}
let education = { graduated: true, degree: 'BSc' }
let permissions = { isAdmin: true }

Object.assign(user_profile, education, permissions);
console.log(user_profile)
//output:
// {
//     name: 'Mary',
//     sex: 'Female',
//     img_link: 'https://some-image-link.png',
//     graduated: true,
//     degree: 'BSc',
//     isAdmin: true
//   }
```

您可以看到我们能够从两个对象（`education`和`permissions`）中复制属性到我们的原始对象`user_profile`中。通过这种方式，我们可以通过简单列出所有对象来调用`Object.assign`方法，将任意数量的对象复制到另一个对象中。

提示

您还可以使用**spread**运算符执行深拷贝。这实际上更快，更容易编写，如下面的示例所示：

`let user_profile = {`

`name: 'Mary',`

`sex: 'Female'`

`}`

`let education = { graduated: true, degree: 'BSc' }`

`let permissions = { isAdmin: true }`

`const allObjects = {...user_profile, ...education, ...permissions}`

```js
allObjects. This syntax is easier and quicker than the object.assign method and is largely used today.
```

在下一节中，我们将讨论与 JavaScript 对象相关的另一个重要概念，称为**this**属性。

# 理解 this 属性

**this**关键字是一个对象属性。当在函数内部使用时，它以函数在调用时绑定的对象的形式出现。

在每个 JavaScript 环境中，我们都有一个全局对象。在 Node.js 中，全局对象被命名为**global**，在浏览器中，全局对象被命名为**window**。

所谓的全局对象是指所有变量声明和函数都表示为这个全局对象的属性和方法。例如，在浏览器脚本文件中，我们可以访问全局对象，如下面的代码片段所示：

```js
name = "Dale"
function print() {
    console.log("global")
}
// using the browser as our environment 
console.log(window.name) // Dale 
window.print() // global
```

在前面的代码块中，`name`变量和`print`函数是在全局范围声明的，因此它们可以作为**window**全局对象的属性（`window.name`）和方法（`window.print()`）来访问。

前面一句话中的陈述可以总结为全局名称和函数默认绑定（或分配）到全局对象 window。

这也意味着我们可以将这个变量绑定到任何具有相同`name`变量和相同函数`print`的对象上。

为了理解这个概念，首先让我们将`window.print()`重写为`print.call(window)`。这种新的方法在 JavaScript 中被称为 de-sugaring；它就像看到一个方法的实现形式一样。

`.call`方法只是简单地接受我们想要绑定函数调用的对象。

让我们看看`print.call()`和这个属性是如何工作的。我们将重写`print`函数以访问`name`变量，如下面的代码片段所示：

```js
name  = "Dale"
object_name = "window"
function print(){
  console.log(`${this.name} is accessed from      ${this.object_name}`) 
}
console.log(print.call(window)) // Dale is accessed from window
```

现在，让我们创建一个自定义对象，并且给它与`window`对象相同的属性，如下面的代码片段所示：

```js

let custom_object = {
name: Dale,
Object_name: "custom_object"
}

print.call(custom_object) // Dale is accessed from custom_object
```

这个概念可以应用于所有的对象方法，如下面的代码所示：

```js
data = {
            name: 'Dale',
            obj_name: 'data',
            print: function () {
                console.log(`${this.name} is accessed from ${this.obj_name}`);
            }
        }
data.print() // Dale is accessed from data 
// don't forget we can also call print like this 
data.print.call(data) // Dale is accessed from data
```

有了这个，我们也可以将`data`中的`print()`方法绑定到另一个对象，如下面的代码片段所示：

```js
let data2 = {
 name: "Dale D"
 Object_name: "data2"
}
data.print.call(data2) // Dale D is accessed from data2
```

这种方法展示了 this 属性如何依赖于函数调用时的运行时。这个概念也影响了 JavaScript 中一些事件操作的工作方式。

进一步阅读

为了更深入地理解这个概念，*Emberjs 和 TC39 成员*之一 Yehuda Katz 在他的文章*理解 JavaScript 函数调用和 "this"*中对此进行了更详细的阐述。

# 箭头函数

箭头函数只是未命名或匿名函数。**箭头**函数的一般语法如下所示：

```js
( args ) => { // function body }
```

箭头函数提供了一种创建简洁可调用函数的方法。这意味着箭头函数不可构造，也就是说，它们不能用 `new` 关键字实例化。

以下是如何以及何时使用箭头函数的不同方式：

+   箭头函数可以赋值给一个变量：

```js
const unnamed = (x) => {
console.log(x)
}
unnamed(10) //  10
```

+   箭头函数可以用作**IIFE**（**立即调用函数表达式**）。IIFE 是一旦被 JavaScript 编译器遇到就立即调用的函数：

```js
((x) => { 
    console.log(x) 
})("unnamed function as IIFE") // output: unnamed function as IIFE
```

+   箭头函数可以用作回调：

```js
function processed(arg, callback) {
    let x = arg * 2;
    return callback(x);
}
processed(2, (x) => {
    console.log(x + 2)
});   // output:  6
```

虽然箭头函数在某些情况下很棒，但使用它们也有缺点。例如，箭头函数没有自己的 `this` 作用域，因此它的作用域始终绑定到一般作用域，从而改变了我们对函数调用的整体理念。

在*理解 this 属性*部分，我们谈到了函数如何绑定到它们的调用范围，并使用这种能力来支持**闭包**，但使用箭头函数默认情况下会剥夺我们这个特性：

```js
const Obj = {
     name: "just an object",
     func: function(){
          console.log(this.name);
     }
}
Obj.func() // just an object
```

即使在对象中，如代码片段所示，我们使用了匿名函数（但不是箭头函数），我们仍然可以访问对象的 `Obj` 属性：

```js
const Obj = {
     name: "just an object",
     func:  () => {
          console.log(this.name);
     }
}
Obj.func() // undefined
```

使用的箭头函数使 `Obj.func` 的输出为 `undefined`。让我们看看如果全局作用域中有一个名为 `name` 的变量时它是如何工作的：

```js
let name = "in the global scope"
const Obj = {
     name: "just an object",
     func:  () => {
          console.log(this.name);
     }
}

Obj.func() // in the global 
```

正如我们所看到的，`Obj.func` 调用了全局作用域中的变量。因此，我们必须知道何时何地使用箭头函数。

在下一节中，我们将讨论 Promise 和 async/await 概念。这将使我们能够轻松管理长时间运行的任务，并避免回调地狱（回调中有回调）。

# Promise 和 async/await

让我们深入一下异步函数的世界，现在调用但稍后完成的函数。在本节中，我们将看到为什么我们需要**Promise**和**async/await**。

让我们从下面的代码片段中显示的一个简单问题开始。我们需要使用一个函数在调用函数后的 `1` 秒后更新一个数组：

```js
let syncarray = ["1", "2", "3", "4", "5"]
function addB() {
    setTimeout(() => {
        syncarray.forEach((value, index)=>{
            syncarray[index] = value + "+B"
        })
        console.log("done running")
    }, 1000)
}
addB()
console.log(syncarray);
// output 
// ["1", "2", "3", "4", "5"]
// "done running"
```

`console.log(syncarray)` 在 `addB()` 函数之前执行，因此我们在更新之前看到了 `syncarray` 的输出。这是一种异步行为。解决这个问题的一种方法是使用回调：

```js
let syncarray = ["1", "2", "3", "4", "5"]
function addB(callback) {
    setTimeout(() => {
        syncarray.forEach((value, index)=>{
            syncarray[index] = value + "+B"
        })
        callback() //call the callback function here
    }, 1000)
}
addB(()=>{
  // here we can do anything with the updated syncarray 
  console.log(syncarray);  
})
// output 
// [ '1+B', '2+B', '2+B', '4+B', '5+B' ]
```

使用前面的回调方法意味着我们总是传递回调以执行对更新后的 `syncarray` 函数的其他操作。让我们稍微更新一下代码，这次我们还将字符串 `"A"` 添加到 `syncarray` 中，然后打印出更新后的数组：

```js
let syncarray = ["1", "2", "3", "4", "5"]
function addB(callback) {
    setTimeout(() => {
        syncarray.forEach((value, index) => {
            syncarray[index] = value + "+B"
        })
        callback() //call the callback function here
    }, 1000)
}
addB(() => {
    setTimeout(() => {
        syncarray.forEach((value, index) => {
            syncarray[index] = value + "+A";
        })
        console.log(syncarray);
    }, 1000)
})
// output
// [ '1+B+A', '2+B+A', '3+B+A', '4+B+A', '5+B+A' ]
```

前面的代码块显示了传递 `callback` 的快速方法。根据我们讨论的箭头函数，通过创建一个命名函数可以使代码更有组织性。

## 使用 Promise 清理回调

使用回调很快变得难以控制，并且很快就会陷入回调地狱。摆脱这种情况的一种方法是使用 Promise。Promise 使我们的回调更有组织性。它提供了一种可链接的机制，用于统一和编排依赖于先前函数的代码，正如你将在下面的代码块中看到的：

```js
let syncarray = ["1", "2", "3", "4", "5"]
function addA(callback) {
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            syncarray.forEach((value, index) => {
                syncarray[index] = value + "+A";
            })
            resolve()
        }, 1000);
    })
}
addA().then(() => console.log(syncarray)); 
//output
//[ '1+A', '2+A', '2+A', '4+A', '5+A' ]
```

在前面的代码片段中，`setTimeout` 被包裹在 `Promise` 函数中。使用以下表达式始终实例化 `Promise`：

```js
New Promise((resolve, rejection) => {
})
```

`Promise` 要么被解决，要么被拒绝。当它被解决时，我们可以做其他事情，当它被拒绝时，我们需要处理错误。

例如，让我们确保以下的 `Promise` 被拒绝：

```js
let syncarray = ["1", "2", "3", "4", "5"]
function addA(callback) {
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            syncarray.forEach((value, index) => {
                syncarray[index] = value + "+A";
            })
            let error = true;
            if (error) {
                reject("just testing promise rejection")
            }
        }, 1000);
    })
}
addA().catch(e => console.log(e)) // just testing promise rejection
```

每当我们有多个 Promise 时，我们可以使用 `.then()` 方法来处理每一个：

```js
addA.then(doB)
     .then(doC)
     .then(doD)
     .then(doF)
     .catch(e= > console.log(e));
```

使用多个`.then()`方法来处理多个 promise 可能会很快变得难以控制。为了防止这种情况，我们可以使用`Promise.all()`、`Promise.any()`和`Promise.race()`等方法。

`Promise.all()`方法接受一个要执行的 promise 数组，并且只有当所有 promise 都被实现时才会解析。在下面的代码片段中，我们向我们之前的示例中添加了另一个异步函数，并使用`Promise.all()`来处理它们：

```js
let syncarray = ["1", "2", "2", "4", "5"]
function addA() {
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            syncarray.forEach((value, index) => {
                syncarray[index] = value + "+A";
            })
            resolve()
        }, 1000);
    })
}
function addB() {
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            syncarray.forEach((value, index) => {
                syncarray[index] = value + "+B";
            })
            resolve()
        }, 2000);
    })
}
Promise.all([addA(), addB()])
.then(() => console.log(syncarray)); // [ '1+A+B', '2+A+B', '2+A+B', '4+A+B', '5+A+B' ]
```

在前面的部分输出中，您可以看到每个异步函数按添加顺序执行，并且最终结果是这两个函数对`syncarray`变量的影响。

另一方面，`promise.race`方法将在数组中的任何 promise 被解析或拒绝时立即返回。您可以将其视为一场比赛，其中每个 promise 都试图首先解析或拒绝，一旦发生这种情况，比赛就结束了。要查看深入的解释以及代码示例，您可以访问 MDN 文档：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/any`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/any)。

最后，`promise.any`方法将返回第一个实现的 promise，而不管其他被拒绝的`promise`函数。如果所有 promise 都被拒绝，那么`Promise.any`通过为所有 promise 提供错误来拒绝 promise。要查看深入的解释以及代码示例，您可以访问 MDN 文档：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/race`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Promise/race)。

虽然使用 promise 来处理回调解决了很多问题，但实现或使用它们的更好方法是**async/await**函数。我们将在下一节介绍这些函数，并向您展示如何使用它们。

## async/await

正如前面所说，async/await 提供了一种更优雅的处理 promise 的方式。它赋予我们控制在函数内部如何以及何时调用每个 promise 函数的能力，而不是使用`.then()`和`Promise.all()`。

以下代码片段显示了如何在代码中使用 async/await：

```js
Async function anyName() {
    await anyPromiseFunction()
         await anyPromiseFunction()
}
```

前面的`async`函数可以包含尽可能多的 promise 函数，每个函数在执行之前都在等待其他函数执行。此外，注意`async`函数被解析为`Promise`。也就是说，您只能使用`.then()`或在另一个`async`/`await`函数中调用它来获取前面`anyName`函数的返回变量（或解析函数）：

```js
Async function someFunction() {
    await anyPromiseFunction()
         await anotherPromiseFunction()
    return "done"
}
// To get the returned value, we can use .then()
anyName().then(value => console.log(value)) // "done"
// we can also call the function inside another Async/await function
Async function resolveAnyName() {
   const result = await anyName()
   console.log(result)
}
resolveAnyName() // "done"
```

有了这个知识，我们可以重新编写前一节中的 promise 执行，而不是使用`Promise.all([addA(), addB()])`：

```js
let syncarray = ["1", "2", "2", "4", "5"] 
function addA(callback) {
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            syncarray.forEach((value, index) => {
                syncarray[index] = value + "+A";
            })
            resolve()
        }, 1000);
    })
}
function addB(callback) {
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            syncarray.forEach((value, index) => {
                syncarray[index] = value + "+B";
            })
            resolve()
        }, 2000);
    })
}
Async function runPromises(){ 
    await addA() 
    await  addB() 
    console.log(syncarray); 
  } 
runPromises() 
//output: [ '1+A+B', '2+A+B', '2+A+B', '4+A+B', '5+A+B' ]
```

您可以从前面的输出中看到，我们与使用`Promise.all`语法时得到了相同的输出，但采用了更简洁和清晰的方法。

注意

使用多个 await 而不是`promise.all`的一个缺点是效率。尽管很小，但`promise.all`是处理多个独立 promise 的首选和推荐方式。

Stack Overflow 上的这个主题（[`stackoverflow.com/questions/45285129/any-difference-between-await-promise-all-and-multiple-await`](https://stackoverflow.com/questions/45285129/any-difference-between-await-promise-all-and-multiple-await)）清楚地解释了为什么这是处理多个 promise 的推荐方式。

在下一节中，我们将讨论 JavaScript 中的**面向对象编程**（**OOP**）以及如何使用 ES6 类。

# 面向对象编程和 JavaScript 类

OOP 是大多数高级语言支持的常见编程范式。在 OOP 中，您通常使用对象的概念来编写应用程序，这些对象可以是数据和代码的组合。

数据表示对象的信息，而代码表示可以在对象上执行的属性、属性和行为。

面向对象编程打开了一个全新的可能性世界，因为许多问题可以被模拟或设计为不同对象之间的交互，从而更容易设计复杂的程序，并且更易于维护和扩展它们。

JavaScript，像其他高级语言一样，提供了对面向对象编程概念的支持，尽管不是完全的（[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Classes`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Classes)），但实质上，大多数重要的面向对象编程概念，如**对象**、**类**和**继承**都得到了支持，这些概念大多足以解决使用面向对象编程建模的许多问题。在接下来的部分，我们将简要介绍类以及它们与 JavaScript 中的面向对象编程的关系。

## 类

面向对象编程中的类就像对象的蓝图。也就是说，它们以一种抽象对象的模板定义，使得可以通过遵循该蓝图创建多个副本。这里的副本官方称为**实例**。因此，实质上，如果我们定义了一个类，那么我们可以轻松地创建该类的多个实例。

在 ECMA 2015 中，使用 ES16 的`class`关键字的`User`对象：

```js
class User {
    constructor(firstName, lastName, email) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
    }
    getFirstName() {
        return this.firstName;
    }
    getLastName() {
        return this.lastName;
    }
    getFullName() {
        return `${this.firstName} ${this.lastName}`;
    }
    getEmail() {
        return this.email;
    }
    setEmail(email) {
        this.email = email;
    }
}
let Person1 = new User("John", "Benjamin", "john@some-email.com")
console.log(Person1.getFullName());
console.log(Person1.getEmail());
// outputs 
// "John Benjamin"
// "john@someemail.com"
```

通过使用`class`关键字，您可以以更清晰的方式将数据（名称和电子邮件）与功能（函数/方法）结合在一起，从而有助于易于维护和理解。

在我们继续之前，让我们更详细地分解类模板，以便更好地理解。

第一行以`class`关键字开头，通常后面跟着一个类名。按照惯例，类名采用驼峰命名法，例如`UserModel`或`DatabaseModel`。

类定义中可以添加一个可选的构造函数。`constructor` 类是一个初始化函数，每次从类创建新实例时都会运行。在这里，通常会添加代码，用特定属性初始化每个实例。例如，在以下代码片段中，我们从`User`类创建两个实例，并使用特定属性进行初始化：

```js
let Person2 = new User("John", "Benjamin", "john@some-email.com")
let Person3 = new User("Hannah", "Joe", "hannah@some-email.com")
console.log(Person2.getFullName());
console.log(Person3.getFullName());
//outputs 
// "John Benjamin"
// "Hannah Montanna"
```

类的下一个重要部分是添加函数。函数充当`class`方法，并通常为类添加特定行为。函数也对从类创建的每个实例都可用。在我们的`User`类中，添加了诸如`getFirstName`、`getLastName`、`getEmail`和`setEmail`等方法，以根据它们的实现执行不同的功能。要在类实例上调用函数，通常使用点表示法，就像访问对象的属性时一样。例如，在以下代码中，我们返回`Person1`实例的全名：

```js
Person1.getFullName()
```

有了类之后，我们现在转向面向对象编程中的下一个概念，称为*继承*。

## 继承

在面向对象编程中，**继承**是一个类使用另一个类的属性/方法的能力。这是一种通过使用另一个类（超类/父类）来扩展一个类（子类/子类）特征的简单方法。这样，子类继承了父类的所有特征，并且可以扩展或更改这些特性。让我们使用一个示例来更好地理解这个概念。

在我们的应用程序中，假设我们已经在上一节中定义了`User`类，但我们想创建一个名为`Teachers`的新用户组。教师也是用户类，他们也将需要基本属性，例如`User`类已经具有的名称和电子邮件。因此，我们可以简单地扩展它，而不是创建一个具有这些现有属性和方法的新类，如下面的代码片段所示：

```js
class Teacher extends User {
}
```

请注意我们使用了`extends`关键字。这个关键字简单地使得父类（`User`）中的所有属性都可以在子类（`Teacher`）中使用。只需基本的设置，`Teacher`类就自动可以访问`User`类的所有属性和方法。例如，我们可以像创建`User`值一样实例化和创建一个新的`Teacher`：

```js
let teacher1 = new Teacher("John", "Benjamin", "john@someemail.com")
console.log(teacher1.getFullName());
//outputs
// "John Benjamin"
```

在扩展一个类之后，我们基本上想要添加新的特性。我们可以通过简单地在子类模板中添加新的函数或属性来实现这一点，就像下面的代码所示：

```js
class Teacher extends User {
  getUserType(){
    return "Teacher"
  }
}
```

在上面的代码片段中，我们添加了一个新的方法`getUserType`，它返回`user`类型的字符串。通过这种方式，我们可以添加更多原本不在`parent`类中的特性。

值得一提的是，你可以通过在`child`类中创建一个同名的新函数来替换`parent`函数。这个过程在`Teacher`类中称为`getFullName`函数，我们可以这样做：

```js
class User {
    constructor(firstName, lastName, email) {
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
    }
    getFirstName() {
        return this.firstName;
    }
    getLastName() {
        return this.lastName;
    }
    getFullName() {
        return `${this.firstName} ${this.lastName}`;
    }
    getEmail() {
        return this.email;
    }
    setEmail(email) {
        this.email = email;
    }
}
class Teacher extends User { 
    getFullName(){ 
      return `Teacher: ${this.firstName} ${this.lastName}`; 
    } 
    getUserType(){ 
      return "Teacher" 
    } 
  } 
let teacher1 = new Teacher("John", "Benjamin", "john@someemail.com") 
console.log(teacher1.getFullName()); 
//output 
// "Teacher: John Benjamin"
```

这里可能会有一个问题：如果我们想要在初始化`Teacher`类时除了`firstname`、`lastname`和`email`之外添加额外的实例，该怎么办？这是可以实现的，我们可以通过使用一个新的关键字`super`轻松扩展构造函数。我们在下面的代码中演示了如何做到这一点：

```js
// class User{
// previous User class goes here
//     ... 
// }

class Teacher extends User {
    constructor(firstName, lastName, email, userType, subject) {
        super(firstName, lastName, email) //calls parent class constructor 
        this.userType = userType
        this.subject = subject
    }
    getFullName() {
        return `Teacher: ${this.firstName} ${this.lastName}`;
    }
    getUserType() {
        return "Teacher"
    }
}
let teacher1 = new Teacher("Johnny", "Benjamin", "john@someemail.com", "Teacher", "Mathematics")
console.log(teacher1.getFullName());
console.log(teacher1.userType);
console.log(teacher1.subject);
//outputs 
// "Teacher: Johnny Benjamin"
// "Teacher"
// "Mathematics"
```

在上面的代码中，我们进行了两件新的事情。首先，我们向`Teacher`类添加了两个新的实例属性（`userType`和`subject`），然后我们调用了`super`函数。`super`函数简单地调用父类（`User`），执行实例化，然后立即初始化`Teacher`类的新属性。

通过这种方式，我们能够在初始化类属性之前先初始化父类属性。

类在面向对象编程中非常有用，JavaScript 中提供的`class`关键字使得使用面向对象编程变得容易。值得一提的是，在幕后，JavaScript 将类模板转换为对象，因为它没有对类的一流支持。这是因为 JavaScript 默认是基于原型的面向对象语言。因此，JavaScript 在幕后调用的类接口被称为底层原型模型上的**语法糖**。你可以在以下链接中阅读更多关于这个问题：[`es6-features.org/#ClassDefinition`](http://es6-features.org/#ClassDefinition)。

现在我们对 JavaScript 中的面向对象编程有了基本的了解，我们可以开始创建易于维护的复杂应用程序。在接下来的部分中，我们将讨论 JavaScript 开发的另一个重要方面，即使用现代 JavaScript 支持设置开发环境。

# 设置一个支持转译器的现代 JavaScript 环境

JavaScript 的一个独特特性，也是它非常受欢迎的原因之一，就是它的跨平台支持。JavaScript 几乎可以在任何地方运行，从浏览器和桌面到甚至服务器端。虽然这是一个独特的特性，但要让 JavaScript 在这些环境中运行得最佳，需要一些设置和配置，使用第三方工具/库。设置工具的另一个原因是，你可以用不同的风格来编写 JavaScript，因为这些现代/新的风格可能不被旧版浏览器支持。这意味着你在新语法中编写的代码，通常是 ES15 之后的语法，需要被转译成 ES16 之前的格式，才能在大多数浏览器中正确运行。

在本节中，你将学习如何设置和配置一个 JavaScript 项目，以支持跨平台和现代 JavaScript 代码。你将使用两个流行的工具——**Babel**和**webpack**来实现这一点。

## Babel

Babel 是一个工具，用于将用 ES15 编写的 JavaScript 代码转换为现代或旧版浏览器中向后兼容的 JavaScript 版本。Babel 可以帮助你做到以下几点：

+   转换/转译语法。

+   填充在目标环境中缺失的功能。Babel 会自动添加一些在旧环境中不可用的现代功能。

+   转换源代码。

在下面的代码中，我们展示了一个经过 Babel 转换的代码片段的示例：

```js
// Babel Input: ES2015 arrow function
["Lion", "Tiger", "Shark"].map((animal) => console.log(animal));

// Babel Output: ES5 equivalent
["Lion", "Tiger", "Shark"].map(function(animal) {
  console.log(animal)
});
```

您会注意到在前面的代码片段中，现代箭头函数会自动转译为所有浏览器都支持的`function`关键字。这就是 Babel 在幕后对您的源代码所做的事情。

接下来，让我们了解 webpack 的作用。

## Webpack

webpack 也是一个转译器，可以执行与 Babel 相同的功能，甚至更多。webpack 可以将几乎任何东西，包括*图像*、*HTML*、*CSS*和*JavaScript*打包和捆绑成一个优化的脚本，可以轻松在浏览器中使用。

在本节中，我们将利用 Babel 和 webpack 来展示如何设置一个跨平台的 JavaScript 项目。让我们马上开始吧。

### 使用 Babel 和 webpack 的示例项目

在本节中，我们将使用`npm`创建一个简单的 JavaScript 项目。因此，您应该在本地安装 Node.js 以便跟随操作。执行以下步骤来实现这一点：

1.  在您喜欢的目录中打开终端，并使用以下命令创建一个文件夹：

```js
cross-env-js, in your directory, and then change the directory as well.
```

1.  创建一个`package.json`文件。虽然您可以手动创建，但使用`npm`创建会更容易。在终端中运行以下命令：

```js
package.json file and accept all default options. Ideally, this should output the following:![Figure 1.1 – Output from running the npm init –y command    ](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_01_01.jpg)Figure 1.1 – Output from running the npm init –y command
```

1.  接下来，安装所有相关的软件包，以帮助我们进行捆绑和转译：

```js
package.json file should look like this:

```

{

"name": "cross-env-js",

"version": "1.0.0",

"description": "",

"main": "index.js",

"scripts": {

"test": "echo \"Error: no test specified\" && exit 1"

},

"keywords": [],

"author": "",

"license": "ISC",

"devDependencies": {

"@babel/cli": "⁷.12.8",

"@babel/core": "⁷.12.9",

"@babel/preset-env": "⁷.12.7"

"babel-loader": "⁸.2.2",

"webpack": "⁵.9.0",

"webpack-cli": "⁴.2.0"

},

"dependencies": {

"@babel/polyfill": "⁷.12.1"

}

}

```js

```

1.  添加一些代码，我们将对其进行转译和测试。对于这一部分，您可以从终端创建文件和文件夹，也可以使用代码编辑器。我将在这里使用 Visual Studio Code 编辑器。

在您的代码编辑器中，打开`cross-env-js`项目文件夹，然后创建以下文件和文件夹：

```js
├── dist
│   └── index.html
├── src
│   ├── index.js
│   ├── utils.js
```

也就是说，您将创建两个名为`dist`和`src`的文件夹。`dist`将包含一个 HTML 文件（`index.html`），用于测试我们的捆绑应用程序，`src`将包含我们想要转译的现代 JavaScript 代码。

创建这些文件和文件夹后，整个目录结构应如下所示：

```js
├── dist
│   └── index.html
├── node_modules
├── package-lock.json
├── package.json
└── src
    ├── index.js
    └── utils.js
```

注意

如果您使用 Git 等版本控制工具，通常会添加一个`.gitignore`文件，指定`node_modules`可以被忽略。

1.  创建一个`dist`文件夹，在该文件夹中创建一个带有以下代码的`index.html`文件：

```js
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="img/bundle.js"></script>
    <title>Cross Environment Support</title>
</head>
<body>

</body>
</html>
```

HTML 文件对您来说应该很熟悉，但请注意我们添加了一个指向`bundle.js`文件的`script`标签。这个文件目前还不存在，将由 webpack 在幕后使用 Babel 生成。

1.  在`src`文件夹中编写一些现代 JavaScript。从`utils.js`开始，我们将创建并导出一些函数，然后导入它们以在`index.js`中使用。

从`utils.js`开始，添加以下代码：

```js
const subjects = {
    John: "English Language",
    Mabel: "Mathematics",
    Mary: "History",
    Joe: "Geography"
}

export const names = ["John", "Mabel", "Mary", "Joe"]
export const getSubject = (name) =>{
    return subjects[name]
}
```

`utils.js`脚本使用一些现代的 JS 语法，比如`export`和箭头函数，这些在转译后只能兼容旧浏览器。

接下来，在`index.js`脚本中，您将导入这些函数并使用它们。将以下代码添加到您的`index.js`脚本中：

```js
import { names, getSubject } from "./utils";
names.forEach((name) =>{
    console.log(`Teacher Name: ${name}, Teacher Subject: ${getSubject(name)}`)
})
```

您会注意到我们还在`index.js`文件中使用箭头函数和解构导入。在这里，我们从`utils.js`脚本中导入了导出的数组（names）和`getSubject`函数。我们还使用箭头函数和模板文字（`` ``）的组合来检索和记录每个`Teacher`的详细信息。

1.  现在我们的现代 JS 文件已经准备好，我们将创建一个配置文件，告诉 webpack 在哪里找到我们的源代码来捆绑，以及使用哪个转译器，就我们的情况而言，是 Babel。

在您的根目录中，创建一个`webpack.config.js`文件，并添加以下代码：

```js
const path = require('path');
module.exports = {
  entry: './src/index.js',
  output: {
    filename: 'bundle.js',
    path: path.resolve(__dirname, 'dist'),
    publicPath: '/dist'
  },
  module: {
    rules: [
      {
        test: /\.js$/,
        exclude: /(node_modules)/,
        use: {
          loader: 'babel-loader',
        }
      }
    ]
  }
};
```

让我们了解一下这个文件中发生了什么：

a) 配置文件的第一部分需要`path`模块，这将有助于解决所有与路径相关的函数。

b) 接下来，您会注意到`entry`字段。这个字段简单地告诉 webpack 在哪里找到起始/主要脚本。webpack 将使用这个文件作为起点，然后递归地遍历每个导入依赖项，以链接与入口文件相关的所有文件。

c) 接下来是`output`字段，它告诉 webpack 在哪里保存捆绑文件。在我们的示例中，我们将捆绑文件保存到`dist`文件夹下的`bundle.js`文件中（请记住我们在 HTML 文件中引用了`bundle.js`）。

d) 最后，在`module`字段中，我们指定要使用 Babel 转译每个脚本，并且排除转译`node_modules`。有了这个 webpack 配置文件，您就可以准备转译和捆绑您的源代码了。

1.  在您的`package.json`文件中，您将添加一个脚本命令，该命令将调用`webpack`，如下面的代码块所示：

```js
{
  ...
  "scripts": {
    "build": "webpack --mode=production",
    "test": "echo \"Error: no test specified\" && exit 1"
  },

  ...
}
```

1.  在您的终端中，运行以下命令：

```js
package.json file, and this, in turn, will ask webpack to bundle your code referencing the config file you created earlier.Following successful compilation, you should have the following output in your terminal:
```

![图 1.2 – webpack 捆绑成功的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_01_02.jpg)

图 1.2 – webpack 捆绑成功的输出

在完成上述步骤后，您可以导航到`dist`文件夹，在那里您将找到一个额外的文件–`bundle.js`。这个文件已经被`index.html`文件引用，因此每当我们在浏览器中加载`index.html`文件时，它将被执行。

要测试这一点，打开默认浏览器中的`index.html`文件。可以通过导航到目录并双击`index.html`文件来完成。

一旦您在浏览器中打开了`index.html`文件，您应该打开开发者控制台，在那里您可以找到您的代码输出，就像下面的截图中一样：

![图 1.3 – 浏览器控制台中的 index.js 输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_01_03.jpg)

图 1.3 – 浏览器控制台中的 index.js 输出

这表明您已成功将现代 JS 代码转译和捆绑成可以在任何浏览器中执行的格式，无论是旧的还是新的。

进一步阅读

捆绑文件可能会很快变得困难和混乱，特别是在项目变得更大时。如果您需要进一步了解如何捆绑文件，您可以参考以下资源：

* 使用 webpack([`webpack.js.org/guides/getting-started/`](https://webpack.js.org/guides/getting-started/))入门

* 使用指南([`babeljs.io/docs/en/usage`](https://babeljs.io/docs/en/usage)) for Babel

* 如何在 Node 和 Express 中启用 ES6（及更高版本）语法([`www.freecodecamp.org/news/how-to-enable-es6-and-beyond-syntax-with-node-and-express-68d3e11fe1ab/`](https://www.freecodecamp.org/news/how-to-enable-es6-and-beyond-syntax-with-node-and-express-68d3e11fe1ab/))

在下一节中，您将学习如何设置测试并在您的 JavaScript 应用程序中进行单元测试。

# 使用 Mocha 和 Chai 进行单元测试

为您的应用程序代码编写测试非常重要，但在大多数书籍中很少谈到。这就是为什么我们决定添加这一部分关于使用 Mocha 进行单元测试。虽然您可能不会为本书中构建的每个示例应用程序编写冗长的测试，但我们将向您展示您需要了解的基础知识，并且您甚至可以在自己的项目中使用它们。

测试，或自动化测试，用于在开发过程中检查我们的代码是否按预期运行。也就是说，函数的编写者通常会预先知道函数的行为，因此可以测试结果与预期结果是否一致。

`it`和`describe`，可用于自动编写和运行测试。Mocha 的美妙之处在于它可以在 node 和浏览器环境中运行。Mocha 还支持与各种断言库的集成，如*Chai* ([`www.chaijs.com/`](https://www.chaijs.com/))，*Expect.js* ([`github.com/LearnBoost/expect.js`](https://github.com/LearnBoost/expect.js))，*Should.js* ([`github.com/shouldjs/should.js`](https://github.com/shouldjs/should.js))，甚至是 Node.js 的内置*assert* ([`nodejs.org/api/assert.html`](https://nodejs.org/api/assert.html))模块。在本书中，我们将使用 Chai 断言库，因为它是 Mocha 中最常用的断言库之一。

## 设置测试环境

在我们开始编写测试之前，我们将建立一个基本的 Node.js 项目。执行以下步骤来实现这一点：

1.  在你当前的工作目录中，创建一个名为`unit-testing`的新文件夹：

```js
$ mkdir unit-testing
$ cd unit-testing
```

1.  使用以下命令使用`npm`初始化一个新的 Node.js 项目：

```js
$ npm init -y
```

1.  安装 Mocha 和 Chai 作为开发依赖项：

```js
$ npm install mocha chai --save-dev
```

1.  安装成功后，打开你的`package.json`文件，并将`scripts`中的`test`命令更改为以下内容：

```js
{
 ...

  "scripts": {
    "test": "mocha"
  },
 ...
}
```

这意味着我们可以通过在终端中运行`npm run test`命令来运行测试。

1.  创建两个文件夹，`src`和`test`。`src`文件夹将包含我们的源代码/脚本，而`test`文件夹将包含我们代码的相应测试。创建完文件夹后，你的项目树应该如下所示：

```js
├── package-lock.json
├── package.json
├── src
 └── test
```

1.  在`src`文件夹中，创建一个名为`utils.js`的脚本，并添加以下函数：

```js
exports.addTwoNumbers = function (num1, num2) {
  if (typeof num1 == "string" || typeof num2 == "string"){
    throw new Error("Cannot add string type to number")
  }
  return num1 + num2;
};
exports.mean = function (numArray) {
  let n = numArray.length;
  let sum = 0;
  numArray.forEach((num) => {
    sum += num;
  });
  return sum / n;
};
```

前面的函数执行一些基本的计算。第一个函数将两个数字相加并返回结果，而第二个函数计算数组中数字的平均值。

注意

我们在这里编写的是 ES16 之前的 JavaScript。这是因为我们不打算为这个示例项目设置任何转译器。在使用现代 JavaScript 的项目中，你通常会在测试之前转译源代码。

1.  在你的`test`文件夹中，添加一个名为`utils.js`的新文件。建议使用这种命名约定，因为不同的文件应该与其对应的源代码同名。在`test`文件夹中的`utils.js`文件中，添加以下代码：

```js
const chai = require("chai");
const expect = chai.expect;
const utils = require("../src/utils"); 
describe("Test addition of two numbers", () => {
  it("should return 20 for addition of 15 and 5", () => {
    expect(utils.addTwoNumbers(15, 5)).equals(20);
  });

  it("should return -2 for addition of 10 and -12", () => {
    expect(utils.addTwoNumbers(10, -12)).equals(-2);
  });

  it("should throw an error when string data type is passed", () => {
    expect(() => utils.addTwoNumbers("One", -12)).to.throw(
      Error,
      "Cannot add string type to number"
    );
  });
});

describe("Test mean computation of an array", () => {
  it("should return 25 as mean of array [50, 25, 15, 10]", () => {
    expect(utils.mean([50, 25, 15, 10])).equals(25);
  });
  it("should return 2.2 as mean of array [5, 2, 1, 0, 3]", () => {
    expect(utils.mean([5, 2, 1, 0, 3])).equals(2.2);
  });
});
```

在上述代码片段的前三行中，我们导入了`chai`和`expect`，以及包含我们源代码的`utils`脚本。

接下来，我们使用 Mocha 的`describe`和`it`函数来定义我们的测试用例。请注意，我们有两个`describe`函数对应于我们源代码中的两个函数。这意味着每个`describe`函数将包含测试我们代码不同方面的单元测试。

第一个`describe`函数测试`addTwoNumber`函数，并包含三个单元测试，其中一个测试了在传递字符串数据类型时是否抛出了正确的错误。第二个`describe`函数通过提供不同的值来测试`mean`函数。

1.  要运行我们的测试，去你的终端并运行以下命令：

```js
package.json file, and outputs a formatted test case report, as shown in the following screenshot:
```

![图 1.4 - Mocha 测试输出显示所有测试通过](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_01_04.jpg)

图 1.4 - Mocha 测试输出显示所有测试通过

通过遵循上述步骤，我们能够编写并运行一些在第一次运行时通过的测试。这在大多数情况下可能不是这样，因为你的测试通常会在通过之前失败很多次，特别是当你有许多不同边界情况的单元测试时。

例如，我们将添加一个新的测试用例，当传递给平均函数的数组不包含任何元素时，期望出现错误。

在测试脚本中，在第二个`describe`函数下，添加以下单元测试：

```js
...
 it("should throw error on empty array arg", () => {
    expect(() => utils.mean([])).to.throw(Error, "Cannot compute mean of empty array")
  });
...
```

再次运行测试，我们将看到以下错误：

![图 1.5 - Mocha 测试输出显示一个测试失败](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_01_05.jpg)

图 1.5 - Mocha 测试输出显示一个测试失败

Mocha 提供的错误消息告诉我们，当传递一个空数组时，我们的函数应该抛出一个错误，但目前并没有这样做。为了修复这个错误，我们将转到我们的源代码并更新`mean`函数，如下面的代码块所示：

```js
exports.mean = function (numArray) {
  if (numArray.length == 0){
    throw new Error("Cannot compute mean of empty array")
  }
  let n = numArray.length;
  let sum = 0;
  numArray.forEach((num) => {
    sum += num;
  });

  return sum / n;
};
```

现在，如果我们再次运行测试，我们应该看到它成功通过：

![图 1.6 - Mocha 测试输出显示所有测试都通过了](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_01_06.jpg)

图 1.6 - Mocha 测试输出显示所有测试都通过了

进一步阅读

Mocha 是多才多艺的，并为您可能遇到的几乎所有测试用例和场景提供支持。要了解更多信息，您可以访问官方文档：[`mochajs.org/`](https://mochajs.org/)。

Chai, 另一方面，提供了许多断言语句和函数，您可以使用它们来丰富您的测试。您可以在这里了解更多关于这些断言：[`www.chaijs.com/api/`](https://www.chaijs.com/api/)。

恭喜您完成了本章！这是一个冗长的章节，但所涵盖的概念很重要，因为它们将帮助您构建更好的数据驱动产品，正如您将在未来章节中看到的。

# 总结

在本章中，我们介绍并讨论了 ECMA 6 中引入的一些现代 JavaScript 语法。我们首先考虑了`let`和`var`之间的区别，并讨论了为什么`let`是初始化变量的首选方法。在此之后，我们讨论了解构、展开运算符、作用域，以及闭包。然后，我们介绍了一些数组、对象和字符串的重要方法。在此之后，我们讨论了箭头函数，包括它们相对于传统函数的优势，然后我们继续讨论了 JavaScript 的 promises 和 async/await。

然后，我们简要介绍了 JavaScript 中的面向对象编程概念和支持，并通过示例展示了如何编写类。我们还学习了如何使用诸如 Babel 和 webpack 之类的工具建立现代 JavaScript 环境，支持转译和捆绑。最后，我们介绍了使用 Mocha 和 Chai 库进行单元测试。

在下一章中，我们将介绍 Dnotebook，这是一个交互式计算环境，可以在 JavaScript 中进行快速和交互式的实验。


# 第二部分：使用 Danfo.js 和 Dnotebook 进行数据分析和操作

本节向读者介绍了 Danfo.js 和 Dnotebook（JavaScript 中的交互式计算环境）。它还深入研究了 Danfo.js 的内部，检查了数据框架和系列，数据转换和分析，绘图和可视化，以及数据聚合和分组操作。

本节包括以下章节：

+   第二章，Dnotebook - 用于 JavaScript 的交互式计算环境

+   第三章，使用 Danfo.js 入门

+   第四章，数据分析，整理和转换

+   第五章，使用 Plotly.js 进行数据可视化

+   第六章，使用 Danfo.js 进行数据可视化

+   第七章，数据聚合和分组操作


# 第三章：Dnotebook - 用于 JavaScript 的交互式计算环境

使我们的代码足够表达人类可读，而不仅仅是供机器消费的想法是由 Donald Knuth 开创的，他还写了一本名为《文学编程》的书([`www.amazon.com/Literate-Programming-byKnuth-Knuth/dp/B004WKFC4S`](https://www.amazon.com/Literate-Programming-byKnuth-Knuth/dp/B004WKFC4S))。诸如 Jupyter Notebook 之类的工具同样重视散文和代码，因此程序员和研究人员可以通过代码和文本（包括图像和工作流程）进行广泛表达。

在本章中，您将学习有关**Dnotebook**的知识 - 用于 JavaScript 的交互式编码环境。您还将学习如何在本地安装 Dnotebook。此外，您还将学习如何在其中编写代码和 Markdown。此外，您还将学习如何保存和导入已保存的笔记本。

本章将涵盖以下主题：

+   Dnotebook 介绍

+   Dnotebook 的设置和安装

+   Dnotebook 中交互式计算的基本概念

+   编写交互式代码

+   使用 Markdown 单元格

+   保存笔记本

# 技术要求

要成功跟随本章内容，您需要在计算机上安装**Node.js**和现代浏览器，如 Chrome、Safari、Firefox 或 Opera。

要安装 Node.js，您可以在这里按照官方指南进行：[`nodejs.org/en/`](https://nodejs.org/en/)。

本章的代码可在 GitHub 上克隆，网址为[`github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter02`](https://github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter02)

# Dnotebook 介绍

在过去几年的数据科学领域，诸如 Jupyter Notebook 和 JupyterLab 之类的交互式计算环境实际上已经对代码共享产生了巨大影响，这增强了想法的快速迭代。

近年来，数据科学正朝着浏览器端发展，以支持 Web 开发人员等各种用户。这意味着 Python 生态系统中许多成熟的数据科学工具需要在 JavaScript 中进行移植或提供。基于这一推理，我们本书的作者以及 Danfo.js 的创建者决定创建一个专门针对 JavaScript 生态系统的 Jupyter Notebook 的新版本。

正如我们所称呼的，Dnotebook 可以帮助您在 JavaScript 中进行快速和交互式的实验/原型设计。这意味着您可以以交互式和笔记本式的方式编写代码并立即查看结果，就像下面的屏幕截图所示：

![图 2.1 - 使用 Dnotebook 进行交互式编码示例](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_01.jpg)

图 2.1 - 使用 Dnotebook 进行交互式编码示例

Dnotebook 可以用于许多领域和不同的事物，例如以下内容：

+   **数据科学/分析**：它可以帮助您使用高效的 JavaScript 包（如*Danfo.js*、*Plotly.js*、*Vega*、*Imagecook*等）轻松进行交互式数据探索和分析。

+   **机器学习**：它可以帮助您使用机器学习库（如*Tensorflow.js*）轻松构建、训练和原型化机器学习模型。

+   **交互式学习 JavaScript**：它可以帮助您以交互式和可视化的方式学习或教授 JavaScript。这有助于学习和理解。

+   **纯粹的实验/原型设计**：任何可以用 JavaScript 编写的实验都可以在 Dnotebook 上运行，因此这可以帮助快速实验想法。

现在您已经了解了 Dnotebook 是什么，让我们学习如何在本地设置和使用它。

# Dnotebook 的设置和安装

要在本地安装和运行 Dnotebook，您需要确保已安装 Node.js。安装 Node.js 后，您可以通过在终端中运行以下命令轻松安装 Dnotebook：

```js
npm install –g dnotebook
```

上述命令会全局安装 Dnotebook。这是推荐的安装方式，因为它确保了 Dnotebook 服务器可以从计算机的任何位置启动。

注意

您还可以在不安装 Dnotebook 的情况下在线使用它；请查看 Dnotebook 游乐场（[`playnotebook.jsdata.org/demo`](https://playnotebook.jsdata.org/demo)）。

安装后，您可以通过在终端/命令提示符中运行以下命令来启动服务器：

```js
> dnotebook
```

此命令将在默认浏览器中打开一个选项卡，端口为 http://localhost:4400，如下截图所示：

![图 2.2 – Dnotebook 主页](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_02.jpg)

图 2.2 – Dnotebook 主页

打开的页面是 Dnotebook 界面的默认页面，从这里您可以开始编写 JavaScript 和 Markdown。

注意

我们目前使用的是**Dnotebook 版本 0.1.1**，因此，在将来使用本书时，您可能会注意到一些细微的变化，特别是在用户界面方面。

# Dnotebook 中交互式计算的基本概念

为了在 Dnotebook 中编写交互式代码/Markdown，您需要了解一些概念，比如单元格和持久性/状态。我们从解释这些概念开始这一部分。

## 单元格

Dnotebook 中的单元格是一个可以写入代码或文本以便执行的单元块。以下是一个示例截图，显示了代码和 Markdown 单元格：

![图 2.3 – Dnotebook 中的空代码和 Markdown 单元格](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_03.jpg)

图 2.3 – Dnotebook 中的空代码和 Markdown 单元格

每个单元格都有编辑按钮，可以用于不同的目的，如下截图所示：

![图 2.4 – 每个单元格中可用的操作按钮](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_04.jpg)

图 2.4 – 每个单元格中可用的操作按钮

现在，让我们了解一下这些按钮的作用：

+   **运行**：**运行**按钮可用于执行单元格以显示输出。

+   **添加代码**：添加代码按钮有两种变体（向上和向下），由箭头方向指定。它们可以用于在当前单元格上方或下方添加代码单元格。

+   **添加 Markdown**：添加 Markdown 按钮与添加代码按钮类似，有两种变体，可以在当前单元格下方或上方添加 Markdown 单元格。

+   **删除**：顾名思义，此按钮可用于删除单元格。

有两种类型的单元格，即代码单元格和 Markdown 单元格。

## 代码单元格

**代码单元格**是一个可以编写和执行任何 JavaScript 代码的单元格。新笔记本中的第一个单元格始终是代码单元格，我们可以通过经典的 hello world 示例来测试这一点。

在您打开的 Dnotebook 中，写入以下命令并单击**运行**按钮：

```js
console.log('Hello World!')
```

注意

悬停在代码单元格上会显示**运行**按钮。或者，您可以使用 Windows 中的快捷键*Ctrl* + *Enter*或 Mac 中的*Command* + *Enter*来运行代码单元格。

hello world 的代码和输出应该与下面的截图类似：

![图 2.5 – Dnotebook 中的代码单元格和执行输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_05.jpg)

图 2.5 – Dnotebook 中的代码单元格和执行输出

接下来，让我们了解 Markdown 单元格。

## Markdown 单元格

**Markdown 单元格**与代码单元格类似，不同之处在于它们只能执行 Markdown 或文本。这意味着 Markdown 文本可以编译任何使用 Markdown 语法编写的文本。

Dnotebook 中的 Markdown 单元格通常是白色的，可以通过单击打开单元格中的**文本**按钮来打开。**文本**按钮通常适用于每个单元格，如下截图所示：

![图 2.6 – 在 Dnotebook 中打开一个 Markdown 单元格](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_06.jpg)

图 2.6 – 在 Dnotebook 中打开一个 Markdown 单元格

单击**文本**按钮会打开一个 Markdown 单元格，如下截图所示：

![图 2.7 – 在 Markdown 单元格中编写 Markdown 文本](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_07.jpg)

图 2.7 – 在 Markdown 单元格中编写 Markdown 文本

在这里，您可以编写任何 Markdown 格式的文本，当执行时，结果将被编译为文本并显示在 Markdown 单元格的位置上，如下所示：

![图 2.8 – Markdown 单元格的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_08.jpg)

图 2.8 – Markdown 单元格的输出

现在，让我们谈谈交互式编程中的另一个重要概念，称为**持久性**/**状态**。

## 持久性/状态

交互式计算中的持久性或状态是环境变量或数据在创建它的单元格之外继续存在（持续）的能力。这意味着在一个单元格中声明/创建的变量可以在另一个单元格中使用，而不管单元格的位置如何。

每个 Dnotebook 实例都运行一个持久状态，而在没有 `let` 和 `const` 声明的单元格中声明的变量可供所有单元格使用。

注意

在 Dnotebook 中工作时，我们鼓励您以两种主要方式声明变量。

选项 1 – 没有声明关键字（首选方法）：

`food_price = 100`

`clothing_price = 200`

`total = food_price + clothing_price`

选项 2 – 使用 `var` 全局关键字（这样做可以，但不建议）：

`var food_price = 100`

`var clothing_price = 200`

`var total = food_price + clothing_price`

使用 `let` 或 `const` 等关键字会使变量在新单元格中无法访问。

为了更好地理解这一点，让我们声明一些变量，并尝试在之后或之前创建的多个单元格中访问它们：

1.  在您的打开笔记本中创建一个新单元格，并添加以下代码：

```js
num1 = 20
num2 = 35
sum = num1 + num2
console.log(sum)
//output 55
```

运行此代码单元格，您将看到总和打印在单元格下方，如下面的截图所示：

![图 2.9 – 简单的代码来相加两个数字](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_09.jpg)

图 2.9 – 简单的代码来相加两个数字

1.  接下来，通过单击代码单元格按钮，在第一个单元格后创建一个新单元格，并尝试使用 `sum` 变量，如下面的代码块所示：

```js
newSum = sum + 30
console.log(newSum)
//outputs 85
```

通过执行前面的单元格，您将得到 `85` 的输出。这意味着第一个单元格中的变量 sum 也会持续到第二个单元格以及您将创建的任何其他单元格，如下面的截图所示：

![图 2.10 – 两个共享持久状态的代码单元](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_10.jpg)

图 2.10 – 两个共享持久状态的代码单元

注意

Markdown 单元格不会保留变量，因为它们不执行 JavaScript 代码。

现在您了解了单元格和持久性是什么，您现在可以在 Dnotebook 中轻松编写交互式代码，在下一节中，我们将向您展示如何做到这一点。

# 编写交互式代码

在本节中，我们将强调在 Dnotebook 中编写交互式代码时需要了解的一些重要事项。

## 加载外部包

在编写 JavaScript 时，将外部包导入笔记本非常重要，因此 Dnotebook 具有一个名为 `load_package` 的内置函数来执行此操作。

`load_package` 方法可以帮助您通过它们的 CDN 链接轻松地将外部包/库添加到您的笔记本中。例如，要加载 `Tensorflow.js` 和 `Plotly.js`，您可以将它们的 CDN 链接传递给 `load_package` 函数，如下面的代码所示：

```js
load_package(["https://cdn.jsdelivr.net/npm/@tensorflow/tfjs@3.4.0/dist/tf.min.js","https://cdn.plot.ly/plotly-latest.min.js"])
```

这将加载包并将它们添加到笔记本状态中，以便可以从任何单元格中访问它们。在下一节中，我们将使用刚刚导入的 `Plotly` 库。

将以下代码添加到笔记本中的新单元格中：

```js
trace1 = {
  x: [1, 2, 3, 4],
  y: [10, 11, 12, 13],
  mode: 'markers',
  marker: {
    size: [40, 60, 80, 100]
  }
};

data = [trace1];
layout = {
  title: 'Marker Size',
  showlegend: false,
  height: 600,
  width: 600
};

Plotly.newPlot(this_div(), data, layout); //this_div is a built-in function that returns the current output's div name.
```

执行前面部分的代码单元格将显示一个图表，如下面的截图所示：

![图 2.11 – 使用外部包制作图表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_11.jpg)

图 2.11 – 使用外部包制作图表

因此，通过使用 `load_package`，您可以添加任何您选择的外部 JavaScript 包，并在 Dnotebook 中进行交互操作。

## 加载 CSV 文件

将数据导入笔记本，特别是导入到数据框中，非常重要。因此，我们在这里介绍的另一个内置函数是 `load_csv`。

注意

数据框以行和列的形式表示数据。它们类似于电子表格或数据库中的行和列集合。我们将在 *第三章* 中深入介绍数据框和系列，*使用 Danfo.js 入门*。

`load_csv`函数帮助您异步将 CSV 文件加载到`Danfo.js` DataFrame 中。当读取大文件并且想要跟踪进度时，您应该使用这个函数，而不是 Danfo 的内置`read_csv`函数。这是因为`load_csv`会在导航栏上显示一个旋转器来指示进度。

让我们通过一个例子更好地理解这一点。在一个新的代码单元格中，添加以下代码：

```js
load_csv("https://raw.githubusercontent.com/plotly/datasets/master/finance-charts-apple.csv")
.then((data)=>{
  df = data
})
```

执行单元格后，如果您查看右上角，您会注意到一个旋转器，指示数据加载的进度。

执行单元格后，您可以像处理 Danfo DataFrame 一样与数据集交互。例如，您可以使用另一个内置函数`table`来轻松地以表格格式显示数据。

在一个新的单元格中，添加以下代码：

```js
table(df)
```

执行时，您应该会看到数据表，如下截图所示：

![图 2.12–加载和显示 CSV 文件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_12.jpg)

图 2.12–加载和显示 CSV 文件

接下来，我们将简要介绍另一个内置函数，它有助于在笔记本中显示图表。

## 获取绘图的 div 容器

为了显示图表，大多数绘图库都需要某种容器或 HTML `div`。这是使用 Danfo.js 和 Plotly.js 库进行绘图所必需的。为了更容易地访问输出`div`，Dnotebook 内置了`this_div`函数。

`this_div`函数将返回当前代码单元格输出的 HTML ID。例如，在以下代码中，我们将`this_div`的值传递给 DataFrame 的`plot`方法：

```js
const df = new dfd.DataFrame({col1: [1,2,3,4], col2: [2,4,6,8]})

df.plot(this_div()).line({x: "col1", y: "col2"})
```

这将当前单元格的`div` ID 传递给 DataFrame 的`plot`方法，并在执行时显示生成的图表，如下截图所示：

图 2.13–绘制 DataFrame

](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_13.jpg)

图 2.13–绘制 DataFrame

最后，在下一节中，我们将简要讨论在`for`循环中打印值的问题。这不会按预期工作，我们将解释原因。

## 在使用 for 循环时要注意的事项

当您编写`for`循环并尝试在 Dnotebook 代码单元格中打印每个元素时，您只会得到最后一个元素。这个问题与浏览器中控制台的工作方式有关。例如，尝试执行以下代码并观察输出：

```js
for(let i=0; i<10; i++){
  console.log(i)
}
//outputs 9
```

如果您想要在运行`for`循环时看到所有输出，特别是在 Dnotebook 中进行调试，您可以使用 Dnotebook 内置的`forlog`方法。这个方法已经附加到默认的控制台对象上，并且可以像以下代码块中所示那样使用：

```js
for(let i=0; i<10; i++){
  console.forlog(i)
}
```

执行前面的代码单元格将返回所有值，如下截图所示：

![图 2.14–比较 for 和 forlog 方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_14.jpg)

图 2.14–比较 for 和 forlog 方法

您会注意到，当使用`console.forlog`方法时，每个输出都会打印在新的一行上，就像在脚本环境中`console.log`的默认行为一样。

在本节中，我们介绍了一些在 Dnotebook 环境中编写交互式代码时会有用的重要函数和特性。在下一节中，我们将看一下如何使用 Markdown 单元格。

# 使用 Markdown 单元格

Dnotebook 支持 Markdown，这使得您可以将代码与文本和多媒体混合使用，从而使得那些可以访问笔记本的人更容易理解。

Markdown 是一种使用纯文本编辑器创建格式化文本的标记语言。它广泛用于博客、文档页面和 README 文件。如果您使用 GitHub 等工具，那么您可能已经使用过 Markdown。

与许多其他工具一样，Dnotebook 支持所有 Markdown 语法、图像导入、添加链接等。

在接下来的几节中，我们将看到在 Dnotebook 中使用 Markdown 时可以利用的一些重要功能。

## 创建一个 Markdown 单元格

为了在 Dnotebook 环境中编写 Markdown，您需要通过单击**文本**按钮（向上或向下）添加一个 Markdown 单元格。此操作会向您的笔记本添加一个新的 Markdown 单元格。以下屏幕截图显示了在 Markdown 单元格中编写的示例文本：

![图 2.15–在 Markdown 单元格中编写简单文本](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_15.jpg)

图 2.15–在 Markdown 单元格中编写简单文本

在 Markdown 单元格中编写 Markdown 文本后，您可以单击**运行**按钮来执行它。这将用读取模式中的转译文本替换单元格。双击文本会再次显示 Markdown 单元格以进行编辑。

## 添加图像

要将图像添加到 Markdown 单元格中，您可以使用以下代码中显示的图像语法：

```js
![alt Text](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/links to the image)
```

以下是输出：

![图 2.16–添加图像](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_16.jpg)

图 2.16–添加图像

例如，在前面的屏幕截图中，我们添加了一个指向互联网上可用图像的链接。代码如下所示：

```js
![](https://tinyurl.com/yygzqzrq)
```

提供的链接是指向狗图像的链接。需要单击**运行**按钮以查看图像的结果，如下所示：

![图 2.17–Markdown 图像结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_17.jpg)

图 2.17–Markdown 图像结果

在接下来的部分中，您将学习一些基本的 Markdown 语法，您也可以将其添加到您的笔记本中。要查看全面的指南，您可以访问网站[`www.markdownguide.org/basic-syntax/`](https://www.markdownguide.org/basic-syntax/)。

## 标题

要创建标题，您只需在单词或短语前面添加井号符号`（#）`：

```js
# First Heading
## Second Heading 
### Third Heading
```

如果我们将前面的文本粘贴到 Markdown 中并单击**运行**按钮，我们将得到以下输出：

![图 2.18–添加标题文本](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_18.jpg)

图 2.18–添加标题文本

在结果中，您会注意到在文本前面有不同数量的井号会导致不同的大小。

## 列表

列表对于枚举对象很重要，可以通过在文本前加上星号符号（*****）来添加。我们在以下部分提供了一个示例：

```js
* Food
* Cat
    * kitten
* Dog
```

前面的示例创建了一个无序列表，其中包括**食物**、**猫**和**狗**，**小猫**作为**猫**的子列表。

为了创建一个编号列表，只需在文本前面添加数字，如下所示：

1.  **第一项**

1.  **第二项**

1.  **更多**

在 Markdown 输入字段中输入前面的文本应该输出以下内容：

![图 2.19–列表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_19.jpg)

图 2.19–列表

在接下来的部分中，我们将介绍 Dnotebook 的一个重要部分–保存。这对于重用和与其他人共享您的笔记本非常重要。

# 保存笔记本

Dnotebook 支持保存和导入已保存的笔记本。保存和导入笔记本可以让您/其他人重用您的笔记本。

要保存和导入笔记本，请单击**文件**菜单，然后根据您想要执行的操作选择**下载笔记本**或**上传笔记本**按钮。选项显示在以下屏幕截图中：

![图 2.20–保存和导入笔记本](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_02_20.jpg)

图 2.20–保存和导入笔记本

单击**下载笔记本**会以 JSON 格式保存笔记本，这可以很容易地共享或重新加载。

保存和导入

要测试此功能，请转到[`playnotebook.jsdata.org/demo`](https://playnotebook.jsdata.org/demo)。尝试保存演示笔记本。然后打开一个新笔记本，[`playnotebook.jsdata.org`](https://playnotebook.jsdata.org)，并导入保存的文件。

# 总结

在本章中，我们介绍了 Dnotebook，这是一个支持文本和多媒体的交互式库。首先，我们介绍了在本地安装 Dnotebook，并指出您可以免费在线运行部署版本。接下来，我们介绍了一些基本概念和在处理代码和 Markdown 时需要注意的事项，最后，我们向您展示了如何保存笔记本以供共享和重用。

在下一章中，我们将开始使用 Danfo.js，并介绍这个令人惊叹的库的一些基本概念。
