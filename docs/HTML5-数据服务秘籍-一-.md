# HTML5 数据服务秘籍（一）

> 原文：[`zh.annas-archive.org/md5/1753B09CD35CEC6FE2CC3F9B8DA85828`](https://zh.annas-archive.org/md5/1753B09CD35CEC6FE2CC3F9B8DA85828)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

HTML5 无处不在，从个人电脑到平板电脑、智能手机，甚至现代电视机。网络是最普遍的应用平台和信息媒介。最近，HTML5 已成为已建立的操作系统（如 Microsoft Windows 8、Firefox OS 和 Google Chrome OS）中的一等公民。

开放性是网络的重要方面之一。HTML5 是反对私有和专有解决方案的主要方式之一，这些解决方案强制使用特定技术。在过去几年中，真正的革命正在发生。JavaScript 已经成为 Web 应用程序开发的领先位置，无论是服务器端还是客户端。

过去，获取一半完成的脚本和编写不良的 JavaScript 非常常见，因此该语言声誉不佳。HTML5 功能已经可用，但广泛未被使用。有很多网络应用程序在重新发明轮子，而 HTML5 已经有他们需要的功能。

这本书将帮助您快速学习现代 HTML5 功能。在书的结尾，您应该对浏览器和服务器中的 JavaScript 有扎实的理解。除此之外，您还将创建使用新 HTML5 技术的酷小应用程序，并学会如何调整现有应用程序以使用这些新功能。

# 本书涵盖的内容

第一章，“文本数据的显示”，涵盖了在 HTML5 中显示文本所需的知识。这包括格式化数字、显示数学公式和测量单位。此外，还有关于显示表格数据和呈现 Markdown 的部分，展示了一些日常开发功能。

第二章，“图形数据的显示”，首先介绍了使用 Flot 图表库创建图表，以及更现代的数据驱动`D3.js`。本章还涵盖了显示带有路线和标记的地图。

第三章，“动画数据显示”，探讨了动画和交互式可视化的创建。本章大部分可视化基于`D3.js`，但也有一些从头开始或使用通知 API 等技术的示例。

第四章，“使用 HTML5 输入组件”，首先介绍了简单文本输入元素的使用，然后转向 HTML5 添加的新输入类型。它还涵盖了新属性的使用，以及使用地理位置或拖放区域的更高级输入。

第五章，“自定义输入组件”，延续了前一章的主题，重点是创建自定义控件，添加新功能或模仿桌面应用程序中可用的组件。本章解释了如何创建菜单、对话框、列表选择和富文本输入等控件。

第六章，“数据验证”，介绍了 HTML5 处理表单验证的方式。本章将涵盖文本和数字的验证，内置的电子邮件和数字验证。此外，它还涵盖了使用 Node.js 进行服务器端验证，并展示了如何结合客户端和服务器端验证。

第七章，“数据序列化”，深入探讨了从客户端 JavaScript 创建 JSON、base64 和 XML，以及从这些格式创建 JavaScript 对象的逆向过程。

第八章，“与服务器通信”，让您开始使用 Node.js 并创建 REST API。本章还包含了如何从纯 JavaScript 发出 HTTP 调用、如何处理二进制文件以及通信安全的详细信息。

第九章，“客户端模板”，介绍了流行的客户端模板语言 Handlebars，EJS 和 Jade 的使用。它涵盖并比较了这些语言的基本用法，以及它们更高级的功能，如部分，过滤器和混合。

第十章，“数据绑定框架”，让您开始使用两种不同类型的 Web 框架。一方面，我们有 Angular，它是许多不同客户端 MVC 框架中强大的代表，另一方面，我们有 Meteor，它是在某些领域缩短开发时间的反应性框架。

第十一章，“数据存储”，探讨了 HTML5 中可用的新客户端存储 API，以及用于处理文件的新 API。这些新功能使我们能够在页面刷新后持久保存数据，并保存不会在每个请求中来回传输的客户端信息。

第十二章，“多媒体”，介绍了在浏览器中播放视频和音频文件的一些方法，这在过去是由外部插件完成的。

附录 A，“安装 Node.js 和使用 npm”，简要介绍了安装 Node.js 及其包管理器 npm。

附录 B，“社区和资源”，包含了 HTML5 开发的主要组织的简短历史和参考资料。

# 本书所需的内容

开始所需的一切只是一个现代浏览器，如 Firefox，Chrome，Safari，Opera 或 Internet Explorer 9，一个简单的文本编辑器，如 Notepad ++，Emacs 或 Vim，以及互联网连接。

在第七章，“数据序列化”和后续章节中，您还需要安装 Node.js 来尝试一些配方。安装过程在*附录 A*中有介绍，*安装 Node.js 和使用 npm*。

# 这本书是为谁写的

这本书是为那些以某种方式已经使用过 JavaScript 的程序员而写的。它适用于那些与大量后端代码一起工作，并希望快速了解 HTML5 和 JavaScript 世界的人。它适用于那些使用复制/粘贴来修补页面的一部分并想了解背后工作原理的人。它适用于希望通过 HTML5 实现的新技术和功能更新他们的 JavaScript 开发人员。

本书既适用于初学者又适用于经验丰富的开发人员，假设您已经具有一些 HTML，JavaScript 和 jQuery 的经验，但不一定需要深入的知识。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词显示如下：“`d3.behavior.zoom()`方法使我们能够向我们的`projection`类型添加自动缩放功能，并使用`scaleExtent`中给定的比例和缩放范围。”

代码块设置如下：

```html
<!DOCTYPE HTML>
<html>
  <head>
    <title>Chart example</title>
  </head>
  <body>
    <div id="chart" style="height:200px;width:800px;"></div>
    <script src="img/jquery.min.js"></script>
    <script src="img/jquery.flot.js"></script>
    <script src="img/jquery.flot.navigate.js"></script>
    <script type="text/javascript" src="img/example.js"></script>
  </body>
</html>
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```html
#carousel {
 perspective: 500px;
  -webkit-perspective: 500px;
  position:relative; display:inline-block;
  overflow:hidden;
}
```

任何命令行输入或输出都以以下形式编写：

```html
Object:
 color: "#00cc00"
 data: Array[50]
 name: "one"

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这样的方式出现在文本中：“此外，我们可以添加一个包含默认文本的属性 data-placeholder，例如我们的示例中的**职业**。如果未指定，它将默认为**选择某些选项**进行单选。”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧看起来像这样。


# 第一章：文本数据的显示

在本章中，我们将涵盖以下主题：

+   舍入数字以进行显示

+   填充数字

+   显示公制和英制测量单位

+   在用户的时区中显示格式化日期

+   显示已经过去的动态时间

+   显示数学

+   创建无限滚动列表

+   创建可排序的分页表

+   创建多选过滤器

+   创建范围过滤器

+   创建组合复杂过滤器

+   在 HTML 中显示代码

+   渲染 Markdown

+   自动更新字段

# 介绍

与 Web 应用程序开发相关的最常见任务是显示文本。本章将涵盖程序员在浏览器中显示数据时面临的一些问题，并将解释如何以简单而有效的方式解决这些问题，为程序员提供几种不同的选择。这些示例将包含标记的渲染或其他数据类型转换为纯文本。

# 舍入数字以进行显示

在文本之后，应用程序中使用的第二种最常见的数据类型是数字。有许多不同的处理数字的方式，当需要给定精度时，我们将看一些这些方式。第一个明显的选择是使用 JavaScript 的`Number`对象包装器来处理数值。

## 准备工作

`Number`对象包含`toFixed([digits])`方法，可用于显示数字；这里的`digits`参数可以在 0 和 20 之间取值。如果需要，数字将自动舍入，或者如果需要，数字将填充额外的零。好的，让我们看看它的效果。

## 如何做...

执行以下步骤来演示使用`Number`对象：

1.  首先，我们将创建一个数字列表；请注意，这些数字是有意挑选的，以说明一些函数的特性：

```html
    var listOfNumbers=
        [1.551, 1.556, 1.5444, 1.5454, 1.5464, 1.615, 1.616, 1.4, 1.446,1.45];
```

1.  迭代列表，并使用`.toFixed()`方法显示数字，分别使用`digits`参数的值 0、1 和 2：

```html
for (var i = 0; i < listOfNumbers.length; i++) {
      var number = listOfNumbers[i];
         // iterate over all of the numbers and write to output all the value
      document.write(number + "---"
                   + number.toFixed(2) + "---"
                   + number.toFixed(1) + "---"
                   + number.toFixed() + "<br />");
    };
```

## 它是如何工作的...

执行代码后得到的结果将打印出带有它们各自`toFixed`表示的数字，这应该很简单。

让我们来看一些特征值：

+   `1.616.toFixed(2)`将返回`1.62`

+   `1.4.toFixed(2)`将返回`1.40`，如预期的那样，添加一个尾随零

+   `1.5454.toFixed()`将返回`2`，因为`toFixed()`的默认值是`0`；这意味着没有小数点，另外`0.5`部分被舍入为`1`，所以这里使用了天花板值

+   `1.615.toFixed(2)`将返回`1.61`，忽略`0.005`部分，或者将使用地板值

`toFixed()`方法在大多数情况下都能按预期工作，只要我们不需要更高的精度或仅用它来显示数字，其中舍入的类型并不是关键。

此外，当我们需要在有类似 1.446 的数字的情况下进行舍入时，我们不能依赖于`toFixed()`; 调用`1.446.toFixed(1)`将导致不一致和不可预测的结果。

## 还有更多...

有各种方法可以解决这个问题。快速而肮脏的解决方案是重新定义`Number.prototype.toFixed()`函数，但我们鼓励您不要这样做，因为这样做可能会产生不明显的副作用。如果不是绝对必要，对内置对象的函数进行重新定义被认为是一种反模式。问题在于如果另一个库或一段代码使用相同的函数。另一个库可能期望我们重新定义的函数以某种方式工作。这些类型的重新定义很难跟踪；即使我们添加一个函数而不是重新定义它，其他人可能会做同样的事情。例如，假设我们决定向`Number`对象添加一些函数：

```html
Number.prototype.theFunction = function(arg1,arg2){}
```

没有保证其他人没有将`theFunction`添加到`Number`对象中。我们可以进行额外的检查来验证函数是否已经存在，但我们不能确定它是否会按我们希望的方式工作。

相反，使用一个实用函数来实现一致的数据将是一个更好的选择。

解决问题的一种方法是首先将数字乘以`10 ^ digits`，然后在结果上调用`Math.round(number)`方法，或者您可以调用`Math.ceil(number)`。例如，如果您需要将值向上舍入到最接近的整数，使用以下方法：

```html
    function round(number, digits) {
        if(typeof digits === "undefined" || digits < 0){
          digits = 0;
        }
        var power = Math.pow(10, digits),
         fixed = (Math.round(number * power) / power).toString();
        return fixed;
    };
```

现在，由于数字乘以`10 ^ digits`，然后四舍五入，我们不会观察到`toFixed()`的问题。请注意，这种方法与`toFixed()`的行为不同，不仅在处理舍入的方式上有所不同，而且还会添加尾随零。

另一个选择是使用一个类似 Big.js 这样的任意精度库，如果精度很重要的话（[`github.com/MikeMcl/big.js`](https://github.com/MikeMcl/big.js)）。

# 填充数字

有时我们需要将数字填充到一定的范围。例如，假设我们想要以五位数字的形式显示一个数字，比如`00042`。一个明显的解决方案是使用迭代方法并在前面添加字符，但还有一些更简洁的解决方案。

## 准备工作

首先，我们需要看一下我们将要使用的一些函数。让我们看一下`Array.join(separator)`方法，它可以用来从元素列表创建连接的文本：

```html
new Array('life','is','life').join('*')
```

这将导致`"life*is*life"`，显示了用给定分隔符连接的相当简单的元素。另一个有趣的方法是`Array.slice(begin[, end])`，它返回数组的一部分的副本。对于我们的用途，我们只对`begin`参数感兴趣，它可以具有正值和负值。如果我们使用正值，这意味着这将是使用基于零的索引的切片的起始索引；例如，考虑以下代码行：

```html
new Array('a','b','c','d','e','f','g').slice(4);
```

上面的代码将返回一个包含元素`'e'`、`'f'`和`'g'`的数组。

另一方面，如果对`begin`元素使用负值，则表示从数组末尾的偏移量，考虑以下使用负值的相同示例：

```html
new Array('a','b','c','d','e','f','g').slice(-3);
```

结果将是`'e'，'f'，'g'`，因为我们是从末尾切片。

## 如何做...

让我们回到我们的问题：如何为数字添加前导零创建一个干净的解决方案？对于迭代解决方案，我们创建一个接受数字、格式化结果的大小和用于填充的字符的方法；例如，让我们以`'0'`为例：

```html
function iterativeSolution(number,size,character) {
   var strNumber = number.toString(),
    len = strNumber.length,

    prefix = '';
   for (var i=size-len;i>0;i--) {
      prefix += character;
   }
 return prefix + strNumber;
}
```

在这里，我们将数字转换为字符串，以便获得其表示的长度；之后，我们简单地创建一个`prefix`，它将有`size-len`个字符的`character`变量，并返回结果`prefix + strNumber`，这是该数字的字符串表示。

您可能会注意到，如果`size`小于`len`，则会返回原始数字，这可能需要更改，以使该函数适用于这种特殊情况。

另一种方法是使用`Array.slice()`方法来实现类似的结果：

```html
function sliceExample(number,prefix){
   return (prefix+number).slice(-prefix.length);
}
sliceExample(42,"00000");
```

这将只是在数字前面添加一个前缀，并从末尾切掉多余的`'0'`，使解决方案更加简洁，并且还能够更灵活地确定前缀的内容。这样做的缺点是我们手动构造了将成为方法调用`sliceExample(42,"00000")`一部分的前缀。为了使这个过程自动化，我们可以使用`Array.join`：

```html
function padNumber(number,size,character){
  var prefix = new Array(1 + size).join(character);
```

我们创建一个预期的`size + 1`的数组，因为在连接时，我们将得到总数组`size-1 个连接的元素`。这将构造预期大小的前缀，而其他部分将保持不变：

```html
  return (prefix + number).slice(-prefix.length);
 }
```

一个示例方法调用将是`padNumber(42,5,'0')`; 这将不具有以前方法的灵活性，但在处理更大的数字时会更简单。

## 它是如何工作的...

这个配方相当简单，但需要注意的一点是功能性方法。如果有一件事可以从这个配方中带走的话，那就是迭代解决方案并不总是最好的。当涉及到 JavaScript 时，通常有几种其他完成任务的方法；它们并不总是*那么*直接，有时甚至不是更快，但它们可能更加干净。

## 还有更多...

如果由于某种原因我们经常填充数字，将函数添加到`Number`对象中并使用`this`关键字删除`input`参数数字可能是有意义的：

```html
Number.prototype.pad=function(size,character){
     //same functionality here
}
```

由于该函数现在是每个`Number`对象的一部分，我们可以直接从任何数字中使用它；让我们来看下面的例子：

```html
  3.4.pad(5,'#');
```

此外，如果不应包括“。”字符在填充的计算中，我们可以添加一个额外的检查，以减少前缀的大小。

### 注意

请注意，在*舍入数字以进行显示*配方中，我们解释了为什么向标准对象添加函数是一种可能会对我们产生反作用的黑客行为。

# 显示公制和英制测量

处理计算和测量的网站通常需要解决同时使用公制和英制计量单位的问题。本教程将演示一种数据驱动的方法来处理单位转换。由于这是一本 HTML5 书籍，解决方案将在客户端而不是服务器端实现。

我们将实现一个客户端，“理想体重”计算器，支持公制和英制测量。这一次，我们将创建一个更通用和优雅的数据驱动解决方案，利用现代 HTML5 功能，如数据属性。目标是尽可能抽象出混乱和容易出错的转换。

## 准备工作

计算体重指数（BMI）的公式如下：

BMI =（千克中的体重/（米中的身高 x 米中的身高））

我们将使用 BMI = 22 来计算“理想体重”。

## 如何做...

1.  创建以下 HTML 页面：

```html
<!DOCTYPE HTML>
<html>
    <head>
        <title>BMI Units</title>
    </head>
    <body>
        <label>Unit system</label>
        <select id="unit">
            <option selected value="height=m,cm 0;weight=kg 1;distance=km 1">Metric</option>
            <option value="height=ft,inch 0;weight=lbs 0;distance=mi 1">Imperial</option>
        </select><br>

        <label>Height</label>
        <span data-measurement="height" id="height">
            <input data-value-display type="text" id="height" class="calc">
            <span data-unit-display></span>
            <input data-value-display type="text" id="height" class="calc">
            <span data-unit-display></span>
        </span>
        <br>
        <label>Ideal Weight</label>
        <span data-measurement="weight" id="weight">
            <span data-value-display type="text">0</span>
            <span data-unit-display></span>
        </span> <br>

        <script src="img/jquery.min.js"></script>
        <script type="text/javascript" src="img/unitval.js"></script>
        <script type="text/javascript" src="img/example.js"></script>
        </script>
    </body>
</html>
```

这个页面看起来非常像我们为基于 BMI 的理想体重计算器制作的常规页面。主要区别如下：

+   我们有一个英制/公制选择输入

+   我们还有额外的自定义数据属性，为 HTML 字段赋予特殊含义

+   我们使用`data-measurement`来表示元素将显示的测量类型（例如，体重或身高）

+   我们使用`data-display-unit`和`data-display-value`来表示显示单位字符串和测量值的字段

1.  创建一个名为`example.js`的文件，其中包含以下代码：

```html
(function() {
    // Setup unitval
    $.unitval({
        weight: {
            "lbs": 0.453592, // kg
            "kg" : 1 // kg
        },
        height: {
            "ft"  : 0.3048, // m
            "inch": 0.0254, // m
            "m"   : 1, // m
            "cm"  : 0.01, // m
        }
    });
    $("#unit").change(function() {
        var measurementUnits = $(this).val().split(';').map(function(u) {
            var type_unitround = u.split('='),
                unitround = type_unitround[1].split(' ');
            return {
                type: type_unitround[0],
                units: unitround[0].split(','),
                round: unitround[1]
            };
        });
        // Setup units for measurements.
        $('body').unitval(measurementUnits);
    });

    $("#unit").trigger("change");

    $('#height').on('keyup change',function() {
        var height = $('#height').unitval(), bmi = 22;
        var idealWeight = bmi * height * height;
        $("#weight").unitval(idealWeight);
    });

}
```

代码的第一部分配置了一个名为`unitval`的 jQuery 插件，其中包含我们将使用的测量和单位的转换因子（体重和身高）。

第二部分通过从`select`字段中读取规范来设置文档的测量单位。它指定了一个测量数组，每个测量都有以下内容：

+   一个类型字符串，例如“身高”

+   单位列表，例如`["ft", "inch"]`

+   用于最后一个单位的小数位数

第三部分是一个常规计算器，几乎与没有单位转换时写的一样。唯一的例外是，值是使用名为`$.unitval`的 jQuery 插件从具有`data-measurement`属性的元素中获取的。

1.  我们将编写一个通用的单位转换器。它将需要两个函数：一个将用户显示（输入）数据转换为标准国际（SI）测量单位的函数，另一个将其从 SI 单位转换回用户友好的显示单位。我们的转换器将支持同时使用多个单位。在从输入转换时，第一个参数是测量类型（例如，距离），第二个是值-单位对的数组（例如，`[[5，'km']，[300，'m']]`），单个对（例如`[5，'km']`），或者只是值（例如`5`）。

1.  如果第二个参数是一个简单的值，我们将接受一个包含单位的第三个参数（例如`'km'`）。输出始终是一个简单的 SI 值。

在将值转换为所需的输出单位时，我们将单位指定为数组，例如，作为`['km', 'm']`或作为单个单位。我们还指定最后一个单位的小数位数。我们的输出是转换后的值数组。

转换是使用`Factors`对象中的值完成的。该对象包含我们将要使用的每个测量名称的属性。每个这样的属性都是一个对象，其中包含该测量的可用单位作为属性，其 SI 因子作为值。在`example.js`中查看示例。

1.  jQuery 插件`unitval.js`的源代码如下：

```html
(function() {
    var Factors = {};
    var Convert = window.Convert = {
        fromInput: function(measurement, valunits, unit) {
            valunits = unit ? [[valunits, unit]] // 3 arguments
                : valunits instanceof Array && valunits[0] instanceof Array ? valunits  
                : [valunits]; // [val, unit] array

            var sivalues = valunits.map(function(valunit) { // convert each to SI
                return valunit[0] * Factors[measurement][valunit[1]];
            });
            // sivalues.sum():
            return sivalues.reduce(function(a, e) { return a + e; });
        },
        toOutput: function(measurement, val, units, round) {
            units = units instanceof Array ? units : [units];
            var reduced = val;
            return units.map(function(unit, index) {
                var isLast = index == units.length - 1,
                    factor = Factors[measurement][unit];
                var showValue = reduced / factor;
                if (isLast && (typeof(round) != 'undefined'))
                    showValue = showValue.toFixed(round) - 0;
                else if (!isLast) showValue = Math.floor(showValue);
                reduced -= showValue * factor;
                return showValue;
            });
        }
    };
    $.unitval = function(fac) {
        Factors = fac;
    }
    // Uses .val() in input/textarea and .text() in other fields.
    var uval = function() {
        return ['input','textarea'].indexOf(this[0].tagName.toLowerCase()) < 0 ?
                this.text.apply(this, arguments) : this.val.apply(this, arguments);
    }
```

1.  我们的通用转换器很有用，但不太方便或用户友好；我们仍然必须手动进行所有转换。为了避免这种情况，我们将在元素上放置数据属性，表示它们显示的测量。在其中，我们将放置用于显示值和单位的单独元素。当我们设置测量单位时，函数`setMeasurementUnits`将在具有此数据属性的每个元素上设置它们。此外，它还将相应地调整内部值和单位元素：

```html
// Sets the measurement units within a specific element.
// @param measurements An array in the format [{type:"measurement", units: ["unit", ...], round:N}]
// for example [{type:"height", units:["ft","inch"], round:0}]
    var setMeasurementUnits = function(measurements) {
        var $this = this;
        measurements.forEach(function(measurement) {
            var holders = $this.find('[data-measurement="'+measurement.type+'"]');
            var unconverted = holders.map(function() { return $(this).unitval(); })
            holders.attr('data-round', measurement.round);
            holders.find('[data-value-display]').each(function(index) {
                if (index < measurement.units.length)    
                    $(this).show().attr('data-unit', measurement.units[index]);
                else $(this).hide();
            });
            holders.find('[data-unit-display]').each(function(index) {
                if (index < measurement.units.length)    
                    $(this).show().html(measurement.units[index]);
                else $(this).hide();
            });

            holders.each(function(index) { $(this).unitval(unconverted[index]); });
        });
    };
```

1.  由于每个元素都知道其测量和单位，因此我们现在可以简单地在其中放入 SI 值，并让它们显示转换后的值。为此，我们将编写`unitval`。它允许我们设置和获取“联合”值，或在具有`data-measurement`属性的元素上设置单位选项：

```html
    $.fn.unitval = function(value) {
        if (value instanceof Array) {
            setMeasurementUnits.apply(this, arguments);
        }
        else if (typeof(value) == 'undefined') {
            // Read value from element
            var first       = this.eq(0),
                measurement = first.attr('data-measurement'),
                displays    = first.find('[data-value-display]:visible'),
                // Get units of visible holders.
                valunits = displays.toArray().map(function(el) {
                    return [uval.call($(el)), $(el).attr('data-unit')] });
            // Convert them from input
            return Convert.fromInput(measurement, valunits);
        }
        else if (!isNaN(value)) {
            // Write value to elements
            this.each(function() {
                var measurement   = $(this).attr('data-measurement'),
                    round         = $(this).attr('data-round'),
                    displays      = $(this).find('[data-value-display]:visible'),
                    units         = displays.map(function() {
                        return $(this).attr('data-unit'); }).toArray();
  var values = Convert.toOutput(measurement, value, units, round);
                displays.each(function(index) { uval.call($(this), values[index]); });
            });
        }
    }
}());
```

此插件将在下一节中解释。

## 它是如何工作的...

HTML 元素没有测量单位的概念。为了支持单位转换，我们添加了自己的数据属性。这些属性允许我们赋予某些元素特殊的含义，其具体内容由我们自己的代码决定。

我们的约定是，具有`data-measurement`属性的元素将用于显示指定测量的值和单位。例如，具有`data-measurement="weight"`属性的字段将用于显示重量。

此元素包含两种类型的子元素。第一种类型具有`data-display-value`属性，并显示测量的值（始终是一个数字）。第二种类型具有`data-display-unit`属性，并显示测量的单位（例如，`"kg"`）。对于用多个单位表示的测量（例如，高度可以以“5 英尺 3 英寸”的形式表示），我们可以使用两种类型的多个字段。

当我们改变我们的单位制度时，`setMeasurementUnits`会向以下元素添加附加的数据属性：

+   `data-round`属性附加到`data-measurement`元素

+   向包含适当单位的`data-display-value`元素添加了`data-unit 属性`

+   `data-display-unit`元素填充了适当的单位

因此，`$.unitval()`知道我们页面上每个测量元素上显示的值和单位。该函数在返回之前读取并将测量转换为 SI。我们所有的计算都使用 SI 单位。最后，当调用`$.unitval(si_value)`时，我们的值会在显示之前自动转换为适当的单位。

该系统通过识别只有在读取用户输入和显示输出时才真正需要转换时，最小化了容易出错的单位转换代码的数量。此外，数据驱动的方法允许我们完全从我们的代码中省略转换，并专注于我们的应用逻辑。

# 在用户的时区中显示格式化的日期

在这个示例中，我们将学习如何在用户的本地时区中格式化并显示日期；此外，我们还将看到 JavaScript 中如何使用和表示日期。最好的方法是让用户选择他们希望日期显示的时区，但不幸的是，这很少是一个选项。

## 准备工作

就像大多数编程语言一样，JavaScript 使用 Unix 时间。这实际上是一种表示给定时间实例的系统，即自 1970 年 1 月 1 日午夜以来经过了多少秒或在 JavaScript 的情况下是毫秒，通常称为协调世界时的时间。

### 注意

关于 UTC 的一些有趣的小知识：缩写是法语版本 Temps Universel Coordonné和英语版本协调世界时之间的妥协，法语版本将是 TUC，英语版本将是 CUT。

这个数字实际上并不完全符合 UTC，也没有考虑到闰秒等各种非典型情况，但在大多数情况下这是可以接受的。

在 JavaScript 中，我们有`Date`对象，可以以不同的方式构造：

```html
new Date() // uses local time
new Date(someNumber) //create date with milliseconds since epoch
new Date(dateString) // create date from input string representation
new Date(year, month, day [, hour, minute, second, millisecond])
```

### 注意

请注意，在各种浏览器中，从字符串表示创建日期可能会有不同的行为，`Date.parse`方法解析字符串为日期也是如此。

在构造过程中，如果您提供了一些参数并省略了可选参数，它们将默认为零。还有一件事要注意的是，JavaScript 中的月份是基于零的，而日期不是。

### 注意

在 JavaScript 中，将`Date`对象作为函数而不是构造函数使用，使用`new Date(...)`，将导致您获得该日期的字符串表示，而不是获得`Date`对象，这与大多数其他 JavaScript 对象的预期不同。

## 如何做...

1.  您需要做的第一件事是创建`Date`对象：

```html
  var endOfTheWorld= new Date(1355270400000);
```

1.  然后，只需使用本地化的日期和时间表示：

```html
    document.writeln(endOfTheWorld.toLocaleDateString());
    document.writeln(endOfTheWorld.toLocaleTimeString());
```

1.  如果您需要知道用户时区与 UTC 之间的小时偏移量，可以使用以下代码：

```html
var offset = - new Date().getTimezoneOffset()/60;
```

1.  此偏移变量表示本地用户时区到 UTC 的小时数。这里的减号将逻辑反转为日期；这意味着差异将从日期到 UTC 而不是从 UTC 到日期。

## 它是如何工作的...

我们通常可以从服务器端返回毫秒表示，并在本地时区中格式化数字。因此，假设我们的 API 返回了毫秒`1355270400000`，实际上是 2012 年 12 月 12 日，也被称为世界末日日期。

日期的创建如下：

```html
var endOfTheWorld= new Date(1355270400000);
```

在本地字符串中打印时，有一些可用的选项；其中之一是`toLocaleDateString`：

```html
   endOfTheWorld.toLocaleDateString()
```

此方法使用底层操作系统来获取格式约定。例如，在美国，格式为月/日/年，而在其他国家，格式为日/月/年。对于我们的情况，世界末日是在“2012 年 12 月 12 日星期三”。您还可以使用适当的`getX`方法手动构造打印日期。

还有一种打印本地时间的方法叫做`toLocaleTimeString`，可以用在我们的世界末日日期上。因为这种方法也为我们使用操作系统的本地时间，所以它是 01:00:00，因为我们处于 UTC+1 时区。对我们来说，这意味着我们有一个额外的小时可以活着；或者也许不是？

为了获取本地用户的偏移量，`Date`对象中有一个名为`getTimezoneOffset()`的方法，它返回日期到 UTC 的时区偏移量（以分钟为单位）。问题在于没有小时的方法，此外，它是反直觉的，因为我们通常想要知道从 UTC 到给定日期的差异。

## 还有更多...

如果处理日期是您的应用程序中常见的事情，那么使用一个库是有意义的，比如**Moment.js**（[`momentjs.com/`](http://momentjs.com/)）。

Moment.js 提供了对国际化和更高级的日期操作的支持。例如，从当前日期减去 10 天只需使用以下代码即可完成：

```html
moment().subtract('days', 10).calendar();
```

要从今天的开始时间获取时间，请使用以下代码：

```html
moment().startOf('day').fromNow();
```

# 显示经过的动态时间

在每个主要网站上，通常都会有这些很棒的计数器，显示页面上各种元素的时间戳。例如，这可能是“您在 3 小时前打开了此页面”或“2 分钟前发表了评论”。这就是为什么，除了名称“动态经过的时间”，这个功能也被称为“时间过去”。

## 准备工作

我们将使用一个名为**timeago**的 jQuery 插件，专门为此目的设计，可以从[`timeago.yarp.com/`](http://timeago.yarp.com/)获取。

## 如何做…

我们将创建一个简单的页面，其中我们将通过执行以下步骤显示经过的时间：

1.  因为`timeago`是一个 jQuery 插件，我们首先需要包含 jQuery，然后添加`timeago`插件：

```html
 <script src="img/jquery.min.js">
 </script>
 <script src="img/jquery.timeago.js" type="text/javascript"></script>
```

1.  举个例子，添加以下 HTML：

```html
        <p> Debian was first announced <abbr class='timeago' title="1993-08-16T00:00:00Z">16 August 1993</abbr>
          </p>
          <p> You opened this page <span class='page-opened' /> </p>
           <p> This is done use the time element
              <time datetime="2012-12-12 20:09-0700">8:09pm on December 12th, 2012</time>
          </p>
```

1.  这将使我们能够对`timeago`插件提供的基本功能有一个概述。之后，让我们添加以下 JavaScript：

```html
 $(document).ready(function() {
          jQuery.timeago.settings.allowFuture = true;
          var now= new Date();
          $(".timeago").timeago();
          $(".page-opened").text( $.timeago(now));
          $("time").timeago();
          //$("some-future-date") $.timeago(new Date(999999999999));
      });
```

就是这样；现在您有一个完全工作的时间示例，它将计算自给定日期以来的时间并更新它，另外，与`page-opened`选择的第二部分将随着用户在页面上花费更多时间而自动更新。

## 它是如何工作的…

您可能想知道的第一件事是关于`abbr`和`time`标签。实际上，第一个是“缩写”的表示，并且可以选择性地为其提供完整的描述。如果存在完整的描述，`title`属性必须包含此完整描述，而不包含其他内容。完整的描述通常在浏览器中显示为工具提示，但这是一个标准。为什么我们选择`abbr`标签来显示时间？嗯，有一个名为`time`的新的 HTML5 时间元素，围绕它有一些争议，因为它被从规范中删除，但后来又被重新添加。这个元素在语义上更正确，而且以机器可读的格式表示日期，可以被浏览器用来启用类似“添加到日历”的功能。使用`abbr`元素的理由只支持旧的浏览器，但随着时间的推移，这变得越来越不相关。目前，大多数现代桌面和移动浏览器都支持语义上正确的`time`元素，即使 IE 9+也支持它。

其余的 HTML 由标准的、众所周知的标签和一些标记组成，例如为了以后选择这些元素而添加的不同 CSS 类。

让我们来看看 JavaScript；首先我们使用标准的 jQuery 文档准备好函数：

```html
$(document).ready(function() {
```

之后，我们将`allowFuture`的设置设置为`true`，以启用`timeago`插件与未来日期一起工作，因为这不是默认设置的：

```html
jQuery.timeago.settings.allowFuture = true;
```

如果`timeago`直接应用于选定的`abbr`或`time`元素，则我们无需做任何其他操作，因为计算是自动完成的：

```html
 $(".timeago").timeago();
 $("time").timeago();
```

您还可以注意到，我们可以直接从 JavaScript 中获取给定日期的文本，并以任何我们认为合适的方式处理它：

```html
$(".page-opened").text( $.timeago(now));
```

## 还有更多...

在处理国际化和本地化应用程序时，会有一些问题。其中之一是`timeago`自动处理的时区支持。我们唯一需要确保的是我们的时间戳遵循**ISO 8601**（[`en.wikipedia.org/wiki/ISO_8601`](http://en.wikipedia.org/wiki/ISO_8601)）时间格式，并具有完整的时区标识符（[`en.wikipedia.org/wiki/ISO_8601#Time_zone_designators`](http://en.wikipedia.org/wiki/ISO_8601#Time_zone_designators)）。另一个经常出现的问题是语言支持，但在这方面我们大多数都有覆盖，因为有许多语言的本地化版本的插件，甚至您可以创建自己的版本并贡献给社区。要做到这一点，您可以使用[`github.com/rmm5t/jquery-timeago/tree/master/locales`](https://github.com/rmm5t/jquery-timeago/tree/master/locales)上托管的代码。

还有一些其他执行类似工作的实现，例如*John Resig*的*pretty date*，可以在他的博客[`ejohn.org/blog/javascript-pretty-date/`](http://ejohn.org/blog/javascript-pretty-date/)上找到。

# 显示数学

在技术写作方面，我们经常希望在页面内显示数学公式。过去，这是通过在服务器上从某种标记创建图像来完成的，甚至是手动使用外部程序创建图像。自 MathML 引入以来，这就不再需要了；这样可以节省我们在解决布局问题上的时间，并使浏览器原生支持显示方程式。在撰写本书时，尽管大多数功能的规范已经可用了几年，但并非所有主要浏览器都支持 MathML。

显示数学

## 准备工作

**数学标记语言**（**MathML**）是一种应用程序描述公式的标准化方式，不仅旨在实现 Web 集成，还可用于其他应用程序。

W3C 维护了一个使用 MathML 的软件列表；可以在[`www.w3.org/Math/Software/`](http://www.w3.org/Math/Software/)找到。规范的几个修订是由工作组完成的（[`www.w3.org/Math/`](http://www.w3.org/Math/)），最新的是第 3 版（[`www.w3.org/TR/MathML3/`](http://www.w3.org/TR/MathML3/)）。

HTML5 增加了在 HTML 内嵌入 MathML 文档的支持。

在这个配方中，我们要描述一个公式，如前面π的连分数，使用 MathML，其中我们有一个不同表示*π*的示例。

## 如何做...

1.  我们将使用一个名为`MathJax`的库，可以从作者的 CDN 检索，也可以单独下载并包含在项目中。

```html
<script type="text/javascript"
      src="img/MathJax.js?config=TeX-AMS-MML_HTMLorMML">
 </script>
```

1.  我们可以通过添加以下 MathML 示例来继续：

```html
<math >
       <mrow>
           <mi>π</mi>
         <mo>=</mo>
         <mfrac>
            <mstyle scriptlevel="0">
              <mn>3</mn>
            </mstyle>
            <mstyle scriptlevel="0">
               <mrow>
                 <mn>7</mn>
                 <mo>+</mo>
                 <mfrac numalign="left">
                   <mstyle scriptlevel="0">
                     <msup><mn>1</mn></msup>
                   </mstyle>
                 </mfrac>
               </mrow>
            </mstyle>
         </mfrac>
      </mrow>
    </math>
```

元素的基本含义将在后面解释，但您可以注意到，示例在很少的嵌套级别后变得非常庞大，很难阅读。这是因为 MathML 从未打算手动创建，而是作为某些应用程序的格式来使用。

1.  那么，如果我们想启用可编辑的标记，对我们来说真正简单的选项是什么？嗯，最简单的选择是一种称为`ASCIIMath`的东西；为了启用它，我们需要改变请求中的`config`参数：

```html
<script type="text/javascript" src="img/MathJax.js?config=AM_HTMLorMML-full"> </script>
```

通常我们使用所有可能的输入格式和呈现选项的版本，但这样我们会遇到 JavaScript 文件大小的问题。

那么，使用`ASCIIMath`有多简单呢？嗯，我们之前解释的表达式可以用一行显示：

```html
 <p>
        `π = 3+1/(7+1/(15+1/(1+1/...)))`
 </p>
```

### 注意

请注意，表达式包含在[P37]"中，否则重音字符将被呈现为 HTML 和 CSS 或任何其他已配置的呈现方法。

## 还有更多...

`ASCIIMath`方法非常简单，并且在 Khan Academy（[`www.khanacademy.org/`](https://www.khanacademy.org/)）和 Math StackExchange（[`math.stackexchange.com/`](http://math.stackexchange.com/)）等主要网站上非常受欢迎。如果您有兴趣了解如何使用`ASCIIMath`，可以在其官方网页[`www1.chapman.edu/~jipsen/mathml/asciimath.html`](http://www1.chapman.edu/~jipsen/mathml/asciimath.html)上获取更多信息。使用`MathJax`，您还可以呈现其他标记格式语言，如 Tex 和 Latex。

### 注意

Tex 是由*Donald Knuth*制作的排版格式，目的是帮助他撰写他的著名书籍。另一方面，Latex 是一种使用 Tex 作为排版格式的文档标记。有关它们的更多信息可以在[`en.wikipedia.org/wiki/TeX`](http://en.wikipedia.org/wiki/TeX)和[`www.latex-project.org/`](http://www.latex-project.org/)上找到。

# 创建一个无限滚动列表

无限滚动列表是由社交网络网站（如 Facebook 和 Twitter）推广的。它们的目标是营造整个可用内容已经加载的假象。此外，通过这种技术，用户试图找到下一页按钮而导致的正常滚动中断可以避免。

同时，我们也希望避免不必要的带宽浪费；这意味着一次加载整套数据不是一个选择。

解决方案是监视用户的滚动并检测页面底部的接近。当用户足够接近底部时，我们可以通过将其附加到当前显示内容的末尾来自动加载下一页的内容。

## 准备工作

您必须已经有一个按页面提供内容的服务。此示例默认情况下可以工作，但要使其完全功能，需要一个实际的 HTTP 服务器，以便 Ajax 请求下一页的工作。

## 如何做...

让我们编写 HTML 页面、CSS 样式和 JavaScript 代码。

1.  创建一个名为`index.html`的文件，其中包含我们示例的完整 HTML、CSS 和 JavaScript 代码。我们需要在 HTML 文档中插入一个 DOCTYPE；否则，浏览器将以“怪癖模式”运行，高度测量函数`$(window).height()`将无法工作。

```html
<!DOCTYPE HTML>
```

我们将在页面中添加一个内容占位符元素：

```html
<div id="content"></div>
```

1.  为了演示目的，我们将添加以下 CSS 代码以使页面可见。可以跳过这个 CSS：

```html
div.page {
   min-height: 1200px;
   width: 800px;
   background-color:#f1f1f1;
   margin:0.3em;
   font-size: 3em;
}
div.error {
   color:#f00;
}
```

1.  最后，我们添加 JavaScript 代码。首先加载 jQuery：

```html
<script src="img/jquery.min.js">
</script>
```

然后我们可以添加我们的脚本：

```html
<script type="text/javascript">
(function() {
```

我们的页面获取器使用 null 错误参数和一个简单的包含页面编号的字符串（例如`Page 1`）来调用回调函数，但它也可以执行 Ajax 请求。有关如何修改它以进行 Ajax 请求的更多信息，请参见以下代码。

这个函数人为地限制了 10 页的内容。第十页后，回调函数将带有错误调用，表示没有更多可用页面：

```html
var page = 1;
function getPage(callback) {
   if (page <= 10)
       callback(null, 'Page ' + page);
   else
       callback("No more pages");
   page += 1;
};
```

1.  我们使用`triggerPxFromBottom`来指定何时开始加载下一页。当只剩下`triggerPxFromBottom`像素要滚动时，将开始加载下一页。它的值设置为`0`；这意味着用户必须到达当前可见页面的末尾才能触发加载过程：

```html
var currentlyLoading = false;
var triggerPxFromBottom = 0;
```

1.  `loadNext`将下一页附加到`#content` div 中。但是，如果回调函数带有错误调用，它将在页面的最后部分下方显示`没有更多内容`。错误事件发生后，将不再加载更多页面。这意味着当`getPage`返回错误时，我们的代码将停止加载新页面。这是期望的行为：

```html
function loadNext() {
   currentlyLoading = true;
   getPage(function(err, html) {
        if (err) {
            $("<div />")
                .addClass('error')
                .html("No more content")
                .appendTo("#content");
        } else {
            $("<div />")
                .addClass('page')
                .html(html).appendTo("#content");
            currentlyLoading = false;
        }
      });
}
```

1.  当页面以任何方式滚动时，将调用此事件处理程序。它计算剩余的滚动像素数。如果像素数足够小且代码当前未加载页面，则调用页面加载函数：

```html
$(window).on('scroll', function() {
    var remainingPx = $(document).height()
        - $(window).scrollTop()
        - $(window).height();
    if (remainingPx <= triggerPxFromBottom
        && !currentlyLoading)
        loadNext();
});
```

1.  最后，我们第一次调用`loadNext()`来加载第一页：

```html
loadNext();
}());
</script>
```

## 它是如何工作的...

浏览器的可见区域（也称为视口）具有自己的尺寸，可以通过调用 jQuery 的`$.fn.height()`函数来获取`$(window)`对象的高度。另一方面，`$(document).height()`为我们提供页面整个内容的高度。最后，`$(window).scrollTop()`给出滚动偏移量。

使用这些函数，我们可以计算剩余需要滚动的像素。然后，我们在用户滚动页面时重新计算和检查这个值。如果值足够小，我们调用我们的加载函数。同时，我们确保在当前加载过程完成之前停止加载新页面。（否则，用户的滚动操作可能会在等待内容加载时加载更多页面。）

## 还有更多...

这是`getPage`函数的一个可能的 Ajax 实现。该函数向在相同域上托管的请求处理程序发送 Ajax 请求，路径为`/pages/<number>`，以检索下一页的 HTML 内容：

```html
function getPage(cb) {
    $.get('/pages/' + page)
        .success(function(html) { cb(null, html); })
        .error(function() { cb("Error"); }
    page += 1;
}
```

要使此版本工作，您需要在服务器端代码中实现请求处理程序。

您的服务器端代码可以返回错误，比如 404，表示没有更多的内容可用。因此，jQuery 永远不会调用我们的成功回调，我们的代码将停止加载新页面。

无限滚动列表配方提供了很好的用户体验，但它有一个重大缺点。我们必须确保`contents`元素下面没有重要的页面内容。这意味着放在底部的页面元素（通常是页脚链接和版权信息）可能无法到达。

# 创建一个可排序的分页表

在创建网站时，我们遇到的最常见任务之一是显示列表和表格。大多数技术都侧重于服务器端的排序、分页和数据呈现。我们的解决方案完全在客户端，适用于小到中等数量的数据。客户端解决方案的主要好处是速度；排序和切换页面将几乎是瞬间完成的。

在这个配方中，我们将创建一个客户端可排序的分页表。

## 准备工作

我们假设一个服务以 JSON 对象的形式提供数据，其中包含一个`data`属性，该属性是一个数组的数组：

```html
{data:[["object1col1", "object1col2"], ["object2col1", "object2col2"],  …]}
```

在我们的示例中，我们将显示附近的人员列表。表中的每个人都有自己的 ID 号码、姓名、年龄、与我们的距离和交通方式。

我们将以公里为单位显示距离，并希望能够按姓氏对人员列表进行排序。

随着表格显示问题迅速超出最初的简单问题，我们不打算构建自己的解决方案。相反，我们将使用可在[`datatables.net/`](http://datatables.net/)上获得的出色的 jQuery DataTables 插件。

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

## 如何做...

让我们编写 HTML 页面、CSS 样式和 JavaScript 代码。

1.  首先，我们将创建一个包含空表的 HTML 页面。我们还将添加一些 CSS 来导入表的基本 DataTables 样式。样式表通常随 DataTables 分发。我们的`index.html`文件如下：

```html
<!DOCTYPE HTML>
<html>
    <head>
        <title>Sortable paged table</title>
        <style type="text/css">
            @import "http://live.datatables.net/media/css/demo_page.css";
            @import "http://live.datatables.net/media/css/demo_table.css";
            #demo, #container {
                width:700px;
            }
            #demo td {
                padding: 0.2em 2em;
            }
            #demo_info {
                width:690px;
                height:auto;
            }
        </style>
    </head>
    <body>
        <div id="container">
            <table id="demo">
                <thead>
                    <tr>
                        <th>Id</th><th>Name</th><th>Age</th><th>Distance</th><th>Transportation</th>
                    </tr>
                </thead>
                <tbody>
                </tbody>
            </table>
        </div>
        <script src="img/jquery.min.js"></script>
        <script type="text/javascript" src="img/jquery.dataTables.min.js"></script>
        <script type="text/javascript" src="img/example.js"></script>
    </body>
</html>
```

示例包括一个链接到官方网站上托管的 DataTables 的缩小版本。

DataTables 插件在表格下方附加了`pager`和`info`元素。因此，我们需要将表格包装在一个`container`元素内。

1.  `example.js`文件如下：

```html
(function() {
    $.extend($.fn.dataTableExt.oSort, {
        "lastname-sort-pre": function (a) {
            return a.split(' ').reverse().join(' ');
        },
        "lastname-sort-asc": function(a, b) { return a < b ? -1 : a > b ? 1 : 0; },
        "lastname-sort-desc": function(a, b) { return a > b ? -1 : a < b ? 1 : 0; },
        "unitnumber-pre": function(a) { return new Number(a.split(' ')[0]); },
        "unitnumber-asc": function(a, b) { return a - b; },
        "unitnumber-desc": function(a, b) { return b - a; }
    } )
    var fetchData = function(callback) {
        var data = [
            [1,'Louis Garland', 12, 32, 'Walking'],
            [2,'Misty Lamar',32, 42, 'Bus'],
            [3,'Steve Ernest',32, 12, 'Cycling'],
            [4,'Marcia Reinhart',42, 180, 'Bus'],
            [5,'Lydia Rouse',35, 31, 'Driving'],
            [6,'Sean Kasten',80,42, 'Driving'],
            [7,'Patrick Sharkey',65,43, 'Cycling'],
            [8,'Becky Rashid',63, 51, 'Bus'],
            [9,'Michael Fort',34, 23, 'Walking'],
            [10,'Genevieve Blaine',55, 11, 'Walking'],
            [11,'Victoria Fry',58, 14, 'Walking'],
            [12,'Donald Mcgary',34, 15, 'Cycling'],
            [13,'Daniel Dreher',16, 23, 'Walking'],
            [14,'Valerie Santacruz',43, 35, 'Driving'],
            [15,'Jodi Bee',23, 13, 'Walking'],
            [16,'Jo Montana',14, 31, 'Cycling'],
            [17,'Stephanie Keegan',53, 24, 'Driving'],
            [18,'Philip Dewey',12, 29, 'Cycling'],
            [19,'Jack Clemons',11, 44, 'Walking'],
            [20,'Steve Serna',14, 60, 'Cycling']
        ];
        callback({data:data});
    };
    window.myTable = {};
    var table = window.myTable.table = $("#demo").dataTable({
        'bLengthChange': false, 'bFilter': false,
        'iDisplayLength': 10,
        'aoColumnDefs':[{             aTargets: [3], // distance
            mRender: function(data) { return data + ' km'; },
            sType: 'unitnumber'
        }, {
            aTargets: [1],
            sType: 'lastname-sort'
        }]
    });
    var setData = window.myTable.setData = function(data) {
        table.fnClearTable();
        table.fnAddData(data);
        table.fnDraw();
    };

    fetchData(function(result) {
        window.myTable.data = result.data;
        setData(result.data);
    });

}());
```

示例中`fetchData`的实现提供了硬编码的示例数据。您可以轻松地将其替换为对您的服务的请求。`setData`函数是一个方便的函数，用于更改表数据——我们将使用相同的脚本，该脚本将调用此函数来设置其自己的数据，用于多个示例。最后，其余的代码是特定于 DataTables，并将在下一节中进行解释。

## 它是如何工作的...

以下图片显示了生成的表格：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_01_02.jpg)

要初始化表格，我们使用`dataTable`初始化函数。我们可以将多个选项传递给函数。例如，我们可以通过将`iDisplayLength`属性的值设置为`10`来指定每页 10 个项目。

因为我们要对**Distance**列（第 3 列）进行稍微不同于仅显示的渲染，所以我们在`aoColumnDefs`选项中为目标列 3 添加了一个项目，为该列设置了一个自定义渲染函数。这是一个简单地将`km`字符串附加到我们的数字的函数；但我们也可以使用更复杂的函数（涉及自定义日期格式化、单位转换等）。

分页在 DataTables 中自动工作——插件附加了一个分页控件，提供对上一页/下一页的访问。排序也大部分自动工作。然而，在我们的特定示例中，尽管**Name**列以"firstname lastname"的格式显示，但我们需要对其进行特殊排序（按姓氏）。为此，我们为该列指定了一个名为`lastname-sort`的自定义排序类型。我们还为**Distance**列指定了一个特殊的排序类型，称为`unitnumber`。

DataTables 允许我们定义自定义排序类型作为插件。自定义排序器具有以下属性：

+   在将其传递给排序器之前，对列值进行预处理的预处理函数

+   一个升序排序函数，根据传递的两个参数的值返回一个值：如果第一个值较小，则返回-1，如果它们相等，则返回 0，如果第一个值较大，则返回 1

+   一个与升序排序函数类似的降序排序函数

这些属性使我们能够按照**Name**列的姓氏进行排序，以及按照**Distance**列的数字进行排序。

## 还有更多...

这里是`fetchData`函数的一个简单 Ajax 替代，向托管在同一域上路径为`/people`的请求处理程序发送一个 Ajax 请求以检索数组数据：

```html
function fetchData(cb) {
    $.get('/people/').success(cb);
}
```

请注意，这种解决方案对于大型数据集效果不佳。虽然现代客户端具有处理大量数据的性能，但带宽也是一个考虑因素。在使用此解决方案之前，应仔细考虑带宽要求和目标客户端（桌面或移动）。

# 创建多选过滤器

在显示表格时的一个常见任务是将表格中的数据过滤为满足某些条件的子集。多选表格过滤器适用于具有有限数量值的列。例如，如果我们有一个包含某些人的数据的表，其中一列是人员使用的交通方式，则在该列上使用的过滤器将是多选过滤器。用户应该能够选择一个或多个交通方式，表视图将显示所有使用所选方式的人员。

## 准备就绪

我们将假设我们正在使用上一个示例中的代码和数据。我们有一个人员列表，他们的交通方式显示在一个可排序、分页的表中，使用 DataTables jQuery 插件。我们将复制上一个示例中的文件，然后对其进行补充。

我们需要过滤的数据已经在`tableData`全局变量中可用；我们可以过滤这些数据，然后使用全局的`tableSetData`函数来显示过滤后的表格。

过滤将在**交通**字段上进行。

## 如何做...

让我们修改上一个代码，向我们的表格添加多选过滤器：

1.  在上一个配方的`index.html`文件中，在开头的`<body>`标签后添加一个多选选择列表：

```html
<select id="list" style="width:100px;"  multiple>
</select>
```

1.  在关闭`</body>`标签之前为`filter.js`添加一个脚本元素：

```html
<script type="text/javascript" src="img/filter.js"></script>
```

1.  我们还将修改`example.js`末尾的`fetchData`调用，以触发自定义事件，通知任何观察者数据已经被获取并设置：

```html
$(function() {
    fetchData(function(result) {
        window.myTable.data = result.data;
        setData(result.data);
        $("#demo").trigger("table:data");
    });
});
```

代码被包装以在页面加载后执行，以便事件触发工作。在页面加载之前，无法触发任何事件。

1.  创建一个名为`filter.js`的文件，并添加以下代码：

```html
(function() {
    function getUnique(data, column) {
        var unique = [];
        data.forEach(function(row) {
            if (unique.indexOf(row[column]) < 0) unique.push(row[column]); });
        return unique;
    }

    function choiceFilter(valueList, col) {
        return function filter(el) {
            return valueList.indexOf(el[col]) >= 0;
        }
    }
    $("#demo").on('table:data', function() {
        getUnique(window.myTable.data, 4).forEach(function(item) {
            $("<option />").attr('value', item).html(item).appendTo("#list");
        });
    })
    $("#list").change(function() {
        var filtered = window.myTable.data.filter(
                choiceFilter($("#list").val(), 4));
        window.myTable.setData(filtered);
    });
}());
```

## 工作原理...

实现多选过滤器的最简单方法是使用多选选择元素。

当数据可用时，我们还需要填充元素。为此，我们在获取数据后触发我们的新自定义事件`table:data`。监听器从数据的**交通**列中提取唯一值，并用这些值为选择列表添加选项。

当选择发生变化时，我们提取所选值（作为数组），并使用`choiceFilter`创建一个新的过滤函数，这是一个高阶函数。高阶函数返回一个新的过滤函数。这个过滤函数接受一个表行参数，并在该行的第四列的值包含在指定列表中时返回`true`。

过滤函数被传递给`Array.filter`；它将此函数应用于每一行，并返回一个仅包含过滤函数返回`true`的行的数组。然后显示过滤后的数据，而不是原始数据。

# 创建范围过滤器

表格也可以通过其数字列进行过滤。例如，给定一个表格，其中每一行都是一个人，其中一列包含有关该人年龄的数据，我们可能需要通过指定年龄范围来过滤该表格。为此，我们使用范围过滤器。

## 准备工作

我们将假设我们正在使用*创建可排序的分页表*配方中的代码和数据。我们有一个人员名单，他们的年龄显示在一个可排序的分页表中，使用 DataTables jQuery 插件。我们将从配方中复制文件，然后添加一些额外的过滤代码。

我们需要过滤的数据已经在`tableData`全局变量中可用；我们可以过滤这些数据，然后使用`tableSetData`全局函数来显示过滤后的表格。

过滤将在**年龄**字段上进行。

## 如何做...

让我们修改上一个代码，向我们的表格添加范围过滤器：

1.  在上一个配方的`index.html`文件中，在开头的`<body>`标签后添加两个输入元素：

```html
 Age: <input id="range1" type="text">
 to <input id="range2" type="text"> <br>       
```

1.  在关闭`</body>`标签之前为`filter.js`添加一个脚本元素：

```html
<script type="text/javascript" src="img/filter.js"></script>
```

1.  最后，我们创建我们的`filter.js`脚本：

```html
(function() {
    function number(n, def) {
        if (n == '') return def;
        n = new Number(n);
        if (isNaN(n)) return def;
        return n;
    }
    function rangeFilter(start, end, col) {
        var start = number(start, -Infinity),
            end = number(end, Infinity);
        return function filter(el) {
            return start < el[col] && el[col] < end;
        }
    }
    $("#range1,#range2").on('change keyup', function() {
        var filtered = window.myTable.data.filter(
            rangeFilter($("#range1").val(), $("#range2").val(), 2));
        window.myTable.setData(filtered);
    });
}());
```

## 工作原理...

过滤数组数据的最简单方法是使用 JavaScript 内置的`Array.filter`函数。这是一个高阶函数；它的第一个参数是一个函数，它接受一个行参数，并在行应该添加到过滤后的数组时返回`true`，或者在行应该被排除时返回`false`。

为了提供这样的功能，我们创建自己的高阶函数。它接受开始和结束范围以及指定的列。返回结果是一个过滤每一行的函数。

为了忽略输入中的空值或无效值，我们使用`number`函数。如果输入字段为空或包含非数字数据，则提供默认值（范围的开始为`-Infinity`，结束为`+Infinity`）。这也使我们能够进行单侧范围过滤。

`Array.filter`函数返回通过过滤器的所有元素的数组。我们在表格中显示这个数组。

# 创建组合复杂过滤器

在显示表格时，我们有时希望使用涉及多个列的多个条件来过滤表格元素。例如，给定一个包含人员信息的人员表，例如他们的姓名、年龄和交通方式，我们可能只想查看年龄大于 30 岁且使用公交车交通的人。我们可能还想按姓名过滤人员。为此，我们必须同时对数据应用多个过滤器，例如年龄范围过滤器、多选过滤器和文本过滤器。这样做的最简单方法是创建一个过滤器组合函数。

## 准备工作

我们假设我们正在使用*创建可排序的分页表*配方中的代码，并且我们将根据前两个配方中描述的方式添加我们的过滤器。这次我们将允许组合过滤器。

## 如何做...

让我们修改前面的代码，向我们的表格添加多个过滤器：

1.  在开头的`<body>`标签后，我们将在页面中添加与过滤相关的输入：

```html
<select id="list" style="width:100px;"  multiple>
</select>
Age: <input id="range1" type="text">
to <input id="range2" type="text">,
Name: <input type="text" id="name"> <br>
```

1.  在关闭`</body>`标签之前添加`filter.js`脚本：

```html
<script type="text/javascript" src="img/filter.js"></script>
```

1.  我们将修改`example.js`，在页面加载后获取数据并在显示数据后触发`table:data`事件：

```html
    $(function() {
        fetchData(function(data) {
            window.myTable.data = data;
            setData(data);
            $("#demo").trigger("table:data");
        });
    });
```

1.  然后我们可以通过组合前两个配方中的代码来创建`filter.js`：

```html
(function() {
    function getUnique(data, column) {
        var unique = [];
        data.forEach(function(row) {
            if (unique.indexOf(row[column]) < 0)
                unique.push(row[column]);
        });
        return unique;
    }
    function choiceFilter(valueList, col) {
        return function filter(el) {
            return valueList.indexOf(el[col]) >= 0;
        }
    }
    function number(n, def) {
        if (n == '') return def;
        n = new Number(n);
        if (isNaN(n)) return def;
        return n;
    }
    function rangeFilter(start, end, col) {
        var start = number(start, -Infinity),
            end = number(end, Infinity);
        return function filter(el) {
            return start < el[col] && el[col] < end;
        };
    }
    function textFilter(txt, col) {
        return function filter(el) {
            return el[col].indexOf(txt) >= 0;
        };
    }
    $("#demo").on('table:data', function() {
        getUnique(window.myTable.data, 4)
        .forEach(function(item) {
            $("<option />").attr('value', item)
                .html(item).appendTo("#list");
        });
    });
    var filters = [null, null, null];
    $("#list").change(function() {
        filters[0] = choiceFilter($("#list").val(), 4);
        filterAndShow();
    });
    $("#range1,#range2").on('change keyup', function() {
        filters[1] = rangeFilter($("#range1").val(),
            $("#range2").val(), 2);
        filterAndShow();
    });
    $("#name").on('change keyup', function() {
        filters[2] = textFilter($("#name").val(), 1); filterAndShow();
    });
    function filterAndShow() {
        var filtered = window.myTable.data;
        filters.forEach(function(filter) {
            if (filter) filtered = filtered.filter(filter);
        });
        window.myTable.setData(filtered);
    };
}());
```

## 它是如何工作的...

与之前的配方一样，我们使用`Array.filter`函数来过滤表格。这次我们连续应用多个过滤器。我们将所有过滤函数存储在一个数组中。

每当输入发生变化时，我们更新适当的过滤函数，并重新运行`filterAndShow()`来显示过滤后的数据。

## 还有更多...

DataTables 是一个高度灵活的表格库，具有许多选项和丰富的 API。更多信息和示例可以在官方网站[`www.datatables.net/`](http://www.datatables.net/)上找到。

# 在 HTML 中显示代码

在 HTML 中显示代码或甚至在 HTML 中显示 HTML 代码是一种常见需求，特别是在技术文档或博客中。这已经做过太多次，通过从格式化代码中获取图像并将其作为页面的一部分。图像中的代码可能不会被搜索引擎捕捉到。此外，它可能限制我们到特定的页面布局或屏幕尺寸，而在今天的移动革命中，这不是一个选择。

## 准备工作

这个配方的唯一要求是要显示的数据需要被正确转义；这意味着`<p>awesome </p>`需要被转换为`&lt;p&gt;awesome &lt;/p&gt;`。这可以在服务器端完成，也可以在保存之前进行转义。

## 如何做...

1.  我们将使用**Google 代码美化**，因为在发言时，这个库在任何 CDN 上都不完全可用；你可以从[`code.google.com/p/google-code-prettify/`](http://code.google.com/p/google-code-prettify/)获取它。

1.  之后，我们可以在`<pre /> <code />`块中添加转义代码：

```html
<body onload="prettyPrint()">
     <div>
          <pre class="prettyprint">
            <code>
              SELECT *
              FROM Book
              WHERE price &lt; 100.00
              ORDER BY name;
            </code>
          </pre>
        </div>
</body>
```

1.  这两个标签中的任何一个都必须包含`prettyprint` CSS 类。除此之外，我们还需要包含`onload="prettyPrint()"`属性。

1.  还有一个选项，可以从 JavaScript 中添加的其他事件监听器中调用`prettyPrint`函数：

```html
<script>
       window.addEventListener('load', function (e){
          prettyPrint();
       }, false);
       </script>
```

## 它是如何工作的...

`prettyprint`类会自动选择所有标记有适当 CSS 类的块，并自动检测所使用的编程语言，然后进行高亮显示。

词法分析器应该适用于大多数语言；在常见语言中，有特定语言的自定义脚本，例如基于 lisp 的语言。

## 还有更多...

因为`prettyprint`自动检测源语言，如果我们想要获得更好的结果，我们可以自行指定。例如，如果我们想要显示 XML，代码将如下所示：

```html
<pre class="prettyprint"><code class="language-xml">...</code></pre>
```

大多数常见语言都有 CSS 类。

`prettyprint`是其中一个较旧的可用脚本，还有一些替代方案可以提供更多的自定义选项和更好的 JavaScript API。

其中一些，如**SyntaxHighliger** ([`alexgorbatchev.com/SyntaxHighlighter/`](http://alexgorbatchev.com/SyntaxHighlighter/))，**Rainbow** ([`craig.is/making/rainbows`](http://craig.is/making/rainbows))，和**Highlight.js** ([`softwaremaniacs.org/soft/highlight/en/`](http://softwaremaniacs.org/soft/highlight/en/))，通常可以在大多数网站上找到。

# 渲染 Markdown

Markdown 是一种流行的轻量级标记语言。这种语言类似于维基标记（在维基百科上使用），强调简单性。它的主要目的是让用户编写纯文本并获得格式化的 HTML 输出。因此，它被流行的网站使用，如 Reddit、Stack Overflow、GitHub，以及各种论坛，作为不太直观的 BBCode 格式的替代品。

Markdown 是为我们的用户启用格式化文本输入的最快方式，而无需将完整的 HTML 编辑器嵌入页面。有多个库可以渲染 markdown；在这个示例中，我们将使用简单的`markdown-js`脚本来实时渲染 markdown。

## 如何做...

渲染 markdown 非常简单。一个最简单的例子如下：

```html
<!DOCTYPE HTML>
<html>
    <head>
        <title>Render markdown</title>
        <style type="text/css">
            #markdown, #render { width: 48%; min-height:320px; }
            #markdown { float: left; }
            #render { float: right; }
        </style>
    </head>
    <body>
        <textarea id="markdown">
# Markdown example.
This is an example of markdown text. We can link to [Google](http://www.google.com)
or insert Google's logo:
![Google Logo](https://www.google.com/images/srpr/logo3w.png)

## Text formatting
We can use *emphasis* or **strong** text,
> insert a quote
etc.</textarea>
        <div id="render"></div>
        <script src="img/jquery.min.js"></script>
        <script src="img/markdown.js"></script>
        <script type="text/javascript">
            function rendermd(val) { $("#render").html(markdown.toHTML($("#markdown").val())); }
            $("#markdown").on('keyup', rendermd); $(rendermd);
        </script>
    </body>
</html>
```

## 它是如何工作的...

当页面加载时，`textarea`元素中的 markdown 文本将被渲染到右侧的`#render`元素中。每次按键都会导致脚本更新渲染的元素。

## 还有更多...

从官方网站[`daringfireball.net/projects/markdown/`](http://daringfireball.net/projects/markdown/)了解更多关于 markdown 格式的信息。

# 自动更新字段

这些天，在字段上自动更新是很常见的，其中一个部分是给定选择的结果，或者显示给定的图像或文本块。其中一个例子是密码强度计算；例如，在谷歌上搜索“货币转换器”会在结果中显示一个框，你可以在其中进行美元和欧元之间的货币转换。以这种方式链接字段是有意义的，当我们有两个或更多逻辑上相关的字段，或者一个是另一个的结果形式时。

为了演示这一点，我们将创建一个温度转换器，其中更新一个字段将导致另一个字段的更改，因为这些值是相关的。

## 准备工作

对于这个示例，我们只需要对 jQuery 有基本的了解，并且有一个简单的公式来在摄氏度和华氏度之间进行转换：

```html
Celsius = (Fahrenheit -32) x (5/9)
```

或者：

```html
Fahrenheit = Celsius  x(9/5) +32
```

## 如何做...

1.  首先，我们将创建 HTML 部分，并创建两个将自动更新并添加适当标签的输入字段：

```html
<div>
<label for='celsius'>C&deg;</label>
<input id='celsius' type='text' /> =
<label for='fahrenheit'>F&deg;</label>
<input id='fahrenheit' type='text' />
</div>
```

1.  之后，我们必须确保已经包含了 jQuery：

```html
<script src="img/jquery.min.js"> </script>
```

1.  接下来，我们可以添加处理字段之间绑定的脚本：

```html
$(document).ready(function() {
  $('#celsius').keyup(function(data) {
  var celsius = new Number(data.currentTarget.value);
  var farenheit =celsius *(9/5) + 32;
    $('#farenheit').val(farenheit);
    });
   $('#farenheit').keyup(function(data) {
       var farenheit = new Number(data.currentTarget.value);
    var celsius =(farenheit-32)*(5/9);
     $('#celsius').val(celsius);
     });
        });
```

这将连接并自动计算温度的前后。

## 它是如何工作的...

首先让我们看一下显示部分，这里没有什么特别的；我们使用一个简单的文本输入类型，并为每个字段添加适当的标签。此外，我们可以使用转义字符`&deg;`来显示度字符。

如果我们看一下 jQuery `keyup`事件，我们会发现它在用户释放键盘上的键时执行。这个事件可以附加在任何 HTML 元素上，但只有在元素处于焦点时才会起作用；因此，它在输入元素上使用起来更有意义。由于`keyup`事件有一个选项来执行一个将接受事件对象的函数，所以对于我们的情况，它如下所示：

```html
$('#celsius').keyup(function(event) {
```

在`event`对象中，我们可以访问触发事件的元素并访问其值：

```html
event.currentTarget.value
```

之后，我们可以进行计算（*摄氏度*(9/5) + 32*）并将结果设置为另一个元素的值，以便在华氏度中显示：

```html
$('#fahrenheit').val(fahrenheit);
```

由于我们希望绑定可以双向工作，我们也可以在华氏度的输入字段上做同样的事情：

```html
$('#farenheit').keyup(function(event) {
```

当然，你需要使用适当的公式（*华氏度-32）*（5/9)*）来返回到摄氏度。

## 还有更多...

这个食谱展示了如何简单地使用 jQuery `event`来实时更新输入文本，它也可以用于创建自动完成框或功能，比如谷歌的即时搜索。这里的想法是，我们可以并且应该为各种 HTML 元素使用单向或双向绑定，特别是当我们谈论派生数据或数据是同一来源的表示时。


# 第二章：图形数据的显示

在本章中，我们将涵盖许多常见的图形任务，例如：

+   创建折线图

+   创建柱状图

+   创建饼图

+   创建面积图

+   显示组合图表

+   创建气泡图

+   显示带有标记位置的地图

+   显示带有路径的地图

+   显示仪表

+   显示树

+   使用 Web 字体的 LED 记分牌

# 介绍

在本章中，我们将介绍使用基于现代 HTML5 标准的各种 JavaScript 库显示图形数据。主要目的是让您对从 2D 图形到 SVG 数据驱动文档的各种视觉部分感兴趣，并通过解决问题的示例来帮助您。

# 创建折线图

线图是最基本的图表类型。它们通过线连接在一起显示一系列数据点。线图通常用于可视化时间序列数据。

有各种库实现这种图表功能，有付费的也有免费的。我们将使用**Flot**图表库。它是免费的，简单易用，过去 4 年来一直在积极开发。它还旨在产生美观的图表。

在这个示例中，我们将制作一个时间序列图表，显示过去 24 小时的室外温度历史。

## 准备工作

我们需要从官方网站[`www.flotcharts.org/`](http://www.flotcharts.org/)下载 Flot，并将内容提取到一个名为`flot`的单独文件夹中。

## 操作步骤...

让我们编写 HTML 和 JavaScript 代码。

1.  创建一个包含图表占位符的基本 HTML 页面。我们还将包括 jQuery（Flot 所需）和 Flot 本身。Flot 需要在占位符 div 中绘制图表画布，因此我们将提供一个。图表占位符需要指定其宽度和高度，否则 Flot 将无法正确绘制：

```html
<!DOCTYPE HTML>
<html>
    <head>
        <title>Chart example</title>
    </head>
    <body>
        <div id="chart" style="height:200px; width:800px;"></div>
        <script src="img/jquery.min.js"></script>
        <script src="img/jquery.flot.js"></script>
        <script type="text/javascript" src="img/example.js"></script>
    </body>
</html>
```

1.  在`example.js`中添加绘制图表的代码。`getData`函数生成一些看起来很真实的随机数据，您可以轻松地用一个从服务器获取数据的函数替换它。数据需要以两个元素数组的形式返回。在这对中，第一个（x 轴）值是标准的 UNIX 时间戳（以毫秒为单位），通常在 JavaScript 中使用，而第二个（y 轴）值是温度。

1.  绘制图表非常简单。`$.plot`函数在指定的占位符中绘制包含指定图表选项的指定系列的图表：

```html
$(function() {    
    function getData(cb) {
        var now  = Date.now();
        var hour = 60 * 60 * 1000;
        var temperatures = [];
        for (var k = 24; k > 0; --k)
            temperatures.push([now - k*hour,
                Math.random()*2 + 10*Math.pow((k-12)/12,2)]);
        cb({data:temperatures});
    }
    getData(function(data) {
        $.plot("#chart", [data], {xaxis: {mode: 'time'}});
    });
});
```

就是这样！以下是最终的结果：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_02_01.jpg)

## 它是如何工作的...

`$.plot`函数接受三个参数：

+   占位符选择器。这是 Flot 将绘制图表的地方。

+   要绘制的系列数组。Flot 可以同时在同一图表上绘制多个系列。每个系列都是一个对象，至少必须包含`data`属性。该属性是一组两个元素数组，它们是系列的 x 和 y 值。其他属性允许我们控制特定系列的绘制方式-这些将在下一个示例中更详细地探讨。默认情况下，Flot 使用预设颜色绘制常规线图。

+   一个包含广泛的图表绘制选项的`options`对象，用于图表标签、轴、图例和网格。这些选项也将在下一个示例中探讨。

在这个示例中，我们为 x 轴指定了“时间”模式。这会导致 Flot 在我们的轴上适当地标记小时、天、月或年（取决于数据的时间跨度）。

## 还有更多...

以下是`getData`函数的简单 Ajax 替代，发送一个 Ajax 请求到同一域上的路径`/chart`上托管的请求处理程序以检索图表数据：

```html
function getData(cb) {
    $.get('/chart').success(cb);
}
```

# 创建柱状图

与通常用于显示平均值或瞬时值的折线图不同，条形图用于可视化属于离散组的数据。例如每日、每月和每周的销售量（组是天、月和周），每个用户的页面访问量，每辆车的燃料消耗等。

Flot 图表库还可以绘制条形图。在这个示例中，我们将可视化过去七天的每日销售量。我们还将分别显示来自不同产品的销售量，堆叠在彼此之上。

## 准备工作

我们需要从官方网站[`www.flotcharts.org/`](http://www.flotcharts.org/)下载 Flot，并将内容提取到名为`flot`的单独文件夹中。

## 如何做...

让我们修改折线图代码，以绘制我们的柱状图。

1.  首先，我们将复制上一个折线图示例中的相同 HTML 页面，但是我们会做一些更改。为了绘制堆叠条形图，我们需要堆叠插件，它位于`jquery.flot.stack.js`文件中。图表占位符的高度增加以获得对各个堆叠条形图的更好概览：

```html
<!DOCTYPE HTML>
<html>
    <head>
        <title>Chart example</title>
    </head>
    <body>
        <div id="chart" style="height:300px; width:800px;"></div>
        <script src="img/jquery.min.js"></script>
        <script src="img/jquery.flot.js"></script>
        <script src="img/jquery.flot.stack.js"></script>
        <script type="text/javascript" src="img/example.js"></script>
    </body>
</html>
```

1.  然后我们将创建`example.js`脚本：

```html
$(function() {    
    var day = 24 * 60 * 60 * 1000;
    function getData(cb) {
        var now  = new Date();
        now = new Date(now.getYear(), now.getMonth(), now.getDate()).getTime();
        var products = [];
        for (var product = 1; product < 4; ++product) {
            var sales = { label: "Product " + product, data: [] };
            for (var k = 7; k > 0; --k)
                sales.data.push([now - k*day, Math.round(Math.random()*10)]);
            products.push(sales);
        }
        cb({series:products});
    }

    getData(function(data) {
        $.plot("#chart", data.series, {
            series: {
                stack: true, lines: { show: false },
                bars: { show: true, barWidth: 0.8 * day, align:'center' }
            }, xaxis: {mode: 'time'}
        });
    });
});
```

代码在下一节中进行了解释。以下是生成的图表的外观：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_02_02.jpg)

## 它是如何工作的...

与以前的示例一样，`$.plot`函数接受三个参数。第一个参数是图表占位符，第二个是数据，第三个是包含图表选项的对象。

以下是我们输入数据的方案：

```html
[
  {label: "Product 1", data:[
    [timestamp, value],
    [timestamp, value], …]},
  {label: "Product 2", data: […]},
  {label: "Product 3", data: […]}
]
```

输入数据是一个系列的数组。每个系列代表一个产品的销售情况。系列对象有一个`label`属性表示产品，以及一个`data`属性，它是一个数据点的数组。每个数据点都是一个二维数组。此数组的第一个元素是日期，表示为以毫秒为单位的 UNIX 时间戳——即当天的确切开始。第二个元素是当天的销售数量。

为了更轻松地操作日期，我们定义一个表示一天中毫秒数的变量。稍后，我们将使用此变量来定义图表中条形的宽度。

Flot 会自动从预定义列表中为我们选择系列颜色（但是，我们也可以指定我们需要的颜色，我们将在下面的示例中看到）。

代码中指定了几个系列选项。我们通过将`stack`属性的值设置为`true`来告诉 Flot 堆叠我们的系列。我们还确保隐藏了默认情况下会显示的线条。

为了使柱形图的中心与日期的 x 轴刻度对齐，我们将`bar`对象中的`align`属性的值设置为`center`。

我们输入数据中的每个系列都有一个标签。因此，Flot 会自动生成一个放置在右上角的图例。

Flot 会自动选择轴的边界，但可以使用`options`对象来控制它们。

# 创建饼图

当可视化比例或百分比作为一个整体时，通常使用饼图。饼图足够简单，可以自己绘制；但是，为了获得更灵活和美观的结果，我们将使用 Flot 图表库及其饼图插件。

Flot 的饼图插件可以显示带有图例或不带图例的饼图，并具有广泛的选项来控制标签的位置。它还能够渲染倾斜的饼图和甜甜圈图。还包括交互式饼图的支持。

在这个示例中，我们将制作一个关于访问者浏览器的饼图。

## 准备工作

我们需要从官方网站[`www.flotcharts.org/`](http://www.flotcharts.org/)下载 Flot，并将内容提取到名为`flot`的单独文件夹中。

## 如何做...

让我们编写 HTML 和 JavaScript 代码。

1.  在`index.html`中创建以下 HTML 页面：

```html
<!DOCTYPE HTML>
<html>
    <head>
        <title>Chart example</title>
    </head>
    <body>
        <div id="chart" style="height:600px; width:600px;"></div>
        <script src="img/jquery.min.js"></script>
        <script src="img/jquery.flot.js"></script>
        <script src="img/jquery.flot.pie.js"></script>
        <script type="text/javascript" src="img/example.js"></script>
    </body>
</html>
```

页面中有一个图表的占位符元素。

Flot 依赖于包含的 jQuery 库。要绘制饼图，我们需要添加 Flot 的饼图插件。

1.  创建`example.js`脚本：

```html
$(function() {    
    var day = 24 * 60 * 60 * 1000;
    function getData(cb) {
        var browsers = [
            {label: 'IE', data: 35.5, color:"#369"},
            {label: 'Firefox', data: 24.5, color: "#639"},
            {label: 'Chrome', data: 32.1, color: "#963"},
            {label: 'Other', data: 7.9, color: "#396"}
        ];
        cb(browsers);
    }

    getData(function(data) {
        $.plot("#chart", data, {
        series: {
            pie: {
                show: true,
                radius: 0.9,
                label: {
                    show: true,
                    radius: 0.6,
                },
                tilt: 0.5
            }
        },
        legend: { show: false }
        });
    });
});
```

它生成以下饼图：

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_02_03.jpg)

## 工作原理...

Flot 要求饼图切片数据以对象数组的形式提供。每个对象包含以下两个属性：

+   `label`：这是切片的标签

+   `data`：这是切片的编号——一个可以是任何值的数字（不需要是百分比）

在调用`$.plot`时，第一个参数是饼图的占位符元素，第二个是饼图切片的数组，第三个包含饼图选项。

为了显示饼图，最小的`options`对象如下：

```html
{pie: {show: true}}
```

自定义默认饼图，我们使用以下内容添加到`pie`属性中：

+   `radius`：指定饼图的大小，以画布的百分比表示。

+   `label`：`show`（布尔值）属性设置为`true`以显示饼图标签，`radius`属性控制标签与饼图中心的距离。

+   `tilt`：这会对饼图进行 3D 倾斜。如果省略，Flot 将渲染一个无标题的圆形饼图。

## 还有更多...

还有更多可用的选项，例如以下内容：

+   `innerRadius`：将其设置为值，例如`0.5`，以创建一个圆环图。

+   `combine`：此属性用于将较小的切片合并为单个切片。它是一个包含以下属性的对象：

+   `threshold`：设置为整体的百分比，例如，`0.1`

+   `color`：这是用于渲染“其他”部分的颜色，例如，`#888`

有关更多详细信息，请参阅[`people.iola.dk/olau/flot/examples/pie.html`](http://people.iola.dk/olau/flot/examples/pie.html)上的饼图示例。

# 创建面积图

在需要在线图的位置上堆叠多个结果时，通常使用面积图。它们也可以在某些情况下用于增强图表的视觉吸引力。

这个示例将展示一个使用面积图来增强视觉吸引力的例子：显示海拔数据。

假设我们需要可视化一个 8 公里的下坡徒步旅行，然后是 12 公里的平地行走的海拔。我们还想标记图表的“山脉”部分。最后，我们希望海拔线下的区域以一种让人联想到颜色浮雕地图的方式填充，低海拔使用绿色，中等海拔使用黄色，高海拔使用白色。

## 准备工作

在这个示例中，我们还将使用 Flot 图表库，因此我们需要从官方网站[`www.flotcharts.org/`](http://www.flotcharts.org/)下载 Flot 并将内容提取到名为`flot`的单独文件夹中。

## 如何操作...

1.  我们的 HTML 文件需要一个图表占位符元素和必要的脚本。以下是内容：

```html
<!DOCTYPE HTML>
<html>
    <head>
        <title>Chart example</title>
        <style type="text/css">
            #chart { font-family: Verdana; }
        </style>
    </head>
    <body>
        <div id="chart" style="height:200px; width:800px;"></div>
        <script src="img/jquery.min.js"></script>
        <script src="img/jquery.flot.js"></script>
        <script type="text/javascript" src="img/example.js"></script>
    </body>
</html>
```

1.  我们将在包含以下代码的`example.js`脚本中绘制图表：

```html
$(function() {    
    function getData(cb) {
        var altitudes = [];
        // Generate random but convincing-looking data.
        for (var k = 0; k < 20; k += 0.5)
            altitudes.push([k, Math.random()*50 + 1000*Math.pow((k-15)/15,2)]);
        cb(altitudes);
    }

    getData(function(data) {
        $.plot("#chart", [{data: data}], {
            xaxis: {
                tickFormatter: function(km) { return km + ' km'; }
            },
            lines: {
                fill: true,
                fillColor: {colors: ["#393", "#990", "#cc7", "#eee"] }
            },
            grid: {
                markings: [{ xaxis: { from: 0, to: 8 }, color: "#eef" }]
            }
        });
    });
});
```

以下是我们的结果：

![如何操作...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_02_04.jpg)

海拔线下的区域以一种让人联想到颜色浮雕的方式填充。山区部分由`markings`对象创建的蓝色区域标记。

## 工作原理...

与我们所有的示例一样，`example.js`中的`getData`函数生成随机数据，然后调用提供的回调函数以使用数据。我们可以很容易地编写一个替代函数，而不是从服务器获取数据，而是使用 jQuery。

单次调用`$.plot`将绘制面积图。第一个参数是目标容器。第二个参数是要绘制的系列数组——在这种情况下只有一个。

第三个参数更复杂。它包括以下部分：

+   `xaxis`属性指定我们的 x 轴的行为。我们通过提供自己的刻度格式化程序来覆盖默认的刻度标签。此格式化程序在刻度值后添加`"km"`字符串。

+   `lines`属性指定我们将使用填充线图。我们希望有类似山的渐变填充效果，因此我们指定了一个包含 CSS 颜色字符串数组的渐变对象，即`{color: [颜色数组]}`。

+   `grid`属性用于在我们的图表上标记山脉段。我们指定它应该包含一个 x 轴段的标记，跨越 0 到 8 公里的范围，并具有浅蓝色。

## 还有更多...

Flot 有更多的面积图选项——它们可以在随分发的 API 文档中找到。

要使用这个配方，我们需要从服务器提供我们自己的数据数组。以下是`getData`函数的一个简单 Ajax 替代，向托管在同一域上的请求处理程序发送 Ajax 请求，以检索图表数据的路径`/areachart`。这很简单：

```html
function getData(cb) {
    $.get('/areachart').success(cb);
}
```

# 显示组合图表

组合图表是具有多个 x 或 y 轴的图表，并且可能具有多种类型的系列（线条、条形和面积）。有时，我们可能希望在单个图表上呈现多种异构类型的数据，通常是为了可视化其相关性。

在这个配方中，我们将尝试通过在单个图表上呈现温度和海拔来可视化一次登山。高度系列将是一个具有渐变颜色的面积图，让人联想到地形图，但温度系列将是一条线状图，如果高于摄氏 19 度则为红色，如果低于摄氏 19 度则为蓝色。

为了做到这一点，我们需要一个能够处理两个 y 轴的图表库。我们将使用 Flot 图表库，因为它能够显示具有两个或多个 x 或 y 轴的图表。

## 准备工作

就像在以前的配方中一样，我们需要从官方网站[`www.flotcharts.org/`](http://www.flotcharts.org/)下载 Flot 并将内容提取到名为`flot`的单独文件夹中。

## 如何做...

让我们编写 HTML 和 JavaScript 代码。

1.  我们的 HTML 文件需要一个图表占位符、jQuery、Flot 和我们的示例脚本。这次我们还需要`threshold`插件，以便有两种温度颜色。以下是内容：

```html
<!DOCTYPE HTML>
<html>
    <head>
        <title>Chart example</title>
        <style type="text/css">
            #chart { font-family: Verdana; }
        </style>
    </head>
    <body>
        <div id="chart" style="height:200px; width:800px;"></div>
        <script src="img/jquery.min.js"></script>
        <script src="img/jquery.flot.js"></script>
        <script src="img/jquery.flot.threshold.js"></script>
        <script type="text/javascript" src="img/example.js"></script>
    </body>
</html>
```

1.  我们的图表是在`example.js`中使用以下代码绘制的：

```html
$(function() {    
    function getData(cb) {
        var altitudes = [], temperatures = [];
        // Generate random but convincing-looking data.
        for (var k = 0; k < 20; k += 0.5) {
            altitudes.push([k, Math.random()*50 + 1000*Math.pow((k-15)/15,2)]);
            temperatures.push([k, Math.random()*0.5 + k/4 + 15]);
        }
        cb({alt:altitudes, temp:temperatures});
    }

    getData(function(data) {
        $.plot("#chart", [
           {
             data: data.alt, yaxis:1,
             lines: {fill:true, fillColor: {
             colors: ["#393", "#990", "#cc7", "#eee"] } }
                },
           {
             data: data.temp, yaxis:2, color: "rgb(200, 20, 30)",
             threshold: { below: 19, color: "rgb(20, 100, 200)" }
                }
            ], {
            yaxes: [ { }, { position: "right"}],
            xaxis: {
                tickFormatter: function(km) { return km + ' km'; }
            },
            grid: {
                markings: [{ xaxis: { from: 0, to: 8 }, color: "#eef" }]
            }
        });
    });
});
```

以下屏幕截图显示了最终结果：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_02_05.jpg)

## 它是如何工作的...

使用`getData`函数，我们为绘图生成了两个系列，一个包含温度，另一个包含海拔。

在绘制图表时，我们首先调用`getData`函数。在提供的回调中，我们将数据传递给`$.plot`函数，该函数接受目标容器元素、系列数组和绘图选项。

数组中的第一个系列包含高度数据。我们有两个 y 轴，所以我们需要声明我们将用于该系列的 y 轴——第一个 y 轴。其余的参数声明了填充渐变；有关更多信息，请参阅*创建面积图*配方。

第二个系列使用第二个 y 轴。新的是`threshold`属性。它指定对于低于 19 度的值，线的颜色应该不同（蓝色而不是红色）。

我们将在`options`对象中通过指定`yaxes`属性（注意名称中的复数形式）来配置第二个 y 轴。该属性是一个包含 y 轴选项的数组。我们将使用第一个轴的默认值，因此为空对象。我们将把第二个轴放在右侧。

x 轴的单位是公里，因此我们的`tickformatter`函数在数字后添加字符串`" km"`。

最后，我们用网格标记选项将“山脉部分”（从 0 到 8 公里）标记为蓝色。

## 还有更多...

这里是`getData`函数的一个简单 Ajax 替代，向托管在同一域上的请求处理程序发送 Ajax 请求，以检索图表数据的`/charts`路径。此处理程序应返回以下格式的对象：

```html
{alt: data1, temp: data2}
```

其中`data1`和`data2`是包含数据的二维数组。

```html
function getData(cb) {
    $.get('/charts').success(cb);
}
```

# 创建气泡图

气泡图可以将值集显示为圆圈。它们适用于大小在 10 到 100 之间的数据集。它们特别适用于可视化数量级差异的值，并且可以在这些情况下取代饼图。

由于气泡图更复杂且稍微不太常见，我们需要一个灵活的库来绘制它们。优秀的 D3 库（[`d3js.org/`](http://d3js.org/)）非常适合；它提供了一组工具（核心数据驱动 DOM API 加上“pack”数据布局），可以实现气泡图的创建。

我们将绘制一个气泡图，显示来自引荐网站的访问者数量。

## 操作步骤如下...

让我们编写 HTML 和 JavaScript 代码。

1.  我们将创建一个包含图表占位符的 HTML 页面。我们将包括图表库 D3，以及将从我们的`example.js`文件绘制气泡图的代码：

```html
<!DOCTYPE HTML>
<html>
    <head>
        <title>Chart example</title>
        <style type="text/css">
            #chart text { font-family: Verdana; font-size:10px; }
        </style>
    </head>
    <body>
        <div id="chart"></div>
        <script src="img/d3.v2.js?2.9.5"></script>
        <script type="text/javascript" src="img/example.js"></script>
    </body>
</html>
```

1.  然后我们将在`example.js`中添加以下代码：

```html
(function() {
var getData = function(cb) {
    cb({children:[
        {domain: 'google.com', value: 6413},
        {domain: 'yahoo.com', value: 831},
        {domain: 'bing.com', value: 1855},
        {domain: 'news.ycombinator.com', value: 5341},
        {domain: 'reddit.com', value: 511},
        {domain: 'blog.someone.com', value: 131},
        {domain: 'blog.another.com', value: 23},
        {domain: 'slashdot.org', value: 288},
        {domain: 'twitter.com', value: 327},
        {domain: 'review-website.com', value: 231}
    ]});
}

// r is the dimension of the bubble chart
var r = 640,
    fill = d3.scale.category20c();

// create the visualization placeholder
var vis = d3.select("#chart").append("svg")
    .attr("width", r)
    .attr("height", r)
    .attr("class", "bubble");

// create a pack layout for the bubbles
var bubble = window.bubble = d3.layout.pack()
    .sort(null)
    .size([r, r])
    .padding(1.5);

    getData(function(json) {
        // Process the data with the pack layout
        var data = bubble.nodes(json);
        // Create a node for every leaf data element
        var selection = vis.selectAll("g.node")
            .data(data.filter(function(d) { return !d.children; }));
        var node = selection.enter().append("g");

        node.attr("class", "node");
        node.append("title")
            .text(function(d) { return d.domain });
        node.attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
        node.append("circle")
            .attr("r", function(d) { return d.r; })
            .style("fill", function(d) { return fill(d.domain); });
        node.append("text")
            .attr("text-anchor", "middle")
            .attr("dy", ".3em")
            .text(function(d) { return d.domain.substring(0, d.r / 3); });
    });
}());
```

在接下来的部分中，我们将解释 D3 的工作原理以及我们如何使用它来创建气泡图：

## 工作原理...

与大多数其他图表库不同，D3 没有任何预定义的图表类型，可以绘制。相反，它提供了一组模块化工具，您可以自由混合和匹配，以创建任何类型的数据驱动文档。

然而，D3 包含一些非常特定于可视化的工具。

例如，`d3.scale.category20c`创建一个序数比例尺。序数比例尺将输入值映射到一组离散的输出值。在这种情况下，离散的值集是一组预定义的 20 种输出颜色。比例尺是一个函数——它将输入值映射到输出值。我们可以明确指定哪些输入值映射到哪些输出值，但如果我们不这样做，它会根据使用情况进行推断。在我们的情况下，这意味着第一个域名将映射到第一个颜色，第二个将映射到第二个，依此类推。

其他工具包括类似于 jQuery 的 DOM 选择工具，在我们的示例中，我们使用它们将 SVG 元素添加到我们的图表占位符中。

另一个例子是 D3 布局。要绘制气泡图，我们需要一个包布局。布局根据某些规则和约束将一组具有值的对象映射到一组输出坐标。一个常见的例子是**力布局**，它是一种通过在图形节点之间迭代应用虚拟力来排列对象的图形布局。

我们使用的是将对象层次化地打包成圆圈的包布局。我们的数据是平面的，因此包布局仅用于自动排列我们的圆圈。创建一个包布局并将其分配给`bubble`变量。

包布局通过将`bubble.nodes`函数应用于输入数据来工作。此函数查找输入数据中每个对象中的`value`属性。基于这个属性（它将其视为相对半径）和布局的大小，它将以下属性添加到我们的数据中：x、y 和 r，并返回结果数组。

此时，我们已经有了绘制气泡图所需的大部分数据：我们有气泡的位置和尺寸。现在我们需要做的就是将它们转换为适当的 SVG 元素。我们用来做这个的工具是 D3 的`selectAll`函数。

与 jQuery 选择器不同，D3 的`selectAll`可以用于在文档和数据对象之间维护双向映射。我们使用选择的`.data`函数指定映射到我们选择的数据数组。

声明了这个映射之后，我们可以决定当一个元素被添加到我们的数据数组时会发生什么，使用`.enter`函数。在我们的示例中，我们声明一个新的 SVG 图形元素被添加到 SVG 画布中，并将该声明分配给`node`变量。

需要注意的是，我们的节点变量并不持有 SVG 元素；相反，它是未来将创建的节点集合中每个图形 SVG 元素的选择，每当新的数据元素“进入”选择时，节点上的操作指定将在每个添加的 SVG 元素上执行的操作。

我们指定每个节点都将有一个`title`属性（将在鼠标悬停时显示）。此标题的内部文本取决于数据数组中的特定元素。为了描述这一点，我们将一个函数作为`.text()`调用的参数传递。传递函数的第一个参数将是特定节点的数据元素，返回的值应该是将设置为标题的文本。

类似地，我们将我们的气泡移动到由包布局计算的位置。之后，我们添加一个由包布局计算的半径的圆和颜色比例尺来生成圆的颜色。

最后，以相同的方式附加文本节点。

以下是结果的样子：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_02_06.jpg)

## 还有更多...

此示例使用 SVG（可缩放矢量图形）标记来呈现可视化。大多数现代浏览器都支持 SVG，但 IE9 之前的 Internet Explorer 版本不支持。但是，D3 不仅限于 SVG，它还能够生成 HTML 元素，这些元素可以用作 IE 旧版本的替代品。

# 展示带有标记位置的地图

谷歌地图的崛起和他们出色的 API 使地图嵌入网站变得流行起来。嵌入式地图有各种用途：显示用户去过的地方，显示事件的位置，显示商店的位置等等。地图可以与我们网站上显示的每个文本地址一起显示。

在这个教程中，我们将制作一个简单的地图，并在上面标记一个位置。为此，我们将使用**Leaflet**库（[`leafletjs.com/`](http://leafletjs.com/)），这是一个广泛被 Flickr、FourSquare、Craigslist、Wikimedia 和其他流行网站使用的知名库。

我们将显示一个**OpenStreetMap**地图图层。OpenStreetMap（[`www.openstreetmap.org/`](http://www.openstreetmap.org/)）是一个类似维基百科的免费协作创建的街道地图，覆盖范围广泛。

我们还将添加一个描述气球，当点击标记时会显示。

## 如何做...

让我们编写 HTML 和 JavaScript 代码。

1.  在我们的 HTML 文件中添加 Leaflet 的样式表，以及 IE8 和更旧版本所需的条件额外 CSS：

```html
<link rel="stylesheet" href="http://cdn.leafletjs.com/leaflet-0.4/leaflet.css" />
 <!--[if lte IE 8]>
     <link rel="stylesheet" href="http://cdn.leafletjs.com/leaflet-0.4/leaflet.ie.css" />
<![endif]-->
```

1.  在我们的脚本中包含 Leaflet 库 JS 文件：

```html
<script src="img/leaflet.js"></script>
```

1.  在我们的页面上放置地图的占位符。我们还必须指定它的高度，否则 Leaflet 将无法正常工作：

```html
<div id="map" style="height:200px;"></div>
```

1.  通过添加`example.js`来添加我们的 JS 代码：

```html
<script src="img/example.js"></script>
```

1.  最后，在`example.js`中添加创建地图的代码：

```html
var map = L.map('map').setView([51.505, -0.09], 13);

L.tileLayer('http://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{
        attribution:'Copyright (C) OpenStreetMap.org',
        maxZoom:18
        }).addTo(map);

var marker = L.marker([51.5, -0.09]).addTo(map);
marker.bindPopup("<b>Hello world!</b><br>I am a popup.").openPopup();
```

## 它是如何工作的...

大多数地图库通过使用瓦片图像图层来绘制它们的地图。瓦片图像图层是具有预定义固定大小的图像网格。这些图像是地图的切片部分，已经预先渲染并托管在瓦片服务器上。

地图使用称为**缩放级别**的离散缩放点。不同的缩放级别使用不同的瓦片图像。

在某些情况下，特别是在高缩放级别下，服务器会根据需要在空间超出合理存储空间大小的情况下动态渲染瓦片。例如，OpenStreetMap 使用 19 个缩放级别。第一级使用单个瓦片，第二级将此瓦片分成四个瓦片，第三级使用 16 个瓦片，依此类推。在第 19 个缩放级别，有 480 亿个瓦片，假设平均瓦片大小为 10KB，那将需要 480TB 的存储空间。

当用户滚动地图时，以前未加载的区域的瓦片会动态加载并显示在容器中。当用户更改缩放级别时，旧缩放级别的瓦片将被移除，新的瓦片将被添加。

在我们的`example.js`文件中，我们使用 Leaflet 的函数（在`L`命名空间对象中找到）来创建地图。地图初始化为位于伦敦的中心，使用代表`[纬度，经度]`对的数组。另一个参数是缩放级别，设置为`13`。

之后添加了一个瓦片图层。我们指定 OpenStreetMap 使用的瓦片服务器模式如下：

```html
http://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png
```

其中`s`是服务器字母（`a`，`b`或`c`），`z`是缩放级别，`x`和`y`是瓦片的离散坐标。例如，在缩放级别 1 时，`x`和`y`中的每一个可以是`1`或`2`，而在缩放级别 2 时，它们可以在 1 到 4 的范围内。我们还指定了可用的最大缩放级别。

我们向地图添加自己的标记。初始化参数是一个`[纬度，经度]`对。之后，我们可以在标记内部添加一个弹出窗口，显示文本和/或任意 HTML。我们立即打开弹出窗口。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_02_07.jpg)

使用 Leaflet 绘制的地图

# 显示带有路径的地图

在显示地图时，有时我们可能希望显示的不仅仅是位置。除了标记，另一个最常见的地图叠加层是路径和区域。

在这个食谱中，我们将创建一个显示路径和区域的地图。

## 如何做...

让我们编写 HTML 和 JavaScript 代码。

1.  就像在*显示带有标记位置的地图*食谱中一样，我们需要包含适当的 CSS 和脚本。以下是一个示例 HTML 文件：

```html
<!DOCTYPE HTML>
<html>
    <head>
        <title>Map example</title>
        <link rel="stylesheet" href="http://cdn.leafletjs.com/leaflet-0.4/leaflet.css" />
        <!--[if lte IE 8]>
        <link rel="stylesheet" href="http://cdn.leafletjs.com/leaflet-0.4/leaflet.ie.css" />
        <![endif]-->
    </head>
    <body>
        <div id="map" style="height:480px; width:640px;"></div>
        <script src="img/jquery.min.js"></script>
        <script src="img/leaflet.js"></script>
        <script type="text/javascript" src="img/example.js"></script>
    </body>
</html>
```

1.  然后我们可以将我们的代码添加到`example.js`中：

```html
var map = L.map('map').setView([52.513, -0.06], 14)

L.tileLayer('http://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{
    attribution:'Copyright (C) OpenStreetMap.org',
    maxZoom:18
}).addTo(map);

var polyline = L.polyline([
    [52.519, -0.08],
    [52.513, -0.06],
    [52.52, -0.047]
]).addTo(map);

var polygon = L.polygon([
    [52.509, -0.08],
    [52.503, -0.06],
    [52.51, -0.047]
], {
    color:"#f5f",
    stroke: false,
    fillOpacity:0.5
}).addTo(map);
```

## 它是如何工作的...

我们使用`L.map`函数创建地图，并使用`setView`在指定的`[纬度，经度]`数组和缩放级别上设置地图的位置。我们还添加了标准的 OpenStreetMap 瓦片图层。

首先，我们创建并添加一个标准折线。由于我们没有指定任何选项，Leaflet 对颜色、不透明度、边框等都使用了合理的默认值。折线构造函数采用`[纬度，经度]`对的数组，并绘制通过它们的顶点的线。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_02_08.jpg)

之后，我们创建一个稍微定制的多边形。与折线构造函数一样，多边形也采用`[纬度，经度]`对的数组。此外，我们自定义了背景颜色，删除了多边形的边框，并指定了多边形的不透明度为 50%。

# 显示表盘

模拟表盘对于可视化数值在预定义最小值和最大值之间并随时间变化的数据非常有用。示例包括燃料量，当前速度，磁盘空间，进程和内存使用等。

在这个食谱中，我们将为 jQuery 制作一个非常灵活的、数据驱动的表盘插件。然后我们将使用这个插件来显示模拟汽车速度表。以下是速度表的外观：

![显示表盘](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_02_09.jpg)

该食谱广泛使用了 HTML5 的画布。

## 如何做...

让我们为我们的示例编写 HTML 代码，表盘插件和将它们联系在一起的代码。

1.  制作一个简单的 HTML 文件，其中包含我们的表盘的画布：

```html
<!DOCTYPE HTML>
<html>
    <head>
        <title>Gauge example</title>
    </head>
    <body>
        <canvas id="gauge" width="400" height="400"></canvas>
        <script src="img/jquery.min.js"></script>
        <script type="text/javascript" src="img/example.js"></script>
    </body>
</html>
```

1.  然后在`example.js`中编写我们的表盘插件代码：

```html
(function($) {
```

1.  这是一个支持函数，它替换了`Array.forEach`，可以在单个项目和数组上工作。我们的表盘将支持多个条纹、指针和刻度，但当提供单个条纹时，它也应该能够工作：

```html
    function eachOrOne(items, cb) {
        return (items instanceof Array ? items : [items]).map(cb);
    }
```

1.  以下是一个通用函数，它围绕中心`c`（角度量为`a`）旋转点`pt`。方向是顺时针的：

```html
    function rotate(pt, a, c) {
        a = - a;
        return { x: c.x + (pt.x - c.x) * Math.cos(a) - (pt.y-c.y) * Math.sin(a),
                 y: c.y + (pt.x - c.x) * Math.sin(a) + (pt.y-c.y) * Math.cos(a) };
    }
```

1.  以下是我们的表盘插件

```html
    $.gauge = function(target, options) {
        var defaults = {
            yoffset: 0.2,
            scale: {
                type: 'linear',
                values: [1, 200],
                angles: [0, Math.PI]
            },
            strip: {
                scale: 0, radius: 0.8, width: 0.05,
                color: "#aaa", from: 0, to: 200
            },           
            ticks: {
                scale: 0, radius: 0.77, length: 0.1, width: 1, color: "#555",
                values: {from: 0, to:200, step: 10},
            },           
            labels: {
                scale: 0, radius: 0.65,
                font: '12px Verdana', color: "#444",
                values: {from: 0, to:200, step: 20}
            },
            needle: {
                scale: 0, length: 0.8, thickness: 0.1,
                color: "#555", value: 67
            }
        };
```

默认情况下，我们的表盘具有以下特点：

+   从顶部偏移 20%

+   具有值范围 1 到 200 的线性刻度，角度范围 0 到 180 度，

+   具有 80%或总半径宽度为总半径 5%的单条带，颜色为灰色，范围从 0 到 200。

+   具有一个从 0 到 200 的单个`ticks`数组，步长为 10

+   具有从 0 到 200 的标签，步长为 20

+   具有单个指针设置为值 67

1.  我们允许用户覆盖选项，并指定之前提到的任何组件的多个：

```html
        var options = $.extend(true, {}, defaults, options);
        for (var key in defaults) if (key != 'yoffset')
            options[key] = eachOrOne(options[key], function(item) {
                return $.extend(true, {}, defaults[key], item);
            });        
        var $target = $(target);
        var ctx = $target[0].getContext('2d');
```

1.  我们构建我们的`scale`函数，并用实际数组替换指定值范围的对象。请注意，您可以指定实际数组，而不是`range`对象：

```html
        options.scale = eachOrOne(options.scale, function(s) {
            return $.gauge.scale(s);
        });
        eachOrOne(options.ticks, function(t) {
            return t.values = $.gauge.range(t.values);
        });
        eachOrOne(options.labels, function(l) {
            return l.values = $.gauge.range(l.values);
        });
```

1.  以下是绘图代码：

```html
        function draw(options) {
```

1.  我们将使用仪表中心作为参考点，并清除画布：

```html
            var w = $target.width(), h = $target.height(),
                c = {x: w * 0.5, y: h * (0.5 + options.yoffset)},
                r = w * 0.5,
                pi = Math.PI;
            ctx.clearRect(0, 0, w, h);
```

1.  然后我们将绘制所有条带（一个或多个）作为弧线：

```html
            // strips
            eachOrOne(options.strip, function(s) {
                var scale = options.scale[s.scale || 0];
                ctx.beginPath();
                ctx.strokeStyle = s.color;
                ctx.lineWidth = r * s.width;
                ctx.arc(c.x, c.y, s.radius * r, scale(s.to), scale(s.from), true);
                ctx.stroke();
            });
```

1.  然后绘制所有刻度（我们使用非常短、非常粗的弧线作为刻度）。我们的`scale`函数将`range`中的值转换为角度：

```html
            // ticks
            eachOrOne(options.ticks, function(s) {
                var scale = options.scale[s.scale || 0];
                ctx.strokeStyle = s.color;
                ctx.lineWidth = r * s.length;
                var delta = scale(s.width) - scale(0);
                s.values.forEach(function(v) {
                    ctx.beginPath();
                    ctx.arc(c.x, c.y, s.radius * r,
                        scale(v) + delta, scale(v) - delta, true);
                    ctx.stroke();
                });
            });
```

1.  然后我们绘制标签。我们通过将其放在最右边的垂直居中位置来确定位置，然后按照与值缩放的量逆时针旋转它：

```html
            // labels
            ctx.textAlign    = 'center';
            ctx.textBaseline = 'middle';
            eachOrOne(options.labels, function(s) {
                var scale = options.scale[s.scale || 0];
                ctx.font = s.font;
                ctx.fillStyle = s.color;
                s.values.forEach(function(v) {
                    var pos = rotate({x: c.x + r * s.radius, y:c.y},
                        0 - scale(v), c);
                    ctx.beginPath();
                    ctx.fillText(v, pos.x, pos.y);
                    ctx.fill();
                });
            });
```

1.  最后，我们绘制指针。指针由一个圆和一个三角形组成，圆心位于仪表的中心旋转点，三角形从那里延伸。我们旋转所有三角形点的方式与旋转标签中心的方式相同：

```html
            // needle
            eachOrOne(options.needle, function(s) {
                var scale = options.scale[s.scale || 0];
                var rotrad = 0 - scale(s.value);
                var p1 = rotate({x: c.x + r * s.length, y: c.y},    rotrad, c),
                    p2 = rotate({x: c.x, y: c.y + r*s.thickness/2}, rotrad, c),
                    p3 = rotate({x: c.x, y: c.y - r*s.thickness/2}, rotrad, c);
                ctx.fillStyle = s.color;
                ctx.beginPath();
                ctx.arc(c.x, c.y, r * s.thickness / 2, 0, 2*Math.PI);
                ctx.fill();
                ctx.beginPath();
                ctx.moveTo(p1.x, p1.y);
                ctx.lineTo(p2.x, p2.y);
                ctx.lineTo(p3.x, p3.y);
                ctx.fill();                
            });            
        }        
        draw(options);
```

1.  在绘制整个仪表之后，`gauge`函数返回一个函数，该函数可用于更改仪表指针值并重新绘制它：

```html
        return function(val, i) {
            i = i || 0;
            options.needle[i].value = val;
            draw(options);
        }
    };
```

1.  这些是常见的辅助函数。`range`函数创建一个值数组，而`scale`创建一个将值从一个范围缩放到另一个范围的函数。两者都支持对数刻度：

```html
    $.gauge.range = function(opt) {
        if (opt instanceof Array) return opt;
        var arr = [], step = opt.step;
        var last = opt.from;
        for (var k = opt.from; k <= opt.to; k+= step)
            arr.push(opt.log ? Math.pow(opt.log, k) : k);
        return arr;
    };
    $.gauge.scale = function(opt, f) {
        if (opt.type == 'linear') opt.type = function(x) { return x; };
        else if (opt.type == 'log') opt.type = Math.log;
        var f = opt.type,
            v0 = f(opt.values[0]),
            v1 = f(opt.values[1]);
        return function(v) {
            return (f(v) - v0) / (v1 - v0)
                    * (opt.angles[1] - opt.angles[0]) + Math.PI + opt.angles[0];
        };
    }
}(jQuery));
```

使用 jQuery 对象作为参数调用匿名函数，在函数的范围内变为`$`。这是构建具有自己私有范围的 jQuery 插件的典型方式，并在该范围内使 jQuery 作为`$`可用，而不管全局命名空间中的`$`是否与 jQuery 相同。

1.  我们将在`example.js`中绘制我们的仪表。以下是内容：

```html
$(function() {
    var g = $.gauge("#gauge", {
        scale: {
            angles: [-0.3, Math.PI+0.3],
            values: [0, 220]
        },
        strip: [
            { from: 0,   to: 140, color:"#ada" },
            { from: 140, to: 180, color:"#dda" },
            { from: 180, to: 220, color:"#d88" }
        ],
        ticks: [{
            color: "rgba(0,0,0,0.33)",
            values: { from: 0, to: 220, step:10 },
            length:0.05, radius:0.8, width:0.3
        }, {
            color: "rgba(0,0,0,0.33)",
            values: { from: 0, to: 220, step:20 },
            length:0.11, radius: 0.77, width:0.3
        }],
        labels: {
            color: "#777",
            values: { from: 0, to: 220, step:20 },
            radius: 0.62
        },
        needle: { color:"#678" }
    });
    g(25);
});
```

## 它是如何工作的...

我们为仪表指定了一个线性刻度，角度略低于中间，并且速度值在 0 到 220 的范围内。我们创建了三个条带，绿色的范围是 0 到 140 公里/小时，黄色的范围是 140 到 180 公里/小时，红色的范围是 180 到 220 公里/小时。我们将使用两组条带：每 20 公里/小时一个较大的，每 10 公里/小时一个较小的，都是半透明的。最后，我们添加了一个带有蓝色色调的指针。

最后，我们可以使用返回的函数设置仪表值，我们将其设置为 25 公里/小时。

# 显示树

在这个配方中，我们将看看如何以树状布局显示数据。我们将通过 JSON 文件来可视化 Linux 的一个小家族树。此外，我们将使用`D3.js`文件来操作 DOM 以显示数据。

![显示树](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_02_10.jpg)

## 准备工作

首先，我们需要有将用于可视化的数据。我们需要获取这个配方示例中的`tree.json`文件。

## 如何做...

我们将编写 HTML 和支持 JavaScript 代码，应该从 JSON 文件生成数据：

1.  让我们首先看一下 JSON 数据的结构：

```html
{
  "name": "GNU/Linux",
  "url": "http://en.wikipedia.org/wiki/Linux",
  "children": [
    {
      "name": "Red Hat",
      "url": "http://www.redhat.com",
      "children": [ .. ]
   } ]
...
}
```

每个对象都有一个`name`属性，表示分布名称，一个`url`属性，其中包含指向官方网页的链接，以及可选的`children`属性，其中包含其他对象的列表。

1.  下一步将是使用 HTML5 文档类型创建页面，并添加对`D3.js`的依赖项和名为`tree.css`的 CSS 文件：

```html
<!DOCTYPE html>
<html>
  <head>
    <title>Linux Tree History</title>
    <script src="img/d3.v2.js"></script>
    <link type="text/css" rel="stylesheet" href="tree.css"/>
  </head>
```

1.  在`body`部分，我们将添加一个具有名为`location`的`id`的`<div>`标签，我们将用它作为占位符，并另外包含一个名为`tree.js`的 JavaScript 文件，该文件将用于包含映射数据的逻辑：

```html
  <body>
    <div id="location"></div>
    <script type="text/javascript" src="img/tree.js"></script>
  </body>
</html>
```

1.  让我们从在`tree.js`文件中创建显示区域开始。首先，我们创建提供内部私有状态的匿名函数：

```html
(function() {
```

1.  然后，我们设置生成图像的大小，给定`width`和`height`。为简单起见，我们将它们设置为固定值：

```html
var width = 1000,
          height = 600;
```

1.  然后，我们设置了一个标准的 D3 布局树：

```html
  var tree = d3.layout.tree()
          .size([height, width - 200]);
  var diagonal = d3.svg.diagonal()
          .projection(function(d) {
            return [d.y, d.x];
          });
```

1.  由于我们需要指定和创建实际的 SVG，我们使用之前在 HTML 中选择的`id`来选择位置，然后附加 SVG 元素：

```html
  var vis = d3.select("#location").append("svg")
          .attr("width", width)
          .attr("height", height)
          .append("g")
          .attr("transform", "translate(60, 0)");
```

1.  我们还需要从`tree.json`中读取数据，并以某种方式使用给定的层次结构创建节点和链接：

```html
d3.json("tree.json", function(json) {
    var nodes = tree.nodes(json);
    vis.selectAll("path.link")
          .data(tree.links(nodes))
          .enter().append("path")
          .attr("class", "link")
          .attr("d", diagonal);
    var node = vis.selectAll("g.node")
            .data(nodes)
            .enter().append("g")
            .append("a")
            .attr("xlink:href", function(d) {
                 return d.url;
              })
            .attr("class", "node")
            .attr("transform", function(d) {
                return "translate(" + d.y + "," + d.x + ")";
              });

    node.append("circle")
            .attr("r", 20);

    node.append("text")
            .attr("dx", -19)
            .attr("fill", "white")
            .attr("dy", -19)
            .style("font-size", "20")
            .text(function(d) {
              return d.name;
            });
```

1.  我们可以使用 CSS 样式页面，选择页面链接背景和圆圈的颜色：

```html
 .node circle {
     fill: #fc0;
     stroke: steelblue;
     stroke-width: 1px;
}
.link {
  fill: none;
  stroke: #fff;
  stroke-width: 5.0px;
}
body{  
    background-color: #000;
 }
```

## 它是如何工作的...

`d3.layout.tree()`创建一个具有默认设置的新树布局，其中假定数据元素中的每个输入都有一个子数组。

使用`d3.svg.diagonal()`，我们创建了一个具有默认访问器函数的生成器。 返回的函数可以生成连接节点的立方贝塞尔路径数据，其中我们有用于平滑线条的切线。

### 注意

有关贝塞尔曲线的更多信息，请访问[`en.wikipedia.org/wiki/Bézier_curve`](http://en.wikipedia.org/wiki/Bézier_curve)。 它背后有一些数学知识，但最简单的解释是，它是一条受到某些点影响的线，使其成为定义曲线的不错选择。

由于我们希望树从左到右而不是默认的从上到下，我们需要通过进行投影来改变默认行为：

```html
var diagonal = d3.svg.diagonal()
          .projection(function(d) {
              return [d.y, d.x];
          });
```

该函数将使用`[d.y, d.x]`而不是默认的`[d.x,d.y]`。 你可能已经注意到了`.append("g")`函数，它添加了 SVG `g`元素，这是一个用于将各种相关元素分组在一起的容器元素。 我们可以在其中有多个嵌套元素，一个在另一个内部，到任意深度，允许我们在各个级别创建组：

```html
<g>
      <g>
      <g>
       </g>
     </g>
   </g>
```

要读取 JSON 数据，我们使用了以下内容：

```html
d3.json("tree.json", function(json) { … }
```

这将对`tree.json`资源进行 AJAX 调用。

### 注意

请注意，默认情况下，您的浏览器不会允许跨域请求。 这包括对本地文件系统的请求。 要克服这一点，请使用附录 A 中解释的本地 Web 服务器，*安装 Node.js 和使用 npm*。 另一个选择是使用 JSONP 作为一个很好的解决方法，因为在这种安全限制下有一些缺点。 在第八章中，*与服务器通信*，我们将介绍这些限制背后的问题和原因。

有关更多信息，请查看 W3C 页面[`www.w3.org/TR/cors/`](http://www.w3.org/TR/cors/)。

然后，我们使用`tree.nodes(json)`自动映射来自 JSON 文件的数据，其中对我们在数据中有什么进行了一些假设； 例如，我们可以有一个父节点或子节点。

之后，我们使用类似于 jQuery 的 W3C 选择器选择了所有的`path.link`：

```html
vis.selectAll("path.link")
```

使用`.data`，我们将它们与`tree.links`返回的链接信息绑定：

```html
.data(tree.links(nodes))
```

D3 的树布局有一个`links`函数，它接受一个节点数组，并返回表示这些节点的父节点到子节点的链接的对象数组。 不会创建叶子节点的链接。 返回对象中存储的信息有一个`source`或父节点和`target`或子节点。 现在，在接下来的部分中，有一个非常 D3 魔术的`.enter()`函数。 每个数组中的元素都是`.data([theArray])`的一部分，并且在选择中找不到相应的 DOM 元素时，它就会“进入数据”，从而允许我们使用`.append`、`.insert`、`.select`或`.empty`操作符。 在我们的情况下，我们想要创建具有 CSS 类`link`和使用我们之前定义的对角线函数计算的`d`属性的 SVG 路径元素：

```html
           .enter()
           .append("path")
           .attr("class", "link")
           .attr("d", diagonal)
```

因此，对于每个数据元素，它将创建`<path class='link' d='dataCalucatedByDiagonal' />`。

SVG 路径元素是一个用于表示线条绘制的概念，例如，具有各种类型的几何和表示。`d`属性包含了用`moveto(M)`、`lineto(L)`、`curve( cubic and quadratic besiers)`、`arc(A)`、`closepath(Z)`、`vertical lineto (V)`等指定的路径数据。

了解 D3 为我们生成了什么，以便更全面地了解它是如何工作的。比如说我们想要显示一个简单的线：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_02_11.jpg)

SVG 代码如下：

```html
<svg  version="1.1">
  <g style="stroke: red; fill: none;">
    <path d="M 10 30 L 200 10"/>
 </g>
</svg>
```

检查路径数据值，我们可以看到它的意思是将`pen(M)`移动到`(10,30)`，并画`line(L)`到`(200,10)`。

在我们的树的例子中，我们使用路径绘制线条，所以下一步是绘制节点。我们应用相同的过程，选择所有旧的`g.node`元素并输入节点数据，但是我们不是创建`<path/>`元素，而是只是附加`"g"`，并额外添加一个带有`<xlink:href>`属性的`<a>`元素：

```html
…
            .append("a")
            .attr("xlink:href", function(d) {
                 return d.url;
              })
```

由于我们已经自动迭代了所有数据节点，我们可以访问`d.url`，检索每个节点的 URL，并将其设置为我们稍后要添加的所有内部元素的链接。

不要忘记我们需要旋转坐标，因为我们希望树从左到右显示：

```html
            .attr("transform", function(d) {
                return "translate(" + d.y + "," + d.x + ")";
              });
```

在此之后，我们可以向每个元素附加其他元素，为了创建圆，我们添加以下内容：

```html
    node.append("circle")
            .attr("r", 20);
```

这样就创建了一个半径为 20px 的 SVG 圆，另外，我们附加了将显示分布名称的`<text/>`元素：

```html
   node.append("text")
            .attr("dx", -19)
            .attr("dy", -19)
             ...
```

注意，我们将文本元素移动了`(-19,-19)`，以避免与圆和线重叠，就是这样。

## 还有更多...

你首先要做的事情是玩弄一下那些是常数的值，比如图像大小或文本偏移量。这将帮助你更好地理解变化如何影响布局。有各种不同的函数来生成布局，你可以以径向方式创建它，或者使它看起来像树突一样。

有各种方法可以添加交互，你可以在代码的某些部分进行更新，使某些部分动画化，甚至在 SVG 内部包含 HTML。

# 使用网络字体的 LED 记分牌

在这个食谱中，我们将创建一个 LED 记分牌，类似于篮球比赛中使用的记分牌，通过巧妙地使用 HTML 网络字体。该食谱的主要目标是介绍网络字体及其提供的功能。

![使用网络字体的 LED 记分牌](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-dt-svc-cb/img/9282OT_02_12.jpg)

### 提示

有关网络字体的完整规范可以在 W3C 上找到[`www.w3.org/TR/css3-webfonts/`](http://www.w3.org/TR/css3-webfonts/)。

## 准备工作完成

在开始之前，你需要获取我们在这个例子中要使用的字体。这些文件可以从示例代码中检索，它们都有一个`RADIOLAND`前缀。

## 如何做...

为了创建记分牌，我们将创建一个 HTML 页面，一个支持 JavaScript 代码，用于更新计时器和相关数据，以及一个使用网络字体的 CSS 文件：

1.  首先，我们将从创建 HTML 页面开始；在`head`部分，包括`stylesheet.css`和对 jQuery 的依赖。

```html
  <link rel="stylesheet" href="stylesheet.css" type="text/css" charset="utf-8">
  <script src="img/jquery.min.js"></script>
```

1.  在`body`部分，添加我们将用作分数占位符的`div`元素，并另外包括`scoreboard.js`：

```html
    <div class="counter"></div>
    <div class="score">
              <span class="home"></span>
               <span class="period"></span>
               <span class="guests"></span>
    </div>
  </div>
  <script type="text/javascript" src="img/scoreboard.js"></script>
```

1.  我们现在可以创建`stylesheet.css`文件，首先定义具有 LED 外观的网络字体：

```html
@font-face {
  font-family: 'RadiolandRegular';
  src: url('RADIOLAND-webfont.eot');
  src: url('RADIOLAND-webfont.eot?#iefix') format('embedded-opentype'),
    url('RADIOLAND-webfont.woff') format('woff'),
    url('RADIOLAND-webfont.ttf') format('truetype'),
    url('RADIOLAND-webfont.svg#RadiolandRegular') format('svg');
  font-weight: normal;
  font-style: normal;
}
```

1.  由于字体现在被定义为`RadiolandRegular`，我们可以直接引用它：

```html
div.counter{
  font: 118px/127px 'RadiolandRegular', Arial, sans-serif;
  color: green;
}
    .score {
      font: 55px/60px 'RadiolandRegular', Arial, sans-serif;
      letter-spacing: 0;
      color: red;
      width: 450px;
    }

  .period {
      font: 35px/45px 'RadiolandRegular', Arial, sans-serif;
      color: white;
    }

    div.display {
      padding: 50px;
    }
```

1.  我们可以继续创建将要使用的 JavaScript，并且我们将使用一个名为`game`的模拟对象，该对象具有游戏信息。一般来说，这个对象应该通过 AJAX 调用从服务器检索，但为了简单起见，我们使用了一些预定义的值：

```html
  var game = {
    periodStart: 1354650343000,
    currentPeriod: 1,
    score: {
      home: 15,
      guests: 10
    }
  };
```

1.  为了使我们的显示对象的创建逻辑和数据获取逻辑分离，我们可以将其放在一个函数中：

```html
  function fetchNewData() {
    // server data
    var game = {
      periodStart: new Date().getTime(),
      //the server will return data like: periodStart: 1354838410000,
      currentPeriod: 1,
      score: {
        home: 15,
        guests: 10
      }
    };
    //return display data
    return {
      periodStart: game.periodStart,
      counter: '00:00',
      period: game.currentPeriod + ' Period',
      score: {
        home: game.score.home,
        guests: game.score.guests
      }
    };
  }
```

1.  我们还创建了一个 `config` 对象，可以在其中定义游戏参数，例如周期数和每周期的分钟数：

```html
  var config = {
    refreshSec: 1,
    periods: 4,
    minPerPeriod: 12
  };
```

1.  然后我们定义 `updateCounter()` 和 `updateScore()` 函数，它们将更新显示并执行计时器的计算。我们将检查当前时间是否小于游戏开始时间，并将计时器设置为 `00:00`。如果当前时间大于最大可能时间，则将计时器设置为最大可能时间：

```html
  function updateCounter() {
          var now = new Date(),
          millsPassed = now.getTime() - displayData.periodStart;

         if (millsPassed < 0) {
           displayData.counter = '00:00';
         } else if (millsPassed > config.minPerPeriod * 60 * 1000) {
           displayData.counter = config.minPerPeriod + ':00';
         } else {
           //counting normal time
           var min = Math.floor(millsPassed/60000);
           if (min<10) {
             min = '0' + min;
           }
           var sec = Math.floor((millsPassed % 60000)/1000);
           if (sec<10) {
             sec = '0'+sec;
           }
           displayData.counter = min+':'+sec;
         }
         $('.counter').text(displayData.counter);
         $('.period').text(displayData.period);
```

1.  随后，我们添加一个将更新得分的函数：

```html
  function updateScore(){
    $('.home').text(displayData.score.home);
    $('.guests').text(displayData.score.guests);
  }
```

1.  最后，我们可以调用 `setInterval` 函数，该函数将每 500 毫秒调用更新：

```html
    setInterval(updateCounter, 500);
    setInterval(updateScore, 500);
```

## 工作原理…

这个配方中的 HTML 和 JavaScript 代码非常简单直接，但另一方面，我们正在深入研究 CSS 和字体文件。

通过添加 `@font-face` at-rule，我们可以指定在其他元素中使用在线字体。通过这样做，我们允许使用客户端机器上不可用的不同字体。

在 `@font-face` 的定义中，我们添加了 `font-family` ——一个我们随后可以应用在任何元素上的名称定义。例如，考虑以下示例，我们将我们的字体称为 `someName`：

```html
@font-face {
  font-family: someName;
  src: url(awesome.woff) format("woff"),
       url(awesome.ttf) format("opentype");
}
```

您可以在此示例中以及我们的 `stylesheet.css` 中的 `url` 旁边注意到名为 `format("woff")` 的格式定义。可以应用以下格式：

+   `.woff`：这代表**Web 开放字体格式**（**WOFF**），这是由 Mozilla 开发的一种较新的标准之一。完整规范可在 [`www.w3.org/TR/WOFF/`](http://www.w3.org/TR/WOFF/) 上找到。该格式的目标是为其他格式提供替代解决方案，这些解决方案在需要一定级别的许可证时会更加优化。该格式允许将元数据附加到文件本身，其中可以包含许可证。

+   `.ttf` 和 `.otf`：**TrueType 字体**（**TTF**）和扩展版本**OpenType 字体**（**OTF**）是一些最广泛使用的类型。TrueType 的标准是由苹果电脑在 80 年代末开发的，作为一些 PostScript 标准的替代品。它为字体开发人员提供了灵活性和对用户以多种不同大小显示字体的控制。由于其流行和功能，它迅速传播到其他平台，如 Windows。OpenType 是基于 TrueType 的后继版本。该规范由微软开发，并得到 Adobe Systems 的补充。OpenType 是微软公司的注册商标。详细规范可以在 [`www.microsoft.com/typography/otspec/default.htm`](http://www.microsoft.com/typography/otspec/default.htm) 上找到。

+   `.eot`：嵌入式 OpenType 字体是设计用于网页的 OpenType 字体的一种形式。对嵌入版本的扩展与制作版权保护密切相关。由于其他字体很容易被复制，EOT 只向用户提供可用字符的子集，使得复制整个字体更加困难。有关 EOT 的更多信息，请参阅 W3C 规范 [`www.w3.org/Submission/EOT/`](http://www.w3.org/Submission/EOT/)。

+   `.svg` 和 `.svgz`：SVG 和带有扩展名 `.svgz` 的经过解压缩的版本可以用来表示字体。字体定义存储为 SVG 字形，可以轻松支持。有关 SVG 字体的更多信息可以在规范 [`www.w3.org/TR/SVG/fonts.html`](http://www.w3.org/TR/SVG/fonts.html) 中找到。不幸的是，目前写作时，这种格式在 IE 和 Firefox 中不受支持。

`@font-face` 上还可以使用一些其他属性，例如 `font-style`、`font-weight` 和 `font-stretch`。此外，我们可以通过为 `unicode-range` 设置值来指定 Unicode 中使用的字符范围。规范中的一些示例如下：

+   `unicode-range: U+0-7F;`：这是基本 ASCII 字符的代码范围

+   `unicode-range: U+590-5ff;`：这是希伯来字符的代码范围

Web 字体的一个问题是 CSS2 的规范没有要求特定的格式。这通常意味着我们需要提供几种不同的格式，以在各种浏览器中获得相同的体验。

### 注意

有许多`font-face`定义生成器可以简化所有这些可能选项的创建。其中一个是**FontSquirrel**（[`www.fontsquirrel.com/tools/webfont-generator`](http://www.fontsquirrel.com/tools/webfont-generator)）。

Web 字体正在成为 Web 的最常见构建块之一，因此，当我们需要一个出色的排版时，它们应该始终被考虑。图像、SVG、Coufons 和类似类型与文本不太兼容。我们可能会使用这些来获得出色的文本外观，但搜索引擎无法访问文本，大多数辅助功能软件将忽略它，甚至可能使页面大小变大。另一方面，使用文本允许我们对数据进行各种 CSS 调整，我们可以使用选择器，比如`:first-letter`、`:first-line`和`:lang`。

## 还有更多...

Google 有许多我们可以使用的字体，这些字体可以在[`www.google.com/fonts/`](http://www.google.com/fonts/)上找到。除了标准的字体包含，他们还有一个基于 JavaScript 的字体加载器。这个加载器解决了在“真正”的字体加载时看到回退文本渲染的问题，通常被称为**未样式化文本的闪烁**（**FOUT**）。例如，我们可以这样做来包含一个名为`'Noto Sans'`的字体：

```html
<script type="text/javascript">
  WebFontConfig = {
    google: { families: [ 'Noto+Sans::latin' ] }
  };
  (function() {
    var wf = document.createElement('script');
    wf.src = ('https:' == document.location.protocol ? 'https' : 'http') +
      '://ajax.googleapis.com/ajax/libs/webfont/1/webfont.js';
    wf.type = 'text/javascript';
    wf.async = 'true';
    var s = document.getElementsByTagName('script')[0];
    s.parentNode.insertBefore(wf, s);
  })(); </script>
```

之后，我们可以简单地在 CSS 中使用`font-family: 'Noto Sans', sans-serif;`来包含它。

### 注意

有关 Google 字体选项的更多信息，请访问[`developers.google.com/fonts/`](https://developers.google.com/fonts/)。至于所谓的 FOUT 以及一些对抗它的方法，*Paul Irish*在[`paulirish.com/2009/fighting-the-font-face-fout/`](http://paulirish.com/2009/fighting-the-font-face-fout/)的文章中有更多内容。
