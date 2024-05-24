# jQuery 设计模式（一）

> 原文：[`zh.annas-archive.org/md5/9DBFD51895CA93BE96AC02124FF5B7E1`](https://zh.annas-archive.org/md5/9DBFD51895CA93BE96AC02124FF5B7E1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

自 2006 年推出以来，jQuery 库已经使 DOM 遍历和操作变得更加容易。这导致了具有越来越复杂用户交互的 Web 页面的出现，从而促进了 Web 作为支持大型应用程序实现的平台的成熟。

本书提供了一系列使 Web 应用程序实现更高效的最佳实践。此外，我们将分析可以应用于 Web 开发的计算机科学中最重要的设计模式。通过这种方式，我们将学习如何利用其他编程领域中广泛使用和测试的技术，这些技术最初是作为模拟复杂问题解决方案的通用方法创建的。

在《jQuery 设计模式》中，我们将分析各种设计模式在 jQuery 实现中的应用以及它们如何用于改进我们的实现组织。通过采用本书中展示的设计模式，您将能够创建更有组织的实现，更快地解决大问题类别。此外，当开发团队使用时，它们可以提高团队之间的沟通并导致同质化实现，其中代码的每个部分都易于被其他人理解。

# 本书涵盖内容

第一章, *jQuery 和复合模式复习*，将教读者如何通过分析它们在 jQuery 本身实现中的使用来编写代码，使用复合模式和方法链接（流畅接口）。它还演示了与 jQuery 返回的复合集合对象良好配对的迭代器模式。

第二章，*观察者模式*，将教您如何使用观察者模式响应用户操作。它还演示了如何使用事件委托作为一种减少处理动态注入页面元素的代码的内存消耗和复杂性的方法。最后，它将教您如何发出和监听自定义事件，以实现更大的灵活性和代码解耦。

第三章，*发布/订阅模式*，将教您如何利用发布/订阅模式创建一个中心点来发出和接收应用程序级事件，作为解耦代码和业务逻辑与用于呈现的 HTML 之间的一种方式。

第四章, *用模块模式进行分而治之*, 展示并比较了行业中最常用的模块模式。它将教会你如何使用命名空间来将你的应用程序结构化为小的独立模块，遵循关注点分离原则，从而实现可扩展的实现。

第五章, *外观模式*, 将教会你如何使用外观模式将复杂的 API 包装成更适合你应用程序需求的简单 API。它还演示了如何改变应用程序的部分，同时保持相同的模块级 API，避免影响其余的实现。

第六章, *建造者和工厂模式*, 解释了建造者模式和工厂模式的概念和区别。它将教会你何时以及如何使用它们，以改善代码的清晰度，通过将生成复杂结果的过程抽象成单独的专用方法。

第七章, *异步控制流模式*, 将解释 jQuery 的 Deferred 和 Promise API 是如何工作的，并将它们与经典的回调模式进行比较。你将学习如何使用 Promises 来控制异步程序的执行，让它们以顺序或并行的方式运行。

第八章, *模拟对象模式*, 教会你如何创建和使用模拟对象和服务作为一种简化应用程序开发的方式，并在所有部分完成之前提前感受到其功能。

第九章, *客户端模板化*, 展示如何使用 Underscore.js 和 Handlebars.js 模板库作为创建复杂 HTML 结构的更好更快的方式。通过这一章节，你将了解它们的惯例，评估它们的特点，并找到最符合你口味的那一个。

第十章, *插件和小部件开发模式*, 介绍了 jQuery 插件开发的基本概念和惯例，并分析了最常用的设计模式，使你能够识别并使用最适合任何用例的模式。

第十一章 *优化模式*，指导您使用最佳提示创建高效且健壮的实现。您将能够将本章用作改进应用程序性能并降低内存消耗的最佳实践的检查表，然后将其移到生产环境。

# 本书所需内容

为了运行本书中的示例，您需要在系统上安装 Web 服务器来提供代码文件。例如，您可以使用 Apache、IIS 或 NGINX。为了使 Apache 的安装过程更加简单，您可以使用更完整的开发环境解决方案，例如 XAMPP 或 WAMP Server。

就技术熟练度而言，本书假定您已经有一些使用 jQuery、HTML、CSS 和 JSON 的经验。本书中的所有代码示例都使用 jQuery v2.2.0，并且一些章节还讨论了在 jQuery v1.12.0 中的相应实现，这可以在需要支持旧版浏览器的情况下使用。

# 本书适合谁

这本书面向现有的 jQuery 开发者或想将自己的技能和理解水平提升到高级水平的新开发者。这是一个详细介绍了如何将各种行业标准模式应用于 jQuery 应用程序的入门，以及一组最佳实践，它可以帮助大型团队协作并创建组织良好、可扩展的实现。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码词、文件夹名称、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“在上述 CSS 代码中，我们首先为 `box`、`boxsizer` 和 `clear` CSS 类定义了一些基本样式。”

代码块设置如下：

```js
$.each([3, 5, 7], function(index){
    console.log(this + 1 + '!');
});
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体设置：

```js
$('#categoriesSelector').change(function() { 
    var $selector = $(this); 
    var message = { categoryID: $selector.val() }; 
 broker.trigger('dashboardCategorySelect', [message]); 
});
```

我们正在遵循 Google JavaScript 样式指南，除了使用四个空格缩进外，以改善书中代码的可读性。简而言之，我们将大括号放在顶部，并使用单引号表示字符串字面值。

### 注意

有关 Google JavaScript 样式指南的更多信息，请访问以下 URL：[`google.github.io/styleguide/javascriptguide.xml`](https://google.github.io/styleguide/javascriptguide.xml)

任何命令行输入或输出都以如下形式书写：

```js
npm install jquery

```

**新术语**和**重要单词**以粗体显示。屏幕上看到的词语，例如菜单或对话框中的词语，以如下形式出现在文本中：“返回的 **jQuery 对象** 是一个**类似数组的对象**，它充当包装对象并携带检索到的元素的集合。”

### 注意

警告或重要提示会出现在这样的框中。

### 提示

提示和技巧会出现在这样。 


# 第一章：jQuery 和复合模式复习。

直到 **Web 2.0** 时代开始，Web 只是基于文档的媒体，它所提供的仅仅是连接不同页面/文档和客户端脚本编写，大多数情况下仅限于表单验证。到 2005 年，Gmail 和 Google 地图发布了，JavaScript 证明了自己是大型企业用于创建大规模应用程序并提供丰富用户界面交互的语言。

尽管 JavaScript 自发布以来几乎没有什么变化，但企业界对网页应该具备的功能期望发生了巨大变化。从那时起，Web 开发人员需要提供复杂的用户交互，并最终，"Web 应用程序" 这个术语出现在市场上。因此，开始变得明显，他们应该创建一些代码抽象，定义一些最佳实践，并采用计算机科学提供的所有适用的 **设计模式**。JavaScript 作为企业级应用程序的广泛采用帮助了语言的发展，随着 **EcmaScript2015**/**EcmaScript6**（**ES6**）规范的发布，语言得以扩展，以便更轻松地利用更多的设计模式。

2006 年 8 月，John Resig 在 [`jquery.com`](http://jquery.com) 首次发布了 jQuery 库，旨在创建一个方便的 API 来定位 DOM 元素。从那时起，它已成为 Web 开发人员工具包的一个组成部分。jQuery 在其核心中使用了几种设计模式，并通过提供的方法试图敦促开发人员使用它们。复合模式是其中之一，它通过非常核心的 `jQuery()` 方法向开发人员公开，该方法用于 DOM 遍历，这是 jQuery 库的一个亮点。

在本章中，我们将：

+   通过 jQuery 进行 DOM 脚本编写的复习。

+   介绍复合模式。

+   看看 jQuery 如何使用复合模式。

+   讨论 jQuery 相对于纯 JavaScript DOM 操作所带来的优势。

+   介绍迭代器模式。

+   在一个示例应用中使用迭代器模式。

# jQuery 和 DOM 脚本编写。

通过 DOM 脚本编写，我们指的是在浏览器加载后修改或操作网页元素的任何过程。DOM API 是一种 JavaScript API，于 1998 年标准化，它为网页开发人员提供了一组方法，允许在加载和解析网页的 HTML 代码后操作浏览器创建的 DOM 树元素。

### 注意。

要了解有关 **文档对象模型**（**DOM**）及其 API 的更多信息，您可以访问 [`developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model/Introduction`](https://developer.mozilla.org/en-US/docs/Web/API/Document_Object_Model/Introduction)。

通过在他们的 JavaScript 代码中利用 DOM API，web 开发者可以操纵 DOM 的节点，并向页面添加新元素或删除现有元素。最初 DOM 脚本的主要用例仅限于客户端表单验证，但随着时间的推移和 JavaScript 获得企业界的信任，开始实现更复杂的用户交互。

jQuery 库的初始版本于 2006 年 8 月首次发布，它试图简化 web 开发者遍历和操纵 DOM 树的方式。其主要目标之一是提供抽象，以产生更短、更易读、更不容易出错的代码，同时确保跨浏览器的互操作性。

jQuery 遵循的这些核心原则在其主页中清晰可见，它将自己呈现为：

> …一个快速、小巧且功能丰富的 JavaScript 库。它通过一个易于使用的 API，简化了 HTML 文档遍历和操纵、事件处理、动画和 Ajax，适用于众多浏览器。jQuery 结合了多功能性和可扩展性，改变了数百万人编写 JavaScript 的方式。

jQuery 从一开始提供的抽象 API，以及不同的设计模式是如何编排的，导致在 web 开发者中得到了广泛的接受。因此，根据多个来源（例如 BuiltWith.com ([`trends.builtwith.com/javascript/jQuery`](http://trends.builtwith.com/javascript/jQuery)）），全球访问量最高的网站中有超过 60% 的网站引用了 jQuery 库。

## 使用 jQuery 操纵 DOM

为了对 jQuery 进行复习，我们将通过一个示例网页进行一些简单的 DOM 操作。在这个例子中，我们将加载一个简单结构的页面，最初看起来像下图所示：

![使用 jQuery 操纵 DOM](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00002.jpeg)

我们将使用一些 jQuery 代码来更改页面的内容和布局，并且为了使其效果清晰可见，我们将设置它在页面加载后约`700 milliseconds`运行。我们的操作结果将如下图所示：

![使用 jQuery 操纵 DOM](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00003.jpeg)

现在让我们回顾一下前面示例所需的 HTML 代码：

```js
<!DOCTYPE html> 
<html> 
  <head> 
    <title>DOM Manipulations</title> 
    <link rel="stylesheet" type="text/css" href="dom-manipulations.css">
  </head> 
  <body> 
    <h1 id="pageHeader">DOM Manipulations</h1> 

    <div class="boxContainer"> 
      <div> 
        <p class="box"> 
          Doing DOM Manipulations is easy with JS! 
        </p> 
      </div> 
      <div> 
        <p class="box"> 
          Doing DOM Manipulations is easy with JS! 
        </p> 
      </div> 
      <div> 
        <p class="box"> 
          Doing DOM Manipulations is easy with JS! 
        </p> 
      </div> 
    </div> 

    <p class="box"> 
      Doing DOM Manipulations is easy with JS! 
    </p> 
    <p class="box"> 
      Doing DOM Manipulations is easy with JS! 
    </p>

    <script type="text/javascript" src="img/jquery-2.2.0.min.js"></script>
    <script type="text/javascript" src="img/jquery-dom-manipulations.js"></script>
  </body>
</html>
```

使用的 CSS 代码非常简单，只包含三个 CSS 类，如下所示：

```js
.box {
    padding: 7px 10px;
    border: solid 1px #333;
    margin: 5px 3px;
    box-shadow: 0 1px 2px #777;
}

.boxsizer {
    float: left;
    width: 33.33%;
}

.clear { clear: both; }
```

前述代码在浏览器中打开并在执行我们的 JavaScript 代码之前，页面看起来像第一个图示所示。在前述 CSS 代码中，我们首先为 `box`、`boxsizer` 和 `clear` CSS 类定义了一些基本样式。`box` 类通过一些填充、一条细边框、周围一些间距和在元素下方创建一个小阴影来为页面中的相关元素添加样式，使它们看起来像一个盒子。`boxsizer` 类将使用它的元素的宽度设置为其父元素的 1/3，并创建一个三列布局。最后，`clear` 类将用于元素作为列布局的断点，以使其后的所有元素都位于其下方。`boxsizer` 和 `clear` 类最初未被 HTML 代码中定义的任何元素使用，但会在我们将在 JavaScript 中进行的 DOM 操作之后使用。

在我们的 HTML 的 `<body>` 元素中，我们最初定义了一个带有 ID `pageHeader` 的 `<h1>` 标题元素，以便通过 JavaScript 轻松选择。紧接着，在它下面，我们定义了五个段落元素 (`<p>`)，具有 `box` 类，前三个元素被包裹在三个 `<div>` 元素中，然后再包裹在另一个具有 `boxContainer` 类的 `<div>` 元素中。

到达我们的两个 `<script>` 标签时，我们首先从 jQuery CDN 引入了对 jQuery 库的引用。有关更多信息，您可以访问 [`code.jquery.com/`](http://code.jquery.com/)。在第二个 `<script>` 标签中，我们引用了带有所需代码的 JavaScript 文件，例如：

```js
setTimeout(function() {
    $('#pageHeader').css('font-size', '3em');

    var $boxes = $('.boxContainer .box');
    $boxes.append(
      '<br /><br /><i>In case we need simple things</i>.');
    $boxes.parent().addClass('boxsizer');

    $('.boxContainer').append('<div class="clear">');
}, 700);
```

我们所有的代码都包装在一个 `setTimeout` 调用中以延迟其执行，根据之前描述的用例。`setTimeout` 函数调用的第一个参数是一个匿名函数，它将在定时器 700 毫秒过期后执行，如第二个参数中定义的那样。

在我们匿名回调函数的第一行，我们使用 jQuery 的 `$()` 函数遍历 DOM 并定位 ID 为 `pageHeader` 的元素，并使用 `css()` 方法将其 `font-size` 增加到 `3em`。接下来，我们向 `$()` 函数提供了一个更复杂的 CSS 选择器，来定位所有具有 `box` 类的元素，这些元素是具有 `boxContainer` 类的元素的后代，然后将结果存储在名为 `$boxes` 的变量中。

### 提示

**变量命名约定**

在开发者中使用命名约定来命名持有特定类型对象的变量是一种常见做法。使用这种约定不仅有助于你记住变量持有的内容，还能使你的代码更易于其他团队成员理解。在 jQuery 开发者中，当变量存储了 `$()` 函数的结果（也称为 jQuery 集合对象）时，使用以 "$" 符号开头的变量名是常见的。

在获取我们感兴趣的`box`元素之后，我们在每个元素的末尾添加两个换行空格和一些额外的斜体文本。然后，我们使用`$boxes`变量遍历 DOM 树，使用`parent()`方法上升一个级别。`parent()`方法返回一个不同的 jQuery 对象，其中包含我们最初选择的框的父`<div>`元素，然后我们链式调用`addClass()`方法将它们分配给`boxsizer` CSS 类。

### 小贴士

如果您需要遍历所选元素的所有父节点，则可以使用`$.fn.parents()`方法。如果您只需要找到与给定 CSS 选择器匹配的第一个祖先元素，请考虑改用`$.fn.closest()`方法。

最后，由于`boxsizer`类使用浮动来实现三列布局，我们需要清除`boxContainer`中的浮动。再次，我们使用简单的`.boxContainer` CSS 选择器和`$()`函数遍历 DOM。然后，我们调用`.append()`方法创建一个带有`.clear` CSS 类的新`<div>`元素，并将其插入到`boxContainer`的末尾。

700 毫秒后，我们的 jQuery 代码将完成，结果是之前显示的三列布局。在其最终状态下，我们的`boxContainer`元素的 HTML 代码如下所示：

```js
<div class="boxContainer"> 
 <div class="boxsizer"> 
    <p class="box"> 
      Doing DOM Manipulations is easy with JS! 
 <br><br><i>In case we need simple things</i>. 
    </p> 
  </div> 
 <div class="boxsizer"> 
    <p class="box"> 
      Doing DOM Manipulations is easy with JS! 
 <br><br><i>In case we need simple things</i>. 
    </p> 
  </div> 
 <div class="boxsizer"> 
    <p class="box"> 
      Doing DOM Manipulations is easy with JS! 
 <br><br><i>In case we need simple things</i>. 
    </p> 
  </div> 
 <div class="clear"></div> 
</div> 
```

### 方法链和流畅接口

实际上，在上面的示例中，我们还可以进一步将所有三个与框相关的代码语句合并为一个，其效果如下所示：

```js
$('.boxContainer .box') 
  .append('<br /><br /><i>In case we need simple things</i>.') 
  .parent() 
  .addClass('boxsizer');
```

这种语法模式被称为**方法链**，并且被 jQuery 和 JavaScript 社区广泛推荐。方法链是流畅接口的面向对象实现模式的一部分，其中每个方法将其指令上下文传递给后续方法。

大多数适用于 jQuery 对象的 jQuery 方法也会返回相同或新的 jQuery 元素集合对象。这使我们能够链式调用多个方法，不仅使代码更易读和表达，而且减少了所需的变量声明。

# 组合模式

组合模式的关键概念是使我们能够像处理单个对象实例一样处理对象集合。通过在集合上使用方法来操作组合将导致将操作应用于其每个部分。这样的方法可以成功应用，而不管组合集合中包含的元素数量如何，甚至当集合不包含元素时也可以。

另外，组合集合的对象不一定需要提供完全相同的方法。组合对象可以只公开集合对象中对象之间共同的方法，或者可以提供一个抽象的 API，并适当处理每个对象的方法差异。

让我们继续探讨 jQuery 公开的直观 API 如何受到组合模式的高度影响。

## jQuery 如何使用组合模式

组合模式是 jQuery 架构的一个组成部分，并且从 `$()` 函数的核心自身应用。 对 `$()` 函数的每次调用都会创建并返回一个元素集合对象，这通常简称为 jQuery 对象。 这正是我们看到组合模式的第一个原则的地方； 实际上，`$()` 函数不是返回单个元素，而是返回一组元素。

返回的 jQuery 对象是一个类似数组的对象，充当包装对象并携带检索到的元素集合。 它还公开了一些额外的属性，如下所示：

+   检索到的元素集合的 `length`

+   对象构造的 `context`

+   在 `$()` 函数调用中使用的 CSS `selector`

+   在链式调用方法后如果我们需要访问先前的元素集合，则有一个 `prevObject` 属性

### 提示

**简单的类似数组对象定义**

类似数组的对象是具有数字 `length` 属性和相应数量的属性的 JavaScript 对象 `{ }`，具有连续的数字属性名称。 换句话说，具有 `length == 2` 属性的类似数组对象预计也应该定义两个属性 `"0"` 和 `"1"`。 给定上述属性，类似数组的对象允许您使用简单的 `for` 循环访问它们的内容，通过利用 JavaScript 的括号属性访问器的语法：

```js
for (var i = 0; i < obj.length; i++) { 
  console.log(obj[i]); 
}
```

我们可以轻松地尝试使用 `$()` 函数返回的 jQuery 对象，并通过使用我们喜爱的浏览器的开发者工具检查上述属性。 要在大多数浏览器上打开开发者工具，我们只需要在 Windows 和 Linux 上按下 *F12*，或在 Mac 上按 *Cmd* + *Opt* + *I*，然后我们可以在控制台中发出一些 `$()` 调用并单击返回的对象以检查它们的属性。

在下图中，我们可以看到在之前示例中使用的 `$('#pageHeader')` 调用的结果在 Firefox 开发者工具中的样子：

![jQuery 如何使用组合模式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00004.jpeg)

`$('.boxContainer .box')` 调用的结果如下：

![jQuery 如何使用组合模式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00005.jpeg)

jQuery 使用类似数组的对象作为返回元素的包装器，从而使其能够公开一些额外的适用于返回的集合的方法。这是通过原型继承 `jQuery.fn` 对象来实现的，导致每个 jQuery 对象也可以访问 jQuery 提供的所有方法。这完成了组合模式，该模式提供了适用于集合的方法，这些方法适用于集合的每个成员。因为 jQuery 使用类似数组的对象具有原型继承，所以这些方法可以轻松地作为每个 jQuery 对象的属性访问，就像本章开头的示例中所示：`$('#pageHeader').css('font-size', '3em');`。此外，jQuery 还为其 DOM 操作代码添加了一些额外的好处，遵循更小和更不容易出错的代码的目标。例如，当使用 `jQuery.fn.html()` 方法更改已包含子元素的 DOM 节点的内部 HTML 时，jQuery 首先尝试删除与子元素关联的任何数据和事件处理程序，然后再将它们从页面中删除并附加所提供的 HTML 代码。

让我们看一下 jQuery 如何实现这些适用于集合的方法。对于这个任务，我们可以从 jQuery 的 GitHub 页面下载并查看源代码（[`github.com/jquery/jquery/releases`](https://github.com/jquery/jquery/releases)），或者使用类似 jQuery 源代码查看器这样的工具，该工具可在[`james.padolsey.com/jquery`](http://james.padolsey.com/jquery)找到。

### 注意

根据您使用的版本，您可能会在某种程度上获得不同的结果。在编写本书时，作为参考的最新稳定版 jQuery 版本是 v2.2.0。

展示适用于集合的方法如何实现的最简单方法之一是 `jQuery.fn.empty()`。您可以通过搜索 `"empty:"` 或使用 jQuery 源代码查看器并搜索 `"jQuery.fn.empty"` 来轻松找到它在 jQuery 源代码中的实现。使用其中任一种方式都会带我们到以下代码：

```js
empty: function() { 
  var elem, i = 0; 

  for ( ; ( elem = this[ i ] ) != null; i++ ) {
    if ( elem.nodeType === 1 ) { 
      // Prevent memory leaks 
      jQuery.cleanData( getAll( elem, false ) ); 

      // Remove any remaining nodes 
      elem.textContent = ""; 
    } 
  } 

  return this; 
}
```

如您所见，代码一点也不复杂。jQuery 使用简单的 `for` 循环遍历集合对象的所有项（称为 `this`，因为我们在方法实现内部），对于集合的每个项，即元素节点，它都使用 `jQuery.cleanData()` 辅助函数清除任何 data-* 属性值，然后立即将其内容设置为空字符串。

### 注意

关于不同指定节点类型的更多信息，请访问[`developer.mozilla.org/en-US/docs/Web/API/Node/nodeType`](https://developer.mozilla.org/en-US/docs/Web/API/Node/nodeType)。

## 与普通 DOM API 相比的优势

为了清楚地展示复合模式提供的好处，我们将在不使用 jQuery 提供的抽象的情况下重新编写我们最初的示例。通过仅使用普通 JavaScript 和 DOM API，我们可以编写一个等效的代码，如下所示：

```js
setTimeout(function() { 
  var headerElement = document.getElementById('pageHeader'); 
  if (headerElement) { 
    headerElement.style.fontSize = '3em'; 
  } 
  var boxContainerElement = document.getElementsByClassName('boxContainer')[0]; 
  if (boxContainerElement) { 
    var innerBoxElements = boxContainerElement.getElementsByClassName('box'); 
    for (var i = 0; i < innerBoxElements.length; i++) { 
      var boxElement = innerBoxElements[i]; 
      boxElement.innerHTML +='<br /><br /><i>In case we need simple things</i>.'; 
      boxElement.parentNode.className += ' boxsizer'; 
    } 
    var clearFloatDiv = document.createElement('div'); 
    clearFloatDiv.className = 'clear'; 
    boxContainerElement.appendChild(clearFloatDiv); 
  } 
}, 700);
```

再次使用`setTimeout`与匿名函数，并将`700`毫秒设置为第二个参数。在函数内部，我们使用`document.getElementById`来检索已知在页面中具有唯一 ID 的元素，后来在需要检索具有特定类的所有元素时使用`document.getElementsByClassName`。我们还使用`boxContainerElement.getElementsByClassName('box')`来检索所有具有`box`类的元素，这些元素是具有`boxContainer`类的元素的后代。

最明显的观察是，在这种情况下，我们需要 18 行代码才能实现相同的结果。相比之下，当使用 jQuery 时，我们只需要 9 行代码，这是后面实现所需行数的一半。使用 jQuery 的`$()`函数与 CSS 选择器是检索所需元素的更简单的方法，它还确保与不支持`getElementsByClassName()`方法的浏览器的兼容性。然而，除了代码行数和改进的可读性之外，还有更多的好处。作为复合模式的实施者，`$()`函数始终检索元素集合，使我们的代码在与我们使用的每个`getElement*`方法的差异化处理相比更加统一。我们以完全相同的方式使用`$()`函数，无论我们是只想检索具有唯一 ID 的元素，还是具有特定类的一些元素。

作为返回类似数组的对象的额外好处，jQuery 还可以提供更方便的方法来遍历和操作 DOM，例如我们在第一个示例中看到的`.css()`、`.append()`和`.parent()`方法，它们作为返回对象的属性可访问。此外，jQuery 还提供了抽象更复杂的用例的方法，例如没有等效方法可用作 DOM API 的一部分的`.addClass()`和`.wrap()`。

由于返回的 jQuery 集合对象除了封装的元素不同之外，我们可以以相同的方式使用 jQuery API 的任何方法。正如我们前面所看到的，这些方法适用于检索到的每个元素，而不管元素计数如何。因此，我们不需要单独的`for`循环来迭代每个检索到的元素并分别应用我们的操作；相反，我们直接将我们的操作（例如`.addClass()`）应用到集合对象上。

为了在后面的示例中继续提供相同的执行安全保证，我们还需要添加一些额外的`if`语句来检查`null`值。这是必需的，因为，例如，如果未找到`headerElement`，将会发生错误，并且其余的代码行将永远不会被执行。有人可能会认为这些检查，如`if (headerElement)`和`if (boxContainerElement)`在本示例中不是必需的，可以省略。在这个示例中，这似乎是正确的，但实际上这是在开发大型应用程序时发生错误的主要原因之一，其中元素不断地被创建、插入和删除到 DOM 树中。不幸的是，所有语言和目标平台的程序员都倾向于首先编写他们的实现逻辑，然后在以后的某个时候填写这些检查，通常是在测试实现时出现错误后。

遵循复合模式，即使是一个空的 jQuery 集合对象（不包含任何检索到的元素），仍然是一个有效的集合对象，我们可以安全地应用 jQuery 提供的任何方法。因此，我们不需要额外的`if`语句来检查集合是否实际包含任何元素，然后应用诸如`.css()`之类的方法，仅仅是为了避免 JavaScript 运行时错误。

总的来说，jQuery 使用复合模式提供的抽象使得代码行数减少，更易读、统一，并且有更少的易出错行（比较输入`$('#elementID')`与`document.getElementById('elementID')`）。

## 使用复合模式开发应用程序

现在我们已经看到了 jQuery 如何在其架构中使用复合模式，并且还进行了比较以及提供的好处，让我们尝试编写一个自己的示例用例。我们将尝试涵盖本章中早期看到的所有概念。我们将结构化我们的复合对象以成为一个类似数组的对象，操作完全不同结构的对象，提供流畅的 API 以允许链式调用，并且具有应用于集合中所有项目的方法。

### 一个示例用例

假设我们有一个应用程序，某个时刻需要对数字执行操作。另一方面，它需要操作的项目来自不同的来源，且完全不统一。为了使这个示例有趣，假设数据的一个来源提供普通数字，另一个提供具有包含我们感兴趣数字的特定属性的对象：

```js
var numberValues = [2, 5, 8]; 

var objectsWithValues = [ 
    { value: 7 }, 
    { value: 4 }, 
    { value: 6 }, 
    { value: 9 } 
];
```

在我们使用情景的第二个来源返回的对象可能具有更复杂的结构，可能还有一些额外的属性。这些更改不会以任何方式区分我们的示例实现，因为在开发复合对象时，我们只对提供对目标项目的共同部分进行统一处理感兴趣。

### 复合集合实现

让我们继续并定义构造函数和原型，来描述我们的组合集合对象：

```js
function ValuesComposite() { 
    this.length = 0; 
} 

ValuesComposite.prototype.append = function(item) { 
    if ((typeof item === 'object' && 'value' in item) || 
        typeof item === 'number') { 
        this[this.length] = item; 
        this.length++; 
    } 

    return this; 
}; 

ValuesComposite.prototype.increment = function(number) { 
    for (var i = 0; i < this.length; i++) { 
        var item = this[i]; 
        if (typeof item === 'object' && 'value' in item) { 
            item.value += number; 
        } else if (typeof item === 'number') { 
            this[i] += number; 
        } 
    } 

    return this; 
}; 

ValuesComposite.prototype.getValues = function() { 
    var result = []; 
    for (var i = 0; i < this.length; i++) { 
        var item = this[i]; 
        if (typeof item === 'object' && 'value' in item) { 
            result.push(item.value); 
        } else if (typeof item === 'number') { 
            result.push(item); 
        } 
    } 
    return result; 
};
```

在我们的例子中，`ValuesComposite()` 构造函数非常简单。当使用 `new` 操作符调用时，它返回一个长度为零的空对象，表示它包装的集合是空的。

### 注意

有关 JavaScript 基于原型的编程模型的更多信息，请访问 [`developer.mozilla.org/zh-CN/docs/Web/JavaScript/Introduction_to_Object-Oriented_JavaScript`](https://developer.mozilla.org/zh-CN/docs/Web/JavaScript/Introduction_to_Object-Oriented_JavaScript)。

我们首先需要定义一种方法，使我们能够填充我们的组合集合对象。我们定义了 `append` 方法，该方法检查提供的参数是否是它可以处理的类型之一；在这种情况下，它将参数附加到组合对象上的下一个可用数字属性，并增加 `length` 属性值。例如，第一个附加的项，无论是具有值属性的对象还是纯数字，都将暴露给组合对象的 "`0`" 属性，并可以使用括号属性访问者的语法访问为 `myValuesComposition[0]`。

`increment` 方法被呈现为一个简单的例子方法，可以通过操作所有集合项来操作这些集合。它接受一个数字值作为参数，然后根据它们的类型适当地处理它，将它添加到我们集合的每个项中。由于我们的组合是类似于数组的对象，`increment` 使用 `for` 循环来迭代所有集合项，并增加 `item.value`（如果项是对象）或存储的实际数字值（当集合项存储的是数字时）。同样地，我们可以继续实现其他方法，例如使我们能够将集合项与特定数字相乘。

为了允许链接我们的组合对象的方法，原型的所有方法都需要返回对对象实例的引用。我们通过简单地在操纵集合的所有方法的最后一行添加 `return this;` 语句来实现这个目标，例如 `append` 和 `increment`。请记住，例如 `getValues` 这样不操纵集合但用于返回结果的方法，根据定义，不能链接到传递集合对象实例的后续方法调用。

最后，我们实现 `getValues` 方法作为检索我们集合中所有项的实际数字值的便捷方式。与 `increment` 方法类似，`getValues` 方法抽象了我们集合的不同项类型之间的处理。它遍历集合项，提取每个数字值，并将它们附加到一个 `result` 数组中，然后返回给它的调用者。

### 一个例子执行

现在让我们看一个实际的例子，将使用我们刚刚实现的组合对象：

```js
var valuesComposition = new ValuesComposite(); 

for (var i = 0; i < numberValues.length; i++) { 
    valuesComposition.append(numberValues[i]); 
} 

for (var i = 0; i < objectsWithValues.length; i++) { 
    valuesComposition.append(objectsWithValues[i]); 
}

valuesComposition.increment(2) 
    .append(1) 
    .append(2) 
    .append({ value: 3 }); 

console.log(valuesComposition.getValues()); 
```

当在浏览器中执行上述代码时，通过将代码编写到现有页面或直接编写到浏览器控制台中，将记录如下结果：

```js
► Array [ 4, 7, 10, 9, 6, 8, 11, 1, 2, 3 ]
```

我们正在使用我们的数据源，例如前面显示的`numberValues`和`objectsWithValues`变量。上述代码遍历它们并将它们的项附加到一个新创建的组合对象实例上。然后，我们通过 2 递增我们的复合集合的值。紧接着，我们使用`append`链式三个项目插入，前两个追加数值，第三个追加一个具有值属性的对象。最后，我们使用`getValues`方法获取一个包含我们集合所有数值的数组，并在浏览器控制台中记录它。

### 可选的实现方式

请记住，组合对象不一定要是类似数组的对象，但通常偏好于这样的实现，因为 JavaScript 让创建这样的实现变得很容易。另外，类似数组的实现还有一个好处，就是允许我们使用简单的`for`循环迭代集合项。

另一方面，如果不喜欢类似数组的对象，我们可以轻松地在组合对象上使用一个属性来保存我们的集合项。例如，这个属性可以命名为`items`，并且可以在我们的方法中使用`this.items.push(item)`和`this.items[i]`来存储和访问集合的项，分别。

# 迭代器模式

迭代器模式的关键概念是使用一个负责遍历集合并提供对其项访问的函数。这个函数被称为迭代器，提供了一种访问集合项的方式，而不暴露具体实现和集合对象所使用的底层数据结构。

迭代器提供了关于迭代发生方式的封装级别，将集合项的迭代与其消费者的实现逻辑解耦。

### 注意

关于**单一职责原则**的更多信息，请访问[`www.oodesign.com/single-responsibility-principle.html`](http://www.oodesign.com/single-responsibility-principle.html)。

## jQuery 如何使用迭代器模式

正如我们在本章前面看到的，jQuery 核心`$()`函数返回一个类似数组的对象，包装了一组页面元素，并提供了一个迭代函数来遍历它并单独访问每个元素。它实际上进一步提供了一个通用的辅助方法`jQuery.each()`，可以迭代数组、类似数组的对象，以及对象属性。

更多技术描述可以在 jQuery API 文档页面[`api.jquery.com/jQuery.each/`](http://api.jquery.com/jQuery.each/)中找到，其中`jQuery.each()`的描述如下：

> 一个通用的迭代器函数，可以无缝地迭代对象和数组。数组和具有长度属性的类数组对象（例如函数的参数对象）通过数值索引迭代，从 0 到 length-1。其他对象通过它们的命名属性进行迭代。

`jQuery.each()`辅助函数在 jQuery 源代码的几个地方内部使用。其中一个用途是遍历 jQuery 对象的条目，并对每个条目应用操作，这正如组合模式所建议的那样。简单搜索关键字`.each(`会发现有 56 个匹配结果。

### 注意

在撰写本书时，最新的稳定版本是 v2.2.0，它被用于上述统计信息。

我们可以轻松地跟踪它在 jQuery 源码中的实现，可以通过搜索`"each:"`（注意有两个出现）或使用 jQuery 源码查看器搜索`"jQuery.each()"`（就像我们在本章早些时候做的那样）：

```js
each: function( obj, callback ) {
  var length, i = 0;

  if ( isArrayLike( obj ) ) {
    length = obj.length;
    for ( ; i < length; i++ ) {
      if ( callback.call( obj[ i ], i, obj[ i ] ) === false ) {
        break;
      }
    }
  } else {
    for ( i in obj ) {
      if ( callback.call( obj[ i ], i, obj[ i ] ) === false ) {
        break;
      }
    }
   }

  return obj;
}
```

这个辅助函数也可以通过使用之前看到的像`.append()`这样的方法一样的原型继承在任何 jQuery 对象上访问。你可以轻松找到确切实现这个功能的代码，只需在 jQuery 源码查看器中搜索`"jQuery.fn.each()"`或者直接搜索 jQuery 源代码中的`each:`（注意有两个出现的地方）：

```js
each: function( callback ) {
  return jQuery.each( this, callback );
}
```

使用`".each()"`的方法版本可以让我们以更方便的语法直接迭代 jQuery 集合对象的元素。

下面的示例代码展示了如何在我们的代码中使用两种`.each()`的方式：

```js
// using the helper function on an array
$.each([3, 5, 7], function(index){
    console.log(this + 1);
});
// using the method on a jQuery object
$('.boxContainer .box').each(function(index) {
    console.log('I\'m box #' + (index + 1)); // index is zero-based
});
```

当执行时，前面的代码将在浏览器控制台上记录以下内容：

![jQuery 如何使用迭代器模式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00006.jpeg)

## 与组合模式搭配使用

因为组合模式将一个项目集合封装为单个对象，并且迭代器模式可以用于迭代抽象数据结构，所以我们可以很容易地将这两种模式描述为互补的。

## 可以在哪里使用

迭代器模式可以用于我们的应用程序中抽象化我们从数据结构中访问项目的方式。例如，假设我们需要从以下树形结构中检索大于 4 的所有项目：

```js
var collection = { 
    nodeValue: 7, 
    left: { 
        nodeValue: 4, 
        left: 2, 
        right: { 
            nodeValue: 6, 
            left: 5, 
            right: 9 
        } 
    }, 
    right: { 
        nodeValue: 9, 
        left: 8 
    } 
}; 
```

现在让我们实现迭代器函数。因为树形数据结构可以有嵌套，所以我们最终得到下面的递归实现：

```js
function iterateTreeValues(node, callback) { 
    if (node === null || node === undefined) { 
        return; 
    } 

    if (typeof node === 'object') { 
        if ('left' in node) { 
            iterateTreeValues(node.left, callback); 
        } 
        if ('nodeValue' in node) { 
            callback(node.nodeValue); 
        } 
        if ('right' in node) { 
            iterateTreeValues(node.right, callback); 
        } 
    } else { 
        // its a leaf, so the node is the value 
        callback(node); 
    } 
} 
```

最后，我们得到的实现如下所示：

```js
var valuesArray = []; 
iterateTreeValues(collection, function(value) { 
    if (value > 4) { 
        valuesArray.push(value); 
    } 
}); 
console.log(valuesArray);
```

当执行时，前面的代码将在浏览器控制台上记录以下内容：

```js
► Array [ 5, 6, 9, 7, 8, 9 ]
```

我们可以清楚地看到迭代器简化了我们的代码。我们再也不需要每次访问满足特定条件的一些项目时烦恼于使用的数据结构的实现细节。我们的实现建立在迭代器公开的通用 API 之上，并且我们的实现逻辑出现在我们为迭代器提供的回调中。

这种封装使我们能够将我们的实现与所使用的数据结构解耦，前提是将提供具有相同 API 的迭代器。例如，在这个例子中，我们可以轻松地将使用的数据结构更改为排序的二叉树或简单数组，并保持我们的实现逻辑不变。

# 摘要

在本章中，我们对 JavaScript 的 DOM 脚本 API 和 jQuery 进行了复习。我们介绍了复合模式，并看到了它是如何被 jQuery 库使用的。我们看到了复合模式如何简化我们的工作流程，当我们在不使用 jQuery 的情况下重新编写了我们的示例页面之后，并且随后展示了在我们的应用程序中使用复合模式的示例。最后，我们介绍了迭代器模式，并看到了当与复合模式一起使用时它是多么出色。

现在我们已经完成了关于复合模式在我们日常使用 jQuery 方法中发挥重要作用的介绍，我们可以继续下一章，在那里我们将展示观察者模式以及使用 jQuery 在我们的页面中方便地利用它的方式。


# 第二章：观察者模式

在本章中，我们将展示观察者模式以及我们如何使用 jQuery 在我们的页面中方便地利用它。随后，我们还将解释委托事件观察者模式的变体，当正确应用于网页时，可以简化代码并减少页面所需的内存消耗。

在本章中，我们将：

+   介绍观察者模式

+   查看 jQuery 如何使用观察者模式

+   将观察者模式与使用事件属性进行比较

+   学习如何避免观察者引起的内存泄漏

+   介绍委托事件观察者模式并展示其好处

# 介绍观察者模式

观察者模式的关键概念是有一个对象，通常称为可观察对象或主体，在其生命周期内其内部状态会发生变化。还有其他几个对象，被称为观察者，它们希望在可观察对象/主体的状态发生变化时被通知，以执行一些操作。

观察者可能需要被通知关于可观察对象的任何状态改变，或者仅特定类型的改变。在最常见的实现中，可观察对象维护一个观察者列表，并在适当的状态改变发生时通知它们。如果可观察对象发生状态改变，它会遍历对那种类型的状态改变感兴趣的观察者列表，并执行它们定义的特定方法。

![介绍观察者模式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00007.jpeg)

根据观察者模式的定义和计算机科学书籍中的参考实现，观察者被描述为实现了众所周知的编程接口的对象，大多数情况下，该接口对于它们感兴趣的每个可观察对象都是特定的。在状态改变的情况下，可观察对象将执行每个观察者的众所周知方法，因为它在编程接口中被定义。

### 注意

有关在传统的面向对象编程中如何使用观察者模式的更多信息，您可以访问 [`www.oodesign.com/observer-pattern.html`](http://www.oodesign.com/observer-pattern.html)。

在 Web 堆栈中，观察者模式通常使用普通的匿名回调函数作为观察者，而不是具有众所周知方法的对象。可以通过等效结果实现观察者模式，因为回调函数保留了对其定义所在环境的变量的引用——这种模式通常被称为**闭包**。使用观察者模式而不是回调作为调用或初始化参数的主要优点是观察者模式可以支持单个目标上的几个独立处理程序。

### 注意

有关闭包的更多信息，您可以访问 [`developer.mozilla.org/en-US/docs/Web/JavaScript/Closures`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Closures)。

### 提示

**定义简单回调**

回调可以定义为作为另一个函数/方法的参数传递或分配给对象的属性，并且期望在稍后的某个时间点执行的函数。通过这种方式，将我们的回调交给的代码将调用它，将操作或事件的结果传播回定义回调的上下文。

由于将函数注册为观察者的模式被证明更灵活和更简单直接的编程，它在网页堆栈之外的编程语言中也可以找到。其他编程语言通过语言特性或特殊对象（如子例程、lambda 表达式、块和函数指针）提供了等效的功能。例如，Python 也像 JavaScript 一样将函数定义为一等对象，使它们能够被用作回调函数，而 C#则定义了委托作为特殊对象类型，以实现相同的结果。

观察者模式是开发响应用户操作的 Web 界面的一个组成部分，每个 Web 开发人员都在某种程度上使用它，即使在不知情的情况下也是如此。这是因为创建丰富用户界面时，Web 开发人员需要做的第一件事是向页面元素添加事件侦听器，并定义浏览器应该如何响应它们。

传统上，这是通过在需要监听事件的页面元素上使用`EventTarget.addEventListener()`方法实现的，例如“点击”，并提供一个回调函数，其中包含需要在事件发生时执行的代码。值得一提的是，为了支持旧版本的 Internet Explorer，需要测试`EventTarget.attachEvent()`的存在，并使用它来代替。

### 注意

有关`addEventListener()`和`attachEvent()`方法的更多信息，您可以访问[`developer.mozilla.org/en-US/docs/Web/API/EventTarget/addEventListener`](https://developer.mozilla.org/en-US/docs/Web/API/EventTarget/addEventListener)和[`developer.mozilla.org/en-US/docs/Web/API/EventTarget/attachEvent`](https://developer.mozilla.org/en-US/docs/Web/API/EventTarget/attachEvent)。

## jQuery 如何使用它

jQuery 库在其实现的几个部分中大量使用观察者模式，直接使用`addEventListener`方法或创建其自己的抽象来实现。此外，jQuery 提供了一系列抽象和方便的方法，使在 Web 上使用观察者模式变得更容易，并且还在内部使用其中一些方法来实现其他方法。

### jQuery 的 on 方法

`jQuery.fn.on()`方法是将事件处理程序附加到元素的中央 jQuery 方法，提供了一种简单的方法来采用观察者模式，同时保持我们的代码易于阅读和理解。它将所请求的事件处理程序附加到由`$()`函数返回的复合 jQuery 集合对象的所有元素上。

在 jQuery 源码查看器中搜索 `jQuery.fn.on`（可在 [`james.padolsey.com/jquery`](http://james.padolsey.com/jquery) 找到），或直接在 jQuery 源代码中搜索 `on: function`（第一个字符是制表符），将引导我们找到方法的定义，代码共有 67 行。事实上，在内部 `on` 函数的前 55 行只是处理 `jQuery.fn.on()` 方法可以被调用的不同方式；接近末尾，我们能看到它实际上使用了内部方法 `jQuery.event.add()`：

```js
jQuery.fn.extend({
  on: function( types, selector, data, fn ) {
    return on( this, types, selector, data, fn );
  }
});

function on( elem, types, selector, data, fn, one ) {

  /* 55 lines of code handling the method overloads */
  return elem.each( function() {
    jQuery.event.add( this, types, fn, data, selector );
  } );
}
```

```js
 trimmed down version of that method, where some code related to the technical implementation of jQuery and not related to the Observer Pattern has been removed for clarity:
```

```js
add: function( elem, types, handler, data, selector ) { 
    /* ... 4 lines of code ... */
        elemData = dataPriv.get( elem ); 
    /* ... 13 lines of code ... */

    // Make sure that the handler has a unique ID, 
    // used to find/remove it later 
 if ( !handler.guid ) { 
 handler.guid = jQuery.guid++; 
 } 

    // Init the element's event structure and main handler, 
    // if this is the first 
 if ( !( events = elemData.events ) ) { 
 events = elemData.events = {}; 
 } 
    /* ... 9 lines of code ... */ 

    // Handle multiple events separated by a space 
    types = ( types || "" ).match( rnotwhite ) || [ "" ]; 
    t = types.length; 
    while ( t-- ) { 
        /* ... 30 lines of code ... */ 

        // Init the event handler queue if we're the first 
        if ( !( handlers = events[ type ] ) ) { 
 handlers = events[ type ] = []; 
            handlers.delegateCount = 0; 

            // Only use addEventListener if the special events handler
            // returns false 
            if ( !special.setup || special.setup.call( elem, data, namespaces, eventHandle ) === false ) {
 if ( elem.addEventListener ) { 
 elem.addEventListener( type, eventHandle ); 
 } 
            } 
        }

        /* ... 9 lines of code ... */ 

        // Add to the element's handler list, delegates in front 
 if ( selector ) { 
 handlers.splice( handlers.delegateCount++, 0, handleObj ); 
 } else { 
 handlers.push( handleObj ); 
 }
        /* ... 3 lines of code ... */
    } 
}
```

现在，让我们通过引用前面高亮的代码，了解 `jQuery.event.add()` 如何实现观察者模式。

`jQuery.event.add()` 方法的参数中的 `handler` 变量存储最初作为参数传递给 `jQuery.fn.on()` 方法的函数。我们可以称这个函数为我们的观察器函数，因为它在附加到的元素上触发相应事件时被执行。

在第一个高亮的代码区域中，jQuery 创建并给存储在 `handler` 变量中的观察器函数分配了一个 `guid` 属性。记住，在 JavaScript 中，可以给函数赋值属性，因为函数是一流对象。`jQuery.guid++` 语句在分配旧值之后执行，这是因为 `jQuery.guid` 是 jQuery 和 jQuery 插件在内部使用的全局计数器。观察器函数上的 `guid` 属性用作标识和定位 jQuery 为每个元素维护的观察器函数列表中的观察器函数的一种方式。例如，`jQuery.fn.off()` 方法使用它来定位并从与元素关联的观察器函数列表中删除观察器函数。

### 小贴士

`jQuery.guid` 是一个页面范围的计数器，它被插件和 jQuery 本身用作集中的方式来检索唯一的整数 ID。它通常用于给元素、对象和函数分配唯一的 ID，以便更容易地在集合中定位它们。每个检索和使用 `jQuery.guid` 当前值的实现者都有责任在每次使用后也增加属性值（加一）。否则，由于这是一个页面范围的计数器，被 jQuery 插件和 jQuery 自己用于标识，页面可能会面临难以调试的故障。

在第二个和第三个突出显示的代码区域中，jQuery 初始化一个数组来保存每个可能在该元素上触发的事件的观察者列表。需要注意的是，第二个突出显示的代码区域中的观察者列表并不是实际 DOM 元素的属性。正如 `jQuery.event.add()` 方法开头附近的 `dataPriv.get( elem )` 语句所示，jQuery 使用单独的映射对象来保存 DOM 元素与其观察者列表之间的关联。通过使用这种数据缓存机制，jQuery 能够避免向 DOM 元素添加额外属性，这些属性是其实现所需要的。

### 注意

您可以通过搜索 `function Data()` 在 jQuery 源代码中轻松找到数据缓存机制的实现。这将带您到 `Data` 类的构造函数，该构造函数后面跟随着在 `Data.prototype` 对象中定义的类方法的实现。有关更多信息，您可以访问 [`api.jquery.com/data`](http://api.jquery.com/data)。

下一个突出显示的代码区域是 jQuery 检查 `EventTarget.addEventListener()` 方法是否实际上对该元素可用，然后使用它将事件监听器添加到该元素。在最后一个突出显示的代码区域中，jQuery 将观察者函数添加到其内部列表中，该列表保存了附加到该特定元素的相同事件类型的所有观察者。

### 注意

根据您所使用的版本，可能会在某种程度上获得不同的结果。编写本书时发布和使用的最新稳定的 jQuery 版本是 v2.2.0。

如果您需要为旧版浏览器（例如低于版本 9 的 Internet Explorer）提供支持，则应使用 jQuery 的 v1.x 版本。编写本书时的最新版本是 v1.12.0，它提供与 v2.2.x 版本完全相同的 API，但也具有在旧版浏览器上运行所需的代码。

为了涵盖旧版浏览器的实现不一致性，jQuery v1.x 中 `jQuery.event.add()` 的实现要长一些，更复杂一些。其中一个原因是因为 jQuery 还需要测试浏览器是否实际上支持 `EventTarget.addEventListener()`，如果不是，则尝试使用 `EventTarget.attachEvent()`。

正如我们在前面的代码中看到的，jQuery 的实现遵循观察者模式描述的操作模型，但也融入了一些实现技巧，以使其与 Web 浏览器可用的 API 更有效地配合工作。

### 文档准备就绪的观察者

jQuery 提供的另一个方便的方法，是被开发人员广泛使用的`$.fn.ready()`方法。此方法接受一个函数参数，仅在页面的 DOM 树完全加载后才执行它。这在以下情况下可能会有用：如果您的代码不是最后加载到页面上，而且您不想阻塞初始页面呈现，或者它需要操作的元素被定义在其自身`<script>`标签之后。

### 注意

请记住，`$.fn.ready()`方法的工作方式与`window.onload`回调和页面的"load"事件稍有不同，它们会等待页面的所有资源加载完毕。有关更多信息，您可以访问[`api.jquery.com/ready`](http://api.jquery.com/ready)。

以下代码演示了`$.fn.ready()`方法的最常见使用方式：

```js
$(document).ready(function() {
    /* this code will execute only after the page has been fully loaded */ 
})
```

如果我们尝试找到`jQuery.fn.ready`的实现，我们会看到它实际上在内部使用`jQuery.ready.promise`来工作：

```js
jQuery.fn.ready = function( fn ) { 
  // Add the callback 
  jQuery.ready.promise().done( fn ); 

  return this; 
};
/* … a lot lines of code in between */
jQuery.ready.promise = function( obj ) { 
  if ( !readyList ) { 

    readyList = jQuery.Deferred(); 

    // Catch cases where $(document).ready() is called
    // after the browser event has already occurred.
    // Support: IE9-10 only
    // Older IE sometimes signals "interactive" too soon
    if ( document.readyState === "complete" || ( document.readyState !== "loading" && !document.documentElement.doScroll ) ) {
      // Handle it asynchronously to allow ... to delay ready 
      window.setTimeout( jQuery.ready ); 

    } else { 
      // Use the handy event callback 
 document.addEventListener( "DOMContentLoaded", completed ); 

      // A fallback to window.onload, that will always work 
 window.addEventListener( "load", completed ); 
    } 
  } 
  return readyList.promise( obj ); 
};
```

正如您在实现中前面高亮显示的代码区域中所见，jQuery 使用`addEventListener`来观察`document`对象上的`DOMContentLoaded`事件何时触发。另外，为了确保它在各种浏览器中都能工作，它还注意到`window`对象上的`load`事件何时被触发。

jQuery 库还提供了在代码中添加上述功能的更短的方法。由于上述实现实际上不需要对文档的引用，因此我们可以用`$().ready(function() {/* ... */ })`来代替。还存在一个`$()`函数的重载，它能够达到相同的效果，它的使用方式是`$(function() {/* ... */ })`。这两种替代方法使用`jQuery.fn.ready`在开发者中受到了严重批评，因为它们通常会导致误解。尤其是第二种更为简短的版本会引起混淆，因为它看起来像一个**立即调用的函数表达式**（**IIFE**），这是 JavaScript 开发人员大量使用和已学会识别的一种模式。实际上，它只有一个字符(`$`)的不同，因此在与开发团队讨论之前不建议使用它。

### 注意

`$.fn.ready()`方法也被称为为我们的代码实现惰性初始化/执行模式提供了一种简单的方法。该模式的核心概念是推迟执行一段代码或在以后的时间点加载远程资源。例如，我们可以等待页面完全加载后再添加观察者，或者在下载网页资源之前等待某个特定事件发生。

## 演示一个样本用例

为了看到观察者模式的实际效果，我们将创建一个示例来展示控制面板的骨架实现。在我们的示例中，用户将能够向其控制面板添加与标题栏中可供选择的一些示例项目和类别相关的信息框。

我们的示例将为我们的项目设有三个预定义的类别：**产品**、**销售**和**广告**。每个类别都将有一系列相关项目，这些项目将出现在类别选择器正下方的区域。用户可以通过使用下拉选择器选择所需的类别，这将更改仪表板的可见选择项目。

![演示一个使用案例](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00008.jpeg)

我们的仪表板最初将包含关于仪表板用法的提示信息框。每当用户点击类别项之一时，一个新的信息框将出现在我们的三列布局仪表板中。在前述图像中，用户通过点击相关按钮为**产品 B**和**产品 D**添加了两个新的信息框。

![演示一个使用案例](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00009.jpeg)

用户还可以通过点击每个信息框顶部右侧的红色关闭按钮来取消这些信息框中的任何一个。在前述图像中，用户取消了**产品 D**信息框，然后添加了**广告 3**以及**销售**类别的第 1、2 和 3 周项目的信息框。

通过仅仅阅读上述描述，我们可以轻松地分离出所有实现我们仪表板所需的用户交互。我们将需要为每一个这些用户交互添加观察者，并在回调函数中编写执行适当 DOM 操作的代码。

具体来说，我们的代码将需要：

+   观察当前选定元素所做的更改，并通过隐藏或显示相应项目来响应此类事件

+   观察每个项目按钮的点击并通过添加新的信息框来响应

+   观察每个信息框的关闭按钮的点击并通过将其从页面中移除来响应

现在让我们继续并查看所需的 HTML、CSS 和 JavaScript 代码，以完成前面的示例。让我们从 HTML 代码开始，假设我们将其保存在名为`Dashboard Example.html`的文件中，代码如下：

```js
<!DOCTYPE html> 
<html> 
  <head> 
    <title>Dashboard Example</title> 
    <link rel="stylesheet" type="text/css" href="dashboard-example.css"> 
  </head> 
  <body> 
    <h1 id="pageHeader">Dashboard Example</h1> 

    <div class="dashboardContainer"> 
      <section class="dashboardCategories"> 
        <select id="categoriesSelector"> 
          <option value="0" selected>Products</option> 
          <option value="1">Sales</option> 
          <option value="2">Advertisements</option> 
        </select> 
        <section class="dashboardCategory"> 
          <button>Product A</button> 
          <button>Product B</button> 
          <button>Product C</button> 
          <button>Product D</button> 
          <button>Product E</button> 
        </section> 
        <section class="dashboardCategory hidden"> 
          <button>1st week</button> 
          <button>2nd week</button> 
          <button>3rd week</button> 
          <button>4th week</button> 
        </section> 
        <section class="dashboardCategory hidden"> 
          <button>Advertisement 1</button> 
          <button>Advertisement 2</button> 
          <button>Advertisement 3</button> 
        </section> 
        <div class="clear"></div> 
      </section> 

      <section class="boxContainer"> 
        <div class="boxsizer"> 
          <article class="box"> 
            <header class="boxHeader"> 
              Hint! 
              <button class="boxCloseButton">&#10006;</button> 
            </header> 
            Press the buttons above to add information boxes... 
          </article> 
        </div> 
      </section> 
      <div class="clear"></div> 
    </div> 

    <script type="text/javascript" src="img/jquery.js"></script> 
    <script type="text/javascript" src="img/dashboard-example.js">
    </script> 
  </body> 
</html>
```

在前述 HTML 中，我们将所有与仪表板相关的元素放在带有`dashboardContainer` CSS 类的`<div>`元素内。这将使我们能够有一个中心起点来搜索我们仪表板的元素，并且作用域我们的 CSS。在它内部，我们使用一些 HTML5 语义元素定义了两个`<section>`元素，以便使用逻辑区域划分仪表板。

第一个带有`dashboardCategories`类的`<section>`用于保存我们仪表板的类别选择器。在其中，我们有一个带有 ID `categoriesSelector`的`<select>`元素，用于过滤可见的类别项目，以及三个带有`dashboardCategory`类的子部分，用于包装在单击时将用信息框填充仪表板的`<button>`元素。其中两个还具有`hidden`类，以便在页面加载时仅显示第一个，通过匹配类别选择器的最初选择选项(`<option>`)。此外，在第一节的末尾，我们还添加了一个带有`clear`类的`<div>`，正如我们在第一章中看到的那样，它将用于清除浮动的`<button>`元素。

带有`boxContainer`类的第二个`<section>`用于保存我们仪表板的信息框。最初，它仅包含一个关于如何使用仪表板的提示。我们使用带有`boxsizer`类的`<div>`元素来设置框尺寸，以及带有`box`类的 HTML5 `<article>` 元素来添加所需的边框填充和阴影，类似于第一章中的框元素。

每个信息框除了其内容之外，还包含一个带有`boxHeader`类的`<header>`元素和一个带有`boxCloseButton`类的`<button>`元素，当点击时，会移除包含它的信息框。我们还使用了`&#10006;` HTML 字符代码作为按钮的内容，以获得更漂亮的“x”标记，并避免使用单独的图像来实现此目的。

最后，由于信息框也是浮动的，我们还需要一个带有`clear`类的`<div>`放置在`boxContainer`的末尾。

在前述 HTML 的`<head>`中，我们还引用了一个名为`dashboard-example.css`的 CSS 文件，其内容如下：

```js
.dashboardCategories { 
    margin-bottom: 10px; 
} 

.dashboardCategories select, 
.dashboardCategories button { 
    display: block; 
    width: 200px; 
    padding: 5px 3px; 
    border: 1px solid #333; 
    margin: 3px 5px; 
    border-radius: 3px; 
    background-color: #FFF; 
    text-align: center; 
    box-shadow: 0 1px 1px #777; 
    cursor: pointer; 
} 

.dashboardCategories select:hover, 
.dashboardCategories button:hover { 
    background-color: #DDD; 
} 

.dashboardCategories button { 
    float: left; 
} 

.box { 
    padding: 7px 10px; 
    border: solid 1px #333; 
    margin: 5px 3px; 
    box-shadow: 0 1px 2px #777; 
} 

.boxsizer { 
    float: left; 
    width: 33.33%; 
} 

.boxHeader { 
    padding: 3px 10px;
    margin: -7px -10px 7px;
    background-color: #AAA; 
    box-shadow: 0 1px 1px #999; 
} 

.boxCloseButton { 
    float: right; 
    height: 20px; 
    width: 20px; 
    padding: 0; 
    border: 1px solid #000; 
    border-radius: 3px; 
    background-color: red; 
    font-weight: bold; 
    text-align: center; 
    color: #FFF; 
    cursor: pointer; 
} 

.clear { clear: both; } 
.hidden { display: none; }
```

正如您在我们的 CSS 文件中所看到的，首先我们在具有`dashboardCategories`类的元素下面添加了一些空间，并且为`<select>`元素和其中的按钮定义了相同的样式。为了使其与默认浏览器样式区分开来，我们添加了一些填充，圆角边框，悬停鼠标指针时的不同背景颜色以及它们之间的一些空间。我们还定义了我们的`<select>`元素应该作为块独自显示在其行中，以及分类项目按钮应该相邻浮动。我们再次使用了`boxsizer`和`box` CSS 类，就像在第一章，*jQuery 和组合模式复习*中所做的一样；第一个用于创建三列布局，第二个实际提供信息框的样式。我们继续定义`boxHeader`类，应用于我们信息框的`<header>`元素，并定义一些填充，灰色背景颜色，轻微阴影，以及一些负边距，以抵消框填充的效果并将其放置在其边框旁边。

要完成信息框的样式设计，我们还定义了`boxCloseButton` CSS 类，它（i）将框的关闭按钮浮动到框的`<header>`内的右上角，（ii）定义了`20px`的宽度和高度，（iii）覆盖了默认浏览器的`<button>`样式以零填充，并且（iv）添加了一个单像素的黑色边框，圆角和红色背景颜色。最后，就像在第一章，*jQuery 和组合模式复习*中，我们定义了`clear`实用的 CSS 类以防止元素被放置在前面浮动元素的旁边，并且还定义了`hidden`类作为隐藏页面元素的方便方式。

在我们的 HTML 文件中，我们引用了 jQuery 库本身以及一个名为`dashboard-example.js`的 JavaScript 文件，其中包含我们的仪表板实现。遵循创建高性能网页的最佳实践，我们将它们放在了`</body>`标签之前，以避免延迟初始页面渲染：

```js
$(document).ready(function() { 

    $('#categoriesSelector').change(function() { 
        var $selector = $(this); 
        var selectedIndex = +$selector.val(); 
        var $dashboardCategories = $('.dashboardCategory'); 
        var $selectedItem = $dashboardCategories.eq(selectedIndex).show(); 
        $dashboardCategories.not($selectedItem).hide();
    }); 

    function setupBoxCloseButton($box) { 
        $box.find('.boxCloseButton').click(function() { 
            $(this).closest('.boxsizer').remove(); 
        }); 
    } 

    // make the close button of the hint box work 
    setupBoxCloseButton($('.box')); 

    $('.dashboardCategory button').on('click', function() { 
        var $button = $(this); 
        var boxHtml = '<div class="boxsizer"><article class="box">' + 
                '<header class="boxHeader">' + 
                    $button.text() + 
                    '<button class="boxCloseButton">&#10006;' + 
                    '</button>' + 
                '</header>' + 
                'Information box regarding ' + $button.text() + 
            '</article></div>'; 
        $('.boxContainer').append(boxHtml); 
        setupBoxCloseButton($('.box:last-child')); 
    });

}); 
```

我们将所有代码放在了一个`$(document).ready()`调用中，以延迟其执行直到页面的 DOM 树完全加载。如果我们将代码放在`<head>`元素中，这将是绝对必要的，但在任何情况下遵循的最佳实践也是很好的。

首先，我们使用`$.fn.change()`方法为`categoriesSelector`元素的`change`事件添加了一个观察者。实际上，这是`$.fn.on('change', /* … */)``方法的一种简写方法。在 jQuery 中，作为观察者使用的函数内的`this`关键字的值保存着被触发事件的 DOM 元素的引用。这适用于所有注册观察者的 jQuery 方法，从核心的`$.fn.on()`到方便的`$.fn.change()`和`$.fn.click()`方法。所以我们使用`$()`函数用`<select>`元素创建一个 jQuery 对象，并将其存储在`$selector`变量中。然后，我们使用`$selector.val()`来检索所选`<option>`的值，并通过使用`+`运算符将其转换为数值。紧接着，我们检索`dashboardCategory`的`<section>`元素，并将结果缓存到`$dashboardCategories`变量中。然后，我们通过找到并显示位置等于`selectedIndex`变量值的类别来继续，并将结果的 jQuery 对象存储到`$selectedItem`变量中。最后，我们使用`$.fn.not()`方法使用`$selectedItem`变量检索并隐藏除了刚刚显示的类别元素之外的所有类别元素。

在下一个代码部分中，我们定义了`setupBoxCloseButton`函数，该函数将用于初始化关闭按钮的功能。它期望一个带有盒子元素的 jQuery 对象作为参数，并且对于每一个盒子元素，搜索它们的后代以找到我们在关闭按钮上使用的`boxCloseButton` CSS 类。使用`$.fn.click()`，这是`$.fn.on('click', /* fn */)`的一个方便方法，我们注册一个匿名函数，以便在每次点击事件被触发时执行，该函数使用`$.fn.closest()`方法来查找具有`boxsizer`类的第一个祖先元素，并将其从页面中删除。紧接着，我们对已经存在于页面中在页面加载时的盒子元素调用此函数一次。在这种情况下，使用提示的盒子元素。

### 注意

使用`$.fn.closest()`方法时需要注意的另一件事情是，它从 jQuery 集合的当前元素开始测试给定的选择器，然后再进行其祖先元素的测试。有关更多信息，您可以访问其文档 [`api.jquery.com/closest`](http://api.jquery.com/closest)。

在最终的代码部分中，我们使用`$.fn.on()`方法在每个类别按钮上添加点击事件的观察者。在这种情况下，在匿名观察者函数内部，我们使用`this`关键字，它保存了被点击的`<button>`的 DOM 元素，并使用`$()`方法创建一个 jQuery 对象，并将其引用缓存在`$button`变量中。紧接着，我们使用`$.fn.text()`方法获取按钮的文本内容，并结合它构建信息框的 HTML 代码。对于关闭按钮，我们使用`&#10006` HTML 字符代码，它将被渲染为更漂亮的“**X**”图标。我们创建的模板基于最初可见提示框的 HTML 代码；在本章的示例中，我们使用纯字符串拼接。最后，我们将生成的 HTML 代码附加到`boxContainer`，由于我们期望它是最后一个元素，我们使用`$()`函数查找它，并将其作为参数传递给`setupBoxCloseButton`。

## 与事件属性相比如何

在 DOM Level 2 Events 规范中定义`EventTarget.addEventListener()`之前，事件监听器的注册方法是通过使用可用于 HTML 元素的事件属性或可用于 DOM 节点的元素事件属性。

### 注意

有关 DOM Level 2 事件规范和事件属性的更多信息，您可以访问[`www.w3.org/TR/DOM-Level-2-Events`](http://www.w3.org/TR/DOM-Level-2-Events)和[`developer.mozilla.org/en-US/docs/Web/Guide/HTML/Event_attributes`](https://developer.mozilla.org/en-US/docs/Web/Guide/HTML/Event_attributes)。

事件属性是一组可用于 HTML 元素的属性，提供了一种声明性的方法来定义应在触发该元素上特定事件时执行的 JavaScript 代码片段（最好是函数调用）。由于它们的声明性特质和简单易用的方式，这通常是新开发者首次接触网页开发中的事件的方式。

如果我们在上面的示例中使用了事件属性，那么信息框中关闭按钮的 HTML 代码将如下所示：

```js
<article class="box"> 
    <header class="boxHeader"> 
        Hint! 
 <button onclick="closeInfoBox();" 
                class="boxCloseButton">&#10006;</button> 
    </header> 
    Press the buttons above to add information boxes... 
</article>
```

另外，我们应该更改用于创建新信息框的模板，并将`closeInfoBox`函数暴露在`window`对象上，以便可以从 HTML 事件属性中访问:

```js
window.closeInfoBox = function() { 
    $(this).closest('.boxsizer').remove(); 
};
```

使用事件属性而不是观察者模式的一些缺点包括：

+   它使得更难定义在元素上触发事件时需要执行的多个单独操作

+   这会使页面的 HTML 代码变得更大，且不易读取

+   它违反了关注点分离原则，因为它在我们的 HTML 中添加了 JavaScript 代码，可能会使错误更难跟踪和修复

+   大多数情况下，这会导致事件属性中调用的函数暴露给全局的 `window` 对象，从而“污染”全局命名空间。

使用元素事件属性不需要对我们的 HTML 进行任何更改，所有的实现都保留在我们的 JavaScript 文件中。我们在 `setupBoxCloseButton` 函数中需要进行的更改将使它看起来如下所示：

```js
function setupBoxCloseButton($box) { 
    var $closeButtons = $box.find('.boxCloseButton'); 
    for (var i = 0; i < $closeButtons.length; i++) { 
        $closeButtons[i].onclick = function() { 
 this.onclick = null; 
            $(this).closest('.boxsizer').remove(); 
        }; 
    } 
}
```

请注意，为了方便起见，我们仍然在 DOM 操作中使用 jQuery，但生成的代码仍然具有前述的一些缺点。更重要的是，为了避免内存泄漏，我们还需要在从页面中移除元素之前删除分配给 `onclick` 属性的函数，如果它包含对其应用的 DOM 元素的引用。

使用当今浏览器提供的工具，我们甚至可以达到事件属性声明性质所提供的便利程度。在下图中，您可以看到 Firefox 开发者工具在我们使用它们来检查附加了事件侦听器的页面元素时为我们提供了有用的反馈：

![与事件属性相比如何](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00010.jpeg)

如前图所示，所有附加了观察者的元素旁都有一个 **ev** 标志，单击该标志将显示一个对话框，显示当前附加的所有事件侦听器。为了使我们的开发体验更好，我们可以直接看到这些处理程序所在的文件和行。此外，我们可以单击它们以展开并显示它们的代码，或者单击它们前面的标志以导航到其源并添加断点。

使用观察者模式而不是事件属性的最大好处之一，在于当某个事件发生时需要执行多个操作的情况下清晰可见。假设我们还需要在示例仪表板中添加一个新功能，该功能可以防止用户意外双击类别项目按钮并将相同的信息框两次添加到仪表板。新的实现理想上应完全独立于现有的实现。使用观察者模式，我们只需添加以下代码来观察按钮点击并在 700 毫秒内禁用该按钮：

```js
$(document).ready(function() { 
  $('.dashboardCategory button').on('click', function() { 
    var $button = $(this); 
    $button.prop('disabled', true); 

    setTimeout(function() { 
      $button.prop('disabled', false); 
    }, 700); 
  }); 
});
```

上述代码确实完全独立于基本实现，我们可以将其放在同一个或不同的 JS 文件中，并将其加载到我们的页面中。这在使用事件属性时会更加困难，因为它要求我们在同一个事件处理程序函数中同时定义两个动作；结果，它会强烈地耦合两个独立的动作。

## 避免内存泄漏

正如我们之前所见，使用观察者模式处理网页上的事件有一些强大的优势。当使用`EventTarget.addEventListener()`方法向元素添加观察者时，我们还需要记住，为了避免内存泄漏，我们在将这些元素从页面中移除之前，还必须调用`EventTarget.removeEventListener()`方法，以便观察者也被移除。

### 注意

有关从元素中移除事件侦听器的更多信息，您可以访问[`developer.mozilla.org/zh-CN/docs/Web/API/EventTarget/removeEventListener`](https://developer.mozilla.org/zh-CN/docs/Web/API/EventTarget/removeEventListener)，或者查看 jQuery 等效方法，请访问[`api.jquery.com/off/`](http://api.jquery.com/off/)。

jQuery 库的开发者意识到这样一个实现上的关注点可能会被轻易地忘记或者没有正确处理，从而使得观察者模式的采用看起来更加复杂，因此他们决定将适当的处理封装在`jQuery.event`实现中。因此，当使用任何 jQuery 的事件处理方法，比如核心的`$.fn.on()`或者任何方便的方法，比如`$.fn.click()`或`$.fn.change()`时，观察者函数由 jQuery 本身跟踪，并且如果我们后来决定将元素从页面中移除，它们将被正确取消注册。正如我们之前在`jQuery.event`的实现中看到的那样，jQuery 将每个元素的观察者存储在一个单独的映射对象中。每次我们使用一个 jQuery 方法来从页面中移除 DOM 元素时，它首先通过检查映射对象来确保移除这些元素或任何后代元素上附加的任何观察者。因此，即使我们不使用任何显式移除我们添加到创建的元素上的观察者的方法，我们之前使用的示例代码也不会造成内存泄漏。

### 提示

**在混合使用 jQuery 和纯 DOM 操作时要小心**

即使所有 jQuery 方法都可以确保您免受由从未取消注册的观察者引起的内存泄漏，但请记住，如果使用纯 DOM API 的方法从文档中移除元素，则无法保护您。如果使用`Element.remove()`和`Element.removeChild()`等方法，并且被移除的元素或其后代有附加的观察者，则它们将不会被自动取消注册。当分配给`Element.innerHTML`属性时也是如此。

# 介绍委托事件观察者模式

现在我们已经学习了如何使用 jQuery 使用观察者模式的一些高级细节，我们将介绍一种特殊的变体，它完全适用于 Web 平台并提供了一些额外的好处。委托事件观察器模式（简称委托观察器模式）经常用于 Web 开发，并利用了大多数在 DOM 元素上触发的事件具有的冒泡特性。例如，当我们单击页面元素时，单击事件立即在其上触发，然后在达到 HTML 文档根之前还会在所有父元素上触发。使用 jQuery 的 `$.fn.on` 方法的略有不同的重载版本，我们可以轻松地为触发在特定子元素上的委托事件创建和附加观察者。

### 注意

术语“事件委托”描述了一种编程模式，其中事件的处理程序不直接附加到感兴趣的元素，而是附加到其祖先元素之一。

## 如何简化我们的代码

使用委托事件观察器模式重新实现我们的仪表板示例将只需要更改包含的 JavaScript 文件的代码如下：

```js
$(document).ready(function() { 

    $('#categoriesSelector').change(function() { 
        var $selector = $(this); 
        var selectedIndex = +$selector.val(); 
        var $dashboardCategories = $('.dashboardCategory'); 
        var $selectedItem = $dashboardCategories.eq(selectedIndex).show(); 
        $dashboardCategories.not($selectedItem).hide(); 
    }); 

 $('.dashboardCategories').on('click', 'button', function() { 
        var $button = $(this); 
        var boxHtml = '<div class="boxsizer"><article class="box">' + 
                '<header class="boxHeader">' + 
                    $button.text() + 
                    '<button class="boxCloseButton">&#10006;' + 
                    '</button>' + 
                '</header>' + 
                'Information box regarding ' + $button.text() + 
            '</article></div>'; 
        $('.boxContainer').append(boxHtml); 
    }); 

 $('.boxContainer').on('click', '.boxCloseButton', function() { 
        $(this).closest('.boxsizer').remove(); 
    }); 

});
```

最明显的区别在于新的实现更短。通过仅为适用于多个页面元素的每个操作定义一个观察者，可以获得益处。因此，我们使用 `$.fn.on(events, selector, handler)` 方法的重载变体。

具体来说，我们向具有 `dashboardCategories` CSS 类的页面元素添加一个观察者，并监听其任何 `<button>` 后代触发的 `click` 事件。类似地，我们向 `boxContainer` 元素添加一个观察者，该观察者将在其匹配 `.boxCloseButton` CSS 选择器的任何后代上触发单击事件时执行。

由于上述观察者不仅适用于在注册时存在于页面上的元素，还适用于以后任何时间添加的匹配指定 CSS 选择器的任何元素；我们能够将处理关闭按钮点击的代码解耦，并将其放在一个单独的观察者中，而不是每次添加新信息框时都注册一个新观察者。因此，负责在仪表板中添加新信息框的观察者更简单，只需处理信息框的 HTML 创建和插入到仪表板中，从而实现了更大的关注点分离。此外，我们不再需要在单独的代码片段中处理提示框关闭按钮的观察者注册。

## 比较内存使用优势

我们现在将比较使用`$.fn.on()`方法与简单和委托事件观察者模式变体时的内存使用差异。为了实现这一点，我们将打开我们仪表板示例的两个实现，并在 Chrome 上比较它们的内存使用情况。要打开 Chrome 的开发者工具，只需按下*F12*，然后导航到**Timeline**选项卡。我们在 Chrome 的**Timeline**选项卡中按下"record"按钮，然后按下每个类别项按钮 10 次，将 120 个信息框添加到我们的仪表板。在添加所有框之后，我们总共有 121 个打开的框，因为提示框仍然打开，然后停止时间线记录。

我们初始观察者模式实现的时间线结果如下：

![比较内存使用优势](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00011.jpeg)

为委托事件观察者模式实现重复相同的过程将提供更平滑的时间线，显示较少的对象分配和垃圾收集，如下所示：

![比较内存使用优势](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00012.jpeg)

正如在前面的图片中所示，我们最终在两种情况下都有 1192 个页面元素，但在第一种实现中，我们使用了 134 个事件侦听器，而在使用事件委托的实现中，我们最初创建了三个事件侦听器，并且实际上从未添加过其他事件侦听器。

最后，正如你在图表中看到的蓝线所示，委托版本的内存消耗保持相对稳定，仅增加了约 200 KB。另一方面，在原始实现中，堆大小增加了五倍多，增加了超过 1 MB。

添加这么多元素可能并不是一个实际的使用情况，但是仪表板可能不会是你页面上唯一的动态部分。因此，在一个相对复杂的网页中，如果我们使用委托事件观察者模式的变体重新实现了它的每个适用部分，我们可能会得到类似的改进。

# 摘要

在本章中，我们了解了观察者模式，以及它如何使我们网页的 HTML 代码更清晰，以及它如何将其与我们应用程序的代码解耦。我们了解了 jQuery 如何在其方法中添加保护层，以保护我们免受未检测到的内存泄漏的影响，这可能会在不使用 jQuery DOM 操作方法时，通过向元素添加观察者而发生。

我们还尝试了委托事件观察者模式变体，并将其用于重写我们的初始示例。我们比较了这两种实现，并看到它如何简化了在页面加载后应用于许多页面元素的代码编写。最后，我们就普通观察者模式与其委托变体的内存消耗进行了比较，并强调了它如何通过减少所需的附加观察者数量来减少页面的内存消耗。

现在我们已经完成了关于观察者模式如何用于监听用户操作的介绍，我们可以继续下一章，了解自定义事件、发布/订阅模式以及它们如何导致更解耦的实现方式。


# 第三章：发布/订阅模式

在本章中，我们将展示发布/订阅模式，这是一种设计模式，与观察者模式非常相似，但具有更明确的角色，更适合更复杂的用例。我们将看到它与观察者模式的区别，以及 jQuery 如何采用其某些概念并将其带入其观察者模式实现。

后来，我们将继续并使用此模式重写我们上一章的示例。我们将利用此模式的优势来添加一些额外功能，并减少我们的代码与网页元素之间的耦合。

在本章中，我们将：

+   引入发布/订阅模式

+   了解它与观察者模式的区别以及它的优势在哪里

+   了解 jQuery 如何将一些特性带入其方法中

+   学习如何使用 jQuery 发射自定义事件

+   使用此模式重写并扩展来自第二章的示例，*观察者模式*，

# 介绍发布/订阅模式

发布/订阅模式是一种消息模式，其中称为**发布者**的消息发射器向许多被称为**订阅者**的接收者多播消息，这些接收者已表达了对接收此类消息的兴趣。这种模式的关键概念，也常简称为 Pub/Sub 模式，是提供一种方法以避免发布者和订阅者之间的依赖关系。

这种模式的一个额外概念是使用**主题**，订阅者使用这些主题来表示他们只对特定类型的消息感兴趣。这样一来，发布者在发送消息之前就可以对订阅者进行过滤，并且只将该消息分发给适当的订阅者，从而减少了双方所需的流量和工作量。

![介绍发布/订阅模式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00013.jpeg)

另一个常见的变体是使用一个称为**代理**的中央，应用程序范围内的对象，它将由发布者产生的消息中继给相关的订阅者。在这种情况下，代理充当了一个众所周知的消息处理程序，用于发送和订阅消息主题。这使我们能够不将不同的应用程序部分耦合在一起，而只引用代理本身以及我们的组件感兴趣的主题。尽管主题可能不是该模式的第一变体中的绝对要求，但该变体在可扩展性方面起着至关重要的作用，因为通常会存在比发布者和订阅者少得多的代理（如果不只有一个）。

![介绍发布/订阅模式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00014.jpeg)

通过遵循订阅方案，发布者的代码完全与订阅者解耦，这意味着发布者不必知道依赖于它们的对象。因此，我们不需要在发布者中硬编码每个应该在应用程序的不同部分执行的单独操作。相反，应用程序的组件以及可能的第三方扩展只订阅他们需要知道的主题/事件。在这样的分布式架构中，向现有应用程序添加新功能只需要对其依赖的应用程序组件进行最小到无需更改。

## 它与观察者模式的不同之处

最基本的区别在于，根据定义，发布/订阅模式是一种单向消息模式，可以传递消息，而观察者模式只是描述如何通知观察者有关主题特定状态更改的方法。

此外，与观察者模式不同，带有代理的发布/订阅模式导致实现的不同部分之间的代码更松散耦合。这是因为观察者需要知道发出事件的主题；然而，另一方面，发布者及其订阅者只需知道使用的代理。

# 如何被 jQuery 应用

再次提醒，jQuery 库为我们提供了一种方便的方式来利用代码中的发布/订阅模式。开发人员决定通过扩展`jQuery.fn.on()`和`jQuery.fn.trigger()`方法的能力来处理和发出自定义事件，而不是通过添加名为"publish"和"subscribe"的新方法并引入新概念来扩展其 API。这样，jQuery 可以使用它已经提供的方便的方法来实现使用发布者/订阅者通信方案。

## jQuery 中的自定义事件

自定义事件允许我们使用几乎任何用户定义的字符串值作为我们可以为其添加监听器的通用事件，并在页面元素上手动触发它。作为一个额外但宝贵的特性，自定义事件还可以携带一些额外的数据以传递给事件的监听器。

jQuery 库在任何网页规范实际添加之前就已经添加了自己的自定义事件实现。这样，就证明了在 web 开发中使用它们时可以有多么有用。正如我们在上一章中看到的，在 jQuery 中，有一个特定的部分处理通用元素事件和自定义事件。`jQuery.event` 对象保存了与触发和监听事件相关的所有内部实现。此外，`jQuery.Event` 类是 jQuery 为了满足通用元素事件和其自定义事件实现需要而专门使用的包装器。

## 使用自定义事件实现发布/订阅模式

在上一章中，我们看到 `jQuery.fn.on()` 方法可以用于在元素上添加事件侦听器。我们还看到它的实现在维护添加的处理程序列表并在需要时通知它们。此外，事件名称似乎具有与主题一样的协调目的。这种实现语义似乎与 Pub/Sub 模式完全匹配。

`jQuery.fn.trigger()` 方法实际上使用了内部的 `jQuery.event.trigger()` 方法，在 jQuery 中用于触发事件。它在内部处理程序列表上进行迭代，并使用所请求的事件以及自定义事件定义的任何额外参数执行它们。再次，这也符合 Pub/Sub 模式的操作要求。

因此，`jQuery.fn.trigger()` 和 `jQuery.fn.on()` 似乎符合 Pub/Sub 模式的需求，可以分别用于"publish"和"subscribe"方法。由于它们都可在 `jQuery.fn` 对象上使用，因此我们可以在任何 jQuery 对象上使用这些方法。这个 jQuery 对象将作为发布者和订阅者之间的中间实体，完全符合代理的定义。

一个很好的共同做法，也被很多 jQuery 插件所使用，是使用包含应用程序或插件实现的最外层页面元素作为代理。另一方面，jQuery 实际上允许我们使用任何对象作为代理，因为它实际上只需要一个目标来发出观察我们自定义事件的通知。因此，我们甚至可以使用一个空对象作为我们的代理，比如 `$({})`，以防使用页面元素看起来太受限制或根据 Pub/Sub 模式不够清晰。这实际上就是 jQuery Tiny Pub/Sub 库所做的事情，还有一些方法别名，这样我们实际上使用的是名为 "publish" 和 "subscribe" 的方法，而不是 jQuery 的 "on" 和 "trigger"。有关 Tiny 的更多信息，您可以访问其仓库页面[`github.com/cowboy/jquery-tiny-pubsub`](https://github.com/cowboy/jquery-tiny-pubsub)。

# 展示一个示例用例

为了了解 Pub/Sub 模式的使用，并方便将其与观察者模式进行比较，我们将重新编写来自第二章中的仪表板示例，*The Observer Pattern*，并使用这种模式。这还将清楚地演示这种模式如何帮助我们解耦实现的各个部分，并使其更具扩展性和可伸缩性。

## 在仪表板示例中使用 Pub/Sub

```js
adapt to the Publisher/Subscriber Pattern:
```

```js
$(document).ready(function() { 
 window.broker = $('.dashboardContainer'); 

    $('#categoriesSelector').change(function() { 
        var $selector = $(this); 
        var message = { categoryID: $selector.val() }; 
 broker.trigger('dashboardCategorySelect', [message]); 
    }); 

 broker.on('dashboardCategorySelect', function(event, message) { 
        var $dashboardCategories = $('.dashboardCategory'); 
        var selectedIndex = +message.categoryID; 
        var $selectedItem = $dashboardCategories.eq(selectedIndex).show(); 
        $dashboardCategories.not($selectedItem).hide(); 
    }); 

    $('.dashboardCategory').on('click', 'button', function() { 
        var $button = $(this); 
        var message = { categoryName: $button.text() }; 
 broker.trigger('categoryItemOpen', [message]); 
    }); 

 broker.on('categoryItemOpen', function(event, message) { 
        var boxHtml = '<div class="boxsizer"><article class="box">' + 
                '<header class="boxHeader">' + 
                    message.categoryName + 
                    '<button class="boxCloseButton">&#10006;' +
                    '</button>' + 
                '</header>' + 
                'Information box regarding ' + message.categoryName + 
            '</article></div>'; 
        $('.boxContainer').append(boxHtml); 
    }); 

 $('.boxContainer').on('click', '.boxCloseButton', function() { 
 var boxIndex = $(this).closest('.boxsizer').index(); 
        var message = { boxIndex: boxIndex }; 
        broker.trigger('categoryItemClose', [message]); 
    }); 

 broker.on('categoryItemClose', function(event, message) { 
        $('.boxContainer .boxsizer').eq(message.boxIndex).remove(); 
    });
}); 
```

就像我们以前的实现一样，我们使用`$(document).ready()`来延迟执行我们的代码，直到页面完全加载。首先，我们声明我们的代理并将其分配给`window`对象上的一个新变量，以便在页面上全局可用。对于我们应用程序的代理，我们使用了一个具有我们实现的最外层容器的 jQuery 对象，我们的情况下是具有`dashboardContainer`类的`<div>`元素。

### 提示

即使使用全局变量通常是一个反模式，我们将代理存储为全局变量，因为它是整个应用程序的重要同步点，并且必须对我们实现的每一部分都可用，即使是存储在单独的`.js`文件中的部分也是如此。正如我们将在下一章关于模块模式的讨论中所讨论的，前面的代码可以通过将代理存储为应用程序命名空间的属性来改进。

为了实现类别选择器，我们首先观察`<select>`元素的`change`事件。当所选类别更改时，我们使用一个简单的 JavaScript 对象创建我们的消息，并将所选`<option>`的`value`存储在`categoryID`属性中。然后，我们使用 jQuery 的`jQuery.fn.trigger()`方法在我们的代理上发布它到`dashboardCategorySelect`主题。这样，我们从 UI 元素事件移动到一个包含所有所需信息的具有应用程序语义的消息。在我们订阅者的代码中，我们使用`jQuery.fn.on()`方法在我们的代理上使用`dashboardCategorySelect`主题作为参数（我们的自定义事件），就像我们监听简单的 DOM 事件一样。然后订阅者使用从接收到的消息中的`categoryID`，就像我们在前一章的实现中所做的那样，来显示适当的类别项。

按照相同的方法，我们将处理仪表板中添加和关闭信息框的代码分割成发布者和订阅者。为了这个演示的需要，`categoryItemOpen` 主题的消息只包含我们想要打开的类别的名称。然而，在一个从服务器检索框内容的应用程序中，我们可能会使用类别项 ID。然后订阅者使用消息中的类别项名称创建并插入所请求的信息框。

类似地，`categoryItemClose`主题的消息包含我们要移除的框的索引。我们的发布者使用`jQuery.fn.closest()`方法遍历 DOM 并到达我们的`boxContainer`元素的子元素，然后使用`jQuery.fn.index()`方法在其同级元素中找到其位置。然后，订阅者使用从接收到的消息中的`boxIndex`属性和`jQuery.fn.eq()`方法来过滤并仅从仪表板中移除所请求的信息框。

### 提示

在更复杂的应用程序中，我们可以将每个信息框元素与一个新检索到的`jQuery.guid`关联起来，而不是使用框索引，使用一个映射对象。这样，我们的发布者就可以在消息中使用那个`guid`而不是（与 DOM 相关的）元素索引。订阅者将在映射对象中搜索该`guid`以定位并删除相应的框。

由于我们正在试图展示 Pub/Sub 模式的优势，这种实现变化不是为了简化与观察者模式的比较而引入的，而是作为读者的推荐练习留下的。

总结以上内容，我们使用了`dashboardCategorySelect`、`categoryItemOpen`和`categoryItemClose`主题作为我们的应用级事件，以便将用户操作的处理与它们的来源（UI 元素）解耦。因此，我们现在有了专门的可重用代码片段，用于操控我们仪表板的内容，这等同于将它们抽象为单独的函数。这使我们能够以编程方式发布一系列消息，以便我们可以，例如，删除所有现有的信息框并添加当前选择类别的所有类别项。或者，更好的是，让仪表板显示每个类别的所有项 10 秒，然后切换到下一个。

## 扩展实现

为了展示 Pub/Sub 模式带来的可扩展性，我们将通过添加一个计数器来扩展我们当前的示例，用于显示当前在仪表板中打开的框的数量。

![扩展实现](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00016.jpeg)

对于计数器的实现，我们需要向我们的页面添加一些额外的 HTML，并创建并引用一个新的 JavaScript 文件来保存计数器的实现：

```js
      ...
      </section> 
 <div style="margin-left: 5px;"> 
 Open boxes: 
 <output id="dashboardItemCounter">1</output> 
 </div> 
      <section class="boxContainer">
      ...
```

在示例的 HTML 页面中，我们需要添加一个额外的`<div>`元素来容纳我们的计数器和一些描述文本。对于我们的计数器，我们使用一个`<output>`元素，这是一个语义化的 HTML5 元素，用于呈现用户操作的结果。浏览器将像对待常规的`<span>`元素一样对待它，因此它将出现在其描述的旁边。此外，由于我们的仪表板中最初有一个提示框是打开的，我们使用`1`作为其初始内容：

```js
$(document).ready(function() { 
 broker.on('categoryItemOpen categoryItemClose', function (event, message) { 
        var $counter = $('#dashboardItemCounter'); 
        var count = parseInt($counter.text()); 

 if (event.type === 'categoryItemOpen') { 
            $counter.text(count + 1); 
 } else if (event.type === 'categoryItemClose' && count > 0) { 
            $counter.text(count - 1); 
        }
    }); 
});
```

对于计数器实现本身，我们只需要向仪表板的代理添加一个额外的订阅者，该代理是全局可用的，因为我们将其附加到`window`对象上。我们通过将它们以空格分隔传递给`jQuery.fn.on()`方法来同时订阅两个主题。在此之后，我们定位具有 ID `dashboardItemCounter` 的计数器`<output>`元素，并将其文本内容解析为数字。为了根据消息接收到的主题来区分我们的动作，我们使用 jQuery 传递给我们匿名函数的第一个参数，即`event`对象，该对象是我们的订阅者。具体来说，我们使用`event`对象的`type`属性，该属性保存了接收到的消息的主题名称，并根据其值更改计数器的内容。

### 注意

有关 jQuery 提供的事件对象的更多信息，请访问[`api.jquery.com/category/events/event-object/`](http://api.jquery.com/category/events/event-object/)。

类似地，我们也可以重写防止类别项按钮意外双击的代码。所需的一切就是为`categoryItemOpen`主题添加额外的订阅者，并使用消息的`categoryName`属性来定位按下的按钮。

## 使用任何对象作为代理

在我们的示例中，我们将仪表板的最外层容器元素用作我们的代理，但通常也可以使用`$(document)`对象作为代理。使用应用程序的容器元素被认为是一种很好的语义实践，它还限定了发出的事件。

正如我们在本章前面所描述的，jQuery 实际上允许我们使用任何对象作为代理，甚至是一个空对象。因此，我们可以使用`window.broker = $({});`之类的东西作为我们的代理，以防我们更喜欢它而不是使用页面元素。

通过使用新构造的空对象，我们还可以轻松创建几个代理，以防特定实现首选这样的情况。此外，如果不喜欢集中式代理，我们可以只将每个发布者作为自己的代理，从而导致实现更像发布/订阅模式的第一种/基本变体。

由于在大多数情况下，声明的变量用于在页面内访问应用程序的代理，因此上述方法之间几乎没有什么区别。只需选择更符合您团队口味的方法，在以后改变主意时，您只需在`broker`变量上使用不同的赋值即可。

# 使用自定义事件命名空间

作为本章的结束语，我们将简要介绍 jQuery 提供的自定义事件命名空间机制。事件命名空间的主要好处是它允许我们使用更具体的事件名称来更好地描述它们的目的，同时还帮助我们避免不同实现部分和插件之间的冲突。它还提供了一种方便的方法，可以从任何目标（元素或代理）解绑定给定命名空间的所有事件。

一个简单的示例实现如下所示：

```js
var broker = $({});
broker.on('close.dialog', function (event, message){
    console.log(event.type, event.namespace);
});
broker.trigger('close.dialog', ['messageEmitted']);
broker.off('.dialog');
// removes all event handlers of the "dialog" namespace
```

欲了解更多信息，请访问[`docs.jquery.com/Namespaced_Events`](http://docs.jquery.com/Namespaced_Events)文档页面和 CSS-Tricks 网站上的文章[`css-tricks.com/namespaced-events-jquery/`](https://css-tricks.com/namespaced-events-jquery/)。

# 总结

在本章中，我们介绍了发布/订阅模式。我们看到了它与观察者模式的相似之处，并通过比较了解了它的好处。我们分析了发布/订阅模式提供的更明确的角色和额外功能如何使其成为更复杂用例的理想模式。我们看到了 jQuery 开发人员是如何采用其中一些概念并将其带入到他们的观察者模式实现中作为自定义事件的。最后，我们使用发布/订阅模式重新编写了上一章的示例，添加了一些额外功能，并且在我们的应用程序的不同部分和页面元素之间实现了更大程度的解耦。

现在我们已经完成了对发布/订阅模式如何作为解耦实现不同部分的第一步的介绍，我们可以继续下一章，在那里我们将介绍模块模式。在下一章中，我们将学习如何将实现的不同部分分离为独立模块，并如何使用命名空间来实现更好的代码组织，并定义严格的 API 以实现不同模块之间的通信。


# 第四章：模块模式的分而治之

在本章中，我们将介绍模块和命名空间的概念，并看看它们如何带来更健壮的实现。我们将展示这些设计原则如何在应用程序中使用，通过展示一些最常用的开发模式来创建 JavaScript 中的**模块**。

在本章中，我们将：

+   复习模块和命名空间的概念

+   介绍对象字面量模式

+   介绍模块模式及其变种

+   介绍揭示模块模式及其变种

+   简要介绍 ES5 严格模式和 ES6 模块

+   解释模块如何用于 jQuery 应用程序产生益处

# 模块和命名空间

本章的两个主要实践是模块和命名空间，它们一起使用以便结构化和组织我们的代码。我们将首先分析模块的主要概念，即代码封装，然后我们将继续命名空间，用于逻辑上组织实现。

## 封装实现的内部部分

在开发大规模和复杂的 Web 应用程序时，从一开始就需要一个定义良好，结构化的架构的需求变得清晰。为了避免创建代码混乱的实现，其中我们的代码的不同部分以混乱的方式相互调用，我们必须将应用程序分割为小的，独立的部分。

这些独立的代码片段可以被定义为**模块**。为了记录这个架构原则，**计算机科学**已经定义了诸如**关注分离**之类的概念，其中每个模块的角色，操作和公开 API 都应严格定义并专注于为特定问题提供通用解决方案。

### 注意

有关**封装**和**关注分离**的更多信息，您可以访问[`developer.mozilla.org/en-US/docs/Glossary/Encapsulation`](https://developer.mozilla.org/en-US/docs/Glossary/Encapsulation)和[`aspiringcraftsman.com/2008/01/03/art-of-separation-of-concerns/`](http://aspiringcraftsman.com/2008/01/03/art-of-separation-of-concerns/)。

## 避免使用全局变量和命名空间

在 JavaScript 中，`window`对象也被称为**全局命名空间**，其中每个声明的变量和函数标识符默认附加在其上。**命名空间**可以定义为每个标识符必须是唯一的命名上下文。**命名空间**的主要概念是提供一种逻辑分组应用程序不同和独立一部分所有相关部分的方式。换句话说，它建议我们创建相关函数和变量的组，并使它们在相同的标识符下可访问。这有助于避免不同应用程序部分和所使用的其他 JavaScript 库之间的命名冲突，因为我们只需要在每个不同的命名空间下保持所有标识符唯一。

一个很好的名称空间的例子是 JavaScript 提供的数学函数和常量，它们被分组到名为`Math`的内置 JavaScript 对象下。由于 JavaScript 提供了 40 多个短命名的数学标识符，如`E`、`PI`和`floor()`，为了避免命名冲突并将它们分组在一起，它们被设计成作为`Math`对象的属性可访问，该对象充当了这个内置库的命名空间。

没有适当的名称空间，每个函数和变量必须在整个应用程序中具有唯一的名称，不同应用程序部分的标识符之间或者甚至与应用程序使用的第三方库的标识符之间可能发生冲突。最终，虽然模块提供了隔离应用程序每个独立部分的方法，但名称空间提供了一种将不同模块结构化成应用程序架构的方法。

## 这些模式的好处

基于模块和名称空间设计应用程序架构有助于更好地组织代码并明确分离部分。在这样的架构中，模块用于组合相关的实现部分，而名称空间将它们连接在一起以创建应用程序结构。

![这些模式的好处](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00017.jpeg)

这种架构有助于协调大型开发团队，使独立部分的实现可以并行进行。它还可以缩短向现有实现中添加新功能所需的开发时间。这是因为可以轻松定位使用的现有部分，并且添加的实现很少与现有代码发生冲突的可能性。

由此产生的代码结构不仅干净分离，而且由于每个模块被设计来实现单一目标，它们也有很大可能性在其他类似的应用程序中使用。作为额外好处，由于每个模块的角色严格定义，因此在大型代码库中追踪错误的起源也变得更加容易。

## 广泛接受

社区和企业界意识到，为了编写在 JavaScript 中的可维护的大型前端应用程序，他们应该最终得出一套最佳实践，并应该将这些最佳实践纳入他们实现的每个部分中。

JavaScript 实现中模块和名称空间的接受和采用在社区和企业发布的最佳实践和代码风格指南中清晰可见。

例如，谷歌的 JavaScript 风格指南（可在[`google.github.io/styleguide/javascriptguide.xml#Naming`](https://google.github.io/styleguide/javascriptguide.xml#Naming)找到）描述并建议在我们的实现中采用名称空间：

> 始终使用与项目或库相关的唯一伪命名空间作为全局范围标识符的前缀。

此外，jQuery JavaScript 风格指南（可在 [`contribute.jquery.org/style-guide/js/#global-variables`](https://contribute.jquery.org/style-guide/js/#global-variables) 获取）建议使用全局变量，以便：

> 每个项目最多只能公开一个全局变量。

开发人员社区中另一个被接受的例子来自 Mozilla Developer Network。它的对象导向 JavaScript 指南（可在 [`developer.mozilla.org/en-US/docs/Web/JavaScript/Introduction_to_Object-Oriented_JavaScript#Namespace`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Introduction_to_Object-Oriented_JavaScript#Namespace) 获取）还建议使用命名空间，将应用程序的实现封装在一个单一的暴露变量下，使用以下简单的方法：

```js
// global namespace
var MYAPP = MYAPP || {};
```

# 对象字面量模式

对象字面量模式可能是将实现的所有相关部分封装在一个作为模块的伞对象下的最简单方式。这种模式的名称准确地描述了它的使用方式。开发人员只需声明一个变量并将需要封装到该模块中的所有相关部分赋值给一个对象即可。

让我们看看如何创建一个模块，以类似于 `jquery.guid` 的方式为页面提供唯一的整数：

```js
var simpleguid = { 
  guid: 1, 
  init: function() { 
    this.guid = 1; 
  }, 
  increaseCounter: function() { 
    this.guid++; 
    // or simpleguid.guid++;
  }, 
  getNext: function() { 
    var nextGuid = this.guid; 
    this.increaseCounter(); 
    return nextGuid; 
  } 
};
```

如上所述，您可以遵循的一个简单规则是将每个实现所需的所有变量和函数定义为对象的属性。我们的代码是可重用的，不会污染全局命名空间，除了为我们的模块定义一个单一变量名，例如在本例中是 `simpleguid`。

我们可以通过使用 `this` 关键字（例如 `this.guid`）或使用模块的全名（例如 `simpleguid.guid`）在内部访问模块属性。为了在我们的代码中使用上述模块，我们只需通过其名称访问其属性。例如，调用 `simpleguid.getNext()` 方法将向我们的代码返回下一个顺序数字 guid，并通过增加内部计数器改变模块的状态。

这种模式的一个负面方面是它不提供对模块内部部分的任何隐私。模块的所有内部部分都可以被外部代码访问和覆盖，即使我们理想地只希望公开 `simpleguid.init()` 和 `simpleguid.getNext()` 方法。有几种命名约定描述了将下划线 (_) 添加到仅用于内部使用的属性名称的开头或结尾，但从技术上讲，这并不能解决这个缺点。

另一个缺点是，使用对象字面量编写一个大型模块很容易让人感到疲倦。 JavaScript 开发人员习惯于在变量和函数定义后加上分号 (`;`)，尝试使用逗号 (`,`) 在每个属性后编写一个大型模块很容易导致语法错误。

尽管此模式使得声明模块的嵌套命名空间变得容易，但在需要多层嵌套的情况下，也可能导致代码结构庞大且难以阅读。例如，让我们看一下以下 Todo 应用程序的框架：

```js
var myTodoApp = { 
  todos: [], 
  addTodo: function(todo) { this.todos.push(todo); }, 
  getTodos: function() { return this.todos; }, 
  updateTodo: function(todo) { /*...*/ },
  imports: { 
    fromGDrive: function() { /*...*/ }, 
    fromUrl: function() { /*...*/ }, 
    fromText: function() { /*...*/ } 
  }, 
  exports: { 
    gDrivePublicKey: '#wnanqAASnsmkkw',
    toGDrive: function() { /*...*/ }, 
    toFile: function() { /*...*/ }, 
  }, 
  share: { 
    toTwitter: function(todo) { /*...*/ } 
  }
};
```

幸运的是，这可以通过将对象字面量拆分为每个子模块的多个赋值（最好是到不同的文件）来轻松解决，如下所示：

```js
var myTodoApp = { 
  todos: [], 
  addTodo: function(todo) { this.todos.push(todo); }, 
  getTodos: function() { return this.todos; }, 
  updateTodo: function(todo) { /*...*/ },
};
/* … */
myTodoApp.exports = { 
  gDrivePublicKey: '#wnanqAASnsmkkw', 
  toGDrive: function() { /*...*/ }, 
  toFile: function() { /*...*/ }, 
};
/*...*/
```

# 模块模式

基本模块模式的关键概念是提供一个简单的函数、类或对象，供应用程序的其余部分使用，通过一个众所周知的变量名。它使我们能够为模块提供一个最小的 API，通过隐藏不需要暴露的实现部分。这样，我们还可以避免用于我们模块的内部使用的变量和实用函数污染全局命名空间。

## IIFE 构建块

在本小节中，我们将简要介绍 IIFE 设计模式，因为它是我们将在本章中看到的所有模块模式变体的一个重要部分。**立即调用函数表达式**（**IIFE**）是 JavaScript 开发人员中非常常用的设计模式，因为它以清晰的方式隔离了代码块。在模块模式中，IIFE 用于包装所有实现，以避免污染全局命名空间，并向模块本身提供声明的隐私。

每个 IIFE 都创建了一个闭包，其中声明的变量和函数。创建的闭包使得 IIFE 的公开函数能够在其他部分的实现中被执行时保留对其环境余下声明的引用，并且正常访问它们。因此，IIFE 的非公开声明不会泄漏到外部，而是被保持私有，并且只能被创建的闭包中的函数访问。

### 注意

欲了解更多关于 IIFE 和闭包的信息，您可以访问[`developer.mozilla.org/en-US/docs/Glossary/IIFE`](https://developer.mozilla.org/en-US/docs/Glossary/IIFE) 和 [`developer.mozilla.org/en-US/docs/Web/JavaScript/Closures`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Closures)。

IIFE 最常用的用法如下：

```js
(function() { 
  var x = 7; 
  console.log(x); 
  // prints 7 
})(); 
```

由于前面的代码构造在第一眼看起来可能很奇怪，让我们看看它由哪些部分组成。IIFE 几乎等价于声明一个匿名函数，将其赋值给一个变量，然后执行它，如下面的代码所示：

```js
var tmp = function() { 
  var x = 7; 
  console.log(x); 
}; 

tmp(); 
// or 
(tmp)(); 
```

在前面的代码中，我们定义了一个函数表达式，并使用`tmp()`执行它。由于在 JavaScript 中，我们可以在标识符周围使用括号而不改变其含义，我们也可以使用`(tmp)();`来执行存储的函数。最后一步，为了将前面的代码转换为 IIFE，是将`tmp`变量替换为实际的匿名函数声明。

正如我们之前看到的那样，唯一的区别在于，使用 IIFE 时，我们确实需要声明一个变量来保存函数本身。我们只创建一个匿名函数，并在定义后立即调用它。

由于可以通过几种方式创建 IIFE，这可能看起来像是对 JavaScript 规则的一种练习，JavaScript 开发者社区已经得出结论，将上述代码结构作为此模式的参考点。这种创建 IIFE 的方式被认为具有更好的可读性，并且被大型库所使用，作为其被采用的结果，开发人员可以在大型 JavaScript 实现中轻松识别它。

创建 IIFE 的不常用方式的示例是以下代码结构：

```js
(function() { 
  // code 
}());
```

## 简单的 IIFE 模块模式

由于此模式没有实际名称，因此它被认为是定义的模块返回单个实体的事实。为了参考如何使用此模式创建可重用库，我们将重新编写之前看到的`simpleguid`模块。得到的实现将如下所示：

```js
var simpleguid = (function() { 
  var simpleguid = {}; 
  var guid; 

  simpleguid.init = function() { 
    guid = 1; 
  }; 

  simpleguid.increaseCounter = function() { 
    guid++; 
  }; 

  simpleguid.getNext = function() { 
    var nextGuid = guid; 
    this.increaseCounter(); 
    return nextGuid; 
  }; 

  simpleguid.init(); 

  return simpleguid;
})(); 
```

此模式使用 IIFE 定义一个充当模块容器的对象，将属性附加到该对象上，然后将其返回。前面代码的第一行中的变量`simpleguid`用作模块的命名空间，并赋予了 IIFE 返回的值。在返回对象上定义的方法和属性是模块的唯一公开部分，并构成其公共 API。

再次，这种模式允许我们使用`this`关键字，以便访问我们模块的公开方法和属性。此外，它还提供了在完成模块定义之前执行任何所需初始化代码的灵活性。

与**对象字面量模式**不同，**模块模式**使我们能够在模块中创建实际的私有成员。在 IIFE 中声明的变量，不附加到返回值的变量，比如`guid`变量，作为私有成员，只能被创建闭包的其他成员在模块内部访问。

最后，如果我们需要定义嵌套的命名空间，我们所需做的就是更改 IIFE 返回的值的赋值。作为应用程序用子模块结构化的示例，让我们看看如何为之前看到的 Todo 应用程序骨架定义导出子模块：

```js
var myTodoApp = (function() { 
  var myTodoApp = {}; 

  var todos = []; 

  myTodoApp.addTodo = function(todo) { 
    todos.push(todo); 
  };

  myTodoApp.getTodos = function() { 
    return todos; 
  };

  return myTodoApp; 
})(); 

myTodoApp.exports = (function() { 
  var exports = {}; 

  var gDrivePublicKey = '#wnanqAASnsmkkw'; 

  exports.toGDrive = function() { /*...*/ }; 

  exports.toFile = function() { /*...*/ }; 

  return exports; 
})();
```

鉴于我们应用的命名空间`myTodoApp`已在之前定义过了，`exports`子模块可以定义为其上的一个简单属性。要遵循的一个良好实践是为上述每个模块创建一个文件，使用 IIFE 作为代码拆分的标志。一个广泛使用的命名约定，也是由 Google 的 JavaScript 样式指南建议的，是为文件使用小写命名，并使用破折号分隔子模块。例如，按照这个命名约定，前面的代码应该分别定义在名为`mytodoapp.js`和`mytodoapp-exports.js`的两个文件中。

### 它如何被 jQuery 使用

**模块模式**被 jQuery 本身使用，以隔离 CSS 选择器引擎（**Sizzle**）的源代码，它为`$()`函数提供支持，并将其与 jQuery 源代码的其余部分隔离开来。从一开始，Sizzle 就是 jQuery 源代码的一个重要部分，目前大约有 2135 行代码；自 2009 年以来，它已经拆分为一个名为 Sizzle 的独立项目，这样就更容易维护，可以独立开发，并且可以被其他库重复使用：

```js
var Sizzle = (function(window) { 

  /* 179 lines of code */ 

  function Sizzle(selector, context, results, seed) { 
    /* 131 lines of code */ 
  } 

  /* 
    1804 lines of code , defining methods like: 
    Sizzle.attr 
    Sizzle.compile 
    Sizzle.contains 
    Sizzle.getText 
    Sizzle.matches 
    Sizzle.matchesSelector 
    Sizzle.select 
  */ 

  return Sizzle; 

})(window); 

jQuery.find = Sizzle; 
```

**Sizzle**被添加到 jQuery 的源码中的 IIFE 内部，而其主要功能则被返回并分配给`jQuery.find`以供使用。

### 注意

关于 Sizzle 的更多信息，请访问[`github.com/jquery/sizzle`](https://github.com/jquery/sizzle)。

## 命名空间参数模块变体

在这个变体中，我们不是从 IIFE 返回对象，然后将其分配给充当模块的命名空间的变量，而是创建命名空间并将其作为参数传递给 IIFE 本身：

```js
(function(simpleguid) { 
  var guid; 

  simpleguid.init = function() { 
    guid = 1; 
  }; 

  simpleguid.increaseCounter = function() { 
    guid++; 
  };

  simpleguid.getNext = function() { 
    var nextGuid = guid; 
    this.increaseCounter(); 
    return nextGuid; 
  }; 

  simpleguid.init(); 
})(window.simpleguid = window.simpleguid || {});
```

模块定义的最后一行检查模块是否已经定义；如果没有，则将其初始化为空对象文字，并将其分配给全局对象（`window`）。无论如何，在 IIFE 的第一行中，`simpleguid`参数都将保存模块的命名空间。

### 注意

上述表达式几乎等同于写成：

```js
window.simpleguid = window.simpleguid !== undefined ? window.simpleguid : {};
```

使用逻辑或运算符（`||`）使表达式更简短且更易读。此外，这是大多数 Web 开发人员已经学会轻松识别的模式，在许多开发模式和最佳实践中都有出现。

再次，这种模式允许我们使用`this`关键字从模块的导出方法中访问公共成员。同时，它还允许我们保持一些函数和变量私有，这些私有函数和变量只能被模块的其他函数访问。

即使将每个模块定义为自己的 JS 文件被认为是一种良好的做法，此变体还允许我们将大型模块的实现分割到多个文件中。这个好处来自于在将其初始化为空对象之前检查模块是否已经定义。这在某些情况下可能会有用，唯一的限制是每个模块的部分文件都可以访问其自己 IIFE 中定义的私有成员。

此外，为了避免重复，我们可以为 IIFE 的参数使用更简单的标识符，并将我们的模块编写为如下所示：

```js
(function(namespace) { 
  /* … */

  namespace.getNext = function() { 
    var nextGuid = guid; 
    this.increaseCounter(); 
    return nextGuid; 
  }; 

  namespace.init(); 
})(window.simpleguid = window.simpleguid || {});
```

当涉及具有嵌套命名空间的应用程序时，这种模式可能开始感觉阅读起来有点不舒服。每个额外的嵌套命名空间级别所定义的模块定义的最后一行将会变得越来越长。例如，让我们看一下我们的 Todo 应用程序的`exports`子模块将会是怎样的：

```js
(function(exports) { 
  var gDrivePublicKey = '#wnanqAASnsmkkw'; 

  exports.toGDrive = function() { /*...*/ }; 

  exports.toFile = function() { /*...*/ }; 

})(myTodoApp.exports = myTodoApp.exports || {}); 
```

正如您所见，每个额外级别的嵌套命名空间都需要在作为 IIFE 参数传递的赋值两侧添加。对于具有复杂功能并导致多级嵌套命名空间的应用程序，这可能导致模块定义看起来像这样：

```js
(function(smallModule) { 

  smallModule.method = function() { /*...*/ }; 

  return smallModule; 
})(myApp.bigFeature.featurePart.smallModule = myApp.bigFeature.featurePart.smallModule || {}); 
```

此外，如果我们想要提供与原始代码示例相同的安全保证，那么我们需要为每个命名空间级别添加类似的安全检查。考虑到这一点，我们之前看到的 Todo 应用程序的`exports`模块将需要具有以下形式：

```js
(function(exports) { 
  var gDrivePublicKey = '#wnanqAASnsmkkw'; 

  exports.toGDrive = function() { /*...*/ }; 

  exports.toFile = function() { /*...*/ }; 

})((window.myTodoApp = window.myTodoApp || {}, myTodoApp.exports = myTodoApp.exports || {})); 
```

如前所述的代码中所示，我们使用逗号运算符（`,`）来分隔每个命名空间的存在检查，并将整个表达式包装在额外的括号对中，以便整个表达式作为 IIFE 的第一个参数使用。使用逗号运算符（`,`）将表达式连接起来将导致它们按顺序计算，并将最后评估的表达式的结果作为 IIFE 的参数传递，并且该结果将用作模块的命名空间。请记住，对于每个额外的嵌套命名空间级别，我们都需要使用逗号运算符（`,`）添加额外的存在检查表达式。

这种模式的一个缺点，尤其是在用于嵌套命名空间时，是模块的命名空间定义在文件末尾。即使强烈建议为 JS 文件命名，以便它们正确表示包含的模块，例如，`mytodoapp.exports.js`；但是，没有命名空间在文件顶部附近有时可能会产生反效果或误导性。解决这个问题的一个简单方法是在 IIFE 之前定义命名空间，然后将其作为参数传递。例如，使用这种技术的前述代码将转换为以下形式：

```js
window.myTodoApp = window.myTodoApp || {}; 
myTodoApp.exports = myTodoApp.exports || {}; 

(function(exports) { 
  var gDrivePublicKey = '#wnanqAASnsmkkw'; 

  exports.toGDrive = function() { /*...*/ }; 

  exports.toFile = function() { /*...*/ }; 

})(myTodoApp.exports); 
```

## IIFE 包含的模块变体

像在模块模式的以前变体一样，这种变体实际上并没有一个特定的变体名称，但是通过代码结构的方式进行识别。这种变体的关键概念是将所有模块的代码移至 IIFE 中：

```js
(function() { 

  window.simpleguid = window.simpleguid || {}; 

  var guid; 

  simpleguid.init = function() { 
    guid = 1; 
  }; 

  simpleguid.increaseCounter = function() { 
    guid++; 
  }; 

  simpleguid.getNext = function() { 
    var nextGuid = guid; 
    this.increaseCounter(); 
    return nextGuid; 
  }; 

  simpleguid.init(); 
})(); 
```

这种变体看起来与前一种非常相似，主要区别在于命名空间的创建方式。首先，它将命名空间检查和初始化保持在模块的顶部附近，就像一个标题，使得我们的代码更具可读性，无论我们是否为模块使用单独的文件。与模块模式的其他变体一样，它支持模块的私有成员，并且还允许我们使用`this`关键字来访问公共方法和属性，使得我们的代码看起来更符合面向对象的特性。

关于具有嵌套命名空间的实现，我们的待办应用程序骨架的`exports`子模块的代码结构如下所示：

```js
(function() { 
  window.myTodoApp = window.myTodoApp || {}; 
  myTodoApp.exports = myTodoApp.exports || {}; 

  var gDrivePublicKey = '#wnanqAASnsmkkw'; 

  myTodoApp.exports.toGDrive = function() { /*...*/ }; 

  myTodoApp.exports.toFile = function() { /*...*/ }; 

})();
```

如前面的代码所示，我们还从以前的变体中借用了命名空间定义检查，并同样将其应用到嵌套命名空间的每个级别。即使这并非绝对必要，但它带来了我们之前讨论过的好处，比如使我们能够将模块定义分割为多个文件，并且甚至导致应用程序模块导入顺序方面的实现更容错。

# 揭示模块模式

**揭示模块模式**是**模块模式**的一种变体，具有一个广为人知和认可的名称。使得这种模式特殊的是它结合了**对象字面量模式**和**模块模式**的最佳部分。模块的所有成员都声明在一个 IIFE 内部，最终返回一个仅包含模块公共成员的**对象字面量**，并分配给作为我们命名空间的变量：

```js
var simpleguid = (function() { 
  var guid = 1; 

  function init() { 
    guid = 1; 
  } 

  function increaseCounter() { 
    guid++; 
  } 

  function getNext() { 
    var nextGuid = guid; 
    increaseCounter(); 
    return nextGuid; 
  } 

  return { 
    init: init, 
    getNext: getNext 
  }; 
})(); 
```

这种模式与其他变体区别最大的一个主要好处是它允许我们像在**全局命名空间**中声明代码一样，在 IIFE 内部编写所有模块的代码。此外，这种模式不需要在声明公共和私有成员的方式上做任何变化，使得模块代码看起来统一。

由于返回的对象字面量定义了模块的公开成员，因此这也是一种方便的方法来检查其公共 API，即使它是由其他人编写的。此外，如果我们需要在模块的 API 中公开一个私有方法，我们只需向返回的对象字面量中添加一个额外的属性，而无需更改其定义的任何部分。此外，使用对象字面量使我们能够更改模块 API 的公开标识符，而不需要更改模块内部实现使用的名称。

即使这不太明显，`this`关键字也可以用于模块的公共成员之间的调用。不幸的是，*对于此模式而言，使用`this`关键字是不鼓励的*，因为它会破坏函数声明的统一性，并且很容易导致错误，特别是在将公共方法的可见性更改为私有时。

由于命名空间定义被保留在 IIFE 的体外，这种模式清晰地将命名空间定义与模块的实际实现分开。在嵌套命名空间中使用此模式来定义模块不会影响模块的实现，任何时候它都不会与顶级命名空间模块有所不同。重写我们的 Todo 骨架应用程序的`exports`子模块，使用此模式将使其看起来像这样：

```js
myTodoApp.exports = (function() { 
  var gDrivePublicKey = '#wnanqAASnsmkkw'; 

  function toGDrive() { /*...*/ } 

  function toFile() { /*...*/ } 

  return { 
    toGDrive: toGDrive, 
    toFile: toFile 
  }; 
})();
```

由于这种分离，我们减少了代码重复，并且可以轻松地更改模块的命名空间，而不会对其实现造成任何影响。

# 使用 ES5 严格模式

对于所有将 IIFE 作为其基本构建块的模块模式的一个小但宝贵的补充，是使用**严格模式**来执行 JavaScript。这在 JavaScript 的第五版中标准化，是一种选择性的执行模式，具有略微不同的语义，以防止 JavaScript 的一些常见陷阱，但也考虑了向后兼容性。

在此模式下，JavaScript 运行时引擎将防止您意外创建全局变量并污染全局命名空间。即使在不是特别大的应用程序中，也很有可能在变量的初始赋值之前缺少`var`声明，自动将其提升为全局变量。为了防止这种情况，严格模式在向未声明的变量发出赋值时会抛出错误。以下图像显示了 Firefox 和 Chrome 在发生严格模式违规时抛出的错误。

![使用 ES5 严格模式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00018.jpeg)

可以通过在任何其他语句之前添加`"use strict";`或`'use strict';`语句来启用此模式。尽管可以在全局范围内启用它，但强烈建议仅在函数范围内启用它。在全局范围内启用它可能会使不符合严格模式的第三方库停止工作或行为异常。另一方面，启用严格模式的最佳位置是在模块的 IIFE 内部。严格模式将递归地应用于该 IIFE 的所有嵌套命名空间、方法和函数。

### 注意

有关 JavaScript 严格执行模式的更多信息，您可以访问 [`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Strict_mode`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Strict_mode)。

# 引入 ES6 模块

尽管 JavaScript 最初没有像其他编程语言一样内置的打包和命名空间支持，但 Web 开发人员通过定义并采用一些设计模式来填补这些空白。这些软件开发实践解决了 JavaScript 缺失的功能，并允许在这种一些年前大多用于表单验证的编程语言上进行大规模和可扩展的复杂应用程序实现。

直到 2015 年 6 月作为标准发布的 JavaScript 第 6 版（通常称为 ES6），引入了模块的概念作为语言的一部分。

### 注意

ES6 是 ECMAScript 第 6 版的缩写，也称为 Harmony 或 ECMAScript 2015，其中 ECMAScript 是 JavaScript 的标准化过程使用的术语。规范可在 [`www.ecma-international.org/ecma-262/6.0/index.html#sec-modules`](http://www.ecma-international.org/ecma-262/6.0/index.html#sec-modules) 找到。

作为 ES6 模块的示例，我们将看到 `simpleguid` 模块的许多编写方式之一：

```js
var es6simpleguid = {}; 
export default es6simpleguid; 

var guid; 

es6simpleguid.init = function() { 
  guid = 1; 
}; 

es6simpleguid.increaseCounter = function() { 
  guid++; 
}; 

es6simpleguid.getNext = function() { 
  var nextGuid = guid; 
  this.increaseCounter(); 
  return nextGuid; 
}; 

es6simpleguid.init();
```

如果我们将此保存为名为 `es6simpleguid.js` 的文件，则我们可以通过简单地编写以下代码在不同的文件中导入并使用它：

```js
import es6simpleguid from 'es6simpleguid'; 
console.log(es6simpleguid.getNext());
```

由于 **ES6 模块** 默认处于严格模式，因此今天使用首选模块模式变体编写模块，并启用严格模式，将使您更容易过渡到 ES6 模块。上述某些模式需要进行非常少的更改才能实现这一点。例如，在 IIFE-contained 模块模式变体中，只需要删除 IIFE 和 `"use strict";` 语句，用变量替换模块的命名空间，并在其上使用 `export` 关键字。

不幸的是，在撰写本书时，没有任何浏览器对 ES6 模块提供 100% 的支持。因此，需要特殊的加载程序或工具将 ES6 转译为 ES5，以便我们可以开始使用 ES6 的新功能编写我们的代码。

### 注意

欲知详情，可访问 ES6 模块加载器的文档页面 [`github.com/ModuleLoader/es6-module-loader`](https://github.com/ModuleLoader/es6-module-loader)，和 Babel 转译器（之前称为 ES6toES5） [`babeljs.io/`](http://babeljs.io/)。

# 在 jQuery 应用程序中使用模块

为了演示模块模式如何带来更好的应用程序结构，我们将重新实现前几章中所见的仪表板示例。我们将包括到目前为止所见的所有功能，包括打开信息框的计数器。所使用的 HTML 和 CSS 代码与前一章完全相同，因此我们的仪表板看起来与以前完全相同：

![在 jQuery 应用程序中使用模块](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00019.jpeg)

为了进行演示，我们将将我们的 JavaScript 代码重构为四个小模块，使用简单的 IIFE 封装的 Module 变体。`dashboard` 模块将充当代码执行的主要入口，也将充当 dashboard 应用程序的中央协调点。`categories` 子模块将负责实现我们的 dashboard 顶部的上部分。这包括类别选择，适当按钮的呈现和按钮点击的处理。`informationBox` 子模块将负责我们的 dashboard 的主要部分。它将提供创建和删除 dashboard 中信息框的方法。最后，计数器子模块将负责保持当前打开的信息框数字段最新，并响应用户操作。

为了支持这种多模块架构，我们需要对页面的 HTML 中包含 JavaScript 文件的方式做出一些限制：

```js
<script type="text/javascript" src="img/jquery.js"></script>
<script type="text/javascript" src="img/dashboard.js"></script>
<script type="text/javascript" src="img/dashboard.categories.js"></script> <script type="text/javascript" src="img/dashboard.informationbox.js">
</script>
<script type="text/javascript" src="img/dashboard.counter.js"></script>
```

### 提示

即使这种多文件结构使得开发和调试过程变得更加容易，我们仍建议在将应用移至生产环境之前将所有这些文件合并。有几个专门用于此任务的工具存在；例如，非常简单有效的 grunt-contrib-concat 项目，可在 [`github.com/gruntjs/grunt-contrib-concat`](https://github.com/gruntjs/grunt-contrib-concat) 获取。

## 主要的 dashboard 模块

`dashboard` 模块的最终代码将如下所示：

```js
(function() { 
    'use strict'; 

    window.dashboard = window.dashboard || {};

    dashboard.$container = null; 

    dashboard.init = function() { 
        dashboard.$container = $('.dashboardContainer'); 

        dashboard.categories.init(); 
        dashboard.informationBox.init(); 
        dashboard.counter.init(); 
    }; 

    $(document).ready(dashboard.init);
})(); 
```

如我们先前提到的，`dashboard` 模块将是我们应用的中心点。由于这是我们应用执行的起始点，它的主要职责是为自身和每个子模块执行所有必需的初始化。调用 `init()` 方法被包装在对 `$(document).ready()` 方法的调用内，以便其执行被延迟直到页面的 DOM 树完全加载。

需要注意的一点是，在初始化期间，我们进行 DOM 遍历以找到 dashboard 的容器元素，并将其存储到 Module 的一个公共属性 `$container` 中。此元素将被 dashboard 的所有需要访问 DOM 树的方法使用，以便将它们的代码范围限定在该容器元素内，避免使用复杂选择器不断遍历整个 DOM 树。保留关键 DOM 元素的引用并在不同的子模块中重用它们，可以使应用程序更加灵活，并减少意外干扰页面的机会；从而导致更少且更易于解决的错误。

### 提示

**缓存元素但避免内存泄漏。**

请记住，保持对不断添加和移除页面的 DOM 元素的引用会给我们的应用程序增加额外的复杂性。这甚至可能导致内存泄漏，如果我们不小心保留对已从页面中移除的元素的引用。对于这样的元素，如信息框，更安全、更有效的方法可能是对它们触发的事件进行委派处理，并在需要时进行范围限定的 DOM 遍历，以检索具有新引用的元素的 jQuery 对象。

## 类别模块

让我们继续进行 `categories` 子模块：

```js
(function() { 
    'use strict'; 

    dashboard.categories = dashboard.categories || {}; 

    dashboard.categories.init = function() { 
        dashboard.$container.find('#categoriesSelector').change(function() { 
            var $selector = $(this); 
            var categoryIndex = +$selector.val(); 
            dashboard.categories.selectCategory(categoryIndex); 
        }); 

        dashboard.$container.find('.dashboardCategories').on('click', 'button', function() { 
            var $button = $(this); 
            var itemName = $button.text(); 
            dashboard.informationBox.openNew(itemName); 
        }); 
    }; 

    dashboard.categories.selectCategory = function(categoryIndex) { 
        var $dashboardCategories = dashboard.$container.find('.dashboardCategory'); 
        var $selectedItem = $dashboardCategories.eq(categoryIndex).show(); 
        $dashboardCategories.not($selectedItem).hide(); 
    }; 
})(); 
```

此子模块的初始化方法使用主模块提供的 `$container` 元素的引用，并向页面添加了两个观察者。第一个处理 `<select>` 类别上的 `change` 事件，并调用 `selectCategory()` 方法，传递所选类别的数值。该子模块的 `selectCategory()` 方法然后将处理显示适当的类别项，将其与事件处理代码解耦，并使其成为整个应用程序可重用的功能。

在此之后，我们创建了一个单一的**委托事件观察者**，处理 `<button>` 类别项上的 `click` 事件。它提取了按下的 `<button>` 的文本，并调用包含所有与信息框相关的实现的 `informationBox` 子模块的 `openNew()` 方法。在非演示级别的应用程序中，此类方法的参数可能是一个标识符，而不是用于从远程服务器检索更多详细信息的文本值。

## 信息框模块

包含与我们仪表板主要区域相关的实现部分的 `informationBox` 子模块具有以下形式：

```js
(function() { 
    'use strict'; 

    dashboard.informationBox = dashboard.informationBox || {}; 

    var $boxContainer = null; 

    dashboard.informationBox.init = function() { 
        $boxContainer = dashboard.$container.find('.boxContainer'); 

        $boxContainer.on('click', '.boxCloseButton', function() { 
            var $button = $(this); 
            dashboard.informationBox.close($button); 
        }); 
    }; 

    dashboard.informationBox.openNew = function(itemName) { 
        var boxHtml = '<div class="boxsizer"><article class="box">' + 
                '<header class="boxHeader">' + 
                    itemName + 
                    '<button class="boxCloseButton">&#10006;' + 
                    '</button>'+ 
                '</header>' + 
                'Information box regarding ' + itemName + 
            '</article></div>'; 
        $boxContainer.append(boxHtml); 
    }; 

    dashboard.informationBox.close = function($boxElement) { 
        $boxElement.closest('.boxsizer').remove();
    }; 

})();
```

此子模块初始化代码的第一件事是使用仪表板的 `$container` 属性来检索并存储容纳信息框的容器的引用到 `$boxContainer` 变量中，从而进行作用域限定。

`openNew()` 方法负责创建新信息框所需的 HTML，并使用 `$boxContainer` 变量将其添加到仪表板中，该变量像模块的私有成员一样，用于缓存先前分配的 DOM 元素的引用。这是一个很好的实践，可以提高应用程序的性能，因为存储的元素从未从页面中移除，并且在初始化和 `openNew()` 方法调用时都会使用。这样，我们就不再需要在每次调用 `openNew()` 方法时执行缓慢的 DOM 遍历了。

另一方面，`close()` 方法负责从仪表板中移除现有的信息框。它接收一个与目标信息框相关的 jQuery 组合集合对象作为参数，这是基于 `$.fn.closest()` 方法的工作方式，可以是框元素容器或其任何后代。

### 提示

提供灵活性的方法实现方式可以使它们被大型应用程序中的更多部分使用。对于此方法的下一个逻辑步骤，留给读者作为练习的是使其接受参数，即需要关闭的信息框的索引或标识符。

## 计数器模块

最后，这里是我们如何将我们在上一章中看到的`counter`实现重写为一个独立的子模块：

```js
(function() { 
    'use strict'; 

    dashboard.counter = dashboard.counter || {}; 

    var dashboardItemCounter; 
    var $counter; 

    dashboard.counter.init = function() { 
        $counter = $('#dashboardItemCounter'); 

        var $boxContainer = dashboard.$container.find('.boxContainer'); 
        var initialCount = $boxContainer.find('.boxsizer').length; 
        dashboard.counter.setValue(initialCount); 

        dashboard.$container.find('.dashboardCategories').on('click', 'button', function() { 
            dashboard.counter.setValue(dashboardItemCounter + 1); 
        }); 

        $boxContainer.on('click', '.boxCloseButton', function() { 
            dashboard.counter.setValue(dashboardItemCounter - 1); 
        }); 
    }; 

    dashboard.counter.setValue = function (value) { 
        dashboardItemCounter = value; 
        $counter.text(dashboardItemCounter); 
    }; 

})(); 
```

对于此子模块，我们使用`$counter`变量作为私有成员来缓存对显示计数的元素的引用。模块的另一个私有成员是`dashboardItemCounter`变量，它在任何时间点都将保存仪表板中可见信息框的数量。将这些信息保存在模块的成员中可以减少我们需要到达 DOM 树以提取应用程序状态信息的次数，从而使实现更加高效。

### 提示

将应用程序的状态保留在 JavaScript 对象或模块的属性中，而不是到 DOM 中提取它们，这是一种非常好的做法，可以使应用程序的架构更加面向对象，并且也被大多数现代 Web 开发框架采纳。

在模块初始化期间，我们给计数器变量赋予一个初始值，以便我们不再依赖页面的初始 HTML，并且拥有更健壮的实现。此外，我们附加了两个**委托事件观察器**，一个用于导致创建新信息框的点击，另一个用于关闭它们的点击。

## 实现概述

通过以上内容，我们将仪表板骨架应用程序重写为模块化架构。所有可用操作都公开为每个子模块的公共方法，可以通过编程方式调用，这样它们就与触发它们的事件解耦了。

对于读者来说，一个很好的练习是通过在上述实现中采用发布者/订阅者模式来进一步推动解耦。代码已经结构化为模块，这样的更改将更容易实现。

另一个可以以不同方式实现的部分是子模块的初始化方式。我们可以不再明确地在主仪表板模块中协调每个模块的初始化，而是通过在`$(document).ready()`调用中包装`init()`方法的调用并在声明后立即进行初始化来独立地初始化每个子模块。另一方面，没有一个中心点来协调初始化并依赖页面事件可能会感觉不够确定。另一种实现方式可能是像发布者/订阅者模式一样，在我们的主模块上暴露一个`registerForInit()`方法，它将通过数组跟踪已被请求进行初始化的模块。

### 注意

欲了解更多 jQuery 代码组织技巧，您可以访问[`learn.jquery.com/code-organization/concepts/`](http://learn.jquery.com/code-organization/concepts/)。

# 摘要

在这一章节中，我们学习了模块和命名空间的概念，还有它们在大型应用中采用时带来的好处。我们深入分析了最广泛采用的模式，并比较了它们的优点和局限性。我们通过示例学习了如何使用对象字面量模式、模块模式的变体以及揭示模块模式来开发模块。

我们继续简要介绍 ES5 的严格模式，并看到它如何有益于当今的模块。然后我们学习了一些关于标准化但尚未广泛支持的**ES6 模块**的细节。最后，我们看到在实施中使用模块模式后，仪表板应用程序的架构如何出现了巨大变化。

现在我们已经完成了关于如何使用模块和命名空间的介绍，我们可以继续下一章节，在下一章节中我们将介绍外观模式。在下一章节中，我们将学习关于外观的哲学，以及它们定义代码抽象的统一方式，使其易于其他开发人员理解和重复使用。
