# KnockoutJS 基础知识（一）

> 原文：[`zh.annas-archive.org/md5/2823CCFFDCBA26955DFD8A04E5A226C2`](https://zh.annas-archive.org/md5/2823CCFFDCBA26955DFD8A04E5A226C2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

当我们构建用户界面时，解决的最困难的问题之一是同步开发人员在代码中管理的数据和向用户显示的数据。开发人员采取的第一步是将演示和逻辑分开。这种分离使开发人员能够更好地分别管理两侧。但这两个层之间的通信仍然很困难。那是因为 JavaScript 被认为是一种不重要的语言，我们过去只是用它进行验证。然后 jQuery 给了我们一个线索，说明这种语言有多强大。但是数据仍然在服务器上管理，我们只是显示静态演示。这使得用户体验差和缓慢。

在过去的几年中，一种新型的架构模式出现了。它被称为 MVVM 模式。使用这种模式的库和框架使开发人员能够轻松地同步视图和数据。其中一个库就是 Knockout，使用 Knockout 的框架名为 Durandal。

Knockout 是一个快速且跨浏览器兼容的库，可以帮助我们开发具有更好用户体验的客户端应用程序。

开发人员不再需要担心数据同步的问题。Knockout 将我们的代码绑定到 HTML 元素，实时向用户显示我们代码的状态。

这种动态绑定使我们忘记了编码同步，我们可以将精力集中在编写应用程序的重要功能上。

如今，管理这些框架对前端开发人员来说是必不可少的。在本书中，你将学习 Knockout 和 Durandal 的基础知识，并且我们将深入探讨 JavaScript 的最佳设计实践和模式。

如果你想改进应用程序的用户体验并创建完全操作的前端应用程序，Knockout 和 Durandal 应该是你的选择。

# 本书涵盖内容

第一章，*使用 KnockoutJS 自动刷新 UI*，教你关于 Knockout 库。你将创建可观察对象并使你的模板对变化具有反应性。

第二章，*KnockoutJS 模板*，展示了如何创建模板以减少 HTML 代码。模板将帮助您保持设计的可维护性，并且它们可以根据您的数据进行调整。

第三章，*自定义绑定和组件*，展示了如何扩展 Knockout 库以使您的代码更易维护和可移植。

第四章, *管理 KnockoutJS 事件*，教你如何使用 jQuery 事件与隔离的模块和库进行通信。事件将帮助你在不同组件或模块之间发送消息。

第五章，*从服务器获取数据*，展示了如何使用 jQuery AJAX 调用从客户端与服务器通信。您还将学习如何使用模拟技术在没有服务器的情况下开发客户端。

第六章，*模块模式 – RequireJS*，教您如何使用模块模式和 AMD 模式编写良好形式的模块以管理库之间的依赖关系。

第七章，*Durandal – The KnockoutJS Framework*，教您最好的 Knockout 框架是如何工作的。您将了解框架的每个部分，从而能够用更少的代码制作大型应用程序。

第八章，*Durandal – The Cart Project*，将本书中构建的应用程序迁移到 Durandal。你将用几行代码开发同样的应用程序，并能够添加新功能。

# 本书所需内容

下面是在不同阶段需要的软件应用程序列表：

+   要开始：

    +   Twitter Bootstrap 3.2.0

    +   jQuery 2.2.1

    +   KnockoutJS 3.2.0

+   为了管理高级模板：

    +   Knockout 外部模板引擎 2.0.5

+   用于从浏览器执行 AJAX 调用的服务器：

    +   Mongoose 服务器 5.5

+   为了模拟数据和服务器调用：

    +   Mockjax 1.6.1

    +   MockJSON

+   要验证数据：

    +   Knockout 验证 2.0.0

+   使用浏览器进行调试：

    +   Chrome Knockout 调试器扩展

+   为了管理文件依赖关系：

    +   RequireJS

    +   Require 文本插件

    +   Knockout 和 helpers

+   KnockoutJS 框架：

    +   Durandal 2.1.0 Starter Kit

+   其他：

    +   iCheck 插件 1.0.2

# 本书适合谁

如果您是一名 JavaScript 开发人员，一直在使用 DOM 操作库（如 jQuery、MooTools 或 Scriptaculous），并且希望在现代 JavaScript 开发中进一步使用简单、轻量级和文档完善的库，那么这项技术和本书就适合您。

学习 Knockout 将是构建响应用户交互的 JavaScript 应用程序的下一个完美步骤。

# 约定

在本书中，您会发现许多文本样式，用于区分不同类型的信息。以下是一些这些样式的示例以及它们的含义解释。

文本中的代码字、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄如下所示：“例如，`background-color` 会抛出错误，因此您应该写成 `'background-color'`。”

代码块如下所示：

```js
var cart = ko.observableArray([]);
var showCartDetails = function () {
  if (cart().length > 0) {
    $("#cartContainer").removeClass("hidden");
  }
};
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
```

当我们希望引起您对代码块中特定部分的注意时，相关行或项目将以粗体显示：

```js
[default]
exten => s,1,Dial(Zap/1|30)
exten => s,2,Voicemail(u100)
exten => s,102,Voicemail(b100)
exten => i,1,Voicemail(s0)
<button class="btn btn-primary btn-sm" data-bind="click: showCartDetails, enable: cart().length  > 0">
  Show Cart Details
</button>

<button class="btn btn-primary btn-sm" data-bind="click: showCartDetails, disable: cart().length  < 1">
  Show Cart Details
</button>
```

任何命令行输入或输出如下所示：

```js
# cp /usr/src/asterisk-addons/configs/cdr_mysql.conf.sample
 /etc/asterisk/cdr_mysql.conf

```

**新术语**和**重要词汇**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中："一旦我们点击了**确认订单**按钮，订单应该显示给我们以审查，并确认我们是否同意。"

### 注意

警告或重要提示会以这样的框中出现。

### 提示

小贴士和技巧会出现在这样的格式中。


# 第一章：自动刷新 UI，使用 KnockoutJS

如果你正在阅读这本书，那是因为你已经发现管理 web 用户界面是相当复杂的。 **DOM**（Document Object Model 的缩写）仅使用本地 JavaScript 进行操作是非常困难的。这是因为每个浏览器都有自己的 JavaScript 实现。为了解决这个问题，过去几年中诞生了不同的 DOM 操作库。最常用于操作 DOM 的库是 jQuery。

越来越常见的是找到帮助开发人员在客户端管理越来越多功能的库。正如我们所说，开发人员已经获得了轻松操作 DOM 的可能性，因此可以管理模板和格式化数据。此外，这些库为开发人员提供了轻松的 API 来发送和接收来自服务器的数据。

然而，DOM 操作库并不为我们提供同步输入数据与代码中模型的机制。我们需要编写代码来捕捉用户操作并更新我们的模型。

当一个问题在大多数项目中经常出现时，在几乎所有情况下，它肯定可以以类似的方式解决。然后，开始出现了管理 HTML 文件与 JavaScript 代码之间连接的库。这些库实现的模式被命名为 MV*（Model-View-Whatever）。星号可以被更改为：

+   控制器，MVC（例如，AngularJS）

+   ViewModel，MVVM（例如，KnockoutJS）

+   Presenter（MVP）（例如，ASP.NET）

在这本书中我们要使用的库是 Knockout。它使用视图模型将数据和 HTML 进行绑定，因此它使用 MVVM 模式来管理数据绑定问题。

在本章中，你将学习这个库的基本概念，并开始在一个真实项目中使用 Knockout 的任务。

# KnockoutJS 和 MVVM 模式

**KnockoutJS** 是一个非常轻量级的库（仅 20 KB 经过压缩），它赋予对象成为视图和模型之间的纽带的能力。这意味着你可以使用清晰的底层数据模型创建丰富的界面。

为此，它使用声明性绑定来轻松将 DOM 元素与模型数据关联起来。数据与表示层（HTML）之间的这种链接允许 DOM 自动刷新显示的值。

Knockout 建立了模型数据之间的关系链，隐式地转换和组合它。Knockout 也是非常容易扩展的。可以将自定义行为实现为新的声明性绑定。这允许程序员在几行代码中重用它们。

使用 KnockoutJS 的优点有很多：

+   它是免费且开源的。

+   它是使用纯 JavaScript 构建的。

+   它可以与其他框架一起使用。

+   它没有依赖关系。

+   它支持所有主流浏览器，甚至包括古老的 IE 6+、Firefox 3.5+、Chrome、Opera 和 Safari（桌面/移动）。

+   它完全有 API 文档、实时示例和交互式教程。

Knockout 的功能很明确：连接视图和模型。它不管理 DOM 或处理 AJAX 请求。为了这些目的，我建议使用 jQuery。 Knockout 给了我们自由发展我们自己想要的代码。

![KnockoutJS 和 MVVM 模式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_01_01.jpg)

MVVM 模式图

# 一个真实的应用程序—koCart

为了演示如何在实际应用中使用 Knockout，我们将构建一个名为 koCart 的简单购物车。

首先，我们将定义用户故事。我们只需要几句话来知道我们想要实现的目标，如下所示：

+   用户应该能够查看目录

+   我们应该有能力搜索目录

+   用户可以点击按钮将物品添加到目录中

+   应用程序将允许我们从目录中添加、更新和删除物品

+   用户应该能够向购物车中添加、更新和删除物品

+   我们将允许用户更新他的个人信息。

+   应用程序应该能够计算购物车中的总金额

+   用户应该能够完成订单

通过用户故事，我们可以看到我们的应用程序有以下三个部分：

+   目录，包含和管理店内所有的商品。

+   购物车负责计算每行的价格和订单总额。

+   订单，用户可以在其中更新他的个人信息并确认订单。

# 安装组件

为了开发我们的真实项目，我们需要安装一些组件并设置我们的第一个布局。

这些都是你需要下载的组件:

+   Bootstrap: [`github.com/twbs/bootstrap/releases/download/v3.2.0/bootstrap-3.2.0-dist.zip`](https://github.com/twbs/bootstrap/releases/download/v3.2.0/bootstrap-3.2.0-dist.zip)

+   jQuery: [`code.jquery.com/jquery-2.1.1.min.js`](https://code.jquery.com/jquery-2.1.1.min.js)

+   KnockoutJS: [`knockoutjs.com/downloads/knockout-3.2.0.js`](http://knockoutjs.com/downloads/knockout-3.2.0.js)

由于我们在前几章只在客户端工作，我们可以在客户端模拟数据，现在不需要服务器端。 所以我们可以选择我们通常用于项目的任何地方来开始我们的项目。 我建议您使用您通常用来做项目的环境。

首先，我们创建一个名为`ko-cart`的文件夹，然后在其中创建三个文件夹和一个文件：

1.  在`css`文件夹中，我们将放置所有的 css。

1.  在`js`文件夹中，我们将放置所有的 JavaScript。

1.  在`fonts`文件夹中，我们会放置 Twitter Bootstrap 框架所需的所有字体文件。

1.  创建一个`index.html`文件。

现在你应该设置你的文件，就像以下截图所示：

![安装组件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_01_02.jpg)

初始文件夹结构

然后我们应该设置`index.html`文件的内容。记得使用`<script>`和`<link>`标签设置所有我们需要的文件的链接：

```js
<!DOCTYPE html>
<html>
<head>
  <title>KO Shopping Cart</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" type="text/css" href="css/bootstrap.min.css">
</head>
<body>
  <script type="text/javascript" src="img/jquery.min.js">
  </script>
  <script type="text/javascript" src="img/bootstrap.min.js">
  </script>
  <script type="text/javascript" src="img/knockout.debug.js">
  </script>
</body>
</html>
```

有了这些行代码，我们就有了开始应用程序所需的一切。

# 视图-模型

**视图模型**是 UI 上的数据和操作的纯代码表示。它不是 UI 本身。它没有任何按钮或显示样式的概念。它也不是持久化的数据模型。它保存用户正在处理的未保存数据。视图模型是纯 JavaScript 对象，不了解 HTML。以这种方式将视图模型保持抽象，让它保持简单，这样您就可以管理更复杂的行为而不会迷失。

要创建一个视图模型，我们只需要定义一个简单的 JavaScript 对象：

```js
var vm = {};
```

然后要激活 Knockout，我们将调用以下行：

```js
ko.applyBindings(vm);
```

第一个参数指定我们要与视图一起使用的视图模型对象。可选地，我们可以传递第二个参数来定义我们想要搜索`data-bind`属性的文档的哪个部分。

```js
ko.applyBindings(vm, document.getElementById('elementID'));
```

这将限制激活到具有`elementID`及其后代的元素，这在我们想要有多个视图模型并将每个视图模型与页面的不同区域关联时非常有用。

## 视图

**视图**是表示视图模型状态的可见、交互式 UI。它显示来自视图模型的信息，向视图模型发送命令（例如，当用户点击按钮时），并在视图模型状态更改时更新。在我们的项目中，视图由 HTML 标记表示。

为了定义我们的第一个视图，我们将构建一个 HTML 来显示一个产品。将这个新内容添加到容器中：

```js
<div class="container-fluid">
  <div class="row">
    <div class="col-md-12">
      <!-- our app goes here →
      <h1>Product</h1>
      <div>
        <strong>ID:</strong>
        <span data-bind="text:product.id"></span><br/>
        <strong>Name:</strong>
        <span data-bind="text:product.name"></span><br/>
        <strong>Price:</strong>
        <span data-bind="text:product.price"></span><br/>
        <strong>Stock:</strong>
        <span data-bind="text:product.stock"></span>
      </div> 
    </div>
  </div>
</div>
```

查看`data-bind`属性。这被称为**声明性绑定**。尽管这个属性对 HTML 来说并不是本机的，但它是完全正确的。但由于浏览器不知道它的含义，您需要激活 Knockout（`ko.applyBindings`方法）才能使其生效。

要显示来自产品的数据，我们需要在视图模型内定义一个产品：

```js
var vm = {
  product: {
    id:1,
    name:'T-Shirt',
    price:10,
    stock: 20
  }
};
ko.applyBindings(vm);//This how knockout is activated

```

在脚本标签的末尾添加视图模型：

```js
<script type="text/javascript" src="img/viewmodel.js"></script>
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中购买的所有 Packt 图书中下载示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册以直接通过电子邮件将文件发送给您。

这将是我们应用的结果：

![视图](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_01_03.jpg)

数据绑定的结果

## 模型

此数据表示业务域内的对象和操作（例如，产品）和任何 UI 无关。使用 Knockout 时，您通常会调用一些服务器端代码来读取和写入此存储的模型数据。

模型和视图模型应该彼此分离。为了定义我们的产品模型，我们将按照一些步骤进行：

1.  在我们的`js`文件夹内创建一个文件夹。

1.  将其命名为`models`。

1.  在`models`文件夹内，创建一个名为`product.js`的 JavaScript 文件。

`product.js`文件的代码如下：

```js
var Product = function (id,name,price,stock) {
  "use strict";
  var
    _id = id,
    _name = name,
    _price = price,
    _stock = stock
  ;

  return {
    id:_id,
    name:_name,
    price:_price,
    stock:_stock
  };
};
```

此函数创建一个包含产品接口的简单 JavaScript 对象。使用这种模式定义对象，称为**揭示模块模式**，允许我们清晰地将公共元素与私有元素分开。

要了解更多关于揭示模块模式的信息，请访问链接 [`carldanley.com/js-revealing-module-pattern/`](https://carldanley.com/js-revealing-module-pattern/)。

将此文件与您的`index.html`文件链接，并将其设置在所有脚本标签的底部。

```js
<script type="text/javascript" src="img/product.js">
</script>
```

现在我们可以使用产品模型定义视图模型中的产品：

```js
var vm = {
  product: Product(1,'T-Shirt',10,20);
};
ko.applyBindings(vm);
```

如果我们再次运行代码，将看到相同的结果，但我们的代码现在更易读了。视图模型用于存储和处理大量信息，因此视图模型通常被视为模块，并且在其上应用了揭示模块模式。此模式允许我们清晰地公开视图模型的 API（公共元素）并隐藏私有元素。

```js
var vm = (function(){
  var product = Product(1,'T-Shirt', 10, 20);
  return {
    product: product
  };
})();
```

当我们的视图模型开始增长时使用此模式可以帮助我们清晰地看到哪些元素属于对象的公共部分，哪些是私有的。

# 可观察对象自动刷新 UI

最后一个示例向我们展示了 Knockout 如何绑定数据和用户界面，但它没有展示自动 UI 刷新的魔法。为了执行此任务，Knockout 使用可观察对象。

**可观察对象**是 Knockout 的主要概念。这些是特殊的 JavaScript 对象，可以通知订阅者有关更改，并且可以自动检测依赖关系。为了兼容性，`ko.observable`对象实际上是函数。

要读取可观察对象的当前值，只需调用可观察对象而不带参数。在这个例子中，`product.price()`将返回产品的价格，`product.name()`将返回产品的名称。

```js
var product = Product(1,"T-Shirt", 10.00, 20);
product.price();//returns 10.00
product.name();//returns "T-Shirt"
```

要将新值写入可观察对象，请调用可观察对象并将新值作为参数传递。例如，调用`product.name('Jeans')`将把`name`值更改为`'Jeans'`。

```js
var product = Product(1,"T-Shirt", 10.00, 20);
product.name();//returns "T-Shirt"
product.name("Jeans");//sets name to "Jeans"
product.name();//returns "Jeans"
```

有关可观察对象的完整文档在官方 Knockout 网站上 [`knockoutjs.com/documentation/observables.html`](http://knockoutjs.com/documentation/observables.html)。

为了展示可观察对象的工作原理，我们将在模板中添加一些输入数据。

在包含产品信息的`div`上添加这些 HTML 标签。

```js
<div>
  <strong>ID:</strong>
  <input class="form-control" type="text" data-bind="value:product.id"/><br/>
  <strong>Name:</strong>
  <input class="form-control" type="text" data-bind="value:product.name"><br/>
  <strong>Price:</strong>
  <input class="form-control" type="text" data-bind="value:product.price"/><br/>
  <strong>Stock:</strong>
  <input class="form-control" type="text" data-bind="value:product.stock"><br/>
</div>
```

我们已经使用`value`属性将输入与视图模型链接起来。运行代码并尝试更改输入中的值。发生了什么？什么都没有。这是因为变量不是可观察对象。更新您的`product.js`文件，为每个变量添加`ko.observable`方法：

```js
"use strict";
function Product(id, name, price, stock) {
  "use strict";
  var
    _id = ko.observable(id),
    _name = ko.observable(name),
    _price = ko.observable(price),
    _stock = ko.observable(stock)
  ;

  return {
    id:_id,
    name:_name,
    price:_price,
    stock:_stock
  };
}
```

请注意，当我们更新输入中的数据时，我们的产品值会自动更新。当您将`name`值更改为`Jeans`时，文本绑定将自动更新关联的 DOM 元素的文本内容。这就是视图模型的更改如何自动传播到视图的方式。

![可观察对象自动刷新 UI](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_01_04.jpg)

可观察模型会自动更新

## 使用 observables 管理集合

如果你想检测并响应一个对象的变化，你会使用 observables。如果你想检测并响应一组东西的变化，请使用`observableArray`。这在许多情况下都很有用，比如显示或编辑多个值，并且需要在添加和删除项时重复出现和消失 UI 的部分。

要在我们的应用程序中显示一组产品，我们将按照一些简单的步骤进行：

1.  打开`index.html`文件，删除`<body>`标签内的代码，然后添加一个表格，我们将列出我们的目录：

    ```js
    <h1>Catalog</h1>
    <table class="table">
      <thead>
        <tr>
          <th>Name</th>
          <th>Price</th>
          <th>Stock</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td></td>
          <td></td>
          <td></td>
        </tr>
      </tbody>
    </table>
    ```

1.  在视图模型内定义一个产品数组：

    ```js
    "use strict";
    var vm = (function () {

      var catalog = [
        Product(1, "T-Shirt", 10.00, 20),
        Product(2, "Trousers", 20.00, 10),
        Product(3, "Shirt", 15.00, 20),
        Product(4, "Shorts", 5.00, 10)
      ];

      return {
        catalog: catalog
      };
    })();
    ko.applyBindings(vm);
    ```

1.  Knockout 中有一个绑定，用于在集合中的每个元素上重复执行一段代码。更新表格中的`tbody`元素：

    ```js
    <tbody data-bind="foreach:catalog">
      <tr>
        <td data-bind="text:name"></td>
        <td data-bind="text:price"></td>
        <td data-bind="text:stock"></td>
      </tr>
    </tbody>
    ```

我们使用`foreach`属性来指出该标记内的所有内容都应该针对集合中的每个项目进行重复。在该标记内部，我们处于每个元素的上下文中，所以你可以直接绑定属性。在浏览器中观察结果。

我们想知道目录中有多少个项目，所以在表格上方添加这行代码：

```js
<strong>Items:</strong>
<span data-bind="text:catalog.length"></span>
```

## 在集合中插入元素

要向产品数组中插入元素，应该发生一个事件。在这种情况下，用户将点击一个按钮，这个动作将触发一个操作，将一个新产品插入集合中。

在未来的章节中，你将会了解更多关于事件的内容。现在我们只需要知道有一个名为`click`的绑定属性。它接收一个函数作为参数，当用户点击元素时，该函数会被触发。

要插入一个元素，我们需要一个表单来插入新产品的值。将此 HTML 代码写在`<h1>`标签的下方：

```js
<form class="form-horizontal" role="form" data-bind="with:newProduct">
  <div class="form-group">
    <div class="col-sm-12">
      <input type="text" class="form-control" placeholder="Name" data-bind="textInput:name">
      </div>
    </div>
    <div class="form-group">
      <div class="col-sm-12">
      <input type="password" class="form-control" placeholder="Price" data-bind="textInput:price">
      </div>
    </div>
    <div class="form-group">
      <div class="col-sm-12">
      <input type="password" class="form-control" placeholder="Stock" data-bind="textInput:stock">
      </div>
    </div>
    <div class="form-group">
      <div class="col-sm-12">
      <button type="submit" class="btn btn-default" data-bind="{click:$parent.addProduct}">
        <i class="glyphicon glyphicon-plus-sign">
        </i> Add Product
      </button>
    </div>
  </div>
</form>
```

在这个模板中，我们找到了一些新的绑定：

+   `with` 绑定：它创建一个新的绑定上下文，以便后代元素在指定对象的上下文中绑定，本例中为`newProduct`。

    [`knockoutjs.com/documentation/with-binding.html`](http://knockoutjs.com/documentation/with-binding.html)

+   `textInput` 绑定：`textInput` 绑定将文本框（`<input>`）或文本区域（`<textarea>`）与视图模型属性连接起来，提供视图模型属性和元素值之间的双向更新。与`value`绑定属性不同，`textInput` 提供了对于所有类型的用户输入，包括自动完成、拖放和剪贴板事件的 DOM 的即时更新。它从 Knockout 的 3.2 版本开始提供。

    [`knockoutjs.com/documentation/textinput-binding.html`](http://knockoutjs.com/documentation/textinput-binding.html)

+   `click` 绑定：`click` 绑定添加了一个事件处理程序，使得当关联的 DOM 元素被点击时，您选择的 JavaScript 函数被调用。在调用处理程序时，Knockout 将当前模型值作为第一个参数提供。这在为集合中的每个项目渲染 UI，并且您需要知道哪个项目的 UI 被点击时特别有用。

    [`knockoutjs.com/documentation/click-binding.html`](http://knockoutjs.com/documentation/click-binding.html)

+   `$parent` 对象：这是一个绑定上下文属性。我们用它来引用`foreach`循环外的数据。

欲了解有关绑定上下文属性的更多信息，请阅读 Knockout 文档：[`knockoutjs.com/documentation/binding-context.html`](http://knockoutjs.com/documentation/binding-context.html)。

![在集合中插入元素](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_01_05.jpg)

使用 with 设置上下文和 parent 通过它们导航

现在是时候向我们的视图模型添加 `newProduct` 对象了。首先，我们应该定义一个带有空数据的新产品：

```js
var newProduct = Product("","","","");
```

我们已经定义了一个字面对象，将包含我们要放入新产品的信息。此外，我们已经定义了一个清除或重置对象的方法，一旦插入完成就会进行。现在我们定义我们的`addProduct` 方法：

```js
var addProduct = function (context) {
  var id = new Date().valueOf();//random id from time
  var newProduct = Product(
    id,
    context.name(),
    context.price(),
    context.stock()
  );
  catalog.push(newProduct);
  newProduct.clear();
};
```

此方法创建一个从点击事件接收到的数据的新产品。

点击事件始终将上下文作为第一个参数发送。还要注意，您可以在可观察数组中使用`push`等数组方法。请查看 Knockout 文档 ([`knockoutjs.com/documentation/observableArrays.html`](http://knockoutjs.com/documentation/observableArrays.html)) 以查看数组中可用的所有方法。

我们应该实现一个私有方法，一旦将新产品添加到集合中，就会清除新产品的数据：

```js
var clearNewProduct = function () {
  newProduct.name("");
  newProduct.price("");
  newProduct.stock("");
};
```

更新视图模型：

```js
return {
    catalog: catalog,
    newProduct: newProduct,
    addProduct: addProduct
};
```

如果您运行代码，您将注意到当您尝试添加新产品时什么也不会发生。这是因为，尽管我们的产品具有可观察属性，但我们的数组不是一个可观察的数组。因此，Knockout 不会监听更改。我们应该将数组转换为`observableArray`可观察的数组。

```js
var catalog = ko.observableArray([
  Product(1, "T-Shirt", 10.00, 20),
  Product(2, "Trousers", 20.00, 10),
  Product(3, "Shirt", 15.00, 20),
  Product(4, "Shorts", 5.00, 10)
]);
```

现在 Knockout 正在监听该数组的变化，但不会监听每个元素内部发生的事情。Knockout 只告诉我们在数组中插入或删除元素的情况，但不告诉我们修改元素的情况。如果您想知道元素内发生了什么，那么对象应具有可观察的属性。

`observableArray` 只会跟踪它所持有的对象，并在添加或删除对象时通知监听者。

在幕后，`observableArray` 实际上是一个值为数组的可观察属性。因此，您可以像调用任何其他可观察属性一样，以无参数的方式将`observableArray`可观察属性作为函数进行调用，从而获取底层的 JavaScript 数组。然后您可以从那个底层数组中读取信息。

```js
<strong>Items:</strong>
<span data-bind="text:catalog().length"></span>
```

## 计算可观察属性

想要思考一下我们在界面中显示的某些值是否取决于 Knockout 已经观察到的其他值并不奇怪。例如，如果我们想要按名称搜索我们目录中的产品，显然我们在列表中显示的目录产品与我们在搜索框中输入的术语相关联。在这些情况下，Knockout 为我们提供了**计算可观察对象**。

您可以在 Knockout 文档中详细了解[计算可观察对象](http://knockoutjs.com/documentation/computedObservables.html)。

要开发搜索功能，请定义一个文本框，我们可以在其中写入要搜索的术语。我们将把它绑定到`searchTerm`属性。要在编写时更新值，我们应该使用`textInput`绑定。如果我们使用值绑定，当元素失去焦点时，值将被更新。将此代码放在产品表上方：

```js
<div class="input-group">
  <span class="input-group-addon">
    <i class="glyphicon glyphicon-search"></i> Search</span>
  <input type="text" class="form-control" data-bind="textInput: searchTerm">
</div>
```

要创建一个过滤目录，我们将检查所有项目，并测试`searchTerm`是否在项目的`name`属性中。

```js
var searchTerm = ko.observable(''); 
var filteredCatalog = ko.computed(function () {
  //if catalog is empty return empty array
  if (!catalog()) {
    return [];
  }
  var filter = searchTerm().toLowerCase();
  //if filter is empty return all the catalog
  if (!filter) {
    return catalog();
  }
  //filter data
  var filtered = ko.utils.arrayFilter(catalog(), function (item) {
    var fields = ["name"]; //we can filter several properties
    var i = fields.length;
    while (i--) {
      var prop = fields[i];
      var strProp = ko.unwrap(item[prop]).toLocaleLowerCase();
      if (strProp.indexOf(filter) !== -1){
        return true;
      };
    }
    Return false;
  });
  return filtered;
});
```

`ko.utils`对象在 Knockout 中没有文档。它是库内部使用的对象。它具有公共访问权限，并具有一些可以帮助我们处理可观察对象的函数。互联网上有很多关于它的非官方示例。

它的一个有用函数是`ko.utils.arrayFilter`。如果您看一下第 13 行，我们已经使用了此方法来获取过滤后的数组。

此函数以数组作为第一个参数。请注意，我们调用`catalog`数组可观察对象以获取元素。我们不传递可观察对象本身，而是传递可观察对象的内容。

第二个参数是决定项目是否在过滤数组中的函数。如果项目符合过滤数组的条件，它将返回`true`。否则返回`false`。

在此片段的第 14 行，我们可以找到一个名为`fields`的数组。此参数将包含应符合条件的字段。在这种情况下，我们只检查过滤值是否在`name`值中。如果我们非常确定只会检查`name`字段，我们可以简化过滤函数：

```js
var filtered = ko.utils.arrayFilter(catalog(), function (item) {
  var strProp = ko.unwrap(item["name"]).toLocaleLowerCase();
  return (strProp.indexOf(filter) > -1);
});
```

`ko.unwrap`函数返回包含可观察对象的值。当我们不确定变量是否包含可观察对象时，我们使用`ko.unwrap`，例如：

```js
var notObservable = 'hello';
console.log(notObservable()) //this will throw an error.
console.log(ko.unwrap(notObservable)) //this will display 'hello');
```

将过滤后的目录暴露到公共 API 中。请注意，现在我们需要使用过滤后的目录而不是原始产品目录。因为我们正在应用**揭示模块模式**，我们可以保持原始 API 接口，只需使用过滤后的目录更新目录的值即可。只要我们始终保持相同的公共接口，就不需要通知视图我们将使用不同的目录或其他元素：

```js
return {
  searchTerm: searchTerm,
  catalog: filteredCatalog,
  newProduct: newProduct,
  addProduct: addProduct
};
```

现在，尝试在搜索框中键入一些字符，并在浏览器中查看目录如何自动更新数据。

太棒了！我们已经完成了我们的前三个用户故事：

+   用户应能够查看目录

+   用户应能够搜索目录

+   用户应能够向目录添加项目

让我们看看最终结果：

![计算观察对象](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_01_06.jpg)

# 总结

在本章中，你学会了 Knockout 库的基础知识。我们创建了一个简单的表单来将产品添加到我们的目录中。你还学会了如何管理 observable 集合并将其显示在表中。最后，我们使用计算观察对象开发了搜索功能。

你已经学会了三个重要的 Knockout 概念：

+   **视图模型**：这包含代表视图状态的数据。它是一个纯 JavaScript 对象。

+   **模型**：这包含了来自业务领域的数据。

+   **视图**：这显示了我们在视图模型中存储的数据在某一时刻的情况。

为构建响应式 UI，Knockout 库为我们提供了一些重要的方法：

+   `ko.observable`：用于管理变量。

+   `ko.observableArray`：用于管理数组。

+   `ko.computed`：它们对其内部的 observable 的更改作出响应。

要迭代数组的元素，我们使用`foreach`绑定。当我们使用`foreach`绑定时，我们会创建一个新的上下文。这个上下文是相对于每个项目的。如果我们想要访问超出此上下文的内容，我们应该使用`$parent`对象。

当我们想要为变量创建一个新的上下文时，我们可以将`with`绑定附加到任何 DOM 元素。

我们使用`click`绑定将点击事件附加到元素上。点击事件函数始终将上下文作为第一个参数。

要从我们不确定是否为 observable 的变量中获取值，我们可以使用`ko.unwrap`函数。

我们可以使用`ko.utils.arrayFilter`函数来筛选集合。

在下一章中，我们将使用模板来保持我们的代码易维护和干净。模板引擎帮助我们保持代码整洁，且方便我们以简单的方式更新视图。

本章开发的代码副本在此处：

[`github.com/jorgeferrando/knockout-cart/archive/chapter1.zip`](https://github.com/jorgeferrando/knockout-cart/archive/chapter1.zip)。


# 第二章：KnockoutJS 模板

一旦我们建立了我们的目录，就是时候给我们的应用程序添加一个购物车了。当我们的代码开始增长时，将其拆分成几个部分以保持可维护性是必要的。当我们拆分 JavaScript 代码时，我们谈论的是模块、类、函数、库等。当我们谈论 HTML 时，我们称这些部分为模板。

KnockoutJS 有一个原生模板引擎，我们可以用它来管理我们的 HTML。它非常简单，但也有一个很大的不便之处：模板应该在当前 HTML 页面中加载。如果我们的应用程序很小，这不是问题，但如果我们的应用程序开始需要越来越多的模板，这可能会成为一个问题。

在本章中，我们将使用原生引擎设计我们的模板，然后我们将讨论可以用来改进 Knockout 模板引擎的机制和外部库。

# 准备项目

我们可以从我们在第一章中完成的项目开始，*使用 KnockoutJS 自动刷新 UI*。首先，我们将为页面添加一些样式。将一个名为`style.css`的文件添加到`css`文件夹中。在`index.html`文件中添加一个引用，就在`bootstrap`引用下面。以下是文件的内容：

```js
.container-fluid {
  margin-top: 20px;
}
.row {
  margin-bottom: 20px;
}
.cart-unit {
  width: 80px;
}
.btn-xs {
  font-size:8px;
}
.list-group-item {
  overflow: hidden;
}
.list-group-item h4 {
  float:left;
  width: 100px;
}
.list-group-item .input-group-addon {
  padding: 0;
}
.btn-group-vertical > .btn-default {
  border-color: transparent;
}
.form-control[disabled], .form-control[readonly] {
  background-color: transparent !important;
}
```

现在从 body 标签中删除所有内容，除了脚本标签，然后粘贴下面这些行：

```js
<div class="container-fluid">
  <div class="row" id="catalogContainer">
    <div class="col-xs-12" data-bind="template:{name:'header'}"></div>
    <div class="col-xs-6" data-bind="template:{name:'catalog'}"></div>
    <div id="cartContainer" class="col-xs-6 well hidden" data-bind="template:{name:'cart'}"></div>
  </div>
  <div class="row hidden" id="orderContainer" data-bind="template:{name:'order'}">
  </div>
  <div data-bind="template: {name:'add-to-catalog-modal'}"></div>
  <div data-bind="template: {name:'finish-order-modal'}"></div>
</div>
```

让我们来审查一下这段代码。

我们有两个 row 类。它们将是我们的容器。

第一个容器的名称为`catalogContainer`，它将包含目录视图和购物车。第二个引用为`orderContainer`的容器，我们将在那里设置我们的最终订单。

我们还有两个更多的`<div>`标签在底部，将包含模态对话框，显示向我们的目录中添加产品的表单（我们在第一章中构建的表单），另一个将包含一个模态消息，告诉用户我们的订单已经完成。

除了这段代码，你还可以看到`data-bind`属性中的一个模板绑定。这是 Knockout 用来将模板绑定到元素的绑定。它包含一个`name`参数，表示模板的 ID。

```js
<div class="col-xs-12" data-bind="template:{name:'header'}"></div>
```

在这个例子中，这个`<div>`元素将包含位于 ID 为`header`的`<script>`标签内的 HTML。

# 创建模板

模板元素通常在 body 底部声明，就在具有对我们外部库引用的`<script>`标签上面。我们将定义一些模板，然后我们将讨论每一个模板：

```js
<!-- templates -->
<script type="text/html" id="header"></script>
<script type="text/html" id="catalog"></script>
<script type="text/html" id="add-to-catalog-modal"></script>
<script type="text/html" id="cart-widget"></script>
<script type="text/html" id="cart-item"></script>
<script type="text/html" id="cart"></script>
<script type="text/html" id="order"></script>
<script type="text/html" id="finish-order-modal"></script>
```

每个模板的名称本身就足够描述性了，所以很容易知道我们将在其中设置什么。

让我们看一个图表，展示我们在屏幕上放置每个模板的位置：

![创建模板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_02_01.jpg)

请注意，`cart-item`模板将针对购物车集合中的每个项目重复出现。模态模板只会在显示模态对话框时出现。最后，`order`模板在我们点击确认订单之前是隐藏的。

在`header`模板中，我们将有页面的标题和菜单。`catalog`模板将包含我们在第一章中编写的产品表格，*使用 KnockoutJS 自动刷新 UI*。`add-to-catalog-modal`模板将包含显示向我们的目录添加产品的表单的模态框。`cart-widget`模板将显示我们购物车的摘要。`cart-item`模板将包含购物车中每个项目的模板。`cart`模板将具有购物车的布局。`order`模板将显示我们想购买的最终产品列表和确认订单的按钮。

## 头部模板

让我们从应该包含`header`模板的 HTML 标记开始：

```js
<script type="text/html" id="header">
  <h1>
    Catalog
  </h1>

  <button class="btn btn-primary btn-sm" data-toggle="modal" data-target="#addToCatalogModal">
    Add New Product
  </button>
  <button class="btn btn-primary btn-sm" data-bind="click: showCartDetails, css:{ disabled: cart().length  < 1}">
    Show Cart Details
  </button>
  <hr/>
</script>
```

我们定义了一个`<h1>`标签和两个`<button>`标签。

第一个按钮标签附加到具有 ID`#addToCatalogModal`的模态框。由于我们使用的是 Bootstrap 作为 CSS 框架，我们可以使用`data-target`属性按 ID 附加模态，并使用`data-toggle`属性激活模态。

第二个按钮将显示完整的购物车视图，只有在购物车有商品时才可用。为了实现这一点，有许多不同的方法。

第一个方法是使用 Twitter Bootstrap 提供的 CSS-disabled 类。这是我们在示例中使用的方式。CSS 绑定允许我们根据附加到类的表达式的结果来激活或停用元素中的类。

另一种方法是使用`enable`绑定。如果表达式评估为`true`，此绑定将启用元素。我们可以使用相反的绑定，称为`disable`。Knockout 网站上有完整的文档[`knockoutjs.com/documentation/enable-binding.html`](http://knockoutjs.com/documentation/enable-binding.html)：

```js
<button class="btn btn-primary btn-sm" data-bind="click: showCartDetails, enable: cart().length  > 0"> 
  Show Cart Details
</button>

<button class="btn btn-primary btn-sm" data-bind="click: showCartDetails, disable: cart().length  < 1"> 
  Show Cart Details
</button>
```

第一种方法使用 CSS 类来启用和禁用按钮。第二种方法使用 HTML 属性`disabled`。

我们可以使用第三个选项，即使用计算可观察值。我们可以在视图模型中创建一个计算可观察变量，根据购物车的长度返回`true`或`false`：

```js
//in the viewmodel. Remember to expose it
var cartHasProducts = ko.computed(function(){
  return (cart().length > 0);
});
//HTML
<button class="btn btn-primary btn-sm" data-bind="click: showCartDetails, enable: cartHasProducts"> 
  Show Cart Details
</button>
```

要显示购物车，我们将以与上一章中相同的方式使用`click`绑定。

现在我们应该转到我们的`viewmodel.js`文件，并添加所有我们需要使此模板工作的信息：

```js
var cart = ko.observableArray([]);
var showCartDetails = function () {
  if (cart().length > 0) {
    $("#cartContainer").removeClass("hidden");
  }
};
```

并且你应该在视图模型中公开这两个对象：

```js
  return {
  //first chapter
    searchTerm: searchTerm,
    catalog: filteredCatalog,
    newProduct: newProduct,
    totalItems:totalItems,
    addProduct: addProduct,
  //second chapter
    cart: cart,
    showCartDetails: showCartDetails,
  };
```

## 目录模板

下一步是在`header`模板下方定义`catalog`模板：

```js
<script type="text/html" id="catalog">
  <div class="input-group">
    <span class="input-group-addon">
      <i class="glyphicon glyphicon-search"></i> Search
    </span>
    <input type="text" class="form-control" data-bind="textInput: searchTerm">
  </div>
  <table class="table">
    <thead>
    <tr>
      <th>Name</th>
      <th>Price</th>
      <th>Stock</th>
      <th></th>
    </tr>
    </thead>
    <tbody data-bind="foreach:catalog">
    <tr data-bind="style:color:stock() < 5?'red':'black'">
      <td data-bind="text:name"></td>
      <td data-bind="text:price"></td>
      <td data-bind="text:stock"></td>
      <td>
        <button class="btn btn-primary" data-bind="click:$parent.addToCart">
          <i class="glyphicon glyphicon-plus-sign"></i> Add
        </button>
      </td>
    </tr>
    </tbody>
    <tfoot>
    <tr>
      <td colspan="3">
        <strong>Items:</strong><span data-bind="text:catalog().length"></span>
      </td>
      <td colspan="1">
        <span data-bind="template:{name:'cart-widget'}"></span>
      </td>
    </tr>
    </tfoot>
  </table>
</script>
```

这是我们在上一章中构建的相同表格。我们只是添加了一些新东西：

```js
<tr data-bind="style:{color: stock() < 5?'red':'black'}">...</tr>
```

现在，每行使用 `style` 绑定来提醒用户，当他们购物时，库存达到最大限制。`style` 绑定与 CSS 绑定类似。它允许我们根据表达式的值添加样式属性。在这种情况下，如果库存高于五，行中的文本颜色必须是黑色，如果库存是四或更少，则为红色。我们可以使用其他 CSS 属性，所以随时尝试其他行为。例如，如果元素在购物车内部，将目录的行设置为绿色。我们应记住，如果属性有连字符，你应该用单引号括起来。例如，`background-color` 会抛出错误，所以你应该写成 `'background-color'`。

当我们使用根据视图模型的值激活的绑定时，最好使用计算观察值。因此，我们可以在我们的产品模型中创建一个计算值，该值返回应显示的颜色值：

```js
//In the Product.js
var _lineColor = ko.computed(function(){
  return (_stock() < 5)? 'red' : 'black';
});
return {
  lineColor:_lineColor
};
//In the template
<tr data-bind="style:lineColor"> ... </tr>
```

如果我们在 `style.css` 文件中创建一个名为 `stock-alert` 的类，并使用 CSS 绑定，效果会更好。

```js
//In the style file
.stock-alert {
  color: #f00;
}
//In the Product.js
var _hasStock = ko.computed(function(){
  return (_stock() < 5);   
});
return {
  hasStock: _hasStock
};
//In the template
<tr data-bind="css: hasStock"> ... </tr>
```

现在，看一下 `<tfoot>` 标签内部。

```js
<td colspan="1">
  <span data-bind="template:{name:'cart-widget'}"></span>
</td>
```

正如你所见，我们可以有嵌套模板。在这种情况下，我们在 `catalog` 模板内部有一个 `cart-widget` 模板。这使我们可以拥有非常复杂的模板，将它们分割成非常小的片段，并组合它们，以保持我们的代码整洁和可维护性。

最后，看一下每行的最后一个单元格：

```js
<td>
  <button class="btn btn-primary" data-bind="click:$parent.addToCart">
    <i class="glyphicon glyphicon-plus-sign"></i> Add
  </button>
</td>
```

看看我们如何使用魔术变量 `$parent` 调用 `addToCart` 方法。Knockout 给了我们一些魔术词来浏览我们应用程序中的不同上下文。在这种情况下，我们在 `catalog` 上下文中，想要调用一个位于一级上的方法。我们可以使用名为 `$parent` 的魔术变量。

在 Knockout 上下文中，还有其他变量可供使用。Knockout 网站上有完整的文档 [`knockoutjs.com/documentation/binding-context.html`](http://knockoutjs.com/documentation/binding-context.html)。

在这个项目中，我们不会使用所有这些绑定上下文变量。但我们会快速解释这些绑定上下文变量，只是为了更好地理解它们。

如果我们不知道我们有多少级别深入，我们可以使用魔术词 `$root` 导航到视图模型的顶部。

当我们有许多父级时，我们可以获得魔术数组 `$parents` 并使用索引访问每个父级，例如 `$parents[0]`，`$parents[1]`。想象一下，你有一个类别列表，每个类别包含一个产品列表。这些产品是一个 ID 列表，而类别有一个获取其产品名称的方法。我们可以使用 `$parents` 数组来获取对类别的引用：

```js
<ul data-bind="foreach: {data: categories}">
  <li data-bind="text: $data.name"></li>
  <ul data-bind="foreach: {data: $data.products, as: 'prod'}>
    <li data-bind="text: $parents[0].getProductName(prod.ID)"></li>
  </ul>
</ul>
```

看看`foreach`绑定内部的`as`属性有多有用。它使代码更易读。但是，如果你在`foreach`循环内部，你也可以使用`$data`魔术变量访问每个项目，并且可以使用`$index`魔术变量访问集合中每个元素的位置索引。例如，如果我们有一个产品列表，我们可以这样做：

```js
<ul data-bind="foreach: cart">
  <li><span data-bind="text:$index">
    </span> - <span data-bind="text:$data.name"></span>
</ul>
```

这应该显示：

**0 – 产品 1**

**1 – 产品 2**

**2 – 产品 3**

**...**

![目录模板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_02_02.jpg)

KnockoutJS 魔术变量用于导航上下文

现在我们更多地了解了绑定变量是什么，让我们回到我们的代码。我们现在将编写`addToCart`方法。

我们将在我们的`js/models`文件夹中定义购物车项目。创建一个名为`CartProduct.js`的文件，并插入以下代码：

```js
//js/models/CartProduct.js
var CartProduct = function (product, units) {
  "use strict";

  var _product = product,
    _units = ko.observable(units);

  var subtotal = ko.computed(function(){
    return _product.price() * _units();
  });

  var addUnit = function () {
    var u = _units();
    var _stock = _product.stock();
    if (_stock === 0) {
      return;
    }
  _units(u+1);
    _product.stock(--_stock);
  };

  var removeUnit = function () {
    var u = _units();
    var _stock = _product.stock();
    if (u === 0) {
      return;
    }
    _units(u-1);
    _product.stock(++_stock);
  };

  return {
    product: _product,
    units: _units,
    subtotal: subtotal,
    addUnit : addUnit,
    removeUnit: removeUnit,
  };
};
```

每个购物车产品由产品本身和我们想购买的产品的单位组成。我们还将有一个计算字段，其中包含该行的小计。我们应该让对象负责管理其单位和产品的库存。因此，我们已经添加了`addUnit`和`removeUnit`方法。如果调用了这些方法，它们将增加一个产品单位或删除一个产品单位。

我们应该在我们的`index.html`文件中与其他`<script>`标签一起引用这个 JavaScript 文件。

在视图模型中，我们应该创建一个购物车数组，并在返回语句中公开它，就像我们之前做的那样：

```js
var cart = ko.observableArray([]);
```

是时候编写`addToCart`方法了：

```js
var addToCart = function(data) {
  var item = null;
  var tmpCart = cart();
  var n = tmpCart.length;
  while(n--) {
    if (tmpCart[n].product.id() === data.id()) {
      item = tmpCart[n];
    }
  }
  if (item) {
    item.addUnit();
  } else {
    item = new CartProduct(data,0);
    item.addUnit();
    tmpCart.push(item);        
  }
  cart(tmpCart);
};
```

此方法在购物车中搜索产品。如果存在，则更新其单位，如果不存在，则创建一个新的。由于购物车是一个可观察数组，我们需要获取它，操作它，并覆盖它，因为我们需要访问产品对象以了解产品是否在购物车中。请记住，可观察数组不会观察它们包含的对象，只会观察数组属性。

## 添加到购物车模态框模板

这是一个非常简单的模板。我们只需将我们在第一章中创建的代码包装在一起，*使用 KnockoutJS 自动刷新 UI*，以将产品添加到 Bootstrap 模态框中：

```js
<script type="text/html" id="add-to-catalog-modal">
  <div class="modal fade" id="addToCatalogModal">
    <div class="modal-dialog">
      <div class="modal-content">
        <form class="form-horizontal" role="form" data-bind="with:newProduct">
          <div class="modal-header">
            <button type="button" class="close" data-dismiss="modal">
              <span aria-hidden="true">&times;</span>
              <span class="sr-only">Close</span>
            </button><h3>Add New Product to the Catalog</h3>
          </div>
          <div class="modal-body">
            <div class="form-group">
              <div class="col-sm-12">
                <input type="text" class="form-control" placeholder="Name" data-bind="textInput:name">
              </div>
            </div>
            <div class="form-group">
              <div class="col-sm-12">
                <input type="text" class="form-control" placeholder="Price" data-bind="textInput:price">
              </div>
            </div>
            <div class="form-group">
              <div class="col-sm-12">
                <input type="text" class="form-control" placeholder="Stock" data-bind="textInput:stock">
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <div class="form-group">
              <div class="col-sm-12">
                <button type="submit" class="btn btn-default" data-bind="{click:$parent.addProduct}">
                  <i class="glyphicon glyphicon-plus-sign">
                  </i> Add Product
                </button>
              </div>
            </div>
          </div>
        </form>
      </div><!-- /.modal-content -->
    </div><!-- /.modal-dialog -->
  </div><!-- /.modal -->
</script>
```

## 购物车小部件模板

此模板可以快速向用户提供有关购物车中有多少件商品以及它们的总成本的信息：

```js
<script type="text/html" id="cart-widget">
  Total Items: <span data-bind="text:totalItems"></span>
  Price: <span data-bind="text:grandTotal"></span>
</script>
```

我们应该在我们的视图模型中定义`totalItems`和`grandTotal`：

```js
var totalItems = ko.computed(function(){
  var tmpCart = cart();
  var total = 0;
  tmpCart.forEach(function(item){
    total += parseInt(item.units(),10);
  });
  return total;
});
var grandTotal = ko.computed(function(){
  var tmpCart = cart();
  var total = 0;
  tmpCart.forEach(function(item){
    total += (item.units() * item.product.price());
  });
  return total;
});
```

现在你应该像我们一直做的那样在返回语句中公开它们。现在不要担心格式，你将在未来学习如何格式化货币或任何类型的数据。现在你必须专注于学习如何管理信息以及如何向用户显示信息。

## 购物车项目模板

`cart-item`模板显示购物车中的每一行：

```js
<script type="text/html" id="cart-item">
  <div class="list-group-item" style="overflow: hidden">
    <button type="button" class="close pull-right" data-bind="click:$root.removeFromCart"><span>&times;</span></button>
    <h4 class="" data-bind="text:product.name"></h4>
    <div class="input-group cart-unit">
      <input type="text" class="form-control" data-bind="textInput:units" readonly/>
        <span class="input-group-addon">
          <div class="btn-group-vertical">
            <button class="btn btn-default btn-xs" data-bind="click:addUnit">
              <i class="glyphicon glyphicon-chevron-up"></i>
            </button>
            <button class="btn btn-default btn-xs" data-bind="click:removeUnit">
              <i class="glyphicon glyphicon-chevron-down"></i>
            </button>
          </div>
        </span>
    </div>
  </div>
</script>
```

我们在每条线的右上角设置了一个**x**按钮，方便从购物车中移除一条线。正如您所见，我们使用了`$root`魔术变量来导航到顶级上下文，因为我们将在`foreach`循环中使用此模板，这意味着该模板将处于循环上下文中。如果我们把这个模板视为一个独立的元素，我们无法确定我们在上下文导航中有多深。为了确保，我们要到正确的上下文中调用`removeFormCart`方法。在这种情况下最好使用`$root`而不是`$parent`。

`removeFromCart`的代码应该在 view-model 上下文中，代码应该如下所示：

```js
var removeFromCart = function (data) {
  var units = data.units();
  var stock = data.product.stock();
  data.product.stock(units+stock);
  cart.remove(data);
};
```

注意，在`addToCart`方法中，我们获得了 observable 内部的数组。我们这样做是因为我们需要导航到数组的元素内部。在这种情况下，Knockout 可观察数组有一个叫做`remove`的方法，允许我们移除作为参数传递的对象。如果对象在数组中，则会被移除。

记住，数据环境始终作为我们在单击事件中使用的函数的第一个参数传递。

## 购物车模板

`cart`模板应显示购物车的布局：

```js
<script type="text/html" id="cart">
  <button type="button" class="close pull-right" data-bind="click:hideCartDetails">
    <span>&times;</span>
  </button>
  <h1>Cart</h1>
  <div data-bind="template: {name: 'cart-item', foreach:cart}" class="list-group"></div>
  <div data-bind="template:{name:'cart-widget'}"></div>
  <button class="btn btn-primary btn-sm" data-bind="click:showOrder">
    Confirm Order
  </button>
</script>
```

重要的是，您注意到我们**<h1>购物车</h1>**下面正好绑定了模板。我们使用`foreach`参数将模板与数组绑定。通过这种绑定，Knockout 会为购物车中的每个元素渲染`cart-item`模板。这样可以大大减少我们在每个模板中编写的代码，而且使它们更易读。

我们再次使用`cart-widget`模板显示总商品数量和总金额。这是模板的一个很好的特点，我们可以反复使用内容。

请注意，我们在购物车的右上方放置了一个按钮，当我们不需要查看购物车的详细信息时，可以关闭购物车，并且另一个按钮是在完成时确认订单。我们的 view-model 中的代码应该如下：

```js
var hideCartDetails = function () {
  $("#cartContainer").addClass("hidden");
};
var showOrder = function () {
  $("#catalogContainer").addClass("hidden");
  $("#orderContainer").removeClass("hidden");
};
```

正如您所见，我们使用 jQuery 和 Bootstrap 框架的 CSS 类来显示和隐藏元素。隐藏类只是给元素添加了`display: none`样式。我们只需要切换这个类来在视图中显示或隐藏元素。将这两个方法暴露在您的 view-model 的`return`语句中。

当需要显示`order`模板时我们将回来。

这就是我们有了我们的目录和购物车后的结果：

![购物车模板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_02_03.jpg)

## 订单模板

一旦我们单击**确认订单**按钮，订单应该显示给我们，以便审查和确认我们是否同意。

```js
<script type="text/html" id="order">
  <div class="col-xs-12">
    <button class="btn btn-sm btn-primary" data-bind="click:showCatalog">
      Back to catalog
    </button>
    <button class="btn btn-sm btn-primary" data-bind="click:finishOrder">
      Buy & finish
    </button>
  </div>
  <div class="col-xs-6">
    <table class="table">
      <thead>
      <tr>
        <th>Name</th>
        <th>Price</th>
        <th>Units</th>
        <th>Subtotal</th>
      </tr>
      </thead>
      <tbody data-bind="foreach:cart">
      <tr>
        <td data-bind="text:product.name"></td>
        <td data-bind="text:product.price"></td>
        <td data-bind="text:units"></td>
        <td data-bind="text:subtotal"></td>
      </tr>
      </tbody>
      <tfoot>
      <tr>
        <td colspan="3"></td>
        <td>Total:<span data-bind="text:grandTotal"></span></td>
      </tr>
      </tfoot>
    </table>
  </div>
</script>
```

这里有一个只读表格，显示所有购物车条目和两个按钮。其中一个是确认按钮，将显示模态对话框，显示订单完成，另一个让我们有选择返回目录继续购物。有些代码需要添加到我们的 view-model 中并向用户公开：

```js
var showCatalog = function () {
  $("#catalogContainer").removeClass("hidden");
  $("#orderContainer").addClass("hidden");
};
var finishOrder = function() {
  cart([]);
  hideCartDetails();
  showCatalog();
  $("#finishOrderModal").modal('show');
};
```

正如我们在先前的方法中所做的，我们给想要显示和隐藏的元素添加和删除隐藏类。`finishOrder`方法移除购物车中的所有商品，因为我们的订单已完成；隐藏购物车并显示目录。它还显示一个模态框，向用户确认订单已完成。

![订单模板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_02_04.jpg)

订单详情模板

## `finish-order-modal`模板

最后一个模板是告诉用户订单已完成的模态框：

```js
<script type="text/html" id="finish-order-modal">
  <div class="modal fade" id="finishOrderModal">
    <div class="modal-dialog">
            <div class="modal-content">
        <div class="modal-body">
        <h2>Your order has been completed!</h2>
        </div>
        <div class="modal-footer">
          <div class="form-group">
            <div class="col-sm-12">
              <button type="submit" class="btn btn-success" data-dismiss="modal">Continue Shopping
              </button>
            </div>
          </div>
        </div>
      </div><!-- /.modal-content -->
    </div><!-- /.modal-dialog -->
  </div><!-- /.modal -->
</script>
```

以下截图显示了输出：

![完成订单模板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_02_05.jpg)

# 用 if 和 ifnot 绑定处理模板

你已经学会如何使用 jQuery 和 Bootstrap 的强大功能来显示和隐藏模板。这非常好，因为你可以在任何你想要的框架中使用这个技术。这种类型的代码的问题在于，由于 jQuery 是一个 DOM 操作库，你需要引用要操作的元素。这意味着你需要知道想要应用操作的元素。Knockout 给我们一些绑定来根据我们视图模型的值来隐藏和显示元素。让我们更新`show`和`hide`方法以及模板。

将两个控制变量添加到你的视图模型中，并在`return`语句中公开它们。

```js
var visibleCatalog = ko.observable(true);
var visibleCart = ko.observable(false);
```

现在更新`show`和`hide`方法：

```js
var showCartDetails = function () {
  if (cart().length > 0) {
    visibleCart(true);
  }
};

var hideCartDetails = function () {
  visibleCart(false);
};

var showOrder = function () {
  visibleCatalog(false);
};

var showCatalog = function () {
  visibleCatalog(true);
};
```

我们可以欣赏到代码变得更易读和有意义。现在，更新`cart`模板、`catalog`模板和`order`模板。

在`index.html`中，考虑这一行：

```js
<div class="row" id="catalogContainer">
```

用以下行替换它：

```js
<div class="row" data-bind="if: visibleCatalog">
```

然后考虑以下行：

```js
<div id="cartContainer" class="col-xs-6 well hidden" data-bind="template:{name:'cart'}"></div>
```

用这个来替换它：

```js
<div class="col-xs-6" data-bind="if: visibleCart">
  <div class="well" data-bind="template:{name:'cart'}"></div>
</div>
```

重要的是要知道，if 绑定和模板绑定不能共享相同的`data-bind`属性。这就是为什么在这个模板中我们从一个元素转向两个嵌套元素。换句话说，这个例子是不允许的：

```js
<div class="col-xs-6" data-bind="if:visibleCart, template:{name:'cart'}"></div>
```

最后，考虑这一行：

```js
<div class="row hidden" id="orderContainer" data-bind="template:{name:'order'}">
```

用这个来替换它：

```js
<div class="row" data-bind="ifnot: visibleCatalog">
  <div data-bind="template:{name:'order'}"></div>
</div>
```

通过我们所做的更改，显示或隐藏元素现在取决于我们的数据而不是我们的 CSS。这样做要好得多，因为现在我们可以使用`if`和`ifnot`绑定来显示和隐藏任何我们想要的元素。

让我们粗略地回顾一下我们现在的文件：

我们有我们的`index.html`文件，其中包含主容器、模板和库：

```js
<!DOCTYPE html>
<html>
<head>
  <title>KO Shopping Cart</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" type="text/css" href="css/bootstrap.min.css">
  <link rel="stylesheet" type="text/css" href="css/style.css">
</head>
<body>

<div class="container-fluid">
  <div class="row" data-bind="if: visibleCatalog">
    <div class="col-xs-12" data-bind="template:{name:'header'}"></div>
    <div class="col-xs-6" data-bind="template:{name:'catalog'}"></div>
    <div class="col-xs-6" data-bind="if: visibleCart">
      <div class="well" data-bind="template:{name:'cart'}"></div>
    </div>
  </div>
  <div class="row" data-bind="ifnot: visibleCatalog">
    <div data-bind="template:{name:'order'}"></div>
  </div>
  <div data-bind="template: {name:'add-to-catalog-modal'}"></div>
  <div data-bind="template: {name:'finish-order-modal'}"></div>
</div>

<!-- templates -->
<script type="text/html" id="header"> ... </script>
<script type="text/html" id="catalog"> ... </script>
<script type="text/html" id="add-to-catalog-modal"> ... </script>
<script type="text/html" id="cart-widget"> ... </script>
<script type="text/html" id="cart-item"> ... </script>
<script type="text/html" id="cart"> ... </script>
<script type="text/html" id="order"> ... </script>
<script type="text/html" id="finish-order-modal"> ... </script>
<!-- libraries -->
<script type="text/javascript" src="img/jquery.min.js"></script>
<script type="text/javascript" src="img/bootstrap.min.js"></script>
<script type="text/javascript" src="img/knockout.debug.js"></script>
<script type="text/javascript" src="img/product.js"></script>
<script type="text/javascript" src="img/cartProduct.js"></script>
<script type="text/javascript" src="img/viewmodel.js"></script>
</body>
</html>
```

我们还有我们的`viewmodel.js`文件：

```js
var vm = (function () {
  "use strict";
  var visibleCatalog = ko.observable(true);
  var visibleCart = ko.observable(false);
  var catalog = ko.observableArray([...]);
  var cart = ko.observableArray([]);
  var newProduct = {...};
  var totalItems = ko.computed(function(){...});
  var grandTotal = ko.computed(function(){...});
  var searchTerm = ko.observable("");
  var filteredCatalog = ko.computed(function () {...});
  var addProduct = function (data) {...};
  var addToCart = function(data) {...};
  var removeFromCart = function (data) {...};
  var showCartDetails = function () {...};
  var hideCartDetails = function () {...};
  var showOrder = function () {...};
  var showCatalog = function () {...};
  var finishOrder = function() {...};
  return {
    searchTerm: searchTerm,
    catalog: filteredCatalog,
    cart: cart,
    newProduct: newProduct,
    totalItems:totalItems,
    grandTotal:grandTotal,
    addProduct: addProduct,
    addToCart: addToCart,
    removeFromCart:removeFromCart,
    visibleCatalog: visibleCatalog,
    visibleCart: visibleCart,
    showCartDetails: showCartDetails,
    hideCartDetails: hideCartDetails,
    showOrder: showOrder,
    showCatalog: showCatalog,
    finishOrder: finishOrder
  };
})();
ko.applyBindings(vm);
```

在调试时将视图模型全局化是很有用的。在生产环境中这样做并不是好的实践，但在调试应用程序时是很好的。

```js
Window.vm = vm;
```

现在你可以从浏览器调试器或 IDE 调试器轻松访问你的视图模型。

除了在第一章中编写的产品模型之外，我们还创建了一个名为`CartProduct`的新模型：

```js
var CartProduct = function (product, units) {
  "use strict";
  var _product = product,
    _units = ko.observable(units);
  var subtotal = ko.computed(function(){...});
  var addUnit = function () {...};
  var removeUnit = function () {...};
  return {
    product: _product,
    units: _units,
    subtotal: subtotal,
    addUnit : addUnit,
    removeUnit: removeUnit
  };
};
```

你已经学会了如何使用 Knockout 管理模板，但也许你已经注意到，在`index.html`文件中拥有所有模板并不是最佳的方法。我们将讨论两种机制。第一种更像是自制的，而第二种是许多 Knockout 开发者使用的外部库，由 Jim Cowart 创建，名为*Knockout.js-External-Template-Engine*（[`github.com/ifandelse/Knockout.js-External-Template-Engine`](https://github.com/ifandelse/Knockout.js-External-Template-Engine)）。

# 使用 jQuery 管理模板

由于我们希望从不同的文件加载模板，让我们将所有的模板移到一个名为`views`的文件夹中，并且每个模板都用一个文件表示。每个文件的名称将与模板的 ID 相同。因此，如果模板的 ID 是`cart-item`，那么文件应该被称为`cart-item.html`，并且将包含完整的`cart-item`模板：

```js
<script type="text/html" id="cart-item"></script>
```

![使用 jQuery 管理模板](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_02_06.jpg)

包含所有模板的 views 文件夹

现在在`viewmodel.js`文件中，删除最后一行（`ko.applyBindings(vm)`）并添加此代码：

```js
var templates = [
  'header',
  'catalog',
  'cart',
  'cart-item',
  'cart-widget',
  'order',
  'add-to-catalog-modal',
  'finish-order-modal'
];

var busy = templates.length;
templates.forEach(function(tpl){
  "use strict";
  $.get('views/'+ tpl + '.html').then(function(data){
    $('body').append(data);
    busy--;
    if (!busy) {
      ko.applyBindings(vm);
    }
  });
});
```

此代码获取我们需要的所有模板并将它们附加到 body。一旦所有模板都加载完成，我们就调用`applyBindings`方法。我们应该这样做，因为我们是异步加载模板，我们需要确保当所有模板加载完成时绑定我们的视图模型。

这样做已足以使我们的代码更易维护和易读，但如果我们需要处理大量的模板，仍然存在问题。而且，如果我们有嵌套文件夹，列出所有模板就会变成一个头疼的事情。应该有更好的方法。

# 使用`koExternalTemplateEngine`管理模板

我们已经看到了两种加载模板的方式，它们都足以管理少量的模板，但当代码行数开始增长时，我们需要一些允许我们忘记模板管理的东西。我们只想调用一个模板并获取内容。

为此目的，Jim Cowart 的库`koExternalTemplateEngine`非常完美。这个项目在 2014 年被作者放弃，但它仍然是一个我们在开发简单项目时可以使用的好库。在接下来的章节中，您将学习更多关于异步加载和模块模式的知识，我们将看到其他目前正在维护的库。

我们只需要在`js/vendors`文件夹中下载库，然后在我们的`index.html`文件中链接它，放在 Knockout 库的下面即可。

```js
<script type="text/javascript" src="img/knockout.debug.js"></script>
<script type="text/javascript" src="img/koExternalTemplateEngine_all.min.js"></script>
```

现在你应该在`viewmodel.js`文件中进行配置。删除模板数组和`foreach`语句，并添加以下三行代码：

```js
infuser.defaults.templateSuffix = ".html";
infuser.defaults.templateUrl = "views";
ko.applyBindings(vm);
```

这里，`infuser`是一个我们用来配置模板引擎的全局变量。我们应该指示我们的模板将具有哪个后缀名，以及它们将在哪个文件夹中。

我们不再需要`<script type="text/html" id="template-id"></script>`标签，所以我们应该从每个文件中删除它们。

现在一切应该都正常了，我们成功所需的代码并不多。

KnockoutJS 有自己的模板引擎，但是您可以看到添加新的引擎并不困难。如果您有其他模板引擎的经验，如 jQuery Templates、Underscore 或 Handlebars，只需将它们加载到您的`index.html`文件中并使用它们，没有任何问题。这就是 Knockout 的美丽之处，您可以使用任何您喜欢的工具。

你在本章学到了很多东西，对吧？

+   Knockout 给了我们 CSS 绑定，根据表达式激活和停用 CSS 类。

+   我们可以使用 style 绑定向元素添加 CSS 规则。

+   模板绑定帮助我们管理已在 DOM 中加载的模板。

+   使用`foreach`绑定可以在集合上进行迭代。

+   在`foreach`内部，Knockout 给了我们一些魔术变量，如`$parent`、`$parents`、`$index`、`$data`和`$root`。

+   我们可以在`foreach`绑定中使用`as`绑定来为每个元素获取别名。

+   我们可以只使用 jQuery 和 CSS 来显示和隐藏内容。

+   我们可以使用`if`、`ifnot`和`visible`绑定来显示和隐藏内容。

+   jQuery 帮助我们异步加载 Knockout 模板。

+   您可以使用`koExternalTemplateEngine`插件以更有效的方式管理模板。这个项目已经被放弃了，但它仍然是一个很好的解决方案。

# 摘要

在本章中，您已经学会了如何使用共享相同视图模型的模板来拆分应用程序。现在我们知道了基础知识，扩展应用程序会很有趣。也许我们可以尝试创建产品的详细视图，或者给用户选择订单发送位置的选项。您将在接下来的章节中学习如何做这些事情，但是只使用我们现在拥有的知识进行实验会很有趣。

在下一章中，我们将学习如何扩展 Knockout 行为。这将有助于格式化数据并创建可重用的代码。您将学习自定义绑定和组件是什么，以及它们如何帮助我们编写可重用和优雅的代码。

本章的代码在 GitHub 上：

[`github.com/jorgeferrando/knockout-cart/archive/chapter2.zip`](https://github.com/jorgeferrando/knockout-cart/archive/chapter2.zip)


# 第三章：自定义绑定和组件

通过前两章学到的所有概念，你可以构建出大部分真实世界中遇到的应用程序。当然，如果只凭借这两章的知识编写代码，你应该非常整洁，因为你的代码会变得越来越庞大，维护起来会很困难。

有一次一个谷歌工程师被问及如何构建大型应用程序。他的回答既简短又雄辩：*别*。不要编写大型应用程序。相反，编写小型应用程序，小型的隔离代码片段互相交互，并用它们构建一个大系统。

我们如何编写小型、可重用和独立的代码片段来扩展 Knockout 的功能？答案是使用自定义绑定和组件。

# 自定义绑定

我们知道什么是绑定，它是我们写在`data-bind`属性中的一切。我们有一些内置的绑定。点击和值是其中的两个。但我们可以编写我们自己的自定义绑定，以整洁的方式扩展我们应用程序的功能。

编写自定义绑定非常简单。它有一个基本结构，我们应该始终遵循：

```js
ko.bindingHandlers.yourBindingName = {
  init: function(element, valueAccessor, allBindings, viewModel, bindingContext) {
    // This will be called when the binding is first applied to an element
    // Set up any initial state, event handlers, etc. here
  },
  update: function(element, valueAccessor, allBindings, viewModel, bindingContext) {
    // This will be called once when the binding is first applied to an element,
    // and again whenever any observables/computeds that are accessed change
    // Update the DOM element based on the supplied values here.
  }
};
```

Knockout 有一个内部对象叫做`bindingHandlers`。我们可以用自定义绑定扩展这个对象。我们的绑定应该有一个名称，在`bindingHandlers`对象内用来引用它。我们的自定义绑定是一个具有两个函数`init`和`update`的对象。有时你应该只使用其中一个，有时两个都要用。

在`init`方法中，我们应该初始化绑定的状态。在`update`方法中，我们应该设置代码以在其模型或值更新时更新绑定。这些方法给了我们一些参数来执行这个任务：

+   `element`：这是与绑定有关的 DOM 元素。

+   `valueAccessor`：这是绑定的值。通常是一个函数或可观察对象。使用`ko.unwrap`来获取值更安全，比如`var value = ko.unwrap(valueAccessor());`。

+   `allBindings`：这是一个对象，你可以用它来访问其他绑定。你可以使用`allBindings.get('name')`来获取一个绑定，或使用`allBindings.has('name')`来查询绑定是否存在。

+   `viewModel`：在 Knockout 3.x 中已弃用。你应该使用`bindingContext.$data`或`bindigContext.$rawData`代替。

+   `bindingContext`：使用绑定上下文，我们可以访问熟悉的上下文对象，如`$root`、`$parents`、`$parent`、`$data`或`$index`来在不同的上下文中导航。

我们可以为许多事物使用自定义绑定。例如，我们可以自动格式化数据（货币或日期是明显的例子），或增加其他绑定的语义含义。给绑定起名叫`toggle`比仅仅设置`click`和`visible`绑定来显示和隐藏元素更加描述性。

![自定义绑定](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_03_01.jpg)

新的文件夹结构与自定义绑定和组件

## 这个 toggle 绑定

要向我们的应用程序添加新的自定义绑定，我们将创建一个名为`custom`的新文件夹，放在我们的`js`文件夹中。然后，我们将创建一个名为`koBindings.js`的文件，并将其链接到我们的`index.html`文件中，放在我们的模板引擎的下方：

```js
<script type="text/javascript" src="img/koExternalTemplateEngine_all.min.js"></script>
<script type="text/javascript" src="img/koBindings.js"></script>
```

我们的第一个自定义绑定将被称为`toggle`。我们将使用此自定义绑定来更改布尔变量的值。通过这种行为，我们可以显示和隐藏元素，即我们的购物车。只需在`koBindings.js`文件的开头编写以下代码。

```js
ko.bindingHandlers.toggle = {
  init: function (element, valueAccessor) {
    var value = valueAccessor();
    ko.applyBindingsToNode(element, {
      click: function () {
          value(!value());
      }
    });
  }
};
```

在这种情况下，我们不需要使用`update`方法，因为我们在初始化绑定时设置了所有行为。我们使用`ko.applyBingidsToNode`方法将`click`函数链接到元素上。`applyBindingsToNode`方法具有与`applyBindings`相同的行为，但我们设置了一个上下文，一个从 DOM 中获取的节点，其中应用了绑定。我们可以说`applyBindings`是`applyBindingsToNode($('body'), viewmodel)`的别名。

现在我们可以在我们的应用程序中使用这个绑定。更新`views/header.html`模板中的`showCartDetails`按钮。删除以下代码：

```js
<button class="btn btn-primary btn-sm" data-bind="click:showCartDetails, css:{disabled:cart().length  < 1}">Show Cart Details
</button>
```

更新以下按钮的代码：

```js
<button class="btn btn-primary btn-sm" data-bind="toggle:visibleCart, css:{disabled:cart().length  < 1}">
  <span data-bind="text: visibleCart()?'Hide':'Show'">
  </span> Cart Details
</button>
```

现在我们不再需要`showCartDetails`和`hideCartDetails`方法了，我们可以直接使用`toggle`绑定攻击`visibleCart`变量。

通过这个简单的绑定，我们已经删除了代码中的两个方法，并创建了一个可重用的代码，不依赖于我们的购物车视图模型。因此，您可以在任何想要的项目中重用 toggle 绑定，因为它没有任何外部依赖项。

我们还应该更新`cart.html`模板：

```js
<button type="button" class="close pull-right" data-bind="toggle:visibleCart"><span>&times;</span></button>
```

一旦我们进行了此更新，我们意识到不再需要使用`hideCartDetails`。要彻底删除它，请按照以下步骤操作：

1.  在`finishOrder`函数中，删除以下行：

    ```js
    hideCartDetails();
    ```

1.  添加以下行：

    ```js
    visibleCart(false);
    ```

没有必要保留只管理一行代码的函数。

## 货币绑定

自定义绑定提供的另一个有用的工具是格式化应用于节点数据的选项。例如，我们可以格式化购物车的货币字段。

在 toggle 绑定的下方添加以下绑定：

```js
ko.bindingHandlers.currency = {
  symbol: ko.observable('$'),
  update: function(element, valueAccessor, allBindingsAccessor){
    return ko.bindingHandlers.text.update(element,function(){
      var value = +(ko.unwrap(valueAccessor()) || 0),
        symbol = ko.unwrap(allBindingsAccessor().symbol !== undefined? allBindingsAccessor().symbol: ko.bindingHandlers.currency.symbol);
      return symbol + value.toFixed(2).replace(/(\d)(?=(\d{3})+\.)/g, "$1,");
    });
  }
};
```

在这里，我们不需要初始化任何内容，因为初始状态和更新行为是相同的。必须要知道，当`init`和`update`方法执行相同的操作时，只需使用`update`方法。

在这种情况下，我们将返回我们想要的格式的数字。首先，我们使用内置绑定称为 `text` 来更新我们元素的值。这个绑定获取元素和一个函数，指示如何更新此元素内部的文本。在本地变量 `value` 中，我们将写入 `valueAccessor` 内部的值。记住 `valueAccessor` 可以是一个 observable；这就是为什么我们使用 `unwrap` 方法。我们应该对 `symbol` 绑定执行相同的操作。`symbol` 是我们用来设置货币符号的另一个绑定。我们不需要定义它，因为此绑定没有行为，只是一个写/读绑定。我们可以使用 `allBindingsAccesor` 访问它。最后，我们返回连接两个变量的值，并设置一个正则表达式将值转换为格式化的货币。

我们可以更新 `catalog` 和 `cart` 模板中的价格绑定。

```js
<td data-bind="currency:price, symbol:'€'"></td>
```

我们可以设置我们想要的符号，价格将被格式化为：€100，或者如果我们设置符号为 `$` 或空，则将看到 `$100`（如果价格值为 100）。

![货币绑定](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_03_02.jpg)

货币自定义绑定

注意观察如何轻松地添加越来越多有用的绑定以增强 Knockout 的功能。

![货币绑定](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_03_03.jpg)

使用 $root 上下文显示的容器进行调试。

# 创建一个调试绑定 – toJSON 绑定。

当我们开发我们的项目时，我们会犯错误并发现意外的行为。Knockout 视图模型很难阅读，因为我们没有普通对象，而是 observables。因此，也许在开发过程中，拥有一个显示视图模型状态的方法和容器可能很有用。这就是为什么我们要构建一个 `toJSON` 绑定，将我们的视图模型转换为一个普通的 JSON 对象，我们可以在屏幕上或控制台中显示。

```js
ko.bindingHandlers.toJSON = {
  update: function(element, valueAccessor){
    return ko.bindingHandlers.text.update(element,function(){
      return ko.toJSON(valueAccessor(), null, 2);
    });
  }
};
```

我们已经使用 `ko.toJSON` 对象将我们获取的值转换为 JSON 对象。

此函数具有与原生 `JSON.stringify` 函数相同的接口。它将三个参数作为参数：

第一个参数是我们想要转换为普通 JSON 对象的对象。

第二个是替换参数。它可以是一个函数或一个数组。它应该返回应添加到 JSON 字符串中的值。有关替换参数的更多信息，请参阅以下链接：

[`developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Using_native_JSON#The_replacer_parameter`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Using_native_JSON#The_replacer_parameter)

最后一个表示应该应用于格式化结果的空格。因此，在这种情况下，我们说我们将使用 `valueAccesor()` 方法中包含的对象，不使用替换函数，并且将缩进两个空格。 

要看到它的作用，我们应该将此行放在具有 `container-fluid` 类的元素的末尾：

```js
<pre class="well well-lg" data-bind="toJSON: $root"></pre>
```

现在在这个`<div>`标签里，我们可以将`$root`上下文视为一个 JSON 对象。`$root`上下文是我们整个 Knockout 上下文的顶部，所以我们可以在这个框中看到我们所有的视图模型。

为了让这在没有原生 JSON 序列化程序的老浏览器上工作（例如，IE 7 或更早版本），你还必须引用 `json2.js` 库。

[`github.com/douglascrockford/JSON-js/blob/master/json2.js`](https://github.com/douglascrockford/JSON-js/blob/master/json2.js)

你可以在这个链接中了解更多关于 Knockout 如何将 observables 转换为普通 JSON：[`knockoutjs.com/documentation/json-data.html`](http://knockoutjs.com/documentation/json-data.html)

## 通过我们的绑定语义化

有时候，我们写的代码对我们来说似乎很简单，但当我们仔细看时，我们意识到它并不简单。例如，在 Knockout 中，我们有内置的 visible 绑定。很容易认为如果我们想要隐藏某些东西，我们只需写：`data-bind="visible:!isVisible"`，并且每次我们想要隐藏某些东西时都写这个。这并不够清晰。我们想要表达什么？这个元素应该默认隐藏吗？当变量不可见时它应该可见吗？

最好的方法是写一个名为`hidden`的绑定。如果你有一个`hidden`绑定，你可以写`data-bind="hidden: isHidden;"`，这听起来更清晰，不是吗？这个绑定很简单，让我们看看以下的代码：

```js
ko.bindingHandlers.hidden = {
  update: function (element, valueAccessor) {
    var value = ! ko.unwrap(valueAccessor());
    ko.bindingHandlers.visible.update(element, function () { 
      return value; 
    });
  }
};
```

我们只是使用`visible`类型的`bindingHandler`来改变`valueAccessor`方法的值。所以我们创建了一个更加有含义的绑定。

看看 Knockout 有多么强大和可扩展。我们可以构建越来越多的行为。例如，如果我们想要练习自定义绑定，我们可以创建一个接收照片数组而不仅仅是一张照片的自定义图像绑定，然后我们可以创建一个轮播。我们可以创建我们自己的链接绑定，帮助我们在我们的应用程序中导航。可能性是无限的。

现在，让我们看看如何将一个 jQuery 插件集成到我们的绑定中。

## 将一个 jQuery 插件包装成自定义绑定

Knockout 和 jQuery 兼容。实际上，没有必要将一个 jQuery 插件包装成一个绑定。它会工作，因为 Knockout 和 jQuery 是兼容的。然而，正如我们之前提到的，jQuery 是一个 DOM 操作库，所以我们需要设置一个 ID 来定位我们想要应用插件的元素，这将创建一个依赖关系。如果我们将插件包装在一个自定义绑定中，我们可以通过元素和`valueAccessor`参数访问元素和它的值，并且我们可以通过`allBindings`对象传递我们需要的一切。

我们将集成一个简单的插件叫做`iCheck`，这将为我们的复选框提供一个很酷的主题。

首先下载`iCheck`插件并将`iCheck.js`文件放入`js`文件夹中。然后将`skins`文件夹保存到`css`文件夹中。`iCheck`插件的下载链接如下：

[`github.com/fronteed/iCheck/archive/2.x.zip`](https://github.com/fronteed/iCheck/archive/2.x.zip)

使用`index.html`文件链接`css`和`javascript`文件：

```js
<link rel="stylesheet" type="text/css" href="css/iCheck/skins/all.css"><!-- set it just below bootstap -->
<script type="text/javascript" src="img/icheck.js">
</script><!-- set it just below jquery -->
```

现在我们需要初始化插件并更新元素的值。在这种情况下，`init`和`update`方法是不同的。因此，我们需要编写当绑定开始工作时发生的情况以及当值更新时发生的情况。

.

![将 jQuery 插件封装到自定义绑定中](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_03_04.jpg)

将 iCheck 添加到我们的项目中

`iCheck`插件仅通过给我们的复选框提供样式来工作。现在的问题是我们需要将这个插件与我们的元素链接起来。

`iCheck`的基本行为是`$('input [type=checkbox]').icheck(config)`。当复选框的值更改时，我们需要更新我们绑定的值。幸运的是，`iCheck`有事件来检测值何时更改。

这个绑定只会管理`iCheck`的行为。这意味着可观察值的值将由另一个绑定处理。

使用`checked`绑定是有道理的。分别使用这两个绑定，以便`iCheck`绑定管理呈现，而`checked`绑定管理值行为。

将来，我们可以移除`icheck`绑定或者使用另一个绑定来管理呈现，复选框仍将正常工作。

按照我们在本章第一部分看到的`init`约定，我们将初始化插件并在`init`方法中设置事件。在`update`方法中，我们将在由`checked`绑定处理的可观察值更改时更新复选框的值。

注意我们使用`allBindingsAccesor`对象来获取已检查绑定的值：

```js
ko.bindingHandlers.icheck = {
  init: function (element, valueAccessor, allBindingsAccessor) {
    var checkedBinding = allBindingsAccessor().checked;
    $(element).iCheck({
      checkboxClass: 'icheckbox_minimal-blue',
      increaseArea: '10%'
    });
    $(element).on('ifChanged', function (event) {
      checkedBinding(event.target.checked);
    });
  },
  update: function (element,valueAccessor, allBindings) {
    var checkedBinding = allBindingsAccessor().checked;
    var status = checked?'check':'uncheck';
    $(element).iCheck(status);
  }
};
```

现在我们可以使用这个来以隔离的方式在我们的应用程序中创建酷炫的复选框。我们将使用这个插件来隐藏和显示我们的搜索框。

将此添加到`header.html`模板中**显示购物车详情** / **隐藏购物车详情**按钮的下方：

```js
<input type="checkbox" data-bind="icheck, checked:showSearchBar"/> Show Search options
```

然后转到`catalog.html`文件，在搜索栏中添加一个可见的绑定，如下所示：

```js
<div class="input-group" data-bind="visible:showSearchBar">
  <span class="input-group-addon">
    <i class="glyphicon glyphicon-search"></i> Search
  </span>
  <input type="text" class="form-control" data-bind="textInput:searchTerm">
</div>
```

将变量添加到视图模型中，并在`return`语句中设置它，就像我们对所有其他变量所做的那样：

```js
var showSearchBar = ko.observable(true);
```

现在你可以看到一个酷炫的复选框，允许用户显示和隐藏搜索栏：

![将 jQuery 插件封装到自定义绑定中](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_03_05.jpg)

## 组件 - 隔离的视图模型

自定义绑定非常强大，但有时我们需要更强大的行为。我们想要创建一个对应用程序的其余部分表现为黑匣子的隔离元素。这些类型的元素被称为**组件**。组件有自己的视图模型和模板。它还有自己的方法和事件，我们也可以说它本身就是一个应用程序。当然，我们可以使用依赖注入将我们的组件与我们的主应用程序视图模型链接起来，但是组件可以与给它正确数据的每个应用程序一起工作。

我们可以构建诸如表格、图表和您能想象到的一切复杂组件。要学习如何构建一个组件，您可以构建一个简单的组件。我们将创建一个`add-to-cart`按钮。这是一个连接我们的目录和购物车的组件，所以通过这个组件我们可以隔离我们的目录和我们的购物车。它们将通过这个组件连接，这个组件只是一个按钮，接收购物车和目录中的商品，并且将有将商品插入到购物车的所有逻辑。这是非常有用的，因为购物车不需要关心插入的商品，目录也不需要。另外，如果您需要在插入商品之前或之后执行一些逻辑，您可以在一个隔离范围内执行。

![组件-隔离视图模型](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_03_06.jpg)

组件有与主应用程序交互的隔离视图模型

一个组件的基本结构如下：

```js
ko.components.register('component-name', {
  viewModel: function(params) {
    // Data: values you want to initilaize
    this.chosenValue = params.value;
    this.localVariable = ko.observable(true);
    // Behaviors: functions
    this.externalBehaviour = params.externalFunction;
    this.behaviour = function () { ... }
  },
  template:
    '<div>All html you want</div>'
});
```

使用这个模式的帮助，我们将构建我们的`add-to-cart`按钮。在`custom`文件夹内创建一个名为`components.js`的文件，并写入以下内容：

```js
ko.components.register('add-to-cart-button', {
  viewModel: function(params) {
    this.item = params.item;
    this.cart = params.cart;

    this.addToCart = function() {
      var data = this.item;
      var tmpCart = this.cart();
      var n = tmpCart.length;
      var item = null;

      while(n--) {
        if (tmpCart[n].product.id() === data.id()) {
          item = tmpCart[n];
        }
      }

      if (item) {
        item.addUnit();
      } else {
        item = new CartProduct(data,1);
        tmpCart.push(item);
        item.product.decreaseStock(1);
      }

      this.cart(tmpCart);
    };
  },
  template:
    '<button class="btn btn-primary" data-bind="click:addToCart">
       <i class="glyphicon glyphicon-plus-sign"></i> Add
    </button>'
});
```

我们将要添加到购物车的商品和购物车本身作为参数发送，并定义`addToCart`方法。这个方法是我们在视图模型中使用的，但现在被隔离在这个组件内部，所以我们的代码变得更清晰了。模板是我们在目录中拥有的用于添加商品的按钮。

现在我们可以将我们的目录行更新如下：

```js
<tbody data-bind="{foreach:catalog}">
  <tr data-bind="style:{color:stock() < 5?'red':'black'}">
    <td data-bind="{text:name}"></td>
    <td data-bind="{currency:price, symbol:''}"></td>
    <td data-bind="{text:stock}"></td>
    <td>
      <add-to-cart-button params= "{cart: $parent.cart, item: $data}">
      </add-to-cart-button>
    </td>
  </tr>
</tbody>
```

## 高级技术

在这一部分，我们将讨论一些高级技术。我们并不打算将它们添加到我们的项目中，因为没有必要，但知道如果我们的应用程序需要时可以使用这些方法是很好的。

### 控制后代绑定

如果我们的自定义绑定有嵌套绑定，我们可以告诉我们的绑定是否 Knockout 应该应用绑定，或者我们应该控制这些绑定如何被应用。 我们只需要在`init`方法中返回`{ controlsDescendantBindings: true }`。

```js
ko.bindingHandlers.allowBindings = {
  init: function(elem, valueAccessor) {
    return { controlsDescendantBindings: true };
  }
};
```

这段代码告诉 Knockout，名为`allowBindings`的绑定将处理所有后代绑定：

```js
<div data-bind="allowBindings: true">
  <!-- This will display 'New content' -->
  <div data-bind="text: 'New content'">Original content</div>
</div>
<div data-bind="allowBindings: false">
  <!-- This will display 'Original content' -->
  <div data-bind="text: 'New content'">Original content</div>
</div>
```

如果我们想用新属性扩展上下文，我们可以用新值扩展`bindingContext`属性。然后我们只需要使用`ko.applyBindingsToDescendants`来更新其子项的视图模型。当然我们应该告诉绑定它应该控制后代绑定。如果我们不这样做，它们将被更新两次。

```js
ko.bindingHandlers.withProperties = {
  init: function(element, valueAccessor, allBindings, viewModel, bindingContext) {
    var myVM = { parentValues: valueAccessor, myVar: 'myValue'};
    var innerBindingContext = bindingContext.extend(myVM);
    ko.applyBindingsToDescendants(innerBindingContext, element);
    return { controlsDescendantBindings: true };
  }
};
```

这里我们并不创建一个子上下文。我们只是扩展父上下文。如果我们想创建子上下文来管理后代节点，并且能够使用`$parentContext`魔术变量来访问我们的父上下文，我们需要使用`createChildContext`方法来创建一个新上下文。

```js
var childBindingContext = bindingContext.createChildContext(
  bindingContext.$rawData,
  null, //alias of descendant item ($data magic variable)
  function(context) {
    //manage your context variables
    ko.utils.extend(context, valueAccessor());
  });
ko.applyBindingsToDescendants(childBindingContext, element);
return { controlsDescendantBindings: true }; //Important to not bind twice
```

现在我们可以在子节点内部使用这些魔术变量：

```js
<div data-bind="withProperties: { displayMode: 'twoColumn' }">
  The outer display mode is <span data-bind="text: displayMode"></span>.
  <div data-bind="withProperties: { displayMode: 'doubleWidth' }">
    The inner display mode is <span data-bind="text: displayMode"></span>, but I haven't forgotten that the outer display mode is <span data-bind="text: $parentContext.displayMode"></span>.
  </div>
</div>
```

通过修改绑定上下文和控制后代绑定，您将拥有一个强大而先进的工具来创建自己的自定义绑定机制。

### 使用虚拟元素

**虚拟元素**是允许使用 Knockout 注释的自定义绑定。您只需要告诉 Knockout 我们的绑定是允许虚拟的。

```js
ko.virtualElements.allowedBindings.myBinding = true;
ko.bindingHandlers.myBinding = {
  init: function () { ... },
  update: function () { ... }
};
```

要将我们的绑定添加到允许的虚拟元素中，我们写下这个：

```js
<!-- ko myBinding:param -->
<div></div>
<!-- /ko
```

虚拟元素具有操作 DOM 的 API。您可以使用 jQuery 操作虚拟元素，因为 Knockout 的一个优点是它与 DOM 库完全兼容，但是我们在 Knockout 文档中有完整的虚拟元素 API。这个 API 允许我们执行在实现控制流绑定时所需的类型的转换。有关虚拟元素的自定义绑定的更多信息，请参考以下链接：

[`knockoutjs.com/documentation/custom-bindings-for-virtual-elements.html`](http://knockoutjs.com/documentation/custom-bindings-for-virtual-elements.html)

### 在绑定之前预处理数据

我们能够在绑定应用之前预处理数据或节点。这在显示数据之前格式化数据或向我们的节点添加新类或行为时非常有用。您也可以设置默认值，例如。我们只需要使用`preprocess`和`preproccessNode`方法。使用第一个方法，我们可以操纵我们绑定的值。使用第二个方法，我们可以操纵我们绑定的 DOM 元素（模板），如下所示：

```js
ko.bindingHandlers.yourBindingHandler.preprocess = function(value) {
  ...
};
```

我们可以使用钩子`preprocessNode`操纵 DOM 节点。每当我们用 Knockout 处理 DOM 元素时，都会触发此钩子。它不绑定到一个具体的绑定。它对所有已处理的节点触发，因此您需要一种机制来定位要操纵的节点。

```js
ko.bindingProvider.instance.preprocessNode = function(node) { 
  ...
};
```

# 摘要

在本章中，您已经学习了如何使用自定义绑定和组件扩展 Knockout。自定义绑定扩展了我们可以在`data-bind`属性中使用的选项，并赋予了我们使代码更可读的能力，将 DOM 和数据操作隔离在其中。另一方面，我们有组件。组件有它们自己的视图模型。它们本身就是一个孤立的应用程序。它们帮助我们通过彼此交互的小代码片段构建复杂的应用程序。

现在您已经知道如何将应用程序拆分成小代码片段，在下一章中，您将学习如何以不显眼的方式使用事件以及如何扩展可观察对象以增加 Knockout 的性能和功能。

要下载本章的代码，请转到 GitHub 存储库[`github.com/jorgeferrando/knockout-cart/tree/chapter3`](https://github.com/jorgeferrando/knockout-cart/tree/chapter3)。
