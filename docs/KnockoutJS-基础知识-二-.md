# KnockoutJS 基础知识（二）

> 原文：[`zh.annas-archive.org/md5/2823CCFFDCBA26955DFD8A04E5A226C2`](https://zh.annas-archive.org/md5/2823CCFFDCBA26955DFD8A04E5A226C2)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：管理 KnockoutJS 事件

我们的应用程序与用户之间的交互是我们需要解决的最重要问题。在过去的三章中，我们一直专注于业务需求，现在是时候考虑如何使最终用户更容易使用我们的应用程序了。

事件驱动编程是一种强大的范式，它能让我们更好地隔离我们的代码。KnockoutJS 给了我们几种处理事件的方式。如果我们想使用声明范式，可以使用点击绑定或者事件绑定。

有两种不同的方式来声明事件。声明范式说我们可以在我们的 HTML 中写 JavaScript 和自定义标签。另一方面，命令范式告诉我们应该将 JavaScript 代码与 HMTL 标记分开。为此，我们可以使用 jQuery 来编写不显眼的事件，也可以编写自定义事件。我们可以使用 `bindingHandlers` 来包装自定义事件，以便在我们的应用程序中重复使用它们。

# 事件驱动编程

当我们使用顺序编程来编写我们的应用程序时，我们会准确地知道我们的应用程序将会如何行为。通常情况下，我们在我们的应用程序与外部代理没有交互时使用这种编程范式。在网页开发中，我们需要使用事件驱动的编程范式，因为最终用户会主导应用程序的流程。

即使我们之前还没谈论过事件，我们知道它们是什么，因为我们一直在使用网页开发中最重要的事件之一，即点击事件。

用户可以触发许多事件。正如我们之前提到的，点击事件是用户可以在键盘上按键的地方；我们还可以从计算机那里接收事件，比如就绪事件，以通知我们 DOM 元素都已加载完毕。现在，如果我们的屏幕是可以触摸的，我们也有触摸事件。

我们还可以定义我们自定义的事件。如果我们想要通知实体但又不想创建它们之间的依赖关系，这就很有用。例如，假设我们想向购物车中添加物品。现在添加物品到购物车的责任在于视图模型。我们可以创建一个购物车实体，它封装了所有的购物车行为：添加、编辑、删除、显示、隐藏等等。如果我们开始在我们的代码中写： `cart.add`, `cart.delete` 或 `cart.show`，那么我们的应用程序将依赖于 `cart` 对象。如果我们在我们的应用程序中创建事件，那么我们只需要触发它们，然后忘记接下来会发生什么，因为事件处理程序将为我们处理。

事件驱动编程能够减少耦合，但也降低内聚。我们应该选择在多大程度上要保持你的代码可读。事件驱动编程有时候是一个好的解决方案，但有一条规则我们应该始终遵循：KISS（保持简单，傻瓜）。所以，如果一个事件是一个简单的解决方案，就采用它。如果事件只是增加了代码行数，却没有给我们带来更好的结果，也许你应该考虑依赖注入作为更好的方法。

![事件驱动的编程](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_04_01.jpg)

事件驱动的编程工作流程

# 点击事件

在过去的三章中，我们一直在使用点击绑定。在这一章中，您将学习更多关于这个事件。点击事件是用户与应用程序进行交互的基本事件，因为鼠标一直是外设的首选（也是键盘）。

您可能已经了解到，如果将函数附加到点击绑定上，那么这个函数将会随着点击事件触发。问题在于，在 Knockout 中，点击事件不接受参数。据我们所知，我们点击函数的参数是预定义的。

## 传递更多参数

如我们所提到的，我们绑定到点击事件的函数具有预定义的签名：`function functionName(data, event){...}`，并且这两个参数已经被分配：data 是绑定到元素的数据，event 是点击事件对象。那么如果我们想传递更多的参数会发生什么呢？我们有三种解决方案，如下所示：

+   第一种是在视图模型中绑定参数：

    ```js
    function clickEventFunctionWithParams(p1, p2, data, event) {
      //manageEvent
    }

    function clickEventFunction(data, event) {
      clickEventFunctionWithParams('param1', 'param2', data, event);
    }
    ```

+   第二种选择是内联编写函数。如果我们想直接从模板中的上下文对象传递参数，那么这是一个有趣的选择。

    ```js
    <button data-bind="click: function(data, event) {
      clickEventFunctionWithParams($parent.someVariable, $root.otherVariable, data, event);
    }">Click me</button>
    ```

+   我们的第三个和最终的解决方案是第二个的变体，但更加优雅：

    ```js
    <button data-bind="
      click: clickEventFunctionWithParams.bind($data, 'param1', 'param2')"
    >Click me</button>
    ```

我们可以使用最接近我们需求的那个。例如，如果我们想要传递的参数是视图模型中的常量或可观察对象，我们可以使用第一个。但是，如果我们需要传递上下文变量，比如`$parent`，我们可以使用最后一个。

`bind`函数是 JavaScript 原生的。它使用`$data`作为上下文创建另一个函数，然后将其余的参数应用到自身。您可以在[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/bind`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/bind)找到更多信息。

## 允许默认点击操作

默认情况下，KnockoutJS 阻止了点击时的默认操作。这意味着如果您在锚标签(`<a>`)中使用了点击操作，浏览器将执行我们已经链接的操作，而不会导航到链接的`href`。这种默认行为非常有用，因为如果您使用点击绑定，通常是因为您想执行不同的操作。如果您想允许浏览器执行默认操作，只需在函数末尾返回`true`：

```js
function clickEventFunction(data, event) {
  //run your code...

  //it allows to run the default behavior.
  //In anchor tags navigates to href value.
  return true;
}
```

## 事件冒泡

默认情况下，Knockout 允许点击事件继续冒泡到任何更高级别的事件处理程序。如果您的元素有一个也处理点击事件的父级，那么您将触发两个函数。为了避免冒泡事件，您需要包含一个名为`clickBubble`的附加绑定，并将其设置为`false`。

```js
<button data-bind="{
  click: clickEventFunction,
  clickBubble: false
}">Click me</button>
```

![事件冒泡](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_04_02.jpg)

事件冒泡的工作流程

# 事件类型

浏览器可以抛出许多类型的事件。 您可以在[`developer.mozilla.org/en-US/docs/Web/Events`](https://developer.mozilla.org/en-US/docs/Web/Events)找到完整的参考资料。

正如我们所知，每个浏览器都有自己的一套指令； 因此，我们可以将事件分类为以下几组：

+   **标准事件**：这些事件在官方 Web 规范中定义，应该在各种浏览器中普遍存在。

+   **非标准事件**：这些事件是为每个浏览器引擎专门定义的。

+   **Mozilla 特定事件**：这些事件用于插件开发，包括以下内容：

    +   插件特定事件

    +   XUL 事件

# 事件绑定

为了捕获和处理所有这些不同的事件，Knockout 有`event`绑定。 我们将使用它在文本上方和离开时显示和隐藏调试面板，借助以下代码的帮助：

1.  `index.html` 模板的第一个更新如下。 用这个新的 HTML 替换调试 div：

    ```js
    <div data-bind="event: {
      mouseover:showDebug,
      mouseout:hideDebug
    }">
      <h3 style="cursor:pointer">
        Place the mouse over to display debug
      </h3>
      <pre class="well well-lg" data-bind="visible:debug, toJSON: $root"></pre>
    </div>
    ```

    该代码表示，当我们将鼠标悬停在`div`元素上时，我们将显示调试面板。 最初，只显示`h3`标签内容。

1.  当我们将鼠标悬停在`h3`标签上时，我们将更新调试变量的值，并显示调试面板。 为了实现这一点，我们需要使用以下代码更新我们的视图模型：

    ```js
    var debug = ko.observable(false);

    var showDebug = function () {
      debug(true);
    };

    var hideDebug = function () {
      debug(false); 
      };
    ```

1.  然后我们需要更新我们的接口（视图模型的返回值）。

    ```js
    return {
      debug: debug,
      showDebug:showDebug,
      hideDebug:hideDebug,
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
      showSearchBar: showSearchBar,
      showCartDetails: showCartDetails,
      hideCartDetails: hideCartDetails,
      showOrder: showOrder,
      showCatalog: showCatalog,
      finishOrder: finishOrder
    };
    ```

现在当鼠标悬停在`h3`标签上时，调试面板将显示。 试试吧！

# 无侵入 jQuery 事件

在过去几年里，从 HTML 模板中删除所有 JavaScript 代码已经成为一个良好的做法。 如果我们从 HTML 模板中删除所有 JavaScript 代码并将其封装在 JavaScript 文件中，我们就是在进行命令式编程。 另一方面，如果我们在 HTML 文件中编写 JavaScript 代码或使用组件和绑定，我们就是在使用声明式编程。 许多程序员不喜欢使用声明式编程。 他们认为这使得设计人员更难以处理模板。 我们应该注意，设计人员不是程序员，他们可能不理解 JavaScript 语法。 此外，声明式编程将相关代码拆分为不同的文件，可能使人们难以理解整个应用程序的工作方式。 此外，他们指出，双向绑定使模型不一致，因为它们在没有任何验证的情况下即时更新。 另一方面，有人认为声明式编程使代码更易于维护，模块化和可读性强，并且说如果您使用命令式编程，您需要在标记中填充不必要的 ID 和类。

没有绝对的真理。你应该在两种范式之间找到平衡。声明式本质在消除常用功能并使其变得简单方面表现得很出色。`foreach` 绑定及其兄弟，以及语义 HTML（组件），使代码易于阅读并消除了复杂性。我们必须自己用 JavaScript 编写，使用选择器与 DOM 交互，并为团队提供一个共同的平台，使他们可以专注于应用程序的工作原理，而不是模板和模型之间的通信方式。

还有其他框架，如 Ember、React 或 AngularJS，它们成功地使用了声明式范式，因此这并不是一个坏主意。但是，如果你感觉更舒适地使用 jQuery 定义事件，你将学会如何做。我们将以不引人注目的方式编写 **确认订单** 按钮。

首先，删除 `data-bind` 属性并添加一个 ID 来定位按钮：

```js
<button id="confirmOrderBtn" class="btn btn-primary btn-sm">
  Confirm Order
</button>
```

现在，在 `applyBindings` 方法的上方写入这段 JavaScript 代码：

```js
$(document).on('click', '#confirmOrderBtn').click(function() {
  vm.showOrder();
});
ko.applyBindings(vm);
```

这两种方法都是正确的；决定选择哪种范式是程序员的决定。

如果我们选择以 jQuery 的方式编写我们的事件，将所有事件合并到文件中也是一个好习惯。如果你没有很多事件，你可以有一个名为 `events.js` 的文件，或者如果你有很多事件，你可以有几个文件，比如 `catalog.events.js` 或 `cart.events.js`。

![使用 jQuery 实现不引人注目的事件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_04_03.jpg)

命令式范式与声明式范式

# 委托模式

当我们处理大量数据时，普通的事件处理会影响性能。有一种技术可以提高事件的响应时间。

当我们直接将事件链接到项目时，浏览器为每个项目创建一个事件。然而，我们可以将事件委托给其他元素。通常，这个元素可以是文档或元素的父级。在这种情况下，我们将其委托给文档，即添加或移除产品中的一个单位的事件。问题在于，如果我们只为所有产品定义一个事件管理器，那么我们如何设置我们正在管理的产品？KnockoutJS 为我们提供了一些有用的方法来成功实现这一点，`ko.dataFor` 和 `ko.contextFor`。

1.  我们应该通过分别添加 `add-unit` 和 `remove-unit` 类来更新 `cart-item.html` 文件中的添加和移除按钮：

    ```js
    <span class="input-group-addon">
      <div class="btn-group-vertical">
        <button class="btn btn-default btn-xs add-unit">
          <i class="glyphicon glyphicon-chevron-up"></i>
        </button>
        <button class="btn btn-default btn-xs remove-unit">
          <i class="glyphicon glyphicon-chevron-down"></i>
        </button>
      </div>
    </span>
    ```

1.  然后，我们应该在 `确认订单` 事件的下方添加两个新事件：

    ```js
     $(document).on("click", ".add-unit", function() {
      var data = ko.dataFor(this);
      data.addUnit();
    });

    $(document).on("click", ".remove-unit", function() {
      var data = ko.dataFor(this);
      data.removeUnit();
    });
    ```

1.  使用 `ko.dataFor` 方法，我们可以获得与我们在 KnockoutJS 上下文中使用 `$data` 获得的相同内容。有关不引人注目的事件处理的更多信息，请访问[`knockoutjs.com/documentation/unobtrusive-event-handling.html`](http://knockoutjs.com/documentation/unobtrusive-event-handling.html)

1.  如果我们想要访问上下文，我们应该使用 `ko.contextFor`；就像这个例子一样：

    ```js
    $(document).on("click", ".add-unit", function() {
      var ctx = ko.contextFor(this);
      var data = ctx.$data;
      data.addUnit();
    });
    ```

因此，如果我们有数千种产品，我们仍然只有两个事件处理程序，而不是数千个。以下图表显示了代理模式如何提高性能：

![代理模式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_04_04.jpg)

代理模式提高了性能。

# 构建自定义事件

有时，我们需要使应用程序中的两个或多个实体进行通信，这些实体彼此不相关。例如，我们希望将我们的购物车保持独立于应用程序。我们可以创建自定义事件来从外部更新它，购物车将对此事件做出反应；应用所需的业务逻辑。

我们可以将事件拆分为两个不同的事件：点击和动作。因此，当我们点击上箭头添加产品时，我们触发一个新的自定义事件来处理添加新单位的操作，删除产品时同样如此。这为我们提供了关于应用程序中正在发生的事情的更多信息，我们意识到一个通用含义的事件，比如点击，只是获取数据并将其发送到更专业的事件处理程序，该处理程序知道该怎么做。这意味着我们可以将事件数量减少到只有一个。

1.  在`viewmodel.js`文件末尾创建一个`click`事件处理程序，抛出一个自定义事件：

    ```js
    $(document).on("click", ".add-unit", function() {
      var data = ko.dataFor(this);
      $(document).trigger("addUnit",[data]);
    });

    $(document).on("click", ".remove-unit", function() {
      var data = ko.dataFor(this);
      $(document).trigger("removeUnit, [data]);
    });

    $(document).on("addUnit",function(event, data){
      data.addUnit();
    });
    $(document).on("removeUnit",function(event, data){
      data.removeUnit();
    });
    ```

    粗体行展示了我们如何使用 jQuery 触发方法来发出自定义事件。与关注触发动作的元素不同，自定义事件将焦点放在被操作的元素上。这给了我们一些好处，比如代码清晰，因为自定义事件在其名称中有关于其行为的含义（当然我们可以称事件为`event1`，但我们不喜欢这种做法，对吧？）。

    您可以在 jQuery 文档中阅读更多关于自定义事件的内容，并查看一些示例，网址为[`learn.jquery.com/events/introduction-to-custom-events/`](http://learn.jquery.com/events/introduction-to-custom-events/)。

1.  现在我们已经定义了我们的事件，是时候将它们全部移到一个隔离的文件中了。我们将这个文件称为`cart/events.js`。这个文件将包含我们应用程序的所有事件。

    ```js
    //Event handling
    (function() {
      "use strict";
      //Classic event handler
      $(document).on('click','#confirmOrder', function() {
        vm.showOrder();
      });
      //Delegated events
      $(document).on("click", ".add-unit", function() {
        var data = ko.dataFor(this);
        $(document).trigger("addUnit",[data]);
      });
      $(document).on("click", ".remove-unit", function() {
        var data = ko.dataFor(this);
        $(document).trigger("removeUnit, [data]);
      })
      $(document).on("addUnit",function(event, data){
       data.addUnit();
      });
      $(document).on("removeUnit",function(event, data){
       data.removeUnit();
      });
    })();
    ```

1.  最后，将文件添加到脚本部分的末尾，就在`viewmodel.js`脚本的下方：

    ```js
    <script type="text/javascript" src="img/events.js"></script>
    ```

我们应该注意到现在与购物车的通信是使用事件完成的，并且我们没有证据表明有一个名为`cart`的对象。我们只知道我们要与之通信的对象具有两个方法的接口，即`addUnit`和`removeUnit`。我们可以更改接口中的对象（HTML），如果我们遵守接口，它将按照我们的期望工作。

# 事件和绑定

我们可以将事件和自定义事件包装在`bindingHandlers`中。假设我们希望仅在按下*Enter*键时过滤产品。这使我们能够减少对过滤方法的调用，并且如果我们正在对服务器进行调用，这种做法可以帮助我们减少流量。

在`custom/koBindings.js`文件中定义自定义绑定处理程序：

```js
ko.bindingHandlers.executeOnEnter = {
  init: function (element, valueAccessor, allBindingsAccessor, viewModel) {
    var allBindings = allBindingsAccessor();
    $(element).keypress(function (event) {
      var keyCode = (event.which ? event.which : event.keyCode);
      if (keyCode === 13) {
        allBindings.executeOnEnter.call(viewModel);
        return false;
      }
      return true;
    });
  }
};
```

由于这是一个事件，我们应该记住事件初始化可以在`init`方法本身中设置。我们用 jQuery 捕获`keypress`事件并跟踪被按下的键。*Enter*键的键码是 13。如果我们按下*Enter*键，我们将在视图模型的上下文中调用`executeOnEnter`绑定值。这就是`allBindings.executeOnEnter.call(viewModel);`所做的。

然后，我们需要更新我们的视图模型，因为我们的过滤目录是一个计算的可观察数组，每当按下键时都会更新自身。现在我们需要将这个计算的可观察数组转换为一个简单的可观察数组。因此，请根据以下方式更新您的`filteredCatalog`变量：

```js
//we set a new copy from the initial catalog
var filteredCatalog = ko.observableArray(catalog());
```

意识到以下更改的后果：

```js
var filteredCatalog = catalog();
```

我们不是在制作副本，而是在创建一个引用。如果我们这样做，当我们过滤目录时，我们将丢失项目，而且我们将无法再次获取它们。

现在我们应该创建一个过滤目录项目的方法。这个函数的代码与我们在上一个版本中拥有的计算值类似：

```js
var filterCatalog = function () {
  if (!catalog()) {
    filteredCatalog([]);
  }
  if (!filter) {
    filteredCatalog(catalog());
  }
  var filter = searchTerm().toLowerCase();
  //filter data
  var filtered = ko.utils.arrayFilter(catalog(), function(item){
    var strProp = ko.unwrap(item["name"]).toLocaleLowerCase();
    if (strProp && (strProp.indexOf(filter) !== -1)) {
      return true;
    }
    return false;
  });
  filteredCatalog(filtered);
};
```

现在将其添加到`return`语句中：

```js
return {
  debug: debug,
  showDebug:showDebug,
  hideDebug:hideDebug,
  searchTerm: searchTerm,
  catalog: filteredCatalog,
  filterCatalog:filterCatalog,
  cart: cart,
  newProduct: newProduct,
  totalItems:totalItems,
  grandTotal:grandTotal,
  addProduct: addProduct,
  addToCart: addToCart,
  removeFromCart:removeFromCart,
  visibleCatalog: visibleCatalog,
  visibleCart: visibleCart,
  showSearchBar: showSearchBar,
  showCartDetails: showCartDetails,
  hideCartDetails: hideCartDetails,
  showOrder: showOrder,
  showCatalog: showCatalog,
  finishOrder: finishOrder
};
```

最后一步是更新`catalog.html`模板中的搜索元素：

```js
<div class="input-group" data-bind="visible:showSearchBar">
  <span class="input-group-addon">
    <i class="glyphicon glyphicon-search"></i> Search
  </span>
  <input type="text" class="form-control"
  data-bind="
    textInput: searchTerm,
    executeOnEnter: filterCatalog"
  placeholder="Press enter to search...">
</div>
```

现在，如果您在搜索框中输入内容，输入项目将不会更新；然而，当您按下*Enter*键时，过滤器会应用。

这是在插入新代码后我们的文件夹结构的样子：

![事件和绑定](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_04_05.jpg)

文件夹结构

# 摘要

在本章中，您已经学会了如何使用 Knockout 和 jQuery 管理事件。您已经学会了如何结合这两种技术，以根据项目的要求应用不同的技术。我们可以使用声明性范例来组合事件附加、`bindingHandlers`和 HTML 标记，或者我们可以使用 jQuery 事件将事件隔离在 JavaScript 代码中。

在下一章中，我们将解决与服务器通信的问题。您将学习如何验证用户输入，以确保我们向服务器发送干净和正确的数据。

我们还将学习模拟数据服务器端的技术。使用模拟库将帮助我们开发我们的前端应用程序，而无需一个完整的操作服务器。为了发送 AJAX 请求，我们将启动一个非常简单的服务器来运行我们的应用程序，因为浏览器默认不允许本地 AJAX 请求。

请记住，您可以在 GitHub 上检查本章的代码：

[`github.com/jorgeferrando/knockout-cart/tree/chapter4`](https://github.com/jorgeferrando/knockout-cart/tree/chapter4)


# 第五章：从服务器获取数据

我们现在有了一个购物车应用程序。要使其像真实世界的应用程序一样工作，我们需要从服务器获取数据。然而，本书侧重于如何使用 KnockoutJS 开发项目，而不是如何配置和运行服务器。

幸运的是，这种情况在每个项目中都会发生。前端开发人员开始仅使用数据规范，而没有任何后端服务器。

本章中，我们将构建一个完全功能的前端通信层，而无需后端服务器。要成功完成这项任务，我们将使用虚假对象模拟我们的数据层。当我们移除模拟层时，我们的应用将能够使用真实数据。这将帮助我们更快、更安全地开发我们的应用程序：更快，因为我们不需要等待真实服务器的响应，更安全，因为我们的数据操作不会影响真实服务器。

# REST 服务

在本章中，你将学习如何使前端层与后端层通信。

你不是在构建一个简单的网页，你正在构建一个 web 应用程序。这意味着你的项目不仅包含要显示给用户的数据，还有一些可点击的锚点和导航。这个网页还有一个逻辑和模型层，这使得它比一个简单的网页更复杂。

前端与服务器通信使用 Web 服务。W3C（代表 World Wide Web Consortium）定义 Web 服务为一种设计用于在网络上支持可互操作的机器对机器交互的软件系统。你可以使用许多协议来执行此交互：SOAP、POX、REST、RPC 等。

现在在 web 开发中，RESTful 服务被最多使用。这是因为 REST（代表 Representational State Transfer）协议具有一些特性，使其在这种应用程序中易于使用：

+   它们是基于 URI 的

+   通信使用互联网媒体类型（通常为 JSON，但也可以是 XML 或其他格式）

+   HTTP 方法是标准的：`GET`、`POST`、`PUT`、`DELETE`

+   可以使用超链接来引用资源的状态

要理解这些概念，我们将看一些示例。考虑到购物车场景，假设你想检索所有你的产品，那么请执行以下操作：

1.  定义 API 的入口点。RESTful 协议是基于 URI 的，如下所示：

    ```js
    http://mydomain.com/api/
    ```

1.  现在你想检索所有你的产品，因此定义一个指向此资源的 URI 如下所示：

    ```js
    http://mydomain.com/api/products
    ```

1.  由于这是一个检索操作，因此 HTTP 头应包含如下所示的 `GET` 方法：

    ```js
    GET /api/products HTTP/1.1
    ```

1.  为了利用 HTTP 协议，你可以在头部发送元数据；例如，你要发送的数据类型以及你要接收的数据，如下所示：

    ```js
    'Content-Type': 'application/json' //what we send
    Accept: 'application/json; charset=utf-8'//what we expect
    ```

1.  服务器将以预期格式回应一些数据和通常包含在 HTTP 头中的一些信息，例如操作的状态：`HTTP/1.1 200 OK`。以下是格式：

    +   如果一切顺利，则 2xx

    +   4xx，如果前端出现错误

    +   5xx，如果服务器端出现错误

如果您想要更新或删除一个对象，请将该对象的 ID 附加到 URI 并使用相应的标头。例如，要编辑或删除一个产品，使用适当的方法调用此 URI：`PUT`进行编辑和`DELETE`进行删除。服务器将适当处理这些请求，查找 URI 和标头中的信息，例如：

```js
http://mydomain.com/api/products/1
```

要了解有关 REST 和 RESTful 服务的更多信息，请参阅[`en.wikipedia.org/wiki/Representational_state_transfer`](http://en.wikipedia.org/wiki/Representational_state_transfer)。

# 定义 CRUD

当您定义一个用于发送和接收数据的服务时，此对象通常应执行最低程度的行为。您可以通过缩写**CRUD**来识别此行为：

+   **创建（C）**：您需要向服务器发送一条消息，其中包含要将其持久化在数据库中的新对象。HTTP 的`POST`动词用于此类请求。

+   **检索（R）**：该服务应能够发送请求以获取对象集合或仅特定对象。用于此类请求的是`GET`动词。

+   **更新（U）**：这是一个更新对象的请求。按照惯例，用于此类请求的是`PUT`动词。

+   **删除（D）**：这是一个删除对象的请求。用于此类请求的是`DELETE`动词。

可以实现更多操作，有时您不需要编写所有 CRUD 方法。您应根据应用程序的要求调整代码，并仅定义应用程序需要的操作。请记住，编写比应用程序需要的更多代码意味着在代码中创造更多错误的可能性。

# 单例资源

在此应用程序中，我们将资源称为与 API 服务器中包含的 URI 相关的对象。这意味着要管理`/products`URI，我们将拥有一个名为`ProductResource`的对象，该对象将管理此 URI 的 CRUD 操作。

我们将创建此对象作为单例，以确保我们在应用程序中只有一个对象管理每个 URI。有关单例的更多信息，请参阅[`en.wikipedia.org/wiki/Singleton_pattern`](http://en.wikipedia.org/wiki/Singleton_pattern)。

# 在资源中设置 CRUD 操作

我们将定义一些服务来为我们的产品和订单定义 CRUD 操作。一些开发人员常犯的一个常见错误是在模型类中设置 CRUD 操作。最佳实践表明，最好将模型和通信层分开。

为准备您的项目，请创建一个名为`services`的文件夹。在此文件夹中，存储包含 CRUD 操作的文件。执行以下步骤：

1.  在新文件夹中创建两个文件。它们代表两个通信服务：`OrderResource.js`和`ProductResource.js`。

1.  打开`ProductResource.js`文件，并定义基本的 CRUD 操作如下：

    ```js
    var ProductResource = (function () {
      function all() {}
      function get(id) {}
      function create(product) {}
      function update(product) {}
      function remove(id) {}
      return {
        all: all,
        get: get,
        create: create,
        update: update,
        remove: remove
      };
    })();
    ```

    这是 CRUD 服务的骨架。你可以使用 `all` 和 `get` 方法来定义检索操作。`all` 方法将返回所有产品，而 `get` 方法只返回传递的 ID 的产品。`create` 方法将创建一个产品，而 `update` 方法将更新一个产品。`remove` 方法将执行删除操作。我们称其为 `remove`，因为 `delete` 是 JavaScript 语言中的保留字。

1.  要实现这些方法的主体，请使用 jQuery AJAX 调用 ([`api.jquery.com/jquery.ajax/`](http://api.jquery.com/jquery.ajax/))。这样向服务器发出的请求是异步的，并使用一个称为 promise 的概念 ([`api.jquery.com/promise/`](http://api.jquery.com/promise/))。**Promise** 只是一个将来会包含一个值的对象。这个值通过使用回调函数来处理。

    Promise 图表：一个 promise 执行异步代码

1.  要定义 `retrieve` 方法，你需要定义 AJAX 请求的配置。调用此方法将返回一个 promise。你可以按照以下方式在视图模型中处理此 promise 中包含的数据：

    ```js
    function all() {
      return $.ajax({
        dataType:'json',
        type: 'GET',
        url: '/products'
      });
    }
    function get(id) {
      return $.ajax({
        dataType:'json',
        type: 'GET',
        url: '/products/'+id
      });
    }
    ```

1.  注意，你只需要定义服务器可用于获取数据的响应类型和端点。此外，完成 `CREATE`、`UPDATE` 和 `DELETE` 方法。记住要尊重动词 (`POST`、`PUT` 和 `DELETE`)。

    ```js
    function create(product) {
      return $.ajax({
        datatype:'json',
        type: 'POST',
        url: '/products',
        data: product
      });
    }
    function update(product) {
      return $.ajax({
        datatype:'json',
        type: 'PUT',
        url: '/products/'+product.id,
        data: product
      });
    }
    function remove(id) {
      return $.ajax({
        datatype:'json',
        type: 'DELETE',
        url: '/products/'+id
      });
    }
    ```

记住你正在构建一个 REST API，所以要遵循架构的约定。这意味着实体的 URL 应该以复数形式命名。

要获取所有产品，使用 `/products` URL。要获取一个产品，仍然使用 `/products` URL，但也将产品的 ID 添加到 URI 中。例如，`/products/7` 将返回 ID 为 `7` 的产品。如果关系更深入，例如，“客户 5 有消息”，则将路由定义为 `/customers/5/messages`。如果要从用户 `5` 中读取消息 ID 为 `1` 的消息，则使用 `/customers/5/message/1`。

有些情况下，你可以使用单数名称，比如 `/customers/5/configuration/`，因为一个用户通常只有一个配置。何时使用复数形式取决于你。唯一的要求是保持一致性。如果你更喜欢使用所有名称的单数形式，也可以，没有问题。将名称变为复数只是一种约定，而不是规则。

# 在视图模型中使用资源

现在我们已经创建了我们的产品资源，我们将在我们的视图模型中使用它来通过以下步骤获取我们的数据：

1.  首先，在 `index.html` 文件中链接 `ProductResource.js` 文件，如下所示：

    ```js
    <script type='text/javascript' src='js/resources/ProductResource.js'></script>
    ```

    由于资源是异步工作的，所以不能在文件末尾应用绑定，因为数据可能还没有准备好。因此，应在数据到达时应用绑定。

    要做到这一点，请创建一个名为`activate`的方法。此方法将在文件末尾触发，在我们之前调用`ko.applyBindings`的同一行上，方式如下：

    1.  获取此行代码：

        ```js
        ko.applyBindings(vm);
        ```

    1.  用这个替换它：

        ```js
        vm.activate();
        ```

1.  现在在视图模型中定义`activate`方法：

    ```js
    var activate = function () {
      ProductResource.all().done(allCallbackSuccess);
    };
    ```

    当您调用`all`方法时，将返回一个 jQuery 承诺。为了管理承诺的结果，jQuery 提供了一个承诺 API：

    +   `.done(callback)`：当承诺以成功解决时触发此方法。这意味着收到了与 5xx 或 4xx 不同的状态。

    +   `.fail(callback)`：您可以使用此方法来处理被拒绝的承诺。它由 5xx 和 4xx 头触发。

    +   `.then(successCb, errorCb)`：此方法以两个回调作为参数。第一个在承诺解决时调用，第二个在承诺被拒绝时调用。

    +   `.always(callback)`：传递给此方法的回调在两种情况下运行。

    通过使用 HTTP 头，您可以避免在响应主体中发送额外的信息以了解您是否收到了错误。了解您正在使用的协议（在本例中为 HTTP）并尝试使用它的所有优势是很重要的，比如在本例中，可以在其标头中发送信息的可能性。

1.  现在是定义`allCallbackSuccess`方法的时候了：

    ```js
    var allCallbackSuccess = function(response){
      catalog([]);
      response.data.forEach(function(item){
        catalog.push( 
          Product (item.id, item.name, item.price, item.stock)
        );
      });
      filteredCatalog(catalog());
      ko.applyBindings(vm);
    };
    ```

    一个 jQuery AJAX 回调总是将响应作为第一个参数。在这种情况下，您会收到一个 JSON 响应，其中包含目录中的所有项目。

    第一步是将目录初始化为空数组。一旦目录初始化完成，就可以对项目集合进行迭代。该集合存储在一个数据对象中。将数据隔离在其他变量中是一个好习惯。这只是为了以防您想向响应添加元数据。一旦目录准备就绪，请将其链接到`filteredCatalog`方法。

    当我们准备好初始数据时，这就是您可以调用`ko.applyBindings`方法的时刻。如果您在回调范围之外调用它，您不能确定目录是否已经包含了所有项目。这是因为资源执行操作是异步的，这意味着代码不是按顺序执行的。当资源返回的承诺有数据可用时，它才被执行。

1.  最后一步是在文件末尾运行`activate`方法，如下所示：

    ```js
    //ko External Template Settings
    infuser.defaults.templateSuffix = '.html';
    infuser.defaults.templateUrl = 'views';
    vm.activate();

    ```

运行我们的应用程序，它将无法工作，因为没有服务器来处理我们的请求。我们会得到一个 404 错误。为了解决这个问题，我们将模拟我们的 AJAX 调用和数据。

![在视图模型中使用资源](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_05_03.jpg)

在没有服务器支持的情况下进行 AJAX 调用会引发 404 错误

# 使用 Mockjax 模拟 HTTP 请求

**Mocking** **data**意味着用另一个模拟其行为的函数替换`$.ajax`调用。在遵循测试驱动开发范 paradigm 时，模拟是一种常用的技术。

要模拟 jQuery AJAX 调用，我们将使用一个名为 Mockjax 的库。要在应用程序中安装 Mockjax，请按照以下步骤操作：

1.  从[`github.com/jakerella/jquery-mockjax`](https://github.com/jakerella/jquery-mockjax)下载该库。

1.  将其保存到`vendors`文件夹中。

1.  在`index.html`页面中添加一个引用，就在 jQuery 库后面。为此，使用`<script>`标签，如下所示：

    ```js
    <script type='text/javascript' src='vendors/jquery.mockjax.js'></script>
    ```

1.  创建一个名为`mocks`的文件夹，并在其中创建一个名为`product.js`的文件。

1.  在`product.js`文件中，定义一个调用`$.mockjax`函数的模拟，如下所示：

    ```js
    $.mockjax({
      url: '/products',
      type: 'GET',
      dataType: 'json',
      responseTime: 750,
      responseText: []
    });
    ```

    在这个定义中，你正在模拟`ProducResource.all()`方法内部调用的请求。要定义模拟，你只需要定义这些参数：

    +   **url**：你想要模拟的 URL

    +   **type**：请求的类型

    +   **dataType**：你期望的数据类型

    +   **responseTime**：响应所需的持续时间

    +   **responseText**：响应体

# 使用 MockJSON 生成模拟数据

一旦你模拟了 HTTP 调用，你需要在响应中发送一些数据。你有不同的可能性：

+   你可以手写数据到`$.mockjax`调用的`responseText`属性中：

    ```js
    $.mockjax({
      url: '/products',
      type: 'GET',
      dataType: 'json',
      responseTime: 750,
      responseText: ['Here I can fake the response']
    });
    ```

+   你可以使用一个函数来生成模拟数据：

    ```js
    $.mockjax({
      url: '/products',
      type: 'GET',
      dataType: 'json',
      responseTime: 750,
      response: function(settings) {
        var fake = 'We fake the url:'+settings.url;
        this.responseText = fake;
      }
    });
    ```

+   你可以使用一个在响应中生成复杂和随机数据的库。

    这第三个选项可以通过一个叫做`mockJSON`的库来执行。你可以从 GitHub 仓库[`github.com/mennovanslooten/mockJSON`](https://github.com/mennovanslooten/mockJSON)下载它。

    这个库允许你生成数据模板来创建随机数据。这有助于使你的虚假数据更加真实。你可以在屏幕上看到许多不同类型的数据。这将帮助你检查更多的数据显示可能性，比如文字是否溢出容器或者文字过长或过短在屏幕上看起来很难看。

    +   要生成一个随机元素，定义一个模拟模板如下：

        ```js
        $.mockJSON.generateFromTemplate({
          'data|5-10': [{
            'id|1-100': 0,
            'name': '@PRODUCTNAME',
            'price|10-500': 0,
            'stock|1-9': 0
          }]
        });
        ```

        这个模板表示你想要生成 5 到 10 个具有以下结构的元素：

        +   ID 将是介于 1 到 100 之间的数字。

        +   产品名称将是存储在`PRODUCTNAME`数组中的值。

        +   价格将是介于 10 到 500 之间的数字。

        +   股票价格将是介于 1 到 9 之间的数字。

        +   要生成产品名称数组，你只需要将一个数组或一个函数添加到`$.mockJSON.data`对象中，如下所示：

            ```js
            $.mockJSON.data.PRODUCTNAME = [
              'T-SHIRT', 'SHIRT', 'TROUSERS', 'JEANS', 'SHORTS', 'GLOVES', 'TIE'
            ];
            ```

    你可以生成任何你能想象到的数据。只需创建一个函数，返回一个你想要生成的值的数组，或者定义一个生成随机结果、数字、唯一 ID 等的函数。

    +   要将其作为响应返回，请将此模板附加到响应文本。你的代码应该如下所示：

        ```js
        $.mockJSON.data.PRODUCTNAME = [
          'T-SHIRT', 'SHIRT', 'TROUSERS', 'JEANS', 'SHORTS', 'GLOVES', 'TIE'
        ];
        $.mockjax({
          url: '/products',
          type: 'GET',
          dataType: 'json',
          responseTime: 750,
          status:200,
          responseText: $.mockJSON.generateFromTemplate({
            'data|5-5': [{
              'id|1-100': 0,
              'name': '@PRODUCTNAME',
              'price|10-500': 0,
              'stock|1-9': 0
            }]
          })
        });
        ```

在`index.html`文件的末尾使用`<script>`标签添加`mocks/product.js`文件，然后查看每次刷新网页时如何获得新的随机数据。

![使用 MockJSON 生成模拟数据](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_05_04.jpg)

当进行模拟调用时，我们会在控制台中看到这条消息

# 通过 ID 检索产品

要从我们的 API 获取一个产品，我们将伪造 `ProductResource` 的 `get` 方法。 即当我们在目录列表中点击产品名称时，`ProductResource.get` 方法将被激活。

此 URI 在 URI 的最后一段包含产品的 ID。 这意味着 ID=1 的产品将生成类似 `/products/1` 的 URI。 ID=2 的产品将生成类似 `/products/2` 的 URI。

因此，这意味着我们无法将 URL 设置为固定字符串。 我们需要使用正则表达式。

如果您需要更多关于正则表达式的信息，请查看此链接：

[`developer.mozilla.org/en/docs/Web/JavaScript/Guide/Regular_Expressions`](https://developer.mozilla.org/en/docs/Web/JavaScript/Guide/Regular_Expressions)

为了完成代码以检索产品，请按照以下步骤进行：

1.  添加一个 `mockjax` 调用来模拟 URI。它应该使用 `GET` HTTP 方法。将正则表达式附加到 `url` 属性，如下所示：

    ```js
    $.mockjax({
      url: /^\/products\/([\d]+)$/,
      type: 'GET',
      dataType: 'json',
      responseTime: 750,
      responseText: ''
    });
    ```

1.  创建一个返回单个产品对象的模板。要生成随机描述，您可以使用 `@LOREM_IPSUM` 魔术变量，它会返回随机文本。它的使用方式与构建 `@PRODUCTNAME` 变量的方式相同。让我们使用以下代码创建一个模板：

    ```js
    $.mockJSON.generateFromTemplate({
      'data': {
        'id|1-100': 0,
        'name': '@PRODUCTNAME',
        'price|10-500': 0,
        'stock|1-9': 0,
        'description': '@LOREM_IPSUM'
      }
    })
    ```

1.  将以下模板附加到 `responseText` 变量：

    ```js
    //URI: /products/:id
    $.mockjax({
      url: /^\/products\/([\d]+)$/,
      type: 'GET',
      dataType: 'json',
      responseTime: 750,
      responseText: $.mockJSON.generateFromTemplate({
        'data': {
          'id|1-100': 0,
          'name': '@PRODUCTNAME',
          'price|10-500': 0,
          'stock|1-9': 0,
          'description': '@LOREM_IPSUM'
        }
      })
    });
    ```

1.  在 `viewmodel.js` 文件中，创建一个方法，该方法使用 `ProductResource` 对象检索产品。 该方法在数据可用时将显示一个警告框。

    ```js
    var showDescription = function (data) {
      ProductResource.get(data.id())
      .done(function(response){
        alert(response.data.description);
      });
    };
    ```

1.  将 `showDescription` 方法绑定到 `catalog.html` 模板上：

    ```js
    <td><a href data-bind='click:$parent.showDescription, text: name'></a></td>
    ```

1.  在视图模型接口中公开 `showDescription` 方法：

    ```js
    return {
      …
      showDescription: showDescription,
      …
    };
    ```

1.  测试如何在警告框中获取描述。![按 ID 检索产品](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_05_05.jpg)

    点击产品名称将显示产品描述

# 创建一个新产品

要创建一个产品，请按照前一节中的相同步骤进行：

1.  在`mocks/product.js` 文件中添加一个 AJAX 模拟调用：

    ```js
    $.mockjax({
      url: '/products',
      type:'POST',
      dataType: 'json',
      responseTime: 750,
      status:200,
      responseText: {
        'data': {
          text: 'Product created'
        }
      }
    });
    ```

    您应该记住一些注意事项：

    +   您应该使用 `POST` 动词来创建对象。实际上，您可以使用任何您想要的动词，但根据 RESTful API 的约定，`POST` 动词是您应该用来创建新对象的一个。

    +   响应文本是提供有关结果的一些信息的消息。

    +   结果本身由标头管理：

    +   如果在状态中获得 `2xx` 值，则会触发 `done` 方法。

    +   如果收到 `4xx` 或 `5xx` 错误，则调用 `fail` 方法。

1.  转到 `modelview.js` 文件并更新 `addProduct` 函数：

    ```js
    var addProduct = function (data) {
      var id = new Date().valueOf();
      var product = new Product(
        id,
        data.name(),
        data.price(),
        data.stock()
      );

      ProductResource.create(ko.toJS(data))
      .done(function (response){
        catalog.push(product);
        filteredCatalog(catalog());
        newProduct = Product(new Date().valueOf(),'',0,0);
        $('#addToCatalogModal').modal('hide');
      });
    };
    ```

显而易见，您不能将 Knockout observables 发送到服务器。 要将包含 observables 的对象转换为普通 JSON 对象，请使用 `ko.to` `JS` 函数。 此函数会遍历对象并提取每个 observable 的值。

您可以在 [`knockoutjs.com/documentation/json-data.html`](http://knockoutjs.com/documentation/json-data.html) 上找到关于 `ko.to` `JS` 和其他方法的信息。

也许你已经注意到了，当你添加一个新产品时，库存会减少一个。这是因为当你在产品中使用`ko.toJS`函数时，它会执行所有的函数。因此，为了使用它，你应该避免那些会操作对象并可能在内部改变其值的方法。我们将在下一节中解决这个问题。

测试应用程序在调用`addProduct`方法时是否发送数据。

![创建新产品](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_05_06.jpg)

添加新产品时使用 AJAX 调用；注意 URL 和类型字段

# 关注关注点分离 - 行为和数据

我们在应用程序中发现了一个问题。当我们使用`ko.toJS`函数时，结果与预期不符。这是软件开发中常见的情况。

我们在模型中设置了一些逻辑，这是一个错误的选择，我们需要修复它。为了解决这个问题，我们将数据和这些行为分开。我们将使用一些我们称之为服务的类。

服务将管理我们模型的逻辑。这意味着每个模型都会有一个相关的服务来管理其状态。

# 创建产品服务

如果你查看`models/product.js`文件，你会发现该模型包含一些逻辑：

```js
var hasStock = function () {
  return _product.stock() > 0;
};
var decreaseStock = function () {
  var s = _product.stock();
  if (s > 0) {
    s--;
  }
  _product.stock(s);
};
```

我们将使用以下步骤将此逻辑和更多内容移动到一个服务中：

1.  创建一个名为`services`的文件夹。

1.  在其中，创建一个名为`ProductService`的文件。

1.  创建一个单例对象，并添加`hasStock`和`decreaseStock`函数，如下所示：

    ```js
    var ProductService = (function() {
      var hasStock = function (product) {
        return product.stock() > 0;
      };

      var decreaseStock = function (product) {
        var s = product.stock();
        if (s > 0) {
          s--;
        }
        product.stock(s);
      };

      return {
        hasStock:hasStock,
        decreaseStock:decreaseStock
      };
    })();
    ```

1.  更新`add-to-cart-button`组件：

    ```js
    this.addToCart = function() {
      ...
      if (item) {
        CartProductService.addUnit(item);
      } else {
        item = CartItem(data,1);
        tmpCart.push(item);
        ProductService.decreaseStock(item.product);
      }
      this.cart(tmpCart);
    };
    ```

注意，你还需要创建一个服务来管理购物车商品的逻辑。

# 创建`CartProduct`服务

购物车商品服务还提取了`CartProduct`模型的逻辑。要创建此服务，请按照以下步骤操作：

1.  在`service`文件夹中创建一个名为`CartProductService.js`的文件。

1.  从`CartProduct`模型中删除`addUnit`和`removeUnit`方法。

1.  使用以下方法更新服务：

    ```js
    var CartProductService = (function() {

      var addUnit = function (cartItem) {
        var u = cartItem.units();
        var _stock =  cartItem.product.stock();
        if (_stock === 0) {
          return;
        }
        cartItem.units(u+1);
        cartItem.product.stock(--_stock);
      };

      var removeUnit = function (cartItem) {
        var u =  cartItem.units();
        var _stock =  cartItem.product.stock();
        if (u === 0) {
          return;
        }
        cartItem.units(u-1);
        cartItem.product.stock(++_stock);
      };

      return {
        addUnit:addUnit,
        removeUnit:removeUnit
      };
    })();
    ```

# 更新产品

在我们的目录中，我们将希望更新我们产品的价值。要完成此操作，请按照以下步骤操作：

1.  首先，要更新一个产品，你需要模拟处理该操作的 URI：

    ```js
    $.mockjax({
        url: /^\/products\/([\d]+)$/,
        type:'PUT',
        dataType: 'json',
        responseTime: 750,
        status:200,
        responseText: {
            'data': {
                text: 'Product saved'
            }
        }
    });
    ```

1.  在`catalog.html`视图的每一行中添加一个按钮，在您有`add-to-cart-button`组件的相同单元格中：

    ```js
    <button class='btn btn-info' data-bind='click: $parent.openEditModal'>
      <i class='glyphicon glyphicon-pencil'></i>
    </button>
    ```

1.  现在，使用这个产品的数据打开一个模态框：

    ```js
    var openEditModal = function (product) {
      tmpProduct = ProductService.clone(product);
      selectedProduct(product);
      $('#editProductModal').modal('show');
    };
    ```

1.  `tmpProduct`将包含您要编辑的对象的副本：

    ```js
    Var tmpProduct = null;
    ```

1.  `selectedProduct`将包含您要编辑的原始产品：

    ```js
    Var selectedProduct = ko.observable();
    ```

1.  在`ProductService`资源中创建`clone`函数：

    ```js
    var clone = function (product) {
      return Product(product.id(), product.name(), product.price(), product.stock());
    };
    ```

1.  在`ProductService`资源中创建`refresh`函数。此方法允许服务在不丢失对购物车中产品的引用的情况下刷新产品。

    ```js
    var refresh = function (product,newProduct) {
      product.name(newProduct.name());
      product.stock(newProduct.stock());
      product.price(newProduct.price());
    };
    ```

1.  将这两个方法添加到服务接口中：

    ```js
    return {
      hasStock:hasStock,
      decreaseStock:decreaseStock,
      clone:clone,
      refresh: refresh
    };
    ```

1.  创建`edit-product-modal.html`模板以显示编辑模态框。此模板是`create-product-modal.html`模板的副本。你只需要更新 form 标签行，如下所示：

    ```js
    <form class='form-horizontal' role='form' data-bind='with:selectedProduct'>
    ```

1.  你还需要更新`button`绑定：

    ```js
    <button type='submit' class='btn btn-default' data-bind='click: $parent.cancelEdition'>
      <i class='glyphicon glyphicon-remove-circle'></i> Cancel
    </button>
    <button type='submit' class='btn btn-default' data-bind='click: $parent.updateProduct'>
      <i class='glyphicon glyphicon-plus-sign'></i> Save
    </button>
    ```

1.  现在，定义`cancelEditon`和`saveProduct`方法：

    ```js
    var cancelEdition = function (product) {
      $('#editProductModal').modal('hide');
    };
    var saveProduct = function (product) {
      ProductResource.save(ko.toJS(product)).done( function(response){
        var tmpCatalog = catalog();
        var i = tmpCatalog.length;
        while(i--){
          if(tmpCatalog[i].id() === product.id()){
            ProductService.refresh(tmpCatalog[i],product);
          }
        }
        catalog(tmpCatalog);
        filterCatalog();
        $('#editProductModal').modal('hide');
      });
    };
    ```

1.  最后，将这些方法添加到视图模型 API 中。

现在，您可以测试如何更新产品的不同值。

# 删除产品

要删除产品，按照与`CREATE`和`UPDATE`方法相同的简单步骤进行操作。

1.  第一步是在`mocks/products.js`文件中创建模拟内容，如下所示：

    ```js
    $.mockjax({
      url: /^\/products\/([\d]+)$/,
      type:'DELETE',
      dataType: 'json',
      responseTime: 750,
      status:200,
      responseText: {
        'data': {
          text: 'Product deleted'
        }
      }
    });
    ```

1.  这种方法非常简单。只需添加一个类似编辑按钮的按钮，然后删除它。

    ```js
    var deleteProduct = function (product){
      ProductResource.remove(product.id())
      .done(function(response){
        catalog.remove(product);
        filteredCatalog(catalog());
        removeFromCartByProduct(product);
      });
    };
    ```

1.  创建一个函数来从购物车中移除产品。此函数遍历购物车项目并找到与移除产品相关的购物车项目。一旦找到该项目，就可以使用`removeFromCart`函数将其删除为普通项目：

    ```js
    var removeFromCartByProduct = function (product) {
      var tmpCart = cart();
      var i = tmpCart.length;
      var item;
      while(i--){
        if (tmpCart[i].product.id() === product.id()){
          item = tmpCart[i];
        }
      }
      removeFromCart(item);
    }
    ```

1.  在目录模板中添加一个按钮，位于编辑按钮旁边：

    ```js
    <button class='btn btn-danger' data-bind='click: $parent.deleteProduct'>
      <i class='glyphicon glyphicon-remove'></i>
    </button>
    ```

    ![删除产品](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_05_07.jpg)

    编辑和删除按钮

# 将订单发送到服务器

一旦您可以与服务器通信来管理我们的产品，就是时候发送订单了。为此，请按照以下说明进行：

1.  创建一个名为`resources/OrderResource.js`的文件，并添加以下内容：

    ```js
    'use strict';
    var OrderResource = (function () {
      function create(order) {
        return $.ajax({
          type: 'PUT',
          url: '/order',
          data: order
        });
      }
      return {
        create: create
      };
    })();
    ```

1.  通过创建名为`mocks/order.js`的文件并添加以下代码来模拟调用：

    ```js
    $.mockjax({
      type: 'POST',
      url: '/order',
      status: 200,
      responseTime: 750,
      responseText: {
        'data': {
          text: 'Order created'
        }
      }
    });
    ```

1.  更新`viewmodel.js`文件中的`finishOrder`方法：

    ```js
    var finishOrder = function() {
      OrderResource.create().done(function(response){
        cart([]);
        visibleCart(false);
        showCatalog();
        $('#finishOrderModal').modal('show');
      });
    };
    ```

我们应用程序的要求之一是，用户可以更新个人数据的选项。我们将允许用户将个人数据附加到订单中。这很重要，因为当我们发送订单时，我们需要知道谁将收到订单。

1.  在`models`文件夹中创建一个名为`Customer.js`的新文件。它将包含以下函数，用于生成客户：

    ```js
    var Customer = function () {
      var firstName = ko.observable('');
      var lastName = ko.observable('');
      var fullName = ko.computed(function(){
        return firstName() + ' ' + lastName();
      });
      var address = ko.observable('');
      var email = ko.observable('');
      var zipCode = ko.observable('');
      var country = ko.observable('');
      var fullAddress = ko.computed(function(){
        return address() + ' ' + zipCode() + ', ' + country();
      });
      return {
        firstName:firstName,
        lastName: lastName,
        fullName: fullName,
        address: address,
        email: email,
        zipCode: zipCode,
        country: country,
        fullAddress: fullAddress,
      };
    };
    ```

1.  链接到视图模型：

    ```js
    var customer = Customer();
    ```

1.  还要创建一个用于存储可销售国家的可观察数组：

    ```js
    var countries = ko.observableArray(['United States', 'United Kingdom']);
    ```

1.  在订单模板中创建一个表单，以显示一个完成客户数据的表单：

    ```js
    <div class='col-xs-12 col-sm-6'>
      <form class='form-horizontal' role='form' data-bind='with:customer'>
        <div class='modal-header'>
          <h3>Customer Information</h3>
        </div>
        <div class='modal-body'>
          <div class='form-group'>
            <div class='col-sm-12'>
              <input type='text' class='form-control' placeholder='First Name' data-bind='textInput:firstName'>
            </div>
          </div>
          <div class='form-group'>
            <div class='col-sm-12'>
              <input type='text' class='form-control' placeholder='Last Name' data-bind='textInput:lastName'>
            </div>
          </div>
          <div class='form-group'>
            <div class='col-sm-12'>
              <input type='text' class='form-control' placeholder='Address' data-bind='textInput:address'>
            </div>
          </div>
          <div class='form-group'>
            <div class='col-sm-12'>
              <input type='text' class='form-control' placeholder='Zip code' data-bind='textInput:zipCode'>
            </div>
          </div>
          <div class='form-group'>
            <div class='col-sm-12'>
              <input type='text' class='form-control' placeholder='Email' data-bind='textInput:email'>
            </div>
          </div>
          <div class='form-group'>
            <div class='col-sm-12'>
              <select class='form-control' data-bind='options: $parent.countries,value:country'></select>
            </div>
          </div>
        </div>
      </form>
    </div>
    ```

1.  使用`finishOrder`方法将此信息与订单请求一起发送：

    ```js
    var finishOrder = function() {
      var order = {
        cart: ko.toJS(cart),
        customer: ko.toJS(customer)
      };
      OrderResource.create(order).done(function(response){
        cart([]);
        hideCartDetails();
        showCatalog();
        $('#finishOrderModal').modal('show');
      });
    };
    ```

我们的 AJAX 通讯已经完成。现在，您可以在项目中添加和移除`mocks/*.js`文件，以获取虚假数据或真实数据。在使用此方法时，当您开发前端问题时，无需在应用程序后面运行服务器。

![将订单发送到服务器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_05_08.jpg)

一旦提供了个人数据，您就可以关闭订单

# 处理 AJAX 错误

我们构建了应用程序的正常路径。但在现实世界中，在与服务器的通讯过程中可能会发生错误。要处理这种情况有两种方法：

+   AJAX 承诺的`fail`方法：

    ```js
    ProductResource.remove()
    .done(function(){...})
    .fail(function(response){
      console.error(response);
      alert("Error in the communication. Check the console!");
    });
    ```

+   一个全局的 AJAX 错误处理程序：

    ```js
    $(document).ajaxError(function(event,response) {
      console.error(response);
      alert("Error in the communication. Check the console!");
    });
    ```

如果您有一致的错误格式，全局处理程序是处理错误的非常好的选择。

要测试错误，请将一个模拟的状态属性从 200 更新为 404 或 501：

```js
$.mockjax({
  url: /^\/products\/([\d]+)$/,
  type:"DELETE",
  dataType: "json",
  responseTime: 750,
  status:404,
  responseText: {
    "data": {
      text: "Product deleted"
    }
  }
});
```

# 验证数据

现在您可以发送和接收数据了，但是如果用户设置了服务器不允许的一些数据会发生什么？您无法控制用户输入。如果某些值不允许，重要的是要提醒用户。要验证 Knockout 数据，有一个名为 Knockout Validation 的库（可在[`github.com/Knockout-Contrib/Knockout-Validation`](https://github.com/Knockout-Contrib/Knockout-Validation)找到），可以使这变得非常容易。

此库通过为可观察对象添加一些值来扩展可观察对象，以使您在数据更改时能够验证数据。我们现在将更新我们的模型以添加某种验证。

# 扩展产品模型

为了使用 Knockout Validation 库验证我们的模型，我们将扩展我们模型的属性。**扩展器**是 Knockout 的基本功能。使用扩展器，我们可以向我们的可观察对象添加一些属性以增强其行为。有关扩展器的更多信息，请参阅以下链接：

[`knockoutjs.com/documentation/extenders.html`](http://knockoutjs.com/documentation/extenders.html)

我们将通过以下步骤扩展我们的产品模型以添加一些属性，以允许我们验证数据：

1.  转到`models/Product.js`文件。

1.  更新`name`字段。它应至少包含三个字母，并且应仅包含字母、数字和破折号：

    ```js
    _name = ko.observable(name).extend({
      required: true,
      minLength: 3,
      pattern: {
        message: 'Hey this doesn\'t match my pattern',
        params: '^[A-Za-z0-9 \-]+$'
      }
    })
    ```

1.  更新`price`以仅允许数字，并为其设置范围（最大和最小值）：

    ```js
    _price = ko.observable(price).extend({
      required: true,
      number:true,
      min: 1
    }),
    ```

1.  对`stock`也执行同样的操作：

    ```js
    _stock = ko.observable(stock).extend({
      required: true,
      min: 0,
      max: 99,
      number: true
    })
    ```

1.  创建一个验证组以确定何时整个对象是有效的：

    ```js
    var errors = ko.validation.group([_name, _price, _stock]);
    ```

    此错误变量将包含一个可观察数组。当此数组没有元素时，所有可观察对象均具有正确的值。

1.  在`add-to-catalog-modal.html`模板中，仅在产品中的所有值都有效时才启用创建按钮：

    ```js
    <button type='submit' class='btn btn-default' data-bind='click:$parent.addProduct, enable:!errors().length'>
      <i class='glyphicon glyphicon-plus-sign'></i> Add Product
    </button>
    ```

1.  在`edit-product-modal.html`模板中添加相同的按钮：

    ```js
    <button type='submit' class='btn btn-default' data-bind='enable:!errors().length, click: $parent.saveProduct'>
      <i class='glyphicon glyphicon-plus-sign'></i> Save
    </button>
    ```

1.  如果要为错误消息设置样式，只需为`validationMessage`类定义 CSS 规则，如下所示。将显示一个`span`元素，显示在与验证的可观察对象绑定的元素旁边：

    ```js
    .validationMessage { color: Red; }
    ```

# 扩展客户模型

您还需要验证客户数据。以下是验证规则：

+   名字是必需的

+   姓是必需的，且至少需要三个字符

+   地址是必需的，且至少需要五个字符

+   电子邮件地址是必需的，并且必须与内置的电子邮件模式匹配

+   邮政编码是必需的，且必须包含五个数字

要完成此任务，请按照以下方式更新代码：

1.  在`models/Customer.js`文件中扩展客户对象：

    ```js
    var firstName = ko.observable('').extend({
      required: true
    });
    var lastName = ko.observable('').extend({
      required: true,
      minLength: 3
    });
    var fullName = ko.computed(function(){
      return firstName() + ' ' + lastName();
    });
    var address = ko.observable('').extend({
      required: true,
      minLength: 5
    });
    var email = ko.observable('').extend({
      required: true,
      email: true
    });
    var zipCode = ko.observable('').extend({
      required: true,
      pattern: {
        message: 'Zip code should have 5 numbers',
        params: '^[0-9]{5}$'
      }
    });
    var country = ko.observable('');
    var fullAddress = ko.computed(function(){
        return address() + ' ' + zipCode() + ', ' + country();
    });
    var errors = ko.validation.group([firstName, lastName, address, email, zipCode]);
    ```

1.  如果客户数据已完成并且有效，请在`order.html`模板中启用购买按钮。

    ```js
    <button class='btn btn-sm btn-primary' data-bind='click:finishOrder, enable:!customer.errors().length'>
      Buy & finish
    </button>
    ```

1.  在`finish-order-modal.html`模板中显示用户信息。

    ```js
    <div class='modal-body'>
      <h2>Your order has been completed!</h2>
      <p>It will be sent to:</p>
      <p>
        <b>Name: </b><span data-bind='text: customer.fullName'></span><br/>
        <b>Address: </b><span data-bind='text: customer.fullAddress'></span><br/>
        <b>Email: </b><span data-bind='text: customer.email'></span><br/>
      </p>
    </div>
    ```

    ![扩展客户模型](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_05_09.jpg)

    如果字段中的信息无效，则显示验证消息。

现在我们的模型已经验证，并且我们知道我们发送的数据具有有效的格式。

要查看应用程序的完整代码，你可以从[`github.com/jorgeferrando/knockout-cart/tree/chapter5`](https://github.com/jorgeferrando/knockout-cart/tree/chapter5)下载本章的代码。

# 摘要

在本章中，你学会了如何使用 jQuery 与我们的应用程序进行通信以执行 AJAX 调用。 你还学会了使用 Knockout Validation 库对我们的模型应用验证有多么容易，该库使用了 Knockout 本身的`extend`方法来增强可观察对象的行为。

你经历了 KnockoutJS 的一个问题：你需要将对象序列化后发送到服务器，并且需要在从服务器返回时将它们包装在可观察对象中。 要解决这个问题，你可以使用`ko.toJS`方法，但这意味着对象没有允许它们更新值的代码。

在接下来的章节中，你将学会如何使用 RequireJS 和模块模式来管理文件之间的依赖关系。


# 第六章：模块模式 - RequireJS

我们现在可以说我们的应用程序具有我们在第一章中提到的所有功能，*使用 KnockoutJS 自动刷新 UI*。我们在过去的四章中所做的是解决小型项目中的代码设计的一个很好的方法。代码整洁，文件夹结构也是连贯的。代码易于阅读和跟踪。

然而，当项目开始增长时，这种方法是不够的。你需要保持代码的整洁，不仅是在文件和文件夹结构上，还包括逻辑上。

在这一章中，我们将把我们的代码模块化，以保持应用程序的不同部分隔离和可重用。我们还将看到如何保持我们的上下文更清晰。

现在项目开始变得更加复杂。当你发现错误时，了解帮助你调试代码的工具是很重要的。在本章的第一部分，你将学习一些可以帮助你检查你的 KnockoutJS 代码的工具。你将使用一个浏览器插件（Chrome 扩展）来分析代码。

在本章的第二部分，你将把你的文件转换成模块。这将帮助你将应用程序的每个部分与其他部分隔离开来。你将使用一种叫做“依赖注入”的模式来解决模块之间的依赖关系。在[`en.wikipedia.org/wiki/Dependency_injection`](http://en.wikipedia.org/wiki/Dependency_injection)了解更多关于这个模式的信息。

在最后一部分，你将学习如何创建遵循异步模块定义（AMD）规范的模块。为了创建遵循 AMD 规范的模块，你将使用一个叫做 RequireJS 的库。这个库将管理不同模块之间的所有依赖关系。有关 AMD 的更多信息，请参阅[`en.wikipedia.org/wiki/Asynchronous_module_definition`](http://en.wikipedia.org/wiki/Asynchronous_module_definition)。

# 安装 Knockout 上下文调试器扩展

在前面的章节中，你创建了一个简单的调试器来显示你的视图模型的状态。这对于快速查看应用程序的状态非常有用。有了调试绑定，你不需要打开扩展工具来检查你的数据发生了什么变化。但是你经常只是隔离应用程序的一部分或查看绑定到 DOM 元素的模型发生了什么变化。

在 Google Chrome 中，你有一个非常好的扩展叫做**KnockoutJS 上下文调试器**，可以从[`chrome.google.com/webstore/detail/knockoutjs-context-debugg/oddcpmchholgcjgjdnfjmildmlielhof`](https://chrome.google.com/webstore/detail/knockoutjs-context-debugg/oddcpmchholgcjgjdnfjmildmlielhof)下载。

这个扩展允许你查看每个 DOM 节点的绑定，并通过控制台在线跟踪你的视图模型的变化。安装它并重新启动 Chrome 浏览器。

![安装 Knockout 上下文调试器扩展](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_06_01.jpg)

检查 chrome://extensions 是否已安装 KnockoutJS 上下文调试器

要检查绑定到模型的上下文，请按 *F12* 打开 **Chrome 开发者工具** 并打开 **Elements** 标签。您会看到两个面板。左侧面板有 DOM 结构。右侧面板有不同的标签。默认情况下，打开 **Styles** 标签。选择名为 **Knockout 上下文** 的标签。在那里，您应该看到添加到根上下文的所有绑定。

![安装 Knockout 上下文调试器扩展](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_06_02.jpg)

如何显示绑定到 DOM 元素的 KnockoutJS 上下文

如果您选择目录中的 `<tr>` 元素，您将深入上下文并位于目录项范围内。您将无法看到 `$root` 上下文；您将看到 `$data` 上下文。您可以通过 `$parent` 元素向上导航或更改 DOM 面板中的元素。

![安装 Knockout 上下文调试器扩展](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_06_03.jpg)

您可以轻松检查 foreach 绑定中的项目上下文。

您还可以看到 `ko` 对象。这是浏览 Knockout API 的好方法。

![安装 Knockout 上下文调试器扩展](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_06_04.jpg)

您可以访问 Knockout API 并查看方法、绑定、组件等。

现在找到 **KnockoutJS** 标签（它与 **Elements** 标签在同一集合中）。按下 **启用跟踪** 按钮。此功能允许您跟踪视图模型的实时更改。更改将在控制台中显示。

![安装 Knockout 上下文调试器扩展](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_06_05.jpg)

如果启用跟踪，您可以通过控制台捕获视图模型的更改。

此外，您还可以使用 **Timeline** 标签测量时间和性能。您可以看到应用程序在模型发生变化时用于渲染 DOM 元素的时间。

![安装 Knockout 上下文调试器扩展](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_06_06.jpg)

启用跟踪功能后，您可以记录事件并获得有用信息。

现在您已经了解了这个插件，我们可以删除（或保留，这取决于您）之前构建的调试绑定。

# 控制台

**控制台** 是开发人员最重要的工具之一。您可以使用它来检查应用程序在使用过程中的状态。

您可以定位 JavaScript 代码并设置断点，以检查特定点发生了什么。您可以在 **Sources** 标签中找到 JavaScript 文件。只需点击要停在的行即可。然后，您可以检查变量的值并逐步运行代码。此外，您还可以在代码中写入 `debugger` 以在此处停止程序。

![控制台](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_06_07.jpg)

您可以在代码中设置断点并检查变量的值。

如果您导航到**控制台**选项卡，您将看到控制台本身。在那里，您可以使用`console.log`函数显示信息，或者查看控制台对象文档以查看您可以在每个时刻使用的最佳方法（[`developer.mozilla.org/en-US/docs/Web/API/Console`](https://developer.mozilla.org/en-US/docs/Web/API/Console)）。

如果您在控制台中写入单词`window`，您将看到在全局范围内的所有对象。

![控制台](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_06_08.jpg)

使用控制台，您可以访问当前和全局上下文中的变量

您可以写入单词`vm`（视图模型）以查看我们创建的`vm`对象。

![控制台](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/knckt-ess/img/7074OS_06_09.jpg)

所有组件都设置在全局范围内

但是您也可以写`Product`或`ProductService`或我们创建的任何内容，您都会看到它。当您有大量信息时，在顶层拥有所有对象可能会很混乱。定义命名空间并保持层次结构是保持组件隔离的良好实践。您应该只保留应用程序的一个入口点。

# 模块模式

此模式允许我们专注于哪些代码部分暴露给类外部（公共元素），以及代码的哪些部分对最终用户隐藏（私有元素）。

此模式通常用于 JavaScript 软件开发。它应用于像 jQuery、Dojo 和 ExtJS 等流行库中。

一旦您知道如何使用它，此模式具有非常清晰的结构，并且非常容易应用。让我们在我们的应用程序中应用模块模式：

1.  首先，定义模块的名称。如果您在不同的文件中定义模块，重要的是要应用允许其可扩展性的模式来定义和初始化它。在初始化中使用`||`运算符表示如果`ModuleName`值已经有值，则将其赋值给自身。如果它没有值，则意味着这是它第一次被创建，因此给它一个默认值—在这种情况下是一个空对象：

    ```js
    var ModuleName;
    ModuleName = ModuleName || {};
    ```

1.  然后，定义模块的每个组件。它可以是函数、变量或另一个模块：

    ```js
    ModuleName.CustomComponent = function () {
    };
    ModuleName.CustomProperty = 10;
    ModeleName.ChildModule = OtherModule;
    ```

1.  最后，使用依赖注入模式插入模块的依赖项。该模式将所有模块依赖项作为参数传递，并立即调用该函数：

    ```js
    ModuleName.CustomComponent = (function (dependency){
      //Component code
    })(dependency);
    ```

1.  这就是一个完整模块的样子：

    ```js
    var ModuleName;
    var ModuleName = ModuleName || {};
    ModuleName.CustomComponent = (function(dependency){
      //Component code
    })(dependency);
    ```

1.  要定义组件，请返回`component`对象。定义组件的第一个模式是使用揭示模块模式。它包含在函数末尾返回一个仅包含公共接口的对象。这些是单例对象：

    ```js
    ModuleName.CustomComponent = (function(dependency){
      var somePrivateProperty = 1;
      var method1 = function(){
        dependency.methodFromDependency();
      };
      return {
        method1:method1,
        method2:method2
      }
    })(dependency);
    You can also define objects that can be instantiated using the new operator:  ModuleName.CustomComponent = (function(dependency){
      var component = function (a,b,c) {
        var somePrivateProperty=1;
        this.someMethod = function(){
          dependency.methodFromDependency()
        }
        this.otherMethod(){
          return a+b*c; 
        }
        return this;
      }    

      return component;
    })(dependency);
    //We can instantiate the component as an object
    //var instance = new ModuleName.CustomComponent(x,y,z);
    ```

# 创建 Shop 模块

为了使我们的应用程序模块化，我们将创建一个名为`Shop`的模块，该模块将包含我们的整个应用程序。此模块将包含其他子模块和组件。此分层结构将帮助您保持代码的一致性。

作为第一种方法，按文件和类型分组你的组件。这意味着模块的每个组件都将在一个文件中，并且文件将在一个文件夹中按类型分组。例如，有一个名为`services`的文件夹。这意味着所有服务都将在这个文件夹中，并且每个服务将在一个文件中完全定义。按照惯例，组件将与它们所在的文件具有相同的名称，当然不包括扩展名。

实际上，文件已经按类型分组了，所以这是一个你不需要再做的工作。我们将把精力集中在将我们的文件转换为模块上。

# 视图模型模块

我们的应用程序中只有一个视图模型。这是一个可以应用单例模块方法的组件。

我们将小心翼翼地逐步创建我们的第一个模块：

1.  打开`viewmodel.js`文件。

1.  定义`Shop`模块，这是我们应用程序的顶级模块：

    ```js
    var Shop;
    ```

1.  通过应用扩展模式初始化`Shop`模块：

    ```js
    Shop = Shop || {};
    ```

1.  定义`ViewModel`组件：

    ```js
    Shop.ViewModel = (function(){})();
    ```

1.  将未模块化的视图模型版本的代码放入模块中：

    ```js
    Shop.ViewModel = (function(){
      var debug = ko.observable(false);
      var showDebug = function () {
        debug(true);
      };

      var hideDebug = function () {
        debug(false);
      };
      var visibleCatalog = ko.observable(true);
      // ... the rest of the code
      return {
        debug: debug,
        showDebug:showDebug,
        hideDebug:hideDebug,
        searchTerm: searchTerm,
        catalog: filteredCatalog,
    ....
      };
    })();
    ```

1.  您还没有将其他文件转换为模块，但现在您将向模块添加依赖项：

    ```js
    Shop.ViewModel = (function (ko, Models, Services, Resources){
      //code of the module
    })(ko, Shop.Models, Shop.Services, Shop.Resources);
    ```

1.  在文件末尾，模块外部，初始化模板、验证和对象：

    ```js
    $(document).ajaxError(function(event,response) {
      console.error(response);
      alert("Error in the communication. Check the console!");
    });

    //ko External Template Settings
    infuser.defaults.templateSuffix = ".html";
    infuser.defaults.templateUrl = "views";

    ko.validation.init({
      registerExtenders: true,
      messagesOnModified: true,
      insertMessages: true,
      parseInputAttributes: true
    });
    var vm = Shop.ViewModel;
    vm.activate();
    ```

您需要更新我们的视图模型中的两个方法：`activate`方法和`allCallbackSuccess`方法。您需要更新这些方法的原因是因为在`allCallbackSuccess`方法中，您需要运行`ko.applyBindings`方法，而`allCallbackSuccess`无法访问此对象，因为它超出了范围。

要解决这个问题，我们将使用与点击绑定相同的技术来附加更多参数。我们将使用`bind` JavaScript 方法将`allCallbackSuccess`方法绑定到这个对象上。因此，我们将能够像下面的代码一样使用此对象运行`ko.applyBindings`：

```js
var allCallbackSuccess = function(response){
  catalog([]);
  response.data.forEach(function(item){
    catalog.push(Product( item.id,item.name,item.price,item.stock));
  });
  filteredCatalog(catalog());
  if (catalog().length) {
    selectedProduct(catalog()[0]);
  }
  ko.applyBindings(this);
};

var activate = function () {
  ProductResource.all()
  .done(allCallbackSuccess.bind(this));
};
```

使用这种模式，您可以将任何代码片段转换为一个隔离的、可移植的模块。下一步是创建`Models`模块、`Services`模块和`Resources`模块。

# 模型模块

就像我们对视图模型所做的一样，我们将每个模型转换为一个组件，并将其包装在一个名为`Models`的模块中，具体步骤如下：

1.  打开`models/product.js`文件。

1.  定义我们的顶层模块，`Shop`，并初始化它：

    ```js
    var Shop;
    Shop = Shop || {};
    ```

1.  然后创建`Models`命名空间。它将是一个对象，或者如果存在的话，它将是它之前的值：

    ```js
    Shop.Models = Shop.Models || {};
    ```

1.  用其依赖项定义产品模型。请记住，第一个值是产品本身。这样可以允许我们在使用多个文件定义它的情况下扩展模型。因此，我们将产品模型定义如下：

    ```js
    Shop.Models.Product = (function(){
    })()
    ```

1.  传递依赖项。这次你只需要使用 Knockout 依赖项来使用 observables。Knockout 是一个全局对象，不需要将其添加到依赖项中，但最好像下面的代码那样做。

    ```js
    Shop.Models.Product = (function (ko){
    }(ko)
    ```

1.  最后，在先前的`models/Product.js`文件中设置我们之前拥有的代码：

    ```js
    var Shop;
    Shop = Shop || {};
    Shop.Models = Shop.Models || {};
    Shop.Models.Product  = (function (ko){
      return function (id, name, price, stock) {
        _id = ko.observable(id).extend(...);
        _name = ko.observable(name).extend(...);
        _price = ko.observable(price).extend(...);
        _stock = ko.observable(error).extend(...);
        var errors = ko.validation.group([_name, _price, _stock]);
        return {
          id: _id,
          name: _name,
          price: _price,
          stock: _stock,
          errors: errors
        };
      };
    })(ko);
    ```

对`models/CartProduct.js`和`models/Customer.js`文件执行相同的步骤以将其转换为模块。模型是应用我们用于生成可实例化对象的模式的完美候选对象。

重要的是要保持组件和文件名之间的一致性。确保你的文件名称与其包含的组件名称并带有`.js`扩展名。

这是将`models/CartProduct.js`文件转换为最终结果的步骤：

```js
var Shop;
Shop = Shop || {};
Shop.Models = Shop.Models || {};
Shop.Models.CartProduct = (function(ko){

  return function (product,units){
    var
    _product = product,
    _units = ko.observable(units)
    ;

    var subtotal = ko.computed(function(){
      return _product.price() * _units();
    });

    return {
      product: _product,
      units: _units,
      subtotal: subtotal
    };
  }
})(ko);
```

同样，查看`models/Customer.js`文件的结果：

```js
var Shop;
Shop = Shop || {};
Shop.Models = Shop.Models || {};
Shop.Models.Customer = (function(ko){
  return function() {
    var firstName = ko.observable("John").extend({
      required: true
    });
    var lastName = ko.observable("Doe").extend({
      required: true,
      minLength: 3
    });
    var fullName = ko.computed(function(){
      return firstName() + " " + lastName();
    });
    var address = ko.observable("Baker Street").extend({
      required: true,
      minLength: 5
    });
    var email = ko.observable("john@doe.com").extend({
      required: true,
      email: true
    });
    var zipCode = ko.observable("12345").extend({
      required: true,
      minLength: 3,
      pattern: {
        message: 'Zip code should have 5 numbers',
        params: '^[0-9]{5}$'
      }
    });
    var country = ko.observable("");
    var fullAddress = ko.computed(function(){
      return address() + " " + zipCode() + ", " + country();
    });
    var errors = ko.validation.group([firstName, lastName, address, email, zipCode]);
    return {
      firstName:firstName,
      lastName: lastName,
      fullName: fullName,
      address: address,
      email: email,
      zipCode: zipCode,
      country: country,
      fullAddress: fullAddress,
      errors: errors
    };
  };
})(ko);
```

# 资源模块

从编码角度来看，构建包含模型的模块和构建包含资源的模块并没有太大的不同。应用的模块模式是相同的。然而，你不需要创建资源的实例。要对模型应用 CRUD 操作，你只需要一个处理此责任的对象。因此，资源将是单例的，就像以下步骤中所做的那样：

1.  打开`resources/ProductResource.js`文件。

1.  创建顶层层次模块：

    ```js
    var Shop;
    Shop = Shop || {};
    ```

1.  创建`Resources`命名空间：

    ```js
    Shop.Resources = Shop.Resources || {};
    ```

1.  使用模块模式定义`ProductResource`：

    ```js
    Shop.Resources.ProductResource = (function(){
    })()
    ```

1.  设置依赖关系。在这种情况下，jQuery 是你需要的依赖项。jQuery 是一个全局对象，不需要将其作为依赖项传递，但这样做是一个很好的实践。

    ```js
    Shop.Resources.ProductResource = (function($){
    }(jQuery);
    ```

1.  最后，在`resources/ProductResource.js`文件中设置以下代码。由于在我们的应用程序中资源是单例的，将资源与以下代码中使用的方法扩展起来：

    ```js
    var Shop;
    Shop = Shop || {};
    Shop.Resources = Shop.Resources || {};
    Shop.Resources.ProductResource = (function($){
      function all() {
        return $.ajax({
          type: 'GET',
          url: '/products'
        });
      }
      function get(id) {
        return $.ajax({
          type: 'GET',
          url: '/products/'+id
        });
      }
      function create(product) {
        return $.ajax({
          type: 'POST',
          url: '/products',
          data: product
        });
      }
      function save(product) {
        return $.ajax({
          type: 'PUT',
          url: '/products/'+product.id,
          data: product
        });
      }
      function remove(id) {
        return $.ajax({
          type: 'DELETE',
          url: '/products/'+id
        });
      }
      return {
        all:all,
        get: get,
        create: create,
        save: save,
        remove: remove
      };
    }(jQuery);
    ```

现在对`OrderResouce`组件应用相同的步骤。你可以在这段代码中看到最终结果：

```js
var Shop;
Shop = Shop || {};
Shop.Resources = Shop.Resources || {};
Shop.Resources.OrderResource = (function ($) {
  function save(order) {
    return $.ajax({
      type: 'PUT',
      url: '/order',
      data: order
    });
  }
  return {
    save: save
  };
})(jQuery);
```

# 服务模块

服务也是单例的，和资源一样，所以按照与资源模块相同的步骤进行操作：

1.  打开`services/ProductService.js`文件。

1.  创建顶层层次模块：

    ```js
    var Shop;
    Shop = Shop || {};
    ```

1.  创建`Resources`命名空间：

    ```js
    Shop.Services = Shop.Services || {};
    ```

1.  定义`ProductService`：

    ```js
    Shop.Services.ProductService = (function(){
    })();
    ```

1.  在这种情况下，服务没有依赖关系。

1.  最后，在`services/ProductService.js`文件中设置以下代码。由于在应用程序中资源是单例的，将资源与以下代码中使用的方法扩展起来：

    ```js
    var Shop;
    Shop = Shop || {};
    Shop.Services = Shop.Services || {};
    Shop.Services.ProductService = (function(Product) {
      var hasStock = function (product) {
        return product.stock() > 0;
      };

      var decreaseStock = function (product) {
        var s = product.stock();
        if (s > 0) {
          s--;
        }
        product.stock(s);
      };

      var clone = function (product) {
        return Product(product.id(), product.name(), product.price(), product.stock());
      };

      var refresh = function (product,newProduct) {
        product.name(newProduct.name());
        product.stock(newProduct.stock());
        product.price(newProduct.price());
      };

      return {
        hasStock:hasStock,
        decreaseStock:decreaseStock,
        clone:clone,
        refresh: refresh
      };
    })(Shop.Models.Product);
    ```

# 事件、绑定和 Knockout 组件

我们不打算模块化事件，因为它们是特定于此应用程序的。孤立非可移植的东西是没有意义的。我们也不会将绑定或组件模块化，因为它们被注入到 Knockout 对象中作为库的一部分，所以它们已经足够孤立，它们不是模块的一部分，而是 Knockout 对象的一部分。但我们需要更新所有这些文件中的依赖关系，因为应用程序的不同部分现在都隔离在`Shop`模块及其子模块中。

# 更新 add-to-cart-button 组件

要使用新命名空间更新组件，更新（覆盖）对依赖项的引用，如下所示：

```js
ko.components.register('add-to-cart-button', {
  viewModel: function(params) {
    this.item = params.item;
    this.cart = params.cart;
    this.addToCart = function() {
      var CartProduct = Shop.Models.CartProduct;
      var CartProductService = Shop.Services.CartProductService;
      var ProductService = Shop.Services.ProductService;

      var data = this.item;
      var tmpCart = this.cart();
      var n = tmpCart.length;
      var item = null;

      if(data.stock()<1) {
        return;
      }
      while(n--) {
        if (tmpCart[n].product.id() === data.id()) {
          item = tmpCart[n];
        }
      }
      if (item) {
        CartProductService.addUnit(item);
      } else {
        item = CartProduct(data,1);
        tmpCart.push(item);
        ProductService.decreaseStock(item.product);
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

# 更新事件

按照以下方式更新那些具有新模块依赖关系的代码行：

```js
(function() {
  "use strict";
  $(document).on("click","#confirmOrderBtn", function() {
    vm.showOrder();
  });
  $(document).on("click", ".add-unit", function() {
    var data = ko.dataFor(this);
    $(document).trigger("addUnit",[data]);
  });
  $(document).on("click", ".remove-unit", function() {
    var data = ko.dataFor(this);
    $(document).trigger("removeUnit",[data]);
  });
  $(document).on("addUnit",function(event, data){
    Shop.Services.CartProductService.addUnit(data);
  });
  $(document).on("removeUnit",function(event, data){
    Shop.Services.CartProductService.removeUnit(data);
  });
})();
```

您已经学会了一种非常好的模式，可以在没有任何外部工具的情况下管理依赖关系。您几乎可以在所有项目中使用它。如果您将所有文件合并到一个文件中，则其效果会更好。

本书不会涵盖如何合并和缩小文件以在生产环境中使用它们。合并和缩小文件可以提高应用程序的性能，因为缩小可以减少文件的大小，而合并可以减少 HTTP 调用的次数至一个。

要做到这一点，您可以使用 Node.js ([`nodejs.org/`](http://nodejs.org/)) 和一个构建模块，如 Grunt ([`gruntjs.com/`](http://gruntjs.com/)) 或 Gulp ([`gulpjs.com/`](http://gulpjs.com/))。如果您有兴趣了解诸如缩小、文件组合等部署实践，互联网上有大量关于 Node.js 和部署工具的参考文献。

要访问本章节代码的这一部分，请访问 GitHub 仓库：

[`github.com/jorgeferrando/knockout-cart/tree/chapter6Part1`](https://github.com/jorgeferrando/knockout-cart/tree/chapter6Part1)。

# 使用 RequireJS 来管理依赖关系

在上一节中，您学会了如何隔离代码的不同部分。您还按类型和组件名称对文件进行了分组，这遵循了一致的模式。但是，您还没有解决一个随着项目规模增大而增长的重要问题。为了给您一个关于这个问题是什么的提示，让我们来看看我们的`index.html`文件。查看`<script>`标签部分的部分：

```js
<script type="text/javascript" src="img/jquery.min.js"></script>
<script type="text/javascript" src="img/jquery.mockjax.js"></script>
<script type="text/javascript" src="img/jquery.mockjson.js"></script>
<script type="text/javascript" src="img/icheck.js"></script>
<script type="text/javascript" src="img/bootstrap.min.js"></script>
<script type="text/javascript" src="img/knockout.debug.js"></script>
...
...
...
<script type="text/javascript" src="img/ProductResource.js"></script>
<script type="text/javascript" src="img/OrderResource.js"></script>
<script type="text/javascript" src="img/viewmodel.js"></script>
<script type="text/javascript" src="img/cart.js"></script>
```

您需要手动维护所有这些文件之间的依赖关系。随着项目的增长，这样做的复杂性也在增加。因此，当您需要知道所有文件的依赖关系时，就会出现问题。这在小型项目中很容易处理，但在处理大型项目时，这可能是一场噩梦。此外，如果您在开始时加载所有文件，启动应用程序可能会受到惩罚。

要解决这个问题，有多个库可以帮助。我们将使用 RequireJS（有关更多信息，请参阅 [`requirejs.org/`](http://requirejs.org/)），它专注于异步加载脚本和管理依赖关系。它遵循 AMD 来编写不同的模块。这意味着它使用`define`和`require`语句来定义和加载不同的模块。AMD 库专注于应用程序的客户端，并在需要时帮助加载 JavaScript 模块。有关 AMD 的更多信息，请访问以下链接：

[`en.wikipedia.org/wiki/Asynchronous_module_definition`](http://en.wikipedia.org/wiki/Asynchronous_module_definition)

这非常有帮助，因为它优化了所发出请求的数量。这使得应用程序可以更快地启动，并且仅加载用户需要的模块。

还有另一种定义异步模块的模式，称为 CommonJS（在 [`requirejs.org/docs/commonjs.html`](http://requirejs.org/docs/commonjs.html) 中了解更多信息），它默认由 Node.js 模块使用。你可以在客户端应用程序中使用这个定义，使用 Node.js 和一个叫做 **browserify** 的库（在 [`browserify.org/`](http://browserify.org/) 中了解更多信息）。

在本书中，我们将专注于 RequireJS，因为它不需要 Node.js 或任何编译，并且在客户端应用程序中经常使用。

# 更新模板引擎

不幸的是，我们到目前为止使用的 `ExternalTemplateEngine` 不兼容 AMD。这就是为什么你应该使用其他解决方案。有一个叫做 amd-helpers 的 KnockoutJS 扩展。你可以从 [`github.com/rniemeyer/knockout-amd-helpers`](https://github.com/rniemeyer/knockout-amd-helpers) 下载它。Ryan Niemeyer 是这个扩展的作者。他是一个非常有名的 Knockout 开发者，在 Knockout 社区拥有很多粉丝。他有一个名为 Knockmeout 的博客 ([`knockmeout.net`](http://knockmeout.net))，上面有大量关于 Knockout 的文章以及如何使用 amd-helpers 库的良好示例。在本书中，我们只会使用模板引擎。但这个扩展有很多其他功能。

RequireJS 只是原生加载 JavaScript 文件。要异步加载 HTML 文件，请从 [`github.com/requirejs/text`](https://github.com/requirejs/text) 下载 text 扩展，并将其添加到 `vendors` 文件夹中。有了这个扩展，你可以加载任何类型的文件作为文本。

现在，当我们需要加载文本文件时，只需在文件路径前加上前缀 `text!`。

# 配置 RequireJS

要配置 RequireJS，请在与 `viewmodel.js` 文件位于相同级别的位置创建一个文件。你可以称之为 `main.js`，并按照以下步骤操作：

1.  定义基本的 `config` 方法：

    ```js
    require.config({

    });
    ```

1.  然后，定义脚本的基本 URL。这是 RequireJS 将查找脚本的地方：

    ```js
    Require.config({
    baseUrl:'js'
    });
    ```

1.  现在，在 `paths` 属性中为供应商库的路径定义别名。这样可以帮助你避免在模块依赖项中编写长路径。你不需要定义扩展名。RequireJS 会为你添加扩展名：

    ```js
    require.config({
      baseUrl:'js',
      paths: {
        bootstrap:'vendors/bootstrap.min',
        icheck: 'vendors/icheck',
        jquery: 'vendors/jquery.min',
        mockjax: 'vendors/jquery.mockjax',
        mockjson: 'vendors/jquery.mockjson',
        knockout  : 'vendors/knockout.debug',
        'ko.validation':'vendors/ko.validation',
        'ko-amd-helpers': 'vendors/knockout-amd-helpers',
        text: 'vendors/require.text'
      }
    });
    ```

1.  还要在 `shim` 属性内定义依赖项。这告诉 RequireJS 必须在加载库之前加载哪些文件：

    ```js
    require.config({
      baseUrl:'js',
      paths: {
        ...
      },
      shim: {
        'jquery': {
          exports: '$'
        },
        bootstrap: {
          deps:['jquery']
        },
        mockjax: {
          deps:['jquery']
        },
        mockjson: {
          deps:['jquery']
        },
        knockout: {
          exports: 'ko',
          deps:['jquery']
        },
        'ko.validation':{
          deps:['knockout']
        },
        'ko.templateEngine': {
            deps:['knockout']
        }
      },
    });
    ```

1.  定义配置完成后应调用的文件。在本例中，文件是 `app.js`。此文件将是应用程序的入口点，并触发项目启动时加载的所有依赖项：

    ```js
    //write this inside main.js file
    require.config({
      baseUrl:'js',
      paths: {...},
      shim: {...},
      deps: ['app']
    });
    ```

1.  现在，从 `index.html` 文件中删除所有 `<script>` 标签，并引用 `vendors/require.min.js` 文件。此文件使用 `data-main` 属性引用配置文件（`main.js`）。

    ```js
    <script type='text/javascript' src='vendors/require.min.js' data-main='main.js'></script>
    ```

# 在我们的项目中使用 RequireJS

要将我们的模块转换为 RequireJS 兼容的模块，我们将使用 AMD 规范对它们进行定义。该规范指出，要定义一个模块，需要调用`define`函数。该函数接收一个包含字符串的数组。这些字符串表示每个依赖项（模块中所需的文件）的配置文件中的路径或别名。

`define`函数需要的第二个参数是一个将返回模块的函数。此函数将从数组中的依赖项作为参数。使用这种模式的好处是，在加载所有依赖项之前，`define`函数内部的代码不会被执行。以下是`define`函数的样子：

```js
define(['dependency1','dependendency2'],function(dependency1,depencency2){
  //you can use depencencies here, not outside.
  var Module = //can be a literal object, a function.
  return Module; 
});
```

函数应该始终返回模块变量，或者模块需要返回的任何内容。如果我们没有设置`return`语句，模块将返回一个未定义的值。

# 定义 app.js 文件

当我们定义了 RequireJS 配置时，我们说入口点将是`app.js`文件。以下是创建`app.js`文件的步骤：

1.  创建`app.js`文件。

1.  设置依赖项数组。将这些依赖项映射为函数中的参数。有些文件只是执行代码，它们返回一个未定义的值。如果它们位于依赖项列表的末尾，你不需要映射这些文件。

    ```js
    define([
      //LIBRARIES
      'bootstrap',
      'knockout',
      'koAmdHelpers',
      'ko.validation',
      'icheck',

      //VIEWMODEL
      'viewmodel',

      //MOCKS
      'mocks/product',
      'mocks/order',

      //COMPONENTS
      'custom/components',

      //BINDINGS
      'custom/koBindings',

      //EVENTS
      'events/cart'
    ], function(bs, ko, koValidation, koAmdHelpers, 'iCheck', 'ViewModel) {
    });
    ```

1.  现在定义模块的主体。它将初始化全局配置和全局行为。最后，它将返回视图模型：

    ```js
    define([...],function(...){
      //ko External Template Settings
      ko.amdTemplateEngine.defaultPath = "../views";
      ko.amdTemplateEngine.defaultSuffix = ".html";
      ko.amdTemplateEngine.defaultRequireTextPluginName = "text";
      ko.validation.init({
        registerExtenders: true,
        messagesOnModified: true,
        insertMessages: true,
        parseInputAttributes: true
      });

      $( document ).ajaxError(function(event,response) {
        console.error(response);
        alert("Error in the communication. Check the console!");
      });

      vm.activate();

      return vm;
    });
    ```

第一个文件有很多依赖项，我们应该保持有序。首先我们定义了库，然后是视图模型，模拟，组件，最后是事件。这些文件中的每一个也应该被定义为模块；当它们被调用时，依赖项将被加载。

注意我们如何更新了模板引擎的定义：`defaultPath` 值用于定义模板所在的位置，`defaultSuffix` 值用于定义模板的扩展名，以及用于加载模板的库（在我们的情况下是 text）。现在，我们应该将这个模式应用到其余的文件中。

# 将普通模块转换为 AMD 模块

要转换普通模块，我们将执行以下步骤。始终对我们所有的模块应用相同的步骤。我们需要将它们包装到`define`函数中，列出依赖项，并返回我们在旧模块中返回的模块。

1.  打开`viewmodel.js`文件。

1.  创建`define`函数：

    ```js
    define([],function(){});
    ```

1.  添加所有依赖项：

    ```js
    define([
      'knockout',
      'models/Product',
      'models/Customer',
      'models/CartProduct',
      'services/ProductService',
      'services/CartProductService',
      'resources/ProductResource',
      'resources/OrderResource'
    ],function (ko, Product, Customer, ProductService, CartProductService, ProductResource, OrderResource) {
    });
    ```

1.  导出模块到`define`函数中：

    ```js
    define([],function(){
      var debug = ko.observable(false);
      var showDebug = function () {
        debug(true);
      } 
      ...
      var activate = function () {
        ProductResource.all()
          .done(allCallbackSuccess.bind(this));
      };
      return {
        debug: debug,
        showDebug:showDebug,
        hideDebug:hideDebug,
        ...
      };
    });
    ```

当我们将`knockout`作为依赖项时，RequireJS 将检查配置以找到别名。如果别名不存在，则它将查找我们在`baseUrl`属性中设置的路径。

现在我们应该更新所有使用这种模式的文件。注意，应该设置为依赖项的元素与我们使用模块模式设置的元素相同。

# 将 RequireJS 应用到组件

我们没有在本章的第二部分中将我们的绑定和组件模块化。但这并不意味着我们不能。

我们不仅可以使用 RequireJS 创建模块，还可以异步加载文件。在我们的情况下，绑定和组件不需要返回对象。当加载这些文件时，它们扩展了 `ko` 对象并完成了它们的工作。事件也是如此。我们初始化事件并完成工作。因此，这些文件只需要被包装到 `define` 函数中。添加依赖项并像在上一节中那样在 `app.js` 文件中加载它们。

对于 `add-to-cart-button` 组件，在文件中的代码将是以下内容：

```js
define([
  'knockout',
  'models/CartProduct',
  'services/CartProductService',
  'services/ProductService'
],function(ko, CartProduct,CartProductService,ProductService){
  ko.components.register('add-to-cart-button', {
    ...
  });
});
```

# 将 RequireJS 应用于模拟

在模拟的情况下，我们需要如下引入 Mockjax 和 Mockjson 库：

```js
define([
  'jquery',
  'mockjson',
  'mockjax'
], function ($, mockjson, mockjax) {
  $.mockJSON.data.PRODUCTNAME = [
    'T-SHIRT', 'SHIRT', 'TROUSERS', 'JEANS', 'SHORTS', 'GLOVES', 'TIE'
  ];
  ...
});
```

# 将 RequireJS 应用于绑定

绑定易于转换。它们只有 jQuery 和 Knockout 依赖项，如下所示：

```js
define(['knockout','jquery'],function(ko, $){
  //toggle binding
  ko.bindingHandlers.toggle = { ... };
  ...
});
```

# 将 RequireJS 应用于事件

最后，我们需要更新 `events/cart.js` 文件。确认订单事件需要更新视图模型。我们可以将 `viewmodel` 作为依赖项并访问其公共接口：

```js
define([
  'jquery','viewmodel','services/CartProductService'
], function(vm, CartProductService) {
  "use strict";
  $(document).on("click","#confirmOrderBtn", function() {
    vm.showOrder();
  });

  $(document).on("click", ".add-unit", function() {
    var data = ko.dataFor(this);
    $(document).trigger("addUnit",[data]);
  });

  $(document).on("click", ".remove-unit", function() {
    var data = ko.dataFor(this);
    $(document).trigger("removeUnit",[data]);
  });

  $(document).on("addUnit",function(event, data){
    CartProductService.addUnit(data);
  });

  $(document).on("removeUnit",function(event, data){
    CartProductService.removeUnit(data);
  });
});
```

# 应用程序的限制

最后我们有了一个模块化的应用程序。尽管如此，它有一些限制：

+   浏览器的后退和前进按钮的行为是什么？如果我们尝试使用它们，我们的应用程序不会按预期工作。

+   如果我们想将我们的应用程序分成多个页面，我们总是需要在同一个页面中显示和隐藏模板吗？

正如您所看到的，还有很多工作要做。Knockout 很好，但也许它需要与其他库合作来解决其他问题。

在本章中开发的代码副本位于 [`github.com/jorgeferrando/knockout-cart/tree/chapter6RequireJS`](https://github.com/jorgeferrando/knockout-cart/tree/chapter6RequireJS)。

# 总结

在本章中，您学习了如何在我们的项目中构建模块以及如何按需加载文件。

我们谈论了模块模式和 AMD 规范来构建模块。您还学习了如何使用 Chrome 扩展程序 Knockout 上下文调试器 调试 KnockoutJS 应用程序。

最后，我们发现当应用程序变得更大时，它将需要许多库来满足所有需求。RequireJS 是一个帮助我们管理依赖关系的库。Knockout 是一个帮助我们在项目中轻松应用 MVVM 模式的库，但是大型应用程序需要 Knockout 无法提供的其他功能。

在接下来的两章中，您将学习一个称为 Durandal 的框架。这个框架使用 jQuery、Knockout 和 RequireJS 来应用 MVVM 模式。此外，Durandal 提供了更多模式来解决其他问题，如路由和导航，并通过插件和小部件实现了添加新功能的能力。我们可以说 Durandal 是 KnockoutJS 的大哥。
