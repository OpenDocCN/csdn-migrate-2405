# Aurelia 学习手册（二）

> 原文：[`zh.annas-archive.org/md5/31FCE017BF58226A6BEEA3734CAADF0F`](https://zh.annas-archive.org/md5/31FCE017BF58226A6BEEA3734CAADF0F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：显示数据

为了渲染视图，Aurelia 依赖于两个核心库：`aurelia-templating`，它提供了一个丰富且可扩展的模板引擎，以及`aurelia-binding`，它是一个现代且适应性强的数据绑定库。由于模板引擎依赖于数据绑定的抽象，这意味着可以使用 Aurelia 之外的数据绑定库，`aurelia-templating-binding`库充当了两者之间的桥梁。此外，`aurelia-templating-resources`建立在模板引擎之上，定义了一组标准行为和组件。

在本章中，我们将介绍数据绑定和模板的基础知识。我们将了解 Aurelia 提供的标准行为以及如何在视图中使用它们。

在渲染任何数据之前，首先必须获取它。大多数时候，单页网络应用程序依赖于某种类型的网络服务。因此，我们将了解 Fetch API 是什么，如何使用 Aurelia 的 Fetch 客户端，以及如何配置它。

最后，在关闭本章之前，我们将把我们新学到的知识应用到我们的联系人管理应用程序中，通过添加视图来显示联系人列表和联系人的详细信息。

# 模板基础

模板是一个根元素为`template`元素的 HTML 文件。它必须是有效的 HTML，因为模板引擎依赖于浏览器解析该文件并从中构建一个 DOM 树，然后引擎将遍历、分析和丰富行为。

这意味着适用于 HTML 文件的限制也适用于任何 Aurelia 模板。例如，`table`元素只能作为子元素包含某些类型的元素，如`thead`、`tbody`或`tr`。因此，以下模板在大多数浏览器中是非法的：

```js
<template> 
  <table> 
    <compose view="table-head.html"></compose>  
  </table> 
</template> 

```

在这里，我们想要使用在后面小节中介绍的`compose`元素，以插入包含表头的视图。由于`compose`不是`table`的有效子元素，大多数浏览器在解析 HTML 文件时会忽略它，因此模板引擎无法看到它。

为了克服这些限制，Aurelia 寻找一个特殊的`as-element`属性。这个属性作为元素名称的别名供模板引擎使用：

```js
<template> 
  <table> 
    <thead as-element="compose " view="table-head.html"></thead> 
  </table> 
</template> 

```

在这里，将元素名称从`compose`更改为`thead`使其成为一个合法的 HTML 片段，并添加`as-element="compose"`属性告诉 Aurelia 的模板引擎将这个`thead`元素视为一个`compose`元素。

## 视图资源

视图资源是可供模板引擎使用的工件，因此它们可以被模板使用。例如，自定义元素或值转换器是资源。

正如我们在前一章中看到的那样，资源可以全局加载，例如通过应用程序的`configure`方法、通过插件或通过特性。这样的资源对应用程序中的每个模板都可用。

### 本地加载资源

除了全局资源外，每个模板都有自己的资源集。一个需要使用一个在全球范围内不可用的资源的模板必须首先加载它。这通过使用`require`元素来实现：

`src/some-module/some-template.html`

```js
<template> 
  <require from="some-resource"></require> 
  <!-- at this point, some-resource is available to the template --> 
</template> 

```

`from`属性必须是要加载的资源的路径。在前一个示例中，路径是相对于代码根目录的，通常是指向`src`目录。这意味着`some-resource`预期直接位于`src`中。然而，路径也可以通过使用`.`前缀来使其相对于当前模板文件所在的目录：

`src/some-module/some-template.html`

```js
<template> 
  <require from="./some-resource"></require> 
</template> 

```

在这个例子中，`some-resource`预期位于`src/some-module`目录中。

此外，可以指定`as`属性。它用于更改资源的本地名称，以解决与其他资源的名字冲突，例如：

```js
<template> 
  <require from="some-resource" as="another-resource"></require> 
</template> 

```

在这个例子中，`some-resource`作为`another-resource`在模板中可用。

### 资源类型

默认情况下，预期资源是一个 JS 文件，在这种情况下，路径应该排除`.js`扩展名。例如，要加载从`sort.js`文件导出的值转换器，模板只需要求`sort`。无论资源类型是什么，值转换器、绑定行为、自定义元素等等，除了用作自定义元素的模板之外，都是正确的。

稍后我们将看到如何创建自定义元素。我们还将看到在没有视图模型的情况下如何创建仅包含模板的组件，当一个组件没有行为时。在这种情况下，作为资源加载时，仅包含模板的组件必须使用其完整文件名（包括其扩展名）来引用。例如，要加载一个名为`menu.html`的仅包含模板的组件，我们需要要求`menu.html`，而不仅仅是`menu`。否则，模板引擎将不知道它在寻找一个 HTML 文件而不是一个 JS 文件，并尝试加载`menu.js`。当我们开始将应用程序拆分为组件时，我们将看到这个的真实示例。

## 加载 CSS

除了本地加载模板资源外，`require`元素还可以用来加载样式表：

`src/my-component.html`

```js
<template> 
  <require from="./my-component.css"></require> 
</template> 

```

在这个例子中，`my-component.css`样式表将被加载并添加到文档的头部。

此外，可以使用`as="scoped"`属性将样式表的作用域限定在组件内：

`src/my-component.html`

```js
<template> 
  <require from="./my-component.css" as="scoped"></require> 
</template> 

```

在这个第二个例子中，如果`my-component`使用 ShadowDOM，并且浏览器支持它，样式表将被注入到 ShadowDOM 根部。否则，它将被注入到组件的视图中，并将`scoped`属性设置到`style`元素。

### 注意

影子 DOM 是一个 API，它允许我们在 DOM 中创建孤立的子树。这样的子树可以加载它们自己的样式表和 JavaScript，并与周围文档的冲突风险无关。这项技术对于无痛开发 Web 组件至关重要，但在撰写本文时，它仍然没有得到广泛浏览器的支持。

在`style`元素上的`scoped`属性告诉浏览器将样式表的作用域限制在包含元素及其后代元素上。这防止样式与其他文档部分发生冲突，而无需使用 ShadowDOM 根。它是 ShadowDOM 的有用替代品，但仍然没有得到广泛浏览器的支持。

# 数据绑定

数据绑定是将模板元素使用表达式与数据模型链接起来的动作，数据模型是一个 JS 对象。这个数据模型称为绑定上下文。这个上下文由 Aurelia 用于例如，暴露组件视图模型的属性和方法给其模板。此外，以下部分描述的一些行为会在其绑定上下文中添加信息。

## 绑定模式

数据绑定支持三种不同的模式：

+   **单向**：该表达式最初被评估，并且应用了说明并在视图中渲染。该表达式被观察，因此，无论其值如何变化，都可以重新评估，说明可以更新视图。它的变化只流向一个方向，从模型流向视图。

+   **双向**：与单向类似，但更新既可以从模型流向视图，也可以从视图流向模型：如果模板元素（如`input`）通过用户交互发生变化，模型就会被更新。它的变化是双向的，从模型流向视图，以及从视图流向模型。

    ### 注意

    当然，双向绑定限制了可以绑定的表达式的种类。只有可赋值表达式（通常是可以在 JavaScript 赋值指令的等号（`=`）操作符左侧使用的表达式）可以用于双向绑定。例如，你不能双向绑定到一个条件三元表达式或一个方法调用。

+   **一次性**：该表达式最初被评估，并且应用了说明，但该表达式不会被观察，因此任何在初始渲染后发生的模型变化都不会在视图中反映出来。绑定只会在视图渲染时从模型流向视图，只有一次。

## 字符串插值

构建模板时最基本的需求是显示文本。这可以通过使用字符串插值来实现：

```js
<template> 
  <h1>Welcome ${user.name}!</h1> 
</template> 

```

与 ES2015 的字符串插值类似，Aurelia 模板中的此类说明在`${`和`}`之间评估表达式，并将结果作为文本插入到 DOM 中。

字符串插值可以与更复杂的表达式一起使用：

```js
<template> 
  <h1>Welcome ${user ? user.name : 'anonymous user'}!</h1> 
</template> 

```

这里，我们使用三元表达式在绑定上下文中定义用户时显示用户的名字，否则显示通用信息。

它也可以用在属性内部：

```js
<template> 
  <h1 class="${isFirstTime ? ' emphasis' : ''}">Welcome!</h1> 
</template> 

```

在这个例子中，我们使用三元表达式在`model`的`isFirstTime`属性为真时，有条件地将`emphasis` CSS 类分配给`h1`元素。

默认情况下，字符串插值指令被绑定单向。这意味着，无论表达式的值如何变化，它都将被重新评估并在文档中更新。

## 数据绑定命令

当分析模板中的一个元素时，模板引擎会寻找带有数据绑定命令的属性。数据绑定命令是附加在属性后面，由点分隔的。它指导引擎对这个属性执行某种数据绑定。它有以下形式：`attribute.command="expression"`。

让我们来看看 Aurelia 提供的各种绑定命令。

### 绑定（bind）

`bind`命令将属性的值解释为表达式，并将这个表达式绑定到属性本身：

```js
<template> 
  <a href.bind="url">Go</a> 
</template> 

```

在这个例子中，绑定上下文中`url`属性的值将被绑定到`a`元素的`href`属性上。

`bind`命令是自适应的。它根据其目标元素和属性选择其绑定模式。默认情况下，它使用单向绑定，除非目标属性可以通过用户交互更改：例如`input`的`value`。在这种情况下，`bind`执行双向绑定，因此用户引起的变化会在模型上得到反映。

### 单向（One-way）

类似于`bind`，这个命令执行数据绑定，但不适应其上下文；绑定被强制为单向，无论目标类型如何。

### 双向（Two-way）

类似于`bind`，这个命令执行数据绑定，但不适应其上下文，绑定被强制为双向，无论目标类型如何。当然，将这个命令应用于自身无法更新的属性是毫无意义的。

### 一次性（One-time）

类似于`bind`，这个命令执行数据绑定，但强制进行一次性绑定，意味着在初始渲染之后模型中的任何变化都不会在视图中反映出来。

### 注意（Note）

你可能已经推断出一次性绑定比提供的实时绑定（单向和双向绑定）要轻量得多。确实，因为实时绑定需要观察，所以它更消耗 CPU 和内存。在一个大型应用程序中，如果有很多数据绑定指令，尽可能使用一次性绑定会在性能上产生巨大的不同。这就是为什么尽可能坚持使用一次性绑定，并在必要时才使用实时绑定被认为是一个好习惯。

### 触发器（trigger）

`trigger`命令将事件绑定到表达式，每次事件被触发时该表达式将被评估。`Event`对象作为`$event`变量可供表达式使用：

```js
<template> 
  <button click.trigger="open($event)">Open</button> 
</template> 

```

在这个例子中，`button` 的 `click` 事件将触发对绑定上下文的 `open` 方法的调用，并将 `Event` 对象传递给它。当然，使用 `$event` 是完全可选的；在这里，点击处理器可以是 `open()`，在这种情况下，`Event` 对象将被简单忽略。

请注意，事件名称不带 `on` 前缀：属性名称为 `click`，而不是 `onclick`。

### delegate

与直接在目标元素上附加事件处理器的 `trigger` 命令不同，`delegate` 利用事件委托，通过将一个处理程序附加到文档或最近的 ShadowDOM 根元素上来实现。这个处理程序会将事件分派到它们正确的目标，以便评估绑定的表达式。

与 `trigger` 一样，`Event` 对象作为 `$event` 变量 available 给表达式，属性名中必须省略 `on` 前缀。

### 注意

与直接附加到目标元素的事件处理程序相比，事件委托消耗的内存要少得多。就像一次性绑定与实时绑定一样，在小型应用程序中使用委托几乎不会注意到任何差异，但随着应用程序的大小增长，它可能会对内存足迹产生影响。另一方面，直接将事件处理程序附加到元素上是某些场景所必需的，尤其是当禁用冒泡时要触发自定义事件。

### call

`call` 命令用于将一个包含表达式的函数绑定到自定义属性或自定义元素的结构。当发生特定事件或满足给定条件时，这些自定义行为可以调用该函数来评估包装的表达式。

此外，自定义行为可以传递一个参数对象，此对象上的每个属性都将在此表达式的上下文中作为变量可用：

```js
<template> 
  <person-form save.call="createPerson(person)"></person-form> 
</template> 

```

在这里，我们可以想象有一个带有 `save` 属性的 `person-form` 自定义元素。在这个模板中，我们将 `person-form` 的 `save` 属性绑定到一个包含对模型 `createPerson` 方法的调用的函数，并向其传递表达式作用域上 `person` 变量的值。

然后 `person-form` 视图模型会在某个时刻调用这个函数。传递给这个函数的参数对象将在此表达式的上下文中可用：

```js
this.save({ person: this.somePersonData }); 

```

在这里，`person-form` 视图模型调用绑定在 `save` 属性上的函数，并向其传递一个 `person` 参数。

显然，这个命令在与原生 HTML 元素一起使用时是没有用的。

当我们覆盖自定义元素的制作时，我们会看到这个命令更具体的例子。

### ref

`ref` 命令可用于将 HTML 元素或组件部分的引用分配给绑定上下文。如果模板或视图模型需要访问模板中使用的 HTML 元素或组件的某部分，这可能很有用。

在以下示例中，我们首先使用 `ref` 将模型上的 `input` 元素分配为 `nameInput`，然后使用字符串插值实时显示这个 `input` 的 `value`：

```js
<template> 
  <input type="text" ref="nameInput"> 
  <p>Is your name really ${nameInput.value}?</p> 
</template> 

```

`ref`命令必须用于一组特定的属性：

+   `element.ref="someProperty"`（或`ref="someProperty"`的简写）将在绑定上下文中创建一个名为`someProperty`的属性，引用一个 HTML 元素

+   当放在具有`some-attribute`自定义属性的元素上时，`some-attribute.ref="someProperty"`将在绑定上下文中创建一个属性，名为`someProperty`，引用这个自定义属性的视图模型

+   当放在自定义元素上时，`view-model.ref="someProperty"`将在绑定上下文中创建一个属性，名为`someProperty`，引用自定义元素的视图模型

+   当放在自定义元素上时，`view.ref="someProperty"`将在绑定上下文中创建一个属性，名为`someProperty`，引用自定义元素的`view`实例

+   当放在自定义元素上时，`controller.ref="someProperty"`将在绑定上下文中创建一个属性，名为`someProperty`，引用自定义元素的两个`Controller`实例

## 绑定字面量

模板引擎将所有没有命令的属性的值解释为字符串。例如，一个`value="12"`属性将被解释为一个`'12'`字符串。

一些组件可能具有需要特定值类型的属性，例如布尔值、数字，甚至是数组或对象。在这种情况下，您应该使用数据绑定强制模板引擎将表达式解释为适当的类型，即使该表达式是一个字面值，且永远不会改变。例如，一个`value.bind="12"`属性将被解释为数字`12`。

类似地，一个`options="{ value: 12 }"`属性将被解释为一个`'{ value: 12 }'`字符串，而`options.bind="{ value: 12 }"`属性将被解释为一个包含`value`属性的数字`12`的对象。

当然，当数据绑定到字面值时，最好使用`one-time`而不是`bind`，以减少应用程序的内存占用。

## 使用内置绑定上下文属性

每个绑定上下文都公开了两个可能在某些场景中有用的属性：

+   `$this`: 一个自引用的属性。它包含对上下文本身的引用。它可能很有用，例如，将整个上下文传递给一个方法，或者在组合时将其注入到组件中。

+   `$parent`: 一个引用父级绑定上下文的属性。它可能很有用，例如，在`repeat.for`属性的作用域内访问被子上下文覆盖的父上下文的一个属性。它可以通过链式调用向上追溯到绑定上下文树更高层。例如，调用`$parent.$parent.$parent.name`将尝试访问曾祖上下文的`name`属性。

## 绑定到 DOM 属性

一些标准 DOM 属性通过 Aurelia 暴露为属性，因此它们可以进行数据绑定。

### `innerhtml`

`innerhtml`属性可用于数据绑定到元素的`innerHTML`属性：

```js
<template> 
  <div innerhtml.bind="htmlContent"></div> 
</template> 

```

在这个例子中，我们可以想象模型的`htmlContent`属性将包含 HTML 代码，这些代码与`div`的`innerHTML`属性数据绑定，将在`div`内部显示。

然而，这 HTML 不被认为是模板，所以它不会被模板引擎解释。如果它包含绑定表达式或需要指令，例如，它们不会被评估。

显示用户生成的 HTML 是一个众所周知的安全风险，因为它可能包含恶意脚本。强烈建议在向任何用户显示之前对这种 HTML 进行消毒。

`aurelia-templating-resources`附带一个简单的值转换器（我们将在本章后面看到值转换器是什么），名为`sanitizeHTML`，它用于这个目的。然而，强烈建议使用更完整的消毒器，如`sanitize-html`，可以在[`www.npmjs.com/package/sanitize-html`](https://www.npmjs.com/package/sanitize-html)找到。

### textcontent

`textcontent`属性可用于数据绑定到元素的`textContent`属性：

```js
<template> 
  <div textcontent.bind="text"></div> 
</template> 

```

在这个例子中，我们可以想象模型的`text`属性将包含一些文本，这些文本与`div`的`textContent`属性数据绑定，将在`div`内部显示。

与`innerhtml`类似，绑定到`textcontent`的文本不被认为是模板，所以它不会被模板引擎解释。

如前所述，`bind`命令试图检测它应该使用哪种绑定模式。因此，如果元素的`contenteditable`属性设置为`true`，则`textcontent`上的`bind`命令将使用双向绑定：

```js
<template> 
  <div textcontent.bind="text" contenteditable="true"></div> 
</template> 

```

在这个例子中，模型的`text`属性将被绑定到`div`的`textContent`属性并在`div`内部显示。另外，由于`div`的内容是可编辑的，用户对这部分内容所做的任何更改都将反映在模型的`text`属性上。

### style

`style`属性可用于数据绑定到元素的`style`属性。它可以绑定到一个字符串或一个对象：

```js
some-component.js 
export class ViewModel { 
  styleAsString = 'font-weight: bold; font-size: 20em;'; 
  styleAsObject = { 
    'font-weight': 'bold', 
    'font-size': '20em' 
  }; 
} 
some-component.html 
<template> 
  <div style.bind="styleAsString"></div> 
  <div style.bind="styleAsObject"></div> 
</template> 

```

另外，`style`属性可以使用字符串插值。然而，由于一些技术限制，它不支持 Internet Explorer。为了解决这个问题，并确保应用程序与 IE 兼容，在使用字符串插值时应使用`css`别名：

```js
<template> 
  <div css="color: ${color}; background-color: ${bgColor};"></div> 
</template> 

```

在这里，`div`将把其`color`和`background-color`样式与模型的`color`和`bgColor`属性数据绑定。

### scrolltop

`scrolltop`属性可用于绑定到元素的`scrollTop`属性。默认支持双向绑定，该属性可用于更改元素的的水平滚动位置，或者将其位置分配给上下文中的属性以便使用。

### scrollleft

`scrollleft`属性可以用来绑定到元素的`scrollLeft`属性。默认双向绑定，这个属性可以用来更改元素的垂直滚动位置，或者将其位置分配给上下文中的一个属性以便使用。

# 使用内置行为

核心库`aurelia-templating-resources`提供了一组标准行为，基于`aurelia-templating`构建，可以在 Aurelia 模板中使用。

## show

`show`属性根据它所绑定的表达式的值来控制元素的可见性：

```js
<template> 
  <p show.bind="hasError">An error occurred.</p> 
</template> 

```

在这个例子中，只有当模型的`hasError`属性为 truthy 时，`p`元素才会可见。

这个属性通过在文档头部或最近的 ShadowDOM 根中注入 CSS 类，并在元素应该隐藏时添加这个 CSS 类来工作。这个 CSS 类简单地将`display`属性设置为`none`。

## hide

这与`show`类似，但条件是倒置的：

```js
<template> 
  <p hide.bind="isValid">Form is invalid.</p> 
</template> 

```

在这个例子中，当模型的`isValid`属性为 truthy 时，`p`元素将隐藏。

除了倒置条件之外，这个属性的工作方式与`show`完全一样，并使用相同的 CSS 类。

## if

`if`属性与`show`非常相似。主要区别在于，当绑定的表达式评估为`false`值时，它不是简单地隐藏元素，而是完全将元素从 DOM 中移除。

```js
<template> 
  <p if.bind="hasError">An error occurred.</p> 
</template> 

```

由于`if`属性是一个模板控制器，因此可以直接放在嵌套的`template`元素上，以控制多个元素的可见性：

```js
<template> 
  <h1>Some title</h1> 
  <template if.bind="hasError"> 
    <i class="fa fa-exclamation-triangle"></i> 
    An error occurred. 
  </template> 
</template> 

```

在这个例子中，当`hasError`为`false`时，`i`元素及其后面的文本将从 DOM 中移除。

实际上，当条件为 falsey 时，它所附加的元素不仅会被从 DOM 中移除，它自己的行为和其子元素的行为也会被解绑。这是一个非常重要的区别，因为它有重大的性能影响。

以下示例中，假设`some-component`非常大，显示大量数据，有许多绑定，并且非常耗内存和 CPU。

```js
<template> 
  <some-component if.bind="isVisible"></some-component> 
</template> 

```

如果我们在这里用`show`替换`if`，整个组件层次结构的数据绑定仍然存在，即使它不可见也会消耗内存和 CPU。当使用`if`时，当`isVisible`变为`false`，组件将解绑，减少应用程序中的活动绑定数量。

另一方面，这意味着当条件变为 truthy 时，元素及其后代必须重新绑定。在条件经常开关的场景中，使用`show`或`hide`可能更好。选择`if`和`show`/`hide`之间的主要问题是平衡性能和用户体验的优先级，并且应该有真实的性能测试支持。

### 注意

模板控制器是一个属性，它将所作用的元素转换成模板，并控制这个模板的渲染方式。标准的属性`if`和`repeat`是模板控制器。

## repeat.for

`repeat`属性与特殊的`for`绑定命令一起使用时，可以用来为一系列值重复一个元素：

```js
<template> 
  <ul> 
    <li repeat.for="item of items">${item.title}</li> 
  </ul> 
</template> 

```

在这个例子中，`li`元素将被重复并绑定到`items`数组中的每个项目：

instead of an array, a `Set` object can also be data-bound too.

作为一个模板控制器，`repeat`实际上将所作用的元素转换成一个模板。然后为绑定序列中的每个项目渲染这个模板。对于每个项目，将创建一个子绑定上下文，在该上下文中，通过绑定表达式中`of`关键字左边的名称来使用项目本身。这意味着两件事：您可以随意命名项目变量，而且您可以在项目的上下文中使用它：

```js
<template> 
  <ul> 
    <li repeat.for="person of people"  
        class="${person.isImportant ? 'important' : ''}"> 
      ${person.fullName} 
    </li> 
  </ul> 
</template> 

```

在这个例子中，`li`元素将被插入到`ul`元素中，为`people`数组中的每个项目。对于每个`li`元素，将创建一个子上下文，将当前项目作为`person`属性暴露出来，如果对应的`person`的`isImportant`属性，那么`li`上会设置一个`important` CSS 类。每个`li`元素将包含其`person`的`fullName`，作为文本。

此外，由`repeat`创建的子上下文从周围上下文继承，所以`li`元素外的任何可用属性在内部都是可用的：

```js
<template> 
  <ul> 
    <li repeat.for="person of people"  
        class="${person === selectedPerson ? 'active' : ''}"> 
      ${person.fullName} 
    </li> 
  </ul> 
</template> 

```

在这里，根绑定上下文暴露了两个属性：一个`people`数组和`selectedPerson`。当每个`li`元素被渲染时，每个子上下文都可以访问当前的`person`以及父上下文。这就是`li`元素对于`selectedPerson`将具有`active` CSS 类的原因。

`repeat`属性默认使用单向绑定，这意味着绑定数组将被观察，对其进行的任何更改都将反映在视图中：

如果向数组中添加一个项目，模板将被渲染成一个额外的视图，并插入到 DOM 中的适当位置。

如果从数组中删除一个项目，相应的视图元素将被从 DOM 中删除。

### 绑定到地图

`repeat`属性能够与`map`对象一起使用，使用稍微不同的语法：

```js
<template> 
  <ul> 
    <li repeat.for="[key, value] of map">${key}: ${value}</li> 
  </ul> 
</template> 

```

在这里，`repeat`属性将为`map`中的每个条目创建一个分别具有`key`和`value`属性的子上下文，分别与`map`条目的`key`和`value`匹配。

重要的是要记住，这种语法只适用于`map`对象。在前一个示例中，如果`map`不是`Map`实例，那么在子绑定上下文中就不会定义`key`和`value`属性。

### 重复 n 次

`repeat`属性还可以在绑定到数值时使用标准语法重复一个模板给定次数：

```js
<template> 
  <ul class="pager"> 
    <li repeat.for="i of pageCount">${i + 1}</li> 
  </ul> 
</template> 

```

在这个例子中，假设 `pageCount` 是一个数字，`li` 元素将被重复多次，次数等于 `pageCount`，`i` 从 `0` 到 `pageCount - 1` 包括在内。

### 重复模板

如果需要重复的元素由多个没有每个项目单一容器的元素组成，可以在 `template` 元素上使用 `repeat`：

```js
<template> 
  <div> 
    <template repeat.for="item of items"> 
      <i class="icon"></i> 
      <p>${item}</p> 
    </template> 
  </div> 
</template> 

```

在这里，渲染后的 DOM 是一个包含交替 `i` 和 `p` 元素的 `div` 元素。

### 上下文变量

除了当前项目本身，`repeat` 还在子绑定上下文中添加了其他变量：

+   `$index`：项目在数组中的索引

+   `$first`：如果项目是数组的第一个，则为 `true`；否则为 `false`

+   `$last`：如果项目是数组的最后一个，则为 `true`；否则为 `false`

+   `$even`：如果项目的索引是偶数，则为 `true`；否则为 `false`

+   `$odd`：如果项目的索引是奇数，则为 `true`；否则为 `false`

## `with` 属性

`with` 属性通过它绑定的表达式创建一个子绑定上下文。它可以用来重新作用域模板的一部分，以防止访问路径过长。

例如，以下模板没有使用 `with`，在访问其属性时 `person` 被多次遍历：

```js
<template> 
  <div> 
    <h1>${person.firstName} ${person.lastName}</h1> 
    <h3>${person.company}</h3> 
  </div> 
</template> 

```

通过将顶层的 `div` 元素重新作用域为 `person`，可以简化对其属性的访问：

```js
<template> 
  <div with.bind="person"> 
    <h1>${firstName} ${lastName}</h1> 
    <h3>${company}</h3> 
  </div> 
</template> 

```

前面的例子很短，但你可以想象一个更大的模板如何从中受益。

此外，由于 `with` 创建了一个子上下文，外层作用域中所有可用的变量都将可在内层作用域中访问。

## 焦点属性

`focus` 属性可用于将元素的所有权与文档的焦点绑定到表达式。它默认使用双向绑定，这意味着当元素获得或失去 `focus` 时，它所绑定的变量将被更新。

以下代码片段摘自 `samples/chapter-3/binding-focus`：

```js
<template> 
  <input type="text" focus.bind="hasFocus"> 
</template> 

```

在 previous example，如果 `hasFocus` 是 `true`，则在渲染时 `input` 将会获得焦点。当 `hasFocus` 变为 `false` 值时，`input` 将会失去 `focus`。此外，如果用户将 `focus` 给予 `input`，`hasFocus` 将被设置为 `true`。类似地，如果用户将焦点从 `input` 移开，`hasFocus` 将被设置为 `false`。

## 组合元素

组合是将组件实例化并插入视图中的动作。`aurelia-templating-resources` 库导出一个 `compose` 元素，允许我们在视图中动态组合组件。

### 注意

以下各节中的代码片段摘自 `samples/chapter-3/composition`。在阅读本节时，你可以并行运行示例应用程序，这样你就可以查看组合的实时示例。

### 渲染视图模型

组件可以通过引用其视图模型的 JS 文件路径来组合：

```js
<template> 
  <compose view-model="some-component"></compose> 
</template> 

```

在这里，当渲染时，`compose` 元素将加载 `some-component` 的视图模型，实例化它，定位其模板，渲染视图，并将其插入到 DOM 中。

当然，`view-model`属性可以绑定或使用字符串插值：

```js
<template> 
  <compose view-model="widgets/${currentWidgetType}"></compose> 
</template> 

```

在这个例子中，`compose`元素将根据当前绑定上下文中的`currentWidgetType`属性的值，显示位于`widgets`目录中的组件。当然，这意味着当`currentWidgetType`发生变化时，compose 将交换组件（除非使用了一次性绑定）。

此外，`view-model`属性可以绑定到视图模型的实例：

`src/some-component.js`

```js
import {AnotherComponent} from 'another-component'; 

export class SomeComponent { 
  constructor() { 
    this.anotherComponent = new AnotherComponent(); 
  } 
} 

```

在这里，一个组件导入并实例化了另一个组件的视图模型。在其模板中，`compose`元素可以直接绑定到`AnotherComponent`的实例：

`src/some-component.html`

```js
<template> 
  <compose view-model.bind="anotherComponent"></compose> 
</template> 

```

当然，这意味着，如果`anotherComponent`被分配了一个新值，`compose`元素将相应地反应，并用新的一个替换掉之前的组件视图。

### 传递激活数据

当渲染组件时，组合引擎将尝试调用组件上存在的`activate`回调方法。与路由器的屏幕激活生命周期方法类似，这个方法可以被组件实现，以便在它们被渲染时可以行动。它还可以用来将激活数据注入组件。

`compose`元素也支持`model`属性。如果有的话，这个属性的值将被传递给组件的`activate`回调方法。

让我们想象一下以下的组件：

`src/some-component.js`

```js
export class SomeComponent { 
  activate(data) { 
    this.activationData = data || 'none'; 
  } 
} 
src/some-component.html 
<template> 
  <p>Activation data: ${activationData}</p> 
</template> 

```

当没有任何`model`属性时，这个组件将显示`<p>Activation data: none</p>`。然而，当像这样组成时，它会显示`<p>Activation data: Some parameter</p>`：

```js
<template> 
  <compose view-model="some-component" model="Some parameter"></compose> 
</template> 

```

当然，`model`可以使用字符串插值，也可以进行数据绑定，因此可以将复杂对象传递给组件的`activate`方法。

当与未实现`activate`方法的组件一起使用时，`model`属性的值将被直接忽略。

### 渲染模板

`compose`元素还可以简单地渲染一个模板，使用当前的绑定上下文：

```js
<template> 
  <compose view="some-template.html"></compose> 
</template> 

```

在这里，`some-template.html`将使用周围的绑定上下文渲染成一个视图。这意味着`compose`元素周围的任何变量也将对`some-template.html`可用。

当与`view-model`属性一起使用时，`view`属性将覆盖组件的默认模板。它可以在使用不同模板时复用视图模型的行为。

# 值转换器

在数据绑定的世界里，经常需要将数据在视图模型和视图之间进行转换，或者在双向绑定更新模型时将用户输入转换回来。

实现这种方法的一种方式是在视图模型中使用计算属性，以执行另一个属性值的来回转换。这种解决方案的缺点是，它不能跨视图模型复用。

在 Aurelia 中，值转换器解决了这个需求。值转换器是一个可以插入绑定表达式的对象。每次绑定需要评估表达式以渲染其结果，或者在双向绑定情况下更新模型时，转换器都作为拦截器，可以转换值。

## 使用值转换器

值转换器是视图资源。和 Aurelia 中的所有视图资源一样，为了在模板中使用，它必须被加载，要么通过一个`configure`函数全局加载，要么通过一个`require`元素局部加载。

### 注意

如果你不记得如何加载资源，请参阅*模板基础*部分。

在模板中，可以使用管道（`|`）操作符将值转换器包裹在一个数据绑定表达式周围：

```js
<template> 
  <div innerhtml.bind="htmlContent | sanitizeHTML"></div> 
</template> 

```

在这个示例中，我们使用了内置的`sanitizeHTML`值转换器来绑定`innerhtml`属性。这个值转换器会在绑定过程中被管道使用，并将会清除绑定值中的任何潜在危险元素。

值转换器实际上并不改变它们操作的绑定上下文值。它们仅仅作为拦截器，为绑定提供了一个用于渲染的替代值。

### 传递一个参数

值转换器可以接受参数，在这种情况下，它们必须在绑定表达式中使用冒号（`:`）分隔符指定。

让我们想象一个名为`truncate`的值转换器，它对字符串值起作用，同时期望一个`length`参数。在评估期间，它将提供的值截断到提供的长度（如果更长），并返回结果。这个转换器将如何使用：

```js
<template> 
  <h1>${title | truncate:20}</h1> 
</template> 

```

在这里，如果`title`超过 20 个字符，它将被截断到 20 个字符。否则，它将保持不变。

### 传递多个参数

可以向值转换器传递多个参数。只需继续使用冒号（`:`）分隔符。例如，如果`truncate`可以接受第二个参数，即在截断后的字符串后添加省略号，它将像这样传递：

```js
${title | truncate:20:'...'} 

```

### 传递上下文变量作为参数

绑定上下文中的变量也可以作为参数使用，在这种情况下，当这些变量中的任何一个发生变化时，绑定表达式将会重新评估。例如：

`some-component.js`

```js
export class ViewModel { 
  title = 'Some title'; 
  maxTitleLength = 2; 
} 
some-component.html 
<template> 
  <h1>${title | truncate:maxTitleLength}</h1> 
</template> 

```

在这里，字符串插值的价值取决于视图模型的`title`和`maxTitleLength`属性。每当它们中的一个发生变化时，表达式将会重新评估，`truncate`转换器将会重新执行，视图将会更新。

### 串联

值转换器可以被串联。在这种情况下，值通过转换器链进行管道，当评估表达式值时从左到右，当更新模型时从右到左：

```js
<template> 
  <h1>${title | truncate:20:'...' | capitalize}</h1> 
</template> 

```

在这个示例中，`title`首先会被截断，然后首字母大写后渲染。

## 实现一个值转换器

值转换器是一个必须实现至少以下方法之一的类：

+   `toView(value: any [, ...args]): any`：在评估绑定表达式后、渲染结果之前调用。`value`参数是绑定表达式的值。该方法必须返回转换后的值，它将传递给下一个转换器或渲染到视图中。

+   `fromView(value: any [, ...args]): any`：当更新模型的绑定目标值时调用，在将值分配给模型之前。`value`参数是绑定目标的值。该方法必须返回转换后的值，它将传递给下一个转换器或分配给模型。

如果值转换器使用参数，它们将以附加参数的形式传递给方法。例如，让我们想象一下值转换器的以下使用方式：

```js
${text | truncate:20:'...'} 

```

在这种情况下，`truncate`值转换器的`toView`方法预计会像这样：

```js
export TruncateValueConverter { 
  toView(value, length, ellipsis = '...') { 
    value = value || ''; 
    return value.length > length ? value.substring(0, length) + ellipsis : value; 
  } 
} 

```

在这里，`truncate`值转换器的`toView`方法除了它应用的`value`之外，还期望有一个`length`参数。它还接受一个名为`ellipsis`的第三个参数，有一个默认值。如果提供的`value`比提供的`length`长，该方法将截断它，附上`ellipsis`，然后返回这个新值。如果`value`不太长，它简单地返回它不变。

默认情况下，Aurelia 认为任何以`ValueConverter`结尾的作为资源加载的类都是一个值转换器。值转换器的名称将是类名，不包含`ValueConverter`后缀，驼峰命名。例如，一个名为`OrderByValueConverter`的类将作为`orderBy`值转换器提供给模板。

然而，当创建一个将包含在可重用插件或库中的转换器时，你不应依赖这个约定。在这种情况下，类应该用`valueConverter`装饰器装饰：

```js
import {valueConverter} from 'aurelia-framework'; 

@valueConverter('truncate') 
export Truncate { 
  // Omitted snippet... 
} 

```

这样，即使你的插件用户改变了默认的命名约定，你的类仍然会被 Aurelia 识别为值转换器。

# 绑定行为

绑定行为是视图资源，与值转换器相似，它们应用于表达式。然而，它们拦截绑定操作本身并访问整个绑定说明，因此可以修改它。这开辟了许多可能性。

## 使用绑定行为

要为一个绑定表达式添加绑定行为，它必须紧跟在表达式的末尾，使用`&`分隔符：

```js
${title & oneTime} 

```

当然，就像值转换器一样，绑定行为可以链接，在这种情况下，它们将从左到右执行：

```js
${title & oneWay & throttle} 

```

如果表达式还使用值转换器，绑定行为必须放在它们之后：

```js
${title | toLower | capitalize & oneWay & throttle} 

```

### 传递参数

就像值转换器一样，绑定行为也可以传递参数，使用相同的语法：

```js
${title & throttle:500} 

```

行为及其参数必须用冒号（:）分隔，参数之间也必须以同样的方式分隔：

```js
${title & someBehavior:p1:p2} 

```

## 内置绑定行为

`aurelia-templating-resources`库附带了许多绑定行为。让我们去发现它们。

### 注意

以下部分中的代码片段摘自`samples/chapter-3/binding-behaviors`。

### `oneTime`

`oneTime`行为使绑定变为单向 only。它可以用在字符串插值表达式上：

```js
<template> 
  <em>${quote & oneTime}</em> 
</template> 

```

在这里，视图模型的`quote`属性不会被观察，所以如果它发生变化，文本不会被更新。

此外，Aurelia 还附带了其他绑定模式的绑定行为：`oneWay`和`twoWay`。它们可以像`oneTime`一样使用。

### 节流

`throttle`绑定行为可用于限制视图模型更新的速率对于双向绑定或视图更新的速率对于单向绑定。换句话说，一个被 500 毫秒节流的绑定将至少在两个更新通知之间等待 500 毫秒。

```js
<template> 
  ${title & throttle} 
  <input value.bind="value & throttle"> 
</template> 

```

在这里，我们看到了这两个场景的例子。第一个`throttle`应用于字符串插值表达式，默认是单向的，当视图模型的`title`属性发生变化时，将节流视图中的文本更新。第二个应用于`input`元素的`value`属性的绑定，默认是双向的，当`input`的`value`发生变化时，将节流视图模型的`value`属性的更新。

`throttle`行为可以接受一个参数，表示更新之间的时差，以毫秒表示。然而，这个参数可以省略，默认使用 200 毫秒。

```js
<template> 
  ${title & throttle:800} 
  <input value.bind="value & throttle:800"> 
</template> 

```

在这里，我们有一个与之前相同的示例，但是绑定将被 800 毫秒节流。

事件也可以被节流。无论它是在`trigger`还是`delegate`绑定命令中使用，将事件分发到视图模型的节流将相应地节流：

```js
<template> 
  <div mousemove.delegate="position = $event & throttle:800"> 
    The mouse was last moved to (${position.clientX}, ${position.clientY}). 
  </div> 
</template> 

```

在这里，`div`元素的`mousemove`事件的处理程序将事件对象分配给视图模型的`position`属性。然而，这个处理程序将被节流，所以`position`将每 800 毫秒更新一次。

您可以在`samples/chapter-3/binding-behaviors`中看到`throttle`行为的一些示例。

### `debounce`

`debounce`绑定行为也是一种速率限制行为。它确保在给定延迟过去且没有更改的情况下不发送任何更新。

一个常见的用例是一个搜索输入，它会自动触发搜索 API 的调用。在用户每次输入后调用这样的 API 将是效率低下且消耗资源的。最好在用户停止输入后等待一段时间再调用搜索 API。这可以通过使用`debounce`来实现：

```js
<template> 
  <input value.bind="searchTerms & debounce"> 
</template> 

```

在这个例子中，视图模型将观察`searchTerms`属性，并在每次更改时触发搜索。`debounce`行为将确保在用户停止输入 200 毫秒后`searchTerms`才得到更新。

这意味着，当应用于双向绑定时，`debounce`限制了视图模型的更新速率。然而，当应用于单向绑定时，它限制了视图的更新速率：

```js
<template> 
  <input value.bind="text"> 
  ${text & debounce:500} 
</template> 

```

在这里，`debounce`应用于字符串插值表达式，所以只有当用户在输入中停止打字 500 毫秒后，显示的文本才会更新。这里的区别很重要。`text`属性仍然会实时更新。只有字符串插值绑定会被延迟。

就像`throttle`一样，`debounce`也可以应用于事件，使用触发器或委托绑定命令：

```js
<template> 
  <div mousemove.delegate="position = $event & debounce:800"> 
    The mouse was last moved to (${position.clientX}, ${position.clientY}). 
  </div> 
</template> 

```

在这里，`div`元素的`mousemove`事件的处理程序将事件对象分配给视图模型的`position`属性。然而，这个处理程序将被防抖，所以只有在鼠标在`div`上停止移动 800 毫秒后，`position`才会更新。

你可能会注意到，在之前的例子中，`throttle`和`debounce`都可以接受延迟，以毫秒表示，作为参数。省略时，延迟也默认为 200 毫秒。

### updateTrigger

`updateTrigger`绑定行为用于改变触发视图模型更新的事件。这意味着它只能与双向绑定一起使用，只能用于支持双向绑定的元素的属性，如`input`的`value`、`select`的`value`或具有`contenteditable="true"`的`div`的`textcontent`属性。

使用时，它期望事件名称作为参数，至少需要一个：

```js
<template> 
  <input value.bind="title & updateTrigger:'change':'input' "> 
</template> 

```

在这里，视图模型的`title`属性将在每次`input`触发`change`或`input`事件时更新。

实际上，`change`和`input`事件在 Aurelia 中是默认的触发器。除了这两个，`blur`、`keyup`和`paste`事件也可以用作触发器。

### signal

信号绑定行为允许程序化地触发绑定更新。这对于不可观察的绑定值或在特定时间间隔内必须刷新时特别有用。

让我们想象一个名为`timeInterval`的值转换器，它接收一个`Date`对象，计算输入日期和当前日期之间的时间间隔，并将这个时间间隔输出为用户友好的字符串，如`a minute ago`、`in 2 hours`或`3 years ago`。

由于结果取决于当前日期和时间，如果不定期刷新，它将很快过时。可以使用`signal`行为来实现这一点：

`src/some-component.html`

```js
<template> 
  Last updated ${lastUpdatedAt | timeInterval & signal:'now'} 
</template> 

```

在这个模板中，`lastUpdatedAt`使用`timeInterval`值转换器显示，其绑定被一个名为`now`的`signal`装饰。

`src/some-component.js`

```js
import {inject} from 'aurelia-framework'; 
import {BindingSignaler} from 'aurelia-templating-resources'; 

@inject(BindingSignaler) 
export class SomeComponent { 
  constructor(signaler) { 
    this.signaler = signaler; 
  } 

  activate() { 
    this.handle = setInterval(() => this.signaler.signal('now'), 5000); 
  } 

  deactivate() { 
    clearInterval(this.handle); 
  } 
} 

```

在视图模型中，在注入一个`BindingSignaler`实例并将其存储在实例变量中后，`activate`方法创建一个间隔循环，每 5 秒触发一个名为`now`的信号。每次触发信号时，模板中的字符串插值绑定都将更新，使得显示的时间间隔最多比当前时间晚 5 秒。当然，为了防止内存泄漏，间隔处理程序存储在实例变量中，并在组件停用时使用`clearInterval`函数销毁。

可以将多个信号名称作为参数传递给`signal`。在这种情况下，每次触发任何一个信号时，绑定都会刷新：

```js
<template> 
  <a href.bind="url & signal:'signal-1':'signal-2' ">Go</a> 
</template> 

```

此外，它只能用于字符串插值和属性绑定；信号一个`trigger`、`call`或`ref`表达式是没有意义的。

# 计算属性

高效的数据绑定是一个复杂的问题。Aurelia 的数据绑定库是适应性强的，并使用多种技术尽可能高效地观察视图模型和 DOM 元素。它在可能的情况下利用 DOM 事件和 Reflect API，在没有其他策略适用时才回退到脏检查。

### 注意

脏检查是一种使用超时循环反复评估表达式的观察机制，检查其值自上次评估以来是否发生变化，如果发生变化，则更新相关绑定。

计算属性是脏检查经常使用的一种场景。看这个例子：

```js
export class ViewModel { 
  get fullName() { 
    return `${this.firstName} ${this.lastName}`;
  } 
} 

```

当对`fullName`应用绑定时，Aurelia 无法知道其值是如何计算的，必须依赖脏检查来检测变化。在这个例子中，`fullName`的获取器评估速度很快，所以使用脏检查是绝对可以的。

然而，一些计算属性可能会最终执行重工作：例如从一个大型数组中搜索或聚合数据。在这种情况下，依赖脏检查意味着属性将每秒评估几次，这可能会使浏览器过载。

## 计算来自

`aurelia-binding`库导出一个`computedFrom`装饰器，可以用来解决这个问题。在装饰一个计算属性时，它通知绑定系统属性依赖于哪些依赖项来计算其结果。

```js
import {computedFrom} from 'aurelia-binding'; 

const items = [/* a static, huge list of items */]; 
export class ViewModel { 
  @computedFrom('searchTerm') 
  get matchCount() { 
    return items.filter(i => i.value.includes(this.searchTerm)).size; 
  } 
} 

```

在这里，为了观察`matchCount`，绑定系统会观察`searchTerm`。只有当它发生变化时，它才会重新评估`matchCount`。这比每秒多次评估属性的结果以检查其是否已更改要高效得多。

`computedFrom`装饰器接受访问路径作为依赖项，这些路径相对于它所在的类的实例是相对的：

```js
import {computedFrom} from 'aurelia-binding'; 

const items = [/* a static, huge list of items */]; 
export class ViewModel { 
  model = { 
    searchTerm: '...' 
  }; 

  @computedFrom('model.searchTerm') 
  get matchCount() { 
    return items.filter(i => i.value.includes(this.searchTerm)).size; 
  } 
} 

```

在这里，我们可以看到`matchCount`依赖于作为视图模型`model`属性存储的对象的`searchTerm`属性。

当然，它期望至少有一个依赖项作为参数传递。

`computedFrom`装饰器观察属性或路径。它无法观察数组的内容。这意味着以下示例将无法工作：

```js
import {computedFrom} from 'aurelia-binding'; 

export class ViewModel { 
  items = [/* a huge list of items, that can change during the lifetime of the component */]; 
  searchTerms = '...'; 

  @computedFrom('items', 'searchTerms') 
  get matchCount() { 
    return this.items.filter(i => i.value.includes(this.searchTerm)).size; 
  } 
} 

```

在这里，如果`items`得到一个项目的添加或删除，`computedFrom`不会检测到它，也不会重新评估`matchCount`。它能检测到的唯一情况是一个全新的数组是否被分配给`items`属性。

`computedFrom`装饰器在非常特定的情况下很有用。它不应该替代值转换器，因为那些是转换数据的首选方式。

# 从端点获取数据

## Fetch API

Fetch API 已被设计用于获取资源，包括通过网络。在撰写本文时，尽管其规范非常有前途，但仍未获得批准。然而，许多现代浏览器如 Chrome、Edge 和 Firefox 已经支持它。对于其他浏览器，需要一个 polyfill。

Fetch API 依赖于请求和响应的概念。这允许拦截管道在发送之前修改请求和接收时修改响应。它使得处理诸如认证和 CORS 之类的事情变得更容易。

在以下章节中，术语`Request`和`Response`指的是 Fetch API 的类。Mozilla 开发者网络有关于这个 API 的详尽文档：[`developer.mozilla.org/en-US/docs/Web/API/Fetch_API`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API)。

## 使用 Fetch 客户端

Aurelia 的 Fetch 客户端是一个围绕原生或 polyfilled Fetch API 的包装器。它支持默认请求配置，以及可插拔的拦截机制。它由一个名为`HttpClient`的类组成。这个类暴露了通过 HTTP 获取资源的方法。

## 配置

`HttpClient`类有一个`configure`方法。它期望的参数是一个回调函数，该函数接收一个配置对象，该对象暴露了可以用来配置客户端的方法：

+   `withBaseUrl(baseUrl: string)`：这为客户端设置了基础 URL。所有相对 URL 的请求都将相对于这个 URL 进行。

+   `withDefaults(defaults: RequestInit)`：这设置了传递给`Request`构造函数的默认属性。

+   `withInterceptor(interceptor: Interceptor)`：这为拦截管道添加了一个`Interceptor`对象。

+   `rejectErrorReponses()`：`fetch`方法返回一个`Response`对象的`Promise`。这个`Promise`只在发生网络错误或类似情况阻止请求完成时被拒绝。否则，无论服务器可能回答什么 HTTP 状态，`Promise`都会成功解决为`Response`。这个方法添加了一个拦截器，当响应的状态不是成功代码时拒绝`Promises`。HTTP 成功代码在`200`到`299`之间。

+   `useStandardConfiguration()`：标准配置包括`same-origin`凭据设置（有关此设置的更多信息，请参见官方 Fetch API 文档）和拒绝错误响应（请参阅前面的`rejectErrorResponses`方法）。

除了一个回调配置函数外，`configure`方法还可以直接传递一个`RequestInit`对象。在这种情况下，这个`RequestInit`对象将被用作所有请求的默认属性。

这意味着，如果我们有一个存储在`defaultProperties`变量中的`RequestInit`对象，下面的两行将执行完全相同的事情：

```js
client.configure(defaultProperties); 
client.configure(config => { config.withDefaults(defaultProperties); }); 

```

`RequestInit`对象对应于 Fetch API 的`Request`构造函数期望的第二个参数。它用于指定`Request`的各种属性。最常用的属性有：

+   `method`：HTTP 方法，例如 GET、POST

+   `headers`：包含请求的 HTTP 头的对象

+   `body`：请求体，例如一个`Blob`、`BufferSource`、`FormData`、`URLSearchParams`或`USVString`实例

    ### 注意

    我将让你查看官方文档以获取关于可用`Request`属性的更多详细信息。

正如你所看到的，一个`RequestInit`对象可以用来指定一个 HTTP 方法和请求体，因此我们将能够执行 POST 和 PUT 请求来创建和更新`person`对象。我们将在下一章看到这个例子，那时我们开始构建表单。

### 一个常见的陷阱

正如我们在第二章中看到的，*布局、菜单和熟悉*，DI 容器默认自动将所有类作为应用程序单例注册。这意味着，如果您的应用程序包含多个服务，它们依赖于应该是独立的`HttpClient`实例，并且各自配置其相应的`HttpClient`不同，您会遇到奇怪的问题。

让我们想象一下以下两个服务：

```js
import {inject} from 'aurelia-framework'; 
import {HttpClient} from 'aurelia-fetch-client'; 

@inject(HttpClient) 
export class ContactService { 
  constructor(http) { 
    this.http = http.configure(c => c.withBaseUrl('api/contacts')); 
  } 
} 

@inject(HttpClient) 
export class AddressService { 
  constructor(http) { 
    this.http = http.configure(c => c.withBaseUrl('api/addresses')); 
  } 
} 

```

在这里，我们有两个服务，分别名为`ContactService`和`AddressService`。它们在其构造函数中都作为`HttpClient`实例注入，并使用不同的基础 URL 配置自己的实例。

默认情况下，相同的`HttpClient`实例将被注入到两个服务中，因为 DI 容器默认认为它是应用程序的单例。您看到问题了吗？第二个服务创建后，将覆盖第一个服务的基础 URL，所以第一个服务最终将尝试对错误的 URL 执行 HTTP 调用。

这种场景有很多可能的解决方案。您可以使用`NewInstance`解析器在每个服务中强制注入一个新的实例：

```js
import {inject, NewInstance} from 'aurelia-framework'; 
import {HttpClient} from 'aurelia-fetch-client'; 

@inject(NewInstance.of(HttpClient)) 
export class ContactService { 
  constructor(http) { 
    this.http = http.configure(c => c.withBaseUrl('api/contacts')); 
  } 
} 

@inject(NewInstance.of(HttpClient)) 
export class AddressService { 
  constructor(http) { 
    this.http = http.configure(c => c.withBaseUrl('api/addresses')); 
  } 
} 

```

另一个解决方案可能是将`HttpClient`类作为您的应用程序主要`configure`方法中的瞬态注册：

```js
import {HttpClient} from 'aurelia-fetch-client'; 

export function configure(config) { 
  config.container.registerTransient(HttpClient); 
  //Omitted snippet... 
} 

```

## 拦截器

拦截器是在 HTTP 调用过程中的不同时间截取请求和响应的对象。一个`Interceptor`对象可以实现以下任意回调方法：

+   `request(request: Request): Request|Response|Promise<Request|Response>`：在请求被发送之前调用。它可以修改请求，或者返回一个新的请求。它还可以返回一个响应来短路剩余的过程。在这种情况下，下一个拦截器的`request`方法将被跳过，并且将使用响应，好像请求已经被发送一样。支持`Promise`。

+   `requestError(error: any): Request|Response|Promise<Request|Response>`：当一个拦截器的`request`方法抛出错误时调用。它可能重新抛出错误以传播它，或者返回一个新的请求或响应以从失败中恢复。支持`Promise`。

+   `response(response: Response, request?: Request): Response|Promise<Response>`：在响应被接收之后调用。它可以修改响应，或者返回一个新的响应。支持`Promise`。

+   `responseError(error: any, request?: Request): Response|Promise<Response>`：当一个拦截器的`response`方法抛出错误时调用。它可能重新抛出错误以传播它，或者返回一个新的响应以从失败中恢复。支持`Promise`。

例如，我们可以定义以下的拦截器类：

```js
export class BearerAuthorizationInterceptor { 
  constructor(token) { 
    this.token = token; 
  } 

  request(request) { 
    request.headers.set('Authorization', `Bearer ${this.token}`); 
  } 
} 

```

这个拦截器期望一个`Bearer`认证令牌在它的构造函数中被传递。当添加到一个 Fetch 客户端时，它会在每个请求中添加一个`Authorization`头，允许一个已经认证的用户访问一个受保护的端点。

# 我们的应用程序

至此，我们已经涵盖了我们将需要的应用程序的下一步：查询我们的 HTTP 端点、显示联系人列表以及允许导航到给定联系人的详细信息。

为了使我们的应用程序更具吸引力，我们将利用 Font Awesome，一个提供可缩放矢量图标的 CSS 库。让我们首先安装它：

```js
> npm install font-awesome --save

```

接下来，我们需要将其包含在我们的应用程序中：

`index.html`

```js
<head>  
  <!-- Omitted snippet --> 
  <link href="node_modules/font-awesome/css/font-awesome.min.css" rel="stylesheet"> 
</head> 

```

## 我们的联系人网关

我们本可以在我们的视图模型中直接进行 HTTP 调用。然而，这样做会模糊责任之间的界限。视图模型除了要负责数据展示（其主要任务）之外，还要负责调用、解析请求、处理错误以及最终缓存响应。

相反，我们将创建一个联系人网关类，它将负责从端点获取数据，将是可重用的，并且能够独立发展：

`src/contact-gateway.js`

```js
import {inject} from 'aurelia-framework'; 
import {HttpClient} from 'aurelia-fetch-client'; 
import {Contact} from './models'; 
import environment from './environment'; 

@inject(HttpClient) 
export class ContactGateway { 

  constructor(httpClient) { 
    this.httpClient = httpClient.configure(config => { 
      config 
        .useStandardConfiguration() 
        .withBaseUrl(environment.contactsUrl); 
    }); 
  } 

  getAll() {    
    return this.httpClient.fetch('contacts') 
      .then(response => response.json()) 
      .then(dto => dto.map(Contact.fromObject)); 
  } 

  getById(id) { 
    return this.httpClient.fetch(`contacts/${id}`) 
      .then(response => response.json()) 
      .then(Contact.fromObject); 
  } 
} 

```

在这里，我们首先声明一个构造函数期望一个`HttpClient`实例的类，这是 Aurelia 的 Fetch 客户端。在这个构造函数中，我们配置客户端，使其使用标准配置，我们在*配置*部分看到了这个配置，并使用`environment`对象的`contactsUrl`属性作为其基本 URL。这意味着所有带有相对 URL 的请求都将相对于这个 URL 进行。

我们的 contact gateway 暴露了两个方法：一个获取所有联系人，第二个通过其 ID 获取单个联系人。它们通过调用客户端的`fetch`方法来工作，该方法默认向提供的 URL 发送 GET 请求。在这里，由于 URL 是相对路径，它们将相对于在构造函数中配置的基 URL 进行转换。

当 HTTP 请求完成后，`fetch`返回的`Promise`被解决，然后在解决后的`Response`对象上调用`json`方法来反序列化响应体为 JSON。`json`方法也返回一个`Promise`，所以当这个第二个`Promise`解决时，我们将未类型的数据传输对象转换为稍后我们将编写的`Contact`类的实例。

这意味着，基于端点返回的内容，`getAll`返回一个`Contact`对象的数组`Promise`，而`getById`返回一个单个`Contact`对象的`Promise`。

### 先决条件

为了让这一切正常工作，我们需要做两件事。首先，我们将安装 Fetch 客户端，通过在移动到应用程序目录后，在控制台中运行以下命令：

```js
npm install aurelia-fetch-client --save

```

### 注意

本书中编写的所有代码都在 Google Chrome 上运行过。如果你使用其他浏览器，你可能需要为各种 API（如 Fetch）安装 polyfill。

此外，你还需要让 Aurelia 打包器知道这个库。在`aurelia_project/aurelia.json`中，在`build`下的`bundles`中，在名为`vendor-bundle.js`的包定义中，将`aurelia-fetch-client`添加到`dependencies`数组中：

`aurelia_project/aurelia.json`

```js
{ 
  //Omitted snippet... 
  "build": { 
    //Omitted snippet ... 
    "bundles": { 
      //Omitted snippet ... 
      { 
        "name": "vendor-bundle.js", 
        //Omitted snippet ... 
        "dependencies": [ 
          "aurelia-fetch-client", 
          //Omitted snippet ... 
        ] 
      } 
    } 
  } 
} 

```

这是为了让`aurelia-fetch-client`库与其他库一起被捆绑，以便我们的应用程序可以使用它。

最后，`contactsUrl`属性在`environment`配置对象中默认不存在。我们需要添加它：

`aurelia_project/environments/dev.js`

```js
export default { 
  debug: true, 
  testing: true, 
  contactsUrl: 'http://127.0.0.1:8000/', 
}; 

```

在这里，我们将默认在哪个 URL 上运行我们的端点的 URL 分配给`contactsUrl`属性。在现实世界中，我们还会将其设置在`stage.js`和`prod.js`中，因此我们的端点为所有环境配置。我将留下这个作为读者的练习。

## 显示联系人

现在让我们在我们的空`contact-list`组件中添加一些代码。我们将利用我们新的`ContactGateway`类来获取联系人列表并显示它。

`src/contact-list.js`

```js
import {inject} from 'aurelia-framework'; 
import {ContactGateway} from './contact-gateway'; 

@inject(ContactGateway) 
export class ContactList { 

  contacts = []; 

  constructor(contactGateway) { 
    this.contactGateway = contactGateway; 
  } 

  activate() { 
    return this.contactGateway.getAll() 
      .then(contacts => { 
        this.contacts.splice(0); 
        this.contacts.push.apply(this.contacts, contacts); 
      }); 
  } 
} 

```

在这里，我们首先在`contact-list`组件的视图模型中注入了一个`ContactGateway`实例。在`activate`方法中，我们使用`getAll`获取联系人，一旦`Promise`解决，我们确保清除联系人数组；然后我们将加载的联系人添加到其中，以便它们可供模板使用。

在这种情况下，更改数组被视为比覆盖整个`contacts`属性更好的做法，因为视图中的`repeat.for`绑定观察数组实例的更改，但不观察属性本身，所以如果`contacts`在视图渲染后覆盖，视图不会刷新。

您可能注意到了`getAll`返回的`Promise`是如何在`activate`中返回的。这使得对 HTTP 端点的调用作为屏幕激活生命周期的一部分运行。如果没有这

我们还需要定义`Contact`类。它在列表和详细视图中会有用的计算属性：

`src/models.js`

```js
export class Contact { 
  static fromObject(src) { 
    return Object.assign(new Contact(), src); 
  } 

  get isPerson() { 
    return this.firstName || this.lastName; 
  } 

  get fullName() { 
    const fullName = this.isPerson  
      ? `${this.firstName} ${this.lastName}`  
      : this.company; 
    return fullName || ''; 
  } 
} 

```

这个类有一个名为`fromObject`的静态方法，它作为一个工厂方法。它期望一个源对象作为其参数，创建一个`Contact`的新实例，并将源对象的所有属性分配给它。此外，它定义了一个`isPerson`属性，如果联系人至少有一个名字或姓氏，则返回`true`，并在模板中用来区分人和公司。它还定义了一个`fullName`属性，如果联系人代表一个人，它将返回名字和姓氏，如果联系人是公司，它将返回公司名称。

现在，唯一缺少的是`contact-list`模板：

`src/contact-list.html`

```js
<template> 
  <section class="container"> 
    <h1>Contacts</h1> 
    <ul> 
      <li repeat.for="contact of contacts">${contact.fullName}</li> 
    </ul> 
  </section> 
</template> 

```

这里我们简单地将联系人渲染为无序列表。

你现在可以测试它：

```js
> au run --watch

```

### 注意

不要忘记通过在`api`目录中运行`npm start`来启动 HTTP 端点。当然，如果你之前没有运行过，你首先需要运行`npm install`来安装其依赖项。

如果你没有省略任何步骤，当你导航到 http://localhost:9000/时，你应该看到联系人列表出现。

## 对联系人进行分组和排序

目前，联系人列表很无聊。联系人以子弹列表的形式显示，甚至没有排序。我们可以通过按联系人名字的第一个字母分组并按字母顺序对这些组进行排序，大大提高这个屏幕的可使用性。这将使浏览列表和查找联系人变得更容易。

要实现这一点，我们有两个选择：我们可以在视图模型中先分组然后排序联系人，或者我们可以将此逻辑隔离在值转换器中，以便我们以后可以重新使用它们。我们将选择后者，因为它符合单一责任原则，并使我们的代码更加简洁。

### 创建 orderBy 值转换器

我们的`orderBy`值转换器将应用于一个数组，并期望其第一个参数为用于排序项目的属性名称。

我们的值转换器还可以接受一个可选的第二个参数，这将是一个排序方向，作为一个`'asc'`或`'desc'`字符串。省略时，排序顺序将升序。

`src/resources/value-converters/order-by.js`

```js
export class OrderByValueConverter { 
  toView(array, property, direction = 'asc') { 
    array = array.slice(0); 
    const directionFactor = direction == 'desc' ? -1 : 1;  
    array.sort((item1, item2) => { 
      const value1 = item1[property]; 
      const value2 = item2[property]; 
      if (value1 > value2) { 
        return directionFactor; 
      } else if (value1 < value2) { 
        return -directionFactor; 
      } else { 
        return 0; 
      } 
    }); 
    return array; 
  } 
} 

```

### 注意

一个重要的部分是在调用`sort`之前调用`slice`。它确保对数组进行复制，因为`sort`方法会修改它调用的数组。如果没有`slice`调用，原始数组将被修改。这是不好的；值转换器绝不应该修改其源值。这不是预期行为，因此这样的转换器会让使用它的开发者感到非常惊讶。

在设计值转换器时，你确实应该密切关注以避免此类副作用。

为了使这个新的转换器对模板可用，而不是每次需要时都手动`require`它，让我们在`resources`特性中加载它：

`src/resources/index.js`

```js
export function configure(config) { 
  config.globalResources([ 
    './value-converters/order-by', 
  ]); 
} 

```

你可以通过将`contact of contacts | orderBy:'fullName'`的`repeat.for`指令更改为`contact-list`模板中的新`firstLetter`属性来测试它。

### 创建 groupBy 值转换器

接下来，我们的`groupBy`值转换器将以几乎相同的方式工作；它将应用于数组，并期望一个参数，这个参数将是用于分组项目的属性的名称。它将返回一个对象数组，每个对象都包含两个属性：用作`key`的分组值和作为`items`数组的分组项目：

`src/resources/value-converters/group-by.js`

```js
export class GroupByValueConverter { 
  toView(array, property) { 
    const groups = new Map(); 
    for (let item of array) { 
      let key = item[property]; 
      let group = groups.get(key); 
      if (!group) { 
        group = { key, items: [] }; 
        groups.set(key, group); 
      } 
      group.items.push(item); 
    } 
    return Array.from(groups.values()); 
  } 
} 

```

这个值转换器还需要在`resources`特性的`configure`函数中加载。这个你自己来吧。

### 更新联系人列表

为了利用我们的值转换器，我们首先需要在`Contact`类中添加一个新属性：

`src/models.js`

```js
//Omitted snippet... 
export class Contact { 
  //Omitted snippet... 
  get firstLetter() { 
    const name = this.lastName || this.firstName || this.company; 
    return name ? name[0].toUpperCase() : '?'; 
  } 
} 

```

这个新的`firstLetter`属性取联系人的姓氏、名字或公司名字的第一个字母。它将用于将联系人分组在一起。

接下来，让我们丢弃我们之前的联系人列表模板，重新开始：

`src/contact-list.html`

```js
<template> 
  <section class="container"> 
    <h1>Contacts</h1> 
    <div repeat.for="group of contacts|groupBy:'firstLetter'|orderBy:'key'" 
         class="panel panel-default"> 
      <div class="panel-heading">${group.key}</div> 
      <ul class="list-group"> 
        <li repeat.for="contact of group.items|orderBy:'fullName'"    
            class="list-group-item"> 
          <a route-href="route: contact-details;  
                         params.bind: { id: contact.id }"> 
            <span if.bind="contact.isPerson"> 
              ${contact.firstName} <strong>${contact.lastName}</strong> 
            </span> 
            <span if.bind="!contact.isPerson"> 
              <strong>${contact.company}</strong> 
            </span> 
          </a> 
        </li> 
      </ul> 
    </div> 
  </section> 
</template> 

```

在这里，我们首先按照它们的`firstLetter`属性的值将联系人分组。`groupBy`转换器返回一个组对象的数组，然后根据它们的`key`属性进行排序并重复到面板上。对于每个组，以该组分的字母显示在面板标题中，然后按`fullName`属性对组中的联系人进行排序并显示在列表组中。对于每个联系人，都会渲染一个到其详细视图的链接，显示其人员或公司名称。

## 筛选联系人

即使联系人被分组和排序，找到特定的联系人可能仍然很麻烦，特别是如果用户不知道联系人的全名。我们添加一个搜索框，用于实时过滤联系人列表。

我们首先需要创建另一个值转换器来过滤联系人数组：

`src/resources/value-converters/filter-by.js`

```js
export class FilterByValueConverter { 
  toView(array, value, ...properties) { 
    value = (value || '').trim().toLowerCase(); 
    if (!value) { 
      return array; 
    } 
    return array.filter(item =>  
      properties.some(property =>  
        (item[property] || '').toLowerCase().includes(value))); 
  } 
} 

```

我们的`filterBy`值转换器期望一个第一个参数，这是要搜索的值。此外，它考虑以下参数是要搜索的属性。任何不在指定属性中包含搜索值的联系人将被过滤出结果。

### 注意

不要忘记在`resources`特性的`configure`函数中加载`filterBy`值转换器。

接下来，我们需要在`contact-list`模板中添加搜索框并应用我们的值转换器：

`src/contact-list.html`

```js
<template> 
  <section class="container"> 
    <h1>Contacts</h1> 

    <div class="row"> 
      <div class="col-sm-2"> 
        <div class="input-group"> 
          <input type="text" class="form-control" placeholder="Filter"  
                 value.bind="filter & debounce"> 
          <span class="input-group-btn" if.bind="filter"> 
            <button class="btn btn-default" type="button"  
                    click.delegate="filter = ''"> 
              <i class="fa fa-times"></i> 
              <span class="sr-only">Clear</span> 
            </button> 
          </span> 
        </div> 
      </div> 
    </div> 

    <div repeat.for="group of contacts 
                     | filterBy:filter:'firstName':'lastName':'company' 
                     | groupBy:'firstLetter'  
                     | orderBy:'key'" 
         class="panel panel-default"> 
      <!-- Omitted snippet... --> 
    </div> 
  </section> 
</template> 

```

在这里，我们首先添加一个搜索框，形式为一个`input`元素，其`value`绑定到`filter`属性。这个绑定是去抖的，所以属性将在用户停止输入 200 毫秒后才会更新。

另外，当`filter`不为空时，`input`旁边会显示一个按钮。点击这个按钮，简单地将`filter`分配为一个空字符串。

最后，我们在`repeat.for`绑定中将对`contacts`应用`filterBy`，传递`filter`作为搜索值，随后是`firstName`、`lastName`和`company`属性的名称，这些属性将被搜索。

### 注意

这里有趣的一点是，我们甚至没有在视图模型中声明`filter`属性。它只在视图中使用。由于它绑定到输入元素的值属性，默认情况下绑定是双向的，绑定只会将其值分配给视图模型。视图模型不需要知道这个属性。

## 联系人详细视图

如果你点击一个联系人，你应该在浏览器控制台看到一个错误。原因很简单：应该显示联系人详情的路由指的是一个`contact-details`组件，而这个组件还不存在。让我们来纠正这个问题。

### 视图模型

视图模型将利用我们之前编写的某些类：

`src/contact-details.js`

```js
import {inject} from 'aurelia-framework'; 
import {ContactGateway} from './contact-gateway'; 

@inject(ContactGateway) 
export class ContactDetails { 
  constructor(contactGateway) { 
    this.contactGateway = contactGateway; 
  } 

  activate(params, config) { 
    return this.contactGateway.getById(params.id) 
      .then(contact => { 
        this.contact = contact; 
        config.navModel.setTitle(contact.fullName); 
      }); 
  } 
} 

```

这段代码相当直接。视图模型期望在其构造函数中注入`ContactGateway`的一个实例，并实现`activate`生命周期回调方法。这个方法使用`id`路由参数并向网关请求适当的联系人对象。它返回网关的`Promise`，所以导航只有在联系人加载完成后才会完成。当这个`Promise`解决时，联系人对象被分配给视图模型的`contact`属性。此外，路由`config`对象用于动态将文档标题分配给联系人的`fullName`。

### 模板

联系人详情的模板很大，所以让我们将其分解为部分。你可以按照这一节逐步构建模板。

首先，让我们添加一个头，将显示联系人的图片和姓名：

```js
<template> 
  <section class="container"> 
    <div class="row"> 
      <div class="col-sm-2"> 
        <img src.bind="contact.photoUrl" class="img-responsive" alt="Picture"> 
      </div> 
      <template if.bind="contact.isPerson"> 
        <h1 class="col-sm-10">${contact.fullName}</h1> 
        <h2 class="col-sm-10">${contact.company}</h2> 
      </template>  
      <template if.bind="!contact.isPerson"> 
        <h1 class="col-sm-10">${contact.company}</h1> 
      </template> 
    </div> 
  </section> 
</template> 

```

模板的其余部分，应该放在关闭`section`标签之前，被一个带有`form-horizontal`类的`div`元素包含：

```js
<div class="form-horizontal"> 
  <!-- the rest of the template goes here. --> 
</div> 

```

在这个元素内部，我们首先显示联系人在创建和最后修改时的日期和时间：

```js
<div class="form-group"> 
  <label class="col-sm-2 control-label">Created on</label> 
  <div class="col-sm-10"> 
    <p class="form-control-static">${contact.createdAt}</p> 
  </div> 
</div> 

<div class="form-group"> 
  <label class="col-sm-2 control-label">Modified on</label> 
  <div class="col-sm-10"> 
    <p class="form-control-static">${contact.modifiedAt}</p> 
  </div> 
</div> 

```

接下来，如果联系人有生日，我们将显示联系人的生日：

```js
<div class="form-group" if.bind="contact.birthday"> 
  <label class="col-sm-2 control-label">Birthday</label> 
  <div class="col-sm-10"> 
    <p class="form-control-static">${contact.birthday}</p> 
  </div> 
</div> 

```

之后，我们将显示联系人的电话号码：

```js
<template if.bind="contact.phoneNumbers.length > 0"> 
  <hr> 
  <div class="form-group"> 
    <h4 class="col-sm-2 control-label">Phone numbers</h4> 
  </div> 
  <div class="form-group" repeat.for="phoneNumber of contact.phoneNumbers"> 
    <label class="col-sm-2 control-label">${phoneNumber.type}</label> 
    <div class="col-sm-10"> 
      <p class="form-control-static"> 
        <a href="tel:${phoneNumber.number}">${phoneNumber.number}</a> 
      </p> 
    </div> 
  </div> 
</template> 

```

在这里，块被包含在一个模板中，该模板仅当联系人至少有一个电话号码时才渲染。每个电话号码都显示其类型：家庭、办公室或移动电话等。

接下来的部分都会遵循与电话号码相同的模式。它们将显示联系人的电子邮件地址、地理位置和社交媒体资料：

```js
<template if.bind="contact.emailAddresses.length > 0"> 
  <hr> 
  <div class="form-group"> 
    <h4 class="col-sm-2 control-label">Email addresses</h4> 
  </div> 
  <div class="form-group"  
       repeat.for="emailAddress of contact.emailAddresses"> 
    <label class="col-sm-2 control-label">${emailAddress.type}</label> 
    <div class="col-sm-10"> 
      <p class="form-control-static"> 
        <a href="mailto:${emailAddress.address}"  
           target="_blank">${emailAddress.address}</a> 
      </p> 
    </div> 
  </div> 
</template> 

<template if.bind="contact.addresses.length > 0"> 
  <hr> 
  <div class="form-group"> 
    <h4 class="col-sm-2 control-label">Addresses</h4> 
  </div> 
  <div class="form-group" repeat.for="address of contact.addresses"> 
    <label class="col-sm-2 control-label">${address.type}</label> 
    <div class="col-sm-10"> 
      <p class="form-control-static">${address.number} ${address.street}</p> 
      <p class="form-control-static">${address.postalCode} ${address.city}</p> 
      <p class="form-control-static">${address.state} ${address.country}</p> 
    </div> 
  </div> 
</template> 

<template if.bind="contact.socialProfiles.length > 0"> 
  <hr> 
  <div class="form-group"> 
    <h4 class="col-sm-2 control-label">Social Profiles</h4> 
  </div> 
  <div class="form-group" repeat.for="profile of contact.socialProfiles"> 
    <label class="col-sm-2 control-label">${profile.type}</label> 
    <div class="col-sm-10"> 
      <p class="form-control-static"> 
        <a if.bind="profile.type === 'GitHub'"  
           href="https://github.com/${profile.username}"  
           target="_blank">${profile.username}</a> 
        <a if.bind="profile.type === 'Twitter'"  
           href="https://twitter.com/${profile.username}"  
           target="_blank">${profile.username}</a> 
      </p> 
    </div> 
  </div> 
</template> 

```

最后，如果有的话，我们将显示联系人的备注：

```js
<template if.bind="contact.note"> 
  <hr> 
  <div class="form-group"> 
    <label class="col-sm-2 control-label">Note</label> 
    <div class="col-sm-10"> 
      <p class="form-control-static">${contact.note}</p> 
    </div> 
  </div> 
</template> 

```

由于在组件的生命周期中加载的联系人永远不会改变，可以通过将所有`bind`命令替换为`one-time`命令，并将所有字符串插值装饰为`oneTime`绑定行为来大大改进此模板。我将把这个作为读者的练习留给读者。

# 概要

正如你所见，Aurelia 的数据绑定语言清晰简洁。它相当容易理解，即使对于不熟悉 Aurelia 的开发人员来说，模板也很容易理解。此外，它是适应性强的，使得编写高性能应用程序尽可能简单。

除了 Fetch 客户端的便利性，这些特质结合了值转换器和绑定行为系统的灵活性与可重用性，使得编写数据展示组件变得非常简单。

构建用于创建和编辑数据的形式并不比这更复杂。我们将在下一章中看到这一点，其中包括表单验证。


# 第四章：表单及其验证方式

在本章中，我们将了解数据绑定如何适用于用户输入元素，如`input`、`select`和`textarea`。我们还将了解当处理比简单 GET 请求更复杂的场景时，Fetch 客户端如何工作，例如带有 JSON 主体的 POST 或 PUT 请求，或者向服务器上传文件的需求。

此外，我们还将了解如何使用`aurelia-validation`插件验证表单。

最后，我们将讨论使用`aurelia-dialog`插件创建复杂表单的各种策略，从内联列表编辑到使用模态窗口编辑。

# 绑定表单输入

Aurelia 支持所有官方 HTML5 用户输入元素的双向绑定。其中一些相当简单易用，比如`text input`，我们已经在前面的章节中用许多示例探索过。其他的，如单选按钮或复选框，则不太直接。让我们逐一了解它们。

以下部分中的代码片段摘自`chapter-4/samples/binding-forms`。

## 选择元素

对于`select`元素，我们通常绑定到它的`value`属性，并且经常使用`repeat.for`来渲染它的`option`元素：

```js
<template> 
  <select value.bind="selectedCountry"> 
    <option>Select your country</option> 
    <option repeat.for="country of countries"  
            value.bind="country">${country}</option> 
  </select> 
</template> 

```

当然，`select`元素的`value`属性默认绑定双向，所以选中的`option`元素的`value`将分配给绑定到`select`的`value`属性的表达式。在此示例中，`selectedCountry`属性将被分配选中的`country`值。

`option`元素的`value`属性只期望字符串值。在前一个示例中，`countries`属性是一个字符串数组，因此每个`option`的`value`绑定到一个字符串。要渲染绑定到任何其他类型值的`option`——例如一个对象——必须使用特殊的`model`属性：

```js
<template> 
  <select value.bind="selectedCulture"> 
    <option>Select your culture</option> 
    <option repeat.for="culture of cultures"  
            model.bind="culture">${culture.name}</option> 
  </select> 
</template> 

```

在此，`selectedCulture`属性将被赋值为选中的`culture`对象，因为`cultures`属性是一个对象数组。

或者，如果你需要选择一个键属性，比如一个 ID，而不是整个数组项，你仍然可以使用`option`元素的`value`属性，前提是键属性是一个字符串值：

```js
<template> 
  <select value.bind="selectedCultureIsoCode"> 
    <option>Select your culture</option> 
    <option repeat.for="culture of cultures"  
            value.bind="culture.isoCode">${culture.name}</option> 
  </select> 
</template> 

```

在此示例中，选中的`option`的`value`绑定到相应项的`isoCode`属性，这是一个字符串，因此选中项的此属性将被分配给`selectedCultureIsoCode`。

当然，在渲染过程中，绑定到`select`属性的`value`表达式的值将被求值，如果任何`option`具有匹配的`value`或`model`属性，这个`option`将被渲染为选中状态。

### 多选

当`select`元素具有`multiple`属性时，绑定到其`value`属性的表达式预期是一个数组：

```js
<template> 
  <select value.bind="selectedCountries" multiple> 
    <option repeat.for="country of countries"  
            value.bind="country">${country}</option> 
  </select> 
</template> 

```

在此，选中的选项的值将被添加到`selectedCountries`数组中。

当用户选择一个项目时，选中的值总是添加到选择数组的末尾。

当然，当将非字符串值的数组渲染到多选列表时，也适用于相同的规则；数组的每个项目应绑定到其`option`的`model`属性上：

```js
<template> 
  <select value.bind="selectedCultures" multiple> 
    <option repeat.for="culture of cultures"  
            model.bind="culture">${culture.name}</option> 
  </select> 
</template> 

```

在这里，所选的`culture`对象将被添加到`selectedCultures`数组中。

使用键字符串属性的替代方案，在多选中同样适用：

```js
<template> 
  <select value.bind="selectedCulturesIsoCodes" multiple> 
    <option repeat.for="culture of cultures"  
            value.bind="culture.isoCode">${culture.name}</option> 
  </select> 
</template> 

```

在这个示例中，所选`culture`对象的`isoCode`属性将被添加到`selectedCulturesIsoCodes`数组中，这是一个字符串数组。

### 匹配器

当使用`model`属性时，可能会发生这种情况：分配给`select`的`value`属性的对象具有相同的身份，但与分配给`option`的`model`属性的对象不是同一个实例。在这种情况下，Aurelia 将无法渲染正确的`option`作为选中项。

`matcher`属性正是为这种场景设计的：

```js
<template> 
  <select value.bind="selectedCulture" matcher.bind="matchCulture"> 
    <option>Select your culture</option> 
    <option repeat.for="culture of cultures"  
            model.bind="culture">${culture.name}</option> 
  </select> 
</template> 

```

在这里，当尝试找出哪个`option`应该被选中时，`select`元素会将等价比较委托给`matchCulture`函数，该函数应大致如下所示：

```js
export class ViewModel { 
  matchCulture = (culture1, culture2) => culture1.isoCode === culture2.isoCode; 
} 

```

在这里，这个函数期望有两个文化对象，它们可能具有相同的身份，代表相同的文化。如果这两个对象具有相同的身份，将返回`true`，否则返回`false`。

## 输入元素

绑定到`input`元素在大多数情况下是很简单的，但实际上取决于`type`属性。例如，对于`text`输入，`value`属性默认是双向绑定的，可以用来获取用户的输入：

```js
<template> 
  <input type="text" value.bind="title"> 
</template> 

```

在这里，`title`属性的初始值将在`input`中显示，用户对`input`值的任何更改也将应用到`title`属性上。类似地，对`title`属性的任何更改也将应用到`input`的`value`上。

对于大多数其他类型的`input`，使用方式相同：`color`、`date`、`email`、`number`、`password`、`tel`或`url`等。然而，也有一些特殊情况，如下所述。

### 文件选择器

当`input`元素的`type`属性为`file`时，它暴露其`files`属性作为一个属性。它默认使用双向绑定：

```js
<template> 
  <input type="file" accepts="image/*" files.bind="images"> 
</template> 

```

在这个示例中，`input`元素的`files`属性被绑定到视图模型的`images`属性上。当用户选择一个文件时，`images`被赋予一个包含所选文件的`FileList`对象。如果`input`元素具有`multiple`属性，用户可以选择多个文件，结果的`FileList`对象将包含用户选择的多个`File`对象。

`FileList`和`File`类是 HTML5 文件 API 的一部分，可以与 Fetch API 一起使用，将用户选择的文件发送到服务器。在本书稍后的章节中，我们将看到在构建联系人应用程序的照片编辑组件时的一个示例。

Mozilla 开发者网络有关于文件 API 的详尽文档。关于`FileList`类的详细信息可以在[`developer.mozilla.org/en-US/docs/Web/API/FileList`](https://developer.mozilla.org/en-US/docs/Web/API/FileList)找到。

### 单选按钮

与`select`元素的`option`类似，单选按钮可以使用`value`或`model`属性来指定按钮选中时的值。`value`属性只期望字符串值，所以对于任何其他类型的值，必须使用`model`属性。

此外，单选按钮可以绑定它们的`checked`属性，该属性默认是双向的，到一个表达式，当选中时将被分配按钮的`value`或`model`。

```js
<template> 
  <label repeat.for="country of countries"> 
    <input type="radio" name="countries" value.bind="country"  
           checked.bind="selectedCountry"> 
    ${country} 
  </label> 
</template> 

```

在这里，一组单选按钮使用名为`countries`的字符串数组进行渲染。选中的单选按钮的`country`，绑定到`value`属性，将被分配给`selectedCountry`属性。

与`option`元素一样，当绑定到不是字符串的值时，应使用`model`属性而不是`value`：

```js
<template> 
  <label repeat.for="culture of cultures"> 
    <input type="radio" name="cultures" model.bind="culture"  
              checked.bind="selectedCulture"> 
    ${culture.name} 
  </label> 
</template> 

```

在这里，一组单选按钮使用一个`culture`对象的数组进行渲染。选中的单选按钮的`culture`，绑定到`model`属性，将被分配给`selectedCulture`属性。

与`select`元素类似，使用`model`属性的单选按钮也可以使用`matcher`属性来自定义等价比较逻辑。

所有之前的示例都使用了`repeat.for`绑定到数组来渲染动态的单选按钮列表。如果你需要渲染一个静态的单选按钮列表，并且期望的输出是一个布尔值，例如呢？在这种情况下，不需要在数组上迭代：

```js
<template> 
  <h4>Do you speak more than one language?</h4> 
  <label> 
    <input type="radio" name="isMultilingual" model.bind="null"  
           checked.bind="isMultilingual">  
    That's none of your business 
  </label> 
  <label> 
    <input type="radio" name="isMultilingual" model.bind="true"  
           checked.bind="isMultilingual"> 
    Yes 
  </label> 
  <label> 
    <input type="radio" name="isMultilingual" model.bind="false"  
           checked.bind="isMultilingual"> 
    No 
  </label> 
</template> 

```

在这个例子中，渲染了一个静态的单选按钮列表，每个按钮都使用它们的`model`属性绑定到不同的标量值。它们的`checked`属性绑定到`isMultilingual`属性，这将根据选择哪个按钮而被分配为`null`、`true`或`false`。

当然，在渲染过程中，如果绑定到按钮组`checked`属性的表达式有一个值与按钮的`value`或`model`属性匹配，这个按钮将被渲染为选中状态。

### 复选框

复选框列表在其典型用法上与带`multiple`属性的`select`元素相似。每个`input`元素都有`value`或`model`属性。此外，预期`checked`属性将被绑定到数组，到这个数组中将会添加所有选中的`input`的`value`或`model`：

```js
<template> 
  <label repeat.for="country of countries"> 
    <input type="checkbox" value.bind="country"  
           checked.bind="selectedCountries"> 
    ${country} 
  </label> 
</template> 

```

在这里，一组复选框使用名为`countries`的字符串数组进行渲染。选中的复选框的`country`，绑定到`value`属性，将被添加到`selectedCountries`数组。

与`option`元素或单选按钮一样，`value`属性只期望字符串值。当绑定到任何其他类型的值时，应使用`model`属性：

```js
<template> 
  <label> 
    <input type="checkbox" model.bind="culture"  
           checked.bind="selectedCultures"> 
    ${culture.name} 
  </label> 
</template> 

```

在此，一组复选框使用`culture`对象的数组进行渲染。选中的复选框的`culture`，通过`model`属性绑定，将被添加到`selectedCultures`数组中。

与`select`元素和单选按钮类似，使用`model`属性的复选框也可以使用`matcher`属性来自定义等价比较逻辑。

当然，如果渲染对象数组时，选中的值是某种字符串 ID，仍然可以使用`value`属性：

```js
<template> 
  <label> 
    <input type="checkbox" value.bind="culture.isoCode"  
           checked.bind="selectedCulturesIsoCodes"> 
    ${culture.name} 
  </label> 
</template> 

```

在此，一组复选框使用`culture`对象的数组进行渲染。选中的复选框的`culture`的`isoCode`属性，绑定到`value`属性，将被添加到`selectedCulturesIsoCodes`字符串数组中。

当然，在渲染过程中，如果绑定到`checked`属性的数组包含绑定到`value`或`model`属性的值，此复选框将被渲染为选中状态。

Alternatively，复选框可以绑定到不同的布尔表达式，而不是一个单一的数组。这可以通过省略任何`value`或`model`属性来实现：

```js
<template> 
  <label> 
    <input type="checkbox" checked.bind="speaksFrench">French 
  </label> 
  <label> 
    <input type="checkbox" checked.bind="speaksEnglish">English 
  </label> 
  <label> 
    <input type="checkbox" checked.bind="speaksGerman">German 
  </label> 
</template> 

```

在此示例中，每个`checkbox`绑定到不同的属性，这将根据复选框是否被选中分配`true`或`false`。

## `textarea`

绑定到`textarea`元素与绑定到`text``input`元素相同：

```js
<template> 
  <textarea value.bind="text"></textarea> 
</template> 

```

在此，`text`属性的初始值将在`textarea`内显示，由于`textarea`的`value`属性的绑定是默认的双向的，用户对`textarea`内容的所有修改都将反映在`text`属性上。

## 禁用元素

禁用`input`、`select`、`textarea`或`button`元素只需绑定到其`disabled`属性即可：

```js
<template> 
  <input type="text" disabled.bind="isSending"> 
  <button disabled.bind="isSending">Send</button> 
</template> 

```

当`isSending`为`true`时，`input`和`button`元素都将被禁用。

## 设置元素只读

同样，使`input`或`textarea`元素只读只需将其`readonly`属性绑定即可：

```js
<template> 
  <input type="text" readonly.bind="!canEdit"> 
</template> 

```

在此，当`canEdit`为`false`时，`input`将变为只读。

# 向我们的应用程序添加表单

既然我们知道如何处理用户输入元素，我们可以在我们的联系人管理应用程序中添加表单以创建和编辑联系人。

## 添加新路由

我们需要添加三个新路由：一个用于创建新联系人，另一个用于编辑现有联系人，最后一个用于上传联系人的照片。让我们在根组件中添加它们：

`src/app.js`文件将如下所示：

```js
export class App { 
  configureRouter(config, router) { 
    this.router = router; 
    config.title = 'Learning Aurelia'; 
    config.map([ 
      { route: '', redirect: 'contacts' }, 
      { route: 'contacts', name: 'contacts', moduleId:        'contact-list',  
        nav: true, title: 'Contacts' }, 
      { route: 'contacts/new', name: 'contact-creation',  
        moduleId: 'contact-edition', title: 'New contact' }, 
      { route: 'contacts/:id', name: 'contact-details',  
        moduleId: 'contact-details' }, 
      { route: 'contacts/:id/edit', name: 'contact-edition',  
        moduleId: 'contact-edition' }, 
      { route: 'contacts/:id/photo', name: 'contact-photo', 
        moduleId: 'contact-photo' }, 
    ]); 
    config.mapUnknownRoutes('not-found'); 
  } 
} 

```

在前面的代码片段中，三个新路由被突出显示。

在这里，定位很重要。`contact-creation`路径在`contact-details`路径之前，这是因为它们的`route`属性。在尝试查找 URL 更改时的匹配路径时，路由器会按照它们被定义的顺序深入路由定义。由于`contact-details`的模式匹配任何以`contacts/`开头，后跟第二个部分作为参数的解释，因此路径`contacts/new`符合此模式，所以如果`contact-creation`路径定义在后面，它将无法到达，而`contact-details`路径将使用等于`new`的`id`参数到达。

依赖于路由顺序的更好替代方法是将模式更改，以避免可能的冲突。例如，我们可以将`contact-details`的模式更改为类似于`contacts/:id/details`。在这种情况下，路由的顺序将不再重要。

您可能已经注意到两个新路径具有相同的`moduleId`。这是因为我们将为创建新联系人和编辑现有联系人使用相同的组件。

## 添加新路径的链接

下一步将是添加刚刚添加的路由的链接。我们首先在`contact-list`组件中添加一个到`contact-creation`路径的链接：

`src/contact-list.html`

```js
 <template> 
  <section class="container"> 
    <h1>Contacts</h1> 

    <div class="row"> 
      <div class="col-sm-1"> 
        <a route-href="route: contact-creation" class= "btn btn-primary"> 
          <i class="fa fa-plus-square-o"></i> New 
        </a> 
      </div> 
      <div class="col-sm-2"> 
        <!-- Search box omitted for brevity --> 
      </div> 
    </div> 
    <!--  Contact list omitted for brevity --> 
  </section> 
</template> 

```

在这里，我们添加了一个`a`元素，并利用`route-href`属性渲染`contact-creation`路径的 URL。

我们还需要添加到`contact-photo`和`contact-edition`路径的链接。我们将在`contact-details`组件中完成这个任务：

`src/contact-details.html`

```js
 <template> 
  <section class="container"> 
    <div class="row"> 
      <div class="col-sm-2"> 
        <a route-href="route: contact-photo; params.bind:
          { id: contact.id }"  
           > 
          <img src.bind="contact.photoUrl" class= "img-responsive" alt="Photo"> 
        </a> 
      </div> 
      <div class="col-sm-10"> 
        <template if.bind="contact.isPerson"> 
          <h1>${contact.fullName}</h1> 
          <h2>${contact.company}</h2> 
        </template> 
        <template if.bind="!contact.isPerson"> 
          <h1>${contact.company}</h1> 
        </template> 
        <a class="btn btn-default" route-href="route:
          contact-edition;  
          params.bind: { id: contact.id }"> 
          <i class="fa fa-pencil-square-o"></i> Modify 
        </a> 
      </div> 
    </div> 
    <!-- Rest of template omitted for brevity --> 
  </section> 
</template> 

```

在这里，我们首先重构显示`fullName`和`company`（如果联系人是人）的模板，通过添加一个外部的`div`并将`col-sm-10`CSS 类从标题移动到这个`div`。

接下来，我们将显示联系人性照的`img`元素包裹在一个导航到`contact-photo`路径的锚点中，使用联系人的`id`作为参数。

最后，我们添加另一个指向`contact-edition`路径的锚点，使用联系人的`id`作为参数。

## 更新模型

为了重用代码，我们将坚持使用`Contact`类，并在我们的表单组件中使用它。我们还将为电话号码、电子邮件地址、地址和社会资料创建类，这样我们的`contact-edition`组件就无需知道创建这些对象空实例的详细信息。

我们需要添加创建我们模型空实例的能力，并将其所有属性初始化为适当的默认值。因此，我们将为我们的模型类添加所有属性的默认值。

最后，我们需要更新`Contact`的`fromObject`工厂方法，以便所有列表项都正确映射到我们的模型类实例。

`src/models.js`

```js
export class PhoneNumber { 
  static fromObject(src) { 
    return Object.assign(new PhoneNumber(), src); 
  } 

  type = 'Home'; 
  number = ''; 
} 

export class EmailAddress { 
  static fromObject(src) { 
    return Object.assign(new EmailAddress(), src); 
  } 

  type = 'Home'; 
  address = ''; 
} 

export class Address { 
  static fromObject(src) { 
    return Object.assign(new Address(), src); 
  } 

  type = 'Home'; 
  number = ''; 
  street = ''; 
  postalCode = ''; 
  city = ''; 
  state = ''; 
  country = ''; 
} 

export class SocialProfile { 
  static fromObject(src) { 
    return Object.assign(new SocialProfile(), src); 
  } 

  type = 'GitHub'; 
  username = ''; 
} 

export class Contact { 
  static fromObject(src) { 
    const contact = Object.assign(new Contact(), src); 
    contact.phoneNumbers = contact.phoneNumbers 
      .map(PhoneNumber.fromObject); 
    contact.emailAddresses = contact.emailAddresses 
      .map(EmailAddress.fromObject); 
    contact.addresses = contact.addresses 
      .map(Address.fromObject); 
    contact.socialProfiles = contact.socialProfiles 
      .map(SocialProfile.fromObject); 
    return contact; 
  } 

  firstName = ''; 
  lastName = ''; 
  company = ''; 
  birthday = ''; 
  phoneNumbers = []; 
  emailAddresses = []; 
  addresses = []; 
  socialProfiles = []; 
  note = ''; 

  // Omitted snippet... 
} 

```

在这里，我们首先添加了`PhoneNumber`、`EmailAddress`、`Address`和`SocialProfile`类的类。每个类都有一个静态的`fromObject`工厂方法，其属性都使用默认值正确初始化。

接下来，我们添加了一个`Contact`对象属性，其初始值为默认值，并更改了其`fromObject`工厂方法，以便列表项能够正确映射到它们相应的类中。

## 创建表单组件

现在我们可以创建我们新的`contact-edition`组件了。如早前所提，这个组件将用于创建和编辑。它能够通过检查在其`activate`回调方法中是否接收了一个`id`参数来检测它是用于创建新的联系人还是编辑现有的联系人。确实，`contact-creation`路由的模式定义了无参数，所以当我们的表单组件通过这个路由被激活时，它不会接收任何`id`参数。另一方面，由于`contact-edition`路由的模式确实定义了一个`id`参数，所以当我们的表单组件通过这个路由被激活时，它会接收到这个参数。

我们可以这样做，因为在我们联系管理应用程序的范围内，创建和编辑过程几乎是一致的。然而，在许多情况下，最好是为创建和编辑分别设计单独的组件。

### 激活视图模型

让我们首先从视图模型和`activate`回调方法开始：

`src/contact-edition.js`

```js
import {inject} from 'aurelia-framework'; 
import {ContactGateway} from './contact-gateway'; 
import {Contact} from './models'; 

@inject(ContactGateway) 
export class ContactEdition { 
  constructor(contactGateway) { 
    this.contactGateway = contactGateway; 
  } 

  activate(params, config) { 
    this.isNew = params.id === undefined; 
    if (this.isNew) { 
      this.contact = new Contact(); 
    } 
    else { 
      return this.contactGateway.getById(params.id).then(contact => { 
        this.contact = contact; 
        config.navModel.setTitle(contact.fullName); 
      }); 
    } 
  } 
} 

```

在这里，我们首先向我们的视图模型注入`ContactGateway`类的实例。然后，在`activate`回调方法中，我们首先定义了一个`isNew`属性，该属性基于是否存在`id`参数。这个属性将用于我们的组件，使其知道它是被用来创建一个新的联系人还是编辑一个现有的联系人。

接下来，基于这个`isNew`属性，我们初始化组件。如果我们正在创建一个新的联系人，那么我们只需创建一个`contact`属性并将其分配给一个新的、空的`Contact`实例；否则，我们使用`ContactGateway`根据`id`参数检索适当的联系人，当`Promise`解决时，将`Contact`实例分配给`contact`属性，并将文档标题设置为联系人的`fullName`属性。

一旦激活周期完成，视图模型将有一个适当初始化为`Contact`对象的`contact`属性和一个指示联系人是新的还是现有的`isNew`属性。

### 构建表单布局

接下来，让我们构建一个用于显示表单的模板。由于这个模板相当大，我将把它分成几部分，这样你就可以逐步构建它并在每个步骤进行测试（如果需要的话）。

模板由一个头部组成，后面是一个`form`元素，它将包含模板的其余部分：

`src/contact-edition.html`

```js
 <template> 
  <section class="container"> 
    <h1 if.bind="isNew">New contact</h1> 
    <h1 if.bind="!isNew">Contact #${contact.id}</h1> 

    <form class="form-horizontal"> 
      <!-- The rest of the template goes in here --> 
    </form> 
  </section> 
</template> 

```

在头部，我们使用`isNew`属性来显示是告诉用户他正在创建一个新的联系人还是显示正在编辑的联系人`id`的动态标题。

### 编辑标量属性

接下来，我们将向`form`元素中添加块，其中包含输入元素，以编辑联系人的`firstName`、`lastName`、`company`、`birthday`和`note`，如前一个代码片段中定义的那样：

```js
<div class="form-group"> 
  <label class="col-sm-3 control-label">First name</label> 
  <div class="col-sm-9"> 
    <input type="text" class="form-control" value.bind="contact.firstName"> 
  </div> 
</div> 

<div class="form-group"> 
  <label class="col-sm-3 control-label">Last name</label> 
  <div class="col-sm-9"> 
    <input type="text" class="form-control" value.bind="contact.lastName"> 
  </div> 
</div> 

<div class="form-group"> 
  <label class="col-sm-3 control-label">Company</label> 
  <div class="col-sm-9"> 
    <input type="text" class="form-control" value.bind="contact.company"> 
  </div> 
</div> 

<div class="form-group"> 
  <label class="col-sm-3 control-label">Birthday</label> 
  <div class="col-sm-9"> 
    <input type="date" class="form-control" value.bind="contact.birthday"> 
  </div> 
</div> 

<div class="form-group"> 
  <label class="col-sm-3 control-label">Note</label> 
  <div class="col-sm-9"> 
    <textarea class="form-control" value.bind="contact.note"></textarea> 
  </div> 
</div> 

```

在这里，我们仅为每个属性定义一个`form-group`以进行编辑。前三个属性各自绑定到一个`text input`元素。此外，`birthday`属性绑定到一个`date`输入，使其更容易编辑日期——当然，仅限支持它的浏览器，而`note`属性则绑定到一个`textarea`元素。

### 编辑电话号码

在此之后，我们需要为列表添加编辑器。由于每个列表中包含的数据并不复杂，我们将使用内联编辑器，这样用户就可以在最少的点击次数内直接编辑任何项目的任何字段。

我们将在本章后面讨论更复杂的编辑模型，使用对话框。

让我们从电话号码开始：

```js
<hr> 
<div class="form-group" repeat.for="phoneNumber of contact.phoneNumbers"> 
  <div class="col-sm-2 col-sm-offset-1"> 
    <select value.bind="phoneNumber.type" class="form-control"> 
      <option value="Home">Home</option> 
      <option value="Office">Office</option> 
      <option value="Mobile">Mobile</option> 
      <option value="Other">Other</option> 
    </select> 
  </div> 
  <div class="col-sm-8"> 
    <input type="tel" class="form-control" placeholder="Phone number"  
           value.bind="phoneNumber.number"> 
  </div> 
  <div class="col-sm-1"> 
    <button type="button" class="btn btn-danger"  
            click.delegate="contact.phoneNumbers.splice($index, 1)"> 
      <i class="fa fa-times"></i>  
    </button> 
  </div> 
</div> 
<div class="form-group"> 
  <div class="col-sm-9 col-sm-offset-3"> 
    <button type="button" class="btn btn-default" click.delegate="contact.addPhoneNumber()"> 
      <i class="fa fa-plus-square-o"></i> Add a phone number 
    </button> 
  </div> 
</div> 

```

这个电话号码列表编辑器可以分解为几个部分，其中最重要的是突出显示的。首先，为联系的`phoneNumbers`数组中的每个`phoneNumber`重复一个`form-group`。

对于每个`phoneNumber`，我们定义一个`select`元素，其`value`绑定到`phoneNumber`的`type`属性，以及一个`tel`输入，其`value`绑定到`phoneNumber`的`number`属性。此外，我们定义了一个`button`，当点击时，使用当前的`$index`（正如您可能记得的前一章中提到的，这是通过`repeat`属性添加到绑定上下文的），从`contact`的`phoneNumbers`数组中拼接出电话号码。

最后，在电话号码列表之后，我们定义了一个`button`，其`click`事件调用`contact`中的`addPhoneNumber`方法。

### 添加缺失的方法

我们在上一个模板中添加的按钮之一调用了一个尚未定义的方法。让我们把这个方法添加到`Contact`类中：

`src/models.js`

```js
//Snippet... 
export class Contact { 
  //Snippet... 
  addPhoneNumber() { 
    this.phoneNumbers.push(new PhoneNumber()); 
  } 
} 

```

此代码片段中的第一个方法用于向列表中添加一个空电话号码，简单地在`phoneNumbers`数组中推入一个新的`PhoneNumber`实例。

### 编辑其他列表

其他列表的模板，如电子邮件地址、地址和社会资料，都非常相似。只有正在编辑的字段会改变，但主要概念——重复的表单组、每个条目都有一个删除按钮和一个在列表末尾的添加按钮——是相同的。

让我们从`emailAddresses`开始：

```js
<hr> 
<div class="form-group" repeat.for="emailAddress of contact.emailAddresses"> 
  <div class="col-sm-2 col-sm-offset-1"> 
    <select value.bind="emailAddress.type" class="form-control"> 
      <option value="Home">Home</option> 
      <option value="Office">Office</option> 
      <option value="Other">Other</option> 
    </select> 
  </div> 
  <div class="col-sm-8"> 
    <input type="email" class="form-control" placeholder="Email address"  
           value.bind="emailAddress.address"> 
  </div> 
  <div class="col-sm-1"> 
    <button type="button" class="btn btn-danger"  
            click.delegate="contact.emailAddresses.splice($index, 1)"> 
      <i class="fa fa-times"></i>  
    </button> 
  </div> 
</div> 
<div class="form-group"> 
  <div class="col-sm-9 col-sm-offset-3"> 
    <button type="button" class="btn btn-primary"  
            click.delegate="contact.addEmailAddress()"> 
      <i class="fa fa-plus-square-o"></i> Add an email address 
    </button> 
  </div> 
</div> 

```

这个模板与电话号码的模板非常相似。主要区别在于可用的类型并不完全相同，而且`input`的`type`是`email`。

如您所想象，地址的编辑器会更大一些：

```js
<hr> 
<div class="form-group" repeat.for="address of contact.addresses"> 
  <div class="col-sm-2 col-sm-offset-1"> 
    <select value.bind="address.type" class="form-control"> 
      <option value="Home">Home</option> 
      <option value="Office">Office</option> 
      <option value="Other">Other</option> 
    </select> 
  </div> 
  <div class="col-sm-8"> 
    <div class="row"> 
      <div class="col-sm-4"> 
        <input type="text" class="form-control" placeholder="Number"  
               value.bind="address.number"> 
      </div> 
      <div class="col-sm-8"> 
        <input type="text" class="form-control" placeholder="Street"  
               value.bind="address.street"> 
      </div> 
    </div> 
    <div class="row"> 
      <div class="col-sm-4"> 
        <input type="text" class="form-control" placeholder="Postal code"  
               value.bind="address.postalCode"> 
      </div> 
      <div class="col-sm-8"> 
        <input type="text" class="form-control" placeholder="City"  
               value.bind="address.city"> 
      </div> 
    </div> 
    <div class="row"> 
      <div class="col-sm-4"> 
        <input type="text" class="form-control" placeholder="State"  
               value.bind="address.state"> 
      </div> 
      <div class="col-sm-8"> 
        <input type="text" class="form-control" placeholder="Country"  
               value.bind="address.country"> 
      </div> 
    </div> 
  </div> 
  <div class="col-sm-1"> 
    <button type="button" class="btn btn-danger"  
            click.delegate="contact.addresses.splice($index, 1)"> 
      <i class="fa fa-times"></i>  
    </button> 
  </div> 
</div> 
<div class="form-group"> 
  <div class="col-sm-9 col-sm-offset-3"> 
    <button type="button" class="btn btn-primary"  
            click.delegate="contact.addAddress()"> 
      <i class="fa fa-plus-square-o"></i> Add an address 
    </button> 
  </div> 
</div> 

```

在这里，左侧包含六个不同的输入，允许我们编辑地址的各种文本属性。

至此，您可能已经对社交资料的模板有一个大致的了解：

```js
<hr> 
<div class="form-group" repeat.for="profile of contact.socialProfiles"> 
  <div class="col-sm-2 col-sm-offset-1"> 
    <select value.bind="profile.type" class="form-control"> 
      <option value="GitHub">GitHub</option> 
      <option value="Twitter">Twitter</option> 
    </select> 
  </div> 
  <div class="col-sm-8"> 
    <input type="text" class="form-control" placeholder="Username"  
           value.bind="profile.username"> 
  </div> 
  <div class="col-sm-1"> 
    <button type="button" class="btn btn-danger"  
            click.delegate="contact.socialProfiles.splice($index, 1)"> 
      <i class="fa fa-times"></i>  
    </button> 
  </div> 
</div> 
<div class="form-group"> 
  <div class="col-sm-9 col-sm-offset-3"> 
    <button type="button" class="btn btn-primary"  
            click.delegate="contact.addSocialProfile()"> 
      <i class="fa fa-plus-square-o"></i> Add a social profile 
    </button> 
  </div> 
</div> 

```

当然，每个列表添加项目的方法都需要添加到`Contact`类中：

`src/models.js`

```js
//Omitted snippet... 
export class Contact { 
  //Omitted snippet... 
  addEmailAddress() { 
    this.emailAddresses.push(new EmailAddress()); 
  } 

  addAddress() { 
    this. addresses.push(new Address()); 
  } 

  addSocialProfile() { 
    this.socialProfiles.push(new SocialProfile()); 
  } 
} 

```

正如你所看到的，这些方法与我们之前为电话号码编写的那些几乎完全相同。此外，每个列表的模板片段也基本上彼此相同。所有这种冗余都呼吁进行重构。我们将在第五章，*制作可复用的组件*中看到，如何将常见行为和模板片段提取到一个组件中，我们将重新使用它来管理每个列表。

### 保存和取消

我们表单（至少在视觉上）完整的最后一件缺失的事情是在包含`form`元素的末尾添加一个保存和取消按钮：

```js
//Omitted snippet... 
<form class="form-horizontal" submit.delegate="save()"> 
  //Omitted snippet... 
  <div class="form-group"> 
      <div class="col-sm-9 col-sm-offset-3"> 
        <button type="submit" class="btn btn-success">Save</button> 
        <a if.bind="isNew" class="btn btn-danger"  
           route-href="route: contacts">Cancel</a> 
        <a if.bind="!isNew" class="btn btn-danger"  
           route-href="route: contact-details;  
           params.bind: { id: contact.id }">Cancel</a> 
      </div> 
    </div> 
</form> 

```

首先，我们将一个对`save`方法的调用绑定到`form`元素的`submit`事件，然后我们添加了一个包含一个名为`Save`的`submit`按钮的最后一个`form-group`。

接下来，我们添加了两个`Cancel`链接：一个在创建新联系人时显示，用于导航回到联系人列表；另一个在编辑现有联系人时显示，用于导航回到联系人的详细信息。

我们还需要将`save`方法添加到视图模型中。这个方法最终将委派给`ContactGateway`，但为了测试我们到目前为止所做的一切是否工作，让我们只写一个方法版本：

```js
save() { 
  alert(JSON.stringify(this.contact)); 
} 

```

至此，你应该能够运行应用程序并尝试创建或编辑一个联系人。点击**保存**按钮时，你应该会看到一个显示联系人的警报，该联系人作为 JSON 序列化格式。

## 使用 fetch 发送数据

我们现在可以向`ContactGateway`类添加创建和更新联系人的方法：

`src/contact-gateway.js`

```js
//Omitted snippet... 
import {HttpClient, json} from 'aurelia-fetch-client'; 
//Omitted snippet... 
export class ContactGateway { 
  //Omitted snippet... 
  create(contact) { 
    return this.httpClient.fetch('contacts',  
      { method: 'POST', body: json(contact) }); 
  } 

  update(id, contact) { 
    return this.httpClient.fetch(`contacts/${id}`,  
      { method: 'PUT', body: json(contact) }); 
  } 
} 

```

首先要做的第一件事是`import`从`fetch-client`中`json`函数。这个函数接受任何 JS 值作为参数，并返回一个包含接收参数序列化为 JSON 的`Blob`对象。

接下来，我们添加了一个`create`方法，它接受一个`contact`作为参数，并调用 HTTP 客户端的`fetch`方法，传递要调用的相对 URL，然后是一个配置对象。这个对象包含将分配给底层`Request`对象的属性。在这里，我们指定一个`method`属性，告诉客户端执行一个`POST`请求，我们指示请求的`body`将是序列化为 JSON 的`contact`。最后，`fetch`方法返回一个`Promise`，这是我们新`create`方法返回的，所以调用者可以在请求完成后做出反应。

`update`方法非常相似。第一个区别是参数：首先期望联系人的`id`，然后是`contact`对象本身。其次，`fetch`调用略有不同；它发送一个到不同 URL 的请求，使用`PUT`方法，但其主体相同。

一个 Fetch`Request`的`body`预期是一个`Blob`、一个`BufferSource`、一个`FormData`、一个`URLSearchParams`或一个`USVString`对象。关于这方面的文档可以在 Mozilla 开发者网络上找到，网址为[`developer.mozilla.org/en-US/docs/Web/API/Request/Request`](https://developer.mozilla.org/en-US/docs/Web/API/Request/Request)。

为了测试我们新方法是否有效，让我们将`contact-edition`组件的视图模型中的模拟`save`方法替换为真实的方法：

```js
//Omitted snippet... 
import {Router} from 'aurelia-router'; 

@inject(ContactGateway, Router) 
export class ContactEdition { 
  constructor(contactGateway, router) { 
    this.contactGateway = contactGateway; 
    this.router = router; 
  } 

  // Omitted snippet... 
  save() { 
    if (this.isNew) { 
      this.contactGateway.create(this.contact)  
        .then(() => this.router.navigateToRoute('contacts')); 
    } 
    else { 
      this.contactGateway.update(this.contact.id, this.contact)  
        .then(() => this.router.navigateToRoute('contact-details',  
                    { id: this.contact.id })); 
    } 
  } 
} 

```

在这里，我们首先导入`Router`，并在视图模型中注入它的一个实例。接下来，我们改变`save`方法的主体：如果组件正在创建一个新的联系人，我们首先调用`ContactGateway`的`create`方法，将`contact`对象传递给它，然后在`Promise`解决时返回至`contacts`路由；否则，当组件正在编辑一个现有的联系人时，我们首先调用`ContactGateway`的`update`方法，将联系人的`id`和`contact`对象传递给它，然后在`Promise`解决时返回至该联系人的详情路由。

此时，你应该能够创建或更新一个联系人。然而，一些创建或更新的请求可能会返回状态码为 400 的响应，表示“坏的请求”。不必惊慌；因为 HTTP 端点会执行一些验证，而我们的表单目前不会，所以这种情况是预料之中的，例如，如果你留下了一些字段是空的。我们将在本章后面为我们的表单添加验证，这将防止这类错误的发生。

## 上传联系人的照片

既然我们能够创建和编辑联系人，现在让我们添加一个组件来上传其照片。这个组件将被命名为`contact-photo`，并通过我们已经在本章早些时候添加的具有相同名称的路由来激活。

这个组件将使用一个`file input`元素让用户从他的文件系统中选择一个图片文件，并将利用 HTML5 文件 API 以及 Fetch 客户端将选定的图片文件发送到我们的 HTTP 端点。

### 构建模板

这个组件的模板简单地重用了我们已经在前面讲解过的几个概念：

`src/contact-photo.html`

```js
 <template> 
  <section class="container"> 
    <h1>${contact.fullName}</h1> 

    <form class="form-horizontal" submit.delegate="save()"> 
      <div class="form-group"> 
        <label class="col-sm-3 control-label" for="photo">Photo</label> 
        <div class="col-sm-9"> 
          <input type="file" id="photo" accept="image/*"  
                 files.bind="photo"> 
        </div> 
      </div> 

      <div class="form-group"> 
        <div class="col-sm-9 col-sm-offset-3"> 
          <button type="submit" class="btn btn-success">Save</button> 
          <a class="btn btn-danger" route-href="route: contact-details;  
             params.bind: { id: contact.id }">Cancel</a> 
        </div> 
      </div> 
    </form> 
  </section> 
</template> 

```

在这里，我们首先将联系人的`fullName`作为页面标题显示出来。然后，在一个`form`元素中，其`submit`事件会触发一个`save`方法，我们添加了一个`file input`和两个按钮，用于**保存**或**取消**上传照片。`file input`有一个`accept`属性，迫使浏览器的文件选择对话框只显示图片文件，并且它的`files`属性被绑定到`photo`属性。

### 创建视图模型

视图模型与`contact-edition`视图模型非常相似，至少在比较导入、构造函数和`activate`方法时是这样的：

`src/contact-photo.js`

```js
import {inject} from 'aurelia-framework'; 
import {Router} from 'aurelia-router'; 
import {ContactGateway} from './contact-gateway'; 

@inject(ContactGateway, Router) 
export class ContactPhoto { 

  constructor(contactGateway, router) { 
    this.contactGateway = contactGateway; 
    this.router = router; 
  } 

  activate(params, config) { 
    return this.contactGateway.getById(params.id).then(contact => { 
      this.contact = contact; 
      config.navModel.setTitle(this.contact.fullName); 
    }); 
  } 
  save() { 
    if (this.photo && this.photo.length > 0) { 
      this.contactGateway.updatePhoto( 
        this.contact.id,  
        this.photo.item(0) 
      ).then(() => { 
        this.router.navigateToRoute( 
          'contact-details',  
          { id: this.contact.id }); 
      }); 
    } 
  } 
} 

```

这个视图模型期望在其构造函数中注入`ContactGateway`的一个实例和`Router`的一个实例。在其`activate`方法中，它然后使用其`id`参数加载一个`Contact`实例，并使用`contact`的`fullName`初始化文档标题。这与`contact-edition`视图模型非常相似。

`save`方法有一点不同。它首先检查是否已经选择了文件；如果没有，现在什么也不做。否则，它调用`ContactGateway`的`updatePhoto`方法，将联系人的`id`和选定的文件传递给它，并在`Promise`解决时返回到联系人的详细信息。

### 使用 fetch 上传文件

使我们的照片上传功能正常工作的最后一步是在`ContactGateway`类中的`uploadPhoto`方法：

`src/contact-gateway.js`

```js
//Omitted snippet... 
export class ContactGateway { 
  //Omitted snippet... 
  updatePhoto(id, file) { 
    return this.httpClient.fetch(`contacts/${id}/photo`, {  
      method: 'PUT', 
      headers: { 'Content-Type': file.type }, 
      body: file 
    }); 
  } 
} 

```

我们 HTTP 后端的`contacts/{id}/photo`端点期望一个 PUT 请求，带有正确的`Content-Type`头和图像二进制作为其主体。这正是这里`fetch`调用的作用：它使用`file`参数，这被期望是一个`File`类的实例，并使用它的`type`属性设置`Content-Type`头，然后将`file`本身作为请求体发送。

如早先所述，`File`类是 HTML5 文件 API 的一部分。Mozilla 开发者网络提供了关于这个 API 的详尽文档。关于`File`类的细节可以在[`developer.mozilla.org/en-US/docs/Web/API/File`](https://developer.mozilla.org/en-US/docs/Web/API/File)找到。

像往常一样，`updatePhoto`方法返回由 HTTP 请求解决的`Promise`，所以调用者可以在操作完成时采取行动。

至此，你应该能够运行应用程序并通过上传新图像文件来更新联系人的照片。

## 删除联系人

至此，我们的应用程序允许我们创建、读取和更新联系人。显然，**创建、读取、更新、删除**（**CRUD**）这四个字母中有一个缺失了：我们还不能删除一个联系人。让我们快速实现这个功能。

首先，让我们在联系人的`details`组件中添加一个**删除**按钮：

`src/contact-details.html`

```js
 <template> 
  <section class="container"> 
    <div class="row"> 
      <div class="col-sm-2"> 
        <!-- Omitted snippet... --> 
      </div> 
      <div class="col-sm-10"> 
        <!-- Omitted snippet... --> 
        <a class="btn btn-default" route-href="route: contact-edition;  
          params.bind: { id: contact.id }"> 
          <i class="fa fa-pencil-square-o"></i> Modify 
        </a> 
        <button class="btn btn-danger" click.delegate="tryDelete()"> 
          <i class="fa fa-trash-o"></i> Delete 
        </button> 
      </div> 
    </div> 
    <!-- Rest of template omitted for brevity --> 
  </section> 
</template> 

```

新的**删除**按钮将在点击时调用`tryDelete`方法：

`src/contact-details.js`

```js
//Omitted snippet... 
export class ContactDetails { 
  //Omitted snippet... 
  tryDelete() { 
    if (confirm('Do you want to delete this contact?')) { 
      this.contactGateway.delete(this.contact.id) 
        .then(() => { this.router.navigateToRoute('contacts'); }); 
    } 
  } 
} 

```

`tryDelete`方法首先要求用户进行**确认**删除，然后使用联系人的`id`调用网关的`delete`方法。当返回的`Promise`解决时，它返回到联系人列表。

最后，`ContactGateway`类的`delete`方法只是执行一个到后端适当路径的 Fetch 调用，使用`DELETE`HTTP 方法：

`src/contact-gateway.js`

```js
//Omitted snippet... 
export class ContactGateway { 
  //Omitted snippet... 
  delete(id) { 
    return this.httpClient.fetch(`contacts/${id}`, { method: 'DELETE' }); 
  } 
} 

```

至此，如果你点击一个联系人的**删除**按钮并批准确认对话框，你应该会被重定向到联系人列表，并且联系人应该消失了。

# 验证

如果你尝试保存一个生日无效、电话号码为空、地址、电子邮件或社交资料用户名为空的联系人，而你的浏览器的调试控制台是打开的，你会看到 HTTP 端点用 400 Bad Request 响应拒绝这个请求。这是因为后端在对创建或更新的联系人执行一些验证。

拥有一个执行某种验证的远程服务是很常见的；相反的，实际上被认为是糟糕的架构，因为远程服务不应该信任其客户端的有效数据。然而，为了提供更佳的用户体验，通常也会看到客户端应用程序也执行验证。

Aurelia 提供了`aurelia-validation`库，该库为验证提供者定义了一个接口，以及将验证插入组件的各种机制。它还提供了这个接口的默认实现，提供了一个简单而强大的验证机制。

让我们看看我们如何使用这些库来验证我们的联系人表单。

这一节只是对`aurelia-validation`提供的最常见特性的概述。实际上，这个库比这里描述的要灵活得多，功能也更强大，所以我在阅读这本书后邀请你进一步挖掘它。

## 安装库

要安装这个库，你只需要在项目的目录下运行以下命令：

```js
> npm install aurelia-validation --save

```

接下来，我们需要使这个库在应用程序的包中可用。在`aurelia_project/aurelia.json`中，在`build`下的`bundles`中，在名为`vendor-bundle.js`的包的`dependencies`数组中，添加以下条目：

```js
{ 
  "name": "aurelia-validation", 
  "path": "../node_modules/aurelia-validation/dist/amd", 
  "main": "aurelia-validation" 
}, 

```

这个配置项将告诉 Aurelia 的打包器将新安装的库包含在供应商包中。

## 配置

`aurelia-validation`库在使用前需要一些配置。此外，作为一个 Aurelia 插件，它需要在我们的应用程序启动时加载。

我们可以在我们主要的`configure`函数里完成这一切。然而，这种情况真的是一个很好的 Aurelia 特性的候选。如果你记得的话，特性类似于插件，只不过它们是在应用程序本身内定义的。通过引入一个`validation`特性，我们可以隔离验证的配置，这会给我们一个可以放置额外服务和自定义验证规则的中央位置。

让我们先创建我们的`validation`特性：

`src/validation/index.js`

```js
export function configure(config) { 
  config 
    .plugin('aurelia-validation'); 
} 

```

我们新特性的`configure`函数只是加载了`aurelia-validation`插件。

接下来，我们需要在我们主要的`configure`函数中加载这个特性：

```js
src/main.js 
//Omitted snippet... 
export function configure(aurelia) { 
  aurelia.use 
    .standardConfiguration() 
    .feature('validation') 
    .feature('resources'); 
  //Omitted snippet... 
} 

```

在这里，我们只是链接了引导式 API 的`feature`方法的额外调用，以加载我们的`validation`特性。

## 验证联系人表单

既然一切配置都正确，那就让我们在我们的`contact-edition`表单中添加验证吧。

### 设置模板

为了告诉验证机制需要验证什么，所有用于获取待验证用户输入的双向绑定都必须用`validate`绑定行为装饰，这由`aurelia-validation`提供：

`src/contact-edition.html`

```js
 <template> 
  <!-- Omitted snippet... -->   
  <input type="text" class="form-control"  
         value.bind="contact.firstName & validate"> 
  <!-- Omitted snippet... --> 
  <input type="text" class="form-control"  
         value.bind="contact.birthday & validate"> 
  <!-- Omitted snippet... --> 
  <textarea class="form-control"  
            value.bind="contact.note & validate"></textarea> 
  <!-- Omitted snippet... --> 
  <select value.bind="phoneNumber.type & validate" class="form-control"> 
  <!-- Omitted snippet... --> 
  <input type="tel" class="form-control" placeholder="Phone number"  
         value.bind="phoneNumber.number & validate"> 
  <!-- Omitted snippet... --> 
</template> 

```

在这里，我们在每个双向绑定中添加了`validate`绑定行为。代码片段没有展示`contact-edition`表单的所有绑定；我留给读者一个练习，即在模板中所有`input`、`textarea`和`select`元素的`value`属性上添加`validate`。本书的示例应用程序可以作为参考。

`validate`绑定行为有两个任务。首先，它将绑定指令注册到`ValidationController`，该控制器为给定组件组织验证，所以验证机制知道指令绑定的属性，并在需要时对其进行验证。其次，它可以连接到绑定指令，所以绑定到元素的属性可以在元素的目标值变化时立即验证。

### 使用 ValidationController

`ValidationController`在验证过程中扮演着指挥者的角色。它跟踪一组需要验证的绑定，提供方法手动触发验证，并记录当前的验证错误。

为了利用`ValidationController`，我们首先必须在组件中注入一个实例：

`src/contact-edition.js`

```js
import {inject, NewInstance} from 'aurelia-framework'; 
import {ValidationController} from 'aurelia-validation'; @inject(ContactGateway, NewInstance.of(ValidationController), Router) 
export class ContactEdition { 

  constructor(contactGateway, validationController, router) { 
    this.contactGateway = contactGateway; 
    this.validationController = validationController; 
    this.router = router; 
  } 
  //Omitted snippet... 
} 

```

在这里，我们向视图模型中注入了一个全新的`ValidationController`实例。使用`NewInstance`解析器很重要，因为默认情况下，DI 容器认为所有服务都是应用程序单例，而我们确实希望每个组件都有一个独特的实例，以便在验证时它们可以被孤立考虑。

接下来，我们只需要确保在保存任何联系人之前表单是有效的：

`src/contact-edition.js`

```js
//Omitted snippet... 
export class ContactEdition { 
  //Omitted snippet... 
  save() { 
    this.validationController.validate().then(errors => { 
 if (errors.length > 0) { 
 return; 
 } 
      //Omitted call to create or update... 
    } 
  } 
} 

```

在这里，我们将调用网关的`create`或`update`方法的代码封装起来，以便在验证（完成且没有错误时）执行：

`validate`方法返回一个`Promise`，该`Promise`用验证错误数组解决。这意味着验证规则可以是异步的。例如，自定义规则可以执行 HTTP 调用到后端以检查数据唯一性或执行进一步的数据验证，`validate`方法的返回`Promise`将在 HTTP 调用完成时解决。

如果异步规则的`Promise`被拒绝，例如 HTTP 调用失败，`validate`返回的`Promise`也将被拒绝，所以当使用此类异步、远程验证规则时，确保在这个层次上处理拒绝，这样用户就知道发生了什么。

### 添加验证规则

此时，验证已经准备就绪，但不会做任何事情，因为我们还没有在模型上定义任何验证规则。让我们从`Contact`类开始：

`src/models.js`

```js
import {ValidationRules} from 'aurelia-validation'; 
// Omitted snippet... 

export class Contact { 
  // Omitted snippet... 

  constructor() { 
 ValidationRules 
 .ensure('firstName').maxLength(100) 
 .ensure('lastName').maxLength(100) 
 .ensure('company').maxLength(100) 
 .ensure('birthday') 
 .satisfies((value, obj) => value === null || value === undefined 
 || value === '' || !isNaN(Date.parse(value))) 
 .withMessage('${$displayName} must be a valid date.') 
 .ensure('note').maxLength(2000) 
 .on(this); 
 } 

  //Omitted snippet... 
} 

```

在这里，我们使用`aurelia-validation`的流式 API，为`Contact`的某些属性添加验证规则：`firstName`、`lastName`和`company`属性的长度不能超过 100 个字符，`note`属性的长度不能超过 2000 个字符。

此外，我们使用`satisfies`方法为`birthday`属性定义内联的自定义规则。这个规则确保`birthday`只有在它是空值或可以解析为有效`Date`对象的字符串时才是有效的。我们还使用`withMessage`方法指定当我们的自定义规则被违反时应显示的错误消息模板。

消息模板使用与 Aurelia 的模板引擎相同的字符串插值语法，并且可以使用一个名为`$displayName`的上下文变量，它包含正在验证的属性的显示名称。

### 注意

自定义验证规则应始终接受空值。这是为了保持关注点的分离；`required`规则已经负责拒绝空值，所以你的自定义规则应只关注其自己的特定验证逻辑。这样，开发者可以根据他们想做什么，选择性地使用你的自定义规则，或不与`required`一起使用。

最后，`on`方法将刚刚构建的规则集附加到`Contact`实例的元数据中。这样，当验证`Contact`对象的属性时，验证过程可以检索应适用的验证规则。

我们还需要为`Contact`中代表列表项的所有类添加验证规则：

`src/models.js`

```js
//Omitted snippet... 

export class PhoneNumber { 
  //Omitted snippet... 

  constructor() { 
 ValidationRules 
 .ensure('type').required().maxLength(25) 
 .ensure('number').required().maxLength(25) 
 .on(this); 
 } 

  //Omitted snippet... 
} 

export class EmailAddress { 
  //Omitted snippet...   

  constructor() { 
 ValidationRules 
 .ensure('type').required().maxLength(25) 
 .ensure('address').required().maxLength(250).email() 
 .on(this); 
 } 

  //Omitted snippet...   
} 

export class Address { 
  //Omitted snippet... 

  constructor() { 
 ValidationRules 
 .ensure('type').required().maxLength(25) 
 .ensure('number').required()maxLength(100) 
 .ensure('street').required().maxLength(100) 
 .ensure('postalCode').required().maxLength(25) 
 .ensure('city').required().maxLength(100) 
 .ensure('state').maxLength(100) 
 .ensure('country').required().maxLength(100) 
 .on(this); 
 } 

  //Omitted snippet... 
} 

export class SocialProfile { 
  //Omitted snippet...   

  constructor() { 
 ValidationRules 
 .ensure('type').required().maxLength(25) 
 .ensure('username').required().maxLength(100) 
 .on(this); 
 } 

  //Omitted snippet...   
} 

```

在这里，我们将每个属性设置为`required`，并为它们指定最大长度。此外，我们确保`EmailAddress`类的`address`属性是一个有效的电子邮件地址。

## 渲染验证错误

此时，如果我们的表单无效，`save`方法不会向后端发送任何 HTTP 请求，这是正确的行为。然而，它仍然不显示任何错误消息。让我们看看如何向用户显示验证错误。

### 错误属性

控制器有一个`errors`属性，其中包含当前的验证错误。这个属性可以用来，例如，渲染一个验证摘要：

`src/contact-edition.html`

```js
<template>   
  <!-- Omitted snippet... --> 
  <form class="form-horizontal" submit.delegate="save()"> 
    <ul class="col-sm-9 col-sm-offset-3 list-group text-danger" 
        if.bind="validationController.errors"> 
      <li repeat.for="error of validationController.errors"  
          class="list-group-item"> 
        ${error.message} 
      </li> 
    </ul> 
    <!-- Omitted snippet... --> 
  </form> 
</template> 

```

在这个例子中，我们添加了一个无序列表，它将在验证控制器有错误时渲染。在这个列表内部，我们为每个`error`重复一个列表项。在每个列表项中，我们渲染错误的`message`。

### 验证错误属性

使用`validation-errors`自定义属性，也可以检索到不是所有的验证错误，而是只检索来自更窄范围的错误。

当添加到给定元素时，此属性会收集其宿主元素下所有验证过的绑定指令的验证错误，并使用双向绑定将这些错误分配给它所绑定的属性。

例如，让我们从上一个示例中移除验证摘要，并使用`validation-errors`属性为表单中的特定字段渲染错误：

`src/contact-edition.html`

```js
<template> 
  <!-- Omitted snippet... --> 
  <div validation-errors.bind="birthdayErrors"  
       class="form-group ${birthdayErrors.length ? 'has-error' : ''}"> 
    <label class="col-sm-3 control-label">Birthday</label> 
    <div class="col-sm-9"> 
      <input type="text" class="form-control"  
             value.bind="contact.birthday & validate"> 
      <span class="help-block" repeat.for="errorInfo of birthdayErrors"> 
 ${errorInfo.error.message} 
 <span> 
    </div> 
  </div> 
  <!-- Omitted snippet... --> 
</template> 

```

在这里，我们在包含`birthday`属性的`form-group div`中添加了`validation-errors`属性，我们将其绑定到新的`birthdayErrors`属性。如果`birthday`有任何错误，我们还向`form-group div`添加了`has-error` CSS 类。最后，我们添加了一个`help-block span`，它针对`birthdayErrors`数组中的每个错误重复出现，并显示错误的`message`。

### 创建自定义 ValidationRenderer

`validation-errors`属性允许我们在模板中显示特定区域的错误。然而，如果我们必须为表单中的每个属性添加此代码，这将很快变得繁琐且无效。幸运的是，`aurelia-validation`提供了一个机制，可以在一个名为验证渲染器的专用服务中提取此逻辑。

验证渲染器是一个实现`render`方法的类。这个方法以其第一个参数接收到一个验证渲染指令对象。这个指令对象包含了关于应显示哪些错误和哪些应移除的信息。它基本上是前一次和当前验证状态之间的差异，因此渲染器知道它必须对 DOM 中显示的错误消息应用哪些更改。

在撰写本文时，Aurelia 中还没有可用的验证渲染器。很可能一些社区插件很快就会提供针对主要 CSS 框架的渲染器。与此同时，让我们自己实现这个功能：

`src/validation/bootstrap-form-validation-renderer.js`

```js
export class BootstrapFormValidationRenderer { 

  render(instruction) { 
    for (let { error, elements } of instruction.unrender) { 
      for (let element of elements) { 
        this.remove(element, error); 
      } 
    } 

    for (let { error, elements } of instruction.render) { 
      for (let element of elements) { 
        this.add(element, error); 
      } 
    } 
  } 
} 

```

在这里，我们导出一个名为`BootstrapFormValidationRenderer`的类，其中包含一个`render`方法。这个方法简单地遍历`instruction`的错误来进行`unrender`，然后遍历每个错误`elements`，并调用一个`remove`方法（我们马上就会写）。接下来，它遍历`instruction`的错误来进行`render`，然后遍历每个错误`elements`，并调用一个`add`方法。

接下来，我们需要告诉我们的类如何显示验证错误，通过编写我们的验证渲染器类中的`add`方法：

```js
add(element, error) { 
  const formGroup = element.closest('.form-group'); 
  if (!formGroup) { 
    return; 
  } 

  formGroup.classList.add('has-error'); 

  const message = document.createElement('span'); 
  message.className = 'help-block validation-message'; 
  message.textContent = error.message; 
  message.id = `bs-validation-message-${error.id}`; 
  element.parentNode.insertBefore(message, element.nextSibling); 
} 

```

在这里，我们检索到离承载绑定指令触发错误的元素的`form-group` CSS 类最近的元素，并向其添加`has-error` CSS 类。接下来，我们创建一个`help-block span`，它将包含错误的`message`。我们还设置其`id`属性使用错误的`id`，这样在需要删除时可以轻松找到它。最后，我们将这个消息元素插入 DOM，紧随触发错误的元素之后。

为了完成我们的渲染器，让我们编写一个将删除先前渲染的验证错误的方法：

```js
remove(element, error) { 
  const formGroup = element.closest('.form-group'); 
  if (!formGroup) { 
    return; 
  } 

  const message = formGroup.querySelector( 
    `#bs-validation-message-${error.id}`); 
  if (message) { 
    element.parentNode.removeChild(message); 
    if (formGroup.querySelectorAll('.help-block.validation-message').length  
        === 0) {     
      formGroup.classList.remove('has-error'); 
    } 
  } 
} 

```

在这里，我们首先获取到离触发错误的绑定说明的宿主元素最近的具有`form-group`类的元素。然后我们使用错误的`id`获取消息元素，并将其从 DOM 中移除。最后，如果`form-group`不再包含任何错误消息，我们将其`has-error`类移除。

我们的验证渲染器现在必须通过依赖注入容器向应用程序提供。逻辑上，我们会在我们`validation`特性的`configure`函数中进行此操作：

`src/validation/index.js`

```js
//Omitted snippet... 
import {BootstrapFormValidationRenderer} 
 from './bootstrap-form-validation-renderer'; 

export function configure(config) { 
  config.plugin('aurelia-validation'); 
  config.container.registerHandler( 
 'bootstrap-form', 
 container => container.get(BootstrapFormValidationRenderer)); 
} 

```

在这里，我们以`bootstrap-form`的名称注册我们的验证渲染器。我们可以在我们的`contact-edition`表单中使用这个名称，告诉验证控制器应该使用这个渲染器来显示`form`的验证错误：

`src/contact-edition.html`

```js
<template> 
  <!-- Omitted snippet... --> 
  <form class="form-horizontal" submit.delegate="save()" 
        validation-renderer="bootstrap-form"> 
    <!-- Omitted snippet... --> 
  </form> 
  <!-- Omitted snippet... --> 
</template> 

```

`validation-renderer`属性将根据提供的值解析我们的`BootstrapFormValidationRenderer`实例，并将其注册到当前的验证控制器。然后控制器会在验证状态发生更改时通知渲染器，以便可以渲染新的错误并移除已解决的错误。

### 注意

使用字符串键注册渲染器使得可以注册多个不同名称的验证渲染器，因此不同的渲染器可以在不同的表单中使用。

## 更改验证触发器

默认情况下，当元素失去焦点时验证属性，但是可以通过设置控制器的`validateTrigger`属性来更改这种行为：

`src/contact-edition.js`

```js
import {ValidationController, validateTrigger} from 'aurelia-validation'; 
// Omitted snippet... 
export class ContactEdition { 
  constructor(contactGateway, validationController, router) { 
    validationController.validateTrigger = validateTrigger.change; 
    // Omitted snippet... 
  } 
} 

```

在这里，我们首先导入`validateTrigger`枚举，并告诉`ValidationController`当它们绑定的元素的值发生变化时应该重新验证属性。

除了`change`，`validateTrigger`枚举还有另外三个值：

+   `blur`：当绑定说明的宿主元素失去焦点时验证属性。这是默认值。

+   `changeOrBlur`：当绑定说明发生变化时或当宿主元素失去焦点时验证属性。它基本上结合了`change`和`blur`两种行为。

+   `manual`：完全禁用自动验证。在这种情况下，只有调用控制器的`validate`方法，如我们在`save`方法中所做的那样，才能触发验证，并且它一次性对所有注册的绑定进行验证。

当然，即使`validateTrigger`是`blur`、`change`或`blurOrChange`，显式调用`validate`方法总是执行验证。

## 创建自定义 ValidationRules

`aurelia-validation`库可以轻松添加自定义验证规则。为了说明这一点，我们首先将应用于`Contact`的`birthday`属性的规则移动到一个可重用的`date`验证规则中。然后，我们还将向我们的联系人照片上传组件添加验证，这需要一些自定义规则来验证文件。

### 验证日期

让我们先创建一个文件，该文件将声明并注册我们各种自定义规则：

`src/validation/rules.js`

```js
import {ValidationRules} from 'aurelia-validation'; 

ValidationRules.customRule( 
  'date',  
  (value, obj) => value === null || value === undefined || value === ''  
                  || !isNaN(Date.parse(value)),  
  '${$displayName} must be a valid date.' 
); 

```

这个文件没有导出任何内容。它只是导入了`ValidationRules`类，并使用其`customRule`静态方法注册了一个新的`date`规则，该规则重用了我们在`Contact`类中之前定义的准则和消息。

接下来，我们需要在某个地方导入这个文件，以便注册规则并将其提供给应用程序。最好在`validation`功能的`configure`函数中执行此操作：

`src/validation/index.js`

```js
import './rules'; 
//Omitted snippet... 

```

通过导入`rules`文件，`date`自定义规则被注册，因此一旦通过 Aurelia 导入`validation`功能，它就可以使用。

最后，我们现在可以更改`Contact`的`birthday`属性的`ValidationRules`，使其使用这个规则：

`src/models.js`

```js
//Omitted snippet... 
export class Contact { 
  //Omitted snippet... 

  constructor() { 
    ValidationRules 
      .ensure('firstName').maxLength(100) 
      .ensure('lastName').maxLength(100) 
      .ensure('company').maxLength(100) 
 .ensure('birthday').satisfiesRule('date') 
      .ensure('note').maxLength(2000) 
      .on(this); 
  } 

  //Omitted snippet... 
} 
//Omitted snippet... 

```

在这里，我们简单地移除了对`birthday`属性的`satisfies`调用，并将其替换为对`satisfiesRule`的调用，该调用期望规则名称作为其第一个参数。

### 验证文件是否被选择

在这一点上，如果未选择任何文件，联系人照片上传组件在用户点击**保存**按钮时不会做任何事情。我们在验证方面可以做的第一件事是确保已选择文件。因此，我们将创建一个名为`notEmpty`的新规则，以确保验证的值有一个`length`属性大于零：

`src/validation/rules.js`

```js
//Omitted snippet... 
ValidationRules.customRule( 
  'notEmpty', 
  (value, obj) => value && value.length && value.length > 0, 
  '${$displayName} must contain at least one item.' 
); 

```

在这里，我们使用`ValidationRules`类的`customRule`静态方法全局注册我们的验证规则。此方法期望以下参数：

+   规则的名称。它必须是唯一的。

+   条件函数，它接收值和（如果有）父对象。如果规则得到满足，它预期返回`true`，如果规则被违反，则返回`false`。它还可以返回一个`Promise`，其解析结果为`boolean`。

+   错误消息模板。

这个规则能够与具有`length`属性的任何值一起工作。例如，它可以用于数组或`FileList`实例。

### 验证文件大小

接下来，我们将创建一个验证规则，以确保`FileList`实例中的所有文件重量小于最大尺寸：

`src/validation/rules.js`

```js
//Omitted snippet... 
ValidationRules.customRule( 
  'maxFileSize', 
  (value, obj, maximum) => !(value instanceof FileList) 
    || value.length === 0 
    || Array.from(value).every(file => file.size <= maximum), 
  '${$displayName} must be smaller than ${$config.maximum} bytes.', 
  maximum => ({ maximum }) 
); 

```

在这里，我们首先定义一个新的`maxFileSize`验证规则，确保`FileList`中的每个文件的大小不超过给定的`maximum`。该规则仅在值为`FileList`实例且`FileList`不为空时适用。

此规则期望一个`maximum`参数。使用此类规则时，传递给`satisfiesRule`流畅方法的任何参数都将传递给底层的条件函数，以便它使用它来评估条件。然而，为了对消息模板可用，规则参数必须在单个对象中聚合。因此，`customRule`可以传递第四个参数，预期是一个函数，它将规则参数聚合到单个对象中。此对象随后作为`$config`对消息模板可用。

这就是我们在`maxFileSize`规则中所看到的；它期望以一个名为`maximum`的参数被调用，这是以字节为单位的最大文件大小。当向属性添加规则时，此参数预期传递给`satisfiesRule`方法：

```js
ValidationRules.ensure('photo').satisfiesRule('maxFileSize', 1024); 

```

此参数随后传递给条件函数，以便可以验证`FileList`实例中所有文件的大小。它还传递给聚合函数，该函数返回一个包含`maximum`属性的对象。此对象随后作为`$config`对消息模板可用，因此模板可以在错误消息中显示`maximum`。

在这里，我们的自定义规则只有一个参数，但一个规则可以有尽可能多的参数。它们都将以相同的顺序传递给条件函数和聚合函数，顺序与传递给`satisfiesRule`的顺序相同。

### 验证文件扩展名

最后，让我们创建一个规则，以确保`FileList`实例中的所有文件扩展名都在特定的一组值中：

`src/validation/rules.js`

```js
//Omitted snippet... 
function hasOneOfExtensions(file, extensions) { 
  const fileName = file.name.toLowerCase(); 
  return extensions.some(ext => fileName.endsWith(ext)); 
} 

function allHaveOneOfExtensions(files, extensions) { 
  extensions = extensions.map(ext => ext.toLowerCase()); 
  return Array.from(files) 
    .every(file => hasOneOfExtensions(file, extensions)); 
} 

ValidationRules.customRule( 
  'fileExtension', 
  (value, obj, extensions) => !(value instanceof FileList) 
    || value.length === 0 
    || allHaveOneOfExtensions(value, extensions), 
  '${$displayName} must have one of the following extensions: '  
    + '${$config.extensions.join(', ')}.', 
  extensions => ({ extensions }) 
); 

```

此规则名为`fileExtension`，期望一个文件扩展名数组作为参数，并确保`FileList`中的所有文件名以扩展名之一结尾。与`maxFileSize`一样，仅当验证的值是一个不为空的`FileList`实例时，它才适用。

### 验证联系照片选择器

既然我们已经定义了验证联系照片组件所需的所有规则，让我们像对`contact-edition`组件一样设置视图模型：

1.  在`ContactPhoto`视图模型中注入`ValidationController`的`NewInstance`

1.  在`save`中显式调用`validate`方法，如果有任何验证错误，则省略调用`updatePhoto`

1.  在`contact-photo.html`模板中的`form`元素添加`validation-renderer="bootstrap-form"`属性

1.  将`validate`绑定行为添加到`file input`上`files`属性的绑定

这些任务与我们对`contact-edition`组件已经完成的任务相同，我将留给读者作为练习。

接下来，我们需要向视图模型的`photo`属性添加验证规则：

`src/contact-photo.js`

```js
import {ValidationController, ValidationRules} from 'aurelia-validation'; 
//Omitted snippet... 
export class ContactPhoto { 
  //Omitted snippet... 

  constructor(contactGateway, router, validationController) { 
    //Omitted snippet... 
    ValidationRules 
      .ensure('photo') 
        .satisfiesRule('notEmpty') 
          .withMessage('${$displayName} must contain 1 file.') 
        .satisfiesRule('maxFileSize', 1024 * 1024 * 2) 
        .satisfiesRule('fileExtension', ['.jpg', '.png']) 
      .on(this); 
  } 

  //Omitted snippet... 
} 

```

在这里，我们告诉验证控制器`photo`必须至少包含一个文件，这个文件必须是 JPEG 或 PNG，并且最大不超过 2 MB。我们还使用`withMessage`方法定制当没有选择文件时显示的消息。

如果您测试这个，它应该能正常工作。然而，验证在`file input`失去焦点时触发，使得可用性有些奇怪。为了在用户关闭浏览器的文件选择对话框时立即验证表单，从而立即显示可能的错误消息，让我们将验证控制器的`validateTrigger`更改为`change`：

`src/contact-photo.js`

```js
import {ValidationController, ValidationRules, validateTrigger}  
  from 'aurelia-validation'; 
//Omitted snippet... 
export class ContactPhoto { 
  //Omitted snippet... 

  constructor(contactGateway, router, validationController) { 
    validationController.validateTrigger = validateTrigger.change; 
    //Omitted snippet... 
  } 

  //Omitted snippet... 
} 

```

如果您在做出此更改后进行测试，您应该发现可用性得到了很大改善，因为文件在用户关闭文件选择对话框时就会进行验证。

# 编辑复杂结构

在前几节中，我们创建了一个表单，用于编辑项目列表（如电话号码、电子邮件地址、地址和社会资料等），这种策略称为内联编辑。表单包括每个列表项的输入元素。这种策略将用户编辑或添加新列表项所需的点击次数降到最低，因为用户可以直接在表单中编辑所有列表项的所有字段。

然而，当表单需要管理更复杂项目的列表时，一个解决方案是只显示列表中最具相关性的信息作为只读，并使用模态对话框创建或编辑项目。对话框为单个项目显示复杂表单提供了更多的空间。

`aurelia-dialog`插件暴露了一个对话框功能，我们可以利用它来创建模态编辑器。为了说明这一点，我们将克隆我们的联系人管理应用程序，并更改`contact-edition`组件，使其使用对话框编辑而不是列表项的内联编辑。

以下代码片段是`chapter-4/samples/list-edition-models`的摘录。

## 安装对话框插件

要安装`aurelia-dialog`插件，只需在项目目录中打开一个控制台，并运行以下命令：

```js
> npm install aurelia-dialog --save 

```

安装完成后，我们还需要将插件添加到供应商包配置中。为此，请打开`aurelia_project/aurelia.json`，然后在`build`下的`bundles`中，在名为`vendor-bundle.js`的包的`dependencies`数组中添加以下条目：

```js
{ 
  "name": "aurelia-dialog", 
  "path": "../node_modules/aurelia-dialog/dist/amd", 
  "main": "aurelia-dialog" 
}, 

```

最后，我们需要在我们的主`configure`函数中加载插件：

`src/main.js`

```js
//Omitted snippet... 
export function configure(aurelia) { 
  aurelia.use 
    .standardConfiguration() 
    .plugin('aurelia-dialog') 
    .feature('validation') 
    .feature('resources'); 
  //Omitted snippet... 
} 

```

此时，`aurelia-dialog`暴露的服务和组件已准备好在我们的应用程序中使用。

## 创建编辑对话框

对话框插件使用组合来将组件作为对话框显示。这意味着下一步是创建将用于编辑新或现有项目的组件。

由于无论编辑的项目类型如何，对话框编辑的背后的行为都将相同，我们将创建一个单一的视图模型，我们将在电话号码、电子邮件地址、地址和社会资料等项目中重复使用：

`src/dialogs/edition-dialog.js`

```js
import {inject, NewInstance} from 'aurelia-framework'; 
import {DialogController} from 'aurelia-dialog'; 
import {ValidationController} from 'aurelia-validation'; 

@inject(DialogController, NewInstance.of(ValidationController)) 
export class EditionDialog { 

  constructor(dialogController, validationController) { 
    this.dialogController = dialogController; 
    this.validationController = validationController; 
  } 

  activate(model) { 
    this.model = model; 
  } 

  ok() { 
    this.validationController.validate().then(errors => { 
      if (errors.length === 0) { 
        this.dialogController.ok(this.model) 
      } 
    }); 
  } 

  cancel() { 
    this.dialogController.cancel(); 
  } 
} 

```

在这里，我们创建了一个组件，在该组件中注入了`DialogController`和`ValidationController`类的`NewInstance`。接下来，我们定义了一个接收`model`的`activate`方法，该`model`将是需要编辑的项目 - 电话号码、电子邮件地址、地址或社会资料。我们还定义了一个`ok`方法，该方法验证表单，如果没有错误，则使用更新后的`model`作为对话框的输出调用`DialogController`的`ok`方法。最后，我们定义了一个`cancel`方法，它简单地将调用委托给`DialogController`的`cancel`方法。

当`DialogController`被注入到一个作为对话框显示的组件中时，它被用来控制显示组件的对话框。它的`ok`和`cancel`方法可以用来关闭对话框，并向调用者返回一个响应。这个响应随后可以被调用者用来确定对话框是否被取消以及检索其输出（如果有）。

尽管我们将为所有项目类型重用相同的视图模型类，但每个项目类型的模板必须是不同的。让我们从电话号码的对话框编辑开始：

`src/dialogs/phone-number-dialog.html`

```js
<template> 
  <ai-dialog> 
    <form class="form-horizontal" validation-renderer="bootstrap-form"  
          submit.delegate="ok()"> 
      <ai-dialog-body> 
        <h2>Phone number</h2> 
        <div class="form-group"> 
          <div class="col-sm-2"> 
            <label for="type">Type</label> 
          </div> 
          <div class="col-sm-10"> 
            <select id="type" value.bind="model.type & validate"  
                    attach-focus="true" class="form-control"> 
              <option value="Home">Home</option> 
              <option value="Office">Office</option> 
              <option value="Mobile">Mobile</option> 
              <option value="Other">Other</option> 
            </select> 
          </div> 
        </div> 
        <div class="form-group"> 
          <div class="col-sm-2"> 
            <label for="number">Number</label> 
          </div> 
          <div class="col-sm-10"> 
            <input id="number" type="tel" class="form-control"  
                   placeholder="Phone number"  
                   value.bind="model.number & validate"> 
          </div> 
        </div> 
      </ai-dialog-body>
<ai-dialog-footer> 
        <button type="submit" class="btn btn-primary">Ok</button> 
        <button class="btn btn-danger"  
                click.trigger="cancel()">Cancel</button> 
      </ai-dialog-footer> 
    </form> 
  </ai-dialog> 
</template> 

```

这里值得注意的是`ai-dialog`、`ai-dialog-body`和`ai-dialog-footer`元素，它们是 Aurelia 对话框的容器。此外，`select`元素上的`attach-focus="true"`属性确保当对话框显示时这个元素获得焦点。最后，`form`的`submit`事件委托给`ok`方法，而点击取消按钮则委托给`cancel`方法。

模板的其余部分应该很熟悉。用户输入元素绑定到`model`的属性，这些绑定被`validate`绑定行为装饰，以便属性得到适当验证。

我们还需要为其他项目类型创建模板：`src/dialogs/email-address-dialog.html`、`src/dialogs/address-dialog.html`和`src/dialogs/social-profile-dialog.html`。此时，这些模板应该很容易创建。我将留给读者一个练习来编写它们；`list-edition-models`示例可以作为参考。

## 使用编辑对话框

利用我们新的视图模型和模板的最后一步是改变`contact-edition`组件的行为：

`src/contact-edition.js`

```js
import {DialogService} from 'aurelia-dialog'; 
import {Contact, PhoneNumber, EmailAddress, Address, SocialProfile}  
  from './models'; 
//Omitted snippet... 
@inject(ContactGateway, NewInstance.of(ValidationController), Router,  
        DialogService) 
export class ContactEdition { 
  constructor(contactGateway, validationController, router, dialogService) { 
    this.contactGateway = contactGateway; 
    this.validationController = validationController; 
    this.router = router; 
    this.dialogService = dialogService; 
  } 
   //Omitted snippet... 
  _openEditDialog(view, model) { 
    return new Promise((resolve, reject) => { 
      this.dialogService.open({  
        viewModel: 'dialogs/edition-dialog', 
        view: `dialogs/${view}-dialog.html`,  
        model: model 
      }).then(response => { 
        if (response.wasCancelled) { 
          reject(); 
        } else { 
          resolve(response.output); 
        } 
      }); 
    }); 
  } 

  editPhoneNumber(phoneNumber) { 
    this._openEditDialog('phone-number',  
                         PhoneNumber.fromObject(phoneNumber)) 
      .then(result => { Object.assign(phoneNumber, result); }); 
  } 

  addPhoneNumber() { 
    this._openEditDialog('phone-number', new PhoneNumber()) 
      .then(result => { this.contact.phoneNumbers.push(result); }); 
  } 

  //Omitted snippet... 
} 

```

在这里，我们通过在构造函数中注入`DialogService`来向我们的`ContactEdition`视图模型添加一个新的依赖。接下来，我们定义了一个`_openEditDialog`方法，它定义了打开编辑对话框的通用行为。

此方法调用`DialogService`的`open`方法来打开一个对话框，使用`edition-dialog`视图模型和给定项目类型的模板，组合成一个单一组件。还传递了一个`model`，它将在`edition-dialog`的`activate`方法中注入。如果你阅读了第三章*显示数据*中的组合部分，这应该会很熟悉。

此外，该方法返回一个 `Promise`，当用户点击 **确定** 时解析，但当用户点击 **取消** 时拒绝。这样，在使用这个方法时，只有当用户通过点击 **确定** 来确认其修改时，结果的 `Promise` 才会被解析，否则会被拒绝。

`editPhoneNumber` 方法使用 `_openEditDialog` 方法来显示电话号码编辑对话框。要编辑的 `phoneNumber` 的副本作为 `model` 传递，因为如果我们传递原始 `phoneNumber` 对象，即使用户取消其修改，它也会被修改。当用户确认其修改时，`Promise` 解析，这时更新后的 `model` 属性会被回赋给原始的 `phoneNumber`。

同样地，`addPhoneNumber` 方法使用了 `_openEditDialog` 方法，但传递了一个新的 `PhoneNumber` 实例作为模型。另外，当 `Promise` 解析时，新的电话号码会被添加到 `contact` 的 `phoneNumbers` 数组中。

最后，模板必须更改，以便电话号码列表以只读方式显示，并为每个电话号码添加一个新的 **编辑** 按钮：

`src/contact-edition.html`

```js
<template> 
  <!-- Omitted snippet... --> 
  <hr> 
  <div class="form-group" repeat.for="phoneNumber of contact.phoneNumbers"> 
    <div class="col-sm-2 col-sm-offset-1">${phoneNumber.type}</div> 
    <div class="col-sm-7">${phoneNumber.number}</div> 
    <div class="col-sm-1"> 
      <button type="button" class="btn btn-danger"  
              click.delegate="editPhoneNumber(phoneNumber)"> 
        <i class="fa fa-pencil"></i> Edit 
      </button> 
    </div> 
    <div class="col-sm-1"> 
      <button type="button" class="btn btn-danger"  
              click.delegate="contact.phoneNumbers.splice($index, 1)"> 
        <i class="fa fa-times"></i>  
      </button> 
    </div> 
  </div> 
  <div class="form-group"> 
    <div class="col-sm-9 col-sm-offset-3"> 
      <button type="button" class="btn btn-primary"  
              click.delegate="addPhoneNumber()"> 
        <i class="fa fa-plus-square-o"></i> Add a phone number 
      </button> 
    </div> 
  </div> 
  <!-- Omitted snippet... --> 
</template> 

```

在这里，我们移除了 `select` 和 `input` 元素，并用字符串插值指令来显示 `phoneNumber` 的 `type` 和 `number` 属性。我们还添加了一个 **编辑** 按钮，当点击时，调用新的 `editPhoneNumber` 方法。最后，我们更改了 **添加** 按钮，使其调用新的 `addPhoneNumber` 方法。

当然，对于 `contact-edition` 组件的视图模型和模板，以及其他项目类型的更改也必须应用相同的更改。然而，对于电子邮件地址、地址和社会资料的内联编辑策略的更改，现在对您来说应该是很直接的；我将把这个留给读者作为一个练习。

# 总结

使用 Aurelia 创建表单很简单，主要是利用双向绑定。验证表单也很容易，得益于验证插件。此外，验证插件的抽象层允许我们使用我们想要的验证库，尽管插件提供的默认实现已经相当强大。

在下一章中，Aurelia 的力量将真正开始变得清晰。通过利用我们迄今为止看到的内容，并添加自定义属性、自定义元素和内容投射到混合中，我们将能够创建极其强大、可重用和可扩展的组件，将它们组合成模块化和可测试的应用程序。当然，在覆盖这些主题的同时，我们将对我们的联系人管理应用程序进行大量重构，以提取组件和可重用行为，同时添加在没有自定义元素和属性时无法实现的特性。
