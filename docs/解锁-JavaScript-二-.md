# 解锁 JavaScript（二）

> 原文：[`zh.annas-archive.org/md5/A343D1C7BB9FB1F5BEAC75A7F1CFB40B`](https://zh.annas-archive.org/md5/A343D1C7BB9FB1F5BEAC75A7F1CFB40B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：DOM 脚本和 AJAX

当涉及到**文档对象模型**（**DOM**）操作和 AJAX 时，第一反应可能是使用 jQuery 或 Zepto。但是，这难道不让你烦恼吗？你为了一些普通的任务，却加载了一个沉重的第三方库，而浏览器已经为你提供了所需的一切？有些人引入 jQuery 是为了跨浏览器兼容性。好吧，这个库是用来修复*损坏的 DOM API*。这在我们要支持像 IE7 这样老旧浏览器的时候真的很有帮助。然而，今天，当我们支持的浏览器使用率不到 0.1%时，我们几乎不需要关心遗留浏览器([`www.w3schools.com/browsers/browsers_explorer.asp`](http://www.w3schools.com/browsers/browsers_explorer.asp))。现代浏览器在支持 Web API 方面相当一致。总的来说，跨浏览器兼容性不再是问题。

第二个，也是最常见的借口是，这个库简化了你需要编写的查询和操作 DOM 的代码量。它在某种程度上简化了代码，但缺点是，现在我们有一代开发者不知道 JavaScript 和 Web API，只知道 jQuery。其中许多人没有这个库就无法解决一个简单的任务，也不知道当他们调用库方法时实际发生了什么。良好的代码意味着可移植性和高性能。没有对原生 API 的了解，很难实现这一点。

因此，在本章中，我们将探讨原生处理 DOM 和 AJAX 的方式，重点关注高性能。

本章将涵盖以下主题：

+   高速 DOM 操作

+   与服务器的通信

# 高速 DOM 操作

为了高效地处理 DOM，我们需要了解它的本质。DOM 是一个表示在浏览器中打开的文档的树结构。DOM 中的每个元素都称为节点。

![高速 DOM 操作](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-ulk/img/00007.jpeg)

每个节点作为一个对象都有属性和方法([`developer.mozilla.org/en/docs/Web/API/Node`](https://developer.mozilla.org/en/docs/Web/API/Node))。节点有不同的类型。在前面的图片中，你可以看到一个文档节点、元素节点和文本节点。实际上，树也可能包含特定类型的节点，如注释节点、文档类型节点等。为了说明树内的关系，我们可以认为 HTML 有两个子节点**HEAD**和**BODY**，它们作为兄弟姐妹相互关联。显然，HTML 是 HEAD 和 BODY 的父节点。我们可以使用这些通过节点属性可访问的关系来导航树：

```js
var html = document.documentElement;
console.log( html.nodeName ); // HTML

var head = html.childNodes[0];
console.log( head.nodeName );  // HEAD
console.log( head.parentNode === html );  // true
```

这部分很清楚，但如果我们请求下一个兄弟节点是 HEAD 而不是 BODY，我们将得到一个内容中包含空白符的文本节点（`nodeValue`）：

```js
var sibling = head.nextSibling;
// the same as html.childNodes[1]
console.log( sibling.nodeName ); // #text
console.dir( sibling.nodeValue ); // "\n  "
```

在 HTML 中，我们通常用空格、TAB 和换行符来分隔元素，以提高可读性，这些也构成了 DOM 的一部分。因此，为了访问元素，我们最好使用文档和元素方法。

## 遍历 DOM

当然，你知道如何通过 ID（`document.getElementById`）或标签名（`document.getElementsByTagName`）找到一个元素。你也可以通过 CSS 选择器（`document.querySelector`）查找一个元素：

```js
<article id="bar">
  <h2>Lorem ipsum</h2>
</article>
var article = document.querySelector( "#bar" ),
      heading = article.querySelector( "h2" );
```

选择器由一个或多个类型（标签）选择器、类选择器、ID 选择器、属性选择器或伪类/元素选择器组合而成（[`www.w3.org/TR/CSS21/selector.html%23id-selectors`](http://www.w3.org/TR/CSS21/selector.html%23id-selectors)）。考虑到组合（匹配一组、后代或兄弟姐妹），这给了我们相当多的可能选项。所以选择一个将 HTML 元素从 JavaScript 绑定的策略可能会很难。我的建议是始终使用`data-*`属性选择器：

```js
<article data-bind="bar">
  <h2 data-bind="heading">Lorem ipsum</h2>
</article>

var article = document.querySelector( "[data-bind=\"bar\"]" ),
      heading = article.querySelector( "[data-bind=\"heading\"]" );
```

这样我们就独立于 HTML 结构了。如果我们改变标签，例如为了更好的语义，JavaScript 方面不会出错。我们独立于 CSS 类，这意味着我们可以安全地重构 CSS。我们不受 ID 的限制，ID 在每个文档中应该是唯一的。

`querySelector`取 DOM 中匹配选择器的第一个元素，而`querySelectorAll`检索所有它们：

```js
<ul data-bind="bar">
  <li data-bind="item">Lorem ipsum</li>
  <li data-bind="item">Lorem ipsum</li>
  <li data-bind="item">Lorem ipsum</li>
</ul>

var ul = document.querySelector( "[data-bind=\"bar\"]" ),
      lis = ul.querySelectorAll( "[data-bind=\"item\"]" );
console.log( lis.length );
```

找到的元素被表示为一个`NodeList`。它看起来像一个数组，但它不是。它是一个实时集合，在每次 DOM 重排时都会被更新。考虑以下示例：

```js
var divs = document.querySelectorAll( "div" ), i; 
for ( i = 0; i < divs.length; i++ ) { 
  document.appendChild( document.createElement( "div" ) ); 
}
```

前面的代码会导致一个无限循环，因为无论我们访问集合的下一个元素，都会向集合中添加一个新元素，`divs.length`递增，我们永远满足不了循环条件。

重要的是要知道，遍历一个实时集合（`NodeList`、`HTMLCollection`）是慢的，并且资源消耗很大。如果你不需要它是实时的，只需将集合转换为一个数组，例如`[].slice.call( nodeList )`，正如在第一章，*深入 JavaScript 核心*中提到的那样。在 ES6 中，这可以用`[...nodeList]spread`操作符完成：

```js
var ul = document.querySelector( "[data-bind=\"bar\"]" ),
      lis = ul.querySelectorAll( "[data-bind=\"item\"]" );
console.log( [].slice.call( lis ) ); // into array ES5 way
console.log( [ ...lis ] ); // into array ES6 way
```

除了查询，我们还可以测试找到的元素是否与给定的选择器匹配：

```js
console.log( el.matches( ".foo > .bar" ) );
console.log( input.matches( ":checked" ) );
```

## 改变 DOM

嗯，现在我们知道如何在 DOM 中找到元素了。那么我们来看看如何将新元素动态插入到 DOM 树中。有多种方法。我们可以简单地使用`el.innerHTML`方法设置新的 HTML 内容：

```js
var target = document.getElementById( "target" );
target.innerHTML = "<div></div>";
```

否则，我们可以创建一个节点（`document.createElement`）并将其注入到 DOM 中（`el.appendChild`）：

```js
var target = document.getElementById( "target" ),
      div = document.createElement( "div" ),
target.appendChild( div );
```

在这里你应该记得，每次我们改变`el.innerHTML`或者向一个元素中添加一个子元素，我们都会引起 DOM 重排。当这种情况在循环中反复发生时，它可能会减慢应用程序的速度。

当我们通过`el.innerHTML`传递 HTML 时，浏览器首先必须解析字符串。这是一个耗资源的操作。然而，如果我们明确地创建元素，这个操作会快得多。如果我们生产出一系列相似的元素，流程还可以进一步优化。我们可以在循环中创建每一个元素，也可以创建一个原始创建的元素副本（`el.cloneNode`），这样可以快得多：

```js
var target = document.getElementById( "target" ),
    /**
     * Create a complex element
     * @returns {Node}
     */
    createNewElement = function(){
      var div = document.createElement( "div" ),
          span = document.createElement( "span" );
      span.appendChild( document.createTextNode( "Bar" ) );
      div.appendChild( span );
      return div;
    },
    el;

el = createNewElement();
// loop begins
target.appendChild( el.cloneNode( true ) );
// loop ends
```

另一方面，我们可以创建一个文档片段（`document.createDocumentFragment`）并在循环中向片段添加创建的节点。文档片段是一种虚拟 DOM，我们对其进行操作而不是真实的 DOM。一旦我们完成，我们可以将文档片段作为分支注入到真实的 DOM 中。通过结合这种技术和克隆技术，我们预计在性能上会有所收获。实际上，这并不确定([`codepen.io/dsheiko/pen/vObVOR`](http://codepen.io/dsheiko/pen/vObVOR))。例如，在 WebKit 浏览器中，虚拟 DOM（`document.createDocumentFragment`）比真实 DOM 运行得慢。

正如我们在性能方面所做的那样，让我们关注准确性。如果我们需要将一个元素注入到确切的位置（例如，在`foo`和`bar`节点之间），`el.appendChild`并不是正确的方法。我们必须使用`el.insertBefore`：

```js
parent.insertBefore(el, parent.firstChild);
```

要从 DOM 中删除一个特定的元素，我们这样做：

```js
el.parentNode.removeChild(el);
```

此外，我们还可以重新加载元素，例如，重置所有订阅的事件监听器：

```js
function reload( el ) {
    var elClone = el.cloneNode( true );
    el.parentNode && el.parentNode.replaceChild( elClone, el );
 }
```

## 样式化 DOM

谈到样式，我们 wherever possible 使用 CSS 类。这提供了更好的可维护性——继承、组合和关注分离。你当然知道如何通过`el.className`属性为元素分配预期的类。然而，在现实世界中，`el.classList`对象要实用得多：

```js
el.classList.add( "is-hidden" );
el.classList.remove( "is-hidden" );
var isAvailable = true;
el.classList.toggle("is-hidden", !isAvailable );
if ( el.classList.contains( "is-hidden" ) ){}
```

在这里，除了明显的添加/删除/包含方法，我们还使用`toggle`。这个方法根据作为第二个参数传递的布尔值，要么添加，要么删除指定的类。

有时我们需要显式地操作样式。DOM 的一个部分叫做**CSS 对象模型**（**CSSOM**），它提供了一个接口来操作 CSS。因此，我们可以使用`el.style`属性读取或设置元素的动态样式信息：

```js
el.style.color = "red";
el.style.fontFamily = "Arial";
el.style.fontSize = "1.2rem";
```

一个较少为人所知的技巧是改变样式规则的实际文本：

```js
el.style.cssText = "color:red;font-family: Arial;font-size: 1.2rem;";
```

正如你所看到的，第二种方法并不那么灵活。你不能改变或访问一个声明，而只能访问整个规则。然而，这种样式的速度显著更快([`codepen.io/dsheiko/pen/qdvWZj`](http://codepen.io/dsheiko/pen/qdvWZj))。

虽然`el.style`包含了元素的显式样式，但`window.getComputedStyle`返回的是继承（计算）样式：

```js
var el = document.querySelector( "h1" ),
    /**
     * window.getComputedStyle
     * @param {HTMLElement} el
     * @param {String} pseudo - pseudo-element selector or null 
     * for regular elements
     * @return {CSSStyleDeclaration}
     */
    css = window.getComputedStyle( el, null );
console.log( css.getPropertyValue( "font-family" ) );
```

我们刚刚检查的情况指的是内联样式。实际上，我们也可以访问外部或内部样式表：

```js
<style type="text/css">
.foo {
 color: red;
}
</style>
<div class="foo">foo</div>
<script type="text/javascript">
var stylesheet = document.styleSheets[ 0 ];
stylesheet.cssRules[ 0 ].style.color = "red";
// or
// stylesheet.cssRules[ 0 ].style.cssText = "color: red;";
</script>
```

为什么我们要这样做呢？因为有特殊情况。例如，如果我们想要修改，比如说，伪元素的样式，我们必须涉及到样式表：

```js
var stylesheet = document.styleSheets[ 0 ];
stylesheet.addRule( ".foo::before", "color: green" );
// or
stylesheet.insertRule( ".foo::before { color: green }", 0 );
```

## 利用属性和属性

HTML 元素有属性，我们可以从 JavaScript 访问它们：

```js
el.setAttribute( "tabindex", "-1" );
if ( el.hasAttribute( "tabindex" ) ) {}
el.getAttribute( "tabindex" );
el.removeAttribute( "tabindex" );
```

虽然 HTML 定义了元素属性，但属性是由 DOM 定义的。这造成了区别。例如，如果你有一个输入元素，最初属性和属性（`el.value`）有相同的值。然而，当用户或脚本改变值时，属性不会受到影响，但属性会：

```js
// attribute
console.log( input.getAttribute( "value" ) );
// property
console.log( input.value );
```

正如你可能很可能知道的那样，除了全局属性之外，还有一种特殊类型——自定义数据属性。这些属性旨在提供 HTML 及其 DOM 表示之间交换专有信息，由脚本使用。基本想法是，你定义一个自定义属性，如`data-foo`，并为其设置一个值。然后，从脚本中，我们使用`el.dataset`对象访问和改变属性：

```js
console.log( el.dataset.foo ); 
el.dataset.foo = "foo";
```

如果你定义了一个多部分属性，如`data-foo-bar-baz`，相应的`dataset`属性将是`fooBarBaz`：

```js
console.log( el.dataset.fooBarBaz ); 
el.dataset.fooBarBaz = "foo-bar-baz";
```

## 处理 DOM 事件

在浏览器中发生了许多事件。这可以是设备事件（例如，设备改变位置或方向），窗口事件（例如，窗口大小），一个过程（例如，页面加载），媒体事件（例如，视频暂停），网络事件（连接状态改变），当然，还有用户交互事件（点击，键盘，鼠标和触摸）。我们可以使我们的代码监听这些事件，并在事件发生时调用订阅的处理函数。要订阅 DOM 元素的某个事件，我们使用`addEventListener`方法：

```js
EventTarget.addEventListener( <event-name>, <callback>, <useCapture> );
```

在前面的代码中，`EventTarget`可以是窗口、文档、元素或其他对象，如`XMLHttpRequest`。

`useCapture`是一个布尔值，你可以指定事件传播的方式。例如，用户点击一个按钮，这个按钮在一个表单中，我们为这个点击事件订阅了两个元素的处理程序。当`useCapture`为`true`时，表单元素的处理程序（`ancestor`）将首先被调用（`capturing flow`）。否则，表单的处理程序将在按钮的处理程序之后被调用（`bubbling flow`）。

`callback`是一个在事件触发时调用的函数。它接收一个`Event`对象作为参数，该对象具有以下属性：

+   `Event.type`：这是事件的名字

+   `Event.target`：这是事件发生的事件目标

+   `Event.currentTarget`：这是事件目标，监听器附加到该目标（`target`和`currentTarget`可能在我们为多个元素附加相同的事件处理程序时有所不同，如[`developer.mozilla.org/en-US/docs/Web/API/Event/currentTarget`](https://developer.mozilla.org/en-US/docs/Web/API/Event/currentTarget)所述）

+   `Event.eventPhase`：这指示事件流程的哪个阶段正在被评估（无、捕获、目标或冒泡）

+   `Event.bubbles`：这表明事件是否是冒泡事件

+   `Event.cancelable`：这表明是否可以防止事件的默认动作

+   `Event.timeStamp`：这指定了事件时间

事件还有以下方法：

+   `Event.stopPropagation()`：这阻止事件进一步传播。

+   `Event.stopImmediatePropagation()`：如果我们有多个监听器订阅了同一个事件目标，在调用这个方法后，剩下的监听器将不会被调用。

+   `Event.preventDefault()`：这阻止默认行为。例如，如果它是一个提交类型的按钮的点击事件，通过调用这个方法，我们可以阻止它自动提交表单。

让我们在实践中试试看：

```js
<form action="/">
<button type="submit">Click me</button>
</form>
<script>
var btn = document.querySelector( "button" )
    onClick = function( e ){
      e.preventDefault(); 
      console.log( e.target );
    };
btn.addEventListener( "click", onClick, false );
</script>
```

在这里，我们为按钮元素的一个点击事件订阅了一个`onClick`监听器。当按钮被点击时，它会在 JavaScript 控制台中显示表单没有被提交的事实。

如果我们想要订阅键盘事件，我们可以这样做：

```js
addEventListener( "keydown", function( e ){
    var key = parseInt( e.key || e.keyCode, 10 );
     // Ctrl-Shift-i
    if ( e.ctrlKey && e.shiftKey && key === 73 ) {
      e.preventDefault();
      alert( "Ctrl-Shift-L pressed" );
    }
  }, false );
```

过程事件的最常见例子是文档就绪状态的改变。我们可以监听`DOMContentLoaded`或`load`事件。第一个事件在文档完全加载和解析后触发。第二个事件还等待样式表、图像和子框架加载完成。在这里，有一个怪癖。我们必须检查`readyState`，因为如果在事件可能已经触发后注册一个监听器，回调将永远不会被调用：

```js
function ready( cb ) {
  if ( document.readyState !== "loading" ){
    cb();
  } else {
    document.addEventListener( "DOMContentLoaded", cb );
  }
}
```

嗯，我们知道如何使用`EventTarget.addEventListener`方法订阅 DOM 事件。`EventTarget`对象还有一个方法来取消订阅监听器。例如，请看以下内容：

```js
btn.removeEventListener( "click", onClick );
```

如果我们想要触发一个 DOM 事件，例如模拟一个按钮点击，我们必须创建一个新的`Event`对象，设置它，并在我们想要事件触发时在元素上分派：

```js
var btn = document.querySelector( "button" ),
    // Create Event object
    event = document.createEvent( "HTMLEvents" );
// Initialize a custom event that bubbles up and cannot be canceled 

event.initEvent( "click", true, false );
// Dispatch the event
btn.dispatchEvent( event );
```

同样，我们也可以创建我们自己的自定义事件：

```js
var btn = document.querySelector( "button" ),
    // Create Event object
    event = document.createEvent( "CustomEvent" );
// Subscribe to the event 
btn.addEventListener("my-event", function( e ){
  console.dir( e );
});
// Initialize a custom event that bubbles up and cannot be canceled 
event.initEvent( "my-event", true, false );
// Dispatch the event
btn.dispatchEvent( event );
```

# 与服务器通信

许多人使用第三方库来向服务器发送任何请求。但我们真的需要这些库吗？让我们在下面的内容中看看如何使用原生的 AJAX，以及下一个通信 API 将是什么。

## XHR

**XMLHttpRequest**（**XHR**）是 JavaScript 中用于在客户端和服务器之间交换数据的主要 API。XHR 最初由微软在 IE5 中通过 ActiveX 呈现（1999 年），并且在 IE 浏览器直到版本 7（2006 年）中都有一种专有的语法。这导致了兼容性问题，促成了*AJAX 库*（如 Prototype 和 jQuery）的出现。如今，XHR 在所有主流浏览器中的支持都是一致的。通常，要执行一个 HTML 或 HTTPS 请求，我们需要完成许多任务。我们创建一个 XHR 的实例，通过 open 方法初始化一个请求，为与请求相关的事件订阅监听器，设置请求头（`setRequestHeader`），最后调用 send 方法：

```js
var xhr = new XMLHttpRequest();
xhr.open( "GET", "http://www.telize.com/jsonip?callback=0", true );
xhr.onload = function() {
      if ( this.status === 200 ) {
        return console.log( this.response );
      }
    };

xhr.responseType = "json";
xhr.setRequestHeader( "Content-Type", "application/x-www-form-urlencoded" );
xhr.send( null );
```

还有更多选项可用。例如，我们可以利用`progress`和`abort`事件来控制文件上传（[`developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/Using_XMLHttpRequest`](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/Using_XMLHttpRequest)）。

我突然想到，对于一个简单的调用，这个接口过于复杂了。互联网上有大量的 XHR 包装器实现。最流行的实现之一可以在[`github.com/Raynos/xhr`](https://github.com/Raynos/xhr)找到。它使得 XHR 的使用如此简单：

```js
xhr({
  uri: "http://www.telize.com/jsonip",
  headers: {
    "Content-Type": "application/json"
  }
}, function ( err, resp ) {
  console.log( resp );
})
```

此外，该库还提供了一个模拟对象，可用于在单元测试中替换真实的 XHR。

## Fetch API

我们刚刚检查了 XHR API。这在 15 年前看起来不错，但现在看起来很笨拙。我们必须使用包装器来使其更友好。幸运的是，语言已经演进，现在我们有一个新的内置方法叫做 Fetch API。想想使用它进行调用的容易程度：

```js
fetch( "/rest/foo" ).then(function( response ) {
  // Convert to JSON
  return response.json();
}).catch(function( err ) {
  console.error( err );
});
```

尽管表面上很简单，这个 API 还是很强大的。`fetch`方法期望在第一个强制参数中是一个带有远程方法 URL 的字符串或者一个`Request`对象。请求选项可以在第二个可选参数中传递：

```js
fetch( "/rest/foo", {
  headers: {
    "Accept": "application/json",
    "Content-Type": "application/json"
  }
});
```

与我们的上一个片段类似，fetch 方法返回**Promise**。Promise 对于异步或延时操作已经成为一种常见的实践。在 Promise 实现时调用的函数（参见 then）接收一个`Response`对象。这个函数有许多属性和方法（[`developer.mozilla.org/en-US/docs/Web/API/Response`](https://developer.mozilla.org/en-US/docs/Web/API/Response)）。因此，我们可以使用相应的转换方法将响应转换为 JSON、文本、blob 或流，并且我们可以获得与请求相关的信息：

```js
console.log( response.text() );
console.log( response.status );
console.log( response.statusText );
console.log( response.headers.get( "Content-Type" ) );
```

那么`POST`请求呢？Fetch 有一个名为`body`的混合插件，它代表了`Response`/`Request`的正文。我们可以通过这个传递`POST`数据：

```js
var form = document.querySelector( "form[data-bind=foo]" ),
    inputEmail = form.querySelector( "[name=email]" ),
    inputPassword = form.querySelector( "[name=pwd]" );

fetch( "/feedback/submit", {
  method: "post",
  body: JSON.stringify({
    email: inputEmail.value,
    answer: inputPassword.value
  })
});
```

它不仅接受键值对，还可以接受例如`FormData`，所以你可以像这样提交整个表单以及附带的文件：

```js
var form = document.querySelector( "form[data-bind=foo]" );
fetch( "/feedback/submit", {
  method: "post",
  body: new FormData( form )
});
```

目前，一些主流浏览器（例如，IE/Edge、Safari）不支持这个 API。然而，如果你打算使用 Fetch API，你可以使用 Fetch 的 polyfill([`github.com/github/fetch`](https://github.com/github/fetch))。

# 总结

在过去，每个浏览器的制造商都有自己定制的 DOM 实现，这些实现之间几乎不兼容。然而，这种情况已经改变，W3C DOM 至少在浏览器中得到了十年的支持。今天，我们可以安全地使用 JavaScript 原生 API 来访问、操作和样式化 DOM。

在 JavaScript 中，XHR 仍然是客户端与服务器之间通信的主要 API。不过它对开发者并不太友好。因此，我们通常为其编写自定义包装器。

然而，一个新的 API，名为 Fetch，已经被提出并已经在 Chrome、Firefox 和 Opera 中得到实现。这个新 API 的使用要简单得多，与 XHR 相比，它提供了更加令人印象深刻且灵活的功能。


# 第四章：HTML5 API

尽管语言规范（**ECMA-262**）每几年变化一次，但新的 HTML5 API 几乎在每次浏览器更新时都会潜入语言中。已经可用的 API 数量相当多。然而，在本章中，我们将重点关注那些重新考虑整个开发过程的 API。我们将学习如何利用 web workers 进行多线程，如何从可重用的独立 web 组件构建应用程序，如何在客户端存储和搜索大量数据，以及如何与服务器建立双向通信。

在本章中，我们将介绍以下主题：

+   在 web 浏览器中存储数据

+   使用 JavaScript workers 提高性能

+   创建我们的第一个 web 组件

+   学习使用服务器到浏览器通信通道

# 在 web 浏览器中存储数据

在 HTML5 特性中，有几个是为了在客户端存储数据而设计的：Web 存储、IndexedDB 和 FileSystem API。当以下情况发生时，我们才能从这些技术中受益：

+   我们希望缓存客户端数据，以便在没有额外 HTTP 请求的情况下进行检索。

+   在 web 应用程序中，我们有大量的本地数据，我们希望我们的应用程序离线工作

让我们来看看这些技术。

## Web 存储 API

过去，我们只有保持应用程序状态的机制，而且它是使用**HTTP cookies**。除了不友好的 API 之外，cookie 还有几个缺点。它们的最大大小通常约为 4 KB。所以我们根本不能存储任何像样的数据。当在不同标签页中更改应用程序状态时，cookie 并不真正适用。cookie 容易受到**跨站脚本攻击**。

现在我们有一个高级 API，称为**Web 存储**。它提供了更大的存储容量（取决于浏览器，5-25 MB）并且不会将任何数据附加到 HTTP 请求头中。实现此接口的两个 JavaScript 内置对象是：**localStorage**和**sessionStorage**。第一个用于持久数据存储，第二个用于会话期间保持数据。

存储 API 非常易于使用，如下所示：

```js
var storage = isPersistent ? localStorage : sessionStorage;
storage.setItem( "foo", "Foo" );
console.log( storage.getItem( "foo" ) );
storage.removeItem( "foo" );
```

另外，我们可以为了方便使用 getters/setters，如下所示：

```js
storage.foo = "Foo";
console.log( storage.foo );
delete storage.foo;
```

如果我们想要遍历存储，我们可以使用`storage.length`和`storage.key()`：

```js
var i = 0, len = storage.length, key;
for( ; i < len; i++ ) {
  key = storage.key( i );
  storage.getItem( key );
}
```

正如你所见，与 cookies 相比，Web 存储 API 对开发者更加友好，也更加强大。最常见的实际例子之一是我们需要存储的情况是购物车。在设计应用程序时，我们必须记住，用户在做出选择时通常会在多个标签页或窗口中打开产品详细页。因此，我们必须照顾到所有打开的页面之间的存储同步。

幸运的是，无论何时我们更新 localStorage，都会在 window 对象上触发 `storage` 事件。因此，我们可以为这个事件订阅一个处理程序来用实际数据更新购物车。这个例子简单的代码可能看起来像这样：

```js
<html>
  <head>
    <title>Web Storage</title>
  </head>
  <body>
    <div>
      <button data-bind="btn">Add to cart</button>
      <button data-bind="reset">Reset</button>
    </div>
    <output data-bind="output">

    </output>
    <script>

    var output = document.querySelector( "[data-bind=\"output\"]" ),
        btn = document.querySelector( "[data-bind=\"btn\"]" ),
        reset = document.querySelector( "[data-bind=\"reset\"]" ),
        storage = localStorage,
       /**
        * Read from the storage
        * @return {Arrays}
        */
        get = function(){
           // From the storage we receive either JSON string or null
           return JSON.parse( storage.getItem( "cart" ) ) || [];
        },
        /**
         * Append an item to the cart
         * @param {Object} product
         */
        append = function( product ) {
          var data = get();
          data.push( product );
          // WebStorage accepts simple objects, so we pack the object into JSON string         storage.setItem( "cart", JSON.stringify( data ) );
        },
        /** Re-render list of items */
        updateView = function(){
          var data = get();
          output.innerHTML = "";
          data && data.forEach(function( item ){
            output.innerHTML += [ "id: ", item.id, "<br />" ].join( "" );
          });
        };

    this.btn.addEventListener( "click", function(){
      append({ id: Math.floor(( Math.random() * 100 ) + 1 ) });
      updateView();
    }, false );

    this.reset.addEventListener( "click", function(){
      storage.clear();
      updateView();
    }, false );

    // Update item list when a new item is added in another window/tab
    window.addEventListener( "storage", updateView, false );

    updateView();

    </script>
  </body>
</html>
```

为了看到这个功能实际运行的情况，我们必须在两个或更多标签页中打开代码 HTML。现在，当我们点击**加入购物车**按钮时，每个标签页都会更新已订购商品的列表。正如您可能注意到的，我们还可以通过点击**重置**按钮来清理购物车。这会调用`storage.clear`方法，清空列表。如果您想在这里使用 sessionStorage 而不是 localStorage，我必须警告您这样做是不行的。sessionStorage 对每个标签页或窗口都是隔离的，所以我们不能用这种方法跨它们进行通信。

然而，如果我们能在不同的框架中加载同一窗口中的页面运行这个例子，那么我们本可以使用 sessionStorage 的。下方的截图是一个购物车应用实际运行的示例：

![Web Storage API](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-ulk/img/00008.jpeg)


## 第五章：索引数据库（IndexedDB）

当我们需要存储相当小的数据量（兆字节）时，Web Storage 表现很好。然而，如果我们需要大量结构化数据，并且我们希望通过索引进行性能搜索，我们将使用 IndexedDB API。在浏览器中存储数据的 API 的想法并不新鲜。几年前，谷歌及其合作伙伴积极推广一个名为**Web SQL Database**的标准候选。尽管如此，这个规范还是未能通过 W3C 推荐。现在，我们有了 IndexedDB API，它已经得到广泛支持，并提供了显著的性能提升（异步 API 以及由于索引键而强大的搜索功能）。

然而，IndexedDB 的 API 相当复杂。由于大量的嵌套回调，它也很难阅读：

```js
/**
 * @type {IDBOpenDBRequest}
 * Syntax: indexedDB.open( DB name, DB version );
 */
var request = indexedDB.open( "Cem", 2 );

/** Report error */
request.onerror = function() {
  alert( "Opps, something went wrong" );
};
/**
 * Create DB
 * @param {Event} e
 */
request.onupgradeneeded = function ( e ) {
  var objectStore;
  if ( e.oldVersion ) {
    return;
  }
  // define schema
  objectStore = e.currentTarget.result.createObjectStore( "employees", { keyPath: "email" });
  objectStore.createIndex( "name", "name", { unique: false } );
   // Populate objectStore with test data
  objectStore.add({ name: "John Dow", email: "john@company.com" });
  objectStore.add({ name: "Don Dow", email: "don@company.com" });
};
/**
 * Find a row from the DB
 * @param {Event} e
 */
request.onsuccess = function( e ) {
  var db = e.target.result,
      req = db.transaction([ "employees" ]).objectStore( "employees" ).get( "don@company.com" );

  req.onsuccess = function() {
    console.log( "Employee matching `don@company.com` is `" + req.result.name + "`" );
  };
};
```

在这个示例中，我们创建了一个打开数据库的请求。如果数据库不存在或其版本已更改，将触发`upgradeneeded`事件。在监听这个事件的函数中，我们可以通过声明对象存储及其索引来定义模式。因此，如果我们需要更新现有数据库的模式，我们可以增加版本号，`upgradeneeded`将再次触发，监听器将被调用以更新模式。一旦我们定义了模式，我们就可以用示例数据填充对象存储。当打开数据库的请求完成后，我们请求与电子邮件 ID `don@company.com`匹配的记录。请求完成后，我们进入控制台：

```js
Employee matching 'don@company.com` is `Don Dow'
```

相当复杂，不是吗？这个 API 让我想到了一个包装器。我所知道最好的一个叫做**Dexie** ([`www.dexie.org`](http://www.dexie.org))。只需比较一下它暴露的接口如何轻松地解决同一个任务：

```js
<script src="img/Dexie.js"></script>
<script>
var db = new Dexie( "Cem" );
// Define DB
db.version( 3 )
  .stores({ employees: "name, email" });

// Open the database
db.open().catch(function( err ){
  alert( "Opps, something went wrong: " + err );
});

// Populate objectStore with test data
db.employees.add({ name: "John Dow", email: "john@company.com" });
db.employees.add({ name: "Don Dow", email: "don@company.com" });

// Find an employee by email
db.employees
  .where( "email" )
  .equals( "don@company.com" )
  .each(function( employee ){
    console.log( "Employee matching `don@company.com` is `" + employee.name + "`" );
  });

</script>
```

## 文件系统 API

好吧，在 Web 应用程序中，我们可以使用 Web Storage 存储键值对，我们也可以创建和使用 IndexedDB。还有一件事 missing。桌面应用程序可以读写文件和目录。这是我们经常在能够离线运行的 Web 应用程序中需要的东西。FileSystem API 允许我们在应用程序范围内创建、读取和写入用户的本地文件系统。让我们举一个例子：

```js
window.requestFileSystem  = window.requestFileSystem || window.webkitRequestFileSystem;
    /**
     * Read file from a given FileSystem
     * @param {DOMFileSystem} fs
     * @param {String} file
     */
var readFile = function( fs, file ) {
      console.log( "Reading file " + file );
      // Obtain FileEntry object
      fs.root.getFile( file, {}, function( fileEntry ) {
        fileEntry.file(function( file ){
           // Create FileReader
           var reader = new FileReader();
           reader.onloadend = function() {
             console.log( "Fetched content: ", this.result );
           };
           // Read file
           reader.readAsText( file );
        }, console.error );
      }, console.error );
    },
    /**
     * Save file into a given FileSystem and run onDone when ready
     * @param {DOMFileSystem} fs
     * @param {String} file
     * @param {Function} onDone
     */
    saveFile = function( fs, file, onDone ) {
      console.log( "Writing file " + file );
      // Obtain FileEntry object
      fs.root.getFile( file, { create: true }, function( fileEntry ) {
        // Create a FileWriter object for the FileEntry
        fileEntry.createWriter(function( fileWriter ) {
          var blob;
          fileWriter.onwriteend = onDone;
          fileWriter.onerror = function(e) {
            console.error( "Writing error: " + e.toString() );
          };
          // Create a new Blob out of the text we want into the file.
          blob = new Blob([ "Lorem Ipsum" ], { type: "text/plain" });
          // Write into the file
          fileWriter.write( blob );
        }, console.error );
      }, console.error );
    },
    /**
     * Run when FileSystem initialized
     * @param {DOMFileSystem} fs
     */
    onInitFs = function ( fs ) {
      const FILENAME = "log.txt";
      console.log( "Opening file system: " + fs.name );
      saveFile( fs, FILENAME, function(){
        readFile( fs, FILENAME );
      });
    };

window.requestFileSystem( window.TEMPORARY, 5*1024*1024 /*5MB*/, onInitFs, console.error );
```

首先，我们请求一个沙盒化的本地文件系统（`requestFileSystem`），该文件系统对应用程序来说是持久的。通过将 `window.TEMPORARY` 作为第一个参数传递，我们允许浏览器自动删除数据（例如，当需要更多空间时）。如果我们选择 `window.PERSISTENT`，我们确定数据在没有明确用户确认的情况下无法清除。第二个参数指定了我们可以为文件系统分配多少空间。然后，还有 `onSuccess` 和 `onError` 回调。当创建文件系统时，我们收到一个对 `FileSystem` 对象的引用。这个对象有一个 `fs.root` 属性，其中对象保持对根文件系统目录的 `DirectoryEntry` 绑定。`DirectoryEntry` 对象有 `DirectoryEntry.getDirectory`、`DirectoryEntry.getFile`、`DirectoryEntry.removeRecursevly` 和 `DirectoryEntry.createReader` 方法。在前一个示例中，我们在当前（`root`）目录中写入，所以我们只需使用 `DirectoryEntry.getFile` 打开一个给定名称的文件。成功打开文件后，我们收到一个代表打开文件的 `FileEntry` 对象。该对象有几个属性，如：`FileEntry.fullPath`、`FileEntry.isDirectory`、`FileEntry.isFile` 和 `FileEntry.name`，以及方法如 `FileEntry.file` 和 `FileEntry.createWriter`。第一个方法返回一个 `File` 对象，该对象可用于读取文件内容，第二个用于写入文件。当操作完成时，我们从文件中读取。为此，我们创建一个 `FileReader` 对象，并让它读取我们的 `File` 对象作为文本。

# 使用 JavaScript workers 提高性能

JavaScript 是单线程环境。所以，多个脚本实际上并不能真的同时运行。是的，我们使用 `setTimeout()`、`setInterval()`、`XMLHttpRequest` 以及事件处理程序来异步运行任务。因此我们获得了非阻塞执行，但这并不意味着并发。然而，通过使用 web workers，我们可以在与 UI 脚本无关的后台独立运行一个或多个脚本。Web workers 是长期运行的脚本，不会被阻塞的 UI 事件中断。Web workers 利用多线程，因此我们可以从多核 CPU 中受益。

那么，我们可以在哪些地方使用 web workers 呢？任何我们需要进行处理器密集型计算而不希望它们阻塞 UI 线程的地方。这可以是图形、网络游戏、加密和 Web I/O。我们从 web worker 直接操作 DOM 是不可能的，但我们有访问 `XMLHttpRequest`、Web Storage、IndexedDB、FileSystem API、Web Sockets 等特性的权限。

那么，让我们来看看实践中这些 web workers 是什么。总的来说，我们在主脚本中注册一个现有的 web worker 并通过 PostMessage API 与 web worker 进行通信（[`developer.mozilla.org/en-US/docs/Web/API/Window/postMessage`](https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage)）：

```js
index.html
<html>
  <body>
<script>
"use strict";
// Register worker
var worker = new Worker( "./foo-worker.js" );
// Subscribe for worker messages
worker.addEventListener( "message", function( e ) {
  console.log( "Result: ", e.data );
}, false );
console.log( "Starting the task..." );
// Send a message to worker
worker.postMessage({
  command: "loadCpu",
  value: 2000
});
</script>
  </body>
</html>
foo-worker.js
"use strict";
var commands = {
  /**
   * Emulate resource-consuming operation
   * @param {Number} delay in ms
   */
  loadCpu: function( delay ) {
    var start = Date.now();
    while (( Date.now() - start ) < delay );
    return "done";
  }
};
// Workers don't have access to the window object. // To access global object we have to use self object instead.
self.addEventListener( "message", function( e ) {
  var command;
  if ( commands.hasOwnProperty( e.data.command ) ) {
    command = commands[ e.data.command ];
    return self.postMessage( command( e.data.value ) );
  }
  self.postMessage( "Error: Command not found" );

}, false );
```

在这里的`index.html`中，我们请求网络工作者（`foo-worker.js`）订阅工作者消息，并要求它加载 CPU 2,000 毫秒，这代表了一个消耗资源的进程。工作者接收到消息并检查`command`属性中指定的函数。如果存在，工作者会将消息值传递给函数，并返回返回值。

请注意，尽管通过启动`index.html`启动了如此昂贵的进程，主线程仍然是非阻塞的。然而，当进程完成后，它还是会向控制台报告。但是，如果你尝试在主脚本内运行`loadCpu`函数，UI 将会冻结，很可能会导致脚本超时错误。现在考虑这个：如果你异步调用`loadCpu`（例如，使用`setTimeout`），UI 仍然会挂起。处理 CPU 敏感操作的唯一安全方法是将它们交给网络工作者。

网络工作者可以是专用的，也可以是共享的。专用的网络工作者只能通过一个脚本访问，该脚本是我们调用工作者的地方。共享工作者可以从多个脚本中访问，甚至包括在不同窗口中运行的脚本。这使得这个 API 有些不同：

**index.html**

```js
<script>
"use strict";
var worker = new SharedWorker( "bar-worker.js" );
worker.port.onmessage = function( e ) {
  console.log( "Worker echoes: ", e.data );
};
worker.onerror = function( e ){
  console.error( "Error:", e.message );
};
worker.port.postMessage( "Hello worker" );
</script>
bar-worker.js
"use strict";
onconnect = function( e ) {
  var port = e.ports[ 0 ];
  port.onmessage = function( e ) {
    port.postMessage( e.data );
  };
  port.start();
};
```

前面的例子中的工作线程只是简单地回显了接收到的消息。如果工作线程进行了有效的计算，我们就可以从不同页面上的不同脚本中指挥它。

这些例子展示了并发计算中网络工作者的使用。那么，将一些网络 I/O 操作从主线程中卸载又会怎样呢？例如，我们被要求将特定的 UI 事件报告给远程**商业智能服务器**（在这里**BI 服务器**用于接收统计数据）。这不是核心功能，因此最好是将这些请求产生的任何负载都保持在主线程之外。因此，我们可以使用一个网络工作者。然而，工作者只有在加载后才可用。通常，这非常快，但我还是想确保由于工作者不可用而没有丢失任何 BI 事件。我可以做的是将网络工作者代码嵌入 HTML 中，并通过数据 URI 注册网络工作者：

```js
<script data-bind="biTracker" type="text/js-worker">
  "use strict";

  // Here shall go you BI endpoint
  const REST_METHOD = "http://www.telize.com/jsonip";
  /**
   * @param {Map} data - BI request params
   * @param {Function} resolve
   */
  var call = function( data, resolve ) {
    var xhr = new XMLHttpRequest(),
        params = data ? Object.keys( data ).map(function( key ){
            return key + "=" + encodeURIComponent( data[ key ] );
          }).join( "&" ) : "";

    xhr.open( "POST", REST_METHOD, true );
    xhr.addEventListener( "load", function() {
        if ( this.status >= 200 && this.status < 400 ) {
          return resolve( this.response );
        }
        console.error( "BI tracker - bad request " + this.status );
      }, false );
    xhr.addEventListener( "error", console.error, false );
    xhr.responseType = "json";
    xhr.setRequestHeader( "Content-Type", "application/x-www-form-urlencoded" );
    xhr.send( params );
  };
  /**
   * Subscribe to window.onmessage event
   */
  onmessage = function ( e ) {
    call( e.data, function( data ){
      // respond back
      postMessage( data );
    })
  };
</script>

<script type="text/javascript">
  "use strict";
  window.biTracker = (function(){
    var blob = new Blob([ document.querySelector( "[data-bind=\"biTracker\"]" ).textContent ], {
          type: "text/javascript"
        }),
        worker = new Worker( window.URL.createObjectURL( blob ) );

    worker.onmessage = function ( oEvent ) {
      console.info( "Bi-Tracker responds: ", oEvent.data );
    };
    return worker;
  }());
  // Let's test it
  window.biTracker.postMessage({ page: "#main" });
</script>
```

通过将网络 I/O 交给工作者，我们还可以对其进行额外的控制。例如，在网络状态发生变化时（`ononline`和`onoffline`事件，以及工作者可以访问的`navigator.online`属性），我们可以要么返回实际的调用结果，要么返回缓存的结果。换句话说，我们可以使我们的应用程序离线工作。实际上，还有特殊类型的 JavaScript 工作者，称为服务工作者。服务工作者继承自共享工作者，充当网页应用程序和网络之间的代理（[`developer.mozilla.org/en-US/docs/Mozilla/Projects/Social_API/Service_worker_API_reference`](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/Social_API/Service_worker_API_reference)）。

# 创建第一个网络组件

你可能熟悉 HTML5 视频元素([`www.w3.org/TR/html5/embedded-content-0.html#the-video-element`](http://www.w3.org/TR/html5/embedded-content-0.html#the-video-element)).通过在 HTML 中放置一个元素，你将得到一个运行视频的小工具。这个元素接受多个属性来设置播放器。如果你想要增强这个功能，你可以使用它的公共 API 并在其事件上订阅监听器([`www.w3.org/2010/05/video/mediaevents.html`](http://www.w3.org/2010/05/video/mediaevents.html)).因此，每当我们需要播放器时，我们都会重用这个元素，并且只针对与项目相关的外观和感觉进行自定义。如果每次我们都需要页面上的小工具时，都有足够多的这样的元素就好了。然而，这并不是在 HTML 规范中包含我们可能需要的任何小工具的正确方法。然而，创建自定义元素的 API，比如视频，已经存在。我们确实可以定义一个元素，打包化合物（JavaScript，HTML，CSS，图片等），然后只需从消费 HTML 中链接它。换句话说，我们可以创建一个独立且可重用的 Web 组件，然后通过在 HTML 中放置相应的自定义元素（`<my-widget />`）来使用它。我们可以重新样式化该元素，如果需要，我们可以利用元素 API 和事件。例如，如果你需要一个日期选择器，你可以取一个现有的 Web 组件，比如说在[`component.kitchen/components/x-tag/datepicker`](http://component.kitchen/components/x-tag/datepicker)可用的那个。我们只需要下载组件源（例如，使用浏览器包管理器）并在我们的 HTML 代码中链接到该组件：

```js
<link rel="import" href="bower_components/x-tag-datepicker/src/datepicker.js"> 
```

在 HTML 代码中声明组件：

```js
<x-datepicker name="2012-02-02"></x-datepicker>
```

这应该在最新版本的 Chrome 中顺利运行，但在其他浏览器中可能不会工作。运行 Web 组件需要在客户端浏览器中解锁多项新技术，如**自定义元素**、**HTML 导入**、**Shadow DOM**和模板。模板包括我们在第一章中研究的 JavaScript 模板(*Diving into JavaScript core*)。自定义元素 API 允许我们定义新的 HTML 元素、它们的行为和属性。Shadow DOM 封装了一个由自定义元素所需的 DOM 子树。而 HTML 导入的支持意味着通过给定的链接，用户代理通过在页面上包含其 HTML 来启用 Web 组件。我们可以使用 polyfill([`webcomponents.org/`](http://webcomponents.org/))确保所有主要浏览器都支持所需的技术：

```js
<script src="img/webcomponents.min.js"></script>
```

你想写自己的 Web 组件吗？我们一起做。我们的组件类似于 HTML 的`details/summary`。当点击**summary**时，详细信息显示出来。因此，我们创建`x-details.html`，在其中我们放置组件样式和 JavaScript 以及组件 API：

**x-details.html**

```js
<style>
  .x-details-summary {
    font-weight: bold;
    cursor: pointer;
  }
  .x-details-details {
    transition: opacity 0.2s ease-in-out, transform 0.2s ease-in-out;
    transform-origin: top left;
  }
  .x-details-hidden {
    opacity: 0;
    transform: scaleY(0);
  }
</style>
<script>
"use strict";
    /**
     * Object constructor representing x-details element
     * @param {Node} el
     */
var DetailsView = function( el ){
      this.el = el;
      this.initialize();
    },
    // Creates an object based in the HTML Element prototype
    element = Object.create( HTMLElement.prototype );
/** @lend DetailsView.prototype */
Object.assign( DetailsView.prototype, {
  /**
   * @constracts DetailsView
   */
  initialize: function(){
    this.summary = this.renderSummary();
    this.details = this.renderDetails();
    this.summary.addEventListener( "click", this.onClick.bind( this ), false );
    this.el.textContent = "";
    this.el.appendChild( this.summary );
    this.el.appendChild( this.details );
  },
  /**
   * Render summary element
   */
  renderSummary: function(){
    var div = document.createElement( "a" );
    div.className = "x-details-summary";
    div.textContent = this.el.dataset.summary;
    return div;
  },
  /**
   * Render details element
   */
  renderDetails: function(){
    var div = document.createElement( "div" );
    div.className = "x-details-details x-details-hidden";
    div.textContent = this.el.textContent;
    return div;
  },
  /**
   * Handle summary on click
   * @param {Event} e
   */
  onClick: function( e ){
    e.preventDefault();
    if ( this.details.classList.contains( "x-details-hidden" ) ) {
      return this.open();
    }
    this.close();
  },
  /**
   * Open details
   */
  open: function(){
    this.details.classList.toggle( "x-details-hidden", false );
  },
  /**
   * Close details
   */
  close: function(){
    this.details.classList.toggle( "x-details-hidden", true );
  }
});

// Fires when an instance of the element is created
element.createdCallback = function() {
  this.detailsView = new DetailsView( this );
};
// Expose method open
element.open = function(){
  this.detailsView.open();
};
// Expose method close
element.close = function(){
  this.detailsView.close();
};
// Register the custom element
document.registerElement( "x-details", {
  prototype: element
});
</script>
```

在 JavaScript 代码的进一步部分，我们基于一个通用 HTML 元素（`Object.create( HTMLElement.prototype )`）创建了一个元素。如果需要，我们这里可以继承一个复杂元素（例如，视频）。我们使用前面创建的作为原型的元素注册了一个`x-details`自定义元素。通过`element.createdCallback`，我们在自定义元素创建时订阅了一个处理程序。在这里，我们将我们的视图附加到元素上，以通过为其提供我们打算的功能来增强它。现在我们可以在 HTML 中使用该组件，如下所示：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>X-DETAILS</title>
    <!-- Importing Web Component's Polyfill -->
    <!-- uncomment for non-Chrome browsers
    script src="img/webcomponents.min.js"></script-->
    <!-- Importing Custom Elements -->
 <link rel="import" href="./x-details.html">
  </head>
  <body>
    <x-details data-summary="Click me">
      Nunc iaculis ac erat eu porttitor. Curabitur facilisis ligula et urna egestas mollis. Aliquam eget consequat tellus. Sed ullamcorper ante est. In tortor lectus, ultrices vel ipsum eget, ultricies facilisis nisl. Suspendisse porttitor blandit arcu et imperdiet.
    </x-details>
  </body>
</html>
```

下面屏幕截图展示了 X-details web-组件在行动中的情况：

![创建第一个 web 组件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-ulk/img/00009.jpeg)

# 学习使用服务器到浏览器的通信通道

使用 XHR 或 Fetch API，我们可以从服务器请求一个状态。这是一条单向通信。如果我们想要实时通信，我们同样也需要反方向也这样做。例如，我们可能希望在数据库中相应记录发生变化时，用户通知（你的帖子被点赞了，新评论，或者新私信）能够立即弹出。服务器端有连接到数据库，所以期望服务器能通知客户端。在过去，要在客户端接收这些事件，我们使用了被称为**COMET**（隐藏 iframe，长轮询，标签长轮询等）的技巧。现在我们可以使用原生的 JavaScript API。

## 服务器发送事件

提供了一种订阅服务器端事件的技术是**服务器发送事件**（**SSE**）API。在客户端，我们注册一个服务器流（`EventSource`）并订阅来自它的事件：

```js
var src = new EventSource( "./sse-server.php" );

src.addEventListener( "open", function() {
   console.log( "Connection opened" );
}, false);

src.addEventListener( "error", function( e ) {
  if ( e.readyState === EventSource.CLOSED ) {
    console.error( "Connection closed" );
  }
}, false );

src.addEventListener( "foo", function( e ) {
  var data = JSON.parse( e.data );
  console.log( "Received from the server:", data );
}, false);
```

在这里，我们为特定事件`"foo"`订阅了一个监听器。如果你想让回调在每次服务器事件上被调用，只需使用`src.onmessage`。至于服务器端，我们只需要设置 MIME 类型`text/event-stream`，并发送由换行符成对分隔的事件负载块：

```js
event: foo\n
data: { time: "date" }\n\n
```

SSE 通过 HTTP 连接工作，因此我们需要一个 Web 服务器来创建一个流。PHP 要简单得多，并且是一个广泛使用的服务器端语言。很可能你已经熟悉其语法。另一方面，PHP 并不适合持久连接的长久维持。然而，我们可以通过声明一个循环让我们的 PHP 脚本永不结束来欺骗它：

```js
<?PHP
set_time_limit( 0 );
header("Content-Type: text/event-stream");
header("Cache-Control: no-cache");
date_default_timezone_set("Europe/Berlin");

function postMessage($event, $data){
  echo "event: {$event}", PHP_EOL;
  echo "data: ", json_encode($data, true), PHP_EOL, PHP_EOL;
  ob_end_flush();
  flush();
}
while (true) {
  postMessage("foo", array("time" => date("r")) );
  sleep(1);
}
```

你可能看到过 SSE 示例，其中服务器脚本一次性输出数据并终止进程（例如，[`www.html5rocks.com/en/tutorials/eventsource/basics/`](http://www.html5rocks.com/en/tutorials/eventsource/basics/)）。那也是一个工作示例，因为每次服务器通过服务器终止连接时，浏览器都会重新建立连接。然而，这种方法并没有 SSE 的任何好处，它像轮询一样工作。

现在一切看起来都准备好了，所以我们可以运行 HTML 代码。这样做时，我们在控制台得到以下输出：

```js
Connection opened
Received from the server: Object { time="Tue, 25 Aug 2015 10:31:54 +0200"}
Received from the server: Object { time="Tue, 25 Aug 2015 10:31:55 +0200"}
Received from the server: Object { time="Tue, 25 Aug 2015 10:31:56 +0200"}
Received from the server: Object { time="Tue, 25 Aug 2015 10:31:57 +0200"}
Received from the server: Object { time="Tue, 25 Aug 2015 10:31:58 +0200"}
Received from the server: Object { time="Tue, 25 Aug 2015 10:31:59 +0200"}
Received from the server: Object { time="Tue, 25 Aug 2015 10:32:00 +0200"}
Received from the server: Object { time="Tue, 25 Aug 2015 10:32:01 +0200"}
Received from the server: Object { time="Tue, 25 Aug 2015 10:32:02 +0200"}
...
```

## Web Sockets

好吧，使用 XHR/Fetch 我们从客户端到服务器进行通信。使用 SSE，我们这样做是反向的。但是我们可以同时进行双向通信吗？另一个 HTML5 好东西叫做 Web Sockets，它提供了双向、全双工的客户端服务器通信。

客户端看起来类似于 SSE。我们只需注册 WebSocket 服务器，订阅其事件，并向其发送我们的事件：

```js
var rtm = new WebSocket("ws://echo.websocket.org");
rtm.onopen = function(){
  console.log( "Connection established" );
  rtm.send("hello");
};
rtm.onclose = function(){
  console.log( "Connection closed" );
};
rtm.onmessage = function( e ){
  console.log( "Received:", e.data );
};
rtm.onerror = function( e ){
  console.error( "Error: " + e.message );
};
```

这个在`ws://echo.websocket.org`的演示源简单地回显发送给它的任何消息：

```js
Connection established
Received: hello
```

需要更实际的东西吗？我相信最说明问题的例子将是一个聊天室：

**demo.html**

```js
<style>
  input {
    border-radius: 5px;
    display: block;
    font-size: 14px;
    border: 1px solid grey;
    margin: 3px 0;
  }
  button {
    border-radius: 5px;
    font-size: 14px;
    background: #189ac4;
    color: white;
    border: none;
    padding: 3px 14px;
  }
</style>

<form data-bind="chat">
  <input data-bind="whoami" placeholder="Enter your name">
  <input data-bind="text" placeholder="Enter your msg" />
  <button type="submit">Send</button>
</form>
<h3>Chat:</h3>
<output data-bind="output">
</output>
<script>

var whoami = document.querySelector( "[data-bind=\"whoami\"]" ),
    text = document.querySelector( "[data-bind=\"text\"]" ),
    chat = document.querySelector( "[data-bind=\"chat\"]" ),
    output = document.querySelector( "[data-bind=\"output\"]" ),
    // create ws connection
    rtm = new WebSocket("ws://localhost:8001");

rtm.onmessage = function( e ){
  var data = JSON.parse( e.data );
  output.innerHTML += data.whoami + " says: " + data.text + "<br />";
};
rtm.onerror = function( e ){
  console.error( "Error: " + e.message );
};

chat.addEventListener( "submit", function( e ){
  e.preventDefault();
  if ( !whoami.value ) {
    return alert( "You have enter your name" );
  }
  if ( !text.value ) {
    return alert( "You have enter some text" );
  }
  rtm.send(JSON.stringify({
    whoami: whoami.value,
    text: text.value
  }));
});

</script>
```

这里有一个带有两个输入字段的表单。第一个期望输入一个人的名字，第二个是聊天信息。当表单提交时，将两个输入字段的值发送到 WebSocket 服务器。服务器的响应显示在输出元素中。与 SSE 不同，WebSocket 需要特殊的协议和服务器实现才能工作。为了运行示例，我们将使用一个简单的基于 nodejs 的服务器实现，**nodejs-websocket**（[`github.com/sitegui/nodejs-websocket`](https://github.com/sitegui/nodejs-websocket)）：

**ws.js**

```js
    /** @type {module:nodejs-websocket} */
var ws = require( "nodejs-websocket" ),
    /** @type {Server} */
    server = ws.createServer(function( conn ) {
        conn.on( "text", function ( str ) {
          console.log( "Received " + str );
          broadcast( str );
        });
    }).listen( 8001 ),
    /**
     * Broadcast message
     * @param {String} msg
     */
    broadcast = function ( msg ) {
      server.connections.forEach(function ( conn ) {
        conn.sendText( msg );
      });
    };
```

脚本创建了一个在端口 8001 上监听 WebSocket 消息的服务器，当接收到任何消息时，端口将其广播给所有可用的连接。我们可以这样启动服务器：

```js
node ws.js
```

现在我们在两个不同的浏览器中打开我们的聊天室演示。当我们从一个浏览器中发送消息时，消息会在两个浏览器中显示出来。下面的截图显示了在 Firefox 中的 WebSocket 驱动的聊天：

![Web Sockets](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-ulk/img/00010.jpeg)

下面的截图显示了在 Chrome 中的 WebSocket 驱动的聊天：

![Web Sockets](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-ulk/img/00011.jpeg)

注意客户端对事件反应有多快。通过套接字进行的通信具有无可争辩的优势。

有许多针对不同语言的 WebSocket 服务器实现，例如，Socket.IO（[`socket.io`](http://socket.io)）用于 Node.js，Jetty（[`www.eclipse.org/jetty`](http://www.eclipse.org/jetty)）用于 Java，Faye（[`faye.jcoglan.com`](http://faye.jcoglan.com)）用于 Ruby，Tornado（[`www.tornadoweb.org`](http://www.tornadoweb.org)）用于 Python，甚至还有一个名为 Ratchet 的 PHP 实现（[`socketo.me`](http://socketo.me)）。然而，我想向您介绍一个与语言无关的 WebSocket 守护进程——Websocketd（[`websocketd.com/`](http://websocketd.com/)）。它就像**公共网关接口**（**CGI**），但是用于 Web Sockets。所以您可以使用您喜欢的语言编写服务器登录脚本，然后将脚本附加到守护进程：

```js
websocketd --port=8001 my-script
```

# 总结

HTML5 提供了一些很棒的 API，我们刚才检查了一些。在浏览器存储 API 中，有 localStorage 和 sessionStorage，它们扩展了 cookie 遗留问题。两者都 capable of storing megabytes of data and can be easily synchronized across different browser windows/tabs. IndexedDB 允许我们存储更多的数据，并提供了一个用于使用索引的高性能搜索的接口。我们还可以使用 FileSystem API 来创建和操作与网络应用程序绑定的本地文件系统。

虽然 JavaScript 是一个单线程环境，我们仍然可以在多个线程中运行脚本。我们可以注册专用或共享的 Web Workers，并将任何耗处理器操作交给它们，从而不会影响主线程和 UI。我们还可以利用一种特殊的 JavaScript 工作者---服务工作者---作为网络应用程序和网络之间的代理。这可以在浏览器在线/离线模式之间切换时控制网络 I/O。

现在我们可以创建自己的自定义高级元素，这些元素可以轻松地被重复使用、重新设计并增强。渲染此类元素所需的资源包括 HTML、CSS、JavaScript 和图片，它们被作为 Web 组件捆绑在一起。因此，我们实际上可以从类似建筑物的组件开始构建网页。

在过去，我们使用被称为 COMET 的技巧来在服务器和客户端之间交换事件。现在我们可以使用 SSE API 来订阅通过 HTTP 发送的服务器事件。我们还可以使用 Web Sockets 进行双向、全双工的客户端-服务器通信。


# 第五章：异步 JavaScript

如今，互联网用户变得没有耐心，页面加载或导航过程中的 2-3 秒延迟，他们就会失去兴趣，并且可能会离开服务，转而使用其他东西。我们最高优先级的是减少用户响应时间。这里的主要方法被称为*芥末切割*（[`www.creativebloq.com/web-design/responsive-web-design-tips-bbc-news-9134667`](http://www.creativebloq.com/web-design/responsive-web-design-tips-bbc-news-9134667)）。我们提取应用程序的核心体验所需的组件并首先加载它们。然后，我们逐步添加增强的体验。至于 JavaScript，我们需要最关心的是非阻塞流程。因此，我们必须避免在 HTML 渲染之前同步加载脚本，并将所有长时间运行的任务包装到异步回调中。这可能是你已经知道的事情。但你是高效地这样做吗？

在本章中，我们将介绍以下主题：

+   非阻塞 JavaScript

+   错误优先回调

+   延续传递风格

+   使用 ES7 方式处理异步函数

+   使用 Async.js 库进行并行任务和任务系列

+   事件处理优化

# 非阻塞 JavaScript

首先，让我们看看当我们异步做事情时实际发生的情况。无论何时在 JavaScript 中调用一个函数，它都会创建一个新的栈帧（执行对象）。每个内部调用都会进入这个帧。这里帧是从调用堆栈的顶部以**LIFO**（**后进先出**）的方式推入和弹出。换句话说，在代码中，我们调用`foo`函数，然后调用`bar`函数；然而，在执行过程中，`foo`调用`baz`函数。在这种情况下，在`call`堆栈中，我们有以下顺序：`foo`、`baz`，然后才是`bar`。所以`bar`是在`foo`的栈帧清空后才被调用。如果任何一个函数执行一个 CPU 密集型任务，所有后续的调用都会等待它完成。然而，JavaScript 引擎具有**事件队列**（或任务队列）。

![非阻塞 JavaScript](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-ulk/img/00012.jpeg)

如果我们为 DOM 事件订阅一个函数，或者将一个回调传递给定时器（`setTimeout`或`setInterval`）或任何 Web I/O API（XHR、IndexedDB 和 FileSystem），它最终都会进入相应的队列。然后，浏览器的事件循环决定何时将哪个回调推入回调堆栈。以下是一个例子：

```js
function foo(){
  console.log( "Calling Foo" );
}
function bar(){
  console.log( "Calling Bar" );
}
setTimeout(foo, 0 );
bar();
```

使用`setTimeout( foo, 0 )`，我们声明`foo`应立即被调用，然后我们调用`bar`。然而，`foo`进入一个队列，事件循环将其推入调用堆栈的更深位置：

```js
Calling Bar
Calling Foo
```

这也意味着如果`foo`回调执行一个 CPU 密集型任务，它不会阻塞主线程的执行流程。同样，异步发起的 XHR/Fetch 请求在等待服务器响应时不会锁定交互：

```js
function bar(){
  console.log( "Bar complete" );
}
fetch( "http://www.telize.com/jsonip" ).then(function( response ) {
  console.log( "Fetch complete" );
});
bar();

// Console:
// Bar complete
// Fetch complete
```

这如何适用于实际应用？以下是一个常见的流程：

```js
"use strict";
// This statement loads imaginary AMD modules
// You can find details about AMD standard in 
// "Chapter 2: Modular programming with JavaScript" 
require([ "news", "Session", "User", "Ui" ], function ( News, Session, User, Ui ) {
  var session = new Session(),
      news = new News(),
      ui = new Ui({ el: document.querySelector( "[data-bind=ui]" ) });
  // load news
 news.load( ui.update );
 //  authorize user 
 session.authorize(function( token ){
   var user = new User( token );
   // load user data
   user.load(function(){
     ui.update();
     // load user profile picture
     user.loadProfilePicture( ui.update );
     // load user notifications  
     user.loadNotifications( ui.update );
   });
 });
});
```

JavaScript 依赖的加载是排队进行的，所以浏览器可以在不等待加载完成的情况下渲染并把 UI 交付给用户。一旦脚本完全加载，应用程序就会把两个新任务推入队列：*加载新闻*和*认证用户*。再次强调，它们都不会阻塞主线程。只有在这些请求之一完成并涉及到主线程时，它才会根据新接收的数据增强 UI。一旦用户被认证并且会话令牌被检索到，我们可以加载用户数据。任务完成后，我们又会排队新的任务。

正如你所见，与同步代码相比，异步代码更难阅读。执行序列可能会相当复杂。此外，我们还需要特别注意错误控制。当处理同步代码时，我们可以用`try`/`catch`包围程序的一块，拦截执行期间抛出的任何错误：

```js
function foo(){
  throw new Error( "Foo throws an error" );
}
try {
  foo();
} catch( err ) {
  console.log( "The error is caught" );
}
```

然而，如果调用被排队，它就会滑出`try`/`catch`的作用域：

```js
function foo(){
  throw new Error( "Foo throws an error" );
}
try {
  setTimeout(foo, 0 );
} catch( err ) {
  console.log( "The error is caught" );
}
```

是的，异步编程有其怪癖。为了掌握这一点，我们将检查编写异步代码的现有实践。

因此，为了使代码异步，我们排队一个任务并订阅一个事件，当任务完成时触发该事件。实际上，我们采用的是*事件驱动编程*，特别是，我们应用了一个*发布/订阅*模式。例如，我们在第三章中提到的`EventTarget`接口，*DOM 脚本和 AJAX*，简而言之，就是关于为 DOM 元素的事件订阅监听器，并从 UI 或以编程方式触发这些事件：

```js
var el = document.createElement( "div" );
    event = new CustomEvent( "foo", { detail: "foo data" });
el.addEventListener( "foo", function( e ){
  console.log( "Foo event captured: ", e.detail );
}, false );

el.dispatchEvent( event );

// Foo event captured: foo data
```

在 DOM 背后，我们使用了一个类似的原理，但实现可能会有所不同。最流行的接口可能是基于两个主要方法`obj.on`（用于订阅处理程序）和`obj.trigger`（用于触发事件）：

```js
obj.on( "foo", function( data ){
  console.log( "Foo event captured: ", data );
});
obj.trigger( "foo", "foo data" );
```

这是在抽象框架中实现发布/订阅的方式，例如，Backbone。jQuery 在 DOM 事件上也使用这个接口。这个接口因其简单性而获得了势头，但它实际上并不能帮助处理意大利面条代码，也没有涵盖错误处理。

# 错误优先的回调

在 Node.js 中所有异步方法使用的模式被称为**错误优先的回调**。以下是一个例子：

```js
fs.readFile( "foo.txt", function ( err, data ) {
  if ( err ) {
    console.error( err );
  }
  console.log( data );
});
```

任何异步方法都期望有一个回调函数作为参数。完整的回调参数列表取决于调用方法，但第一个参数总是错误对象或 null。当我们使用异步方法时，函数执行期间抛出的异常不能在`try`/`catch`语句中检测到。事件发生在 JavaScript 引擎离开`try`块之后。在前面的例子中，如果在读取文件时抛出任何异常，它作为第一个和必需的参数落在回调函数上。尽管它的使用很普遍，但这种方法有其缺陷。在编写具有深层回调序列的实际代码时，很容易遇到所谓的**回调地狱**（[`callbackhell.com/`](http://callbackhell.com/)）。代码变得相当难以跟踪。

# 继续传递风格

我们经常需要一个异步调用的链，即一个任务在另一个任务完成后开始的任务序列。我们感兴趣的是异步调用链的最终结果。在这种情况下，我们可以从**继续传递风格**（**CPS**）中受益。JavaScript 已经有了内置的`Promise`对象。我们用它来创建一个新的`Promise`对象。我们把异步任务放在`Promise`回调中，并调用参数列表的`resolve`函数，以通知`Promise`回调任务已解决：

```js
"use strict";
    /**
     * Increment a given value
     * @param {Number} val
     * @returns {Promise}
     */
var foo = function( val ) {
      /**
       * Return a promise.
       * @param {Function} resolve
       */
      return new Promise(function( resolve ) {
        setTimeout(function(){
          resolve( val + 1 );
        }, 0 );
      });
    };

foo( 1 ).then(function( val ){
  console.log( "Result: ", val );
});

// Result: 5
```

在前面的例子中，我们调用`foo`，它返回`Promise`。使用这种方法，我们设置了一个处理器，当`Promise`被满足时调用。

那么关于错误控制呢？在创建`Promise`时，我们可以使用第二个参数（`reject`）中的函数来报告失败：

```js
"use strict";
/**
 * Make GET request
 * @param {String} url
 * @returns {Promise}
 */
function ajaxGet( url ) {
  return new Promise(function( resolve, reject ) {
    var req = new XMLHttpRequest();
    req.open( "GET", url );
    req.onload = function() {
      // If response status isn't 200 something went wrong
      if ( req.status !== 200 ) {
        // Early exit
        return reject( new Error( req.statusText ) );
      }
      // Everything is ok, we can resolve the promise
      return resolve( JSON.parse( req.responseText ) );
    };
    // On network errors
    req.onerror = function() {
      reject( new Error( "Network Error" ) );
    };
    // Make the request
    req.send();
  });
};

ajaxGet("http://www.telize.com/jsonip").then(function( data ){
  console.log( "Your IP is ", data.ip );
}).catch(function( err ){
  console.error( err );
});
// Your IP is 127.0.0.1
```

关于`Promises`最令人兴奋的部分是它们可以被链式调用。我们可以把回调函数排队作为异步任务，或者进行值转换：

```js
"use strict";
    /**
     * Increment a given value
     * @param {Number} val
     * @returns {Promise}
     */
var foo = function( val ) {
      /**
       * Return a promise.
       * @param {Function} resolve
       * @param {Function} reject
       */
      return new Promise(function( resolve, reject ) {
        if ( !val ) {
          return reject( new RangeError( "Value must be greater than zero" ) );
        }
        setTimeout(function(){
          resolve( val + 1 );
        }, 0 );
      });
    };

foo( 1 ).then(function( val ){
  // chaining async call
  return foo( val );
}).then(function( val ){
  // transforming output
  return val + 2;
}).then(function( val ){
  console.log( "Result: ", val );
}).catch(function( err ){
  console.error( "Error caught: ", err.message );
});

// Result: 5
```

注意，如果我们把`0`传给`foo`函数，入口条件会抛出一个异常，我们最终会进入`catch`方法的回调。如果在回调中抛出异常，它也会在`catch`回调中出现。

`Promise`链以类似于瀑布模型的方式解决——任务一个接一个地调用。我们也可以让`Promise`在几个并行处理任务完成后解决：

```js
"use strict";
    /**
     * Increment a given value
     * @param {Number} val
     * @returns {Promise}
     */
var foo = function( val ) {
      return new Promise(function( resolve ) {
        setTimeout(function(){
          resolve( val + 1 );
        }, 100 );
      });
    },
    /**
     * Increment a given value
     * @param {Number} val
     * @returns {Promise}
     */
    bar = function( val ) {
      return new Promise(function( resolve ) {
        setTimeout(function(){
          resolve( val + 2 );
        }, 200 );
      });
    };

Promise.all([ foo( 1 ), bar( 2 ) ]).then(function( arr ){
  console.log( arr );
});
//  [2, 4]
```

`Promise.all`静态方法在所有最新浏览器中还得不到支持，但你可以通过[`github.com/jakearchibald/es6-promise`](https://github.com/jakearchibald/es6-promise)的 polyfill 来获得。

另一种可能性是让`Promise`在任何一个并发运行的任务完成时解决或拒绝：

```js
Promise.race([ foo( 1 ), bar( 2 ) ]).then(function( arr ){
  console.log( arr );
});
// 2
```

# 用 ES7 的方式处理异步函数

我们已经在 JavaScript 中有了 Promise API。即将到来的技术是 Async/Await API，它出现在 EcmaScript 第七版的提案中（[`tc39.github.io/ecmascript-asyncawait/`](https://tc39.github.io/ecmascript-asyncawait/)）。这描述了我们如何可以声明非阻塞的异步函数并等待`Promise`的结果：

```js
"use strict";

// Fetch a random joke
function fetchQuote() {
  return fetch( "http://api.icndb.com/jokes/random" )
  .then(function( resp ){
    return resp.json();
  }).then(function( data ){
    return data.value.joke;
  });
}
// Report either a fetched joke or error
async function sayJoke()
{
  try {
    let result = await fetchQuote();
    console.log( "Joke:", result );
  } catch( err ) {
    console.error( err );
  }
}
sayJoke();
```

目前，API 在任何一个浏览器中都不受支持；然而，你可以在运行时使用 Babel.js 转换器来运行它。你也可以在线尝试这个例子：[`codepen.io/dsheiko/pen/gaeqRO`](http://codepen.io/dsheiko/pen/gaeqRO)。

这种新语法允许我们编写看起来是同步运行的异步代码。因此，我们可以使用诸如`try`/`catch`之类的常见构造来进行异步调用，这使得代码更加可读，更容易维护。

# 使用 Async.js 库的并行任务和任务系列

处理异步调用的另一种方法是一个名为**Async.js**的库（[`github.com/caolan/async`](https://github.com/caolan/async)）。使用这个库时，我们可以明确指定我们想要任务批次如何解析—作为瀑布（链）或并行。

在第一种情况下，我们可以向`async.waterfall`提供回调数组，假设当一个完成后，下一个会被调用。我们还可以将一个回调中解析的值传递给另一个，并在方法的`on-done`回调中接收累积值或抛出的异常：

```js
/**
 * Concat given arguments
 * @returns {String}
 */
function concat(){
  var args = [].slice.call( arguments );
  return args.join( "," );
}

async.waterfall([
    function( cb ){
      setTimeout( function(){
        cb( null, concat( "foo" ) );
      }, 10 );
    },
    function( arg1, cb ){
      setTimeout( function(){
        cb( null, concat( arg1, "bar" ) );
      }, 0 );
    },
    function( arg1, cb ){
      setTimeout( function(){
        cb( null, concat( arg1, "baz" ) );
      }, 20 );
    }
], function( err, results ){
   if ( err ) {
     return console.error( err );
   }
   console.log( "All done:", results );
});

// All done: foo,bar,baz
```

同样，我们将回调数组传递给`async.parallel`。这次，它们全部并行运行，但当它们都解决时，我们在方法的`on-done`回调中接收结果或抛出的异常：

```js
async.parallel([
    function( cb ){
      setTimeout( function(){
        console.log( "foo is complete" );
        cb( null, "foo" );
      }, 10 );
    },
    function( cb ){
      setTimeout( function(){
        console.log( "bar is complete" );
        cb( null, "bar" );
      }, 0 );
    },
    function( cb ){
      setTimeout( function(){
        console.log( "baz is complete" );
        cb( null, "baz" );
      }, 20 );
    }
], function( err, results ){
   if ( err ) {
     return console.error( err );
   }
   console.log( "All done:", results );
});

// bar is complete
// foo is complete
// baz is complete
// All done: [ 'foo', 'bar', 'baz' ]
```

当然，我们可以组合这些流程。此外，该库还提供了迭代方法，如`map`、`filter`和`each`，适用于异步任务的数组。

Async.js 是这种类型的第一个项目。今天，有许多受此启发的库。如果你想要一个轻量级且健壮的与 Async.js 类似的解决方案，我建议你查看一下 Contra ([`github.com/bevacqua/contra`](https://github.com/bevacqua/contra))。

# 事件处理优化

编写内联表单验证器时，你可能会遇到一个问题。当你输入时，`user-agent`会不断向服务器发送验证请求。这样你可能会很快就会通过产生 XHR 来污染网络。另一个你可能熟悉的问题是一些 UI 事件（`touchmove`、`mousemove`、`scroll`和`resize`）会频繁触发，订阅的事件处理程序可能会使主线程过载。这些问题可以通过两种已知的方法来解决，称为*去抖*和*节流*。这两个函数都可以在第三方库（如 Underscore 和 Lodash）中找到（`_.debounce`和`_.throttle`）。然而，它们可以用一点`o`代码实现，不需要依赖额外的库来实现这个功能。

## 去抖

通过去抖，我们确保在重复触发的事件中，处理函数只被调用一次：

```js
  /**
   * Invoke a given callback only after this function stops being called `wait` milliseconds
   * usage:
   * debounce( cb, 500 )( ..arg );
   *
   * @param {Function} cb
   * @param {Number} wait
   * @param {Object} thisArg
   */
  function debounce ( cb, wait, thisArg ) {
    /**
     * @type {number}
     */
    var timer = null;
    return function() {
      var context = thisArg || this,
          args = arguments;
      window.clearTimeout( timer );
      timer = window.setTimeout(function(){
        timer = null;
        cb.apply( context, args );
      }, wait );
    };
  }
```

假设我们希望只有在组件进入视图时才进行延迟加载，在我们的案例中，这需要用户至少向下滚动 200 像素：

```js
var TOP_OFFSET = 200;
// Lazy-loading
window.addEventListener( "scroll", debounce(function(){
  var scroll = window.scrollY || window.pageYOffset || document.documentElement.scrollTop;
  if ( scroll >= TOP_OFFSET ){
     console.log( "Load the deferred widget (if not yet loaded)" );
  }
}, 20 ));
```

如果我们简单地为滚动事件订阅一个监听器，它在用户开始和停止滚动的时间间隔内会被调用很多次。多亏了去抖代理，检查是否是加载小部件的时候的处理程序只调用一次，即当用户停止滚动时。

## 节流

通过节流，我们设置在事件触发时允许处理程序被调用的频率：

```js
  /**
   * Invoke a given callback every `wait` ms until this function stops being called
   * usage:
   * throttle( cb, 500 )( ..arg );
   *
   * @param {Function} cb
   * @param {Number} wait
   * @param {Object} thisArg
   */
 function throttle( cb, wait, thisArg ) {
  var prevTime,
      timer;
  return function(){
    var context = thisArg || this,
        now = +new Date(),
        args = arguments;

    if ( !prevTime || now >= prevTime + wait ) {
      prevTime = now;
      return cb.apply( context, args );
    }
    // hold on to it
    clearTimeout( timer );
    timer = setTimeout(function(){
      prevTime = now;
      cb.apply( context, args );
    }, wait );
  };
}
```

所以如果我们通过节流在容器的`mousemove`事件上订阅一个处理程序，`handler`函数一次（在这里是每秒一次）直到鼠标光标离开容器边界：

```js
document.body.addEventListener( "mousemove", throttle(function( e ){
  console.log( "The cursor is within the element at ", e.pageX, ",", e.pageY );
}, 1000 ), false );

// The cursor is within the element at 946 , 715
// The cursor is within the element at 467 , 78
```

## 编写不会影响延迟关键事件的回调

我们有些任务不属于核心功能，可能是在后台运行。例如，我们希望在不滚动页面时派发分析数据。我们不使用去抖或节流，以免加重 UI 线程的负担，可能导致应用无响应。在这里去抖不相关，节流也不会提供精确数据。然而，我们可以使用`requestIdleCallback`原生方法（[`w3c.github.io/requestidlecallback/`](https://w3c.github.io/requestidlecallback/)）在`user-agent`空闲时安排任务。

# 总结

我们最优先的目标之一是减少用户响应时间，即，应用程序架构必须确保用户流程永远不会被阻塞。这可以通过将任何长时间运行的任务排队异步调用来实现。然而，如果您有许多异步调用，其中一些并行运行，一些顺序运行，不特别注意，很容易陷入所谓的回调地狱。恰当地使用诸如*继续传递风格*（*Promise API*）、Async/Await API 或外部库如 Async.js 等方法可以显著改进您的异步代码。我们还需要记住，像`scroll`/`touch`/`mousemove`这样的某些事件，虽然被频繁触发，但频繁调用订阅的监听器可能会造成不必要的 CPU 负载。我们可以使用去抖和节流技术来避免这些问题。

通过学习异步编程的基础，我们可以编写非阻塞应用程序。在第六章，大规模 JavaScript 应用程序架构，我们将讨论如何使我们的应用程序可扩展，并总体上提高可维护性。


# 第六章：大型 JavaScript 应用程序架构

任何有经验的程序员都会努力使代码具有可重用性和可维护性。在这里，我们遵循面向对象编程的原则，如封装、抽象、继承、组合和多态。除了这些基本原则之外，我们还遵循 Robert C. Martin 定义的面向对象编程和设计的基本原则，即著名的**SOLID**原则([`en.wikipedia.org/wiki/SOLID_(object-oriented_design)`](https://en.wikipedia.org/wiki/SOLID_(object-oriented_design)))。在代码审查过程中，如果我们遇到任何这些原则的违反，都会被视为代码异味，并导致重构。我们每天在开发中解决的核心任务，通常都是我们一次又一次遇到的问题。在本章中，我们将介绍 JavaScript 开发中最常见的通用架构解决方案和概念：

+   JavaScript 中的设计模式

+   使用 JavaScript MV* 框架了解 JavaScript 中的关注分离

# JavaScript 中的设计模式

抽象的万无一失的解决方案早已为人所知，通常被称为**设计模式**。编程中的最初的 23 个设计模式首次收集在 1995 年出版的*Erich Gamma*、*Richard Helm*、*Ralph Johnson*和*John Vlissides*(*GoF*)合著的《设计模式：可复用面向对象软件的元素》一书中。这些模式与特定的编程语言无关。尽管如此，*Addy Osmani*在他的在线书籍《学习 JavaScript 设计模式》([`addyosmani.com/resources/essentialjsdesignpatterns/book/`](http://addyosmani.com/resources/essentialjsdesignpatterns/book/))中展示了如何实现一些 GoF 的模式，特别是在 JavaScript 中。

在这里，我们不会重复他的工作；相反，我们将研究如何组合这些模式。JavaScript 开发中的一个常见问题是在动态创建的对象之间的通信。例如，我们有一个对象，并需要从对象`foo`调用对象`bar`的`baz`方法。然而，我们无法知道`bar`是否已经可用。GoF 的模式中介者鼓励我们创建一个用于代理其他对象之间通信的对象。因此，通过避免对象之间的直接交互，我们促进了松耦合。在我们的案例中，尽管调用`bar.baz`，但我们告知中介者我们的意图。中介者在`bar`可用时会进行调用：

```js
"use strict";

class EventEmitter {
  /** Initialize */
  constructor() {
    /**
    * @access private
    * @type {EventHandler[]}
    */
   this.handlers = [];
  }
 /**
  * Subscribe a cb handler for a given event in the object scope
  * @param {String} ev
  * @param {Function} cb
  * @param {Object} [context]
  * @returns {EventEmitter}
  */
  on( ev, cb, context ){
     this.handlers.push({
       event: ev,
       callback: cb,
       context: context
     });
     return this;
  }
/**
  * Emit a given event in the object
  * @param {String} ev
  * @param {...*} [arg]
  * @returns {EventEmitter}
  */
  trigger( ev, ...args ) {
    this.handlers.forEach(function( evObj ){
     if ( evObj.event !== ev || !evObj.callback.apply ) {
       return;
     }
     evObj.callback.apply( evObj.context || this, args );
   }, this );
   return this;
  }
}

window.mediator = new EventEmitter();
```

在这里，我们使用了 ES6 语法，它非常适合描述代码设计。借助 ES6，意图可以简洁明了地表达，而在 JavaScript 的 ES5 及更早版本中，要达到同样的效果需要编写额外的代码行。

在前面的示例中，我们通过实例化`EventEmitter`类创建了一个中介者对象。`EventEmitter`实现了一种称为 PubSub 的消息模式。这种模式描述了一种消息交换，其中一个对象向另一个对象发送事件，第二个对象调用订阅了该事件的手动函数（如果有的话）。换句话说，如果我们为`foo`对象的`myevent`中介者事件（`mediator.on`）订阅一个处理器函数，我们就可以通过在中介者上发布`myevent`事件来调用`foo`的处理器（`mediator.trigger`）。让我们看一个例子。我们的虚构应用程序是本地化的。它从登录屏幕开始。当用户登录时，屏幕会跳转到带有新闻的仪表板。用户可以在任意屏幕上更改语言。然而，在第一阶段，新闻视图对象甚至还没有被创建，而在第二阶段，登录视图对象已经被销毁。但是，如果我们使用中介者，我们可以触发`translate`事件，所有可用的订阅者都将收到消息：

```js
class News {
  /** Initialize */
  constructor(){
    mediator.on( "translate", this.update, this );
  }
  /** @param {String} lang */
  update( lang ){
    // fetch news from remote host for a given lang
    console.log( "News loaded for", lang );
  }
}

class Language {
  /** @param {String} lang */
  change( lang ) {
    mediator.trigger( "translate", lang );
  }
}

let language = new Language();
new News()
language.change( "de" );
```

每当用户更改语言(`language.change`)时，相应的事件通过中介者广播出去。当 news 实例可用时，它会调用接收事件负载的`update`方法。在实际应用中，这个实例将为给定语言加载新闻并更新视图。

那么我们取得了什么成果呢？当我们使用中介者和基于事件驱动的方法（PubSub）时，我们的对象/模块是松耦合的，因此，整体架构更能接受需求变化。此外，我们在单元测试中获得了更多的灵活性。

在撰写这本书的时候，没有任何浏览器提供对 ES6 类语句的本地支持。然而，你可以使用 Babel.js 运行时（[`babeljs.io/docs/usage/browser/`](https://babeljs.io/docs/usage/browser/)）或转译来运行给定的代码。

当应用程序增长，我们处理的事件太多时，将事件处理封装到一个单独的消息总线对象中是有意义的。这时，`Facade`模式就会浮现在脑海中，它为其他接口定义了一个统一的高层次接口：

```js
class Facade {
  constructor(){
    mediator.on( "show-dashboard", function(){
      this.dashboard.show()
      this.userPanel.remove();
    }, this )
    .on( "show-userpanel", function(a){
      this.dashboard.hide()
      this.userPanel = new UserPanel( this.user );
    }, this )
    .on( "authorized", function( user ){
      this.user = user;
      this.topBar = new TopBar( user.name );
      this.dashboard = new Dashboard( user.lang );
      this.mainMenu = new MainMenu( user.lang );
    }, this )
    .on( "logout", function(){
      this.userPanel.remove();
      this.topBar.remove();
      this.dashboard.remove();
      this.mainMenu.remove();
      this.login = new Login();
    }, this );
  }
}
```

在初始化`Facade`类之后，我们可以通过在中介者上触发事件来启动一个涉及多个模块的复杂流程。这种方式将行为逻辑封装到一个专门的物体中；这使得代码更具可读性，整个系统更容易维护。

# 理解 JavaScript 中的关注点分离

编写 JavaScript（尤其是客户端）时，一个主要的挑战是避免*意大利面条代码*，在这种代码中，同一个模块渲染用户视图，处理用户交互，还做业务逻辑。这样的模块可能会迅速成长为一个源文件怪物，开发者在其中迷失方向，而不是发现问题并解决问题。

被称为**模型-视图-控制器**（**MVC**）的编程范式将应用程序功能分为不同的层次，如表示层、数据层和用户输入层。简而言之，MVC 意味着用户与控制器模块中的视图交互，控制器模块操作模型，模型更新视图。在 JavaScript 中，控制器通常是一个观察者，它监听 UI 事件。用户点击一个按钮，事件被触发，控制器处理相应的模型。例如，控制器请求模型将提交的数据发送到服务器。视图得知模型状态变化，并相应地作出反应，比如说它显示一条消息，“数据已保存”。以下图片展示了 MVC 模式中组件的协作：

![理解 JavaScript 中关注分离的原理](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-ulk/img/00013.jpeg)

正如你所见，我们可以将所有用户输入处理器封装在单个模块（这里指的是**控制器**）中，我们可以将遵循领域驱动设计实践的数据层抽象为模型模块。最终，我们有一个负责更新 UI 的视图模块。所以，模型对组件的表示（HTML，CSS）一无所知，也不知道 DOM 事件——这只是纯粹的数据及其操作。控制器只知道视图的事件和视图 API。最后，视图不知道模型和控制器，但暴露出它的 API 并发送事件。因此，我们得到了一个易于维护和测试的高效架构。

然而，在由 JavaScript 构建的 UI 情况下，将视图逻辑和控制器逻辑分开并不那么容易。这里我们有了 MVC 的衍生版本：**MVP**和**MVVM.MVP**。

在**MVP**模式中的**P**代表**Presenter**，它负责处理用户请求。Presenter 监听视图事件，检索数据，操作数据，并使用视图 API 更新展示。Presenter 可以与模型交互以持久化数据。正如您将在以下图表中看到的，Presenter 就像一个经理，它接收请求，使用可用资源处理它，并指导视图进行更改。下面的图片显示了 MVP 模式中组件的协作：

![理解 JavaScript 中关注分离的原理](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-ulk/img/00014.jpeg)

MVP 相比于 MVC 提供了更好的可测试性和关注分离。您可以在[`codepen.io/dsheiko/pen/WQymbG`](http://codepen.io/dsheiko/pen/WQymbG)找到一个实现 MVP 的`TODO`应用的示例。

## MVVM

被动的 MVP 观点主要涉及数据绑定和 UI 事件的代理。实际上，这些都是我们可以抽象的。在**模型-视图-视图模型**（**MVVM**）方法中的视图可能根本不需要任何 JavaScript。通常，视图是使用视图模型知道的指令扩展的 HTML。模型表示特定领域的数据并暴露相应的诸如验证的方法。视图模型是视图和模型之间的中间人。它将模型的数据对象转换为视图所需的格式，例如，当模型属性包含原始日期时间时，视图模型将其转换为视图中所期望的格式如`2016 年 1 月 1 日 00:01`。下面的图片显示了 MVVM 模式中组件的协作：

![MVVM](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/js-ulk/img/00015.jpeg)

MVVM 模式的优势在于命令式和声明式编程两者之间。它可能通过将大部分通用视图逻辑抽象到一个公共绑定模块中来大大减少开发时间。随着像 Knockout，Angular 和 Meteor 这样的流行 JavaScript 框架的出现，这个模式得到了推动。你可以在[`msdn.microsoft.com/en-us/magazine/hh297451.aspx`](https://msdn.microsoft.com/en-us/magazine/hh297451.aspx)找到基于 MVVM 模式的 RSS 阅读器应用程序的示例。

# 使用 JavaScript MV* 框架

当你开始一个新的可扩展的网页应用时，你必须决定是否使用框架。现在很难找到任何不是建立在框架之上的大型项目。然而，使用框架也有缺点；只需看看**零框架宣言**（[`bitworking.org/news/2014/05/zero_framework_manifesto`](http://bitworking.org/news/2014/05/zero_framework_manifesto)）。然而，如果你决定支持框架，那么你将面临一个选择困境：选用哪一个。这确实不是一件易事。现在的 JavaScript 框架非常众多；只需看看 TodoMVC 提供的多样性([`todomvc.com`](http://todomvc.com))。很难一一审查它们，但我们可以简要地检查一些最受欢迎的框架。根据最近的调查（例如，[`ashleynolan.co.uk/blog/frontend-tooling-survey-2015-results`](http://ashleynolan.co.uk/blog/frontend-tooling-survey-2015-results)），目前最流行的是 Angular，React 和 Backbone。这三个给出了非常不同的开发范式。所以它们适合用来概述 JavaScript 框架的一般情况。

## 后端

Backbone ([`backbonejs.org`](http://backbonejs.org)) 非常轻量级且易于入门。这是唯一一个你可以在相对较短的时间内掌握整个代码库的流行框架([`backbonejs.org/docs/backbone.html`](http://backbonejs.org/docs/backbone.html))。本质上，Backbone 为你提供了一致性的抽象，除此之外什么也没有。总的来说，我们将所有的 UI 相关逻辑封装到 `Backbone.View` 的子类型中。视图所需的所有数据，我们将其放入 `Backbone.Model` 或 `Backbone.Collection` 的派生类型中（当它是一个条目列表）。最后，我们通过 `Backbone.Route` 实现基于哈希的导航请求的路由。

让我们考虑一个例子。我们的虚构应用程序允许我们通过给定的电子邮件地址查找联系人。由于我们希望这个应用程序友好，所以期望在应用程序表单中输入时进行验证。为此，我们需要一点 HTML：

```js
<form data-bind="fooForm">
      <label for="email">Email:</label>
      <input id="email" name="email" required />
      <span class="error-msg" data-bind="errorMsg"></span>
      <button data-bind="submitBtn" type="submit">Submit</button>
  </form>
```

这里有一个输入控件，一个提交按钮，以及一个可能错误信息的容器。为了管理这些，我们将使用以下 `Backbone.View`：

**ContactSearchView.js**

```js
"use strict";
/** @class {ContactSearchView}  */
var ContactSearchView = Backbone.View.extend(/** @lends ContactSearchView.prototype */{
  events: {
    "submit": "onSubmit"
  },
  /** @constructs {ContactSearchView} */
  initialize: function() {
    this.$email = this.$el.find( "[name=email]" );
    this.$errorMsg = this.$el.find( "[data-bind=errorMsg]" );
    this.$submitBtn = this.$el.find( "[data-bind=submitBtn]" );
    this.bindUi();
  },
  /** Bind handlers */
  bindUi: function(){
    this.$email.on( "input", this.onChange.bind( this ) );
    this.model.on( "invalid", this.onInvalid.bind( this ) );
    this.model.on( "change", this.onValid.bind( this ) );
  },
  /** Handle input onchange event */
  onChange: function(){
    this.model.set({
      email: this.$email.val(),
      // Hack to force model running validation on repeating payloads
      "model:state": ( 1 + Math.random() ) * 0x10000
    }, { validate: true });
  },
  /** Handle model in invalid state */
  onInvalid: function(){
    var error = arguments[ 1 ];
    this.$errorMsg.text( error );
    this.$submitBtn.prop( "disabled", "disabled" );
  },
  /** Handle model in valid state */
  onValid: function(){
    this.$errorMsg.empty();
    this.$submitBtn.removeProp( "disabled" );
  },
  /** Handle form submit */
  onSubmit: function( e ){
    e.preventDefault();
    alert( "Looking up for " + this.model.get( "email") );
  }
});
```

在构造函数（`initialize` 方法）中，我们将 HTML 的操作节点与视图的属性绑定，并订阅 UI 和模型事件的事件处理程序。然后，我们在 `submit` 表单和 `input` 表单上注册监听器方法。当我们输入时，第二个处理程序被调用，并更新模型。模型运行验证，根据结果，它以 `invalid` 或 `change` 模型事件作出响应。在 `invalid` 事件的情况下，视图显示错误信息，否则它被隐藏。

现在我们可以添加模型，如下所示：

**ContactSearchModel.js**

```js
 "use strict";
/** @class {ContactSearchModel}  */
var ContactSearchModel = Backbone.Model.extend(/** @lends ContactSearchModel.prototype */{
  /** @type {Object} */
  defaults: {
    email: ""
  },
  /**
   * Validate email
  * @param {String} email
  */
  isEmailValid: function( email ) {
    var pattern = /^[a-zA-Z0-9\!\#\$\%\&\'\*\+\-\/\=\?\^\_\`\{\|\}\~\.]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,4}$/g;
    return email.length && pattern.test( email );
  },
  /**
   * Validate model
  * @param {Map} attrs
  */
  validate: function( attrs ) {
    if ( !attrs.email ) {
      return "Email is required.";
    }
    if ( !this.isEmailValid( attrs.email ) ) {
      return "Invalid email address.";
    }
  }
});
```

这个模型在`defaults`属性中定义了领域数据，并提供了`validate`方法，当我们将模型设置或保存时会自动调用该方法。

现在我们可以把所有东西结合起来并初始化视图：

```js
<!DOCTYPE html>
<html>
  <script type="text/javascript" src="img/jquery.min.js"></script>
  <script type="text/javascript" src="img/underscore-min.js"></script>
  <script type="text/javascript" src="img/backbone-min.js"></script>
  <script type="text/javascript" src="img/ContactSearchView.js"></script>
  <script type="text/javascript" src="img/ContactSearchModel.js"></script>
  <style>
    fieldset { border: 0; }
    .error-msg{ color: red; }
  </style>
  <body>
   <form data-bind="fooForm">
    <fieldset>
      <label for="email">Email:</label>
      <input id="email" name="email" required />
      <span class="error-msg" data-bind="errorMsg"></span>
    </fieldset>
    <fieldset>
      <button data-bind="submitBtn" type="submit">Submit</button>
    </fieldset>
  </form>
<script>

// Render foo view
 new ContactSearchView({
   el: $( "[data-bind=fooForm]" ),
   model: new ContactSearchModel
 });

</script>
  </body>
</html> 
```

backbone 本身的大小令人惊讶地小（6.5 Kg 压缩），但是加上 jQuery 和 Underscore 的依赖关系，这使得整体捆绑包变得相当大。这两个依赖关系在过去至关重要，但现在值得怀疑——我们是否需要它们？因此，检查 **Exoskeleton** ([`exosjs.com/`](http://exosjs.com/)) 项目是有意义的，这是一个经过优化的 Backbone 版本，无需依赖关系即可完美工作。

## 安吉拉

Angular ([`Angular.org`](http://Angular.org)) 现在似乎是世界上最受欢迎的 JavaScript 框架。它由谷歌支持，被认为是一个解决你大部分日常任务的框架。特别是，Angular 有一个名为双向绑定的特性，这意味着 UI 变化传播到绑定的模型，反之亦然，模型变化（例如，通过 XHR）更新 UI。

在 AngularJS 中，我们直接在 HTML 中定义行为，使用指令。指令是自定义的元素和属性，它们假设与 Web 组件类似的 UI 逻辑。实际上，你可以在 AngularJS 中创建功能性小部件，而不需要写一行 JavaScript 代码。AngularJS 中的模型是简单数据容器，与 Backbone 不同，它们没有与外部来源的连接。当我们需要读取或写入数据时，我们使用服务。任何数据发送到视图时，我们可以使用过滤器来格式化输出。该框架利用依赖注入（DI）模式，允许将核心组件作为依赖项相互注入。这使得模块更容易满足需求变化和单元测试。让我们在实践中看看这个：

```js
<!DOCTYPE html>
<html>
  <script src="img/angular.min.js"></script>
  <style>
    fieldset { border: 0; }
    .error-msg{ color: red; }
  </style>
  <body>
   <form ng-app="contactSearch" name="csForm" ng-submit="submit()" ng-controller="csController">
    <fieldset>
      <label for="email">Email:</label>
      <input id="email" name="email" ng-model="email" required
          ng-pattern="/^[a-zA-Z0-9\!\#\$\%\&\'\*\+\-\/\=\?\^\_\`\{\|\}\~\.]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,4}$/"  />
      <span class="error-msg" ng-show="csForm.email.$dirty && csForm.email.$invalid">
        <span ng-show="csForm.email.$error.required">Email is required.</span>
        <span ng-show="csForm.email.$error.pattern">Invalid email address.</span>
      </span>
    </fieldset>
    <fieldset>
      <button type="submit" ng-disabled="csForm.email.$dirty && csForm.email.$invalid">Submit</button>
    </fieldset>
  </form>
<script>
  "use strict";
  angular.module( "contactSearch", [] ).controller( "csController", [ "$scope", function ( $scope ){
    $scope.email = "";
    $scope.submit = function() {
      alert( "Looking up for " + $scope.email );
    };
  }]);
</script>
  </body>
</html>
```

在这个例子中，我们声明了一个输入字段，并将其绑定到一个模型邮箱上（`ng-model` 指令）。表单验证的工作方式与 HTML5 表单相同：如果我们声明了一个输入类型为邮箱的输入字段并进行相应的验证。这里我们使用默认的文本类型，并使用 `ng-pattern`（类似于 HTML5 的 pattern）属性来设置与 Backbone 案例相同的邮箱验证规则。接下来，我们依靠 `ng-show` 指令在输入状态为空（`csForm.email.$dirty`）或无效（`csForm.email.$invalid`）时显示错误信息块。在这种情况下，提交按钮相反是隐藏的。使用 `ng-controller` 和 `ng-submit` 指令，我们将 `csController` 控制器和 `on-submit` 处理程序绑定到表单上。在 `csController` 的主体（JavaScript）中，`$scope.submit` 期望有一个处理表单提交事件的事件处理函数。

正如你所看到的，与 Angular 相比，实现相同任务所需的总代码量要少得多。然而，我们必须接受一个事实，那就是将应用逻辑保持在 HTML 中确实使得代码难以阅读。

此外，Angular 每个指令都会订阅许多观察者（意图处理器、自动脏检查等），在包含众多交互元素的页面中，这会使其变得缓慢且资源消耗大。如果你想调整你的应用性能，你最好去学习 Angular 的源代码，这对于有 ~11.2K 行代码（版本 1.4.6）来说将是一个具有挑战性的任务。

## React

React ([`facebook.github.io`](https://facebook.github.io)) 是 Facebook 的一个项目，它不是一个框架，而是一个库。React 独特的 approach 暗示了基于组件的应用。本质上，React 通过所谓的虚拟 DOM 来定义组件的视图，这使得 UI 渲染和更新出奇地快。由于 React 专注于视图，因此它包含了一个模板引擎。可选地，React 组件可以用 JavaScript 的一个子集 JSX 来编写，其中你可以将 HTML 模板放在 JavaScript 中。JSX 可以根据以下示例动态解析，或者可以预编译。由于 React 只处理视图，并且不假设其他关注点，因此与其它框架一起使用是有意义的。因此，React 可以插入到框架中（例如，作为 Angular 的指令或 Backbone 的视图）。

在这次实现联系人搜索应用的过程中，我们将使用 React 来控制我们的示例视图，通过将其拆分为两个组件（`FormView` 和 `EmailView`）。第一个组件定义了搜索表单的视图：

```js
   /** @class {FormView}  */
var FormView = React.createClass({
  /** Create an initial state with the model  */
  getInitialState: function () {
    return {
      email: new EmailModel()
    };
  },
  /**
   * Update state on input change event
   * @param {String} value - changed value of the input
   */
  onChange: function( value ){
    this.state.email.set( "email", value );
    this.forceUpdate();
  },
  /** Handle form submit */
  onSubmit: function( e ){
    e.preventDefault();
    alert( "Looking up for " + this.state.email.get( "email") );
  },
  /** Render form */
  render: function () {
    return <form onSubmit={this.onSubmit}>
      <fieldset>
      <label htmlFor="email">Email:</label>
      <EmailView model={this.state.email} onChange={this.onChange} />
      </fieldset>
      <fieldset>
        <button data-bind="submitBtn" type="submit">Submit</button>
      </fieldset>
    </form>;
  }
});
```

在 `render` 方法中，我们使用 JSX 表示法声明了组件的视图。这使得操作虚拟 DOM 变得容易得多。与 Angular 类似，我们可以在 HTML 中直接引用组件作用域。因此，我们可以通过引用 `onSubmit` 和 `onChange` 属性中的相应处理程序来订阅表单提交事件和输入变更事件。由于 React 没有内置模型，我们复用了在探索 Backbone 时创建的 `ContactSearchModel` 模型。

你可能会注意到 JSX 中有一个 `EmailView` 自定义标签。这就是我们引用我们的第二个组件的方式，它代表了一个电子邮件输入控件：

```js
    /** @class {EmailView}  */
var EmailView = React.createClass({
  /**
   * Delegate input on-changed event to the from view
   * @param {Event} e
   */
  onChanged: function( e ){
    this.props.onChange( e.target.value );
  },
  /** Render input */
  render: function () {
    var model = this.props.model;
    return <span>
      <input id="email" type="text" value={model.email} onChange={this.onChanged} />      
      <span className="error-msg" data-bind="errorMsg"> {model.isValid() ? "" : model.validationError}</span>
    </span>;
  }
});
```

在这里，我们将电子邮件输入绑定到模型，将错误消息容器绑定到模型状态。我们还把输入的 `onChange` 事件传递给了父组件。

好了，现在我们可以将组件添加到 HTML 中并渲染表单：

```js
<!DOCTYPE html>
<html>
<head>
  <script src="img/react.js"></script>
  <script src="img/JSXTransformer.js"></script>
  <script type="text/javascript" src="img/underscore-min.js"></script>
  <script type="text/javascript" src="img/backbone-min.js"></script>
  <script type="text/javascript" src="img/ContactSearchModel.js"></script>
  <style>
    fieldset { border: 0; }
    .error-msg{ color: red; }
  </style>
</head>
<body>
  <div data-bind="app"></div>
<script type="text/jsx">
  /** @jsx React.DOM */

// Please insert here both components
// FormView and EmailView

// render app
React.render(
  <FormView />,
  document.querySelector( "[data-bind=app]" )
);
</script>
</body>
</html>
```

我们通过相应的自定义元素来在模板中引用组件，比如 web-components。不要让自己混淆于它们的相似性，React 组件是从浏览器中抽象出来的，而 web-components 类似于浏览器原生组件。React 的核心概念是虚拟 DOM 允许我们避免不必要的 DOM reflow 周期，这使得该库适用于高性能应用。React 在服务器上使用 Node.js 渲染静态页面非常出色。因此，我们可以在服务器和客户端之间复用应用程序组件。

# 总结

编写可维护的代码是一门艺术。或许在提供这方面指导方面最好的书籍是*Robert C. Martin*所著的《Clean Code: A Handbook of Agile Software Craftsmanship》。这本书讲述了如何命名函数、方法、类，注释，代码格式化，当然还有面向对象编程（OOP）和 SOLID 原则的正确使用。然而，当我们重复使用本书或设计模式系列中描述的解决方案时，我们必须将它们翻译成 JavaScript，这可能由于语言的特性而具有挑战性。在更高的层次上，我们必须将代码划分为表示层、业务逻辑层、数据访问层和持久化层，其中每一组代码都关注一个问题，并且与其他代码松耦合。在这里，我们可以选择一种方法。在 JavaScript 世界中，这通常是 MVC（MVP 或 MVVM 或其他）的派生。考虑到这一点，一个体面的编程设计需要大量的抽象。如今，我们可以使用许多框架。它们提供了多样的编程范式。
