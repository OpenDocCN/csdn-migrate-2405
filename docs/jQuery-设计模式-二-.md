# jQuery 设计模式（二）

> 原文：[`zh.annas-archive.org/md5/9DBFD51895CA93BE96AC02124FF5B7E1`](https://zh.annas-archive.org/md5/9DBFD51895CA93BE96AC02124FF5B7E1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：门面模式

在这一章中，我们将展示**门面模式**，一种结构设计模式，试图定义开发人员应如何在其代码中创建抽象的统一方式。最初，我们将使用此模式来包装复杂的 API，并公开专注于我们应用程序需求的简化 API。我们将看到 jQuery 如何在其实现中采用此模式的概念，它如何将是 Web 开发者工具箱中的重要组成部分的复杂实现封装成易于使用的 API，以及这对其广泛采用的关键作用。

在这一章中，我们将：

+   介绍门面模式

+   记录其关键概念和优势

+   看看 jQuery 在其实现中如何使用它

+   编写一个示例实现，其中门面被用于完全抽象和解耦第三方库

# 介绍门面模式

门面模式是一种处理如何创建实现各部分的抽象的结构性软件设计模式。门面模式的关键概念是抽象出现有实现，并提供一个简化的 API，更好地匹配开发应用程序的用例。根据大多数描述此模式的计算机科学参考书目，门面最常见的实现方式是作为一个专门的类，用于将应用程序的实现分割成更小的代码片段，同时提供一个完全隐藏封装的复杂性的接口。在 Web 开发世界中，还常常使用普通对象或函数来实现门面，利用 JavaScript 将函数视为对象的方式。

在具有模块化结构的应用程序中，例如上一章的示例，通常还会将门面实现为具有自己命名空间的单独模块。此外，对于具有非常复杂部分的较大实现，也可以采用多级门面的方法。再次，门面将作为模块和子模块实现，顶层门面将编排其子模块的方法，并提供一个完全隐藏整个子系统复杂性的 API。

# 此模式的优势

大多数情况下，门面模式被采用于具有相对高复杂度并在应用程序的多个地方使用的实现部分，其中大量的代码可以被简单调用已创建的门面替换，这不仅减少了代码重复，还有助于增加实现的可读性。由于门面方法通常以它们封装的高级应用概念命名，所以产生的代码也更易于理解。门面通过其方便的方法提供的简化 API，导致实现更易于使用、理解，也更易于编写单元测试。

![这种模式的好处](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00020.jpeg)

此外，将复杂实现抽象化为 Facades 在需要改变实现的业务逻辑时证明了其有用性。如果 Facade 具有良好设计的 API，并对未来需求进行了预测，这些更改通常只需要修改 Facade 的代码，而不会影响应用程序的其余实现，并遵循**关注点分离**原则。

以同样的方式，使用 Facades 将第三方库的 API 抽象化以更好地匹配每个应用程序的需求，提供了我们的代码与所用库之间的一定程度解耦。如果第三方库更改其 API 或需要用另一个替换，应用程序的不同模块不需要重新编写，因为实现更改将被限制在包装 Facade 上。在这种情况下，只需要使用新库 API 提供等效实现，同时保持 Facade 的 API 不变即可。

![这种模式的好处](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00021.jpeg)

作为编排方法调用并为特定用例使用明智默认值的示例，请看以下示例实现：

```js
function do (x, y) {
  var z = y - x / 2;
  var yy = Math.pow(y, 2);
  var b = 3 * Math.random(); // add some randomness to the result
  var i = 0; // for this case
  return LibraryA.doingMethod(x, z, i, yy, b);
}
```

# 它是如何被 jQuery 接受的

jQuery 实现的非常大的部分专门用于为不同的 JavaScript API 已经允许我们实现的事物提供更简单、更短、更方便的方法，但需要更多的代码行数和工作量。通过查看 jQuery 提供的 API，我们可以区分出一些相关方法的组。这种分组也可以在源代码结构中看到，将相关 API 的方法放置在彼此附近。

即使单词**Facade**在 jQuery 的源代码中没有出现，但通过观察相关方法在公开的 jQuery 对象上的定义方式，可以看出这种模式的使用。大多数情况下，形成一组的相关方法被实现并定义为**对象字面量**的属性，然后通过一次调用`$.extend()`或`$.fn.extend()`方法附加到 jQuery 对象上。你可能还记得，从本章开始时，这几乎与计算机科学常用来描述如何实现 Facade 的方式完全匹配，唯一的区别在于，在 JavaScript 中，我们可以创建一个普通对象，而不需要首先定义一个类。因此，jQuery 本身可以被视为一组 Facades，其中每个 Facade 都通过提供便利方法的 API 独立地为库增添了巨大价值。

### 注意

欲了解更多关于`$.extend()`和`$.fn.extend()`的信息，您可以访问[`api.jquery.com/jQuery.extend/`](http://api.jquery.com/jQuery.extend/)和[`api.jquery.com/jQuery.fn.extend/`](http://api.jquery.com/jQuery.fn.extend/)。

jQuery 实现中一些承担关键角色并对其采用起到至关重要作用的抽象 API 组如下：

+   DOM 遍历 API

+   AJAX API

+   DOM 操作 API

+   特效 API

此外，一个很好的例子是 jQuery 的事件 API，它提供了各种方便的方法，用于最常见的使用情况，比相应的纯 JavaScript API 更易于使用。

## jQuery DOM 遍历 API

在 jQuery 发布时，网页开发人员只能使用非常有限的`getElementById()`和`getElementsByTagName()`方法来定位页面的特定 DOM 元素，因为其他方法，如`getElementsByClassName()`，并未得到现有浏览器的广泛支持。jQuery 团队意识到，如果有一个简单的 API 可以轻松进行这样的 DOM 遍历，它能够在所有浏览器上以相同的方式工作，像熟悉的**CSS 选择器**一样有效，并且尽最大努力使这样的实现成为现实。

这一努力的成果是如今著名的 jQuery DOM 遍历 API，通过`$()`函数公开，它在**Level 2 Selector API**的`querySelectorAll()`方法的标准化中扮演了重要角色。其底层实现使用**DOM API**提供的方法，在 jQuery v2.2.0 中约有 2,135 行代码，而在需要支持旧版浏览器的 v1.x 版本中甚至更多。正如我们在本章中所看到的，由于其复杂性，这一实现现在已成为一个名为**Sizzle**的独立项目的一部分。

### 注

有关 Sizzle 和`querySelectorAll()`方法的更多信息，请访问[`github.com/jquery/sizzle`](https://github.com/jquery/sizzle)和[`developer.mozilla.org/en-US/docs/Web/API/document/querySelectorAll`](https://developer.mozilla.org/en-US/docs/Web/API/document/querySelectorAll)。

尽管其实现复杂，所公开的 API 非常易于使用，主要使用简单的 CSS 选择器作为字符串参数，这使得它成为一个很好的例子，说明外观模式可以完全隐藏其内部工作的复杂性并公开一个方便的 API。由于 Sizzle 的 API 仍然相当复杂，jQuery 库实际上使用自己的 API 包装它，作为额外的 Facade 级别：

```js
// Line 733
function Sizzle( selector, context, results, seed ) { /* ... */ }

// Line 2678
jQuery.find = Sizzle;
```

jQuery 库首先保留 Sizzle 对内部`jQuery.find()`方法的引用，然后使用它来实现其所有公开的 DOM 遍历方法，这些方法适用于像`$.fn.find()`这样的复合对象：

```js
// Line 2769
jQuery.fn.extend( { 
  find: function( selector ) { 
    /* 15 lines of code */ 
    for ( i = 0; i < len; i++ ) { 
 jQuery.find( selector, self[ i ], ret ); 
    } 
    /* 3 lines of code */
    return ret; 
  } 
} );
```

最后，著名的`$()`函数实际上可以以多种方式调用，但即使使用 CSS 选择器作为字符串参数调用时，它实际上有一个额外的隐藏复杂性：

```js
// Line 71
jQuery = function( selector, context ) { 
  return new jQuery.fn.init( selector, context ); 
}; 

// Line 2825
rquickExpr = /^(?:\s*(<[\w\W]+>)[^>]*|#([\w-]*))$/, 
// Line 2735 
init = jQuery.fn.init = function( selector, context, root ) { 
  /* 12 lines of code */ 
 if ( typeof selector === "string" ) { 
    if (/* ... */) { 
      /* 3 lines of code */ 
    } else { 
      match = rquickExpr.exec( selector ); 
    } 

    // Match html or make sure no context is specified for #id 
    if ( match && ( match[ 1 ] || !context ) ) { 
      if ( match[1] ) {
      /* 27 lines of code */ 
      // HANDLE: $(#id) 
      } else { 
 elem = document.getElementById( match[ 2 ] ); 

        // Support: Blackberry 4.6 
        // gEBID returns nodes no longer in the document (#6963) 
        if ( elem && elem.parentNode ) { 
          // Inject the element directly into the jQuery object 
          this.length = 1; 
          this[ 0 ] = elem; 
        } 

        this.context = document; 
        this.selector = selector; 
        return this; 
      } 

    // HANDLE: $(expr, $(...)) 
    } else if ( !context || context.jquery ) { 
 return ( context || root ).find( selector ); 

    // HANDLE: $(expr, context) 
    // (which is just equivalent to: $(context).find(expr) 
    } else { 
 return this.constructor( context ).find( selector ); 
    } 
  } /* else ... 21 lines of code */
};
```

如您所见，在上述代码中，`$()`实际上是使用`$.fn.init()`创建一个新对象。它不仅仅是`$.fn.find()`或`jQuery.find()`的入口点，而是一个隐藏了一层优化的门面。具体来说，它通过直接调用`getElementById()`方法，使得 jQuery 在使用简单的 ID 选择器时，通过避免调用`$.fn.find()`和 Sizzle，而变得更快。

## 属性访问和操作 API

遵循门面模式原则的另一个非常有趣的抽象，可以在 jQuery 源代码中找到，即`$.fn.prop()`方法。像`$.fn.attr()`、`$.fn.val()`、`$.fn.text()`和`$.fn.html()`一样，它属于一系列既是相应主题的获取器又是设置器的方法。该方法的执行模式的区分是通过检查在调用期间传递的参数数量来完成的。这种方便的 API 让我们只需记住更少的方法签名，并且使得设置器只需要一个额外的参数来进行区分。例如，`$('#myCheckBox').prop('checked')`将根据所选复选框的状态返回 true 或 false。另一方面，`$('#myCheckBox').prop('checked', true);`将对该复选框进行程序化的选中。在同样的概念中，`$('button').prop('disabled', true);`将禁用页面上所有`<button>`元素。

`$.fn.prop()`方法执行 jQuery 复合对象处理，但 Facade 的实际实现是内部的`jQuery.prop()`方法。为 Facade 的实现增加复杂性的一个额外问题是，一些 HTML 属性在 DOM 元素上具有与之对应的不同标识符：

```js
jQuery.extend( { 

  prop: function( elem, name, value ) { 
    /* 8 lies of code */
    if ( nType !== 1 || !jQuery.isXMLDoc( elem ) ) {
      // Fix name and attach hooks 
 name = jQuery.propFix[ name ] || name; 
 hooks = jQuery.propHooks[ name ]; 
    } 

 if ( value !== undefined ) { 
      if ( hooks && "set" in hooks &&
        ( ret = hooks.set( elem, value, name ) ) !== undefined ) {
        return ret;
      }
 return ( elem[ name ] = value );
    }

    if ( hooks && "get" in hooks &&( ret = hooks.get( elem, name ) ) !== null ) {
      return ret;
    }
 return elem[ name ];
  }, 

  propHooks: { 
    tabIndex: { 
      get: function( elem ) { 
        var tabindex = jQuery.find.attr( elem, "tabindex" );
        return tabindex ?parseInt( tabindex, 10 ) : /*...*/;
      }
    }
  },

  propFix: {
    "for": "htmlFor",
    "class": "className"
  } 
} );
```

第一个突出显示的代码区域通过使用`propFix`和`propHooks`对象来高效地解决属性到属性标识符不匹配的问题。`propFix`对象就像一个简单的字典，用于匹配标识符，而`propHooks`对象则保存一个函数，以一种不那么硬编码的方式进行匹配，通过编程化的测试。这是一个通用的实现，可以通过向这两个对象添加额外的属性来轻松扩展。

其余突出显示的区域负责方法的获取器/设置器模式。总体实现是执行以下任务：

+   检查是否将值作为参数传递，并且如果属性发现分配成功，则执行分配并返回该值。

+   或者，如果没有传递值，则返回可检索的请求属性的值。

# 在我们的应用程序中使用门面

为了演示外观如何被用来封装复杂性，帮助我们执行关注点分离原则，并将第三方库的 API 抽象成更方便的应用程序中心化方法，我们将演示一个非常简单的抽奖应用程序。我们的“元素抽奖”应用程序将使用唯一 ID 填充其容器，并包含随机数的一些抽奖票元素。

![在我们的应用程序中使用外观](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00022.jpeg)

中奖号码将通过随机选择抽奖元素之一，基于创建的唯一 ID 中的随机索引来挑选。然后宣布获胜号码是所选元素的数字内容。让我们看看我们应用程序的模块：

```js
(function() { 
  window.elementLottery = window.elementLottery || {}; 

  var elementIDs; 
  var $lottery; 
  var ticketCount = 30; 

  elementLottery.init = function() { 
    elementIDs = []; 
    $lottery = $('#lottery').empty(); 
    elementLottery.add(ticketCount); 
    $('#lotteryTicketButton').on('click', elementLottery.pick); 
  }; 

  elementLottery.add = function(n) { 
    for (var i = 0; i < n; i++) { 
      var id = this.uidProvider.get(); 
      elementIDs.push(id); 
      $lottery.append(this.ticket.createHtml(id)); 
    } 
  }; 

  elementLottery.pick = function() { 
    var index = Math.floor(Math.random() * elementIDs.length); 
    var result = $lottery.find('#' + elementIDs[index]).text(); 
    alert(result); 
    return result; 
  }; 

  $(document).ready(elementLottery.init);
})(); 
```

我们应用程序的主要 `elementLottery` 模块会在页面完全加载后立即初始化。`add` 方法用于向抽奖容器元素添加票证。它使用 `uidProvider` 子模块为票证元素生成唯一标识符，并在 `elementIDs` 数组上跟踪它们，使用票证子模块构造适当的 HTML 代码，并最终将元素附加到抽奖中。`pick` 方法用于通过随机选择生成的标识符之一来随机选择获胜者票证，检索具有该 ID 的页面元素，并在警报框中显示其内容作为获胜结果。`pick` 方法是在初始化阶段添加观察者的按钮点击时触发的：

```js
(function() { 
  elementLottery.ticket = elementLottery.ticket || {}; 

  elementLottery.ticket.createHtml = function(id) { 
    var ticketNumber = Math.floor(Math.random() * 1000 * 10); 
    return '<div id="' + id + '" class="ticket">' + ticketNumber + '</div>'; 
  }; 
})(); 

(function() { 
  elementLottery.uidProvider = elementLottery.uidProvider || {}; 

  elementLottery.uidProvider.get = function() { 
    return 'Lot' + simpleguid.getNext(); 
  }; 
})(); 
```

`ticket` 子模块充当一个外观，具有一个用于封装随机数生成和将用作票证的 HTML 代码的单个方法。另一方面，`uidProvide` 子模块是一个提供单个 get 方法的外观，封装了我们在前几章节中看到的 `simpleguid` 模块的使用方式。因此，我们可以轻松更改用于生成唯一标识符的库，而我们需要修改现有实现的唯一位置将是 `uidProvide` 子模块。例如，让我们看看如果我们决定使用生成 128 位唯一标识符的精美 node-uuid 库，它会是什么样子：

```js
(function() { 
  elementLottery.uidProvider = elementLottery.uidProvider || {}; 

  elementLottery.uidProvider.get = function() { 
    return uuid.v4();
  }; 
})(); 
```

### 注意

关于 node-uui 库的更多信息，您可以访问 [`github.com/broofa/node-uuid`](https://github.com/broofa/node-uuid)。

# 摘要

在本章中，我们了解了外观实际上是什么。我们了解了其哲学以及统一定义代码抽象应该如何创建，以便其他开发人员能够轻松理解并重用它们。

从该模式的最简单用例开始，我们学习了如何使用 Facade 封装复杂的 API，并公开一个更简单的 API，专注于我们应用程序的需求，并更好地匹配其特定的用例。 我们还看到了 jQuery 如何在其实现中采用了这种模式的概念，以及为更基本的 web 开发技术（如 DOM 遍历）提供简单 API 如何对其广泛采用起到了至关重要的作用。

现在我们已经完成了对 Facade 模式如何用于解耦和抽象实现的介绍，我们可以继续下一章，在下一章中，我们将介绍 Builder 和 Factory 模式。 在下一章中，我们将学习如何使用这两种创建型设计模式来抽象生成和初始化新对象的过程，以满足特定用例，并分析它们的采用如何使我们的实现受益。


# 第六章：生成器和工厂模式

本章中，我们将展示生成器模式和工厂模式，这两种最常用的创建型设计模式之一。这两种设计模式彼此之间有一些相似之处，共享一些共同的目标，并致力于简化复杂结果的创建。我们将分析它们的采用对我们实现的好处，以及它们之间的区别。最后，我们将学习如何正确使用它们，并为我们实现的不同用例选择最合适的模式。

本章中，我们将：

+   介绍工厂模式

+   查看 jQuery 如何使用工厂模式

+   在 jQuery 应用程序中有一个工厂模式示例

+   介绍生成器模式

+   比较生成器模式和工厂模式

+   查看 jQuery 如何使用生成器模式

+   在 jQuery 应用程序中有一个生成器模式示例

# 介绍工厂模式

工厂模式是创建型模式组中的一部分，总体上描述了一种用于对象创建和初始化的通用方式。它通常实现为一个用于生成其他对象的对象或函数。根据大多数计算机科学资源，工厂模式的参考实现描述为一个提供返回新创建的对象的方法的类。返回的对象通常是特定类或子类的实例，或者它们公开一组特定的特性。

![介绍工厂模式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00023.jpeg)

工厂模式的关键概念是抽象出为特定目的创建和初始化对象或一组相关对象的方式。这种抽象的目的是避免将实现与特定类或每个对象实例需要创建和配置的方式耦合在一起。结果是一种按照关注点分离的概念来进行对象创建和初始化的实现。

结果的实现仅基于其算法或业务逻辑所需的对象方法和属性。这种方法可以通过遵循编程的概念而不是对象类的功能和功能来受益于实现的模块化和可扩展性。这使我们可以灵活地将所使用的类更改为任何其他公开相同功能的对象。

## 它是如何被 jQuery 采用的

正如我们在早期章节中已经注意到的那样，jQuery 的早期目标之一是提供一种在所有浏览器上都能够正常工作的解决方案。jQuery 1.12.x 版本系列专注于为老旧的 Internet Explorer 6（IE6）提供支持，同时保持与仅关注现代浏览器的较新版本 v2.2.x 相同的 API。

为了拥有类似的结构并最大化两个版本之间的公共代码，jQuery 团队试图在不同的实现层中抽象出大部分兼容性机制。这样的开发实践极大地提高了代码的可读性，并减少了主要实现的复杂性，将其封装成不同的较小的片段。

这个很好的例子是 jQuery 提供的与 AJAX 相关方法的实现。具体来说，在以下代码中，您可以找到它的一部分，就像在 jQuery 的 1.12.0 版本中找到的那样：

```js
// Create the request object 
// (This is still attached to ajaxSettings for backward compatibility) 
jQuery.ajaxSettings.xhr = window.ActiveXObject !== undefined ? 
  // Support: IE6-IE8
  function() { 

    // XHR cannot access local files, always use ActiveX for that case 
    if ( this.isLocal ) {
      return createActiveXHR();
    }
    // Support: IE 9-11
    if ( document.documentMode > 8 ) {
      return createStandardXHR();
    }
    // Support: IE<9
    return /^(get|post|head|put|delete|options)$/i.test( this.type ) && createStandardXHR() || createActiveXHR();

  } : 
  // For all other browsers, use the standard XMLHttpRequest object 
  createStandardXHR; 

// Functions to create xhrs 
function createStandardXHR() { 
  try { 
    return new window.XMLHttpRequest(); 
  } catch ( e ) {} 
} 

function createActiveXHR() { 
  try { 
    return new window.ActiveXObject( "Microsoft.XMLHTTP" ); 
  } catch ( e ) {} 
}
```

每次在 jQuery 上发出新的 AJAX 请求时，`jQuery.ajaxSettings.xhr`方法被用作一个工厂，根据当前浏览器的支持创建一个新的适当的 XHR 对象的实例。更详细地看，我们可以看到`jQuery.ajaxSettings.xhr`方法协调使用两个更小的工厂函数，每个函数负责特定的 AJAX 实现。此外，我们可以看到它实际上试图避免在每次调用时都运行兼容性测试，而是在适当时直接将其引用连接到较小的`createStandardXHR`工厂函数。

## 在我们的应用程序中使用工厂

作为工厂的一个示例用例，我们将创建一个数据驱动的表单，其中我们的用户将能够填写一些动态创建并插入到页面中的字段。我们将假设存在一个包含描述每个需要呈现的表单字段的对象的数组。我们的工厂方法将封装每个表单字段需要被构建的方式，并根据相关对象上定义的特征正确处理每个特定的情况。

![在我们的应用程序中使用工厂](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00024.jpeg)

这个页面的 HTML 代码非常简单：

```js
    <h1>Data Driven Form</h1> 

    <form></form> 

    <script type="text/javascript" src="img/jquery.js"></script> 
    <script type="text/javascript" src="img/datadrivenform.js"></script> 
```

它只包含一个`<h1>`元素，用于页面标题，以及一个空的`<form>`元素，用于承载生成的字段。至于使用的 CSS，我们只对`<button>`元素进行了样式化，与之前的章节中所做的方式相同。

至于应用程序的 JavaScript 实现，我们创建一个模块，并声明`dataDrivenForm`为这个示例的命名空间。这个模块将包含描述我们表单的数据，生成每个表单元素的 HTML 的工厂方法，当然还有将上述部分组合起来创建结果表单的初始化代码：

```js
(function() { 
  'use strict'; 

  window.dataDrivenForm = window.dataDrivenForm || {}; 

  dataDrivenForm.formElementHTMLFactory = function (type, name, title) { 
    if (!title || !title.length) { 
      title = name; 
    } 
    var topPart = '<div><label><span>' + title + ':</span><br />'; 
    var bottomPart = '</label></div>'; 
    if (type === 'text') { 
      return topPart + 
        '<input type="text" maxlength="200" name="' +name + '" />' + 
        bottomPart; 
    } else if (type === 'email') { 
      return topPart + 
        '<input type="email" required name="' + name + '" />' + 
        bottomPart; 
    } else if (type === 'number') { 
      return topPart + 
        '<input type="number" min="0" max="2147483647" ' +'name="' + name + '" />' + 
        bottomPart; 
    } else if (type === 'date') { 
      return topPart + 
        '<input type="date" min="1900-01-01" name="' +
          name + '" />' + 
        bottomPart; 
    } else if (type === 'textarea') { 
      return topPart + 
        '<textarea cols="30" rows="3" maxlength="800" name="' +name + '" />' + 
        bottomPart; 
    } else if (type === 'checkbox') { 
      return '<div><label><span>' + title + ':</span>' + 
        '<input type="checkbox" name="' + name + '" />' + 
        '</label></div>'; 
    } else if (type === 'notice') { 
      return '<p>' + name + '</p>'; 
    }  else if (type === 'button') { 
      return '<button name="' + name + '">' + title + '!</button>'; 
    } 
  }; 

})(); 
```

我们的工厂方法将被调用三个参数。从最重要的开始，它接受表单字段的`类型`和`名称`，以及将用作其描述的`标题`。由于大多数表单字段共享一些共同的特征，比如它们的标题，工厂方法试图将它们抽象出来，以减少代码重复。正如您所见，工厂方法还为每种字段类型包含一些合理的额外配置，比如文本字段的`maxlength`属性，这是特定用例的特定属性。

将用于表示每个表单元素的对象结构将是一个简单的 JavaScript 对象，它具有`type`、`name`和`title`属性。描述表单字段的对象集合将被分组在一个数组中，并在我们的模块的`dataDrivenForm.parts`属性上可用。在实际应用中，这些字段通常会通过 AJAX 请求检索，或者被注入到页面的某个部分中。在以下代码片段中，我们可以看到将用于驱动我们的表单创建的数据：

```js
dataDrivenForm.parts = [{ 
    type: 'text', 
    name: 'firstname', 
    title: 'First Name' 
  }, { 
    type: 'text', 
    name: 'lastname', 
    title: 'Last Name' 
  }, { 
    type: 'email', 
    name: 'email', 
    title: 'e-mail address' 
  }, { 
    type: 'date', 
    name: 'birthdate', 
    title: 'Date of birth' 
  }, { 
    type: 'number', 
    name: 'experience', 
    title: 'Years of experience' 
  }, { 
    type: 'textarea', 
    name: 'summary', 
    title: 'Summary' 
  }, { 
    type: 'checkbox', 
    name: 'receivenotifications', 
    title: 'Receive notification e-mails' 
  }, { 
    type: 'notice', 
    name: 'By using this form you accept the terms of use' 
  }, { 
    type: 'button', 
    name: 'save' 
  }, { 
    type: 'button', 
    name: 'submit' 
  }];
```

最后，我们定义并立即调用了一个`init`方法来初始化我们的模块：

```js
dataDrivenForm.init = function() { 
  for (var i = 0; i < dataDrivenForm.parts.length; i++) { 
    var part = dataDrivenForm.parts[i]; 
    var elementHTML = dataDrivenForm.formElementHTMLFactory(part.type, part.name, part.title); 
    // check if the result is null, undefined or empty string
    if (elementHTML && elementHTML.length) { 
      $('form').append(elementHTML); 
    } 
  } 
}; 

$(document).ready(dataDrivenForm.init); 
```

初始化代码会等待页面的 DOM 完全加载，然后使用工厂方法创建表单元素并将它们附加到页面的`<form>`元素上。在实际使用之前，上述代码的一个额外关注点是检查工厂方法调用的结果是否有效。

大多数工厂在使用不能处理的情况下被调用时，会返回`null`或空对象。因此，使用工厂时，检查每次调用的结果是否实际有效是一个很好的常见做法。

正如你所见，仅接受简单参数（例如字符串和数字）的工厂，在许多情况下会导致参数数量增加。即使这些参数只在特定情况下使用，我们的工厂的 API 也开始变得尴尬而冗长，并且需要针对每个特殊情况进行适当的文档编写，以便可用。

理想情况下，工厂方法应尽量接受尽可能少的参数，否则它将开始看起来像一个仅提供不同 API 的 Facade。由于在某些情况下，仅使用单个字符串或数值参数不足以满足要求，为了避免使用大量参数，我们可以遵循一种做法，即设计工厂以接受单个对象作为其参数。

例如，在我们的情况下，我们可以将描述表单字段的整个对象作为参数传递给工厂方法：

```js
dataDrivenForm.formElementHTMLFactory = function (formElementDefinition) { 
  var topPart = '<div><label><span>' + formElementDefinition.title + ':</span><br />'; 
  var bottomPart = '</label></div>'; 
  if (formElementDefinition.type === 'text') { 
    return topPart + 
      '<input type="text" maxlength="200" name="' +formElementDefinition.name + '" />' + 
      bottomPart; 
  } /* ... */ 
};
```

这种做法适用于以下情况：

+   当我们创建的工厂是不专注于特定用例的通用工厂，并且我们需要为每个特定用例分别配置它们的结果时。

+   当构造的对象具有许多可选配置参数且差异很大时。在这种情况下，将它们作为单独的参数添加到工厂方法中将导致调用具有一些`null`参数，具体取决于我们想要定义哪个确切的参数。

另一种做法，特别是在 JavaScript 编程中，是创建一个工厂方法，该方法接受一个简单的字符串或数字值作为其第一个参数，并可选地提供一个补充对象作为第二个参数。这使我们能够拥有一个简单的通用 API，可以特定于用例，并且还为我们提供了一些额外的自由度来配置一些特殊情况。这种方法被`$.ajax( url [, settings ] )`方法所使用，该方法允许我们通过只提供 URL 来生成简单的 GET 请求，还接受一个可选的`settings`参数，允许我们配置请求的任何方面。将上述实现更改为使用此变体留作读者的练习，以便进行实验并熟悉工厂方法的使用。

# 介绍建造者模式

建造者模式是创建模式组中的一部分，为我们提供了一种在达到可以使用的点之前需要大量配置的对象的创建方法。建造者模式通常用于接受许多可选参数以定义其操作的对象。另一个匹配的案例是创建需要在几个步骤或特定顺序中完成配置的对象。

根据计算机科学的共同范例，建造者模式的常见范式是有一个建造者对象，提供一个或多个设置方法（`setA（...）`，`setB（...）`），以及一个单独的生成方法，用于构建并返回新创建的结果对象（`getResult（）`）。

![介绍建造者模式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00025.jpeg)

此模式有两个重要概念。第一个是建造者对象公开一些方法作为配置正在构建的对象的不同部分的一种方式。在配置阶段，建造者对象保留一个内部状态，反映了所提供的设置方法的调用的效果。当用于创建接受大量配置参数的对象时，这可能是有益的，解决了拖尾构造函数的问题。

### 注意

拖尾构造函数是面向对象编程的反模式，描述了一个类提供了几个构造函数，这些构造函数往往在所需参数的数量，类型和组合上有所不同。具有多个参数可以以许多不同组合使用的对象类通常会导致实现落入这种反模式中。

第二个重要概念是它还提供了一个生成方法，根据前述配置返回实际构造的对象。大多数情况下，请求对象的实例化是惰性进行的，并且实际上是在调用此方法的时候发生的。在某些情况下，建造者对象允许我们调用生成方法超过一次，从而使我们能够使用相同配置生成多个对象。

## 它如何被 jQuery 的 API 接受

建造者模式也可以作为 jQuery 公开的 API 的一部分找到。具体来说，jQuery 的 `$()` 函数也可以通过使用 HTML 字符串作为参数来创建新的 DOM 元素。因此，我们可以创建新的 DOM 元素并根据需要设置它们的不同部分，而不必创建所需的最终结果的确切 HTML 字符串：

```js
var $input = $('<input />'); 
$input.attr('type','number'); 
$input.attr('min', '0'); 
$input.attr('max', '100'); 
$input.prop('required', true);
$input.val(4);

$input.appendTo('form');
```

`$('<input />')` 调用返回一个包含未附加到页面的 DOM 树的元素的复合对象。这个未附加的元素只是一个内存对象，直到我们将其附加到页面为止，它既不完全构造也不完全功能。在这种情况下，此复合对象就像一个具有尚未最终化的对象内部状态的构建对象实例。在此之后，我们使用一些 jQuery 方法对其进行一系列操作，这些方法就像建造者模式描述的设置器方法一样。

最后，在我们应用所有必需的配置之后，使得生成的对象以期望的方式行为，我们调用 `$.fn.appendTo()` 方法。`$.fn.appendTo()` 方法作为建造者模式的生成方法，将 `$input` 变量的内存元素附加到页面的 DOM 树上，将其转换为实际附加的 DOM 元素。

当然，通过利用 jQuery 为其方法提供的流式 API，并组合 `$.fn.attr()` 方法调用，以上示例可以变得更易读且不太重复。此外，jQuery 允许我们使用几乎所有其方法来在构建中的元素上执行遍历和操作，就像我们可以在普通 DOM 元素的复合对象上执行的那样。因此，以上示例可以更完整地如下所示：

```js
$('<input />').attr({
    'type':'number',
    'min': '0',
    'max': '100'
  })
  .prop('required', true) 
  .val(4)
  .css('display', 'block') 
  .wrap('<label>') // wrap the input with a <label> 
  .parent() // traverse one level up, to the <label> 
  .prepend('<span>Qty:#</span') 
  .appendTo('form');
```

结果如下所示：

![它如何被 jQuery 的 API 接受](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00026.jpeg)

允许我们将调用 `$()` 函数的这种过载方式归类为采用建造者模式的实现的标准是：

+   它返回一个具有包含部分构造元素的内部状态的对象。所包含的元素仅是内存对象，不是页面 DOM 树的一部分。

+   它为我们提供了操作其内部状态的方法。大多数 jQuery 方法都可以用于此目的。

+   它为我们提供了生成最终结果的方法。我们可以使用 jQuery 方法，例如 `$.fn.appendTo()` 和 `$.fn.insertAfter()`，作为完成内部元素构造并使其成为具有反映其较早内存表示的属性的 DOM 树的一部分的方法。

正如我们已经在第一章 *jQuery 和组合模式的复习*中看到的，使用 `$()` 函数的主要方法是将其与 CSS 选择器作为字符串参数调用，然后它将检索匹配的页面元素并以组合对象返回它们。另一方面，当 `$()` 函数检测到它已被调用的字符串参数看起来像一个 HTML 片段时，它将作为 DOM 元素生成器。这种重载的 `$()` 函数的调用方式基于提供的 HTML 代码以 `<` 和 `>` 不等号符号开始和结束的假设：

```js
  init = jQuery.fn.init = function( selector, context ) { 
    /* 11 lines of code */ 
    // Handle HTML strings 
    if ( typeof selector === "string" ) { 
      if ( selector[ 0 ] === "<" &&selector[ selector.length - 1 ] === ">" &&selector.length >= 3 ) { 
        // Assume that strings that start and end with <> are HTML // and skip the regex check 
        match = [ null, selector, null ]; 

      } /*...*/

      // Match html or make sure no context is specified for #id 
      if ( match && ( match[ 1 ] || !context) ) { 

        // HANDLE: $(html) -> $(array) 
        if ( match[ 1 ] ) { 
          /* 4 lines of code */
          jQuery.merge( this, jQuery.parseHTML( match[ 1 ], /*...*/ ) ); 
          /* 16 lines of code */ 

          return this; 
        }/*...*/ 
      }/*...*/ 
    }/*...*/ 
  }; 
```

正如我们在前面的代码中所看到的，这个重载使用了 `jQuery.parseHTML()` 辅助方法，最终导致调用 `createDocumentFragment()` 方法。创建的**文档片段**然后被用作正在构建的元素树结构的宿主。在 jQuery 完成将 HTML 转换为元素之后，文档片段被丢弃，只返回其托管的元素：

```js
jQuery.parseHTML = function( data, context, keepScripts ) { 
  /* 17 lines of code */ 
  // Single tag 
  if ( parsed ) { 
    return [ context.createElement( parsed[ 1 ] ) ]; 
  } 

  parsed = buildFragment( [ data ], context, scripts ); 
  /* 5 lines of code */
  return jQuery.merge( [], parsed.childNodes ); 
};
```

这导致创建一个包含内存中元素树结构的新 jQuery 组合对象。尽管这些元素未附加到页面的实际 DOM 树上，我们仍然可以像对待任何其他 jQuery 组合对象一样对它们进行遍历和操作。

### 注意

有关文档片段的更多信息，您可以访问：[`developer.mozilla.org/en-US/docs/Web/API/Document/createDocumentFragment`](https://developer.mozilla.org/en-US/docs/Web/API/Document/createDocumentFragment)。

## 内部使用 jQuery 的方法

jQuery 的一个毫无疑问的重要部分是其与 AJAX 相关的实现，其目标是提供一个简单的 API 用于异步调用，同时也可以在很大程度上进行配置。使用 jQuery 源代码查看器并搜索 `jQuery.ajax`，或直接在 jQuery 的源代码中搜索 `"ajax:"`，将带来上述实现。为了使其实现更加直接并允许其进行配置，jQuery 内部使用一种特殊的对象结构，该结构充当了用于创建和处理每个 AJAX 请求的生成器对象。正如我们将看到的，这不是使用生成器对象的最常见方式，但实际上是一种具有一些修改以适应这个复杂实现要求的特殊变体：

```js
jqXHR = { 
  readyState: 0, 

  // Builds headers hashtable if needed 
  getResponseHeader: function( key ) {/* ... */}, 

  // Raw string 
  getAllResponseHeaders: function() {/* ... */}, 

  // Caches the header 
  setRequestHeader: function( name, value ) {/* ... */}, 

  // Overrides response content-type header 
  overrideMimeType: function( type ) {/* ... */}, 

  // Status-dependent callbacks 
  statusCode: function( map ) {/* ... */}, 

  // Cancel the request 
  abort: function( statusText ) {/* ... */} 
}; 
```

`jqXHR` 对象公开用于配置生成的异步请求的主要方法是 `setRequestHeader()` 方法。这个方法的实现相当通用，使得 jQuery 可以使用一个方法设置请求的所有不同 HTTP 标头。

为了提供更大程度的灵活性和抽象性，jQuery 内部使用一个单独的`transport`对象作为`jqXHR`对象的包装器。这个传输对象处理实际将 AJAX 请求发送到服务器的部分，像一个与`jqXHR`对象合作创建最终结果的*合作构建器对象*。这样，jQuery 可以使用相同的 API 和整体实现从相同或跨域服务器获取脚本、XML、JSON 和 JSONP 响应：  

```js
transport = inspectPrefiltersOrTransports( transports, s, options, jqXHR ); 

// If no transport, we auto-abort 
if ( !transport ) { 
  done( -1, "No Transport" ); 
} else { 
  jqXHR.readyState = 1; 
  /* 12 lines of code */ 
  try { 
    state = 1; 
    transport.send( requestHeaders, done ); 
  } catch ( e ) {/* 7 lines of code */} 
}
```

这个构建器模式的实现的另一个特殊之处是，它应该能够以同步和异步方式操作。因此，`transport`对象的`send()`方法，它作为包装的`jqXHR`对象的结果生成方法，不能只返回一个结果对象，而是需要使用回调来调用它。

最后，在请求完成后，jQuery 使用`getResponseHeader()`方法检索所有必需的响应标头。紧接着，标头被用于正确转换存储在`jqXHR`对象的`responseText`属性中的接收到的响应。

## 如何在我们的应用程序中使用它

作为在使用 jQuery 的客户端应用程序中使用构建器模式的示例用例，我们将创建一个简单的数据驱动多选题测验。与我们之前看到的工厂模式示例相比，构建器模式更适合这种情况的主要原因是结果更复杂，具有更多的配置度。每个问题都将基于一个模型对象生成，该对象将表示其所需的属性。

![在我们的应用程序中如何使用它](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00027.jpeg)

再次强调，所需的 HTML 非常简单，只包含一个页面标题的`<h1>`元素，一个空的`<form>`标签，以及对我们的 CSS 和 JavaScript 资源的一些引用：

```js
    <h1>Data Driven Quiz</h1> 
    <form> </form> 

    <script type="text/javascript" src="img/jquery.js"></script> 
    <script type="text/javascript" src="img/datadrivenquiz.js"></script> 
```

除了我们在之前章节中看到的常见的简单样式之外，这个示例的 CSS 还额外定义了：

```js
ul.unstyled > li { 
    margin: 0; 
    padding: 0; 
    list-style: none; 
}
```

为了这个例子的需要，我们将创建一个带有新命名空间`dataDrivenQuiz`的模块。正如我们在本章前面看到的，我们将假设存在一个数组，其中包含描述需要呈现的每个多选题的模型对象。每个这些模型对象都将具有：

+   一个`title`属性，将保存问题

+   一个`options`属性，将是一个包含可供选择的答案的数组

+   一个可选的`acceptsMultiple`属性，表示我们应该使用单选按钮还是复选框

描述表单问题的模型对象数组将在我们的模块的`dataDrivenQuiz.parts`属性中可用，同时要牢记我们的实现可以轻松地修改为使用 AJAX 请求获取模型：

```js
dataDrivenQuiz.questions = [{ 
  title: 'Which is the most preferred way to write our JavaScript code?', 
  options: [ 
    'inline along with our HTML', 
    'flat inside *.js files', 
    'in small Modules, one per *.js file' 
  ] 
}, { 
  title: 'What does the $() function returns when invoked with a CSS selector?', 
  options: [ 
    'a single element', 
    'an array of elements', 
    'the HTML of the selected element', 
    'a Composite Object' 
  ] 
}, { 
  title: 'Which of the following are Design Patterns', 
  acceptsMultiple: true, 
  options: [ 
    'Garbage Collector', 
    'Class', 
    'Object Literal', 
    'Observer' 
  ] 
}, { 
  title: 'How can get a hold to the <body> element of a page?', 
  acceptsMultiple: true, 
  options: [ 
    'document.body', 
    'document.getElementsByTagName(\'body\')[0]', 
    '$(\'body\')[0]', 
    'document.querySelector(\'body\')' 
  ] 
}];
```

### 提示

在开始实际实现之前，定义描述问题所需的数据结构使我们能够专注于应用程序的需求，并对其整体复杂性进行估算。

鉴于前述示例数据，现在让我们继续实现我们的构建器：

```js
function MultipleChoiceBuilder() { 
  this.title = 'Untitled'; 
  this.options = []; 
} 
dataDrivenQuiz.MultipleChoiceBuilder = MultipleChoiceBuilder; 

MultipleChoiceBuilder.prototype.setTitle = function(title) { 
  this.title = title; 
  return this; 
}; 

MultipleChoiceBuilder.prototype.setAcceptsMultiple = function(acceptsMultiple) { 
    this.acceptsMultiple = acceptsMultiple; 
    return this; 
  }; 

MultipleChoiceBuilder.prototype.addOption = function(title) { 
  this.options.push(title); 
  return this; 
}; 

MultipleChoiceBuilder.prototype.getResult = function() { 
  var $header = $('<header>').text(this.title || 'Untitled'); 

  var questionGuid = 'quizQuestion' + (jQuery.guid++); 
  var $optionsList = $('<ul class="unstyled">'); 
  for (var i = 0; i < this.options.length; i++) { 
    var $input = $('<input />').attr({
      'type': this.acceptsMultiple ? 'checkbox' : 'radio',
      'value': i,
      'name': questionGuid,
    });

    var $option = $('<li>'); 
    $('<label>').append($input, $('<span>').text(this.options[i]))
      .appendTo($option); 
    $optionsList.append($option); 
  } 
  return $('<article>').append($header, $optionsList);
};
```

使用 JavaScript 的原型面向对象方法，我们首先为我们的`MultipleChoiceBuilder`类定义构造函数。当使用`new`运算符调用构造函数时，它将创建一个新的构建器实例，并将其`title`属性初始化为`"Untitled"`，将`options`属性初始化为空数组。

在这之后，我们完成了构建器的构造函数的定义，将其作为模块的成员附加，并继续定义其设置器方法。遵循原型类范例，`setTitle()`、`setAcceptsMultiple()`和`addOption()`方法被定义为构建器原型的属性，并用于修改正在构建的元素的内部状态。另外，为了使我们能够链式调用这些方法的多个调用，从而获得更可读的实现，它们都以`return this;`语句结束。

我们使用`getResult()`方法完成构建器的实现，该方法负责收集应用于构建器对象实例的所有参数，并生成包装在 jQuery 组合对象中的结果元素。在其第一行，它创建了一个问题的标题。紧接着，它创建一个带有`unstyled` CSS 类的`<ul>`元素，用于容纳问题的可能答案，并使用一个唯一标识符作为问题生成的`<input>`的`name`。

在接下来的`for`循环中，我们将：

+   为问题的每个选项创建一个`<input />`元素。

+   根据`acceptsMultiple`属性的值，将其`type`适当设置为`checkbox`或`radio`按钮。

+   使用`for`循环的迭代编号作为其`value`。

+   将我们之前生成的问题的唯一标识符设置为输入的`name`，以便将答案分组。

+   最后，在问题的`<ul>`中添加包含选项文本的`<label>`，并将其全部包装在一个`<li>`中。

最后，标题和选项列表都被包装在一个`<article>`元素中，并作为构建器的最终结果返回。

在上述实现中，我们使用`$.fn.text()`方法为问题的标题及其可用选择分配内容，而不是使用字符串连接，以便正确转义其中的`<`和`>`字符。额外说明，由于一些答案也包含单引号，我们需要在模型对象中使用反斜杠(`\'`)对它们进行转义。

最后，在我们模块的实现中，我们定义并立即调用`init`方法：

```js
dataDrivenQuiz.init = function() { 
  for (var i = 0; i < dataDrivenQuiz.questions.length; i++) { 
    var question = dataDrivenQuiz.questions[i]; 
    var builder = new dataDrivenQuiz.MultipleChoiceBuilder(); 

    builder.setTitle(question.title) .setAcceptsMultiple(question.acceptsMultiple); 

    for (var j = 0; j < question.options.length; j++) { 
      builder.addOption(question.options[j]); 
    } 

    $('form').append(builder.getResult());
  }
}; 

$(document).ready(dataDrivenQuiz.init);
```

初始化代码的执行被延迟，直到页面的 DOM 树完全加载完成。然后，`init()` 方法遍历模型对象数组，并使用 Builder 创建每个问题，并填充我们页面的`<form>`元素。

对于读者来说，一个很好的练习是扩展上述实现，以支持对测验的客户端评估。首先，这需要您扩展问题对象以包含有关每个选项有效性的信息。然后，建议您创建一个 Builder，该 Builder 将从表单中获取答案，评估它们，并创建一个包含用户选择和测验总体成功的结果对象。

# 摘要

在本章中，我们学习了 Builder 和 Factory 模式的概念，这两种是最常用的创建型设计模式之一。我们分析了它们的共同目标，它们在抽象生成和初始化特定用例的新对象过程方面的不同方法，以及它们的采用如何使我们的实现受益。最后，我们学习了如何正确使用它们，并如何为任何给定实现的不同用例选择最合适的模式。

现在我们已经完成了对最重要的创建型设计模式的介绍，我们可以继续下一章，介绍用于编写异步和并发程序的开发模式。更详细地说，我们将学习如何通过使用回调和 jQuery Deferred 和 Promises API 来编排顺序或并行运行的异步程序的执行。


# 第七章：异步控制流模式

本章专注于用于简化异步和并发过程编程的开发模式。

首先，我们将复习 JavaScript 编程中如何使用回调函数以及它们是网页开发的一个组成部分。然后，我们将继续识别它们在大型和复杂实现中的好处和局限性。

接下来，我们将介绍 Promises 的概念。我们将学习 jQuery 的 Deferred 和 Promise API 的工作原理，以及它们与 ES6 Promises 的区别。我们将看到它们在 jQuery 内部的使用方式以简化其实现并导致更可读的代码。我们将分析它们的好处，分类最匹配的用例，并将它们与经典的回调模式进行比较。

到达本章结束时，我们将能够使用 jQuery Deferred 和 Promises 来有效地编排按顺序或并行运行的异步过程的执行。

在本章中，我们将：

+   对 JavaScript 编程中如何使用回调函数进行复习

+   介绍 Promises 的概念

+   学习如何使用 jQuery 的 Deferred 和 Promise API

+   比较 jQuery Promises 和 ES6 Promises

+   学习如何使用 Promises 来编排异步任务。

# 使用回调函数进行编程

回调函数可以被定义为作为调用参数传递给另一个函数或方法（称为高阶函数）的函数，并且预计将在以后的某个时间点执行。通过这种方式，被传递给我们的回调函数的代码片段最终会调用它，将操作或事件的结果传播回定义回调函数的上下文。

回调函数可以根据被调用方法的操作方式分为同步或异步。当回调由阻塞方法执行时，回调被称为同步。另一方面，JavaScript 开发人员更熟悉异步回调，也称为延迟回调，它们被设置为在异步过程完成后或发生特定事件时执行（页面加载，单击，AJAX 响应到达等）。

![使用回调进行编程](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00028.jpeg)

由于回调函数是许多核心 JavaScript API（如 AJAX）的组成部分，因此在 JavaScript 应用程序中广泛使用。此外，JavaScript 对该模式的实现几乎与上述简单定义所描述的一字不差。这是 JavaScript 将函数视为对象并允许我们将方法引用存储和传递为简单变量的方式的结果。

## 在 JavaScript 中使用简单回调函数

在 JavaScript 中使用异步回调的最简单的例子之一可能是`setTimeout()`函数。下面的代码演示了它的一个简单用法，我们将`setTimeout()`与`doLater()`函数作为回调参数一起调用，并且在等待 1000 毫秒后，`doLater()`回调被调用：

```js
var alertMessage = 'One second passed!'; 
function doLater() { 
    alert(alertMessage); 
}
setTimeout(doLater, 1000);
```

如简单的前面示例所示，回调在定义的上下文中执行。回调仍然可以访问定义它的上下文的变量，通过创建闭包来实现。即使前面的示例使用了之前定义的命名函数，对于匿名回调也是适用的：

```js
var alertMessage = 'One second passed!';
setTimeout(function() { 
    alert(alertMessage); 
}, 1000);
```

在许多情况下，使用匿名回调是一种更方便的编程方式，因为它会导致代码更短，也减少了可读性噪音，这是由定义几个只使用一次的不同命名函数而产生的。

## 将回调设置为对象属性

上述定义的一个小变化也存在，其中回调函数被分配给对象的属性，而不是作为方法调用的参数传递。这在需要在方法调用期间或之后执行几种不同操作的情况下通常使用：

```js
var c = new Countdown(); 

c.onProgress = function(progressStatus) { /*...*/ };
c.onDone = function(result) {  /*...*/ };
c.onError = function(error) {  /*...*/ };

c.start();
```

上述变体的另一个用例是在已实例化和初始化的对象上添加处理程序。这种情况的一个很好的例子是我们为简单（非 jQuery）AJAX 调用设置结果处理程序的方式：

```js
var r = new XMLHttpRequest(); 
r.open('GET', 'data.json', true); 
r.onreadystatechange = function() { 
    if (r.readyState != 4 || r.status != 200) { 
        return; 
    } 
    alert(r.responseText); 
};
r.send();
```

在上述代码中，我们将一个匿名函数设置在 XMLHttpRequest 对象的`onreadystatechange`属性上。这个函数充当回调，每当进行中的请求状态发生变化时都会被调用。在我们的回调内部，我们检查请求是否以成功的 HTTP 状态码完成，并显示带有响应主体的警报。就像在这个示例中一样，我们通过调用`send()`方法而不传递任何参数来启动 AJAX 调用，使用这种变体的 API 通常导致以最小的方式调用它们的方法。

## 在 jQuery 应用程序中使用回调

在 jQuery 应用程序中使用回调的最常见方式可能是用于事件处理。这是合乎逻辑的，因为每个交互式应用程序都应该首先处理和响应用户操作。正如我们在前面章节中看到的，将事件处理程序附加到元素的最便捷方式之一是使用 jQuery 的`$.fn.on()`方法。

jQuery 中另一个常见的使用回调的地方是 AJAX 请求，`$.ajax()`方法起着中心作用。此外，jQuery 库还提供了几个方便的方法来进行 AJAX 请求，这些方法都专注于最常见的用例。由于所有这些方法都是异步执行的，它们也接受一个回调作为参数，以便将检索到的数据返回给发起 AJAX 请求的上下文。其中一个方便的方法是`$.getJSON()`，它是`$.ajax()`的一个包装器，并且用作执行意图检索 JSON 响应的 AJAX 请求的更匹配的 API。

其他广泛使用的接受回调的 jQuery API 如下：

+   诸如`$.animate()`之类的与效果相关的 jQuery 方法

+   `$(document).ready()`方法

现在让我们通过演示一个代码示例来继续，该示例中使用了上述所有方法。

```js
$(document).ready(function() { 
  $('#fetchButton').on('click', function() { 
    $.getJSON('AjaxContent.json', function(json) { 
      console.log('done loading new content'); 

      $('#newContent').css({ 'display': 'none' }) 
        .text(json.data) 
        .slideDown(function() { 
          console.log('done displaying new content'); 
        }); 
    }); 
  }); 
}); 
```

前面的代码首先延迟执行，直到页面的 DOM 树完全加载，然后通过使用 jQuery 的`$.fn.on()`方法，在 ID 为`fetchButton`的`<button>`上添加一个点击观察器。每当点击事件触发时，提供的回调将被调用，并启动一个 AJAX 调用来获取`AjaxContent.json`文件。在此示例中，我们使用一个简单的 JSON 文件，如下所示：

```js
{ "data": "I'm the text content fetched by an AJAX call!" }
```

当接收到响应并成功解析 JSON 时，回调函数将以解析后的对象作为参数被调用。最后，回调函数本身会在页面中查找 ID 为`newContent`的页面元素，隐藏它，然后将检索到的 JSON 数据字段设置为其文本内容。紧接着，我们使用 jQuery 的`$.fn.slideDown()`方法，通过逐渐增加其高度使新设置的页面内容出现。最后，在动画完成后，我们向浏览器控制台输出一个日志消息。

### 注

关于 jQuery 的`$.ajax()`、`$.getJSON()`和`$.fn.slideDown()`方法更多的文档可以在[`api.jquery.com/jQuery.ajax/`](http://api.jquery.com/jQuery.ajax/)、[`api.jquery.com/jQuery.getJSON/`](http://api.jquery.com/jQuery.getJSON/)和[`api.jquery.com/slideDown/`](http://api.jquery.com/slideDown/)中找到。

请记住，当通过文件系统加载页面时，`$.getJSON()`方法可能在某些浏览器中无法工作，但在使用 Apache、IIS 或 nginx 等任何 Web 服务器时可以正常工作。

## 编写接受回调的方法

当编写一个使用一个或多个异步 API 的函数时，这也意味着结果函数结果也是异步的。在这种情况下，很明显，简单地返回结果值不是一个选项，因为结果可能在函数调用已经完成后才可用。

异步实现的最简单解决方案是使用一个回调函数作为函数的参数，正如我们之前讨论的那样，在 JavaScript 中这是很方便的。例如，我们将创建一个异步函数，它生成指定范围内的随机数：

```js
function getRandomNumberAsync (max, callbackFn) { 
    var runFor = 1000 + Math.random() * 1000; 
    setTimeout(function() { 
        var result = Math.random() * max; 
        callbackFn(result); 
    }, runFor); 
}
```

`getRandomNumberAsync()` 函数接受其 `max` 参数作为生成的随机数的数值上限，还接受一个回调函数作为参数，它将使用生成的结果调用。它使用 `setTimeout()` 来模拟一个范围在 1000 到 2000 毫秒之间的异步计算。为了生成结果，它使用 `Math.random()` 方法，将其乘以允许的最大值，最后使用提供的回调函数调用它。调用此函数的简单方法如下所示：

```js
getRandomNumberAsync(10, function(number) { 
    console.log(number); // returns a number between 0 and 10
});
```

即使上面的示例使用 `setTimeout()` 来模拟异步处理，但不管使用哪种异步 API，实现原理都是相同的。例如，我们可以重写上述函数以通过 AJAX 调用来检索其结果：

```js
function getRandomNumberWS (max, callbackFn, errorFn) { 
  $.ajax({ 
    url: 'https://qrng.anu.edu.au/API/jsonI.php?length=1&type=uint16', 
    dataType: 'json', 
    success: function(json) { 
      var result = json.data[0] / 65535 * max; 
      callbackFn(result); 
    }, 
    error: errorFn 
  });
}
```

前述实现使用了 `$.ajax()` 方法，该方法使用一个对象参数调用，该对象封装了请求的所有选项。除了请求的 URL 外，该对象还定义了结果的预期 `dataType` 和 `success` 和 `error` 回调函数，这些函数与我们函数的相应参数配合使用。

或许前面的代码唯一额外需要解决的问题是如何在成功回调内处理错误，以便在创建结果过程中出现问题时通知函数的调用者。例如，AJAX 请求可能会返回一个空对象。为这些情况添加适当的处理留给读者，在阅读本章剩余部分之后。

### 注意

澳大利亚国立大学（ANU）通过他们的 REST Web 服务向公众提供免费的真正随机数。更多信息，请访问 [`qrng.anu.edu.au/API/api-demo.php`](http://qrng.anu.edu.au/API/api-demo.php)。

## 调度回调函数

我们现在将继续分析一些在处理接受回调函数的异步方法时常用的控制执行流程的模式。

### 按顺序排队执行

作为我们的第一个例子，我们将创建一个函数，演示如何排队执行多个异步任务：

```js
function getThreeRandomNumbers(callbackFn, errorFn) {
    var results = []; 
    getRandomNumberAsync(10, function(number) { 
        results.push(number); 

        getRandomNumberAsync(10, function(number) { 
            results.push(number); 

            getRandomNumberWS(10, function(number) {
                results.push(number); 
                callbackFn(results); 
            }, function (error) { 
                errorFn(error); 
            }); 
        }); 
    });
}
```

在前面的实现中，我们的函数创建了一个包含三个随机数生成的队列。前两个随机数是从我们的样本 `setTimeout()` 实现中生成的，第三个是通过 AJAX 调用从上述 Web 服务中检索的。在这个例子中，所有的数字都被收集在 `result` 数组中，在所有异步任务完成后作为调用参数传递给 `callbackFn`。

前述的实现相当简单直接，并且只是反复应用了回调模式的简单原则。对于每一个额外或排队的异步任务，我们只需将其调用嵌套在它依赖的任务的回调内部即可。请记住，在不同的用例中，我们可能只关心返回最终任务的结果，并将中间步骤的结果作为参数传递给每个后续的异步调用。

#### 避免回调地狱反模式

尽管编写像上面示例中显示的代码很容易，但当应用于大型和复杂的实现时，可能会导致可读性较差。由代码前面的空格创建的三角形形状和接近末尾的几个`});`的堆叠是我们的代码可能会导致的反模式的两个迹象，该反模式被称为**回调地狱**。

### 注意

欲了解更多信息，请访问[`callbackhell.com/`](http://callbackhell.com/)。

一种避免这种反模式的方法是展开嵌套的回调函数，通过在与它们使用的异步任务相同级别创建单独的命名函数。将这个简单的提示应用到上面的示例后，生成的代码看起来更清晰：

```js
function getThreeRandomNumbers(callbackFn, errorFn) { 
    var results = []; 

    getRandomNumberAsync(10, function(number) { // task 1 
        results.push(number); 
        task2(); 
    }); 

    function task2 () { 
        getRandomNumberAsync(10, function(number) { 
            results.push(number); 
            task3(); 
        }); 
    } 

    function task3 () { 
        getRandomNumberWS(10, function(number) { 
            results.push(number); 
            callbackFn(results); 
        }, errorFn); 
    } 
}
```

正如您所见，生成的代码确实不会让我们想起回调地狱反模式的特征。另一方面，现在它需要更多的代码行来实现，主要用于现在需要的额外函数声明`function taskX () { }`。

### 提示

在上述两种方法之间的一个中间解决方案是将这种异步执行队列的相关部分组织成小型且易于管理的函数。

### 并行运行

尽管 Web 浏览器中的 JavaScript 是单线程的，但使独立的异步任务并行运行可以使我们的应用程序运行更快。例如，我们将重新编写前面的实现以并行获取所有三个随机数，这样可以使结果的检索速度比以前快得多：

```js
function getRandomNumbersConcurent(callbackFn, errorFn) { 
    var results = []; 
    var resultCount = 0; 
    var n = 3; 

    function gatherResult (resultPos) { 
        return function (result) { 
            results[resultPos] = result; 
            resultCount++; 
            if (resultCount === n) { 
                callbackFn(results); 
            } 
        }; 
    } 

    getRandomNumberAsync(10, gatherResult(0)); 
    getRandomNumberAsync(10, gatherResult(1)); 
    getRandomNumberWS(10, gatherResult(2), errorFn); 
}
```

在前面的代码中，我们定义了`gatherResult()`辅助函数，它返回一个匿名函数，该函数用作我们的随机数生成器的回调。返回的回调函数使用`resultPos`参数作为将生成或检索到的随机数存储的数组的索引。此外，它追踪它被调用的次数，以了解是否所有三个并行任务已结束。最后，在第三次和最后一次回调之后，使用`results`数组作为参数调用`callbackFn`函数。

除了 AJAX 调用之外，这种技术的另一个很好的应用是访问存储在**IndexedDB**中的数据。并行从数据库中检索许多值可以带来性能增益，因为数据检索可以在不互相阻塞的情况下并行执行。

### 注意

有关 IndexedDB 的更多信息，您可以访问 [`developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API/Using_IndexedDB`](https://developer.mozilla.org/en-US/docs/Web/API/IndexedDB_API/Using_IndexedDB)。

# 介绍 Promise 的概念

Promise，也被计算机科学称为 Futures，被描述为专门用于同步异步、并发或并行过程的特殊对象。它们也被用作代理来在生成完成任务的结果时传播结果。这样，一个 Promise 对象就像是一个合同，其中一项操作最终将完成其执行，任何持有这个合同引用的人都可以声明他们对结果的通知感兴趣。

自从它们作为几个库的一部分被引入到 JavaScript 开发中，它们彻底改变了我们使用异步函数以及在实现中与复杂的同步方案结合使用的方式。这样，Web 开发人员可以创建更灵活、可扩展和可读性更强的实现，使带有回调的方法调用看起来像是一个原始模式，并有效地消除了回调地狱（Callback Hell）的情况。

![介绍 Promise 的概念](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00029.jpeg)

Promise 的一个关键概念是，异步方法返回一个代表其最终结果的对象。每个 Promise 都有一个最初状态为 Pending 的内部状态。这个内部状态只能改变一次，从 Pending 改变为 Resolved 或 Rejected，通过使用每个实现都提供的 `resolve()` 或 `reject()` 方法。这些方法只能调用来改变 Pending Promise 的状态；在大多数情况下，它们只能由 Promise 对象的原始创建者使用，而不是提供给其消费者。`resolve()` 方法可以用操作的结果作为单一参数来调用，而 `reject()` 方法通常用引起 Promise 对象被拒绝的 `Error` 来调用。

另一个 Promise 的关键概念是存在一个 `then()` 方法，使它们被称为“thenable”，这是一个通用术语，用来描述所有不同实现中的 promises。每个 Promise 对象都暴露了一个 `then()` 方法，调用者可以用它来提供在 Promise 被解决（Resolved）或拒绝（Rejected）时将被调用的函数。`then()` 方法可以用两个函数作为参数来调用，第一个函数在 Promise 被解决时被调用，而第二个函数在被拒绝时被调用。第一个参数通常被称为`onFulfilled()` 回调，而第二个参数被称为 `onRejected()`。

![介绍 Promise 的概念](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00030.jpeg)

每个 Promise 都保存着两个内部列表，其中包含作为参数传递给 `then()` 方法的所有 `onFulfilled()` 和 `onRejected()` 回调函数。`then()` 方法可以针对每个 Promise 调用多次，向适当的内部列表添加新条目，只要相应的参数实际上是一个函数。当 Promise 最终得到解决或拒绝时，它会遍历适当的回调列表，并按顺序调用它们。此外，一旦 Promise 被解决并且之后，每次使用 `then()` 方法都会立即调用相应的提供的回调。

### 注意

根据其特性，Promise 在某种程度上可以被比作发布/订阅模式中的代理。它们的主要区别包括它只能用于单个发布，并且即使订阅者在发布之后表达了兴趣，他们也会收到结果通知。

## 使用 Promises

正如我们之前所说，Promise 的概念彻底改变了 JavaScript 中异步任务的编程方式，并且在很长一段时间内，它们是每个人都热情的新事物。那时，许多专门的库出现了，每个库都提供了一个稍有不同的 Promise 实现。此外，Promise 实现也作为 jQuery 之类的实用程序库的一部分以及诸如 AngularJS 和 EmberJS 之类的 Web 框架的一部分而可用。那时，"CommonJS Promises/A"规范以参考点的形式出现，并且是第一个尝试定义如何跨所有实现实际工作的 Promise。

### 注意

有关"CommonJS Promises/A"规范的更多信息，您可以访问[`wiki.commonjs.org/wiki/Promises/A`](http://wiki.commonjs.org/wiki/Promises/A)。

### 使用 jQuery Promise API

基于"CommonJS Promises/A"设计，Promise-based API 首次出现在 jQuery v1.5 中。该实现引入了附加概念 Deferred 对象，它的工作方式类似于**Promise 工厂**。Deferred 对象公开了一组 Promises 提供的方法的超集，其中附加方法可用于对其内部 Promise 的状态进行操作。此外，Deferred 对象公开了一个`promise()`方法，并返回实际的 Promise 对象，该对象不公开任何方式来操作其内部状态，只公开像`then()`这样的观察方法。

换句话说：

+   只有引用 Deferred 对象的代码才能实际更改其 Promise 的内部状态，无论是解决还是拒绝。

+   任何具有对 Promise 对象的引用的代码片段都无法更改其状态，而只能观察其状态是否更改。

### 注意

有关 jQuery 的 Deferred 对象的更多信息，您可以访问[`api.jquery.com/jQuery.Deferred/`](http://api.jquery.com/jQuery.Deferred/)。

作为 jQuery 的 Deferred 对象的一个简单示例，让我们看看如何重写本章早些时候看到的 `getRandomNumberAsync()` 函数，以使用 Promises 而不是回调：

```js
function getRandomNumberAsync (max) { 
    var d = $.Deferred(); 
    var runFor = 1000 + Math.random() * 1000; 
    setTimeout(function() { 
        var result = Math.random() * max; 
        d.resolve(result); 
    }, runFor); 
    return d.promise(); 
} 

getRandomNumberAsync(10).then(function(number) { 
    console.log(number); // returns a number between 0 and 10 
});
```

我们的目标是创建一个返回最终解决为生成的随机数的 Promise 的异步函数。首先，创建一个新的 Deferred 对象，然后使用 Deferred 的 `promise()` 方法返回相应的 Promise 对象。当结果的异步生成完成时，我们的方法使用 Deferred 对象的 `resolve()` 方法设置先前返回的 Promise 的最终状态。

我们函数的调用者使用返回的 Promise 的 `then()` 方法，附加一个回调函数，一旦 Promise 被解决，就会以结果作为参数调用该回调。此外，还可以传递第二个回调函数，以便在 Promise 被拒绝时得到通知。需要注意的一件重要事情是，通过遵循上述模式，即函数总是返回 Promises 而不是实际的 Deferred 对象，我们可以确保只有 Deferred 对象的创建者可以更改 Promise 的状态。

### 使用 Promises/A+

在进行了一段时间的实践性实验后，社区确定了 CommonJS Promises/A 的一些限制，并推荐了一些改进方法。结果是创建了 Promises/A+ 规范，作为改进现有规范的一种方式，也是统一各种可用实现的第二次尝试。新规范的最重要部分关注于如何使链接 Promises 工作，使它们更加实用和方便。

### 注意

有关 Promises/A+ 规范的更多信息，您可以访问 [`promisesaplus.com/`](https://promisesaplus.com/)。

最终，Promises/A+ 规范作为 JavaScript 第 6 版的一部分发布，通常称为 ES6，于 2015 年 6 月发布为标准。因此，Promises/A+ 开始在浏览器中原生实现，不再需要使用自定义的第三方库，并推动大多数现有库升级其语义。截至撰写本书时，几乎所有现代浏览器都提供了原生的 Promises/A+ 兼容实现，除了 IE11，使其可以供超过 65% 的网络用户直接使用。

### 注意

关于浏览器中采用 A+ Promises 的更多信息，您可以访问 [`caniuse.com/#feat=promises`](http://caniuse.com/#feat=promises)。

使用现在原生实现的 ES6 A+ Promises 重写 `getRandomNumberAsync()` 函数将如下所示：

```js
function getRandomNumberAsync (max) { 
    return new Promise(function (resolve, reject) { 
        var runFor = 1000 + Math.random() * 1000; 
        setTimeout(function() { 
            var result = Math.random() * max; 
            resolve(result); 
        }, runFor); 
    }); 
} 

getRandomNumberAsync(10).then(function(number) { 
    console.log(number); // returns a number between 0 and 10 
});
```

正如你所看到的，ES6 / A+ Promises 是通过使用 Promise 构造函数和 `new` 关键字创建的。构造函数被调用时带有一个函数作为参数，这使得闭包可以访问到 Promise 被创建的上下文的变量，同时也可以通过参数访问 `resolve()` 和 `reject()` 函数，这是改变新创建的 Promise 状态的唯一方法。在 `setTimeout()` 函数触发其回调后，将用生成的随机数作为参数调用 `resolve()` 函数，将 Promise 对象的状态更改为已完成。最后，我们函数的调用者使用返回的 Promise 的 `then()` 方法，方式与我们之前使用 jQuery 的实现完全相同。

### 比较 jQuery 和 A+ Promises

我们将深入逐步分析 jQuery 和 A+ Promise API 的核心概念，并通过两者的代码进行逐行对比。这将是一个非常有价值的资料，因为在 Promises 的实现逐渐适应 ES6 A+ 规范时，你还可以将其作为参考。

从一开始就了解这两种变体的差异的需求似乎更为重要，因为 jQuery 团队已经宣布版本 3.0 的库将具有符合 Promises/A+ 规范的实现。具体而言，在编写本书时，第一个 beta 版本已经发布，这使得迁移的时间似乎更近了。

### 注意

关于 jQuery v3.0 A+ Promises 实现的更多信息，请访问 [`blog.jquery.com/2016/01/14/jquery-3-0-beta-released/`](http://blog.jquery.com/2016/01/14/jquery-3-0-beta-released/)。

两种实现之间最明显的区别之一是创建新 Promises 的方式。正如我们所见，jQuery 使用 `$.Deferred()` 函数像一个工厂一样创建了一个更复杂的对象，该对象直接提供对 Promise 状态的访问，并最终使用单独的方法提取实际的 Promise。另一方面，A+ Promises 使用 `new` 关键字和一个函数作为参数，运行时将使用 `resolve()` 和 `reject()` 函数作为参数调用该函数：

```js
var d = $.Deferred(); 
setTimeout(function() { 
    d.resolve(7); 
}, 2000); 
var p = d.promise(); // jQuery Promise

var p = new Promise(function(resolve, reject) { // Promises/A+
    setTimeout(function() { 
        resolve(7); 
    }, 2000); 
});
```

此外，jQuery 还提供了另一种创建类似 A+ Promises 工作方式的 Promise 的方法。在这种情况下，`$.Deferred()` 可以被调用，并以函数作为参数，该函数接收 Deferred 对象作为参数：

```js
var d = $.Deferred(function (deferred) { 
    setTimeout(function() { 
        deferred.resolve(7); 
    }, 2000); 
}); 
var p = d.promise(); 
```

正如我们之前讨论的那样，Promise 的第二种可能结果是被 Rejected，这个特性很好地配合了 JavaScript 在同步编程中的经典异常。拒绝一个 Promise 通常用于在处理结果时发生错误的情况，或者在结果无效的情况下。虽然 ES6 Promises 在其构造函数传递给函数的参数中提供了一个 `reject()` 函数，但在 jQuery 的实现中，`reject()` 方法仅简单地在 Deferred 对象本身上暴露。

```js
var p = $.Deferred(function (deferred) { 
    deferred.reject(new Error('Something happened!')); 
}).promise(); 

var p = new Promise(function(resolve, reject) { 
    reject(new Error('Something happened!')); 
});
```

在两种实现中，可以使用 `then()` 方法检索 Promise 的结果，该方法可以用两个函数作为参数调用，一个用于处理 Promise 被 Fulfill 的情况，另一个用于处理其被 Rejected 的情况：

```js
p.then(function(result) { // works the same in jQuery & ES6
    console.log(result); 
}, function(error) { 
    console.error('An error occurred: ', error); 
});
```

两种实现还提供了方便的方法来处理 Promise 被 Rejected 的情况，但使用不同的方法名。ES6 Promises 提供了 `catch()` 方法，很好地配合了 try...catch JavaScript 表达式，而 jQuery 的实现则为相同的目的提供了 `fail()` 方法：

```js
p.fail(function(error) { // jQuery
    console.error(error); 
}); 

p.catch(function(error) { // ES6
    console.error(error); 
});
```

此外，作为 jQuery 独有的特性，jQuery Promises 还暴露了 `done()` 和 `always()` 方法。提供给 `done()` 的回调在 Promise 被 Fulfill 时被调用，并且等同于使用带有单个参数的 `then()` 方法，而 `always()` 方法的回调在 Promise 被 settled 时被调用，无论其结果如何。

### 注意

要了解更多关于 `done()` 和 `always()` 的信息，您可以访问 [`api.jquery.com/deferred.done`](http://api.jquery.com/deferred.done) 和 [`api.jquery.com/deferred.always`](http://api.jquery.com/deferred.always)。

最后，两种实现都提供了一个简单的方法，直接创建已经 Resolved 或 Rejected 的 Promises。这可以作为实现复杂同步方案的起始值，或者作为使同步函数操作像异步函数一样的简单方法：

```js
var pResolved = $.Deferred().resolve(7).promise(); // jQuery
var pRejected = $.Deferred().reject(new Error('Something happened!')).promise(); 

var pResolved = Promise.resolve(7); // ES6
var pRejected = Promise.reject(new Error('Something happened!'));
```

## 高级概念

Promises 的另一个关键概念是使它们独特并极大地增加它们的实用性的能力，即轻松创建几个 Promise 的组合，这些 Promise 又是 Promise 本身。组合有两种形式，串行组合将 Promises 连接在一起，而并行组合则使用特殊方法将并发 Promises 的解决方案合并为一个新的解决方案。正如我们在本章前面看到的那样，使用传统的回调方法很难实现这样的同步方案。另一方面，Promises 试图以更方便和可读的方式解决这个问题。

# 链接 Promises

每次调用`then()`方法都会返回一个新的 Promise，其最终状态和结果取决于调用`then()`方法的 Promise，但也取决于附加的回调返回的值。这使我们能够通过连续连接它们来组合 Promise，从而使我们能够轻松地编排异步和同步代码，其中每个链接步骤将其结果传播到下一个步骤，并允许我们以可读且声明性的方式构建最终结果。

现在让我们继续分析调用`then()`方法的不同方式。由于我们将专注于通过链式调用进行 Promise 组合的概念，这与 jQuery 和 ES6 Promises 的工作方式相同，所以假设有一个`p`变量，它保存了由以下代码行之一创建的 Promise 对象：

```js
var p = $.Deferred().resolve(7).promise(); 
//or 
var p = Promise.resolve(7);
```

展示链接能力的最简单用例是调用的回调返回一个（非 promise）值。新创建的 Promise 使用返回的值作为其结果，同时保留与调用`then()`方法的 Promise 相同的状态：

```js
p.then(function(x) { // works the same in jQuery & ES6
    console.log(x); // logs 7 
    return x * 3; 
}).then(function(x) { 
    console.log(x); // logs 21 
});
```

需要牢记的一个特殊情况是，不返回任何结果的函数会被处理为返回`undefined`。这实质上从新返回的 Promise 中删除了结果值，现在只保留了父级解决状态：

```js
p.then(function(x) { // works the same in jQuery & ES6
    console.log(x); // logs 7 
}).then(function(x) { 
    console.log(x); // logs undefined 
});
```

在调用回调函数返回另一个 Promise 的情况下，其状态和结果将用于由`then()`方法返回的 Promise：

```js
p.then(function(x) { // for jQuery Promises
    console.log(x); // logs 7 
    var d2 = $.Deferred(); 
    setTimeout(function() { 
        d2.resolve(x*3); 
    }, 2000); 
    return d2.promise(); 
}).then(function(x) { 
    console.log(x); // logs 21 
}); 

p.then(function(x) { // for the A+ Promises
    console.log(x); // logs 7 
    return new Promise(function(resolve) { 
        setTimeout(function() { 
            resolve(x*3); 
        }, 2000); 
    }); 
}).then(function(x) { 
    console.log(x); // logs 21 
});
```

前面的代码示例演示了 jQuery 和 A+ Promises 的实现方式，两者都具有相同的结果。在两种情况下，都从第一个`then()`方法调用中将**7**记录到控制台，并返回一个新的 Promise，稍后将使用`setTimeout()`解析它。 2000 毫秒后，`setTimeout()`将触发其回调，返回的 Promise 将以`21`作为值解析，并在此时，`21`也将记录在控制台中。

还有一件额外需要注意的事情是，原始 Promise 已经被解决，而且没有为链接的`then()`方法提供适当的回调。在这种情况下，新创建的 Promise 解决为相同的状态和结果，就像在其中调用`then()`方法的 Promise 一样：

```js
p.then(null, function (error) { // works the same in jQuery & ES6
    console.error('An error happened!');// does not run, since the promise is resolved
}).then(function(x) { 
    console.log(x); // logs 7 
});
```

在前面的示例中，作为`then()`方法的第二个参数传递的具有`console.error`语句的回调不会被调用，因为 Promise 解析为 7 作为其值。结果，链的回调最终接收到一个新的 Promise，该 Promise 也以`7`作为其值解析并在控制台中记录。要深入了解 Promise 链式调用的工作原理，有一件事需要牢记，即在所有情况下`p != p.then()`。

## 处理抛出的错误

链接的最终概念定义了在调用 `then()` 回调时抛出异常的情况。Promise/A+ 规范定义了新创建的 Promise 被拒绝，其结果是抛出的 `Error`。此外，拒绝将在整个 Promise 链中传播，使我们能够仅在链的末尾附近定义错误处理，就能得到有关链中任何错误的通知。

不幸的是，这在撰写本书时最新稳定版本的 jQuery 中并不一致，该版本为 v2.2.0：

```js
$.Deferred().resolve().promise().then(function() { 
    throw new Error('Something happened!'); 
    // the execution stops here
}).then(null, function(x) { 
    console.log(x); // nothing gets printed
}); 

$.Deferred().resolve().promise().then(function() { 
    try { // this is a workaround 
        throw new Error('Something happened!'); 
    } catch (e) { 
        return $.Deferred().reject(e).promise(); 
    } 
}).then(function(){ 
    console.log('Success'); // not printed 
}).then(null, function(x) { // almost equivalent to .fail()
    console.log(x); // logs 'Something happened!'' 
}); 

Promise.resolve().then(function() { 
    throw new Error('Something happened!'); 
}).then(function(){ 
    console.log('Success'); // not printed 
}).then(null, function(x) { // equivalent to .catch()
    console.log(x); // logs 'Something happened!''
});
```

在第一种情况下，抛出的异常会停止 Promise 链的执行。唯一的解决方法可能是在传递给 `then()` 方法的回调中显式添加 try...catch 语句，如所示的第二种情况所示。

## 加入 Promise

另一种并发执行 Promise 的编排方式是将它们组合在一起。举个例子，假设存在两个 Promise，p1 和 p2，在分别经过 2000 和 3000 毫秒后以 7 和 11 作为它们的值被解决。由于这两个 Promise 是同时执行的，所以组合后的 Promise 只需要 3000 毫秒就能被解决，因为它是这两个持续时间中较大的一个：

```js
// jQuery
$.when(p1, p2).then(function(result1, result2) { 
    console.log('p1', result1); // logs 7 
    console.log('p2', result2); // logs 11 
    // this can be used to make our code look like A+ 
    var results = arguments;
}); 

// A+ 
Promise.all([p1, p2]).then(function(results) { 
    console.log('p1', results[0]); // logs 7 
    console.log('p2', results[1]); // logs 11 
});
```

两种 Promise API 都提供了一个专门的函数，允许我们轻松创建 Promise 组合并检索组合的单个结果。当所有部分都被解决时，组合后的 Promise 被解决，而当任何一个部分被拒绝时，它被拒绝。不幸的是，这两种 Promise API 不仅在函数的名称上有所不同，而且在调用方式和提供结果的方式上也有所不同。

jQuery 实现提供了 `$.when()` 方法，可以用任意数量的参数来调用它们要组合的内容。通过在组合后的 jQuery Promise 上使用 `then()` 方法，我们可以在组合作为整体时得到通知，并访问每个单独的结果作为回调的参数。

另一方面，A+ Promise 规范为我们提供了 `Promise.all()` 方法，它用一个数组作为其单个参数调用，该数组包含我们要组合的所有 Promise。返回的组合 Promise 与我们迄今为止看到的 Promise 没有任何区别，并且 `then()` 方法的回调以一个数组作为其参数被调用，该数组包含组合中所有 Promise 的结果。

## jQuery 如何使用 Promise

在 jQuery 添加 Promise 实现到其 API 后，它还开始通过其 API 的其他异步方法来公开它。也许最著名的例子就是 `$.ajax()` 系列方法，它返回一个 jqXHR 对象，这是一个专门的 Promise 对象，还提供了一些与 AJAX 请求相关的额外方法。

### 注意

有关 jQuery 的 `$.ajax()` 方法和 jqXHR 对象的更多信息，您可以访问 [`api.jquery.com/jQuery.ajax/#jqXHR`](http://api.jquery.com/jQuery.ajax/#jqXHR)。jQuery 团队还决定更改库的几个内部部分的实现以使用 Promises，以改进其实现。首先，`$.ready()` 方法使用 Promises 实现，以便提供的回调即使在其调用之前页面已加载很长时间也会触发。此外，jQuery 提供的一些复杂动画内部使用 Promises 作为动画队列的顺序部分执行的首选方式。

## 将 Promises 转换为其他类型

使用多个不同的 JavaScript 库进行开发往往会使得我们的项目中出现多种 Promise 实现，而不幸的是，它们往往对参考 Promises 规范的遵从程度不同。组合不同库方法返回的 Promise 往往会导致难以跟踪和解决的问题，因为它们的实现不一致。

为了避免在这种情况下造成混淆，不建议在尝试组合它们之前将所有 Promises 转换为单一类型。对于这种情况，建议使用 Promises/A+ 规范，因为它不仅被社区广泛接受，而且还是 JavaScript 的新发布版本（ES6 语言规范）的一部分，已经在许多浏览器中本地实现。

### 转换为 Promises/A+

例如，让我们看看如何将 jQuery Promise 转换为大多数最新浏览器中可用的 A+ Promise：

```js
var jqueryPromise = $.Deferred().resolve('I will be A+ compliant').promise(); 
var p = Promise.resolve(jqueryPromise); 
p.then(function(result) { 
    console.log(result); 
});
```

在上述示例中，`Promise.resolve()` 方法检测到它已被调用并带有一个 "thenable"，并且新创建的 A+ Promise 将其状态和结果绑定到所提供的 jQuery Promise 的状态和结果。这本质上相当于执行以下操作：

```js
var p = new Promise(function (resolve, reject) { 
    jqueryPromise.then(resolve, reject); 
});
```

当然，这不仅限于通过直接调用 `$.Deferred()` 方法创建的 Promises。上述技术也可以用于转换由任何 jQuery 方法返回的 Promises。例如，以下是它与 `$.getJSON()` 方法的使用方式：

```js
var aPlusAjaxPromise = Promise.resolve($.getJSON('AjaxContent.json')); 
aPlusAjaxPromise.then(function(result) { 
    console.log(result); 
}); 
```

### 转换为 jQuery Promises

尽管我通常不建议这样做，但也有可能将任何 Promise 转换为 jQuery 变体。新创建的 jQuery Promise 接收 jQuery 提供的所有额外功能，但转换不像前一个那么直接：

```js
var aPromise = Promise.resolve('I will be a jQuery Promise'); 
var p = $.Deferred(function (deferred) { 
    aPromise.then(function(result) { 
        return deferred.resolve(result); 
    }, function(error) { 
        return deferred.reject(error); 
    }); 
}).promise();
p.then(function(result) { 
    console.log(result); 
});
```

仅在需要扩展已使用 jQuery Promises 实现的大型 Web 应用程序的情况下，才应使用上述技术。另一方面，您还应考虑升级此类实现，因为 jQuery 团队已经宣布库的 3.0 版本将具有 Promises/A+ 兼容的实现。

### 注意

要了解有关 jQuery v3.0 A+ Promises 实现的更多信息，您可以访问 [`blog.jquery.com/2016/01/14/jquery-3-0-beta-released/`](http://blog.jquery.com/2016/01/14/jquery-3-0-beta-released/)。

## 总结 Promise 的好处

总的来说，使用 Promises 而不是简单的回调的好处包括：

+   有一个统一的方法来处理异步调用的结果

+   有用于使用回调的可预测的调用参数

+   为 Promise 的每个结果附加多个处理程序的能力

+   即使 Promise 已经被解析（或拒绝），也保证适当的附加处理程序将执行

+   链接异步操作的能力，使它们按顺序运行

+   轻松创建异步操作的组合，使它们并发运行的能力

+   处理 Promise 链中错误的便捷方式

使用返回 Promise 的方法消除了直接将一个上下文的函数传递给另一个上下文作为调用参数以及哪些参数用作成功和错误回调的问题。此外，我们在阅读关于方法调用参数的文档之前，已经在一定程度上了解到了如何获取返回 Promise 的任何操作的结果，通过使用 `then()` 方法。

较少的参数通常意味着较少的复杂性、更小的文档和每次想要执行方法调用时的搜索量较少。更好的是，很有可能只有一个或几个参数，使得调用更加合理和可读。异步方法的实现也变得更加简单，因为不再需要接受回调函数作为额外参数或者需要正确地使用结果来调用它们。

# 总结

在本章中，我们分析了用于编写异步和并发过程的开发模式。我们还学习了如何有效地编排执行按顺序或并行运行的异步过程。

首先，我们对 JavaScript 编程中如何使用回调进行了复习，并且了解了它们是 Web 开发的一个组成部分。我们分析了在大型和复杂实现中使用它们时的好处和局限性。

就在这之后，我们介绍了 Promise 的概念。我们学习了 jQuery 的 Deferred 和 Promise API 的工作原理，以及它们与 ES6 Promises 的区别。我们还看到了它们在 jQuery 内部的使用位置和方式，作为它们如何导致更可读的代码并简化这样复杂实现的一个例子。

在下一章中，我们将继续学习如何在我们的应用程序中设计、创建和使用 MockObjects 和 Mock Services。我们将分析一个适当的 Mock 对象应该具有的特征，并了解它们如何被用作代表性用例甚至是我们代码的测试用例。


# 第八章：模拟对象模式

本章中，我们将展示模拟对象模式，这是一种促进应用程序开发的模式，而不实际成为最终实现的一部分。我们将学习如何设计、创建和使用这种行业标准的设计模式，以便更快地协调和完成多部分 jQuery 应用程序的开发。我们将分析一个合适的模拟对象应该具有的特征，并了解它们如何被用作代表性用例，甚至是我们代码的测试用例。

我们将看到良好的应用程序架构如何使我们更容易使用模拟对象和服务，通过匹配应用程序的各个部分，并且意识到在开发过程中使用它们的好处。到本章结束时，我们将能够创建模拟对象和服务，以加速我们应用程序的实现，并且在所有部分完成之前就对其整体功能有所了解。

在本章中，我们将：

+   介绍模拟对象和模拟服务模式

+   分析模拟对象和服务应该具有的特征

+   了解为什么它们与具有良好架构的应用程序更匹配

+   学习如何在 jQuery 应用程序中使用它们作为推动开发并加速开发的一种方式

# 介绍模拟对象模式

模拟对象模式的关键概念在于创建和使用一个模拟行为更复杂的对象的虚拟对象，该对象是（或将成为）实现的一部分。模拟对象应该具有与实际（或真实）对象相同的 API，使用相同的数据结构返回类似的结果，并且在其方法如何改变其公开状态（属性）方面操作方式相似。

模拟对象通常在应用程序的早期开发阶段创建。它们的主要用途是使我们能够继续开发一个模块，即使它依赖于尚未实现的其他模块。模拟对象也可以被描述为实现之间交换的数据的原型，起着开发人员之间的契约作用，并且促进了相互依赖模块的并行开发。

### 提示

就像模块模式的原则解耦了应用程序不同部分的实现一样，创建和使用模拟对象和模拟服务也解耦了它们的开发。

在开始实施每个模块之前为其创建模拟对象清晰地定义了应用程序将使用的数据结构和 API，消除了任何误解，并使我们能够检测到所提供的 API 中的不足。

### 提示

在开始实际实现之前定义描述问题所需的数据结构，使我们能够专注于应用程序的需求，并了解其整体复杂性和结构。

通过使用为原始实现创建的 Mock 对象，您可以在任何代码更改后始终测试实现的任何部分。通过在修改后的方法上使用 Mock 对象，您可以确保原始用例仍然有效。当修改后的实现是涉及多阶段的用例的一部分时，这非常有用。

如果模块的实现发生变化并导致应用程序其他部分表现异常，Mock 对象尤其有用，可以用于追踪错误。通过使用现有的 Mock 对象，我们可以轻松识别与原始规范不符的模块。此外，相同的 Mock 对象可用作高质量测试用例的基础，因为它们通常包含更真实的样本数据，特别适用于团队遵循测试驱动开发（TDD）范例。

### 注意

在测试驱动开发（TDD）中，开发人员首先为需要添加的用例或新功能定义测试用例，然后通过尝试满足所创建的测试用例来实施。更多信息，请访问：[`www.packtpub.com/books/content/overview-tdd`](https://www.packtpub.com/books/content/overview-tdd)。

Mock 对象模式通常被前端网络开发人员用于将客户端开发与后端将公开的网络服务解耦。因此，导致了一些风趣的评论，比如：

> “网络服务总是拖延并突然改变，所以使用 Mock 代替。”

总结所有这些，创建 Mock 对象和服务的主要原因包括：

+   实际对象或服务尚未实现。

+   实际对象难以为特定用例设置。

+   我们需要模拟罕见或非确定性的行为。

+   实际对象的行为难以复现，比如网络错误或 UI 事件。

# 在 jQuery 应用程序中使用 Mock 对象

为了展示 Mock 对象模式在开发多部分应用程序时的用法，我们将扩展仪表板示例，如我们在第四章 *用模块模式进行分而治之*中看到的，以显示来自网络开发会议的 YouTube 视频的缩略图。视频引用被分为四个预定义类别，并根据当前的类别选择显示相关按钮，如下所示：

![在 jQuery 应用程序中使用 Mock 对象](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsn-ptn/img/00031.jpeg)

需要引入到 HTML 和 CSS 中的更改是最小的。与第四章 *用模块模式进行分而治之*现有实现相比，上述实现唯一需要额外的 CSS 是与缩略图宽度相关的：

```js
.box img { 
  width: 100%; 
}
```

HTML 中的变化旨在组织每个类别的`<button>`元素。这个变化将使我们的实现更加直观，因为类别及其项不再在 HTML 中静态定义，而是动态创建，由可用数据驱动。

```js
      <!-- … -->
      <section class="dashboardCategories"> 
        <select id="categoriesSelector"></select> 
        <div class="dashboardCategoriesList"></div> 
        <div class="clear"></div> 
      </section> 
      <!-- … -->
```

在上面的 HTML 片段中，带有`dashboardCategoriesList` CSS 类的`<div>`元素将被用作不同视频类别的分组按钮的容器。在涵盖了 UI 元素后，让我们现在转向 JavaScript 实现的分析。

## 定义实际服务需求

在我们的仪表板中显示的视频引用可以从各种来源检索到。例如，您可以直接调用 YouTube 的客户端 API 或通过后端 Web 服务进行 AJAX 调用。在所有上述情况下，将此数据检索机制抽象为一个单独的模块被认为是一种良好的实践，遵循前几章的代码结构建议。

由于这个原因，我们需要向现有实现添加一个额外的模块。这将是一个服务，负责提供允许我们从每个类别中检索最相关视频并单独加载每个视频信息的方法。这将通过分别使用`searchVideos()`和`getVideo()`方法来实现。

正如我们已经提到的，每个实现的一个最重要的阶段，尤其是在并行开发的情况下，是对要使用的数据结构进行分析和定义。由于我们的仪表板将使用 YouTube API，我们需要创建一些遵循其数据结构规则的示例数据。在检查了 API 之后，我们得到了一组需要用于我们的仪表板的字段的子集，并且可以继续创建一个具有模拟数据的 JSON 对象来演示所使用的数据结构：

```js
{ 
  "items": [{ 
    "id": { "videoId": "UdQbBq3APAQ" }, 
    "snippet": { 
      "title": "jQuery UI Development Tutorial: jQuery UI Tooltip | packtpub.com", 
      "thumbnails": { 
        "default": { "url": "https://i.ytimg.com/vi/UdQbBq3APAQ/default.jpg" }, 
        "medium": { "url": "https://i.ytimg.com/vi/UdQbBq3APAQ/mqdefault.jpg" }, 
        "high": { "url": "https://i.ytimg.com/vi/UdQbBq3APAQ/hqdefault.jpg" } 
      } 
    } 
  }/*,...*/]
}
```

### 注意

有关 YouTube API 的更多信息，请访问：[`developers.google.com/youtube/v3/getting-started`](https://developers.google.com/youtube/v3/getting-started)。

我们的服务提供两种核心方法，一种用于在指定类别中搜索视频，另一种用于检索特定视频的信息。用于搜索方法的示例对象结构用于检索一组相关项目，而用于检索单个视频信息的方法使用每个单独项目的数据结构。生成的视频信息检索实现位于名为`videoService`的单独模块中，该模块将在`dashboard.videoService`命名空间上可用，我们的 HTML 将包含类似以下的`<script>`引用：

```js
<script type="text/javascript" src="img/dashboard.videoservice.js"></script>
```

## 实现模拟服务

改变服务实现的`<script>`引用与模拟服务之间的相互转换应该使我们得到一个可工作的应用程序，帮助我们在实际视频服务实现完成之前进展和测试其他实现。因此，模拟服务需要使用相同的`dashboard.videoService`命名空间，但其实现应该在一个名为`dashboard.videoservicemock.js`的不同命名的文件中，它简单地添加了“mock”后缀。

正如我们先前提到的，将所有的模拟数据放在一个单独的变量下是一个很好的做法。此外，如果有很多模拟对象，通常会将它们放在一个完全不同的文件中，带有嵌套的命名空间。在我们的案例中，包含模拟数据的文件名为`dashboard.videoservicemock.mockdata.js`，其命名空间为`dashboard.videoService.mockData`，同时公开了`searches`和`videos`属性，这些属性将被我们的模拟服务的两个核心方法使用。

即使模拟服务的实现应该简单，它们也有自己的复杂性，因为它们需要提供与目标实现相同的方法，接受相同的参数，并且看起来好像它们是以完全相同的方式操作的。例如，在我们的案例中，视频检索服务需要是异步的，其实现需要返回 Promises：

```js
(function() { // dashboard.videoservicemock.js
    'use strict'; 

    dashboard.videoService = dashboard.videoService || {}; 

    dashboard.videoService.searchVideos = function(searchKeywords) { 
        return $.Deferred(function(deferred) { 
            var searches = dashboard.videoService.mockData.searches; 
            for (var i = 0; i < searches.length; i++) { 
                if (searches[i].keywords === searchKeywords) { 
                    // return the first matching search results 
                    deferred.resolve(searches[i].data); 
                    return; 
                } 
            } 
            deferred.reject('Not found!'); 
        }).promise(); 
    }; 

    dashboard.videoService.getVideo = function(videoTitle) { 
        return $.Deferred(function(deferred) { 
            var videos = dashboard.videoService.mockData.allVideos;
            for (var i = 0; i < videos.length; i++) { 
                if (videos[i].snippet.title === videoTitle) { 
                    // return the first matching item 
                    deferred.resolve(videos[i]); 
                    return; 
                } 
            } 
            deferred.reject('Not found!'); 
        }).promise(); 
    }; 

    var videoBaseUrl = 'https://www.youtube.com/watch?v='; 
    dashboard.videoService.getVideoUrl = function(videoId) { 
        return videoBaseUrl + videoId; 
    }; 
})(); 
```

如上面模拟服务的实现所示，`searchVideos()`和`getVideo()`方法正在遍历带有模拟数据的数组，并返回一个 Promise，该 Promise 在找到合适的模拟对象时被解析，或者在未找到这样的对象时被拒绝。最后，你可以在下面看到包含模拟对象的子模块的代码，遵循了我们先前描述的数据结构。注意，我们将所有类别的模拟对象都存储在`allVideos`属性中，以便通过模拟的`getVideo()`方法更简单地进行搜索。

```js
(function() { // dashboard.videoservicemock.mockdata.js
    'use strict'; 

    dashboard.videoService.mockData = dashboard.videoService.mockData || {}; 

    dashboard.videoService.mockData.searches = [{ 
        keywords: 'jQuery conference', 
        data: { 
            "items": [/*...*/] 
        } 
    }/*,...*/]; 

    var allVideos = []; 
    var searches = dashboard.videoService.mockData.searches; 
    for (var i = 0; i < searches.length; i++) { 
        allVideos = allVideos.concat(searches[i].data.items);
    } 

    dashboard.videoService.mockData.allVideos = allVideos; 
})(); 
```

通过对一些模拟服务实现的实验，你将在很短的时间内熟悉它们的常见实现模式。除此之外，你将能够轻松地创建模拟对象和服务，帮助你设计应用程序的 API，通过使用模拟测试它们，最终确定每个用例的最佳匹配方法和数据结构。

### 提示

**使用 jQuery Mockjax 库**

jQuery Mockjax 插件库（可在[`github.com/jakerella/jquery-mockjax`](https://github.com/jakerella/jquery-mockjax)）专注于提供一种简单的方法来模拟或模拟 AJAX 请求和响应。如果你所需要的只是拦截对 Web 服务的 AJAX 请求并返回模拟对象，那么这将减少你完全实现自己的模拟服务所需的代码量。

## 使用模拟服务

为了向现有的仪表板实现添加我们之前描述的功能，我们需要对`categories`和`informationBox`模块进行一些更改，添加将使用我们服务的方法的代码。作为使用新创建的 Mock 服务的典型示例，让我们看一下`informationBox`模块中`openNew()`方法的实现：

```js
dashboard.informationBox.openNew = function(itemName) {
    var $box = $('<div class="boxsizer"><article class="box">' +
            '<header class="boxHeader">' +
                '<button class="boxCloseButton">&#10006;</button>' +
                itemName +
            '</header>' +
            '<div class="boxContent">Loading...</div>' +
        '</article></div>');
    $boxContainer.append($box);

    dashboard.videoService.getVideo(itemName).then(function(result) {
        var $a = $('<a>').attr('href', dashboard.videoService.getVideoUrl(result.id.videoId));
        $a.append($('<img />').attr('src', result.snippet.thumbnails.medium.url));
        $box.find('.boxContent').empty().append($a);
    }).fail(function() {
        $buttonContainer.html('An error occurred!');
    });
};
```

此方法首先以**加载中...**标签作为其内容打开一个新的信息框，并使用`dashboard.videoService.getVideo()`方法异步检索请求的视频的详细信息。最后，当返回的 Promise 得到解析时，将**加载中...**标签替换为包含视频缩略图的锚。

# 摘要

在这一章中，我们学习了如何设计、创建和使用我们应用程序中的 Mock 对象和 Mock 服务。我们分析了 Mock 对象应具有的特征，并理解了它们如何作为典型用例来使用。我们现在能够使用 Mock 对象和服务来加速我们应用程序的实现，并在其所有单个部分完成之前更好地了解其整体功能。

在下一章中，我们将介绍客户端模板化，并学习如何从可读模板在浏览器中高效生成复杂的 HTML 结构。我们将介绍`Underscore.js`和`Handlebars.js`，分析它们的约定，评估它们的特性，并找出哪一个更适合我们的口味。


# 第九章：客户端模板

本章将演示一些最常用的库，以更快速地创建复杂的 HTML 模板，同时使我们的实现在与传统字符串拼接技术相比更容易阅读和理解。我们将更详细地了解如何使用`Underscore.js`和`Handlebars.js`模板库，体验它们的约定，评估它们的特性，并找到最适合我们口味的。

本章结束时，我们将能够通过可读的模板在浏览器中有效地生成复杂的 HTML 结构，并利用每个模板库的独特特性。

在本章中，我们将：

+   讨论使用专门的模板库的好处

+   介绍当前客户端模板中的潮流，特别是使用 `<% %>` 和 `{{ }}` 作为占位符的家族中的顶级代表

+   以`Underscore.js`为例，介绍一族使用`<% %>`占位符的模板引擎

+   以`Handlebars.js`为例，介绍一族使用大括号 `{{ }}` 占位符的模板引擎

# 介绍 Underscore.js

`Underscore.js`是一个 JavaScript 库，提供了一系列实用方法，帮助 Web 开发人员更有效地工作，专注于应用程序的实际实现，而不必为重复的算法问题烦恼。 `Underscore.js`默认情况下通过全局命名空间的“`_`”标识符访问，这也正是它的名称的由来。

### 注意

与 jQuery 中的 `$` 标识符一样，underscore "`_`" 标识符也可以在 JavaScript 中作为变量名使用。

其中提供的实用程序函数之一是`_.template()`方法，它为我们提供了一种便利的方式，将特定值插入到遵循特定格式的现有模板字符串中。 `_.template()`方法在模板内部识别三种特殊的占位符符号，用于添加动态特性：

+   `<%= %>`符号用作在模板中插入变量或表达式值的最简单方式。

+   `<%- %>`符号对变量或表达式进行 HTML 转义，然后将其插入模板中。

+   `<% %>`标记用于执行任何有效的 JavaScript 语句作为模板生成的一部分。

`_.template()`方法接受遵循这些特征的模板字符串，并返回一个纯 JavaScript 函数，通常称为模板函数，可以使用包含将在模板中插入的值的对象调用。模板函数的调用结果是一个字符串值，这是提供的值在模板内插值的结果：

```js
var templateFn = _.template('<h1><%= title %></h1>');
var resultHtml = templateFn({ 
  title: 'Underscore.js example' 
});
```

例如，上面的代码返回`<h1>Underscore.js 示例</h1>`，等效于以下简写调用：

```js
var resultHtml = _.template('<h1><%= title %></h1>')({ 
  title: 'Underscore.js example' 
});
```

### 注意

关于`_.template`方法的更多信息，您可以在此处阅读文档：[`underscorejs.org/#template`](http://underscorejs.org/#template)。

使`Underscore.js`模板非常灵活的是`<% %>`符号，它允许我们执行任何方法调用，并且例如被用作在模板中创建循环的推荐方法。另一方面，过度使用此功能可能会向您的模板添加过多的逻辑，这是许多其他框架中的已知反模式，违反了**关注点分离**原则。

## 在我们的应用程序中使用 Underscore.js 模板

作为使用`Underscore.js`进行模板化的示例，我们现在将其用于重构仪表板示例中一些模块中发生的 HTML 代码生成，正如我们在之前的章节中所看到的。对现有实现所需的修改仅限于`categories`和`informationBox`模块，它们通过添加新元素来操作页面的 DOM 树。

此类重构可以应用的第一个地方是`categories`模块的`init()`方法。我们可以修改创建`<select>`类别的可用`<option>`的代码如下：

```js
var optionTemplate = _.template('<option value="<%= value %>"><%- title %></option>'); 
var optionsHtmlArray = [];
for (var i = 0; i < dashboard.categories.data.length; i++) { 
    var categoryInfo = dashboard.categories.data[i]; 
 optionsHtmlArray.push(optionTemplate({ 
 value: i, 
 title: categoryInfo.title 
 }));  
}
$categoriesSelector.append(optionsHtmlArray.join(''));
```

如您所见，我们遍历仪表板的类别，以创建并附加适当的`<option>`元素到`<select>`类别元素。在我们的模板中，我们使用`<%= %>`符号来表示`<option>`的`value`属性，因为我们知道它将保存一个不需要转义的整数值。另一方面，我们使用`<%- %>`符号来表示每个`<option>`的内容部分，以便为每个类别的标题进行转义，以防其值不是 HTML 安全字符串。

我们在`for`循环之外使用`_.template()`方法来创建一个单个编译的模板函数，在`for`循环的每次迭代中重复使用。这样一来，浏览器不仅仅执行一次`_.template()`方法，而且还会优化生成的模板函数，并使其在`for`循环中的每次后续执行速度更快。最后，我们使用`join('')`方法来将`optionsHtmlArray`变量的所有 HTML 字符串组合在一起，并通过单个操作将结果`append()`到 DOM 中。

实现相同结果的另一种可能更简单的方法是结合`<% %>`符号和`Underscore.js`提供的`_.each()`方法，使我们能够在模板本身中实现循环。这样，模板将负责对提供的类别数组进行迭代，将复杂性从模块的实现转移到模板中。

```js
var templateSource = ''.concat( 
 '<% _.each(categoryInfos, function(categoryInfo, i) { %>', 
 '<option value="<%= i %>"><%- categoryInfo.title %></option>', 
 '<% }); %>'); 
var optionsHtml = _.template(templateSource)({ 
    categoryInfos: dashboard.categories.data 
}); 
$categoriesSelector.append(optionsHtml);
```

如上面的代码所示，我们的 JavaScript 实现不再包含`for`循环，减少了其复杂性和所需的嵌套。只有一次对`_.template()`方法的调用，很好地将实现抽象为一个生成 HTML 并为所有类别渲染`<option>`元素的操作。您还可以看到这种技术与 jQuery 自身遵循的组合逻辑非常契合，其中方法旨在处理元素集合而不是单个项目。

### 将 HTML 模板与 JavaScript 代码分开

即使引入了上述所有改进，很快就会变得显而易见，在应用逻辑之间编写模板可能不是最佳的方法。一旦您的应用变得足够复杂，或者当您需要使用超过几行的模板时，实现起来会因为应用逻辑和 HTML 模板的混合而感到分散。

解决这个问题的更清晰的方法是将模板存储在页面其他部分的 HTML 代码旁边。这是朝着更好的**关注点分离**迈出的一大步，因为它适当地将呈现与应用逻辑隔离开来。

为了将 HTML 模板包含在不活动形式的网页中，我们需要使用一个宿主标签，这可以阻止它们被渲染，但也允许我们在需要时以程序方式检索其内容。为此，我们可以在页面的`<head>`或`<body>`内使用`<script>`标签，并指定除我们通常用于 JavaScript 代码的常见的`text/javascript`之外的任何`type`。这背后的操作原则是，浏览器在未识别其`type`属性的情况下不尝试解析、执行或呈现`<script>`标签的内容。经过一些实验，`Underscore.js`用户社区基本上采用了这种做法，并同意将`text/template`指定为这些`<script>`标签的首选类型，试图使这些实现在开发人员中更加统一。

### 提示

尽管`Underscore.js`既不是一个偏执的库，也不含有任何特定于模板变得可用的实现，但使用`text/template` `<script>`标签和/或 Ajax 请求都是有价值的技术，被广泛使用且被认为是最佳实践。

作为将复杂模板移入`<script>`标签中的受益示例，我们将重新构建`informationBox`模块的`openNew()`方法。如下所示，在下面的代码中，生成的`<script>`标签格式清晰，并且我们不再需要对多行模板的定义进行字符串拼接：

```js
<script id="box-template" type="text/template"> 
  <div class="boxsizer"> 
    <article class="box"> 
      <header class="boxHeader"> 
        <button class="boxCloseButton">&#10006;</button> 
        <%- itemName %> 
      </header> 
      <div class="boxContent">Loading...</div> 
    </article> 
  </div> 
</script>
```

将 HTML 模板移出我们的代码时的一个好的做法是编写一个抽象的机制来负责检索它们并提供编译后的模板函数。这种方法不仅将实现的其余部分与模板检索机制解耦，而且使其更少重复，并创建了一个专门设计为为应用程序的其余部分提供模板的集中方法。此外，正如我们下面可以看到的，这种方法还允许我们优化模板的检索方式，将好处传播到所有使用它们的地方。

```js
var templateCache = {}; 

function getEmbeddedTemplate(templateName) { 
    var compiledTemplate = templateCache[templateName]; 
    if (!compiledTemplate) { 
        var template = $('#' + templateName).html(); 
 compiledTemplate = _.template(template); 
        templateCache[templateName] = compiledTemplate; 
    } 
    return compiledTemplate; 
}

dashboard.informationBox.openNew = function(itemName) { 
 var boxCompiledTemplate = getEmbeddedTemplate('box-template'); 
    var boxHtml = boxCompiledTemplate({ 
        itemName: itemName 
    }); 
    var $box = $(boxHtml).appendTo($boxContainer); 

    /* ... */
};
```

如上所示的实现中，`informationBox` 模块的 `openNew()` 方法只是通过传递与请求模板相关联的唯一标识符来调用 `getEmbeddedTemplate()` 函数，并使用返回的模板函数生成新框的 HTML，最后将其附加到页面上。实现中最有趣的部分是 `getEmbeddedTemplate()` 方法，它使用 `templateCache` 变量作为字典来保存所有先前编译的模板函数。

第一步始终是检查请求的模板标识符是否存在于我们的模板缓存中。如果不存在，则搜索页面的 DOM 树以查找带有相关 ID 的 `<script>` 标签，并使用其 HTML 内容创建模板函数，然后将其存储在缓存中并返回给调用方。

请记住，在 HTML 模板的所有标识符中使用特定的前缀或后缀是一个好的做法，以避免与其他页面元素的 ID 冲突。为此，在上面的示例中，我们使用了 `-template` 作为我们框模板标识符的后缀。

理想情况下，模板提供程序方法的实现应该在一个单独的模块中，该模块将被应用程序的所有部分使用，但是，由于在我们的仪表板中只使用了一次，我们通过简单地使用一个函数来满足我们演示的需求。

# 引入 Handlebars.js

**Handlebars.js**，或简称 Handlebars，是一种专门的客户端模板库，使 Web 开发人员能够有效地创建语义化模板。使用 Handlebars 进行模板化会导致创建无逻辑的模板，这确保了视图和代码的隔离，有助于保持关注点分离原则。它与 Mustache 模板基本兼容，Mustache 是一个模板语言规范，随着时间的推移已经证明了其有效性，并且有许多主要编程语言的实现。此外，Handlebars 还提供了一组在 Mustache 模板规范之上的扩展，例如辅助方法和局部模板，作为扩展模板引擎并创建更有效模板的一种手段。

### 注意

你可以在[Handlebars 文档](http://handlebarsjs.com/)中查看所有 Handlebars 的文档。你可以在[JavaScript Mustache](https://github.com/janl/mustache.js/)中获取更多有关 Mustache 的信息。

Handlebars 提供的主要模板表示法是双花括号语法 `{{ }}`。由于 Handlebars 最初是为 HTML 模板设计的，所以默认情况下也适用于 HTML 转义，降低了未转义值可能到达模板并导致潜在安全问题的几率。如果需要特定部分的模板进行非转义的插值，我们可以使用三个花括号的表示法 `{{{ }}}`。

此外，由于 Handlebars 阻止我们直接从模板中调用方法，它为我们提供了定义和使用辅助方法和块表达式的能力，以涵盖更复杂的用例，同时帮助我们尽可能地保持模板的清晰和可读性。内置助手集包括 `{{#if }}` 和 `{{#each }}` 助手，它们允许我们非常轻松地对数组执行迭代，并根据条件更改模板的结果。

Handlebars 库的中心方法是 `Handlebars.compile()` 方法，它接受模板字符串作为参数，并返回一个函数，该函数可用于生成符合所提供模板形式的字符串值。然后，可以使用一个对象作为参数调用此函数（与 `Underscore.js` 中一样），其中的属性将用作对原始模板中定义的所有 Handlebars 表达式（花括号表示法）进行评估的上下文：

```js
var templateFn = Handlebars.compile('<h1>!!!{{ title }}!!!</h1>');
var resultHtml = templateFn({ 
  title: '> Handlebars example <'
});
```

作为示例，上述代码返回 `"<h1>!!!&gt; Handlebars example &lt;!!!</h1>"`，将插入的标题转换为安全的 HTML 字符串，但是当附加到页面的 DOM 树时，它将以正确的方式呈现。当然，如果我们不需要将编译后的模板函数的引用保留以供将来使用，则可以使用以下简写调用来实现相同的结果：

```js
var resultHtml = Handlebars.compile('<h1>!!!{{ title }}!!!</h1>')({ 
  title: '> Handlebars example <' 
});
```

## 在我们的应用程序中使用 Handlebars.js

作为使用 `Handlebars.js` 进行模板化的示例，并且为了展示它与 `Underscore.js` 模板的区别，我们现在将使用它来重构我们的仪表板示例，就像我们在前一节中所做的那样。与之前一样，重构仅限于 `categories` 和 `informationBox` 模块，这些模块通过添加新元素来操作页面的 DOM 树。

`categories` 模块的 `init()` 方法的重构实现应该如下所示：

```js
var optionTemplate = Handlebars.compile('<option value= "{{ value }}">{{ title }}</option>'); 
var optionsHtmlArray = []; 
for (var i = 0; i < dashboard.categories.data.length; i++) { 
    var categoryInfo = dashboard.categories.data[i]; 
 optionsHtmlArray .push(optionTemplate({ 
        value: i, 
        title: categoryInfo.title 
    })); 
}
$categoriesSelector.append(optionsHtmlArray.join(''));
```

首先，我们使用了`Handlebars.compile()`方法，该方法基于提供的模板字符串生成并返回模板函数。与我们在上一节中看到的`Underscore.js`的实现的主要区别在于，我们现在使用双花括号符号`{{ }}`来插值我们的模板中的值。除了外观上的差异外，`Handlebars.js`还默认执行 HTML 字符串转义，以尝试通过将转义作为其主要用例之一来消除 HTML 注入安全漏洞。

正如我们在本章前面所做的那样，我们将在`for`循环之外创建模板函数，并将其用于为每个`<option>`元素生成 HTML。所有生成的 HTML 字符串都被收集到一个数组中，最终通过一次操作使用`$.append()`方法将它们组合并附加到 DOM 树上。

减少我们实现复杂性的下一个渐进步骤是使用模板引擎本身的循环能力将迭代抽象化为我们的 JavaScript 代码之外：

```js
var templateSource = ''.concat( 
 '{{#each categoryInfos}}', 
 '<option value="{{@index}}">{{ title }}</option>', 
 '{{/each}}'); 
var optionsHtml = Handlebars.compile(templateSource)({ 
    categoryInfos: dashboard.categories.data 
}); 
$categoriesSelector.append(optionsHtml);
```

`Handlebars.js`库允许我们通过使用特殊的`{{#each }}`符号来实现这一点。在`{{#each }}`和`{{/each}}`之间，模板的上下文被更改以匹配迭代的每个单独对象，允许直接访问和插值`categoryInfos`数组中每个对象的`{{ title }}`。此外，为了访问循环计数器，Handlebars 提供了特殊的`@index`变量作为循环的上下文的一部分。

### 注意

您可以阅读[`handlebarsjs.com/reference.html`](http://handlebarsjs.com/reference.html)上的文档，获取 Handlebars 提供的所有特殊符号的完整列表。

### 将 HTML 模板与 JavaScript 代码分离

和大多数模板引擎一样，Handlebars 也让我们将模板与应用程序的 JavaScript 实现隔离开，并通过将它们包含在页面 HTML 中的`<script>`标签中，在浏览器中传递它们。此外，Handlebars 有一定的偏好，更喜欢特殊的`text/x-handlebars-template`作为所有包含 Handlebars 模板的`<script>`标签的 type 属性。例如，这是根据库推荐的方式定义仪表板框的模板的方式：

```js
<script id="box-template" type="text/x-handlebars-template"> 
  <div class="boxsizer"> 
    <article class="box"> 
      <header class="boxHeader"> 
        <button class="boxCloseButton">&#10006;</button> 
        {{ itemName }} 
      </header> 
      <div class="boxContent">Loading...</div> 
    </article> 
  </div> 
</script>
```

### 提示

尽管如果为`<script>`标签指定了不同的`type`，我们的实现仍然可以正常工作，但遵循库的指南显然可以使开发人员之间的实现更加统一。

正如我们在本章前面所做的那样，我们将遵循最佳实践，创建一个单独的函数负责在应用程序中需要的任何地方提供模板：

```js
var templateCache = {}; 

function getEmbeddedTemplate(templateName) { 
    var compiledTemplate = templateCache[templateName]; 
    if (!compiledTemplate) { 
        var template = $('#' + templateName).html(); 
 compiledTemplate = Handlebars.compile(template); 
        templateCache[templateName] = compiledTemplate; 
    } 
    return compiledTemplate; 
} 

dashboard.informationBox.openNew = function(itemName) { 
    var boxCompiledTemplate = getEmbeddedTemplate('box-template'); 
    var boxHtml = boxCompiledTemplate({ 
        itemName: itemName 
    }); 
    var $box = $(boxHtml).appendTo($boxContainer); 

    /* ... */ 
};
```

正如你所看到的，该实现与我们在本章前面看到的`Undescore.js`示例基本相同。唯一的区别是我们现在使用`Handlebars.compile()`方法来从检索到的模板生成已编译模板函数。

### 预编译模板

Handlebars 库的一个额外功能是支持模板预编译。这使我们可以使用一个简单的终端命令预先生成所有模板函数，然后让我们的服务器将它们传送到浏览器，而不是实际的模板。这样，浏览器就可以直接使用预编译的模板，而不需要对每个单独的模板进行编译，使得库和应用程序的执行速度更快。

为了预编译我们的模板，我们首先需要将它们放在单独的文件中。 Handlebars 文档建议我们的文件使用`.handlebars`扩展名，但如果更喜欢，我们仍然可以使用`.html`扩展名。在我们的开发机器上安装编译工具（使用`npm install handlebars -g`），我们可以在终端中发出以下命令来编译模板：

```js
handlebars box-template.handlebars -f box-template.js

```

这将生成实际上是一个将模板添加到`Handlebars.templates`的迷你模块定义的`box-template.js`文件。生成的文件可以像常规 JavaScript 文件一样合并和最小化，并且当被浏览器加载时，模板函数将通过`Handlebars.templates['box-template']`属性可用。

### 注意

请记住，如果模板使用`.html`扩展名，则预编译的模板函数将通过`Handlebars.templates['box-template.html']`属性可用。

正如您所见，使用模板提供者函数有助于将现有应用程序迁移到预编译模板，因为它允许我们封装模板的检索方式。只需将`getEmbeddedTemplate()`更改为以下内容即可将其迁移到预编译模板：

```js
function getEmbeddedTemplate(templateName) { 
    return Handlebars.templates[templateName]; 
}
```

### 注意

有关 Handlebars 中模板预编译的更多信息，请阅读：[`handlebarsjs.com/precompilation.html`](http://handlebarsjs.com/precompilation.html)。

# 异步检索 HTML 模板

掌握客户端模板的最后一步是一种开发实践，该实践允许我们动态加载模板并在已加载的网页中使用它们。这种方法可以导致比在每个页面的 HTML 源文件中将所有可用模板嵌入为`<script>`标签的方法更具可伸缩性的实现。

这种技术的关键要素是仅在需要呈现网页时加载每个模板，通常是在用户操作之后。这种方法的主要优点是：

+   初始页面加载时间减少，因为页面的 HTML 更小。如果我们的应用程序有很多只在特定情况下使用的模板，例如在特定用户交互后，页面尺寸减小的收益将变得更大。

+   用户只在实际使用模板时才会下载模板。通过这种方式，可以减少每个页面加载的总下载资源的大小。

+   对于已经加载的模板的后续请求不会导致额外的下载，因为浏览器的 HTTP 缓存机制将返回缓存的资源。此外，由于浏览器缓存用于所有 HTTP 请求，无论它们来自哪个页面，用户在使用我们的 Web 应用程序时只需下载所需的模板一次。

由于其对用户体验和可伸缩性的好处，这种技术被最流行的电子邮件和社交网络网站广泛使用，根据用户的操作动态加载各种 HTML 模板和 JavaScript 模块。

### 注意

关于如何使用 jQuery 在页面上动态加载 JavaScript 模块的更多信息，请阅读`$.getScript()`方法的文档：[`api.jquery.com/jQuery.getScript/`](https://api.jquery.com/jQuery.getScript/)。

## 采用它在一个已有的实现中

为了说明这个技术，我们将更改`informationBox`模块的`Underscore.js`和`Handlebars.js`实现，以便使用 AJAX 请求获取我们仪表板的盒子模板。

让我们通过分析我们的`Underscore.js`实现所需的改变来继续：

```js
var templateCache = {}; 

function getAjaxTemplate(templateName) { 
    var compiledTemplate = templateCache[templateName]; 
    if (compiledTemplate) { 
        return $.Deferred().resolve(compiledTemplate); 
    } 
    return $.ajax({ 
        mimeType: 'text/html', 
        url: templateName + '.html' 
    }).then(function(template) { 
 templateCache[templateName] = _.template(template); 
        return templateCache[templateName]; 
    }); 
} 
```

正如你在上面的代码中所看到的，我们已经实现了`getAjaxTemplate()`函数作为一种将负责获取模板的机制与使用它的实现解耦的方式。这个实现与我们之前使用的`getEmbeddedTemplate()`函数有很多相似之处，主要区别在于`getAjaxTemplate()`函数是异步的，因此返回一个**Promise**。

`getAjaxTemplate()`函数首先检查所请求的模板是否已经存在于其缓存中，这是为了进一步减少向服务器发出的 HTTP 请求。如果在缓存中找到模板，则它将作为已解决的 Promise 的一部分返回，否则我们将使用`$.ajax()`方法启动一个 AJAX 请求从服务器检索它。像以前一样，我们需要对模板 HTML 文件的命名和用于在服务器上存储它们的路径有一个约定。在我们的示例中，我们正在查找与网页本身相同的目录，并只附加`.html`文件扩展名。在某些情况下，根据所使用的 Web 服务器的不同，还需要额外考虑资源的`mimeType`定义为`text/html`。

当 AJAX 请求完成时，`then()` 方法将以模板内容作为字符串参数执行，用于生成编译后的模板函数。我们的实现最终将编译后的模板函数作为链式 Promise 的结果返回，直接将其添加到缓存中。由于 `getAjaxTemplate()` 函数是异步的，我们还必须更改 `openNew()` 方法的实现，并将所有使用返回的模板函数的代码移到 `then()` 回调内部。除此之外，实现保持不变，并且与之前完全相同地使用模板函数。

```js
dashboard.informationBox.openNew = function(itemName) { 
 var templatePromise = getAjaxTemplate('box-template'); 
    templatePromise.then(function(boxCompiledTemplate) { 
 var boxHtml = boxCompiledTemplate({ 
            itemName: itemName 
        }); 
        var $box = $(boxHtml).appendTo($boxContainer); box); 
        /* ... */ 
    }); 
};
```

当重新实现 `getAjaxTemplate()` 函数以使用 `Handlebars.js` 时，结果代码基本与以前相同。唯一的区别在于调用 `Handlebars.compile()` 方法而不是 `Underscore.js` 的等价方法。这是一个额外的好处，因为许多客户端模板引擎彼此影响，并已经在它们的模板函数的使用方式方面收敛到非常相似的 API，主要是因为现有实现的积极用户反馈。

```js
function getAjaxTemplate(templateName) { 
    /* …same as before... */
    return $.ajax({ /* …same as before... */ }).then(function(template) { 
 templateCache[templateName] = Handlebars.compile(template); 
        return templateCache[templateName]; 
    }); 
}
```

### 注意

请记住，当通过文件系统加载页面时，`$.ajax()` 方法可能在某些浏览器中无法工作，但在像 Apache、IIS 或 nginx 这样的 Web 服务器上加载时则能正常工作。

## 凡事适度

尽管这种技术减少了每个网页的总下载量，但也不可避免地增加了所发出的 HTTP 请求的数量。此外，懒加载每个模板的做法有时会增加用户等待的时间，特别是如果模板在页面的初始渲染中是必需的。

在懒加载和将模板嵌入 `<script>` 标签之间平衡加载模板的方式通常会带来最佳效果。这种混合方法被行业认为是最佳实践，因为它允许我们根据需要微观管理和微调每个实现。根据这种实践，用于页面主要内容呈现的模板被嵌入到其 HTML 中，而其余的模板则在需要时延迟提供，利用浏览器缓存。

此类模板提供程序函数的实现留给读者作为练习。作为提示，此类方法必须是异步的，因为当页面中未找到请求的模板嵌入在 `<script>` 标签中时，它将必须继续并发出 AJAX 请求从服务器检索它。

### 提示

请记住，通常更倾向于在服务器端生成页面的完整初始 HTML 内容，而不是使用客户端模板。这不仅会导致初始页面内容的加载时间更短，而且可以防止在 JavaScript 不可用或发生错误时向用户呈现空白页面的情况发生。

# 总结

在这一章中，我们学习了如何使用两个最常见的客户端模板库：`Underscore.js` 和 `Handlebars.js`。我们还学习了它们如何帮助我们更快地创建复杂的 HTML 模板，同时使我们的实现更易于阅读和理解。我们随后分析了它们的惯例，评估了它们的特性，并通过示例学习了它们如何可以有效且高效地在我们的实现中使用。

完成本章后，我们现在能够通过使用可读模板和利用模板库的独特特点，在浏览器中高效生成复杂的 HTML 结构。

在下一章中，我们将学习如何创建 jQuery 插件来将应用程序的部分抽象为可重用和可扩展的实现方式。我们将介绍开发 jQuery 插件最广泛使用的模式，并分析每种模式帮助解决的实现问题。
