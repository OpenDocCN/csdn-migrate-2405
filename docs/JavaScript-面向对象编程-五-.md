# JavaScript 面向对象编程（五）

> 原文：[`zh.annas-archive.org/md5/9BD01417886F7CF4434F47DFCFFE13F5`](https://zh.annas-archive.org/md5/9BD01417886F7CF4434F47DFCFFE13F5)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：编码和设计模式

既然您已经了解了 JavaScript 中的所有对象，掌握了原型和继承，并看到了使用特定于浏览器的对象的一些实际示例，让我们继续前进，或者说，向上移动一级。让我们来看看一些常见的 JavaScript 模式。

但首先，什么是模式？简而言之，模式是对常见问题的良好解决方案。将解决方案编码为模式使其可重复使用。

有时，当您面对一个新的编程问题时，您可能立即意识到您以前解决过另一个非常相似的问题。在这种情况下，值得将这类问题隔离出来，并寻找一个共同的解决方案。模式是一种经过验证和可重复使用的解决方案（或解决方案的方法）。

有时，模式只是一个想法或一个名称。有时，仅仅使用一个名称可以帮助您更清晰地思考问题。此外，在团队中与其他开发人员合作时，当每个人使用相同的术语讨论问题或解决方案时，沟通会更容易。

有时，您可能会遇到一个独特的问题，看起来与您以前见过的任何东西都不一样，并且不容易适应已知的模式。盲目地应用模式只是为了使用模式，这不是一个好主意。最好不要使用任何已知的模式，而是尝试调整问题，使其适应现有的解决方案。

本章讨论了以下两种模式：

+   **编码模式**：这些主要是 JavaScript 特定的最佳实践

+   **设计模式**：这些是与语言无关的模式，由著名的*四人帮*书籍推广

# 编码模式

让我们从一些反映 JavaScript 独特特性的模式开始。一些模式旨在帮助您组织代码，例如命名空间；其他与改进性能有关，例如延迟定义和初始化时分支；还有一些弥补了缺失的功能，例如私有属性。本节讨论的模式包括以下主题：

+   分离行为

+   命名空间

+   初始化时分支

+   延迟定义

+   配置对象

+   私有变量和方法

+   特权方法

+   将私有函数作为公共方法

+   立即函数

+   链接

+   JSON

## 分离行为

如前所述，网页的三个构建块如下：

+   内容（HTML）

+   演示（CSS）

+   行为（JavaScript）

### 内容

HTML 是网页的内容，实际文本。理想情况下，内容应该使用尽可能少的 HTML 标记进行标记，以充分描述该内容的语义含义。例如，如果您正在处理导航菜单，最好使用`<ul>`和`<li>`标记，因为导航菜单本质上只是一个链接列表。

您的内容（HTML）应该不包含任何格式化元素。视觉格式应属于演示层，并且应通过**CSS**（层叠样式表）来实现。这意味着以下内容：

+   如果可能的话，不应该使用 HTML 标记的样式属性。

+   根本不应该使用`<font>`等呈现 HTML 标签。

+   标记应该根据其语义含义使用，而不是因为浏览器默认呈现它们。例如，开发人员有时会在更适合使用`<p>`的地方使用`<div>`标记。使用`<strong>`和`<em>`而不是`<b>`和`<i>`也是有利的，因为后者描述的是视觉呈现而不是含义。

### 演示

将演示内容与内容分开的一个好方法是重置或清空所有浏览器默认设置，例如使用来自 Yahoo! UI 库的`reset.css`。这样，浏览器的默认呈现不会让您分心，而是会让您有意识地考虑使用适当的语义标记。

### 行为

网页的第三个组件是行为。行为应该与内容和表现分开。通常使用隔离在`<script>`标签中的 JavaScript 来添加，最好包含在外部文件中。这意味着不使用任何内联属性，如`onclick`，`onmouseover`等。相反，您可以使用上一章中的`addEventListener`/`attachEvent`方法。

将行为与内容分离的最佳策略如下：

+   最小化`<script>`标签的数量

+   避免内联事件处理程序

+   不要使用 CSS 表达式

+   在内容的末尾，当您准备关闭`<body>`标签时，插入一个`external.js`文件

#### 行为分离示例

假设您在页面上有一个搜索表单，并且希望使用 JavaScript 验证表单。因此，您可以继续保持`form`标签不受任何 JavaScript 的影响，然后在关闭`</body>`标签之前立即插入一个链接到外部文件的`<script>`标签，如下所示：

```js
    <body> 
      <form id="myform" method="post" action="server.php"> 
      <fieldset> 
        <legend>Search</legend> 
        <input 
          name="search" 
          id="search" 
          type="text"   
        /> 
        <input type="submit" /> 
        </fieldset> 
      </form> 
      <script src="behaviors.js"></script> 
    </body> 

```

在`behaviors.js`中，您可以将事件侦听器附加到提交事件。在您的侦听器中，您可以检查文本输入字段是否为空，如果是，则阻止表单提交。这样，您将节省服务器和客户端之间的往返，并使应用程序立即响应。

`behaviors.js`的内容如下所示。它假定您已经根据上一章的练习创建了您的`myevent`实用程序：

```js
    // init 
    myevent.addListener('myform', 'submit', function (e) { 
      // no need to propagate further 
      e = myevent.getEvent(e); 
      myevent.stopPropagation(e); 
      // validate 
      var el = document.getElementById('search'); 
      if (!el.value) { // too bad, field is empty 
        myevent.preventDefault(e); // prevent the form submission 
        alert('Please enter a search string'); 
      } 
    }); 

```

### 异步 JavaScript 加载

您注意到脚本是在 HTML 结束前加载的，就在关闭 body 之前。原因是 JavaScript 会阻止页面的 DOM 构建，并且在某些浏览器中，甚至会阻止后续组件的下载。通过将脚本移动到页面底部，您可以确保脚本不会妨碍，并且当它到达时，它只是增强了已经可用的页面。

防止外部 JavaScript 文件阻止页面的另一种方法是异步加载它们。这样您可以更早地开始加载它们。HTML5 具有此目的的`defer`属性。请考虑以下代码行：

```js
    <script defer src="behaviors.js"></script> 

```

不幸的是，`defer`属性不受旧版浏览器支持，但幸运的是，有一个可以跨浏览器（新旧）工作的解决方案。解决方案是动态创建一个`script`节点并将其附加到 DOM。换句话说，您可以使用一点内联 JavaScript 来加载外部 JavaScript 文件。您可以在文档顶部放置此脚本加载程序片段，以便下载可以尽早开始。请看以下代码示例：

```js
    ... 
    <head> 
    <script> 
    (function () { 
      var s = document.createElement('script'); 
      s.src = 'behaviors.js'; 
      document.getElementsByTagName('head')[0].appendChild(s); 
    }()); 
    </script> 
    </head> 
    ... 

```

## 命名空间

应避免全局变量以减少变量命名冲突的可能性。通过为变量和函数命名空间化，您可以最小化全局变量的数量。这个想法很简单，您只会创建一个全局对象，而您的所有其他变量和函数都成为该对象的属性。

### 对象作为命名空间

让我们创建一个名为`MYAPP`的全局对象：

```js
    // global namespace 
    var MYAPP = MYAPP || {}; 

```

现在，不再需要全局的`myevent`实用程序（来自上一章），您可以将其作为`MYAPP`对象的`event`属性，如下所示：

```js
    // sub-object 
    MYAPP.event = {}; 

```

向`event`实用程序添加方法仍然是相同的。请考虑以下示例：

```js
    // object together with the method declarations 
    MYAPP.event = { 
      addListener: function (el, type, fn) { 
        // .. do the thing 
      }, 
      removeListener: function (el, type, fn) { 
        // ... 
      }, 
      getEvent: function (e) { 
        // ... 
      } 
      // ... other methods or properties 
    }; 

```

### 命名空间构造函数

使用命名空间不妨碍您创建构造函数。以下是如何创建具有`Element`构造函数的 DOM 实用程序，它允许您轻松创建 DOM 元素：

```js
    MYAPP.dom = {}; 
    MYAPP.dom.Element = function (type, properties) { 
      var tmp = document.createElement(type); 
      for (var i in properties) { 
        if (properties.hasOwnProperty(i)) { 
          tmp.setAttribute(i, properties[i]); 
        } 
      } 
       return tmp; 
    }; 

```

类似地，您可以有一个`Text`构造函数来创建文本节点。请考虑以下代码示例：

```js
    MYAPP.dom.Text = function (txt) { 
      return document.createTextNode(txt); 
    }; 

```

使用构造函数在页面底部创建链接可以按以下方式完成：

```js
    var link = new MYAPP.dom.Element('a',  
      {href: 'http://phpied.com', target: '_blank'}); 
    var text = new MYAPP.dom.Text('click me'); 
    link.appendChild(text); 
    document.body.appendChild(link); 

```

### 一个命名空间()方法

您可以创建一个命名空间实用程序，使您的生活更轻松，以便您可以使用更方便的语法，如下所示：

```js
    MYAPP.namespace('dom.style'); 

```

而不是更冗长的语法如下：

```js
    MYAPP.dom = {}; 
    MYAPP.dom.style = {}; 

```

以下是如何创建`namespace()`方法的方法。首先，您将使用句点（`.`）作为分隔符拆分输入字符串，创建一个数组。然后，对于新数组中的每个元素，如果全局对象中不存在该属性，则添加一个属性，如下所示：

```js
    var MYAPP = {}; 
    MYAPP.namespace = function (name) { 
      var parts = name.split('.'); 
      var current = MYAPP; 
      for (var i = 0; i < parts.length; i++) { 
        if (!current[parts[i]]) { 
          current[parts[i]] = {}; 
        } 
        current = current[parts[i]]; 
      } 
    }; 

```

通过以下方式进行新方法的测试：

```js
    MYAPP.namespace('event'); 
    MYAPP.namespace('dom.style'); 

```

前面代码的结果与以下操作相同：

```js
    var MYAPP = { 
      event: {}, 
      dom: { 
        style: {} 
      } 
    }; 

```

## 初始化时分支

在前一章中，您注意到有时不同的浏览器对相同或类似的功能有不同的实现。在这种情况下，您需要根据当前执行脚本的浏览器支持的内容对代码进行分支。根据您的程序，这种分支可能会发生得太频繁，结果可能会减慢脚本的执行速度。

您可以通过在初始化时对代码的某些部分进行分支来缓解这个问题，当脚本加载时，而不是在运行时。借助动态定义函数的能力，您可以根据浏览器的不同分支和定义相同的函数，具体取决于浏览器。让我们看看如何。

首先，让我们定义一个命名空间和`event`实用程序的占位符方法。

```js
    var MYAPP = {}; 
    MYAPP.event = { 
      addListener: null, 
      removeListener: null 
    }; 

```

此时，添加或删除侦听器的方法尚未实现。根据特性嗅探的结果，可以以不同的方式定义这些方法，如下所示：

```js
    if (window.addEventListener) { 
      MYAPP.event.addListener = function (el, type, fn) { 
        el.addEventListener(type, fn, false); 
      }; 
      MYAPP.event.removeListener = function (el, type, fn) { 
        el.removeEventListener(type, fn, false); 
      }; 
    } else if (document.attachEvent) { // IE 
      MYAPP.event.addListener = function (el, type, fn) { 
        el.attachEvent('on' + type, fn); 
      }; 
      MYAPP.event.removeListener = function (el, type, fn) { 
        el.detachEvent('on' + type, fn); 
      }; 
    } else { // older browsers 
      MYAPP.event.addListener = function (el, type, fn) { 
        el['on' + type] = fn; 
      }; 
      MYAPP.event.removeListener = function (el, type) { 
        el['on' + type] = null; 
      }; 
    } 

```

脚本执行后，您将以与浏览器相关的方式定义`addListener()`和`removeListener()`方法。现在，每次调用这些方法时，都不再需要特性嗅探，这将减少工作量并加快执行速度。

在嗅探特性时要注意的一点是，在检查一个特性后不要假设太多。在前面的示例中，这条规则被打破了，因为代码只检查了`addEventListener`的支持，但随后定义了`addListener()`和`removeListener()`。在这种情况下，可以假设如果浏览器实现了`addEventListener()`，那么它也实现了`removeEventListener()`。然而，想象一下，如果浏览器实现了`stopPropagation()`但没有实现`preventDefault()`，而您没有单独检查这些情况会发生什么。您假设因为`addEventListener()`未定义，浏览器必须是一个旧的 IE，并使用您对 IE 工作方式的知识和假设来编写代码。请记住，您所有的知识都是基于某个浏览器今天的工作方式，但不一定是明天的工作方式。因此，为了避免在新的浏览器版本发布时多次重写代码，最好单独检查您打算使用的特性，并不要对某个浏览器支持的特性进行概括。

## 懒惰定义

懒惰定义模式类似于先前的初始化时分支模式。不同之处在于分支只会在第一次调用函数时发生。当调用函数时，它会使用最佳实现重新定义自身。与初始化时分支不同，初始化时分支只发生一次，在加载时，而在这里，当函数从未被调用时，可能根本不会发生。懒惰定义还使初始化过程更轻松，因为不需要进行初始化时分支工作。

让我们通过定义一个`addListener()`函数的示例来说明这一点。首先，该函数使用通用的主体进行定义。当首次调用函数时，它会检查浏览器支持的功能，然后使用最合适的实现重新定义自身。在第一次调用结束时，函数会调用自身，以便执行实际的事件附加。下次调用相同的函数时，它将使用新的主体进行定义，并准备好使用，因此不需要进一步的分支。以下是代码片段：

```js
    var MYAPP = {}; 
    MYAPP.myevent = { 
     addListener: function (el, type, fn) { 
        if (el.addEventListener) { 
          MYAPP.myevent.addListener = function (el, type, fn) { 
            el.addEventListener(type, fn, false); 
          }; 
        } else if (el.attachEvent) { 
          MYAPP.myevent.addListener = function (el, type, fn) { 
            el.attachEvent('on' + type, fn); 
          }; 
        } else { 
          MYAPP.myevent.addListener = function (el, type, fn) { 
            el['on' + type] = fn; 
          }; 
        } 
        MYAPP.myevent.addListener(el, type, fn); 
      } 
    }; 

```

## 配置对象

当您有一个接受许多可选参数的函数或方法时，这种模式很方便。由您决定多少个构成了很多。但一般来说，一个具有三个以上参数的函数不方便调用，因为您必须记住参数的顺序，当一些参数是可选的时，这更加不方便。

而不是有许多参数，您可以使用一个参数并将其设置为对象。对象的属性是实际参数。这适用于传递配置选项，因为这些 tend to be numerous and optional (with smart defaults). 使用单个对象而不是多个参数的美妙之处如下所述：

+   顺序无关紧要

+   您可以轻松跳过不想设置的参数

+   很容易添加更多的可选配置属性

+   它使代码更易读，因为配置对象的属性与它们的名称一起出现在调用代码中

想象一下，您有一些 UI 小部件构造函数，用于创建漂亮的按钮。它接受要放在按钮内部的文本（`<input>`标签的`value`属性）以及`type`按钮的可选参数。为简单起见，让我们假设漂亮的按钮采用与常规按钮相同的配置。看一下以下代码：

```js
    // a constructor that creates buttons 
    MYAPP.dom.FancyButton = function (text, type) { 
      var b = document.createElement('input'); 
      b.type = type || 'submit'; 
      b.value = text; 
      return b; 
    }; 

```

使用构造函数很简单；您只需给它一个字符串。然后，您可以将新按钮添加到文档的主体中，如下所示：

```js
    document.body.appendChild( 
      new MYAPP.dom.FancyButton('puuush') 
    ); 

```

这一切都很好，运行良好，但是然后您决定还想能够设置按钮的一些样式属性，比如颜色和字体。您最终可能会得到以下定义：

```js
    MYAPP.dom.FancyButton =  
      function (text, type, color, border, font) { 
      // ... 
    }; 

```

现在，使用构造函数可能会变得有点不方便，特别是当您想设置第三个和第五个参数，但不想设置第二个或第四个时。考虑以下示例：

```js
    new MYAPP.dom.FancyButton( 
      'puuush', null, 'white', null, 'Arial'); 

```

更好的方法是使用一个`config`对象参数来设置所有的设置。函数定义可以变成以下代码片段：

```js
    MYAPP.dom.FancyButton = function (text, conf) { 
      var type = conf.type || 'submit'; 
      var font = conf.font || 'Verdana'; 
      // ... 
    }; 

```

使用构造函数如下所示：

```js
    var config = { 
      font: 'Arial, Verdana, sans-serif', 
      color: 'white' 
    }; 
    new MYAPP.dom.FancyButton('puuush', config); 

```

另一个用法示例如下：

```js
    document.body.appendChild( 
      new MYAPP.dom.FancyButton('dude', {color: 'red'}) 
    ); 

```

如您所见，设置只有一些参数并且切换它们的顺序很容易。此外，当您在调用方法的地方看到参数的名称时，代码更友好，更易于理解。

这种模式的缺点与其优点相同。很容易不断添加更多的参数，这意味着滥用这种技术很容易。一旦您有理由向这个自由的属性包中添加更多内容，您会发现很容易不断添加一些并非完全可选的属性，或者一些依赖于其他属性的属性。

作为一个经验法则，所有这些属性都应该是独立的和可选的。如果您必须在函数内部检查所有可能的组合（“哦，A 已设置，但只有在 B 也设置了 A 才会被使用”），这将导致一个庞大的函数体，很快就会变得令人困惑和难以理解，甚至是不可能测试，因为所有的组合。

## 私有属性和方法

JavaScript 没有访问修饰符的概念，它设置对象中属性的特权。其他语言通常有访问修饰符，如下所示：

+   `Public`: 对象的所有用户都可以访问这些属性或方法

+   `Private`: 只有对象本身才能访问这些属性

+   `Protected`: 只有继承所讨论的对象的对象才能访问这些属性

JavaScript 没有特殊的语法来表示私有属性或方法，但如第三章中所讨论的 *函数*，您可以在函数内部使用局部变量和方法，并实现相同级别的保护。

继续使用`FancyButton`构造函数的示例，您可以有一个包含所有默认值的本地变量 styles 和一个本地的`setStyle()`函数。这些对于构造函数外部的代码是不可见的。以下是`FancyButton`如何利用本地私有属性：

```js
    var MYAPP = {}; 
    MYAPP.dom = {}; 
    MYAPP.dom.FancyButton = function (text, conf) { 
      var styles = { 
        font: 'Verdana', 
        border: '1px solid black', 
        color: 'black', 
        background: 'grey' 
      }; 
      function setStyles(b) { 
        var i; 
        for (i in styles) { 
          if (styles.hasOwnProperty(i)) { 
            b.style[i] = conf[i] || styles[i]; 
          } 
       } 
      } 
      conf = conf || {}; 
      var b = document.createElement('input'); 
      b.type = conf.type || 'submit'; 
      b.value = text; 
      setStyles(b); 
      return b; 
    }; 

```

在此实现中，`styles`是一个私有属性，`setStyle()`是一个私有方法。构造函数在内部使用它们（它们可以访问构造函数内部的任何内容），但它们对函数外部的代码不可用。

## 特权方法

特权方法（这个术语是由 Douglas Crockford 创造的）是可以访问私有方法或属性的普通公共方法。它们可以充当桥梁，以受控的方式包装特定的私有功能，使其可访问。

## 私有函数作为公共方法

假设您已经定义了一个绝对需要保持完整的函数，因此将其设置为私有。但是，您还希望提供对相同函数的访问权限，以便外部代码也可以从中受益。在这种情况下，您可以将私有函数分配给公开可用的属性。

让我们将`_setStyle()`和`_getStyle()`定义为私有函数，然后将它们分配给公共的`setStyle()`和`getStyle()`，考虑以下示例：

```js
    var MYAPP = {}; 
    MYAPP.dom = (function () { 
      var _setStyle = function (el, prop, value) { 
        console.log('setStyle'); 
      }; 
      var _getStyle = function (el, prop) { 
        console.log('getStyle'); 
      }; 
      return { 
        setStyle: _setStyle, 
        getStyle: _getStyle, 
        yetAnother: _setStyle 
      }; 
    }()); 

```

现在，当您调用`MYAPP.dom.setStyle()`时，它会调用私有的`_setStyle()`函数。您也可以从外部覆盖`setStyle()`如下：

```js
    MYAPP.dom.setStyle = function () {alert('b');}; 

```

现在，结果如下：

+   `MYAPP.dom.setStyle`指向新函数

+   `MYAPP.dom.yetAnother`仍然指向`_setStyle()`

+   `_setStyle()`在任何其他内部代码依赖它按预期工作时始终可用，而不受外部代码的影响

当您公开私有内容时，请记住对象（函数和数组也是对象）是通过引用传递的，因此可以从外部修改。

## 立即函数

帮助您保持全局命名空间清晰的另一种模式是将代码包装在匿名函数中并立即执行该函数。这样，只要使用`var`语句，函数内部的任何变量都是局部的，并且在函数返回时被销毁，如果它们不是闭包的一部分。这种模式在第三章*函数*中有更详细的讨论。看一下以下代码：

```js
    (function () { 
      // code goes here... 
    }()); 

```

此模式特别适用于一次性初始化任务，在脚本加载时执行。

立即自执行函数模式可以扩展到创建和返回对象。如果创建这些对象更复杂并涉及一些初始化工作，那么您可以在自执行函数的第一部分中执行此操作，并返回一个可以访问和受益于顶部私有属性的单个对象，如下所示：

```js
    var MYAPP = {}; 
    MYAPP.dom = (function () { 
      // initialization code... 
      function _private() { 
        // ...  
      } 
      return { 
        getStyle: function (el, prop) { 
          console.log('getStyle'); 
          _private(); 
        }, 
        setStyle: function (el, prop, value) { 
          console.log('setStyle'); 
        } 
      }; 
    }()); 

```

## 模块

结合前面几种模式可以得到一个新模式，通常称为模块模式。编程中的模块概念很方便，因为它允许您编写单独的代码片段或库，并根据需要组合它们，就像拼图一样。

模块模式包括以下内容：

+   命名空间以减少模块之间的命名冲突

+   立即函数提供私有作用域和初始化

+   私有属性和方法

### 注意

ES5 没有内置的模块概念。有来自[`www.commonjs.org`](http://www.commonjs.org)的模块规范，它定义了一个`require()`函数和一个 exports 对象。然而，ES6 支持模块。第八章类和模块已经详细介绍了模块。

+   返回具有模块公共 API 的对象，如下所示：

```js
        namespace('MYAPP.module.amazing'); 

        MYAPP.module.amazing = (function () { 

          // short names for dependencies 
          var another = MYAPP.module.another; 

          // local/private variables 
          var i, j; 

          // private functions 
          function hidden() {} 

          // public API 
          return { 
            hi: function () { 
              return "hello"; 
            } 
          }; 
        }()); 

```

而且，您可以以以下方式使用模块：

```js
    MYAPP.module.amazing.hi(); // "hello" 

```

## 链接

链接是一种模式，允许你在一行上调用多个方法，就好像这些方法是链条中的链接一样。当调用几个相关的方法时，这是很方便的。你在前一个方法的结果上调用下一个方法，而不使用中间变量。

假设你已经创建了一个构造函数，可以帮助你处理 DOM 元素。创建一个新的添加到`<body>`标签的`<span>`标签的代码可能如下所示：

```js
    var obj = new MYAPP.dom.Element('span'); 
    obj.setText('hello'); 
    obj.setStyle('color', 'red'); 
    obj.setStyle('font', 'Verdana'); 
    document.body.appendChild(obj); 

```

如你所知，构造函数返回所谓的`this`关键字所创建的对象。你可以让你的方法，比如`setText()`和`setStyle()`，也返回`this`关键字，这样你就可以在前一个方法返回的实例上调用下一个方法。这样，你可以链式调用方法，如下所示：

```js
    var obj = new MYAPP.dom.Element('span'); 
    obj.setText('hello') 
       .setStyle('color', 'red') 
       .setStyle('font', 'Verdana'); 
    document.body.appendChild(obj); 

```

如果你在新元素添加到树之后不打算使用`obj`变量，那么代码看起来像下面这样：

```js
    document.body.appendChild( 
      new MYAPP.dom.Element('span') 
        .setText('hello') 
        .setStyle('color', 'red') 
        .setStyle('font', 'Verdana') 
    );    

```

这种模式的一个缺点是，当长链中的某个地方发生错误时，它会使得调试变得有点困难，因为你不知道哪个链接有问题，因为它们都在同一行上。

## JSON

让我们用几句话来总结本章的编码模式部分关于 JSON 的内容。JSON 在技术上并不是一个编码模式，但你可以说使用它是一个很好的模式。

JSON 是一种流行的轻量级数据交换格式。在使用`XMLHttpRequest()`从服务器检索数据时，它通常优先于 XML。**JSON**除了它极其方便之外，没有什么特别有趣的地方。JSON 格式由使用对象和数组文字定义的数据组成。以下是一个 JSON 字符串的示例，你的服务器可以在`XHR`请求之后用它来响应：

```js
    { 
      'name':   'Stoyan', 
      'family': 'Stefanov', 
      'books':  ['OOJS', 'JSPatterns', 'JS4PHP'] 
    } 

```

这个的 XML 等价物将是以下代码片段：

```js
    <?xml version="1.1" encoding="iso-8859-1"?> 
    <response> 
      <name>Stoyan</name> 
      <family>Stefanov</family> 
      <books> 
        <book>OOJS</book> 
        <book>JSPatterns</book> 
        <book>JS4PHP</book> 
      </books> 
    </response> 

```

首先，你可以看到 JSON 在字节数量上更轻。然而，主要好处不是较小的字节大小，而是在 JavaScript 中使用 JSON 非常简单。比如，你已经发出了一个`XHR`请求，并在`XHR`对象的`responseText`属性中收到了一个 JSON 字符串。你可以通过简单地使用`eval()`将这个数据字符串转换为一个可用的 JavaScript 对象。考虑以下示例：

```js
    // warning: counter-example 
    var response = eval('(' + xhr.responseText + ')'); 

```

现在，你可以像下面这样访问`obj`中的数据作为对象属性：

```js
    console.log(response.name); // "Stoyan" 
    console.log(response.books[2]); // "JS4PHP" 

```

问题在于`eval()`是不安全的，所以最好使用 JSON 对象来解析 JSON 数据（旧版浏览器的备用方案可在[`json.org/`](http://json.org/)找到）。从 JSON 字符串创建对象仍然很简单，如下所示：

```js
    var response = JSON.parse(xhr.responseText); 

```

要做相反的事情，也就是将对象转换为 JSON 字符串，你可以使用`stringify()`方法，如下所示：

```js
    var str = JSON.stringify({hello: "you"}); 

```

由于其简单性，JSON 很快就成为了一种独立于语言的数据交换格式，并且你可以使用你喜欢的语言在服务器端轻松地生成 JSON。例如，在 PHP 中，有`json_encode()`和`json_decode()`函数，让你将 PHP 数组或对象序列化为 JSON 字符串，反之亦然。

## 高阶函数

到目前为止，函数式编程一直局限于有限的一组语言。随着越来越多的语言添加支持函数式编程的特性，人们对这一领域的兴趣正在增长。JavaScript 正在发展以支持函数式编程的常见特性。你将逐渐看到很多以这种风格编写的代码。重要的是要理解函数式编程风格，即使你现在还不想在你的代码中使用它。

高阶函数是函数式编程的重要支柱之一。高阶函数是至少做以下一种事情的函数：

+   以一个或多个函数作为参数

+   返回一个函数作为结果

由于 JavaScript 中函数是一等对象，因此将函数传递给函数并从函数返回函数是一件相当常见的事情。回调函数是高阶函数。让我们看看如何将这两个原则结合起来编写一个高阶函数。

让我们编写一个`filter`函数；这个函数根据由函数确定的条件从数组中过滤出值。这个函数接受两个参数-一个返回布尔值`true`以保留此元素的函数。

例如，使用这个函数，我们正在从数组中过滤出所有奇数值。考虑以下代码行：

```js
    console.log([1, 2, 3, 4, 5].filter(function(ele){
      return ele % 2 == 0; })); 
    //[2,4] 

```

我们将一个匿名函数作为第一个参数传递给`filter`函数。这个函数根据一个条件返回一个布尔值，检查元素是奇数还是偶数。

这是 ECMAScript 5 中添加的几个高阶函数之一的示例。我们试图表达的观点是，您将越来越多地看到 JavaScript 中类似的使用模式。您必须首先了解高阶函数的工作原理，然后，一旦您对概念感到舒适，尝试在您的代码中也加入它们。

随着 ES6 函数语法的变化，编写高阶函数变得更加优雅。让我们以 ES5 中的一个小例子来看看它如何转换为 ES6：

```js
    function add(x){ 
      return function(y){ 
        return y + x; 
      }; 
    } 
     var add3 = add(3); 
    console.log(add3(3));          // => 6 
    console.log(add(9)(10));       // => 19 

```

`add`函数接受`x`并返回一个接受`y`作为参数的函数，然后返回表达式`y+x`的值。

当我们讨论箭头函数时，我们讨论了箭头函数隐式返回单个表达式的结果。因此，前面的函数可以通过将箭头函数的主体变为另一个箭头函数来转换为箭头函数。看看下面的例子：

```js
    const add = x => y => y + x; 

```

在这里，我们有一个外部函数，`x =>` [带有`x`作为参数的内部函数]，以及一个内部函数，`y => y+x`。

这个介绍将帮助您熟悉高阶函数的增加使用，以及它们在 JavaScript 中的增加重要性。

# 设计模式

本章的第二部分介绍了 JavaScript 对《设计模式：可复用面向对象软件的元素》中引入的设计模式子集的方法，这是一本有影响力的书，通常被称为《四人帮》或《GoF》（四位作者的缩写）。《GoF》书中讨论的模式分为以下三组：

+   处理对象如何创建（实例化）的创建模式

+   描述不同对象如何组合以提供新功能的结构模式

+   描述对象之间通信方式的行为模式

《四人帮》中有 23 种模式，自该书出版以来已经发现了更多模式。讨论所有这些模式远远超出了本书的范围，因此本章的其余部分仅演示了四种模式，以及它们在 JavaScript 中的实现示例。请记住，这些模式更多关于接口和关系而不是实现。一旦您了解了设计模式，通常很容易实现它，特别是在 JavaScript 这样的动态语言中。

本章剩余部分讨论的模式如下：

+   单例

+   工厂

+   装饰器

+   观察者

## 单例模式

单例是一种创建型设计模式，意味着它的重点是创建对象。当您想要确保只有一个给定种类或类的对象时，它会帮助您。在经典语言中，这意味着只创建一个类的实例，并且任何后续尝试创建相同类的新对象都将返回原始实例。

在 JavaScript 中，由于没有类，单例是默认和最自然的模式。每个对象都是单例对象。

JavaScript 中单例的最基本实现是对象字面量。看一下下面的代码行：

```js
    var single = {}; 

```

那很容易，对吧？

## 单例 2 模式

如果您想使用类似类的语法并且仍然实现单例模式，事情会变得更有趣一些。假设您有一个名为`Logger()`的构造函数，并且希望能够执行以下操作：

```js
    var my_log = new Logger(); 
    my_log.log('some event'); 

    // ... 1000 lines of code later in a different scope ... 

    var other_log = new Logger(); 
    other_log.log('some new event'); 
    console.log(other_log === my_log); // true 

```

思想是，尽管使用了`new`，但只需要创建一个实例，然后在连续调用中返回该实例。

### 全局变量

一种方法是使用全局变量来存储单个实例。您的构造函数可能如下代码片段所示：

```js
    function Logger() { 
      if (typeof global_log === "undefined") { 
        global_log = this; 
      } 
      return global_log; 
    } 

```

使用此构造函数会产生预期的结果，如下所示：

```js
    var a = new Logger(); 
    var b = new Logger(); 
    console.log(a === b); // true 

```

缺点显而易见，就是使用全局变量。它可以在任何时候被意外覆盖，您可能会丢失实例。相反，覆盖别人的全局变量也是可能的。

### 构造函数的属性

如您所知，函数是对象，它们有属性。您可以将单个实例分配给构造函数的属性，如下所示：

```js
    function Logger() { 
      if (!Logger.single_instance) { 
        Logger.single_instance = this; 
      } 
      return Logger.single_instance; 
    } 

```

如果您编写`var a = new Logger()`，`a`指向新创建的`Logger.single_instance`属性。随后的`var b = new Logger()`调用会导致`b`指向相同的`Logger.single_instance`属性，这正是您想要的。

这种方法确实解决了全局命名空间问题，因为不会创建全局变量。唯一的缺点是`Logger`构造函数的属性是公开可见的，因此可以随时被覆盖。在这种情况下，单个实例可能会丢失或修改。当然，您只能提供有限的保护，以防止其他程序员自食其力。毕竟，如果有人可以干扰单实例属性，他们也可以直接干扰`Logger`构造函数。

### 在私有属性中

解决公开可见属性被覆盖的问题的方法不是使用公共属性，而是使用私有属性。您已经知道如何使用闭包保护变量，因此作为练习，您可以实现这种方法来实现单例模式。

## 工厂模式

工厂是另一种创建型设计模式，因为它涉及创建对象。当您有类似类型的对象并且事先不知道要使用哪个时，工厂可以帮助您。根据用户输入或其他条件，您的代码可以动态确定所需的对象类型。

假设您有三种不同的构造函数，实现类似的功能。它们创建的所有对象都需要一个 URL，但对其执行不同的操作。一个创建文本 DOM 节点；第二个创建一个链接；第三个创建一个图像，如下所示：

```js
    var MYAPP = {}; 
    MYAPP.dom = {}; 
    MYAPP.dom.Text = function (url) { 
      this.url = url; 
      this.insert = function (where) { 
        var txt = document.createTextNode(this.url); 
        where.appendChild(txt); 
      }; 
    }; 
    MYAPP.dom.Link = function (url) { 
      this.url = url; 
      this.insert = function (where) { 
        var link = document.createElement('a'); 
        link.href = this.url; 
        link.appendChild(document.createTextNode(this.url)); 
        where.appendChild(link); 
      }; 
    }; 
    MYAPP.dom.Image = function (url) { 
      this.url = url; 
      this.insert = function (where) { 
        var im = document.createElement('img'); 
        im.src = this.url; 
        where.appendChild(im); 
      }; 
    }; 

```

使用三种不同的构造函数完全相同-传递`url`变量并调用`insert()`方法，如下所示：

```js
    var url = 'http://www.phpied.com/images/covers/oojs.jpg'; 

    var o = new MYAPP.dom.Image(url); 
    o.insert(document.body); 

    var o = new MYAPP.dom.Text(url); 
    o.insert(document.body); 

    var o = new MYAPP.dom.Link(url); 
    o.insert(document.body); 

```

想象一下，您的程序事先不知道需要哪种类型的对象。用户在运行时通过单击按钮等方式决定。如果`type`包含所需的对象类型，则需要使用`if`或`switch`语句，并编写以下代码片段：

```js
    var o; 
    if (type === 'Image') { 
      o = new MYAPP.dom.Image(url); 
    } 
    if (type === 'Link') { 
      o = new MYAPP.dom.Link(url); 
    } 
    if (type === 'Text') { 
      o = new MYAPP.dom.Text(url); 
    } 
    o.url = 'http://...'; 
    o.insert(); 

```

这样做效果很好；但是，如果您有很多构造函数，代码会变得太长且难以维护。此外，如果您正在创建允许扩展或插件的库或框架，您甚至不知道所有构造函数的确切名称。在这种情况下，有一个工厂函数来负责创建动态确定类型的对象是很方便的。

让我们向`MYAPP.dom`实用程序添加一个工厂方法：

```js
    MYAPP.dom.factory = function (type, url) { 
      return new MYAPP.domtype; 
    }; 

```

现在，您可以用更简单的代码替换三个`if`函数，如下所示：

```js
    var image = MYAPP.dom.factory("Image", url); 
    image.insert(document.body); 

```

先前代码中的示例`factory()`方法很简单；但是，在实际情况下，您可能希望针对类型值进行一些验证（例如，检查`MYAPP.dom[type]`是否存在），并且可能对所有对象类型进行一些通用的设置工作（例如，设置所有构造函数使用的 URL）。

## 装饰器模式

装饰者设计模式是一种结构模式；它与对象如何创建没有太多关系，而是与它们的功能如何扩展有关。你可以有一个基础对象和一组不同的装饰者对象，它们提供额外的功能，而不是使用继承，继承是线性的（父-子-孙），你的程序可以选择想要的装饰者，以及顺序。对于不同的程序或代码路径，你可能有不同的需求集，并从同一个池中选择不同的装饰者。看一下以下代码片段，看看装饰者模式的使用部分如何实现：

```js
    var obj = { 
      doSomething: function () { 
        console.log('sure, asap'); 
      } 
      //  ... 
    }; 
    obj = obj.getDecorator('deco1'); 
    obj = obj.getDecorator('deco13'); 
    obj = obj.getDecorator('deco5'); 
    obj.doSomething(); 

```

你可以看到如何从一个具有`doSomething()`方法的简单对象开始。然后，你可以选择你手头上的一个装饰者对象，并通过名称进行识别。所有装饰者都提供一个`doSomething()`方法，首先调用前一个装饰者的相同方法，然后继续执行自己的代码。每次添加一个装饰者，都会用改进版本的`obj`覆盖基础对象。最后，当你添加完装饰者后，调用`doSomething()`。结果，所有装饰者的`doSomething()`方法都按顺序执行。让我们看一个例子。

### 装饰一棵圣诞树

让我们用一个装饰一棵圣诞树的例子来说明装饰者模式。你可以按照以下方式开始`decorate()`方法：

```js
    var tree = {}; 
    tree.decorate = function () { 
      alert('Make sure the tree won't fall'); 
    }; 

```

现在，让我们实现一个`getDecorator()`方法，添加额外的装饰者。装饰者将作为构造函数实现，并且它们都将从基础`tree`对象继承，如下所示：

```js
    tree.getDecorator = function (deco) { 
      tree[deco].prototype = this; 
      return new tree[deco]; 
    }; 

```

现在，让我们创建第一个装饰者`RedBalls()`，作为`tree`的属性，以保持全局命名空间更清洁。红色球对象也提供一个`decorate()`方法，但它们确保首先调用它们父级的`decorate()`。例如，看一下以下代码：

```js
    tree.RedBalls = function () { 
      this.decorate = function () { 
        this.RedBalls.prototype.decorate(); 
        alert('Put on some red balls'); 
      }; 
    }; 

```

同样，按照以下方式实现`BlueBalls()`和`Angel()`装饰者：

```js
    tree.BlueBalls = function () { 
      this.decorate = function () { 
        this.BlueBalls.prototype.decorate(); 
        alert('Add blue balls'); 
      }; 
    }; 
    tree.Angel = function () { 
      this.decorate = function () { 
        this.Angel.prototype.decorate(); 
        alert('An angel on the top'); 
      }; 
    }; 

```

现在，让我们将所有装饰者添加到基础对象中，如下所示的代码片段：

```js
    tree = tree.getDecorator('BlueBalls'); 
    tree = tree.getDecorator('Angel'); 
    tree = tree.getDecorator('RedBalls'); 

```

最后，按照以下方式运行`decorate()`方法：

```js
    tree.decorate(); 

```

这个单一的调用会导致以下警报，具体顺序如下：

1.  确保树不会倒下。

1.  添加蓝色的球。

1.  在顶部添加一个天使。

1.  添加一些红色的球。

正如你所看到的，这个功能允许你拥有任意数量的装饰者，并以任意方式选择和组合它们。

## 观察者模式

观察者模式，也称为**订阅者-发布者**模式，是一种行为模式，意味着它处理不同对象之间的交互和通信。在实现观察者模式时，你会有以下对象：

+   一个或多个发布者对象，它们在做重要事情时会宣布。

+   一个或多个订阅者调整到一个或多个发布者。他们听取发布者的宣布然后采取适当的行动。

观察者模式可能对你来说很熟悉。它听起来与前一章讨论的浏览器事件类似，这是正确的，因为浏览器事件是这种模式的一个应用实例。浏览器是发布者；它宣布了事件（如`click`）发生的事实。订阅了这种类型事件的事件监听函数在事件发生时会收到通知。浏览器-发布者向所有订阅者发送一个事件对象。在自定义实现中，你可以发送任何你认为合适的数据。

观察者模式有两种子类型：推（push）和拉（pull）。推是指发布者负责通知每个订阅者，而拉是指订阅者监视发布者状态的变化。

让我们看一个推送模型的示例实现。让我们将观察者相关的代码保留在一个单独的对象中，然后将此对象用作混合对象，将其功能添加到任何决定成为发布者的其他对象中。这样，任何对象都可以成为发布者，任何函数都可以成为订阅者。观察者对象将具有以下属性和方法：

+   一个 `subscribers` 数组，它们只是回调函数

+   `addSubscriber()` 和 `removeSubscriber()` 方法，用于向 `subscribers` 集合添加和移除订阅者

+   一个 `publish()` 方法，它接受数据并调用所有订阅者，将数据传递给它们

+   一个 `make()` 方法，它接受任何对象，并通过向其添加之前提到的所有方法将其转换为发布者

这是一个包含所有订阅相关方法的观察者混合对象，可以用来将任何对象转换为发布者：

```js
    var observer = { 
      addSubscriber: function (callback) { 
        if (typeof callback === "function") { 
          this.subscribers[this.subscribers.length] = callback; 
        } 
      }, 
      removeSubscriber: function (callback) { 
        for (var i = 0; i < this.subscribers.length; i++) { 
          if (this.subscribers[i] === callback) { 
            delete this.subscribers[i]; 
          } 
        } 
      }, 
      publish: function (what) { 
        for (var i = 0; i < this.subscribers.length; i++) { 
          if (typeof this.subscribers[i] === 'function') { 
            this.subscribersi; 
          } 
        } 
      }, 
      make: function (o) { // turns an object into a publisher 
        for (var i in this) { 
          if (this.hasOwnProperty(i)) { 
            o[i] = this[i]; 
            o.subscribers = []; 
          } 
        } 
      } 
   }; 

```

现在，让我们创建一些发布者。发布者可以是任何对象，其唯一职责是在发生重要事件时调用 `publish()` 方法。这里有一个 `blogger` 对象，每次准备好新的博客帖子时都会调用 `publish()`：

```js
    var blogger = { 
      writeBlogPost: function() { 
        var content = 'Today is ' + new Date(); 
        this.publish(content); 
      } 
    }; 

```

另一个对象可以是 LA Times 报纸，当有新的报纸发布时调用 `publish()`。考虑以下代码行：

```js
    var la_times = { 
      newIssue: function() { 
        var paper = 'Martians have landed on Earth!'; 
        this.publish(paper); 
      } 
    }; 

```

您可以将这些对象转换为发布者，如下所示：

```js
    observer.make(blogger); 
    observer.make(la_times); 

```

现在，让我们来看一下以下两个简单的对象，`jack` 和 `jill`：

```js
    var jack = { 
      read: function(what) { 
        console.log("I just read that " + what) 
      } 
    }; 
    var jill = { 
      gossip: function(what) { 
        console.log("You didn't hear it from me, but " + what) 
      } 
    }; 

```

`jack` 和 `jill` 对象可以通过提供他们想要在发布时调用的回调方法来订阅 `blogger` 对象，如下所示：

```js
    blogger.addSubscriber(jack.read); 
    blogger.addSubscriber(jill.gossip); 

```

现在，当 `blogger` 对象写了一个新的帖子时会发生什么？结果是 `jack` 和 `jill` 会收到通知：

```js
    > blogger.writeBlogPost(); 
       I just read that Today is Fri Jan 04 2013 19:02:12 GMT-0800 (PST) 
       You didn't hear it from me, but Today is Fri Jan 04 2013 19:02:12 GMT-0800    
         (PST) 

```

在任何时候，`jill` 可能决定取消她的订阅。然后，在写另一篇博客文章时，已取消订阅的对象将不再收到通知。考虑以下代码片段：

```js
    > blogger.removeSubscriber(jill.gossip); 
    > blogger.writeBlogPost();
    I just read that Today is Fri Jan 04 2013 19:03:29 GMT-0800 (PST) 

```

`jill` 对象可以决定订阅 LA Times，因为一个对象可以订阅多个发布者，如下所示：

```js
    > la_times.addSubscriber(jill.gossip); 

```

然后，当 LA Times 发布新问题时，`jill` 被通知并执行 `jill.gossip()`，如下所示：

```js
    > la_times.newIssue();
    You didn't hear it from me, but Martians have landed on Earth! 

```

# 总结

在本章中，您了解了常见的 JavaScript 编码模式，并学会了如何使您的程序更清洁、更快速，并更好地与其他程序和库一起工作。然后，您看到了《四人组设计模式》中一些设计模式的讨论和示例实现。您可以看到 JavaScript 是一种功能齐全的动态编程语言，而在动态弱类型语言中实现经典模式是相当容易的。总的来说，模式是一个大主题，您可以加入本书的作者在 [JSPatterns.com](http://www.jspatterns.com/) 进一步讨论 JavaScript 模式，或者查看 *JavaScript Patterns* 书籍。下一章将重点介绍测试和调试方法论。


# 第十二章：测试和调试

当你编写 JavaScript 应用程序时，你很快会意识到拥有一个完善的测试策略是不可或缺的。事实上，不写足够的测试几乎总是一个坏主意。覆盖代码的所有非平凡功能是至关重要的，以确保以下几点：

+   现有代码按规范行为

+   任何新代码都不会破坏规范定义的行为

这两点都非常重要。许多工程师只考虑第一点作为足够测试代码的唯一原因。测试覆盖的最明显优势是确保推送到生产系统的代码大部分是无错误的。聪明地编写测试用例以覆盖代码的最大功能区域，通常可以很好地指示代码的整体质量。在这一点上不应该有争论或妥协。尽管很不幸，许多生产系统仍然缺乏足够的代码覆盖。建立一个工程文化，让开发人员像编写代码一样考虑编写测试是非常重要的。

第二点更加重要。传统系统通常很难管理。当你在处理代码时，无论是别人写的还是由一个大型分布式团队编写的，很容易引入错误并破坏事物。即使是最优秀的工程师也会犯错。当你在处理一个你不熟悉的大型代码库时，如果没有足够的测试覆盖来帮助你，你会引入错误。因为没有测试用例来确认你的更改，你对自己的更改没有信心，你的代码发布将是不稳定的，缓慢的，显然充满了隐藏的错误。

你将不会重构或优化你的代码，因为你不会真正确定对代码库的更改可能会破坏什么（同样，因为没有测试用例来确认你的更改）；所有这些都是一个恶性循环。这就像土木工程师说-尽管我建造了这座桥，但我对建筑质量没有信心。它可能会立即倒塌，也可能永远不会。尽管这听起来可能有些夸张，但我见过很多高影响的生产代码被推送而没有测试覆盖。这是有风险的，应该避免。当你编写足够的测试用例来覆盖大部分功能代码时，当你对这些部分进行更改时，你会立即意识到是否存在问题。如果你的更改导致测试用例失败，你会意识到问题。如果你的重构破坏了测试场景，你会意识到问题；所有这些都发生在代码被推送到生产之前。

近年来，像测试驱动开发和自测试代码这样的想法在敏捷方法中变得越来越重要。这些都是基本合理的想法，将帮助你编写健壮的代码-你有信心的代码。我们将在本章讨论所有这些想法。我们将了解如何在现代 JavaScript 中编写良好的测试用例。我们还将看一些工具和方法来调试你的代码。传统上，由于缺乏工具，JavaScript 测试和调试都有些困难，但现代工具使这两者都变得容易和自然。

# 单元测试

当我们谈论测试用例时，我们大多指的是单元测试。假设我们要测试的单元总是一个函数是不正确的。这个单元，或者说工作单元，是一个构成单一行为的逻辑单元。这个单元应该能够通过公共接口被调用，并且应该能够独立进行测试。

因此，单元测试可以执行以下功能：

+   它测试一个单一的逻辑函数

+   它可以在没有特定执行顺序的情况下运行

+   它负责处理自己的依赖和模拟数据

+   对于相同的输入，总是返回相同的结果

+   它应该是自解释的，可维护的和可读的

Martin Fowler 提倡*测试金字塔*（[`martinfowler.com/bliki/TestPyramid.html`](http://martinfowler.com/bliki/TestPyramid.html)）策略，以确保我们有大量的单元测试来确保最大的代码覆盖率。在本章中，我们将讨论两种重要的测试策略。

## 测试驱动开发

**测试驱动开发**（**TDD**）在过去几年中变得非常重要。这个概念最初是作为极限编程方法论的一部分提出的。其核心思想是有短小的重复开发周期，重点是先编写测试用例。这个周期看起来像下面这样：

1.  根据代码单元的具体规格添加一个测试用例。

1.  运行现有的测试套件，看看你编写的新测试用例是否失败；它应该失败，因为该单元尚未有代码。这一步确保当前的测试工具能够正常工作。

1.  编写的代码主要用于确认测试用例。这段代码并没有经过优化、重构，甚至可能并不完全正确。但是，目前来说这是可以接受的。

1.  重新运行测试，看看所有的测试用例是否通过。经过这一步，你可以确信新代码没有破坏任何东西。

1.  重构代码以确保你正在优化单元并处理所有边缘情况

这些步骤对于你添加的任何新代码都是重复的。这是一种对敏捷方法论非常有效的优雅策略。只有当可测试的代码单元很小并且仅符合测试用例时，TDD 才会成功。

## 行为驱动开发

在尝试遵循 TDD 时一个非常常见的问题是词汇和正确性的定义。BDD 试图在遵循 TDD 时引入一种通用语言。这种语言确保业务和工程都在讨论同一件事情。

我们将使用 Jasmine 作为主要的 BDD 框架，并探索各种测试策略。

### 注意

你可以通过从[`github.com/jasmine/jasmine/releases/download/v2.3.4/jasmine-standalone-2.3.4.zip`](https://github.com/jasmine/jasmine/releases/download/v2.3.4/jasmine-standalone-2.3.4.zip)下载独立包来安装 Jasmine。

当你解压这个包时，你会看到以下的目录结构：

![行为驱动开发](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_12_001.jpg)

`lib`目录包含了你在项目中需要的 JavaScript 文件，用于开始编写 Jasmine 测试用例。如果你打开`SpecRunner.html`，你会发现其中包含了以下 JavaScript 文件：

```js
    <script src="lib/jasmine-2.3.4/jasmine.js"></script> 
    <script src="lib/jasmine-2.3.4/jasmine-html.js"></script> 
    <script src="lib/jasmine-2.3.4/boot.js"></script>     

    <!-- include source files here... -->    
    <script src="src/Player.js"></script>    
    <script src="src/Song.js"></script>     
    <!-- include spec files here... -->    
    <script src="spec/SpecHelper.js"></script>    
    <script src="spec/PlayerSpec.js"></script> 

```

前三个是 Jasmine 自己的框架文件。接下来的部分包括我们想要测试的源文件和实际的测试规格。

让我们通过一个非常普通的例子来尝试 Jasmine。创建一个`bigfatjavascriptcode.js`文件，并将其放在`src/`目录中。我们将要测试的函数如下：

```js
    function capitalizeName(name){ 
      return name.toUpperCase(); 
    } 

```

这是一个简单的函数，只做了一件事情。它接收一个字符串并返回一个大写的字符串。我们将围绕这个函数测试各种情况。这就是我们之前讨论过的代码单元。

接下来，创建测试规格。创建一个 JavaScript 文件`test.spec.js`，并将其放在`spec/`目录中。你需要将以下两行添加到你的`SpecRunner.html`中：文件应包含以下内容：

```js
    <script src="src/bigfatjavascriptcode.js"></script>     
    <script src="spec/test.spec.js"></script>    

```

包含的顺序并不重要。当我们运行`SpecRunner.html`时，你会看到类似以下图片的内容：

![行为驱动开发](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_12_002.jpg)

这是 Jasmine 报告，显示了执行的测试数量以及失败和成功的数量。现在，让我们让测试用例失败。我们想要测试一个情况，即将一个`undefined`变量传递给函数。让我们添加一个测试用例，如下所示：

```js
    it("can handle undefined", function() { 
        var str= undefined; 
        expect(capitalizeName(str)).toEqual(undefined); 
    }); 

```

现在，当你运行`SpecRunner`时，你会看到以下结果：

![行为驱动开发](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_12_003.jpg)

正如你所看到的，这个测试用例显示了一个详细的错误堆栈的失败。现在，我们将着手解决这个问题。在你的原始 JS 代码中，处理 undefined 如下：

```js
    function capitalizeName(name){ 
      if(name){ 
        return name.toUpperCase(); 
      }   
    } 

```

通过这个改变，你的测试用例将通过，并且你将在 Jasmine 报告中看到以下结果：

![行为驱动开发](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_12_004.jpg)

这非常类似于测试驱动开发的样子。你编写测试用例，然后填写必要的代码以符合规范，并重新运行测试套件。让我们了解一下 Jasmine 测试的结构。

我们的测试规范看起来像以下代码片段：

```js
    describe("TestStringUtilities", function() { 
          it("converts to capital", function() { 
              var str = "albert"; 
              expect(capitalizeName(str)).toEqual("ALBERT"); 
          }); 
          it("can handle undefined", function() { 
              var str= undefined; 
              expect(capitalizeName(str)).toEqual(undefined); 
          }); 
    }); 

```

`describe("TestStringUtilities"`是一个测试套件。测试套件的名称应该描述我们正在测试的代码单元；这可以是一个函数或一组相关功能。在规范内部，你将调用全局的 Jasmine 函数`it`，并传递规范的标题和验证测试用例条件的函数。这个函数就是实际的测试用例。你可以使用`expect`函数捕获一个或多个断言或一般的期望。当所有期望都为`true`时，你的规范通过了。你可以在`describe`和`it`函数内部编写任何有效的 JavaScript 代码。作为期望的一部分验证的值使用匹配器进行匹配。在我们的例子中，`toEqual`是匹配器，用于匹配两个值是否相等。Jasmine 包含丰富的匹配器，适合大多数常见用例。Jasmine 支持的一些常见匹配器如下：

+   toBe：这个匹配器检查被比较的两个对象是否相等。这与===比较相同。例如，看下面的代码片段：

```js
        var a = { value: 1}; 
        var b = { value: 1 }; 

        expect(a).toEqual(b);  // success, same as == comparison 
        expect(b).toBe(b);     // failure, same as === comparison 
        expect(a).toBe(a);     // success, same as === comparison 

```

+   not：你可以用 not 前缀否定一个匹配项。例如，`expect(1).not.toEqual(2);`将否定`toEqual()`所做的匹配。

+   toContain：这个检查一个元素是否是数组的一部分。它不是一个精确的对象匹配，如 toBe。例如，看一下下面的代码行：

```js
        expect([1, 2, 3]).toContain(3); 
        expect("astronomy is a science").toContain("science"); 

```

+   toBeDefined 和 toBeUndefined：这两个匹配项很方便，可以检查变量是否为 undefined。

+   toBeNull：这个检查变量的值是否为 null。

+   toBeGreaterThan 和 toBeLessThan：这两个匹配器执行数字比较（也适用于字符串）。例如，考虑以下代码片段：

```js
        expect(2).toBeGreaterThan(1); 
        expect(1).toBeLessThan(2); 
        expect("a").toBeLessThan("b"); 

```

Jasmine 的一个有趣特性是间谍。当你编写一个大型系统时，不可能确保所有系统始终可用和正确。同时，你不希望你的单元测试因为一个可能被破坏或不可用的依赖而失败。为了模拟所有依赖都可用于我们要测试的代码单元的情况，我们将模拟这个依赖，始终给出我们期望的响应。模拟是测试的一个重要方面，大多数测试框架都提供了模拟支持。Jasmine 允许使用一个名为**Spy**的功能进行模拟。Jasmine 间谍本质上是我们可能在编写测试用例时没有准备好的函数的存根，但作为功能的一部分，我们需要跟踪我们正在执行这些依赖项而不是忽略它们。考虑以下例子：

```js
    describe("mocking configurator", function() { 
      var cofigurator = null; 
      var responseJSON = {}; 

      beforeEach(function() { 
        configurator = { 
          submitPOSTRequest: function(payload) { 
            //This is a mock service that will eventually be replaced  
            //by a real service 
            console.log(payload); 
            return {"status": "200"}; 
          } 
        }; 
        spyOn(configurator, 'submitPOSTRequest').and.returnValue
         ({"status": "200"}); 
       configurator.submitPOSTRequest({ 
          "port":"8000", 
          "client-encoding":"UTF-8" 
        }); 
      }); 

      it("the spy was called", function() { 
        expect(configurator.submitPOSTRequest).toHaveBeenCalled(); 
      }); 

      it("the arguments of the spy's call are tracked", function() { 
        expect(configurator.submitPOSTRequest).toHaveBeenCalledWith(
          {"port":"8000", "client-encoding":"UTF-8"}); 
      }); 
    }); 

```

在这个例子中，当我们编写这个测试用例时，我们要么没有依赖项`configurator.submitPOSTRequest()`的真正实现，要么有人正在修复这个特定的依赖项；无论哪种情况，我们都没有它可用。为了使我们的测试工作，我们需要模拟它。Jasmine 间谍允许我们用它的模拟替换一个函数，并允许我们跟踪它的执行。

在这种情况下，我们需要确保调用了依赖项。当实际的依赖项准备好时，我们将重新访问这个测试用例，以确保它符合规范；然而，此时，我们只需要确保调用了依赖项。Jasmine 函数`tohaveBeenCalled()`让我们跟踪可能是模拟的函数的执行。我们可以使用`toHaveBeenCalledWith()`，它允许我们确定存根函数是否使用正确的参数进行了调用。使用 Jasmine 间谍可以创建几种其他有趣的场景。本章的范围不允许我们覆盖它们所有，但我鼓励你自己发现这些领域。

## 摩卡，柴和西农

尽管 Jasmine 是最突出的 JavaScript 测试框架，但 mocha 和 chai 在`Node.js`环境中也越来越受到重视。

+   Mocha 是用于描述和运行测试用例的测试框架

+   柴是 Mocha 支持的断言库

+   西农在创建测试时非常方便地创建模拟和存根

我们不会在本书中讨论这些框架；然而，如果你想尝试这些框架，对 Jasmine 的经验将会很有帮助。

# JavaScript 调试

如果你不是一个完全新的程序员，我相信你一定花了一些时间来调试你自己或别人的代码。调试几乎就像一种艺术形式。每种语言在调试方面都有不同的方法和挑战。JavaScript 传统上是一种难以调试的语言。我曾经在痛苦中度过了几天几夜，试图使用`alert()`函数调试糟糕的 JavaScript 代码。幸运的是，现代浏览器，如 Mozilla，Firefox 和 Google Chrome，都有出色的**开发者工具**，可以帮助在浏览器中调试 JavaScript。还有像 IntelliJ IDEA 和 WebStorm 这样的 IDE，对 JavaScript 和 Node.js 有很好的调试支持。在本章中，我们将主要关注 Google Chrome 内置的开发者工具。Firefox 也支持 Firebug 扩展，并且有出色的内置开发者工具，但由于它们的行为与 Google Chrome 的**开发者工具**几乎相同，我们将讨论在这两种工具中都适用的常见调试方法。

在我们讨论具体的调试技术之前，让我们了解一下在尝试调试我们的代码时我们感兴趣的错误类型。

## 语法错误

当你的代码有一些不符合 JavaScript 语法的东西时，解释器会拒绝那部分代码。如果你的 IDE 帮助你进行语法检查，这些错误很容易被捕捉到。大多数现代 IDE 都可以帮助解决这些错误。早些时候，我们讨论了工具的有用性，比如 JSLint 和 JSHint，可以帮助捕捉代码中的语法问题。它们分析代码并标记语法错误。JSHint 的输出可能非常有启发性。例如，以下输出显示了我们可以在代码中进行的许多更改。以下代码片段来自我的一个现有项目：

```js
    temp git:(dev_branch) X jshint test.js 
    test.js: line 1, col 1, Use the function form of "use strict". 
    test.js: line 4, col 1, 'destructuring expression' 
      is available in ES6 (use esnext option) or 
      Mozilla JS extensions (use moz). 
    test.js: line 44, col 70, 'arrow function syntax (=>)' 
      is only available in ES6 (use esnext option). 
    test.js: line 61, col 33, 'arrow function syntax (=>)'
      is only available in ES6 (use esnext option). 
    test.js: line 200, col 29, Expected ')' to match '(' from
      line 200 and instead saw ':'. 
    test.js: line 200, col 29, 'function closure expressions' 
      is only available in Mozilla JavaScript extensions (use moz option). 
    test.js: line 200, col 37, Expected '}' to match '{' from 
      line 36 and instead saw ')'. 
    test.js: line 200, col 39, Expected ')' and instead saw '{'. 
    test.js: line 200, col 40, Missing semicolon. 

```

### 使用严格模式

我们在前几章中简要讨论了严格模式。当你启用严格模式时，JavaScript 不再接受代码中的语法错误。严格模式不会悄悄失败，而是会将这些失败抛出错误。它还可以帮助你将错误转换为实际的错误。有两种强制使用严格模式的方法。如果你想要整个脚本都使用严格模式，你可以在 JavaScript 程序的第一行添加`use strict`语句（带引号）。如果你想要特定函数符合严格模式，你可以将指令添加为函数的第一行。例如，看一下以下代码片段：

```js
    function strictFn(){    
      // This line makes EVERYTHING under this scrict mode 
      'use strict';    
      ... 
      function nestedStrictFn() {  
        //Everything in this function is also nested 
        ... 
      }    
    } 

```

## 运行时异常

当您执行代码时，出现这些错误，尝试引用一个`未定义`的变量，或者尝试处理`null`。当运行时异常发生时，导致异常的特定行之后的任何代码都不会被执行。在代码中正确处理这种异常情况是至关重要的。虽然异常处理可以帮助防止崩溃，但它们也有助于调试。您可以将可能遇到运行时异常的代码包装在`try{ }`块中。当此块内的任何代码生成运行时异常时，相应的处理程序会捕获它。处理程序由`catch(exception){}`块定义。让我们通过以下示例来澄清这一点：

```js
    try { 
      var a = doesnotexist; // throws a runtime exception 
    } catch(e) {  
      console.log(e.message);  //handle the exception 
      //prints - "doesnotexist is not defined" 
    } 

```

在这个例子中，`var a = doesnotexist`行试图将一个`未定义`的变量`doesnotexist`赋值给另一个变量`a`。这会导致运行时异常。当我们将这个有问题的代码包装在`try{}catch(){}`块中，或者当异常发生（或被抛出）时，执行会在`try{}`块中停止，并直接转到`catch() {}`处理程序。捕获处理程序负责处理异常情况。在这种情况下，我们为了调试目的在控制台上显示错误消息。您可以明确地抛出异常来触发代码中未处理的情况。考虑以下的例子：

```js
    function engageGear(gear){ 
      if(gear==="R"){ console.log ("Reversing");} 
      if(gear==="D"){ console.log ("Driving");} 
      if(gear==="N"){ console.log ("Neutral/Parking");} 
      throw new Error("Invalid Gear State"); 
    } 
    try 
    { 
      engageGear("R");  //Reversing 
      engageGear("P");  //Invalid Gear State 
    } 
    catch(e){ 
      console.log(e.message); 
    } 

```

在这个例子中，我们正在处理变速器的有效状态：`R`，`N`和`D`；然而，当我们收到无效状态时，我们明确地抛出异常，清楚地说明原因。当我们调用可能引发异常的函数时，我们将在`try{}`块中包装代码，并附加一个带有`catch(){}`的处理程序。当异常被`catch()`块捕获时，我们将适当地处理异常情况。

### Console.log 和断言

在控制台上显示执行状态在调试时可能非常有用。尽管现代开发工具允许您设置断点并在运行时停止执行以检查特定值，但通过在控制台上记录一些变量状态，您可以快速检测到一些小问题。

有了这些概念，让我们看看如何使用 Chrome **开发者工具**来调试 JavaScript 代码。

### Chrome 开发者工具

您可以通过单击**菜单** | **更多工具** | **开发者工具**来启动 Chrome **开发者工具**。看一下以下的屏幕截图：

![Chrome Developer Tools](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_12_005.jpg)

Chrome 开发者工具在浏览器的下方窗格中打开，并且有一堆非常有用的部分。考虑以下的屏幕截图：

![Chrome Developer Tools](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_12_006.jpg)

**元素**面板帮助您检查和监视 DOM 树和每个组件的相关样式表。

**网络**面板对于理解网络活动非常有用。例如，您可以实时监视通过网络下载的资源。

对我们来说最重要的窗格是**Sources**窗格。这个窗格显示了 JavaScript 和调试器。让我们创建一个包含以下内容的示例 HTML：

```js
    <!DOCTYPE html> 
    <html> 
    <head> 
      <meta charset="utf-8"> 
      <title>This test</title> 
      <script type="text/javascript"> 
      function engageGear(gear){ 
        if(gear==="R"){ console.log ("Reversing");} 
        if(gear==="D"){ console.log ("Driving");} 
        if(gear==="N"){ console.log ("Neutral/Parking");} 
        throw new Error("Invalid Gear State"); 
      } 
      try 
      { 
        engageGear("R");  //Reversing 
        engageGear("P");  //Invalid Gear State 
      } 
      catch(e){ 
        console.log(e.message); 
      } 
      </script> 
    </head> 
    <body> 
    </body> 
    </html> 

```

保存这个 HTML 文件并在 Google Chrome 中打开它。在浏览器中打开**开发者工具**，您将看到以下屏幕：

![Chrome Developer Tools](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_12_007.jpg)

这是**Sources**面板的视图。您可以在此面板中看到 HTML 和嵌入的 JavaScript 源代码。您还可以看到**Console**窗口，并且可以看到文件被执行并且输出显示在控制台上。

在右侧，您将看到调试器窗口，如下面的屏幕截图所示：

![Chrome Developer Tools](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_12_008.jpg)

在**Sources**面板中，单击行号**8**和**15**以添加断点。断点允许您在指定的位置停止脚本的执行。考虑以下的屏幕截图：

![Chrome Developer Tools](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/5239_12.jpg)

在调试窗格中，您可以看到所有现有的断点。看一下以下的屏幕截图：

![Chrome 开发者工具](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_12_010.jpg)

现在，当您重新运行同一个页面时，您会看到执行停在调试点。请看下面的截图：

![Chrome 开发者工具](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_12_011.jpg)

这个窗口现在有了所有的操作。您可以看到执行已经暂停在第 15 行。在调试窗口中，您可以看到触发了哪个断点。您还可以看到**调用堆栈**并以多种方式恢复执行。调试命令窗口有很多操作。看一下下面的截图：

![Chrome 开发者工具](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_12_012.jpg)

您可以通过点击以下按钮恢复执行，直到下一个断点：

![Chrome 开发者工具](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_12_013.jpg)

当您这样做时，执行会继续，直到遇到下一个断点。在我们的情况下，我们将在第 8 行停下来。请看下面的截图：

![Chrome 开发者工具](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_12_014.jpg)

您可以观察到**调用堆栈**窗口显示了我们是如何到达第 8 行的。**作用域**面板显示了**局部**作用域，在断点到达时您可以看到作用域中的变量。您还可以步进或跳过下一个函数。

使用 Chrome 开发者工具还有其他非常有用的机制来调试和分析您的代码。我建议您尝试使用这个工具，并将其作为您常规开发流程的一部分。

# 总结

测试和调试阶段对于开发健壮的 JavaScript 代码至关重要。TDD 和 BDD 是与敏捷方法学密切相关的方法，被 JavaScript 开发者社区广泛接受。在本章中，我们回顾了围绕 TDD 的最佳实践以及 Jasmine 作为测试框架的使用。此外，我们还看到了使用 Chrome 开发者工具调试 JavaScript 的各种方法。

在下一章中，我们将探索 ES6、DOM 操作和跨浏览器策略的新颖世界。


# 第十三章：响应式编程和 React

随着 ES6，一些新的想法正在涌现。这些是强大的想法，可以帮助你用更简洁的代码和设计构建强大的系统。在本章中，我们将向你介绍两种这样的想法-响应式编程和 react。尽管它们听起来相似，但它们是非常不同的。本章不会详细讨论这些想法的实际细节，但会给你必要的信息，让你了解这些想法的潜力。有了这些信息，你可以开始将这些想法和框架融入到你的项目中。我们将讨论响应式编程的基本思想，并更详细地看一下 react。

# 响应式编程

响应式编程最近受到了很多关注。这个想法相对较新，像许多新想法一样，有很多令人困惑的，有时是矛盾的信息在流传。我们在本书的前面讨论了异步编程。JavaScript 通过提供支持异步编程的一流语言构造，将异步编程推向了新的高度。

响应式编程本质上是使用异步事件流进行编程。事件流是随时间发生的事件序列。考虑以下图表：

![Reactive programming](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_13_001.jpg)

在上图中，时间从左到右流逝，不同的事件随时间发生。随着事件随时间发生，我们可以向整个序列添加事件监听器。每当事件发生时，我们都可以通过做一些事情来对其做出反应。

JavaScript 中的另一种序列是数组。例如，考虑以下代码行：

```js
    var arr = [1,1,13,'Rx',0,0]; 
    console.log(arr); 
    >>> [1, 1, 13, "Rx", 0, 0] 

```

在这种情况下，整个序列同时存在于内存中。然而，在事件流的情况下，事件随时间发生，此时没有状态。考虑以下代码行：

```js
    var arr = Rx.Observable.interval(500).take(9).map(
      a=>[1,1,13,'Rx',0,0][a]); 
    var result = arr; 
    result.subscribe(x=>console.log(x)); 

```

暂时不要太担心这个例子中发生了什么。在这里，事件是随时间发生的。这里不是有一个固定的数组元素，而是随时间发生的，500 毫秒后。

我们将向`arr`事件流添加一个事件监听器，当事件发生时，我们将在控制台上打印出元素。你可以看到数组和事件流中的方法之间的相似之处。现在，为了扩展这种相似性，假设你想要从这个列表中过滤掉所有的非数字。你可以使用`map`函数来处理这个事件流，就像你在数组上使用它一样，然后你会想要过滤结果，只显示整数。考虑以下代码行：

```js
    var arr = [1,1,13,'Rx',0,0]; 
    var result = arr.map(x => parseInt(x)).filter(x => !isNan(x)); 
    console.log(result); 

```

有趣的是，相同的方法也适用于事件流。看一下以下代码示例：

```js
    var arr = Rx.Observable.interval(500).take(9).map(
      a=>[1,1,13,'Rx',0,0][a]); 
    var result = arr.map(x => parseInt(x)).filter(x => !isNaN(x)); 
    result.subscribe(x=>console.log(x)); 

```

这些只是更简单的例子，只是为了确保你开始看到事件流随时间流动。请暂时不要担心语法和结构。在我们能够看它们之前，我们需要确保我们理解如何在响应式编程中思考。事件流对于响应式编程至关重要；它们允许你在声明时定义值的动态行为（定义来自 Andre Staltz 的博客）。

假设你有一个`a`变量，最初的值是`3`。然后，你有一个`b`变量，它是`10 * a`。如果我们在控制台上输出`b`，我们会看到`30`。考虑以下代码行：

```js
    let a = 3; 
    let b = a * 10; 
    console.log(b); //30 
    a = 4; 
    console.log(b); // Still 30 

```

我们知道结果是非常直接的。当我们将`a`的值更改为`4`时，`b`的值不会改变。这就是静态声明的工作原理。当我们谈论响应式编程和事件流时，这是人们在理解事件流如何流动时遇到困难的地方。理想情况下，我们希望创建一个公式，*b=a*10*，随着时间的推移，无论`a`的值如何变化，变化的值都会反映在公式中。

这就是我们可以通过事件流实现的。假设`a`是一个只有值`3`的事件流。然后，我们有`streamB`，它是`streamA`映射的结果。每个`a`值都将映射为`10 * a`。

如果我们给`streamB`添加一个事件监听器，并且我们控制台记录，我们会看到`b`是`30`。看一下以下的例子：

```js
    var streamA = Rx.Observable.of(3, 4); 
    var streamB = streamA.map(a => 10 * a); 
    streamB.subscribe(b => console.log(b)); 

```

如果我们这样做，我们将得到一个事件流，它只有两个事件。它有事件`3`，然后有事件`4`，当`a`改变时，`b`也会相应地改变。如果我们运行这个，我们会看到`b`是`30`和`40`。

现在我们已经花了一些时间来了解响应式编程的基础知识，你可能会问以下问题。

## 为什么你应该考虑响应式编程？

在我们编写现代网络和移动应用程序时，需要高度响应和交互式的 UI 应用程序，有必要找到一种处理实时事件而不会停止用户在 UI 上交互的方法。当你处理多个 UI 和服务器事件时，你将花费大部分时间编写处理这些事件的代码。这很繁琐。响应式编程为你提供了一个结构化的框架，以最少的代码处理异步事件，同时你可以专注于应用程序的业务逻辑。

响应式编程不仅限于 JavaScript。响应式扩展在许多平台和语言中都有，比如 Java、Scala、Clojure、Ruby、Python 和 Object C/Cocoa。`Rx.js`和`Bacon.js`是流行的提供响应式编程支持的 JavaScript 库。

深入研究`Rx.js`不是本章的目的。我们的目的是向你介绍响应式编程的概念。如果你有兴趣为你的项目采用响应式编程，你应该看看 Andre Staltz 的优秀介绍（[`gist.github.com/staltz/868e7e9bc2a7b8c1f754`](https://gist.github.com/staltz/868e7e9bc2a7b8c1f754)）。

# React

React 正在以 JavaScript 世界为风暴。Facebook 创建了 React 框架来解决一个古老的问题-如何有效地处理传统的**模型-视图-控制器**应用程序的视图部分。

React 提供了一种声明式和灵活的构建用户界面的方式。关于 React 最重要的一点是，它只处理一个东西-视图或 UI。React 不处理数据、数据绑定或其他任何东西。有完整的框架，比如 Angular，处理数据、绑定和 UI；React 不是那样的。

React 提供了一个模板语言和一小组函数来渲染 HTML。React 组件可以在内存中存储它们自己的状态。要构建一个完整的应用程序，你还需要其他部分；React 只是处理该应用程序的视图部分。

在编写复杂 UI 时的一个大挑战是在模型改变时管理 UI 元素的状态。React 提供了一个声明式 API，这样你就不必担心每次更新时确切发生了什么变化。这使得编写应用程序变得更加容易。React 使用虚拟 DOM 和差异算法，因此组件更新是可预测的，同时也足够快以用于高性能应用程序。

# 虚拟 DOM

让我们花一点时间来了解什么是虚拟 DOM。我们讨论了**DOM**（文档对象模型），一个网页上 HTML 元素的树结构。DOM 是事实上的，也是网页的主要渲染机制。DOM 的 API，比如`getElementById()`，允许遍历和修改 DOM 树中的元素。DOM 是一棵树，这种结构非常适合遍历和更新元素。然而，DOM 的遍历和更新都不是很快。对于一个大页面，DOM 树可能会相当大。当你想要一个有大量用户交互的复杂 UI 时，更新 DOM 元素可能会很繁琐和缓慢。我们已经尝试过 jQuery 和其他库来减少频繁 DOM 修改的繁琐语法，但 DOM 本身作为一种结构是相当有限的。

如果我们不必一遍又一遍地遍历 DOM 来修改元素呢？如果您只是声明组件应该是什么样子，然后让其他人处理如何渲染该组件的逻辑呢？react 就是这样做的。React 允许您声明您希望 UI 元素看起来像什么，并将低级别的 DOM 操作 API 抽象出来。除了这个非常有用的抽象之外，react 还做了一些相当聪明的事情来解决性能问题。

React 使用一种称为虚拟 DOM 的东西。虚拟 DOM 是 HTML DOM 的轻量级抽象。您可以将其视为 HTML DOM 的本地内存副本。React 使用它来执行呈现 UI 组件状态所需的所有计算。

您可以在[`facebook.github.io/react/docs/reconciliation.html`](https://facebook.github.io/react/docs/reconciliation.html)找到有关此优化的更多详细信息。

然而，React 的主要优势不仅仅是虚拟 DOM。React 是一个很棒的抽象，使得在开发大型应用程序时更容易进行组合、单向数据流和静态建模。

# 安装和运行 react

首先，让我们安装 react。早些时候，在您的计算机上安装和设置 react 需要处理一堆依赖项。但是，我们将使用一个相对更快的方法来让 react 运行起来。我们将使用`create-react-app`，通过它可以安装 react 而无需任何构建配置。安装是通过`npm`完成的，如下所示：

```js
    npm install -g create-react-app 

```

在这里，我们正在全局安装`create-react-app`节点模块。安装了`create-react-app`之后，您可以为应用程序设置目录。考虑以下命令：

```js
    create-react-app react-app 
    cd react-app/ 
    npm start 

```

然后，打开`http://localhost:3000/`来查看您的应用程序。您应该会看到类似以下屏幕截图的内容：

![Installing and running react](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_13_002.jpg)

如果您在编辑器中打开目录，您将看到为您创建了几个文件，如下面的屏幕截图所示：

![Installing and running react](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_13_003.jpg)

在这个项目中，`node_modules`是运行此项目所需的依赖项，也是 react 本身的依赖项。重要的目录是`src`，其中保存了源代码。对于这个示例，让我们只保留两个文件-`App.js`和`index.js`。`/public/index.html`文件应该只包含根`div`，它将用作我们的 react 组件的目标。考虑以下代码片段：

```js
    <!doctype html> 
    <html lang="en"> 
      <head> 
        <title>React App</title> 
      </head> 
      <body> 
 **<div id="root"></div>** 
      </body> 
    </html> 

```

进行这种更改的时候，您将看到以下错误：

![Installing and running react](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_13_004.jpg)

使用 react 进行开发的美妙之处在于代码更改是实时重新加载的，您可以立即得到反馈。

接下来，清空`App.js`的所有内容，并用以下代码替换它：

```js
    import React from 'react'; 
    const App = () => <h1>Hello React</h1> 
    export default App 

```

现在，转到`index.js`并删除`import ./index.css;`行。您无需做任何操作，比如重新启动服务器和刷新浏览器，就可以在浏览器上看到修改后的页面。考虑以下屏幕截图：

![Installing and running react](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_13_005.jpg)

在我们创建`HelloWorld` react 组件之前，有一些重要的事情需要注意。

在`App.js`和`index.js`中，我们导入了创建 react 组件所需的两个库。考虑以下代码行：

```js
    import React from 'react'; 
    import ReactDOM from 'react-dom'; 

```

在这里，我们导入了`React`，这是一个允许我们构建 react 组件的库。我们还导入了`ReactDOM`，这是一个允许我们放置我们的组件并在 DOM 的上下文中使用它们的库。然后，我们导入了我们刚刚工作过的组件-App 组件。

我们还在`App.js`中创建了我们的第一个组件。考虑以下代码行：

```js
    const App = () => <h1>Hello React</h1> 

```

这是一个无状态函数组件。创建组件的另一种方法是创建一个类组件。我们可以用以下类组件替换前面的组件：

```js
    class App extends React.Component { 
      render(){ 
        return <h1>Hello World</h1> 
      } 
    } 

```

这里有很多有趣的事情正在发生。首先，我们使用`class`关键字创建一个类组件，它继承自超类`React.Component`。

我们的组件`App`是一个 react 组件类或 react 组件类型。组件接受参数，也称为`props`，并通过`render`函数返回要显示的视图层次结构。

`render`方法返回要渲染的描述，然后 react 接受该描述并将其渲染到屏幕上。特别是，`render`返回一个 react 元素，它是要渲染的轻量级描述。大多数 react 开发人员使用一种称为 JSX 的特殊语法，这使得编写这些结构更容易。`<div />`语法在构建时转换为`React.createElement`(`'div'`)。JSX 表达式`<h1>Hello World</h1>`在构建时转换为以下内容：

```js
    return React.createElement('h1', null, 'Hello World'); 

```

类组件和无状态函数组件之间的区别在于，类组件可以包含状态，而无状态（因此名称为）函数组件不能。

react 组件的`render`方法只允许返回单个节点。如果你做了以下操作：

```js
    return <h1>Hello World</h1><p>React Rocks</p> 

```

你会得到以下错误：

```js
    Error in ./src/App.js 
    Syntax error: Adjacent JSX elements must be wrapped in 
      an enclosing tag (4:31) 

```

这是因为你实质上返回了两个`React.createElement`函数，这不是有效的 JavaScript。虽然这可能看起来像是一个破坏者，但这很容易解决。我们可以将我们的节点包装成一个父节点，并从`render`函数返回该父节点。我们可以创建一个父`div`，并将其他节点包装在其中。考虑以下示例：

```js
    render(){ 
        return ( 
          <div> 
            <h1>Hello World</h1> 
            <p>React Rocks</p> 
          </div> 
          ) 
    } 

```

## 组件和 props

组件在概念上可以被视为 JavaScript 函数。它们像普通函数一样接受任意数量的输入。这些输入被称为 props。为了说明这一点，让我们考虑以下函数：

```js
    function Greet(props) { 
      return <h1>Hello, {props.name}</h1>; 
    } 

```

这是一个普通函数，也是一个有效的 react 组件。它接受一个名为`props`的输入，并返回一个有效的 JSX。我们可以在 JSX 中使用`props`，使用大括号和`name`等属性使用标准对象表示法。现在`Greet`是一个一流的 react 组件，让我们在`render()`函数中使用它，如下所示：

```js
    render(){ 
      return ( 
       return <Greet name="Joe"/> 
      ) 
    } 

```

我们将`Greet()`作为一个普通组件调用，并将`this.props`传递给它。自定义组件必须大写。React 认为以小写字母开头的组件名称是标准 HTML 标签，并期望自定义组件名称以大写字母开头。正如我们之前看到的，我们可以使用 ES6 类创建一个类组件。这个组件是`React.component`的子类。与我们的`Greet`函数等效的组件如下：

```js
    class Greet extends React.Component { 
      render(){ 
          return <h1>Hello, {this.props.name}</h1> 
      } 
    } 

```

就实际目的而言，我们将使用这种创建组件的方法。我们很快就会知道为什么。

一个重要的要点是组件不能修改自己的 props。这可能看起来像是一个限制，因为在几乎所有非平凡的应用程序中，你都希望用户交互在 react 中改变 UI 组件状态，例如，在表单中更新出生日期，`props`是只读的，但有一个更健壮的机制来处理 UI 更新。

## 状态

状态类似于 props，但它是私有的，并且完全由组件控制。正如我们之前看到的，React 中的函数组件和类组件是等效的，一个重要的区别是状态仅在类组件中可用。因此，就实际目的而言，我们将使用类组件。

我们可以改变我们现有的问候示例来使用状态，每当状态改变时，我们将更新我们的`Greet`组件以反映更改的值。

首先，我们将在我们的`App.js`中设置状态，如下所示：

```js
    class Greet extends React.Component { 
 **constructor(props) {**
 **super(props);** 
 **this.state = {** 
**greeting: "this is default greeting text"** 
**}** 
 **}** 
      render(){ 
          return <h1>{this.state.greeting}, {this.props.name} </h1> 
      } 
    } 

```

在这个例子中有一些重要的事情需要注意。首先，我们调用类`constructor`来初始化`this.state`。我们还调用基类构造函数`super()`，并将`props`传递给它。调用`super()`后，我们通过将`this.state`设置为一个对象来初始化我们的默认状态。例如，我们在这里给一个`greeting`属性赋值。在`render`方法中，我们将使用`{this.state.greeting}`来使用这个属性。设置了初始状态后，我们可以添加 UI 元素来更新这个状态。让我们添加一个输入框，当输入框改变时，我们将更新我们的状态和`greeting`元素。考虑以下代码行：

```js
    class Greet extends React.Component { 
      constructor(props) { 
        super(props); 
        this.state = { 
          greeting: "this is default greeting text" 
        } 
      } 
 **updateGreeting(event){** 
**this.setState({** 
**greeting:
      event.target.value,**
 **})**
 **}** 
      render(){ 
          return ( 
          <div>   
 **<input type="text" onChange={this.updateGreeting.bind(this)}/>** 
            <h1>{this.state.greeting}, {this.props.name} </h1> 
           </div>  
          ) 
        } 
    } 

```

在这里，我们添加一个输入框，并在输入框的`onChange`方法被调用时更新组件的状态。我们使用自定义的`updateGreeting()`方法通过调用`this.setState`和更新属性来更新状态。当您运行此示例时，您会注意到当您在文本框上输入内容时，只有`greeting`元素被更新，而`name`没有。看一下下面的截图：

![State](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_13_006.jpg)

React 的一个重要特性是，一个 React 组件可以输出或渲染其他 React 组件。我们这里有一个非常简单的组件。它有一个值为文本的状态。它有一个`update`方法，它将从事件中更新文本的值。我们将创建一个新的组件。这将是一个无状态函数组件。我们将它称为 widget。它将接受`props`。我们将在这里返回这个 JSX 输入。考虑以下代码片段：

```js
    render(){ 
        return ( 
          <div>   
 **<Widget update={this.updateGreeting.bind(this)} />** 
 **<Widget update={this.updateGreeting.bind(this)} />** 
 **<Widget update={this.updateGreeting.bind(this)} />** 
          <h1>{this.state.greeting}, {this.props.name} </h1> 
          </div>  
        ) 
      } 
    } 
    const Widget = (props) => <input type="text" 
      onChange={props.update}/> 

```

首先，我们将输入元素提取到一个无状态函数组件中，并将其称为`Widget`。我们将`props`传递给此组件。然后，我们将`onChange`更改为使用`props.update`。现在，在我们的`render`方法中，我们使用`Widget`组件并传递一个绑定`updateGreeting()`方法的 prop `update`。现在`Widget`是一个组件，我们可以在`Greet`组件的任何地方重用它。我们创建了`Widget`的三个实例，当任何一个`Widget`被更新时，问候文本将被更新，如下面的截图所示：

![State](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_13_007.jpg)

## 生命周期事件

当您有一堆组件和几个状态更改和事件时，清理工作变得很重要。React 为您提供了几个组件生命周期钩子来处理组件的生命周期事件。了解组件的生命周期将使您能够在创建或销毁组件时执行某些操作。此外，它还为您提供了决定是否应该首先更新组件的机会，并根据`props`或状态更改做出反应。

组件经历三个阶段-挂载、更新和卸载。对于每个阶段，我们都有钩子。看一下下面的图表：

![Life cycle events](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/oo-js-3e/img/image_13_008.jpg)

当组件初始渲染时，会调用两个方法`getDefaultProps`和`getInitialState`，正如它们的名称所暗示的，我们可以在这些方法中设置组件的默认`props`和初始状态。

`componentWillMount`在执行`render`方法之前被调用。我们已经知道`render`是我们返回要渲染的组件的地方。一旦`render`方法完成，`componentDidMount`方法就会被调用。您可以在此方法中访问 DOM，并建议在此方法中执行任何 DOM 交互。

状态更改会调用一些方法。`shouldComponentUpdate`方法在`render`方法之前被调用，它让我们决定是否应该允许重新渲染或跳过。这个方法在初始渲染时从未被调用。`componentWillUpdate`方法在`shouldComponentUpdate`方法返回`true`后立即被调用。`componentDidUpdate`方法在`render`完成后被渲染。

对`props`对象的任何更改都会触发类似状态更改的方法。另一个被调用的方法是`componentWillReceiveProps`；它仅在`props`发生变化时被调用，而且不是初始渲染。您可以在此方法中基于新旧 props 更新状态。

当组件从 DOM 中移除时，将调用`componentWillUnmount`。这是一个执行清理的有用方法。

React 的一个很棒的地方是，当您开始使用它时，这个框架对您来说会感觉非常自然。您只需要学习很少的移动部分，抽象程度恰到好处。

# 摘要

本章旨在介绍一些最近备受关注的重要新观念。响应式编程和 React 都可以显著提高程序员的生产力。React 绝对是由 Facebook 和 Netflix 等公司支持的最重要的新兴技术之一。

本章旨在为您介绍这两种技术，并帮助您开始更详细地探索它们。
