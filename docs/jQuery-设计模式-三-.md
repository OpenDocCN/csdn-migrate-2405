# jQuery 设计模式（三）

> 原文：[`zh.annas-archive.org/md5/9DBFD51895CA93BE96AC02124FF5B7E1`](https://zh.annas-archive.org/md5/9DBFD51895CA93BE96AC02124FF5B7E1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：插件和小部件开发模式

本章重点介绍了实现 jQuery 插件时使用的设计模式和最佳实践。我们将在这里学习如何将应用程序的部分抽象为单独的 jQuery 插件，促进**关注点分离**原则和代码的可重用性。

首先分析 jQuery 插件可以实现的最简单方式，学习 jQuery 插件开发的各种约定以及每个插件应满足的基本特性，以遵循 jQuery 原则。然后，我们将介绍最常用的设计模式，并分析每种模式的特点和优势。到本章结束时，我们将能够使用最适合每种情况的开发模式实现可扩展的 jQuery 插件。

在本章中，我们将：

+   介绍 jQuery 插件 API 及其约定

+   分析构成优秀插件的特点

+   学习通过扩展`$.fn`对象来创建插件

+   学习如何实现可扩展的通用插件，以使它们在更多用例中可重用

+   学习如何为插件提供选项和方法

+   介绍 jQuery 插件开发的最常见设计模式，并分析它们各自有助于解决的常见实现问题

# 引入 jQuery 插件

jQuery 插件的关键概念在于通过将其功能作为 jQuery **复合集合**对象上的方法来扩展 jQuery API。一个 jQuery 插件只是一个定义为`$.fn`对象上的新方法的函数，该对象是每个 jQuery 集合对象所继承的**原型对象**。

```js
$.fn.simplePlugin101 = function(arg1, arg2/*, ...*/) { 
    // Plugin's implementation... 
};
```

通过在`$.fn`对象上定义方法，我们实际上是扩展了核心 jQuery API 本身，因为这使得该方法在此后创建的所有 jQuery 集合对象上都可用。因此，在网页中加载了插件后，其功能将作为`$()`函数返回的每个对象的方法可用：

```js
$('h1').simplePlugin101('test', 1);
```

jQuery 插件 API 的主要约定是，调用插件的 jQuery 集合对象作为其执行上下文可用于插件的方法中。换句话说，我们可以在插件方法中使用`this`标识符，如下所示：

```js
$.fn.simplePlugin101 = function() { 
    this.slideToggle(); 
    // "this" is a jQuery object where all 
    // jQuery methods are available
};
```

## 遵循 jQuery 原则

创建插件时的一个目标是使其感觉像 jQuery 本身的一部分。阅读前几章后，您应该熟悉一些所有 jQuery 方法遵循的原则以及使其方法独特的特点。实现遵循这些原则的插件使用户更加熟悉其 API，更具生产力，并且减少了实现错误，从而增加了插件的流行度和采用率。

一个优秀的 jQuery 插件应具备的两个最重要特征如下：

+   它应该在适用的情况下应用于被调用的 jQuery 集合对象的所有元素

+   它应该允许其他 jQuery 方法的进一步链接

现在让我们继续分析这些原则的每一个。

### 在复合集合对象上操作

jQuery 方法最重要的一个特点是，它们应用于被调用的复合集合对象的每个项。例如，`$.fn.addClass()`方法在分别检查每个类是否已经在每个单独的元素上定义之后，将一个或多个 CSS 类添加到集合的每个项上。

结果，我们的 jQuery 插件也应该遵循这个原则，即在逻辑上合理时操作集合的每个元素。如果您的插件实现中仅使用 jQuery 方法，大多数情况下，您可以免费获得这一点。另一方面，需要牢记的一点是，并非所有的 jQuery 方法都作用于集合对象的每个元素。像`$.fn.html()`、`$.fn.css()`和`$.fn.data()`这样的方法用作 setter 方法时会作用于集合的所有项，但用作 getter 时只作用于第一个元素。

让我们看一个使用`$.fn.animate()`在 jQuery 对象的所有项目上创建抖动效果的插件的示例实现：

```js
$.fn.vibrate = function() { 
  this.each(function(i, element) { 
    // specifically handle every element
    var $element = $(element); 
    if ($element.css('position') === 'static') { 
      $element.css({ position: 'relative' }); 
    } 
  }); 

  this.animate({ left: '+=3' }, 30) 
    .animate({ left: '-=6' }, 60) 
    .animate({ left: '+=6' }, 60) 
    .animate({ left: '-=3' }, 30); 

  return this; // allow further chaining
};
```

用`$('button').vibrate();`调用此插件将对页面中的每个匹配元素应用抖动动画。为了实现这一点，插件使用`$.fn.animate()`方法改变所有匹配元素的`left` CSS 属性，该方法方便地操作每个元素。另一方面，由于`$.fn.css()`方法作为 getter 使用时只应用于集合的第一个元素，我们必须使用`$.fn.each()`方法迭代所有元素，并确保每个元素都不是静态定位，否则`left` CSS 属性将不会影响其外观。

显然，仅仅使用 jQuery 方法并不总是足够实现插件。在大多数情况下，一个新插件将至少需要使用一个非 jQuery API 来实现，这要求我们迭代集合的项目，并逐个应用插件的逻辑。当集合的每个元素的状态有所不同时，也应该使用相同的方法进行处理。

因此，插件通常会在`$.fn.each()`的调用中包装几乎所有的实现。通过识别显式迭代所涵盖的常见需求，jQuery 团队和大多数 jQuery 插件样板现在将其作为标准做法的一部分。

### 允许进一步的链接

通常，当您的插件代码不需要返回任何内容时，为了启用进一步的链式操作，您只需在其最后一行添加一个`return this;`语句，就像我们在上一个示例中看到的那样。确保所有的代码路径都返回调用上下文（`this`）的引用或另一个相关的 jQuery 集合对象，就像`$.fn.parent()`和`$.fn.find()`一样。或者，当您的所有代码都包裹在另一个 jQuery 方法内部时，例如`$.fn.each()`，通常的做法是简单地返回该调用的结果，如下所示：

```js
$.fn.myLogPlugin = function() { 
    return this.each(function(i, element) { 
        console.log($(element).text()); 
    }); 
};
```

请记住，如果您的代码操作了它被调用的集合对象，而不是返回`this`引用，您可能需要返回插件操作的新集合对象。

### 注意

您应该避免将插件的实现基于返回值以允许进一步的链式操作。而不是这样做，最好是在其第一次调用时初始化插件，然后提供一些重载的方式来调用它，作为返回值的一种方式。

## 使用$.noConflict()操作

改进插件实现的第一步是使其在无法访问`$`标识符的环境中工作。其中一个示例是当网页使用`jQuery.noConflict()`方法时，它会阻止 jQuery 将自身分配给`$`全局标识符（或`window.$`），并且仅将其保留在`jQuery`命名空间（`window.jQuery`）上。

### 注意

`jQuery.noConflict()`方法允许我们防止 jQuery 与其他库和实现发生冲突，这些库和实现也可能使用`$`变量。有关更多信息，请访问 jQuery 文档页面：[`api.jquery.com/jQuery.noConflict/`](http://api.jquery.com/jQuery.noConflict/)

在这种情况下，插件定义会抛出**$ is not defined**错误，甚至更糟的是；它可能会尝试使用开发人员保留用于实现的`$`变量，导致难以调试的错误。

幸运的是，修复这个问题所需的更改很容易实现，并且不会影响插件的功能。我们所要做的就是将插件中所有的`$`标识符的出现都重命名为`jQuery`，如下所示：

```js
jQuery.fn.simplePlugin101 = function(arg1, arg2/*, ...*/) { 
    var $buttons = jQuery('button');
    // ...
};
```

## 使用 IIFE 包装

遵循的下一个最佳实践是使用 IIFE 包装我们的插件的定义和实现。这不仅使我们的插件看起来像**模块模式**，而且通过为其增加几个其他好处，使我们的实现更加健壮。

首先，IIFE 模式允许我们在插件定义的上下文中创建和使用私有变量和函数。这些变量与插件的所有实例共享，类似于其他编程语言中静态变量的工作方式，使我们能够将它们用作插件实例之间的同步点：

```js
(function($) { 
    var callCounter = 0; 

    function utilityLogMethod(message) { 
        if (window.console && console.log) { 
            console.log(message); 
        } 
    } 

    $.fn.simplePlugin101 = function(arg1, arg2/*, ...*/) { 
        callCounter++; 
        utilityLogMethod(callCounter); 
        return this;
    }; 
})(jQuery);
```

否则，我们将不得不使用类似`$.simplePlugin101._callCounter`或`$.simplePlugin101._utilityLogMethod()`这样的东西来模拟隐私，这只是一种命名约定，并不提供任何实际的隐私。

如上例所示，第二个好处是，它允许我们再次使用`$`标识符来访问 jQuery，而不必担心冲突。为了实现这一点，我们将 jQuery 命名空间变量作为调用参数传递给我们的 IIFE，并使用`$`标识符来命名相应的参数。通过这种方式，我们有效地将 jQuery 命名空间别名为`$`，使我们可以在 IIFE 创建的上下文中使用最小的`$`标识符来使我们的代码简洁可读，即使使用了`jQuery.noConflict()`也是如此。

另外，在我们的 IIFE 顶部添加`use strict;`语句有助于消除变量泄漏到全局命名空间的问题。例如，以下代码在调用插件方法时会抛出**ReferenceError: assignment to undeclared variable x**错误，这使我们能够在插件开发阶段捕获这些错误，从而产生更健壮的最终实现：

```js
(function($) { 
    'use strict'; 

    $.fn.leakingPlugin = function() { 
        x = 0;// there is no "var x" declaration, 
        // so an error is thrown when executed
    }; 
})(jQuery); 

$('div').leakingPlugin();
```

### 注意

要了解更多关于 JavaScript 严格执行模式的信息，请访问：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Strict_mode`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Strict_mode)

最后，与所有使用 IIFE 的命名空间别名实践一样，此模式也可以帮助增加在缩小插件源代码时的收益，与直接引用 jQuery 命名空间变量的实现相比。为了最大化此技术的好处，还常常将插件访问的所有全局命名空间变量都别名化，如下所示：

```js
(function ( $, window, document, undefined ) { 
    // Plugin's implementation... 
})( jQuery, window, document );
```

# 创建可重复使用的插件

在分析了 jQuery 插件开发的最重要方面之后，我们现在准备分析一个用于更多功能的实现，而不仅仅是一个简单的演示。为了创建一个真正有用且可重复使用的插件，必须设计得这样，使其操作不受其原始用例的要求限制。

最受欢迎的插件，就像最有用的 jQuery 方法一样，是那些提供了高度配置其功能的插件。创建可配置的插件为其实现增加了一定的灵活性，使我们能够满足由相同操作原则控制的其他多个用例的需求。

正如我们之前所说，一个 jQuery 插件只是附加到`$.fn`对象的函数，因此我们可以将其实现更加抽象和通用，就像我们的模块的简单函数一样。与简单函数一样，区分 jQuery 插件的操作最简单的方法是使用调用参数。一个暴露了许多配置参数的插件有很大的潜力能够满足几种不同用例的要求。

## 接受配置参数

与我们通常接受高达五个参数但仍具有可管理和相对清晰 API 的函数的实现方式形成对比，这种做法在 jQuery 插件中效果不佳。为了暴露清晰的 API 并保持高可用性，无论暴露了哪些不同的配置选项，大多数 jQuery 插件都提供了一个最小的 API，接受高达三个调用参数。这是通过使用具有特定格式的专用设置对象来实现的，作为一种封装多个选项并将它们作为单个参数传递的方法。另一种方法是使用两个参数暴露 API，其中第一个是定义插件操作的常规值，第二个用于包装不太重要的配置选项。

这些做法的一个很好的例子是`$.ajax(settings)`方法，它通过单个设置对象作为参数调用以定义其操作方式，但还暴露了另一个重载的方式，以两个参数调用。两个参数重载通过`$.ajax(url, settings)`调用，其中第一个是 HTTP 请求的目标 URL，第二个是具有其余配置选项的对象。对它们都适用的是，方法本身包含一组明智的默认值，用于替代用户未定义的任何配置参数。此外，第二种重载还将第二个参数定义为可选参数，如果在其调用过程中未提供，则其操作将基于默认设置。

在我们的插件中采用设置对象实践不仅带来所有上述的好处，还允许我们以更具可扩展性的方式扩展其实现，因为添加额外的配置参数对其 API 的其余部分几乎没有影响。作为这一点的例子，我们将在更通用的方式中重新实现我们在本章中早些时候看到的`$.fn.vibrate`插件，以便使用具有默认值的设置对象来进行配置：

```js
(function($) { 

  $.fn.vibrate = function(options) { 
    var opts = $.extend({}, $.fn.vibrate.defaultOptions, options);

    this.each(function(i, element) { 
      var $element = $(element); 
      if ($element.css('position') === 'static') { 
        $element.css({ position: 'relative' }); 
      } 
    }); 

    for (var i = 0, len = opts.loops * 4; i < len; i++) { 
      var animationProperties = {}; 
      var movement = (i % 2) ? '+=': '-='; 

      movement += (i === 0 || i === len - 1) ? 
        opts.amplitude / 2: 
        opts.amplitude; 

      var t = (i === 0 || i === len - 1) ? 
        opts.period / 4: 
        opts.period / 2; 

      animationProperties[opts.direction] = movement; 
      this.animate(animationProperties, t); 
    }

    return this; 
  }; 

  $.fn.vibrate.defaultOptions = { 
    loops: 2, 
    amplitude: 8, 
    period: 100, 
    direction: 'left' 
  }; 
})(jQuery);
```

与原始固定实现相比，这个实现接受一个作为调用参数的单个对象，其中包装了四个可以用于使插件操作多样化的不同选项。通过暴露四个定制点，选项对象允许我们通过暴露四个定制点来使插件的操作多样化：

+   抖动效果应该运行的循环数

+   动画的振幅，作为控制元素应该离其原始位置移动多少的手段

+   每个循环的周期，作为控制运动速度的手段

+   动画的方向，当使用`left`时是水平的，或者当使用`top`时是垂直的

通过遵循广泛接受的最佳实践，我们将所有配置选项的默认值定义为一个单独的对象。这种模式不仅允许我们将所有相关值收集到单个对象下，而且还使我们能够使用`$.extend()`方法有效地将所有已定义选项与未定义选项的默认值组合在一起。因此，我们可以避免明确检查每个单独属性的存在，从而减少了代码的复杂性和大小。

简而言之，`$.extend()`方法在将后续对象的属性合并到第一个对象中后返回第一个参数传递的对象。因此，返回的对象将包含除了在调用参数中定义的选项对象中定义的默认值之外的所有默认值。

### 注意

有关`$.extend()`助手方法的更多信息，您可以访问文档页面：[`api.jquery.com/jQuery.extend/`](http://api.jquery.com/jQuery.extend/)

此外，我们没有使用简单的变量，而是将默认选项对象公开为插件函数的属性，使用户可以根据自己的需要进行更改。例如，考虑需要特定应用程序的平滑动画的情况。通过设置`$.fn.vibrate.defaultOptions.period = 250`，开发人员将完全消除在每次调用插件时指定`period`选项的需要，这将导致具有更少重复代码的实现。

### 注意

jQuery 库本身采用了此实践来定义`$.ajax()`方法的默认配置参数。由于此方法的复杂性增加，jQuery 为我们提供了`jQuery.ajaxSetup()`方法，作为设置每个 AJAX 请求的默认参数的一种方式。

最后，为了创建原始实现的通用变体并利用上述配置选项，我们用使用了`for`循环来替换了原始实现的`$.fn.animate()`方法的四个固定调用。在`for`循环内部，我们构造每次调用`$.fn.animate()`方法的参数，并在每次循环的后续执行中简要地交替动画移动的方向，并确保第一个和最后一个动作的时间持续时间和所有其他步骤的位移的一半。

最终的实现可以配置为产生不同的动画，根据每个特定用例的需求而变化，从适用于通知用户无效操作的短水平动画，到看起来像漂浮效果的垂直长动画。插件可以以任何组合的前述选项调用，对于缺失选项使用默认值，甚至在没有调用参数的情况下运行，如下所示：

```js
// do the default intense animation on a button
// that appears disabled, to designate an invalid action 
$('button.disabled').on('click', function() { 
  $(this).vibrate(); 
}); 

// do a smother shake animation to catch the user's 
// attention on an important part of the page 
$('.save-button').vibrate({loops: 3, period: 250}); 

// start a long running levitation effect on the header of the page 
$('h1').vibrate({direction: 'top', loops: 1000, period: 5000});
```

## 编写具有状态的 jQuery 插件

到目前为止，我们看过的插件实现是无状态的，因为在完成执行后，它们会恢复对 DOM 状态的操作，并且不会在浏览器内存中保留分配的对象。因此，对无状态插件的后续调用始终产生相同的结果。

你可能已经猜到，这种插件的应用范围有限，因为它们无法用于创建与网页用户的一系列复杂交互。为了协调复杂的用户交互，插件需要保持内部状态，以记录到目前为止采取的操作，并适当地改变其操作模式并处理后续交互。比较具有状态和无状态插件的特性可以定义为将普通（静态）函数与是对象的一部分并可以对其状态进行操作的方法进行比较。

另一个流行的插件类别是必须具有内部状态的类别，这是操纵 DOM 树的插件系列。这些插件通常创建复杂的元素结构，如富文本编辑器、日期选择器和日历，通常是通过在用户定义的空白 `<div>` 元素上构建。

## 实现一个具有状态的 jQuery 插件

作为实现这类插件的模式的示例，我们将编写一个通用的 **元素变异观察器** 插件。该插件将为我们提供一种方便的方法，用于添加对来自该插件所调用的任何元素的 DOM 树更改的事件侦听器。为了实现这一点，以下实现使用了 **MutationObserver** API，在撰写本文时，该 API 已由所有现代浏览器实现，并且可供超过 86% 的网络用户使用。

### 注意

有关 Mutation Observer 的更多信息，请访问：[`developer.mozilla.org/en-US/docs/Web/API/MutationObserver`](https://developer.mozilla.org/en-US/docs/Web/API/MutationObserver)

现在让我们继续实施并分析所使用的做法：

```js
(function($) { 
  $.fn.mutationObserver = function(action) { 
    return this.each(function(i, element) { 
      var $element = $(element); 
      var instance = $element.data('plugin_mutationObserver'); 

      if (!instance) { 
        var observer = new MutationObserver(function(mutations) { 
          mutations.forEach(function(mutation) { 
            instance.callbacks.forEach(function(callbackFn) { 
              callbackFn(mutation); 
            }); 
          }); 
        }); 

        observer.observe(element, {
          attributes: true,
          childList: true,
          characterData: true
        }); 

        instance = { 
          observer: observer, 
          callbacks: [] 
        }; 
        $element.data('plugin_mutationObserver', instance); 
      } 

      if (typeof action === 'function') { 
        instance.callbacks.push(action); 
      } 
    }); 

  }; 
})(jQuery);
```

首先，我们在 IIFE 内部定义我们的插件，正如本章前面建议的那样。在插件在 `$.fn` 对象上的声明之后，我们使用 `$.fn.each()` 方法作为直接方法，以确保我们的插件的功能应用于调用它的 jQuery Collection Object 的每个项目。

有状态插件实现的两个主要问题之一是缺乏保留每个插件实例内部状态的机制，以及避免在同一页面元素上多次初始化的方法。为了解决这两个问题，我们需要使用类似哈希表的东西，其中键是元素本身，值是插件实例状态的对象。

幸运的是，这或多或少是`$.fn.data()`方法的工作原理，通过使用特定的字符串键将 DOM 元素和 JavaScript 对象值关联起来。通过使用`$.fn.data()`方法和插件的名称作为关联键，我们能够非常容易地存储和检索我们插件的状态对象。

### 提示

对于这种用例，使用`$.fn.data()`方法被认为是一种最佳实践，并且被大多数有状态插件实现和样板文件使用，因为它是 jQuery 的一个强大的部分，可以使我们减少插件实现的大小。

如果找不到现有的状态对象，则可以假定插件尚未在该特定元素上初始化，并立即开始初始化。该插件的状态对象将包含负责跟踪观察的 DOM 元素上发生的更改的活动 MutationObserver 实例，并且一个订阅它以获得关于更改通知的所有回调的数组。

创建新的 MutationObserver 实例后，我们将其配置为查找三种特定类型的 DOM 更改，并指示它在发生此类 DOM 更改时调用插件状态对象的所有回调。最后，我们创建状态对象本身来保存观察者和关联的回调，并使用`$.fn.data()`方法作为设置器，并将其与页面元素关联。

在确保插件在提供的元素上被实例化和初始化之后，我们检查插件是否以函数作为参数调用，如果是，则将其添加到插件的回调列表中。

### 提示

请记住，对于每个元素使用单个 MutationObserver 实例，并通过迭代回调数组通知 DOM 更改，可以大大减少实现的内存需求，就像我们使用单个委托观察器时一样。

使用我们新实现的插件来观察特定 DOM 元素的更改的示例如下：

```js
$('.container').mutationObserver(function(mutation) { 
  console.log('Something changed on the DOM tree!'); 
});
```

## 销毁插件实例

有状态插件必须考虑的额外因素是为开发人员提供一种方式来撤销它对页面状态引入的更改。实现这一点的最常见和简单的 API 是使用`destroy`字面量作为其第一个参数调用插件。让我们继续进行所需的实现更改：

```js
(function($) { 
  $.fn.mutationObserver = function(action) { 
    return this.each(function(i, element) { 
      var $element = $(element); 
      var instance = $element.data('plugin_mutationObserver'); 

      if (action === 'destroy' && instance) { 
        instance.observer.disconnect(); 
        instance.observer = null;
        $element.removeData('plugin_mutationObserver'); 
        return; 
      } 

      if (!instance) { 
        /* ... */ 
      } 
    }); 

  }; 
})(jQuery);
```

为了使我们的实现适应上述需求，我们所要做的就是在检索插件状态对象后检查插件是否以`destroy`字符串值作为其第一个参数调用。如果我们发现插件已经被实例化在指定的元素上，并且已经使用了`destroy`字符串值，我们就可以继续停止 Mutation Observer 本身，并清除`$.fn.data()`创建的关联，方法是使用`$.fn.removeData()`方法。最后，在`if`语句的结尾处，我们添加了一个`return`语句，因为在完成销毁插件实例后，我们不再需要执行任何其他代码。使用此实现销毁插件实例的示例如下所示：

```js
$('.container').mutationObserver('destroy');
```

## 实现获取器和设置器方法

通过使用我们先前展示的与插件的`destroy`方法的实现相同的技术，我们可以提供几种其他重载的方式来调用我们的插件，这些方式就像普通的方法一样工作。这种模式不仅被普通的 jQuery 插件所使用，而且还被更复杂的插件架构所采用，就像 jQuery-UI 一样。

另一方面，我们可能会得到一个插件实现，结果是大量调用重载，这会使其难以使用和文档化。解决这个问题的一种方法是将 API 的获取器和设置器方法合并成多用途方法。这不仅减少了插件的 API 表面，使开发人员需要记住的方法名称更少，而且还增加了生产力，因为在许多 jQuery 方法中都使用了相同的模式，比如`$.fn.html()`、`$.fn.css()`、`$.fn.prop()`、`$.fn.val()`和`$.fn.data()`。

作为对此的演示，让我们看看如何为我们的 MutationObserver 插件添加一个新方法，该方法既作为获取器又作为注册回调的设置器：

```js
(function($) { 
  $.fn.mutationObserver = function(action, callbackFn) { 
    var result = this; 

    this.each(function(i, element) { 
      var $element = $(element); 
      var instance = $element.data('plugin_mutationObserver'); 
      /* ... */ 

      if (typeof action === 'function') { 
        instance.callbacks.push(action); 
      } else if (action === 'callbacks') { 
        if (callbackFn && callbackFn.length >= 0) { 
          // used as a setter 
          instance.callbacks = callbackFn; 
        } else { 
          // used as a getter for the first element 
          result = instance.callbacks; 
          return false;// break the $.fn.each() iteration 
        } 
      }
    }); 

    return result; 
  }; 
})(jQuery); 
```

正如上面的代码所示，我们已经创建了一个重载的调用方法，该方法使用`callbacks`字符串值作为插件调用的第一个参数。这个获取器和设置器方法允许我们检索或覆盖注册在 MutationObserver 上的所有回调，并且与使用函数参数和`destroy`方法的预先存在的调用插件方法一起使用。

getter 和 setter 的实现基于这样的假设：当尝试将 `callbacks` 方法用作 getter 时，你不需要传递任何额外的参数；当尝试将其用作 setter 时，你将传递一个额外的数组作为调用参数。为了支持 getter 变体，该变体防止进一步的链式操作，仅对复合集合的第一个元素进行操作，我们不得不声明并使用 `result` 变量，该变量初始化为 `this` 标识符的值。如果使用 `callbacks` getter，则将集合的第一个元素的 `callbacks` 分配给 `result` 变量，并通过返回 `false` 以结束插件方法的执行来退出 `$.fn.each()` 迭代。

这是我们新实现的 getter 和 setter 方法的一个示例用例：

```js
// retrieve the callbacks 
var oldCallbacks = $('.container').mutationObserver('callbacks'); 
// clear them 
$('.container').mutationObserver('callbacks', []); 
// add a new one 
$('.container').mutationObserver(function() { 
  console.log('Printed only once'); 
  // restore the old callbacks
  $('.container').mutationObserver('callbacks', oldCallbacks); 
});
```

### 提示

请记住，防止进一步链式调用的调用重载应该有很好的文档记录，因为这种技术与每个人都期望工作的链式原则相冲突。

## 在我们的仪表板应用程序中使用我们的插件

完成我们的 `mutationObserver` 插件后，现在让我们看看如何将其用于我们在前几章中在仪表板实现中使用的 `counter` 子模块的实现：

```js
(function() { 
    'use strict'; 
    dashboard.counter = dashboard.counter || {}; 

    var $counter; 

    dashboard.counter.init = function() { 
        $counter = $('#dashboardItemCounter'); 
        var $boxContainer = dashboard.$container
          .find('.boxContainer'); 

        $boxContainer.mutationObserver(function(mutation) { 
            dashboard.counter.setValue($boxContainer.children().length); 
        }); 
    }; 

    dashboard.counter.setValue = function (value) { 
        $counter.text(value); 
    }; 
})(); 
```

正如你在上面的实现中所看到的，我们的插件很好地抽象并替换了旧的实现，提供了一个通用、灵活和可重用的 API。现在，该实现不再监听页面上不同按钮的点击事件，而是使用 `mutationObserver` 插件并观察 `boxContainer` 元素以查看子元素的添加或移除。此外，此实现更改不会影响 `counter` 模块的功能，因为所有更改都封装在模块中。

# 使用 jQuery 插件模板

jQuery Boilerplate 项目位于 [`github.com/jquery-boilerplate/jquery-patterns`](https://github.com/jquery-boilerplate/jquery-patterns)，提供了几个模板，可用作实现稳健且可扩展插件的起点。这些模板融合了许多最佳实践和设计模式，例如本章前面分析的那些。每个模板都包含了一些良好结合在一起的最佳实践，旨在提供更适合各种用例的良好起点。

或许最广泛使用的模板是 Adam Sontag 和 Addy Osmani 的`jquery.basic.plugin-boilerplate`，即使它被描述为一个适用于初学者及以上的通用模板，但仍成功地涵盖了 jQuery 插件开发的大多数方面。 使这个模板独特的是它遵循的面向对象的方法，它以这样一种方式呈现，帮助您编写更好结构化的代码，而不会增加引入自定义实现的难度。 让我们继续分析其源代码：

```js
/*! 
 * jQuery lightweight plugin boilerplate 
 * Original author: @ajpiano 
 * Further changes, comments: @addyosmani 
 * Licensed under the MIT license 
 */ 
;(function ( $, window, document, undefined ) { 
  var pluginName = "defaultPluginName", 
    defaults = { 
      propertyName: "value" 
    }; 
  function Plugin( element, options ) { 
    this.element = element; 
    this.options = $.extend( {}, defaults, options) ; 
    this._defaults = defaults; 
    this._name = pluginName; 
    this.init(); 
  } 
  Plugin.prototype = { 
    init: function() { /* Place initialization logic here  */ },
    yourOtherFunction: function(options) { /* some logic */ }
  };
  // A really lightweight plugin wrapper around the constructor, 
  // preventing against multiple instantiations 
  $.fn[pluginName] = function ( options ) { 
    return this.each(function () { 
      if (!$.data(this, "plugin_" + pluginName)) { 
        $.data(this, "plugin_" + pluginName, 
        new Plugin( this, options )); 
      } 
    }); 
  }; 

})( jQuery, window, document ); 
```

IIFE 之前的分号是为了在不幸的脚本连接（以及可能的最小化）中避免错误，可能缺少结束分号的文件。 正如下面所示，样板使用`pluginName`变量作为 DRY 方式命名我们的插件并为任何其他情况使用其名称。 作为附加好处，如果我们需要重命名插件，所有我们需要做的就是更改此变量的值，并相应地重命名我们插件的`.js`文件。

遵循我们之前看到的最佳实践，使用一个变量来保存插件的默认选项，并且正如我们稍后看到的，它使用`$.extend()`方法将其与用户提供的选项合并。 请记住，如果我们想公开默认选项，所有我们需要做的就是将其定义为插件命名空间的一部分：`$.fn[pluginName].defaultOptions = defaults;`

实际的插件定义可以在此样板代码的末尾找到。 遵循已经讨论过的最佳实践，它使用`$.fn.each()`迭代集合的项并返回其结果，这相当于返回`this`。 然后，它通过使用`$.data()`方法和带有前缀的插件名称作为关联键，确保每个集合项都存在一个插件状态实例。

`Plugin`构造函数用于创建插件状态对象，该对象在存储 DOM 元素和最终插件选项作为对象属性后，调用其原型的`init()`方法。 `init()`方法是定义初始化代码的建议位置，例如，它可以像本章前面所做的那样实例化新的 MutationObserver。

## 向您的插件添加方法

默认情况下，作为原型的一部分定义的每个方法仅供内部使用。 另一方面，我们可以轻松地扩展上述实现，以使方法对所有用户可用，如下所示：

```js
$.fn[pluginName] = function ( options, extraParam ) { 
  return this.each(function () { 
    var instance = $.data(this, "plugin_" + pluginName); 
    if (!instance) { 
      instance = new Plugin( this, options ); 
      $.data(this, "plugin_" + pluginName, instance); 
    } else if (options === 'yourOtherFunction') { 
      instance.yourOtherFunction(this, extraParam); 
    } 
  }); 
};
```

在使用此样板时要遵循的一个准则是通过向`Plugin`的原型添加额外方法来扩展您的插件。此外，尽量保持对插件定义的任何修改尽可能小，理想情况下是单行方法调用。

为了使实现更具可扩展性，关于插件方法的调用方式以及如果我们想为插件添加一个抽象方法，该方法是为插件的内部或私有使用而设计的，我们可以引入以下更改：

```js
$.fn[pluginName] = function ( options ) {
  var restArgs = Array.prototype.slice.call(arguments, 1);
  return this.each(function () {
    var instance = $.data(this, "plugin_" + pluginName);
    if (!instance) {
      instance = new Plugin( this, options );
      $.data(this, "plugin_" + pluginName, instance);
    } else if (typeof options === 'string' && // method name
      options[0] !== '_' && // protect private methods
      typeof instance[options] === 'function') {
      instance[options].apply(instance, restArgs);
    }
  });
};
```

在上述实现中，我们使用第一个参数来识别需要调用的方法，然后用剩余的参数来调用它。我们还添加了一个检查，以防止调用以下划线开头的方法，根据通常的约定，这些方法是用于内部或私有使用的。因此，为了向插件的公共 API 添加额外的方法，我们只需在之前看到的`Plugin.prototype`中声明它。

### 注意

当您已经在应用程序中使用 jQuery-UI 时，实现插件的另一种绝佳方式是使用`$.widget()`方法，也称为 jQuery-UI Widget 工厂。其实现抽象了我们在本章中看到的几部分样板代码，并帮助创建复杂而健壮的插件。有关更多信息，您可以阅读文档：[`api.jqueryui.com/jQuery.widget/`](http://api.jqueryui.com/jQuery.widget/)

# 选择一个名字

最后，在学习了我们需要创建 jQuery 插件的最佳实践之后，让我们谈谈命名约定和在哪里发布您的新而闪亮的插件。

正如您可能已经看到的那样，大多数 jQuery 插件使用以下命名约定：jQuery-myPluginName 作为其项目站点和存储库，并将其实现存储在名为`jquery.mypluginname.js`的文件中。在为插件选择一些可能的名称之后，请花一点时间在网络上搜索以验证是否有其他人使用相同的项目名称。jQuery 文档建议在 NPM 上搜索插件，并使用`jquery-plugin`关键字来细化您的结果。这显然是发布您的插件的最佳方式，以便其他人可以轻松找到它。

### 注意

有关 NPM 的更多信息，请访问：[`www.npmjs.com/`](https://www.npmjs.com/)

搜索和托管 JavaScript 库的另一个热门地方是 GitHub。您可以在[`github.com/search?l=JavaScript`](https://github.com/search?l=JavaScript)找到其存储库搜索页面，其中它将搜索结果过滤为仅包含 JavaScript 项目，并搜索现有插件和已使用的项目名称。由于在我们的情况下，我们专注于 jQuery 插件，因此通过搜索遵循前述命名约定的项目名称，jQuery-myPluginName，您将获得更好的结果。

### 注意

直到最近，开发人员可以在官方的 jQuery 插件注册表 ([`plugins.jquery.com/`](http://plugins.jquery.com/))中搜索现有的插件并注册新的插件。不幸的是，它已经停止服务，现在只允许搜索旧的插件，不再接受新的提交。

# 总结

在本章中，我们学习了如何通过实现和使用插件来扩展 jQuery。我们首先看到了一个 jQuery 插件可以实现的最简单方式的示例，并分析了使一个优秀的插件的特点，以及符合 jQuery 库原则的插件。

我们随后介绍了开发者社区中最常见的用于创建 jQuery 插件的开发模式。我们分析了每种模式解决的实现问题以及更适合它们的使用案例。

完成本章后，我们现在能够将应用程序的部分抽象为可重用和可扩展的 jQuery 插件，这些插件使用最适合每个使用案例的开发模式进行结构化。

在下一章中，我们将介绍几种优化技术，可用于改善我们的 jQuery 应用程序的性能，特别是当它们变得庞大和复杂时。我们将讨论简单的实践，例如使用 CDN 加载第三方库，并继续讨论更高级的主题，例如延迟加载实现的模块。


# 第十一章：优化模式

本章介绍了几种优化技术，可用于改善 jQuery 应用程序的性能，特别是当它们变得庞大和复杂时。

我们将从捆绑和最小化我们的 JavaScript 文件等简单实践开始，并讨论使用**CDN**加载第三方库的好处。然后，我们将继续分析一些简单的编写高效 JavaScript 代码的模式，并学习如何编写高效的 CSS 选择器，以提高页面的渲染速度和使用 jQuery 进行 DOM 遍历。

然后，我们将研究特定于 jQuery 的实践，如缓存 jQuery 复合集合对象，如何最小化 DOM 操作，并将**委托观察者模式**作为**享元模式**的一个好例子。最后，我们将介绍**惰性加载**的高级技术，并演示如何根据用户操作逐步加载实施的不同模块。

到本章结束时，我们将能够在实施中应用最常见的优化模式，并将本章用作将应用程序移至生产环境之前的最佳实践和性能提示的检查表。

在本章中，我们将：

+   学习捆绑和最小化我们的 JavaScript 文件的好处

+   学习如何通过 CDN 服务器加载第三方库

+   学习一些简单的 JavaScript 性能提示

+   学习如何优化我们的 jQuery 代码

+   介绍享元模式并展示一些例子

+   学习在用户操作时如何按需惰性加载我们应用的部分

# 将脚本放置在页面末尾

提高页面初始渲染速度的第一个提示是收集所有所需的 JavaScript 文件，并将它们的`<script>`标签置于页面末尾，最好就在关闭`</body>`标签之前。这个改变会对页面的初始渲染时间产生很大的影响，特别是对于使用低速连接的用户（如移动用户）。如果您已经为所有与 DOM 相关的初始化目的使用了`$(document).ready()`方法，将`<script>`标签移动到其他位置不会对您的实施功能产生任何影响。

其主要原因是，即使浏览器并行下载页面的 HTML 和其他资源（CSS、图像等），当遇到`<script>`标签时，浏览器会暂停一切，直到它被下载和执行。为了解决规范的这一限制，HTML5 引入了`defer`和`async`等属性作为`<script>`标签规范的一部分，但不幸的是，直到最近才开始被一些浏览器采用。因此，即使在旧版浏览器上仍广泛使用这种做法来获得良好的页面加载速度。

### 注：

有关`<script>`标签的更多信息，请访问：[`developer.mozilla.org/en-US/docs/Web/HTML/Element/script`](https://developer.mozilla.org/en-US/docs/Web/HTML/Element/script)

# 捆绑和缩小资源

要使页面加载速度更快，首先要寻找减少 HTTP 请求的数量和总大小的方法。好处在于浏览器下载内容时可以更大块地下载，而不是花时间等待许多小的往返请求完成。这对于低速连接的用户（如移动用户）尤其有益。

资源串联是一个简单的概念，无需任何介绍。这可以手动完成，但最好用捆绑脚本自动化此任务，或者为项目引入一个构建步骤。根据您的开发环境，有不同的捆绑解决方案可供选择。如果您在开发栈中使用**grunt**或**gulp**，您可以使用像`grunt-contrib-concat`（[`github.com/gruntjs/grunt-contrib-concat`](https://github.com/gruntjs/grunt-contrib-concat)）和`gulp-concat`（[`github.com/contra/gulp-concat`](https://github.com/contra/gulp-concat)）这样的解决方案。

缩小 JavaScript 文件是一个更复杂的过程，包括一系列应用于目标源代码的代码转换，从简单的空格删除到更复杂的任务如变量重命名。流行的缩小 JavaScript 的解决方案包括：

+   YUI 压缩器可在[`yui.github.io/yuicompressor/`](http://yui.github.io/yuicompressor/)找到。

+   谷歌的闭包编译器可在[`developers.google.com/closure/compiler/`](https://developers.google.com/closure/compiler/)找到。

+   UglifyJS 可在[`github.com/mishoo/UglifyJS2`](https://github.com/mishoo/UglifyJS2)找到。

再次强调，有各种解决方案可以很好地将上述库与您喜欢的开发环境集成，使缩小成为一个简单的任务。例如，grunt 和 gulp 的集成示例包括`grunt-contrib-uglify`（[`github.com/gruntjs/grunt-contrib-uglify`](https://github.com/gruntjs/grunt-contrib-uglify)）和`gulp-uglify`（[`github.com/terinjokes/gulp-uglify`](https://github.com/terinjokes/gulp-uglify)）。

作为最后的建议，要记住，你的代码应该尽可能地易读和逻辑结构清晰。将 JavaScript 和 CSS 文件进行捆绑和缩小，最有效的方法是作为开发和部署过程的构建步骤来完成。

## 使用 IIFE 参数

除了有助于避免污染全局命名空间之外，使用 IIFE 来包装您的实现也对缩小后的 JavaScript 文件大小有益。让我们看看下面的代码，其中`jQuery`、`window`和`document`变量作为调用参数传递到模块的 IIFE 中。

```js
(function ( $, window, document, undefined ) { 
    if (window.myModule === undefined) { 
        window.myModule = {}; 
    } 

    myModule.init = function() { /*...*/ };

    $(document).ready(myModule.init); 

})( jQuery, window, document ); 
```

我们在上一章中看到了类似的模式，作为创建 jQuery 插件的建议模板的一部分。尽管变量别名不影响实现的功能，但它允许代码最小化器在更多地方应用变量重命名，导致以下代码：

```js
(function(b, a, c, d) { 
    a.myModule === d && (a.myModule = {}); 
    myModule.init = function() { /*...*/ };
    b(c).ready(myModule.init); 
})(jQuery, window, document); 
```

正如您在上面的代码中可以看到的，所有 IIFE 的调用参数都被缩小器重命名为单个字母标识符，这尤其增加了最小化的收益，特别是如果原始标识符在多个地方使用。

### 提示

作为附加好处，别名还可以保护我们的模块，防止原始变量意外赋予不同的值。例如，当 IIFE 参数未被使用时，来自不同模块的赋值，如`$ = {}`或`undefined = 7`，会破坏所有实现。

# 使用 CDN

不要从您的网站服务器提供所有的第三方库的 JavaScript 和 CSS 文件，您应该考虑使用**内容交付网络**（**CDN**）。使用 CDN 来提供您的网站所使用的库的静态文件可以使它加载更快，因为：

+   CDN 具有高速连接和多个缓存级别。

+   CDN 有许多地理分布的服务器，可以更快地传送所请求的文件，因为它们离最终用户更近。

+   CDN 有助于并行化资源请求，因为大多数浏览器只能同时从任何特定域下载最多四个资源。

而且，如果用户从使用相同 CDN 的另一个网站上缓存了静态资源，他或她将不必再次下载它们，减少了您的网站需要加载的时间。

下面是一个使用 JavaScript 库的最广泛使用的 CDN 列表，您可以在您的实现中使用它们：

+   [`code.jquery.com/`](https://code.jquery.com/)

+   [`developers.google.com/speed/libraries/`](https://developers.google.com/speed/libraries/)

+   [`cdnjs.com/`](https://cdnjs.com/)

+   [`www.jsdelivr.com/`](http://www.jsdelivr.com/)

## 使用 JSDelivr API

CDN 世界的新来者是 JSDelivr，由于其独特的功能而备受欢迎。除了简单地提供现有的静态文件外，JSDelivr 还提供一个 API（[`github.com/jsdelivr/api`](https://github.com/jsdelivr/api)），允许我们创建和使用带有我们需要加载的资源的自定义捆绑包，帮助我们最小化网站所需的 HTTP 请求。此外，其 API 允许我们以不同级别的特定性（主要、次要或错误修复版本）定位库，甚至允许我们只加载库的特定部分。

例如，看一下以下 URL，它允许我们使用单个请求加载 jQuery v1.11.x 的最新 bug 修复版本，以及 jQuery-UI v1.10.x 和 Bootstrap v3.3.x 的一些部分：[`cdn.jsdelivr.net/g/jquery@1.11,jquery.ui@1.10(jquery.ui.core.min.js+jquery.ui.widget.min.js+jquery.ui.mouse.min.js+jquery.ui.sortable.min.js),bootstrap@3.3`](http://cdn.jsdelivr.net/g/jquery@1.11,jquery.ui@1.10(jquery.ui.core.min.js+jquery.ui.widget.min.js+jquery.ui.mouse.min.js+jquery.ui.sortable.min.js),bootstrap@3.3)

# 优化常见的 JavaScript 代码

在本节中，我们将分析一些不特定于 jQuery 的性能提示，并且可以应用于大多数 JavaScript 实现。

## 编写更好的 for 循环

当使用`for`循环遍历数组或类似数组的集合时，提高迭代性能的一个简单方法是避免在每个循环中访问`length`属性。可以通过将迭代`length`存储到一个单独的变量中，在循环之前声明，甚至与循环一起声明，如下所示：

```js
for (var i = 0, len = myArray.length; i < len; i++) { 
    var item = myArray[i]; 
    /*...*/ 
} 
```

此外，如果我们需要迭代不包含**假值**的数组项，我们可以使用一个更好的模式，通常用于迭代包含对象的数组：

```js
var objects = [{ }, { }, { }]; 
for (var i = 0, item; item = objects[i]; i++) { 
    console.log(item); 
}
```

在这种情况下，我们利用了数组的超出边界位置返回`undefined`的事实，这是假值并且停止迭代。可以在迭代**节点列表**或 jQuery 复合集合对象时使用此技巧的另一个示例情况如下：

```js
var anchors = $('a'); // or document.getElementsByTagName('a');
for (var i = 0, anchor; anchor = anchors[i]; i++) { 
    console.log(anchor.href); 
} 
```

### 注意

有关 JavaScript 中**真值**和**假值**的更多信息，请访问：[`developer.mozilla.org/en-US/docs/Glossary/Truthy`](https://developer.mozilla.org/en-US/docs/Glossary/Truthy) 和 [`developer.mozilla.org/en-US/docs/Glossary/Falsy`](https://developer.mozilla.org/en-US/docs/Glossary/Falsy)

# 编写高性能的 CSS 选择器

尽管**Sizzle**（jQuery 的选择引擎）隐藏了基于复杂 CSS 选择器的 DOM 遍历的复杂性，我们应该了解我们的选择器是如何执行的。了解 CSS 选择器如何匹配 DOM 的元素可以帮助我们编写更有效的选择器，在与 jQuery 一起使用时性能更佳。

有效 CSS 选择器的关键特征是特异性。根据这一点，ID 和类选择器总是比`div`和`*`这样结果较多的选择器更高效。在编写复杂的 CSS 选择器时，要记住它们是从右到左进行评估的，并且在递归测试每个父元素直到 DOM 根元素后，选择器将被拒绝。

因此，在执行选择器期间，尽量使最右边的选择器尽可能具体，以尽快减少匹配的元素数量。

```js
// initially matches all the anchors of the page 
// and then removes those that are not children of the container 
$('.container a'); 

// performs better, since it matches fewer elements 
// in the first step of the selector's evaluation 
$('.container .mySpecialLinks');
```

另一个性能提示是在适用的地方使用子选择器（"parent > child"），以消除对 DOM 树层次结构的递归。一个极好的应用案例是目标元素可以在共同祖先元素的特定后代级别找到的情况：

```js
// initially matches all the div's of the page, which is bad 
$('.container div') ;

// a lot faster than the previous one,
// since it avoids the recursive class checks
// until reaching the root of the DOM tree 
$('.container > div');

// best of all, but can't be used always 
$('.container > .specialDivs');
```

### 提示

相同的技巧也适用于用于页面样式的 CSS 选择器。尽管浏览器一直在尝试优化任何给定的 CSS 选择器，上述技巧可以极大地减少渲染网页所需的时间。

### 注意

有关 jQuery CSS 选择器性能的更多信息，您可以访问：[`learn.jquery.com/performance/optimize-selectors/`](http://learn.jquery.com/performance/optimize-selectors/)

# 编写高效的 jQuery 代码

现在让我们继续分析最重要的 jQuery 特定性能提示。有关 jQuery 最新性能提示的更多信息，请关注 jQuery 学习中心的相关页面：[`learn.jquery.com/performance`](http://learn.jquery.com/performance)

## 减少 DOM 遍历

由于 jQuery 使 DOM 遍历变得如此简单，许多 web 开发人员在每处都过度使用 `$()` 函数，甚至在后续的代码行中使用，通过执行不必要的代码来使其实现变慢。操作复杂性如此经常被忽视的主要原因之一是 jQuery 使用优雅和极简的语法。尽管 JavaScript 浏览器引擎在过去几年变得多次更快，性能可与许多编译语言媲美，但是 DOM API 仍然是它们最慢的组件之一，因此开发人员必须尽量减少与它的交互。

### 缓存 jQuery 对象

将 `$()` 函数的结果存储到本地变量中，并随后在检索到的元素上操作是消除不必要的相同 DOM 遍历执行的最简单方法。

```js
var $element = $('.boxHeader');
if ($element.css('position') === 'static') {
  $element.css({ position: 'relative' });
}
$element.height('40px');
$element.wrapInner('<b>');
```

在之前的章节中，我们甚至建议将重要页面元素的组合集合对象作为模块的属性进行存储，并在应用程序的各个地方重复使用：

```js
    dashboard.$container = null; 
    dashboard.init = function() { 
        dashboard.$container = $('.dashboardContainer'); 
    };
```

### 提示

当元素不会从页面中移除时，将检索到的元素缓存在模块上是一种非常好的做法。请记住，当处理生命周期较短的元素时，为了避免内存泄漏，您必须确保在从页面中删除它们时清除所有引用，或者在需要时重新检索新的引用，并仅在函数内部缓存它。

### 作用域元素遍历

而不是为遍历编写复杂的 CSS 选择器：

```js
$('.dashboardContainer .dashboardCategories');
```

你可以通过使用已经检索到的祖先元素来限定 DOM 遍历，以更高效的方式获得相同的结果。这样做，不仅使用了更简单的 CSS 选择器来匹配页面元素，而且减少了需要检查的元素数量。此外，生成的实现代码重复性较少（更干净），使用的 CSS 选择器简单，因此更易读。

```js
var $container = $('.dashboardContainer');
$container.find('.dashboardCategories');
```

另外，这种做法与整个模块范围的缓存元素一起使用效果更佳，就像我们在前几章中使用的那样：

```js
$boxContainer = dashboard.$container.find('.boxContainer');
```

### 链式调用 jQuery 方法

所有 jQuery API 的特点之一是它们是**流式**接口实现，使我们能够在单个组合集合对象上链式调用多个方法。

```js
$('.boxContent').html('') 
    .append('<a href="#">') 
    .height('40px') 
    .wrapInner('<b>');
```

正如我们在前几章中讨论的，链式调用可以减少所用变量的数量，并且以更少的代码重复实现更易读的实现。

## 不要过度使用

请记住，jQuery 还提供了 `$.fn.end()` 方法（[`api.jquery.com/end/`](http://api.jquery.com/end/)）作为从链式遍历中返回的一种方式。

```js
$('.box') 
    .filter(':even') 
    .find('.boxHeader') 
    .css('background-color', '#0F0') 
    .end() 
    .end() // undo the filter and find traversals
    .filter(':odd') // applied on  the initial .box results
    .find('.boxHeader') 
    .css('background-color', '#F00');
```

尽管这在许多情况下都是一个方便的方法，但你应该避免过度使用它，因为它可能会损害代码的可读性和性能。在许多情况下，使用缓存的元素集合而不是 `$.fn.end()` 可以获得更快、更可读的实现。

## 改进 DOM 操作

正如我们之前所说的，广泛使用 DOM API 是使应用程序变慢的最常见因素之一，特别是在用于操作 DOM 树状态时。在本节中，我们将展示一些改进操作 DOM 树性能的技巧。

### 创建 DOM 元素

创建 DOM 元素最有效的方式是构造一个 HTML 字符串并使用 `$.fn.html()` 方法将其附加到 DOM 树中。此外，由于在某些用例中这太过限制，你也可以使用 `$.fn.append()` 和 `$.fn.prepend()` 方法，虽然稍微慢一些，但可能更适合你的实现。理想情况下，如果需要创建多个元素，你应该尝试通过创建一个定义所有元素的 HTML 字符串，然后将其插入到 DOM 树中，如下所示：

```js
var finalHtml = ''; 
for (var i = 0, len = questions.length; i < len; i++) { 
  var question = questions[i]; 
  finalHtml += '<div><label><span>' + question.title + ':</span>' + 
    '<input type="checkbox" name="' + question.name + '" />' + 
  '</label></div>'; 
} 
$('form').html(finalHtml);
```

另一种实现相同结果的方法是使用数组来存储每个中间元素的 HTML，然后在插入到 DOM 树之前将它们连接起来：

```js
var parts = []; 
for (var i = 0, len = questions.length; i < len; i++) { 
  var question = questions[i]; 
  parts.push('<div><label><span>' + question.title + ':</span>' + 
    '<input type="checkbox" name="' + question.name + '" />' + 
  '</label></div>'); 
} 
$('form').html(parts.join(''));
```

### 注意

自近些年来，这是一个常用的模式，因为它比使用 "+=" 连接中间结果性能更好。

### 样式和动画

在可能的情况下，通过利用`$.fn.addClass()`和`$.fn.removeClass()`方法使用 CSS 类进行样式操作，而不是通过`$.fn.css()`方法手动操纵元素的样式。当你需要为大量元素设置样式时，这特别有用，因为这是 CSS 类的主要用途，并且浏览器已经花费了数年的时间对其进行优化。

### 提示

作为最小化操作元素数量的额外优化步骤，你可以在单个公共祖先元素上应用 CSS 类，并使用后代 CSS 选择器来应用你的样式，如此处所示：[`developer.mozilla.org/en-US/docs/Web/CSS/Descendant_selectors`](https://developer.mozilla.org/en-US/docs/Web/CSS/Descendant_selectors)

当你仍然需要使用`$.fn.css()`方法时，例如，当你的实现需要是命令式的时候，使用接受对象参数的调用重载：[`api.jquery.com/css/#css-properties`](http://api.jquery.com/css/#css-properties)。这样，在为元素应用多个样式时，所需的方法调用将被最小化，而且你的代码组织得更好。

此外，避免混合使用操纵 DOM 的方法和从 DOM 中读取数据的方法，因为这会强制页面重新排版，以便浏览器计算页面元素的新位置。

而不是像这样做：

```js
$('h1').css('padding-left', '2%'); 
$('h1').css('padding-right', '2%'); 
$('h1').append('<b>!!</b>'); 
var h1OuterWidth = $('h1').outerWidth(); 

$('h1').css('margin-top', '5%'); 
$('body').prepend('<b>--!!--</b>'); 
var h1Offset = $('h1').offset();
```

更好地将非冲突的操作分组在一起，像这样：

```js
$('h1').css({ 
    'padding-left': '2%', 
    'padding-right': '2%', 
    'margin-top': '5%' 
}).append('<b>!!</b>'); 
$('body').prepend('<b>--!!--</b>'); 

var h1OuterWidth = $('h1').outerWidth(); 
var h1Offset = $('h1').offset();
```

浏览器因此可以跳过对页面的一些重新渲染，从而减少代码执行时的暂停。

### 注意

有关重排的更多信息，请访问以下页面：[`developers.google.com/speed/articles/reflow`](https://developers.google.com/speed/articles/reflow)

最后，请注意，v1.x 和 v2.x 中所有由 jQuery 生成的动画都是使用`setTimeout()`函数实现的。这将在 jQuery 的 v3.x 中发生变化，该版本计划使用`requestAnimationFrame()`函数，这更适合创建命令式动画。在那之前，你可以使用**jQuery-requestAnimationFrame**插件 ([`github.com/gnarf/jquery-requestAnimationFrame`](https://github.com/gnarf/jquery-requestAnimationFrame))，它对 jQuery 进行了猴子补丁，以便在可用时使用`requestAnimationFrame()`函数进行动画。

### 操纵分离的元素

操纵 DOM 元素时避免页面不必要的重绘的另一种方法是将元素从页面中分离，并在完成操作后重新附加它。使用分离的内存中元素要快得多，并且不会导致页面重排。

为了实现这一点，我们使用`$.fn.detach()`方法，与`$.fn.remove()`相比，它保留了分离元素上的所有事件处理程序和 jQuery 数据。

```js
var $h1 = $('#pageHeader'); 
var $h1Cont = $h1.parent(); 
$h1.detach(); 

$h1.css({ 
    'padding-left': '2%', 
    'padding-right': '2%', 
    'margin-top': '5%' 
}).append('<b>!!</b>'); 

$h1Cont.append($h1); 
```

另外，为了能够将操作过的元素放回其原始位置，我们可以在 DOM 中创建并插入一个隐藏的占位符元素。这个空的隐藏元素不会影响页面的渲染，并在将原始项目放回其原始位置后被移除。

```js
var $h1PlaceHolder = $('<div style="display: none;"></div>'); 
var $h1 = $('#pageHeader'); 
$h1PlaceHolder.insertAfter($h1); 

$h1.detach(); 

$h1.css({ 
    'padding-left': '2%', 
    'padding-right': '2%', 
    'margin-top': '5%' 
}).append('<b>!!</b>'); 

$h1.insertAfter($h1PlaceHolder); 
$h1PlaceHolder.remove(); 
$h1PlaceHolder = null; 
```

### 注意

欲了解有关 `$.fn.detach()` 方法的更多信息，请阅读文档：[`api.jquery.com/detach/`](http://api.jquery.com/detach/)

### 引入 Flyweight 模式

根据计算机科学的说法，Flyweight 是一种对象，用于通过提供与其他对象实例共享的功能和/或数据来减少实现的内存消耗。JavaScript 构造函数的**原型**可以被定义为 Flyweights，因为每个对象实例都可以使用其原型中定义的所有方法和属性，直到覆盖它们为止。另一方面，经典的 Flyweights 是与它们一起使用的对象系列中的独立对象，并经常在特殊的数据结构中保存共享的数据和功能。

## 使用委托观察者

在 jQuery 应用程序中，委托观察者是 Flyweights 的一个很好的示例，正如我们在第二章中看到的*观察者模式*中的仪表板示例一样，它可以通过作为大量元素的集中事件处理程序来大大降低实现的内存需求。通过这种方式，我们可以避免为每个元素设置单独的观察者和事件处理程序的成本，并使用浏览器的事件冒泡机制在单个共同的祖先元素上观察它们并过滤它们的来源。

```js
$boxContainer.on('click', '.boxCloseButton', function() { 
    var $button = $(this); 
    dashboard.informationBox.close($button); 
});
```

### 注意

实际的 Flyweight 对象是与祖先元素附加的回调一起的事件处理程序。

## 使用 $.noop() 方法

jQuery 库提供了 `$.noop()` 方法，实际上是一个可以在不同实现之间共享的空函数。使用空函数作为默认回调值通过减少 `if` 语句的数量来简化和提高实现的可读性。这对于已经封装了复杂功能的 jQuery 插件非常方便。

```js
function doLater(callbackFn) { 
    setTimeout(function() { 
        if (callbackFn) { 
            callbackFn(); 
        } 
    }, 500); 
} 

// with $.noop() 
function doLater(callbackFn) { 
    callbackFn = callbackFn || $.noop(); 
    setTimeout(function() { 
        callbackFn(); 
    }, 500); 
} 
```

在这种情况下，无论是由于实现需求还是开发者的个人品味，都导致了使用空函数，`$.noop()` 方法都是一种降低内存消耗的有效方式，它通过在整个实现的所有不同部分之间共享一个空函数实例来实现。使用 `$.noop()` 方法的另一个好处是，我们还可以通过简单检查 `callbackFn === $.noop()` 来检查传递的函数引用是否为空函数。

### 注意

欲了解更多信息，请参阅文档：[`api.jquery.com/jQuery.noop/`](http://api.jquery.com/jQuery.noop/)

## 使用 $.single 插件

在 jQuery 应用程序中，另一个简单的享元模式示例是 *James Padolsey* 在他的文章 *76 bytes for faster jQuery* 中描述的 `jQuery.single` 插件，该插件尝试在单个页面元素上应用 jQuery 方法时消除创建新的 jQuery 对象。该实现非常小，创建一个单一的 jQuery 复合集合对象，在每次调用 `jQuery.single()` 方法时返回，该对象包含用作参数的页面元素。

```js
jQuery.single = (function(){ 
    var collection = jQuery([1]);
    // Fill with 1 item, to make sure length === 1 
    return function(element) { 
        collection[0] = element; // Give collection the element: 
        return collection; // Return the collection: 
    }; 
}());
```

当在 `$.fn.on()` 这样的观察者和 `$.each()` 这样的方法迭代中使用时，`jQuery.single` 插件非常有用。

```js
$boxContainer.on('click', '.boxCloseButton', function() { 
    // var $button = $(this); 
    var $button = $.single(this);
    // this is not creating any new object
    dashboard.informationBox.close($button); 
});
```

使用 `jQuery.single` 插件的好处在于我们创建的对象更少，因此当释放短生命周期对象的内存时，浏览器的垃圾回收器的工作量也会减少。

作为一个副作用，请注意每次调用`$.single()`方法时返回的单个 jQuery 对象以及最后一个调用参数将存储到下一次调用该方法之前的事实：

```js
var buttons = document.getElementsByTagName('button'); 
var $btn0 = $.single(buttons[0]); 
var $btn1 = $.single(buttons[1]); 
$btn0 === $btn1 // this is true
```

另外，如果你使用类似 `$btn1.remove()` 这样的方法，那么该元素将一直保留，直到下一次调用 `$.single()` 方法将其从插件的内部集合对象中删除为止。

另一个类似但更全面的插件是 `jQuery.fly` 插件，它可以使用数组和 jQuery 对象作为参数调用。

### 注意

关于 `jQuery.single` 和 `jQuery.fly` 的更多信息，请访问以下链接：[`james.padolsey.com/javascript/76-bytes-for-faster-jquery/`](http://james.padolsey.com/javascript/76-bytes-for-faster-jquery/) 和 [`github.com/matjaz/jquery.fly`](https://github.com/matjaz/jquery.fly)。

另一方面，处理带有单个页面元素的 `$()` 方法调用的 jQuery 实现并不复杂，只创建一个简单的对象。

```js
jQuery = function( selector, context ) { 
  return new jQuery.fn.init( selector, context ); 
}; 
/*...*/ init = jQuery.fn.init = function( selector, context, root ) { 
  /*... else */ 
  if ( selector.nodeType ) { 
    this.context = this[ 0 ] = selector; 
    this.length = 1; 
    return this; 
  } /* ... */ 
}; 
```

此外，现代浏览器的 JavaScript 引擎在处理短生命周期对象时已经非常高效，因为这些对象通常作为方法调用参数在应用程序中传递。

# 延迟加载模块

最后，我们将介绍一种高级技术——**延迟加载模块**。这种实践的关键概念是，在页面加载期间，浏览器仅下载并执行那些在页面的初始渲染过程中所需的模块，而其余的应用程序模块则在页面完全加载后，并且需要响应用户操作时才被请求。`RequireJS` ([`requirejs.org/`](http://requirejs.org/)) 是一个常用的 JavaScript 库，用作模块加载器，但对于简单情况，我们可以使用 jQuery 来实现相同的效果。

作为此的示例，我们将在用户首次单击仪表板上的 `<button>` 后，使用它来延迟加载我们在以前章节中看到的 Dashboard 示例的 `informationBox` 模块。我们将抽象出负责下载和执行 JavaScript 文件的实现，成为一个通用且可重用的模块，名为 `moduleUtils`。

```js
(function() { 
    'use strict'; 

    dashboard.moduleUtils = dashboard.moduleUtils || {}; 

    dashboard.moduleUtils.getModule = function(namespaceString) { 
        var parts = namespaceString.split('.'); 
        var result = parts.reduce(function(crnt, next){ 
            return crnt && crnt[next]; 
        }, window); 
        return result; 
    }; 

    var ongoingModuleRequests = {}; 

    dashboard.moduleUtils.ensureLoaded = function(namespaceString) { 
        var existingNamespace = this.getModule(namespaceString); 
        if (existingNamespace) { 
            return $.Deferred().resolve(existingNamespace); 
        } 

        if (ongoingModuleRequests[namespaceString]) { 
            return ongoingModuleRequests[namespaceString]; 
        } 

        var modulePromise = $.getScript(namespaceString.toLowerCase() + '.js') 
            .always(function() { 
                ongoingModuleRequests[namespaceString] = null; 
            }).then(function() { 
               return dashboard.moduleUtils.getModule(namespaceString); 
            }); 
        ongoingModuleRequests[namespaceString] = modulePromise; 
        return modulePromise; 
    };

})(); 
```

`getModule()` 方法接受模块的命名空间作为字符串参数，并返回模块的**单例对象**本身，或者如果模块尚未加载，则返回假值。这是通过使用 `Array.reduce()` 方法完成的，该方法用于迭代命名空间字符串的不同部分，使用点（.）作为分隔符，并在先前对象上下文中评估每个部分，从`window`开始。

### 注意

有关 `Array.reduce()` 方法的更多信息，请访问：[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/Reduce`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Array/Reduce)

`ensureLoaded()` 是 `moduleUtils` 模块的主要方法，负责检索并执行尚未加载的模块。它首先使用 `getModule()` 方法检查请求的模块是否已加载，如果是，则将其命名空间对象作为已解决的 Promise 返回。

下一步，如果模块尚未加载，则是检查 `ongoingModuleRequests` 对象，以验证请求的模块是否尚未下载。为了做到这一点，`ongoingModuleRequests` 对象将模块的命名空间字符串作为属性，并存储用于从服务器检索 `.js` 文件的 AJAX 请求的 Promises。如果有一个 Promise 对象可用，那么我们可以推断出 AJAX 请求仍在进行中，并且我们不会启动新的请求，而是返回现有的 Promise。

最后，当上述任何一个都没有返回结果时，我们使用在之前章节中讨论的小写模块文件命名约定，并使用 jQuery 的 `$.getScript()` 方法发起 AJAX 请求以检索所请求的模块文件。为 AJAX 请求创建的 Promise 被分配为 `ongoingModuleRequests` 对象的适当属性，并随后返回给方法的调用者。当在以后的时间点，Promise 被完成时，我们重新评估模块并将其作为返回的 Promise 的最终结果返回。此外，无论 AJAX 请求的结果如何，Promise 也会从 `ongoingModuleRequests` 对象中删除，以便在网络故障时保持实现的可重用性，并释放为请求分配的内存。

### 注意

请记住，当页面通过文件系统加载时，`$.getScript()` 方法可能在某些浏览器中无法工作，但在像 Apache、IIS 或 nginx 这样的 Web 服务器上加载时则可以正常工作。有关 `$.getScript()` 的更多信息，请访问：[`api.jquery.com/jQuery.getScript/`](http://api.jquery.com/jQuery.getScript/)

我们对现有的 `informationBox` 模块的实现仅做了一个改变，即使其自我初始化，以尝试减少 `ensureLoaded()` 方法的复杂性。

```js
(function() { 
    'use strict'; 

    dashboard.informationBox = dashboard.informationBox || {}; 

    var $boxContainer = null; 

    dashboard.informationBox.init = function() { /* … */ };

    $(document).ready(dashboard.informationBox.init); 

   /*...*/
})(); 
```

最后，我们还必须更改 `categories` 模块的实现，以便在使用 `informationBox` 模块之前使用 `ensureLoaded()` 方法。正如您下面所见，我们不得不重构处理仪表板 `<button>` 的点击事件的代码，因为 `ensureLoaded()` 方法返回一个 Promise 作为结果：

```js
// in dashboard.categories.init 
dashboard.$container.find('.dashboardCategories').on('click', 'button', function() { 
    var $button = $(this); 
    var itemName = $button.text(); 

    var p = dashboard.moduleUtils.ensureLoaded('dashboard.informationBox');

    p.then(function(){ 
        dashboard.informationBox.openNew(itemName); 
    }); 
});
```

# 摘要

在本章中，我们学习了几种优化技术，可以用来提高 jQuery 应用程序的性能，特别是当它们变得庞大和复杂时。

我们从简单的实践开始，比如捆绑和缩小我们的 JavaScript 文件，并讨论了使用 CDN 加载第三方库的好处。然后，我们继续分析了一些编写高效 JavaScript 代码的简单模式，并学习了如何编写高效的 CSS 选择器来提高页面的渲染速度，并使用 jQuery 来改进 DOM 遍历。

我们继续使用 jQuery 特定的实践，例如缓存 jQuery 组合集合对象、如何最小化 DOM 操作，并提醒代理观察者模式，作为享元模式的一个很好的例子。最后，我们介绍了惰性加载的高级技术，并演示了如何根据用户操作逐步加载实现的各个模块。

完成本章后，我们现在能够将最常见的优化模式应用于我们的实现，并在将应用程序移至生产环境之前，将本章用作最佳实践和性能提示的检查清单。
