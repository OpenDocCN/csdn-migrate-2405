# jQuery3 学习手册（二）

> 原文：[`zh.annas-archive.org/md5/B3EDC852976B517A1E8ECB0D0B64863C`](https://zh.annas-archive.org/md5/B3EDC852976B517A1E8ECB0D0B64863C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：样式和动画

如果说行动胜于言辞，那么在 JavaScript 世界中，效果使行动更加响亮。通过 jQuery，我们可以轻松地为我们的行动增添影响力，通过一组简单的视觉效果甚至制作我们自己复杂的动画。

jQuery 提供的效果为页面增添了简单的视觉华丽效果，赋予了现代感和动感。然而，除了仅仅是装饰之外，它们还可以提供重要的可用性增强，帮助用户在页面上发生某些事件时进行定位（尤其在 Ajax 应用程序中常见）。

在本章中，我们将涵盖：

+   动态改变元素的样式

+   使用各种内置效果隐藏和显示元素

+   创建元素的自定义动画

+   将效果按顺序连续发生

# 修改内联属性的 CSS

在我们深入研究 jQuery 效果之前，先来简要了解一下 CSS 是如何使用的。在之前的章节中，我们通过在单独的样式表中为类定义样式，然后使用 jQuery 添加或删除这些类来修改文档的外观。通常，这是将 CSS 注入 HTML 的首选过程，因为它尊重样式表在处理页面呈现方面的作用。然而，有时我们可能需要应用还没有或者不能轻松定义在样式表中的样式。幸运的是，jQuery 为这种情况提供了`.css()`方法。

这个方法既作为**获取器**又作为**设置器**。要获取单个样式属性的值，我们只需将属性名称作为字符串传递，然后返回一个字符串。要获取多个样式属性的值，我们可以将属性名称作为字符串数组传递，然后返回属性值对的对象。多词属性名称，例如`backgroundColor`，可以通过 jQuery 在连字符化的 CSS 表示法（`background-color`）或驼峰式的 DOM 表示法（`backgroundColor`）中解释：

```js
// Get a single property's value 
.css('property') 
// "value" 

// Get multiple properties' values 
.css(['property1', 'property-2']) 
// {"property1": "value1", "property-2": "value2"} 

```

对于设置样式属性，`.css()`方法有两种形式。一种形式接受单个样式属性及其值，另一种形式接受属性值对的对象：

```js
// Single property and its value 
.css('property', 'value') 

// Object of property-value pairs 
.css({ 
  property1: 'value1', 
  'property-2': 'value2' 
}) 

```

这些简单的键值集合，称为**对象字面量**，是直接在代码中创建的真正的 JavaScript 对象。

对象字面量表示法

在属性值中，字符串通常像往常一样用引号括起来，但是其他数据类型如数字则不需要。由于属性名称是字符串，因此它们通常会被包含在引号中。然而，如果属性名称是有效的 JavaScript 标识符，比如在驼峰式的 DOM 表示法中书写时，属性名称就不需要引号。

我们使用`.css()`方法的方式与使用`.addClass()`方法的方式相同；我们将其应用于一个指向 DOM 元素集合的 jQuery 对象。为了演示这一点，我们将玩弄一个类似于第三章中的样式切换器，*处理事件*：

```js
<div id="switcher"> 
  <div class="label">Text Size</div> 
  <button id="switcher-default">Default</button> 
  <button id="switcher-large">Bigger</button> 
  <button id="switcher-small">Smaller</button> 
</div> 
<div class="speech"> 
  <p>Fourscore and seven years ago our fathers brought forth 
       on this continent a new nation, conceived in liberty,  
       and dedicated to the proposition that all men are created  
       equal.</p> 
  ... 
</div> 

```

获取示例代码

您可以从 GitHub 存储库访问示例代码：[`github.com/PacktPublishing/Learning-jQuery-3`](https://github.com/PacktPublishing/Learning-jQuery-3)。

通过链接到具有几个基本样式规则的样式表，页面将最初呈现如下：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_04_01.png)

完成我们的代码后，单击“Bigger”和“Smaller”按钮将增加或减小 `<div class="speech">` 的文本大小，而单击“Default”按钮将重置 `<div class="speech">` 的原始文本大小。

# 设置计算的样式属性值

如果我们想要的仅仅是将字体大小一次性更改为预定值，我们仍然可以使用 `.addClass()` 方法。但是，现在假设我们想要每次单击相应按钮时文本都继续递增或递减。虽然可能可以为每次单击定义一个单独的类并对其进行迭代，但更简单的方法是每次通过获取当前大小并增加固定因子（例如，40%）来计算新的文本大小。

我们的代码将以 `$(() => {})` 和 `$('#switcher-large').click()` 事件处理程序开头：

```js
$(() => {
  $('#switcher-large')
    .click((e) => { 

    }); 
}); 

```

列表 4.1

接下来，可以使用 `.css()` 方法轻松发现字体大小：`$('div.speech').css('fontSize')`。然而，返回的值是一个字符串，包含数值字体大小值和该值的单位（`px`）。我们需要去掉单位标签，以便使用数值进行计算。另外，当我们计划多次使用一个 jQuery 对象时，通常最好通过将生成的 jQuery 对象存储在常量中来缓存选择器：

```js
$(() => { 
  const $speech = $('div.speech'); 
  $('#switcher-large')
    .click(() => {
      const num = parseFloat($speech.css('fontSize')); 
    }); 
}); 

```

列表 4.2

`$(() => {})` 内的第一行创建一个包含指向 `<div class="speech">` 的 jQuery 对象的**常量**。注意名称中的美元符号（`$`），`$speech`。由于美元符号是 JavaScript 标识符中的合法字符，我们可以用它来提醒常量是一个 jQuery 对象。与其他编程语言（如 PHP）不同，美元符号在 JavaScript 中没有特殊意义。

使用常量（`const`）而不是变量（`var`）有充分的理由。常量是在 JavaScript 的 ES2015 版本中引入的，它们可以帮助减少某些类型的错误。以我们的 `$speech` 常量为例。它除了 `<div class="speech">` 之外，会持有其他值吗？不会。由于我们声明了这是一个常量，试图给 `$speech` 分配另一个值会导致错误。这些错误很容易修复。如果 `$speech` 被声明为一个变量，并且我们错误地给它分配了一个新值，那么失败将是微妙且难以诊断的。当然，有时我们*需要*能够分配新值，在这种情况下，您将使用一个变量。

在 `.click()` 处理程序内部，我们使用 `parseFloat()` 仅获取字体大小属性的数值部分。`parseFloat()` 函数从左到右查看字符串，直到遇到一个非数字字符为止。数字字符串被转换为浮点数（十进制数）。例如，它会将字符串`'12'`转换为数字`12`。此外，它会从字符串中去除非数字的尾随字符，因此`'12px'`变成了`12`。如果字符串以非数字字符开头，`parseFloat()` 将返回 `NaN`，表示*不是一个数字*。

唯一剩下的就是修改解析出来的数值并根据新值重置字体大小。在我们的示例中，每次点击按钮时，我们将字体大小增加 40%。为此，我们将 `num` 乘以 `1.4`，然后通过连接结果和`'px'`来设置字体大小：

```js
$(() => {
  const $speech = $('div.speech');

  $('#switcher-large')
    .click(() => {
      const num = parseFloat($speech.css('fontSize'));
      $speech.css('fontSize', `${num * 1.4}px`);
    });
}); 

```

清单 4.3

现在，当用户点击“放大”按钮时，文本变大了。再次点击，文本就变得更大了：

![图 4.4](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_04_02.png)

要让“缩小”按钮减小字体大小，我们将使用除法而不是乘法：`num / 1.4`。更好的是，我们将两者合并成一个单一的`.click()`处理程序，适用于`<div id="switcher">`中的所有`<button>`元素。然后，在找到数值之后，我们可以根据被点击的按钮的 ID 来乘以或除以。*清单 4.4* 对此进行了说明。

```js
$(() => {
  const sizeMap = {
    'switcher-small': n => n / 1.4,
    'switcher-large': n => n * 1.4
  };

  const $speech = $('div.speech');

  $('#switcher button')
    .click((e) => {
      const num = parseFloat($speech.css('fontSize'));
      $speech.css(
        'fontSize',
        `${sizeMape.target.id}px`
      );
    });
}); 

```

清单 4.4

`e.target.id` 值用于确定点击事件的行为。`sizeMap` 是存储这些行为的地方。这是一个简单的对象，将元素 ID 映射到一个函数。此函数接收当前的 `fontSize` 值。我们之所以想使用这样的映射，是因为它比编码为 `if` 语句之类的东西更容易添加或删除行为。例如，假设当前的字体大小是`"10px"`，用户点击了“放大”按钮。那么，模板字符串``${sizeMape.target.id}px`` 将导致`"14px"`。

让字体大小恢复到初始值也是很好的。为了让用户能够这样做，我们可以简单地在 DOM 准备就绪时将字体大小存储在一个变量中。然后，每当点击“默认”按钮时，我们就可以恢复这个值。我们只需要向 `sizeMap` 添加另一个函数：

```js
$(() => {
  const sizeMap = {
    'switcher-small': n => n / 1.4,
    'switcher-large': n => n * 1.4,
    'switcher-default': () => defaultSize
  };

  const $speech = $('div.speech');
  const defaultSize = parseFloat($speech.css('fontSize'));

  $('#switcher button')
    .click((e) => {
      const num = parseFloat($speech.css('fontSize'));
      $speech.css(
        'fontSize',
        `${sizeMape.target.id}px`
      );
    });
}); 

```

清单 4.5

注意我们根本不需要更改点击处理程序来适应这种新行为？我们创建了一个名为`defaultSize`的新常量，它将始终保存原始字体大小。然后，我们只需要为`switcher-default` ID 添加一个新函数到 `sizeMap` 中，该函数返回 `defaultSize` 的值。

使用这样的映射，更容易改变我们的点击处理程序行为，而不必维护 `if` 或 `switch` 语句。

# 使用特定于供应商的样式属性

当浏览器供应商引入实验性的样式属性时，通常会在属性名称前加上前缀，直到浏览器的实现与 CSS 规范一致为止。当实现和规范足够稳定时，供应商会去除该前缀，并允许使用标准名称。因此，在样式表中，看到如下一组 CSS 声明是很常见的：

```js
-webkit-property-name: value; 
-moz-property-name: value; 
-ms-property-name: value; 
-o-property-name: value; 
property-name: value; 

```

如果我们想要在 JavaScript 中应用相同的效果，我们需要测试 DOM 版本的这些变化的存在性：`propertyName`、`WebkitPropertyName`、`msPropertyName` 等等。然而，使用 jQuery，我们可以简单地应用标准属性名称，例如 `.css('propertyName', 'value')`。如果在样式对象的属性中找不到该名称，则 jQuery 在幕后循环遍历供应商前缀--`Webkit`、`O`、`Moz` 和 `ms`--并使用找到的第一个作为属性，如果有的话。

# 隐藏和显示元素

基本的 `.hide()` 和 `.show()` 方法，没有任何参数，可以被视为 `.css('display', 'string')` 的智能快捷方式方法，其中 `'string'` 是适当的显示值。效果如预期，匹配的元素集将立即隐藏或显示，没有动画。

`.hide()` 方法将匹配元素集的内联样式属性设置为 `display: none`。这里的巧妙之处在于它记住了显示属性的值--通常是 `block`、`inline` 或 `inline-block`--在改为 `none` 之前的值。相反，`.show()` 方法将匹配元素集的显示属性恢复为在应用 `display: none` 之前的初始值。

显示属性

要了解更多关于 `display` 属性以及它的值在网页中的视觉呈现方式的信息，请访问 Mozilla Developer Center [`developer.mozilla.org/zh-CN/docs/Web/CSS/display`](https://developer.mozilla.org/zh-CN/docs/Web/CSS/display)，并查看示例 [`developer.mozilla.org/samples/cssref/display.html`](https://developer.mozilla.org/samples/cssref/display.html)。

`.show()` 和 `.hide()` 的这个特性在隐藏已在样式表中被覆盖其默认 `display` 属性的元素时尤其有帮助。例如，`<li>` 元素默认具有 `display: list-item` 属性，但我们可能希望将其更改为 `display: inline` 以用于水平菜单。幸运的是，对一个隐藏的元素（比如其中一个 `<li>` 标签）使用 `.show()` 方法不会简单地将其重置为其默认的 `display: list-item`，因为这会将 `<li>` 标签放在自己的一行上。相反，该元素被恢复到其先前的 `display: inline` 状态，从而保持了水平设计。

我们可以通过在示例 HTML 中的第一个段落后添加一个“阅读更多”链接来设置这两种方法的快速演示：

```js
<div class="speech"> 
  <p>Fourscore and seven years ago our fathers brought forth  
       on this continent a new nation, conceived in liberty,  
       and dedicated to the proposition that all men are  
       created equal. 
  </p> 
  <p>Now we are engaged in a great civil war, testing whether  
       that nation, or any nation so conceived and so dedicated,  
       can long endure. We are met on a great battlefield of  
       that war. We have come to dedicate a portion of that  
       field as a final resting-place for those who here gave  
       their lives that the nation might live. It is altogether  
       fitting and proper that we should do this. But, in a  
       larger sense, we cannot dedicate, we cannot consecrate,  
       we cannot hallow, this ground. 
  </p> 
  <a href="#" class="more">read more</a> 
    ... 
</div> 

```

当 DOM 就绪时，我们选择一个元素并对其调用 `.hide()` 方法：

```js
$(() => {
  $('p')
    .eq(1)
    .hide();   
}); 

```

清单 4.6

`.eq()`方法类似于第二章*选择元素*中讨论的`:eq()`伪类。它返回一个 jQuery 对象，指向提供的从零开始的索引处的单个元素。在这种情况下，该方法选择第二个段落并隐藏它，以便在第一个段落后立即显示“阅读更多”链接：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_04_03.png)

当用户在第一个段落末尾点击“阅读更多”时，我们调用`.show()`来显示第二个段落，并调用`.hide()`来隐藏点击的链接：

```js
$(() => {
  $('p')
    .eq(1)
    .hide();

  $('a.more')
    .click((e) => {
      e.preventDefault();
      $('p')
        .eq(1)
        .show();
      $(e.target)
        .hide();
    });
});

```

清单 4.7

注意使用`.preventDefault()`来阻止链接触发其默认操作。现在演讲看起来像这样：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_04_04.png)

`.hide()`和`.show()`方法快速实用，但并不十分引人注目。为了增添一些风彩，我们可以给它们指定持续时间。

# 效果和持续时间

当我们在`.show()`或`.hide()`中包含持续时间（有时也称为速度）时，它就会变成动画效果——在指定的时间段内发生。例如，`.hide(duration)`方法会逐渐减小元素的高度、宽度和不透明度，直到这三者都达到零，此时将应用 CSS 规则`display: none`。`.show(duration)`方法将增加元素的高度从顶部到底部，宽度从左边到右边，不透明度从 0 到 1，直到其内容完全可见。

# 加速中

使用任何 jQuery 效果时，我们可以使用两种预设速度之一，`'slow'`或`'fast'`。使用`.show('slow')`使显示效果在 600 毫秒（0.6 秒）内完成，`.show('fast')`在 200 毫秒内完成。如果提供了任何其他字符串，jQuery 将使用默认的动画持续时间 400 毫秒。为了更精确地控制，我们可以指定毫秒数，例如`.show(850)`。

让我们在显示亚伯拉罕·林肯的《葛底斯堡演说》第二段时包含一个速度示例：

```js
$(() => {
  $('p')
    .eq(1)
    .hide();

  $('a.more')
    .click((e) => {
      e.preventDefault();
      $('p')
        .eq(1)
        .show('slow');
      $(e.target)
        .hide();
    });
});

```

清单 4.8

当我们大致捕捉到段落在效果中的中间时，我们看到以下内容：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_04_05.png)

# 淡入和淡出

尽管动画化的`.show()`和`.hide()`方法确实很引人注目，但在实践中，它们会比有用的属性更多地进行动画处理。幸运的是，jQuery 提供了另外几种预定义动画，效果更为微妙。例如，要使整个段落逐渐增加不透明度而出现，我们可以使用`fadeIn('slow')`代替：

```js
$(() => {
  $('p')
    .eq(1)
    .hide();

  $('a.more')
    .click((e) => {
      e.preventDefault();
      $('p')
        .eq(1)
        .fadeIn('slow');
      $(e.target)
        .hide();
    });
});

```

清单 4.9

现在当我们在效果进行时观察段落时，它看起来像这样：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_04_06.png)

这里的不同之处在于`.fadeIn()`效果首先设置段落的尺寸，使内容可以简单地淡入其中。为了逐渐减少不透明度，我们可以使用`.fadeOut()`。

# 滑动向上和向下

淡入淡出动画对于在文档流之外的项目非常有用。例如，这些是覆盖在页面上的*灯箱*元素上的典型效果。但是，当一个元素是文档流的一部分时，在其上调用`.fadeIn()`会导致文档跳转以提供新元素所需的房地产，这并不美观。

在这些情况下，jQuery 的`.slideDown()`和`.slideUp()`方法是正确的选择。这些效果仅对所选元素的高度进行动画处理。要使我们的段落以垂直滑动效果显示，我们可以调用`.slideDown('slow')`：

```js
$(() => {
  $('p')
    .eq(1)
    .hide();

  $('a.more')
    .click((e) => {
      e.preventDefault();
      $('p')
        .eq(1)
        .slideDown('slow');
      $(e.target)
        .hide();
    });
});

```

列表 4.10

这次当我们检查动画中点的段落时，我们看到以下内容：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_04_07.png)

要撤销这种效果，我们将调用`.slideUp()`方法。

# 切换可见性

有时我们需要切换元素的可见性，而不是像之前的示例中一样仅显示它们一次。这种切换可以通过首先检查匹配元素的可见性，然后调用适当的方法来实现。再次使用淡入淡出效果，我们可以修改示例脚本如下：

```js
$(() => {
  const $firstPara = $('p')
    .eq(1)
    .hide();

  $('a.more')
    .click((e) => {
      e.preventDefault();

      if ($firstPara.is(':hidden')) {
        $firstPara.fadeIn('slow');
        $(e.target).text('read less');
      } else {
        $firstPara.fadeOut('slow');
        $(e.target).text('read more');
      }
    });
}); 

```

列表 4.11

正如我们在本章前面所做的那样，我们在这里缓存了我们的选择器，以避免重复的 DOM 遍历。还要注意，我们不再隐藏点击的链接；相反，我们正在更改其文本。

要检查元素包含的文本并更改该文本，我们使用`.text()`方法。我们将在第五章，*操作 DOM*中更深入地探讨此方法。

使用`if-else`语句是切换元素可见性的完全合理的方法。但是，通过 jQuery 的复合效果方法，我们可以从代码中删除一些条件逻辑。jQuery 提供了复合方法`.fadeToggle()`和`.slideToggle()`，它们使用相应的效果显示或隐藏元素。当我们使用`.slideToggle()`方法时，脚本看起来是这样的：

```js
$(() => {
  const $firstPara = $('p')
    .eq(1)
    .hide();

  $('a.more')
    .click((e) => {
      e.preventDefault();

      $firstPara.slideToggle('slow');
      $(e.target)
        .text(
          $(e.target).text() === 'read more' ?
            'read less' : 'read more'
        );
    });
}); 

```

列表 4.12

**三元表达式**（`$(e.target).text() === 'read more' ?`）检查链接的文本而不是第二段落的可见性，因为我们只是用它来更改文本。当我们需要基于某些条件获取值时，我们可以使用三元表达式作为完整的`if`语句的较短替代方法。把三元表达式想象成调用一个函数，根据提供的参数返回不同的值。

# 创建自定义动画

除了预先构建的效果方法外，jQuery 还提供了一个强大的`.animate()`方法，允许我们使用精细的控制创建自己的自定义动画。`.animate()`方法有两种形式。第一种最多接受四个参数：

+   一个包含样式属性和值的对象，与本章前面讨论的`.css()`参数类似

+   一个可选的持续时间，可以是预设字符串之一，也可以是毫秒数

+   可选的缓动类型，这是一个我们现在不会使用的选项，但我们将在第十一章 *高级效果*中讨论它。

+   可选的回调函数，稍后在本章中讨论

总之，这四个参数看起来像这样：

```js
.animate(
  { property1: 'value1', property2: 'value2'},  
  duration,
  easing,
  () => { 
    console.log('The animation is finished.'); 
  } 
); 

```

第二种形式接受两个参数：一个属性对象和一个选项对象：

```js
.animate({properties}, {options}) 

```

在这种形式中，第二个参数将第一种形式的第二到第四个参数包装到另一个对象中，并将一些更高级的选项加入其中。以下是传递实际参数时的第二种形式：

```js
.animate(
  { 
    property1: 'value1',  
    property2: 'value2' 
  },
  { 
    duration: 'value',  
    easing: 'value', 
    specialEasing: { 
      property1: 'easing1', 
      property2: 'easing2' 
    }, 
    complete: () => { 
      console.log('The animation is finished.'); 
    }, 
    queue: true, 
    step: callback 
  }
); 

```

现在，我们将使用`.animate()`方法的第一种形式，但在本章讨论排队效果时，我们将返回到第二种形式。

# 手动构建效果

我们已经看到了几种用于显示和隐藏元素的预包装效果。在讨论`.animate()`方法之前，通过调用`.slideToggle()`使用这个较低级别的接口实现相同的结果将是有用的。用我们的自定义动画替换前面示例中的`.slideToggle()`行非常简单：

```js
$(() => {
  const $firstPara = $('p')
    .eq(1)
    .hide();

  $('a.more')
    .click((e) => {
      e.preventDefault();

      $firstPara.animate({ height: 'toggle' }, 'slow');
      $(e.target)
        .text(
          $(e.target).text() === 'read more' ?
            'read less' : 'read more'
        );
    }); 
}); 

```

列表 4.13

这不是`.slideToggle()`的完美替代品；实际的实现还会动画化元素的边距和填充。

如示例所示，`.animate()`方法提供了用于 CSS 属性的方便的简写值，如`'show'`、`'hide'`和`'toggle'`，以简化当我们想要模拟预包装效果方法如`.slideToggle()`的行为时的过程。

# 同时动画多个属性

使用`.animate()`方法，我们可以同时修改任意组合的属性。例如，要在切换第二段落时创建一个同时滑动和淡出的效果，我们只需将`opacity`添加到传递给`.animate()`的属性中即可：

```js
$(() => {
  const $firstPara = $('p')
    .eq(1)
    .hide();

  $('a.more')
    .click((e) => {
      e.preventDefault();

      $firstPara.animate({
        opacity: 'toggle',
        height: 'toggle'
      }, 'slow');
      $(e.target)
        .text(
          $(e.target).text() === 'read more' ?
            'read less' : 'read more'
        );
    }); 
}); 

```

列表 4.14

另外，我们不仅可以使用简写效果方法中使用的样式属性，还可以使用数值 CSS 属性，例如`left`、`top`、`fontSize`、`margin`、`padding`和`borderWidth`。在*列表 4.5*中，我们改变了段落的文本大小。我们可以通过简单地将`.animate()`方法替换为`.css()`方法来动画化文本大小的增加或减少：

```js
$(() => {
  const sizeMap = {
    'switcher-small': n => n / 1.4,
    'switcher-large': n => n * 1.4,
    'switcher-default': () => defaultSize
  };

  const $speech = $('div.speech');
  const defaultSize = parseFloat($speech.css('fontSize'));

  $('#switcher button')
    .click((e) => {
      const num = parseFloat($speech.css('fontSize'));
      $speech.animate({
        fontSize: `${sizeMape.target.id}px`
      });
    });
}); 

```

列表 4.15

额外的动画属性允许我们创建更复杂的效果。例如，我们可以将一个项目从页面的左侧移动到右侧，同时将其高度增加 20 像素，并将其边框宽度更改为 5 像素。我们将用`<div id="switcher">`框来说明这一复杂的属性动画集。在我们对其进行动画化之前，它是这样的：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_04_08.png)

对于具有可伸缩宽度布局，我们需要计算框在与页面右侧对齐之前需要移动的距离。假设段落的宽度是 `100%`，我们可以从段落的宽度中减去“文本大小”框的宽度。我们可以使用 `jQuery.outerWidth()` 方法来计算这些宽度，包括填充和边框。我们将使用此方法来计算 switcher 的新 `left` 属性。为了本例子的目的，我们将通过点击按钮上方的“文本大小”标签来触发动画。下面是代码应该的样子：

```js
$(() => {
  $('div.label')
    .click((e) => {
      const $switcher = $(e.target).parent();
      const paraWidth = $('div.speech p').outerWidth();
      const switcherWidth = $switcher.outerWidth();

      $switcher.animate({
        borderWidth: '5px',
        left: paraWidth - switcherWidth,
        height: '+=20px'
      }, 'slow');
    });
}); 

```

列表 4.16

有必要详细检查这些动画属性。`borderWidth` 属性很直接，因为我们正在指定一个带单位的常量值，就像在样式表中一样。`left` 属性是一个计算出的数字值。在这些属性上，单位后缀是可选的；因为我们在这里省略了它，所以假定为 `px`。最后，`height` 属性使用了我们之前未见过的语法。在属性值上的 `+=` 前缀表示相对值。所以，不是将高度动画变为 `20` 像素，而是将高度动画变为当前高度的 `20` 像素更高。由于涉及到特殊字符，相对值必须指定为字符串。

尽管此代码成功增加了 `<div>` 标签的高度并扩大了其边框，但是目前，`left` 位置似乎未更改：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_04_09.png)

我们仍然需要在 CSS 中启用更改此框的位置。

# 使用 CSS 进行定位

在使用 `.animate()` 时，重要的是要记住 CSS 对我们希望更改的元素施加的限制。例如，调整 `left` 属性对匹配元素没有影响，除非这些元素的 CSS 位置设置为 `relative` 或 `absolute`。所有块级元素的默认 CSS 位置都是 `static`，这准确描述了如果我们在先更改它们的 `position` 值之前尝试移动它们，这些元素将保持不变的方式。

有关绝对和相对定位的更多信息，请参阅 CSS 技巧：[`css-tricks.com/almanac/properties/p/position/`](https://css-tricks.com/almanac/properties/p/position/)。

在我们的样式表中，我们可以将 `<div id="switcher">` 设置为相对定位：

```js
#switcher { 
  position: relative; 
} 

```

不过，让我们通过在需要时通过 JavaScript 更改此属性来练习我们的 jQuery 技能：

```js
$(() =>
  $('div.label')
    .click((e) => {
      const $switcher = $(e.target).parent();
      const paraWidth = $('div.speech p').outerWidth();
      const switcherWidth = $switcher.outerWidth();

      $switcher
        .css('position', 'relative')
        .animate({
          borderWidth: '5px',
          left: paraWidth - switcherWidth,
          height: '+=20px'
        }, 'slow');
    });
}); 

```

列表 4.17

考虑了 CSS 后，在动画完成后点击“文本大小”后的结果如下：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_04_10.png)

# 同时执行与顺序执行的效果

正如我们刚刚发现的那样，`.animate()` 方法对影响特定一组元素的**同时**效果非常有用。然而，有时候我们想要**排队**我们的效果，以便它们一个接一个地发生。

# 使用单组元素

当对同一组元素应用多个效果时，通过链接这些效果可以轻松实现排队。为了演示这种排队，我们将通过将文本大小框移动到右侧，增加其高度和边框宽度来重新访问*列表 4.17*。但是，这次，我们只需将每个效果放在自己的`.animate()`方法中，并将三者链接在一起，便可以依次执行三个效果：

```js
$(() => {
  $('div.label')
    .click((e) => {
      const $switcher = $(e.target).parent();
      const paraWidth = $('div.speech p').outerWidth();
      const switcherWidth = $switcher.outerWidth();

      $switcher
        .css('position', 'relative')
        .animate({ borderWidth: '5px' }, 'slow')
        .animate({ left: paraWidth - switcherWidth }, 'slow')
        .animate({ height: '+=20px' }, 'slow');
    }); 
}); 

```

列表 4.18

请记住，链式调用允许我们将所有三个`.animate()`方法保持在同一行上，但是在这里，我们将它们缩进并将每个方法放在自己的一行上以提高可读性。

我们可以通过链接它们来对 jQuery 效果方法中的任何一个进行排队，而不仅仅是`.animate()`。例如，我们可以按照以下顺序对`<div id="switcher">`上的效果进行排队：

1.  使用`.fadeTo()`将其不透明度淡化为 0.5。

1.  使用`.animate()`将其移到右侧。

1.  使用`.fadeTo()`将其淡回完全不透明。

1.  使用`.slideUp()`将其隐藏。

1.  使用`.slideDown()`再次显示它。

我们需要做的就是按照代码中相同的顺序链接效果：

```js
$(() => {
  $('div.label')
    .click((e) => {
      const $switcher = $(e.target).parent();
      const paraWidth = $('div.speech p').outerWidth();
      const switcherWidth = $switcher.outerWidth();

      $switcher
        .css('position', 'relative')
        .fadeTo('fast', 0.5)
        .animate({ left: paraWidth - switcherWidth }, 'slow')
        .fadeTo('slow', 1.0)
        .slideUp('slow')
        .slideDown('slow');
    }); 
}); 

```

列表 4.19

# 绕过队列

但是，如果我们想要在淡入到半透明度的同时将`<div>`标签移到右侧怎么办？如果两个动画的速度相同，我们可以简单地将它们合并为一个`.animate()`方法。但是，在这个例子中，淡出使用了'快'速度，而移到右侧则使用了'慢'速度。这就是第二种形式的`.animate()`方法派上用场的地方：

```js
$(() => {
  $('div.label')
    .click((e) => {
      const $switcher = $(e.target).parent();
      const paraWidth = $('div.speech p').outerWidth();
      const switcherWidth = $switcher.outerWidth();

      $switcher
        .css('position', 'relative')
        .fadeTo('fast', 0.5)
        .animate(
          { left: paraWidth - switcherWidth },
          { duration: 'slow', queue: false }
        )
        .fadeTo('slow', 1.0)
        .slideUp('slow')
        .slideDown('slow');
    }); 
}); 

```

列表 4.20

第二个参数，一个选项对象，提供了`queue`选项，当设置为`false`时，使动画与前一个动画同时开始。如果你考虑一下，这是有道理的，因为任何在队列中的东西都必须等待已经在队列中的东西。

# 手动排队效果

关于单一元素队列效应的最后观察是，排队不会自动应用于其他非效果方法，例如`.css()`。所以，假设我们想在`.slideUp()`方法之后但在`slideDown()`方法之前将`<div id="switcher">`的背景颜色更改为红色。

我们可以尝试这样做：

```js
$(() => {
  $('div.label')
    .click((e) => {
      const $switcher = $(e.target).parent();
      const paraWidth = $('div.speech p').outerWidth();
      const switcherWidth = $switcher.outerWidth();

      $switcher
        .css('position', 'relative')
        .fadeTo('fast', 0.5)
        .animate(
          { left: paraWidth - switcherWidth },
          { duration: 'slow', queue: false }
        )
        .fadeTo('slow', 1.0)
        .slideUp('slow')
        .css('backgroundColor', '#f00')
        .slideDown('slow');
    }); 
}); 

```

列表 4.21

然而，尽管改变背景颜色的代码被放置在链中的正确位置，但它会立即在点击时发生。

我们可以使用名为`.queue()`的方法将非效果方法添加到队列中。以下是在我们的示例中的样子：

```js
$(() => {
  $('div.label')
    .click((e) => {
      const $switcher = $(e.target).parent();
      const paraWidth = $('div.speech p').outerWidth();
      const switcherWidth = $switcher.outerWidth();

      $switcher
        .css('position', 'relative')
        .fadeTo('fast', 0.5)
        .animate(
          { left: paraWidth - switcherWidth },
          { duration: 'slow', queue: false }
        )
        .fadeTo('slow', 1.0)
        .slideUp('slow')
        .queue((next) => {
          $switcher.css('backgroundColor', '#f00');
          next();
        })
        .slideDown('slow');
    }); 
}); 

```

列表 4.22

当即将执行一个回调函数时，`.queue()`方法将该函数添加到要对匹配元素执行的效果队列中。在函数内部，我们将背景颜色设置为红色，然后调用`next()`，这是一个作为参数传递给我们的回调函数的函数。包含这个`next()`函数调用允许动画队列从断点恢复，并用后续的`.slideDown('slow')`行完成链条。如果我们没有调用`next()`，动画将停止。

有关`.queue()`的更多信息和示例，请访问[`api.jquery.com/category/effects/`](http://api.jquery.com/category/effects/)。

当我们研究对多组元素进行效果处理时，我们将发现另一种在非效果方法中排队的方法。

# 处理多组元素

与单一元素不同，当我们对不同的元素集应用效果时，它们几乎同时发生。为了看到这些同时发生的效果，我们将把一个段落向下滑动，同时将另一个段落向上滑动。我们将处理我们示例文档中的第三段和第四段：

```js
<p>Fourscore and seven years ago our fathers brought forth 
   on this continent a new nation, conceived in liberty, 
   and dedicated to the proposition that all men are 
   created equal.</p> 
<p>Now we are engaged in a great civil war, testing whether 
   that nation, or any nation so conceived and so 
   dedicated, can long endure. We are met on a great 
   battlefield of that war. We have come to dedicate a 
   portion of that field as a final resting-place for those 
   who here gave their lives that the nation might live. It 
   is altogether fitting and proper that we should do this. 
   But, in a larger sense, we cannot dedicate, we cannot 
   consecrate, we cannot hallow, this ground.</p> 
<a href="#" class="more">read more</a> 
<p>The brave men, living and dead, who struggled here have 
   consecrated it, far above our poor power to add or 
   detract. The world will little note, nor long remember, 
   what we say here, but it can never forget what they did 
   here. It is for us the living, rather, to be dedicated 
   here to the unfinished work which they who fought here 
   have thus far so nobly advanced.</p> 
<p>It is rather for us to be here dedicated to the great 
   task remaining before us&mdash;that from these honored 
   dead we take increased devotion to that cause for which 
   they gave the last full measure of devotion&mdash;that 
   we here highly resolve that these dead shall not have 
   died in vain&mdash;that this nation, under God, shall 
   have a new birth of freedom and that government of the 
   people, by the people, for the people, shall not perish 
   from the earth.</p> 

```

为了帮助我们看到效果的发生过程，我们将给第三段添加 1 像素的边框，将第四段添加灰色背景。此外，在 DOM 准备就绪时，我们将隐藏第四段：

```js
$(() => {
  $('p')
    .eq(2)
    .css('border', '1px solid #333');
  $('p')
    .eq(3)
    .css('backgroundColor', '#ccc')
    .hide(); 
}); 

```

列表 4.23

我们的示例文档现在显示了开头段落，然后是阅读更多链接和有边框的段落：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_04_11.png)

最后，我们将在第三段应用一个`click`处理程序，这样当单击它时，第三段将向上滑动（最终滑出视野），而第四段将向下滑动（并进入视野）：

```js
$(() => { 
  $('p')
    .eq(2)
    .css('border', '1px solid #333')
    .click((e) => {
      $(e.target)
        .slideUp('slow')
        .next()
        .slideDown('slow');
    });
  $('p')
    .eq(3)
    .css('backgroundColor', '#ccc')
    .hide();
}); 

```

列表 4.24

在滑动中截取这两个效果的屏幕截图证实它们的确是同时发生的：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_04_12.png)

第三段开始是可见的，正在向上滑动，与此同时第四段，开始是隐藏的，正在向下滑动。

# 使用回调函数排队

为了允许在不同元素上排队效果，jQuery 为每个效果方法提供了一个回调函数。正如我们在事件处理程序和`.queue()`方法中所看到的，回调函数只是作为方法参数传递的函数。至于效果，它们出现在方法的最后一个参数中。

如果我们使用一个回调将这两个滑动效果排队，我们可以让第四段在第三段之前滑下来。让我们先尝试将`.slideUp()`调用移到`.slideDown()`方法的完成回调中：

```js
$(() => { 
  $('p')
    .eq(2)
    .css('border', '1px solid #333')
    .click((e) => {
      $(e.target)
        .next()
        .slideDown('slow', () => {
          $(e.target).slideUp('slow');
        });
    });
  $('p')
    .eq(3)
    .css('backgroundColor', '#ccc')
    .hide();
}); 

```

列表 4.25

如果我们决定在`click()`回调函数和`slideDown()`回调函数中都使用`$(this)`，事情将不会按预期进行。因为`this`是有上下文的。相反，我们可以完全避免它，并引用`$(e.target)`来获取我们需要的`<p>`元素。

这一次，在效果进行一半的快照中，第三段和第四段都是可见的；第四段已经滑动下来，第三段即将开始滑动上去：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_04_13.png)

现在我们已经讨论了回调函数，我们可以返回到*清单 4.22*中的代码，其中我们在一系列效果的最后排队更改了背景颜色。与当时所做的一样，我们可以简单地使用回调函数，而不是使用`.queue()`方法：

```js
$(() => {
  $('div.label')
    .click((e) => {
      const $switcher = $(e.target).parent();
      const paraWidth = $('div.speech p').outerWidth();
      const switcherWidth = $switcher.outerWidth();

      $switcher
        .css('position', 'relative')
        .fadeTo('fast', 0.5)
        .animate(
          { left: paraWidth - switcherWidth },
          { duration: 'slow', queue: false }
        )
        .fadeTo('slow', 1.0)
        .slideUp('slow', () => {
          $switcher.css('backgroundColor', '#f00');
        })
        .slideDown('slow');
    });
}); 

```

清单 4.26

再次说明，在`<div id="switcher">`滑动上升之后和滑动回落之前，背景色会变为红色。请注意，当使用效果的完成回调而不是`.queue()`时，我们不需要担心在回调中调用`next()`。

# 简而言之

考虑到应用效果时的各种变化，记住效果是同时还是顺序发生可能变得困难。简要的大纲可能会有所帮助。

单一元素集上的效果是：

+   将多个属性同时应用于单个`.animate()`方法时

+   在方法链中应用时排队，除非将 `queue` 选项设置为 `false`

多个元素集上的效果是：

+   默认情况下同时进行

+   在另一个效果的回调中应用时或者在`.queue()`方法的回调中应用时排队

# 摘要

使用本章中探讨的效果方法，我们现在应该能够从 JavaScript 修改内联样式属性，将预包装的 jQuery 效果应用于元素，并创建我们自己的自定义动画。特别是，您学会了如何逐步增加和减小文本大小，使用`.css()` 或 `.animate()` 方法，通过修改多个属性逐渐隐藏和显示页面元素，以及如何以多种方式动画元素（同时或顺序）。

在本书的前四章中，我们的所有示例都涉及到操纵硬编码到页面 HTML 中的元素。在第五章，*操作 DOM* 中，我们将探讨直接操作 DOM 的方法，包括使用 jQuery 创建新元素并将其插入到我们选择的 DOM 中。

# 进一步阅读

动画主题将在第十一章，*高级效果* 中详细探讨。本书附录 B 中提供了完整的效果和样式方法列表，或者在官方 jQuery 文档[`api.jquery.com/`](http://api.jquery.com/) 中提供。

# 练习

挑战练习可能需要使用官方 jQuery 文档[`api.jquery.com/`](http://api.jquery.com/)：

1.  修改样式表以最初隐藏页面内容。当页面加载时，逐渐淡入内容。

1.  只有当鼠标悬停在段落上时，才给每个段落添加黄色背景。

1.  点击标题`(<h2>)`，同时将其淡出至 25%的不透明度，并将其左边距增加到`20px`。然后，当此动画完成时，将演讲文本淡出至 50%的不透明度。

1.  这里有一个挑战给你。通过平滑地移动开关框，对箭头键的按键作出反应，向相应方向移动 20 像素。箭头键的键码分别为：`37`（左）、`38`（上）、`39`（右）和`40`（下）。


# 第五章：操纵 DOM

Web 经验是 Web 服务器和 Web 浏览器之间的合作伙伴关系。传统上，生成可供浏览器使用的 HTML 文档一直是服务器的职责。我们在本书中看到的技术略微改变了这种安排，使用 CSS 技术实时改变 HTML 文档的外观。但要真正发挥我们的 JavaScript 实力，你需要学会修改文档本身。

在本章中，我们将涵盖：

+   使用**文档对象模型**（**DOM**）提供的接口修改文档

+   在页面上创建元素和文本

+   移动或删除元素

+   通过添加、删除或修改属性和属性，转换文档

# 操纵属性和属性

在本书的前四章中，我们一直在使用`.addClass()`和`.removeClass()`方法来演示如何在页面上更改元素的外观。尽管我们非正式地讨论了这些方法，提到了操纵`class`属性，但 jQuery 实际上修改了一个名为`className`的 DOM 属性。`.addClass()`方法创建或添加到该属性，而`.removeClass()`删除或缩短它。再加上`.toggleClass()`方法，它在添加和删除类名之间切换，我们就有了一种高效而健壮的处理类的方式。这些方法特别有帮助，因为它们在元素上添加类时避免了添加已经存在的类（所以我们不会得到`<div class="first first">`，例如），并且正确处理应用于单个元素的多个类的情况，例如`<div class="first second">`。

# 非类属性

我们可能需要不时访问或更改其他几个属性或属性。对于操纵诸如`id`、`rel`和`href`之类的属性，jQuery 提供了`.attr()`和`.removeAttr()`方法。这些方法使更改属性变得简单。此外，jQuery 还允许我们一次修改多个属性，类似于我们使用`.css()`方法在第四章*样式和动画*中处理多个 CSS 属性的方式。

例如，我们可以轻松地一次设置链接的`id`、`rel`和`title`属性。让我们从一些示例 HTML 开始：

```js
<h1 id="f-title">Flatland: A Romance of Many Dimensions</h1> 
<div id="f-author">by Edwin A. Abbott</div> 
<h2>Part 1, Section 3</h2> 
<h3 id="f-subtitle"> 
   Concerning the Inhabitants of Flatland 
</h3> 
<div id="excerpt">an excerpt</div> 
<div class="chapter"> 
  <p class="square">Our Professional Men and Gentlemen are 
    Squares (to which class I myself belong) and Five-Sided  
    Figures or <a  
    href="http://en.wikipedia.org/wiki/Pentagon">Pentagons 
    </a>. 
  </p> 
  <p class="nobility hexagon">Next above these come the  
    Nobility, of whom there are several degrees, beginning at  
    Six-Sided Figures, or <a  
    href="http://en.wikipedia.org/wiki/Hexagon">Hexagons</a>,  
    and from thence rising in the number of their sides till  
    they receive the honourable title of <a  
    href="http://en.wikipedia.org/wiki/Polygon">Polygonal</a>,  
    or many-Sided. Finally when the number of the sides  
    becomes so numerous, and the sides themselves so small,  
    that the figure cannot be distinguished from a <a  
    href="http://en.wikipedia.org/wiki/Circle">circle</a>, he  
    is included in the Circular or Priestly order; and this is  
    the highest class of all. 
  </p> 
  <p><span class="pull-quote">It is a <span class="drop">Law  
    of Nature</span> with us that a male child shall have  
    <strong>one more side</strong> than his father</span>, so  
    that each generation shall rise (as a rule) one step in  
    the scale of development and nobility. Thus the son of a  
    Square is a Pentagon; the son of a Pentagon, a Hexagon;  
    and so on. 
  </p> 
<!-- . . . code continues . . . --> 
</div> 

```

获取示例代码

您可以从以下 GitHub 存储库访问示例代码：[`github.com/PacktPublishing/Learning-jQuery-3`](https://github.com/PacktPublishing/Learning-jQuery-3)。

现在，我们可以迭代`<div class="chapter">`内的每个链接，并逐个应用属性。如果我们需要为所有链接设置单个属性值，我们可以在我们的`$(() => {})`处理程序中用一行代码完成：

```js
$(() => {
  $('div.chapter a').attr({ rel: 'external' });
});

```

列表 5.1

就像`.css()`方法一样，`.attr()`也可以接受一对参数，第一个指定属性名，第二个是其新值。不过，更典型的是，我们提供一个键值对的对象，就像在 *清单 5.1* 中所做的那样。以下语法允许我们轻松地扩展我们的示例以一次修改多个属性：

```js
$(() => {
  $('div.chapter a')
    .attr({
      rel: 'external',
      title: 'Learn more at Wikipedia'
    });
});

```

清单 5.2

# 值回调

将一个简单对象传递给`.attr()`是一个直接的技巧，当我们希望每个匹配的元素具有相同的值时，它就足够了。然而，通常情况下，我们添加或更改的属性必须每次具有不同的值。一个常见的例子是，对于任何给定的文档，如果我们希望我们的 JavaScript 代码表现可预测，那么每个`id`值必须是唯一的。为每个链接设置唯一的`id`值，我们可以利用 jQuery 方法的另一个特性，如`.css()`和`.each()`--**值回调**。

值回调只是一个提供给参数的函数，而不是值。然后，对匹配集合中的每个元素调用此函数一次。从函数返回的任何数据都将用作属性的新值。例如，我们可以使用以下技术为每个元素生成不同的`id`值：

```js
$(() => {
  $('div.chapter a')
    .attr({
      rel: 'external',
      title: 'Learn more at Wikipedia',
      id: index => `wikilink-${index}`
    });
});

```

清单 5.3

每次调用我们的值回调时，都会传递一个整数，指示迭代计数；在这里，我们正在使用它为第一个链接赋予一个`id`值`wikilink-0`，第二个`wikilink-1`，依此类推。

我们正在使用`title`属性邀请人们在维基百科了解更多有关链接术语的信息。到目前为止，我们使用的 HTML 标签中，所有链接都指向维基百科。但是，为了考虑到其他类型的链接，我们应该使选择器表达式更具体一些：

```js
$(() => {
  $('div.chapter a[href*="wikipedia"]')
    .attr({
      rel: 'external',
      title: 'Learn more at Wikipedia',
      id: index => `wikilink-${index}`
    });
});

```

清单 5.4

要完成我们对`.attr()`方法的介绍，我们将增强这些链接的`title`属性，使其更具体地描述链接目标。再次，值回调是完成工作的正确工具：

```js
$(() => {
  $('div.chapter a[href*="wikipedia"]')
    .attr({
      rel: 'external',
      title: function() {
        return `Learn more about ${$(this).text()} at Wikipedia.`;
      },
      id: index => `wikilink-${index}`
    });
});

```

清单 5.5

这次我们利用了值回调的上下文。就像事件处理程序一样，关键字`this`每次调用回调时都指向我们正在操作的 DOM 元素。在这里，我们将元素包装在一个 jQuery 对象中，以便我们可以使用`.text()`方法（在第四章中介绍的 *Styling and Animating*）来检索链接的文本内容。这使得每个链接标题与其他链接不同，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_05_01.png)

# 数据属性

HTML5 数据属性允许我们将任意数据值附加到页面元素。然后，我们的 jQuery 代码可以使用这些值，以及修改它们。使用数据属性的原因是我们可以将控制它们的显示和行为的 DOM 属性与特定于我们的应用程序的数据分开。

使用`data()` jQuery 方法来读取数据值并更改数据值。让我们添加一些新功能，允许用户通过点击来标记段落为已读。我们还需要一个复选框，用于隐藏已标记为已读的段落。我们将使用数据属性来帮助我们记住哪些段落已标记为已读：

```js
$(() => {
  $('#hide-read')
    .change((e) => {
      if ($(e.target).is(':checked')) {
        $('.chapter p')
          .filter((i, p) => $(p).data('read'))
          .hide();
      } else {
        $('.chapter p').show();
      }
    });

  $('.chapter p')
    .click((e) => {
      const $elm = $(e.target);

      $elm
        .css(
          'textDecoration',
          $elm.data('read') ? 'none' : 'line-through'
        )
        .data('read', !$(e.target).data('read'));
    });
});

```

列表 5.6

当您单击段落时，文本将被标记为已读：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/Screen-Shot-2017-01-08-at-12.21.23-PM.png)

正如您所看到的，点击事件处理程序在段落被点击时改变其视觉外观。但处理程序还做了其他事情--它切换了元素的`read`数据：`data('read', !$(e.target).data('read'))`。这让我们能够以一种不干扰我们可能设置的其他 HTML 属性的方式将应用程序特定的数据与元素绑定。

隐藏已读段落复选框的更改处理程序寻找具有此数据的段落。`filter((i, p) => $(p).data('read'))`调用只会返回具有值为`true`的`read`数据属性的段落。我们现在能够根据特定的应用程序数据来过滤元素。以下是隐藏已读段落后页面的外观：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/Screen-Shot-2017-01-08-at-12.33.01-PM.png)

我们将在本书的后期重新讨论一些使用 jQuery 处理数据的高级用法。

# DOM 元素属性

正如前面提到的，HTML **属性** 和 DOM **属性** 之间存在微妙的区别。属性是页面 HTML 源代码中用引号括起来的值，而属性是 JavaScript 访问时的值。我们可以在 Chrome 等开发者工具中轻松观察属性和属性：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/Screen-Shot-2017-01-08-at-5.29.42-PM.png)

Chrome 开发者工具的元素检查器向我们展示了高亮显示的`<p>`元素具有名为`class`的属性，其值为`square`。在右侧面板中，我们可以看到该元素具有一个名为`className`的对应属性，其值为`square`。这说明了属性及其等效属性具有不同名称的情况之一。

在大多数情况下，属性和属性在功能上是可以互换的，并且 jQuery 会为我们处理命名不一致性。然而，有时我们确实需要注意两者之间的区别。一些 DOM 属性，如`nodeName`，`nodeType`，`selectedIndex`和`childNodes`，没有等效的属性，因此无法通过`.attr()`访问。此外，数据类型可能不同：例如，`checked`属性具有字符串值，而`checked`属性具有布尔值。对于这些布尔属性，最好测试和设置*属性*而不是*属性*，以确保跨浏览器行为的一致性。

我们可以使用`.prop()`方法从 jQuery 获取和设置属性：

```js
// Get the current value of the "checked" property 
const currentlyChecked = $('.my-checkbox').prop('checked'); 

// Set a new value for the "checked" property 
$('.my-checkbox').prop('checked', false); 

```

`.prop()`方法具有与`.attr()`相同的所有功能，例如接受一次设置多个值的对象和接受值回调函数。

# 表单控件的值

在尝试获取或设置表单控件的值时，属性和属性之间最麻烦的差异也许就是最为令人头疼的。对于文本输入，`value`属性等同于`defaultValue`属性，而不是`value`属性。对于`select`元素，通常通过元素的`selectedIndex`属性或其`option`元素的`selected`属性来获取值。

由于这些差异，我们应该避免使用`.attr()`——在`select`元素的情况下，甚至避免使用`.prop()`——来获取或设置表单元素的值。相反，我们可以使用 jQuery 为这些场合提供的`.val()`方法：

```js
// Get the current value of a text input 
const inputValue = $('#my-input').val(); 
// Get the current value of a select list 
const selectValue = $('#my-select').val(); 
//Set the value of a single select list 
$('#my-single-select').val('value3'); 
// Set the value of a multiple select list 
$('#my-multi-select').val(['value1', 'value2']); 

```

与`.attr()`和`.prop()`一样，`.val()`方法可以接受一个函数作为其设置器参数。借助其多功能的`.val()`方法，jQuery 再次让 Web 开发变得更加容易。

# DOM 树操作

`.attr()`和`.prop()`方法是非常强大的工具，借助它们，我们可以对文档进行有针对性的更改。尽管如此，我们仍然没有看到如何更改文档的整体结构。要真正操作 DOM 树，你需要更多地了解位于`jQuery`库核心的函数。

# `$()`函数再探讨

从本书的开头，我们一直在使用`$()`函数来访问文档中的元素。正如我们所见，这个函数充当了一个工厂的角色，产生了指向由 CSS 选择器描述的元素的新的 jQuery 对象。

`$()`函数的功能远不止于此。它还可以改变页面的内容。只需将一小段 HTML 代码传递给函数，我们就可以创建一个全新的 DOM 结构。

辅助功能提醒

我们应该再次牢记，将某些功能、视觉吸引力或文本信息仅提供给那些能够（并启用了）使用 JavaScript 的 Web 浏览器的人，存在固有的危险。重要信息应该对所有人可访问，而不仅仅是那些使用正确软件的人。

# 创建新元素

常见于 FAQ 页面的功能之一是在每个问题和答案对之后显示返回顶部链接。可以说这些链接没有任何语义作用，因此它们可以通过 JavaScript 合法地作为页面访问者子集的增强功能。在我们的示例中，我们将在每个段落后面添加一个返回顶部链接，以及返回顶部链接将指向的锚点。首先，我们简单地创建新元素：

```js
$(() => {
  $('<a href="#top">back to top</a>'); 
  $('<a id="top"></a>'); 
}); 

```

列表 5.7

我们在第一行代码中创建了一个返回顶部链接，在第二行创建了链接的目标锚点。然而，页面上还没有出现返回顶部的链接。

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_05_05.png)

虽然我们编写的两行代码确实创建了元素，但它们还没有将元素添加到页面上。我们需要告诉浏览器这些新元素应该放在哪里。为此，我们可以使用众多 jQuery **插入方法**之一。

# 插入新元素

`jQuery` 库有许多可用于将元素插入文档的方法。每个方法都规定了新内容与现有内容的关系。例如，我们希望我们的返回顶部链接出现在每个段落后面，因此我们将使用适当命名的 `.insertAfter()` 方法来实现这一点：

```js
$(() => { 
  $('<a href="#top">back to top</a>')
    .insertAfter('div.chapter p'); 
  $('<a id="top"></a>'); 
}); 

```

列表 5.8

因此，现在我们实际上已经将链接插入到页面中（并插入到 DOM 中），它们将出现在 `<div class="chapter">` 中的每个段落之后：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_05_06.png)

请注意，新链接出现在自己的一行上，而不是在段落内部。这是因为 `.insertAfter()` 方法及其对应的 `.insertBefore()` 方法会在指定元素*外部*添加内容。

不幸的是，链接还不能使用。我们仍然需要插入带有 `id="top"` 的锚点。这一次，我们将使用一个在其他元素*内部*插入元素的方法：

```js
$(() => { 
  $('<a href="#top">back to top</a>')
    .insertAfter('div.chapter p'); 
  $('<a id="top"></a>')
    .prependTo('body'); 
}); 

```

列表 5.9

这段额外的代码将锚点插入在 `<body>` 标签的开头；换句话说，位于页面顶部。现在，使用链接的 `.insertAfter()` 方法和锚点的 `.prependTo()` 方法，我们有了一个完全功能的返回顶部链接集合。

一旦我们添加了相应的 `.appendTo()` 方法，我们现在就有了一个完整的选项集，用于在其他元素之前和之后插入新元素：

+   `.insertBefore()`: 在现有元素之外并且在其*前面*添加内容

+   `.prependTo()`: 在现有元素之内并且在其*前面*添加内容

+   `.appendTo()`: 在现有元素之内并且在其*后面*添加内容

+   `.insertAfter()`: 在现有元素之外并且在其*后面*添加内容

# 移动元素

在添加返回顶部链接时，我们创建了新的元素并将它们插入到页面中。还可以将页面上的元素从一个地方移动到另一个地方。这种插入的实际应用是动态放置和格式化脚注。一个脚注已经出现在我们用于此示例的原始 *Flatland* 文本中，但为了演示目的，我们还将指定文本的另外几部分作为脚注：

```js
<p>How admirable is the Law of Compensation! <span     
   class="footnote">And how perfect a proof of the natural  
   fitness and, I may almost say, the divine origin of the  
   aristocratic constitution of the States of Flatland!</span> 
   By a judicious use of this Law of Nature, the Polygons and  
   Circles are almost always able to stifle sedition in its  
   very cradle, taking advantage of the irrepressible and  
   boundless hopefulness of the human mind.&hellip; 
</p> 

```

我们的 HTML 文档包含三个脚注；上一个段落包含一个示例。脚注文本位于段落文本内部，使用 `<span class="footnote"></span>` 进行分隔。通过以这种方式标记 HTML 文档，我们可以保留脚注的上下文。样式表中应用的 CSS 规则使脚注变为斜体，因此受影响的段落最初看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_05_07.png)

现在，我们需要抓取脚注并将它们移动到文档底部。具体来说，我们将它们插入在`<div class="chapter">`和`<div id="footer">`之间。

请记住，即使在隐式迭代的情况下，处理元素的顺序也是精确定义的，从 DOM 树的顶部开始并向下工作。由于在页面上保持脚注的正确顺序很重要，我们应该使用`.insertBefore('#footer')`。这将使每个脚注直接放在`<div id="footer">`元素之前，以便第一个脚注放在`<div class="chapter">`和`<div id="footer">`之间，第二个脚注放在第一个脚注和`<div id="footer">`之间，依此类推。另一方面，使用`.insertAfter('div.chapter')`会导致脚注以相反的顺序出现。

到目前为止，我们的代码看起来像下面这样：

```js
$(() => { 
  $('span.footnote').insertBefore('#footer'); 
}); 

```

图 5.10

脚注位于`<span>`标签中，默认情况下显示为内联，一个紧挨着另一个，没有分隔。但是，我们在 CSS 中已经预料到了这一点，在`span.footnote`元素处于`<div class="chapter">`之外时，给予了`display`值为`block`。因此，脚注现在开始成形：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_05_08.png)

现在，脚注已经位于正确的位置，但是仍然有很多工作可以做。一个更健壮的脚注解决方案应该执行以下操作：

1.  对每个脚注编号。

1.  使用脚注的编号标记从文本中提取每个脚注的位置。

1.  从文本位置创建到其匹配脚注的链接，并从脚注返回到从文本中提取每个脚注的位置，使用脚注的编号。

# 包装元素

为了给脚注编号，我们可以在标记中显式添加数字，但是在这里我们可以利用标准的有序列表元素，它会为我们自动编号。为此，我们需要创建一个包含所有脚注的`<ol>`元素和一个单独包含每个脚注的`<li>`元素。为了实现这一点，我们将使用**包装方法**。

在将元素包装在另一个元素中时，我们需要明确我们是想让每个元素都包装在自己的容器中，还是所有元素都包装在一个单一的容器中。对于我们的脚注编号，我们需要两种类型的包装器：

```js
$(() => {
  $('span.footnote') 
    .insertBefore('#footer') 
    .wrapAll('<ol id="notes"></ol>') 
    .wrap('<li></li>'); 
}); 

```

图 5.11

一旦我们在页脚之前插入了脚注，我们就使用`.wrapAll()`将整个集合包装在一个单独的`<ol>`元素内。然后，我们继续使用`.wrap()`将每个单独的脚注包装在其自己的`<li>`元素内。我们可以看到这样创建了正确编号的脚注：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_05_09.png)

现在，我们已经准备好标记并编号我们提取脚注的位置。为了以简单直接的方式做到这一点，我们需要重写我们现有的代码，使其不依赖于隐式迭代。

# 显式迭代

`.each()`方法充当**显式迭代器**，与最近添加到 JavaScript 语言中的`forEach`数组迭代器非常相似。当我们想要对匹配的每个元素使用的代码过于复杂时，可以使用`.each()`方法。它接受一个回调函数，该函数将对匹配集合中的每个元素调用一次。

```js
$(() => { 
  const $notes = $('<ol id="notes"></ol>')
    .insertBefore('#footer');

  $('span.footnote')
    .each((i, span) => {
      $(span)
        .appendTo($notes)
        .wrap('<li></li>');
    });
}); 

```

**清单 5.12**

我们这里的更改动机很快就会变得清晰。首先，我们需要了解传递给我们的`.each()`回调的信息。

在*清单 5.12*中，我们使用`span`参数创建一个指向单个脚注`<span>`的 jQuery 对象，然后将该元素追加到脚注 `<ol>` 中，最后将脚注包装在一个 `<li>` 元素中。

为了标记从中提取脚注的文本位置，我们可以利用`.each()`回调的参数。该参数提供了迭代计数，从`0`开始，并在每次调用回调时递增。因此，该计数器始终比脚注的数量少 1。在生成文本中的适当标签时，我们将考虑到这一事实：

```js
$(() => { 
  const $notes = $('<ol id="notes"></ol>')
    .insertBefore('#footer');

  $('span.footnote')
    .each((i, span) => {
      $(`<sup>${i + 1}</sup>`)
        .insertBefore(span);
      $(span)
        .appendTo($notes)
        .wrap('<li></li>');
    });
}); 

```

**清单 5.13**

现在，在每个脚注被从文本中取出并放置在页面底部之前，我们创建一个包含脚注编号的新 `<sup>` 元素，并将其插入到文本中。这里的操作顺序很重要；我们需要确保标记被插入到移动脚注之前，否则我们将丢失其初始位置的追踪。

再次查看我们的页面，现在我们可以看到脚注标记出现在原来的内联脚注位置上：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_05_10.png)

# 使用反向插入方法

在*清单 5.13*中，我们在一个元素之前插入内容，然后将该元素追加到文档的另一个位置。通常，在 jQuery 中处理元素时，我们可以使用链式操作来简洁高效地执行多个操作。但是在这里，我们无法做到这一点，因为`this`是`.insertBefore()`的*目标*，同时也是`.appendTo()`的*主语*。**反向插入方法**将帮助我们克服这个限制。

每个插入方法，如`.insertBefore()`或`.appendTo()`，都有一个对应的反向方法。反向方法执行的任务与标准方法完全相同，但主语和目标被颠倒了。例如：

```js
$('<p>Hello</p>').appendTo('#container'); 

```

与下面相同：

```js
$('#container').append('<p>Hello</p>'); 

```

使用`.before()`，即`.insertBefore()`的反向形式，现在我们可以重构我们的代码以利用链式操作：

```js
$(() => {
  const $notes = $('<ol id="notes"></ol>')
    .insertBefore('#footer');

  $('span.footnote')
    .each((i, span) => {
      $(span)
        .before(`<sup>${i + 1}</sup>`)
        .appendTo($notes)
        .wrap('<li></li>');
    });
}); 

```

**清单 5.14**

插入方法回调

反向插入方法可以接受一个函数作为参数，就像`.attr()`和`.css()`一样。这个函数会针对每个目标元素调用一次，并且应返回要插入的 HTML 字符串。我们可以在这里使用这种技术，但由于我们将遇到每个脚注的几种这样的情况，因此单个的`.each()`调用最终将成为更清晰的解决方案。

现在我们准备处理我们清单中的最后一步：为文本位置创建到相应脚注的链接，以及从脚注返回到文本位置。为了实现这一点，我们需要每个脚注四个标记：在文本中和脚注之后各一个链接，以及在相同位置的两个`id`属性。因为`.before()`方法的参数即将变得复杂，这是一个引入新的字符串创建的好时机。

在*清单 5.14* 中，我们使用**模板字符串**准备了我们的脚注标记。这是一种非常有用的技术，但是当连接大量字符串时，它可能开始显得混乱。相反，我们可以使用数组方法`.join()`来构建更大的字符串。以下语句具有相同的效果：

```js
var str = 'a' + 'b' + 'c'; 
var str = `${'a'}${'b'}${'c'}`;
var str = ['a', 'b', 'c'].join(''); 

```

尽管在这个例子中需要输入更多的字符，但`.join()`方法可以在原本难以阅读的字符串连接或字符串模板时提供清晰度。让我们再次看一下我们的代码，这次使用`.join()`来创建字符串：

```js
$(() => { 
  const $notes = $('<ol id="notes"></ol>')
    .insertBefore('#footer');

  $('span.footnote')
    .each((i, span) => {
      $(span)
        .before([
          '<sup>',
          i + 1,
          '</sup>'
        ].join(''))
        .appendTo($notes)
        .wrap('<li></li>');
    }); 
}); 

```

项目清单 5.15

使用这种技术，我们可以为脚注标记增加一个到页面底部的链接，以及一个唯一的`id`值。一边做这些，我们还将为`<li>`元素添加一个`id`，这样链接就有了一个目标，如下面的代码片段所示：

```js
$(() => { 
  const $notes = $('<ol id="notes"></ol>')
    .insertBefore('#footer');

  $('span.footnote')
    .each((i, span) => {
      $(span)
        .before([
          '<a href="#footnote-',
          i + 1,
          '" id="context-',
          i + 1,
          '" class="context">',
          '<sup>',
          i + 1,
          '</sup></a>'
        ].join(''))
        .appendTo($notes)
        .wrap('<li></li>');
    }); 
}); 

```

项目清单 5.16

在额外的标记放置后，每个脚注标记现在都链接到文档底部的对应脚注。 现在唯一剩下的就是创建一个从脚注返回到其上下文的链接。为此，我们可以使用`.appendTo()`方法的反向，即`.append()`:

```js
$(() => {
  const $notes = $('<ol id="notes"></ol>')
    .insertBefore('#footer');

  $('span.footnote')
    .each((i, span) => {
      $(span)
        .before([
          '<a href="#footnote-',
          i + 1,
          '" id="context-',
          i + 1,
          '" class="context">',
          '<sup>',
          i + 1,
          '</sup></a>'
        ].join(''))
        .appendTo($notes)
        .append([
          '&nbsp;(<a href="#context-',
          i + 1,
          '">context</a>)'
        ].join(''))
        .wrap('<li></li>');
    }); 
}); 

```

项目清单 5.17

请注意，`href`标签指向了对应标记的`id`值。在下面的屏幕截图中，您可以再次看到脚注，不同的是这次每个脚注后都附加了新链接：

![图片](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_05_11.png)

# 复制元素

到目前为止，在本章中，我们已经插入了新创建的元素，将元素从文档中的一个位置移动到另一个位置，并将新元素包裹在现有元素周围。但是，有时，我们可能想要复制元素。例如，出现在页面页眉中的导航菜单也可以复制并放置在页脚中。每当元素可以被复制以增强页面的视觉效果时，我们可以让 jQuery 承担繁重的工作。

对于复制元素，jQuery 的`.clone()`方法正是我们需要的；它接受任何匹配元素集并为以后使用创建它们的副本。就像我们前面在本章中探讨过的`$()`函数的元素创建过程一样，复制的元素在应用插入方法之前不会出现在文档中。

例如，下面的行创建了`<div class="chapter">`中第一个段落的副本：

```js
$('div.chapter p:eq(0)').clone(); 

```

光靠这些还不足以改变页面的内容。我们可以使克隆的段落出现在`<div class="chapter">`之前用插入方法：

```js
$('div.chapter p:eq(0)')
  .clone()
  .insertBefore('div.chapter'); 

```

这将导致第一个段落出现两次。因此，使用一个熟悉的类比，`.clone()` 与插入方法的关系就像 *复制* 与 *粘贴* 一样。

带事件的克隆

默认情况下，`.clone()` 方法不会复制绑定到匹配元素或其任何后代的任何事件。然而，它可以接受一个布尔参数（当设置为 true（`.clone(true)`）时），也会克隆事件。这种方便的事件克隆使我们避免了手动重新绑定事件，正如 第三章 中讨论的那样，*处理事件*。

# 用于引文的克隆

许多网站，就像它们的印刷对应物一样，使用 **引文** 来强调文本的小部分并吸引读者的注意。引文简单地是主文档的摘录，它以特殊的图形处理与文本一起呈现。我们可以通过 `.clone()` 方法轻松实现这种修饰。首先，让我们再次看一下示例文本的第三段：

```js
<p> 
  <span class="pull-quote">It is a Law of Nature  
  <span class="drop">with us</span> that a male child shall  
  have <strong>one more side</strong> than his father</span>,  
  so that each generation shall rise (as a rule) one step in  
  the scale of development and nobility. Thus the son of a  
  Square is a Pentagon; the son of a Pentagon, a Hexagon; and  
  so on. 
</p> 

```

注意段落以 `<span class="pull-quote">` 开始。这是我们将要复制的类。一旦在另一个位置粘贴了该 `<span>` 标签中的复制文本，我们就需要修改其样式属性以使其与其余文本区分开。

为了实现这种类型的样式，我们将在复制的 `<span>` 中添加一个 `pulled` 类。在我们的样式表中，该类接收以下样式规则：

```js
.pulled { 
  position: absolute; 
  width: 120px; 
  top: -20px; 
  right: -180px; 
  padding: 20px; 
  font: italic 1.2em "Times New Roman", Times, serif; 
  background: #e5e5e5; 
  border: 1px solid #999; 
  border-radius: 8px; 
  box-shadow: 1px 1px 8px rgba(0, 0, 0, 0.6); 
} 

```

具有此类的元素通过应用背景、边框、字体等样式规则在视觉上与主内容区分开来。最重要的是，它是绝对定位的，距离 DOM 中最近的（`absolute` 或 `relative`）定位的祖先元素的顶部 20 像素，并且向右偏移 20 像素。如果没有祖先元素应用了定位（除了 `static` 之外），引用的引用将相对于文档 `<body>` 定位。因此，在 jQuery 代码中，我们需要确保克隆的引文的父元素设置了 `position:relative`。

CSS 定位计算

尽管顶部定位相当直观，但可能一开始不清楚引文框将如何定位到其定位父级的右侧 20 像素。我们首先从引文框的总宽度推导数字，这是 `width` 属性的值加上左右填充的值，或 `145px + 5px + 10px = 160px`。然后，我们设置引文的 `right` 属性。一个值为 `0` 将使引文的右侧与其父元素的右侧对齐。因此，为了将其左侧定位到父元素的右侧 20 像素处，我们需要将其向负方向移动超过其总宽度的 20 像素，即 `-180px`。

现在，我们可以考虑应用此样式所需的 jQuery 代码。我们将从选择器表达式开始，找到所有 `<span class="pull-quote">` 元素，并像我们刚讨论的那样为每个父元素应用 `position: relative` 样式：

```js
$(() => {
  $('span.pull-quote')
    .each((i, span) => {
      $(span)
        .parent()
        .css('position', 'relative');
    });
}); 

```

列表 5.18

接下来，我们需要创建引用本身，利用我们准备好的 CSS。我们需要克隆每个 `<span>` 标签，将 `pulled` 类添加到副本，并将其插入到其父段落的开头：

```js
$(() => { 
  $('span.pull-quote')
    .each((i, span) => {
      $(span)
        .clone()
        .addClass('pulled')
        .prependTo(
          $(span)
            .parent()
            .css('position', 'relative')
        );
    });
}); 

```

列表 5.19

因为我们在引用处使用了绝对定位，所以它在段落中的位置是无关紧要的。只要它保持在段落内部，根据我们的 CSS 规则，它将相对于段落的顶部和右侧定位。

引用现在出现在其原始段落旁边，正如预期的那样：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_05_12.png)

这是一个不错的开始。对于我们的下一个改进，我们将稍微清理引用内容。

# 内容获取器和设置器方法

修改引用并使用省略号来保持内容简洁将是很好的。为了演示这一点，我们在示例文本中的几个单词中包裹了一个 `<span class="drop">` 标签。

完成此替换的最简单方法是直接指定要替换旧实体的新 HTML 实体。`.html()` 方法非常适合这个目的：

```js
$(() => { 
  $('span.pull-quote')
    .each((i, span) => {
      $(span)
        .clone()
        .addClass('pulled')
        .find('span.drop')
          .html('&hellip;')
          .end()
        .prependTo(
          $(span)
            .parent()
            .css('position', 'relative')
        );
    });
}); 

```

列表 5.20

*列表 5.20* 中的新行依赖于我们在[第二章](https://example.org/chapter_2)中学到的 DOM 遍历技巧，*选择元素*。我们使用 `.find()` 在引用中搜索任何 `<span class="drop">` 元素，对它们进行操作，然后通过调用 `.end()` 返回到引用本身。在这些方法之间，我们调用 `.html()` 将内容更改为省略号（使用适当的 HTML 实体）。

在没有参数的情况下调用 `.html()` 会返回匹配元素内的 HTML 实体的字符串表示。有了参数，元素的内容将被提供的 HTML 实体替换。当使用此技术时，我们必须小心只指定一个有效的 HTML 实体，并正确地转义特殊字符。

指定的单词现已被省略号替换：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_05_13.png)

引用通常不保留其原始字体格式，比如这个示例中的粗体文本。我们真正想显示的是 `<span class="pull-quote">` 的文本，不包含任何 `<strong>`、`<em>`、`<a href>` 或其他内联标签。为了将所有引用的 HTML 实体替换为剥离后的仅文本版本，我们可以使用 `.html()` 方法的伴随方法 `.text()`。

像 `.html()` 一样，`.text()` 方法可以检索匹配元素的内容或用新字符串替换其内容。但与 `.html()` 不同的是，`.text()` 总是获取或设置纯文本字符串。当 `.text()` 检索内容时，所有包含的标签都将被忽略，HTML 实体将被转换为普通字符。当它设置内容时，特殊字符如 `<` 将被转换为它们的 HTML 实体等价物：

```js
$(() => { 
  $('span.pull-quote')
    .each((i, span) => {
      $(span)
        .clone()
        .addClass('pulled')
        .find('span.drop')
          .html('&hellip;')
          .end()
        .text((i, text) => text)
        .prependTo(
          $(span)
            .parent()
            .css('position', 'relative')
        );
    });
}); 

```

列表 5.21

使用`text()`检索值时，会去除标记。这正是我们尝试实现的内容。与你目前学习的其他一些 jQuery 函数一样，`text()`接受一个函数。返回值用于设置元素的文本，而当前文本则作为第二个参数传入。因此，要从元素文本中删除标记，只需调用`text((i, text) => text)`。太棒了！

以下是这种方法的结果：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_05_14.png)

# DOM 操作方法简介

jQuery 提供的大量 DOM 操作方法根据任务和目标位置而异。我们在这里没有涵盖所有内容，但大多数都类似于我们已经见过的方法，更多内容将在第十二章，*高级 DOM 操作*中讨论。以下概要可作为我们可以使用哪种方法来完成哪种任务的提醒：

+   若要*从 HTML 中创建*新元素，请使用`$()`函数

+   若要*在*每个匹配元素*内部*插入新元素，请使用以下函数：

    +   `.append()`

    +   `.appendTo()`

    +   `.prepend()`

    +   `.prependTo()`

+   若要*在*每个匹配元素*旁边*插入新元素，请使用以下函数：

    +   `.after()`

    +   `.insertAfter()`

    +   `.before()`

    +   `.insertBefore()`

+   若要*在*每个匹配元素*周围*插入新元素，请使用以下函数：

    +   `.wrap()`

    +   `.wrapAll()`

    +   `.wrapInner()`

+   若要*用新元素或文本替换*每个匹配元素，请使用以下函数：

    +   `.html()`

    +   `.text()`

    +   `.replaceAll()`

    +   `.replaceWith()`

+   若要*在每个匹配元素内部删除*元素，请使用以下函数：

    +   `.empty()`

+   若要*删除*文档中*每个匹配元素及其后代*，而实际上不删除它们，请使用以下函数：

    +   `.remove()`

    +   `.detach()`

# 摘要

在本章中，我们使用 jQuery 的 DOM 修改方法创建、复制、重新组装和美化内容。我们将这些方法应用于单个网页，将一些通用段落转换为带有脚注、拉引用、链接和样式化的文学摘录。这一章向我们展示了使用 jQuery 添加、删除和重新排列页面内容是多么容易。此外，你已经学会了如何对页面元素的 CSS 和 DOM 属性进行任何想要的更改。

接下来，我们将通过 jQuery 的 Ajax 方法进行一次往返旅程到服务器。

# 进一步阅读

DOM 操作的主题将在第十二章，*高级 DOM 操作*中进行更详细的探讨。DOM 操作方法的完整列表可在本书的附录 B*，快速参考*，或在官方 jQuery 文档[`api.jquery.com/`](http://api.jquery.com/)中找到。

# 练习

挑战练习可能需要使用官方 jQuery 文档`http://api.jquery.com/`。

1.  改变引入回到顶部链接的代码，使得链接只在第四段后出现。

1.  当点击回到顶部链接时，在链接后添加一个新段落，其中包含消息“你已经在这里了”。确保链接仍然可用。

1.  当点击作者的名字时，将其加粗（通过添加元素，而不是操作类或 CSS 属性）。

1.  挑战：在对加粗的作者名字进行后续点击时，移除已添加的`<b>`元素（从而在加粗和正常文本之间切换）。

1.  挑战：对每个章节段落添加一个`inhabitants`类，而不调用`.addClass()`。确保保留任何现有的类。


# 第六章：使用 Ajax 发送数据

术语 **Asynchronous JavaScript and XML**（**Ajax**）是由 *Jesse James Garrett* 在 2005 年创造的。此后，它已经代表了许多不同的事物，因为该术语包含了一组相关的能力和技术。在其最基本的层次上，Ajax 解决方案包括以下技术：

+   **JavaScript**：用于捕获与用户或其他与浏览器相关的事件的交互，并解释来自服务器的数据并在页面上呈现它

+   **XMLHttpRequest**：这允许在不中断其他浏览器任务的情况下向服务器发出请求

+   **文本数据：** 服务器提供的数据格式可以是 XML、HTML 或 JSON 等。

Ajax 将静态**网页**转变为交互式**网络应用程序**。毫不奇怪，浏览器在实现`XMLHttpRequest`对象时并不完全一致，但 jQuery 会帮助我们。

在本章中，我们将涵盖：

+   在不刷新页面的情况下从服务器加载数据

+   从浏览器中的 JavaScript 发送数据回服务器

+   解释各种格式的数据，包括 HTML、XML 和 JSON

+   向用户提供有关 Ajax 请求状态的反馈

# 按需加载数据

Ajax 只是一种从服务器加载数据到网络浏览器中而无需刷新页面的方法。这些数据可以采用许多形式，而当数据到达时，我们有许多选项可以处理它。我们将通过使用不同的方法执行相同的基本任务来看到这一点。

我们将构建一个页面，显示按字典条目起始字母分组的条目。定义页面内容区域的 HTML 将如下所示：

```js
<div id="dictionary"> 
</div> 

```

我们的页面一开始没有内容。我们将使用 jQuery 的各种 Ajax 方法来填充这个 `<div>` 标记，以显示字典条目。

获取示例代码

您可以从以下 GitHub 仓库访问示例代码：[`github.com/PacktPublishing/Learning-jQuery-3`](https://github.com/PacktPublishing/Learning-jQuery-3)。

我们需要一种触发加载过程的方法，所以我们将添加一些链接供我们的事件处理程序依附：

```js
<div class="letters"> 
  <div class="letter" id="letter-a"> 
    <h3><a href="entries-a.html">A</a></h3> 
  </div> 
  <div class="letter" id="letter-b"> 
    <h3><a href="entries-a.html">B</a></h3> 
  </div> 
  <div class="letter" id="letter-c"> 
    <h3><a href="entries-a.html">C</a></h3> 
  </div> 
  <div class="letter" id="letter-d"> 
    <h3><a href="entries-a.html">D</a></h3> 
  </div> 
  <!-- and so on --> 
</div> 

```

这些简单的链接将带领我们到列出该字母字典条目的页面。我们将采用渐进式增强的方法，允许这些链接在不加载完整页面的情况下操作页面。应用基本样式后，这个 HTML 将产生如下页面：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_06_01.png)

现在，我们可以专注于将内容放到页面上。

# 追加 HTML

Ajax 应用程序通常不过是对一块 HTML 的请求。这种技术有时被称为 **Asynchronous HTTP and HTML**（**AHAH**），在 jQuery 中几乎很容易实现。首先，我们需要一些要插入的 HTML，我们将其放置在一个名为 `a.html` 的文件中，与我们的主文档一起。这个辅助 HTML 文件的开头如下：

```js
<div class="entry"> 
  <h3 class="term">ABDICATION</h3> 
  <div class="part">n.</div> 
  <div class="definition"> 
    An act whereby a sovereign attests his sense of the high 
    temperature of the throne. 
    <div class="quote"> 
      <div class="quote-line">Poor Isabella's Dead, whose 
      abdication</div> 
      <div class="quote-line">Set all tongues wagging in the 
      Spanish nation.</div> 
      <div class="quote-line">For that performance 'twere 
      unfair to scold her:</div> 
      <div class="quote-line">She wisely left a throne too 
      hot to hold her.</div> 
      <div class="quote-line">To History she'll be no royal 
      riddle &mdash;</div> 
      <div class="quote-line">Merely a plain parched pea that 
      jumped the griddle.</div> 
      <div class="quote-author">G.J.</div> 
    </div> 
  </div> 
</div> 

<div class="entry"> 
  <h3 class="term">ABSOLUTE</h3> 
  <div class="part">adj.</div> 
  <div class="definition"> 
    Independent, irresponsible.  An absolute monarchy is one 
    in which the sovereign does as he pleases so long as he 
    pleases the assassins.  Not many absolute monarchies are 
    left, most of them having been replaced by limited 
    monarchies, where the sovereign's power for evil (and for 
    good) is greatly curtailed, and by republics, which are 
    governed by chance. 
  </div> 
</div> 

```

页面继续以这种 HTML 结构的更多条目。单独渲染的话，`a.html` 看起来相当简单：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_06_02.png)

请注意，`a.html` 不是一个真正的 HTML 文档；它不包含 `<html>`、`<head>` 或 `<body>`，这些通常是必需的。我们通常将这样的文件称为*部分*或*片段*；它的唯一目的是被插入到另一个 HTML 文档中，我们现在将这样做：

```js
$(() => {
  $('#letter-a a')
    .click((e) => {
      e.preventDefault()

      $('#dictionary').load('a.html');
    });
});

```

第 6.1 节

`.load()` 方法为我们做了所有繁重的工作。我们使用普通的 jQuery 选择器指定 HTML 片段的目标位置，然后将要加载的文件的 URL 作为参数传递。现在，当单击第一个链接时，文件将被加载并放置在 `<div id="dictionary">` 内。一旦插入新的 HTML，浏览器就会渲染它：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_06_03.png)

注意 HTML 现在已经有样式了，而之前是原样呈现。这是由于主文档中的 CSS 规则；一旦插入新的 HTML 片段，规则也会应用于其元素。

在测试这个示例时，当单击按钮时，字典定义可能会立即出现。这是在本地工作应用程序时的一个危险；很难预测跨网络传输文档时的延迟或中断。假设我们添加一个警报框，在加载定义后显示：

```js
$(() => {
  $('#letter-a a')
    .click((e) => {
      e.preventDefault()

      $('#dictionary').load('a.html');
      alert('Loaded!');
    });
});

```

第 6.2 节

我们可能会从这段代码的结构中假设警报只能在执行加载后显示。JavaScript 的执行是**同步**的，严格按顺序一个任务接一个任务执行。

然而，当这段特定的代码在生产 Web 服务器上测试时，由于网络延迟，警报将在加载完成之前出现并消失。这是因为所有 Ajax 调用默认是**异步**的。异步加载意味着一旦发出检索 HTML 片段的 HTTP 请求，脚本执行立即恢复而不等待。稍后，浏览器收到来自服务器的响应并处理它。这是期望的行为；锁定整个 Web 浏览器等待数据检索是不友好的。

如果必须延迟动作直到加载完成，jQuery 为此提供了一个回调函数。我们已经在第四章中看到了回调，在*样式和动画*中使用它们在效果完成后执行操作。Ajax 回调执行类似的功能，在从服务器接收数据后执行。我们将在下一个示例中使用此功能，学习如何从服务器读取 JSON 数据。

# 处理 JavaScript 对象

根据需要按需获取完整形式的 HTML 非常方便，但这意味着必须传输有关 HTML 结构的大量信息以及实际内容。有时我们希望尽可能少地传输数据，并在数据到达后进行处理。在这种情况下，我们需要以 JavaScript 可以遍历的结构检索数据。

借助 jQuery 的选择器，我们可以遍历获取的 HTML 并对其进行操作，但原生 JavaScript 数据格式涉及的数据量较少，处理起来的代码也较少。

# 检索 JSON

正如我们经常看到的那样，JavaScript 对象只是一组键值对，并且可以用花括号（`{}`）简洁地定义。另一方面，JavaScript 数组是用方括号（`[]`）即时定义的，并且具有隐式键，即递增整数。结合这两个概念，我们可以轻松表达一些非常复杂和丰富的数据结构。

术语**JavaScript 对象表示法**（**JSON**）是由 *Douglas Crockford* 创造的，以利用这种简单的语法。这种表示法可以提供简洁的替代方法来替代臃肿的 XML 格式：

```js
{ 
  "key": "value", 
  "key 2": [ 
    "array", 
    "of", 
    "items" 
  ] 
} 

```

尽管基于 JavaScript 对象字面量和数组字面量，但 JSON 对其语法要求更具规范性，对其允许的值更具限制性。例如，JSON 指定所有对象键以及所有字符串值必须用双引号括起来。此外，函数不是有效的 JSON 值。由于其严格性，开发人员应避免手动编辑 JSON，而应依赖于诸如服务器端脚本之类的软件来正确格式化它。

有关 JSON 的语法要求、一些潜在优势以及它在许多编程语言中的实现的信息，请访问[`json.org/`](http://json.org/)。

我们可以以许多方式使用此格式对数据进行编码。为了说明一种方法，我们将一些字典条目放入一个名为 `b.json` 的 JSON 文件中：

```js
[ 
  { 
    "term": "BACCHUS", 
    "part": "n.", 
    "definition": "A convenient deity invented by the...", 
    "quote": [ 
      "Is public worship, then, a sin,", 
      "That for devotions paid to Bacchus", 
      "The lictors dare to run us in,", 
      "And resolutely thump and whack us?" 
    ], 
    "author": "Jorace" 
  }, 
  { 
    "term": "BACKBITE", 
    "part": "v.t.", 
    "definition": "To speak of a man as you find him when..." 
  }, 
  { 
    "term": "BEARD", 
    "part": "n.", 
    "definition": "The hair that is commonly cut off by..." 
  }, 
  ... file continues ... 

```

要检索此数据，我们将使用 `$.getJSON()` 方法，该方法获取文件并对其进行处理。当数据从服务器到达时，它只是一个 JSON 格式的文本字符串。`$.getJSON()` 方法解析此字符串并向调用代码提供生成的 JavaScript 对象。

# 使用全局 jQuery 函数

到目前为止，我们使用的所有 jQuery 方法都附加在我们用 `$()` 函数构建的 jQuery 对象上。选择器允许我们指定一组要处理的 DOM 节点，并且这些方法以某种方式对其进行操作。然而，`$.getJSON()` 函数是不同的。它没有逻辑 DOM 元素可以应用；结果对象必须提供给脚本，而不是注入到页面中。因此，`getJSON()` 被定义为全局 jQuery 对象的方法（由 `jQuery` 库一次定义的单个对象，称为 `jQuery` 或 `$`），而不是单个 jQuery 对象实例的方法（由 `$()` 函数返回的对象）。

如果 `$` 是一个类 `$.getJSON()` 将是一个类方法。对于我们的目的，我们将把这种类型的方法称为**全局函数**；实际上，它们是使用 `jQuery` 命名空间的函数，以避免与其他函数名称冲突。

要使用此函数，我们像以前一样将文件名传递给它：

```js
$(() => {
  $('#letter-b a')
    .click((e) => {
      e.preventDefault();
      $.getJSON('b.json');
    });
});

```

列表 6.3

当我们单击链接时，此代码似乎没有任何效果。函数调用加载文件，但我们还没有告诉 JavaScript 如何处理生成的数据。为此，我们需要使用回调函数。

`$.getJSON()` 函数接受第二个参数，这是在加载完成时调用的函数。如前所述，Ajax 调用是异步的，回调提供了一种等待数据传输完成而不是立即执行代码的方法。回调函数还接受一个参数，其中填充了生成的数据。所以，我们可以写：

```js
$(() => {
  $('#letter-b a')
    .click((e) => {
      e.preventDefault();
      $.getJSON('b.json', (data) => {});
    });
});

```

列表 6.4

在这个函数内部，我们可以使用 `data` 参数根据需要遍历 JSON 结构。我们需要迭代顶级数组，为每个项目构建 HTML。我们将使用数据数组的 `reduce()` 方法将其转换为 HTML 字符串，然后将其插入文档中。`reduce()` 方法接受一个函数作为参数，并为数组的每个项返回结果的一部分：

```js
$(() => {
  $('#letter-b a')
    .click((e) => {
      e.preventDefault();

        $.getJSON('b.json', (data) => {
          const html = data.reduce((result, entry) => `
            ${result}
            <div class="entry">
              <h3 class="term">${entry.term}</h3>
              <div class="part">${entry.part}</div>
              <div class="definition">
                ${entry.definition}
              </div>
            </div>
          `, '');

        $('#dictionary')
          .html(html);
    });
  });
});

```

列表 6.5

我们使用模板字符串来构建每个数组项的 HTML 内容。`result` 参数是上一个数组项的值。使用这种方法，通过字符串拼接，可以更容易地看到 HTML 结构。一旦为每个条目构建了所有的 HTML，我们就用 `.html()` 将其插入到 `<div id="dictionary">` 中，替换可能已经存在的任何内容。

安全的 HTML

这种方法假定数据对 HTML 消费是安全的；例如，它不应该包含任何杂乱的 `<` 字符。

唯一剩下的就是处理带引号的条目，我们可以通过实现一对使用 `reduce()` 技术构建字符串的辅助函数来完成：

```js
$(() => {
  const formatAuthor = entry =>
    entry.author ?
      `<div class="quote-author">${entry.author}</div>` :
      '';

  const formatQuote = entry =>
    entry.quote ?
      `
      <div class="quote">
        ${entry.quote.reduce((result, q) => `
          ${result}
          <div class="quote-line">${q}</div>
        `, '')}
        ${formatAuthor(entry)}
      </div>
      ` : '';

    $('#letter-b a')
      .click((e) => {
        e.preventDefault();

        $.getJSON('b.json', (data) => {
          const html = data.reduce((result, entry) => `
            ${result}
            <div class="entry">
              <h3 class="term">${entry.term}</h3>
              <div class="part">${entry.part}</div>
              <div class="definition">
                ${entry.definition}
                ${formatQuote(entry)}
              </div>
            </div>
          `, '');

          $('#dictionary')
            .html(html);
        });
      });
});

```

列表 6.6

有了这段代码，我们可以单击 B 链接并确认我们的结果。词典条目如预期的那样显示在页面的右侧：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_06_04.png)

JSON 格式简洁，但并不宽容。每个括号、大括号、引号和逗号必须存在且被计算在内，否则文件将无法加载。在某些情况下，我们甚至不会收到错误消息；脚本会悄无声息地失败。

# 执行脚本

有时，我们不希望在页面首次加载时检索到所有将需要的 JavaScript。在某些用户交互发生之前，我们可能不知道需要哪些脚本。我们可以在需要时动态引入 `<script>` 标签，但更加优雅的注入附加代码的方法是让 jQuery 直接加载 `.js` 文件。

拉取脚本与加载 HTML 片段一样简单。在这种情况下，我们使用 `$.getScript()` 函数，它——与其兄弟们一样——接受指向脚本文件的 URL：

```js
$(() => { 
  $('#letter-c a')
    .click((e) => {
      e.preventDefault();
      $.getScript('c.js');
    });
}); 

```

列表 6.7

在我们的最后一个示例中，我们需要处理结果数据，以便我们可以对加载的文件执行一些有用的操作。不过，对于脚本文件，处理是自动的；脚本只是简单地运行。

以这种方式获取的脚本在当前页面的全局上下文中运行。这意味着它们可以访问所有全局定义的函数和变量，特别是包括 jQuery 本身。因此，我们可以仿照 JSON 示例，在脚本执行时准备和插入 HTML 到页面上，并将此代码放在`c.js`中：

```js
const entries = [ 
  { 
    "term": "CALAMITY", 
    "part": "n.", 
    "definition": "A more than commonly plain and..." 
  }, 
  { 
    "term": "CANNIBAL", 
    "part": "n.", 
    "definition": "A gastronome of the old school who..." 
  }, 
  { 
    "term": "CHILDHOOD", 
    "part": "n.", 
    "definition": "The period of human life intermediate..." 
  } 
  // and so on 
]; 

const html = entries.reduce((result, entry) => `
  ${result}
  <div class="entry">
    <h3 class="term">${entry.term}</h3>
    <div class="part">${entry.part}</div>
    <div class="definition">
      ${entry.definition}
    </div>
  </div>
`, '');

$('#dictionary')
  .html(html); 

```

现在，点击 C 链接会得到预期的结果，显示相应的字典条目。

# 加载 XML 文档

XML 是 Ajax 首字母缩写的一部分，但我们实际上还没有加载任何 XML。这样做很简单，而且与 JSON 技术非常相似。首先，我们需要一个 XML 文件，`d.xml`，其中包含我们希望显示的一些数据：

```js
<?xml version="1.0" encoding="UTF-8"?> 
<entries> 
  <entry term="DEFAME" part="v.t."> 
    <definition> 
      To lie about another.  To tell the truth about another. 
    </definition> 
  </entry> 
  <entry term="DEFENCELESS" part="adj."> 
    <definition> 
      Unable to attack. 
    </definition> 
  </entry> 
  <entry term="DELUSION" part="n."> 
    <definition> 
      The father of a most respectable family, comprising 
      Enthusiasm, Affection, Self-denial, Faith, Hope, 
      Charity and many other goodly sons and daughters. 
    </definition> 
    <quote author="Mumfrey Mappel"> 
      <line>All hail, Delusion!  Were it not for thee</line> 
      <line>The world turned topsy-turvy we should see; 
        </line> 
      <line>For Vice, respectable with cleanly fancies, 
        </line> 
      <line>Would fly abandoned Virtue's gross advances. 
        </line> 
    </quote> 
  </entry> 
</entries> 

```

当然，这些数据可以用许多方式表达，有些方式更接近我们早期用于 HTML 或 JSON 的结构。然而，在这里，我们正在说明 XML 的一些特性，以使其对人类更加可读，例如使用`term`和`part`属性而不是标签。

我们将以熟悉的方式开始我们的函数：

```js
$(() => {
  $('#letter-d a')
    .click((e) => {
      e.preventDefault();
      $.get('d.xml', (data) => {

      });
    });
}); 

```

列表 6.8

这次，是`$.get()`函数完成了我们的工作。通常，此函数只是获取所提供 URL 的文件，并将纯文本提供给回调函数。但是，如果由于其服务器提供的 MIME 类型而已知响应为 XML，则回调函数将交给 XML DOM 树。

幸运的是，正如我们已经看到的，jQuery 具有实质性的 DOM 遍历功能。我们可以像在 HTML 上一样在 XML 文档上使用正常的`.find()`、`.filter()`和其他遍历方法：

```js
$(() => { 
  $('#letter-d a')
    .click((e) => {
      const formatAuthor = entry =>
        $(entry).attr('author') ?
          `
          <div class="quote-author">
            ${$(entry).attr('author')}
          </div>
          ` : '';

      const formatQuote = entry =>
        $(entry).find('quote').length ?
          `
          <div class="quote">
            ${$(entry)
              .find('quote')
              .get()
              .reduce((result, q) => `
                ${result}
                <div class="quote-line">
                  ${$(q).text()}
                </div>
              `, '')}
            ${formatAuthor(entry)}
          </div>
          ` : '';

      e.preventDefault();

      $.get('d.xml', (data) => {
        const html = $(data)
          .find('entry')
          .get()
          .reduce((result, entry) => `
            ${result}
            <div class="entry">
              <h3 class="term">${$(entry).attr('term')}</h3>
              <div class="part">${$(entry).attr('part')}</div>
              <div class="definition">
                ${$(entry).find('definition').text()}
                ${formatQuote(entry)}
              </div>
            </div>
          `, '');

        $('#dictionary')
          .html(html);
      });
    });
}); 

```

列表 6.9

当点击 D 链接时，这将产生预期的效果：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_06_05.png)

这是我们已经了解的 DOM 遍历方法的一种新用法，揭示了 jQuery 的 CSS 选择器支持的灵活性。CSS 语法通常用于帮助美化 HTML 页面，因此标准`.css`文件中的选择器使用 HTML 标签名称（如`div`和`body`）来定位内容。然而，jQuery 可以像标准 HTML 一样轻松地使用任意的 XML 标签名称，比如`entry`和`definition`。

jQuery 内部的高级选择器引擎使在更复杂的情况下找到 XML 文档的部分变得更加容易。例如，假设我们想将显示的条目限制为具有又带有作者的引用的条目。为此，我们可以通过将`entry`更改为`entry:has(quote)`来限制具有嵌套的`<quote>`元素的条目。然后，我们可以通过编写`entry:has(quote[author])`来进一步限制具有`<quote>`元素上的`author`属性的条目。现在，*列表 6.9* 中的带有初始选择器的行如下所示：

```js
$(data).find('entry:has(quote[author])').each(function() { 

```

这个新的选择器表达式相应地限制了返回的条目：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_06_06.png)

虽然我们可以在从服务器返回的 XML 数据上使用 jQuery，但缺点是我们的代码量已经显著增长。

# 选择数据格式

我们已经查看了四种用于外部数据的格式，每种格式都由 jQuery 的 Ajax 函数处理。我们还验证了所有四种格式都能够处理手头的任务，在用户请求时加载信息到现有页面上，并且在此之前不加载。那么，我们如何决定在我们的应用程序中使用哪种格式？

*HTML 片段* 需要非常少的工作来实现。可以使用一个简单的方法将外部数据加载并插入到页面中，甚至不需要回调函数。对于简单的任务，添加新的 HTML 到现有页面中不需要遍历数据。另一方面，数据的结构不一定适合其他应用程序重用。外部文件与其预期的容器紧密耦合。

*JSON 文件* 结构化简单，易于重用。它们紧凑且易于阅读。必须遍历数据结构以提取信息并在页面上呈现，但这可以通过标准 JavaScript 技术完成。由于现代浏览器可以通过单个调用`JSON.parse()`原生解析文件，读取 JSON 文件非常快速。JSON 文件中的错误可能导致静默失败，甚至在页面上产生副作用，因此数据必须由可信任的方进行精心制作。

*JavaScript 文件* 提供了最大的灵活性，但实际上并不是一种数据存储机制。由于文件是特定于语言的，因此无法用于向不同的系统提供相同的信息。相反，加载 JavaScript 文件的能力意味着很少需要的行为可以拆分到外部文件中，减少代码大小，直到需要为止。

尽管 *XML* 在 JavaScript 社区中已经不再受欢迎，大多数开发人员更喜欢 JSON，但它仍然如此普遍，以至于以此格式提供数据很可能使数据在其他地方得到重用。XML 格式有点臃肿，解析和操作速度可能比其他选项慢一些。

考虑到这些特点，通常最容易将外部数据提供为 HTML 片段，只要数据不需要在其他应用程序中使用。在数据将被重用但其他应用程序也可能受到影响的情况下，由于其性能和大小，JSON 通常是一个不错的选择。当远程应用程序未知时，XML 可能提供最大的保证，可以实现互操作性。

比起其他任何考虑因素，我们应确定数据是否已经可用。如果是，那么很可能最初就是以其中一种这种格式呈现的，因此决策可能已经为我们做出。

# 向服务器传递数据

到目前为止，我们的示例重点放在从 Web 服务器检索静态数据文件的任务上。但是，服务器可以根据来自浏览器的输入动态地塑造数据。在这项任务中，jQuery 也为我们提供了帮助；我们迄今为止介绍的所有方法都可以修改，以便数据传输变成双向街道。

与服务器端代码交互

由于演示这些技术需要与 Web 服务器进行交互，所以我们将在这里首次使用服务器端代码。给出的示例将使用 Node.js，它非常广泛使用并且免费提供。我们不会在这里涵盖任何 Node.js 或 Express 的具体内容，但是如果你搜索这两项技术，网络上有丰富的资源可供参考。

# 执行 GET 请求

为了说明客户端（使用 JavaScript）与服务器（同样使用 JavaScript）之间的通信，我们将编写一个脚本，每次请求只向浏览器发送一个词典条目。所选择的条目将取决于从浏览器发送的参数。我们的脚本将从类似于这样的内部数据结构中获取数据：

```js
const E_entries = {
  EAVESDROP: {
    part: 'v.i.',
    definition: 'Secretly to overhear a catalogue of the ' +
                'crimes and vices of another or yourself.',
    quote: [
      'A lady with one of her ears applied',
      'To an open keyhole heard, inside,',
      'Two female gossips in converse free &mdash;',
      'The subject engaging them was she.',
      '"I think," said one, "and my husband thinks',
      'That she's a prying, inquisitive minx!"',
      'As soon as no more of it she could hear',
      'The lady, indignant, removed her ear.',
      '"I will not stay," she said, with a pout,',
      '"To hear my character lied about!"',
    ],
    author: 'Gopete Sherany',
  },
  EDIBLE: {
    part:'adj.',
    definition: 'Good to eat, and wholesome to digest, as ' +
                'a worm to a toad, a toad to a snake, a snake ' +
                'to a pig, a pig to a man, and a man to a worm.',
  },
  // Etc...

```

在这个示例的生产版本中，数据可能会存储在数据库中，并根据需要加载。由于数据在这里是脚本的一部分，所以检索它的代码非常简单。我们检查 URL 的查询字符串部分，然后将术语和条目传递给一个返回 HTML 片段以显示的函数：

```js
const formatAuthor = entry =>
  entry.author ?
    `<div class="quote-author">${entry.author}</div>` :
    '';

const formatQuote = entry =>
  entry.quote ?
    `
    <div class="quote">
      ${entry.quote.reduce((result, q) => `
        ${result}
        <div class="quote-line">${q}</div>
      `, '')}
      ${formatAuthor(entry)}
    </div>
    ` : '';

const formatEntry = (term, entry) => `
  <div class="entry">
    <h3 class="term">${term}</h3>
    <div class="part">${entry.part}</div>
    <div class="definition">
      ${entry.definition}
      ${formatQuote(entry)}
    </div>
  </div>
`;

app.use(express.static('./'));

app.get('/e', (req, res) => {
  const term = req.query.term.toUpperCase();
  const entry = E_entries[term];
  let content;

  if (entry) {
    content = formatEntry(term, entry);
  } else {
    content = '<div>Sorry, your term was not found.</div>';
  }

  res.send(content);
}); 

```

现在，对这个 `/e` 处理器的请求，将返回对应于在 GET 参数中发送的术语的 HTML 片段。例如，当使用 `/e?term=eavesdrop` 访问处理器时，我们会得到：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_06_07.png)

再次注意我们之前看到的 HTML 片段缺乏格式，因为尚未应用 CSS 规则。

由于我们正在展示数据如何传递到服务器，所以我们将使用不同的方法来请求条目，而不是迄今为止所依赖的孤立按钮。相反，我们将为每个术语呈现一个链接列表，并且点击任何一个链接都将加载相应的定义。我们将添加以下 HTML：

```js
<div class="letter" id="letter-e"> 
  <h3>E</h3> 
  <ul> 
    <li><a href="e?term=Eavesdrop">Eavesdrop</a></li> 
    <li><a href="e?term=Edible">Edible</a></li> 
    <li><a href="e?term=Education">Education</a></li> 
    <li><a href="e?term=Eloquence">Eloquence</a></li> 
    <li><a href="e?term=Elysium">Elysium</a></li> 
    <li><a href="e?term=Emancipation">Emancipation</a> 
      </li> 
    <li><a href="e?term=Emotion">Emotion</a></li> 
    <li><a href="e?term=Envelope">Envelope</a></li> 
    <li><a href="e?term=Envy">Envy</a></li> 
    <li><a href="e?term=Epitaph">Epitaph</a></li> 
    <li><a href="e?term=Evangelist">Evangelist</a></li> 
  </ul> 
</div> 

```

现在，我们需要让我们的前端 JavaScript 代码调用后端 JavaScript，并传递正确的参数。我们可以使用正常的 `.load()` 机制来做到这一点，直接将查询字符串附加到 URL 并使用类似于 `e?term=eavesdrop` 的地址获取数据。但是，我们可以让 jQuery 根据我们提供给 `$.get()` 函数的对象构造查询字符串：

```js
$(() => { 
  $('#letter-e a')
    .click((e) => {
      e.preventDefault();

      const requestData = {
        term: $(e.target).text()
      };

      $.get('e', requestData, (data) => {
        $('#dictionary').html(data);
      });
    });
}); 

```

列表 6.10

现在我们已经看到 jQuery 提供的其他 Ajax 接口，这个函数的操作看起来很熟悉。唯一的区别是第二个参数，它允许我们提供一个包含键和值的对象，这些键和值成为查询字符串的一部分。在这种情况下，键始终是 `term`，但值是从每个链接的文本中获取的。现在，点击列表中的第一个链接会显示其定义：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_06_08.png)

这里的所有链接都有 URL，即使我们在代码中没有使用它们。为了防止链接在点击时正常跟随，我们调用`.preventDefault()`方法。

返回 false 还是阻止默认行为？

在本章中编写 `click` 处理程序时，我们选择使用 `e.preventDefault()` 而不是以 `return false` 结束处理程序。当默认操作否则会重新加载页面或加载另一页时，建议采用这种做法。例如，如果我们的 `click` 处理程序包含 JavaScript 错误，调用处理程序的第一行`.preventDefault()`（在遇到错误之前）确保表单不会被提交，并且我们浏览器的错误控制台将正确报告错误。请记住，从 第三章 *处理事件*，`return false` 调用了 `event.preventDefault()` 和 `event.stopPropagation()`。如果我们想要阻止事件冒泡，我们还需要调用后者。

# 序列化表单

将数据发送到服务器通常涉及用户填写表单。与其依赖于正常的表单提交机制，该机制将在整个浏览器窗口中加载响应，我们可以使用 jQuery 的 Ajax 工具包异步提交表单并将响应放置在当前页面中。

要尝试这个，我们需要构建一个简单的表单：

```js
<div class="letter" id="letter-f"> 
  <h3>F</h3> 
  <form action="f"> 
    <input type="text" name="term" value="" id="term" /> 
    <input type="submit" name="search" value="search" 
      id="search" /> 
  </form> 
</div> 

```

这一次，我们将通过使我们的 `/f` 处理程序搜索提供的搜索词作为字典词的子字符串来从服务器返回一组条目。我们将使用我们从 `/e` 处理程序 中的 `formatEntry()` 函数以与之前相同的格式返回数据。以下是 `/f` 处理程序的实现：

```js
app.post('/f', (req, res) => {
  const term = req.body.term.toUpperCase();
  const content = Object.keys(F_entries)
    .filter(k => k.includes(term))
    .reduce((result, k) => `
      ${result}
      ${formatEntry(k, F_entries[k])}
    `, '');

  res.send(content);
}); 

```

现在，我们可以对表单提交做出反应，并通过遍历 DOM 树来制作正确的查询参数：

```js
$(() => {
  $('#letter-f form')
    .submit((e) => {
      e.preventDefault();

      $.post(
        $(e.target).attr('action'),
        { term: $('input[name="term"]').val() },
        (data) => { $('#dictionary').html(data); }
      );
    });
}); 

```

清单 6.11

此代码具有预期效果，但按名称搜索输入字段并逐个将其附加到地图中是繁琐的。特别是，随着表单变得更加复杂，这种方法的扩展性不佳。幸运的是，jQuery 提供了一个经常使用的惯用语的快捷方式。`.serialize()` 方法作用于 jQuery 对象，并将匹配的 DOM 元素转换为可以与 Ajax 请求一起传递的查询字符串。我们可以将我们的提交处理程序概括如下：

```js
$(() => {
  $('#letter-f form')
    .submit((e) => {
      e.preventDefault();

      $.post(
        $(e.target).attr('action'),
        $(e.target).serialize(),
        (data) => { $('#dictionary').html(data); }
      );
    }); 
}); 

```

清单 6.12

同样的脚本将用于提交表单，即使字段数量增加。例如，当我们搜索 `fid` 时，包含该子字符串的术语会显示如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_06_10.png)

# 注意请求

到目前为止，我们只需调用一个 Ajax 方法并耐心等待响应就足够了。然而，有时候，了解 HTTP 请求在进行中的情况会很方便。如果出现这种需要，jQuery 提供了一套函数，可以在发生各种与 Ajax 相关的事件时注册回调函数。

`.ajaxStart()` 和 `.ajaxStop()` 方法是这些观察者函数的两个示例。当没有其他传输正在进行时开始一个 Ajax 调用时，将触发 `.ajaxStart()` 回调。相反，当最后一个活动请求结束时，将执行与 `.ajaxStop()` 绑定的回调。所有观察者都是全局的，它们在发生任何 Ajax 通信时被调用，无论是什么代码启动的。而且所有这些观察者只能绑定到 `$(document)`。

我们可以利用这些方法在网络连接缓慢的情况下向用户提供一些反馈。页面的 HTML 可以附加适当的加载消息：

```js
<div id="loading"> 
  Loading... 
</div> 

```

这个消息只是一段任意的 HTML 代码；例如，它可以包含一个动画 GIF 图像作为加载指示器。在这种情况下，我们将在 CSS 文件中添加一些简单的样式，以便在显示消息时，页面看起来如下：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_06_11.png)

为了符合渐进增强的精神，我们不会直接将这个 HTML 标记放在页面上。相反，我们将使用 jQuery 插入它：

```js
$(() => {
  $('<div/>')
    .attr('id', 'loading')
    .text('Loading...')
    .insertBefore('#dictionary');
}); 

```

我们的 CSS 文件将给这个 `<div>` 添加一个 `display: none;` 的样式声明，以便最初隐藏消息。在适当的时候显示它，我们只需使用 `.ajaxStart()` 将其注册为观察者：

```js
$(() => {
  const $loading = $('<div/>')
    .attr('id', 'loading')
    .text('Loading...')
    .insertBefore('#dictionary');

  $(document)
    .ajaxStart(() => {
      $loading.show(); 
    }); 
}); 

```

我们可以将隐藏行为链接在一起：

```js
$(() => {
  const $loading = $('<div/>')
    .attr('id', 'loading')
    .text('Loading...') 
    .insertBefore('#dictionary'); 

  $(document)
    .ajaxStart(() => {
      $loading.show(); 
    })
    .ajaxStop(() => {
      $loading.hide(); 
    }); 
}); 

```

列表 6.13

现在我们有了加载反馈。

再次说明，这些方法与 Ajax 通信开始的具体方式无关。附加到 A 链接的 `.load()` 方法和附加到 B 链接的 `.getJSON()` 方法都会导致这些操作发生。

在这种情况下，这种全局行为是可取的。不过，如果我们需要更具体的行为，我们有几个选择。一些观察者方法，比如 `.ajaxError()`，会将它们的回调函数发送给 `XMLHttpRequest` 对象的引用。这可以用于区分一个请求和另一个请求，并提供不同的行为。通过使用低级别的 `$.ajax()` 函数，我们可以实现其他更具体的处理，稍后我们会讨论这个函数。

与请求交互的最常见方式是 `success` 回调，我们已经介绍过了。我们在几个示例中使用它来解释从服务器返回的数据，并用结果填充页面。当然，它也可以用于其他反馈。再次考虑我们从 *列表 6.1* 中的 `.load()` 示例：

```js
$(() => { 
  $('#letter-a a')
    .click((e) => {
      e.preventDefault();
      $('#dictionary')
        .load('a.html'); 
    }); 
}); 

```

我们可以通过使加载的内容淡入而不是突然出现来进行一点小改进。`.load()` 方法可以接受一个回调函数在完成时被触发：

```js
$(() => { 
  $('#letter-a a')
    .click((e) => {
      e.preventDefault();
      $('#dictionary')
        .hide()
        .load('a.html', function() { 
          $(this).fadeIn(); 
        }); 
    }); 
}); 

```

列表 6.14

首先，我们隐藏目标元素，然后开始加载。加载完成后，我们使用回调函数将新填充的元素显示出来，以淡入的方式。

# 错误处理

到目前为止，我们只处理了 Ajax 请求的成功响应，当一切顺利时加载页面以显示新内容。然而，负责任的开发人员应考虑网络或数据错误的可能性，并适当地报告它们。在本地环境中开发 Ajax 应用程序可能会使开发人员产生自满感，因为除了可能的 URL 输入错误外，Ajax 错误不会在本地发生。Ajax 方便的方法，如`$.get()`和`.load()`本身不提供错误回调参数，因此我们需要寻找其他地方解决此问题。

除了使用`global .ajaxError()`方法外，我们还可以利用 jQuery 的延迟对象系统来对错误做出反应。我们将在第十一章，*高级效果*中更详细地讨论延迟对象，但是，现在我们简单地指出，我们可以将`.done()`，`.always()`和`.fail()`方法链接到除`.load()`之外的任何 Ajax 函数，并使用这些方法来附加相关的回调。例如，如果我们取自*列表 6.16*的代码，并将 URL 更改为不存在的 URL，我们可以测试`.fail()`方法：

```js
$(() => { 
  $('#letter-e a')
    .click((e) => {
      e.preventDefault();

      const requestData = {
        term: $(e.target).text()
      };

      $.get('notfound', requestData, (data) => {
        $('#dictionary').html(data);
      }).fail((xhr) => {
        $('#dictionary')
          .html(`An error occurred:
            ${xhr.status}
            ${xhr.responseText}
          `);
      });
    });
}); 

```

列表 6.15

现在，点击以 E 开头的任何术语链接都会产生错误消息。`jqXHR.responseText`的确切内容将根据服务器配置的不同而变化：

![](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/lrn-jq3/img/5297_06_12.png)

`.status`属性包含服务器提供的数字代码。这些代码在 HTTP 规范中定义，当触发`.fail()`处理程序时，它们将代表错误条件，例如：

| **响应代码** | **描述** |
| --- | --- |
| 400 | 错误请求 |
| 401 | 未经授权 |
| 403 | 禁止访问 |
| 404 | 未找到 |
| 500 | 内部服务器错误 |

可以在 W3C 的网站上找到完整的响应代码列表：[`www.w3.org/Protocols/rfc2616/rfc2616-sec10.html`](http://www.w3.org/Protocols/rfc2616/rfc2616-sec10.html)。

我们将更仔细地检查错误处理在第十三章，*高级 Ajax*中。

# Ajax 和事件

假设我们想允许每个词典术语名称控制其后跟的定义的显示；点击术语名称将显示或隐藏相关定义。根据我们目前所见的技术，这应该是相当简单的：

```js
$(() => {
  $('h3.term')
    .click((e) => {
      $(e.target)
        .siblings('.definition')
        .slideToggle();
    });
}); 

```

列表 6.16

当点击术语时，此代码会查找具有`definition`类的元素的兄弟元素，并根据需要将它们上下滑动。

一切看起来都井然有序，但此代码不起作用。不幸的是，当我们附加`click`处理程序时，术语尚未添加到文档中。即使我们设法将`click`处理程序附加到这些项上，一旦我们点击不同的字母，处理程序将不再附加。

这是一个常见的问题，当页面的某些区域由 Ajax 填充时。一个流行的解决方案是每次页面区域被刷新时重新绑定处理程序。然而，这可能很麻烦，因为每次任何事情导致页面的 DOM 结构发生变化时，事件绑定代码都需要被调用。

更优的选择在第三章，*事件处理*中被介绍。我们可以实现**事件委托**，实际上将事件绑定到一个永远不会改变的祖先元素上。在这种情况下，我们将`click`处理程序附加到`<body>`元素上，使用`.on()`这样来捕获我们的点击：

```js
$(() => { 
  $('body')
    .on('click', 'h3.term', (e) => {
      $(e.target)
        .siblings('.definition')
        .slideToggle();
    });
}); 

```

第 6.17 节

当以这种方式使用时，`.on()`方法告诉浏览器在整个文档中观察所有点击。如果（且仅当）点击的元素与`h3.term`选择器匹配，则执行处理程序。现在，切换行为将在任何术语上发生，即使它是由后来的 Ajax 事务添加的。

# 延迟对象和承诺

在 JavaScript 代码中处理异步行为时，jQuery 延迟对象是在没有一致的方式时引入的。承诺帮助我们编排异步事务，如多个 HTTP 请求、文件读取、动画等。承诺不是 JavaScript 专有的，也不是一个新的想法。将承诺视为一个承诺*最终*解析值的合同是最好的理解方式。

现在承诺已经正式成为 JavaScript 的一部分，jQuery 现在完全支持承诺。也就是说，jQuery 延迟对象的行为与任何其他承诺一样。这很重要，因为我们将在本节中看到，这意味着我们可以使用 jQuery 延迟对象来与返回原生承诺的其他代码组合复杂的异步行为。

# 在页面加载时执行 Ajax 调用

现在，我们的字典在初始页面加载时不显示任何定义。相反，它只显示一些空白空间。让我们通过在文档准备好时显示"A"条目来改变这种情况。我们如何做到这一点？

一种方法是简单地将`load('a.html')`调用添加到我们的文档准备处理程序（`$(() => {})`）中，以及其他所有内容。问题在于这样效率低下，因为我们必须等待文档准备好才能发出 Ajax 请求。如果我们的 JavaScript 一运行就发出 Ajax 请求会不会更好呢？

挑战在于将文档准备事件与 Ajax 响应准备事件同步。这里存在竞争条件，因为我们不知道哪个事件会先发生。文档准备可能会首先完成，但我们不能做出这种假设。这就是承诺非常有用的地方：

```js
Promise.all([
  $.get('a.html'),
  $.ready
]).then(([content]) => {
  $('#dictionary')
    .hide()
    .html(content)
    .fadeIn();
});

```

第 6.18 节

`Promise.all()`方法接受其他 promise 的数组，并返回一个新的 promise。当数组参数中的所有内容都解析了，这个新的 promise 就解析了。这就是 promise 为我们处理异步竞争条件的方式。无论 Ajax promise (`$.get('a.html')`)先解析还是文档准备好 promise (`$.ready`)先解析，都不重要。

`then()`处理程序是我们想要执行依赖于异步值的任何代码的地方。例如，content 值是解析后的 Ajax 调用。文档准备好隐式解析了 DOM。如果 DOM 没有准备好，我们就不能运行`$('#dictionary')...`。

# 使用 fetch()

JavaScript 的另一个近期新增功能是`fetch()`函数。这是`XMLHttpRequest`的更灵活的替代品。例如，当进行跨域请求时或需要调整特定的 HTTP 头值时，使用`fetch()`更加容易。让我们使用`fetch()`来实现*G*条目：

```js
$(() => {
  $('#letter-g a')
    .click((e) => { 
      e.preventDefault();

      fetch('/g')
        .then(resp => resp.json())
        .then(data => {
          const html = data.reduce((result, entry) => `
            ${result}
            <div class="entry">
              <h3 class="term">${entry.term}</h3>
              <div class="part">${entry.part}</div>
              <div class="definition">
                ${entry.definition}
                ${formatQuote(entry)}
              </div>
            </div>
          `, '');

          $('#dictionary')
            .html(html);
        });
    });
});

```

列表 6.19

`fetch()`函数返回一个 promise，就像各种 jQuery Ajax 函数一样。这意味着如果我们在这个例子中调用的`/g`网址实际上位于另一个域中，我们可以使用`fetch()`来访问它。如果我们需要 JSON 数据，我们需要在`.then()`处理程序中调用`.json()`。然后，在第二个处理程序中，我们可以使用在本章前面创建的相同函数来填充 DOM。

Promise 背后的整个理念是一致性。如果我们需要同步异步行为，promise 是解决的方法。任何 jQuery 异步执行的内容，都可以使用其他 promise。

# 总结

你已经学会了 jQuery 提供的 Ajax 方法可以帮助我们从服务器加载多种不同格式的数据，而无需页面刷新。我们可以根据需要从服务器执行脚本，并将数据发送回服务器。

你还学会了如何处理异步加载技术的常见挑战，比如在加载完成后保持处理程序的绑定以及从第三方服务器加载数据。

这结束了我们对`jQuery`库基本组件的介绍。接下来，我们将看看这些功能如何通过 jQuery 插件轻松扩展。

# 进一步阅读

Ajax 的主题将在第十三章 *高级 Ajax*中更详细地探讨。完整的 Ajax 方法列表可以在本书的附录 B *快速参考*或官方的 jQuery 文档中找到 [`api.jquery.com/`](http://api.jquery.com/)。

# 练习

挑战性的练习可能需要使用官方的 jQuery 文档

[`api.jquery.com/`](http://api.jquery.com/):

1.  当页面加载时，将`exercises-content.html`的内容填充到页面的内容区域。

1.  而不是一次性显示整个文档，当用户将鼠标悬停在左侧列中的字母上时，通过从`exercises-content.html`加载适当字母的内容，创建工具提示。

1.  为这个页面加载添加错误处理，将错误消息显示在内容区域。通过将脚本更改为请求`does-not-exist.html`而不是`exercises-content.html`来测试这个错误处理代码。

1.  这是一个挑战。页面加载时，向 GitHub 发送一个 JSONP 请求，并检索用户的存储库列表。将每个存储库的名称和网址插入页面的内容区域。检索 jQuery 项目存储库的网址是[`api.github.com/users/jquery/repos`](https://api.github.com/users/jquery/repos)。
