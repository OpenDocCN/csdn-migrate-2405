# jQuery 参考指南（三）

> 原文：[`zh.annas-archive.org/md5/0AC785FD3E3AB038A029EF6BA3FEE889`](https://zh.annas-archive.org/md5/0AC785FD3E3AB038A029EF6BA3FEE889)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：效果方法

> 它有风格，有品位
> 
> ——德沃,
> 
> "无法控制的冲动"

在本章中，我们将仔细检查每个效果方法，揭示 jQuery 提供给用户的所有视觉反馈机制。

# 预打包效果

这些方法允许我们快速应用常用效果，并具有最小的配置。

## `.show()`

| 显示匹配的元素。

```js
.show([speed][, callback])

```

|

### 参数

+   speed（可选）：确定动画运行时间的字符串或数字

+   回调（可选）：动画完成后要调用的函数

### 返回值

jQuery 对象，用于链式操作。

### 描述

没有参数时，`.show()`方法是显示元素的最简单方法：

```js
$('.target').show();

```

匹配的元素将立即显示，没有动画。这大致相当于调用`.css('display', 'block')`，除了`display`属性会恢复为初始值。如果将元素的`display`值设置为`inline`，然后将其隐藏和显示，则它将再次以`inline`显示。

如果提供了速度，则`.show()`变为动画方法。`.show()`方法同时动画匹配元素的宽度、高度和不透明度。

速度以动画的毫秒持续时间给出；较高的值表示较慢的动画，*而不是*较快的动画。可以提供字符串`fast、normal`和`slow`来指示速度值为`200、400`和`600`，如果省略速度参数，则默认为`normal`。

如果提供了回调函数，则在动画完成后调用。这对于将不同的动画按顺序串联在一起非常有用。回调函数不接收任何参数，但`this`被设置为正在被动画化的 DOM 元素。回调函数对每个匹配的元素执行一次，*而不是*对整个动画执行一次。

我们可以对任何元素进行动画处理，例如简单的包含图像的`<div>`：

```js
<div class="content">
  <div class="trigger button">Trigger</div>
  <div class="target"><img src="img/hat.gif" width="80" height="54" alt="Hat" /></div>
  <div class="log"></div>
</div>
```

初始隐藏元素后，我们可以缓慢显示它：

```js
$('.trigger').click(function() {
  $('.target').show('slow', function() {
    $(this).log('Effect complete.');
  });
});
```

![Description.show() about](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_06_01.jpg)

## `.hide()`

| 隐藏匹配的元素。

```js
.hide([speed][, callback])

```

|

### 参数

+   speed（可选）：确定动画运行时间的字符串或数字

+   回调（可选）：动画完成后要调用的函数

### 返回值

jQuery 对象，用于链式操作。

### 描述

没有参数时，`.hide()`方法是隐藏元素的最简单方法：

```js
$('.target').hide();

```

匹配的元素将立即被隐藏，没有动画。这大致相当于调用`.css('display', 'none')`，除了`display`属性的值被保存为元素的另一个属性，以便稍后可以将`display`恢复为其初始值。如果将元素的`display`值设置为`inline`，然后将其隐藏和显示，则它将再次以`inline`显示。

如果提供了速度，则`.hide()`变为动画方法。`.hide()`方法同时动画匹配元素的宽度、高度和不透明度。

速度以动画的毫秒持续时间给出；较高的值表示较慢的动画，*而不是*较快的动画。可以提供字符串`fast，normal`和`slow`来表示速度值`200、400`和`600`。如果省略了速度参数，则假定为`normal`。

如果提供了回调函数，则在动画完成后调用该函数。这对于按顺序连接不同的动画非常有用。回调函数不接收任何参数，但`this`被设置为正在进行动画处理的 DOM 元素。回调函数对每个匹配的元素执行一次，而不是对整个动画执行一次。

我们可以对任何元素进行动画处理，比如一个简单的包含图片的`<div>`：

```js
<div class="content">
  <div class="trigger button">Trigger</div>
  <div class="target"><img src="img/hat.gif" width="80" height="54" alt="Hat" /></div>
  <div class="log"></div>
</div>
```

初始显示元素后，我们可以慢慢隐藏它：

```js
$('.trigger').click(function() {
  $('.target').hide('slow', function() {
    $(this).log('Effect complete.');
  });
});
```

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_06_04.jpg)

## `.toggle()`

| 显示或隐藏匹配的元素。

```js
.toggle([speed][, callback])

```

|

### 参数

+   速度（可选）：确定动画运行时间的字符串或数字

+   回调（可选）：动画完成后要调用的函数

### 返回值

jQuery 对象，用于链接目的。

### 描述

没有参数时，`.toggle()`方法简单地切换元素的可见性：

```js
$('.target').toggle();

```

匹配的元素将立即显示或隐藏，没有动画效果。如果元素最初是显示的，则将其隐藏；如果是隐藏的，则将其显示。根据需要保存并恢复`display`属性。如果给定的元素具有`inline`的`display`值，则隐藏和显示后，它将再次以`inline`的方式显示。

当提供速度时，`.toggle()`变为动画方法。`.toggle()`方法同时动画匹配元素的宽度、高度和不透明度。

速度以动画的毫秒持续时间给出；较高的值表示较慢的动画，*而不是*较快的动画。可以提供字符串`fast，normal`和`slow`来表示速度值`200、400`和`600`。如果省略了速度参数，则假定为`normal`。

如果提供了回调函数，则在动画完成后调用该函数。这对于按顺序连接不同的动画非常有用。回调函数不接收任何参数，但`this`被设置为正在进行动画处理的 DOM 元素。回调函数对每个匹配的元素执行一次，而不是对整个动画执行一次。

我们可以对任何元素进行动画处理，比如一个简单的包含图片的`<div>`：

```js
<div class="content">
  <div class="trigger button">Trigger</div>
  <div class="target"><img src="img/hat.gif" width="80" height="54" alt="Hat" /></div>
  <div class="log"></div>
</div>
```

初始显示元素后，我们可以慢慢隐藏和显示它：

```js
$('.trigger').click(function() {
  $('.target').toggle('slow', function() {
    $(this).log('Effect complete.');
  });
});
```

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_06_07.jpg)![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_06_10.jpg)

## `.slideDown()`

| 以滑动方式显示匹配的元素。

```js
.slideDown([speed][, callback])

```

|

### 参数

+   速度（可选）：确定动画运行时间的字符串或数字

+   回调（可选）：动画完成后要调用的函数

### 返回值

jQuery 对象，用于链接目的。

### 描述

`.slideDown()`方法会使匹配元素的高度发生动画变化。这会导致页面的底部向下滑动，为显示的项目让出空间。

速度以动画的毫秒持续时间给出；更高的值表示更慢的动画，*而不是*更快的动画。可以提供字符串`fast、normal`和`slow`来指示速度值为`200、400`和`600`。如果省略速度参数，则假定为`normal`。

如果提供了回调函数，动画完成后将触发该回调。这对于按顺序串联不同的动画非常有用。回调函数不接收任何参数，但`this`被设置为正在进行动画的 DOM 元素。回调函数针对每个匹配的元素执行一次，而不是针对整个动画执行一次。

我们可以对任何元素进行动画处理，比如一个包含图像的简单的`<div>`：

```js
<div class="content">
  <div class="trigger button">Trigger</div>
  <div class="target"><img src="img/hat.gif" width="80" height="54" alt="Hat" /></div>
  <div class="log"></div>
</div>
```

以元素初始隐藏的状态，我们可以缓慢显示它：

```js
$('.trigger').click(function() {
  $('.target').slideDown('slow', function() {
    $(this).log('Effect complete.');
  });
});
```

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_06_12.jpg)

## .slideUp()

| 以滑动动作隐藏匹配的元素。

```js
.slideUp([speed][, callback])

```

|

### 参数

+   speed（可选）：确定动画将运行多长时间的字符串或数字

+   回调（可选）：动画完成后要调用的函数

### 返回值

jQuery 对象，用于链接目的。

### 描述

`.slideUp()`方法动画化匹配元素的高度。这将导致页面的较低部分向上滑动，似乎隐藏了项目。

速度以动画的毫秒持续时间给出；更高的值表示更慢的动画，*而不是*更快的动画。可以提供字符串`fast、normal`和`slow`来指示速度值为`200、400`和`600`。如果省略速度参数，则假定为`normal`。

如果提供了回调函数，动画完成后将触发该回调。这对于按顺序串联不同的动画非常有用。回调函数不接收任何参数，但`this`被设置为正在进行动画的 DOM 元素。回调函数针对每个匹配的元素执行一次，而不是针对整个动画执行一次。

我们可以对任何元素进行动画处理，比如一个包含图像的简单的`<div>`：

```js
<div class="content">
  <div class="trigger button">Trigger</div>
  <div class="target"><img src="img/hat.gif" width="80" height="54" alt="Hat" /></div>
  <div class="log"></div>
</div>
```

以元素初始可见的状态，我们可以缓慢隐藏它：

```js
$('.trigger').click(function() {
  $('.target').slideUp('slow', function() {
    $(this).log('Effect complete.');
  });
});
```

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_06_15.jpg)

## .slideToggle()

| 以滑动动作显示或隐藏匹配的元素。

```js
.slideToggle([speed][, callback])

```

|

### 参数

+   speed（可选）：确定动画将运行多长时间的字符串或数字

+   回调（可选）：动画完成后要调用的函数

### 返回值

jQuery 对象，用于链接目的。

### 描述

`.slideToggle()`方法动画化匹配元素的高度。这将导致页面的较低部分向上或向下滑动，似乎隐藏或显示了项目。

速度以动画的毫秒持续时间给出；更高的值表示更慢的动画，*而不是*更快的动画。可以提供字符串`fast、normal`和`slow`来指示速度值为`200、400`和`600`。如果省略速度参数，则假定为`normal`。

如果提供，回调函数在动画完成时被触发。这对于按顺序将不同的动画串联起来非常有用。回调不发送任何参数，但`this`被设置为正在被动画化的 DOM 元素。回调一次对匹配元素执行一次，而不是整个动画执行一次。

我们可以对任何元素进行动画处理，例如一个包含图像的简单的`<div>`：

```js
<div class="content">
  <div class="trigger button">Trigger</div>
  <div class="target"><img src="img/hat.gif" width="80" height="54" alt="Hat" /></div>
  <div class="log"></div>
</div>
```

初始显示该元素，然后我们可以慢慢隐藏和显示它：

```js
$('.trigger').click(function() {
  $('.target').slideToggle('slow', function() {
    $(this).log('Effect complete.');
  });
});
```

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_06_18.jpg)![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_06_19.jpg)

## .fadeIn()

| 通过将匹配元素淡化为不透明来显示它们。

```js
.fadeIn([speed][, callback])

```

|

### 参数

+   速度（可选）：确定动画运行时间的字符串或数字。

+   回调（可选）：动画完成时要调用的函数。

### 返回值

jQuery 对象，用于链接目的。

### 描述

`.fadeIn()`方法动画显示匹配元素的不透明度。

速度以动画的毫秒持续时间给出；较高的值表示较慢的动画，*而不是*较快的动画。可以提供字符串`fast, normal`和`slow`表示速度值分别为`200, 400`和`600`。如果省略速度参数，则假定为`normal`。

如果提供，回调函数在动画完成时被触发。这对于按顺序将不同的动画串联起来非常有用。回调不发送任何参数，但`this`被设置为正在被动画化的 DOM 元素。回调一次对匹配元素执行一次，*而不是*整个动画执行一次。

我们可以对任何元素进行动画处理，例如一个包含图像的简单的`<div>`：

```js
<div class="content">
  <div class="trigger button">Trigger</div>
  <div class="target"><img src="img/hat.gif" width="80" height="54" alt="Hat" /></div>
  <div class="log"></div>
</div>
```

初始隐藏该元素，然后我们可以慢慢显示它：

```js
$('.trigger').click(function() {
  $('.target').fadeIn('slow', function() {
    $(this).log('Effect complete.');
  });
});
```

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_06_23.jpg)

## .fadeOut()

| 通过将匹配元素淡化为透明来隐藏它们。

```js
.fadeOut([speed][, callback])
```

|

### 参数

+   速度（可选）：确定动画运行时间的字符串或数字。

+   回调（可选）：动画完成时要调用的函数。

### 返回值

jQuery 对象，用于链接目的。

### 描述

`.fadeOut()`方法动画隐藏匹配元素的不透明度。

速度以动画的毫秒持续时间给出；较高的值表示较慢的动画，*而不是*较快的动画。可以提供字符串`fast, normal`和`slow`表示速度值分别为`200, 400`和`600`。如果省略速度参数，则假定为`normal`。

如果提供，回调函数在动画完成时被触发。这对于按顺序将不同的动画串联起来非常有用。回调不发送任何参数，但`this`被设置为正在被动画化的 DOM 元素。回调一次对匹配元素执行一次，*而不是*整个动画执行一次。

我们可以对任何元素进行动画处理，例如一个包含图像的简单的`<div>`：

```js
<div class="content">
  <div class="trigger button">Trigger</div>
  <div class="target"><img src="img/hat.gif" width="80" height="54" alt="Hat" /></div>
  <div class="log"></div>
</div>
```

初始显示该元素，然后我们可以慢慢隐藏它：

```js
$('.trigger').click(function() {
  $('.target').fadeOut('slow', function() {
    $(this).log('Effect complete.');
  });
});
```

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_06_26.jpg)

## .fadeTo()

| 调整匹配元素的不透明度。

```js
.fadeTo(speed, opacity[, callback])
```

|

### 参数

+   速度：确定动画将运行多长时间的字符串或数字

+   不透明度：介于 0 和 1 之间的目标不透明度的数字

+   回调：（可选）：动画完成后要调用的函数

### 返回值

jQuery 对象，用于链接目的。

### 描述

`.fadeTo（）`方法会动画化匹配元素的不透明度。

速度以动画的毫秒持续时间给出；较高的值表示较慢的动画，*不*表示更快的动画。可以提供字符串`fast，normal`和`slow`以指示速度值分别为`200，400`和`600`。与其他效果方法不同，`.fadeTo（）`要求速度应明确指定。

如果提供了回调函数，则在动画完成后触发。这对于串联不同的动画在序列中很有用。回调函数不会发送任何参数，但`this`被设置为正在动画的 DOM 元素。回调函数针对每个匹配的元素执行一次，*不*是动画作为整体执行一次。

我们可以对任何元素进行动画处理，例如一个简单的包含图像的`<div>`：

```js
<div class="content">
  <div class="trigger button">Trigger</div>
  <div class="target"><img src="img/hat.gif" width="80" height="54" alt="Hat" /></div>
  <div class="log"></div>
</div>
```

使用元素最初显示，我们可以慢慢将其变暗：

```js
$('.trigger').click(function() {
  $('.target').fadeTo('slow', 0.5, function() {
    $(this).log('Effect complete.');
  });
});
```

![描述](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-ref-gd/img/3810_06_29.jpg)

将*速度*设置为`0`，此方法只是更改`opacity`CSS 属性，因此`.fadeTo（0，opacity）`与`.css（'opacity'，opacity）`相同。

### 注意

在 jQuery 版本 1.1.3 之前，`.fadeTo（）`会将元素的`display`属性设置为`block`。这在与非块项（如表格行和内联元素）一起使用时可能导致奇怪的布局渲染。从 jQuery 1.1.3 开始，可以安全地对这些元素使用淡入淡出。

# 自定义效果

本节描述了如何创建 jQuery 未提供的效果。

## `.animate（）`

| 执行一组 CSS 属性的自定义动画。

```js
.animate(properties[, speed][, easing][, callback])
```

|

### 参数

+   属性：动画将向其移动的 CSS 属性的映射

+   速度（可选）：确定动画将运行多长时间的字符串或数字

+   缓动（可选）：指示要用于过渡的缓动函数的字符串

+   回调（可选）：动画完成后要调用的函数

### 返回值

jQuery 对象，用于链接目的。

### 描述

`.animate（）`方法允许我们在任何数字 CSS 属性上创建动画效果。唯一必需的参数是一组 CSS 属性的映射。此映射类似于可以发送到`.css（）`方法的映射，只是属性范围更为限制。

所有动画属性都被视为像素数。如果属性最初以不同的单位（如 em 或百分比）指定，这可能会产生奇怪的结果。

除了数字值之外，每个属性还可以采用字符串`show，hide`和`toggle`。这些快捷方式允许自定义隐藏和显示动画，考虑了元素的显示类型。

速度以动画的毫秒持续时间给出；更高的值表示较慢的动画，*不*是更快的动画。可以提供字符串`fast, normal`和`slow`来指示速度值分别为`200, 400`和`600`。如果省略速度参数，则假定为`normal`。

如果提供了回调函数，则在动画完成时会触发。这对于按顺序串联不同的动画非常有用。回调函数不会发送任何参数，但`this`设置为正在动画的 DOM 元素。回调函数对每个匹配的元素执行一次，*而不是*对整个动画执行一次。

我们可以动画任何元素，比如一个简单的包含图像的`<div>`：

```js
<div class="content">
  <div class="trigger button">Trigger</div>
  <div class="target"><img src="img/hat.gif" width="80" height="54" alt="Hat" /></div>
  <div class="log"></div>
</div>
```

我们可以同时动画多个属性：

```js
$('.trigger').click(function() {
  $('.target').animate({
    'width': 300,
    'left': 100,
    'opacity': 0.25
  }, 'slow', function() {
    $(this).log('Effect complete.');
  });
});
```

如果我们希望像示例中那样动画`left`属性，则元素的`position`属性不能是`fixed`。

### 注意

更复杂的`.animate()`方法的版本可以在*Interface*插件中找到。它处理一些非数字样式，比如颜色，还处理类的动画，而不是单个属性。

`.animate()`的剩余参数是一个命名的字符串，用于指定要使用的缓动函数。缓动函数指定动画在动画内不同点的进度速度。jQuery 库中唯一的缓动实现是默认的`linear`。通过使用插件，如 Interface，可以获得更多的缓动函数。


# 第七章：AJAX 方法

> 她失去了同步
> 
> 她从出口进入
> 
> 从未停下来思考
> 
> ——Devo
> 
> "失去同步"

jQuery 中的 AJAX 功能帮助我们从服务器加载数据，而不需要浏览器页面刷新。在本章中，我们将检查每个可用的 AJAX 方法和函数。我们将看到启动 AJAX 请求的各种方式，以及可以随时观察到正在进行的请求的几种方法。

# 低级接口

这些方法可用于进行任意的 AJAX 请求。

## $.ajax()

| 执行异步 HTTP（AJAX）请求。

```js
$.ajax(settings)

```

|

### 参数

+   settings：请求选项的映射可以包含以下项：

    +   `url`：包含发送请求的 URL 的字符串。

    +   `type`（可选）：定义用于请求的 HTTP 方法的字符串（`GET` 或 `POST`）。默认值为 `GET`。

    +   `dataType`（可选）：定义从服务器返回的数据类型的字符串（`xml，html，json` 或 `script`）。

    +   `ifModified`（可选）：一个布尔值，指示服务器在响应请求之前是否应检查页面是否已修改。

    +   `timeout`（可选）：请求失败时的超时毫秒数。

    +   `global`（可选）：一个布尔值，指示此请求是否会触发全局 AJAX 事件处理程序。默认值为 `true`。

    +   `beforeSend`（可选）：在发送请求之前执行的回调函数。

    +   `error`（可选）：请求失败时执行的回调函数。

    +   `success`（可选）：请求成功时执行的回调函数。

    +   `complete`（可选）：无论请求是否完成都会执行的回调函数。

    +   `data`（可选）：与请求一起发送到服务器的映射或字符串。

    +   `processData`（可选）：一个布尔值，指示是否将提交的数据从对象形式转换为查询字符串形式。默认值为 `true`。

    +   `contentType`（可选）：包含要为请求设置的 MIME 内容类型的字符串。默认值为 `application/x-www-form-urlencoded`。

    +   `async`（可选）：一个布尔值，指示是否异步执行请求。默认值为 `true`。

### 返回值

创建的 XMLHttpRequest 对象。

### 描述

`$.ajax()` 函数是 jQuery 发送的所有 AJAX 请求的基础。这个函数很少直接调用，因为有几个更高级的替代方法可用，如 `$.post()` 和 `.load()`，并且更容易使用。但是，如果需要不太常见的选项，`$.ajax()` 可以提供更大的灵活性。

在其最简单的形式下，`$.ajax()` 函数必须至少指定要加载数据的 URL：

```js
$.ajax({
  url: 'ajax/test.html',
});
```

### 注意

即使这个唯一的必需参数也可以通过使用 `$.ajaxSetup()` 函数设置默认值来变为可选。

这个例子，使用唯一的必需选项，加载了指定 URL 的内容，但对结果没有做任何操作。要使用结果，我们可以实现其中一个回调函数。`beforeSend，error，success`和`complete`选项接受在适当时候被调用的回调函数：

+   `beforeSend`：在发送请求之前调用；`XMLHttpRequest`对象作为一个参数传递给它。

+   `error`：如果请求失败，将`XMLHttpRequest`对象作为参数调用，以及一个指示错误类型的字符串和一个（如适用）异常对象。

+   `success`：如果请求成功，将返回的数据作为其参数传递。

+   `complete`：当请求完成时调用，无论成功与否。将`XMLHttpRequest`对象以及一个包含成功或错误代码的字符串作为参数传递给它。

为了使用返回的 HTML，我们可以实现一个`success`处理程序：

```js
$.ajax({
  url: 'ajax/test.html',
  success: function(data) {
    $('.result').html(data);
    $().log('Load was performed.');
  },
});
```

这样一个简单的例子通常最好使用`.load()`或`$.get()`来提供服务。

`$.ajax()`函数依赖于服务器提供有关检索数据的信息。如果服务器将返回数据报告为 XML，结果可以使用普通的 XML 方法或 jQuery 的选择器来遍历。如果检测到其他类型，比如上面的例子中的 HTML，数据将被视为文本。

通过使用`dataType`选项，可以实现不同的数据处理。除了纯粹的`xml`之外，`dataType`还可以是`html，json`或`script`。如果指定了`html`，检索数据中的任何嵌入 JavaScript 在返回 HTML 字符串之前将被执行。类似地，`script`将执行从服务器拉回的 JavaScript，并将脚本本身作为文本数据返回。`json`选项使用`eval()`来解析获取的数据文件，并将构造的对象作为结果数据返回。

### 注意

我们必须确保 Web 服务器报告的 MIME 类型与我们选择的`dataType`匹配。特别是，`xml`必须由服务器声明为`text/xml`以获得一致的结果。

默认情况下，AJAX 请求使用`GET HTTP`方法发送。如果需要`POST`方法，可以通过为`type`选项设置一个值来指定方法。这个选项影响`data`选项的内容如何发送到服务器。

`data`选项可以包含形式为`key1=value1&key2=value2`的查询字符串，或形式为`{key1: 'value1', key2: 'value2'}`的映射。如果使用后一种形式，数据在发送之前会被转换为查询字符串。如果希望将 XML 对象发送到服务器，则可以通过将`processData`设置为`false`来阻止这种处理。如果我们希望发送 XML 对象到服务器，可能并不需要这个处理；在这种情况下，我们还希望将`contentType`选项从`application/x-www-form-urlencoded`更改为一个更合适的 MIME 类型。

其余选项——`ifModified、timeout、global`和`async`——很少需要。有关`ifModified`的信息，请参阅`$.getIfModified()`函数。请求超时通常可以使用`$.ajaxSetup()`设置为全局默认值，而不是使用`timeout`选项针对特定请求设置。`global`选项阻止注册的处理程序使用`.ajaxSend()、.ajaxError()`或类似方法在此请求触发时触发。例如，如果请求频繁且简短，则可以使用此选项来禁止我们使用`.ajaxSend()`实现的加载指示器。最后，`async`选项的默认值为`true`，表示在请求完成后可以继续执行代码。强烈不建议将此选项设置为`false`，因为它可能导致浏览器无响应。

### 提示

使用此选项使请求同步不如使用*blockUI*插件效果更好。

`$.ajax()`函数返回它创建的`XMLHttpRequest`对象。通常可以丢弃此对象，但它确实提供了一个更低级别的接口来观察和操作请求。特别是，在对象上调用`.abort()`将在请求完成之前停止请求。

## $.ajaxSetup()

| 为将来的 AJAX 请求设置默认值。

```js
$.ajaxSetup(settings)

```

|

### 参数

+   设置：用于未来请求的选项映射。与`$.ajax()`中可能的项相同。

### 返回值

无。

### 描述

有关`$.ajaxSetup()`可用设置的详细信息，请参阅`$.ajax()`。所有使用任何函数的后续 AJAX 调用将使用新的设置，除非被单独调用覆盖，直到下一次调用`$.ajaxSetup()`为止。

例如，在反复 ping 服务器之前，我们可以为 URL 参数设置一个默认值：

```js
$.ajaxSetup({
  url: 'ping.php',
});
```

现在每次进行 AJAX 请求时，将自动使用此 URL：

```js
$.ajax({});
$.ajax({
  data: {'date': Date()},
});
```

# 快捷方法

这些方法使用更少的代码执行更常见类型的 AJAX 请求。

## $.get()

| 使用 GET HTTP 请求从服务器加载数据。

```js
$.get(url[, data][, success])

```

|

### 参数

+   URL：包含要发送请求的 URL 的字符串

+   数据：（可选）：发送请求的数据的映射

+   成功：（可选）：如果请求成功则执行的函数

### 返回值

创建的`XMLHttpRequest`对象。

### 描述

这是一个简写的 AJAX 函数，等价于：

```js
$.ajax({
  url: url,
  data: data,
  success: success
});
```

回调函数传递了返回的数据，这将是一个 XML 根元素或文本字符串，具体取决于响应的 MIME 类型。

大多数实现将指定一个成功处理程序：

```js
$.get('ajax/test.html', function(data) {
  $('.result').html(data);
  $().log('Load was performed.');
});
```

此示例获取所请求的 HTML 片段并将其插入页面。

## $.getIfModified()

| 如果自上次请求以来已更改，则使用`GET HTTP`请求从服务器加载数据。

```js
$.getIfModified(url[, data][, success])

```

|

### 参数

+   URL：包含要发送请求的 URL 的字符串

+   数据：（可选）：发送请求的数据的映射

+   成功：（可选）：如果请求成功则执行的函数

### 返回值

创建的`XMLHttpRequest`对象。

### 描述

这是一个简写的 AJAX 函数，相当于：

```js
$.ajax({
  url: url,
  data: data,
  success: success,
  ifModified: true
});
```

回调传递了返回的数据，这将是一个 XML 根元素或一个文本字符串，具体取决于响应的 MIME 类型。

大多数实现都会指定一个成功处理程序：

```js
$.getIfModified('ajax/test.html', function(data) {
  if (data) {
    $('.result').html(data);
  }
  $().log('Load was performed.');
});
```

此示例获取所请求的 HTML 片段，并将其插入到页面中。

发送 AJAX 请求时，将添加一个`If-Modified-Since`的 HTTP 标头。Web 服务器应该遵守这一点，并在文件未更改时省略数据。这可以用来节省带宽，当在页面内刷新数据时。

仍将未修改的页面响应视为`success`。在这种情况下，回调仍将被执行，但不会有数据可用。回调应该捕获这一点，以避免丢弃以前获取的数据。

## .load()

| 从服务器加载数据，并将返回的 HTML 放入匹配的元素中。

```js
.load(url[, data][, success])

```

|

### 参数

+   url: 包含发送请求的 URL 的字符串

+   data (可选): 要发送的数据的映射

+   success (可选): 如果请求成功，则执行的函数

### 返回值

jQuery 对象，用于链式调用。

### 描述

此方法是从服务器获取数据的最简单方法。它大致等同于`$.get(url, data, success)`，不同之处在于它是一个方法而不是一个全局函数，并且它具有一个隐式回调函数。当检测到成功响应时，`.load()`将匹配元素的 HTML 内容设置为返回的数据。这意味着该方法的大多数用法都可以非常简单：

```js
$('.result').load('ajax/test.html');

```

提供的回调（可选）在执行此后处理后执行：

```js
$('.result').load('ajax/test.html', function() {
  $(this).log('Load was performed.');
});
```

如果提供了数据，则使用 POST 方法；否则，假定为 GET。

### 注意

事件处理套件还有一个名为`.load()`的方法。哪一个被触发取决于传递的参数集。

## .loadIfModified()

| 从服务器加载数据，如果自上次请求以来已更改，则将返回的 HTML 放入匹配的元素中。

```js
.loadIfModified(url[, data][, success])

```

|

### 参数

+   url: 包含发送请求的 URL 的字符串

+    (可选): 要发送的数据的映射

+   success: (可选): 如果请求成功，则执行的函数

### 返回值

jQuery 对象，用于链式调用。

### 描述

此方法大致等同于`$.getIfModified(url, data, success)`，不同之处在于它是一个方法而不是一个全局函数，并且它具有一个隐式回调函数。当检测到成功响应时，`.loadIfModified()`将匹配元素的 HTML 内容设置为返回的数据。这意味着该方法的大多数用法都可以非常简单：

```js
$('.result').loadIfModified('ajax/test.html');

```

提供的回调（如果有）在执行此后处理后执行：

```js
$('.result').loadIfModified('ajax/test.html', function() {
  $(this).log('Load was performed.');
});
```

如果提供了数据，则使用 POST 方法；否则，假定为 GET。

要了解修改日期检查的工作原理，请参见`$.getIfModified()`。

## $.post()

| 使用 `POST HTTP` 请求从服务器加载数据。

```js
$.post(url[, data][, success])

```

|

### 参数

+   url: 包含发送请求的 URL 的字符串

+   （可选）：随请求发送的数据映射

+   success:（可选）：如果请求成功，则执行的函数

### 返回值

创建的 `XMLHttpRequest` 对象。

### 描述

这是一个简写的 AJAX 函数，相当于：

```js
$.ajax({
  type: 'POST',
  url: url,
  data: data,
  success: success
});
```

回调函数传递返回的数据，这将是一个 XML 根元素或一个取决于响应的 MIME 类型的文本字符串。

大多数实现将指定一个成功处理程序：

```js
$.post('ajax/test.html', function(data) {
  $('.result').html(data);
  $().log('Load was performed.');
});
```

这个例子获取请求的 HTML 片段并将其插入到页面上。

使用 `POST` 获取的页面永远不会被缓存，因此 `ifModified` 选项对这些请求没有影响。

## $.getJSON()

| 使用 `GET HTTP` 请求从服务器加载 JSON 编码的数据。

```js
$.getJSON(url[, data][, success])

```

|

### 参数

+   url: 包含发送请求的 URL 的字符串

+   （可选）：随请求发送的数据映射

+   success:（可选）：如果请求成功，则执行的函数

### 返回值

创建的 `XMLHttpRequest` 对象。

### 描述

这是一个简写的 AJAX 函数，相当于：

```js
$.ajax({
  url: url,
  dataType: 'json',
  data: data,
  success: success
});
```

回调函数传递返回的数据，这将根据 JSON 结构定义并使用 `eval()` 函数解析为 JavaScript 对象或数组。

有关 JSON 格式的详细信息，请参阅 [`json.org/`](http://json.org/)。

大多数实现将指定一个成功处理程序：

```js
$.getJSON('ajax/test.json', function(data) {
  $('.result').html('<p>' + data.foo + '</p><p>' + data.baz[1]+ '</p>');
  $().log('Load was performed.');
});
```

当然，此示例依赖于 JSON 文件的结构：

```js
{
  “foo": “The quick brown fox jumps over the lazy dog.",
  “bar": “How razorback-jumping frogs can level six piqued gymnasts!",
  “baz": [52, 97]
}
```

使用这个结构，示例将文件的第一个字符串和第二个数字插入到页面上。如果 JSON 文件中存在语法错误，请求通常会静默失败；为此避免频繁手动编辑 JSON 数据。

## $.getScript()

| 使用 `GET HTTP` 请求从服务器加载 JavaScript，并执行它。

```js
$.getScript(url[, success])

```

|

### 参数

+   url: 包含发送请求的 URL 的字符串

+   success:（可选）：如果请求成功，则执行的函数

### 返回值

创建的 `XMLHttpRequest` 对象。

### 描述

这是一个简写的 AJAX 函数，相当于：

```js
$.ajax({
  url: url,
  type: 'script',
  success: success
});
```

回调函数传递返回的 JavaScript 文件。这通常是没有用的，因为此时脚本已经运行。

脚本在全局上下文中执行，因此可以引用其他变量并使用 jQuery 函数。包含的脚本应该对当前页面产生一定的影响：

```js
$('.result').html('<p>Lorem ipsum dolor sit amet.</p>');
```

然后可以通过引用文件名来包含并运行脚本：

```js
$.getScript('ajax/test.js', function() {
  $().log('Load was performed.');
});
```

在 Safari 中，不能保证在调用成功回调之前执行脚本。实际上，这意味着回调中的代码不应该在没有至少小延迟的情况下调用在外部脚本中定义的函数或引用变量。

# 全局 AJAX 事件处理程序

这些方法注册处理程序，以在页面上发生任何 AJAX 请求时调用。

## .ajaxComplete()

| 注册一个处理程序，以在 AJAX 请求完成时调用。

```js
.ajaxComplete(handler)

```

|

### 参数

+   处理程序：要调用的函数

### 返回值

用于链式调用的 jQuery 对象。

### 描述

每当 AJAX 请求完成时，jQuery 会触发 `ajaxComplete` 事件。所有已使用 `.ajaxComplete()` 方法注册的处理程序都在此时执行。

要观察此方法的操作，我们可以设置一个基本的 AJAX 加载请求：

```js
<div class="trigger button">Trigger</div>
<div class="result"></div>
<div class="log"></div>

```

我们可以将我们的事件处理程序附加到任何元素上：

```js
$('.log').ajaxComplete(function() {
  $(this).log('Triggered ajaxComplete handler.');
});
```

现在，我们可以使用任何 jQuery 方法进行 AJAX 请求：

```js
$('.trigger').click(function() {
  $('.result').load('ajax/test.html');
});
```

当用户单击按钮并且 AJAX 请求完成时，日志消息会被显示。

所有 `ajaxComplete` 处理程序都会被调用，不管完成了什么 AJAX 请求。如果我们必须区分这些请求，我们可以使用传递给处理程序的参数。每次执行 `ajaxComplete` 处理程序时，都会传递事件对象、`XMLHttpRequest` 对象以及用于创建请求的设置对象。例如，我们可以将回调限制为仅处理与特定 URL 相关的事件：

```js
$('.log').ajaxComplete(function(e, xhr, settings) {
  if (settings.url == 'ajax/test.html') {
    $(this).log('Triggered ajaxComplete handler for “ajax/test.html".');
  }
});
```

## .ajaxError()

| 注册一个处理程序，以在 AJAX 请求完成时带有错误时调用。

```js
.ajaxError(handler)
```

|

### 参数

+   处理程序：要调用的函数

### 返回值

用于链式调用的 jQuery 对象。

### 描述

每当 AJAX 请求完成并出现错误时，jQuery 会触发 `ajaxError` 事件。所有已使用 `.ajaxError()` 方法注册的处理程序都在此时执行。

要观察此方法的操作，我们可以设置一个基本的 AJAX 加载请求：

```js
<div class="trigger button">Trigger</div>
<div class="result"></div>
<div class="log"></div>

```

我们可以将我们的事件处理程序附加到任何元素上：

```js
$('.log').ajaxError(function() {
  $(this).log('Triggered ajaxError handler.');
});
```

现在，我们可以使用任何 jQuery 方法进行 AJAX 请求：

```js
$('.trigger').click(function() {
  $('.result').load('ajax/missing.html');
});
```

当用户单击按钮并且 AJAX 请求失败时，因为请求的文件不存在，日志消息会被显示。

所有 `ajaxError` 处理程序都会被调用，不管完成了什么 AJAX 请求。如果我们必须区分这些请求，我们可以使用传递给处理程序的参数。每次执行 `ajaxError` 处理程序时，都会传递事件对象、`XMLHttpRequest` 对象以及用于创建请求的设置对象。如果请求失败是因为 JavaScript 引发了异常，则异常对象会作为第四个参数传递给处理程序。例如，我们可以将回调限制为仅处理与特定 URL 相关的事件：

```js
$('.log').ajaxError(function(e, xhr, settings, exception) {
  if (settings.url == 'ajax/missing.html') {
    $(this).log('Triggered ajaxError handler for “ajax/missing.html".');
  }
});
```

## .ajaxSend()

| 注册一个处理程序，以在 AJAX 请求开始时调用。

```js
.ajaxSend(handler)
```

|

### 参数

+   处理程序：要调用的函数

### 返回值

用于链式调用的 jQuery 对象。

### 描述

每当 AJAX 请求即将发送时，jQuery 会触发 `ajaxSend` 事件。所有已使用 `.ajaxSend()` 方法注册的处理程序都在此时执行。

要观察此方法的操作，我们可以设置一个基本的 AJAX 加载请求：

```js
<div class="trigger button">Trigger</div>
<div class="result"></div>
<div class="log"></div>

```

我们可以将我们的事件处理程序附加到任何元素上：

```js
$('.log').ajaxSend(function() {
  $(this).log('Triggered ajaxSend handler.');
});
```

现在，我们可以使用任何 jQuery 方法进行 AJAX 请求：

```js
$('.trigger').click(function() {
  $('.result').load('ajax/test.html');
});
```

当用户点击按钮并且 AJAX 请求即将开始时，日志消息将被显示。

所有的`ajaxSend`处理程序都会被调用，无论要发送什么 AJAX 请求。如果我们必须区分这些请求，我们可以使用传递给处理程序的参数。每次执行`ajaxSend`处理程序时，都会传递事件对象、`XMLHttpRequest`对象和在创建请求时使用的设置对象。例如，我们可以限制我们的回调只处理与特定 URL 相关的事件：

```js
$('.log').ajaxSend(function(e, xhr, settings) {
  if (settings.url == 'ajax/test.html') {
    $(this).log('Triggered ajaxSend handler for “ajax/test.html".');
  }
});
```

## .ajaxStart()

| 注册一个处理程序，当第一个 AJAX 请求开始时调用。

```js
.ajaxStart(handler)
```

|

### 参数

+   处理程序：要调用的函数

### 返回值

用于链接目的的 jQuery 对象。

### 描述

每当一个 AJAX 请求即将发送，jQuery 都会检查是否还有其他尚未完成的 AJAX 请求。如果没有进行中的请求，jQuery 就会触发`ajaxStart`事件。所有使用`.ajaxStart()`方法注册的处理程序都会在这个时间点执行。

要观察这种方法的实际应用，我们可以设置一个基本的 AJAX 加载请求：

```js
<div class="trigger button">Trigger</div>
<div class="result"></div>
<div class="log"></div>

```

我们可以将我们的事件处理程序附加到任何元素：

```js
$('.log').ajaxStart(function() {
  $(this).log('Triggered ajaxStart handler.');
});
```

现在，我们可以使用任何 jQuery 方法进行 AJAX 请求：

```js
$('.trigger').click(function() {
  $('.result').load('ajax/test.html');
});
```

当用户点击按钮并且 AJAX 请求被发送时，日志消息将会被显示。

## .ajaxStop()

| 注册一个处理程序，当所有 AJAX 请求都完成时调用。

```js
.ajaxStop(handler)
```

|

### 参数

+   处理程序：要调用的函数

### 返回值

用于链接目的的 jQuery 对象。

### 描述

每当一个 AJAX 请求完成，jQuery 都会检查是否还有其他尚未完成的 AJAX 请求；如果没有，jQuery 就会触发`ajaxStop`事件。所有使用`.ajaxStop()`方法注册的处理程序都会在这个时间点执行。

要观察这种方法的实际应用，我们可以设置一个基本的 AJAX 加载请求：

```js
<div class="trigger button">Trigger</div>
<div class="result"></div>
<div class="log"></div>

```

我们可以将我们的事件处理程序附加到任何元素：

```js
$('.log').ajaxStop(function() {
  $(this).log('Triggered ajaxStop handler.');
});
```

现在，我们可以使用任何 jQuery 方法进行 AJAX 请求：

```js
$('.trigger').click(function() {
  $('.result').load('ajax/test.html');
});
```

当用户点击按钮并且 AJAX 请求完成时，日志消息将被显示。

### 注意

因为`.ajaxStart(), .ajaxStop(), .ajaxSend(), ajaxError()`和`.ajaxComplete()`都作为方法而不是全局函数实现，我们可以像这样使用关键字`this`来引用回调函数中的选定元素。

## .ajaxSuccess()

| 注册一个处理程序，当 AJAX 请求成功完成时调用。

```js
.ajaxSuccess(handler)

```

|

### 参数

+   处理程序：要调用的函数

### 返回值

用于链接目的的 jQuery 对象。

### 描述

每当一个 AJAX 请求成功完成，jQuery 就会触发`ajaxSuccess`事件。所有使用`.ajaxSuccess()`方法注册的处理程序都会在这个时间点执行。

要观察这种方法的实际应用，我们可以设置一个基本的 AJAX 加载请求：

```js
<div class="trigger button">Trigger</div>
<div class="result"></div>
<div class="log"></div>

```

我们可以将我们的事件处理程序附加到任何元素：

```js
$('.log').ajaxSuccess(function() {
  $(this).log('Triggered ajaxSuccess handler.');
});
```

现在，我们可以使用任何 jQuery 方法进行 AJAX 请求：

```js
$('.trigger').click(function() {
  $('.result').load('ajax/test.html');
});
```

当用户单击按钮并且 AJAX 请求成功完成时，将显示日志消息。

### 提示

因为 `.ajaxSuccess()` 被实现为方法而不是全局函数，所以我们可以像这样使用 `this` 关键字来在回调函数中引用所选元素。

所有的 `ajaxSuccess` 处理程序都会被调用，无论完成了什么 AJAX 请求。如果我们必须区分这些请求，我们可以使用传递给处理程序的参数。每次执行 `ajaxSuccess` 处理程序时，它都会传递事件对象、`XMLHttpRequest` 对象和用于创建请求的设置对象。例如，我们可以将我们的回调限制为仅处理涉及特定 URL 的事件：

```js
$('.log').ajaxSuccess(function(e, xhr, settings) {
  if (settings.url == 'ajax/test.html') {
    $(this).log('Triggered ajaxSuccess handler for “ajax/test.html".');
  }
});
```

# 辅助函数

此函数协助执行 AJAX 任务时遇到的常见习语。

## `.serialize()`

| 将一组表单元素编码为提交字符串。

```js
.serialize(param)

```

|

### 参数

无。

### 返回值

包含元素序列化表示的字符串。

### 描述

`.serialize()` 方法使用标准的 URL 编码表示法创建一个文本字符串。它在表示一组表单元素的 jQuery 对象上操作。表单元素可以是几种类型：

```js
<form>
  <div><input type="text" name="a" value="1" id="a" /></div>
  <div><input type="text" name="b" value="2" id="b" /></div>
  <div><input type="hidden" name="c" value="3" id="c" /></div>
  <div><textarea name="d" rows="8" cols="40">4</textarea></div>
  <div><select name="e">
    <option value="5" selected="selected">5</option>
    <option value="6">6</option>
    <option value="7">7</option>
  </select></div>
  <div><input type="checkbox" name="f" value="8" id="f" /></div>
  <div><input type="submit" name="g" value="Submit" id="g">
</form>
```

我们可以在选择它们之后对所有这些元素类型进行序列化：

```js
$('form').submit(function() {
  $(this).log($('input, textarea, select').serialize());
  return false;
});
```

这将生成一个标准的查询字符串。

```js
a=1&b=2&c=3&f=8&g=Submit&d=4&e=5

```

该字符串接近于，但不完全相同于，在正常表单提交期间浏览器将生成的字符串。`.submit()` 方法使用每个元素的 `.name` 和 `.value` 属性来创建字符串，因此在这些属性不反映实际表单值的情况下，字符串可能不正确。例如，上面的示例中的复选框始终具有 `.value` 为 `8` 的值，无论框是否被选中。

为了得到更健壮的解决方案，*form* 插件是可用的。它的方法提供了与浏览器提供的相匹配的编码。


# 第八章：其他方法

> 选择的自由是你获得的
> 
> 选择的自由是你想要的
> 
> - Devo,
> 
> "选择的自由"

在前面的章节中，我们已经审查了许多类别的 jQuery 方法。但是到目前为止，该库提供的一些方法还不属于任何类别。在本章中，我们将探讨用于缩写常见 JavaScript 习语的方法。

# 设置方法

这些函数在主代码体开始之前很有用。

## $.browser

| 包含有关当前运行浏览器的信息。

```js
$.browser

```

|

### 参数

无。

### 返回值

每个用户代理可能的布尔标记。

### 描述

`$.browser`属性允许我们检测访问页面的是哪个 Web 浏览器，如浏览器本身所报告的。它包含每个最常见的浏览器类别——Internet Explorer，Mozilla，Safari 和 Opera 的标志。可以独立测试这些浏览器：

```js
$()
  .log('Safari: ' + $.browser.safari)
  .log('Opera: ' + $.browser.opera)
  .log('MSIE: ' + $.browser.msie)
  .log('Mozilla: ' + $.browser.mozilla);
```

在 Firefox 浏览器上执行时，结果是：

```js
Safari: false
Opera: false
MSIE: false
Mozilla: true

```

这个属性立即可用。因此可以用它来确定是否调用`$(document).ready()`是安全的。

因为`$.browser`使用`navigator.useragent`来确定平台，所以用户可能会伪装它。最好在可能的情况下完全避免特定于浏览器的代码。在需要为不同代理编写它的特殊情况下，最好的选择是测试你想要使用的 JavaScript 功能的存在。如果这不能很好地区分客户端，可以使用`$.browser`属性进行进一步的区分。

## $.noConflict()

| 放弃 jQuery 对`$`变量的控制。

```js
$.noConflict()
```

|

### 参数

无。

### 返回值

全局 jQuery 对象。这可以设置为一个变量，提供一个替代快捷键给`$`.

### 描述

许多 JavaScript 库使用`$`作为函数或变量名，就像 jQuery 一样。在 jQuery 的情况下，`$`只是`jQuery`的别名，所以所有功能都可以在不使用`$`的情况下实现。如果我们需要在 jQuery 旁边使用另一个 JavaScript 库，我们可以通过调用`$.noConflict()`来让`$`的控制权归还给其他库：

```js
// Import other library
// Import jQuery
$.noConflict();
// Code that uses other library’s $ can follow here.

```

这种技术特别适用于`.ready()`方法与`jQuery`对象的别名，因为在`.ready()`中，我们可以使用`$`而不必担心后续的冲突：

```js
// Import other library
// Import jQuery
$.noConflict();
jQuery(document).ready(function($) {
  // Code that uses jQuery’s $ can follow here.
});
// Code that uses other library’s $ can follow here.
```

# DOM 元素方法

这些方法帮助我们处理每个 jQuery 对象下的 DOM 元素。

## .length

| 返回 jQuery 对象匹配的 DOM 元素的数量。

```js
.length

```

|

### 参数

无。

### 返回值

匹配的元素数量。

### 描述

假设页面上有一个简单的无序列表：

```js
<ul>
  <li>foo</li>
  <li>bar</li>
</ul>
```

我们可以通过调用`.length`来确定列表项的数量：

```js
$().log('Length: ' + $('li’).length);

```

## .size()

| 返回 jQuery 对象匹配的 DOM 元素的数量。

```js
.size()
```

|

### 参数

无。

### 返回值

匹配的元素数量。

### 描述

假设页面上有一个简单的无序列表：

```js
<ul>
  <li>foo</li>
  <li>bar</li>
</ul>
```

我们可以通过调用`.size()`来确定列表项的数量：

```js
$().log('Size: ' + $('li’).size());

```

## .get()

| 检索与 jQuery 对象匹配的 DOM 元素。

```js
.get([index])
```

|

### 参数

+   索引（可选）：指示要检索的元素的整数

### 返回值

一个 DOM 元素，或者如果省略索引，则是一组 DOM 元素的数组。

### 描述

`.get()`方法允许我们访问每个 jQuery 对象下面的 DOM 节点。假设我们在页面上有一个简单的无序列表：

```js
<ul>
  <li>foo</li>
  <li>bar</li>
</ul>
```

指定了索引，`.get()`将检索单个元素：

```js
$().log('Get(0): ' + $('li’).get(0));

```

由于索引是从零开始的，因此返回第一个列表项：

```js
Get(0): [object HTMLLIElement]

```

每个 jQuery 对象也都伪装成数组，因此我们可以使用数组解引用运算符来获取列表项：

```js
$().log('Get(0): ' + $('li’)[0]);

```

没有参数时，`.get()`返回正常数组中的所有匹配的 DOM 节点：

```js
$().log('Get(): ' + $('li’).get());

```

在我们的示例中，这意味着返回了所有列表项：

```js
Get(): [object HTMLLIElement],[object HTMLLIElement]

```

## .index()

| 从匹配的元素中搜索给定的 DOM 节点。

```js
.index(node)

```

|

### 参数

+   节点：要查找的 DOM 元素

### 返回值

元素在 jQuery 对象中的位置，如果找不到则为`-1`。

### 描述

与`.get()`相对应的操作，它接受一个索引并返回一个 DOM 节点，`.index()`接受一个 DOM 节点并返回一个索引。假设我们在页面上有一个简单的无序列表：

```js
<ul>
  <li>foo</li>
  <li>bar</li>
</ul>
```

如果我们检索了两个列表项中的一个，我们可以将其存储在一个变量中。然后，`.index()`可以在匹配元素集中搜索此列表项：

```js
var listItem = $('li’)[1];
$().log('Index: ' + $('li’).index(listItem));

```

我们得到了列表项的从零开始的位置：

```js
Index: 1

```

# 集合操作

这些辅助函数操作数组，映射和字符串。

## .each()

| 在集合上进行迭代，在每个项目上触发回调函数。

```js
.each(callback)
$.each(collection, callback)

```

|

### 参数（第一版）

+   回调：要对每个匹配的元素执行的函数

### 返回值（第一版）

jQuery 对象，用于链接目的。

### 参数（第二版）

+   集合：要迭代的对象或数组

+   回调：要在集合中的每个项目上执行的函数

### 返回值（第二版）

集合。

### 描述

`.each()`方法和`$.each()`函数是设计用于创建简洁且不易出错的循环结构的通用迭代器。它们在集合上操作，并且对该集合中的每个项目执行一次回调函数。

上面列出的第一种语法是 jQuery 对象的一种方法，当调用它时，它会迭代对象的一部分 DOM 元素。每次回调运行时，都将当前循环迭代作为参数传递，从`0`开始。更重要的是，回调在当前 DOM 元素的上下文中触发，因此关键字`this`指的是该元素。

假设我们在页面上有一个简单的无序列表：

```js
<ul>
  <li>foo</li>
  <li>bar</li>
</ul>
```

我们可以选择列表项并对它们进行迭代：

```js
$('li’).each(function(index) {
  $(this).log(index + ': ' + $(this).text());
});
```

因此，对列表中的每个项目记录了一条消息：

```js
0: foo
1: bar

```

第二种语法类似，但它是一个全局函数，而不是一个方法。在这种情况下，集合作为第一个参数传递，并且可以是映射（JavaScript 对象）或数组。在数组的情况下，每次回调都会将数组索引和相应的数组值作为参数传递：

```js
$.each([52, 97], function(key, value) {
  $().log(key + ': ' + value);
});
```

这产生了两条消息：

```js
0: 52
1: 97
```

如果作为集合使用映射，每次回调都会把一个键值对传递为参数：

```js
$.each({'flammable’: 'inflammable’, 'duh’: 'no duh’}, function(index, value) {
  $().log(index + ': ' + value);
});
```

再次，这产生了两条消息：

```js
flammable: inflammable
duh: no duh

```

## $.grep()

| 筛选一个数组，只留下所选的项目。

```js
$.grep(array, filter[, invert])

```

|

### 参数

+   数组: 要搜索的数组

+   filter: 要对每个项目应用的测试函数，或包含要用作测试的表达式的字符串

+   invert（可选）：一个布尔值，指示是否倒转过滤条件

### 返回值

新构建的、经过过滤的数组。

### 描述

`$.grep()` 方法根据需要从数组中移除项，以便所有剩余项都通过提供的测试。 测试是一个函数，它以数组项和数组中的索引作为参数； 只有在测试返回 true 时，项才会在结果数组中。

与 jQuery 方法一样，回调函数通常是匿名定义的：

```js
var array = [0, 1, 52, 97];
$(this).log('Before: ' + array);
array = $.grep(array, function(a) {
  return (a > 50);
});
$(this).log('After: ' + array);
```

结果数组中保留了所有大于`50`的项目：

```js
Before: 0,1,52,97
After: 52,97

```

由于过滤函数往往非常简短，jQuery 提供了一个更进一步的快捷方式。 过滤函数可以定义为对数组中的每个项目`a`进行评估的单个表达式：

```js
var array = [0, 1, 52, 97];
$(this).log('Before: ' + array);
array = $.grep(array, 'a > 50’);
$(this).log('After: ' + array);

```

这产生了与以前相同的结果。 通过添加第三个参数，我们可以反转这个测试：

```js
var array = [0, 1, 52, 97];
$(this).log('Before: ' + array);
array = $.grep(array, 'a > 50’, true);
$(this).log('After: ' + array);

```

现在产生了一个小于或等于`50`的项目数组：

```js
Before: 0,1,52,97
After: 0,1

```

## $.map()

| 通过使用一个过滤函数将一个数组转换成另一个数组。

```js
$.map(array, filter)

```

|

### 参数

+   数组: 要转换的数组

+   过滤器: 要应用于每个项的函数，或包含要应用的表达式的字符串

### 返回值

新构建的转换数组。

### 描述

`$.map()` 方法对数组中的每个项目应用一个函数，将结果收集到一个新数组中。 过滤器是一个函数，它以数组项和数组中的索引作为参数。

与 jQuery 方法一样，回调函数通常是匿名定义的：

```js
var array = [0, 1, 52, 97];
$(this).log('Before: ' + array);
array = $.map(array, function(a) {
  return (a - 45);
});
$(this).log('After: ' + array);
```

结果数组中的所有项目都减去了`45`：

```js
Before: 0,1,52,97
After: -45,-44,7,52

```

由于过滤函数往往非常简短，jQuery 提供了一个更进一步的快捷方式。 过滤函数可以定义为应用于数组中每个项目`a`的单个表达式：

```js
var array = [0, 1, 52, 97];
$(this).log('Before: ' + array);
array = $.map(array, 'a - 45’);
$(this).log('After: ' + array);

```

这产生了与以前相同的结果。 通过从过滤函数中返回`null`，我们可以从数组中移除项目：

```js
var array = [0, 1, 52, 97];
$(this).log('Before: ' + array);
array = $.map(array, 'a > 50 ? a - 45 : null’);
$(this).log('After: ' + array);

```

现在产生了一个大于`50`的项目数组，每个都减去了`45`：

```js
Before: 0,1,52,97
After: 7,52

```

如果过滤函数返回的是一个数组而不是一个标量，则返回的数组将连接在一起形成结果：

```js
var array = [0, 1, 52, 97];
$(this).log('Before: ' + array);
array = $.map(array, function(a, i) {
  return [a - 45, i];
});
$(this).log('After: ' + array);
```

而不是二维结果数组，映射形成了一个扁平化的结果：

```js
Before: 0,1,52,97
After: -45,0,-44,1,7,2,52,3

```

## $.merge()

| 将两个数组的内容合并到第一个数组中。

```js
$.merge(array1, array2)
```

|

### 参数

+   array1: 要合并的第一个数组

+   array2: 要合并的第二个数组

### 返回值

由两个提供的数组元素组成的数组。

### 描述

`$.merge()` 操作形成一个包含两个数组中所有元素的数组，重复项已被移除。第一个数组中的项目顺序被保留，第二个数组中的项目被附加：

```js
var array1 = [0, 1, 52];
var array2 = [52, 97];
$(this).log('Array 1: ' + array1);
$(this).log('Array 2: ' + array2);
array = $.merge(array1, array2);
$(this).log('After: ' + array);

```

结果数组包含所有四个不同的项目：

```js
Array 1: 0,1,52
Array 2: 52,97
After: 0,1,52,97

```

`$.merge()` 函数是破坏性的。它修改第一个参数以添加第二个参数中的项目。如果需要原始的第一个数组，在调用 `$.merge()` 之前复制它。幸运的是，`$.merge()` 本身可以用于这种复制：

```js
var newArray = $.merge([], oldArray);

```

这个快捷方式创建一个新的空数组，并将 `oldArray` 的内容合并到其中，从而有效地克隆数组。

## $.unique()

| 创建一个删除重复项的对象数组的副本。

```js
$.unique(array)
```

|

### 参数

+   数组：对象数组

### 返回值

仅由唯一对象组成的数组。

### 描述

`$.unique()` 函数搜索对象数组，形成一个不包含重复对象的新数组。如果两个对象引用内存中的不同位置，则认为它们是不同的对象，即使它们的内容相同也是如此。原始数组不会被修改。数组可以包含任何类型的 JavaScript 对象：

```js
var alice = {'alice’: 'alice’};
var bob = {'bob’: 'bob’};
var carol = {'carol’: 'carol’};
var ted = {'bob’: 'bob’};
var oldArray = [alice, bob, carol, bob, ted];
$(this).log('Before: ' + oldArray);
newArray = $.unique(oldArray);
$(this).log('After: ' + newArray);

```

结果数组仅包含四个不同的项目：

```js
Before: {alice: alice}, {bob: bob}, {carol: carol},
  {bob: bob}, {bob: bob}
After: {alice: alice, mergeNum: 52}, {bob: bob, mergeNum: 52},
  {carol: carol, mergeNum: 52}, {bob: bob, mergeNum: 52}
```

结果数组中移除了第二个名为 `bob` 的对象实例。但是，名为 `ted` 的对象保留了下来，即使它具有相同的内容，因为它是作为单独的对象创建的。

注意，`$.unique()` 修改数组中的对象，为每个对象添加了一个名为 `mergeNum` 的额外属性。这个属性是函数实现的副作用，并且对调用代码没有用处。

## $.extend()

| 将两个对象的内容合并到第一个对象中。

```js
$.extend([target, ]properties[, ...])

```

|

### 参数

+   目标（可选）：将接收新属性的对象

+   属性：包含要合并的其他属性的对象

### 返回值

修改后的目标对象。

### 描述

`$.extend()` 函数以与 `$.merge()` 合并数组相同的方式合并两个对象。将第二个对象的属性添加到第一个对象中，创建一个具有两个对象所有属性的对象：

```js
var object1 = {
  apple: 0,
  banana: 52,
  cherry: 97
};
var object2 = {
  banana: 1,
  durian: 100
};

$().log(object1);
$().log(object2);
var object = $.extend(object1, object2);
$().log(object);
```

第二个对象中的 `durian` 的值被添加到第一个对象中，而 `banana` 的值被覆盖：

```js
{apple: 0, banana: 52, cherry: 97, }
{banana: 1, durian: 100, }
{apple: 0, banana: 1, cherry: 97, durian: 100, }

```

`$.extend()` 函数是破坏性的；目标对象在过程中被修改。这通常是期望的行为，因为 `$.extend()` 可以用来模拟对象继承。添加到对象的方法可供所有引用对象的代码使用。然而，如果我们想保留原始对象的副本，我们可以通过将空对象作为目标来实现：

```js
var object = $.extend({}, object1, object2)

```

我们还可以向 `$.extend()` 提供两个以上的对象。在这种情况下，所有对象的属性都将添加到目标对象中。

如果给`$.extend()`提供了一个参数，这意味着目标参数被省略了。在这种情况下，jQuery 对象本身被假定为目标。通过这样做，我们可以向 jQuery 命名空间添加新功能。在讨论如何创建 jQuery 插件时，我们将探讨这种能力。

`$.extend()`执行的合并不是递归的；如果第一个对象的属性本身是对象或数组，则它将被第二个对象中具有相同键的属性完全覆盖。值不会合并。

## $.trim()

| 从字符串的两端删除空白。

```js
$.trim()

```

|

### 参数

+   string：要修剪的字符串

### 返回值

修剪后的字符串。

### 描述

`$.trim()`函数从提供的字符串的开头和结尾删除所有换行符、空格和制表符：

```js
var string = "\tYes, no, I, this is. \n ";
$(this).log('Before: ' + string);
string = $.trim(string);
$(this).log('After: ' + string);

```

所有空白字符都被修剪：

```js
Before: 	Yes, no, I, this is. 

After: Yes, no, I, this is.
```
