# jQuery 游戏开发基础（三）

> 原文：[`zh.annas-archive.org/md5/7D66632184130FBF91F62E87E7F01A36`](https://zh.annas-archive.org/md5/7D66632184130FBF91F62E87E7F01A36)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：制作您的游戏移动端

移动设备正在迅速成为游戏的首选平台。好消息是，大多数这些设备中的 Web 浏览器都相当不错，在大多数情况下，您可以使您的移动游戏在其上顺利运行。

但是，这些设备具有一些内存和电源限制。目前有一些游戏在移动浏览器上根本无法运行。您不能指望在智能手机上运行和桌面计算机性能只有十分之一的设备上顺畅运行同样数量的精灵。

移动设备的一个优点是，它提供了一些通常在桌面上找不到的功能：

+   多点触摸界面允许您以新的方式与您的游戏互动

+   设备方向 API 允许您以有趣的方式控制您的游戏或 UI。

+   大多数设备允许您的游戏像原生应用一样安装到“springboard”，模糊了浏览器游戏和原生游戏之间的界线。

+   离线缓存允许您的游戏即使在设备上没有活动的互联网连接时也能工作。

在本章中，我们将采取我们的 MMORP 并使其在 iOS 设备上运行。我们将使用的大多数 API 都是事实上的标准，并且也支持 Android。以下是我们将要涵盖的主题的简要概述：

+   处理移动设备的性能限制

+   为我们的游戏添加多点触控控制

+   将我们的游戏与 springboard 和其他移动特定配置集成

+   使用设备方向 API

+   利用 Web 存储和离线应用缓存

我们选择只考虑 iOS 方面的原因有几个：

+   尽管安卓最近赶上了，但 iOS 仍然是全球使用最广泛的移动操作系统（根据来源和什么被认为是移动设备，您会发现 iOS 的市场份额在 30% 到 50% 之间）。

+   即使苹果选择禁止第三方浏览器进入其操作系统在某种程度上引起了争议，但它具有积极的副作用，即使 Web 开发变得更加容易。实际上，您不必在浏览器端处理太多的差异。

+   移动浏览器上可用的大多数特定 API 首先是由苹果在 Webkit 移动端上创建或实现的。

在我们开始之前，我想强调这一点，这是一个比 Web 开发世界其他领域发展得更快的领域。新的 API 定期添加，每个新设备的性能明显优于其替代品。如果您认真考虑制作充分利用移动设备的游戏，您应该投入一些时间来使自己了解这些变化。

# 使您的游戏在移动设备上运行良好

性能问题可能是开发基于浏览器的移动游戏时会遇到的最大问题，主要原因是有各种各样的设备可用，每个设备的功能都非常不同。

即使你选择仅支持 iOS，这可能是目前最简单的生态系统，你仍然会在性能、屏幕分辨率和浏览器支持方面有很大的差异。

为了了解情况的复杂性，可以查看 jQuery Mobile 支持的设备（[`jquerymobile.com/gbs/`](http://jquerymobile.com/gbs/)）。对于你的游戏，你可能应该有一个类似于他们的方法；选择几个设备/软件版本作为目标。你的游戏应该在这些设备上无缝运行。

然后确保游戏在更广泛的设备上无错误运行。在这些设备上，性能可能不理想。最后，明确划定一个线，超过这条线你甚至都不会去测试游戏是否能够运行。

每个类别的大小将取决于你想要投入多少精力。一个问题是你实际上不能使用每个平台 SDK 提供的模拟器来调查性能问题。这意味着最终你将不得不在实际设备上测试你的游戏。

这对于大公司来说不是问题，但如果你是一个小型独立游戏开发者，你可能会发现这是一个限制你支持的设备数量的因素。

## 检测移动浏览器

为了应对桌面和移动设备之间的差异，有许多可能的方法：

1.  只设计一个游戏，专注于移动设备。它也可以在桌面上毫无问题地运行，但可能不像专门为桌面设计的那样美观或复杂。好处是，如果玩家在你的游戏中相互竞争，他们都将处于同一水平。

1.  设计两个游戏，一个优化用于桌面，一个用于移动。这几乎是两倍的工作量，但你可能会共享大部分艺术、音乐和服务器端代码（如果有）。从性能上讲，这是理想的解决方案，但如果你的游戏中有 PvP（玩家对玩家），那么在一个平台上的玩家与其他平台上的玩家相比可能更具优势。

1.  如果游戏在桌面浏览器上运行，你可以只设计一个游戏，但是增加一些纯粹的装饰性功能。通过这种解决方案，你只需要一个代码库，但可能会稍微复杂一些。PvP 游戏的问题仍然存在。

你将选择遵循的方法将取决于你的优先级，但对于第二和第三种方法，你需要检测玩家运行游戏的平台类型。

根据你想要多精确，这可能是一个相当复杂的任务。基本上有两种一般的方法可以使用：客户端检测和服务器端检测。

### 客户端浏览器检测

如果你想要实现之前描述的第三种方法，即在客户端检测浏览器，那么这是非常合理的。最常见的方法是使用`navigator.userAgent`字符串（**UA**简称）。这个变量包含一个非常长和晦涩的字符串，其中包含了大量信息。

需要记住的是浏览器可以伪造这个字符串（这被称为**UA 伪装**）。例如，在 Safari 中，你可以指定它模仿哪个浏览器。好处是移动设备通常不会在用户部分进行某些黑客行为。此外，一些非常不同的移动设备具有相同的 UA，例如桌面和移动版本的 Internet Explorer。

其中很大一部分是出于遗留原因，你真的不应该关心它，但通过查看这个更长字符串中特定字符串的出现，你可以检测到你正在处理的浏览器的类型。例如，如果`userAgent`字符串包含`iPhone`，你就知道浏览器是在 iPhone 上运行的 Safari 移动版。相应的 JavaScript 代码可能如下所示：

```js
if(navigator.userAgent.match(/iPhone/i)){
    // iPhone detected
    // ...
} else {
   // not an iPhone
}
```

现在这对于 iPhone 可能有效，但如果你的用户使用的是 iPad，则不会被检测到。你必须查找字符串`iPad`来检测 iPad。对于 iPod Touch 也是一样，你必须查找`iPod`。如果你想区分 iDevices 和其他设备，你可以这样做：

```js
if(navigator.userAgent.match(/iPhone|iPod|iPad/i){
    // iDevice detected
    // ...
} else {
   // not an iDevice
}
```

如果你希望精确检测各个设备，你应该使用以下代码：

```js
if(navigator.userAgent.match(/iPhone/i)){
  // iPhone detected
} else if(navigator.userAgent.match(/iPad/i)) {
 // iPad detected
} else if(navigator.userAgent.match(/iPod/i)) {
 // iPod touch detected
} else {
   // not an iDevice
}
```

正如你所想象的，如果你想要检测大量设备，这个列表可能很快变得相当长。希望存在着确切完成你目标的代码片段。如果你只想检测移动设备，你可以使用 [`detectmobilebrowsers.com/`](http://detectmobilebrowsers.com/) 提供的脚本。如果你想更精确地控制你要检测的内容，你可以使用由总是出色的 Peter-Paul Koch 提供的脚本，网址为 [`www.quirksmode.org/js/detect.html`](http://www.quirksmode.org/js/detect.html)。

### 服务器端检测

如果你想要实现第二种方法（为移动和桌面浏览器提供不同版本的游戏），你可能会想要在服务器上检测玩家的浏览器，并将他们重定向到游戏的正确版本。与客户端检测一样，最常见的技术使用浏览器的`userAgent`字符串。

如果你使用 PHP，你会很高兴地了解到它几乎支持开箱即用的浏览器检测。实际上，你可以使用 `get_browser` 函数与一个最新的 `php_browscap.ini` 文件结合使用，以获取有关浏览器的信息（你可以在 [`tempdownloads.browserscap.com/`](http://tempdownloads.browserscap.com/) 找到各种版本的此文件）。你将不得不在你的 `php.ini` 文件中配置 `browscap` 属性，将其指向你的 `php_browscap.ini` 文件，以便它被识别。复制我们先前实现的客户端检测的代码将如下所示：

```js
$browser = get_browser(null);

if($browser->platform == "iOS"){
  echo "iOS";
} else {
  echo "not iOS";
}
```

这与客户端实现具有相同的缺点：浏览器可以伪造 `userAgent` 字符串。

### 你真的需要检测浏览器吗？

通常不建议检测浏览器。首选解决方案通常是使用功能检测。例如，如果你想使用设备方向，那么你只需在运行时检查相应的 API 是否可用，这样做真的很有意义。

在这种情况下，这是一种更为健壮的方法，但我们讨论的是对游戏性能的优化。没有可以检测的特性会提供有关这方面的信息。在这种情况下，我认为检测浏览器是有意义的。

更健壮的替代方案是在开始游戏之前运行一个非常快速的基准测试，以推断游戏运行的设备的性能。这将是很多工作，但在可以线性地扩展游戏性能的情况下，这样做可能是值得的。例如，你可以非常精细地定义绘制森林所使用的树的数量，比如，最大树数的 80%。

如果你使用了大量的粒子效果，通常就会出现这种情况。然后，非常容易调整你使用的粒子总数以匹配设备的性能。

## 性能限制 - 内存

现在我们能够检测到游戏在移动设备上运行，我们将能够适应设备的限制。谈论性能时，你脑海中可能首先浮现的是处理器的速度，但大多数情况下，内存是一个更大的限制。

在桌面上，你不再需要考虑内存，大多数情况下（除了避免内存泄漏）。在移动设备上，内存是一种更为有限的资源，有时，仅仅加载一个大图像对浏览器来说就太多了。例如，对于 iDevices，允许的最大图像尺寸如下：

|   | **< 256 MB 的 RAM** | **> 256 MB 的 RAM** |
| --- | --- | --- |
| **GIF、PNG 和 TIFF 图像** | 3 百万像素 | 5 百万像素 |
| **JPEG** | 32 百万像素 | 32 百万像素 |
| **Canvas DOM 元素** | 3 百万像素 | 5 百万像素 |

需要注意的是，这与图像的压缩毫无关系。事实上，尽管压缩图像以减少下载所需的时间对内存印记很重要，但唯一重要的是分辨率。

所以，如果压缩不会有所帮助，我们该怎么办呢？让我们以我们的多人在线角色扮演游戏为例。在那里，我们使用了一个非常大的图像，其中包含我们瓦片地图的所有图块。实际上，我们游戏中创建的地图并未使用许多这些图块。因此，减少这个非常大的图像的一个非常简单的方法是删除我们不需要的所有图块。

这意味着，您不再拥有一个整个游戏都会使用的大图像，而是为每个区域都有一个较小的图像。这将增加代码的复杂性，因为它意味着管理区域之间的过渡，但它有一个优点，即完全不会降低您的级别设计。

在某些情况下，即使使用这种技术，您可能会发现很难将图像的大小减小到足够小。一个简单的解决方案是为桌面和移动平台分别设置两个版本的级别。在移动版本中，您将减少图块的种类。例如，在我们的游戏中，我们使用多个图块来渲染草地，如下图所示：

![性能限制 - 内存](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_09_01.jpg)

在这里，我们可以简单地使用一个单一的图块。当然，生成的图形将会变得不那么多样化，但它将大大减少您所需的图块数量。然而，这种做法的缺点是需要您维护每个级别的两个单独版本。

## 性能限制 - 速度

移动设备的性能差异很大，但即使是最快的移动设备也比任何桌面设备都要慢得多。这意味着有些游戏根本无法在移动设备上运行，无论您付出多少努力。然而，有许多游戏可以稍加改造，使其以合理的速度运行。

制作基于 DOM 的游戏时，您可以加快速度的地方并不多。您应该做的第一件事是尝试减少精灵或图块的数量。

### 指定页面的可见区域

减少图块数量的一个非常简单的方法是使游戏区域更小。您可能会认为这是一个非常糟糕的主意，因为您真正想要的是游戏区域填满整个屏幕，这意味着要适应设备的分辨率。好吧，是的...也不是！是的，您希望游戏区域填满整个屏幕，但不，这并不一定意味着使用完整的分辨率。

移动浏览器提供了一个非常方便的`meta`属性，允许您指定浏览器应该如何管理页面宽度。这在这里将非常有用，因为我们基本上可以选择游戏区域的大小，然后强制浏览器将其显示在全屏模式下。

这个属性称为视口，要为屏幕指定一个给定的宽度，您可以简单地写：

```js
<meta name="viewport" content="user-scalable=no, width=480" />
```

我们在这里配置了两种不同的行为。首先，我们告诉浏览器页面的原始宽度为 480 像素。假设设备的原生分辨率为 960 像素；这意味着页面将被放大。如果设备分辨率为 320 像素，页面将被缩小。

我们在这里做的第二件事是禁用用户的缩放功能。如果你想后续使用触摸事件来控制游戏，这是不必要的；为了控制游戏，你要确保用户在尝试操作游戏时不会放大或缩小页面。

### 细节级别

减少精灵的数量可能会很棘手。例如，你不希望减少游戏中的 NPC（非玩家角色）或敌人的数量。识别可以移除的元素是一项繁琐的任务。

以下图片摘自 第五章，*透视*。这是我们为我们的 RPG 使用的瓦片地图的结构的快速提醒。

![细节级别](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_09_02.jpg)

如果你将这个图中最后两层中纯装饰性的元素保留下来，减少精灵的数量就变得很容易；如果需要，只需删除这两层，就完成了。

这并不一定意味着你必须摆脱所有这些元素。你可以做的是有两个不同版本的这些层，一个有很多元素，一个元素更少。

如果你真的需要进一步减少精灵的数量，你将不得不考虑这将对游戏玩法产生的影响。这里没有标准答案；你将需要针对每个游戏进行独立的处理，并在保持游戏玩法与游戏速度之间找到正确的平衡。

# 触摸控制

到目前为止，我们只谈到了移动设备的问题部分，但是这些设备也带来了一些优势。触摸屏允许非常有趣的游戏机制（而且多点触摸屏效果更好）。

在这一部分，我们将实现两种不同的触摸控制方式，但这确实是一个可以发挥创意、找到新颖而引人入胜的方式让玩家与你的游戏进行交互的领域。重要的是要知道触摸控制的 API 不是标准的，而且移动设备可能会以一些不同的方式实现它。尽管如此，下一节中显示的代码应该可以在 iOS 和最新版本的 Android 上正常工作。

我们将实现的两个界面都基于同样的基本思想：整个屏幕都是一个摇杆，没有可见的 UI 元素被使用。这样做的优势是，用于控制的表面越大，控制就越精确。缺点是，如果用户不是通过简单地看屏幕就能发现它是如何工作的，你就需要解释给用户听。

我们使用的代码可以很容易地调整为适用于放置在屏幕底部/侧边的较小控件。

## 十字键

方向键（缩写为 D-pad）是一种在老式游戏机上使用的控制方式。它提供了几个预定义的方向供用户选择（例如，上、下、左和右）。相比之下，摇杆提供了一个模拟接口，玩家可以选择精确的方向（例如，30 度角度）。我们将要实现的第一个控制方法将屏幕划分为如下图所示的五个区域：

![方向键](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_09_03.jpg)

优点在于此方法与键盘控制有一一对应关系。如果玩家触摸**上**区域，它将对应于按下键盘上的上箭头，其他边界区域类似。如果玩家触摸中心区域，它将对应于按下空格键。

要实现这一点，我们将创建五个虚拟键，并扩展检查键盘输入的代码部分以进行检查。下面的代码摘录是定义这些虚拟键的部分：

```js
var UP = {
  on: false,
  id: 0
};
var DOWN = {
  on: false,
  id: 0
};
var LEFT = {
  on: false,
  id: 0
};
var RIGHT ={
  on: false,
  id: 0
};
var INTERACT ={
  on: false,
  id: 0
};
```

如您所见，这些键具有 ID 字段。这是必要的，因为我们正在处理多点触摸事件，我们必须能够识别哪些触摸事件结束时将`on`字段切换回`false`，玩家抬起手指时。

为了检测玩家触摸屏幕，我们将注册一个`touchstart`事件处理程序。这个事件类似于`onmousedown`事件，除了它包含一个触摸列表。这是有道理的，因为我们正在处理多点触摸输入，我们不能简单地假设只有一个手指触摸屏幕。

所有这些触摸都存储在`event.changedTouches`数组中。在您的事件处理程序中，您只需查看每个触摸。下面的代码摘录是整个事件处理程序：

```js
document.addEventListener('touchstart', function(e) {
  if(gameStarted){
    e.preventDefault();
 for (var i = 0; i < e.changedTouches.length; i++){
      var touch = e.changedTouches[i]

       var x = touch.pageX - 480 / 2;
       var y = touch.pageY - 320 / 2;

       if (Math.abs(x) < 20 && Math.abs(y) < 20){
         INTERACT.on = true;
         INTERACT.id = touch.identifier;

       } else if (Math.abs(x) > 480 / 320 *  Math.abs(y)) {
         // left or right
         if(x > 0){
           RIGHT.on = true;
           RIGHT.id = touch.identifier;
         } else {
           LEFT.on = true;
           LEFT.id = touch.identifier;
         }
       } else {
         // up or down
         if(y > 0){
           DOWN.on = true;
           DOWN.id = touch.identifier;
         } else {
           UP.on = true;
           UP.id = touch.identifier;
         }
       }
     }
    }
}, false);
```

由于"jQuery 核心"不支持触摸事件，我们使用标准方法来注册事件处理程序。然后我们阻止事件冒泡，以确保它们不会产生缩放、滚动等。此事件处理程序的最后一部分检查每个触摸，以确定它在哪个区域，将相应按键的`on`标志切换为`true`，并设置正确的`id`值以进行跟踪。

现在我们需要能够检测触摸何时结束。这通过`touchend`事件完成。这个事件的工作方式类似于`touchstart`，事件处理程序的代码结构相同。在这里，我们不需要担心触摸的位置，而只需要关注其 ID。然后，我们将相应触摸的`on`标志切换回`false`。

```js
document.addEventListener('touchend', function(e) {
  if(gameStarted){
    e.preventDefault();

    for (var i = 0; i < e.changedTouches.length; i++){
        var touch = e.changedTouches[i]
        if (touch.identifier === UP.id){
         UP.on = false;
        } 
        if (touch.identifier === LEFT.id){
         LEFT.on = false;
        }
        if (touch.identifier === RIGHT.id){
         RIGHT.on = false;
        }
        if (touch.identifier === DOWN.id){
         DOWN.on = false;
        }
        if (touch.identifier === INTERACT.id){
         INTERACT.on = false;
        }
     }
  }
}, false);
```

现在我们的虚拟键持有正确的值，我们可以像使用保存真实键状态的数组一样在我们的代码中使用它们。下面的代码正是如此；修改部分已经突出显示：

```js
var gameLoop = function() {
    var idle = true;

    if(gf.keyboard[37] || LEFT.on){ //left arrow
        player.left();
     idle = false;
    }
    if(gf.keyboard[38] || UP.on){ //up arrow
     player.up();
     idle = false;
    }
    if(gf.keyboard[39] || RIGHT.on){ //right arrow
        player.right();
        idle = false;
    }
    if(gf.keyboard[40] || DOWN.on){ //down arrow
     player.down();
     idle = false;
    }
    if(gf.keyboard[32] || INTERACT.on){ //space
        player.strike();
        idle = false;
    }
    if(idle){
        player.idle();
    }

    // ...
};
```

通过这些简单的修改，我们已经实现了我们的触摸控制的第一个版本。

## 模拟摇杆

之前的控制方法不错，但您可能想要让玩家以更自然的方式移动角色。这就是下面的方法发挥作用的地方。这里，我们只有两个区域：中心的一个小区域，它的作用类似于空格键，以及屏幕的其余部分。下图显示了这两个区域：

![模拟摇杆](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_09_04.jpg)

如果玩家触摸这个更大的区域，角色将朝触摸的方向移动。如果玩家的手指改变方向，角色的移动也会相应改变，如下图所示：

![模拟摇杆](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_09_05.jpg)

要实现这一点，我们稍微改变了玩家控制的方式，因此我们在`player`对象中添加了一个新方法：`direction`。该函数接受以度为单位的角度，并推断出最合适的动画，以及玩家的新位置。下面的代码显示了这个函数：

```js
this.move = function(angle){
  if(state !== "strike"){
 var xratio = Math.cos(angle);
 var yratio = Math.sin(angle);
    if(Math.abs(xratio) > Math.abs(yratio)){
      if(xratio < 0){
        this.left();
      } else {
        this.right();
      }
    } else {
      if (yratio < 0){
        this.up();
      } else {
        this.down();
      }
    }
 moveX = 3*xratio;
 moveY = 3*yratio;
    }
};
```

这里只有一小段代码值得指出，如前面的片段所示。要从角度计算垂直和水平移动，我们使用正弦和余弦函数。它们的含义在下图中解释：

![模拟摇杆](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_09_06.jpg)

这两个函数将给我们一个介于-1 和 1 之间的数字，表示玩家应该沿每个轴移动多少。然后我们简单地将这个数乘以最大移动量（在我们的例子中为 3）来获得沿每个轴的实际移动。

我们不需要支持玩家尝试使用键盘和触摸屏控制游戏的情况，因为这种情况是非常不可能发生的。

### 事件处理程序

现在我们将使用一种与之前使用的虚拟键类似的模式，这里我们只会有两个。一个将与以前相同：交互键。第二个有点特殊，因为它将用于存储角度，该角度是角色应该移动的方向。

`touchstart` 事件处理程序与之前几乎相同，只是我们计算了触摸点和屏幕中心之间的角度：

```js
document.addEventListener('touchstart', function(e) {
  if(gameStarted){
     for (var i = 0; i < e.changedTouches.length; i++){
       var touch = e.changedTouches[i];
       var x = touch.pageX - 480 / 2;
         var y = touch.pageY - 320 / 2;
       var radius = Math.sqrt(Math.pow(x,2)+Math.pow(y,2));

       if(radius < 30) {
         INTERACT.on = true;
         INTERACT.id = touch.identifier;
       } else if(!MOVE.on){
         MOVE.on = true;
         MOVE.id = touch.identifier;
         MOVE.angle = Math.atan2(y,x);
       }
     }
    }
}, false);
```

为此，我们使用另一个三角函数：余切。这个函数允许我们检索右角三角形的两条边之间的角度，如下图所示：

![事件处理程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_09_07.jpg)

`touchend` 处理程序与之前的处理程序相同，但适用于两个虚拟键。

```js
document.addEventListener('touchend', function(e) {
  if(gameStarted){
     for (var i = 0; i < e.changedTouches.length; i++){
       var touch = e.changedTouches[i]
        if (touch.identifier === INTERACT.id){
         INTERACT.on = false;
        }
       if (touch.identifier === MOVE.id){
         MOVE.on = false;
        } 
     }
    }
}, false);
```

我们需要第三个事件处理程序来跟踪手指在触摸开始和结束之间的移动。此处理程序的结构与`touchend`的结构类似，但更新了`MOVE`虚拟键的角度：

```js
document.addEventListener('touchmove', function(e) {
  if(gameStarted){
    e.preventDefault();
     for (var i = 0; i < e.changedTouches.length; i++){
       var touch = e.changedTouches[i];
       if (touch.identifier === MOVE.id){
         var x = touch.pageX - 480 / 2;
         var y = touch.pageY - 320 / 2;
         MOVE.angle = Math.atan2(y,x);
        } 
     }
    }
}, false);
```

通过这三个事件处理程序，我们实现了新的控制界面。您真的必须尝试它们，看看哪种方法更适合您。这些方法实际上只是许多其他方法中的两种，选择合适的方法将对您的游戏在移动设备上的成功产生重大影响，因此在选择最终方法之前，请毫不犹豫地尝试很多方法！

# 将我们的游戏与主屏幕集成

有一种非常优雅的方法可以使您的游戏在 iOS 上全屏运行。通过适当的配置，我们可以使您的游戏可安装到 SpringBoard 上。这将产生几个效果：游戏将在没有任何浏览器 UI 元素的情况下运行，并且将具有一个图标和一个启动画面。

所有这些都是通过在文档标头中设置一系列`meta`标签来完成的。

## 使您的游戏可安装

要使您的游戏可安装，您必须在文档头部使用`apple-mobile-web-app-capable` `meta`标签，并将值设置为`yes`。一旦完成这个步骤，玩家就可以从 Safari 将游戏添加到 SpringBoard，如下面的截图所示：

![使您的游戏可安装](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_09_08.jpg)

您应该在标头中拥有的代码如下所示：

```js
<meta name="apple-mobile-web-app-capable" content="yes" />
```

以这种方式安装的网页将在没有任何可见浏览器 UI 元素（也称为 Chrome）的情况下运行。以下图列出了所有 UI 元素的名称：

![使您的游戏可安装](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_09_10.jpg)

遗憾的是，在撰写本文时，这个属性在安卓手机上的支持并不好。其中一些手机会将网页安装到主屏幕并使用自定义图标，但不接受无 Chrome 模式。其他手机将完全忽略它。 

## 配置状态栏

一旦从 SpringBoard 启动，唯一剩下的 UI 元素就是状态栏。如前面的图所示，它是屏幕顶部的栏，显示诸如网络接收和名称以及剩余电量等信息。

您可以选择状态栏的外观，使其尽可能地适合您的应用程序。这可以通过`apple-mobile-web-app-status-bar-style` `meta`标签完成。

以下列表列出了您可以为此标签指定的可能值及其相应的效果：

+   `default`：如果您不使用这个`meta`标签或给它赋予这个值，则将状态栏的外观选择留给操作系统。

+   `black`: 使用这个值，状态栏将具有黑色背景和白色文本。

+   `black-translucent`: 使用这个值，状态栏将具有略带透明的黑色背景和白色文本。这个设置的特殊之处在于网页将被渲染在状态栏下面。这样做的好处是为游戏提供完整的设备分辨率；而使用其他设置，网页将在屏幕顶部丢失一些像素。

您应该在标头中拥有的代码如下所示：

```js
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent" />
```

## 指定应用程序图标

如果您没有指定任何内容，iOS 将使用网页的屏幕截图作为图标。如果您想指定一个要替代使用的图标，则需要使用一个或多个`link`标签。问题在于不同的 iDevices 需要不同大小的图标。解决方案是在`link`标签中指定图标的大小，如下所示：

```js
<link rel="apple-touch-icon" sizes="72x72" href="icon.png" />
```

可能的尺寸是：57 x 57、72 x 72、114 x 114 和 144 x 144。您使用此标签指定的图标将被覆盖上一种光泽效果。如果您希望您的图标原样使用，可以改用`rel`标签`apple-touch-icon-precomposed`。

## 指定闪屏

当用户启动游戏时，页面加载期间将显示一个屏幕截图。如果您希望指定一张图像，可以使用一个带有`rel`标签`apple-touch-startup-image`的`link`标签。

我们将遇到与图标相同的问题：每个设备都有另一个屏幕分辨率，应该使用相应的图像。但是，用于指定图像分辨率的方法与图标的方法不同。在这里，您需要使用`media`属性。

使用`media`属性，您可以使用`device-width`指定设备宽度，使用`orientation`指定设备方向，使用`-webkit-device-pixel-ratio`指定设备是否使用视网膜显示。完整的示例如下：

```js
<link href="startup-image.png" media="(device-width: 320px) and (orientation: portrait) and (-webkit-device-pixel-ratio: 2)" rel="apple-touch-startup-image">
```

# 使用设备方向

在某些情况下，访问设备方向可能很有用。例如，您可以使用它来控制角色的移动。要做到这一点，您可以简单地注册一个事件处理程序，每当设备方向更改时就会收到一个事件。以下代码正是如此：

```js
if(window.DeviceOrientationEvent) {
  window.addEventListener("deviceorientation", function(event){
    var alpha = event.alpha;
     var beta = event.beta;
     var gamma = event.gamma;
     // do something with the orientation
  }, false);
}
```

第一个`if`语句是用来检查设备是否支持设备方向 API 的。然后我们注册一个事件处理程序来访问设备的方向。这个方向由三个角度提供：`alpha`是绕 z 轴的旋转，`beta`是绕 x 轴的旋转，而`gamma`是绕 y 轴的旋转。

您已经知道 x 和 y 轴是什么；它们与我们用来定位游戏元素的轴相同。z 轴是一个指向玩家的屏幕外的轴。

以下图显示了这些轴及其相应的角度：

![使用设备方向](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060OT_09_09.jpg)

# 使用离线应用程序缓存

移动设备的一个非常有用的功能是网页可以脱机工作。对于我们之前创建的平台游戏，这意味着一旦安装，您就再也不需要网络连接来加载游戏资产了。

要启用离线模式，您需要创建一个名为清单的文件。清单是游戏所需的所有文件的列表。它们将在春板上安装游戏时在设备上本地存储。

此清单的格式如下：

```js
CACHE MANIFEST

CACHE:
tilesheet.png
level.json
gameFramework.js
rpg.js
jquery.js

NETWORK:
*
```

`CACHE`部分列出了所有要本地存储的文件。`NETWORK`部分列出了当应用程序在线时可访问的所有外部资源。如果您不想限制网络访问，可以像前面的示例中一样简单地写`*`。

要将清单链接到您的游戏中，您将使用以下属性为您的`html`标记：

```js
<html manifest="pathto/manifestFiles">
```

清单必须由服务器以 MIME 类型`text/cache-manifest`提供。

你必须意识到，一旦使用这样一个清单安装了应用程序，即使服务器上的应用程序发生了变化，游戏文件也不会被更新。强制刷新资源的唯一方法是更改清单本身。如果你不真的需要更改清单，你可以简单地在注释中写上版本号或时间戳；这就足够触发刷新。

另一种可能性是在静态媒体中添加版本号。这将有助于避免 iOS 中静态文件未能正确刷新的一些错误。

# 使用 Web 存储

然而，在一些情况下，你的应用程序需要将信息传输到服务器，例如，当玩家获得高分时。如果此刻游戏正在离线模式下运行，你该怎么办？

解决方案是使用 Web 存储。我们不会详细介绍你可以用 Web 存储做什么，但基本思想是在本地存储所有你想发送到服务器的信息，并在游戏再次在线时传输它。这项技术是 HTML5 规范的一部分，因此只有现代浏览器支持。你可以用它来保存数据的可用空间为 5MB，所以你必须明智地使用它。

要在客户端存储任何值，你可以简单地使用`sessionStorage`对象的`setItem`方法。要检索该值，你可以使用`getItem`方法。

以下代码正是显示这一点：

```js
sessionStorage.setItem('key','value');
sessionStorage.getItem('key');
```

现在，如果你想检查游戏是否在线，你可以使用`navigator`对象上的`onLine`标志，如下所示：

```js
if(navigator.onLine){
  // push data to the server
}
```

对于我们的 RPG 游戏来说，你可能希望在本地存储玩家位置和其击败的敌人，并在 Internet 连接恢复后将它们推送到服务器。

# 摘要

在本章中，你已经学习了许多仅适用于移动设备的特定 API 和技术。使用 Web 技术为移动设备编写游戏通常是一个挑战，但会极大地增加你的游戏潜在玩家数量。

甚至可以通过使用 PhoneGap（又名 Apache Cordova）在 App Store 上分发你的游戏。

在下一章中，我们将学习如何将声音和音乐添加到你的游戏中。使用 Web 技术来做这件事情可能有些麻烦，但它绝对是值得的！


# 第十章：发出一些声音

这是本书的最后一章，但这远非不重要的主题。音乐和音效是游戏用户体验的重要组成部分。合适的音乐可以完全改变关卡的感觉。合适的音效可以帮助玩家理解游戏的机制，或者给予他们在正确的时间执行正确操作所需的反馈。

此外，玩家期望在游戏中有声音，因为自从游戏诞生以来，声音一直存在于游戏中。不幸的是，当涉及到声音时，HTML 游戏存在一些大问题。您不能使用一个强大的解决方案使其能够在所有浏览器上添加声音并使其正常工作。

在本章中，我们将介绍四种不同的技术来为您的游戏添加声音：

+   **嵌入**：这是在页面中包含声音的最古老的方法。在旧时代，它经常用于使页面播放 MIDI 文件作为背景音乐。它不是标准的，不提供一致的 JavaScript API，并且您无法保证支持给定的音频格式。不过，它被几乎所有您可以找到的浏览器支持。

+   **HTML5 音频**：您可以使用`audio`标签来产生声音。积极的一面是，几乎所有的浏览器都支持它。不利之处在于，您将不得不处理每个浏览器支持不同编解码器的事实，而且您将无法操纵声音。

+   **Web 音频 API**：这基本上是围绕 OpenAL 的 JavaScript 封装。这意味着您可以对声音做任何您想做的事情。遗憾的是，目前只有 Chrome 和 Safari（iOS 上也是如此）支持它。

+   **Flash**：可以使用 Flash 来播放声音。这可能看起来像一个奇怪的想法，因为我们在这里制作的是一个 JavaScript 游戏，但您通常可以将其用作旧浏览器的后备方案。

然后我们将看一些有趣的工具，您可以用来为您的游戏生成声音。

# 抽象音频

首先，让我们创建一个非常简单的库来抽象我们的框架与我们选择的音频实现之间的交互。以下代码代表了所有我们的实现都必须遵守的“契约”：

```js
// a sound object
sound = function(){
  // Preloads the sound
  this.preload = function(url){
    // TODO: implement
  };

  // Returns true if the sound is preloaded
  this.isPreloaded = function(){
    // TODO: implement
  }

  // Starts to play the sound. If loop is true the
  // sound will repeat until stopped 
  this.play = function(loop){
    // TODO: implement
  };

  // Stops the sound
  this.stop = function(){
    // TODO: implement
  };
};
```

对于 Web 音频 API 的实现，我们将为我们的对象添加更多的功能，但这是您可能期望的任何音频库的基本功能。

## 使用我们的小型库

要在我们的游戏中使用声音，我们只需将相应的实现链接到我们的 HTML 文件中：

```js
<script type="text/javascript" src="img/sound.js"></script>
```

现在我们将为我们的关卡添加背景音乐；我们需要设置声音并预加载它。我们将通过将`initialize`函数拆分为两个部分来完成此操作：

```js
var initialize = function() {
    // ... 
    backgroundMusic = new sound();
    backgroundMusic.preload("background_music.mp3");
    waitForSound();
}

var waitForSound = function(){
  if (backgroundMusic.isPreloaded()){
    // ...
    backgroundMusic.play(true);
  } else {
    setTimeout(arguments.callee, 100);
  }
}
```

`waitForSound`函数检查声音是否已预加载。如果没有，我们创建一个超时以稍后再次检查其状态（准确地说，100 毫秒后）。正如您所见，一旦声音被预加载，我们就开始了级别并播放声音。现在，我们需要在级别完成时停止声音，如下面的代码所示：

```js
var player = new (function(){
    // ...
    this.update = function () {
        if(status == "dead"){
           // ...
        } else if (status == "finished") {
          backgroundMusic.stop();
          // ...
```

当下一个级别开始时再次启动它：

```js
var gameLoop = function() {
    if(gameState === "level"){
        // ..
    } else if (gameState === "menu") {

      if (gf.keyboard[32]){
        // ..
        backgroundMusic.play(true);
      }
    }
};
```

通过这些修改，如果声音库遵守我们刚刚指定的契约，我们将拥有背景音乐。现在让我们来看看针对此声音库的不同实现。

# 嵌入声音

HTML 具有一种非常方便的方法来将某些内容的阅读委托给插件：`embed`标签。这不是一个标准标签，但所有浏览器都支持它，并且被广泛用于在网站中包含 Flash。

这个相同的 HTML 标签可以用来在网页中包含声音。出于许多原因，这都不是一个理想的解决方案：

+   没有标准的程序化方法来知道浏览器是否支持此功能。

+   没有标准的方式来控制声音播放，因为暴露的 API 取决于用于播放声音的插件。尝试检测加载了哪个插件是可能的，但这个过程并不是非常可靠。此外，为每个可能的插件提供实现将是很多工作。

+   支持的格式取决于已安装的插件，而不仅仅是浏览器。

+   即使声音格式受支持，浏览器也可能要求允许启动插件。只要用户没有接受启动插件，就不会播放任何声音。

可能存在一些情况，其中使用此方法将声音包含到游戏中是合理的，但如果本章其余部分介绍的任何其他技术对您有效，我建议使用那些技术。

## 实施

让我们来看看负责预加载的部分的实现：

```js
// Preloads the sound
this.preload = function(url){
  // Preloading is not supported in a consistant
  // way for embeded sounds so we just save the 
  // URL for later use.
  this.url = url;
};

// Returns true if the sound is preloaded
this.isPreloaded = function(){
  // Since we use no preloading we always return true
  return true;
}
```

使用`embed`标签实现预加载将需要知道用于播放声音的确切插件的知识。遗憾的是，这是不可能的。相反，我们选择创建一个完全通用的实现。作为副作用，我们不能支持预加载。上述代码简单地通过始终返回`true`来绕过预加载。

这造成了一个重大问题：文件只有在您想要播放它时才会开始加载。这意味着在调用`play`函数和播放器听到声音之间会有相当大的延迟。这对背景音乐来说不是什么大问题，但对于音效来说，这个时间几乎是毫无意义的。好的一面是，第二次播放声音时，它很可能已经被缓存，因此延迟应该会减少。

由于我们不想使用任何 JavaScript API 与插件交互，我们只需将`embed`标签注入页面并配置它自动开始播放。

```js
// Starts to play the sound. If loop is true the
// sound will repeat until stopped 
this.play = function(loop){
  var embed = "<embed width='0' height='0' src='";
  embed += this.url;
  embed += "' loop='";
  embed += (loop)? "true" : "false";
  embed += "' autostart='true' />";
  this.obj = $(embed);
  $("body").append(this.obj);
};
```

我们存储生成的标签以便在`stop`方法中删除它：

```js
// Stops the sound
this.stop = function(){
  this.obj.remove();
};
```

这样做的缺点是我们不会重用我们创建的标签。但是，由于您不会在需要创建大量声音的情况下使用此技术，这并不是一个大问题。

## 支持的格式

由于使用`embed`标签支持的格式列表取决于已安装的插件，无法保证某个文件可播放。但是，如果您使用 WAV 和 MIDI，应该是安全的。

如果您选择使用 WAV 文件，请注意，因为在此格式中，音频可以以许多不同的方式进行编码，为了最大限度地提高兼容性，您应该使用未压缩的波形。

# HTML5 音频元素

为了匹配 Flash 的多媒体功能，HTML5 中添加了`video`和`audio`元素。它们都配有相匹配的 JavaScript API，允许您使用 JavaScript 创建和操作视频或音频，而无需编写到文档中（就像`Image`对象允许您加载图像而无需使用`img`标签一样）。

首先，让我们快速看一下`audio`标签的外观：

```js
<audio>
   <source src="img/backgroundMusic.ogg" type='audio/ogg; codecs="vorbis"'>
   <source src="img/backgroundMusic.mp3" type='audio/mpeg; codecs="mp3"'>
</audio>
```

正如您在这里所看到的，可以为`audio`标签提供多个来源。这是为了绕过此 API 的最大问题：文件格式的兼容性。事实上，即使所有现代浏览器都支持`audio`元素，也没有一种单一的音频格式可供您使用，所有这些浏览器都能识别。解决方法是提供多种格式。

这远非理想，因为它将强迫您在服务器上维护多个版本的音频文件。以下表格显示了现有音频格式与当前浏览器版本的兼容性：

|   | **MP3** | **AAC** | **WAV** | **Ogg Vorbis** |
| --- | --- | --- | --- | --- |
| **Chrome** | ✓ |   | ✓ | ✓ |
| **Firefox** |   |   | ✓ | ✓ |
| **Internet Explorer** | ✓ | ✓ |   |   |
| **Opera** |   |   | ✓ | ✓ |
| **Safari** | ✓ | ✓ | ✓ |   |

这意味着如果您希望支持所有浏览器，您将至少需要提供两种文件格式。一致的意见是您应该选择 MP3 和 Ogg Vorbis（以`.ogg`结尾的音频文件）。

对于游戏，您通常不会使用 HTML 标签，而是直接使用 JavaScript API 进行工作。在我们开始之前，有一个小警告：尽管此标准的规范尚未最终确定，但大多数现代浏览器对此功能的支持相当好。由于标准在过去几年中发生了变化，某些较旧版本的当前浏览器可能具有略有不同的实现。

让我们看看如何在 JavaScript 中创建一个`audio`元素：

```js
var audio = new Audio();
```

要了解浏览器可以使用 JavaScript 播放的格式，您可以使用`canPlayType`方法。基本用法将是：

```js
var canPlay = audio.canPlayType('audio/ogg; codecs="vorbis"');
```

问题出现在此函数返回的可能值："probably"、"maybe"、"no"和""。这可能远不如你期望的那样，但有一个非常好的理由：取决于格式，解码器在访问文件本身之前并不总是能确定是否支持它。这些值的含义如下：

+   `"probably"`: 几乎可以确定是“是”！浏览器知道文件类型，并且相当确定它可以解码几乎所有这种类型的文件。

+   `"maybe"`: 浏览器知道文件格式，但也知道不支持它的所有变体。另一个原因可能是浏览器将该文件的读取委托给插件，并且无法确定插件能处理这个特定的文件。

+   `""`: 浏览器对这种文件类型一无所知，也不会将阅读委派给插件。通过这个响应，你可以安全地假设这个文件不会被播放。

+   `"no"`: 这与`""`相同；一些早期的标准实现使用了它。如果你想要支持更旧的浏览器，也应该期望这个响应。

有了这些知识，模仿我们之前看到的 HTML 代码的行为，你可以做像这样的事情：

```js
var audio = new Audio();
var canPlayOggVorbis = audio.canPlayType('audio/ogg; codecs="vorbis"');
var canPlayMP3 = audio.canPlayType('audio/mpeg; codecs="mp3"');
if (canPlayOggVorbis == "probably" || (canPlayOggVorbis == "maybe" && canPlayMP3 != "probably")) {
  sound.ext = ".ogg";
} else {
  sound.ext = ".mp3";
} 
```

这给了 Ogg Vorbis 优先权，但在“可能”和“或许”之间更倾向于“可能”，因此如果浏览器可能只能*或许*播放 Ogg Vorbis，但认为可以*可能*播放 MP3，我们将加载文件的 MP3 版本。

## 预加载声音

与`embed`标签相比，`audio`元素提供了管理声音预加载的方法，通过`audio`元素的`readyState`属性来完成。它有很多可能的值：

+   `HAVE_NOTHING`: 要么文件无法访问，要么到目前为止根本没有加载任何数据；可能是前者。这个状态对应的数字值是 `0`。

+   `HAVE_METADATA`: 文件的开头部分已经预加载；这已经足够解析声音的元数据部分。有了这些数据，可以解析声音的持续时间。这个状态对应的数字值是 `1`。

+   `HAVE_CURRENT_DATA`: 声音已经加载到当前播放位置，但还不足以继续播放。最有可能是由于播放位置是文件的结尾，因为通常情况下，状态转换非常快速到下面的文件。这个状态对应的数字值是 `2`。

+   `HAVE_FUTURE_DATA`: 音频已经预加载足够，可以从给定的播放位置开始播放剩余的文件，但是不能保证播放不会很快停止以允许更多缓冲。这个状态对应的数字值是 `3`。

+   `HAVE_ENOUGH_DATA`: 足够的声音已经预加载，所以声音应该在完全不中断的情况下播放（这是基于播放速率和下载速度的估计）。这个状态对应的数字值是 `4`。

对于我们的实现，我们将只考虑在 `HAVE_ENOUGH_DATA` 状态下预加载的声音。让我们看看我们小型库的预加载实现：

```js
// a sound object
sound = function(){

  // Preloads the sound
  this.preload = function(url){
    this.audio = new Audio();
    this.audio.preload = "auto";
    this.audio.src = url + sound.ext;
    this.audio.load();
  };

  // Returns true if the sound is preloaded
  this.isPreloaded = function(){
    return (this.audio.readyState == 4)
  }

  // ..
};

(function(){
 var audio = new Audio();
 var canPlayOggVorbis = audio.canPlayType('audio/ogg; codecs="vorbis"');
 var canPlayMP3 = audio.canPlayType('audio/mpeg; codecs="mp3"');
 if (canPlayOggVorbis == "probably" || (canPlayOggVorbis == "maybe" && canPlayMP3 != "probably")) {
 sound.ext = ".ogg";
 } else {
 sound.ext = ".mp3";
 }
})();

```

在前面的代码中有两部分；我们已经看到了突出显示的部分——它用于确定支持的声音格式。它被包装在一个只执行一次的函数中，并将支持的格式存储在 `sound` 对象中作为对象变量。

其余的代码是预加载的实现。首先我们创建一个 `audio` 对象。然后我们将预加载模式设置为 `auto`。这告诉浏览器它可以从文件中下载尽可能多的内容。之后，我们指向我们文件的正确版本。在这里，你可以看到 `src` 参数预计会省略扩展名，以便函数选择正确的版本。

最后，我们调用 `load` 函数。对于一些实现来说，这是必要的，才能开始加载文件。我们只有在 `readyState` 属性的值为 `HAVE_ENOUGH_DATA` 时才会考虑声音预加载。

## 播放和停止声音

控制播放很容易。让我们先看看我们的实现：

```js
// Starts to play the sound. If loop is true the
// sound will repeat until stopped 
this.play = function(loop){
  if (this.audio.lopp === undefined){
    this.audio.addEventListener('ended', function() {
        this.currentTime = 0;
        this.play();
    }, false);
  } else {
    this.audio.loop = loop;
  }
  this.audio.play();
};

// Stops the sound
this.stop = function(){
  this.audio.pause();
 this.audio.currentTime = 0;
};
```

`play` 部分的实现非常直接。然而，一些旧版本的浏览器不支持 `loop` 属性。对于这些情况，我们需要手动循环。为了实现这一点，我们注册一个事件处理程序，当声音播放到结束时将被调用。这个事件处理程序简单地将声音倒回并再次播放。

正如你所看到的，`audio` 元素没有 `stop` 函数，但是有一个 `pause` 函数。这意味着如果我们在 `pause` 函数之后再次调用 `start`，声音将继续从原来的位置播放，而不会从头开始。为了倒带声音，我们将当前时间设置为 `0`，这意味着“从头开始”。

有一个 `pause` 函数可能会很方便，所以我们将在我们的库中添加一个。

```js
// Pauses the sound
this.pause = function(loop){
  this.audio.pause();
};
```

现在你可能会认为这是一个相当好的解决方案，在大多数情况下，确实如此。然而，它还是存在一些问题；你不能在很大程度上操作声音，除了改变它的播放速度之外。效果、声道平移（控制声音在可用输出通道中的分配）等都不可能实现。此外，在某些设备上（主要是移动设备），你不能同时播放两个声音。大多数情况下，这是由于硬件限制，但结果是你不能同时拥有背景音乐和音效。如果你想在 iOS 上使用这个 API，你必须知道你只能在用户生成的事件响应中开始播放声音。

# Web 音频 API

Web Audio API 的目标是给 JavaScript 开发人员基本上与编写本机应用程序时所用工具相同的工具。它复制了 OpenAL 的功能，OpenAL 是一种非常广泛使用的游戏开发 API。而且它是一个标准 API。不幸的是，目前它只在基于 Webkit 的浏览器上实现，包括 iOS 6 的移动版本。

在制定这一标准之前，Mozilla 在 Firefox 中添加了一个类似的 API，称为 Audio Data，并正在努力迁移到 Web Audio API。它可能会在 2013 年底之前的稳定版本中提供。至于 Internet Explorer，目前尚未公布任何信息。如果你想在 Firefox 中使用 Web Audio API，现在可以使用 `audionode.js` 库 ([`github.com/corbanbrook/audionode.js`](https://github.com/corbanbrook/audionode.js))，但它并不完整，并且多年未更新。然而，如果你只是简单使用，它可能会起到作用！

这个 API 不仅提供了播放声音的方法，而且提供了生成声音效果的完整堆栈。这会导致 API 稍微复杂一些。

## 基本用法

Web Audio API 的理念是你连接节点以将声音路由到扬声器。你可以想象这些节点是真实的设备，比如放大器、均衡器、效果器或 CD 播放器。所有这些都是通过音频上下文（Audio context）完成的。它是一个实例化的对象，但你一次只能有一个实例。

让我们从一个非常基本的例子开始，将 MP3 源连接到扬声器，如下图所示：

![基本用法](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060_10_01.jpg)

要创建一个 MP3 源，你首先需要加载声音。这是通过异步 XML HTTP 请求完成的。一旦完成，我们就有了一个编码为 MP3 的文件，我们需要对其进行解码以获得描述声波的字节并将其存储到缓冲区中：

```js
var soundBuffer = null;
var context = new webkitAudioContext();

var request = new XMLHttpRequest();

request.open('GET', url, true);
request.responseType = 'arraybuffer';

// Decode asynchronously
request.onload = function() {
  context.decodeAudioData(request.response, function(buffer) {
    soundBuffer = buffer;
  }, onError);
}
request.send();

var context = new webkitAudioContext();
```

此时，`soundBuffer` 对象保存了解码后的声音数据。然后我们需要创建一个源节点并将其连接到缓冲区。比喻地说，这就像把 CD 放入 CD 播放器中一样：

```js
var source = context.createBufferSource();
source.buffer = buffer;
```

最后，我们需要将源连接到扬声器：

```js
source.connect(context.destination);
```

这就像将我们的 CD 播放器连接到耳机或扬声器一样。此时，你听不到任何声音，因为我们还没有播放声音。要做到这一点，我们可以写下以下内容：

```js
source.start(0);
```

如果这个方法的名称最近更改为更容易理解，它以前称为 `noteOn`，所以你可能也想支持这个，因为这个更改是相当近期的，一些浏览器可能仍然实现了旧的名称。如果你想停止播放，你将调用 `stop` （或它的新名称 `noteOff`）。你可能想知道为什么我们需要向这个函数传递一个参数。因为这个 API 允许你以非常精确的方式同步音频，以便做任何你想做的事情（另一个声音或视觉效果）。你传递的值是声音应该开始播放（或停止）的时刻。这个值以秒为单位给出。

根据我们到目前为止所见到的，我们已经可以实现我们的小型库了，所以在我们看更复杂的用法之前，让我们先这样做吧：

```js
sound = function(){
  this.preloaded = false;

  // Preloads the sound
  this.preload = function(url){
    var request = new XMLHttpRequest();
    request.open('GET', url, true);
    request.responseType = 'arraybuffer';

    // Decode asynchronously
    var that = this;
    request.onload = function() {
      sound.context.decodeAudioData(request.response, function(buffer) {
        that.soundBuffer = buffer;
        that.preloaded = true;
      });
    }
    request.send();
  };

  // Returns true if the sound is preloaded
  this.isPreloaded = function(){
    return this.preloaded;
  }

  // Starts to play the sound. If loop is true the
  // sound will repeat until stopped 
  this.play = function(loop){
    this.source = sound.context.createBufferSource();
 this.source.buffer = this.soundBuffer;
    this.source.connect(sound.context.destination);
    this.source.loop = true;
    this.source.start(0);
  };

  // Stops the sound
  this.stop = function(){
    this.source.stop(0);
  };
};

sound.context = new webkitAudioContext();
```

这里没有什么新的，除了 `play` 和 `stop` 函数只能被调用一次。这意味着你每次想播放声音时都必须创建一个新的 `bufferSource` 对象。

## 连接更多节点

让我们向我们的上下文添加一个新的节点：一个 `gain` 节点。这个节点允许你改变你的声音的音量。这个声音的真实版本将是一个放大器。下图显示了我们的节点将如何连接：

![连接更多节点](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060_10_02.jpg)

首先让我们创建节点：

```js
var gainNode = context.createGainNode();
```

然后我们将我们的源连接到节点输入，将扬声器连接到节点输出：

```js
source.connect(gainNode);
gainNode.connect(context.destination);
```

完成这件事之后，我们可以通过改变 `gain.value` 属性的值来修改音量，如下所示：

```js
gainNode.gain.value = 0.8;
```

`gain` 参数是一种叫做 `AudioParams` 的东西。它是你会在许多节点中找到的一个参数，它拥有一系列函数，允许你不仅立即操纵一个值，还可以使它随着时间而改变。以下是你可以在这个对象上调用的函数：

+   `setValueAtTime(value,` `time)`: 这将在指定的时间改变值。时间是以秒为单位的绝对时间，就像 `start` 函数一样。

+   `linearRampToValueAtTime(value, time)`: 这将使当前值在提供的时间内线性变化，直到达到指定的值。

+   `exponentialRampToValueAtTime(value, time)`: 这将使当前值从提供的时间到达指定值的时间内呈指数变化。

+   `setTargetAtTime(target, time, constant)`: 这将使当前值以恒定速率从给定时间接近目标值。

+   `setValueCurveAtTime(valuesArray, time, duration)`: 这将使值在提供的时间段内，根据提供的数组中的所有值进行过渡。

+   `cancelScheduledValues(time)`: 这将取消从给定时间开始的所有预定值变化。

以下图示例显示了这些函数的示例：

![连接更多节点](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060_10_03.jpg)

所有这些函数都可以设置成一个接一个地链式调用。它们之间的精确互动方式有时可能很复杂，一些过渡会产生错误。有关更多详细信息，请参阅规范。

## 加载多个声音

这个声音只是你可以用来创建声音图的众多可用节点中的一个。你可以随意组合它们，当然，也可以将多个源连接到你的`context.destination`对象上。如果你想使用多个声音，你会想要一次性预加载它们。

你可以使用我们之前看到的 API 来做到这一点，但是在 Web 音频中，通过使用`BufferLoader`，可以直接实现这一点。以下代码显示了这是如何工作的：

```js
bufferLoader = new BufferLoader(
  context,
  [
    'sound1.mp3',
    'sound2.mp3'
  ],
  function(bufferList){
    // bufferList is an array of buffer
  }
);
bufferLoader.load();
```

当声音被缓冲时，回调将被执行，就像前面示例中的`onload`回调一样。

## 那么多节点，时间太少

这个 API 提供了相当多的效果节点；现在让我们快速概述一下这些节点。这个列表来自规范（[`www.w3.org/TR/webaudio/`](http://www.w3.org/TR/webaudio/)）。请记住，规范仍在发展中，实现并不总是完整的或与规范保持最新。

### 延迟节点

**延迟**节点只会延迟传入的声音。它只有一个参数，表示声音应该延迟多长时间。

![延迟节点](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060_10_04.jpg)

### 脚本处理器节点

这个节点是一个通用的节点，允许你用 JavaScript 编写自己的效果。它有两个参数：

+   `bufferSize`：这定义了缓冲区的大小，它必须是以下值之一：256、512、1024、2048、4096、8192 或 16384。缓冲区是你的 JavaScript 函数将要处理的声音的部分。

+   `onaudioprocess`：这是将修改你的声音的函数。它将接收一个事件作为参数，具有以下属性：调用它的节点、输入缓冲区和从缓冲区播放音频的时间。函数将不得不将声音写入事件的输出缓冲区。

![脚本处理器节点](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060_10_05.jpg)

### 定位器节点

这个节点将允许你在 3D 环境中对声音进行空间化处理。你可以使用`setPosition`、`setOrientation`和`setVelocity`函数定义声源的空间属性。要修改听者的空间属性，你将不得不访问`context.listener`对象并使用相同的函数。

你可以在这个节点上设置许多模式参数来微调空间化的方式，但是你需要查看规范以获取详细信息。

![Panner node](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060_10_06.jpg)

### 卷积节点

这个节点创建一个**卷积器**效果（[`en.wikipedia.org/wiki/Convolution`](http://en.wikipedia.org/wiki/Convolution)）。它接受两个参数：保存用作卷积的声波的缓冲区和一个布尔值，指定效果是否应该被归一化。

![卷积节点](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060_10_07.jpg)

### 分析节点

此节点根本不改变声音；相反，它可以用于进行频率和时域分析。

![分析节点](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060_10_08.jpg)

### 动态压缩器节点

此节点实现了一个压缩器效果。您可以使用以下参数配置效果：**threshold**，**knee**，**ratio**，**reduction**，**attack**和**release**。

![动态压缩器节点](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-gm-dev-ess/img/5060_10_09.jpg)

### 双二次滤波器节点

此节点可用于应用一系列低阶滤波器。要指定使用哪一个，您可以使用节点的 `type` 属性将其分配给以下值之一：`lowpass`，`highpass`，`bandpass`，`lowshelf`，`highshelf`，`peaking`，`notch` 和 `allpass`。您可以通过设置节点的一些属性来配置所选择的效果。有关详细信息，您可以查看规格。

### WaveShaper 节点

此节点实现了一个波形整形器效果（[`en.wikipedia.org/wiki/Waveshaper`](http://en.wikipedia.org/wiki/Waveshaper)），由节点的曲线属性中提供的整形函数数组定义。

# Flash 回退

这可能听起来很奇怪，但有几种情况下您可能希望使用 Flash 进行声音处理。例如，您可能已经使用 HTML 设计了一个简单的游戏，因为您想同时面向 iOS 设备和台式机。但是您还希望旧版浏览器（如 IE 6）也具有声音。或者您希望仅使用 MP3 并为不支持 Flash 的设备提供 Flash。这些是一些情况，在这些情况下，如果不支持 HTML5 Audio 元素，则可能希望使用 Flash。

有一些库可以使您抽象化此过程；我们将详细查看其中之一——SoundManager 2——然后快速概述一些可用的替代方案。

## SoundManager 2

要使用 SoundManager 2（[`www.schillmania.com/projects/soundmanager2/`](http://www.schillmania.com/projects/soundmanager2/)），您只需要在页面上包含一小段 JavaScript 代码，并提供指向 Flash 文件的链接（在同一服务器上托管以遵守同一来源策略）。让我们快速看一下预加载的实现将会是什么样子。

```js
sound = function(){

  this.preloadStarted = false;

  // Preloads the sound
  this.preload = function(url){
    if(sound.ready){
      this.audio = soundManager.createSound({
        id: 'sound'+sound.counter++,
        url: url,
        autoLoad: true,
        autoPlay: false,
        volume: 50
      });
      this.preloadStarted = true;
    } else {
      this.url = url;
    }
  };

  // Returns true if the sound is preloaded
  this.isPreloaded = function(){
    if (!this.preloadStarted){
      this.preload(this.url);
      return false;
    } else {
      return (this.audio.readyState == 3)
    }
  }
  //...
};

sound.ready = false;
sound.counter = 0;
// a sound object
soundManager.setup({
 url: 'sm2.swf',
 flashVersion: 8, 
 useHTML5Audio: true,
 onready: function() {
 sound.ready = true;
 }
});

```

要使用 SoundManager 2，我们首先必须配置它；这是前面代码中突出显示的部分所做的。 `url` 参数是播放声音所使用的 Flash 文件的路径。我们选择了 Flash 版本 8，因为如果要模仿 HTML5 Audio 元素，则不需要更高版本。然后，我们设置一个标志，以在 Flash 不可用时使库使用 HTML5 播放声音。由于此方法可能需要一些时间才能加载和准备就绪，我们设置了一个事件处理程序来检测 `SoundManager` 对象是否已准备就绪。此事件处理程序仅设置一个标志。还有更多可用参数，我建议您在写得很好的 `SoundManager` 文档中查看它们。

要实现 `preload` 函数，我们必须考虑到 SoundManager 可能尚未准备好。如果是这种情况，我们等待下一次调用 `isPreloaded` 来开始预加载（如果此时 `SoundManager` 已准备就绪）。

要查询音频状态，我们可以使用 `readyState` 参数，但要小心；可用值与 HTML5 音频元素的值不同：

+   `0`: 音频未初始化；预加载尚未开始

+   `1`: 音频正在加载

+   `2`: 加载音频时发生错误

+   `3`: 文件已加载

很明显，如果 `readyState` 参数的值为 `3`，我们将认为音频已准备就绪。下面是最后三个方法的实现；这里没有特别之处，因为每个方法都与 `SoundManager` 中的一个精确匹配：

```js
// Starts to play the sound. If loop is true the
// sound will repeat until stopped 
this.play = function(loop){
  this.audio.loops = loop;
  this.audio.play();
};

// Pauses the sound
this.pause = function(loop){
  this.audio.pause();
};

// Stops the sound
this.stop = function(){
  this.audio.stop();
};
```

这就是我们音频库的 SoundManager 实现了。

## 替代方案 SoundManager

有许多其他库可以完成 SoundManager 的功能。jPlayer ([`www.jplayer.org/`](http://www.jplayer.org/)) 就是其中之一。与 SoundManager 不同的是，它允许您播放视频，并且从一开始就围绕 HTML5 音频和视频元素构建，而这些后来才添加到 SoundManager。此外，它被构想为一个 jQuery 插件。但是，它被构想为媒体播放器，用户可以看到 UI。如果您想在游戏中使用它，可以禁用此功能。

另一种可能性是使用 SoundJS ([`www.createjs.com/#!/SoundJS`](http://www.createjs.com/#!/SoundJS))。它是 CreateJS 工具套件的一部分，非常适合游戏编程。SoundJS 支持 HTML5 音频、Web Audio API 和 Flash。如果您熟悉 CreateJS，使用它应该不是问题；否则，它可能会比前两种更难使用。我认为这值得付出努力，因为这是一个非常干净和现代的库。

如果您不想学习另一个播放音频的库，可以使用 `mediaelement.js` ([`mediaelementjs.com/`](http://mediaelementjs.com/))；它为不支持 HTML5 音频和视频元素的浏览器提供了实现。如果使用此库，您只需使用 `audio` 元素编写代码，需要时将使用 Flash 或 Silverlight 脚本进行播放。

# 生成音效

到目前为止，我们大多讨论的是音乐。当然，相同的技术也可以用于播放音效。不过，处理它们的一个非常优雅的解决方案是：在运行时生成它们。这模仿了许多旧游戏主机上创建效果的方式。要在 JavaScript 中执行此操作，您可以使用 `SFXR.js` ([`github.com/humphd/sfxr.js`](https://github.com/humphd/sfxr.js))。它是受欢迎的 SFXR 的一个端口。不幸的是，它只能与 Firefox 的 Audio Data API 一起使用。尽管如此，我鼓励您去了解一下！

# 总结

你现在已经学会了使用标准 API、插件和 Flash 库在游戏中播放声音的许多不同方法，你的脑袋现在可能有些疼了！目前浏览器中的音频状态并不是很好，但是在几年后，当 Web Audio API 在所有浏览器中得到支持时，我们将处于一个更好的境地！因此，我建议花一些时间好好学习它，即使它比 HTML5 音频元素稍微复杂一些。

现在，你已经拥有了创建完美的 jQuery 游戏所需的所有工具！我真诚地希望你喜欢阅读这本书，并且它将激励你创造许多精彩的游戏。
