# 面向 Flash 开发者的 HTML5（二）

> 原文：[`zh.annas-archive.org/md5/EE4F7F02D625483135EC01062083BBEA`](https://zh.annas-archive.org/md5/EE4F7F02D625483135EC01062083BBEA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：一次编码，到处发布

我相信您现在可能已经注意到，尽管所有现代浏览器都支持指定的 HTML5 功能集的许多方面，但在许多情况下，开发人员必须以特定方式编写其代码，以实现对其项目的适当跨浏览器支持。这不仅是一项耗时的任务，需要大量的冗余和调整，而且要求开发人员保持与 HTML5 规范的当前浏览器支持的最前沿；不仅针对每个目标浏览器，还要针对每个浏览器的每个更新。随着 HTML5 开发的流行度以极快的速度增长，许多开发人员已经创建了库和框架，以帮助使用单个代码实例针对所有平台。

在本章中，我们将学习：

+   CreateJS 工具包的概述，这是 Flash 开发人员在 HTML5 开发中的最佳伙伴，以及其内部库 EaselJS、SoundJS、PreloadJS 和 TweenJS

+   使用 Modernizr 检测客户端浏览器功能

+   深入了解 CSS3 媒体查询

# 覆盖所有基础

Flash 和 HTML5 开发范式之间最大的区别之一是开发人员对最终用户的期望。通常，Flash 开发人员会在启动项目时预设项目的发布设置，以便将项目发布到最能支持应用程序内置功能集的 Flash Player。当然，这意味着用户计算机上安装的 Flash Player 必须是最新的，以满足先决条件版本。在开发任何基于 HTML 的 Web 项目时，这个问题会更加严重，因为开发人员失去了对用户如何查看其内容的控制。尽管有些浏览器比其他浏览器更常见，但如今有大量的互联网浏览器软件可用，不仅适用于台式机和移动设备，还适用于电视等设备。不幸的是，每个浏览器的规格并不完全相同，如果您忽略在每个浏览器中测试您的项目，就无法保证您的内容将被显示并且将按照您创建的方式运行。

随着微软发布的 Internet Explorer 10 版本的发布，开发人员不再抱怨为 Internet Explorer 6 版本开发网页的日子已经一去不复返。然而，随着 HTML5 的出现，一系列新问题也随之而来。网页和基于 Web 的应用程序现在可以访问许多您已经习惯于在本机桌面应用程序中使用的功能。新的系统集成，如文件访问权限，外围支持以及硬件加速，要求现代 Web 浏览器实现对这些功能的支持，以便为查看这些新 HTML5 内容的用户提供适当的支持。

那么哪个浏览器是最好的呢？从开发人员的角度来看，尽管有一个最喜欢的浏览器是很好的，但如果您希望每个人都能查看您的内容，这并不重要。了解差异以及它们如何已经改变，以及将来会如何改变，将使您的 HTML5 技能保持最新并领先于潮流。如前所述，如果您使用今天可用的流行和现代 Web 浏览器，大多数基础将得到覆盖。在撰写本书时，即将推出的功能，如我们将在本书后面介绍的 WebRTC，只在 Google Chrome 等浏览器中得到支持。

# CreateJS

由于这本书是专门为 Flash 开发人员编写的，他们正在用 HTML5 扩展他们的技能，我们首先要介绍的是 CreateJS。CreateJS 是一组开源的、模块化的 JavaScript 库，可以单独工作，以实现从 ActionScript 3 到 JavaScript 的更无缝的过渡。CreateJS 专门为了让 Web 开发人员能够轻松地在他们的 HTML5 项目中创建、嵌入和操纵媒体资产。如果你来自 Flash 开发背景，这一点尤其正确。

### 注意

CreateJS 中所有元素的最新版本以及完整的文档可以在[`www.createjs.com`](http://www.createjs.com)找到。

CreateJS 专注于资产集成和操纵，以便让您，开发人员，花更多的时间来确保您的项目像素完美。最近有一些很棒的例子，展示了一些令人惊叹的项目，这些项目利用了这个库，产生了一些令人惊叹的 HTML5 体验，比如[`www.findyourwaytooz.com`](http://www.findyourwaytooz.com)、[`www.atari.com/arcade`](http://www.atari.com/arcade)和[`shinobicorp.com/retro-soccer`](http://shinobicorp.com/retro-soccer)。

虽然我们可以详细介绍 CreateJS 包中每个令人兴奋的功能，但我们可能会填满一半的书。因此，为了确保您至少可以初步了解 CreateJS 提供了什么，让我们回顾一下包中的每个元素以及它们如何在您的 HTML5 项目中使用。

## EaselJS

EaselJS 是一个旨在模仿 Flash 中 ActionScript 3 的显示列表语法的 JavaScript 库。它通过使用 HTML5 Canvas 元素来实现这一点，就像 Flash 中的舞台一样。作为 HTML5 和 JavaScript 语法的新手，EaselJS 可能是一个不仅可以让你继续以与你到目前为止一直在开发的方式相似的方式创建应用程序，而且还可以让你相对轻松地将你现有的 Flash 应用程序移植到 HTML5 的库。

### 注意

最新的 EaselJS 文档可以在[`www.createjs.com/Docs/EaselJS`](http://www.createjs.com/Docs/EaselJS)上轻松找到。

EaselJS 可以用来处理 HTML5 项目中的所有图形元素，如位图、矢量和精灵表。EaselJS 的最佳用例之一是将现有的 ActionScript 3 类移植到 JavaScript 中。由于 EaselJS 被设置为模拟 Flash 中的显示列表，一旦我们的 ActionScript 3 类被转换，我们就可以开始在我们的 JavaScript 项目中使用它，方式几乎与在 Flash 项目中使用它的方式相同。

每个使用 EaselJS 或任何其他 CreateJS 库的项目都需要将库源导入到他们的 HTML5 项目中。一旦你从 CreateJS 网站获取了必要的 JavaScript 源文件，就可以按照下面的例子设置你的 HTML 文档：

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>CreateJS - EaselJS Example</title>

    <!-— Import the EaselJS Library --> 
    <script src="img/easeljs-0.5.0.min.js"></script>

    <script>
      function init() {
        // We can place our custom code here.
      }
    </script>
  </head>

  <body onload="init()">
    <canvas id="exampleCanvas" width="800" height="600">
  </body>
</html>
```

正如您从上面的例子中所看到的，EaselJS 库是在`<script>`标签中导入到我们的文档中的。我们还在文档的主体中添加了一个空的 Canvas 元素。由于 EaselJS 使用 HTML5 Canvas 元素来替代 Flash 中的舞台，这在这个例子和所有使用这个库的项目中都是必需的。

在我们的例子中，我们将首先回顾一个基本的 ActionScript 3 类，这个类可以在任何 Flash 项目中使用。这个类是一个简单的演示，将一个位图图形应用到舞台上鼠标的位置，并在鼠标移动时更新图形的位置。这个例子不仅涵盖了对外部图形引用的使用，还涵盖了基于鼠标和时间的事件：

```html
package {

  import flash.display.*;

  public class MouseLine() {

    private var oldX:int;
    private var oldY:int;

    public function MouseLine() { }

    public function update(container:Sprite, x:int, y:int):void {
      container.graphics.setStrokeStyle(1);
      container.graphics.moveTo(oldX, oldY);
      container.graphics.lineTo(x, x);

      oldX = x;
      oldY = y;
    }
  }
}
```

如果你花了一些时间使用 ActionScript 3 类，所有这些都应该看起来非常熟悉，所以让我们直接进入转换过程。正如我们在整本书中所看到的例子一样，在 JavaScript 中创建类时，语法、布局和用法都有一些明显的不同。首先是包声明以及导入语句。JavaScript 中不存在包；因此，该代码可以被移除。代码目录和文件结构仍然可以被使用；然而，在代码中不需要引用来区分哪个代码在哪个包中。导入语句也可以完全移除，因为它们在 JavaScript 中也不被使用。相反，项目中需要的任何外部代码应该在 HTML 文档内的`<script>`标签元素中导入。

由于我们打算将所有课程作为项目源结构中的单独文件保留，因此我们可以用以下自执行匿名函数替换 ActionScript 3 类中的典型包语法：

```html
(function(window) {
  // Place Your Code here
})(window);
```

当我们的类源代码放置在这个函数内时，它将在加载后自动执行，允许我们从项目的其余代码中利用这个类。在删除函数和变量的严格类型以及将公共和私有变量转换为 JavaScript 语法之后，我们的类将看起来像下面这样：

```html
(function(window) {

  function MouseLine() {
    this.oldX = 0;
    this.oldY = 0;
  };

  MouseLine.update = function(container, x, y) {
    container.graphics.setStrokeStyle(1);
    container.graphics.moveTo(this.oldX, this.oldY);
    container.graphics.lineTo(x, y);

    this.oldX = x;
    this.oldY = y;
  }

  window.MouseLine = MouseLine;

})(window);
```

注意在自执行匿名函数中附加的最后一行，`window.MouseLine = MouseLine;`

类的最后添加允许我们从应用程序基础实例化一个新的`MouseLine`对象，并在类中使用功能。但在我们开始使用这个类之前，我们需要将其导入到我们的项目中，如下所示：

```html
<script type="text/javascript" src="img/MouseLine.js"></script>
```

将我们的类保存为`MouseLine.js`后，我们现在可以像往常一样将其导入到我们的 HTML 文档中，通过在 HTML5 文档的头部使用`<script>`标签。在这个例子中，我们还将在文档的*head*中打开另一个`<script>`标签，在那里我们将放置利用我们的新类的自定义 JavaScript 代码：

```html
<script type="text/javascript">
  var stage;
  var line;

  function init() {
    stage = new createjs.Stage("exampleCanvas");
  }
</script>
```

在前面的例子中，我们开始构建 EaselJS 项目的`stage`。我们首先创建两个全局变量，一个用于我们的`stage`元素，另一个用于我们的鼠标图形元素。在全局变量之后是我们的`init()`函数，该函数将在页面加载时调用。在我们的`init`函数内的下一步是设置 Canvas 元素，我们将其应用到这个 HTML 文档的 body 上。我们使用`new.createjs.Stage('canvas-element')`语法告诉 EaselJS，我们的 ID 为`exampleCanvas`的 Canvas 是我们预期的 stage。

将 EaselJS 应用到我们的项目中并引用我们的 Canvas 元素后，下一步是应用一个 ticker，以允许我们模拟 ActionScript 3 中的`onEnterFrame`事件。由于我们打算让`MouseGraphic`类中的图形在 Canvas 上跟随鼠标移动，我们需要不断检查鼠标的位置，将这些值转换为图形的 x 和 y 位置值。如前所述，在 ActionScript 3 中，传统上会使用`onEnterFrame`事件；然而，在 JavaScript 中没有 MovieClips 和 frames 的概念，因此设置使用了 EaselJS 的`Ticker`对象。

在我们刚刚创建的`init()`函数中，我们现在可以应用以下代码来设置我们的`Ticker`对象：

```html
createjs.Ticker.setFPS(60);
createjs.Ticker.addListener(window);
```

我们不仅为我们的`Ticker`对象创建了一个新的事件监听器，并且还通过使用 CreateJS 内部对象方法之一来设置了 Canvas 渲染的预期每秒帧数。然而，通过创建我们的事件监听器，我们需要一个在每次渲染新帧时调用的函数。在使用 CreateJS 中的`Ticker`对象时，我们可以简单地在与`Ticker`对象相同的范围内附加一个`tick()`函数，这将在每个间隔调用：

```html
function tick() {
  stage.update();
}
```

在这个 tick 函数中，我们还添加了对我们在`init()`函数中创建的 Stage 对象的全局变量引用的调用。正如您可能猜到的那样，这个调用实际上告诉`stage`对象通过渲染舞台进度中的下一个间隔来更新自己。因此，任何在 ActionScript 3 中通常附加在`onEnterFrame`事件中的代码都将在调用`stage.update()`方法之前放置。

有了我们基本的 EaselJS 结构，我们的示例现在应该看起来像下面这样：

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>CreateJS - EaselJS Example</title>

    <script src="img/easeljs-0.5.0.min.js"></script>
    <script src="img/MouseLine.js"></script>

    <script>
      var stage;
      var mouseImage;

      function init() {
        stage = new createjs.Stage("exampleCanvas");

        createjs.Ticker.setFPS(60);
        createjs.Ticker.addListener(window);
      }

      function tick() {
        stage.update();
      }

    </script>
  </head>

  <body onload="init()">
    <canvas id="exampleCanvas" width="800" height="600">
  </body>
</html>
```

最后，我们需要导入我们的自定义类，并在`Ticker`对象的每个间隔中读取鼠标位置属性，以便重新定位图像：

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>CreateJS - EaselJS Example</title>

    <style>
      canvas {
        border:1px solid #000;
      }
    </style>

    <!-- Import the EaselJS library. -->
    <script type="text/javascript" src="img/easeljs-0.5.0.min.js"></script>

    <!-- Import our custom classes. -->
    <script type="text/javascript" src="img/MouseLine.js"></script>

    <script type="text/javascript">
      // A global reference to our stage object.
      var stage; 
      var line;

      /**
       * Called on body load.
       */
      function init() {
        // Initialize the stage.
         stage = new createjs.Stage("exampleCanvas"); 
         line = new createjs.Shape();
         stage.addChild(line);

        // Create our ticker (ie. onEnterFrame).
        // Sets the target frames per second.
        createjs.Ticker.setFPS(60); 
        createjs.Ticker.addListener(window);
      }

      /**
       * The 'tick' function is continuously called on the specified interval set by Ticker.setFPS()
       */
      function tick() {
      line.graphics.beginStroke(createjs.Graphics.getRGB(0, 0, 0));

        MouseLine.update(line, stage.mouseX, stage.mouseY);

        stage.update();
      }

    </script>
  </head>

  <body onload="init()">
    <!— Canvas element to be used as our Stage. -->
    <canvas id="exampleCanvas" width="800" height="600">
  </body>
</html>
```

这个简单的示例只是使用 EaselJS 时的冰山一角，但它展示了如何使用 Canvas 元素作为舞台的核心流程。EaselJS 实际上是 CreateJS 捆绑包的核心，因为当它与捆绑包中的任何或所有其他库一起使用时，一切都会变得生动起来。让我们继续查看 CreateJS 中的库列表，看看下一个库 TweenJS。

## TweenJS

对于 Flash 开发人员来说，对对象进行缓动应该并不陌生。然而，在 ActionScript 3 中处理对象动画要比使用 CSS3 动画或编写自己的缓动引擎要容易得多。这就是 TweenJS 发挥作用的地方。TweenJS（[`www.createjs.com/#!/TweenJS`](http://www.createjs.com/#!/TweenJS)）使用了 ActionScript 和 TweenMax（[`www.greensock.com/tweenmax`](http://www.greensock.com/tweenmax)）等库中常用的缓动语法，可以让您轻松创建适用于 HTML5 的动画，通过允许 TweenJS 在特定时间段内执行所有对象属性操作。虽然 TweenJS 是一个非常简单的库，但它在开发新项目或转换现有 Flash 项目时所能节省的时间可能是无价的。与 CreateJS 包中的所有元素一样，TweenJS 与 EaseJS 库非常配合，我们可以在下面的代码示例中演示：

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>CreateJS - TweenJS Example</title>

    <style>
      canvas {
        border:1px solid #000;
      }
    </style>

    <!-- Import the TweenJS library. -->
    <script type="text/javascript" src="img/easeljs-0.6.1.min.js"></script>
    <script type="text/javascript" src="img/tweenjs-0.4.1.min.js"></script>
<!-- Import the TweenJS Ease library as well. -->
    <script type="text/javascript" src="img/Ease.js"></script>

    <script type="text/javascript">
      var canvas, stage;

      // Called on body load.
      function init() {
        stage = new createjs.Stage("exampleCanvas");

        var circle = new createjs.Shape();
        circle.graphics.beginFill("#00FF00").drawCircle(100, 100, 100);

        stage.addChild(circle);

        createjs.Tween.get(circle, {loop:true})
          .to({
            x:600,
          }, 1000)
          .wait(500)
          .to({
          scaleX:0.2,
            scaleY:0.2
          }, 500)
          .to({
            x:600,
            y:400
          }, 1000)
                .to({
            scaleX:1,
            scaleY:1
          },1000)
          .to({
            x:0,
            y:0
          }, 1000);

        createjs.Ticker.setFPS(30);
        createjs.Ticker.addEventListener("tick", stage);
      }
    </script>
  </head>

  <body onload="init()">
    <!-- Canvas element to be used as our Stage. -->
    <canvas id="exampleCanvas" width="800" height="600">
  </body>
</html>
```

正如您在前面的示例代码中所看到的，在 EaselJS 创建的舞台中对元素进行缓动非常简单和熟悉，对于任何 Flash 开发人员来说都是如此。与 CreateJS 中的所有元素一样，TweenJS 可以与 CreateJS 套件的其余部分一起使用，也可以单独使用。因此，如果您需要一个简单但功能强大的缓动引擎来节省大量时间和开销，同时在 HTML5 项目中对元素进行动画处理，那么 TweenJS 绝对值得一试。

## PreloadJS

就像在 Flash 应用程序中一样，在 HTML5 项目中预加载资产可以是一个关键步骤，以确保您的内容以适当的方式传递给最终用户。PreloadJS（[`www.createjs.com/#!/PreloadJS`](http://www.createjs.com/#!/PreloadJS)）允许轻松设置多个资产的预加载，实时进度反馈和队列支持。正如我们在 EaselJS 示例中看到的，CreateJS 已经设置了自己的资产管理系统，可以轻松集成到 PreloadJS API（[`www.createjs.com/Docs/PreloadJS/modules/PreloadJS.html`](http://www.createjs.com/Docs/PreloadJS/modules/PreloadJS.html)）中。考虑以下简化的示例，它从 Web 加载外部音频和图像资产。

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>CreateJS - PreloadJS Example</title>

    <!-- Import the PreloadJS library. -->
    <script type="text/javascript" src="img/preloadjs-0.3.1.min.js"></script>
    <!-- Import the SoundJS library. -->
    <script type="text/javascript" src="img/soundjs-0.4.1.min.js"></script>

    <script type="text/javascript">

      // Called on body load.
      function init() {
        var loadCount = 0;

        var queue = new createjs.LoadQueue(false);
        queue.installPlugin(createjs.Sound);
        queue.addEventListener("complete", handleComplete);
        queue.addEventListener("fileload", handleFileLoad);

        // We can load a specific external file...
        queue.loadFile({id:"sound", src:"http://www.w3schools.com/html/horse.mp3"});

        // Or create a manifest which lists all of the files to load.
        queue.loadManifest([
        // Load some Google Doodles from the Google Servers.
           	{ id: "doodle1", src:"http://www.google.com/logos/2013/first_day_of_summer_2013-1536005-hp.gif" },
           	{ id: "doodle2", src:"http://www.google.com/logos/2013/first_day_of_winter_2013-1985005-hp.gif" },
           	{ id: "doodle3", src:"http://www.google.com/logos/2013/140th_anniversary_of_the_rcmp-1580006-hp.jpg" }
        ]);

        // Called on LoadQueue file load complete.
        function handleFileLoad(event) {
          var item = event.item;
              console.log("File Loaded: " + item.id);

          loadCount++;
            	console.log((loadCount / 4) * 100 + "% completed.");
        }

        // Called on LoadQueue load complete.
        function handleComplete() {
            console.log("File Loading Completed!");

            createjs.Sound.play("sound");

            var d1 = queue.getResult("doodle1");
            document.body.appendChild(d1);

            var d2 = queue.getResult("doodle2");
            document.body.appendChild(d2);

            var d3 = queue.getResult("doodle3");
            document.body.appendChild(d3);
        }
      }

    </script>
  </head>

  <body onload="init()">
  </body>
</html>
```

正如我们在本书的前面示例中所看到的，等待所有文档及其资产在与其交互之前加载是几乎每个 JavaScript 应用程序都会使用的关键步骤。然而，在页面加载期间下载资产时，没有简单的方法来监视下载或完成过程。尽管我们典型的`onload`调用仍将等待我们的资产准备就绪，但在许多应用程序中，进度条的使用可以极大地增强用户体验，尤其是在较长的应用程序加载时间内。

再次审查前面的示例，您会发现我们在每个文件加载时都添加了事件侦听器，以及在所有资产加载完成时。将要加载的资产数量的数值与已加载的资产数量相结合，我们可以轻松地找到当前的预加载完成百分比。为了避免冗长的代码示例，我只是使用开发者控制台来补充了一些预加载用户界面：

![PreloadJS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_05_04.jpg)

## SoundJS

在撰写本书时，处理所有现代 HTML5 兼容浏览器上的音频和音频交互支持仍然非常困难。当前的 HTML5 音频支持水平在不同浏览器之间甚至在大多数移动平台上都可能存在极大的差异。正确地调整音频交互和操作，以在每台设备和浏览器上运行几乎似乎是一项不可能的任务。幸运的是，SoundJS 可以帮助解决许多与 HTML5 音频开发相关的常见问题。SoundJS 允许您轻松地查询客户端浏览器的功能，以确保您使用的音频具有用户设备支持的正确功能和插件：

```html
<script>
  var preload;

  function init() {
    if (window.top != window) {
      document.getElementById("header").style.display = "none";
    }

    createjs.FlashPlugin.BASE_PATH = "../src/soundjs/" // Initialize the base path from this document to the Flash Plugin
    if (!createjs.SoundJS.checkPlugin(true)) {
      document.getElementById("error").style.display = "block";
      document.getElementById("content").style.display = "none";
      return;
     }

    document.getElementById("loader").className = "loader";
    var assetsPath = "assets/";
    var manifest = [
        {src:assetsPath+"Game-Break.mp3|"+assetsPath+"Game-Break.ogg",id:1, data: 1},
        {src:assetsPath+"Game-Spawn.mp3|"+assetsPath+"Game-Spawn.ogg",id:2, data: 1},
        {src:assetsPath+"Game-Shot.mp3|"+assetsPath+"Game-Shot.ogg", id:3, data: 1},

        {src:assetsPath+"GU-StealDaisy.mp3|"+assetsPath+"GU-StealDaisy.ogg", id:4, data: 1},
        {src:assetsPath+"Humm.mp3|"+assetsPath+"Humm.ogg", id:5, data:1},
        {src:assetsPath+"R-Damage.mp3|"+assetsPath+"R-Damage.ogg", id:6, data: 1},

        {src:assetsPath+"Thunder1.mp3|"+assetsPath+"Thunder1.ogg", id:7, data: 1},
        {src:assetsPath+"S-Damage.mp3|"+assetsPath+"S-Damage.ogg", id:8, data: 1},
        {src:assetsPath+"U-CabinBoy3.mp3|"+assetsPath+"U-CabinBoy3.ogg", id:9, data: 1},

        {src:assetsPath+"ToneWobble.mp3|"+assetsPath+"ToneWobble.ogg",id:10, data: 1},
        {src:assetsPath+"Game-Death.mp3|"+assetsPath+"Game-Death.ogg", id:11, data: 1},
        {src:assetsPath+"Game-Break.mp3|"+assetsPath+"Game-Break.ogg",id:12, data: 1}
		];

      preload = new createjs.PreloadJS();
      //Install SoundJS as a plugin, then PreloadJS will initialize itautomatically.
      preload.installPlugin(createjs.SoundJS);

      //Available PreloadJS callbacks
      preload.onFileLoad = function(event) {
        // Show the icon on loaded items.
        var div = document.getElementById(event.id);
        div.style.backgroundImage = "url('assets/audioButtonSheet.png')";
      };
    preload.onComplete = function(event) {
      document.getElementById("loader").className = "";
    }

      //Load the manifest and pass 'true' to start loading immediately. Otherwise, you can call load() manually.
      preload.loadManifest(manifest, true);
  }

  function stop() {
    if (preload != null) { preload.close(); }
    createjs.SoundJS.stop();
  }

  function playSound(target) {
      //Play the sound: play (src, interrupt, delay, offset, loop, volume, pan)
      var instance = createjs.SoundJS.play(target.id, createjs.SoundJS.INTERRUPT_NONE, 0, 0, false, 1);
    if (instance == null || instance.playState == createjs.SoundJS.PLAY_FAILED) { return; }
    target.className = "gridBox active";
    instance.onComplete = function(instance) {
      target.className = "gridBox";
    }

  }
</script>
```

## CreateJS Toolkit

CreateJS 最伟大的方面之一是由*Grant Skinner*（[`www.gskinner.com`](http://www.gskinner.com)）和 Adobe 创建的 CreateJS Toolkit。这个工具包是 Adobe Flash Professional 的插件，可以让您轻松地在 Flash Professional 环境中创建 CreateJS-ready 的动画和元素，这是每个 Flash 开发人员已经习惯的。

### 提示

您可以在[`www.adobe.com/devnet/createjs.html`](http://www.adobe.com/devnet/createjs.html)获取 CreateJS Toolkit 的最新消息和文档。

### 设置工具包

首先，您需要前往 Adobe 网站上的 Adobe CreateJS Toolkit 页面（[`www.adobe.com/devnet/createjs.html`](http://www.adobe.com/devnet/createjs.html)）下载插件的最新版本以安装到您的计算机上。找到此页面的最简单方法之一是单击打开 Flash CS6 时可能已显示的链接：

![设置工具包](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_05_01.jpg)

一旦您下载了扩展程序，请确保退出所有正在运行的 Flash CS6 实例，并在 Adobe Extension Manager CS6 应用程序中打开下载的文件，将其安装到您的计算机的创意套件设置中。阅读并接受条款和条件以完成安装。

安装完成后，您应该能够在 Flash 扩展下看到 CreateJS Toolkit 扩展程序的列表，就是这样，我们已经准备好再次在 Flash 中开始使用 Toolkit 了：

![设置工具包](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_05_03.jpg)

安装了扩展程序并重新打开 Flash 后，启动一个新的 ActionScript 3 项目，并通过从**窗口**下拉菜单中选择 CreateJS Toolkit 来打开 CreateJS Toolkit 窗口。生成的 Toolkit 窗口将类似于以下图像。从这个窗口，您将能够在 Flash Professional 中使用 CreateJS Toolkit 配置和发布当前项目，而不是传统的导出到 SWF 设置：

![设置工具包](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_05_05.jpg)

在深入发布内容之前，值得查看一下工具包窗口中的配置设置。点击工具包窗口中的“编辑设置”按钮，打开 CreateJS Toolkit 的“发布设置”窗口：

![设置工具包](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_05_06.jpg)

从 Flash 项目中发布内容的配置设置相对简单。默认的“输出”值将在与 FLA 文件相同的目录中，您的项目保存在其中，并设置了资产路径。**选项**部分中的最终值再次非常简单，除了以下值：

+   **紧凑形状**：此值将代码压缩为绘图 API 类的最小版本

+   **多帧边界**：此值计算资产的`boundsRect`

### 发布您的资产

一旦您的资产都准备好了，可以在工具包窗口中点击“发布”按钮。结果将是典型的应用程序输出，而不是编译成 SWF，结果完全设置在 HTML5 中：

![发布您的资产](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_05_07.jpg)

这个 CreateJS Toolkit 编译器最好的部分是能够轻松地获取导出源代码的一部分，并在应用程序的特定部分中使用它。这个过程极大地提高了设计师和开发人员轻松地处理 HTML5 内容和资产，并轻松更新现有媒体的能力。

### 审查 CreateJS Toolkit 的输出

在完成工具包之前，值得审查一下从其编译器中导出的一些代码。让我们看看它为我们的太空游戏示例创建了什么：

```html
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>CreateJS export from SpaceAssets</title>

<script src="img/easeljs-0.5.0.min.js"></script>
<script src="img/SpaceAssets.js"></script>

<script>
var canvas, stage, exportRoot;

function init() {
	canvas = document.getElementById("canvas");
	exportRoot = new lib.SpaceAssets();

	stage = new createjs.Stage(canvas);
	stage.addChild(exportRoot);
	stage.update();

	createjs.Ticker.setFPS(30);
	//createjs.Ticker.addListener(stage);
}
</script>
</head>

<body onload="init();" style="background-color:#D4D4D4">
	<canvas id="canvas" width="800" height="600" style="background-color:#ffffff"></canvas>
</body>
</html>
```

正如您所看到的，通过上面的所有示例和库，CreateJS 是一组 JavaScript 功能的大集合，打包成了几个非常良好维护的开源 JavaScript 库。如前所述，在这本书中我们没有时间涵盖的内容远远超过这些，所以一定要前往 CreateJS 网站（[`www.createjs.com`](http://www.createjs.com)）并阅读最新版本的文档。

# Modernizr

我们在 CreateJS 捆绑包中看到的一个重要功能是轻松地检查客户端的 Web 浏览器是否支持在您的网页上使用的 HTML5 功能。然而，只有 CreateJS 具有检查库中使用的功能的兼容性的能力。如果您需要更深入地检查用户的 Web 浏览器是否具有适当的功能，Modernizr 项目绝对值得一看。Modernizr 允许您仅使用几行代码和一个仅有几千字节的外部 JavaScript 文件轻松地检查 HTML5 功能集中的每个功能。

## 使用 Modernizr

首先，您需要前往[`modernizr.com`](http://modernizr.com)并下载库的最新版本。与许多 JavaScript 库一样，您可以选择下载生产版本或开发版本的代码，以便节省文件大小和带宽：

![使用 Modernizr](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_05_08.jpg)

为了方便示例和学习的缘故，我们将下载开发版本的代码，其中包括整个 Modernizer 库。一旦 JavaScript 文件下载完成，它可以像包含任何 JavaScript 引用一样包含到您的 HTML 文档中。

### 提示

如果您仍然在寻找 Modernizr 设置方面遇到问题，请前往官方安装文档，网址为[`modernizr.com/docs/#installing`](http:// http://modernizr.com/docs/#installing)。

### 理解 Polyfills

在网页开发中，Polyfill 的概念一旦在实际项目中处理起来就非常简单。幸运的是，即使您来自 100％的 Flash 开发背景，您以前可能也有过这个概念的经验。在 HTML 页面中嵌入 Flash 内容时，即使在 Flash Professional 中使用了自动发布设置，生成的代码也会创建一个带有对编译的 SWF 文件的引用的 HTML 对象元素。但是，如果您仔细观察，或者在 Web 浏览器中禁用 Flash，您会注意到仍会显示警告，提示您需要下载 Flash 播放器以及指向 Flash 播放器下载页面的链接。这个内容只在 Flash 内容无法显示时显示，并且是 Polyfill 的一个最简单形式的示例。

在 HTML5 中使用 Polyfills 可能是为了在特定浏览器和平台上达到预期受众而必不可少的。但是，并不总是需要使用 Polyfills。如果您试图提供尽可能最佳的体验，可能不值得尝试使用您的尖端 HTML5 功能来针对像 IE7 这样的浏览器。

### Modernizr.load()

Moderizr 中的`load`方法可能是库中最强大但又易于使用的实用工具之一。简而言之，`load`方法允许您有选择地选择应加载哪些脚本和数据，这取决于用户是否能够利用 HTML5 功能集的特定部分。考虑以下示例：

```html
Modernizr.load({
  test: Modernizr.geolocation,
  yep : 'geo.js',
  nope: 'geo-polyfill.js'
});
```

这个简单的例子展示了我们如何根据用户是否能够在其浏览器中使用地理位置功能来轻松选择要加载的 JavaScript 文件。如果客户端能够在其浏览器中使用地理位置 API，则将加载`geo.js`文件并继续执行。如果用户无法使用地理位置，则使用`nope`值，并加载`geo-polyfill.js`文件。

正如您在此演示中所看到的，Modernizr 是一个简单的库，其主要目标是简化处理多个浏览器和平台尝试查看您的 HTML5 内容的混乱，并且它做得非常好。

## Modernizr 可以检测到的内容

感谢世界各地许多 JavaScript 开发人员的贡献，Modernizr 自豪地宣称它能够检测并为当前指定的每个 HTML5 功能创建 Polyfill。由于有太多功能要列出，我将把 Modernizr API 文档的研究留给你，并给你以下代码示例，以演示这个伟大库的进一步用途：

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Modernizr Example</title>

    <!-- Import the Modernizr library. -->
    <script type="text/javascript" src="img/modernizr-latest.js"></script>

    <script>
      function init() {
        // Touch
        if(Modernizr.touch){
           console.log('You are on a touch enabled device.');
        } else {
           console.log('You are not on a touch enabled device.');
        }

        // WebGL
        if(Modernizr.webgl){
           console.log('You are on a WebGL enabled browser.');
        } else {
           console.log('You are on a WebGL enabled browser.');
        }

        // Display all values
        console.log(Modernizr);
      }
    </script>
  </head>

  <body onload="init()">
  </body>
</html>
```

如上例所示，Modernizr 的实现非常简单。条件易于识别，因为它们的命名约定几乎直接匹配可以测试的功能集。要更好地了解 Modernizr 提供的不断增长的 API，请访问官方项目文档[`modernizr.com/docs`](http://modernizr.com/docs)。

# CSS 媒体查询

尽管我们已经在前几章中涉及了 CSS3 媒体查询，但在本章中也值得停下来注意一下。如果活动视口在设置内容以便在所有设备上可见并具有响应式布局和显示设置时发生大小变化，CSS3 媒体查询可以轻松地允许您避免操纵任何站点内容，只操纵附加到它们的样式。这个概念不仅非常适合在所有桌面和移动项目上实施，而且还可以用于更多其他用途。考虑以下一些可以直接从 CSS 源中查询的属性列表：

+   **全部**：此属性允许*所有*设备监听此属性

+   **盲文**：此属性用于盲文触觉反馈设备

+   **浮雕**：此属性用于分页盲文打印机

+   **Handheld**：此属性用于手持设备（智能手机和平板电脑*不*适用于此！）

+   **Print**：此属性用于分页材料和在屏幕上打印预览模式中查看的文档

+   **Projection**：此属性用于投影演示，例如投影仪

+   **Screen**：此属性主要用于彩色计算机屏幕和智能手机

+   **Speech**：此属性用于语音合成器

+   **tty**：此属性用于使用固定间距字符网格的媒体，例如电传打字机、终端或具有有限显示功能的便携设备

+   **Tv**：此属性用于电视类型设备，例如低分辨率、彩色、有限滚动功能的屏幕，带有可用音频

媒体查询的正确使用可以轻松地让您针对各种设备进行定位，使您的内容能够根据浏览器的特定大小、平台和设置做出响应：

```html
#mycontent {
    background-repeat: no-repeat;
    background-image:url('image.gif');
}

@media screen and (min-width: 1200px) {
    # mycontent {
        background-image:url('large-image.gif');
    }
}

@media print {
    #mycontent {
        display: none;
    }
}
```

# 总结

在本章中，我们介绍了将现有的 Flash 应用程序转换或移植到 HTML5 时可用的一些选项，以及使用户能够在任何设备上正确查看其内容的方法。我们深入研究了构成 CreateJS 的各个优秀库，从在 JavaScript 中模拟 Flash 显示列表，到使用传统的 ActionScript 3 tweening 语法对元素进行动画处理。我们了解了 CreateJS 工具包对于任何具有 Adobe Flash 专业版 IDE 的先前知识的人来说是多么有用，以及如何直接从舞台和库编译资产以供在 Web 文档中使用。我们还学习了如何通过使用 Modernizr 等库来统一开发体验。通过查询浏览器功能支持，您可以轻松决定是否需要使用替代显示方法或 shim 来使用户获得良好的体验。


# 第六章：HTML5 框架和库

与任何编程语言一起工作最令人兴奋的方面之一是发现可以用来扩展和简化驱动应用程序的代码的新库和框架。随着 HTML5 在许多不同平台和设备上的开发日益受欢迎，为帮助任何人进行 HTML5 开发而公开提供的代码量以惊人的速度增长。在本章中，我们将概述一些最受欢迎的库和框架，您可以随时利用它们，不仅可以节省时间，还可以让您更多地专注于用户体验，而不是编写复杂的 JavaScript 以在每个现代浏览器中运行。

在本章中，我们将涵盖以下内容：

+   框架和库如何让你的生活更轻松

+   使用框架或库可以创建的东西

+   对广受欢迎的 jQuery 库和 jQuery 移动框架进行概述

+   使用**HTML5** Boilerplate 模板构建**HTML**页面

+   使用 Bootstrap 创建响应式统一页面布局

+   使用 GreenSock 的动画平台来使用熟悉的缓动引擎对内容进行动画处理

+   使用`Backbone.js`在流行的**MVC**结构中开发您的 JavaScript

+   使用 WebGL 和`Three.js`编程硬件加速的 3D 图形

+   通过查看 Google 的 V8 项目来概述 JavaScript 编译器

+   使用`Node.js`将 JavaScript 推动到应用程序开发的极限

# 框架和库如何让你的生活更轻松？

从外部人或非开发人员的角度来看，在项目中使用他人的代码的想法可能会引起许多负面联想。如果您使用的是由您不认识的人创建并自由分发的代码，您如何能相信它的性能与所宣传的一样，并且不会显示恶意功能？传统上，在任何编程语言中导入库和使用框架时，只会使用整个代码库的一小部分。这会导致更大的开销，并可能对应用程序运行时执行速度产生影响。尽管所有这些论点都是有效的，但许多关于使用外部库和框架的流行关注点已经得到解决。在**HTML5**项目中使用外部资源的概念已经变得如此普遍，以至于 JavaScript 已经轻松成为社交编码网站 GitHub（[`github.com/languages`](https://github.com/languages)）上最受欢迎的编程语言。

由于 GitHub 等网站（[`github.com`](http://github.com)）的出现，分享和为开源项目做出贡献的概念已经爆炸式增长。借助外部库和框架，开发人员可以轻松地从头脑中的概念或想法转移到在几分钟到几小时内构建原型。开发人员还可以更多地专注于实际的概念集成，而不是处理诸如浏览器优化和平台支持等小问题。因此，随着开发人员周围的环境扩大和支持项目的开源项目增长，升级外部依赖项将导致应用程序功能集获得最新和最好的支持。

## JavaScript 框架和库可以做什么？

正如你在本书前面章节中所看到的，现代 Web 浏览器对 JavaScript 的支持每天都在变得更好。将所有应用程序类型的典型应用程序流程移动到 Web 的想法随着时间的推移变得更加现实。JavaScript 现在开始进入桌面和移动操作系统应用程序。有了对这么多平台的新覆盖，JavaScript 可以做很多你现在可能还不知道的事情。作为一个有经验的 Flash 应用程序开发者，你可能会发现，在理解和实现许多新颖的 JavaScript API 方面，当涉及到转向 HTML5 时，你会有另一个优势。从麦克风和摄像头集成到触摸设备上的多点触控手势，你可以用 JavaScript 做的事情每天都在增加。为了让你对可能的事情更加兴奋，这里是一些 HTML5 应用程序可以做的一些伟大的事情的简短列表：

+   动态控制 CSS 属性以创建 2D 和 3D 动画

+   从客户端摄像头和麦克风实时音频和视频流传输

+   使用硬件加速渲染 3D 图形和高帧率

+   将 JavaScript 直接编译成机器码，以便作为服务器或应用程序运行

## 寻找适合项目的正确库或框架

当涉及到寻找适合项目的外部资源时，可能会变成一个繁琐的任务，需要筛选各种项目，因为它们似乎都在做同样的事情。随着 JavaScript 开发的当前流行，人们只能期望这个问题会随着越来越多的开发者发布他们的项目而变得更加严重。幸运的是，开发社区支持你！那么，一个人应该去哪里找到最新和最好的开源项目，以在他们的 HTML5 项目中使用呢？嗯，和互联网上的任何东西一样，没有一个地方可以找到所有这些可用的项目。然而，随着时间的推移，越来越多的项目被托管在 GitHub 上（[`github.com`](http://github.com)），这样开发者就可以轻松地分享和贡献项目，同时利用 Git 版本控制系统。

在尝试寻找新项目时，像 GitHub 这样的社交编码网站的最好之处不仅在于能够按特定的编程语言对项目进行排序，还在于项目的当前流行程度（[`github.com/explore`](https://github.com/explore)）。GitHub 通过关注、派生和对相关项目的贡献数量来排名项目的流行程度。因此，通过排序这些值，将显示无数受欢迎和最新的项目。当然，使用站点搜索只会在寻找特定主题和平台时进一步细化您的结果：

寻找适合项目的正确库或框架

因此，在进行一些调查后，您可能已经找到了一些您认为是适合您需求的库或框架。下一个决定是将选择范围缩小到您可以开始使用的内容。那么，您该如何选择呢？显然，对于这个问题也没有简单的答案。但是，在下载和实施您找到的库或框架之前，有一些重要的考虑值得考虑。第一个考虑因素应该始终是您期望的最终结果是什么。如果您只是为了自己编写代码来学习新的框架，那么您几乎可以自由下载和测试任何您希望的内容。如果您考虑将此代码用于专业用途或可能向公众开放的项目，花一些时间研究有关所涉及项目的更多具体信息将有助于您避免日后的麻烦。如果您发现了一个感兴趣的开源项目，但该项目几乎没有或没有任何开发活动，无论是错误修复还是更新，那么该项目背后的开发团队很可能已经转移到了新项目。因此，您将下载和使用的代码版本将需要您维护和更新，以便在没有任何问题的情况下实施和使用它。如果最初创建项目的开发人员已经放弃了它，他们很可能不会很快回来专门帮助您解决问题。另一方面，如果您正在查看一个刚刚诞生或仍处于早期开发阶段的项目，那么如果您将该项目实施到您的项目中，您将需要在每次进行关键依赖项的手动更正时将其重新引入您的项目中。尽管这在大多数开发情况下都是典型的，但在早期阶段（选择和使用外部资产）时，始终值得记住，您可能会在项目的生命周期中使用这些代码。

为了让您了解一些可用功能，让我们概述一些等待在您下一个项目中使用的优秀开源项目。

# jQuery

在列出 JavaScript 库的清单时，我们不可能不从 jQuery 开始。在本书的这一部分，我们还没有在任何示例中使用 jQuery。但是，如果您在阅读本书之前花了一些时间研究 Web 开发，那么您很可能已经听说过这个项目。jQuery 最初发布于 2006 年，已经成为最受欢迎的 JavaScript 库，截至目前（撰写本书时）在互联网上访问量最高的 10,000 个网站中，超过 55%使用了 jQuery。由于 jQuery 在互联网上的大大小小项目中被广泛使用，它已经成为**HTML5**开发者工具包中几乎必不可少的技能。

### 提示

为了让您了解与 jQuery 相关的一切，请访问项目网站[`jquery.com`](http://jquery.com)。

当然，随着 jQuery 的压倒性流行，文档、示例和教程的数量也是压倒性的。因此，与其花费大量时间查看 jQuery 的所有功能，我们将简要概述它的基本原理以及您可以用它做什么。

与本书中的所有主题一样，如果您有兴趣了解更多，快速的谷歌搜索将非常有帮助：

![jQuery](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_06_02.jpg)

那么 jQuery 到底是什么呢？嗯，jQuery 是一个相对较小的 JavaScript 库，用于帮助解决各种常见的 JavaScript 开发任务和问题。通过轻松选择文档中的元素，创建和处理各种事件，在文档中对元素进行动画处理，使用 Ajax 调用和检索外部数据，jQuery 可以为您提供一个更简单、易于使用和统一的语法，可在大量的 Web 浏览器上运行。jQuery 最好的部分是，它可以在只导入一个小于 50 KB 的 JavaScript 文件的情况下完成所有这些工作。

## 将 jQuery 投入实践

与所有 JavaScript 项目一样，了解 jQuery 的最佳方法是通过示例。因此，让我们快速了解如何将 jQuery 正确添加到您的项目中，以及如何开始在您的代码中使用其功能。

一切都始于前往 jQuery 项目网站获取项目的最新稳定版本（[`jquery.com`](http://jquery.com)）。值得注意的是，几乎所有积极开发的开源项目都有许多不同的构建类型可供您下载和使用。通常情况下，当访问 jQuery 等项目网站时，您通常会找到一个链接，用于下载项目的最新稳定版本。积极开发的项目的稳定版本通常不是最新版本，但稳定版本经过测试并获得批准供公众使用。随着开发人员对项目的贡献不断增加，它们将继续增加，直到开发团队批准当前代码库已准备好供公众使用。因此，在软件的每个版本发布之间的整个时间内，项目将有一个开发版本，在许多情况下，您也可以下载和使用，当然可能会遇到新的未记录问题的可能性。

在到达 jQuery 下载页面（[`jquery.com/download`](http://jquery.com/download)）后，您可以选择下载当前版本的压缩或未压缩版本。压缩代码的原因是为了减小文件大小，并在您的 Web 服务器请求时实现更快的加载时间。压缩或压缩 JavaScript 实际上是您可以轻松完成的工作，我们将在后面的章节中继续深入探讨这个主题。现在，您可以将这些 jQuery 源 JavaScript 文件中的任何一个保存在计算机上，最好是在您将创建**HTML5**项目的目录中。创建空的 HTML 文档后，导入 jQuery 就像导入任何其他外部 JavaScript 文档一样简单：

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>jQuery Importing Example</title>
    <script src="img/jquery.min.js"></script>
  </head>

  <body>
  </body>
</html>
```

完成了这项艰苦的工作后，您现在可以在项目中利用 jQuery 的所有功能。但是，通常需要从一个关键位置开始，那就是控制代码准备执行的时间点。到目前为止，我们已经使用了许多常见的技术来完成这项任务，比如将`body onload`参数设置为 JavaScript 函数。

```html
<body onload="init()">
```

或在`window`对象上设置`onload`事件：

```html
window.onload = function() {
	// Start executing your code here...
}
```

使用这种方式调用 JavaScript 的一个问题是，等待文档加载的方式包括等待所有图像资产加载，包括不受控制的外部资产，如横幅广告。因此，jQuery 创建了自己的文档就绪事件处理程序语法来规避这个问题。通常情况下，对于所有基于 jQuery 的项目，要追加的第一段代码将是文档就绪处理程序：

```html
$( document ).ready( function() {
  // Start executing your code here...
});
```

## 使用 jQuery 选择元素

jQuery 最伟大的方面之一是其选择器引擎，也被称为 Sizzle（[`sizzlejs.com`](http://sizzlejs.com)）。选择器引擎之所以如此出色，是因为在处理 HTML 文档中的交互元素时，它使整个开发过程变得非常简单。考虑一下我们在 body 中添加一些简单内容的工作示例：

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>jQuery Importing Example</title>

    <!-- Always import external libraries before your custom site code. -->
    <script src="img/jquery.min.js"></script>

    <script>
      $( document ).ready( function() {
        // Start executing your code here...
      });
    </script>
  </head>

  <body>
    <div>
        <p>
        <a href="http://www.google.com">Go to Google</a>
        </p>
    </div>
  </body>
</html>
```

尽管这个页面布局很简单，但页面中的每个元素都可以通过使用 jQuery 选择器来轻松控制。要为我们的链接到 Google 添加事件监听器，我们可以在文档准备好的回调函数中添加它：

```html
$( document ).ready(function() {
  $("a").click(function(event) {
    alert("Tell Google I said hello!");
  });
});
```

尽管前面的示例非常简单，但有几个关键方面应该立即介绍。jQuery 选择器语法依赖于`$()`语法。在我们的示例中，在选择器语法括号内，我们提供参数"`a"`来选择文档主体中的所有`<a>`元素标记。仅仅选择一个元素不会让你走得太远；因此，示例中的下一步是将点击事件监听器链接到所选元素。当然，点击事件远非您可以应用于元素的唯一可用事件，您可以参考事件文档以查看整个列表（[`api.jquery.com/category/events`](http://api.jquery.com/category/events)）。最后一步是定义要在事件回调中使用的方法，在我们的示例中，我们只是直接将函数定义到回调参数中。

通过添加、保存并在浏览器中重新加载此更改后，当单击链接时，将显示一个警报对话框，然后是页面位置（[`google.com)`](http://google.com)）。如您所见，我们的事件监听器在锚标签中引用的**URL**移动到之前已经被触发。选择器引擎与大量的 jQuery 事件一起使用，可以让您控制页面中可能发生的大量用户和网络交互。

覆盖预定义的操作也很容易。正如您在我们的示例中定义的回调函数中所看到的，当它被调用时，它将事件变量传递给方法。这个事件属性用于控制事件，可以很容易地被操纵或完全覆盖：

```html
$(document).ready(function() {
	$("a").click(function(event) {
		alert("You're not going anywhere!");
		event.preventDefault();
	});
});
```

通过在事件对象上调用`preventDefault()`方法，我们可以禁用事件的默认操作，并使用我们自己的代码来控制结果。

## 通过 jQuery 控制 CSS

jQuery 的另一个伟大之处是可以轻松地使用 CSS3 属性来控制元素的外观和感觉。使用 jQuery 选择器和 CSS 方法在任何元素上获取和设置 CSS 值非常简单：

```html
$("#example").css("width", 200);
$("#example").css("height", 300);
```

正如您在前面的示例中所看到的，设置特定元素的宽度和高度的 CSS 属性非常简单。我们可以通过将 CSS 属性传递给对象而不是单独传递它们来简化这两行 CSS 属性更新为一行：

```html
$("#example").css({ width:200, height:300 });
```

这相当于在文档的 CSS 结构中添加以下内容：

```html
#example {
  width:200px;
  height:300px;
}
```

在 jQuery 中进行 CSS 操作不仅仅是为了设置文档中元素的宽度和高度。jQuery 现在完全支持 CSS3 属性，其中包括圆角、文本效果、不透明度、2D 和 3D 变换以及滤镜等属性。

### CSS 动画

由于通过 jQuery 可以控制几乎任何元素的 CSS 属性，因此也可以轻松地对它们进行动画处理。

在查看一些示例之前，有一些重要的要点需要注意。如第二章中所述，*准备战斗*，以及第三章中所述，*可扩展性、限制和影响*，在涵盖 CSS 属性及其值与 ActionScript 3 API 相比时，定位文档中元素的值不是基于传统的 x 和 y 值集。因此，在对元素位置进行动画处理时，应注意元素位置值，以正确定义移动元素的正确值：

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>jQuery CSS Animation Example</title>

    <style>
      html, body {
        margin:0;
        padding:0;
        height:100%;
      }
      #example {
        width:200px;
        margin:auto;
        background-color:#EFEFEF;
        border:1px solid #000;
        text-align:center;
        cursor:pointer;
      }
    </style>

    <script src="img/jquery.min.js"></script>
    <script>
      $( document ).ready( function() {
        $('#example').click(function(event){ 
          // Animate the #example element
          $("#example").animate({
              marginLeft: '0',
              width:'100%',
              height:'100%',
              fontSize:'40px'
          }, 500, function(event) {
          // Update the element paragraph inner HTML.
            $("#example p").html('Animation Complete!');
          });
        });
      });
    </script>
  </head>

  <body>
    <div id="example">
      <p>Click To Begin Animation</p>
  </div>
  </body>
</html>
```

## 使用 jQuery Ajax 请求外部数据

由于 ActionScript 3 中内置的`URLLoader`和`URLRequest`类，请求外部数据（无论是项目内部还是 Web 上的外部数据）都非常简单。创建了一个`URLLoader`，以及一个包含数据路径引用的`URLRequest`对象。最后，将`URLRequest`对象传递到加载器对象中，并调用`load`方法：

```html
Var loader:URLLoader = new URLLoader();
var request:URLRequest = new URLRequest("data.xml");
loader.load(request);
```

当然，要正确完成此示例，您需要添加事件处理程序来捕获数据的返回，并知道何时可以开始操作或利用它。然而，从应用程序中调用和检索外部数据的概念对您可能并不陌生。

在 JavaScript 中开发应用程序时，这种功能的首选是**AJAX**。**AJAX**（异步 JavaScript 和 XML）是在客户端使用网页时与 Web 服务器交换数据的概念，而无需重新加载页面。如今在 Web 上使用**AJAX**是如此普遍，以至于几乎不可能一天不在许多网站或服务中使用它。一个完美的例子是在查看 Facebook 时间线或 Twitter 动态时的无限滚动。当您向下滚动页面查看内容时，底层运行的 JavaScript 会检测到您即将到达页面底部，并调用服务器以获取更多数据以不断填充列表。传统上，这将通过将数据应用于多个页面并要求用户为每个视图刷新页面来完成。

那么 jQuery 在开发应用程序的**AJAX**功能方面能做些什么呢？在 jQuery 库中有许多方法专门设计用于处理**AJAX**请求和请求类型。

在其最基本的形式中，jQuery 的`load`方法可以在一行 JavaScript 中检索外部数据并将其放置在所选元素中：

```html
$('#myElement').load('example.html');
```

当然，外部资产不需要是**HTML**文档。**XML**、JavaScript、JSON、纯文本和 HTML 文档都支持在 AJAX 请求中使用。

可以理解的是，您可能并不总是希望将**AJAX**请求中的传入数据直接放入文档中，因此响应处理程序通常会放置在这些类型的调用中。这可以通过使用**AJAX**方法本身以自我实例化的 jQuery 语法来实现：

```html
$.ajax({
    url: 'example.html'
}).done(function(data) {
  if(data != '') {
    $("body").append(data);
  }
});
```

现在，通过返回的数据，您可以在将其包含在文档中之前轻松操作和验证**AJAX**调用返回的数据。

数据也可以在调用外部数据时提供。根据所引用文档中脚本的要求，您可以选择通过**HTTP** GET 请求发送数据：

```html
$.get("getmyphotos.php", { user:"johnsmith", id:"200" })
.done(function(data) {
	console.log(data);
});
```

或者，您可以选择通过 HTTP POST 请求发送数据：

```html
$.post("getmyphotos.php", { user:"johnsmith", id:"200" })
.done(function(data) {
	console.log(data);
});
```

## jQuery Mobile

在最近，jQuery 团队发布了 jQuery Mobile ([`jquerymobile.com`](http://jquerymobile.com))，它为开发人员创建了一个统一的**HTML5**用户界面，可以在现代移动设备的广泛范围内正确显示内容。就像 jQuery 本身一样，jQuery Mobile 非常轻量，甚至带有预构建的主题包，可以在可主题化的元素设计中使用。jQuery Mobile 旨在通过允许您更多地专注于应用程序内容而不是为浏览器支持编写特殊的 shims 和条件代码来简化您的移动开发过程。更新由开发团队发布的速度能够跟上移动设备市场惊人的速度。因此，您可以编写能够在尽可能多的设备上运行的移动 Web 应用程序，而无需专门针对每个设备进行定位：

![jQuery Mobile](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_06_04.jpg)

自发布以来，jQuery Mobile 已经被大大小小的网站广泛使用。jQuery Mobile 框架的核心方面包括页面、对话框、工具栏、列表视图和按钮的使用。通过围绕框架中的这些核心元素开发您的网页和内容，您可以为移动设备布局您的页面，而无需打开 Photoshop。

jQuery Mobile 充分利用了自定义数据属性，这是**HTML5**中的一个新功能。如果您查看下面的示例多页面 jQuery Mobile 布局，您会看到许多元素属性使用了`data-*`语法。这些是任何人现在都可以将其实现到他们的**HTML5**项目中的自定义数据属性。它们可以有任何字符串，至少是一个字符，并且可以用于在设置元素属性时轻松声明值：

```html
<body>
  <div data-role="page" id="one">
    <div data-role="header">
      <h1>Page 1</h1>
    </div>
    <div data-role="content" >
      <h2>Page One</h2>
      <p><a href="#two" data-role="button">Show Page 2</a></p>
      <p><a href="page3.html" data-role="button">Show Page 3</a></p>
    </div>
    <div data-role="footer" data-theme="d">
      <h4>Page Footer</h4>
    </div>
  </div>

  <div data-role="page" id="two" data-theme="a">
    <div data-role="header">
      <h1>Page 2</h1>
    </div>

    <div data-role="content" data-theme="a">	
      <h2>Page Two</h2>
      <p><a href="#one" data-direction="reverse" data-role="button" data-theme="b">Back to Page 1</a></p>	
    </div>

    <div data-role="footer">
      <h4>Page Footer</h4>
    </div>
  </div>
</body>
```

正如你所看到的，这个单个的**HTML**文件实际上是两个页面，分别用`data-role="page"`元素分隔成 DIV 元素。现在当 jQuery Mobile 框架加载包含这两个页面的**HTML**文件时，只有初始页面会显示，第二个页面会等待用户交互滑动到视图中。在第一个页面中，你可以看到到我们第二个页面的链接实际上只是一个锚标签，因为它在引用当前**HTML**文档中另一个页面的 ID 之前使用了`#`字符。为了进一步说明这种差异，在初始页面的导航中还有一个到第三个页面的链接，它以传统的方式链接到外部**HTML**文档。

默认情况下，当请求新页面时，数据会被加载（如果尚未加载），并显示在一个 DIV 元素中，实际上对于最终用户是不可见的。当数据加载和文档准备工作完成后，新页面会从右向左动画显示给用户。这种内容动画是许多现代移动设备应用程序用户界面的典型特征，因此使您的应用程序更加熟悉于最终用户：

![jQuery Mobile](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_06_05.jpg)

jQuery Mobile 在实际操作中最简单、最精致的例子之一是该框架的文档。正如您在上面的截图中所看到的，默认情况下，jQuery Mobile 的用户界面看起来非常适合移动设备。按钮很大，可以轻松地拉伸以适应页面，让用户可以轻松选择菜单项而不必担心误点。标题和段落文本易于阅读，并且位置完美。在文档导航中的特定元素添加了图标。在打印的截图中看不到的是布局的响应性。为了更好地说明移动设备上响应性的重要性，这里是同一 jQuery Mobile 文档网页在更大的窗口大小下的截图：

![jQuery Mobile](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_06_06.jpg)

正如您所看到的，同一个页面现在已经响应了更大的浏览器窗口大小，并重新调整了页面布局以更好地适应可见的显示区域。jQuery Mobile 使用**CSS**媒体查询来定义当前的视口大小，并将页面内容定向到适当的位置，而不是在不同的浏览器大小上显示相同页面的多个设计。使用 jQuery Mobile 构建网站的最大优势是，您无需编写一行**CSS**或自己定义特殊的**CSS**媒体查询。

# HTML5 模板

像 jQuery 这样的库非常适合帮助您轻松编写 JavaScript 代码，但让您的项目启动运行是另一个问题。页面布局、浏览器故障保护和跟踪代码通常是您最终会添加到项目中的所有内容，这些只是**HTML5**模板（[`html5boilerplate.com`](http://html5boilerplate.com)）中的一些出色功能。HTML5 模板在技术上并不是一个库或框架，因为在其核心，它只是创建 HTML5 文档的起点。

然而，由于其简单性、渴望跟上网络周围的所有变化以及在其背后有大量开源贡献的支持，这个**HTML5**模板在处理任何大小的项目时都是一个很好的起点：

![HTML5 模板](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_06_07.jpg)

从项目网站下载最新版本的**HTML5**模板后，您会发现一系列文件，其中不仅包括基本的 ready-to-go `index.html`文件及其引用文件，还包括一组其他常见文件，通常在公共网络服务器的基本网站目录中找到。

要了解这个模板的确切外观和它对您的实际作用，让我们快速浏览一下以下默认的`index.html`文件：

```html
<!DOCTYPE html>
<!--[if lt IE 7]>      <html class="no-js lt-ie9 lt-ie8 lt-ie7"> <![endif]-->
<!--[if IE 7]>         <html class="no-js lt-ie9 lt-ie8"> <![endif]-->
<!--[if IE 8]>         <html class="no-js lt-ie9"> <![endif]-->
<!--[if gt IE 8]><!--> <html class="no-js"> <!--<![endif]-->
    <head>
        <meta charset="utf-8">
        <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
        <title></title>
        <meta name="description" content="">
        <meta name="viewport" content="width=device-width">

        <!-- Place favicon.ico and apple-touch-icon.png in the root directory -->

        <link rel="stylesheet" href="css/normalize.css">
        <link rel="stylesheet" href="css/main.css">
        <script src="img/modernizr-2.6.2.min.js"></script>
    </head>
    <body>
        <!--[if lt IE 7]>
            <p class="chromeframe">You are using an <strong>outdated</strong> browser. Please <a href="http://browsehappy.com/">upgrade your browser</a> or<a href="http://www.google.com/chromeframe/?redirect=true"> activate Google Chrome Frame</a> to improve your experience.</p>
        <![endif]-->

        <!-- Add your site or application content here -->
        <p>Hello world! This is HTML5 Boilerplate.</p>

        <script src="img/jquery.min.js"></script>
        <script>window.jQuery || document.write('<script src="img/jquery-1.9.0.min.js"><\/script>')</script>
        <script src="img/plugins.js"></script>
        <script src="img/main.js"></script>

        <!-- Google Analytics: change UA-XXXXX-X to be your site's ID. -->
        <script>
            var _gaq=[['_setAccount','UA-XXXXX-X'],['_trackPageview']];
            (function(d,t){var g=d.createElement(t),s=d.getElementsByTagName(t)[0];
            g.src=('https:'==location.protocol?'//ssl':'//www')+'.google-analytics.com/ga.js';
            s.parentNode.insertBefore(g,s)}(document,'script'));
        </script>
    </body>
</html>
```

正如您所看到的，这个模板 HTML 文件做了很多事情，而且幸运的是它有非常完善的文档。从头到尾，这个示例充满了浏览器检查和故障保护，网站图标的引用，用于清理和设置开发环境的 Modernizr 的引用，以及对 jQuery 和包括 Google Analytics 访客跟踪的默认代码的引用。

HTML5 模板是在 MIT 许可下开发的，甚至包括一些精制和优化的 Web 服务器配置，如果您有兴趣优化您的 Web 服务器提供内容的方式。

# Bootstrap

如果你和我一样喜欢编写代码而不是处理在 Photoshop 中设计和创建页面，你可能会对 Bootstrap 很感兴趣，这是由两名 Twitter 员工创建的。Bootstrap 是一个 HTML5 框架，旨在让开发人员轻松创建基于 12 列网格系统的强大和响应式页面布局和设计。Bootstrap 支持在所有现代设备和浏览器上正确呈现页面布局，减少了大量编写 CSS 和 JavaScript 的需求，以便以统一的方式为所有用户显示内容，无论他们如何尝试查看您的内容：

![Bootstrap](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_06_08.jpg)

使用 Bootstrap 开发新项目并使其运行起来，就像本章涵盖的许多项目一样，非常简单。只需转到项目网站[`twitter.github.com/bootstrap`](http://twitter.github.com/bootstrap)并下载最新版本。下载并解压缩后，将下载的目录内容移动到项目目录的根目录。您会注意到下载的 Bootstrap 文件不包含用于开始工作的 HTML 文件，而是期望您生成自己的文件。原因是页面没有定义特定的布局模板。Bootstrap 利用网格布局系统，使开发人员能够轻松地将其网站内容放置在网格格式中，以便轻松地响应动态浏览器窗口大小的正确定义布局：

![Bootstrap](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_06_09.jpg)

默认的 Bootstrap 布局是建立在一个具有无限行数的 12 列网格布局上的，因为行的溢出将导致典型的网页滚动。通过查看前面图像中的示例网格布局，您几乎可以想象出您每天使用的每个网站以及它是如何在这样的网格中排列的。由于这种网格布局系统对于几乎任何网页设计都非常有价值，它几乎可以在您将来遇到的几乎每个 HTML5 项目中为您提供帮助。

如果您仍然不确定 Bootstrap 是否适合您的网站，请转到 Bootstrap 项目网站的**示例**部分，查看正在使用该项目的最新热门网站列表[`twitter.github.com/bootstrap/getting-started.html#examples`](http://twitter.github.com/bootstrap/getting-started.html#examples)。

## Bootstrap 附加组件

随着 Bootstrap 的流行度迅速增长，用户贡献的数量也开始跟随。许多这些第三方外部插件和功能可以添加到现有的 Bootstrap 设置中，以扩展其基本功能。让我们快速浏览一下其中一些最受欢迎的项目，以便让您对可用的内容有所了解。

### StyleBootstrap.info

尽管 Bootstrap 在创建元素时附带了许多不同的颜色选择，但您可能希望进一步定制的机会相当高。`StyleBootstrap.info` ([`stylebootstrap.info`](http://stylebootstrap.info))是一个很好的在线资源，可以通过简单的点击和选择用户界面轻松定制 Bootstrap 设置的外观和感觉。完成设计后，该网站将为您生成必要的**CSS**文件，供您下载并包含在项目中。

### Font Awesome

另一个扩展 Bootstrap 已有功能集的优秀库是 Font Awesome ([`fortawesome.github.com/Font-Awesome`](http://fortawesome.github.com/Font-Awesome))。虽然听起来像是这是框架的新字体添加，但实际上它是一个额外的图标集，可以轻松地实现到您的设计中。之所以提到字体的概念是因为图标集实际上是在打包的字体中实现的，以实现可伸缩的矢量图形，而不是在**HTML**文档中找到的典型位图图形。由于您来自 Flash 背景，您可能已经了解了在缩放图像时矢量图形有多么重要，您可能已经明白为什么使用字体打包概念会使库变得非常易于使用。包中的所有图标都有特定的名称，并且可以通过在**HTML**元素中调用该唯一图标名称作为类来轻松实现到您的页面中：

![Font Awesome](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_06_10.jpg)

正如前面的屏幕截图所示，其中仅显示了包中可用图标的一小部分，每个图标都有一个特定的名称。根据项目文档的规定，将图标附加到文档中的最佳方法是在`<i>`或斜体**HTML**标记的类属性中调用唯一的图标名称。例如，如果我们想在文档中的“书籍”旁边放置一个书籍图标，HTML 语法将表示如下：

```html
<p><i class="icon-book"></i> Books</p>
```

由于斜体标记可以放置在几乎任何 HTML 元素中，这使您可以将图标放在需要的任何位置，比如放在 Bootstrap 自定义按钮内部：

```html
<a href="books.html" class="btn">
<i class="icon-book"></i> Books
</a>
```

同样值得注意的是，由于字体包以矢量格式保存，以允许动态字体大小，因此默认的 Bootstrap 设置以及此项目中的图标也都是矢量格式。要更改文档中图标的大小，只需设置`font-size`属性或将其附加到已配置字体样式的元素中。

### bootstrap-wysihtml5

如果您计划构建需要大量基于文本的用户输入的 Web 应用程序，那么 Bootstrap **WYSIWYG**（所见即所得）库值得一看（[`jhollingworth.github.com/bootstrap-wysihtml5`](http://jhollingworth.github.com/bootstrap-wysihtml5)）。只需几行代码，您就可以为用户构建格式化的**HTML**文本内容的优雅工具输入表单：

![bootstrap-wysihtml5](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_06_11.jpg)

尽管简单，这只是互联网上许多免费分发的众多优秀示例之一，随时可以在您的项目中使用。

# Hammer.js

如果您计划进入快速发展的移动 Web 开发世界，处理新的事件，如触摸交互，将是必不可少的。尽管传统的 JavaScript 鼠标事件在触摸设备上直接转换为基本的触摸事件，但是像滑动和捏合这样的事件并不常见于传统的桌面用户交互（[`eightmedia.github.com/hammer.js`](http://eightmedia.github.com/hammer.js)）。

Hammer.js 目前支持轻触、双击、滑动、按住、捏合（变换）和拖动事件，并且可以轻松地实现到任何现有网站中，无论您是否使用 jQuery。由于库的简单性，压缩后的文件大小仅为 2KB：

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>Hammer.js Example</title>

    <style>
      body {
        padding:10px;	
      }
          #touch-area {
              border: 5px dashed #000;
              text-align: center;
              width: 100%;
              line-height:10px;
              padding-top:200px;
              padding-bottom:200px;
          }
          #touch-area p {
          font-size: 30px;
          }
          #touch-area p.subtext {
          	font-size:12px;
          	color:#666;
          }
      </style>

      <script type="text/javascript" src="img/jquery-1.9.1.min.js"></script>
    <script type="text/javascript" src="img/hammer.js"></script>
    <script type="text/javascript"  src="img/jquery.specialevent.hammer.js"></script>
    <script>
      function hammerLog(event){
          event.preventDefault();
          $('#output').prepend( "Type: " + event.type + ", Fingers: " + event.touches.length + ", Direction: " + event.direction + "<br/>" );
      }

      $(document).ready(function() {
        var events = ['hold', 'tap', 'swipe', 'doubletap', 'transformstart', 'transform', 'transformend', 'dragstart', 'drag', 'dragend', 'swipe', 'release'];

        $.each(events, function(key, val) {
          console.log('NOTICE: Applying Touch Event: ' + val);
          $('#touch-area').on(val,  hammerLog);
        });  
      });
    </script>
  </head>

  <body>
    <div id="touch-area">
      <p>Touch here to see results<p>
      <p class="subtext">For best results, open this page on a touch enabled device.</p>
    </div>

    <p id="output"></p>
  </body>
</html>
```

# GreenSock 动画平台

如果您花了足够的时间开发 Flash 应用程序，很可能您以前已经接触过 GreenSock TweenMax 或 TweenLite 库。TweenMax 和 TweenLite 库可以轻松地让您在舞台上移动 Flash 对象，并支持 ActionScript 2 和 ActionScript 3 项目。GreenSock 现在已经开发并发布了他们的纯 JavaScript 库，没有依赖关系，为您的 HTML5 项目带来了许多伟大的熟悉功能。

因此，在查看 jQuery 动画方法及其功能后，为什么您需要使用这样的库呢？与 jQuery 不同，GSAP JS 专注于非常出色地完成一件事。诸如按顺序动画以启用适时的动画、覆盖控制以随时停止运行的动画以及能够对几乎任何内容进行动画处理等功能，将相对轻松地增强您的 Web 应用程序的视觉吸引力。

就像 ActionScript 伴侣一样，GreenSock JavaScript 库（[`www.greensock.com/v12`](http://www.greensock.com/v12)）包含大量的最新文档和示例，将指导您正确的起步方向。事实上，他们专门创建了一个视觉快速入门指南，让您轻松上手并在浏览器中演示代码的结果：

![GreenSock 动画平台](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_06_12.jpg)

GSAP JS 文档的最佳补充是交互式入门指南，可以在[`www.greensock.com/jump-start-js/`](http://www.greensock.com/jump-start-js/)找到。这个简单易用的交互式应用程序可以让您在几分钟内从未使用过该库，了解它的功能；我无法强调这个功能有多么棒。

再次，如果您在以前的 Flash 项目中使用过 GreenSock TweenMax 或 TweenLite 库，那么您将非常容易地转移到 GSAP JS。如前所述，大多数 ActionScript 3 开发人员在使用此库时将面临的主要问题是正确处理为 Tween 提供的**CSS3**属性，以便正确运行。

# Three.js

如果您喜欢硬件加速的 3D 图形世界，`Three.js`（[`mrdoob.github.com/three.js`](http://mrdoob.github.com/three.js)）绝对值得一看。这个轻量级的 3D 库非常容易上手，并且在网络上有大量的示例和文档。`Three.js`不仅使用`<canvas>`元素进行渲染，还使用`<svg>`、`CSS3D`和`WebGL`，从而支持各种现代浏览器和设备。

为了让您对`Three.js`在打印中的功能有所了解，请查看我在查看`Three.js`项目网站上找到的一些示例项目时拍摄的一些美丽的屏幕截图：

![Three.js](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_06_13.jpg)![Three.js](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_06_14.jpg)![Three.js](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_06_15.jpg)

从前面的截图中可以看出，JavaScript 和 WebGL 在很短的时间内取得了长足的进步。再次强调，所有这些截图都是从`Three.js`项目网站上找到的示例中获取的，所以一定要去那里尝试一下，看看它们在您的设备和浏览器上运行得如何。请记住，许多现代移动设备的网络浏览器都渴望获得更强大的 WebGL 支持，因此也可以在手机或平板电脑上尝试一下。

在开始开发您的`Three.js`项目之前，最好确保您熟悉 3D 编程的许多常见方面和原则。在其核心，典型的`Three.js`应用程序将包括一个场景、一个渲染器、一个摄像机和一个对象。这些元素将相互配合，以创建一个 3D 环境。学习关于`Three.js`的最佳入门教程之一是*Paul Lewis*的*Getting Started with Three.js*文章（[`www.aerotwist.com/tutorials/getting-started-with-three-js`](http://www.aerotwist.com/tutorials/getting-started-with-three-js)）。在这篇文章中，他涵盖了 3D 编程的所有原则以及如何在`Three.js`框架中利用它们。

不要深入细节，因为已经有许多优秀的书籍和在线资源可以学习 Three.js 开发，这里是一个在`Three.js`中渲染场景的非常简单的代码布局：

```html
// Scene sizes
var WIDTH = 500;
var HEIGHT = 300;

// set some camera attributes
var VIEW_ANGLE = 45,
    ASPECT = WIDTH / HEIGHT,
    NEAR = 0.1,
    FAR = 10000;

// get the DOM element to attach to
var $container = document.getElementById('example');

// create a WebGL renderer, camera
// and a scene
var renderer = new THREE.WebGLRenderer();
var camera = new THREE.PerspectiveCamera(  VIEW_ANGLE,
                                ASPECT,
                                NEAR,
                                FAR  );
var scene = new THREE.Scene();

// the camera starts at 0,0,0 so pull it back
camera.position.z = 300;

// start the renderer
renderer.setSize(WIDTH, HEIGHT);

// attach the render-supplied DOM element
$container.append(renderer.domElement);

// create the sphere's material
var sphereMaterial = new THREE.MeshLambertMaterial({ color: 0xCC0000 });

// Set up the sphere vars
var radius = 50, segments = 16, rings = 16;

// Create a new mesh with sphere geometry -
// we will cover the sphereMaterial next!
var sphere = new THREE.Mesh(
   new THREE.SphereGeometry(radius, segments, rings),
   sphereMaterial);

// Add the sphere to the scene
scene.add(sphere);

// and the camera
scene.add(camera);

// create a point light
var pointLight = new THREE.PointLight( 0xFFFFFF );

// set its position
pointLight.position.x = 10;
pointLight.position.y = 50;
pointLight.position.z = 130;

// add to the scene
scene.add(pointLight);

// draw!
renderer.render(scene, camera);
```

从前面的`Three.js`代码示例的顶部开始，我们可以看到最初将舞台大小附加到`WIDTH`和`HEIGHT`变量中。这些属性对每个 Flash 开发人员来说都很熟悉，它们定义了内容将被渲染的可视区域。在舞台配置之后是初始摄像机配置。创建 3D 场景时，渲染前端的视图将来自已放置在场景中的摄像机的透视。就像任何其他对象一样，摄像机可以根据 x、y 和 z 值以及属性（如视角、摄像机方面和缩放能力）移动。摄像机配置之后，我们需要将文档中的特定元素作为我们的舞台目标，并且`document.getElementById`查找我们在 HTML 文档中已经创建的元素就可以了。配置值设置好，选择了一个准备好设置我们场景的元素，我们实际上可以开始初始化我们的`scene`元素。

当然，`Three.js`项目并不需要 100%使用 JavaScript。一旦您的场景设置好并准备好查看，转到 Blender 或 Maya 等 3D 建模软件将允许您创建极其详细的 3D 对象，这些对象可以轻松地导入到您的 HTML5 项目中。正如您之前在一些示例图像中看到的那样，可以获得的细节水平简直令人惊叹。

关于在 JavaScript 中使用 3D 或 WebGL 的最后一点说明：目前在桌面环境中，浏览器对 WebGL 的支持已经非常广泛。您几乎不会在几乎所有现代桌面 Web 浏览器中遇到任何问题，但是在移动浏览器中可能仍然会遇到许多限制。谷歌 Chrome 浏览器在桌面和移动端都试图通过 Chrome 实验网站([`www.chromeexperiments.com/webgl/`](http://www.chromeexperiments.com/webgl/))来推动 WebGL 的极限。该网站包含大量出色的示例和项目，可以让您轻松测试您正在运行的浏览器、设备或平台对硬件加速图形的处理能力。

# 编译 JavaScript

早已过去了将 JavaScript 仅视为用于 HTML 元素操作的前端开发语言的日子。随着 JavaScript 编译器的出现，仅仅编写一些 JavaScript 代码就可以做一些难以想象的事情。就像您在 Flash 中习惯的方法，其中 ActionScript 被编译成二进制包一样，JavaScript 编译器将纯 JavaScript 转换为机器代码，可以在计算机上像任何其他应用程序一样运行。尽管这个概念可能看起来很遥远，但实际上有很多很好的原因，其中最好的原因是用于 Web 浏览器。

## 谷歌的 V8 引擎

2008 年底，谷歌发布了 Chrome 的初始版本，随之而来的是 V8 引擎的初始版本。V8 将 JavaScript 直接编译成本机机器代码，甚至在这样做时优化代码。结果是应用程序可以像用 Python 或 C++编写的应用程序一样运行。V8 是用 C++编写的，并自原始发布以来一直是开源和免费提供给公众的。您可以通过访问项目网站[`code.google.com/p/v8`](http://code.google.com/p/v8)了解更多关于 Google V8 项目的信息。

## Node.js

从谷歌 V8 引擎诞生的最酷的新项目之一就是 Node.js([`nodejs.org`](http://nodejs.org))。`Node.js`允许您完全使用 JavaScript 编写服务器端应用程序（通常是 Web 服务器），这通常是用**PHP**、**Perl**、**Python**甚至**C**或**C++**等编程语言完成的。

与本章涵盖的许多框架和库一样，`Node.js`拥有大量的优秀文档和示例，遍布整个网络。然而，由于一些项目的开发速度，可用的文档很容易过时。`Node.js`最好的资源之一是由`Node.js`项目的早期核心贡献者之一*Felix Geisendörfer*创建的[`nodeguide.com`](http://nodeguide.com)，该资源不断更新到项目的当前稳定版本。

由于`Node.js`是用于服务器端运行的，而不是将其包含到您的**HTML5**项目中，您必须在计算机上安装它以便作为应用程序运行。因此，在您选择的计算机上下载并安装`Node.js`文件后，您现在可以像运行任何其他命令行应用程序一样从命令行运行`Node.js`准备好的 JavaScript 文件。

为了演示如何启动`Node.js`应用程序的基本用法，我们将使用流行的`Node.js` Web 服务器示例，该示例可以在官方文档中找到。创建一个名为`example.js`的新 JavaScript 文件，并使用以下 JavaScript 填充它：

```html
var http = require('http');

http.createServer(
  function (request, response)
  {
    response.writeHead(200, {'Content-Type': 'text/plain'});
    response.end('Hello World\n');
  }
).listen(8000);

console.log('Server running at http://localhost:8000/');
```

示例代码的第一行是在`Node.js`框架中导入**HTTP**模块。包含 HTTP 模块后，将调用`createServer`方法并提供成功函数。该函数包含一个简单的“Hello World”问候，并将`Content-Type`设置为`text/plain`，因此查看它的浏览器知道它只是纯文本。最后，将`listen`方法链接到服务器声明中以指定端口，**HTTP**服务器将在该端口上监听请求。

保存`example.js`文件后，在运行`Node.js`的系统上打开命令行，并将当前工作目录指向您的新 JavaScript 文件的位置，然后输入以下命令。使用`Node.js`执行文件就像使用*node*应用程序引用 JavaScript 文件一样简单：

```html
% node example.js

```

执行此命令将产生以下响应：

```html
Server running at http://localhost:8000/

```

命令行将等待物理终止。在停止服务器之前，我们必须测试以确保它正常工作。因此，在执行`node`命令后，转到响应中指定的 URL：

![Node.js](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_06_16.jpg)

尽管这个输出很简单，但事实上，您只是使用 JavaScript 创建了一个简单的自定义 Web 服务器。这只是`Node.js`所提供的众多功能的开始，最好的部分是`Node.js`可以做的许多伟大的事情已经存在，并且随时可供您查找和使用。`Node.js`不需要在 Google 上花费数小时搜索要包含在项目中的模块，它使用自己的系统来查找并安装更多功能到您的`Node.js`服务器中。

## Node 包管理器

如果您仍然不确定`Node.js`对您有什么作用，**NPM**（**Node 包管理器**）可能能够帮助您。包管理器是一个在线收集的包，可以轻松地在您的节点项目中下载和使用。由于`Node.js`已安装在您的计算机上，当涉及到检查依赖关系、版本和平台支持时，包管理器可以完成所有繁重的工作。要轻松搜索当前的`Node.js` **NPM**目录，请转到[`npmjs.org`](https://npmjs.org)并浏览，直到找到您有兴趣安装的内容：

![Node 包管理器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_06_17.jpg)

在注册表中找到的任何包都可以通过在命令行中运行安装命令来轻松安装到您的系统上：

```html
% npm install PACKAGE-NAME

```

如前所述，如果您请求安装的软件包需要注册表中的其他软件包，它们将自动下载和安装，而无需您自己去寻找适当的版本。随着开发人员对您可能使用的软件包进行更新并发布更新，NPM 注册表将自动负责向您提供更新信息，并允许轻松更新您安装的任何过时软件包。

## 托管公共 Node.js 服务器

由于您需要一个服务器来运行您的`Node.js`项目，您需要设置一个面向公众的服务器来托管您希望对互联网开放的任何项目。由于在计算机上安装`Node.js`进行测试无法实现这一点，您需要设置自己的服务器，并进行适当的网络设置，或者从`Node.js`托管公司购买此服务。由于您用于网页托管的公司通常不允许您完成此操作，因此研究 Nodejitsu（[`nodejitsu.com`](http://nodejitsu.com)）等服务可能会有用：

托管公共 Node.js 服务器

与传统的网络托管公司一样，Nodejitsu 提供您自己的面向公众的`Node.js`服务器，可用于在线的任何网页项目。您可以始终从免费试用账户开始，以了解该服务如何允许您在世界各地使用您的`Node.js`服务器，然后根据您的需求转入付费账户。

# 摘要

本章仅仅触及了作为 HTML5 开发人员可用的一部分内容。这里介绍的是目前最流行的一些库和框架的集合。全世界开发人员公开发布并积极开发的惊人代码数量似乎以超指数速度增长。分配和利用本章列出的外部资产需要您作为开发人员在将其实施到公开网站之前了解使用库或框架的影响和好处。

花时间去研究、测试和贡献许多您感兴趣的项目，不仅有利于您现有的开发技能，还可以让您利用手头的最佳工具。随着时间的推移和网络开发的变化，跟上这些流行的库和框架将始终有助于您了解整个 HTML5 开发环境的最新情况。

在下一章中，我们将把这些新获得的 HTML5 框架和库的知识扩展到直接将您现有的 Flash 应用程序转换为 HTML5 网页项目的领域。


# 第七章：选择开发方式

进入 HTML5 开发流程将需要您摆脱在 Flash 开发周期中熟悉的应用程序。诸如 Flash 专业版、Flash Builder 和 Flash Develop 等应用程序都是专门设计用于处理 Flash 内容的。尽管这些应用程序非常出色，但有许多类似的 HTML5 开发应用程序可以让您以非常类似的方式构建丰富的网络体验。本章将介绍摆脱使用 Adobe Flash 专业版开发环境的过程，并开始艰难决定在创建 HTML5 项目时使用什么新的开发软件。虽然有许多优秀的软件可供选择，本章将介绍许多当前网页开发人员正在使用的新型和流行的应用程序。

在本章中，我们将涵盖以下内容：

+   了解 HTML5 IDE 所需的内容

+   资产创建和操作工具

+   使用 Adobe Edge 创建交互式动画 HTML5 元素

+   一些最受欢迎的 HTML5 代码编辑器概述

+   代码执行和运行时测试工具

# 替换 Flash 开发环境

在 Flash 环境中开发应用程序的最大优势在于 Adobe 花费大量时间构建了 Creative Suite 中包含的工具和应用程序，使您能够在其应用程序集中创建整个应用程序。尽管有人认为这个系统限制性强，更新速度慢。事实是，当所有正确的工具都可用于帮助您构建应用程序时，进入下一个项目就会更容易。由于 HTML5 开发不受特定公司的监管或控制，它是一个更加开放的开发平台，开发人员可以自由选择如何以及使用什么来构建他们的项目。

我必须强调，在本章中，我们将概述许多 HTML5 开发人员用来完成工作的常见方法和应用程序。当然，这些应用程序或方法都不是构建 HTML5 项目的绝对正确方式，希望您能找到符合您需求的应用程序。随着时间的推移，您构建越来越多与 HTML5 相关的项目，一定要在研究最适合手头工作的最佳工具时付出额外的努力。快速变化的环境导致许多项目在短时间内兴起和衰落。了解市场上的情况将有助于保持您的竞争力，并继续扩展您的 HTML5 开发技能。

# HTML5 开发环境的要求

当在同一个代码编辑器中编写 HTML、CSS 和 JavaScript 时，大多数开发人员通常会考虑一些一般性的因素，以确保他们获得适合自己需求的功能集。由于整个 HTML5 堆栈都是以纯文本文档的形式呈现，从技术上讲，任何文本编辑器都可以完成工作。尽管每个开发人员都有自己独特的设置和开发风格，但总是值得留意许多常见的功能。

## 资产和文件管理

具有预览甚至操纵项目中包含的资产的能力，如图像、视频、音频和其他外部资产，直接在开发环境中可以帮助您加快开发流程，将焦点集中在特定应用程序内。我们将在稍后介绍的 Adobe Dreamweaver 等应用程序是设计用来将设计和开发过程结合在一起的绝佳例子。值得注意的是，本章将概述的许多简单的代码编辑器可能不包含支持轻松文件和资产管理的功能。然而，当像这样的大型功能集成不包含在代码编辑器中时，一般的最终结果是更快速、轻量级的应用程序。

## 代码高亮

与任何编程语言一样，代码高亮或着色是代码编辑器中必不可少的功能。轻松理解代码的各个部分在做什么的能力，不仅可以让您更轻松地开发应用程序，还可以帮助您更轻松地理解其他开发人员的代码。代码高亮也是确保您以正确的语言语法编写代码的关键。为了让代码编辑器能够正确地着色或高亮显示您的代码，应用程序必须能够正确识别和解析您的代码所编写的特定语言。因此，在寻找最佳选择时，要密切关注支持您打算使用的特定编程语言的代码编辑应用程序是至关重要的。幸运的是，在我们的情况下，HTML5 开发或 HTML、CSS 和 JavaScript 开发得到了许多可用的代码编辑应用程序的广泛支持，因此您拥有的选择非常丰富。

## 代码完成

在您选择使用的代码编辑器中内置良好的代码完成功能可以帮助您学习新的编程语言。如果您在 Flash 开发职业生涯中使用 Flash Builder，我相信您已经看到了您可以编写良好、有效的代码的速度有多快。尽管一些开发人员认为代码完成只会让开发人员变得懒惰，避免记住语言语法的具体细节。事实是，从新手到经验丰富的老手，开发人员都使用代码完成来避免在编写代码时出现延迟，以及加快编写长代码片段所需的时间。

在使用 Flash Builder（[`www.adobe.com/products/flash-builder.html`](http://www.adobe.com/products/flash-builder.html)）或 Flash Develop（[`www.flashdevelop.org`](http://www.flashdevelop.org)）等开发环境开发 Flash 应用程序时，您将面临着利用代码完成的最佳情况之一。由于这些代码编辑器专门用于编写 ActionScript 3，它们可以通过专注于 ActionScript 3 API 中可用的内容来优化开发体验。

实际上，在开发 HTML5 或其他许多语言时，存在两种形式的代码完成。这种明显的形式是在您输入时自动完成文本。例如，当您键入声明的变量名称并按下*.*键以准备指定该对象上的属性时。一些编辑器将在活动代码行下生成一个下拉菜单，列出您可以附加到当前对象上的可用属性列表。当学习一种新语言时，这种代码完成形式非常方便，因为它在您开发时就在您面前展示了可用的可能性。代码完成的第二种形式是生成更大的代码片段。例如，当您尝试通过在代码编辑器中键入单词`function`来声明一个新函数时，一些编辑器会识别这一点，并自动生成默认的函数布局。您所要做的就是填写内部代码，然后完成。一些开发人员对此功能有意见，因为它可能无法生成符合其精确规范的代码，但现在许多编辑器都支持修改预先存在的代码片段甚至添加自己的代码。

## 创建和操作资产

作为以前在 Flash 中创建应用程序的开发人员，您可能已经习惯于使用 Flash Professional 开发环境，不仅可以将应用程序资产文件存储在 SWC 文件中以供项目包含，还可以构建整个项目。在功能丰富的开发环境中使用项目资产的能力，比如 Flash Professional，是 Flash 首先变得如此受欢迎的原因之一。转向 HTML5 开发时，失去这样一个用于构建和操作资产的出色开发环境将是一件遗憾。幸运的是，随着 HTML5 的普及，许多新的令人兴奋的项目和应用程序已经发布，将这种资产控制带到了 Web 开发周期中。

### Adobe Edge Animate

随着 Adobe 将其产品发展为完全基于云的软件设置，他们还推出了许多基于 HTML5 的项目，使 Web 开发人员可以在传统的 Adobe 用户友好环境中轻松创建 HTML5 内容。在这个系列中最新和令人兴奋的软件之一是 Adobe Edge。Edge 允许在一个点和点击用户界面中轻松创建交互式和动画的 HTML5 内容。实质上，您可以将 Edge 视为在 HTML5 堆栈中使用 HTML、CSS 和 JavaScript 开发时 Flash IDE 的替代品。尽管这个软件远没有 Flash IDE 支持的功能强大，但自发布以来，其功能支持已经呈指数级增长。

通过登录 Adobe 的应用程序管理器，可以免费下载 Adobe Edge。前往[`html.adobe.com/edge/animate`](http://html.adobe.com/edge/animate)下载 Edge，并注册 Adobe 帐户（如果尚未注册）。设置完帐户后，在应用程序管理器中找到**Edge Tools & Services**部分，并将软件下载到您的计算机。值得注意的是，正如前面提到的，这种新的基于云的软件交付系统是 Adobe 正在朝着的新方向，以便更轻松地访问其目录中的软件。您可以通过单击下面截图中显示的每个可用软件描述下的**Try**链接来轻松测试 Adobe 的任何其他产品。

![Adobe Edge Animate](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_01.jpg)

一旦您成功下载并安装了 Edge，启动它，您就可以首次看到用户界面。虽然它不完全像您可能习惯于的 Flash Professional 用户界面，但您可能会看到许多相似之处，这将使您轻松地整合您从 Flash、Photoshop 等软件中获得的现有 Adobe 用户界面技能：

![Adobe Edge Animate](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_02.jpg)

让我们花点时间来概述 Edge 对 CSS3 滤镜和动画等独特功能的激动人心的支持和功能。我们可以从一个简单的蓝色框开始，这是用户界面领域的 Hello World。默认情况下，主要工具栏位于窗口顶部，方形形状工具在其中很容易找到：

![Adobe Edge Animate](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_03.jpg)

值得一提的是，工具栏中的其他工具也很熟悉和不言自明。无论如何，我们很快就会回来仔细研究它们。现在我们将选择方形形状工具，并在用户界面中呈现的舞台上绘制一个相当大的矩形。请注意，这个过程与在 Flash 中创建内容非常相似：

![Adobe Edge Animate](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_04.jpg)

默认情况下，你的形状不会是蓝色的，所以在放置在舞台上后，转到默认情况下位于应用程序窗口左侧的**属性**面板，并使用颜色选择器修改形状的颜色。

准备好进行动画处理的框后，让我们把焦点转移到默认情况下显示在应用程序窗口底部的**时间轴**面板。如前所述，如果你花时间在 Flash Professional 和基于时间轴的动画上，Edge 中的这个功能不仅会很熟悉，而且可能会让你兴奋。如果时间轴动画的概念对你来说是新的，那么它是控制应用程序视图中元素在一定时间内的过程。通过定义你的资产如何随时间变化，你可以轻松控制它们在特定播放间隔上的行为。为了演示这一点，我们将使用时间轴来使我们的新蓝色矩形在舞台周围进行动画，同时应用不同的效果和属性。

首先，我们将启用切换销钉，这将轻松地允许我们在动画时间轴的关键帧中设置元素的新状态。切换销钉位于**时间轴**面板中的顶部按钮导航中。它用蓝色销钉标记表示：

![Adobe Edge Animate](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_05.jpg)

启用切换销钉后，当时间轴设置为新位置时，元素的任何更新将仅应用于该新关键帧内。结果将是在一定时间内自动生成的动画补间。

通过将时间轴上的播放头拖动到 1 秒，我们现在告诉 Edge 开始将新属性应用于舞台上的任何元素。因此，让我们将蓝色框从舞台的左上角拖动到右上角，然后按空格键查看结果动画：

![Adobe Edge Animate](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_06.jpg)

当然，在文本中你只能相信我的话，但结果是你在 Flash 中对元素进行补间动画时所习惯的。当播放头从 0 秒移动到我们新的 1 秒关键帧时，蓝色框的位置会自动更新，从起点到终点进行动画。尽管这个例子很简单，但它不仅展示了 Edge 与 Flash Professional 非常相似的许多方面，而且突出了 Edge 的核心功能。

让我们花更多时间来检查我们的蓝色框还能做些什么，通过查看**属性**面板中提供的内容。不要深入每个**属性**面板的细节，总结起来最简单的方法是，它显然受到了 Flash 专业版中**属性**面板的启发。虽然 Edge 中可用的一些属性与 Flash 不同，但布局和风格几乎相同。如果 Adobe Edge 引起了您的兴趣，值得花些时间查看当前版本中提供的一些可用属性。我还建议在测试时，打开发布的文件，并在您可以使用的所有浏览器中进行测试，从桌面到移动设备。了解不同设备和平台对 HTML5 动画负载的反应，以更好地判断未来应用程序的推进程度。

当然，在开发或测试阶段的任何时候，您都可以在**文件**菜单中选择**在浏览器中预览**选项，查看您当前项目在实际网络浏览器中的外观和感觉。这也是深入生成的源代码以更好地了解 Edge 编译器实际为我们做了什么的绝佳时机。

Edge 将应用程序源代码构建为 HTML、CSS 和最小化的 JavaScript 文件，并将 JavaScript 数据保存为`YOUR-PROJECT-NAME_edgePreload.js`的文件名。尽管这些最小化的 JavaScript 很难阅读或理解，但它被设置为尽可能小的文件大小，以优化通过互联网由最终用户检索时的加载速度。

Adobe Edge 还包含一个内置的代码编辑器，允许您轻松地将代码附加到您的 Edge 项目中，进一步扩展您的 Web 应用程序的功能。这个代码编辑器，虽然使用方式略有不同，但对于任何在 Flash IDE 中编写过任何 ActionScript 的人来说，它是一个极具辨识度的面板。在代码编辑面板中，您将找到一系列代码片段，可以通过单击将其附加到您的项目中。从在您的元素上添加播放方法调用这样简单的功能，到动态创建和销毁您的元素的新实例，内置的代码片段可以轻松帮助您入门。代码编辑器还可以通过仅显示您操纵元素所需的内容来简化代码显示。这可以通过选择代码窗口右上角的**完整代码**选项卡来切换，结果将显示整个项目 JavaScript 文档源代码。

## 编码环境

通常，创建 HTML5 项目的大部分工作将在一个设置允许您在同一位置编写 HTML、CSS 和 JavaScript 的环境中进行。由于所有这些不同的开发语言都包含在纯文本文件中，因此在选择编辑器时没有特定的要求。然而，随着 HTML5 成为一个更成熟的 Web 和应用程序开发平台，支持媒体集成、代码格式化和完成、设备测试和调试等功能的平台几乎已成为必需。许多自 HTML5 之前就存在的软件标题已更新其功能集，以支持 HTML5 开发，并添加了新功能，使 Web 开发变得更加容易。一个很好的例子就是 Adobe Creative Suite 最新版本中包含的最新版本的 Adobe Dreamweaver。

### Adobe Dreamweaver CS6

由于 Adobe Creative Suite 应该已经对您来说有些熟悉，我们将从 Adobe 的 Dreamweaver 开始概述 HTML5 代码编辑器。Dreamweaver 自从第 3 版以来一直是 Creative Suite 的一部分。尽管您可能会发现许多网页开发人员对 Dreamweaver 有爱恨交织的关系，因为如果您购买了 Creative Suite，它非常容易获得，许多网页开发人员曾经或另一次使用过它。现在需要注意的重要事情是，无论您以前是否使用过 Dreamweaver，Adobe 都已经添加了大量专门与 HTML5 网页开发相关的新功能，以帮助您整个开发周期中的工作。

![Adobe Dreamweaver CS6](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_08.jpg)

我不会深入探讨 Dreamweaver 的使用，因为网络上有许多优秀的书籍和教程可以帮助您学习其功能集和用户界面。然而，我将概述 Dreamweaver CS6 包含的一些新的和令人兴奋的功能，以便让网页开发人员轻松地将 HTML5 元素和功能集成到他们的网页项目中。值得注意的是，写作本书时，这些功能中的许多功能只在 Creative Cloud 上 Dreamweaver CS6 的第二次更新中才可用。目前安装了 Dreamweaver 原生版本的用户目前没有这些功能。如果您有兴趣测试其中一些功能，请从 Creative Cloud 下载 Dreamweaver 的 30 天试用版并尝试一下。

#### 音频和视频嵌入

Dreamweaver CS6 的最新更新增加了一些围绕将 HTML5 准备好的音频和视频文件包含和操作到您的文档中的新功能。与许多可以导入到 HTML5 项目中的媒体形式一样，音频和视频现在可以轻松地从项目源目录中选择，并通过几次点击放置到您的文档中。从 Dreamweaver 用户界面直接设置元素属性，如自动播放，启用播放控件，甚至设置海报图像，都可以轻松完成。这个过程不仅可以确保您正在开发媒体播放代码到正确的语法规范，而且可以轻松地为只支持特定文件类型的浏览器和平台设置播放替代方案。

#### Adobe Edge 支持

由于您已经了解了 Adobe Edge Animate 的一些功能，您可能会理解为什么直接将 Adobe Edge 集成到 Dreamweaver 中对于网页开发人员来说是一个巨大的胜利。现在，您可以无缝地将交互式和动画元素直接集成到 Dreamweaver 项目中，而不是手动地从 Adobe Edge 项目中提取导出的数据并将其应用到您自己的项目中。如果您曾经有幸在 Flash Professional 中使用“从 Photoshop 导入”功能节省了几个小时，您将很容易理解这种跨应用程序通信如何为您节省无数的开发时间。

#### PhoneGap 和 jQuery Mobile 支持

您可能会惊讶地发现，Adobe 实际上在 jQuery Mobile 框架的开发中扮演了重要角色。看来两者的关系仍然很密切，因为 Adobe 已经将其对 Dreamweaver CS5.5 的完整 jQuery Mobile 支持延续到了 CS6。最新的 jQuery Mobile 功能更新使得为您的 jQuery Mobile 项目设置主题变得非常容易：

![PhoneGap 和 jQuery Mobile 支持](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_09.jpg)

正如您在上一张截图中所看到的，jQuery Mobile **Swatches**面板允许我们轻松选择项目的实时视图中的特定元素，并通过单击鼠标应用新的主题属性到该元素。生成的代码更新显示为突出显示的更改，向您展示了在现有文档中进行了什么修改。此功能远远超出了仅支持默认 jQuery Mobile 主题。Dreamweaver 将自动检测已附加到项目中的任何自定义主题，并允许您继续在 Dreamweaver jQuery Mobile **Swatches**面板中操作和实现该主题。您可以将选择范围缩小到网页中的特定元素，并修改图标和字体等资源。最受欢迎的 HTML5 移动框架变得更加易于使用。

PhoneGap 用户也不会被冷落。如果您希望将移动项目构建为原生应用程序，Dreamweaver 已经从开发人员的角度使其非常用户友好。新的 PhoneGap **Build Service**面板允许您通过单击几下鼠标为任何支持的移动平台构建当前的工作项目。您可以从 Dreamweaver 内部将 PhoneGap 构建发送并从 PhoneGap 构建服务器下载。使用 HTML5 为五种不同的流行移动平台构建原生应用程序从未如此简单或用户友好。

#### 流体网格布局和 HiDPI 支持

Dreamweaver 中的新**流体网格布局**系统允许您从项目创建开始轻松地针对特定设备定位和自定义网页布局。在页面布局中激活网格系统后，您可以开始指定特定元素可以占用多少列。如果浏览器窗口大小调整或页面加载到高于或低于目标屏幕分辨率的显示器上，网格系统将自动响应更改，更新将显示多少列。在网页中布置元素的概念并不新鲜。然而，随着现在可以访问您的内容的设备的发布，要求跟上现代显示规格可能会很耗费精力。Adobe 已经使 Dreamweaver 用户能够轻松集成优化的条件集，从而实现轻松的响应式 Web 设计。

![流体网格布局和 HiDPI 支持](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_10.jpg)

今天我们看到移动和台式屏幕的像素密度越来越高。即使开发人员没有访问权限，也需要适当的环境来测试这些显示器，这已经成为必须。Dreamweaver 现在已经将 HiDPI 支持集成到易于使用的用户界面中，使得针对特定显示类型进行测试变得轻而易举。

### Aptana

如果您来自主要在 Flash Builder 中存在的 Flash 开发背景，那么 Aptana（[`www.aptana.com`](http://www.aptana.com)）可能值得一看。Aptana 建立在与 Flash Builder 相同的 Eclipse（[`www.eclipse.org`](http://www.eclipse.org)）编辑器上，为许多 Flash 开发人员带来了非常熟悉的代码开发用户界面：

![Aptana](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_11.jpg)

Aptana 包括许多专门设计用于辅助 Web 开发的出色功能。代码辅助功能可帮助处理 HTML、CSS 和 JavaScript 语法，部署向导可以轻松地将自动文件更新集成到您的公共 Web 服务器中。Aptana 还包含内置的 Git 集成支持，因此您可以轻松地为您的项目集成版本控制支持。与 Flash Builder 一样，Aptana 允许您轻松地将多个项目同时添加到应用程序中。在您面前有来自多个项目的代码可以在引用其他地方添加的功能源代码时轻松节省时间。Aptana 是免费的，开源的，并且由一大群贡献者积极开发。

### Brackets

Adobe 的 Brackets（[`brackets.io/`](http://brackets.io/)）是目前正在开发中的最新和最令人兴奋的 HTML5 代码编辑器之一。这个开源编辑器不仅专门为 HTML5 开发人员设计，而且应用程序本身实际上是用 HTML5 堆栈编写的，使您可以轻松定制您的编辑体验。

Brackets 实际上是 HTML 开发在过去几年中发展的一个惊人的代表。使用 Web 技术在计算机上创建这样一个丰富的交互环境来操作本地文件，只是朝着完全基于 Web 应用程序的生活方式迈出的又一步。

Brackets 仍处于早期开发阶段，但已经可以被任何人使用。尽管它是用 HTML、CSS 和 JavaScript 编写的，但由于它被打包并作为桌面应用程序运行，它可以轻松地在本地机器上创建和操作文件。

要开始使用 Brackets，您需要前往项目网站获取最新版本的链接（[`download.brackets.io/`](http://download.brackets.io/)）。与许多开源项目一样，作为最终用户，您将被要求下载软件的预打包版本，这通常是最稳定的。或者您可以下载每夜版或最新的开发版本，这是项目贡献者正在积极开发的版本。开发版本可能会不稳定，并可能在使用过程中出现一些问题。然而，如果您愿意冒着使用有 bug 的软件的风险，那么您在使用过程中获得的信息和经验对于项目的开发团队来说可能非常重要。您遇到的问题和 bug 应该记录在 Brackets 的 GitHub 项目账户的**Issue Tracker**中（[`github.com/adobe/brackets/issues`](https://github.com/adobe/brackets/issues)）。

为了举例说明，我将下载软件的最新预打包稳定版本，以展示 Brackets 提供的一些令人兴奋的功能。下载安装程序并运行后，在 Windows 或基于 OS X 的机器上打开应用程序。在应用程序的初始启动时，您将看到一个默认的示例设置，类似于以下屏幕截图：

![Brackets ](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_12.jpg)

正如您在上一个屏幕截图中所看到的，界面虽然对许多人来说很熟悉，但却极为简单，同时又具有优雅的风格和布局。

#### 内联编辑

目前内置在 Brackets 中的最酷的功能之一是其易于使用的内联代码编辑系统。作为 Web 开发人员，您会发现自己不仅在开发项目时从一个程序跳转到另一个程序，而且还会从包含完全不同编程语言的文件跳转。为了简化这个过程并加快文档中元素的开发，Brackets 允许您选择 HTML 文件中的元素，并查看它们的相关 CSS 样式。要实现这一点，选择 HTML 示例文件中的一个元素，然后按下*Ctrl* +*E*或*Cmd* + *E*（取决于您的操作系统）以在同一 HTML 文件中直接显示该元素的样式。

您不再需要浪费时间在专用的 CSS 文件中逐行查找元素样式。现在 Brackets 可以在您继续编写代码的同时进行所有繁重的搜索工作：

![内联编辑](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_13.jpg)

当内联编辑器显示时（如在前一个屏幕截图中在`<body>` HTML 元素标签下看到的），不仅可以轻松编辑与所选元素相关的样式，还会显示一些重要的数据。在内联样式窗口的左上角是包含相关样式的文档的文件名，文件名旁边是可以找到样式的行号。

内联编辑的概念就像是简单的一样，我们可以通过检查包含多个样式定义的元素的样式来进一步完善它。例如，查看以下链接元素中的多个不同样式的括号显示了所有以某种方式应用于同一元素的不同样式。通过在内联编辑器中选择不同的定义，您可以轻松地在每个样式设置之间切换，编辑它们，然后继续进行。当然，这种内联编辑的概念不仅适用于 HTML 和 CSS，它也适用于您的 JavaScript 开发周期。Brackets 团队仍在将更多的内联编辑功能扩展到应用程序中，扩展功能包括颜色和渐变选择等。

#### 实时预览

Brackets 中已经内置的另一个很棒的功能是**实时预览**。与传统的编辑代码、保存代码，然后转到浏览器进行测试的方法不同，实时预览系统将这一切简化为在您输入时自动进行测试构建。当在应用程序窗口的右上角激活**实时预览**按钮时，默认的系统 Web 浏览器将打开包含当前工作的 HTML 页面。如前所述，选择了此功能后，您可以继续修改当前文档并在输入时查看反映的更改：

![实时预览](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_16.jpg)

上述截图说明了对 body 元素的 background-color 样式属性的更改，将其从白色更改为红色。这种简单的自动保存和重新加载功能只是 Brackets 的另一个部分，它使 Web 开发人员花费更少的时间来执行重复耗时的任务。

#### 插件

由于 Brackets 是开源的，并且是使用与其预期使用的相同平台创建的，许多开发人员已经开始为 Brackets 创建自己定制的扩展和插件。从使用鼠标进行自定义代码高亮的能力，到增加对代码完成的支持，公众的输入范围已经非常惊人。当然，您不必依赖公众来将新功能引入 Brackets。如前所述，整个项目都是使用您在本书中学习的技术构建的。因此，如果您愿意尝试添加一些新的独特功能到 Brackets 中，这可能是一个很好的学习项目。

#### 贡献

Brackets 最棒的部分不仅在于它完全开源、免费提供并且在积极开发中，而且整个应用程序都是基于 HTML5 堆栈构建的。随着您的 Web 开发技能的增长，Brackets 项目可以成为一个与世界其他地方分享您的开发技能的绝佳场所。开发团队不断追加公众提交的更新和修改，并且始终要求用户提供更多的意见。由于 Brackets 仍在开发中，现在是一个很好的时机来加入并帮助创建可能成为下一个重要的 HTML5 代码编辑器的东西。所有项目信息都可以在项目网站页面以及项目 GitHub 页面中找到。如果您希望深入了解更多，请登录 IRC 并在[freenode.net](http://freenode.net)上检查`#brackets`频道。

### Sublime Text

如果像 Brackets 这样的轻量级代码编辑器更适合您，那么 Sublime Text 是另一个值得一试的编辑器（[`www.sublimetext.com`](http://www.sublimetext.com)）。Sublime 简单、轻巧，并且支持大量的编程语言，因此它不仅可以用于 HTML5 开发：

![Sublime Text](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_17.jpg)

Sublime 的多文本选择功能值得注意。在处理大型代码文档时，经常需要对大量文本进行相同的编辑，例如间距。为了解决这个问题，Sublime 使用多文本选择和编辑功能，允许您轻松修改同一文档的许多部分，只需进行一次更改：

![Sublime Text](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_18.jpg)

正如您在上述截图中所看到的，Sublime 还包括代码的最小化布局，以便您根据外观轻松定位代码的特定部分。尽管这听起来有些奇怪，但令人惊讶的是，它确实非常有效。Sublime 还有许多其他出色的功能，使它成为我个人最喜欢的代码编辑器之一。

Sublime 可在 Windows、OS X 和 Linux 上免费下载和永久使用。但是，为了去除购买提醒，可以从 Sublime Text 网站购买 70 美元的许可证([`www.sublimetext.com/buy`](https://www.sublimetext.com/buy))。

# 执行和测试

到目前为止，所展示的许多软件标题都包含了它们自己的方法来帮助您测试和调试您的网站和应用程序的过程。然而，用于测试和测试的技术数量正在以难以保持领先地位的速度增长。拥有不同应用程序和服务的库不仅可以让您测试项目的许多不同方面，还可能在此过程中节省大量时间。

## Web 浏览器开发人员控制台

尽管我们在本书中已经花了一些时间研究了许多流行浏览器开发人员控制台中包含的功能，但在考虑前端执行基准测试和测试时，还有一些其他方面值得研究。随着项目的规模和复杂性不断增长，您需要花时间优化应用程序的流程和执行。如果您曾有机会使用 Adobe Flash Profiler 或 Adobe Scout 来深入了解应用程序在运行时的操作和情况，您可能已经了解了这种预防措施的好处：

![Web 浏览器开发人员控制台](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_19.jpg)

上述截图来自新的 Adobe Scout ([`gaming.adobe.com/technologies/scout/`](http://gaming.adobe.com/technologies/scout/))，游戏开发人员使用这些工具来查看游戏实际进行时的情况。不幸的是，放弃 Flash 开发意味着放弃诸如 Scout 之类的新应用程序和分析器的使用，但是作为 HTML5 开发人员，您有许多可供选择的替代方案，我们只需要去寻找它们。

### 提示

在 2013 年 Adobe Max 会议期间，讨论了专门为 HTML5 开发而构建的新版本 Adobe Scout 的细节。请在 Adobe 网站上关注这个神奇工具的发布日期。您还可以在会议上观看视频演示[`tv.adobe.com/watch/max-2013/adobe-scout-profiling-taken-to-the-next-level/`](http://tv.adobe.com/watch/max-2013/adobe-scout-profiling-taken-to-the-next-level/)。

我们已经花了一些时间来研究今天许多流行的 Web 浏览器中的 JavaScript 或 Web 开发人员控制台，但这些面板包含许多其他功能，可以帮助您在发布项目之前对其进行测试和基准测试。

### 网络分析

许多网络浏览器中的开发者控制台包含网络控制台，允许您从用户的角度可视化您的网页中的数据是如何加载的。在加载页面之前打开控制台，当页面加载完成时，实时数据将传递到一个易于阅读的表格中，该表格可以显示正在加载的文件，它们是否成功加载，资产的文件大小以及加载所需的时间：

![网络分析](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_20.jpg)

将所有这些数据结合起来可以很容易地帮助您找到在开发阶段可能忽略的网页中的问题。要注意的一件简单的事情是，一旦页面完全加载，要注意页面的总加载大小是多少。考虑到用户连接到互联网的各种方法和速度，当尝试优化项目中使用的资产的文件大小时，始终首先考虑最终用户是明智的。

### 时间轴分析

使用许多常见的内置时间轴分析工具，您可以简单地点击记录按钮，捕获应用程序运行时内部发生的情况。当事件被捕获时，它们会实时显示，并显示总内存使用情况。在尝试定位应用程序中任何潜在内存泄漏可能发生的地方时，这些数据非常有帮助：

![时间轴分析](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_21.jpg)

如果您对这些应用程序分析方法中的一些形式感到陌生，不用担心，我们将在接下来的章节中更多地涵盖这个主题。花时间检查您的网站和应用程序在不同平台上的实际运行情况，可以在发布后避免许多麻烦。

## Stats.js

在 Flash 中处理**每秒帧数**或**FPS**的概念是经常发生的事情。由于整个平台都建立在时间轴的概念上，使您的应用程序以特定的 FPS 或最大 FPS 运行通常是每个 Flash 项目的最终目标。在您的 Flash 开发生涯中，您可能曾经遇到过或甚至使用过 Mr. Doob 的 Hi-ReS Stats 脚本的版本([`github.com/mrdoob/Hi-ReS-Stats`](https://github.com/mrdoob/Hi-ReS-Stats))。这段很棒的小代码片段允许您轻松地在应用程序上附加一个覆盖层，显示随时间变化的 FPS 以及您的应用程序当前使用的内存量：

![Stats.js](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_07_22.jpg)

正如您在来自伟大的 Flash 资源网站 WonderFl([`wonderfl.net/c/6fCf`](http://wonderfl.net/c/6fCf))上找到的原型示例中所看到的，统计脚本被用来显示魔方应用程序的运行情况。当尝试找到可能导致问题的项目执行位置时，这非常方便。

尽管 HTML5 开发中的 FPS 概念并不完全相同，因为静态 HTML 页面在加载期间或加载后没有活动 FPS。但是，在 JavaScript 中处理动画和定时器间隔时，FPS 概念可以像在 Flash 开发中一样使用。由于 Mr. Doob 的工作，曾经只存在于 Flash 项目中的`Stats`脚本现在也可以在您的 HTML5 项目中使用了。

访问[`github.com/mrdoob/stats.js/`](https://github.com/mrdoob/stats.js/)下载项目的最新版本。在 JavaScript 中实现`Stats`显示比在 ActionScript 3 中更复杂，但仍然相对简单。看一下项目文档中`Stats`显示的示例实现：

```html
var stats = new Stats();
stats.setMode(1); // 0: fps, 1: ms

// Align top-left
stats.domElement.style.position = 'absolute';
stats.domElement.style.left = '0px';
stats.domElement.style.top = '0px';

document.body.appendChild(stats.domElement);

setInterval( function () {
    stats.begin();

    // your code goes here

    stats.end();
}, 1000 / 60 );
```

这里的主要区别在于你需要自己创建`Stats`窗口将绘制其计算的时间间隔。正如前面提到的，JavaScript 并不是基于基于帧的开发范式，应用自己的方法来设置应用程序间隔是计算诸如每秒帧数之类的数据的唯一方法。这很容易通过 JavaScript 中内置的`setInterval()`方法来实现，并手动设置预期的帧速率。由于帧将被有效地模拟渲染，我们可以进行一些简单的数学运算，使事情符合我们已经习惯的方式。在前面的例子中，我们将间隔持续时间设置为*1000/60*，其中*60*是预期的每秒帧数值。这个计算等于*16.66666666666667*，这是在一秒钟内对 60 个间隔求和的毫秒值。因此，在创建`Stats`对象并使用`setMode()`方法设置显示模式之后，你还需要手动设置显示位置。

在接下来的章节中，我们将继续深入研究一些这些应用程序，以及概述更多可以帮助项目测试和基准测试的平台。正如我在前面的几章中提到的，仔细检查你的完成项目以测试执行时间、内存使用和浏览器性能的重要性非常重要，以确保你可以相信每个人都可以按照你设计的方式查看你的内容。网页开发缺乏 Flash 编译器在运行之前自动优化我们的应用程序的好处。这项工作取决于你，确保你的程序运行顺畅。

# 总结

我可能无法再次强调一件事情有多重要，那就是你要去探索尽可能多的不同应用程序和其他服务。你对作为网页开发者可用的内容有越好的理解，你就能更好地判断手头工作的正确工具是什么。尽管在许多方面类似，但 HTML5 开发更多地是一种开放式的开发方式。无需使用特定的应用程序集，你可以自由地做任何你想做的事情。本章仅仅是对一些当今开发者正在使用的流行应用程序的浅显介绍。然而，我希望通过对所解释的软件的概述，你可以开始用最适合工作的工具开发自己的 HTML5 应用程序。

在下一章中，我们将看看一些将 JavaScript 推向更远的流行选项，不仅将 JavaScript 编译为其他编程语言，还将其他编程语言编译为 JavaScript。


# 第八章：导出到 HTML5

在第五章中，*一次编码，到处发布*，我们花了一些时间学习了 CreateJS JavaScript 框架以及 Flash Professional CS6 的 CreateJS Toolkit 插件（[`www.adobe.com/ca/products/flash/flash-to-html5.html`](http://www.adobe.com/ca/products/flash/flash-to-html5.html)），以及它们如何可以轻松地将您对 Flash 开发的现有知识直接整合到 HTML5 项目中。在过去的一年里，Adobe 已经采用了这个框架作为在 HTML5 项目中处理基于 Flash 的资产的官方方式。也就是说，实际上有许多其他方法可以在尝试直接将基于 Flash 的应用程序和游戏移植到纯 HTML5 时实现类似的效果。在本章中，我们将继续探讨一些可能帮助您进行资产和代码开发流程的第三方工具和应用程序。

在本章中，我们将涵盖以下内容：

+   使用 Google 的 Swiffy 从 Flash SWF 自动生成 HTML5 项目

+   手动将动画资产转换为 HTML5 准备的精灵表

+   使用 Jangaroo 在 ActionScript 3 中编写您的 JavaScript 库和框架

+   使用 Haxe 在单一语言源中定位您所有的平台开发需求

+   使用 Google 的 Dart 编程语言构建强大的 Web 应用程序

# Google Swiffy

由 Google 创建的 Swiffy 项目（[`www.google.com/doubleclick/studio/swiffy`](https://www.google.com/doubleclick/studio/swiffy)）是将您现有的 Flash 应用程序移植到 HTML5 项目中的最简单的方法之一。该项目的目标是接收已经编译的 Flash SWF 文件，并将其中的数据转换为带有 SVG 矢量动画数据的 JSON 对象。然后，生成的 Swiffy 编译的 JavaScript 可以在现代 Web 浏览器中直接运行，借助 Google Swiffy Runtime 的帮助。

尽管该项目仍处于 Beta 阶段，并且有许多限制，但 Swiffy 支持用 ActionScript 2 和 ActionScript 3 编写的 Flash 项目，使您有可能避免手动将 AS2 转换为 AS3 项目。对于项目中更复杂的 Flash 资产的支持正在稳步增长，但是在使用之前，最好花时间查看项目网站上的当前浏览器和功能支持列表，因为它可能无法完全覆盖您打算转换的应用程序（[`www.google.com/doubleclick/studio/swiffy/gettingstarted.html`](https://www.google.com/doubleclick/studio/swiffy/gettingstarted.html)）。Swiffy 中的 ActionScript 3 支持仅限于在特定类中使用特定方法，以确保转换可以正确进行。在撰写本书时，Swiffy 中的 ActionScript 3 支持包括以下限制：

+   不支持异常处理

+   不支持可选参数

+   不支持 XML 处理

+   对象初始化和构造的顺序不是恒定的

您可以在项目网站的 Swiffy ActionScript 3 支持页面上找到当前 ActionScript 3 支持的完整和最新文档（https://www.google.com/doubleclick/studio/swiffy/actionscript3.html）。如果您转到 ActionScript 支持页面，您可以更好地了解哪些类和方法可以在您的 Flash 应用程序中使用。如果您的应用程序超出了项目支持页面中列出的支持属性，那么您的应用程序很可能无法正确转换。

## Swiffy 是如何工作的？

为了了解 Swiffy 的工作原理，并亲自看到输出和限制，让我们创建一个简单的 Flash 应用程序，将其转换为 HTML5 并查看结果。我们将从可能是 Swiffy 转换的最佳案例开始。我们的 Flash 项目将包含完全在 Flash Professional IDE 内创建的资产和动画，并暂时避免使用任何 ActionScript。为了使这个示例更接近真实世界的情况，我们可以假装这个 Flash 应用程序是一个现有的横幅广告或其他简单的 Flash 电影，我们希望在移动设备或其他没有访问 Adobe Flash Player 的设备上显示。

![Swiffy 是如何工作的？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_08_01.jpg)

尽管前面的例子很丑陋，但它实际上代表了一些重要的测试因素。首先，我们有一个在舞台上运动的圆。其次，我们有一个填充有渐变背景颜色的矩形，同样是矢量格式。最后，我们有两行文本：一行是对**Times New Roman**字体的简单使用，另一行是对更复杂字体如**Wingdings**的测试。就像两个形状一样，文本在播放时将在舞台上进行动画。这个测试的想法是看看 Swiffy 如何处理只有时间轴修改元素的极为常见的 SWF 设置。为了使这个测试不那么复杂，我们还将省略任何 ActionScript，并假设时间轴将无限循环。

创建了时间轴后，我们可以将这部电影的 SWF 输出到我们的项目目录中。Swiffy 生成 Web 准备好的输出所需的唯一 SWF 来自于你的 Flash 项目创建的单个 SWF，所以打开一个 Web 浏览器，前往 Swiffy 项目网站（[`www.google.com/doubleclick/studio/swiffy`](https://www.google.com/doubleclick/studio/swiffy)）。

### 提示

在撰写本书时，Swiffy 允许你上传任何大小等于或小于 1MB 的 SWF 文件。

当你准备好转换你的 SWF 时，使用项目网站首页上的表单将你的 SWF 上传到 Swiffy 服务器。结果应该很快就会出现，就像下面的截图所示：

![Swiffy 是如何工作的？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_08_02.jpg)

结果应该显示类似于前面的截图。转换后的 SWF 的预览将显示在 Web 准备好的显示中，以及所有的输出消息和下载输出的链接。每个 SWF 转换页面上提供的 QR 码将允许您轻松地在移动设备上测试生成的源代码，以验证它是否正常工作。如输出页面所示，您可以通过右键单击外部输出示例的链接（在本例中为`Banner-Test.html`）轻松下载 HTML 文档以及所有其他数据，并以这种方式保存引用页面。

## 检查 Swiffy 生成的代码

将内容保存到本地计算机后，让我们花点时间来审查究竟做了什么，以及我们如何将这个资产移植到现有的网站中。打开 HTML 文件后，首先要注意的是使用外部库：

```html
<script src="img/runtime.js"></script>
```

这个 JavaScript 调用是从 Google 文件服务器导入 Google Swiffy 运行时，并且需要正确显示其后的数据。就像 CreateJS 一样，已创建的代码是 JavaScript 和需要最终解释器才能正常运行的混合体。这是关于 Swiffy 的一个非常重要的事情。包括`runtime.js`文件是项目的绝对要求，只要添加了从 Swiffy 生成的任何资产。

在 Swiffy 运行时包含之后，你会注意到更多 HTML `<script>`标签中包含了大量文本。以下是它的一部分：

```html
swiffyobject = {"tags":[{"frames":[],"scenes":[{"name":"Scene 1","offset":0}],"type":23},{"bounds":[{"ymin":0,"ymax":2240,"xmin":0,"xmax":10399}],"id":1,"fillstyles":[{"transform":["4738D::1056F199e20k"],"type":2,"gradient":{"stops":[{"color":[-65536],"offset":[0]},{"color":[-256],"offset":[42]},{"color":[-16711936],"offset":[93]},{"color":[-16711681],"offset":[127]}….
```

这些数据是 JavaScript 对象，代表了原始 SWF 中包含的所有资产和动画的数据。由于我们的例子中没有包含任何位图图像，而且其中的一切都是基于矢量的，整个应用程序已经被编译为 100%的代码，并且可以用几行进一步的 JavaScript 来显示：

```html
var swiffyElement = document.getElementById('swiffycontainer');
var stage = new swiffy.Stage(swiffyElement), swiffyobject);
stage.start();
```

## 发现 Swiffy 的限制

所有这些都很好，直到我们开始让事情变得更加复杂。在下一个例子中，我创建了一个非常简单的 ActionScript 3 游戏。游戏的想法是通过移动鼠标来控制舞台上方框的位置。随着时间的推移，你的方框会开始增长并占据舞台上更多的空间。游戏的目标是尽可能长时间地让你的方框不要碰到任意移动的黑点。为简单起见，我在这个游戏中没有包含任何用户界面。所有的结果和输出都将暂时发送到 Web 浏览器的开发者控制台。你可以在可下载的章节示例文件中找到这个例子的工作形式。

![发现 Swiffy 的限制](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_08_03.jpg)

是的，这非常粗糙，但它涵盖了 Flash 应用程序中许多常见的方面，并且用可管理的代码行数，非常适合我们的演示目的。如前所述，游戏中没有用户界面，任何游戏输出都将被发送到 Flash 输出调试窗口。在继续之前，让我们先看一下代码，这样你就可以注意到已经使用的特定功能、类和变量类型。

```html
package {

  import flash.display.MovieClip;
  import flash.events.Event;
  import flash.events.MouseEvent;

  // Setting the frame rate is important here as we calculate
  // the users score from how many frames have passed.
  // It's worth noting that the TimerEvent class can be used
  // without any issue by applications converted with
  // Google Swiffy.
  [SWF(backgroundColor="0xEFEFEF", width="1024", height="768", frameRate="30")]

  public class PlayerMoveTest extends MovieClip {
    // Setting a static const variable, defines
    // how many bad guy dots to add to the stage.
    private static const BAD_GUY_COUNT:int = 10;

    // The 'Player' class is a red box created and defined
    // within an SWC included into this project.
    private var _player:Player;

    // An array to hold all of the bad guys created
    // when the game is created.
    private var _badGuys:Array;

    private var _lifeTimer:int;
    private var _playerTarget:Object = new Object();

    /**
     * PlayerMoveTest Constructor
     */
    public function PlayerMoveTest() {
      // Start by creating and adding all of the bad
      // guys to the game stage.
      _badGuys = new Array();
      for(var i:int = 0; i < BAD_GUY_COUNT; i++) {
        // Using MovieClips instead of Sprites
        // as Sprites are not supported by the
        // Google Swiffy compiler.
        var badGuy:MovieClip = new MovieClip();
        badGuy.graphics.beginFill(0x000000, 1);
        badGuy.graphics.drawRect(-5, -5, 10, 10);
        badGuy.graphics.endFill();
        badGuy.x = Math.floor(Math.random() * (1000 + 1));
        badGuy.y = Math.floor(Math.random() * (700 + 1));
        _badGuys.push(badGuy);
        addChild(badGuy);
      }

// Create the users Player object
// Again, this is created within a included SWC.
      _player = new Player();
      _player.x = 100;
      _player.y = 100;
      _playerTarget.x = _player.x;
      _playerTarget.y = _player.y;
      addChild(_player);

      // Add a on enter frame to update the game stage.
      this.addEventListener(Event.ENTER_FRAME, updateEnviroment, false, 0, true);
    }

/**
 * Called on every frame when the game is in a playable
 * state.
 */ 
    private function updateEnviroment(event:Event):void {
      // Update the life timer, used for player score.
      _lifeTimer++;

      // Set the new player position target.
      // this position is based of the current X and Y
      // position of the user's mouse.
      _playerTarget.x = this.mouseX - 50;
      _playerTarget.y = this.mouseY - 50;

// Calculate the distance to the current 
// player target.
      var xDistance:int = _playerTarget.x - _player.x;
      var yDistance:int = _playerTarget.y - _player.y;

      // Update the position of the player object. Use
      // a simple method to ease the position into the 
      // target.
      _player.x = _playerTarget.x - (xDistance * 0.9);
      _player.y = _playerTarget.y - (yDistance * 0.9);
      _player.width += 0.5;
      _player.height += 0.5;

// Randomly move the position of each bad guy on
// every frame.
      for(var i:int = 0; i < BAD_GUY_COUNT; i++) {
        _badGuys[i].x += Math.round(Math.random() * (15 - (-15)) + (-15));
        _badGuys[i].y += Math.round(Math.random() * (15 - (-15)) + (-15));

// Using the common hitTestObject method 
// to check and see if any of these bad guys 
// are currently touching the player object. 
        if(_player.hitTestObject(_badGuys[i])) {
          // The player is touching a bad guy
          // so stop the on enter frame event
          // and alert the users score.
          this.removeEventListener(Event.ENTER_FRAME, updateEnviroment);

          trace('GAME OVER!!!');
          trace('You lasted ' + Math.round(_lifeTimer / 30) + ' seconds.');
        }
      }
    }
  }
}
```

如果你有兴趣实际编译这个应用程序的源代码，你可以找到所有的文件，在 Flash Builder 中打开它作为一个 ActionScript 项目。将应用程序编译为 SWF 并在本地测试应用程序以确认它是否正常工作。如果一切顺利，让我们尝试将这个文件发送给 Swiffy，看看会发生什么：

![发现 Swiffy 的限制](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_08_04.jpg)

只要你正确地按照步骤操作，当尝试转换这个 SWF 并生成前一个截图中的错误列表时，Swiffy 会失败。让我们快速看一下出了什么问题，限制以及可以采取的解决方法。首先，第一个错误列出了数组不受 Swiffy 编译器支持的通知。在我们的应用程序中，我们使用数组来包含所有坏人实例在一个全局变量中。在这个或任何应用程序中，如果不使用数组来管理数据，就需要以更原始的方式来管理数据。这个问题本身可以成为决定是否使用 Swiffy 进行转换的关键因素。尽管有许多方法可以解决这个问题，事实是，如果你的应用程序中到处都是数组，那么当前版本的 Swiffy 很可能无法帮助你。不管有多少坏消息，让我们继续看第二个问题。毫不奇怪，常见的 ActionScript 3 开发中的`hitTestObject`方法也不被编译器支持。

这种易于使用的方法在 Flash 开发中需要简单的碰撞检测时可以成为救命稻草，但由于没有直接的 JavaScript 等效方法来转换它。再次弥补这一点是可以的，但结果代码会比在典型的 ActionScript 3 开发中调用单个方法要大得多。因此，这可能被视为一个问题，但并不是一个死胡同，只要你的碰撞检测只使用支持的方法和属性。我们转换尝试中列出的最终错误是使用`Sprite.graphics`类。如果你还记得，代码示例明确使用了 MovieClips 而不是 Sprites，因为 Sprites 不受 Swiffy 编译器支持。然而，与最初在 Flash Professional IDE 中创建并保存到 SWC 中的`Player`对象不同，坏人对象是在代码中使用内部 ActionScript 3 Graphics API 创建的。

```html
badGuy.graphics.beginFill(0x000000, 1);
badGuy.graphics.drawRect(-5, -5, 10, 10);
badGuy.graphics.endFill();
```

这三行是最终错误的原因。由于 Flash 中的`MovieClip`对象是建立在`Sprite`类之上的，所以结果错误也是如此。由于 SWC 处理了`Player`对象的创建，因此该对象不会出现错误。然而，值得注意的是，即使通过移除所有坏人并只让一个方块在周围移动来修复这些错误，成功转换的结果在游戏的 HTML 版本中仍然没有显示任何内容。目前看来，Swiffy 不支持在 ActionScript 3 项目中使用 SWC，它更倾向于使用旧式的纯 Flash IDE 开发风格的应用程序开发。

尽管 Swiffy 缺乏多年来在 Flash 开发中常用的许多功能，但它仍然可以成为集成网站动画或广告横幅等资产的非常方便的工具。实际上，Swiffy 可靠地为你做的大部分工作是简单的 Flash 应用程序和电影转换，而不是你典型的 Flash 游戏或应用程序。

# 在 Flash Professional CS6 中生成精灵表

如果你打算将一些现有的基于 Flash 的时间轴动画移植或复制到 HTML5 项目中，你将不得不进行一些自己的转换。正如你在本书的示例中所看到的，时间轴动画在 HTML5 堆栈中根本不存在。因此，你需要将动画序列转换为一种新的格式，以便在 Web 上正确显示。最简单的选项之一是将动画转换为视频文件，并使用`<video>`标签元素进行播放。不幸的是，将位图或矢量资产转换为可以在 Web 上正确播放的视频文件将导致大量的质量损失。更糟糕的是，视频播放将非常沉重，导致应用加载时间变慢。最后，HTML5 中的视频缺少许多重要功能，比如不支持 alpha 透明度，导致所有资产都包含在一个完全可见的矩形容器中。为了解决所有这些问题，许多网页开发人员正在转向经过验证的精灵表方法。精灵表背后的概念非常简单。将动画序列中的所有帧放在同一张图像上（带有透明背景），并将图像保存为未压缩的 PNG 文件。这样，当客户端在 Web 上加载时，只需下载一个文件就可以将整个动画序列加载到内存中准备播放。将基于 Flash 的时间轴动画手动转换为精灵表，通过将每一帧复制并粘贴到 PNG 文档中，是一项漫长而繁琐的工作。幸运的是，这是一项你不需要处理的工作，因为 Flash Professional CS6 在 IDE 中已经集成了精灵表生成器。

在 Flash CS6 中使用精灵表生成器非常简单。Adobe 的工程师们成功地创建了一个工具，可以让您在几分钟内轻松地在 HTML5 项目中使用 Flash 动画。虽然使用简单，但该功能可能有点隐藏，因此让我们快速看一下精灵表生成器的操作，并将一些结果放入工作中的 HTML5 文档进行测试。

举例来说，我创建了一个非常简单的 Flash 动画示例，时间轴上只包括三种不同的形状。每种形状仅显示 5 帧，总共有 15 帧动画：

### 提示

和往常一样，您可以在可下载的章节示例中找到所有示例文件。

![在 Flash Professional CS6 中生成精灵表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_08_05.jpg)

在 Flash 项目的库中找到 MovieClip，右键单击它。在右键单击任何 MovieClip 时显示的上下文菜单中，您将找到**生成精灵表**选项。选择此选项，将会出现新的、功能丰富的**生成精灵表**窗口：

![在 Flash Professional CS6 中生成精灵表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_08_06.jpg)

初步检查时，您会看到动画中的每一帧都自动添加到同一文档中，并以网格格式排列。如前所述，该动画包含 15 帧，因此每帧都已添加到精灵表**预览**窗口中，并显示默认配置。在保存此输出之前，让我们查看一些可用的选项，看看是否可以进一步优化这个精灵表。

我们可以从对即将导出的内容进行概述开始。在**生成精灵表**窗口的左下角，您将找到当前 MovieClip 的详细信息，包括基于特定帧速率的帧数和持续时间。在窗口的右侧，您可以看到一个易于查看的预览，显示了在当前配置下生成的精灵表的外观。选择第二个**预览**选项卡将显示以其原生形式运行的动画。

在预览窗口下方是在导出动画资产和数据集时可用的所有配置属性。导出图像的尺寸可以由 Flash 自动调整，也可以手动配置以设置动画帧的可用区域。图像格式也可以配置为 PNG 或 JPG 格式，以便对导出图像进行进一步压缩。建议将其设置为 PNG 格式，无背景，除非需要允许正确的图像背景透明度：

![在 Flash Professional CS6 中生成精灵表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_08_07.jpg)

配置属性的正确大小包含了数据集导出的设置。由于为精灵表导出的图像将只包含帧资产而没有动画数据，因此精灵表将需要某种形式的数据才能正确播放。当使用可用的切片算法中的基本算法时，通常不会出现问题。使用基本设置时，精灵以漂亮的统一行排列在易于使用的网格布局中。这是处理任何简单动画时的最佳输出设置。目前算法的另一个选项是**MaxRects**选项。此选项用于尝试尽可能紧密地打包帧。这样做的原因是为了最小化导出图像文件大小，以便在互联网连接上实现更快的下载时间。选择算法后，我们可以继续进行此导出窗口中可能最重要的设置。**数据格式**选择允许您将数据导出格式设置为特定于您正在开发的 HTML5 应用程序的工作方式。已包括对 iOS 开发的**The Sparrow Framework**（[`gamua.com/sparrow`](http://gamua.com/sparrow)）、用于 ActionScript 3 的**The Starling Framework**（[`gamua.com/starling/`](http://gamua.com/starling/)）以及**Cocos2D**（[`cocos2d.org/`](http://cocos2d.org/)）的支持。作为 HTML5 开发人员，您可能最感兴趣的三个主要导出设置是**JSON**、**JSON-Array**和**easeljs**选项。将数据集导出为简单的 JSON 导出将允许您将数据通用地用作 JSON，这是人类可读的数据存储的开放标准。**JSON-Array**设置非常相似，不同之处在于将数据存储在 JSON 数组中而不是直接对象中。这两者之间的区别实际上只会影响您在代码中如何解释数据。最后，**easlejs**导出设置允许您自动准备导出的动画以包含在您的 CreateJS 或 EaselJS 项目中。当您尝试将外部资产包含到现有的基于 CreateJS 工具包的项目中时，这种导出设置非常方便：

![在 Flash Professional CS6 中生成精灵表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_08_08.jpg)

配置中的最终设置是**修剪**和**堆叠帧**选项。修剪精灵表中的帧将删除每个元素之间的未使用空白空间。这将通过最小化导出图像文件大小再次优化您的最终结果。最后，**堆叠帧**选项允许您通过删除或堆叠动画中相同的帧来进一步优化您的动画。

由于导出的数据集将包含时间轴信息，因此无需存储相同的图像两次，因此可以毫无问题地删除这些资产：

![在 Flash Professional CS6 中生成精灵表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_08_09.jpg)

所有这些设置都已覆盖，让我们使用前面截图中的设置导出这个动画，看看我们得到了什么输出。当单击**导出**按钮时，窗口完成后将关闭，您将能够在项目目录的根目录中找到导出的材料。在**数据格式**选项中附加**JSON**设置后，将导出两个文件。第一个文件是 PNG 格式的精灵表图像：

![在 Flash Professional CS6 中生成精灵表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_08_10.jpg)

第二个文件是我们的 JSON 输出，其中包含动画的前三帧的所有帧位置和大小的数据。以下是导出的 JSON 中包含的动画数据的片段：

```html
{"frames": {

"ShapeAnimation0000":
{
  "frame": {"x":0,"y":0,"w":100,"h":100},
  "rotated": false,
  "trimmed": false,
  "spriteSourceSize": {"x":0,"y":0,"w":100,"h":100},
  "sourceSize": {"w":100,"h":100}
},
"ShapeAnimation0001":
{
  "frame": {"x":0,"y":0,"w":100,"h":100},
  "rotated": false,
  "trimmed": false,
  "spriteSourceSize": {"x":0,"y":0,"w":100,"h":100},
  "sourceSize": {"w":100,"h":100}
},
"ShapeAnimation0002":
{
  "frame": {"x":0,"y":0,"w":100,"h":100},
  "rotated": false,
  "trimmed": false,
  "spriteSourceSize": {"x":0,"y":0,"w":100,"h":100},
  "sourceSize": {"w":100,"h":100}
},
"ShapeAnimation0003":
{
  "frame": {"x":0,"y":0,"w":100,"h":100},
  "rotated": false,
  "trimmed": false,
  "spriteSourceSize": {"x":0,"y":0,"w":100,"h":100},
  "sourceSize": {"w":100,"h":100}
},
```

数据非常简单易懂，这很好，因为从这一点开始，如果没有使用游戏开发框架或 CreateJS，我们必须自己解释和显示这些数据和资产：

```html
<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <title>ShapeAnimation Sprite Sheet Example</title>

    <style>
      #animation {
        width:100px;
        height:100px;
        overflow:hidden;
      }
      </style>

      <script type="text/javascript" src="img/jquery-1.9.1.min.js"></script>
    <script>
      var animationData = Array();
      var currentFrame = 0;

      $(document).ready(function() {
        // Get the Sprite Sheet JSON
        $.getJSON('ShapeAnimation.json', function(data) {
          // Save each of the objects into an array.
          $.each(data['frames'], function(key, val) {
            animationData.push(val);
          });

          // Start the animation.
          runAnimation();
        });
      });

      function runAnimation() {
        // Update the CSS properties of the Sprite Sheet image.
        $('#animation img').css('margin-left', animationData[currentFrame]['frame']['x'] * -1);
        $('#animation img').css('margin-top', animationData[currentFrame]['frame']['y'] * -1);

        // Update the frame counter and reset if needed.
        currentFrame++;
        if(currentFrame == animationData.length) currentFrame = 0;

        // Keep calling this method every 200ms.
        setTimeout(runAnimation, 200);
      }
    </script>
  </head>

  <body>
    <div id="animation">
      <img src="img/ShapeAnimation.png">
    </div>
  </body>
</html>
```

由于 Flash Professional CS6 对 CreateJS 的巨大支持，使用 EaselJS 设置来导出和使用精灵表绝对是最简单的方法。然而，正如前面的代码片段所示，通过标准化的 JSON 导出方法，你可以相对容易地将任何 Flash 动画实现为精灵表，用于你的 HTML5 项目。

### 提示

如果你对精灵表感兴趣，但又不想花时间创建所有的资源，可以前往 Google 图片搜索精灵表。你会发现无穷无尽的精灵表资源，可以用来测试你的应用程序。当然，在公共网站上使用任何资产时，你应该确保拥有权限或所有权。

# Jangaroo

Jangaroo（[`www.jangaroo.net`](http://www.jangaroo.net)）的开发背后实际上非常有趣。Jangaroo 是由 CoreMedia（[`www.coremedia.com`](http://www.coremedia.com)）的开发团队创建的，它是由内部开发团队对当前 JavaScript 开发能力的挫折而构建的。CoreMedia 的开发团队并没有处理 JavaScript 所具有的许多常见语法问题，而是着手创建了一个用 Java 编写的 ActionScript 3 到 JavaScript 编译器。尽管这听起来可能很荒谬，但实际情况是，Flash 开发人员可以轻松地继续使用熟悉的语法，同时专门针对基于 HTML5 的 Web 开发。Jangaroo 旨在允许开发人员使用 ActionScript 3 的强大功能编写高质量的 JavaScript 框架和应用程序。简而言之，它将接收 ActionScript 3 文件，并借助其用 Java 编写的编译器将它们转换为可用的 JavaScript：

![Jangaroo](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_08_11.jpg)

那么，为什么有人想要避免编写原生 JavaScript，开始为下一个 HTML5 项目编写 ActionScript 3 呢？嗯，作为一个有过编写 ActionScript 3 经验的开发者，你可能已经可以从本书中到目前为止的所有示例和概述中回答这个问题。在编写大型强大的 HTML5 应用程序时，JavaScript 中缺少包、类和适当的继承可能会开始创建一堆代码的雷区，这些代码可能很难管理。通过允许自己继续使用一种你不仅习惯了的语言来开发应用程序，而且可以更容易地管理项目中的类，你可以克服许多在纯 JavaScript 开发周期中可能出现的常见障碍。

Jangaroo 项目的核心是名为`jooc`的 Jangaroo ActionScript 3 到 JavaScript 编译器。编译器将接收你的 ActionScript `.as`文件，并将它们导出为编译后的 JavaScript `.js`文件。要安装和运行 Jangaroo，你需要首先确保已安装最新版本的 Java 运行环境（[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)）以及 Maven（[`maven.apache.org`](http://maven.apache.org)）。安装和设置这两个软件可能看起来令人生畏，但请放心，这个过程非常简单直接，并且有很好的文档记录，所以我会把这个过程留给你自己。

### 提示

在安装 Java 运行环境时，值得注意的一点是要确保`JAVA_HOME`环境变量已正确设置。如果在安装或测试 Jangaroo 过程中遇到任何问题，这将是一个很好的调试起点。

为了给你一个用 ActionScript 3 创建并使用 Jangaroo 编译的 JavaScript 驱动应用程序的简化开发周期的例子，让我们使用可以在项目网站上找到的 HelloWorld 示例（[`www.jangaroo.net/tutorial`](http://www.jangaroo.net/tutorial)）。

```html
package {
/**
 * The most simple Jangaroo class on earth.*/
public class HelloWorld {
  /**
   * Let the browser display a welcome message.*/
  public static function main():void {window.document.body.innerHTML = "<strong>Hello World from Jangaroo!</strong>";
  }
}
}
```

正如您在代码示例中所看到的，您的 ActionScript 类可用的语法是常见的 ActionScript 3 和一些特殊的窗口和文档对象引用的混合，以便您可以正确地将应用程序集成到浏览器中。如果您对准备将 ActionScript 3 编译为 Jangaroo 编译器感兴趣，可以前往官方 Jangaroo 文档的**编写代码**页面了解有关语言和代码语法选项的更多信息（[`www.jangaroo.net/tutorial/writing_code`](http://www.jangaroo.net/tutorial/writing_code)）。

Jangaroo 的大部分是开源的，项目代码和资产可以在 CoreMedia 的 Github 页面上找到（[`github.com/CoreMedia`](https://github.com/CoreMedia)）。

# Haxe

继续讨论将应用程序和其他编程语言直接编译为 JavaScript 的话题，我应该花点时间介绍一下 Haxe 开发世界中一些令人兴奋的功能：

![Haxe](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_08_12.jpg)

**Haxe**（[`haxe.org`](http://haxe.org)）是一种独立的开源编程语言。大多数编程语言都是为特定的应用类型而构建的，JavaScript 用于 Web，ActionScript 用于 Flash，而 Haxe 可以从相同的源代码编译和运行在各种平台和设备上。Haxe 源代码可以有选择地编译成 JavaScript、Flash、PHP、C++、C#和 Java，结合您之前对 ActionScript 3 的经验和您在 JavaScript 中学到的新技能，学习 Haxe 语法是轻而易举的。

尽管跨平台开发现在可能不是您的兴趣所在，但至少对诸如 Haxe 等语言提供的基本了解可能会让您填补开发技能中的一些空白。在我们继续之前，让我们快速看一下 Haxe 项目网站的**代码片段**页面上可以找到的 Haxe 代码示例。以下代码是实现流行排序方法 Quicksort 的示例（[`en.wikipedia.org/wiki/Quicksort`](http://en.wikipedia.org/wiki/Quicksort)）。由于我们已经了解了这个排序算法试图实现的目标，让我们主要审查这段代码，以了解 Haxe 编程语言中的类、方法和变量语法：

```html
class Quicksort {

    static var arr = [4,8,0,3,9,1,5,2,6,7];

    static function quicksort( lo : Int, hi : Int ) : Void {
        var i = lo;
        var j = hi;
        var buf = arr;
        var p = buf[(lo+hi)>>1];
        while( i <= j ) {
            while( arr[i] > p ) i++;
            while( arr[j] < p ) j--;
            if( i <= j ) {
                var t = buf[i];
                buf[i++] = buf[j];
                buf[j--] = t;
            }
        }
        if( lo < j ) quicksort( lo, j );
        if( i < hi ) quicksort( i, hi );
    }

    static function main() {
        quicksort( 0, arr.length-1 );
        trace(arr);
    }
}
```

正如您可以直接在第一行看到的那样，Haxe 具有完整的类支持，不像 JavaScript。这个概念本身可能是一个卖点，因为从 ActionScript 转到 Haxe 的开发人员会发现许多在 JavaScript 中不可用的相似之处。其他功能，如静态函数、严格的变量类型和常见的调试方法，比如`trace()`，只是 Haxe 中让具有先前 ActionScript 3 开发经验的开发人员脱颖而出的众多出色功能之一。

### 提示

如果您对了解 Haxe 开发的激动人心世界感兴趣，请查看《Haxe 2 初学者指南》，*Packt Publishing*（[`www.packtpub.com/haxe-2-beginners-guide/book`](http://www.packtpub.com/haxe-2-beginners-guide/book)）。

Haxe 本身是一个庞大的项目。直接将应用程序源代码交叉编译到几乎所有现代平台上的能力是一个非常宝贵的资产，尤其是当您开发具有非常特定平台要求的项目时。即使您只打算使用 Haxe 源代码针对 HTML5 Web 项目，只需点击几下鼠标即可将应用程序移植到另一个平台的能力是非常惊人的。此外，就像我们在本章中审查的许多其他平台和编译器一样，Haxe 可以减轻许多 Web 开发人员对 JavaScript 语法的常见抱怨。该项目仍然相对较新，尽管许多开发人员已经加入了这一行列。如果在 Haxe 中开发您的下一个应用程序听起来像一个有趣的挑战，我强烈建议您进一步了解一下。

# Google Dart

为了帮助来自各个平台的开发人员构建现代 Web 的复杂、高性能客户端应用程序，谷歌的 Dart（[`code.google.com/p/dart/`](https://code.google.com/p/dart/)）是推动 Web 开发的又一个很好的例子，更具体地说是 JavaScript 开发。就像 Haxe 一样，Dart 是一个开源项目，使用自己特定的编程语言编译成 Web-ready JavaScript 文档，就像 Jangaroo 一样，Dart 是基于对当前 Web 开发平台限制的不满而构建的。为了引入新的结构化、单一语言工作流程，谷歌发布了 Dart 项目的*技术预览*，以便早期测试和来自 Web 开发社区的反馈：

![Google Dart](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_08_13.jpg)

当然，由于 Dart 是基于自己的语法构建的，刚开始时会有一个学习曲线。为了帮助减轻学习新语言的压力，我强烈建议查看官方的 Dart Editor。Dart Editor（[`www.dartlang.org/docs/editor/`](http://www.dartlang.org/docs/editor/)）可能是最简单的开始和运行 Dart 开发的方法。

它支持实时错误和语法检查功能，以在编译之前提醒您任何问题，同时还支持代码完成功能，以帮助您了解每个方法和属性可以做什么。

![Google Dart](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-fls-dev/img/3325OT_08_14.jpg)

Dart Editor，就像许多其他编辑器一样，是基于流行的 Eclipse IDE 构建的。尽管代码编辑器简化了，但对于有 Flash Builder 经验的人来说，这可以被认为是又一个胜利，因为界面会非常熟悉。我说这个编辑器简化了，因为这个编辑器不是作为 Eclipse 的插件提供的，而是作为自己独立的基于 Eclipse 的编辑器打包，删除了所有不必要的元素。

就像 Haxe 的概述一样，我会保持简短，因为 Dart 仍然是一个非常新的项目，我还没有亲自遇到任何使用它开发流行 Web 应用程序的人。也就是说，绝对没有理由贬低 Dart 这样的语言。随着 JavaScript 规范的发展和浏览器支持的跟进，对这些项目的需求可能会减少。然而，就像任何 Flash 开发人员知道的，使用适当的调试和输出流编译项目可以让他们比许多传统的客户端脚本编写方法更快地找到和修复问题。

# 总结

在本章的过程中，我们花了一些时间研究了一些正在推动网页应用程序开发极限的项目，例如谷歌的 Swiffy 项目，它可以轻松地将简单的 Flash SWF 文件直接转换为 Web 友好的 HTML 和 JavaScript 配置，以及从 Flash Professional IDE 中直接导出 Flash 矢量和位图动画到 Web 准备好的精灵表。诸如 Haxe、Dart 和 Jangaroo 之类的项目为开发人员在尝试创建他们的 HTML5 项目时提供了新的选择。驱动他们应用程序的本机 JavaScript 实际上可以用完全不同的语言编写。最初，将 JavaScript 的能力扩展到其他语言可能看起来有些反向，但创建这些项目的原因通常都归结为在编写 JavaScript 时缺乏通用语法和开发流程问题。正如前面提到的，开发下一个 HTML5 项目时，并不需要使用本章中提到的特定应用程序中的项目或功能。了解当前网页开发人员可以使用的项目和平台的知识将使您能够更好地得出结论，找到最佳的方式来处理下一个 HTML5 项目。

我必须强调，本章提到的应用程序、功能和编译器列表只是在使用 JavaScript 时可用的一小部分。如果您有兴趣了解更多可以编译到 JavaScript 或扩展 JavaScript 的项目，请访问[`altjs.org`](http://altjs.org)。在那里，您将找到针对初学者到高级开发人员风格的项目列表，所以我相信那里一定会有一些能够吸引您的东西。许多这些项目都是基于 CoffeeScript（[`coffeescript.org`](http://coffeescript.org)）开发的，这是另一种直接编译为 JavaScript 的专用语言，也是我推荐您了解的另一个很棒的项目。与扩展 JavaScript 的开发流程和能力相关的项目数量似乎是无穷无尽的，并且每天都在增长。没有人能指望您了解所有这些项目，但是对现有项目以及许多这些平台能做什么有一个基本的了解，将使您在着手开发下一个项目时能够做出更快更好的决策。

在接下来的两章中，我们将开始将我们到目前为止所涵盖的所有内容融入到实际的 HTML5 应用程序开发流程中。我们将涵盖每个开发人员在为 Web 开发时应该注意的许多重要方面，以及在开发过程中正确测试应用程序的方法。最后，为了总结一切，我们将把该应用程序发布到互联网，并介绍一些在应用程序上线后发布和维护项目的方法。
