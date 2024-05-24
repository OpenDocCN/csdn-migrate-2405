# 面向孩子们的 JavaScript 项目（二）

> 原文：[`zh.annas-archive.org/md5/9C2A1F6AA0F3566A2BF5430895525455`](https://zh.annas-archive.org/md5/9C2A1F6AA0F3566A2BF5430895525455)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：探索 jQuery 的好处

如果你已经阅读了上一章，你可能已经在你的**战舰**游戏中实现了**jQuery**。在本章中，我们将详细讨论 jQuery。

jQuery 库是一个 JavaScript 框架。它于 2006 年发布。人们过去称它为**jSelect**。我们在我们的网站中使用 jQuery，这样我们就可以更轻松地使用 JavaScript 并为我们的网页添加效果。你可能会认为 jQuery 与 JavaScript 不同。不！jQuery 只是另一个 JavaScript 文件。它是一个非常轻量级的库，可以帮助你更轻松地装饰你的网页，编写更少的代码。

我们使用 jQuery 是因为以下优势：

+   它是开源的；如果需要，你可以编辑或修改它的代码

+   它是一个小型库（大约 150 KB 文件）

+   jQuery 的社区支持非常强大；你可以轻松地从用户那里获得帮助

+   它用户友好且流行

+   它支持跨浏览器

+   它是公开开发的；你可以通过编辑代码来修复任何错误或添加功能

+   它帮助开发人员通过使用 AJAX 构建响应式网站

+   它具有内置的动画功能，帮助开发人员在他们的网站中创建动画

# 安装 jQuery

问题是在哪里找到 jQuery。嗯，你可以在[`jquery.com/`](http://jquery.com/)找到它。我也在这本书中附上了文件。你可以从那里下载。

如果你去[`jquery.com/`](http://jquery.com/)，你会看到以下屏幕：

![安装 jQuery](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_06_01.jpg)

点击**下载 jQuery**按钮。你将被重定向到以下页面：

![安装 jQuery](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_06_02.jpg)

jQuery 有两个版本：`1.x.x`和`2.x.x`。这些版本之间只有一些差异。压缩版本的代码不可读，因为该版本没有空格和注释；然而，未压缩版本的代码清晰且格式良好，它还有重要的注释来理解代码和函数的工作。如果你想学习 jQuery 的函数如何工作，我建议你阅读 jQuery 未压缩版本。

在本章中，我们将使用`2.x.x`版本。最新版本的`2.x.x`是`2.2.0`。

### 注意

你可以下载压缩或未压缩版本的 jQuery。

我建议你使用压缩版本，因为它很轻量级。

我们将在本章中使用未压缩版本，这样你就可以学习`jquery.js`并清楚地了解它的工作原理。点击**下载未压缩的开发版 jQuery** `2.2.0`后，你将在浏览器上看到 jQuery 库。按下键盘上的*Ctrl* + *S*来保存文件，如下面的截图所示：

![安装 jQuery](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_06_03.jpg)

下载 jQuery 后，将其放在你的电脑上。为了简单起见，将其重命名为`jquery`。

在同一个文件夹中创建一个新的 HTML 文件，并通过在`<head></head>`标签中输入以下代码将`jquery.js`包含在你的 HTML 文档中：

```js
<script src="img/jquery.js"></script>
```

要检查你导入的`jquery.js`是否工作，输入以下代码。我稍后会解释代码：

```js
<html>
  <head>
    <script type="text/JavaScript" src="img/jquery.js"></script>
  </head>
  <script type="text/JavaScript">
    jQuery(document).ready(function()
    {
      jQuery('h1').click(function()
      {
        alert("jQuery is working!");
      } //click function ends here.
      );
    } // ready function ends here.
    );
  </script>
  <body>
    <h1>Click Here!</h1>
  </body>
</html>
```

打开 HTML 文件后，点击**点击这里！** 你会看到以下屏幕：

![安装 jQuery](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_06_04.jpg)

这意味着你的 jQuery 正在工作。

让我们讨论一下我们写的代码。

### 注意

你也可以在不下载的情况下安装 jQuery。这种安装方式称为**内容交付网络**（**CDN**）安装。

你需要将以下行添加到你的 HTML 文档中，如果你在线连接，你的浏览器将自动加载 jQuery。

```js
<script type = "text/javascript" src = "http://ajax.googleapis.com/ajax/libs/jquery/2.1.3/jquery.min.js"></script>
```

# 解释代码

现在，让我们讨论我们之前使用的代码。我们在我们的代码中使用了以下函数：

```js
jQuery(document).ready(function(){
//our codes. 
});
```

这是一个 jQuery 函数，允许你设置你的 jQuery 准备好被使用。你可以用下面的代码将`jQuery`替换为美元符号（`$`）：

```js
$(document).ready(function(){
//our codes.
});
```

您需要考虑在哪里应用 jQuery。我们在 body 标签中写了`<h1>点击这里！</h1>`。我们希望我们的`点击这里！`在被点击时做一些事情，这就是为什么我们添加了一个类似于以下格式的`click`函数：

```js
  jQuery('h1').click(function(){
    //our codes.
  });
```

`jQuery`可以被替换为`$`，如前所述。

我们添加了一个`alert`函数，这样当我们点击文本时，就会出现一个警报框。

# 深入了解

让我们详细讨论我们经常使用的 jQuery 函数/方法。

所有方法都应该写在`ready()`函数中。一些常用的方法如下：

+   加载

+   keyup

+   按键

+   更改

+   焦点

+   模糊

+   调整大小

+   滚动

## load()方法

使用这种方法，您可以在浏览器上加载文件。考虑您想要从浏览器上的`.txt`文件中获取一些文本。您可以进行以下编码：

```js
<html>
  <head>
    <script type="text/JavaScript" src="img/jquery.js"></script>
  </head>
  <script>
    $(document).ready(function(){
      $("button").click(function(){
        $("#click").load("test.txt");
      });
    });
  </script>
  <body>
    <div id="click">
      Hello;
    </div>
    <button type="button" name="button">Click to replace "Hello" from text file</button>
  </body>
</html>
```

单击按钮后，`click` div 中的文本将更改为**恭喜！您已经加载了您的文件！！**，如下所示：

！load()方法

## keyup()和 keydown()方法

使用这种方法，您可以控制键盘按钮的按键。当按下或未按下键时，您可以让浏览器执行某些操作。假设您有一个文本框，您想从中获取输入。当按下键时，您希望您的文本框变为红色；否则颜色应保持为绿色。您可以通过实现/编写以下代码来实现这一点：

```js
<html>
  <head>
    <script type="text/JavaScript" src="img/jquery.js"></script>
  </head>
  <script>
    $(document).ready(function(){
      $("input").keydown(function(){
        $("input").css("background-color", "green");
      });
      $("input").keyup(function(){
        $("input").css("background-color", "red");
      });
    });
  </script>
  <body>
    Type Something:  <input type="text">
  </body>
</html>
```

！keyup()和 keydown()方法

## change()方法

要更改一些文本，您可以使用以下代码来使用此方法：

```js
<html>
  <head>
    <script type="text/JavaScript" src="img/jquery.js"></script>
  </head>
  <script>
  $(document).ready(function(){
    $("input").change(function(){
      alert("The text has been changed.");
    });
  });
  </script>
  <body>
    Type Something:  <input type="text">
  </body>
</html>
```

您的输出将类似于以下图像：

！change()方法

## 模糊()和聚焦()方法

要使您的文本或按钮模糊或聚焦，您可以实现以下代码：

```js
<html>
  <head>
    <script type="text/JavaScript" src="img/jquery.js"></script>
  </head>
  <script>
  $(document).ready(function(){
    $("button").blur(function(){
      alert("Your button is not focused!");
    });
  });
  </script>
  <body>
    <button type="button">CLick Me!</button>
  </body>
</html>
```

您也可以对`focus()`方法执行此操作，如下所示：

！blur()和 focus()方法

## resize()方法

如果您想查看浏览器调整大小了多少次，您可以在 HTML 文档中执行以下操作：

！resize()方法

## scroll()方法

您可以使用以下代码为鼠标滚动添加动作：

```js
<html>
  <head>
    <script src="img/jquery.js"></script>
    <script>
      $(document).ready(function(){
        $("div").scroll(function(){
          $("span").text("You are scrolling!");
        });
      });
    </script>
  </head>
  <body>
    <div style="border:2px solid black;width:200px; height:200px;overflow:scroll;">
      Cowards die many times before their deaths;<br>
      The valiant never taste of death but once.<br>
      Of all the wonders that I yet have heard,<br>
      It seems to me most strange that men should fear;<br>
      Seeing that death, a necessary end,<br>
      Will come when it will come.<br>
    </div>
    <span></span>
  </body>
</html>
```

当您用鼠标滚动时，您可以看到您在`scroll()`函数中创建的事件，如下所示：

！scroll()方法

# 总结

jQuery 库非常有趣且易于新学习者使用。您所要做的就是练习 jQuery 的方法和函数。有很多 jQuery 插件在线。您也可以下载并将它们安装到您的网页上。使用 jQuery 及其插件，您可以轻松地美化和编写您的网站。对我来说，jQuery 最有趣的部分是动画。我将在下一章中解释如何使用 jQuery 来制作动画。


# 第七章：介绍画布

在本章中，我们将学习 HTML 画布。HTML 画布可以帮助您在 HTML 页面上绘制图形（例如圆圈、正方形、矩形等）。`<canvas></canvas>`标签通常由 JavaScript 控制。画布可以绘制文本，也可以进行动画。让我们看看使用 HTML 画布我们能做些什么。

# 实现画布

要在您的 HTML 页面上添加画布，您需要在`<canvas></canvas>`标签中定义画布的高度和宽度，如下所示：

```js
<html>
  <head>
    <title>Canvas</title>
  </head>
  <body>
  <canvas id="canvasTest" width="200" height="100" style="border:2px solid #000;">

    </canvas>
  </body>
</html>
```

我们已经将画布 ID 定义为`canvasTest`，将用它来操作画布。我们在画布上使用了内联 CSS。使用 2 像素的实线边框可以更好地查看画布。

# 添加 JavaScript

现在，我们将为我们的画布添加几行 JavaScript。我们需要在`<script></script>`标签中的`<canvas></canvas>`标签之后添加我们的 JavaScript。

# 画一个矩形

要测试我们的画布，让我们在画布中画一个矩形，输入以下代码：

```js
<script type="text/javascript">
  var canvas = document.getElementById("canvasTest"); //called our canvas by id
  var canvasElement = canvas.getContext("2d"); // made our canvas 2D
  canvasElement.fillStyle = "black"; //Filled the canvas black
  canvasElement.fillRect(10, 10, 50, 50); //created a rectangle
</script>
```

在脚本中，我们声明了两个 JavaScript 变量。`canvas`变量用于使用我们在`<canvas></canvas>`标签中使用的画布 ID 来保存我们画布的内容。`canvasElement`变量用于保存画布的上下文。我们将`black`赋给`fillstyle`，这样我们要绘制的矩形在填充时变黑。我们使用`canvasElement.fillRect(x, y, w, h);`来确定矩形的形状。其中`x`是矩形距离*x*轴的距离；`y`是矩形距离*y*轴的距离；`w`和`h`分别是矩形的宽度和高度。

完整的代码如下所示：

```js
<html>
  <head>
    <title>Canvas</title>
  </head>
  <body>
    <canvas id="canvasTest" width="200" height="100" style="border:2px solid #000;">
    </canvas>
    <script type="text/javascript">
      var canvas = document.getElementById("canvasTest"); //called our canvas by id
      var canvasElement = canvas.getContext("2d"); // made our canvas 2D
      canvasElement.fillStyle = "black"; //Filled the canvas black
      canvasElement.fillRect(10, 10, 50, 50); //created a rectangle
    </script>
  </body>
</html>
```

代码的输出如下：

![画一个矩形](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_07_01.jpg)

# 画一条线

要在画布中画一条线，您需要在`<script></script>`标签中插入以下代码：

```js
<script type="text/javascript">
  var c = document.getElementById("canvasTest");
  var canvasElement = c.getContext("2d");
  canvasElement.moveTo(0,0);
  canvasElement.lineTo(100,100);
  canvasElement.stroke();
</script>
```

在这里，`canvasElement.moveTo(0,0);`用于使我们的线从画布的(0,0)坐标开始。`canvasElement.lineTo(100,100);`语句用于使线对角线。`canvasElement.stroke();`语句用于使线可见。我建议您更改`canvasElement.lineTo(100,100);`和`canvasElement.moveTo(0,0);`中的数字，并查看画布绘制的线的变化。

以下是代码的输出：

![画一条线](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_07_02.jpg)

# 一个快速的练习

1.  使用画布和 JavaScript 画一条与画布的*y*轴平行的线。

1.  画一个高 300 像素，宽 200 像素的矩形。在同一画布上画一条线，触及矩形。

# 画一个圆

要在画布中画一个圆，您需要在`<script></script>`标签中添加以下代码：

```js
<script type="text/javascript">
  var c = document.getElementById("canvasTest");
  var canvasElement = c.getContext("2d");
  canvasElement.beginPath();
  canvasElement.arc(95,50,40,0,2*Math.PI);
  canvasElement.stroke();
</script>
```

在这里，我们使用了`canvasElement.beginPath();`来开始画圆，`canvasElement.arc(95,50,40,0,2*Math.PI);`来确定圆的形状，`canvasElement.stroke();`来设置圆可见。

### 注意

`canvasElement.arc(95,50,40,0,2*Math.PI);`语句类似于`canvasElement.arc(x, y, r, sA, eA, ac);`,

其中`x`是从*x*轴开始的坐标，`y`是从*y*轴开始的坐标，`r`是圆的半径，`sA`是圆的起始角度，`eA`是圆的结束角度，`ac`是圆的方向。在这里，`ac`表示逆时针。

我们的代码的输出将是以下图像：

![画一个圆](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_07_03.jpg)

# 绘制线性渐变

让我们画点新东西。我们将画一个矩形，并使其颜色逐渐变淡。在您的`<script></script>`标签中输入以下代码：

```js
<script type="text/javascript">
  var c = document.getElementById("canvasTest");
  var canvasElement = c.getContext("2d");
  // Create the gradient
  var grdient = canvasElement.createLinearGradient(0,0,100,0);
  grdient.addColorStop(0,"blue"); // here we added blue as our primary color
  grdient.addColorStop(1,"white"); //here we used white as our secondary color. 
  // Fill with gradient
  canvasElement.fillStyle = grdient;
  canvasElement.fillRect(10,10,150,80);
</script>
```

我们添加了`canvasElement.createLinearGradient(0,0,100,0);`来创建渐变或淡化。我们添加了`grdient.addColorStop(0,"blue");`和`grdient.addColorStop(1,"white");`来给矩形上色。

代码的输出如下图所示：

![绘制线性渐变](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_07_04.jpg)

# 一个快速的练习

1.  使用 HTML 画布绘制以下笑脸。（**提示**：您将不得不绘制三个完整的圆和一个半圆。诀窍是您可以通过玩转画布的圆形代码来绘制图形。）：![一个快速练习](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_07_05.jpg)

1.  用颜色渐变绘制一个圆。

# 让我们制作一个时钟！

我们将绘制一个模拟时钟，并使其像真正的时钟一样工作。在 HTML 文档的 body 部分中，键入以下代码：

```js
<canvas id="myclock" height="500" width="500"></canvas>
In your <script></script> tags, take the following variables:
Var canvas; // the clock canvas
var canvasElement; // canvas's elements

// clock settings
var cX = 0; 
var cY = 0;
var radius = 150;
```

在这里，`cX`和`cY`是我们时钟的中心坐标。我们将时钟的半径取为 150 像素。您可以增加或减少它。

然后，我们需要初始化变量。在定义前述变量之后，创建一个`init();`函数。

该函数应该看起来类似于以下内容：

```js
function init() {

  canvas = document.getElementById("myclock");
  //Called the element to work on. 
  canvasElement = canvas.getContext("2d");
  //Made the context 2d. 

  cX = canvas.width / 2;
  // we divided by two to get the middle point of X-axis
  cY = canvas.height / 2;
  // we divided by two to get the middle point of Y-axis
  initTime(); //called the initTime() function.
  drawClock(); //Called the drawClock() function to draw the graphics. 

  setInterval("animateClock()", 1000); // Made the animation for each second. Here 1000 is equal to 1 second. 

}
```

让我们初始化时钟的秒、分和时针：

```js
function initTime() {
  date = new Date();
  hours = date.getHours() % 12; // Divided by 12 to make our clock 12 hours. 
  minutes = date.getMinutes(); 
  seconds = date.getSeconds();

}
```

在这里，`date.getHours()`，`date.getMinutes()`和`date.getSeconds()`将返回您计算机的时间并将其保存在我们的变量中。

创建另一个函数，用于为我们的时钟添加动画：

```js
function animateClock() {
  //This function will help our 'second' hand to move after an interval. 
  clearCanvas(); // This will clear the canvas 
  refreshTime(); // This will refresh time after 1 second. 
  drawClock();   // This will draw the clock. 

}
```

我们现在将编写`clearCanvas()`，`refreshTime()`和`drawClock()`：

```js
function clearCanvas() {
  canvasElement.clearRect(0, 0, canvas.width, canvas.height);
}
```

在这里，`canvasElement.clearRect(0, 0, canvas.width, canvas.height);`将在一定时间间隔后重置我们的画布。

我们的`refreshTime()`函数应该如下所示：

```js
function refreshTime() {
  seconds += 1;
  if (Math.floor((seconds / 60)) != 0) { //we divide seconds by 60 until second is equal to zero. 
    minutes += 1; // If 60 second is passed we increment minute by 1\. 
    seconds %= 60; 
  }
  if (Math.floor((minutes / 60)) != 0) { 
    hours += 1; //We increment hour by 1 after 60 minutes. 
    minutes %= 60; 
  }
}
```

我们在`refreshTime()`函数中递增了我们的`seconds`变量。因此，每当调用此函数时，我们的变量将递增`1`。然后，我们对`hours`和`minutes`进行了两个条件操作。

现在，让我们绘制时钟：

```js
function drawClock() {
  drawClockBackground(); //This draws clock background. 
  drawSecondsHand(); //This draws clock's second hand. 
  drawMinutesHand(); //This draws clock's minute hand. 
  drawHoursHand(); //This draws clock's hour hand.
}
```

我们将编写`drawClockBackground()`，`drawSecondsHand()`，`drawMinutesHand()`和`drawHoursHand()`函数：

```js
function drawClockBackground() {
  //this function will draw the background of our clock. We are declaring few variables for mathematical purposes. 
  var correction = 1/300;
  var shift_unit = 1/170;
  var shift_factor = 1/30;
  var angle_initial_position = 2;
  var angle_current_position_begin = 0;
  var angle_current_position_end = 0;
  var repeat = 60;
  var lineWidth = 10;

  for (var i=0; i < repeat; i+=1) {
  //These lines are written for making our clock error free with the angle of the hands (hands' positions)
  angle_current_position_begin = angle_initial_position - (i * shift_factor) - correction;
  angle_current_position_end = angle_current_position_begin + shift_unit;

  if (i % 5 === 0) 
  lineWidth = 20;
  else 
  lineWidth = 10;

  drawArcAtPosition(cX, cY, radius, angle_current_position_begin*Math.PI, angle_current_position_end*Math.PI, false, lineWidth);
  }
  drawLittleCircle(cX, cY);
}
```

我们在这个函数中进行了一些数学运算，并编写了`drawLittleCircle(cX, cY)`函数，用于在时钟中心绘制一个小圆。

该函数应该看起来类似于以下内容：

```js
function drawLittleCircle(cX, cY) {
  drawArcAtPosition(cX, cY, 4, 0*Math.PI, 2*Math.PI, false, 4);
}
```

编写`drawSecondsHand()`函数。此函数将绘制秒针，如下所示：

```js
function drawSecondsHand() {
  /* Simple mathematics to find the co ordinate of the second hand; 
    You may know this: x = rcos(theta), y = rsin(theta). We used these here.
    We divided the values n=by 30 because after 5 seconds the second hand moves 30 degree. 
  */ 
  endX = cX + radius*Math.sin(seconds*Math.PI / 30);
  endY = cY - radius*Math.cos(seconds*Math.PI / 30);
  drawHand(cX, cY, endX, endY);
}
```

我们的`drawMinutesHand()`函数应该如下所示。此函数将绘制时钟的分针，如下所示：

```js
function drawMinutesHand() {
  var rotationUnit = minutes + seconds / 60;
  var rotationFactor = Math.PI / 30;
  var rotation = rotationUnit*rotationFactor;
  var handLength = 0.8*radius;
  endX = cX + handLength*Math.sin(rotation);
  endY = cY - handLength*Math.cos(rotation);
  drawHand(cX, cY, endX, endY);
}
```

现在，让我们看看我们的`drawHoursHand();`函数。此函数将绘制时针：

```js
function drawHoursHand() {
  var rotationUnit = 5 * hours + minutes / 12;
  var rotationFactor = Math.PI / 30;
  var rotation = rotationUnit*rotationFactor;
  var handLength = 0.4*radius;

  endX = cX + handLength*Math.sin(rotation);
  endY = cY - handLength*Math.cos(rotation);
  drawHand(cX, cY, endX, endY);
}
```

我们在前述函数中使用了`drawHand();`函数。让我们编写该函数，如下所示：

```js
function drawHand(beginX, beginY, endX, endY) {
  canvasElement.beginPath();
  canvasElement.moveTo(beginX, beginY);
  canvasElement.lineTo(endX, endY);
  canvasElement.stroke();
  canvasElement.closePath();
}
```

现在，我们将编写我们时钟的最后一个函数，如下所示：

```js
function drawArcAtPosition(cX, cY, radius, start_angle, end_angle, counterclockwise, lineWidth) {
  canvasElement.beginPath();
  canvasElement.arc(cX, cY, radius, start_angle, end_angle, counterclockwise);
  canvasElement.lineWidth = lineWidth;
  canvasElement.strokeStyle = "black";
  canvasElement.stroke();
  canvasElement.closePath();
}
```

我们时钟的完整代码应该看起来类似于以下代码：

```js
<html>
  <head>
    <script type="text/javascript">
      var canvas; 
      var canvasElement;

      // clock settings
      var cX = 0;

      var cY = 0;
      var radius = 150;

      // time settings
      var date;
      var hours;
      var minutes;
      var seconds;

      function init() {
        canvas = document.getElementById("myclock");
        canvasElement = canvas.getContext("2d");

        cX = canvas.width / 2;
        cY = canvas.height / 2;

        initTime();
        drawClock();
        setInterval("animateClock()", 1000);
      }

      // get your system time
      function initTime() {
        date = new Date();
        hours = date.getHours() % 12;
        minutes = date.getMinutes();
        seconds = date.getSeconds();
      }

      // animate the clock
      function animateClock() {
        clearCanvas();
        refreshTime();
        drawClock();
      }

      // clear the canvas
      function clearCanvas() {
        canvasElement.clearRect(0, 0, canvas.width, canvas.height);
      }

      // refresh time after 1 second
      function refreshTime() {
        seconds += 1;
        if (Math.floor((seconds / 60)) != 0) { minutes += 1; seconds %= 60; }
        if (Math.floor((minutes / 60)) != 0) { hours += 1; minutes %= 60; }
      }

      // draw or redraw Clock after time refresh function is called
      function drawClock() {
        drawClockBackground();
        drawSecondsHand();
        drawMinutesHand();
        drawHoursHand();
      }
      function drawHand(beginX, beginY, endX, endY) {
        canvasElement.beginPath();
        canvasElement.moveTo(beginX, beginY);
        canvasElement.lineTo(endX, endY);
        canvasElement.stroke();
        canvasElement.closePath();
      }

      // draw Hand for seconds
      function drawSecondsHand() {
        endX = cX + radius*Math.sin(seconds*Math.PI / 30);
        endY = cY - radius*Math.cos(seconds*Math.PI / 30);
        drawHand(cX, cY, endX, endY);
      }

      // draw Hand for minutes
      function drawMinutesHand() {
        var rotationUnit = minutes + seconds / 60;
        var rotationFactor = Math.PI / 30;
        var rotation = rotationUnit*rotationFactor;
        var handLength = 0.8*radius;

        endX = cX + handLength*Math.sin(rotation);
        endY = cY - handLength*Math.cos(rotation);
        drawHand(cX, cY, endX, endY);
      }

      // draw Hand for hours
      function drawHoursHand() {
        var rotationUnit = 5 * hours + minutes / 12;
        var rotationFactor = Math.PI / 30;
        var rotation = rotationUnit*rotationFactor;
        var handLength = 0.4*radius;

        endX = cX + handLength*Math.sin(rotation);
        endY = cY - handLength*Math.cos(rotation);
        drawHand(cX, cY, endX, endY);
      }

      function drawClockBackground() {
        var correction = 1/300;
        var shift_unit = 1/170;
        var shift_factor = 1/30;
        var angle_initial_position = 2;
        var angle_current_position_begin = 0;
        var angle_current_position_end = 0;
        var repeat = 60;
        var lineWidth = 10;

        for (var i=0; i < repeat; i+=1) {
          angle_current_position_begin = angle_initial_position - (i * shift_factor) - correction;
          angle_current_position_end = angle_current_position_begin + shift_unit;

          if (i % 5 == 0) lineWidth = 20;
          else lineWidth = 10;

          drawArcAtPosition(cX, cY, radius, angle_current_position_begin*Math.PI, angle_current_position_end*Math.PI, false, lineWidth);
        }
        drawLittleCircle(cX, cY);
      }

      function drawArcAtPosition(cX, cY, radius, start_angle, end_angle, counterclockwise, lineWidth) {
        canvasElement.beginPath();
        canvasElement.arc(cX, cY, radius, start_angle, end_angle, counterclockwise);
        canvasElement.lineWidth = lineWidth;
        canvasElement.strokeStyle = "black";
        canvasElement.stroke();
        canvasElement.closePath();
      }
      function drawLittleCircle(cX, cY) {
        drawArcAtPosition(cX, cY, 4, 0*Math.PI, 2*Math.PI, false, 4);
      }

    </script>
  </head>
  <body onload="init()">
    <canvas id="myclock" height="500" width="500"></canvas>
  </body>
</html>
```

如果您能看到代码的输出如下图像，则恭喜您！您成功地使用画布创建了您的 HTML 时钟：

![让我们制作一个时钟！](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_07_06.jpg)

# 摘要

在本章中，我们学习了 HTML 画布的基础知识。我希望您现在可以使用 HTML 画布绘制任何东西。您可能已经玩过在线游戏；它们大多数的组件都是使用 HTML 画布绘制的。因此，如果您想开发自己的 Web 应用程序或游戏，您需要学习画布。您可以轻松编写 JavaScript 代码来绘制和动画形状。

在下一章中，我们将使用 HTML 画布开发一个名为**Rat-man**的游戏。在开始第八章之前，*构建 Rat-man！*，我希望您通过本章学到了很多关于 HTML 画布的知识。如果您学到了，让我们现在开发我们的游戏。


# 第八章：构建老鼠人！

在本章中，我们将构建一个名为**老鼠人**的游戏，实际上是著名游戏**吃豆人**的修改版本。我们将使用 canvas、JavaScript、CSS 和 HTML 来构建我们的游戏。

让我们开始介绍我们游戏的角色：

+   我们的游戏将有一只老鼠。玩家将扮演老鼠。

+   将有四只猫试图抓住老鼠，还有很多奶酪可以让老鼠吃。

+   游戏的主要目标是吃掉所有的奶酪，而不被怪猫抓住。

听起来很有趣，对吧？让我们开始吧...

### 注意

为了使我们的代码更清晰，我们将把我们的 JavaScript、CSS 和图像文件放在单独的文件夹中。我们将有三个主要文件夹，命名如下：

+   `css`

+   `img`

+   `scripts`

# 游戏用户界面

要开始构建我们的游戏，我们需要准备我们的画布。我们的 HTML 文件应该类似于以下内容：

```js
<html>
  <head>
  </head>
  <body>
    <canvas id="main_canvas"></canvas>
  </body>
</html>
```

我们的游戏用户界面将在`<body></body>`标签中。我们很快会在我们的画布上添加 JavaScript。

在`css`文件夹中，创建一个名为`styles.css`的 CSS 文件，其中包含以下代码，用于我们的 HTML`body`、`canvas`和一个播放`button`：

```js
body {
  position: absolute;
  top: 0;
  right: 0;
  bottom: 0;
  left: 0;
  background-color: #ffffff;
  -webkit-background-size: cover;
  -moz-background-size: cover;
  -o-background-size: cover;
  background-size: cover;
  overflow: hidden;
}

canvas {
  position: absolute;
  top: 0;
  right: 0;
  bottom: 0;
  left: 0;
  margin: auto;
  border: 10px solid rgba(63, 72, 204, 0.7);
  border-radius: 20px;
  box-shadow: 0 0 500px 100px #ffffff;
}

button {
  width: 100%;
  height: 100%;
  background-color: #000000;
  color: #FFFFFF;
  font-size: 60px;
  opacity: 0;
  z-index: 1000;
  transition: 5s ease;
  visibility: hidden;
}
```

在同一个文件夹中创建另一个名为`reset.css`的 CSS 文件，并将以下代码添加到 CSS 文件中。这个文件将设计游戏初始屏幕的用户界面：

```js
html, body, div, span, applet, object, iframe,
h1, h2, h3, h4, h5, h6, p, blockquote, pre,
a, abbr, acronym, address, big, cite, code,
del, dfn, em, img, ins, kbd, q, s, samp,
small, strike, strong, sub, sup, tt, var,
b, u, i, center,
dl, dt, dd, ol, ul, li,
fieldset, form, label, legend,
table, caption, tbody, tfoot, thead, tr, th, td,
article, aside, canvas, details, embed, 
figure, figcaption, footer, header, hgroup, 
menu, nav, output, ruby, section, summary,
time, mark, audio, video {
  margin: 0;
  padding: 0;
  border: 0;
  font-size: 100%;
  font: inherit;
  vertical-align: baseline;
}
article, aside, details, figcaption, figure, 
footer, header, hgroup, menu, nav, section {
  display: block;
}

body {
  line-height: 0;
}

ol, ul {
  list-style: none;
}

blockquote, q {
  quotes: none;
}

blockquote:before, blockquote:after,
q:before, q:after {
  content: '';
  content: none;
}

table {
  border-collapse: collapse;
  border-spacing: 0;
}
```

保存这两个文件并在您的 HTML 文件中包含它们，代码如下在`<head></head>`标签中：

```js
<link href="css/styles.css" rel="stylesheet"/>
<link href="css/reset.css" rel="stylesheet"/>
```

如果现在打开浏览器的 HTML 文件，您将看到以下图像：

![游戏用户界面](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_08_01.jpg)

我们将在前面的矩形中绘制我们的游戏界面。

# 为游戏添加功能

为了添加用户界面和游戏功能，我们将需要 JavaScript。我们将在`scripts`文件夹中需要以下 JavaScript 文件：

+   `app.main.js`

+   `app.display_functions.js`

+   `app.init.js`

+   `app.key_handler.js`

+   `app.movement_functions.js`

+   `app.constants.js`

## app.main.js 文件

我们的`app.main.js`文件应该包含以下函数，用于处理`app.key_handler.js`文件和您计算机的键盘。它还将调用`app.init.js`文件来初始化我们的变量。

### 注意

在这里我们使用了`app.main.js`；您不需要像这样命名您的 JavaScript 文件。但是保持命名约定是一个好习惯。

以下代码是`app.main.js`文件的内容：

```js
(function () {
  "use strict";
  APP.Init();
  APP.timer = setInterval(APP.Show_World, 1000 / APP.GAME_FPS);
  window.addEventListener("keydown", APP.Keydown_Handler, false);
  APP.Reset = function () {
    APP.map.Init();
    APP.player.Init();
    APP.monsters.Init();
    APP.blackout.style.transition = "0s";
    APP.blackout.style.visibility = "hidden";
    setTimeout(function () {
      APP.timer = setInterval(APP.Show_World, 1000 / APP.GAME_FPS);
      APP.blackout.style.opacity = 0;
      APP.blackout.style.transition = "5s ease";
    }, 100);
  };
}());
```

## app.display_functions.js 文件

在我们的`app.display_functions.js`文件中，我们将编写一个函数，其中我们将包括`APP.Show_world`函数，该函数在`app.init.js`文件中使用。

该函数应包含以下代码（参考注释以了解每个步骤的作用）：

```js
  APP.Show_World = function () {
    var i,
    dots = 0; //initialized cheese number
    dots = APP.map.Draw(); //put our cheese on the canvas
    if (!dots) {
      APP.Game_Over("YOU WIN!"); //if all cheese are ate by the rat, then the screen should display this.
    }
    */This loop is determine if the rat is caught by the cats  */
    for (i = 0; i < APP.MONSTERS_QUANTITY; i++) {
      if (APP.monsters[i].x === APP.player.x) {
        if (APP.monsters[i].y === APP.player.y) {
          APP.Game_Over("YOU LOSE!");
        }
      }
    }
    APP.monsters.Move(); //cats' movement function
    APP.player.Move();  // rat's movement function
    APP.player.Check_For_Dots(); //This function will check number of chees. 
    APP.portals.Show(); //This will display two portals by using these the rat can escape. 
    APP.player.Show(); //This will show the rat on the canvas. 
      /* this function will show the monster on the canvas */
    for (i = 0; i < APP.MONSTERS_QUANTITY; i++) {
      APP.monsters[i].Show();
    }
  };
```

`APP.map.Draw`函数将包含以下代码：

```js
    APP.map.Draw = function () {
      var i, j, image, x, y, dot_counter = 0; //initialized variables. 
      /*this loop will create our game map/maze */
      for (i = 0; i < APP.MAP_WIDTH; i++) {
        for (j = 0; j < APP.MAP_HEIGHT; j++) {
          image = APP.images[APP.map.cells[j][i]];
          x = i * APP.CELL_WIDTH;
          y = j * APP.CELL_HEIGHT;
          APP.context.drawImage(image, x, y);
          if (APP.map.cells[j][i] === APP.DOT_CELL_DIGIT) {
            dot_counter++;
          }
        }
      }
      return dot_counter;
    };
```

对于猫的移动，我们将使用以下代码的`APP.monsters.Move`函数：

```js
    APP.monsters.Move = function () {
      var i;
      /*This loop will define the cats' quantity */
      for (i = 0; i < APP.MONSTERS_QUANTITY; i++) {
        if (APP.monsters[i].frame === APP.monsters[i].speed) {
          if (APP.monsters[i].direction !== APP.Direction.STOP) {
            APP.monsters[i].previus_direction =
            APP.monsters[i].direction;
          }
          APP.monsters[i].Select_Direction(); //Will select the cats' direction.
          APP.monsters[i].Check_Direction(); //Will check the cats' direction.
          APP.monsters[i].Check_Wall();//Will check the surroundings of the canvas or any block. 
        }
        /* These conditions will check the boundaries of the canvas and make the cats move. */
        if (APP.monsters[i].direction !== APP.Direction.STOP) {
          if (APP.monsters[i].up) {
            APP.monsters[i].Move_Up();
          }
          if (APP.monsters[i].down) {
            APP.monsters[i].Move_Down();
          }
          if (APP.monsters[i].left) {
            APP.monsters[i].Move_Left();
          }
          if (APP.monsters[i].right) {
            APP.monsters[i].Move_Right();
          }
        }
      }
    };
```

当调用`APP.player.Move()`函数时，我们的老鼠将移动，代码如下：

```js
    APP.player.Move = function () {
      if (APP.player.frame === APP.player.speed) {
        APP.player.Check_Direction();
        APP.player.Check_Wall(); //This will check wall
      }
      /* these conditions will check our rat's valid movements */
      if (APP.player.direction !== APP.Direction.STOP) {
        if (APP.player.up) {
          APP.player.Move_Up(); 
        }
        if (APP.player.down) {
          APP.player.Move_Down();
        }
        if (APP.player.left) {
          APP.player.Move_Left();
        }
        if (APP.player.right) {
          APP.player.Move_Right();
        }
      }
    };
    /*this function will feed our rat the chees */
    APP.player.Check_For_Dots = function () {
      if (APP.map.marks[APP.player.y][APP.player.x] === APP.DOT_MARK) {
        APP.player.bonuses++;
        APP.map.marks[APP.player.y][APP.player.x] = APP.BLANK_MARK;
        APP.map.cells[APP.player.y][APP.player.x] = APP.BLANK_CELL_DIGIT;
      }
    };
```

现在，我们将在画布上使我们的老鼠可见，同时通过以下代码调用函数来移动老鼠：

```js
APP.player.Show = function () {
  //initializing our needed variables. 
  var figure_offset = 5,
  frame_number = 2 - Math.floor(this.frame / 3),
  frame_offset = 1 - this.frame / this.speed,
  image, x, y;
  /* conditions for the rat's direction for up, down, left, right*/
  if (this.up) {
    image = this.up_images[frame_number];
    x = (this.x * APP.CELL_WIDTH) - figure_offset;
    y = ((this.y - frame_offset) * APP.CELL_HEIGHT) - figure_offset;

  } else if (this.down) {
    image = this.down_images[frame_number];
    x = (this.x * APP.CELL_WIDTH) - figure_offset;
    y = ((this.y + frame_offset) * APP.CELL_HEIGHT) - figure_offset;

  } else if (this.right) {
    image = this.right_images[frame_number];
    x = ((this.x + frame_offset) * APP.CELL_WIDTH) - figure_offset;
    y = (this.y * APP.CELL_HEIGHT) - figure_offset;

  } else {
    image = this.left_images[frame_number];
    x = ((this.x - frame_offset) * APP.CELL_WIDTH) - figure_offset;
    y = (this.y * APP.CELL_HEIGHT) - figure_offset;

  }
  APP.context.drawImage(image, x, y);
};
```

要在画布上显示我们的猫，我们需要在我们的`APP.Show_Monster()`函数中使用以下代码：

```js
APP.Show_Monster = function () {
  //initializing needed variables. 
  var figure_offset = 15,
  frame_offset = 1 - this.frame / this.speed,
  image, x, y;
  /* binding the cats' directions for 4 directions*/
  if (this.up) {
    image = this.up_images[0];
    x = (this.x * APP.CELL_WIDTH) - figure_offset;
    y = ((this.y - frame_offset) * APP.CELL_HEIGHT) - figure_offset;

  } else if (this.down) {

    image = this.down_images[0];
    x = (this.x * APP.CELL_WIDTH) - figure_offset;
    y = ((this.y + frame_offset) * APP.CELL_HEIGHT) - figure_offset;

  } else if (this.right) {

    image = this.right_images[0];
    x = ((this.x + frame_offset) * APP.CELL_WIDTH) - figure_offset;
    y = (this.y * APP.CELL_HEIGHT) - figure_offset;

  } else {

    image = this.left_images[0];
    x = ((this.x - frame_offset) * APP.CELL_WIDTH) - figure_offset;
    y = (this.y * APP.CELL_HEIGHT) - figure_offset;

  }

  APP.context.drawImage(image, x, y);
};
```

要显示传送门，我们需要编写另一个名为`APP.portals.Show()`的函数，包括以下代码：

```js
    APP.portals.Show = function () {
      //initialized variables and incremented. 
      var offset, frame_offset, sw = +!this.raise;
      frame_offset = sw - this.frame_counter / (this.speed * APP.GAME_FPS); 
      /*controlled frame of the game */
      offset = Math.abs(this.width * frame_offset);
      APP.context.drawImage(this[0].image, this[0].x - offset, this[0].y);
      APP.context.drawImage(this[1].image, this[1].x + offset, this[1].y);
      this.frame_counter++;
      if (this.frame_counter === this.speed * APP.GAME_FPS) {
        this.frame_counter = 0;
        this.raise = !this.raise;
      }
    };
```

游戏结束后，用户需要看到一条消息或使屏幕模糊。为此，我们需要声明另一个名为`APP.Game_Over()`的函数，其中包含以下代码：

```js
    APP.Game_Over = function (condition) {
      clearInterval(APP.timer);
      APP.blackout = document.getElementById("blackout");
      APP.blackout.textContent = condition;
      APP.blackout.style.visibility = "visible";
      APP.blackout.style.opacity = 0.7;
    };
```

## app.init.js 文件

我们的`app.init.js`文件将包含一个函数。在这个函数中，我们将声明以下变量：

```js
  APP.map = {};
  APP.player = {};
  APP.monsters = [{}, {}, {}, {}];
  APP.portals = [{}, {}];
  APP.images = [];
  APP.timer = {};
  APP.canvas = {};
  APP.context = {};
  APP.blackout = document.getElementById("blackout");
```

编写一个包含几个变量的函数，如下所示：

```js
  APP.Init = function () {
    APP.map.Init();
    APP.player.Init();
    APP.portals.Init();
    APP.monsters.Init();
    APP.images.Init();
    APP.canvas.Init();
  };
```

现在，我们将初始化游戏地图：

```js
APP.map.Init = function () {

  //initializing few variables ; few of them may look ugly, but don't worry they are a little bit random. 
  var i, j, map_in_strings = [
                "5000000000000250000000000002",
                "1777777777777117777777777771",
                "1750027500027117500027500271",
                "1716617166617117166617166171",
                "1740037400037437400037400371",
                "1777777777777777777777777771",
                "1750027527500000027527500271",
                "1740037117400250037117400371",
                "1777777117777117777117777771",
                "4000027140026116500317500003",
                "0000217150036436400217150000",
                "6666117116666666666117116666",
                "0000317116502665026117140000",
                "0000037436153664216437400000",
                "6666667666116666116667666666",
                "0000027526140000316527500000",
                "0000217116400000036117150000",
                "6666117116666666666117116666",
                "0000317116500000026117140000",
                "5000037436400250036437400002",
                "1777777777777117777777777771",
                "1750027500027117500027500271",
                "1740217400037437400037150371",
                "1777117777777777777777117771",
                "4027117527500000027527117503",
                "5037437117400250037117437402",
                "1777777117777117777117777771",
                "1750000340027117500340000271",
                "1740000000037437400000000371",
                "1777777777777777777777777771",
                "4000000000000000000000000003"
            ];
  APP.map.cells = [];
  for (i = 0; i < APP.MAP_HEIGHT; i++) {
    APP.map.cells[i] = [];
    for (j = 0; j < APP.MAP_WIDTH; j++) {
      APP.map.cells[i][j] = +map_in_strings[i].charAt(j);
    }
  }
  APP.map.marks = [];
  /* This loop will determine the map's size */
  for (i = 0; i < APP.MAP_HEIGHT; i++) {
    APP.map.marks[i] = [];
    for (j = 0; j < APP.MAP_WIDTH; j++) {
      if (APP.map.cells[i][j] <= APP.WALL_CELL_DIGIT) {
        APP.map.marks[i][j] = APP.WALL_MARK;
      } else if (APP.map.cells[i][j] === APP.BLANK_CELL_DIGIT) {
        APP.map.marks[i][j] = APP.BLANK_MARK;
      } else if (APP.map.cells[i][j] === APP.DOT_CELL_DIGIT) {
        APP.map.marks[i][j] = APP.DOT_MARK;
      }
    }
  }
};
```

# Rat-man 的图像！

为了构建游戏，我们将需要一些图像。我们将把所有图像放在`img`文件夹中。在`img`文件夹中，我们将创建四个文件夹，如下所示：

+   怪物

+   玩家

+   portal

+   墙

我们将在`img`文件夹中保留两个图像，命名为`dot.png`和`blank.png`。

## 怪物文件夹

在`monsters`文件夹中，创建四个以我们猫的名字命名的文件夹。

假设我们的猫的名字如下（您可以随意命名它们）：

+   blinky

+   inky

+   pinky

+   clyde

每个猫文件夹将有四个文件夹，用于猫的定向图像。文件夹名称如下：

+   `up`

+   `down`

+   `left`

+   `right`

每个方向文件夹应包含老鼠的图像。图像名称应为`0.png`。

您需要保持您的图像尺寸为 50 x 50 像素。

## player 文件夹

`player`文件夹应包含四个用于老鼠方向的文件夹。文件夹应命名如下所示：

+   `up`

+   `down`

+   `left`

+   `right`

每个文件夹应包含老鼠的定向图像。需要有两个图像，`0.png`和`1.png`。一个图像是张开嘴的老鼠，另一个是闭嘴的老鼠。图像的尺寸应为 50 x 50 像素。

## 传送门文件夹

`portal`文件夹应包含两个传送门的图像，通过这些传送门，我们的老鼠将从一端传送到另一端。图像名称应为`0.png`和`1.png`。

## 墙壁文件夹

`walls`文件夹应该有五个图像来绘制画布上的墙壁。

图像应命名为`0.png`，`1.png`，`2.png`，`3.png`和`4.png`。图像将是墙的角落和直线。

在构建游戏中使用的图像的分层表示如下：

![墙壁文件夹](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_08_05.jpg)

# 为我们的猫添加图像

我们将编写四个函数，为我们的猫添加完美的图像。函数应该类似于以下函数：

```js
  APP.monsters[0].Init = function () {
    APP.monsters[0].up_images = [];
    APP.monsters[0].right_images = [];
    APP.monsters[0].down_images = [];
    APP.monsters[0].left_images = [];
    APP.monsters[0].up_images[0] = new Image();
    APP.monsters[0].up_images[0].src = "img/monsters/blinky/up/0.png";
    APP.monsters[0].right_images[0] = new Image();
    APP.monsters[0].right_images[0].src = "img/monsters/blinky/right/0.png";
    APP.monsters[0].down_images[0] = new Image();
    APP.monsters[0].down_images[0].src = "img/monsters/blinky/down/0.png";
    APP.monsters[0].left_images[0] = new Image();
    APP.monsters[0].left_images[0].src = "img/monsters/blinky/left/0.png";
    APP.monsters[0].up = false;
    APP.monsters[0].right = true;
    APP.monsters[0].down = false;
    APP.monsters[0].left = false;
    APP.monsters[0].x = APP.INITIAL_BLINKY_X;
    APP.monsters[0].y = APP.INITIAL_BLINKY_Y;
    APP.monsters[0].frame = APP.INITIAL_BLINKY_FRAME;
    APP.monsters[0].speed = APP.BLINKY_SPEED;
  };
```

我们将更改`APP.monsters[0].Init = function ();`函数的索引编号为`APP.monsters[1].Init = function ();`以用于第二只猫。对于第三和第四只猫，我们将更改`APP.monsters[2].Init = function ()`和`APP.monsters[3].Init = function ()`。

我们还需要更改猫的图像位置和索引编号。

为了使用图像初始化墙壁和奶酪，我们需要编写一个函数，如下所示：

```js
  APP.images.Init = function () {
    var i;
    for (i = 0; i <= APP.DOT_CELL_DIGIT; i++) {
      APP.images[i] = new Image();
    }
    APP.images[0].src = "img/walls/0.png";
    APP.images[1].src = "img/walls/1.png";
    APP.images[2].src = "img/walls/2.png";
    APP.images[3].src = "img/walls/3.png";
    APP.images[4].src = "img/walls/4.png";
    APP.images[5].src = "img/walls/5.png";
    APP.images[6].src = "img/blank.png";
    APP.images[7].src = "img/dot.png";
  };
```

# 绘制画布

我们将通过向我们的`app.init.js`文件添加以下函数来绘制我们的画布：

```js
APP.canvas.Init = function () {
  APP.canvas = document.getElementById("main_canvas");
  APP.canvas.width = APP.MAP_WIDTH * APP.CELL_WIDTH;
  APP.canvas.height = APP.MAP_HEIGHT * APP.CELL_HEIGHT;
  APP.context = APP.canvas.getContext("2d");
  APP.context.fillStyle = APP.BG_COLOR;
  APP.context.fillRect(0, 0, APP.canvas.width, APP.canvas.height);
};
```

## app.key_handler.js 文件

现在，在`app.key_handler.js`文件中，我们将编写我们的代码，以使玩家能够使用键盘移动我们的老鼠。代码应该类似于以下内容：

```js
APP.Keydown_Handler = function (event) {
  "use strict";
  var KEYS = {
    /* We will initialize the arrow keys first. 37 = left key, 38 
      = up key, 39 = right key and 40 = down key. */
    LEFT    : 37,
    UP      : 38,
    RIGHT   : 39,
    DOWN    : 40
  }; 
  /* This switch-case will handle the key pressing and the rat's 
    movement. */
  switch (event.keyCode) {
    case KEYS.UP:
      APP.player.direction = APP.Direction.UP;
      break;
    case KEYS.RIGHT:
      APP.player.direction = APP.Direction.RIGHT;
      break;
    case KEYS.DOWN:
      APP.player.direction = APP.Direction.DOWN;
      break;
    case KEYS.LEFT:
      APP.player.direction = APP.Direction.LEFT;
      break;
  }
};
```

## app.movement_functions.js 文件

当按下键时，我们需要查看墙壁的结束或开始位置。当我们到达边缘时，我们需要停止移动老鼠。因此，我们必须为此设置一些条件。第一个条件是检查方向。函数可以编写如下所示：

```js
  APP.Check_Direction = function () {
    switch (this.direction) {
      case APP.Direction.UP:
        if (APP.map.marks[this.y - 1][this.x] !== APP.WALL_MARK){
          this.up = true;
          this.down = false;
          this.right = false;
          this.left = false;
          return true;
        }
        break;
      case APP.Direction.DOWN:
        if (APP.map.marks[this.y + 1][this.x] !== APP.WALL_MARK) {
          this.up = false;
          this.down = true;
          this.right = false;
          this.left = false;
          return true;
        }
        break;
      case APP.Direction.RIGHT:
        if (APP.map.marks[this.y][this.x + 1] !== APP.WALL_MARK) {
          this.up = false;
          this.down = false;
          this.right = true;
          this.left = false;
          return true;
        }
        break;
      case APP.Direction.LEFT:
        if (APP.map.marks[this.y][this.x - 1] !== APP.WALL_MARK) {
          this.up = false;
          this.down = false;
          this.right = false;
          this.left = true;
          return true;
        }
        break;
    }
    return false;
  };
```

在检查方向时，我们还需要朝正确的方向移动。选择方向的函数可以编写如下：

```js
APP.Select_Direction = function () {
  var possible_directions = [],
  direction_quantity = 9,
  rnd;
  switch (this.previus_direction) {
    case APP.Direction.UP:
      possible_directions[0] = APP.Direction.UP;
      possible_directions[1] = APP.Direction.UP;
      possible_directions[2] = APP.Direction.UP;
      possible_directions[3] = APP.Direction.UP;
      possible_directions[4] = APP.Direction.UP;
      possible_directions[5] = APP.Direction.UP;
      possible_directions[6] = APP.Direction.RIGHT;
      possible_directions[7] = APP.Direction.DOWN;
      possible_directions[8] = APP.Direction.LEFT;
      break;
    case APP.Direction.RIGHT:
      possible_directions[0] = APP.Direction.RIGHT;
      possible_directions[1] = APP.Direction.RIGHT;
      possible_directions[2] = APP.Direction.RIGHT;
      possible_directions[3] = APP.Direction.RIGHT;
      possible_directions[4] = APP.Direction.RIGHT;
      possible_directions[5] = APP.Direction.RIGHT;
      possible_directions[6] = APP.Direction.UP;
      possible_directions[7] = APP.Direction.DOWN;
      possible_directions[8] = APP.Direction.LEFT;
      break;
    case APP.Direction.DOWN:
      possible_directions[0] = APP.Direction.DOWN;
      possible_directions[1] = APP.Direction.DOWN;
      possible_directions[2] = APP.Direction.DOWN;
      possible_directions[3] = APP.Direction.DOWN;
      possible_directions[4] = APP.Direction.DOWN;
      possible_directions[5] = APP.Direction.DOWN;
      possible_directions[6] = APP.Direction.UP;
      possible_directions[7] = APP.Direction.RIGHT;
      possible_directions[8] = APP.Direction.LEFT;
      break;
    case APP.Direction.LEFT:
      possible_directions[0] = APP.Direction.LEFT;
      possible_directions[1] = APP.Direction.LEFT;
      possible_directions[2] = APP.Direction.LEFT;
      possible_directions[3] = APP.Direction.LEFT;
      possible_directions[4] = APP.Direction.LEFT;
      possible_directions[5] = APP.Direction.LEFT;
      possible_directions[6] = APP.Direction.UP;
      possible_directions[7] = APP.Direction.RIGHT;
      possible_directions[8] = APP.Direction.DOWN;
      break;
  }
  rnd = Math.floor(Math.random() * direction_quantity);
  this.direction = possible_directions[rnd];
};
```

现在，我们必须检查墙壁。我们可以通过向函数添加一些条件来实现这一点，如下所示：

```js
  APP.Check_Wall = function () {
    if (this.up) {
      if (APP.map.marks[this.y - 1][this.x] !== APP.WALL_MARK) {
        this.up = true;
        this.down = false;
        this.right = false;
        this.left = false;
      } else {
        this.direction = APP.Direction.STOP;
      }
    }

    if (this.right) {
      if (APP.map.marks[this.y][this.x + 1] !== APP.WALL_MARK) {
        this.up = false;
        this.down = false;
        this.right = true;
        this.left = false;
      } else {
        this.direction = APP.Direction.STOP;
      }
    }

    if (this.down) {
      if (APP.map.marks[this.y + 1][this.x] !== APP.WALL_MARK) {
        this.up = false;
        this.down = true;
        this.right = false;
        this.left = false;
      } else {
        this.direction = APP.Direction.STOP;
      }
    }

    if (this.left) {
      if (APP.map.marks[this.y][this.x - 1] !== APP.WALL_MARK) {
        this.up = false;
        this.down = false;
        this.right = false;
        this.left = true;
      } else {
        this.direction = APP.Direction.STOP;
      }
    }
  };
```

箭头键的移动应该有明确定义。我们应该为箭头键创建以下功能：

```js
APP.Move_Up = function () {
  if (this.frame === 0) {
    this.frame = this.speed;
    this.y--;
  } else {
    this.frame--;
  }
  if (this.y < 0) {
    this.y = APP.MAP_HEIGHT - 1;
  }
};
APP.Move_Right = function () {
  if (this.frame === 0) {
    this.frame = this.speed;
    this.x++;
  } else {
    this.frame--;
  }
  if (this.x >= APP.MAP_WIDTH) {
    this.x = 0;
  }
};
APP.Move_Down = function () {
  if (this.frame === 0) {
    this.frame = this.speed;
    this.y++;
  } else {
    this.frame--;
  }
  if (this.y >= APP.MAP_HEIGHT) {
    this.y = 0;
  }
};
APP.Move_Left = function () {
  if (this.frame === 0) {
    this.frame = this.speed;
    this.x--;
  } else {
    this.frame--;
  }
  if (this.x < 0) {
    this.x = APP.MAP_WIDTH - 1;
  }
};
```

## app.constants.js 文件

为了保持我们游戏的画布清洁并保持良好状态，我们需要用一些固定的变量初始化一些变量（例如，地图的高度，单元格的高度，地图的宽度，单元格的宽度等）。我们可以通过在`app.constants.js`文件中编写以下代码来实现这一点。检查带有代码的注释，以清楚地了解代码的工作原理：

```js
var APP = {};
(function () {
  "use strict";
  //used for map's size and each cell's size
  APP.MAP_WIDTH = 28;
  APP.MAP_HEIGHT = 31;
  APP.CELL_WIDTH = 20;
  APP.CELL_HEIGHT = 20;
  APP.BG_COLOR = "#000000";
  APP.GAME_FPS = 40;
  APP.PLAYER_SPEED = 8;
  APP.INITIAL_PLAYER_FRAME = 8;
  APP.INITIAL_PLAYER_X = 14;
  APP.INITIAL_PLAYER_Y = 23;
  APP.WALL_CELL_DIGIT = 5;
  APP.BLANK_CELL_DIGIT = 6;
  APP.DOT_CELL_DIGIT = 7;
  APP.WALL_MARK = "W";
  APP.BLANK_MARK = "B";
  APP.DOT_MARK = "D";
  APP.PORTAL_BLINKING_SPEED = 2;
  APP.PORTAL_WIDTH = 20;
  APP.FIRST_PORTAL_X = 0;
  APP.FIRST_PORTAL_Y = 265;
  APP.SECOND_PORTAL_X = 510;
  APP.SECOND_PORTAL_Y = 265;
  APP.MONSTERS_QUANTITY = 4;
  APP.INKY_SPEED = 7;
  //for the cat's speed and position. 
  APP.INITIAL_INKY_X = 12;
  APP.INITIAL_INKY_Y = 14;
  APP.INITIAL_INKY_FRAME = 7;
  APP.PINKY_SPEED = 7;
  APP.INITIAL_PINKY_X = 13;
  APP.INITIAL_PINKY_Y = 14;
  APP.INITIAL_PINKY_FRAME = 4;
  APP.BLINKY_SPEED = 7;
  APP.INITIAL_BLINKY_X = 14;
  APP.INITIAL_BLINKY_Y = 11;
  APP.INITIAL_BLINKY_FRAME = 4;
  APP.CLYDE_SPEED = 7;
  APP.INITIAL_CLYDE_X = 15;
  APP.INITIAL_CLYDE_Y = 14;
  APP.INITIAL_CLYDE_FRAME = 7;
  APP.Direction = {
    UP      : "UP",
    RIGHT   : "RIGHT",
    DOWN    : "DOWN",
    LEFT    : "LEFT",
    STOP    : "STOP"
  };
})();
```

# 玩游戏

如果您正确集成了代码，并且您的 HTML 文件现在看起来类似于以下内容，您现在可以运行 HTML 文件：

```js
<html>
  <head>
    <link href="css/reset.css" rel="stylesheet"/>
    <link href="css/styles.css" rel="stylesheet"/>
  </head>
  <body>
    <canvas id="main_canvas"></canvas>
    <button id="blackout" onclick="APP.Reset()"></button>
    <script src="img/app.constants.js"></script>
    <script src="img/app.init.js"></script>
    <script src="img/app.display_functions.js"></script>
    <script src="img/app.movement_functions.js"></script>
    <script src="img/app.key_handler.js"></script>
    <script src="img/app.main.js"></script>
  </body>
</html>
```

在浏览器上运行 HTML 文件后，您将能够看到以下屏幕：

![玩游戏](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_08_02.jpg)

恭喜！您已成功构建了老鼠侠！

要玩游戏，请单击画布上的任何位置，并使用箭头键移动您的老鼠。

如果您失去所有生命，您将看到以下屏幕：

![玩游戏](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_08_03.jpg)

如果您赢了，您将看到以下屏幕：

![玩游戏](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_08_04.jpg)

# 总结

我们已经建立了老鼠人！我希望你现在正在玩你建立的游戏。如果你编码了几个小时后无法玩游戏，不要担心。保持冷静，再试一次。整个源代码和所需的图像都包含在这本书中。你可以下载并运行它。然而，在这之前，我建议你至少尝试两次。让我们继续阅读第九章，“使用 OOP 整理您的代码”，以更好地了解如何创建文件或文件夹并访问它们。


# 第九章：使用 OOP 整理您的代码

在本章中，我们将学习**面向对象编程**（**OOP**）并讨论著名游戏**Hangman**的代码。

“OOP 是一种使用抽象来创建基于现实世界的模型的编程范式。OOP 使用了几种来自先前建立的范式的技术，包括模块化、多态和封装。”或者“OOP 语言通常通过使用类来标识，以创建具有相同属性和方法的多个对象。”

您可能已经假定 JavaScript 是一种面向对象的编程语言。是的，你是完全正确的。让我们看看它为什么是一种 OOP 语言。如果计算机编程语言具有以下几个特点，我们称之为面向对象：

+   继承

+   多态

+   封装

+   抽象

在继续之前，让我们讨论**对象**。我们以以下方式在 JavaScript 中创建对象：

```js
var person = new Object();
person.name = "Harry Potter";
person.age = 22;
person.job = "Magician";
```

我们为一个人创建了一个对象。我们添加了一些人的属性。

如果我们想要访问对象的任何属性，我们需要调用该属性。

假设您想要弹出前面`person`对象的`name`属性。您可以使用以下方法来实现：

```js
person.callName = function(){
  alert(this.name);
};
```

我们可以将前面的代码写成以下形式：

```js
var person = {
  name: "Harry Potter",
  age: 22,
  job: "Magician",
  callName: function(){
  alert(this.name);
  }
};
```

# JavaScript 中的继承

继承意味着从父母或祖先那里获得某些东西（如特征、品质等）。在编程语言中，当一个类或对象基于另一个类或对象以保持父类或对象的相同行为时，这被称为**继承**。

我们还可以说这是获得其他东西的属性或行为的概念。

假设，X 从 Y 那里继承了一些东西；这就像 X 是 Y 的一种类型。

JavaScript 占据了继承的能力。让我们来看一个例子。鸟从动物那里继承，因为鸟是动物的一种。因此，鸟可以做与动物相同的事情。

JavaScript 中的这种关系有点复杂，需要一种语法。我们需要使用一个名为`prototype`的特殊对象，它将属性分配给一种类型。我们需要记住只有函数有原型。我们的`Animal`函数应该类似于以下内容：

```js
function Animal(){
//We can code here. 
}; 
```

要添加函数的一些属性，我们需要添加一个原型，如下所示：

```js
Animal.prototype.eat = function(){
  alert("Animal can eat.");
};
```

让我们为我们的`Bird`函数创建原型。我们的函数和原型应该类似于以下内容：

```js
function Bird(){
};
Bird.prototype = new Animal();
Bird.prototype.fly = function(){
  alert("Birds can fly.");
};
Bird.prototype.sing = function(){
  alert("Bird can sing.");
};
```

原型和函数的结果是，您创建的任何`Bird`都将具有`Animal`和`Bird`的属性。但是，如果您创建`Animal`，那么它只会具有`Animal`的属性。`Bird`继承了`Animal`的属性。

因此，我们可以说 JavaScript 具有继承属性。

# JavaScript 中的封装

在面向对象编程中，**封装**是一个非常重要的概念，它允许对象将公共和私有类的成员组合在一个名称下。我们使用封装来保护我们的类免受意外或故意的愚蠢。封装意味着将某物封装在内，就好像某物在胶囊中一样。

现在，我们将看看 JavaScript 是否支持封装。如果是这样，我们可以说 JavaScript 是一种 OOP 语言。让我们看看以下例子：

```js
var person = {
  "name" : "Harry Potter",
  "age" : 22,
};
alert(person.name);
person.name = "John";
alert(person.name);
```

如果我们在控制台上运行这个。第一个警报框将打印以下图像：

![JavaScript 中的封装](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_09_01.jpg)

我们将变量`name`更改为`John`。因此，第二个警报框将类似于以下图像：

![JavaScript 中的封装](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_09_02.jpg)

如果我们意外地将一个数字赋给`name`变量会发生什么？

将数字赋给`name`变量是完全可以接受的。就 JavaScript 而言，变量可以接受任何类型的数据作为其值。但是，我们不希望在名字的位置上出现数字。我们该怎么办？我们可以使用 JavaScript 的封装属性，如下所示：

```js
var person = function () {
  var Name = "Harry Potter";
  var reg = new RegExp(/\d+/);
  return { 
    "setName" : function (newValue) {
      if( reg.test(newValue) ) {
        alert("Invalid Name");
      }
      else {
        Name = newValue;
      }
    },
    "getName" : function () {
      return Name; 
    }
  }; 
}(); 

alert(person.getName());   // Harry potter
person.setName( "John" );
alert(person.getName());  // John
person.setName( 42 ); // Invalid Name; the name is not changed.
person.Name = 42;     // Doesn't affect the private Name variable.
alert(person.getName());  // John is printed again.
```

现在，如果我们在控制台上运行上面的代码，第一个输出将显示一个弹出窗口，其中包含**Harry Potter**，因为我们只调用了`getName()`函数。`getName()`函数有一个初始值，即`Harry Potter`：

![JavaScript 中的封装](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_09_03.jpg)

第二个输出将如下，因为我们将`person`的`Name`属性更改为`John`，然后再次调用`getName()`函数：

![JavaScript 中的封装](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_09_04.jpg)

第三个输出将如下所示，因为我们试图将一个数字推送到一个字符串变量中。一个名字不能是整数，因此，在`if`语句下出现了**Invalid Name**：

![JavaScript 中的封装](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_09_05.jpg)

第四个输出将如下所示，因为数字没有添加到`Name`属性。因此，我们将得到我们推送到`Name`属性的最后数据：

![JavaScript 中的封装](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_09_06.jpg)

我们现在可以确认 JavaScript 支持封装。

JavaScript 还支持**多态**和**抽象**。如果您想了解它们，可以参考以下链接：

[`developer.mozilla.org/en-US/docs/Web/JavaScript/Introduction_to_Object-Oriented_JavaScript`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Introduction_to_Object-Oriented_JavaScript)

让我们做一些有趣的事情。你可能听说过一个叫做“绞刑架”的游戏。我们将讨论该游戏中的面向对象编程。首先，让我们向您介绍这个游戏。

玩家需要猜一个单词。如果他能猜对单词，他就安全了；否则，他将被绞死。看一下以下图像，以清楚地了解游戏：

![JavaScript 中的封装](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_09_07.jpg)

# 解剖绞刑架

绞刑架游戏有两个文件夹和一个 HTML 文件。这两个文件夹的名称分别为`css`和`js`。`index.html` HTML 文件应包含以下代码：

```js
<html lang="en" ng-app="hangman"> 
  <head>
    <title>Hangman</title>
    <link rel="stylesheet" href="css/styles.css">
    <script src="img/angular.min.js"></script>
  </head>
  <body ng-controller="StartHangman">
    <p>Hangman</p>
    <svg width="400" height="400">
      <rect ng-show="failedGuess.length >= 1" x="0" y="0" width="40" height="400"></rect>
      <rect ng-show="failedGuess.length >= 2" x="40" y="20" width="200" height="40"></rect>
      <rect ng-show="failedGuess.length >= 3" x="173" y="50" width="4" height="100"></rect>
      <circle ng-show="failedGuess.length >= 3" cx="175" cy="120" r="40"></circle>
      <line ng-show="failedGuess.length >= 4" x1="175" y1="150" x2="175" y2="185" style="stroke:rgb(0,0,0)" stroke-width="10"></line>
      <line ng-show="failedGuess.length >= 4" x1="175" y1="180" x2="100" y2="240" style="stroke:rgb(0,0,0)" stroke-width="10"></line>
      <line ng-show="failedGuess.length >= 5" x1="175" y1="180" x2="250" y2="240" style="stroke:rgb(0,0,0)" stroke-width="10"></line>
      <line ng-show="failedGuess.length >= 6" x1="175" y1="180" x2="175" y2="265" style="stroke:rgb(0,0,0)" stroke-width="10"></line>
      <line ng-show="failedGuess.length >= 7" x1="175" y1="260" x2="120" y2="340" style="stroke:rgb(0,0,0)" stroke-width="10"></line>
      <line ng-show="failedGuess.length >= 8" x1="175" y1="260" x2="230" y2="340" style="stroke:rgb(0,0,0)" stroke-width="10"></line>
    </svg>

    <div ng-show="stage == 'initial'">
      <h2>Please enter your secret words:</h2>
      <input type="text" ng-model="secretWords" autofocus ng-keyup="$event.keyCode == 13 ? startGame() : null">
      <button ng-click="startGame()">Enter</button>
    </div>

    <div ng-show="stage == 'play'">
      <h1>{{ answer }}</h1>
      <h2>Failed guess ({{ failedGuess.length }}) = {{ failedGuess}}</h2>

      <input type="text" ng-model="charGuess" id="char-guess" ng-keyup="$event.keyCode == 13 ? guess(charGuess) : null" placeholder="Guess a letter">
      <button ng-click="guess(charGuess)">Enter</button>
    </div>

    <div ng-show="stage == 'won'">
      <h1>You Win! :)</h1>
      <h2>That's right, the secret words is {{ secretWords }}</h2>
      <p>Press F5 to replay</p>
    </div>

    <div ng-show="stage == 'lost'">
      <h1>You Lose! :(</h1>
      <h2>The secret word is {{ secretWords }}</h2>
      <p>Press F5 to replay</p>
    </div>

    <script src="img/hangman.js"></script>
  </body>
</html>
```

`css`文件夹应该有一个`styles.css`文件。`styles.css`文件应包含以下代码：

```js
body {
  font-family: monospace;
  text-align: center;
  font-size: 16px;
  line-height: 1.40;
}

input[type="text"] {
  padding: 5px;
  font-family: monospace;
  height: 30px;
  font-size: 1.8em;
  background-color: #fff;
  border: 2px solid #000;
  vertical-align: bottom;
}

svg {
  margin: 0 0 30px;
}

button {
  cursor: pointer;
  margin: 0;
  height: 44px;
  background-color: #fff;
  border: 2px solid #000;
}
```

`js`文件夹中应该有两个 JavaScript 文件，`angular.min.js`和`hangman.js`。

`angular.min.js`文件是一个框架。您可以从[`angularjs.org/`](https://angularjs.org/)下载它，或者它可以与本书的代码捆绑包一起提供。

`hangman.js`文件应该包含以下代码：

```js
var hangman = angular.module('hangman', []).controller('StartHangman', StartHangman);
  function StartHangman($scope, $document) {
    $scope.stage = "initial";
    $scope.secretWords = "";
    $scope.answer = "";
    $scope.failedGuess = [];
    var hasWon = function() {
      var foundDash = $scope.answer.search(/-/);
      return (foundDash == -1);
    }
    var hasLost = function() {
      return ($scope.failedGuess.length >= 8);
    }
    $scope.startGame = function() {
      $scope.secretWords = $scope.secretWords.toLowerCase();
      for(i in $scope.secretWords) {
        $scope.answer += $scope.secretWords[i] == ' ' ? ' ' : '-';
      }
      $scope.stage = "play"
    }
    $scope.guess = function(ch) {
      ch = ch.toLowerCase();
      $scope.charGuess = "";
      if(ch.length != 1) {
        if(ch.length > 1) {
          alert("Please only enter one character at a time");
        }
      return ;
    }
    /* If ch is already in the failed guess list */
    for(i in $scope.failedGuess) {
      if(ch == $scope.failedGuess[i]) return ;
    }
    /* Check if it's part of the answer */
    var found = false;
    $scope.answer = $scope.answer.split(""); /* convert to array of char */
    for(i in $scope.secretWords) {
      if($scope.secretWords[i] === ch) {
        found = true;
        $scope.answer[i] = ch;
      }
    }
    $scope.answer = $scope.answer.join(""); /* convert back to string */
    if(!found) {
      $scope.failedGuess.push(ch);
    }
    if(hasWon()) {
      $scope.stage = "won";
    }
    if(hasLost()) {
      $scope.stage = "lost";
    }
  }
}
```

让我们讨论一下代码。

我们使用`var hangman = angular.module('hangman', []).controller('StartHangman', StartHangman);`来导入我们的`angular.min.js`文件，并开始控制游戏其余的代码。

我们编写了一个`StartHangman($scope, $document) {}`函数，在这里我们将编写我们的代码。我们从我们的`angular.min.js`文件中传递了两个变量，`$scope`和`$document`。

我们初始化了一些变量，如下所示：

```js
$scope.stage = "initial";
$scope.secretWords = "";
$scope.answer = "";
$scope.failedGuess = [];
```

我们为赢得和输掉游戏编写了两个函数，如下所示：

```js
var hasWon = function() {
  var foundDash = $scope.answer.search(/-/);
  return (foundDash == -1);
}
var hasLost = function() {
  return ($scope.failedGuess.length >= 8);
}
```

我们在这里固定了我们的猜测次数。然后，我们编写了一个函数来开始我们的游戏。我们创建了一个对象，并使用了 JavaScript 的继承属性，如下所示：

```js
$scope.startGame = function() {
  $scope.secretWords = $scope.secretWords.toLowerCase();
  for(i in $scope.secretWords) {
    $scope.answer += $scope.secretWords[i] == ' ' ? ' ' : '-';
  }
  $scope.stage = "play"
}
```

我们从玩家那里得到一个输入，以便将其作为我们的秘密单词存储。

游戏的提示页面将类似于以下图像：

![解剖绞刑架](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_09_08.jpg)

然后，我们介绍了我们最重要的函数`$scope.guess = function(ch){}`。我们向函数传递一个字符，并检查它是否与玩家输入的任何字母匹配秘密单词。

# 总结

在本章中，您学习了面向对象编程语言的特性。我们还看到了面向对象编程特性在著名游戏“绞刑架”中的用途！希望您喜欢创建和玩“绞刑架”。在本书的下一章和最后一章中，我们将看到 JavaScript 的可能性。
