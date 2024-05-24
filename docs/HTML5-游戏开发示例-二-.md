# HTML5 游戏开发示例（二）

> 原文：[`zh.annas-archive.org/md5/4F48ABC6F07BFC08A9422C3E7897B7CC`](https://zh.annas-archive.org/md5/4F48ABC6F07BFC08A9422C3E7897B7CC)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：使用 Canvas 和绘图 API 构建 Untangle 游戏

> HTML5 中一个突出的新功能是 Canvas 元素。我们可以将画布元素视为一个动态区域，可以使用脚本在上面绘制图形和形状。
> 
> 网站中的图像多年来一直是静态的。有动画 gif，但它无法与访问者进行交互。画布是动态的。我们可以通过 JavaScript 绘图 API 动态绘制和修改画布中的上下文。我们还可以向画布添加交互，从而制作游戏。

在过去的两章中，我们已经讨论了基于 DOM 的游戏开发与 CSS3 和一些 HTML5 功能。在接下来的两章中，我们将专注于使用新的 HTML5 功能来创建游戏。在本章中，我们将介绍一个核心功能，即画布，以及一些基本的绘图技术。

在本章中，我们将涵盖以下主题：

+   介绍 HTML5 画布元素

+   在画布中绘制圆

+   在画布元素中绘制线条

+   与画布中绘制的对象进行交互的鼠标事件

+   检测线交点

+   使用 Canvas 和绘图 API 构建 Untangle 解谜游戏

Untangle 解谜游戏是一个玩家被给予一些连接的圆的游戏。这些线可能会相交，玩家需要拖动圆圈，使得没有线再相交。

以下截图预览了我们将通过本章实现的游戏：

![使用 Canvas 和绘图 API 构建 Untangle 游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_01.jpg)

所以让我们从头开始制作我们的画布游戏。

# 介绍 HTML5 Canvas 元素

W3C 社区表示画布元素和绘图功能是：

> 一个分辨率相关的位图画布，可用于实时渲染图形、游戏图形或其他视觉图像。

画布元素包含用于绘制的上下文，实际的图形和形状是由 JavaScript 绘图 API 绘制的。

# 在画布中绘制圆

让我们从基本形状——圆开始在画布上绘制。

# 在画布上绘制彩色圆圈的时间

1.  首先，让我们为示例设置新环境。这是一个包含画布元素、一个帮助我们进行 JavaScript 的 jQuery 库、一个包含实际绘图逻辑的 JavaScript 文件和一个样式表的 HTML 文件。![在画布上绘制彩色圆圈的时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_02.jpg)

1.  将以下 HTML 代码放入`index.html`中。这是一个包含画布元素的基本 HTML 文档：

```js
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Drawing Circles in Canvas</title>
<link rel="stylesheet" href="css/untangle.css" />
</head>
<body>
<header>
<h1>Drawing in Canvas</h1>
</header>
<canvas id="game" width="768" height="400">
Sorry, your web browser does not support Canvas content.
</canvas>
<script src="img/jquery-1.6.min.js"></script>
<script src="img/html5games.untangle.js"></script>
</body>
</html>

```

1.  使用 CSS 在`untangle.css`中设置画布的背景颜色：

```js
canvas {
background: #333;
}

```

1.  在`html5games.untangle.js` JavaScript 文件中，我们放置了一个 jQuery `ready`函数，并在其中绘制了一个彩色圆圈：

```js
$(function(){
var canvas = document.getElementById("game");
var ctx = canvas.getContext("2d");
ctx.fillStyle = "rgba(200, 200, 100, .6)";
ctx.beginPath();
ctx.arc(100, 100, 50 , 0, Math.PI*2, true);
ctx.closePath();
ctx.fill();
});

```

1.  在 Web 浏览器中打开`index.html`文件，我们将得到以下截图：

![在画布上绘制彩色圆圈的时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_03.jpg)

## 刚刚发生了什么？

我们刚刚在上面创建了一个简单的带有圆圈的画布**上下文**。

画布元素本身没有太多设置。我们设置了画布的宽度和高度，就像我们固定了真实绘图纸的尺寸一样。此外，我们为画布分配了一个 ID 属性，以便在 JavaScript 中更容易地引用它：

```js
<canvas id="game" width="768" height="400">
Sorry, your web browser does not support Canvas content.
</canvas>

```

## 当 Web 浏览器不支持画布时放置回退内容

并非所有的 Web 浏览器都支持画布元素。特别是那些古老的版本。Canvas 元素提供了一种简单的方法来提供**回退内容**，如果不支持画布元素。在画布的开放和关闭标记内的任何内容都是回退内容。如果 Web 浏览器支持该元素，则此内容将被隐藏。不支持画布的浏览器将显示该回退内容。在回退内容中提供有用的信息是一个好的做法。例如，如果画布的目的是动态图片，我们可以考虑在那里放置一个`<img>`的替代内容。或者我们还可以为访问者提供一些链接，以便轻松升级他们的浏览器。

在这个例子中，我们在画布元素内提供了一个句子。这个句子对于支持画布元素的任何浏览器都是隐藏的。如果他们的浏览器不支持新的 HTML5 画布功能，它将显示给访问者。以下截图显示了旧版本的 Internet Explorer 显示回退内容，而不是绘制画布元素：

![在 Web 浏览器不支持画布时放置回退内容](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_04.jpg)

## 使用画布弧函数绘制圆圈和形状

没有绘制圆的圆函数。画布绘图 API 提供了一个绘制不同弧的函数，包括圆。弧函数接受以下参数

| 参数 | 讨论 |
| --- | --- |
| X | 弧的 x 轴中心点。 |
| Y | 弧的 y 轴中心点。 |
| 半径 | 半径是中心点和弧周围的距离。绘制圆时，较大的半径意味着较大的圆。 |
| startAngle | 起始点是弧度角。它定义了在周边开始绘制弧的位置。 |
| endAngle | 结束点是弧度角。弧是从起始角度的位置绘制到这个结束角度。 |
| 逆时针 | 这是一个布尔值，指示从`startingAngle`到`endingAngle`的弧是顺时针还是逆时针绘制的。这是一个可选参数，默认值为 false。 |

## 将度数转换为弧度

弧函数中使用的角度参数是**弧度**，而不是**度**。如果您熟悉度角，您可能需要在将值放入弧函数之前将度转换为弧度。我们可以使用以下公式转换角度单位：

```js
radians = π/180 x degrees

```

以下图表包含了一些常见的角度值，分别以度和弧度为单位。图表还指示了角度值的位置，以便我们在绘制画布中的弧时轻松选择起始角度和结束角度参数。

![将度数转换为弧度](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_05.jpg)

为了更清楚地绘制具有起始角度和结束角度的不同弧，让我们绘制一些弧。

# 采取行动 用弧函数绘制不同的弧

让我们通过给出不同的起始和结束角度来对`arc`函数进行一些实验：

1.  打开我们刚刚用来绘制圆的`html5games.untangle.js`文件。

1.  通过使用以下弧绘制代码替换圆绘制代码：

```js
$(function(){
var canvas = document.getElementById('game');
var ctx = canvas.getContext('2d');
ctx.fillStyle = "rgba(200, 200, 100, .6)";
// draw bottom half circle
ctx.beginPath();
ctx.arc(100, 110, 50 , 0, Math.PI);
ctx.closePath();
ctx.fill();
// draw top half circle
ctx.beginPath();
ctx.arc(100, 90, 50 , 0, Math.PI, true);
ctx.closePath();
ctx.fill();
// draw left half circle
ctx.beginPath();
ctx.arc(230, 100, 50 , Math.PI/2, Math.PI*3/2);
ctx.closePath();
ctx.fill();
// draw right half circle
ctx.beginPath();
ctx.arc(250, 100, 50 , Math.PI*3/2, Math.PI/2);
ctx.closePath();
ctx.fill();
// draw a shape that is almost a circle
ctx.beginPath();
ctx.arc(180, 240, 50 , Math.PI*7/6, Math.PI*2/3);
ctx.closePath();
ctx.fill();
// draw a small arc
ctx.beginPath();
ctx.arc(150, 250, 50 , Math.PI*7/6, Math.PI*2/3, true);
ctx.closePath();
ctx.fill();
});

```

1.  是时候在 Web 浏览器中测试它了。如下截图所示，画布上应该有六个不同的半圆和弧：

![采取行动 用弧函数绘制不同的弧](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_06.jpg)

## 发生了什么？

我们在弧函数中使用了不同的`startAngle`和`endAngle`参数来绘制六种不同的弧形状。这些弧形状演示了弧函数的工作原理。

让我们回顾一下度和弧度的关系圆，并看一下顶部的半圆。顶部的半圆从角度 0 开始，到角度π结束，弧是逆时针绘制的。如果我们看一下圆，它看起来像下面的图表：

发生了什么？

如果我们从 210 度开始，到 120 度结束，顺时针方向，我们将得到以下弧：

![发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_08.jpg)

## 小测验

1.  我们可以使用哪个弧命令来绘制以下弧？![小测验](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_09.jpg)

a. ctx.arc(300, 250, 50 , Math.PI*3/2, Math.PI/2, true);

b. ctx.arc(300, 250, 50 , Math.PI*3/2, Math.PI/2);

c. ctx.arc(300, 250, 50 , Math.PI*3/2, 0, true);

d. ctx.arc(300, 250, 50 , Math.PI*3/2, 0);

## 在画布中执行路径绘制

当我们调用弧函数或其他路径绘制函数时，我们并没有立即在画布上绘制路径。相反，我们将其添加到路径列表中。这些路径直到我们执行绘图命令才会被绘制。

有两个绘制执行命令。一个用于填充路径，另一个用于绘制描边。

我们通过调用`fill`函数填充路径，并通过调用`stroke`函数绘制路径的描边，这在绘制线条时会用到：

```js
ctx.fill();

```

## 为每种样式开始一个路径

`fill`和`stroke`函数填充和绘制画布上的路径，但不清除路径列表。以以下代码片段为例。在用红色填充我们的圆之后，我们添加其他圆并用绿色填充。代码的结果是两个圆都被绿色填充，而不仅仅是新圆被绿色填充：

```js
var canvas = document.getElementById('game');
var ctx = canvas.getContext('2d');
ctx.fillStyle = "red";
ctx.arc(100, 100, 50 , 0, Math.PI*2, true);
ctx.fill();
ctx.arc(210, 100, 50, 0, Math.PI*2, true);
ctx.fillStyle = "green";
ctx.fill();

```

这是因为在调用第二个`fill`命令时，画布中的路径列表包含两个圆。因此，`fill`命令会用绿色填充两个圆，并覆盖红色圆。

为了解决这个问题，我们希望确保每次绘制新形状时都调用`beginPath`。

`beginPath`清空路径列表，所以下次调用`fill`和`stroke`命令时，它只会应用于`beginPath`之后的所有路径。

## 试试看

我们刚刚讨论了一个代码片段，我们打算用红色绘制两个圆，另一个用绿色。结果代码绘制出来的两个圆都是绿色的。我们如何向代码添加`beginPath`命令，以便正确绘制一个红色圆和一个绿色圆？

## 关闭路径

`closePath`函数将从最新路径的最后一个点绘制一条直线到路径的第一个点。这是关闭路径。如果我们只打算填充路径而不打算绘制描边轮廓，`closePath`函数不会影响结果。以下屏幕截图比较了在半圆上调用`closePath`和不调用`closePath`的结果：

![关闭路径](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_10.jpg)

## 快速测验

1.  如果我们只想填充颜色而不绘制轮廓描边，我们需要在绘制的形状上使用`closePath`函数吗？

a. 是的，我们需要`closePath`函数。

b. 不，它不在乎我们是否有`closePath`函数。

## 将绘制圆形包装在函数中

绘制圆形是一个常见的函数，我们将经常使用它。最好创建一个绘制圆形的函数，而不是现在输入几行代码。

# 执行操作将绘制圆形的代码放入函数中

让我们为绘制圆形创建一个函数，并在画布上绘制一些圆圈：

1.  打开`html5games.untangle.js`文件。

1.  用以下代码替换 JavaScript 文件中的原始代码。它基本上将我们刚刚使用的绘制圆形的代码放入一个函数中，并使用 for 循环在画布上随机放置五个圆圈：

```js
var untangleGame = {};
function drawCircle(ctx, x, y, radius) {
ctx.fillStyle = "rgba(200, 200, 100, .9)";
ctx.beginPath();
ctx.arc(x, y, radius, 0, Math.PI*2, true);
ctx.closePath();
ctx.fill();
}
$(function(){
var canvas = document.getElementById('game');
var ctx = canvas.getContext('2d');
var circleRadius = 10;
var width = canvas.width;
var height = canvas.height;
// random 5 circles
var circlesCount = 5;
for (var i=0;i<circlesCount;i++) {
var x = Math.random()*width;
var y = Math.random()*height;
drawCircle(ctx, x, y, circleRadius);
}
});

```

1.  在 Web 浏览器中打开 HTML 文件以查看结果。

![执行操作将绘制圆形的代码放入函数中](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_11.jpg)

## 刚刚发生了什么？

绘制圆形的代码在页面加载和准备就绪后执行。我们使用循环在画布上随机绘制了几个圆圈。

## 在 JavaScript 中生成随机数

在游戏开发中，我们经常使用`random`函数。我们可能希望随机召唤一个怪物让玩家战斗，我们可能希望玩家取得进展时随机掉落奖励，我们可能希望随机数成为掷骰子的结果。在这段代码中，我们随机放置圆圈在画布上。

要在 JavaScript 中生成一个随机数，我们使用`Math.random()`函数。

`random`函数中没有参数。它总是返回一个介于 0 和 1 之间的浮点数。这个数字大于或等于 0，小于 1。

有两种常见的使用`random`函数的方式。一种方式是在给定范围内生成随机数。另一种方式是生成真或假值

| 用法 | 代码 | 讨论 |
| --- | --- | --- |
| 获取 A 和 B 之间的随机整数`Math.floor(Math.random()*B)+A` `Math.floor()`函数去掉给定数字的小数点。以`Math.floor(Math.random()*10)+5`为例。`Math.random()`返回 0 到 0.9999 之间的小数。`Math.random()*10`是 0 到 9.9999 之间的小数。`Math.floor(Math.random()*10)`是 0 到 9 之间的整数。最后，`Math.floor(Math.random()*10) + 5`是 5 到 14 之间的整数。 |
| 获取一个随机的布尔值（Math.random() > 0.495）`(Math.random() > 0.495)`意味着有 50%的假和 50%的真。我们可以进一步调整真/假比例。`(Math.random() > 0.7)`意味着几乎有 70%的假和 30%的真。 |

## 保存圆的位置

当我们开发基于 DOM 的游戏时，比如我们在前几章中构建的游戏，我们经常将游戏对象放入 DIV 元素中，并在代码逻辑中稍后访问它们。在基于画布的游戏开发中情况就不同了。

为了在画布上绘制游戏对象后访问它们，我们需要自己记住它们的状态。比如现在我们想知道有多少个圆被绘制了，它们在哪里，我们需要一个数组来存储它们的位置。

# 行动时间保存圆的位置

1.  在文本编辑器中打开`html5games.untangle.js`文件。

1.  在 JavaScript 文件的顶部添加以下`circle`对象定义代码：

```js
function Circle(x,y,radius){
this.x = x;
this.y = y;
this.radius = radius;
}

```

1.  现在我们需要一个数组来存储圆的位置。向`untangleGame`对象添加一个新数组：

```js
var untangleGame = {
circles: []
};

```

1.  在画布上绘制每个圆之后，我们将圆的位置保存到`circles`数组中。在调用`drawCircle`函数后添加突出显示的行：

```js
$(function(){
var canvas = document.getElementById('game');
var ctx = canvas.getContext('2d');
var circleRadius = 10;
var width = canvas.width;
var height = canvas.height;
// random 5 circles
var circlesCount = 5;
for (var i=0;i<circlesCount;i++) {
var x = Math.random()*width;
var y = Math.random()*height;
drawCircle(ctx, x, y, circleRadius); untangleGame.circles.push(new Circle(x,y,circleRadius));
}
});

```

1.  现在我们可以在 web 浏览器中测试代码。在画布上绘制随机圆时，这段代码与上一个示例之间没有视觉差异。这是因为我们保存了圆圈，但没有改变任何影响外观的代码。

## 刚刚发生了什么？

我们保存了每个圆的位置和颜色。这是因为我们无法直接访问画布中绘制的对象。所有线条和形状都是在画布上绘制的，我们无法将线条或形状作为单独的对象访问。绘制的项目都是在画布上绘制的。我们不能像在油画中移动房子一样，也不能直接操作画布元素中的任何绘制项目。

## 在 JavaScript 中定义一个基本的类定义

JavaScript 是**面向对象编程**语言。我们可以为我们的使用定义一些对象结构。`Circle`对象为我们提供了一个数据结构，可以轻松存储一组 x 和 y 位置以及半径。

在定义`Circle`对象之后，我们可以通过以下代码创建一个新的`Circle`实例，具有 x、y 和半径值：

```js
var circle1 = new Circle(100, 200, 10);

```

### 注意

有关面向对象编程 JavaScript 的更详细用法，请阅读以下链接中的 Mozilla Developer Center：

[`developer.mozilla.org/en/Introduction_to_Object-Oriented_JavaScript`](http://https://developer.mozilla.org/en/Introduction_to_Object-Oriented_JavaScript)

## 试一试

我们在画布上随机画了几个圆。它们是相同风格和相同大小的。我们如何随机绘制圆的大小？并用不同的颜色填充圆？尝试修改代码并使用绘图 API 进行操作。

# 在画布上绘制线条

现在我们这里有几个圆，怎么样用线连接它们？让我们在每个圆之间画一条直线。

# 行动时间在每个圆之间绘制直线

1.  打开我们刚刚在圆形绘制示例中使用的`index.html`。

1.  将**在 Canvas 中绘制圆**的措辞更改为**在 Canvas 中绘制线条**。

1.  打开`html5games.untangle.js` JavaScript 文件。

1.  我们将在现有圆形绘制代码的基础上添加线条绘制代码。用以下代码替换原始代码。修改后的代码已突出显示：

```js
function Circle(x,y,radius){
this.x = x;
this.y = y;
this.radius = radius;
}
function Line(startPoint,endpoint, thickness) {
this.startPoint = startPoint;
this.endPoint = endPoint;
this.thickness = thickness;
}
var untangleGame = {
circles: [],
thinLineThickness: 1,
lines: []
};
function drawLine(ctx, x1, y1, x2, y2, thickness) {
ctx.beginPath();
ctx.moveTo(x1,y1);
ctx.lineTo(x2,y2);
ctx.lineWidth = thickness;
ctx.strokeStyle = "#cfc";
ctx.stroke();
}
function drawCircle(ctx, x, y, radius) {
ctx.fillStyle = "rgba(200, 200, 100, .9)";
ctx.beginPath();
ctx.arc(x, y, radius, 0, Math.PI*2, true);
ctx.closePath();
ctx.fill();
}
$(function(){
var canvas = document.getElementById('game');
var ctx = canvas.getContext('2d');
var circleRadius = 10;
var width = canvas.width;
var height = canvas.height;
// random 5 circles
var circlesCount = 5;
for (var i=0;i<circlesCount;i++) {
var x = Math.random()*width;
var y = Math.random()*height;
drawCircle(ctx, x, y, circleRadius);
untangleGame.circles.push(new Circle(x,y,radius));
}
for (var i=0;i< untangleGame.circles.length;i++) {
var startPoint = untangleGame.circles[i];
for(var j=0;j<i;j++) {
var endPoint = untangleGame.circles[j];
drawLine(ctx, startPoint.x, startPoint.y, endPoint.x, endPoint.y, 1);
untangleGame.lines.push(new Line(startPoint, endpoint, untangleGame.thinLineThickness));
}
lines, in canvaslines, in canvasstraight lines, drawing}
});

```

1.  在 web 浏览器中测试代码。我们应该看到有线连接到每个随机放置的圆。

![时间进行绘制每个圆圈之间的直线](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_12.jpg)

## 刚刚发生了什么？

与保存圆圈位置的方式类似，我们有一个数组来保存我们绘制的每个线段。我们声明一个线条类定义来存储线段的一些基本信息。也就是说，我们保存线段的起始点和终点以及线条的粗细。

## 介绍线条绘制 API

有一些绘制 API 供我们绘制和设置线条样式

| 线条绘制函数 | 讨论 |
| --- | --- |
| MoveTo | `Moveto`函数就像我们手中拿着笔在纸上移动而不用笔触到纸。 |
| LineTo | 这个函数就像在纸上放下笔并画一条直线到目标点。 |
| lineWidth | `LineWidth`设置我们之后绘制的线条的粗细。 |
| 描边 | `stroke`是执行绘制的函数。我们设置了一系列的`moveTo, lineTo`或样式函数，最后调用`stroke`函数在画布上执行它。 |

通常我们使用`moveTo`和`lineTo`对来绘制线条。就像在现实世界中，我们在纸上移动笔到线条的起始点并放下笔来绘制一条线。然后，继续绘制另一条线或在绘制之前移动到其他位置。这正是我们在画布上绘制线条的流程。

### 注意

我们刚刚演示了绘制一条简单的线。我们可以在画布中为线条设置不同的样式。有关更多线条样式的详细信息，请阅读 W3C 的样式指南（[`dev.w3.org/html5/2dcontext/#line-styles`](http://dev.w3.org/html5/2dcontext/#line-styles)）和 Mozilla 开发者中心（[`developer.mozilla.org/En/Canvas_tutorial/Applying_styles_and_colors`](https://developer.mozilla.org/En/Canvas_tutorial/Applying_styles_and_colors)）。

# 通过鼠标事件与画布中的绘制对象交互

到目前为止，我们已经展示了我们可以根据逻辑动态在画布中绘制形状。游戏开发中还有一个缺失的部分，那就是输入。

现在想象一下，我们可以在画布上拖动圆圈，连接的线条会跟随圆圈移动。在这一部分，我们将在画布上添加鼠标事件，使我们的圆圈**可拖动**。

# 拖动画布中的圆圈的时间

1.  让我们继续之前的代码。打开`html5games.untangle.js`文件。

1.  我们需要一个函数来清除画布中的所有绘制。将以下函数添加到 JavaScript 文件的末尾：

```js
function clear(ctx) {
ctx.clearRect(0,0,ctx.canvas.width,ctx.canvas.height);
}

```

1.  在 jQuery 的`ready`函数中删除线条绘制代码。我们将其分成两部分，线条数据和绘制。

1.  添加以下函数，为每个圆圈分配连接线。这些线将稍后绘制：

```js
function connectCircles()
{
// connect the circles to each other with lines
untangleGame.lines.length = 0;
for (var i=0;i< untangleGame.circles.length;i++) {
var startPoint = untangleGame.circles[i];
for(var j=0;j<i;j++) {
var endPoint = untangleGame.circles[j];
untangleGame.lines.push(new Line(startPoint, endPoint, untangleGame.thinLineThickness));
}
}
}

```

1.  将鼠标事件监听器代码添加到 jQuery 的`ready`函数中。以下是函数现在的样子。高亮显示的代码是鼠标事件处理程序：

```js
$(function(){
// get the reference of canvas element.
var canvas = document.getElementById("game");
var ctx = canvas.getContext("2d");
var circleRadius = 10;
var width = canvas.width;
var height = canvas.height;
// random 5 circles
var circlesCount = 5;
for (var i=0;i<circlesCount;i++) {
var x = Math.random()*width;
var y = Math.random()*height;
drawCircle(ctx, x, y, circleRadius);
untangleGame.circles.push(new Circle(x,y,circleRadius));
}
connectCircles();
// Add Mouse Event Listener to canvas
// we find if the mouse down position is on any circle
// and set that circle as target dragging circle.
$("#game").mousedown(function(e) {
var canvasPosition = $(this).offset();
var mouseX = e.layerX || 0;
var mouseY = e.layerY || 0;
for(var i=0;i<untangleGame.circles.length;i++)
{
var circleX = untangleGame.circles[i].x;
var circleY = untangleGame.circles[i].y;
var radius = untangleGame.circles[i].radius;
if (Math.pow(mouseX-circleX,2) + Math.pow(mouseY-circleY,2) < Math.pow(radius,2))
if (Math.pow(mouseX-circleX,2) + Math.pow(mouseY-circleY,2) < Math.pow(radius,2))
{
canvascanvascircles, dragginguntangleGame.targetCircle = i;
break;
}
}
});
// we move the target dragging circle when the mouse is moving
$("#game").mousemove(function(e) {
if (untangleGame.targetCircle != undefined)
{
var canvasPosition = $(this).offset();
var mouseX = e.layerX || 0;
var mouseY = e.layerY || 0;
var radius = untangleGame.circles[untangleGame.targetCircle]. radius;
untangleGame.circles[untangleGame.targetCircle] = new Circle(mouseX, mouseY,radius);
}
connectCircles();
});
// We clear the dragging circle data when mouse is up
$("#game").mouseup(function(e) {
untangleGame.targetCircle = undefined;
});
// setup an interval to loop the game loop
setInterval(gameloop, 30);
});

```

1.  然后我们添加`gameloop`函数，用于绘制更新后的圆圈和线条：

```js
function gameloop() {
// get the reference of the canvas element and the drawing context.
var canvas = document.getElementById('game');
var ctx = canvas.getContext('2d');
// clear the canvas before re-drawing.
clear(ctx);
// draw all remembered line
for(var i=0;i<untangleGame.lines.length;i++) {
var line = untangleGame.lines[i];
var startPoint = line.startPoint;
var endPoint = line.endPoint;
var thickness = line.thickness;
drawLine(ctx, startPoint.x, startPoint.y, endPoint.x, endPoint.y, thickness);
}
// draw all remembered circles
for(var i=0;i<untangleGame.circles.length;i++) {
var circle = untangleGame.circles[i];
drawCircle(ctx, point.x, point.y, circle.radius);
}
}

```

1.  在网络浏览器中打开`index.html`。应该有五个圆圈，它们之间有连线。尝试拖动圆圈。被拖动的圆圈会跟随鼠标光标移动，连接的线也会跟随移动。

![时间进行在画布中拖动圆圈](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_13.jpg)

## 刚刚发生了什么？

我们在 jQuery 的`ready`函数中设置了三个鼠标事件监听器。它们是鼠标按下、移动和松开事件。

## 获取画布元素中的鼠标位置

我们可以通过鼠标事件中的`layerX`和`layerY`属性获取相对于元素的鼠标光标位置。以下是我们在代码示例中使用的代码片段。`|| 0`是为了在`layerX`或`layerY`未定义时使结果为 0：

```js
var mouseX = e.layerX || 0;
var mouseY = e.layerY || 0;

```

请注意，我们需要显式设置元素的位置属性，以便获取正确的`layerX`和`layerY`属性。

## 在画布中检测圆圈上的鼠标事件

在讨论了基于 DOM 开发和基于画布开发之间的区别之后，我们不能直接监听画布中任何绘制形状的鼠标事件。这是不可能的。我们不能监视画布中任何绘制形状的事件。我们只能获取画布元素的鼠标事件，并计算画布的相对位置。然后根据鼠标位置改变游戏对象的状态，最后在画布上重新绘制它。

我们如何知道我们点击了一个圆？

我们可以使用**点在圆内**的公式。这是为了检查圆的中心点与鼠标位置之间的距离。当距离小于圆的半径时，鼠标点击了圆。

我们使用以下公式来计算两点之间的距离：

```js
Distance = (x2-x1)2 + (y2-y1)2

```

以下图表显示了当中心点与鼠标光标之间的距离小于半径时，光标在圆内的情况：

![在画布上检测圆上的鼠标事件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_14.jpg)

我们使用的以下代码解释了如何在鼠标按下事件处理程序中应用距离检查来知道鼠标光标是否在圆内：

```js
if (Math.pow(mouseX-circleX,2) + Math.pow(mouseY-circleY,2) < Math.pow(untangleGame.circleRadius,2))
{
untangleGame.targetCircle = i;
break;
}

```

当我们知道鼠标光标按在画布上的圆上时，我们将其标记为在鼠标移动事件上被拖动的目标圆。在鼠标移动事件处理程序中，我们将目标拖动的圆的位置更新为最新的光标位置。当鼠标松开时，我们清除目标圆的引用。

## 小测验

1.  我们能直接访问画布中已经绘制的形状吗？

a. 是的

b. 不

1.  我们可以使用哪种方法来检查一个点是否在圆内？

a. 点的坐标小于圆的中心点的坐标。

b. 点与圆的中心之间的距离小于圆的半径。

c. 点的 x 坐标小于圆的半径。

d. 点与圆的中心之间的距离大于圆的半径。

## 游戏循环

在第二章《使用基于 DOM 的游戏开发入门》中，我们讨论了游戏循环的方法。在第二章的乒乓球游戏中，**游戏循环**操作键盘输入并更新基于 DOM 的游戏对象的位置。

在这里，游戏循环用于重新绘制画布以呈现后来的游戏状态。如果我们在改变状态后不重新绘制画布，比如圆的位置，我们将看不到它。

这就像是在电视上刷新图像。电视每秒刷新屏幕 12 次。我们也会每秒重新绘制画布场景。在每次重绘中，我们根据当前圆的位置在画布上绘制游戏状态。

## 清除画布

当我们拖动圆时，我们重新绘制画布。问题是画布上已经绘制的形状不会自动消失。我们将继续向画布添加新路径，最终搞乱画布上的一切。如果我们在每次重绘时不清除画布，将会发生以下截图中的情况：

清除画布

由于我们已经在 JavaScript 中保存了所有游戏状态，我们可以安全地清除整个画布，并根据最新的游戏状态绘制更新的线条和圆。要清除画布，我们使用画布绘制 API 提供的`clearRect`函数。`clearRect`函数通过提供一个矩形裁剪区域来清除矩形区域。它接受以下参数作为裁剪区域：

ctx.clearRect(x,context.clearRect(x, y, width, height)

| Argument | Definition |
| --- | --- |
| x | 矩形裁剪区域的左上角点的 x 轴坐标。 |
| y | 矩形裁剪区域的左上角点的 y 轴坐标。 |
| width | 矩形区域的宽度。 |
| height | 矩形区域的高度。 |

`x`和`y`设置了要清除的区域的左上位置。`width`和`height`定义了要清除的区域大小。要清除整个画布，我们可以将(0,0)作为左上位置，并将画布的宽度和高度提供给`clearRect`函数。以下代码清除了整个画布上的所有绘制内容：

```js
ctx.clearRect(0, 0, ctx.canvas.width, ctx.canvas.height);

```

## 小测验

1.  我们可以使用`clearRect`函数清除画布的一部分吗？

a. 是

b. 否

1.  以下代码是否清除了画布上的绘制内容？

```js
ctx.clearRect(0, 0, ctx.canvas.width, 0);

```

a. 是

b. 否

# 在画布中检测线相交

我们在画布上有可拖动的圆圈和连接的线条。一些线相交，而另一些则不相交。现在想象我们想要区分相交的线。我们需要一些数学公式来检查它们，并加粗这些相交的线。

# 时间行动 区分相交的线

让我们增加这些相交线的粗细，这样我们就可以在画布中区分它们：

1.  在文本编辑器中打开`html5games.untangle.js`文件。

1.  我们将`thinLineThickness`设置为默认线条粗细。我们添加以下代码来定义粗线的粗细：

```js
var untangleGame = {
circles: [],
thinLineThickness: 1,
boldLineThickness: 5,
lines: []
};

```

1.  为了使代码更具可重用性和可读性，我们希望将线相交逻辑与游戏逻辑隔离开来。我们创建一个函数来检查给定的两条线是否相交。将以下函数添加到 JavaScript 文件的末尾：

```js
function isIntersect(line1, line2)
{
// convert line1 to general form of line: Ax+By = C
var a1 = line1.endPoint.y - line1.point1.y;
var b1 = line1.point1.x - line1.endPoint.x;
var c1 = a1 * line1.point1.x + b1 * line1.point1.y;
// convert line2 to general form of line: Ax+By = C
var a2 = line2.endPoint.y - line2.point1.y;
var b2 = line2.point1.x - line2.endPoint.x;
var c2 = a2 * line2.startPoint.x + b2 * line2.startPoint.y;
// calculate the intersection point
var d = a1*b2 - a2*b1;
// parallel when d is 0
if (d == 0) {
return false;
}else {
line intersectionline intersectiondetermining, in canvasvar x = (b2*c1 - b1*c2) / d;
var y = (a1*c2 - a2*c1) / d;
// check if the interception point is on both line segments
if ((isInBetween(line1.startPoint.x, x, line1.endPoint.x) || isInBetween(line1.startPoint.y, y, line1.endPoint.y)) &&
(isInBetween(line2.startPoint.x, x, line2.endPoint.x) || isInBetween(line2.startPoint.y, y, line2.endPoint.y)))
{
return true;
}
}
return false;
}
// return true if b is between a and c,
// we exclude the result when a==b or b==c
function isInBetween(a, b, c) {
// return false if b is almost equal to a or c.
// this is to eliminate some floating point when
// two value is equal to each other but different with 0.00000...0001
if (Math.abs(a-b) < 0.000001 || Math.abs(b-c) < 0.000001) {
return false;
}
// true when b is in between a and c
return (a < b && b < c) || (c < b && b < a);
}

```

1.  接下来，我们有一个函数来检查我们的线是否相交，并用粗体标记该线。将以下新函数添加到代码中：

```js
function updateLineIntersection()
{
// checking lines intersection and bold those lines.
for (var i=0;i<untangleGame.lines.length;i++) {
for(var j=0;j<i;j++) {
var line1 = untangleGame.lines[i];
var line2 = untangleGame.lines[j];
// we check if two lines are intersected,
// and bold the line if they are.
if (isIntersect(line1, line2)) {
line1.thickness = untangleGame.boldLineThickness;
line2.thickness = untangleGame.boldLineThickness;
}
}
}
}

```

1.  最后，我们通过在两个地方添加以下函数调用来更新线相交。一个是在连接我们的圆圈之后，另一个是在鼠标移动事件处理程序中：

updateLineIntersection();

1.  现在是在 Web 浏览器中测试相交的时间了。在画布中查看圆圈和线条，相交的线应该比没有相交的线更粗。尝试拖动圆圈以改变相交关系，线条将变细或变粗。

![时间行动 区分相交的线](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_16.jpg)

## 刚刚发生了什么？

我们刚刚在现有的拖动圆圈示例中添加了**线相交**检查代码。线相交代码涉及一些数学公式，以获得两条线的**交点**，并检查该点是否在我们提供的线段内。让我们看看数学部分，看看它是如何工作的。

## 确定两条线段是否相交

根据我们从几何学中学到的相交方程，对于一般形式中的两条给定线，我们可以得到交点。

**一般形式是什么？** 在我们的代码中，我们有线段的起点和终点的 x 和 y 坐标。这是一个**线段**，因为在数学中它只是线的一部分。线的一般形式由`Ax + By = C`表示。

以下图表解释了一般形式上的线段：

![确定两条线段是否相交](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_17.jpg)

我们可以通过以下方程将具有点 1 的线段转换为 x1，y1 和具有点 2 的线段转换为 x2，y2 的一般形式：

```js
A = y2-y1
B = x1-x2
C = A * x1 + B * y2

```

现在我们有一个线方程`AX+BY = C`，其中`A，B，C`是已知的，`X`和`Y`是未知的。

我们正在检查两条相交的线。我们可以将两条线都转换为一般形式，并得到两条线方程：

```js
Line 1: A1X+B1Y = C1
Line 2: A2X+B2Y = C2

```

通过将两个一般形式方程放在一起，X 和 Y 是两个未知的变量。然后我们可以解这两个方程，得到 X 和 Y 的交点。

如果`A1 * B2 - A2 * B1`为零，则两条线是平行的，没有交点。否则，我们可以使用以下方程得到交点：

```js
X = (B2 * C1 B1 * C2) / (A1 * B2 A2 * B1)
Y = (A1 * C2 A2 * C1) / (A1 * B2 A2 * B1)

```

一般形式的交点只能说明两条线不相互平行，并且将在某一点相交。它并不保证交点在两条线段上。

以下图表显示了交点和给定线段的两种可能结果。在左图中，交点不在两条线段之间，在这种情况下，两条线段互不相交。在右侧图中，点在两条线段之间，因此这两条线段相互相交：

![确定两条线段是否相交](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_18.jpg)

因此，我们需要另一个名为`isInBetween`的函数来确定提供的值是否在开始和结束值之间。然后我们使用这个函数来检查方程的交点是否在我们正在检查的两条线段之间。

在获得线条相交的结果后，我们绘制粗线以指示那些相交的线条。

# 制作解开谜题游戏

现在我们已经创建了一个交互画布，我们可以拖动圆圈和连接圆圈的线条与其他线条相交。我们来玩个游戏吧？有一些预定义的圆圈和线条，我们的目标是拖动圆圈，使没有线条与其他线条相交。这就是所谓的**解开谜题游戏**。

# 行动时间：在画布中制作解开谜题游戏

让我们在我们的线交点代码中添加游戏逻辑：

1.  在文本编辑器中打开`index.html`文件。

1.  首先，让我们将标题设置为以下内容：

```js
<header>
<h1>Untangle Puzzle Game in Canvas</h1>
</header>

```

1.  我们还需要向玩家显示当前级别和进度。在画布元素之后添加以下代码：

<p>谜题<span id="level">0</span>，完成度：<span id="progress">0</span>%</p>

1.  打开`html5games.untangle.js` JavaScript 文件以添加游戏逻辑。

1.  添加变量 info，`untangleGame`。它存储游戏的当前级别：

```js
var untangleGame = {
circles: [],
thinLineThickness: 1,
boldLineThickness: 5,
lines: [],
currentLevel: 0
};

```

1.  我们需要一些预定义的级别数据供玩家玩。这是一个定义圆圈放置位置以及它们最初如何连接到彼此的数据集合。将以下级别数据代码添加到`untangleGame`对象中：

```js
untangleGame.levels =
[
{
"level" : 0,
"circles" : [{"x" : 400, "y" : 156},
{"x" : 381, "y" : 241},
{"x" : 84, "y" : 233},
{"x" : 88, "y" : 73}],
"relationship" : {
"0" : {"connectedPoints" : [1,2]},
"1" : {"connectedPoints" : [0,3]},
"2" : {"connectedPoints" : [0,3]},
"3" : {"connectedPoints" : [1,2]}
}
},
{
"level" : 1,
"circles" : [{"x" : 401, "y" : 73},
{"x" : 400, "y" : 240},
{"x" : 88, "y" : 241},
{"x" : 84, "y" : 72}],
"relationship" : {
"0" : {"connectedPoints" : [1,2,3]},
"1" : {"connectedPoints" : [0,2,3]},
"2" : {"connectedPoints" : [0,1,3]},
"3" : {"connectedPoints" : [0,1,2]}
}
},
{
"level" : 2,
"circles" : [{"x" : 92, "y" : 85},
{"x" : 253, "y" : 13},
{"x" : 393, "y" : 86},
{"x" : 390, "y" : 214},
{"x" : 248, "y" : 275},
{"x" : 95, "y" : 216}],
"relationship" : {
"0" : {"connectedPoints" : [2,3,4]},
"1" : {"connectedPoints" : [3,5]},
"2" : {"connectedPoints" : [0,4,5]},
"3" : {"connectedPoints" : [0,1,5]},
"4" : {"connectedPoints" : [0,2]},
"5" : {"connectedPoints" : [1,2,3]}
}
}
];

```

1.  在每个级别开始时，我们需要设置初始级别数据。为了帮助使代码更易读，我们创建一个函数。在 JavaScript 文件的末尾添加以下代码：

```js
function setupCurrentLevel() {
untangleGame.circles = [];
var level = untangleGame.levels[untangleGame.currentLevel];
for (var i=0; i<level.circles.length; i++) {
untangleGame.circles.push(new Point(level.circles[i].x, level. circles[i].y, 10));
}
// setup line data after setup the circles.
connectCircles();
updateLineIntersection();
}

```

1.  这是一个有几个级别的游戏。我们需要检查玩家是否解决了当前级别的谜题并跳转到下一个谜题。在文件末尾添加以下函数：

```js
function checkLevelCompleteness() {
if ($("#progress").html() == "100") {
if (untangleGame.currentLevel+1 < untangleGame.levels.length)
untangleGame.currentLevel++;
setupCurrentLevel();
}
}

```

1.  我们更新原始的鼠标抬起事件处理程序以检查玩家是否完成了级别：

```js
$("#game").mouseup(function(e) {
untangleGame.targetCircle = undefined;
// on every mouse up, check if the untangle puzzle is solved.
checkLevelCompleteness();
});

```

1.  我们将根据级别数据绘制圆圈，而不是随机绘制它们。因此，我们删除 jQuery`ready`函数中的圆圈绘制代码。

1.  在我们删除 jQuery`ready`函数中的圆圈绘制代码的地方，我们添加以下代码来设置游戏循环使用的圆圈级别数据：

setupCurrentLevel();

1.  接下来，我们更新`connectCircles`函数以根据级别数据连接圆圈：

```js
function connectCircles()
{
// setup all lines based on the circles relationship
var level = untangleGame.levels[untangleGame.currentLevel];
untangleGame.lines.length = 0;
for (var i in level.relationship) {
var connectedPoints = level.relationship[i].connectedPoints;
var startPoint = untangleGame.circles[i];
for (var j in connectedPoints) {
var endPoint = untangleGame.circles[connectedPoints[j]];
untangleGame.lines.push(new Line(startPoint, endPoint));
}
}
}

```

1.  我们需要另一个函数来更新游戏进度。将以下函数添加到代码中：

```js
function updateLevelProgress()
{
// check the untangle progress of the level
var progress = 0;
for (var i=0;i<untangleGame.lines.length;i++) {
if (untangleGame.lines[i].thickness == untangleGame. thinLineThickness) {
progress++;
}
}
var progressPercentage = Math.floor(progress/untangleGame.lines. length*100);
$("#progress").html(progressPercentage);
// display the current level
$("#level").html(untangleGame.currentLevel);
}

```

1.  最后，我们需要在以下鼠标移动事件处理程序中更新级别进度。

```js
$("#game").mousemove(function(e) {
…
connectCircles();
updateLineIntersection();
updateLevelProgress();
…
});

```

1.  保存所有文件并在浏览器中测试游戏。我们可以拖动圆圈，线条的粗细将指示它是否与其他线条相交。在鼠标拖动期间，当检测到更多或更少的线交点时，级别完成百分比应该发生变化。如果我们解决了谜题，也就是说没有线条相交，游戏将跳转到下一个级别。当游戏达到最后一个级别时，它将继续显示最后一个级别。这是因为我们还没有添加游戏结束画面。

![行动时间：在画布中制作解开谜题游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_04_19.jpg)

## 刚刚发生了什么？

我们已经在我们的画布中添加了游戏逻辑，以便我们可以玩我们在整章中创建的圆圈拖动代码。

让我们回顾一下我们添加到`untangleGame`对象的变量。以下表格列出了这些变量的描述和用法：

| 变量 | 描述 |
| --- | --- |
| circleRadius | 所有绘制圆圈的半径设置。 |
| thinLineThickness | 绘制细线时的线条粗细。 |
| boldLineThickness | 绘制粗线时的线条粗细。 |
| circles | 一个数组，用来存储画布中所有绘制的圆圈。 |
| lines | 一个数组，用来存储画布中所有绘制的线条。 |
| targetCircle | 跟踪我们正在拖动的圆圈。 |
| levels | 以 JSON 格式存储每个级别的所有初始数据。 |
| currentLevel | 一个数字，用来记录当前级别。 |

## 定义级别数据

在每个级别中，我们有解谜游戏中圆圈的初始位置。级别数据被设计为对象数组。每个对象包含每个级别的数据。在每个级别数据中，有三个属性：级别编号、圆圈和连接圆圈的线。下表显示了每个级别数据中的属性：

| 级别属性 | 定义 | 讨论 |
| --- | --- | --- |
| level | 对象的级别编号。 | 这是每个级别对象中的一个数字，让我们轻松地知道我们在哪个级别。 |
| circles | 一个数组，用来存储级别中圆圈的位置。 | 这定义了当级别设置时圆圈的初始位置。 |
| relationships | 一个定义哪些圆圈连接到彼此的关系数组。 | 每个级别中有一些连接圆圈的线。我们设计线条连接，使每个级别都有解决方案。线条关系定义了哪个圆圈连接到哪个圆圈。例如，以下代码表示圆圈 1 连接到圆圈 2：{"connectedPoints" : [1,2]} |

在每个级别数据都以我们自定义的结构定义好之后

## 确定升级

当没有线条相互交叉时，级别完成。我们遍历每条线，并查看有多少条线是细线。细线意味着它们没有与其他线条相交。我们可以使用细线与所有线条的比率来得到级别完成的百分比：

```js
var progress = 0;
for (var i in untangleGame.lines) {
if (untangleGame.lines[i].thickness == untangleGame. thinLineThickness) {
progress++;
}
}
var progressPercentage = Math.floor(progress/untangleGame.lines.length * 100);

```

当进度达到 100%时，我们可以简单地确定级别已经完成：

```js
if ($("#progress").html() == "100") {
// level complete, level up code
}

```

## 显示当前级别和完成进度

在画布游戏下方有一句话描述当前级别的状态和进度。它用于向玩家显示游戏状态，让他们知道他们在游戏中取得了进展：

```js
<p>Puzzle <span id="level">0</span>, Completeness: <span id="progress">0</span>%</p>

```

我们使用了我们在第二章中讨论的 jQuery HTML 函数，*开始 DOM 游戏开发*，来更新完成进度。

```js
$("#progress").html(progressPercentage);

```

## Have a go hero

在示例解谜游戏中，我们只定义了三个级别。只有三个级别是不够有趣的。要不要给游戏添加更多级别？如果你想不出级别，可以在互联网上搜索类似的解谜游戏，获取一些级别设计的灵感。

# 总结

在本章中，我们学到了很多关于绘制形状和与新的 HTML5 画布元素和绘图 API 交互的知识。

具体来说，我们涵盖了：

+   在画布中绘制不同的路径和形状，包括圆圈、弧线和直线。

+   添加鼠标事件和与画布中绘制的路径的交互。

+   在画布中拖动绘制的路径。

+   通过数学公式来检查线条的交叉。

+   创建一个解谜游戏，玩家需要拖动圆圈，使连接线不相交。

现在我们已经学习了关于画布和绘图 API 中的基本绘图功能，可以使用它们在画布中创建一个解谜游戏。我们准备学习一些高级的画布绘图技术。在下一章中，我们将使用更多的画布绘图 API 来增强我们的解谜游戏，比如绘制文本、绘制图像和绘制渐变。


# 第五章：构建 Canvas 游戏大师班

> 在上一章中，我们探索了一些基本的画布上下文绘图 API，并创建了一个名为 Untangle 的游戏。在本章中，我们将通过使用其他一些上下文绘图 API 来增强游戏。

在本章中，我们将：

+   用渐变颜色填充我们的游戏对象

+   在画布中使用自定义网络字体填充文本

+   在 Canvas 中绘制图像

+   动画精灵表图像

+   并构建多个画布层

以下截图是我们将通过本章构建的最终结果的预览。它是一个基于 Canvas 的 Untangle 游戏，带有动画游戏指南和一些细微的细节：

![构建 Canvas 游戏大师班](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_01.jpg)

所以让我们开始吧...

# 用渐变颜色填充形状

在上一章中，我们介绍了填充纯色。Canvas 在填充形状时可以做得更多。我们可以用线性渐变和径向渐变填充形状。

# 行动时间 给 Untangle 游戏绘制渐变颜色背景

让我们改进一下我们现在的纯黑色背景。如何从上到下绘制一个渐变呢？

1.  我们将使用上一章中创建的 Untangle 游戏作为起点。在文本编辑器中打开`html5games.untangle.js` JavaScript 文件。

1.  在`gameloop`函数中清除画布后，添加以下代码以绘制**渐变**背景：

```js
var bg_gradient = ctx.createLinearGradient(0,0,0,ctx.canvas.height);
bg_gradient.addColorStop(0, "#000000");
bg_gradient.addColorStop(1, "#555555");
ctx.fillStyle = bg_gradient;
ctx.fillRect(0,0,ctx.canvas.width,ctx.canvas.height);

```

1.  保存文件并在浏览器中预览`index.html`。背景应该是一个线性渐变，顶部是黑色，逐渐变成底部的灰色。

![行动时间 给 Untangle 游戏绘制渐变颜色背景](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_02.jpg)

## 刚刚发生了什么？

我们刚刚用**线性渐变**颜色填充了一个矩形。要填充线性渐变颜色，我们只需要设置渐变的起点和终点。然后在它们之间添加几个颜色停止。

以下是我们如何使用线性渐变函数的方式：

```js
createLinearGradient(x1, y1, x2, y2);

```

| 参数 | 定义 |
| --- | --- |
| x1 | 渐变的起点。 |
| y1 |   |
| x2 | 渐变的终点。 |
| y2 |   |

## 在渐变颜色中添加颜色停止

仅仅拥有起点和终点是不够的。我们还需要定义我们使用的颜色以及它如何应用到渐变中。这在渐变中被称为**颜色停止**。我们可以使用以下`gradient`函数向渐变中添加一个颜色停止：

```js
addColorStop(position, color);

```

| 参数 | 定义 | 讨论 |
| --- | --- | --- |
| 位置 | 0 到 1 之间的浮点数。 | 位置 0 表示颜色停在起点，1 表示它停在终点。0 到 1 之间的任何数字表示它停在起点和终点之间。例如，0.5 表示一半，0.33 表示离起点 30%。 |
| 颜色 | 那个颜色停止的颜色样式。 | 颜色样式与 CSS 颜色样式的语法相同。我们可以使用 HEX 表达式，如#FFDDAA。或其他颜色样式，如 RGBA 颜色名称。 |

下面的截图显示了线性渐变设置和结果绘制之间的并排比较。起点和终点定义了渐变的范围和角度。颜色停止定义了颜色在渐变范围之间的混合方式：

![在渐变颜色中添加颜色停止](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_03.jpg)

### 提示

**添加带不透明度的颜色停止**

我们可以使用 RGBA 函数为颜色停止设置不透明度值。以下代码告诉渐变从红色开始，不透明度为一半：

`gradient.addColorStop(0, "rgba(255, 0, 0, 0.5)")`;

## 填充径向渐变颜色

Canvas 绘图 API 中有两种渐变类型。我们刚刚使用的是线性渐变。另一种是**径向渐变**。径向渐变从一个圆到另一个圆填充渐变。

# 行动时间 用径向渐变颜色填充圆

想象一下，我们现在将我们拖动的圆填充为径向渐变。我们将把实心黄色圆改为白黄渐变：

1.  打开`html5game.untangle.js` JavaScript 文件。我们将修改用于在游戏中绘制圆的代码。

1.  在使用`arc`函数绘制圆形路径后，填充之前，我们将原始的实色样式设置替换为以下径向渐变颜色：

```js
function drawCircle(ctx, x, y) {
// prepare the radial gradients fill style
var circle_gradient = ctx.createRadialGradient(x-3,y- 3,1,x,y,untangleGame.circleRadius);
circle_gradient.addColorStop(0, "#fff");
circle_gradient.addColorStop(1, "#cc0");
ctx.fillStyle = circle_gradient;
// draw the path
ctx.beginPath();
ctx.arc(x, y, untangleGame.circleRadius, 0, Math.PI*2, true);
ctx.closePath();
// actually fill the circle path
ctx.fill();
}

```

1.  保存修改后的文件，并在 Web 浏览器中预览`index.html`。现在圆形填充了径向渐变颜色。

在下面的屏幕截图中，我将绘图放大到 200％，以更好地演示圆形中的径向渐变：

![行动时间 填充圆形与径向渐变颜色](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_04.jpg)

## 刚刚发生了什么？

我们通过填充径向渐变使拖动圆看起来更真实。

以下是我们创建径向渐变的方法：

```js
createRadialGradient(x1, y1, r1, x2, y2, r2);

```

| 参数 | 定义 |
| --- | --- |
| x1, y1 | 画布坐标中起始圆的中心 x 和 y。 |
| r1 | 起始圆的半径。 |
| x2, y2 | 画布坐标中结束圆的中心 x 和 y。 |
| r2 | 结束圆的半径。 |

下面的屏幕截图显示了径向渐变设置和画布中的最终结果之间的并排比较：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_05.jpg)

径向渐变将颜色从起始圆到结束圆进行混合。在这个渐变圆中，起始圆是中心的小圆，结束圆是最外面的圆。有三个颜色停止点。白色在起始和结束圆处停止；另一种深色在离起始圆 90％的地方停止。

## 尝试一下英雄填充渐变

我们向渐变中添加颜色停止点来定义颜色的混合方式。如果我们忘记向渐变中添加任何颜色停止点并填充一个矩形会发生什么？如果我们只定义一个颜色停止点会怎样？尝试实验颜色停止点设置。

在径向渐变示例中，小的起始圆在较大的结束圆内。如果起始圆比结束圆大会发生什么？如果起始圆不在结束圆内会怎么样？也就是说，如果两个圆不重叠会发生什么？

# 在画布中绘制文本

现在想象一下，我们想直接在画布内显示进度级别。画布为我们提供了在画布内绘制文本的方法。

# 行动时间 在画布元素内显示进度级别文本

1.  我们将继续使用我们的 Untangle 游戏。在文本编辑器中打开`html5games.untangle.js` JavaScript 文件。

1.  首先，让我们将级别进度百分比设为全局变量，这样我们可以在不同的地方使用它：

```js
var untangleGame = {
circles: [],
thinLineThickness: 1,
boldLineThickness: 5,
lines: [],
currentLevel: 0,
progressPercentage: 0
};

```

1.  在`gameloop`函数中的画布绘制代码之后添加以下代码：

```js
// draw the title text
ctx.font = "26px Arial";
ctx.textAlign = "center";
ctx.fillStyle = "#ffffff";
ctx.fillText("Untangle Game",ctx.canvas.width/2,50);
// draw the level progress text
ctx.textAlign = "left";
ctx.textBaseline = "bottom";
ctx.fillText("Puzzle "+untangleGame.currentLevel+", Completeness: " + untangleGame.progressPercentage + "%", 20,ctx.canvas.height-5);

```

1.  保存文件并在 Web 浏览器中预览`index.html`。我们会看到文本现在绘制在画布内。

![行动时间 在画布元素内显示进度级别文本](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_06.jpg)

## 刚刚发生了什么？

我们刚刚在基于画布的游戏中绘制了标题和级别进度文本。我们使用**fillText**函数在画布中绘制文本。以下表格显示了我们如何使用该函数：

```js
fillText(string, x, y);

```

| 参数 | 定义 |
| --- | --- |
| string | 我们要绘制的文本。 |
| x | 文本绘制的 x 坐标。 |
| y | 文本绘制的 y 坐标。 |

这是绘制文本的基本设置。还有几个绘图上下文属性需要设置文本绘制。

| 上下文属性 | 定义 | 讨论 |
| --- | --- | --- |
| `context.font` | 文本的字体样式。 | 它与我们在 CSS 中声明字体样式所使用的语法相同。例如，以下代码将字体样式设置为 20 像素的 Arial 粗体：ctx.font = "bold 20px Arial"; |
| `context.textAlign` | 文本对齐。 | **对齐**定义了文本的对齐方式。可以是以下值之一：startendleftrightcenter 例如，如果我们要将文本放在画布的右边缘。使用`left`对齐意味着我们需要计算文本宽度以知道文本的 x 坐标。在这种情况下使用右对齐，我们只需要将 x 位置直接设置为画布宽度。文本将自动放置在画布的右边缘。 |
| `context.textBaseline` | 文本基线。 | 以下列出了**textBaseline**的常见值：topmiddlebottomalphabet 与文本对齐类似，当我们想要将文本放在画布底部时，`bottom` **基线**是有用的。`fillText`函数的 y 位置是基于文本的底部基线而不是顶部。`alphabet`基线根据小写字母表对齐 y 位置。以下截图显示了我们使用**alphabet**基线的文本绘制。 |

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_07.jpg)

### 注意

请注意，画布中的文本绘制被视为位图图像数据。这意味着访问者无法选择文本；搜索引擎无法索引文本；我们无法搜索它们。因此，我们应该仔细考虑是否要在画布中绘制文本，还是直接将它们放在 DOM 中。

## 快速测验在画布中绘制文本

1.  如果我们要在画布的右下角附近绘制文本，哪种对齐和基线设置更好？

a. 左对齐，底部基线。

b. 居中对齐，字母基线。

c. 右对齐，底部基线。

d. 居中对齐，中间基线。

1.  我们将使用最新的开放网络标准制作一个具有翻页效果的逼真书籍。以下哪种设置更好？

a. 在画布中绘制逼真的书籍，包括所有文本和翻页效果。

b. 将所有文本和内容放在 DOM 中，并在画布中绘制逼真的翻页效果。

## 在画布中使用嵌入的 Web 字体

在上一章的记忆匹配游戏中，我们使用了自定义字体。自定义字体嵌入也适用于画布。让我们在画布中的 Untangle 游戏中进行一个绘制自定义字体的实验。

# 执行嵌入 Google Web 字体到画布元素的时间

让我们用手写风格字体绘制画布文本：

1.  首先，转到 Google 字体目录，选择手写风格字体。我使用了字体**Rock Salt**，你可以从以下 URL 获取：

```js
http://code.google.com/webfonts/family?family=Rock+Salt&subset=latin#code.

```

1.  Google 字体目录提供了一个 CSS 链接代码，我们可以将其添加到游戏中以嵌入字体。将以下 CSS 链接添加到`index.html`的头部：

```js
<link href='http://fonts.googleapis.com/css?family=Rock+Salt' rel='stylesheet' type='text/css'>

```

1.  接下来要做的是使用字体。我们打开`html5games.untangle.js` JavaScript 文件，并将上下文`font`属性修改为以下内容：

```js
ctx.font = "26px 'Rock Salt'";

```

1.  现在是时候在网络浏览器中打开我们的游戏来测试结果了。现在在画布中绘制的文本使用了我们在 Google 字体目录中选择的字体。

![执行嵌入 Google Web 字体到画布元素的时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_08.jpg)

## 刚刚发生了什么？

我们刚刚选择了一个网络字体，并将其嵌入到画布中绘制文本时。这表明我们可以像其他 DOM 元素一样为画布中填充的文本设置字体系列。

### 提示

有时，不同字体系列的文本宽度会有所不同，尽管它们具有相同的字数。在这种情况下，我们可以使用`measureText`函数来获取我们绘制的文本的宽度。以下链接到 Mozilla 开发者网络解释了我们如何使用该函数：

[`developer.mozilla.org/en/Drawing_text_using_a_canvas#measureText()`](http://https://developer.mozilla.org/en/Drawing_text_using_a_canvas#measureText())

# 在画布中绘制图像

我们已经在画布内绘制了一些文本。那么绘制图像呢？是的。在画布中绘制图像和图像处理是画布具有的一个重要功能。

# 执行添加图形到游戏的时间

我们将在游戏中绘制一个黑板背景：

1.  从代码示例包或以下 URL 下载图形文件。图形文件包括我们在本章中需要的所有图形：

```js
http://gamedesign.cc/html5games/1260_05_example_graphics.zip

```

1.  将新下载的图形文件放入名为`images`的文件夹中。

1.  我们将加载一幅图像，加载意味着可能需要一段时间直到图像加载完成。理想情况下，我们不应该在所有游戏资源加载完成之前开始游戏。在这种情况下，我们可以准备一个带有加载文字的启动画面，让玩家知道游戏将在稍后开始。在 jQuery 的`ready`函数中清除画布上下文后，添加以下代码：

```js
// draw a splash screen when loading the game background
// draw gradients background
var bg_gradient = ctx.createLinearGradient(0,0,0,ctx.canvas.height);
bg_gradient.addColorStop(0, "#cccccc");
bg_gradient.addColorStop(1, "#efefef");
ctx.fillStyle = bg_gradient;
ctx.fillRect(0, 0, ctx.canvas.width, ctx.canvas.height);
// draw the loading text
ctx.font = "34px 'Rock Salt'";
ctx.textAlign = "center";
ctx.fillStyle = "#333333";
ctx.fillText("loading...",ctx.canvas.width/2,canvas.height/2);

```

1.  现在是真正加载图像的时候了。我们刚刚下载了一个名为`board.png`的图形文件。这是一个我们将绘制到画布上的黑板图形背景。在我们刚刚添加的代码之后添加以下代码：

```js
// load the background image
untangleGame.background = new Image();
untangleGame.background.onload = function() {
// setup an interval to loop the game loop
setInterval(gameloop, 30);
}
untangleGame.background.onerror = function() {
console.log("Error loading the image.");
}
untangleGame.background.src = "images/board.png";

```

1.  在`gameloop`函数中，我们在清除上下文并在绘制任何其他内容之前将图像绘制到画布中。由于图像加载需要时间，我们还需要确保在绘制之前加载它：

```js
// draw the image background
ctx.drawImage(untangleGame.background, 0, 0);

```

1.  我们设置了一个`levels`数组来存储包括初始圆位置在内的级别数据。现在一些圆与背景图像的边框重叠，所以我们可能需要改变圆的位置。使用以下新值更新级别 2 的圆数组：

```js
"circles" : [{"x" : 192, "y" : 155},
{"x" : 353, "y" : 109},
{"x" : 493, "y" : 156},
{"x" : 490, "y" : 236},
{"x" : 348, "y" : 276},
{"x" : 195, "y" : 228}],

```

1.  我们还需要调整级别进度文本的位置。修改`fill text`函数调用为以下代码，使用不同的位置值：

```js
ctx.fillText("Puzzle "+untangleGame.currentLevel+", Completeness: " + untangleGame.progressPercentage + "%", 60, ctx.canvas.height- 80);

```

1.  接下来，我们不希望为画布设置背景颜色，因为我们有一个带有透明边框的 PNG 背景。打开`untangle.css`文件并删除画布中的背景属性。

1.  现在保存所有文件并在 Web 浏览器中打开`index.html`。背景应该在那里，手写字体应该与我们的黑板主题相匹配。

![执行操作添加图形到游戏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_09.jpg)

## 刚刚发生了什么？

我们刚刚在画布元素内绘制了一幅图像。

在画布上绘制图像有两种常见的方法。我们可以引用现有的`img`标签，也可以在 JavaScript 中动态加载图像。

这是我们在画布中引用现有图像标签的方式。

假设我们在 HTML 中有以下`img`标签：

```js
<img id="board" src="img/board.png">

```

我们可以使用以下 JavaScript 代码在画布中绘制图像：

```js
var img = document.getElementById('board');
context.drawImage(img, x, y);

```

这是另一个加载图像的代码片段，而不将`img`标签附加到 DOM 中。如果我们在 JavaScript 中加载图像，我们需要确保图像在绘制到画布上之前已加载。因此，我们在图像的`onload`事件之后绘制图像：

```js
var board = new Image();
board.onload = function() {
context.drawImage(board, x, y);
images, inside canvasimages, inside canvasdrawing}
board.src = "images/board.png";

```

### 提示

**设置 onload 事件处理程序和分配图像 src 时的顺序很重要**

当我们将`src`属性分配给图像并且如果图像被浏览器缓存，一些浏览器会立即触发`onload`事件。如果我们在分配`src`属性后放置`onload`事件处理程序，我们可能会错过它，因为它是在我们设置事件处理程序之前触发的。

在我们的示例中，我们使用了后一种方法。我们创建了一个 Image 对象并加载了背景。当图像加载完成时，我们启动游戏循环，从而开始游戏。

加载图像时我们还应该处理的另一个事件是`onerror`事件。当我们访问额外的网络数据时，这是特别有用的。我们有以下代码片段来检查我们示例中的错误：

```js
untangleGame.background.onerror = function() {
console.log("Error loading the image.");
}

```

## 试一试

现在加载错误只在控制台中显示消息。玩家通常不会查看控制台。设计一个警报对话框或其他方法来告诉玩家游戏未能加载游戏资源，如何？

## 使用 drawImage 函数

有三种在画布中绘制图像的行为。我们可以在给定的坐标上绘制图像而不进行任何修改，我们还可以在给定的坐标上绘制具有缩放因子的图像，或者我们甚至可以裁剪图像并仅绘制裁剪区域。

`drawImage`函数接受几个参数：

```js
drawImage(image, x, y);

```

| 参数 | 定义 | 讨论 |
| --- | --- | --- |
| 图像 | 我们要绘制的图像引用。 | 我们可以通过获取现有的`img`元素或创建 JavaScript`Image`对象来获取图像引用。 |
| x | 在画布坐标中放置图像的 x 位置。 | x 和 y 坐标是我们放置图像的位置，相对于其左上角。 |
| y | 在画布坐标中放置图像的 y 位置。 |   |

```js
drawImage(image, x, y, width, height);

```

| 参数 | 定义 | 讨论 |
| --- | --- | --- |
| 图像 | 我们要绘制的图像引用。 | 我们可以通过获取现有的`img`元素或创建 JavaScript`Image`对象来获取图像引用。 |
| x | 在画布坐标中放置图像的 x 位置。 | x 和 y 坐标是我们放置图像的位置，相对于其左上角。 |
| y | 在画布坐标中放置图像的 y 位置。 |   |
| 宽度 | 最终绘制图像的宽度。 | 如果宽度和高度与原始图像不同，我们会对图像应用比例。 |
| 高度 | 最终绘制图像的高度。 |   |

```js
drawImage(image, sx, sy, sWidth, sHeight, dx, dy, width, height);

```

| 参数 | 定义 | 讨论 |
| --- | --- | --- |
| 图像 | 我们要绘制的图像引用。 | 我们可以通过获取现有的`img`元素或创建 JavaScript`Image`对象来获取图像引用。 |
| sx | 裁剪区域左上角的 x 坐标。 | 裁剪 x、y、宽度、高度一起定义了一个矩形裁剪区域。给定的图像将被此矩形裁剪。 |
| sy | 裁剪区域左上角的 y 坐标。 |   |
| sWidth | 裁剪区域的宽度。 |   |
| sHeight | 裁剪区域的高度。 |   |
| 参数 | 定义 | 讨论 |
| dx | 在画布坐标中放置图像的 x 位置。 | x 和 y 坐标是我们放置图像的位置，相对于其左上角。 |
| dy | 在画布坐标中放置图像的 y 位置。 |   |
| 宽度 | 最终绘制图像的宽度。 | 如果宽度和高度与裁剪尺寸不同，我们会对裁剪后的图像应用比例。 |
| 高度 | 最终绘制图像的高度。 |   |

## 试试看英雄 优化背景图像

在示例中，我们在每次调用`gameloop`函数时将黑板图像作为背景绘制。由于我们的背景是静态的，不会随时间变化，所以一遍又一遍地清除并重新绘制会浪费 CPU 资源。我们如何优化这个性能问题？

## 装饰基于画布的游戏

我们已经用渐变和图像增强了画布游戏。在继续之前，让我们装饰一下画布游戏的网页。

# 行动时间为游戏添加 CSS 样式和图像装饰

我们将建立一个居中对齐的布局，带有一个游戏标题：

1.  我们从 Google 字体目录嵌入了另一种字体来为正常的正文文本设置样式。在`index.html`的`head`中添加以下 CSS 链接：

```js
<link href='http://fonts.googleapis.com/css?family=Josefin+Sans:600' rel='stylesheet' type='text/css'>

```

1.  使用一个分组 DOM 元素来为布局设置样式更容易。我们将所有元素放入一个带有`id`页面的部分中：

```js
<section id="page">
...
</section>

```

1.  让我们对页面布局应用 CSS。用以下代码替换`untangle.css`文件中的现有内容：

```js
html, body {
background: url(../images/title_bg.png) 50% 0 no-repeat, url(../ images/bg_repeat.png) 50% 0 repeat-y #889ba7;
margin: 0;
font-family: 'Josefin Sans', arial, serif;
color: #111;
}
#game{
position:relative;
}
#page {
width: 821px;
min-height: 800px;
margin: 0 auto;
padding: 0;
text-align: center;
text-shadow: 0 1px 5px rgba(60,60,60,.6);
}
header {
height: 88px;
padding-top: 36px;
margin-bottom: 50px;
font-family: "Rock Salt", Arial, sans-serif;
font-size: 14px;
text-shadow: 0 1px 0 rgba(200,200,200,.5);
color: #121;
}

```

1.  现在我们在带上有标题的带子中有了标题文本。在画布中再次显示标题似乎是多余的。让我们删除以下绘制标题的代码行：

```js
ctx.fillText("Untangle Game",ctx.canvas.width/2,50);

```

1.  是时候保存所有文件并在 Web 浏览器中预览了。我们应该看到一个居中对齐的标题带和精心设计的布局。以下截图显示了结果：

![行动时间为游戏添加 CSS 样式和图像装饰](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_10.jpg)

## 刚刚发生了什么？

我们刚刚装饰了包含基于画布的游戏的网页。虽然我们的游戏是基于画布绘制的，但这并不限制我们用图形和 CSS 样式装饰整个网页。

### 注意

画布元素的默认背景

画布元素的默认背景是透明的。如果我们不设置画布的任何背景 CSS 样式，它将是透明的。当我们的绘图不是矩形时，这是有用的。在这个例子中，纹理布局背景显示在画布区域内。

## 快速测验 设置画布背景

1.  我们如何将画布背景设置为透明？

a. 将背景颜色设置为#ffffff。

b. 什么也不做。默认情况下是透明的。

# 在 canvas 中制作精灵表动画

我们在第三章“在 CSS3 中构建记忆匹配游戏”中首次使用了**精灵表**图像，用于显示一副扑克牌。

# 行动时间 制作游戏指南动画

在 images 文件夹中有一个名为`guide_sprite.png`的图形文件。这是一个包含动画每一步的游戏指南图形。

![行动时间 制作游戏指南动画](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_11.jpg)

让我们用**动画**将这个指南画到我们的游戏中：

1.  在文本编辑器中打开`html5games.untangle.js` JavaScript 文件。

1.  在 jQuery 的`ready`函数中添加以下代码：

```js
// load the guide sprite image
untangleGame.guide = new Image();
untangleGame.guide.onload = function() {
untangleGame.guideReady = true;
// setup timer to switch the display frame of the guide sprite
untangleGame.guideFrame = 0;
setInterval(guideNextFrame, 500);
}
untangleGame.guide.src = "images/guide_sprite.png";

```

1.  我们添加以下函数，以便每 500 米将当前帧移动到下一帧：

```js
function guideNextFrame()
{
untangleGame.guideFrame++;
// there are only 6 frames (0-5) in the guide animation.
// we loop back the frame number to frame 0 after frame 5.
if (untangleGame.guideFrame > 5)
{
untangleGame.guideFrame = 0;
}
}

```

1.  在`gameloop`函数中，我们根据当前帧绘制指南动画。

```js
// draw the guide animation
if (untangleGame.currentLevel == 0 && untangleGame.guideReady)
{
// the dimension of each frame is 80x130.
var nextFrameX = untangleGame.guideFrame * 80;
ctx.drawImage(untangleGame.guide, nextFrameX, 0, 80, 130, 325,
130, 80, 130);
}

```

1.  通过打开`index.html`在 Web 浏览器中观看动画。以下截图演示了游戏指南动画的动画。指南动画将播放并循环，直到玩家升级：

![行动时间 制作游戏指南动画](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_12.jpg)

## 刚刚发生了什么？

在使用`drawImage`上下文函数时，我们可以只绘制图像的一部分区域。

以下截图逐步演示了动画的过程。矩形是裁剪区域。我们使用一个名为`guideFrame`的变量来控制显示哪一帧。每帧的宽度为 80。因此，我们通过将宽度和当前帧数相乘来获得裁剪区域的 x 位置：

```js
var nextFrameX = untangleGame.guideFrame * 80;
ctx.drawImage(untangleGame.guide, nextFrameX, 0, 80, 130, 325, 130, 80, 130);

```

`guideFrame`变量每 500 米通过以下`guideNextFrame`函数进行更新：

```js
function guideNextFrame()
{
untangleGame.guideFrame++;
// there are only 6 frames (0-5) in the guide animation.
// we loop back the frame number to frame 0 after frame 5.
if (untangleGame.guideFrame > 5)
{
untangleGame.guideFrame = 0;
}
}

```

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_13.jpg)

在开发游戏时，制作精灵动画是一种常用的技术。在传统视频游戏中使用精灵动画有一些好处。这些原因可能不适用于网页游戏开发，但我们在使用精灵表动画时有其他好处：

+   所有帧都加载为一个文件，因此一旦精灵文件加载完毕，整个动画就准备就绪。

+   将所有帧放入一个文件中意味着我们可以减少 Web 浏览器向服务器的 HTTP 请求。如果每一帧都是一个文件，那么浏览器会多次请求文件，而现在它只请求一个文件并使用一个 HTTP 请求。

+   将不同的图像放入一个文件中还有助于减少重复文件的页眉、页脚和元数据。

+   将所有帧放入一张图像中意味着我们可以轻松裁剪图像以显示任何帧，而无需复杂的代码来更改图像源。

它通常用于角色动画。以下截图是我在名为邻居的 HTML5 游戏中使用的愤怒猫的**精灵动画**：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_14.jpg)

在这个例子中，我们通过裁剪帧并自行设置定时器来构建精灵表动画。当处理大量动画时，我们可能希望使用一些第三方精灵动画插件或创建自己的画布精灵动画，以更好地重用和管理逻辑代码。

### 注意

**精灵动画**是 HTML5 游戏开发中的重要主题，有许多在线资源讨论这个主题。以下链接是其中一些：

CodeUtopia 的精灵动画教程（[`codeutopia.net/blog/2009/08/21/using-canvas-to-do-bitmap-sprite-animation-in-javascript/`](http://codeutopia.net/blog/2009/08/21/using-canvas-to-do-bitmap-sprite-animation-in-javascript/)）讨论了如何从头开始制作精灵对象并使用它来动画显示精灵。

John Graham 的精灵动画演示（[`www.johnegraham2.com/web-technology/html-5-canvas-tag-sprite-animation-demo/`](http://www.johnegraham2.com/web-technology/html-5-canvas-tag-sprite-animation-demo/)）提供了另一个精灵对象，用于在画布中动画显示精灵。

另一方面，Spritely（[`www.spritely.net/`](http://www.spritely.net/)）提供了在 DOM 元素上使用 CSS 进行精灵动画。当我们想要在不使用画布的情况下动画显示精灵时，这是很有用的。

# 创建多层画布游戏

现在所有的东西都绘制到上下文中，它没有其他状态来区分已绘制的项目。我们可以将画布游戏分成不同的图层，并编写逻辑来控制和绘制每个图层。

# 行动时间将游戏分成四个图层

我们将把 Untangle 游戏分成四个图层：

1.  在`index.htm`中，我们将画布 HTML 更改为以下代码。它包含一个部分内的几个画布：

```js
<section id="layers">
<canvas id="bg" width="768" height="440">
Sorry, your web browser does not support canvas content.
</canvas>
<canvas id="guide" width="768" height="440"></canvas>
<canvas id="game" width="768" height="440"></canvas>
<canvas id="ui" width="768" height="440"></canvas>
</section>

```

1.  我们还需要对画布应用一些样式，使它们重叠在一起，以创建多层效果。此外，我们还需要准备一个`fadeout`类和`dim`类，使目标变得透明。将以下代码添加到`untangle.css`文件中：

```js
#layers {
height: 440px;
position: relative;
margin: 0 auto;
width:768px;
height: 440px;
}
#layers canvas{
left: 50%;
margin-left: -384px;
position: absolute;
}
#guide {
opacity: .7;
}
#guide.fadeout {
opacity: 0;
-webkit-transition: opacity .5s linear;
transition: opacity .5s linear;
}
#ui {
-webkit-transition: opacity .3s linear;
transition: opacity .3s linear;
}
#ui.dim {
opacity: .3;
}

```

1.  在`html5games.untangle.js` JavaScript 文件中，我们修改代码以支持图层功能。首先，我们添加一个数组来存储每个画布的上下文引用：

```js
untangleGame.layers = new Array();

```

1.  然后，我们获取上下文引用并将它们存储在数组中：

```js
// prepare layer 0 (bg)
var canvas_bg = document.getElementById("bg");
untangleGame.layers[0] = canvas_bg.getContext("2d");
// prepare layer 1 (guide)
var canvas_guide = document.getElementById("guide");
untangleGame.layers[1] = canvas_guide.getContext("2d");
// prepare layer 2 (game)
var canvas = document.getElementById("game");
var ctx = canvas.getContext("2d");
untangleGame.layers[2] = ctx;
// prepare layer 3 (ui)
var canvas_ui = document.getElementById("ui");
untangleGame.layers[3] = canvas_ui.getContext("2d");

```

1.  由于现在游戏画布重叠在一起，我们在`game`画布中的鼠标事件监听器不再起作用。我们可以从父`layers` DIV 中监听事件，该 DIV 具有与画布相同的位置和尺寸：

```js
$("#layers").mousedown(function(e)
$("#layers").mousemove(function(e)
$("#layers").mouseup(function(e)

```

1.  我们将绘图部分分成不同的函数，用于不同的图层。在以下的`drawLayerBG`函数中，它只负责绘制背景：

```js
function drawLayerBG()
{
var ctx = untangleGame.layers[0];
clear(ctx);
// draw the image background
ctx.drawImage(untangleGame.background, 0, 0);
}

```

1.  当背景图像加载时，我们绘制背景层。将以下突出显示的代码添加到背景的`onload`事件中：

```js
untangleGame.background.onload = function() {
drawLayerBG();
// setup an interval to loop the game loop
setInterval(gameloop, 30);
}

```

1.  我们将游戏循环分成三个不同的函数，用于指定的图层：

```js
function gameloop() {
drawLayerGuide();
drawLayerGame();
drawLayerUI();
}

```

1.  现在我们将指导线动画放入一个专用画布中，这样我们就可以轻松地应用 CSS 样式来淡出指导线：

```js
function drawLayerGuide()
{
var ctx = untangleGame.layers[1];
clear(ctx);
// draw the guide animation
if (untangleGame.guideReady)
{
// the dimension of each frame is 80x130.
var nextFrameX = untangleGame.guideFrame * 80;
ctx.drawImage(untangleGame.guide, nextFrameX, 0, 80, 130, 325, 130, 80, 130);
}
// fade out the guideline after level 0
if (untangleGame.currentLevel == 1)
{
$("#guide").addClass('fadeout');
}
}

```

1.  以下的`drawLayerGame`保留了我们在游戏中使用的所有绘图代码。大部分代码来自原始的`gameloop`函数：

```js
function drawLayerGame()
{
// get the reference of the canvas element and the drawing context.
var ctx = untangleGame.layers[2];
// draw the game state visually
// clear the canvas before drawing.
clear(ctx);
// draw all remembered line
for(var i=0;i<untangleGame.lines.length;i++) {
var line = untangleGame.lines[i];
var startPoint = line.startPoint;
var endPoint = line.endPoint;
var thickness = line.thickness;
drawLine(ctx, startPoint.x, startPoint.y, endPoint.x, endPoint.y, thickness);
}
// draw all remembered circles
for(var i=0;i<untangleGame.circles.length;i++) {
var circle = untangleGame.circles[i];
drawCircle(ctx, circle.x, circle.y, circle.radius);
}
}

```

1.  级别进度文本现在放置在 UI 层中，并由`drawLayerUI`函数绘制。它使用一个专用层，因此当文本与游戏对象（如圆圈）重叠时，我们可以轻松地降低不透明度：

```js
function drawLayerUI()
multi-layers canvas gamemulti-layers canvas gamefour layers, dividing into{
var ctx = untangleGame.layers[3];
clear(ctx);
// draw the level progress text
ctx.font = "26px 'Rock Salt'";
ctx.fillStyle = "#dddddd";
ctx.textAlign = "left";
ctx.textBaseline = "bottom";
ctx.fillText("Puzzle "+untangleGame.currentLevel+", Completeness: ", 60,ctx.canvas.height-80);
ctx.fillText(untangleGame.progressPercentage+"%",450, ctx.canvas.height-80);
// get all circles, check if the ui overlap with the game objects
var isOverlappedWithCircle = false;
for(var i in untangleGame.circles) {
var point = untangleGame.circles[i];
if (point.y > 310)
{
isOverlappedWithCircle = true;
}
}
if (isOverlappedWithCircle)
{
$("#ui").addClass('dim');
}
else
{
$("#ui").removeClass('dim');
}
}

```

1.  保存所有文件，并在 Web 浏览器中检查我们的大量代码更改。游戏应该显示得好像我们什么都没改变一样。尝试将圆圈拖动到靠近黑板的底部边缘。级别进度文本应该变得不透明。完成第一级时，指导线动画将优雅地淡出。以下截图显示了半透明的级别进度：

![行动时间将游戏分成四个图层](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_15.jpg)

## 刚刚发生了什么？

现在总共有四个画布。每个画布负责一个图层。图层分为背景、游戏指导线、游戏本身和显示级别进度的用户界面。

默认情况下，画布和其他元素一样，是依次排列的。为了重叠所有画布以构建图层效果，我们对它们应用了`absolute`位置。

以下截图显示了我们游戏中现在设置的四个层。默认情况下，后添加的 DOM 位于之前添加的 DOM 之上。因此，`bg`画布位于底部，`ui`位于顶部：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gm-dev-ex-bgd/img/1260_05_16.jpg)

## 将 CSS 技术与画布绘制混合

我们正在创建一个基于画布的游戏，但我们并不局限于只使用画布绘图 API。级别进度信息现在在另一个 ID 为`ui`的画布中。在这个示例中，我们混合了我们在第三章中讨论的 CSS 技术，*在 CSS3 中构建记忆匹配游戏*。

当我们在画布上拖动圆圈时，它们可能会重叠在级别信息上。在绘制 UI 画布层时，我们会检查是否有任何圆圈的坐标过低并且重叠在文本上。然后我们会淡化 UI 画布的 CSS 不透明度，这样就不会分散玩家对圆圈的注意力。

在玩家升级后，我们还会淡出指南动画。这是通过将整个`guide`画布淡出到 CSS 过渡缓和为 0 不透明度来实现的。由于`guide`画布只负责该动画，隐藏该画布不会影响其他元素：

```js
if (untangleGame.currentLevel == 1)
{
$("#guide").addClass('fadeout');
}

```

### 提示

**只清除改变的区域以提高画布性能**

我们可以使用`clear`函数来清除画布上下文的一部分。这将提高性能，因为它避免了每次重新绘制整个画布上下文。这是通过标记自上次绘制以来状态发生变化的上下文的“脏”区域来实现的。

在我们的示例中的指南画布层，我们可以考虑只清除精灵表图像绘制的区域，而不是整个画布。

在简单的画布示例中，我们可能看不到明显的差异，但是当我们有一个包含许多精灵图像动画和复杂形状绘制的复杂画布游戏时，它有助于提高性能。

## 试试吧

当玩家进入第 2 级时，我们会淡出指南。当玩家拖动任何圆圈时，我们如何淡出指南动画？我们怎么做？

# 总结

在本章中，我们学到了很多关于在画布中绘制渐变、文本和图像的知识。

具体来说，我们涵盖了：

+   用线性或径向渐变填充形状

+   用字体嵌入和其他文本样式在画布中填充文本

+   将图像绘制到画布中

+   通过`clipping`函数在绘制图像时对精灵表进行动画处理

+   通过堆叠多个画布元素将游戏分成几个层

+   在基于画布的游戏中混合 CSS 过渡动画

在这本书中我们没有提到的一件事是画布中的位图操作。画布上下文是一个位图数据，我们可以在每个像素上应用操作。例如，我们可以在画布上绘制图像并对图像应用类似于 Photoshop 的滤镜。我们不会在书中涵盖这个内容，因为图像处理是一个高级话题，而且应用可能与游戏开发无关。

在互联网上有一些很好的画布游戏示例。Canvas Demo ([`www.canvasdemos.com/type/games/`](http://www.canvasdemos.com/type/games/))链接了其他网站上最新的画布游戏。Mozilla 的 Game On 2010 画廊([`gaming.mozillalabs.com/games/`](https://gaming.mozillalabs.com/games/))列出了他们游戏开发竞赛的一系列游戏条目。其中一些是用画布制作的。

现在我们已经学会了在画布中构建游戏并为游戏对象制作动画，比如游戏角色，我们准备在下一章为我们的游戏添加音频组件和音效。

我们将在第九章中回到基于画布的游戏，
