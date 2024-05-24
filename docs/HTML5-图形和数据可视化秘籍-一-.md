# HTML5 图形和数据可视化秘籍（一）

> 原文：[`zh.annas-archive.org/md5/6DD5FA08597C1F517B2FC929FBC4EC5A`](https://zh.annas-archive.org/md5/6DD5FA08597C1F517B2FC929FBC4EC5A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

今天，网络和世界越来越多地被数据所定义。随着互联网在九十年代初期以及直到今天的数据革命，越来越多的数据被公开和聚合，从政府机构、公共部门信息、金融信息、数字媒体和新闻、社交媒体到私营部门信息、用户信息等等。随着网络上数据的过载，很容易忽视信息，因为以数据格式阅读和分析要困难得多。这就是我们介入的地方。我们在这本书中的目标是向您打开数据可视化的大门。通过逐步指南，您将从基本的视觉图表创建一直到由 Google 地图和 Google 文档（云端硬盘）驱动的复杂地理位置信息。

HTML5 和 JavaScript 正在引领数据可视化的新路径，并且正在将我们从传统的使用 Adobe Flash 创建客户端图形或服务器端生成图像的方式中移开。随着浏览器的成熟，它们变得比以往任何时候都更有能力和稳定。现在是将图表创建转移到 HTML/JavaScript 的绝佳时机。但您应该从哪里开始，以及创建项目所需的特定图表/地图的最佳方式是什么？

话虽如此，我们在这本书中的目标是快速展示并教授 HTML5/JavaScript 数据可视化时代所需的所有关键技能。我们的目标是帮助您在需要构建自定义图形或图表时做出正确选择，并帮助您在创建自己的图形或使用第三方小/大工具创建图形的方式之间做出正确选择。

尽管这是一本食谱，但我已经非常有条理地按主题组织了它，使它从头到尾都很有趣。因此，我个人建议您坐下来实际从头到尾阅读它，如果您这样做，您将在这个过程中学到关于二维画布 API、如何创建形状、交互和各种图表/图表以及如何在 HTML5 画布中从头开始创建它们的一切。您将学会如何使用和修改第三方工具，使用 Google 可视化 API、Google 地图和 Google 文档。在整本书中，我们将涉及各种数据格式，从基本字符串、外部文件、XML 和 Google 文档到 Twitter 搜索结果。因此，您将在 JavaScript 中获得额外的加载、修改和处理数据的练习。

通过本书，您将在数据可视化、图表、数据策略和 HTML5 画布方面建立坚实的工作基础。

# 本书涵盖内容

第一章 *在画布中绘制形状*，向您介绍了如何使用画布。在创建图表时，我们将花费大部分时间与画布一起工作。在本章中，我们将重点介绍如何使用二维画布 API 了解画布的工作原理以及如何创建自定义形状。

第二章 *画布中的高级绘图*，延续了第一章中的内容，我们通过添加各种功能来掌握画布的技能。我们将使用曲线、图像、文本，甚至像素操作。

第三章 *创建基于笛卡尔坐标系的图表*，展示了我们第一组图表，即基于笛卡尔坐标系的图表。总的来说，这种图表风格相对简单；它为探索数据提供了惊人的创造性方式。在本章中，我们将奠定构建图表的基础，并将继续扩展我们对画布的整体知识。

第四章, *让事物变得曲线*，利用创建非线性图表来表示多维数据的能力。在本章中，我们将创建气泡图、饼图、圆环图、雷达图和树图。

第五章, *走出框框*，进入更加创新、不常用的图表，并重新审视一些旧图表，以将动态数据或更改其布局整合到其中。在本章中，我们将创建一个漏斗图，为我们的图表添加交互性，创建一个递归树图，添加用户交互，并最后创建一个交互式点击计数器。

第六章, *让静态事物活起来*，介绍了 JavaScript 面向对象编程，从头开始创建动画库，添加多层画布，最后创建一个能感知周围环境的图例。这一章将通过首先使一切都变得动态，然后创建一个更面向对象的程序，让我们养成一些新的习惯，这样更容易区分任务并减少我们的代码量。

第七章, *依赖开源领域*，向你介绍了各种库。开源数据可视化社区非常丰富和详细，有很多选择和一些真正令人惊叹的库。每个库都有其优点和缺点。有些是独立的代码，而其他的则依赖于其他平台。我们在本章的目标是展示我们认为是最好、最有创意的在线选项，并学习定制第三方工具并扩展其功能超出其可用文档的新技能。

第八章, *与 Google 图表玩耍*，逐步探讨了 Google 可视化 API。我们将看看创建图表并将其与图表 API 集成的步骤。在这个过程中，我们将创建新的图表，并探索这个库的核心能力。

第九章, *使用 Google 地图*，探讨了 Google 地图上的一些功能，让我们准备好开始使用地图。地图本身并不是数据可视化，但是在我们建立了如何使用地图的基本理解之后，我们将拥有一个非常稳定的背景，使我们能够创建许多集成数据和数据可视化的尖端、酷炫的项目。

第十章, *地图的应用*，更深入地与我们的数据可视化和地图主题联系在一起。如今，最流行的数据可视化方式之一是使用地图。在本章中，我们将探讨如何将数据集成到使用 Google 地图平台的地图中的一些想法。

*附录*，*选择你的图形技术*，将探讨本书未涵盖的其他替代选项。这个附录的目标是设置环境，让你更好地了解其他图表选项。这个附录不在书中，但可以在以下链接免费下载：

[`www.packtpub.com/sites/default/files/downloads/3707OT_Appendix_Final.pdf`](http://www.packtpub.com/sites/default/files/downloads/3707OT_Appendix_Final.pdf)

# 你需要为这本书做好准备

你需要具备一些 HTML 和 JavaScript 或其他类似编程语言的基本背景知识。

# 这本书是为谁准备的

这不是一本初学者的书，而是为想要将他们的技能扩展到图表、画布、实践中的面向对象编程、第三方修改以及整体数据策略和数据可视化的 JavaScript 开发人员准备的。

# 约定

在本书中，您会发现一些区分不同信息类型的文本样式。以下是一些示例以及它们的含义解释。

文本中的代码单词显示如下：“设置我们的`grayStyle`样式对象为默认样式：”

代码块设置如下：

```js
var aGray =  [
    {
      stylers: [{saturation: -100}]
    }
  ];
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```js
map.mapTypes.set('grayStyle', grayStyle);
map.setMapTypeId('grayStyle');
```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，比如菜单或对话框中的单词，会在文本中以这种方式出现：“从左侧菜单中选择**服务**选项：”

### 注意

警告或重要提示会以这种方式出现在框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：在画布中绘制形状

在本章中，我们将涵盖：

+   使用 2D 画布进行图形处理

+   从基本形状开始

+   分层矩形以创建希腊国旗

+   使用路径创建形状

+   创建复杂形状

+   添加更多顶点

+   重叠形状以创建其他形状

# 介绍

本章的主要重点是突破在画布上工作。在创建图表时，我们将花费大部分时间与画布一起工作。

在本章中，我们将掌握使用画布 API 绘制基本形状和样式。本章将是本书其余部分的图形支柱，因此如果在任何阶段您觉得需要复习，可以回到本章。绘制线条可能...嗯，不是很激动人心。有什么比将主题整合到本章作为一个子主题更能使它更加戏剧化呢：创建旗帜！

# 使用 2D 画布进行图形处理

画布是 HTML 的主要和最激动人心的补充。这是行业的热点，所以让我们从那里开始。我们将在后面的章节中再次访问画布。在这个示例中，我们将学习如何使用画布动态绘制，并创建一个彩色圆形数组，每秒更新一次。

![使用 2D 画布进行图形处理](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_01_01.jpg)

## 如何做...

我们将创建两个文件（一个 HTML5 文件和一个 JS 文件）。让我们从创建一个新的 HTML5 文档开始：

1.  第一步是创建一个空的 HTML5 文档：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Canvas Example</title>
  </head>
  <body>
  </body>
</html>
```

### 提示

**下载示例代码**

您可以从您在[`www.PacktPub.com`](http://www.PacktPub.com)的帐户中购买的所有 Packt 图书下载示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)并注册以直接通过电子邮件接收文件。

代码文件也可以在[`02geek.com/books/html5-graphics-and-data-visualization-cookbook.html`](http://02geek.com/books/html5-graphics-and-data-visualization-cookbook.html)上找到。

1.  创建一个新的画布元素。我们给我们的画布元素一个 ID 为`myCanvas`：

```js
  <body>
<canvas id="myCanvas"> </canvas>
  </body>

```

1.  将 JavaScript 文件`01.01.canvas.js`导入 HTML 文档（我们将在第 5 步中创建此文件）：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
 <script src="img/01.01.canvas.js"></script>
    <title>Canvas Example</title>
  </head>

```

1.  添加一个`onLoad`监听器，并在文档加载时触发函数`init`：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta charset="utf-8" />
    <script src="img/01.01.canvas.js"></script>
    <title>Canvas Example</title>
  </head>
  <body onLoad="init();" style="margin:0px">
    <canvas id="myCanvas" />
  </body>
</html>
```

1.  创建`01.01.canvas.js`文件。

1.  在 JavaScript 文件中，创建函数`init`并在其中调用函数`updateCanvas`：

```js
function init(){
  updateCanvas();
}
```

1.  创建函数`updateCanvas`：

```js
function  updateCanvas(){
  //rest of the code in the next steps will go in here
}
```

1.  在`updateCanvas`函数中（在接下来的步骤中，所有代码都将添加到此函数中），创建两个变量，用于存储您所需的宽度和高度。在我们的情况下，我们将获取窗口的宽度：

```js
function  updateCanvas(){
 var width = window.innerWidth;
 var height = 100;
...
```

1.  访问 HTML 文档中的画布层，并更改其宽度和高度：

```js
var myCanvas = document.getElementById("myCanvas");
    myCanvas.width = width;
    myCanvas.height = height;
```

1.  获取画布的 2D 上下文：

```js
var context = myCanvas.getContext("2d");
```

1.  创建一个矩形以填充画布的完整可见区域：

```js
context.fillStyle = "#FCEAB8";
context.fillRect(0,0,width,height);
```

1.  让我们创建一些辅助变量，以帮助我们确定要绘制的元素的颜色、大小和数量：

```js
var circleSize=10;
var gaps= circleSize+10;
var widthCount = parseInt(width/gaps); 
var heightCount = parseInt(height/gaps); 
var aColors=["#43A9D1","#EFA63B","#EF7625","#5E4130"];
var aColorsLength = aColors.length;
```

1.  创建一个嵌套循环，并创建一个随机颜色的圆形网格：

```js
for(var x=0; x<widthCount;x++){
  for(var y=0; y<heightCount;y++){
    context.fillStyle = aColors[parseInt(Math.random()*aColorsLength)];
    context.beginPath();
    context.arc(circleSize+gaps*x,circleSize+ gaps*y, circleSize, 0, Math.PI*2, true); 
    context.closePath();
    context.fill();	
  }
}
}
```

哇！这是很多步骤！如果您按照所有步骤进行操作，当您运行应用程序时，您将在浏览器中找到许多圆形。

## 它是如何工作的...

在我们直接进入此应用程序的 JavaScript 部分之前，我们需要触发`onLoad`事件以调用我们的`init`函数。我们通过将`onLoad`属性添加到我们的 HTML body 标签中来实现这一点：

```js
<body onLoad="init();">
```

让我们分解 JavaScript 部分，并了解这样做的原因。第一步是创建`init`函数：

```js
function init(){
  updateCanvas();
}
```

我们的`init`函数立即调用`updateCanvas`函数。这样做是为了以后可以刷新并再次调用`updateCanvas`。

在`updateCanvas`函数中，我们首先获取浏览器的当前宽度，并为我们的绘图区域设置一个硬编码值的高度：

```js
var width = window.innerWidth;
var height = 100;
```

我们的下一步是使用其 ID 获取我们的画布，然后根据先前的变量设置其新的宽度和高度：

```js
var myCanvas = document.getElementById("myCanvas");
    myCanvas.width = width;
    myCanvas.height = height;
```

是时候开始绘制了。为了做到这一点，我们需要要求我们的画布返回其上下文。有几种类型的上下文，如 2D 和 3D。在我们的情况下，我们将专注于 2D 上下文，如下所示：

```js
var context = myCanvas.getContext("2d");
```

现在我们有了上下文，我们有了开始探索和操纵我们的画布所需的一切。在接下来的几个步骤中，我们通过使用十六进制值设置`fillStyle`颜色来定义画布的背景颜色，并绘制一个适合整个画布区域的矩形：

```js
var context = myCanvas.getContext("2d");
    context.fillStyle = "#FCEAB8";
 context.fillRect(0,0,width,height);

```

`fillRect`方法接受四个参数。前两个是矩形的（x，y）位置，在我们的情况下，我们想从（0,0）开始，后面的参数是我们新矩形的宽度和高度。

让我们画我们的圆。为此，我们需要定义我们圆的半径和圆之间的间距。让我们不间隔圆，创建半径为 10 像素的圆。

```js
var rad=10;
var gaps= rad*2;
```

第一行分配了我们圆的半径，而第二行捕获了我们创建的每个圆的中心之间的间隙，或者在我们的情况下是我们圆的直径。通过将其设置为两倍的半径，我们将我们的圆精确地一个接一个地间隔开。

```js
var widthCount = parseInt(width/gaps); 
var heightCount = parseInt(height/gaps); 
var aColors=["#43A9D1","#EFA63B","#EF7625","#5E4130"];
var aColorsLength = aColors.length;
```

使用我们的新`gaps`变量，我们发现我们可以在画布组件的宽度和高度上创建多少个圆。我们创建一个存储一些圆的颜色选项的数组，并将变量`aColorsLength`设置为`aColors`的长度。我们这样做是为了减少处理时间，因为变量比属性更容易获取，因为我们将在我们的`for`循环中多次调用这个元素：

```js
for(var x=0; x<widthCount;x++){
 for(var y=0; y<heightCount;y++){
    context.fillStyle = aColors[parseInt(Math.random()*aColorsLength)];
    context.beginPath();
    context.arc(rad+gaps*x,rad+ gaps*y, rad, 0, Math.PI*2, true); 
    context.closePath();
    context.fill();
  }
}
```

我们嵌套的`for`循环使我们能够创建我们的圆到画布的宽度和高度。第一个`for`循环专注于升级宽度值，而第二个`for`循环负责遍历每一列。

```js
context.fillStyle = aColors[parseInt(Math.random()*aColorsLength)];
```

使用`Math.random`，我们随机从`aColors`中选择一种颜色，用作我们新圆的颜色。

```js
context.beginPath();
context.arc(rad+gaps*x,rad+ gaps*y, rad, 0, Math.PI*2, true); 
context.closePath();
```

在上一段代码的第一行和最后一行声明了一个新形状的创建。`beginPath`方法定义了形状的开始，`closePath`方法定义了形状的结束，而`context.arc`创建了实际的圆。`arc`属性采用以下格式的值：

```js
context.arc(x,y,radius,startPoint,endPoint, isCounterClock);
```

`x`和`y`属性定义了弧的中心点（在我们的例子中是一个完整的圆）。在我们的`for`循环中，我们需要添加额外半径的缓冲区，将我们的内容推入屏幕。我们需要这样做，因为如果我们不通过额外的半径将其推到左边和底部，那么我们第一个圆的四分之一将是可见的。

```js
context.fill();
```

最后但并非最不重要的是，我们需要调用`fill()`方法来填充我们新创建的形状的颜色。

## 还有更多...

让我们使我们的元素每秒刷新一次；要做到这一点，我们只需要添加两行。第一行将使用`setInterval`每秒触发对`updateCanvas`函数的新调用。

```js
function init(){
 setInterval(updateCanvas,1000);
  updateCanvas();
} 
```

如果您刷新浏览器，您会发现我们的示例正在工作。如果您努力寻找问题，您将找不到，但我们有一个问题。这不是一个主要问题，而是一个让我们学习画布的另一个有用功能的绝佳机会。在任何阶段，我们都可以清除画布或其部分。让我们在重新绘制之前清除当前画布，而不是在当前画布上绘制。在`updateCanvas`函数中，我们将添加以下突出显示的代码：

```js
var context = myCanvas.getContext("2d"); 
context.clearRect(0,0,width,height);

```

一旦我们得到上下文，我们就可以使用`clearRect`方法清除已经存在的数据。

## 另外

+   *从基本形状开始*食谱

# 从基本形状开始

在这个阶段，您知道如何创建一个新的画布区域，甚至创建一些基本形状。让我们扩展我们的技能，开始创建旗帜。

## 准备工作

嗯，我们不会从最基本的旗帜开始，因为那只是一个绿色的矩形。如果您想学习如何创建绿色旗帜，您不需要我，所以让我们转向稍微复杂一点的旗帜。

如果您已经按照*使用 2D 画布进行绘图*食谱的步骤进行操作，您已经知道如何做了。这个食谱专门为我们帕劳读者和完美的圆弧（也称为圆）而设。

![准备工作](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_01_02.jpg)

在这个食谱中，我们将忽略 HTML 部分，因此，如果您需要了解如何创建带有 ID 的画布，请返回到本章的第一个食谱，并设置您的 HTML 文档。不要忘记使用正确的 ID 创建画布。您也可以下载我们的示例 HTML 文件。

## 如何做...

添加以下代码块：

```js
var cnvPalau = document.getElementById("palau");
  var wid = cnvPalau.width;
  var hei = cnvPalau.height;

  var context = cnvPalau.getContext("2d");
      context.fillStyle = "#4AADD6";
      context.fillRect(0,0,wid,hei);

      context.fillStyle = "#FFDE00";
      context.arc(wid/2.3, hei/2, 40, 0, 2 * Math.PI, false);
      context.fill();
```

就是这样，你刚刚创建了一个完美的圆弧，以及你的第一个具有形状的国旗。

## 它是如何工作的...

在这个阶段，这段代码的大部分内容应该看起来非常熟悉。因此，我将重点放在与本章第一个食谱中使用的代码相比的新行上。

```js
  var wid = cnvPalau.width;
  var hei = cnvPalau.height;
```

在这些行中，我们提取了画布的宽度和高度。我们有两个目标：缩短我们的代码行数，减少不必要的 API 调用次数。由于我们使用它超过一次，我们首先获取这些值并将它们存储在`wid`和`hei`中。

现在我们知道了画布的宽度和高度，是时候画我们的圆圈了。在开始绘制之前，我们将调用`fillStyle`方法来定义在画布中使用的背景颜色，然后我们将创建圆弧，最后触发`fill`方法来完成。

```js
      context.fillStyle = "#FFDE00";
      context.arc(wid/2.3, hei/2, 40, 0, 2 * Math.PI, false);
      context.fill();
```

然后，我们使用`arc`方法创建我们的第一个完美圆圈。重要的是要注意，我们可以在任何时候更改颜色，例如在这种情况下，我们在创建新圆圈之前更改颜色。

让我们更深入地了解一下`arc`方法的工作原理。我们首先通过`x`和`y`位置定义我们圆圈的中心。画布标签遵循标准的笛卡尔坐标：（0，0）在左上角（`x`向右增长，`y`向底部增长）。

```js
context.arc(x, y, radius, startingAngle, endingAngle, ccw);
```

在我们的示例中，我们决定通过将画布的宽度除以`2.3`来将圆圈略微定位到中心的左侧，并将`y`定位在画布的正中心。下一个参数是我们圆圈的半径，接下来是两个参数，定义了我们描边的起始和结束位置。由于我们想要创建一个完整的圆圈，我们从`0`开始，到两倍的`Math.PI`结束，即一个完整的圆圈（`Math.PI`相当于 180 度）。最后一个参数是我们圆弧的方向。在我们的情况下，由于我们正在创建一个完整的圆圈，设置在这里无关紧要（ccw = 逆时针）。

```js
context.fill();
```

最后但同样重要的是，我们调用`fill`函数来填充和着色我们之前创建的形状。与`fillRect`函数不同，它既创建又填充形状，`arc`方法不会。`arc`方法只定义要填充的形状的边界。您可以使用这种方法（和其他方法）在实际绘制到舞台之前创建更复杂的形状。我们将在本章的后续食谱中更深入地探讨这一点。

# 层叠矩形以创建希腊国旗

我们在为帕劳创建国旗时学到，当我们使用`arc`方法创建一个圆圈时，我们必须单独触发一个请求来填充形状。这对我们从头开始创建的所有形状都是如此，对于创建线条也是如此。让我们转向一个稍微复杂一点的国旗：希腊国旗。

![将矩形层叠以创建希腊国旗](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_01_03.jpg)

## 准备工作

与上一个食谱一样，我们将跳过 HTML 部分，直接进入绘制画布的 JavaScript 部分。有关创建画布元素所涉及的步骤的详细说明，请参考本章的第一个食谱。

在开始编码之前，仔细观察国旗，并尝试制定一个攻击计划，列出创建这面国旗所需执行的步骤。

## 如何做...

如果我们看一下旗帜，很容易就能想出如何规划这个过程。有很多方法可以做到这一点，但以下是我们的尝试：

1.  我们首先启动我们的应用程序，并创建一个空白的蓝色画布：

```js
  var canvas = document.getElementById("greece");
  var wid = canvas.width;
  var hei = canvas.height;

  var context = canvas.getContext("2d");
      context.fillStyle = "#000080";
      context.fillRect(0,0,wid,hei);
```

1.  如果你看一下前面的图，有四条白色条纹和五条蓝色条纹将成为背景的一部分。让我们将画布的总高度除以`9`，这样我们就可以找到我们线条的合适大小：

```js
  var lineHeight = hei/9;
```

1.  到目前为止，我们使用内置工具创建了形状，比如`arc`和`fillRect`。现在我们要手动绘制线条，为此我们将设置`lineWidth`和`strokeStyle`的值，这样我们就可以在画布上绘制线条：

```js
  context.lineWidth = lineHeight;
  context.strokeStyle = "#ffffff";
```

1.  现在，让我们循环四次，创建一条从右侧到左侧的线，如下所示：

```js
  var offset = lineHeight/2;
  for(var i=1; i<8; i+=2){
    context.moveTo(0,i*lineHeight + offset);
    context.lineTo(wid,i*lineHeight+offset);

  }
```

就是这样，我们成功了。重新加载你的 HTML 页面，你会发现希腊的国旗以其全部的荣耀展现在那里。嗯，还不是全部的荣耀，但足够让你猜到这是希腊的国旗。在我们继续之前，让我们深入了解一下这是如何工作的。

## 它是如何工作的...

注意偏移量的增加。这是因为`lineWidth`从线的中心点向两个方向增长。换句话说，如果从(0, 0)到(0, height)绘制宽度为 20 像素的线条，那么只有 10 像素可见，因为线条的厚度范围在(-10 到 10)之间。因此，我们需要考虑到我们的第一条线需要被其宽度的一半向下推，这样它就在正确的位置上了。

`moveTo`函数接受两个参数`moveTo(x,y)`。`lineTo`函数也接受两个参数。我相信你一定已经猜到它们之间的区别了。一个会移动虚拟点而不绘制任何东西，而另一个会在点之间创建一条线。

## 还有更多...

如果你运行你的 HTML 文件，你会发现我们的线条没有显示出来。别担心，你没有犯错（至少我是这么认为的；））。为了让线条变得可见，我们需要告诉浏览器我们已经准备好了，就像我们在使用`arc`时调用`fill()`方法一样。在这种情况下，由于我们正在创建线条，我们将在定义完线条后立即调用`stroke()`方法，如下所示：

```js
var offset = lineHeight/2;
  for(var i=1; i<8; i+=2){
    context.moveTo(0,i*lineHeight + offset);
    context.lineTo(wid,i*lineHeight+offset);

  }
 context.stroke();

```

如果你现在刷新屏幕，你会发现我们已经离成功更近了。现在是时候在屏幕的左上角添加那个矩形了。为此，我们将重用我们的`lineHeight`变量。我们的矩形的大小是`lineHeight`长度的五倍：

```js
  context.fillRect(0,0,lineHeight*5,lineHeight*5);
```

现在是时候在旗帜上创建十字了：

```js
  context.moveTo(0, lineHeight*2.5);
  context.lineTo(lineHeight*5,lineHeight*2.5);
  context.moveTo(lineHeight*2.5,0);
  context.lineTo(lineHeight*2.5,lineHeight*5+1);
  context.stroke();
```

如果你现在运行应用程序，你会感到非常失望。我们完全按照之前学到的内容去做了，但结果并不如预期。

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_01_04.jpg)

线条都混在一起了！好吧，别害怕，这意味着是时候学习新东西了。

### beginPath 方法和 closePath 方法

我们的旗帜效果不太好，因为它被我们之前创建的所有线搞混了。为了避免这种情况，我们应该告诉画布我们何时开始新的绘图，何时结束。为此，我们可以调用`beginPath`和`closePath`方法，让画布知道我们已经完成了某些事情或者正在开始新的事情。在我们的情况下，通过添加`beginPath`方法，我们可以解决我们的旗帜问题。

```js
  context.fillRect(0,0,lineHeight*5,lineHeight*5);
 context.beginPath();
  context.moveTo(0, lineHeight*2.5);
  context.lineTo(lineHeight*5,lineHeight*2.5);
  context.moveTo(lineHeight*2.5,0);
  context.lineTo(lineHeight*2.5,lineHeight*5+1);
  context.stroke();
```

恭喜！你刚刚创建了你的前两个国旗，并且在这个过程中学到了很多关于画布 API 的知识。这已经足够让你能够从 196 个国旗中创建 53 个国家的国旗。这已经是一个很好的开始；世界上 25%的国家都在你手中。

你现在应该能够做的最复杂的旗帜是英国的国旗。如果你想探索一下，试试看。如果你真的为此感到自豪，请给我写封邮件`<ben@02geek.com>`，我会很乐意看到它。

# 使用路径创建形状

我们在上一个教程中学习了如何创建世界国旗四分之一的内容，但这并不能结束，对吧？这个教程将致力于使用路径创建更复杂的形状。我们将从创建一个三角形开始，然后逐渐进展到更复杂的形状。

## 做好准备

让我们从基本形状库中不包括的最简单的形状开始：三角形。所以，如果你准备好了，让我们开始吧...

## 如何做...

让我们从创建我们的第一个形状开始，一个三角形：

```js
context.fillStyle = color;
context.beginPath();
context.moveTo(x1,y1);
context.lineTo(x2,y2);
context.lineTo(x3,y3);
context.lineTo(x1,y1);
context.closePath();
context.fill();
```

这里的代码中的点 `x1,y1` 到 `x3,y3` 是伪代码。你需要选择自己的点来创建一个三角形。

## 工作原理...

这里的大部分元素都不是新的。这里最重要的变化是，我们正在使用之前使用过的元素从头开始创建形状。当我们创建一个形状时，我们总是从使用 `beginPath()` 方法声明它开始。然后我们创建形状，并使用 `closePath()` 方法结束创建。在屏幕上我们仍然看不到任何东西，直到我们决定我们想要对我们创建的形状做什么，比如显示它的填充或显示它的描边。在这种情况下，因为我们试图创建一个三角形，我们将调用 `fill` 函数。

让我们在一个真实的国旗示例中看看它的运行情况。这次我们将参观圭亚那的罗赖马山。

![工作原理...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_01_05.jpg)

好的，你已经了解了三角形的概念。让我们看看它的实际应用。我提取了这段代码并将其放入一个函数中。要创建这个国旗，我们需要创建四个三角形。

```js
var canvas = document.getElementById("guyana");
var wid = canvas.width;
var hei = canvas.height;

var context = canvas.getContext("2d");
    context.fillStyle = "#009E49";
    context.fillRect(0,0,wid,hei);

fillTriangle(context,	0,0,
             wid,hei/2,
             0,hei, "#ffffff");
fillTriangle(context,0,10,
             wid-25,hei/2,
             0,hei-10, "#FCD116");
fillTriangle(context,0,0,
             wid/2,hei/2,
             0,hei, "#000000");
fillTriangle(context,0,10,
             wid/2-16,hei/2,
             0,hei-10, "#CE1126");

function fillTriangle(context,x1,y1,x2,y2,x3,y3,color){
  context.fillStyle = color;
  context.beginPath();
  context.moveTo(x1,y1);
  context.lineTo(x2,y2);
  context.lineTo(x3,y3);
  context.lineTo(x1,y1);
  context.closePath();
  context.fill();
}
```

通过创建 `fillTriangle()` 函数，我们现在可以快速有效地创建三角形，就像我们创建矩形一样。这个函数使得创建一个有如此丰富数量的三角形的国旗变得轻而易举。现在，借助 `fillTriangle` 方法的帮助，我们可以创建世界上任何有三角形的国旗。

## 还有更多...

不要让三角形成为你最复杂的形状，因为你可以创建任意数量的尖锐形状。让我们创建一个更复杂的锯齿形图案。为此，我们将飞到巴林王国。

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_01_06.jpg)

试着找到我们分解和解释之前的新逻辑。

```js
var canvas = document.getElementById("bahrain");
var wid = canvas.width;
var hei = canvas.height;

var context = canvas.getContext("2d");
    context.fillStyle = "#CE1126";
    context.fillRect(0,0,wid,hei);
var baseX = wid*.25;
    context.fillStyle = "#ffffff";
    context.beginPath();
    context.lineTo(baseX,0);

var zagHeight = hei/5;
for(var i=0; i<5; i++){
  context.lineTo(baseX +25 , (i+.5)*zagHeight);
  context.lineTo(baseX  , (i+1)*zagHeight);

}
context.lineTo(0,hei);
context.lineTo(0,0);
context.closePath();
context.fill();

addBoarder(context,wid,hei);
```

让我们分解这个锯齿形并理解这里发生了什么。在正常设置画布元素后，我们立即开始创建我们的形状。我们首先绘制一个红色背景，然后创建一个将有白色区域的形状。它非常像一个矩形，只是它里面有锯齿。

在这段代码中，我们首先创建一个矩形，但我们的目标是改变突出显示的代码行，使其成为锯齿形：

```js
var baseX = wid*.25;
context.fillStyle = "#ffffff";
context.beginPath();
context.lineTo(baseX,0);
context.lineTo(wid*.25,hei);
context.lineTo(0,hei);
context.lineTo(0,0);
context.closePath();
context.fill();
```

在这段代码中，我们将填充颜色设置为白色，我们设置了 `beginPath`，然后 `lineTo`（从点 `(0,0)` 开始，即默认起始点）并创建一个填充了画布宽度 25% 的矩形。我突出了水平线，因为这是我们想要用锯齿形的线。通过观察国旗，我们可以看到我们将在屏幕上创建五个三角形，所以让我们用 `for` 循环来替换这条线：

```js
...
context.lineTo(baseX,0);

var zagHeight = hei/5;
for(var i=0; i<5; i++){
 context.lineTo(baseX +25 , (i+.5)*zagHeight);
 context.lineTo(baseX  , (i+1)*zagHeight);

}

context.lineTo(0,hei);
  ...
```

因此，在我们运行循环之前，我们的第一步是决定每个三角形的高度：

```js
var zagHeight = hei/5;
```

我们将画布的总高度除以五，得到每个三角形的高度。

我们在 `for` 循环中绘制了锯齿形。为此，我们需要在每一轮中使用以下两行代码：

```js
context.lineTo(baseX +25 , (i+.5)*zagHeight);
context.lineTo(baseX  , (i+1)*zagHeight);		
```

在第一行中，我们远离当前位置，并将线条延伸到三角形高度的一半，并延伸到右侧的极点；然后在第二行中，我们返回到起始的 `x` 点，并更新我们的 `y` 到下一行段的起始点。顺便说一句，`baseX +25` 的添加是完全任意的。我只是随意尝试，直到看起来不错，但如果你愿意，你可以使用比例来代替（这样如果你扩展画布，它看起来仍然很好）。

所有这一切最令人惊奇的部分就是知道如何创建一些锯齿、三角形、矩形和圆。你可以创建更多的国旗，但我们还没有完成。我们继续追求如何创建世界上所有国旗的知识。

如果您是第一次通过代码绘图，或者觉得自己需要一些额外的练习，只需查看世界地图，并挑战自己根据我们已经建立的技能创建国旗。

# 创建复杂形状

现在是时候将我们学到的一切融入到迄今为止我们见过的最复杂的形状中，即大卫之星。这颗星星是以色列国旗的一部分（世界上我最喜欢的国旗之一；））。在我们能够创建它之前，我们需要绕个圈，访问正弦和余弦的神奇世界。

![创建复杂形状](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_01_07.jpg)

你一定会喜欢它，对吧？我知道很多人害怕余弦和正弦，但实际上它们非常容易和有趣。让我们在这里以一种更适合绘图的方式来解释它们。最基本的想法是你有一个有一个 90 度角的三角形。你对这个三角形有一些信息，这就是你开始使用正弦和余弦的全部所需。一旦你知道你有一个 90 度角并且知道正弦/余弦，你就有了所有你需要的信息，通过它你可以发现任何缺失的信息。在我们的情况下，我们知道所有的角度，我们知道斜边的长度（它就是我们的半径；看看带有圆的图像，看看它是如何运作的）。在 JavaScript 中，`Math.cos()`和`Math.sin()`方法都代表一个半径为 1 的圆，位于屏幕上的(0,0)点。如果我们将要查找的角度输入到`sin`函数中，它将返回`x`值（在这种情况下是邻边的长度），`cos`函数将返回对边的长度，在我们的情况下是所需的值`y`。

我制作了一个很好的视频，深入探讨了这个逻辑。你可以在[`02geek.com/courses/video/58/467/Using-Cos-and-Sin-to-animate.html`](http://02geek.com/courses/video/58/467/Using-Cos-and-Sin-to-animate.html)上查看它。

## 准备就绪

理解正弦/余弦工作的最简单方法是通过一个实时的例子，而在我们的情况下，我们将用它来帮助我们弄清楚如何在以色列国旗中创建大卫之星。我们将退一步，学习如何找到屏幕上的点来创建形状。同样，我们将跳过创建 HTML 文件的过程，直接进入 JavaScript 代码。有关如何设置 HTML 的概述，请查看*使用 2D 画布进行图形处理*配方。

![准备就绪](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_01_08.jpg)

## 如何做...

在创建 JavaScript 文件后，在您的`init`函数中添加以下代码。

1.  创建我们基本的画布变量：

```js
var canvas = document.getElementById("israel");
var wid = canvas.width;
var hei = canvas.height;
var context = canvas.getContext("2d");
```

1.  定义弧度中的一度。我们这样做是因为`Math.cos`和`Math.sin`期望的是弧度值而不是度值（`radian`是以弧度测量的一度）：

```js
var radian = Math.PI/180;
```

1.  创建一个`tilt`变量。这个变量将定义将要创建的三角形的倾斜。想象三角形在一个圆内，我们正在用这个`tilt`变量旋转圆：

```js
var tilt = radian*180;
```

1.  定义画布的中心点：

```js
var baseX = wid / 2;
var baseY = hei / 2;
```

1.  设置大卫之星的无形边界圆的半径：

```js
var radius = 24;
```

1.  定义国旗中条纹的高度：

```js
var stripHeight = 14;
```

1.  定义线宽：

```js
context.lineWidth=5;
```

1.  创建两个三角形（一个倾斜，一个不倾斜）：

```js
createTrinagle(context,
  baseX+ Math.sin(0) * radius, baseY + Math.cos(0) * radius,
  baseX+ Math.sin(radian*120) * radius, baseY + Math.cos(radian*120) * radius,
  baseX+ Math.sin(radian*240) * radius, baseY + Math.cos(radian*240) * radius, 
  null,"#0040C0");

createTrinagle(context,
  baseX+ Math.sin(tilt) * radius, baseY + Math.cos(tilt) * radius,
  baseX+ Math.sin(radian*120+tilt) * radius, baseY + Math.cos(radian*120+tilt) * radius,
  baseX+ Math.sin(radian*240+tilt) * radius, baseY + Math.cos(radian*240+tilt) * radius, 
  null,"#0040C0");
```

1.  绘制国旗条纹：

```js
context.lineWidth=stripHeight;
context.beginPath();
context.moveTo(0,stripHeight);
context.lineTo(wid,stripHeight);
context.moveTo(0,hei- stripHeight);
context.lineTo(wid,hei- stripHeight);
context.closePath();
context.stroke();
```

1.  创建`createTriangle`函数：

```js
function createTriangle(context,x1,y1,x2,y2,x3,y3,fillColor,strokeColor){
  context.beginPath();
  context.moveTo(x1,y1);
  context.lineTo(x2,y2);
  context.lineTo(x3,y3);
  context.lineTo(x1,y1);
  context.closePath();
  if(fillColor) {
    context.fillStyle = fillColor;
    context.fill();	
  }
  if(strokeColor){
  context.strokeStyle = strokeColor;
  context.stroke();

  }
}
```

你完成了。运行你的应用程序，你会发现以色列国旗，中间有大卫之星。

## 它是如何工作的...

在我们深入探讨国旗的创建和如何完成它之前，我们需要了解如何在圆中定位点。为此，让我们看一个更简单的例子：

```js
var rad = Math.PI/180;	
context.fillStyle = "#FFDE00";
context.arc(wid / 2, hei / 2, 30, 0, 2 * Math.PI, false);
context.fill();
context.beginPath();
context.strokeStyle = "#ff0000";
context.lineWidth=6;
context.moveTo(Math.sin(0) * 30 + wid / 2, Math.cos(0) * 30 + hei/2);
context.lineTo(Math.sin(rad*120) * 30 + wid / 2, Math.cos(rad*120) * 30 + hei/2);
context.stroke();
```

以下是代码将生成的输出：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_01_09.jpg)

尽管在我们人类友好的头脑中，一个圆是一个有 360 度的形状，但实际上在大多数编程语言中最好用弧度表示。

弧度就像度数一样，只是它们不是人类友好的 0 到 360 之间的数字，而是 0 到两倍 Pi 之间的数字。你可能想知道 Pi 是什么，所以再多说一点关于 Pi。Pi 本质上是当你取任何圆的周长并将其除以相同圆的直径时得到的值。返回的结果将是 Pi 或约为 3.14159。这是一个神奇的数字，好消息是，如果你不想知道更多，你就不需要知道更多。你只需要知道 3.142 等于半个圆。有了这个事实，我们现在可以将 Pi 除以`180`得到一个弧度值等于一度的值：

```js
var rad = Math.PI/180;
```

然后我们在屏幕中心创建一个半径为`30`的圆，以帮助我们可视化，然后开始创建一条线，该线将从我们圆的角度`0`开始，到角度`120`结束（因为我们想创建一个 360/3 的三角形）。

```js
context.strokeStyle = "#ff0000";
context.lineWidth=6;
context.moveTo(Math.sin(0) * 30 + wid / 2, Math.cos(0) * 30 + hei/2);
context.lineTo(Math.sin(rad*120) * 30 + wid / 2, Math.cos(rad*120) * 30 + hei/2);
context.stroke();
```

让我们分解最复杂的那行代码：

```js
context.lineTo(Math.sin(rad*120) * 30 + wid / 2, Math.cos(rad*120) * 30 + hei/2);
```

由于`Math.sin`和`Math.cos`返回半径为`1`的值，我们将乘以我们圆的半径（在本例中为`30`）返回的任何值。在`Math.sin`和`Math.cos`的参数中，我们将提供完全相同的值；在这个例子中是`120`弧度。由于我们的圆将位于画布的左上角，我们希望通过添加到我们的值`wid/2`和`hei/2`来将圆移到屏幕中心开始。

在这个阶段，你应该知道如何在圆上找到点，以及如何在两点之间画线。让我们回到以色列国旗，深入研究新函数`createTriangle`。它是基于*使用路径创建形状*食谱中创建的`fillTriangle`函数。

```js
function createTriangle(context,x1,y1,x2,y2,x3,y3,fillColor,strokeColor){

...

 if(fillColor) {
 context.fillStyle = fillColor;
 context.fill(); 
 }

if(stokeColor){
 context.strokeStyle = fillColor;
 context.stroke(); 

 }

}
```

我已经突出显示了这个函数的新组件，与函数`fillTriangle`相比。两个新参数`fillColor`和`strokeColor`定义了我们是否应该填充或描边三角形。请注意，我们将`strokeStyle`和`fillStyle`方法移到函数底部，以减少我们的代码量。太棒了！我们现在有了一个现代的三角形创建器，可以处理大卫之星。

## 还有更多...

好的，是时候连接这些点（字面意思）并创建以色列国旗了。回顾我们的原始代码，我们发现自己使用`createTriangle`函数两次来创建完整的大卫之星形状。让我们深入研究一下这里的逻辑，看看第二个三角形（倒置的那个）：

```js
createTriangle(context,
  baseX+ Math.sin(tilt) * radius, 
  baseY + Math.cos(tilt) * radius,
 baseX+ Math.sin(radian*120+tilt) * radius, 
 baseY + Math.cos(radian*120+tilt) * radius,
baseX+ Math.sin(radian*240+tilt) * radius,
  baseY + Math.cos(radian*240+tilt) * radius, null,"#0040C0");
```

我们发送三个点到虚拟圆上创建一个三角形。我们将虚拟圆分成三等份，并找到`0`、`120`和`240`度的点值。这样，如果我们在这些点之间画一条线，我们将得到一个完美的三角形，其中所有边都是相等的。

让我们深入研究一下发送到`createTriangle`函数的一个点：

```js
baseX + Math.sin(radian*120+tilt) * radius, 	
baseY + Math.cos(radian*120+tilt) * radius
```

我们从`baseX`和`baseY`（屏幕中心）开始作为我们圆的中心点，然后找出从基本起始点到实际点间的间隙。然后分别从中加上我们从`Math.sin`和`Math.cos`得到的值。在这个例子中，我们试图得到`120`度加上倾斜值。换句话说，`120`度加上`180`度（或`300`度）。

为了更容易理解，在伪代码中，它看起来类似于以下代码片段：

```js
 startingPositionX + Math.sin(wantedDegree) * Radius 
 startingPositionY + Math.cin(wantedDegree) * Radius 
```

除了祝贺之外，没有更多要说的了。我们刚刚完成了另一面国旗的创建，并在这个过程中学会了如何创建复杂的形状，使用数学来帮助我们找出屏幕上的点，并混合不同的形状来创建更复杂的形状。

# 添加更多顶点

有许多国旗包含星星，这些星星无法通过重叠的三角形来创建。在这个示例中，我们将找出如何创建一个包含任意数量顶点的星星。我们将利用在上一个示例中发现的相同关键概念，利用虚拟圆来计算位置，这次只用两个虚拟圆。在这个示例中，我们将创建索马里的国旗，并在此过程中找出如何创建一个能够创建星星的函数。

![添加更多顶点](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_01_10.jpg)

## 准备就绪

请继续在上一个示例中工作。如果您还没有开始，请务必这样做，因为这个示例是上一个示例的下一个逻辑步骤。与上一个示例一样，我们将跳过此示例的 HTML 部分。请查看本书中的第一个示例，以刷新所需的 HTML 代码。

## 如何做...

让我们开始创建索马里的国旗。

1.  创建画布的标准逻辑：

```js
var canvas = document.getElementById("somalia");
var wid = canvas.width;
var hei = canvas.height;

var context = canvas.getContext("2d");
```

1.  填充画布的背景颜色：

```js
context.fillStyle = "#4189DD";
context.fillRect(0,0,wid,hei);
```

1.  通过调用`createStar`函数来绘制星星：

```js
createStar(context,wid/2,hei/2,7,20,5,"#ffffff",null,0);
```

1.  创建`createStart`函数：

```js
function createStar(context,baseX,baseY,
                    innerRadius,outerRadius,
                    points,fillColor,
                    strokeColor,tilt){
// all the rest of the code in here
}
```

1.  从这一点开始，我们将在`createStart`函数中进行工作。添加一些辅助变量：

```js
function createStar(context,baseX,baseY,innerRadius,outerRadius,points,fillColor,strokeColor,tilt){
  var radian = Math.PI/180;
  var radianStepper = radian * ( 360/points) /2;
  var currentRadian =0;
  var radianTilt = tilt*radian;
```

1.  在开始绘制任何形状之前，调用`beginPath`方法：

```js
  context.beginPath();
```

1.  将绘图指针移动到内部圆圈的角度`0`：

```js
  context.moveTo(baseX+ Math.sin(currentRadian + radianTilt) * innerRadius,baseY+ Math.cos(currentRadian + radianTilt) * innerRadius);
```

1.  循环遍历星星的总点数，并在外圆和内圆之间来回绘制线条，以创建星形：

```js
for(var i=0; i<points; i++){
  currentRadian +=  radianStepper;
  context.lineTo(baseX+ Math.sin(currentRadian + radianTilt) * outerRadius,baseY+ Math.cos(currentRadian + radianTilt) * outerRadius);
  currentRadian +=  radianStepper;
  context.lineTo(baseX+ Math.sin(currentRadian + radianTilt) * innerRadius,baseY+ Math.cos(currentRadian + radianTilt) * innerRadius);
}
```

1.  关闭绘图路径，并根据函数参数进行填充或描边：

```js
context.closePath();

  if(fillColor){
    context.fillStyle = fillColor;
    context.fill();	
  }

  if(strokeColor){
    context.strokeStyle = strokeColor;
    context.stroke();	

  }

}
```

当您运行 HTML 包装器时，您将找到您的第一个星星，随之而来的是另一面国旗。

## 它是如何工作的...

让我们首先了解我们要创建的函数期望的内容。这个想法很简单，为了创建一个星形，我们希望有一个虚拟的内圆和一个虚拟的外圆。然后我们可以在圆圈之间来回绘制线条，以创建星形。为此，我们需要一些基本参数。

```js
function createStar(context,baseX,baseY,
     innerRadius,outerRaduis,points,fillColor,
                             strokeColor,tilt){
```

我们的常规上下文，`baseX`和`baseY`不需要进一步介绍。虚拟的`innerRadius`和`outerRadius`用于帮助定义创建星星的线段的长度和它们的位置。我们想知道我们的星星将有多少个点。我们通过添加`points`参数来实现。我们想知道`fillColor`和/或`strokeColor`，这样我们就可以定义星星的实际颜色。我们用`tilt`值来完成（当我们为以色列国旗创建大卫之星时，它可能很有用）。

```js
var radian = Math.PI/180;
var radianStepper = radian * ( 360/points) / 2;
var currentRadian =0;
var radianTilt = tilt*radian;
```

然后，我们继续配置我们星星的辅助变量。这不是我们第一次看到弧度变量，但这是我们第一次看到`radianStepper`。弧度步进器的目标是简化我们循环中的计算。我们将 360 度除以我们的三角形将具有的点数。我们将该值除以`2`，因为我们将有两倍于线条的点数。最后但并非最不重要的是，我们希望将该值转换为弧度，因此我们通过我们的弧度变量复制完整的结果。然后我们创建一个简单的`currentRadian`变量来存储我们目前所处的步骤，并最后将`tilt`值转换为弧度值，这样我们就可以在循环中添加到所有我们的线条中而无需额外的计算。

像往常一样，我们使用`beginPath`和`closePath`方法开始和完成我们的形状。让我们更深入地看一下我们即将形成的形状的起始位置：

```js
context.moveTo(baseX+ Math.sin(currentRadian + radianTilt) * innerRadius,baseY+ Math.cos(currentRadian + radianTilt) * innerRadius);
```

虽然乍一看这可能有点吓人，但实际上与我们创建大卫之星的方式非常相似。我们从`currentRadian`（目前为`0`）开始，使用`innerRadius`作为起点。

在我们的循环中，我们的目标是在内部和外部圆圈之间来回织线。为此，我们需要在每次循环周期中通过`radianStepper`来推进`currentRadian`值：

```js
for(var i=0; i<points; i++){
 currentRadian +=  radianStepper;
  context.lineTo(baseX+ Math.sin(currentRadian + radianTilt) * outerRadius,baseY+ Math.cos(currentRadian + radianTilt) * outerRadius);
  currentRadian +=  radianStepper;
  context.lineTo(baseX+ Math.sin(currentRadian + radianTilt) * innerRadius,baseY+ Math.cos(currentRadian + radianTilt) * innerRadius);
}
```

我们根据参数中的点数开始一个循环。在这个循环中，我们在内圆和外圆之间来回绘制两条线，每次步进大小由点数（我们用`radianStepper`变量配置的值）定义。

在之前的教程中，当我们创建`createTriangle`函数时，我们已经涵盖了其余的功能。就是这样！现在你可以运行应用程序并找到我们的第七面旗帜。有了这个新的复杂函数，我们可以创建所有实心星星和所有镂空的非实心星星。

好了，我希望你坐下...有了新获得的星星能力，你现在可以创建至少 109 面旗帜，包括美利坚合众国和所有其他国家的旗帜（世界上 57%的国家，而且还在增加！）。

# 重叠形状创建其他形状

目前为止，我们已经创建了许多旗帜和许多一般形状，这些形状可以通过组合我们迄今为止创建的形状来创建。在 82 面我们不知道如何创建的最受欢迎的形状之一是土耳其国旗中的新月形状。通过它，我们学会了使用减法来创建更深入的形状。

![重叠形状创建其他形状](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_01_11.jpg)

## 准备工作

前一个教程是本教程的起点。从这里开始，我们将继续努力创建更复杂的形状，这些形状是由两个形状组合而成的。因此，我们将使用上一个教程中创建的代码，位于`01.02.flags.js`中。

## 如何做...

让我们直接跳到我们的代码中，看看它是如何运作的。

1.  获取上下文并将画布的宽度和高度保存到变量中：

```js
var canvas = document.getElementById("turkey");
var wid = canvas.width;
var hei = canvas.height;

var context = canvas.getContext("2d");
```

1.  填充矩形画布区域：

```js
context.fillStyle = "#E30A17";
context.fillRect(0,0,wid,hei);
```

1.  创建一个完整的圆：

```js
context.fillStyle = "#ffffff";
context.beginPath();
context.arc(wid / 2 - 23, hei / 2, 23, 0, 2 * Math.PI, false);
context.closePath();
context.fill();
```

1.  更改画布填充的颜色。用另一个圆填充其边界内的圆，隐藏了上一个创建的圆的一部分。这种效果创建了一个看起来像新月的形状：

```js
context.fillStyle = "#E30A17";
context.beginPath();
context.arc(wid / 2 - 18, hei / 2, 19, 0, 2 * Math.PI, false);
context.closePath();
context.fill();
```

1.  重复使用前一个教程中的`createStart`来添加土耳其星：

```js
createStar(context,wid/2 + 13,hei/2,5,16,5,"#ffffff",null,15);
```

就是这样！你刚刚创建了一个不可能的形状，这是通过用一个形状遮罩另一个形状实现的。

## 它是如何工作的...

这里的关键是我们使用了两个圆，一个覆盖另一个来创建新月形状。顺便说一句，注意我们如何倾斜星星，以便其一个点指向圆的中心。

在过去的几个示例中，我们已经经历了很多，此时你应该非常熟悉在画布中创建许多形状和元素。在我们可以说我们已经掌握了画布之前，还有很多东西可以探索，但我们绝对可以说我们已经掌握了大部分世界旗帜的创建，这非常酷。我很想看到你的旗帜。当你创建了一面书中没有的旗帜时，给我留言！ :)


# 第二章：画布中的高级绘图

+   绘制弧线

+   使用控制点绘制曲线

+   创建贝塞尔曲线

+   将图像整合到我们的艺术中

+   使用文本绘制

+   理解像素操作

# 介绍

这是最后一章，我们将深入研究画布，因为剩下的章节将专注于构建图表和交互。

在本章中，我们将继续通过向画布添加曲线、图像、文本，甚至像素操作来掌握我们的技能。

# 绘制弧线

我们可以在画布中创建三种类型的曲线 - 使用弧线、二次曲线和贝塞尔曲线。让我们开始吧。

## 准备工作

如果您回忆一下第一章，*画布中的形状绘制*，在我们的第一个示例中，我们使用弧线方法创建了完美的圆圈。弧线方法不仅仅是如此。我们实际上可以在圆形中创建任何部分曲线。如果您不记得绘制圆圈，我强烈建议您再次浏览第一章 ，*画布中的形状绘制*，同时您也会找到创建 HTML 文档的模板。在本示例中，我们将专门关注 JavaScript 代码。

## 如何做...

让我们开始并创建我们的第一个具有曲线的非圆形：

1.  访问`pacman`画布元素，并使用以下代码片段获取其宽度和高度：

```js
var canvas = document.getElementById("pacman");
var wid = canvas.width;
var hei = canvas.height;
```

1.  创建一个`radian`变量（一度的弧度）：

```js
var radian = Math.PI/180;
```

1.  获取画布上下文，并使用以下代码片段将其背景填充为黑色：

```js
var context = canvas.getContext("2d");
  context.fillStyle = "#000000";
  context.fillRect(0,0,wid,hei);
```

1.  在开始绘制之前开始一个新路径：

```js
  context.beginPath();
```

1.  更改填充样式颜色：

```js
  context.fillStyle = "#F3F100";
```

1.  将指针移动到屏幕中心：

```js
  context.moveTo(wid/2,hei/2);
```

1.  绘制一个从 40 度开始到 320 度结束的曲线（半径为 40），位于屏幕中心：

```js
  context.arc(wid / 2, hei / 2, 40, 40*radian, 320*radian, false);
```

1.  通过使用以下代码片段，关闭形状，绘制一条线回到我们形状的起始点：

```js
  context.lineTo(wid/2,hei/2);
```

1.  关闭路径并填充形状：

```js
  context.closePath();
  context.fill();
```

您刚刚创建了一个 PacMan。

## 如何做...

第一次，我们利用并创建了一个饼状形状，称为 PacMan（当我们开始创建饼图时，您可以看到这是非常有用的）。非常简单 - 再次连接到弧度的概念：

```js
context.arc(wid / 2, hei / 2, 40, 40*radian, 320*radian, false);
```

请注意我们的第 4 和第 5 个参数 - 而不是从 0 开始到`2*Math.PI`结束的完整圆圈 - 正在设置弧线开始的角度为弧度 40，结束于弧度 320（留下 80 度来创建 PacMan 的嘴）。剩下的就是从圆的中心开始绘制：

```js
context.moveTo(wid/2,hei/2);
context.arc(wid / 2, hei / 2, 40, 40*radian, 320*radian, false);
context.lineTo(wid/2,hei/2);
```

我们首先将指针移动到圆的中心。然后创建弧线。由于我们的弧线不是完整的形状，它会继续我们离开的地方 - 从弧线的中心到起始点（40 度）画一条线。我们通过画一条线回到弧线的中心来完成动作。现在我们准备填充它并完成我们的工作。

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_02_01.jpg)

既然我们已经解决了弧线问题，您可以看到这对于创建饼图将会非常有用。

# 使用控制点绘制曲线

如果世界上只有两个点和一个完美的弧线，那么这将是本书的结尾，但不幸或幸运的是，对我们来说，还有许多更复杂的形状需要学习和探索。有许多曲线不是完全对齐的曲线。到目前为止，我们创建的所有曲线都是完美圆的一部分，但现在不再是这样了。在本示例中，我们将探索二次曲线。二次曲线使我们能够创建不是圆形的曲线，通过添加第三个点 - 控制器来控制曲线。您可以通过查看以下图表轻松理解这一点：

![使用控制点绘制曲线](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_02_02.jpg)

**二次曲线**是一条具有一个控制点的曲线。考虑这样一种情况，当创建一条线时，我们在两点（本示例中的 A 和 B）之间绘制它。当我们想要创建一个二次曲线时，我们使用一个外部重力控制器来定义曲线的方向，而中间线（虚线）定义了曲线的延伸距离。

## 准备工作

与以前的示例一样，我们在这里也跳过了 HTML 部分——并不是说它不需要，只是每个示例中都重复出现，如果您需要了解如何设置 HTML，请参阅第一章中的*使用 2D 画布绘图*示例，*在画布中绘制形状*。

## 如何做...

在这个示例中，我们将创建一个看起来像一个非常基本的眼睛的封闭形状。让我们开始吧：

1.  我们总是需要从提取我们的画布元素开始，设置我们的宽度和高度变量，并定义一个弧度（因为我们发现它对我们有用）：

```js
var canvas = document.getElementById("eye");
  var wid = canvas.width;
  var hei = canvas.height;
  var radian = Math.PI/180;
```

1.  接下来，用纯色填充我们的画布，然后通过触发`beginPath`方法开始一个新形状：

```js
var context = canvas.getContext("2d");
  context.fillStyle = "#dfdfdf";
  context.fillRect(0,0,wid,hei);
  context.beginPath();
```

1.  为我们的眼睛形状定义线宽和描边颜色：

```js
  context.lineWidth = 1;
  context.strokeStyle = "#000000"; // line color	
  context.fillStyle = "#ffffff";
```

1.  将我们的绘图指针移动到左中心点，因为我们需要在屏幕中心从左到右绘制一条线，然后再返回（只使用曲线）：

```js
  context.moveTo(0,hei/2);
```

1.  通过使用锚点从我们的初始点绘制两个二次曲线到画布的另一侧，然后返回到初始点，锚点位于画布区域的极端顶部和极端底部：

```js
  context.quadraticCurveTo(wid / 2, 0, wid,hei/2);
  context.quadraticCurveTo(wid / 2, hei, 0,hei/2);
```

1.  关闭路径。填充形状并在形状上使用`stroke`方法（`fill`用于填充内容，`stroke`用于轮廓）：

```js
  context.closePath();
  context.stroke();
  context.fill();
```

干得好！您刚刚使用`quadraticCurveTo`方法创建了您的第一个形状。

## 工作原理...

让我们仔细看看这个方法：

```js
context.quadraticCurveTo(wid / 2, 0, wid,hei/2);
```

因为我们已经在原点（点 A）上，我们输入另外两个点——控制点和点 B。

```js
context.quadraticCurveTo(controlX, controlY, pointB_X, pointB_Y);
```

在我们的示例中，我们创建了一个封闭形状——创建眼睛的起点。通过控制器来调整方向和曲线的大小。一个经验法则是，越靠近垂直线，曲线就会越平缓，而离中心点越远，曲线的形状就会越弯曲。

![工作原理...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_02_03.jpg)

# 创建贝塞尔曲线

我们刚刚学到，使用二次曲线时我们有一个控制点。虽然我们可以用一个控制点做很多事情，但我们并没有真正对曲线有完全的控制。所以让我们更进一步，添加一个控制点。添加第二个控制点实际上增加了这两个点之间的关系，使其成为三个控制因素。如果我们包括实际的锚点（我们有两个），最终会有五个控制形状的点。这听起来很复杂；因为我们获得的控制越多，理解它的工作原理就越复杂。仅仅通过代码来弄清楚复杂的曲线并不容易，因此我们实际上使用其他工具来帮助我们找到正确的曲线。

为了证明前面的观点，我们可以找到一个非常复杂的形状并从那个形状开始（不用担心，在本示例中，我们将练习一个非常简单的形状，以便搞清楚概念）。我们将选择绘制加拿大国旗，主要是枫叶。

![创建贝塞尔曲线](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_02_06.jpg)

## 准备工作

这个示例很难理解，但我们将在接下来的*工作原理...*部分详细介绍。所以如果您对曲线不熟悉，我强烈建议您在实现之前从*工作原理...*部分开始学习。

## 如何做...

让我们创建加拿大国旗。让我们直接进入 JavaScript 代码：

1.  创建画布和上下文：

```js
var canvas = document.getElementById("canada");
var wid = canvas.width;
var hei = canvas.height;

var context = canvas.getContext("2d");
```

1.  填充背景以匹配加拿大国旗的背景：

```js
context.fillStyle="#FF0000";
context.fillRect(0,0,50,100);
context.fillRect(wid-50,0,50,100);
```

1.  开始一个新路径并将指针移动到`84,19`：

```js
context.beginPath();
context.moveTo(84,19);
```

1.  绘制曲线和线条以创建枫叶：

```js
context.bezierCurveTo(90,24,92,24,99,8);
context.bezierCurveTo(106,23,107,23,113,19);
context.bezierCurveTo(108,43,110,44,121,31);
context.bezierCurveTo(122,37,124,38,135,35);
context.bezierCurveTo(130,48,131,50,136,51);
context.bezierCurveTo(117,66,116,67,118,73);
context.bezierCurveTo(100,71,99,72,100,93);
context.lineTo(97,93);
context.bezierCurveTo(97,72,97,71,79,74);
context.bezierCurveTo(81,67,80,66,62,51);
context.bezierCurveTo(67,49,67,48,63,35);
context.bezierCurveTo(74,38,75,37,77,31);
context.bezierCurveTo(88,44,89,43,84,19);
```

1.  关闭路径并填充形状：

```js
context.closePath();
context.fill();	
```

现在，你已经创建了加拿大国旗。我不知道你是否已经知道它是如何工作的，或者我们是如何得到我们放入曲线中的看似随机的数字的，但你已经创建了加拿大国旗！不要担心，我们将立即在下一节中解密曲线的魔力。

## 它是如何工作的……

在我们解释加拿大国旗的工作原理之前，我们应该退后一步，创建一个更简单的示例。在这个简短的示例中，我们将使用`bezierCurveTo`方法创建一个椭圆形状。

```js
context.moveTo(2,hei/2);
  context.bezierCurveTo(0, 0,wid,0, wid-2,hei/2);
  context.bezierCurveTo(wid, hei,0,hei, 2,hei/2);
  context.closePath();
  context.stroke();
  context.fill();
```

就是这样。以下是你通过这种方法得到的结果：

![它是如何工作的……](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_02_04.jpg)

如果你明白了这一点，那就太好了。我们现在将解释这是如何工作的，然后进入我们是如何找出加拿大国旗的所有点的。我们再次充分利用整个画布，并通过将两个控制器设置为画布的角来控制我们的控制器：

```js
context.bezierCurveTo(controlPointX1, controlPointY1, controlPointX2, controlPointY2, pointBX, pointBY);
```

通过操纵控制器，看看使用两个点可以获得多少更多的控制权——当你需要更详细地控制曲线时，这是非常有用的。

这是我们完整国旗示例的核心。我强烈建议你探索改变控制点的值的影响，以更好地理解和敏感于它。现在是时候回到我们的国旗，看看我们是如何构造它的。

现在是时候将我们最复杂的绘图风格——贝塞尔曲线——用于比椭圆更有趣的东西了。我有一个坦白：当我决定从头开始创建加拿大国旗时，我感到害怕。我在想“我要怎么完成这个？这将花费我几个小时”，然后我恍然大悟……很明显，这面旗帜需要用很多贝塞尔点来创建，但我怎么知道这些点应该在哪里呢？因此，对于这样一个高级的形状，我打开了我的图形编辑器（在我这里是 Flash 编辑器），并为枫叶形状添加了枢轴点：

![它是如何工作的……](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_02_05.jpg)

如果你仔细看前面的图表，你会发现我基本上是在加拿大国旗上做了标记，并在每个尖角上放了一个黑点。然后我创建了一个画布，并画了线，看看我得到的基本形状是否在正确的位置（顺便说一句，我得到这些点只是通过选择 Flash 中的点，看看它们的（x，y）坐标是否与画布坐标系统相同）。

```js
var context = canvas.getContext("2d");
context.beginPath();
context.moveTo(84,19);
context.lineTo(99,8);
context.lineTo(113,19);
context.lineTo(121,31);
context.lineTo(135,35);
context.lineTo(136,51);
context.lineTo(118,73);
context.lineTo(100,93);
context.lineTo(97,93);
context.lineTo(79,74);
context.lineTo(62,51);
context.lineTo(63,35);
context.lineTo(77,31);
context.lineTo(84,19);

context.closePath();
context.stroke();
```

我得到了一个远离我想要的形状。但现在我知道我的形状正在朝着正确的方向发展。缺少的是连接点之间的曲线。如果你再次看前面的图表，你会注意到我在每个尖角之间放了两个蓝点，以定义曲线的位置以及它们的锐利或柔和程度。然后我回到画布，更新了值以获得这两个控制点。我添加了所有的曲线，并从创建描边切换到创建填充。

```js
var context = canvas.getContext("2d");
 context.fillStyle="#FF0000";
 context.fillRect(0,0,50,100);
 context.fillRect(wid-50,0,50,100);

  context.beginPath();
  context.moveTo(84,19);
 context.bezierCurveTo(90,24,92,24,99,8);
 context.bezierCurveTo(106,23,107,23,113,19);
 context.bezierCurveTo(108,43,110,44,121,31);
 context.bezierCurveTo(122,37,124,38,135,35);
 context.bezierCurveTo(130,48,131,50,136,51);
 context.bezierCurveTo(117,66,116,67,118,73);
 context.bezierCurveTo(100,71,99,72,100,93);
 context.lineTo(97,93);
 context.bezierCurveTo(97,72,97,71,79,74);
 context.bezierCurveTo(81,67,80,66,62,51);
 context.bezierCurveTo(67,49,67,48,63,35);
 context.bezierCurveTo(74,38,75,37,77,31);
 context.bezierCurveTo(88,44,89,43,84,19);
  context.closePath();
  context.fill();	
```

太棒了！我刚刚得到了一个几乎完美的国旗，我觉得这对这个样本来说已经足够了。

不要试图自己创建非常复杂的形状。也许有一些人可以做到，但对于我们其他人来说，最好的方法是通过某种视觉编辑器来追踪元素。然后我们可以获取图形信息，并像我在加拿大国旗示例中所做的那样更新画布中的值。

在这个阶段，我们已经涵盖了画布中可以涵盖的最复杂的形状。本章的其余部分专门讨论屏幕上内容的其他操作方式。

# 将图像集成到我们的艺术中

幸运的是，我们并不总是需要从头开始，我们可以把更复杂的艺术留给外部图像。让我们想想如何将图像集成到我们的画布中。

## 准备工作

在本章中，我们一直在讨论国旗主题，现在我觉得现在是时候再添一面国旗了。所以让我们把目光转向海地，让他们的国旗运行起来。要创建这面国旗，我们需要有放置在国旗中心的象征的图像。

![准备就绪](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_02_07.jpg)

在源文件中，您会找到一个中心图形的图像（在`img/haiti.png`）。顺便说一句，当将艺术作品整合到画布中时，最好尽量避免通过代码调整图像大小，以保持图像质量。

## 如何做...

我们将准备背景以匹配国旗，然后将整个图像放在国旗的中心/画布上：

1.  按照我们需要访问画布的基本步骤。设置宽度、高度和实际上下文：

```js
var canvas = document.getElementById("haiti");
  var wid = canvas.width;
  var hei = canvas.height;

  var context = canvas.getContext("2d");	
```

1.  绘制背景元素：

```js
context.fillStyle="#00209F";
context.fillRect(0,0,wid,hei/2);
context.fillStyle="#D21034";
context.fillRect(0,hei/2,wid,hei/2);
```

1.  创建一个新的`Image`对象：

```js
var oIMG = new Image();

```

1.  创建一个`onLoad`函数（当图像加载时将被调用）：

```js
oIMG.onload = function(){
context.drawImage(this, (wid-this.width)/2, (hei-this.height)/2);
};
```

1.  设置图像的来源：

```js
oIMG.src = "img/haiti.png";
```

是的，将图像添加到画布中是如此简单，但让我们更深入地审视一下我们刚刚做的事情。

## 它是如何工作的...

创建图像涉及下载其数据，然后以与画布相同的方式创建一个新的图像容器：

```js
var oIMG = new Image();
```

下一步是创建一个监听器，当图像加载并准备好使用时将被触发：

```js
oIMG.onload = theListenerFunctionHere;
```

加载过程的最后一步是告诉画布应该加载哪个图像。在我们的情况下，我们正在加载`img/haiti.png`：

```js
oIMG.src = "img/haiti.png";
```

加载图像并准备好使用它只是第一步。如果我们在没有实际告诉画布该怎么处理它的情况下运行我们的应用程序，除了加载图像之外什么也不会发生。

在我们的情况下，当我们的监听器被触发时，我们将图像按原样添加到屏幕的中央：

```js
context.drawImage(this, (wid-this.width)/2, (hei-this.height)/2);
```

这就是将图像整合到画布项目中所需的全部步骤。

## 还有更多...

在画布中，我们可以对图像进行更多的操作，而不仅仅是将它们用作背景。我们可以精确定义图像的哪些部分（缩放）。我们可以调整和操作整个图像（缩放）。我们甚至可以对图像进行像素操作。我们可以对图像做很多事情，但在接下来的几个主题中，我们将涵盖一些更常用的操作。

### 缩放图像

我们可以通过向`drawImage`函数添加两个参数来缩放图像，这两个参数设置了我们图像的宽度和高度。尝试以下操作：

```js
context.drawImage(this, (wid-this.width)/2, (hei-this.height)/2 , 100, 120);
```

在前面的示例中，我们正在加载相同的图像，但我们正在强制调整大小的图像（请注意，位置不会在舞台的实际中心）。

### 添加更多的控制。

您可以控制图像的许多方面。如果您需要比前面示例更多的控制，您需要输入可能坐标的完整数量：

```js
context.drawImage(this, sourceX, sourceY, sourceWidth, sourceHeight, destX, destY, destWidth, destHeight);
```

在这种情况下，顺序已经改变（注意！）。现在，在`this`之后的前两个参数是图像的本地 x 和 y 坐标，然后是宽度和高度（创建我们谈论的裁剪），然后是画布上的位置及其控制信息（x、y、宽度和高度）。

在我们的情况下：

```js
context.drawImage(this, 25,25,20,20,0,0,50,50);
```

前面的代码行意味着我们想要从图像的内部位置（25,25）取图像，并且我们想要从中裁剪出一个 20 x 20 的矩形。然后我们想要将这个新裁剪的图像定位在（0,0），也就是画布的左上角，我们希望输出是一个 50 x 50 的矩形。

### 使用图像作为填充

我们可以使用加载的图像来填充对象：

```js
var oIMG = new Image();
  oIMG.onload = function(){
    var pattern = context.createPattern(this, "repeat");
    createStar(context,wid/2,hei/2,20,50,20,pattern,"#ffffff",20);
  };
  oIMG.src = "img/haiti.png";
```

图像加载后（始终在图像加载后，您开始操作它），我们创建一个基于我们的图像重复的模式：

```js
var pattern = context.createPattern(this, "repeat");
```

然后我们可以使用这种模式作为我们的填充。因此，在这种情况下，我们正在调用我们在早期任务中创建的`createStar`——通过以下模式在屏幕中心绘制一个星星：

```js
createStar(context,wid/2,hei/2,20,50,20,pattern,"#ffffff",20);
```

这结束了我们对旗帜的痴迷，转向了在旗帜中看不到的形状。顺便说一下，在这个阶段，你应该能够创建世界上所有的旗帜，并利用集成图像的优势，当你自己从头开始绘制它时，这样做就不再有趣，比如详细的国家标志。

# 用文本绘图

我同意，我们一直在做一些复杂的事情。现在，是时候放松一下，踢掉鞋子，做一些更容易的事情了。

## 准备工作

好消息是，如果你在这个页面上，你应该已经知道如何启动和运行画布的基础知识。所以除了选择文本的字体、大小和位置之外，你没有太多需要做的事情。

### 注意

在这里，我们不涉及如何嵌入在 JavaScript 中创建的字体，而是通过 CSS，我们将使用基本字体，并希望在这个示例中取得最好的效果。

![准备工作](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_02_08.jpg)

## 如何做...

在这个例子中，我们将创建一个文本字段。在这个过程中，我们将第一次使用渐变和阴影。执行以下步骤：

1.  获得对画布 2D API 的访问：

```js
var canvas = document.getElementById("textCanvas");
  var wid = canvas.width;
  var hei = canvas.height;

  var context = canvas.getContext("2d");
```

1.  创建渐变样式并用它填充背景：

```js
var grd = context.createLinearGradient(wid/2, hei/2, wid, hei);
  grd.addColorStop(0, "#8ED6FF"); 
  grd.addColorStop(1, "#004CB3")
  context.fillStyle= grd;
  context.fillRect(0,0,wid,hei);
```

1.  创建用于文本的渐变：

```js
  grd = context.createLinearGradient(100, hei/2, 200, hei/2+110);
  grd.addColorStop(0, "#ffff00"); 
  grd.addColorStop(1, "#aaaa44");
```

1.  定义要使用的字体并设置样式：

```js
  context.font = "50pt Verdana, sans-serif";
  context.fillStyle = grd;
```

1.  在绘制文本之前添加阴影细节：

```js
  context.shadowOffsetX = 0;
  context.shadowOffsetY = 0;
  context.shadowBlur    = 8;
  context.shadowColor   = 'rgba(255, 255, 255, 0.5)';
```

1.  使用`fillText`填充形状，使用`strokeText`描绘形状的轮廓（请注意，我称文本为形状；这是因为一旦我们绘制它，它就只是我们画布的一部分，而不是实时文本）。

```js
  context.fillText("Hello World!", 100, hei/2);
  context.strokeStyle = "#ffffff";
  context.strokeText("Hello World!", 100, hei/2);
```

就是这样，我们刚刚将我们第一次绘制的文本集成到了画布中。

## 它是如何工作的...

到目前为止，我们一直在使用纯色。现在，我们将摆脱这一点，转向渐变颜色的新世界。请参考以下代码片段：

```js
var grd = context.createLinearGradient(wid/2, hei/2, wid, hei);
  grd.addColorStop(0, "#8ED6FF"); 
  grd.addColorStop(1, "#004CB3");
```

创建渐变涉及几个步骤。第一步是定义它的范围：

```js
var grd = context.createLinearGradient(x1, y1, x2, y2);
```

与许多其他语言相反，在画布中定义渐变的旋转和大小非常容易。如果你以前使用过 Photoshop，你会发现这很容易（即使你没有，它也会很容易）。

你需要做的就是定义渐变的起始位置和结束位置。你可以将两个点发送到`createLinearGradient`方法中：

```js
grd.addColorStop(0, "#8ED6FF"); 
grd.addColorStop(1, "#004CB3");
```

在这个过渡中，我们只使用两种颜色。将它们放在 0 和 1 之间的值。这些值是比率，换句话说，我们要求从渐变区域的开始一直到结束来扩展颜色过渡。我们可以添加更多的颜色，但我们的目标是将它们都绑定在 0 到 1 的比率内。你添加的颜色越多，你就需要更多地玩弄发送到第一个参数的值。

你刚刚完成了创建渐变。现在是时候使用它了：

```js
context.fillStyle= grd;
context.fillRect(0,0,wid,hei);
```

在这部分中，我们将使用`fillStyle`方法，然后创建一个矩形。

请注意，你可能发送到`addColorStop`方法的值范围的重要性。随着你在渐变中添加更多的颜色，这里发送的值的重要性就会更加明显。这些点不是计数器，而是我们示例中颜色的比率。过渡是在两种颜色的范围从 0 到 1 之间，换句话说，它们从我们发送到`createLinearGradient`方法的第一个点一直到最后一个点进行过渡。由于我们正在使用两种颜色，这对我们来说是完美的比率。

虽然我们没有涉及径向渐变，但对你来说应该很容易，因为我们已经学到了很多关于径向形状和渐变的知识。该方法的签名如下：

```js
context.createRadialGradient(startX,startY,startR, endX,endY,endR);
```

这里唯一的区别是我们的形状是一个径向形状。我们还想将起始半径和结束半径添加到其中。你可能会想知道为什么我们需要两个甚至更多的半径。那么为什么我们不能根据两个点（起点和终点）之间的距离来确定半径呢？我希望你会对此感到好奇，如果你没有，那么在阅读下一段之前，请先思考一下。

我们可以单独控制半径，主要是为了使我们能够分离半径并使我们能够在不改变实际艺术或重新计算颜色比例的情况下移动绘图中的焦点。一个真正好的方法是在绘制月亮时使用它。月亮的渐变随时间会改变，或者更准确地说，颜色的半径和半径的位置会随时间改变，具体取决于月亮相对于太阳的位置。

我们还没有完成。我们刚刚掌握了关于渐变的所有知识，现在是时候将一些文本整合到其中了。

```js
context.font = "50pt Verdana, sans-serif";
context.fillText("Hello World!", 100, hei/2);
```

我们设置全局字体值，然后创建一个新的文本元素。`fillText`方法有三个参数；第一个是要使用的文本，另外两个是新元素的 x 和 y 位置。

```js
context.strokeStyle = "#ffffff";
context.strokeText("Hello World!", 100, hei/2);
```

在我们的例子中，我们给我们的文本绘制了填充和轮廓。这两个函数是分开调用的。`fillText`方法用于填充形状的内容，而`strokeText`方法用于轮廓文本。我们可以使用其中一个或两个方法，它们可以获得完全相同的参数。

## 还有更多...

有一些更多的选项可以让你去探索。

### 在文本中使用渐变

如果您可以对画布中的任何图形元素进行任何操作，那么您也可以对文本进行操作，例如，在我们的示例中，我们为文本使用了渐变。

```js
grd = context.createLinearGradient(100, hei/2, 200, hei/2+110);
  grd.addColorStop(0, "#ffff00"); 
  grd.addColorStop(1, "#aaaa44");

  context.font = "50pt Verdana, sans-serif";
  context.fillStyle = grd;
```

请注意，我们正在更新我们的渐变。我们上一个渐变对于如此小的文本区域来说太大了。因此，我们正在从文本的开始周围水平绘制一条线，长度为 110 像素。

### 添加阴影和发光

您可以向任何填充元素添加阴影/发光：

```js
context.shadowOffsetX = 0;
  context.shadowOffsetY = 0;
  context.shadowBlur    = 8;
  context.shadowColor   = 'rgba(255, 255, 255, 0.5)';
  context.fillText("Hello World!", 100, hei/2);
```

您可以控制阴影的偏移位置。在我们的例子中，我们希望它成为一个发光的效果，所以我们把阴影放在了我们的元素正下方。当将模糊值设置为阴影时，尝试使用 2 的幂值以提高效率（渲染 2 的幂值更容易）。

请注意，当我们定义阴影颜色时，我们选择使用 RGBA，因为我们希望将 alpha 值设置为 50%。

# 理解像素操作

现在您已经掌握了在画布中绘制的技巧，是时候转向与画布一起工作的新方面了。在画布中，您可以操作像素。它不仅是一个矢量绘图工具，还是一个非常智能的像素编辑器（光栅）。

## 准备就绪

现在我们即将开始读取画布上存在的数据，我们需要了解在处理像素时安全性是如何工作的。为了保护不属于您的内容，与您的主机不同的数据的处理涉及安全问题。我们不会在本节中涵盖这些安全问题，并且将始终使用与我们的代码（或全部本地）在同一域中的图像。

您的第一步是找到您希望使用的图像（我已经将自己的旧图像添加到了源文件中）。在本示例中，我们将重新创建一个像素淡出动画-非常酷，对幻灯片非常有用。

![准备就绪](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_02_09.jpg)

## 如何做...

让我们让我们的代码运行起来，然后分解它看看它是如何工作的。执行以下步骤：

1.  创建一些辅助全局变量：

```js
var context;
var imageData;
var pixelData;
var pixelLen;
var currentLocation=0;
var fadeOutImageInterval;
```

1.  创建一个`init`函数（在接下来的步骤中，所有代码都将在这个函数中）：

```js
function init(){
  //all the rest of the code will go in here
}
```

1.  为 2D 画布 API 创建一个上下文变量：

```js
function init(){
  var canvas = document.getElementById("textCanvas");
  var wid = canvas.width;
  var hei = canvas.height;

  context = canvas.getContext("2d");
```

1.  创建一个新图像：

```js
var oIMG = new Image();
```

1.  添加`onload`监听器逻辑：

```js
oIMG.onload = function(){
  context.drawImage(this, 0,0,this.width,this.height,0,0,wid,hei);
  imageData = context.getImageData(0, 0, wid, hei);
  pixelData = imageData.data;
  pixelLen = pixelData.length;
  fadeOutImageInterval = setInterval(fadeOutImage, 25);
};
```

1.  定义图像源：

```js
oIMG.src = "img/slide2.jpg";

} //end of init function
```

1.  创建一个名为`fadeOutImage`的新函数。这个图像将过渡我们的图像：

```js
function fadeOutImage(){
  var pixelsChanged=0;
  for (var i = 0; i < pixelLen; i +=4) {
    if(pixelData[i]) {
      pixelData[i] =  pixelData[i]-1; // red
      pixelsChanged++;
    }
    if(pixelData[i + 1]){
      pixelData[i + 1] = pixelData[i+1]-1; // green
      pixelsChanged++;
    }
    if(pixelData[i + 2]){
      pixelData[i + 2] = pixelData[i+2]-1; // green
      pixelsChanged++;
    }

  }
  context.putImageData(imageData, 0, 0);

  if(pixelsChanged==0){
    clearInterval(fadeOutImageInterval);	
    alert("we are done fading out");
  }
}
```

您的结果应该看起来像以下截图：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_02_10.jpg)

## 它是如何工作的...

我们将跳过解释我们在早期示例中已经涵盖的内容，比如如何加载图像以及如何使用`drawImage`方法（在本章前面讨论的*将图像整合到我们的艺术品中*配方中涵盖）。

```js
var context;
var imageData;
var pixelData;
var pixelLen;
var currentLocation=0;
var fadeOutImageInterval;
```

我们将在代码中看到这些变量的用法，但所有这些变量都已保存为全局变量，因此无需在函数中重新定义它们。通过一次性定义这些变量，我们提高了应用程序的效率。

真正的新逻辑始于`onLoad`监听器。在我们将图像绘制到画布上后，我们添加了新的逻辑。在下面的代码片段中进行了突出显示：

```js
var oIMG = new Image();
  oIMG.onload = function(){
    context.drawImage(this, 0,0,this.width,this.height,0,0,wid,hei);
 imageData = context.getImageData(0, 0, wid, hei);
 pixelData = imageData.data;
 pixelLen = pixelData.length;
 fadeOutImageInterval = setInterval(fadeOutImage, 25);
  };
  oIMG.src = "img/slide2.jpg";
```

我们现在开始利用在画布区域和全局存储信息的优势。我们存储的第一个变量是`imageData`。这个变量包含了我们画布的所有信息。我们通过调用`context.getImageData`方法来获取这个变量。

```js
context.getImageData(x, y, width, height);
```

`getImageData`函数返回矩形区域的每个像素。我们需要通过定义我们想要的区域来设置它。在我们的情况下，我们希望整个画布区域作为我们的图像设置。

返回的对象（`imageData`）将像素数据信息直接存储在其数据属性（`imageData.data`）中，这是我们直接处理像素时的主要关注点。该对象包含画布中每个像素的所有颜色信息。信息存储在四个单元格（红色、绿色、蓝色和 alpha 通道）中。换句话说，如果我们的应用程序中总共有 100 个像素，我们期望我们的数组在`imageData.data`数组中包含 400 个单元格。

在我们的`onLoad`监听器中完成逻辑之前，还剩下最后一件事要做，那就是触发我们的动画，使我们的图像过渡；为此，我们将添加一个间隔，如下所示：

```js
fadeOutImageInterval = setInterval(fadeOutImage, 25);
```

我们的动画在每 25 毫秒触发一次，直到完成。淡出视图的逻辑发生在我们的`fadeOutImage`函数中。

现在我们已经做好了所有的准备工作，是时候深入了解`fadeoutImage`函数了。在这里，我们将进行实际的像素处理逻辑。该函数的第一步是创建一个变量，用于计算我们的`imageData.data`数组所做的更改次数。当达到所需的更改次数时，我们终止我们的间隔（或在实际应用中可能是动画下一个图像）：

```js
var pixelsChanged=0;
```

现在我们开始通过使用`for`循环遍历所有像素：

```js
for (var i = 0; i < pixelLen; i +=4) {
  //pixel level logic will go in here
}
```

每个像素存储 RGBA 值，因此每个像素在我们的数组中占据四个位置，因此我们每次跳过四个步骤以在像素之间移动。

```js
context.putImageData(imageData, 0, 0);
```

当我们完成了对数据的操作，就该更新画布了。为此，我们只需要将新数据发送回我们的上下文。第二个和第三个参数是 x 和 y 的起始点。

```js
if(pixelsChanged==0){
  clearInterval(fadeOutImageInterval);	
  alert("we are done fading out");
}
```

当我们没有更多的更改时（您可以调整以符合您的愿望，例如当更改的像素少于 100 个时），我们终止间隔并触发警报。

在我们的`for`循环中，我们将降低红色、绿色和蓝色的值，直到它们降至 0。在我们的情况下，由于我们正在计算更改，因此我们还将计数器添加到循环中：

```js
for (var i = 0; i < pixelLen; i +=4) {
  if(pixelData[i]) {
    pixelData[i] =  pixelData[i]-1; // red
    pixelsChanged++;
  }
  if(pixelData[i + 1]){
    pixelData[i + 1] = pixelData[i+1]-1; // green
    pixelsChanged++;

  if(pixelData[i + 2]){
    pixelData[i + 2] = pixelData[i+2]-1; // blue
    pixelsChanged++;
  }

}
```

我们之前提到每个像素在数组中有四个单元格的信息。前三个单元格存储 RGB 值，而第四个存储 alpha 通道。因此，我认为值得注意的是，我们跳过位置`i+3`，因为我们不希望影响 alpha 通道。`pixelData`数组中的每个元素的值都在`0`和`255`之间。换句话说，如果该像素的值为`#ffffff`（白色），所有三个 RGB 单元格的值将等于`255`。顺便说一句，要使这些单元格中的值降至`0`，需要调用我们的函数 255 次，因为单元格中的值将从`255`开始，每次减 1。

我们总是跳过位置`i+3`，因为我们不希望在我们的数组中改变任何内容。我们的值在`255`和`0`之间；换句话说，如果我们的图像的值为`#ffffff`（完全白色像素），我们的函数将下降`255`次才能达到`0`。

### 使图像变为灰度

要使图像或画布变为灰度，我们需要考虑所有的颜色（红色、绿色、蓝色）并将它们混合在一起。混合在一起后，得到一个亮度值，然后我们可以将其应用到所有的像素上。让我们看看它的实际效果：

```js
function grayScaleImage(){
  for (var i = 0; i < pixelLen; i += 4) {
    var brightness = 0.33 * pixelData[i] + 0.33 * pixelData[i + 1] + 0.34 * pixelData[i + 2];
    pixelData[i] = brightness; // red
    pixelData[i + 1] = brightness; // green
    pixelData[i + 2] = brightness; // blue
  }
  context.putImageData(imageData, 0, 0);	
}
```

在这种情况下，我们取红色（`pixelData[i]`），绿色（`pixelData[i+1]`）和蓝色（`pixelData[i+2]`），并使用每种颜色的三分之一来组合在一起得到一种颜色，然后我们将它们全部赋予这个新的平均值。

尝试只改变三个值中的两个，看看会得到什么结果。

### 像素反转

颜色反转图像非常容易，因为我们只需要逐个像素地取最大可能值（`255`）并从中减去当前值：

```js
function colorReverseImage(){
  for (var i = 0; i < pixelLen; i += 4) {
    pixelData[i] = 255-pixelData[i];
    pixelData[i + 1] = 255-pixelData[i+1];
    pixelData[i + 2] = 255-pixelData[i+2];
  }
  context.putImageData(imageData, 0, 0);	
}
```

就是这样！我们讨论了一些像素操作的选项，但限制实际上取决于你的想象力。实验一下，你永远不知道会得到什么结果！
