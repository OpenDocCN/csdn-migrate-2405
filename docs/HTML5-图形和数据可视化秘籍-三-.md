# HTML5 图形和数据可视化秘籍（三）

> 原文：[`zh.annas-archive.org/md5/6DD5FA08597C1F517B2FC929FBC4EC5A`](https://zh.annas-archive.org/md5/6DD5FA08597C1F517B2FC929FBC4EC5A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：走出常规

在本章中，我们将涵盖：

+   通过漏斗（金字塔图表）

+   重新审视线条：使线状图表具有交互性

+   树状映射和递归

+   将用户交互添加到树状映射中

+   制作一个交互式点击计数器

# 介绍

我们已经涵盖了大多数标准图表的基础知识。在这个阶段，是时候让我们的图表变得更有创意了。从本章开始，我们将进入更具创意的、不常用的图表，并重新审视一些旧图表，将动态数据整合到它们中，或者改变它们的布局。

# 通过漏斗（金字塔图表）

很少见到动态创建的金字塔图表。在大多数情况下，它们是在设计和创意上进行完善，当它们到达网络时变成一个.jpg 文件，这正是我想以这个图表开始这一章的原因——它并不像听起来那么复杂。

![通过漏斗（金字塔图表）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_05_01.jpg)

金字塔图表本质上是一种让我们可视化数据变化的方式，这些数据本质上是定量的。它们在较低层和较高层之间有明确的关系。听起来很模糊，所以让我们通过一个例子来解释。

假设在某一年有 X 人完成了他们的第八年学校教育，如果我们跟随同一群人，四年后有多少人完成了他们的第十二年教育？好吧！我们无法知道答案，但我们知道的一件事是，它不可能超过最初的 X 人数。金字塔图表的概念正是这样一个数据体，随着时间或其他因素的变化，通过漏斗的数据越来越少。这是一个非常好的图表，可以比较教育水平、财务、政治参与等方面的情况。

## 准备工作

和往常一样，设置我们的 HTML 文件逻辑。如果需要关于如何启动 HTML 文件的复习，请回到第一章中的*使用 2D 画布进行图形处理*。

## 如何做... 

除了我们标准的 HTML 准备工作之外，我们需要想出我们希望展示的数据来源。让我们开始建立我们的金字塔。直接进入 JS 文件，让我们开始吧。

1.  对于我们的示例，我们将创建一个金字塔，以找出从第一章到第五章阅读本书的人中实际到达第五章的人数（这些数据是虚构的；我希望每个开始阅读的人都能到达那里！）。

```js
var layers = [{label:"Completed Chapter 1", amount:23},
  {label:"Completed Chapter 2", amount:15},
  {label:"Completed Chapter 3", amount:11},
  {label:"Completed Chapter 4", amount:7},
  {label:"Completed Chapter 5", amount:3} ];
```

1.  然后，提供一些图表和样式信息。

```js
var chartInfo= {height:200, width:200};

var s = { outlinePadding:4,
  barSize:16,
  font:"12pt Verdana, sans-serif",
  background:"eeeeee",
  stroke:"cccccc",
  text:"605050"
};
```

### 注意

注意，这是我们第一次区分我们希望画布的大小和图表（漏斗/三角形）的实际大小。另一个重要的事情是，为了使我们的示例在当前格式下工作，我们的三角形高度和宽度（底）必须相同。

1.  定义一些全局辅助变量。

```js
var wid;
var hei;
var totalPixels;
var totalData=0;
var pixelsPerData;
var currentTriangleHeight = chartInfo.height;
```

1.  现在是时候创建我们的`init`函数了。这个函数将在另一个函数的帮助下承担大部分的工作。

```js
function init(){
  var can = document.getElementById("bar");

  wid = can.width;
  hei = can.height;
  totalPixels = (chartInfo.height * chartInfo.width) / 2;
  for(var i in layers) totalData +=layers[i].amount;

  pixelsPerData = totalPixels/totalData;

  var context = can.getContext("2d");
  context.fillStyle = s.background;
  context.strokeStyle = s.stroke;

  context.translate(wid/2,hei/2 - chartInfo.height/2);

  context.moveTo(-chartInfo.width/2 , chartInfo.height);
  context.lineTo(chartInfo.width/2,chartInfo.height);
  context.lineTo(0,0);
  context.lineTo(-chartInfo.width/2 , chartInfo.height);

  for(i=0; i+1<layers.length; i++) findLine(context, layers[i].amount);

  context.stroke();
}
```

1.  我们的函数执行正常的设置并执行样式逻辑，然后创建一个三角形，然后找到正确的点（使用`findLine`函数）我们应该在哪里切割三角形：

```js
function findLine(context,val){
  var newHeight = currentTriangleHeight;
  var pixels = pixelsPerData * val;
  var lines = parseInt(pixels/newHeight); //rounded

  pixels = lines*lines/2; //missing pixels

  newHeight-=lines;

  lines += parseInt(pixels/newHeight);
  currentTriangleHeight-=lines;

  context.moveTo(-currentTriangleHeight/2 , currentTriangleHeight);
  context.lineTo(currentTriangleHeight/2,currentTriangleHeight);
}
```

这个函数根据当前线的数据找到我们三角形上的点。就是这样；现在是时候理解我们刚刚做了什么了。

## 它是如何工作的...

在`init`函数中设置了线条的代码之后，我们准备开始考虑我们的三角形。首先，我们需要找出在我们的三角形内的总像素数。

```js
totalPixels = (chartInfo.height * chartInfo.width) / 2;
```

这很容易，因为我们知道我们的高度和宽度，所以公式非常简单。下一个关键的数据点是总数据量。我们可以创建像素和数据之间的关系。

```js
for(var i in layers) totalData +=layers[i].amount;
```

因此，我们循环遍历所有的数据层，并计算所有数据点的总和。在这个阶段，我们已经准备好找出实际像素的数量。每个数据元素相当于：

```js
pixelsPerData = totalPixels/totalData;
```

设置了我们的描边和填充样式后，我们停下来考虑哪种最好的转换方式可以帮助我们构建我们的三角形。对于我们的三角形，我选择了顶边作为`0,0`点，创建了三角形后：

```js
context.translate(wid/2,hei/2 - chartInfo.height/2);

context.moveTo(-chartInfo.width/2 , chartInfo.height);
context.lineTo(chartInfo.width/2,chartInfo.height);
context.lineTo(0,0);
context.lineTo(-chartInfo.width/2 , chartInfo.height);
```

我们`init`函数的最后两行调用`layers`数组中每个元素的`findLine`方法：

```js
for(i=0; i+1<layers.length; i++) findLine(context, layers[i].amount);
context.stroke();
```

现在是时候深入了解`findLine`函数是如何找到创建线的点的。这个想法非常简单。基本思想是尝试找出完成三角形中像素数量需要多少条线。由于我们不是在建立数学公式，我们不在乎它是否 100%准确，但它应该足够准确以在视觉上工作。

## 还有更多...

让我们开始向我们的调色板引入颜色。

```js
var layers = [{label:"Completed Chapter 1", amount:23, style:"#B1DDF3"},  {label:"Completed Chapter 2", amount:15, style:"#FFDE89"},
  {label:"Completed Chapter 3", amount:11, style:"#E3675C"},
  {label:"Completed Chapter 4", amount:7, style:"#C2D985"},
  {label:"Completed Chapter 5", amount:3, style:"#999999"}];
```

好了，我们完成了简单的部分。现在，是时候重新调整我们的逻辑了。

### 使`findLine`更智能

为了能够创建一个封闭的形状，我们需要有一种改变绘制线的方向的方法，从右到左或从左到右，而不是让它总是朝一个方向。除此之外，我们现在正在使用`moveTo`，因此永远无法创建一个封闭的形状。我们实际上想要的是移动我们的点并绘制一条线：

```js
function findLine(context,val,isMove){
  var newHeight = currentTriangleHeight;
  var pixels = pixelsPerData * val;
  var lines = parseInt(pixels/newHeight); //rounded

  pixels = lines*lines/2; //missing pixels

  newHeight-=lines;

  lines += parseInt(pixels/newHeight);

  currentTriangleHeight-=lines;

 if(isMove){
    context.moveTo(currentTriangleHeight/2,currentTriangleHeight);
 context.lineTo(-currentTriangleHeight/2 , currentTriangleHeight);
 }else{
 context.lineTo(-currentTriangleHeight/2 , currentTriangleHeight);
 context.lineTo(currentTriangleHeight/2,currentTriangleHeight); 
 }
}
```

我们下一个问题是，我们不想改变实际的三角形高度，因为我们将调用这个函数的次数比过去多。为了解决这个问题，我们需要提取一些逻辑。我们将返回创建的新线的数量，这样我们就可以从三角形中外部删除它们。这个操作使我们对视觉有更精细的控制（当我们加入文本时这一点将很重要）。

```js
function findLine(context,val,isMove){
  var newHeight = currentTriangleHeight;
  var pixels = pixelsPerData * val;
  var lines = parseInt(pixels/newHeight); //rounded

  pixels = lines*lines/2; //missing pixels

  newHeight-=lines;

  lines += parseInt(pixels/newHeight);

 newHeight = currentTriangleHeight-lines;

 if(isMove){
 context.moveTo(newHeight/2,newHeight); 
 context.lineTo(-newHeight/2 , newHeight);
 }else{
 context.lineTo(-newHeight/2 , newHeight);
 context.lineTo(newHeight/2,newHeight); 
 }

return lines;
}
```

在这个阶段，我们的`findLine`函数非常智能，能够帮助我们创建封闭的形状，而不需要控制更多（因为它不会改变任何全局数据）。

### 更改`init`中的逻辑以创建形状

现在我们有了一个智能的`findLine`函数，是时候重新编写与在`init`函数中绘制线相关的逻辑了。

```js
var secHeight = 0;
  for(i=0;i<layers.length-1; i++){
    context.beginPath();
    findLine(context, 0,true);
    secHeight = findLine(context, layers[i].amount);
    currentTriangleHeight -= secHeight;
    context.fillStyle = layers[i].style;
    context.fill();	
  }

  context.beginPath();
  findLine(context, 0,true);
  context.lineTo(0,0);
  context.fillStyle = layers[i].style;
  context.fill();
```

首先，我们在循环中绘制所有元素，减去最后一个（因为我们的最后一个元素实际上是一个三角形而不是一条线）。然后，为了帮助我们隐藏我们的数学不准确性，每次循环开始时我们都创建一个新路径，并首先调用我们的`findLine`函数，没有新数据（在上次绘制线的地方绘制线，因为没有数据），然后绘制第二条线，这次使用真实的新数据。

我们对规则的例外是在循环之外创建的，在那里，我们只是手动绘制我们的形状，从最后一行开始，并将`0,0`点添加到它上面，覆盖我们的三角形。

### 将文本添加到我们的图表中

这将很简单，因为我们在调整三角形大小之前已经得到了线数。我们可以使用这些数据来计算我们想要定位文本字段变量的位置，所以让我们做吧：

```js
var secHeight = 0;
  for(i=0;i<layers.length-1; i++){
    context.beginPath();
    findLine(context, 0,true);
    secHeight = findLine(context, layers[i].amount);
    currentTriangleHeight -= secHeight;
    context.fillStyle = layers[i].style;
    context.fill();	
 context.fillStyle = s.text;
 context.fillText(layers[i].label, currentTriangleHeight/2 +secHeight/2, currentTriangleHeight+secHeight/2);
  }

  context.beginPath();
  findLine(context, 0,true);
  context.lineTo(0,0);
  context.fillStyle = layers[i].style;
  context.fill();
 context.fillStyle = s.text;
 context.fillText(layers[i].label, currentTriangleHeight/2 , currentTriangleHeight/2);

```

只需看一下在循环中绘制文本和在循环外绘制文本之间的区别。由于我们在循环中没有获取新的行数据，我们需要通过使用剩余三角形的总大小来改变点逻辑。

# 重温线条：使线图表交互

在这个食谱中，我们将回到我们早期的一个食谱，*在第三章*中创建基于笛卡尔的图表，并为其添加一些用户控制。这个控制使用户能够打开和关闭数据流。

![重温线条：使线图表交互](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_05_02.jpg)

## 准备工作

您需要采取的第一步是从第三章*创建基于笛卡尔坐标的图表*中获取源代码。我们将`03.05.line-revamp.html`和`03.05.line-revamp.js`重命名为`05.02.line-revisit`。

现在我们的文件已经更新，添加我们的 HTML 文件——三个单选按钮组来表示三个数据源（2009 年、2010 年和 2011 年）。

```js
<hr/>

  2009 : <input type="radio" name="i2009" value="-1" /> off
    <input type="radio" name="i2009" value="0" /> line
    <input type="radio" name="i2009" value="1" select="1" /> full<br/>
  2010 : <input type="radio" name="i2010" value="-1" /> off
    <input type="radio" name="i2010" value="0" /> line
    <input type="radio" name="i2010" value="1" select="1" /> full<br/>
  	2011 : <input type="radio" name="i2011" value="-1" /> off
    <input type="radio" name="i2011" value="0" /> line
    <input type="radio" name="i2011" value="1" select="1" /> full<br/>
```

请注意，我已经为每个单选按钮组添加了“i”以表示年份，并将可能的值设置为`-1`、`0`或`1`。

## 如何做...

执行以下步骤：

1.  创建一些常量（不会更改的变量），并设置以下三行，现在默认值已经分配：

```js
var HIDE_ELEMENT = -1;
var LINE_ELEMENT = 0;
var FILL_ELEMENT = 1;

var elementStatus={ i2009:FILL_ELEMENT,
  i2010:FILL_ELEMENT,
  i2011:FILL_ELEMENT};
```

1.  是时候将创建图表的逻辑移到一个单独的函数中。在初始化画布之后的所有内容都将被移出。

```js
var context;

function init(){
  var can = document.getElementById("bar");

  wid = can.width;
  hei = can.height;
  context = can.getContext("2d");

  drawChart();
}
```

1.  更新单选框以突出显示当前选定的内容，并为所有单选按钮添加`onchange`事件。

```js
function init(){
  var can = document.getElementById("bar");

  wid = can.width;
  hei = can.height;
  context = can.getContext("2d");

  drawChart();

  var radios ;
    for(var id in elementStatus){
      radios = document.getElementsByName(id);
      for (var rid in radios){
      radios[rid].onchange = onChangedRadio;
      if(radios[rid].value == elementStatus[id] )
      radios[rid].checked = true;	
    }
  }

}
```

1.  在我们的`drawChart`函数中进行一些更新。我们的目标是将新的控制器`elementStatus`纳入线条的绘制中。

```js
function drawChart(){
  context.lineWidth = 1;
  context.fillStyle = "#eeeeee";
  context.strokeStyle = "#999999";
  context.fillRect(0,0,wid,hei);
  context.font = "10pt Verdana, sans-serif";
  context.fillStyle = "#999999";

  context.moveTo(CHART_PADDING,CHART_PADDING);
  context.rect(CHART_PADDING,CHART_PADDING,wid-CHART_PADDING*2,hei-CHART_PADDING*2);
  context.stroke();
  context.strokeStyle = "#cccccc";
  fillChart(context,chartInfo);

  if(elementStatus.i2011>-1) addLine(context,formatData(a2011,   "/2011","#B1DDF3"),"#B1DDF3",elementStatus.i2011==1);
  if(elementStatus.i2010>-1) addLine(context,formatData(a2010, "/2010","#FFDE89"),"#FFDE89",elementStatus.i2010==1);
  if(elementStatus.i2009>-1) addLine(context,formatData(a2009, "/2009","#E3675C"),"#E3675C",elementStatus.i2009==1);

}
```

1.  最后但并非最不重要的是，让我们将逻辑添加到我们的`onChangedRadio`函数中。

```js
function onChangedRadio(e){	
  elementStatus[e.target.name] = e.target.value;
  context.clearRect(0,0,wid,hei);
  context.beginPath();
  drawChart();
}
```

就是这样！我们刚刚在图表中添加了用户交互。

## 它是如何工作的...

我们没有提前计划在此图表上进行用户交互。因此，我们需要重新审视它以更改一些逻辑。当 Canvas 绘制某物时，就是这样，它将永远存在！我们不能只删除一个对象，因为 Canvas 中没有对象，因此我们需要一种按需重新绘制的方法。为了实现这一点，我们需要从`init`函数中提取所有绘图逻辑，并创建`drawChart`函数。除了在函数末尾添加我们的逻辑之外，我们还需要添加函数的开始部分：

```js
context.lineWidth = 1;
```

尽管我们最初计算出用作背景宽度的默认值，在第二次重绘中，我们的画布仍然会保留其上次的大小（在我们的情况下可能是`3`），因此我们将其重置为原始值。

我们使用一个名为`elementStatus`的对象来存储图表上每条线的当前状态。它可以存储的值如下：

+   `-1`：不绘制

+   `0`：绘制无填充的线

+   `1`：绘制填充

因此，我们在函数末尾添加以下逻辑：

```js
if(elementStatus.i2011>-1) addLine(context,formatData(a2011, "/2011","#B1DDF3"),"#B1DDF3",elementStatus.i2011==1);
```

由于逻辑重复三次，让我们只关注其中一个。如果愿意，我们可以使用我们的常量变量使逻辑更容易查看。

```js
if(elementStatus.i2011!=HIDE_ELEMENT)
  addLine(context,formatData(a2011, "/2011","#B1DDF3"),"#B1DDF3",elementStatus.i2011==FILL_ELEMENT);
```

逻辑分解为第一个`if`语句，测试我们的内容是否应该隐藏。如果我们确定应该添加这行，我们通过将当前值与`FILL_ELEMENT`进行比较的结果发送到填充/线参数中来绘制它，根据此操作的结果有两种变化。

## 还有更多...

不幸的是，因为我们没有使用任何开源库，内置的 HTML 功能不允许我们为单选按钮组设置事件，因此我们需要找到它们并使用我们在`elementStatus`控制器中存储的 ID 为它们添加`onchange`事件。

```js
var radios ;
  for(var id in elementStatus){
    radios = document.getElementsByName(id);
    for (var rid in radios){
      radios[rid].onchange = onChangedRadio;
 if(radios[rid].value == elementStatus[id] ) radios[rid].checked = true; 
    }

  }
```

注意高亮显示的代码。在这里，我们正在检查当前单选按钮的值是否与`elementStatus`中的元素值匹配。如果是，这意味着单选按钮将被选中。

### 分解 onChangedRadio 的逻辑

让我们再来看看这个函数中的逻辑：

```js
elementStatus[e.target.name] = e.target.value;
```

我们要做的第一件事是将新选择的值保存到我们的`elementStatus`控制器中。

```js
context.clearRect(0,0,wid,hei);
```

接着我们清空画布上的所有内容。

```js
context.beginPath();
```

接下来，清空并开始一个新路径。

```js
drawChart();
```

然后开始重新绘制所有内容，我们在`elementStatus`中的新参数将验证正确的内容将被绘制。

## 另请参阅

+   第三章*创建基于笛卡尔坐标的图表*中的*构建线图*配方

# 树状映射和递归

树状映射使我们能够从鸟瞰视角深入了解数据。与比较图表相反——例如我们到目前为止创建的大多数图表——树状映射将树状结构的数据显示为一组嵌套的矩形，使我们能够可视化它们的数量特性和关系。

![树状映射和递归](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_05_03.jpg)

让我们从仅展示一级信息的树状映射开始。

## 准备工作

我们将从世界上的人数开始我们的应用程序，以百万为单位，按大陆划分（基于 2011 年的公共数据）。

```js
var chartData = [
  {name: "Asia", value:4216},
  {name: "Africa",value:1051},
  {name: "The Americas and the Caribbean", value:942},
  {name: "Europe", value:740},
  {name: "Oceania", value:37}
];
```

我们将在我们的示例中稍后更新这个数据源，所以请记住这个数据集是临时的。

## 如何做...

我们将从创建一个简单的、工作的、平面树状图开始。让我们直接开始，找出创建树状图所涉及的步骤：

1.  让我们在数据集的顶部添加一些辅助变量。

```js
var wid;
var hei;
var context;
var total=0;
```

1.  创建`init`函数。

```js
function init(){
  var can = document.getElementById("bar");

  wid = can.width;
  hei = can.height;
  context = can.getContext("2d");

  for(var item in chartData) total += chartData[item].value;

  context.fillRect(0,0,wid,hei);
  context.fillStyle = "RGB(255,255,255)";
  context.fillRect(5,5,wid-10,hei-10);
  context.translate(5,5);
  wid-=10;
  hei-=10;

  drawTreeMap(chartData);

}
```

1.  创建函数`drawTreeMap`。

```js
function drawTreeMap(infoArray){
  var percent=0;
  var cx=0;
  var rollingPercent = 0;
  for(var i=0; i<infoArray.length; i++){
    percent = infoArray[i].value/total;
    rollingPercent +=percent
    context.fillStyle = formatColorObject(getRandomColor(255));
    context.fillRect(cx,0 ,wid*percent,hei);
    cx+=wid*percent;
    if(rollingPercent > 0.7) break;

  }

  var leftOverPercent = 1-rollingPercent;
  var leftOverWidth = wid*leftOverPercent;
  var cy=0;
  for(i=i+1; i<infoArray.length; i++){
    percent = (infoArray[i].value/total)/leftOverPercent;
    context.fillStyle = formatColorObject(getRandomColor(255));
    context.fillRect(cx,cy ,leftOverWidth,hei*percent);
    cy+=hei*percent;
  }

}
```

1.  创建一些格式化函数来帮助我们为我们的树状映射块创建一个随机颜色。

```js
function formatColorObject(o){
  return "rgb("+o.r+","+o.g+","+o.b+")";
}

function getRandomColor(val){
  return {r:getRandomInt(255),g:getRandomInt(255),b:getRandomInt(255)};
}

function getRandomInt(val){
  return parseInt(Math.random()*val)+1
}
```

在创建这么多格式化函数时有点过度，它们的主要目标是在我们准备进行下一步时帮助我们——在我们的数据中创建更多深度（有关更多细节，请参阅本食谱中的*还有更多...*部分）。

## 它是如何工作的...

让我们从最初的想法开始。我们的目标是创建一个地图，展示我们矩形区域内更大的体积区域，并在一侧留下一条条带以展示较小的区域。所以，让我们从我们的`init`函数开始。我们的基本入门工作之外的第一个任务是计算实际总数。我们通过循环遍历我们的数据源来做到这一点，因此：

```js
for(var item in chartData) total += chartData[item].value;
```

我们继续设计一些东西，并且让我们的工作区比总画布大小小 10 像素。

```js
CONTEXT.FILLRECT(0,0,WID,HEI);
CONTEXT.FILLSTYLE = "RGB(255,255,255)";
CONTEXT.FILLRECT(5,5,WID-10,HEI-10);
CONTEXT.TRANSLATE(5,5);
WID-=10;
HEI-=10;

drawTreeMap(chartData);
```

是时候来看看我们的`drawTreeMap`函数是如何工作的了。首先要注意的是，我们发送一个数组而不是直接使用我们的数据源。我们这样做是因为我们希望这个函数在我们开始构建这种可视化类型的内部深度时可以被重复使用。

```js
function drawTreeMap(infoArray){...}
```

我们的函数从几个辅助变量开始（`percent`变量将存储循环中的当前`percent`值）。我们的矩形的`cx`（当前 x）位置和`rollingPercent`将跟踪我们的总图表完成了多少。

```js
var percent=0;
var cx=0;
var rollingPercent = 0;
```

是时候开始循环遍历我们的数据并绘制出矩形了。

```js
for(var i=0; i<infoArray.length; i++){
  percent = infoArray[i].value/total;
  rollingPercent +=percent
  context.fillStyle =
  formatColorObject(getRandomColor(255));
  context.fillRect(cx,0 ,wid*percent,hei);
  cx+=wid*percent;
```

在我们完成第一个循环之前，我们将测试它，看看我们何时越过我们的阈值（欢迎您调整该值）。当我们达到它时，我们需要停止循环，这样我们就可以开始按高度而不是宽度绘制我们的矩形。

```js
if(rollingPercent > 0.7) break;
}
```

在我们开始处理我们的框之前，它们占据了全部剩余的宽度并扩展到高度，我们需要一些辅助变量。

```js
var leftOverPercent = 1-rollingPercent;
var leftOverWidth = wid*leftOverPercent;
var cy=0;
```

从现在开始，我们需要根据剩余空间的大小计算每个元素，我们将计算值（`leftOverPercent`），然后我们将提取我们形状的剩余宽度，并启动一个新的`cy`变量来存储当前的 y 位置。

```js
for(i=i+1; i<infoArray.length; i++){
  percent = (infoArray[i].value/total)/leftOverPercent;
  context.fillStyle = formatColorObject(getRandomColor(255));
  context.fillRect(cx,cy ,leftOverWidth,hei*percent);
  cy+=hei*percent;
}
```

我们从比我们离开的值高一个值开始我们的循环（因为我们在之前的循环中打破了它之前，我们没有机会更新它的值并绘制到我们剩余区域的高度。

请注意，在两个循环中我们都使用了`formatColorObject`和`getRandomColor`。这些函数的分解是为了让我们在下一部分中更容易操纵返回的颜色。

## 还有更多...

为了使我们的图表真正具有额外的功能，我们需要一种方法来使它能够以至少第二个较低级别的数据显示数据的方式。为此，我们将重新审视我们的数据源并对其进行重新编辑：

```js
var chartData = [
  {name: "Asia", data:[
    {name: "South Central",total:1800},
    {name: "East",total:1588},
    {name: "South East",total:602},
    {name: "Western",total:238},
    {name: "Northern",total:143}
  ]},
  {name: "Africa",total:1051},
  {name: "The Americas and the Caribbean", data:[
    {name: "South America",total:396},
    {name: "North America",total:346},
    {name: "Central America",total:158},
    {name: "Caribbean",total:42}
  ]},
  {name: "Europe", total:740},
  {name: "Oceania", total:37}
];
```

现在我们有了世界上两个地区的更深入的子地区的视图。是时候修改我们的代码，使其能够再次处理这些新数据了。

### 更新`init`函数——重新计算总数

在`init`函数中，我们需要执行的第一步是用一个新的循环替换当前的总循环，这个新循环可以深入到元素中计算真正的总数。

```js
var val;
var i;
for(var item in chartData) {
  val = chartData[item];
  if(!val.total && val.data){
    val.total = 0;
    for( i=0; i<val.data.length; i++)
    val.total+=val.data[i].total;
  }

  total += val.total;
}
```

实质上，我们正在检查是否没有总数，以及是否有数据源。如果是这样，我们就开始一个新的循环来计算我们元素的实际总数——现在您可以尝试将这个逻辑变成一个递归函数（这样您就可以有更多层的数据）。

接下来，我们将更改`drawTreeMap`并准备将其变成一个递归函数。为了实现这一点，我们需要从中提取全局变量，并将它们作为函数的参数发送。

```js
drawTreeMap(chartData,wid,hei,0,0,total);
```

### 将 drawTreeMap 转换为递归函数

让我们更新我们的函数以启用递归操作。我们首先添加一个额外的新参数来捕获最新的颜色。

```js
function drawTreeMap(infoArray,wid,hei,x,y,total,clr){
  var percent=0;
  var cx=x ;
  var cy=y;

  var pad = 0;
  var pad2 = 0;

  var rollingPercent = 0;
  var keepColor = false;
 if(clr){ //keep color and make darker
 keepColor = true;
 clr.r = parseInt(clr.r *.9);
 clr.g = parseInt(clr.g *.9);
 clr.b = parseInt(clr.b *.9);
 pad = PAD*2; 
 pad2 = PAD2*2;
 }

```

如果我们传递了一个`clr`参数，我们需要在所有新创建的矩形中保持该颜色，并且我们需要在形状周围添加一些填充，以便更容易看到它们。我们还通过减去其所有 RGA 属性的 10%使颜色变暗一点。

下一步是添加填充和递归逻辑。

```js
for(var i=0; i<infoArray.length; i++){
  percent = infoArray[i].total/total;
  rollingPercent +=percent
 if(!keepColor){
 clr = getRandomColor(255);
 }

 context.fillStyle = formatColorObject(clr);
 context.fillRect(cx+pad ,cy+pad ,wid*percent - pad2,hei-pad2);
 context.strokeRect(cx+pad ,cy+pad ,wid*percent - pad2,hei-pad2);
 if(infoArray[i].data){
 drawTreeMap(infoArray[i].data,parseInt(wid*percent - PAD2),hei - PAD2,cx+ PAD,cy + PAD,infoArray[i].total,clr);
 }
  cx+=wid*percent;
  if(rollingPercent > 0.7) break;

}
```

同样的逻辑也在第二个循环中实现了（查看源文件以了解详情）。

### 将数据和总数转换为递归数据

让我们首先更新我们的树数据，使其真正递归（完整数据集请参考源代码）。

```js
...
{name: "Asia", data:[
  {name: "South Central",total:1800},
  {name: "East",total:1588},
  {name: "South East",total:602},
  {name: "Western",total:238},
  {name: "Northern",data:[{name: "1",data:[
    {name: "2",total:30},
    {name: "2",total:30}
  ]},
  {name: "2",total:53},
  {name: "2",total:30}
]}  ...
```

现在，我们有一个具有四个以上信息级别的树状图，我们可以重新审视我们的代码，并解决我们最后的问题，验证我们的总数在所有级别上始终是最新的。为了解决这个问题，我们将计算总数的逻辑提取到一个新函数中，并更新`init`函数中的`total`行。

```js
function init(){
  var can = document.getElementById("bar");

  wid = can.width;
  hei = can.height;
  context = can.getContext("2d");

  total = calculateTotal(chartData); //recursive function
...
```

是时候创建这个神奇的（递归）函数了。

```js
function calculateTotal(chartData){
  var total =0;
  var val;
  var i;
  for(var item in chartData) {
    val = chartData[item];
    if(!val.total && val.data)
      val.total = calculateTotal(val.data);

    total += val.total;
  }

return total;

}
```

逻辑与以前非常相似，唯一的区别是所有数据条目都是函数内部的，并且每次需要处理另一层数据时，它都会以递归的方式重新发送到同一个函数中，直到所有数据都解析完毕——直到它返回总数。

## 另请参阅

+   *将用户交互添加到树映射*教程

# 将用户交互添加到树映射

到目前为止，我们在示例中限制了用户的交互。在我们最后的一个示例中，我们以一种受控的方式添加和删除图表元素；在这个示例中，我们将使用户能够深入图表并通过创建一个真正无尽的体验来查看更多细节（如果我们只有无尽的数据可以挖掘）。

在下图中，左侧是初始状态，右侧是用户点击一次后的状态（图表重新绘制以展示被点击的区域）。

![将用户交互添加到树映射](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_05_04.jpg)

考虑当用户点击图表时的情况（例如，点击左侧矩形后生成的下一张图片——树状图将更新并放大到该区域）。

![将用户交互添加到树映射](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_05_05.jpg)

## 准备工作

为了正确使用这个示例，您需要从我们上一个教程*树映射和递归*开始，并调整它以适应这个示例。

## 如何做...

这是我们的第一个示例，我们使我们的画布区域具有交互性。在接下来的几步中，我们将从上一个示例中添加一些逻辑到我们的教程中，以使用户能够放大或缩小它：

1.  新增一个全局变量，

```js
var currentDataset;
```

1.  存储发送到树映射函数的当前数据。

```js
currentDataset = chartData;
drawTreeMap(chartData,wid,hei,0,0,total);
```

1.  在我们的画布区域添加一个`click`事件。

```js
can.addEventListener('click', onTreeClicked, false);
```

1.  创建`onTreeClick`事件。

```js
function onTreeClick(e) {
  var box;
  for(var item in currentDataset){
    if(currentDataset[item].data){
      box = currentDataset[item].box;
      if(e.x>= box.x && e.y>= box.y &&
      e.x<= box.x2 && e.y<= box.y2){
        context.clearRect(0,0,wid,hei);
        drawTreeMap(currentDataset[item].data,wid,hei,0,0,currentDataset[item].total);
        currentDataset = currentDataset[item].data;

      break;
      }

    }
  }
}
```

1.  在`drawTreemap`中两次绘制矩形——第一次在第一个循环中，第二次在第二个循环中。让我们用一个外部函数来替换它——替换绘制矩形的`for`循环行：

```js
drawRect(cx+pad ,cy+pad ,wid*percent – pad2,hei-pad2,infoArray[i]);
```

1.  是时候创建矩形函数了。

```js
function drawRect(x,y,wid,hei,dataSource){
  context.fillRect(x,y,wid,hei);
  context.strokeRect(x,y,wid,hei);
  dataSource.box = {x:x,y:y,x2:x+wid,y2:y+hei};

}
```

就是这样！我们有一个完全功能的、深层次的、与用户无限交互的图表（只取决于我们有多少数据）。

## 它是如何工作的...

Canvas 元素目前不支持与对象交互的智能方式。由于画布中没有对象，一旦创建元素，它就会变成位图，并且其信息将从内存中删除。幸运的是，我们的示例是由矩形构成的，这样就更容易识别我们点击的元素。我们需要在内存中存储我们绘制的每个元素的当前框位置。

因此，我们逻辑的第一步是我们在步骤 6 中做的最后一件事。我们想捕获构成我们矩形的点，这样在我们的`click`事件中，我们就可以弄清楚我们的点与矩形的关系：

```js
function onTreeClick(e) {
   var box;
  for(var item in currentDataset){
    if(currentDataset[item].data){
```

我们循环遍历我们的数据源（当前的数据源），并检查我们当前所在的元素是否有数据源（即子元素）；如果有，我们继续，如果没有，我们将跳过下一个元素来测试它。

现在我们知道我们的元素有子元素，我们准备看看我们的点是否在元素的范围内。

```js
box = currentDataset[item].box;
if(e.x>= box.x && e.y>= box.y &&
   e.x<= box.x2 && e.y<= box.y2){
```

如果是，我们准备重新绘制树状图，并用当前更深的数据集替换我们当前的数据集。

```js
context.clearRect(0,0,wid,hei);
drawTreeMap(currentDataset[item].data,wid,hei,0,0,currentDataset[item].total);
currentDataset = currentDataset[item].data;

break;
```

然后我们退出循环（使用`break`语句）。请注意，我们做的最后一件事是更新`currentDataset`，因为我们仍然需要从中获取信息以将总数据发送到`drawTreeMap`。当我们使用完它后，我们准备用新的数据集覆盖它（之前的子元素变成了下一轮的主要参与者）。

## 还有更多...

目前，没有办法在不刷新一切的情况下返回。因此，让我们添加到我们的逻辑中，如果用户点击没有子元素的元素，我们将恢复到原始地图。

### 回到主要的树状图

让我们将以下代码添加到`click`事件中：

```js
function onTreeClick(e) {
   var box;
  for(var item in currentDataset){
    if(currentDataset[item].data){
      box = currentDataset[item].box;
      if(e.x>= box.x && e.y>= box.y &&
      e.x<= box.x2 && e.y<= box.y2){
        context.clearRect(0,0,wid,hei);
        drawTreeMap(currentDataset[item].data,wid,hei,0,0,currentDataset[item].total);
        currentDataset = currentDataset[item].data;

      break;
      }

    }else{
      currentDataset = chartData;
      drawTreeMap(chartData,wid,hei,0,0,total);

    }
  }
}
```

太棒了！我们刚刚完成了为用户创建一个完全互动的体验，现在轮到你来让它看起来更好一些了。添加一些悬停标签和所有可视化效果，这将使您的图表在视觉上更加愉悦，并有助于理解。

# 创建一个交互式点击计量器

在下一个示例中，我们将专注于客户端编程的一个更强大的特性——与用户交互的能力和动态更新数据的能力。为了简单起见，让我们重新访问一个旧图表——第三章中的条形图，*创建基于笛卡尔坐标的图表*——并集成一个计数器，它将计算用户在任何给定秒内点击 HTML 文档的次数，并相应地更新图表。

![创建一个交互式点击计量器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_05_06.jpg)

## 如何做...

大部分步骤都会很熟悉，如果你曾经在第三章中的条形图上工作过，*创建基于笛卡尔坐标的图表*。因此，让我们运行它们，然后专注于新的逻辑：

1.  让我们创建一些辅助变量。

```js
var currentObject = {label:1,
  value:0,
  style:"rgba(241, 178, 225, .5)"};
  var colorOptions = ["rgba(241, 178, 225, 1)","#B1DDF3","#FFDE89","#E3675C","#C2D985"];

  var data = [];

var context;
var wid;
var hei;
```

1.  接下来是我们的`init`函数。

```js
function init(){

  var can = document.getElementById("bar");
  wid = can.width;
  hei = can.height;

  context = can.getContext("2d");

  document.addEventListener("click",onClick);
  interval = setInterval(onTimeReset,1000);
  refreshChart();
}
```

1.  现在是时候创建`onTimeReset`函数了。

```js
function onTimeReset(){
  if(currentObject.value){
    data.push(currentObject);
    if(data.length>25) data = data.slice(1);
    refreshChart();	
  }
  currentObject = {label:currentObject.label+1, value:0, style: colorOptions[currentObject.label%5]};

}
```

1.  下一步是创建`onClick`监听器。

```js
function onClick(e){
  currentObject.value++;
  refreshChart();
}
```

1.  现在创建`refreshChart`函数。

```js
function refreshChart(){
  var newData = data.slice(0);
  newData.push(currentObject);

  drawChart(newData);
}
```

1.  最后但并非最不重要的是，让我们创建`drawChart`（它的大部分逻辑与第三章中讨论的`init`函数相同，*创建基于笛卡尔坐标的图表*）。

```js
function drawChart(data){
  context.fillStyle = "#eeeeee";
  context.strokeStyle = "#999999";
  context.fillRect(0,0,wid,hei);

  var CHART_PADDING = 20;

  context.font = "12pt Verdana, sans-serif";
  context.fillStyle = "#999999";

  context.moveTo(CHART_PADDING,CHART_PADDING);
  context.lineTo(CHART_PADDING,hei-CHART_PADDING);
  context.lineTo(wid-CHART_PADDING,hei-CHART_PADDING);

  var stepSize = (hei - CHART_PADDING*2)/10;
  for(var i=0; i<10; i++){
    context.moveTo(CHART_PADDING, CHART_PADDING + i*stepSize);
    context.lineTo(CHART_PADDING*1.3,CHART_PADDING + i*stepSize);
    context.fillText(10-i, CHART_PADDING*1.5, CHART_PADDING + i*	stepSize + 6);
  }
  context.stroke();

  var elementWidth =(wid-CHART_PADDING*2)/ data.length;
  context.textAlign = "center";
  for(i=0; i<data.length; i++){
    context.fillStyle = data[i].style;
    context.fillRect(CHART_PADDING +elementWidth*i ,hei-CHART_PADDING - data[i].value*stepSize,elementWidth,data[i].value*stepSize);
    context.fillStyle = "rgba(255, 255, 225, 0.8)";
    context.fillText(data[i].label, CHART_PADDING +elementWidth*(i+.5), hei-CHART_PADDING*1.5);

  }
}
```

就是这样！我们有一个交互式图表，它将每秒更新一次，取决于您在 1 秒内点击鼠标的次数——我假设没有人可以在一秒内点击超过 10 次，但我已经成功做到了（使用两只手）。

## 它是如何工作的...

让我们专注于第三章中数据变量的分解，*创建基于笛卡尔的图表*。我们之前在数据对象中准备好了所有数据。这一次，我们保持数据对象为空，而是将一个数据行放在一个单独的变量中。

```js
var currentObject = {label:1,
  value:0,
  style:"rgba(241, 178, 225, .5)"};
var data = [];
```

每次用户点击时，我们都会更新`currentObject`的计数器，并刷新图表，从而使用户体验更加动态和实时。

```js
function onClick(e){
  currentObject.value++;
  refreshChart();
}
```

我们在`init`函数中设置间隔如下：

```js
interval = setInterval(onTimeReset,1000);
```

每秒钟，函数都会检查用户在那段时间内是否有任何点击，如果有，它会确保我们将`currentObject`推入数据集中。如果数据集的大小大于`25`，我们就会将其中的第一项删除，并刷新图表。无论我们创建什么，一个新的空对象都会被标记上显示当前时间的新标签。

```js
function onTimeReset(){
  if(currentObject.value){
    data.push(currentObject);
    if(data.length>25) data = data.slice(1);
    refreshChart();
}
  currentObject = {label:currentObject.label+1, value:0, style: colorOptions[currentObject.label%5]};

}
```

在我们结束这个示例之前，你应该看一下最后一件事：

```js
function refreshChart(){
  var newData = data.slice(0);
  newData.push(currentObject);

  drawChart(newData);

}
```

我们逻辑的这一部分真的是让我们能够在用户点击按钮时更新数据的关键。我们想要有一个新的数组来存储新数据，但我们不希望当前元素受到影响，所以我们通过将新数据对象添加到其中来复制数据源，然后将其发送到创建图表。


# 第六章：将静态事物变得生动起来

在本章中，我们将涵盖以下主题：

+   堆叠图形层

+   转向面向对象的视角

+   动画独立层

+   添加一个交互式图例

+   创建一个上下文感知的图例

# 介绍

到目前为止，保持组织和清洁的重要性并不像完成我们的项目那样重要，因为我们的项目相对较小。本章将通过首先使一切都变得动态，然后创建一个更面向对象的程序，使我们更容易分离任务并减少我们的代码量，为我们带来一些新的习惯。经过所有这些辛苦的工作，我们将重新审视我们的应用程序，并开始添加额外的逻辑，以使我们的应用程序逐层动画化。

本章是重构实践的一个很好的资源。在本章的前半部分，我们将专注于改进我们的代码结构，以使我们能够在本章的后半部分拥有我们需要的控制水平。

# 堆叠图形层

在我们可以在画布上进行任何真正的动画之前，我们真的需要重新思考在一个画布层上构建一切的概念。一旦画布元素被绘制，就非常难以对其进行微小的细微变化，比如特定元素的淡入效果。我们将重新访问我们的一个著名图表，柱状图，我们在早期章节中多次玩耍和增强。在本章中，我们的目标将是打破逻辑并使其更加模块化。在这个配方中，我们将分离层。每一层都将在我们准备好进行动画时给我们更多的控制。

## 准备工作

首先从上一章中获取最新的文件：`05.02.line-revisit.html`和`05.02.line-revisit.js`。

## 如何做...

对 HTML 文件进行以下更改：

1.  更新 HTML 文件以包含更多的画布元素（每个绘制线条一个）：

```js
<body onLoad="init();" style="background:#fafafa">
    <h1>Users Changed between within a year</h1>
    <div class="graphicLayers" >
      <canvas id="base" class="canvasLayer" width="550" height="400"> </canvas>

      <canvas id="i2011" class="canvasLayer" width="550" height="400"> </canvas>
      <canvas id="i2010" class="canvasLayer" width="550" height="400"> </canvas>
      <canvas id="i2009" class="canvasLayer" width="550" height="400"> </canvas>

  </div>
  <div class="controllers">
  2009 : <input type="radio" name="i2009" value="-1" /> off
        <input type="radio" name="i2009" value="0" /> line
        <input type="radio" name="i2009" value="1" select="1" /> full ||
    2010 : <input type="radio" name="i2010" value="-1" /> off
        <input type="radio" name="i2010" value="0" /> line
        <input type="radio" name="i2010" value="1" select="1" /> full ||
    2011 : <input type="radio" name="i2011" value="-1" /> off
        <input type="radio" name="i2011" value="0" /> line
        <input type="radio" name="i2011" value="1" select="1" /> full
  </div>
</body>
</html>
```

1.  添加一个 CSS 脚本，使层叠起来：

```js
<head>
    <title>Line Chart</title>
    <meta charset="utf-8" />
    <style>
    .graphicLayers {
    	position: relative;	
    	left:100px
    }

    .controllers {
      position: relative;	
      left:100px;
      top:400px;

    }

    .canvasLayer{
      position: absolute; 
      left: 0; 
      top: 0; 
    }
    </style>
  <script src="img/06.01.layers.js"></script>		
  </head>
```

让我们进入 JavaScript 文件进行更新。

1.  添加一个`window.onload`回调函数（在代码片段中突出显示的更改）：

```js
window.onload = init;

function init(){
```

1.  从全局范围中删除变量`context`（删除高亮显示的代码片段）：

```js
var CHART_PADDING = 20;
var wid;
var hei;
var context;

```

1.  将所有柱线信息合并到一个对象中，以便更容易控制（删除所有高亮显示的代码片段）：

```js
var a2011 = [38,65,85,111,131,160,187,180,205,146,64,212];
var a2010 = [212,146,205,180,187,131,291,42,98,61,74,69];
var a2009 = [17,46,75,60,97,131,71,52,38,21,84,39];

var chartInfo= { y:{min:0, max:300, steps:5,label:"users"},
        x:{min:1, max:12, steps:11,label:"months"}
      };

var HIDE_ELEMENT = -1;
var LINE_ELEMENT = 0;
var FILL_ELEMENT = 1;

var elementStatus={i2009:FILL_ELEMENT,i2010:FILL_ELEMENT,i2011:FILL_ELEMENT};

var barData = {
        i2009:{
          status:	FILL_ELEMENT,
          style: "#E3675C",
          label: "/2009",
          data:[17,46,75,60,97,131,71,52,38,21,84,39]
        },
        i2010:{
          status:	FILL_ELEMENT,
          style: "#FFDE89",
          label: "/2010",
          data:[212,146,205,180,187,131,291,42,98,61,74,69]
        },
        i2011:{
          status:	FILL_ELEMENT,
          style: "#B1DDF3",
          label: "/2011",
          data:[38,65,85,111,131,160,187,180,205,146,64,212]
        }

      };
```

1.  从`init`函数中删除所有画布逻辑，并将其添加到`drawChart`函数中：

```js
function init(){
  var can = document.getElementById("bar");

  wid = can.width;
  hei = can.height;
  context = can.getContext("2d");

  drawChart();

  var radios ;
  for(var id in elementStatus){
    radios = document.getElementsByName(id);
    for (var rid in radios){
       radios[rid].onchange = onChangedRadio;
      if(radios[rid].value == elementStatus[id] ) radios[rid].checked = true;	 
    }

  }

}

function drawChart(){
 var can = document.getElementById("base");

 wid = can.width;
 hei = can.height;
 var context = can.getContext("2d");
...
```

1.  在`init`函数中更新对新数据对象的引用：

```js
function init(){
  drawChart();

  var radios ;
 for(var id in barData){
    radios = document.getElementsByName(id);
    for (var rid in radios){
       radios[rid].onchange = onChangedRadio;
 if(radios[rid].value == barData[id].status ) radios[rid].checked = true; 
    }

  }

}
```

1.  在`drawChart`函数中，将线条创建的逻辑提取到一个外部函数中（删除高亮显示的代码片段）：

```js
 if(elementStatus.i2011>-1) addLine(context,formatData(a2011, "/2011","#B1DDF3"),"#B1DDF3",elementStatus.i2011==1);
 if(elementStatus.i2010>-1) addLine(context,formatData(a2010, "/2010","#FFDE89"),"#FFDE89",elementStatus.i2010==1);
 if(elementStatus.i2009>-1) addLine(context,formatData(a2009, "/2009","#E3675C"),"#E3675C",elementStatus.i2009==1);
  changeLineView("i2011",barData.i2011.status);
  changeLineView("i2010",barData.i2010.status);
  changeLineView("i2009",barData.i2009.status);
```

1.  更改`onChangedRadio`回调函数中的逻辑。让它触发对`changeLineView`函数的调用（我们将在下面创建该函数）：

```js
function onChangedRadio(e){
  changeLineView(e.target.name,e.target.value);
}
```

1.  创建函数`changeLineView`：

```js
function changeLineView(id,value){
  barData[id].status = value;
  var dataSource = barData[id];

  can = document.getElementById(id);
  context = can.getContext("2d");
  context.clearRect(0,0,wid,hei);
  if( dataSource.status!=HIDE_ELEMENT){
    context.beginPath();
    addLine(context,formatData(dataSource.data, dataSource.label,dataSource.style),dataSource.style,dataSource.status==1);
  }
}
```

在所有这些更改之后运行 HTML 文件，你应该看到与我们在开始所有这些更改之前看到的完全相同的东西。如果是这样，那么你就处于一个很好的位置。然而，我们目前还看不到任何变化。

## 工作原理...

这个配方的核心是我们的 HTML 文件，它使我们能够将画布元素层叠在彼此之上，由于我们的画布默认是透明的，我们可以看到它下面的元素。在我们的画布上叠加了四个层之后，是时候将我们的背景与线条分开了，因此我们希望将所有的图表背景信息都放在基础画布中：

```js
var can = document.getElementById("base");
```

对于每个线条层，我们使用一个预先配置的画布元素，它已经设置好：

```js
changeLineView("i2011",barData.i2011.status);
changeLineView("i2010",barData.i2010.status);
changeLineView("i2009",barData.i2009.status); 
```

第一个参数既是我们画布的 ID，也是我们在存储线条信息的新对象中使用的键（以保持我们的代码简洁）：

```js
var barData = {
        i2009:{...},
        i2010:{...},
        i2011:{...}	

      };
```

在这个数据对象中，我们有与画布中完全相同数量的元素，名称也完全相同。这样我们就可以非常容易地获取信息，而不需要使用额外的变量或条件。这与创建/更新线条的逻辑相关：

```js
function changeLineView(id,value){
  barData[id].status = value;
  var dataSource = barData[id];

  can = document.getElementById(id);
  context = can.getContext("2d");
  context.clearRect(0,0,wid,hei);
  if( dataSource.status!=HIDE_ELEMENT){
    context.beginPath();
    addLine(context,formatData(dataSource.data, dataSource.label,dataSource.style),dataSource.style,dataSource.status==1);
  }
}
```

我们没有改变我们线条的核心逻辑，而是将逻辑重定向到当前线条的上下文中：

```js
can = document.getElementById(id);
```

这样我们就可以提取任何直接提及年份或元素的提及，而不直接引用元素名称。这样我们可以添加或删除元素，我们只需要在 HTML 文件中添加另一个画布，添加新属性，并在创建函数中添加线条。这仍然很多，那么在继续前进到更有创意的领域之前，我们如何继续优化这段代码呢？

## 还有更多...

我们这个食谱的最终目标是帮助最小化用户需要进行的更改线条的步骤数量。目前，要添加更多线条，用户需要在三个地方进行更改。接下来的一些优化技巧将帮助我们减少添加/删除线条所需的步骤数量。

### 优化`drawChart`函数

我们的`drawChart`函数经历了一次改头换面，但是现在，当我们创建我们的线条时，我们仍然直接引用我们当前的元素：

```js
  changeLineView("i2011",barData.i2011.status);
  changeLineView("i2010",barData.i2010.status);
  changeLineView("i2009",barData.i2009.status);
```

相反，让我们利用`barData`对象并使用该对象的数据键。这样我们完全可以避免直接引用我们的显式元素的需要，而是依赖于我们的数据源作为信息来源：

```js
  for(var id in barData){
    changeLineView(id,barData[id].status);
  }
```

完美！现在我们`barData`对象中的任何更改都将定义在应用程序启动时最初呈现的元素。我们刚刚减少了用户需要进行的更改次数到两次。

### 进一步简化我们的代码

我们现在比刚开始时要好得多。最初，我们的代码中有三个地方直接引用了图表信息的硬编码值。在最后一次更新中，我们将其减少到了两个（一次在 HTML 文件中，一次在数据源中）。

现在是时候删除另一个硬编码的实例了。让我们删除我们额外的画布，并动态创建它们。

所以让我们从 HTML 文件中删除我们的图表画布元素，并为我们的`<div>`标签设置一个 ID（删除突出显示的代码片段）：

```js
<div id="chartContainer" class="graphicLayers" >
      <canvas id="base" class="canvasLayer" width="550" height="400"> </canvas>

 <canvas id="i2011" class="canvasLayer" width="550" height="400">      </canvas>
 <canvas id="i2010" class="canvasLayer" width="550" height="400">      </canvas>
 <canvas id="i2009" class="canvasLayer" width="550" height="400">      </canvas>

  </div>
```

顺便说一句，我们为包含图层的`<div>`添加了一个 ID，这样我们就可以在 JavaScript 中轻松访问它并进行更改。

现在我们的图层没有任何画布，我们希望在第一次绘制图表时动态创建它们（这发生在`drawChart`函数中，我们刚刚在*优化`drawChart`函数*部分中创建的新`for`循环中）：

```js
var chartContainer = document.getElementById("chartContainer");

  for(var id in barData){
 can = document.createElement("canvas");
 can.id=id;
 can.width=wid;
 can.height=hei; 
 can.setAttribute("class","canvasLayer");
 chartContainer.appendChild(can);

    changeLineView(id,barData[id].status);

  }

}
```

刷新您的 HTML 文件，您会发现我们的画布元素看起来和以前一样。我们还有最后一件事要解决，那就是我们的控制器，它们目前在 HTML 文件中是硬编码的。

### 动态创建单选按钮

另一个可以是动态的部分是我们创建单选按钮。所以让我们从 HTML 文件中删除单选按钮，并为我们的包装器添加一个 ID（删除突出显示的代码片段）：

```js
<div id="chartContainer" class="controllers">
 2009 : <input type="radio" name="i2009" value="-1" /> off
 <input type="radio" name="i2009" value="0" /> line
 <input type="radio" name="i2009" value="1" select="1" /> full ||
 2010 : <input type="radio" name="i2010" value="-1" /> off
 <input type="radio" name="i2010" value="0" /> line
 <input type="radio" name="i2010" value="1" select="1" /> full ||
 2011 : <input type="radio" name="i2011" value="-1" /> off
 <input type="radio" name="i2011" value="0" /> line
 <input type="radio" name="i2011" value="1" select="1" /> full
  </div>
```

回到我们的 HTML 文件，让我们创建一个创建新单选按钮的函数。我们将其称为`appendRadioButton`函数：

```js
function appendRadioButton(container, id,value,text){
  var radioButton = document.createElement("input");
  radioButton.setAttribute("type", "radio");
  radioButton.setAttribute("value", value);
  radioButton.setAttribute("name", id);

  container.appendChild(radioButton);

  container.innerHTML += text;
}
```

最后但同样重要的是在我们开始与它交互之前绘制我们的新按钮：

```js
function init(){
  drawChart();

 var radContainer = document.getElementById("controllers");

 var hasLooped= false;
 for(var id in barData){

 radContainer.innerHTML += (hasLooped ? " || ":"") + barData[id].label +": " ;

 appendRadioButton(radContainer,id,-1," off ");
 appendRadioButton(radContainer,id,0," line ");
 appendRadioButton(radContainer,id,1," full ");
 hasLooped = true;

 }

  var radios ;
  for(id in barData){
    radios = document.getElementsByName(id);
    for (var i=0; i<radios.length; i++){
       radios[i].onchange = onChangedRadio;
      if(radios[i].value == barData[id].status ){
         radios[i].checked = true;	 
      }
    }
  }

}
```

请注意，我们没有将两个`for`循环整合在一起。尽管看起来可能是一样的，但分离是必要的。JavaScript 需要一些时间，几纳秒，才能将元素实际呈现到屏幕上，因此通过分离我们的循环，我们给浏览器一个机会来追赶。创建元素和操作元素之间的分离主要是为了让 JavaScript 有机会在与创建的元素交互之前呈现 HTML 文件。

干得好！我们刚刚完成了更新我们的内容，使其完全动态化。现在一切都通过一个位置控制，即数据源，我们准备开始在接下来的食谱中探索分层画布逻辑。

# 转向面向对象的视角

我们的应用程序一直在不断发展。现在是时候通过将我们的图表更改为更符合面向对象编程的方式来停止了。在这个食谱中，我们将进一步清理我们的代码，并将其中一些转换为对象。我们将继续从上一个食谱*堆叠图形层*中离开的地方继续。

## 准备工作

第一步是获取我们的最新源文件：`06.01.layers.optimized.html`和`06.01.layers.optimized.js`。我们将重命名它们并添加我们的动画逻辑。除了在我们的 HTML 文件中更改引用之外，我们不会在 HTML 文件中做任何其他更改，而是将注意力集中在 JavaScript 文件中。

在 JavaScript 中创建对象的最简单方法之一是使用函数。我们可以创建一个函数，并在函数名称中引用`this`，通过这样做，我们可以将函数视为对象（有关更多详细信息，请参阅本食谱的*工作原理...*部分）。

## 如何做...

让我们立即开始将我们的代码转换为更符合面向对象编程的方式：

1.  我们从 JavaScript 文件开始进行代码更改。创建`LineChart`构造方法：

```js
function LineChart(chartInfo,barData){
  this.chartInfo = chartInfo;
  this.barData = barData;

  this.HIDE_ELEMENT = -1;
  this.LINE_ELEMENT = 0;
  this.FILL_ELEMENT = 1;
  this.CHART_PADDING = 20;

  this.wid;
  this.hei;

  drawChart();

  var radContainer = document.getElementById("controllers");

  var hasLooped= false;
  for(var id in barData){

    radContainer.innerHTML += (hasLooped ? " || ":"") + barData[id].label +": " ;

    appendRadioButton(radContainer,id,-1," off ");
    appendRadioButton(radContainer,id,0," line ");
    appendRadioButton(radContainer,id,1," full ");
    hasLooped = true;

  }

  var radios ;
  for(id in barData){
    radios = document.getElementsByName(id);
    for (var i=0; i<radios.length; i++){
       radios[i].onchange = onChangedRadio;
      if(radios[i].value == barData[id].status ){
         radios[i].checked = true;	 
      }
    }
  }

}
```

1.  让我们更新所有函数，使其成为`LineChart`函数（我们的伪类）的原型：

```js
LineChart.prototype.drawChart =function(){...}
LineChart.prototype.appendRadioButton = function(container, id,value,text){...}
LineChart.prototype.onChangedRadio = function (e){...}
LineChart.prototype.changeLineView = function(id,value){...}
LineChart.prototype.fillChart = function (context, chartInfo){...}
LineChart.prototype.addLine = function(context,data,style,isFill){ ...}
LineChart.prototype.formatData = function(data , labelCopy , style){...}
```

1.  现在让我们来看看真正困难的部分。我们需要用`this`引用所有函数和对象变量。有关更改的完整列表，请查看源文件（因为我们不想为此占用太多页面）。这里是一个小样本：

```js
LineChart.prototype.drawChart =function(){
  var can = document.getElementById("base");

 this.wid = can.width;
 this.hei = can.height;
  var context = can.getContext("2d");

  context.lineWidth = 1;
  context.fillStyle = "#eeeeee";
  context.strokeStyle = "#999999";
  context.fillRect(0,0,this.wid,this.hei);

  context.font = "10pt Verdana, sans-serif";
  context.fillStyle = "#999999";

  context.moveTo(this.CHART_PADDING,this.CHART_PADDING);
 context.rect(this.CHART_PADDING,this.CHART_PADDING,this.wid-this.CHART_PADDING*2,this.hei-this.CHART_PADDING*2);
  context.stroke();
  context.strokeStyle = "#cccccc";
  this.fillChart(context,this.chartInfo);

  var chartContainer = document.getElementById("chartContainer");

  for(var id in this.barData){
    can = document.createElement("canvas");
    can.id=id;
 can.width=this.wid;
 can.height=this.hei; 
    can.setAttribute("class","canvasLayer");
    chartContainer.appendChild(can);
 this.changeLineView(id,this.barData[id].status);

  }

}
//continue and update all methods of our new object
```

1.  到目前为止，为了处理单选按钮，我们只创建了一个回调函数，该函数设置为所有单选按钮。当用户点击我们的单选按钮时，将触发事件。一个问题将出现，因为事件内部的作用域将会中断，因为`this`将是其他内容的`this`引用，而不是我们的主对象。单选按钮有自己的作用域（自己的`this`引用）。我们想要强制进行作用域更改；为此，我们将创建一个辅助函数：

```js
LineChart.prototype.bind = function(scope, fun){
   return function () {
        fun.apply(scope, arguments);
    };

}
```

1.  我们现在将重写在`LineChart`构造函数中触发事件的行：

```js
for (var i=0; i<radios.length; i++){
 radios[i].onchange = this.bind(this, this.onChangedRadio);
   if(radios[i].value == barData[id].status ){
         radios[i].checked = true;	 
      }
    }

```

1.  我们现在将重写我们的`init`函数。我们将在其中创建我们的数据点：

```js
window.onload = init;

function init(){
  var chartInfo= { y:{min:0, max:300, steps:5,label:"users"},
        x:{min:1, max:12, steps:11,label:"months"}
      };

  var barData = {
        i2011:{
          status:	FILL_ELEMENT,
          style: "#B1DDF3",
          label: "2011",
          data:[38,65,85,111,131,160,187,180,205,146,64,212]
        },
        i2010:{
          status:	FILL_ELEMENT,
          style: "#FFDE89",
          label: "2010",
          data:[212,146,205,180,187,131,291,42,98,61,74,69]
        },	

        i2009:{
          status:	FILL_ELEMENT,
          style: "#E3675C",
          label: "2009",
          data:[17,46,75,60,97,131,71,52,38,21,84,39]
        }

      };

  chart = new LineChart(chartInfo,barData);	
}
```

1.  删除所有全局变量。

令人惊讶的是，你刚刚将所有逻辑移到了一个对象中。在我们的应用程序中没有任何全局变量，这样可以更容易地同时拥有多个图表。

## 工作原理...

我们将我们的更改保持在最小阶段。JavaScript 是一种面向对象的编程语言，因此我们可以通过将所有函数包装到一个新类中来利用它。我们首先创建一个构造函数。这个函数将被用作我们的对象类型/名称：

```js
function MyFirstObject(){
 //constructor code
}
```

要创建对象变量，我们将使用`this`引用构造函数变量。`this`运算符是一个动态名称，始终指的是当前作用域。在对象内部的当前作用域是对象本身；在我们的情况下，`MyFirstObject`函数将如下所示：

```js
function MyFirstObject(){
 this.a = "value";
}
```

你仍然可以在函数内部使用常规变量定义来创建变量，但是，在那里，作用域不会是对象作用域，而是仅在该函数内部。因此，每当你想创建在整个对象中共享的变量时，你必须创建它们，并使用前导`this`引用来引用它们。

下一步是将所有函数重命名为我们创建的新类（函数）的原型。这样，我们的函数将属于我们正在创建的新对象。我们希望过去的全局变量的转变成为当前对象的对象变量。每当我们想引用对象变量（属性）时，我们需要通过使用`this`指令明确地让 JavaScript 知道我们的对象。例如，如果我们想引用`sampleVar`变量，我们可以这样做：

```js
this.sampleVar;
```

我们只遇到了一个问题，那就是当我们在代码中引入其他对象时。指令`this`需要知道其位置的范围，以知道我们正在引用的是哪个对象。在使用事件的情况下，我们对`this`指向我们的对象的期望将不成立。实际上，在事件侦听器中处理`this`时，`this`指令总是指向被侦听的元素，也就是被操作的元素。因此，向单选按钮添加事件将导致我们的范围被破坏。为了解决这个问题，我们创建一个函数，将我们的范围绑定到侦听器上。`bind`方法将我们的函数绑定到当前范围。尽管默认情况下，侦听器的范围将是它正在侦听的对象，但我们强制范围保持在我们的对象上，使我们的代码更好地为我们工作。

这留下了我们的最后一个任务。我们需要创建我们对象的一个新实例。通过创建一个新实例，我们将激活我们迄今为止所做的所有工作。创建新对象的步骤与创建其他基本对象的步骤相同，只是这一次我们使用我们的构造函数名称：

```js
new LineChart(chartInfo,barData);
```

我们对象的真正测试将是我们是否能创建多个图表实例。现在我们还不能，所以我们需要对我们的逻辑做一些更改才能使其工作。

## 还有更多...

尽管现在我们有一个可用的 OOP 对象，但它并没有真正优化，可以进行一些改进。由于我们在一个范围内，我们可以重新审视和重连可以发送的内容以及可以依赖内部变量的内容。我们将在本章的这一部分探讨下一个任务。

### 将我们的基本画布元素移到我们的构造函数中

让我们从`drawChart`函数开始移动。以下逻辑将获取基本画布并在我们的新构造函数中创建一个全局变量：

```js
var can = document.getElementById("base");

  this.wid = can.width;
  this.hei = can.height;
  this.baseCanvas = can.getContext("2d");
```

接下来将替换`drawChart`方法中的相关行，引用我们新创建的`baseCanvas`对象：

```js
LineChart.prototype.drawChart =function(){
  var context = this.baseCanvas;
...
  this.fillChart();
```

注意，我们从`fillChart`方法中删除了函数参数，因为现在我们可以在方法内部传递它们：

```js
LineChart.prototype.fillChart = function (){ 
  var context = this.baseCanvas;
  var chartInfo = this.chartInfo;
```

我强烈建议您继续以同样的方式优化其余的函数，但是对于我们的示例，让我们继续下一个主题。

### 动态创建所有 HTML 组件

我们为什么要动态创建我们的控制器和基本画布？因为我们提前创建了一些类，所以我们在每个 HTML 页面中只能有一个对象。如果我们动态创建了控制器或传递了类信息，我们就可以在我们的应用程序中启用创建多个控制器。由于我们正在动态创建许多元素，继续这样做似乎是合乎逻辑的。让我们首先动态创建剩下的两个元素。

让我们从 HTML 页面中删除内部画布细节（删除突出显示的代码片段）：

```js
<div id="chartContainer" class="graphicLayers" >
 <canvas id="base" class="canvasLayer" width="550" height="400"> </canvas>

	</div>
 <div id="controllers" class="controllers">

 </div>

```

我们将开始将控制器类插入到我们的全局`<div>`标记中，该标记将用于我们的画布。我们需要更新控制器的 CSS 信息：

```js
.controllers {
      position: absolute;	
      left:0;
      top:400px;

    }
```

好的。我们现在准备对我们的构造函数进行一些代码更新。应该实现的更新代码片段已经突出显示：

```js
function LineChart(chartInfo,barData,divID){
  this.chartInfo = chartInfo;
  this.barData = barData;

  this.HIDE_ELEMENT = -1;
  this.LINE_ELEMENT = 0;
  this.FILL_ELEMENT = 1;
  this.CHART_PADDING = 20;
  this.BASE_ID = divID;

 var chartContainer = document.getElementById(divID);
 var	can = document.createElement("canvas");
 can.width=chartInfo.width;
 can.height=chartInfo.height; 
 can.setAttribute("class","canvasLayer");
 chartContainer.appendChild(can);

  this.wid = can.width;
  this.hei = can.height;
 this.baseCanvas = can.getContext("2d");

  this.drawChart();

 var	div = document.createElement("div");
 div.setAttribute("class","controllers");
 chartContainer.appendChild(div);
 var radContainer = div;

  var hasLooped= false;
  for(var id in barData){

    radContainer.innerHTML += (hasLooped ? " || ":"") + barData[id].label +": " ;

    this.appendRadioButton(radContainer,id,-1," off ");
    this.appendRadioButton(radContainer,id,0," line ");
    this.appendRadioButton(radContainer,id,1," full ");
    hasLooped = true;

  }

  var radios ;
  for(id in barData){
    radios = document.getElementsByName(id);
    for (var i=0; i<radios.length; i++){
       radios[i].onchange = this.bind(this, this.onChangedRadio);
      if(radios[i].value == barData[id].status ){
         radios[i].checked = true;	 
      }
    }
  }

}
```

我们希望通过将`<div>`标签 ID 发送到`LineChart`对象来开始：

```js
  new LineChart(chartInfo,barData,"chartContainer");	 
```

如果您刷新屏幕，所有这些辛苦的工作应该是看不见的。如果一切仍然像我们开始做出改变之前一样工作，那么干得好，您刚刚完成了将图表转换为智能和动态的过程。

### 移除松散的部分

尽管我们提取了所有外部画布和控制器，并且一切都在运行，但我们仍然是以一种可能会破坏它们的方式引用内部画布元素和单选按钮。如果我们尝试在它们旁边创建一个镜像图表来解决这个问题，我们需要查看所有我们的新元素，并在它们的名称中添加一个唯一的键（我们可以使用`div id`元素作为该键，因为在任何 HTML 应用程序中只能有一个具有相同 ID 的`<div>`标签）。为了节省一些页面，我只会在这里展示基本逻辑，但请获取最新的代码包以查找所有更新。

```js
LineChart.prototype.extractID = function(str){
  return  str.split(this.BASE_ID + "_")[1];
}

LineChart.prototype.wrapID = function(str){
  return  this.BASE_ID + "_"+str;
}
```

我创建了两个辅助函数，它们的作用很简单：通过将主`<div>`标签 ID 添加到它们的名称中来重命名`<div>`标签/类/单选按钮。这样我们就不会有重复的元素。剩下的就是定位我们创建元素的所有区域（我们在`drawChart`函数中创建画布，在构造函数中创建单选按钮，但我们在一些函数中与它们交互）。搜索调用`this.extractID`或`this.wrapID`方法的更改，并理解为什么它们被调用。

### 通过创建两个图表来测试我们的工作

为了让生活变得更加困难，我们将使用相同的数据源两次创建完全相同的图表（因为这是一个很好的边缘案例，所以如果这样可以工作，任何图表都可以工作）。更新 HTML 文件并添加两个`<div>`标签，并更新 CSS：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>Line Chart</title>
    <meta charset="utf-8" />
    <style>
 #chartContainer {
 position: relative; 
 left:100px
 }
 #chartContainer2{
 position: relative; 
 left:700px
 }
    .controllers {
      position: absolute;	
      left:0;
      top:400px;

    }
    .canvasLayer{
      position: absolute; 
      left: 0; 
      top: 0; 
    }
    </style>
  <script src="img/06.02.objects.optimized.js"></script>		
  </head>
  <body style="background:#fafafa">
    <h1>Users Changed between within a year</h1>
 <div id="chartContainer" class="graphicLayers" >

 </div>
 <div id="chartContainer2" class="graphicLayers2" >

 </div> 
  </body>
</html>
```

在我们的`init`函数中让我们设置好两个图表：

```js
 new LineChart(chartInfo,barData,"chartContainer"); 
 new LineChart(chartInfo,barData,"chartContainer2"); 

```

是的！我们有两个基于相同代码基础的交互式图表同时工作。干得好！不用担心，本章的其余部分会更容易一些。

# 独立层的动画

经过一些非常困难的配方之后，让我们做一些有趣且简单的事情；让我们为我们的图表添加一些动画，并添加一些淡入和延迟。

## 准备工作

我们应用程序的核心逻辑是在前两个配方*堆叠图形层*和*转向面向对象编程*中构建的。我们的状态非常良好，因此我们可以非常容易地扩展并创建内容并将其添加到我们的应用程序中。我们将对我们最新的 HTML 文件进行一些非常轻微的更新，主要是删除我们不需要的东西，然后就是 JavaScript 了。

从我们上一个示例（`06.02.objects.optimized.html`和`06.02.objects.optimized.js`）中获取最新的文件，然后让我们继续。

## 操作步骤...

在接下来的几个步骤中，我们的目标是删除不需要的代码，然后构建我们的分层动画。执行以下步骤：

1.  删除不需要的 HTML、CSS 和`<div>`标签（删除高亮显示的代码片段）：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>Line Chart</title>
    <meta charset="utf-8" />
    <style>
    #chartContainer {
    	position: relative;	
    	left:100px
    }
 #chartContainer2{
 position: relative; 
 left:700px
 }

    .controllers {
      position: absolute;	
      left:0;
      top:400px;

    }

    .canvasLayer{
      position: absolute; 
      left: 0; 
      top: 0; 
    }
    </style>
  <script src="img/06.02.objects.optimized.js"></script>		
  </head>
  <body style="background:#fafafa">
    <h1>Users Changed between within a year</h1>
    <div id="chartContainer" class="graphicLayers" >

  </div>
 <div id="chartContainer2" class="graphicLayers2" >

 </div> 
  </body>
</html>
```

1.  创建新的`Animator`构造函数：

```js
function Animator(refreshRate){
  this.animQue = [];
  this.refreshRate = refreshRate || 50; //if nothing set 20 FPS
  this.interval = 0;
}
```

1.  创建`add`方法：

```js
Animator.prototype.add = function(obj,property, from,to,time,delay){
  obj[property] = from;
  this.animQue.push({obj:obj,
            p:property,
            crt:from,
            to:to,
            stepSize: (to-from)/(time*1000/this.refreshRate),
            delay:delay*1000 || 0});

  if(!this.interval){ //only start interval if not running already
    this.interval = setInterval(this._animate,this.refreshRate,this);	
  }

}
```

1.  创建内部的`_animate`方法：

```js
Animator.prototype._animate = function(scope){
  var obj;
  var data;

  for(var i=0; i<scope.animQue.length; i++){
      data = scope.animQue[i];

      if(data.delay>0){
        data.delay-=scope.refreshRate;
      }else{
        obj = data.obj;
        if(data.crt<data.to){
          data.crt +=data.stepSize;
          obj[data.p] = data.crt;
        }else{
          obj[data.p] = data.to;	
          scope.animQue.splice(i,1);
          --i;
        }
      }

  }

  if(	scope.animQue.length==0){
    clearInterval(scope.interval);
    scope.interval = 0; //so when next animation starts we can start over
  }
}
```

1.  在`LineChart`构造函数方法中创建一个新的`Animate`对象并对关键组件进行动画处理：

```js
function LineChart(chartInfo,barData,divID){
...
 this.animator = new Animator(50);

  var chartContainer =this.mainDiv;
  var	can = document.createElement("canvas");
    can.width=chartInfo.width;
      can.height=chartInfo.height; 
    can.setAttribute("class","canvasLayer");
  chartContainer.appendChild(can);
 this.animator.add(can.style,"opacity",0,1,.5,.2);

... 

  var	div = document.createElement("div");
    div.setAttribute("class","controllers");
  chartContainer.appendChild(div);

 this.animator.add(div.style,"opacity",0,1,.4,2.2);
...

```

1.  在`drawChart`方法中为画布元素添加动画：

```js
 var delay = .75;
  for(var id in this.barData){
    can = document.createElement("canvas");
    can.id=this.wrapID(id);
        can.width=this.wid;
        can.height=this.hei; 
    can.setAttribute("class","canvasLayer");
    chartContainer.appendChild(can);
    this.changeLineView(id,this.barData[id].status);

 this.animator.add(can.style,"opacity",0,1,1,delay);
 delay+=.5;

  }
```

当您再次运行网页时，您会发现分离层的淡入效果。

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_06_01.jpg)

## 它是如何工作的...

让我们从查看我们的`Animator`构造函数开始。我们在构造函数中首先有一些变量：

```js
function Animator(refreshRate){
  this.animQue = [];
  this.refreshRate = refreshRate || 50; //if nothing set 20 FPS
  this.interval = 0;
}
```

这些变量是一切的关键。`animQue`数组将存储我们发出的每个新动画请求。`refreshRate`属性将控制我们的动画更新频率。更新得越频繁，我们的动画就会越流畅（刷新率的值越高，用户系统的压力就越小）。例如，如果我们想要有几个动画，一个在更平滑的设置中，另一个以较低的刷新率运行，我们可以设置两个不同的`Animator`类，具有不同的刷新率。

我们的`add`方法接收所有必要的信息来对属性进行动画处理：

```js
Animator.prototype.add = 
    function(obj,property, from,to,time,delay){}
```

发送到动画的每个元素都会被转换为一个引用对象，该对象在动画运行时将被使用，并推送到我们的`animQue`数组中：

```js
  this.animQue.push({obj:obj,
            p:property,
            crt:from,
            to:to,
            stepSize: (to-from)/(time*1000/this.refreshRate),
            delay:delay*1000 || 0});
```

在队列中存储我们将需要动画元素的所有信息，从对象的当前状态到每个间隔应该进行多少变化。除此之外，我们还添加了一个延迟选项，使我们能够稍后开始动画。

我们只在这个函数中控制间隔的创建，所以在调用这个函数之前，将不会有间隔运行：

```js
if(!this.interval){ //only start interval if not running already
    this.interval = setInterval(this._animate,this.refreshRate,this);
  }
```

现在是我们对象的内部逻辑的时间了。`_animate`方法在有东西需要动画时被内部调用。换句话说，只要`animQue`数组中有东西。它循环遍历所有`animQue`数组元素，并对每个元素进行一些测试：

1.  如果元素设置了延迟，它将通过`refreshRate`属性降低延迟值，使得在每次循环中延迟变小，直到变为零或更小。当这种情况发生时，下一步将触发。

1.  现在延迟已经完成，`_animate`方法改变了状态。它开始为`animQue`数组中的对象进行动画，直到`data.crt`的值小于`data.to`为止。

1.  在测试从数组中移除元素之前，间隔将继续一次。这里的分步是帮助我们避免在核心逻辑中添加`if`语句，从而减少我们`for`循环的复杂性。因为我们只需要测试一次，所以我们可以吸收一个额外的循环周期的成本。在这个额外的周期中，我们将确切的最终值强制给我们的对象，并将其从动画队列中移除。

这是唯一的奇怪逻辑，我们在这里强制将循环变量的值降低：

```js
}else{
  obj[data.p] = data.to;	
  scope.animQue.splice(i,1);
  --i;
}
```

在这段代码中，我们正在移除我们的元素。一旦我们移除了元素，我们的`i`的当前值将比应该的值大一个，因为我们的对象已经缩小了。为了解决这个问题，我们需要强制降低值，将其重置为新的当前索引。

最后，在每次更新结束时，我们检查一下我们的数组中是否有任何东西。如果数组为空，那么是时候移除间隔了。我们希望在不需要时避免间隔运行。下次触发`add`方法时，它将重新启动间隔：

```js
  if(	scope.animQue.length==0){
    clearInterval(scope.interval);
    scope.interval = 0; //reset interval variable
  }
```

这就是我们逻辑的核心，现在是时候创建一个新的`animator`对象，并开始发送我们想要动画的元素了。尝试一下，动画其他东西，并找到你喜欢的动画速度、延迟和属性之间的平衡。这个`animator`类是所有动画库的基础，尽管我们的示例更简化，有更多的用户过载的可能性，比如多次发送相同的对象。

# 添加一个交互式图例

尽管我们之前创建了一个图例，但我们的图例注定是非交互式的，因为我们没有办法移动它。在这个示例中，我们将创建一个快速简单的图例，当用户在我们的图表上滚动时，它将更新其位置，并淡入淡出。

## 准备好

从我们之前的`06.03.fade.html`和`06.03.fade.js`中获取最新的文件，然后让我们开始吧。在这个例子中，我们将硬编码我们的值，但是提取动态元素的更模块化方法是使这个类可重用的好方法。

## 如何做...

这一次，我们将在`LineChart`对象中创建一个方法，为我们创建图例。执行以下步骤：

1.  创建`createLegend`方法：

```js
LineChart.prototype.createLegend = function (){
  var	can = document.createElement("canvas");
    can.width=70;
      can.height=100; 
    can.setAttribute("class","canvasLayer");
  chartContainer.appendChild(can);

  this.legend = can;
  this.updateLegend();
  can.style.opacity = 0;
}
```

1.  创建`updateLegend`方法：

```js
LineChart.prototype.updateLegend = function(){
  var wid = this.legend.width;
  var hei = this.legend.height;
  var context = this.legend.getContext("2d");
  context.fillStyle = "rgba(255,255,255,.7)";
  context.strokeStyle = "rgba(150,150,150,.7)";
  context.fillRect(0,0,wid,hei);
  context.strokeRect(5,5,wid-10,hei-10);

  var nextY= 10;
  var space = (hei-10 - this.chartInfo.bars * nextY) / this.chartInfo.bars;
  for(var id in this.barData){
    context.fillStyle = this.barData[id].style;
    context.fillRect(10,nextY,10,10);
    context.fillText(this.barData[id].label,25, nextY+9);
    nextY+=10+space;

  }
  this.legend.style.left = this.wid +"px";

}
```

1.  接下来，我们要创建一些方法，这些方法将被用作事件监听器。让我们添加一些监听器来控制我们的动画：

```js
LineChart.prototype.onMouseMoveArea = function(e){
  this.legend.style.top = (e.layerY) +"px";

}

LineChart.prototype.fadeInLegend = function(){
  this.animator.add(this.legend.style,"opacity",this.legend.style.opacity,1,.5);	
}

LineChart.prototype.fadeOutLegend = function(){
  this.animator.add(this.legend.style,"opacity",this.legend.style.opacity,0,.5);	
}
```

1.  我们刚刚创建的方法现在准备好与回调方法链接，比如我们的`mainDiv`的`onmouseover`或`onmouseout`事件。我们将我们的范围绑定回我们的主对象，并在用户触发这些内置事件时触发我们之前创建的方法。让我们在构造函数中注册我们的监听器：

```js
	this.drawChart();

this.createLegend();
this.mainDiv.onmousemove = this.bind(this,this.onMouseMoveArea);
this.mainDiv.onmouseover = this.bind(this,this.fadeInLegend);
this.mainDiv.onmouseout = this.bind(this,this.fadeOutLegend);

```

1.  在代码中添加一个变量，用于计算`drawChart`更新代码中图表中有多少个条形图：

```js
this.chartInfo.bars = 0;
  for(var id in this.barData){
 this.chartInfo.bars++;
    can = document.createElement("canvas");
    can.id=this.wrapID(id);
        can.width=this.wid;
        can.height=this.hei; 
    can.setAttribute("class","canvasLayer");
    chartContainer.appendChild(can);
    this.changeLineView(id,this.barData[id].status);

    this.animator.add(can.style,"opacity",0,1,1,delay);
    delay+=.5;

  }
```

干得好！当你刷新浏览器时，你会看到一个根据我们的鼠标移动而淡入/淡出和重新定位的传说。

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_06_02.jpg)

## 它是如何工作的...

这一次的逻辑很简单，因为我们的应用程序已经很好地设置和优化了。我们的`createLegend`方法为我们创建了一个新的画布区域，我们可以用它来制作我们的传说。我已经在其中添加了一些硬编码的值，但将它们提取到我们的`chartInfo`变量中会是一个好主意。

唯一需要解释的是传说布局涉及的逻辑。我们需要知道我们的图表包含多少项，以避免再次循环遍历数据源或要求用户添加此信息。我们可以在第一次循环遍历用户生成的数据时计算这些信息，然后更新它以包含我们的总项数。

我们设置了我们的方法，这样我们就可以将动态数据直接放入我们的图表中。我留下了这个挑战给你去探索和为它设置基础。

## 还有更多...

还有一件事需要注意的是，如果你在这个例子中努力搜索并对我们的`Animator`类进行压力测试，你会发现它并不是百分之百优化的。如果我们向`Animator`类发送具有冲突指令的相同对象，它不会自动终止冲突。相反，它将运行直到完成（例如，它将同时淡出和淡入；它不会破坏我们的应用程序，但会产生不需要的结果）。为了解决这样的问题，我们需要修改我们的`Animator`类来覆盖冲突的动画。

通过检查我们的动画队列是否已经有相同属性的相同对象在进行动画来解决动画冲突。我们将创建一个`find`函数来帮助我们在`animQue`属性中找到重复的索引：

```js
Animator.prototype.find= function(obj,property){
  for(var i=0; i<this.animQue.length; i++){
    if(this.animQue[i].obj == obj && this.animQue[i].p == property) return i;	

  }

  return -1;
}
```

该函数将扫描我们的`animQue`数组并找到重复项。如果找到匹配项，将返回索引值。如果没有找到，将返回`-1`。现在是时候更新我们的`add`方法来使用这个新的`find`方法了：

```js
Animator.prototype.add = function(obj,property, from,to,time,delay){
  obj[property] = from;

 var index = this.find(obj,property);
  if(index!=-1) this.animQue.splice(index,1);
  this.animQue.push({obj:obj,
            p:property,
            crt:from,
            to:to,
            stepSize: (to-from)/(time*1000/this.refreshRate),
            delay:delay*1000 || 0});

  if(!this.interval){ //only start interval if not running already
    this.interval = setInterval(this._animate,this.refreshRate,this);	
  }

}
```

太好了！问题解决了！虽然在这个例子中我们还没有解决动态传说，但我们将在下一个示例中创建一个新的传说方向，它将是同样动态的，也许更加动态，*创建一个上下文感知的传说*。

# 创建一个上下文感知的传说

我们的目标是创建一个根据用户鼠标悬停在应用程序上的位置而更新的传说。根据用户的鼠标位置，我们将更新我们的传说以反映用户鼠标下的信息。

## 准备工作

从上一个示例中获取最新的文件：`06.04.legend.html`和`06.04.legend.js`。

## 如何做...

我们不会在 HTML 文件中做任何改变，所以让我们直接进入 JavaScript 并构建我们的动态传说：

1.  从`ChartLine`构造函数中删除 rollover/rollout 事件，因为我们希望保持我们的传说始终可见：

```js
  this.drawChart();

  this.createLegend();
  this.mainDiv.onmousemove = this.bind(this,this.onMouseMoveArea);
  this.mainDiv.onmouseover = this.bind(this,this.fadeInLegend);
  this.mainDiv.onmouseout = this.bind(this,this.fadeOutLegend);
```

1.  更新`createLegend`方法：

```js
LineChart.prototype.createLegend = function (){
  var	can = document.createElement("canvas");
    can.width=90;
      can.height=100; 
    can.setAttribute("class","canvasLayer");
  chartContainer.appendChild(can);

  this.legend = can;
  this.updateLegend(null,-1);
  can.style.left = this.wid +"px";
}
```

1.  更新`updateLegend`方法：

```js
LineChart.prototype.updateLegend = function(ren,currentXIndex){
  var ren = ren || this.barData;	
  var wid = this.legend.width;
  var hei = this.legend.height;
  var context = this.legend.getContext("2d");
  context.fillStyle = "rgba(255,255,255,.7)";
  context.strokeStyle = "rgba(150,150,150,.7)";
  context.fillRect(0,0,wid,hei);
  context.strokeRect(5,5,wid-10,hei-10);

  var nextY= 10;
  var space = (hei-10 - this.chartInfo.bars * nextY) / this.chartInfo.bars;
  var isXIndex = currentXIndex !=-1;
  for(var id in ren){
    context.fillStyle = this.barData[id].style;
    context.fillRect(10,nextY,10,10);
    context.fillText(this.barData[id].label + (isXIndex ? (":"+ this.barData[id].data[currentXIndex] ):""),25, nextY+9);
    nextY+=10+space;

  }

}
```

1.  更改事件监听器`onMouseMoveArea`：

```js
LineChart.prototype.onMouseMoveArea = function(e){
  var pixelData;
  var barCanvas;

  var chartX = e.layerX-this.CHART_PADDING;
  var chartWid = 	this.wid -this.CHART_PADDING*2;
  var currentXIndex = -1;
  if(chartX>=0 && chartX<= chartWid){
    currentXIndex = Math.round(chartX/this.chartInfo.x.stepSize)	
  }

  var renderList = {};
  var count = 0;
  for(var id in this.barData){
    barCanvas = this.barData[id].canvas;		
    pixelData = barCanvas.getImageData(e.layerX, e.layerY, 1, 1).data

    if( pixelData[3]){
       count++;
       renderList[id] = true; //there is content on this layer now
    }
  }

  if(!count) renderList = this.barData;

  this.updateLegend(renderList,currentXIndex);
}
```

1.  我们需要将步长添加到我们的数据中。这个变量应该动态计算，因为如果我们可以计算出来，用户就不需要知道这个信息。因此，当我们在`fillChart`方法中计算步长时，我们将把这个计算添加到我们的`chartInfo`对象中：

```js
stepSize = rangeLength/steps;
this.chartInfo.x.stepSize = chartWidth/steps;

```

1.  最后但同样重要的是，让我们直接将画布信息添加到我们的`barData`对象中，这样我们就可以轻松地与它交互（添加到`drawChart`函数中）：

```js
for(var id in this.barData){
    this.chartInfo.bars++;
    can = document.createElement("canvas");
    can.id=this.wrapID(id);
        can.width=this.wid;
        can.height=this.hei;
    can.setAttribute("class","canvasLayer");
    chartContainer.appendChild(can);
 this.barData[id].canvas =can.getContext("2d"); 
    this.changeLineView(id,this.barData[id].status);

    this.animator.add(can.style,"opacity",0,1,1,delay);
    delay+=.5;

  }
```

我们应该已经准备好了。当你再次运行页面时，你的鼠标应该控制传说中基于你所在的确切坐标提供的信息。

## 它是如何工作的...

在上一节配方的最后两个步骤中，我们添加了一些辅助变量来帮助我们创建鼠标移动逻辑。这是一个有趣的部分，因为在这个示例中，我们首次向画布请求像素信息。我们将主要关注`onMouseMoveArea`事件侦听器内的逻辑。

我们首先要确定画布区域的边界：

```js
var chartX = e.layerX-this.CHART_PADDING;
var chartWid = 	this.wid -this.CHART_PADDING*2;
```

接下来将是对我们所在图表的当前区域进行快速计算：

```js
var currentXIndex = -1;
	if(chartX>=0 && chartX<= chartWid){
		currentXIndex = Math.round(chartX/this.chartInfo.x.stepSize);	
	}
```

如果我们离开区域，我们的`currentXIndex`变量将保持为`-1`，而如果我们在区域内，我们将得到一个值，介于`0`和数据源步数的最大可能值之间。我们将把这个值发送到我们新更新的`updateLegend`方法中，该方法将把该索引信息的实际值从数据源附加到图例的渲染中。

接下来是一个`for`循环，我们通过循环遍历我们的数据来测试我们的画布元素，看它们是否是不透明的：

```js
var renderList = {};
  var count = 0;
  for(var id in this.barData){
    barCanvas = this.barData[id].canvas;		
    pixelData = barCanvas.getImageData(e.layerX, e.layerY, 1, 1).data;

    if( pixelData[3]){
       count++;
       renderList[id] = true; //there is content on this layer now
    }
  }
```

只有返回的数据确认鼠标指针下有内容，我们才会将该 ID 添加到`renderList`对象中。`renderList`对象将成为我们的中心；它将控制要发送到`updateLegend`方法的图例数据字段。如果我们的鼠标位于绘制的元素上方，我们将展示与用户悬停相关的图例信息；如果没有，我们将不展示。

我们将更新调用`updateLegend`方法的方式，但在将其发送到新参数之前，我们要确认我们确实发送了一些东西。如果我们的辅助（链接对象）为空，我们将发送原始对象。这样，如果鼠标指针下没有图表，一切都会渲染：

```js
if(!count) renderList = this.barData;
this.updateLegend(renderList,currentXIndex);
```

是时候来看看`updateLegend`方法内的变化了。第一件新事情就在第一行出现：

```js
var ren = ren || this.barData;
```

这是一个很好的编码技巧，它使我们能够更新我们的`ren`参数。它的工作方式非常简单；`||`运算符将始终返回它看到的第一个真值。在我们的情况下，如果`ren`参数为空，或为零，或为假，它将返回`this.barData`中的值。逻辑很简单，如果`ren`参数有内容，它将保持不变，而如果为空，则`this.barData`属性将在`ren`变量中设置。

```js
var isXIndex = currentXIndex !=-1;
 for(var id in ren){
    context.fillStyle = this.barData[id].style;
    context.fillRect(10,nextY,10,10);
 context.fillText(this.barData[id].label + (isXIndex ? (":"+ this.barData[id].data[currentXIndex] ):""),25, nextY+9);
    nextY+=10+space;

  }
```

这确实是整个配方的魔力所在。我们不是通过`this.barData`属性进行循环，而是通过包含我们要渲染的所有项目的键对象进行循环。在添加文本时，只需在添加文本时添加数据，如果有列出有效索引。

就是这样！我们刚刚添加了一个非常酷的动态图例，随着用户探索我们的图表而变化。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_06_03.jpg)
