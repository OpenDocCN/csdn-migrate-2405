# HTML5 图形和数据可视化秘籍（四）

> 原文：[`zh.annas-archive.org/md5/6DD5FA08597C1F517B2FC929FBC4EC5A`](https://zh.annas-archive.org/md5/6DD5FA08597C1F517B2FC929FBC4EC5A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：依赖于开源领域

在本章中，我们将涵盖：

+   创建一个仪表盘表（jqPlot）

+   创建一个动画 3D 图表（canvas3DGraph）

+   随着时间的推移绘制图表（flotJS）

+   使用 RaphaelJS 创建时钟

+   使用 InfoVis 制作一个日光图

# 介绍

开源数据可视化社区非常丰富和详细，有许多选项和一些真正令人惊叹的库。每个库都有其优点和缺点。有些是独立的代码，而其他依赖于其他平台，如 jQuery。有些非常庞大，有些非常小；没有一个选项适用于所有机会，但是有这么多的选择，最重要的是找出哪个库适合您。

在使用开源库时总会有一个权衡，主要是在文件大小和拖慢应用程序速度、加载时间等方面有太多功能的情况下。但是由于社区的丰富和创造力，很难避免在几分钟内创建出真正奇妙的图表，而不是几个小时。

在本章中，我们将探索使用一些这些选项。我们的目标不是根据项目的文档使用库，而是找到方法来覆盖内置库，以便更好地控制我们的应用程序，以防在应用程序的文档中找不到合适的解决方案。因此，本章的目标现在是双重的，即找到执行不是自然设置的事情的方法，并找到绕过问题的方法。

还有一件重要的事情要注意，所有这些开源库都有版权。建议您在继续之前检查项目的法律文件。

# 创建一个仪表盘表（jqPlot）

在这个配方中，我们将创建一个非常有趣的仪表盘表，并注入一些随机动画，使其看起来像是连接到实时数据源，比如汽车的速度：

![创建一个仪表盘表（jqPlot）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_07_01.jpg)

## 准备工作

要开始，您需要使用 jQuery 和 jqPlot。这一次我们将从头开始。

要获取最新的脚本，请访问[`blog.everythingfla.com/?p=339`](http://blog.everythingfla.com/?p=339)的创建者网站。

下载 jQuery 和 jqPlot，或者下载我们的源文件开始。

## 如何做...

让我们列出完成任务所需的步骤：

1.  为我们的项目创建一个 HTML 页面：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>JQPlot Meter</title>
    <meta charset="utf-8" />
    <link rel="stylesheet" href="./external/jqplot/jquery.jqplot.min.css">
    <script src="img/jquery.min.js"></script>
    <script src="img/jquery.jqplot.js"></script>
    <script src="img/jqplot.meterGaugeRenderer.min.js"></script>

    <script src="img/07.01.jqplot-meter.js"></script>		
  </head>
  <body style="background:#fafafa">

  <div id="meter" style="height:400px;width:400px; "></div>
  </body>
</html>
```

1.  创建`07.01.jqplot-meter.js`文件。

1.  让我们添加一些辅助变量。我们将在渲染仪表时使用它们：

```js
var meter;
var meterValue=0;
var startingSpeed = parseInt(Math.random()*60) + 30;
var isStarting = true;
var renderOptions= {
               label: 'Miles Per Hour',
               labelPosition: 'bottom',
               labelHeightAdjust: -10,
               intervalOuterRadius: 45,
               ticks: [0, 40, 80, 120],
               intervals:[25, 90, 120],
               intervalColors:[ '#E7E658','#66cc66', '#cc6666']
            };
```

1.  现在是时候创建我们的仪表盘了。我们将使用 jQuery 来知道我们的文档何时被阅读，然后创建我们的图表。

```js
$(document).ready(function(){

  meter = $.jqplot('meter',[[meterValue]],{
    seriesDefaults: {
      renderer: $.jqplot.MeterGaugeRenderer,
      rendererOptions:renderOptions
    }
  });

});
```

1.  现在是时候为我们的图表添加动画了。让我们在`ready`监听器间隔的最后一行中添加（从现在开始直到配方结束）：

```js
$(document).ready(function(){

  meter = $.jqplot('meter',[[meterValue]],{
    seriesDefaults: {
      renderer: $.jqplot.MeterGaugeRenderer,
      rendererOptions:renderOptions
    }
  });

  setInterval(updateMeter,30);

});
```

1.  最后但同样重要的是，现在是创建`updateMeter`函数的时候了：

```js
function updateMeter(){
  meter.destroy();  

  if(isStarting && meterValue<startingSpeed){
    ++meterValue	
  }else{
    meterValue += 1- Math.random()*2;
    meterValue = Math.max(0,Math.min(meterValue,120)); //keep our value in range no mater what	
  }

  meter = $.jqplot('meter',[[meterValue]],{
    seriesDefaults: {
      renderer: $.jqplot.MeterGaugeRenderer,
      rendererOptions:renderOptions
    }
  });

}
```

做得好。刷新您的浏览器，您会发现一个动画速度计，看起来像是汽车在行驶（如果您只是想象）。

## 它是如何工作的...

这个任务真的很容易，因为我们不需要从头开始。为了使仪表运行，我们需要导入`meterGaugeRenderer`库。我们通过将其添加到我们正在加载的 JavaScript 文件中来实现这一点。但让我们专注于我们的代码。我们 JavaScript 的第一步是准备一些全局变量；我们使用全局变量是因为我们希望在两个不同的函数中重复使用这些变量（当我们准备重置我们的数据时）。

```js
var meter;
var meterValue=0;
var startingSpeed = parseInt(Math.random()*60) + 30;
var isStarting = true;
```

`meter`变量将保存我们从开源库生成的仪表。`meterValue`将是应用程序加载时的初始值。我们的`startingSpeed`变量将是`30`和`90`之间的随机值。目标是每次从不同的地方开始，使其更有趣。应用程序一启动，我们希望我们的仪表快速动画到其新的基本速度（`startingSpeed`变量）。最后，这与`isStarting`变量相关联，因为我们希望有一个动画将我们带到基本速度。当我们到达那里时，我们希望切换到一个会导致动画改变的随机驾驶速度。现在我们已经设置了所有辅助变量，我们准备创建`renderOptions`对象：

```js
var renderOptions= {
               label: 'Miles Per Hour',
               labelPosition: 'bottom',
               labelHeightAdjust: -10,
               intervalOuterRadius: 45,
               ticks: [0, 40, 80, 120],
               intervals:[25, 90, 120],
               intervalColors:[ '#E7E658','#66cc66', '#cc6666']
           };
```

这个对象实际上是我们应用程序视觉效果的核心。（在 jqPlot 项目主页文档中还有其他选项可供您探索。）现在让我们回顾一些关键参数。

`intervalOuterRadius`有一个有点棘手的名称，但实际上它是内半径。我们的仪表的实际大小由我们设置应用程序所在的`div`的大小控制。`intervalOuterRadius`控制速度计核心中内部形状的大小。

```js
var renderOptions= {
  label: 'Miles Per Hour',
  labelPosition: 'bottom',
  labelHeightAdjust: -10,
  intervalOuterRadius: 45,
 //ticks: [0, 40, 80, 120],
 intervals:[10,25, 90, 120],
 intervalColors:['#999999', '#E7E658','#66cc66', '#cc6666']
};
```

`ticks`函数控制复制轮廓的位置。默认情况下，它会将我们的顶部范围除以 4（即 30、60、90 和 120）。`intervals`和`intervalColors`函数让仪表知道范围和内部、内部、饼颜色（与刻度分开）。

```js
$(document).ready(function(){

  meter = $.jqplot('meter',[[meterValue]],{
    seriesDefaults: {
      renderer: $.jqplot.MeterGaugeRenderer,
      rendererOptions:renderOptions
    }
  });
  setInterval(updateMeter,30);

});
```

要使用 jqPlot 库创建新图表，我们总是调用`$.jqplot`函数。函数的第一个参数是`div`层，这是我们的工作所在的地方。第二个参数是包含图表数据的二维数组（对于这个示例来说看起来有点奇怪，因为它期望一个二维数组，而我们的示例一次只包含一个数据条目，所以我们需要将它包装在两个数组中）。第三个参数定义了使用的渲染器和`rendererOptions`（我们之前创建的）。

## 还有更多…

让我们再探索一些功能。

### 创建`updateMeter`函数

`updateMeter`函数每 30 毫秒调用一次。我们需要做的是每次调用时都清除我们的艺术品：

```js
meter.destroy();  
```

这将清除与我们的仪表相关的所有内容，以便我们可以重新创建它。

如果我们仍然处于应用程序的介绍部分，希望我们的速度达到目标速度，我们需要通过`1`更新我们的`meterValue`。

```js
if(isStarting && meterValue<startingSpeed){
    ++meterValue;
}
```

如果我们已经通过了这个状态，想让我们的仪表随机上下波动，看起来像是驾驶速度的变化，我们将使用以下代码片段：

```js
}else{
    meterValue += 1- Math.random()*2;
    meterValue = Math.max(0,Math.min(meterValue,120)); //keep our value in range no mater what	
}
```

我们随机地向我们的仪表值添加一个介于`-1`和`1`之间的值。通过保持我们的值不低于`0`且不高于`120`，然后用我们的新的`meterValue`值重新绘制我们的仪表，可以实现对我们结果的修正。

# 创建一个动画 3D 图表（canvas3DGraph）

这个配方真的很有趣。它基于 Dragan Bajcic 的源文件。它不是一个完整的图表库，但它是一个很棒的启发式图表，可以修改并用来创建您自己的 3D 数据可视化。

尽管我们附带示例中的源文件是从原始源文件（主要是`canvas3DGraph.js`）修改的，但要获取本书中使用的开源项目的原始源，请访问我们的集中列表[`blog.everythingfla.com/?p=339`](http://blog.everythingfla.com/?p=339)。

![创建一个动画 3D 图表（canvas3DGraph）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_07_02.jpg)

## 准备好了

如果您想关注我们的更新，请从提供的链接下载原始源文件，或者查看我们对 Dragan 的源文件所做的更改。

## 如何做到…

让我们马上开始，因为我们有很多工作要做：

1.  创建 HTML 文件：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>canvas3DGraph.js</title>
    <meta charset="utf-8" />
    <link rel="stylesheet" href="./external/dragan/canvas3DGraph.css">
    <script src="img/canvas3DGraph.js"></script>
    <script src="img/07.02.3d.js"></script>

  </head>
  <body style="background:#fafafa">

    <div id="g-holder">  
      <div id="canvasDiv">  
        <canvas id="graph" width="600" height="600" ></canvas>  
        <div id="gInfo"></div>   
      </div>  

    </div>      
  </body>
</html>
```

1.  创建 CSS 文件`canvas3DGraph.css`：

```js
#g-holder {  
    height:620px;  
    position:relative;  
}  

#canvasDiv{  
    border:solid 1px #e1e1e1;  
    width:600px;  
    height:600px;  
    position:absolute;  
    top:0px; left:0px;  
    z-index:10;  
}  
#x-label{  
    position:absolute;  
    z-index:2;  
    top:340px;  
    left:580px;  
}  

#y-label{  
    position:absolute;  
    z-index:2;  
    top:10px;  
    left:220px;  
}  

#z-label{  
    position:absolute;  
    z-index:2;  
    top:540px;  
    left:10px;  
}  

#gInfo div.gText{  
    position:absolute;  
    z-index:-1;  
    font:normal 10px Arial;  
}  
```

1.  现在是时候转到 JavaScript 文件了。

1.  让我们添加一些辅助变量：

```js
var gData = [];

var curIndex=0;
var trailCount = 5;
var g;
var trailingArray=[];
```

1.  当文档准备就绪时，我们需要创建我们的图表：

```js
window.onload=function(){  
  //Initialize Graph  
  g = new canvasGraph('graph');  
  g.barStyle = {cap:'rgba(255,255,255,1)',main:'rgba(0,0,0,0.7)', shadow:'rgba(0,0,0,1)',outline:'rgba(0,0,0,0.7)',formater:styleFormater};	
  for(i=0;i<100;i++){
    gData[i] = {x:(Math.cos((i/10)) * 400 + 400), y:(1000-(i*9.2)), z:(i*10)};
  }

plotBar();
setInterval(plotBar,40);

}  
```

1.  创建`plotBar`函数：

```js
function plotBar(){
  trailingArray.push(gData[curIndex]);

  if(trailingArray.length>=5) trailingArray.shift();

  g.drawGraph(trailingArray);//trailingArray);
  curIndex++
  if(curIndex>=gData.length) curIndex=0;
}
```

1.  创建格式化函数`styleFormatter`：

```js
function styleFormatter(styleColor,index,total){
  var clrs = styleColor.split(",");
  var alpha = parseFloat(clrs[3].split(")"));
  alpha *= index/total+.1;
  clrs[3] = alpha+")";
  return clrs.join(",");
}
```

假设您正在使用我们修改过的开源 JavaScript 文件，现在您应该看到您的图表正在进行动画。(在这个食谱的*更多内容*部分，我们将深入研究这些更改以及我们为什么进行这些更改。)

## 它是如何工作的...

让我们首先以与 JavaScript 库交互的方式来查看我们的代码。之后我们将更深入地了解这个库的内部工作原理。

```js
var gData = [];
var trailingArray=[];
var trailCount = 5;
var curIndex=0;
```

`gData`数组将存储 3D 空间中所有可能的点。一个 3D 条形图将使用这些点创建(这些点是将作为对象放入这个数组中的 3D 点 x、y 和 z 值)。`trailingArray`数组将存储视图中当前的条形图元素。`trailCount`变量将定义同时可以看到多少条形图，我们的当前索引(`curIndex`)将跟踪我们最新添加到图表中的元素。

当窗口加载时，我们创建我们的图表元素：

```js
window.onload=function(){  
  //Initialise Graph  
  g = new canvasGraph('graph');  
  g.barStyle = {cap:'rgba(255,255,255,1)',main:'rgba(0,0,0,0.7)', shadow:'rgba(0,0,0,1)',outline:'rgba(0,0,0,0.7)',formatter:styleFormatter};	
  for(i=0;i<100;i++){
    gData[i] = {x:(Math.cos((i/10)) * 400 + 400), y:(1000-(i*9.2)), z:(i*10)};
  }

  plotBar();
  setInterval(plotBar,40);

}  
```

在创建我们的图表之后，我们更新`barStyle`属性以反映我们想要在条形图上使用的颜色。除此之外，我们还发送了一个格式化函数，因为我们希望单独处理每个条形图(在视觉上对它们进行不同处理)。然后我们创建我们的数据源——在我们的情况下是在我们的内部空间中旅行的`Math.cos`。随意玩弄所有数据点；它会产生一些非常惊人的内容。在实际应用中，您可能希望使用实时或真实数据。为了确保我们的数据将从后到前堆叠，我们需要对数据进行排序，以便后面的 z 值首先呈现。在我们的情况下，不需要排序，因为我们的循环正在创建一个按顺序增长的 z 索引顺序，所以数组已经组织好了。

## 更多内容...

接下来我们调用`plotBar`并且每 40 毫秒重复一次这个动作。

### plotBar 的逻辑

让我们来审查一下`plotBar`函数中的逻辑。这是我们应用程序的真正酷的部分，我们通过更新数据源来创建动画。我们首先将当前索引元素添加到`trailingArray`数组中：

```js
trailingArray.push(gData[curIndex]);
```

如果我们的数组长度为`5`或更多，我们需要摆脱数组中的第一个元素：

```js
if(trailingArray.length>=5) trailingArray.shift();
```

然后我们绘制我们的图表并将`curIndex`的值增加一。如果我们的`curIndex`大于数组元素，我们将其重置为`0`。

```js
g.drawGraph(trailingArray);//trailingArray);
curIndex++
if(curIndex>=gData.length) curIndex=0;
```

### styleFormatter 的逻辑

每次绘制条形图时，我们的格式化函数都会被调用来计算要使用的颜色。它将获取条形图的索引和正在处理的图表中数据源的总长度。在我们的示例中，我们只是根据它们的位置改变条形图的`alpha`值。(数字越大，我们就越接近最后输入的数据源。)通过这种方式，我们创建了我们的淡出效果。

```js
function styleFormatter(styleColor,index,total){
  var clrs = styleColor.split(",");
  var alpha = parseFloat(clrs[3].split(")"));
  alpha *= index/total+.1;
  clrs[3] = alpha+")";
  return clrs.join(",");
}
```

这个示例实际上还有更多。在不深入代码本身的情况下，我想概述一下这些更改。

为了控制我们的条形图的颜色，第三方包的第 66 行必须更改。因此，我引入了`this.barStyle`并且替换了在创建条形图元素时硬编码值的所有引用(并设置了一些默认值)：

```js
this.barStyle = {cap:'rgba(255,255,255,1)',main:'rgba(189,189,243,0.7)', shadow:'rgba(77,77,180,0.7)',outline:'rgba(0,0,0,0.7)',formatter:null};
```

我为我们的条形图创建了一个样式生成器。这是为了帮助我们在外部格式化程序和内部样式之间重定向逻辑：

```js
canvasGraph.prototype.getBarStyle= function(baseStyle,index,total){
  return this.barStyle.formatter? this.barStyle.formatter(baseStyle,index,total):baseStyle;
}
```

我们创建了一个清除函数，以删除图表中的所有可视内容，这样我们每次调用它时就可以重新渲染数据：

```js
canvasGraph.prototype.getBarStyle= function(baseStyle,index,total){
  return this.barStyle.formatter? this.barStyle.formatter(baseStyle,index,total):baseStyle;
}
```

我们将绘制图表的逻辑移动到`drawGraph`函数中，这样我可以同时删除图表，使得每次刷新所有数据更容易：

```js
canvasGraph.prototype.drawGraph=function(gData){
  //moved this to the drawGraph so i can clear each time its called.
  this.clearCanvas();
  // Draw XYZ AXIS 
  this.drawAxis();
  this.drawInfo();

  var len = gData.length;

  for(i=0;i<len;i++){
    this.drawBar(gData[i].x,gData[i].y,gData[i].z,i,len); 
  }
}
```

当前索引和长度信息现在通过`drawBar`传递，直到它到达格式化函数。

最后但并非最不重要的是，我已经从构造函数中删除了绘制图表的部分，这样我们的图表将更有利于我们的动画想法。

# 随时间变化的图表(flotJS)

这个库的一个更令人印象深刻的特性是更新图表信息的简易性。当您第一次审查这个库及其样本时，就可以很容易地看出作者热爱数学和图表。我最喜欢的功能是图表可以根据输入动态更新其 x 范围。

我第二喜欢的功能是使用`tickFormater`方法更新图表文本信息的简易性。

![随时间变化的图表（flotJS）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_07_03.jpg)

## 准备工作

要获取`flotJS`库的最新版本，请访问我们的链接中心[`blog.everythingfla.com/?p=339`](http://blog.everythingfla.com/?p=339)以获取图表开源库，或者下载我们书籍的源文件，在出版时包含最新版本[`02geek.com/books/html5-graphics-and-data-visualization-cookbook.htm`](http://02geek.com/books/html5-graphics-and-data-visualization-cookbook.htm)。

## 如何做...

让我们创建我们的 HTML 和 JavaScript 文件：

1.  创建一个 HTML 文件：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>flot</title>
    <meta charset="utf-8" />
    <script src="img/jquery.min.js"></script>
    <script src="img/jquery.flot.js"></script>
    <script src="img/jquery.flot.fillbetween.js"></script>    

    <script src="img/07.03.flot.js"></script>

  </head>
  <body style="background:#fafafa">

    <div id="placeholder" style="width:600px;height:300px;"></div> 
  </body>
</html>
```

1.  创建一个新的 JavaScript 文件（`07.03.flot.js`），然后创建我们的数据源：

```js
var males = {

//...
//please grab from source files its a long list of numbers
};Create helper variables:
var VIEW_LENGTH = 5;
var index=0;
var plot;

var formattingData = {
  xaxis: { tickDecimals: 0, tickFormatter: function (v) { return v%12 + "/" + (2009+Math.floor(v/12)); } },
  yaxis: { tickFormatter: function (v) { return v + " cm"; } }
};
```

1.  创建一个`ready`事件并触发`updateChart`：

```js
$(document).ready(updateChart);
```

1.  创建`updateChart`：

```js
function updateChart() {
  plot = $.plot($("#placeholder"), getData(), formattingData);

  if(index+5<males['mean'].length){
    setTimeout(updateChart,500);
  }
}
```

1.  创建`getData`：

```js
function getData(){
  var endIndex = index+5>=males.length?males.length-1:index+5;
  console.log(index,endIndex);
  var dataset = [
    { label: 'Male mean', data: males['mean'].slice(index,endIndex), lines: { show: true }, color: "rgb(50,50,255)" },
    { id: 'm15%', data: males['15%'].slice(index,endIndex), lines: { show: true, lineWidth: 0, fill: false }, color: "rgb(50,50,255)" },
    { id: 'm25%', data: males['25%'].slice(index,endIndex), lines: { show: true, lineWidth: 0, fill: 0.2 }, color: "rgb(50,50,255)", fillBetween: 'm15%' },
    { id: 'm50%', data: males['50%'].slice(index,endIndex), lines: { show: true, lineWidth: 0.5, fill: 0.4, shadowSize: 0 }, color: "rgb(50,50,255)", fillBetween: 'm25%' },
    { id: 'm75%', data: males['75%'].slice(index,endIndex), lines: { show: true, lineWidth: 0, fill: 0.4 }, color: "rgb(50,50,255)", fillBetween: 'm50%' },
    { id: 'm85%', data: males['85%'].slice(index,endIndex), lines: { show: true, lineWidth: 0, fill: 0.2 }, color: "rgb(50,50,255)", fillBetween: 'm75%' }
  ];

  index++;
  return dataset;
}
```

现在，如果您在浏览器中运行图表，您将一次看到 6 个月，每隔半秒，图表将通过将图表向前推一个月来更新，直到数据源的末尾。

## 工作原理...

`flotJS`具有内置逻辑，在重新绘制时重置自身，这是我们的魔法的一部分。我们的数据源是从`flotJS`的样本中借来的。我们实际上使用数据来表示一个虚构的情况。最初，这些数据代表了人们根据年龄的平均体重，按百分位数分解。但我们在这个例子中的重点不是展示数据，而是展示数据的可视化方式。因此，在我们的情况下，我们必须通过保持百分位数的原意来处理数据，但使用内部数据来展示多年来的平均值，而不是年龄，如下所示：

```js
{'15%': [[yearID, value], [yearID, value]...
```

`yearID`的值范围从`2`到`19`。我们希望将这些信息展示为如果我们从 2006 年开始选择我们的数据。每个`yearId`将代表一个月（19 将是 2006 年之后 1.5 年的时间，而不是实际代表的年龄 19）。

所以让我们开始分解。现在我们知道我们将如何处理我们的数据集，我们想要限制我们在任何给定时间内可以看到的月数。因此，我们将添加两个辅助参数，一个用于跟踪我们当前的索引，另一个用于跟踪任何给定时间内可见元素的最大数量：

```js
var VIEW_LENGTH = 5;
var index=0;
```

我们将为我们的 Flot 图创建一个全局变量，并创建一个格式化程序来帮助我们格式化将发送的数据。

```js
var plot;
var formattingData = {
  xaxis: { tickDecimals: 0, tickFormatter: function (v) { return v%12 + "/" + (2003+Math.floor(v/12)); } },
  yaxis: { tickFormatter: function (v) { return v + " cm"; } }
};
```

请注意，`tickFormater`使我们能够修改图表中刻度的外观方式。在 x 轴的情况下，目标是展示当前日期`2/2012...`，在 y 轴上，我们希望在屏幕上打印出的数字后面添加`cm`。

## 还有更多...

还有两件事情要讲——`getData`函数和`updateChart`函数。

### 获取数据函数

在`flotJS`中，每个数据点都有一个 ID。在我们的情况下，我们想展示六种相关的内容类型。调整参数以查看它们如何改变视图的方式。在我们发送创建的数组之前，我们将索引 ID 更新一次，这样下次调用函数时它将发送下一个范围。

我们需要注意的另一件事是实际数据范围。由于我们没有发送完整的数据范围（而是最多`5`个），我们需要验证索引后至少有五个项目，如果没有，我们将返回数组的最后一个元素，确保我们不会切割超过实际长度的部分：

```js
var endIndex = index+5>=males.length?males.length-1:index+5;
```

### 更新图表函数

这部分可能是最简单的。相同的代码用于第一次渲染和所有后续渲染。如果数据集有效，我们创建一个超时，并再次调用此函数，直到动画完成。

# 使用 RaphaelJS 构建时钟

毫无疑问，这是本章中我最喜欢的示例。它基于 Raphael 网站上的两个示例的混合（我强烈建议你去探索）。尽管`Raphael`不是一个绘图库，但它是一个非常强大的动画和绘图库，非常值得玩耍。

在这个示例中，我们将创建一个创意的时钟（我认为）。我计划玩这个库一两天，结果玩了整个周末，因为我玩得太开心了。我最终得到了一个数字变形时钟（基于 Raphael 在其网站上为字母变形创建的示例），并根据其网站上的极坐标时钟示例加入了一些弧线。让我们看看它的表现：

![使用 RaphaelJS 构建时钟](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_07_04.jpg)

## 准备工作

就像本章中的其他部分一样，您需要 Raphael 的原始库。我已经将其添加到我们的项目中。所以只需下载文件，让我们开始吧。

要获取原始库，请访问本章的外部源文件中心[`blog.everythingfla.com/?p=339`](http://blog.everythingfla.com/?p=339)。

## 如何做...

让我们构建我们的应用程序：

1.  创建 HTML 文件：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>Raphael</title>
    <meta charset="utf-8" />
    <script src="img/jquery.min.js"></script>
    <script src="img/raphael-min.js"></script> 
    <script src="img/07.04.raphael.js"></script>
    <style>
      body {
        background: #333;
        color: #fff;
        font: 300 100.1% "Helvetica Neue", Helvetica, "Arial Unicode MS", Arial, sans-serif;
      }
      #holder {
        height: 600px;
        margin: -300px 0 0 -300px;
        width: 600px;
        left: 50%;
        position: absolute;
        top: 50%;
      }
    </style>

  </head>
  <body>

  <div id="holder"></div>
  </body>
</html>
```

1.  现在是时候进入 JavaScript 文件`07.04.raphael.js`了。将路径参数复制到一个名为`helveticaForClock`的对象中，以绘制数字`0`到`9`和`:`符号。这实际上只是一个很长的数字列表，所以请从我们可下载的源文件中复制它们：

```js
var helveticaForClock = {...};
```

1.  我们将创建一个`onload`监听器，并将所有代码放入其中，以与 Raphael 示例中的代码风格相匹配：

```js
window.onload = function () {
  //the rest of the code will be put in here from step 3 and on
};
```

1.  创建一个 600 x 600 大小的新`Raphael`对象：

```js
var r = Raphael("holder", 600, 600);
```

1.  现在我们需要使用一个辅助函数来找出弧线的路径。为此，我们将创建一个`arc`函数作为我们新创建的`Raphael`对象的额外属性：

```js
r.customAttributes.arc = function (per,isClock) {
  var R = this.props.r,
  baseX = this.props.x,
  baseY = this.props.y;
  var degree = 360 *per;
  if(isClock) degree = 360-degree;

  var a = (90 - degree) * Math.PI / 180,
  x = baseX + R * Math.cos(a),
  y = baseY - R * Math.sin(a),
  path;

  if (per==1) {
    path = [["M", baseX, baseY - R], ["A", R, R, 0, 1, 1, baseX, baseY - R]];
  } else {
    path = [["M", baseX, baseY - R], ["A", R, R, 0, +(degree > 180), 1, x, y]];
  }

  var alpha=1;

  if(per<.1 || per>.9) 
    alpha = 0;
  else  
    alpha = 1;

  return {path: path,stroke: 'rgba(255,255,255,'+(1-per)+')'};  
};
```

1.  创建我们时钟的小时绘制（00:00）：

```js
var transPath;

var aTrans = ['T400,100','T320,100','T195,100','T115,100'];
var base0 = helveticaForClock[0];
var aLast = [0,0,0,0];
var aDigits = [];

var digit;
for(i=0; i<aLast.length; i++){
  digit = r.path("M0,0L0,0z").attr({fill: "#fff", stroke: "#fff", "fill-opacity": .3, "stroke-width": 1, "stroke-linecap": "round", translation: "100 100"});

  transPath = Raphael.transformPath(helveticaForClock[aLast[i]], aTrans[i]);
  digit.attr({path:transPath});
  aDigits.push(digit);
}
var dDot = r.path("M0,0L0,0z").attr({fill: "#fff", stroke: "#fff", "fill-opacity": .3, "stroke-width": 1, "stroke-linecap": "round", translation: "100 100"});
transPath = Raphael.transformPath(helveticaForClock[':'], 'T280,90');
dDot.attr({path:transPath});
```

1.  现在是时候为我们的`seconds`动画创建艺术品了：

```js
var time;
var sec = r.path();
sec.props = {r:30,x:300,y:300}; //new mandatory params

var sec2 = r.path();
sec2.props = {r:60,x:300,y:300};

animateSeconds();
animateStrokeWidth(sec,10,60,1000*60);
```

1.  创建`animateSeconds`递归函数：

```js
function animateSeconds(){ //will run forever
  time = new Date();

  sec.attr({arc: [1]});
  sec.animate({arc: [0]}, 1000, "=",animateSeconds);
  sec2.attr({arc: [1,true]});
  sec2.animate({arc: [0,true]}, 999, "=");

  var newDigits = [time.getMinutes()%10,
  parseInt(time.getMinutes()/10),
  time.getHours()%10,
  parseInt(time.getHours()/10)	];
  var path;
  var transPath;
  for(var i=0; i<aLast.length; i++){
    if(aLast[i]!=newDigits[i]){
      path = aDigits[i];
      aLast[i] = newDigits[i]; 	
      transPath = Raphael.transformPath(helveticaForClock[newDigits[i]], aTrans[i]);
      path.animate({path:transPath}, 500);
    }
  }

}
```

1.  创建`animateStrokeWidth`函数：

```js
function animateStrokeWidth(that,startWidth,endWidth,time){
  that.attr({'stroke-width':startWidth});
  that.animate({'stroke-width':endWidth},time,function(){
    animateStrokeWidth(that,startWidth,endWidth,time); //repeat forever
  });
}
```

如果现在运行应用程序，您将看到我与 Raphael 库玩耍一天的成果。

## 它是如何工作的...

这个项目有很多元素。让我们开始关注弧线动画。请注意，我们在代码中使用的一个元素是当我们创建新的路径时（我们创建了两个）。我们添加了一些硬编码的参数，这些参数将在`arc`方法中后来用于绘制弧线：

```js
var sec = r.path();sec.props = {r:30,x:300,y:300}; //new mandatory params

var sec2 = r.path();sec2.props = {r:60,x:300,y:300};
```

我们这样做是为了避免每次将这三个属性发送到弧线中，并且使我们能够选择一个半径并坚持下去，而不是将其集成或硬编码到动画中。我们的`arc`方法是基于 Raphael 示例中用于极坐标时钟的`arc`方法，但我们对其进行了更改，使值可以是正数或负数（这样更容易来回动画）。

然后在`animateSeconds`函数内部动画化时，使用`arc`方法来绘制我们的弧线：

```js
sec.attr({arc: [1]});
sec.animate({arc: [0]}, 1000, "=",animateSeconds);
sec2.attr({arc: [1,true]});
sec2.animate({arc: [0,true]}, 999, "=");
```

`attr`方法将重置我们的`arc`属性，以便我们可以重新对其进行动画处理。

顺便说一句，在`animateStrokeWidth`中，我们正在将我们的描边宽度从最小值动画到最大值，持续 60 秒。

## 还有更多...

你真的以为我们完成了吗？我知道你没有。让我们看看其他一些关键步骤。

### 动画路径

这个库中更酷的事情之一是能够动画化路径。如果您曾经使用过 Adobe Flash 的形状 Tween，这看起来会非常熟悉——毫无疑问，这真的很酷。

这个想法非常简单。我们有一个具有许多路径点的对象。如果我们通过它们绘制线信息，它们将一起创建一个形状。我们借用了 Raphael 创建的一个列表，所以我们不需要从头开始，而且我们在其中改变的只是我们不希望我们的元素按照它们当前的路径绘制。我们需要做的就是使用内部的`Raphael.transformPath`方法来转换它们的位置：

```js
transPath = Raphael.transformPath(helveticaForClock[0], 'T400,100');
```

换句话说，我们正在抓取数字 0 的路径信息，然后将其转换，向右移动 400 像素，向下移动 100 像素。

在我们的源代码中，看起来我们正在循环执行该函数（这有点更复杂，但是压缩了）：

```js
for(i=0; i<aLast.length; i++){
  digit = r.path("M0,0L0,0z").attr({fill: "#fff", stroke: "#fff", "fill-opacity": .3, "stroke-width": 1, "stroke-linecap": "round", translation: "100 100"});

  transPath = Raphael.transformPath(helveticaForClock[aLast[i]], aTrans[i]);
  digit.attr({path:transPath});
  aDigits.push(digit);
}
```

基本上，我们正在循环遍历`aLast`数组（我们要创建的数字列表），并为每个元素创建一个新的数字。然后，我们根据`aTrans`数组中的转换信息确定数字的位置，然后通过添加一个新的路径到属性中将其绘制出来。最后但并非最不重要的是，我们将我们的数字保存到`aDigits`数组中，以便在以后重新渲染元素时使用。

每次调用`animateSeconds`函数（每秒一次），我们都会弄清楚数字是否发生了变化，如果发生了变化，我们就准备更新它的信息：

```js
var newDigits = [time.getMinutes()%10,
  parseInt(time.getMinutes()/10),
  time.getHours()%10,
  parseInt(time.getHours()/10)];
var path;
var transPath;
  for(var i=0; i<aLast.length; i++){
    if(aLast[i]!=newDigits[i]){
    path = aDigits[i];
    aLast[i] = newDigits[i]; 	
    transPath = Raphael.transformPath(helveticaForClock[newDigits[i]], aTrans[i]);
    path.animate({path:transPath}, 500);
  }
}
```

我们首先收集当前时间`HH:MM`到一个数组中（`[H,H,M,M]`），然后查看我们的数字是否发生了变化。如果它们发生了变化，我们就从我们的`helveticaForClock`函数中获取所需的新数据，并在我们的新路径信息中为我们的数字（路径）进行动画处理。

这涵盖了遵循此方法的最重要因素。

# 使用 InfoVis 制作一个日晕图

另一个非常酷的库是`InfoVis`。如果我必须对这个库进行分类，我会说它是关于连接的。当您查看 Nicolas Garcia Belmonte 提供的丰富示例时，您会发现很多非常独特的关系数据类型。

这个库是通过 Sencha 的法定所有者免费分发的。（版权很容易遵循，但请查看您遇到的任何开源项目的说明。）

我们将从他的基本示例之一开始——源文件中的日晕示例。我做了一些改变，赋予它新的个性。日晕图的基本思想是展示节点之间的关系。树是有序的父子关系，而日晕图中的关系是双向的。一个节点可以与任何其他节点有关系，可以是双向或单向关系。一个完美适合这种情况的数据集是一个国家的总出口额的例子——从一个国家到所有其他从中获得出口的国家的线。

我们将保持相对简单，只有四个元素（Ben，Packt Publishing，02geek 和 InfoVis 的创建者 Nicolas）。我与他们每个人都有单向关系：作为`02geek.com`的所有者，作为 Packt Publishing 的作者，以及作为 InfoVis 的用户。虽然这对我来说是真的，但并非所有其他人都与我有真正深入的关系。其中一些人与我有联系，比如 02geek 和 Packt Publishing，而对于这个例子来说，Nicolas 是一个我从未互动过的陌生人。这可以用日晕图来描述：

![使用 InfoVis 制作日晕图](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_07_05.jpg)

## 准备工作

和往常一样，您将需要源文件，您可以下载我们的示例文件，或者访问我们的聚合列表获取最新版本。

## 如何做...

让我们创造一些 HTML 和 JavaScript 的魔法：

1.  创建一个 HTML 文件如下：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>Sunberst - InfoVis</title>
    <meta charset="utf-8" />

    <style>
      #infovis {
        position:relative;
        width:600px;
        height:600px;
        margin:auto;
        overflow:hidden;
      }
    </style>

    <script  src="img/jit-yc.js"></script>
    <script src="img/07.05.jit.js"></script>
  </head>

  <body onload="init();">
    <div id="infovis"></div>    
  </body>
</html>
```

1.  其余的代码将在`07.05.jit.js`中。创建一个基本数据源如下：

```js
var dataSource = [ {"id": "node0", "name": "","data": {"$type": "none" },"adjacencies": []}]; //starting with invisible root
```

1.  让我们创建一个将为我们的图表系统创建所需节点的函数：

```js
function createNode(id,name,wid,hei,clr){
  var obj = {id:id,name:name,data:{"$angularWidth":wid,"$height":hei,"$color":clr},adjacencies:[]};
  dataSource[0].adjacencies.push({"nodeTo": id,"data": {'$type': 'none'}});
  dataSource.push(obj);

  return obj;
}
```

1.  为了连接这些点，我们需要创建一个函数，用于创建元素之间的关系：

```js
function relate(obj){
  for(var i=1; i<arguments.length; i++){
    obj.adjacencies.push({'nodeTo':arguments[i]});
  }
}
```

1.  我们希望能够突出显示关系。为此，我们需要一种方法来重新排列数据并突出显示我们想要突出显示的元素：

```js
function highlight(nodeid){
  var selectedIndex = 0;
  for(var i=1; i<dataSource.length; i++){
    if(nodeid!=	dataSource[i].id){
      for(var item in dataSource[i].adjacencies)
      delete dataSource[i].adjacencies[item].data;
    }else{
      selectedIndex = i;
      for(var item in dataSource[i].adjacencies)
      dataSource[i].adjacencies[item].data =  {"$color": "#ddaacc","$lineWidth": 4 };
      }

    }

    if(selectedIndex){ //move selected node to be first (so it will highlight everything)
    var node = dataSource.splice(selectedIndex,1)[0];
    dataSource.splice(1,0,node); 
  }

}
```

1.  创建一个`init`函数：

```js
function init(){
/* or the remainder of the steps 
all code showcased will be inside the init function  */
}
```

1.  让我们开始建立数据源和关系：

```js
function init(){
  var node = createNode('geek','02geek',100,40,"#B1DDF3");
  relate(node,'ben');
  node = createNode('packt','PacktBub',100,40,"#FFDE89");
  relate(node,'ben');
  node = createNode('ben','Ben',100,40,"#E3675C");
  relate(node,'geek','packt','nic');

  node = createNode('nic','Nicolas',100,40,"#C2D985");
  //no known relationships so far ;)
...
```

1.  创建实际的旭日图并与 API 交互（我已将其简化到最基本的形式；在原始示例中，它更加详细）：

```js
var sb = new $jit.Sunburst({
  injectInto: 'infovis', //id container
  Node: {
    overridable: true,
    type: 'multipie'
  },
  Edge: {
    overridable: true,
    type: 'hyperline',
    lineWidth: 1,
    color: '#777'
  },
  //Add animations when hovering and clicking nodes
  NodeStyles: {
    enable: true,
    type: 'Native',
    stylesClick: {
    'color': '#444444'
  },
  stylesHover: {
    'color': '#777777'
  },
    duration: 700
  },
  Events: {
    enable: true,
    type: 'Native',
    //List node connections onClick
    onClick: function(node, eventInfo, e){
      if (!node) return;

      highlight(node.id);
      sb.loadJSON(dataSource);
      sb.refresh()
    }
  },
  levelDistance: 120
});
```

1.  最后但并非最不重要的是，我们希望通过提供其`dataSource`来渲染我们的图表，并首次刷新渲染：

```js
sb.loadJSON(dataSource);
sb.refresh();
```

就是这样。如果运行应用程序，您将找到一个可点击和有趣的图表，并且只是展示了这个真正酷的数据网络库的功能。

## 它是如何工作的...

我将避免详细介绍实际 API，因为那相当直观，并且具有非常丰富的信息和示例库。因此，我将专注于我在此应用程序中创建的更改和增强功能。

在我们这样做之前，我们需要了解此图表的数据结构是如何工作的。让我们深入了解填充信息后数据源对象的外观：

```js
{
        "id": "node0",
        "name": "",
        "data": {
          "$type": "none"
        },
        "adjacencies": [
            {"nodeTo": "node1","data": {'$type': 'none'}}, 
            {"nodeTo": "node2","data": {'$type': 'none'}}, 
            {"nodeTo": "node3","data": {'$type': 'none'}}, 
            {"nodeTo": "node4","data": {'$type': 'none'}}
                       ]
}, 

{
        "id": "node1",
        "name": "node 1",
        "data": {
          "$angularWidth": 300,
          "$color": "#B1DDF3",
          "$height": 40
        },
        "adjacencies": [
            {
              "nodeTo": "node3",
              "data": {
                "$color": "#ddaacc",
                "$lineWidth": 4
              }
            }
                    ]
},
```

有一些重要因素需要注意。首先是有一个基本父级，它是所有无父节点的父级的父级。在我们的情况下，它是一个平面图表。真正令人兴奋的关系是在相同级别的节点之间。因此，主父级与所有接下来的节点都有关系。子元素，例如在这种情况下的`node1`，可能具有关系。它们在一个名为`adjacencies`的数组中列出，其中包含对象。唯一强制性的参数是`nodeTo`属性。它让应用程序知道单向关系列表。还有一些可选的布局参数，我们将在需要突出显示一条线时才添加。因此，让我们看看如何使用一些函数动态创建这种类型的数据。

`createNode`函数通过将脏步骤封装在一起，帮助我们保持代码清晰。我们添加的每个新元素都需要添加到数组中，并且需要更新我们的主父元素（始终位于新元素数组的位置`0`）：

```js
function createNode(id,name,wid,hei,clr){
  var obj = {id:id,name:name,data:{"$angularWidth":wid,"$height":hei,"$color":clr},adjacencies:[]};
  dataSource[0].adjacencies.push({"nodeTo": id,"data": {'$type': 'none'}});
  dataSource.push(obj);

  return obj; 	
}
```

我们返回对象，因为我们希望继续并建立与该对象的关系。一旦我们创建一个新对象（在我们的`init`函数中），我们就调用`relate`函数，并将所有与其相关的关系发送给它。`relate`函数的逻辑看起来比实际上更复杂。该函数使用 JavaScript 中的一个隐藏或经常被忽略的特性，该特性使开发人员能够使用`arguments`数组将开放数量的参数发送到函数中，该数组在每个函数中都会自动创建。我们可以将这些参数作为名为`arguments`的数组获取：

```js
function relate(obj){
  for(var i=1; i<arguments.length; i++){
    obj.adjacencies.push({'nodeTo':arguments[i]});
  }
}
```

`arguments`数组内置在每个函数中，并存储已发送到函数中的所有实际信息。由于第一个参数是我们的对象，我们需要跳过第一个参数，然后将新关系添加到`adjacencies`数组中。

我们最后一个与数据相关的函数是我们的`highlight`函数。`highlight`函数期望一个参数`nodeID`（我们在`createNode`中创建）。`highlight`函数的目标是遍历所有数据元素，并取消突出显示限于所选元素及其关系的所有关系。

```js
function highlight(nodeid){
  var selectedIndex = 0;
  for(var i=1; i<dataSource.length; i++){
    if(nodeid!=	dataSource[i].id){
      for(var item in dataSource[i].adjacencies)
      delete dataSource[i].adjacencies[item].data;
    }else{
      selectedIndex = i;
      for(var item in dataSource[i].adjacencies)
      dataSource[i].adjacencies[item].data =  {"$color": "#ddaacc","$lineWidth": 4 };
    }

  }
}
```

如果我们没有`highlight`，我们希望确认并删除节点的邻接数据对象的所有实例，而如果它被选中，我们需要通过设置它的颜色和更粗的线来添加相同的对象。

数据几乎都完成了。但是在运行应用程序时，如果我们就此结束，你会发现一个问题。问题出在图表系统的工作方式上。如果画了一条线，它将不会再次重绘。实际上，如果我们选择“Ben”，而`ben`不是列表中的第一个元素，那么“Ben”与其他人的所有关系都将不可见。为了解决这个问题，我们希望将所选节点推到位置`0`（主要父节点）之后的第一个元素，这样它将首先渲染所选的关系：

```js
if(selectedIndex){ 
  var node = dataSource.splice(selectedIndex,1)[0];
  dataSource.splice(1,0,node); 
}
```

## 还有更多...

还有一件事是，当用户点击一个元素时，我们需要能够刷新我们的内容。为了完成这个任务，我们需要在`jit.Sunburst`的初始化参数对象中添加一个事件参数：

```js
var sb = new $jit.Sunburst({
  injectInto: 'infovis', //id container
     ...
  Events: {
    enable: true,
    type: 'Native',
    //List node connections onClick
    onClick: function(node, eventInfo, e){
      if (!node) return;

      highlight(node.id);
      sb.loadJSON(dataSource);
        sb.refresh();
    }
  },
  levelDistance: 120
});
```

在这个示例中需要注意的另一件事是`levelDistance`属性，它控制着你与渲染元素的距离（使其变大或变小）。

### 副本在哪里？

还有一个问题。我们的图表中没有任何副本，让我们知道实际点击的是什么。我从原始示例中删除了它，因为我不喜欢文本的定位，也搞不清楚如何把它弄对，所以我想出了一个变通方法。你可以直接与画布交互，直接在画布上绘制。画布元素将始终以与我们项目相同的 ID 命名（在我们的情况下是`infovis`后跟着`-canvas`）：

```js
var can = document.getElementById("infovis-canvas");
  var context = can.getContext("2d"); 
...
```

剩下的就留给你去探索了。逻辑的其余部分很容易理解，因为我已经简化了它。所以如果你也喜欢这个项目，请访问 InfoVis Toolkit 网站，并尝试更多他们的界面选项。


# 第八章：使用 Google 图表玩耍

在这一章中，我们将涵盖：

+   使用饼图开始

+   使用 ChartWrapper 创建图表

+   将数据源更改为 Google 电子表格

+   使用选项对象自定义图表属性

+   向图表添加仪表板

# 介绍

在这一章中，我们将逐个任务地探索 Google 可视化 API。我们将看一下创建图表并将其与图表 API 集成的步骤。

要使用 Google API，您必须遵守 Google 的使用条款和政策，可以在[`google-developers.appspot.com/readme/terms`](https://google-developers.appspot.com/readme/terms)找到。

# 使用饼图开始

在这个第一个示例中，我们将从 Google 图表开始，涵盖您在使用 Google 图表时需要了解的基本步骤，通过基于美国 CDC（LCWK）2008 年美国 15 个主要死因的死亡率的交互式数据集——死亡人数、总死亡人数的百分比以及按种族和性别分组的五年龄段内的死亡率。

## 准备工作

我们将从一个空的 HTML 文件和一个名为`08.01.getting-started.html`和`08.01.getting-started.js`的空 JavaScript 文件开始。

## 如何做...

让我们列出完成任务所需的步骤，从 HTML 文件开始：

1.  让我们从创建一个`head`并将其链接到 Google 的`jsapi`和我们的本地 JavaScript 文件开始：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>Google Charts Getting Started</title>
    <meta charset="utf-8" />   
    <script src="img/jsapi"></script>
    <script src="img/08.01.getting-started.js"></script>
  </head>
```

1.  然后创建一个空的`div`，带有`id chart`：

```js
  <body style="background:#fafafa">
    <div id="chart"></div>
  </body>
</html>
```

现在，是时候进入`08.01.getting-started.js`文件了。

1.  让我们从 Google 的`jsapi`请求可视化 API：

```js
google.load('visualization', '1.0', {'packages':['corechart']});
```

1.  我们想要添加一个`callback`，当库准备就绪时将被触发：

```js
google.setOnLoadCallback(init);
```

1.  创建一个`init`函数如下：

```js
function init(){
..

}
```

从现在开始，我们将分解在`init`函数中添加的代码：

1.  创建一个新的 Google 数据对象，并按以下代码片段中所示提供数据源：

```js
data.addColumn('string', 'Type of Death');
data.addColumn('number', 'Deaths');
data.addRows([
        ['Diseases of heart', 616828],
        ['Malignant neoplasms', 565469],
        ['Chronic lower respiratory diseases', 141090], 
        ['Cerebrovascular diseases', 134148],
        ['Accidents', 121902],
        ['Alzheimer\'s disease', 82435],
        ['Diabetes mellitus', 70553],
        ['Influenza and pneumonia', 56284],
        ['Suicide', 36035],
        ['Septicemia', 35927],
        ['Chronic liver disease and cirrhosis', 29963],
        ['Essential hypertension and hypertensive renal disease', 25742],
        ['Parkinson\'s disease', 20483],
        ['Homicide', 17826],
        ['All other causes', 469062]

]);
```

1.  为图表创建一个`options`对象：

```js
var options = {'title':'Deaths, for the 15 leading causes of death: United States, 2008',
                     'width':800,
                     'height':600};
```

1.  使用以下代码片段创建并绘制图表：

```js
var chart = new google.visualization.PieChart(document.getElementById('chart'));
    chart.draw(data, options);
```

加载 HTML 文件。您将会发现一个工作的交互式图表，如下截图所示：

![如何做...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_08_01.jpg)

## 它是如何工作的...

让我们探索与 Google 图表一起工作的步骤。我们在使用 Google API 时首先要做的是将 Google 的 API 链接添加到我们的 HTML 文件中：

```js
 <script src="img/jsapi"></script>
```

现在，Google API 已加载到我们的应用程序中，我们可以请求我们希望使用的库。在我们的情况下，我们想要使用可视化 API 和`corechart`包：

```js
google.load('visualization', '1.0', {'packages':['corechart']});
```

请注意，我们正在请求版本 1.0；这可能会让人困惑，但实际上我们正在请求生产图表，1.0 始终是当前的生产版本。因此，如果您想要锁定一个版本，您需要发现它的代码版本并发送它，而不是 1.0 稳定版本。

在示例中，`corechart`库定义了大多数基本图表。对于未包含的图表，您需要传入所需的额外包，例如表格图表：

```js
google.load('visualization', '1.0', {'packages':['corechart','table']});
```

这涵盖了如何加载 API 的基础知识。但在我们完成加载过程之前，我们需要一种方式来进行回调，以便我们知道库何时可供我们操作：

```js
google.setOnLoadCallback(init);
```

我们正在请求 Google API 让我们知道包何时加载，方式类似于我们向文档添加回调的方式。当 API 加载完成时，是时候让我们开始与图表 API 进行交互了。

在每个 Google 图表中，您可能想要探索三个组件：

+   创建数据源

+   向您的图表添加选项

+   创建图表

让我们探索所有这些选项。

所有 Google 图表都需要数据源。数据源格式是基于通过图表 API 创建的内部对象：

```js
var data = new google.visualization.DataTable();
```

数据表是 2D 数组（或表）。它们像数据库一样有列和行。我们的下一步将是定义数据列：

```js
data.addColumn('string', 'Type of Death');
data.addColumn('number', 'Deaths');
```

在我们的情况下，由于我们正在使用饼图，只需要两行——一行用于命名我们的元素，另一行用于为它们提供值。`addColumn`方法只有一个强制参数来定义数据类型。数据类型可以是以下之一：

+   `字符串`

+   `数字`

+   `布尔`

+   `日期`

+   `日期时间`

+   `timeofday`

第二个参数是数据类型的可选描述，用于可视化，例如在我们的情况下是`10 Deaths`。还有其他参数，但只要我们按照顺序提供元素，我们就不需要探索它们。

最后但并非最不重要的，我们将调用`addRows`方法。我们可以调用`addRows`方法并发送一个一维数组（再次按照我们设置`addColumn`的数据顺序）。在我们的情况下，我们正在使用期望二维数组的`addRows`方法：

```js
data.addRows([
        ['Diseases of heart', 616828],
....
]);
```

这涵盖了我们的数据集。只要我们按照我们的数据顺序设置列并通过数组发送我们的信息，我们就不需要深入研究数据 API。

`options`对象使我们能够创建和修改图表的元素。我们在应用程序中控制的元素是宽度、高度和标题。

创建数据源并为我们的数组设置选项后，现在是简单的部分。创建图表的第一步是选择图表类型并定义它将被创建的位置。然后我们用数据源和选项来渲染它：

```js
var chart = new google.visualization.PieChart(document.getElementById('chart'));
chart.draw(data, options);
```

## 还有更多...

让我们探索一些谷歌图表的技巧和高级功能。使用选项`Objectto 创建 3D 图表`，我们可以将我们的图表转换为 3D。我们可以非常快速简单地将一个新参数添加到选项对象中：

```js
var options = {'title':'Deaths, for the 15 leading causes of death: United States, 2008',
                     'width':800,
                     'height':600,
                     "is3D": true};
```

结果将是一个在 3D 空间中倾斜的图表。

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_08_02.jpg)

### 更改图表类型

更改图表类型并不复杂。只要图表类型共享相同数量的数据条目，更改通常只是从图表的实际构造对象中的一个单词。例如，我们可以通过更改调用可视化库中的方法来非常快速地切换图表类型：

```js
var chart = new google.visualization.LineChart(document.getElementById('chart'));
    chart.draw(data, options);
```

这将使用相同的数据，只是呈现为线图（`LineChart`对象）。

![更改图表类型](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_08_03.jpg)

# 使用 ChartWrapper 创建图表

使用谷歌图表创建图表有两种方法。一种是我们在*使用饼图入门*中所做的方式，另一种将在本教程中介绍。ChartWrapper 对象的目标是使您能够减少创建图表所需的代码量。

它的主要优点是代码更少，数据源的灵活性更大。它的缺点是对图形创建步骤的控制较少。

## 做好准备

从上一个教程（*使用饼图入门*）中获取 HTML 文件。我们只会修改外部 JavaScript 文件的文件路径，其余代码将保持不变。

## 如何做...

在更改 HTML 文件源路径为 JavaScript 文件之后，现在是时候进入 JavaScript 文件并重新开始了：

1.  加载谷歌 API（您不需要再提及您想要加载的内容），并添加一个回调：

```js
google.load('visualization', '1.0');
google.setOnLoadCallback(init);
```

1.  创建`init`函数：

```js
function init(){
...
}
```

1.  使用数据源构建一个 2D 数组：

```js
var dataTable = [
        ['Type of Death','Deaths'],
        ['Diseases of heart', 616828],
        ['Malignant neoplasms', 565469],
        ['Chronic lower respiratory diseases', 141090], 
        ['Cerebrovascular diseases', 134148],
        ['Accidents ', 121902],
        ['Alzheimer\'s disease ', 82435],
        ['Diabetes mellitus', 70553],
        ['Influenza and pneumonia', 56284],
        ['Suicide', 36035],
        ['Septicemia', 35927],
        ['Chronic liver disease and cirrhosis', 29963],
        ['Essential hypertension and hypertensive renal disease', 25742],
        ['Parkinson\'s disease', 20483],
        ['Homicide', 17826],
        ['All other causes', 469062]
      ];
```

1.  创建`options`对象：

```js
var options = {'title':'Deaths, for the 15 leading causes of death: United States, 2008',
                     'width':800,
                     'height':600,
                     "is3D": true};
```

1.  构建和渲染图表：

```js
var chart = new google.visualization.ChartWrapper({
  chartType:'PieChart',
  dataTable:dataTable,
  options:options,
  containerId:'chart'

});
chart.draw();
```

您已经完成了创建这种图表类型。刷新您的屏幕，您将看到与上一个例子中相同的图表，只是使用了更少的代码。

## 它是如何工作的...

这个例子的好处是你不需要知道更多关于它是如何工作的。`ChartWrapper`函数本身处理了你在上一个教程中需要处理的所有信息。话虽如此，并不意味着这种方式总是更好的方式——如果你需要更多对步骤的控制，上一个例子会更好地工作。

## 还有更多...

由于这个教程非常简单，让我们添加一个额外的指针。

### 在一行中更改图表

在 Google Chart API 的不同视图类型之间切换非常容易。你只需要切换类型。让我们把我们的图表改成`BarChart`：

```js
var chart = new google.visualization.ChartWrapper({
  chartType:'BarChart',
  dataTable:dataTable,
  options:options,
  containerId:'chart'

});
```

刷新你的窗口，你会发现一个条形图。

![一行代码改变图表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_08_04.jpg)

# 将数据源更改为 Google 电子表格

与 Google API 合作的一个强大功能是产品线之间的深层关系。在这个配方中，基于上一个配方，我们将创建一个 Google 电子表格，然后将其整合到我们的应用程序中。

## 准备工作

在你周围备有上一个配方的源文件的副本（*使用 ChartWrapper 创建图表*）。

## 操作步骤...

创建新的 Google 文档所涉及的步骤很简单，但需要能够整合我们的工作；因此我们将快速地运行一遍。

1.  转到[`drive.google.com/`](http://drive.google.com/)（以前称为 Google Docs）并注册/登录。

1.  创建一个新的电子表格。

1.  向电子表格添加数据。![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_08_05.jpg)

1.  点击**分享**按钮并将视图设置为公开：![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_08_06.jpg)

1.  根据文档 ID 创建 API URL：

+   **文档链接**：

[`docs.google.com/spreadsheet/ccc?key=0Aldzs55s0XbDdFJfUTNVSVltTS1ZQWQ0bWNsX2xSbVE`](https://docs.google.com/spreadsheet/ccc?key=0Aldzs55s0XbDdFJfUTNVSVltTS1ZQWQ0bWNsX2xSbVE)

+   **API 链接**：

[`spreadsheets.google.com/tq?key=0Aldzs55s0XbDdFJfUTNVSVltTS1ZQWQ0bWNsX2xSbVE`](https://spreadsheets.google.com/tq?key=0Aldzs55s0XbDdFJfUTNVSVltTS1ZQWQ0bWNsX2xSbVE)

1.  现在，是时候进入我们的 JavaScript 文件，删除当前数据源，并用 URL feed 替换它：

```js
google.load('visualization', '1.0');

google.setOnLoadCallback(init);

function init(){
  var options = {'title':'Deaths, for the 15 leading causes of death: United States, 2008',
                     'width':800,
                     'height':600};
  var chart = new google.visualization.ChartWrapper({
    chartType:'BarChart',
 dataSourceUrl:"https://spreadsheets.google.com/tq?key=0Aldzs55s0XbDdFJfUTNVSVltTS1ZQWQ0bWNsX2xSbVE",
    options:options,
    containerId:'chart'

  });
  chart.draw();	
}
```

太棒了！看看我们需要多少代码才能创建一个丰富而完全交互的图表：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_08_07.jpg)

## 它是如何工作的...

这真的是令人惊讶的部分。你不需要理解它是如何工作的，你只需要创建你的图表，并使用前一节提供的步骤，你就可以将你自己的任何电子表格转换成 Google 电子表格。

在前面的步骤中，最重要的一步是第 4 步。注意通过 Google 文档（Google Drive）生成的 URL 与在代码中工作时需要访问的 URL 不同。这是因为第一个 URL 旨在呈现为可视页面，而第二个链接生成一个新的 Google 数据对象。不要忘记每个页面都有自己独特的 ID。

## 还有更多...

如果你有一点关于使用数据库的背景，你可以将简单的 SQL 查询发送到数据源，只获取你想要查看的项目。比如在我们的例子中，我们想以不同的顺序获取项目，排除 B 列，并根据 D 列（按年龄）进行排序：

```js
SELECT A,E,D,C ORDER BY D
```

我们的`Select`语句列出了我们想要选择的内容。`ORDER BY`语句不言自明。让我们把它添加到我们的代码中：

```js
var chart = new google.visualization.ChartWrapper({
  chartType:'BarChart',
  dataSourceUrl:"https://spreadsheets.google.com/tq?key=0Aldzs55s0XbDdFJfUTNVSVltTS1ZQWQ0bWNsX2xSbVE",
  query: 'SELECT A,E,D,C ORDER BY D',
  options:options,
  containerId:'chart'

});
```

当你刷新你的代码时，B 列将消失，数据将根据 D 列进行组织。

最后但并非最不重要的，将这添加到你的代码中：

```js
var chart = new google.visualization.ChartWrapper({
  chartType:'BarChart',
  dataSourceUrl:"https://spreadsheets.google.com/tq?key=0Aldzs55s0XbDdFJfUTNVSVltTS1ZQWQ0bWNsX2xSbVE",
  query: 'SELECT A,E,D,C ORDER BY D',
  refreshInterval: 1,
  options:options,
  containerId:'chart'

});
chart.draw();
```

现在回到公共图表并更改其中的数据。你会发现它会自动更新图表。

# 使用选项对象自定义图表属性

在这个配方中，我们将使用 Google Charts API 创建一个新的图表——蜡烛图，并将各种配置整合到其中。

## 准备工作

我们将通过创建一个全新的 JavaScript 和 HTML 文件开始一个干净的板。

## 操作步骤...

大多数步骤看起来几乎与本章中的过去的配方相同。我们的主要重点将放在我们的`options`参数上：

1.  创建一个 HTML 文件并将其链接到一个 JavaScript 文件（在我们的例子中是`08.04.candlestick.js`）：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>Google Charts Getting Started</title>
    <meta charset="utf-8" />   
    <script src="img/jsapi"></script>
    <script src="img/08.04.candlestick.js"></script>		
  </head>
  <body style="background:#fafafa">
    <div id="chart"></div>
  </body>
</html>
```

1.  在`08.04.candlestick.js`文件中，添加 API 的`load`和`callback`函数：

```js
google.load('visualization', '1', {packages: ['corechart']});
google.setOnLoadCallback(init);

function init(){
```

1.  在`init`函数中（从现在开始到本配方结束，我们将一直保持在`init`函数中），使用`google.visualization.arrayToDataTable`方法创建一个新的`DataTable`对象：

```js
  var data = google.visualization.arrayToDataTable([
    ['Mon', 10, 24, 18, 21],
    ['Tue', 31, 38, 55, 74],
    ['Wed', 50, 55, 20, 103],
    ['Thu', 77, 77, 77, 77],
    ['Fri', 68, 66, 22, 15]
  ], true);
```

1.  为图表创建一个`options`对象（配置对象）：

```js
  var options = {
    legend:'none',
    backgroundColor:{fill:'#eeeeee',strokeWidth:2},
    bar:{groupWidth:17},
    candlestick:{hollowIsRising:true,
      fallingColor:{stroke:'red',fill:'#ffaaaa'},
      risingColor: {stroke:'blue',fill:'#aaaaff'}
    },
    enableInteractivity:false

  };
```

1.  使用以下代码片段绘制图表：

```js
  var chart = new google.visualization.CandlestickChart(document.getElementById('chart'));
  chart.draw(data, options);

}
```

加载 HTML 文件后，您将发现一个定制的蜡烛图表，如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_08_08.jpg)

## 它是如何工作的...

这是我们第一次使用`google.visualization.arrayToDataTable`方法。该方法接受一个数组并返回一个数据表。当此方法的第二个参数设置为`true`时，它将将数组中的第一行视为数据的一部分；否则，它将被视为标题数据。 

有许多选项，有关完整列表，请参阅 Google Charts 文档。我们将专注于我们选择修改视图的项目。Google 图表使您能够发送带有参数的对象。每种图表类型都有不同的选项集。在我们的情况下，我们有许多选项，使我们能够控制图表外观的细节。大多数选项与样式相关：

```js
backgroundColor:{fill:'#eeeeee',strokeWidth:2},
  bar:{groupWidth:17},
  candlestick:{hollowIsRising:true,
   fallingColor:{stroke:'red',fill:'#ffaaaa'},
  risingColor: {stroke:'blue',fill:'#aaaaff'}
  },
```

一些选项直接与功能相关，例如禁用图例：

```js
legend:'none',
```

或者禁用交互元素：

```js
enableInteractivity:false
```

## 还有更多...

突出显示这个元素的主要目的不是因为它很难，而是因为它很容易，这是您会发现自己对图表进行更改的主要地方。需要注意的一点是，在使用 Google Charts 之前，确保您可以通过使用 Google Charts 来做您需要的事情，因为与其他图表系统相反，您不能进入它们的源文件并对其进行更改，就像我们在第七章的示例中所做的那样，*依赖于开源领域*。

# 向图表添加仪表板

在本章的最后一个示例中，我们将添加实时控制器，使用户可以更改数据的过滤，以查看更少或更多的信息。

## 准备就绪

我们将从头开始，所以不用担心。

## 如何操作...

以下是创建基本仪表板控制器所需的步骤：

1.  创建一个 HTML 文件并将其链接到外部 JavaScript 文件（在我们的例子中，我们将使用文件`08.05.slider.js`）：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>Google Charts DASHBOARD</title>
    <meta charset="utf-8" />   
    <script src="img/jsapi"></script>
    <script src="img/08.05.slider.js"></script>		
  </head>
  <body style="background:#fafafa">
 <div id="chart"></div>
 <div id="dashboard"></div>
 <div id="filter"></div>
  </body>
</html>
```

1.  现在，是时候进入`08.05.slider.js`并加载 Google Visualization API 了。这一次我们将加载控制器包：

```js
google.load('visualization', '1', {packages: ['controls']});
```

1.  现在，是时候添加一个回调了：

```js
google.setOnLoadCallback(init);
function init(){
```

1.  让我们创建我们的数据源。我们将以 2008 年 CDC 死亡率为基础：

```js
var data = google.visualization.arrayToDataTable([
    ['Age (+- 2 Years)', 'Deaths'],
        [2, 4730],
        [7, 2502],
        [12, 3149], 
        [17, 12407],
        [22, 19791],
        [27,20786],
        [32,21489],
        [37,29864],
        [42,46506],
        [47,77417],
        [52, 109125],
        [57,134708],
        [62,161474],
        [67,183450],
        [72,218129],
        [77,287370],
        [82,366190],
        [87,372552],
        [92,251381],
         [100,20892],
    ]);
```

1.  然后创建一个新的仪表板：

```js
var dashboard = new google.visualization.Dashboard(document.getElementById('dashboard'));
```

1.  让我们创建一个滑块并为其提供连接到数据源所需的信息：

```js
  var slider = new google.visualization.ControlWrapper({
    containerId: 'filter',
    controlType: 'NumberRangeFilter',
    options: {
    filterColumnLabel: 'Age (+- 2 Years)'
  }
});
```

1.  创建一个图表：

```js
var chart = new google.visualization.ChartWrapper({
  chartType: 'ScatterChart',
  containerId: 'chart',
  options: {
    legend: 'left',
    title:'Deaths, for the 15 leading causes of death: United States, 2008',
    width: 800,
    height: 600

  }
});
```

1.  最后但并非最不重要的，是时候绑定和绘制我们的控制器了：

```js
dashboard.bind(slider, chart).draw(data);			
}
```

加载 HTML 文件，您将发现一个散点图，带有一个控制器，可以选择您想要深入了解的年龄范围。

![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_08_09.jpg)

## 它是如何工作的...

这可能是使用 Google 图表 API 中最顺畅的部分之一。因此，让我们分解并弄清楚创建图表控制器涉及的步骤。我们将展示一个控制器，但相同的逻辑流程适用于所有组件。

首先，在我们的 HTML 文件中，我们需要有一个与我们的仪表板关联的`div`层和每个后续控制器的`div`。要添加控制器，我们将它们分配给仪表板。我们首先创建一个仪表板：

```js
var dashboard = new google.visualization.Dashboard(document.getElementById('dashboard'));
```

这个仪表板现在将成为我们连接所有控制器的中心（在我们的情况下，一个控制器）。然后，我们将创建下一个控制器；在我们的情况下，我们想使用一个滑块：

```js
var slider = new google.visualization.ControlWrapper({
  containerId: 'filter',
  controlType: 'NumberRangeFilter',
  options: {
    filterColumnLabel: 'Age (+- 2 Years)'
  }
});
```

请注意，我们正在添加一个控件类型以获取我们的范围滑块，并通过给它列 ID（第一行中的标签）来将其链接到列。

我们继续以与之前相同的方式创建图表。在这种情况下，我们选择了散点图。这里的顺序并不重要，但最重要的部分是连接我们的控制器和图表。我们通过使用`dashboard.bind`方法来实现这一点：

```js
dashboard.bind(slider, chart);	
```

然后，当创建一个`bind`函数时，我们将我们的元素绘制为我们的仪表板返回自身：

```js
dashboard.bind(slider, chart).draw(data);
```

如果我们想的话，我们可以将其拆分为如下的单独行：

```js
dashboard.bind(slider, chart);
dashboard.draw(data);
```

现在你知道如何使用仪表板了。这些步骤很关键，但现在你可以添加任何控制器。这个产品的其余文档是不言自明的。


# 第九章：使用 Google 地图

在本章中，我们将涵盖：

+   使用 Google Visualization API 创建地理图表

+   获取 Google API 密钥

+   构建 Google 地图

+   添加标记和事件

+   自定义控件和重叠地图

+   使用样式重新设计地图

# 介绍

本章将致力于探索 Google 地图上的一些功能，以便让我们准备好处理地图工作。单独的地图并不是数据可视化，但是在我们通过了解如何处理地图来建立基础之后，我们将能够通过整合数据和数据可视化来创建许多尖端、酷炫的项目。

在本章中，我们将探索在 Google 领域创建地图的主要方法。

# 使用 Google Visualization API 创建地理图表

在本章的第一个配方中，我们将开始使用基于矢量的世界地图。我们将用它来根据数据源突出显示国家。在我们的情况下，我们将使用维基百科的国家列表，根据故意谋杀率（最新数据）。

要查看原始数据，请访问[`en.wikipedia.org/wiki/List_of_countries_by_intentional_homicide_rate`](http://en.wikipedia.org/wiki/List_of_countries_by_intentional_homicide_rate)。

我们的目标是拥有一张世界地图，根据每 10 万人中故意谋杀的数量而突出显示一系列颜色。根据维基百科 2012 年的最新数据，它听起来像是最不安全的地方是洪都拉斯——如果你不想被故意杀害的话——而在日本你应该感到非常安全。你的国家怎么样？我的国家还不错。我可能应该避开让我感觉自己生活在战区的当地新闻台。

![使用 Google Visualization API 创建地理图表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_09_01.jpg)

## 准备工作

不需要做太多事情。我们将使用 Google Visualization API 来创建地理图表。

## 如何做...

我们将创建一个新的 HTML 和一个新的 JavaScript 文件，并将它们命名为`08.01.geo-chart.html`和`08.01.geo-chart.js`。按照以下步骤进行：

1.  在 HTML 文件中添加以下代码：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>Geo Charts</title>
    <meta charset="utf-8" />   
    <script src="img/jsapi"></script>
    <script src="img/08.01.geo-chart.js"></script>
  </head>
  <body style="background:#fafafa">
    <div id="chart"></div>
  </body>
</html>
```

1.  让我们转到`js`文件。这一次，我们将要求从 Google Visualization 包中请求`geochart`功能。为此，我们将从以下代码开始：

```js
google.load('visualization','1',{'packages': ['geochart']});
```

1.  然后我们将添加一个回调，当包准备就绪时将触发`init`函数：

```js
google.setOnLoadCallback(init);
function init(){
 //...
}
```

1.  现在是时候在`init`函数中添加逻辑了。在第一步中，我们将从维基百科格式化数据为另一种格式，以便适用于 Google Visualization API：

```js
var data = google.visualization.arrayToDataTable([
    ['Country','Intentional Homicide Rate per 100,000'],
    ['Honduras',87],['El Salvador',71],['Saint Kitts and Nevis',68],
    ['Venezuela',67],['Belize',39],['Guatemala',39],['Jamaica',39],
    ['Bahamas',36],['Colombia',33],['South Africa', 32],
    ['Dominican Republic',31],['Trinidad and Tobago',28],['Brazil',26],
    ['Dominica', 22],['Saint Lucia',22],['Saint Vincent and the Grenadines',22],
    ['Panama',20],['Guyana',18],['Mexico',18],['Ecuador',16],
    ['Nicaragua',13],['Grenada',12],['Paraguay',12],['Russia',12],
    ['Barbados',11],['Costa Rica',10 ],['Bolivia',8.9],
    ['Estonia',7.5],['Moldova',7.4],['Haiti',6.9],
    ['Antigua and Barbuda',6.8],['Uruguay',6.1],['Thailand',5.3],
    ['Ukraine',5.2],['United States',4.7 ],['Georgia',4.1],['Latvia',4.1 ],
    ['India',3.2],['Taiwan',3.0 ],['Bangladesh',2.4 ],['Lebanon',2.2],
    ['Finland',2.1 ],['Israel', 2.1],['Macedonia',1.94 ],['Canada',1.7],
    ['Czech Republic',1.67],['New Zealand',1.41],['Morocco',1.40 ],
    ['Chile',1.33],['United Kingdom',1.23 ],['Australia',1.16],
    ['Poland',1.1 ],['Ireland',0.96 ],['Italy',.87 ],['Netherlands',.86 ],
    ['Sweden',.86],['Denmark',.85],['Germany',.81 ],['Spain',0.72],
    ['Norway',0.68],['Austria',0.56],['Japan',.35] 
]);
```

1.  让我们配置我们的图表选项：

```js
var options = {width:800,height:600};
```

1.  最后但绝不是最不重要的，让我们创建我们的图表：

```js
 var chart = new google.visualization.GeoChart(document.getElementById('chart'));
  chart.draw(data,options);
}//end of init function
```

当您加载 HTML 文件时，您会发现世界各国以反映谋杀率的突出颜色显示出来。（我们没有所有世界国家的完整列表，有些国家太小，很难找到它们。）

## 它是如何工作的...

这个配方的逻辑非常简单，所以让我们快速浏览一下，并添加一些额外的功能。与所有其他可视化图表一样，有三个单独的步骤：

+   定义数据源

+   设置图表

+   绘制图表

并非所有国家都是相同的。如果您在处理一个有轮廓的国家时遇到问题，请搜索最新的 Google 文档，了解支持的国家。您可以在[`gmaps-samples.googlecode.com/svn/trunk/mapcoverage_filtered.html`](http://gmaps-samples.googlecode.com/svn/trunk/mapcoverage_filtered.html)上查看完整列表。

## 还有更多...

让我们对我们的图表添加一些额外的自定义。与所有 Google Visualization 库元素一样，我们可以通过`options`对象控制许多可视化效果。

我们地图中突出显示的绿色看起来不对。你会认为杀戮越少，一个国家就会越绿，所以在杀戮更多的地方，更深的红色更合适。所以让我们通过更新`options`对象来改变颜色：

```js
  var options = {width:800,height:600,
    colorAxis: {colors: ['#eeffee', 'red']}
      };
```

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_09_02.jpg)

### 使较小的区域更可见

为了解决真正小的不可见的国家的问题，我们可以将我们的渲染切换为基于标记的。我们可以切换到基于标记的渲染模式，而不是突出显示土地本身：

```js
var options = {width:800,height:600,
    displayMode: 'markers',
        colorAxis: {colors: ['#22ff22', 'red']}
      };
```

默认情况下，当使用标记渲染可视化地图时，当您在压缩区域上滚动时，高亮的缩放视图将帮助创建更清晰的视图：

![使较小的区域更可见](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_09_03.jpg)

另一个选择是放大到该区域（我们可以两者都做，或者只是放大）。要放大到一个区域，我们将使用这段代码：

```js
  var options = {width:800,height:600,
    region:'MX',
        colorAxis: {colors: ['#22ff22', 'red']}
      };
```

要了解可能的值列表，请参阅本章前面的国家列表。在这种情况下，我们正在放大到`MX`地区：

![使较小的区域更可见](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_09_04.jpg)

这涵盖了使用地理图表的基础知识。有关使用 Google Visualization API 的更多信息，请参阅第八章*玩转 Google 图表*。

# 获取 Google API 密钥

要使用大多数 Google API，你必须有一个 Google API 密钥。因此，我们将介绍获取 Google API 密钥所涉及的步骤。

Google API 有一些限制和约束。尽管大多数 API 对于中小型网站是免费的，但你仍然受到一些规则的约束。请参考每个库的规则和条例。

## 准备工作

要完成这个示例，你必须有一个 Google ID；如果你没有，你需要创建一个。

## 如何做...

让我们列出获得访问 Google API 所需步骤：

1.  登录到[`code.google.com/apis/console`](https://code.google.com/apis/console)的 API 控制台。

1.  从左侧菜单中选择**服务**选项：![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_09_05.jpg)

1.  激活你想要使用的 API（例如，在下一个示例*构建 Google 地图*中，我们将使用 Google Maps API v3 服务）：![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_09_06.jpg)

1.  同样，在左侧菜单中选择**API 访问**选项。您将需要复制**API 密钥**并在将来的 Google API 项目中替换它：![操作步骤...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_09_07.jpg)

这是我们唯一一次讨论与 Google API 平台的密钥和权限有关的问题。请验证您已激活密钥，并设置正确的库以便您可以访问。

## 它是如何工作的...

理解这是如何工作的并不难。你只需要记住这些步骤，因为它们将成为我们创建未来 Google API 交互的基础。

正如你可能已经注意到的，Google 库中有许多 API，我们甚至无法全部涉及，但我建议你浏览一下并探索你的选择。在接下来的几个示例中，我们将使用 Google API 来执行一些与地图相关的任务。

# 构建 Google 地图

数据和地理有着非常自然的关系。数据在地图上更有意义。使用实时地图是一个非常好的选择，因为它可以让用户与地理区域内集成了您自己数据呈现的 UI 进行交互。在这个示例中，我们将集成我们的第一个真实实时地图。

## 准备工作

要完成这个示例，你必须有一个 Google ID。如果你没有，你需要创建一个。除此之外，你还需要在 API 控制台中激活 Google Maps API v3 服务。有关更多信息，请参阅本章前面讨论的*获取 Google API 密钥*示例。

我们的目标是创建一个全屏的 Google 地图，将放大并聚焦在法国：

![准备工作](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_09_08.jpg)

## 如何做...

让我们列出创建此示例的步骤。要创建此示例，我们将创建两个文件——一个`.html`文件和一个`.js`文件：

1.  让我们从 HTML 文件开始。我们将为我们的项目创建一个基本的 HTML 文件基线：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>Google Maps Hello world</title>
    <meta charset="utf-8" />
  </head>
  <body>
    <div id="jsmap"></div>
  </body>
</html>
```

1.  我们将添加 HTML 视口信息。这是移动设备如何呈现页面的指示（如果您不关心在移动设备上访问地图，可以跳过此步骤）：

```js
<head>
  <title>Google Maps Hello world</title>
  <meta charset="utf-8" />
 <meta name="viewport" content="initial-scale=1.0, user-scalable=no" /> 
</head>
```

1.  将样式信息添加到头部：

```js
<style>
  html { height: 100% }
  body { height: 100%; margin: 0; padding: 0 }
  #jsmap { height: 100%; width:100% }
</style>
```

1.  加载 Google Maps v3 API（用您的 API 密钥替换粗体文本）：

```js
<script src="img/strong>&sensor=true">
```

1.  添加我们的`09.03.googleJSmaps.js` JavaScript 文件的脚本源：

```js
<script src="img/09.03.googleJSmaps.js"></script>
```

1.  添加一个`onload`触发器，将调用`init`函数（这将在下一步中创建）：

```js
<body onload="init();">
```

1.  在`09.03.googleJSmaps.js` JavaScript 文件中，添加`init`函数：

```js
function init() {
  var mapOptions = {
    center: new google.maps.LatLng(45.52, 0),
    zoom: 7,
    mapTypeId: google.maps.MapTypeId.ROADMAP
  };
  var map = new google.maps.Map(document.getElementById("jsmap"), mapOptions);
}
```

1.  加载 HTML 文件，您应该会发现一个全屏幕的路线图缩放到法国。

## 它是如何工作的...

最重要和第一步是加载`maps` API。为了让 Google 满足您的请求，您必须拥有有效的 API 密钥。因此，请不要忘记用您的密钥替换粗体文本：

```js
<script src="img/strong>&sensor=true">
```

不要忘记使用您自己的密钥。您可能会发现自己的网站地图出现故障。URL 中的`sensor`参数是强制性的，必须设置为`true`或`false`。如果您的地图需要知道用户位置在哪里，您必须将其设置为`true`，如果不需要，可以将其设置为`false`。

在我们的应用程序中另一个有趣的事情是，这是我们第一次在示例中使用视口。由于这个主题超出了本书的范围，我想留下来。我知道你们中的许多人最终会在移动设备上使用地图，并希望地图默认为垂直/水平视图。要了解更多有关视口如何工作的信息，请查看此处提供的文章：[`developer.mozilla.org/en/Mobile/Viewport_meta_tag/`](https://developer.mozilla.org/en/Mobile/Viewport_meta_tag/)。

您可能已经注意到，我们在我们的 CSS 中设置了许多东西为 100%，正如您可能猜到的那样，这是为了向后兼容性和验证地图将填满整个屏幕。如果您只想创建一个固定的宽度/高度，您可以通过用以下代码替换 CSS 来实现：

```js
<style>
    #jsmap { height: 200px; width:300px; }
</style>
```

这涵盖了我们在 HTML 文件中需要做的主要事情。

## 还有更多...

我们还没有涵盖`init`函数如何工作的细节。`init`函数的基本原理非常简单。创建地图只涉及两个步骤。我们需要知道我们希望地图位于哪个`div`层，并且我们希望将哪些选项发送到我们的地图：

```js
var map = new google.maps.Map(div,options);
```

与上一个配方中的 Google 可视化 API 有三个步骤不同，我们可以看到 Google `maps` API 只有一个步骤，在其中我们直接发送两个选项以进行渲染（在创建和渲染之间没有步骤）。

让我们更深入地了解选项，因为它们将改变地图的大部分视觉和功能。

### 使用纬度和经度

**纬度和经度**（**lat/long**）是一种将地球划分为网格模式的坐标系统，使得在地球上定位点变得容易。纬度代表垂直空间，而经度代表水平空间。需要注意的是，谷歌使用世界大地测量系统 WGS84 标准。还有其他标准存在，所以如果你的纬度/经度不使用相同的标准，你会发现自己位于一个与最初寻找的位置不同的地方。

基于纬度/经度定位区域的最简单方法是通过我们地图上的辅助工具或搜索主要城市的纬度/经度信息。

[`www.gorissen.info/Pierre/maps/googleMapLocation.php`](http://www.gorissen.info/Pierre/maps/googleMapLocation.php)将帮助您直接在谷歌地图上点击以定位一个点。在此类别中的另一个选项是在主谷歌地图站点（[`maps.google.com/`](http://maps.google.com/)）上打开实验室功能。在屏幕左下角的主谷歌地图站点上，您会找到**地图实验室**。在那里，您会找到一些纬度/经度助手。

或者您可以通过访问[`www.realestate3d.com/gps/latlong.htm`](http://www.realestate3d.com/gps/latlong.htm)按城市搜索数据。

在我们的情况下，当我们准备好做出选择时，我们将更新`options center`属性，以反映我们希望地图居中的位置，并调整缩放级别，直到感觉合适：

```js
var mapOptions = {
    center: new google.maps.LatLng(45.52, 0),
    zoom: 7,
    mapTypeId: google.maps.MapTypeId.ROADMAP
};
```

### 地图类型

有许多地图类型，甚至可以创建自定义的地图类型，但是对于我们的需求，我们将专注于最常用的基本类型：

+   `google.maps.MapTypeId.ROADMAP`：显示谷歌地图的正常、默认的 2D 瓦片

+   `google.maps.MapTypeId.SATELLITE`：显示摄影瓦片

+   `google.maps.MapTypeId.HYBRID`：显示摄影瓦片和突出特征的瓦片图层（道路、城市名称等）

+   `google.maps.MapTypeId.TERRAIN`：显示用于显示海拔和水体特征（山脉、河流等）的物理地形瓦片

这涵盖了您需要了解的基础知识，以便将地图集成到网站上。

# 添加标记和事件

我们屏幕上有地图很棒（假设您已经按照上一篇文章*构建谷歌地图*），但是如何连接数据并将其集成到我们的地图中呢。我很高兴你问到了这个问题，因为这篇文章将是我们第一步，将数据添加到标记和事件的形式中。

在这个示例中，我们的目标是在纽约市放置四个标记。当点击标记时，我们将放大到该区域并切换地图视图类型。

![添加标记和事件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_09_09.jpg)

## 准备工作

在这个阶段，您应该已经使用 JS API 创建了（至少一次）谷歌地图；如果没有，请回到*构建谷歌地图*的步骤。

## 如何做到这一点...

我们不会在上一篇文章*构建谷歌地图*中创建的 HTML 页面中进行进一步的更改；因此，我们将把注意力集中在 JavaScript 文件上：

1.  创建一个`init`函数：

```js
function init(){
//all the rest of logic in here
}
```

1.  在`base`状态中创建地图常量，然后放大到该状态：

```js
function init() {
  var BASE_CENTER = new google.maps.LatLng(40.7142,-74.0064 );
  var BASE_ZOOM = 11;
  var BASE_MAP_TYPE = google.maps.MapTypeId.SATELLITE;
  var INNER_ZOOM = 14;
  var INNER_MAP_TYPE = google.maps.MapTypeId.ROADMAP;
```

1.  创建默认地图选项：

```js
//40.7142° N, -74.0064 E NYC
var mapOptions = {
  center: BASE_CENTER,
  zoom: BASE_ZOOM,
  mapTypeId: BASE_MAP_TYPE
};
var map = new google.maps.Map(document.getElementById("jsmap"), mapOptions);
```

1.  为我们的点创建数据源：

```js
var aMarkers = [
  {label:'New York City',
  local: map.getCenter()},
  {label:'Brooklyn',
  local: new google.maps.LatLng(40.648, -73.957)},
  {label:'Queens',
  local: new google.maps.LatLng(40.732, -73.800)}, 
  {label:'Bronx',
  local: new google.maps.LatLng(40.851, -73.871)},  

];
```

1.  循环遍历每个数组元素，并创建一个带有事件的标记，该事件将放大到该位置，切换视图并平移到正确的位置：

```js
var marker;

for(var i=0; i<aMarkers.length; i++){
  marker = new google.maps.Marker({
    position: aMarkers[i].local,
    map: map,
    title: aMarkers[i].label
  });
  google.maps.event.addListener(marker, 'click', function(ev) {
    map.setZoom(INNER_ZOOM);
    map.panTo(ev.latLng);
    map.setMapTypeId(INNER_MAP_TYPE);
  });

}
```

1.  最后但并非最不重要的是，使地图可点击。因此，当用户点击地图时，它应该重置为其原始状态：

```js
google.maps.event.addListener(map, 'click', function() {
   	 map.setZoom(BASE_ZOOM);
    map.panTo(BASE_CENTER);
    map.setMapTypeId(BASE_MAP_TYPE);

});
```

当您运行应用程序时，您会在屏幕上找到四个标记。当您点击它们时，您将跳转到更深的缩放视图。当您点击空白区域时，它将带您回到原始视图。

## 工作原理...

与事件和谷歌地图一起工作非常容易。所涉及的步骤始终从调用静态方法`google.maps.event.addListener`开始。此函数接受三个参数，即要监听的项目、事件类型（作为字符串）和一个函数。

例如，在我们的`for`循环中，我们创建标记，然后为它们添加事件：

```js
 google.maps.event.addListener(marker, 'click', function(ev) {
    map.setZoom(INNER_ZOOM);
    map.panTo(ev.latLng);
    map.setMapTypeId(INNER_MAP_TYPE);
  });
```

相反，我们可以创建事件，然后不需要每次循环时重新创建一个新的匿名函数：

```js
for(var i=0; i<aMarkers.length; i++){
  marker = new google.maps.Marker({
    position: aMarkers[i].local,
    map: map,
    title: aMarkers[i].label
  });	

  google.maps.event.addListener(marker, 'click', onMarkerClicked);
  }

 function onMarkerClicked(ev){
 map.setZoom(INNER_ZOOM);
 map.panTo(ev.latLng);
 map.setMapTypeId(INNER_MAP_TYPE);
  }
```

优势真的很大。我们不是为每个循环创建一个函数，而是在整个过程中使用相同的函数（更智能，内存占用更小）。在我们的代码中，我们没有提及任何硬编码的值。相反，我们使用事件信息来获取`latLng`属性。我们可以毫无问题地重复使用相同的函数。顺便说一句，您可能已经注意到，这是我们第一次将一个命名函数放在另一个命名函数（`init`函数）中。这并不是问题，它的工作方式与变量作用域完全相同。换句话说，我们创建的这个函数只在`init`函数范围内可见。

创建标记非常简单；我们只需要创建一个新的`google.maps.Marker`并为其分配一个位置和一个地图。所有其他选项都是可选的。（有关完整列表，请查看[`developers.google.com/maps/documentation/javascript/reference#MarkerOptions`](https://developers.google.com/maps/documentation/javascript/reference#MarkerOptions)上可用的 Google API 文档。）

## 还有更多...

您可能已经注意到我们使用了`map.panTo`方法，但实际上没有发生平移，一切都会立即到位。如果运行地图，您会发现我们实际上并没有看到任何平移；这是因为我们同时切换了地图类型，缩小了地图，并进行了平移。只有平移可以在没有一些技巧和绕过的情况下实际动画化，但所有这些步骤使我们的应用程序变得更加复杂，对动画的实际控制非常有限。在下一个示例中，我们将提出一个解决方案，因为我们使用了两张地图而不是一张地图*自定义控件和重叠地图*。如果我们愿意，我们可以添加延迟并分别执行每个步骤并动画化平移，但如果我们想要创建一个平滑的过渡，我会考虑使用两张叠放在一起的地图，然后淡入和淡出主世界地图的想法。

# 自定义控件和重叠地图

这个示例的目标是练习使用 Google 地图。我们将在本章学到的关于使用 Google 地图的知识，并将我们对用户行为的控制，例如用户可以使用哪些控制器，整合到其中。我们将开始挖掘创建我们自己不支持的未记录的行为，例如锁定用户的平移区域。

在这个示例中，我们的主要任务是将我们在上一个示例中的工作，而不是让地图放大和移动，而是在放大和缩小选项之间创建清晰的过渡；但由于界面不支持以清晰的方式进行，我们将使用外部焦点。这个想法很简单；我们将两张地图叠放在一起，淡入和淡出顶部地图，从而完全控制过渡的流畅性。

## 准备工作

尽管我们是从头开始的，但我们在上一个示例中所做的大部分工作都被重复使用，因此我强烈建议您在进入本示例之前先阅读上一个示例*添加标记和事件*。

在这个示例中，我们还将把 jQuery 整合到我们的工作中，以节省我们在创建自己的动画工具上的时间（或者重用我们在第六章中创建的动画独立图层的工具），因为这会让我们偏离主题。

## 如何做到...

在这个示例中，我们将创建两个文件。一个 HTML 文件和一个 JS 文件。让我们来看看，从 HTML 文件开始：

1.  创建一个 HTML 文件并导入 Google `maps` API 和 jQuery：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>Google Maps Markers and Events</title>
    <meta charset="utf-8" />
    <meta name="viewport" content="initial-scale=1.0, user-scalable=no" />
    <script src="img/jquery.min.js"></script>
    <script src="img/js?key=AIzaSyAywwIFJPo67Yd4vZgPz4EUSVu10BLHroE&sensor=true"></script>
    <script src="img/09.05.controls.js"></script>
  </head>
  <body onload="init();">
    <div id="mapIn"></div>
  <div id="mapOut"></div>
  </body>
</html>
```

1.  使用 CSS 将地图的图层堆叠在一起：

```js
<style>
    html { height: 100% }
    body { height: 100%; margin: 0; padding: 0 }
    #mapIn, #mapOut { height: 100%; width:100%; position:absolute; top:0px; left:0px }
</style>
```

1.  创建`09.05.controls.js` JS 文件，并在其中创建一个`init`函数（从这一点开始，其余的代码将在`init`函数中）：

```js
function init(){
  //rest of code in here
}
```

1.  创建具有自定义信息的两张地图：

```js
var BASE_CENTER = new google.maps.LatLng(40.7142,-74.0064 );

//40.7142¬∞ N, -74.0064 E NYC
var mapOut = new google.maps.Map(document.getElementById("mapOut"),{
  center: BASE_CENTER,
  zoom: 11,
  mapTypeId: google.maps.MapTypeId.SATELLITE,
  disableDefaultUI: true
});
var mapIn = new google.maps.Map(document.getElementById("mapIn"),{
  center: BASE_CENTER,
  zoom: 14,
  mapTypeId: google.maps.MapTypeId.ROADMAP,
  disableDefaultUI: true,
  panControl:true
});
```

1.  将标记添加到上层地图：

```js
var aMarkers = [
  {label:'New York City',
  local: mapOut.getCenter()},
  {label:'Brooklyn',
  local: new google.maps.LatLng(40.648, -73.957)},
  {label:'Queens',
  local: new google.maps.LatLng(40.732, -73.800)}, 
  {label:'Bronx',
  local: new google.maps.LatLng(40.851, -73.871)},  

];
var marker;

  for(var i=0; i<aMarkers.length; i++){
    marker = new google.maps.Marker({
      position: aMarkers[i].local,
      map: mapOut,
      title: aMarkers[i].label
    });

  google.maps.event.addListener(marker, 'click', onMarkerClicked);

  }

  function onMarkerClicked(ev){
    mapIn.panTo(ev.latLng);
    $("#mapOut").fadeOut(1000);
  }
```

1.  将`click`事件添加到内部地图，当您点击它时，将返回到上层地图：

```js
google.maps.event.addListener(mapIn, 'click', function() {
  mapIn.panTo(BASE_CENTER);
  $("#mapOut").fadeIn(1000);
  });
```

1.  使用`center_changed`事件强制用户禁用上层地图中的`pan`：

```js
google.maps.event.addListener(mapOut, 'center_changed', function() {
        mapOut.panTo(BASE_CENTER); 
//always force users back to center point in external map
});
```

当您加载 HTML 文件时，您会发现一个全屏地图，无法拖动。当您点击标记时，它将淡入所选区域。现在您可以在地图周围拖动光标。下次您在内部地图上点击（在任何区域上进行常规点击）时，地图将再次淡出到原始的上层。

## 它是如何工作的...

我们最大的一步是创建两个地图，一个重叠在另一个上面。我们通过一些 CSS 魔术来实现这一点，通过叠加元素并将我们的顶层放在堆栈的最后位置（我们可能可以使用 z-index 来验证它，但它有效，所以我没有将其添加到 CSS 中）。之后，我们创建了两个`div`层并设置了它们的 CSS 代码。在 JavaScript 代码中，与上一个示例中的方式相反，我们将我们想要的值硬编码到了两个地图中。

在两个地图的选项中，我们将通过将属性`disableDefaultUI`设置为`true`来设置默认控制器不生效，而在`mapIn`中，我们将`panControl`设置为`true`，以展示地图可以通过平移来移动：

```js
var mapOut = new google.maps.Map(document.getElementById("mapOut"),{
  center: BASE_CENTER,
  zoom: 11,
  mapTypeId: google.maps.MapTypeId.SATELLITE,
  disableDefaultUI: true
});
var mapIn = new google.maps.Map(document.getElementById("mapIn"),{
  center: BASE_CENTER,
  zoom: 14,
  mapTypeId: google.maps.MapTypeId.ROADMAP,
  disableDefaultUI: true,
  panControl:true
});
```

我们可以通过将布尔值设置为以下任何选项来手动设置所有控制器：

+   `panControl`

+   `zoomControl`

+   `mapTypeControl`

+   `streetViewControl`

+   `overviewMapControl`

我们的`event`逻辑与上一个示例中的逻辑完全相同。唯一的变化在于实际的监听器中，我们使用 jQuery 在地图之间进行切换：

```js
function onMarkerClicked(ev){
  mapIn.panTo(ev.latLng);
  $("#mapOut").fadeOut(1000);
}

google.maps.event.addListener(mapIn, 'click', function() {
  mapIn.panTo(BASE_CENTER);
  $("#mapOut").fadeIn(1000);
});
```

在标记的事件和地图的`click`事件中，我们使用 jQuery 的`fadeIn`和`fadeOut`方法来动画显示我们外部地图的可见性。

## 还有更多...

当您尝试在高级地图（第一个可见地图）周围拖动时，您会注意到地图无法移动——它是不可平移的。Google API v3 不支持禁用平移的功能，但它支持在地图中心点更改时每次获得更新。

因此，我们监听以下更改：

```js
google.maps.event.addListener(mapOut, 'center_changed', function() {
        mapOut.panTo(BASE_CENTER); 
});
```

我们所做的就是每次地图位置发生变化时，强制将其恢复到原始位置，使我们的地图无法移动。

# 使用样式重新设计地图

在使用 Google Maps 创建更高级的应用程序时，您经常会希望创建自己的自定义样式地图。当您希望拥有前景内容并且不希望它与背景内容竞争时，这是非常有用的。

在本示例中，我们将创建一些样式化地图。在本示例结束时，您将知道如何创建全局定制、个体样式，以及添加新地图类型。

这是我们将创建的一个样式：

![使用样式重新设计地图](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_09_10.jpg)

这是我们将创建的第二个样式：

![使用样式重新设计地图](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-gph-dtvz-cb/img/3707OT_09_11.jpg)

## 准备工作

要完成本示例，您需要从上一个示例的副本开始。我们只描述与本示例中上一个示例不同的新步骤。要查看和理解所有步骤，请阅读*自定义控件和重叠地图*示例。

因此，我们将跳过 HTML 代码，因为它与上一个示例中的代码完全相同。

## 如何做到...

打开上一个示例中的 JavaScript 文件（`09.05.controls.js`），并按照以下步骤操作：

1.  在`init`函数中创建一个`aVeinStyle`数组。该数组包含了所有用于定制地图样式的视觉指南：

```js
var aVeinStyle =  [
  {
    featureType:'water',
    elementType: "geometry",
    stylers:[{color:'#E398BF'}]
  },
  {
    featureType:'road',
    elementType: "geometry",
    stylers:[{color:'#C26580'}]
  },
  {
    featureType:'road.arterial',
    elementType: "geometry",
    stylers:[{color:'#9B2559'}]
  },
  {
    featureType:'road.highway',
    elementType: "geometry",
    stylers:[{color:'#75000D'}]
  },
  {
    featureType:'landscape.man_made',
    elementType: "geometry",
    stylers:[{color:'#F2D2E0'}]
  },
  {
    featureType:'poi',
    elementType: "geometry",
    stylers:[{color:'#C96FB9'}]
  },
  {
    elementType: "labels",
    stylers:[{visibility:'off'}]
  }
];
```

1.  创建一个名为`Veins`的新`google.maps.StyledMapType`地图：

```js
var veinStyle = new google.maps.StyledMapType(aveinStyle,{name: "Veins"});
```

1.  创建一个公交样式：

```js
var aBusStyle =  [
  {
    stylers: [{saturation: -100}]
  },
  {
    featureType:'transit.station.rail',
    stylers:[{ saturation: 60},{hue:'#0044ff'},{visibility:'on'}]

  }
];

var busStyle = new google.maps.StyledMapType(aBusStyle,{name: "Buses"}); 
```

1.  对于内部地图，使地图类型控制器可见，并在其中包括我们新地图样式的 ID：

```js
var mapIn = new google.maps.Map(document.getElementById("mapIn"),{
  center: BASE_CENTER,
  zoom: 14,
  mapTypeId: google.maps.MapTypeId.ROADMAP,
  disableDefaultUI: true,
  panControl:true,
  mapTypeControl:true,
  mapTypeControlOptions: {
    mapTypeIds: [google.maps.MapTypeId.ROADMAP, 'veinStyle', 'busStyle']
  }

});
```

1.  将地图样式信息添加到`mapIn`对象中：

```js
mapIn.mapTypes.set('veinStyle', veinStyle);
mapIn.mapTypes.set('busStyle', busStyle);    
```

1.  设置默认地图类型：

```js
mapIn.setMapTypeId('busStyle');
```

当您重新启动 HTML 文件中的内部地图（在单击标记中的一个后），您将找到一个控制器菜单，可以在自定义地图类型之间切换。

## 它是如何工作的...

使用 Google 样式很有趣，它们的工作方式与 CSS 非常相似。我们设置的样式有几个步骤；第一步是创建样式的规则，下一步是定义一个 Google 样式对象（`google.maps.StyledMapType`），最后一步是定义这个样式信息与哪个地图相关联。样式只能应用于`google.maps.MapTypeId.ROADMAP`类型的地图。

第一个示例是创建公交车样式。这种样式的目标是使地图变成黑白色，并只突出显示公共交通站点：

```js
var aBusStyle =  [
  {
    stylers: [{saturation: -100}]
  },
  {
    featureType:'transit.station.rail',
    stylers:[{ saturation: 60},{hue:'#0044ff'},{visibility:'on'}]

  }
];

var busStyle = new google.maps.StyledMapType(aBusStyle,{name: "Buses"});
```

第一个变量是一个常规数组。我们可以添加任意多个样式；每次我们想要定义规则（搜索条件）之前，都会应用这些规则。让我们更深入地看一下一个样式规则：

```js
{stylers: [{saturation: -100}]}
```

这个例子是最基本的。我们没有规则，或者换句话说，我们想将这种样式应用到所有东西上。就像在这个例子中，我们将饱和度设置为`-100`，我们正在使一切变成黑白色（饱和度默认值为`0`，可以取值在`-100`和`100`之间）。

可能的样式属性如下：

+   `可见性`：这是一个字符串值（`no`，`off`或`simplified`）。这会向地图添加或移除元素；在大多数情况下，它将用于根据提供的信息删除文本，如标签和细节。

+   `伽马`：这是一个介于`0.01`和`10`之间的数字值（默认值为`1.0`）。这个选项控制视图中有多少光。较低的值（低于`1`）会加强较浅和较暗颜色之间的差异，较高的数字（大于`1`）会产生更全局的效果，使一切随着数值的增加而更加发光。

+   `色调`：这是一个十六进制颜色值，包装成字符串（例如#`222222`）。最好的描述色调的方式是，想象戴上与提供的十六进制值匹配的有色玻璃的太阳镜。有色玻璃如何影响你周围的颜色并改变它们的方式，就像地图的色调颜色改变的方式一样。

+   `亮度`：这是一个介于`-100`和`100`之间的值（默认值为`0`）。如果提供一个小于`0`的值，这个效果就非常简单。这与在地图上放置一个黑色矩形并改变其不透明度的效果相同（即，`-30`将与 30%的不透明度相匹配）。你可能已经猜到了正值的结果——对于正值，想法是一样的，但只是用一个白色矩形。

+   `饱和度`：这是一个介于`-100`和`100`之间的值（默认值为`0`）。这个效果侧重于像素级的值，`-100`会创建更接近`100`的灰度图像值。它会从图像中去除所有灰色，使一切更加生动。

这就是所有可用的样式信息，有了它，我们可以控制地图内的每个样式元素。每个样式属性的信息都需要作为`stylers`数组中的单独对象发送；例如，如果我们想要在我们的片段中添加一个`色调`，它会看起来像这样：

```js
{stylers: [{saturation: -40},{hue:60}]}
```

现在我们知道了可以改变地图视觉效果的所有不同方式，是时候了解我们将如何定义应该被选择的内容。在最后的代码片段中，我们控制了整个地图，但我们可以通过添加过滤逻辑来过滤我们想要控制的内容：

```js
{elementType: "geometry",
  stylers:[{color:'#E398BF'}]
```

在这个片段中，我们正在过滤我们想要改变所有`geometry`元素的颜色，这意味着不是`geometry`元素的任何东西都不会受到影响。有三种类型的元素类型选项：

+   `全部`（默认选项）

+   `几何`

+   `标签`

还有一种过滤信息的方法，就是使用`featureType`属性。例如：

```js
  {
    featureType:'landscape.man_made',
    elementType: "geometry",
    stylers:[{color:'#F2D2E0'}]
  }
```

在这种情况下，我们正在列出我们想要关注的内容。我们想关注特征类型和元素类型。如果我们提取`elementType`属性，我们的颜色效果将影响`geometry`和`labels`。而如果我们提取`featureType`，它将影响地图中的所有`geometry`元素。

有关`featureType`属性选项的完整列表，请访问[`goo.gl/H7HSO`](http://goo.gl/H7HSO)。

## 还有更多...

现在我们已经掌握了如何创建我们想要使用的样式，下一个关键步骤是实际将我们的样式与地图连接起来。最简单的方法（如果我们只有一个样式）是直接将其连接到地图上：

```js
inMap.setOptions({styles: styles});
```

这可以通过调用`setOptions`函数或在创建地图时添加`style`属性来完成。样式只能添加到路线图中，因此如果将此样式添加到不是路线图的地图上，它将不会被应用。

由于我们想要添加多个样式选项，我们必须列出地图类型。在这之前，我们需要使用以下代码创建一个新的地图类型对象：

```js
var busStyle = new google.maps.StyledMapType(aBusStyle,{name: "Buses"});
```

在创建新地图时，我们提供了一个名称，该名称将用作我们在控制器中的名称 - 如果我们选择创建一个控制器（在我们的示例中我们会这样做）。重要的是要注意，这个名称不是我们元素的 ID，而只是元素的标签，我们仍然需要在将其发送到地图之前为我们的元素创建一个 ID。为此，我们将首先将 ID 添加到我们的控制器中，并使我们的控制器可见：

```js
var mapIn = new google.maps.Map(document.getElementById("mapIn"),{
  center: BASE_CENTER,
  zoom: 14,
  mapTypeId: google.maps.MapTypeId.ROADMAP,
  disableDefaultUI: true,
  panControl:true,
 mapTypeControl:true,
 mapTypeControlOptions: {
 mapTypeIds: [google.maps.MapTypeId.ROADMAP, 'veinStyle', 'busStyle']
 }

});
```

在此之后，我们将添加设置指令，将我们的新地图类型连接到它们的样式对象：

```js
mapIn.mapTypes.set('veinStyle', veinStyle);
mapIn.mapTypes.set('busStyle', busStyle);
```

最后但同样重要的是，我们可以将默认地图更改为我们的样式地图之一：

```js
mapIn.setMapTypeId('busStyle');
```

就是这样。现在你已经知道了如何在谷歌地图中使用样式的所有必要信息。
