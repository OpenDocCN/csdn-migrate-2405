# HTML5 画布秘籍（一）

> 原文：[`zh.annas-archive.org/md5/5BECA7AD01229D44A883D4EFCAD8E67B`](https://zh.annas-archive.org/md5/5BECA7AD01229D44A883D4EFCAD8E67B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

HTML5 画布正在改变网络上的图形和可视化。由 JavaScript 驱动，HTML5 Canvas API 使 Web 开发人员能够在浏览器中创建可视化和动画，而无需 Flash。尽管 HTML5 Canvas 迅速成为在线图形和交互的标准，但许多开发人员未能充分利用这一强大技术所提供的所有功能。

《HTML5 Canvas Cookbook》首先介绍了 HTML5 Canvas API 的基础知识，然后提供了处理 API 不直接支持的高级技术，如动画和画布交互的方法。最后，它提供了一些最常见的 HTML5 画布应用的详细模板，包括数据可视化、游戏开发和 3D 建模。它将使您熟悉有趣的主题，如分形、动画、物理学、颜色模型和矩阵数学。

通过本书的学习，您将对 HTML5 Canvas API 有扎实的理解，并掌握了创建任何类型的 HTML5 画布应用的技术，仅受想象力的限制。

# 本书内容

第一章，“开始使用路径和文本”，首先介绍了子路径绘制的基础知识，然后通过探索绘制锯齿和螺旋的算法来深入研究更高级的路径绘制技术。接下来，本章深入探讨了文本绘制，最后探索了分形。

第二章，“形状绘制和合成”，首先介绍了形状绘制的基础知识，并向您展示如何使用颜色填充、渐变填充和图案。接下来，本章深入研究了透明度和合成操作，然后提供了绘制更复杂形状的方法，如云、齿轮、花朵、纸牌花色，甚至是一个完整的矢量飞机，包括图层和阴影。

第三章，“使用图像和视频”，介绍了图像和视频处理的基础知识，向您展示如何复制和粘贴画布的部分，并涵盖了不同类型的像素操作。本章还向您展示了如何将图像转换为数据 URL，将画布绘制保存为图像，并使用数据 URL 加载画布。最后，本章以一个可以用于动态聚焦和模糊图像的像素操作的像素化图像焦点算法结束。

第四章，“掌握变换”，探索了画布变换的可能性，包括平移、缩放、旋转、镜像变换和自由形式变换。此外，本章还详细探讨了画布状态堆栈。

第五章，“使用动画使画布栩栩如生”，首先构建一个`Animation`类来处理动画阶段，并向您展示如何创建线性运动、二次运动和振荡运动。接下来，它涵盖了一些更复杂的动画，如肥皂泡的振荡、摆动的钟摆和旋转的机械齿轮。最后，本章以创建自己的粒子物理模拟器的方法结束，并提供了在画布内创建数百个微生物以测试性能的方法。

第六章，与画布交互：将事件侦听器附加到形状和区域，首先构建了一个扩展画布 API 的`Events`类，提供了一种在画布上附加事件侦听器到形状和区域的方法。接下来，该章节涵盖了获取画布鼠标坐标的技术，检测区域事件，检测图像事件，检测移动触摸事件和拖放。该章节最后提供了一个创建图像放大器的方法和另一个创建绘图应用程序的方法。

第七章，创建图表和图表，提供了生产就绪的图表类，包括饼图、条形图、方程图和折线图。

第八章，用游戏开发拯救世界，通过展示如何创建一个名为 Canvas Hero 的整个横向卷轴游戏，让您开始使用画布游戏开发。该章节向您展示如何创建精灵表，创建关卡和边界地图，创建处理英雄、坏人、关卡和英雄生命的类，还向您展示如何使用 MVC（模型视图控制器）设计模式构建游戏引擎。

第九章，介绍 WebGL，首先构建了一个 WebGL 包装类，以简化 WebGL API。该章节通过展示如何创建一个 3D 平面和一个旋转的立方体来介绍 WebGL，还向您展示如何向模型添加纹理和光照。该章节最后展示了如何创建一个完整的 3D 世界，您可以在其中进行第一人称探索。

附录 A，附录 B 和附录 C 讨论了其他特殊主题，如画布支持检测、安全性、画布与 CSS3 过渡和动画，以及移动设备上画布应用的性能。

# 您需要什么

要开始使用 HTML5 画布，您只需要一个现代浏览器，如 Google Chrome，Firefox，Safari，Opera 或 IE9，以及一个简单的文本编辑器，如记事本。

# 这本书适合谁

本书面向熟悉 HTML 和 JavaScript 的 Web 开发人员。它适用于初学者和有一定 JavaScript 工作知识的 HTML5 开发人员。

# HTML5 画布是什么？

Canvas 最初是由苹果于 2004 年创建的，用于实现 Dashboard 小部件并在 Safari 浏览器中提供图形支持，后来被 Firefox、Opera 和 Google Chrome 采用。如今，画布是下一代 Web 技术的新 HTML5 规范的一部分。

HTML5 画布是一个 HTML 标签，您可以将其嵌入到 HTML 文档中，用于使用 JavaScript 绘制图形。由于 HTML5 画布是一个位图，绘制到画布上的每个像素都会覆盖其下的像素。

这是本书所有 2D HTML5 画布配方的基本模板：

```js
<!DOCTYPE HTML>
<html>
    <head>
        <script>
            window.onload = function(){
                var canvas = document.getElementById("myCanvas");
                var context = canvas.getContext("2d");

                // draw stuff here
            };
        </script>
    </head>
    <body>
        <canvas id="myCanvas" width="578" height="200">
        </canvas>
    </body>
</html>
```

请注意，画布元素嵌入在 HTML 文档的主体内，并且使用`id`、`width`和`height`进行定义。JavaScript 使用`id`引用画布标签，`width`和`height`用于定义绘图区域的大小。一旦使用`document.getElementById()`访问了画布标签，我们就可以定义一个 2D 上下文：

```js
var context = canvas.getContext("2d");
```

尽管本书大部分内容涵盖了 2D 上下文，但最后一章使用了 3D 上下文来使用 WebGL 渲染 3D 图形。

# 约定

在本书中，您会发现一些区分不同信息类型的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词显示如下：“定义`Events`构造函数。”

代码块设置如下：

```js
var Events = function(canvasId){
    this.canvas = document.getElementById(canvasId);
    this.context = this.canvas.getContext("2d");
    this.stage = undefined;
    this.listening = false;
};
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```js
var Events = function(canvasId){
 this.canvas = document.getElementById(canvasId);
 this.context = this.canvas.getContext("2d");
    this.stage = undefined;
    this.listening = false;
};
```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，在菜单或对话框中出现在文本中，就像这样：“它在原点处写出文本**Hello Logo!**”

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：开始使用路径和文本

在这一章中，我们将涵盖：

+   绘制一条线

+   绘制一条弧线

+   绘制二次曲线

+   绘制贝塞尔曲线

+   绘制锯齿

+   绘制螺旋

+   使用文本

+   使用阴影绘制 3D 文本

+   释放分形的力量：绘制一棵幽灵树

# 介绍

本章旨在通过一系列逐渐复杂的任务来演示 HTML5 画布的基本功能。HTML5 画布 API 提供了绘制和样式化不同类型子路径的基本工具，包括线条、弧线、二次曲线和贝塞尔曲线，以及通过连接子路径创建路径的方法。该 API 还提供了对文本绘制的良好支持，具有几种样式属性。让我们开始吧！

# 绘制一条线

当第一次学习如何使用 HTML5 画布绘制时，大多数人都对绘制最基本和最原始的画布元素感兴趣。这个配方将向您展示如何通过绘制简单的直线来做到这一点。

![绘制一条线](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_01_01.jpg)

## 如何做...

按照以下步骤绘制一条对角线：

1.  定义一个 2D 画布上下文并设置线条样式：

```js
window.onload = function(){
  // get the canvas DOM element by its ID
     var canvas = document.getElementById("myCanvas");
  // declare a 2-d context using the getContext() method of the 
  // canvas object
     var context = canvas.getContext("2d");

  // set the line width to 10 pixels
     context.lineWidth = 10;
  // set the line color to blue
     context.strokeStyle = "blue";
```

1.  定位画布上下文并绘制线条：

```js
  // position the drawing cursor
     context.moveTo(50, canvas.height - 50);
  // draw the line
     context.lineTo(canvas.width - 50, 50);
  // make the line visible with the stroke color
     context.stroke();
};
```

1.  将画布标签嵌入到 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>

```

### 注意

**下载示例代码** 

您可以从[www.html5canvastutorials.com/cookbook](http://www.html5canvastutorials.com/cookbook)运行演示并下载本书的资源，或者您可以从您在[`www.PacktPub.com`](http://www.PacktPub.com)购买的所有 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/support)并注册，以便直接通过电子邮件接收文件。

# 它是如何工作的...

从前面的代码中可以看出，我们需要等待页面加载完成，然后再尝试通过其 ID 访问画布标签。我们可以通过`window.onload`初始化器来实现这一点。页面加载完成后，我们可以使用`document.getElementById()`访问画布 DOM 元素，并通过将`2d`传递给画布对象的`getContext()`方法来定义一个 2D 画布上下文。正如我们将在最后两章中看到的，我们还可以通过传递其他上下文（如`webgl`、`experimental-webgl`等）来定义 3D 上下文。

在绘制特定元素（如路径、子路径或形状）时，重要的是要理解样式可以在任何时候设置，无论是在元素绘制之前还是之后，但是样式必须在元素绘制后立即应用才能生效，我们可以使用`lineWidth`属性设置线条的宽度，使用`strokeStyle`属性设置线条颜色。想象一下，这个行为就像我们在纸上画东西时会采取的步骤。在我们开始画之前，我们会选择一个带有特定尖端厚度的彩色标记（`strokeStyle`）。

现在我们手里有了标记，可以使用`moveTo()`方法将其定位到画布上：

```js
context.moveTo(x,y);
```

将画布上下文视为绘图光标。`moveTo()`方法为给定点创建一个新的子路径。画布左上角的坐标为（0,0），右下角的坐标为（画布宽度，画布高度）。

一旦我们定位了绘图光标，我们可以使用`lineTo()`方法绘制线条，定义线条终点的坐标：

```js
context.lineTo(x,y);
```

最后，为了使线条可见，我们可以使用`stroke()`方法。除非另有规定，默认的描边颜色是黑色。

总结一下，当使用 HTML5 画布 API 绘制线条时，我们应该遵循的典型绘制过程如下：

1.  样式你的线条（比如选择一个特定尖端厚度的彩色标记）。

1.  使用`moveTo()`定位画布上下文（就像把标记放在纸上）。

1.  使用`lineTo()`绘制线条。

1.  使用`stroke()`使线条可见。

# 还有更多...

HTML5 画布线条也可以具有三种不同的线帽，包括**butt**、**round**和**square**。线帽样式可以使用画布上下文的`lineCap`属性进行设置。除非另有规定，线帽样式默认为 butt。下图显示了三条线，每条线都具有不同的线帽样式。顶部线使用默认的 butt 线帽，中间线使用 round 线帽，底部线使用 square 线帽：

![还有更多...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_01_14.jpg)

请注意，中间和底部线比顶部线稍长，尽管所有线宽度相等。这是因为 round 线帽和 square 线帽会使线的长度增加，增加的量等于线的宽度。例如，如果我们的线长为 200 像素，宽度为 10 像素，并且使用 round 或 square 线帽样式，那么结果线的长度将为 210 像素，因为每个线帽都会增加 5 像素的线长。

# 另请参阅...

+   *绘制锯齿*

+   *将所有内容放在一起：在第二章中绘制喷气式飞机

# 绘制一条弧

在使用 HTML5 画布绘制时，有时需要绘制完美的弧。如果你对绘制快乐的彩虹、笑脸或图表感兴趣，这个方法将是你努力的良好起点。

![绘制一条弧](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_01_02.jpg)

## 如何做...

按照以下步骤绘制简单的弧：

1.  定义一个 2D 画布上下文并设置弧线样式：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
    context.lineWidth = 15;
    context.strokeStyle = "black"; // line color
```

1.  绘制弧：

```js
context.arc(canvas.width / 2, canvas.height / 2 + 40, 80, 1.1 * Math.PI, 1.9 * Math.PI, false);
    context.stroke();
};
```

1.  将 canvas 标签嵌入 HTML 文档的 body 中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 工作原理...

我们可以使用`arc()`方法创建 HTML5 弧，该方法由虚拟圆的圆周部分定义。看一下下面的图表：

![工作原理...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_01_05.jpg)

虚拟圆由一个中心点和一个半径定义。圆周部分由起始角度、结束角度以及弧是顺时针绘制还是逆时针绘制来定义：

```js
context.arc(centerX,centerY, radius, startingAngle, 
      endingAngle,counterclockwise);
```

注意，角度从圆的右侧 0π开始，顺时针移动到 3π/2、π、π/2，然后返回 0。对于这个方法，我们使用 1.1π作为起始角度，1.9π作为结束角度。这意味着起始角度略高于虚拟圆左侧的中心，结束角度略高于虚拟圆右侧的中心。

## 还有更多...

起始角度和结束角度的值不一定要在 0π和 2π之间。实际上，起始角度和结束角度可以是任何实数，因为角度可以在围绕圆圈旋转时重叠。

例如，假设我们将起始角度定义为 3π。这相当于围绕圆圈一周（2π）再围绕圆圈半周（1π）。换句话说，3π等同于 1π。另一个例子，-3π也等同于 1π，因为角度沿着圆圈逆时针旋转一周半，最终到达 1π。

使用 HTML5 画布创建弧的另一种方法是利用`arcTo()`方法。`arcTo()`方法生成的弧由上下文点、控制点、结束点和半径定义：

```js
context.arcTo(controlPointX1, controlPointY1, endingPointX,   endingPointY, radius);
```

与`arc()`方法不同，`arcTo()`方法依赖于上下文点来定位弧，类似于`lineTo()`方法。`arcTo()`方法在创建路径或形状的圆角时最常用。

## 另请参阅...

+   *在第二章中绘制一个圆

+   *在第五章中制作机械齿轮动画

+   *在第五章中制作时钟动画

# 绘制二次曲线

在这个配方中，我们将学习如何绘制二次曲线。与其表亲弧线相比，二次曲线提供了更多的灵活性和自然的曲线，是创建自定义形状的绝佳工具。

![绘制二次曲线](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_01_03.jpg)

## 操作步骤...

按照以下步骤绘制二次曲线：

1.  定义一个 2D 画布上下文并设置曲线样式：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    context.lineWidth = 10;
    context.strokeStyle = "black"; // line color
```

1.  定位画布上下文并绘制二次曲线：

```js
context.moveTo(100, canvas.height - 50);
    context.quadraticCurveTo(canvas.width / 2, -50, canvas.width - 100, canvas.height - 50);
    context.stroke();
};
```

1.  将 canvas 标签嵌入 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 工作原理...

HTML5 二次曲线由上下文点、一个控制点和一个结束点定义：

```js
  context.quadraticCurveTo(controlX, controlY, endingPointX,       endingPointY);
```

查看以下图表：

![工作原理...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_01_06.jpg)

二次曲线的曲率由三个特征切线定义。曲线的第一部分与一条虚拟线相切，该虚拟线从上下文点开始，到控制点结束。曲线的顶点与从中点 1 开始到中点 2 结束的虚拟线相切。最后，曲线的最后一部分与从控制点开始到结束点结束的虚拟线相切。

## 另请参阅...

+   *将所有内容放在一起：在第二章中绘制喷气机*

+   *解锁分形的力量：绘制一棵幽灵树*

# 绘制贝塞尔曲线

如果二次曲线不能满足您的需求，贝塞尔曲线可能会起作用。贝塞尔曲线也被称为三次曲线，是 HTML5 画布 API 中最先进的曲线。

![绘制贝塞尔曲线](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_01_04.jpg)

## 操作步骤...

按照以下步骤绘制任意贝塞尔曲线：

1.  定义一个 2D 画布上下文并设置曲线样式：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    context.lineWidth = 10;
    context.strokeStyle = "black"; // line color
    context.moveTo(180, 130);
```

1.  定位画布上下文并绘制贝塞尔曲线：

```js
context.bezierCurveTo(150, 10, 420, 10, 420, 180);
    context.stroke();
};
```

1.  将 canvas 标签嵌入 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>

```

## 工作原理...

HTML5 画布贝塞尔曲线由上下文点、两个控制点和一个结束点定义。与二次曲线相比，额外的控制点使我们对其曲率有更多控制：

```js
  context.bezierCurveTo(controlPointX1, controlPointY1, 
      controlPointX2, controlPointY2, 
      endingPointX, endingPointY);
```

查看以下图表：

![工作原理...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_01_07.jpg)

与二次曲线不同，贝塞尔曲线由五个特征切线定义，而不是三个。曲线的第一部分与一条虚拟线相切，该虚拟线从上下文点开始，到第一个控制点结束。曲线的下一部分与从中点 1 开始到中点 3 结束的虚拟线相切。曲线的顶点与从中点 2 开始到中点 4 结束的虚拟线相切。曲线的第四部分与从中点 3 开始到中点 5 结束的虚拟线相切。最后，曲线的最后一部分与从第二个控制点开始到结束点结束的虚拟线相切。

## 另请参阅...

+   *随机化形状属性：在第二章中绘制一片花海*

+   *将所有内容放在一起：在第二章中绘制喷气机*

# 绘制锯齿

在这个配方中，我们将通过迭代连接线子路径来介绍路径绘制，以绘制锯齿路径。

![绘制锯齿](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_01_08.jpg)

## 操作步骤...

按照以下步骤绘制锯齿路径：

1.  定义一个 2D 画布上下文并初始化锯齿参数：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    var startX = 85;
    var startY = 70;
    var zigzagSpacing = 60;
```

1.  定义锯齿样式并开始路径：

```js
context.lineWidth = 10;
    context.strokeStyle = "#0096FF"; // blue-ish color
    context.beginPath();
    context.moveTo(startX, startY);
```

1.  绘制七条连接的锯齿线，然后使用`stroke()`使锯齿路径可见：

```js
// draw seven lines
    for (var n = 0; n < 7; n++) {
        var x = startX + ((n + 1) * zigzagSpacing);
        var y;

        if (n % 2 == 0) { // if n is even...
            y = startY + 100;
        }
        else { // if n is odd...
            y = startY;
        }
        context.lineTo(x, y);
    }

    context.stroke();
};
```

1.  将 canvas 标签嵌入 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 工作原理...

要绘制锯齿，我们可以连接交替的对角线以形成路径。通过设置一个循环来实现，该循环在奇数迭代上向上和向右绘制对角线，在偶数迭代上向下和向右绘制对角线。

在这个示例中需要注意的关键事项是`beginPath()`方法。这个方法本质上声明正在绘制一个路径，以便每个线段子路径的结束定义下一个子路径的开始。如果不使用`beginPath()`方法，我们将不得不费力地使用`moveTo()`来定位每个线段，同时确保前一个线段的结束点与当前线段的起点匹配。正如我们将在下一章中看到的，`beginPath()`方法也是创建形状的必要步骤。

### 线连接样式

注意每个线段之间的连接是如何形成尖锐点的。这是因为 HTML5 canvas 路径的线连接样式默认为**miter**。或者，我们也可以使用画布上下文的`lineJoin`属性将线连接样式设置为**round**或**bevel**。

如果您的线段相当细，并且不以陡峭的角度连接，要区分不同的线连接样式可能有些困难。通常，当路径厚度超过 5 像素且线段之间的角度相对较小时，不同的线连接样式会更加明显。

# 绘制螺旋线

注意，这个示例可能会引起催眠。在这个示例中，我们将通过连接一系列短线段来形成螺旋路径来绘制一个螺旋线。

![绘制螺旋线](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_01_10.jpg)

## 如何做...

按照以下步骤绘制一个居中的螺旋线：

1.  定义一个 2D 画布上下文并初始化螺旋参数：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    var radius = 0;
    var angle = 0;
```

1.  设置螺旋线样式：

```js
context.lineWidth = 10;
    context.strokeStyle = "#0096FF"; // blue-ish color
    context.beginPath();
    context.moveTo(canvas.width / 2, canvas.height / 2);
```

1.  围绕画布中心旋转三次（每次完整旋转 50 次迭代），同时增加半径 0.75，并使用`lineTo()`从上一个点到当前点绘制一条线段。最后，使用`stroke()`使螺旋线可见：

```js
for (var n = 0; n < 150; n++) {
        radius += 0.75;
        // make a complete circle every 50 iterations
        angle += (Math.PI * 2) / 50;
        var x = canvas.width / 2 + radius * Math.cos(angle);
        var y = canvas.height / 2 + radius * Math.sin(angle);
        context.lineTo(x, y);
    }

    context.stroke();
};
```

1.  将 canvas 标签嵌入 HTML 文档的 body 中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>

```

## 它是如何工作的...

要使用 HTML5 canvas 绘制螺旋线，我们可以将绘图游标放在画布中心，迭代增加半径和角度，然后从上一个点到当前点绘制一个超短的线段。另一种思考方式是想象自己站在人行道上，手里拿着一支彩色粉笔。弯下腰把粉笔放在人行道上，然后开始围绕中心转圈（不要转得太快，除非你想晕倒）。当你转动时，把粉笔向外移动。几圈之后，你就画出了一个漂亮的小螺旋线。

# 处理文本

几乎所有的应用程序都需要一些文本来有效地向用户传达信息。这个示例将向您展示如何绘制一个简单的文本字符串，带有一种乐观的欢迎。

![处理文本](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_01_12.jpg)

## 如何做...

按照以下步骤在 canvas 上写字：

1.  定义一个 2D 画布上下文并设置文本样式：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    context.font = "40pt Calibri";
    context.fillStyle = "black";
```

1.  水平和垂直对齐文本，然后绘制它：

```js
// align text horizontally center
    context.textAlign = "center";
    // align text vertically center
    context.textBaseline = "middle";
    context.fillText("Hello World!", canvas.width / 2, 120);
};
```

1.  将 canvas 标签嵌入 HTML 文档的 body 中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

要在 HTML5 canvas 上绘制文本，我们可以使用`font`属性定义字体样式和大小，使用`fillStyle`属性定义字体颜色，使用`textAlign`属性定义水平文本对齐，使用`textBaseline`属性定义垂直文本对齐。`textAlign`属性可以设置为`left`、`center`或`right`，`textBaseline`属性可以设置为`top`、`hanging`、`middle`、`alphabetic`、`ideographic`或`bottom`。除非另有规定，否则`textAlign`属性默认为`left`，`textBaseline`属性默认为 alphabetic。

## 还有更多...

除了`fillText()`之外，HTML5 canvas API 还支持`strokeText()`：

```js
  context.strokeText("Hello World!", x, y);
```

这种方法将为文本的周边着色而不是填充。要为 HTML 画布文本设置填充和描边，可以同时使用`fillText（）`和`strokeText（）`方法。在渲染描边厚度时，最好先使用`fillText（）`方法，然后再使用`strokeText（）`方法。

## 另请参阅...

+   *带阴影的 3D 文字绘制*

+   *在* 第四章 *中创建镜像变换*

+   *在* 第四章 *中绘制简单的标志并随机化其位置、旋转和比例*

# 带阴影的 3D 文字绘制

如果 2D 文本不能激发你的热情，你可以考虑绘制 3D 文本。尽管 HTML5 画布 API 并没有直接为我们提供创建 3D 文本的手段，但我们可以使用现有的 API 创建自定义的`draw3dText（）`方法。

![带阴影的 3D 文字绘制](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_01_11.jpg)

## 如何做...

按照以下步骤创建 3D 文本：

1.  设置画布上下文和文本样式：

```js
  window.onload = function(){
    canvas = document.getElementById("myCanvas");
    context = canvas.getContext("2d");

    context.font = "40pt Calibri";
    context.fillStyle = "black";
```

1.  对齐并绘制 3D 文本：

```js
// align text horizontally center
    context.textAlign = "center";
    // align text vertically center
    context.textBaseline = "middle";
    draw3dText(context, "Hello 3D World!", canvas.width / 2, 120, 5);
};
```

1.  定义`draw3dText（）`函数，绘制多个文本层并添加阴影：

```js
function draw3dText(context, text, x, y, textDepth){
    var n;

    // draw bottom layers
    for (n = 0; n < textDepth; n++) {
        context.fillText(text, x - n, y - n);
    }

    // draw top layer with shadow casting over
    // bottom layers
    context.fillStyle = "#5E97FF";
    context.shadowColor = "black";
    context.shadowBlur = 10;
    context.shadowOffsetX = textDepth + 2;
    context.shadowOffsetY = textDepth + 2;
    context.fillText(text, x - n, y - n);
}
```

1.  在 HTML 文档的主体中嵌入画布标记：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

要使用 HTML5 画布绘制 3D 文本，我们可以将多个相同文本的图层叠加在一起，以创建深度的错觉。在这个示例中，我们将文本深度设置为五，这意味着我们的自定义`draw3dText（）`方法会在一起叠加五个“Hello 3D World！”的实例。我们可以将这些图层着色为黑色，以在文本下方创建黑暗的错觉。

接下来，我们可以添加一个有颜色的顶层来描绘一个朝前的表面。最后，我们可以通过设置画布上下文的`shadowColor`，`shadowBlur`，`shadowOffsetX`和`shadowOffsetY`属性，在文本下方应用柔和的阴影。正如我们将在后面的示例中看到的，这些属性不仅限于文本，还可以应用于子路径、路径和形状。

# 释放分形的力量：绘制一棵幽灵树

首先，什么是分形？如果你还不知道，分形是数学与艺术相结合的令人惊叹的结果，可以在构成生活的各种模式中找到。从算法上讲，分形是基于经历递归的方程。在这个示例中，我们将通过绘制一个分叉成两个分支的树干，然后从我们刚刚绘制的两个分支中再绘制两个分支，来创建一个有机的树。

![释放分形的力量：绘制一棵幽灵树](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_01_13.jpg)

## 如何做...

按照以下步骤绘制使用分形的树：

1.  创建一个递归函数，绘制一个分叉成两个分支的单个分支，然后递归调用自身，从分叉分支的端点绘制另外两个分支：

```js
function drawBranches(context, startX, startY, trunkWidth, level){
    if (level < 12) {
        var changeX = 100 / (level + 1);
        var changeY = 200 / (level + 1);

        var topRightX = startX + Math.random() * changeX;
        var topRightY = startY - Math.random() * changeY;

        var topLeftX = startX - Math.random() * changeX;
        var topLeftY = startY - Math.random() * changeY;
        // draw right branch
        context.beginPath();
        context.moveTo(startX + trunkWidth / 4, startY);
        context.quadraticCurveTo(startX + trunkWidth / 4, startY - trunkWidth, topRightX, topRightY);
        context.lineWidth = trunkWidth;
        context.lineCap = "round";
        context.stroke();

        // draw left branch
        context.beginPath();
        context.moveTo(startX - trunkWidth / 4, startY);
        context.quadraticCurveTo(startX - trunkWidth / 4, startY -
        trunkWidth, topLeftX, topLeftY);
        context.lineWidth = trunkWidth;
        context.lineCap = "round";
        context.stroke();

        drawBranches(context, topRightX, topRightY, trunkWidth * 0.7, level + 1);
        drawBranches(context, topLeftX, topLeftY, trunkWidth * 0.7, level + 1);
    }
}
```

1.  初始化画布上下文，并通过调用`drawBranches（）`开始绘制树分形：

```js
window.onload = function(){
    canvas = document.getElementById("myCanvas");
    context = canvas.getContext("2d");

    drawBranches(context, canvas.width / 2, canvas.height, 50, 0);
};
```

1.  在 HTML 文档的主体中嵌入画布标记：

```js
<canvas id="myCanvas" width="600" height="500" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

要使用分形创建树，我们需要设计定义树的数学特性的递归函数。如果你花一点时间研究一棵树（如果你仔细想想，它们是相当美丽的），你会注意到每个分支都分叉成更小的分支。反过来，这些分支又分叉成更小的分支，依此类推。这意味着我们的递归函数应该绘制一个分叉成两个分支的单个分支，然后递归调用自身，从我们刚刚绘制的两个分支中再绘制两个分支。

现在我们有了创建分形的计划，我们可以使用 HTML5 画布 API 来实现它。绘制一个分叉成两个分支的最简单方法是通过绘制两个二次曲线，这些曲线从彼此弯曲向外。

如果我们对每次迭代使用完全相同的绘图过程，我们的树将会是完全对称且相当无趣的。为了使我们的树看起来更自然，我们可以引入随机变量来偏移每个分支的结束点。

## 还有更多...

这个配方的有趣之处在于每棵树都是不同的。如果你自己编写这个代码并不断刷新你的浏览器，你会发现每棵树的形成都是完全独特的。你可能还会对调整分支绘制算法以创建不同类型的树，甚至在最小的分支尖端绘制叶子感兴趣。

一些其他很好的分形例子可以在海贝壳、雪花、羽毛、植物、晶体、山脉、河流和闪电中找到。


# 第二章：形状绘制和复合

在本章中，我们将涵盖：

+   绘制矩形

+   绘制圆形

+   使用自定义形状和填充样式

+   贝塞尔曲线的乐趣：绘制云

+   绘制透明形状

+   使用上下文状态堆栈保存和恢复样式

+   使用复合操作

+   使用循环创建图案：绘制齿轮

+   随机化形状属性：绘制一片花田

+   创建自定义形状函数：纸牌花色

+   将所有内容组合在一起：绘制喷气机

# 介绍

在第一章*路径和文本入门*中，我们学习了如何绘制子路径，如线条、弧线、二次曲线和贝塞尔曲线，然后学习了如何将它们连接在一起形成路径。在本章中，我们将专注于基本和高级形状绘制技术，如绘制矩形和圆形、绘制自定义形状、填充形状、使用复合操作和绘制图片。让我们开始吧！

# 绘制矩形

在本示例中，我们将学习如何绘制 HTML5 画布 API 提供的唯一内置形状，即矩形。尽管矩形可能看起来不那么令人兴奋，但许多应用程序以某种方式使用它们，因此您最好熟悉一下。

![绘制矩形](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_02_01.jpg)

## 如何做...

按照以下步骤在画布上绘制一个简单的居中矩形：

1.  定义 2D 画布上下文：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  使用`rect()`方法绘制一个矩形，使用`fillStyle`属性设置填充颜色，然后使用`fill()`方法填充形状：

```js
    context.rect(canvas.width / 2 - 100, canvas.height / 2 - 50, 200, 100);
    context.fillStyle = "#8ED6FF";
    context.fill();
    context.lineWidth = 5;
    context.strokeStyle = "black";
    context.stroke();
};
```

1.  将画布标签嵌入 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

从前面的代码中可以看出，我们可以使用`rect()`方法来绘制一个简单的矩形：

```js
context.rect(x,y,width,height);
```

`rect()`方法在位置`x，y`处绘制一个矩形，并使用`width`和`height`定义其大小。在本示例中需要注意的另一件重要的事情是使用`fillStyle`和`fill()`。与`strokeStyle`和`stroke()`类似，我们可以使用`fillStyle`方法分配填充颜色，并使用`fill()`填充形状。

### 提示

请注意，我们在`stroke()`之前使用了`fill()`。如果我们在填充形状之前描边形状，填充样式实际上会覆盖描边样式的一半，有效地减半了使用`lineWidth`设置的线宽样式。因此，最好在使用`stroke()`之前使用`fill()`。

## 还有更多...

除了`rect()`方法，还有两种额外的方法可以用一行代码绘制矩形并应用样式，即`fillRect()`方法和`strokeRect()`方法。

### `fillRect()`方法

如果我们打算在使用`rect()`绘制矩形后填充它，我们可以考虑使用`fillRect()`方法同时绘制和填充矩形：

```js
context.fillRect(x,y,width,height);
```

`fillRect()`方法相当于使用`rect()`方法后跟`fill()`。在使用此方法时，您需要在调用它之前定义填充样式。

### `strokeRect()`方法

除了`fillRect()`方法，我们还可以使用`strokeRect()`方法一次绘制矩形并描边：

```js
context.strokeRect(x,y,width,height);
```

`strokeRect()`方法相当于使用`rect()`方法后跟`stroke()`。与`fillRect()`类似，您需要在调用此方法之前定义描边样式。

### 提示

不幸的是，HTML5 画布 API 不支持同时填充和描边矩形的方法。个人而言，我喜欢使用`rect()`方法，并根据需要使用`stroke()`和`fill()`应用描边样式和填充，因为这更符合自定义形状绘制的一致性。但是，如果您想要在使用这些简写方法之一时同时应用描边和填充矩形，最好使用`fillRect()`后跟`stroke()`。如果您使用`strokeRect()`后跟`fill()`，您会通过填充覆盖描边样式，使描边线宽减半。

## 另见...

+   在第五章中创建线性运动

+   在第六章中检测区域事件

+   在第七章中创建条形图

# 绘制一个圆

尽管 HTML5 画布 API 不支持圆形方法，但我们可以通过绘制完全封闭的弧线来创建一个圆。

![绘制一个圆](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_02_02.jpg)

## 如何做...

按照以下步骤绘制一个居中在画布上的圆：

1.  定义一个 2D 画布上下文：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  使用`arc()`方法创建一个圆，使用`fillStyle`属性设置颜色填充，然后使用`fill()`方法填充形状：

```js
    context.arc(canvas.width / 2, canvas.height / 2, 70, 0, 2 * Math.PI, false);
    context.fillStyle = "#8ED6FF";
    context.fill();
    context.lineWidth = 5;
    context.strokeStyle = "black";
    context.stroke();
};
```

1.  将画布标签嵌入到 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 工作原理...

正如您可能还记得的那样，我们可以使用`arc()`方法创建一个弧线，该方法绘制由起始角和结束角定义的圆的一部分。然而，如果我们将起始角和结束角之间的差定义为 360 度（2π），我们将有效地绘制了一个完整的圆：

```js
context.arc(centerX, centerY, radius, 0, 2 * Math.PI, false);
```

## 另请参阅...

+   使用循环创建图案：绘制齿轮

+   将圆形变换为椭圆在第四章中

+   在第五章中摆动钟摆

+   在第五章中模拟粒子物理

+   在第五章中制作动画时钟

+   在第六章中检测区域事件

+   在第七章中创建饼图

# 使用自定义形状和填充样式

在这个配方中，我们将绘制四个三角形，然后用不同的填充样式填充每一个。HTML5 画布 API 提供的填充样式包括颜色填充、线性渐变、径向渐变和图案。

![使用自定义形状和填充样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_02_10.jpg)

## 如何做...

按照以下步骤绘制四个三角形，一个用颜色填充，一个用线性渐变填充，一个用径向渐变填充，一个用图案填充：

1.  创建一个绘制三角形的简单函数：

```js
function drawTriangle(context, x, y, triangleWidth, triangleHeight, fillStyle){
    context.beginPath();
    context.moveTo(x, y);
    context.lineTo(x + triangleWidth / 2, y + triangleHeight);
    context.lineTo(x - triangleWidth / 2, y + triangleHeight);
    context.closePath();
    context.fillStyle = fillStyle;
    context.fill();
}
```

1.  定义一个 2D 画布上下文，并设置三角形的高度、宽度和 y 位置：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    var grd;
    var triangleWidth = 150;
    var triangleHeight = 150;
    var triangleY = canvas.height / 2 - triangleWidth / 2;
```

1.  使用颜色填充绘制三角形：

```js
    // color fill (left)
    drawTriangle(context, canvas.width * 1 / 5, triangleY, triangleWidth, triangleHeight, "blue");
```

1.  使用线性渐变填充绘制三角形：

```js
    // linear gradient fill (second from left)
    grd = context.createLinearGradient(canvas.width * 2 / 5, triangleY, canvas.width * 2 / 5, triangleY + triangleHeight);
    grd.addColorStop(0, "#8ED6FF"); // light blue
    grd.addColorStop(1, "#004CB3"); // dark blue
    drawTriangle(context, canvas.width * 2 / 5, triangleY, triangleWidth, triangleHeight, grd);
```

1.  使用径向渐变填充绘制三角形：

```js
    // radial gradient fill (second from right)
    var centerX = (canvas.width * 3 / 5 +
    (canvas.width * 3 / 5 - triangleWidth / 2) +
    (canvas.width * 3 / 5 + triangleWidth / 2)) / 3;

    var centerY = (triangleY +
    (triangleY + triangleHeight) +
    (triangleY + triangleHeight)) / 3;

    grd = context.createRadialGradient(centerX, centerY, 10, centerX, centerY, 100);
    grd.addColorStop(0, "red");
    grd.addColorStop(0.17, "orange");
    grd.addColorStop(0.33, "yellow");
    grd.addColorStop(0.5, "green");
    grd.addColorStop(0.666, "blue");
    grd.addColorStop(1, "violet");
    drawTriangle(context, canvas.width * 3 / 5, triangleY, triangleWidth, triangleHeight, grd);
```

1.  使用图案填充绘制三角形：

```js
    // pattern fill (right)
    var imageObj = new Image();
    imageObj.onload = function(){
        var pattern = context.createPattern(imageObj, "repeat");
        drawTriangle(context, canvas.width * 4 / 5, triangleY, triangleWidth, triangleHeight, pattern);
    };
    imageObj.src = "wood-pattern.png";
}; 
```

1.  将画布标签嵌入到 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 工作原理...

正如您可能还记得的那样，我们可以使用`beginPath()`方法开始一个新路径，使用`moveTo()`放置我们的绘图光标，然后绘制连续的子路径以形成路径。我们可以通过使用画布上下文的`closePath()`方法来关闭路径，从而创建一个形状：

```js
context.closePath();
```

这种方法基本上告诉画布上下文通过连接路径中的最后一个点和路径的起点来完成当前路径。

在`drawTriangle()`方法中，我们可以使用`beginPath()`开始一个新路径，使用`moveTo()`定位绘图光标，使用`lineTo()`绘制三角形的两条边，然后使用`closePath()`完成三角形的第三条边。

从上面的截图中可以看出，从左边数第二个三角形是用线性渐变填充的。线性渐变可以使用画布上下文的`createLinearGradient()`方法创建，该方法由起点和终点定义：

```js
var grd=context.createLinearGradient(startX,startY,endX,endY);
```

接下来，我们可以使用`addColorStop()`方法设置渐变的颜色，该方法在 0 到 1 的渐变线偏移位置处分配颜色值：

```js
grd.addColorStop(offset,color);
```

偏移值为 0 的颜色将位于线性渐变的起点，偏移值为 1 的颜色将位于线性渐变的终点。在这个例子中，我们将浅蓝色放在三角形的顶部，深蓝色放在三角形的底部。

接下来，让我们来介绍径向渐变。右侧的第二个三角形填充有一个由六种不同颜色组成的径向渐变。可以使用画布上下文的`createRadialGradient()`方法创建径向渐变，该方法需要一个起点、起始半径、终点和终点半径：

```js
var grd=context.createRadialGradient(startX,startY,
   startRadius,endX,endY,endRadius);
```

径向渐变由两个虚拟圆定义。第一个虚拟圆由`startX`，`startY`和`startRadius`定义。第二个虚拟圆由`endX`，`endY`和`endRadius`定义。与线性渐变类似，我们可以使用画布上下文的`addColorStop()`方法沿径向渐变线位置颜色。

最后，HTML5 画布 API 提供的第四种填充样式是图案。我们可以使用画布上下文的`createPattern()`方法创建一个`pattern`对象，该方法需要一个`image`对象和一个重复选项：

```js
var pattern=context.createPattern(imageObj, repeatOption);
```

`repeatOption`可以选择四个选项之一，`repeat`，`repeat-x`，`repeat-y`和`no-repeat`。除非另有说明，否则`repeatOption`默认为`repeat`。我们将在第三章中更深入地介绍图像，*使用图像和视频*。

## 另请参阅...

+   *将所有内容放在一起：绘制一架喷气机*

# 贝塞尔曲线的乐趣：绘制一朵云

在这个示例中，我们将学习如何通过连接一系列贝塞尔曲线子路径来绘制自定义形状，从而创建一朵蓬松的云。

![贝塞尔曲线的乐趣：绘制一朵云](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_02_05.jpg)

## 如何做...

按照以下步骤在画布中心绘制一朵蓬松的云：

1.  定义一个 2D 画布上下文：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  通过连接六个贝塞尔曲线来绘制一朵云：

```js
    var startX = 200;
    var startY = 100;

  // draw cloud shape
    context.beginPath(); 
    context.moveTo(startX, startY);
    context.bezierCurveTo(startX - 40, startY + 20, startX - 40, startY + 70, startX + 60, startY + 70);
    context.bezierCurveTo(startX + 80, startY + 100, startX + 150, startY + 100, startX + 170, startY + 70);
    context.bezierCurveTo(startX + 250, startY + 70, startX + 250, startY + 40, startX + 220, startY + 20);
    context.bezierCurveTo(startX + 260, startY - 40, startX + 200, startY - 50, startX + 170, startY - 30);
    context.bezierCurveTo(startX + 150, startY - 75, startX + 80, startY - 60, startX + 80, startY - 30);
    context.bezierCurveTo(startX + 30, startY - 75, startX - 20, startY - 60, startX, startY);
    context.closePath();
```

1.  使用`createRadialGradient()`方法定义一个径向渐变并填充形状：

```js
  //add a radial gradient
    var grdCenterX = 260;
    var grdCenterY = 80;
    var grd = context.createRadialGradient(grdCenterX, grdCenterY, 10, grdCenterX, grdCenterY, 200);
    grd.addColorStop(0, "#8ED6FF"); // light blue
    grd.addColorStop(1, "#004CB3"); // dark blue
    context.fillStyle = grd;
    context.fill();
```

1.  设置线宽并描绘云：

```js
  // set the line width and stroke color
    context.lineWidth = 5;
    context.strokeStyle = "#0000ff";
    context.stroke();
};
```

1.  将画布标签嵌入 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;"> 
</canvas>
```

## 它是如何工作的...

使用 HTML5 画布 API 绘制一朵蓬松的云，可以连接多个贝塞尔曲线以形成云形的周边。为了营造一个球形表面的幻觉，我们可以使用`createRadialGradient()`方法创建径向渐变，使用`addColorStop()`方法设置渐变颜色和偏移，使用`fillStyle`设置径向渐变为填充样式，然后使用`fill()`应用渐变。

# 绘制透明形状

对于需要形状分层的应用程序，通常希望使用透明度。在这个示例中，我们将学习如何使用全局 alpha 合成来设置形状的透明度。

![绘制透明形状](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_02_03.jpg)

## 如何做...

按照以下步骤在不透明正方形上方绘制一个透明圆：

1.  定义一个 2D 画布上下文：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  绘制一个矩形：

```js
    // draw rectangle
    context.beginPath();
    context.rect(240, 30, 130, 130);
    context.fillStyle = "blue";
    context.fill();
```

1.  使用`globalAlpha`属性设置画布的全局 alpha，并绘制一个圆：

```js
    // draw circle
    context.globalAlpha = 0.5; // set global alpha
    context.beginPath();
    context.arc(359, 150, 70, 0, 2 * Math.PI, false);
    context.fillStyle = "red";
    context.fill();
}; 
```

1.  将画布标签嵌入 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

使用 HTML5 画布 API 设置形状的不透明度，可以使用`globalAlpha`属性：

```js
context.globalAlpha=[value]
```

`globalAlpha`属性接受 0 到 1 之间的任何实数。我们可以将`globalAlpha`属性设置为`1`，使形状完全不透明，也可以将`globalAlpha`属性设置为`0`，使形状完全透明。

# 使用上下文状态堆栈来保存和恢复样式

在创建更复杂的 HTML5 画布应用程序时，您会发现自己需要一种方法来恢复到以前的样式组合，这样您就不必在绘图过程的不同点设置和重置几十种样式属性。幸运的是，HTML5 画布 API 为我们提供了访问上下文状态堆栈的方式，允许我们保存和恢复上下文状态。在这个示例中，我们将演示状态堆栈是如何工作的，通过保存上下文状态，设置全局 alpha，绘制一个透明圆，将状态堆栈恢复到设置全局 alpha 之前的状态，然后绘制一个不透明的正方形。让我们来看看！

![使用上下文状态堆栈保存和恢复样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_02_11.jpg)

## 准备好了...

在我们讨论画布状态堆栈之前，您必须了解堆栈数据结构的工作原理（如果您已经了解，可以跳到*它是如何工作*部分）。

堆栈数据结构是一种后进先出（LIFO）结构。堆栈有三个主要操作-**push**，**pop**和**stack top**。当一个元素被推送到堆栈上时，它被添加到堆栈的顶部。当堆栈被弹出时，顶部元素被从堆栈中移除。*stack top*操作简单地返回堆栈顶部的元素。

![准备好了...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_02_12.jpg)

看一下前面的图表，它代表了在多个操作中堆栈的状态。在步骤 1 中，我们开始时有一个包含一个元素“a”的堆栈。在步骤 2 中，“b”元素被推送到堆栈上。在步骤 3 中，“c”元素被推送到堆栈上。在步骤 4 中，我们弹出堆栈，这将移除最后推送到堆栈上的元素。由于元素“c”位于堆栈顶部，因此它被移除。在步骤 5 中，我们再次弹出堆栈，这将移除最后推送到堆栈上的元素。由于元素“b”位于堆栈顶部，因此它被移除。

正如我们将在下一节中看到的，堆栈是一个很好的数据结构，用于保存随时间变化的状态，然后通过弹出堆栈来恢复它们。

## 如何做...

按照以下步骤在透明圆上绘制一个不透明的正方形：

1.  定义一个 2D 画布上下文：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  画一个矩形：

```js
    // draw rectangle
    context.beginPath();
    context.rect(150, 30, 130, 130);
    context.fillStyle = "blue";
    context.fill();
```

1.  使用`save()`保存上下文状态，使用`globalAlpha`属性设置画布的全局 alpha，绘制一个圆，然后使用`restore()`恢复画布状态：

```js
    // wrap circle drawing code with save-restore combination
    context.save();
    context.globalAlpha = 0.5; // set global alpha
    context.beginPath();
    context.arc(canvas.width / 2, canvas.height / 2, 70, 0, 2 * Math.PI, false);
    context.fillStyle = "red";
    context.fill();
    context.restore();
```

1.  绘制另一个矩形（将是不透明的），以显示上下文状态已恢复到设置全局 alpha 属性之前的状态：

```js
    // draw another rectangle
    context.beginPath();
    context.rect(canvas.width - (150 + 130), canvas.height - (30 + 130), 130, 130);
    context.fillStyle = "green";
    context.fill();
};
```

1.  将 canvas 标签嵌入到 HTML 文档的 body 中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>

```

## 它是如何工作...

如您在前面的代码中所见，通过将圆形绘制代码包装在 save-restore 组合中，我们实质上是在`save()`方法和`restore()`方法之间封装了我们使用的任何样式，以便它们不会影响之后绘制的形状。可以将 save-restore 组合视为一种引入样式作用域的方式，类似于函数在 JavaScript 中引入变量作用域的方式。尽管您可能会说“嗯，这听起来像是一个复杂的方法来将 globalAlpha 设置回 1！” 等一下伙计。在现实世界中，您通常会处理大量不同的样式组合，用于代码的不同部分。在这种情况下，save-restore 组合是救命稻草。在没有 save-restore 组合的情况下编写复杂的 HTML5 画布应用程序，就像使用全局变量在一个大的 JavaScript 代码块中构建复杂的 Web 应用程序一样。天啊！

## 还有更多...

在第四章中，我们将看到*掌握变换*，状态堆栈的另一个常见用法是保存和恢复变换状态。

## 另请参阅...

+   *使用状态堆栈处理多个变换*在第四章中

# 使用复合操作进行工作

在这个示例中，我们将通过创建每种变化的表格来探索复合操作。复合操作对于创建复杂形状、在其他形状下面绘制形状而不是在其上面以及创建其他有趣的效果非常有用。

![使用复合操作](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_02_04.jpg)

## 准备好了...

以下是 HTML5 画布 API 中可用的每种可能的复合操作的描述，其中红色圆表示源（S），蓝色正方形表示目标（D）。为了进一步加深对复合操作的理解，在阅读每个描述时，有助于查看相应的操作：

| 操作 | 描述 |
| --- | --- |
| `source-atop` (S atop D) | 在两个图像都不透明的地方显示源图像。在目标图像不透明但源图像透明的地方显示目标图像。在其他地方显示透明度。 |
| `source-in` (S in D) | 在源图像和目标图像都不透明的地方显示源图像。在其他地方显示透明度。 |
| `source-out` (S out D) | 在源图像不透明且目标图像透明的地方显示源图像。在其他地方显示透明度。 |
| `source-over` (S over D, default) | 在源图像不透明的地方显示源图像。在其他地方显示目标图像。 |
| `destination-atop` (S atop D) | 在两个图像都不透明的地方显示目标图像。在源图像不透明但目标图像透明的地方显示源图像。在其他地方显示透明度。 |
| `destination-in` (S in D) | 在目标图像和源图像都不透明的地方显示目标图像。在其他地方显示透明度。 |
| `destination -out` (S out D) | 在目标图像不透明且源图像透明的地方显示目标图像。在其他地方显示透明度。 |
| `destination -over` (S over D) | 在目标图像不透明的地方显示目标图像。在其他地方显示目标图像。 |
| `lighter` (S plus D) | 显示源图像和目标图像的总和。 |
| `xor` (S xor D) | 源图像和目标图像的异或。 |
| `copy` (D is ignored) | 显示源图像而不是目标图像。 |

在撰写本文时，处理复合操作相当棘手，因为五个主要浏览器——Chrome、Firefox、Safari、Opera 和 IE9——对复合操作的处理方式不同。与其向您展示当前支持的复合操作的图表，您应该上网搜索类似"canvas composite operation support by browser"的内容，以查看每个浏览器当前的支持情况，如果您打算使用它们。

## 如何做...

按照以下步骤创建复合操作的实时表格：

1.  为画布和文本显示定义样式：

```js
/* select the div child element of the body */
body > div {
    width: 680px;
    height: 430px;
    border: 1px solid black;
    float: left;
    overflow: hidden;
}

canvas {
    float: left;
    margin-top: 30px;
}

div {
    font-size: 11px;
    font-family: verdana;
    height: 15px;
    float: left;
  width: 160px;
}

/* select the 1st, 5th, and 9th label div */
body > div > div:nth-of-type(4n+1) {
    margin-left: 40px;
}
```

1.  定义每个正方形和圆的大小和相对距离：

```js
window.onload = function(){
    var squareWidth = 55;
    var circleRadius = 35;
    var rectCircleDistX = 50;
    var rectCircleDistY = 50;
```

1.  构建一个复合操作的数组：

```js
    // define an array of composite operations
    var operationArray = [];
    operationArray.push("source-atop"); // 0
    operationArray.push("source-in"); // 1
    operationArray.push("source-out"); // 2
    operationArray.push("source-over"); // 3
    operationArray.push("destination-atop"); // 4
    operationArray.push("destination-in"); // 5
    operationArray.push("destination-out"); // 6
    operationArray.push("destination-over"); // 7
    operationArray.push("lighter"); // 8
    operationArray.push("xor"); // 9
    operationArray.push("copy"); // 10
```

1.  执行每个操作并在相应的画布上绘制结果：

```js
    // draw each of the eleven operations
    for (var n = 0; n < operationArray.length; n++) {
        var thisOperation = operationArray[n];
        var canvas = document.getElementById(thisOperation);
        var context = canvas.getContext("2d");

        // draw rectangle
        context.beginPath();
        context.rect(40, 0, squareWidth, squareWidth);
        context.fillStyle = "blue";
        context.fill();

        // set the global composite operation
        context.globalCompositeOperation = thisOperation;

        // draw circle
        context.beginPath();
        context.arc(40 + rectCircleDistX, rectCircleDistY, circleRadius, 0, 2 * Math.PI, false);
        context.fillStyle = "red";
        context.fill();
    }
};
```

1.  在 HTML 文档的主体中嵌入每个操作的画布标签：

```js
<body>
    <div>
        <canvas id="source-atop" width="160" height="90">
        </canvas>
        <canvas id="source-in" width="160" height="90">
        </canvas>
        <canvas id="source-out" width="160" height="90">
        </canvas>
        <canvas id="source-over" width="160" height="90">
        </canvas>
        <div>
            source-atop
        </div>
        <div>
            source-in
        </div>
        <div>
            source-out
        </div>
        <div>
            source-over
        </div>
        <canvas id="destination-atop" width="160" height="90">
        </canvas>
        <canvas id="destination-in" width="160" height="90">
        </canvas>
        <canvas id="destination-out" width="160" height="90">
        </canvas>
        <canvas id="destination-over" width="160" height="90">
        </canvas>
        <div>
            destination-atop
        </div>
        <div>
            destination-in
        </div>
        <div>
            destination-out
        </div>
        <div>
            destination-over
        </div>
        <canvas id="lighter" width="160" height="90">
        </canvas>
        <canvas id="xor" width="160" height="90">
        </canvas>
        <canvas id="copy" width="160" height="90">
        </canvas>
        <canvas width="160" height="90">
        </canvas>
        <div>
            lighter
        </div>
        <div>
            xor
        </div>
        <div>
            copy
        </div>
    </div>
</body>

```

## 它是如何工作的...

我们可以使用画布上下文的`globalCompositeOperation`属性来设置复合操作：

```js
context.globalCompositeOperation=[value];
```

`globalCompositeOperaton`属性接受十一个值之一，包括`source-atop`，`source-in`，`source-out`，`source-over`，`destination-atop`，`destination-in`，`destination-out`，`destination-over`，`lighter`，`xor`和`copy`。`Source`指的是操作后在画布上绘制的所有内容，`destination`指的是操作前在画布上绘制的所有内容。除非另有规定，默认的复合操作设置为`source-over`，这基本上意味着每次在画布上绘制东西时，它都会绘制在已经存在的东西的顶部。

我们可以为每个复合操作创建一个数组，然后循环遍历每个数组，将结果绘制到相应的画布上。对于每次迭代，我们可以绘制一个正方形，设置复合操作，然后绘制一个圆。

# 使用循环创建图案：绘制齿轮

在这个食谱中，我们将通过迭代绘制径向锯齿来创建一个机械齿轮，然后绘制圆来形成齿轮的主体。

![使用循环创建图案：绘制齿轮](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_02_06.jpg)

## 如何做...

按照以下步骤在画布中心绘制齿轮：

1.  定义 2D 画布上下文并设置齿轮属性：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    // gear position
    var centerX = canvas.width / 2;
    var centerY = canvas.height / 2;

  // radius of the teeth tips
    var outerRadius = 95;

  // radius of the teeth intersections
    var innerRadius = 50;

  // radius of the gear without the teeth
    var midRadius = innerRadius * 1.6;

  // radius of the hole
    var holeRadius = 10;

  // num points is the number of points that are required
  // to make the gear teeth.  The number of teeth on the gear
  // are equal to half of the number of points.  In this recipe,
  // we will use 50 points which corresponds to 25 gear teeth.
    var numPoints = 50;
```

1.  绘制齿轮齿：

```js

    // draw gear teeth
    context.beginPath();
  // we can set the lineJoinproperty to bevel so that the tips
  // of the gear teeth are flat and don't come to a sharp point
    context.lineJoin = "bevel";

  // loop through the number of points to create the gear shape
    for (var n = 0; n < numPoints; n++) {
        var radius = null;

    // draw tip of teeth on even iterations
        if (n % 2 == 0) {
            radius = outerRadius;
        }
    // draw teeth connection which lies somewhere between
    // the gear center and gear radius
        else {
            radius = innerRadius;
        }

        var theta = ((Math.PI * 2) / numPoints) * (n + 1);
        var x = (radius * Math.sin(theta)) + centerX;
        var y = (radius * Math.cos(theta)) + centerY;

    // if first iteration, use moveTo() to position
    // the drawing cursor
        if (n == 0) {
            context.moveTo(x, y);
        }
    // if any other iteration, use lineTo() to connect sub paths
        else {
            context.lineTo(x, y);
        }
    }

    context.closePath();

  // define the line width and stroke color
    context.lineWidth = 5;
    context.strokeStyle = "#004CB3";
    context.stroke();
```

1.  绘制齿轮主体：

```js
    // draw gear body
    context.beginPath();
    context.arc(centerX, centerY, midRadius, 0, 2 * Math.PI, false);

  // create a linear gradient
    var grd = context.createLinearGradient(230, 0, 370, 200);
    grd.addColorStop(0, "#8ED6FF"); // light blue
    grd.addColorStop(1, "#004CB3"); // dark blue
    context.fillStyle = grd;
    context.fill();
    context.lineWidth = 5;
    context.strokeStyle = "#004CB3";
    context.stroke();
```

1.  绘制齿轮孔：

```js
    // draw gear hole
    context.beginPath();
    context.arc(centerX, centerY, holeRadius, 0, 2 * Math.PI, false);
    context.fillStyle = "white";
    context.fill();
    context.strokeStyle = "#004CB3";
    context.stroke();
};
```

1.  将画布标签嵌入 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

要在 HTML5 画布上绘制齿轮，我们可以从齿轮周围绘制齿。绘制齿轮的一种方法是使用倒角线连接绘制径向锯齿图案。径向锯齿的一个很好的例子是星星，它沿着想象的内圆有五个点，沿着想象的外圆有五个点。要创建一个星星，我们可以设置一个循环，进行 10 次迭代，每个点进行一次迭代。对于偶数次迭代，我们可以沿着外圆绘制一个点，对于奇数次迭代，我们可以沿着内圆绘制一个点。由于我们的星星有 10 个点，每个点之间的间隔为（2π / 10）弧度。

您可能会问自己“星星与齿轮齿有什么关系？”如果我们将这种逻辑扩展到绘制 50 个点的锯齿形状而不是 10 个点，我们将有效地创建了一个具有 25 个楔形齿的齿轮。

一旦处理了齿轮齿，我们可以绘制一个圆，并使用“createLinearGradient（）”方法应用线性渐变，然后为齿轮的孔绘制一个较小的圆。

## 另请参阅...

+   *在第五章中制作机械齿轮*

# 随机化形状属性：绘制一片花海

在这个食谱中，我们将通过创建一片色彩缤纷的花海来拥抱我们内心的嬉皮士。

![随机化形状属性：绘制一片花海](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_02_07.jpg)

## 如何做...

按照以下步骤在整个画布上绘制随机花朵：

1.  定义`Flower`对象的构造函数：

```js
// define Flower constructor
function Flower(context, centerX, centerY, radius, numPetals, color){
    this.context = context;
    this.centerX = centerX;
    this.centerY = centerY;
    this.radius = radius;
    this.numPetals = numPetals;
    this.color = color;
}
```

1.  定义一个`Flower`对象的`draw`方法，该方法使用`for`循环创建花瓣，然后绘制一个黄色中心：

```js
// Define Flower draw method
Flower.prototype.draw = function(){
    var context = this.context;
    context.beginPath();

    // draw petals
    for (var n = 0; n < this.numPetals; n++) {
        var theta1 = ((Math.PI * 2) / this.numPetals) * (n + 1);
        var theta2 = ((Math.PI * 2) / this.numPetals) * (n);

        var x1 = (this.radius * Math.sin(theta1)) + this.centerX;
        var y1 = (this.radius * Math.cos(theta1)) + this.centerY;
        var x2 = (this.radius * Math.sin(theta2)) + this.centerX;
        var y2 = (this.radius * Math.cos(theta2)) + this.centerY;

        context.moveTo(this.centerX, this.centerY);
        context.bezierCurveTo(x1, y1, x2, y2, this.centerX, this.centerY);
    }

    context.closePath();
    context.fillStyle = this.color;
    context.fill();

    // draw yellow center
    context.beginPath();
    context.arc(this.centerX, this.centerY, this.radius / 5, 0, 2 * Math.PI, false);
    context.fillStyle = "yellow";
    context.fill();
};
```

1.  设置 2D 画布上下文：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  为背景创建绿色渐变：

```js
    // create a green gradation for background
    context.beginPath();
    context.rect(0, 0, canvas.width, canvas.height);
    var grd = context.createLinearGradient(0, 0, canvas.width, canvas.height);
    grd.addColorStop(0, "#1EDE70"); // light green
    grd.addColorStop(1, "#00A747"); // dark green
    context.fillStyle = grd;
    context.fill();
```

1.  创建一个花色数组：

```js
    // define an array of colors
    var colorArray = [];
    colorArray.push("red"); // 0
    colorArray.push("orange"); // 1
    colorArray.push("blue"); // 2
    colorArray.push("purple"); // 3
```

1.  创建一个生成具有随机位置、大小和颜色的花朵的循环：

```js
    // define number of flowers
    var numFlowers = 50;

    // draw randomly placed flowers
    for (var n = 0; n < numFlowers; n++) {
        var centerX = Math.random() * canvas.width;
        var centerY = Math.random() * canvas.height;
        var radius = (Math.random() * 25) + 25;
        var colorIndex = Math.round(Math.random() * (colorArray.length - 1));

        var thisFlower = new Flower(context, centerX, centerY, radius, 5, colorArray[colorIndex]);
        thisFlower.draw();
    }
};
```

1.  将画布标签嵌入 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

这个食谱主要是关于随机化对象属性并使用 HTML5 画布在屏幕上绘制结果。其想法是创建一堆具有不同位置、大小和颜色的花朵。

为了帮助我们创建一片花海，创建一个`Flower`类非常有用，该类定义了花的属性和绘制花的方法。对于这个食谱，我保持了花瓣数量恒定，尽管您可以自行尝试每朵花的花瓣数量不同。

绘制一朵花实际上与我们以前的食谱“使用循环创建图案：绘制齿轮”非常相似，只是这一次，我们将在圆周围绘制花瓣，而不是锯齿。我发现使用 HTML5 画布绘制花瓣的最简单方法是绘制贝塞尔曲线，其起点连接到终点。贝塞尔曲线的起点和终点在花的中心，控制点在`Flower`类的“draw（）”方法中的每次迭代中定义。

一旦我们的`Flower`类设置好并准备就绪，我们可以创建一个循环，每次迭代都实例化随机的`Flower`对象，然后用“draw（）”方法渲染它们。

如果你自己尝试这个教程，你会发现每次刷新屏幕时花朵完全是随机的。

# 创建自定义形状函数：纸牌花色

如果皇家同花顺让你的肾上腺素飙升，那么这个教程适合你。在这个教程中，我们将为黑桃、红心、梅花和方块花色创建绘图函数。

![创建自定义形状函数：纸牌花色](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_02_08.jpg)

## 如何做…

按照以下步骤绘制黑桃、红心、梅花和方块花色：

1.  定义 drawSpade()函数，使用四条贝塞尔曲线、两条二次曲线和一条直线绘制黑桃：

```js
function drawSpade(context, x, y, width, height){
    context.save();
    var bottomWidth = width * 0.7;
    var topHeight = height * 0.7;
    var bottomHeight = height * 0.3;

    context.beginPath();
    context.moveTo(x, y);

    // top left of spade          
    context.bezierCurveTo(
        x, y + topHeight / 2, // control point 1
        x - width / 2, y + topHeight / 2, // control point 2
        x - width / 2, y + topHeight // end point
    );

    // bottom left of spade
    context.bezierCurveTo(
        x - width / 2, y + topHeight * 1.3, // control point 1
        x, y + topHeight * 1.3, // control point 2
        x, y + topHeight // end point
    );

    // bottom right of spade
    context.bezierCurveTo(
        x, y + topHeight * 1.3, // control point 1
        x + width / 2, y + topHeight * 1.3, // control point 2
        x + width / 2, y + topHeight // end point
    );

    // top right of spade
    context.bezierCurveTo(
        x + width / 2, y + topHeight / 2, // control point 1
        x, y + topHeight / 2, // control point 2
        x, y // end point
    );

    context.closePath();
    context.fill();

    // bottom of spade
    context.beginPath();
    context.moveTo(x, y + topHeight);
    context.quadraticCurveTo(
        x, y + topHeight + bottomHeight, // control point
        x - bottomWidth / 2, y + topHeight + bottomHeight // end point
    );
    context.lineTo(x + bottomWidth / 2, y + topHeight + bottomHeight);
    context.quadraticCurveTo(
        x, y + topHeight + bottomHeight, // control point
        x, y + topHeight // end point
    );
    context.closePath();
    context.fillStyle = "black";
    context.fill();
    context.restore();
}
```

1.  定义 drawHeart()函数，使用四条贝塞尔曲线绘制心形：

```js
function drawHeart(context, x, y, width, height){
    context.save();
    context.beginPath();
    var topCurveHeight = height * 0.3;
    context.moveTo(x, y + topCurveHeight);
    // top left curve
    context.bezierCurveTo(
        x, y, 
        x - width / 2, y, 
        x - width / 2, y + topCurveHeight
    );

    // bottom left curve
    context.bezierCurveTo(
        x - width / 2, y + (height + topCurveHeight) / 2, 
        x, y + (height + topCurveHeight) / 2, 
        x, y + height
    );

    // bottom right curve
    context.bezierCurveTo(
        x, y + (height + topCurveHeight) / 2, 
        x + width / 2, y + (height + topCurveHeight) / 2, 
        x + width / 2, y + topCurveHeight
    );

    // top right curve
    context.bezierCurveTo(
        x + width / 2, y, 
        x, y, 
        x, y + topCurveHeight
    );

    context.closePath();
    context.fillStyle = "red";
    context.fill();
    context.restore();
}
```

1.  定义 drawClub()函数，使用四个圆形、两条二次曲线和一条直线绘制梅花：

```js
function drawClub(context, x, y, width, height){
    context.save();
    var circleRadius = width * 0.3;
    var bottomWidth = width * 0.5;
    var bottomHeight = height * 0.35;
    context.fillStyle = "black";

    // top circle
    context.beginPath();
    context.arc(
        x, y + circleRadius + (height * 0.05), 
        circleRadius, 0, 2 * Math.PI, false
    );
    context.fill();

    // bottom right circle
    context.beginPath();
    context.arc(
        x + circleRadius, y + (height * 0.6), 
        circleRadius, 0, 2 * Math.PI, false
    );
    context.fill();

    // bottom left circle
    context.beginPath();
    context.arc(
        x - circleRadius, y + (height * 0.6), 
        circleRadius, 0, 2 * Math.PI, false
    );
    context.fill();

    // center filler circle
    context.beginPath();
    context.arc(
        x, y + (height * 0.5), 
        circleRadius / 2, 0, 2 * Math.PI, false
    );
    context.fill();

    // bottom of club
    context.moveTo(x, y + (height * 0.6));
    context.quadraticCurveTo(
        x, y + height, 
        x - bottomWidth / 2, y + height
    );
    context.lineTo(x + bottomWidth / 2, y + height);
    context.quadraticCurveTo(
        x, y + height, 
        x, y + (height * 0.6)
    );
    context.closePath();
    context.fill();
    context.restore();
}
```

1.  定义 drawDiamond()函数，使用四条直线绘制菱形：

```js
function drawDiamond(context, x, y, width, height){
    context.save();
    context.beginPath();
    context.moveTo(x, y);

    // top left edge
    context.lineTo(x - width / 2, y + height / 2);

    // bottom left edge
    context.lineTo(x, y + height);

    // bottom right edge
    context.lineTo(x + width / 2, y + height / 2);

    // closing the path automatically creates
    // the top right edge
    context.closePath();

    context.fillStyle = "red";
    context.fill();
    context.restore();
}
```

1.  页面加载时，定义画布上下文，然后使用四个绘图函数来渲染黑桃、红心、梅花和方块：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    drawSpade(context, canvas.width * 0.2, 70, 75, 100);
    drawHeart(context, canvas.width * 0.4, 70, 75, 100);
    drawClub(context, canvas.width * 0.6, 70, 75, 100);
    drawDiamond(context, canvas.width * 0.8, 70, 75, 100);
};
```

1.  在 HTML 文档的 body 内嵌入 canvas 标签：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的…

这个教程演示了如何通过组合 HTML5 画布提供的四种主要子路径类型：直线、圆弧、二次曲线和贝塞尔曲线来绘制任何形状。

要绘制黑桃，我们可以连接四条贝塞尔曲线形成顶部部分，然后使用两条二次曲线和一条直线形成底部部分。要绘制红心，我们可以以与黑桃相同的方式连接四条贝塞尔曲线，只是形状的顶点在底部而不是顶部。要创建梅花，我们可以使用圆弧绘制三个圆形作为顶部部分，与黑桃类似，我们可以使用两条二次曲线和一条直线来形成底部部分。最后，要绘制方块，我们可以简单地连接四条直线。

# 将所有内容放在一起：绘制飞机

在这个教程中，我们将通过使用线条、曲线、形状、颜色、线性渐变和径向渐变来推动 HTML5 画布绘图 API 的极限，绘制出矢量飞机。

![将所有内容放在一起：绘制飞机](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_02_09.jpg)

## 如何做…

按照以下步骤绘制矢量飞机：

1.  定义一个 2D 画布上下文，并设置线连接样式：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
  var grd;

    context.lineJoin = "round";
```

1.  绘制右尾翼：

```js
    // outline right tail wing
    context.beginPath();
    context.moveTo(248, 60); //13
    context.lineTo(262, 45); // 12
    context.lineTo(285, 56); //11
    context.lineTo(284, 59); // 10
    context.lineTo(276, 91); // 9
    context.closePath();
    context.fillStyle = "#495AFE";
    context.fill();
    context.lineWidth = 4;
    context.stroke();

    // right tail wing detail
    context.beginPath();
    context.moveTo(281, 54); // 10
    context.lineTo(273, 84); // 9
    context.closePath();
    context.lineWidth = 2;
    context.stroke();
```

1.  绘制右翼：

```js
    // outline right wing
    context.beginPath();
    context.moveTo(425, 159);
    context.lineTo(449, 91); // 4
    context.lineTo(447, 83); // 5
    context.lineTo(408, 67); // 6
    context.lineTo(343, 132); // 7
    context.fillStyle = "#495AFE";
    context.fill();
    context.lineWidth = 4;
    context.stroke();

    // right wing detail
    context.beginPath();
    context.moveTo(420, 158);
    context.lineTo(447, 83); // 4
    context.lineWidth = 2;
    context.stroke();

    context.beginPath();
    context.moveTo(439, 102);
    context.lineTo(395, 81);
    context.lineWidth = 2;
    context.stroke();
```

1.  绘制机身和尾部顶部：

```js
    // outline body
    context.beginPath();
    context.moveTo(541, 300); // 1
    context.quadraticCurveTo(529, 252, 490, 228); // 2
    context.quadraticCurveTo(487, 160, 303, 123); // 3

    // outline tail
    context.lineTo(213, 20); // 14
    context.lineTo(207, 22); // 15
    context.bezierCurveTo(208, 164, 255, 207, 412, 271); // 27
    context.lineTo(427, 271); // 28
    context.quadraticCurveTo(470, 296, 541, 300); // 1
    context.closePath();
    grd = context.createLinearGradient(304, 246, 345, 155);
    grd.addColorStop(0, "#000E91"); // dark blue
    grd.addColorStop(1, "#495AFE"); // light blue
    context.fillStyle = grd;
    context.fill();
    context.lineWidth = 4;
    context.stroke();

    // tail detail
    context.beginPath();
    context.moveTo(297, 124);
    context.lineTo(207, 22);
    context.lineWidth = 2;
    context.stroke();
```

1.  绘制左尾翼：

```js
    // outline left tail wing
    context.beginPath();
    context.moveTo(303, 121); // 8
    context.lineTo(297, 125); // 8
    context.lineTo(255, 104);
    context.lineWidth = 2;
    context.stroke();

    context.beginPath();
    context.moveTo(212, 80);
    context.lineTo(140, 85); // 18
    context.lineTo(138, 91); // 19
    context.lineTo(156, 105); // 20
    context.lineTo(254, 104);
    context.lineTo(254, 100);
    context.lineWidth = 4;
    context.fillStyle = "#495AFE";
    context.fill();
    context.stroke();

    // left tail wing detail
    context.beginPath();
    context.moveTo(140, 86); // 18
    context.lineTo(156, 100); // 20
    context.lineTo(254, 100);
    context.lineTo(209, 77);
    context.lineWidth = 2;
    context.stroke();
```

1.  绘制左翼：

```js
    // outline left wing
    context.beginPath();
    context.moveTo(262, 166); // 22
    context.lineTo(98, 208); // 23
    context.lineTo(96, 215); // 24
    context.lineTo(136, 245); // 25
    context.lineTo(339, 218);
    context.lineTo(339, 215);
    context.closePath();
    context.fillStyle = "#495AFE";
    context.fill();
    context.lineWidth = 4;
    context.stroke();

    // left wing detail
    context.beginPath();
    context.moveTo(98, 210);
    context.lineTo(136, 240); // 25
    context.lineTo(339, 213);
    context.lineWidth = 2;
    context.stroke();

    context.beginPath();
    context.moveTo(165, 235);
    context.lineTo(123, 203);
    context.lineWidth = 2;
    context.stroke();
```

1.  绘制侧面细节：

```js
    // side detail
    context.beginPath();
    context.moveTo(427, 271);
    context.lineTo(423, 221);
    context.quadraticCurveTo(372, 175, 310, 155);
    context.lineWidth = 4;
    context.stroke();
```

1.  绘制机头细节：

```js
    // nose detail
    context.beginPath();
    context.moveTo(475, 288);
    context.quadraticCurveTo(476, 256, 509, 243);
    context.quadraticCurveTo(533, 268, 541, 300); // 1
    context.quadraticCurveTo(501, 300, 475, 288);
    grd = context.createLinearGradient(491, 301, 530, 263);
    grd.addColorStop(0, "#9D0000"); // dark red
    grd.addColorStop(1, "#FF0000"); // light red
    context.fillStyle = grd;
    context.fill();
    context.lineWidth = 4;
    context.stroke();

    context.beginPath();
    context.moveTo(480, 293);
    context.quadraticCurveTo(480, 256, 513, 246);
    context.lineWidth = 2;
    context.stroke();
```

1.  绘制座舱：

```js
    // cockpit detail
    context.beginPath();
    context.moveTo(442, 169);
    context.quadraticCurveTo(419, 176, 415, 200);
    context.quadraticCurveTo(483, 250, 490, 228);
    context.quadraticCurveTo(480, 186, 439, 170);
    context.lineWidth = 4;
    context.stroke();
    grd = context.createRadialGradient(473, 200, 20, 473, 200, 70);
    grd.addColorStop(0, "#E1E7FF"); // dark gray
    grd.addColorStop(1, "#737784"); // light gray
    context.fillStyle = grd;
    context.fill();

    context.beginPath();
    context.moveTo(448, 173);
    context.quadraticCurveTo(425, 176, 420, 204);
    context.lineWidth = 2;
    context.stroke();

    context.beginPath();
    context.moveTo(470, 186);
    context.quadraticCurveTo(445, 190, 440, 220);
    context.lineWidth = 2;
    context.stroke();
```

1.  绘制进气口：

```js
    // intake outline
    context.beginPath();
    context.moveTo(420, 265);
    context.lineTo(416, 223);
    context.bezierCurveTo(384, 224, 399, 270, 420, 265);
    context.closePath();
    context.fillStyle = "#001975";
    context.fill();
    context.lineWidth = 4;
    context.stroke();

    context.beginPath();
    context.moveTo(420, 265);
    context.lineTo(402, 253);
    context.lineWidth = 2;
    context.stroke();

    context.beginPath();
    context.moveTo(404, 203);
    context.bezierCurveTo(364, 204, 379, 265, 394, 263);
    context.lineWidth = 2;
    context.stroke();
};
```

1.  在 HTML 文档的 body 内嵌入 canvas 标签：

```js
<canvas id="myCanvas" width="650" height="350" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的…

这个教程结合了线条、二次曲线、贝塞尔曲线、路径、形状、实心填充、线性渐变和径向渐变的使用。尽管 HTML5 画布相当基础，但它提供了我们绘制出优秀图形所需的一切，包括矢量飞机。

要使用 HTML5 画布绘制飞机，我们可以先在 Adobe Photoshop 或其他带有绘图区域大小等于画布大小的图像编辑器中绘制一架飞机，本例中为 650 x 350 像素。接下来，我们可以使用鼠标在绘图中找到形成飞机形状的主要点，通过悬停在绘图的每条线的端点上记录 x、y 坐标。有了这些坐标，我们可以用 4 像素的线宽绘制飞机的主要轮廓，然后我们可以回去用 2 像素的线宽填充飞机的细节。

### 提示

最好的做法是首先绘制远离观众的图形部分，因为你在画布上绘制的每个形状都会重叠在前面的形状上。如果你看一下前面的代码，你会注意到右翼先被绘制，然后是飞机的机身，最后是左翼。这是因为右翼离观众最远，而左翼离观众最近。

一旦线条绘制完成，我们可以用纯色填充喷气机，给机身添加线性渐变，给座舱添加径向渐变，使绘画具有一定的深度。最后，我们可以在飞机的机头上添加醒目的红色渐变，为起飞做准备，激发我们的想象力。
