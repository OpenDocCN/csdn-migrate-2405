# HTML5 画布秘籍（二）

> 原文：[`zh.annas-archive.org/md5/5BECA7AD01229D44A883D4EFCAD8E67B`](https://zh.annas-archive.org/md5/5BECA7AD01229D44A883D4EFCAD8E67B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：使用图像和视频

在本章中，我们将涵盖：

+   绘制图像

+   裁剪图像

+   复制和粘贴画布的部分

+   使用视频

+   获取图像数据

+   像素操作简介：反转图像颜色

+   反转视频颜色

+   将图像颜色转换为灰度

+   将画布绘制转换为数据 URL

+   将画布绘制保存为图像

+   使用数据 URL 加载画布

+   创建像素化图像焦点

# 介绍

本章重点介绍 HTML5 画布、图像和视频的另一个非常令人兴奋的主题。除了提供定位、调整大小和裁剪图像和视频的基本功能外，HTML5 画布 API 还允许我们访问和修改每个像素的颜色和透明度。让我们开始吧！

# 绘制图像

让我们通过绘制一个简单的图像来开始。在本示例中，我们将学习如何加载图像并在画布上的某个位置绘制它。

![绘制图像](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_03_01.jpg)

按照以下步骤在画布中央绘制图像：

## 如何做...

1.  定义画布上下文：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  创建一个`image`对象，将`onload`属性设置为绘制图像的函数，然后设置图像的源：

```js
    var imageObj = new Image();
    imageObj.onload = function(){
        var destX = canvas.width / 2 - this.width / 2;
        var destY = canvas.height / 2 - this.height / 2;

        context.drawImage(this, destX, destY);
    };
    imageObj.src = "jet_300x214.jpg";
};
```

1.  将 canvas 标签嵌入 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

要绘制图像，我们首先需要使用`new Image()`创建一个`image`对象。请注意，我们在定义图像的源*之前*设置了`image`对象的`onload`属性。

### 提示

在设置图像源*之前*定义加载图像时要执行的操作是一个很好的做法。理论上，如果我们在定义`onload`属性之前定义图像的源，图像可能会在定义完成之前加载（尽管这很不太可能）。

本示例中的关键方法是`drawImage()`方法：

```js
context.drawImage(imageObj,destX,destY);
```

其中`imageObj`是`image`对象，`destX`和`destY`是我们想要放置图像的位置。

## 还有更多...

除了使用`destX`和`destY`定义图像位置外，我们还可以添加两个额外的参数，`destWidth`和`destHeight`来定义图像的大小：

```js
context.drawImage(imageObj,destX,destY,destWidth,destHeight);
```

在大多数情况下，最好不要使用`drawImage()`方法调整图像的大小，因为缩放图像的质量会明显降低，类似于使用 HTML 图像元素的宽度和高度属性调整图像大小时的结果。如果图像质量是您关心的问题（为什么你不会关心？），通常最好在创建需要缩放图像的应用程序时使用缩略图图像。另一方面，如果您的应用程序动态缩小和扩展图像，使用`drawImage()`方法和`destWidth`和`destHeight`来缩放图像是一个完全可以接受的方法。

# 裁剪图像

在本示例中，我们将裁剪图像的一部分，然后将结果绘制到画布上。

![裁剪图像](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_03_02.jpg)

按照以下步骤裁剪图像的一部分并将结果绘制到画布上。

## 如何做...

1.  定义画布上下文：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  创建一个图像对象，将`onload`属性设置为裁剪图像的函数，然后设置图像的源：

```js
    var imageObj = new Image();
    imageObj.onload = function(){
    // source rectangular area
        var sourceX = 550;
        var sourceY = 300;
        var sourceWidth = 300;
        var sourceHeight = 214;

    // destination image size and position
        var destWidth = sourceWidth;
        var destHeight = sourceHeight;
        var destX = canvas.width / 2 - destWidth / 2;
        var destY = canvas.height / 2 - destHeight / 2;

        context.drawImage(this, sourceX, sourceY, sourceWidth, sourceHeight, destX, destY, destWidth, destHeight);
    };
    imageObj.src = "jet_1000x714.jpg";
};
```

1.  将 canvas 标签嵌入 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

在上一个示例中，我们讨论了使用`drawImage()`方法在画布上绘制图像的两种不同方式。在第一种情况下，我们可以传递一个`image`对象和一个位置，简单地在给定位置绘制图像。在第二种情况下，我们可以传递一个`image`对象，一个位置和一个大小，在给定位置以给定大小绘制图像。此外，如果我们想要裁剪图像，还可以向`drawImage()`方法添加六个参数：

```js
Context.drawImage(imageObj,sourceX,sourceY,sourceWidth, sourceHight, sourceHeight,sourceHeight, destX, destY, destWidth, destHeight);
```

看一下下面的图表：

![图像裁剪，步骤是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_03_02a.jpg)

正如您所看到的，`sourceX`和`sourceY`指的是源图像中裁剪区域的左上角。`sourceWidth`和`sourceHeight`指的是源图像中裁剪图像的宽度和高度。`destX`和`destY`指的是裁剪图像在画布上的位置，`destWidth`和`destHeight`指的是结果裁剪图像的宽度和高度。

### 提示

如果您不打算缩放裁剪的图像，则`destWidth`等于`sourceWidth`，`destHeight`等于`sourceHeight`。

# 复制和粘贴画布的部分

在这个示例中，我们将介绍`drawImage()`方法的另一个有趣用法——复制画布的部分。首先，我们将在画布中心绘制一个梅花，然后我们将复制梅花的右侧，然后粘贴到左侧，然后我们将复制梅花的左侧，然后粘贴到右侧。

![复制和粘贴画布的部分](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_03_02b.jpg)

按照以下步骤在画布中心绘制一个梅花，然后将形状的部分复制并粘贴回画布上：

## 如何做...

1.  定义画布上下文：

```js
window.onload = function(){
    // drawing canvas and context
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  使用我们在第二章中创建的`drawSpade()`函数，在画布中心绘制一个梅花，*形状绘制和合成*：

```js
    // draw spade
    var spadeX = canvas.width / 2;
    var spadeY = 20;
    var spadeWidth = 140;
    var spadeHeight = 200;

    // draw spade in center of canvas
    drawSpade(context, spadeX, spadeY, spadeWidth, spadeHeight);
```

1.  复制梅花的右半部分，然后使用`drawImage()`方法将其粘贴到梅花左侧的画布上：

```js
    context.drawImage(
    canvas,         
    spadeX,         // source x
    spadeY,         // source y
    spadeWidth / 2,     // source width
    spadeHeight,       // source height
    spadeX - spadeWidth,  // dest x
    spadeY,         // dest y
    spadeWidth / 2,     // dest width
    spadeHeight        // dest height
  );
```

1.  复制梅花的左半部分，然后使用`drawImage()`方法将其粘贴到梅花右侧的画布上：

```js
    context.drawImage(
    canvas, 
    spadeX - spadeWidth / 2,  // source x   
    spadeY,           // source y
    spadeWidth / 2,       // source width
    spadeHeight,         // source height
    spadeX + spadeWidth / 2,   // dest x
    spadeY,           // dest y
    spadeWidth / 2,       // dest width
    spadeHeight          // dest height
  );
};
```

1.  将画布嵌入到 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

要复制画布的一部分，我们可以将`canvas`对象传递给`drawImage()`方法，而不是一个`image`对象：

```js
Context.drawImage(canvas,sourceX,sourceY,sourceWidth, sourceHight, sourceHeight,sourceHeight, destX, destY, destWidth, destHeight);
```

正如我们将在下一个示例中看到的，我们不仅可以使用`drawImage()`复制图像或画布的部分，还可以复制 HTML5 视频的部分。

# 使用视频

尽管 HTML5 画布 API 没有提供像图像那样在画布上绘制视频的直接方法，但我们可以通过从隐藏的视频标签中捕获帧，然后通过循环将它们复制到画布上来处理视频。

![使用视频](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_03_03.jpg)

## 准备工作...

在开始之前，让我们谈谈每个浏览器支持的 HTML5 视频格式。在撰写本文时，视频格式之争仍在继续，所有主要浏览器——Chrome、Firefox、Opera、Safari 和 IE——继续增加和删除对不同视频格式的支持。更糟糕的是，每当一个主要浏览器增加或删除对特定视频格式的支持时，开发人员就必须重新制定所需的最小视频格式集，以确保其应用程序在所有浏览器中正常工作。

在撰写本文时，三种主要的视频格式是 Ogg Theora、H.264 和 WebM。在本章的视频示例中，我们将使用 Ogg Theora 和 H.264 的组合。在处理视频时，强烈建议您在网上搜索，了解视频支持的当前状态，因为它可能随时发生变化。

还有更多！一旦您决定支持哪些视频格式，您可能需要一个视频格式转换器，将手头的视频文件转换为其他视频格式。一个很好的视频格式转换选项是 Miro Video Converter，它支持几乎任何视频格式的视频格式转换，包括 Ogg Theora、H.264 或 WebM 格式。

Miro Video Converter 可能是目前最常见的视频转换器，尽管您当然可以使用任何其他您喜欢的视频格式转换器。您可以从以下网址下载 Miro Video Converter：[`www.mirovideoconverter.com/`](http://www.mirovideoconverter.com/)。

按照以下步骤将视频绘制到画布上：

## 如何做...

1.  创建一个跨浏览器的方法来请求动画帧：

```js
window.requestAnimFrame = (function(callback){
    return window.requestAnimationFrame ||
    window.webkitRequestAnimationFrame ||
    window.mozRequestAnimationFrame ||
    window.oRequestAnimationFrame ||
    window.msRequestAnimationFrame ||
    function(callback){
        window.setTimeout(callback, 1000 / 60);
    };
})();
```

1.  定义`drawFrame()`函数，它会复制当前视频帧，使用`drawImage()`方法将其粘贴到 canvas 上，然后请求新的动画帧来绘制下一帧：

```js
function drawFrame(context, video){
    context.drawImage(video, 0, 0);
    requestAnimFrame(function(){
        drawFrame(context, video);
    });
}
```

1.  定义 canvas 上下文，获取视频标签，并绘制第一帧视频：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
    var video = document.getElementById("myVideo");
    drawFrame(context, video);
};
```

1.  在 HTML 文档的 body 中嵌入 canvas 和 video 标签：

```js
<video id="myVideo" autoplay="true" loop="true" style="display:none;">
    <source src="img/BigBuckBunny_640x360.ogv" type="video/ogg"/><source src="img/BigBuckBunny_640x360.mp4" type="video/mp4"/>
</video>
<canvas id="myCanvas" width="600" height="360" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

要在 HTML5 画布上绘制视频，我们首先需要在 HTML 文档中嵌入一个隐藏的视频标签。在这个示例中，以及将来的视频示例中，我使用了 Ogg Theora 和 H.264（mp4）视频格式。

接下来，当页面加载时，我们可以使用跨浏览器的`requestAnimFrame()`方法尽可能快地捕获视频帧，然后将它们绘制到 canvas 上。

# 获取图像数据

现在我们知道如何绘制图像和视频，让我们尝试访问图像数据，看看我们可以玩的属性有哪些。

![获取图像数据](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_03_04.jpg)

### 注意

警告：由于`getImageData()`方法的安全限制，此示例必须在 Web 服务器上运行。

## 准备工作...

在开始处理图像数据之前，重要的是我们要了解画布安全和 RGBA 颜色空间。

那么为什么画布安全对于访问图像数据很重要呢？简单来说，为了访问图像数据，我们需要使用画布上下文的`getImageData()`方法，如果我们尝试从非 Web 服务器文件系统上的图像或不同域上的图像访问图像数据，它将抛出`SECURITY_ERR`异常。换句话说，如果你要自己尝试这些演示，如果你的文件存储在本地文件系统上，它们将无法工作。你需要在 Web 服务器上运行本章的其余部分。

接下来，由于像素操作主要是改变像素的 RGB 值，我们可能应该在这里介绍 RGB 颜色模型和 RGBA 颜色空间。RGB 代表像素颜色的红色、绿色和蓝色分量。每个分量都是 0 到 255 之间的整数，其中 0 表示没有颜色，255 表示完整的颜色。RGB 值通常表示如下：

```js
rgb(red,green,blue)
```

以下是用 RGB 颜色模型表示的一些常见颜色值：

```js
rgb(0,0,0) = black
rgb(255,255,255) = white
rgb(255,0,0) = red
rgb(0,255,0) = green
rgb(0,0,255) = blue
rgb(255,255,0) = yellow
rgb(255,0,255) = magenta
rgb(0,255,255) = cyan
```

除了 RGB，像素还可以有一个 alpha 通道，它指的是像素的不透明度。alpha 通道为 0 是完全透明的像素，alpha 通道为 255 是完全不透明的像素。RGBA 颜色空间简单地指的是 RGB 颜色模型（RGB）加上 alpha 通道（A）。

### 提示

请注意不要混淆 HTML5 画布像素的 alpha 通道范围（整数 0 到 255）和 CSS 颜色的 alpha 通道范围（小数 0.0 到 1.0）。

按照以下步骤写出图像数据的属性：

## 如何做...

1.  定义一个 canvas 上下文：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  创建一个`image`对象，将`onload`属性设置为一个绘制图像的函数：

```js
    var imageObj = new Image();
    imageObj.onload = function(){
        var sourceWidth = this.width;
        var sourceHeight = this.height;
        var destX = canvas.width / 2 - sourceWidth / 2;
        var destY = canvas.height / 2 - sourceHeight / 2;
        var sourceX = destX;
        var sourceY = destY;

    // draw image on canvas
        context.drawImage(this, destX, destY);
```

1.  获取图像数据，写出其属性，然后在`onload`定义之外设置`image`对象的源：

```js
    // get image data from the rectangular area 
    // of the canvas containing the image
        var imageData = context.getImageData(sourceX, sourceY, sourceWidth, sourceHeight);
        var data = imageData.data;

    // write out the image data properties
        var str = "width=" + imageData.width + ", height=" + imageData.height + ", data length=" + data.length;
        context.font = "12pt Calibri";
        context.fillText(str, 4, 14);
    };
    imageObj.src = "jet_300x214.jpg";
};
```

1.  将 canvas 标签嵌入 HTML 文档的 body 中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

这个示例的思路是绘制图像，获取其图像数据，然后将图像数据属性写到屏幕上。从前面的代码中可以看到，我们可以使用 canvas 上下文的`getImageData()`方法获取图像数据：

```js
context.getImageData(sourceX,sourceY,sourceWidth,sourceHeight);
```

请注意，`getImageData()`方法只能与 canvas 上下文一起使用，而不能直接使用`image`对象本身。因此，为了获取图像数据，我们必须先将图像绘制到 canvas 上，然后使用 canvas 上下文的`getImageData()`方法。

`ImageData`对象包含三个属性：`width`、`height`和`data`。从这个食谱开头的截图中可以看到，我们的`ImageData`对象包含一个宽度属性为 300，一个高度属性为 214，以及一个`data`属性，它是一个像素信息数组，在这种情况下，长度为 256,800 个元素。说实话，`ImageData`对象的关键是`data`属性。`data`属性包含我们图像中每个像素的 RGBA 信息。由于我们的图像由 300 * 214 = 64,200 像素组成，因此这个数组的长度为 4 * 64,200 = 256,800 个元素。

# 像素处理简介：反转图像颜色

现在我们知道如何访问图像数据，包括图像或视频中每个像素的 RGBA，我们的下一步是探索像素处理的可能性。在这个食谱中，我们将通过反转每个像素的颜色来反转图像的颜色。

![像素处理简介：反转图像颜色](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_03_05.jpg)

### 注意

警告：由于`getImageData()`方法的安全限制，这个食谱必须在 web 服务器上运行。

按照以下步骤反转图像的颜色：

## 操作步骤...

1.  定义 canvas 上下文：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  创建一个`image`对象，并将`onload`属性设置为绘制图像和获取图像数据的函数：

```js
    var imageObj = new Image();
    imageObj.onload = function(){
        var sourceWidth = this.width;
        var sourceHeight = this.height;
        var sourceX = canvas.width / 2 - sourceWidth / 2;
        var sourceY = canvas.height / 2 - sourceHeight / 2;
        var destX = sourceX;
        var destY = sourceY;
        context.drawImage(this, destX, destY);

        var imageData = context.getImageData(sourceX, sourceY, sourceWidth, sourceHeight);
        var data = imageData.data;
```

1.  循环遍历图像中的所有像素并反转颜色：

```js
        for (var i = 0; i < data.length; i += 4) {
            data[i] = 255 - data[i]; // red
            data[i + 1] = 255 - data[i + 1]; // green
            data[i + 2] = 255 - data[i + 2]; // blue
            // i+3 is alpha (the fourth element)
        }
```

1.  用处理后的图像覆盖原始图像，然后在`onload`定义之外设置图像的源：

```js
        // overwrite original image with
        // new image data
        context.putImageData(imageData, destX, destY);
    };
    imageObj.src = "jet_300x214.jpg";
};
```

1.  将 canvas 标签嵌入到 HTML 文档的 body 中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

使用 HTML5 画布反转图像的颜色，我们可以简单地循环遍历图像中的所有像素，然后使用颜色反转算法反转每个像素。别担心，这比听起来容易。要反转像素的颜色，我们可以通过从 255 中减去每个值来反转其 RGB 分量中的每一个值，如下所示：

```js
data[i  ] = 255 - data[i  ]; // red
data[i+1] = 255 - data[i+1]; // green
data[i+2] = 255 - data[i+2]; // blue
```

一旦像素被更新，我们可以使用画布上下文的`putImageData()`方法重新绘制图像：

```js
context.putImageData(imageData, destX, destY); 
```

这个方法基本上允许我们使用图像数据而不是`drawImage()`方法的源图像来绘制图像。

# 反转视频颜色

这个食谱的目的是演示如何对视频进行像素处理，方法与处理图像的方式基本相同。在这个食谱中，我们将反转一个短视频片段的颜色。

![drawImage()方法像素处理工作中反转视频颜色](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_03_06.jpg)

### 注意

警告：由于`getImageData()`方法的安全限制，这个食谱必须在 web 服务器上运行。

按照以下步骤反转视频的颜色：

## 操作步骤...

1.  创建一个跨浏览器的方法来请求动画帧：

```js
window.requestAnimFrame = (function(callback){
    return window.requestAnimationFrame ||
    window.webkitRequestAnimationFrame ||
    window.mozRequestAnimationFrame ||
    window.oRequestAnimationFrame ||
    window.msRequestAnimationFrame ||
    function(callback){
        window.setTimeout(callback, 1000 / 60);
    };
})();
```

1.  定义`drawFrame()`函数，捕获当前视频帧，反转颜色，将帧绘制在画布上，然后请求一个新的动画帧：

```js
function drawFrame(canvas, context, video){
    context.drawImage(video, 0, 0);

    var imageData = context.getImageData(0, 0, canvas.width, canvas.height);
    var data = imageData.data;

    for (var i = 0; i < data.length; i += 4) {
        data[i] = 255 - data[i]; // red
        data[i + 1] = 255 - data[i + 1]; // green
        data[i + 2] = 255 - data[i + 2]; // blue
        // i+3 is alpha (the fourth element)
    }

    // overwrite original image
    context.putImageData(imageData, 0, 0);

    requestAnimFrame(function(){
        drawFrame(canvas, context, video);
    });
}
```

1.  定义画布上下文，获取视频标签，并绘制第一个动画帧：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
    var video = document.getElementById("myVideo");
    drawFrame(canvas, context, video);
};
```

1.  将视频和 canvas 元素嵌入到 HTML 文档的 body 中：

```js
<video id="myVideo" autoplay="true" loop="true" style="display:none;">
    <source src="img/BigBuckBunny_640x360.ogv" type="video/ogg"/><source src="img/BigBuckBunny_640x360.mp4" type="video/mp4"/>
</video>
<canvas id="myCanvas" width="640" height="360" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

与之前的食谱类似，我们可以对视频进行像素处理，方法与处理图像的方式基本相同，因为`getImageData()`方法从画布上下文获取图像数据，而不管上下文是如何渲染的。在这个食谱中，我们可以简单地反转画布上每个像素的颜色，对应`requestAnimFrame()`方法提供的每个视频帧。

# 将图像颜色转换为灰度

在这个食谱中，我们将探讨另一个常见的像素处理算法，将颜色转换为灰度。

![requestAnimFrame()方法将图像颜色转换为灰度](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_03_07.jpg)

### 注意

警告：由于`getImageData()`方法的安全限制，这个食谱必须在 web 服务器上运行。

按照以下步骤将图像的颜色转换为灰度：

## 操作步骤...

1.  定义 canvas 上下文：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  创建一个`image`对象，并将`onload`属性设置为绘制图像并获取图像数据的函数：

```js
    var imageObj = new Image();
    imageObj.onload = function(){
        var sourceWidth = this.width;
        var sourceHeight = this.height;
        var destX = canvas.width / 2 - sourceWidth / 2;
        var destY = canvas.height / 2 - sourceHeight / 2;
        var sourceX = destX;
        var sourceY = destY;

        context.drawImage(this, destX, destY);

        var imageData = context.getImageData(sourceX, sourceY, sourceWidth, sourceHeight);
        var data = imageData.data;
```

1.  循环遍历图像中的像素，并使用亮度方程将颜色转换为灰度：

```js
        for (var i = 0; i < data.length; i += 4) {
            var brightness = 0.34 * data[i] + 0.5 * data[i + 1] + 0.16 * data[i + 2];

            data[i] = brightness; // red
            data[i + 1] = brightness; // green
            data[i + 2] = brightness; // blue
            // i+3 is alpha (the fourth element)
        }
```

1.  用处理后的图像覆盖原始图像，然后在`onload`定义后设置图像源：

```js
        // overwrite original image
        context.putImageData(imageData, destX, destY);
    };
    imageObj.src = "jet_300x214.jpg";
};
```

1.  将 canvas 元素嵌入 HTML 文档的 body 中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 工作原理...

要将 RGB 颜色转换为灰度渐变，我们需要获取颜色的亮度。我们可以使用亮度方程来获取彩色像素的灰度值。这个方程基于这样一个事实，即人类对绿光最敏感，其次是红光，对蓝光最不敏感：

`亮度= 0.34 * R + 0.5 * G + 0.16 * B`

为了考虑生理效应，请注意我们已经增加了对绿色值的权重（最敏感），然后是红色值（较不敏感），最后是蓝色值（最不敏感）。

有了这个方程，我们可以简单地循环遍历图像中的所有像素，计算感知亮度，将这个值分配给 RGB 值中的每个值，然后重新绘制图像到画布上。

# 将画布绘图转换为数据 URL

除了图像数据，我们还可以提取图像数据 URL，它基本上只是一个包含有关画布图像的编码信息的非常长的文本字符串。如果我们想要将画布绘图保存在本地存储或离线数据库中，数据 URL 非常方便。在这个示例中，我们将绘制一个云形状，获取其数据 URL，然后将其插入到 HTML 页面中，以便我们可以看到它的样子。

按照以下步骤将画布绘图转换为数据 URL：

## 如何做...

1.  定义画布上下文并绘制云形状：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

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

    context.lineWidth = 5;
    context.fillStyle = "#8ED6FF";
    context.fill();
    context.strokeStyle = "#0000ff";
    context.stroke();
```

1.  使用`canvas`对象的`toDataURL()`方法获取画布的数据 URL：

```js
    // save canvas image as data url (png format by default)
    var dataURL = canvas.toDataURL();
```

1.  将（长）数据 URL 插入到`<p>`标签中，以便我们可以看到它：

```js
    // insert url into the HTML document so we can see it
    document.getElementById("dataURL").innerHTML = "<b>dataURL:</b> " + dataURL;
};
```

1.  将 canvas 标签嵌入 HTML 文档的 body 中，并创建一个`<p>`标签，用于存储数据 URL：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
<p id="dataURL" style="width:600px;word-wrap: break-word;">
</p>
```

## 工作原理...

这个示例的关键是`toDataURL()`方法，它将画布绘图转换为数据 URL：

```js
var dataURL = canvas.toDataURL();
```

运行此演示时，您将看到一个非常长的数据 URL，看起来像这样：

```js
data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAlg
AAAD6CAYAAAB9LTkQAAAgAElEQVR4Xu3dXbAUxd3H8f+5i09
VrEjuDlRFBSvoo1ETD/HmEcQIXskRc6FViaA+N7woRlNJUDQm4
kueeiS+INz4wEGfilwocLxSUASvDMf4XokpQbFKuAtYSdWT3PXz
/885C3t2Z3dndntme3q+W7UehN2e7k/3sj96enpGhAcCCCCAAAI
IIICAV4ERr6VRGAIIIIAAAggggIAQsBgECCCAAAIIIICAZwECl
mdQikMAAQQQQAABBAhYjAEEEEAAAQQQQMCzAAHLMyjFIYAAAgg
ggAACBCzGAAIIIIAAAggg4FmAgOUZlOIQQAABBBBAAAECFmMAA
QQQQAABBBDwLEDA8gxKcQgggAACCCCAAAGLMYAAAggggAACCHgWI
GB5BqU4BBBAAAEEEECAgMUYQAABBBBAAAEEPAsQsDyDUhwCCCCAA
AIIIEDAYgwggAACCCCAAAKeBQhYnkEpDgEEEEAAAQQQIGAxBhBAA
AEEEEAAAc8CBCzPoBSHAAIIIIAAAggQsBgDCCCAAAIIIICAZwECl
mdQikMAAQQQQAABBAhYjAEEEEAAAQQQQMCzAAHLMyjFIYAAAgggg
AACBCzGAAIIIIAAAggg4FmAgOUZlOIQQAABBBBAAAECFmMAAQQQQ
AABBBDwLEDA8gxKcQgggAACCCCAAAGLMYAAAggggAACCHgWIGB5
BqU4BBBAAAEEEECAgMUYQAABBBBAAAEEPAsQsDyDUhwCCCCAAAI
IIEDAYgwggAACCCCAAAKeBQhYnkEpDgEEEEAAAQQQIGAxBhBAAA
EEEEAAAc8CBCzPoBSHAAIIIIAAAggQsBgDCCCAAAIIIICAZwECl
mdQikMAAQQQQAABBAhYjAEEEEAAAQQQQMCzAAHLMyj
```

在这里看到的只是整个数据 URL 的一小部分。URL 中需要注意的重要部分是非常开始的部分，以`data:image/png;base64`开头。这意味着数据 URL 是一个 PNG 图像，由 base 64 编码表示。

与图像数据不同，图像数据 URL 是特殊的，因为它是一个字符串，可以与本地存储一起存储，或者可以传递到 Web 服务器以保存在离线数据库中。换句话说，图像数据用于检查和操作构成图像的每个单独像素，而图像数据 URL 旨在用于存储画布绘图并在客户端和服务器之间传递。

# 将画布绘图保存为图像

除了将画布绘图保存在本地存储或离线数据库中，我们还可以使用图像数据 URL 将画布绘图保存为图像，以便用户可以将其保存到本地计算机。在这个示例中，我们将获取画布绘图的图像数据 URL，然后将其设置为`image`对象的源，以便用户可以右键单击并将图像下载为 PNG。

按照以下步骤将画布绘图保存为图像：

## 如何做...

1.  定义画布上下文并绘制云形状：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    // draw cloud
    context.beginPath(); // begin custom shape
    context.moveTo(170, 80);
    context.bezierCurveTo(130, 100, 130, 150, 230, 150);
    context.bezierCurveTo(250, 180, 320, 180, 340, 150);
    context.bezierCurveTo(420, 150, 420, 120, 390, 100);
    context.bezierCurveTo(430, 40, 370, 30, 340, 50);
    context.bezierCurveTo(320, 5, 250, 20, 250, 50);
    context.bezierCurveTo(200, 5, 150, 20, 170, 80);
    context.closePath(); // complete custom shape
    context.lineWidth = 5;
    context.fillStyle = "#8ED6FF";
    context.fill();
    context.strokeStyle = "#0000ff";
    context.stroke();
```

1.  获取数据 URL：

```js
    // save canvas image as data url (png format by default)
    var dataURL = canvas.toDataURL();
```

1.  将图像标签的源设置为数据 URL，以便用户可以下载它：

```js
    // set canvasImg image src to dataURL
    // so it can be saved as an image
    document.getElementById("canvasImg").src = dataURL;
};
```

1.  将 canvas 标签嵌入 HTML 文档的 body 中，并添加一个图像标签，其中将包含画布绘图：

```js
<canvas id="myCanvas" width="578" height="200">
</canvas>
<p>
    Image:
</p>
<img id="canvasImg" alt="Right click to save me!">
```

## 工作原理...

在画布上绘制完某些内容后，我们可以创建一个用户可以保存的图像，方法是使用`toDataURL()`方法获取图像数据 URL，然后将`image`对象的源设置为数据 URL。一旦图像加载完成（因为图像是直接加载的，不需要向 Web 服务器发出请求，所以几乎是瞬间完成的），用户可以右键单击图像将其保存到本地计算机。

# 使用数据 URL 加载画布

要使用数据 URL 加载画布，我们可以通过创建一个带有数据 URL 的`image`对象并使用我们的好朋友`drawImage()`将其绘制到画布上来扩展上一个示例。在这个示例中，我们将通过创建一个简单的 Ajax 调用来从文本文件获取数据 URL，然后使用该 URL 将图像绘制到画布上。当然，在现实世界中，您可能会从本地存储获取图像数据 URL，或者通过调用数据服务来获取。

按照以下步骤使用数据 URL 加载画布绘图：

## 操作步骤...

1.  定义`loadCanvas()`函数，该函数以数据 URL 作为输入，定义画布上下文，使用数据 URL 创建一个新的图像，然后在加载完成后将图像绘制到画布上：

```js
function loadCanvas(dataURL){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    // load image from data url
    var imageObj = new Image();
    imageObj.onload = function(){
        context.drawImage(this, 0, 0);
    };

    imageObj.src = dataURL;
}
```

1.  进行一个 AJAX 调用，以获取存储在服务器上的数据 URL，然后在接收到响应时使用响应文本调用`loadCanvas()`：

```js
window.onload = function(){
    // make ajax call to get image data url
    var request = new XMLHttpRequest();
    request.open("GET", "dataURL.txt", true);
    request.onreadystatechange = function(){
        if (request.readyState == 4) { 
            if (request.status == 200) { // successful response
                loadCanvas(request.responseText);
            }
        }
    };
    request.send(null);
};
```

1.  将 canvas 标签嵌入到 HTML 文档的 body 中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 工作原理...

要从 Web 服务器获取图像数据 URL，我们可以设置一个 AJAX 调用（异步 JavaScript 和 XML）来向 Web 服务器发出请求并获取数据 URL 作为响应。当我们得到状态码 200 时，这意味着请求和响应成功，我们可以从`request.responseText`获取图像数据 URL，然后将其传递给`loadCanvas()`函数。然后，该函数将创建一个新的`image`对象，将其源设置为数据 URL，然后在加载完成后将图像绘制到画布上。

# 创建一个像素化图像焦点

寻找一种时髦的方法来聚焦图像？像素化图像焦点怎么样？在这个示例中，我们将通过循环一个像素化算法来探索图像像素化的艺术，直到完全聚焦。

![创建像素化图像焦点](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_03_08.jpg)

### 注意

警告：由于`getImageData()`方法的安全限制，必须在 Web 服务器上运行此示例。

按照以下步骤创建一个逐渐聚焦图像的像素化函数：

## 操作步骤...

1.  定义`focusImage()`函数，该函数根据像素化值去像素化图像：

```js
function focusImage(canvas, context, imageObj, pixelation){
    var sourceWidth = imageObj.width;
    var sourceHeight = imageObj.height;
    var sourceX = canvas.width / 2 - sourceWidth / 2;
    var sourceY = canvas.height / 2 - sourceHeight / 2;
    var destX = sourceX;
    var destY = sourceY;

    var imageData = context.getImageData(sourceX, sourceY, sourceWidth, sourceHeight);
    var data = imageData.data;

    for (var y = 0; y < sourceHeight; y += pixelation) {
        for (var x = 0; x < sourceWidth; x += pixelation) {
            // get the color components of the sample pixel
            var red = data[((sourceWidth * y) + x) * 4];
            var green = data[((sourceWidth * y) + x) * 4 + 1];
            var blue = data[((sourceWidth * y) + x) * 4 + 2];

            // overwrite pixels in a square below and to
            // the right of the sample pixel, whos width and
            // height are equal to the pixelation amount
            for (var n = 0; n < pixelation; n++) {
                for (var m = 0; m < pixelation; m++) {
                    if (x + m < sourceWidth) {
                        data[((sourceWidth * (y + n)) + (x + m)) * 4] = red;
                        data[((sourceWidth * (y + n)) + (x + m)) * 4 + 1] = green;
                        data[((sourceWidth * (y + n)) + (x + m)) * 4 + 2] = blue;
                    }
                }
            }
        }
    }

    // overwrite original image
    context.putImageData(imageData, destX, destY);
}
```

1.  定义画布上下文、决定图像聚焦速度的 fps 值、相应的时间间隔和初始像素化量：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
    var fps = 20; // frames / second
    var timeInterval = 1000 / fps; // milliseconds

    // define initial pixelation.  The higher the value,
    // the more pixelated the image is.  The image is
    // perfectly focused when pixelation = 1;
    var pixelation = 40;
```

1.  创建一个新的`image`对象，将`onload`属性设置为创建一个定时循环的函数，该函数调用`focusImage()`函数并递减每次调用的像素化值，直到图像聚焦，然后在`onload`定义之外设置图像源：

```js
    var imageObj = new Image();
    imageObj.onload = function(){
        var sourceWidth = imageObj.width;
        var sourceHeight = imageObj.height;
        var destX = canvas.width / 2 - sourceWidth / 2;
        var destY = canvas.height / 2 - sourceHeight / 2;

        var intervalId = setInterval(function(){
            context.drawImage(imageObj, destX, destY);

            if (pixelation < 1) {
                clearInterval(intervalId);
            }
            else {
                focusImage(canvas, context, imageObj, pixelation--);
            }
        }, timeInterval);
    };
    imageObj.src = "jet_300x214.jpg";
};
```

1.  将 canvas 标签嵌入到 HTML 文档的 body 中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 工作原理...

在进入像素化算法之前，让我们定义像素化。当人眼可以检测到构成图像的单个像素时，图像就会出现像素化。老式视频游戏图形和被放大的小图像是像素化的很好的例子。通俗地说，如果我们将像素化定义为构成图像的像素可见的条件，这就意味着像素本身相当大。事实上，像素越大，图像就越像素化。我们可以利用这一观察结果来创建像素化算法。

要创建一个像素化图像的算法，我们可以对图像进行颜色采样，然后用超大像素代替。由于像素需要是正方形的，我们可以构造 1 x 1（标准像素大小）、2 x 2、3 x 3、4 x 4 等像素大小。像素越大，图像看起来就越像素化。

到目前为止，我们的方法只是简单地循环遍历`data`属性中的所有像素，并用简单的算法转换它们，而没有太关注哪些像素正在被更新。然而，在这个方法中，我们需要通过查看基于 x，y 坐标的图像特定区域来检查样本像素。我们可以使用以下方程式根据 x，y 坐标来挑选出像素的 RGBA 分量：

```js
var red = data[((sourceWidth * y) + x) * 4];
var green = data[((sourceWidth * y) + x) * 4 + 1];
var blue = data[((sourceWidth * y) + x) * 4 + 2];
```

有了这些方程，我们可以使用`setInterval()`在一段时间内渲染一系列像素化的图像，其中每个连续的像素化图像都比上一个图像少像素化，直到像素化值等于 0，图像恢复到原始状态。


# 第四章：掌握变换

在本章中，我们将涵盖：

+   转换画布上下文

+   旋转画布上下文

+   缩放画布上下文

+   创建镜像变换

+   创建自定义变换

+   剪切画布上下文

+   使用状态堆栈处理多个变换

+   将圆形变换为椭圆

+   旋转图像

+   绘制一个简单的标志并随机化其位置、旋转和缩放

# 介绍

本章将揭示画布变换的威力，它可以极大地简化复杂的绘图，并提供新的功能，否则我们将无法拥有。到目前为止，我们一直在屏幕上直接定位元素的 x 和 y 坐标。如果您已经计算出复杂绘图的每个点的坐标，然后后来决定整个绘图需要重新定位、旋转或缩放，这可能很快成为一个问题。画布变换通过使开发人员能够在不必重新计算构成绘图的每个点的坐标的情况下，转换、旋转和缩放画布的整个部分来解决这个问题。此外，画布变换还使开发人员能够旋转和缩放图像和文本，这是没有变换不可能的。让我们开始吧！

# 转换画布上下文

在这个示例中，我们将学习如何执行 HTML5 画布 API 提供的最基本和最常用的变换——平移。如果您对变换术语不熟悉，“平移”只是一种花哨的说法，意思是“移动”。在这种情况下，我们将把上下文移动到画布上的新位置。

![转换画布上下文](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_04_01.jpg)

## 如何做...

按照以下步骤绘制一个移动到画布中心的平移矩形：

1.  定义画布上下文和矩形的尺寸：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    var rectWidth = 150;
    var rectHeight = 75;
```

1.  将上下文转换为画布的中心：

```js
    // translate context to center of canvas
    context.translate(canvas.width / 2, canvas.height / 2);
```

1.  绘制一个中心位于平移画布上下文左上角的矩形：

```js
    context.fillStyle = "blue";
    context.fillRect(-rectWidth / 2, -rectHeight / 2, rectWidth, rectHeight);
};
```

1.  在 HTML 文档的 body 内嵌入 canvas 标签：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

它是如何工作的！

![画布上下文转换，步骤是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_04_10.jpg)

HTML5 画布变换的思想是以某种方式变换画布上下文，然后在画布上绘制。在这个示例中，我们已经将画布上下文平移，使得上下文的左上角移动到画布的中心：

```js
context.translate(tx,ty);
```

*tx*参数对应于水平平移，*ty*参数对应于垂直平移。一旦上下文被变换，我们就可以在画布上下文的左上角上绘制一个居中的矩形。最终结果是一个被平移的矩形，它被移动到画布的中心。

# 旋转画布上下文

HTML5 画布 API 提供的下一种类型的变换，也可以说是最方便的变换，是旋转变换。在这个示例中，我们将首先使用平移变换来定位画布上下文，然后使用`rotate()`方法来旋转上下文。

![旋转画布上下文](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_04_03.jpg)

## 如何做...

按照以下步骤绘制一个旋转的矩形：

1.  定义画布上下文和矩形的尺寸：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    var rectWidth = 150;
    var rectHeight = 75;
```

1.  将画布上下文平移，然后将其旋转 45 度：

```js
    // translate context to center of canvas
    context.translate(canvas.width / 2, canvas.height / 2);

    // rotate context 45 degrees clockwise
    context.rotate(Math.PI / 4);
```

1.  绘制矩形：

```js
    context.fillStyle = "blue";
    context.fillRect(-rectWidth / 2, -rectHeight / 2, rectWidth, rectHeight);
};
```

1.  在 HTML 文档的 body 内嵌入 canvas 标签：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

它是如何工作的！

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_04_11.jpg)

为了定位和旋转矩形，我们可以将画布上下文转换为画布的中心，就像我们在上一个示例中所做的那样，然后我们可以使用旋转变换来旋转画布上下文，这将使上下文围绕上下文的左上角旋转：

```js
canvas.rotate(theta);
```

参数*theta*以弧度表示，变换将上下文顺时针旋转。一旦上下文被平移和旋转，我们就可以在画布上下文的左上角上绘制一个居中的矩形。最终结果是一个以画布为中心的旋转矩形。

### 提示

请注意，我们通过链接两种不同的变换（平移和旋转）来实现了这个结果。HTML5 画布 API 提供的三种变换都会将一个变换矩阵应用于当前状态。例如，如果我们连续应用三次将画布上下文向右移动 10 像素的平移，最终结果将是向右移动 30 像素的平移。

如果我们想要围绕不同的点旋转矩形，比如说矩形的右下角，我们可以简单地在画布上下文的原点处绘制矩形的右下角。

在创建复杂的 HTML5 画布绘图时，平移和旋转是最常用的变换链。正如我们将在下一章中看到的那样，旋转在动画形状围绕轴旋转时非常有用。

## 参见...

+   *在第五章中摆动钟摆*

+   *在第五章中制作机械齿轮的动画*

+   *在第五章中制作时钟的动画*

# 缩放画布上下文

除了平移和旋转之外，HTML5 画布 API 还为我们提供了一种缩放画布上下文的方法。在这个示例中，我们将使用`scale()`方法缩小画布上下文的高度。

![缩放画布上下文](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_04_02.jpg)

## 如何做...

按照以下步骤绘制一个缩放的矩形：

1.  定义画布上下文和矩形的尺寸：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    var rectWidth = 150;
    var rectHeight = 75;
```

1.  平移画布上下文，然后将画布上下文的高度缩小 50%：

```js
    // translate context to center of canvas
    context.translate(canvas.width / 2, canvas.height / 2);

    // scale down canvas height by half
    context.scale(1, 0.5);
```

1.  绘制一个中心位于画布上下文左上角的矩形：

```js
    context.fillStyle = "blue";
    context.fillRect(-rectWidth / 2, -rectHeight / 2, rectWidth, rectHeight);
};
```

1.  将画布标签嵌入 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 工作原理...

要缩放画布上下文，我们可以简单地使用缩放变换：

```js
context.scale(sx,sy);
```

在上下文的默认状态下，`sx`和`sy`参数被标准化为`1`和`1`。正如您所期望的那样，`sx`参数对应于水平比例，`sy`参数对应于垂直比例。

在这个示例中，我们通过将`sy`参数设置为`0.5`来将垂直上下文缩小了 50%。另一方面，如果我们将`sy`分配给大于`1`的值，上下文将垂直拉伸。正如我们将在下一个示例中看到的，如果我们将`sx`或`sy`值分配为负值，我们将水平或垂直地翻转画布上下文，从而创建一个镜像变换。

## 参见...

+   *在第五章中振荡气泡*

# 创建镜像变换

缩放变换的另一个有趣用途是它能够垂直或水平地镜像画布上下文。在这个示例中，我们将水平镜像画布上下文，然后写出一些倒序的文本。

![创建镜像变换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_04_05.jpg)

## 如何做...

按照以下步骤将文本写成倒序：

1.  定义画布上下文：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  平移画布上下文，然后使用负的`x`值水平翻转上下文：

```js
    // translate context to center of canvas
    context.translate(canvas.width / 2, canvas.height / 2);

    // flip context horizontally
    context.scale(-1, 1);
```

1.  写出“Hello World!”：

```js
    context.font = "30pt Calibri";
    context.textAlign = "center";
    context.fillStyle = "blue";
    context.fillText("Hello World!", 0, 0);
};
```

1.  将画布标签嵌入 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 工作原理...

要使用 HTML5 画布 API 创建镜像变换，我们可以在使用画布上下文的`scale`方法时将`sx`或`sy`赋予负值：

```js
context.scale(-sx,-sy);
```

在这个示例中，我们将画布上下文平移到画布的中心，然后通过应用`scale()`变换的`-sx`值来水平翻转上下文。

# 创建自定义变换

如果您想执行除平移、缩放或旋转之外的自定义变换，HTML5 画布 API 还提供了一种方法，允许我们定义一个自定义变换矩阵，该矩阵可以应用于当前上下文。在这个示例中，我们将手动创建一个平移变换，以演示`transform()`方法的工作原理。

![创建自定义变换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_04_06.jpg)

## 如何做...

按照以下步骤执行自定义变换：

1.  定义矩形的画布上下文和尺寸：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    var rectWidth = 150;
    var rectHeight = 75;
```

1.  通过手动平移画布上下文应用自定义变换：

```js
    // translation matrix:
    //  1  0  tx              
    //  0  1  ty
    //  0  0  1  
    var tx = canvas.width / 2;
    var ty = canvas.height / 2;

    // apply custom transform
    context.transform(1, 0, 0, 1, tx, ty); 
```

1.  绘制矩形：

```js
    context.fillStyle = "blue";
    context.fillRect(-rectWidth / 2, -rectHeight / 2, rectWidth, rectHeight);
};
```

1.  将画布元素嵌入到 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

在本示例中，我们通过将自定义平移变换矩阵应用于上下文状态来创建了自定义平移变换。变换矩阵只是一个二维矩阵，可以用来将当前矩阵转换为新矩阵。可以使用画布上下文的`transform()`方法将自定义变换应用于上下文状态：

```js
context.transform(a,b,c,d,e,f);
```

其中参数`a`、`b`、`c`、`d`、`e`和`f`对应于变换矩阵的以下组成部分：

![自定义变换执行步骤的工作原理...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_04_15.jpg)

这里，*x'*和*y'*是应用变换后的新矩阵*x*和*y*分量。平移变换的变换矩阵如下所示：

![自定义变换执行步骤的工作原理...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_04_13.jpg)

其中*tx*是水平平移，*ty*是垂直平移。

## 还有更多...

除了`transform()`方法之外，还可以使用画布上下文的`setTransform()`方法*设置*变换矩阵，该方法将变换矩阵应用于当前上下文状态：

```js
context.setTransform(a,b,c,d,e,f);
```

如果您想直接使用经过公式化的变换矩阵设置上下文的变换矩阵，而不是通过一系列变换获得相同的结果，那么这种方法可能会很有用。

# 倾斜画布上下文

在本示例中，我们将使用画布上下文的`transform()`方法从水平方向对画布上下文进行自定义剪切变换，利用了我们从画布上下文的`transform()`方法中学到的知识。

![倾斜画布上下文](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_04_07.jpg)

## 如何做...

按照以下步骤绘制一个倾斜的矩形：

1.  定义矩形的画布上下文和尺寸：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    var rectWidth = 150;
    var rectHeight = 75;
```

1.  平移画布上下文，然后对上下文应用自定义剪切变换：

```js
    // shear matrix:
    //  1  sx  0              
    //  sy  1  0
    //  0  0  1  

    var sx = 0.75; // 0.75 horizontal shear
    var sy = 0; // no vertical shear
    // translate context to center of canvas
    context.translate(canvas.width / 2, canvas.height / 2);

    // apply custom transform
    context.transform(1, sy, sx, 1, 0, 0); 
```

1.  绘制矩形：

```js
    context.fillStyle = "blue";
    context.fillRect(-rectWidth / 2, -rectHeight / 2, rectWidth, rectHeight);
};
```

1.  将画布元素嵌入到 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

要使画布上下文倾斜，可以应用以下变换矩阵：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_04_14.jpg)

我们可以使用`transform()`方法和以下参数：

```js
context.transform(1,sy,sx,1,0,0);
```

我们增加`sx`的值，上下文水平倾斜就越大。我们增加`sy`的值，上下文垂直倾斜就越大。

# 使用状态堆栈处理多个变换

现在我们已经很好地掌握了 HTML5 画布 API 的变换，我们现在可以进一步探索画布状态堆栈，并了解它在变换方面对我们有什么作用。在第二章中，*形状绘制和合成*，我们介绍了状态堆栈，这是画布 API 的一个非常强大但有时被忽视的属性。尽管画布状态堆栈可以帮助管理样式，但它最常见的用法是保存和恢复变换状态。在本示例中，我们将在每次变换之间保存画布状态，并在恢复每个状态后绘制一系列矩形，以查看效果。

![使用状态堆栈处理多个变换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_04_08.jpg)

## 如何做...

按照以下步骤构建具有四种不同状态的状态堆栈，然后在弹出每个状态后绘制一个矩形：

1.  定义矩形的画布上下文和尺寸：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");

    var rectWidth = 150;
    var rectHeight = 75;
```

1.  将当前变换状态，即默认状态，推入状态堆栈，并平移上下文：

```js
    context.save(); // save state 1
    context.translate(canvas.width / 2, canvas.height / 2);
```

1.  将当前变换状态，即已平移的状态，推入堆栈，并旋转上下文：

```js
    context.save(); // save state 2
    context.rotate(Math.PI / 4);
```

1.  将当前变换状态，即已平移和旋转的状态，推入堆栈，并缩放上下文：

```js
    context.save(); // save state 3
    context.scale(2, 2);
```

1.  绘制一个蓝色的矩形：

```js
  // draw the rectangle
    context.fillStyle = "blue";
    context.fillRect(-rectWidth / 2, -rectHeight / 2, rectWidth, rectHeight);
```

1.  从状态堆栈中弹出当前状态以恢复先前的状态，然后绘制一个红色的矩形：

```js
    context.restore(); // restore state 3
    context.fillStyle = "red";
    context.fillRect(-rectWidth / 2, -rectHeight / 2, rectWidth, rectHeight);
```

1.  从状态堆栈中弹出当前状态以恢复先前的状态，然后绘制一个黄色的矩形：

```js
    context.restore(); // restore state 2
    context.fillStyle = "yellow";
    context.fillRect(-rectWidth / 2, -rectHeight / 2, rectWidth, rectHeight);
```

1.  从状态堆栈中弹出当前状态以恢复先前的状态，然后绘制一个绿色的矩形：

```js
    context.restore(); // restore state 1
    context.fillStyle = "green";
    context.fillRect(-rectWidth / 2, -rectHeight / 2, rectWidth, rectHeight);
};
```

1.  将画布标签嵌入 HTML 文档的主体中：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 工作原理...

这个方法执行了一系列三次变换，平移、旋转和缩放变换，同时使用`save()`操作将每个变换状态推送到状态堆栈上。当绘制蓝色矩形时，它被居中、旋转和缩放。此时，状态堆栈有四个状态（从底部到顶部）：

1.  默认状态

1.  已翻译状态

1.  已翻译和旋转状态

1.  当前状态（已翻译、旋转和缩放状态）

绘制蓝色矩形后，我们使用`restore()`方法弹出状态堆栈中的顶部状态，并将画布上下文恢复到第三个状态，其中画布上下文被平移和旋转。然后绘制红色矩形，您会看到它已经被平移和旋转，但没有被缩放。接下来，我们再次使用`restore()`方法弹出状态堆栈中的顶部状态，并恢复第二个状态，其中画布上下文仅被平移。然后我们绘制一个黄色的矩形，它确实只是被平移。最后，我们再次调用`restore()`方法，弹出状态堆栈中的顶部状态，并返回到默认状态。当我们绘制绿色矩形时，它出现在原点，因为没有应用任何变换。

### 提示

使用状态堆栈，我们可以在变换状态之间跳转，这样我们就不必不断地将状态重置为默认状态，然后分别对每个元素进行平移。此外，我们还可以使用保存-恢复组合来封装一小段代码的变换，而不会影响后面绘制的形状。

# 将圆形变成椭圆

缩放变换最常见的应用之一是将圆水平或垂直拉伸以创建椭圆。在这个方法中，我们将通过平移画布上下文、水平拉伸它，然后绘制一个圆来创建一个椭圆。

![将圆形变成椭圆](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_04_04.jpg)

## 如何做...

按照以下步骤绘制一个椭圆：

1.  定义画布上下文：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  将当前变换状态（默认状态）推送到状态堆栈上：

```js
    context.save(); // save state
```

1.  定义圆的尺寸：

```js
    var centerX = 0;
    var centerY = 0;
    var radius = 50;
```

1.  将画布上下文平移到画布的中心，然后缩放上下文宽度以向外伸展：

```js
    context.translate(canvas.width / 2, canvas.height / 2);
    context.scale(2, 1);
```

1.  绘制圆：

```js
    context.beginPath();
    context.arc(centerX, centerY, radius, 0, 2 * Math.PI, false);
```

1.  恢复先前的变换状态，即默认状态，并从状态堆栈中弹出当前的变换状态：

```js
    context.restore(); // restore original state
```

1.  对椭圆应用样式：

```js
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

## 工作原理...

要使用 HTML5 画布 API 绘制椭圆，我们可以简单地使用`translate()`方法将上下文平移到所需的位置，使用`scale()`方法在垂直或水平方向上拉伸上下文，然后绘制圆。在这个方法中，我们已经将画布上下文水平拉伸，以创建一个宽度是高度两倍的椭圆。

因为我们想要对椭圆应用描边样式，我们可以使用保存-恢复组合来封装用于创建椭圆的变换，以便它们不会影响椭圆后面的样式。

如果您自己尝试这个方法，并且删除`save()`和`restore()`方法，您会发现椭圆顶部和底部的线条厚度为 5 像素，椭圆两侧的线条厚度为 10 像素，因为描边样式也随着圆形在水平方向被拉伸。

## 另请参阅...

+   *在第五章中*振荡一个气泡*

# 旋转图像

在这个食谱中，我们将通过平移和旋转画布上下文来旋转图像，然后在变换后的上下文上绘制图像。

![旋转图像](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_04_16.jpg)

## 如何做...

按照以下步骤旋转图像：

1.  定义一个画布上下文：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  创建一个新的`image`对象并设置其`onload`属性：

```js
    var imageObj = new Image();
    imageObj.onload = function(){
```

1.  当图像加载时，将上下文转换到画布的中心，逆时针旋转上下文 45 度，然后绘制图像：

```js
        // translate context to center of canvas
        context.translate(canvas.width / 2, canvas.height / 2);

        // rotate context by 45 degrees counter clockwise
        context.rotate(-1 * Math.PI / 4);
        context.drawImage(this, -1 * imageObj.width / 2, -1 * imageObj.height / 2);
    };
```

1.  设置图像的来源：

```js
    imageObj.src = "jet_300x214.jpg";
};
```

1.  在 HTML 文档的 body 中嵌入 canvas 标签：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

要旋转图像，我们可以简单地使用`translate()`方法定位画布上下文，使用`rotate()`方法旋转上下文，然后使用`drawImage()`方法绘制图像。

## 还有更多...

值得注意的是，除了旋转图像之外，与图像一起使用的另一个常见变换是镜像变换。要镜像图像，我们可以将上下文转换到所需的位置，使用`scale(-1,1)`水平反转上下文，或者使用`scale(1,-1)`垂直反转上下文，然后使用`drawImage()`绘制图像。

## 另请参阅...

+   *创建镜像变换*食谱

# 绘制一个简单的标志并随机化其位置、旋转和比例

这个食谱的目的是通过转换复杂的形状来演示变换的实际用途。在这种情况下，我们的复杂形状将是一个标志，它只是一些文本，下面有几条波浪线。当我们想要转换、旋转或缩放复杂的形状时，变换非常有用。开发人员经常创建函数，在原点绘制复杂的东西，然后使用变换将其移动到屏幕上的某个位置。在这个食谱中，我们将在屏幕上绘制五个随机位置、旋转和缩放的标志。

![绘制一个简单的标志并随机化其位置、旋转和比例](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_04_09.jpg)

## 如何做...

按照以下步骤绘制五个随机位置、旋转和缩放的标志：

1.  定义`drawLogo()`函数，通过写出文本并在其下方绘制两条波浪线来绘制一个简单的标志：

```js
function drawLogo(context){
    // draw Hello Logo! text
    context.beginPath();
    context.font = "10pt Calibri";
    context.textAlign = "center";
    context.textBaseline = "middle";
    context.fillStyle = "blue";
    context.fillText("Hello Logo!", 0, 0);
    context.closePath();

  // define style for both waves
    context.lineWidth = 2;
    context.strokeStyle = "blue";

    // draw top wave
    context.beginPath();
    context.moveTo(-30, 10);
    context.bezierCurveTo(-5, 5, 5, 15, 30, 10);
    context.stroke();

    // draw bottom wave
    context.beginPath();
    context.moveTo(-30, 15);
    context.bezierCurveTo(-5, 10, 5, 20, 30, 15);
    context.stroke();
}
```

1.  定义`getRandomX()`函数，返回 0 到画布宽度之间的随机`X`值：

```js
function getRandomX(canvas){
    return Math.round(Math.random() * canvas.width);
}
```

1.  定义`getRandomY()`函数，返回 0 到画布高度之间的随机`Y`值：

```js
function getRandomY(canvas){
    return Math.round(Math.random() * canvas.height);
}
```

1.  定义`getRandomSize()`函数，返回 0 到 5 之间的随机大小：

```js
function getRandomSize(){
    return Math.round(Math.random() * 5);
}
```

1.  定义`getRandomAngle()`函数，返回 0 到 2π之间的随机角度：

```js
function getRandomAngle(){
    return Math.random() * Math.PI * 2;
}
```

1.  定义画布上下文：

```js
window.onload = function(){
    var canvas = document.getElementById("myCanvas");
    var context = canvas.getContext("2d");
```

1.  创建一个循环，绘制五个随机位置、旋转和缩放的标志：

```js
    // draw 5 randomly transformed logos
    for (var n = 0; n < 5; n++) {
        context.save();
        // translate to random position
        context.translate(getRandomX(canvas), getRandomY(canvas));

        // rotate by random angle
        context.rotate(getRandomAngle());

        // scale by random size
        var randSize = getRandomSize();
        context.scale(randSize, randSize);

        // draw logo
        drawLogo(context);
        context.restore();
    }
};
```

1.  在 HTML 文档的 body 中嵌入 canvas 标签：

```js
<canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
</canvas>
```

## 它是如何工作的...

首先，要绘制我们简单的标志，我们可以创建一个名为`drawLogo()`的函数，它在原点写出文本**Hello Logo!**，然后使用`bezierCurveTo()`方法为每个波绘制两条波浪线。

接下来，要绘制五个随机位置、旋转和缩放的标志，我们可以创建一些实用函数，返回位置、旋转和缩放的随机值，然后创建一个`for`循环，每次迭代使用保存-恢复组合来引入状态范围，执行三次变换，然后使用`drawLogo()`方法绘制标志。如果你自己尝试这个食谱，你会发现每次刷新屏幕时，五个标志的位置、旋转和缩放都不同。


# 第五章：通过动画让画布活跃起来

在本章中，我们将涵盖：

+   创建一个动画类

+   创建线性运动

+   创建加速度

+   创建振荡

+   振荡气泡

+   摆动钟摆

+   动画机械齿轮

+   动画时钟

+   模拟粒子物理

+   创建微观生命形式

+   压力测试画布并显示 FPS

# 介绍

在本书的前半部分，我们介绍了 HTML5 画布的基本功能，包括路径绘制、形状绘制、图像和视频处理以及变换。本章重点介绍动画，这不是 HTML5 画布 API 的一部分。尽管 API 没有提供动画功能，但我们肯定可以创建一个动画类，用于支持动画项目。我们将涵盖基本的运动类型，包括线性运动、加速度和振荡，并利用所学知识创建一些真正令人惊叹的演示。让我们开始吧！

# 创建一个动画类

由于 HTML5 画布 API 没有提供动画方法，我们必须为处理动画阶段创建自己的动画类。本教程将介绍动画的基础知识，并为我们未来的动画项目提供一个动画类。

## 准备好了...

由于浏览器和计算机硬件并非完全相同，因此重要的是要了解每个动画的最佳 FPS（每秒帧数）值取决于浏览器、计算机硬件和动画算法。因此，开发人员很难弄清楚每个用户的最佳 FPS 值是多少。幸运的是，浏览器现在正在实现`window`对象的`requestAnimationFrame`方法，该方法可以自动确定动画的最佳 FPS（谢天谢地）。正如我们将在本章后面看到的，流畅动画的典型 FPS 值在 40 到 60 帧之间。

![准备好了...](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_05_01.jpg)

看一下前面的图表。要创建动画，我们首先需要初始化舞台上的对象。我们可以将画布称为“舞台”，因为画布上的移动对象可以看作是舞台上的“演员”。此外，舞台的类比使我们感到画布中的东西正在发生，而不仅仅是静静地坐在那里。一旦我们的对象初始化完成，我们就可以开始一个动画循环，更新舞台，清除画布，重绘舞台，然后请求一个新的动画帧。

由于这种行为可以定义任何类型的动画，所以我们创建一个处理这些步骤的动画类对我们来说是有意义的。

## 操作方法...

按照以下步骤创建一个动画类，该类将支持本章的动画示例：

1.  定义`Animation`构造函数并创建一个跨浏览器的`requestAnimationFrame`方法：

```js
var Animation = function(canvasId){
    this.canvas = document.getElementById(canvasId);
    this.context = this.canvas.getContext("2d");
    this.t = 0;
    this.timeInterval = 0;
    this.startTime = 0;
    this.lastTime = 0;
    this.frame = 0;
    this.animating = false;

    // provided by Paul Irish
    window.requestAnimFrame = (function(callback){
        return window.requestAnimationFrame ||
        window.webkitRequestAnimationFrame ||
        window.mozRequestAnimationFrame ||
        window.oRequestAnimationFrame ||
        window.msRequestAnimationFrame ||
        function(callback){
            window.setTimeout(callback, 1000 / 60);
        };
    })();
};
```

1.  定义`getContext()`方法：

```js
Animation.prototype.getContext = function(){
    return this.context;
};
```

1.  定义`getCanvas()`方法：

```js
Animation.prototype.getCanvas = function(){
    return this.canvas;
};
```

1.  定义`clear()`方法，清除画布：

```js
Animation.prototype.clear = function(){
    this.context.clearRect(0, 0, this.canvas.width, this.canvas.height);
};
```

1.  定义`setStage()`方法，设置`stage()`函数。该函数将为每个动画帧执行：

```js
Animation.prototype.setStage = function(func){
    this.stage = func;
};
```

1.  定义`isAnimating()`方法：

```js
Animation.prototype.isAnimating = function(){
    return this.animating;
};
```

1.  定义`getFrame()`方法，返回帧数：

```js
Animation.prototype.getFrame = function(){
    return this.frame;
};
```

1.  定义`start()`方法，开始动画：

```js
Animation.prototype.start = function(){
    this.animating = true; 
    var date = new Date();
    this.startTime = date.getTime();
    this.lastTime = this.startTime;

    if (this.stage !== undefined) {
        this.stage();
    }

    this.animationLoop();
};
```

1.  定义`stop()`方法，停止动画：

```js
Animation.prototype.stop = function(){
    this.animating = false;
};
```

1.  定义`getTimeInterval()`方法，返回上一帧和当前帧之间的毫秒时间：

```js
Animation.prototype.getTimeInterval = function(){
    return this.timeInterval;
};
```

1.  定义`getTime()`方法，返回动画运行的毫秒时间：

```js
Animation.prototype.getTime = function(){
    return this.t;
};
```

1.  定义`getFps()`方法，返回动画的当前 FPS：

```js
Animation.prototype.getFps = function(){
    return this.timeInterval > 0 ? 1000 / this.timeInterval : 0;
};
```

1.  定义`animationLoop()`方法，处理动画循环：

```js
Animation.prototype.animationLoop = function(){
    var that = this;

    this.frame++;
    var date = new Date();
    var thisTime = date.getTime();
    this.timeInterval = thisTime - this.lastTime;
    this.t += this.timeInterval;
    this.lastTime = thisTime;

    if (this.stage !== undefined) {
        this.stage();
    }

    if (this.animating) {
        requestAnimFrame(function(){
            that.animationLoop();
        });
    }
};
```

## 工作原理...

`Animation`类的思想是通过封装和隐藏动画所需的所有逻辑，简化我们的动画项目，例如提供帧之间的时间间隔，处理动画循环和清除画布。

`Animation`类的关键在于`Animation`构造函数中，我们设置了`window`对象的`requestAnimFrame`方法。这个方法充当了`requestAnimationFrame`的跨浏览器实现，允许用户的浏览器决定动画的最佳 FPS。FPS 是完全动态的，并且会在整个动画过程中发生变化。

我们的`Animation`类还提供了一些方便的方法，比如“getTimeInterval（）”，它返回自上一个动画帧以来的毫秒数，“getTime（）”方法返回动画自启动以来运行的毫秒数，“start（）”方法启动动画，“stop（）”方法停止动画，“clear（）”方法清除画布。

现在我们已经有一个可以投入使用的`Animation`类，本章中的其余动画以及您未来的动画项目都将变得轻而易举。

# 创建线性运动

在这个示例中，我们将通过创建一个简单的线性运动动画来尝试我们的`Animation`类，将一个盒子从画布的左侧移动到右侧：

![创建线性运动](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_05_02.jpg)

## 如何做…

按照以下步骤将一个盒子从画布的一侧移动到另一侧：

1.  链接到`Animation`类：

```js
<head>
    <script src="img/animation.js">
    </script>
```

1.  实例化一个`Animation`对象并获取画布上下文：

```js
    <script>
        window.onload = function(){
            var anim = new Animation("myCanvas");
            var canvas = anim.getCanvas();
            var context = anim.getContext();
```

1.  定义盒子的线性速度并创建一个包含盒子位置和大小的`box`对象：

```js
            var linearSpeed = 100; // pixels / second
            var box = {
                x: 0,
                y: canvas.height / 2 - 25,
                width: 100,
                height: 50
            };
```

1.  设置“stage（）”函数，更新盒子的位置，清除画布并绘制盒子：

```js
        anim.setStage(function(){
            // update
            var linearDistEachFrame = linearSpeed * this.getTimeInterval() / 1000;

            if (box.x < canvas.width - box.width) {
                box.x += linearDistEachFrame;
            }
            else {
                anim.stop();
            }

            // clear
            this.clear();

            // draw
            context.beginPath();
            context.fillStyle = "blue";
            context.fillRect(box.x, box.y, box.width, box.height);
        });
```

1.  开始动画：

```js
        anim.start();
    };
    </script>
</head>
```

1.  将画布嵌入到 HTML 文档的主体中：

```js
<body>
    <canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
    </canvas>
</body>
```

## 它是如何工作…

要创建简单的线性运动，首先我们需要实例化一个新的`Animation`对象，然后获取画布和上下文。接下来，我们可以定义盒子的速度，对于这个示例，我们将速度设置为每秒 100 像素，并且可以创建一个包含盒子位置和大小的`box`对象。

现在我们的盒子已经初始化，我们可以定义“stage（）”函数，该函数将在动画循环中执行。对于每个动画循环，我们可以通过首先计算盒子在上一帧和当前帧之间移动的距离，然后通过添加它移动的距离来更新盒子的 x 位置。一旦盒子到达画布的边缘，我们可以通过调用“stop（）”来停止动画。

最后，一旦“stage（）”函数被定义，我们可以使用“start（）”方法开始动画。

## 另请参阅…

+   *在第二章中绘制一个矩形*

# 创建加速度

现在我们已经掌握了动画的基础知识，让我们尝试一些更复杂的东西，通过重力加速一个盒子向下移动。

![startAnimation（）方法创建加速度](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_05_03.jpg)

## 如何做…

按照以下步骤在画布顶部绘制一个盒子，由于重力的作用而向下移动：

1.  链接到`Animation`类：

```js
<head>
    <script src="img/animation.js">
    </script>
```

1.  实例化一个`Animation`对象并获取画布上下文：

```js
    <script>
        window.onload = function(){
            var anim = new Animation("myCanvas");
            var canvas = anim.getCanvas();
            var context = anim.getContext();
```

1.  定义重力并创建一个包含盒子位置、x 和 y 速度以及大小的`box`对象：

```js
            var gravity = 2; // pixels / second²
            var box = {
                x: canvas.width / 2 - 50,
                y: 0,
                vx: 0,
                vy: 0,
                width: 100,
                height: 50
            };
```

1.  设置“stage（）”函数，更新盒子，清除画布并绘制盒子：

```js
            anim.setStage(function(){
                // update
        if (this.getTime() > 1000) {
                    var speedIncrementEachFrame = gravity * anim.getTimeInterval() / 1000; // pixels / second
                    box.vy += speedIncrementEachFrame;
                    box.y += box.vy * this.getTimeInterval();

                    if (box.y > canvas.height - box.height) {
                        box.y = canvas.height - box.height;
                        this.stop();
                    }
        }

                // clear
                this.clear();

                // draw
                context.beginPath();
                context.fillStyle = "blue";
                context.fillRect(box.x, box.y, box.width, box.height);
            });
```

1.  开始动画：

```js
            anim.start(); 
        };
    </script>
</head>
```

1.  将画布嵌入到 HTML 文档的主体中：

```js
<body>
    <canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
    </canvas>
</body>
```

## 它是如何工作的…

要创建加速度，我们可以增加盒子的速度，更新盒子的位置，清除画布，然后绘制盒子。

我们可以通过添加由于重力引起的速度变化来计算盒子每帧的新 y 速度，这被设置为每秒 2 像素/秒²：

```js
var speedIncrementEachFrame = gravity * anim.getTimeInterval() / 1000; // pixels / second
box.vy += speedIncrementEachFrame;
```

接下来，我们可以通过添加自上一帧以来移动的距离来计算框的新 y 位置：

```js
box.y += box.vy * this.getTimeInterval();
```

换句话说，y 位置的变化等于框的速度乘以时间的变化（时间间隔）。

最后，我们可以添加一个条件来检查框是否已经到达画布的底部，如果是，我们可以使用`stop()`方法停止动画。

### 注意

当施加力到一个物体或粒子时，加速度特别有用。一些施加力的例子包括重力、空气阻力、阻尼、地板摩擦和电磁力。对于需要大量物理学的强烈动画，您可能考虑寻找一个开源矢量库，以帮助处理 x 和 y 方向的速度和加速度。

## 另请参阅...

+   在第二章中绘制一个矩形

# 创建振荡

在这个配方中，我们将探讨第三种主要类型的运动——振荡。一些振荡的好例子是挂在弹簧上的弹簧、振荡气泡或来回摆动的摆。

![振荡气泡](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_05_04.jpg)

## 如何做...

按照以下步骤来使框来回振荡：

1.  链接到`Animation`类：

```js
<head>
    <script src="img/animation.js">
    </script>
```

1.  实例化一个`Animation`对象并获取画布上下文：

```js
    <script>
        window.onload = function(){
            var anim = new Animation("myCanvas");
            var canvas = anim.getCanvas();
            var context = anim.getContext();
```

1.  创建一个包含框的位置和大小的`box`对象：

```js
            var box = {
                x: 250,
                y: canvas.height / 2 - 25,
                width: 100,
                height: 50
            };
```

1.  定义谐波振荡方程所需的参数：

```js
            var centerX = canvas.width / 2 - box.width / 2;
            var amplitude = 150; // pixels
            var period = 2000; // ms
```

1.  设置`stage()`函数，根据谐波振荡方程更新框的位置，清除画布，然后绘制框：

```js
            anim.setStage(function(){
        // update
        box.x = amplitude * Math.sin(anim.getTime() * 2 * Math.PI / period) + centerX;

        // clear
        this.clear();

        // draw
                context.beginPath();
                context.rect(box.x, box.y, box.width, box.height);
                context.fillStyle = "blue";
                context.fill();
            });
```

1.  开始动画：

```js
            anim.start();
        };
    </script>
</head>
```

1.  将画布嵌入到 HTML 文档的主体中：

```js
<body>
    <canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
    </canvas>
</body>
```

## 工作原理...

页面加载后，我们可以实例化一个新的`Animation`对象，然后获取画布和上下文。

接下来，我们可以创建一个`box`对象，定义框的位置和大小，然后定义谐波振荡方程所需的变量：

```js
x(t) = A * sin (t * 2π / T + Φ) + x0
```

对于这个配方，我们将振幅`A`设置为`150`，周期`T`设置为`2`秒，偏移`x0`和相位差`Φ`设置为`0`。

对于每个动画帧，我们可以利用谐波振荡方程来更新框的位置，清除画布，然后使用`rect()`方法绘制框。

最后，我们可以使用`start()`方法开始动画。

## 另请参阅...

+   在第二章中绘制一个矩形

# 振荡气泡

在这个配方中，我们将使用谐波振荡和画布变换的原理来创建一个逼真的振荡气泡。

![振荡气泡](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_05_05.jpg)

## 如何做...

按照以下步骤创建一个在空中漂浮的逼真的振荡气泡：

1.  链接到`Animation`类：

```js
<head>
    <script src="img/animation.js">
    </script>
```

1.  实例化一个`Animation`对象并获取画布上下文：

```js
    <script>
        window.onload = function(){
            // instantiate new animation object
            var anim = new Animation("myCanvas");
            var context = anim.getContext();
            var canvas = anim.getCanvas();
```

1.  设置`stage()`函数，更新气泡的宽度和高度比例，清除画布，缩放画布上下文，然后绘制气泡：

```js
            anim.setStage(function(){
                // update
                var widthScale = Math.sin(this.getTime() / 200) * 0.1 + 0.9;
                var heightScale = -1 * Math.sin(this.getTime() / 200) * 0.1 + 0.9;

                // clear
                this.clear();

                //draw
                context.beginPath();
                context.save();
                context.translate(canvas.width / 2, canvas.height / 2);
                context.scale(widthScale, heightScale);
                context.arc(0, 0, 65, 0, 2 * Math.PI, false);
                context.restore();
                context.fillStyle = "#8ED6FF";
                context.fill();
                context.lineWidth = 2;
                context.strokeStyle = "#555";
                context.stroke();

                context.beginPath();
                context.save();
                context.translate(canvas.width / 2, canvas.height / 2);
                context.scale(widthScale, heightScale);
                context.arc(-30, -30, 15, 0, 2 * Math.PI, false);
                context.restore();
                context.fillStyle = "white";
                context.fill();
            });
```

1.  开始动画：

```js
            anim.start();
        };
    </script>
</head>
```

1.  将画布标签嵌入到 HTML 文档的主体中：

```js
<body>
    <canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
    </canvas>
</body>
```

## 工作原理...

在我们讨论振荡气泡之前，首先介绍如何使用画布变换来在 x 和 y 方向上拉伸气泡是一个好主意。要绘制水平拉伸的气泡，我们可以将上下文转换到画布的中心，水平缩放上下文，然后绘制气泡。要绘制垂直拉伸的气泡，我们可以将其转换到画布的中心，垂直缩放上下文，然后绘制气泡。

为了使气泡振荡，我们需要交替改变画布的缩放方向，使水平缩放和垂直缩放始终等于一个常数，在我们的例子中是 1.8，这样气泡的体积保持不变。一旦建立了这种关系，我们就可以使用谐波振荡方程来振荡气泡的 x 和 y 缩放。

当页面首次加载时，我们可以实例化一个新的`Animation`对象并获取画布和上下文。接下来，我们可以设置`stage()`函数，负责更新气泡，清除画布，然后为每个动画帧绘制气泡。为了更新每一帧的气泡，我们可以使用谐波振荡方程来计算气泡的水平和垂直缩放。接下来，我们可以清除画布，然后使用`arc()`方法绘制气泡。

最后，一旦`stage()`函数设置好，我们就可以用`start()`方法开始动画。

## 另请参阅...

+   *在第二章中绘制圆形*

+   *在第四章中缩放画布上下文*

+   *在第四章中将圆形变成椭圆*

# 摆动钟摆

与气泡示例不同，这个示例中的钟摆的宽度和高度不随时间变化，而是钟摆的*角度*随时间变化。

![摆动钟摆](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_05_06.jpg)

## 如何做...

按照以下步骤来摆动钟摆：

1.  链接到`Animation`类：

```js
<head>
    <script src="img/animation.js">
    </script>
```

1.  实例化一个新的`Animation`对象并获取画布上下文：

```js
    <script>
        window.onload = function(){
            var anim = new Animation("myCanvas");
            var canvas = anim.getCanvas();
            var context = anim.getContext();
```

1.  定义钟摆的属性：

```js
            var amplitude = Math.PI / 4; // 45 degrees
            var period = 4000; // ms
            var theta = 0;
            var pendulumLength = 250;
            var pendulumWidth = 10;
            var rotationPointX = canvas.width / 2;
            var rotationPointY = 20;
```

1.  设置`stage()`函数，更新钟摆的角度，清除画布，然后绘制钟摆：

```js
            anim.setStage(function(){
                // update
                theta = (amplitude * Math.sin((2 * Math.PI * this.getTime()) / period)) + Math.PI / 2;

                // clear
                this.clear();

                // draw top circle
                context.beginPath();
                context.arc(rotationPointX, rotationPointY, 15, 0, 2 * Math.PI, false);
                context.fillStyle = "#888";
                context.fill();

                // draw top inner circle
                context.beginPath();
                context.arc(rotationPointX, rotationPointY, 10, 0, 2 * Math.PI, false);
                context.fillStyle = "black";
                context.fill();

                // draw shaft
                context.beginPath();
                var endPointX = rotationPointX + (pendulumLength * Math.cos(theta));
                var endPointY = rotationPointY + (pendulumLength * Math.sin(theta));
                context.beginPath();
                context.moveTo(rotationPointX, rotationPointY);
                context.lineTo(endPointX, endPointY);
                context.lineWidth = pendulumWidth;
                context.lineCap = "round";
                context.strokeStyle = "#555";
                context.stroke();

                // draw bottom circle
                context.beginPath();
                context.arc(endPointX, endPointY, 40, 0, 2 * Math.PI, false);
                var grd = context.createLinearGradient(endPointX - 50, endPointY - 50, endPointX + 50, endPointY + 50);
                grd.addColorStop(0, "#444");
                grd.addColorStop(0.5, "white");
                grd.addColorStop(1, "#444");
                context.fillStyle = grd;
                context.fill();
            });
```

1.  开始动画：

```js
            anim.start();
        };
    </script>
</head>
```

1.  将画布嵌入 HTML 文档的主体中：

```js
<body>
    <canvas id="myCanvas" width="600" height="330" style="border:1px solid black;">
    </canvas>
</body>
```

## 工作原理...

当页面加载时，我们可以实例化一个新的`Animation`对象，然后获取画布和上下文。接下来，我们可以定义钟摆的属性，包括角振幅、周期、初始角度θ、钟摆长度、宽度和旋转中心。

一旦我们的钟摆初始化完成，我们可以设置`stage()`函数，它将使用谐波振荡方程更新钟摆角度，清除画布，然后立即重新绘制钟摆。

我们可以通过在旋转点绘制一对圆圈，从旋转点到钟摆重物绘制粗线来形成轴，然后在线的末端绘制一个大圆圈，具有漂亮的对角灰色渐变，以营造抛光表面的 illusio。

一旦`stage()`函数设置好，我们就可以用`start()`方法开始动画。

## 另请参阅...

+   *在第一章中绘制直线*

+   *在第二章中绘制圆形*

+   *在第二章中使用自定义形状和填充样式*

# 动画机械齿轮

对于那些懂机械和工程的人，这个是给你们的。在这个示例中，我们将创建一个相互连接的旋转齿轮系统。

![动画机械齿轮](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_05_08.jpg)

## 如何做...

按照以下步骤来动画一个相互连接的齿轮系统：

1.  链接到`Animation`类：

```js
<head>
    <script src="img/animation.js">
    </script>
```

1.  定义`Gear`类的构造函数：

```js
    <script>
        function Gear(config){
            this.x = config.x;
            this.y = config.y;
            this.outerRadius = config.outerRadius;
            this.innerRadius = config.innerRadius;
            this.holeRadius = config.holeRadius;
            this.numTeeth = config.numTeeth;
            this.theta = config.theta;
            this.thetaSpeed = config.thetaSpeed;
            this.lightColor = config.lightColor;
            this.darkColor = config.darkColor;
            this.clockwise = config.clockwise;
            this.midRadius = config.outerRadius - 10;
        }
```

1.  定义`Gear`类的`draw`方法，绘制`gear`对象：

```js
        Gear.prototype.draw = function(context){
            context.save();
            context.translate(this.x, this.y);
            context.rotate(this.theta);

            // draw gear teeth
            context.beginPath();
            // we can set the lineJoin property to bevel so that the tips
            // of the gear teeth are flat and don't come to a sharp point
            context.lineJoin = "bevel";

            // loop through the number of points to create the gear shape
            var numPoints = this.numTeeth * 2;
            for (var n = 0; n < numPoints; n++) {
                var radius = null;

                // draw tip of teeth on even iterations
                if (n % 2 == 0) {
                    radius = this.outerRadius;
                }
                // draw teeth connection which lies somewhere between
                // the gear center and gear radius
                else {
                    radius = this.innerRadius;
                }

                var theta = ((Math.PI * 2) / numPoints) * (n + 1);
                var x = (radius * Math.sin(theta));
                var y = (radius * Math.cos(theta));

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
            context.strokeStyle = this.darkColor;
            context.stroke();

            // draw gear body
            context.beginPath();
            context.arc(0, 0, this.midRadius, 0, 2 * Math.PI, false);

            // create a linear gradient
            var grd = context.createLinearGradient(-1 * this.outerRadius / 2, -1 * this.outerRadius / 2, this.outerRadius / 2, this.outerRadius / 2);
            grd.addColorStop(0, this.lightColor); 
            grd.addColorStop(1, this.darkColor); 
            context.fillStyle = grd;
            context.fill();
            context.lineWidth = 5;
            context.strokeStyle = this.darkColor;
            context.stroke();

            // draw gear hole
            context.beginPath();
            context.arc(0, 0, this.holeRadius, 0, 2 * Math.PI, false);
            context.fillStyle = "white";
            context.fill();
            context.strokeStyle = this.darkColor;
            context.stroke();
            context.restore();
        };
```

1.  实例化一个`Animation`对象并获取画布上下文：

```js
        window.onload = function(){
            var anim = new Animation("myCanvas");
            var canvas = anim.getCanvas();
            var context = anim.getContext();
```

1.  构建一个`gear`对象的数组：

```js
            var gears = [];

            // add blue gear
            gears.push(new Gear({
                x: 270,
                y: 105,
                outerRadius: 90,
                innerRadius: 50,
                holeRadius: 10,
                numTeeth: 24,
                theta: 0,
                thetaSpeed: 1 / 1000,
                lightColor: "#B1CCFF",
                darkColor: "#3959CC",
                clockwise: false
            }));

            // add red gear
            gears.push(new Gear({
                x: 372,
                y: 190,
                outerRadius: 50,
                innerRadius: 15,
                holeRadius: 10,
                numTeeth: 12,
                theta: 0.14,
                thetaSpeed: 2 / 1000,
                lightColor: "#FF9E9D",
                darkColor: "#AD0825",
                clockwise: true
            }));

            // add orange gear
            gears.push(new Gear({
                x: 422,
                y: 142,
                outerRadius: 28,
                innerRadius: 5,
                holeRadius: 7,
                numTeeth: 6,
                theta: 0.35,
                thetaSpeed: 4 / 1000,
                lightColor: "#FFDD87",
                darkColor: "#D25D00",
                clockwise: false
            }));
```

1.  设置`stage()`函数，更新每个齿轮的旋转，清除画布，然后绘制齿轮：

```js
            anim.setStage(function(){
                // update
                for (var i = 0; i < gears.length; i++) {
                    var gear = gears[i];
                    var thetaIncrement = gear.thetaSpeed * this.getTimeInterval();
                    gear.theta += gear.clockwise ? thetaIncrement : -1 * thetaIncrement;
                }

                // clear
                this.clear();

                // draw
                for (var i = 0; i < gears.length; i++) {
                    gears[i].draw(context);
                }
            });
```

1.  开始动画：

```js
            anim.start();
        };
    </script>
</head>
```

1.  将画布嵌入 HTML 文档的主体中：

```js
<body>
    <canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
    </canvas>
</body>
```

## 工作原理...

要创建一个旋转齿轮系统，我们可以重用第二章中的齿轮绘制过程，并创建一个`Gear`类，该类具有一些额外的属性，如齿数、颜色、θ和θ速度。`θ`定义了齿轮的角位置，`θSpeed`定义了齿轮的角速度。我们还可以在`Gear`类中添加一个`clockwise`属性，该属性定义了齿轮旋转的方向。

页面加载后，我们可以实例化一个新的`Animation`对象并获取画布和上下文。接下来，我们可以通过实例化`Gear`对象并将其推入齿轮数组来初始化一些齿轮。现在我们的舞台已经初始化，我们可以设置`stage()`函数，该函数将更新每个齿轮的角度，清除画布，然后使用`Gear`类的`draw()`方法绘制每个齿轮。

现在`stage()`函数已经设置好了，我们可以使用`start()`方法开始动画。

## 另请参阅...

+   *绘制一个圆*在第二章中

+   *使用循环创建图案：绘制齿轮*在第二章中

# 时钟动画

对于那些在开发酷炫项目时陷入恍惚状态，时间似乎消失的人，这个是给你的。在这个示例中，我们将创建一个漂亮的动画时钟，以提醒我们网络空间之外的真实世界时间。

![时钟动画](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_05_10.jpg)

## 如何做...

按照以下步骤在时钟上动画时针、分针和秒针：

1.  链接到`Animation`类：

```js
<head>
    <script src="img/animation.js">
    </script>
```

1.  实例化一个`Animation`对象，获取画布上下文，并定义时钟半径：

```js
    <script>
        window.onload = function(){
            var anim = new Animation("myCanvas");
            var canvas = anim.getCanvas();
            var context = anim.getContext();
            var clockRadius = 75;
```

1.  设置`stage()`函数，该函数获取当前时间，计算时针、分针和秒针的角度，清除画布，然后绘制时钟：

```js
            anim.setStage(function(){

                // update
                var date = new Date();
                var hours = date.getHours();
                var minutes = date.getMinutes();
                var seconds = date.getSeconds();

                hours = hours > 12 ? hours - 12 : hours;

                var hour = hours + minutes / 60;
                var minute = minutes + seconds / 60;

        // clear
        this.clear();

        // draw
                var context = anim.getContext();
                context.save();
                context.translate(canvas.width / 2, canvas.height / 2);

                // draw clock body
                context.beginPath();
                context.arc(0, 0, clockRadius, 0, Math.PI * 2, true);

                var grd = context.createLinearGradient(-clockRadius, -clockRadius, clockRadius, clockRadius);
                grd.addColorStop(0, "#F8FCFF"); // light blue
                grd.addColorStop(1, "#A1CCEE"); // dark blue
                context.fillStyle = grd;
                context.fill();

                // draw numbers  
                context.font = "16pt Calibri";
                context.fillStyle = "#024F8C";
                context.textAlign = "center";
                context.textBaseline = "middle";
                for (var n = 1; n <= 12; n++) {
                    var theta = (n - 3) * (Math.PI * 2) / 12;
                    var x = clockRadius * 0.8 * Math.cos(theta);
                    var y = clockRadius * 0.8 * Math.sin(theta);
                    context.fillText(n, x, y);
                }

                context.save();

                // apply drop shadow
                context.shadowColor = "#bbbbbb";
                context.shadowBlur = 5;
                context.shadowOffsetX = 1;
                context.shadowOffsetY = 1;

                // draw clock rim
                context.lineWidth = 3;
                context.strokeStyle = "#005EA8";
                context.stroke();

                context.restore();

                // draw hour hand
                context.save();
                var theta = (hour - 3) * 2 * Math.PI / 12;
                context.rotate(theta);
                context.beginPath();
                context.moveTo(-10, -4);
                context.lineTo(-10, 4);
                context.lineTo(clockRadius * 0.6, 1);
                context.lineTo(clockRadius * 0.6, -1);
                context.fill();
                context.restore();

                // minute hand
                context.save();
                var theta = (minute - 15) * 2 * Math.PI / 60;
                context.rotate(theta);
                context.beginPath();
                context.moveTo(-10, -3);
                context.lineTo(-10, 3);
                context.lineTo(clockRadius * 0.9, 1);
                context.lineTo(clockRadius * 0.9, -1);
                context.fill();
                context.restore();

                // second hand
                context.save();
                var theta = (seconds - 15) * 2 * Math.PI / 60;
                context.rotate(theta);
                context.beginPath();
                context.moveTo(-10, -2);
                context.lineTo(-10, 2);
                context.lineTo(clockRadius * 0.8, 1);
                context.lineTo(clockRadius * 0.8, -1);
                context.fillStyle = "red";
                context.fill();
                context.restore();

                context.restore();
            });
```

1.  开始动画：

```js
            anim.start();
        };
    </script>
</head>
```

1.  将画布嵌入到 HTML 文档的主体中：

```js
<body>
    <canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
    </canvas>
</body>
```

## 工作原理...

页面加载时，我们可以实例化一个新的`Animation`对象，然后获取画布和上下文。接下来，我们可以开始定义`stage()`函数，该函数负责更新时钟、清除画布，然后为每个动画循环绘制时钟。

在代码的更新部分，我们可以实例化一个新的`Date()`对象，然后获取小时、分钟和秒。接下来，我们可以调整小时和分钟，以表示 12 小时制时间（上午和下午）。

清除画布后，我们可以开始绘制时钟：

+   使用`translate()`方法将画布上下文转换到画布的中心

+   使用`arc()`方法绘制主体

+   创建一个循环，使用`fillText()`方法在边缘绘制时钟的数字

+   使用`shadowOffsetX`和`shadowOffsetY`属性应用阴影

+   通过`stroke()`方法描绘时钟边缘

+   通过旋转画布上下文并绘制一个最厚的梯形来绘制每个时钟指针，其最厚的一端位于中心。

最后，一旦`stage()`函数设置好了，我们就可以使用`start()`方法开始动画。

## 另请参阅...

+   *使用文本*在第一章

+   *绘制一个圆*在第二章中

+   *使用自定义形状和填充样式*在第二章中

# 模拟粒子物理学

现在我们已经介绍了古典物理学的基础知识，让我们把它们整合起来。在这个示例中，我们将通过模拟重力、边界条件、碰撞阻尼和地板摩擦来模拟粒子物理学。

![模拟粒子物理学](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_05_09.jpg)

## 如何做...

按照以下步骤在画布内启动一个粒子，并观察它在墙上弹跳、逐渐因重力落到地板上，然后因地板摩擦而减速停止的弹道：

1.  链接到`Animation`类：

```js
<head>
    <script src="img/animation.js">
    </script>
```

1.  定义`applyPhysics()`函数，它以粒子作为输入，并根据重力、碰撞阻尼和地板摩擦等物理变量更新其位置和速度：

```js
        function applyPhysics(anim, particle){
            // physics globals
            var gravity = 1500; // pixels / second²
            var collisionDamper = 0.8; // 80% velocity lost when collision occurs
            var floorFriction = 100; // pixels / second²
            var timeInterval = anim.getTimeInterval();
            var canvas = anim.getCanvas();

            // gravity
            particle.vy += gravity * timeInterval / 1000;

            // position
            particle.y += particle.vy * timeInterval / 1000;
            particle.x += particle.vx * timeInterval / 1000;

            // floor condition
            if (particle.y > (canvas.height - particle.radius)) {
                particle.y = canvas.height - particle.radius;
                particle.vy *= -1;
                particle.vy *= collisionDamper;
            }

            // floor friction
            if (particle.y == canvas.height - particle.radius) {
                if (particle.vx > 0.1) {
                    particle.vx -= floorFriction * timeInterval / 1000;
                }
                else if (particle.vx < -0.1) {
                    particle.vx += floorFriction * timeInterval / 1000;
                }
                else {
                    particle.vx = 0;
                }
            }

            // ceiling  condition
            if (particle.y < (particle.radius)) {
                particle.y = particle.radius;
                particle.vy *= -1;
                particle.vy *= collisionDamper;
            }

            // right wall condition
            if (particle.x > (canvas.width - particle.radius)) {
                particle.x = canvas.width - particle.radius;
                particle.vx *= -1;
                particle.vx *= collisionDamper;
            }

            // left wall condition
            if (particle.x < (particle.radius)) {
                particle.x = particle.radius;
                particle.vx *= -1;
                particle.vx *= collisionDamper;
            }
        }
```

1.  实例化一个新的`Animation`对象并获取画布上下文：

```js
        window.onload = function(){
            var anim = new Animation("myCanvas");
            var canvas = anim.getCanvas();
            var context = anim.getContext();
```

1.  使用位置、x 和 y 速度以及半径初始化一个`particle`对象：

```js
            var particle = {
                x: 10,
                y: canvas.height - 10,
                vx: 600, // px / second
                vy: -900, // px / second
                radius: 10
            };
```

1.  设置`stage()`函数，通过将其传递给`applyPhysics()`函数来更新粒子，清除画布，然后绘制粒子：

```js
            anim.setStage(function(){
                // update
                applyPhysics(this, particle);

                // clear
                this.clear();

                // draw 
                context.beginPath();
                context.arc(particle.x, particle.y, particle.radius, 0, 2 * Math.PI, false);
                context.fillStyle = "blue";
                context.fill();
            });
```

1.  开始动画：

```js
            anim.start();
        };
    </script>
</head>
```

1.  在 HTML 文档的 body 内嵌入画布标签：

```js
<body>
    <canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
    </canvas>
</body>
```

## 工作原理...

模拟粒子物理学，我们需要处理每一帧粒子的 x 和 y 位置以及粒子在 x 和 y 方向的速度。理解粒子物理模拟的关键是要记住，粒子在系统中的运动是基于作用在粒子上的所有力的总和。在我们的情况下，重力将使粒子向下移动，与墙壁、天花板和地板的碰撞将根据碰撞阻尼常数减少粒子的速度，地板摩擦将在粒子在地板上滚动时减少其水平速度。

首先，当页面加载时，我们可以实例化一个新的`Animation`对象，然后获取画布和上下文。接下来，我们可以初始化一个具有位置、初始速度和大小的粒子。现在我们已经在舞台上初始化了演员（粒子），我们可以设置`stage()`函数，该函数将更新粒子，清除画布，然后为每个动画帧绘制粒子。

更新逻辑发生在`applyPhysics()`函数内，该函数接收对`Animation`对象的引用，以及`particle`对象。`applyPhysics()`函数遍历一系列条件，更新粒子的位置和速度。

在调用`applyPhysics()`函数并更新粒子后，我们可以清除画布，然后通过绘制一个简单的圆来绘制粒子，其半径等于粒子的半径。

最后，一旦`stage()`函数被设置，我们可以使用`start()`方法开始动画。

## 还有更多...

如果你真的想要变得花哨，甚至可以添加额外的力，比如空气阻力。作为一个经验法则，你添加到粒子模拟中的力越多，它就越像真实的生命。你可以尝试不同的初始位置和速度，看看不同的抛射路径。

## 另请参阅...

+   *在第二章中绘制一个圆形*

# 创建微观生命形式

你是否曾在显微镜中看到微生物，并观察它们如何摇摆？这个配方受到微生物的外星世界的启发。在这个配方中，我们将创建 100 个随机微生物，并让它们在画布上自由移动。

![创建微观生命形式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_05_11.jpg)

## 操作步骤...

按照以下步骤在画布内创建摇摆的微生物：

1.  链接到`Animation`类：

```js
<head>
    <script src="img/animation.js">
    </script>
```

1.  定义`getRandColor()`函数，返回一个随机颜色：

```js
    <script>
        function getRandColor(){
            var colors = ["red", "orange", "yellow", "green", "blue", "violet"];
            return colors[Math.floor(Math.random() * colors.length)];
        }
```

1.  定义`getRandTheta()`函数，返回一个随机角度：

```js
        function getRandTheta(){
            return Math.random() * 2 * Math.PI;
        }
```

1.  定义`updateMicrobes()`函数，通过为每个微生物添加一个新的头部段并生成随机角度，然后移除尾部段来更新`microbe`对象：

```js
        function updateMicrobes(anim, microbes){
            var canvas = anim.getCanvas();
            var angleVariance = 0.2;

            for (var i = 0; i < microbes.length; i++) {
                var microbe = microbes[i];
                var angles = microbe.angles;

        /*
         * good numNewSegmentsPerFrame values:
         * 60fps -> 1
         * 10fps -> 10 
         * 
         * for a linear relationship, we can use the equation:
         * n = mf + b, where n = numNewSegmentsPerFrame and f = FPS
         * solving for m and b, we have:
         * n = (-0.18)f + 11.8
         */
                var numNewSegmentsPerFrame = Math.round(-0.18 * anim.getFps() + 11.8);

                for (var n = 0; n < numNewSegmentsPerFrame; n++) {
                    // create first angle if no angles
                    if (angles.length == 0) {
                        microbe.headX = canvas.width / 2;
                        microbe.headY = canvas.height / 2;
                        angles.push(getRandTheta());
                    }

                    var headX = microbe.headX;
                    var headY = microbe.headY;
                    var headAngle = angles[angles.length - 1];

                    // create new head angle
                    var dist = anim.getTimeInterval() / (10 * numNewSegmentsPerFrame);
                    // increase new head angle by an amount equal to
                    // -0.1 to 0.1
                    var newHeadAngle = headAngle + ((angleVariance / 2) - Math.random() * angleVariance);
                    var newHeadX = headX + dist * Math.cos(newHeadAngle);
                    var newHeadY = headY + dist * Math.sin(newHeadAngle);

                    // change direction if collision occurs
                    if (newHeadX >= canvas.width || newHeadX <= 0 || newHeadY >= canvas.height || newHeadY <= 0) {
                        newHeadAngle += Math.PI / 2;
                        newHeadX = headX + dist * Math.cos(newHeadAngle);
                        newHeadY = headY + dist * Math.sin(newHeadAngle);
                    }

                    microbe.headX = newHeadX;
                    microbe.headY = newHeadY;
                    angles.push(newHeadAngle);

                    // remove tail angle
                    if (angles.length > 20) {
                        angles.shift();
                    }
                }
            }
        }
```

1.  定义`drawMicrobes()`函数来绘制所有的微生物：

```js
        function drawMicrobes(anim, microbes){
            var segmentLength = 2; // px
            var context = anim.getContext();

            for (var i = 0; i < microbes.length; i++) {
                var microbe = microbes[i];

                var angles = microbe.angles;
                context.beginPath();
                context.moveTo(microbe.headX, microbe.headY);

                var x = microbe.headX;
                var y = microbe.headY;

                // start with the head and end with the tail
                for (var n = angles.length - 1; n >= 0; n--) {
                    var angle = angles[n];

                    x -= segmentLength * Math.cos(angle);
                    y -= segmentLength * Math.sin(angle);
                    context.lineTo(x, y);
                }

                context.lineWidth = 10;
                context.lineCap = "round";
                context.lineJoin = "round";
                context.strokeStyle = microbe.color;
                context.stroke();
            }
        }
```

1.  实例化一个`Animation`对象并获取画布上下文：

```js
        window.onload = function(){
            var anim = new Animation("myCanvas");
            var canvas = anim.getCanvas();
            var context = anim.getContext();
```

1.  初始化 100 个微生物：

```js
            // init microbes
            var microbes = [];
            for (var n = 0; n < 100; n++) {
                // each microbe will be an array of angles
                microbes[n] = {
                    headX: 0,
                    headY: 0,
                    angles: [],
                    color: getRandColor()
                };
            }
```

1.  设置`stage()`函数，通过调用`updateMicrobes()`函数来更新微生物，清除画布，然后通过调用`drawMicrobes()`函数来绘制微生物：

```js
            anim.setStage(function(){
                // update
                updateMicrobes(this, microbes);

                // clear
                this.clear();

                // draw
                drawMicrobes(this, microbes);
            });
```

1.  开始动画：

```js
            anim.start();
        };
    </script>
</head>
```

1.  在 HTML 文档的 body 内嵌入画布：

```js
<body>
    <canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
    </canvas>
</body>
```

## 工作原理...

要创建一个微生物，我们可以绘制一系列连接的段，以创建一个类似蛇的短生物。我们可以将微生物表示为一个包含头部位置和角度数组的对象。这些角度表示段之间的角度。

这个示例初始化了 100 个随机化的微生物，并将它们放在画布的中心。我们的`stage()`函数包含`updateMicrobes()`和`drawMicrobes()`函数。

`updateMicrobes()`函数循环遍历所有微生物对象，为每个微生物添加一个新的头部段，并删除每个微生物的尾部段。这样，每个微生物的段在移动时会摆动。当微生物的头部碰到画布的边缘时，它的角度将增加 90 度，以便它反弹回画布区域。

`drawMicrobes()`函数循环遍历所有`microbe`对象，将绘图光标定位在每个微生物的头部，然后根据每个段的角度绘制 20 条线段。

## 另请参阅...

+   在第一章中绘制螺旋

+   在第六章中创建一个绘图应用程序

# 强调画布并显示 FPS

在看到上一个示例之后，你可能会想“我们可以动画化多少微生物？”这个问题的直接答案是肯定的。由于 HTML5 画布的 2D 上下文不是硬件加速的，而且我们的动画纯粹由 JavaScript 驱动，所以肯定有一个点，当浏览器加班工作时，它会开始变得吃力。为了说明这一点，我们可以绘制我们动画的 FPS，并观察屏幕上微生物数量与 FPS 值之间的关系。

![强调画布并显示 FPS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-cnvs-cb/img/1369_05_12.jpg)

## 如何做...

按照以下步骤来强调画布并显示 FPS：

1.  链接到`Animation`类：

```js
<head>
    <script src="img/animation.js">
    </script>
```

1.  定义`drawFps()`函数，在画布的右上角绘制 FPS 值：

```js
        function drawFps(anim, fps){
            var canvas = anim.getCanvas();
            var context = anim.getContext();

            context.fillStyle = "black";
            context.fillRect(canvas.width - 100, 0, 100, 30);

            context.font = "18pt Calibri";
            context.fillStyle = "white";
            context.fillText("fps: " + fps.toFixed(1), canvas.width - 93, 22);
        }
```

1.  定义`getRandColor()`函数，返回一个随机颜色：

```js
    <script>
        function getRandColor(){
            var colors = ["red", "orange", "yellow", "green", "blue", "violet"];
            return colors[Math.floor(Math.random() * colors.length)];
        }
```

1.  定义`getRandTheta()`函数，返回一个随机的θ：

```js
        function getRandTheta(){
            return Math.random() * 2 * Math.PI;
        }
```

1.  定义`updateMicrobes()`函数，通过为每个微生物添加一个具有随机生成角度的新头部段来更新`microbe`对象，然后删除尾部段：

```js
        function updateMicrobes(anim, microbes){
            var canvas = anim.getCanvas();
            var angleVariance = 0.2;

            for (var i = 0; i < microbes.length; i++) {
                var microbe = microbes[i];
                var angles = microbe.angles;

                /*
              * good numNewSegmentsPerFrame values:
              * 60fps -> 1
              * 10fps -> 10 
              * 
              * for a linear relationship, we can use the equation:
              * n = mf + b, where n = numNewSegmentsPerFrame and f = FPS
              * solving for m and b, we have:
              * n = (-0.18)f + 11.8
              */

                var numNewSegmentsPerFrame = Math.round(-0.18 * anim.getFps() + 11.8);

                for (var n = 0; n < numNewSegmentsPerFrame; n++) {
                    // create first angle if no angles
                    if (angles.length == 0) {
                        microbe.headX = canvas.width / 2;
                        microbe.headY = canvas.height / 2;
                        angles.push(getRandTheta());
                    }

                    var headX = microbe.headX;
                    var headY = microbe.headY;
                    var headAngle = angles[angles.length - 1];

                    // create new head angle
                    var dist = anim.getTimeInterval() / (10 * numNewSegmentsPerFrame);
                    // increase new head angle by an amount equal to
                    // -0.1 to 0.1
                    var newHeadAngle = headAngle + ((angleVariance / 2) - Math.random() * angleVariance);
                    var newHeadX = headX + dist * Math.cos(newHeadAngle);
                    var newHeadY = headY + dist * Math.sin(newHeadAngle);

                    // change direction if collision occurs
                    if (newHeadX >= canvas.width || newHeadX <= 0 || newHeadY >= canvas.height || newHeadY <= 0) {
                        newHeadAngle += Math.PI / 2;
                        newHeadX = headX + dist * Math.cos(newHeadAngle);
                        newHeadY = headY + dist * Math.sin(newHeadAngle);
                    }

                    microbe.headX = newHeadX;
                    microbe.headY = newHeadY;
                    angles.push(newHeadAngle);

                    // remove tail angle
                    if (angles.length > 20) {
                        angles.shift();
                    }
                }
            }
        }
```

1.  定义`drawMicrobes()`函数，绘制所有的微生物：

```js
        function drawMicrobes(anim, microbes){
            var segmentLength = 2; // px
            var context = anim.getContext();

            for (var i = 0; i < microbes.length; i++) {
                var microbe = microbes[i];

                var angles = microbe.angles;
                context.beginPath();
                context.moveTo(microbe.headX, microbe.headY);

                var x = microbe.headX;
                var y = microbe.headY;

                // start with the head and end with the tail
                for (var n = angles.length - 1; n >= 0; n--) {
                    var angle = angles[n];

                    x -= segmentLength * Math.cos(angle);
                    y -= segmentLength * Math.sin(angle);
                    context.lineTo(x, y);
                }

                context.lineWidth = 10;
                context.lineCap = "round";
                context.lineJoin = "round";
                context.strokeStyle = microbe.color;
                context.stroke();
            }
        }
```

1.  实例化一个`Animation`对象并获取画布上下文：

```js
        window.onload = function(){
            var anim = new Animation("myCanvas");
            var canvas = anim.getCanvas();
            var context = anim.getContext();
```

1.  初始化 1,500 个微生物：

```js
            // init microbes
            var microbes = [];
            for (var n = 0; n < 1500; n++) {
                // each microbe will be an array of angles
                microbes[n] = {
                    headX: 0,
                    headY: 0,
                    angles: [],
                    color: getRandColor()
                };
            }
```

1.  设置`stage()`函数，该函数更新微生物，每 10 帧更新一次 FPS 值，清除画布，然后绘制微生物和 FPS 值：

```js
            var fps = 0;

            anim.setStage(function(){
                // update
                updateMicrobes(this, microbes);

                if (anim.getFrame() % 10 == 0) {
                    fps = anim.getFps();
                }

                // clear
                this.clear();

                // draw
                drawMicrobes(this, microbes);
                drawFps(this, fps);
            });
```

1.  开始动画：

```js
            anim.start();
        };
    </script>
</head>
```

1.  将画布嵌入到 HTML 文档的主体中：

```js
<body>
    <canvas id="myCanvas" width="600" height="250" style="border:1px solid black;">
    </canvas>
</body>

```

## 它是如何工作的...

为了绘制动画的 FPS，我们可以创建`drawFps()`函数，该函数以 FPS 值作为输入，绘制画布右上角的黑色框，然后写出 FPS 值。为了避免过于频繁地更新 FPS，我们可以将 FPS 值的副本存储在变量`FPS`中，并在每 10 帧更新一次。这样，FPS 最多每秒更新 6 次。

为了强调画布，我们可以简单地初始化更多的微生物。在这个示例中，我们初始化了 1,500 个微生物。如果你自己尝试这段代码，你可以尝试不同的数字，看看 FPS 如何受到影响。

## 还有更多...

如前所述，典型的动画应该以大约 40 到 60 FPS 运行。如果 FPS 低于 30，你会开始注意到动画有轻微的延迟。在 32 位 Windows 7 机器上使用 Google Chrome 进行测试，配备 2.2 GHz AMD 处理器和 2 GB RAM（是的，我知道，我需要升级），当我在动画 1,500 个微生物时，我看到大约 5 FPS。看起来不错，但也不是很好。当动画 2,000 个或更多的微生物时，动画开始看起来不可接受地卡顿。

我们使用 2D 上下文创建的几乎所有动画在台式机和笔记本电脑上表现良好。然而，如果您发现自己处于一个情况，您的动画在 2D 上下文中的计算开销足够大，以至于表现不佳，您可能会考虑改用 WebGL（我们将在第九章中介绍 WebGL，*WebGL 简介*）。与 2D 上下文不同，WebGL 利用硬件加速。在撰写本文时，所有主要浏览器中的 2D 上下文都不利用硬件加速。然而，使用 WebGL 确实会带来成本，因为开发和维护 WebGL 动画要比创建 2D 上下文动画困难得多。

## 另请参阅...

+   在第一章中处理文本

+   在第一章中绘制螺旋线

+   在第六章中创建绘图应用程序
