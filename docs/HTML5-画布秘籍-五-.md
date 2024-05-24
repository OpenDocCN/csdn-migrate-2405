# HTML5 画布秘籍（五）

> 原文：[`zh.annas-archive.org/md5/5BECA7AD01229D44A883D4EFCAD8E67B`](https://zh.annas-archive.org/md5/5BECA7AD01229D44A883D4EFCAD8E67B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 附录 A. 检测 Canvas 支持

# Canvas 回退内容

由于所有浏览器都不支持 canvas，因此最好提供回退内容，以便用户知道如果他们选择的浏览器不支持 canvas，则某些功能无法正常工作。处理不支持 canvas 的浏览器最简单和最直接的技术是在 canvas 标签内添加回退内容。通常，这个内容将是文本或图像，告诉用户他们过时的浏览器不支持 canvas，并建议下载一个在本年代开发的浏览器。使用支持 canvas 的浏览器的用户将看不到内部内容：

```js
<canvas id="myCanvas" width="578" height="250">
            Yikes!  Your browser doesn't support canvas.  Try using 
Google Chrome or Firefox instead.
</canvas>
```

Canvas 回退内容并不总是最好的解决方案。例如，如果浏览器不支持 canvas，您可能希望警告错误消息，将用户重定向到不同的 URL，甚至使用应用程序的 Flash 版本作为回退。检测浏览器是否支持 canvas 的最简单方法是创建一个虚拟 canvas 元素，然后检查我们是否可以执行 getContext 方法：

```js
function isCanvasSupported(){
            return !!document.createElement('canvas').getContext;
        }
```

当页面加载时，我们可以调用 isCanvasSupported()函数来确定浏览器是否支持 canvas，然后适当处理结果。

这个函数使用了我最喜欢的 JavaScript 技巧之一，双非技巧（!!），它确定了 getContext 方法是否成功执行。双非的第一个非将数据类型强制转换为布尔值。由于强制转换数据类型的行为产生了我们不想要的相反结果，我们可以添加第二个非（!!）来翻转结果。双非技巧是检查一段代码是否成功执行的一种非常方便的方式，在我看来，它比用 try/catch 块包装一行代码要优雅得多。

## 检测可用的 WebGL 上下文

如果您的 canvas 应用程序利用了 WebGL，您可能还想知道浏览器支持哪些上下文，以便您可以成功初始化一个 WebGL 应用程序。

在撰写本文时，有五个主要的上下文：

+   2D

+   webgl

+   实验性的 WebGL

+   moz-webgl

+   webkit-3d

包括 Google Chrome，Firefox，Safari，Opera 和 IE9 在内的所有主要浏览器都支持 2D 上下文。然而，当涉及到 WebGL 支持时，情况完全不同。在撰写本文时，Google Chrome 和 Safari 支持实验性的 WebGL 和 webkit-3d 上下文，Firefox 支持实验性的 WebGL 和 moz-webgl 上下文，IE9 不支持任何形式的 WebGL。

要自己看到这一点，您可以创建一个名为 getCanvasSupport()的函数，该函数循环遍历所有可能的上下文，并使用双非技巧来确定哪些上下文是可用的：

```js
function getCanvasSupport(){
    // initialize return object
    var returnObj = {
        canvas: false,
        webgl: false,
        context_2d: false,
        context_webgl: false,
        context_experimental_webgl: false,
        context_moz_webgl: false,
        context_webkit_3d: false
    };
    // check if canvas is supported
    if (!!document.createElement('canvas').getContext) {
        returnObj.canvas = true;
    }

    // check if WebGL rendering context is supported
    if (window.WebGLRenderingContext) {
        returnObj.webgl = true;
    }

    // check specific contexts
    var contextMapping = {
        context_2d: "2d",
        context_webgl: "webgl",
        context_experimental_webgl: "experimental-webgl",
        context_moz_webgl: "moz-webgl",
        context_webkit_3d: "webkit-3d"
    };

    for (var key in contextMapping) {
        try {
            if (!!document.createElement('canvas').getContext(contextMapping[key])) {
                returnObj[key] = true;
            }
        } 
        catch (e) {
        }
    }

    return returnObj;
}

function showSupport(obj){
    var str = "";

    str += "-- General Support --<br>";
    str += "canvas: " + (obj.canvas ? "YES" : "NO") + "<br>";
    str += "webgl: " + (obj.webgl ? "YES" : "NO") + "<br>";

    str += "<br>-- Successfully Initialized Contexts --<br>";
    str += "2d: " + (obj.context_2d ? "YES" : "NO") + "<br>";
    str += "webgl: " + (obj.context_webgl ? "YES" : "NO") + "<br>";
    str += "experimental-webgl: " + (obj.context_experimental_webgl ? "YES" : "NO") + "<br>";
    str += "moz-webgl: " + (obj.context_moz_webgl ? "YES" : "NO") + "<br>";
    str += "webkit-3d: " + (obj.context_webkit_3d ? "YES" : "NO") + "<br>";

    document.write(str);
}

window.onload = function(){
    showSupport(getCanvasSupport());
};
```


# 附录 B. 画布安全

为了保护网站上图像、视频和画布的像素数据，HTML5 画布规范中有防护措施，防止其他域的脚本访问这些媒体，操纵它们，然后创建新的图像、视频或画布。

在画布上绘制任何内容之前，画布标签的 origin-clean 标志设置为 true。这基本上意味着画布是“干净的”。如果您在托管代码运行的同一域上的画布上绘制图像，则 origin-clean 标志保持为 true。但是，如果您在托管在另一个域上的画布上绘制图像，则 origin-clean 标志将设置为 false，画布现在是“脏的”。

根据 HTML5 画布规范，一旦发生以下任何操作，画布就被视为脏：

+   - 调用元素的 2D 上下文的`drawImage()`方法时，使用的`HTMLImageElement`或`HTMLVideoElement`的原点与拥有画布元素的文档对象不同。

+   - 调用元素的 2D 上下文的`drawImage()`方法时，使用的`HTMLCanvasElement`的 origin-clean 标志为 false。

+   - 元素的 2D 上下文的`fillStyle`属性设置为从`HTMLImageElement`或`HTMLVideoElement`创建的`CanvasPattern`对象，当时该模式的原点与拥有画布元素的文档对象不同。

+   - 元素的 2D 上下文的`fillStyle`属性设置为从`HTMLCanvasElement`创建的`CanvasPattern`对象，当时该模式的 origin-clean 标志为 false。

+   元素的 2D 上下文的`strokeStyle`属性设置为从`HTMLImageElement`或`HTMLVideoElement`创建的`CanvasPattern`对象，当时该模式的原点与拥有画布元素的文档对象不同。

+   - 元素的 2D 上下文的`strokeStyle`属性设置为从`HTMLCanvasElement`创建的`CanvasPattern`对象，当时该模式的 origin-clean 标志为 false。

+   - 调用元素的 2D 上下文的`fillText()`或`strokeText()`方法，并考虑使用原点与拥有画布元素的文档对象不同的字体。（甚至不必使用字体；重要的是字体是否被用于绘制任何字形。）

- 此外，如果您在本地计算机上执行以下任何操作（而不是在 Web 服务器上），则 origin-clean 标志将自动设置为 false，因为资源将被视为来自不同的来源。

接下来，根据规范，如果在脏画布上发生以下任何操作，将抛出`SECURITY_ERR`异常：

+   - 调用`toDataURL()`方法

+   - 调用`getImageData()`方法

+   - 使用`measureText()`方法时，使用的字体的原点与文档对象不同

尽管画布安全规范是出于良好意图创建的，但它可能会给我们带来更多麻烦。举个例子，假设您想创建一个绘图应用程序，该应用程序可以连接到 Flickr API，从公共域中获取图像以添加到您的绘图中。如果您希望您的应用程序能够使用`toDataURL()`方法将该绘图保存为图像，或者如果您希望您的应用程序使用`getImageData()`方法具有复杂的像素操作算法，那么您将遇到一些麻烦。在脏画布上执行这些操作将抛出 JavaScript 错误，并阻止您的应用程序正常工作。

解决这个问题的一种方法是创建一个代理，从另一个域获取图像，然后传递回客户端，使其看起来像图像来自您的域。如果您曾经使用过跨域 AJAX 应用程序，您会感到非常熟悉。


# 附录 C. 其他主题

# 画布与 CSS3 过渡和动画

除了画布之外，HTML5 规范还引入了两个令人兴奋的 CSS3 规范补充——**过渡**和**动画**。

过渡使开发人员能够创建简单的动画，可以在一定时间内改变 DOM 元素的样式。例如，如果你鼠标悬停在一个按钮上，希望它在一秒钟内逐渐变淡到不同的颜色，你可以使用 CSS3 过渡。

动画使开发人员能够通过定义指定的关键帧来创建更复杂的动画，这些关键帧可以被视为一系列链接的过渡。例如，如果你想通过移动`DIV`元素来创建动画，先向上移动，然后向左移动，然后向下移动，最后回到原来的位置，你可以使用 CSS3 动画，并为路径上的每个点定义一个关键帧。

所以，这就是人们困惑的地方。什么时候应该使用画布，什么时候应该使用 CSS3 来进行动画？如果你是一位经验丰富的开发人员，我相信你知道正确的答案是“这取决于情况”。作为一个经验法则，如果你要对 DOM 节点进行动画，或者动画简单且定义明确，最好使用 CSS3 过渡和动画。另一方面，如果你要对更复杂的东西进行动画，比如物理模拟器或在线游戏，那么使用画布可能更合适。

# 移动设备上的画布性能

随着移动和平板市场继续侵蚀传统的台式机和笔记本市场，重要的是要关注画布在移动空间中的作用。在撰写本文时，几乎所有移动设备上的画布动画性能都非常差，因为它们的 CPU 性能不足以处理。平板通常有更好的性能。不过也有好消息。除了软件改进和更强大的 CPU 外，移动设备和平板正在努力更好地利用硬件加速，帮助动画更流畅地运行。如果你考虑构建一个图形密集型的 Web 应用程序，大量使用画布动画，确保在移动设备上运行良好，那么最好事先做一些研究。
