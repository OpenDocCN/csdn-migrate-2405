# HTML5 Web 应用开发示例（四）

> 原文：[`zh.annas-archive.org/md5/F338796025D212EF3B95DC40480B4CAD`](https://zh.annas-archive.org/md5/F338796025D212EF3B95DC40480B4CAD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：Web Workers Unite

> "如果你想要有创造力的工作者，就给他们足够的玩耍时间。"

*—约翰·克里斯*

*在本章中，我们将学习如何使用 HTML5 web worker 在另一个线程中运行后台进程。我们可以使用这个功能使具有长时间运行进程的应用程序更具响应性。我们将使用 web worker 在画布上绘制 Mandelbrot 分形，以异步方式生成它，而不会锁定浏览器窗口。*

在本章中，我们将学习以下主题：

+   通过使用 web workers 使 web 应用程序更具响应性的方法

+   如何启动和管理 web worker

+   如何与 web worker 通信并来回发送数据

+   如何使用 web worker 在画布上绘制 Mandelbrot 分形

+   调试 web workers 的技巧

# Web workers

Web workers 提供了一种在 Web 应用程序的主线程之外的后台线程中运行 JavaScript 代码的方式。尽管由于其异步性质，JavaScript 可能看起来是多线程的，但事实上只有一个线程。如果你用一个长时间运行的进程来占用这个线程，网页将变得无响应，直到进程完成。

过去，您可以通过将长时间运行的进程分成块来缓解这个问题，以便一次处理一点工作。在每个块之后，您将调用`setTimeout()`，将超时值设为零。当您调用`setTimeout()`时，实际上会在指定的时间后将事件放入事件队列。这允许队列中已经存在的其他事件有机会被处理，直到您的计时器事件到达队列的最前面。

如果您以前使用过线程，您可能会意识到很容易遇到并发问题。一个线程可能正在处理与另一个线程相同的数据，这可能导致数据损坏，甚至更糟糕的是死锁。幸运的是，web worker 不会给我们太多机会遇到并发问题。web worker 不允许访问非线程安全的组件，如 DOM。它们也无法访问`window`、`document`或`parent`对象。

然而，这种线程安全是有代价的。由于 web worker 无法访问 DOM，它无法执行任何操作来操作页面元素。它也无法直接操作主线程的任何数据结构。此时你可能会想，如果 web worker 无法访问任何东西，那它有什么用呢？

好吧，web worker 无法访问主线程中的数据，但它们可以通过消息来回传递数据。然而，需要记住的关键一点是，传递给 web worker 的任何数据在发送之前都会被序列化，然后在另一端进行反序列化，以便它在副本上工作，而不是原始数据。然后，web worker 可以对数据进行一些处理，并再次使用序列化将其发送回主线程。只需记住，传递大型数据结构会有一些开销，因此您可能仍然希望将数据分块并以较小的批次进行处理。

### 注意

一些浏览器确实支持在不复制的情况下传输对象，这对于大型数据结构非常有用。目前只有少数浏览器支持这一功能，所以我们在这里不会涉及。

## 生成 web worker

web worker 的代码在其自己的 JavaScript 文件中定义，与主应用程序分开。主线程通过创建一个新的`Worker`对象并给它文件路径来生成一个 web worker：

```html
var myWorker = new Worker("myWorker.js");
```

应用程序和 worker 通过发送消息进行通信。要接收消息，我们使用`addEventListener()`为 worker 添加消息事件处理程序：

```html
myWorker.addEventListener("message", function (event) {
  alert("Message from worker: " + event.data);
}, false);
```

一个`event`对象作为参数传递给事件处理程序。它有一个`data`字段，其中包含从 worker 传回的任何数据。`data`字段可以是任何可以用 JSON 表示的东西，包括字符串、数字、数据对象和数组。

创建 Worker 后，可以使用`postMessage()`方法向其发送消息。它接受一个可选参数，即要发送给 Worker 的数据。在这个例子中，它只是一个字符串：

```html
myWorker.postMessage("start");
```

## 实现 Web Worker

如前所述，Web Worker 的代码在单独的文件中指定。在 Worker 内部，您还可以添加一个事件监听器，以接收来自应用程序的消息：

```html
self.addEventListener("message", function (event) {
  // Handle message
}, false);
```

在 Worker 内部，有一个`self`关键字，它引用 Worker 的全局范围。使用`self`关键字是可选的，就像使用`window`对象一样（所有全局变量和函数都附加到`window`对象）。我们在这里使用它只是为了显示上下文。

Worker 可以使用`postMessage()`向主线程发送消息。它的工作方式与主线程完全相同：

```html
self.postMessage("started");
```

当 Worker 完成后，可以调用`close()`方法来终止 Worker。关闭后，Worker 将不再可用：

```html
self.close();
```

您还可以使用`importScripts()`方法将其他外部 JavaScript 文件导入 Worker。它接受一个或多个脚本文件的路径：

```html
importScripts("script1.js", "script2.js");
```

这对于在主线程和 Web Worker 中使用相同的代码库非常有效。

# 行动时间 - 使用 Web Worker

让我们创建一个非常简单的应用程序，获取用户的名称并将其传递给 Web Worker。Web Worker 将向应用程序返回一个“hello”消息。此部分的代码可以在`Chapter 9/example9.1`中找到。

### 注意

在某些浏览器中，Web Worker 不起作用，除非您通过 IIS 或 Apache 等 Web 服务器运行它们。

首先，我们创建一个包含`webWorkerApp.html`、`webWorkerApp.css`和`webWorkerApp.js`文件的应用程序。我们在 HTML 中添加一个文本输入字段，询问用户的名称，并添加一个响应部分，用于显示来自 Worker 的消息：

```html
<div id="main">
    <div>
        <label for="your-name">Please enter your name: </label>
        <input type="text" id="your-name"/>
        <button id="submit">Submit</button>
    </div>
    <div id="response" class="hidden">
        The web worker says: <span></span>
    </div>
</div>
```

在`webWorkerApp.js`中，当用户点击提交按钮时，我们调用`executeWorker()`方法：

```html
function executeWorker()
{
    var name = $("#your-name").val();
    var worker = new Worker("helloWorker.js");
    worker.addEventListener("message", function(event) {
        $("#response").fadeIn()
            .children("span").text(event.data);
    });
    worker.postMessage(name);
}
```

首先我们获取用户在文本字段中输入的名称。然后我们创建一个在`helloWorker.js`中定义了其代码的新的`Worker`。我们添加一个消息事件监听器，从 Worker 那里获取消息并将其放入页面的响应部分。最后，我们使用`postMessage()`将用户的名称发送给 Worker 以启动它。

现在让我们在`helloWorker.js`中创建我们的 Web Worker 的代码。在那里，我们添加了从主线程获取消息并发送消息的代码：

```html
self.addEventListener("message", function(event) {
    sayHello(event.data);
});
function sayHello(name)
{
    self.postMessage("Hello, " + name);
}
```

首先，我们添加一个事件监听器来获取应用程序的消息。我们从`event.data`字段中提取名称，并将其传递给`sayHello()`函数。`sayHello()`函数只是在用户的名称前面加上“Hello”，然后使用`postMessage()`将消息发送回应用程序。在主应用程序中，它获取消息并在页面上显示它。

## *刚刚发生了什么？*

我们创建了一个简单的应用程序，获取用户的名称并将其传递给 Web Worker。Web Worker 将消息发送回应用程序，在页面上显示 - 这就是使用 Web Worker 的简单方法。

# Mandelbrot 集

演示如何使用 Web Worker 来进行一些真正的处理，我们将创建一个绘制 Mandelbrot 分形的应用程序。绘制 Mandelbrot 需要相当多的处理能力。如果不在单独的线程中运行，应用程序在绘制时会变得无响应。

绘制 Mandelbrot 是一个相对简单的过程。我们将使用**逃逸时间算法**。对于图像中的每个像素，我们将确定达到临界逃逸条件需要多少次迭代。迭代次数决定像素的颜色。如果我们在最大迭代次数内未达到逃逸条件，则被视为在 Mandelbrot 集内，并将其涂黑。

有关此算法和 Mandelbrot 集的更多信息，请参阅维基百科页面：

[`en.wikipedia.org/wiki/Mandelbrot_set`](http://en.wikipedia.org/wiki/Mandelbrot_set)

# 行动时间-实施算法

让我们在一个名为`mandelbrotGenerator.js`的新文件中创建一个`MandelbrotGenerator`对象。这个对象将实现生成 Mandelbrot 的算法。构造函数接受画布的宽度和高度，以及 Mandelbrot 的边界：

```html
function MandelbrotGenerator(canvasWidth, canvasHeight, left, top,right, bottom)
    {
```

接下来我们定义算法使用的变量：

```html
    var scalarX = (right - left) / canvasWidth,
        scalarY = (bottom - top) / canvasHeight,
        maxIterations = 1000,
        abort = false,
        inSetColor = { r: 0x00, g: 0x00, b: 0x00 },
        colors = [ /* array of color objects */ ];
```

`scalarX`和`scalarY`变量用于将 Mandelbrot 坐标转换为画布坐标。它们是通过将 Mandelbrot 的宽度或高度除以画布的宽度或高度来计算的。例如，虽然画布可能设置为 640x480 像素，但 Mandelbrot 的边界可能是左上角(-2，-2)和右下角(2，2)。在这种情况下，Mandelbrot 的高度和宽度都是 4：

![行动时间-实施算法](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_09_01.jpg)

接下来，我们将算法的最大迭代次数设置为 1000。如果您将其设置得更高，您将获得更好的结果，但计算时间将更长。使用 1000 提供了处理时间和可接受结果之间的良好折衷。`abort`变量用于停止算法。`inSetColor`变量控制 Mandelbrot 集中的像素的颜色。我们将其设置为黑色。最后，有一个颜色数组，用于给不在集合中的像素上色。

让我们首先编写这些方法，将画布坐标转换为 Mandelbrot 坐标。它们只是将位置乘以标量，然后加上顶部或左侧的偏移量：

```html
function getMandelbrotX(x)
{
    return scalarX * x + left;
}
function getMandelbrotY(y)
{
    return scalarY * y + top;
}
```

现在让我们在一个名为`draw()`的公共方法中定义算法的主循环。它以要绘制的画布上的图像数据作为参数：

```html
this.draw = function(imageData)
{
    abort = false;

    for (var y = 0; y < canvasHeight; y++)
    {
        var my = getMandelbrotY(y);
        for (var x = 0; x < canvasWidth; x++)
        {
            if (abort) return;
            var mx = getMandelbrotX(x);
            var iteration = getIteration(mx, my);
            var color = getColor(iteration);
            setPixel(imageData, x, y, color);
        }
    }
};
```

在外部循环中，我们遍历画布中所有行的像素。在这个循环内，我们调用`getMandelbrotY()`，传入画布的 y 位置，并返回 Mandelbrot 中相应的 y 位置。

接下来，我们遍历行中的所有像素。对于每个像素，我们：

1.  调用`getMandelbrotX()`，传入画布的 x 位置，并返回 Mandelbrot 中相应的 x 位置。

1.  调用`getIterations()`，传入 Mandelbrot 的 x 和 y 位置。这个方法将找到达到逃逸条件所需的迭代次数。

1.  调用`getColor()`，传入迭代次数。这个方法获取迭代次数的颜色。

1.  最后，我们调用`setPixel()`，传入图像数据、x 和 y 位置以及颜色。

接下来让我们实现`getIterations()`方法。这是我们确定像素是否在 Mandelbrot 集合内的地方。它以 Mandelbrot 的 x 和 y 位置作为参数：

```html
function getIterations(x0, y0)
{
    var x = 0,
        y = 0,
        iteration = 0;
    do
    {
        iteration++;
        if (iteration >= maxIterations) return -1;
        var xtemp = x * x - y * y + x0;
        y = 2 * x * y + y0;
        x = xtemp;
    }
    while (x * x + y * y < 4);

    return iteration;
}
```

首先，我们将工作的`x`和`y`位置初始化为零，`iteration`计数器初始化为零。接下来，我们开始一个`do-while`循环。在循环内，我们递增`iteration`计数器，如果它大于`maxIterations`，我们返回`-1`。这表示逃逸条件未满足，该点在 Mandelbrot 集合内。

然后我们计算用于检查逃逸条件的 x 和 y 变量。然后我们检查条件，以确定是否继续循环。一旦满足逃逸条件，我们返回找到它所需的迭代次数。

现在我们将编写`getColor()`方法。它以迭代次数作为参数：

```html
function getColor(iteration)
{
    if (iteration < 0) return inSetColor;
    return colors[iteration % colors.length];
}
```

如果`iteration`参数小于零，这意味着它在 Mandelbrot 集合中，我们返回`inSetColor`对象。否则，我们使用模运算符在颜色数组中查找颜色对象，以限制迭代次数的长度。

最后，我们将编写`setPixel()`方法。它接受图像数据、画布 x 和 y 位置以及颜色：

```html
function setPixel(imageData, x, y, color)
{
    var d = imageData.data;
    var index = 4 * (canvasWidth * y + x);
    d[index] = color.r;
    d[index + 1] = color.g;
    d[index + 2] = color.b;
    d[index + 3] = 255; // opacity
}
```

这应该看起来非常熟悉，就像第五章中的内容，我们学习了如何操作图像数据。首先，我们找到图像数据数组中的像素的索引。然后，我们从`color`对象中设置每个颜色通道，并将不透明度设置为`255`的最大值。

## *刚刚发生了什么？*

我们实现了绘制 Mandelbrot 到画布图像数据的算法。每个像素要么设置为黑色，要么根据找到逃逸条件所需的迭代次数设置为某种颜色。

# 创建 Mandelbrot 应用程序

现在我们已经实现了算法，让我们创建一个应用程序来使用它在页面上绘制 Mandelbrot。我们将首先在没有 Web Worker 的情况下进行绘制，以展示这个过程如何使网页无响应。然后我们将使用 Web Worker 在后台绘制 Mandelbrot，以查看差异。

# 行动时间-创建 Mandelbrot 应用程序

让我们从创建一个新的应用程序开始，其中包括`mandelbrot.html`、`mandelbrot.css`和`mandelbrot.js`文件。我们还包括了之前为应用程序创建的`mandelbrotGenerator.js`。您可以在`第九章/example9.2`中找到本节的代码。

在 HTML 文件中，我们向 HTML 添加了一个`<canvas>`元素来绘制 Mandelbrot，并将大小设置为 640x480：

```html
<canvas width="640" height="480"></canvas>
```

我们还添加了三个按钮，其中预设的 Mandelbrot 边界以 JSON 格式定义为`data-settings`自定义数据属性中的数组：

```html
<button class="draw"
    data-settings="[-2, -2, 2, 2]">Draw Full</button>
<button class="draw"
    data-settings="[-0.225, -0.816, -0.197, -0.788]">Preset 1
</button>
<button class="draw"
    data-settings="[-1.18788, -0.304, -1.18728, -0.302]">Preset 2
</button>
```

现在让我们进入 JavaScript 文件，并添加调用 Mandelbrot 生成器的代码。在这里，我们定义变量来保存对画布及其上下文的引用：

```html
function MandelbrotApp()
{
    var version = "9.2",
        canvas = $("canvas")[0],
        context = canvas.getContext("2d");
```

接下来，我们添加一个`drawMandelbrot()`方法，当其中一个按钮被点击时将被调用。它以 Mandelbrot 的边界作为参数进行绘制：

```html
function drawMandelbrot(left, top, right, bottom)
{
    setStatus("Drawing...");
    var imageData =
        context.getImageData(0, 0, canvas.width, canvas.height);
    var generator = new MandelbrotGenerator(canvas.width, canvas.height, 
        left, top, right, bottom);
    generator.draw(imageData);
    context.putImageData(imageData, 0, 0)
    setStatus("Finished.");
}
```

首先，我们在状态栏中显示**绘制中...**的状态。然后，我们获取整个画布的图像数据。接下来，我们创建`MandelbrotGenerator`对象的一个新实例，传入画布和边界设置。然后我们调用它的`draw()`方法，传入图像数据。当它完成时，我们将图像数据绘制回画布，并将状态设置为**完成**。

我们需要做的最后一件事是更新应用程序的`start()`方法：

```html
this.start = function()
{
    $("#app header").append(version);

    $("button.draw").click(function() {
        var data = $(this).data("settings");
        drawMandelbrot(data[0], data[1], data[2], data[3]);
    });

    setStatus("ready");
};
```

在这里，我们为所有按钮添加了一个点击事件处理程序。当点击按钮时，我们获取`settings`自定义数据属性（一个数组），并将值传递给`drawMandelbrot()`进行绘制。

就是这样-让我们在浏览器中打开并查看一下。根据您使用的浏览器（有些比其他浏览器快得多）和您系统的速度，Mandelbrot 应该需要足够长的时间来绘制，以至于您会注意到页面已经变得无响应。如果您尝试点击其他按钮，将不会发生任何事情。还要注意，尽管我们调用了`setStatus("Drawing...")`，但您从未看到状态实际上发生变化。这是因为绘图算法在运行时有机会更新页面上的文本之前就接管了控制权：

![开始行动-创建 Mandelbrot 应用程序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_09_02.jpg)

## *刚刚发生了什么？*

我们创建了一个应用程序来绘制 Mandelbrot 集，使用了我们在上一节中创建的绘图算法。它还没有使用 Web Worker，因此在绘制时页面会变得无响应。

# 行动时间-使用 Web Worker 的 Mandelbrot

现在我们将实现相同的功能，只是这次我们将使用 Web Worker 来将处理转移到另一个线程。这将释放主线程来处理页面更新和用户交互。您可以在`第九章/example9.3`中找到本节的源代码。

让我们进入 HTML 并添加一个复选框，我们可以选择是否使用 Web Worker。这将使在浏览器中比较结果更容易：

```html
<input type="checkbox" id="use-worker" checked />
<label for="use-worker">Use web worker</label>
```

我们还将添加一个停止按钮。以前没有 Web Worker 的情况下无法停止，因为 UI 被锁定，但现在我们将能够实现它：

```html
<button id="stop">Stop Drawing</button>
```

现在让我们继续在一个名为`mandelbrotWorker.js`的新文件中创建我们的 Web Worker。我们的 worker 需要使用`MandelbrotGenerator`对象，因此我们将该脚本导入 worker：

```html
importScripts("mandelbrotGenerator.js");
```

现在让我们为 worker 定义消息事件处理程序。在接收到包含绘制 Mandelbrot 所需数据的消息时，worker 将开始生成它：

```html
self.addEventListener("message", function(e)
{
    var data = e.data;
    var generator = new MandelbrotGenerator(data.width, data.height,
        data.left, data.top, data.right, data.bottom);
    generator.draw(data.imageData);
    self.postMessage(data.imageData);
    self.close();
});
```

首先，我们创建`MandelbrotGenerator`的一个新实例，传入我们从主应用程序线程获取的值，包括画布的宽度和高度以及 Mandelbrot 边界。然后，我们调用生成器的`draw()`方法，传入消息中也包含的图像数据。生成器完成后，我们通过调用`postMessage()`将包含绘制 Mandelbrot 的图像数据传递回主线程。最后，我们调用`close()`来终止 worker。

至此，worker 就完成了。让我们回到我们的主应用程序对象`MandelbrotApp`，并添加代码，以便在单击按钮时启动 Web Worker。

在`mandelbrot.js`中，我们需要向应用程序对象添加一个名为 worker 的全局变量，该变量将保存对 Web Worker 的引用。然后，我们重写`drawMandelbrot()`以添加一些新代码来启动 worker：

```html
function drawMandelbrot(left, top, right, bottom)
{
    if (worker) return;

    context.clearRect(0, 0, canvas.width, canvas.height);
    setStatus("Drawing...");

    var useWorker = $("#use-worker").is(":checked");
    if (useWorker)
    {
        startWorker(left, top, right, bottom);
    }
    else
    {
        /* Draw without worker */
    }
}
```

首先，我们检查`worker`变量是否已设置。如果是，则 worker 已经在运行，无需继续。然后我们清除画布并设置状态。接下来，我们检查**使用 worker**复选框是否被选中。如果是，我们调用`startWorker()`，传入 Mandelbrot 边界参数。`startWorker()`方法是我们创建 Web Worker 并启动它的地方：

```html
function startWorker(left, top, right, bottom)
{
    worker = new Worker("mandelbrotWorker.js");
    worker.addEventListener("message", function(e)
    {
        context.putImageData(e.data, 0, 0)
        worker = null;
        setStatus("Finished.");
    );

    var imageData =
        context.getImageData(0, 0, canvas.width, canvas.height);
    worker.postMessage({
        imageData: imageData,
        width: canvas.width,
        height: canvas.height,
        left: left,
        top: top,
        right: right,
        bottom: bottom
    });
}
```

首先，我们创建一个新的`Worker`，将`mandelbrotWorker.js`的路径传递给它。然后，我们向 worker 添加一个消息事件处理程序，当 worker 完成时将调用该处理程序。它获取从 worker 返回的图像数据并将其绘制到画布上。

接下来我们启动 worker。首先，我们从画布的上下文中获取图像数据。然后，我们将图像数据、画布的宽度和高度以及 Mandelbrot 边界放入一个对象中，通过调用`postMessage()`将其传递给 worker。

还有一件事要做。我们需要实现停止按钮。让我们编写一个`stopWorker()`方法，当单击停止按钮时将调用该方法：

```html
function stopWorker()
{
    if (worker)
    {
        worker.terminate();
        worker = null;
        setStatus("Stopped.");
    }
}
```

首先，我们通过检查`worker`变量是否已设置来检查 worker 是否正在运行。如果是，我们调用 worker 的`terminate()`方法来停止 worker。调用`terminate()`相当于在 worker 内部调用`self.close()`。

## *刚刚发生了什么?*

我们实现了一个可以从后台线程绘制 Mandelbrot 的 Web Worker。这使用户可以在 Mandelbrot 绘制时继续与页面交互。我们通过添加一个停止按钮来演示这一点，该按钮可以停止绘制过程。您还会注意到，在绘制分形时，**正在绘制...**状态消息现在会显示出来。

## 试试看

我们 Mandelbrot 应用程序的一个问题是，我们正在序列化和传输整个画布的图像数据到 Web Worker，然后再传回。在我们的示例中，这是 640 * 480 * 4 字节，或 1,228,800 字节。那是 1.2 GB！看看您是否能想出一种将 Mandelbrot 的绘制分成更小块的方法。如果您想看看我是如何做到的，请查看`第九章/示例 9.4`。

# 调试 Web Worker

调试 Web Worker 可能很困难。您无法访问`window`对象，因此无法调用`alert()`来显示消息，也无法使用`console.log()`来写入浏览器的 JavaScript 控制台。您也无法向 DOM 写入消息。甚至无法附加调试器并逐步执行代码。那么，一个可怜的开发人员该怎么办呢？

您可以为 worker 添加错误监听器，以便在 worker 线程内发生任何错误时收到通知：

```html
worker.addEventListener("error", function(e)
{
    alert("Error in worker: " + e.filename + ", line:" + e.lineno + ", " + e.message);
});
```

错误处理程序传入的事件对象包含`filename`、`lineno`和`message`字段。通过这些字段，您可以准确地知道错误发生的位置。

但是，如果你没有收到错误，事情只是不正常工作呢？首先，我建议你将所有处理工作的代码放在一个单独的文件中，就像我们在`mandelbrotGenerator.js`中所做的那样。这样可以让你从主线程以及工作者中运行代码。如果需要调试，你可以直接从应用程序运行它，并像平常一样进行调试。

您可以使用的一个调试技巧是在 Web 工作者中定义一个`console`对象，将消息发送回主线程，然后可以使用窗口的控制台记录它们：

```html
var console = {
    log: function(msg)
    {
        self.postMessage({
            type: "log",
            message: msg
        });
    }
};
```

然后在你的应用程序中，监听消息并记录它：

```html
worker.addEventListener("message", function(e)
{
    if (e.data.type == "log")
    {
        console.log(e.data.message);
    }
});
```

## 小测验

Q1. 如何向 Web 工作者发送数据？

1.  你不能向工作线程发送数据。

1.  使用`postMessage()`方法。

1.  使用`sendData()`方法。

1.  使用`sendMessage()`方法。

Q2. Web 工作者在主线程中可以访问哪些资源？

1.  DOM。

1.  `window`对象。

1.  `document`对象。

1.  以上都不是。

# 摘要

在本章中，我们创建了一个应用程序来绘制 Mandelbrot 分形图，以了解如何使用 HTML Web 工作者在后台线程中执行长时间运行的进程。这使得浏览器能够保持响应并接受用户输入，同时生成图像。

我们在本章中涵盖了以下概念：

+   如何使用 Web 工作者使 Web 应用程序更具响应性

+   如何创建 Web 工作者并启动它

+   如何在主线程和 Web 工作者之间发送消息和数据

+   如何使用 Web 工作者绘制 Mandelbrot

+   如何捕获从 Web 工作者抛出的错误

+   如何调试 Web 工作者

在下一章和最后一章中，我们将学习如何通过组合和压缩其 JavaScript 文件来准备 Web 应用程序以发布。这将使应用程序在网络上的印记更轻。此外，我们将看到如何使用 HTML5 应用程序缓存来缓存应用程序，以便在用户离线时运行。


# 第十章：将应用程序发布到野外

> “互联网是一个充满了自己的游戏、语言和手势的荒野，通过它们我们开始分享共同的感受。”
> 
> - 艾未未

*在本章中，我们将学习如何为发布准备 Web 应用程序。首先，我们将讨论如何压缩和合并 JavaScript 文件以加快下载速度。然后，我们将看看如何使用 HTML5 应用程序缓存接口使您的应用程序离线可用。*

在本章中，我们将学习：

+   如何合并和压缩 JavaScript 文件

+   如何创建一个命令行脚本来准备一个应用程序发布

+   如何使用 HTML5 应用程序缓存 API 使页面及其资源离线可用

+   如何创建一个缓存清单文件来确定哪些资源被缓存

+   如何确定应用程序的缓存何时已更新

# 合并和压缩 JavaScript

过去，JavaScript 开发人员的共识是你应该将所有的代码写在一个文件中，因为下载多个脚本文件会导致大量不必要的网络流量，并减慢加载时间。虽然减少下载文件的数量确实更好，但在一个文件中编写所有的代码很难阅读和维护。我们在其他语言中不会这样写代码，那么为什么我们在 JavaScript 中要这样做呢？

幸运的是，这个问题有一个解决方案：JavaScript 压缩器。压缩器将应用程序的所有 JavaScript 源文件合并成一个文件，并通过将本地变量重命名为最小可能的名称，删除空格和注释来压缩它们。我们既可以利用多个源代码文件进行开发的好处，又可以在发布应用程序时获得单个 JavaScript 文件的所有好处。你可以把它看作是将你的源代码编译成一个紧凑的可执行包。

有许多 JavaScript 压缩器可供选择。你可以在网上找到许多。这些压缩器的问题在于你必须复制你的源代码并将其粘贴到一个网页表单中，然后再将其复制回到一个文件中。这对于大型应用程序来说效果不太好。我建议你使用可以从命令提示符运行的压缩应用程序之一，比如雅虎的 YUI 压缩器或谷歌的 Closure 编译器：

+   [`developers.google.com/closure/`](https://developers.google.com/closure/)

+   [`yui.github.io/yuicompressor/`](http://yui.github.io/yuicompressor/)

YUI 和 Closure 都很容易使用，并且工作得非常好。它们都提供有关糟糕代码的警告（但不是相同的警告）。它们都是用 Java 编写的，因此需要安装 Java 运行时。我不能说哪一个比另一个更好。我选择 YUI 的唯一原因是如果我还想要压缩 CSS，因为 Closure 不支持它。

# 行动时间-创建一个发布脚本

为了为 JavaScript 准备发布，最简单的方法是创建一个可以从命令行运行的脚本。在这个例子中，我们将使用 YUI 压缩器，但它几乎与 Closure 相同。唯一的区别是命令行参数。在这个例子中，我们创建一个可以从 Windows 命令行运行的命令行脚本，它将获取我们在第七章中编写的钢琴英雄应用程序，*钢琴英雄*，并将其打包发布。您可以在`第十章/example10.1`中找到本节的代码。

在我们开始之前，我们需要为应用程序定义一个文件夹结构。我喜欢为应用程序创建一个基本文件夹，其中包含一个`src`文件夹和一个`release`文件夹。基本文件夹包含命令行批处理脚本。`src`文件夹包含所有的源代码和资源。`release`文件夹将包含压缩的 JavaScript 文件和运行应用程序所需的所有其他资源：

![行动时间-创建一个发布脚本](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_10_01.jpg)

现在让我们创建我们的批处理脚本文件，并将其命名为`release.bat`。我们需要告诉 YUI 要压缩哪些文件。有几种方法可以做到这一点。我们可以将所有 JavaScript 文件连接成一个文件，然后引用该文件，或者传入所有单独的文件列表。您使用的方法取决于您的需求。

如果您需要按特定顺序处理文件，或者文件不多，那么您可以将它们作为参数单独指定。如果您的应用程序中有很多文件，并且您不担心顺序，那么最简单的方法可能就是将它们连接成一个文件。在这个例子中，我们将使用`type`命令将所有 JavaScript 文件连接成一个名为`pianoHero.collated.js`的文件。

```html
type src\*.js > pianoHero.collated.js
```

我们使用`type`命令在`src`文件夹中找到所有`.js`文件，并将它们写入一个名为`pianoHero.collated.js`的文件中。请注意，这不包括`lib`文件夹中的文件。我喜欢将它们分开，但如果你愿意的话，你当然可以包括任何外部库（如果它们的许可证允许）。现在我们将执行压缩器，传入合并的 JavaScript 文件：

```html
java -jar ..\yui\yuicompressor-2.4.6.jar --type js -o release\pianoHero.min.js pianoHero.collated.js
```

我们启动 Java 运行时，告诉它在哪里找到 YUI 压缩器的 JAR 文件。我们传入一个文件类型参数`js`，因为我们正在压缩 JavaScript（YUI 也可以压缩 CSS）。`-o`参数告诉它输出的位置。最后是 JavaScript 文件（如果有多个文件）。

现在我们在`release`文件夹中有一个`pianoHero.min.js`文件。我们仍然需要将所有其他资源复制到`release`文件夹，包括 HTML 和 CSS 文件，jQuery 库和音频文件：

```html
xcopy /Y src\*.html release
xcopy /Y src\*.css release
xcopy /Y /S /I src\lib release\lib
xcopy /Y /S /I src\audio release\audio
```

我们使用`xcopy`命令将`pianoHero.html`，`pianoHero.css`，`lib`文件夹中的所有内容以及`audio`文件夹中的所有内容复制到`release`文件夹中。此时，我们在`release`文件夹中有运行应用程序所需的一切。

还有最后一件事要做。我们需要删除 HTML 文件中过时的`<script>`元素，并用指向我们压缩后的 JavaScript 文件的元素替换它们。这部分不容易自动化，所以我们需要打开文件并手动操作：

```html
<head>
    <title>Piano Hero</title>
    <link href="pianoHero.css" rel="StyleSheet" />
    <script src="img/jquery-1.8.1.min.js"></script>
    <script src="img/strong>"></script>
</head>
```

就是这样。现在在浏览器中打开应用程序，进行一次烟雾测试，确保一切仍然按照您的期望工作，然后发布它！

## *刚刚发生了什么？*

我们创建了一个 Windows 命令行脚本，将所有 JavaScript 源文件合并为一个文件，并使用 YUI 压缩器进行压缩。我们还将运行应用程序所需的所有资源复制到`release`文件夹中。最后，我们将脚本引用更改为压缩后的 JavaScript 文件。

## 尝试一下

YUI 压缩器还可以压缩 CSS。在发布脚本中添加代码来压缩 CSS 文件。

# HTML5 应用程序缓存

HTML5 应用程序缓存 API 提供了一种缓存网页使用的文件和资源的机制。一旦缓存，就好像用户在他们的设备上下载并安装了您的应用程序。这允许应用程序在用户未连接到互联网时离线使用。

### 注意

浏览器可能会限制可以缓存的数据量。一些浏览器将其限制为 5MB。

使应用程序被缓存的关键是缓存清单文件。这个文件是一个简单的文本文件，包含了应该被缓存的资源的信息。它被`<html>`元素的`manifest`属性引用：

```html
<html manifest="myapp.appcache">
```

在清单文件中，您可以指定要缓存或不缓存的资源。该文件可以有三个部分：

+   `CACHE`：这是默认部分，列出要缓存的文件。声明此部分标题是可选的。在 URI 中不允许使用通配符。

+   `网络`：此部分列出需要网络连接的文件。对这些文件的请求将绕过缓存。允许使用通配符。

+   `FALLBACK`：这个部分列出了如果资源在离线状态下不可用的备用文件。每个条目包含原始文件的 URI 和备用文件的 URI。通配符是允许的。两个 URI 必须是相对的，并且来自应用程序的同一个域。

### 注意

缓存清单文件可以有任何文件扩展名，但必须以 text/cache-manifest 的 MIME 类型传递。你可能需要在你的 Web 服务器中将你使用的扩展名与这个 MIME 类型关联起来。

需要注意的一件重要的事情是，一旦应用程序的文件被缓存，只有这些文件的版本会被使用，即使它们在服务器上发生了变化。应用程序缓存中的资源可以更新的方式只有两种：

+   当清单文件发生变化时

+   当用户清除浏览器对你的应用程序的数据存储时

我建议在开发应用程序时，将缓存清单文件放在与 HTML 文件不同的文件夹中。你不希望在编写代码时缓存文件。将它放在应用程序的基本文件夹中，以及你的发布脚本，并将它复制到你的脚本中的`release`文件夹中。

是否缓存你的应用程序取决于你的应用程序的性质。如果它严重依赖于对服务器的 Ajax 调用来工作，那么使它离线可用就没有意义。然而，如果你可以编写你的应用程序，使其在离线状态下本地存储数据，那么这可能是值得的。你应该确定维护缓存清单的开销是否对你的应用程序有益。

# 行动时间 - 创建缓存清单

让我们从我们的模板中创建一个简单的应用程序，以演示如何使用缓存清单。它包含 HTML、CSS 和 JavaScript 文件，以及一个`image`文件夹中的一些图片。你可以在`Chapter 10/example10.2`中找到这个示例的源代码。

现在让我们创建一个名为`app.appcache`的缓存清单文件：

```html
CACHE MANIFEST
# v10.2.01
```

清单文件必须始终以`CACHE MANIFEST`开头。在第二行我们有一个注释。以井号(`#`)开头的行是注释。建议在清单文件的注释中有某种版本标识或发布日期。正如之前所述，导致应用程序重新加载到缓存中的唯一方法是更改清单文件。每次发布新版本时，你都需要更新这个版本标识。

接下来，我们添加我们想要缓存的文件。如果你愿意，你可以添加`CACHE`部分的标题，但这不是必需的：

```html
CACHE:
app.html
app.css
app.js
lib/jquery-1.8.1.min.js
```

不幸的是，在这个部分中不允许使用通配符，所以你需要明确列出每个文件。对于一些应用程序，比如带有所有音频文件的钢琴英雄，可能需要大量输入！

接下来让我们定义`NETWORK`部分。现在你可能会想，这部分有什么意义？我们已经列出了所有我们想要被缓存的文件。那么为什么需要列出你不想被缓存的文件呢？原因是一旦被缓存，你的应用程序将只从缓存中获取文件，即使在线。如果你想在应用程序中使用非缓存资源，你需要在这个部分中包含它们。

例如，假设我们在页面上有一个用于跟踪页面点击的站点跟踪图像。如果我们不将它添加到`NETWORK`部分，即使用户在线，对它的请求也永远不会到达服务器。出于这个例子的目的，我们将使用一个静态图像文件。实际上，这可能是 PHP 或其他服务器端请求处理程序，返回一个图像：

```html
NETWORK:
images/tracker.png
```

现在让我们定义`FALLBACK`部分。假设我们想在我们的应用程序中显示一张图片，让用户知道他们是在线还是离线。这就是我们指定从在线到离线图片的备用的地方：

```html
FALLBACK:
online.png offline.png
```

这就是我们的清单文件。现在在浏览器中打开应用程序以便它被缓存。然后进入 JavaScript 文件并更改应用程序对象中`version`变量的值。现在刷新页面；什么都不应该改变。接下来进入清单文件并更改版本，再次刷新。仍然没有改变。发生了什么？

还记得我之前说过的吗？清单文件发生更改会导致应用程序重新加载？虽然这是真的，但在页面从缓存加载后，清单文件不会被检查是否有更改。因此用户需要两次重新加载页面才能获得更新的版本。幸运的是，我们可以在 JavaScript 中检测清单文件何时发生更改，并向用户提供消息，表明有新版本可用的方法。

让我们添加一个名为`checkIfUpdateAvailable()`的 JavaScript 方法来检查缓存何时已更新：

```html
function checkIfUpdateAvailable()
{
    window.applicationCache.addEventListener('updateready',
    function(e)
    {
        setStatus("A newer version is available. Reload the page to update.");
    });
}
```

首先，我们向`applicationCache`对象添加一个`updateready`事件监听器。这在浏览器发现清单文件已更改并下载了更新资源后触发。当我们收到缓存已更新的通知时，我们显示一条消息告诉用户重新加载页面。现在我们只需要在应用程序的`start()`方法中调用这个方法，我们就准备好了。

现在去更新应用程序和清单文件中的版本号并刷新页面。你应该看到更新消息显示。再次刷新页面，你会看到版本已经改变：

![操作时间-创建缓存清单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_10_02.jpg)

最后，让我们检查我们的回退。断开互联网连接并重新加载页面。你应该看到离线图像显示而不是在线图像。还要注意，它无法加载跟踪图像，因为我们将其标记为非缓存资源：

![操作时间-创建缓存清单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-webapp-dev-ex/img/5947OT_10_03.jpg)

## *刚才发生了什么？*

我们学习了如何使用 HTML 应用程序缓存来缓存 Web 应用程序。我们使用清单文件定义了应该被缓存的资源，一个不被缓存的资源，以及应用程序离线时的回退资源。我们还学习了如何以编程方式检查缓存何时已更新。

## 弹出测验

Q1. JavaScript 压缩器*不*做什么？

1.  将你的代码压缩成一个压缩文件

1.  将你的 JavaScript 文件合并成一个文件

1.  从 JavaScript 文件中删除所有空格和注释

1.  将本地变量重命名为尽可能小的名称

Q2. 资源何时在应用程序缓存中更新？

1.  当服务器上的文件发生变化时

1.  当清单文件发生更改时

1.  资源永远不会更新

1.  每次用户启动应用程序时

# 总结

在本章中，我们学习了如何将我们完成的应用程序准备好发布到世界上。我们使用 JavaScript 压缩器将所有 JavaScript 文件合并压缩成一个紧凑的文件。然后我们使用应用程序缓存 API 使应用程序离线可用。

在本章中，我们涵盖了以下概念：

+   如何使用 YUI 压缩器合并和压缩 JavaScript 文件

+   如何创建一个命令行脚本，打包我们的应用程序并准备发布

+   如何使用应用程序缓存 API 缓存应用程序并使其离线可用

+   如何创建缓存清单文件并定义缓存、非缓存和回退文件

+   如何以编程方式检查清单文件何时发生更改并提醒用户更新可用

就是这样。我们已经从创建起始模板到准备应用程序发布，覆盖了 HTML5 Web 应用程序开发。现在去开始编写你自己的 HTML5 Web 应用程序吧。我期待看到你如何使用 HTML5 来创造下一个大事件。


# 附录 A. 突发测验答案

# 第一章，手头的任务

## 突发测验

| 问题 1 4 |
| --- |
| 问题 2 4 |

# 第二章，让我们时尚起来

## 突发测验

| 问题 1 4 |
| --- |
| 问题 2 1 |

# 第三章，魔鬼在细节中

## 突发测验

| 问题 1 2 |
| --- |
| 问题 2 4 |

# 第四章，一块空白画布

## 突发测验

| 问题 1 3 |
| --- |
| 问题 2 2 |

# 第五章，不那么空白的画布

## 突发测验

| 问题 1 1 触摸事件可以有任意数量的点与之关联，存储在`touches`数组中 |
| --- |
| 问题 2 3 每像素四个字节，代表红色、绿色、蓝色和 alpha 值 |

# 第六章，钢琴人

## 突发测验

| 问题 1 4 |
| --- |
| 问题 2 2 |

# 第七章，钢琴英雄

## 突发测验

| 问题 1 3 |
| --- |
| 问题 2 1 |

# 第八章，天气变化

## 突发测验

| 问题 1 4 |
| --- |
| 问题 2 2 |
| 问题 3 1 |

# 第九章，网络工作者团结起来

## 突发测验

| 问题 1 2 |
| --- |
| 问题 2 4 |

# 第十章，将应用程序发布到野外

## 突发测验

| 问题 1 1 |
| --- |
| 问题 2 2 |
