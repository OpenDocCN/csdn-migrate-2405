# 精通 SVG（三）

> 原文：[`zh.annas-archive.org/md5/1F43360C7693B2744A58A3AE0CFC5935`](https://zh.annas-archive.org/md5/1F43360C7693B2744A58A3AE0CFC5935)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：辅助库 Snap.svg 和 SVG.js

到目前为止，我们在本书中已经学到了很多关于 SVG 的知识。如果你已经走到了这一步，你已经准备好进行一些严肃的 SVG 开发，对此有三种方法：

+   继续做我们在本书中大部分已经做过的事情-了解核心技术如何相互作用并将 SVG 集成到您的站点或应用程序中，就像您在任何标记中一样。用 JavaScript 和 CSS 操纵它，你就可以准备好处理基本上任何事情。这是一个有效的方法，也是我在自己的工作中经常采用的方法。

+   使用特定任务的框架和库。我们已经开始用 GSAP 和 Vivus 进行动画的一点探索。我们将在第十章中继续探讨这个问题，*使用 D3.js*，当我们研究 D3，一个强大的可视化框架。

+   使用通用的 SVG 库，它将帮助您处理各种与 SVG 相关的任务。SVG 是在一个名为 Raphael 的库的支持下进入了 Web 开发的主流，目前有一些库可供您在自己的工作中使用。这个选项是本章的重点。

如前所述，由于浏览器的有限支持，SVG 花了很多年时间才获得了广泛的应用。一个名为 Raphael.js 的通用 SVG 库通过为较旧版本的 Internet Explorer 提供了一个非常聪明的**矢量标记语言**(**VML**)的 polyfill 来弥合了这种支持差距。它还为处理浏览器中的 SVG 提供了一个友好的 API，这有助于那些对 SVG 不熟悉的人快速、轻松地入门。

本章涉及两个最受欢迎的 Raphael.js 的后继者：

+   `Snap.svg`：是 Raphael 的直接继承者，由 Raphael.js 的作者 Dmitry Baranovskiy([`snapsvg.io/`](http://snapsvg.io/))编写的库。

+   `svg.js`：另一个小巧、轻量级的库，提供了许多强大的选项来操纵 SVG([`svgjs.com/`](http://svgjs.com/))

本章的其余部分将介绍每个库的基础知识，然后通过一些熟悉的例子，重新利用这些通用的 SVG 工具的功能。

我们将从 Snap.svg 开始。

# 使用 Snap.svg

Snap.svg 是 Adobe 的 SVG 实用库，由 Dmitry Baranovskiy 编写。它功能相对齐全，具有友好、易于探索的 API，并且是开源的。最近这个库的开发速度有所放缓，但它仍然是一个有用的工具，如果您正在探索通用的 SVG 库，您应该意识到它。

让我们开始吧。

# 开始使用 Snap.svg

Snap.svg 可以在`npm`上获得，因此最简单的方法是使用`npm`安装它：

```xml
npm install snapsvg
```

它也可以直接从网站[`snapsvg.io/`](http://snapsvg.io/)下载，也可以从 GitHub[`github.com/adobe-webplatform/Snap.svg`](https://github.com/adobe-webplatform/Snap.svg)下载或克隆。

一旦你做到了这一点，只需包含`node_modules`中的`snap.svg-min.js`，或者从下载的文件夹中，你就可以开始使用 Snap 了。

在这个第一个例子中，我们将 Snap 加载到文档中，然后通过一些 Snap 基础知识加载 Snap API 并操纵一些 SVG。

最初，在这个第一个例子中，我们获取了一个包含`div`的引用，使用 ID`#target`。然后我们使用`new`关键字创建了一个 Snap 的实例，并将其存储在变量`S`中。传入了两个参数，`800`和`600`。这代表了 SVG 元素的宽度和高度。

在本章中，我们将使用变量`S`来表示`Snap.svg`的 API，你可以将变量命名为任何你喜欢的名称，只要你将`Snap.svg`构造函数的返回值分配给它。S 并没有什么神奇之处，除了它是 Snap 作者在他们的示例中使用的传统变量名。

接下来，我们使用 Snap 的实用方法`S.appendTo`将我们的新 SVG 元素添加到文档中，使用我们的`#target`元素作为容器。

现在 SVG 元素已经在页面上，我们向文档中添加了两个新的 SVG 元素，以展示使用 Snap 添加和操作 SVG 元素的基本模式。我们添加了一个圆和一个矩形。圆是用`S.circle`添加的，传入三个属性，`中心 x`、`中心 y`和`半径`。一旦圆被添加，我们调用链式方法`attr`，传入`fill`和`stroke`。

接下来我们调用`S.rect`来创建一个矩形，传入`x`、`y`、`width`和`height`参数，并再次使用`attr`来添加`fill`和`stroke`。

类似于 jQuery 的方法链式调用来操作 SVG 元素是与 Snap 交互的核心。如果你有这种开发风格的经验，你会很快掌握 Snap。API 清晰而逻辑，因此很容易进行实验：

```xml
<!doctype html>
<html lang="en">

<head>
 <meta charset="utf-8">
 <title>Mastering SVG- Basic Snap.svg demo</title>
 <link rel="stylesheet" 
  href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.m
  in.css" integrity="sha384-
  Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" 
  crossorigin="anonymous">
</head>

<body>

 <div class="container-fluid">
 <div class="row">
 <div class="col-12" id="target">

 </div>
 </div>
 </div>

 <script src="img/snap.svg-min.js"></script>
 <script>
 const target = document.getElementById("target");
 const S = new Snap(800,600);
 S.appendTo(target);
 S.circle(250,250,100)
 .attr({
 "fill":"blue",
 "stroke":"green"
 });
 S.rect(550,250,100,100)
 .attr({
 "fill":"green",
 "stroke":"blue"
 });
 </script>
</body>

</html>
```

在浏览器中运行上述代码会产生以下输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/9f040b3f-f908-4c1c-a61b-75c757ef89a2.png)

有了这种基本模式，我们现在可以开始使用 Snap 重新创建之前做过的一些演示。从核心技术过渡到库可以很有启发性，可以让你对库有所了解，以及它是否适合你使用。

# 使用 Snap 进行动画

由于 SVG 动画是现代网页的一个重要特性，Snap 提供了几个动画工具。它还提供了操作现有 SVG 元素的能力，而不仅仅是 Snap 本身生成的元素（这是 SVG.js 无法做到的）。这个演示利用了这两个功能。

设置与我们之前在这个动画演示的例子中看到的类似。我们通过获取三个元素引用`doc`（文档）、`canvas`（父 SVG）和`circle`（圆圈元素）来开始演示。接下来，我们获取`viewBox`的引用和相关的`width`，以便对圆的结束点进行一些计算。这个新的结束点被存储为`newX`。

接下来是这个例子的 Snap 特定特性。首先，我们使用 Snap 的 API 加载了一个对`circle`元素的引用。我们通过将变量`circle`，一个对`circle`元素的 DOM 引用，传递给 Snap 来实现这一点。如果你经常使用 jQuery，这可能对你来说是一个熟悉的模式。

完成后，我们可以使用 Snap 的`animate`方法来使圆圈在屏幕上移动。在这种情况下，`animate`接受四个参数：

1.  第一个是一个对象，指示动画的结束状态。在这种情况下，我们正在将`cx`属性动画到计算出的`newX`值。

1.  然后我们传入动画的持续时间，三秒的毫秒数。

1.  之后我们传入动画缓动。我们再次使用了弹跳缓动。这是作为 Snap 的`mina`对象的一部分提供的，它提供了内置的缓动选项以及一些其他用于处理动画的实用工具。

1.  最后，我们传入一个`callback`函数，在动画完成后运行。这个函数将填充颜色更改为红色：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- SVG Animation with Snap.svg</title>
  <link rel="stylesheet" 
   href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/boot
   strap.min.css" integrity="sha384-
   Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6J
   Xm"
    crossorigin="anonymous">
</head>

<body>

  <div class="container-fluid">
    <div class="row">
      <div class="col-12">
        <svg  viewBox="0 0 1000
         450" width="1000" height="450" version="1.1" id="canvas"
         class="canvas">
          <circle cx="75" cy="225" r="50" fill="blue" 
           id="circle"></circle>
        </svg>
      </div>
    </div>
  </div>

  <script src="img/snap.svg-min.js"></script>
  <script>
    const doc = document;
    const canvas = doc.getElementById("canvas");
    const circle = doc.getElementById("circle");
    const viewBox = canvas.viewBox.baseVal;
    const width = viewBox.width;
    const newX = width - (circle.r.baseVal.value * 3);
    const S = new Snap(circle);

    S.animate({ "cx": newX }, 3000, mina.bounce, () => {
      S.attr({ "fill": "red" })
    });
  </script>
</body>

</html>
```

除了在这个例子中看到的动画工具之外，Snap 还包括其他用于处理 SVG 的工具。下一节将介绍其中一些工具。

# Snap.svg 工具

这个例子将说明一些可用于处理 SVG 的有用的 Snap 实用程序。使用通用库如 Snap 的目的是使用诸如以下的实用方法。这个例子只显示了两个这样的实用程序，但这应该足以向您展示可用的东西的类型。

示例的开始是标准的`Snap.svg`开发。您首先获取对`#target`元素的引用。我们创建一个`Snap`变量`S`，然后将其附加到`#target`元素上。

一旦它在文档中，我们可以使用两个实用程序中的第一个。这是一个单行赋值给变量`bbox`，它返回 SVG 元素的边界框，这种情况下是一个圆。

边界框是可以包含形状（或一组形状）的最小可能矩形。

让我们看看这个赋值发生了什么。首先，我们在（`255`，`255`）处创建一个新的`circle`，半径为`110`像素。然后我们添加`fill`和`stroke`，以便在 SVG 元素上看到它。然后我们调用`getBbox`方法，存储为`bbox`。

当我们`console.log`出`bbox`变量时，我们看到以下值：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/8249c115-1a72-40ab-ad36-ab620620d986.png)

正如您所看到的，返回值包含的信息远不止可以包含元素的最小可能矩形的简单坐标。它包含了这些信息（`x`，`y`，`height`和`width`），但它还有其他几个属性，如果您正在处理元素与动画、可视化或动态绘图中的另一个元素的关系，这些属性可能会很有用。

以下列表显示了边界框的值及其代表的含义：

+   `cx` - 盒子中心的*x*值

+   `cy` - 盒子中心的*y*值

+   `h` - 盒子的高度

+   `height` - 盒子的高度

+   `path` - 盒子的路径命令

+   `r0` - 完全包围盒子的圆的半径

+   `r1` - 可以包含在盒子内的最小圆的半径

+   `r2` - 可以包含的最大圆的半径

+   `vb` - 作为`viewBox`命令的盒子

+   `w` - 盒子的宽度

+   `width` - 盒子的宽度

+   `x2` - 盒子右侧的*x*值

+   `x` - 盒子左侧的*x*值

+   `y2` - 盒子底边的*y*值

+   `y` - 盒子顶边的*y*值

这是一个非常有用但可能普通的实用方法。正如你将在 SVG.js 部分看到的，边界框是在使用 SVG 时一个重要且常见的概念。

下一个实用程序示例更有趣一些。让我们看看它是如何工作的。

为此，我们首先创建一个代表风格化字母 R 的`path`。您之前在我们的动画示例中看到了这个 R 和相关的`path`。一旦字母 R 被插入文档中，我们为其添加`fill`和`stroke`，然后对其进行变换，以便将其居中放置在我们之前创建的`circle`上。最终结果如下截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/84fe1b92-8341-42d1-8b4e-02dddb89787b.png)

一旦路径被插入，我们再次调用`console.log`，使用另一个实用方法`path.getTotalLength()`作为参数传入。`path.getTotalLength()`就像它的名字一样 - 它返回引用路径元素的总长度。

例如，如果您正在沿着路径在一定时间长度内进行动画，获取路径的长度将是一个重要的度量。正如下面的截图所示，这个实用程序提供了这个强大的度量，而几乎没有麻烦：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/4fbe144a-9612-4ea8-a469-54be1507c26f.png)

刚刚描述的整个代码如下：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- Snap.svg utilities</title>
  <link rel="stylesheet" 
   href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.
    min.css" integrity="sha384-
    Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
    crossorigin="anonymous">
</head>

<body>

  <div class="container-fluid">
    <div class="row">
      <div class="col-12" id="target">

      </div>
    </div>
  </div>

  <script src="img/snap.svg-min.js"></script>
  <script>
    const target = document.getElementById("target");
    const S = new Snap(800,600);
    S.appendTo(target);
    const bbox = S.circle(255,255,110)
                    .attr({
                        "fill":"blue",
                        "stroke":"green"
                    }).getBBox();
    console.log("bounding box",bbox);

   const path = 
   S.path("M28.14,92.59c1.43,1.56,2.81,3,4,4.45,3.56,4.31,6.05,9.14,6.3
    9,14.82.37,6.35-2,11.81-5.82,16.7-.61.76-1.27,1.48-
    2,2.35,3.15-.86,6.09-1.74,9.07-2.48,2.82-.7,5.66-1.4,8.54-
    1.82a6.54,6.54,0,0,0,2.84-1.15c4.26-2.9,8.5-5.84,12.87-
    8.56a30.61,30.61,0,0,1,10.12-
    4.23c3.16-.64,6.11-.57,7.81,3a73.85,73.85,0,0,0-.4-7.64c-.51-4.55-
    1.4-9-3.7-13-2.84-5-7-6.39-12.32-4.22a32.44,32.44,0,0,0-
    9.07,6.17c-.38.34-.77.65-1.51,1.26-.88-4.66-1.72-9-5.08-12.1.76-
    1.26,1.5-2.32,2.05-3.46a22.71,22.71,0,0,0,1.38-
    3.57,31.72,31.72,0,0,0,0-16.47c-1-4.39-2.26-8.73-3.33-13.11-.37-
    1.53-.53-3.12-.77-4.58-12-.08-23.06-3.78-34.44-
   6.66L6.21,65.08l14.68,9.47L.83,105.88c5.07.89,9.91,1.7,14.74,2.6a1.5
  ,1.5,0,0,0,1.76-.72C20.86,102.76,24.42,97.8,28.14,92.59Z")
    .attr({"fill":"gray","stroke":"burgundy"})
    .transform("s2 t110,85");

    console.log("total length", path.getTotalLength());

  </script>
</body>

</html>
```

现在我们已经看了一些 Snap 实用程序，让我们来看看 Snap 的事件系统，它允许您以交互方式使用 SVG 元素，同时仍然紧密地遵循 Snap API 的限制。

# Snap.svg 事件

虽然您可能已经掌握了使用`Element.addEventListener`手动管理事件，或者已经使用类似 jQuery 的东西来处理事件，但值得注意的是，Snap 提供了一些自己的事件工具。这使您可以减少外部依赖，如果您正在专注于 SVG 的工作。它还允许您跳过像 jQuery 这样的库在处理 SVG 元素时提供的任何怪癖。

以下示例是一个熟悉的示例，修改后显示了 Snap.svg 事件的工作原理。在这个示例中，我们再次向空白的 SVG 画布添加`click`事件处理程序，并在点击点将随机大小的圆插入 SVG 元素。使用 Snap 来实现这个演示与您之前看到的非常相似，但它有一些值得注意的便利，并且说明了 Snap 处理事件的简单方式。

该示例首先获取`#target`元素的访问权限，设置`height`和`width`变量，然后创建一个附加到`#target`元素并存储在标准 Snap 变量`S`中的 Snap 实例。

一旦我们加载了 Snap，我们将一系列方法调用链接在一起，使用`S.circle`方法添加一个圆，使用`attr`方法设置`fill`，然后使用 Snap 的`click`事件工具为元素添加点击事件处理程序。

当用户单击 SVG 元素时调用的`callback`函数与普通 JS 版本几乎相同，尽管它使用 Snap 方法`S.circle`插入一个圆元素，使用熟悉的随机参数`fill`，`radius`，`newX`和`newY`：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- SVG Events with Snap.svg</title>

</head>

<body>

  <div class="container-fluid">
    <div class="row">
      <div class="col-12" id="target">

      </div>
    </div>
  </div>

  <script src="img/snap.svg-min.js"></script>
  <script>
    const target = document.getElementById("target");
    const height = 600;
    const width = 800;
    const S = new Snap(width,height);
    S.appendTo(target);
    S.circle(250,250,100).attr({"fill":"blue"}).click(()=>{
      const newX = Math.random() * width;
      const newY = Math.random() * height;
      const r = Math.random() * height/2;
      const red = Math.random() * 255;
      const blue = Math.random() * 255;
      const green = Math.random() * 255;
      S.circle(newX,newY,r).attr({
        "fill":`rgba(${red},${blue},${green},${Math.random()})`
      });
    });

  </script>
</body>

</html>
```

如果您习惯于使用 jQuery 或其他遵循类似模式的库，那么您应该能够快速掌握 Snap 的事件工具。

# 使用 Snap.svg 进行自定义数据可视化

最后一个使用`Snap.svg`的示例显示了它如何用于进行自定义数据可视化。这将展示`Snap.svg`的许多功能，并提供对该库的最终全面了解。

这个例子将再次生成一个可视化，显示大卫·奥尔蒂兹在波士顿红袜队职业生涯中每年击出的全垒打的正负增量与每年击出的平均全垒打数之间的对比。

由于我们已经看到了这个可视化，在本节中我们将只关注使用`Snap.svg`的地方，而不是脚本的每一行。如果您需要对数据可视化本身的方法和原因以及如何计算指标进行复习，请回顾第八章，“SVG 动画和可视化”，以获得整个脚本的完整解释。

您将看到的第一个文件是 HTML 文件，它与此可视化的原始版本类似。唯一的真正区别是包括从`node_modules`中的`Snap.svg`源文件：

```xml
  <div class="container-fluid">
    <div class="row">
      <div class="col-12">
        <svg  viewBox="0 0 1000 450" 
         width="1000" height="450" version="1.1" id="canvas" 
         class="canvas">
        </svg>
      </div>
    </div>
  </div>

  <script src="img/snap.svg-min.js"></script>
  <script src="img/scripts.js"></script>
```

查看`scripts.js`的源代码，`viz()`函数在结构上是相同的，但有一些与 Snap 相关的差异，您会想要注意到。

`data`变量完全相同，并在此处截断，以使`viz()`函数稍微易于阅读。请参阅第八章，“SVG 动画和可视化”，或查看源代码以查看完整的数据集。

在`data`变量之后，一些有趣的东西从`S`变量开始。正如您之前看到的，`S`是`Snap.svg`的一个实例，这将是我们进行大部分工作的接口。在那之后，在这个版本和原始版本之间没有任何变化，直到我们使用对 SVG 元素的 DOM 节点的 Snap 引用`S.node`来访问 SVG 元素的`viewBox`。

接下来，你会注意到的最大的区别是能够使用 Snap 的便利方法`S.rect`、`S.line`和`S.text`（都与`S.attr`配对）将我们的线条、方框和文本元素添加到屏幕上。我们还使用`S.addClass`将 CSS 类添加到我们的线条中。

因为所有这些方法都存在于`Snap.svg`中，这个例子和我们仅使用 JavaScript 的例子之间最大的区别是我们自己手动编写的便利方法的缺失。由于 Snap 提供了许多便利功能，我们不需要自己提供。这本身就很棒，当然，Snap 包括的便利方法远远多于`S.rect`、`S.line`、`S.text`和`S.attr`。

```xml
function viz() {
  /*
    ES6
  */
  const data = [
    /* truncated for brevity - see Chapter 8 for the full data set*/   
    {
      "year": 2016,
      "hrs": 38
    }
  ];

  const doc = document;
  const canvas = doc.getElementById("canvas");
  const S = new Snap(canvas);
  function maxDiffer(arr) {
    let maxDiff = arr[1] - arr[0];
    for (let i = 0; i < arr.length; i++) {
      for (let j = i + 1; j < arr.length; j++) {
        if (arr[j] - arr[i] > maxDiff) {
          maxDiff = arr[j] - arr[i];
        }
      }
    }
    return maxDiff;
  }
  document.addEventListener("DOMContentLoaded", () => {
    const viewBox = S.node.viewBox.baseVal;
    const width = viewBox.width;
    const height = viewBox.height;
    const x = viewBox.x;
    const y = viewBox.y;
    const padding = width / 200;
    const vizWidth = width - padding;
    const years = data.length;
    const total = data.reduce((total, item) => {
      return total + item.hrs;
    }, 0);
    const avg = total / years;
    const verticalMidPoint = (y + height) / 2;
    const diffs = data.map((item) => {
      return item.hrs - avg;
    });
    const maxDiff = maxDiffer(diffs);
    const yIntervals = verticalMidPoint / maxDiff;
    const xInterval = (vizWidth / years);
    for (const i in diffs) {
      const newX = xInterval * i;
      const newY = diffs[i] * yIntervals;
      if (diffs[i] < 0) {
        S.rect(
          newX + padding,
          verticalMidPoint,
          xInterval - padding,
          Math.abs(newY)
        ).attr({ 
          "fill": "#C8102E", 
          "stroke": "#ffffff" 
        });

        S.text(
          newX + padding, 
          verticalMidPoint + Math.abs(newY) + (padding * 3), 
          `${data[i].hrs} in ${data[i].year}`
        );
      }
      else if (diffs[i] > 0) {
        S.rect(
          newX + padding,
          verticalMidPoint - newY,
          xInterval - padding,
          newY,
        ).attr({ 
          "fill": "#4A777A", 
          "stroke": "#ffffff" 
        });

        S.text(
          newX + padding,
          verticalMidPoint - newY - (padding * 2)
          , `${data[i].hrs} in ${data[i].year}`
        );
      }
      S.line(
        x,
        verticalMidPoint,
        width,
        verticalMidPoint
      ).attr({ 
        "stroke": "#ffffff" 
      });
      S.text(
        x + padding,
        height - (padding * 3)
        `Based on an average of ${avg} home runs over ${years} years`
       ).addClass("large");
    }
  });

}

viz();
```

现在我们已经仔细研究了`Snap.svg`，并希望让你感受到与它一起工作的感觉，让我们再看看另一个`helper`库，名为 SVG.js。

# 使用 SVG.js

SVG.js 是由 Wout Fierens 创建的，目前由 Ulrich-Matthias Schäfer、Jon Ronnenberg 和 Rémi Tétreault 维护。它被设计成轻量级和快速，并且是一个友好的 SVG 工作界面。它的维护活跃度比`Snap.svg`更高，所以它有这个优势。在撰写本文时，最近的代码是在过去两周内添加到项目中的。

# 开始使用 SVG.js

与`Snap.svg`一样，SVG.js 也可以在`npm`上获得，因此使用`npm`安装 SVG.js 是最简单的方法：

```xml
npm install svg.js
```

确保你使用`npm`安装`svg.js`而不是`svg.js`。两者都可以使用并且都指向正确的项目。然而，`svg.js`已经过时，因为官方包是`svg.js`。

它也可以直接从[`svgjs.com/installation/#download`](http://svgjs.com/installation/#download)下载。也可以从 GitHub 的[`svgjs.com/`](http://svgjs.com/)下载或克隆，并且可以在`cdnjs`[.](http://snapsvg.io/)上找到。

一旦你做到了，只需包含`node_modules`或下载文件夹中的`svg.min.js`，你就可以开始使用 SVG.js 了。

这个第一个例子重复了之前的蓝色圆/绿色方块演示。SVG.js 的约定，如他们的演示所示，是使用一个变量`draw`来保存你要使用的 SVG.js 的加载实例。

要创建 SVG.js 的实例，你需要传入一个目标 HTML 元素的引用，SVG.js 会将一个加载好的 SVG 元素插入到目标元素中，准备让你使用。然后你可以链式调用`SVG.size`方法，它会设置新创建的 SVG 元素的大小。

在本章中，我们将使用变量`draw`来表示 SVG.js API，你可以用任何你喜欢的变量名。只要将 SVG.js 构造函数的返回值分配给它，任何变量名都可以使用。`draw`并没有什么特别神奇的地方，除了它是 SVG.js 作者在他们的示例中使用的传统变量名。

`Snap.svg`和变量`S`也是如此。这些只是约定。

SVG.js 并不是为了与现有的 SVG 元素一起工作而设计的，因此如果你习惯于获取现有 SVG 元素的引用然后对其进行操作，你必须稍微改变你的方法。

一旦我们有了对`draw`的引用并且我们的 SVG 元素添加到页面上，我们就可以开始操纵 SVG 元素，添加我们的正方形和圆形。

看看圆的例子，我们调用了名为`draw.circle`的方法来创建一个圆。`draw.circle`接受*一个*参数，即圆的*半径*。

有趣的是，所有其他属性都是用熟悉的（来自 jQuery 和 Snap 的）`attr`方法进行操作。我认为这是一个奇怪的选择，因为只有半径的圆并不是很有用。对于`draw.rect`也是一样，它需要矩形的高度和宽度作为参数，然后使用`attr`作为其他属性。

这种语法完全有效。但有趣的是属性分布在两个方法中：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- Basic SVG.js demo</title>
  <link rel="stylesheet" 
   href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.
    min.css" integrity="sha384-
    Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
    crossorigin="anonymous">
</head>

<body>

  <div class="container-fluid">
    <div class="row">
      <div class="col-12" id="target">

      </div>
    </div>
  </div>

  <script src="img/svg.min.js"></script>
  <script>
    const draw = SVG('target').size(800,600);
    draw.circle(200)
        .attr({
          "fill":"blue",
          "stroke":"green", 
          "x":250,
          "y":250
        });
    draw.rect(100,100)
        .attr({
          "fill":"green",
          "stroke":"blue", 
          "x":550,
          "y":250
        });
  </script>
</body>

</html>
```

# SVG.js 动画

现在我们已经看到了将元素插入页面的基本示例，让我们继续遵循与`Snap.svg`相同的模式，并看看如何使用 SVG.js 创建动画。

我们需要另一个依赖项才能在 SVG.js 中正确运行动画，`svg.easing.js`。这是一个与 SVG 动画一起使用的缓动函数库：

```xml
npm install svg.easing.js
```

在包含主 SVG.js 文件之后包含它，然后您就可以开始了。

开始使用这个例子，我们创建了几个变量来在整个动画中使用，`width`，`height`，`cx`，`cy`和`radius`。您之前看到过这些，它们映射到 SVG 元素的属性。

然后我们创建了我们的 SVG.js 实例，使用`height`和`width`值作为参数，并将其存储在`draw`变量中。之后我们通过调用`draw.circle`创建了我们将要进行动画的`circle`元素，参数是`radius`变量。然后我们调用`attr`，传入蓝色的`fill`值和`cx`和`cy`变量作为`cx`和`cy`属性的值。这在 SVG 元素上正确的位置创建了蓝色的圆。

然后我们计算了`newX`变量。然后我们使用 SVG.js 方法`circle.animate`将圆形动画到新值。`animate`方法接受三个参数，`3000`，动画的长度，`SVG.easing.bounce`，要使用的缓动函数（来自`svg.easing.js`），和`1000`，动画延迟。

接下来是一个链式操作方法，`center`，在这个例子中，表示要执行的动画类型。`center`本身将元素的中心移动到传入的新`(x,y)`坐标。将其与`animate`链接意味着您将在两个状态之间平滑地进行动画。在我们的例子中，`center`将`newX`和原始`cy`变量作为参数，这为我们提供了新的水平放置位置，同时保留了原始的垂直放置位置。

最后，为了说明动画`callback`方法，我们使用`after`方法，它允许我们在动画完成后运行一个函数。在这里，我们只是使用`attr`方法改变了圆的颜色：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- SVG Animation with SVG.js</title>
  <link rel="stylesheet" 
   href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.
    min.css" integrity="sha384-
    Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
    crossorigin="anonymous">
</head>

<body>

  <div class="container-fluid">
    <div class="row">
      <div class="col-12" id="canvas">

      </div>
    </div>
  </div>

  <script src="img/svg.min.js"></script>
  <script src="img/svg.easing.min.js"></script>
  <script>
    const width = 1000;
    const height = 450;
    const radius = 50;
    const cx = 75;
    const cy = 225;
    const draw = SVG('canvas').size(width,height);
    const circle = draw.circle(radius * 2)
                        .attr({
                            "fill":"blue",
                            "cx":cx,
                            "cy":cy
                         });
    const newX = width - (radius * 3);
    circle.animate(3000, SVG.easing.bounce, 1000)
      .center(newX,cy)
      .after(function(situation) {
        this.attr({ 
          "fill": 'red' 
        });
      });

  </script>
</body>
</html>
```

正如我们在这两个示例中看到的，SVG.js API 中有一些怪癖。由于这些怪癖是一致的，比如在两个链接的方法中设置属性，您可以非常快速地适应它们。

# SVG.js 实用程序

像`Snap.svg`一样，SVG.js 有一套实用函数，可以帮助您处理 SVG。其中一些确实很棒。这个例子展示了其中许多函数的工作原理。

为了开始这个例子，我们创建了一个加载了 SVG.js 变量`draw`，并传入`800`，`600`作为`height`和`width`。

立即开始使用一些实用程序，我们调用`draw.viewbox()`来获取 SVG 元素的`viewBox`。如果您还记得使用`Snap.svg`完成的可视化示例，您会记得我们必须导航多个属性才能访问`Snap`中的`viewBox`。根本没有方便的方法，只是表示 SVG 元素的 DOM 节点的属性。

这里有一个方便的方法直接返回它：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/6299d61f-3d66-43d0-afcf-f28483706ef6.png)

接下来，我们使用`rect`加载一个`100`乘`100`的矩形，位于(`100`, `100`)，然后`console.log`出`rect.bbox()`，它返回矩形的边界框。正如您在下面的截图中所看到的，它的属性比`Snap.svg`示例的边界框要少，但它仍然具有所有您需要与该元素进行干净交互的标准属性：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/a880d18b-7513-47c9-b13a-4c2fab5aee8d.png)

下一个非常有用的与标准边界框相关的实用程序被说明了。

首先，我们使用 SVG.js 的`transform`方法转换矩形，将其旋转 125 度。`transform`是一个`getter`/`setter`，当没有参数调用时，将返回当前的转换值，当使用参数调用时，将设置该值。

一旦我们转换了`rect`矩形，我们就会`console.log`出`rect.rbox()`的返回值，它返回一个表示元素的可视表示的边界框，其中包括所有的变换。*如果你正在处理变换后的元素，这将节省你大量的编码工作：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/0c7752a6-c0b5-4358-b450-07eeb98ada5d.png)

接下来的方法`data`的工作方式与 jQuery 的 data 方法完全相同。作为`setter`调用时，`rect.data({"data":"storing arbitrary data"}),`，`data`在对象上设置任意数据，存储在用户提供的标签下。作为`getter`调用时，传入标签作为参数，`rect.data("data")`，它返回标记数据的值：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/94970048-f07a-47e9-bccc-ce0454dc37b9.png)

下一个实用方法允许你调整 SVG 元素的堆栈。与绝对定位的 HTML 元素不同，它们具有显式的堆叠顺序（z-index），SVG 元素是基于它们在 DOM 中的出现顺序进行分层的。在 DOM 中后出现的元素似乎位于先出现的元素的顶部。

下一个代码块展示了如何使用 SVG.js 实用程序调整这个堆叠顺序。

首先，我们创建两个正方形，一个绿色的正方形，然后是一个蓝色的正方形。当它们最初出现在屏幕上时，它们看起来如下截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/fa7a2182-d20b-4d0a-b96e-b4eb155f4280.png)

然后，在一秒的超时内，我们调用`back()`方法，将元素发送到堆栈的底部。之后，正方形看起来如下：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/0181a282-3e7c-48b0-980c-d486a87e6ce8.png)

现在我们在屏幕上有两个正方形，是时候看一下最后一个非常有用的边界框相关实用程序了。如果你调用`first.bbox().merge`并将`second.bbox()`作为参数传入，你将得到一个合并的边界框。如果你正在处理不属于结构化 SVG 组的多个元素，这将非常有用：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/590dc8e3-adcd-40c6-86f2-d5f84c63aa91.png)

这是整个代码示例：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- SVG.js utilities</title>
  <link rel="stylesheet" 
   href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.
    min.css" integrity="sha384-
    Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
    crossorigin="anonymous">
</head>

<body>

  <div class="container-fluid">
    <div class="row">
      <div class="col-12" id="canvas">

      </div>
    </div>
  </div>

  <script src="img/svg.min.js"></script>
  <script>
    const draw = SVG('canvas').size(800,600);
    console.log("view box:",draw.viewbox());
    const rect = draw.rect(100,100)
                    .attr({
                        "x":100,
                        "y":100
                     });
    console.log("bounding box:", rect.bbox());
    rect.transform({ rotation: 125 });
    console.log("rbox:",rect.rbox());
    rect.data({"data":"storing arbitrary data"});
    console.log("data method:", rect.data("data"));

    const first = draw.rect(50,50)
                      .attr({
                          "x": 200,
                          "y": 200, 
                          "fill": "green"
                       });
    const second = draw.rect(50,50)
                        .attr({
                            "x": 225,
                            "y": 225, 
                            "fill": "blue"
                        });
    setTimeout(()=> {
      second.back();
    },2000);
    console.log("merged bounding box", first.bbox().merge(second.bbox()));

  </script>
</body>

</html>
```

# SVG.js 事件

SVG.js 还具有事件处理工具。下面的示例将说明 SVG.js 提供的非常熟悉的事件处理模式。

我们再次通过将`click`事件绑定到一个函数来说明事件处理，该函数在画布上插入随机大小的圆和随机填充。这也将说明 SVG.js `front()`方法的一个很好的用法。

示例从创建`draw`变量开始，设置其高度和宽度，然后创建一个带有 SVG.js 增强的`circle`元素的`circle`变量。

之后，我们将`click`事件绑定到圆上，使用事件工具`circle.click`创建随机大小/填充的圆元素。这很简单。就像`Snap.svg`示例或早期版本的 jQuery 示例一样，你将`callback`方法作为参数传递给`click`，这就是正确绑定事件所需的全部内容。

在`callback`中，我们使用`draw.circle`来创建我们的圆，每次函数运行时都会生成随机值。

在这里使用 SVG.js 的一个好处是，你可以通过在每个圆添加后调用`circle.front()`来确保可点击的圆始终位于堆栈的顶部。否则，它最终可能会被其他在 DOM 中后插入的元素埋没，因为它们出现在它的上面：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- SVG.js Events

  </title>
</head>

<body>

  <div class="container-fluid">
    <div class="row">
      <div class="col-12" id="target">

      </div>
    </div>
  </div>

  <script src="img/svg.min.js"></script>
  <script>
    const height = 600;
    const width = 800;
    const draw = SVG('target').size(width,height);
    const circle = draw.circle(100)
                    .attr({
                      "fill":"blue",
                      "cx":250,
                      "cy":250
                    });

    circle.click((e)=> {
      const newX = Math.random() * width;
      const newY = Math.random() * height;
      const r = Math.random() * height/2;
      const red = Math.random() * 255;
      const blue = Math.random() * 255;
      const green = Math.random() * 255;
      draw.circle(r)
        .attr({
            "cx": newX,
            "cy": newY,
            "fill":`rgba(${red},${blue},${green},${Math.random()})`
          });
      circle.front();
    });

  </script>
</body>

</html>
```

# 使用 SVG.js 进行自定义数据可视化

本章的最后一个示例是另一个自定义数据可视化的示例。我们将再次回顾代表大卫·奥尔蒂兹作为波士顿红袜队成员的职业生涯中的全垒打的可视化。

由于我们已经看到了这个多次，我们可以简单地专注于 SVG.js 如何帮助我们完成这项工作。

你将看到的第一个文件是 HTML 文件。与纯 JS 版本之间唯一的区别是包含了来自`node_modules`的 SVG.js 源文件，以及没有基本 SVG 元素：

```xml
  <div class="container-fluid">
    <div class="row">
      <div class="col-12" id="target">

      </div>
    </div>
  </div>
  <script src="img/svg.min.js"></script>
  <script src="img/scripts.js"></script>
</body>
```

`viz()`函数与`Snap.svg`版本中看到的类似。再次，我们为了可读性对数据对象进行了剪裁。

接下来是使用 SVG.js 的熟悉模式。我们设置`width`和`height`变量，然后使用`width`和`height`变量作为参数创建`draw` SVG.js 实例。

SVG.js 首次发挥作用的地方是`DOMContentLoaded 回调`函数中易于使用的`viewBox()`方法，该方法返回 SVG 元素的`viewBox`。我们使用这个变量来计算可视化中使用的多个变量。在创建了超过 20 行熟悉变量之后（请参阅第八章，*SVG 动画和可视化*，以便了解每个变量的作用），我们绘制了一些框，画了一些线，并添加了一些文本。

让我们看一个 SVG.js 如何帮助解决这些问题的例子。

绘制框允许我们暴露一些 SVG.js 提供的便利方法，作为`attr`中属性设置的替代。`draw.rect`的调用方式与以前相同，传入每个框的计算宽度和高度。然后，我们对其进行了三次方法调用：`attr`用于设置`x`和`y`，然后，作为它们可用性的说明，我们还使用了两个便利方法`fill`和`stroke`，直接设置了`fill`和`stroke`。完全可以将所有内容设置为`attr`的参数，但如果您喜欢以这种方式链接方法调用，那么调用`fill`和`stroke`来设置这些属性是一个不错的选择。

绘制文本引入了一个新方法`draw.plain`。有一个`draw.text`方法，但`draw.text`设计用于处理更大的文本块，因此引入了`tspan`元素来帮助控制流和换行。这实际上非常聪明，对于许多情况下需要处理 SVG 中的长文本块的情况来说，这是一个有用的选择，因为一切与流和换行有关的事情都必须手动处理。在这些情况下，有多个元素可供使用是很好的。

然而，`draw.plain`非常适合我们这里的需求，因为我们只对单个文本元素感兴趣。要使用它，我们调用`draw.plain`，将我们连接的字符串作为参数传入，然后使用我们的好朋友`attr`设置`(x,y)`坐标。

绘制线需要四个初始参数，起始`(x,y)`和结束`(x,y)`。一旦我们提供了`viz()`函数的其余部分计算出的这些值，我们就可以执行诸如添加描边之类的操作，通过`draw.attr`（就像这个例子中一样）或`draw.stroke`（如果您喜欢），或者使用便利方法`draw.addClass`添加类。

```xml
function viz() {
  /*
    ES6
  */
  const data = [
/* truncated for brevity - see Chapter 8 for the full data set */
    {
      "year": 2016,
      "hrs": 38
    }
  ];
  const width = 1000;
  const height = 450;
  const draw = SVG("target").size(width, height);
  function maxDiffer(arr) {
    let maxDiff = arr[1] - arr[0];
    for (let i = 0; i < arr.length; i++) {
      for (let j = i + 1; j < arr.length; j++) {
        if (arr[j] - arr[i] > maxDiff) {
          maxDiff = arr[j] - arr[i];
        }
      }
    }
    return maxDiff;
  }
  document.addEventListener("DOMContentLoaded", () => {
    const viewBox = draw.viewbox();
    const width = viewBox.width;
    const height = viewBox.height;
    const x = viewBox.x;
    const y = viewBox.y;
    const padding = width / 200;
    const vizWidth = width - padding;
    const years = data.length;
    const total = data.reduce((total, item) => {
      return total + item.hrs;
    }, 0);
    const avg = total / years;
    const verticalMidPoint = (y + height) / 2;
    const diffs = data.map((item) => {
      return item.hrs - avg;
    });
    const maxDiff = maxDiffer(diffs);
    const yIntervals = verticalMidPoint / maxDiff;
    const xInterval = (vizWidth / years);
    for (const i in diffs) {
      const newX = xInterval * i;
      const newY = diffs[i] * yIntervals;
      if (diffs[i] < 0) {
        draw.rect(
          xInterval - padding,
          Math.abs(newY)
        )
        .attr({
          "x": newX + padding,
          "y": verticalMidPoint,
        })
        .fill("#C8102E")
        .stroke("#ffffff");

        draw.plain(`${data[i].hrs} in ${data[i].year}`)
        .attr({
          "x": newX + padding,
          "y": verticalMidPoint + Math.abs(newY) + (padding * 3)
        });
      }
      else if (diffs[i] > 0) {
        draw.rect(
          xInterval - padding,
          newY,
        )
        .attr({
          "x": newX + padding,
          "y": verticalMidPoint - newY
        })
        .fill("#4A777A")
        .stroke("#ffffff");

        draw.plain(`${data[i].hrs} in ${data[i].year}`)
        .attr({
          "x": newX + padding,
          "y": verticalMidPoint - newY - (padding * 2)
        });
      } 
    }
    draw.line(
      x,
      verticalMidPoint,
      width,
      verticalMidPoint
    )
    .attr({ 
      "stroke": "#ffffff" 
    });

    draw.plain(`Based on an average of ${avg} home runs over ${years} years`)
    .attr({
      "x": x + padding,
      "y": height - (padding * 3)
    })
    .addClass("large");
  });

}

viz();
```

# 摘要

本章为您提供了两个用于处理 SVG 的独立库`Snap.svg`和 SVG.js 的快速介绍。在这两个库中，使用相同的熟悉任务，您可以看到使用原始 JS 和使用库进行这些 SVG 操作之间的区别。您还可以比较两个库在类似任务上的差异。

总的来说，通过这两个库，您学到了许多不同的主题，包括如何入门，如何为元素添加动画，如何处理事件，以及如何进行自定义数据可视化。

现在我们已经了解了通用库，我们将最后看一下一个非常特定目的的 SVG 库，D3.js。D3 用于重型数据可视化，并且是处理 SVG 的最强大的工具之一。


# 第十章：使用 D3.js

这一章将向您介绍**数据驱动文档**（**D3**），这是一个功能强大的可视化库，也是世界上最受欢迎的开源项目之一。有趣的是，尽管它最重要的是其数据操作功能，但 D3 只是用于直接处理 SVG 的最强大的库之一。即使在作为我们在上一章中讨论的`helper`库的上下文中，它也有许多非常有用的功能，用于处理 SVG 文档，包括许多复制`Snap.svg`和 SVG.js 提供的功能以及更多功能。

然而，D3 并不止于此。它远远超出了 SVG 创作和实用功能集，并提供了丰富的工具套件，用于数据操作和随后生成数据可视化。此外，D3 在底层使用了您在整本书中一直在使用的相同的 Web 标准，并将其与强大的 API 结合在一起，为处理 SVG 和数据提供了一个真正的游乐场。

D3 诞生于一个名为 Protovis 的早期可视化库（[`mbostock.github.io/protovis/`](http://mbostock.github.io/protovis/)），自 2010 年代初以来一直存在，并且仍由项目的原始开发人员 Mike Bostock 密切关注。该项目正在积极开发，并提供大量文档和丰富的示例供学习。

一旦你掌握了它，它也会很有趣。这是本书介绍的最后一个新技术，用于直接处理 SVG，因此很高兴能以一个高潮结束本书的这一阶段。

让我们玩得开心。

在本章中，我们将学习一些主题，包括：

+   如何安装 D3 以及如何使用库进行基本的 SVG 操作

+   如何使用 D3 使用比例尺和帮助定义图表的*x*和*y*轴来制作条形图

+   如何使用`d3-fetch`实用程序获取和解析 JSON 和 CSV 数据

+   如何使用`enter`和`exit`选择来根据数据集的更改操作 SVG DOM

+   如何使用 D3 的`arc`和`pie`函数实现甜甜圈图表

+   如何实现和弦图；一个包含多个组件的复杂可视化

# 开始使用 D3

D3 API 可能需要一些时间来适应。本章的示例将努力说明一些基本概念，并随着我们的深入展示 D3 所提供的一些最佳功能。

在做任何事情之前，您需要将 D3 引入您的页面。为此，您可以使用`npm`将其安装到您的项目文件夹中：

```xml
npm install d3
```

安装完成后，您可以使用脚本标签从您的文档中链接到压缩的 D3 源代码：

```xml
<script src="img/d3.min.js"></script>
```

如果您不想使用`npm`，也可以直接从[d3js.org](https://d3js.org/)链接到它：

```xml
<script src="img/d3.v5.js"></script>
```

此外，如果您想要本地副本，可以从 GitHub（[`github.com/d3/d3`](https://github.com/d3/d3)）克隆项目，或者从[d3js.org](https://d3js.org/)下载项目，然后以任何您喜欢的方式组织您的文件。

安装完成后，您就可以开始探索 D3 API 了。

以下示例显示了如何使用 D3 实现一个简单的条形图。在本书中，您已经看到了用于生成条形图的一些概念，但这里的区别在于 D3 会为您完成。D3 了解所有关于可视化的知识，因此它将为您生成所需的度量标准。

这个可视化将比较有史以来销量最高的十本个人漫画书。它将说明的数据如下：[`itsalljustcomics.com/all-time-record-comic-book-sales/`](https://itsalljustcomics.com/all-time-record-comic-book-sales/)

| **标题/期号/等级** | **销售日期** | **销售价格** |
| --- | --- | --- |
| 动作漫画 1 9.0 | 2014/08/24 | $3,207,852.00 |
| 动作漫画 1 9.0 | 2011/11/30 | $2,161,000.00 |
| 动作漫画 1 8.5 | 2018/06/13 | $2,052,000.00 |
| 动作漫画 1 8.5 | 2010/03/29 | $1,500,000.00 |
| 了不起的幻想 15 9.6 | 2011/03/09 | $1,100,000.00 |
| 侦探漫画 27 8.0 | 2010/02/25 | $1,075,000.00 |
| 动作漫画 1 堪萨斯城 8.0 | 2010/02/22 | $1,000,000.00 |
| 动作漫画 1 5.5 | 2016/08/04 | $956,000.00 |
| 全明星漫画 8 9.4 | 2017/08/27 | $936,223.00 |
| 动作漫画 1 5.0 | 2018/03/20 | $815,000.00 |

可视化的最终结果将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/c63a1b78-0cc5-4b3b-87c0-909679e0da39.png)

本章中的所有 JavaScript 代码都是为了充分利用 ES6 功能而编写的，比如箭头函数、const 和 let。

接下来是非常简单的标记。我们再次包括 Bootstrap 来进行简单的布局任务和`Raleway`，这本书中我们选择的字体。然后我们为文本元素设置了一些基本的 CSS 样式，并设置了一个简单的容器来容纳可视化内容。之后，我们包括了三个文件：`d3.min.js`，主要的 D3 文件，`d3-fetch.min.js`，D3 的 Fetch 实用程序（[`developer.mozilla.org/en-US/docs/Web/API/Fetch_API)`](https://developer.mozilla.org/en-US/docs/Web/API/Fetch_API)），以及我们的可视化文件`bar.js`：

```xml
<!doctype html>
<html lang="en">

<head>
 <meta charset="utf-8">
 <title>Mastering SVG- D3 Bar Chart</title>
 <link rel="stylesheet" 
   href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.
    min.css" integrity="sha384-
    Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
    crossorigin="anonymous">
 <link href="https://fonts.googleapis.com/css?family=Raleway" 
    rel="stylesheet">
 <style type="text/css">
  text {
   font-family: Raleway;
   font-size: 1em;
  }
 </style>
</head>

<body>
 <div class="container">
  <div class="row">
   <div class="col-12" id="target">

   </div>
  </div>
 </div>
 <script src="img/d3.min.js"></script>
 <script src="img/d3-fetch.min.js"></script>
 <script src="img/bar.js"></script>
</body>
</html>
```

由于这里的 JavaScript 很复杂，并引入了许多新概念，我将逐个解释每个块。如果您想一次看到整个文件，请查看下载的源代码中的完整文件。

查看`bar.js`，它包含一个在屏幕上绘制整个可视化的函数。函数的开始设置了几个常量，这些常量在整个可视化过程中都被使用：`width`、`height`、`chartHeight`（用于设置图表本身的大小与整个 SVG 的大小）和一个`margin`常量，用于确保 SVG 元素中有足够的边距来容纳整个可视化内容：

```xml
function bar() {
  const width = 960,
    height = 800,
    chartHeight = 600,
    margin = 30;
```

之后，我们开始直接使用 D3。D3 允许您访问和操作现有的 SVG 元素，并且，就像本书中 D3 演示的情况一样，生成一个经过 D3 增强的 SVG 元素并将其附加到 DOM 中。

在这种情况下，我们使用 D3 的查询选择器实用程序`d3.select`来选择`#target`元素，然后将一个新的 SVG 元素附加到其中。然后，我们使用越来越熟悉的命名函数`attr`来设置 SVG 元素的`height`和`width`。一旦 SVG 元素在文档中，我们附加一个新的`g`元素，并立即通过*x*和*y*轴上的`margin`进行平移。

链接的 D3 方法的行为类似于 jQuery 或其他使用这种模式的库，因此变量`svg`是对链中最终元素的 D3 启用引用，即新添加的`g`。任何与该变量交互的内容都将从该`g`元素的上下文开始：

```xml
 let svg = d3.select("#target").append("svg")
    .attr("width", width)
    .attr("height", height)
    .append("g")
    .attr("transform", `translate(${margin},${margin})`);
```

接下来，我们使用一些方法来设置*x*和*y*轴的比例，然后实际生成*x*和*y*轴。这就是 D3 真正发挥作用的地方。做这项工作并不是不可能的。这通常是简单的数学。只是没有人想一直编写这些函数，D3 通过一整套比例函数（[`github.com/d3/d3-scale`](https://github.com/d3/d3-scale)）使其变得容易。

`x`变量保存了`scaleBand`方法调用的返回值。`scaleBand`允许您将数值比例划分为组件*band*，我们将使用它来创建条形图的水平间距。初始调用链接到两个后续调用，每个调用都通知了我们特定可视化的 band。`range`方法调用将*x*比例尺设置为从`10`像素到计算出的上限（`width`减去两个水平边距）。`paddingInner`设置 band 的内部填充。这个属性允许我们在列之间创建一些空间。

`y`变量被创建为线性比例尺。线性比例尺是两个值之间的连续、常规比例尺。这个特定比例尺的值是通过调用`range`并将`chartHeight`和`0`作为范围值来设置的。

随后，我们使用新创建的`x`和`y`比例尺调用了两个便利方法，`axisLeft`和`axisBottom`。这些方法为比例尺渲染了可读的参考标记。创建了`xAxis`，然后将刚刚创建的`x`比例尺传递给`xAxis`，以将`xAxis`与`x`比例尺的值连接起来。*y*轴的生成方式完全相同：

```xml
 let x = d3.scaleBand()
    .range([10, (width - margin.left - margin.right)])
    .paddingInner(0.1);
  let y = d3.scaleLinear()
    .range([chartHeight, 0]);
  let xAxis = d3.axisBottom()
    .scale(x);
  let yAxis = d3.axisLeft()
    .scale(y);

```

然后，我们使用另一个比例尺方法`scaleOrdinal`来创建我们的离散数据值和相应一组颜色之间的映射：

```xml
 let color = d3.scaleOrdinal()
    .range([
      "#1fb003",
      "#1CA212",
      "#199522",
      "#178732",
      "#147A41",
      "#126C51",
      "#0F5F61",
      "#0C5170",
      "#0A4480",
      "#073690"
    ]);

```

该方法的其余部分使用了`d3-fetch`和`d3.json`中的实用程序来访问我们的数据文件，然后作为`fetch`请求的`callback`来处理数据并生成我们的可视化。

`callback`方法以对`x`和`y`轴的`domain`进行两次调用开始。

对于序数比例尺，`xAxis`和`domain`接受一个数组，并将比例尺的域设置为数组中的特定值集。在这里，我们`map`返回的`data`以创建`title`属性的集合，作为`xAxis`中使用的值。

对于线性比例尺，调用`domain`将连续比例尺限制为特定的值集。在这种情况下，我们将比例尺设置为最小值为`0`，最大值为`d3.max`的返回值，该返回值为数组中的最大值。

接下来，我们开始操作 SVG 元素来创建实际的可视化效果。

第一组链接的方法附加了一个新的 SVG 组元素`g`，并向其添加了一对类`x`和`axis`，然后将其转换为一个点(`0`, `chartHeight`)。这将该组放置在图表底部，这正是您希望*x*轴的图例所在的位置。

然后我们使用`d3.call`函数调用`xAxis`并生成我们的*x*轴。`d3.call`是一个实用方法，允许您在选择上调用一个函数，然后返回修改后的选择。这使您能够以一种启用链接的方式将一些功能封装在可重用的函数中。在这里，我们调用`xAxis`，即我们之前创建的`axisBottom`方法，以创建*x*轴 - 包括构成*x*轴的所有元素。不做其他任何操作，*x*轴现在看起来像下面这样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/df12a31f-1b9e-4a3d-a55e-c8d1628e5c62.png)

如您所见，对于某些值，该布局可能是可以的，但对于我们的目的来说，它并不实用。由于我们标题的长度，我们需要调整标签以便可读。我们将它们旋转 90 度。

为此，我们在当前链上再链接了一些方法。首先，我们选择了当前选择的所有子节点中的所有`text`元素。这些都是我们刚刚用`xAxis`创建的所有`text`元素。一旦我们有了这个选择，我们就对文本元素应用了-90 度的旋转。这重新定位了文本为垂直。随后，我们调整了`dx`和`dy`属性，使文本整齐地排列。

接下来，我们附加一个新的`g`元素。

使用这些组并不是严格必要的，但它们有助于组织生成的代码以进行调试，并且使您更容易创建易于操作的选择。这就是组的作用。

这个新的`g`元素将保存*y*轴。*y*轴的创建方式与*x*轴类似 - 尽管这是一个更简单的过程，因为不需要操作文本元素。水平文本布局对*y*轴来说是可以的。在这个调用中，我们向`g`元素添加了`y`和`axis`类，然后调用`yAxis`，它生成了构成*y*轴的所有元素。

在这个`callback`函数中的最终方法链展示了在 D3 中工作时的常见模式。第一个调用是`d3.selectAll`。`selectAll`将访问与提供的选择器匹配的*所有*元素。返回的值在 D3 中称为*selection*。选择可以是 DOM 元素的列表，或者在这种情况下，是与数据中的项目匹配的占位符元素的数组。因此，在这种情况下，空是可以的，因为我们将根据接收到的数据来处理选择并向其添加元素。

我们将在下一节更深入地说明`enter`和相关方法`exit`，但简而言之，如果您的选择的元素少于数据集中的点数，则这些额外的数据点将存储在所谓的*enter 选择*中。调用`enter`允许我们进入并操作这个进入选择。在我们的情况下，我们正在向 SVG 元素添加许多`rect`元素。

这些`rect`元素中的每一个都以以下方式进行操作：

+   其`fill`是参考`color`比例的成员设置的。

+   `x`属性是基于`x`比例的成员创建的。

+   `width`是使用`x-bandwidth`计算的，这是一个根据该比例计算宽度的方法，包括任何定义的填充。

+   `y`属性是基于先前创建的`y`比例创建的

+   `height`是通过从`chartHeight`减去此数据点的*y*比例值来计算的。这实际上是将框从`y`值悬挂到图表底部。

所有这些属性组合在一起创建了可视化的核心：

```xml
  d3.json("data/top-ten.json").then((data) => {
    x.domain(data.map((d) => {
      return d.title;
    }));
    y.domain([0, d3.max(data,(d) => {
      return d.price;
    })]);
    svg.append("g")
      .attr("class", "x axis")
      .attr("transform", `translate(0, ${chartHeight})`)
      .call(xAxis)
      .selectAll("text")
      .style("text-anchor", "end")
      .attr("transform", "rotate(-90)")
      .attr("dx", -10)
      .attr("dy", -5);
    svg.append("g")
      .attr("class", "y axis")
      .call(yAxis);
    svg.selectAll("rect")
      .data(data)
      .enter().append("rect")
      .style("fill", (d) => {
        return color(d.price);
      })
      .attr("x", (d) => {
        return x(d.title); })
      .attr("width", () => {
        return x.bandwidth();
      })
      .attr("y", (d) => {
        return y(d.price);
      })
      .attr("height", (d) => {
        return chartHeight - y(d.price);
      });
  });
}
bar();
```

文件的最后一行只是调用`bar()`来创建可视化。

# D3 的 enter 和 exit

正如我在上一节中提到的，我想简要地看一下`enter`和相关方法`exit`。这些方法对于处理动态数据集非常重要。使用这些方法，您可以获取任意选择，将其与数据混合，然后使用 D3 的工具对其进行操作，以创建可视化效果。

在这一部分，您将看到三个例子。第一个示例展示了使用`enter`的示例，说明了对完全空选择调用该方法。第二个示例说明了在具有现有元素的选择上调用`enter`。第三个示例说明了`exit`的工作原理。

在这个第一个示例中，我们选择`#target`元素，然后使用`p`作为参数调用`selectAll`。由于`#target`元素中没有段落，这是一个空选择。在其上调用`data`将空选择绑定到我们的数据。在绑定的选择上调用`enter`允许我们根据每个数据点来操作我们的选择。

如果此时记录`d3.select("#target").selectAll("p").data(data).enter()`的返回值，它将看起来像以下的屏幕截图，显示一个包含原始数据的五个元素的数组，存储为内部的`__data__`属性：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/2b23bbf2-7266-4d18-b7e8-cc3b4362a068.png)

接下来，我们简单地为每个数据点在文档中`append`一个段落，并使用`text`方法将代表数据的文本节点插入文档中：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- D3 Enter</title>
</head>

<body>
  <div class="container">
    <div class="row">
      <div class="col-12" id="target">

      </div>
    </div>
  </div>
  <script src="img/d3.min.js"></script>
  <script src="img/d3-fetch.min.js"></script>
  <script>
    function enter() {
      const data = ["a", "b", "c", "d", "e"];
      d3.select("#target")
        .selectAll("p")
        .data(data)
        .enter().append("p")
        .text((d) => d);
    }
    enter();

  </script>
</body>

</html>
```

在浏览器中运行代码会产生以下输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/b8179d05-c82f-481d-b425-4bc16f455d21.png)

下一个示例类似，只是在`#target div`中有一个现有的段落元素。由于存在`p`元素，在选择上调用`d3.select("#target").selectAll("p").data(data).enter()`的结果如下。如您所见，`_groups`数组具有相同的五个成员，但第一个条目，与`selection`中的现有成员对应的条目为空。这是因为它不是进入选择的一部分（因为它对应于*现有*元素）：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/0677d8c8-621e-40b5-97a3-cfede4a6b9b2.png)

这个示例的其他内容与使用`enter`的上一个示例相同：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- D3 Enter with existing content</title>
</head>

<body>
  <div class="container">
    <div class="row">
      <div class="col-12" id="target">
        <p>This is an existing paragraph</p>

      </div>
    </div>
  </div>
  <script src="img/d3.min.js"></script>
  <script src="img/d3-fetch.min.js"></script>
  <script>
    function enter() {
      const data = ["a", "b", "c", "d", "e"];
      d3.select("#target")
        .selectAll("p")
        .data(data)
        .enter()
        .append("p")
        .text((d) => d);
    }
    enter();

  </script>
</body>

</html>
```

由于在这个示例中只更新了输入选择，因此在浏览器中运行上述代码会产生以下输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/46baebc7-0833-4c4a-b616-43523ce639f0.png)

要更新*整个*选择，您只需要在更新输入选择之前操纵原始选择：

```xml
      const data = ["a", "b", "c", "d", "e"];
      d3.select("#target")
        .selectAll("p")
        .data(data)
        .text((d) => d)
        .enter()
        .append("p")
        .text((d) => d);
```

`exit`选择允许您清理不再与数据关联的元素。以下示例显示了这是如何工作的。

`render`函数最初通过一些我们已经看到的模式。该函数在`#target div`的子元素`p`上调用`selectAll`，加载数据，进入输入选择，并附加一系列带有正确数据的段落元素。

接下来我们重复这个过程，而不是调用`enter`，我们调用`exit`，然后立即调用`remove`。`exit`选择返回选择中不对应数据点的任何元素。`remove`从文档中删除这些元素。第一次运行时，没有元素被删除，因为数据刚刚被加载。选择中的所有元素都用正确的数据填充。

有趣的事情发生在`setTimeout`。在那个`callback`函数中，如果数据数组仍然有成员，就会调用`data.pop()`。`pop`从数组中删除最后一个元素，然后在 1 秒后递归调用`render`。当函数再次运行并且我们到达退出选择时，我们调用`exit.remove`，数据和选择之间存在不匹配。第一次递归调用时，有五个段落，但只有四个数据点。因为第五个段落没有与之关联的数据点，所以它从文档中删除。

这个过程重复，直到没有数据点或段落剩下，递归调用停止：

```xml
<!doctype html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <title>Mastering SVG- D3 Exit</title>
</head>

<body>
  <div class="container">
    <div class="row">
      <div class="col-12" id="target">

      </div>
    </div>
  </div>
  <script src="img/d3.min.js"></script>
  <script>
      const data = ["a", "b", "c", "d", "e"];
      function render(){
        d3.select("#target")
          .selectAll("p")
          .data(data)
          .enter()
          .append("p")
          .text((d) => d );
        d3.select("#target")
          .selectAll("p")
          .data(data)
          .exit()
          .remove();
        if (data.length) {
          setTimeout(()=>{
            data.pop();
            render();
          }
          ,1000);
        }
      }
    render();
  </script>
</body>

</html>
```

希望这些简化的例子足以说明这种非常强大的模式如何帮助处理数据集。

现在我们已经看了这两种方法，让我们回到一些更有趣的东西，用一个新的，稍微更复杂的可视化。

# 使用 D3 实现甜甜圈图

下一个示例说明了另一种基本的数据可视化：在这种情况下，是一个甜甜圈图。比饼图稍微复杂一些，这个可视化展示了 D3 的一些新特性。完成后，可视化将如下截图所示。

它代表了个别漫画书（按标题和期号引用）在有史以来的前 50 本漫画书销售中的分布（公开销售，在撰写时）。像这样的列表中有一些主导的漫画书，这张图表将显示哪些最主导：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/fbc62d23-dba6-4d33-a0aa-57a67117cb73.png)

数据看起来像下面的 CSV：

```xml
title,numbers
"Action Comics #1",18
"All Star #8", 1
"Amazing Fantasy #15",4
"Batman #1",2
"Captain America Comics #1", 1
"Detective Comics #27",13
"Flash Comics #1", 2
"Incredible Hulk #1", 2
"Marvel Comics #1", 1
"Sensation Comics #1", 1
"Tales of Suspense #39", 1
"X-Men #1", 3
```

HTML 文件非常简单。它包括了`Raleway`，Bootstrap，`d3-fetch`和 D3 作为依赖项。它包括了我们在本书中几个示例中一直在工作的相同标记，然后包括我们的`donut.js`文件，这是一切有趣的地方：

```xml
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>Mastering SVG- D3 Chord Diagram</title>
    <link rel="stylesheet" 
href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
        crossorigin="anonymous">
    <link href="https://fonts.googleapis.com/css?family=Raleway" 
     rel="stylesheet">
    <style type="text/css">
        text {
            font-family: Raleway;
            font-size: .8em;
            text-anchor: middle;
            fill: #fff;
        }
        text.legend{
            font-size: 1.25em;
            fill: #000;
        }
    </style>
</head>

<body>
    <div class="container">
        <div class="row">
            <div class="col-12" id="target">

            </div>
        </div>
    </div>

    <script src="img/d3.min.js"></script>
    <script src="img/d3-fetch.min.js"></script>
    <script src="img/donut.js"></script>

</body>

</html>
```

看着`donut.js`，有很多事情要做，所以我们将再次逐个部分地查看文件。如果您想看整个文件，请查看完整的源代码。

文件从设置可视化的`height`，`width`和`radius`的几个常数开始。然后我们创建一个颜色比例尺，它经过 13 种蓝色和绿色的色调：

```xml
const width = 1000,
  height = 1000,
  radius = Math.min(width, height) / 2;

const color = d3.scaleOrdinal()
  .domain(d3.range(13))
  .range([
    "#1fb003",
    "#1CA212",
    "#199522",
    "#178732",
    "#147A41",
    "#126C51",
    "#0F5F61",
    "#0C5170",
    "#0A4480",
    "#073690",
    "#05299F",
    "#021BAF",
    "#000EBF"
  ]);
```

接下来的两个方法调用只是为了为以后的可视化设置。在这一点上，我们没有任何数据可以使用，但是当数据到达时，我们仍然可以创建一些加载的 D3 工具来处理数据。第一个常数`arc`将允许我们用`outerRadius`绘制弧，该弧接近 SVG 元素的边缘，并且`innerRadius`在`outerRadius`内 200 像素。这创建了一个 190 像素的环。

接下来我们调用`d3.ie`，这是一个接收数据并返回代表饼图或甜甜圈图的正确比例切片的方法。我们还没有数据，但是我们设置了该方法，以便在创建`arc`时使用数据对象的`numbers`属性：

```xml
const arc = d3.arc()
  .outerRadius(radius - 10)
  .innerRadius(radius - 200);

const pie = d3.pie()
  .value((d) => {
    return d.numbers;
  });
```

接下来我们开始实现一些 SVG。第一个调用到这个时候应该对你来说是常见的。我们调用`d3.select`来获取`#target`元素，然后将 SVG 元素附加到 DOM 中。然后我们使用`attr`来设置`height`和`width`，然后在 SVG 文档中附加一个组`g`元素。然后将该`g`转换为 SVG 元素的中心，通过将其平移半个宽度和半个高度。

接下来，我们在包含可视化的`g`元素中附加一个新的`text`元素，用于小传说：

```xml
let svg = d3.select("#target").append("svg")
  .attr("width", width)
  .attr("height", height)
  .append("g")
  .attr("transform", `translate(${width / 2},${height / 2})`);

svg.append("text")
  .text("Distribution of comic book titles in top 50 sales of all time.")
  .attr("class","legend");

```

现在我们已经完成了所有这些设置，是时候处理一些数据并绘制可视化了。我们首先使用`d3-fetch`中的另一个方法`d3.csv`，来获取包含我们的数据并在 D3 解析后处理它的 CSV 文件。

在`callback`内部，有一个现在熟悉的 D3 模式。首先，调用`svg.selectAll("arc")`，这时返回一个空选择。然后我们调用`data`，传入`pie(data)`。`pie`接收数据并返回我们用于甜甜圈图的起始和结束角度。接下来我们进入 enter 选择，并为每个选择的成员附加`g`元素。我们还没有画任何东西，但是我们已经为每个数据点设置了组，并且已经计算了应用于数据集的起始和结束角度。

下一节说明了与 D3 一起工作有多么美妙。

此时，我们已经得到了通过调用`pie`生成的角度，附加到许多空的`g`元素上。在下一个调用中，我们附加了一个`path`元素，并且通过调用先前创建的`arc`方法，将`d`属性填充为绘制可视化所需的完整`arc`。就是这么简单。

现在，对于图表本身，唯一剩下的就是通过从之前创建的颜色比例尺返回一个值来填充`arc`的颜色。这是基于数据的索引进行选择。数据根据其在漫画书标题中的排名进行排序。这样在运行此可视化时，我们看到了漂亮的渐变。如果你停在这里，你实际上已经有了一个可视化。它没有与之相关的任何文本，但你已经有了一个看起来不错的甜甜圈图。这就是 D3 的威力。

也就是说，我们应该添加一些标签，让我们看看它是如何工作的。初始模式是你应该开始熟悉的。我们调用`selectAll(".label")`，加载数据（通过对`pie`的另一个调用来操作，以获得相同的起始和结束角度），然后在 enter 选择中操作它。在 enter 选择中，我们附加一个`text`元素，然后采取几个步骤将文本放置在整个可视化中的有用位置。

第一步是使用`arc.centroid`方法将文本元素平移到`arc`的中心。同样，这是 D3 有多么有用的一个很好的例子。一个小小的调用就可以让你访问一个复杂形状的几何中心。这对大多数文本元素都适用。我们快要完成了。

我们只需要调整两种特定情况下的文本。没有下一个调用，最后几个元素的可视化中文本会以不美观的方式重叠，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/61ef5499-ed86-42fd-ae21-2ded41d86a74.png)

要调整这两个重叠元素的位置，我们需要找出它们是哪两个。我们知道它们是最后两个，并且它们会靠近圆圈的末端。这里的角度是用弧度来测量的（360 度是 2PI 或大约 6.28 弧度）。使用粗略的简写，一个切片（0.125 弧度大约代表我们可视化中的一个切片），我们从整个圆圈向后测试最后两个切片，并使用`dy`属性稍微调整它们。第一个通过`.6em`进行调整。接下来，最后一个文本元素通过`1.5em`进行调整。这意味着每个标签都清晰可读。

最终的调用实际上通过调用`text`并将数据的`title`作为参数将文本附加到元素中：

```xml
d3.csv("data/top-fifty-comics-data.csv").then((data) => {
  let g = svg.selectAll(".arc")
    .data(pie(data))
    .enter()
    .append("g");

  g.append("path")
    .attr("d", arc)
    .style("fill", (d) => {
      return color(d.index);
    });

  svg.selectAll(".label")
    .data(pie(data))
    .enter()
    .append("text")
    .attr("class", "text")
    .attr("transform", (d) => {
      return `translate(${arc.centroid(d)})`;
    })
    .attr("dy", (d) => {
      if (d.startAngle > 6.0 && d.startAngle < 6.125) {
        return "-.6em";
      } else if (d.startAngle > 6.125) {
        return "-1.5em";
      }
    })
    .text((d) => {
      return d.data.title;
    });

});
```

现在我们已经完成了两个标准图表，是时候做一个更有趣的弦图了。这个最终的例子将展示 D3 的更多特性。这会很有趣。

# 在 D3 中实现弦图

这个最终的可视化在数据和编码方面都更加复杂。该可视化基于几年前发布的数据，作为 Hubway 数据可视化挑战的一部分（[`hubwaydatachallenge.org/`](http://hubwaydatachallenge.org/)）。这是一个庞大的数据集，代表了波士顿的 Hubway 共享单车项目（现在称为 Blue Bikes）上的每一次行程，包括出发和到达站。这个可视化展示了波士顿十个最受欢迎站点之间的关系，说明了这些站点之间发生的行程数量。这很有趣，可以看到主要枢纽站之间的潜在公共交通网络漏洞（很多人在主要枢纽站之间出行，比如北站和南站），或者可能被游客用来观光波士顿（很多南站的行程返回到南站）。

最终的可视化看起来是这样的。每个`arc`代表一个出发站，两个站点之间的带状物显示了两个站点之间行程的相对权重。当它离开`arc`时的宽度代表行程的数量。`arc`的颜色由生成两个站点之间更多行程的站点拥有：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/0e8f63c5-9a15-438f-b6bf-05c99c3b2d91.png)

这个可视化的 HTML，就像其他 D3 示例一样非常简单。我们在头部有`Raleway`和 Bootstrap。然后顶部有一段 CSS 来添加一些文本样式，以及一个小的定义来为圆圈外缘显示刻度数字的小刻度添加描边颜色。

另外，有一个包含可视化描述的`H1`。然后我们只包含主要的 D3 文件和我们的可视化文件。所有重要的事情都发生在`chord.js`中：

```xml
<!doctype html>
<html lang="en">

<head>
    <meta charset="utf-8">
    <title>Mastering SVG- D3 Chord Diagram</title>
    <link rel="stylesheet" 
href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm"
        crossorigin="anonymous">
    <link href="https://fonts.googleapis.com/css?family=Raleway" rel="stylesheet">
    <style type="text/css">
    h1 {
        font-family: Raleway;
    }
    text {
        font-family: Raleway;
        font-size: 1em;
    }
    text.tick {
        font-size: .8em;
        fill: #999;
    }
    .group-tick line {
        stroke: #999;
    }
    </style>
</head>

<body>
    <div class="container-fluid">
        <div class="row">
            <div class="col-12" id="target">
                <h1>Trip connections between the top 10 Hubway 
                    departure stations. Data from the
                    <a href="http://hubwaydatachallenge.org/">Hubway 
                     Data Visualization Challenge</a>
                </h1>

            </div>
        </div>
    </div>

    <script src="img/d3.min.js"></script>
    <script src="img/chord.js"></script>

</body>

</html>
```

让我们开始通过查看数据来看`chord.js`。文件顶部有整个可视化的硬编码数据。这是一个更大数据集的精简版本，在这个可视化的原始版本中，有很多代码用于创建特定格式的数据。生成这些数据的代码可以在 GitHub 上找到，以及本书的其他源代码。

弦图需要一个*方阵*。这是一个数组的数组，其中数组的成员总数与子数组的成员总数相匹配，并且你可以在它们之间进行映射。在我们的例子中，父数组代表一个*出发*站，子数组的值代表到达每个*到达*站的总行程数。子数组的索引与父数组的索引相匹配。一个出发站也可以是到达站。

`names` `const` 包含每个出发站的名称，与`matrix`数组中出发站的索引相匹配：

```xml
function drawChord() {
  const names = [
    "South Station",
    "TD Garden",
    "Boston Public Library",
    "Boylston St. at Arlington St",
    "Back Bay / South End Station",
    "Charles Circle",
    "Kenmore Sq / Comm Av",
    "Beacon St / Mass Av",
    "Lewis Wharf",
    "Newbury St / Hereford S"
  ];
  const matrix = [
    [2689, 508, 1170, 189, 1007, 187, 745, 248, 263, 2311],
    [1064, 121, 830, 323, 2473, 393, 453, 312, 533, 599],
    [506, 296, 813, 530, 988, 540, 1936, 578, 747, 268],
    [706, 311, 1568, 526, 1273, 371, 618, 694, 481, 227],
    [178, 701, 277, 176, 663, 227, 379, 284, 330, 111],
    [550, 270, 548, 445, 196, 769, 868, 317, 1477, 195],
    [344, 141, 468, 955, 172, 346, 502, 388, 415, 97],
    [333, 207, 455, 545, 196, 1322, 618, 254, 659, 62],
    [655, 120, 301, 90, 2368, 108, 226, 99, 229, 875],
    [270, 221, 625, 436, 239, 278, 548, 1158, 320, 90]
  ];
```

现在我们已经整理好了数据，让我们开始看看如何生成实际的可视化。前五个代码块都是用于设置。这是你通常使用 D3 做的事情，而这个比其他的更复杂，所以需要更多的设置。

第一个块只涉及对可视化所需的各种度量的常量的创建。`width`和`height`对我们所有的 D3 示例都是常见的。`radius`是一个计算出的值，表示一个圆的完整半径，该圆可以适应由高度和宽度创建的正方形。`padding`常量用于计算可视化实际圆的`outerRadius`。然后我们使用`outerRadius`来计算`innerRadius`。

接下来，我们将直接开始使用 D3。第一个调用是`d3.chord`，其结果存储在一个常量`chord`中。`chord`是一个加载方法，将使用我们的设置生成一个弦图。第一个设置`padAngle`是一个`radians`参数，表示`arc`之间的间距。对于这样一个复杂的可视化，`arc`之间有一点空间是很好的，以便为各个部分带来一些清晰度。第二个设置指示我们是否要对子组进行排序。在我们的情况下，我们需要，所以我们传入`d3.descending`作为预定义的排序。

下一个变量`arc`加载了一个`d3.arc`的实例，带有我们计算出的`innerRadius`和`outerRadius`，就像甜甜圈图表一样。一旦你开始把这些东西看作是可以组合在一起的组件，可能性就会打开。

接下来，我们将使用 D3 `ribbon`创建一个实例，`innerRadius`是唯一的配置设置，作为参数传递给`radius`方法。这个方法与`chord`方法一起使用，创建可视化的核心，连接连接的丝带的两端，在我们的例子中是出发和到达站。

最后，我们创建一个`color`比例尺，将车站映射到一组彩虹颜色：

```xml
const width = 1200,
    height = 1200,
    radius = Math.min(width, height) / 2,
    padding = 200,
    outerRadius = radius - padding,
    innerRadius = outerRadius - 25;

  const chord = d3.chord()
    .padAngle(0.025)
    .sortSubgroups(d3.descending);

  const arc = d3.arc()
    .innerRadius(innerRadius)
    .outerRadius(outerRadius);

  const ribbon = d3.ribbon()
    .radius(innerRadius);

  const color = d3.scaleOrdinal()
    .domain(d3.range(9))
    .range([
      "#e6194b",
      "#ffe119",
      "#0082c8",
      "#f58231",
      "#911eb4",
      "#46f0f0",
      "#f032e6",
      "#d2f53c",
      "#808000",
      "#008080"
    ]);
```

现在我们已经设置好了，是时候开始在屏幕上进行可视化工作了。第一个块在这一点上应该非常熟悉。在其中，我们选择`#target`元素，附加一个 SVG 元素，然后设置它的`width`和`height`。

下一个块也应该大部分是熟悉的。在其中，我们向 SVG 元素添加一个`g`组，然后将其平移到屏幕的中心。这里有趣的部分是对`datum`的调用，这是一个非常类似于`data`的方法，除了它将数据传播到整个树中。在这里，我们传入我们的`chord`实例，以及我们的`matrix`，`chord`方法返回我们数据可视化的构建块。

这一部分的最后一个块创建了将容纳我们的弧段、路径和组刻度的组。我们进入`enter`选择，并为`matrix`的每个项目附加一个子`g`元素：

```xml
  const svg = d3.select("#target")
    .append("svg")
    .attr("height", height)
    .attr("width", width);

  const g = svg.append("g")
    .attr("transform", `translate(${width / 2},${height / 2})`)
    .datum(chord(matrix));

  const group = g.append("g")
    .attr("class", "groups")
    .selectAll("g")
    .data((chords) => chords.groups)
    .enter()
    .append("g");
```

在这一点上，我们已经完成了*所有*的设置。现在是时候真正地在屏幕上绘制一些元素了。

添加到可视化中的第一个部分是`arc`。这个模式对你来说应该很熟悉，来自甜甜圈图表。这完全相同的模式；只是这里它是更大的可视化的一部分。

`group`变量已经是一个`Enter`选择的一部分，因此这一部分和我们添加图例的下一部分已经在完整的数据集上运行。

首先我们附加一个`path`，并使用我们对`arc`的调用结果设置`path`的`d`属性。这返回了切片的起始和结束角度。然后我们给它一个`fill`和一个`stroke`。`stroke`提供了 D3 的另一个实用工具的首次亮相。D3.color ([`github.com/d3/d3-color`](https://github.com/d3/d3-color))提供了几种选项来处理颜色。在这里，我们使用`d3.color.darker`来返回所选“弧”的略暗色，以便给它足够的对比度来显示边缘。最后，我们添加了两个事件处理程序，允许用户在鼠标悬停在该站点的弧上时淡化所有其他站点的弧和带。这将使他们能够检查特定站点的连接，而不会受到其他站点的干扰。我们稍后会详细讨论这个功能。

接下来我们添加了带。这与“弧”非常相似。我们从核心`g`组开始，附加一个新的带组，添加一个带的类。然后我们调用`selectAll("path")`来进行选择，调用`data`来应用弦数据，然后我们进入`enter`选择来构建带。对于数据集的每个成员，我们附加一个新的`path`，并使用`ribbon`的调用设置路径的`d`属性。`ribbon`的返回值创建了一个连接“弧”一侧的两个角度与“弧”另一侧的两个角度的路径。之后，我们以与弧相同的方式设置`stroke`和`fill`，以便一切匹配：

```xml
  group.append("path")
    .attr("d", arc)
    .style("fill", (d) => color(d.index))
    .style("stroke", (d) => d3.color(color(d.index)).darker())
    .on("mouseover", fade(.1))
    .on("mouseout", fade(1));

  g.append("g")
    .attr("class", "ribbons")
    .selectAll("path")
    .data((chords) => chords)
    .enter()
    .append("path")
    .attr("d", ribbon)
    .style("fill", (d) => color(d.source.index))
        .style("stroke", (d) => {
      return d3.color(color(d.source.index)).darker();
    });
```

此时，可视化已经绘制到屏幕上。不过我们仍然可以做得更好，所以让我们来做吧。

接下来的部分为每个站点添加了小标签。与之前一样，我们已经处于“enter”选择中，因此我们已经在正确的数据集上操作。这个链中的第一个调用是`each`，它允许我们在选择的每个成员上运行一个函数。传入的`callback`函数添加了一个新的属性到数据集，即`angle`。`angle`通过将“弧”的起始角度和结束角度相加并除以 2 来计算得到，得到“弧”的中间部分。我们将使用该角度来在下一个调用中放置标签。

我们用甜甜圈图表做的标签放在了“弧”上。这在我们设置的弦图表和我们拥有的长文本标签上实际上看起来并不那么好，所以我们想把标签移到圆圈外。我们用一些三角学来实现这一点。

以下图表显示了这是如何工作的。所有这些`text`元素都在 SVG 元素的中心的一个组中。我们要将它们移动到它们的新位置，即圆圈外与它们标记的弧的中间对齐。为此，我们取我们计算的`d.angle`属性，并将其用作直角三角形的斜边（最长边）。一旦我们得到了那个角度，我们就可以计算正弦（对边长与斜边长的比值）和余弦（邻边长与斜边长的比值）。一旦我们有了这些比值，我们只需将它们乘以`outerRadius`（再加上一些额外像素以给它一些空间）就可以得到三角形的邻边和对边的长度。我们将这些值用作将文本元素转换到它们的新位置所需的*x*和*y*。

这项技术将随时派上用场：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/530b6391-6d4b-4469-8e6c-c1f362eef330.png)

接下来的部分根据`arc`上文本元素的位置调整`text-anchor`属性。如果它大于一半（圆上有两个 PI 弧度，所以`Math.PI`相当于圆的一半），那么我们需要将`text-anchor`设置为`end`，以便与圆右侧的标签平衡。如果我们不以这种方式调整 text-anchor，可视化的左侧文本元素将与该侧的弧重叠。

最后，我们附加文本本身：

```xml
group.append("text")
    .each((d) => d.angle = (d.startAngle + d.endAngle) / 2)
    .attr("text-anchor", (d) => {
      if (d.angle > Math.PI) {
        return "end";
      }
    })
    .attr("transform", (d) => {
      const y = Math.sin(d.angle) * (outerRadius + 10),
        x = Math.cos(d.angle) * (outerRadius + 20);
      return `translate(${y},${(-x)})`;
    })
    .text((d) => {
      return names[d.index];
    });
```

我们要为这个可视化添加的最后的 SVG 元素是在外边缘添加组刻度和刻度标签。这些将允许我们以友好的方式指示可视化的规模，以千为单位。

我们首先创建一个新的常量`groupTick`，它基于对`groupTicks`方法的调用返回的数据设置了一个新的进入选择。`groupTick`接收链中的现有数据，并返回一个新的操纵后的数据集，代表每 1000 个单位的新刻度。这些新的`groupTick`数据条目具有一个新的角度，对应于刻度在弧上的正确位置，并引用原始数据的`value`。一旦`groupTick`数据返回，我们进入选择，附加一个新的组并添加一个类`group-tick`。然后我们将元素旋转以在外边缘形成视觉圆圈，并将其平移到`outerRadius`的一个点。

一旦完成，我们在每个刻度处添加一个六像素长的灰色“线”。记住，`groupTick`仍然在这个新链中的一个进入选择中，所以即使我们打破了之前的链，我们仍然可以操作每个数据点。

最后，我们再次进入选择并`filter`数据，防止空数据，然后测试值是否可以被 5000 整除，使用模数（或余数）运算符（[`developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Arithmetic_Operators#Remainder_()`](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Arithmetic_Operators#Remainder_())）。如果可以被 5000 整除，我们需要添加一些文本以指示我们已经为该站点完成了 5000 次行程。这样做的步骤如下。调整`x`属性，将其移动到`outerRadius`之外。调整`dy`属性，将文本元素向上移动一点，以更好地与刻度线对齐。

如果角度超过圆的一半，则转换`text`元素。再次对`Math.PI`进行测试，然后，如果超过一半，我们将文本旋转 180 度，然后将其平移 16 像素，以使其完美地贴合`outerRadius`的边缘。我们还对`text`元素是否超过圆的一半进行相同的测试，如果是，我们将`text-anchor`属性更改为将文本的右边缘固定在圆的边缘。最后，我们向`text`元素添加一个类`ticks`，并使用`d3.formatPrefix`附加实际文本。`d3.formatPrefix`根据提供的格式化参数格式化数字，使其更友好。

在这种情况下，我们希望使用 SI（国际单位制）前缀（[`en.wikipedia.org/wiki/Metric_prefix#List_of_SI_prefixes`](https://en.wikipedia.org/wiki/Metric_prefix#List_of_SI_prefixes)）格式化数字，这将把`5000`转换为`5k`：

```xml
  const groupTick = group.selectAll(".group-tick")
    .data((d) => groupTicks(d, 1000))
    .enter()
    .append("g")
    .attr("class", "group-tick")
    .attr("transform", (d) => {
      return `rotate(${(d.angle * 180 / Math.PI - 90)}) translate(${outerRadius},0)`;
    });

  groupTick.append("line")
    .attr("x2", 6);

  groupTick
    .filter((d) => d.value && !(d.value % 5000))
    .append("text")
    .attr("x", 8)
    .attr("dy", ".35em")
    .attr("transform", (d) => {
      if (d.angle > Math.PI) {
        return "rotate(180) translate(-16)";
      }
    })
    .style("text-anchor", (d) => {
      if (d.angle > Math.PI) {
        return "end";
      }
    })
    .attr("class", "tick")
    .text((d) => d3.formatPrefix(",.0", 1000)(d.value));

  function groupTicks(d, step) {
    let k = (d.endAngle - d.startAngle) / d.value;
    return d3.range(0, d.value, step).map((value) => {
      return {
        value: value,
        angle: value * k + d.startAngle
      };
    });
  }
```

最后的代码是之前提到的`fade`方法。这个函数选择与 CSS 选择器匹配的所有元素。`.ribbons path`过滤掉与当前选择相关的任何元素，并将它们的`opacity`设置为提供的`opacity`参数：

```xml
  function fade(opacity) {
    return function(g, i) {
      svg.selectAll(".ribbons path")
        .filter((d)=> {
          return d.source.index !== i && d.target.index !== i;
        })
        .transition()
        .style("opacity", opacity);
    };
  }
```

效果如下截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/eaa04668-dc32-4142-9109-fe294dc6f380.png)

有了这个，弦图就完成了。这并不是你在 D3 中见过的最复杂的可视化，但它还是相当不错的。连同甜甜圈图和条形图，这三种图表结合起来展示了 D3 的许多重要特性。

# 总结

本章向您介绍了 D3 的世界。尽管本章深入，但只是触及了 D3 所提供的一部分。希望您能将在这里学到的知识继续在未来的几个月和几年中进行实验。这是一个值得掌握的有益工具。

在本书中，我们只剩下一个简短的章节，我们将讨论一些优化 SVG 在网络上提供的方法。这是一个至关重要的领域，至少应该有一些了解，特别是如果您在您的网站或应用程序中使用了大量的 SVG。


# 第十一章：优化 SVG 的工具

现在您已经在本书中学习了关于 SVG 的一切，从纯 SVG 标记的基础知识到过去几章中您所做的基于动态 JavaScript 的 SVG 工作，您已经准备好充分利用 SVG 所提供的一切。

我们应该看一下 SVG 的最后一个方面，即确保您提供给用户的工作以最佳方式呈现。SVG 应该针对性能进行优化，无论是在传输过程中的性能还是在复杂性方面。保持 SVG 文件尽可能精简并有效地提供它们将为用户带来更好的体验。

本章将作为一个高层次的介绍，向您展示优化 SVG 图像的许多方法。接下来的内容有些是纯粹与性能相关的工程。其他则是纯 SVG 工具。

本章中，您将了解以下内容：

+   在三种流行的服务器平台（IIS、Apache 和 nginx）上对服务器上的 SVG 进行压缩

+   SVGO 及其相关工具

+   svgcleaner，SVGO 的替代方案，提供无损优化

# 提供压缩的 SVG

在处理 SVG 时，最直接的性能增强之一就是在提供文件时对`gzip`文件进行压缩。虽然文本文件通常在提供给浏览器时受益于被 gzipped，但 SVG 是一个特别重要的目标，因为 SVG 图像的使用方式（通常用于核心界面）以及一些文件的潜在大小。您希望您的图像加载速度快，SVG 也不例外。

根据您的平台，这可能只需添加几行代码或在对话框中勾选一个框。接下来的几节将向您展示如何在三种常见的 Web 服务器上实现此操作。

# 在 Apache 上对 SVG 进行 gzip 压缩

放置以下代码的位置取决于您的 Apache 实例设置以及您对服务器的访问权限。大多数共享主机的用户将在他们的`.htaccess`文件中执行此操作。`.htaccess`是服务器根目录中的一个特殊文件，允许您在不必访问主配置文件（`httpd.conf`）的情况下配置 Apache 行为。假设您的服务器允许您访问此功能（一些主机不允许您打开压缩，因为它会使用更多的服务器资源），则将文本内容进行 gzip 压缩就像在您的`.htaccess`文件中添加以下内容一样简单。示例代码来自 H5BP Apache 服务器配置项目（[`github.com/h5bp/server-configs-apache/blob/master/dist/.htaccess#L795`](https://github.com/h5bp/server-configs-apache/blob/master/dist/.htaccess#L795)）。有三个部分：

+   第一个修复了代理服务器搞乱请求标头导致资源无法被提供为 gzipped 的问题（这不仅修复了 SVG）

+   第二个实际上告诉 Apache 压缩列出的 MIME 类型的文件（这里进行了缩写；通常会列出几十种不同的 MIME 类型）

+   第三个确保以压缩格式`.svgz`压缩并保存的 SVG 文件能够正确提供：

```xml
# ######################################################################
# # WEB PERFORMANCE #
# ######################################################################

# ----------------------------------------------------------------------
# | Compression |
# ----------------------------------------------------------------------

<IfModule mod_deflate.c>

    # Force compression for mangled `Accept-Encoding` request headers
    #
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Accept-Encoding
    # https://calendar.perfplanet.com/2010/pushing-beyond-gzipping/

    <IfModule mod_setenvif.c>
        <IfModule mod_headers.c>
            SetEnvIfNoCase ^(Accept-EncodXng|X-cept-Encoding|X{15}|~{15}|-{15})$ ^((gzip|deflate)\s*,?\s*)+|[X~-]{4,13}$ HAVE_Accept-Encoding
            RequestHeader append Accept-Encoding "gzip,deflate" env=HAVE_Accept-Encoding
        </IfModule>
    </IfModule>

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    # Compress all output labeled with one of the following media types.
    #
    # https://httpd.apache.org/docs/current/mod/mod_filter.html#addoutputfilterbytype

    <IfModule mod_filter.c>
        AddOutputFilterByType DEFLATE "application/atom+xml" \
                                      "application/javascript" \
                                      "application/json" \
# Many other MIME types clipped for brevity
                                      "image/svg+xml" \
# Many other MIME types clipped for brevity        
                                      "text/xml"

    </IfModule>

    # - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

    # Map the following filename extensions to the specified
    # encoding type in order to make Apache serve the file types
    # with the appropriate `Content-Encoding` response header
    # (do note that this will NOT make Apache compress them!).
    #
    # If these files types would be served without an appropriate
    # `Content-Enable` response header, client applications (e.g.:
    # browsers) wouldn't know that they first need to uncompressed
    # the response, and thus, wouldn't be able to understand the
    # content.
    #
    # https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Encoding
    # https://httpd.apache.org/docs/current/mod/mod_mime.html#addencoding

    <IfModule mod_mime.c>
        AddEncoding gzip svgz
    </IfModule>

</IfModule>
```

# 在 nginx 上对 SVG 进行压缩

与 Apache 类似，为 SVG 打开`gzip`压缩只是配置几行代码的问题。这段代码块来自 HTML5 锅炉板 nginx 服务器配置项目（[`github.com/h5bp/server-configs-nginx/blob/master/nginx.conf#L89`](https://github.com/h5bp/server-configs-nginx/blob/master/nginx.conf#L89)），提供了如何执行此操作的示例。该代码将打开`gzip`压缩，设置`gzip`压缩级别，停止对已经很小的对象进行压缩，为代理设置一些值，然后将 SVG MIME 类型添加到应该被压缩的对象列表中（这里进行了缩写；通常会列出几十种不同的 MIME 类型）：

```xml
# Enable gzip compression.
  # Default: off
  gzip on;

  # Compression level (1-9).
  # 5 is a perfect compromise between size and CPU usage, offering about
  # 75% reduction for most ASCII files (almost identical to level 9).
  # Default: 1
  gzip_comp_level 5;

  # Don't compress anything that's already small and unlikely to shrink much
  # if at all (the default is 20 bytes, which is bad as that usually leads to
  # larger files after gzipping).
  # Default: 20
  gzip_min_length 256;

  # Compress data even for clients that are connecting to us via proxies,
  # identified by the "Via" header (required for CloudFront).
  # Default: off
  gzip_proxied any;

  # Tell proxies to cache both the gzipped and regular version of a resource
  # whenever the client's Accept-Encoding capabilities header varies;
  # Avoids the issue where a non-gzip capable client (which is extremely rare
  # today) would display gibberish if their proxy gave them the gzipped version.
  # Default: off
  gzip_vary on;

  # Compress all output labeled with one of the following MIME-types.
  # text/html is always compressed by gzip module.
  # Default: text/html
  gzip_types
    # Many other MIME types clipped for brevity
    image/svg+xml
    # Many other MIME types clipped for brevity
```

# IIS 上的 SVG 压缩

IIS 默认情况下不会压缩 SVG 文件。根据服务器的配置方式，需要在`applicationHost.config`（`C:\Windows\System32\inetsrv\config`）或`web.config`文件中进行以下更改。您只需将 SVG MIME 类型添加到`httpCompression`模块中的`staticTypes`和`dynamicTypes`元素中，然后就可以开始了：

```xml
<httpCompression directory="%SystemDrive%\inetpub\temp\IIS Temporary Compressed Files">
    <scheme name="gzip" dll="%Windir%\system32\inetsrv\gzip.dll" />
        <staticTypes>
            <add mimeType="image/svg+xml" enabled="true" />
        </staticTypes>
        <dynamicTypes>
            <add mimeType="image/svg+xml" enabled="true" />
        </dynamicTypes>
</httpCompression>
```

现在我们已经学会了有效地提供 SVG，是时候看看一些在将 SVG 放在服务器上之前对 SVG 进行优化的方法了。

# SVGO

SVG 优化器（[`github.com/svg/svgo`](https://github.com/svg/svgo)）是用于优化 SVG 文件的 Node.js 实用程序。SVG 文件，特别是由编辑器生成的文件，可能会有许多与之相关的垃圾。SVGO 可以清理元数据、注释、隐藏元素等，而不会改变 SVG 元素本身的渲染。

要安装它，假设您已安装了 Node.js，请在命令行上运行以下命令：

```xml
$ npm install -g svgo
```

使用方法就是这么简单：

```xml
svgo svgo.svg
```

在 Inkscape 生成的小文件上运行，可以将文件大小减少 50％以上：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/9d8d598b-8a7f-42e7-bd50-6bedead62d96.png)

如果您查看`svgo.svg`源代码在优化之前和之后的变化，差异是显而易见的。

以下截图显示了在创作过程中 Inkscape 添加的元数据：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/1869e97d-22ba-48bc-9ce5-0b2fed462670.png)

此截图显示了优化后的清理文件：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/d05d9dbb-2867-40d7-be10-88de011cb70c.png)

这是一个很棒的工具，有许多配置选项（[`github.com/svg/svgo#usage`](https://github.com/svg/svgo#usage)）和与其他工具的集成（[`github.com/svg/svgo#other-ways-to-use-svgo`](https://github.com/svg/svgo#other-ways-to-use-svgo)）。

# SVGOMG

在前面的链接中列出的集成之一是与 SVGO 的 Web 前端 SVGOMG 的集成（[`jakearchibald.github.io/svgomg/`](https://jakearchibald.github.io/svgomg/)）。SVGOMG 是 SVGO 的 Web 前端。在 UI 中几乎暴露了所有选项，使您能够更深入地了解 SVGO 提供的优化，而无需研究所有配置选项。将 SVG 元素加载到界面中，会呈现以下视图：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/1130e1ce-0b61-4d6c-90a2-151487bc445e.png)

加载的 SVG 在左侧，显示为优化视图。您可以切换“显示原始”按钮，以查看由于优化而导致的可见图像是否有任何降级。

请记住，SVGO 提供的一些优化可能会有*损失*。这意味着图像本身可能会以某种可见的方式发生变化；由于运行的优化，图像的有效数据将丢失。

然后，在右侧有许多可供您调整图像的选项。有一个节省的预览，然后有一个下载按钮，可以让您下载您的作品。

尽管许多人会将此优化作为构建过程的一部分自动化，但知道您可以在 Web 上对此工具进行精细控制，并立即获得更改的反馈是件好事。

# SVGO 创作插件

除了可用的命令行工具和基于 Web 的界面之外，还有一些创作插件可供您将 SVGO 直接集成到创作工作流程中。`SVG-NOW`是 Adobe Illustrator 的插件（尽管它似乎已被放弃；自 2014 年以来就没有更新过），而 SVGO Compressor 是流行应用 Sketch 的一个正在积极开发的插件。如果您有一个设计团队，您可以通过在生产过程中较早地集成这些优化来节省时间并避免出现意外。由于他们将控制导出过程，他们将准确知道 SVGO 优化的输出将是什么。

# svgcleaner

svgcleaner 是 SVGO 的替代品，提供*无损优化*（[`github.com/RazrFalcon/svgcleaner`](https://github.com/RazrFalcon/svgcleaner)）。与有可能破坏事物的 SVGO 相比，svgcleaner 承诺永远不会破坏 SVG 文件。浏览他们的图表（[`github.com/RazrFalcon/svgcleaner#charts`](https://github.com/RazrFalcon/svgcleaner#charts)）以查看他们如何与 SVGO 和 scour（另一种替代品）进行比较。

此外，还有一个可下载的 GUI（[`github.com/RazrFalcon/svgcleaner-gui/releases`](https://github.com/RazrFalcon/svgcleaner-gui/releases)），您可以在桌面上运行。以下截图显示了它的运行情况。要达到这种状态所发生的一切就是加载一个 SVG 元素并点击播放按钮，这将运行优化：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-svg/img/e270fb80-99f5-4bf9-84bb-0f11ed55588a.png)

由于它是用 Rust 构建的，而不是原生的 Node.js 应用程序，它与`npm/node`世界的兼容性不是很好，但它仍然是一个很棒的工具。

# 总结

这是本书中最轻松的一章，但您仍然学到了一些有助于 SVG 优化的知识。牢记这些因素和这些工具将确保用户获得最佳的结果，并确保您对 SVG 的辛勤工作能够以最佳的方式展现出来。

有了这一点，我们对 SVG 世界的旅程就结束了。从最基本的 SVG 元素，到复杂的 JavaScript 可视化和基于 CSS 的动画，您体验了 SVG 所能提供的全部广度。希望您享受了这段旅程，并将继续在未来与 SVG 一起工作。
