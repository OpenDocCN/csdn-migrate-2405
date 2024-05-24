# 使用 CSS3 设计下一代 Web 项目（二）

> 原文：[`zh.annas-archive.org/md5/F3C9A89111033834E71A833FAB58B7E3`](https://zh.annas-archive.org/md5/F3C9A89111033834E71A833FAB58B7E3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：缩放用户界面

在本章中，我们将学习如何创建一个简单的**ZUI**。这个缩放用户界面的首字母缩写代表**缩放用户界面**；一个用户可以改变所看区域的比例以查看更多或更少细节的图形环境。对于这个项目，我们将创建一个 ZUI，让用户移动和探索一个**信息图表**，这是数据、信息或知识的视觉图形表示。我们将要构建的项目结合了许多 CSS3 特性，如过渡、变换和灵活的盒子布局。它还介绍了 SVG 以及我们可以用来在 HTML 页面中嵌入它们的各种方法。此外，作为额外的挑战，我们还将使我们的页面在旧版浏览器上运行，并探索完成这项任务的巧妙方法。

以下是本章讨论的主题的预览：

+   信息图表

+   灵活的盒子布局

+   Polyfills

+   嵌入 SVG

+   Modernizr

+   `:target`伪选择器

+   CSS3 变换

+   用 CSS 定位 SVG

+   优雅降级

# 信息图表

信息图表正在迅速改变我们消费信息的方式，通过创建图形表示来聚合数据或显示流程，并能够以非常直观和易于使用的方式显示大量知识。关于这个主题的一个很好的信息来源是 FlowingData 博客（[`flowingdata.com/`](http://flowingdata.com/)）。

对于这个项目，我们将使用意大利公司 Oxigenio 创建的以下令人惊叹的信息图表（[`www.officinastrategia.it`](http://www.officinastrategia.it)）：

![信息图表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_01.jpg)

我们希望为这个惊人的信息图表保留大部分浏览器视口区域，除了一个宽度为 200 像素的侧边栏，其中包含一些我们马上会看到的命令。首先让我们在一个`index.html`文件中定义一些基本的 HTML：

```css
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
   <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <title> A ZUI for an infographic</title>
    <link rel="stylesheet" type="text/css" 
href="http://yui.yahooapis.com/3.5.0/build/cssreset/
cssreset-min.css" data-noprefix>
    <link rel="stylesheet" type="text/css" 
href="css/application.css">

    <script src="img/modernizr.js"></script>
    <script src="img/prefixfree.js"></script>

  </head>
  <body>
    <section id="infographic">
      <header>
        <h1>a cool infographic</h1>
      </header>
      <article>

      </article>
    </section>
  </body>
</html>
```

对于这个项目，我们使用`modernizr.js`和`prefixfree.js`文件。因此，让我们在项目的根文件夹下创建一个`js`目录，并从它们各自的网站（[`modernizr.com/downloads/modernizr-latest.js`](http://modernizr.com/downloads/modernizr-latest.js)和[`leaverou.github.com/prefixfree/`](http://leaverou.github.com/prefixfree/)）下载它们到那里。

接下来，我们需要准备一个`css`文件夹，并在其中创建一个空的`application.css`文件。

到目前为止，我们定义的 HTML 结构非常简单和极简：一个`header`元素和一个被`section`元素包围的`article`元素。现在我们想把`header`元素放在左侧，宽度固定为 200 像素，并告诉`article`元素覆盖屏幕的剩余部分。

我们可以通过各种技术实现这种元素布置。对于本书的目的，我们将使用 CSS3 灵活的盒子布局。

# 实现灵活的盒子布局

CSS2.1 定义了四种布局模式：块状、内联、表格和定位。CSS3 添加了一些新的布局模式，其中之一是**灵活的盒子布局**。这种新模式是通过我们可以给`display`语句的一个新值来激活的，并且可以通过一整套新的属性进行配置。

这种新布局模式背后的基本思想是，在容器元素（例如，我们的`section`元素）中，我们可以指定我们希望内部元素显示的方向。因此，如果我们说`horizontal`，那么元素将从左到右流动，如果我们说`vertical`，它们将依次从上到下排列。

然后我们可以通过使用固定尺寸或定义增长因子来决定每个元素的大小。

### 注意

当容器内有新空间可用时，元素会按照它们的增长因子成比例地增加宽度。

够说了！让我们创建一个小型演示来测试一下：

```css
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <title> A ZUI for an infographic</title>
    <link rel="stylesheet" type="text/css" 
href="http://yui.yahooapis.com/3.5.0/build/cssreset/
cssreset-min.css">

    <style>
      ul{
        width: 500px;
        height: 200px;
 display: box;
        counter-reset: anchors;
 box-orient: horizontal;
        border: 1px solid black;
      }
      li{
        text-align: center;
        line-height: 200px;
        display: block;
 box-flex: 1;
        counter-increment: anchors;
      }
      li:hover{
 box-flex: 2;
      }
      li:nth-child(2n){
        background: #ddd;
      }
      li:before{
        content: counter(anchors);
      }
    </style>

    <script src="img/prefixfree.js"></script>
  </head>
  <body>
    <ul>
      <li></li>
      <li></li>
      <li></li>
      <li></li>
      <li></li>
    </ul>
  </body>
</html>
```

我们可以看到`ul`元素内的`li`元素以相同的宽度开始，这恰好是包含元素宽度的五分之一。这是因为它们都具有相同的增长因子，由属性`box-flex`指定，这使它们平均分配可用空间。当我们将鼠标悬停在`li`元素上时，我们改变了元素的`box-flex`值；我们将鼠标悬停在`2`上，使其宽度是其他元素的两倍。以下是刚加载页面的屏幕截图：

![实现弹性盒布局](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_02.jpg)

以下是悬停在元素上时的屏幕截图：

![实现弹性盒布局](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_03.jpg)

通过将`box-orient`属性从`horizontal`更改为`vertical`，我们可以观察到在相反轴上的相同行为。由于这个特定示例的结构，我们还必须修改`line-height`以去除我们设置的`200px`高度：

```css
ul{
  box-orient: vertical;
}
li{
  line-height: normal;
}
```

以下是显示结果的屏幕截图：

![实现弹性盒布局](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_04.jpg)

# 定义基本结构

现在我们已经有了创建项目结构的基础，我们需要在`section`元素内定义水平方向，然后将`header`元素的宽度设置为固定值。

我们已经在本章的第一部分创建了`index.html` HTML。现在让我们为了清晰起见再次重印`body`部分：

```css
<body>
  <section id="infographic">
    <header>
      <h1>a cool infographic</h1>
    </header>
    <article>

    </article>
  </section>
</body>
```

我们可以开始将以下指令添加到`application.css`：

```css
html, body{
  height: 100%;
}
body{
  overflow: hidden;
font-family: sans-serif;
}
section{
 display: box;
 box-orient: horizontal;
  height: 100%;
  width: 100%;
  overflow: hidden;
}
header{
 width: 200px;
  background: rgb(181, 65, 71);
}
article{
  background-color: rgb(204, 204, 204);
  background-image: 
    repeating-linear-gradient(bottom left, rgb(204, 204, 204) 0px, 
    rgb(204, 204, 204) 20px, 
    rgb(210, 210, 210) 20px, rgb(210, 210, 210) 40px);
 box-flex: 1;
  overflow: hidden;
  position: relative;
}
```

我们在上一个示例中添加了更多的说明，因为我们还希望`section`元素覆盖整个浏览器视口。此外，我们应该防止显示垂直滚动条，因为唯一的导航机制必须是 ZUI 提供的。因此，我们在`section`和`article`中都添加了`overflow: hidden`属性。

如果我们现在在支持 CSS3 的浏览器中加载项目，我们可以欣赏结果：

![定义基本结构](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_05.jpg)

### 注意

弹性盒布局模块规范正在迅速发展，目前没有一个 web 浏览器支持所有规范。我们的实现对应于 2009 年 7 月 23 日发布的以下文档：

[`www.w3.org/TR/2009/WD-css3-flexbox-20090723/`](http://www.w3.org/TR/2009/WD-css3-flexbox-20090723/)

# 添加 Polyfills

自本书开始以来，我们首次使用 CSS3 来定义页面的结构。这意味着我们不能简单地依赖优雅降级来支持旧版浏览器，因为这会损害项目的整体结构。相反，我们将寻找一些能够模拟我们已实现行为的 JavaScript 库。当然，如果用户的浏览器缺少 JavaScript 支持和弹性盒布局，这可能会导致一些问题，但至少我们可以希望这样的用户数量非常少。

有不同类型的 JavaScript 库，根据需要多少额外工作来获得与原生实现相同的结果进行分类：

+   **通用库**：通用库不允许开发人员获得完全相同的结果，但给他/她一些工具来编写解决方案的替代实现。

+   **Shims**：Shims 允许开发人员完美地模仿原生实现，但实现它需要额外的工作成本。

+   **Polyfills**：Polyfills 是最好的。这些库读取我们的代码，检测不支持的功能，并实现所需的 JavaScript 解决方法，而无需添加额外的代码。

我们需要找到一个模拟弹性盒布局模块的 polyfill。我们可以从以下页面开始搜索，这个页面是由 Modernizr 的作者创建和维护的，列出了他们测试过并发现有效的所有 polyfills：

[`github.com/Modernizr/Modernizr/wiki/HTML5-Cross-Browser-Polyfills`](https://github.com/Modernizr/Modernizr/wiki/HTML5-Cross-Browser-Polyfills)

在页面向下滚动后，我们找到了 Flexie，它声称为旧版浏览器（最多到 IE6）添加了对弹性盒布局的支持。我们所要做的就是将库`flexie.js`下载到我们的`js`文件夹中（它也可以从 GitHub 上获取，网址为[`github.com/doctyper/flexie`](https://github.com/doctyper/flexie)，在`src`文件夹中）。

让我们通过在`</body>`标签之前添加以下行来修改我们的`index.html`文件：

```css
<!-- Adding older browser's support -->
<script 
src="http://ajax.googleapis.com/ajax/libs/jquery/1.7.2/
jquery.min.js"></script>
<script src="img/flexie.js"></script>
```

现在我们可以测试一下，看看是否一切顺利，加载我们的项目到不支持 CSS3 弹性盒布局的浏览器中。以下是从 IE8 中获取的屏幕截图：

![添加 Polyfills](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_06.jpg)

从输出中可以看出，没有条纹背景，但整体结构得到了很好的保留。

### 注意

向项目添加 Polyfill 不可避免地增加了其复杂性。Polyfills 几乎总是能够模拟它们为之构建的 CSS3 功能，但显然与原生实现有所不同。可能需要 Polyfill 向我们的页面注入额外的元素，或者添加 CSS 属性。因此，在开发页面时尽早添加这些库，并经常测试，以便捕捉开发页面和库之间的冲突，这是一个很好的经验法则。

# 嵌入 SVG

我们想要在支持的情况下使用**可缩放矢量图形**（**SVG**）而不是光栅图像。我们正在构建一个 ZUI，因此我们的信息图表需要进行缩放，使用矢量图形可以保持对象的质量。事实上，矢量图像是大小独立的，因此在缩放时不会出现像素化。

### 注意

有关矢量图像和 SVG 的更多信息可以在维基百科上找到[`en.wikipedia.org/wiki/Vector_graphics`](http://en.wikipedia.org/wiki/Vector_graphics)。

有三种嵌入 SVG 的方式：

+   作为`<object>`元素。这是添加 SVG 的最受支持的方式。然而，它在某种程度上受到限制，因为 SVG 被视为外部元素，因此不能通过 JavaScript 进行操作（除了一些明显的属性，如`width`和`height`）。

+   作为 CSS 的值，需要图像的地方。

+   直接在我们的 HTML 代码中。这种方法提供了 SVG 和页面之间最多的交互。正如我们将在本章后面看到的，我们可以直接从 CSS 或甚至从 JavaScript 与矢量图形进行交互。

让我们选择第三种方式，因为我们希望我们的 CSS 能够影响 SVG 图形的一部分。首先，让我们创建一个`div`元素，它将作为我们在本章前面创建的`<article>`中的 SVG 元素的容器：

```css
<article>
<div class="panel">

  <!-- place here the svg content -->

</div>
</article>
```

接下来，我们可以使用 jQuery 从`img`文件夹直接加载 SVG 文件到我们刚刚创建的容器中，只需在我们之前编写的`index.html`文件的`script`标签后添加几行：

```css
  <script>
    $(document).ready(function(){
      $('div.panel').load('img/infographic.svg' );
    });
  </script>
</body>
```

在这些行中，我们首先要求 jQuery 等待 DOM 准备就绪，然后将我们的 SVG 文件的内容加载到具有`.panel`类的`div`元素中。

现在我们可以添加一些 CSS 来使`div`元素在包含的`article`中垂直和水平居中。

这可能会很奇怪，因为只有 Webkit 浏览器和 IE9+似乎接受大小为`100%`的容器，所以我们必须区分这些浏览器和其他浏览器。因此，让我们在`application.css`中添加以下指令：

```css
div.panel{
  width: 572px;
  height: 547px;
}

.-webkit- div.panel, 
.-ms- div.panel {
  width: 100%;
  height: 100%;
}

img.panel{
  display: block;
  position: absolute;
  top: 50%; left: 50%;
  margin-top: -282px;
  margin-left: -273px;
}

html:not(.-webkit-):not(.-ms-) div.panel{
  display: block;
  position: absolute;
  top: 50%; left: 50%;
  margin-top: -282px;
  margin-left: -273px;
}
```

我们现在已经涵盖了所有可能的情况：

+   我们使用了 Prefix Free 的能力，向`<html>`元素添加了一个额外的类，以检测 Webkit 和 Microsoft 浏览器，并为这些浏览器设置容器大小为`100%`，以便获得尽可能大的 SVG 容器。

+   如果浏览器不是前一项讨论中的浏览器之一，我们将 SVG 居中对齐并设置固定大小

+   如果有图像而不是 SVG（我们马上会看到我们如何处理这个），我们基本上做与前一项相同的事情。

如果我们现在在浏览器中重新加载项目，我们可以看到 SVG 的显示：

![嵌入 SVG](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_07.jpg)

### 注意

由于我们使用了 AJAX，我们需要一个合适的 Web 服务器来尝试这个项目。只需双击`index.html`文件，不会生成预期的结果。请参考本书的*前言*部分，以获取有关如何安装 Web 服务器的更多信息。

当然，有些浏览器不支持 SVG。IE8 就是其中之一，因此我们需要找到一个解决方案，以便在这些浏览器上也能保持我们的项目愉快。

# 利用 Modernizr

在上一章中，我们已经对 Modernizr 有所了解，它是一个库，可以做很多事情，其中一些列在下面：

+   它为旧浏览器添加了对新 HTML5 标签的支持。

+   它在 JavaScript 中公开了一些方法，允许我们测试某个 CSS3/HTML5 功能。例如，`Modernizr.multiplebg`根据对多个背景的支持返回`true`或`false`。

+   它向`<html>`元素添加了一些类，反映了对某些 CSS3/HTML5 功能的支持。例如，根据对多个背景的支持，是`<html class="multiplebg">`还是`<html class="no-multiplebg">`。

我们已经将这个库添加到我们的项目中。但是，如果没有正确调整，Modernizr 会执行所有测试来检测支持的功能，即使我们不打算使用它们。为了增强库的性能，我们可以选择要执行哪些测试。

为此，我们必须单击 Modernizr 的下载页面（[`modernizr.com/download/`](http://modernizr.com/download/)），并仅检查我们将使用此库的功能。

对于这个项目，我们需要测试对内联 SVG 的支持。以下是屏幕截图，右侧的复选框已被选中：

![利用 Modernizr](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_08.jpg)

接下来，我们单击**生成！**按钮，然后单击**下载**按钮，以下载并覆盖我们项目中的`modernizr.js`文件。

我们现在可以检查我们项目的生成 HTML 代码，看看如果浏览器支持内联 SVG，则`html`元素如何被`inlinesvg`类丰富，否则是`no-inlinesvg`类。

### 提示

您可以使用浏览器的开发控制台检查生成的 HTML 代码。例如，如果使用 Google Chrome，按下*Ctrl* + *Shift* + *I*（在 Windows 和 Linux 上），或按下*Command* + *Option* + *I*（在 Mac 上）。

![利用 Modernizr](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_09.jpg)

我们现在要实现一个替代 SVG 图形的方法，使用普通图像；然后，通过利用 Modernizr 提供给我们的类，根据浏览器的支持切换其中一个。因此，让我们首先在`index.html`的`</article>`标签之前添加一个小的 HTML 片段：

```css
<img class="panel" src="img/infographic.png">
```

然后我们需要修改我们的`application.css`：

```css
.no-inlinesvg div.panel{
  display: none;
}

.inlinesvg img.panel{
  display: none;
}
```

如果我们现在在 IE8 中重新加载项目，我们可以看到一切都被正确处理了：

![利用 Modernizr](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_10.jpg)

# :target 伪选择器

现在我们可以开始为我们的项目添加一些交互。我们希望在`<header>`侧边栏中公开一些控件，当单击时，可以缩放到信息图表的指定区域。

为了实现这一点，我们将利用一个新的 CSS3 伪选择器：`:target`。当锚点成为当前 URL 的目标时，它会被激活。让我们创建一个小例子来尝试一下：

```css
<!doctype html>
<html>
  <head>
    <meta charset="utf8">
    <title> :target test</title>
    <link rel="stylesheet" type="text/css" 
href="http://yui.yahooapis.com/3.5.0/build/cssreset/
cssreset-min.css">

    <style>
    a[id]{
      display: block;
      width: 100px;
      height: 100px;
      text-align: center;
      line-height: 100px;
      margin: 10px;
      background: gray;
    }
 a:target{
 background: yellow;
 }
    </style>

    <script src="img/prefixfree.js"></script>
  </head>
  <body>
    <a href="#one"> light 1 </a>
    <a href="#two"> light 2 </a>
    <a id="one" name="one"> one </a>
    <a id="two" name="two"> two </a>
  </body>
</html>
```

在上面的例子中，我们基本上说当`a`元素成为当前 URL 的目标时，它的背景颜色必须变成黄色。下面的屏幕截图显示了结果（注意 URL）：

![:target 伪选择器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_11.jpg)

现在我们需要一组包含用户可以执行的命令的`a`元素。所以让我们在我们的`index.html`文件的`header`元素中添加一个`nav`元素：

```css
<nav>
  <ul>
    <li><a href="#italy">Italy</a></li>
    <li><a href="#montreal">Montreal</a></li>
    <li><a href="#sanfrancisco">San Francisco</a></li>
    <li><a href="#">Whole view</a></li>
  </ul>
</nav>
```

接下来，我们可以在我们的`application.css`文件中使用一些 CSS 指令来为这些命令设置样式：

```css
nav, ul, li{
  width: 100%;
}

h1{
  font-size: 16px;
  text-transform: uppercase;
  letter-spacing: -1px;
  font-weight: bold;
  line-height: 30px;
  text-align: center;
  padding: 10px 0 10px 0;
  color: rgb(255,255,255);
  background: rgb(85, 85, 85);
  margin-bottom: 10px;
}

li, li a{
  display: block;
  height: 30px;
  line-height: 30px;
}

li a{
  color: rgb(255,255,255);
  text-decoration: none;
  font-weight: bold;
  padding-left: 20px;
}

li a:hover{
  text-decoration: underline;
}
```

如果我们重新加载项目，我们可以看到结果：

![`:target`伪选择器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_12.jpg)

## 添加一些锚点

现在我们需要放置`a`元素，这些元素是我们刚刚实现的命令的目标。这里有一个小技巧：如果我们将这些元素放在页面顶部然后隐藏它们，我们可以使用邻接选择器（`+`和`~`）来匹配它们后面的元素，并能够虚拟地到达页面中的每个其他元素。

所以，让我们从在我们的`index.html`文件的`body`元素下方为我们指定的每个命令添加一个`a`元素开始：

```css
<a id="italy" name="italy"></a>
<a id="montreal" name="montreal"></a>
<a id="sanfrancisco" name="sanfrancisco"></a>
```

好了！现在，如果我们想在单击**Italy**命令后更改`header`背景颜色，我们可以在我们的 CSS 中添加一行简单的代码：

```css
a[id="italy"]:target ~ section header{
  background: green;
}
```

当然我们不想这样做，但是通过使用相同的原理，我们可以触发信息图的一些变化。首先我们必须学习有关变换的知识。

# CSS3 变换

我们将探索一整套新的属性，目标是能够使用 CSS 任意缩放元素。这是我们需要学习的最后一个核心技术，涉及的属性被称为**CSS3 变换**。

使用 CSS3 变换，我们可以对页面上的元素应用一些修饰符，即：

+   `translateX(x)`, `translateY(y)`, 和 `translate(x,y)`: 这些修饰符通过由`x`和`y`变量指定的距离沿一个或两个轴移动元素（以 px 为单位）

+   `rotate(deg)`: 它通过由`deg`变量指定的值旋转元素，该值必须以度数表示（从 0 到 360 度）

+   `scaleX(s)`, `scaleY(s)`, 和 `scale(s,[s])`: 它通过比例因子`s`缩放元素，其中比例为`1`表示保持元素大小不变

+   `skewX(k)` 和 `skewY(k)`: 它通过给定的`k`角度（以度数表示，从 0 到 360 度）应用倾斜变换

还有一个接受六个参数并让我们定义一个变换矩阵的`matrix`修饰符。有关`matrix`修饰符的更多信息可以在[`www.w3.org/TR/SVG/coords.html#TransformMatrixDefined`](http://www.w3.org/TR/SVG/coords.html#TransformMatrixDefined)找到。

让我们在一个小演示中尝试这些修饰符：

```css
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <title>transform test</title>
    <link rel="stylesheet" type="text/css" 
href="http://yui.yahooapis.com/3.5.0/build/cssreset/
cssreset-min.css">

    <style>
    div{
      width: 100px;
      height: 100px;
      background: green;
      margin: 30px auto;
    }
 div:first-child{
 transform: translateX(100px);
 }
 div:nth-child(2){
 transform: rotate(45deg);
 }
 div:nth-child(3){
 transform: scale(2);
 background: red;
 }
 div:nth-child(4){
 transform: skewX(45deg);
 }
 div:last-child{
 transform: skewY(45deg) scale(1.2) rotate(45deg);
 }
    </style>

    <script src="img/prefixfree.js"></script>
  </head>
  <body>
    <div>translate</div>
    <div>rotate</div>
    <div>scale</div>
    <div>skew</div>
    <div>mixed</div>
  </body>
</html>
```

正如你所看到的，变换可以组合在一起以获得一些有趣的结果。以下是在符合 CSS3 标准的浏览器中运行此演示的屏幕截图：

![CSS3 变换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_13.jpg)

### 注

另一个要注意的好功能是元素位置在应用变换之前进行计算。这一点的证明是缩放的`div`元素不会使其他元素向下移动，而只是重叠。

## 应用变换

现在我们只需要将我们刚学到的东西放在一起，并在点击其中一个命令时转换信息图。为了实现平滑的变换，让我们在`application.css`中的所有变换属性上指定一个`1`秒的过渡：

```css
.panel{
    transition: transform 1s;
}

/*
Now we can add these few instructions to trigger the transform when corresponding anchor became target of the current URL:
*/

a[id='italy']:target ~ section div.panel { 
  transform: scale(2) translateY(15%);
  -ms-transform: scale(2) translateY(15%);
}

a[id='montreal']:target ~ section div.panel{
  transform: scale(1.8) translate(24%, -21%);
  -ms-transform: scale(1.8) translate(24%, -21%);
}

a[id='sanfrancisco']:target ~ section div.panel{
  transform: scale(1.8) translate(-24%, -21%);
  -ms-transform: scale(1.8) translate(-24%, -21%);
}
```

好了！让我们在浏览器中重新加载项目：

![应用变换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_14.jpg)

## 闪烁问题

在撰写本文时，所有最新版本的 Chrome 浏览器（截至 18 版本）在应用某些 CSS 属性时会在 CPU 和 GPU 加速图形之间切换（其中包括过渡）。如果计算机处理不够快，这可能会在屏幕上产生闪烁。一种解决方法是在页面加载时强制 Chrome 应用 GPU 加速属性。在这种解决方案中，我们将在接下来的几章中看到的 3D 变换属性非常有用，因此我们可以向`body`元素添加一个空的`translateZ`属性，如下所示：

```css
body{
  -webkit-transform: translateZ(0);
}
```

然而，我们必须记住，这种解决方案降低了 SVG 的质量，因为 Chrome 似乎不会在加速后对图形进行细化。此外，像我们刚刚使用的这样的 3D 变换属性在移动环境中应该谨慎对待，因为它们占用内存。

# 添加蒙版

我们可能想为每个可用的缩放区域添加一个小的描述蒙版。在蒙版中，我们还希望用户能够使用小箭头在缩放区域之间移动。

首先让我们定义所需的 HTML：将有四个蒙版，一个用于三个命令中的每一个，一个用于中心区域。我们可以在`</section>`标签之后添加所需的标记：

```css
<div id="mask"> 
  <div data-detail="italy">
    <span>Help text. Click the arrows to explore more.</span>
    <menu>
      <a role="button" aria-label="move down" 
href="#italy2">&#x25BC;</a>
    </menu>
  </div>
  <div data-detail="italy2">
    <span>Help text. Click the arrows to explore more.</span>
    <menu>
      <a role="button" aria-label="move left" 
href="#montreal">>&#x25C4;</a>
      <a role="button" aria-label="move up" 
href="#italy">&#x25B2;</a><a role="button" aria-label="move right" href="#sanfrancisco">&#x25BA;</a>
    </menu>
  </div>
  <div data-detail="montreal">
    <span>Help text. Click the arrows to explore more.</span>
    <menu>
      <a role="button" aria-label="move right" 
href="#italy2">&#x25BA;</a>
    </menu>
  </div>
  <div data-detail="sanfrancisco">
    <span>Help text. Click the arrows to explore more.</span>
    <menu>
      <a role="button" aria-label="move left" 
href="#italy2">>&#x25C4;</a>
    </menu>
  </div>
</div>
```

现在我们必须将`#mask`元素放置在视口底线的下方，并在触发其中一个命令时激活它。因此，让我们在`application.css`中写入以下指令：

```css
#mask{
  position: absolute;
 padding-top: 5px;
  font-size: 18px; 
  font-weight: bold;
 height: 50px;
  color: rgb(255,255,255);
  background-color: rgb(0,0,0);
  background-color: rgba(0,0,0,0.8);
  text-align: center;
 bottom: -55px;
  left: 201px;
  right: 0;
}

#mask menu{
  position: absolute;
  padding: 0; margin: 0;
  bottom: 4px;
  left: 0;
  right: 0;
  text-align: center;
}

#mask div{
 display: none;
}

#mask a{
  text-decoration: none;
  color: rgb(255,255,255);
  padding: 0 10px;
}

a[id='montreal']:target ~ #mask div[data-detail="montreal"],
a[id='italy2']:target ~ #mask div[data-detail="italy2"],
a[id='italy']:target ~ #mask div[data-detail="italy"],
a[id='sanfrancisco']:target ~ #mask 
div[data-detail="sanfrancisco"]{
 display: block;
}

a[id='italy']:target ~ #mask,
a[id='italy2']:target ~ #mask,
a[id='montreal']:target ~ #mask,
a[id='sanfrancisco']:target ~ #mask{
 transition: bottom 1s;
 bottom: 0;
}

```

在代码的突出部分，我们指示浏览器：

+   隐藏`#mask`元素在浏览器底线以下

+   隐藏`#mask`元素内的所有`div`元素

+   仅显示与目标`a`元素对应的`#mask`元素内的`div`元素

+   当`a`元素是`:target`时，显示`#mask`元素

现在我们需要处理`italy2`锚点。因此，让我们在`index.html`中的`<section>`之前再添加一个`a`元素：

```css
<a id="italy2" name="italy2"></a>
```

以及在`application.css`中对应的 CSS：

```css
a[id='italy2']:target ~ section div.panel{
  transform: scale(2) translateY(-15%);
  -ms-transform: scale(2) translateY(-15%);
}
```

干得好！现在让我们在浏览器中重新加载项目：

![添加蒙版](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_15.jpg)

# 用 CSS 定位 SVG

好的，是时候做最后的修饰了。现在我们想要的是提供一个机制来切换信息图表标签的可见性。由于我们的 SVG 是内联的，我们可以通过简单地向它们的`id`选择器添加`opacity: 0`来关闭它们，就像我们对普通 HTML 元素所做的那样。因此，让我们在`application.css`中添加以下行：

```css
#Layer_2{ /* this id is present within the SVG */
  opacity: 0;
  transition: opacity 1s;
}
```

下一步是找到一种让用户切换`opacity`值的方法。我们可以使用复选框来实现这个结果，并利用`:checked`伪选择器，就像我们使用`:target`一样。

因此，首先让我们在`index.html`文件中的`<section>`标签之前添加一个复选框：

```css
<input type="checkbox" id="show_labels" name="show_labels">
```

然后，在`nav`命令的`</ul>`标签之前添加相应的标签：

```css
<li><label for="show_labels"></label></li>
```

现在在`application.css`中添加以下行：

```css
#show_labels{
 display: none;
}

nav label:before{
 content: 'Click to show labels';
}

#show_labels:checked ~ section label:before{
 content: 'Click to hide labels';
}

#show_labels:checked ~ section #Layer_2{
 opacity: 1;
}

label{
  text-align: left;
  font-family: sans-serif;
  padding-left: 20px;
  font-size: 13px;
  cursor: pointer;
}

nav label{
  display: block;
  height: 30px;
  line-height: 30px;
}

li:not(:nth-last-child(2)) a:after{
  content: " \00BB";
}

li:nth-last-child(2) a:before{
  content: "\00AB";
}
```

以下是我们项目的最终截图：

![用 CSS 定位 SVG](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_16.jpg)

# 优雅降级

因为我们添加了 CSS 变换，旧版浏览器开始出现问题。事实上，旧版浏览器不支持变换和`:target`伪选择器，因此我们必须找到一个有效的替代方案。一个解决方案可以是通过 JavaScript 监听 URL 哈希变化，并使用`hashchange`事件将当前哈希值反映到`section`和`#mask`元素的类中。然后可以使用这个类来触发一些 CSS 属性。

为了能够在旧版浏览器上监听`hashchange`事件，我们需要一个小的 JavaScript 库。我们可以从[`benalman.com/code/projects/jquery-hashchange/docs/files/jquery-ba-hashchange-js.html`](http://benalman.com/code/projects/jquery-hashchange/docs/files/jquery-ba-hashchange-js.html)下载它，将其重命名为`jquery.hashchange.js`，并放置在我们的`js`文件夹中。接下来，我们必须用一个包含**多重背景**测试的新版本替换我们的 Modernizr 副本(`js/modernizr.js`)。为了实现这一点，我们可以使用与之前讨论过的相同的过程。

现在我们需要插入这个库，然后在`</body>`标签之前添加一些小的 JavaScript 代码：

```css
<script src="img/jquery.hashchange.js"></script>
<script>
  $(document).ready(function(){
/* we check for multiblegbs support because browsers who do support multiple backgrounds surely support also the features we need */
    if(!Modernizr.multiplebgs){
      if(window.location.hash.substring(1) != "")
        window.location.href = window.location.href.replace(window.location.hash,'');
      jQuery(window).hashchange(function(e){
 $('section, #mask').removeClass().addClass(window.location.hash.substring(1));
      });
    }
  });
</script>
```

好了！现在我们可以通过改变`img.panel`元素的宽度、高度和位置来模拟`transform`属性。此外，我们还可以使用 JavaScript 动态添加的类来显示和隐藏`#mask`元素。

```css
.no-inlinesvg #mask{
  left: 0px;
}

.no-inlinesvg label{
  display: none;
}

#mask.montreal, #mask.sanfrancisco, #mask.italy, #mask.italy2{
  bottom: 0px;
}

#mask.montreal div[data-detail="montreal"], 
#mask.italy2 div[data-detail="italy2"], 
#mask.italy div[data-detail="italy"], 
#mask.sanfrancisco div[data-detail="sanfrancisco"]{
 display: block;
}

section.italy img.panel{
 top: 60%; left: 25%;
 width: 1000px;
 height: 1000px;
}

section.italy2 img.panel{
 top: 0%; left: 25%;
 width: 1000px;
 height: 1000px;
}

section.montreal img.panel{
 top: -10%; left: 50%;
 width: 1000px;
 height: 1000px;
}

section.sanfrancisco img.panel{
 top: -10%; left: 0%;
 width: 1000px;
 height: 1000px;
}

```

以下屏幕截图显示了最终结果：

![优雅降级](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_04_17.jpg)

# 总结

在本章中，我们学习了如何处理对我们页面结构产生影响的 CSS3 属性。我们还发现了转换，以及一些与 SVG 互动的酷炫方式。在下一章中，我们将讨论如何增强图库。


# 第五章：图库

图库现在是网站的常见组件。在本章中，我们将发现如何使用*仅*CSS 属性实现一系列过渡效果和几种导航模式。我们将首先实现一个基本的过渡效果，使用一系列图像，然后我们将开发一个纯 CSS 结构，让用户选择他喜欢的导航模式和过渡效果，最后，我们将添加更复杂的过渡效果。以下是本章将涵盖的主题列表：

+   基本图库 HTML 结构

+   实现不透明度过渡

+   实现幻灯片过渡

+   3D 变换

+   添加幻灯片模式

+   创建上一个和下一个箭头

+   CSS 预处理器

# 准备结构

与前几章一样，我们首先定义一个基本的 HTML 结构，然后在此基础上构建我们的项目。所以让我们为这个项目创建一个新的文件夹，其中包含一个名为`index.html`的文件，其中包含以下代码：

```css
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge" />
    <title>A 3D Gallery</title>
    <link rel="stylesheet" type="text/css" href="http://yui.yahooapis.com/3.7.3/build/cssreset/cssreset-min.css">
    <link rel="stylesheet" type="text/css" href="css/application.css">
    <script src="img/prefixfree.js"></script>
  </head>
  <body>
    <div>
      choose effect:
      <input type="radio" name="mode" id="opacity" checked >
      <label for="opacity">opacity</label>
      <input type="radio" name="mode" id="slidein">
      <label for="slidein">slidein</label>
      <input type="radio" name="mode" id="cube" >
      <label for="cube">cube</label>
      <br>
      choose mode:
      <input type="radio" name="controls" id="animate">
      <label for="animate">animate</label>
      <input type="radio" name="controls" id="bullets" checked>
      <label for="bullets">bullets</label>
      <input type="radio" name="controls" id="arrows">
      <label for="arrows">arrows</label>

      <a id="picture1" name="picture1"></a>
      <a id="picture2" name="picture2"></a>
      <a id="picture3" name="picture3"></a>
      <a id="picture4" name="picture4"></a>
      <a id="picture5" name="picture5"></a>
      <section>
        <ul>
          <li>
            <figure id="shot1"></figure>
          </li>
          <li>
            <figure id="shot2"></figure>
          </li>
          <li>
            <figure id="shot3"></figure>
          </li>
          <li>
            <figure id="shot4"></figure>
          </li>
          <li>
            <figure id="shot5"></figure>
          </li>
        </ul>
        <span>
          <a href="#picture1" ></a>
          <a href="#picture2" ></a>
          <a href="#picture3" ></a>
          <a href="#picture4" ></a>
          <a href="#picture5" ></a>
        </span>
      </section>
    </div>
  </body>
</hthiml>
```

与前几章一样，我们使用 Yahoo!重置 CSS 样式表以及 Lea Verou 的 Prefix Free 库。您可以从上一章的示例中复制`prefixfree.js`，或者从[`leaverou.github.com/prefixfree/`](http://leaverou.github.com/prefixfree/)下载它。

我们定义的结构包含一些单选按钮，分为`mode`和`controls`两组。在这个项目中，我们将学习如何改变我们的图库的行为，以反映我们的用户所做的选择。首先要实现的默认设置涉及不透明度过渡和基于项目符号的导航系统。

接下来有与我们想要显示的图像数量相等的锚点。然后，在一个`section`元素内，我们为每个图像有一个`figure`元素，并且有一个指向先前定义的锚点的`a`元素。

我们要实现的内容是在按下相应的`a`元素时激活特定图像。为此，我们将使用已经介绍的`:target`伪选择器与其他一些小技巧结合使用，但首先我们必须花一点时间定义基本的 CSS 结构。

## 应用基本 CSS

首先，我们必须将我们的项目居中在浏览器的视口中，然后稍微设计一下单选按钮。为此，我们在`application.css`中写入几行 CSS，如下所示：

```css
/* == [BEGIN] General == */

body,html{
  height: 100%;
  background-image: radial-gradient(center center, white, gray);
}
body > div{
  position: absolute;
  width: 500px;
  height: 400px;
  top: 50%; left: 50%;
  margin-left: -250px;
  margin-top: -200px;
  text-align: center;
  font-family: sans-serif;
  font-size: 13px;
  color: #444;
  line-height: 1.5;
}

section{
  margin-top: 20px;
  width: 500px;
  height: 390px;
  position: relative;
}

section > ul{
  width: 500px;
  height: 390px;
  position: relative;
}

input{
  width: 20px;
}

/* == [END] General == */
```

好了！现在让我们为每个`figure`元素分配相应的图像：

```css
/* == [BEGIN] Pics == */

section figure {
  position: absolute;
  top: 0px; left: 0px;
  width: 500px; height: 370px;
  padding: 0px; margin: 0px;
  background-position: center center;
}

#shot1{
  background-image: url('../img/picture1.jpg');
}
#shot2{
  background-image: url('../img/picture2.jpg');
}

#shot3{
  background-image: url('../img/picture3.jpg');
}

#shot4{
  background-image: url('../img/picture4.jpg');
}

#shot5{
  background-image: url('../img/picture5.jpg');
}

/* == [END] Pics == */
```

### 注意

请注意，在实际示例中，我们可能会通过`style`属性动态插入这些图像。

现在我们可以使用符合 CSS3 标准的浏览器测试此设置阶段的成功。在这一点上，我们还没有为单选按钮添加任何行为，所以我们只期望在`#shot5`中看到图像，而没有任何交互或动画。

![应用基本 CSS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_05_01.jpg)

## 样式化项目符号

让我们开始为`a`元素应用一些样式。我们首先创建了项目符号，因为它们是默认表示。我们的项目符号将显示为一组空心的可点击圆圈，就像在线幻灯片中经常发现的那样。我们可以为这些圆圈使用一些圆角边框，并在元素被点击时应用`background`规则。为了拦截这种状态，我们将在页面顶部插入的相应`a`元素上使用`:target`伪选择器。

```css
/* == [BEGIN] Span == */

section > span > a{
 display: inline-block;
  text-decoration: none;
  color: black;
  font-size: 1px;
  padding: 3px;
  border: 1px solid black;
  border-radius: 4px;
  font-weight: bold;
}

section > span{
  position: absolute;
  bottom: 0px;
  left: 0px;
  right: 0px;
  text-align: center;
}

a[name=picture1]:target ~ section a[href="#picture1"],
a[name=picture2]:target ~ section a[href="#picture2"],
a[name=picture3]:target ~ section a[href="#picture3"],
a[name=picture4]:target ~ section a[href="#picture4"],
a[name=picture5]:target ~ section a[href="#picture5"]{
 background: #111;
}

/* == [END] Span == */
```

我们决定将项目符号设置为`display:inline-block`，以便从此属性在元素标签之间留下一些空间时注入的空间中受益，就像我们在第三章中看到的那样，*Omni 菜单*。

接下来，我们使用`：target`伪选择器与相邻选择器`~`结合使用，定义一个规则，匹配指向当前锚点的项目符号。

现在一切准备就绪，我们可以开始处理我们的第一个过渡效果：不透明度。

# 实现不透明度过渡

透明度效果是最简单的，我们只需要通过`opacity:0`属性隐藏所有元素，除了对应于点击的子弹的元素。为了获得一个漂亮的淡出效果，我们可以使用`transition`属性指定两种状态之间的过渡期。

我们必须在这里实现的一个技巧是，只有在我们的设置面板中选择了**opacity**单选按钮时，才能附加这种行为。为了实现这一点，我们可以在规则之前放置另一个选择器`#opacity:checked`：

```css
/* == [BEGIN] Opacity == */

#opacity:checked ~ section figure{
  opacity: 0;
  transition: opacity 0.4s;
}

#opacity:checked ~ a:not(:target) + a:not(:target) + a:not(:target) + a:not(:target) + a:not(:target) ~ section #shot1,
#opacity:checked ~ a[name=picture1]:target ~ section #shot1,
#opacity:checked ~ a[name=picture2]:target ~ section #shot2,
#opacity:checked ~ a[name=picture3]:target ~ section #shot3,
#opacity:checked ~ a[name=picture4]:target ~ section #shot4,
#opacity:checked ~ a[name=picture5]:target ~ section #shot5{
  opacity: 1;
}

/* == [END] Opacity == */
```

我们基本上使用了与之前相同的技巧，再加上一个规则，如果没有选择任何子弹，则将`opacity:1`设置为第一张图像。为了实现这一点，我们使用`+`选择器来具体匹配五个连续的不是`:target`的`a`元素。

干得好！如果我们在浏览器中运行项目，我们可以测试效果，并注意到这只有在对应的单选按钮被选中时才会起作用。

![实现透明度过渡](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_05_01_2.jpg)

### 注

在继续之前的最后一点，我们为这个项目创建的选择器非常复杂，如果在大型应用程序中广泛使用，可能会引入性能问题。

是时候实现一个新的效果了：滑动！

# 实现滑动过渡

滑动效果基本上是一个过渡，其中一个元素在用户视图之外移动，向一个方向滑动，而另一个元素在移动。为了实现这种效果，我们必须处理两种不同的动画：滑入和滑出。使这种效果起作用的基本思想与之前的类似，尽管稍微复杂一些。为了实现滑入效果，我们必须将所有图片移出部分视口，比如`left:-500px`，然后，当对应的子弹被点击时，取出选定的图片，并使用一个动画将其移动到相反的一侧（`left:500px`），然后将其移动到正确的位置（`left:0`）。

为了实现滑动效果，我们可以使用另一个动画，从`left:0px`到`left:-500px`开始。以下是完整的 CSS 片段：

```css
/* == [BEGIN] Slide In == */

#slidein:checked ~ section > ul{
 overflow:hidden;
}

#slidein:checked ~ section figure{
  left: -500px;
  animation-name: slideout;
  animation-duration: 1.5s;
}

#slidein:checked ~ a:not(:target) + a:not(:target) + a:not(:target) + a:not(:target) + a:not(:target) ~ section #shot1,
#slidein:checked ~ a[name=picture1]:target ~ section #shot1,
#slidein:checked ~ a[name=picture2]:target ~ section #shot2,
#slidein:checked ~ a[name=picture3]:target ~ section #shot3,
#slidein:checked ~ a[name=picture4]:target ~ section #shot4,
#slidein:checked ~ a[name=picture5]:target ~ section #shot5{
  animation-name: slidein; 
  animation-duration: 1.5s;
  left: 0px;
}

@keyframes slidein{
 0% { left: 500px; }
 100% { left: 0px; }
}

@keyframes slideout{
 0% { left: 0px; }
 100% { left: -500px; }
}

/* == [END] Slide In == */
```

我们使用`overflow:hidden`来隐藏部分视口外的图像。`slideout`动画被添加到除选定元素之外的所有元素，因此当一个元素退出选定状态时，动画被激活并将元素平滑地移动到`left:-500px`。

以下是从支持 CSS3 的浏览器（例如 Chrome，Firefox，IE10 等）中截取的屏幕截图：

![实现滑动过渡](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_05_02.jpg)

现在我们准备编写第三个过渡效果的代码：立方体！但首先，为了更好地理解下一步，让我们花一些时间介绍 3D 变换的基础知识。

# 3D 变换

3D 变换在设计网站方面引入了一个重大飞跃。我们现在可以尝试在 3D 空间中移动和动画化元素，如`div`、`img`，甚至`video`，这些都受益于 GPU 加速（对于大多数浏览器）。一旦我们决定引入 3D 效果，我们必须处理的第一件事是**透视**。

我们为`perspective`属性设置的值告诉浏览器如何渲染在 z 轴上位置为 0（或未设置）的元素。例如，`perspective:300px`意味着 z=0（或未设置）的元素被绘制得好像它离视口有 300 像素远。当然，这会影响元素在旋转时的渲染方式。

接下来是一个有用的属性，其目的是告诉浏览器应用 3D 变换。这个属性叫做`transform-style`，它的值可以是`flat`或`preserve-3d`。当值为`flat`时，具有影响 x 或 y 轴旋转的变换的元素没有透视，但当值为`preserve-3d`时，它们实际上表现得像真正的 3D 表面。这个属性也适用于所有元素的子元素。

最后是变换。这里要使用的属性与 2D 变换相同，是`transform`，但有一些新的关键字可以作为值选择。

变换原点默认设置为 z = 0 的元素中心，但可以使用`transform-origin`属性进行调整。

有了这些概念，我们可以开始定义立方体效果，它基本上与滑动效果相同，但当然要利用 3D 变换机制。

```css
/* == [BEGIN] Cube == */

#cube:checked ~ section{
 perspective: 500px;
}

#cube:checked ~ section > ul{
 transform-style: preserve-3d;
}

#cube:checked ~ section figure{
 transform-origin: 250px 185px -250px;
 backface-visibility: hidden;
  transform: rotateY(-90deg);
  animation-name: cubeout;
  animation-duration: 1.5s;

}

#cube:checked ~ a:not(:target) + a:not(:target) + a:not(:target) + a:not(:target) + a:not(:target) ~ section #shot1,
#cube:checked ~ a[name=picture1]:target ~ section #shot1,
#cube:checked ~ a[name=picture2]:target ~ section #shot2,
#cube:checked ~ a[name=picture3]:target ~ section #shot3,
#cube:checked ~ a[name=picture4]:target ~ section #shot4,
#cube:checked ~ a[name=picture5]:target ~ section #shot5{
  animation-name: cubein;
  animation-duration: 1.5s;
  transform: rotateY(0deg);
}

@keyframes cubein{
  0%   { transform: rotateY(90deg); }
  100% { transform: rotateY(0deg); }
}

@keyframes cubeout{
  0%   { transform: rotateY(0deg); }
  100% { transform: rotateY(-90deg); }
}

/* == [END] Cube == */
```

我们将`perspective`和`transform-style`设置为要进行变换的父元素。然后我们定义一个原点，它位于`figure`元素的中心，但从视口中偏移了 250 像素。

然后我们应用绕 y 轴旋转的变换，使用与我们之前使用`slidein`动画相同的机制。

最后，我们告诉浏览器在图片旋转到用户视角的相反方向时不显示图片。这是通过`backface-visibility: hidden`语句实现的。

在浏览器中快速刷新，结果如下：

![3D 变换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_05_03.jpg)

### 注意

如果运行浏览器的 PC 硬件没有 GPU，Chrome 会自动禁用 3D 效果。要检查是否触发了这种行为，可以在地址栏中输入`about:GPU`。

# 添加幻灯片放映模式

现在我们准备实现剩下的两种模式：幻灯片放映和箭头。让我们从幻灯片放映开始。在这里，我们只需为每种效果（**不透明度**、**滑入**和**立方体**）定义一个动画，并触发它，注意为每个`figure`元素指定不同的延迟（使用`animation-delay`属性）。

让我们从最后一部分开始，为每个`figure`元素定义不同的延迟：

```css
/* == [BEGIN] Animation == */

#animate:checked ~ section #shot1{
  animation-delay: 0s;
}

#animate:checked ~ section #shot2{
  animation-delay: 2.5s;
}

#animate:checked ~ section #shot3{
  animation-delay: 5s;
}

#animate:checked ~ section #shot4{
  animation-delay: 7.5s;
}

#animate:checked ~ section #shot5{
  animation-delay: 10s;
}

#animate:checked ~ section span{
 display: none;
}

```

如果每个动画持续 4 秒（1.5 秒用于动画进入，1 秒保持不动，1.5 秒用于动画退出），我们需要第二个`figure`元素在 2.5 秒后开始，正好在第一个元素开始退出动画时。在本章后面，我们将学习如何使此 CSS 代码适应不同数量的图片。

然后我们为剩下的`figure`元素重复这一步骤，并得到之前的代码。

高亮部分用于隐藏子弹，因为在幻灯片放映期间它们是不必要的。

好了！现在我们要写动画。让我们从不透明度动画开始：

```css
/* opacity animation */
#opacity:checked ~ #animate:checked ~ section #shot1,
#opacity:checked ~ #animate:checked ~ section #shot2,
#opacity:checked ~ #animate:checked ~ section #shot3,
#opacity:checked ~ #animate:checked ~ section #shot4,
#opacity:checked ~ #animate:checked ~ section #shot5{
  opacity: 0;
 animation-name: opacity;
 animation-duration: 12.5s;
 animation-iteration-count: infinite;
}

@keyframes opacity{
  0%    { opacity: 0; }
  12%   { opacity: 1; }
  20%   { opacity: 1; }
  32%   { opacity: 0; }
  100%  { opacity: 0; }
}
```

我们必须检查**不透明度**和**动画**单选按钮是否都被选中。在这种状态下，我们可以将动画设置为`opacity`，并选择持续时间为最后一个`figure`元素`#shot5`的`animation-delay`属性的值（10 秒）加上其动画时间（4 秒），减去此动画与上一个动画重叠的时间（1.5 秒）。

接下来，我们定义一些关键帧，将时间转换为百分比（例如，12.5 秒的 12% = 1.5 秒）。

我们也可以轻松地将此行为扩展到剩下的两个动画，如下所示：

+   对于滑动效果，我们从可见区域外开始，然后将其移动直到完全可见。最后，一段时间后，我们再次将其移出可见区域，但是从另一侧。

```css
/* slide animation */
#slidein:checked ~ #animate:checked ~ section #shot1,
#slidein:checked ~ #animate:checked ~ section #shot2,
#slidein:checked ~ #animate:checked ~ section #shot3,
#slidein:checked ~ #animate:checked ~ section #shot4,
#slidein:checked ~ #animate:checked ~ section #shot5{
  left: -500px;
  animation-name: slide;
  animation-duration: 12.5s;
  animation-iteration-count: infinite;
}

@keyframes slide{
  0%    { left: 500px; }
  12%   { left: 0px;   }
  20%   { left: 0px;   }
  32%  { left: -500px;}
  100%  { left: -500px;}
}
```

+   对于旋转立方体效果，我们基本上做同样的事情，但是不使用`left`属性，而是使用`transform: rotate()`，而不是将图片滑入（-500 像素，然后 0 像素，最后 500 像素），我们旋转立方体（90 度，然后 0 度，最后-90 度）。

```css
/* cube animation */
#cube:checked ~ #animate:checked ~ section #shot1,
#cube:checked ~ #animate:checked ~ section #shot2,
#cube:checked ~ #animate:checked ~ section #shot3,
#cube:checked ~ #animate:checked ~ section #shot4,
#cube:checked ~ #animate:checked ~ section #shot5{
  transform: rotateY(-90deg);
  transition: none;
  animation-name: cube;
  animation-duration: 12.5s;
  animation-iteration-count: infinite;
}

@keyframes cube{
  0%    { transform: rotateY(90deg); }
  12%   { transform: rotateY(0deg);  }
  20%   { transform: rotateY(0deg);  }
  32%  { transform: rotateY(-90deg);}
  100%  { transform: rotateY(-90deg);}
}

/* == [END] Animation == */
```

# 上一页和下一页箭头

好的，接下来是最棘手的部分：创建箭头。为了完成这个任务，我们要做的是：

1.  使用 CSS 将每个子弹转换为箭头符号，改变其形状并使用漂亮的背景图像。

1.  将所有箭头移动到图片的左侧，依次排列。这样，唯一可见的箭头将是与最高索引图片对应的箭头。

1.  隐藏与所选图片对应的箭头。

1.  将所有跟随所选图片对应的箭头移动到右侧，一个在另一个上面。这样，左侧将只保留那些对应于所选图片索引低于所选图片的箭头（例如，如果我们选择第三张图片，只有第一张和第二张图片的箭头会留在左侧，第二张图片的箭头会位于堆栈的顶部）。

1.  选择跟随所选图片的箭头，并更改其`z-index`值，以将其放在右侧堆栈的顶部。

以下是相应的 CSS 代码：

```css
/* == [BEGIN] Arrows == */

#arrows:checked ~ section span{
  position: static;
}

/* step 1 and 2: transform each bullet in an arrow sign and move all the arrows to the left of the picture */
#arrows:checked ~ section a{
  display: block;
  width: 50px; height: 50px;
  background-image: url('../img/freccie.png');
  background-repeat: no-repeat;
  background-color: #000;
  background-position: -50px 0px;
  position: absolute;
  padding: 0;
  top: 50%;
  margin-top: -25px;
  margin-left: -70px;
  left: 0;
}

#arrows:checked ~ section a:hover{
  background-color: #333;
}

/* step 3: hide the arrow corresponding to the selected image */
#arrows:checked ~ a[name=picture1]:target ~ section a[href="#picture1"],
#arrows:checked ~ a[name=picture2]:target ~ section a[href="#picture2"],
#arrows:checked ~ a[name=picture3]:target ~ section a[href="#picture3"],
#arrows:checked ~ a[name=picture4]:target ~ section a[href="#picture4"],
#arrows:checked ~ a[name=picture5]:target ~ section a[href="#picture5"]{
 display: none;
}

/* step 4: Move all the arrows that follow the one corresponding to the selected image to the right, one above another */
#arrows:checked ~ a[name=picture1]:target ~ section a[href="#picture1"] ~ a,
#arrows:checked ~ a[name=picture2]:target ~ section a[href="#picture2"] ~ a,
#arrows:checked ~ a[name=picture3]:target ~ section a[href="#picture3"] ~ a,
#arrows:checked ~ a[name=picture4]:target ~ section a[href="#picture4"] ~ a,
#arrows:checked ~ a[name=picture5]:target ~ section a[href="#picture5"] ~ a{
 display: block;
 position: absolute;
 margin-right: -70px;
 right: 0;
 left: auto;
}
/* step 5: Pick the arrow that follows the one corresponding to the selected image and change its z-index in order to put it on top of the right stack */
#arrows:checked ~ a[name=picture1]:target ~ section a[href="#picture1"] + a,
#arrows:checked ~ a[name=picture2]:target ~ section a[href="#picture2"] + a,
#arrows:checked ~ a[name=picture3]:target ~ section a[href="#picture3"] + a,
#arrows:checked ~ a[name=picture4]:target ~ section a[href="#picture4"] + a,
#arrows:checked ~ a[name=picture5]:target ~ section a[href="#picture5"] + a{
 background-position: 0px 0px;
 z-index: 20;
}

/* == [END] Arrows == */
```

以下截图显示了结果：

![上一个和下一个箭头](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_05_04.jpg)

# CSS 预处理器

在这一部分，我们将尝试解决这个项目的最大问题：整个样式表严重依赖于画廊中显示的图片数量。每个效果都围绕着这个数字定制，因此添加新图片可能会在我们的 CSS 中引起大量工作。

为了解决这个问题，我们可以使用**CSS 预处理器**，它可以让我们创建一个文件，使用一种包含一些便利设施的语言，比如循环和变量，并且可以编译成 CSS 样式表。

我们将在这个项目中使用 Sass。要安装它，您需要首先安装 Ruby（[`www.ruby-lang.sorg/en/downloads/`](http://www.ruby-lang.sorg/en/downloads/)），然后在项目目录中的终端模拟器中键入`gem install sass`（根据您的操作系统，您可能需要使用`sudo gem install sass`）。

安装完成后，由于 SCSS 是 CSS3 的*超集*，我们可以通过复制`css/application.css`的内容创建一个`scss/application.scss`文件。

接下来，我们可以在整个代码前面添加一个变量，以包含我们的画廊当前拥有的图片数量：

```css
/* == [BEGIN] Variables == */

$number_of_images: 5;

/* == [END] Variables == */

/* ... rest of CSS ... */
```

现在，每当在 CSS 中遇到类似以下结构的情况时：

```css
a[name=picture1]:target ~ section a[href="#picture1"],
a[name=picture2]:target ~ section a[href="#picture2"],
a[name=picture3]:target ~ section a[href="#picture3"],
a[name=picture4]:target ~ section a[href="#picture4"],
a[name=picture5]:target ~ section a[href="#picture5"]{
  background: #111;
}
```

我们可以改变代码，使其根据`$number_of_images`生成正确数量的选择器：

```css
@for $i from 1 through $number_of_images {
 a[name=picture#{$i}]:target ~ section a[href="#picture#{$i}"]{
 background: #111;
 }
}

```

## 处理特殊情况

不过，还有一些特殊情况，其中之一是当我们遇到一个包含一个字符串令牌重复次数等于图片数量的 CSS 选择器时。例如，以下一行 CSS：

```css
#opacity:checked ~ a:not(:target) + a:not(:target) + a:not(:target) + a:not(:target) + a:not(:target) ~ section #shot1,
```

要将上述代码转换为其变量驱动的版本，我们必须创建一个函数，一个返回字符串的小段代码。我们可以将其写在变量声明的上方，如下所示：

```css
/* == [BEGIN] Function == */

@function negate-a-times($n) {
 $negate: unquote("");
 @for $i from 1 through $n - 1 {
 $negate: append($negate, unquote("a:not(:target) + "), space);
 }
 @return $negate + unquote("a:not(:target)")
}

/* == [END] Function == */

```

现在我们可以定义一个新变量，其中包含字符串`a:not(:target)`重复的次数等于我们画廊中的图片数量。因此，`.scss`文件中的新变量部分将如下所示的 CSS 片段：

```css
* == [BEGIN] Variables == */

$number_of_images: 5;
$negate_images: negate-a-times($number_of_images);

/* == [END] Variables == */
```

最后，之前的 CSS 片段可以转换为：

```css
#opacity:checked ~ #{$negate_images} ~ section #shot1,

```

我们还需要注意的一件事是我们动画的时机。我们必须动态计算动画的总持续时间以及三个关键帧的百分比（进入动画，静止和退出动画），从我们画廊中的图片数量开始。为此，我们必须在`application.scss`文件的`Variables`部分结束之前定义一些额外的变量：

```css
$animation_duration: 2.5 * $number_of_images;
$enter_animation: 0% + (1.5 / $animation_duration) * 100;
$still: 0% + (2.5 / $animation_duration) * 100; 
$exit_animation: 0% + (4 / $animation_duration) * 100;
$animation_duration: $animation_duration + 0s;

/* == [END] Variables == */
```

在前面的几行中，我们定义了动画的总持续时间，然后将动画的时间（1.5 秒动画进入，1 秒静止，1.5 秒动画退出）转换为百分比。

最后但同样重要的是，我们必须遍历我们的`.scss`代码，并将每个`animation-duration: 12.5s;`转换为`animation-duration: $animation_duration;`。我们还必须将`@keyframes opacity`，`@keyframes slide`和`@keyframes cube`更改为以下内容：

```css
@keyframes opacity{
  0%    { opacity: 0; }
 #{$enter_animation}   { opacity: 1; }
 #{$still}             { opacity: 1; }
 #{$exit_animation}    { opacity: 0; }
  100%  { opacity: 0; }
}
@keyframes slide{
  0%    { left: 500px; }
 #{$enter_animation} { left: 0px; }
 #{$still}           { left: 0px; }
 #{$exit_animation}   { left: -500px; }
  100%  { left: -500px; }
}
@keyframes cube{
  0%    { transform: rotateY(90deg); }
 #{$enter_animation}   { transform: rotateY(0deg); }
 #{$still}              { transform: rotateY(0deg); }
 #{$exit_animation}    { transform: rotateY(-90deg); }
  100%  { transform: rotateY(-90deg); }
}
```

### 注意

`application.scss`文件的完整版本可在项目的源代码中找到。

要将我们的`application.scss`文件编译成`application.css`，我们可以在项目的根目录中使用终端模拟器调用以下命令：

```css
sass scss/application.scss:css/application.css

```

通过使用这些简单的翻译规则，我们可以将我们的 CSS 转换成非常灵活的 SCSS。为了证明这一点，我们可以尝试从 HTML 中删除一个`figure`元素（及其相应的`a`元素），将`$number_of_images:`更改为`4`，重新编译`application.scss`，然后注意整个项目如何保持平稳运行。

# 对于旧版浏览器的支持

Internet Explorer 9 或更低版本不支持 CSS3 过渡，也不支持 CSS3 3D 变换，因此这个项目几乎无法在这些浏览器上模拟。然而，我们可以实现基本的图片导航，同时隐藏所有其他选项。为了实现这一点，让我们再次利用条件注释，并用以下行替换`<html>`：

```css
<!--[if lte IE 9]> <html class="lteie9"> <![endif]-->
<!--[if !IE]> --> <html> <!-- <![endif]-->
```

接下来，我们需要为项目中使用的一些 CSS3 选择器添加对 Internet Explorer 8 的支持。为此，我们必须添加一个名为 Selectivizr（[`selectivizr.com/`](http://selectivizr.com/)）的库，该库使用 JavaScript 来支持大多数新的 CSS3 选择器。Selectivizr 依赖于 jQuery，所以我们也需要添加它。最后，我们需要使用一个 polyfill 来使 Internet Explorer 8 支持新的 HTML5 元素。以下是插入这三个库所需的代码片段，我们需要在`index.html`的`head`部分的末尾之前添加它：

```css
<!--[if lte IE 8]> 
<script src="img/html5.js"></script>
<script src="img/jquery.min.js"></script>
<script src="img/selectivizr-min.js"></script>
<![endif]-->
```

最后，我们可以添加一些 CSS 行来隐藏除第一个`figure`元素之外的所有内容，当`.lteie9`类存在时。此外，我们可以利用 Sass 来触发所选项目对应的`figure`元素上的`display:block`。

```css
/* == [BEGIN] Old Browser == */

.lteie9 body > div > span, 
.lteie9 body > div > input, 
.lteie9 body > div > br, 
.lteie9 body > div > label, 
.lteie9 figure{
  display: none;
}

.lteie9 #{$negate_images} ~ section #shot1{
  display: block;
}

@for $i from 1 through $number_of_images {
  .lteie9 a[name=picture#{$i}]:target ~ section #shot#{$i}{
    display: block;
  }
}

/* == [END] Old Browser == */
```

# 总结

CSS3 提供了新的简化方法来创建令人惊叹的画廊，而无需使用 JavaScript。可以理解的是，这些技术不适用于旧的非 CSS3 兼容浏览器，但我们可以检测这些浏览器并创建备用解决方案。

在本章中，我们看到了如何仅使用 CSS3 就可以创建出色的交互机制。此外，我们还发现了一种从更灵活的语言静态生成 CSS 的好方法。

最后但并非最不重要的是，我们尝试了三种很酷的动画效果。这些效果可以很容易地混合使用，或者可以通过例如将`rotateX`更改为`rotateY`，或者将`left`更改为`top`来创建新的效果。在下一章中，我们将探讨如何获得有趣的视差效果。


# 第六章：视差滚动

什么是**视差滚动**？视差滚动是一种视觉效果技术，试图通过移动场景中具有不同速度的元素来实现深度感，以响应用户的操作，比如网页的滚动。这种技术自 80 年代以来在 2D 视频游戏行业被广泛使用。

在本章中，我们将发现如何通过视差滚动和其他对页面滚动响应的酷炫效果来增强我们的网站。为了实现这一点，我们将深入一些高级的——有时是实验性的——CSS 3D 技术，并学习如何有效处理透视。

由于一些实现差异，我们将重点关注如何在不同的布局引擎（如 WebKit 和 Gecko）上获得类似的效果。

如果您正在使用 Windows 操作系统并且使用 Chrome，如果由于缺少或不支持的 GPU 而导致 CSS 3D 效果不如预期，您可能需要切换到 Firefox（或 IE10）。为了检查这一点，我们可以从 Chrome 浏览器中导航到**about:gpu**，并检查**3D CSS**复选框是否已启用。

本章涵盖的主题如下：

+   发现透视

+   创建一个立方体

+   透视原点

+   CSS 3D 视差

+   布局引擎之间的差异

+   在页面滚动时改变视差

+   创建一个支持视差的图库

# 发现透视

正如我们在上一章中开始探索的那样，CSS3 引入了在三维空间中移动我们的 HTML 元素的可能性。我们现在可以沿着 x、y 和 z 三个轴移动和旋转它们。虽然处理围绕 x 和 y 轴的运动相当容易理解，但当 z 轴出现时，情况就变得有些混乱。

沿着 z 轴移动一个元素意味着使其离我们的视点更近或更远，但这个动作有一些隐藏的问题，例如，接下来看下面的陈述：

```css
#element{
  transform: translateZ(100px);
}
```

我们如何想象将一个以像素为单位测量的距离的对象向我们移动？为了解决这个困境，W3C 引入了一个称为`perspective`的属性，基本上告诉浏览器我们从什么距离观察页面。

因此，如果我们将`500px`设置为透视属性，放置在 z 轴上距离为`250`像素的对象将看起来是原来的两倍大，而放置在 z 轴上距离为`500`像素的对象将看起来是原来的一半大。

让我们通过一个小例子来尝试一下：

```css
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>experimenting with perspective</title>

  <style>

  body{
 perspective: 500px;
    transform-style: 'preserve-3d';
  }

  #red-square{
    margin: auto;
    width: 500px;
    height: 500px;
    background: red;
    transform: rotateX(40deg);
  }

  </style>

  <script src="img/prefixfree.js"></script>

</head>
<body>

  <div id="red-square"></div>

</body>
</html>
```

如果我们在支持 CSS 3D 特性的浏览器（如 Chrome、Firefox 或 IE10）中运行此代码，我们将注意到与以下截图中显示的结果类似的结果：

![发现透视](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_06_1.jpg)

增加`perspective`属性的值，结果看起来会更扁平，另一方面，如果减少这个属性，红色的框看起来会被拉伸到地平线上。这里有一个`perspective: 250px`的例子：

![发现透视](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_06_2.jpg)

## 创建一个立方体

为了更好地理解一些`perspective`属性，我们可以利用我们到目前为止学到的知识，仅使用 CSS 创建一个真正的 3D 立方体。我们需要六个`div`标签，每个面一个，再加上一个作为其他面的容器：

```css
<!doctype html>
<html>
  <head>
    <meta charset="utf-8">
    <title>A cube</title>

    <style>

    body, html{
      height: 100%;
      width: 100%;
    }

    </style>

    <script src="img/prefixfree.js"></script>
  </head>
  <body>
    <div id="container">
      <div class="square back"></div>
      <div class="square bottom"></div>
      <div class="square right"></div>
      <div class="square left"></div>
      <div class="square top"></div>
      <div class="square front"></div>
    </div>
  </body>
</html>
```

首先，我们必须将一些属性应用于`#container`选择器；让我们在已经定义的`style`标签中插入以下一段 CSS 代码：

```css
    #container{
      perspective: 500px;
      backface-visibility: visible;
      transform-style: 'preserve-3d';	
      position: relative;
      height: 100%;
      width: 100%;
    }
```

在这里，我们告诉浏览器，容器内的内容必须考虑到 z 轴上的位置进行渲染，并且我们为`#container`选择器和容器内的元素设置了`perspective`属性为`500px`。最后但同样重要的是，我们要求浏览器也渲染我们将用来创建立方体的`div`标签的后面。

好的，现在让我们创建面。我们可以从`.square`的一些基本属性开始：

```css
.square{
  transform-style: 'preserve-3d';	
  position: absolute;
  margin: -100px 0px 0px -100px;
  top: 50%;
  left: 50%;
  height: 200px;
  width: 200px;;
}
```

好的，现在每个正方形都放在另一个上面，我们可以开始逐个调整它们。让我们从`.back`开始，我们必须将其从相机移开到一半大小，所以将`transform`属性设置为`-100px`：

```css
    .back{
      background: red;
      transform: translateZ(-100px);
    }
```

接下来我们看`.left`。在这里，我们首先必须对其 y 轴应用旋转，然后将其向左移动一半大小。这是因为除非另有说明，否则每个转换都是以元素中心为原点；另外，我们必须记住转换是按顺序应用的，所以元素必须沿其 z 轴进行平移，以获得正确的结果：

```css
    .left{
      background: blue;
      transform: rotateY(90deg) translateZ(-100px);
    }
```

这是一个提醒我们迄今为止取得的进展的屏幕截图：

![创建一个立方体](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_06_3.jpg)

我们可以用相同的策略处理所有剩余的面：

```css
    .right{
      background: yellow;
      transform: rotateY(-90deg) translateZ(-100px);
    }

    .front{
      background: green;
      transform: translateZ(100px);
    }

    .top{
      background: orange;
      transform: rotateX(-90deg) translateZ(-100px);
    }

    .bottom{
      background: purple;
      transform: rotateX(90deg) translateZ(-100px);
    }
```

如果我们现在尝试对这个实验进行截图（如图所示），我们可能会遇到一点小失望：

![创建一个立方体](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_06_4.jpg)

`.front`选择器的`div`标签覆盖了所有其他`div`标签。这个小实验向我们展示了一个场景的消失点默认设置为持有`perspective`属性的元素的中心。

## 透视原点属性

幸运的是，我们可以使用`perspective-origin`属性轻松改变消失点，该属性接受两个值，可以用所有常见的 CSS 测量单位或使用文字表达，就像`background-position`一样。

所以我们将把以下内容添加到`#container`：

```css
perspective-origin: top left;
```

并获得类似于这里显示的结果：

![透视原点属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_06_5.jpg)

如果我们调整浏览器窗口大小，我们还会注意到消失点会改变，因为它与`#container`选择器相关联，该选择器的`width`和`height`属性设置为与浏览器视口相等。

这种行为是我们将在下一章中用来构建视差项目的技巧的根源。

# CSS 3D 视差

好了，现在我们有了开始构建项目所需的工具。我们要创建的基本想法是，如果我们将元素放置在不同的高度并在保持消失点在可见区域中心的情况下滚动，那么我们就可以获得一个很酷的视差滚动效果。

像往常一样，我们首先需要一个 HTML 结构，所以让我们从这里开始。让我们创建带有以下代码的`index.html`文件：

```css
<!doctype html>
<html>
  <head>
  <meta charset="utf-8">	
<link href='http://fonts.googleapis.com/css?family=Bowlby+One+SC' rel='stylesheet' type='text/css' data-noprefix>
    <link rel="stylesheet" type="text/css" href="http://yui.yahooapis.com/3.5.1/build/cssreset/cssreset-min.css" data-noprefix>
    <link rel="stylesheet" type="text/css" href="css/application.css">

    <script src="img/prefixfree.js"></script>
    <script src="img/jquery.min.js"></script>

  </head>
  <body>

    <div id="body">
      <div id="container">

      </div>
    </div>

  </body>
</html>
```

除了这个页面，我们还必须创建一个名为`css/application.css`的文件，其中将保存我们的 CSS 属性和选择器。就像我们在之前的例子中所做的那样，我们将`#body`拉伸到适合浏览器视口的大小，所以我们可以在`application.css`中添加几行 CSS 代码：

```css
body,html{
  height: 100%;
}

#body{
  height: 100%;
 overflow-y: auto;
 overflow-x: hidden;
}
```

我们还向元素添加了`overflow-y: auto`和`overflow-x: hidden`，我们将在一会儿讨论这些将如何有用。

## 在 WebKit 中实现视差滚动

好的，在继续之前，我们现在必须一次专注于一个布局引擎；这是因为在 WebKit 和 Firefox 之间关于实现 CSS 3D 属性的一些差异，所以我们必须分别处理这两种情况。让我们从 WebKit 开始。

我们可以利用 Lea Verou 的 Prefix Free 自动放在插入页面的`html`元素上的一个整洁的类。这个类的名称与浏览器所需的实验性前缀相同；所以如果我们从 Internet Explorer 查看页面，类是`-ms-`，如果从 Firefox 查看，它是`-moz-`。

所以我们可以开始向`#body`添加`perspective`和`transform-style`属性，就像我们在之前的例子中所做的那样：

```css
.-webkit- #body{
  perspective: 500px;
  transform-style: preserve-3d;
}
```

现在我们必须处理`#container`选择器；这必须比视口更长——和往常一样，用于此项目的所有图像都位于 Packt Publishing 网站上（[www.packtpub.com](http://www.packtpub.com)）：

```css
#container{
  background-image: url('../img/grass.png');
  text-align: center;
  padding-bottom: 300px;
  /* to be removed when we'll have content */
min-height: 1000px;
}
```

由于我们已经将`overflow`属性应用于`#body`，我们在浏览器中看到的滚动条并不属于整个 HTML 文档，而是属于`#body`。

但`#body`也有一个`perspective`属性；这意味着包含元素的消失点始终位于浏览器屏幕的中心，因此我们已经实现了我们在本章开头希望实现的结构。

为了测试我们的代码，我们可以在容器内添加一些元素并分配它们不同的高度：

```css
<div id="body">
  <div id="container">

  <!-- EXPERIMENT -->
    <img class="experiment1" src="img/pic1.jpg">
    <img class="experiment2" src="img/pic2.jpg">

  </div>
</div>
```

我们可以使用`transform: translateZ();`来设置高度：

```css
.experiment1{
  transform: translateZ(10px);
}

.experiment2{
  transform: translateZ(150px);
}
```

好了，现在我们可以在符合 WebKit 标准的浏览器中测试我们到目前为止所做的事情：

![在 WebKit 中实现视差滚动](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_06_6.jpg)

在滚动时，我们可以注意到第二张图片——离我们视点最近的图片——移动得比第一张图片快。我们刚刚在 WebKit 上实现了视差！

## 在 Gecko 中实现视差滚动

Gecko 和 WebKit 之间存在一些微妙的实现差异，以及一些错误。

首先，在 Gecko 中的`transform-style: preserve-3d`属性不会传播到匹配元素的所有后代，而只会传播到一级子元素。`perspective`和`perspective-origin`属性也是如此。

幸运的是，我们可以找到解决这个问题的方法。例如，可以通过将`perspective`表达为一个转换来实现：

```css
transform: perspective(500px);
```

当我们使用这种方法时，`perspective-origin`就不再有用了，应该用`transform-origin`代替。在 Gecko 内核的浏览器上这样强加`perspective`会导致与在 WebKit 内核的浏览器上使用 perspective 时相同的行为。

所以我们可以添加几行 CSS 代码，使用与我们在 WebKit 中所做的相同策略：

```css
.-moz- #container{
  transform: perspective(500px);
  transform-style: preserve-3d;	
}
```

如果我们现在打开 Firefox 并测试我们的项目，我们会看到类似这样的东西：

![在 Gecko 中实现视差滚动](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_06_7.jpg)

尽管结果看起来与 WebKit 获得的结果相似，但在这种情况下滚动页面不会产生任何视差效果。经过快速分析，我们可能会认为这种行为是由于将`transform: perspective`属性放在了错误的元素（`#container`而不是`#body`）上导致的，但事实是我们有意选择这样做是因为一个微妙的错误（[`bugzilla.mozilla.org/show_bug.cgi?id=704469`](https://bugzilla.mozilla.org/show_bug.cgi?id=704469)）会从具有`overflow`属性的元素中移除`transform: perspective`属性。

所以现在使 Gecko 内核的浏览器表现如预期的唯一方法是实现一小段 JavaScript 代码，可以动态修改我们的消失点，使其保持在浏览器窗口的中心。

这个脚本必须根据滚动事件调整`transform-origin`属性：

```css
<script>
  $(document).ready(function(){
    if($.browser.mozilla){
      $('#body').scroll(function(event){
        var viewport_height = $(window).height(),
          body_scrolltop = $('#body').scrollTop(),
          perspective_y = body_scrolltop + Math.round( viewport_height / 2 );

        $('#container').css({
          'transform-origin': 'center ' + perspective_y + "px",
          '-moz-transform-origin': 'center ' + perspective_y + "px",
        });
      })
    }
  });
</script>
```

完美！现在 Gecko 内核的浏览器也会表现如预期。

## 在 Internet Explorer 中实现视差滚动

Internet Explorer 9 不支持 CSS 3D 变换，但 IE10 支持，所以我们也可以尝试在该浏览器上运行这个项目。为了在 IE10 上实现正确的行为，我们必须应用一些自定义属性；这是因为 IE10 的行为与其他两个浏览器的行为略有不同。

基本上 IE10 支持`perspective`和`transform: perspective`属性，但前者只对具有此属性的元素的直接后代产生影响，后者只对具有该属性的元素起作用。

所以我们必须采用一种更接近 Gecko 内核的行为，但使用`perspective`代替`transform: perspective`。这里是：

```css
.-ms- #container{
  perspective: 500px;
}
```

现在我们还需要稍微改变我们的 JavaScript 代码，以便在浏览器是 Internet Explorer 并支持 3D 变换时影响`perspective-origin`。以下是可以用来代替先前代码的代码：

```css
// == for Firefox and MSIE users ==
$(document).ready(function(){
  if($.browser.mozilla || ( $.browser.msie&& Modernizr.csstransforms3d )){
    $('#body').scroll(function(event){
      var viewport_height = $(window).height(),
        body_scrolltop = $('#body').scrollTop(),
        perspective_y = body_scrolltop + Math.round( viewport_height / 2 );

      if($.browser.mozilla){              
        $('#container').css({
          'transform-origin': 'center ' + perspective_y + "px",
          '-moz-transform-origin': 'center ' + perspective_y + "px",
        });
      }else{
        $('#container').css({
          'perspective-origin': 'center ' + perspective_y + "px",
          '-ms-perspective-origin': 'center ' + perspective_y + "px",
        });
      }
    })
  }
});
```

为了使这个工作，我们必须下载 Modernizr 以检查 CSS 3D 支持，我们可以像在上一章中那样创建一个自定义构建，但这次我们只在配置面板中检查**CSS 3D** **Transforms**复选框（[`modernizr.com/download/`](http://modernizr.com/download/)）。接下来，我们必须在页面中包含下载的文件（[js/modernizr.js](http://js/modernizr.js)）在其他`script`标签之后：

```css
<script src="img/modernizr.js"></script>
```

这是 IE10 的屏幕截图：

![在 Internet Explorer 中实现视差滚动](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_06_8.jpg)

# 向画廊添加一些随机性

现在我们已经解决了浏览器兼容性问题，我们可以安全地删除我们之前附加到图像的实验性注释和类。

为了营造一种随机感，我们可以定义一些类的组，每个组有同一属性的更多变体，然后我们可以为每个图像的每个组选择一个类来显示。这是一个例子；让我们将以下内容添加到`application.css`：

```css
/* sizes */
.size-a{
  width: 30%;
}

.size-b{
  width: 35%;
}

.size-c{
  width: 50%;
}

/* z-indexes */
.depth-a{
  transform: translateZ(10px);
  z-index: 1;
}

.depth-b{
  transform: translateZ(50px);
  z-index: 2;
}

.depth-c{
  transform: translateZ(100px);
  z-index: 3;
}

.depth-d{
  transform: translateZ(150px);
  z-index: 4;
}

.depth-e{
  transform: translateZ(200px);
  z-index: 5;
}
```

现在我们可以用这个列表替换上一节中使用的图像，其中每个图像都有一个`depth-*`和一个`size-*`属性（其中`*`表示在前面的代码中定义的随机选择的类）：

```css
<img class="basic_parallax depth-a size-a" src="img/picture1.jpg">
<img class="basic_parallax depth-b size-c" src="img/picture2.jpg">
<img class="basic_parallax depth-c size-b" src="img/picture3.jpg">
<img class="basic_parallax depth-b size-a" src="img/picture4.jpg">
<img class="basic_parallax depth-d size-c" src="img/picture5.jpg">
<img class="basic_parallax depth-e size-b" src="img/picture6.jpg">
<img class="basic_parallax depth-a size-c" src="img/picture7.jpg">
<img class="basic_parallax depth-c size-a" src="img/picture8.jpg">
<img class="basic_parallax depth-d size-c" src="img/picture9.jpg">
<img class="basic_parallax depth-a size-b" src="img/picture10.jpg">
<img class="basic_parallax depth-e size-b" src="img/picture11.jpg">
<img class="basic_parallax depth-a size-a" src="img/picture12.jpg">
<img class="basic_parallax depth-b size-c" src="img/picture13.jpg">
<img class="basic_parallax depth-c size-a" src="img/picture14.jpg">
```

最后但并非最不重要的，让我们为每个图像定义基本的 CSS：

```css
img.basic_parallax{
  background: rgb(255,255,255);
  padding: 10px;
  box-shadow: 10px 10px10pxrgba(0,0,0,0.6);
  position: relative;
  margin: 10px;
}
```

好了，现在让我们重新加载浏览器并测试一下：

![向画廊添加一些随机性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_06_09.jpg)

# 旋转图像

由于我们正在处理一个真正的 3D 环境，我们可以尝试使用相同的基本思想开发更有趣的效果。例如，如果我们旋转一个元素而不是简单地将它向我们移动会怎么样？让我们试试！首先，我们需要向我们的画廊添加一些更多的图像；这次我们还决定添加一些装饰性文本，如下：

```css
<!-- DECKS -->
<img class="rotatextop" src="img/picture15.jpg">
<p>
  Keremma Dunes
  <small>Bretagne, Finist&eacute;re</small>
</p>
<img class="rotatexbottom" src="img/picture16.jpg">
<p class="depth-e">
  Rennes
  <small>Bretagne</small>
</p>
<img src="img/picture17.jpg">
```

然后我们可以对图像使用`rotateX`变换方法：

```css
.rotatextop{
  transform-origin: top center;
  transform: rotateX(15deg);
}

.rotatexbottom{
  transform-origin: bottom center;
  transform: rotateX(-15deg);		
}
```

还有一些 CSS 属性来稍微样式化段落，然后我们就完成了：

```css
p{
  text-align: center;
  font-family: 'Bowlby One SC', cursive;
  font-size: 6em;
  color: #e4ddc2;
}

p small{
  display: block;
  font-size: 0.4em;
  margin-top: -1em;
}
```

这是结果画廊的屏幕截图：

![旋转图像](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_06_10.jpg)

# 一个 3D 全景

让我们也尝试使用`rotateY`方法来完成这个项目。这次我们将使用这个属性以及`perspective-origin`属性技巧来创建一个很酷的全景效果。

首先我们需要一个全景图像，然后我们可以使用图像编辑器将其切成三部分，其中中央图像的大小大约是其他两个的两倍（例如，800 x 800 像素和 500 x 800 像素）。完成后，我们可以将这些图像添加到`#container`选择器的末尾之前：

```css
<p>
  Ortigia
  <small>Italy</small>
</p>
<img class="panorama left" src="img/panorama_left.jpg">
<img class="panorama center" src="img/panorama.jpg">
<img class="panorama right" src="img/panorama_right.jpg">
```

现在我们可以对`.left`和`.right`都使用`rotateY`方法，如下：

```css
.panorama.left{
  transform-origin: center right;
  transform: rotateY(43deg);  
}

.panorama.right{
  transform-origin: center left;
  transform: rotateY(-43deg);	
}

.panorama.left, .panorama.right{
  width: 27%;
}

.panorama.center{
  width: 43.2%;
}
```

这就是结果：

![一个 3D 全景](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_06_11.jpg)

# 处理旧版本浏览器

尽管这个项目的核心效果利用了一些 CSS 3D 属性，这些属性在旧版本的浏览器中无法模拟，但整个结构只使用了兼容 CSS 2 的属性和选择器，因此几乎可以在任何浏览器中查看：

![处理旧版本浏览器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_06_12.jpg)

# 摘要

处理第三维可能会导致与许多小的实现差异的斗争，但一旦我们驯服了它们，结果就会令人惊叹并且非常愉快。

到目前为止，我们在本章讨论了以下内容：

+   CSS 可以用来转换元素并将它们移动到 3D 空间中

+   我们可以使用一些属性来定义 3D 场景中的消失点

+   通过使用 CSS 3D 属性，可以模拟出很酷的视差滚动效果

+   需要一些 JavaScript 编码来处理浏览器实现差异

在下一章中，我们将学习如何使用 CSS 增强 HTML5 的`video`元素。
