# 响应式 Web 设计指南（二）

> 原文：[`zh.annas-archive.org/md5/50CFC4166B37BD720D7E83B7A7DE4DFD`](https://zh.annas-archive.org/md5/50CFC4166B37BD720D7E83B7A7DE4DFD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用 Bootstrap 开发投资组合网站

*Bootstrap ([`getbootstrap.com/`](http://getbootstrap.com/)) 是最坚固的前端开发框架之一。它具有令人惊叹的功能，如响应式网格、用户界面组件和 JavaScript 库，让我们能够快速构建响应式网站。*

*Bootstrap 如此受欢迎，以至于 Web 开发社区积极支持它，通过开发各种形式的扩展来添加额外功能。如果 Bootstrap 提供的标准功能不足够，可以有扩展来满足特定需求。*

*在本章中，我们将开始第二个项目。我们将使用 Bootstrap 构建一个响应式的投资组合网站。因此，本章显然对那些从事摄影、平面设计和插图等创意领域工作的人很有用。*

*在这里，我们还将使用 Bootstrap 扩展来为投资组合网站提供侧栏导航。在使用 Bootstrap 之后，我们将把 LESS 作为网站样式表的基础。*

*让我们继续。*

本章我们将讨论以下内容：

+   探索 Bootstrap 组件

+   研究 Bootstrap 扩展以实现侧栏导航

+   检查投资组合网站蓝图和设计

+   使用 Bower 和 Koala 设置和组织项目目录和资产

+   构建投资组合网站 HTML 结构

# Bootstrap 组件

与我们在第一个项目中使用的 Responsive.gs 框架不同，Bootstrap 附带了额外的组件，这些组件在 Web 上通常使用。因此，在我们进一步开发投资组合网站之前，首先让我们探索这些组件，主要是我们将在网站中使用的响应式网格、按钮和表单元素等。

### 注意

坦率地说，官方的 Bootstrap 网站([`getbootstrap.com/`](http://getbootstrap.com/))始终是与 Bootstrap 相关的任何内容保持最新的最佳来源。因此，在这里，我想指出一些直接的关键事项。

## Bootstrap 响应式网格

Bootstrap 配备了一个响应式网格系统，以及形成列和行的支持类。在 Bootstrap 中，我们使用这些前缀类来构建列：`col-xs-`、`col-sm-`、`col-md-`和`col-lg-`。然后是列号，范围从`1`到`12`，用于定义列的大小以及针对特定视口大小的列。请参阅以下表格以获取有关前缀的更多详细信息：

| 前缀 | 描述 |
| --- | --- |
| `col-xs-` | 这指定了 Bootstrap 定义的最小（超小）视口大小的列，即小于或等于 768 像素 |
| `col-sm-` | 这指定了 Bootstrap 定义的小视口大小的列，即大于或等于 768 像素。 |
| `col-md-` | 这指定了 Bootstrap 定义的中等视口大小的列，即大于或等于 992 像素 |
| `col-lg-` | 这指定了 Bootstrap 定义的大视口大小的列，即大于或等于 1,200 像素 |

在下面的示例中，我们在一行中设置了三列，每列分配了一个`col-sm-4`类：

```html
<div class="row">
  <div class="col-sm-4"></div>
  <div class="col-sm-4"></div>
  <div class="col-sm-4"></div>
</div>
```

因此，每列的大小将相同，并且它们会缩小到 Bootstrap 定义的小视口大小（≥ 768px）。以下屏幕截图显示了在浏览器中添加一些样式后的标记效果：

![Bootstrap 响应式网格](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00282.jpeg)

查看小于 768 像素的视口大小的示例，所有这些列将开始堆叠——第一列在顶部，第三列在底部，如下图所示：

![Bootstrap 响应式网格](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00283.jpeg)

此外，我们可以添加多个类来指定多个视口大小内的列比例，如下所示：

```html
<div class="row">
  <div class="col-sm-6 col-md-2 col-lg-4"></div>
  <div class="col-sm-3 col-md-4 col-lg-4"></div>
  <div class="col-sm-3 col-md-6 col-lg-4"></div>
</div>
```

根据上述示例，在 Bootstrap 定义的大视口大小（≥ 1,200 像素）内，列的大小将相同，如下截图所示：

![Bootstrap 响应式网格](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00284.jpeg)

然后，当我们在中等视口大小下查看时，根据每个列上分配的类，列的比例将开始变化。第一列的宽度将变小，第二列将保持相同比例，而第三列将变大，如下截图所示：

![Bootstrap 响应式网格](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00285.jpeg)

当网站处于 Bootstrap 定义的中等和小视口大小的临界点时（大约为 991 像素），列的比例将再次开始变化，如下截图所示：

![Bootstrap 响应式网格](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00286.jpeg)

### 注意

要了解如何构建 Bootstrap 网格，请前往 Bootstrap 官方网站的网格系统部分（[`getbootstrap.com/css/#grid`](http://getbootstrap.com/css/#grid)）。

## Bootstrap 按钮和表单

我们将在网站中加入其他组件，如按钮和表单。我们将创建一个在线联系方式，用户可以通过该方式与我们联系。在 Bootstrap 中，按钮由`btn`类和`btn-default`组成，以应用 Bootstrap 默认样式，如下代码所示：

```html
<button type="button" class="btn btn-default">Submit</button>
<a class="btn btn-default">Send</a>
```

将`btn-default`类替换为`btn-primary`、`btn-success`或`btn-info`，以给按钮指定颜色，如下代码所示：

```html
<button type="button" class="btn btn-info">Submit</button>
<a class="btn btn-success">Send</a>
```

以下代码片段使用这些类定义按钮大小：`btn-lg`使按钮变大，`btn-sm`使其变小，`btn-xs`使按钮变得更小，如下代码所示：

```html
<button type="button" class="btn btn-info btn-lg">Submit</button>
<a class="btn btn-success btn-sm">Send</a>
```

以下截图显示了在添加前述类时按钮大小的变化：

![Bootstrap 按钮和表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00287.jpeg)

Bootstrap 允许我们以多种方式显示按钮，例如将一系列按钮内联显示或在按钮中添加下拉切换。要了解如何构建这些类型的按钮，请前往 Bootstrap 官方网站的按钮组（[`getbootstrap.com/components/#btn-groups`](http://getbootstrap.com/components/#btn-groups)）和按钮下拉切换（[`getbootstrap.com/components/#btn-dropdowns`](http://getbootstrap.com/components/#btn-dropdowns)）部分获取更多帮助和详细信息。

![Bootstrap 按钮和表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00288.jpeg)

Bootstrap 按钮组和带下拉切换的按钮

Bootstrap 还提供了一些可重复使用的类来为表单元素（如`<input>`和`<textarea>`）添加样式。Bootstrap 使用`form-control`类来为表单元素添加样式。样式轻巧得体，如下截图所示：

![Bootstrap 按钮和表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00289.jpeg)

有关在 Bootstrap 中对表单元素进行样式和排列的更多信息，请参阅 Bootstrap 官方页面的表单部分（[`getbootstrap.com/css/#forms`](http://getbootstrap.com/css/#forms)）。

## Bootstrap Jumbotron

Bootstrap 将 Jumbotron 描述如下：

> *“一种轻量灵活的组件，可以选择性地扩展整个视口，以展示站点上的关键内容”（[`getbootstrap.com/components/#jumbotron`](http://getbootstrap.com/components/#jumbotron)）*

Jumbotron 是一个特殊的部分，用于显示网站的首行消息，如营销文案、口号或特别优惠，另外还有一个按钮。Jumbotron 通常放置在折叠区域上方和导航栏下方。要在 Bootstrap 中构建 Jumbotron 部分，请应用`jumbotron`类，如下所示：

```html
<div class="jumbotron">
  <h1>Hi, This is Jumbotron</h1>
<p>Place the marketing copy, catchphrases, or special offerings.</p>
  <p><a class="btn btn-primary btn-lg" role="button">Got it!</a></p>
</div>
```

使用 Bootstrap 默认样式，Jumbotron 的外观如下：

![Bootstrap Jumbotron](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00290.jpeg)

这是默认样式下的 Jumbotron 外观

### 注意

有关 Bootstrap Jumbotron 的更多细节可以在 Bootstrap 组件页面找到（[`getbootstrap.com/components/#jumbotron`](http://getbootstrap.com/components/#jumbotron)）。

## Bootstrap 第三方扩展

无法满足每个人的需求，Bootstrap 也是如此。有许多形式的扩展被创建出来，包括 CSS、JavaScript、图标、起始模板和主题，以扩展 Bootstrap。在这个页面上找到完整的列表（[`bootsnipp.com/resources`](http://bootsnipp.com/resources)）。

在这个项目中，我们将包括一个名为 Jasny Bootstrap（[`jasny.github.io/bootstrap/`](http://jasny.github.io/bootstrap/)）的扩展，由 Arnold Daniels 开发。我们将主要用它来整合 off-canvas 导航。off-canvas 导航是响应式设计中的一种流行模式；菜单导航首先设置在网站的可见区域之外，通常只有在点击或轻触时才会滑入，如下面的截图所示：

![Bootstrap 第三方扩展](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00291.jpeg)

当用户点击三条杠图标时，off-canvas 部分滑入

### Jasny Bootstrap off-canvas

Jasny Bootstrap 是一个为原始 Bootstrap 添加额外构建块的扩展。Jasny Bootstrap 是以 Bootstrap 为设计基础的；它几乎在每个方面都遵循 Bootstrap 的约定，包括 HTML 标记、类命名、JavaScript 函数以及 API。

如前所述，我们将使用这个扩展在作品集网站中包含 off-canvas 导航。以下是一个构建 off-canvas 导航的 Jasny Bootstrap 示例代码片段：

```html
<nav id="offcanvas-nav" class="navmenu navmenu-default navmenu-fixed-left offcanvas" role="navigation">
  <ul class="nav navmenu-nav">
    <li class="active"><a href="#">Home</a></li>
    <li><a href="#">Link</a></li>
    <li><a href="#">Link</a></li>
  </ul>
</nav>
<div class="navbar navbar-default navbar-fixed-top">
<button type="button" class="navbar-toggle" data-toggle="offcanvas" data-target="#offcanvas-nav" data-target="body">
    <span class="icon-bar"></span>
    <span class="icon-bar"></span>
    <span class="icon-bar"></span>
  </button>
</div>
```

从上面的代码片段可以看出，构建 off-canvas 导航需要大量的 HTML 元素、类和属性。首先，我们需要两个元素，`<nav>`和`<div>`，分别包含菜单和切换导航菜单的按钮。`<nav>`元素被赋予一个 ID，作为唯一的参考，通过`<button>`中的`data-target`属性来定位目标菜单。

在这些元素中添加了一些类和属性，用于指定颜色、背景、位置和功能：

+   `navmenu`：Jasny Bootstrap 有一种新类型的导航，称为 navmenu。`navmenu`类将垂直显示导航，并放置在网站内容的侧面——右侧或左侧，而不是顶部。

+   `navmenu-default`：这个类将使用默认样式设置`navmenu`类，主要是浅灰色。如果你喜欢深色，可以使用`navmenu-inverse`类。看一下下面的截图：![Jasny Bootstrap off-canvas](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00292.jpeg)

off-canvas 导航的两种默认颜色

+   `navmenu-fixed-left`类将导航菜单定位在左侧。使用`navmenu-fixed-right`类将其设置在右侧。

+   `offcanvas`类是将导航菜单设置在画布之外的主要类。

+   `<button>`中的`data-target="#offcanvas-nav"`代码作为一个选择器，指向具有给定 ID 的特定导航菜单。

+   `data-toggle="offcanvas"`代码告诉按钮切换 off-canvas 导航。此外，原始的 Bootstrap 还附带了几种`data-toggle`类型，用于连接不同的小部件，比如模态框（`data-toggle="modal"`）、下拉菜单（`data-toggle="dropdown"`）和选项卡（`data-toggle="tab"`）。

+   `data-target="body"`让网站主体在 off-canvas 导航被切换时同时滑动。Jasny Bootstrap 称之为推动菜单；访问这个页面（[`jasny.github.io/bootstrap/examples/navmenu-push/`](http://jasny.github.io/bootstrap/examples/navmenu-push/)）来看它的实际效果。

### 注意

此外，Jasny Bootstrap 提供了两种额外类型的画布导航，名为滑入菜单（[`jasny.github.io/bootstrap/examples/navmenu/`](http://jasny.github.io/bootstrap/examples/navmenu/)）和展示菜单（[`jasny.github.io/bootstrap/examples/navmenu-reveal/`](http://jasny.github.io/bootstrap/examples/navmenu-reveal/)）-请访问包含的 URL 以查看它们的运行情况。

# 深入了解 Bootstrap

探索 Bootstrap 组件的每一寸都超出了本书的能力范围。因此，我们只讨论了 Bootstrap 中对项目至关重要的一些内容。除了 Bootstrap 官方网站（[`getbootstrap.com/`](http://getbootstrap.com/)）之外，以下是一些深入研究 Bootstrap 的专门参考资料，您可以查看：

+   初学者的 Bootstrap 教程由 Coder's Guide 提供（[`www.youtube.com/watch?v=YXVoqJEwqoQ`](http://www.youtube.com/watch?v=YXVoqJEwqoQ)），这是一系列视频教程，帮助初学者快速上手 Bootstrap

+   Twitter Bootstrap Web Development How-To, David Cochran, Packt Publishing ([`www.packtpub.com/web-development/twitter-bootstrap-web-development-how-instant`](http://www.packtpub.com/web-development/twitter-bootstrap-web-development-how-instant))

+   Mobile First Bootstrap, Alexandre Magno, Packt Publishing ([`www.packtpub.com/web-development/mobile-first-bootstrap`](http://www.packtpub.com/web-development/mobile-first-bootstrap))

# 使用字体图标

Retina 或高清（HD）显示使屏幕上的所有内容看起来更清晰，更生动。但问题在于在高清显示出现之前带来的传统图像或网络图标。这些图像通常作为位图或光栅图像提供，并且在这个屏幕上变得模糊，如下面的屏幕截图所示：

![使用字体图标](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00293.jpeg)

一系列在视网膜显示器上模糊的图标

我们不希望这种情况发生在我们的网站上，因此我们将不得不使用更可伸缩并在高清屏幕上保持清晰的字体图标。

说实话，Bootstrap 附带了一个名为 Glyphicon 的字体图标集。遗憾的是，它没有我们需要的社交媒体图标。在浏览了许多字体图标集之后，我最终选择了 Ionicons（[`ionicons.com/`](http://ionicons.com/)）。在这里，我们将使用由 Lance Hudson 开发的带有 LESS 的替代版本（[`github.com/lancehudson/ionicons-less`](https://github.com/lancehudson/ionicons-less)），因此我们将能够与 Bootstrap 无缝集成，后者也使用 LESS。

# 检查投资组合网站布局

在我们开始构建网站的块和边缘之前，让我们看一下网站线框图。这个线框图将成为参考，并让我们了解网站布局在移动和桌面视图中将如何组织。

![检查投资组合网站布局](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00294.jpeg)

上面的屏幕截图显示了桌面或技术上说是宽视口大小的网站布局。

网站将在网站的左上方放置一个按钮，带有所谓的汉堡图标，以滑入画布菜单。然后是网站的第一行，显示网站名称和一行口号。接下来的部分将包含投资组合图像，而最后一部分将包含在线表单和社交媒体图标。

移动视图看起来更简化，但保持了与桌面视图布局相同的逻辑结构，如下面的屏幕截图所示：

![检查投资组合网站布局](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00295.jpeg)

# 项目目录、资产和依赖项

让我们通过组织项目目录和包括依赖项、图像和字体图标在内的资产来开始项目。

### 注意

什么是依赖关系？这里的依赖关系是指运行项目和构建网站所需的文件或文件包，如 CSS 和 JavaScript 库。

在这个项目中，我们将实践使用 Bower（[`bower.io/`](http://bower.io/)）来组织项目的依赖关系。Bower，正如我们在第一章中简要提到的那样，*响应式 Web 设计*，是一个前端包管理器，简化了安装、移除和更新前端开发库（如 jQuery、Normalize 和 HTML5Shiv）的方式。

# 进行操作-组织项目目录、资产和使用 Bower 安装项目依赖关系

在本节中，我们将添加包括 Bootstrap、Jasny Bootstrap、Ionicons 和 HTML5Shiv 在内的项目依赖关系。我们将使用 Bower 安装它们，以便将来更轻松地维护它们——移除和更新它们。

此外，由于这可能是您中的许多人第一次使用 Bower，我将以缓慢的速度逐步为您讲解整个过程。请仔细执行以下步骤：

1.  在`htdocs`文件夹中，创建一个新文件夹，并将其命名为`portfolio`。这是项目目录，我们将在其中添加所有项目文件和文件夹。

1.  在`portfolio`文件夹中，创建一个名为`assets`的新文件夹。我们将把项目资产，如图像、JavaScript 和样式表放在这个文件夹中。

1.  在资产文件夹中，创建以下文件夹：

+   `img`用于包含网站图像和基于图像的图标

+   `js`用于包含 JavaScript 文件

+   `fonts`用于包含字体图标集

+   `less`用于包含 LESS 样式表

+   `css`作为 LESS 的输出文件夹

1.  创建`index.html`作为网站的主页。

1.  在`img`文件夹中添加网站的图像；这包括作品集图像和移动设备的图标，如下面的屏幕截图所示：![进行操作-组织项目目录、资产和使用 Bower 安装项目依赖关系](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00296.jpeg)

### 注意

这个网站大约有 14 张图片，包括移动设备的图标。我要感谢我的朋友 Yoga Perdana（[`dribbble.com/yoga`](https://dribbble.com/yoga)）允许我在这本书中使用他的精彩作品。您可以在本书中找到这些图像。但是，当然，您也可以用您自己的图像替换它们。

1.  我们将通过 Bower 安装依赖关系——运行项目和构建网站所需的包、库、JavaScript 或 CSS——但在运行任何 Bower 命令来安装依赖关系之前，我们希望使用`bower init`命令将项目设置为 Bower 项目，以定义`bower.json`中的项目规范，如项目名称、版本和作者。

1.  首先，打开终端或命令提示符（如果您使用 Windows）。然后，使用`cd`命令导航到项目目录，如下所示：

+   在 Windows 中：`cd \xampp\htdocs\portfolio`

+   在 OS X 中：`cd /Applications/XAMPP/htdocs/portfolio`

+   在 Ubuntu 中：`cd /opt/lampp/htdocs/portfolio`

1.  输入`bower init`，如下面的屏幕截图所示：![进行操作-组织项目目录、资产和使用 Bower 安装项目依赖关系](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00297.jpeg)

### 注意

这个命令`bower init`将我们的项目初始化为一个 Bower 项目。这个命令还会引导我们填写一些提示，以描述项目，比如项目名称、项目版本、作者等。

1.  首先，我们指定项目名称。在这种情况下，我想将项目命名为`responsive-portfolio`。输入名称如下，并按*Enter*继续。请看下面的屏幕截图：![进行操作-组织项目目录、资产和使用 Bower 安装项目依赖关系](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00298.jpeg)

1.  指定项目版本。由于项目是新的，让我们简单地将其设置为`1.0.0`，如下面的屏幕截图所示：![进行操作-组织项目目录，资产，并使用 Bower 安装项目依赖项](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00299.jpeg)

1.  按下*Enter*键继续。

1.  指定项目描述。此提示完全是可选的。如果您认为对于您的项目不需要，可以将其留空。在这种情况下，我将描述项目为`使用 Bootstrap 构建的响应式作品集网站`，如下面的屏幕截图所示：![进行操作-组织项目目录，资产，并使用 Bower 安装项目依赖项](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00300.jpeg)

1.  指定项目的主文件。这肯定会根据项目而变化。在这里，让我们将主文件设置为`index.html`，网站的首页，如下面的屏幕截图所示：![进行操作-组织项目目录，资产，并使用 Bower 安装项目依赖项](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00301.jpeg)

1.  这提示了一个问题，“这个软件包暴露了什么类型的模块？”它指定了软件包的用途。在这种情况下，只需选择全局选项，如下面的屏幕截图所示：![进行操作-组织项目目录，资产，并使用 Bower 安装项目依赖项](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00302.jpeg)

1.  按空格键选择它，然后按*Enter*继续。

### 注意

此提示描述了项目中的模块技术（我们的项目）的用途。我们的项目没有附属于特定技术或模块；它只是一个纯静态的网站，包括 HTML、CSS 和几行 JavaScript。我们不构建 Node、YUI 或 AMD 模块。因此，最好选择`globals`选项。

1.  **关键字**提示告诉项目的关系。在这种情况下，我想将其填写为`作品集`，`响应式`，`bootstrap`，如下面的屏幕截图所示。按*Enter*继续：![进行操作-组织项目目录，资产，并使用 Bower 安装项目依赖项](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00303.jpeg)

**关键字**提示是可选的。如果您愿意，可以将其留空，然后按*Enter*键。

1.  **作者**提示指定了项目的作者。此提示预填了您在系统中注册的计算机用户名和电子邮件。然而，您可以通过指定一个新名称并按*Enter*继续来覆盖它，如下面的屏幕截图所示：![进行操作-组织项目目录，资产，并使用 Bower 安装项目依赖项](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00304.jpeg)

### 提示

如果项目有多个作者，您可以使用逗号分隔符指定每个作者，如下所示：

**作者:** `约翰·多, 简·多`。

1.  指定项目的许可证。在这里，我们将简单地将其设置为`MIT`许可证。`MIT`许可证允许任何人对项目中的代码做任何他或她想做的事情，包括修改、转让和商业使用。请看下面的屏幕截图：![进行操作-组织项目目录，资产，并使用 Bower 安装项目依赖项](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00305.jpeg)

### 注意

参考选择许可证（[`choosealicense.com/`](http://choosealicense.com/)）以找到其他类型的许可证。

1.  指定项目的主页。这可以是您自己的网站存储库。在这种情况下，我想将其设置为我的个人域名`creatiface.com`，如下面的屏幕截图所示：![进行操作-组织项目目录，资产，并使用 Bower 安装项目依赖项](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00306.jpeg)

1.  在**将当前安装的组件设置为依赖项？**命令中，输入`n`（否），因为我们还没有安装任何依赖项或软件包，如下面的屏幕截图所示：![进行操作-组织项目目录，资产，并使用 Bower 安装项目依赖项](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00307.jpeg)

1.  **将常见的忽略文件添加到忽略列表中？**命令将创建包含要从 Git 存储库中排除的常见文件列表的`.gitignore`文件。键入`Y`以确认。请查看下面的屏幕截图：![行动时间-组织项目目录，资产，并使用 Bower 安装项目依赖](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00308.jpeg)

### 注意

我将使用 Git 来管理代码修订，并将其上传到 Git 存储库，如 Github 或 Bitbucket，因此我选择了`Y`（是）。但是，如果您尚未熟悉 Git，并且不打算在 Git 存储库中托管项目，您可以忽略此提示并键入`n`。 Git 超出了本书讨论的范围。要了解有关 Git 的更多信息，我推荐以下最佳参考资料：

通过 GitTower 学习初学者的 Git ([`www.git-tower.com/learn/`](http://www.git-tower.com/learn/))。

1.  对于**您是否想将此软件包标记为私有，以防止意外发布到注册表中？**命令，键入`Y`，因为我们不会将项目注册到 Bower 注册表中。请查看下面的屏幕截图：![行动时间-组织项目目录，资产，并使用 Bower 安装项目依赖](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00309.jpeg)

1.  检查输出。如果看起来不错，请在`bower.json`文件中键入`Y`以生成输出，如下面的屏幕截图所示：![行动时间-组织项目目录，资产，并使用 Bower 安装项目依赖](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00310.jpeg)

1.  有许多库我们想要安装。首先，让我们使用`bower install bootstrap ––save`命令安装 Bootstrap，如下面的屏幕截图所示：![行动时间-组织项目目录，资产，并使用 Bower 安装项目依赖](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00311.jpeg)

在命令后面的`--save`参数将在`bower.json`中注册 Bootstrap 作为项目依赖项。如果您打开它，您应该会发现它记录在依赖项下，如下面的屏幕截图所示：

![行动时间-组织项目目录，资产，并使用 Bower 安装项目依赖](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00312.jpeg)

您还应该在新文件夹`bower_components`中找到保存的 Bootstrap 软件包，以及作为 Bootstrap 依赖项的 jQuery，如下面的屏幕截图所示：

![行动时间-组织项目目录，资产，并使用 Bower 安装项目依赖](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00313.jpeg)

1.  使用`bower install jasny-bootstrap –save`命令安装 Bootstrap 扩展 Jasny Bootstrap。

1.  使用`bower install ionicons-less –save`命令安装带有 LESS 样式表的 Ionicons。

1.  Ionicons 软件包附带字体文件。将它们移动到项目目录的`fonts`文件夹中，如下面的屏幕截图所示：![行动时间-组织项目目录，资产，并使用 Bower 安装项目依赖](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00314.jpeg)

1.  最后，使用`bower install html5shiv ––save`命令安装 HTML5Shiv，以在 Internet Explorer 8 及以下版本中启用 HTML5 的新元素。

## *刚刚发生了什么？*

我们刚刚创建了文件夹和网站首页文档`index.html`。还准备了将显示在网站上的图像和图标。我们还在`bower.json`中记录了项目规范。通过这个文件，我们可以知道项目的名称是`responsive-portfolio`，当前版本为 1.0.0，并且有一些依赖项，如下所示：

+   Bootstrap ([`github.com/twbs/bootstrap`](https://github.com/twbs/bootstrap))

+   Jasny Bootstrap ([`jasny.github.io/bootstrap/`](http://jasny.github.io/bootstrap/))

+   带有 LESS 的 Ionicons ([`github.com/lancehudson/ionicons-less`](https://github.com/lancehudson/ionicons-less))

+   HTML5Shiv ([`github.com/aFarkas/html5shiv`](https://github.com/aFarkas/html5shiv))

我们通过`bower install`命令下载了这些库，这比下载和解压`.zip`包要简洁。所有的库应该已经添加到一个名为`bower_components`的文件夹中，如下面的截图所示：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00315.jpeg)

## 尝试自定义 Bower 目录

默认情况下，Bower 会创建一个名为`bower_components`的新文件夹。Bower 允许我们通过 Bower 配置文件`.bowerrc`来配置文件夹名称。通过创建`.bowerrc`文件，根据您的喜好更改文件夹名称。请参考此参考链接（[`bower.io/docs/config/`](http://bower.io/docs/config/)）来配置 bower。

## 小测验-测试您对 Bower 命令的理解

Q1\. 我们已经向您展示了如何使用 Bower 安装和更新库。现在的问题是：如何删除已安装的库？

1.  运行`bower remove`命令。

1.  运行`bower uninstall`命令。

1.  运行`bower delete`命令。

Q2\. 除了安装和删除库之外，我们还可以通过 Bower 注册表搜索库的可用性。如何通过 Bower 注册表搜索库？

1.  运行`bower search`，然后跟上关键字。

1.  运行`bower search`，然后跟上库名称。

1.  运行`bower browse`，然后跟上关键字。

Q3\. Bower 还允许我们查看包属性的详细信息，例如包版本、依赖关系、作者等。我们执行什么命令来查看这些详细信息？

1.  `bower info`。

1.  `bower detail`。

1.  `bower property`。

## 更新 Bower 组件

由于依赖项是通过 Bower 安装的，因此项目的维护将更加简化。这些库可以在以后更新到新版本。通过使用 Bower 命令，更新我们刚刚安装的库实际上比下载`.zip`包并手动将文件移动到项目目录中更加简洁。

运行`bower list`命令以查看所有已安装的 Bower 包，并检查包的新版本是否可用，如下面的截图所示：

![更新 Bower 组件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00316.jpeg)

然后，使用`bower install`命令安装新版本，后面跟着 Bower 包名称和版本号。例如，要安装 Bootstrap 版本 3.2.0，运行`bower install bootstrap#3.2.0 ––save`命令。

### 注意

实际上，我们应该能够使用`bower update`命令来更新包。然而，根据 Bower Issue 线程中的一些报告，这个命令似乎并不按预期工作（[`github.com/bower/bower/issues/1054`](https://github.com/bower/bower/issues/1054)）。因此，目前使用先前展示的`bower install`命令是正确的方法。

# 作品集网站 HTML 结构

现在我们已经准备好构建网站所需的基本内容。让我们开始构建网站的 HTML 结构。与上一个项目一样，在这里，我们将使用一些新的 HTML5 元素来构建语义结构。

# 行动时间-构建网站 HTML 结构

在这一部分，我们将构建网站的 HTML 结构。您会发现，我们将在这里添加的一些元素与我们在第一个网站中添加的元素相似。因此，以下步骤将是直接的。如果您已经从头到尾地跟随了第一个项目，那么这些步骤也应该很容易跟随。让我们继续。

1.  打开`index.html`。然后，添加基本的 HTML 结构，如下所示：

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Portfolio</title>
</head>
<body>

</body>
</html>
```

1.  在`<meta charset="UTF-8">`下面，添加一个 meta 标签来解决 Internet Explorer 的渲染兼容性问题：

```html
<meta http-equiv="X-UA-Compatible" content="IE=edge">
```

前面的 meta 标签规范将强制 Internet Explorer 使用其中的最新引擎版本来渲染页面。

### 注意

有关`X-UA-Compatible`的更多信息，请参考 Modern.IE 文章，*如何使用 X-UA-Compatible*（[`www.modern.ie/en-us/performance/how-to-use-x-ua-compatible`](https://www.modern.ie/en-us/performance/how-to-use-x-ua-compatible)）。

1.  在`http-equiv`meta 标记下方，添加 meta 视口标记：

```html
<meta name="viewport" content="width=device-width, initial-scale=1">
```

前面的视口 meta 标记规定了网页视口宽度要遵循设备视口大小，并在首次打开网页时以 1:1 的比例缩放页面。

1.  在视口 meta 标记下方，添加到 favicon 和 apple-touch-icon 的链接，这将在苹果设备（如 iPhone、iPad 和 iPod）上显示网站的图标：

```html
<link rel="apple-touch-icon" href="assets/img/apple-icon.png">
<link rel="shortcut icon" href="assets/img/favicon.png" type="image/png">
```

1.  在`<title>`下方添加网站的 meta 描述：

```html
<meta name="description" content="A simple portoflio website built using Bootstrap">
```

在这个 meta 标记中指定的描述将显示在**搜索引擎结果页面**（**SERP**）中。

1.  您还可以按照以下方式在 meta 描述标记下方指定页面的作者。

```html
<meta name="author" content="Thoriq Firdaus">
```

1.  在`<body>`内，按照以下方式添加网站的侧栏导航 HTML：

```html
<nav id="menu" class="navmenu navmenu-inverse navmenu-fixed-left offcanvas portfolio-menu" role="navigation">
        <ul class="nav navmenu-nav">
            <li class="active"><a href="#">Home</a></li>
            <li><a href="#">Blog</a></li>
            <li><a href="#">Shop</a></li>
            <li><a href="#">Speaking</a></li>
            <li><a href="#">Writing</a></li>
            <li><a href="#">About</a></li>
        </ul>
    </nav>
```

除了本章中 Jasny Bootstrap 侧栏部分提到的基本类之外，我们还在`<nav>`元素中添加了一个名为`portfolio-menu`的新类，以应用我们自己的样式到侧栏导航。

1.  添加 Bootstrap `navbar`结构，以及用于滑动侧栏的`<button>`：

```html
<div class="navbar navbar-default navbar-portfolio portfolio-topbar">
<button type="button" class="navbar-toggle" data-toggle="offcanvas" data-target="#menu" data-canvas="body">
        <span class="icon-bar"></span>
<span class="icon-bar"></span>
<span class="icon-bar"></span>
</button>
</div>
```

1.  在“导航栏”下方，添加`<main>`元素，如下所示：

```html
<main class="portfolio-main" id="content" role="main">
</main>
```

正如 W3C（[`www.w3.org/TR/html-main-element/`](http://www.w3.org/TR/html-main-element/)）中所描述的，`<main>`元素定义了网站的主要内容。因此，这就是我们将放置网站内容的地方，包括作品集图片。

1.  添加 Bootstrap Jumbotron，包含作品集网站名称和一行标语。由于我将展示一个朋友的作品，Yoga Perdana 的作品，我希望展示他的名字，以及他在 Dribbble 页面个人资料中显示的标语（[`dribbble.com/yoga`](https://dribbble.com/yoga)），如下所示：

```html
<main class="portfolio-main" id="content" role="main">
<section class="jumbotron portfolio-about" id="about">
<h1 class="portfolio-name">Yoga Perdana</h1>
<p class="lead">Illustrator &amp; Logo designer. I work using digital tools, specially vector.</p>
</section>
</main>
```

您可以自由地在此处添加您的姓名或公司名称。

1.  在 Bootstrap Jumbotron 部分下方，使用 HTML5 `<section>`元素添加一个新的部分，并包含定义此部分的标题，如下所示：

```html
...
<section class="jumbotron portfolio-about" id="about">
<h1 class="portfolio-name">Yoga Perdana</h1>
<p class="lead">Illustrator &amp; Logo designer. I work using digital tools, specially vector.</p>
</section>
<section class="portfolio-display" id="portfolio">
  <h2>Portfolio</h2>
</section>
```

1.  在包含以下代码的标题下方添加 Bootstrap 容器（[`getbootstrap.com/css/#overview-container`](http://getbootstrap.com/css/#overview-container)），该容器将包含作品集图片：

```html
<section class="portfolio-display" id="portfolio">
<h2>Portfolio</h2>
   <div class="container">
</div>
</section>
```

1.  将作品集图片排列成列和行。我们有 12 张作品集图片，这意味着我们可以在一行中有四张图片/列。以下是第一行：

```html
...
<div class="container">
<div class="row">
<div class="col-md-3 col-sm-6 portfolio-item">
 <figure class="portfolio-image">
<img class="img-responsive" src="img/6layers.jpg" height="300" width="400" alt="">
<figcaption class="portfolio-caption">6 Layers</figcaption>
 </figure>
 </div>
<div class="col-md-3 col-sm-6 portfolio-item">
 <figure class="portfolio-image">
<img class="img-responsive" src="img/blur.jpg" height="300" width="400" alt="">
<figcaption class="portfolio-caption">Blur</figcaption>
</figure>
 </div>
<div class="col-md-3 col-sm-6 portfolio-item">
 <figure class="portfolio-image">
<img class="img-responsive" src="img/brain.jpg" height="300" width="400" alt="">
<figcaption class="portfolio-caption">Brain</figcaption>
</figure>
 </div>
 <div class="col-md-3 col-sm-6 portfolio-item">
 <figure class="portfolio-image">
<img class="img-responsive" src="img/color.jpg" height="300" width="400" alt="">
<figcaption class="portfolio-caption">Color</figcaption>
</figure>
 </div>
</div>
</div>
```

每列都分配了一个特殊的类，以便我们可以应用自定义样式。我们还在包裹图片的`<figure>`中添加了一个类，以及包裹图片标题的`<figcaption>`元素，以达到同样的目的。

1.  将剩余的图片添加到列和行中。在这种情况下，我们有 12 张图片，因此网站上应该显示三行。每行包含四张图片，包括我们在第 13 步中添加的一行。

1.  在作品集部分下方，添加包含三个表单字段和一个按钮的网站留言表单，如下所示：

```html
...
</section>
<div class="portfolio-contact" id="contact">
 <div class="container">
 <h2>Get in Touch</h2>
<form id="contact" method="post" class="form" role="form">
 <div class="form-group">
<input type="text" class="form-control input-lg" id="input-name" placeholder="Name">
</div>
 <div class="form-group">
<input type="email" class="form-control input-lg" id="input-email" placeholder="Email">
 </div>
 <div class="form-group">
<textarea class="form-control" rows="10"></textarea>
 </div>
 <button type="submit" class="btn btn-lg btn-primary">Submit</button>
 </form>
</div>
</div>

```

在这里，我们只用了三个表单字段来简化网站表单。但是，您可以根据自己的需求添加额外的表单字段。

1.  最后，我们将使用 HTML5 `<footer>`元素添加网站页脚。页脚，正如我们从网站线框图中看到的那样，包含社交媒体图标和网站版权声明。

1.  在网站的主要内容下方添加以下 HTML 标记：

```html
... 
</main>
<footer class="portfolio-footer" id="footer">
        <div class="container">
          <div class="social" id="social">
            <ul>
<li class="twitter"><a class="icon ion-social-twitter" href="#">Twitter</a></li>
<li class="dribbble"><a class="icon ion-social-dribbble-outline" href="#">Dribbble</a></li>
                </ul>
          </div>
<div class="copyright">Yoga Perdana &copy; 2014</div>
        </div>
    </footer>
```

## *刚刚发生了什么？*

我们刚刚使用了一些 HTML5 元素和 Bootstrap 可重用类构建了投资组合网站的 HTML 结构。您应该能够通过以下地址`http://localhost/portfolio/`或`http://{computer-username}/portfolio/`来查看网站，如果您使用的是 OS X。在这个阶段，网站还没有应用任何样式；我们还没有在页面中链接任何样式表。因此，接下来的提示后面的屏幕截图是网站当前的外观。

### 提示

在前面步骤中显示的完整代码也可以从以下 Gist [`git.io/oIh31w`](http://git.io/oIh31w) 获取。

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00317.jpeg)

## 尝试一下 - 扩展投资组合网站

Bootstrap 提供了各种组件。然而，我们只使用了一些，包括网格、Jumbotron、按钮和表单。通过添加额外的 Bootstrap 组件来扩展网站，如下所示：

+   分页（[`getbootstrap.com/components/#pagination`](http://getbootstrap.com/components/#pagination)）

+   面包屑（[`getbootstrap.com/components/#breadcrumbs`](http://getbootstrap.com/components/#breadcrumbs)）

+   响应式嵌入（[`getbootstrap.com/components/#responsive-embed`](http://getbootstrap.com/components/#responsive-embed)）

+   面板（[`getbootstrap.com/components/#panels`](http://getbootstrap.com/components/#panels)）

+   Wells（[`getbootstrap.com/components/#wells`](http://getbootstrap.com/components/#wells)）

此外，尝试创建更多的网页，并通过侧栏导航菜单将它们链接起来。

## 弹出测验 - Bootstrap 按钮类

Bootstrap 指定了许多可重用类，可以快速地为元素设置预设样式。

Q1. 以下哪个类在 Bootstrap 网格中没有被使用？

1.  `col-sm-pull-8`

1.  `col-md-push-3`

1.  `col-xs-offset-5`

1.  `col-lg-6`

1.  `col-xl-7`

Q2. 以下哪个类用于样式化按钮？

1.  `btn-link`

1.  `btn-submit`

1.  `btn-send`

1.  `btn-cancel`

1.  `btn-enter`

# 摘要

本章开始了本书的第二个项目。我们正在使用最流行的前端开发框架之一 Bootstrap 构建一个投资组合网站。我们还探索了一个名为 Bower 的新的引人注目的网页开发工具，它简化了网站依赖管理。

它们都是工具的绝佳组合。Bootstrap 让我们可以快速使用模块化组件和可重用类构建响应式网站，而 Bower 使项目更易于维护。

在下一章中，我们将更多地处理 LESS 和 JavaScript 来装饰网站。


# 第六章：使用 LESS 完善响应式作品集网站

*在前一章中，我们使用 HTML5 和一些 Bootstrap 插入类构建了作品集网站的结构。你可能已经看到，网站还没有装饰。我们还没有编写自己的样式或将样式表链接到页面上。因此，本章的重点将放在网站装饰上。*

*Bootstrap 主要使用 LESS 来生成其组件的样式。我们将遵循其步伐，也使用 LESS 来为作品集网站设计样式。LESS 带来了许多功能，如变量和混合，这将使我们能够编写更精简和高效的样式规则。最终，你会发现使用 LESS 来定制和维护网站样式比纯 CSS 更容易。*

*此外，我们还使用了一个名为 Jasny Bootstrap 的 Bootstrap 扩展来将侧栏导航包含到作品集网站中。在这个阶段，侧栏导航不会发生任何变化；我们只是设置了 HTML 结构。因此，在本章中，除了编译网站样式，我们还将编译 Bootstrap 和 Jasny Bootstrap 的 JavaScript 库，以使侧栏导航功能正常。*

在本章中，我们将讨论许多内容，包括以下主题：

+   学习基本的 LESS 语法，如变量和混合

+   使用 LESS 的`@import`指令整理样式表引用

+   配置 Koala 以将 LESS 编译为常规 CSS

+   查看源映射以调试 LESS

+   使用 LESS 编写网站自定义样式

+   将 JavaScript 编译为静态 CSS 以激活侧栏导航

# 基本 LESS 语法

LESS（[`lesscss.org/`](http://lesscss.org/)）是由 Alexis Sellier（[`cloudhead.io/`](http://cloudhead.io/)）开发的基于 JavaScript 的 CSS 预处理器，也被称为 CloudHead。如前所述，Bootstrap 使用 LESS 来组合其组件样式，尽管它最近才正式发布了 Sass 版本。我们将遵循 Bootstrap 使用 LESS 来组合我们自己的样式规则和管理样式表。

简而言之，LESS 通过引入一些编程特性（如变量、函数和操作）扩展了 CSS。CSS 是一种简单直接的语言，基本上很容易学习。然而，维护静态 CSS 实际上是非常繁琐的，特别是当我们需要处理成千上万行的样式规则和多个样式表时。LESS 提供的功能，如变量、混合、函数和操作（我们很快将会看到）将使我们能够开发更易于维护和组织的样式规则。

## 变量

变量是 LESS 中最基本的特性。在 LESS 中，变量与其他编程语言一样，用于存储常量或值，可以在整个样式表中无限制地重复使用。在 LESS 中，变量用`@`符号声明，后面跟着变量名。变量名可以是数字和字母的组合。在下面的示例中，我们将创建一些 LESS 变量来存储一些十六进制格式的颜色，并在接下来的样式规则中分配它们以传递颜色，如下所示：

```html
@primaryColor: #234fb4;
@secondaryColor: #ffb400;
a {
  color: @primaryColor;
}
button {
  background-color: @secondaryColor;
}
```

使用 LESS 编译器（如 Koala），上述代码将被编译为静态 CSS，如下所示：

```html
a {
  color: #234fb4;
}
button {
  background-color: #ffb400;
}
```

使用变量不仅仅局限于存储颜色，我们可以用变量来存储任何类型的值，例如：

```html
@smallRadius: 3px;
```

使用变量的一个优点是，如果我们需要进行更改，我们只需要更改变量中的值。我们所做的更改将在样式表中该变量的每次出现中生效。这无疑是一个时间节省者。仔细扫描样式表并逐个进行更改，或者使用代码编辑器的**搜索**和**替换**功能可能会导致意外的更改。

### 注意

您会经常看到术语*compile*和*compiler*。这里的编译意味着我们将 LESS 转换为标准的 CSS 格式，可以在浏览器中呈现。编译器是用来做这件事的工具。在这种情况下，我们使用的工具是 Koala。

## 嵌套样式规则

LESS 让我们可以将样式规则嵌套到彼此之中。传统的纯 CSS 中，当我们想要将样式规则应用于元素，比如在`<nav>`元素下，我们可以以以下方式组合样式规则：

```html
nav {
  background-color: #000;
  width: 100%;
}
nav ul {
  padding: 0;
  margin: 0;
}
nav li {
  display: inline;
}
```

从上面的例子中可以看出，每次我们对`<nav>`元素下的特定元素应用样式时，都要重复`nav`选择器。通过使用 LESS，我们能够消除这种重复，并通过嵌套样式规则来简化它，如下所示：

```html
nav {
  background-color: #000;
  width: 100%;
  ul {
    padding: 0;
    margin: 0;
  }
  li {
    display: inline;
  }
}
```

最终，前面的样式规则将返回相同的结果——只是这次我们更有效地编写了样式规则。

## mixin

mixin 是 LESS 中最强大的功能之一。mixin 通过允许我们创建一组 CSS 属性来简化样式规则的声明，并可以包含在样式表中的其他样式规则中。让我们看一下以下代码片段：

```html
.links {
  -webkit-border-radius: 3px;
  -mox-border-radius: 3px;
  border-radius: 3px;
  text-decoration: none;
  font-weight: bold;
}
.box {
-webkit-border-radius: 3px;
  -moz-border-radius: 3px;
  border-radius: 3px;
  position: absolute;
  top: 0;
  left: 0;
}
.button {
  -webkit-border-radius: 3px;
  -mox-border-radius: 3px;
  border-radius: 3px;
}
```

在上面的例子中，我们在三个不同的样式规则中声明了`border-radius`，并加上了供早期版本的 Firefox 和基于 Webkit 的浏览器使用的供应商前缀。在 LESS 中，我们可以通过创建 mixin 来简化`border-radius`的声明。在 LESS 中，mixin 只需用一个类选择器来指定。根据上面的例子，让我们创建一个名为`.border-radius`的 mixin 来包含`border-radius`属性，如下所示：

```html
.border-radius {
  -webkit-border-radius: 3px;
  -moz-border-radius: 3px;
  border-radius: 3px;
}
```

之后，我们将`.border-radius`包含到后续的样式规则中，将包含的属性传递给它们，如下所示：

```html
.links {
  .border-radius;
  text-decoration: none;
  font-weight: bold;
}
.box {
  .border-radius;
  position: absolute;
  top: 0;
  left: 0;
}
.button {
  .border-radius;
}
```

当编译成静态 CSS 时，这段代码将产生与本节第一个代码片段完全相同的输出。

### 参数化 mixin

此外，我们还可以将 mixin 扩展为所谓的**参数化 mixin**。这个特性允许我们添加参数或变量，并使 mixin 可配置。让我们以前面一节中的相同例子为例。但是，这次我们不会分配一个固定的值；相反，我们将其替换为一个变量，如下所示：

```html
 .border-radius(@radius) {
  -webkit-border-radius: @radius;
  -moz-border-radius: @radius;
  border-radius: @radius;
}
```

现在，我们可以将这个 mixin 插入到其他样式规则中，并为每个规则分配不同的值：

```html
a {
  .border-radius(3px);
  text-decoration: none;
  font-weight: bold;
}
div {
  .border-radius(10px);
  position: absolute;
  top: 0;
  left: 0;
}
button {
  .border-radius(12px);
}
```

当我们将其编译成常规 CSS 时，每个样式规则都会应用不同的`border-radius`值，如下所示：

```html
a {
  -webkit-border-radius: 3px;
  -moz-border-radius: 3px;
  border-radius: 3px;
  text-decoration: none;
  font-weight: bold;
}
div {
  -webkit-border-radius: 10px;
  -moz-border-radius: 10px;
  border-radius: 10px;
  position: absolute;
  top: 0;
  left: 0;
}
button {
  -webkit-border-radius: 12px;
  -moz-border-radius: 12px;
  border-radius: 12px;
}
```

#### 在参数化 mixin 中指定默认值

此外，我们可以在参数化 mixin 中指定默认值，这在没有传递参数的情况下会很有用。当我们在 mixin 中设置参数时，就像在前面的例子中所做的那样，LESS 会将参数视为必需的。如果我们没有在其中传递参数，LESS 会返回一个错误。因此，让我们以前面的例子为例，并用默认值，比如`5px`来扩展它，如下所示：

```html
.border-radius(@radius: 5px) {
  -webkit-border-radius: @radius;
  -moz-border-radius: @radius;
  border-radius: @radius;
}
```

前面的参数化 mixin 将默认返回`5px`的边框半径。如果我们在括号内传递自定义值，将覆盖默认值。

### 使用 extend 语法合并 mixin

extend 语法是 LESS 中期待已久的功能。LESS mixin 的一个主要问题是它只是复制 mixin 的包含 CSS 属性，从而产生重复的代码。再次，如果我们处理一个有上千行代码的大型网站，重复的代码量会使样式表的大小变得不必要地大。

在 1.4 版本中，LESS 引入了 extend 语法。extend 语法的形式类似于 CSS 伪类`:extend`。extend 语法将继承包含 mixin 的属性集的 CSS 选择器分组。比较以下两个例子。

首先，我们在没有`:extend`语法的情况下包含一个 mixin：

```html
.border-radius {
  -webkit-border-radius: 3px;
  -moz-border-radius: 3px;
  border-radius: 3px;
}
.box {
  .border-radius;
  position: absolute;
  top: 0;
  left: 0;
}
.button {
  .border-radius;
}
```

上面的 LESS 代码很短，但当它编译成 CSS 时，代码会扩展到大约 17 行，因为`border-radius`属性在每个样式规则中重复或简单复制，如下所示：

```html
.border-radius {
  -webkit-border-radius: 3px;
  -moz-border-radius: 3px;
  border-radius: 3px;
}
.box {
  -webkit-border-radius: 3px;
  -moz-border-radius: 3px;
  border-radius: 3px;
  position: absolute;
  top: 0;
  left: 0;
}
.button {
  -webkit-border-radius: 3px;
  -moz-border-radius: 3px;
  border-radius: 3px;
}
```

在这个第二个例子中，我们将把`:extend`语法应用到同一个 mixin 中：

```html
.border-radius {
  -webkit-border-radius: 3px;
  -moz-border-radius: 3px;
  border-radius: 3px;
}
.box {
  &:extend(.border-radius);
  position: absolute;
  top: 0;
  left: 0;
}
.button {
  &:extend(.border-radius);
}
```

以下是代码转换为普通 CSS 的方式；它甚至比初始未编译的 LESS 代码更短。

```html
.border-radius,
.box
.button {
  -webkit-border-radius: 3px;
  -moz-border-radius: 3px;
  border-radius: 3px;
}
.box {
  position: absolute;
  top: 0;
  left: 0;
} 
```

## 使用数学运算生成值

我们还可以使用 LESS 进行数学运算，如加法、减法、除法和乘法。运算可以非常有用，用于确定长度，比如元素的宽度和高度。在下面的例子中，我们将通过减去填充来计算适当的框宽，以便它适合父容器。

首先，我们将使用`@padding`变量定义填充变量：

```html
@padding: 10px;
```

然后，我们指定框宽并减去`@padding`变量：

```html
.box {
  padding: @padding;
  width: 500px – (@padding * 2);
}
```

请记住，填充占据框的两侧，无论是右和左还是上和下，这就是为什么我们在宽度属性中将`@padding`乘以 2。最后，当我们将这个 LESS 操作编译成常规 CSS 时，这段代码将如下所示：

```html
.box {
  padding: 10px;
  width: 480px;
}
```

在其他情况下，我们也可以对高度属性进行相同操作，如下所示：

```html
.box {
  padding: @padding;
  width: 500px – (@padding * 2);
  height: 500px – (@padding * 2);
}
```

## 使用数学运算和 LESS 函数生成颜色

信不信由你，在 LESS 中，我们可以通过数学运算改变颜色。就像混合颜色一样，只是我们是通过加法、减法、除法和乘法来做的。例如：

```html
.selector {
  color: #aaa + 2;
}
```

编译后，颜色变成了以下样子：

```html
.selector {
  color: #acacac;
}
```

此外，LESS 还提供了一些函数，允许我们将颜色变暗或变亮到一定程度。下面的例子将通过`50%`使`@color`变量中的颜色变亮。

```html
@color: #FF0000;
.selector {
  color: lighten(@color, 50%);
}
```

或者，要使颜色变暗，可以使用`darken()`函数，如下所示：

```html
@color: #FF0000;
.selector {
  color: darken(@color, 50%);
}
```

### 注意

LESS 颜色函数的完整列表可以在 LESS 官方网站的以下页面中找到（[`lesscss.org/functions/#color-operations`](http://lesscss.org/functions/#color-operations)）。

## 引用式导入

这是我在 LESS 中最喜欢的功能之一。引用式导入，顾名思义，允许我们仅作为引用导入外部样式表。在此功能出现之前，使用`@import`指令导入的样式表中的所有样式规则都将被追加，这通常是不必要的。

自从 1.5 版本以来，LESS 引入了`(reference)`选项，将`@import`标记为引用，从而防止外部样式规则被追加。在`@import`后添加`(reference)`标记，如下所示：

```html
@import (reference) 'partial.less'; 
```

### 在导入语句中使用变量

LESS 曾经遇到的一个限制是在`@import`指令中使用变量时（[`github.com/less/less.js/issues/410`](https://github.com/less/less.js/issues/410)）。这是 LESS 中最常请求的功能之一，终于在 LESS 1.4 中得到解决。现在我们可以通过在花括号中命名变量来在`@import`语句中声明变量，例如，`@{variable-name}`。

使用变量和`@import`将允许我们通过变量一次性定义样式表路径。然后，使用变量调用路径，如下所示：

```html
@path: 'path/folder/less/';
@import '@{path}mixins.less';
@import '@{path}normalize.less';
@import '@{path}print.less';
```

这种方法明显比每次导入新样式表时都要添加完整路径更整洁和高效，如下所示：

```html
@import 'path/folder/less/mixins.less';
@import 'path/folder/less/normalize.less';
@import 'path/folder/less/print.less';
```

### 注意

请参考 LESS 官方网站的**导入指令**部分（[`lesscss.org/features/#import-directives-feature`](http://lesscss.org/features/#import-directives-feature)）以获取有关使用 LESS 导入外部样式表的进一步帮助。

## 使用源映射进行更轻松的样式调试

虽然 CSS 预处理器如 LESS 允许我们更高效地编写样式规则，但浏览器仍然只能读取普通的 CSS，这将在调试样式表中出现新问题。

由于浏览器引用生成的 CSS 而不是源文件（LESS），我们可能对样式规则实际在源文件中声明的确切行数一无所知。源映射通过将生成的 CSS 映射回源文件来解决此问题。在支持源映射的浏览器中，您将发现浏览器直接引用源文件。在 LESS 的情况下，浏览器将引用`.less`样式表，如下面的屏幕截图所示：

![使用源映射进行更轻松的样式调试](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00318.jpeg)

在此项目中，我们将生成生成的 CSS 的源映射。因此，如果我们遇到错误，更容易解决。我们可以立即找出样式规则所在的确切位置。

### 注意

查看以下参考资料，了解有关源映射的更多信息：

+   通过 Google 使用 CSS 预处理器（[`developer.chrome.com/devtools/docs/css-preprocessors`](https://developer.chrome.com/devtools/docs/css-preprocessors)）

+   源映射简介（[`blog.teamtreehouse.com/introduction-source-maps`](http://blog.teamtreehouse.com/introduction-source-maps)）

+   使用 LESS 源映射（[`roots.io/using-less-source-maps/`](http://roots.io/using-less-source-maps/)）

## 更多关于 LESS 的信息

LESS 有很多功能，并且将在未来不断增加更多功能。在本书中一次性包含并讨论所有这些功能是不切实际的。因此，以下是一些深入了解的参考资料：

+   LESS 的官方网站（[`lesscss.org/`](http://lesscss.org/)）；了解 LESS 的最佳来源

+   *LESS Web Development Essentials*，*Bass Jobsen*，*Packt Publishing*（[`www.packtpub.com/web-development/less-web-development-essentials`](https://www.packtpub.com/web-development/less-web-development-essentials)）

+   即时 LESS CSS 预处理器（[`www.packtpub.com/web-development/instant-less-css-preprocessor-how-instant`](https://www.packtpub.com/web-development/instant-less-css-preprocessor-how-instant)）

# 外部样式表引用

在前一节中，我们介绍了 LESS 的大量基本语法。现在，我们将开始实际使用 LESS，说到这一点，在我们能够编写自己的样式规则以及重用 Bootstrap 和 Jasny Bootstrap 包中提供的变量、mixin 和函数之前，我们必须使用 LESS 的`@import`指令将它们导入到我们自己的样式表中。

# 行动时间-创建样式表和组织外部样式表引用

执行以下步骤来管理样式表引用：

1.  转到项目目录，并在`assets/less`目录中创建一个名为`var-bootstrap.less`的新样式表。此样式表包含 Bootstrap 预定义变量的副本。此副本将允许我们自定义变量，而不影响初始规范。

1.  因此，在`/bootstrap/less`目录的`variables.less`样式表中复制 Bootstrap 变量。将所有变量粘贴到我们在步骤 1 中创建的`var-bootstrap.less`中。

### 提示

为了方便起见，您还可以直接从 Github 存储库中复制 Bootstrap 变量（[`git.io/7LmzGA`](http://git.io/7LmzGA)）。

1.  创建一个名为`var-jasny.less`的新样式表。与`var-bootstrap.less`类似，此样式表将包含 Jasny Bootstrap 变量的副本。

1.  获取`jasny-bootstrap/less`目录中的`variables.less`中的 Jasny Bootstrap 变量。将所有变量粘贴到我们在步骤 3 中刚创建的`var-jasny.less`样式表中。

### 提示

或者，直接从 Jasny Bootstrap 存储库中复制变量（[`git.io/SK1ccg`](http://git.io/SK1ccg)）。

1.  创建一个名为`frameworks.less`的新样式表。

1.  我们将使用此样式表来导入`bower_component`文件夹中的 Bootstrap 和 Jasny Bootstrap 样式表。

1.  在`frameworks.less`中，创建一个名为`@path-bootstrap`的变量来定义路径，指向名为`less`的文件夹，其中包含 Bootstrap 的所有 LESS 样式表：

```html
@path-bootstrap: '../../bower_components/bootstrap/less/';
```

1.  同样地，创建一个定义路径的变量，指向 Jasny Bootstrap 的`less`文件夹，如下所示：

```html
@path-jasny: '../../bower_components/jasny-bootstrap/less/';
```

1.  还创建一个变量来定义 Ionicons 路径：

```html
@path-ionicons: '../../bower_components/ionicons-less/less/';
```

1.  使用以下代码导入包含变量的样式表：

```html
@import 'var-bootstrap.less';
@import 'var-jasny.less';
```

1.  导入 Bootstrap 和 Jasny Bootstrap 样式表，这些只是构建投资组合网站所需的。使用我们在步骤 6 到 8 中创建的变量指定路径，如下所示：

```html
// Mixins
@import '@{path-bootstrap}mixins.less';

// Reset
@import '@{path-bootstrap}normalize.less';
@import '@{path-bootstrap}print.less';

// Core CSS
@import '@{path-bootstrap}scaffolding.less';
@import '@{path-bootstrap}type.less';
@import '@{path-bootstrap}grid.less';
@import '@{path-bootstrap}forms.less';
@import '@{path-bootstrap}buttons.less';

// Icons 
@import '@{path-ionicons}ionicons.less';

// Components
@import '@{path-bootstrap}navs.less';
@import '@{path-bootstrap}navbar.less';
@import '@{path-bootstrap}jumbotron.less';

// Offcanvas
@import "@{path-jasny}navmenu.less";
@import "@{path-jasny}offcanvas.less";

// Utility classes
@import '@{path-bootstrap}utilities.less';
@import '@{path-bootstrap}responsive-utilities.less';
```

### 提示

您还可以从 Gist ([`git.io/WpBVAA`](http://git.io/WpBVAA))中复制上述代码。

### 注意

为了最小化不需要的额外样式规则，我们从`frameworks.less`中排除了许多 Bootstrap 和 Jasny Bootstrap 样式表，如之前所示。

1.  创建一个名为`style.less`的新样式表。这是我们将要编写自己的样式规则的样式表。

1.  在`style.less`中导入 Bootstrap 变量和混合：

```html
@path-bootstrap: '../../bower_components/bootstrap/less/'; 
@import 'var-bootstrap.less';
@import 'var-jasny.less'; 
@import (reference) '@{path-bootstrap}mixins.less';
```

## *刚刚发生了什么？*

总之，我们刚刚创建了样式表并对其进行了排序。首先，我们创建了两个名为`var-bootstrap.less`和`var-jasny.less`的样式表，用于存储 Bootstrap 和 Jasny Bootstrap 的变量。正如前面提到的，我们制作了这些副本以避免直接更改原始文件。我们还创建了一个名为`frameworks.less`的样式表，其中包含对 Bootstrap 和 Jasny Bootstrap 样式表的引用。

最后，我们创建了名为`style.less`的网站主样式表，并导入了变量和混合，以便它们可以在`style.less`中重复使用。

## 尝试一下 - 命名和组织样式表

在前面的步骤中，我们根据个人喜好组织和命名了文件夹和文件。即使如此，您也不必完全遵循命名约定。请以您自己的方式组织和命名它们。

### 注意

最重要的是要注意`@import`语句引用了正确的文件名。

以下是一些想法：

+   将`var-bootstrap.less`重命名为简单的`vars.less`。

+   或者，创建一个名为`vars`或`configs`的新文件夹，将`var-bootstrap.less`和`var-jasny.less`样式表放在其中。

+   您知道您也可以导入 LESS 样式表而不声明`.less`扩展名。为了简单起见，您可以省略扩展名，例如：

```html
@import (reference) '@{path-bootstrap}mixins.less';
```

## 小测验 - 以下哪个选项不是 LESS 导入选项？

Q1. 在本章的某一部分中，我们讨论了`(reference)`，它只导入外部 LESS 样式表，但将其视为引用。除了`(reference)`之外，LESS 还提供了更多导入样式表的选项。那么，以下哪个不是 LESS 导入选项？

1.  `(less)`

1.  `(css)`

1.  `(multiple)`

1.  `(once)`

1.  `(default)`

Q2. 如何在`@import`语句中使用变量？

1.  `@import '@{variable}style.less';`

1.  `@import '@[variable]style.less';`

1.  `@import '@(variable)style.less';`

# 使用 Koala

HTML 和样式表已经准备好了。现在是时候将它们放在一起，打造一个坚实的投资组合网站了。我们将使用 LESS 语法来编写网站样式。在这里，我们还将像第一个项目一样使用 Koala。这一次，我们将把 LESS 编译成普通的 CSS。

# 行动时间 - 使用 Koala 将 LESS 编译为 CSS

执行以下步骤，使用 Koala 将 LESS 编译为 CSS：

1.  在 Koala 侧边栏中添加项目目录，如下所示：![执行时间 - 使用 Koala 将 LESS 编译为 CSS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00319.jpeg)

1.  选择除了`frameworks.less`和`style.less`之外的所有样式表。右键单击并选择**切换自动编译**。查看以下截图：![执行时间 - 使用 Koala 将 LESS 编译为 CSS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00320.jpeg)

这将关闭所选样式表上的**自动编译**选项，并防止 Koala 意外编译这些样式表。

1.  另外，确保为剩下的两个样式表`frameworks.less`和`style.less`勾选**自动编译**：![采取行动-使用 Koala 将 LESS 编译为 CSS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00321.jpeg)

1.  确保`frameworks.less`和`style.less`的输出设置为`/assets/css`目录，如下面的截图所示：![采取行动-使用 Koala 将 LESS 编译为 CSS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00322.jpeg)

1.  检查两个样式表的**源映射**选项，以生成源映射文件，在调试时会对我们有所帮助：![采取行动-使用 Koala 将 LESS 编译为 CSS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00323.jpeg)

1.  选择两个样式表`frameworks.less`和`style.less`的输出样式进行**压缩**：![采取行动-使用 Koala 将 LESS 编译为 CSS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00324.jpeg)

此选项将生成一个体积较小的 CSS 样式表，因为样式表中的代码将被压缩成一行。因此，样式表将在浏览器中加载得更快，也会节省用户端的带宽消耗。

1.  选择`frameworks.less`并单击**编译**按钮将其编译为 CSS：![采取行动-使用 Koala 将 LESS 编译为 CSS](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00325.jpeg)

1.  对`style.less`执行相同操作。选择它并单击**编译**按钮将其编译为 CSS。在代码编辑器中打开`index.html`，并在`<head>`内链接这两个样式表，如下所示：

```html
<link href="assets/css/frameworks.css" rel="stylesheet">
<link href="assets/css/style.css" rel="stylesheet">
```

## 发生了什么？

在前面的步骤中，我们将网站的主要样式表`frameworks.less`和`style.less`从 LESS 编译为 CSS。现在，你应该将它们与源映射一起放在`assets/css/`目录中。代码已经压缩，因此文件大小相对较小，如下面的截图所示：

![发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00326.jpeg)

样式表的大小相对较小。如图所示，frameworks.css 为 92 kb，而 style.css 仅为 2 kb

此外，我们还在`index.html`中链接了这些 CSS 样式表。但是，由于我们尚未编写自己的样式，网站仍然使用默认的 Bootstrap 样式，如下面的截图所示：

![发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00327.jpeg)

# 使用 LESS 优化投资组合网站

这是你可能在等待的部分，为投资组合网站设置样式。看到网站开始有形状、颜色和外观显然是一种愉快的体验。在本节中，我们将通过使用本章前面介绍的 LESS 语法自定义默认样式并组合我们的样式规则。

# 采取行动-使用 LESS 语法组合网站样式

执行以下步骤来为网站设置样式：

1.  从 Google Font 中添加一个新的字体系列。在这里，我选择了 Varela Round ([`www.google.com/fonts/specimen/Varela+Round`](http://www.google.com/fonts/specimen/Varela+Round))。在任何其他样式表之前放置以下 Google Font 链接：

```html
<link href='http://fonts.googleapis.com/css?family=Varela+Round' rel='stylesheet' type='text/css'>
```

1.  我们将通过更改一些变量来自定义默认样式。在 Sublime Text 中打开`var-bootstrap.less`。首先，我们将更改定义 Bootstrap 主色的`@brand-primary`变量；将其从`#428bca`更改为`#46acb8`：![采取行动-使用 LESS 语法组合网站样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00328.jpeg)

1.  此外，将`@brand-success`变量中的颜色从`#5cb85c`更改为`#7ba47c`：![采取行动-使用 LESS 语法组合网站样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00329.jpeg)

1.  更改`@headings-font-family`变量，该变量定义了标题中使用的字体系列，将其从`inherit`更改为`"Varela Round"`，如下所示：

```html
@headings-font-family: "Varela Round", @font-family-sans-serif; 
```

1.  当用户聚焦在表单字段上时，Bootstrap 默认样式会显示发光效果。此效果的颜色在`@input-border-focus`中指定。将颜色从`#66afe9`更改为`#89c6cb`：![采取行动-使用 LESS 语法组合网站样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00330.jpeg)

1.  在网站的顶部部分，您可以看到导航栏仍然具有 Bootstrap 默认样式，灰色背景和边框颜色，如下截图所示：![采用 LESS 语法编写网站样式的时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00331.jpeg)

1.  这两种颜色分别在`@navbar-default-bg`和`@navbar-default-border`中指定。将这两个变量的值都更改为 transparent，如下所示：

```html
@navbar-default-bg: transparent;
@navbar-default-border: transparent;
```

1.  同样，Jumbotron 部分的默认样式设置为灰色背景色。要删除这种颜色，将`@jumbotron-bg`变量设置为`transparent`，如下所示：

```html
@jumbotron-bg: transparent;
```

1.  稍后我们将继续编辑一些 Bootstrap 变量。与此同时，让我们编写自己的样式规则。首先，我们将显示被 Bootstrap 默认样式隐藏的导航栏切换按钮。在我们的情况下，此按钮将用于打开和关闭侧栏导航。让我们使用以下样式规则强制使此按钮可见：

```html
.portfolio-topbar {
  .navbar-toggle {
    display: block;
  }
}
```

1.  如下截图所示，带有所谓的汉堡图标（[`gizmodo.com/who-designed-the-iconic-hamburger-icon-1555438787`](http://gizmodo.com/who-designed-the-iconic-hamburger-icon-1555438787)）的切换按钮现在可见：![采用 LESS 语法编写网站样式的时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00332.jpeg)

1.  目前，此按钮位于右侧。参考网站蓝图，它应该在左侧。添加`float:left`将其放在左侧，`margin-left:15px`添加一点空白到按钮的左侧，如下所示：

```html
.portfolio-topbar {
  .navbar-toggle {
    display: block;
    float: left;
    margin-left: 15px;
  }
} 
```

1.  在这里，我想自定义切换按钮的默认样式，这也是通过`var-bootstrap.less`中的一些变量指定的。因此，在 Sublime Text 中打开`var-bootstrap.less`。

1.  首先，我们将通过将`@navbar-default-toggle-border-color`变量的值从`#ddd`更改为`transparent`来删除按钮边框，如下所示：

```html
@navbar-default-toggle-border-color: transparent;
```

1.  我们还将删除悬停在按钮上时出现的灰色背景颜色。通过将`@navbar-default-toggle-hover-bg`变量从`#ddd`更改为`transparent`来将灰色背景颜色移出，如下所示：

```html
@navbar-default-toggle-hover-bg: transparent;
```

1.  我希望汉堡图标看起来更加粗体和强烈。因此，在这里，我们希望将颜色改为黑色。将`@navbar-default-toggle-icon-bar-bg`的值从`#888`更改为`#000`：

```html
 @navbar-default-toggle-icon-bar-bg: #000;
```

1.  在这个阶段，网站内容被对齐到左侧，这是任何内容的默认浏览器对齐方式。根据网站蓝图，网站内容应该居中。使用`text-align: center`，如下所示，将内容对齐到中心：

```html
.portfolio-about,
.portfolio-display,
.portfolio-contact,
.portfolio-footer {
  text-align: center;
}
```

1.  添加以下内容将网站名称转换为大写（全部大写字母），使其更大更粗：

```html
.portfolio-about {
  .portfolio-name {
    text-transform: uppercase;
  }
}
```

1.  另一方面，通过将文本颜色指定为灰色浅色，使标语行更加微妙。在这里，我们可以简单地使用 Bootstrap 的预定义变量`@gray-light`来应用灰色，如下所示：

```html
.portfolio-about {
  .portfolio-name {
    text-transform: uppercase;
  }
 .lead {
 color: @gray-light;
 }
}
```

1.  在投资组合部分，使用灰色浅色指定背景颜色，比`@gray-lighter`变量中的颜色更浅。添加背景颜色的目的是为了在投资组合部分加强一点重点。

1.  在这个项目中，我们选择使用 LESS 的`darken()`函数轻微加深白色，如下所示：

```html
.portfolio-display {
  background-color: darken(#fff, 1%);
}
```

### 注意

可以通过使用 LESS 的`lighten()`函数将黑色颜色减轻 99%来替代地实现背景颜色，如`background-color: lighten(#000, 99%);`。

1.  在这个阶段，如果我们看一下投资组合部分，似乎顶部和底部只有很少的空间，如下截图所示：![采用 LESS 语法编写网站样式的时间](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00333.jpeg)

1.  通过添加`padding-top`和`padding-bottom`，为投资组合部分提供更多空间，如下所示：

```html
.portfolio-display {
  background-color: darken(#fff, 1%);
padding-top: 60px;
 padding-bottom: 60px;
}
```

1.  总之，我们在网站中添加了两个标题，包括作品集部分中的一个，以明确显示部分名称。这些标题将共享相同的样式规则。因此，在这种情况下，最好创建一个专门定义标题样式的 mixin。

1.  定义 mixin 以及应用标题样式的 CSS 属性，如下所示：

```html
.heading {
  color: lighten(#000, 70%);  
  text-transform: uppercase;
  font-size: 21px;
  margin-bottom: 60px;  
}
```

1.  为部分标题添加以下样式规则，使其看起来更加柔和，并与作品集部分的背景颜色协调：

```html
.portfolio-display {
...
  h2 {
    &:extend(.heading);
  }
}
```

1.  如下截图所示，每行之间的间距非常小；行之间的距离太近了，如下所示：![采用 LESS 语法编写网站样式的时间到了](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00334.jpeg)

因此，通过为每个作品集项目指定`margin-bottom`来增加更多空间，如下所示：

```html
.portfolio-item {
  margin-bottom: 30px;
}
```

1.  为作品集图片添加样式，如下所示：

```html
.portfolio-image {
  padding: 15px;
  background-color: #fff;
margin-right: auto;
margin-left: auto;
}
```

1.  还要为说明添加样式，如下所示：

```html
.portfolio-caption {
  font-weight: 500;
  margin-top: 15px;
  color: @gray;
}
```

1.  当我们悬停在作品集图片上时，你觉得显示过渡效果怎么样？那看起来会很好，不是吗？在这种情况下，我想在悬停时显示围绕作品集图片的阴影。

1.  使用 Bootstrap 预定义的 mixin`.transition()`和`.box-shadow()`添加效果，如下所示：

```html
.portfolio-image {
  padding: 15px;
  background-color: #fff;
margin-right: auto;
margin-left: auto; 
 .transition(box-shadow 1s);
 &:hover {
 .box-shadow(0 0 8px fade(#000, 10%));
 }
}
```

1.  在作品集部分下面，我们有网站联系表单，已经应用了 Bootstrap 的默认样式。因此，让我们用我们自己的样式规则自定义它。

1.  首先，我们将使用`padding`在联系表单部分的顶部和底部添加更多空间。

1.  使用我们在第 18 步中创建的`.heading` mixin 为标题添加样式：

```html
.portfolio-contact {
...
 h2 {
 &:extend(.heading);
 }
} 
```

1.  目前表格完全跨越整个容器。因此，请添加以下样式规则以设置最大宽度，但仍然在容器中间显示表单，如下所示：

```html
.portfolio-contact {
...
 .form {
 width: 100%;
 max-width: 600px;
 margin-right: auto;
 margin-left: auto;
 }
} 
```

1.  添加以下样式规则使表单元素—`<input>`、`<textarea>`、`<button>`—看起来更加扁平。这些样式规则去除了阴影并降低了边框半径。看一下以下代码：

```html
.portfolio-contact {
...
  .form {
    width: 100%;
    max-width: 600px;
    margin-right: auto;
    margin-left: auto;
 input, textarea, button {
 box-shadow: none;
 border-radius: @border-radius-small;
 }
  }
}
```

1.  添加以下行以为按钮添加样式，并使用过渡效果使其生动起来，如下所示：

```html
.portfolio-contact {
...
  .form {
    width: 100%;
    max-width: 600px;
    margin-right: auto;
    margin-left: auto;
    input, textarea, button {
      box-shadow: none;
      border-radius: @border-radius-small;
    }
 .btn {
 display: block;
 width: 100%;
 .transition(background-color 500ms);
 }
  }
}
```

1.  从这一步开始，我们将为网站的最后一个部分——页脚添加样式规则。页脚包含社交媒体链接 Dribbble 和 Twitter，以及底部的版权声明。

1.  首先，与前面的步骤一样，我们使用`padding`在部分的顶部和底部添加更多空白空间：

```html
.portfolio-footer {
  padding-top: 60px;
  padding-bottom: 60px;
}
```

1.  然后，通过指定`margin-bottom`在社交媒体链接和版权声明之间增加更多空间：

```html
.portfolio-footer {
  padding-top: 60px;
  padding-bottom: 60px;
.social {
    margin-bottom: 30px;
}
} 
```

1.  添加以下行以删除从默认浏览器样式中派生的`<ul>`元素的`padding`：

```html
.portfolio-footer {
...
  .social {
    margin-bottom: 30px;
 ul {
 padding-left: 0;
 }
  }
}
```

1.  在以下代码中添加突出显示的行以将社交媒体链接并排显示：

```html
.portfolio-footer {
...
  .social {
    margin-bottom: 30px;
    ul {
      padding-left: 0;
    }
 li {
 list-style: none;
 display: inline-block;
 margin: 0 15px;
 }
  }
}
```

1.  给社交媒体链接赋予其各自社交媒体品牌的颜色，如下所示：

```html
.portfolio-footer {
...
  .social {
    ...
 a {
 font-weight: 600;
 color: @gray;
 text-decoration: none;
 .transition(color 500ms);
 &:before {
 display: block;
 font-size: 32px;
 margin-bottom: 5px;
 }
 }
 .twitter a:hover {
 color: #55acee;
 }
 .dribbble a:hover {
 color: #ea4c89;
 }
  }
} 
```

### 提示

在 BrandColors（[`brandcolors.net/`](http://brandcolors.net/)）中获取更多热门网站的颜色。

1.  最后，用灰色使版权声明颜色更加柔和：

```html
.portfolio-footer {
...
 .copyright {
 color: @gray-light;
 }
}
```

## *刚刚发生了什么？*

在前面的步骤中，我们通过自定义一些 Bootstrap 变量以及组合我们自己的样式规则来为网站添加样式。编译`style.less`以生成 CSS。此外，你可以从这个 Gist（[`git.io/-FWuiQ`](http://git.io/-FWuiQ)）获取我们应用的所有样式规则。

网站现在应该是可以展示的。以下截图显示了网站在桌面视图中的外观：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00335.jpeg)

网站也是响应式的；布局将根据视口宽度大小进行调整，如下截图所示：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00336.jpeg)

## 尝试更有创意

我们刚刚在前面的部分应用的许多样式规则仅仅是装饰性的。请随意添加更多创意和自定义，如下所示：

+   探索网站的新配色方案。使用 Kuler 等方便的工具（[`kuler.adobe.com/`](https://kuler.adobe.com/)）生成配色方案

+   应用不同的字体系列

+   使用 CSS3 展示更多令人惊叹的过渡效果

## 快速测验-使用 LESS 函数和扩展语法

Q1\. 如何使用 LESS 使颜色变浅？

1.  `lighter(#000, 30%);`

1.  `lighten(#000, 30%);`

1.  `lightening(#000, 30%);`

Q2\. 如何使颜色透明？

1.  `fadeout(#000, 10%);`

1.  `transparentize(#000, 10%);`

1.  `fade-out(#000, 10%);`

Q3\. 以下哪一种方式是在 LESS 中扩展 mixin 的不正确方式？

1.  `.class:extend(.another-class);`

1.  `.class::extend(.another-class);`

1.  `.class {`

`:extend(.another-class);`

`}`

# 改进并使用 JavaScript 使网站正常运行

侧栏导航尚未激活。如果您点击切换按钮，侧栏导航将不会滑入。此外，如果您在 Internet Explorer 8 中查看作品集网站，您会发现许多样式规则没有被应用。这是因为 Internet Explorer 8 不识别网站中使用的 HTML5 元素。为了解决这些问题，我们将不得不使用一些 JavaScript 库。

# 进行操作-使用 Koala 编译 JavaScript

1.  在`assets/js`目录中创建一个名为`html5shiv.js`的新 JavaScript 文件。

1.  从我们通过 Bower 下载的 HTML5Shiv 包中导入`html5shiv.js`到这个文件中：

```html
// @koala-prepend "../../bower_components/html5shiv/dist/html5shiv.js"
```

1.  创建一个名为`bootstrap.js`的新 JavaScript 文件。

1.  在`bootstrap.js`中，导入所需的 JavaScript 库以打开侧栏导航功能，如下所示：

```html
// @koala-prepend "../../bower_components/jquery/dist/jquery.js"
// @koala-prepend "../../bower_components/bootstrap/js/transition.js"
// @koala-prepend "../../bower_components/jasny-bootstrap/js/offcanvas.js"
```

1.  打开 Koala，并确保`html5shiv.js`和`bootstrap.js`的**自动编译**选项已经被选中，如下图所示：![进行操作-使用 Koala 编译 JavaScript](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00337.jpeg)

1.  此外，确保这两个 JavaScript 文件的输出路径设置为`/assets/js`目录，如下图所示：![进行操作-使用 Koala 编译 JavaScript](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00338.jpeg)

1.  点击 Koala 中的**编译**按钮编译这两个 JavaScript 文件，如下所示：![进行操作-使用 Koala 编译 JavaScript](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00339.jpeg)

一旦这些 JavaScript 文件被编译，你应该会发现这些文件的压缩版本`html5shiv.min.js`和`bootstrap.min.js`，如下图所示：

![进行操作-使用 Koala 编译 JavaScript](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00340.jpeg)

1.  在 Sublime Text 中打开`index.html`，并在`<head>`部分使用 Internet Explorer 条件注释标签链接`html5shiv.js`，如下所示：

```html
<!--[if lt IE 9]>
<script type="text/javascript" src="img/html5shiv.min.js"></script>
<![endif]-->
```

1.  在`index.html`的底部链接`bootstrap.min.js`，如下所示：

```html
<script type="text/javascript" src="img/bootstrap.min.js"></script>
```

## *刚刚发生了什么？*

我们刚刚编译了 jQuery 和 Bootstrap JavaScript 库，以启用侧栏功能。我们还使用 HTML5Shiv 在 Internet Explorer 8 中启用了 HTML5 元素。到目前为止，网站已经完全可用。

### 提示

您可以通过这个 Github 页面查看网站([`tfirdaus.github.io/rwd-portfolio/`](http://tfirdaus.github.io/rwd-portfolio/))。

您应该能够滑动进出侧栏导航，并且样式现在应该在 Internet Explorer 8 中可见。看一下以下的截图：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00341.jpeg)

侧栏导航菜单已经滑入。

# 总结

我们刚刚完成了本书的第二个项目。在这个项目中，我们使用 Bootstrap 构建了一个作品集网站。Bootstrap 使得使用提供的快速插入类来构建响应式网站和网站组件变得简单快捷。

此外，我们还使用了一个名为 Jasny Bootstrap 的 Bootstrap 扩展，以包括侧栏导航，这是原始 Bootstrap 中缺少的流行响应式设计模式之一。在网站样式方面，我们使用了 LESS，这是一种 CSS 预处理器，可以让我们更有效地编写样式规则。

总之，在这个项目中我们做了很多事情来让网站正常运行。希望你在这个过程中学到了很多东西。

在下一章中，我们将使用 Foundation 框架开始本书的第三个项目。敬请关注！


# 第七章：使用 Foundation 为企业构建响应式网站

在这个时代，许多人都与互联网连接，拥有一个网站对于任何规模的公司都变得至关重要——无论是小公司还是拥有数十亿美元业务的财富 500 强公司。因此，在本书的第三个项目中，我们将为企业构建一个响应式网站。

构建网站时，我们将采用一个名为 Foundation 的新框架。Foundation 是由总部位于加利福尼亚的 Web 开发机构 ZURB 开发的。它是一个精心打造的框架，具有一系列交互式小部件。在技术方面，Foundation 样式是建立在 Sass 和 SCSS 之上的。因此，在项目进行过程中，我们也将学习这个主题。

为了开展这个项目，首先让我们假设你有一个商业理念。这可能有点夸张，但这是一个可能会变成数十亿美元业务并改变世界的杰出理念。你有一个很棒的产品，现在是建立网站的时候了。你非常兴奋，迫不及待地想要改变世界。

所以，话不多说，让我们开始这个项目。

本章将主要围绕 Foundation 展开，我们将在此讨论的主题包括：

+   在线框架中检查网站设计和布局

+   研究 Foundation 的特性、组件和附加组件

+   管理项目目录和资产

+   通过 Bower 获取 Foundation 包

+   构建网站 HTML 结构

# 检查网站布局

首先，与我们之前做的两个项目不同，我们将在本章中进一步研究网站布局的线框图。在检查完之后，我们将发现网站所需的 Foundation 组件，以及 Foundation 包中可能不包含的组件和资产。以下是正常桌面屏幕尺寸下的网站布局：

![检查网站布局](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00342.jpeg)

前面的线框图显示，网站将有五个部分。第一部分，显而易见的是页眉。页眉部分将包含网站标志、菜单导航、几行标语和一个按钮——许多人称之为行动号召按钮。

### 注意

以下是关于行动号召按钮的指南、最佳实践和示例的一些参考资料。这些是旧的帖子，但其中的指南、技巧和原则是永恒的；至今仍然有效和相关。

+   Call to Action Buttons: Examples and Best Practices ([`www.smashingmagazine.com/2009/10/13/call-to-action-buttons-examples-and-best-practices/`](http://www.smashingmagazine.com/2009/10/13/call-to-action-buttons-examples-and-best-practices/)).

+   "Call To Action" Buttons: Guidelines, Best Practices And Examples ([`www.hongkiat.com/blog/call-to-action-buttons-guidelines-best-practices-and-examples/`](http://www.hongkiat.com/blog/call-to-action-buttons-guidelines-best-practices-and-examples/)).

+   How To Design Call to Action Buttons That Convert ([`unbounce.com/conversion-rate-optimization/design-call-to-action-buttons/`](http://unbounce.com/conversion-rate-optimization/design-call-to-action-buttons/)).

通常，人们在决定购买之前需要尽可能多地了解优缺点。因此，在页眉下，我们将显示产品的项目列表或提供的关键功能。

除了功能列表，我们还将在滑块中显示客户的推荐。根据[www.entrepreneur.com](http://www.entrepreneur.com) ([`www.entrepreneur.com/article/83752`](http://www.entrepreneur.com/article/83752))，显示客户的推荐是推动更多客户或销售的有效方式之一，这对业务最终是有利的。

在推荐部分下方，网站将显示计划和价格表。最后一个部分将是包含次要网站导航和指向 Facebook 和 Twitter 的链接的页脚。

现在让我们看看网站在较小的视口大小下的布局，如下所示：

![检查网站布局](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00343.jpeg)

与我们在之前的项目中构建的网站类似，所有内容都将被堆叠。口号和行动号召按钮都居中对齐。导航中的菜单现在被描述为汉堡图标。接下来，我们将看看 Foundation 在其套件中提供了什么来构建网站。

# 深入了解 Foundation

Foundation ([`foundation.zurb.com/`](http://foundation.zurb.com/))是最流行的前端开发框架之一。它被许多知名公司使用，如 Pixar、华盛顿邮报、Warby Parker ([`www.warbyparker.com/`](https://www.warbyparker.com/))等。正如前面提到的，Foundation 附带了常见的网页组件和交互式小部件。在这里，我们将研究我们将用于网站的组件和小部件。

## 网格系统

网格系统是框架的一个组成部分。它是使管理网页布局感觉轻松的一件事。Foundation 的网格系统包括可以通过提供的类适应窄视口大小的十二列。与我们在前几章中探讨的两个框架类似，网格由行和列组成。每个列都必须包含在行内，以使布局正确跨越。

在 Foundation 中，应用`row`类来定义一个元素作为行，并将元素应用`columns`或`column`类来定义为列。例如：

```html
<div class="row">
<div class="columns">
</div>
<div class="columns">
</div>
</div>
```

您还可以从`columns`中省略*s*，如下所示：

```html
<div class="row">
<div class="column">
</div>
<div class="column">
</div>
</div>
```

列的大小通过以下一系列类来定义：

+   `small-{n}`：这指定了小视口大小范围（大约 0 像素-640 像素）中的网格列宽度。

+   `medium-{n}`：这指定了中等视口大小范围（大约 641 像素-1,024 像素）中的网格列宽度。

+   `large-{n}`：这指定了大视口大小范围（大约 1,025 像素-1,440 像素）中的网格列宽度。

### 注意

我们在前面的类名中给出的`{n}`变量代表从`1`到`12`的数字。一行中的列数之和不应超过`12`。

这些类可以在单个元素中结合应用。例如：

```html
<div class="row">
<div class="small-6 medium-4 columns"></div>
<div class="small-6 medium-8 columns"></div>
</div>
```

上面的示例在浏览器中产生以下结果：

![网格系统](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00344.jpeg)

调整视口大小，使其足够小，以便列的宽度根据分配的类进行调整。在这种情况下，每个列的宽度相等，因为它们都分配了`small-6`类：

![网格系统](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00345.jpeg)

### 注意

通常，您可以通过拖动浏览器窗口来调整视口大小。如果您使用 Chrome，可以激活设备模式和移动模拟器([`developer.chrome.com/devtools/docs/device-mode`](https://developer.chrome.com/devtools/docs/device-mode))。或者，如果您使用 Firefox，可以启用响应式设计视图([`developer.mozilla.org/en-US/docs/Tools/Responsive_Design_View`](https://developer.mozilla.org/en-US/docs/Tools/Responsive_Design_View))，这将允许您调整视口大小，而无需拖动 Firefox 窗口。

## 按钮

按钮对于任何类型的网站都是必不可少的，我们肯定会在网站的某些地方添加按钮。Foundation 使用`button`类来定义一个元素作为按钮。您可以将该类分配给元素，例如`<a>`和`<button>`。该类应用了默认的按钮样式，如下面的屏幕截图所示：

![按钮](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00346.jpeg)

此外，您可以包含其他类来定义按钮的颜色或上下文。使用`secondary`、`success`、`alert`中的一个类来设置按钮颜色：

![按钮](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00347.jpeg)

您还可以使用`tiny`、`small`或`large`中的一个类来指定按钮大小：

![按钮](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00348.jpeg)

使用`radius`和`round`中的一个类使按钮更漂亮，带有圆角：

![按钮](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00349.jpeg)

### 注

还有一些类来形成按钮。此外，Foundation 还提供多种类型的按钮，如按钮组、分割按钮和下拉按钮。因此，您可以转到 Foundation 文档的**按钮**部分，了解更多信息。

## 导航和顶部栏

网站上一个重要的部分是导航。导航帮助用户从一个页面浏览到另一个页面。在这种情况下，Foundation 提供了几种导航类型，其中之一称为顶部栏。Foundation 的顶部栏将位于网站的顶部，任何内容或部分之前。以下是 Foundation 默认样式下顶部栏的外观：

![导航和顶部栏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00350.jpeg)

顶部栏是响应式的。尝试调整浏览器的视口大小，使其足够小，您会发现导航隐藏在菜单中，需要点击**菜单**才能显示完整的菜单项列表：

![导航和顶部栏](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00351.jpeg)

Foundation 顶部栏主要由`top-bar`类形成应用样式，`data-topbar`属性运行与顶部栏相关的 JavaScript 函数，最后`role="navigation"`以提高可访问性。

因此，以下代码是我们开始在 Foundation 中构建顶部栏的方式：

```html
<nav class="top-bar" data-topbar role="navigation">      
  ...
</nav>
```

Foundation 将顶部栏内容分为两个部分。左侧区域称为标题区域，包括网站名称或标志。Foundation 使用列表元素构建此部分，如下所示：

```html
<ul class="title-area">
<li class="name">
    <h1><a href="#">Hello</a></h1>
  </li>
  <li class="toggle-topbar menu-icon">
<a href="#"><span>Menu</span></a>
</li>
</ul>
```

第二部分简称为顶部栏部分。通常，此部分包含菜单、按钮和搜索表单。Foundation 使用`top-bar-section`类设置此部分，以及`left`和`right`类来指定对齐方式。因此，将所有内容放在一起，以下是构建基本 Foundation 顶部栏的完整代码，如前面的屏幕截图所示：

```html
<nav class="top-bar" data-topbar role="navigation">
  <ul class="title-area">
    <li class="name">
      <h1><a href="#">Hello</a></h1>
    </li>
    <li class="toggle-topbar menu-icon">
<a href="#"><span>Menu</span></a>
</li>
  </ul>
<section class="top-bar-section">
    <ul class="right">
      <li class="active"><a href="#">Home</a></li>
      <li><a href="#">Blog</a></li>
      <li><a href="#">About</a></li>
      <li><a href="#">Contact</a></li>
    </ul>
  </section>
</nav>
```

当然，您需要在文档中预先链接 Foundation CSS 样式表，以查看顶部栏的外观。

## 价格表

无论您是销售产品还是服务，您都应该命名您的价格。

由于我们将为企业构建网站，因此需要显示价格表。幸运的是，Foundation 已经将此组件包含在其核心中，因此我们不需要第三方扩展。为了灵活性，Foundation 使用列表元素结构化价格表，如下所示：

```html
<ul class="pricing-table pricing-basic">
   <li class="title">Basic</li>
   <li class="price">$10<small>/month</small></li>
   <li class="description">Perfect for personal use.</li>
   <li class="bullet-item">1GB Storage</li>
   <li class="bullet-item">1 User</li>
   <li class="bullet-item">24/7 Support</li>
<li class="cta-button">
<a class="button success round" href="#">Sign Up</a>
</li>
</ul>
```

列表中的每个项目都使用一个类进行设置，我相信类名已经解释了它自己。鉴于前面的 HTML 结构和 Foundation CSS 提供的默认样式，输出结果非常好，如下面的屏幕截图所示：

![价格表](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00352.jpeg)

## 在 Orbit 中移动

轮播或滑块是网络上最流行的设计模式之一。尽管在可访问性方面存在争议，但许多人仍然喜欢在他们的网站上使用它，我们也是如此。在这里，我们希望使用 Orbit ([`foundation.zurb.com/docs/components/orbit.html`](http://foundation.zurb.com/docs/components/orbit.html))，Foundation jQuery 插件来显示内容滑块。

Orbit 是可定制的，我们可以完全控制输出，以及通过类、属性或 JavaScript 初始化幻灯片的行为。我们还可以在 Orbit 幻灯片中添加几乎任何内容，包括文本内容、图像、链接和混合内容。不用说，我们可以为其大部分部分设置样式。

### 轨道是如何构建的？

Foundation 使用`list`元素来构建幻灯片容器，以及幻灯片，并使用 HTML5 的`data-`属性`data-orbit`来启动功能。以下是 Orbit 滑块结构的基本示例，包含两张图片幻灯片：

```html
<ul class="example-orbit" data-orbit>
<li><img src="img/image.jpg" alt="" /></li>
<li class="active"><img src="img/image2.jpg" alt="" /></li>
</ul>
```

部署 Orbit 非常简单，从技术上讲，它几乎可以包含任何类型的内容在幻灯片中，而不仅仅是图片。随着我们构建网站，我们将更多地关注这一点。

### 注意

目前，可以随意探索 Foundation 官方网站的 Orbit 滑块部分（[`foundation.zurb.com/docs/components/orbit.html`](http://foundation.zurb.com/docs/components/orbit.html)），在我看来，这是了解 Orbit 滑块的最佳地方。

## 添加附加组件，字体图标

Foundation 还提供了一些附加组件，其中之一是 Webicons（[`zurb.com/playground/social-webicons`](http://zurb.com/playground/social-webicons)）。毋庸置疑，我们需要社交图标，由于这些图标基本上是矢量图，因此在任何屏幕分辨率（普通或高清）下都可以无限缩放，因此将保持清晰和锐利。请查看以下图标集：

![添加附加组件，字体图标](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00353.jpeg)

图标集中的一些字形

除了这个图标集，您还可以找到以下内容：

+   一系列起始模板（[`foundation.zurb.com/templates.html`](http://foundation.zurb.com/templates.html)），这些模板对于启动新网站和网页非常有用。

+   响应式表格（[`foundation.zurb.com/responsive-tables.html`](http://foundation.zurb.com/responsive-tables.html)）

+   模板（[`foundation.zurb.com/stencils.html`](http://foundation.zurb.com/stencils.html)），您会发现对于勾画和原型设计新网站很有用

## 关于 Foundation 的更多信息

详细介绍 Foundation 的每个角落和方面超出了本书的范围。这些是我们将在项目和网站中使用的框架的最基本组件。

幸运的是，Packt Publishing 出版了几本专门介绍 Foundation 的书籍。如果您有兴趣进一步探索这个框架，我建议您看一下以下书籍：

+   *学习 Zurb Foundation*，*Kevin Horek*，*Packt Publishing*（[`www.packtpub.com/web-development/learning-zurb-foundation`](https://www.packtpub.com/web-development/learning-zurb-foundation)）

+   *ZURB Foundation Blueprints*，*James Michael Stone*，*Packt Publishing*（[`www.packtpub.com/web-development/zurb-foundation-blueprints`](https://www.packtpub.com/web-development/zurb-foundation-blueprints)）

# 额外所需资产

除了 Foundation 自己的组件之外，我们还需要一些文件。这些文件包括网站页眉的图像封面，将代表网站功能列表部分的图标，favicon 图像以及 Apple 图标，显示在推荐部分的头像图像，以及最后（也很重要）网站标志。

在页眉图像方面，我们将使用 Alejandro Escamilla 拍摄的以下图像，该图像显示了一名男子正在使用他的 Macbook Air；尽管屏幕似乎关闭了（[`unsplash.com/post/51493972685/download-by-alejandro-escamilla`](http://unsplash.com/post/51493972685/download-by-alejandro-escamilla)）：

![额外所需资产](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00354.jpeg)

用于显示功能列表项旁边的图标是由 Ballicons 的 Nick Frost 设计的（[`ballicons.net/`](http://ballicons.net/)）。我们将在网站中包含该系列中的以下图标：

![额外所需资产](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00355.jpeg)

以下是使用 Photoshop 动作 AppIconTemplate 生成的 favicon 和 Apple 图标：

![额外所需资产](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00356.jpeg)

Favicon 和 Apple 图标

我们将使用 WordPress 的神秘人作为默认头像。此头像图像将显示在推荐语句上方，如下线框所示：

![额外所需资产](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00357.jpeg)

神秘人

该网站的标志是用 SVG 制作的，以确保清晰度和可伸缩性。标志显示在以下截图中：

![额外所需资产](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00358.jpeg)

您可以从随本书提供的源文件中获取所有这些资产。否则，可以从我们在前面段落中显示的 URL 中获取它们。

# 项目目录、资产和依赖项

一旦我们评估了网站布局、框架功能和所有所需的资产，我们将开始着手项目。在这里，我们将开始整理项目目录和资产。此外，我们将通过 Bower 获取并记录所有项目依赖项，第二个项目使用 Bootstrap。所以，是时候行动了。

# 行动时间-组织项目目录、资产和依赖项

1.  在`htdocs`文件夹中，创建一个新文件夹，命名为`startup`。这是网站将驻留的文件夹。

1.  在`startup`文件夹中，创建一个名为`assets`的文件夹，以包含所有资产，如样式表、JavaScript 文件、图像等。

1.  在`assets`文件夹内创建文件夹以对这些资产进行分组：

+   `css`用于样式表。

+   `js`包含 JavaScript 文件。

+   `scss`包含 SCSS 样式表（关于 SCSS 的更多内容请参见下一章）。

+   `img`包含图像。

+   `fonts`包含字体图标。

1.  添加图像，包括网站标志、页眉图像、图标和头像图像，如下截图所示：![行动时间-组织项目目录、资产和依赖项](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00359.jpeg)

1.  现在，我们将下载项目依赖项，其中包括 Foundation 框架、图标、jQuery 和其他几个库。因此，让我们打开终端或命令提示符（如果您使用 Windows）。然后，使用`cd`命令导航到项目目录：

+   在 Windows 中：`cd \xampp\htdocs\startup`

+   在 OSX 中：`cd /Applications/XAMPP/htdocs/startup`

+   在 Ubuntu 中：`cd /opt/lampp/htdocs/startup`

1.  与第二个项目一样，键入命令，填写提示以设置项目规范，包括项目名称和项目版本，如下截图所示：![行动时间-组织项目目录、资产和依赖项](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00360.jpeg)

当所有提示都填写并完成时，Bower 将生成一个名为`bower.json`的新文件，以存放所有信息。

1.  在安装项目依赖项之前，我们将设置依赖项文件夹的目标位置。为此，请创建一个名为`.bowerrc`的点文件。将以下行保存在文件中：

```html
{
  "directory": "components"
}
```

这行将告诉 Bower 将文件夹命名为`components`而不是`bower_components`。一旦配置设置完成，我们就可以安装库，首先安装 Foundation 包。

1.  要通过 Bower 安装 Foundation 包，请键入`bower install foundation ––save`。确保包括`--save`参数以记录 Foundation 在`bower.json`文件中。

### 注意

除了 Foundation 主要包（例如样式表和 JavaScript 文件）外，此命令还将获取与 Foundation 相关的库，即：

Fastclick ([`github.com/ftlabs/fastclick`](https://github.com/ftlabs/fastclick))

jQuery ([`jquery.com/`](http://jquery.com/))

jQuery Cookie ([`github.com/carhartl/jquery-cookie`](https://github.com/carhartl/jquery-cookie))

jQuery Placeholder ([`github.com/mathiasbynens/jquery-placeholder`](https://github.com/mathiasbynens/jquery-placeholder))

Modernizr ([`modernizr.com/`](http://modernizr.com/))

1.  Foundation 字体图标设置在一个单独的存储库中。要安装它，请键入`bower install foundation-icons --save`命令。

1.  Foundation 图标包带有样式表，通过 HTML 类指定和呈现图标文件。在这里，我们需要将包文件夹中的字体复制到我们自己的`fonts`文件夹中。请看下面的屏幕截图：![行动时间-组织项目目录、资产和依赖关系](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00361.jpeg)

## *刚刚发生了什么？*

我们刚刚创建了项目目录，以及用于组织项目资产的文件夹。此外，我们还通过 Bower 安装了构建网站所需的库，其中包括 Foundation 框架。

在添加了图像和库之后，我们将在下一节中构建网站的主页标记。因此，不用再多说，让我们继续前进，再次行动起来。

# 行动时间-构建网站的 HTML 结构

1.  创建一个名为`index.html`的新 HTML 文件。然后，在 Sublime Text 中打开它，这是本书中我们选择的代码编辑器。

1.  让我们按照以下方式添加基本的 HTML5 结构：

```html
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Startup</title>
</head>
<body>

</body>
</html>
```

1.  添加 meta`X-UA-Compatible`变量，内容值为`IE=edge`，以允许 Internet Explorer 使用其最新的渲染版本：

```html
<meta http-equiv="X-UA-Compatible" content="IE=edge">
```

1.  不要忘记 meta`viewport`标签，以使网站响应式；将其添加到`<head>`中，如下所示：

```html
<meta name="viewport" content="width=device-width, initial-scale=1">
```

1.  在 meta 视口标签下方添加网站图标以及苹果图标，如下所示：

```html
<link rel="apple-touch-icon" href="assets/img/apple-icon.png">
<link rel="shortcut icon" href="assets/img/favicon.png" type="image/png">
```

1.  为了搜索引擎结果的目的，添加 meta 描述：

```html
<meta name="description" content="A startup company website built using Foundation">
```

1.  内容的 HTML 标记将遵循本书早期部分讨论的 Foundation 指南。此外，我们可能会在元素中添加额外的类来自定义样式。让我们从添加网站`<header>`开始，为此在`<body>`中添加以下行：

```html
<header class="startup-header">
...
</header>
```

1.  接下来，在标题中添加网站导航栏，如下所示：

```html
<header class="startup-header">
<div class="contain-to-grid startup-top-bar">
<nav class="top-bar" data-topbar>
 <ul class="title-area">
 <li class="name startup-name">
 <h1><a href="#">Startup</a></h1>
 </li>
<li class="toggle-topbar menu-icon">
 <a href="#"><span>Menu</span></a>
</li>
</ul>
 <section class="top-bar-section">
 <ul class="right">
 <li><a href="#">Features</a></li>
<li><a href="#">Pricing</a></li>
<li><a href="#">Blog</a></li>
<li class="has-form log-in"><a href="" class="button secondary round">Log In</a></li>
<li class="has-form sign-up"><a href="#" class="button round">Sign Up</a></li>
 </ul>
</section>
</nav>
</div>
</header>
```

1.  在导航栏 HTML 标记下方，按照以下方式添加标语和行动号召按钮：

```html
<header class="startup-header"> 
  ...
<div class="panel startup-hero">
 <div class="row">
<h2 class="hero-title">Stay Cool and be Awesome</h2>
<p class="hero-lead">The most awesome web application in the galaxy.</p>
</div>
 <div class="row">
<a href="#" class="button success round">Signup</a>
 </div>
</div>
</header>
```

1.  接下来，我们将添加包含产品功能列表部分、推荐部分和计划价格表的网站正文内容。首先，在标题下方添加一个包裹正文内容部分的`<div>`，如下所示：

```html
<div class="startup-body">
  ...
</div>
```

1.  在`<div>`中，按照以下方式添加功能列表部分的 HTML 标记：

```html
<div class="startup-body">
<div class="startup-features">
<div class="row">
 <div class="medium-6 columns">
 <div class="row">
 <div class="small-3 medium-4 columns">
 <figure>
<img src="img/analytics.png" height="128" width="128" alt="">
 </figure>
</div>
 <div class="small-9 medium-8 columns">
 <h4>Easy</h4>
<p>This web application is super easy to use. No complicated setup. It just works out of the box.</p>
 </div>
 </div>
 </div>
 <div class="medium-6 columns">
 <div class="row">
<div class="small-3 medium-4 columns">
 <figure>
 <img src="img/clock.png" height="128" width="128" alt="">
 </figure>
 </div>
 <div class="small-9 medium-8 columns">
 <h4>Fast</h4>
 <p>This web application runs in a blink of eye. There is no other application that is on par with our application in term of speed.</p>
 </div>
 </div>
 </div>
 </div>
 <div class="row">
 <div class="medium-6 columns">
 <div class="row">
<div class="small-3 medium-4 columns">
 <figure>
<img src="img/target.png" height="128" width="128" alt="">
</figure>
 </div>
<div class="small-9 medium-8 columns">
 <h4>Secure</h4>
<p>Your data is encyrpted with the latest Kryptonian technology. It will never be shared to anyone. Rest assured, your data is totally safe.</p>
 </div>
 </div>
 </div>
 <div class="medium-6 columns">
 <div class="row">
 <div class="small-3 medium-4 columns">
 <figure>
 <img src="img/bubbles.png" height="128" width="128" alt="">
 </figure>
 </div>
 <div class="small-9 medium-8 columns">
 <h4>Awesome</h4>
 <p>It's simply the most awesome web application and make you the coolest person in the galaxy. Enough said.</p>
 </div>
</div>
 </div>
 </div>
</div>
</div> 
```

此部分的列划分是指网站线框图中显示的布局。因此，正如您从刚刚添加的代码中看到的那样，每个功能列表项都分配了`medium-6`列，因此每个项目的列宽将相等。

1.  在功能列表部分下方，我们按照以下方式添加了推荐部分的 HTML 标记：

```html
<div class="startup-body">
...
<div class="startup-testimonial">
 <div class="row">
 <ul class="testimonial-list" data-orbit>
 <li data-orbit-slide="testimonial-1">
 <div>
 <blockquote>Lorem ipsum dolor sit amet, consectetur adipisicing elit. Dolor numquam quaerat doloremque in quis dolore enim modi cumque eligendi eius.</blockquote>
 <figure>
 <img class="avatar" src="img/mystery.png" height="128" width="128" alt="">
 <figcaption>John Doe</figcaption>
 </figure>
 </div>
 </li>
 <li data-orbit-slide="testimonial-2">
 <div>
 <blockquote>Lorem ipsum dolor sit amet, consectetur adipisicing elit.</blockquote>
 <figure>
 <img class="avatar" src="img/mystery.png" height="128" width="128" alt="">
 <figcaption>Jane Doe</figcaption>
 </figure>
 </div>
 </li>
 </ul>
 </div>
 </div>
</div>
```

1.  根据线框布局，我们应该在推荐部分下方添加计划价格表，如下所示：

```html
<div class="startup-body">
<!-- ... feature list section … -->
<!-- ... testimonial section … --> 
<div class="startup-pricing">
 <div class="row">
 <div class="medium-4 columns">
 <ul class="pricing-table pricing-basic">
 <li class="title">Basic</li>
 <li class="price">$10<small>/month</small></li>
 <li class="description">Perfect for personal use.</li>
 <li class="bullet-item">1GB Storage</li>
 <li class="bullet-item">1 User</li>
 <li class="bullet-item">24/7 Support</li>
 <li class="cta-button"><a class="button success round" href="#">Sign Up</a></li>
 </ul>
 </div>
 <div class="medium-4 columns">
 <ul class="pricing-table pricing-team">
 <li class="title">Team</li>
 <li class="price">$50<small>/month</small></li>
 <li class="description">For a small team.</li>
 <li class="bullet-item">50GB Storage</li>
 <li class="bullet-item">Up to 10 Users</li>
 <li class="bullet-item">24/7 Support</li>
 <li class="cta-button"><a class="button success round" href="#">Sign Up</a></li>
 </ul>
 </div>
 <div class="medium-4 columns">
 <ul class="pricing-table pricing-enterprise">
 <li class="title">Enterprise</li>
 <li class="price">$300<small>/month</small></li>
 <li class="description">For large corporation</li>
 <li class="bullet-item">Unlimited Storage</li>
 <li class="bullet-item">Unlimited Users</li>
 <li class="bullet-item">24/7 Priority Support</li>
 <li class="cta-button"><a class="button success round" href="#">Sign Up</a></li>
 </ul>
 </div>
 </div>
 </div>
</div>
```

1.  最后，在正文内容下方添加网站页脚，如下所示：

```html
</div> <!—the body content end --> 
<footer class="startup-footer">
 <div class="row footer-nav">
 <ul class="secondary-nav">
 <li><a href="#">About</a></li>
 <li><a href="#">Contact</a></li>
 <li><a href="#">Help</a></li>
 <li><a href="#">Careers</a></li>
 <li><a href="#">Terms</a></li>
 <li><a href="#">Privacy</a></li>
 </ul>
 <ul class="social-nav">
 <li><a class="foundicon-facebook" href="#">Facebook</a></li>
 <li><a class="foundicon-twitter" href="#">Twitter</a></li>
 </ul>
 </div>
 <div class="row footer-copyright">
 <p>Copyright 2014 Super Awesome App. All rights reserved.</p>
 </div>
 </footer>
</body> 
```

## *刚刚发生了什么？*

我们只是按照 Foundation 指南构建了网站内容和部分的 HTML 标记。我们还在途中添加了额外的类，以便稍后自定义 Foundation 默认样式。

自从构建 HTML 标记以来，我们还没有添加任何样式；此时的网站看起来是白色和简单的，如下面的屏幕截图所示：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/rsps-web-dsn-bgd-2e/img/image00362.jpeg)

### 提示

我们刚刚添加的 HTML 的完整代码也可以在[`git.io/qvdupQ`](http://git.io/qvdupQ)找到。

# 摘要

本章有效地开始了我们的第三个项目。在这个项目中，我们使用 Foundation 为一家初创公司构建网站。我们浏览了 Foundation 的特性，并将其中一些特性应用到了网站中。不过，本章中我们只添加了网站的 HTML 结构。此时的网站看起来仍然是白色和简单的。我们需要编写样式来定义网站的外观和感觉，这正是我们将在下一章中做的事情。

我们将使用 Sass 来编写网站样式，Sass 是 CSS 预处理器，也定义了 Foundation 基本样式。因此，在下一章的开始，我们将首先学习如何使用 Sass 变量、混合、函数和其他 Sass 特性，然后再编写网站样式。

看起来还有很多工作要做才能完成这个项目。因此，话不多说，让我们继续下一章吧。
