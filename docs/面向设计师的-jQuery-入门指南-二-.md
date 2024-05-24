# 面向设计师的 jQuery 入门指南（二）

> 原文：[`zh.annas-archive.org/md5/FFDF3B70B19F674D777B2A63156A89D7`](https://zh.annas-archive.org/md5/FFDF3B70B19F674D777B2A63156A89D7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：构建交互式导航菜单

> 在 2003 年，A List Apart（[`alistapart.com`](http://alistapart.com)）上发布的一篇文章叫做 *Suckerfish Dropdowns* 展示了如何仅使用 HTML 和 CSS（仅在 IE6 中稍微需要一点 JavaScript 帮助）就可以构建复杂的多级下拉菜单。Suckerfish 名字源自该技术的精美设计演示，其中包含了鲸鲨和寄生鱼的插图。虽然有用，但原始版本要求网站访客在导航时不要将鼠标移出菜单区域，否则菜单会消失。多年来，Suckerfish Dropdowns 激发了许多衍生产品 — Son of Suckerfish，Improved Suckerfish 等，试图解决原始版本的缺点。由于 jQuery 能够让一切变得更好，我们将使用 Superfish jQuery 插件来构建这个想法，使菜单更易于使用。

Superfish 插件的开发者 Joel Birch 表示，插件的大部分支持问题来自于人们不理解菜单的 CSS。为了确保你对 CSS 有牢固的掌握，我强烈建议阅读 *A List Apart* 上的原始 Suckerfish Dropdowns 文章，网址为 [`www.alistapart.com/articles/dropdowns`](http://www.alistapart.com/articles/dropdowns)。

要开始使用此插件，我们将构建一个基本的 Suckerfish 菜单。由于该菜单仅需要 CSS，因此如果我们禁用 JavaScript，我们仍然可以获得一个交互式菜单。菜单只是针对启用 JavaScript 的用户进行了改进。

在本章中，我们将学习以下主题：

+   使用 Superfish jQuery 插件创建水平下拉菜单

+   使用 Superfish 插件创建垂直飞出菜单

+   自定义使用 Superfish 插件创建的下拉和飞出菜单

# 水平下拉菜单

长期以来，水平下拉菜单一直是桌面软件中的常见项目，但在网站中实现起来可能很具挑战性，甚至是不可能的，直到 CSS 和 JavaScript 最终出现，使其成为可能。

# 行动时间 — 创建水平下拉菜单

让我们看看如何使用 Superfish 插件创建水平下拉菜单：

1.  要开始，我们将创建一个简单的 HTML 页面和相关的文件夹和文件，就像我们在 第一章 中创建的那样，*Designer, Meet jQuery*。我们 HTML 文件的主体将包含一个嵌套的无序列表导航菜单，如下所示：

    ```js
    <ul id="sfNav" class="sf-menu">
    <li><a href="#">Papilionidae</a>
    <ul>
    <li><a href="#">Common Yellow Swallowtail</a></li>
    <li><a href="#">Spicebush Swallowtail</a></li>
    <li><a href="#">Lime Butterfly</a></li>
    <li><a href="#">Ornithoptera</a>
    <ul>
    <li><a href="#">Queen Victoria's Birdwing</a></li>
    <li><a href="#">Wallace's Golden Birdwing</a></li>
    <li><a href="#">Cape York Birdwing</a></li>
    </ul>
    </li>
    </ul>
    </li>
    <li><a href="#">Pieridae</a>
    <ul>
    <li><a href="#">Small White</a></li>
    <li><a href="#">Green-veined White</a></li>
    <li><a href="#">Common Jezebel</a></li>
    </ul>
    </li>
    <li><a href="#">Lycaenidae</a>
    <ul>
    <li><a href="#">Xerces Blue</a></li>
    <li><a href="#">Karner Blue</a></li>
    <li><a href="#">Red Pierrot</a></li>
    </ul>
    </li>
    <li><a href="#">Riodinidae</a>
    <ul>
    <li><a href="#">Duke of Burgundy</a></li>
    <li><a href="#">Plum Judy</a></li>
    </ul>
    </li>
    <li><a href="#">Nymphalidae</a>
    <ul>
    <li><a href="#">Painted Lady</a></li>
    <li><a href="#">Monarch</a></li>
    <li><a href="#">Morpho</a>
    <ul>
    <li><a href="#">Sunset Morpho</a></li>
    <li><a href="#">Godart's Morpho</a></li>
    </ul>
    </li>
    <li><a href="#">Speckled Wood</a></li>
    </ul>
    </li>
    <li><a href="#">Hesperiidae</a>
    <ul>
    <li><a href="#">Mallow Skipper</a></li>
    <li><a href="#">Zabulon Skipper</a></li>
    </ul>
    </li>
    </ul>

    ```

    请注意，我们给包含菜单的 `<ul>` 添加了 `id` 为 `sfNav` 和 `class` 为 `sf-menu`。这样可以让我们更容易选择和样式化菜单。

    如果你在浏览器中查看页面，它会类似于以下的屏幕截图：

    ![行动时间 — 创建水平下拉菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_06_image1.jpg)

    正如您所看到的，我们将链接组织成了一个层次结构。这对于查找我们想要的信息很有用，但占用了相当多的空间。这就是我们可以使用一种技术来隐藏额外信息直到需要它的时候的地方。

1.  接下来，我们需要一个 Superfish 插件的副本。请转到[`users.tpg.com.au/j_birch/plugins/superfish/`](http://users.tpg.com.au/j_birch/plugins/superfish/)，在那里您将找到 Joel Birch 的 Superfish 插件可供下载，以及文档和示例。

    在 Joel 的**快速入门指南**中，我们看到实施 Superfish 插件有三个简单的步骤：

    +   编写 CSS 以创建 Suckerfish 样式的下拉菜单

    +   链接到`superfish.js`文件

    +   在包含您的菜单的元素上调用`superfish()`方法

    幸运的是，Joel 还包含了一个样式 CSS 文件的样本，所以我们可以快速开始。我们稍后会看看如何自定义菜单的外观，但现在，我们将继续使用与插件一起提供的 CSS。

1.  点击**下载和支持**选项卡。![操作时间——创建一个水平下拉菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_06_image2.jpg)

    在**下载**部分的第一个链接是下载 ZIP 文件的链接。在此之下，我们看到一个带有所有 ZIP 文件中包含的文件的项目列表，并提供了单独下载每个文件的链接。既然我们将使用其中的几个文件，我们将下载整个 ZIP 文件。点击**Superfish-1.4.8.zip**链接并将文件保存到您的计算机上。

1.  解压文件夹并查看其中的内容：![操作时间——创建一个水平下拉菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_06_image3.jpg)

    我们会发现文件被很好地按类型组织到子目录中，还有一个示例 HTML 文件，我们可以查看以查看插件的工作原理。

1.  我们从**下载**部分需要的第一个文件是`css`文件夹中的`superfish.css`文件。将该文件复制到您自己的`styles`文件夹中。

1.  接下来，我们将编辑我们的 HTML 文件，将`superfish.css`文件包含在文档的头部：

    ```js
    <head>
    <title>Chapter 6: Building an Interactive Navigation Menu </title>
    <link rel="stylesheet" href="styles/superfish.css"/>
    <link rel="stylesheet" href="styles/styles.css"/>
    </head>

    ```

    我们将在`styles.css`文件之前附加`superfish.css`文件，以便于我们稍后覆盖`superfish.css`文件中的任何样式。

1.  现在，如果您在浏览器中刷新页面，您将看到一个可用的 Suckerfish 下拉菜单：![操作时间——创建一个水平下拉菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_06_image4.jpg)

当我将鼠标移到第一个链接上时，嵌套的`<ul>`变得可见。如果我将鼠标移到下拉菜单中的最后一个链接上，嵌套在第三级的`<ul>`就会变得可见。

请记住，所有这些都是在没有 JavaScript 的情况下完成的 — 只有 CSS。如果您花点时间使用该菜单，您可能很快就会意识到一些缺点。首先，如果我想要将我的鼠标从**翻翼鸟**链接移动到**开普约克凤蝶**链接，我的自然倾向是对角线移动鼠标。然而，一旦我的鼠标离开蓝色菜单区域，菜单就会关闭和消失。我必须调整移动我的鼠标直接移到子菜单上，然后向下移动到我感兴趣的链接。

![行动时间 — 创建水平下拉菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_06_image5.jpg)

这很尴尬，使得菜单感觉很脆弱。如果我的鼠标移动超出菜单 1 像素，菜单就会折叠消失。另一个问题是，只要鼠标悬停在菜单上，菜单就会打开。如果我在页面的一个部分移动鼠标移动到另一个部分，菜单就会快速打开和关闭，这可能会分散注意力和不可预期。

这是 jQuery 发挥作用并使事情变得更好更易用的好地方。

# 行动时间 — 使用 jQuery 改善下拉菜单

按照以下步骤，可以使用 jQuery 改善下拉菜单的可用性：

1.  我们将从在 HTML 页面底部将 Superfish 插件连接到我们的文件中开始，放在 jQuery 和我们的`scripts.js`文件之间：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/superfish.js"></script>
    <script src="img/scripts.js"></script>
    </body>
    </html>

    ```

1.  接下来，打开`scripts.js`，我们将在其中编写调用`superfish()`方法的代码。像往常一样，我们将从文档准备语句开始，这样我们的脚本会在页面加载到浏览器中时立即运行：

    ```js
    $(document).ready(function(){
    // Our code will go here.
    });

    ```

1.  查看 Superfish 插件的文档，我们看到我们只需选择要应用行为的元素或元素，然后调用`superfish()`方法即可。在我们的`ready()`方法中，我们将添加以下代码：

    ```js
    $(document).ready(function(){
    $('#sfNav').superfish();
    });

    ```

现在，如果您在浏览器中刷新页面，您会看到菜单看起来仍然很相似，但行为得到了很大改善。Superfish JavaScript 和 CSS 协同工作，为具有嵌套子菜单的菜单项添加箭头。如果将鼠标移开自菜单，它不会立即消失，这样可以将鼠标对角线移动到嵌套菜单项。当菜单项出现时，还会有一个微妙的淡入动画。当鼠标悬停时，每个菜单项的背景颜色会更改，使得当前活动项易于识别。

## 刚才发生了什么？

我们设置了一个导航菜单，由一组嵌套列表组成，形成一个层次结构。接下来，我们连接了一个 CSS 文件，为我们的菜单添加了简单的下拉功能。然而，纯 CSS 的菜单有一些缺陷。因此，我们连接了 Superfish 插件来解决这些问题，使我们的菜单更加用户友好。

# 垂直弹出式菜单

我们看到添加 Superfish 插件如何增强了我们下拉菜单的用户体验，但如果我们想要创建一个垂直的弹出式菜单呢？

# 行动时间 — 创建垂直弹出式菜单

从水平下拉菜单切换到垂直弹出菜单再简单不过了。我们将使用相同的 HTML 标记，我们的 JavaScript 代码也将保持不变。我们唯一需要做的改变是添加一些新的 CSS，使我们的菜单垂直显示而不是水平显示。我们可以继续使用上一个示例中使用的相同文件。

1.  在 Superfish 下载的 `css` 文件夹中，你会找到一个名为 `superfish-vertical.css` 的文件。将该文件复制到你自己的 `styles` 文件夹中。在 HTML 文件的 `head` 部分，我们将附加新的 CSS 文件。在 `superfish.css` 和 `styles.css` 之间，添加新的 CSS 文件：

    ```js
    <link rel="stylesheet" href="styles/superfish.css"/>
    <link rel="stylesheet" href="styles/superfish-vertical.css"/>
    <link rel="stylesheet" href="styles/styles.css"/>

    ```

1.  现在，在 HTML 中，我们将在包含菜单的列表中添加一个 `sf-vertical` 类。

    ```js
    <ul id="sfNav" class="sf-menu sf-vertical">

    ```

1.  现在当你在浏览器中刷新页面时，你将看到菜单垂直显示并带有弹出效果：![进行操作的时间 —— 创建垂直弹出菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_06_image6.jpg)

## 刚刚发生了什么？

水平下拉菜单和垂直弹出菜单之间唯一的区别是 CSS 和一个类名添加到菜单容器上。只需添加一个新的 CSS 文件和一个新的 CSS 类，就可以创建一个垂直弹出菜单，而不是水平下拉菜单。

# 自定义导航菜单

超级鱼插件附带的 CSS 使创建交互式导航菜单变得快速简单，但柔和的蓝色菜单不适合每种设计，所以让我们看看如何自定义菜单。

我们将看看如何通过编写自己的 CSS 来自定义菜单的外观，自定义显示嵌套菜单的动画，突出显示当前页面，并增强菜单的悬停行为。

我们将开始编写一些 CSS，为我们的菜单创建自定义外观。我们将使用 Suckerfish Dropdown 方法创建一个菜单，这将适用于我们网站访问者中没有启用 JavaScript 的用户。我想创建一个柔和的渐变背景，并使我的菜单项看起来像是漂浮在这个背景上的丝带。我的菜单将类似于以下截图：

![自定义导航菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_06_image7.jpg)

我要充分利用现代浏览器中可用的较新 CSS3 属性。我正在使用渐变、盒阴影和圆角。我精心选择了这些选项，因为即使没有这些额外的功能，菜单看起来仍然可以，而且可以使用。以下是菜单在旧版浏览器中的外观示例：

![自定义导航菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_06_image8.jpg)

你会注意到，与现代浏览器示例中的一些额外样式相比，它确实缺少了一些，但仍然完全可用并且通常令人满意。如果在所有浏览器中菜单看起来都一样很重要，那么我们可以使用图片而不是 CSS3 来获得最终效果。但是，我们可能需要添加一些额外的标记，并且肯定需要添加图像和额外的 CSS 行，所有这些都会增加页面的总体负担。是否决定让菜单在旧版浏览器中逐渐降级，或者是否决定编写额外的代码并创建额外的图像，使菜单在所有浏览器中看起来都一样，这是你需要根据客户的期望、网站的目标受众以及构建快速轻量级页面的重要性来做出的决定。

在为下拉菜单或弹出菜单编写自定义 CSS 时，请记住以下几点：

## :hover 和 .sfHover

为了使菜单在没有 JavaScript 的情况下工作，你需要利用列表项的`:hover` 伪类。确保同时为相同元素创建一个带有 `.sfHover` 类的 CSS 选择器，这将被 JavaScript 使用。例如：

```js
.sf-menu li.sfHover ul,
.sf-menu li:hover ul {
left: -1px;
top: 70px; /* match top ul list item height */
z-index: 99;
}

```

当鼠标悬停在父列表项上时，此段代码会使嵌套菜单在屏幕上可见。包括`li:hover`选择器确保菜单在没有 JavaScript 的情况下工作。同时包括`li.sfHover`选择器确保 JavaScript 菜单会应用相同的代码。

## 级联继承样式

CSS 的本质就是样式沿 DOM 层级进行级联，并应用于选择器的所有子元素以及选择器本身。因此，如果你编写代码来为一级菜单的列表项添加样式，如下所示：

```js
ul.sf-menu li {
background: #cc0000; /* Dark red background */
}

```

你菜单中的所有 `<li>` 都将具有深红色背景，无论它们出现在菜单的哪个级别。如果你想为不同的菜单级别应用不同的样式，你需要在其他代码行中覆盖级联。例如，如果我想使第二级菜单具有深蓝色背景，我会在上述代码之后添加此段 CSS：

```js
ul.sf-menu li li {
background: #0000cc; /* Dark blue background */
}

```

这意味着对于另一个`<li>`内部的`<li>`，背景将会是蓝色。请记住，现在这个样式将级联到其他菜单级别，所以如果你想要第三级菜单具有深绿色背景，你需要再添加一点 CSS：

```js
ul.sf-menu li li li {
background: #00cc00; /* Dark green background */
}

```

在某些情况下，在你的 CSS 中使用直接后代选择器可以帮助你避免编写太多覆盖 DOM 中较高元素样式的 CSS。例如：

```js
ul.sf-menu > li {
background: #cc0000; /* Dark red background */
}

```

这段 CSS 利用了直接后代选择器（>`）。在这种情况下，深红色背景只会应用于具有 `sf-menu` 类的 `<ul>` 直接嵌套的 `<li>` 元素。它不会级联到第二级或第三级菜单。

# 供应商前缀

如果你想要尝试新的 CSS3 属性，你必须确保在属性前加上供应商特定的前缀。尽管这些属性受大多数现代浏览器支持，但它们仍在开发中，并且可能在不同浏览器中以稍微不同的方式实现。比如，下面这段 CSS，将底部两个角圆化的代码：

```js
.sf-menu ul li:last-child a {
-webkit-border-bottom-right-radius: 7px;
-webkit-border-bottom-left-radius: 7px;
-moz-border-radius-bottomright: 7px;
-moz-border-radius-bottomleft: 7px;
border-bottom-right-radius: 7px;
border-bottom-left-radius: 7px;
}

```

你可以看到，对于左下角和右下角的属性，在 Webkit 内核浏览器（主要是 Safari 和 Chrome）和 Mozilla 浏览器（主要是 Firefox）之间略有不同。在供应商特定代码之后，包括任何支持的浏览器的一般 CSS3 代码，以确保你的代码是未来兼容的。

# 行动时间——定制 Superfish 菜单

定制 Superfish 菜单主要涉及编写自己的 CSS 来样式化菜单，让它看起来更符合你的喜好。下面是我们将为菜单创建自定义外观的方法：

如果你记得一些网页基础，你会记得 CSS 代表层叠样式表。层叠特性是我们在这里将要关注的。我们为菜单顶层编写的任何样式都将层叠到菜单的其他级别。我们必须记住这一点，并处理那些我们宁愿阻止样式层叠向下传递的情况。

1.  让我们从样式化菜单的顶层开始。由于我使用了新的 CSS3 功能，我们需要准备写一些额外的代码，以便每个浏览器都能优雅地处理我们的代码。下面是我们将为菜单顶层创建的 CSS。将此代码放入你的`styles.css`文件中：

    ```js
    /**** Level 1 ****/
    .sf-menu,
    .sf-menu * {
    list-style: none;
    margin: 0;
    padding: 0;
    }
    .sf-menu {
    background: #f6f6f6; /* Old browsers */
    background: -moz-linear-gradient(top, rgba(0,0,0,1) 1%, rgba(56,56,56,1) 16%, rgba(255,255,255,1) 17%, rgba(246,246,246,1) 47%, rgba(237,237,237,1) 100%); /* FF3.6+ */
    background: -webkit-gradient(linear, left top, left bottom, color-stop(1%,rgba(0,0,0,1)), color-stop(16%,rgba(56,56,56,1)), color-stop(17%,rgba(255,255,255,1)), color-stop(47%,rgba(246,246,246,1)), color-stop(100%,rgba(237,237,237,1))); /* Chrome,Safari4+ */
    background: -webkit-linear-gradient(top, rgba(0,0,0,1) 1%,rgba(56,56,56,1) 16%,rgba(255,255,255,1) 17%,rgba(246,246,246,1) 47%,rgba(237,237,237,1) 100%); /* Chrome10+,Safari5.1+ */
    background: -o-linear-gradient(top, rgba(0,0,0,1) 1%,rgba(56,56,56,1) 16%,rgba(255,255,255,1) 17%,rgba(246,246,246,1) 47%,rgba(237,237,237,1) 100%); /* Opera11.10+ */
    background: -ms-linear-gradient(top, rgba(0,0,0,1) 1%,rgba(56,56,56,1) 16%,rgba(255,255,255,1) 17%,rgba(246,246,246,1) 47%,rgba(237,237,237,1) 100%); /* IE10+ */
    filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#000000', endColorstr='#ededed',GradientType=0 ); /* IE6-9 */
    background: linear-gradient(top, rgba(0,0,0,1) 1%,rgba(56,56,56,1) 16%,rgba(255,255,255,1) 17%,rgba(246,246,246,1) 47%,rgba(237,237,237,1) 100%); /* W3C */
    float: left;
    font-family: georgia, times, 'times new roman', serif;
    font-size: 16px;
    line-height: 14px;
    margin: 28px 0 14px 0;
    padding: 0 14px;
    }
    .sf-menu li {
    border-left: 1px solid transparent;
    border-right: 1px solid transparent;
    float: left;
    position: relative;
    }
    .sf-menu li.sfHover,
    .sf-menu li:hover {
    visibility: inherit; /* fixes IE7 'sticky bug' */
    }
    .sf-menu li.sfHover,
    .sf-menu li:hover {
    background: #DF6EA5;
    border-color: #a22361;
    -webkit-box-shadow: 3px 3px 3px rgba(0,0,0,0.2);
    -moz-box-shadow: 3px 3px 3px rgba(0,0,0,0.2);
    box-shadow: 3px 3px 3px rgba(0,0,0,0.2);
    }
    .sf-menu a {
    border-left: 1px solid transparent;
    border-right: 1px solid transparent;
    color: #444;
    display: block;
    padding: 28px 14px;
    position: relative;
    width: 98px;
    text-decoration: none;
    }
    .sf-menu li.sfHover a,
    .sf-menu li:hover a {
    background: #DF6EA5;
    border-color: #fff;
    color: #fff;
    outline: 0;
    }
    .sf-menu a,
    .sf-menu a:visited {
    color: #444;
    }

    ```

    哎呀！这看起来像是很多代码，但其中大部分是我们需要为每种不同类型的浏览器使用的重复的渐变和阴影声明。让我们祈祷这个要求很快消失，浏览器供应商最终达成一致意见，确定用 CSS 创建渐变和阴影的方法。

1.  接下来，让我们看看如何为我们菜单的下一级样式化。将以下 CSS 添加到你的`styles.css`文件中，以样式化第二级菜单：

    ```js
    /***** Level 2 ****/
    .sf-menu ul {
    background: rgb(223,110,165); /* Old browsers */
    background: -moz-linear-gradient(top, rgba(223,110,165,1) 0%, rgba(211,54,130,1) 100%); /* FF3.6+ */
    background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,rgba(223,110,165,1)), color-stop(100%,rgba(211,54,130,1))); /* Chrome,Safari4+ */
    background: -webkit-linear-gradient(top, rgba(223,110,165,1) 0%,rgba(211,54,130,1) 100%); /* Chrome10+,Safari5.1+ */
    background: -o-linear-gradient(top, rgba(223,110,165,1) 0%,rgba(211,54,130,1) 100%); /* Opera11.10+ */
    background: -ms-linear-gradient(top, rgba(223,110,165,1) 0%,rgba(211,54,130,1) 100%); /* IE10+ */
    filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#df6ea5', endColorstr='#d33682',GradientType=0 ); /* IE6-9 */
    background: linear-gradient(top, rgba(223,110,165,1) 0%,rgba(211,54,130,1) 100%); /* W3C */
    -webkit-border-bottom-right-radius: 7px;
    -webkit-border-bottom-left-radius: 7px;
    -moz-border-radius-bottomright: 7px;
    -moz-border-radius-bottomleft: 7px;
    border-bottom-right-radius: 7px;
    border-bottom-left-radius: 7px;
    border: 1px solid #a22361;
    border-top: 0 none;
    margin: 0;
    padding: 0;
    position: absolute;
    top: -999em;
    left: 0;
    width: 128px;
    -webkit-box-shadow: 3px 3px 3px rgba(0,0,0,0.2);
    -moz-box-shadow: 3px 3px 3px rgba(0,0,0,0.2);
    box-shadow: 3px 3px 3px rgba(0,0,0,0.2);
    font-size: 14px;
    }
    .sf-menu ul li {
    border-left: 1px solid #fff;
    border-right: 1px solid #fff;
    display: block;
    float: none;
    }
    .sf-menu ul li:last-child {
    border-bottom: 1px solid #fff;
    -webkit-border-bottom-right-radius: 7px;
    -webkit-border-bottom-left-radius: 7px;
    -moz-border-radius-bottomright: 7px;
    -moz-border-radius-bottomleft: 7px;
    border-bottom-right-radius: 7px;
    border-bottom-left-radius: 7px;
    }
    .sf-menu ul li:last-child a {
    -webkit-border-bottom-right-radius: 7px;
    -webkit-border-bottom-left-radius: 7px;
    -moz-border-radius-bottomright: 7px;
    -moz-border-radius-bottomleft: 7px;
    border-bottom-right-radius: 7px;
    border-bottom-left-radius: 7px;
    }
    .sf-menu li.sfHover li.sfHover,
    .sf-menu li:hover li:hover {
    -webkit-box-shadow: none;
    -moz-box-shadow: none;
    box-shadow: none;
    }
    .sf-menu li.sfHover li.sfHover {
    border-right-color: #cb2d79
    }
    .sf-menu li li a {
    border: 0 none;
    padding: 14px;
    }
    .sf-menu li li:first-child a {
    padding-top: 0;
    }
    .sf-menu li li.sfHover a,
    .sf-menu li li:hover a {
    background: transparent;
    border: 0 none;
    color: #f8ddea;
    outline: 0;
    }
    .sf-menu li li a:hover {
    color: #f8ddea;
    }
    .sf-menu li.sfHover li a,
    .sf-menu li:hover li a {
    background: transparent;
    }
    .sf-menu li.sfHover li.sfHover a {
    background: #cb2d79;
    }
    .sf-menu li.sfHover ul,
    .sf-menu li:hover ul {
    left: -1px;
    top: 70px; /* match top ul list item height */
    z-index: 99;
    }
    .sf-menu li li.sfHover,
    .sf-menu li li:hover {
    background: transparent;
    border-color: #fff;
    }

    ```

    再一次，这看起来像是很多 CSS，但我们仍然需要为每个单独的浏览器编写我们的声明。菜单的第二级项目也因需要覆盖或取消我们应用于菜单顶层但我们不希望应用于这里的任何样式而变得复杂。例如，我们为菜单顶层的所有项目应用了 `float` 属性，但我们需要取消第二级菜单的应用。

    我相信你开始明白为什么 Superfish 插件的大部分支持问题都与 CSS 有关，而不是 JavaScript。这里有很多要记住的东西。

1.  最后，我们仍然有第三级菜单需要样式化。就像第二级一样，我们需要取消任何我们不希望应用的级联样式。将以下样式添加到你的`styles.css`文件中：

    ```js
    /**** Level 3 ****/
    ul.sf-menu li.sfHover li ul,
    ul.sf-menu li:hover li ul {
    background: #cb2d79;
    top: -999em;
    -webkit-border-radius: 7px;
    -webkit-border-top-left-radius: 0;
    -moz-border-radius: 7px;
    -moz-border-radius-topleft: 0;
    border-radius: 7px;
    border-top-left-radius: 0;
    }
    ul.sf-menu li.sfHover li ul li,
    ul.sf-menu li:hover li ul li {
    background: transparent;
    border: 0 none;
    }
    ul.sf-menu li li.sfHover ul,
    ul.sf-menu li li:hover ul {
    left: 9em; /* match ul width */
    top: 0;
    }
    .sf-menu li.sfHover li.sfHover li a,
    .sf-menu li:hover li:hover li a {
    background: transparent;
    }
    .sf-menu li li li:first-child a {
    padding-top: 14px;
    }
    .sf-menu li li li a:hover {
    background: transparent;
    color: #fff;
    }
    /*** ARROWS ***/
    .sf-sub-indicator {
    display: none;
    }

    ```

现在深吸一口气，因为我们终于到达了为菜单创建自定义样式的 CSS 的尽头。别担心，这是一个特别复杂的设计，使用了大量新的 CSS3 样式。如果你选择了一个稍微简单的东西，你将不得不创建更少的代码来使样式工作。  

这个 CSS 的额外好处是即使没有启用 JavaScript，它也可以工作。Superfish 插件只是增强了菜单，使其更易于使用。  

## 刚才发生了什么事？  

我们编写了自定义 CSS 来使我们的菜单与我们创建的设计匹配。为了正确地使悬停状态工作，我们必须记得同时为`:hover`伪类和`.sfHover`类设置样式。我们还必须深入研究 CSS 的级联特性，并决定哪些样式应该通过菜单的所有级别级联下来，哪些不应该。最后，我们必须记住，新的 CSS3 属性现在至少在不同的浏览器中必须以不同的方式声明。所有这些都导致下拉菜单需要比你最初预期的更多的自定义 CSS。只需耐心，一路下来时记住级联即可。  

## 自定义动画  

现在我们已经编写了自定义样式的 CSS，让我们来看看如何自定义显示子菜单的动画。滑动动画更适合我的菜单风格。默认动画是淡入子菜单，但我宁愿覆盖此默认行为，并用滑动动画替换它。  

# 行动时间 —— 合并自定义动画  

按照以下步骤将自定义动画合并到您的菜单中：  

1.  将菜单淡入意味着菜单的不透明度从 0 变化到 100 百分比。我宁愿动画化子菜单的高度，以便子菜单滑入视图。要做到这一点，打开你的 scripts.js 文件，我们将在 `superfish()` 方法内自定义动画值：  

    ```js
    $(document).ready(function(){
    $('#sfNav').superfish({
    animation: {height:'show'}
    });
    });

    ```

    在此处添加一个值将覆盖插件的默认行为，并用我们选择的动画替换它。  

1.  现在当你在浏览器中刷新页面时，你会看到子菜单滑入视图，而不是淡入，这是与我用来样式化菜单的 CSS 更匹配的动画。  

## 刚才发生了什么事？  

我们利用了 Superfish 插件的自定义选项之一，改变了嵌套子导航链接的显示动画。在 Superfish 菜单的文档中还涵盖了更多的自定义选项。  

# [hoverIntent 插件](https://example.org/hoverIntent)  

早些时候，我指出我们的菜单有一个问题，那就是菜单对`mouseover`事件的反应速度太快了。任何时候鼠标移动到菜单上，嵌套菜单就会打开。虽然这乍看起来可能是一件好事，但如果站点访问者只是在屏幕上移动鼠标，而不打算使用下拉或弹出式菜单，这可能会让人感到不安或惊讶。

Superfish 插件内置支持 hoverIntent 插件。hoverIntent 插件有点暂停`mouseover`事件，并使页面等待以查看鼠标是否减速或停止在一个项目上，以确保这是站点访问者想要做的。这样，如果站点访问者碰巧将鼠标悬停在下拉菜单上，而在页面上寻找其他内容，子菜单不会开始出现，将其置于困惑中。

如果你还记得的话，当我们下载 Superfish 插件时，hoverIntent 插件实际上已经包含在 ZIP 文件中。

# 行动时间——添加 hoverIntent 插件

按照以下步骤利用 hoverIntent 插件来为您的菜单增加功能：

1.  在 Superfish 下载中，找到位于 `js` 文件夹内的 `hoverIntent.js` 文件，并将文件复制到您自己的 `scripts` 文件夹中。

1.  接下来，我们需要将 hoverIntent 插件附加到我们的 HTML 页面上。

    ### 提示

    不要忘记在将多个 JavaScript 文件附加到页面时考虑依赖关系。所有 jQuery 插件都依赖于 jQuery 来运行，因此需要在任何插件之前将 jQuery 附加到您的页面上。在这种情况下，Superfish 插件依赖于 hoverIntent 插件，因此我们需要确保在 Superfish 插件之前添加 hoverIntent。

1.  将新的 `<script>` 标签添加到您的页面底部，与其他脚本一起如下：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/hoverIntent.js"></script>
    <script src="img/superfish.js"></script>
    <script src="img/scripts.js">
    </script>
    </body>
    </html>

    ```

现在，如果您在浏览器中刷新页面，您会发现当鼠标移动到菜单上时会有一个短暂的暂停，然后嵌套的子菜单出现。如果您快速将鼠标移到页面上，越过菜单，页面上不会出现不需要的子菜单。

## 英雄般的尝试——设定你自己的速度

尝试使用在文档中概述的 Superfish 插件的不同定制选项，调整显示子菜单的动画速度。

# 摘要

哇！刚刚我们做了很多工作，但我必须说，我们为我们的努力展示了一个相当令人印象深刻的导航菜单。我们学会了如何使用 Superfish jQuery 插件来生成水平下拉菜单或垂直飞出菜单。我们还学会了如何完全自定义我们菜单的外观和感觉，以完美适应我们的网站设计。能够隐藏站点的子部分直到需要它们，使得复杂的导航结构对于您的站点访问者来说不那么令人难以置信。可以清楚地看到站点的主要部分是什么，他们可以轻松地深入到他们想要的内容。

接下来，我们将通过使用 Ajax 来进一步提升我们的动画效果。


# 第七章：异步导航

> 网站通常设置成，网站的所有页面共享一个通用的页眉和页脚，只有中间的内容从页面到页面发生改变。有时左侧和/或右侧的主要内容区域还有一个或多个侧边栏，在整个网站中保持不变。为什么让我们的网站访问者在浏览我们的网站时一遍又一遍地重新下载相同的页眉、页脚和侧边栏内容呢？

在本章中，我们将涵盖以下主题：

+   构建异步导航的网站

+   增强异步导航以使其更加用户友好

# 简单的异步导航

在 Web 的早期，解决重复下载相同内容的问题的一个方法是框架。如果你对网页开发还太新，以至于不记得，框架提供了一种将单页面视图分割成几个不同的 HTML 文件的方法——浏览网站涉及重新加载一个或多个框架，而其他框架保持不变。框架有助于网站加载更快，使网站更容易维护，但最终它们制造的问题比解决的问题更多。有框架的网站易于破坏，搜索引擎难以索引，经常破坏前进和后退按钮，并且使访问者难以或无法收藏页面、分享链接或打印内容。由于所有这些问题，使用框架已不受青睐。

近来，单页面应用程序开始变得更受欢迎。如果你登录你的 Twitter 账户并开始点击各处，你会注意到整个页面很少刷新——大部分交互发生在一个页面内。如果你访问 Gawker Media 网站中的任何一个，你会注意到在初始页面加载后，当你浏览网站时整个页面并不会再次刷新。现在，让我们看看如何以渐进增强的方式在我们自己的网站上实现相同类型的交互，以确保我们的网站在没有 JavaScript 的情况下仍然可以正常工作，并且可以被搜索引擎轻易索引。

# **行动时间** — 建立一个简单的网站

我们将开始建立一个小而简单的网站，其中包含一些页面。它们都共享相同的页眉、导航、侧边栏和页脚。它们都有一个主内容区，其中将显示每个页面的唯一内容。

1.  通过建立一个包含所有相关文件和文件夹的`index.html`文件来开始，就像我们在第一章中所做的那样，*设计师，遇见 jQuery*。`index.html`文件的主体将包含我们的页眉、导航、侧边栏和页脚：

    ```js
    <div id="ajax-header">
    <h1>Miniature Treats</h1>
    <ul id="ajax-nav">
    <li><a href ="index.html">Home</a></li>
    <li><a href ="cupcakes.html">Cupcakes</a></li>
    <li><a href ="petitfours.html">Petits Fours</a></li>
    <li><a href ="teacakes.html">Tea Cakes</a></li>
    <li><a href ="muffins.html">Muffins</a></li>
    </ul>
    </div>
    <div id="main-col">
    <div id="main-col-wrap">
    <p>Welcome to the miniature treats roundup. We've got a variety of miniature goodies to share with you.</p>
    <p>Don't be shy - just dive right in. Your mouth will water with the possibilites.</p>
    <p>If it's tiny enough to be a single portion all on it's own, we've included it here.</p>
    </div>
    </div>
    <div id="side-col">
    <div class="widget">
    <h4>More Information</h4>
    <ul>
    <li><a href="http://en.wikipedia.org/wiki/Cupcakes">Cupcakes (Wikipedia)</a></li>
    <li><a href="http://en.wikipedia.org/wiki/Petit_fours">Petits Fours (Wikipedia)</a></li>
    <li><a href="http://en.wikipedia.org/wiki/Tea_cake">Tea Cakes (Wikipedia)</a></li>
    <li><a href="http://en.wikipedia.org/wiki/Muffins">Muffins (Wikipedia)</a></li>
    </ul>
    </div>
    <div class="widget">
    <h4>Also Delicious</h4>
    <ul>
    <li><a href="http://en.wikipedia.org/wiki/Banana_bread">Banana Bread</a></li>
    <li><a href="http://en.wikipedia.org/wiki/Pumpkin_bread">Pumpkin Bread</a></li>
    <li><a href="http://en.wikipedia.org/wiki/Swiss_roll">Swiss Roll</a></li>
    <li><a href="http://en.wikipedia.org/wiki/Cheesecake">Cheesecake</a></li>
    <li><a href="http://en.wikipedia.org/wiki/Bundt_cake">Bundt Cake</a></li>
    </ul>
    </div>
    </div>
    <div id="ajax-foot">
    <p>Sample of progressively enhanced asynchronous navigation</p>
    </div>

    ```

    你可能会注意到额外的一个`<div>`，你可能没有预料到：`main-col`id 内的`<div>`，我添加了一个`main-col-wrap`id 的`<div>`标签。这并不用于布局或 CSS 目的，但一旦我们创建异步加载内容的 JavaScript 时，它就会被用到。

1.  接下来，我们将编写一些 CSS 来创建一个简单的布局。打开您的`styles.css`文件并添加以下样式：

    ```js
    #ajax-header { margin: 40px 0 0 0; }
    #ajax-header h1 { color:#859900;margin:0 0 10px 0;padding:0; }
    #ajax-nav { background:#859900;margin:0;padding:0;overflow:hidden;zoom:1; }
    #ajax-nav li { list-style-type:none;margin:0;padding:10px 20px;display:block;float:left; }
    #ajax-nav a,
    #ajax-nav a:link,
    #ajax-nav a:visited { color: #eee8d5; }
    #ajax-nav a:hover,
    #ajax-nav a:active { color: #fff; }
    #main-col { float:left;width:60%; }
    #side-col { float:right;width:35%; }
    .widget { border:2px solid #859900;margin:10px 0; }
    .widget h4 { margin:0 0 10px 0;padding:10px;background:#859900;color:#FDF6E3; }
    .float-right { float:right;margin:0 0 10px 10px; }
    .float-left { float:left;margin:0 10px 10px 0; }
    .source { font-size:12px; }
    #ajax-foot { clear:both;margin:10px 0 40px 0;padding:5px;background:#859900;color:#f3f6e3; }
    #ajax-foot p { margin:0;padding:0;font-size:12px;}

    ```

    最终页面将类似于以下屏幕截图：

    ![行动时间——设置一个简单的网站](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_07_img1.jpg)

    如果您感到灵感来了，请随意编写一些额外的 CSS 来使您的页面看起来更加花哨。

1.  接下来，我们将创建网站的其他页面，即杯子蛋糕、小甜饼、茶点和松饼的页面。HTML 将与主页完全相同，除了`<div>`内部的内容，其`id`为`main-col-wrap`。以下是我为杯子蛋糕页面准备的内容样本：

    ```js
    <div id="main-col-wrap">
    <h2>Cupcakes</h2>
    <p><img src="img/cupcakes.jpg" class="float-right" alt="Photo of cupcakes"/>A cupcake is a small cake designed to serve one person, frequently baked in a small, thin paper or aluminum cup. As with larger cakes, frosting and other cake decorations, such as sprinkles, are common on cupcakes.</p>
    <p>Although their origin is unknown, recipes for cupcakes have been printed since at least the late 18th century.</p>
    <p>The first mention of the cupcake can be traced as far back as 1796, when a recipe notation of "a cake to be baked in small cups" was written in <em>American Cookery</em> by Amelia Simms. The earliest documentation of the term <em>cupcake</em> was in "Seventy-five Receipts for Pastry, Cakes, and Sweetmeats" in 1828 in Eliza Leslie's <em>Receipts</em> cookbook.</p>
    <p class="source">Text source: <a href="http://en.wikipedia.org/wiki/Cupcakes">Wikipedia</a><br/>Image source: <a href="http://flickr.com/people/10506540@N07">Steven Depolo</a> via <a href="http://commons.wikimedia.org/wiki/File:Blue_cupcakes_for_graduation,_closeup_-_Tiffany,_May_2008.jpg">Wikimedia Commons</a></p>
    </div>

    ```

在这个`<div>`之外，我的页面的其他部分与我们之前创建的主页完全相同。继续在类似的方式下创建松饼、茶点和小甜饼的页面，这样您就可以得到一个包含共享页眉、导航、侧边栏和页脚的五页网站。

不要忘记，您的网站每页应在头部部分包含`styles.css`文件的链接，以及在文档底部，在结束`</body>`标记之前包含对 jQuery 和`scripts.js`文件的链接。

## 刚才发生了什么？

我们在 HTML 中设置了一个简单的五页网站。我们网站的每一页共享相同的页眉、导航、侧边栏和页脚。然后我们设置了一些简单的 CSS 来美化我们的页面。唯一表明这里会发生一些花哨的东西是额外的`<div>`包裹着我们的主内容区域——页面上包含从页面到页面不同内容的区域。

# 行动时间——添加 Ajax 魔力

如果您在浏览器中浏览这个简单的小网站，您会发现我们一遍又一遍地重新加载相同的页眉、导航、侧边栏和页脚。只有页面的主要内容区域的内容在页面之间不断地变化。让我们使用 jQuery 的魔力来解决这个问题。

1.  只是一个提醒，除非您的页面是由服务器提供的，否则这些 Ajax 函数将不起作用。要看这段代码的实际效果，您要么需要将页面上传到服务器，要么在自己的计算机上创建一个服务器。首先，我们将打开我们的`scripts.js`文件并开始编写我们的代码。我们将像往常一样以文档就绪语句开始：

    ```js
    $(document).ready(function(){
    // Our code will go here
    });

    ```

1.  我们需要选择导航中的所有链接。这看起来类似于这样：

    ```js
    $(document).ready(function(){
    $('#ajax-nav a')
    });

    ```

1.  当用户点击这些链接时，浏览器会加载请求的页面。这就是我们希望覆盖的行为，因此我们将绑定一个函数到链接，覆盖链接的点击行为如下：

    ```js
    $(document).ready(function(){
    $('#ajax-nav a').bind('click', function(){
    // Our clicky code goes here
    });
    });

    ```

1.  当站点访问者单击链接时，我们需要做的第一件事情就是取消默认行为。我们可以通过告诉函数返回`false`来实现：

    ```js
    $(document).ready(function(){
    $('#ajax-nav a').bind('click', function(){
    return false;
    });
    });

    ```

    现在，如果您在浏览器中重新加载您的简单网站，您会发现单击主导航中的链接没有任何作用。您请求的页面不再加载到浏览器中。我们已经为我们自己的代码做好了准备。

1.  如果我们要从服务器获取页面，我们需要知道我们要获取哪个页面。我们需要知道我们需要调用哪个 URL。幸运的是，我们的链接已经在它们的`href`属性中包含了这些信息，例如，通过查看我们杯子蛋糕链接的 HTML：

    ```js
    <a href ="cupcakes.html">Cupcakes</a>

    ```

    我们可以看到我们需要请求以获取有关杯子蛋糕信息的页面是`cupcakes.html。`

    我们将使用 jQuery 来获取刚刚点击的链接的`href`属性：

    ```js
    $(document).ready(function(){
    $('#ajax-nav a').bind('click', function(){
    var url = $(this).attr('href');
    return false;
    });
    });

    ```

    现在我们有一个名为`url`的变量，其中包含了刚刚点击的链接的`href`属性。记住，变量只是容器。如果我们的网站访问者刚刚点击了杯子蛋糕链接，那么`url`变量将包含`cupcakes.html`。而另一方面，如果网站访问者刚刚点击了松饼链接，那么`url`变量将包含`muffins.html`。这个函数在站点访问者点击主导航中的任何链接时都会被调用- `$(this)`将始终引用刚刚点击的链接。

1.  现在我们知道服务器上的哪个页面包含了网站访问者请求的信息，那么我们该怎么办？幸运的是，jQuery 为我们提供了`load()`方法，它可以轻松地将内容从服务器加载到我们的页面中。我们将选择页面上我们想要加载内容的元素，然后调用那个元素的`load()`方法。在这种情况下，我们将选择`<div>`标签，并且其`id`为`main-col`，因为这是页面上从一页到另一页变化的内容的容器：

    ```js
    $(document).ready(function(){
    $('#ajax-nav a').bind('click', function(){
    var url = $(this).attr('href');
    $('#main-col').load();
    return false;
    });
    });

    ```

1.  如果您刷新浏览器中的页面并点击主导航中的链接，您将会发现没有任何反应。浏览器没有报告任何错误，那么问题出在哪里呢？

    记得 Maggie 这只狗吗，她在第一章 *设计师，见识 jQuery*中正在吃培根。Maggie 有一个这样的`eat`方法：

    ```js
    Maggie.eat();

    ```

    然而，请记住，她不能只是吃东西——她必须吃一些东西。因此，我们将`bacon`传递给 Maggie 的`eat()`方法如下：

    ```js
    Maggie.eat('bacon');

    ```

    `load`方法也类似。我们不能只是加载—我们必须加载一些东西。在这种情况下，我们知道我们需要加载什么—url 变量中包含的 URL 中的内容：

    ```js
    $(document).ready(function(){
    $('#ajax-nav a').bind('click', function(){
    var url = $(this).attr('href');
    $('#main-col').load(url);
    return false;
    });
    });

    ```

    现在，如果刷新浏览器并尝试点击主导航中的杯子蛋糕链接，您会看到杯子蛋糕页面的内容确实加载到我们的`#main-col` div 中。然而，这并不是我们想要的，因为它加载整个页面：

    ![行动时间- 添加 Ajax 魔法](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_07_img2.jpg)

1.  我们不想获取整个页面。我们只需要`#main-col` div 中的内容，这就是额外的包装元素`<div>`和`id`为`main-col-wrap`的地方。我们可以告诉 jQuery 仅将`<div>`和其内容加载到`#main-col <div>`中，如下所示：

    ```js
    $(document).ready(function(){
    $('#ajax-nav a').bind('click', function(){
    var url = $(this).attr('href');
    $('#main-col').load(url + ' #main-col-wrap');
    return false;
    });
    });

    ```

    这有时被称为 jQuery 的**部分加载方法**，因为我们不是将获取到的整个内容加载到页面中，而只是我们关心的部分。如果你在浏览器中刷新页面并点击主导航，你会发现现在内容按我们预期的方式加载，只有页面的主内容区域刷新。页眉、导航、侧边栏和页脚仍然保留在页面上，而主内容区域重新加载。

## 刚刚发生了什么？

我们使用了 jQuery 强大的基于 CSS 的选择器来选择主导航中的所有链接。我们确定了链接的点击行为是我们需要覆盖以获得所需结果的行为。我们将一个点击函数绑定到链接上，每次调用链接时都会运行。我们取消了链接在浏览器窗口中加载新页面的默认行为。接下来，我们检查链接以获取`href`属性中包含的 URL。我们选择了页面上希望加载新内容的容器，并使用 jQuery 的`load()`方法调用所需内容。我们向`load()`方法传递了一个选择器和 URL，以便 jQuery 知道我们只想加载选定元素中的内容，而不是整个页面。

我们将我们简单的网站转换成了单页面应用。我们使用渐进增强的方式来做到这一点，这样那些没有启用 JavaScript 的网站访问者也可以无问题地使用我们的网站。搜索引擎也可以索引我们网站的内容。而这一切都只用了几行 JavaScript 代码 —— 多亏了 jQuery！

# 豪华异步导航

你会对自己只用几行代码就将一个普通网站变成单页面应用而感到非常满意，但让我们面对现实：我们简单的异步导航还有待改进，绝对需要一些润色。

或许最明显的是，我们破坏了浏览器的后退和前进按钮。我们不能再使用它们在我们网站的页面之间导航。我们还剥夺了我们网站访问者将页面链接加为书签或分享的能力。我们在我们的主导航中点击链接后，也没有向我们的网站访问者提供任何反馈。由于我们的页面短小简单，它们通常会很快加载，但互联网在速度方面众所周知是不可预测的。有时加载我们的内容可能需要半秒、一秒或更长时间 —— 我们的网站访问者不知道他们的浏览器正在努力获取新内容 —— 它看起来就像什么都没发生。

还有一些其他小技巧，可以使整个过程更加美观和快速，所以让我们开始制作高级异步导航的豪华版本吧。

# 行动时间 —— 构建豪华异步导航

为了给我们的异步导航添加一些缺失的功能，我们将使用 Ben Alman 的出色的 jQuery BBQ 插件。尽管这个名字可能会让你觉得饥饿，但在这种情况下，BBQ 代表 Back Button 和 Query。我们将继续使用我们在上一个示例中创建的文件。

1.  首先，我们需要获取 BBQ 插件的副本以进行使用。访问 [`benalman.com/projects/jquery-bbq-plugin/`](http://benalman.com/projects/jquery-bbq-plugin/) 获取下载文件以及 jQuery BBQ 插件的文档和示例。![行动时间——构建豪华的异步导航](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_07_img3.jpg)

    和往常一样，我们将下载插件的压缩版本，并将其放入我们的`scripts`文件夹中，与 jQuery 和我们的`scripts.js`文件并列。

    ![行动时间——构建豪华的异步导航](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_07_img4.jpg)

1.  接下来，打开你的迷你网站的每个 HTML 页面，并在 jQuery 之后、`scripts.js`之前添加 BBQ 插件：

    ```js
    <script type="text/javascript" src="img/jquery.js"></script>
    <script type="text/javascript" src="img/jquery.ba-bbq.min.js"></script>
    <script type="text/javascript" src="img/scripts.js"></script>
    </body>
    </html>

    ```

现在我们已经准备好开始构建我们的异步导航的豪华版本了。

## 刚刚发生了什么？

我们下载了 jQuery BBQ 插件，并将其附加到我们的每个页面上。到目前为止，这在我们的网站上没有任何区别——我们已经附加了 BBQ 插件，但我们并没有使用它来做任何事情。接下来，我们将看看如何使用 BBQ 插件。

# 行动时间——使用 BBQ 插件

我们的第一项任务是让返回和前进按钮起作用，并允许我们的网站访问者将链接添加到书签并分享到个别页面。这就是为什么我们包含了 jQuery BBQ 插件。

1.  我们将编写一些新的 JavaScript 代码，因此将`scripts.js`中我们之前编写的代码清除，并用以下简单的文档就绪语句替换它：

    ```js
    $(document).ready(function(){
    // Our deluxe ajaxy code goes here
    });

    ```

1.  接下来，我们将选择主导航中的每个链接，并用哈希链接替换 URL，以便浏览器认为它们是我们 HTML 页面内部的链接。

    ```js
    $(document).ready(function(){
    $('#ajax-nav a').each(function(){
    $(this).attr('href', '#' + $(this).attr('href'));
    });
    });

    ```

    我们选择主导航中的所有链接，然后循环遍历它们以在 URL 前添加一个`#`字符。例如，`cupcakes.html`链接现在是`#cupcakes.html`。如果你在浏览器中刷新页面，你会发现点击链接不会改变页面上的任何内容，但它会更新浏览器位置栏中的哈希。

    ![行动时间——使用 BBQ 插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_07_img5.jpg)

1.  接下来，我们将一个函数绑定到窗口的`hashchange`事件上。现代浏览器提供了一个称为`hashchange`的事件，每当 URL 的哈希更改时就会触发，就像当您单击主导航链接时所做的那样。旧版浏览器不支持`hashchange`事件，但这就是 jQuery BBQ 插件发挥作用的地方。它在大多数浏览器中提供了对伪`hashchange`事件的支持，这样我们只需编写我们的代码一次，而不必担心浏览器的差异。这是我们如何将函数绑定到`hashchange`事件上的方式：

    ```js
    $(document).ready(function(){
    $('#ajax-nav a').each(function(){
    $(this).attr('href', '#' + $(this).attr('href'));
    });
    $(window).bind('hashchange', function(e) {
    // our function goes here
    });
    });

    ```

1.  我们编写的函数现在将在窗口的哈希更改时调用，我们知道每当站点访问者点击我们的主导航中的链接时都会发生这种情况。现在我们可以编写代码，告诉浏览器在发生这种情况时该做什么。

    ```js
    $(document).ready(function(){
    $('#ajax-nav a').each(function(){
    $(this).attr('href', '#' + $(this).attr('href'));
    });
    $(window).bind('hashchange', function(e) {
    var url = e.fragment;
    $('#main-col').load(url + ' #main-col-wrap');
    });
    });

    ```

    首先，我们设置一个名为`url`的变量，并将其设置为`e.fragment`。`fragment`属性由 jQuery BBQ 插件提供。它等于 URL 的哈希但不包括哈希符号。因此，如果窗口的哈希更改为`#cupcakes.html`，`e.fragment`将等于`cupcakes.html`。

    下一行代码与我们的基本 Ajax 导航示例相同。我将选择页面上要加载内容的容器，然后调用`load()`方法。我将传递 URL 和 jQuery 选择器，指定要加载到浏览器中的页面部分。

    如果你现在在浏览器中刷新页面，你会看到我们的主导航再次以异步方式工作。点击链接只会加载页面的主内容区域，而其余部分保持不变。然而，有一个重要的区别——如果你点击回退和前进按钮，它们会起作用。一旦你点击进入杯子页面，你可以点击返回按钮返回首页。

1.  我们只剩下一件事要做，就是确保我们的站点访问者可以收藏和分享我们页面的链接。如果你点击杯子页面，复制浏览器地址栏中的 URL，并打开一个新的浏览器窗口或一个新的选项卡，并粘贴 URL，你会发现你得到的是站点的主页而不是杯子页面。如果你查看 URL，`#cupcakes.html`哈希就在那里，我们只需要告诉我们的代码去找它。最简单的方法是在页面加载时立即触发窗口的`hashchange`事件。以下是我们如何做到的：

    ```js
    $(document).ready(function(){
    $('#ajax-nav a').each(function(){
    $(this).attr('href', '#' + $(this).attr('href'));
    });
    $(window).bind('hashchange', function(e) {
    var url = e.fragment;
    $('#main-col').load(url + ' #main-col-wrap');
    });
    $(window).trigger('hashchange');
    });

    ```

    现在，你可以在新窗口中打开杯子链接，你会看到杯子页面加载，就像它应该的那样。我们的`hashchange`函数在页面加载时立即触发，加载正确的内容。

## 刚刚发生了什么事？

我们使用 jQuery 循环遍历我们的每个导航链接，并用内部链接或哈希链接替换它们。为什么不直接在 HTML 中这样做呢？因为我们想确保我们的页面继续为禁用 JavaScript 的用户工作。

然后，我们使用 jQuery BBQ 插件将我们的异步导航更改为启用书签和共享链接以及浏览器中的后退和前进按钮。这使得我们的站点能够像单页应用程序一样运行，而不会破坏站点访问者的预期体验。

# 行动时间——在导航中突出显示当前页面

我们已经使我们的异步导航比我们简单的示例好得多，但我认为我们可以继续努力，使它变得更好。接下来，我们将突出显示导航中当前正在查看的页面，以便我们的网站访问者轻松看到他们所在的页面。

![行动时间——在导航中突出显示当前页面](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_07_img7.jpg)

1.  首先，让我们再次打开`styles.css`并编写导航的`.current`CSS 类：

    ```js
    #ajax-nav li.current{ background:#a3bb00; }

    ```

    我已经将我的导航栏设为绿色，所以我要将`.current`类设为稍浅一些的绿色，以便当前项目在菜单中突出显示。你可以参考我的示例或创建自己的样式——任何适合你口味的都可以。

1.  现在我们只需要将我们的`.current`类应用到当前导航项上。我们将在之前编写的`hashchange`事件函数中添加几行代码。我们将从检查窗口位置是否有哈希开始：

    ```js
    $(document).ready(function(){
    $('#ajax-nav a').each(function(){
    $(this).attr('href', '#' + $(this).attr('href'));
    });
    $(window).bind('hashchange', function(e) {
    var url = e.fragment;
    $('#main-col').load(url + ' #main-col-wrap');
    if (url) {
    // The code if there is a hash
    } else {
    // The code if there is not a hash
    }
    });
    $(window).trigger('hashchange');
    });

    ```

1.  现在，如果有一个哈希值，那么我们想要找到与哈希值对应的主导航中的链接，找到它的父容器，并添加当前类。听起来有点复杂，但我可以用一行代码完成：

    ```js
    $(window).bind('hashchange', function(e) {
    var url = e.fragment;
    $('#main-col').load(url + ' #main-col-wrap');
    $('#ajax-nav li.current').removeClass('current');
    if (url) {
    $('#ajax-nav a[href="#' + url + '"]').parents('li').addClass('current');
    } else {
    // The code if there is not a hash
    }
    });

    ```

    我正在使用 jQuery 强大的属性选择器来选择具有`href`属性等于窗口哈希的链接。然后我使用`parents()`方法获取链接的父级。我将`li`传递给`parents()`方法，告诉 jQuery 我只对一个父级感兴趣，即包含我的链接的`<li>`。然后我使用`addClass()`方法将我的当前类添加到当前链接中。

1.  如果没有哈希值，那么我想要突出显示主页，这是我们主导航中的第一个页面。我会选择第一个`<li>`并添加当前类，如下面的代码所示：

    ```js
    $(window).bind('hashchange', function(e) {
    var url = e.fragment;
    $('#main-col').load(url + ' #main-col-wrap');
    $('#ajax-nav li.current').removeClass('current');
    if (url) {
    $('#ajax-nav a[href="#' + url + '"]').parents('li').addClass('current');
    } else {
    $('#ajax-nav li:first-child').addClass('current');
    }
    });

    ```

1.  现在，如果你在浏览器中刷新页面并浏览页面，你会看到当前页面被突出显示，但随着你在网站上移动，越来越多的导航被突出显示——我们在添加新突出显示之前没有删除旧的突出显示。我们将添加以下代码以在添加新的突出显示之前删除当前突出显示：

    ```js
    $(window).bind('hashchange', function(e) {
    var url = e.fragment;
    $('#main-col').load(url + ' #main-col-wrap');
    $('#ajax-nav li.current').removeClass('current');
    if (url) {
    $('#ajax-nav a[href="#' + url + '"]').parents('li').addClass('current');
    } else {
    $('#ajax-nav li:first-child').addClass('current');
    }
    });

    ```

在浏览器中刷新页面，你会看到突出显示现在正常工作，只突出显示当前页面。

## 刚刚发生了什么？

我们在我们的`hashchange`函数中添加了几行代码，以在导航中为当前页面添加高亮显示。这将帮助网站访问者在网站上定位自己的位置，并进一步加强他们当前的位置感。

# 行动时间——添加加载动画

接下来，我们想要向网站访问者显示，当他们点击导航中的链接时，有一些事情正在发生。请记住，如果来自服务器的响应速度很慢，网站访问者看不到任何事情正在发生。即使浏览器正在努力获取新页面的内容，网站访问者也没有任何指示表明有任何事情正在发生。让我们添加一个小动画，以明显地显示我们页面上正在发生的事情。

加载动画可以采用许多不同的形式：旋转的雏菊、动画进度条、闪烁的点 —— 任何能传达正在进行的操作的东西都将有助于使您的站点对于您的站点访问者感觉更加迅捷和响应。

![操作时间 — 添加加载动画](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_07_img8.jpg)

1.  首先，前往[`ajaxload.info`](http://ajaxload.info)来创建并下载您选择的加载动画。![操作时间 — 添加加载动画](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_07_img6.jpg)

1.  在**生成器**框中选择类型、背景颜色和前景颜色，然后单击**生成！**按钮。

1.  在**预览**框中，您将看到您按钮的预览以及下载按钮的链接。单击**下载！**链接以下载您刚创建的加载动画的副本。

1.  当你下载了按钮之后，将它放入你的`images`文件夹，与你网站上使用的其他图片一起。

1.  现在，让我们仔细考虑一下我们需要对页面进行的修改。我们希望淡出当前显示在`#main-col` div 中的内容，并在其位置显示我们的加载动画，直到服务器发送回我们新页面的内容。一旦我们收到了那个内容，我们就想隐藏加载动画并显示内容。

    当我们准备向我们的站点访问者显示加载动画时，我们希望它立即可见。如果我们不得不从服务器获取图像，那将毫无意义 —— 实际页面内容可能在我们的图像之前返回。所以我们必须预加载图像。使用 jQuery，这非常简单。一旦文档加载到浏览器中，我们将创建一个新的图像元素，如下所示：

    ```js
    $(document).ready(function(){
    var loadingImage = $('<img src="img/ajax-loader.gif"/>');
    $('#ajax-nav a').each(function(){
    ...

    ```

    只创建此元素就足以将图像预加载到浏览器的缓存中。现在，当我们准备显示图像时，它将立即可用，无需等待。

1.  接下来，我们必须编写一些 CSS 来处理我们的加载图像的显示方式。我们将其包装在一个简单的段落标签中，然后添加一些填充并使图像居中：

    ```js
    #loading { padding:20px;text-align:center;display:none; }

    ```

1.  请注意，我们还将`display`设置为`none`—这样我们在准备好之前就不会有图像显示出来。我们只希望我们的动画出现在 URL 中有一个哈希时，所以在我们的`if/else`语句内，我们将加载动画附加到`#main-col` div 中：

    ```js
    ...
    if (url) {
    $('#main-col').append('<p id="loading"></p>')
    $('#loading').append(loadingImage);
    $('#ajax-nav a[href="#' + url + '"]').parents('li').addClass('current');
    } else {
    ...

    ```

    我们已经在文档中添加了一个`id`为`loading`的段落，并将我们预加载的加载图像附加到该段落中。请记住，即使它存在，由于我们用 CSS 隐藏了它，所以它还不可见。

1.  接下来，我们将淡出当前在页面上显示的内容。如果我们的内容从服务器返回得很快，我们要确保我们没有妨碍，所以我们会告诉动画快速完成：

    ```js
    ...
    if (url) {
    $('#main-col').append('<p id="loading"></p>')
    $('#loading').append(loadingImage);
    $('#ajax-nav a[href="#' + url + '"]').parents('li').addClass('current');
    $('#main-col-wrap').fadeOut('fast');
    } else {
    ...

    ```

1.  最后，我们想要展示我们的加载动画，但我们不想让它在内容淡出之前出现。为了确保它在此之前不会出现，我们将它作为回调函数添加到 `fadeOut()` 方法中。回调函数是在动画完成后调用的函数。这是我们如何向 `fadeOut()` 方法添加回调函数的方式：

    ```js
    ...
    if (url) {
    $('#main-col').append('<p id="loading"></p>')
    $('#loading').append(loadingImage);
    $('#ajax-nav a[href="#' + url + '"]').parents('li').addClass('current');
    $('#main-col-wrap').fadeOut('fast', function(){
    $('#loading').show();
    });
    } else {
    ...

    ```

    现在，当网站访问者点击链接时，定位栏中的哈希将更新。这将触发我们的代码，将页面当前内容淡出，显示加载动画，然后一旦服务器返回新页面内容，立即将加载动画替换为新页面内容。如果您非常幸运，您的网站访问者甚至不会有机会看到加载动画，因为您的服务器会快速返回新页面内容。但是，如果任何地方出现了减速，您的网站访问者将收到一个清晰的信息，表明正在发生某些事情，他们不会感到困惑或感到您的网站缓慢且不响应。

## 刚才发生了什么？

我们为网站访问者添加了一些动画效果，以示在服务器响应新页面内容的过程中出现超过几分之一秒的延迟时发生了什么。网站访问者将立即看到内容淡出，并且加载动画会取而代之，直到服务器响应新页面内容为止。

如果您正在使用 WAMP 或 MAMP 从本地计算机查看页面，那么新内容很可能会返回得非常快，以至于您没有机会看到加载动画。但是，如果您将页面上传到服务器并通过互联网访问它们，则几乎可以肯定会在浏览器获取新内容时至少看到加载动画的一小部分。

# 总结

在本章中，我们学习了如何建立一个简单的网站，然后我们增强了它的功能，使其表现得像一个单页面应用程序，但不会对搜索引擎或禁用 JavaScript 的网站访问者造成影响。首先，我们建立了一个简单版本，可能适用于某些简单情况。然后，我们看了看如何设置豪华版本，它允许收藏和分享链接，工作的前进和后退按钮，导航中当前页面的突出显示，以及平滑的过渡动画，向网站访问者展示浏览器正在辛勤工作。所有这些都相对简单和直接，多亏了 jQuery 和 jQuery BBQ 插件。

接下来，我们将研究如何将内容加载到灯箱中。


# 第八章：在灯箱中显示内容

> 在网上经常看到以灯箱形式展示照片图库已经变得很普遍了。灯箱还可以用于其他用途 — 播放视频、显示附加信息、向网站访问者显示重要信息，甚至显示其他网站。在本章中，我们将介绍如何使用灵活且适应性强的 Colorbox 插件为各种用途创建灯箱。

在本章中，我们将介绍如何使用 Colorbox 插件来：

+   创建一个简单的相册

+   自定义相册设置

+   构建一个花哨的登录框

+   播放一系列视频

+   创建一个单页网站作品集

# 简单相册

简单相册可能是使用灯箱最常见的用途之一。我们将设置一个页面，显示每张照片的缩略图，并在点击缩略图时在灯箱中显示全尺寸图像。要开始，请准备一系列带有每个缩略图的较小尺寸的照片。

这是一个在灯箱中显示的照片的示例：

![简单相册](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_08_01.jpg)

# 操作时间 — 设置简单相册

我们将使用 Colorbox 插件创建一个简单的相册，我们将逐步进行：

1.  我们将开始设置一个基本的 HTML 页面和相关文件和文件夹，就像我们在 第一章 中所做的那样，*设计师，见到 jQuery*。HTML 文档的主体将包含缩略图列表：

    ```js
    <ul class="thumb-list">
    <li><a href="images/abandoned-house.jpg" title="Old Abandoned House" rel="ireland"><img src="img/ abandoned-house.jpg" alt="Abandoned House"/></a></li>
    <li><a href="images/cemetary.jpg" title="Celtic Cemetary with Celtic Crosses" rel="ireland"><img src="img/cemetary.jpg" alt="Celtic Cemetary"/></a></li>
    <li><a href="images/cliffs-of-moher.jpg" title="Cliffs of Moher" rel="ireland"><img src="img/cliffs-of-moher.jpg" alt="Cliffs of Moher"/></a></li>
    <li><a href="images/dublin.jpg" title="River Liffey in Dublin" rel="ireland"><img src="img/dublin.jpg" alt="Dublin"/></a></li>
    <li><a href="images/dun-aonghasa.jpg" title="Dun Aonghasa on Inis More" rel="ireland"><img src="img/dun-aonghasa.jpg" alt="Dun Aonghasa"/></a></li>
    <li><a href="images/falling-in.jpg" title="Warning Sign" rel="ireland"><img src="img/falling-in.jpg" alt="Falling In"/></a></li>
    <li><a href="images/guagan-barra.jpg" title="Guagan Barra" rel="ireland"><img src="img/guagan-barra.jpg" alt="Guagan Barra"/></a></li>
    <li><a href="images/inis-more.jpg" title="Stone Fences on Inis More" rel="ireland"><img src="img/inis-more.jpg" alt="Inis More"/></a></li>
    <li><a href="images/inis-more2.jpg" title="Cliffs on Inis More's West Coast" rel="ireland"><img src="img/inis-more2.jpg" alt="Inis More Too"/></a></li>
    <li><a href="images/inis-more3.jpg" title="Inis More Fence" rel="ireland"><img src="img/inis-more3.jpg" alt="Inis More Three"/></a></li>
    <li><a href="images/mizen-head.jpg" title="Crashing Waves Near Mizen Head" rel="ireland"><img src="img/mizen-head.jpg" alt="Mizen Head"/></a></li>
    <li><a href="images/obriens-tower.jpg" title="O'Brien's Tower at the Cliffs of Moher" rel="ireland"><img src="img/obriens-tower.jpg" alt="O'Brien's Tower"/></a></li>
    <li><a href="images/random-castle.jpg" title="Some Random Castle" rel="ireland"><img src="img/random-castle.jpg" alt="Random Castle"/></a></li>
    <li><a href="images/turoe-stone.jpg" title="Turoe Stone" rel="ireland"><img src="img/turoe-stone.jpg" alt="Turoe Stone"/></a></li>
    </ul>

    ```

    请注意，我们将每个缩略图都包装在到图像全尺寸版本的链接中。如果在浏览器中加载页面，你会看到页面适用于禁用 JavaScript 的用户。点击缩略图会在浏览器中打开全尺寸图像。点击后退按钮会返回到相册。

    请注意，我们还在每个链接上包含了一个 `title` 属性。对于我们的网站访问者来说，这对他们很有帮助，因为当他们用鼠标悬停在缩略图上时，它将显示图像的简短描述。但是稍后也将用于 Colorbox 插件。我们还在每个链接上包含了一个 `rel` 属性，并将其设置为 ireland。这将使我们在准备添加 Colorbox 插件魔法时很容易选择我们的爱尔兰图像组。

1.  接下来，我们将添加一些 CSS 来将图像布局在网格中。打开你的 `styles.css` 文件并添加这些样式：

    ```js
    ul.thumb-list { margin:20px 0;padding:0;text-align:center; }
    ul.thumb-list li { margin:0;padding:0;display:inline-block; }

    ```

    ![操作时间 — 设置简单相册](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_08_02.jpg)

    如果你愿意的话，可以随意调整一下 CSS，为你的图片缩略图创建不同的布局。

1.  现在，让我们添加 jQuery 魔法。我们将使用 Color Powered 的 Colorbox 插件。请前往 [`jacklmoore.com/colorbox`](http://jacklmoore.com/colorbox) 查找下载、文档和演示。你会在**下载**部分找到下载链接，在页面顶部附近。只需点击当前版本号下载 ZIP 文件。![操作时间 — 设置简单相册](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_08_03.jpg)

1.  解压缩文件夹并查看其内容。你会找到插件脚本文件本身，当然还有许多其他好东西。![行动时间——设置简单的照片库](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_08_04.jpg)

    插件代码本身位于`colorbox`文件夹中——你会找到开发和压缩版本。五个示例文件夹中每个都包含一个示例文件（`index.html`），展示了插件的作用。为什么有五个不同的文件夹？每个文件夹包含相同的基本示例，但 Colorbox 有五种不同的外观。这些相同的示例可以在 Colorbox 网站上点击网站上**查看演示**部分中的数字来查看。

    开箱即用，插件的开发人员为我们提供了五种不同的 Colorbox 外观和感觉的可能性。如果这还不够选择，他们还包含了一个包含用于创建这五种不同外观的所有图像资产的`colorbox.ai`（**Adobe Illustrator**）文件。您可以随心所欲地自定义它们，然后从 Illustrator 中导出您的新完全自定义外观，以创建您自己的外观。更改颜色和特效非常简单，但请记住，如果更改图像资产的大小和形状，您将不得不修改相应的 CSS 文件以适应新的大小。

1.  尝试每个不同的示例，无论是在网站上还是使用 ZIP 下载中包含的示例文件，并注意外观、大小、前进和后退按钮的位置、关闭按钮、标题、分页指示器（图像 1/3）等都是通过 CSS 而不是插件代码本身控制的。这使得定制外观和感觉非常容易——所有这些都是通过 CSS 而不是 JavaScript 完成的。

1.  在 ZIP 下载中，在`colorbox`文件夹中，你会找到插件代码一个名为`jquery.colorbox-min.js`的文件。将此文件复制到你自己的`scripts`文件夹中。

1.  我们将从选择提供的 CSS 外观中开始。选择你喜欢的外观，然后将其 CSS 文件复制粘贴到你自己的`styles`文件夹中。打开该 CSS 外观的`images`文件夹，并将该文件夹中的图像复制粘贴到你自己的`images`文件夹中。一旦你选择了一个外观，你自己的设置应该如下所示：![行动时间——设置简单的照片库](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_08_05.jpg)

    `index.html`文件包含了链接到全尺寸版本的缩略图图像的 HTML。`images`文件夹包含了与我选择的 Colorbox 外观提供的图像以及我的幻灯片秀的自己的图像，包括缩略图和全尺寸版本。我的`scripts`文件夹包含了 jQuery（`jquery.js`）和 Colorbox 插件脚本（`jquery.colorbox-min.js`）。我的`styles`文件夹包含了我选择的 Colorbox 外观的 CSS 文件。

1.  我们必须打开 `colorbox.css` 进行一组微小的编辑。在示例文件中，CSS 文件不在 `styles` 或 `css` 文件夹中，而是与 `index.html` 文件一样位于顶层。我们选择遵循我们的首选约定，并将我们的 CSS 存储在我们的 `styles` 文件夹中。这意味着我们将不得不打开 `colorbox.css` 文件并更新 CSS 中的图像引用。我将不得不替换以下引用：

    ```js
    #cboxTopLeft{width:21px; height:21px; background:url(images/controls.png) no-repeat -100px 0;}

    ```

    具有以下引用：

    ```js
    #cboxTopLeft{width:21px; height:21px; background:url(../images/controls.png) no-repeat -100px 0;}

    ```

    我只是告诉 CSS 向上一级查找，然后查找 `images` 文件夹。您应该可以通过使用文本编辑器的查找和替换功能快速替换所有这些内容。

1.  接下来，打开您的 `index.html` 文件，并在您自己的 `styles.css` 之前的 head 部分附加 `colorbox.css` 文件：

    ```js
    <head>
    <title>Chapter 8: Showing Content in Lightboxes</title>
    <link rel="stylesheet" href="styles/colorbox.css"/>
    <link rel="stylesheet" href="styles/styles.css"/>
    </head>

    ```

1.  然后，在文件底部，在关闭`</body>`标签之前，将 Colorbox 插件附加在 jQuery 之后，但在您自己的 `scripts.js` 文件之前：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/jquery.colorbox-min.js"></script>
    <script src="img/scripts.js"></script>

    ```

1.  现在，记住我们在每个链接上包含的 `rel="ireland"` 属性吗？我们将在 JavaScript 中使用它来选择 Colorbox 插件的所有爱尔兰图片链接。打开您的 `scripts.js` 文件，并在文档就绪语句中编写属性选择器，以选择具有 `rel` 属性等于 `ireland` 的所有链接：

    ```js
    $(document).ready(function(){
    $('a[rel="ireland"]')
    });

    ```

1.  唯一剩下的事情就是在这些链接上调用 `colorbox()` 方法，Colorbox 插件会为我们处理其他所有事情：

    ```js
    <script type="text/javascript">
    $('a[rel="ireland"]').colorbox();
    </script>

    ```

    现在，如果您在浏览器中打开页面并单击缩略图图像之一，您将看到全尺寸图像在 Colorbox 中打开。您可以通过后退和前进按钮在所有全尺寸图像之间导航，而无需关闭灯箱。您还可以通过在键盘上按左右箭头键之间移动图像。分页指示器可帮助您查看您在照片集合中的位置。您还会注意到，每个链接上包含的 `title` 属性被重新用作每个图像的图像标题。可以通过单击关闭按钮、单击 Colorbox 外部或按键盘上的 Esc 键来关闭 Colorbox。总的来说，这是一个非常好的开箱即用的体验。

## 刚刚发生了什么？

我们使用 Colorbox jQuery 插件将图像链接列表转换为灯箱，让站点访问者能够在不离开页面的情况下浏览全尺寸图像。我们使用链接的 `title` 属性为图像提供标题。我们使用插件提供的五种 Colorbox 样式之一来创建一个设计良好的灯箱。

# 自定义 Colorbox 的行为

如果您查看 Colorbox 网站的 **Settings** 部分，您会看到有很多选项可以自定义 Colorbox 的行为方式。让我们看看如何利用其中一些选项。对于本节，我们将继续使用上一节设置的文件。

## 过渡

首先，我们将尝试不同的可用过渡效果。默认过渡效果是`elastic`。如果您的全尺寸图像尺寸各不相同，您会发现 Colorbox 使用一个漂亮的调整大小动画来在它们之间进行过渡。过渡的其他选项包括`fade`和`none`。让我们看看如何修改过渡。

# 行动时间 —— 使用自定义过渡

按照以下步骤更改图片之间的默认过渡效果：

1.  对于这个例子，我们将看一下如何使用`fade`过渡。打开您的`scripts.js`文件。我们所要做的就是将`fade`值传递给`colorbox()`方法的过渡关键字，如下所示：

    ```js
    $(document).ready(function(){
    $('a[rel="ireland"]').colorbox({transition:'fade'});
    });

    ```

    请注意，我们在括号内添加了一些花括号。在这些花括号内，我们可以传递键/值对以定制 Colorbox 的不同方面。在这种情况下，关键字是`transition`，值是'fade'。

    如果您在浏览器中重新加载页面，点击其中一个缩略图，然后点击下一个和上一个按钮来浏览图片，您会发现 Colorbox 在每张图片之间淡出然后淡入。

1.  如果我们决定完全取消过渡会怎样？我们只需将`transition`关键字的值更改为`'none'`即可：

    ```js
    $(document).ready(function(){
    $('a[rel="ireland"]').colorbox({transition:'none'});
    });

    ```

    现在，如果您在浏览器中刷新页面，您会发现图片之间没有任何过渡效果。

## 刚才发生了什么？

我们看到了如何利用 Colorbox 插件中的一个可用设置，并修改了当我们的网站访问者浏览图片时的过渡效果。

## 固定大小

在加载到 Colorbox 中的照片尺寸差异很大的情况下，您可能会决定所有调整大小会使网站访问者分心，您想为 Colorbox 设置一个固定大小。这也很容易做到，只需再传入几个键/值对即可。浏览文档，您会发现有很多用于控制 Colorbox 宽度和高度的设置。为了保持简单，我们将使用`width`和`height`。

# 行动时间 —— 设置固定大小

按照以下步骤为 Colorbox 设置固定宽度和高度：

1.  打开您的`scripts.js`文件。我们将对我们的代码进行一些更改，为 Colorbox 设置固定的`width`和`height`：

    ```js
    $('a[rel="ireland"]').colorbox({
    transition: 'none',
    width: '90%',
    height: '60%'
    });

    ```

    现在，如果您在浏览器中刷新页面，您会发现 Colorbox 保持相同的大小。无论图像或浏览器窗口的大小如何，Colorbox 始终会填充浏览器窗口宽度的 90%和高度的 60%。如果图像过大，图像内部会按比例调整大小以适应可用空间。

## 刚才发生了什么？

我们将`width`和`height`设置为百分比值。如果你有可能比您站点访问者的浏览器窗口还大的大照片，这是一个非常有用的选项。将`width`和`height`设置为百分比值可以确保在这种情况下，Colorbox 将是站点访问者浏览器窗口宽度的 90%，高度的 60%，无论浏览器窗口的大小是多少。这样，如果浏览器窗口很小，站点访问者仍然能够看到完整的照片。

Colorbox 还为宽度和高度提供了一些其他设置：

### innerWidth/innerHeight

这些键为 Colorbox 内部内容提供了`width`和`height`值，而不是为 Colorbox 本身提供。在您知道实际内容的确切宽度和高度的情况下，例如视频播放器，这可能很有帮助。

### InitialWidth/initialHeight

Colorbox 非常灵活，可以用于各种不同的内容（我们马上就会看到）。设置`intialWidth`和`initialHeight`允许您在加载任何内容之前控制 Colorbox 的大小。如果通过 Ajax 加载内容，可能需要一些时间才能加载到 Colorbox 中。设置`initialWidth`和`initialHeight`允许您指定在等待内容加载时 Colorbox 应该有多大。

### maxWidth/maxHeight

这些键允许您为 Colorbox 设置最大宽度和最大高度。如果内容较小，则框将在屏幕上显示为较小的尺寸。但是当您加载较大的内容时，它们不会超过您指定的`maxWidth`和`maxHeight` 值。例如，如果您想为各种大小的图像设置 Colorbox，您可以允许 Colorbox 在图像之间使用淡入淡出或弹性过渡来调整大小，但是设置`maxWidth`和`maxHeight`可以确保较大的图像不会超过站点访问者的浏览器窗口。

## 创建一个幻灯片

Colorbox 还为我们提供了一个选项，可以自动循环显示所有图片，这样站点访问者就不必不断点击下一个按钮来查看它们。

# 行动时间——创建幻灯片

我们可以将我们的灯箱图片库变成幻灯片的方法如下：

1.  打开`scripts.js`。我们将向我们的设置添加另一个键/值对。要在我们的 Colorbox 中创建幻灯片，将`slideshow`键设置为`true`：

    ```js
    $('a[rel="ireland"]').colorbox({
    transition: 'none',
    width: '90%',
    height: '60%',
    slideshow: true
    });

    ```

    现在，如果您在浏览器中刷新页面，您会看到在您打开 Colorbox 后，它会自动循环显示图片，使用您选择的任何转换效果。提供一个链接，以便站点访问者随时可以停止幻灯片：

    ![行动时间——创建幻灯片](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_08_06.jpg)

1.  Colorbox 提供了更多我们可以用来控制幻灯片演示的键。我们可以为 `slideshowSpeed` 提供一个值来设置每张照片显示的毫秒数。如果我们不想要幻灯片自动播放，我们可以将 `slideshowAuto` 设置为 `false`。我们可以通过为 `slideshowStart` 和 `slideshowStop` 键传入值来更改链接中显示的启动和停止幻灯片的文本，分别如下所示：

    ```js
    $('a[rel="ireland"]').colorbox({
    transition: 'none',
    width: '90%',
    height: '60%',
    slideshow: true,
    slideshowSpeed: 2000,
    slideshowAuto: false,
    slideshowStart: 'Let\'s get started!',
    slideshowStop: 'Ok, that\'s enough.'

    ```

    通过这段代码，我们设置了我们的幻灯片演示每张照片显示 2 秒（2000 毫秒），不自动启动幻灯片演示，并定制了启动和停止幻灯片的链接上的文本。

    请注意，每个键/值对之间用逗号分隔，但是在最后一个键/值对后面没有逗号。在 Internet Explorer 中，最后一个后面没有逗号只是很重要 —— 如果你在 Internet Explorer 中意外地在最后一个键/值对后面放了一个逗号，它会抛出一个错误，你的 JavaScript 将无法工作。其他浏览器会忽略该错误并继续优雅地工作。在将工作提供给公众之前，请始终在 Internet Explorer 中测试您的工作。

    让我们谈一谈出现在我想用于启动和停止幻灯片演示的链接文本中的 \'。由于这些是字符串，我必须将它们用引号括起来，可以是 ' 单引号也可以是 " 双引号，并且是个人偏好选择哪个。如果我想在我的字符串中使用引号，我必须转义它们 —— 这是 JavaScript 说我必须告诉 JavaScript 那些是我的字符串的一部分而不是 JavaScript 应该注意的字符的方式。

    如果我按照这种方式编写我的字符串：

    ```js
    slideshowStart: 'Let's get started!'

    ```

    这将导致错误。就 JavaScript 而言，Let's 中的 ' 是字符串的结束单引号 —— 而 JavaScript 不知道如何处理行的其余部分。

    在这种情况下，如果我的个人偏好是使用双引号来编写字符串，我就不需要做任何事情。这将是完全可以接受的：

    ```js
    slideshowStart: "Let's get started!"

    ```

    由于我们在字符串周围使用双引号，JavaScript 不会意外地将其读取为我们字符串的结尾。一旦 JavaScript 看到一个开头的 " 字符，它就会自动寻找匹配的结尾 " 字符。

    现在我们已经定制了我们的幻灯片演示，在浏览器中刷新页面并点击一个图片缩略图来打开 Colorbox。唯一可见的区别是添加了**让我们开始吧**链接。点击它启动幻灯片演示并将链接更改为说好了，这样我们就可以停止幻灯片演示。

## 刚刚发生了什么？

我们看到了如何创建和定制幻灯片演示。我们通过向 `colorbox()` 方法传递一系列键/值对来获取简单的灯箱照片库并进行定制。

# 炫酷的登录

使用 lightbox 来显示图片和幻灯片已经足够好了，但是 Colorbox 比这更有能力和灵活。在本节中，我们将看看如何在 Colorbox 中显示一个登录表单。请注意，我们的登录表单没有连接到任何东西，在示例情况下实际上不会起作用。但是这个相同的技术可以应用于一个动态站点，让你的站点访客可以在 lightbox 中查看登录表单。

# 执行操作-创建一个花哨的登录表单

按照以下步骤在 lightbox 中创建一个登录表单：

1.  我们将开始设置一个 HTML 页面和相关的文件和文件夹，就像我们在第一章中所做的那样，*Designer, Meet jQuery*。我们的 HTML 页面将包含一个显示登录表单的标题。通常情况下，站点允许人们从站点的任何页面登录：

    ```js
    <div id="example-header">
    <h1>Ireland: The Emerald Isle</h1>
    <form action="#" id="login-form">
    <div><label for="username">Username:</label> <input type="text" id="username"/></div>
    <div><label for="password">Password:</label> <input type="text" id="password"/></div>
    <div><input type="submit" value="Log In"/></div>
    </form>
    </div>

    ```

1.  接下来，我们将打开`styles.css`并添加一些 CSS，以便标题显示在左侧，表单显示在右侧：

    ```js
    #example-header { border-bottom:2px solid #586E75; border-top:2px solid #586E75;overflow:hidden;zoom:1; }
    #example-header h1 { float:left;padding:0;margin:0; }
    #example-header #login-form { float:right;padding-top:15px; }
    #example-header #login-form div { display:inline; }
    #login-link { display:block;float:right;padding-top:15px; }
    #login-link:focus { outline:none; }

    ```

    如果你在浏览器中查看页面，你会看到以下内容：

    ![执行操作-创建一个花哨的登录表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_08_07.jpg)

    对于没有启用 JavaScript 的用户来说，这是完全可以接受的-他们可以从任何页面登录到网站。但我认为这有点凌乱。所以如果网站访问者启用了 JavaScript，我们将隐藏登录表单，并在网站访问者准备登录时在 Colorbox 中显示它。

1.  接下来，我们将准备使用 Colorbox 插件，方式与我们在上一节中所做的一样：选择一个提供的 Colorbox 样式，并将其样式表附加到文档的头部，将所有必需的图片移动到你的`image`目录并更新 CSS 中的图片路径，并将 Colorbox 插件附加到文档的底部，在 jQuery 和我们的`scripts.js`标签之间。

1.  一旦所有这些都搞定了，我们就可以开始编写我们的 JavaScript 了。打开`scripts.js`并编写你的文档就绪语句：

    ```js
    $(document).ready(function(){
    //Our code goes here
    });

    ```

1.  我们要做的第一件事是隐藏登录表单。我们将使用 JavaScript 而不是 CSS 来做到这一点，因为我们希望对于没有启用 JavaScript 的网站访问者来说，登录表单是可见的。我们希望在页面加载后立即隐藏表单，所以我们将在文档的`ready()`方法内编写我们的隐藏代码：

    ```js
    $(document).ready(function(){
    var form = $('#login-form');
    form.hide()
    });

    ```

    你会注意到我们创建了一个名为`form`的变量，并用它来存储表单的 jQuery 选择器。我们将不得不在我们的代码中多次引用登录表单。我们可以每次想要选择登录表单时都写`$('#login-form')`，但是每次，jQuery 都要重新查找 DOM 页面来找到它。如果我们将它存储在一个变量中，我们的代码将运行得更快，更高效，因为 jQuery 不必每次引用它时都查找登录表单。

    如果你在浏览器中刷新页面，你会发现登录表单已经消失了。

1.  但是现在我们需要一个让网站访问者能够再次显示它以便登录的方法。我们将使用 jQuery 在页面上添加一个登录链接，它将出现在表单原来的位置：

    ```js
    $(document).ready(function(){
    var form = $('#login-form');
    form.hide()
    form.before('<a href="#login-form" id="login-link">Login</a>');
    });

    ```

    已经，我们再次提到了表单 —— 在表单之前插入登录链接。我们已经在 CSS 中包含了一些样式，来样式化链接并将其显示在我们想要的位置。如果你在浏览器中刷新页面，你会看到登录表单被一个登录链接替换了：

    ![操作时间 —— 创建一个花哨的登录表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_08_08.jpg)

1.  但是点击登录链接没有任何反应。让我们通过添加一些 Colorbox 魔法来解决这个问题。我们将选择我们的登录链接，并调用 `colorbox()` 方法，如下所示：

    ```js
    $(document).ready(function(){
    var form = $('#login-form');
    form.hide()
    $('#login-form').before('<a href="#login-form" id="login-link">Login</a>');
    $('#login-link').colorbox();
    });

    ```

    刷新浏览器页面，然后尝试点击链接。嗯... 这不是我们想要的结果，对吧？我们必须告诉 Colorbox 我们想加载一些已经在页面上的内容。

1.  我们已经在链接的 `href` 属性中放置了登录表单的引用，所以我们会利用这一点。我们将向 `colorbox()` 方法传递一些键值对，告诉 Colorbox 我们想加载一些已经在页面上的内容，并确切地指定我们想要显示的内容：

    ```js
    $(document).ready(function(){
    var form = $('#login-form');
    form.hide()
    $('#login-form').before('<a href="#login-form" id="login-link">Login</a>');
    $('#login-link').colorbox({
    inline: true,
    content: $(this).attr('href')
    });
    });

    ```

    刷新浏览器页面，你会看到 Colorbox 打开了，但是它似乎是空的。那是因为我们隐藏了我们的表单。它已经加载到了 Colorbox 中，但是被隐藏了。

1.  我们将使用另一个键值对来告诉 Colorbox 在 Colorbox 打开时显示表单：

    ```js
    $(document).ready(function(){
    var form = $('#login-form');
    form.hide()
    $('#login-form').before('<a href="#login-form" id="login-link">Login</a>');
    $('#login-link').colorbox({
    inline: true,
    content: $(this).attr('href'),
    onOpen: function(){form.show();}
    });
    });

    ```

    `onOpen` 是 Colorbox 插件提供的键之一。它允许我们编写一个函数，该函数将在 Colorbox 打开时运行。在这种情况下，我将找到我的表单并显示它。现在，如果你在浏览器中刷新页面，你将能够在 ColorBox 中看到表单如下：

    ![操作时间 —— 创建一个花哨的登录表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_08_09.jpg)

1.  这看起来已经足够好了，我们稍后会用一点 CSS 来修饰一下，让它看起来更好一些。但是当你关闭 Colorbox 时会发生什么？那个讨厌的登录表单又出现在头部了。所以我们会向我们的 `colorbox()` 方法传递另一个键值对，在 Colorbox 关闭时隐藏表单：

    ```js
    $(document).ready(function(){
    var form = $('#login-form');
    form.hide()
    $('#login-form').before('<a href="#login-form" id="login-link">Login</a>');
    $('#login-link').colorbox({
    inline: true,
    content: $(this).attr('href'),
    onOpen: function(){form.show();},
    onCleanup: function(){form.hide();},
    });
    });

    ```

    这将确保我们的表单在 Colorbox 关闭时被隐藏，这样它就不会再次出现在头部。

1.  现在，让我们让我们的登录表单看起来更友好一些。打开 `styles.css` 文件，然后添加一些 CSS，样式化光箱内的登录表单：

    ```js
    #cboxContent form div { padding:5px 0; }
    #cboxContent label { display:block; }
    #cboxContent input[type='text'] { font-size:1.2em;padding:5px;width:342px;border:1px solid #ccc;box-shadow:inset 2px 2px 2px #ddd;border-radius:5px; }
    #cboxContent input[type='submit'] { font-size:1.2em;padding:10px; }

    ```

1.  我们还希望将登录表单框变宽一点，所以我们会向 `colorbox()` 方法传递一个 `width` 键，如下所示：

    ```js
    $(document).ready(function(){
    var form = $('#login-form');
    form.hide()
    form.before('<a href="#login-form" id="login-link">Login</a>');
    $('#login-link').colorbox({
    width: '400px',
    inline: true,
    content: $(this).attr('href'),
    onOpen: function(){form.show();},
    onCleanup: function(){form.hide();},
    });
    });

    ```

    现在，如果你在浏览器中刷新页面，你会看到我们的 Colorbox 确实是 400 像素宽，我们的登录表单已经采用了我们想要的用 CSS 创建的漂亮的块状外观，但还有一个小问题。我们的表单对于 Colorbox 来说太高了：

    ![操作时间 —— 创建一个花哨的登录表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_08_10.jpg)

    Colorbox 脚本并没有意识到我们的表单在显示在 Colorbox 内部时具有不同的 CSS —— 它仍然期望表单的高度与在标题中显示时的高度相同。但是，该表单要小得多。如果你把鼠标放在登录表单上并向下滚动，你会看到剩下的登录表单在那里 —— 我们只是看不到它。

1.  我们不希望在我们的 Colorbox 中出现任何滚动，所以我们将关闭它，并通过向 `colorbox()` 方法传递一些额外的键/值对告诉 Colorbox 调整大小以适应其内容：

    ```js
    $(document).ready(function(){
    var form = $('#login-form');
    form.hide()
    form.before('<a href="#login-form" id="login-link">Login</a>');
    $('#login-link').colorbox({
    width: '400px',
    inline: true,
    scrolling: false,
    content: $(this).attr('href'),
    onOpen: function(){form.show();},
    onComplete: function(){$.colorbox.resize();},
    onCleanup: function(){form.hide();},
    });
    });

    ```

    滚动键允许我们关闭 Colorbox 内部的任何滚动，并且 `onComplete` 键是一个回调函数，在内容加载到 Colorbox 中后立即调用。一旦内容加载到 Colorbox 中，我们将调用一个 Colorbox 插件提供给我们的方法来调整 Colorbox 的大小以容纳其内容。

    现在，如果你在浏览器中刷新页面，你会看到 Colorbox 滑动打开以适应我们表单的新 CSS 而变得更高。完美！

    ![操作时间 — 创建漂亮的登录表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_08_11.jpg)

## 刚刚发生了什么？

我们学会了如何将简单的标题登录表单更改为在单击时在 Colorbox 中打开登录表单的登录链接。我们通过将回调函数传递给 Colorbox 插件文档中指定的键的值来解决了此方法可能引起的任何潜在问题。我们学会了在 Colorbox 打开时调用函数、当内容加载到 Colorbox 中时以及当 Colorbox 关闭时运行函数。我们学会了通过调用 `$.colorbox.resize()` 方法强制 Colorbox 调整大小以适应其当前内容。

# 视频播放器

Colorbox 是足够灵活的，可以用来显示视频播放器作为内容。我们将链接到一个 YouTube 视频，然后添加一些 Colorbox 魔法来在 Colorbox 中显示视频。请注意，此示例使用了 Ajax，因此只有在上传文件到服务器或在您自己的计算机上创建服务器时才会起作用。

# 操作时间 — 在灯箱中显示视频

按照以下步骤设置 Colorbox 以播放一组视频：

1.  我们将像通常一样开始，通过设置一个基本的 HTML 文件和关联的文件和文件夹，就像我们在第一章中所做的那样，*设计师，见 jQuery*。在我们 HTML 文档的主体中，我们将包含一个指向 YouTube 视频的链接：

    ```js
    <p><a href="http://www.youtube.com/embed/2_HXUhShhmY?autoplay=1" id="video-link">Watch the video</a></p>

    ```

    注意关于我的视频链接的一些事情。首先，我使用的是视频的嵌入式 URL，而不是指向 YouTube 视频页面的链接。对于未启用 JavaScript 的用户，这将把他们带到 YouTube 网站上的独立视频播放器页面。对于启用了 JavaScript 的用户，这将确保只有视频播放器加载到 Colorbox 中，而不是完整的 YouTube 视频页面。其次，我向视频的 URL 添加了一个参数，将`autoplay`设置为 1。这是在访问者查看页面时如何使嵌入式 YouTube 视频自动播放的方法。通常情况下，自动播放视频是一个不好的主意，但在这种情况下，用户已经点击了一个标有 **观看视频** 的链接，所以他们很可能在点击链接后期待视频播放。

1.  接下来，就像迄今为止的其他 Colorbox 示例一样，您需要在文档的头部附加您选择的 Colorbox 皮肤 CSS 文件，确保图像可用，如果需要的话，请更新 CSS 中图像的路径，并最后在文档的底部附加 Colorbox 插件。

1.  现在，我们将打开我们的`scripts.js`文件，并准备好编写我们的自定义 JavaScript。我们将从文档就绪语句开始：

    ```js
    $(document).ready(function(){
    });

    ```

1.  接下来，我们将选择视频链接并调用`colorbox()`方法：

    ```js
    $(document).ready(function(){
    $('#video-link').colorbox();
    });

    ```

    但是，如果我们在浏览器中刷新页面并尝试查看视频，我们会收到一个错误。那是因为我们试图通过 Ajax 加载视频，由于浏览器的安全限制，我们不能对不同服务器进行异步请求。在这种情况下，我们试图调用 [`youtube.com`](http://youtube.com)，但这不是我们 Colorbox 页面托管的地方，所以浏览器阻止了我们的请求。

1.  幸运的是，我们可以创建一个`iframe`并将我们的外部内容加载到`iframe`中。而且幸运的是，Colorbox 提供了一种让我们轻松实现这一点的方法。我们只需向`colorbox()`方法传递一个键/值对，将`iframe`设置为`true`，就像下面这样：

    ```js
    $('#video-link').colorbox({
    iframe: true
    });

    ```

    现在我们的视频加载到了 Colorbox 中，但是 Colorbox 不知道我们的视频有多大，所以我们看不到它。

1.  我们必须告诉 Colorbox 我们期望视频播放器有多大。我们将通过为`innerWidth`和`innerHeight`传递键/值对来实现这一点。在这种情况下，我们使用`innerWidth`和`innerHeight`而不是宽度和高度，因为我们传递的是我们想要视频播放器（或内容）的大小，而不是我们想要 Colorbox 的大小：

    ```js
    $('#video-link').colorbox({
    iframe: true,
    innerWidth: '640px',
    innerHeight: '480px'
    });

    ```

1.  我们还可以使用 Colorbox 创建一种让用户轻松查看多个视频的方式。让我们回到`index.html`，而不是只添加一个视频链接，我们将在页面上添加一个收藏视频的列表。我们为每个视频设置一个`rel`属性为`favorites`，并提供一个`title`属性，这样我们的视频就会在下面显示标题：

    ```js
    <h3>Favorite Videos</h3>
    <ul>
    <li><a href="http://www.youtube.com/embed/itn8TwFCO4M?autoplay=1" rel="favorites" title="Louis CK and Everything is Amazing">Everything is Amazing</a></li>
    <li><a href="http://www.youtube.com/embed/UN0A6h9Wc5c?autoplay=1" rel="favorites" title="All This Beauty by The Weepies">All This Beauty</a></li>
    <li><a href="http://www.youtube.com/embed/ZWtZA-ZmOAM?autoplay=1" rel="favorites" title="ABC's That's Incredible">That's Incredible</a></li>
    </ul>

    ```

1.  我们在`scripts.js`中唯一需要更新的是更新选择器。我们不再通过 ID 选择单个链接，而是通过它们的`rel`属性选择我们的一组收藏链接：

    ```js
    $('a[rel="favorites"]').colorbox({
    iframe:true,
    innerWidth:'640px',
    innerHeight: '480px'
    })

    ```

    如果您在浏览器中查看页面，您会发现在视频下有一个标题，并且有下一个和上一个按钮，允许您在不关闭 Colorbox 的情况下在视频之间导航。

1.  唯一有点尴尬的是，当我们显示视频而不是图像时，我们的分页指示器显示“图像 1/3”。幸运的是，Colorbox 提供了一种让我们使用`current`键自定义此文本的方法：

    ```js
    $('a[rel="favorites"]').colorbox({
    iframe:true,
    innerWidth:'640px',
    innerHeight: '480px',
    current: 'Video {current} of {total}'
    })

    ```

    现在，我们的分页指示器正确显示为 Video 1 of 3。我们的网站访客可以轻松地从一个视频转移到另一个视频，而不必关闭 Colorbox，每个视频都显示标题：

    ![行动时间——在灯箱中显示视频](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_08_12.jpg)

## 刚刚发生了什么？

我们学会了如何在 Colorbox 中创建独立的视频播放器和多个视频播放器。我们学会了传递键/值对以告诉 Colorbox 在`iframe`中加载外部内容，以解决跨域 Ajax 限制。我们还学会了如何修改分页指示器文本以适应我们当前的内容类型。我们使用了`innerWidth`和`innerHeight`键来设置视频播放器的大小。

# 单页网页画廊

接下来，我们将看看如何创建一个单页网页画廊，展示你喜欢的网站或你自己设计的所有令人难以置信的网站。请注意，此示例使用了 Ajax，因此您必须将您的页面上传到网络服务器，或者在您自己的计算机上创建一个网络服务器才能看到其运行情况。

# 行动时间——创建一个单页网页画廊

按照以下步骤创建一个单页网页画廊：

1.  我们将从设置一个基本的 HTML 文件和相关文件和文件夹开始，就像我们在第一章中所做的那样，*设计师，遇见 jQuery*。在我们的 HTML 文档的主体中，我们将创建一个链接列表，链接到我们想在我们的设计画廊中包含的网站：

    ```js
    <h3>One-Page Web Design Gallery</h3>
    <ul>
    <li><a href="http://packtpub.com" rel="gallery">Packt Publishing</a></li>
    <li><a href="http://nataliemac.com" rel="gallery">NatalieMac</a></li>
    <li><a href="http://google.com" rel="gallery">Google</a></li>
    </ul>

    ```

    请注意，我为每个链接都添加了等于`gallery`的`rel`属性。

1.  现在，就像其他 Colorbox 示例一样，选择一个样式并将样式表附加到文档的头部，在页面中使所有必要的图像可用，如果需要更新 CSS 中图像的路径，并在页面底部附加 Colorbox 插件。

1.  接下来，我们将打开我们的`scripts.js`文件并添加我们的文档就绪语句：

    ```js
    $(document).ready(function(){
    });

    ```

1.  接下来，我们将选择所有`rel`属性等于`gallery`的链接，并调用`colorbox()`方法：

    ```js
    $(document).ready(function(){
    $('a[rel="gallery"]').colorbox();
    });

    ```

1.  就像我们在视频示例中所做的一样，我们将`iframe`键设置为`true`，因为我们正在从其他域加载内容。我还将 ColorBox 的`width`和`height`设置为`90％`，这样它几乎占据了整个浏览器窗口。我还将调整分页指示器文本，将其更改为`Web Site`，而不是`Image:`。

    ```js
    $('a[rel="gallery"]').colorbox({
    iframe: true,
    width: '90%',
    height: '90%',
    current: 'Web Site {current} of {total}'
    });

    ```

    现在，如果您在浏览器中刷新页面，您会发现单击其中一个链接会打开一个 Colorbox 并将该网站加载到 Colorbox 中。网站访客可以与加载的网站进行交互，就像他们将其加载到单独的浏览器窗口中一样，浏览页面等。完成一个站点后，他们可以单击下一个箭头访问列表中的下一个网站，然后在完成时单击键盘上的 Esc 键或单击关闭按钮或单击 Colorbox 外部的任何地方关闭 Colorbox。

### 注意

请注意，网站所有者有可能阻止您将其网站加载到 `iframe` 中的能力。如果您使用 MAMP 或 WAMP 设置了本地服务器，那么您可能会注意到 Google 示例无法加载到您的页面中。但是，如果您将代码上传到外部服务器，则可以加载。务必测试您要在网站图库中使用的所有站点，以确保它们按预期工作。

## 刚刚发生了什么？

我们利用创建 Colorbox 视频播放器所学到的大部分内容来在 Colorbox 中显示外部网站。这允许我们的网站访客在不离开我们的页面的情况下浏览一系列网站。我们再次告诉 Colorbox 将我们的内容加载到 `iframe` 中，以解决跨域 Ajax 限制。我们自定义了分页指示器文本，并为 Colorbox 设置了宽度和高度。

# 总结

我们已经看过了适应性和灵活性的颜色框插件的几种用法，它可以用来在灯箱中显示任何类型的内容。它可用于创建可浏览的图像库，提供对表单和视频播放器的访问，而不会在页面上堆积笨重的 UI 元素，甚至可以创建可浏览的网站图库。颜色框插件完全由 CSS 样式化，使得灯箱可以呈现您想象出的任何外观。该插件甚至包括可用作创建自己的灯箱设计起点的矢量图像资源。通过向 `colorbox()` 方法传递一系列键值对，可以修改灯箱的行为，使得 Colorbox 插件适用于任何可能的灯箱用途。

接下来，我们将看一下另一个常见的网站任务：创建幻灯片演示。


# 第九章：创建幻灯片

> 幻灯片通常是在 Flash 中创建的，是展示照片、产品、插图、作品集等的绝佳方式。创建幻灯片是 jQuery 开发人员最常见的任务之一。在本章中，我们将看看如何从头开始创建一个简单的幻灯片，然后探讨三个创建华丽、动态且功能齐全的幻灯片的强大插件。

在本章中，我们将涵盖以下内容：

+   如何规划幻灯片

+   如何从头开始编写一个简单的淡入淡出幻灯片

+   如何使用 CrossSlide 插件创建平移和缩放幻灯片

+   如何使用 Nivo Slider 插件创建具有有趣过渡效果的幻灯片

+   如何使用 Galleriffic 插件创建缩略图幻灯片

# 规划幻灯片

在准备构建 jQuery 幻灯片时，有几个要考虑的事项。它们如下：

+   首先，您必须决定对于禁用 JavaScript 的用户来说，体验会是什么样的。幻灯片中各个内容片段的优先级应该成为您的指南。如果幻灯片只是展示网站其他地方可用的内容片段，那么只需展示一张照片或幻灯片就足够了。如果幻灯片是访问内容的唯一方式，那么您必须确保将内容提供给未启用 JavaScript 的用户。在本章的各个示例中，我们将看看这两种策略。

+   其次，您必须确定幻灯片中的所有项目是否大小相同还是大小不同。出于显而易见的原因，处理所有大小和宽高比相同的项目是最容易的，但有时对所有项目设置相同大小是不切实际或不可能的。随着我们的讨论，我将介绍哪些幻灯片适合相同大小的内容，哪些适合不同大小的内容。

+   接下来，您需要考虑您的网站访问者是否需要对幻灯片有任何控制。有时，只需让您的图像自动轮换很方便。其他时候，允许网站访问者暂停幻灯片，或手动向前和向后移动幻灯片会很有帮助。我会告诉您每种幻灯片方法为您的网站访问者提供了多少控制。

# 简单淡入淡出幻灯片

在本节中，您将学习如何构建一个简单的淡入淡出幻灯片。这种类型的幻灯片非常适合相同大小的图像，并且在禁用 JavaScript 时可以显示为单个图像。最后，这种类型的幻灯片不向您的网站访问者提供任何对幻灯片的控制。他们无法暂停幻灯片或手动浏览幻灯片。

# 行动时间 —— 创建一个简单的淡入淡出幻灯片

按照以下步骤创建一个简单的淡入淡出幻灯片：

1.  我们将开始创建一个基本的 HTML 文档以及与之关联的文件和文件夹，就像我们在第一章*设计师，见 jQuery*中所做的那样。在 HTML 文档的正文中，包括一系列图片。每个列表项将包含一张图片，可选择包装在链接中。以下是我的图片列表的示例：

    ```js
    <ul id="crossfade">
    <li>
    <a href="http://en.wikipedia.org/wiki/Agua_Azul"><img src="img/AguaAzul.jpg" alt="Agua Azul"/></a>
    </li>
    <li>
    <a href="http://en.wikipedia.org/wiki/Burney_Falls"><img src="img/BurneyFalls.jpg" alt="Burney Falls"/></a>
    </li>
    <li>
    <a href="http://en.wikipedia.org/wiki/Venezuala"><img src="img/Cachoeira_do_Pacheco.jpg" alt="Cachoeira do Pacheco"/></a>
    </li>
    </ul>

    ```

1.  接下来，我们将编写几行 CSS 来为幻灯片添加样式。幻灯片一次只显示一张图片，显示一张图片的最简单方法是将图片堆叠在一起。如果网站访问者禁用了 JavaScript，他们将只看到列表中的最后一张幻灯片：

    ```js
    #crossfade { position:relative;margin:0;padding:0;list-style-type:none;width:600px;height:400px;overflow:hidden; }
    #crossfade li { position:absolute;width:600px;height:400px; }

    ```

    如果您在浏览器中查看页面，您将看到幻灯片中的最后一项可见，但其他项都不可见—它们都叠放在最后一项下面。这就是禁用 JavaScript 的网站访问者的体验。

1.  接下来，打开 `scripts.js`，我们将开始编写我们的 JavaScript 代码。这个脚本将与我们以前设置的脚本有些不同。我们不再是在文档加载或网站访问者点击链接时发生一次性事件，而是实际上要设置一个在定时间隔上发生的函数。例如，如果我们希望幻灯片的每一张幻灯片可见三秒钟，我们将必须设置一个每三秒钟调用一次的切换幻灯片的函数。

    我们已经在页面上将幻灯片叠放在一起，并且最后一项在顶部。想想你如何处理一叠照片。您查看顶部的照片，然后将其移至堆栈底部以查看第二张照片。然后，您将第二张照片移至底部以查看第三张照片，依此类推。我们将同样的原理应用于我们的幻灯片。

    在 `scripts.js` 中，创建一个名为 `slideshow` 的函数。这是我们在想要切换照片时每三秒调用的函数。

    ```js
    function slideshow() {
    }

    ```

1.  在我们的函数内部，我们需要做的第一件事是选择堆栈中的第一张照片。

    ```js
    function slideshow() {
    $('#crossfade li:first')
    }

    ```

1.  现在我们已经有了堆叠中的第一张照片，我们只需要将它移到堆栈底部以使下一张照片可见。我们可以使用 jQuery 的 `appendTo()` 方法来实现。这将从列表开头删除第一张照片，并将其追加到列表末尾。

    ```js
    function slideshow() {
    $('#crossfade li:first').appendTo('#crossfade');
    }

    ```

1.  我们的翻转照片的函数已经准备好了。现在我们只需要在页面加载时进行一些初始设置。然后，我们将每三秒设置一次调用我们的翻转照片的函数。我们将在文档上调用 `ready()` 方法。

    ```js
    $(document).ready(function(){
    // Document setup code will go here
    });
    function slideshow() {
    $('#crossfade li:first').appendTo('#crossfade');
    }

    ```

1.  一旦我们的文档准备就绪，我们就要准备我们的幻灯片。我们将从选择幻灯片中的所有照片开始。

    ```js
    $(document).ready(function(){
    $('#crossfade li')
    });

    ```

1.  接下来，我们要隐藏幻灯片中的所有照片。

    ```js
    $(document).ready(function(){
    $('#crossfade li').hide();
    });

    ```

1.  然后，我们将过滤照片列表，只获取第一张。

    ```js
    $(document).ready(function(){
    $('#crossfade li').hide().filter(':first');
    });

    ```

1.  最后，我们将使第一张照片可见。所有其他照片将保持隐藏。

    ```js
    $(document).ready(function(){
    $('#crossfade li').hide().filter(':first').show();
    });

    ```

1.  刷新浏览器页面后，你会发现，如果没有启用 JavaScript，最后一个可见的幻灯片现在被隐藏了，而列表中的第一个幻灯片现在可见了。现在，剩下的事情就是每三秒调用我们的翻页函数。为此，我们将使用一个名为`setInterval()`的 JavaScript 方法。这允许我们以固定的时间间隔调用一个函数。我们向`setInterval`传递两个值：要调用的函数的名称以及应该在函数调用之间经过的毫秒数。例如，要每三秒（或 3000 毫秒）调用我的幻灯片函数，我会这样写：

    ```js
    $(document).ready(function(){
    $('#crossfade li').hide().filter(':first').show();
    setInterval(slideshow, 3000);
    });

    ```

1.  现在，我们每隔三秒调用一次我们的翻页函数，所以你期望如果你在浏览器中刷新页面，你会看到照片每三秒变化一次，但事实并非如此。回顾代码，很容易看出出了什么问题——尽管照片堆栈的实际顺序每三秒都在改变，但除了第一张照片之外，所有的照片都是不可见的。无论第一张照片是否在顶部，它都是唯一可见的照片，因此我们的幻灯片似乎没有变化。我们将不得不回到我们的`slideshow`函数，并修改它使当前照片不可见，并使堆栈中的下一张照片可见。由于我们希望照片以一个漂亮、缓慢的交叉淡入淡出效果切换，我们将调用`fadeOut()`方法将第一张照片淡出为透明，并且我们将向该方法传递`slow`以确保它花费足够的时间：

    ```js
    function slideshow() {
    $('#crossfade li:first').fadeOut('slow').appendTo('#crossfade');
    }

    ```

1.  现在，我们需要移动到列表中当前不可见的下一张照片，并使其不透明。我们将使用`next()`方法获取列表中的下一项，然后调用`fadeIn()`方法使其出现。再次，由于我们想要一个缓慢的效果，我们将`slow`传递给`fadeIn()`方法：

    ```js
    function slideshow() {
    $('#crossfade li:first').fadeOut('slow').next().fadeIn('slow').appendTo('#crossfade');
    }

    ```

1.  最后，我们的 jQuery 方法链有点麻烦。我们从堆栈中的第一张照片开始，淡出它，然后移到堆栈中的第二张照片，并淡入。然而，当我们调用`appendTo()`方法时，我们将第二张照片添加到末尾——我们将第二张照片移动到底部而不是第一张照片。幸运的是，jQuery 为我们提供了一个方法来返回到我们的原始选择——`end()`方法。我们可以在淡入第二张照片后调用`end()`方法，以确保将第一张照片附加到照片堆栈的底部：

    ```js
    function slideshow() {
    $('#crossfade li:first').fadeOut('slow').next().fadeIn('slow').end().appendTo('#crossfade');
    }

    ```

## 刚才发生了什么？

如果你在浏览器中刷新页面，你会看到一个漂亮的交叉淡入淡出的幻灯片。当一张照片淡出时，下一张照片就会淡入，平滑地在每张照片之间过渡。由于我们不断地将堆栈中的顶部照片移到底部，我们永远不会到达幻灯片的结尾，就像你可以不断地翻阅一叠照片一样。

我们设置了一个幻灯片功能，选择了堆栈中的第一张照片，淡出它，并将它移动到堆栈的底部。同时，我们正在找到堆栈中的第二张照片并将其淡入。我们使用了 jQuery 链接的强大功能，只需一行代码就可以完成所有操作。

我们设置了三秒的间隔，并在每个三秒的间隔结束时调用我们的照片翻转函数。

最后，我们在文档加载后做了一些设置工作 —— 隐藏所有照片，然后使第一张照片可见。这将确保照片始终按顺序显示在我们的幻灯片中。

接下来，让我们看看另一个具有一些花哨过渡效果的插件。

# Nivo Slider

在本节中，我们将看看如何充分利用来自 Dev 7 Studios 的 Nivo Slider 插件。Nivo Slider 提供了一些引人注目的照片之间的过渡效果，并提供了许多配置选项。Nivo Slider 非常适合尺寸完全相同的照片，并且很容易在 JavaScript 禁用的情况下显示单张照片以代替幻灯片。站点访问者可以手动向前和向后浏览幻灯片，并且当鼠标移动到幻灯片上时，幻灯片会暂停。

Nivo Slider 与本书中大多数我们将介绍的插件有些不同。该插件本身是根据 MIT 许可证开源的（[`nivo.dev7studios.com/license/`](http://nivo.dev7studios.com/license/)），可以免费下载和使用。此外，还有付费版本的插件供 WordPress 用户使用，包括支持、自动更新和在高级 WordPress 主题中包含插件的权限。我们在本节中创建的幻灯片使用的是该插件的免费开源版本。

# 采取行动的时间 —— 创建 Nivo Slider 幻灯片

按照以下步骤创建具有花哨过渡效果的图像幻灯片：

1.  我们将通过设置一个基本的 HTML 文件和相关文件和文件夹来开始，就像我们在第一章 *设计师，遇见 jQuery* 中所做的那样。在 HTML 文档的正文中，Nivo Slider 只需要一个容器`<div>`内的一组图像。

    如果我们希望幻灯片的每个幻灯片链接到另一个页面或网络位置，我们可以选择将每个图像包装在链接中，但这并不是必需的。Nivo 也可以正常使用未链接的图像。`<img>` 标签的 `title` 属性用于显示幻灯片的标题。

    ```js
    <div id="slideshow">
    <a href="http://en.wikipedia.org/wiki/Agua_Azul"><img src="img/AguaAzul.jpg" alt="Agua Azul" title="Agua Azul, Mexico"/></a>
    <a href="http://en.wikipedia.org/wiki/Burney_Falls"><img src="img/BurneyFalls.jpg" alt="Burney Falls" title="Burney Falls, California, USA"/></a>
    <a href="http://en.wikipedia.org/wiki/Venezuala"><img src="img/Cachoeira_do_Pacheco.jpg" alt="Cachoeira do Pacheco" title="Cachoeira do Pacheco, Venezuela"/></a>
    <a href="http://en.wikipedia.org/wiki/Deer_Leap_Falls"><img src="img/Deer_Leap_Falls.jpg" alt="Deer Leap Falls" title="Deer Leap Falls, Pennsylvania, USA"/></a>
    <a href="http://en.wikipedia.org/wiki/Fulmer_Falls"><img src="img/Fulmer_Falls.jpg" alt="Fulmer Falls" title="Fulmer Falls, Pennsylvania, USA"/></a>
    <a href="http://en.wikipedia.org/wiki/Hopetoun_Falls"><img src="img/Hopetoun_Falls.jpg" alt="Hopetoun Falls" title="Hopetoun Falls, Victoria, Australia"/></a>
    <a href="http://en.wikipedia.org/wiki/Ohiopyle_State_Park"><img src="img/Jonathans_Run.jpg" alt="Jonathan's Run" title="Jonathan's Run, Pennsylvania, USA"/></a>
    <a href="http://en.wikipedia.org/wiki/Kjosfossen"><img src="img/Kjosfossen.jpg" alt="Kjosfossen" title="Kjosfossen, Norway"/></a>
    <a href="http://en.wikipedia.org/wiki/Krimml_Waterfalls"><img src="img/KrimmlFalls.jpg" alt="Krimml Falls" title="Krimml Falls, Salzburgerland, Austria"/></a>
    <a href="http://en.wikipedia.org/wiki/Madhabkunda"><img src="img/Madhabkunda_Falls.jpg" alt="Madhabkunda Falls" title="Madhabkunda Falls, Bangladesh"/></a>
    <a href="http://en.wikipedia.org/wiki/Manavgat_Waterfall"><img src="img/Manavgat.jpg" alt="Manavgat Waterfall" title="Manavgat Waterfall, Turkey"/></a>
    <a href="http://en.wikipedia.org/wiki/Niagra_Falls"><img src="img/Niagara_Falls.jpg" alt="Niagara Falls" title="Niagara Falls, USA and Canada"/></a>
    <a href="http://en.wikipedia.org/wiki/British_Columbia"><img src="img/Nymph_Falls.jpg" alt="Nymph Falls" title="Nymph Falls, British Columbia, Canada"/></a>
    </div>

    ```

1.  接下来，我们将添加一些 CSS，将图像堆叠在一起，并为我们的幻灯片设置固定的宽度和高度：

    ```js
    #slideshow { position:relative;width:600px;height:400px; }
    #slideshow img { position:absolute;top:0;left:0; }

    ```

1.  现在，前往[`nivo.dev7studios.com/pricing/`](http://nivo.dev7studios.com/pricing/)下载 Nivo Slider 插件。在标记为**jQuery plugin**的左框中，你会找到**Download**链接。![采取行动的时间 —— 创建 Nivo Slider 幻灯片](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_09_img2.jpg)

    点击**Download**链接，将 zip 文件保存到您的计算机上。

1.  解压文件夹并查看其内容。![执行操作的时间 — 创建 Nivo Slider 幻灯片播放](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_09_img3.jpg)

    有一个包含示例 HTML 文件以及图像、脚本和样式的**演示**文件夹。插件有两个版本 —— 源版本和打包压缩版本。还有一个许可证的副本，比你期望的要短和简单，所以请随意查看。有一个 CSS 文件，然后有一个包含三个其他文件夹的**主题**文件夹：**default, orman** 和 **pascal**。这是插件附带的三个示例主题。你可以选择其中一个示例主题，创建你自己的主题，或者修改其中一个示例主题以适应你的口味。

1.  让我们将必要的文件复制并准备好使用。首先，将`nivo-slider.css`复制到你自己的`styles`文件夹中。选择一个主题并将整个文件夹复制到你自己的`styles`文件夹中。然后将`jquery.nivo.slider.pack.js`复制到你自己的`scripts`文件夹中，与 jQuery 放在一起。你的设置应该像下面的图片一样：![执行操作的时间 — 创建 Nivo Slider 幻灯片播放](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_09_img4.jpg)

1.  接下来，我们将设置我们的 HTML 文件以使用 Nivo Slider。在文档的`<head>`部分，包含选定主题的`nivo-slider.css`文件以及你的`styles.css`文件之前：

    ```js
    <head>
    <title>Chapter 9: Creating Slideshows</title>
    <link rel="stylesheet" href="styles/nivo-slider.css"/>
    <link rel="stylesheet" href="styles/default/default.css"/>
    <link rel="stylehseet" href="styles/styles.css"/>
    </head>

    ```

1.  在 HTML 文档底部，紧挨着闭合的`</body>`标签下方，插入`<script>`标签以引入 Nivo Slider 插件，位置在 jQuery 和你的`scripts.js`文件之间：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/jquery.nivo.slider.pack.js"></script>
    <script src="img/scripts.js"></script>
    </body>

    ```

1.  打开`scripts.js`并在文档上调用`ready()`方法，这样我们的幻灯片将在页面在浏览器窗口加载时立即开始：

    ```js
    $(document).ready(function(){
    //Nivo Slider code will go here
    });

    ```

1.  接下来，我们将选择幻灯片放置的容器元素：

    ```js
    $(document).ready(function(){
    $('#slideshow');
    });

    ```

1.  最后，我们将调用`nivoSlider()`方法：

    ```js
    $(document).ready(function(){
    $('#slideshow').nivoSlider();
    });

    ```

    现在，如果你在浏览器中查看页面，你会看到我们的幻灯片已经创建了。过渡效果的默认设置是对每个过渡使用不同的随机效果，所以如果你观看一段时间，你会对 Nivo Slider 包含的不同类型的过渡效果有一个很好的了解。

    你还会注意到我们作为每个图像的`title`属性包含的值被显示为每个图像的标题。

1.  现在让我们利用 Nivo Slider 插件提供的一些自定义选项。我们选项的文档可以在[`nivo.dev7studios.com/support/jquery-plugin-usage/`](http://nivo.dev7studios.com/support/jquery-plugin-usage/)找到。

    在文档页面底部，你会找到可用过渡效果的列表。我个人最喜欢的过渡效果叫做 boxRain。让我们设置它成为唯一使用的过渡效果。我们将通过在一对花括号内传递一组键/值对给`nivoSlider()`方法来自定义 Nivo Slider 插件：

    ```js
    $(document).ready(function(){
    $('#slideshow').nivoSlider({
    effect: 'boxRain'
    });
    });

    ```

1.  我们可以指定盒子动画应包含的行数和列数。 默认情况下，有八列和四行，但让我们增加一下，以便 `boxRain` 过渡使用更多（更小的）盒子：

    ```js
    $(document).ready(function(){
    $('#slideshow').nivoSlider({
    effect: 'boxRain',
    boxCols: 10,
    boxRows: 5
    });
    });

    ```

1.  我们还可以自定义动画速度和每张幻灯片显示的时间：

    ```js
    $(document).ready(function(){
    $('#slideshow').nivoSlider({
    effect: 'boxRain',
    boxCols: 10,
    boxRows: 5,
    animSpeed: 800,
    pauseTime: 4000
    });
    });

    ```

    我将 `animSpeed` 设置为 800 毫秒，以便 `boxRain` 过渡效果需要 800 毫秒才能完成。 我还将 `pauseTime` 设置为 4000，因此幻灯片中的每个图像都可见 4000 毫秒或四秒。

## 刚才发生了什么事？

我们设置了 Nivo Slider 插件，展示了具有令人印象深刻的过渡效果的幻灯片。 我们学会了如何适当设置 HTML 文档，如何调用 `nivoSlider()` 方法以及如何自定义一些幻灯片设置。

## 尝试一下吧——自定义幻灯片

除了我们使用的自定义选项之外，幻灯片还提供了几种其他配置选项，包括显示或隐藏上/下一页按钮的能力，设置分页显示或是否显示以及用于编写幻灯片的自定义功能的大量回调函数。 除此之外，您还可以完全自定义用于创建幻灯片的 CSS 和图像，使其看起来任何你想要的样子。

尝试着自定义一个幻灯片，以匹配任何你想要的设计，并尝试使用 Nivo Slider 提供的其他自定义选项。 创建自己设计的自定义幻灯片。

接下来，我们将看看如何创建缩略图照片画廊。

# Galleriffic 幻灯片

Trent Foley 的 Galleriffic 幻灯片允许您将完整尺寸照片的链接列表转换为照片幻灯片。 这种方法与我们迄今为止看到的其他画廊有些不同，那里的重点是将完整尺寸的照片插入文档，然后将它们动画成幻灯片。 相反，Galleriffic 将一个完整尺寸照片的链接列表转换为幻灯片。 这些链接作为浏览幻灯片的一种方式保留在页面上。

Galleriffic 幻灯片可以与大小和纵横比略有不同的照片集合一起使用，但如果不同照片之间的差异太大，那么设置 CSS 来优雅地处理幻灯片将是一个挑战。 Galleriffic 幻灯片使您的站点访问者可以手动导航到幻灯片中的任何照片，并为幻灯片提供了下一张、上一张和播放/暂停按钮。 对于禁用 JavaScript 的站点访问者，将提供一系列链接，这些链接将链接到照片的全尺寸版本。

我们还将探讨一种简单的技术，您可以根据 JavaScript 是否启用来应用不同的 CSS 到页面上。当访问者在没有启用 JavaScript 的情况下访问您的网站时，这种技术可以应用在各种情况下，为您提供对内容呈现方式的更多控制。

# 行动时间——创建一个 Galleriffic 幻灯片秀

按照以下步骤使用 Galleriffic 插件创建幻灯片秀：

1.  首先，我们将额外努力规划幻灯片秀将如何在启用和未启用 JavaScript 的网站访问者中出现。如果网站访问者没有 JavaScript，我们将向他们展示一个缩略图网格，并在下方显示标题。单击缩略图将向他们显示照片的全尺寸版本。

    页面将看起来像以下屏幕截图：

    ![行动时间——创建一个 Galleriffic 幻灯片秀](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_09_img5.jpg)

    对于使用 JavaScript 的用户，我想在主幻灯片区域旁边显示一个较小的缩略图网格，如下面的屏幕截图所示：

    ![行动时间——创建一个 Galleriffic 幻灯片秀](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_09_img6.jpg)

    缩略图的情况下，标题不重要，因为它们将显示在幻灯片秀下方，而不是图片下方。

1.  在考虑我们希望页面的外观时，我们将开始设置一个 HTML 文件和相关文件和文件夹，就像我们在第一章中所做的那样，*设计师，遇见 jQuery*。为每张照片创建一个 100x100 的缩略图，并将它们存储在您的`images`文件夹内的一个`thumbs`文件夹中。我们将使用这些缩略图在 HTML 文档的正文中创建一个到全尺寸照片的链接列表。

    ```js
    <ul class="thumbs">
    <li>
    <a class="thumb" title="Agua Azul, Mexico" href="images/600/AguaAzul.jpg"><img src="img/AguaAzul.png" alt="Agua Azul"/></a>
    <div class="caption">Agua Azul, Mexico</div>
    </li>
    <li>
    <a class="thumb" title="Burney Falls, California, USA" href="images/600/BurneyFalls.jpg"><img src="img/BurneyFalls.png" alt="Burney Falls"/></a>
    <div class="caption">Burney Falls, California, USA</div>
    </li>
    <li>
    <a class="thumb" title="Cachoeira do Pacheco, Venezuela" href="images/600/Cachoeira_do_Pacheco.jpg"><img src="img/Cachoeira_do_Pacheco.png" alt="Cachoeira do Pacheco"/></a>
    <div class="caption">Cachoeira do Pacheco, Venezuela</div>
    </li>
    <li>
    <a class="thumb" title="Deer Leap Falls, Pennsylvania, USA" href="images/600/Deer_Leap_Falls.jpg"><img src="img/Deer_Leap_Falls.png" alt="Deer Leap Falls"/></a>
    <div class="caption">Deer Leap Falls, Pennsylvania, USA</div>
    </li>
    </ul>

    ```

    ### 注意

    我们在每个链接上都包含了一个`title`属性，以确保当鼠标悬停在每个缩略图上时会显示一个工具提示，其中包含此照片的简短描述。我还在每个图像标签上包含了一个`alt`属性，以便无法看到图像的任何原因的网站访问者仍然可以访问该图像的描述。

    在每个`<li>`内部，我还包括了一个`<div>`，带有类名为`caption`，其中包含将显示在缩略图下方或幻灯片秀中图片下方的标题。

    这是足够为非 JavaScript 版本的幻灯片秀设置 HTML 的，但是 Galleriffic 插件需要页面上更多的元素。

1.  我们需要像以下这样，用一个带有`id`为`thumbs`的`<div>`来包裹我们的图片列表：

    ```js
    <div id="thumbs">
    <ul class="thumbs">
    <li>
    ...
    </li>
    </ul>
    </div>

    ```

1.  我们还需要在页面中添加一些空元素，用来容纳我们的幻灯片秀、幻灯片说明和幻灯片控件。

    ```js
    <div id="thumbs">...</div>
    <div id="gallery">
    <div id="controls"></div>
    <div id="slideshow-container">
    <div id="loading"></div>
    <div id="slideshow"></div>
    </div>
    <div id="caption"></div>
    </div>

    ```

    这些元素在页面上的确切位置由您决定——您可以创建任何您喜欢的布局，并将幻灯片秀的各个部分放在您喜欢的页面上的任何位置。出于可用性考虑，当然，这些元素应该相对靠近一起。

    请注意，除了包含缩略图列表的 thumbs `div`外，我们添加到页面的其他元素都是空的。这些元素只会在访问者启用 JavaScript 时使用，并且它们内部的所有内容都将由 Galleriffic 插件自动生成。这将使它们在不使用时保持不可见。

1.  现在，打开你的 HTML 文件，找到开头的`<body>`标签，添加一个`class`为`jsOff`。

    ```js
    <body class="jsOff">

    ```

1.  接下来，我们将为缩略图设置 CSS 样式。打开你的`styles.css`文件并添加这些样式：

    ```js
    .thumbs { margin:0;padding:0;line-height:normal; }
    .thumbs li { display:inline-block;vertical-align:top; padding:0;list-style-type:none;margin:0; }
    .jsOff .thumbs li { width:100px;margin-bottom:5px;background:#fff; border:5px solid #fff;box-shadow:1px 1px 2px rgba(0,0,0,0.1) }
    .jsOff .caption { min-height:52px;font-size:12px; line-height:14px; }
    .jsOff #gallery { display:none; }

    ```

    CSS 在这里有两个部分。以`.thumbs`开头的选择器将应用于缩略图，无论访问者是否启用 JavaScript。以`.jsOff`开头的选择器将仅应用于没有启用 JavaScript 的访问者。这段 CSS 会创建带有标题的缩略图网格。

    我们还选择了幻灯片放映的父容器，并设置为对于没有 JavaScript 的访问者根本不显示。由于这是一组空的`<div>`，它们不应该占用页面上的任何空间，但这是为了确保这些额外的元素不会对没有 JavaScript 的访问者造成任何问题的额外保证。

    该页面的非 JavaScript 版本已经完成。

1.  接下来，我们将为启用 JavaScript 的用户设置页面。我们将开始打开`scripts.js`文件并插入我们的文档就续语句：

    ```js
    $(document).ready(function(){
    // This code will run as soon as the page loads
    });

    ```

1.  接下来，我们将编写一些代码，将`jsOff`类从`body`中删除并替换为`jsOn`类。

    ```js
    $(document).ready(function(){
    $('body').removeClass('jsOff').addClass('jsOn');
    });

    ```

    如果站点访问者启用了 JavaScript，`jsOff`类将从`body`中移除，替换为`jsOn`类。

1.  现在，我们可以编写一些 CSS，应用于对于已启用 JavaScript 的站点访问者的缩略图列表。打开你的`styles.css`文件并添加这些样式：

    ```js
    .jsOn .thumbs { width:288px; }
    .jsOn .thumbs li { width:86px; }
    .jsOn .thumbs img { border:3px solid #fff;max-width:80px;opacity:0.6; }
    .jsOn #thumbs { float:left; }

    ```

    这个 CSS 只会应用于启用 JavaScript 的访问者，因为只有在 JavaScript 可用来工作时，`jsOn`类才能应用于`<body>`。

1.  现在，我们将编写一些样式来控制幻灯片的各个部分，包括控件、标题和幻灯片区域本身：

    ```js
    #gallery { float:left;width:600px;position:relative;background:#fff;padding:10px;margin-bottom:20px;line-height:18px; }
    .ss-controls { text-align:right;float:right;width:40%; }
    .nav-controls { float:left:width:40%; }
    #controls a { font-size:14px;color:#002B36;background:100% 0px no-repeat url(images/controls/sprite.png);padding-right:18px; }
    #controls a.pause { background-position: 100% -18px; }
    #controls a.prev { background-position: 0 -36px;padding-right:0;padding-left:18px;margin-right:10px; }
    #controls a.next { background-position: 100% -54px; }
    .caption { font-size:24px;padding:5px 0; }
    .thumbs li.selected img { border-color:#000;opacity:1; }

    ```

    我已经创建了一个小精灵，其中包含**播放、暂停、上一个**和**下一个**的图像，我将应用到这些控件上。

1.  现在，既然我们已经准备好创建一个令人惊叹的幻灯片放映，我们只需要我们的插件代码。前往 [`www.twospy.com/galleriffic/`](http://www.twospy.com/galleriffic/)，在那里你会找到 Galleriffic 插件的文档和下载。你需要向下滚动页面几乎到底部才能找到**下载**部分。![行动时间 — 创建 Galleriffic 幻灯片](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_09_img7.jpg)

    您会注意到下载有两个选项——您可以获取包含一些示例的 ZIP 文件，也可以仅获取插件代码本身。由于我们已经知道我们想要的幻灯片样式，我们将仅获取插件代码。单击链接将在浏览器窗口中打开代码本身。右键单击或从浏览器菜单中选择 **文件 | 另存为** 将文件保存到您自己的 `scripts` 文件夹中。

1.  现在我们已经获得了插件，我们想将它包含在我们的 HTML 页面中。转到您 HTML 页面的底部，并将 Galleriffic 插件插入在 jQuery 和您的 `scripts.js` 文件之间：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/jquery.galleriffic.js"></script>
    <script src="img/scripts.js">
    </script>

    ```

1.  接下来，我们将打开 `scripts.js` 并选择包装我们的缩略图列表的容器，并在我们改变 body 类的代码行后调用 `galleriffic()` 方法：

    ```js
    $('body').removeClass('jsOff').addClass('jsOn');
    $('#thumbs').galleriffic();

    ```

1.  但是，如果您在浏览器中查看页面，您会发现幻灯片不起作用。这是因为 Galleriffic 插件需要一些配置才能运行。我们将在花括号内传递一组键/值对给 `galleriffic()` 方法，以便我们的幻灯片运行。我们基本上必须告诉插件在哪里显示我们的幻灯片、控件和标题。

    ```js
    $('#thumbs').galleriffic({
    imageContainerSel: '#slideshow',
    controlsContainerSel: '#controls',
    captionContainerSel: '#caption',
    loadingContainerSel: '#loading',
    autoStart: true
    });

    ```

    具有 `id` 为 `slideshow` 的 `<div>` 是我们将显示全尺寸图像的位置。控件将显示在具有 `id` 为 controls 的 `div` 中。 `<div id="caption">` 将显示标题，而我们创建的具有 `id` 为 `loading` 的 `div` 将在幻灯片初始化时显示加载动画。我还将 `autoStart` 设置为 `true`，这样幻灯片就会自动播放。

    现在，如果您在浏览器中刷新页面，您将看到幻灯片正在运行。**下一页** 和 **上一页** 按钮允许您翻转，并且 **播放/暂停** 按钮使您可以控制幻灯片。

## 发生了什么？

我们设置了我们的页面以显示为禁用 JavaScript 的站点访客优化的图像缩略图。然后，我们使用了一行 JavaScript 代码来更改 body 类，以便我们可以为启用 JavaScript 的站点访客应用不同的样式。我们设置了 CSS 来显示我们的幻灯片，并调用了 `galleriffic()` 方法来动画显示幻灯片。站点访客可以手动在照片之间前后移动，可以单击缩略图将相应的全尺寸照片加载到幻灯片区域，并可以在任何时候暂停幻灯片。

# CrossSlide 插件

CrossSlide 插件，由 Tobia Conforto 制作，使得不仅可以淡入淡出图像，还可以动画平移和缩放图像成为可能。如果您有各种不同尺寸的图像，则此插件非常理想。为了获得最佳效果，唯一的要求是所有图像至少与幻灯片查看区域一样大。大于幻灯片查看区域的图像将被裁剪。例如，如果幻灯片宽度为 600 像素，高度为 400 像素，那么幻灯片中使用的所有图像的宽度和高度都应至少为 600 像素和 400 像素。

当 JavaScript 被禁用时，CrossSlide 插件将显示你放入幻灯片的任何内容作为占位符。这可以是一个单独的图像，或者是一个图像加上文本，或者任何你想要的其他类型的 HTML 内容。页面加载时，插件将删除此占位符内容，并用幻灯片替换它。

可以提供按钮，让网站访问者停止和重新启动幻灯片播放。但是，访问者不能手动切换到各个幻灯片。

在我们深入了解之前，我想提醒一下，与我们之前见过的一些插件相比，你会发现 CrossSlide 插件的设计不太友好。一个平移和缩放幻灯片是一个复杂的任务，而该插件只能做到让这种复杂性减轻一些。话虽如此，我相信如果你花点时间并稍微耐心一些，你就能搞清楚。

# 行动时间 —— 构建 CrossSlide 幻灯片

按照以下步骤设置 CrossSlide 幻灯片：

1.  要开始，我们将设置一个简单的 HTML 文档和关联的文件和文件夹，就像我们在第一章中所做的那样，*设计师，见 jQuery*。HTML 文档的主体将包含幻灯片的容器。在容器内，放置任何您希望为禁用 JavaScript 的用户显示的内容。

    ```js
    <div id="slideshow">
    <img src="img/AguaAzul.jpg" alt="Agua Azul"/>
    </div>

    ```

    我将简单地为禁用 JavaScript 的用户显示幻灯片中的第一张照片。我给我的容器 `<div>` 加上了 `id` 为 `slideshow`。

1.  打开 `styles.css` 并添加一些 CSS 来定义幻灯片的宽度和高度：

    ```js
    #slideshow { width:600px;height:400px; }

    ```

1.  接下来，前往 [`tobia.github.com/CrossSlide/`](http://tobia.github.com/CrossSlide/) 获取 CrossSlide 插件的下载和文档。![行动时间 —— 构建 CrossSlide 幻灯片](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_09_img1.jpg)

    你会在页面顶部附近找到**下载缩小版**链接。页面的其余部分展示了 CrossSlide 插件在几个示例中的应用。浏览一下这些示例。你会发现它可以做从与本章第一节中构建的简单交叉淡入淡出幻灯片类似的事情，到完全动态的平移和缩放幻灯片的所有事情。

    现在你已经看了一些你可以使用 CrossSlide 插件创建的幻灯片类型，接下来有几件事情需要记住：

    +   首先，由于某些浏览器（即，Internet Explorer）的渲染限制，对照片进行缩放可能会影响照片显示的质量。插件的作者建议将缩放因子保持在 1 或以下，以最小化此效果。

    +   第二，因为浏览器限制为呈现完整像素，所以平移和缩放动画效果可能不太流畅，特别是对于对角线动画。您可以通过减少或避免对角线动画或选择相对较高的动画速度来减少 1 像素跳跃效果，从而使它们看起来更流畅。

    +   最后，动画可能会占用一些 CPU 资源，特别是当同时使用了平移、缩放和交叉淡化动画，就像我们在这个例子中所做的那样。这并不会使大多数新电脑遇到问题，但是根据你的网站受众，你可能希望避免同时使用所有可能的动画效果。在本教程的结尾，我将向你展示如何避免幻灯片最消耗 CPU 资源的部分，如果它在你自己或你的网站访问者的电脑上造成了问题的话。

1.  当你点击**下载压缩版**链接时，插件脚本本身将在浏览器窗口中打开，就像 jQuery 本身一样。只需右键单击页面或从浏览器的菜单栏选择**文件 | 另存为**，将文件保存到你自己的计算机上。保留文件名`jquery.cross-slide.min.js`，并将文件保存在你的`scripts`文件夹中。

1.  接下来，我们只需要在我们的 HTML 页面底部包含 CrossSlide 插件文件，放在 jQuery 和`scripts.js`之间：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/jquery.cross-slide.min.js"></script>
    <script src="img/scripts.js"></script>
    </body>
    </html>

    ```

1.  接下来，打开你的`scripts.js`文件，我们将通过选择我们的幻灯片容器并调用`crossSlide()`方法来开始使用 CrossSlide 插件：

    ```js
    var slideshow = $('#slideshow');
    slideshow.crossSlide();

    ```

    请记住，变量只是某物的容器。在这种情况下，我们选择了幻灯片容器并将其放在一个名为`slideshow`的变量中。我们这样做是因为我们将在脚本中多次引用这个容器。通过将幻灯片容器保存在一个变量中，我们可以防止 jQuery 每次想要引用它时都需要查询 DOM，使我们的代码更加高效。

1.  此时，如果在浏览器中加载页面，你会发现调用`crossSlide()`方法似乎对我们的页面没有产生任何效果。你仍然会在我们的幻灯片容器内看到占位内容，而且没有幻灯片播放。这是因为我们不仅需要向`crossSlide()`方法传递设置，还需要传递我们想在幻灯片中显示的照片列表。在`crossSlide()`方法的括号内，插入一对花括号，我们将传递一个键值对来配置图片之间淡入淡出的时间长度，单位为秒：

    ```js
    var slideshow = $('#slideshow');
    slideshow.crossSlide({
    fade: 1
    });

    ```

    ### 注意

    请注意，我们使用的时间长度单位是秒，而不是毫秒。CrossSlide 插件设置为期望秒作为时间单位，而不是我们通常在 JavaScript 中找到的毫秒。

1.  接下来，在我们的配置设置之后，我们想要将一组照片传递给`crossSlide()`方法。一个数组被放在方括号中：

    ```js
    slideshow.crossSlide({
    fade: 1
    }, [
    //Our list of photos will go here.
    ]
    );

    ```

1.  每张照片都将有自己的一组描述图片 URL、标题等的键值对。每张照片都将包含在自己的一组花括号中。我们将从图片的 URL 开始，该 URL 由`src`键描述：

    ```js
    slideshow.crossSlide({
    fade: 1
    }, [
    {
    src: 'images/1000/AguaAzul.jpg'
    }
    ]
    );

    ```

1.  接下来，我们将另一个键值对作为照片的标题：

    ```js
    slideshow.crossSlide({
    fade: 1
    }, [
    {
    src: 'images/1000/AguaAzul.jpg',
    alt: 'Agua Azul, Mexico'
    }
    ]
    );

    ```

1.  现在，我们需要添加两个键/值对来描述平移和缩放动画的起点和终点。假设我们要从左上角平移到右下角，同时放大这张照片。这里是我们将传递给 `from` 和 `to` 键的值：

    ```js
    slideshow.crossSlide({
    fade: 1
    }, [
    {
    src: 'images/1000/AguaAzul.jpg',
    alt: 'Agua Azul, Mexico',
    from: 'top left 1x',
    to: 'bottom right .8x'
    }
    ]
    );

    ```

1.  最后，我们要指定动画持续的时间，以秒为单位。我将展示这张照片动画四秒钟：

    ```js
    slideshow.crossSlide({
    fade: 1
    }, [
    {
    src: 'images/1000/AguaAzul.jpg',
    alt: 'Agua Azul, Mexico',
    from: 'top left 1x',
    to: 'bottom right .8x',
    time: 4
    }
    ]
    );

    ```

1.  这是我们幻灯片的一张照片。要添加更多照片，只需在花括号内添加另一组键/值对。不要忘记用逗号将每张照片与前一张照片分隔开。请记住不要在列表中的最后一张照片后面放逗号。这是我添加了另外三张照片的示例：

    ```js
    slideshow.crossSlide({
    fade: 1
    }, [
    {
    src: 'images/1000/AguaAzul.jpg',
    alt: 'Agua Azul, Mexico',
    from: 'top left 1x',
    to: 'bottom right .8x',
    time: 4
    },
    {
    src: 'images/1000/BurneyFalls.jpg',
    alt: 'Burney Falls, California, USA',
    from: 'top left 1.2x',
    to: 'bottom right .8x',
    time: 5
    },
    {
    src: 'images/1000/Cachoeira_do_Pacheco.jpg',
    alt: 'Cachoeira do Pacheco, Venezuela',
    from: '50% 0% 1.2x',
    to: '50% 60% .6x',
    time: 4
    },
    {
    src: 'images/1000/Deer_Leap_Falls.jpg',
    alt: 'Deer Leep Falls, Pennsylvania, USA',
    from: '50% 50% 1.2x',
    to: '50% 100% .8x',
    time: 3
    }
    ]
    );

    ```

    ### 注意

    请注意，我可以选择每张照片显示的时间长度——如果我愿意，可以让一张特别惊艳的照片在页面上停留更长时间，或者更快地将较小或不太有趣的照片移出页面。

    现在，如果您在浏览器中刷新页面，您将看到您的照片的平移和缩放幻灯片放映。我们离成功越来越近了！

1.  接下来，我们将使用我们传递给 `crossSlide()` 方法的标题值为每张照片创建标题。首先，我要回到我的 HTML 标记并添加一个容器用于标题。您可以使用 CSS 自定义此容器的样式：

    ```js
    <div id="slideshow">
    <img src="img/AguaAzul.jpg" alt="Agua Azul"/>
    </div>
    <div class="caption"></div>

    ```

    请记住，您的标题容器必须出现在幻灯片放映容器的外部。如果您将其放在内部，当 CrossSlide 插件用幻灯片放映替换幻灯片放映容器的内容时，它将被移除。

    现在，我们有了一个显示标题的地方，所以我们只需要一种方法将我们的标题放入该容器中。`crossSlide()` 方法将接受一个回调方法以及我们的设置和图像数组。每次图像开始淡出到下一张图像时，都会调用此回调函数，并在淡出完成后再次调用。

    ```js

    slideshow.crossSlide({
    fade: 1
    }, [
    {
    src: 'images/1000/AguaAzul.jpg',
    alt: 'Agua Azul, Mexico',
    from: 'top left 1x',
    to: 'bottom right .8x',
    time: 4
    },
    {
    src: 'images/1000/BurneyFalls.jpg',
    alt: 'Burney Falls, California, USA',
    from: 'top left 1.2x',
    to: 'bottom right .8x',
    time: 4
    },
    {
    src: 'images/1000/Cachoeira_do_Pacheco.jpg',
    alt: 'Cachoeira do Pacheco, Venezuela',
    from: '50% 0% 1.2x',
    to: '50% 60% .6x',
    time: 4
    },
    {
    src: 'images/1000/Deer_Leap_Falls.jpg',
    alt: 'Deer Leep Falls, Pennsylvania, USA',
    from: '50% 50% 1.2x',
    to: '50% 100% .8x',
    time: 3
    }
    ], function(index, img, indexOut, imgOut) {
    //our callback function goes here
    }
    );

    ```

    我们的回调函数传递了四个可能的值：当前图像的索引，当前图像本身，前一图像的索引和前一图像本身。图像的索引只是它在幻灯片中按编号的位置。JavaScript，像其他编程语言一样，从 0 开始计数而不是 1。因此，幻灯片中第一张图像的索引是 0，第二张图像的索引是 1，依此类推。

    记得我说过回调函数在交叉淡入淡出开始时调用一次，然后在交叉淡入淡出完成后再次调用吗？如果交叉淡入淡出正在开始，回调函数将获取所有四个值——当前图像的索引和当前图像，以及前一图像的索引和前一图像。如果交叉淡入淡出已经完成，我们将只得到两个值：当前图像的索引和当前图像本身。

1.  我们将检查交叉淡入淡出是开始还是结束。如果交叉淡入淡出已经结束，那么我们将想要显示新照片的标题。如果交叉淡入淡出刚刚开始，那么我们将隐藏很快就会成为上一张图片的标题：

    ```js
    ], function(index, img, indexOut, imgOut) {
    var caption = $('div.caption');
    if (indexOut == undefined) {
    caption.text(img.alt).fadeIn();
    } else {
    caption.fadeOut();
    }
    }

    ```

    如果交叉淡入淡出完成，那么`indexOut`将是`undefined`，因为不会有一个变量的值传递给回调函数。很容易检查该值是否未定义，以判断交叉淡入淡出动画是开始还是结束。然后，我们使用 jQuery 的`text()`方法将标题的文本设置为我们在每张图片中包含的`alt`值，并将标题渐入。另一方面，如果交叉淡入淡出动画刚开始，我们将只是将标题渐出。

    现在，如果你在浏览器中刷新页面，你会看到每张照片的标题渐隐渐现，随着交叉淡入淡出的开始。这是从一个标题平滑过渡到下一个的美好过渡。

1.  这最后一步是可选的。如果你发现 CrossSlide 插件在我们在这个例子中设置的所有动画同时运行时，对你的计算机或你网站访问者的计算机的 CPU 负荷太大，有一个简单的配置选项可以让你跳过幻灯片最消耗 CPU 的部分 —— 即，当两张照片在平移和缩放时交叉淡入淡出。你只需将另一个键值对传递给配置选项，将`variant`设置为`true:`

    ```js
    slideshow.crossSlide({
    fade: 1,
    variant: true
    }, [
    {
    src: 'images/1000/AguaAzul.jpg',
    ...

    ```

    这将改变你的幻灯片，使每张照片在开始交叉淡入淡出到下一张照片之前完成平移和缩放。

## 刚刚发生了什么？

如果你的头有点晕，不用担心 —— CrossSlide 插件绝对是我们迄今为止使用过的最专业的插件。虽然这个插件不是特别友好于设计师，但我希望你能看到，即使是这种类型的插件也在你的掌握范围内，只要你有点耐心并愿意多尝试一些。仔细研究代码示例将会让你有所收获。

我们设置了一个容器，用于保存我们的静态内容，以供 JavaScript 禁用的用户使用。然后，我们设置了 CrossSlide 插件，将该内容替换为动态的平移和缩放幻灯片，供启用 JavaScript 的用户使用。我们将交叉淡入淡出的时间设置为 1 秒，然后传入了我们的图片数组，包括 URL、标题、动画起点、动画终点和每张图片的持续时间。最后，我们利用了 CrossSlide 插件提供的回调函数，让每张照片的标题渐入，并在照片本身开始淡出时将其渐出。我们还看了如何使幻灯片在可能引起问题的情况下更少地消耗 CPU。

# 概要

我们看了四种不同的用 jQuery 构建图片幻灯片的方法。我们从零开始建立了一个简单的交叉淡入淡出的幻灯片，没有使用插件。我们使用 Nivo Slider 插件探索了花式的过渡效果。然后我们学习了如何使用 Galleriffic 插件设置缩略图幻灯片。最后，我们看了如何使用 CrossSlide 插件构建一个平移和缩放的幻灯片。

接下来，我们将看看如何为您网站上的各种内容构建滑块和走马灯。
