# 面向设计师的 jQuery 入门指南（三）

> 原文：[`zh.annas-archive.org/md5/FFDF3B70B19F674D777B2A63156A89D7`](https://zh.annas-archive.org/md5/FFDF3B70B19F674D777B2A63156A89D7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：在走廊和幻灯片中显示内容

> 除了幻灯片秀，我们还可以在滑块和走马灯中展示图像和文本。一次可以显示一个或多个幻灯片，并使用滑动动画在幻灯片之间进行转换。走马灯非常适合创建特色内容滑块或在较小空间内提供许多图像。我们将查看 Jan Sorgalla 的灵活和可定制的 jCarousel 插件以及如何使用它创建几种不同类型的走马灯和滑块解决方案。

在本章中，我们将学习以下主题：

+   使用 jCarousel 插件创建基本的水平滑块

+   创建垂直新闻滚动条

+   创建具有外部控件的特色内容滑块

+   将幻灯片秀与缩略图走马灯相结合

# 基本 jCarousel

让我们首先看看如何创建基本的水平图像缩略图走马灯。jCarousel 插件包括两种不同的皮肤，因此设置基本的走马灯非常快速和简单。

以下截图是使用该插件附带的 tango 皮肤创建的基本走马灯的示例：

![基本 jCarousel](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img9.jpg)

走廊中有十几张缩略图图像。单击其中一侧箭头将走廊左右滑动以显示下一组。

# 执行操作 — 创建基本走马灯

遵循以下步骤设置基本的图像 jCarousel：

1.  与往常一样，我们将从我们的 HTML 开始。像在 第一章 中一样，设置一个基本的 HTML 文档和相关的文件和文件夹。在 HTML 文档的主体中，创建一个图像的无序列表。当图像具有统一大小时，走马灯效果最佳。我的图像大小为 200 像素宽，150 像素高。以下是我的 HTML 外观：

    ```js
    <ul id="thumb-carousel">
    <li><img src="img/Switzerland.png" alt="Switzerland"/></li>
    <li><img src="img/CostaRica.png" alt="Costa Rica"/></li>
    <li><img src="img/Canada.png" alt="Canada"/></li>
    <li><img src="img/Seychelles.png" alt="Seychelles"/></li>
    <li><img src="img/Tuvalu.png" alt="Tuvalu"/></li>
    <li><img src="img/Iceland.png" alt="Iceland"/></li>
    <li><img src="img/SouthAfrica.png" alt="South Africa"/></li>
    <li><img src="img/Mexico.png" alt="Mexico"/></li>
    <li><img src="img/Spain.png" alt="Spain"/></li>
    <li><img src="img/Italy.png" alt="Italy"/></li>
    <li><img src="img/Australia.png" alt="Australia"/></li>
    <li><img src="img/Argentina.png" alt="Argentina"/></li>
    </ul>

    ```

    你可以看到我给无序列表分配了一个 `id` 为 `thumb-carousel`，HTML 简单明了：只是一系列图像的列表。

1.  接下来，我们需要下载 jCarousel 插件。该插件可以从 GitHub 下载：[`github.com/jsor/jcarousel`](http://https://github.com/jsor/jcarousel)。![执行操作 — 创建基本走马灯](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img1.jpg)

    要下载插件，只需单击 **ZIP** 按钮。

1.  接下来，解压文件夹并查看其内容。![执行操作 — 创建基本走马灯](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img2.jpg)

    在内部，我们会找到一个名为 examples 的文件夹，其中包含许多 jCarousel 插件示例。有一个包含插件文档的 `index.html` 文件。一个 `skins` 文件夹包含插件附带的两种皮肤以及这些皮肤所需的图像。最后，一个 `lib` 文件夹包含 jQuery，以及 jCarousel 插件的两个副本之一经过压缩的版本。

1.  我们将使用 `tango` 样式和插件的压缩版本。将 `jquery.jcarousel.min.js` 复制到你自己的 `scripts` 文件夹，并将整个 `tango` 文件夹复制到你自己的 `styles` 文件夹。

1.  接下来，我们需要将 CSS 和 JavaScript 附加到我们的 HTML 文件中。在文档的 `<head>` 部分，将 tango 样式的 CSS 文件附加在你自己的 `styles.css` 文件之前：

    ```js
    <link rel="stylesheet" href="styles/tango/skin.css"/>
    <link rel="stylesheet" href="styles/styles.css"/>

    ```

1.  在文档底部，在闭合的 `</body>` 标签之前，在你自己的 `scripts.js` 之后，附加 jCarousel 插件文件：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/jquery.jcarousel.min.js"></script>
    <script src="img/scripts.js"></script>

    ```

1.  jCarousel 滑块的 tango 样式依赖于放置在列表包装器上的 `jcarousel-skin-tango` 类。用 `div` 标签将列表包装起来，并给 `div` 添加适当的类：

    ```js
    <div class="jcarousel-skin-tango">
    <ul id="thumb-carousel">
    ...
    </ul>
    </div>

    ```

1.  接下来我们要做的是设置我们自己的 JavaScript。打开你的 `scripts.js` 文件。在文档上调用 `ready` 方法，选择图像列表，并调用 `jcarousel()` 方法：

    ```js
    $(document).ready(function(){
    $('#thumb-carousel').jcarousel();
    });

    ```

    像往常一样，以这种方式调用 `jcarousel()` 方法将加载所有默认设置的轮播。在浏览器中刷新页面，你会看到这样的情况：

    ![进行操作的时间 — 创建基本的轮播](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img3.jpg)

    不完全是我们想象中的样子，但是点击右侧的下一个箭头会推进轮播。让我们来看看如何设置一些自定义设置，以便按照我们预期查看完整的图像。

1.  tango 样式的 CSS 假设我们的图像宽度为 `75` 像素，高度也为 `75` 像素，但实际上我们的轮播不是这样的。我们将在我们的 `styles.css` 中添加几行 CSS 来调整图像的大小。首先，我们将指定单个项目的宽度和高度：

    ```js
    .jcarousel-skin-tango .jcarousel-item { width:200px;height:150px;}

    ```

1.  我们还需要调整轮播容器和剪辑容器的整体大小：

    ```js
    .jcarousel-skin-tango .jcarousel-clip-horizontal { width:830px;height:150px;}
    .jcarousel-skin-tango .jcarousel-container-horizontal { width:830px; }

    ```

    你可能会想知道那个 `830px` 宽度是从哪里来的。每个项目宽度为 `200` 像素，每个图像之间有 `10` 个像素。

    `200 + 10 + 200 + 10 + 200 + 10 + 200 = 830`

    图像和它们之间的间隙的总宽度为 `830` 像素。

1.  接下来，我们需要将下一个和上一个按钮往下移一点，因为我们的轮播比默认的要高，而按钮显示得太高了：

    ```js
    .jcarousel-skin-tango .jcarousel-prev-horizontal,
    .jcarousel-skin-tango .jcarousel-next-horizontal { top:75px; }

    ```

    现在轮播看起来正是我们想要的样子：

    ![进行操作的时间 — 创建基本的轮播](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img4.jpg)

1.  最后，我们将对 jCarousel 插件本身的设置进行一些调整。像许多其他插件一样，我们可以通过在一对花括号内传递一组键/值对给 `jcarousel()` 方法来进行自定义。首先，让我们将 `scroll` 值更改为 `4`，这样每次按下下一个或上一个按钮时会滚动四个项目。回到你的 `scripts.js` 文件，并将新的键/值对添加到你的脚本中，如下所示：

    ```js
    $('#thumb-carousel').jcarousel({
    scroll: 4
    });

    ```

    接下来，轮播图当前在到达开头或结尾时会硬性停止。相反，我们将使轮播图环绕 —— 如果站点访客正在查看轮播图中的最后一个项目并按下下一个按钮，则轮播图将回到开头。如果在查看第一个项目时单击后退按钮，情况也是如此。我们将为`wrap`键添加一个`'both'`值，以便轮播图将在两端环绕：

    ```js
    $('#thumb-carousel').jcarousel({
    scroll: 4,
    wrap: 'both'
    });

    ```

    在浏览器中刷新页面，然后使用下一个或上一个按钮或两者的任意组合来翻页轮播图。这就是使用 jCarousel 插件创建简单轮播图的全部内容。

## 刚刚发生了什么？

我们使用 jCarousel 插件创建了一个基本的动画图像缩略图轮播图。我们使用插件中包含的一个默认外观，并通过 CSS 对我们的内容大小进行调整。一些简单的定制被传递给轮播图，以确保它按照我们想要的方式工作。

# 动画新闻滚动条

水平图像轮播图很好，但使用范围相当有限。幸运的是，jCarousel 插件足够灵活，可以用于各种不同的用途。在本节中，我们将学习如何创建一个动画新闻滚动条。

# 行动时间 —— 创建动画新闻滚动条

按照以下步骤设置垂直新闻列表：

1.  首先，我们将像在第一章中所做的那样设置基本的 HTML 文件和相关文件和文件夹。在 HTML 文档的正文中，创建一个新闻项目的无序列表。每个新闻项目都将包含一个图片和一个包含标题和摘要的 div：

    ```js
    <ul id="news-carousel">
    <li>
    <img src="img/Switzerland.png" alt="Switzerland"/>
    <div class="info">
    <h4>Switzerland</h4>
    <p>Switzerland, officially the Swiss Confederation, is a federal republic consisting of 26 cantons, with Bern as the seat of the federal authorities</p>
    </div>
    </li>
    <li>
    <img src="img/CostaRica.png" alt="Costa Rica"/>
    <div class="info">
    <h4>Costa Rica</h4>
    <p>Costa Rica, officially the Republic of Costa Rica, is a country in Central America, bordered by Nicaragua to the north, Panama to the south, the Pacific Ocean to the west and south and the Caribbean Sea to the east.</p>
    </div>
    </li>
    ...
    </ul>

    ```

    我在我的列表中总共创建了 12 个项目，每个项目都具有相同的结构。请记住，轮播图中的每个项目必须具有相同的宽度和高度。

1.  接下来，我们将打开我们的`styles.css`文件，并添加一些 CSS 代码以使每个新闻项目都以我们希望的方式进行样式设置，其中图片在左侧，标题和摘要在右侧：

    ```js
    #news-carousel li { overflow:hidden;zoom:1;list-style-type:none; }
    #news-carousel li img { float:left; }
    #news-carousel li .info { margin-left:210px; }
    #news-carousel h4 { margin:0;padding:0; }
    #news-carousel p { margin:0;padding:0;font-size:14px; }

    ```

    随意添加一些额外的 CSS 来样式化列表以适应您自己的口味。如果您在浏览器中打开页面，此时，您可以期望看到类似以下截图的内容：

    ![行动时间 —— 创建动画新闻滚动条](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img5.jpg)

1.  正如我们在简单轮播图示例中所做的那样，我们将在文档的`<head>`部分附加 tango 皮肤的 CSS，而在 jQuery 和我们自己的`scripts.js`文件之间，在文档底部附加 jCarousel 插件脚本。

1.  接下来，打开您的`scripts.js`文件。我们将编写我们的文档准备语句，选择我们的新闻滚动条，并调用`jcarousel()`方法，就像我们在上一个示例中所做的那样。

    ```js
    $(document).ready(function(){
    $('#news-carousel').jcarousel();
    });

    ```

1.  我们将一些定制选项传递给`jcarousel()`方法，以调整我们的轮播图以满足我们的需求。首先，它应该是垂直的而不是水平的，所以将`true`作为`vertical`键的值传递进去：

    ```js
    $('#news-carousel').jcarousel({
    vertical:true
    });

    ```

1.  我们还希望每次滚动一个项目：

    ```js
    $('#news-carousel').jcarousel({
    vertical:true,
    scroll:1
    });

    ```

1.  还有，我们希望新闻项目列表可以无限循环，如下所示：

    ```js
    $('#news-carousel').jcarousel({
    vertical:true,
    scroll:1,
    wrap:'circular'
    });

    ```

1.  我们希望轮播图以真正的新闻滚动条方式自动播放新闻故事。我们将每三秒推进一次轮播图：

    ```js
    $('#news-carousel').jcarousel({
    vertical:true,
    scroll:1,
    wrap:'circular',
    auto: 3
    });

    ```

1.  最后但同样重要的是，我们会将动画速度减慢一点，这样在动画触发时，如果我们的网站访客正在阅读，就不会那么令人不适。600 毫秒应该足够慢了：

    ```js
    $('#news-carousel').jcarousel({
    vertical:true,
    scroll:1,
    wrap:'circular',
    auto: 3,
    animation: 600
    });

    ```

1.  现在 jCarousel 已经按我们喜欢的方式配置好了，唯一剩下的就是自定义轮播图的外观了。我们目前使用的是默认的探戈皮肤，它仍然假设我们的单个项目宽度为 75 像素，高度为 75 像素。打开你的`styles.css`文件，我们将从调整必要的宽度和高度开始：

    ```js
    .jcarousel-skin-tango .jcarousel-item { width:475px;height:150px; }
    .jcarousel-skin-tango .jcarousel-clip-vertical { width:475px;height:470px; }
    .jcarousel-skin-tango .jcarousel-container-vertical { height:470px;width:475px; }

    ```

    我们将单个项目的大小设置为 475 像素宽，150 像素高。然后调整容器和裁剪容器的大小以显示三个项目。提醒一下——因为我们的轮播图中每个项目的高度为 150 像素，项目之间还有 10 像素的间距，我们可以如下计算容器的高度：

    150 + 10 + 150 + 10 + 150 = 470 像素

    我们在计算时使用高度而不是宽度，因为我们的轮播图现在是垂直的，而不是水平的。

1.  接下来，我们将调整探戈风格，以适应我的网站设计。我将从用橙色换掉容器的淡蓝色方案开始，调整圆角使其变得不那么圆滑：

    ```js
    .jcarousel-skin-tango .jcarousel-container { -moz-border-radius: 5px;-webkit-border-radius:5px;border-radius:5px;border-color:#CB4B16;background:#f9d4c5; }

    ```

1.  现在，让我们将探戈皮肤的小蓝色箭头替换为横跨整个轮播图宽度的长橙色条。我已经创建了自己的箭头图形，我将在每个按钮的中间显示：

    ```js
    .jcarousel-skin-tango .jcarousel-prev-vertical,
    .jcarousel-skin-tango .jcarousel-next-vertical { left:0;right:0;width:auto; }
    .jcarousel-skin-tango .jcarousel-prev-vertical { top:0;background:#cb4b16 url(images/arrows.png) 50% 0 no-repeat; }
    .jcarousel-skin-tango .jcarousel-prev-vertical:hover,
    .jcarousel-skin-tango .jcarousel-prev-vertical:focus { background-color:#e6581d;background-position:50% 0; }
    .jcarousel-skin-tango .jcarousel-next-vertical { background:#cb4b16 url(images/arrows.png) 50% -32px no-repeat;bottom:0; }
    .jcarousel-skin-tango .jcarousel-next-vertical:hover,
    .jcarousel-skin-tango .jcarousel-next-vertical:focus { background-color:#e6581d;background-position:50% -32px; }

    ```

    现在，如果你在浏览器中刷新页面，你会看到轮播图以不同的颜色方案和外观重新设计了一些：

    ![创建动画新闻滚动条的时间到了](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img6.jpg)

    将鼠标移动到顶部或底部的条上会稍微提亮颜色，点击条将使轮播图朝着那个方向推进一个项目。

## 刚刚发生了什么？

在这种情况下，我们使用 jCarousel 插件创建了一个垂直新闻滚动条。我们的新闻滚动条每三秒自动推进一次项目。我们减慢了动画速度，以便为我们的网站访客提供更流畅的阅读体验。我们还看到了如何自定义探戈皮肤的 CSS 来适应轮播图的颜色方案和外观，以适应我们网站的设计。接下来，我们将看看如何为轮播图添加一些外部控件。

## 尝试一下吧——设计您自己的轮播图

现在你已经看到如何自定义 jCarousel 插件的外观和行为，设计你自己的轮播图吧。它可以是水平或垂直的，包含文本、图片或两者的组合。试验一下 jCarousel 插件提供给你的设置——你会在插件的文档中找到它们的列表和解释。

# 特色内容滑块

除了一次显示多个项目的轮播图之外，jCarousel 还可以用于构建一次仅显示一个项目的内容滑块。还可以构建外部控制，以为您的轮播图增加一些额外的功能。让我们看看如何创建一个具有外部分页控件的单个幻灯片特色内容滑块。

# 行动时间 — 创建特色内容滑块

我们将像往常一样，首先设置我们基本的 HTML 文件和相关的文件和文件夹，就像我们在第一章，《设计师，见识 jQuery》中所做的那样。

1.  在 HTML 文档的主体中，我们的特色内容滑块的 HTML 标记将与我们为新闻滚动条设置的 HTML 非常相似。唯一的区别是我用更大的图片替换了图片，因为我希望图片成为滑块的主要焦点。我使用的图片尺寸为 600 像素宽，400 像素高。以下是 HTML 的示例：

    ```js
    <div class="jcarousel-skin-slider">
    <ul id="featured-carousel">
    <li>
    <a href="#"><img src="img/Switzerland.jpg" alt="Switzerland"/></a>
    <div class="info">
    <h4>Switzerland</h4>
    <p>Switzerland, officially the Swiss Confederation, is a federal republic consisting of 26 cantons, with Bern as the seat of the federal authorities</p>
    </div>
    </li>
    <li>
    <a href="#"><img src="img/CostaRica.jpg" alt="Costa Rica"/></a>
    <div class="info">
    <h4>Costa Rica</h4>
    <p>Costa Rica, officially the Republic of Costa Rica, is a country in Central America, bordered by Nicaragua to the north, Panama to the south, the Pacific Ocean to the west and south and the Caribbean Sea to the east.</p>
    </div>
    </li>
    ...
    </ul>
    </div>

    ```

    我的列表总共有 12 个条目，每个条目的标记就像你在这里看到的那样。注意，我将我的列表包装在一个带有类`jcarousel-skin-slider`的`div`中。我们将使用这个类来使用 CSS 对我们的列表进行样式设置。

1.  接下来，我们将为我们的项目列表设置样式。我们将在照片上叠加标题和文本段落，头部位于顶部，文本段落位于底部。以下是我们可以使用的 CSS：

    ```js
    #featured-carousel li { overflow:hidden;list-style-type:none;position:relative;width:600px;height:400px; }
    #featured-carousel h4 { position:absolute;top:0;left:0;right:0;padding:10px;margin:0;color:#000;font-size:36px;text-shadow:#fff 0 0 1px; }
    #featured-carousel p { position:absolute;bottom:0;left:0;right:0;padding:10px;margin:0;color:#fff;background:#000;background:rgba(0,0,0,0.7); }

    ```

    现在，我的列表中的每个项目看起来都类似于以下的屏幕截图：

    ![行动时间 — 创建特色内容滑块](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img7.jpg)

    我想要引起你对我在这里使用了一些方便的 CSS 技巧的注意。首先，请注意我给标题添加了一小段白色的`text-shadow`，并且将标题文本设为黑色。以防这段文本碰巧悬停在图片的黑色区域上，文本周围微妙的白色轮廓将帮助文本更加突出。然后，请注意，我为短段文本添加了两个背景值。第一个是纯黑色，第二个是使用`rgba`值表示的透明黑色。第一个值是针对 IE9 之前的版本的 Internet Explorer。这些浏览器将显示纯黑色的背景。更新的和更有能力的浏览器将使用第二个值，`rgba`值，在文本的后面显示略微透明的黑色背景—这样图片可以透过一点，同时使文本更易读。

1.  现在，我们将会在页面底部，在 jQuery 和我们的`scripts.js`文件之间，附加 jCarousel JavaScript，就像我们在本章其他示例中所做的那样。

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/jquery.jcarousel.min.js"></script>
    <script src="img/scripts.js"></script>

    ```

1.  现在我们要写一些 CSS 来自定义我们的内容滑块的外观。打开你的`styles.css`文件并添加以下样式：

    ```js
    .jcarousel-skin-slider .jcarousel-container-horizontal { width: 600px; }
    .jcarousel-skin-slider .jcarousel-clip { overflow: hidden; }
    .jcarousel-skin-slider .jcarousel-clip-horizontal { width:600px;height:425px; }
    .jcarousel-skin-slider .jcarousel-item { width:600px;height:400px; }

    ```

    这就是全部了。只需几行代码。我们将设置单个项目、容器和剪辑容器的宽度为 600 像素，与一个图像的宽度相同。单个项目的高度也设置为 400 像素，但我们将把剪辑容器的高度设置为 425 像素，以便为我们添加一些外部控件提供 25 像素的空间，稍后我们会看到这些控件。

1.  现在，打开你的`scripts.js`文件。我们首先要做的是选择我们的列表并将其存储在一个变量中。这是因为我们将多次使用列表，并且我们不希望 jQuery 每次都要查询 DOM 来查找我们的列表。

    ```js
    var slider = $('#featured-carousel');

    ```

1.  接下来，我们将设置我们的文档就绪语句，并在滑块上调用`jcarousel()`方法，并告诉它我们要一次滚动一个窗格。

    ```js
    var slider = $('#featured-carousel');
    $(document).ready(function(){
    slider.jcarousel({
    scroll: 1
    });
    });

    ```

1.  我们将添加我们自己的外部控件，因此我们需要删除`jcarousel()`方法自己创建的控件。我们可以这样做：

    ```js
    $(document).ready(function(){
    slider.jcarousel({
    scroll: 1,
    buttonNextHTML: null,
    buttonPrevHTML: null	
    });
    });

    ```

    提供了`buttonNextHTML`和`buttonPrevHTML`键，以便您可以为这些按钮指定自己的 HTML 标记。在这种情况下，我们将为这两个键传递`null`作为值，这将阻止它们被创建。

    现在我们已经完成了设置幻灯片放映器的基本操作。如果你在浏览器中查看页面，你会看到第一张幻灯片。我们还没有提供导航到其他幻灯片的方法，所以让我们立即解决这个问题。

    ![行动时间 —— 创建一个特色内容滑块](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img7.jpg)

## 分页控件

我们设置了一个基本的滑块，一次显示一个项目，但你肯定已经注意到除了第一个之外，没有办法查看任何幻灯片。我们删除了 jCarousel 的默认下一个和上一个按钮，并且我们还没有提供任何替代方法。让我们添加一些分页控件，这样我们的网站访问者就可以查看任何他们喜欢的幻灯片。

# 行动时间 —— 添加分页控件

接下来，我们要设置一个函数，该函数将创建下一个按钮、上一个按钮和分页按钮，并使它们起作用。

1.  jCarousel 插件提供了一个名为`initCallback`的键，它允许我们传递一个应在轮播创建时调用的函数的名称。让我们通过创建一个空函数并调用它来开始：

    ```js
    var slider = $('#featured-carousel');
    function carouselInit(carousel) {
    // Our function goes here
    }
    $(document).ready(function(){
    slider.jcarousel({
    scroll: 1,
    buttonNextHTML: null,
    buttonPrevHTML: null,
    initCallback: carouselInit	
    });
    });

    ```

    我们在`carouselInit()`函数中写的任何操作都将在轮播初始化或设置时执行。由于只有在启用 JavaScript 时，任何页码、上一个和下一个按钮才会起作用，所以我们想使用 JavaScript 动态创建这些按钮，而不是在 HTML 中编码它们。让我们看看如何创建一个包含滑块中每个幻灯片的页面链接列表。

1.  我们将从获取滑块中的所有幻灯片开始。请记住，我们的滑块是一个无序列表，滑块中的每个幻灯片都是列表中的一个单独列表项。由于我们已经保存了对滑块本身的引用，因此我们可以如下获取其中的所有幻灯片：

    ```js
    function carouselInit(carousel) {
    var slides = slider.find('li');
    }

    ```

1.  我们将在稍后使用这些幻灯片来创建页面数字。但与此同时，我们需要一个放置页面数字的地方，所以让我们在幻灯片之前创建一些容器，这样我们的分页将显示在幻灯片正上方。下面是如何在幻灯片之前插入两个嵌套的`<div>`标签：

    ```js
    function carouselInit(carousel) {
    var slides = slider.find('li');
    slider.before('<span id="page-controls"><span id="pages"></span></span>');
    }

    ```

1.  接下来，我们需要在我们的代码中几次引用这两个新创建的容器，所以我们将在变量中存储对它们的引用，如下面的代码所示：

    ```js
    function carouselInit(carousel) {
    var slides = slider.find('li');
    slider.before('<span id="page-controls"><span id="pages"></span></span>');
    var controls = $('#page-controls');
    var pages = $('#pages');
    }

    ```

1.  现在，我们要高级一点，为幻灯片中的每一页创建一个页码。以下是我们要添加的代码：

    ```js
    function carouselInit(carousel) {
    var slides = slider.find('li');
    slider.before('<span id="page-controls"><span id="pages"></span></span>');
    var controls = $('#page-controls');
    var pages = $('#pages');
    for (i=1; i<=slides.length; i++) {
    pages.append('<a href="#">' + i + '</a>');
    }
    }

    ```

    我们从`i = 1`开始，因为第一页的页码将是 1。然后我们检查`i`是否小于或等于幻灯片的数量（`slides.length`是幻灯片的数量）。如果`i`小于或等于幻灯片的数量，我们将递增 i 一个数字——基本上我们将把 1 添加到`i`上，而`i++`是 JavaScript 中表示`i = i+1`的快捷方式。

    在每次循环中，我们都将在我们创建的页面容器中附加一个链接。它是围绕页码的链接，i 代表我们的页码。

    如果此时在浏览器中刷新页面，你将看到链接到幻灯片秀上面的数字 1 到 12。它们没有样式，并且点击它们不会做任何事情，因为我们还没有设置——这就是我们接下来要做的。

    ![操作时间 — 添加分页控件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img10.jpg)

1.  接下来，我们要样式化链接，使它们看起来我们想要的样子。打开你的`styles.css`文件，添加下面几行到 CSS 中：

    ```js
    #page-controls { line-height:25px;height:25px; }
    #page-controls a { margin:0 4px 0 0;padding:0 5px;border:1px solid #859900; }
    #page-controls a:hover { border-color: #D33682; }
    #page-controls a.current { color:#333;border-color:#333; }

    ```

    这将我们的幻灯片控制行的高度设置为之前允许的 25 个像素。然后我们在每个链接周围放置了一个绿色边框，当鼠标悬停在链接上时，它会变成粉红色边框。我们调整了边距和填充以获得间隔良好的盒子行。最后，我们为我们的链接添加了一个`.current`类，以便我们能够用深灰色标记当前选择的链接。

    ![操作时间 — 添加分页控件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img11.jpg)

1.  好的，我们已经将页面数字添加到我们的文档中，所以我们所要做的就是让它们起作用。我们将为这些链接绑定一个点击函数，因为当我们的网站访客点击链接时我们希望发生一些事情。我们将如下开始：

    ```js
    function carouselInit(carousel) {
    var slides = slider.find('li');
    slider.before('<span id="page-controls"><span id="pages"></span></span>');
    var controls = $('#page-controls');
    var pages = $('#pages');
    for (i=1; i<=slides.length; i++) {
    pages.append('<a href="#">' + i + '</a>');
    }
    pages.find('a').bind('click', function(){
    //click code will go here
    });
    }

    ```

1.  函数内的第一件事是取消点击的默认操作，这样浏览器在点击链接时不会尝试执行自己的操作。

    ```js
    function carouselInit(carousel) {
    var slides = slider.find('li');
    slider.before('<span id="page-controls"><span id="pages"></span></span>');
    var controls = $('#page-controls');
    var pages = $('#pages');
    for (i=1; i<=slides.length; i++) {
    pages.append('<a href="#">' + i + '</a>');
    }
    pages.find('a').bind('click', function(){
    return false;
    });
    }

    ```

1.  jCarousel 插件为我们提供了一个很好的方法来滚动到幻灯片中的特定幻灯片。看起来是这样的：

    ```js
    carousel.scroll($.jcarousel.intval(number));

    ```

    结尾附近的`number`s 是我们将要传递的幻灯片编号。例如，如果我们想滚动到第六张幻灯片，我们会这样说：

    ```js
    carousel.scroll($.jcarousel.intval(6));

    ```

    在我们的情况下，我们要滚动到的数字幻灯片是链接中的页码。例如，如果我点击以下链接：

    ```js
    <a href="#">3</a>

    ```

    这意味着我想要滚动到幻灯片中的第三张幻灯片。我可以使用 jQuery 的`text()`方法来获得该数字，如下所示：

    ```js
    pages.find('a').bind('click', function(){
    carousel.scroll($.jcarousel.intval($(this).text()));
    return false;
    });

    ```

    如果我点击第四个链接，`$(this).text()`将等于 4；点击第七个链接，它将等于 7，以此类推。

    在浏览器中刷新页面，你会看到点击编号链接会将滑块滚动到该幻灯片。

1.  点击页码时，您可能已经注意到当前页码未在分页中突出显示。我们已经编写了用于突出显示具有`current`类的链接的 CSS —— 现在我们只需确保我们正在向当前链接添加该类即可。以下是我们将如何做到这一点的方法。

    ```js
    pages.find('a').bind('click', function(){
    carousel.scroll($.jcarousel.intval($(this).text()));
    $(this).addClass('current');
    return false;
    });

    ```

    现在，如果你在浏览器中刷新页面，你会发现点击页码会将`current`类 CSS 应用于链接，突出显示它。然而，点击第二个页码会突出显示该链接以及上一个链接。我们必须确保我们也从旧链接中移除类。添加以下行来处理这个问题：

    ```js
    pages.find('a').bind('click', function(){
    carousel.scroll($.jcarousel.intval($(this).text()));
    $(this).siblings('.current').removeClass('current');
    $(this).addClass('current');
    return false;
    });

    ```

    此行检查所有链接的兄弟节点，查找是否有任何具有当前类的链接。如果找到任何一个，就移除该类。

1.  现在，我们只需确保在轮播初始化时突出显示第一个链接即可。最简单的方法就是在创建轮播时简单地点击分页中的第一个链接，如下所示：

    ```js
    pages.find('a').bind('click', function(){
    carousel.scroll($.jcarousel.intval($(this).text()));
    $(this).siblings('.current').removeClass('current');
    $(this).addClass('current');
    return false;
    }).filter(':first').click();

    ```

    记住，jQuery 允许我们链式调用方法——即使我们在`bind()`方法内写了一个完整的函数，我们仍然可以在其末尾链式调用 next 方法。我们调用`filter()`方法来将链接列表缩减为仅第一个链接，然后调用`click()`方法来触发我们刚刚绑定到链接的点击函数。

    现在，如果你在浏览器中刷新页面，你会看到第一个链接以我们当前类 CSS 突出显示。

    ![行动时间 —— 添加分页控件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img12.jpg)

## 下一个和上一个按钮

现在我们已经设置好了幻灯片和页码，但我们还想要简单的下一个和上一个按钮，以便轻松地逐页翻阅幻灯片。我们将在分页控件的两端添加它们。

# 行动时间 —— 添加下一个和上一个按钮

现在，我们只需要添加上一个和下一个按钮即可。

1.  我们将在分页的开头添加上一个按钮，在结尾添加下一个按钮。以下是我们如何使用 jQuery 在文档中插入这些链接的方法：

    ```js
    function carouselInit(carousel) {
    var slides = slider.find('li');
    slider.before('<span id="page-controls"><span id="pages"></span></span>');
    var controls = $('#page-controls');
    var pages = $('#pages');
    for (i=1; i<=slides.length; i++) {
    pages.append('<a href="#">' + i + '</a>');
    }
    pages.find('a').bind('click', function(){
    carousel.scroll($.jcarousel.intval($(this).text()));
    $(this).siblings('.current').removeClass('current');
    $(this).addClass('current');
    return false;
    }).filter(':first').click();
    controls.prepend('<a href="#" id="prev">&laquo;</a>');
    controls.append('<a href="#" id="next">&raquo;</a>');
    }

    ```

    我已经使用`prepend()`方法将上一个按钮插入到页码之前，并使用`append()`方法将下一个按钮插入到页码之后。

    如果你在浏览器中刷新页面，你会看到下一个和上一个按钮以及我们的分页按钮显示出来。

    ![行动时间 —— 添加下一个和上一个按钮](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img13.jpg)

    然而，点击它们不会引起任何事情发生——我们必须连接这些按钮以使它们起作用。我们从下一个按钮开始。

1.  就像分页按钮一样，我们需要绑定点击事件。同样，jCarousel 插件为我们提供了一个很好的方法来切换到下一张幻灯片。

    ```js
    function carouselInit(carousel) {
    var slides = slider.find('li');
    slider.before('<span id="page-controls"><span id="pages"></span></span>');
    var controls = $('#page-controls');
    var pages = $('#pages');
    for (i=1; i<=slides.length; i++) {
    pages.append('<a href="#">' + i + '</a>');
    }
    pages.find('a').bind('click', function(){
    carousel.scroll($.jcarousel.intval($(this).text()));
    $(this).siblings('.current').removeClass('current');
    $(this).addClass('current');
    return false;
    }).filter(':first').click();
    controls.prepend('<a href="#" id="prev">&laquo;</a>');
    controls.append('<a href="#" id="next">&raquo;</a>');
    $('#next').bind('click', function() {
    carousel.next();
    return false;
    });
    }

    ```

    我们选择下一个按钮并绑定了一个点击事件。我们取消了浏览器的默认操作，以便在单击链接时浏览器不会尝试执行任何操作。然后，我们所要做的就是调用`carousel.next()`，jCarousel 将负责帮我们前进到下一个幻灯片。

    在浏览器中刷新页面，您会发现单击下一个按钮会将滑块向前移动一个幻灯片。

    您还会注意到，分页中当前突出显示的页面未更新。让我们看看如何解决这个问题。

1.  我们将通过以下方式开始找到当前突出显示的页码：

    ```js
    $('#next').bind('click', function() {
    carousel.next();
    var current = pages.find('.current');
    return false;
    });

    ```

    在这里，我们只是在我们的页码中查找具有`current`类的页码。

1.  接下来，我们将移除`current`类，移动到下一个页面编号链接，并将`current`类添加到该链接中，如下所示：

    ```js
    current.removeClass('current').next().addClass('current');

    ```

    啊，但不要那么快，我们只想在有下一个链接要跳转时才这样做。如果没有，那么我们就什么也不想做。如果我们检查`current.next().` `length`，我们就可以判断是否有下一个链接。因此，我们只需将此代码块包装在一个`if`语句中，如下所示的代码所示：

    ```js
    if ( current.next().length ) { current.removeClass('current').next().addClass('current'); }

    ```

    现在，如果您在浏览器中刷新页面，您会发现下一个按钮按预期工作。当我们到达最后一页时，它不会做任何事情，正如我们所预期的那样。

1.  现在我们将使用与前一个按钮非常相似的函数重复整个过程。以下是它的样子：

    ```js
    $('#prev').bind('click', function(){
    carousel.prev();
    var current = pages.find('.current');
    if ( current.prev().length ) { current.removeClass('current').prev().addClass('current'); }
    return false;
    });

    ```

    这是我们完整的`carouselInit()`函数的样子：

    ```js
    function carouselInit(carousel) {
    var slides = slider.find('li');
    slider.before('<span id="page-controls"><span id="pages"></span></span>');
    var controls = $('#page-controls');
    var pages = $('#pages');
    for (i=1; i<=slides.length; i++) {
    pages.append('<a href="#">' + i + '</a>');
    }
    pages.find('a').bind('click', function(){
    carousel.scroll($.jcarousel.intval($(this).text()));
    $(this).siblings('.current').removeClass('current');
    $(this).addClass('current');
    return false;
    }).filter(':first').click();
    controls.prepend('<a href="#" id="prev">&laquo;</a>');
    controls.append('<a href="#" id="next">&raquo;</a>');
    $('#prev').bind('click', function(){
    carousel.prev();
    var current = pages.find('.current');
    if ( current.prev().length ) { current.removeClass('current').prev().addClass('current'); }
    return false;
    });
    $('#next').bind('click', function() {
    carousel.next();
    var current = pages.find('.current');
    if ( current.next().length ) { current.removeClass('current').next().addClass('current'); }
    return false;
    });
    }

    ```

    现在，如果您在浏览器中刷新页面，您会发现下一个和上一个按钮都按预期工作，连同页面编号。您可以使用这些外部控件导航到幻灯片中的任何幻灯片。

    ![执行操作的时间——添加下一个和上一个按钮](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img14.jpg)

## 刚才发生了什么？

我们设置了 jCarousel 每次显示一个幻灯片。我们确保 jCarousel 没有创建自己的下一个和上一个按钮。我们使用 jQuery 向我们的文档添加了下一个、上一个和分页按钮，然后使用 jCarousel 的有用方法从这些外部控件控制幻灯片。我们确保当前显示的幻灯片在分页中突出显示，以便我们的网站访问者可以轻松地看到他们在幻灯片中的位置。

# 轮播幻灯片

现在我们已经学会了如何设置控制幻灯片的外部控件，让我们也以相同的方式设置幻灯片来控制幻灯片。在本节中，我们将创建一个简单的交叉淡入淡出幻灯片，由缩略图图像的轮播控制。以下是我们将要创建的示例的样本：

![轮播幻灯片](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img8.jpg)

点击轮播内任何缩略图都会在幻灯片区域加载出该图像的大尺寸版本。我也在幻灯片旁边提供了下一个和上一个按钮，让网站访问者可以逐个点击图片而不必单击每个缩略图来通过幻灯片放映中途。让我们看看如何将其放在一起。

# 行动时间-创建一个缩略图幻灯片

设置轮播缩略图幻灯片将是我们使用 jCarousel 做过的最困难的事情。但不要担心，我们会一步一步来。

1.  我敢打赌，你能猜到我们要如何开始，对吧？没错，通过设置我们简单的 HTML 文件和相关的文件和文件夹，就像我们在第一章 *设计师，遇见 jQuery*中做的一样。在这种情况下，我们只想要一个简单的缩略图列表，它们链接到图像的全尺寸版本。并且我们将将其包裹在一个`<div>`中进行样式设置。这就是我的列表是什么样子的：

    ```js
    <div class="jcarousel-skin-slideshow">
    <ul id="thumb-carousel">
    <li><a href="images/600/Switzerland.jpg"><img src="img/Switzerland.jpg" alt="Switzerland"/></a></li>
    <li><a href="images/600/CostaRica.jpg"><img src="img/CostaRica.jpg" alt="Costa Rica"/></a></li>
    <li><a href="images/600/Canada.jpg"><img src="img/Canada.jpg" alt="Canada"/></a></li>
    ...
    </ul>
    </div>

    ```

    我的列表中总共有十二个项目，并且它们都具有相同的标记。

1.  接下来，我们将为轮播图编写 CSS。这是一个定制设计，所以我们不会包含 jCarousel 提供的样式表之一。打开你的`styles.css`文件，并添加以下 CSS：

    ```js
    .jcarousel-skin-slideshow .jcarousel-container { }
    .jcarousel-skin-slideshow .jcarousel-container-horizontal { width:760px;padding:0 48px; }
    .jcarousel-skin-slideshow .jcarousel-clip { overflow:hidden; }
    .jcarousel-skin-slideshow .jcarousel-clip-horizontal { width:760px;height:75px; }
    .jcarousel-skin-slideshow .jcarousel-item { width:100px;height:75px; }
    .jcarousel-skin-slideshow .jcarousel-item-horizontal { margin-left:0;margin-right:10px; }
    .jcarousel-skin-slideshow .jcarousel-item-placeholder { background:#fff;color:#000; }
    .jcarousel-skin-slideshow .jcarousel-next-horizontal { position:absolute;top:0;right:0;width:38px;height:75px;cursor:pointer;background:transparent url(images/arrow-right.png) no-repeat 0 0; }
    .jcarousel-skin-slideshow .jcarousel-next-horizontal:hover,
    .jcarousel-skin-slideshow .jcarousel-next-horizontal:focus { background-position:0 -75px; }
    .jcarousel-skin-slideshow .jcarousel-next-horizontal:active { background-position: 0 -75px; }
    .jcarousel-skin-slideshow .jcarousel-prev-horizontal { position:absolute;top:0;left:0;width:38px;height:75px;cursor:pointer;background:transparent url(images/arrow-left.png) no-repeat 0 0; }
    .jcarousel-skin-slideshow .jcarousel-prev-horizontal:hover,
    .jcarousel-skin-slideshow .jcarousel-prev-horizontal:focus { background-position: 0 -75px; }
    .jcarousel-skin-slideshow .jcarousel-prev-horizontal:active { background-position: 0 -75px; }

    ```

    我已经创建了一个图片精灵，其中包含了我的下一个和上一个按钮的图片，并且这就是它们的背景图片所使用的。其余的部分应该看起来很熟悉 - 为每个项目和轮播图本身设置适当的尺寸。

1.  现在，我们将在文档底部，在 jQuery 和你的`scripts.js`文件之间，附加 jCarousel 插件：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/jquery.jcarousel.min.js"></script>
    <script src="img/scripts.js"></script>

    ```

1.  打开你的`scripts.js`文件，我们将通过在文档就绪语句内选择轮播并调用`jcarousel()`方法来启动我们的缩略图轮播。

    ```js
    $(document).ready(function(){
    $('#thumb-carousel').jcarousel({
    scroll: 6,
    wrap: 'circular'
    });
    });

    ```

    我们已经将值`'circular'`分配给了`wrap`键-这意味着轮播没有开始也没有结束-它将在网站访问者滚动时不断地环绕。

连续包裹很好-我们的网站访问者可以点击向前或向后的轮播按钮，无论他们身在何处，这比禁用按钮更友好一些。然而，连续滚动可能会使我们的网站访问者更难以跟踪他们在轮播中的位置。因此，尽管我们的轮播能够显示七张图片，我们已经将滚动设置为`6`。

假设我们的网站访问者正在查看我们的轮播，并且在轮播的第一个位置有一张美丽的海滩风景照片。网站访问者点击了上一个按钮，而那美丽的海滩风景照片滑过来填补了轮播的最后一个位置。在新位置看到同一张图片有助于传达刚刚发生的事情，并确保我们的网站访问者没有错过任何事情。

![行动时间 — 创建缩略图幻灯片](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img15.jpg)

## 刚才发生了什么？

我们按照了我们在早期 jCarousel 示例中所做的类似步骤。设置了我们的 HTML，为轮播器编写了一些 CSS 样式，然后使用 jQuery 选择了缩略图列表，并调用了`jCarousel()`方法。现在，让我们更进一步，向我们的轮播器添加幻灯片。

## 幻灯片

现在我们已经设置好了我们想要的简单轮播器并对其进行了样式化，让我们深入了解如何添加淡入淡出幻灯片特效。

# 行动时间 — 添加幻灯片

jCarousel 插件已经为我们设置了轮播器，但我们想要变得花哨，并且还要添加一个幻灯片区域。

1.  我们现在独自一人，所以我们将为创建幻灯片区域创建一个单独的函数。然后我们将在我们的文档就绪语句中调用新函数：

    ```js
    function slideshowInit() {
    // Slideshow setup goes here
    }
    $(document).ready(function(){
    slideshowInit();
    $('#thumb-carousel').jcarousel({
    scroll: 6,
    wrap: 'circular'
    });
    });

    ```

1.  首先，我们将在缩略图列表周围包裹一个容器，以创建幻灯片区域。我们发现自己已经需要再次引用缩略图列表，所以让我们将其存储在一个变量中，并更新对`jcarousel()`方法的调用如下：

    ```js
    var thumbs = $('#thumb-carousel');
    function slideshowInit() {
    // Slideshow setup goes here
    }
    $(document).ready(function(){
    slideshowInit();
    thumbs.jcarousel({
    scroll: 6,
    wrap: 'circular'
    });
    });

    ```

1.  接下来，在`slideshowInit()`函数内部，我们将调用 jQuery 的`wrap()`方法将列表包裹在一个`<div>`中。

    ```js
    function slideshowInit() {
    thumbs.wrap('<div id="stage-wrap"></div>');
    }

    ```

1.  接下来，我们需要创建实际的舞台，全尺寸图像将在其中显示。我们还需要创建下一个和上一个按钮。我们将使用`prepend()`方法，以便这些元素在缩略图列表之前被插入到`stage-wrap div`中。

    ```js
    function slideshowInit() {
    thumbs.wrap('<div id="stage-wrap"></div>');
    $('#stage-wrap').prepend('<div id="slideshow-next"></div><div id="slideshow-prev"></div><div id="stage"></div>');
    }

    ```

1.  现在，我们将回到我们的`styles.css`文件，并为这些新元素添加一些样式，如下所示：

    ```js
    #stage-wrap { position:relative;width:856px; }
    #stage { width:600px;height:400px;padding:0 0 20px 0;position:relative;text-align:center;margin:0 128px; }
    #stage img { position:absolute;top:0;left:50%;margin-left:-300px; }
    #slideshow-next { position:absolute;right:80px;top:160px;width:38px;height:75px;cursor:pointer;background:transparent url(images/arrow-right.png) no-repeat 0 0; }
    #slideshow-next:hover,
    #slideshow-next:active { background-position:0 -75px; }
    #slideshow-prev { position:absolute;left:80px;top:160px;width:38px;height:75px;cursor:pointer;background:transparent url(images/arrow-left.png) no-repeat 0 0; }
    #slideshow-prev:hover,
    #slideshow-prev:active { background-position:0 -75px; }

    ```

    所有的全尺寸图像都是相同大小的，600x400，所以我们可以将其设置为舞台的宽度和高度，并相应地定位下一个和上一个图像按钮。如果您现在在浏览器中查看页面，您应该会看到为舞台留下的大空白区域，以及缩略图轮播器上方的下一个和上一个图像按钮，所有这些都位于其上方。

    ![行动时间 — 添加幻灯片](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_10_img16.jpg)

1.  我们有一个轮播器，我们有一个空舞台，我们在舞台两侧有下一个和上一个按钮。接下来，我们将用图像幻灯片填充舞台。我们将通过设置一个变量来引用舞台，并将舞台的`opacity`设置为`0`来开始，如下所示的代码：

    ```js
    function slideshowInit() {
    thumbs.wrap('<div id="stage-wrap"></div>');
    $('#stage-wrap').prepend('<div id="slideshow-next"></div><div id="slideshow-prev"></div><div id="stage"></div>');
    var stage = $('#stage');
    stage.css('opacity',0);
    }

    ```

    我们隐藏了舞台，以便我们可以在不让站点访问者看到图像加载的情况下将图像加载到其中。这让我们能够在创建幻灯片时对其外观有一些控制。在有东西可看之前，我们将保持舞台不可见。

1.  接下来，我们需要获取所有到全尺寸图像的链接，并准备好查找每个全尺寸图像的 URL，如下所示：

    ```js
    function slideshowInit() {
    thumbs.wrap('<div id="stage-wrap"></div>');
    $('#stage-wrap').prepend('<div id="slideshow-next"></div><div id="slideshow-prev"></div><div id="stage"></div>');
    var stage = $('#stage');
    stage.css('opacity',0);
    var imageLinks = thumbs.find('a');
    var src;
    }

    ```

    全尺寸图像的链接包含在缩略图列表中，我们可以用`thumbs`变量引用它们。我们只是找到该列表中的所有链接，并将它们存储在一个名为`imageLinks`的变量中。接下来，我们设置一个名为`src`的空容器，我们将在其中存储图像的 URL。尽管目前，我们将该容器留空。我们稍后会填充它。

1.  我们有 12 个全尺寸图像的链接。对于每个链接，我们需要在舞台上创建一个新图像。我们将使用 jQuery 的`each()`方法循环遍历每个链接并创建一个图像。

    ```js
    function slideshowInit() {
    thumbs.wrap('<div id="stage-wrap"></div>');
    $('#stage-wrap').prepend('<div id="slideshow-next"></div><div id="slideshow-prev"></div><div id="stage"></div>');
    var stage = $('#stage');
    stage.css('opacity',0);
    var imageLinks = thumbs.find('a');
    var src;
    imageLinks.each(function(i) {
    // We'll create our images here
    });
    }

    ```

    这是 jQuery 的方式*说对于每个链接，执行此操作*。

1.  接下来，我们将为每个链接创建一个图像。首先，我们知道图像的`src`属性将等于链接的`href`属性。换句话说，链接如下所示：

    ```js
    <a href="images/600/Switzerland.jpg">Switzerland</a>

    ```

    将用于创建如下图像：

    ```js
    <img src="img/Switzerland.jpg"/>

    ```

    所以我们要做的第一件事是获取之前创建的空`src`变量，并将图像的 URL 存储在其中：

    ```js
    imageLinks.each(function(i) {
    src = $(this).attr('href');
    });

    ```

    接下来，我们将使用这个`src`属性创建一个图像。我将把我新创建的图像存储在一个名为`img`的变量中：

    ```js
    imageLinks.each(function(i) {
    src = $(this).attr('href');
    var img = $('<img/>', {
    src: src,
    css: {
    display: 'none'
    }
    });
    });

    ```

    我们将图像的显示设置为 none，以隐藏以这种方式创建的所有图像。我们已将图像的`src`属性设置为保存图像 URL 的`src`变量。

1.  现在图像已创建，我们将其添加到舞台上。

    ```js
    imageLinks.each(function(i) {
    src = $(this).attr('href');
    var img = $('<img/>', {
    src: src,
    css: {
    display: 'none'
    }
    });
    img.appendTo(stage);
    });

    ```

    jQuery 的`appendTo()`方法允许我们将图像附加到舞台上。

1.  现在舞台上充满了图像，让我们继续使其可见。

    ```js
    function slideshowInit() {
    thumbs.wrap('<div id="stage-wrap"></div>');
    $('#stage-wrap').prepend('<div id="slideshow-next"></div><div id="slideshow-prev"></div><div id="stage"></div>');
    var stage = $('#stage');
    stage.css('opacity',0);
    var imageLinks = thumbs.find('a');
    var src;
    imageLinks.each(function(i) {
    src = $(this).attr('href');
    var img = $('<img/>', {
    src: src,
    css: {
    display: 'none'
    }
    });
    img.appendTo(stage);
    });
    stage.css('opacity',1);
    }

    ```

1.  接下来，我们想要在单击轮播中的缩略图链接时在舞台上显示相应的图像。如果现在单击缩略图，你会发现它会在浏览器中打开全尺寸图像，但我们希望图像显示在舞台上。我们只需要一种方式来从轮播中的图像引用舞台上的特定图像。我们可以通过几种不同的方式来做到这一点，几乎总是有多种方法可以完成某事。在这种情况下，我们将利用 jQuery 的`data()`方法在每个缩略图链接中存储索引号。然后我将使用该索引来找到并显示适当的图像。

    基本上，我们要对列表中的链接进行编号。你可能会认为它们会被编号为 1 到 12，但请记住 JavaScript 计数从 0 开始，因此缩略图图像将被编号为 0 到 11。当单击缩略图时，我们将获取该缩略图的索引号，找到舞台上具有相同索引的图像并显示它。所以如果我们的网站访客单击缩略图编号为 6，我们将在舞台上找到编号为 6 的图像并显示它。

    首先，我们必须为缩略图分配索引号。在文档就绪声明中，添加一个小函数来循环遍历每个缩略图，并添加索引号，如下所示：

    ```js
    $(document).ready(function(){
    thumbs.find('a').each(function(index){
    $(this).data('index', (index));
    });
    slideshowInit();
    thumbs.jcarousel({
    scroll: 6,
    wrap: 'circular',
    initCallback: nextPrev
    });
    });

    ```

1.  现在所有的缩略图链接都已经编号，我们可以编写一个函数，在点击缩略图时找到舞台上适当的图像并显示它。在`slideshowInit()`函数内部，我们将把我们的函数绑定到点击事件上：

    ```js
    function slideshowInit() {
    thumbs.wrap('<div id="stage-wrap"></div>');
    $('#stage-wrap').prepend('<div id="slideshow-next"></div><div id="slideshow-prev"></div><div id="stage"></div>');
    var stage = $('#stage');
    stage.css('opacity',0);
    var imageLinks = thumbs.find('a');
    var src;
    imageLinks.each(function(i) {
    src = $(this).attr('href');
    var img = $('<img/>', {
    src: src,
    css: {
    display: 'none'
    }
    });
    img.appendTo(stage);
    });
    stage.css('opacity',1);
    imageLinks.bind('click', function(){
    // Function to find and show an image goes here
    });
    }

    ```

1.  在我们的新功能内部要做的第一件事是取消浏览器的默认行为。我们不希望链接在浏览器中打开图像，所以我们会返回 false。

    ```js
    imageLinks.bind('click', function(){
    return false;
    })

    ```

1.  接下来，我们需要获取我们链接中存储的数字。我们将再次使用`data()`方法来找到这个数字：

    ```js
    imageLinks.bind('click', function(){
    var index = $(this).data('index');
    return false;
    })

    ```

1.  现在，我们需要在舞台上搜索具有该索引号的图像。我将把图像存储在一个名为`nextImage`的变量中，因为它将是要显示的下一个图像。

    ```js
    imageLinks.bind('click', function(){
    var index = $(this).data('index');
    var nextImage = stage.find('img:eq(' + index + ')');
    })

    ```

    jQuery 允许我们使用`:eq`选择器按索引号查找元素。例如，`$('img:eq(1)')`选择器会选择图像列表中的第二个图像。（记住，JavaScript 计数从 0 开始，而不是从 1 开始。）在这种情况下，我知道我想要哪个数字图像，因为它是刚刚点击的链接中存储的数字。

1.  现在我们已经得到了下一个图像，我们需要显示它。我们将淡入它并添加一个`active`类。

    ```js
    imageLinks.bind('click', function(){
    var index = $(this).data('index');
    var nextImage = stage.find('img:eq(' + index + ')');
    nextImage.fadeIn().addClass('active');
    return false;
    })

    ```

1.  但是不要忘记，已经有另一张图像可见。我们需要找到那张图像并将其淡出。由于我们在图像显示时添加了一个`active`类，所以我们可以通过查找具有`active`类的图像轻松找到当前显示的图像：

    ```js
    imageLinks.bind('click', function(){
    var index = $(this).data('index');
    var nextImage = stage.find('img:eq(' + index + ')');
    stage.find('img.active').fadeOut().removeClass('.active');
    nextImage.fadeIn().addClass('active');
    return false;
    })

    ```

    不要忘记，我们必须确保删除那个`active`类，以便一次只有一个图像被标记为活动状态。

如果你现在在浏览器中刷新页面，你会看到点击幻灯片缩略图链接中的任意一个会在幻灯片中加载相应的图像。一张图像淡出，而下一张图像以一种流畅的方式淡入。接下来，我们将让下一个和上一个按钮工作起来，这样我们就可以轻松地翻转到下一个图像。

## 刚才发生了什么？

哎呀！希望你还在继续跟着我，因为这是向你的网站访问者展示幻灯片的一种非常棒的方式。希望你开始意识到，有时候插件只是一个开始 — 你可以发挥创造力，发明自己的功能来叠加在默认插件行为之上。

## 下一个和上一个按钮

我们确实取得了一些不错的进展。点击缩略图会在幻灯片中加载图像的全尺寸版本，我们可以使用幻灯片控件滚动缩略图并查看它们所有。现在，让我们让下一个和上一个图像按钮起作用。

# 行动时间 —— 激活下一个和上一个按钮

接下来，我们将让围绕图像的下一个和上一个按钮工作起来，这样网站访问者可以轻松地翻阅所有的图像。

1.  就像我们在上一个示例中为幻灯片连接外部控制一样，我们将从设置幻灯片的回调函数开始。我们将函数命名为`nextPrev`并设置如下：

    ```js
    function nextPrev(carousel) {
    }
    thumbs.jcarousel({
    scroll: 6,
    wrap: 'circular',
    initCallback: nextPrev
    });

    ```

    现在`nextPrev`函数将在旋转木马初始化时被调用。

1.  在`nextPrev()`函数内部，我们将选择上一个按钮并绑定一个函数到点击事件：

    ```js
    function nextPrev(carousel) {
    $('#slideshow-prev').bind('click', function() {
    //Click code will go here
    });
    }

    ```

1.  当站点访问者点击上一个按钮时，我们希望显示幻灯片秀中的前一幅图像。与 JavaScript 一般一样，有多种方法可以实现这一点。由于我们已经设置好了一个好用的幻灯片切换功能，当旋转木马中的其中一个缩略图被点击时发生，让我们直接重复使用它。

    当我们的站点访问者点击上一个按钮时，我们会找到旋转木马中的上一个缩略图并点击它。这将启动图像过渡，并允许我们重复使用我们已经编写的代码。

    因此，我们的首要任务是找到当前选择的缩略图。但是，我们并没有简化找到当前缩略图的方法。因此，让我们回到`slideshowInit()`函数内部，并添加一行代码将一个类添加到当前的缩略图上：

    ```js
    function slideshowInit() {
    thumbs.wrap('<div id="stage-wrap"></div>');
    $('#stage-wrap').prepend('<div id="slideshow-next"></div><div id="slideshow-prev"></div><div id="stage"></div>');
    var stage = $('#stage');
    stage.css('opacity',0);
    var imageLinks = thumbs.find('a');
    var src;
    imageLinks.each(function(i) {
    src = $(this).attr('href');
    var img = $('<img/>', {
    src: src,
    css: {
    display: 'none'
    }
    });
    img.appendTo(stage);
    });
    stage.css('opacity',1);
    imageLinks.bind('click', function(){
    var index = $(this).data('index');
    $(this).parents('li').addClass('current').siblings('.current').removeClass('current');
    var nextImage = stage.find('img:eq(' + index + ')');
    stage.find('img.active').fadeOut().removeClass('.active');
    nextImage.fadeIn().addClass('active');
    return false;
    })
    }

    ```

    在这里，我们给包含点击缩略图的`<li>`标签添加了一个`current`类。然后，我们检查所有兄弟元素，以移除`current`类（如果它存在的话）。这确保了在任何给定时间内，旋转木马中只有一个项目具有`current`类。

1.  现在，如果您能给我一个分钟，我们将进行一个旁支到 CSS。由于我们正在向当前缩略图添加一个类，我们可以利用 CSS 来对当前缩略图进行样式设置，使其与其他不同。让我们打开`styles.css`并添加一些样式如下：

    ```js
    #thumb-carousel img { opacity:.5; }
    #thumb-carousel .current img { opacity:1; }

    ```

1.  回到 JavaScript！现在我们有一种简单的方法来选择当前的缩略图，我们只需找到具有`current`类的缩略图即可。在`prevNext()`函数内部，我们可以通过以下方式获取当前链接：

    ```js
    function nextPrev(carousel) {
    $('#slideshow-prev').bind('click', function() {
    var currentSlide = thumbs.find('li.current');
    });
    }

    ```

1.  由于这是附加到上一个按钮的功能，我们需要找到列表中的上一个缩略图。我将使用 jQuery 的`prev()`方法在旋转木马中找到上一个缩略图：

    ```js
    currentSlide.prev();

    ```

    然而，如果当前幻灯片是第一张，那就没有上一个幻灯片可供查看。在这种情况下，如果站点访问者在第一张幻灯片上并单击上一个按钮，我希望他们跳转到列表中的最后一张幻灯片，以便无缝续播。因此，我首先要检查是否有上一张幻灯片如下：

    ```js
    function nextPrev(carousel) {
    $('#slideshow-prev').bind('click', function() {
    var currentSlide = thumbs.find('li.current');
    var prevSlide = currentSlide.prev().length ? currentSlide.prev() : thumbs.find('li:last');
    });
    }

    ```

    这里有几件事情要解释。首先，这行代码从 JavaScript 翻译成英语说*这个缩略图之前有一个吗？如果有的话，那就是我们要去的地方。如果没有，那么我们将前往最后一个缩略图。*

    ```js
    var prevSlide;
    if (currentSlide.prev().length) {
    prevSlide = currentSlide.prev();
    } else {
    prevSlide = thumbs.find('li:last');
    }

    ```

    以下是三元运算符的工作原理：

    ```js
    condition to check ? value if true : value if false

    ```

    它以我们正在检查的条件开始，后跟一个？。之后，我们有如果该条件为真，则跟随的值，后跟一个：，以及如果该条件为假则跟随的值。

1.  现在我们找到了上一个幻灯片，剩下的就是点击其中的链接如下：

    ```js
    function nextPrev(carousel) {
    $('#slideshow-prev').bind('click', function() {
    var currentSlide = thumbs.find('li.current');
    var prevSlide = currentSlide.prev().length? currentSlide.prev() : thumbs.find('li:last');
    prevSlide.find('a').click();
    });
    }

    ```

    这将触发我们编写的在浏览器中更改幻灯片的函数。如果此时在浏览器中重新加载页面，然后点击几次前一个按钮，你会看到图片会像我们预期的那样切换。

    但是，轮播图上并没有太多的事情。它就那么呆在那里。而且马上当前选定的缩略图就看不见了。如果我点击一次前一个按钮，然后滚动轮播图，最终我才能看到高亮的缩略图。理想情况下，轮播图会更新自身，以确保当前缩略图始终可见。

1.  jCarousel 插件使我们可以轻松地滚动到轮播图中的任何幻灯片。我们只需要知道我们想要显示哪一个。jCarousel 的设置脚本的一部分还为轮播图中的每个列表项分配了一个 `jcarouselindex` 属性。我们可以获取该数字并将其用于滚动目的。首先，让我们弄清楚 `prevSlide` 的 `jcarouselindex` 是多少，因为那是我们想要滚动到的位置。

    ```js
    function nextPrev(carousel) {
    $('#slideshow-prev').bind('click', function() {
    var currentSlide = thumbs.find('li.current');
    var prevSlide = currentSlide.prev().length? currentSlide.prev() : thumbs.find('li:last');
    var index = parseInt(prevSlide.attr('jcarouselindex'));
    prevSlide.find('a').click();
    });
    }

    ```

    我使用`parseInt()`来确保我得到一个数字而不是一个字符串。如果我得到一个字符串，它可能会搞乱轮播图中的滚动。

    现在，剩下的就是滚动到正确的缩略图：

    ```js
    function nextPrev(carousel) {
    $('#slideshow-prev').bind('click', function() {
    var currentSlide = thumbs.find('li.current');
    var prevSlide = currentSlide.prev().length? currentSlide.prev() : thumbs.find('li:last');
    var index = parseInt(prevSlide.attr('jcarouselindex'));
    prevSlide.find('a').click();
    carousel.scroll(index);
    });
    }

    ```

    现在，如果你在浏览器中刷新页面，你会看到点击前一个按钮会更新轮播图——轮播图会滚动，以使当前高亮的幻灯片成为轮播图中的第一张。但是，如果我决定希望当前高亮的幻灯片出现在中间呢？很简单！我有七张幻灯片显示。如果高亮的幻灯片在中间，那么在它之前会有三张幻灯片（以及它之后的三张）。我所要做的就是告诉轮播图将高亮幻灯片的前三张幻灯片设为第一张可见的幻灯片，如下所示：

    ```js
    function nextPrev(carousel) {
    $('#slideshow-prev').bind('click', function() {
    var currentSlide = thumbs.find('li.current');
    var prevSlide = currentSlide.prev().length? currentSlide.prev() : thumbs.find('li:last');
    var index = parseInt(prevSlide.attr('jcarouselindex')) - 3;
    prevSlide.find('a').click();
    carousel.scroll(index);
    });
    }

    ```

    现在，例如，当我点击前一个按钮时，如果下一张幻灯片是第 5 张，轮播图将首先显示第 2 张，这意味着第 5 张将出现在轮播图的中间。在浏览器中刷新页面，试一试。很棒，对吧？

1.  唯一剩下的就是使下一个按钮像前一个按钮一样工作。函数几乎相同，只需做一些微调。

    ```js
    function nextPrev(carousel) {
    $('#slideshow-prev').bind('click', function() {
    var currentSlide = thumbs.find('li.current');
    var prevSlide = currentSlide.prev().length? currentSlide.prev() : thumbs.find('li:last');
    var index = parseInt(prevSlide.attr('jcarouselindex')) - 3;
    prevSlide.find('a').click();
    carousel.scroll(index);
    });
    $('#slideshow-next').bind('click', function() {
    var currentSlide = thumbs.find('li.current');
    var nextSlide = currentSlide.next().length ? currentSlide.next() : thumbs.find('li:first');
    var index = parseInt(nextSlide.attr('jcarouselindex')) - 3;
    nextSlide.find('a').click();
    carousel.scroll(index);
    });
    }

    ```

    我使用`next()`方法而不是`prev()`方法来获取下一张幻灯片而不是上一张。除此之外，函数是相同的。

现在，如果你在浏览器中刷新页面，你会看到下一个和前一个图片按钮都可以使用——它们会显示幻灯片秀中的正确图片，并滚动轮播图，以使当前图片在轮播图的中间高亮显示。

## 刚才发生了什么？

我们将一些外部的轮播控制与幻灯片放在一起，创建了一个强大的幻灯片/轮播组合。幻灯片可以从轮播控制——点击轮播中的缩略图将在幻灯片舞台中加载出完整尺寸的图像。并且点击舞台中的下一个和上一个按钮将更新轮播，滚动轮播，以便当前高亮的缩略图出现在轮播的可见区域中间。

我们从一些基本的 HTML 开始，为轮播编写了自定义的 CSS 皮肤，并调用了 `jcarousel()` 方法来使轮播工作。接下来，我们编写了一个函数来动态创建幻灯片舞台和按钮。最后，我们通过一些精巧的 jQuery 操作使它们都能协同工作。

# 总结

我们研究了在各种情况下使用 jCarousel 插件的方法，我们创建了一个简单的水平缩略图轮播，一个垂直新闻滚动条，一个带有外部控制的特色内容滑块，最后，一个展示了 jCarousel 插件功能的轮播/幻灯片组合。现在，你在工具箱中又增加了一个强大的工具——jCarousel 插件是灵活、强大的，并且可以定制以适用于各种不同的情况。

接下来，我们将看一下创建交互式数据表格。


# 第十一章：创建交互式数据网格

> 虽然你可能认为数据网格并不那么令人兴奋，但它们确实为站点访问者提供了一种与大量数据交互并理解数据的方式，这是他们可能无法以其他方式做到的。HTML5 中最令人兴奋的发展之一是引入了网格元素，它允许我们仅使用标记就能轻松创建交互式数据网格。然而，它是新元素之一，浏览器支持落后——目前几乎没有或几乎没有任何浏览器支持，并且可能需要数年时间，我们才能利用这个新元素。幸运的是，我们可以使用 jQuery 来填补这一空白，直到新的网格元素准备就绪。

在本章中，我们将学习以下主题：

+   使用 Allan Jardine 的 DataTables jQuery 插件将普通表格转换为交互式数据网格

+   使用 jQuery UI Themeroller 对数据网格的外观和行为进行定制

# 基本数据网格

我们将使用 DataTables 插件创建一个基本的数据网格，保留默认设置和数据网格提供的样式。当我们有大量数据要呈现时，数据网格是最有帮助的，并且站点访问者可能希望以不同的方式过滤和排序数据，以找到他们正在寻找的信息。例如，想象一下航班列表——一个站点访问者可能有兴趣按出发时间对航班进行排序，以找到可能的最早出发时间，而另一个站点访问者可能想按持续时间对航班进行排序，以找到可能的最短航班。

将数据呈现为交互式数据网格允许每个站点访问者在海量信息中快速轻松地找到他们正在寻找的信息。对于禁用 JavaScript 的站点访问者，他们将只看到一张大型数据表，永远不会知道他们错过了交互式功能。所有信息仍然对他们可用。

# 行动时间——创建基本数据网格

让我们看看如何将基本的 HTML 表格转换为交互式数据网格：

1.  我们将像在第一章 *设计师，见 jQuery* 中一样，使用我们的基本 HTML 文件和相关文件和文件夹开始。我们将使用 HTML 标记来填充我们的 HTML 文档的`<body>`部分，创建一个大型数据表的 HTML 标记。DataTables 插件要求我们对表格标记进行仔细且正确的处理。我们需要确保为表格的标题使用一个`<thead>`元素，并为表格的主体使用一个`<tbody>`元素。可选的为表格页脚使用一个`<tfoot>`元素。以下是一个所有时间最畅销书籍的表格的 HTML 标记的简化样本：

    ```js
    <table id="book-grid">
    <thead>
    <tr>
    <th>Title</th>
    <th>Author</th>
    <th>Original Language</th>
    <th>First Published</th>
    <th>Approximate Sales</th>
    </tr>
    </thead>
    <tbody>
    <tr>
    <td>A Tale of Two Cities</td>
    <td>Charles Dickens</td>
    <td>English</td>
    <td>1859</td>
    <td>200 million</td>
    </tr>
    <tr>
    <td>Le Petit Prince (The Little Prince)</td>
    <td>Antoine de Saint-Exup&eacute;ry</td>
    <td>French</td>
    <td>1943</td>
    <td>200 million</td>
    </tr>
    ...
    </tbody>
    </table>

    ```

    我已经向表格中添加了共计 106 本书，每本都像这样标记。请注意，我们在表格元素上添加了一个`id`为`book-grid`的 id，并使用了`<th>`元素来作为每列的标题，并将其封装在`<thead>`元素中。我们还使用了一个`<tbody>`元素来包装表格主体中的所有行。

1.  接下来，我们将下载 DataTables 插件。前往[`datatables.net`](http://datatables.net)，在那里你会找到插件的下载、文档和示例。点击页眉中的**下载**链接下载 ZIP 文件。![执行操作的时间——创建基本数据表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_11_img1.jpg)

1.  解压文件夹并查看其内部。![执行操作的时间——创建基本数据表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_11_img2.jpg)

    +   有一个`examples`文件夹，其中包含几个不同的 DataTables 插件示例。一个`extras`文件夹提供了高级数据表的额外功能，我们这里不会使用任何其中的东西。有一个`media`文件夹，其中包含`images、css、js`和`unit_testing`资源。最后还有一个`Readme.txt`文件，其中包含有关插件创建者和文档位置等信息。

        最后，你会找到插件的许可证，包括 BSD 和 GPL。你可以阅读这些许可证文件或访问维基百科获取这些许可证的详细信息，但它们都是允许你免费使用插件代码的自由软件许可证。

1.  我们将建立一个基本示例，所以我们只需要为我们自己的项目准备一些东西。首先，将`images`目录的内容复制到你自己的`images`目录中。打开`css`文件夹，将`demo_table.css`复制到你自己的`styles`目录中。要小心选择正确的 CSS 文件`demo_table.css`，因为那里有几个 CSS 文件。最后，在`js`文件夹中，找到插件的压缩版本`jquery.dataTables.min.js`，并将其复制到你自己的`scripts`目录中。

1.  接下来，我们将获取所有必要的文件附加到包含我们表格的 HTML 页面中。在文档的`<head>`部分，在你自己的`styles.css`文件之前附加 CSS 文件：

    ```js
    <link rel="stylesheet" href="styles/demo_table.css"/>
    <link rel="stylesheet" href="styles/styles.css"/>

    ```

1.  接下来，在 HTML 文档的底部，在 jQuery 和你自己的`scripts.js`文件之间附加 DataTables 插件：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/jquery.dataTables.min.js"></script>
    <script src="img/scripts.js"></script>
    </body>
    </html>

    ```

1.  接下来，打开你的`scripts.js`文件，并在文档准备就绪的语句中，选择表格并调用`dataTable()`方法，如下所示：

    ```js
    $(document).ready(function(){
    $('#book-grid').dataTable();
    });

    ```

    现在，如果你在浏览器中刷新页面，你会看到你的表已经被转换成了数据表格。你可以选择一次查看多少项，输入到搜索框中以查找特定的表项，并使用右下角的分页控件浏览数据表的行。

    ![执行操作的时间——创建基本数据表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_11_img3.jpg)

## 刚才发生了什么？

我们设置了一个基本的 HTML 表格，并通过附加一些 CSS 和 DataTables 插件将其转换为交互式数据表。我们选择了表格并调用了 `dataTable()` 方法以激活 DataTables 插件。

这很容易，不是吗？当然，这种淡紫色设计可能不符合您网站的设计，所以让我们看看如何自定义数据表的外观。

# 自定义数据表

DataTables 插件是我们使用的第一个具有 jQuery UI Themeroller 支持的插件。jQuery UI 是一组小部件和交互，使构建复杂应用程序变得更容易更快。学习 jQuery UI 本身超出了本书的范围，但我们将看看如何使用 jQuery UI Themeroller 为我们的数据表创建自定义主题。这个主题将适用于我们页面上使用的任何 jQuery UI 小部件，以及任何包含 jQuery UI Themeroller 支持的 jQuery 插件。

# 行动时间 — 自定义数据表

我们将从上次的数据表结束的地方继续。如果您想保存您的基本示例，只需保存文件的副本。然后按照以下步骤自定义数据表的外观：

1.  转到 [`jqueryui.com/themeroller`](http://jqueryui.com/themeroller) ，我们将看看 Themeroller。在左列中，您会找到选择预定义主题或创建自定义主题的控件，而宽广的右列包含几种不同类型小部件的示例。![行动时间 — 自定义数据表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_11_img4.jpg)

1.  在左列中单击 **Gallery 选项卡** ，您会看到有数十种预构建的 Themeroller 主题可供选择。当您单击不同示例时，您将看到右列中的示例小部件更新以反映该样式。我通常喜欢从选择一个与我想要的颜色方案或外观相当接近的预构建主题开始，然后切换到 **Roll Your Own 选项卡** 进行微调以满足我的需求。对于这个示例，我将从 **Cupertino** 风格开始。

    在切换到 **Roll Your Own 选项卡** 后，您会看到有关字体、颜色、角落、标题等的设置。进行任何您想要的调整，使主题看起来符合您的喜好。请随意玩耍和尝试。如果您走得太远，得到了您不喜欢的东西，那么轻松地切换回 **Gallery 选项卡** 并重新选择预构建主题，剥离掉您的任何自定义内容，然后重新开始。

    请记住，如果重新选择预构建主题，您的任何自定义内容都将丢失。一旦您得到喜欢的东西，请务必继续进行第 3 步以保存它。

1.  一旦您将主题设置得符合您的喜好，只需单击 **下载主题** 按钮。![行动时间 — 自定义数据表](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_11_img5.jpg)

1.  您将会发现自己在 **构建您的下载** 页面上，可能会有点困惑。请注意，jQuery UI 是如此庞大，提供了如此多的不同功能，开发人员意识到强迫每个人下载整个内容是不合理的。如果您只想使用一个小部件，那么就没必要下载所有其他小部件和效果。这个页面让您选择不同的 jQuery UI 组件，这样您就不必下载您不需要的内容。

    由于我们只需要一个主题，所以我们可以放心地点击页面顶部的 **取消选择所有组件** 链接。

    ![行动时间 — 自定义数据网格](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_11_img6.jpg)

    +   然后，我们将离开 **主题** 和 **版本** 设置为默认值，并点击 **下载** 按钮下载一个 ZIP 文件。

1.  解压文件并查看其中内容。您会看到即使我们得到了最简单的下载，我们仍然有相当多的文件。![行动时间 — 自定义数据网格](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_11_img7.jpg)

    +   我们有一个包含我们的主题文件夹、一个 CSS 文件和 **图像** 的 `css` 文件夹。我们还有一个 `development-bundle` 文件夹、一个 HTML 文件和一个包含 jQuery 和 jQuery UI 文件的 `js` 文件夹。

        我们所需的全部内容就是我们的主题。将您的主题文件夹复制到您自己项目的 styles 目录中。我的主题文件夹被命名为 `cupertino`，因为那是我选择的主题。如果您选择了不同的主题，您的主题文件夹将被命名为其他内容。不过很容易找到，因为它将是 `css` 文件夹内唯一的文件夹。

1.  接下来，我们将把我们的主题 CSS 文件附加到我们的 HTML 文件中。在`<head>`部分内，将您的主题 CSS 文件附加到我们在上一个示例中附加的 `demo_table.css` 文件之前。

    ```js
    <link rel="stylesheet" href="styles/cupertino/jquery-ui-1.8.16.custom.css"/>
    <link rel="stylesheet" href="styles/demo_table.css"/>

    ```

1.  不幸的是，我们的主题 CSS 文件并没有包含我们所需的所有样式来美化数据网格。毕竟，jQuery UI 的开发人员无法知道人们将要使用的所有不同类型的小部件和插件，所以他们不可能覆盖每种情况。幸运的是，DataTables 插件作者 Allan Jardine 在这方面已经为我们做了一些很好的工作，并提供了一个包含我们所需样式的 CSS 文件，以使我们的主题数据网格看起来更好。

    您可以在 Allan Jardine 在 [`datatables.net/styling/`](http://datatables.net/styling/) 上提供的文档中了解如何为 DataTables 插件设置样式。

    回到 DataTables 插件文件内部，打开 `media` 文件夹内的 `css` 文件夹，找到 `demo_table_jui.css` 文件。将其复制到您自己的 styles 文件夹中，并更新您的 `<link>` 标签，以链接到这个版本的 `demo_table.css`，如下所示：

    ```js
    <link rel="stylesheet" href="styles/cupertino/jquery-ui-1.8.16.custom.css"/>
    <link rel="stylesheet" href="styles/demo_table_jui.css"/>

    ```

1.  现在我们只需对 JavaScript 代码进行小小的更新。我们必须告诉`dataTable()`方法，我们要使用 jQuery UI。返回到您的`scripts.js`文件，我们将添加一对花括号，并传递一个键/值对以启用我们的数据表的 jQuery UI 样式：

    ```js
    $(document).ready(function(){
    $('#book-grid').dataTable({
    'bJQueryUI': true
    });
    });

    ```

    如果您现在在浏览器中刷新页面，您会看到数据网格现在使用了与我们在 jQuery UI 主题页面上看到的部件一致的样式：

    ![行动时间-自定义数据网格](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_11_img10.jpg)

    +   但您会注意到，表格行的颜色方案仍然是薰衣草色。

1.  让我们对颜色方案进行一些调整。打开`demo_table_jui.css`。只需更新几行。首先，我们将找到第 281 行，那里定义了表格斑马条纹的颜色，并将其更新为我们想要使用的颜色，如下所示：

    ```js
    tr.odd {
    background-color: #f1f7fb;
    }
    tr.even {
    background-color: white;
    }

    ```

    我选择淡蓝色作为奇数行的颜色，白色作为偶数行的颜色，与我之前选择的 Cupertino 样式相匹配。随意选择与您的选择的主题相匹配的颜色。

1.  接下来，我们将更改当前排序行的颜色方案。你会在第 380 行找到已排序的奇数行的 CSS。我将把我的改成中蓝色，如下所示：

    ```js
    tr.odd td.sorting_1 {
    background-color: #d6e7f4;
    }

    ```

1.  最后，我们可以找到 CSS 中已排序的偶数行在第 392 行。我要把它改成浅蓝色。

    ```js
    tr.even td.sorting_1 {
    background-color: #e4eff8;
    }

    ```

    您可以选择与自己选择的主题协调的颜色。

    现在，如果您在浏览器中刷新页面，您会看到表格的斑马条纹图案与我们的主题相匹配。

    ![行动时间-自定义数据网格](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_11_img8.jpg)

1.  接下来，我们将看看对数据网格进行其他一些自定义。首先，让我们将这些简单的下一页和上一页的分页按钮改成数字。我们将传递另一个键/值对给`dataTable`方法，以将按钮替换为分页数字，如下所示：

    ```js
    $(document).ready(function(){
    $('#book-grid').dataTable({
    'sPaginationType': 'full_numbers',
    'bJQueryUI': true
    });
    });

    ```

    ### 注意

    记住每个键/值对之间要用逗号分隔，但不要在最后一个键/值对之后加逗号。

    +   如果您在浏览器中刷新页面，您会看到简单的按钮已被替换为分页数字，如下图所示：

    ![行动时间-自定义数据网格](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_11_img9.jpg)

1.  我们可能会决定，对于这个特定的数据表，搜索功能并不合适。DataTables 插件提供了一种方法来禁用单个功能。要禁用搜索框过滤，我们将传递另一个键/值对，如下所示：

    ```js
    $(document).ready(function(){
    $('#book-grid').dataTable({
    'sPaginationType': 'full_numbers',
    'bJQueryUI': true,
    'bFilter': false
    });
    });

    ```

    在浏览器中刷新页面，您会看到搜索框消失了。

    ![行动时间-自定义数据网格](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_11_img11.jpg)

1.  您可能已经注意到，默认情况下，DataTables 插件按升序将我们的表按第一列排序，从 A 到 Z。在某些情况下，这可能是可以接受的，但在这种情况下，由于我们正在列出有史以来最畅销的书籍，我们可能想要对表进行排序，以便首先显示销售量最高的书籍。我们将传入一个新的键值对来指定默认排序应使用哪一列以及排序应该采用的方向。

    ```js
    $(document).ready(function(){
    $('#book-grid').dataTable({
    'sPaginationType': 'full_numbers',
    'bJQueryUI': true,
    'bFilter': false,
    'aaSorting': [[4, 'desc']]
    });
    });

    ```

    我们正在使用的键称为`'aaSorting'`，值是列号和排序方向，位于两组方括号内。不要忘记 JavaScript 是从 0 开始计数的，而不是从 1 开始计数。因此，我们表格中的第五列实际上是第 4 列。然后，我们希望将最高的数字放在顶部，所以我们传递 `'desc'` 表示降序排序。

    在浏览器中刷新页面，你会发现图书现在按销售量从高到低的顺序排列。同时，请注意，这种默认排序方式不影响您网站访问者根据任何其他列以任何顺序对表进行排序的能力。访客仍然可以与您的表进行交互。我们只是以最合理的方式重新定义了默认视图，以便呈现我们正在呈现的数据。

## 刚刚发生了什么？

我们将我们的基本数据网格提升了一步，通过定制插件的外观和行为。我们学会了如何使用 jQuery UI Themeroller 创建我们数据网格的自定义主题。然后，我们学会了如何用页码替换简单的分页按钮，禁用搜索表，以及如何为数据网格设置默认排序。

# 摘要

在本章中，我们学会了如何将普通的 HTML 表格转变为交互式数据网格。我们的网站访问者现在可以利用对表的不同列进行排序的功能以不同的方式查看数据。禁用 JavaScript 的网站访问者只会看到包含所有数据的普通 HTML 表格。数据网格并不是非常令人兴奋，但它们可以使您的网站访问者更轻松地处理大量数据。接下来，我们将学习如何使表单既更漂亮又更易于使用。


# 第十二章：改善表单

> 如果你曾经尝试过使用网络表单，你就知道它们可以是多么令人头疼。幸运的是，HTML5 的作者们正在努力确保这种体验得到改善。我们都在耐心地等待浏览器支持那些不错的新功能，但与此同时，我们必须建立站点并制作出漂亮且功能良好的表单。

在本章中，您将学习以下主题：

+   使用一些新的 HTML5 属性标记一个表单

+   将光标放在第一个表单字段中

+   在表单字段中使用占位符文本

+   验证您网站访客的表单输入

+   设计样式顽固的表单元素，如文件上传和选择下拉框

# 一个 HTML5 网络表单

我们将利用 HTML5 中提供给我们的一些新属性开始。这些增加的好处在于它们完全向后兼容。不了解如何处理它们的浏览器将要么忽略它们，要么默认为简单的文本输入，而我们网站上的老式浏览器访客甚至可以在不知道自己错过什么的情况下使用我们的表单。

首先，关于网络表单的一个警告。一个网络表单不能单独工作 —— 它需要在某个服务器上进行一些花哨的后端编程来收集表单条目并处理它们，无论是将字段写入数据库还是通过电子邮件发送表单信息。因此，在点击表单上的 **提交** 按钮后，本章中构建的表单实际上不会起作用 —— 什么也不会发生。

如果您想要在项目中添加一个可用的网络表单，您有几个选择。它们如下：

+   您可以学习进行服务器端编程来处理您的表单，但服务器端编程远远超出了本书的范围。

+   您可以使用 CMS，它可能会将表单处理作为其核心功能或作为附加功能之一。好的候选包括 Drupal、WordPress 和 Joomla！。

+   您可以雇用一个服务器端开发人员来使您的表单工作。或者与一个交朋友，用您的设计技能交换他们的编码技能。

+   您可以使用网络表单服务来处理您表单的所有服务器端处理。我个人最喜欢的是 WuFoo，我已经使用了多年而且没有出现过任何问题。([`wufoo.com`](http://wufoo.com))

任何这些方法都将帮助您创建一个可包含在您的项目中的工作表单。但是，让我们看看如何使我们的表单的前端尽可能好。

# 行动时间 —— 设置 HTML5 网络表单

1.  我们将从一个简单的 HTML 文档和关联的文件和文件夹开始，就像我们在第一章中设置的那样，*设计师，见 jQuery*。我们要确保在文档顶部的文档类型声明中使用 HTML5 文档类型：

    ```js
    <!DOCTYPE html>

    ```

    在 HTML 4 和 xHTML 中使用的所有长而复杂的文档类型声明之后，这个声明简直是一股清新的空气，不是吗？

1.  现在，在`<body>`标签内，按照以下方式打开一个`<form>`标签：

    ```js
    <form action="#" id="account-form">
    </form>

    ```

    `form`标签需要一个`action`属性才能工作。由于我们的表单只是用于脚本和样式目的的虚拟表单，我们将使用#作为该属性的值。`action`属性的值通常是一个 URL——我们将发送表单数据进行处理的服务器上的位置。我们还添加了一个`id`属性，以便稍后轻松选择表单用于 CSS 和 JavaScript 目的。

1.  接下来，我们将为我们的网站访问者创建一个用户名和密码的部分。我们将把这两个字段放在一个`fieldset`中，并使用一个`legend`将它们组合起来。

    ```js
    <form action="#" id="account-form">
    <fieldset>
    <legend>My Account</legend>
    <p>
    <label for="username">Username</label>
    <input type="text" name="username" id="username"/>
    </p>
    <p>
    <label for="password">Password</label>
    <input type="password" name="password" id="password"/>
    </p>
    </fieldset>
    </form>

    ```

    我用段落标签（`<p>`）包装了每个字段及其相关的标签。关于用什么标签标记您的表单字段，世界上有各种各样的意见。有些开发人员喜欢简单的`<div>`标签，而其他人喜欢将表单制作为列表（`<ul>`），每个字段为列表项（`<li>`）。其他人喜欢使用定义列表（`<dl>`），将标签放在`<dt>`标签内，将表单字段放在`<dd>`标签内。归根结底，这些任何一种都可以很好地完成任务，并且您的表单将按预期为您的网站访问者工作。使用您个人偏好的任何标签。

    仔细看看我们到目前为止为我们的表单编写的 HTML 标记。有一些重要的事情需要注意。它们如下：

    +   每个`<input>`的`type`与其用途相关。**用户名**具有`text`类型，而**密码**具有`password`类型。

    +   每个`<input>`都有一个唯一的`id`。请记住，`id`在页面上必须是唯一的，因此请谨慎选择您的表单输入的`id`。

    +   每个`<input>`都有一个`name`属性。这将传递给服务器端处理您的表单的任何代码。通常的做法是为表单元素的`name`和`id`使用相同的值，但这不是强制性的。您可以随时为`id`选择不同的值，但如果您想更改`name`值，您应该首先与您的服务器端开发人员核实他或她编写的代码是否仍然有效。

    +   每个`<label>`都有一个`for`属性，将其与特定的表单元素关联起来。`for`属性中的值等于与之关联的表单元素的`id`（而不是`name`）。这为我们的网站访问者提供了一些很好的功能，点击标签将聚焦于相关的表单元素。这种行为对于复选框和单选按钮输入特别有用，因为它们很小，可能很难点击。

        每个浏览器都有自己的方式来为表单元素设置样式，但这是我的**我的账户**部分的样式（在 Mac OSX 上的 Google Chrome 中）：

    ![行动时间——设置 HTML5 网络表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img14.jpg)

1.  接下来，我们将为我们的表单创建一个**关于我**部分。

    ```js
    <fieldset>
    <legend>About Me</legend>
    <p>
    <label for="name">Name</label>
    <input type="text" name="name" id="name"/>
    </p>
    <p>
    <label for="email">Email address</label>
    <input type="email" name="email" id="email"/>
    </p>
    <p>
    <label for="website">Website</label>
    <input type="url" name="website" id="website"/>
    </p>
    <p>
    <label for="birthdate">Birth Date</label>
    <input type="date" name="birthdate" id="birthdate"/>
    </p>
    </fieldset>

    ```

    同样，**Name**输入使用了`text`类型，因为名称是字符串。然而，看一下**Email、Website**和**Birth Date**字段的`type`属性。我们在这里使用了新的 HTML5 输入类型。在不支持这些输入类型的浏览器中，这些字段将看起来和使用`text`类型的输入框一样工作。但在识别这些输入类型的浏览器中，它们的行为会有所不同。用户输入将被浏览器自动验证。例如，如果站点访客在具有`email`类型的输入框中输入一个无效的电子邮件地址，浏览器会警告他们输入了一个无效的电子邮件地址。

    此外，在具有软键盘的设备上，键盘键将被更改以反映输入该数据类型所需的字符。例如，在 iPhone 或 iPad 上，具有`email`类型的输入将打开一个键盘，显示`.`和`@`，这样使得您的站点访客在这些设备上更容易完成所需的信息输入。

    ![执行动作的时间——设置 HTML5 网络表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img15.jpg)

1.  我表单中的下一部分将是有关饮料偏好的部分。我希望站点访客从列表中选择他们喜欢的饮料，然后回答一个关于他们每年喝多少天饮料的问题。以下是我的列表样本：

    ```js
    <fieldset>
    <legend>Beverage Info</legend>
    <fieldset>
    <legend>Select your favorite beverages</legend>
    <p>Select at least three and no more than six beverages</p>
    <ul>
    <li>
    <input type="checkbox" name="favorites[]" id="bev-water" value="bev-water"/>
    <label for="bev-water">Water</label>
    </li>
    <li>
    <input type="checkbox" name="favorites[]" id="bev-juice" value="bev-juice"/>
    <label for="bev-juice">Juice</label>
    </li>
    </ul>
    </fieldset>
    <p>
    <label for="days">How many days per year do you drink a beverage?</label>
    <input type="number" name="days" id="days"/>
    </p>
    </fieldset>

    ```

    ![执行动作的时间——设置 HTML5 网络表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img16.jpg)

    关于我们用于标记此部分的 HTML 的一些新内容如下：

    +   `Fieldsets`可以嵌套。`fieldset`是将一组复选框或单选按钮分组的绝佳方式，我们可以使用`fieldset`的`legend`来为我们的单选按钮或复选框组创建标题。

    +   一组复选框之所以被识别为复选框，是因为它们将共享相同的`name`。由于站点访客可以在一组复选框中选择多个项目，因此我们在名称的末尾添加方括号（[]），以便服务器将所有答案收集到一个数组中。

    +   集合中的每个复选框都有自己独特的`id`和`value`。`id`和`value`不一定要匹配，但通常很容易使它们相同。

    +   最后，每年的天数被赋予了`number`类型的输入，因为这里只接受数字。对于此输入类型要小心。它非常严格，不会接受任何非数字字符。一些数据位看起来是数字，但实际上是字符串，比如电话号码和信用卡号。如果您不打算对您的数字执行某种数学操作，那么它不应该是`number`输入类型。

1.  我们将添加到表单中的下一个部分是支付信息部分：

    ```js
    <fieldset>
    <legend>Payment Info</legend>
    <fieldset>
    <legend>Credit Card Type</legend>
    <ul>
    <li>
    <input type="radio" name="cc-type" id="cc-visa" value="cc-visa"/>
    <label for="cc-visa">Visa</label>
    </li>
    <li>
    <input type="radio" name="cc-type" id="cc-mastercard" value="cc-mastercard"/>
    <label for="cc-mastercard">Mastercard</label>
    </li>
    <li>
    <input type="radio" name="cc-type" id="cc-amex" value="cc-amex"/>
    <label for="cc-amex">American Express</label>
    </li>
    <li>
    <input type="radio" name="cc-type" id="cc-discover" value="cc-discover"/>
    <label for="cc-discover">Discover</label>
    </li>
    </ul>
    </fieldset>
    <p>
    <label for="cc-number">Credit card number</label>
    <input type="text" name="cc-number" id="cc-number"/>
    </p>
    </fieldset>

    ```

    就像复选框一样，我们在`fieldset`内分组了一组单选控件，`legend`充当了该部分的标题。与复选框类似，一组单选控件共享相同的名称，但每个控件都有自己独特的`id`和值。但是，在单选按钮的情况下，只能选择一个，所以不需要将它们标记为数组。

    我们还添加了一个字段，用于收集我们站点访问者的信用卡号码。请注意，我们将此字段的输入类型设置为`text`。即使信用卡号看起来是一个数字，我们也希望将它存储为它本来的样子，永远不会对这个数字进行加减操作。此外，客户可能希望在他们的信用卡号中输入空格或连字符。

    ![行动时间——设置 HTML5 网页表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img17.jpg)

1.  最后，我们将添加一个复选框，供我们的站点访问者接受我们的服务条款，并添加一个提交按钮，让他们向我们提交表单信息。

    ```js
    <fieldset>
    <ul>
    <li>
    <input type="checkbox" name="tos" id="tos" value="tos"/>
    <label for="tos">Click here to accept our terms of service</label>
    </li>
    </ul>
    <p>
    <input type="submit" value="Sign me up!"/>
    </p>
    </fieldset>

    ```

    这里唯一的新东西就是**提交**按钮。默认情况下，带有`submit`类型的输入框将显示**提交**。我们可以通过添加一个带有实际想要出现在按钮上的文本的`value`属性来更改它。

    ![行动时间——设置 HTML5 网页表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img18.jpg)

1.  唯一剩下的事情就是用一点 CSS 为我们的表单添加样式。以下是我为我的简单表单使用的 CSS：

    ```js
    fieldset { width:400px;margin:0;padding:10px;border:1px solid #c1c3e6;background:#f1f2fa;margin-top:10px; }
    fieldset fieldset { border:0 none;border-top:1px solid #c1c3e5;border-bottom:1px solid #c1c3e5;width:380px;margin-bottom:10px; }
    legend { padding:3px 5px;color:#6c71c4;font-weight:bold;font-size:1.2em; }
    fieldset fieldset legend { font-size:1em;font-weight:normal; }
    fieldset p { margin: 0 0 10px 0; }
    fieldset ul { margin:0;padding:0;list-style:none; }
    label { display:inline-block;width:150px; }
    ul label { display:inline;width:auto; }
    input[type="text"],
    input[type="password"],
    input[type="email"],
    input[type="url"],
    input[type="date"],
    input[type="number"] { width:150px;border:1px solid #c1c3e6;padding:4px; }

    ```

    注意我们输入框的`type`属性可用于选择它们进行样式设置。在这种情况下，我已经将它们全部样式设置为相同，但如果需要的话，也可以为每个输入框设置自己的样式。

    这是我的 CSS 样式的表单外观。随意发挥创造力，为表单编写你自己的样式。

    ![行动时间——设置 HTML5 网页表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img19.jpg)

## 刚才发生了什么？

我们看了一些新的 HTML5 输入类型以及如何正确使用它们来组合一个网页表单。我们了解了如何使用`fieldset`和`legend`来将字段组合在一起并添加标题，以及如何将标签与表单元素关联起来。我们学习了文本、密码、电子邮件、URL、日期、复选框、单选按钮和数字输入类型的正确使用。

# 设置焦点

如果你访问[`google.com`](http://google.com)，你会发现他们让你很容易进行网页搜索——只要页面在浏览器中加载完成，光标就会在搜索字段中闪烁。还有其他一些网站也是这样做的，这样就可以快速轻松地开始填写表单。

每当你有一个页面，站点访问者在该页面的主要任务是填写表单时，你都可以通过将光标放在第一个表单字段中来为站点访问者提供便利。使用 jQuery 很容易实现。以下是如何做的。

# 行动时间——将焦点设置到第一个字段

我们将继续使用上一个示例中设置的示例表单进行操作。以下是如何将焦点设置到表单中的第一个字段。

1.  打开你的空白`scripts.js`文件，并添加一个文档就绪的声明。

    ```js
    $(document).ready(function(){
    //code goes here
    });

    ```

1.  接下来，我们想要选择表单中的第一个字段。有许多不同的方法可以做到这一点。在这种情况下，我将使用第一个表单元素的`id`。

    ```js
    $(document).ready(function(){
    $('#username');
    });

    ```

1.  剩下的就是调用那个元素的`focus()`方法。

    ```js
    $(document).ready(function(){
    $('#username').focus();
    });

    ```

    现在，如果你在浏览器中刷新页面，你会看到光标在表单的**用户名**字段中闪烁——正是第一个字段。

## 刚才发生了什么？

我们使用了几行 jQuery 代码来将焦点移动到表单中的第一个字段，这样我们的网站访问者可以轻松地开始填写表单。只需选择第一个表单元素，然后调用该元素的`focus()`方法即可。

# 占位文本

当你访问一个网站时，有一个软灰色的文本在表单字段中给你一些提示，这不是很好吗？过去几年里已经写了无数不同的 jQuery 插件来处理这个问题，因为这可能有点麻烦。

但是，我有个好消息要告诉你。HTML5 提供了一个`placeholder`属性，可以自动在表单字段中创建这种文本，而无需 JavaScript 的帮助。当然，与任何其他尖端技术一样，浏览器支持可能有些欠缺。我们没有等待多年让浏览器支持这一新功能变得普遍——我们现在就必须构建功能性的网站。你可以继续使用所有那些旧的 jQuery 插件，但如果支持 placeholder 属性，为什么不利用它，并只在那些尚未识别它的浏览器中使用 jQuery 来填补空白呢？

这种脚本称为**polyfill**。它用于填补一些浏览器可能缺少的功能。如果浏览器支持`placeholder`属性，polyfill 脚本就什么都不做，只是让浏览器处理占位符。对于那些不支持`placeholder`属性的网站访问者，脚本会立即生效，为所有人提供占位文本功能。

# 是时候行动起来了——添加占位文本

按照以下步骤，为尽可能多的网站访问者添加表单字段的占位文本，无论他们的浏览器是否支持新的 HTML5 占位属性。

1.  我们将继续使用我们在前两节中构建的相同表单。我们首先要做的是重新检查每个表单字段，并在合适的地方添加一个占位属性。以下是我的表单中的一些示例：

    ```js
    <p>
    <label for="username">Username</label>
    <input type="text" name="username" id="username" placeholder="At least 5 characters long"/>
    </p>

    ```

    在这里，我增加了关于用户名所需长度的提示。

    ```js
    <p>
    <label for="password">Password</label>
    <input type="password" name="password" id="password" class="required" placeholder="Choose a secure password"/>
    </p>

    ```

    因为再怎么说都不嫌多，我在这里提醒我的网站访问者创建一个安全的密码。

    ```js
    <p>
    <label for="website">Website</label>
    <input type="url" name="website" id="website" placeholder="Don't forget the http://"/>
    </p>

    ```

    提醒网站访问者，有效的 URL 包括开头的协议。

    ```js
    <p>
    <label for="birthdate">Birth Date</label>
    <input type="date" name="birthdate" id="birthdate" placeholder="yyyy-mm-dd"/>
    </p>

    ```

    任何时候一个字段需要特殊格式，占位文本都可以为网站访问者提供提示。

    当你添加完占位符文本后，可以在 Safari 或 Chrome 中查看你的页面，以查看占位符文本的效果。

    ![行动时间——添加占位符文本](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img20.jpg)

    +   现在我们需要为那些尚未支持占位符文本的浏览器添加支持。

1.  我们将使用丹·本特利（Dan Bentley）的占位符兼容性补丁。要下载它，只需访问 [`github.com/danbentley/placeholder`](http://https://github.com/danbentley/placeholder)。就像我们从 GitHub 下载的其他插件一样，点击 **ZIP** 按钮下载一个压缩文件夹。![行动时间——添加占位符文本](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img1.jpg)

1.  解压文件夹并查看其内容。这是一个非常简单直接的插件。![行动时间——添加占位符文本](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img2.jpg)

    +   您有一个样本 `index.html` 文件，一个 `style.css` 文件和一个 `jquery.placeholder.js` 文件，以及一个许可证和一个自述文件。

1.  有关此插件的好消息是，它只需在页面上存在即可发挥其魔力。将 `jquery.placeholder.js` 复制到您自己的 `scripts` 文件夹中。然后，转到页面底部，并在 jQuery 之后、您自己的 `scripts.js` 文件之前将脚本附加到页面上：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/jquery.placeholder.js"></script>
    <script src="img/scripts.js"></script>

    ```

    现在，如果您在不支持占位符属性的浏览器中打开页面，您将看到占位符正常工作。这些浏览器是 Firefox 3.6 及更低版本，Safari 3 及更低版本，Internet Explorer 9 及更低版本以及 Opera 10 及更低版本。

## 刚刚发生了什么？

我们使用了丹·本特利的占位符兼容性补丁来为不支持的浏览器添加占位符支持。我们在适当的地方给表单字段添加了 `placeholder` 属性，然后在我们的页面上包含了丹的脚本，以使这些占位符属性在尽可能多的浏览器中工作。

# 验证用户输入

有时，当网站访问者不得不多次提交表单来纠正他们填写的错误时，他们可能会感到沮丧。没有 JavaScript，验证网站访问者输入的信息的唯一方法是等待他们提交表单，然后在服务器上识别问题，并返回一个包含表单以及可能帮助网站访问者纠正问题的任何错误消息的页面。

一旦出现错误，立即显示错误将大大提高您的表单的灵活性和响应性，并帮助您的网站访问者在第一次尝试时正确提交表单。在本节中，我们将学习如何使用 Jörn Zaefferer 的验证插件。此插件功能强大且灵活，可以以多种不同的方式处理验证。我们将看一下将客户端验证添加到您的表单中最简单的方法。

# 行动时间——即时验证表单值

我们将继续使用我们在过去三个部分中创建的表单。按照以下步骤验证用户对表单的输入：

1.  我们要做的第一件事是下载验证插件并将其附加到我们的页面上。

    前往[`bassistance.de/jquery-plugins/jquery-plugin-validation/`](http://bassistance.de/jquery-plugins/jquery-plugin-validation/)，并在**Files**部分点击**Download**按钮下载 ZIP 文件。

    ![行动时间——动态验证表单值](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img3.jpg)

1.  打开 ZIP 文件并看看我们得到了什么。![行动时间——动态验证表单值](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img4.jpg)

    +   这里有很多内容。几个不同的 JavaScript 文件，一个更改日志等等。记得我说过这个插件功能强大，可以处理各种各样的验证方法吗？这就是所有这些的用途。处理几乎任何你可能遇到的旧的疯狂的验证情况。

        幸运的是，我们的情况相当简单，所以我们不需要做任何复杂的事情。

1.  将`jquery.validate.min.js`复制到您自己的`scripts`文件夹并将其附加到您的页面。

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/jquery.placeholder.js"></script>
    <script src="img/jquery.validate.min.js"></script>

    ```

    在这种情况下，占位符脚本与验证脚本之间没有依赖关系，因此它们出现的顺序不重要，只要它们都在 jQuery 之后即可。

1.  接下来，我们将回顾一下我们的表单，并添加一些验证插件将使用的信息。让我们从用户名字段开始：

    ```js
    <p>
    <label for="username">Username</label>
    <input type="text" name="username" id="username" placeholder="At least 5 characters long" minlength="5" maxlength="20" class="required"/>
    </p>

    ```

    这是一个必填字段——任何填写此表单的网站访问者都必须选择一个用户名，所以我只需添加一个`class`为`required`。如果我愿意，我可以使用该类名为此表单字段创建特殊的样式。即使我不这样做，验证也会使用此信息确保此字段已填写。

    接下来，所有用户名必须介于 5 到 20 个字符之间。所以我添加了`minlength`和`maxlength`属性。

1.  接下来是密码字段，它也是必填的。所以我会添加所需的类。

    ```js
    <p>
    <label for="password">Password</label>
    <input type="password" name="password" id="password" class="required" placeholder="Choose a secure password"/>
    </p>

    ```

    顺便说一句，我也会在电子邮件字段中添加所需的类。

    ```js
    <p>
    <label for="email">Email address</label>
    <input type="email" name="email" id="email" placeholder="you@example.com" class="required"/>
    </p>

    ```

1.  接下来，让我们看一下喜爱饮料的列表。记得我们在那里给网站访问者留了一条注释，要求他们至少选择三种但不要超过六种？我们实际上可以通过验证插件来强制执行。进入系列中的第一个复选框并添加`minlength`和`maxlength`属性，如下所示：

    ```js
    <li>
    <input type="checkbox" name="favorites[]" id="bev-water" value="bev-water" maxlength="6" minlength="3"/>
    <label for="bev-water">Water</label>
    </li>

    ```

    我们只需要在第一个复选框上添加这个，而不是所有的复选框。验证足够智能，可以理解我们谈论的是这组复选框。

1.  现在，让我们看一下我们询问网站访问者每年喝多少天饮料的领域。显然，一年只有 365 天，这是他们可以在这个领域输入的最高数字。所以我们会添加一个`max`属性来指定最高可能的数字。

    ```js
    <p>
    <label for="days">How many days per year do you drink a beverage?</label>
    <input type="number" name="days" id="days" max="365"/>
    </p>

    ```

1.  这将我们带到了支付部分。无论我们在卖什么，它都不是免费的，所以我们将要求输入信用卡类型和信用卡号。要求输入单选按钮，我们只需要在一组中的第一个单选按钮中添加`required`类。

    ```js
    <li>
    <input type="radio" name="cc-type" id="cc-visa" value="cc-visa" class="required"/>
    <label for="cc-visa">Visa</label>
    </li>

    ```

    我们不必对单选按钮系列进行任何其他更改。

1.  现在，让我们处理信用卡号本身。我们需要添加`required`类。我们还需要添加一个`creditcard`类来验证输入的号码实际上是一个有效的信用卡号。

    ```js
    <p>
    <label for="cc-number">Credit card number</label>
    <input type="text" name="cc-number" id="cc-number" placeholder="xxxxxxxxxxxxxxxx" class="creditcard required"/>
    </p>

    ```

1.  而在我们的表单底部，有我们的**服务条款**复选框。这也是必需的，所以我们将添加`required`类。

    ```js
    <li>
    <input type="checkbox" name="tos" id="tos" class="required" value="tos"/>
    <label for="tos">Click here to accept our terms of service</label>
    </li>

    ```

1.  现在，我们只需要调用 Validation 使我们可以使用的`validate()`方法。在你的文档准备好的声明中，选择表单并调用`validate()`方法。

    ```js
    $(document).ready(function(){
    $('#username').focus();
    $('#account-form').validate();
    });

    ```

1.  现在，如果您在浏览器中刷新页面，您将看到您无法在没有填写任何内容的情况下提交表单 - 必填字段将被标记为错误消息，说明该字段是必需的。如果您尝试在**网站**或**电子邮件地址**字段中输入无效的网址或电子邮件地址，您将收到一条错误消息，让您知道需要纠正的问题。只是一个问题，这些错误消息在我们的复选框和单选按钮的位置有点奇怪。![动作时间-即时验证表单值](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img5.jpg)

    +   那实际上并不能帮助人们准确理解发生了什么。幸运的是，Validation 允许我们在页面上添加自己的错误消息，无论我们想要它们显示在哪里。

1.  我们将在信用卡类型单选按钮列表后添加错误消息。

    ```js
    <li>
    <input type="radio" name="cc-type" id="cc-discover" value="cc-discover"/>
    <label for="cc-discover">Discover</label>
    </li>
    </ul>
    <label for="cc-type" class="error">Select a credit card type!</label>
    </fieldset>

    ```

    我们将添加一个`<label>`。在这种情况下，for 属性将指向字段的`name`，所有单选按钮共享`cc-type`名称。我们将添加一个错误类，并在内部添加我们想要的任何`error`消息。

    注意，在这种情况下，我们的`label`的`for`属性指的是字段的`name`，而不是 ID。这是 Validation 插件创建的特殊情况。如果你不是使用 Validation 插件的自定义错误消息，那么你的标签的`for`属性应该始终引用表单元素的`id`。

1.  接下来，我们不希望这些错误消息出现在页面上，除非它们是需要的。我们也希望它们以红色显示，这样它们就很显眼，易于找到。打开你的`styles.css`文件，为错误消息添加一些样式：

    ```js
    label.error { display:none;width:360px;color:#dc522f;margin-top:5px; }

    ```

    我们添加了一个宽度，因为我已经将我的其他标签设置为短并且浮动到左侧。并且我们添加了一点边距，为了在错误消息和它所指的字段之间添加一些空间。

    现在如果你刷新浏览器，并尝试在没有选择信用卡类型的情况下提交表单，你将得到一个更好的错误消息位置，如下所示：

    ![动作时间-即时验证表单值](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img6.jpg)

1.  接下来，我们需要为我们喜爱的饮料和我们的**服务条款**复选框做同样的事情：这是我们将添加的喜爱的饮料：

    ```js
    <li>
    <input type="checkbox" name="favorites[]" id="bev-wine" value="bev-wine"/>
    <label for="bev-wine">Wine</label>
    </li>
    </ul>
    <label for="favorites[]" class="error">Please select at least three and no more than six favorite beverages</label>
    </fieldset>

    ```

    这是我们将添加的**服务条款：**

    ```js
    <fieldset>
    <ul>
    <li>
    <input type="checkbox" name="tos" id="tos" class="required"/>
    <label for="tos">Click here to accept our terms of service</label>
    </li>
    </ul>
    <label for="tos" class="error">You must accept our terms of service</label>
    <p>
    <input type="submit"/>
    </p>
    </fieldset>

    ```

现在，如果您在浏览器中刷新页面，并且尝试在没有完成必填字段或在表单中输入无效信息的情况下提交表单，您将在检测到问题时立即得到适当的错误消息。

## 刚才发生了什么？

我们使用验证插件向表单添加了一些简单的客户端验证。使用验证插件的最简单方法就是向表单元素添加一些类名和属性。验证插件会处理剩下的事情——它足够智能，能够识别 HTML5 输入类型并验证这些类型，并提供一些其他有用的验证规则，如必填字段、最大数字值、最小和最大长度以及信用卡号码。我们添加了一行 CSS 来样式化我们想要的错误消息。

# 改善外观

如果你尝试过用 CSS 样式化 Web 表单，那么你可能发现一些表单元素，如文本输入和按钮，非常容易样式化。有一些怪癖，但一旦你弄清楚了，你就可以让这些表单元素看起来几乎任何你想要的样子。然而，其他一些表单元素却更为顽固，对 CSS 样式几乎没有什么响应。设计一个可爱的表单，然后意识到从技术上讲它是不可能的，这实在令人沮丧。

这些令人头痛的表单元素是：

```js
<select>
<input type="file">
<input type="checkbox">
<input type="radio">

```

不仅这四个表单元素在 CSS 中无法样式化，而且它们在不同浏览器和操作系统中的外观差异巨大，让我们对表单的外观几乎没有控制。让我们看看 Pixel Matrix 的 Uniform 插件如何帮助我们。

# 行动时间 — 改善表单外观

按照以下步骤利用 Uniform 插件实现可能的样式选项：

1.  我们会从一个基本的 HTML 文件和相关文件和文件夹开始，就像我们在第一章中设置的那样，*设计师，见到 jQuery*。例如，在 HTML 文档的正文中，我们将建立一个简单的表单，其中包含每种难以样式化的表单元素的示例。从`<form>`标签开始：

    ```js
    <form id="pretty-form" action="#">
    </form>

    ```

1.  然后，在我们的表单中，我们将添加我们的表单元素。我们将从一个`select`下拉框开始：

    ```js
    <fieldset>
    <legend>Select your favorite juice</legend>
    <p>
    <label for="juice">Favorite Juice</label>
    <select id="juice" name="juice">
    <option>Select one</option>
    <option value="orange">Orange Juice</option>
    <option value="grape">Grape Juice</option>
    <option value="grapefruit">Grapefruit Juice</option>
    <option value="cranberry">Cranberry Juice</option>
    <option value="tomato">Tomato Juice</option>
    <option value="pineapple">Pineapple Juice</option>
    <option value="apple">Apple Juice</option>
    </select>
    </p>
    </fieldset>

    ```

    我们遵循了与上一个表单相同的规则，确保表单正常工作并且易于访问。

    `<select>`的外观将取决于您的浏览器和操作系统，但在我这里，它在 Chrome 上的 Mac OSX 上的样子是这样的：

    ![行动时间 — 改善表单外观](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img21.jpg)

1.  接下来，我们将添加一个文件输入。

    ```js
    <fieldset>
    <legend>Fruit Picture</legend>
    <p>
    <label for="fruit-photo">Upload a photo of your favorite fruit</label>
    <input type="file" id="fruit-photo" name="fruit-photo"/>
    </p>
    </fieldset>

    ```

    很难相信这个看似无害的标签竟然可能是如此头痛的样式来源，但事实就是如此。这是 Chrome 在 Mac OSX 上的样子：

    ![行动时间 — 改善表单外观](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img22.jpg)

1.  接下来，让我们添加一些复选框，如下所示：

    ```js
    <fieldset>
    <legend>Which hot beverages do you enjoy?</legend>
    <ul>
    <li>
    <input type="checkbox" name="hot-bevs[]" id="hot-coffee">
    <label for="hot-coffee">Coffee</label>
    </li>
    <li>
    <input type="checkbox" name="hot-bevs[]" id="hot-chocolate">
    <label for="hot-chocolate">Hot Chocolate</label>
    </li>
    <li>
    <input type="checkbox" name="hot-bevs[]" id="hot-tea">
    <label for="hot-tea">Tea</label>
    </li>
    </ul>
    </fieldset>

    ```

    ![行动时间 — 改善表单外观](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img23.jpg)

1.  然后是一些单选按钮。

    ```js
    <fieldset>
    <legend>Select your favorite soft drink</legend>
    <ul>
    <li>
    <input type="radio" name="soft-drinks" id="soda"/>
    <label for="soda">Soda</label>
    </li>
    <li>
    <input type="radio" name="soft-drinks" id="sparkling-water"/>
    <label for="sparkling-water">Sparkling water</label>
    </li>
    <li>
    <input type="radio" name="soft-drinks" id="iced-tea"/>
    <label for="iced-tea">Iced Tea</label>
    </li>
    <li>
    <input type="radio" name="soft-drinks" id="lemonade"/>
    <label for="lemonade">Lemonade</label>
    </li>
    </ul>
    </fieldset>

    ```

    ![行动时间 — 改善表单外观](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img24.jpg)

1.  我们将向表单中添加的最后一件事只是一些易于样式化的元素，以便我们学习如何将它们样式化以匹配我们的 Uniform 样式：

    ```js
    <fieldset>
    <legend>Some other stuff about me</legend>
    <p>
    <label for="name">My name</label>
    <input type="text" id="name" name="name"/>
    </p>
    <p>
    <label for="about-me">About me</label>
    <textarea rows="10" cols="40" id="about-me" name="about-me"></textarea>
    </p>
    </fieldset>
    <p class="buttons">
    <input type="submit"/>
    <input type="reset"/>
    </p>

    ```

    ![执行动作的时间 — 改善表单外观](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img25.jpg)

## 刚才发生了什么？

现在我们设置了未经样式处理的表单。我们的表单实际上看起来取决于您的浏览器和操作系统。我们按照本章前面建立的所有正确和可访问的表单设置规则进行设置。但是，这一次，我们包含了一些难以样式化的表单元素。现在让我们看看如何使用 Uniform 插件 —— 让我们的表单在尽可能多的浏览器中保持一致。

## 样式化无法样式化的元素

如果你想抽出一点时间尝试写一些 CSS 来样式化这些表单元素，你会发现它们几乎没什么影响。其中一些似乎根本不受 CSS 的影响，而当它们受到影响时，效果并不总是符合您的期望。难怪这些表单字段让每个人都头疼。JQuery 来拯救。

# 时间来采取行动 —— 添加用于为无样式元素添加样式的 Uniform

使用 Uniform 插件控制表单元素的样式，请按以下步骤操作：

1.  让我们获取 Uniform 插件并看看它是如何工作的。前往 [`uniformjs.com/`](http://uniformjs.com/) 并点击大的**下载 Uniform**按钮。![执行动作的时间 — 添加用于为无样式元素添加样式的 Uniform](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img7.jpg)

1.  解压文件夹并查看其中的内容。![执行动作的时间 — 添加用于为无样式元素添加样式的 Uniform](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img8.jpg)

    +   这很简单，对吧？一些样式，一个演示，一些图片，以及两个版本的 Uniform 插件 —— 一个压缩和一个未压缩。我们以前见过这个。

        默认情况下，Uniform 自带一个默认样式表和图片。但是，还有其他样式可用。回到 `uniformjs.com`，如果在导航中点击**主题**，您将看到当前可用的主题。我非常喜欢 Aristo 的外观，所以我要下载它。

    ![执行动作的时间 — 添加用于为无样式元素添加样式的 Uniform](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img9.jpg)

    +   这给我一个简单的 ZIP 文件，里面只有一些 css 和图片：

    ![执行动作的时间 — 添加用于为无样式元素添加样式的 Uniform](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img10.jpg)

1.  接下来，我们需要将这些文件放入我们自己的项目中，并附加到我们的 HTML 页面中。让我们从 JavaScript 开始。将 `jquery.uniform.min.js` 复制到您自己的 `scripts` 文件夹中，并将 Uniform 脚本在 jQuery 和您自己的 `scripts.js` 文件之间引用：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/jquery.uniform.min.js"></script>
    <script src="img/scripts.js"></script>
    </body>

    ```

1.  现在将您想要使用的主题的 CSS 文件复制到您自己的 `styles` 文件夹中，并在文档的头部引用它：

    ```js
    <head>
    <title>Chapter 12: Improving Forms</title>
    <link rel="stylesheet" href="styles/uniform.aristo.css"/>
    <link rel="stylesheet" href="styles/styles.css"/>

    ```

1.  我们需要获取的最后一样东西是关联的图片。将您选择的主题的图像文件夹的内容复制到您自己的 `images` 文件夹中。现在，您自己项目的结构应该看起来类似于以下截图:![执行动作的时间 — 添加用于为无样式元素添加样式的 Uniform](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img11.jpg)

1.  现在，我们可以调用 `uniform()` 方法来为我们的无法样式化的表单元素添加样式了。打开您的 `scripts.js` 文件，并插入一个文档就绪语句：

    ```js
    $(document).ready(function(){
    //our code will go here
    });

    ```

1.  Uniform 允许我们选择我们想要样式化的表单元素。在这种情况下，我们想要样式化所有四个顽固的元素，所以我们的选择器将是：

    ```js
    $(document).ready(function(){
    $('select, input:checkbox, input:radio, input:file');
    });

    ```

1.  然后，剩下的就是调用 `uniform()` 方法：

    ```js
    $(document).ready(function(){
    $('select, input:checkbox, input:radio, input:file').uniform();
    });

    ```

    现在，如果您在浏览器中刷新页面，您将看到这些顽固且不可样式化的表单元素现在与您选择的 Uniform 主题相匹配。

    ![行动时间 — 为不可样式化的元素添加统一样式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img26.jpg)

+   仍然有一些奇怪的 CSS 问题需要处理，我们的 fieldsets、legends、按钮和文本输入框不匹配。让我们写一点 CSS 将它们整合在一起。

## 所有样式

我们还有一些 CSS 问题需要解决 — 我们的复选框和单选按钮列表仍然有它们的项目符号，我们的文本输入、按钮、fieldsets 等仍未经过样式化。让我们将所有东西都样式化，以匹配我们选择的 Uniform 主题。

# 行动时间 — 为可样式化元素添加样式

1.  打开您的 `styles.css` 文件。我们将从样式化 fieldsets 和 legends 开始：

    ```js
    fieldset {
    background: #fff;
    border: 1px dotted #83b0ca;
    margin: 10px 20px 0 20px;
    padding:10px;
    }
    legend {
    background: #bed6e3;
    border:1px solid #8fb7cf;
    color: #1C4257;
    padding: 0 5px;
    box-shadow:2px 2px 2px rgba(0,0,0,0.2);
    }

    ```

    我选择了与我选用的 Aristo 主题相匹配的蓝色。如果您选择了不同的主题，请随意使用不同的颜色和样式来匹配您选择的主题。

1.  接下来，我们将为表单中使用的某些容器元素添加样式：

    ```js
    fieldset p {
    margin: 0 0 10px 0;
    }
    fieldset ul {
    list-style: none;
    margin: 0;
    padding: 0;
    }
    label {
    display: block;
    }
    ul label {
    display: inline;
    width: auto;
    }
    p.buttons {
    margin: 20px;
    }

    ```

1.  接下来，我们将为文本输入和文本区域添加一些样式，以匹配我们的 Aristo 表单元素：

    ```js
    input[type="text"],
    textarea {
    border: 1px solid #ccc;
    border-radius: 3px;
    box-shadow: inset 0 0 4px rgba(0,0,0,0.3);
    moz-border-radius: 3px;
    moz-box-shadow: inset 0 0 4px rgba(0,0,0,0.3);
    padding: 4px;
    webkit-border-radius: 3px;
    webkit-box-shadow: inset 0 0 4px rgba(0,0,0,0.3);
    width: 250px;
    }

    ```

1.  最后，但同样重要的是，我们将样式化我们的按钮。Aristo 主题使用了一个漂亮的蓝色渐变，所以我将为我的按钮使用渐变。我将不得不为支持所有浏览器编写相当多的代码，但这是它：

    ```js
    input[type='submit'],
    input[type='reset'] {
    background: rgb(185,224,245);
    background: linear-gradient(top, rgba(185,224,245,1) 0%,rgba(131,176,202,1) 100%);
    background: -moz-linear-gradient(top, rgba(185,224,245,1) 0%, rgba(131,176,202,1) 100%);
    background: -ms-linear-gradient(top, rgba(185,224,245,1) 0%,rgba(131,176,202,1) 100%);
    background: -o-linear-gradient(top, rgba(185,224,245,1) 0%,rgba(131,176,202,1) 100%);
    background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,rgba(185,224,245,1)), color-stop(100%,rgba(131,176,202,1)));
    background: -webkit-linear-gradient(top, rgba(185,224,245,1) 0%,rgba(131,176,202,1) 100%);
    border: solid 1px #6e93b0;
    border-radius: 2px;
    box-shadow: rgba(0,0,0,0.15) 0px 1px 3px;
    color: #1C4257;
    cursor: pointer;
    display: inline-block;
    filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#b9e0f5', endColorstr='#83b0ca',GradientType=0 );
    filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#eef3f8', endColorstr='#96b9d4',GradientType=0 );
    font-size: 1em;
    font-weight: bold;
    height: 27px;
    line-height: 26px;
    margin-right: 5px;
    moz-border-radius: 2px;
    moz-box-shadow: rgba(0,0,0,0.15) 0px 1px 3px;
    padding: 0 10px;
    text-shadow: rgba(255,255,255,0.5) 0px 1px 0px;
    webkit-border-radius: 2px;
    webkit-box-shadow: rgba(0,0,0,0.15) 0px 1px 3px;
    }
    input[type='submit']:hover,
    input[type='reset']:hover {
    color: #0b1b24;
    }
    input[type='submit']:active,
    input[type='reset']:active {
    background: rgb(131,176,202);
    background: linear-gradient(top, rgba(131,176,202,1) 0%,rgba(185,224,245,1) 100%);
    background: -moz-linear-gradient(top, rgba(131,176,202,1) 0%, rgba(185,224,245,1) 100%);
    background: -ms-linear-gradient(top, rgba(131,176,202,1) 0%,rgba(185,224,245,1) 100%);
    background: -o-linear-gradient(top, rgba(131,176,202,1) 0%,rgba(185,224,245,1) 100%);
    background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,rgba(131,176,202,1)), color-stop(100%,rgba(185,224,245,1)));
    background: -webkit-linear-gradient(top, rgba(131,176,202,1) 0%,rgba(185,224,245,1) 100%);
    filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#83b0ca', endColorstr='#b9e0f5',GradientType=0 );
    }

    ```

    我在鼠标悬停时添加了微妙的文字颜色变化，并在点击按钮时反转了渐变。现在，刷新浏览器中的页面，看看我们美丽的表单。

    ![行动时间 — 为可样式化元素添加样式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img12.jpg)

## 刚才发生了什么？

我们使用了 Pixelmatrix 的 Uniform jQuery 插件来样式化以前顽固且无法样式化的表单元素。我们选择了一个预设主题，并将所有相关的 CSS 和图像附加到我们的页面上，然后选择我们想要样式化的每一种表单元素，并调用 `uniform()` 方法。然后，我们使用我们的 CSS 技能来样式化其他表单元素，如简单的文本输入、文本区域和一些按钮，以匹配我们选择的主题。结果是一个漂亮的表单，在不同的浏览器中看起来一致，并且对于禁用 JavaScript 的用户仍然完美地工作。

## 我们自己的主题

当然，这个 Aristo 主题很不错，但是如果它不匹配我们的网站怎么办？我们还有其他选择吗？当然有！如果预设的主题都不符合您的网站，您可以使用自己的样式和颜色制作自己的主题，以匹配您喜欢的任何网站。事实上，Pixelmatrix 已经使这变得超级简单了。以下是您可以做到的：

# 行动时间 — 创建自定义的统一主题

1.  首先从 Pixelmatrix 下载主题工具包。你可以在 [uniformjs.com](http://uniformjs.com) 的主题部分找到它！行动时间 — 创建自定义 Uniform 主题

1.  解压缩文件夹，里面有两个 PSD 文件 — `sprite.psd` 和 `sprites.psd`。在 Photoshop 中打开 `sprite.psd` 并按照您的喜好为表单元素添加样式。如果您想要更大或更小的表单元素，您可以更改元素的大小。`Sprites.psd` 仅用于说明每种样式的用途。您可以将其用作参考，以确保覆盖所有可能性，但实际上您不需要使用它来创建您的主题。

1.  当你的精灵准备好时，转到 [`uniformjs.com/themer.html`](http://uniformjs.com/themer.html)。![行动时间 — 创建自定义 Uniform 主题](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/jq-dsnr-bgd/img/6709OS_12_img13.jpg)

    +   填写表单，包括选择精灵的高度、复选框和单选按钮的宽度和高度，以及文件输入的高度。然后点击生成代码。生成用于使 Uniform 与你的精灵配合工作所需的 CSS 将为您生成。将其复制粘贴到 CSS 文件中并保存到您的项目中。

1.  将你的新 CSS 文件附加到 HTML 文档中，并将你的精灵保存为 PNG 文件，保存到你项目的`images`文件夹中，然后你应该一切就绪了。你可能会发现一些需要进行微小调整的地方，但设置一个自定义 Uniform 主题就是这么简单。

### 注意

如果您想将您的主题贡献给 Uniform 社区，让其他设计师和开发人员使用，您可以通过将您的主题的 zip 文件发送到 `<josh@pixelmatrixdesign.com>` 来将其提交给 Pixelmatrix。

## 刚刚发生了什么？

我们学习了如何使用 Pixelmatrix 提供的主题工具包和自定义主题 CSS 生成器，快速轻松地创建我们自己的 Uniform 主题。

# 概要

嗯，这就结束了有关表单的章节。我们学会了如何正确使用新的 HTML5 表单元素来创建一个功能完美且易于访问的表单。我们学会了如何将焦点放在表单中的第一个字段上，在所有浏览器中使用占位文本，验证我们网站访客的表单输入，并为那些难以样式化的固执和臭名昭著的表单元素添加样式。现在你拥有了一系列工具来创建在你的网站上增强你的网站访客体验的美观表单。最重要的是，它们都能够在禁用 JavaScript 的用户上优雅地降级，因为我们采用了渐进增强的思维方式来处理我们的表单 —— 首先构建一个可工作的表单，然后逐步添加增强功能，以供那些浏览器支持的网站访客使用。

我知道对于设计师来说，JavaScript 可能是一个可怕的主题。感谢你一直陪伴我到书的最后！我希望现在你对 jQuery 有了基本的理解，并且确信自己能够自信地应对下一个 JavaScript 挑战。你知道如何有效地利用 jQuery 库来增强你的网站。你知道如何找到好的插件，快速轻松地编写交互功能。你知道 CSS 和 JavaScript 如何共同工作，以增强网站访客在你的网站上的体验。你也知道，如果遇到困难，网络上有很多教程、资源、帮助论坛、文章和讨论可以帮助你。

对于 jQuery 而言，每一次发布都会变得更加出色 — 更加简洁、更快、更有能力。jQuery 团队会注意保持文档的更新，因此你总能弄清楚如何使用每个方法。jQuery 团队聪明而迅速，新的 jQuery 更新定期发布。所有这些都指向一个活跃且有用的库，在 Web 上的受欢迎程度将继续增长。它是许多程序员的最爱，从经验丰富的黑客到像你这样的初学者。

希望你喜欢这本书，并且它给你带来了许多新的想法，可以为你的网站设计和构建交互式元素。一定要与 jQuery 社区保持联系 —— 这将是你在进一步改进和发展 JavaScript 技能方面的最佳资源。
