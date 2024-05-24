# CSS3 专家级编程（三）

> 原文：[`zh.annas-archive.org/md5/2789AE2FE8CABD493B142B2A68E84610`](https://zh.annas-archive.org/md5/2789AE2FE8CABD493B142B2A68E84610)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：在 CSS 中使用背景图像

几乎所有页面上都有背景图像。本章将描述如何在现代设备的广泛范围上正确显示图像，包括手机和平板电脑。

在本章中，我们将涵盖以下主题：

+   使用背景图像

+   如何为背景图像设置正确的位置

+   如何设置背景位置的大小

+   视网膜和移动设备上的图像

# CSS 背景

CSS 背景在现代 Web 浏览器中非常有用。何时应该使用背景，何时应该使用`img`标签？这是一个简单的问题 - 每个作为内容元素的图像都应插入到`img`标签中，每个作为布局元素的图像都应移动到 CSS 背景中。

在本章中，我们将尝试始终使用相同的图像来说明每个属性和值的工作原理。这个图像将是一个有边框的圆，肯定会显示正确的纵横比（如果它不好，它看起来更像省略号），并且有了边框，您可以检查图像的重复工作。图像的宽度和高度都等于 90 像素。

![CSS 背景](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00056.jpeg)

## 背景重复

在处理背景时有许多可用选项。第一个是图像重复。默认值是在*x*和*y*轴上重复图像。因此，当您设置，例如：

```css
Background-image: url(/* here url to your img*/)
```

我们的 SASS 示例：

```css
.container
  width: 1000px
  height: 500px
  border: 3px solid red
  background-image: url(image.jpg)
```

编译的 CSS：

```css
.container {
    width: 1000px;
    height: 500px;
    border: 3px solid red;
    background-image: url(image.jpg);
}
```

对于所有容器，边框都是红色的，以便更好地查看容器的范围。

HTML：

```css
<body>
<div class="container">

</div>
</body>
```

此代码将给我们带来以下视图：

![背景重复](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00057.jpeg)

对于所有容器，边框都是红色的，以便更好地查看容器的范围。这意味着图像在背景中在*x*和*y*轴上重复。让我们添加以下代码并检查它将如何编译以及对我们的视图会产生什么影响：

```css
.container
  width: 1000px
  height: 500px
  border: 3px solid red
  background:
    image: url(image.jpg)
    repeat: repeat
```

编译的 CSS：

```css
.container {
    width: 1000px;
    height: 500px;
    border: 3px solid red;
    background-image: url(image.jpg);
    background-repeat: repeat;
}
```

我们可以使用`background-repeat`的另一个选项和行为：

+   `- repeat-x`：这将重复背景*x*轴![背景重复](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00058.jpeg)

+   - repeat-y：这将重复背景*y*轴![背景重复](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00059.jpeg)

+   `- no-repeat`：这将不会重复背景![背景重复](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00060.jpeg)

## 背景大小

使用新的 CSS 功能，可以设置背景大小。大小可以设置如下：

```css
background-size: 30px 50px
```

让我们获取先前的 HTML 代码并附加新的 SASS 代码：

```css
.container
  width: 1000px
  height: 500px
  border: 3px solid red
  background:
    image: url(image.jpg)
    repeat: repeat
    size: 30px 50px
```

编译的 CSS：

```css
.container {
    width: 1000px;
    height: 500px;
    border: 3px solid red;
    background-image: url(image.jpg);
    background-repeat: repeat;
    background-size: 30px 50px;
}
```

此代码的输出将如下所示：

![背景大小](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00061.jpeg)

如果我们想要为图像设置容器的完整宽度，并自动计算其高度以保持图像的纵横比，执行以下操作：

```css
background-size: 100% auto
```

![背景大小](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00062.jpeg)

当然，我们可以将`fill`选项从*x*轴更改为*y*轴。让我们将`100%`的值更改为`height`，将`width`更改为`auto`：

```css
.container
  width: 1000px
  height: 500px
  border: 3px solid red
  background:
    image: url(image.jpg)
    repeat: repeat
    size: 100% auto
```

编译为：

```css
.container {
    width: 1000px;
    height: 500px;
    border: 3px solid red;
    background-image: url(image.jpg);
    background-repeat: repeat;
    background-size: 100% auto;
}
```

输出将如下所示：

![背景大小](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00063.jpeg)

`contain`值将更改其宽度和高度以包含容器。使用此选项，纵横比将得到保持：

```css
background-size: contain
```

`cover`值将更改其宽度和高度以覆盖容器。使用此选项，纵横比将得到保持：

```css
background-size: cover
```

## 背景位置

在大多数设计中，您将需要设置背景在框中的位置。可以使用 CSS 设置背景位置如下：

```css
background-position: top left
```

![背景位置](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00064.jpeg)

```css
background-position: right
```

![背景位置](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00065.jpeg)

如果要使背景在两个轴上居中，执行以下操作：

```css
background-position: center center
```

![背景位置](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00066.jpeg)

如果要将背景对齐到右下角，请执行以下操作：

```css
background-position: bottom right
```

![背景位置](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00067.jpeg)

要设置背景偏移量（以像素为单位），请执行以下操作：

```css
background-position: 600px 200px
```

![背景位置](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00068.jpeg)

## 多重背景

在过去，使用多个背景与添加具有单独背景的新 DOM 元素相关联。所有这些元素将绝对定位在相对容器中。如今，我们可以在一个容器中使用 CSS 使用多个背景，而无需任何额外的 HTML 代码。

让我们使用相同的 HTML 代码和相同的图像，然后将这个图像定位在容器中的以下位置：

+   顶部左侧

+   顶部中心

+   顶部右侧

+   左侧中心

+   中心中心

+   右侧中心

+   底部左侧

+   底部中心

+   底部右侧

CSS 代码：

```css
    .container {
    width: 1000px;
    height: 500px;
    border: 3px solid red;
    background-image:
            url(image.jpg), /* URL of image #1 */
            url(image.jpg), /* URL of image #2 */
            url(image.jpg), /* URL of image #3 */
            url(image.jpg), /* URL of image #4 */
            url(image.jpg), /* URL of image #5 */
            url(image.jpg), /* URL of image #6 */
            url(image.jpg), /* URL of image #7 */
            url(image.jpg), /* URL of image #8 */
            url(image.jpg); /* URL of image #9 */
    background-repeat: no-repeat;
    background-position:
            left top, /* position of image #1 */
            center top, /* position of image #2 */
            right top, /* position of image # 3*/
            left center, /* position of image #4 */
            center center, /* position of image #5 */
            right center, /* position of image #6 */
            bottom left, /* position of image #7 */
            bottom center, /* position of image #8 */
            bottom right; /* position of image #1 */
    background-size:
            50px auto, /* size of image #1 */
            auto auto, /* size of image #2 */
            auto auto, /* size of image #3 */
            auto auto, /* size of image #4 */
            200px auto, /* size of image #5 */
            auto auto, /* size of image #6 */
            auto auto, /* size of image #7 */
            auto auto, /* size of image #8 */
            50px auto; /* size of image #9 */
}
```

现在，让我们在 SASS 中描述它：

```css
.container
  width: 1000px
  height: 500px
  border: 3px solid red
  background:
    image: url(image.jpg), url(image.jpg), url(image.jpg), url(image.jpg), url(image.jpg),url(image.jpg), url(image.jpg), url(image.jpg), url(image.jpg)
    repeat: no-repeat
    position: left top, center top, right top, left center, center center, right center, bottom left, bottom center, bottom right
    size: 50px auto, auto auto, auto auto, auto auto, 200px auto, auto auto, auto auto, auto auto, 50px auto
```

最终视图将如下所示：

![多重背景](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00069.jpeg)

## 如何创建和使用精灵

什么是精灵？精灵是一种带有图像的图像。但是你如何在你的代码中使用它，为什么应该在你的 CSS 中使用它？因为它可以使你的网站更快，而且创建起来相当简单。让我们来看看下面的图片：

![如何创建和使用精灵](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00070.jpeg)

这是一个具有在*x*和*y*轴上设置偏移的基本精灵。那么我们如何从这个大图像中提取**IMG 3**？

```css
.image3
  display: inline-block
  width: 100px
  height: 100px
  background:
    image: url(image.jpg)
    repeat: no-repeat
    position: -200px 0
```

编译后的 CSS：

```css
.image3 {
    display: inline-block;
    width: 100px;
    height: 100px;
    background-image: url(image.jpg);
    background-repeat: no-repeat;
    background-position: -200px 0;
}
```

为了更好地理解精灵网格，让我们拿着名为**IMG 6**的对象：

```css
.image6
  display: inline-block
  width: 100px
  height: 100px
  background:
    image: url(image.jpg)
    repeat: no-repeat
    position: -200px -100px
```

编译后：

```css
.image6 {
    display: inline-block;
    width: 100px;
    height: 100px;
    background-image: url(image.jpg);
    background-repeat: no-repeat;
    background-position: -200px -100px;
}
```

好的。但是创建精灵非常无聊和耗时。这个过程如何自动化？使用 Compass 非常容易。我们只需要将所有图像收集到一个名为`newsprite`的文件夹中。精灵的最佳格式是 PNG，以保持适当的透明度。假设我们在这个文件夹中有以下三个 PNG 文件：

+   `circle-blue.png`

+   `circle-red.png`

+   `circle-white.png`

图像将如下所示：

![如何创建和使用精灵](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00071.jpeg)

现在我们需要对我们的自动化工具进行一些改变：

```css
var gulp = require('gulp'),
    compass = require('gulp-compass');

gulp.task('compass', function () {
    return gulp.src('src/styles/main.sass')
        .pipe(compass({
            sass: 'src/styles',
            image: 'src/images',
            css: 'dist/css',
            generated_images_path: 'dist/images',
            sourcemap: true,
            style: 'compressed'
        }))
        .on('error', function(err) {
            console.log(err);
        });
});

gulp.task('default', function () {
    gulp.watch('src/styles/**/*.sass', ['compass']);
    gulp.watch('src/images/**/*', ['compass']);
});
```

我们改变了以下定义图像目标的行：

```css
generated_images_path: 'dist/images'
```

现在我们需要在`compass`中添加一个代码来运行精灵创建器：

```css
@import "compass"
@import "newsprite/*.png"
@include all-newsprite-sprites(true)
```

在上述代码的第一行，我们正在导入`compass`库。在第二行，我们正在将我们的图像映射为`sprites`。在第三行，我们正在导入一个带有`sprites`的文件夹。括号中的值在编译后的 CSS 代码中给出了类的尺寸。现在让我们分析编译后的 CSS：

```css
.newsprite-sprite, 
.newsprite-circle-blue, 
.newsprite-circle-red, 
.newsprite-circle-white {
    background-image: url('../images/newsprite-s70c66611b2.png');
    background-repeat: no-repeat
}

.newsprite-circle-blue {
    background-position: 0 0;
    height: 90px;
    width: 90px
}

.newsprite-circle-red {
    background-position: 0 -90px;
    height: 90px;
    width: 90px
}

.newsprite-circle-white {
    background-position: 0 -180px;
    height: 90px;
    width: 90px
}
```

如您所见，生成的代码与文件结构和名称相关，例如：

```css
.newsprite-circle-red
```

其中：

+   `newsprite`: 这是一个文件夹/精灵名称

+   `circle-white`: 这是文件名

Compass 正在为生成的精灵图像添加前缀，例如：

```css
background-image: url('../images/newsprite-s70c66611b2.png');
```

和生成的文件：

![如何创建和使用精灵](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00072.jpeg)

现在让我们稍微改变一下代码，让我们使用 sprite-map。首先，我们需要创建 HTML 代码，最终在浏览器中看到效果：

```css
<div class="element-circle-white"></div>
<div class="element-circle-red"></div>
<div class="element-circle-blue"></div>
```

然后在 SASS 文件中：

```css
@import "compass/utilities/sprites"

$circles: sprite-map("newsprite/*.png", $spacing: 2px, $layout: diagonal)

.element-circle-blue
  background-image: sprite-url($circles)
  background-position: sprite-position($circles, circle-blue)
  @include sprite-dimensions($circles, circle-blue)

.element-circle-red
  background-image: sprite-url($circles)
  background-position: sprite-position($circles, circle-red)
  @include sprite-dimensions($circles, circle-red)

.element-circle-white
  background-image: sprite-url($circles)
  background-position: sprite-position($circles, circle-white)
  @include sprite-dimensions($circles, circle-white)

.element-circle-blue,
.element-circle-red,
.element-circle-white
  float: left
```

生成的 CSS：

```css
.element-circle-blue {
    background-image: url('../images/newsprite-s31a73c8e82.png');
    background-position: 0 -180px;
    height: 90px;
    width: 90px
}

.element-circle-red {
    background-image: url('../images/newsprite-s31a73c8e82.png');
    background-position: -90px -90px;
    height: 90px;
    width: 90px
}

.element-circle-white {
    background-image: url('../images/newsprite-s31a73c8e82.png');
    background-position: -180px 0;
    height: 90px;
    width: 90px
}

.element-circle-blue, .element-circle-red, .element-circle-white {
    float: left
}
```

在上述代码中，我们没有像之前那样添加所有带有它们尺寸的类。当你不想添加很多未使用的代码时，这一点很重要。现在我们只使用了需要的`sprite`部分。让我们深入分析一下：

```css
$circles: sprite-map("newsprite/*.png", $spacing: 2px, $layout: diagonal)
```

这行代码定义了我们的图像（即`@import "newsprite/*.png"`）。第二个参数定义了`sprite`中图像之间的间距（`$spacing: 2px`）；在这种情况下是`2px`。最后一个参数定义了`layout`样式。在这种情况下，`sprite`中的图像将如下所示：

![如何创建和使用精灵](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00073.jpeg)

有了这个参数，我们可以使用以下值：

+   **垂直**：精灵的元素将放置在一个垂直线上

+   **水平**：精灵的元素将放置在一条水平线上

+   **对角线**：精灵的元素将放置在对角线上

+   **智能**：元素将被调整为尽可能小的区域

让我们分析代码的下一部分：

```css
  background-image: sprite-url($circles)
  background-position: sprite-position($circles, circle-red)
  @include sprite-dimensions($circles, circle-red)
```

在上述代码的第一行，我们得到了`$circle`变量，其定义如下：

```css
$circles: sprite-map("newsprite/*.png", $spacing: 2px, $layout: diagonal)
```

这一行添加了背景图像。第二行是获取名为`circle-red`的图像在`$circle`变量（sprite）中的位置。最后一行包括了这个类中`circle-red`的宽度和高度。

在浏览器中，我们可以看到以下视图：

![如何创建和使用 sprites](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00074.jpeg)

## base64 的用法

这是一种与页面加载优化和请求最小化紧密相关的技术。从概念上讲，优化与尽可能减少请求数量有关。所以让我们假设我们有 10 个需要在页面上加载的图像背景。第一个请求是用于 CSS，接下来的 10 个请求发送到服务器是用于图像。但是我们怎样才能在一个请求中完成呢？我们可以使用`base64`编码。

让我们从理论上看一下它是什么样子的：

```css
data:[<mime type>][;charset=<charset>][;base64],<encoded data>
```

这是我们对图像进行编码的主要方法。最终，它看起来像这样：

```css
background-image: url(data:image/gif;base64,<encoded data>)
```

嘿！但是我怎么把我的图像改成编码数据呢？这是一个很好的问题。打开你的终端，尝试使用以下命令：

```css
openssl base64 -in <imgfile> -out <outputfile>
```

完成这个操作后，你需要做的就是将输出文件内容从前一个命令的`<encode data>`复制过来。

# 视网膜问题

视网膜是高分辨率显示器。这种显示器唯一的问题是如何将设备的宽度和高度加倍，然后压缩到保持容器中。这听起来很容易。最简单的方法是将尽可能多的元素移动到字体和 HTML 元素/伪元素中。但我们如何处理 CSS 中的背景图像呢？

让我们从基础知识开始。对于普通屏幕，我们需要具有标准尺寸的图像。图像的宽度和高度都等于 90 像素。

HTML:

```css
<div class="element"></div>
```

SASS：

```css
.element
  background:
    image: url(img/circle-blue.png)
    repeat: no-repeat
  width: 90px
  height: 90px
```

编译后的 CSS：

```css
.element {
    background-image: url(img/circle-blue.png);
    background-repeat: no-repeat;
    width: 90px;
    height: 90px;
}
```

如果我们想要在视网膜显示器上正确显示这个图像，我们需要改变一下代码。这个改变与视网膜显示器的密度有关。视网膜显示器的像素比是等于`2`的。我们需要改变的只是元素的宽度和高度，并调整这个框中的背景图像：

```css
.element
  background:
    image: url(img/circle-blue.png)
    repeat: no-repeat
    size: 50% 50%
  width: 45px
  height: 45px
```

编译后的 CSS：

```css
.element {
    background-image: url(img/circle-blue.png);
    background-repeat: no-repeat;
    background-size: 50% 50%;
    width: 45px;
    height: 45px;
}
```

现在`.element`已经准备好在视网膜显示器上以正确的质量显示。但它会比需要的大小小两倍。在这种情况下，我们需要做的就是从更大的分辨率的图像开始。例如，设计是为浏览器准备的，在浏览器中，主包装器的宽度应该是 1000 像素；所以你应该要求设计师将这个包装器的宽度设计为 200 像素。在更大的设计中，你正在切割需要在视网膜显示器上需要的切片。然后你应该为标准密度切割图像。你可以只留下视网膜图像，但这可能会影响性能，因为更大的图像将始终在浏览器中下载。为了避免这个问题，最好添加一个适当的媒体查询。在描述的例子中，我们在视网膜显示器的情况下全局添加文件的普通版本（`img/circle-blue.png`），这是由媒体查询识别的，因此将加载两倍大的图像（`img/circle-blue@2x.png`）。

```css
.element
  background:
    image: url(img/circle-blue.png)
    repeat: no-repeat
  width: 45px
  height: 45px

@media (-webkit-min-device-pixel-ratio: 2), (min-resolution: 192dpi)
  .element
    background:
      image: url(img/circle-blue@2x.png)
      repeat: no-repeat
      size: 50% 50%
    width: 45px
    height: 45px
```

编译后的 CSS：

```css
.element {
    background-image: url(img/circle-blue.png);
    background-repeat: no-repeat;
    width: 45px;
    height: 45px;
}

@media (-webkit-min-device-pixel-ratio: 2), (min-resolution: 192dpi) {
    .element {
        background-image: url(img/circle-blue@2x.png);
        background-repeat: no-repeat;
        background-size: 50% 50%;
        width: 45px;
        height: 45px;
    }
}
```

接下来是代码的一部分：

```css
background-size: 50% 50%
```

这部分代码可以与以下内容交换：

```css
background-size: contain
```

在这种情况下，图像将调整到添加背景的框的宽度和高度。

# 总结

在这一章中，你获得了关于背景图像的基本知识。你还学会了如何定位背景图像，设置它们的大小，以及如何通过`sprites`和`base64`编码解决主要性能问题。

在下一章中，你将获得关于表单样式的基本知识。你还将深入了解如何用 CSS 代码处理输入。


# 第六章：样式化表单

样式化表单是最具挑战性的任务之一，特别是当表单需要在桌面和移动设备上创建时。为什么？

在本章中，我们将涵盖以下主题：

+   如何为简单样式创建良好的结构

+   使用表单选择器

+   如何样式化表单

+   在表单中 CSS 的可能和不可能

# 表单-最常见的问题

你认识任何一个没有在 HTML/CSS 中构建过任何表单的前端开发人员吗？你认识任何一个喜欢做这项工作的人吗？是的...调整它并不简单，但你需要学会理解你可以用 HTML/CSS 做什么，以及在哪里需要使用 JavaScript 代码来使其更容易甚至可能。

最常见的限制如下：

+   因为输入框没有内容，所以不能使用伪元素`:before`和`:after`（`：before`和`：after`出现在内容之前或之后）

+   全局输入样式的使用并不好，因为有很多类型的输入（文本、密码、提交）

+   在所选框中显示元素的样式化根本不可能（有时更容易使用一些 JavaScript 插件来启用额外的结构，这样更容易进行样式化）

# 表单-启用超级功能

如前所述，在输入框中，无法使用`：before`和`：after`伪元素。但是有一个快速的技巧可以做到这一点，这将在接下来的章节中更好地描述，那就是将其包装在其他元素中。这总是有助于保持一些标签和输入组，并另外允许附加`：before`和`：after`伪元素。

例如，采用以下简单的 HTML 表单代码：

```css
<form>
    <input type="text" placeholder="Login"/>
    <input type="password" placeholder="Password"/>
</form>
```

现在你只需要添加包装元素：

```css
<form>
    <div class="inputKeeper">
        <input type="text" placeholder="Login"/>
    </div>
    <div class="inputKeeper">
        <input type="password" placeholder="Password"/>
    </div>
</form>
```

有什么不同？很容易看出来。第一个表单输出如下：

![表单-启用超级功能](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00075.jpeg)

第二个表单如下：

![表单-启用超级功能](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00076.jpeg)

## 如何样式化简单输入

输入样式基于选择器`<input> <select> <textarea>`。但是`<input>`类型存在问题。它将收集所有类型：

```css
<input type="text">
<input type="submit">
<input type="password">
<input type="checkbox">
```

对于密码输入：

```css
input[type="password"]
For submit input:
input[type="submit"]
```

让我们将这些输入整合到一个在网站上最常见的登录表单中。

HTML 代码：

```css
<form>
    <input type="text" placeholder="login"/>
    <input type="password" placeholder="password"/>
    <input type="submit" />
</form>
```

在浏览器中，它将如下所示：

![如何样式简单输入](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00077.jpeg)

让我们稍微改变结构，用包装的 div：

```css
<form>
    <div class="loginWrapper">
        <input type="text" placeholder="login"/>
    </div>
    <div class="passwordWrapper">
        <input type="password" placeholder="password"/>
    </div>
    <div class="submitWrapper">
        <input type="submit" />
    </div>
</form>
```

现在我们有了一个基本代码来开始样式化：

![如何样式简单输入](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00078.jpeg)

现在我们可以开始创建样式：

SASS：

```css
*
box-sizing: border-box

form
width: 300px

input
margin-bottom: 5px
width: 100%

input[type="text"]
  border: 2px solid blue

input[type="password"]
  border: 2px solid green

input[type="submit"]
  background: #000
color: #fff
width: 100%
```

生成的 CSS：

```css
* {
    box-sizing: border-box;
}

form {
    width: 300px;
}

input {
    margin-bottom: 5px;
    width: 100%;
}

input[type="text"] {
    border: 2px solid blue;
}

input[type="password"] {
    border: 2px solid green;
}

input[type="submit"] {
    background: #000;
    color: #fff;
    width: 100%;
}
```

现在，在了解了正确的选择器并添加了基本的 CSS 之后，我们的表单看起来像这样：

![如何样式简单输入](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00079.jpeg)

让我们看看**提交**按钮。我们需要去掉它的边框。在这个迭代中，让我们添加一些伪元素。让我们更新我们的 SASS 代码如下：

```css
=ring($size, $color, $width)
  width: $size
height: $size
border-radius: 50%
  border: $width solid $color
background: none

=triangleRight($width, $height, $color)
  width: 0
  height: 0
  border-style: solid
  border-width: $height/2 0 $height/2 $width
  border-color: transparent transparent transparent $color

*
  box-sizing: border-box

form
  width: 300px

input
  margin-bottom: 5px
  width: 100%

input[type="text"]
  border: 2px solid blue

input[type="password"]
  border: 2px solid green

input[type="submit"]
  background: #000
  color: #fff
  width: 100%

.loginWrapper,
.passwordWrapper,
.submitWrapper
  position: relative

  &:after
    content: ''
    display: inline-block
    position: absolute
    top: 50%
    right: 10px

.loginWrapper,
.passwordWrapper
  &:after
    margin-top: -6px
    right: 10px
    +ring(4px, #000, 2px)

.submitWrapper
  &:after
    margin-top: -3px
    right: 10px
    +triangleRight(6px, 6px, #fff)
```

生成的 CSS：

```css
* {
    box-sizing: border-box;
}

form {
    width: 300px;
}

input {
    margin-bottom: 5px;
    width: 100%;
}

input[type="text"] {
    border: 2px solid blue;
}

input[type="password"] {
    border: 2px solid green;
}

input[type="submit"] {
    background: #000;
    color: #fff;
    width: 100%;
}

.loginWrapper,
.passwordWrapper,
.submitWrapper {
    position: relative;
}

.loginWrapper:after,
.passwordWrapper:after,
.submitWrapper:after {
    content: "";
    display: inline-block;
    position: absolute;
    top: 50%;
    right: 10px;
}

.loginWrapper:after,
.passwordWrapper:after {
    margin-top: -6px;
    right: 10px;
    width: 4px;
    height: 4px;
    border-radius: 50%;
    border: 2px solid #000;
    background: none;
}

.submitWrapper:after {
    margin-top: -3px;
    right: 10px;
    width: 0;
    height: 0;
    border-style: solid;
    border-width: 3px 0 3px 6px;
    border-color: transparent transparent transparent #fff;
}
```

结果输出如下：

![如何样式简单输入](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00080.jpeg)

我们可以看到，我们忽略了`：before`和`：after`伪元素的问题。

## 不要忘记占位符

使用 HTML5，我们在所有浏览器中都支持占位符属性。它为我们提供了一个机会来添加以下描述：

```css
::-webkit-input-placeholder
  color: red

::-moz-placeholder
  color: red

::-ms-input-placeholder
  color: red
```

编译后的 CSS：

```css
::-webkit-input-placeholder {
    color: red;
}

::-moz-placeholder {
    color: red;
}

::-ms-input-placeholder {
    color: red;
}
```

结果输出如下：

![不要忘记占位符](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00081.jpeg)

## 基于 input[type="text"]和标签的复杂表单

那么让我们从复杂和弹性表单的样式开始。假设我们需要创建一个带有标签和输入的表单，其中标签始终位于左侧，输入正在调整大小。让我们来看 HTML 结构：

```css
<form class="" action="index.html" method="post">
    <fieldset>
        <legend>Personal data</legend>

        <div class="fieldKeeper">
            <label for="input_name">Your name</label>
            <input id="input_name" type="text" name="name" value="">
        </div>

        <div class="fieldKeeper">
            <label for="input_surname">Your surname</label>
            <input id="input_surname" type="text" name="name" value="">
        </div>

        <div class="fieldKeeper">
            <label for="input_address">Address</label>
            <input id="input_address" type="text" name="name" value="">
        </div>
    </fieldset>

    <fieldset>
        <legend>Login data</legend>
        <div class="fieldKeeper">
            <label for="input_login">Login</label>
            <input id="input_login" type="text" name="name" value="" placeholder="Your login">
        </div>

        <div class="fieldKeeper">
            <label for="input_password">Password</label>
            <input id="input_password" type="password" name="password" value="" placeholder="Password">
        </div>

        <div class="fieldKeeper">
            <label for="input_password_confirm">Confirm password</label>
            <input id="input_password_confirm" type="password" name="confirm_password" value="" placeholder="Confirmed password">
        </div>
    </fieldset>
</form>
```

在浏览器中，上述代码将如下所示：

![基于 input[type="text"]和标签的复杂表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00082.jpeg)

如你所见，它现在几乎表现得像应该的样子，但它的输入宽度不是 100%。当你将其改为 100%时，标签将移动到输入框上。所以我们可以做的是将输入框包装在另一个`div`中，并使用填充和绝对/相对位置的技巧。让我们将我们的 HTML 代码改为首个`fieldset`：

```css
<fieldset>
    <legend>Login data</legend>
    <div class="fieldKeeper">
        <label for="input_login">Login</label>
        <div class="inputKeeper">
            <input id="input_login" type="text" name="name" value="" placeholder="Your login">
        </div>
    </div>

    <div class="fieldKeeper">
        <label for="input_password">Password</label>
        <div class="inputKeeper">
            <input id="input_password" type="password" name="password" value="" placeholder="Password">
        </div>
    </div>

    <div class="fieldKeeper">
        <label for="input_password_confirm">Confirm password</label>
        <div class="inputKeeper">
           <input id="input_password_confirm" type="password" name="confirm_password" value=""
                   placeholder="Confirmed password">
        </div>
    </div>
</fieldset>
```

在第一个`fieldset`中进行这个改变后，您将看到代码在有或没有额外的`inputKeeper` `div`的情况下的行为。让我们使用以下 SASS 代码：

```css
.fieldKeeper
  position: relative

fieldset
  width: auto
  border: 2px solid green

legend
  text-transform: uppercase
  font:
    size: 10px
    weight: bold

label
  position: absolute
  width: 200px
  display: inline-block
  left: 0
  font:
    size: 12px

.inputKeeper
  padding:
    left: 200px

input
  width: 100%
```

编译后的 CSS：

```css
.fieldKeeper {
    position: relative;
}

fieldset {
    width: auto;
    border: 2px solid green;
}

legend {
    text-transform: uppercase;
    font-size: 10px;
    font-weight: bold;
}

label {
    position: absolute;
    width: 200px;
    display: inline-block;
    left: 0;
    font-size: 12px;
}

.inputKeeper {
    padding-left: 200px;
}

input {
    width: 100%;
}
```

现在您在浏览器中看到的是：

![基于 input[type="text"]和标签的复杂表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00083.jpeg)

在更大的屏幕上，您将看到以下内容：

![基于 input[type="text"]和标签的复杂表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00084.jpeg)

正如我们所看到的，对于没有额外包装的标签，绝对位置会导致标签覆盖输入的问题。额外的包装给了我们一个机会来添加填充。在这个填充的位置，我们可以使用绝对位置推动标签。在将包装器附加到第二部分之后，它应该在浏览器中看起来如下：

![基于 input[type="text"]和标签的复杂表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00085.jpeg)

## 如何样式化文本区域

`textarea`的样式化非常简单，非常类似于文本输入的样式化。其中一个区别是可以调整`textarea`的机会。这与`input[type="text"]`文本框相同，可以有一个占位符，因此您可以为其添加样式。让我们准备一个简单的 HTML 代码，以便对`textarea`进行简短的调查：

```css
<textarea placeholder="Here describe your skills"></textarea>
```

现在在浏览器中，您将看到以下内容：

![如何样式化文本区域](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00086.jpeg)

请记住，在开放和关闭标签之间不要添加任何空格或行尾，因为它将被视为`textarea`的内容。这将导致占位符出现问题。

和 SASS 代码：

```css
textarea
  width: 300px
  height: 150px
  resize: none
  border: 2px solid green
```

编译后的 CSS：

```css
textarea {
    width: 300px;
    height: 150px;
    resize: none;
    border: 2px solid green;
}
```

在浏览器中，您将看到以下内容：

![如何样式化文本区域](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00087.jpeg)

作为调整大小属性的值，您可以使用以下值：

+   `none`：这将在两个轴上禁用调整大小

+   `vertical`：这将启用垂直调整大小并阻止水平调整大小

+   `horizontal`：这将启用水平调整大小并阻止垂直调整大小

+   `both`：这将在两个轴上启用调整大小

## 选择框的样式化（下拉菜单）

该样式化`select`（下拉菜单）并不像应该那样简单。在大多数情况下，您需要使用一些 JavaScript 插件来使其更容易。但是您可以用简单的 CSS/HTML 代码做些什么呢？让我们看看以下代码：

```css
<select>
    <option>Please choose one option...</option>
    <option>Option one</option>
    <option>Option two</option>
    <option>Option three</option>
    <option>Option four</option>
    <option>Option five</option>
</select>
```

上述代码将生成一个未经样式化的选择框，如下所示：

![选择框的样式化（下拉菜单）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00088.jpeg)

并且在焦点动作之后，它会产生以下输出：

![选择框的样式化（下拉菜单）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00089.jpeg)

现在我们能做些什么呢？让我们尝试添加更多的风味。首先，让我们将其包装到额外的元素中：

```css
<div class="selectWrapper">
    <select>
        <option>Please choose one option...</option>
        <option>Option one</option>
        <option>Option two</option>
        <option>Option three</option>
        <option>Option four</option>
        <option>Option five</option>
    </select>
</div>
```

现在让我们添加一个 SASS 代码：

```css
=triangleBottom($width, $height, $color)
  width: 0
  height: 0
  border-style: solid
  border-width: $height $width/2 0 $width/2
  border-color: $color transparent transparent transparent

.selectWrapper
  width: 300px
  border: 2px solid green
  overflow: hidden
  position: relative

  &:after
    content: ''
    position: absolute
    +triangleBottom(10px, 6px, red)
    right: 5px
    margin-top: -3px
    top: 50%

select
  background: #fff
  color: black
  font:
    size: 14px
  border: none
  width: 105%
```

编译后的 CSS：

```css
.selectWrapper {
    width: 300px;
    border: 2px solid green;
    overflow: hidden;
    position: relative;
}

.selectWrapper:after {
    content: "";
    position: absolute;
    width: 0;
    height: 0;
    border-style: solid;
    border-width: 6px 5px 0 5px;
    border-color: red transparent transparent transparent;
    right: 5px;
    margin-top: -3px;
    top: 50%;
}

select {
    background: #fff;
    color: black;
    font-size: 14px;
    border: none;
    width: 105%;
}
```

![选择框的样式化（下拉菜单）](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00090.jpeg)

正如您所看到的，这种方法相当棘手。我们使选择框比容器宽一点，以将原生控件移出。然后我们向容器添加了溢出隐藏。此外，我们添加了 after 元素以添加一个三角形。

# 总结

在本章中，您了解了如何样式化表单。处理所有这些表单确实有些棘手，但正如您所看到的，总会有一些解决方案（例如，使用额外的包装器）。我建议您创建一个简单的框架，以便您可以处理表单。这使您完全准备好样式化表单。

在下一章中，我们将尝试解决 CSS 中最常见的问题，例如元素居中、处理显示类型等。这将展示旧学校和新学校方法与新的 CSS 功能可能性。


# 第七章：解决经典问题

作为前端开发人员，您总是在处理经典的 CSS 问题。最常见和重复的问题是在两个轴上居中元素和不透明度。使用当前的 CSS，您可以做得非常简单，但您需要有基础知识才能知道如何做。关于浏览器先前版本的回退的知识可以在一些其他进阶技术中使用。这就是为什么它们被添加到这一章节中。

在本章中，我们将：

+   学习如何在两个轴上居中元素

+   学习如何处理不透明度

+   汇集前面的技巧，并创建类似于时尚灯箱效果的效果

# 居中元素

居中元素是自第一个 CSS 版本以来就已知的一个方面。页面上总是有一些需要在某个容器或浏览器中垂直或水平居中的元素/元素。居中一些元素的最简单方法是将元素附加到表元素中，并在 HTML 中添加垂直对齐和水平对齐属性：

```css
<td valign="middle" align="center>  </td>
```

但是在现代 CSS 中我们该如何做到这一点呢？有两种居中方式：

+   水平

+   垂直

让我们解决这个问题。

## 内联元素-水平居中

假设我们有一段文本需要居中。这很简单。我们只需要添加`text-align: center`就可以了。在我们将要实现的示例中，我们将容器的背景设置为`red`，元素的背景设置为`white`以查看它是如何工作的。

让我们从这段 HTML 代码开始：

```css
<p class="container">
    <span class="element">Centered</span>
</p>
```

和 SASS 代码：

```css
.container
  background: red
  padding: 20px

.element
  background: white
```

CSS：

```css
.container {
    background: red;
    padding: 20px;
}

.element {
    background: white;
}
```

在浏览器中我们将看到以下内容：

![内联元素-水平居中](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00091.jpeg)

要使框居中，如前面提到的，我们需要在容器中添加`text-align: center`：

SASS：

```css
.container
  text-align: center
  background: red
  padding: 20px

.element
  background: white
```

现在在浏览器中，我们可以看到以下内容：

![内联元素-水平居中](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00092.jpeg)

假设我们有两个块元素，我们想要调整它们如前面的例子那样。我们需要做什么？我们需要将显示类型更改为`inline`或`inline-block`。让我们稍微改变 HTML 代码：

```css
<div class="container">
    <div class="element">Centered</div>
</div>
```

现在加入之前添加的 SASS 代码，我们的示例将表现得与以下屏幕截图类似：

![内联元素-水平居中](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00093.jpeg)

如前面的屏幕截图所示，块元素占据了全部可能的宽度。我们需要做的是修改 SASS 代码：

```css
.container
  text-align: center
  background: red
  padding: 20px

.element
  background: white
  display: inline-block
```

CSS：

```css
.container {
    text-align: center;
    background: red;
    padding: 20px;
}

.element {
    background: white;
    display: inline-block;
}
```

现在在浏览器中，我们可以看到以下内容：

![内联元素-水平居中](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00094.jpeg)

## 块元素-在两个轴上居中

让我们从前一章的代码开始，这将是我们 CSS 样式的基础。这是`container`中的元素：

```css
<div class="container">
    <div class="element">Centered</div>
</div>
```

添加了带颜色的 SASS 代码以更好地显示问题：

```css
.container
  background: black

.element
  width: 400px
  height: 400px
  background: red
```

CSS：

```css
.container {
    background: black;
}

.element {
    width: 400px;
    height: 400px;
    background: red;
}
```

在起始点，我们在浏览器中的代码将如下所示：

![块元素-在两个轴上居中](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00095.jpeg)

如前面的屏幕截图所示，我们的带有`居中`内容的容器现在位于黑色容器的左侧。假设这是需要居中并粘贴到页面顶部的页面容器：

```css
.container
  background: black
  height: 800px

.element
  width: 400px
  height: 400px
  background: red
  margin: 0 auto
```

编译：

```css
.container {
    background: black;
    height: 800px;
}

.element {
    width: 400px;
    height: 400px;
    background: red;
    margin: 0 auto;
}
```

最重要的一行是加粗的那一行。这使我们的容器居中，如下面的屏幕截图所示：

![块元素-在两个轴上居中](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00096.jpeg)

那么我们该怎么做才能使它在两个轴上居中呢？用已知元素的宽度和高度的老式方法是将容器的相对位置添加到元素的绝对位置。元素需要从顶部和左侧移动 50%。然后我们需要使用负边距将元素向上和向左移动已知高度的一半：

```css
.container
  position: relative

.element
  position: absolute
  width: 100px
  height: 100px
  left: 50%
  right: 50%
  margin-left: -50px
  margin-top: -50px
```

CSS：

```css
.container {
    position: relative;
}

.element {
    position: absolute;
    width: 100px;
    height: 100px;
    left: 50%;
    right: 50%;
    margin-left: -50px;
    margin-top: -50px;
}
```

输出将如下所示：

![块元素-在两个轴上居中](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00097.jpeg)

正如您在前面的截图中所看到的，该元素在两个轴上都居中。最大的问题是元素的静态宽度和高度。是的，当然，有一种方法可以添加 JavaScript 代码来实现它，但最好使用原生 CSS 函数。所以让我们尝试使用`transform`属性来实现它。

## 使用 transform 进行居中

在上一节中，我们一直在尝试解决居中元素的问题。让我们用 transform 声明来扩展它。我们将在下一章中深入了解 transform，以了解它如何与旋转和缩放一起工作，但是对于本章，我们需要添加以下代码：

```css
.container
  position: relative

.element
  position: absolute
  left: 50%
  right: 50%
  transform: translate(-50%, -50%)
```

在前面的代码中，最后一行产生了与上一节中相同的效果，定义了负左和上边距。这段代码的最佳特点是我们可以在任何地方添加它，而不需要知道宽度和高度。在下一章中，我们将学习 flexbox，它可以用于元素的居中。

# 处理不透明度

不透明度在项目中经常出现。例如，当您在页面上创建一些模型窗口或类似灯箱的画廊时。它通常用于在主窗口下添加的图层（覆盖元素），在大多数情况下，该图层在 JavaScript 中添加了`onclick`事件监听器，点击时隐藏窗口。您如何创建这种效果？过去是如何做到的？让我们从一个简单的 HTML 代码开始：

```css
<header> Header </header>
<main> Lorem ipsum dolor sit amet, consectetur adipisicing elit. Architecto dolore doloremque dolores iure laudantium magni mollitia quam ratione, temporibus ut? Aperiam necessitatibus perspiciatis qui ratione vel! Adipisci eligendi sint unde. </main>
<footer> Footer </footer>
```

SASS：

```css
header, footer, main
  padding: 50px
  text-align: center

header, footer
  background: red

main
  background: green
```

编译后：

```css
header, footer, main {
    padding: 50px;
    text-align: center;
}

header, footer {
    background: red;
}

main {
    background: green;
}
```

现在它将看起来像下面这样：

![处理不透明度](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00098.jpeg)

我们需要做的是在当前可见容器之上添加一个带有不透明度的图层。让我们在当前添加的代码之后追加这段代码：

```css
<div class="window_container">
    <div class="window">Content of our window</div>
</div>
```

现在我们需要做的是将容器位置更改为`fixed`，并将元素位置更改为`absolute`。让我们添加一些代码来增加更多的样式，以便更好地看到我们工作的效果：

```css
.window_container
  position: fixed
  width: 100%
  height: 100%
  top: 0
  left: 0
  background: black

.window
  position: absolute
  width: 200px
  height: 200px
  background: white
  top: 50%
  left: 50%
  -webkit-transform: translate(-50%, -50%)
  -moz-transform: translate(-50%, -50%)
  -ms-transform: translate(-50%, -50%)
  -o-transform: translate(-50%, -50%)
  transform: translate(-50%, -50%)
```

编译后：

```css
.window_container {
    position: fixed;
    width: 100%;
    height: 100%;
    top: 0;
    left: 0;
    background: black;
}

.window {
    position: absolute;
    width: 200px;
    height: 200px;
    background: white;
    top: 50%;
    left: 50%;
    -webkit-transform: translate(-50%, -50%);
    -moz-transform: translate(-50%, -50%);
    -ms-transform: translate(-50%, -50%);
    -o-transform: translate(-50%, -50%);
    transform: translate(-50%, -50%);
}
```

在浏览器中，我们将看到白色的居中块在黑色容器上，如下所示：

![处理不透明度](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00099.jpeg)

前面的代码将成为下一节的基础，我们将看到`opacity`和`rgba`之间的差异。

## 不透明度与 RGBA-差异及其使用场景

让我们尝试将先前添加到 HTML/SASS 结构中的`.window_container`元素设置为透明。最简单的方法是添加`opacity`：`.5`。所以让我们尝试将以下代码添加到我们当前的 SASS 代码中：

```css
.window_container
  opacity: .5
  position: fixed
  width: 100%
  height: 100%
  top: 0
  left: 0
  background: black
```

CSS：

```css
.window_container {
    opacity: 0.5;
    position: fixed;
    width: 100%;
    height: 100%;
    top: 0;
    left: 0;
    background: black;
}
```

在浏览器中的效果将如下截图所示：

![不透明度与 RGBA-差异及其使用场景](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00100.jpeg)

正如我们在前面的截图中所看到的，不透明度被`.window_container`内的元素继承。这不是我们想要的方式，所以我们必须更改 CSS（SASS）或 HTML 代码。如果我们想更改 HTML 代码，可以这样做：

```css
<div class="window_container"> </div>
<div class="window">Content of our window</div>
```

SASS 代码将在窗口描述中更改。我们只会将位置更改为`fixed`：

```css
.window
  position: fixed
```

在浏览器中的效果将如下所示：

![不透明度与 RGBA-差异及其使用场景](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00101.jpeg)

正如我们在前面的截图中所看到的，在浏览器中，已经实现了效果，但是我们的 HTML 结构有点混乱。我们已经同时将两个元素添加到了与一个元素相关的 HTML 代码中。所以让我们回到我们章节开头的代码，其中`.window`在`.window_container`中。这是我们将使用`rgba`的地方。确保负责窗口的 HTML 代码如下所示：

```css
<div class="window_container">
    <div class="window">Content of our window</div>
</div>
```

我们需要做的是更改`window_container`的背景颜色定义，并追加我们的`rgba`。正如我们所知，我们可以以几种方式定义元素的颜色：

+   添加颜色名称（`black`，`white`，`red`，...）

+   十六进制颜色定义（`#ff00ff`，`#fff`，...）

+   基于 RGB（`rgb(0,0,0)`，`rgb(255,255,255)`）的颜色

+   基于 HSL（`hsl(100, 90%, 50%)`）的颜色

+   RGBA（`rgb(0,0,0, .4)`, `rgb(255,255,255, .7)`）基于红绿蓝+ alpha 通道

+   HSLA（`hsl(100, 90%, 50%, .8)`）基于色调、饱和度、亮度+ alpha 通道

在我们的情况下，我们将使用`rgba`。`window_container`的最终 SASS 代码如下：

```css
.window_container
  position: fixed
  width: 100%
  height: 100%
  top: 0
  left: 0
  background: rgba(0,0,0,.5)

.window
  position: fixed
  width: 200px
  height: 200px
  background: white
  top: 50%
  left: 50%
  -webkit-transform: translate(-50%, -50%)
  -moz-transform: translate(-50%, -50%)
  -ms-transform: translate(-50%, -50%)
  -o-transform: translate(-50%, -50%)
  transform: translate(-50%, -50%)
```

编译：

```css
.window_container {
    position: fixed;
    width: 100%;
    height: 100%;
    top: 0;
    left: 0;
    background: rgba(0, 0, 0, 0.5);
}

.window {
    position: fixed;
    width: 200px;
    height: 200px;
    background: white;
    top: 50%;
    left: 50%;
    -webkit-transform: translate(-50%, -50%);
    -moz-transform: translate(-50%, -50%);
    -ms-transform: translate(-50%, -50%);
    -o-transform: translate(-50%, -50%);
    transform: translate(-50%, -50%);
}
```

如您所见，`opacity`声明被移除了。颜色定义为 RGBA。其余代码保持不变。在浏览器中的代码如下所示：

![不透明度与 RGBA 的差异以及它们可以在哪里使用](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00102.jpeg)

## 过去的不透明度 - 用于旧 IE 版本的回退

对于旧浏览器的回退方式与当您想要使用边框半径时的方式类似 - 您需要使用图像。最终是如何完成的呢？当图形在图形软件中被裁剪时，覆盖层被裁剪为一个小的透明图像，例如，PNG 1 像素 x1 像素。然后将其添加为背景，并在*x*和*y*轴上重复。

```css
/* FALLBACK */
.window_container
  background-image: url(<1x1.png>)
  background-repeat: repeat
```

# 总结

在本章中，您了解了 CSS 中最常见的经典问题：居中和不透明度。您解决了这个问题，并了解了解决方案的利弊。此外，您还了解了如何在旧浏览器中解决不透明度问题。

在下一章中，您将学习有关现代 CSS 方面的知识，如 flexbox 渐变、阴影、变换和数据属性。您还将学习一些可以应用到您的代码中的技巧。让我们继续下一章。


# 第八章：Flexbox 变换的使用

CSS 仍在发展。作为前端开发人员，每年您都需要关注当前趋势和可以为元素设置的新属性。当然，有很多限制，但在某些情况下，这些限制不存在，例如在新浏览器或选定的移动应用程序中，或者因为设置了要求。在本章中，我们将涵盖以下主题：

+   Flexbox

+   变换属性

# Flexbox

Flexbox 是当前 CSS 项目中使用的最响亮和最现代的布局方法之一。使用 flexbox，您可以为网页创建一个比基于浮动框更灵活的结构。为什么？我们将在本章中进行检查和调查。您需要记住的是，自 Internet Explorer 的第 11 个版本起就支持 flexbox。

让我们来看看 flexbox 的基础知识：

![Flexbox](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00103.jpeg)

如您在前面的屏幕截图中所见，有一个与 flexbox 相关的新字典：

+   **主轴**（绿色箭头）

+   **主轴开始**（红线）

+   **主轴结束**（红线）

+   **主轴尺寸**（黑线）

+   **交叉轴**（绿色箭头）

+   **交叉开始**（红线）

+   **交叉结束**（红线）

+   **交叉尺寸**（黑线）

flexbox 的初始化非常简单。您只需要将以下代码添加到容器中：

```css
.flexContainer
  display: -webkit-box
  display: -moz-box
  display: -ms-flexbox
  display: -webkit-flex
  display: flex
```

编译后的代码是：

```css
.flexContainer {

    display: -webkit-box;

    display: -moz-box;

    display: -ms-flexbox;

    display: -webkit-flex;

    display: flex;

}
```

flexbox 的使用仍然需要前缀以实现跨浏览器兼容性。这是创建可重用 mixin 的一个很好的理由：

```css
=displayFlex

  display: -webkit-box

  display: -moz-box

  display: -ms-flexbox

  display: -webkit-flex

  display: flex
```

现在我们可以创建与以下相同的`.flexContainer`：

```css
.flexContainer

  +displayFlex
```

编译后的代码是：

```css
.flexContainer {

    display: -webkit-box;

    display: -moz-box;

    display: -ms-flexbox;

    display: -webkit-flex;

    display: flex;

}
```

让我们在容器中创建一些元素：

```css
<div class="flexContainer">

    <div class="flexElement">Element 1</div>

    <div class="flexElement">Element 2</div>

    <div class="flexElement">Element 3</div>

</div>
```

让我们稍微装饰一下我们的 CSS 代码，以查看 flexbox 的行为：

```css
=displayFlex

  display: -webkit-box

  display: -moz-box

  display: -ms-flexbox

  display: -webkit-flex

  display: flex

.flexContainer

  +displayFlex

  background: red
```

编译后的代码是：

```css
.flexContainer {

    display: -webkit-box;

    display: -moz-box;

    display: -ms-flexbox;

    display: -webkit-flex;

    display: flex;

    background: red;

}
```

现在我们将在浏览器中看到以下视图：

![Flexbox](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00104.jpeg)

如您在前面的屏幕截图中所见，容器未达到浏览器中的最大可能高度，但确实达到了其全宽。内部元素向左浮动。现在让我们稍微改变 SASS 代码：

```css
.flexContainer

  +displayFlex

  height: 100%

  background: red

.blue

  background: blue

.green

  background: green

.yellow

  background: yellow
```

编译后的代码是：

```css
.flexContainer {

    display: -webkit-box;

    display: -moz-box;

    display: -ms-flexbox;

    display: -webkit-flex;

    display: flex;

    height: 100%;

    background: red;

}

.blue {

    background: blue;

}

.green {

    background: green;

}

.yellow {

    background: yellow;

}
```

让我们在 HTML 代码中添加一个颜色类：

```css
<div class="flexContainer">

    <div class="flexElement blue">Element 1</div>

    <div class="flexElement green">Element 2</div>

    <div class="flexElement yellow">Element 3</div>

</div>
```

在浏览器中，您将看到以下内容：

![Flexbox](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00105.jpeg)

如您在前面的屏幕截图中所见，容器具有全宽和高，并且内部元素的行为类似于内联元素，但继承自容器的全高。这是因为属性称为`align-item`，其默认值为**stretch**。让我们更深入地了解此属性的值。

## Flexbox 属性 align-items

这是我们可以添加到`flexContainer`的属性之一。它有一些我们可以设置的值。目前，我们知道默认的 stretch 值的行为。让我们研究其余可能的值。在所有值之前，让我们稍微改变 HTML 和 CSS 代码，以更好地查看所有行为。

让我们修改 HTML 代码如下：

```css
<div class="flexContainer">

    <div class="flexElement blue h200px">Element 1</div>

    <div class="flexElement green h300px">Element 2</div>

    <div class="flexElement yellow h100px">Element 3</div>

</div>
```

让我们附加以下 SASS 代码：

```css
.h100px

  height: 100px

.h200px

  height: 200px

.h300px

  height: 300px
```

CSS 文件是：

```css
.h100px {

    height: 100px;

}

.h200px {

    height: 200px;

}

.h300px {

    height: 300px;

}
```

可以使用的 flex 的不同值如下：

+   `stretch`（默认）![Flexbox 属性 align-items](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00106.jpeg)

### 提示

对于此值 stretch，您需要删除添加盒子高度（`h100px`，`h200px`，`h300px`）的类。

+   `flex-start`![Flexbox 属性 align-items](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00107.jpeg)

+   `flex-end`![Flexbox 属性 align-items](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00108.jpeg)

+   `center`![Flexbox 属性 align-items](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00109.jpeg)

+   `baseline`

在这种情况下，为了更好地理解这种行为，让我们更改我们的代码以查看如何指定基线：

```css
<div class="flexContainer">
    <div class="flexElement blue h200px">Element 1</div>
    <div class="flexElement green h300px">Element 2 Lorem ipsum dolor sit amet, consectetur adipisicing elit. Possimus necessitatibus est quis sequi, sapiente quos corporis, dignissimos libero quibusdam beatae ipsam quaerat? Excepturi magni voluptas dicta inventore necessitatibus omnis officia.</div>
    <div class="flexElement yellow h100px">Element 3</div>
</div>
```

在 SASS 中，代码可以编写为：

```css
.h100px
  height: 100px
  font-size: 30px
  margin-top: 20px

.h200px
  height: 200px
  font-size: 20px

.h300px
  height: 300px
  font-size: 8px
```

CSS 代码将是：

```css
.h100px {
    height: 100px;
    font-size: 30px;
    margin-top: 20px;
}

.h200px {
    height: 200px;
    font-size: 20px;
}

.h300px {
    height: 300px;
    font-size: 8px;
}
```

前面代码的输出如下：

![Flexbox 属性 align-items](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00110.jpeg)

从顶部的盒子位置是从盒子中的第一行文本指定的基线设置的。有意义的是为`h100px`盒子添加了一个 margin-top，以查看基线是从子元素集中的任何一个盒子计算的。

好的。但是当我们添加一个没有文本内容的框时，这个例子会如何表现呢？让我们修改 HTML 代码如下：

```css
<div class="flexContainer">
    <div class="flexElement blue h200px">Element 1</div>
    <div class="flexElement yellow h100px w100px"></div>
    <div class="flexElement green h300px">Element 2 Lorem ipsum dolor sit amet, consectetur adipisicing elit. Possimus necessitatibus est quis sequi, sapiente quos corporis, dignissimos libero quibusdam beatae ipsam quaerat? Excepturi magni voluptas dicta inventore necessitatibus omnis officia.</div>
    <div class="flexElement yellow h100px">Element 3</div>
</div>
```

让我们在 SASS 代码中添加`w100px`类：

```css
.w100px
  width: 100px

CSS:
.w100px {
    width: 100px;
}
```

前面代码的输出如下：

！[Flexbox 属性 align-items]（img/00111.jpeg）

正如我们在前面的屏幕截图中看到的那样，基线由黄色空框的底部线指定。

## Flexbox 属性 flex-wrap

我们可以为 flex 容器设置的下一个属性之一是`flex-wrap`。此属性与框中的换行有关。我们可以将`nowrap`，`wrap`和`wrap-reverse`设置为值。它们的行为如何？

+   `nowrap`（默认）！[Flexbox 属性 flex-wrap]（img/00112.jpeg）

+   `wrap`！[Flexbox 属性 flex-wrap]（img/00113.jpeg）

+   `wrap-reverse`！[Flexbox 属性 flex-wrap]（img/00114.jpeg）

正如你所看到的，`wrap`和`wrap-reverse`的工作方式相同，但有一个简单的区别：`wrap-reverse`改变了伸缩项的顺序。

## Flexbox 属性 justify-content

`justify-content`属性也与容器有关：

+   `flex-start`！[Flexbox 属性 justify-content]（img/00115.jpeg）

+   `flex-end`！[Flexbox 属性 justify-content]（img/00116.jpeg）

+   `center`！[Flexbox 属性 justify-content]（img/00117.jpeg）

+   `space-between`！[Flexbox 属性 justify-content]（img/00118.jpeg）

+   `space-around`！[Flexbox 属性 justify-content]（img/00119.jpeg）

## Flexbox 属性 align-content

项目的对齐与`flexContainer`有关。您需要记住，当您至少有两行项目时，效果才会可见。因此，让我们更改以下示例代码：

HTML：

```css
<div class="flexContainer">
    <div class="flexElement blue h100px">Element 1</div>
    <div class="flexElement green h200px">Element 2</div>
    <div class="flexElement blue h100px">Element 3</div>
    <div class="flexElement green h200px">Element 4</div>
    <div class="flexElement blue h100px">Element 5</div>
    <div class="flexElement green h200px">Element 6</div>
</div>
```

SASS 代码是：

```css
=displayFlex
  display: -webkit-box
  display: -moz-box
  display: -ms-flexbox
  display: -webkit-flex
  display: flex

.flexContainer
  height: 600px
  width: 900px
  +displayFlex
  flex-wrap: wrap
  background: red

.blue
  background: blue

.green
  background: green

.yellow
  background: yellow

.h100px
  height: 100px
  font-size: 30px
  margin-top: 20px

.h200px
  height: 200px
  font-size: 20px

.h300px
  height: 300px
  font-size: 8px

.w100px
  width: 100px

.flexElement
  width: 300px
```

CSS 代码是：

```css
.flexContainer {
    height: 600px;
    width: 900px;
    display: -webkit-box;
    display: -moz-box;
    display: -ms-flexbox;
    display: -webkit-flex;
    display: flex;
    flex-wrap: wrap;
    background: red;
}

.blue {
    background: blue;
}

.green {
    background: green;
}

.yellow {
    background: yellow;
}

.h100px {
    height: 100px;
    font-size: 30px;
    margin-top: 20px;
}

.h200px {
    height: 200px;
    font-size: 20px;
}

.h300px {
    height: 300px;
    font-size: 8px;
}

.w100px {
    width: 100px;
}

.flexElement {
    width: 300px;
}
```

+   `flex-start`！[Flexbox 属性 align-content]（img/00120.jpeg）

+   `flex-end`！[Flexbox 属性 align-content]（img/00121.jpeg）

+   `center`！[Flexbox 属性 align-content]（img/00122.jpeg）

+   `space-between`！[Flexbox 属性 align-content]（img/00123.jpeg）

+   `space-around`！[Flexbox 属性 align-content]（img/00124.jpeg）

+   `stretch`！[Flexbox 属性 align-content]（img/00125.jpeg）

在最后一个例子中，所有与高度相关的类都已被删除：`h100px`，`h200px`。

## Flexbox 属性 flex-direction

flexbox 的不同属性如下：

+   `row`！[Flexbox 属性 flex-direction]（img/00126.jpeg）

+   `row-reverse`！[Flexbox 属性 flex-direction]（img/00127.jpeg）

+   `column`！[Flexbox 属性 flex-direction]（img/00128.jpeg）

+   `column-reverse`！[Flexbox 属性 flex-direction]（img/00129.jpeg）

您可以添加到您的收藏中的有用的 mixin 如下：

```css
=displayFlex
  display: -webkit-box
  display: -moz-box
  display: -ms-flexbox
  display: -webkit-flex
  display: flex

=flexOrder($number)
  -webkit-box-ordinal-group: $number
  -moz-box-ordinal-group: $number
  -ms-flex-order: $number
  -webkit-order: $number
  order: $number
```

## 使用 flexbox-创建页面结构

当您开始处理项目时，您会将准备好的布局作为图形文件，并且需要在浏览器中使其可用和交互。让我们从当前最知名的结构开始：

```css
<div class="flexContainer">
    <header>Header</header>
    <aside>Side menu</aside>
    <main>Content</main>
    <footer>Footer - Copyright fedojo.com</footer>
</div>
```

因此，我们希望将标题放在顶部，左侧主体放在右侧，页脚放在底部：

```css
.flexContainer
  +displayFlex
  -webkit-flex-flow: row wrap
  flex-flow: row wrap

  & > *
    padding: 10px
    flex: 1 100%

  header
    background: red

  footer
    background: lightblue

  main
    background: yellow
    flex: 3 1 auto

  aside
    background: green
    flex:  0 0 auto
```

CSS 文件是：

```css
.flexContainer {
    display: -webkit-box;
    display: -moz-box;
    display: -ms-flexbox;
    display: -webkit-flex;
    display: flex;
    -webkit-flex-flow: row wrap;
    flex-flow: row wrap;
}

.flexContainer > * {
    padding: 10px;
    flex: 1 100%;
}

.flexContainer header {
    background: red;
}

.flexContainer footer {
    background: lightblue;
}

.flexContainer main {
    background: yellow;
    flex: 3 auto;
}

.flexContainer aside {
    background: green;
    flex: 1 auto;
}
```

浏览器中的效果将如下：

！[使用 flexbox-创建页面结构]（img/00130.jpeg）

当您希望将侧边栏宽度更改为静态值时，您可以在侧边菜单的 SASS 声明中添加一个小的更改：

```css
aside
  background: green
  flex:  0 0 auto
  width: 100px
```

它将在 CSS 中：

```css
.flexContainer aside {
    background: green;
    flex: 0 auto;
    width: 100px;
}
```

这将保持左侧列的静态宽度。

## 使用 flexbox-在移动/平板视图中更改框的顺序

当您在创建 HTML 布局时调整到桌面和移动设备时，可能会出现一些情况，您需要更改框的顺序。桌面的简单示例如下：

+   第一个元素需要在顶部

+   第二个元素需要在底部

移动设备的简单示例如下：

+   第二个元素需要在顶部

+   第一个元素需要在底部

让我们使用以下 HTML 代码：

```css
<div class="container">
    <div class="first">First</div>
    <div class="second">Second</div>
</div>
```

让我们创建几行 SASS 代码：

```css
=displayFlex
  display: -webkit-box
  display: -moz-box
  display: -ms-flexbox
  display: -webkit-flex
  display: flex

=flexOrder($number)
  -webkit-box-ordinal-group: $number
  -moz-box-ordinal-group: $number
  -ms-flex-order: $number
  -webkit-order: $number
  order: $number

.container > *
  padding: 20px

.first
  background: lightblue

.second
  background: lightcyan

@media screen and (max-width: 600px)

  .container
    +displayFlex
    -webkit-flex-flow: row wrap
    flex-flow: row wrap

    & > *
      width: 100%

    .first
      +flexOrder(2)

    .second
      +flexOrder(1)
```

在 CSS 中：

```css
.container > * {
    padding: 20px;
}

.first {
    background: lightblue;
}

.second {
    background: lightcyan;
}

@media screen and (max-width: 600px) {
    .container {
        display: -webkit-box;
        display: -moz-box;
        display: -ms-flexbox;
        display: -webkit-flex;
        display: flex;
        -webkit-flex-flow: row wrap;
        flex-flow: row wrap;
    }

    .container > * {
        width: 100%;
    }

    .container .first {
        -webkit-box-ordinal-group: 2;
        -moz-box-ordinal-group: 2;
        -ms-flex-order: 2;
        -webkit-order: 2;
        order: 2;
    }

    .container .second {
        -webkit-box-ordinal-group: 1;
        -moz-box-ordinal-group: 1;
        -ms-flex-order: 1;
        -webkit-order: 1;
        order: 1;
    }
}
```

在桌面上，当视口宽度大于`600px`时，您可以看到以下内容：

！[使用 flexbox-在移动/平板视图中更改框的顺序]（img/00131.jpeg）

在小于`600px`的视图上，您可以看到以下内容：

![使用 flexbox - 在移动/平板视图中更改框的顺序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00132.jpeg)

# 更多关于 transform 的内容

变换对于前端开发人员非常有用，因为你可以仅使用 CSS 执行基本的图形操作。在 CSS 的早期版本中，这只能通过 JavaScript 实现。在之前的章节中，我们使用`transform`来将元素居中在容器中。现在让我们尝试更深入地理解它，并检查我们还能做些什么：

HTML 文件如下：

```css
<table>
    <tr>
        <td>no transform</td>
        <td><div class="transform_none">no transform</div></td>
    </tr>
    <tr>
        <td>rotate</td>
        <td><div class="transform_rotate">rotate</div></td>
        <td><div class="transform_rotatex">rotateX</div></td>
        <td><div class="transform_rotatey">rotateY</div></td>
        <td><div class="transform_rotatez">rotateZ</div></td>
    </tr>
    <tr>
        <td>skew</td>
        <td><div class="transform_skew">skew</div></td>
        <td><div class="transform_skewx">skewX</div></td>
        <td><div class="transform_skewy">skewY</div></td>
    </tr>
    <tr>
        <td>scale</td>
        <td><div class="transform_scale">scale</div></td>
        <td><div class="transform_scalex">scaleX</div></td>
        <td><div class="transform_scaley">scaleY</div></td>
        <td><div class="transform_scalez">scaleZ</div></td>
    </tr>
    <tr>
        <td>translate</td>
        <td><div class="transform_translate">translate</div></td>
        <td><div class="transform_translatex">translateX</div></td>
        <td><div class="transform_translatey">translateY</div></td>
        <td><div class="transform_translatez">translateZ</div></td>
    </tr>
    <tr>
        <td>multiple</td>
        <td><div class="transform_multiple01">multiple</div></td>
    </tr>

</table>
```

SASS 文件如下：

```css
table
  border-collapse: collapse

  td, th
    border: 1px solid black

div[class^="transform_"]
  width: 100px
  height: 100px
  background: lightblue
  line-height: 100px
  text:
    align: center
    transform: uppercase
  font:
    weight: bold
    size: 10px
  display: inline-block

td
  text-align: center
  vertical-align: middle
  width: 150px
  height: 150px

.transform_
  /* Rotate */
  &rotate
    transform: rotate(25deg)

  &rotatex
    transform: rotateX(25deg)

  &rotatey
    transform: rotateY(25deg)

  &rotatez
    transform: rotateZ(25deg)

  /* Skew */
  &skew
    transform: skew(10deg, 10deg)

  &skewx
    transform: skewX(10deg)

  &skewy
    transform: skewY(10deg)

  /* Scale */
  &scalex
    transform: scaleX(1.2)

  &scale
    transform: scale(1.2)

  &scaley
    transform: scaleY(1.2)

  /* Translate */
  &translate
    transform: translate(10px, 10px)

  &translatex
    transform: translate(10%)

  &translatey
    transform: translate(10%)

  &translatez
    transform: translate(10%)

  /* Multiple */
  &multiple01
    transform: rotateX(25deg) translate(10px, 10px) skewX(10deg)
```

CSS 文件如下：

```css
table {
    border-collapse: collapse;
}

table td, table th {
    border: 1px solid black;
}

div[class^="transform_"] {
    width: 100px;
    height: 100px;
    background: lightblue;
    line-height: 100px;
    text-align: center;
    text-transform: uppercase;
    font-weight: bold;
    font-size: 10px;
    display: inline-block;
}

td {
    text-align: center;
    vertical-align: middle;
    width: 150px;
    height: 150px;
}

.transform_ {
    /* Rotate */
    /* Skew */
    /* Scale */
    /* Translate */
    /* Multiple */
}

.transform_rotate {
    transform: rotate(25deg);
}

.transform_rotatex {
    transform: rotateX(25deg);
}

.transform_rotatey {
    transform: rotateY(25deg);
}

.transform_rotatez {
    transform: rotateZ(25deg);
}

.transform_skew {
    transform: skew(10deg, 10deg);
}

.transform_skewx {
    transform: skewX(10deg);
}

.transform_skewy {
    transform: skewY(10deg);
}

.transform_scalex {
    transform: scaleX(1.2);
}

.transform_scale {
    transform: scale(1.2);
}

.transform_scaley {
    transform: scaleY(1.2);
}

.transform_translate {
    transform: translate(10px, 10px);
}

.transform_translatex {
    transform: translate(10%);
}

.transform_translatey {
    transform: translate(10%);
}

.transform_translatez {
    transform: translate(10%);
}

.transform_multiple01 {
    transform: rotateX(25deg) translate(10px, 10px) skewX(10deg);
}
```

在浏览器中的效果将如下所示：

![更多关于 transform 的内容](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00133.jpeg)

在上面的示例中，在浏览器的示例视图中有一堆可能的变换。在第一行中，你可以看到没有任何变换的元素。在接下来的每一行中，你可以检查以下内容：

+   **rotate**

+   **skew**

+   **scale**

+   **translate**

+   **multiple**

变换的重要方面是可以在每种变换类型中使用的单位：

+   `rotate`：度数，例如，`rotate(20deg, 40deg).`

+   `skew`：度数，例如，`skew(30deg, 50deg).`

+   `scale`：数字，其中 1 = 100%，例如，`scale(1.5, 1.5).`

+   `translate`：与宽度相关的单位，如像素百分比，例如，`translate(50%, 50%)`。重要信息：百分比与转换对象的尺寸相关。

在前面截图的最后一行中，有一个示例显示了如何在一行中链接多个变换。当你需要添加多个变换时，可以使用这个示例。

# 总结

在本章中，你了解了现代 CSS 的主要特性。你学会了 flexbox 的工作原理以及如何在项目中使用它。你分析了二维变换，这些变换可以在你的项目中使用。本章是对新 CSS 特性的介绍，将帮助你了解可能性。

在下一章中，我们将专注于渐变、阴影和动画。我们将创建线性和径向渐变框和文本阴影，并且还将了解`calc`函数的知识。
