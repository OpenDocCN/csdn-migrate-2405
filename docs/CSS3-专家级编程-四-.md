# CSS3 专家级编程（四）

> 原文：[`zh.annas-archive.org/md5/2789AE2FE8CABD493B142B2A68E84610`](https://zh.annas-archive.org/md5/2789AE2FE8CABD493B142B2A68E84610)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：Calc, Gradients, and Shadows

在上一章中，我们分析了 flexbox 和基于 flexbox 模型的简单结构。在本章中，我们将专注于 CSS 的以下方面：

+   Calc 函数

+   渐变

+   阴影

+   CSS 动画。

+   使用 data-attribute

让我们开始吧！

# calc()方法

你有没有遇到过混合单位的问题？例如，假设你需要制作一个方程 60%-10px？这些操作在旧浏览器中可能非常有用，而且现在在 CSS 中可以通过`calc()`方法实现。你如何使用它？让我们解决一个有两个浮动框的问题；一个具有固定宽度，第二个则根据可能的最大宽度进行调整。代码如下：

HTML：

```css
<div class="container">
    <div class="first">First</div>
    <div class="second">Second</div>
</div>
```

SASS：

```css
  &:after
    content: ""
    display: table
    clear: both

.container
  +clearfix

  & > *
    float: left
    height: 200px
    padding: 10px
    box-sizing: border-box

.first
  width: 100px
  background: red

.second
  width: calc(100% - 100px)
  background: blue
```

编译后的 CSS：

```css
.container:after {
    content: "";
    display: table;
    clear: both;
}

.container >* {
    float: left;
    height: 200px;
    padding: 10px;
    box-sizing: border-box;
}

.first {
    width: 100px;
    background: red;
}

.second {
    width: calc(100% - 100px);
    background: blue;
}
```

这是最终结果：

![calc()方法](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00134.jpeg)

`calc()`函数给了我们一个机会去做简单的方程，比如百分比减去像素。在这个简单的例子中，你可以看到我们不需要使用 padding 和绝对位置的技巧。你可以正确使用`calc()`函数，问题就会得到解决。

# CSS 中的渐变

有经验的前端开发人员还记得渐变是如何作为背景图像完成的。是的！那是模仿浏览器中的渐变的唯一想法。你需要从 PSD 文件中裁剪 1px 宽度和渐变高度（如果是垂直渐变；在水平渐变的情况下，高度是 1px，宽度由渐变的宽度指定）。然后，你需要将其添加到 CSS 中，并在背景中重复你的*魔术*图像。

现在，你可以在 CSS 中做到这一点！让我们从线性渐变开始。

## 线性渐变

线性渐变可以有两种类型：从上到下或从左到右。让我们从垂直渐变开始：

```css
background: linear-gradient(to bottom, #000 0%, #f00 100%)
```

这段代码将生成一个从上到下的线性渐变。在顶部，颜色将是黑色，在底部将是红色。

![线性渐变](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00135.jpeg)

然而，成为前端开发人员可能并不那么容易。这就是为什么你需要记住前缀：

```css
background: -webkit-gradient(linear, left top, left bottom, color-stop(0%, #000), color-stop(100%, #f00))
background: -moz-linear-gradient(top, #000 0%, #f00 100%)
background: -webkit-linear-gradient(top, #000 0%, #f00 100%)
background: -o-linear-gradient(top, #000 0%, #f00 100%)
background: -ms-linear-gradient(top, #000 0%, #f00 100%)
background: linear-gradient(to bottom, #000 0%, #f00 100%)
```

正如你所看到的，带前缀的定义占用了大量的代码，特别是当你需要为 IE9 提供回退时（最后一行带有 filter 定义）。

基本的水平渐变定义如下：

```css
background: linear-gradient(left, #fff, #000) 
```

这个例子将生成一个从左到右的渐变，右边是白色，左边是黑色。

![线性渐变](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00136.jpeg)

这是带前缀的版本：

```css
background: -webkit-gradient(linear, left top, right top, from(#fff), to(#000))
background: -webkit-linear-gradient(left, #fff, #000)
background: -moz-linear-gradient(left, #fff, #000)
background: -ms-linear-gradient(left, #fff, #000)
background: -o-linear-gradient(left, #fff, #000)
background: linear-gradient(left, #fff, #000)
```

多色渐变呢？当然是可能的：

```css
background: linear-gradient(to right, black, red, white)
```

这是效果：

![线性渐变](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00137.jpeg)

你也可以旋转渐变：

HTML：

```css
<div class="gradient-04"></div>
```

SASS：

```css
div[class^="gradient-"]
  height: 200px
  width: 200px
  margin-bottom: 20px

.gradient-04
  background: linear-gradient(45deg , black, red, white)
```

CSS：

```css
div[class^="gradient-"] {
    height: 200px;
    width: 200px;
    margin-bottom: 20px;
}

.gradient-04 {
    background: linear-gradient(45deg, black, red, white);
}
```

在浏览器中的效果：

![线性渐变](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00138.jpeg)

如果你想改变颜色之间的平衡呢？例如，也许你想在渐变中有更高浓度的黑色？这也是可能的：

SASS：

```css
.gradient-05
  background: linear-gradient(to right, black 40%, red 50%, white 100%)
```

CSS：

```css
.gradient-05 {
    background: linear-gradient(to right, black 40%, red 50%, white 100%);
}
```

在浏览器中的效果：

![线性渐变](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00139.jpeg)

要理解这一点，你需要逐步检查这个例子：

```css
black 40%:This line means that black color will be finished in 40% of width of the box
red 50%:This means that red color will be finished in 50% of width of the box
white 100%:This means that white color will be finished in 100% of width of the box
```

## 使用渐变 mixin

在本章中，你可以获得这些 mixin 并在你的项目中使用它们。我不喜欢每次都写很长的代码——只需写一次，然后重复简短版本。这就是为什么我准备了这两个简单的渐变：

```css
=linearGradientFromTop($startColor, $endColor)
  background: $startColor
  background: -webkit-gradient(linear, left top, left bottom, color-stop(0%, $startColor), color-stop(100%, $endColor))
  background: -moz-linear-gradient(top, $startColor 0%, $endColor 100%)
  background: -webkit-linear-gradient(top, $startColor 0%, $endColor 100%)
  background: -o-linear-gradient(top, $startColor 0%, $endColor 100%)
  background: -ms-linear-gradient(top, $startColor 0%, $endColor100%)
  background: linear-gradient(to bottom, $startColor 0%, $endColor 100%)
  filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#{$startColor}', endColorstr='#{$endColor}',GradientType=0 )

=linearGradientFromLeft($startColor, $endColor)
  background-color: $startColor
background: -webkit-gradient(linear, left top, right top, from($startColor), to($endColor))
  background: -webkit-linear-gradient(left, $startColor, $endColor)
  background: -moz-linear-gradient(left, $startColor, $endColor)
  background: -ms-linear-gradient(left, $startColor, $endColor)
  background: -o-linear-gradient(left, $startColor, $endColor)
  background: linear-gradient(left, $startColor, $endColor)
  filter: progid:DXImageTransform.Microsoft.gradient(startColorStr='#{$startColor}', endColorStr='#{$endColor}', gradientType='1')
```

在前面的混合示例中最重要的一点是，您需要使用`hex`颜色的完整表示。例如，您不能使用`#f00`来表示红色。您必须使用`#ff0000`。这是因为 IE9 及更低版本不支持渐变中较短的颜色表示。混合中的另一个重要事项是第一行，它仅设置背景颜色。这是所有不支持任何前缀/非前缀渐变版本的浏览器的回退。使用它，颜色仅设置为作为`$startColor`设置的颜色。混合中的第二行与基于 WebKit 的旧版本浏览器有关。最后一行与旧版 IE（9 及更低版本）有关。当然，如果没有使用或不需要，您不必在项目中保留此代码。您可以修改它以满足项目的要求。

## 径向渐变

在一些项目中，您需要添加径向渐变。径向渐变标准函数如下：

```css
radial-gradient()
```

或者你可以使用：

```css
background: repeating-radial-gradient()
```

让我们检查一个示例代码和渐变使用的可能性：

HTML：

```css
<table>
    <tr>
        <td><div class="gradient-04"></div></td>
        <td><div class="gradient-05"></div></td>
        <td><div class="gradient-06"></div></td>
    </tr>
    <tr>
        <td><div class="gradient-07"></div></td>
        <td><div class="gradient-08"></div></td>
        <td><div class="gradient-09"></div></td>
    </tr>
    <tr>
        <td><div class="gradient-10"></div></td>
        <td><div class="gradient-11"></div></td>
        <td><div class="gradient-12"></div></td>
    </tr>
</table>
```

SASS：

```css
div[class^="gradient-"]
  height: 200px
  width: 200px
  margin-bottom: 20px

//
.gradient-04
  background: red
  background: -webkit-radial-gradient(50% 50%, closest-side, red, black)
  background: -o-radial-gradient(50% 50%, closest-side, red, black)
  background: -moz-radial-gradient(50% 50%, closest-side, red, black)
  background: radial-gradient(closest-side at 50% 50%, red, black)

.gradient-05
  background: red
  background: -webkit-radial-gradient(10% 10%, closest-side, red, black)
  background: -o-radial-gradient(10% 10%, closest-side, red, black)
  background: -moz-radial-gradient(10% 10%, closest-side, red, black)
  background: radial-gradient(closest-side at 10% 10%, red, black)

.gradient-06
  background: red
  background: -webkit-radial-gradient(50% 10%, closest-side, red, black)
  background: -o-radial-gradient(50% 10%, closest-side, red, black)
  background: -moz-radial-gradient(50% 10%, closest-side, red, black)
  background: radial-gradient(closest-side at 50% 10%, red, black)

.gradient-07
  background: red
  background: -webkit-radial-gradient(50% 50%, closest-corner, red, black)
  background: -o-radial-gradient(50% 50%, closest-corner, red, black)
  background: -moz-radial-gradient(50% 50%, closest-corner, red, black)
  background: radial-gradient(closest-corner at 50% 50%, red, black)

.gradient-08
  background: red
  background: -webkit-radial-gradient(10% 10%, closest-corner, red, black)
  background: -o-radial-gradient(10% 10%, closest-corner, red, black)
  background: -moz-radial-gradient(10% 10%, closest-corner, red, black)
  background: radial-gradient(closest-corner at 10% 10%, red, black)

.gradient-09
  background: red
  background: -webkit-radial-gradient(50% 10%, closest-corner, red, black)
  background: -o-radial-gradient(50% 10%, closest-corner, red, black)
  background: -moz-radial-gradient(50% 10%, closest-corner, red, black)
  background: radial-gradient(closest-corner at 50% 10%, red, black)

.gradient-10
  background: red
  background: -webkit-repeating-radial-gradient(50% 50%, closest-corner,  red, black)
  background: -o-repeating-radial-gradient(50% 50%, closest-corner, red, black)
  background: -moz-repeating-radial-gradient(50% 50%, closest-corner, red, black)
  background: repeating-radial-gradient(closest-corner at 50% 50%, red, black)

.gradient-11
  background: red
  background: -webkit-repeating-radial-gradient(10% 10%, closest-corner, red, black)
  background: -o-repeating-radial-gradient(10% 10%, closest-corner, red, black)
  background: -moz-repeating-radial-gradient(10% 10%, closest-corner, red, black)
  background: repeating-radial-gradient(closest-corner at 10% 10%, red, black)

.gradient-12
  background: red
  background: -webkit-repeating-radial-gradient(50% 10%, closest-corner, red, black)
  background: -o-repeating-radial-gradient(50% 10%, closest-corner, red, black)
  background: -moz-repeating-radial-gradient(50% 10%, closest-corner, red, black)
  background: repeating-radial-gradient(closest-corner at 50% 10%, red, black)
```

CSS：

```css
div[class^="gradient-"] {
    height: 200px;
    width: 200px;
    margin-bottom: 20px;
}

.gradient-04 {
    background: red;
    background: -webkit-radial-gradient(50% 50%, closest-side, red, black);
    background: -o-radial-gradient(50% 50%, closest-side, red, black);
    background: -moz-radial-gradient(50% 50%, closest-side, red, black);
    background: radial-gradient(closest-side at 50% 50%, red, black);
}

.gradient-05 {
    background: red;
    background: -webkit-radial-gradient(10% 10%, closest-side, red, black);
    background: -o-radial-gradient(10% 10%, closest-side, red, black);
    background: -moz-radial-gradient(10% 10%, closest-side, red, black);
    background: radial-gradient(closest-side at 10% 10%, red, black);
}

.gradient-06 {
    background: red;
    background: -webkit-radial-gradient(50% 10%, closest-side, red, black);
    background: -o-radial-gradient(50% 10%, closest-side, red, black);
    background: -moz-radial-gradient(50% 10%, closest-side, red, black);
    background: radial-gradient(closest-side at 50% 10%, red, black);
}

.gradient-07 {
    background: red;
    background: -webkit-radial-gradient(50% 50%, closest-corner, red, black);
    background: -o-radial-gradient(50% 50%, closest-corner, red, black);
    background: -moz-radial-gradient(50% 50%, closest-corner, red, black);
    background: radial-gradient(closest-corner at 50% 50%, red, black);
}

.gradient-08 {
    background: red;
    background: -webkit-radial-gradient(10% 10%, closest-corner, red, black);
    background: -o-radial-gradient(10% 10%, closest-corner, red, black);
    background: -moz-radial-gradient(10% 10%, closest-corner, red, black);
    background: radial-gradient(closest-corner at 10% 10%, red, black);
}

.gradient-09 {
    background: red;
    background: -webkit-radial-gradient(50% 10%, closest-corner, red, black);
    background: -o-radial-gradient(50% 10%, closest-corner, red, black);
    background: -moz-radial-gradient(50% 10%, closest-corner, red, black);
    background: radial-gradient(closest-corner at 50% 10%, red, black);
}

.gradient-10 {
    background: red;
    background: -webkit-repeating-radial-gradient(50% 50%, closest-corner, red, black);
    background: -o-repeating-radial-gradient(50% 50%, closest-corner, red, black);
    background: -moz-repeating-radial-gradient(50% 50%, closest-corner, red, black);
    background: repeating-radial-gradient(closest-corner at 50% 50%, red, black);
}

.gradient-11 {
    background: red;
    background: -webkit-repeating-radial-gradient(10% 10%, closest-corner, red, black);
    background: -o-repeating-radial-gradient(10% 10%, closest-corner, red, black);
    background: -moz-repeating-radial-gradient(10% 10%, closest-corner, red, black);
    background: repeating-radial-gradient(closest-corner at 10% 10%, red, black);
}

.gradient-12 {
    background: red;
    background: -webkit-repeating-radial-gradient(50% 10%, closest-corner, red, black);
    background: -o-repeating-radial-gradient(50% 10%, closest-corner, red, black);
    background: -moz-repeating-radial-gradient(50% 10%, closest-corner, red, black);
    background: repeating-radial-gradient(closest-corner at 50% 10%, red, black);
}
```

这是在浏览器中的效果：

![径向渐变](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00140.jpeg)

# 如何添加盒子阴影

回到过去，CSS 中没有阴影功能。这个功能让您有机会向盒子（使用`box-shadow`）和文本（使用`text-shadow`）添加阴影效果。`box-shadow`是如何创建的？让我们来看看 CSS 中这个属性的参数：

```css
box-shadow: horizontal-shadow vertical-shadow blur spread color
```

在所有参数之前，您可以添加内部。使用此属性，阴影将位于元素内部。

理解这一点最简单的方法是查看它在浏览器中的行为：

HTML：

```css
<div class="container">
    <div class="box_container">
        <div class="box__bottom_right">bottom right</div>
    </div>
    <div class="box_container">
        <div class="box__bottom_left">bottom left</div>
    </div>
    <div class="box_container">
        <div class="box__top_right">top right</div>
    </div>
    <div class="box_container">
        <div class="box__top_left">top left</div>
    </div>
    <div class="box_container">
        <div class="box__blurred">blurred</div>
    </div>
    <div class="box_container">
        <div class="box__notblurred">notblurred</div>
    </div>
    <div class="box_container">
        <div class="box__spreaded">spreaded</div>
    </div>
    <div class="box_container">
        <div class="box__innershadow">inner shadow</div>
    </div>
</div>
```

SASS：

```css
=clearfix
  &:after
    content: ""
    display: table
    clear: both

.container
  +clearfix
  width: 800px

  & > *
    float: left

.box_container
  width: 200px
  height: 200px
  position: relative

div[class^="box__"]
  width: 100px
  height: 100px
  position: absolute
  background: lightblue
  top: 50%
  left: 50%
  line-height: 100px
  font:
    size: 10px
  text:
    align: center
  transform: translate(-50%,-50%)

.box__bottom_right
  box-shadow: 5px 5px 5px 0 #000

.box__bottom_left
  box-shadow: -5px 5px 5px 0 #000

.box__top_right
  box-shadow: 5px -5px 5px 0 #000

.box__top_left
  box-shadow: -5px -5px 5px 0 #000

.box__blurred
  box-shadow: 0px 0px 10px 0 #000

.box__notblurred
  box-shadow: 0px 0px 0 0 #000

.box__spreaded
  box-shadow: 0px 0px 0 5px #000

.box__innershadow
  box-shadow: inset 0px 0px 5px 0px #000
```

CSS：

```css
.container {
    width: 800px;
}

.container:after {
    content: "";
    display: table;
    clear: both;
}

.container > * {
    float: left;
}

.box_container {
    width: 200px;
    height: 200px;
    position: relative;
}

div[class^="box__"] {
    width: 100px;
    height: 100px;
    position: absolute;
    background: lightblue;
    top: 50%;
    left: 50%;
    line-height: 100px;
    font-size: 10px;
    text-align: center;
    transform: translate(-50%, -50%);
}

.box__bottom_right {
    box-shadow: 5px 5px 5px 0 #000;
}

.box__bottom_left {
    box-shadow: -5px 5px 5px 0 #000;
}

.box__top_right {
    box-shadow: 5px -5px 5px 0 #000;
}

.box__top_left {
    box-shadow: -5px -5px 5px 0 #000;
}

.box__blurred {
    box-shadow: 0px 0px 10px 0 #000;
}

.box__notblurred {
    box-shadow: 0px 0px 0 0 #000;
}

.box__spreaded {
    box-shadow: 0px 0px 0 5px #000;
}

.box__innershadow {
    box-shadow: inset 0px 0px 5px 0px #000;
}
```

这是在浏览器中的效果：

![如何添加盒子阴影](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00141.jpeg)

在这个例子中，您可以查看如何设置垂直和水平阴影。此外，您还可以设置模糊扩散和其颜色。向垂直和水平阴影添加正值会将阴影分别移动到底部和右侧。当您添加负值时，它将移动到顶部和左侧。

# 如何添加文本阴影

为盒子添加阴影非常简单。但是我们如何为文本添加阴影？使用`text-shadow`属性是可能的。它的工作方式与`box-shadow`非常相似。这是定义：

```css
text-shadow: horizontal-shadow vertical-shadow blur-radius color
```

让我们创建一个基于上一章代码的示例，以更好地理解`text-shadow`属性：

HTML：

```css
<div class="container">
    <div class="box_container">
        <div class="box__bottom_right">bottom right</div>
    </div>
    <div class="box_container">
        <div class="box__bottom_left">bottom left</div>
    </div>
    <div class="box_container">
        <div class="box__top_right">top right</div>
    </div>
    <div class="box_container">
        <div class="box__top_left">top left</div>
    </div>
    <div class="box_container">
        <div class="box__blurred">blurred</div>
    </div>
    <div class="box_container">
        <div class="box__notblurred">notblurred</div>
    </div>
</div>
```

SASS：

```css
=clearfix
  &:after
    content: ""
    display: table
    clear: both

.container
  +clearfix
  width: 00px

  &>*
    float: left

.box_container
  width: 100px
  height: 100px
  position: relative

div[class^="box__"]
  width: 100px
  height: 100px
  position: absolute
  background: lightblue
  top: 50%
  left: 50%
  line-height: 100px
  font:
    size: 10px
  text:
    align: center
  transform: translate(-50%,-50%)

.box__bottom_right
  text-shadow: 5px 5px 5px #000

.box__bottom_left
  text-shadow: -5px 5px 5px #000

.box__top_right
  text-shadow: 5px -5px 5px #000

.box__top_left
  text-shadow: -5px -5px 5px #000

.box__blurred
  text-shadow: 0px 0px 10px #000

.box__notblurred
  text-shadow: 5px 5px 0 red
```

CSS：

```css
.container {
    width: 0px;
}

.container:after {
    content: "";
    display: table;
    clear: both;
}

.container >* {
    float: left;
}

.box_container {
    width: 100px;
    height: 100px;
    position: relative;
}

div[class^="box__"] {
    width: 100px;
    height: 100px;
    position: absolute;
    background: lightblue;
    top: 50%;
    left: 50%;
    line-height: 100px;
    font-size: 10px;
    text-align: center;
    transform: translate(-50%, -50%);
}

.box__bottom_right {
    text-shadow: 5px 5px 5px #000;
}

.box__bottom_left {
    text-shadow: -5px 5px 5px #000;
}

.box__top_right {
    text-shadow: 5px -5px 5px #000;
}

.box__top_left {
    text-shadow: -5px -5px 5px #000;
}

.box__blurred {
    text-shadow: 0px 0px 10px #000;
}

.box__notblurred {
    text-shadow: 5px 5px 0 red;
}
```

这是在浏览器中的效果：

![如何添加文本阴影](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00142.jpeg)

# 其他字体和文本功能

在过去的 5 年中，CSS 中的字体功能发生了很大变化。在过去，没有机会使用非标准字体，因为它被描述为*互联网安全*。这是使 Flash 技术更流行的问题之一，不仅因为完整的 Flash 页面，还因为**可扩展的 Inman Flash Replacement**（**SIFR**）。使用 SIFR，您只需要在 Adobe Flash 中附加您的字体并编译文件；然后您可以在网站上使用您的字体。但是您的 HTML 页面中有 Flash 实例。然后，有一种基于 JavaScript 的方法叫做**cufon**。您可以使用您的字体访问 cufon 页面，编译您的字体，然后在您的网站上附加`cufon.js`和您编译的字体（JS 文件）。在 JavaScript 中，您需要添加应该被交换的字体，最后您的字体就会在网站上可见。

如今，我们可以使用 font-face 在 Web 版本中使用自定义字体。

## 在浏览器中使用非标准字体

如果您想在浏览器中使用您的字体，您需要准备它。font-face 的基本定义基于原始 CSS 中的这个示例：

```css
@font-face {
    font-family: font_name;
    src: url(your_font.woff);
}
```

如果您现在想使用您的字体，您需要在 CSS 中附加此示例代码：

```css
.classOfElement {
    font-family: font_name;
}
```

主要问题是，如果我有另一种字体格式，我该如何准备我的字体以在浏览器中使用？如果您有一个字体，您可以使用`fontsquirrel.com`生成最终的 CSS 视图以供使用。当然，还有一些其他地方可以搜索字体：

+   Google Fonts ([`www.google.com/fonts`](https://www.google.com/fonts))

+   Typekit ([`typekit.com/fonts`](https://typekit.com/fonts))

在这里，您可以找到在您的项目中可以直接使用的字体。

## 使用 CSS 动画

CSS 动画是一个非常有用的功能。您无需使用 JavaScript 进行简单的动画，而且 CSS 动画受到 GPU（图形处理单元）的支持。CSS 动画可以做什么？让我们看下面的例子：

```css
<div class="container">
    <div class="rollin"></div>
</div>
```

SASS：

```css
.container
  width: 600px
  border: 1px solid #000

.rollin
  width: 100px
  height: 100px
  background: #000

  animation:
    duration: 1s
    name: roll_in
    iteration-count: 1
    delay: 1s
    fill-mode: backwards

@keyframes roll_in
  from
    margin-left: 100%
    opacity: .3

  to
    margin-left: 0%
    opacity: 1
```

这是生成的 CSS：

```css
.container {
    width: 600px;
    border: 1px solid #000;
}

.rollin {
    width: 100px;
    height: 100px;
    background: #000;
    animation-duration: 1s;
    animation-name: roll_in;
    animation-iteration-count: 1;
    animation-delay: 1s;
    animation-fill-mode: backwards;
}

@keyframes roll_in {
from {
        margin-left: 100%;
        opacity: 0.3;
    }
to {
        margin-left: 0%;
        opacity: 1;
    }
}
```

在浏览器中的效果：

![使用 CSS 动画](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00143.jpeg)

您可以在 SASS/CSS 文件中看到动画的进度。

CSS 动画的属性有：

+   `animation-name`: 此属性定义了应使用哪个`@keyframs`定义，例如：`animation-name: roll_in`

+   `animation-delay`: 此属性定义了元素加载和动画开始之间的延迟时间，例如：`animation-delay: 2s`

+   `animation-duration`: 此属性定义了动画的持续时间，例如：`animation-duration: 2s`

+   `animation-iteration-count`: 此属性定义了动画应重复多少次，例如：`animation- iteration-count: 2`

+   `animation-fill-mode`: 此属性定义了元素在延迟时间方面的行为，例如：`animation- fill-mode: backward`

我如何在悬停时添加动画？让我们创建一个示例：

HTML：

```css
<a href="" class="animation_hover">Element</a>
```

SASS：

```css
.animation_hover
  display: inline-block
  padding: 20px
  background: #d3d3d3
  text-decoration: none
  color: black
  transition:
    duration: .5s
    property: all

  &:hover
    background: blue
    color: white
```

CSS：

```css
.animation_hover {
    display: inline-block;
    padding: 20px;
    background: #d3d3d3;
    text-decoration: none;
    color: black;
    transition-duration: 0.5s;
    transition-property: all;
}

.animation_hover:hover {
    background: blue;
    color: white;
}
```

这是在浏览器中的最终结果：

![使用 CSS 动画](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00144.jpeg)

您可以在悬停操作之前和之后看到元素。此外，还有一个过渡，为此按钮添加了一些动画效果。在这个动画声明中最重要的是什么？

```css
transition-property
```

前面的声明给出了应该被动画化的值列表。这个列表的一个例子可能是：

```css
Color, background-color
```

这个列表意味着颜色和背景颜色将被动画化。当您想要动画化所有属性时，可以使用*all*作为值。

# 数据属性

数据属性主要与 HTML 代码和 JavaScript 相关。使用数据属性，您可以描述 DOM 元素并在脚本中使用这些值，例如，用于排序、动画或任何其他目的。但它如何帮助您在 CSS 代码中呢？让我们考虑以下示例。

## 问题 - 悬停时加粗移动导航

这是网站上一个非常常见的问题。假设您有内联元素对悬停作出反应。悬停后，元素的字重从普通变为粗体。效果是悬停元素之后的每个元素都向右移动。让我们从 HTML 代码开始：

```css
<ul>
    <li><a href="#">First</a></li>
    <li><a href="#">Second</a></li>
    <li><a href="#">Third</a></li>
    <li><a href="#">Fourth</a></li>
    <li><a href="#">Fifth</a></li>
</ul>
```

SASS：

```css
li, a
  display: inline-block
  text-align: center

a:hover
  font-weight: bold
```

CSS：

```css
li, a {
    display: inline-block;
    text-align: center;
}

a:hover {
    font-weight: bold;
}
```

CSS：

```css
li, a {
    display: inline-block;
    text-align: center;
}

a:hover {
    font-weight: bold;
}
```

在浏览器中的效果，没有和有悬停操作：

![问题 - 悬停时加粗移动导航](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00145.jpeg)

红色标尺是结构中的指向性偏移。现在，让我们使用我们的*antidotum*。首先，我们需要轻微更改我们的 HTML 代码。这个变化与`data-alt`属性及其值有关。作为值，我们正在复制 DOM 元素的值：

HTML：

```css
<ul class="bold_list_fix">
    <li><a href="#" data-alt="First">First</a></li>
    <li><a href="#" data-alt="Second">Second</a></li>
    <li><a href="#" data-alt="Third">Third</a></li>
    <li><a href="#" data-alt="Fourth">Fourth</a></li>
    <li><a href="#" data-alt="Fifth">Fifth</a></li>
</ul>
```

SASS：

```css
.bold_list_fix
  a::after
    display: block
    content: attr(data-alt)
    font-weight: bold
    height: 1px
    color: transparent
    overflow: hidden
    visibility: hidden
```

CSS：

```css
.bold_list_fix a::after {
    display: block;
    content: attr(data-alt);
    font-weight: bold;
    height: 1px;
    color: transparent;
    overflow: hidden;
}
```

大功告成！正如您所看到的，这个技巧是基于`:after`伪元素，它现在被保留为一个不可见的元素。内容是通过从 HTML 代码中获取`attr(data-alt)`属性设置的。对这个内容，加粗特性被添加。这给了我们足够的空间，这在以前的代码中没有被占用。最后，元素不会向右移动。

# 摘要

在本章中，我们讨论了 CSS 渐变，因此您无需使用图像制作渐变。我们分析了`box-shadow`和`text-shadow`的使用。我们创建了一个简单的动画并分析了其参数。此外，我们在 CSS 代码中使用了数据属性。

在下一章中，我们将讨论 CSS 中的 DRY（即不要重复自己）并尝试创建一个基本框架，这将是您项目的起点。


# 第十章：不要重复自己-让我们创建一个简单的 CSS 框架

你有多少次做了一些工作，只是在下一个项目中重复了一遍？你有多少次想到了可重复使用的元素？在编码时，你应该考虑下一次在同一个或另一个项目上工作时可以省略多少操作。这意味着你需要使用以下内容：

+   自动化

+   代码模板或框架

这一章是关于构建可重用代码以及如何最终将其用作项目基础的。在这一章中，我们将涵盖以下主题：

+   为一个小而简单的 CSS 框架制定计划

+   创建你自己的网格系统

+   创建可重用元素

请记住，这段代码可以并且应该被扩展。所示的过程应该让你更加清楚如何利用你已经创建的框架来帮助自己，但仍然可以随着你的代码发展而发展。当然，你也可以使用其他框架。

# 文件结构

当你计划一个系统/框架时，文件结构是非常重要的。当你开始创建某些东西时，它需要一个演变。所以根据开发过程，你的系统在不断演变。当你的系统在演变时，它会发生很多变化。所以，让我们创建一个简单的结构：

+   有用的 mixin：

+   有用元素的简化形式

+   内联列表

+   基本元素

+   清除浮动

+   简单的渐变生成器

+   网格 mixin：

+   n 列中的第 n 列

+   表单：

+   输入/文本区样式助手

+   输入占位符

+   按钮：

+   内联（自动宽度）

+   全宽度

+   标准导航：

+   一级

+   两级

我们将使用 mixin 而不是已经创建的类。为什么？我们希望尽量减少 CSS 代码，这样当我们生成完整的 12 列网格时，我们将在媒体查询中的每个断点产生 12 个类。作为前端开发人员，我们希望创建尽可能少的代码。当然，我们可以重用一些类并用 SASS 扩展它们，但这个框架的主要方法是简单和可重用的 mixin。

# 有用元素的简化形式

在 CSS 代码（不仅仅是 CSS），每次重复代码的一部分时，你希望更快地获得最终效果。那么为什么不为一些 CSS 声明创建简短的形式呢？让我们看看我们可以做些什么来缩短它：

```css
/* Text decoration */
=tdn
  text-decoration: none

=tdu
  text-decoration: underline

/* Text align */
=tac
  text-align: center

=tar
  text-align: right

=tal
  text-align: left

/* Text transform */
=ttu
  text-transform: uppercase

=ttl
  text-transform: lowercase

/* Display */
=di
  display: inline

=db
  display: block

=dib
  display: inline-block

/* Margin 0 auto */
=m0a
  margin: 0 auto
```

现在，每次你想将一些文本转换为大写时，只需使用以下代码：

```css
.sampleClass
  +ttu
```

这是编译后的 CSS：

```css
.sampleClass {
    text-transform: uppercase;
}
```

另一个使用短 mixin 的例子是一个元素，它将显示为块元素，文本将居中显示：

```css
.sampleClass
  +db
  +tac
```

这是编译后的 CSS：

```css
.sampleClass {
    display: block;
    text-align: center;
}
```

# 其他 mixin

还有其他对我们的框架有用的 mixin：

+   渐变

+   动画

+   清除浮动

让我们从渐变 mixin 开始：

```css
=linearGradientFromTop($startColor, $endColor)
  background: $startColor /* Old browsers */
  background: -moz-linear-gradient(top,  $startColor 0%, $endColor 100%)
  background: -webkit-gradient(linear, left top, left bottom, color-stop(0%, $startColor), color-stop(100%, $endColor))
  background: -webkit-linear-gradient(top,  $startColor 0%, $endColor 100%)
  background: -o-linear-gradient(top,  $startColor 0%, $endColor 100%)
  background: -ms-linear-gradient(top,  $startColor 0%, $endColor 100%)
  background: linear-gradient(to bottom,  $startColor 0%, $endColor 100%)
  filter: progid:DXImageTransform.Microsoft.gradient( startColorstr='#{$startColor}', endColorstr='#{$endColor}',GradientType=0 ) 

=linearGradientFromLeft($startColor, $endColor)
  background-color: $startColor
  background: -webkit-gradient(linear, left top, right top, from($startColor), to($endColor))
  background: -webkit-linear-gradient(left, $startColor, $endColor)
  background: -moz-linear-gradient(left, $startColor, $endColor)
  background: -ms-linear-gradient(left, $startColor, $endColor)
  background: -o-linear-gradient(left, $startColor, $endColor)
  background: linear-gradient(left, $startColor, $endColor)
  filter: progid:DXImageTransform.Microsoft.gradient(startColorStr='#{$startColor}', endColorStr='#{$endColor}', gradientType='1')
```

全部动画：

```css
=animateAll($time)
  -webkit-transition: all $time ease-in-out
  -moz-transition: all $time ease-in-out
  -o-transition: all $time ease-in-out
  transition: all $time ease-in-out
```

## 清除浮动

不要忘记在你的私人 SASS 框架中的 mixin 中添加`clearfix`。你将使用它作为 mixin 的调用或作为一个类，并且所有其他元素将扩展之前创建的类：

```css
=clearfix
  &:after
    content: " "
    visibility: hidden
    display: block
    height: 0
    clear: both
```

每次你想创建一个可重用的`clearfix`类时，可以这样做：

```css
.clearfix
  +clearfix
```

这是编译后的 CSS：

```css
.clearfix:after {
    content: " ";
    visibility: hidden;
    display: block;
    height: 0;
    clear: both;
}
```

或者可以写一个更简短的版本：

```css
.cf
  +clearfix
```

这是编译后的 CSS：

```css
.cf:after {
    content: " ";
    visibility: hidden;
    display: block;
    height: 0;
    clear: both;
}
```

现在，你可以在 SASS 代码中使用`@extend`来扩展它：

```css
.element
  @extend .cf
```

这是编译后的 CSS：

```css
.cf:after, .element:after {
    content: " ";
    visibility: hidden;
    display: block;
    height: 0;
    clear: both;
}
```

将绝对元素居中在另一个相对元素中：

```css
/* Absolute center vertically and horizontally */
=centerVH
  position: absolute
  top: 50%
  left: 50%
  -ms-transform: translate(-50%,-50%)
  -webkit-transform: translate(-50%,-50%)
  transform: translate(-50%,-50%)
```

# 媒体查询

在每个响应式网页项目中，你都需要创建媒体查询。你需要选择要实施的步骤，然后开始根据这些步骤创建项目。

## 媒体查询模板

媒体查询非常简单易用。媒体查询的主要问题是可重用的步骤，你可以将它们保存在一个地方。在一些项目中，你需要添加更多的查询，因为项目可见性问题或一些额外的代码会影响你的代码。让我们专注于如何通过一些设置来做一次，然后在我们的代码中使用它。

基本设置集中在以下内容上：

+   移动设备（手机）

+   移动设备（平板）

+   桌面设备

+   桌面设备（大屏）

在某些情况下，你可以扩展这个列表，加入移动设备位置（纵向和横向），但是更少的媒体查询对于维护来说更好更容易。那么我们如何保持这些尺寸呢？

+   `$small`：320 像素

+   `$medium`：768 像素

+   `$large`：1024 像素

# 网格

在标准的 HTML/CSS 项目中，最常见的元素是网格。当然，你可以使用别人的网格或从 CSS 框架（如 Bootstrap 或 Foundation）中获取。从头开始创建它很难吗？并不是真的。在本章中，我们将创建一个基本的网格系统，并将使用它来看看它是如何创建行和列的。

## 标准网格 16/12

标准网格是基于 16 列或 12 列系统的。这两种系统的优势是什么？这取决于你的结构。例如，分析布局后，假设你需要：

+   3 列组合

+   2 列组合

+   6 列组合

因此，你可以使用 12 列系统。但是，正如你所看到的，你需要坚持这个系统，那么你如何创建自己的代码，使其更有弹性呢？你可以使用以下命名约定：

```css
.grid-NofK
```

这里，`N`是列数，`K`是分隔符，例如：

```css
.grid-3of12
.grid-5of6
```

当你在处理网格时，你需要记住有时你需要从左边推一些列。这种情况是当你需要创建`.push`类时：

```css
.push-NofK
```

这种命名约定的优点是什么？没有静态分隔符。在经典网格中，你有一个有 12 列或 16 列及其组合的网格。这里是逐个类写的网格示例：

12 列网格：

```css
.grid-1of12 {
    width: 8.33%
}

.push-1of12 {
    margin-left: 8.33%
}

.grid-2of12 {
    width: 16.66%
}

.push-2of12 {
    margin-left: 16.66%
}

.grid-3of12 {
    width: 25%
}

.push-3of12 {
    margin-left: 25%
}

.grid-4of12 {
    width: 33.33%
}

.push-4of12 {
    margin-left: 33.33%
}

.grid-5of12 {
    width: 41.66%
}

.push-5of12 {
    margin-left: 41.66%
}

.grid-6of12 {
    width: 50%
}

.push-6of12 {
    margin-left: 50%
}

.grid-7of12 {
    width: 58.33%
}

.push-7of12 {
    margin-left: 58.33%
}

.grid-8of12 {
    width: 66.66%
}

.push-8of12 {
    margin-left: 66.66%
}

.grid-9of12 {
    width: 75%
}

.push-9of12 {
    margin-left: 75%
}

.grid-10of12 {
    width: 83.33%
}

.push-10of12 {
    margin-left: 83.33%
}

.grid-11of12 {
    width: 91.66%
}

.push-11of12 {
    margin-left: 91.66%
}

.grid-12of12 {
    width: 100%
}

.push-12of12 {
    margin-left: 100%
}
```

16 列网格：

```css
.grid-1of16 {
    width: 6.25%
}

.push-1of16 {
    margin-left: 6.25%
}

.grid-2of16 {
    width: 12.5%
}

.push-2of16 {
    margin-left: 12.5%
}

.grid-3of16 {
    width: 18.75%
}

.push-3of16 {
    margin-left: 18.75%
}

.grid-4of16 {
    width: 25%
}

.push-4of16 {
    margin-left: 25%
}

.grid-5of16 {
    width: 31.25%
}

.push-5of16 {
    margin-left: 31.25%
}

.grid-6of16 {
    width: 37.5%
}

.push-6of16 {
    margin-left: 37.5%
}

.grid-7of16 {
    width: 43.75%
}

.push-7of16 {
    margin-left: 43.75%
}

.grid-8of16 {
    width: 50%
}

.push-8of16 {
    margin-left: 50%
}

.grid-9of16 {
    width: 56.25%
}

.push-9of16 {
    margin-left: 56.25%
}

.grid-10of16 {
    width: 62.5%
}

.push-10of16 {
    margin-left: 62.5%
}

.grid-11of16 {
    width: 68.75%
}

.push-11of16 {
    margin-left: 68.75%
}

.grid-12of16 {
    width: 75%
}

.push-12of16 {
    margin-left: 75%
}

.grid-12of16 {
    width: 81.25%
}

.push-12of16 {
    margin-left: 81.25%
}

.grid-12of16 {
    width: 87.5%
}

.push-12of16 {
    margin-left: 87.5%
}

.grid-12of16 {
    width: 93.75%
}

.push-12of16 {
    margin-left: 93.75%
}

.grid-12of16 {
    width: 100%
}

.push-12of16 {
    margin-left: 100%
}
```

写了很多东西……

现在，我们需要创建一个可以在媒体查询和响应式网站上使用的代码。在最流行的 CSS 框架（如 Bootstrap 和 Foundation）中，你可以为手机/平板/桌面使用类：

```css
<div class="small-2 medium-4 large-5">
</div>
```

例如，当分隔符设置为`12`时，你将在小设备上看到这个框是`2`列宽，中等设备上是`4`列宽，大文档上是`5`列宽。我们可以创建所有这些类，但我建议你创建一个 mixin，我们可以在 CSS 中描述的每个元素中调用它。

SASS 代码将如下所示：

```css
=grid($columns, $divider)
  width: percentage($columns/$divider)

=push($columns, $divider)
  margin-left: percentage($columns/$divider)
```

我们如何在 SASS 代码中使用它？假设我们有一个基于网格`16`的块，并且我们想要给它宽度为`12`的`16`，并用`2`的`16`推动它：

```css
.gridElement
  +grid(12, 16)
  +push(2, 16)
```

这是编译后的 CSS：

```css
.gridElement {
    width: 75%;
    margin-left: 12.5%;
}
```

# 标准可重用结构

作为前端开发人员，你总是在努力处理可重复的元素。在几乎所有情况下，你会觉得自己在试图重复造轮子，那么你可以做些什么来避免重复呢？让我们创建一些标准和可重用的结构。

## 可重用的多级菜单

多级菜单是最可重用的代码。所有更大的网站都有一个你可以描述为可重用代码的菜单。

让我们从 HTML 代码开始：

```css
<ul class="menu-multilevel">
    <li>
        <a href="#">Level one - item one</a>
        <ul>
            <li><a href="#">Level two - item one</a></li>
            <li><a href="#">Level two - item two</a></li>
            <li><a href="#">Level two - item three</a></li>
            <li><a href="#">Level two - item four</a></li>
        </ul>
    </li>
    <li>
        <a href="#">Level two - item one</a>
        <ul>
            <li><a href="#">Level two - item one</a></li>
            <li><a href="#">Level two - item two</a></li>
            <li><a href="#">Level two - item three</a></li>
            <li><a href="#">Level two - item four</a></li>
        </ul>
    </li>
    <li>
        <a href="#">Level one - item three</a>
        <ul>
            <li><a href="#">Level three - item one</a></li>
            <li><a href="#">Level three - item two</a></li>
            <li><a href="#">Level three - item three</a></li>
            <li><a href="#">Level three - item four</a></li>
        </ul>
    </li>
</ul>
```

SASS 代码：

```css
ul.menu-multilevel
  list-style: none
  padding: 0

ul.menu-multilevel > li
  float: left
  display: inline-block
  position: relative
  margin-right: 10px

  &:hover
    ul
      display: block
      width: 200px

ul.menu-multilevel ul
  display: none
  position: absolute
  left: 0

  li
    display: block
```

这是编译后的 CSS：

```css
ul.menu-multilevel {
    list-style: none;
    padding: 0;
}

ul.menu-multilevel > li {
    float: left;
    display: inline-block;
    position: relative;
    margin-right: 10px;
}

ul.menu-multilevel > li:hover ul {
    display: block;
    width: 200px;
}

ul.menu-multilevel ul {
    display: none;
    position: absolute;
    left: 0;
}

ul.menu-multilevel ul li {
    display: block;
}
```

现在，让我们稍微重建这个代码，以在 SASS 中创建一个可重用的 mixin：

```css
=memuMultilevel
  list-style: none
  padding: 0

  & > li
    float: left
    display: inline-block
    position: relative
    margin-right: 10px

    &:hover
      ul
        display: block
        width: 200px

  & ul
    display: none
    position: absolute
    left: 0

    li
      display: block
```

要使用它，你需要像这样调用一个 mixin：

```css
ul.menu-multilevel
  +memuMultilevel
```

生成的 CSS：

```css
ul.menu-multilevel {
    list-style: none;
    padding: 0;
}

ul.menu-multilevel > li {
    float: left;
    display: inline-block;
    position: relative;
    margin-right: 10px;
}

ul.menu-multilevel > li:hover ul {
    display: block;
    width: 200px;
}

ul.menu-multilevel ul {
    display: none;
    position: absolute;
    left: 0;
}

ul.menu-multilevel ul li {
    display: block;
}
```

## 如何创建可重用的按钮

按钮是下一个你可以看到和重复使用的元素。让我们考虑一下按钮参数。当然，我们需要有机会设置背景和字体颜色。我们需要有机会改变边框颜色和填充。

让我们从一个简单的 CSS 定义开始：

```css
.button {
    padding: 5px 10px;
    background: #ff0000;
    color: #fff;
}
```

因此，基于此，mixin 在 SASS 中可以如下所示：

```css
=button($bgc, $fc)
  display: inline-block
  background: $bgc
  color: $fc
```

这里：

+   `$bgc`：背景颜色

+   `$fc`：字体颜色

要使用这个 mixin，你只需要执行这个：

```css
.button
  padding: 5px 10px
  +button(#ff0000, #fff)
```

这是编译后的 CSS：

```css
.button {
    padding: 5px 10px;
    display: inline-block;
    background: #ff0000;
    color: #fff;
}
```

你如何扩展这个 mixin？让我们考虑一下其他可以参数化的值。当然，边框半径。所以，让我们添加一个新的 mixin：

```css
=roundedButton($bgc, $fc, $bc, $br)
  background: $bgc
  color: $fc
  border-color: $bc
  border-radius: $br
```

这里：

+   `$bc`：边框颜色

+   `$br`：边框半径

让我们使用这个 mixin：

```css
.roundedButton
  +roundedButton(black, white, red, 5px)
```

这是编译后的 CSS：

```css
.roundedButton {
    background: black;
    color: white;
    border-color: red;
    border-radius: 5px;
}
```

如果你需要创建一堆有三种尺寸的按钮，你可以这样做：

```css
.button
  +button(#ff0000, #fff)

  .small
    padding: 5px 10px

  .medium
    padding: 10px 20px

  .large
    padding: 15px 30px
```

这是编译后的 CSS：

```css
.button {
    display: inline-block;
    background: #ff0000;
    color: #fff;
}

.button .small {
    padding: 5px 10px;
}

.button .medium {
    padding: 10px 20px;
}

.button .large {
    padding: 15px 30px;
}
```

# 收集其他可重用的 mixin

我们需要一堆有用的可重用的 mixin。还有什么可以额外帮助的？让我们想一想：

+   基本元素

+   内联列表

## 基本元素

正如你可能还记得之前的章节中所提到的，我们一直在使用基元。创建基元的 mixin 列表可以成为我们框架非常有用和有帮助的一部分。我们将为以下内容创建 mixin：

+   矩形（带或不带填充）

+   圆/环

+   三角形

让我们快速回顾一下：

```css
=rectangle($w, $h, $c)
  width: $w
  height: $h
  background: $c

=square($w, $c)
  width: $w
  height: $w
  background: $c

=circle($size, $color)
  width: $size
  height: $size
  border-radius: 50%
  background: $color

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

=triangleLeft($width, $height, $color)
  width: 0
  height: 0
  border-style: solid
  border-width: $height/2 $width $height/2 0
  border-color: transparent $color transparent transparent

=triangleTop($width, $height, $color)
  width: 0
  height: 0
  border-style: solid
  border-width: 0 $width/2 $height $width/2
  border-color: transparent transparent $color transparent

=triangleBottom($width, $height, $color)
  width: 0
  height: 0
  border-style: solid
  border-width: $height $width/2 0 $width/2
  border-color: $color transparent transparent transparent
```

# 让我们测试和使用我们的框架

为了检查我们的框架是如何工作的，以及添加所有内容有多容易，让我们创建一个博客模板。在这个模板中，让我们包括视图：

+   帖子列表

+   单个帖子

+   单页

让我们创建区域：

+   页眉

+   页脚

+   内容

这是我们简化的设计：

！[让我们测试和使用我们的框架]（img/00146.jpeg）

让我们从博客页面（主页）的简单结构开始：

```css
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title></title>
    <link rel="stylesheet" href="css/master.css" media="screen" title="no title" charset="utf-8">
</head>
<body>
<header>
    <h1>FEDojo.com</h1>
    <h2>Front End Developers Blog</h2>
</header>

<nav>
    <ul>
        <li><a href="#">Home</a></li>
        <li><a href="#">About</a></li>
        <li><a href="#">Contact</a></li>
    </ul>
</nav>

<main>
    <article class="main--article">
        <a href="#">
            <img src="img/error_log.png" alt=""/>
            <span class="comments"></span>
        </a>
        <h3>Lorem ipsum dolor sit amet, consectetur adipisicing elit</h3>
        <p>
            sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud
            exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit
            in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non
            proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
        </p>
        <a href="#" class="readmore">Read more</a>
    </article>

</main>

<footer>
    <div class="wrapper">
        <div class="column">
            Left column
        </div>
        <div class="column">
            Right column
        </div>
    </div>
</footer>
</body>
</html>
```

正如你所看到的，我们有一个基于标签的结构：

+   页眉

+   导航

+   主要

+   页脚

这是我们的文件结构：

！[让我们测试和使用我们的框架]（img/00147.jpeg）

让我们描述页眉：

```css
header
  h1
    +tac
    margin-bottom: 0

  h2
    +tac
    font-size: 16px
    margin-top: 0
    margin-bottom: 30px
```

描述页脚：

```css
footer
  width: 100%
  background: #d3d3d3
  padding: 50px 0

  .wrapper
    +m0a /* margin 0 auto */
    +clearfix
    max-width: $wrapper

  .column
    width: 50%
    float: left
```

描述导航：

```css
nav
  background: black
  text-align: center

  ul
    +navigation

  a
    color: white
    +ttu
    padding: 10px
```

在`fed`目录中，我们存储可重复使用的代码（我们的框架）。在其余的目录中，我们存储与项目相关的代码。在描述结构中，我们存储在所有视图上重复的元素的样式。在视图目录中，我们将保留与特定视图相关的元素的样式。

# 记住！

当你创建一些可重复使用的代码甚至任何其他代码时，你需要留下评论。出于某种原因，程序员们当前（并且不礼貌地）趋向于不添加评论“他们的代码不需要额外的描述”。另一种思路是，“那是我的代码。我知道我在写什么”。你认为把它留下是公平的吗？当然，答案是否定的！即使你的记忆也不完美。你可能会忘记你在代码中的意思和目的是什么。建议你至少为自己和将来在项目上工作的其他人写一些简短的评论。

在 Github 和 Bitbucket 的黄金时代，你可以在几秒钟内分享你的代码，并与来自世界另一部分的另一位程序员一起工作，他可以 fork 你的代码或为你的项目做出贡献。

# 摘要

正如你所看到的，有很多可重复使用的结构，每次创建新项目时都可以装饰。最好是写一次东西，然后添加一些新功能，而不是每次都写一些东西并描述可重复的元素。

在下一章中，我们将尝试创建一个简单的 CSS 框架，其中包含准备好使用的组件！
