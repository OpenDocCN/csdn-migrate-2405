# 精通 CSS（四）

> 原文：[`zh.annas-archive.org/md5/6E7477B42C94A8805922EA40B81890C7`](https://zh.annas-archive.org/md5/6E7477B42C94A8805922EA40B81890C7)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：Flexbox，第二部分

让我们继续探索伸缩盒和它所提供的功能。你现在应该已经掌握了基础知识，所以在本章中，我们将继续构建一个新的部分——下面你看到的产品列表，以便获得一些使用伸缩盒构建实际内容的实践经验：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00438.jpeg)

我们还将讨论在使用伸缩盒时需要添加前缀的内容，以及如何以最简单的方式添加前缀。

我们将涵盖以下主题：

+   使用伸缩盒构建一个新的部分

+   使用 flex-wrap 和 align-content

+   更改伸缩项的显示顺序

+   处理供应商前缀

# 构建产品列表

让我们用伸缩盒构建一个产品列表。我们将通过创建一个产品列表来看看我们还可以用伸缩盒构建什么。我们将探讨两个新的伸缩盒属性：`align-items`和`align-self`。

# 使用 align-items

为了构建产品列表，我们将从一些新的标记开始，这些标记将直接位于页脚上方：

```css
<!-- 
===============
Product Listing
===============
-->
<section class="secondary-section grouping">
    <ul class="wrapper product-list">
        <li class="product-list-item">
            <figure>
                <img src="img/octopus-icon.svg" alt="Octopus">
            </figure>
            <h2>The Octopus</h2>
            <p>Lorem ipsum dolor sit.</p>
            <a href="#" class="button">Tenticals &raquo;</a>
        </li>
        <li class="product-list-item">...</li>
        <li class="product-list-item">...</li>
        <li class="product-list-item">...</li>
        <li class="product-list-item">...</li>
        <li class="product-list-item">...</li>
    </ul><!-- end wrapper -->
</section>
<!-- 
================ 
Footer
================
--> 
```

标记相当多，但并不是很复杂。有一个无序列表，其中包含六个列表项（`<li>`标签）。每个列表项都有一个 SVG 图像（`<figure><img></figure>`）、一个标题（`<h2>`）、一个段落（`<p>`）和一个锚点（`<a>`）。在前面的代码片段中，我省略了除第一个之外所有列表项的内容。

我们还将从一些 CSS 开始引导这一部分：

```css
/****************
Product Listing
****************/
.product-list-item {
  border-bottom: 1px solid #766e65;
}
.product-list-item figure {
  width: 50px;
  margin-right: 20px;
}
.product-list-item h2 {
  margin: 0;
}
.product-list-item p {
  margin: 0;
}
.product-list-item .button {
  transform: scale(1);
  width: 130px;
}
```

以下是我们产品列表的初始内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00439.jpeg)

我们希望每个列表项的内容都水平排列。我们可以选择类`product-list-item`，并使用`display: flex`：

```css
.product-list-item {
  border-bottom: 1px solid #766e65;
 display: flex;
}
```

这个规则集是针对具有`product-list-item`类的六个不同的`li`标签。这很重要，因为我们有六个不同的伸缩容器。添加`display: flex`应该会水平排列每个伸缩容器中的所有不同伸缩项。因为这就是伸缩盒的作用。默认情况下，`flex-direction`是`row`，所以一切都是水平排列的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00440.jpeg)

好吧，看起来不太好。我们可以做的一件事是给`h2`添加一个值为`250px`的`flex-basis`：

```css
.product-list-item h2 {
  margin: 0;
  flex-basis: 250px;
}
```

这应该增加一些组织性，而且确实做到了：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00441.jpeg)

现在，让我们使用自动边距将按钮对齐到最右边缘：

```css
.product-list-item .button {
  transform: scale(1);
  width: 130px;
 margin-left: auto
}
```

回顾我们在上一节学到的内容，`margin-left: auto`将自动计算按钮左侧的边距，并将其推到最右边。这好多了，但是仍然有点紧：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00442.jpeg)

让我们用一个叫做`align-items`的新属性来解决这个问题。所以这些按钮彼此之间太近了，而这段落却高高地坐着。我们希望图片、标题、段落和按钮都垂直居中。`align-items`是一个可以用在伸缩容器上的属性，它控制了伸缩项沿交叉轴的定位。这里再次提醒我们，当`flex-direction`设置为`row`时，交叉轴的方向是怎样的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00443.jpeg)

正如我们所看到的，当`flex-direction`为行时，交叉轴从上到下。我们将添加一个值为`center`的`align-items`。这实际上不会有太明显的效果，除非我们添加一个`height`为`80px`。所以我们也来做这个：

```css
.product-list-item {
  border-bottom: 1px solid #766e65;
  display: flex;
 align-items: center;
 height: 80px;
}
```

因此，使用`align-items: center`将使项目在交叉轴中间对齐：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00444.jpeg)

好吧！我们所有的伸缩项都是垂直居中的，只用了一个属性，而且每个项目的高度都不同。另外，我想指出`align-items`的默认值是`stretch`，它会强制伸缩项从交叉轴的起始位置拉伸到结束位置。这就是为什么伸缩盒默认提供了等高列。

我们还可以使用`flex-start`，它将所有伸缩项对齐到伸缩容器的顶部或交叉轴的起始位置：

```css
.product-list-item {
  border-bottom: 1px solid #766e65;
  display: flex;
  align-items: flex-start;
  height: 80px;
}
```

以下是前面代码的输出：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00445.jpeg)

让我们尝试`flex-end`，这将使所有的伸缩项目对齐到底部或交叉轴的末尾：

```css
.product-list-item {
  border-bottom: 1px solid #766e65;
  display: flex;
  align-items: flex-end;
  height: 80px;
}
```

我们的伸缩项目现在对齐到了交叉轴的末尾——底部：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00446.jpeg)

让我们把这个改回到`center`：

```css
.product-list-item {
  border-bottom: 1px solid #766e65;
  display: flex;
 align-items: center;
  height: 80px;
}
```

现在让我们回到我们的三列；我们仍然有图片和标题对齐到左边的问题，我们希望它们居中：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00447.jpeg)

让我们看看如何使用`align-items`来在`flex-direction`设置为`column`时居中我们的海洋生物和标题。在这种情况下，交叉轴是水平的。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00448.jpeg)

这是个好消息。因为`align-items`用于在交叉轴上对齐，而对于`flex-direction: column`来说，交叉轴是水平的，这应该会使我们的海洋生物图片和标题居中。

记住每个`.column`都是`.columns`的一个伸缩项目，但也是其自己的伸缩项目，拥有自己的伸缩项目。这些伸缩项目包括海洋生物图片、标题、段落和按钮等。所以每一列都是其自己的伸缩项目。我们可以使用`align-items: center`：

```css
/****************
3 columns
****************/
.columns {
  display: flex;
  justify-content: space-between;
}
.column {
  flex-basis: 30%;
  display: flex;
  flex-direction: column;
  justify-content: flex-start;
 align-items: center;
}
.column figure {
  max-width: 50%;
  flex-basis: 150px;
}
.column .button {
  margin-top: auto;
}
```

这就是我们最终得到的结果：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00449.jpeg)

事情都居中了，就像标题和底部的按钮一样，但我们的海洋生物图片完全消失了，我们的按钮也变小了。让我们逐个解决这些问题，首先考虑一下为什么我们的海洋生物消失了。让我们在海洋生物应该出现的地方附近检查并找到图片：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00450.jpeg)

在 DevTools 中检查包含`img`元素的`figure`元素，显示宽度为 0，高度为 150。那么如果我们已经设置了这个 CSS，为什么宽度会是 0 呢？

```css
.column figure {
  max-width: 50%;
  flex-basis: 150px;
}
```

嗯，我们没有为这些 SVG 设置明确的`width`。我们设置了`max-width`，但这实际上并没有强制设置宽度。请记住，`max-width`只是说“永远不要超过 x 像素宽度”，但不会强制在该阈值以下设置任何宽度。我们的`flex-basis`是`150px`，因为`flex-direction`是`column`，所以它控制了高度。我们根本没有设置真正的宽度。当我们设置`align-items: center`时，它会强制元素只占据它们需要的宽度或高度，几乎就像当你将块级元素`float`到`left`或`right`时一样。此外，SVG 在图像的宇宙中是独一无二的。传统的 PNG 和 JPG 图像即使在 CSS 中没有指定任何尺寸，也有固定的尺寸。而 SVG 可以按比例缩放到任何大小，因此没有基准尺寸。由于`figure`或`img`都没有设置宽度或高度，`align-items`属性会将宽度挤压为 0，这就是它们消失的原因。

这很容易解决；我们只需要添加一个`width`。让它比以前的尺寸更小一点，大约是其容器的 50%：

```css
.column figure {
  max-width: 50%;
  flex-basis: 150px;
 width: 50%;
}
```

我们的海洋生物又回来了！

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00451.jpeg)

底部的按钮和我们刚刚遇到的图片有相同的问题；它们没有设置任何`padding`或`width`，所以`align-items`强制宽度只能与内容一样宽，这就是为什么它们看起来都被挤压得很小。

解决方法是一样的：只需设置一个`width`。在这种情况下，让`width`为`90%`：

```css
/****************
3 columns
****************/
.columns {
  display: flex;
  justify-content: space-between;
}
.column {
  flex-basis: 30%;
  display: flex;
  flex-direction: column;
  justify-content: flex-start;
  align-items: center;
}
.column figure {
  max-width: 50%;
  width: 50%;
  flex-basis: 150px;
}
.column .button {
  margin-top: auto;
 width: 90%;
}
```

问题解决了：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00452.jpeg)

# 使用`align-self`伸缩属性

看起来不错，但如果我不想让所有的伸缩项目都居中怎么办？我可能更喜欢`h2`对齐到`flex-start`（事实上我是这样做的）。`align-items`是一个用于控制所有伸缩项目在交叉轴上对齐的属性。另一个名为`align-self`的 flexbox 属性控制沿交叉轴的对齐，但是直接用于伸缩项目。这将帮助我们只将我们的`h2`对齐到左边。

让我们为`h2`创建一个新的选择器，并添加`align-self: flex-start`：

```css
/****************
3 columns
****************/
.columns {
  display: flex;
  justify-content: space-between;
}
.column {
  flex-basis: 30%;
  display: flex;
  flex-direction: column;
  justify-content: flex-start;
  align-items: center;
}
.column figure {
  max-width: 50%;
  width: 50%;
  flex-basis: 150px;
}
.column h2 {
 align-self: flex-start;
}
.column .button {
  margin-top: auto;
  width: 90%;
}
```

请注意，`align-self`是仅适用于 flex 项的属性；它的默认值是`auto`，这意味着它告诉它检查`align-items`的值以进行交叉轴对齐。它还接受`stretch`、`flex-start`、`flex-end`、`center`和`baseline`。它允许我们覆盖单个 flex 项的`align-items`值。

如果我们现在刷新浏览器，我们会看到我们的`h2`标签对齐到左侧-在它们的`flex-start`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00453.jpeg)

我们现在看起来不错。让我们花一分钟快速修复一下我们之前创建的一个错误。我们将通过右键单击并选择检查来查看这个错误；我们将在 Chrome 中将 DevTools 移动到右侧。我只是将它调整到平板尺寸；我们现在可以看到问题了，我们的海洋生物失控了！

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00454.jpeg)

我们的列都堆叠在一起。所以我们必须弄清楚为什么会发生这种情况。这是因为我们为每列将`flex-basis`设置为`30%`。当`flex-direction`为行时，它运行得很好，但是您可能还记得从*Floats to Flexbox*部分，我们在较小设备的媒体查询中将`flex-direction`更改为`column`。当`flex-direction`为`column`时，`flex-basis`控制的是高度而不是宽度，因为在这种情况下，主轴是垂直而不是水平的。

所以让我们在媒体查询中修复这个问题。让我们创建一个新的选择器并将`flex-basis`设置为`auto`：

```css
@media screen and (max-width: 1023px){
 .column {
 flex-basis: auto;
    margin-bottom: 50px;
 }
}/* end of media query */
```

您会记得，将`flex-basis`设置为`auto`意味着这样做：看看我的宽度或高度。因为我们没有明确设置高度；高度由内容确定，正是我们想要的——只需使高度成为内容的大小。此外，我偷偷加了`margin-bottom`为`50px`，以在它们之间提供一点间隙：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00455.jpeg)

在本节中，我们使用 flexbox 构建了我们的产品列表，并介绍了两个新的 flex 属性：`align-items`和`align-self`。在下一节中，我将介绍另外两个属性：`flex-wrap`和`align-content`。

# 使用 flex-wrap 和 align-content

`flex-wrap`属性允许我们确定我们是将内容包装到第二行还是将所有 flex 项挤入单行；`align-content`确定被包装到多行的行的对齐方式，从而变成多行。它们基本上是最好的朋友。

# 使用 flex-wrap

我们将返回并使用我们的 flexbox 示例页面（`flexbox.html`）作为测试这些属性的游乐场。这是我们在这个区域最终得到的 CSS：

```css
/***************
Flexbox demo
***************/
.flex-container {
  margin-top: 200px;
  display: flex;
  justify-content: flex-start;
}
.flex-item {
  padding: 20px;
}
.flex-item:last-child {
  margin-left: auto;
}
.flex-item1 { background: deeppink;}
.flex-item2 { background: orange; }
.flex-item3 { background: lightblue; }
.flex-item4 { background: lime; }
.flex-item5 { background: olive; }
```

flex 容器将所有内容都对齐到`flex-start`，或者在我们的情况下是左侧。这是因为`flex-direction`没有设置，因此默认为`row`。最后一个 flex 项被推到最右边，使用`margin-left: auto;`。这是我们的`flexbox.html`页面目前应该看起来的样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00456.jpeg)

在`flexbox.html`中，让我们添加更多的 flex 项并保存它们：

```css
<section class='flex-container'>
    <div class="flex-item flex-item1">item 1</div>
    <div class="flex-item flex-item2">item 2</div>
    <div class="flex-item flex-item3">item 3</div>
    <div class="flex-item flex-item4">item 4</div> 
    <div class="flex-item flex-item5">item 5</div> 
    <div class="flex-item flex-item1">item 6</div>
    <div class="flex-item flex-item1">item 1</div>
    <div class="flex-item flex-item2">item 2</div>
    <div class="flex-item flex-item3">item 3</div>
    <div class="flex-item flex-item4">item 4</div> 
    <div class="flex-item flex-item5">item 5</div> 
    <div class="flex-item flex-item1">item 6</div>
    <div class="flex-item flex-item1">item 1</div>
    <div class="flex-item flex-item2">item 2</div> 
    <div class="flex-item flex-item3">item 3</div> 
    <div class="flex-item flex-item4">item 4</div> 
    <div class="flex-item flex-item5">item 5</div> 
    <div class="flex-item flex-item1">item 6</div>
</section>
```

现在我们看到 flexbox 是如何真正挤压 flex 项以适应在 flex 容器内的一行上的。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00457.jpeg)

所以我们将通过将`flex-wrap`属性添加到 flex 容器中并将值设置为`wrap`来包装多行。此外，让我们通过删除整个规则集来摆脱最后一个 flex 项上的`margin-left: auto`：

```css
/***************
Flexbox demo
***************/
.flex-container {
  margin-top: 200px;
  display: flex;
  justify-content: flex-start;
 flex-wrap: wrap;
}
.flex-item {
  padding: 20px;
}
.flex-item1 { background: deeppink;}
.flex-item2 { background: orange; }
.flex-item3 { background: lightblue; }
.flex-item4 { background: lime; }
.flex-item5 { background: olive; }
```

因此，所有先前收缩以适应一行的 flex 项现在会扩展到其自然大小；这意味着文本的宽度加上文本两侧的`padding`的`20px`。这创建了两行内容。很好，正是我们想要的！

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00458.jpeg)

`flex-wrap`的默认值是`nowrap;`。这是有道理的，因为在将其设置为`wrap`之前，它强制所有我们的 flex 项适合一行。就好像我们根本没有省略`flex-wrap`一样。让我们换成`nowrap`来测试一下：

```css
.flex-container {
    margin-top: 200px;
    display: flex;
    justify-content: flex-start;
 flex-wrap: nowrap;
}
```

就好像我们根本没有指定`flex-wrap`一样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00459.jpeg)

还有`wrap-reverse;`让我们试试：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
  justify-content: flex-start;
 flex-wrap: wrap-reverse;
}
```

最后一个项目现在是第一个，第一个项目是最后一个。从技术上讲，最后一个项目现在是第一行的第四个：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00460.jpeg)

使用`flex-wrap`的好处是，现在每一行在`flex-grow`、`flex-shrink`和`justify-content`等属性方面都可以独立工作。

让我们测试一下，添加`flex-grow: 1`：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
  justify-content: flex-start;
  flex-wrap: wrap-reverse;
}
.flex-item {
  padding: 20px;
 flex-grow: 1;
}
```

这会重新分配任何额外的空间，以确保它们填满所有剩余的空间：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00461.jpeg)

每一行都将它们的 flex 项目扩展以占据额外的空间。正如你所看到的，第一行的 flex 项目被拉伸得更远，以填补比下面一行更多的额外空间。在它下面的另外两行中，flex 项目只被拉伸了一点点来填补额外的空间。

让我们再次看看这些行如何独立于彼此地工作，通过将`justify-content`改为`space-between`在 flex 容器上。我们还将在 flex 项目上去掉`flex-grow`：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
 justify-content: space-between;
  flex-wrap: wrap-reverse;
}
.flex-item {
  padding: 20px;
}
```

因此，在每个 flex 项目之间都有额外的空间分配：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00462.jpeg)

第一行有很多额外的空间，而第二行在每个 flex 项目之间只有一点额外的空间。同样，每一行在处理`flex-grow`、`flex-shrink`和`justify-content`时都是独立的。这种情况非常适合来自**内容管理系统**（**CMS**）的动态、未知数量的内容。

# 使用 align-content

好的，让我们再看看另一个叫做`align-content`的属性。像`flex-wrap`一样，`align-content`是一个只在 flex 容器上工作的属性；然而，`align-content`依赖于`flex-wrap`被设置为`wrap`或`wrap-reverse`，这意味着在所有其他情况下`align-content`都会被忽略。此外，`align-content`类似于`align-items`，因为它控制沿交叉轴的排列或对齐。唯一的区别是，它不是在交叉轴上重新分配每个*flex 项目*，而是在交叉轴上重新分配每个*行*。

让我们将`align-content`设置为`space-between`。我们还将其高度设置为`300px`，并给它一个深灰色的边框：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap-reverse;
 align-content: space-between;
 height: 300px;
 border: 1px solid #777; 
}
```

我还要把 flex 项目的数量加倍，以保持事情的趣味性：

```css
<!--
====================
Flexbox Demo
====================
-->
<section class='flex-container'>
    <div class="flex-item flex-item1">item 1</div>
    <div class="flex-item flex-item2">item 2</div>
    <div class="flex-item flex-item3">item 3</div>
    <div class="flex-item flex-item4">item 4</div> 
    <div class="flex-item flex-item5">item 5</div> 
    <div class="flex-item flex-item1">item 6</div>
    <div class="flex-item flex-item1">item 1</div>
    <div class="flex-item flex-item2">item 2</div>
    <div class="flex-item flex-item3">item 3</div>
    <div class="flex-item flex-item4">item 4</div> 
    <div class="flex-item flex-item5">item 5</div> 
    <div class="flex-item flex-item1">item 6</div>
    <div class="flex-item flex-item1">item 1</div>
    <div class="flex-item flex-item2">item 2</div> 
    <div class="flex-item flex-item3">item 3</div> 
    <div class="flex-item flex-item4">item 4</div> 
    <div class="flex-item flex-item5">item 5</div> 
    <div class="flex-item flex-item1">item 6</div>
    <div class="flex-item flex-item1">item 1</div>
 <div class="flex-item flex-item2">item 2</div>
 <div class="flex-item flex-item3">item 3</div>
 <div class="flex-item flex-item4">item 4</div> 
 <div class="flex-item flex-item5">item 5</div> 
 <div class="flex-item flex-item1">item 6</div>
 <div class="flex-item flex-item1">item 1</div>
 <div class="flex-item flex-item2">item 2</div>
 <div class="flex-item flex-item3">item 3</div>
 <div class="flex-item flex-item4">item 4</div> 
 <div class="flex-item flex-item5">item 5</div> 
 <div class="flex-item flex-item1">item 6</div>
 <div class="flex-item flex-item1">item 1</div>
 <div class="flex-item flex-item2">item 2</div> 
 <div class="flex-item flex-item3">item 3</div> 
 <div class="flex-item flex-item4">item 4</div> 
 <div class="flex-item flex-item5">item 5</div> 
 <div class="flex-item flex-item1">item 6</div>
</section>
```

现在我们有 3 行，并且由于`align-content`，每行之间有空间：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00463.jpeg)

`height`属性是相关的，因为如果省略，flex 容器的高度只会和其 flex 项目一样高；因此，`align-content`不会起作用，因为没有额外的垂直空间可供使用。除了`space-between`之外，`align-items`的其他值包括`flex-start`、`flex-end`、`center`和`space-around`。这些值应该是我们在学习`justify-content`属性时熟悉的。默认值是`stretch`。`space-around`值会均匀地重新分配所有项目周围的额外空间，包括第一个和最后一个。

所以让我们把它从`space-between`改为`space-around`：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap-reverse;
 align-content: space-around;
 height: 300px;
 border: 1px solid #777; 
}
```

你可以看到，使用`space-around`，在 flex 容器的顶部和第一行之间以及容器底部和最后一行之间有一些空间：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00464.jpeg)

而`space-between`让第一行和最后一行紧紧贴着 flex 容器，这是一个细微的差别。我们之前在学习`justify-content`时也注意到了这种微妙之处。

现在让我们将`align-content`的值改为`center`：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
  justify-content: space-between;
  flex-wrap: wrap-reverse;
  align-content: center;
  height: 300px;
  border: 1px solid #777; 
}
```

正如我们所期望的，我们的行是居中的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00465.jpeg)

现在让我们将`flex-direction`改为列，看看在这种情况下`flex-wrap`和`align-content`是如何一起工作的：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
  justify-content: space-between;
  flex-direction: column;
  flex-wrap: wrap-reverse;
  align-content: center;
  height: 300px;
  border: 1px solid #777; 
}
```

这里发生了很多事情，很难准确地说是什么，但我们可以说的一件事是我们在水平方向上是居中的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00466.jpeg)

让我们简化一下，以理解发生了什么。首先，让我们将`flex-wrap`从`wrap-reverse`改回`wrap`：

```css
.flex-container {
    margin-top: 200px;
    display: flex;
    justify-content: space-between;
    flex-direction: column;
 flex-wrap: wrap;
    align-content: center;
    height: 300px;
    border: 1px solid #777; 
}
```

在`flexbox.html`中，我们将大大减少 flex 项目的数量：

```css
<section class='flex-container'>
    <div class="flex-item flex-item1">item 1</div>
    <div class="flex-item flex-item2">item 2</div>
    <div class="flex-item flex-item3">item 3</div>
    <div class="flex-item flex-item4">item 4</div> 
    <div class="flex-item flex-item5">item 5</div> 
    <div class="flex-item flex-item1">item 6</div>
</section>
```

现在，更容易看到`flex-direction`是`column`，这会强制两个垂直列，因为`flex-wrap`设置为`wrap`，并且我们没有足够的空间容纳所有 6 个伸缩项目：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00467.jpeg)

我们为`justify-content`设置的`space-between`正在在每个伸缩项目之间重新分配额外的空间。请注意，两列都独立地重新分配了它们的额外空间，如下图所示。

当交叉轴上有额外空间和多行时，使用`align-content`来排列交叉轴上的行。正如我们所知，当`flex-direction`为行时，交叉轴从上到下运行。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00468.jpeg)

当`flex-direction`为列时，交叉轴从左到右运行：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00469.jpeg)

如果我开始听起来像一个重复的唱片，我很抱歉，但我觉得重复强调伸缩盒的运作方式是很重要的。

# 使用`flex-flow`缩写

之前，我们看到`flex`缩写如何将`flex-grow`、`flex-shrink`和`flex-basis`组合在一起。让我们介绍另一个缩写，`flex-flow`，它将允许我们通过将`flex-direction`和`flex-wrap`组合在一起来减少一些属性。无论如何，这会简化我们的 CSS 代码：

```css
.flex-container {
  margin-top: 200px;
  display: flex;
  justify-content: space-between;
  flex-flow: column wrap;
  align-content: center;
  height: 300px;
  border: 1px solid #777; 
}
```

没有变化，这正是我们在使用缩写重构时想要的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00470.jpeg)

考虑到`align-content`与`flex-wrap`的密切依赖，我期望`align-content`是`flex-flow`的一部分。然而，`align-content`并不是`flex-flow`的一部分，它与`flex-direction`和`flex-wrap`一起。

在本节中，您学习了`flex-wrap`如何允许我们创建多个流或行的内容，而`align-items`则将这些多行定位在其容器的交叉轴上。

# 更改伸缩项目的显示顺序

在本节中，我们将讨论如何更改伸缩项目的显示顺序以及这如何有助于响应式网页设计。我们还将讨论这如何影响网页可访问性。

在较宽的屏幕宽度下，内容水平显示：首先是章鱼，然后是螃蟹，然后是鲸鱼：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00471.jpeg)

在较窄的设备宽度下，内容以与源顺序相同的顺序显示，只是垂直显示，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00472.jpeg)

在这两种情况下，显示顺序与源顺序相同，在这种情况下是有意义的。

在这里做点不同的事情。假设我们正在与一位设计师合作，他希望本周突出显示螃蟹，并在视觉上优先于章鱼和鲸鱼。这就是我们在这里所做的。我在 HTML 和 CSS 中添加了一些额外的内容来实现这种新的特色处理：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00473.jpeg)

在标记中，我为每列的标题添加了一个数字，这样我们在浏览器中查看时就可以轻松记住源顺序。然后，对于螃蟹，我添加了一个名为`featured`的类和一个名为`ribbon`的`div`标签。

```css
<div class="column">
    <figure>
        <img src="img/octopus-icon.svg" alt="Octopus">
    </figure>
    <h2>The Octopus 1</h2>
    <p>Lorem ipsum dolor...</p>
    <a href="#" class="button">Tenticals &raquo;</a>
</div>
<div class="column featured">
 <div class="ribbon">Featured</div>
    <figure>
        <img src="img/crab-icon.svg" alt="Crab">
    </figure>
    <h2>The Crab 2</h2>
    <p>Lorem ipsum dolor...</p>
    <a href="#" class="button">Crabby &raquo;&lt;/a>
</div>
<div class="column">
    <figure>
        <img src="img/whale-icon.svg" alt="Whale">
    </figure>
    <h2>The Whale 3</h2>
    <p>Lorem ipsum dolor sit...</p>
    <a href="#" class="button">Stuart &raquo;</a>
 </div>
```

我添加了一些 CSS 来样式化丝带。

```css
/*featured column*/
.featured {
  padding: 0 0 20px 0;
  background-color: #d3d3d3;
  overflow: hidden;
}
.featured h2, 
.featured p {
  margin-left: 20px;
  margin-right: 20px;
}
.ribbon {
    background-color: #ffc0cb;
    padding: 10px 50px;
    margin-bottom: 20px;
    align-self: stretch;
    text-align: center;
    font-family: 'Maven Pro', Arial, sans-serif;
    font-weight: bold;
    box-shadow: #b7b7b7 0px 2px 15px 0px;
}
```

您可能已经注意到，特色丝带被拉伸横跨顶部；这是使用`align-self: stretch`完成的。正如我们已经讨论过的，`align-self`沿着交叉轴对齐伸缩项目，在我们的情况下，由于`flex-direction`设置为`column`，交叉轴从左到右。`align-self`属性类似于`align-items`，不同之处在于它用于伸缩项目并覆盖`align-items`属性。

在桌面或更宽的视图上，当我们的业务合作伙伴和设计师看到这一点时，他们真的很高兴。但在手机上，他们说，“嗯，我不知道，螃蟹仍然显示为第二。”他们可能是对的，这是特色内容，所以它不仅应该在视觉上突出，而且还应该首先出现。如果我们的内容来自数据库，我们可以更新它，使螃蟹首先出现；或者，我们可以使用一些 JavaScript 来重新排列我们的特色内容，使螃蟹首先出现。这两种解决方案，至少不是理想的。

Flexbox 在这里派上了用场。在我们针对较小设备的媒体查询中，我们可以使用一个名为`order`的 flex 项目属性：

```css
@media screen and (max-width: 1023px){
  .intro-content {
    width: auto;
    float: none;
    padding-bottom: 0;
    margin-bottom: 30px;
  }
  .go-premium {
    width: auto;
    float: none;
    margin-top: 0;
  }
  .columns {
    flex-direction: column;
  }
  .column {
    flex-basis: auto;
    margin-bottom: 50px;
  }
  .featured {
 order: -1;
 }
}/* end of media query */
```

好了，当我刷新浏览器时，它立即将我们的螃蟹移动到了第一个位置，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00474.jpeg)

默认情况下，所有 flex 项目都被赋予`order`为`0`，所以提供`-1`将螃蟹移到了顶部。项目的顺序与主轴一起运行；最低顺序的 flex 项目将位于主轴的开始，而最高顺序的 flex 项目将出现在主轴的末尾。

同样，在我们的情况下，由于`flex-direction`是`column`，主轴从上到下运行。让我们把`order`改为`1`：

```css
@media screen and (max-width: 1023px){
  .intro-content {
    width: auto;
    float: none;
    padding-bottom: 0;
    margin-bottom: 30px;
  }
  .go-premium {
    width: auto;
    float: none;
    margin-top: 0;
  }
  .columns {
    flex-direction: column;
  }
  .column {
    flex-basis: auto;
    margin-bottom: 50px;
  }
 .featured {
 order: 1;
 }
}/* end of media query */
```

这将螃蟹移到底部，因为默认情况下章鱼和鲸鱼都是`0`，而我们已经指定螃蟹为`1`—所以现在它被放在了最后：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00475.jpeg)

好了，让我们再添加两个规则集：

```css
.column:nth-child(1) {
 order: 3;
}
.featured {
  order: 1;
}
.column:nth-child(3) {
 order: 2;
}
```

我们使用`nth-child`伪类来改变顺序。现在刷新浏览器后，螃蟹在显示顺序中是第一个（源顺序中是第二个），鲸鱼是第二个（但源顺序中是第三个），章鱼是第三个（但源顺序中是第一个）。这就是它应该看起来的样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00476.jpeg)

所以我也可以按相反的顺序放置它们。我已经把第一个作为第三个，我可以把第二个作为第二个，第三个作为第一个：

```css
.column:nth-child(1) {
  order: 3;
}
.featured {
  order: 2;
}
.column:nth-child(3) {
  order: 1;
}
```

这就是我们应该看到的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00477.jpeg)

现在我们把第三个作为第一个，第二个作为第二个，第一个作为第三个。相反的顺序。但请记住，我有一个更简单的方法来做到这一点；我实际上可以摆脱这三个规则集，只需指定`flex-direction`为`column-reverse`：

```css
@media screen and (max-width: 1023px){
  .intro-content {
    width: auto;
    float: none;
    padding-bottom: 0;
    margin-bottom: 30px;
  }
  .go-premium {
    width: auto;
    float: none;
    margin-top: 0;
  }
  .columns {
 flex-direction: column-reverse;
  }
  .column {
    flex-basis: auto;
    margin-bottom: 50px;
  }
}/* end of media query */
```

现在当我刷新浏览器时，它们仍然是相反的顺序：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00478.jpeg)

# 无障碍影响

我想提一下的一件事是，改变显示顺序有一个缺点，你可能需要注意：通过内容进行制表。制表顺序仍然基于源顺序，这成为一个无障碍问题。现在你可能会认为在我们的例子中，制表顺序在桌面上是合乎逻辑的，但在较小的设备上，比如手机上，它可能会变得不合逻辑，尽管大多数情况下不会通过字段进行制表。也许这大多数是正确的；然而，改变显示顺序对于屏幕阅读器，比如 JAWS，也是一个问题，它根据源顺序而不是显示顺序向视力受损的用户读取内容。因此，你的内容仍然会根据源顺序被屏幕阅读器宣布，这将与视觉顺序不同步。这可能是一个无障碍问题。因此，如果改变顺序，最好记住这一点。

在这一部分，你学会了`order`属性如何改变 flex 容器中 flex 项目的显示顺序，以及它对制表顺序和无障碍的影响。

# 供应商前缀

让我们谈谈供应商前缀。在这一部分，我们将讨论 flexbox 的浏览器支持以及如何在我们的 flexbox CSS 中添加供应商前缀以获得更深入的 flexbox 支持。我们还将谈论一个叫做**Autoprefixer**的东西，它可以帮助我们添加这些前缀。

Flexbox 支持从 IE10 开始，如果我们使用`-ms-`供应商前缀。但这可能不是您想要添加的唯一供应商前缀，因为自从浏览器首次实现以来，W3C 规范实际上已经发生了变化。当它被实现时，语法和属性名称与今天的不同。为了获得深度浏览器支持，我们可以使用旧语法结合新语法来支持一些早期采用的浏览器。

让我们更新我们最初添加 flexbox 的原始规则集，这是我们的`.columns`：

```css
.columns {
  display: -webkit-box;
  display: -webkit-flex;
  display: -ms-flexbox;
  display: flex;
  -webkit-box-pack: justify;
  -webkit-justify-content: space-between;
  -moz-box-pack: justify;
  -ms-flex-pack: justify;
  justify-content: space-between;
}
```

哇！这里有很多事情。我们不仅仅是在属性的开头添加`-ms-`，`-moz-`和`-webkit-`。当涉及到`display`属性的值时，我们将供应商前缀添加到值的开头。值本身与我们的非前缀版本并没有太大不同。还有 2 个`-webkit-`值！Chrome 和 Safari 真的是 flexbox 的早期采用者，所以实际上有两个不同的前缀，WebKit 浏览器支持：`-webkit-box`和`-webkit-flex`。所以，这是很多前缀和很多记忆，对于`justify-content`属性看起来也很疯狂。这是很多。棘手的部分是学习和记住旧的语法，特别是因为不明显哪些前缀仍然是必需的。

# Autoprefixer

这就是 Autoprefixer CSS 在线工具([`autoprefixer.github.io/`](https://autoprefixer.github.io/))可以非常有帮助的地方。它根据浏览器的总市场份额和我们想要为每个浏览器回溯的版本数量提供我们需要的前缀。让我们将这个过滤器更新为`.01%`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00479.jpeg)

让我们摆脱所有这些前缀，只需将这个规则集复制粘贴到 Autoprefixer 工具的左边框中：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00480.jpeg)

在右侧，它提供了我们应该使用的前缀：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00481.jpeg)

让我们将它复制回我们的 CSS：

```css
.columns {
  display: -webkit-box;
  display: -ms-flexbox;
  display: flex;
  -webkit-box-pack: justify;
      -ms-flex-pack: justify;
          justify-content: space-between;
}
```

这非常方便，比记住所有 flexbox 属性的不同语法要容易得多。如果有一种方法可以自动为我们添加供应商前缀，而不必我们进行所有这些复制和粘贴，那将是很好的。我们可以做的一件事是使用预处理器，比如**Sass**，编写一个称为**mixin**的东西，为我们添加供应商前缀，这样我们就不必太在意这个了。我们将在下一章中看看 Sass mixins

# Gulp

现在我想提一下你可能听说过的东西：Gulp。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00482.jpeg)

Gulp ([`gulpjs.com/`](https://gulpjs.com/))及其朋友 Grunt([`gruntjs.com/`](https://gruntjs.com/))，允许我们创建构建流程，例如压缩我们的 CSS 和 JavaScript 文件，将 Sass 编译成 CSS，甚至自动为 CSS 添加供应商前缀，使用 Autoprefixer。Gulp 在 Node 上运行，需要您下载它，然后下载 Gulp。然后您可以下载单独的任务，比如 Autoprefixer。学习 Gulp 远远超出了本书的范围，但 Gulp 真的非常有用，我非常喜欢它。为了开始使用它，我强烈建议您阅读*Getting Started with Gulp*，*Travis Maynard*，*Packt Publishing*，这本书非常好地解释了如何安装 Gulp，设置它并使用它。这就是我学会如何使用 Gulp 的方式，通过阅读这本书。

Gulp 是一个*命令行*工具，你可以配置它在每次保存 CSS 文件时运行 Autoprefixer。所以，如果我在我的 CSS 中写入一个 flexbox 属性并按下*Ctrl* + *S*，Gulp 将会监视我的文件是否有任何变化，如果它检测到变化，它将告诉 Autoprefixer 运行并使用必要的供应商前缀更新我的 CSS 文件。我知道这听起来很奇怪——用供应商前缀更新我的 CSS 文件——但从技术上讲，它所做的是创建一个新的 CSS 文件，其中包含所有的供应商前缀。这里有比我解释的更多，但是查看 Travis Maynard 的书来设置它。这样，你就再也不用考虑供应商前缀了，因为 Autoprefixer 和 Gulp 会为你考虑这些事情。

# Flexbox 作业

我们已经建立了一个了不起的网站：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00483.jpeg)

然而，它并非没有问题。你可能已经注意到，在产品列表部分，当我们缩小浏览器时，它开始看起来有点怪异，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00484.jpeg)

最后一个带回家的测试是更新媒体查询内的 CSS，使得在较小的设备尺寸下显示效果良好。

在这一部分，我们谈到了我们需要为我们的 flexbox 属性添加供应商前缀，以便获得更深层次的浏览器支持。然而，供应商前缀可能会很棘手，最好将前缀添加工具交给像 Autoprefixer 这样的工具。更好的是，最好自动化 Autoprefixer，这样每次保存 CSS 文件时都会执行它。你可以使用任务运行器，比如 Gulp 或 Grunt 来实现这一点。

# 总结

这完成了我们对 flexbox 的探索。我们现在已经看到了与之相关的每一个属性，并将它们应用到了为我们的网站构建新产品列表中。在下一章中，我们将看看在结尾中关于 CSS 技能和工具的下一步：第十一章，*总结*。


# 第十一章：总结

欢迎来到本书的最后一章。由于我们已经完成了这段旅程，我想带您走过您在 Web 开发学习过程中的一些步骤，并浏览一些链接和资源，以获取有关到目前为止学到的所有内容的更多信息。

# 下一步

学习 CSS 的下一个逻辑步骤是转向 CSS 预处理器，如 Sass 或 Less。CSS 预处理器允许您使用编程功能编写 CSS，如嵌套、导入、变量和混合，这些功能会被编译成常规 CSS。前端开发的另一个逻辑步骤是学习 JavaScript。不过，首先让我们谈谈 CSS 预处理器 Sass。

# CSS 预处理器

我既使用了*Less*又使用了*Sass*，但我现在已经使用 Sass 一段时间了。当我开始为这本书创建课程材料时，我几乎忘记了没有 Sass 的情况下编写 CSS 是什么感觉。毋庸置疑，使用 Sass 编写 CSS 要容易得多。它使您的代码更有组织性和清晰，并且我强烈推荐它。让我们来看看 Sass 的一些显着特点。

# 变量

Sass 的一个简单而强大的功能是变量。让我们设置名为`$blue`和`$red`的变量，分别等于我在整个站点中使用的蓝色或红色的颜色：

```css
//colors
$blue: #0072AE;
$red: #EB2428;
```

现在，当我需要输入难以记住的十六进制值`#0072AE`时，我只需输入`$blue`，Sass 就会神奇地处理它。变量的另一个很好的用途是它们与字体一起使用，这就是我认为它真正强大的地方。对于字体，通常可以输入`font-family`，然后创建一组字体。但是，这可能会变得冗长和重复。因此，将所有这些信息插入变量中，例如`$maven`或`$droid`这样的非常简单的变量，使得快速使用字体变得非常容易，随时都可以使用：

```css
//fonts
$serif: 'Times New Roman', Georgia, serif;
$sans: Arial, Helvetica, sans-serif;
$maven: 'Maven Pro', $sans;
$droid: 'Droid Serif', $serif;
```

然后我可以在设置`font-family`的任何地方使用这些变量：

```css
h1, h2 {
  font-family: $maven;
}
p {
  font-family: $droid;
}
```

这将被编译为整个字符串：

```css
h1, h2 {
  font-family: 'Maven Pro', Arial, Helvetica, sans-serif;;
}
p {
  font-family: 'Droid Serif', 'Times New Roman', Georgia, serif;
}
```

# 混合

Sass 中还有一个更好的功能，称为**混合**。基本上，它们是一种抽象重复的方法。例如，为 CSS3 输入供应商前缀很麻烦，但我可以使用`@mixin`关键字声明一个混合，然后创建一个充满供应商前缀的模板。在这里，我声明了一个名为`transition`的混合：

```css
@mixin transition($property: all, $duration: .25s, $timing-function: ease) {
    -webkit-transition: $property $duration $timing-function;
    transition: $property $duration $timing-function;
}
```

混合带有括号，括号内有参数`$property`，`$duration`和`$timing-function`。每个参数都有默认值，`all`，`.25s`和`ease`。然后我有-webkit-前缀的过渡属性和未前缀的版本。两者都将混合的参数作为它们的值。

这使我可以进入我的 CSS，并且，如果我想使用过渡，只需添加`@include transition`：

```css
.button {
    @include transition();
}
```

这将编译为：

```css
.button {
  -webkit-transition: all .25s ease;
  transition: all .25s ease;
}
```

我还可以在任何时候调用此混合时更新其默认值：

```css
.button {
    @include transition(background-color, .5s, ease-in-out);
}
```

这将编译为：

```css
.button {
  -webkit-transition: background-color .5s ease-in-out;
  transition: background-color .5s ease-in-out;
}
```

# SASS 嵌套

除了变量和混合，还有嵌套，表面上看起来可能不太强大，但非常方便。您可以将选择器嵌套在彼此内部，而不是编写后代选择器。您可以在以下 CSS 代码中看到，我实际上将`focus`和`hover`选择器嵌套在`.button`内部：

```css
.button {
  &:focus,
  &:hover {
    background-color: #333;
    color: #fff;
    transform: scale(1, 1) translate(0, -5px);
  }
}
```

这将编译为以下内容：

```css
.button:focus, 
.button:hover {
  background-color: #333;
  color: #fff;
  transform: scale(1, 1) translate(0, -5px);
}
```

作为一个经验法则，如果不必要，不要嵌套，因为选择器每次嵌套都会变得更具体和更重要。模块化 CSS 的技巧是保持选择器的轻量级。有关 Sass 中嵌套和使用特殊的&字符的更多信息，请查看我为 CSS-Tricks.com 撰写的文章*The Sass Ampersand*（[`css-tricks.com/the-sass-ampersand/`](https://css-tricks.com/the-sass-ampersand/)）。

# 使用 SASS 创建和导入部分文件

在第七章的*Web Fonts*部分的*Font kits and font services*中，我们还讨论了 Sass 允许您为 CSS 的不同部分创建部分文件，并将它们导入到您的主 Sass 文件中：

```css
//Imports
@import '_variables.scss';
@import '_mixins.scss';
@import '_icons.scss';
@import '_reset.scss';
@import '_modular.scss';
@import '_modal.scss';
```

Sass 将所有部分 Sass 文件编译成一个主 CSS 文件。所以我的 CSS 被分解成更小的块。它们都编译成`style.css`。

拥有这些多个组织良好的文件的最大好处是它们会编译成一个文件，这意味着只有一个 HTTP 请求，而不是多个请求。这就是性能的提升。更不用说它使我的 CSS 非常有条理。

这些只是预处理器（特别是 Sass）的一些非常好的特性。在这一点上，使用 Sass 或 Less 绝对是最合乎逻辑的步骤。您编写的 Sass 样式表需要通过编译器处理，将其转换为普通的 CSS；否则，浏览器将无法理解 Sass 代码。对于编译，您有几个选项。您可以安装 Ruby 和 Sass，并使用命令行来监视对 Sass 文件所做的任何更改。您还可以查看类似 CodeKit 的软件来执行相同的操作。或者您可以使用像 Gulp 这样的任务运行器，就像我们在上一节末讨论的那样。

要了解更多关于 SASS 的信息，我建议在 Packt 图书馆中观看*Brock Nunn 的 Rapid SASS*视频课程：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00485.jpeg)

还要查看*Dan Cederholm*的*SASS for Web Designers*。这本书非常好地以简单的方式解释了 Sass，并且阅读起来很快：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00486.jpeg)

# JavaScript 和 jQuery

前端开发人员的另一个合乎逻辑的步骤是学习 JavaScript，如果您还没有学习的话。通过 CSS，我们可以通过`hover`和`focus`状态添加交互性，但我们无法进行单击或滑动等操作。这就是 JavaScript 和 jQuery 的用武之地。我建议您学习 JavaScript 的基础知识；但是，如果您想快速入门，可以先学习 jQuery。

所以假设我们想要做的事情是在单击“了解更多>>”链接时显示一个模态框：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00487.jpeg)

我们可以有一个显示模态框：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00488.jpeg)

所以我们有一个会淡入淡出的动画。因此，使用 jQuery 设置动画相对比使用 JavaScript 更容易。这个想法是在 HTML 和 CSS 中创建一个模态框，就好像它一直存在一样。我创建了模态框，并将 HTML 放在 HTML 文件的最底部：

```css
<div class="modal modal-learn-more">
    <span class="close-modal">close</span>
    <h2>Premium Benefits</h2>
    <ul>
        <li>More shark teeth than you can handle</li>
        <li>13 Species of octopus</li>
        <li>Giant, ancient lobsters!</li>
        <li>4 Whales</li>
    </ul>
</div>
```

然后我有一个名为`modal.scss`的 Sass 部分文件，它样式化了模态框并将其定位到它应该在的位置：

```css

//learn more modal
.modal {
  display: none;
  width: 40%;
  margin: 0 auto;
  position: absolute;
  top: 200px;
  left: 50%;
  @include translateX(-50%);
  background: #fff;
  @include box-shadow;
  @include border-radius;
  overflow: hidden;
  .close-modal {
    position: absolute;
    right: 10px;
    top: 10px;
    color: #fff;
    cursor: pointer;
    text-decoration: underline;
  }
  h2 {
    background: $blue;
    color: #fff;
    padding: 10px;
  }
  ul {
    padding: 10px 30px 30px 30px;
  }
}
```

`.modal`类也设置为`display: none`，因此默认情况下它是不存在的。就像我们的下拉菜单一样；默认情况下，它是隐藏的。

这里有一些 jQuery 来打开模态框：

```css
//open modal//
$(".learn-more").on("click", function(event){
    event.preventDefault();
    $(".modal-learn-more").fadeIn();
});
```

基本上，这会监视具有`learn-more`类的链接的单击，然后淡入具有`modal-learn-more`类的元素。如果我们回到 HTML，我们会看到我们在模态框的最外层父`div`上有`modal-learn-more`类：

```css
<div class="modal modal-learn-more">
    <span class="close-modal">close</span>
    <h2>Premium Benefits</h2>
    <ul>
        <li>More shark teeth than you can handle</li>
        <li>13 Species of octopus</li>
        <li>Giant, ancient lobsters!</li>
        <li>4 Whales</li>
    </ul>
</div>
```

这是可读性很强的一小部分 jQuery。如果我们想要告诉模态框我们要在单击关闭链接时关闭它，也是同样的操作。

```css
//close modal//
$(".close-modal").on("click", function(event){
    event.preventDefault();
    $(".modal-learn-more").fadeOut();
});
```

基本上我们是在说当你单击关闭模态框时，我们将使`modal-learn-more`淡出。jQuery 通过它们创建的预定义方法来处理淡入和淡出的动画。在 jQuery 中非常容易选择我们要淡出的`div`和我们要单击的项目或元素。要了解更多关于 jQuery 的信息，我建议查看 Packt 图书馆中的 jQuery 书籍，特别是*jQuery for Designers: Beginner's Guide*。

Sass 和 jQuery 是接下来的逻辑步骤。Sass 将 CSS 编写提升到了一个新的水平，而 jQuery 将为您的网站添加功能和更深入的交互能力。更不用说它将使您成为一个全面的前端开发人员。在下一节中，我将通过总结我们讨论过的所有内容，并指出一些可以获取更多信息的好资源来结束。

# 结论和链接

感谢阅读《精通 CSS》。我真的很享受整理这本书。我们涵盖了很多内容，所以我将对我们学到的东西进行总结，并指引你获取更多关于这些主题的信息的方向。

# 盒模型和块级与内联元素

我们从回顾基础知识开始这本书，比如盒模型，以及块级和内联元素之间的区别。学习更多关于这两个重要的基础知识的好地方是 Sitepoint 的 A 到 Z CSS 视频。关于块级与内联元素：[`www.sitepoint.com/atoz-css-screencast-display/`](https://www.sitepoint.com/atoz-css-screencast-display/)，关于盒模型：[`www.sitepoint.com/atoz-css-screencast-box-model/`](https://www.sitepoint.com/atoz-css-screencast-box-model/)。在这里，你可以观看一些非常有帮助的盒模型和显示视频。

# 浮动

我们还讨论了很多关于浮动以及如何使用它们来创建多列布局，就像我们在主页上做的那样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00489.jpeg)

我们讨论了浮动带来的问题，比如塌陷，以及其他内容围绕浮动流动。我们还讨论了不同的方法，比如使用`clear-fix`，来避免这些问题。要了解更多关于浮动的知识，我将直接指向 Sitepoint 的 A 到 Z CSS，以及短短六分钟的视频（[`www.sitepoint.com/atoz-css-screencast-float-and-clear/`](https://www.sitepoint.com/atoz-css-screencast-float-and-clear/)），它涵盖了浮动的基础知识以及如何适应它们的怪癖。

# 模块化 CSS

接下来，你学会了如何创建模块化的 CSS。我们不想为网站的一个部分设置样式，然后如果我们想为网站的另一个类似的部分设置样式，就重新设置所有这些样式。我们希望能够通过采用模块化技术来重用我们已经创建的 CSS。当我们使用模块化类构建我们的按钮时，我强调了这一点。要了解更多关于模块化 CSS 的知识，你可以在**SMACSS**（**可扩展和模块化的 CSS 架构**）上找到更多信息；请参阅[smacss.com](http://smacss.com)网站。

# CSS3

在这一点上，我们最终使用了大量的 CSS3 来制作我们的按钮。我们在整个网站上使用了很多悬停效果。在电影页面上，我们为其中一部电影的图片添加了一个悬停效果。如果你想了解更多关于 CSS3 的知识，Packt 图书馆中有一本很棒的书，名为《使用 CSS3 设计下一代 Web 项目》（Designing Next Generation Web Projects with CSS3），作者是 Sandro Paganotti。

另外，你可能想看看丹·塞德霍姆（Dan Cederholm）的《网页设计的 CSS3》，第二版，可以通过[abookapart.com](http://abookapart.com)获取。

# 创建导航

我们继续构建了一个固定在顶部的导航，内容在其下滚动。它有一个漂亮的下拉菜单，使用 CSS 动画向下精美地展开：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00490.jpeg)

我们还让我们的鲨鱼在浏览器刷新时动起来；我们让它看起来像在游泳，这非常有趣。我为我在 CSS 动画上写的一篇文章感到自豪：[`www.richfinelli.com/css-animations-arent-that-tough/`](http://www.richfinelli.com/css-animations-arent-that-tough/)。在这篇文章中，我详细介绍了所有的动画属性，并逐渐进展到创建一个相当复杂的动画：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00491.jpeg)

我发现自己经常参考**Mozilla 开发者网络**（**MDN**）网站，快速查阅动画属性。我认为 MDN 是一个非常可靠和深入的网络资源。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00492.jpeg)

# 使网站响应式

我们在使我们的网站响应式方面做得很好，特别是当我们完全将我们的菜单转换成小屏幕以适应移动设备时：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-css/img/00493.jpeg)

在我看来，学习更多关于响应式网页设计的最佳地方就是从发明它的人那里学习-Ethan Marcotte。看看那本开创性的书- *Responsive Web Design.* 该书的第二版于 2014 年底发布。

# 网络字体

在第七章中，*Web Fonts*，我们谈到了网络字体和图标字体。我们了解到一个好的字体确实可以让网站看起来很棒。回到[abookapart.com](https://abookapart.com/)网站，有一本非常好的书，你可以用来学习如何设置和配对字体。它叫做*On Web Typography*，作者是*Jason Santa Maria*。

# HiDPI 设备

最后，在第八章中，*Workflow for HiDPI Devices*，我们通过学习如何处理图像，使它们在 iPad Retina 等双倍密度显示屏上看起来清晰，使我们的网站“retina ready”。我们研究了许多应对 Retina 的方法。在网页开发中，我最激动的事情之一就是 SVG。它真的解决了一些 Retina 的明显问题。CSS 技巧的 Chris Coyier（[`css-tricks.com`](https://css-tricks.com/)）写了一些关于 SVG 以及如何使用它的很棒的文章，包括一篇标题为- Using SVG 的文章。

此外，关于`srcset`属性的更多信息，我写了两篇文章。一篇是关于 W 描述符和`sizes`属性的（[`www.richfinelli.com/srcset-part-2/`](http://www.richfinelli.com/srcset-part-2/)），另一篇是关于 X 描述符的（[`www.richfinelli.com/srcset-part-1/`](http://www.richfinelli.com/srcset-part-1/)）。

# Flexbox

Flexbox 太有趣了！我们将基于浮动的 3 列布局转换为基于 flexbox 的布局，并使用 flexbox 构建了一个新的部分，我们的产品列表。关于 flexbox 的更多信息，我建议查看 Wes Bos 的视频课程，*What the Flexbox! at* flexbox.io，或者快速全面地参考所有 flexbox 属性，请查看*CSS 技巧的 A Complete Guide to Flexbox*，网址为[`css-tricks.com/snippets/css/a-guide-to-flexbox/`](https://css-tricks.com/snippets/css/a-guide-to-flexbox/)。

# 最后的建议：音频播客非常棒

如果你和我一样，渴望学习并且要长时间开车上班，音频播客可以是一个很好的资源。我最喜欢的前端开发播客是 Shoptalk ([`shoptalkshow.com/`](http://shoptalkshow.com/))和 Syntax ([`syntax.fm/`](https://syntax.fm/))。两者都非常有趣和富有信息。在上班的路上听播客是我保持了解网页开发动态和学习新知识的方式。

# 总结

最后，我认为我们在这里创建了一个非常棒的小网站，学到了很多关于 CSS 和网页开发的知识。再次感谢阅读。我真的很享受把它放在一起的过程。祝你们成功，并希望你们继续磨练你们的 CSS 技能。
