# CSS3 专家级编程（二）

> 原文：[`zh.annas-archive.org/md5/2789AE2FE8CABD493B142B2A68E84610`](https://zh.annas-archive.org/md5/2789AE2FE8CABD493B142B2A68E84610)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：掌握伪元素和伪类

使用 CSS 添加网站上的简单交互自从伪类可用以来就已经很常见了。了解如何在网站上使用这个功能非常重要。伪元素可以在诸如 Internet Explorer 8/9 +之类的浏览器中使用，并且可以帮助处理一些在网页上重复出现的元素，这些元素在大多数情况下是通过空的`spans`和`divs`添加的，例如按钮中的图形细节，三角形等。使用伪元素，您可以在不创建 DOM 元素的情况下添加这些元素。

绘制基本图形是一项非常重要的技能，特别是当你将它们与伪元素链接在一起时，你可以在其中添加它们。添加三角形或其他特定元素可能是一个非常重要的功能，因为你不必将这些图形元素作为背景或`img`元素进行裁剪。

本章将掌握 CSS 代码中的伪元素，伪类和基本图形的绘制。最后，在每个部分中，您可以将这些元素组合成实用且可重用的代码。

在本章中，我们将：

+   学习伪类的使用

+   学习伪元素的使用

+   学习如何绘制基本图形

+   在 SASS 中创建大量可重用的混合

# 伪类

伪类用于描述元素在特定操作后的行为。伪类支持的操作如下：

+   鼠标悬停

+   鼠标点击/触摸

+   输入焦点

伪类的另一个用途是匹配特定容器中的元素，描述了容器中的顺序：

+   第一个子元素，最后一个子元素

+   任何子元素

+   任何类型的子元素

伪类的最重要特性可以在链接（带有`href`属性的`<a>`元素）上看到。

## 我们如何检查：活动状态，悬停状态？

悬停状态可以在将鼠标指针移动到链接上时进行检查。这个属性最简单的用法可以通过以下代码进行检查：

HTML：

```css
<a href="#"> Title of link</a>
```

SASS：

```css
a
  color: #000
  background: #fff

a:hover
  color: #fff
  background: #000
```

生成的 CSS 代码：

```css
a {
    color: #000;
    background: #fff;
}

a:hover {
    color: #fff;
    background: #000;
}
```

使用上述代码，当你将鼠标悬停在链接上时，链接的颜色和背景将会改变。

## 用法-多级菜单

多级菜单是悬停状态的最常见用法。下拉菜单可以使用简单的 HTML 和 CSS 开发。您几乎可以在每个网站上看到它。了解如何构建它可以成为更复杂解决方案的基础。让我们构建一个多级导航，并以以下内容为基础：

HTML 代码：

```css
<ul>
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
<ul>
```

SASS 代码：

```css
ul
  list-style: none
  padding: 0

ul > li
  float: left
  display: inline-block
  position: relative
  margin-right: 10px

  &:hover
    ul
      display: block
      width: 200px

ul ul
  display: none
  position: absolute
  left: 0

  li
    display: block
```

编译后的 CSS：

```css
ul {
    list-style: none;
    padding: 0;
}

ul >li {
    float: left;
    display: inline-block;
    position: relative;
    margin-right: 10px;
}

ul >li:hover ul {
    display: block;
    width: 200px;
}

ul ul {
    display: none;
    position: absolute;
    left: 0;
}

ul ul li {
    display: block;
}
```

在任何元素上悬停时的效果可以在以下截图中看到：

![用法-多级菜单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00032.jpeg)

在悬停在第二个元素后：

![用法-多级菜单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00033.jpeg)

## 用法- CSS 悬停行

在简短的 HTML 表格中，阅读所有内容很容易。但是在您有大量数据（特别是在金融网站上）分配在许多行和列中的情况下，很容易使表格变得难以阅读。有几种方法可以简化阅读过程。最简单的方法是为所有行添加悬停效果。每次指向一行时，它都会改变背景颜色。让我们使用以下 HTML 代码：

```css
<table>
    <thead>
    <tr>
        <th> Col one header</th>
        <th> Col two header</th>
        <th> Col three header</th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td> Col one header</td>
        <td> Col two header</td>
        <td> Col three header</td>
    </tr>
    <tr>
        <td> Col one header</td>
        <td> Col two header</td>
        <td> Col three header</td>
    </tr>
    <tr>
        <td> Col one header</td>
        <td> Col two header</td>
        <td> Col three header</td>
    </tr>
    <tr>
        <td> Col one header</td>
        <td> Col two header</td>
        <td> Col three header</td>
    </tr>
    </tbody>
</table>
```

假设行数（`tbody`中的`tr`元素）几乎是无限的。这可能会给我们带来一个非常长的表格。为了方便阅读，我们可以为每一行添加悬停效果，如下所示：

SASS：

```css
tbody
  tr:hover
    background: #d3d3d3
```

编译后的 CSS：

```css
tbody tr:hover {
    background: #d3d3d3;
}
```

每次悬停在每一行上时，您可以看到以下截图中显示的效果（灰色行被悬停）：

![用法-CSS 悬停行](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00034.jpeg)

# 伪类的用法

新的伪类为 CSS/HTML 编码人员打开了新的视野。大多数功能，如`first-child`，`last-child`和`nth-child`，都是通过 JavaScript 代码添加的。例如，使用 jQuery 代码，您可以获取一个列表元素，并向第一个/最后一个/nth 元素添加特定类，然后正确创建选择器，您可以添加 CSS 代码。

但是当它被浏览器原生支持时，最好使用 CSS。让我们收集关于这个功能的基本知识。

## 如何使用：first-child，:last-child，:nth-child()

这些伪元素的简短介绍如下：

+   `:first-child`：这指向其父元素的第一个子元素

+   `:last-child`：这指向其父元素的最后一个子元素

+   `:nth-child()`：这指向与`()`中包装的模式匹配的元素

检查其工作原理的最简单方法是创建一个带有新元素的无序列表：

```css
<ul>
    <li>Element one</li>
   <li>Element two</li>
   <li>Element three</li>
   <li>Element four</li>
   <li>Element five</li>
   <li>Element six</li>
   <li>Element seven</li>
   <li>Element eight</li>
</ul>
```

假设我们需要为列表的元素添加样式。我们需要添加的第一个样式仅与列表的第一个元素相关。最简单的方法是向该元素添加特定的类，如下所示：

```css
<li class="first_element>Element one</li>
```

然后为其添加特定的 CSS/SASS 代码：

SASS 代码：

```css
.first_element
  color: #f00
```

编译为 CSS：

```css
.first_element {
    color: #f00;
}
```

使用新伪类：

```css
li:first-child
  color: #00f
```

或：

```css
li:nth-child(1)
  color: #00f
```

编译为：

```css
li:first-child {
    color: #00f;
}

li:nth-child(1) {
    color: #00f;
}
```

我们需要追加的第二种样式是使最后一个元素的文本颜色变为蓝色。最简单的方法是更改 HTML 代码：

```css
<li class="last_element">Element eight</li>
```

然后为其添加特定的 CSS/SASS 代码：

```css
.last_element
  color: #00f
```

编译为：

```css
.last_element {
  color: #00f;
}
```

使用新伪类：

```css
li:last-child
  color: #00f
```

编译为：

```css
li:last-child {
  color: #00f; 
}
```

在这种情况下，我们不关心列表中元素的数量。列表的最后一个元素将始终具有前面的 CSS 代码。

为第八个元素添加样式，如下所示：

```css
li:nth-child(8)
  color: #00f
```

编译后：

```css
li:nth-child(8) {
  color: #00f; 
}
```

在这种情况下，我们关心的是计数元素。列表的第八个元素将始终具有前面的 CSS 代码。

假设我们想要使第五个元素变为橙色。最简单的方法是更改 HTML 代码：

```css
<li class="fifth_element">Element five</li>
```

然后追加 CSS 代码：

```css
.fifth_element
  color: orange
```

使用伪类，我们可以这样绘制 SASS：

```css
li:nth-child(5)
  color: orange
```

在浏览器中的代码：

![如何使用:first-child、:last-child、:nth-child()](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00035.jpeg)

## 用法-为表格添加样式

实际示例对于学习是最好的。我们可以使用伪类的所有属性的最常见的情况是表格。让我们看一下以下 HTML 代码：

```css
<table>
    <thead>
    <tr>
        <th> Col one header</th>
        <th> Col two header</th>
        <th> Col three header</th>
    </tr>
    </thead>
    <tbody>
    <tr>
        <td> Col one content</td>
        <td> Col two content</td>
        <td> Col three content</td>
    </tr>
    <tr>
        <td> Col one content</td>
        <td> Col two content</td>
        <td> Col three content</td>
    </tr>
    <tr>
        <td> Col one content</td>
        <td> Col two content</td>
        <td> Col three content</td>
    </tr>
    <tr>
        <td> Col one content</td>
        <td> Col two content</td>
        <td> Col three content</td>
    </tr>
    </tbody>
</table>
```

让我们为表格添加斑马条纹样式；这样可以更轻松地阅读表格：

```css
tbody
  tr:nth-child(2n)
    background: #d3d3d3
```

编译后的 CSS：

```css
tbody tr:nth-child(2n) {
    background: #d3d3d3;
}
```

这种样式将为表格中的每个第二个元素添加灰色背景，如下面的屏幕截图所示：

![用法-为表格添加样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00036.jpeg)

## 探索:nth-child 参数

作为`:nth-child`基于选择器的参数，您可以使用以下任何一个：

+   **Even**：这将匹配所有偶数元素

+   **Odd**：这将匹配所有奇数元素

此外，您可以使用*an+b*参数，例如：

+   **3n+1**：这将匹配具有索引（从 1 开始计数）的元素：1, 4, 7, 10,…

+   **–n+5**：这将匹配从 1 到 5 的元素

+   **2n+4**：这将匹配元素：4, 6, 8, 10, 12, …

## 如何使用:nth-last-child

这个伪类与`nth-child`类似。不同之处在于`nth-child`从列表的开头开始工作，而`nth-last-child`从列表的末尾开始工作：

+   **Even**：这将匹配从最后一个元素开始的所有偶数元素

+   **Odd**：这将匹配从最后一个元素开始的所有奇数元素

您可以使用*an+b*参数，就像我们在`nth-child`中使用的那样：

+   **3n+1**：这将匹配具有索引（从最后一个元素开始计数）的元素：1, 4, 7, 10,…

+   **–n+5**：这将匹配最后五个元素

+   **2n+4**：这将匹配元素：4, 6, 8, 10, 12, …（从最后一个元素开始计数）

## 如何使用:first-of-type、:last-of-type、:nth-of-type 和:nth-last-of-type

这些伪类与容器中的元素相关联，其中聚集了一些元素。它的工作方式类似于 nth-child 机制。为了更好地理解，让我们从以下 HTML 代码开始：

```css
<div class="parent">
    <span>First span</span><br/>
    <strong>First strong</strong><br/>
    <span>Second span</span><br/>
    <strong>Second strong</strong><br/>
    <span>Third span</span><br/>
    <strong>Third strong</strong><br/>
    <span>Fourth span</span><br/>
    <strong>Fourth strong</strong><br/>
    <span>Fifth span</span>
</div>
```

SASS 代码：

```css
.parent
  span
    &:first-of-type
      color: red

    &:last-of-type
      color: red

  strong
    &:nth-of-type(2)
      color: pink

    &:nth-last-of-type(2)
      color: magenta
```

编译为 CSS：

```css
.parent span:first-of-type {
    color: red;
}

.parent span:last-of-type {
    color: red;
}

.parent strong:nth-of-type(2) {
    color: pink;
}

.parent strong:nth-last-of-type(2) {
    color: magenta;
}
```

让我们解释一下：

+   **.parent span:first-of-type**：这将匹配`.parent div (<div class="parent">)`中的第一个元素，即`span`

+   **.parent span:last-of-type**：这将匹配`.parent`中的最后一个元素，即`span`

+   **.parent strong:nth-of-type(2)**：这将匹配第二个元素，即`strong`

+   **.parent strong:nth-last-of-type(2)**：这将匹配从最后一个元素开始计数的第二个元素，*即强调*，如下面的屏幕截图所示：![如何使用:first-of-type，:last-of-type，:nth-of-type 和:nth-last-of-type](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00037.jpeg)

## 使用:empty 伪类的空元素

有时，您需要处理列表，其中需要使用一段 CSS 代码处理空元素，另一段 CSS 代码处理有内容的元素。最简单的方法是向其元素添加*empty*类，而无需干扰 HTML 代码。让我们看看 HTML 代码：

```css
<ul>
    <li class="box">Black text</li>
    <li class="box"></li>
    <li class="box">Black text</li>
    <li class="box"></li>
    <li class="box"></li>
    <li class="box">Black text</li>
    <li class="box"></li>
</ul>
```

和 SASS 代码：

```css
ul
  list-style: none

.box
  background: white
  color: black
  text-align: center
  height: 100px
  width: 100px
  float: left

.box:empty
  color: black
  background: black
```

编译为 CSS：

```css
ul {
    list-style: none;
}

.box {
    background: white;
    color: black;
    text-align: center;
    height: 100px;
    width: 100px;
    float: left;
}

.box:empty {
    color: black;
    background: black;
}
```

这将在浏览器中显示以下视图：

![使用:empty 伪类的空元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00038.jpeg)

很容易分析上述代码。所有空元素（没有子元素的元素）都具有黑色背景。所有具有子元素的元素都具有白色背景和黑色文本。

# 使用伪类支持表单样式

您可以使用 CSS 代码支持表单的验证和简单交互。在接下来的几节中，您将看到如何使用 CSS 选择器进行简单验证和输入的简单交互。使用适当的 CSS 代码，您还可以检查任何元素是否为必填或禁用。让我们看看这是如何完成的。

## 使用:valid 和:invalid 进行验证

以前的验证是使用 JavaScript 代码完成的。使用适当的 CSS 代码，您只需使用良好的选择器即可完成。让我们使用 HTML 和 CSS 代码进行检查：

HTML 代码：

```css
<form class="simple_validation">
    <input type="number" min="5" max="10" placeholder="Number">
    <input type="email" placeholder="Email">
    <input type="text" required placeholder="Your name"/>
</form>
```

SASS 代码：

```css
.simple_validation
  padding: 10px
  width: 400px
  box-sizing: border-box

  &:valid
    background: lightgreen

  &:invalid
    background: lightcoral

  input
    display: block
    margin: 10px 0
    width: 100%
    box-sizing: border-box

    &:valid
      border: 3px solid green

    &:invalid
      border: 3px solid red
```

编译后的 CSS：

```css
.simple_validation {
    padding: 10px;
    width: 400px;
    box-sizing: border-box;
}

.simple_validation:valid {
    background: lightgreen;
}

.simple_validation:invalid {
    background: lightcoral;
}

.simple_validation input {
    display: block;
    margin: 10px 0;
    width: 100%;
    box-sizing: border-box;
}

.simple_validation input:valid {
    border: 3px solid green;
}

.simple_validation input:invalid {
    border: 3px solid red;
}
```

在上面的示例中，您可以检查有效和无效伪类的工作原理。每次将电子邮件输入到电子邮件字符串中，而该字符串不是电子邮件地址时，输入框将具有红色边框，并且表单的背景颜色将更改为浅红色（`lightcoral`）。在输入数字的情况下也是如此，该数字需要在 5 到 10 的范围内。另外，对于类型为文本的输入，添加了 required 属性。如果没有输入，它具有`:invalid`伪类。

## 添加输入状态：:focus，:checked，:disabled

焦点伪类与当前接收焦点的输入相关。请记住，用户可以使用鼠标指针和键盘上的 Tab 键来完成此操作。伪类 checked 与输入类型为复选框和单选按钮相关，并匹配状态更改为已选中的元素。为了展示它的确切工作原理，让我们修改我们在上一节中使用的 HTML 代码：

HTML 代码：

```css
<form class="simple_validation">
    <input type="number" min="5" max="10" placeholder="Number">
    <input type="email" placeholder="Email">
    <input type="text" required placeholder="Your name"/>

    <input type="checkbox" id="newsletter"></input>
    <label for="newsletter">checked</label>
</form>
```

SASS 代码：

```css
.simple_validation
  padding: 10px
  width: 400px
  box-sizing: border-box

  &:valid
    background: lightgreen

  &:invalid
    background: lightcoral

  label
    display: inline-block

    &:before
      content: 'Not '

  input
    display: block
    margin: 10px 0
    width: 100%
    box-sizing: border-box

    &:valid
      border: 3px solid green

    &:invalid
      border: 3px solid red

    &:focus
      background: orange
      color: red
      border: 3px solid orange

    &[type="checkbox"]
      display: inline-block
      width: 20px

      &:checked
        & + label
          color: red

          &:before
            content: 'Is '
```

编译后的 CSS：

```css
.simple_validation {
    padding: 10px;
    width: 400px;
    box-sizing: border-box;
}

.simple_validation:valid {
    background: lightgreen;
}

.simple_validation:invalid {
    background: lightcoral;
}

.simple_validation label {
    display: inline-block;
}

.simple_validation label:before {
    content: "Not ";
}

.simple_validation input {
    display: block;
    margin: 10px 0;
    width: 100%;
    box-sizing: border-box;
}

.simple_validation input:valid {
    border: 3px solid green;
}

.simple_validation input:invalid {
    border: 3px solid red;
}

.simple_validation input:focus {
    background: orange;
    color: red;
    border: 3px solid orange;
}

.simple_validation input[type="checkbox"] {
    display: inline-block;
    width: 20px;
}

.simple_validation input[type="checkbox"]:checked + label {
    color: red;
}

.simple_validation input[type="checkbox"]:checked + label:before {
    content: "Is ";
}
```

上面的示例为表单添加了更多的交互性。第一个新功能是将焦点元素的颜色更改为红色，其背景/边框更改为橙色。第二个功能是与复选框相关的交互。在将其状态更改为已选中后，它将更改`:before`元素（这将在下一节中更好地描述）。在初始化时，`:before`元素设置为`"Not"`。使用 HTML 代码完全给出`"Not checked"`。复选框选中后，`before`元素更改为`"Is"`，并显示完整字符串等于`"Is checked"`。

让我们看看在浏览器中它将是什么样子。以下屏幕截图出现在页面的开头：

![添加输入状态：:focus，:checked，:disabled](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00039.jpeg)

当复选框被选中时，将出现以下内容：

![添加输入状态：:focus，:checked，:disabled](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00040.jpeg)

标签的 before 元素发生了可见的变化，如下面的屏幕截图所示，它还显示了输入的焦点：

添加输入状态：:focus，:checked，:disabled

验证后的表单如下：

![添加输入状态：:focus，:checked，:disabled](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00042.jpeg)

## 额外的方面-给占位符着色

是的，当然！您需要为占位符添加样式。您可以这样做，但是需要额外添加前缀：

对于 Internet Explorer：

```css
:-ms-input-placeholder
```

对于 Firefox：

```css
:-moz-placeholder
```

对于 WebKit 浏览器：

```css
::-webkit-input-placeholder
```

# 使用 CSS 绘制基本图形

绘图原语是图形基础中最简单和主要的情况。在 CSS 中，它可以在常见情况下使用，比如为按钮或任何其他 DOM 元素添加细节。让我们学习在 CSS 中绘制原语的基础知识。

## 如何画一个矩形/正方形

在 CSS 中最容易绘制的原语是矩形。让我们使用以下代码绘制一个简单的矩形：

HTML 代码：

```css
<div class="rectangle"></div>
```

SASS 代码：

```css
.rectangle
width: 100px
height: 200px
background: black
```

编译后的 CSS：

```css
.rectangle {
    width: 100px;
    height: 200px;
    background: black;
}
```

这将在浏览器中绘制一个矩形，如下所示：

![如何画一个矩形/正方形](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00043.jpeg)

要画一个正方形，我们需要创建以下代码：

HTML 代码：

```css
<div class="square"></div>
```

SASS 代码：

```css
.square
width: 100px
height: 100px
background: black
```

编译后的 CSS：

```css
.square {
    width: 100px;
    height: 100px;
    background: black;
}
```

可重用的混合器用于正方形和矩形：

```css
=rectangle($w, $h, $c)
  width: $w
  height: $h
  background: $c

=square($w, $c)
  width: $w
  height: $w
  background: $c
```

## 如何画一个圆

画一个圆非常简单。这种方法是基于边框半径和一个简单的矩形，如下面的例子所示：

HTML 代码：

```css
<div class="circle"></div>
```

SASS 代码：

```css
.circle
    width: 100px
    height: 100px
    border-radius: 50%
    background: black
```

编译后的 CSS：

```css
.circle {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    background: black;
}
```

在浏览器中，你将看到以下内容：

![如何画一个圆](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00044.jpeg)

SASS 混合器：

```css
=circle($size, $color)
  width: $size
  height: $size
  border-radius: 50%
  background: $color
```

## 如何画一个环

画一个环非常类似于画一个圆。模式是一样的，但是有一个适当的边框。让我们从初始的环标记开始：

HTML 代码：

```css
<div class="ring"></div>
```

SASS 代码：

```css
.ring
  width: 100px
  height: 100px
  border-radius: 50%
  border: 2px solid black
  background: none
```

编译后的 CSS：

```css
.ring {
    width: 100px;
    height: 100px;
    border-radius: 50%;
    border: 2px solid black;
    background: none;
}
```

在浏览器中，你将看到以下内容：

![如何画一个环](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00045.jpeg)

SASS 混合器：

```css
=ring($size, $color, $width)
  width: $size
height: $size
border-radius: 50%
  border: $width solid $color
background: none
```

## 如何用 CSS 画一个三角形

画一个三角形是基于边框的一个技巧：

HTML 代码：

```css
<div class="triangle-up"></div><br>
<div class="triangle-down"></div><br>
<div class="triangle-left"></div><br>
<div class="triangle-right"></div>
```

`br`元素仅用于在不同行中显示所有元素。

SASS 代码：

```css
.triangle-up
    width: 0 
    height: 0
    border-left: 10px solid transparent 
    border-right: 10px solid transparent
    border-bottom: 10px solid black

.triangle-down 
    width: 0 
    height: 0 
    border-left: 10px solid transparent
    border-right: 10px solid transparent
    border-top: 10px solid black

.triangle-left 
    width: 0 
    height: 0
    border-top: 10px solid transparent 
    border-bottom: 10px solid transparent
    border-left: 10px solid black 

.triangle-right 
    width: 0
    height: 0
    border-top: 10px solid transparent
    border-bottom: 10px solid transparent
    border-right: 10px solid black
```

编译后的 CSS：

```css
.triangle-up {
    width: 0;
    height: 0;
    border-left: 10px solid transparent;
    border-right: 10px solid transparent;
    border-bottom: 10px solid black;
}

.triangle-down {
    width: 0;
    height: 0;
    border-left: 10px solid transparent;
    border-right: 10px solid transparent;
    border-top: 10px solid black;
}

.triangle-left {
    width: 0;
    height: 0;
    border-top: 10px solid transparent;
    border-bottom: 10px solid transparent;
    border-left: 10px solid black;
}

.triangle-right {
    width: 0;
    height: 0;
    border-top: 10px solid transparent;
    border-bottom: 10px solid transparent;
    border-right: 10px solid black;
}
```

在浏览器中，你将看到以下内容：

![如何用 CSS 画一个三角形](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00046.jpeg)

SASS 混合器：

```css
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

# 伪元素

使用伪元素真的很重要，可以省略需要特定 HTML 代码的重复代码元素。伪元素的主要目的是减少 HTML 代码中的 DOM 元素。

## 什么是:before 和:after？

`:before`和`:after`是伪元素，你可以添加到 HTML 元素中。一个元素被添加为内联元素到一个选定的元素中。要获得`before`和`after`伪元素的基础，你可以绘制如下的 HTML 代码：

```css
<a>Element</a>
```

并附加以下 SASS 代码：

```css
a
  border: 1px solid #000

  &:before
    content: 'before'
    color: orange

  &:after
    content: 'after'
    color: orange
```

编译后的 CSS：

```css
a {
    border: 1px solid #000;
}

a:before {
    content: "before";
    color: orange;
}

a:after {
    content: "after";
    color: orange;
}
```

上述代码的输出如下：

![什么是:before 和:after？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00047.jpeg)

## 我们在哪里可以使用:before 和:after？

让我们假设一个任务，我们需要为列表中的每个元素添加一些文本。例如，我们有一个如下所示的列表：

```css
<ul>
    <li>Mike</li>
    <li>Ravi</li>
    <li>Adam</li>
    <li>Greg</li>
    <li>Anna</li>
</ul>
```

我们需要添加每个人都是前端开发者：

```css
ul
  li
&:before
content: "My name is "
      color: #f00

&:after
content: ". I'm Front End Developer"
      color: #f00
```

编译后的 CSS：

```css
ul li:before {
    content: "My name is ";
    color: #f00;
}

ul li:after {
    content: ". I'm Front End Developer";
    color: #f00;
}
```

在浏览器中，你将看到以下内容：

![我们在哪里可以使用:before 和:after？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00048.jpeg)

让我们使我们之前的代码可重用，并让我们创建一个带有箭头的按钮。HTML 代码将如下所示：

```css
<a href="#">Button</a>
```

让我们将之前创建的三角形混合器重新用到以下 SASS 代码的最后一行 CSS 代码中：

```css
=triangleRight($width, $height, $color)
  width: 0
  height: 0
  border-style: solid
  border-width: $height/2 0 $height/2 $width
  border-color: transparent transparent transparent $color

a
  display: inline-block
  border: 1px solid #000
    radius: 5px
  padding: 10px 40px 10px 10px
  position: relative
  text-decoration: none
  color: #000

  &:after
    display: block
    position: absolute
    right: 10px
    top: 50%
    margin-top: -5px
    content: ''
    +triangleRight(10px, 10px, #000)
```

编译后的 CSS：

```css
a {
    display: inline-block;
    border: 1px solid #000;
    border-radius: 5px;
    padding: 10px 40px 10px 10px;
    position: relative;
    text-decoration: none;
    color: #000;
}

a:after {
    display: block;
    position: absolute;
    right: 10px;
    top: 50%;
    margin-top: -5px;
    content: "";
    width: 0;
    height: 0;
    border-style: solid;
    border-width: 5px 0 5px 10px;
    border-color: transparent transparent transparent #000;
}
```

这将在浏览器中给我们以下结果：

![我们在哪里可以使用:before 和:after？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00049.jpeg)

## 第一个字母和第一行-简单的文本操作

在网页上，有些情况下，你需要为文本的第一行和文本的第一个字母添加样式。使用 CSS，你必须使用适当的选择器来做到这一点。让我们使用以下 HTML 代码：

```css
<p>Paragraph lorem ipsm Lorem ipsum dolor sit amet, consectetur adipisicing elit. Totam nisi soluta doloribus ducimus repellat dolorum quas atque, tempora quae, incidunt at eius eaque sit, culpa eum ut corporis repudiandae.</p>
```

在 SASS 文件中：

```css
p
  &:first-letter
    color: orange
    font:
      weight: bold
      size: 20px

  &:first-line
    color: pink
```

编译后的 CSS：

```css
p:first-letter {
    color: orange;
    font-weight: bold;
    font-size: 20px;
}

p:first-line {
    color: pink;
}
```

上述代码将把文本的第一行颜色改为粉色。第一个字母将被改为`橙色`颜色，`粗体`，`20px`大小。

## 如何改变选择颜色？使用::selection

公司有他们自己的颜色调色板。有时你需要自定义页面上选择的颜色。这可以通过`:selection`伪元素来实现：

SASS 代码：

```css
::-moz-selection,
::selection
background: red
color: white
```

编译后的 CSS：

```css
::-moz-selection,
::selection {
    background: red;
    color: white;
}
```

使用上述代码，每当你在页面上选择某些内容时，选择的颜色将变为`红色`，字体颜色将变为`白色`。

# 总结

在本章中，您学习了 CSS 代码中伪类、伪元素和基本图形的绘制基础。作为前端开发人员，您将经常使用这些 CSS 元素。伪类为您提供基本的交互性（悬停、激活），并扩展了选择器的可能性（`:nth-child`、`:first-child`、`:last-child`）。通过伪元素，您可以用 CSS 代码扩展 HTML 的可能性（`:before`、`:after`、`:first-letter`、`:first-line`），并且可以为选择设置样式。

在下一章中，您将获得有关媒体查询的基本知识，这是响应式网站的基础。


# 第四章：响应式网站-为特定设备准备您的代码

在这一章中，您将了解**响应式网页设计**（**RWD**）以及如何准备项目。它将涵盖现代网站的问题和优化技术。这一章将是关于媒体查询的知识基础-如何准备它们以及如何调整特定设备。

在这一章中，我们将涵盖以下主题：

+   RWD 方法

+   使用媒体查询

# 响应式网站的基础

几乎所有现代网站都可以在桌面和移动设备（手机、平板电脑）上显示。正确调整 CSS 和 HTML 代码是创建响应式网站的主要假设。基本的响应式网站构建过程是基于代码的调整，一旦完成，网站就可以在所有设备上正确显示。现在，响应式网站的*响应性*稍微增强了。它不仅是创建 CSS/HTML/JS 代码和考虑设计方面，还要考虑移动设备上的性能。带有 Web 浏览器的移动设备现在是人们浏览网站的主要设备。让我们看看创建响应式网站的主要方法。

## 桌面优先方法

这种方法曾经是 CSS 框架中的主要方法。HTML 和 CSS 代码的主要目的是在桌面浏览器中查看网页。然后提供基于桌面代码的移动版本。最后的过程是调整移动设备的代码。它看起来像是削减网站的功能，并调整桌面视图以适应较小的移动设备。

## 移动优先方法

这种方法在所有现代 CSS 框架（Twitter bootstrap，Foundation framework）中都有使用。首先，代码是为移动设备准备的，然后再为较大的设备（从平板电脑到台式电脑屏幕）进行*缩放*。这种方法现在更为常见，也更好，因为移动设备的代码不必像在桌面优先方法中那样是 CSS 技巧、HTML 重复和 JS 机制的组合。

哪种方法适合您？这完全取决于项目类型。并非在所有情况下您都是从头开始制作项目。有时，您有一些旧代码，需要调整到移动设备上。在这种情况下，您总是被迫使用桌面优先方法。在可以从头开始编写代码的情况下，建议使用移动优先方法。

## 在 HTML 中调整视口

响应式网站的一个重要元素是正确的 HTML 视口 meta 标签。视口描述应该添加在 HTML 文档的头部。它描述了网页在移动设备上的行为方式。有一堆大多数使用的视口，我们稍后会进行分析。最常用的是以下视口：

```css
<head>
    <!-- ... -->
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <!-- ... -->
</head>
```

这意味着无论何时在移动设备上打开项目，它都将具有设备的宽度，并且项目将具有等于`1`的初始比例。稍微增强的视口看起来像下面这样：

```css
<head>
    <!-- ... -->
    <meta name="viewport"content="width=device-width, initial-scale=2.0">
    <!-- ... -->
</head>
```

第一个和第二个视口之间的主要区别是最大缩放。这意味着在移动设备上双击或捏合手势后，将进行缩放，但此缩放的最大范围设置为`2`。视口的一个更安全的选项如下：

```css
<head>
    <!-- ... -->
    <meta name="viewport"content="width=device-width, initial-scale=1.0, maximum-scale=1">
    <!-- ... -->
</head>
```

为什么更安全？例如，在某些情况下，我们在内容上有一些固定的窗口，它们也不会被缩放，也不会给用户带来不好的体验：

```css
<head>
    <!-- ... -->
    <meta name="viewport"content="width=600, initial-scale=1.0">
    <!-- ... -->
</head>
```

这个`viewport`设置将缩放网站，使其表现得像在桌面上打开的网页，浏览器的宽度设置为`600`。初始比例设置如前面的例子一样，等于`1`。

## 选择正确的视口

所以问题是：推荐使用哪个`viewport`？这是一个很好的问题。最好的体验可以通过以下方式保留：

```css
<head>
    <!-- ... -->
    <meta name="viewport"content="width=device-width, initial-scale=1.0, maximum-scale=2.0">
    <!-- ... -->
</head>
```

为什么？因为我们正在根据设备的`宽度`进行缩放，而且我们不会停止页面的缩放。但最安全的选择如下：

```css
<head>
    <!-- ... -->
    <meta name="viewport"content="width=device-width, initial-scale=1.0, maximum-scale=1">
    <!-- ... -->
</head>
```

这将防止缩放，这可能会让调整变得很烦人，特别是在旧项目中，我们有老式的模态窗口类型。

## 折叠区域之上

这种方法与代码的优化密切相关。它也与网页的移动版和桌面版相关。现代网页加载了很多东西：CSS 文件、JS 文件、图片以及视频和音频等媒体文件。在这么长的队列中，你会发现当页面加载的处理时间，比如说 10 秒，你无法在所有文件加载完之前看到内容。在信息页面的情况下，你应该先看到标题和主要内容，但在这么长的队列中几乎是不可能的。

上述的折叠方法将特定的样式附件分开，描述页面上最重要的元素，比如标题、副标题和文本内容。需要将这些`style`附件分开，并将它们内联到`head`部分，例如：

```css
<head>
    <!-- ... -->
    <style>
        /* here we have a section for inline most important styles */
    </style>
    <!-- ... -->
    <link rel="stylesheet"type="text/css"href="link_to_rest_of_styles.css">
    <!-- ... -->
</head>
```

这意味着这个内联部分将首先被浏览器解析，在长时间的加载过程中，它将首先为读者准备好最重要的元素，然后再加载页面所需的其他资源。

# 媒体查询 - 你可以在哪里使用它

媒体查询是在 CSS 代码中设置的过滤器，有助于描述网站在各种显示器（屏幕、打印）上的显示。在媒体查询中，最常用的过滤器是最小/最大宽度、最小/最大高度、最小/最大像素比和最小/最大宽高比。

## 如何构建媒体查询

首先创建一个媒体查询，然后创建更复杂的过滤器是相当简单的。基本的媒体查询看起来如下：

```css
@media screen and (min-width: 640px)
  .element
    background: #000
```

编译后的 CSS：

```css
@media screen and (min-width: 640px) {
    .element {
        background: #000;
    }
}
```

通过这个媒体查询，你可以过滤出所有最小宽度为 640px 的屏幕的 CSS 声明。让我们试着让它更复杂一些，让我们尝试为特定设备创建更多的媒体查询。

## 媒体查询是如何工作的？

媒体查询是过滤器，如前所述。但让我们试着在代码和浏览器中看看。这个简单的章节将向你展示如何调整代码以适应特定的屏幕分辨率，并为创建更高级的媒体查询奠定基础：

```css
<div class="mobile_only">Mobile only</div>
<div class="tablet_only">Tablet only</div>
<div class="desktop_only">Desktop only</div>
<div class="mobile_and_tablet">Mobile and tablet</div>
<div class="tablet_and_desktop">Tablet and desktop</div>
<div class="all">All views</div>
```

现在代码看起来如下（没有任何样式）：

![媒体查询是如何工作的？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00050.jpeg)

现在我们需要做一些方法：

+   移动视图是宽度小于等于 400px 的所有分辨率

+   平板视图是宽度小于等于 700px 的所有分辨率

+   桌面视图是宽度大于 701px 的所有分辨率

现在，基于上述方法，让我们创建样式和媒体查询：

编译后的 CSS：

```css
.mobile_only,
.tablet_only,
.desktop_only,
.mobile_and_tablet,
.tablet_and_desktop {
    display: none;
}

/* Mobile only */
@media screen and (max-width: 400px) {
body {
        background: red;
    }

    .mobile_only {
        display: block;
    }
}

/* Mobile and tablet */
@media screen and (max-width: 700px) {
    .mobile_and_tablet {
        display: block;
    }
}

/* Tablet only */
@media screen and (min-width: 401px) and (max-width: 700px) {
body {
        background: blue;
    }

    .tablet_only {
        display: block;
    }
}

/* Tablet and desktop */
@media screen and (min-width: 401px) {
    .tablet_and_desktop {
        display: block;
    }
}

/* Desktop only */
@media screen and (min-width: 701px) {
body {
        background: green;
    }

    .desktop_only {
        display: block;
    }
}
```

现在让我们在宽度为 350px 的浏览器中检查一下：

![媒体查询是如何工作的？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00051.jpeg)

在上述视图中，我们可以看到所有在 CSS 文件中描述的元素，带有以下注释：

+   `/* 仅限移动设备 */`

+   `/* 移动和平板 */`

在宽度为 550px 的浏览器中的输出如下：

![媒体查询是如何工作的？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00052.jpeg)

在上述视图中，我们可以看到所有在 CSS 文件中描述的元素，带有以下注释：

+   `/* 仅限平板 */`

+   `/* 移动和平板 */`

+   `/* 平板电脑和台式机 */`

在宽度为 850px 的浏览器中的输出如下：

![媒体查询是如何工作的？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00053.jpeg)

在上述视图中，我们可以看到所有在 CSS 文件中描述的元素，带有以下注释：

+   `/* 平板和台式机 */`

+   `/* 仅限桌面 */`

前面的代码揭示了媒体查询过滤器的工作原理。你如何创建一个在特定视图中可见的代码，以及如何为真实项目创建方法？在接下来的项目中，我们将研究可以过滤的内容，因为媒体查询不仅仅与设备的宽度有关。让我们开始吧！

## 特定视图/设备的媒体查询

媒体查询可以在许多不同的情况下使用。如前所述，我们可以使用媒体查询来设置特定的最小和最大宽度：

```css
@media screen and (min-width: 640px)
@media screen and (max-width: 640px)
```

在前面的媒体查询中，第一个例子是所有最小宽度为`640`像素的分辨率，第二个例子是所有最大宽度为`640`像素的分辨率。前端开发人员处理基本桌面和像素密度更大的屏幕上的像素比。如何用 CSS 过滤它们？让我们来看看这个媒体查询：

```css
@media (-webkit-min-device-pixel-ratio: 2)
```

正如我们所知，视网膜设备的像素比等于`2`。我们还可以用范围构建更复杂的过滤器：

```css
@media screen and (min-width: 640px) and (max-width: 1024px)
```

在这种情况下，我们正在过滤所有宽度匹配从`640`像素到`1024`像素的分辨率。但是我们如何编写一个媒体查询过滤器，以匹配一些特定的设备呢？假设我们想为具有视网膜显示屏的新一代 iPad 编写代码：

```css
@media only screen 
and (min-device-width: 768px) 
and (max-device-width: 1024px) 
and (-webkit-min-device-pixel-ratio: 2)
```

正如我们所知，移动设备有两种方向：横向和纵向。那么我们如何在媒体查询中匹配这种情况呢？对于纵向视图，请使用以下内容：

```css
@media only screen 
and (min-device-width: 768px) 
and (max-device-width: 1024px) 
and (orientation: portrait) 
and (-webkit-min-device-pixel-ratio: 2)
```

而对于横向视图，请使用以下内容：

```css
@media only screen 
and (min-device-width: 768px) 
and (max-device-width: 1024px) 
and (orientation: landscape) 
and (-webkit-min-device-pixel-ratio: 1)
```

通过媒体查询，您还可以过滤打印视图。为此，您需要附加以下代码：

```css
@media print
```

## 如何为移动设备选择合适的媒体查询

为了创建良好的媒体查询过滤器并在其中设置良好的范围，您首先必须选择设备和分辨率。然后，您必须根据最流行的分辨率创建适当的媒体查询。回到过去，设备和标准分辨率的范围较小。因此，主要设置如下：

```css
@media (max-width: 768px)
  // Cover small devices
  .element
    font-size: 12px

@media (min-width: 768px) and (max-width: 1024px)
  // Cover medium devices
  .element
    font-size: 14px

@media (min-width: 1024px)
  // Cover large devices
  .element
    font-size: 16px
```

编译后的 CSS：

```css
@media (max-width: 768px) {
    .element {
        font-size: 12px;
    }
}

@media (min-width: 768px) and (max-width: 1024px) {
    .element {
        font-size: 14px;
    }
}

@media (min-width: 1024px) {
    .element {
        font-size: 16px;
    }
}
```

当然，在每个项目中，您可以为异常情况添加一些*特定*的媒体查询，这样在质量分析过程之后，CSS 文件中可能会出现更多的过滤器。

如今，一种方法是在一个媒体查询步骤中覆盖尽可能多的设备：

```css
@media only screen
  .element
    font-size: 16px
@media only screen and (max-width: 640px)
  // Cover small devices
  .element
    font-size: 12px

@media only screen and (min-width: 641px)
  // Cover devices which resolution is at minimum medium
  .element
    font-size: 14px

@media only screen and (min-width: 641px) and (max-width: 1024px)
  // Cover medium devices
  .element
    font-size: 15px

@media only screen and (min-width: 1025px)
  // Cover  devices which resolution is at minimum large
  .element
    font-size: 16px
```

编译后的 CSS：

```css
@media only screen {
    .element {
        font-size: 16px;
    }
}

@media only screen and (max-width: 640px) {
    .element {
        font-size: 12px;
    }
}

@media only screen and (min-width: 641px) {
    .element {
        font-size: 14px;
    }
}

@media only screen and (min-width: 641px) and (max-width: 1024px) {
    .element {
        font-size: 15px;
    }
}

@media only screen and (min-width: 1025px) {
    .element {
        font-size: 16px;
    }
}
```

为了更好地覆盖和更好地编写代码，让我们在这个媒体查询列表中添加一个`max-width`步骤：

```css
@media only screen and (max-width: 1024px)
    .element
        font-size: 15px
```

编译后的 CSS：

```css
@media only screen and (min-width: 1025px) {
    .element {
        font-size: 16px;
    }
}
```

这个媒体查询将一次覆盖小型和中型设备。目前，桌面网站最常见的分辨率是`1280px`。让我们将这个范围添加到媒体查询中：

```css
@media only screen and (min-width: 1025px) and (max-width: 1280px) {} 
@media only screen and (min-width: 1281px) {}
```

用于媒体查询的 SASS mixin

让我们为 mixin 创建媒体查询，这将帮助我们保持代码清晰。正如我们所知，我们必须将显示类型和断点作为参数添加进去：

```css
@mixin mq($display, $breakpoint)
@media #{$display} and (#{$breakpoint})
@content
```

现在让我们收集我们的标准断点：

```css
@mixin mq($display, $breakpoint)
  @media #{$display} and #{$breakpoint}
    @content

$mq_small_only: "(max-width: 640px)"
$mq_medium_only: "(min-width: 641px) and (max-width: 1024px)"
$mq_small_and_medium: "(max-width: 1024px)"

+mq("screen", $mq_small_only)
  .slider
    width: 100%
    height: 300px

+mq("screen", $mq_medium_only)
  .slider
    width: 100%
    height: 400px

+mq("screen", $mq_small_and_medium)
  .slider
    max-width: 1200px
    width: 100%
```

编译后的 CSS：

```css
@media screen and (max-width: 640px) {
    .slider {
        width: 100%;
        height: 300px;
    }
}

@media screen and (min-width: 641px) and (max-width: 1024px) {
    .slider {
        width: 100%;
        height: 400px;
    }
}

@media screen and (max-width: 1024px) {
    .slider {
        max-width: 1200px;
        width: 100%;
    }
}
```

前面的代码是三个步骤的选择，但您可以添加另一个作为练习，以覆盖上一节中的所有步骤。

# 用法示例-主导航

让我们想象一下，我们想解决与导航相关的经典问题。在大多数情况下，它在桌面视图中是内联的，但在移动视图中变成了元素下的列表元素。让我们从 HTML 开始：

```css
<nav class="main-navigation">
    <ul>
        <li>
            <a href="#">First element</a>
        </li>
        <li>
            <a href="#">Second element</a>
        </li>
        <li>
            <a href="#"> Third element</a>
        </li>
    </ul>
</nav>
```

在 SASS 代码中，我们将使用之前创建的 mixin 来进行媒体查询和清除浮动。以下是完整的 SASS 文件：

```css
@mixin mq($display, $breakpoint)
@media #{$display} and #{$breakpoint}
@content

$mq_small_only: "(max-width: 640px)"
$mq_medium_only: "(min-width: 641px) and (max-width: 1024px)"
$mq_small_and_medium: "(max-width: 1024px)"

=clear fix
  &:after
    content: " "
    visibility: hidden
    display: block
    height: 0
    clear: both

body
  padding: 0
  margin: 0

.main-navigation
  ul
    +clearfix /* This will prevent problems of cleared float */
    list-style: none
    padding: 0
    background: greenyellow
    border:
      bottom: 1px solid darkgreen

  li
    float: left
    display: block

  a
    padding: 10px
    width: 100%
    display: block
    background: greenyellow
    text-decoration: none
    color: darkgreen

    &:hover
      background: darkgreen
      color: greenyellow

+mq("screen", $mq_small_and_medium)
  .main-navigation
    ul
      list-style: none
      border: none

    li
      float: none
      width: 100%

    a
      border:
        bottom: 1px solid darkgreen
```

编译后的 CSS：

```css
body {
    padding: 0;
    margin: 0;
}

.main-navigation ul {
    list-style: none;
    padding: 0;
    background: greenyellow;
    border-bottom: 1px solid darkgreen;
}

.main-navigation ul:after {
    content: "";
    visibility: hidden;
    display: block;
    height: 0;
    clear: both;
}

.main-navigation li {
    float: left;
    display: block;
}

.main-navigation a {
    padding: 10px;
    width: 100%;
    display: block;
    background: greenyellow;
    text-decoration: none;
    color: darkgreen;
}

.main-navigation a:hover {
    background: darkgreen;
    color: greenyellow;
}

@media screen and (max-width: 1024px) {
    .main-navigation ul {
        list-style: none;
        border: none;
    }

    .main-navigation li {
        float: none;
        width: 100%;
    }

    .main-navigation a {
        border-bottom: 1px solid darkgreen;
    }
}
```

![用法示例-主导航](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00054.jpeg)

前面的屏幕截图是在全局 CSS 相关的桌面视图中制作的。下一个屏幕截图与`@media`屏幕和（最大宽度：`1024px`）有关。正如你所看到的，我们改变了导航的显示方式，并为触摸设备提供了更多的灵活性。导航中的较大项目更容易点击（在这个例子中，按钮更长）：

![用法示例-主导航](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prof-c3/img/00055.jpeg)

# 总结

在本章中，您学习了创建响应式网站的主要方法以及移动和桌面优先的含义。然后，我们通过响应式网站的性能基础知识扩展了知识。最后，您了解了媒体查询的基本知识以及如何创建它们以覆盖所有特定的显示类型。在下一章中，您将学习有关 CSS 代码中的图像的知识。

在下一章中，您还将学习有关 CSS 背景和可以使用的新功能的知识。我们将重复图像，裁剪图像，并将它们定位到容器中。让我们看看我们可以用背景做些什么。
