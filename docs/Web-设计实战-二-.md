# Web 设计实战（二）

> 原文：[`zh.annas-archive.org/md5/7F8B3C6FCF9A035C2A6AD7E31BDFDEBB`](https://zh.annas-archive.org/md5/7F8B3C6FCF9A035C2A6AD7E31BDFDEBB)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：使我们的网站响应

在第四章中，*响应式与自适应设计*，您学习了响应式设计和自适应设计之间的区别。前者更容易实现，后者则针对最终用户。

本章将涵盖以下内容：

+   什么是媒体查询？

+   打开浏览器检查器

+   桌面优先和移动优先之间的区别

+   jQuery 介绍

+   如何使我们的网站对每种设备和屏幕尺寸都响应

# 什么是媒体查询？

可以使用*媒体查询*来实现响应式设计。这是如何工作的？将媒体查询视为您应用于 CSS 的条件。您告诉浏览器根据设备或视口大小添加或删除某些 CSS 规则：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/429e400e-7261-464c-914b-6cdcc944a6f3.png)

要应用这些规则，我们需要使用 CSS 属性`@media`，如下所示：

```html
/* Mobile Styles */
@media only screen and (max-width: 400px) {
  body {
    background-color: #F09A9D; /* Red */
  }
} 
```

`@media only screen and (max-width: 400px)` 意味着如果屏幕/视口尺寸小于或等于 `400px`，那么我们将应用这个 CSS。

您可以向媒体添加几种不同类型的属性，并针对不同类型的设备进行定位。

例如，您可以使用以下代码专门针对 iPhone 4：

```html
@media only screen 
  and (min-device-width: 320px) 
  and (max-device-width: 480px)
  and (-webkit-min-device-pixel-ratio: 2)
  and (orientation: portrait) {

}
```

这翻译为以下内容：

```html
and (min-device-width: 320px) 
and (max-device-width: 480px)
```

上述代码意味着任何尺寸大于或等于 `320px` 且小于或等于 `480px` 的设备：

```html
and (-webkit-min-device-pixel-ratio: 2)
```

以下代码针对像素比或密度为 `2` 的任何设备：

```html
and (orientation: portrait)
```

上述代码将仅针对`纵向`方向的设备。

现在我们已经介绍了媒体查询的基础知识，让我们在项目中实践一下。

# 打开检查器

首先，为了能够测试我们网站的响应性，Chrome 中有一个非常有用的工具。要访问它，您可以转到查看 | 开发者 | 开发者工具：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/1a60e5f4-fb73-49a9-b40d-adee1c0df322.png)

要使用此工具，请单击左上角的第二个图标

现在，您可以选择任何您想要测试的设备，如下：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/58370053-48ff-475d-bbd7-2a53e5f4371d.png)

您还可以看到整个页面的代码显示在右侧：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/13208aeb-fbcf-4c26-b892-93c3c37dcb26.png)

谷歌 Chrome 检查器

这非常有用，因为它允许您在放入代码之前尝试不同的 CSS 属性，或者检查您的 CSS 是否有效。您可以快速尝试并进行调整。

# 桌面优先

根据您开始的设计过程，但一般来说，您会从桌面设计开始，然后逐渐降低到移动端。如果您从移动优先的过程开始设计，您将需要从移动端开始，然后升级到桌面端。

因此，初始 CSS 是为桌面设计的，现在我们要考虑的是要应用到 CSS 的条件。

我们想要针对的设备如下：

+   桌面（默认）

+   平板电脑（视口尺寸小于或等于 1,024px）

+   大型移动设备（视口尺寸小于或等于 768px）

+   小型移动设备（视口尺寸小于或等于 400px）

这是一个如何分隔不同断点的示例。您可以根据需要进行更改。

因此，在 CSS 中看起来是这样的：

```html
/* Tablet Styles */
@media only screen and (max-width: 1024px) {

} 

/* Large Mobile Styles */
@media only screen and (max-width: 768px) {

} 

/* Small Mobile Styles */
@media only screen and (max-width: 400px) {

} 
```

现在我们已经准备好了我们的断点，让我们开始使我们的网站响应。

# 设计菜单

在本节中，我们将看看如何在移动设备或平板电脑上隐藏桌面菜单，而在移动设备或平板电脑上显示汉堡图标：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/62d40581-5efd-43fc-b1fc-8a368200bfa1.png)

移动视图的设计

如果我们单击该图标，菜单将在右侧打开：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/d0895659-0031-43cc-ac0e-404c099c9998.png)

在移动设备上打开的菜单

为此，我们首先需要在移动版本和平板版本上隐藏菜单。

在我们的 CSS 的`header`部分末尾，添加以下代码：

```html
/* Tablet Styles */
@media only screen and (max-width: 1024px) {
  header {
    display: none;
  }
}
```

现在我们想在移动设备上显示`汉堡菜单`。我们需要在 HTML 中创建一个`div`标签，并且只在移动设备上显示它，使用 CSS：

```html
<div class="hamburger-menu">
   <img src="img/hambuger-icon.svg">
</div>    
```

我们将把这个放在我们的头部标签`</header>`的结束之前。

在 CSS 中，我们需要在桌面视图中隐藏汉堡，并且只在移动视图中显示它：

```html
.hamburger-menu {
  display: none;
}
/* Tablet Styles */
@media only screen and (max-width: 1024px) {
  header .main-nav, header .right-nav {
    display: none;
  }
  .hamburger-menu {
    display: block;
  }
}
```

让我们保存并查看：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/95e26386-0776-4e95-81b2-64c6882bcd90.jpg)

如果你想为平板视图添加一个花哨的框架，那么点击右上角的三个点，然后点击显示设备框架。

我们可以看到汉堡图标显示出来了，但我们需要正确放置它：

```html
.hamburger-menu {
  display: none;
  position: absolute;
  right: 15px;
  top: 15px;
}
```

不要忘记我们只是通过媒体查询改变`display`属性，所以我们在这里应用的规则将适用于移动版本。

现在我们必须创建另一个仅在移动版本上显示的菜单，当用户点击汉堡菜单时，整个页面将向左移动：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/ce3a3f3b-ff9d-4a71-99d6-7020410f18ff.png)

显示内容和移动导航的不同层的图表

为了能够移动整个页面，我们需要创建一个 HTML 标签并将我们的内容放在其中。我们将创建一个名为`<main>`的标签，并将我们从`header`到`footer`创建的内容放在其中。

现在，在 CSS 中，我们首先需要为我们的`main`标签添加一个新的部分：

```html
/* MAIN SECTION */

main {

}

/* END MAIN SECTION */
```

现在，为了确保这个元素将成为父元素，我们需要将这个元素设置为`position: relative;`，这样每个具有`position: absolute;`的元素现在都将与这个元素相关联：

```html
main {
  position: relative;
}
```

我们还将添加一个`background-color: white;`，以确保它具有与默认的`white`相同的背景`white`：

```html
main {
  position: relative;
  background-color: white;
}
```

现在，为了移动我们的`main`标签，我们将使用`"left:-200px"`的 CSS 属性：

```html
main {
  position: relative;
  background-color: white;
  left:-200px;
}
```

这将使我们的元素水平移动-200px，也就是向左移动 200px。现在，让我们保存并查看：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/ea90c5ac-f8a1-48e2-a95d-1d458deaac94.jpg)

主容器向左移动了 250px

对于我们的移动菜单，让我们创建另一个带有`"mobile-nav"`类的`div`，但我们将把它放在`<main>`标签之外。

```html
<div class="mobile-nav">

</div>
<main>
   <header>
    ...
```

在`.mobile-nav`中，让我们重新创建我们的`nav`（包括`.main-nav`和`.right-nav`列表）：

```html
<div class="mobile-nav">
          <ul>
            <li><a href="upcoming.html">Upcoming events</a></li>
            <li><a href="past.html">Past events</a></li>
            <li><a href="faq.html">FAQ</a></li>
            <li><a href="about.html">About us</a></li>
            <li><a href="blog.html">Blog</a></li>
            <li><a href="contact.html">Contact</a></li>
            <li><a href="login.html">Login</a></li>
            <li><a href="#"><iframe src="img/like.php?href=http%3A%2F%2Ffacebook.com%2Fphilippehongcreative&width=51&layout=button&action=like&size=small&show_faces=false&share=false&height=65&appId=235448876515718" width="51" height="20" style="border:none;overflow:hidden" scrolling="no" frameborder="0" allowTransparency="true"></iframe></a></li>
          </ul>
        </div>
```

在我们的 CSS 文件中，让我们确保在桌面视图中隐藏我们的`.mobile-nav`：

```html
/* MOBILE MAVIGATION */

.mobile-nav {
  display: none;
}

/* Tablet Styles */
@media only screen and (max-width: 1024px) {
  .mobile-nav {
    display: block;
  }
}

/* END MOBILE NAVIGATION */
```

让我们添加一些定制：

```html
.mobile-nav {
  display: none;
  position: fixed;
  background-color: #1F1F1F;
  width: 200px;
  height: 100%;
  right: 0;
  top: 0;
}
```

+   `position: fixed;`：因为我们希望菜单在我们移动`<main>`容器时保持固定在后面

+   `background-color: #1F1F1F;`：从设计中选择的颜色

+   `width: 200px;`和`height: 100%;`：因为我们希望尺寸略小于移动设备的最小宽度，即 320px。200px 看起来不错，当然，我们希望高度为 100%，以垂直占据整个空间

+   `right: 0;`和`top: 0;`：指定从视口的位置

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/a06591fd-2bdb-47f5-bc4c-bc380f1cce43.jpg)

iPad 视图（1,024px）

让我们完成菜单的定制：

```html
.mobile-nav ul {
  margin: 0;
  padding: 25px;
}

.mobile-nav ul li {
  list-style-type: none;
  margin-bottom: 10px;
}

.mobile-nav ul li a {
  color: white;
  text-decoration: none;
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 200;
  font-size: 20px;
  letter-spacing: 4px;
}
```

让我们保存并查看它的样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/3645ea8e-b991-4211-a1aa-6b809153f799.jpg)

iPad 视图（1,024px）

现在让我们将`<main>`容器返回到初始位置：

```html
main {
  position: relative;
  background-color: white;
  left: 0px;
}
```

这就是乐趣开始的时候；我们将在 JS 中创建一个函数，当用户点击汉堡菜单时，会使`<main>`容器动画化。

为了实现这一点，当用户点击汉堡菜单时，我们将向`<main>`标签添加一个类。这个类叫做`active`，将具有以下值：

```html
main.active {
  left: -200px;
}
```

因此，如果我们向`<main>`元素添加一个`active`类，容器将按我们指定的方式向左移动。

现在让我们把它移除，开始 JS。

为了启动任何项目，对于任何初学者来说，最好的方法是从 jQuery 开始。什么是 jQuery？

# 什么是 jQuery？

jQuery 是一个快速而简洁的 JavaScript 库，简化了 HTML 文档的遍历、事件处理、动画和 Ajax 交互，用于快速的 Web 开发。

- jQuery 官方网站

jQuery 本身不是一种语言；它是一个帮助更轻松、更高效地编写 JavaScript 的 JavaScript 框架。jQuery 的优点如下：

+   它简化了 JavaScript 语法

+   它已经解决了 JavaScript 在每个 Web 浏览器之间将会遇到的大部分问题

+   它使部署在所有平台上更安全

+   对于初学者来说很容易理解

+   它有许多库和一个庞大的社区

要使用 jQuery，我们只需要将脚本链接到我们的 HTML，但是幸运的是，使用 HTML 样板，jQuery 已经集成了。以下是在我们的 HTML 中调用 URL 并下载 jQuery 文件的行：

```html
<script src="img/jquery-3.2.1.min.js" integrity="sha256-hwg4gsxgFZhOsEEamdOYGBf13FyQuiTwlAQgxVSNgt4=" crossorigin="anonymous"></script>
```

# jQuery 语法

我们现在来看一下 jQuery 语法。以下语法是一个改变 body 背景的 jQuery 和 JavaScript 代码的示例：

```html
jQuery
$('body').css('background', '#fff'); 

Javascript
function changeBackgroundColor(color) {
   document.body.style.background = color;
}
onload="changeBackgroundColor('white');"
```

您可以看到它们之间的很大区别。

jQuery 的基本语法非常简单：

```html
$(selector).action();
```

1.  `$`符号开始任何 jQuery 操作

1.  `(selector)`用于查询(或查找)HTML 元素，通过 ID 或类，就像在 CSS 中一样(`#`或`.`)

1.  `action()`是要在元素上执行的操作

1.  分号(`;`)用于关闭操作

例如，要在 jQuery 中添加一个类，我们可以使用 jQuery 操作`.addClass`：

```html
$('main').addClass('active'); 
```

要实现这一点，我们需要事先创建一个 JS 文件，并在其中编写所有我们的 JS 代码。但是，我们可以使用 HTML 样板中的一个创建的位于我们的`js`文件夹中的`main.js`。

要调用 jQuery 并说我们需要执行这些操作，我们需要添加以下代码：

```html
$(document).ready(function(){

   // jQuery methods go here...

});
```

这是为了防止在文档完成加载之前运行任何 jQuery 代码。

现在，为了测试我们的 jQuery 是否正确地与我们的 HTML 文件链接，我们可以做的一个快速的事情是在页面加载时显示一个警报。

为此，我们可以使用 JavaScript 的`alert`操作：

```html
$(document).ready(function(){

  alert("Hello world");

});
```

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/c13a08d6-1d63-4f9c-89be-3165bf3c1d74.png)

我们的警报操作正常工作

我们可以删除`alert`操作并添加我们之前创建的小代码：

```html
$(document).ready(function(){

  $('main').addClass('active'); 

});
```

让我们保存并检查一切是否正常工作：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/e8a538fe-7a54-44a6-b60d-7ad0318c6ee6.png)

这显示了检查器上的类

确实，我们从一开始就有我们的类`active`。

将此操作更改为用户单击菜单时，我们需要使用 jQuery 操作`click`：

```html
$('.hamburger-menu').click();
```

我们可以定义这一点，但这将不起作用，因为我们需要在单击图标时定义操作。为此，我们需要在内部设置一个`function`。函数是一组您可以设置的操作，后面跟着一个开放和一个关闭的花括号：

```html
$('.hamburger-menu').click(function(){

}); 
```

现在，在`function`内部，我们将添加`addClass`操作：

```html
$('.hamburger-menu').click(function(){
    $('main').addClass('active');
  });
```

现在保存您的 JS 文件并刷新页面。当您单击`hamburger-menu`时，容器会向左移动。干得好！我们迈出了第一步。但是，现在我们想关闭菜单并将容器移回。

我们可以添加这个：

```html
$('main').click(function(){
    $('main').removeClass('active');
});
```

但是，这不起作用，因为它总是尝试删除类`active`，因为`<main>`是`.hamburger-menu`的父级。为了解决这个问题，我们需要告诉脚本在单击触发器时停止点击`event`冒泡。这意味着它永远不会达到`<main>`级别，并且不会触发`.removeClass()`方法。为此，我们需要添加一种跟踪点击事件并告诉它不要冒泡的方法：

```html
$('.hamburger-menu').click(function(event){
    event.stopPropagation();
    $('main').addClass('active');
  });
```

您现在可以检查您的菜单。它按预期正常工作，但当您单击`.hamburger-menu`本身时，它不会执行任何操作。这是因为我们没有告诉它要执行任何操作。

当我们单击汉堡菜单时，我们需要使`<main>`返回到其初始位置。但是，现在，我们只设置了将类`active`添加到`<main>`。

我们需要配置一种方法，只有在`<main>`上有`active`时才能移除该类。为此，我们需要应用一个条件。在 jQuery 中应用条件，我们只需要使用条件`if`和`else`在`function`内部：

```html
$('.hamburger-menu').click(function(event){
    event.stopPropagation();
    if (condition){

    } else {

    }
  });
```

因此，我们想要的操作如下：

+   如果`<main>`有类`active`，则删除类`active`

+   如果`<main>`没有类`active`，则添加类`active`

要检查元素是否有类，我们可以使用 jQuery 操作`hasClass`，如下所示：

```html
$('.hamburger-menu').click(function(event){
    event.stopPropagation();
    if ($('main').hasClass('active')){
      $('main').removeClass('active');
    } else {
      $('main').addClass('active');
    }
  });
```

现在保存您的 JS 文档。我们的 JS 完美地工作了，但是如果您有完美主义的倾向，添加一些动画不会伤害您。我们可以为容器添加一些过渡效果，以使动画更加流畅：

```html
main {
  position: relative;
  background-color: white;
  left: 0px;
  transition: all 0.2s ease-in-out; 
}
```

过渡效果只会作用于移动的元素，这种情况下是`<main>`元素。

我们的响应式终于完成了；让我们转移到主标题部分。

# 使主标题部分具有响应性

让我们来检查一下目前我们的主标题是如何响应的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/598bc960-c943-4dcb-a2b2-dd5b955129b4.png)

iPad 视图和 iPhone 8 视图

正如我们所看到的，iPad 视图中没有什么需要改变；然而，在 iPhone 视图中，缺少填充，标题似乎有点太大。

我认为可以在不添加太多代码的情况下解决这个问题，就是给每个部分实现的`container`添加一些填充：

```html
.container {
  max-width: 940px;
  margin: 0 auto;
}

/* Tablet Styles */
@media only screen and (max-width: 1024px) {
  .container {
    padding: 0px 15px;
  }
}
```

我们将从平板电脑断点添加一些填充，这样它将影响所有更低的断点。

现在让我们修复我们的标题。这将是直接的；我们只需要找到我们的`.hero-title`类并添加一些媒体查询：

```html
/* Large Mobile Styles */
@media only screen and (max-width: 768px) {
  .hero-text .hero-title {
    font-size: 90px;
  }
}
```

就是这样！您也可以根据需要随时更改值。

# 使博客部分具有响应性

这个博客部分是基于三列网格的，它在台式机和平板电脑上运行得很好；然而，在手机上，它缩小得有点太多，所以我们需要将三列改为两列（对于小手机，一列）：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/2759fdf3-460c-43b1-8639-b5ac349425bc.png)

博客部分的移动视图

要改变列的宽度，让我们转到我们创建的`.blog-post`类，并在大手机断点上将宽度值改为`50%`：

```html
.blog-post {
  width: 33.33%;
  padding: 0 5px;
  box-sizing: border-box;
  margin-bottom: 30px;
}

/* Large Mobile Styles */
@media only screen and (max-width: 768px) {
  .blog-post {
    width: 50%;
  }
}

/* Small Mobile Styles */
@media only screen and (max-width: 400px) {
  .blog-post {
    width: 100%;
  }
}
```

这将确保内容无论出现在哪种设备上都能够被读取。

此外，标题也显得有点太大。在移动视图中，我们可以将`font-size`减小`40px`：

```html
#blog h2 {
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 200;
  font-size: 60px;
}

/* Small Mobile Styles */
@media only screen and (max-width: 400px) {
  #blog h2 {
    font-size: 40px;
  }
}
```

前面的代码将如下所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/f41e1ce7-c3b9-4ed3-808b-035a41972dfa.png)

博客部分的不同断点的视图

# 使关于我们部分具有响应性

关于我们部分在 iPad 视图上看起来很好，但在手机上开始变得有点挤：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/174affa0-dd36-4507-adfc-5ef6483b410f.jpg)

关于我们部分的移动视图

为了解决这个问题，我们需要在手机断点上将宽度值改为`100%`：

```html
.about-us-title {
  width: 50%;
}

/* Small Mobile Styles */
@media only screen and (max-width: 400px) {
  .about-us-title {
    width: 100%;
  }
}

.about-us-desc {
  width: 50%;
}

/* Small Mobile Styles */
@media only screen and (max-width: 400px) {
  .about-us-desc {
    width: 100%;
  }
}
```

此外，我们将通过添加 CSS 属性`flex-orientation: column`来改变 flexbox 的方向。默认情况下，这个值是`row`，但您也可以通过`row-reverse`值来改变顺序，对于`column`值也是一样，使用`column-reverse`：

```html
/* Small Mobile Styles */
@media only screen and (max-width: 400px) {
  #about-us .container {
    flex-direction: column;
  }
}
```

设计看起来不错，但文本与标题仍然有点太近；让我们通过添加一些边距来解决这个问题：

```html
/* Small Mobile Styles */
@media only screen and (max-width: 400px) {
  .about-us-desc {
    width: 100%;
    margin-top: 50px;
  }
}
```

现在，保存并检查：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/acaa6de0-be15-449c-bb1a-461e97d83b42.jpg)

关于我们的响应式布局

# 使 footer 部分具有响应性

最后一部分是`footer`，对于大多数网站来说，它只是一个链接列表。它通常显示为一个简单的垂直列表；它不像我们创建的标题菜单那样复杂。

首先，我们需要移除在`footer`中设置的高度值；为此，我们可以简单地用`auto`值替换它：

```html
/* Small Mobile Styles */
@media only screen and (max-width: 768px) {
  footer .container {
    height: auto;
  }
}
```

我们还需要通过设置 flexbox 的方向来垂直显示链接，就像我们之前看到的那样：

```html
/* Small Mobile Styles */
@media only screen and (max-width: 768px) {
  footer .container {
    flex-direction: column;
    height: auto;
  }
}
```

下一步将是改变我们在`<li>`上设置的显示值：

```html
footer .main-nav li, footer .right-nav li {
  list-style-type: none;
  display: inline-block;
}

/* Small Mobile Styles */
@media only screen and (max-width: 768px) {
  footer .main-nav li, footer .right-nav li {
    display: block;
  }
}
```

此外，我们需要移除在`<a>`标签上设置的填充：

```html
/* Small Mobile Styles */
@media only screen and (max-width: 768px) {
  footer .main-nav li a, footer .right-nav li a {
    padding: 0px;
  }
}
```

最后，我们需要从`<ul>`中移除默认的填充：

```html
/* Small Mobile Styles */
@media only screen and (max-width: 768px) {
  footer .container ul {
    padding: 0;
  }
}
```

现在我们都完成了。

# 总结

那是一个非常紧凑的章节，我希望你仍然能够理解！现在我们已经介绍了如何使用媒体查询使我们的网站具有响应性，还有一个快速介绍 jQuery，我们现在可以继续下一章了。在下一章中，我们将深入研究 CSS 和 jQuery，通过添加一些交互和动态内容来丰富您的网站。我们将讨论 CSS 中的伪类，如何在网站上使用插件，以及如何通过 API 收集信息。我迫不及待要向你展示这些！


# 第九章：添加交互和动态内容

我发现网站构建的这一部分是最有趣和令人愉快的。添加交互和动态内容将为我们的网站带来生机，并为其增添个人风格。

在本章中，我们将：

+   首先学习 CSS 中**伪类**的基础知识，以及一些悬停和激活状态的示例

+   学习如何从头开始创建 CSS 动画

+   通过连接到 API 并导入一些内容来添加一些动态内容以在我们的网站上显示

让我们开始吧！

# CSS 伪类

伪类用于定义元素的特殊状态。例如，当您悬停或单击按钮时，可以激活一个状态。

我们将学习两个简单的伪类，最常见的伪类。当您知道如何使用它们时，您可以轻松地添加和激活其他伪类：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/86da0197-77e2-406d-9e26-e0d8fed74f45.png)

不同的伪类

这两个伪类是`hover`和`active`。当您用鼠标悬停在元素上时，将使用`hover`状态。这对于显示元素是可点击的很有用。另一方面，当您单击元素时，将使用`active`状态。

要使用这些伪类，您只需用冒号`:`调用它们：

```html
.element:hover {
    // Display something
}

.element:active {
    // Display something
}

```

对于第一个示例，当悬停在菜单中的链接上时，我们将添加一些样式。我们希望在悬停时为链接添加下划线。为了做到这一点，最好能够轻松地用 CSS 来定位每一个`<a>`。但是，如果我们查看我们的 HTML，我们会发现每个导航都有许多不同的类。我们要做的是为每个`nav`添加一个共同的类，这样我们就可以轻松地用 CSS 来调用它。

我们在标题和页脚上有类`.main-nav`和`.right-nav`。我们要做的是为这些类中的每一个添加一个共同的类`.nav`：

```html
<ul class="nav main-nav">
              <li><a href="upcoming.html">Upcoming events</a></li>
              <li><a href="past.html">Past events</a></li>
              <li><a href="faq.html">FAQ</a></li>
              <li><a href="about.html">About us</a></li>
              <li><a href="blog.html">Blog</a></li>
              <li><a href="contact.html">Contact</a></li>
            </ul>
            <ul class="nav right-nav">
              <li><a href="login.html">Login</a></li>
              <li><a href="#"><iframe src="img/like.php?href=http%3A%2F%2Ffacebook.com%2Fphilippehongcreative&width=51&layout=button&action=like&size=small&show_faces=false&share=false&height=65&appId=235448876515718" width="51" height="20" style="border:none;overflow:hidden" scrolling="no" frameborder="0" allowTransparency="true"></iframe></a></li>
            </ul>
```

现在，我们必须定位`nav`内的链接。链接是元素`<a>`，正如我们之前所看到的。为了定位它，我们将在 CSS 中调用如下：

```html
.nav li a {
  // CSS
}
```

这将定位每个`.nav`的每个`.li`的每个子元素中的每个`<a>`。

让我们添加伪类`:hover`：

```html
.nav li a:hover {
  // CSS
}
```

要在链接下方添加下划线，我们可以使用 CSS 属性`text-decoration:underline;`：

```html
.nav li a:hover {
  text-decoration: underline;
}
```

现在让我们也为按钮添加一些样式。

对于每个按钮，我们都有类`.btn-primary`，所以，与之前的过程相同，我们将添加伪类`hover`：

```html
.btn-primary:hover {
  background: #A3171B;
}
```

我们在这里做的是在悬停在按钮上时改变按钮的背景颜色。现在让我们添加一个`active`状态：

```html
.btn-primary:active {
  box-shadow: inset 0px 8px 4px rgba(0, 0, 0, 0.25);
}
```

这将在单击按钮时向按钮添加内阴影。

为了增加一些额外的效果，我们可以添加一个`transition`来使动作更加平滑。不要忘记，`transition`必须添加在正常状态下，而不是在伪类上：

```html
.btn-primary {
  display: inline-block;
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 400;
  font-size: 18px;
  letter-spacing: 4.5px;
  background: #BF0000;
  color: white;
  padding: 12px 22px;
  border: none;
  outline: none;
  transition: all 0.3s ease;
}
```

大功告成！相当容易。CSS 中有很多伪类。我们将继续学习更多，但您现在可以尝试一下。以下是 CSS 中的伪类列表：[`www.w3schools.com/css/css_pseudo_classes.asp`](https://www.w3schools.com/css/css_pseudo_classes.asp)。

下一步是构建一个固定导航！我们将结合一些 jQuery 和 CSS 来构建一个导航，当用户滚动页面时，它将固定在顶部。令人兴奋的时刻！

# 固定导航

我们想要做的是在滚动到博客部分时使导航固定在顶部，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/b28f0318-d69f-4438-a1a8-666bd83e7478.png)

我们要构建的固定导航。

为了实现这一点，我们将在标题上添加一个额外的类。这个额外的类将使导航固定在顶部，并使导航背景变暗。让我们首先创建这个额外的类：

```html
header.sticky {

} 
```

我们需要小心，因为我们没有用空格分隔类，这意味着当标题也有类`sticky`时。

对于这个类，我们将添加以下属性：

```html
header.sticky {
  position: fixed;
  top: 0;
  background-color: #212121;
  background-image: none;
}
```

让我们来分解一下：

+   我们使用`position: fixed;`，因为我们希望使导航固定在顶部。`position: fixed`将使元素相对于浏览器窗口定位。

+   `top: 0;`告诉我们它会固定在顶部。

+   `background-color:` 设置了一个纯色背景。

+   `background-image: none;`移除了渐变。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/67776c8d-fb7a-41ee-b957-0ecda1ee39d5.png)

博客部分的粘性页眉

我们有我们的 CSS 类`.sticky`准备就绪。现在我们需要创建我们的 jQuery 函数来实现这一点。

# JS 插件：Waypoints

我们将使用一个插件，当滚动到一个元素时触发一个动作。该插件称为*Waypoints*，可以从此链接下载：[`imakewebthings.com/waypoints/`](http://imakewebthings.com/waypoints/)：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/328c157e-24c0-4de0-ba00-c3ced86c96de.png)

Waypoints 网站。

只需点击“下载”按钮即可下载文件。在您下载的文件中，只有一个文件是必需的。转到`lib`文件夹，找到`jquery.waypoints.min`。复制此文件并粘贴到我们的`Web Project`文件夹中，具体来说是在我们的`js` | `vendor`文件夹中。

粘贴后，我们需要将其链接到我们的 HTML 页面。为此，请转到我们的 HTML 文件，位于结束标签`</body>`之前。您会看到一堆脚本已经链接到我们的 jQuery 文件之前。在最后一个文件`main.js`之前，只需添加以下内容：

```html
<script src="img/jquery.waypoints.min.js"></script>
```

`main.js`应该是列表中的最后一个文件，因为它包含了所有我们个人的 JS 函数，并且需要在浏览器最后读取。

每个插件都有不同的使用方式。最好的方法是阅读插件作者提供的文档。在这里，我将向您解释使用此插件的最简单方法。

要使用`.waypoint`与 jQuery，我们可以使用以下方式调用它：

```html
$('elementToTrigger').waypoint(function(direction){
    /* JS code */
});
```

以下是一些解释：

+   `elementToTrigger`将是我们希望插件监视并在用户滚动通过该元素时触发动作的元素。在这种情况下，它将是`#blog`。

+   `direction`：此参数将用于检测用户是向下滚动还是向上滚动页面。

让我们转到我们的`main.js`并创建我们自己的`JS 代码`：

```html
$('#blog').waypoint(function(direction) {

  });
```

现在我们想要的是，当用户向下滚动并滚过博客部分时执行一个动作，但当用户向上滚动并离开博客部分时执行另一个动作。

为了做到这一点，我们需要使用一个条件，就像我们之前看到的那样：

```html
$('#blog').waypoint(function(direction) {
    if (direction == 'down') {

    } else {

    }
  });
```

`direction == 'down'`表示滚动的方向等于`down`。

现在我们要做的是在用户向下滚动并经过博客部分时添加类`sticky`，并在后者离开时删除相同的类：

```html
$('#blog').waypoint(function(direction) {
    if (direction == 'down') {
      $('header').addClass('sticky');
    } else {
      $('header').removeClass('sticky');
    }
  });
```

让我们保存并看看它是如何工作的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/8529c335-dcb1-4bb9-96fc-7ba7885837ea.png)

我们的粘性页眉。

它工作得很好，但是页眉会立即出现，没有任何动画。让我们尝试使其更加流畅。为了添加一些过渡效果，在这个例子中，我们将使用 CSS 动画。

# CSS 动画

CSS 动画允许创建动画而无需 JS 或 Flash，具有关键帧和每个 CSS 属性。它比简单的过渡提供了更多的优势。

要创建 CSS 动画，您需要创建一个关键帧：

```html
/* The animation code */
@keyframes example {
    from {background-color: red;}
    to {background-color: yellow;}
}
```

`from`表示动画开始时，而`to`表示动画结束时。

您还可以通过设置百分比来更精确地设置时间段：

```html
/* The animation code */
@keyframes example {
    0% {background-color: red;}
    25% {background-color: yellow;}
    50% {background-color: blue;}
    100% {background-color: green;}
}
```

要触发动画，您需要在具有 CSS 属性的特定 div 中调用它：

```html
animation-name: example;
animation-duration: 4s;
```

对于我们的页眉导航，关键帧将是：

```html
/* The animation code */
@keyframes sticky-animation {
    from {transform: translateY(-90px);}
    to {transform: translateY(0px);}
}
```

`transform:` 是 CSS 中的一种新的位置类型，允许您在 2D 或 3D 环境中移动元素。使用`translateY`，我们在*Y 轴*上移动元素。此外，我们将关键帧命名为`sticky-animation`：

```html
header.sticky {
  position: fixed;
  top: 0;
  background-color: #212121;
  background-image: none;
  animation-name: sticky-animation;
 animation-duration: 0.3s;
}
```

最后一部分将是在类`.sticky`中调用动画，持续时间为`0.3s`。

我们现在有一个完美运行的粘性导航，带有一个很酷的动画！

# 添加一个动态的 Instagram 动态

最终目标是能够通过连接到 Instagram API 并从中提取信息来实现自己的 Instagram 动态。

从设计的角度来看，我们希望在页脚之后展示我们最新的 Instagram 照片动态，当您将鼠标悬停在上面时，会有一个不透明度的悬停效果。

它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/111a176c-e0b0-4f01-8413-308386d17435.png)

我们的 Instagram 供稿的最终设计

为了实现这一点，首先我们需要有一个 Instagram 账户。如果你已经有一个，你可以使用你自己的。否则，我已经为这个练习创建了一个账户：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/103d30e4-70b8-4740-9611-7a8a0c205485.png)

我们很棒的 Instagram 供稿

# 安装 Instafeed.js

我之前上传了一些赛车的图片。下一步是安装一个名为`Instafeed.js`的插件。让我们去网站下载它：[`instafeedjs.com/`](http://instafeedjs.com/):

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/69057812-1aea-4399-8528-ebb349eb1390.png)

Instafeed.js 主页

右键点击下载，然后点击另存为....将文件放在我们`Web 项目`中`js`文件夹中的`vendor`文件夹中。

对于每个插件，安装过程每次都相当相似。所有的安装过程通常都在网站上详细说明。让我们来看看 Instafeed 的文档。

设置`Instafeed.js`非常简单。只需下载脚本并将其包含在 HTML 中：

```html
<script type="text/javascript" src="img/instafeed.min.js"></script>
```

首先，我们需要调用最初放在我们的`vendor`文件夹中的`js`文件：

```html
<script src="img/modernizr-3.5.0.min.js"></script>
<script src="img/jquery-3.2.1.min.js" integrity="sha256-hwg4gsxgFZhOsEEamdOYGBf13FyQuiTwlAQgxVSNgt4=" crossorigin="anonymous"></script>
<script>window.jQuery || document.write('<script src="img/jquery-3.2.1.min.js"><\/script>')</script>
<script src="img/jquery.waypoints.min.js"></script>
<script src="img/instafeed.min.js"></script>
<script src="img/plugins.js"></script>
<script src="img/main.js"></script>
```

将其放在我们之前安装的 Waypoints 插件之后。

现在，如果我们仔细查看文档，我们可以找到我们需要的部分。

# 从你的用户账户获取图片

要从你的账户中获取特定的图片，设置`get`和`userId`选项：

```html
<script type="text/javascript">
    var userFeed = new Instafeed({
        get: 'user',
        userId: 'YOUR_USER_ID',
        accessToken: 'YOUR_ACCESS_TOKEN'
    });
    userFeed.run();
</script>
```

下一步是找到 userID 和 TokenAccess。如果你不想创建 Instagram 账户，想要使用我之前创建的账户，你可以直接转到标题为显示供稿的部分。

# 查找我们的 userID 和 TokenAccess

我们需要找到的信息是`userID`和`accessToken`。要获得`userID`，我们需要我们的 Instagram 用户名。Instagram 并没有真的让我们很容易地找到我们的`userID`。幸运的是，有很多人创建了一个简单的方法来找到它。你可以很容易地通过谷歌搜索*如何找到 Instagram userID*来找到一个方法，但我们会直奔主题。只需转到这个网站[`codeofaninja.com/tools/find-instagram-user-id`](https://codeofaninja.com/tools/find-instagram-user-id)并填写你的 Instagram 用户名：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/dd4522c2-2b9a-4fd7-9b3f-1487c63fbd57.png)

查找 Instagram 用户 ID 网站

点击查找 Instagram ID 后，你会得到类似这样的东西，带有你的`User ID`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/63341f47-27a1-457a-b4a0-a0e75dcfd810.png)

我们的 userID

现在让我们转到我们的`main.js`并复制/粘贴`instafeedjs`文档中显示的代码示例。在我们的`Sticky Nav`代码之后，粘贴代码：

```html
// INSTAGRAM

    var userFeed = new Instafeed({
        get: 'user',
        userId: 'YOUR_USER_ID',
        accessToken: 'YOUR_ACCESS_TOKEN'
    });
    userFeed.run();
```

只需复制并粘贴我们从网站上得到的`userID`，替换`'YOUR_USER_ID'`：

```html
// INSTAGRAM

    var userFeed = new Instafeed({
        get: 'user',
        userId: '7149634230',
        accessToken: 'YOUR_ACCESS_TOKEN'
    });
    userFeed.run();
```

还没有完成；我们仍然需要我们的访问令牌。这会有点复杂。

# 获取我们的访问令牌

Instagram 并没有真的让我们很容易地找到访问令牌。通常，生成我们的访问令牌需要相当长的时间，但我们将使用一个工具来帮助我们获得它。让我们前往[ http://instagram.pixelunion.net/ ](http://instagram.pixelunion.net/)并点击生成访问令牌。

这个网站将为我们生成一个令牌访问，我们唯一需要的是授权网站访问我们的账户：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/1baba778-4ddc-4eed-8c19-3f2eb1bdc5c8.png)

Pixel Union 网站

点击生成令牌访问；它应该将你引导到 Instagram 的*授权*页面：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/9aa1cc17-8077-40e1-bf09-63719a929924.png)

Instagram 授权页面

完成后，你可以复制粘贴他们提供的代码：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/2e518079-ff7c-4f09-b513-e0d55640ef05.png)

Pixel Union 访问令牌代码

让我们复制/粘贴最后一块拼图到我们的`main.js`代码中：

```html
// INSTAGRAM

    var userFeed = new Instafeed({
        get: 'user',
        userId: '7149634230',
        accessToken: '7149634230.1677ed0.45cf9bad017c431ba5365cc847977db7',
    });
    userFeed.run();
```

保存`main.js`。下一步是用我们的 Instagram 供稿的照片填充 HTML。

# 显示供稿

Instafeed 插件是如何工作来显示我们的供稿的？它会寻找`<div id="instafeed"></div>`并用链接的缩略图填充它。

让我们转到我们的 HTML 文件的末尾，在我们的`<footer>`标签之后，添加`<div id="instafeed"></div>`：

```html
<footer>
            <div class="container">
              <a class="logo" href="/"><img src="img/logo-footer.png" srcset="img/logo-footer.png 1x, img/logo-footer@2x.png 2x"></a>
              <ul class="nav main-nav">
                <li><a href="upcoming.html">Upcoming events</a></li>
                <li><a href="past.html">Past events</a></li>
                <li><a href="faq.html">FAQ</a></li>
                <li><a href="about.html">About us</a></li>
                <li><a href="blog.html">Blog</a></li>
                <li><a href="contact.html">Contact</a></li>
              </ul>
              <ul class="nav right-nav">
                <li><a href="login.html">Login</a></li>
                <li><a href="#"><iframe src="img/like.php?href=http%3A%2F%2Ffacebook.com%2Fphilippehongcreative&width=51&layout=button&action=like&size=small&show_faces=false&share=false&height=65&appId=235448876515718" width="51" height="20" style="border:none;overflow:hidden" scrolling="no" frameborder="0" allowTransparency="true"></iframe></a></li>
              </ul>
            </div>
          </footer>

          <div id="instafeed"></div>
```

让我们保存并看看它的样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/5d38ae13-b37a-4adb-8f9b-336775bb1c74.png)

我们的 Instagram feed 确实出现了，但我们不能就这样离开它。让我们自定义我们的 feed 并添加一些 CSS 使其漂亮。

我们要做的第一件事是从我们的 feed 中获取更大的图片。默认情况下，Instafeed 从 Instagram 获取缩略图的最小尺寸。要获取更大的缩略图，我们可以阅读文档，并找到以下信息：

在 Instafeed 提供的标准选项中，我们可以看到我们可以使用`resolution`属性从缩略图中选择三种分辨率类型：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/f95961e0-e496-4a84-90e7-cfb10813641b.png)

Instafeed 文档。

让我们选择最大的那个。要添加此选项，我们只需要在我们的 JavaScript 函数中添加一个属性：

```html
// INSTAGRAM

    var userFeed = new Instafeed({
        get: 'user',
        userId: '7149634230',
        accessToken: '7149634230.1677ed0.45cf9bad017c431ba5365cc847977db7',
        resolution: 'standard_resolution'
    });
    userFeed.run();
```

因此，在`accessToken`之后，我们可以添加`resolution`属性。确保在`accessToken`属性的末尾添加逗号，以表明这不是最后一个属性。最后一个属性在末尾不需要逗号。

保存并查看我们有什么：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/53822b42-389d-4e7c-a62e-d13369bc3b69.png)

网站工作正在进行中

很好，现在它需要一些 CSS 来使其漂亮。在转到 CSS 之前，我们需要检查 Instafeed 为我们生成了什么 HTML，以便我们能够在 CSS 中调用它。如果您记得，我们可以在 Google Chrome 中检查元素的 HTML。我们只需右键单击它，然后单击检查：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/716951d8-a88f-4fda-a829-ca8d1847ba7a.png)

我们的 Google Chrome 检查器

我们可以看到 Instafeed 生成了一个带有`<img>`的`<a>`标签。非常简单直接。

知道了这一点，让我们去我们的`styles.css`文件，并在我们的`footer`部分之后写入：

```html
/* INSTAFEED */

#instafeed {
  width: 100%;
  display: flex;
  justify-content: center;
  overflow: hidden;
  background: black;
}

#instafeed a {
  flex-grow: 1;
}
```

为了解释，我们使用：

+   `width: 100%;`因为#instafeed 是包含所有内容的容器。我们希望它占满整个宽度。

+   `display: flex;`因为我们希望水平并排显示缩略图。

+   `justify-content: center;`将内容放置在中心。

+   `overflow: hidden;`因为我们不希望页面水平扩展。

+   `background: black;`因为默认情况下背景是白色的。

最后，但同样重要的是：

+   `flex-grow: 1;`：如果所有项目的`flex-grow`都设置为`1`，则`container`中的剩余空间将均匀分配给所有子项目。如果其中一个子项目的值为 2 或更高，则剩余空间或更多空间将占用其他空间的两倍。

让我们看看现在的样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/0ab28e1b-91d8-460a-b17e-3cbef084e816.png)

网站工作正在进行中

现在，最后一部分是在悬停时添加不透明度效果。我们将使用我们之前学到的不透明度和伪类`:hover`来进行操作：

```html
#instafeed a {
  flex-grow: 1;
  opacity: 0.3;
}

#instafeed a:hover {
  opacity: 1;
}
```

同样，您只需要在伪类中添加您想要更改的值；在这里，它是不透明度。

让我们也添加一些`transition`：

```html
#instafeed a {
  flex-grow: 1;
  opacity: 0.3;
  transition: opacity 0.3 ease;
}
```

让我们保存并查看：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/6e50d18a-46a5-42a1-910d-5ce37ba55f3a.png)

网站工作正在进行中

很好，到目前为止我们做得很好。但是如果您像我一样是一个完美主义者，您会注意到在手机和平板电脑上，图像相当大。让我们添加一些快速响应式 CSS，然后我们就可以结束了：

```html
/* Tablet Styles */
@media only screen and (max-width: 1024px) {
  #instafeed a img {
    max-width: 300px;
  }
}

/* Large Mobile Styles */
@media only screen and (max-width: 768px) {
  #instafeed a img {
    max-width: 200px;
  }
}

/* Small Mobile Styles */
@media only screen and (max-width: 400px) {
  #instafeed a img {
    max-width: 100px;
  }
}

```

我在这里做的是在每个断点上更改图像大小：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/066c4830-e2c7-4cf8-8bdf-7b9df1898300.png)

平板电脑和手机视图中的 Instagram Feed

我们现在已经完成了网站的交互和动态内容。

# 总结

显然，您可以在您的网站上做很多事情和添加很多东西。这只是一个可以非常快速实现的小预览。再次强调，您的想象力和决心将是唯一的限制。这是我们在本章中涵盖的内容：

我们已经学习了 CSS 伪类以及它如何帮助不同的动画。我们已经学会了如何使用 CSS 的`@keyframe`来创建动画。我们现在可以用 JQuery 来定位元素并为其添加不同的功能。我们已经学会了如何连接到 API 并使用插件显示信息。

本章内容非常精彩！在下一章中，我们将学习如何优化我们的网站并发布它！


# 第十章：优化和发布我们的网站

欢迎来到创建我们网站的最后一部分；我们已经走了很长的路。我们的网站看起来非常棒，有一些很酷的动画。在本章中，我们将通过以下方式优化我们的网站：

+   为我们的网站创建和实现一个 Favicon

+   学习如何优化我们的图像

+   学习一些 SEO 基础知识

+   逐步学习如何将我们的网站发布到网上

让我们开始吧！

# 创建一个 Favicon

**Favicons**是你在浏览器标签和书签栏上看到的小图标。它们是任何网站的标识的一部分，让用户认识你的网站：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/75ff8709-46db-4c6e-a964-22b00184e8fc.png)

Dribbble 网站的 Favicon

不要跳过这一步。有一个非常简单的在线工具可以做到这一点。我们只需要一个图像作为我们的图标，所以现在就做吧。让我们去[`realfavicongenerator.net/`](https://realfavicongenerator.net/)，这是 Favicon 生成器。通过这个，我们可以为浏览器创建图标，甚至根据它将在其上运行的不同操作系统进行设计。我们只需要选择我们的图像。在这种情况下，我们将使用资产文件夹中提供的标志，并找到图像`Logo_Square.png`。在网站上点击选择您的 Favicon 图片，并上传标志。

这是我们现在拥有的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/288c4156-ecb6-41a9-8024-e62be450fcd7.png)

它为我们提供了一堆 iOS、Android 和 Windows 手机的图标，并进行了一些自定义，但这并不是真正重要的。真正重要的是页面底部的内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/4e24c93d-91b1-40f1-8f89-c1e9daf7ac85.png)

现在我们将点击第二个选项，因为我们想选择一个路径，我们将把我们的图标放在那里，因为我们不想把它们放在根目录，主项目文件夹中。网站建议我们将 Favicon 放在根目录，但我们将指定一个不同的路径，因为将有很多图像，我们希望保持它有组织。让我们在`img`文件夹内创建一个文件夹，并将其命名为`icons`。然后，我们将编辑网站上输入框中的值，并将`/img/icons`作为我们刚刚创建的文件夹。现在，让我们生成 Favicon！首先，我们需要点击*生成您的 Favicons 和 HTML 代码*，这将带我们到另一个页面，然后我们可以点击 Favicon 包以下载它。还提供了一段代码片段，我们可以复制粘贴。

这段代码将被插入到我们网站的`<head>`标签中，就在`<!-- Place favicon.ico in the root directory -->`之后。

现在可以删除 Boilerplate 提供的三行代码了：

```html
<link rel="manifest" href="site.webmanifest">
<link rel="apple-touch-icon" href="icon.png">
<!-- Place favicon.ico in the root directory -->
```

我们的`head`部分现在应该是这样的：

```html
<head>
        <meta charset="utf-8">
        <meta http-equiv="x-ua-compatible" content="ie=edge">
        <title></title>
        <meta name="description" content="">
        <meta name="viewport" content="width=device-width, initial-scale=1">

        <link rel="apple-touch-icon" sizes="180x180" href="/img/icons/apple-touch-icon.png">
        <link rel="icon" type="image/png" sizes="32x32" href="/img/icons/favicon-32x32.png">
        <link rel="icon" type="image/png" sizes="16x16" href="/img/icons/favicon-16x16.png">
        <link rel="manifest" href="/img/icons/site.webmanifest">
        <link rel="mask-icon" href="/img/icons/safari-pinned-tab.svg" color="#5bbad5">
        <link rel="shortcut icon" href="/img/icons/favicon.ico">
        <meta name="msapplication-TileColor" content="#da532c">
        <meta name="msapplication-config" content="/img/icons/browserconfig.xml">
        <meta name="theme-color" content="#ffffff">

        <link href="https://fonts.googleapis.com/css?family=Roboto:400,700" rel="stylesheet">
        <link rel="stylesheet" href="fonts/font.css"> <!-- Font face CSS link -->
        <link rel="stylesheet" href="css/normalize.css">
        <link rel="stylesheet" href="css/animate.css">
        <link rel="stylesheet" href="css/main.css">
        <link rel="stylesheet" href="css/styles.css">
    </head>
```

最后一步是将我们下载的文件复制到我们的`icons`文件夹中。干得好！让我们跳到下一部分，看看如何优化我们网站的性能。

# 网站性能优化

没有人喜欢慢网站；我们都知道这一点。除此之外，页面速度对用户的参与度有真正的影响，因为没有人想等待网站加载。我们已经添加了一些插件和很多图像。现在，让我们开始优化我们的网站，并通过一些加快上传时间的技术让我们的用户更喜欢我们的网站。我们可以做两件非常基本的事情，即优化重图像和压缩 CSS 和 jQuery 代码。让我们来做吧。

# 优化图像

我们必须优化的第一件事是我们的图像，因为图像通常是网页中最重的内容。我们的一些图像非常重，比如我们的主图像，超过 480KB。所有这些图像，加上我们下载网站时，需要很长时间。想象一下，有人在智能手机上使用缓慢的互联网连接尝试下载这个网站。这将花费他们很长时间。所以，让我们减小文件大小。作为第一步，我们可以减小实际图像大小。

我使用一个叫做[TinyJPG](https://tinyjpg.com/)的工具来压缩大型图像。我发现它比 Sketch 或 Photoshop 的集成优化更强大：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/0539ca17-5028-4a40-a05a-09d26fda48c8.png)

Tinyjpg.com

您需要做的就是拖放您想要压缩的图像。让我们尝试一下我们的`hero-image`，它的大小为 480KB：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/a92aaaf8-0671-45ea-8929-505a7d8777b4.png)

压缩后的 hero-image.jpg

在这里，您可以看到，压缩`hero-image.jpg`后，它现在几乎只有原来的一半大小！不可思议，不是吗？现在我们要做的就是尽可能压缩尽可能多的文件，以减小它们的大小。

# 优化我们的代码

我们还可以对 CSS 和 jQuery 代码进行压缩。这基本上通过删除不必要的空格和优化代码来减小 CSS 和 jQuery 文件的大小。但是，压缩代码使人类阅读变得非常困难，因此我们应该只在准备启动网站时才压缩代码。我使用的一个工具是 Minifier ([`www.minifier.org/`](https://www.minifier.org/))。我们只需将我们的代码粘贴到其中：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/de2ccd4d-f047-4bde-96a6-9a72bba541d7.png)

Minifier.org

当我们有大量代码需要压缩时，这种技术实际上更重要；否则，我们将无法节省太多空间。在我们的情况下，我们没有那么多的代码，所以也许没有必要这样做。

如果您想要对代码进行解压缩，还有另一个网站可以使用：[`unminify.com/.`](http://unminify.com/)

现在，让我们继续进行一些非常基本的搜索引擎优化。

# 基本 SEO 改进

**搜索引擎优化**（**SEO**）是一个非常热门的话题。这是因为非常重要，您的网站可以被用户通过搜索引擎（如 Google）找到。

# 什么是搜索引擎优化？

基本上，搜索引擎优化或 SEO 使用一些技术来改进和推广网站，以增加网站从搜索引擎获得的访问者数量。SEO 有许多方面，但我们只会涵盖一些非常基本的内容，使我们的网站能够被搜索引擎找到。

# Meta 描述

首先，最重要的是，我们需要一个网站标题。这对于 SEO 和用户理解网站非常重要。

在您的 HTML 顶部，有一个`<title>`标签，我们要填写它。在这个例子中，我们将添加`Racing Club - Motor Racing Club for passionate`：

```html
<title>Racing Club - Motor Racing Club for passionate</title> 
```

其次，让我们谈谈`meta 描述`标签。这个标签是网站的简短描述，通常用于在搜索结果页面上描述一个网站，就像我们在这个 Dribbble 网站的例子中看到的一样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/80ccc3d4-8b66-483a-b086-4d4634cc227a.png)

“Dribbble”一词的搜索结果

```html
<meta name="description" content="Shots from popular and up and coming designers in the Dribbble community, your best resource to discover and connect with designers worldwide." />
```

这段文字对网页访问者来说是不可见的，但它可以帮助您为您的网站做广告，从搜索结果中吸引用户访问您的网站。因此，这是搜索营销的一个极其重要的部分。我们应该使用重要关键词来制作引人注目的 meta 描述，但不超过 160 个字符。

现在，让我们为我们的网页做这个；没有比这更容易的了。我们只需使用带有`name="description"`属性的`meta`标签，然后使用我们想要的描述的`content`属性。我们想要添加一些关于 Racing Club 的内容，所以我们会放置类似这样的内容：`“一个由热爱者组成的赛车俱乐部。澳大利亚各地的月度活动。立即购买您的门票。”`在我们的 HTML 中，我们已经预先添加了一个`meta`，所以我们只需要在其中放置描述：

```html
<meta name="description" content="A Racing Club by passionates to passionate. Monthly events in Australia-wide. Buy your ticket now.">
```

您可以在 HTML 的顶部看到这一行：

```html
<meta charset="utf-8">
```

这用于声明网站的字符编码，但它不包括排名，所以与 SEO 无关。不过，这是我们制作每个网站都应该包含的内容。

# 有效的 HTML

我们应该始终编写有效的 HTML 代码。有效的 HTML 代码是遵循官方 HTML 规则并且没有错误的代码。有效的 HTML 被谷歌所青睐，因为它使网站更有可能在我们未经测试的浏览器上运行。它看起来更专业，对可访问性更好，使得屏幕阅读器更容易阅读网站，例如盲人用户。有一个官方工具可以检查我们是否有有效的 HTML 代码，那就是 W3 标记验证器（[`validator.w3.org/`](https://validator.w3.org/)）。我们将使用它来测试我们的网站。为此，我们只需使用命令或*Ctrl* + *A*复制整个代码，然后将其粘贴。在网站 validator.w3 上，我们将使用直接输入验证选项，并在点击检查之前将所有代码粘贴在这里。这需要一点时间，但它告诉我们我们的代码中有八个错误。

在报告中，我们可以看到一些建议：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/de7159b8-3e37-4337-a133-6cf6aadb291c.png)

W3 验证器报告

其中一个建议是我们应该尽量遵循报告建议我们做的事情，但是，你仍然可以按照现在的样子启动网站。

起初，它说：

这个文档似乎是用英语写的，但 HTML 起始标记具有空的 lang 属性。考虑使用 lang="en"（或变体）代替。

事实上，建议指定网站的语言，以便搜索引擎可以识别它，并在必要时进行翻译。让我们在我们的`lang`属性中添加`en`值（表示英语）：

```html
<html class="no-js" lang="en">
```

其次，它建议我们去掉我们实现的 iframe 上的一些属性，但也要在 iframe 之前删除`<a>`标签。让我们这样做。

最后，它说：

img 元素必须具有 alt 属性，除非在某些条件下。

`alt`属性是替代属性。它用于在加载照片时描述照片，或者当浏览器无法正确渲染图像时。它还用于谷歌搜索图像，因此非常重要。

让我们为所有的图片添加`alt`属性，例如：

```html
<img src="img/logo-footer.png" srcset="img/logo-footer.png 1x, img/logo-footer@2x.png 2x" alt="Logo Racing Club">
```

现在让我们再次检查我们的代码：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/ab696e44-071c-41ab-b79b-5c7690dfd0b2.png)

W3 标记检查器上的成功验证

干得好，我们的代码现在已经验证通过了！

# 关键词

接下来要考虑的是*内容为王*。你的网站上有很棒的内容非常重要，即使你的网站是搜索结果中的前几名。如果你的内容不好，你的用户不想阅读它，那么它就毫无价值，即使你排名很高。如果可能的话，继续提供新的内容，这样你的访问者就会想要继续回来。接下来你需要做的是在内容中有策略地放置关键词。这对于在搜索排名中表现良好非常关键，因为关键词是用户实际用来找到你的东西。不过要小心，不要过度使用关键词，因为搜索引擎会认为这是关键词垃圾邮件，他们可能会对你进行惩罚。在标题、meta-description 标签、标题和链接中使用关键词。

# 链接

另一件重要的事情是让其他网站链接到你。这些链接被称为反向链接，就像是给你的网站写推荐信一样。搜索引擎部分地根据指向网站的链接数量和质量对网站进行排名。这是 SEO 的一个关键因素，因此你应该有一个策略来增加指向你网站的反向链接的数量和质量。实际上，关于 SEO 还有很多更多的信息在互联网上。如果你感兴趣，可以查阅一些书籍或互联网上的信息；这是一个充满激情的主题。

至此，优化工作就完成了。让我们继续下一部分，我们将学习如何在互联网上发布我们的网站。

# 启动我们的网站

我们的网站现在已经准备好与世界分享。我们已经走了这么长的路，现在我们几乎到了尽头。发布我们的网站非常容易。我们只需要按照这三个步骤进行即可。

# 购买域名

首先，我们需要选择并购买一个域名。对于我们的网站，可以是[www.racingclub.com](http://www.racingclub.com)。然后，我们需要购买网络托管；把它想象成互联网上的一个文件夹，我们将把所有文件放在其中。为了确保我们的网站运行顺利，我们需要正确的带宽。这是在一定时间内允许的数据传输量。

一旦我们拥有这两样东西，我们只需要将我们的网站上传到我们的网络空间，然后我们就准备好了。有许多域名注册公司和网络托管公司。当然，我不会告诉你应该选择哪一个。我只能告诉你，我曾经用[namecheap.com](http://namecheap.com)注册域名和购买网络托管。那里的服务总是很好，但我不能告诉你它是最好的网络托管，因为我到目前为止还没有尝试过其他服务器。

您可以访问*Namecheap*网站，在购买之前检查您的域名是否可用。这很容易和直接：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/e6f0d70f-d7c5-4470-9750-c72f9208bc12.png)

一旦您拥有域名，您需要一个主机。我建议使用相同的提供商获取托管和域名，这样更容易管理。

在购买托管时，您可以选择使用您购买的域名或您自己的域名：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/c6347af2-700d-41cb-bf95-e998bb5b397a.png)

使用 Namecheap 购买托管

一旦您购买了托管并将其链接到您的域名，您将收到一些确认购买的电子邮件，但更重要的是，连接到服务器以及您的**文件传输协议**（**FTP**）的所有凭据。这是用于将文件传输到服务器的协议。要上传我们的文件，我们需要使用这个协议的工具。我总是使用*FileZilla*。易于使用和开源，它可以胜任工作。下一步是下载 FileZilla（[`filezilla-project.org/`](https://filezilla-project.org/)）：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/2eed839f-2bbf-429d-aeee-5e61c03d69a1.png)

FileZilla 网站

单击下载 FileZilla 客户端，并正确安装 FileZilla。

一旦您在 FileZilla 上，单击文件|站点管理器：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/0640a1f1-952b-41c2-94d1-4c19f5f2fcc8.png)

FileZilla 新网站

现在我们需要添加一个新站点，但我们需要找到 Namecheap 发送给我们的凭据。转到您的电子邮件，查找 SFTP 详细信息，它应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/6c9066f5-4542-4feb-9102-7c780ca99120.png)

Namecheap SFTP 凭据

查看 SFTP 详细信息的描述，以便输入正确的信息：

+   **主机**：这是服务器地址

+   **端口**：这是端口

+   **协议**：需要设置为 SFTP

+   **登录类型**：设置为正常

+   **用户名**和**密码**：相应地放置

单击连接。

现在你会看到一堆文件夹，各种名称。不要担心它们；寻找`public_html`，因为这将是您的`public`文件夹。一旦进入，您可以删除默认设置的文件。

现在转到`Web Project`，并选择您要放入 FileZilla 的所有文件。*要小心；*所有文件，包括隐藏文件，都需要上传。如果您使用 Windows，您不需要担心这个问题，但对于 Mac 用户，隐藏文件在文件名前面有一个点。要显示隐藏文件，只需使用快捷键*Shift* + *CMD* + *。*来显示我们的隐藏文件：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/8d0cd276-87f4-4505-a9e6-ddd1c78ac7d3.png)

在 macOS 中显示隐藏文件

现在将所有文件拖放到 FileZilla 中。它将自动将它们上传到您的服务器。一旦完成，您的网站现在正式上线了！

这将因托管提供商而异，但通常是相同的过程。如果托管使用 FTP 或 SFTP 传输文件，FileZilla 是一个很好的工具，可以与每个托管一起使用。

# Google 分析

现在我们的网站已经上线，我们仍然可以继续工作，因为上线并不是故事的结束。您唯一需要做的就是网站维护。这意味着您应该跟踪您的网站的成功，并监控您的用户行为。我们如何做到这一点？我们使用一个非常强大的工具，叫做 Google Analytics。使用这个软件，您将能够监控统计数据，比如您的网站接收的访问次数，您的访客停留的时间，每个访客的平均页面浏览量，以及许多其他有用的统计数据：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/a8dc2913-8ba0-4f17-a154-2051c69ee762.png)

Google Analytics 网站

然后，使用这些数据，您可以对网站进行调整，使其更好。我现在将在刚上传的网站上安装 Google Analytics，以向您展示它有多么简单。您需要先创建一个 Google Analytics 帐户，但如果您已经有 Google 帐户，这很容易。创建了 Google Analytics 帐户后，您需要创建一个帐户以获取跟踪代码：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/a738752a-aa7d-4873-977c-818905c3712b.png)

Google 分析中的新帐户

在我们的情况下，这是一个网站，我将称之为“赛车俱乐部”。然后，我们需要将其链接到我们的网站。输入所有必要的信息，然后点击获取跟踪 ID：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/10b49bb7-ce92-4269-83f9-52c2ec7812df.png)

Google Analytics 跟踪代码

现在谷歌已经为您提供了一个代码，可以粘贴到您的网站上。这是一个基本的 JavaScript 代码，所以您可以在所有脚本之后粘贴它。

在我们的 HTML 样板中，留有一个位置用于我们的 Google 分析代码。只需用 Google 提供的代码替换即可：

```html
<script src="img/modernizr-3.5.0.min.js"></script>
        <script src="img/jquery-3.2.1.min.js" integrity="sha256-hwg4gsxgFZhOsEEamdOYGBf13FyQuiTwlAQgxVSNgt4=" crossorigin="anonymous"></script>
        <script>window.jQuery || document.write('<script src="img/jquery-3.2.1.min.js"><\/script>')</script>
        <script src="img/jquery.waypoints.min.js"></script>
        <script src="img/instafeed.min.js"></script>
        <script src="img/plugins.js"></script>
        <script src="img/main.js"></script>

        <!-- Global site tag (gtag.js) - Google Analytics -->
        <script async src="img/js?id=YOUR GOOGLE ANALYTICS CODE"></script>
        <script>
          window.dataLayer = window.dataLayer || [];
          function gtag(){dataLayer.push(arguments);}
          gtag('js', new Date());

          gtag('config', 'YOUR GOOGLE ANALYTICS CODE');
        </script>

```

现在的最后一步是使用 FileZilla 将更新后的文件上传到我们的服务器。只需拖放`index.html`（不要忘记保存！），然后就完成了！

这是对 Google Analytics 的一个非常快速的介绍，但这个工具非常强大，可以设置跟踪网站上的所有内容。这是一个相当漫长的旅程，但我们做到了。现在你实际上可以在互联网上打开一个网页，看到我们一起创建的网站。现在你可以自己做到所有这些。很神奇，不是吗？

# Google 搜索控制台

当一切都完成后，您可以通过告诉谷歌查看您的网站并使用他们的机器人爬行来完成您的上线。为此，我们需要将我们的 URL 添加到谷歌数据库，我们将使用他们的 Google 搜索控制台（[`www.google.com/webmasters/tools/`](https://www.google.com/webmasters/tools/)）来完成这一点。

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/1ef02dcc-e38f-469a-9fec-881857a92c67.png)

Google 搜索控制台

只需输入您的域名，验证您拥有此域名，然后您就可以了。

# 总结

干得好。在本章中，我们涵盖了相当多的内容。在本章中，我们走过了启动网站的过程。从创建我们的 favicon，压缩我们的图像，缩小我们的 CSS 和 JS 文件，我们还成功验证了我们的 HTML 与 W3 Markup Validator。接着购买我们的域名并将文件上传到我们的服务器。我们通过集成 Google Analytics 并将网站提交给 Google 搜索来完成了本章。我们可以说这是一个非常紧凑的章节！

在下一章中，我们将学习 Bootstrap 是什么，以及为什么开发人员喜欢它。我们还将了解它的组件，学习如何使用 Bootstrap Grid，最后，Bootstrap 如何使用媒体查询。

让我们跳到下一章！


# 第十一章：什么是 Bootstrap？

现在我们知道如何从头开始构建网站了，我想向您介绍 Bootstrap ([`getbootstrap.com/`](https://getbootstrap.com/))。

在本章中，我们将：

+   了解 Bootstrap 是什么，以及为什么开发者喜欢它

+   阅读 Bootstrap 的文档，了解如何使用它

+   让我们来了解著名的 Bootstrap 网格

+   了解 Bootstrap 如何使用媒体查询

# 什么是 Bootstrap？

Bootstrap 是一个开源的 HTML、CSS 和 JS 库，可以帮助您轻松构建网站和应用程序。它是一个组件库，您可以重复使用这些组件，而不是一遍又一遍地重新创建每个组件。Bootstrap 是响应式和移动优先的；这基本上就是 Bootstrap 的全部内容，也是为什么它在网页开发者中如此受欢迎的原因。现在，假设开发者为不同的设备创建了不同版本的网站；只需在页面上应用少量代码，网站就可以在任何设备上正确显示，这节省了时间和额外的成本。

每隔几年就会有重大更新。Bootstrap 2 于 2012 年正式发布，然后相对较快地被 Bootstrap 3 取代，后者于 2013 年发布。然后，当然，2016 年出现了 Bootstrap 4。它变得越来越稳定，发布之间的间隔也越来越长。希望不久之后 Bootstrap 5 就会到来。

Bootstrap 4 仍然非常新，所以很多开发者仍在使用 Bootstrap 3：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/88d85aed-22e4-486c-ab90-cba0d8699d8c.png)

Bootstrap 网站

在框架内，还有许多元素和组件，您可以在您的网站或页面中使用。文档选项卡中的所有内容都是必不可少的；它包含了您可以随时参考的宝贵信息，也是您想要了解新元素或组件的地方：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/52937e56-2bdf-4923-9e0c-234dcba49c3b.png)

Bootstrap 文档

它从 Bootstrap 的介绍开始，包括了您开始所需的所有信息。然后，在左侧，它提供了所有的部分和组件。这可能是您将查看的最受欢迎的部分之一，因为它包含了您可以在 Bootstrap 中使用的所有不同元素。因此，这可以帮助您构建您的页面。

Bootstrap 还提供了一些示例或快速开始示例，这些都在示例选项卡中。这些是在您完成本章后练习或测试的想法，这样您就可以将新想法应用到自己的页面中，并测试您在整个章节中学到的内容：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/99ceb10c-b233-4f28-87c2-f37794ebebf3.png)

Bootstrap 示例。

值得将此页面加为书签，或者将来再次访问。现在，另一个值得关注的重要部分是 Bootstrap 博客；这是所有更新发布的地方，无论大小。因此，最好随时关注，以防发生可能会影响您网站的变化。

因此，简而言之，这只是对 Bootstrap 网站的一个快速概述。值得将组件页面加为书签，以便将来需要时可以快速查阅。接下来，我们将更仔细地看看这些组件是什么，以及我们将如何使用它们。

# 组件

让我们来看看我们的 Bootstrap 文档 ([`getbootstrap.com/docs/4.0/getting-started/introduction/`](https://getbootstrap.com/docs/4.0/getting-started/introduction/))，更具体地说是组件部分。这位于文档选项卡上，包含了您在使用 Bootstrap 编写网站时将使用的许多元素：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/d2bca210-b469-4913-a65b-191457e9a4cc.png)

Bootstrap 组件

这些都按字母顺序列出，因此您可以轻松找到所需的内容。例如，如果我们只看看按钮，这提供了您在 Bootstrap 中开始使用按钮所需的所有信息。默认按钮有它们自己的样式类；我们可以在这里看到有主要、次要、成功、危险、警告、信息、浅色、深色和链接：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/e42308d9-6e4a-4261-909c-9a07a9d64ccc.png)

Bootstrap 按钮

要将这些按钮中的任何一个添加到您的页面，您可以使用此处提供的代码，或者如果您想要一个按钮的轮廓，例如，如果我们向下滚动，您会看到轮廓按钮也有自己的类。您只需要添加此代码以添加轮廓按钮：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/48d6bea0-b905-4ae3-adf3-ead4da04c0ca.png)

Bootstrap 轮廓按钮

如果我们继续向下滚动，您会看到有许多不同的按钮选项可用。当然，您可以只添加一个标准按钮并手动启动它，但这些示例是快速在页面上使用按钮的好方法。

现在，显然，按钮并不那么令人兴奋；这只是 Bootstrap 中有多少细节以及在 Bootstrap 中编码时有多少支持的一个例子。让我们看另一个例子，比如表单。我们在右侧有所有我们的表单内容。让我们点击内联表单，例如；我们可以看到所有描述内联表单选项的信息，以及您需要添加到页面的代码：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/6bb89d46-e62a-4e5f-bce8-2e5f3b0f59dd.png)

内联表单

如果您选择另一个，例如导航栏，这将显示在向页面添加导航栏时可以使用的所有不同选项。它从基础开始，然后说明导航栏需要一个导航栏类，并且默认情况下是流体的。这只是意味着它们会延伸到整个页面的宽度。然后，它继续描述导航栏的不同元素，包括添加您的品牌、不同的颜色方案以及如何使您的导航栏响应式。有很多信息可以帮助确保您在需要时可以快速上手。如果您愿意，随时查看这些组件。将来使用时，将这个页面加入书签肯定是值得的。

当我们开始构建我们的页面时，我们显然会更详细地讨论。接下来，我们将继续并查看 Bootstrap 网格系统。

# Bootstrap 网格系统

Bootstrap 之所以如此受欢迎的主要原因之一是其响应式特性。现在，Bootstrap 建立在一个网格系统上，并且基于一组 12 列。如果您只是跳转到 Bootstrap 网站上的文档，然后进入布局部分，然后进入网格部分，我们可以更仔细地看一下：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/d46a2197-db5b-443a-8098-96a86d162ee4.png)

Bootstrap 网格

Bootstrap 包含三种不同的组件；它们是列、容器和行。基本上，容器保存内容，行对齐内容，列决定内容在该行上如何分割。如果您对网格系统没有经验，不要担心太多，因为当您逐步学习并获得实际经验时，一切都会变得清晰起来。为了最好地说明网格系统的内容，我们可以看一下接下来页面上的响应式类部分。我觉得这是对网格系统内容的最好解释：Bootstrap：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/4838936c-91d5-475d-af83-43d08b44fafb.png)

Bootstrap 中的响应式类

有五个预定义类的层次结构，用于构建复杂的响应式布局。在这个例子中，我们可以看到正在使用新的`col`类。这意味着在这一行中，我们基本上有四列，并且每个元素占据 12 列行中的特定列数。

在第一种情况下，每个元素占据 12 列行中的三列，因为 3 可以整除 12 四次。这个布局在所有设备上也是一样的，从超小型设备一直到超大型设备。如果您愿意，您还可以定义您想要在行中占据的列数，这在这个例子中是在第二行中。

因此，第一部分内容将占用`8`列，下一个将占用`4`列。同样，无论屏幕尺寸如何，它都将填满整个 12 列。Bootstrap 之所以如此受欢迎，是因为它具有响应式特性，某些元素在较小的设备上堆叠，而在较大的设备上沿着行对齐。为此，我们只需要在我们的列类中定义设备大小：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/66d9e9cf-54b6-488e-9af2-2e4fe661e9cb.png)

响应式特性

在下一个示例中，您可以看到通过使用`sm`类或小类，内容是相似的，因为顶部有`8`和`4`，然后下一行切换为三个部分。然而，在实际的示例中，两者的内容在较小的设备上实际上会堆叠，当断点达到较小设备以上时，它将沿着行显示。在本页中有关网格系统的更多信息，但是，正如我提到的，随着我们逐步学习本章内容，您很快就会习惯它的工作方式。

我希望这能稍微解释一下网格系统，但是，正如我所说的，通过在下一章中使用它，您很快就会掌握它。接下来，我们将看一下 Bootstrap 媒体查询。

# 媒体查询

Bootstrap 最好的一点是，您可以将媒体查询整合到您的 CSS 文件中，这实质上让您可以从特定的项目或断点开始，并帮助您针对特定设备定位样式。如果您首先转到文档选项卡，然后转到布局部分，然后我们只需要稍微向下滚动到响应式断点部分。我们可以在这里看到我们的媒体查询。我们可以看到断点很重要，因为这些通常用作查询的指南，因此您可以确定您想要为哪个设备设置样式：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/fa0ec674-68c9-48c1-b1d9-4652871b3bed.png)

响应式断点

在这段代码的第一部分中，我们有所有断点的媒体查询，除了超小型设备。这使用了`min-width`命令。如果我们稍微向下滚动，我们会看到除了超大型设备之外，我们有所有断点，这些使用了`max-width`命令。不同之处在于，如果您首先为移动设备设计，则倾向于使用`min-width`选项，如果您首先为桌面设计，则倾向于使用`max-width`：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/00c25c1d-2b2a-4361-b5a8-ca66227876ce.png)

最大宽度命令

通常，我倾向于使用`max-width`，并且我倾向于首先为桌面设计，然而；了解两者都是很好的，以防您需要首先为移动设备设计。

这是对媒体查询的简单介绍；再次，随着我们课程的进行，您会更好地理解这一点，但我希望这能稍微解释一下，这样当我们真正开始时，您就有了基本的理解。

# 摘要

在本章中要记住的重要点是，Bootstrap 就像是开发人员可以轻松重复使用的组件库。通过了解它们（网格、组件、媒体查询），您将能够实现很多，而不是从头开始构建网站时。

接下来，我们将使用 Bootstrap 设计我们的页面，并逐步学习如何使用它。


# 第十二章：使用 Bootstrap 构建网站

我们刚刚看到了 Bootstrap 有多么强大。有了一个可以重复使用的广泛组件和元素列表，它可以使我们的开发阶段非常容易，这就是为什么开发人员喜欢它。在本章中，我们将讨论如何使用 Bootstrap 框架构建我们的网站，具体步骤如下：

+   学习如何在项目中设置 Bootstrap

+   创建和设计我们的导航栏

+   继续英雄部分

+   创建和设计博客部分

+   创建和设计关于部分

+   完成页脚

我们将从头开始创建项目，并创建与之前创建的相同页面，以比较我们最初的技术与 Bootstrap 技术。让我们开始吧！

# 安装 Bootstrap

我们需要做的第一件事是下载 Bootstrap。有多种下载方式。让我们前往下载页面查看一下。在主页上点击下载按钮。现在你可以查看不同的下载最新版本 Bootstrap 的方法：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/0aa32595-f9b0-4a0b-9c58-86b73c7287d4.png)

下载 Bootstrap

第一种方法是下载编译后的 Bootstrap 版本。你的版本将取决于你学习这门课程的时间，但总是选择最新版本的 Bootstrap。

你也可以下载包含所有文件的 Bootstrap 源版本，但大多数情况下，你只需要编译后的文件，因为这样更快更容易让 Bootstrap 运行起来。

如果你向下滚动一点，你会注意到 BoostrapCDN。Bootstrap 还提供了一个内容传送网络（CDN），它将在服务器上托管最新版本的 Bootstrap，因此你可以只粘贴 URL 而无需在服务器上托管文件。这很好，因为你的用户不需要再次下载文件，因为他们可能已经通过访问使用 Bootstrap 的其他网站下载了文件。

# 设置我们的项目

要开始，让我们创建一个名为`Racing Club Bootstrap`的文件夹。在 Atom 中，我们将打开一个新窗口，点击添加项目文件夹...，并找到`Racing Club Bootstrap`。

在里面，让我们创建我们的`index.html`文件。点击创建新文件（*Ctrl* + *N*或*Cmd* + *N*），并保存它，这样我们就可以将文件命名为`index.html`。

完成后，让我们前往 Bootstrap 网站（[`getbootstrap.com/docs/4.0/getting-started/introduction/`](http://getbootstrap.com/docs/4.0/getting-started/introduction/)），具体来说是“Introduction”部分。

在这一部分，Bootstrap 为你提供了一个启动项目的模板：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/5b6a6c41-9f62-47cf-9fdd-dfc04b123f54.png)

启动模板

复制提供的代码并粘贴到你的`index.html`文件中。我们可以从模板中删除`<h1>Hello, world!</h1>`。

我们准备好开始了，但我们也想写自己的 CSS。为此，让我们创建一个名为`css`的文件夹和一个名为`styles.css`的 CSS 文件。

为了快速做到这一点，你可以右键单击 Atom 中的左侧栏，然后点击新建文件夹，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/74a2f7cf-5ae1-4fe8-ae30-50fd5798182a.png)

在 Atom 中创建一个文件夹

当你创建 CSS 文件时，你总是需要将它链接到你的 HTML 文件中，否则它不起作用。如果你记得链接它，你将需要添加以下代码：

```html
<link rel="stylesheet" href="css/styles.css">
```

既然我们已经创建了我们的 CSS 文件并将其链接到我们的 HTML 文件中，我们需要做的最后一件事就是复制我们在上一个项目中创建的`img`和`fonts`文件夹。这更容易，因为我们将重新创建相同的页面。只需将这些文件夹复制粘贴到我们的新项目中。

不要忘记将字体 CSS 链接到你的 HTML 文件中。在你的`styles.css`之前添加它：

```html
<link rel="stylesheet" href="fonts/font.css">
```

安装 Google 字体 Roboto：

```html
<link href="https://fonts.googleapis.com/css?family=Roboto:400,700" rel="stylesheet">
```

既然我们都准备好了，让我们开始吧。

# Bootstrap 导航栏

我们将首先创建的是 Bootstrap `navbar`。Bootstrap 中的`navbar`是 Bootstrap 框架中最具标志性的特性之一，因为它的工作方式。因此，为了提供一个它的工作方式的示例，如果我们导航到 Bootstrap 网站，然后到文档选项卡，我们会看到屏幕顶部的所有导航元素：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/c78be0f0-5ca3-4ec2-8f7e-a1087a470fbd.png)

Bootstrap 导航

如果我们缩小浏览器，我们可以看到导航也在缩小。然后，当它达到较小的屏幕时，我们会得到这个汉堡菜单，如果我们点击它，它会显示其中的导航元素：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/8c3ee499-9e69-44e7-a6d1-eeac3e734a44.png)

Bootstrap 移动导航

# 编写 Bootstrap 导航

现在让我们转到 Bootstrap 网站上的组件中的`navbar`部分。在这里，您可以找到使用 Bootstrap 构建导航所需的所有文档。

现在让我们回到我们的 HTML 文件，并写入以下代码：

```html
<nav class="navbar navbar-expand-lg fixed-top ">

</nav>
```

上述代码的细节如下：

1.  我们首先在内容的主体中添加了我们的`<nav>`元素，所有`<nav>`元素都需要一个`navbar`类。

1.  然后，我们添加了新的扩展类，即`navbar-expand-lg`。这基本上告诉浏览器何时折叠`navbar`，何时扩展它。

1.  因此，在这种情况下，当它达到大屏幕时，它将展开并显示桌面版本。如果我们想在中等屏幕上展开，那么我们只需要将`lg`更改为`md`，或者对于较小的屏幕，更改为`sm`。

1.  然后，我们添加了定位类，因为我们希望这个`navbar`固定在屏幕顶部，所以当用户滚动时，导航始终可见，我们只需添加`fixed-top`类。

接下来，让我们添加一些导航选项：

```html
<nav class="navbar navbar-expand-lg fixed-top ">
      <div class="collapse navbar-collapse" id="navigation-bar">

      </div>
    </nav>
```

在这段代码中，我们简单地标识了以下内容：

1.  我们添加了一个带有`collapse`类的`div`。这只是告诉浏览器，这个`div`及其所有内容将是可折叠的元素。

1.  然后，我们添加了一个`navbar-collapse`类。

1.  最后，我们添加了一个将在稍后链接到我们的切换按钮的`id="navigation-bar"`。

现在我们需要添加我们的导航列表，包括`<ul>`和`<li>`用于列表，以及每个链接的`<a>`：

```html
<nav class="navbar navbar-expand-lg fixed-top ">
      <div class="collapse navbar-collapse" id="navigation-bar">
        <ul class="navbar-nav">
          <li class="nav-item"><a class="nav-link" href="upcoming.html">Upcoming events</a></li>
          <li class="nav-item"><a class="nav-link" href="past.html">Past events</a></li>
          <li class="nav-item"><a class="nav-link" href="faq.html">FAQ</a></li>
          <li class="nav-item"><a class="nav-link" href="about.html">About us</a></li>
          <li class="nav-item"><a class="nav-link" href="blog.html">Blog</a></li>
          <li class="nav-item"><a class="nav-link" href="contact.html">Contact</a></li>
        </ul>
      </div>
    </nav>
```

为了使导航正常工作，我们需要在`<ul>`上使用`.navbar-nav`类，在`<li>`上使用`nav-item`类。最后，我们需要在`<a>`标签上使用`.nav-link`类。

现在让我们在浏览器中检查一下我们的列表：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/94dfd980-0930-46ae-850c-dc26b0b0ab45.png)

我们导航的工作进展

我们有了 Bootstrap 导航，但是如果将页面缩小到移动视图，您会注意到导航消失了。这是因为我们还没有包含我们的切换按钮，所以现在让我们添加它。

回到我们的`index.html`，我们可以在创建的`div`上方添加我们的按钮。让我们创建一个按钮标签，并给它`.navbar-toggler`类和指示，如下所示：

```html
<button type="button" class="navbar-toggler" data-toggle="collapse" data-target="#navigation-bar">

</button>
```

`data-target`属性是我们之前所拥有的导航选项的链接方式，即`#navigation-bar`ID。

现在我们需要在这个按钮内添加汉堡菜单。为此，我们可以使用`≡`的 HTML 代码，这是三条杠图标的 HTML 代码。有很多可用的 HTML 符号，您可以使用。您可以搜索 HTML 符号，那将为您提供很多示例和符号。

让我们添加一个带有`.navbar-toggler-icon`类和 HTML 符号的`span`标签：

```html
<button type="button" class="navbar-toggler" data-toggle="collapse" data-target="#navigation-bar">
 <span class="navbar-toggler-icon">≡</span>
</button>
```

现在，如果我们保存并检查，我们可以在移动屏幕上看到我们的菜单图标，如果我们点击它，菜单将正确显示：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/6786a443-f0fb-406d-9dd1-312be245c07b.png)

移动导航。

现在让我们在我们的`navbar`中添加标志。通常，标志是一个链接，所以让我们添加一个带有`.navbar-brand`类的`<a>`标签。

我们不希望标志在移动视图上折叠，所以我们只需在`<button>`之前添加`<a>`：

```html
<nav class="navbar navbar-expand-lg fixed-top ">

      <a class="navbar-brand" href="#"><img src="img/logo.png" class="img-fluid" alt="Logo Racing Club"></a>

      <button type="button" class="navbar-toggler" data-toggle="collapse" data-target="#navigation-bar">
        <span class="navbar-toggler-icon">☰</span>
      </button>

      <div class="collapse navbar-collapse" id="navigation-bar">
        <ul class="navbar-nav">
          <li class="nav-item"><a class="nav-link" href="upcoming.html">Upcoming events</a></li>
          <li class="nav-item"><a class="nav-link" href="past.html">Past events</a></li>
          <li class="nav-item"><a class="nav-link" href="faq.html">FAQ</a></li>
          <li class="nav-item"><a class="nav-link" href="about.html">About us</a></li>
          <li class="nav-item"><a class="nav-link" href="blog.html">Blog</a></li>
          <li class="nav-item"><a class="nav-link" href="contact.html">Contact</a></li>
        </ul>
      </div>

    </nav>
```

在这个`<a>`中，我们添加了以下内容：

1.  一个`.navbar-brand`类

1.  与我们的标志相关联的`img`标签

1.  在这个`img`中，我们添加了一个`.img-fluid`类，使这个图像具有响应性

我们现在设置了我们的标志，但还没有完成。我们需要添加右侧导航。为此，我们只需要在`<ul class="navbar-nav">`之后添加另一个`<ul>`：

```html
<div class="collapse navbar-collapse" id="navigation-bar">
        <ul class="navbar-nav">
          <li class="nav-item"><a class="nav-link" href="upcoming.html">Upcoming events</a></li>
          <li class="nav-item"><a class="nav-link" href="past.html">Past events</a></li>
          <li class="nav-item"><a class="nav-link" href="faq.html">FAQ</a></li>
          <li class="nav-item"><a class="nav-link" href="about.html">About us</a></li>
          <li class="nav-item"><a class="nav-link" href="blog.html">Blog</a></li>
          <li class="nav-item"><a class="nav-link" href="contact.html">Contact</a></li>
        </ul>

        <ul class="navbar-nav ml-auto">
 <li class="nav-item"><a class="nav-link" href="login.html">Login</a></li>
 <li class="nav-item"><span class="nav-link"><iframe src="img/like.php?href=http%3A%2F%2Ffacebook.com%2Fphilippehongcreative&width=51&layout=button&action=like&size=small&show_faces=false&share=false&height=65&appId=235448876515718" width="51" height="20" style="border:none;overflow:hidden"></iframe></span></li>
 </ul>
      </div>
```

我们添加了`.ml-auto`类来将第二个导航移到右侧。这代表着`margin-left`自动。它填充了导航左侧的边距，这将有效地将其移动到右侧。如果你想要相反的效果，你只需添加`.mr-auto`类。

现在让我们来看看我们的导航：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/524cb84d-b1e7-475e-947f-08d129cf635d.png)

Bootstrap 导航

我们的导航看起来很棒，我们已经拥有了导航栏所需的所有元素。接下来，我们将添加一些样式。

# 样式化我们的导航栏

样式化 Bootstrap 组件非常简单。我们唯一需要做的就是覆盖 Bootstrap CSS。但是，我们不想覆盖 Bootstrap CSS 文件本身；我们想要做的唯一事情就是添加额外的 CSS 属性，这些属性将覆盖原始的 Bootstrap CSS。我们之前创建了一个名为`styles.css`的 CSS 文件，并且，由于这个文件在 HTML 文档中按顺序链接到 Bootstrap CSS 文件之后，我们编写的每个具有相同属性和类的 CSS 都将覆盖原始的 Bootstrap CSS：

```html
<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0/css/bootstrap.min.css" integrity="sha384-Gn5384xqQ1aoWXA+058RXPxPg6fy4IWvTNh0E263XmFcJlSAwiGgFAW/dAiS6JXm" crossorigin="anonymous">
<link rel="stylesheet" href="css/styles.css">
```

我们需要定位正确的 CSS 类来覆盖它。如果您记得，我们使用了谷歌 Chrome 的检查器来检查元素并检查它们的 CSS。要打开检查器（或开发工具），右键单击元素，然后单击检查：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/9f641423-5b66-4374-83b7-f5acb2bf06e3.png)

在 Chrome 上检查元素

现在我们可以看到开发者面板，那里有很多信息。您可以检查不同的面板。当在 HTML 中悬停在一个元素上时，您可以看到它显示在网页上：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/ba2dda67-2b7a-4f43-935e-9a3cc0ed40f8.png)

谷歌 Chrome 检查器

当您想要修复任何 CSS 样式问题或查看 HTML 时，这非常有用。现在让我们修复 CSS。

通过检查器，我们可以看到`.navbar`类默认有一些填充，但我们想要摆脱它。

只需将以下 CSS 添加到您的`styles.css`中：

```html
.navbar {
  padding: 0;
}
```

保存后，您可以检查我们用自己的样式覆盖了 bootstrap CSS：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/94265ee5-1fe8-4d71-89d2-5e58dd87961f.png)

覆盖 Bootstrap CSS

现在您了解了原理，我们可以快速修复导航：

```html
.navbar {
  padding: 0;
  background-image: linear-gradient(0deg, rgba(0,0,0,0.00) 0%, rgba(0,0,0,0.50) 50%);
}

.navbar-brand {
  padding: 0;
}

.navbar-nav li a {
  color: white;
  text-decoration: none;
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 200;
  font-size: 20px;
  letter-spacing: 4px;
}

.navbar-collapse {
  padding: 10px 15px;
}

@media (min-width: 992px) {
  .navbar-collapse {
    padding: 0;
  }
}

.navbar-toggler-icon {
  color: white;
}
```

上面的代码将正确地为`navbar`添加样式。您可以看到一切都很正常，而且没有太多的代码，甚至是响应式的部分。这就是 Bootstrap 的强大之处。如果我们比较一下我们为了使导航栏响应而做的工作，使用 jQuery 和所有媒体查询，我们写的代码比我们为*第一个项目*写的要少得多。现在让我们继续进行英雄部分的工作。

# 样式化英雄部分

现在我们了解了如何使用 Bootstrap，我们可以开始使用 Bootstrap 库中的其他组件：

```html
<!-- HERO SECTION -->

    <div class="hero position-relative overflow-hidden d-flex align-items-center">
      <div class="container">
        <div class="col-md-7 my-auto">
          <p class="lead font-weight-normal">13.05.17</p>
          <h1 class="display-2 font-weight-normal custom-font-title">WAKEFIELD PARK</h1>
          <a class="btn btn-primary" href="#">Book now</a>
        </div>
      </div>
    </div>

<!-- END HERO SECTION -->
```

让我解释一下上面的代码片段。

对于*第一个*`div`，它如下所示：

1.  我们首先设置了一个自定义类`.hero`，这样我们就可以在父元素中应用自定义代码。

1.  我们添加了 Bootstrap 提供的实用类`.position-relative`和`.overflow-hidden`，这样我们就不必在 CSS 中应用它们。

1.  类`.d-flex`将设置`display: flex`。

1.  实用类`.align-items-center`将使子元素垂直居中对齐。

1.  我们添加了一个自定义字体`.custom-font-title`，这样我们就可以为每个元素添加自定义字体。

然后我们应用了*第二个*`div`，使用`.container`类，这样我们就可以应用 Bootstrap 默认的`container`类。

以下类都是 Bootstrap 库的一部分。您可以在 Bootstrap 网站上看到它们。

接下来是自定义我们添加的`.hero`类：

```html
.hero {
  width: 100%;
  height: 700px;
  background-image:
    linear-gradient(to bottom, rgba(0,0,0,0.3) 0%,rgba(0,0,0,0.4) 100%),
    url("../img/hero-image.jpg");
  background-repeat: no-repeat;
  background-size: cover;
  background-position: center;
  color: white;
}
```

保存，并查看我们的成果：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/848912ed-18a1-4b45-a653-cc2db2a26cd8.png)

英雄部分的预览

现在让我们为其添加最后的修饰：

```html
.custom-font-title {
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 400;
}

.btn-primary {
  font-size: 18px;
  letter-spacing: 4.5px;
  background: #BF0000;
  color: white;
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 400;
  padding: 12px 22px;
  border: none;
  outline: none;
  transition: all 0.3s ease;
  border-radius: 0px;
}

.btn-primary:hover {
  background: #A3171B;
}

.btn-primary:active {
  box-shadow: inset 0px 8px 4px rgba(0, 0, 0, 0.25);
  background: #A3171B!important;
  box-shadow: none!important;

}

.btn-primary:focus {
  box-shadow: inset 0px 8px 4px rgba(0, 0, 0, 0.25);
  background: #A3171B;
  box-shadow: none;
}
```

这将覆盖 Bootstrap 的默认样式，用于标题和主按钮：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/39b8112b-a917-461b-b3d1-c31910ad78e7.png)

我们最终的英雄部分

现在让我们开始博客部分。

# 美化博客部分

在我们之前建立的网站中，我们有自己的网格系统。然而，现在，我们可以简单地使用 Bootstrap 网格，这比我们创建的网格系统要好得多，更实用。

让我们从 HTML 开始：

```html
<div class="blog py-5">
      <div class="container">
        <div class="row">
          <div class="col-md-4">
            <div class="card mb-4">
              <img class="card-img-top" alt="Thumbnail Blog" src="img/blog1.jpg">
              <div class="card-body">
                <small class="text-muted">09th January 2016</small>
                <h4 class="font-weight-bold">Racing Club Advan Neova Challenge Round 3 Update</h4>
                <p class="card-text">FINAL ROUND: Labour Day Trackday Wakefield Park. Last chance to compete in the Circuit Club Advan Neova Challenge 2016!
There was much anticipation with Jason's big power Evo competing at Round 3, however some suspected engi... </p>
                <a href="#" class="btn btn-outline-primary">Read more</a>
              </div>
            </div>
          </div>
      </div>
    </div>
```

在上面的代码中，您可以注意到有很多`.py-5` `.my-5`类。这些类是间距类；它们已经添加到 Bootstrap 的最新版本中，因此您可以只用一个简单的类来添加间距。要了解如何使用它们，请转到文档的实用程序部分中的间距部分：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/7eda7dc3-316a-4503-ac85-b5bdc892d03f.png)

Bootstrap 中的间距实用工具

此外，您可能已经注意到我们为每个卡片使用了网格。一开始，网格有点难以理解，但是一旦理解了，它就非常强大和有用。最好的做法是尝试一下。您可以通过查看文档中提供的示例来尝试网格。 [`getbootstrap.com/docs/4.0/layout/grid/`](https://getbootstrap.com/docs/4.0/layout/grid/)。

在这里，我们添加了`.col-md-4`类，因为我们希望三个相同宽度的相同块，Bootstrap 使用的是 12 列系统-12 除以 3 等于 4。此外，我们使用了`md`属性，以便仅在浏览器分辨率大于 768px 时应用。

现在让我们为我们的六篇博客文章复制卡片六次：

```html
<!-- BLOG SECTION -->

    <div class="blog py-5">
      <div class="container">
        <div class="row">
          <div class="col-md-4">
            <div class="card mb-4">
              <img class="card-img-top" alt="Thumbnail Blog" src="img/blog1.jpg">
              <div class="card-body">
                <small class="text-muted">09th January 2016</small>
                <h4 class="font-weight-bold">Racing Club Advan Neova Challenge Round 3 Update</h4>
                <p class="card-text">FINAL ROUND: Labour Day Trackday Wakefield Park. Last chance to compete in the Circuit Club Advan Neova Challenge 2016!
There was much anticipation with Jason's big power Evo competing at Round 3, however some suspected engi... </p>
                <a href="#" class="btn btn-outline-primary">Read more</a>
              </div>
            </div>
          </div>
          <div class="col-md-4">
            <div class="card mb-4">
              <img class="card-img-top" alt="Thumbnail Blog" src="img/blog2.jpg">
              <div class="card-body">
                <small class="text-muted">09th January 2016</small>
                <h4 class="font-weight-bold">Hidden Behind the Scenes</h4>
                <p class="card-text">Originally posted by Narada Kudinar, 23.08.11.
At our Trackdays, we get a variety - owners with their girlfriends, owners with their mates, owners and their mechanics - but there is one combination I am truly at envy with. It's the owners and their Dads. </p>
                <a href="#" class="btn btn-outline-primary">Read more</a>
              </div>
            </div>
          </div>
          <div class="col-md-4">
            <div class="card mb-4">
              <img class="card-img-top" alt="Thumbnail Blog" src="img/blog3.jpg">
              <div class="card-body">
                <small class="text-muted">04th July 2013</small>
                <h4 class="font-weight-bold">Introducing Advan Trackdays!</h4>
                <p class="card-text">For the first time, Yokohama Advan Tyres are hosting their very own Trackdays, hosted by your's truly! The aim? To thank their loyal customers by providing a bargain event as well as introduce new Advan tyres to those who don't use them yet.. </p>
                <a href="#" class="btn btn-outline-primary">Read more</a>
              </div>
            </div>
          </div>
          <div class="col-md-4">
            <div class="card mb-4">
              <img class="card-img-top" alt="Thumbnail Blog" src="img/blog4.jpg">
              <div class="card-body">
                <small class="text-muted">03th January 2016</small>
                <h4 class="font-weight-bold">ANZAC Day Spots Running Out!</h4>
                <p class="card-text">FINAL ROUND: Labour Day Trackday Wakefield Park. Last chance to compete in the Circuit Club Advan Neova Challenge 2016!
There was much anticipation with Jason's big power Evo competing at Round 3, however some suspected engi… </p>
                <a href="#" class="btn btn-outline-primary">Read more</a>
              </div>
            </div>
          </div>
          <div class="col-md-4">
            <div class="card mb-4">
              <img class="card-img-top" alt="Thumbnail Blog" src="img/blog5.jpg">
              <div class="card-body">
                <small class="text-muted">02th January 2016</small>
                <h4 class="font-weight-bold">10 Year Anniversary Details Now Available!</h4>
                <p class="card-text">Originally posted by Narada Kudinar, 23.08.11.
At our Trackdays, we get a variety - owners with their girlfriends, owners with their mates, owners and their mechanics - but there is one combination I am truly at envy with. It's the owners and their Dads.</p>
                <a href="#" class="btn btn-outline-primary">Read more</a>
              </div>
            </div>
          </div>
          <div class="col-md-4">
            <div class="card mb-4">
              <img class="card-img-top" alt="Thumbnail Blog" src="img/blog6.jpg">
              <div class="card-body">
                <small class="text-muted">01th January 2016</small>
                <h4 class="font-weight-bold">Prepare for EPICNESS</h4>
                <p class="card-text">For the first time, Yokohama Advan Tyres are hosting their very own Trackdays, hosted by your's truly! The aim? To thank their loyal customers by providing a bargain event as well as introduce new Advan tyres to those who don't use them yet... </p>
                <a href="#" class="btn btn-outline-primary">Read more</a>
              </div>
            </div>
          </div>
      </div>
    </div>

    <!-- END BLOG SECTION -->
```

最后一件事是添加“显示更多”按钮。我们还需要水平居中按钮。为此，我们将使用`.d-flex` flexbox Bootstrap 类配合`.align-items-center`类：

```html
<div class="row d-flex align-items-center py-5">
    <div class="mx-auto">
        <a href="#" class="btn btn-primary">Show more</a>
    </div>
</div>
```

最后，为了使其居中，我们只需要添加`.mx-auto`类，这样左右边距就会自动调整。

让我们来看看现在有什么：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/f0024867-8940-465b-b99e-ed92a16ee425.png)

正在进行中-博客部分

我们有一些相当不错的东西，完全没有样式。唯一剩下的就是自定义卡片和轮廓按钮，然后我们就可以开始了：

```html
body {
    font-family: 'Roboto', sans-serif;
}

.btn-outline-primary {
  color: #BF0000;
  background-color: transparent;
  background-image: none;
  border-color: #BF0000;
}

.btn-outline-primary:hover {
  background: #A3171B;
  border-color: #A3171B;
}

.btn-outline-primary:active {
  box-shadow: inset 0px 8px 4px rgba(0, 0, 0, 0.25);
  background: #A3171B!important;
  box-shadow: none!important;
  outline: none;
  border-color: #A3171B!important;

}

.btn-outline-primary:focus {
  box-shadow: inset 0px 8px 4px rgba(0, 0, 0, 0.25);
  background: #A3171B;
  box-shadow: none;
  outline: none;
}

.card {
  border: none;
}
```

以下是设计的最终阶段：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/e2164d73-9ded-4348-a013-18eb5677f6e2.png)

博客部分的设计最终确定

就是这样；我们已经完成了博客部分。让我们开始关于我们部分。

# 美化关于部分

这一部分非常简单。我们将重用之前使用的相同类。您可以观察以下 HTML 代码：

```html
<!-- ABOUT SECTION -->

    <div class="about position-relative py-5">
      <div class="container">
        <div class="row d-flex align-items-center py-5">
          <div class="col-md-6 my-auto">
            <h1 class="display-1 font-weight-normal custom-font-title text-white">The<br /> Love<br /> of car</h1>
          </div>
          <div class="col-md-6 my-auto">
            <h3 class="font-weight-normal custom-font-title text-white">About us</h3>
            <p class="lead font-weight-normal text-white">Circuit Club was founded in 2003 with one goal in mind, to make motorsport accessible through Trackdays. What started out simply as a bunch of mates with a love of cars and driving fast…</p>
            <a class="btn btn-primary" href="#">Learn more</a>
          </div>
        </div>
      </div>
    </div>

<!-- END ABOUT SECTION -->
```

我们使用的唯一新类是`.text-white`类。这是 Bootstrap 的一个实用类，可以让您使用一些主要颜色来着色字体。您可以在[`getbootstrap.com/docs/4.0/utilities/colors/`](https://getbootstrap.com/docs/4.0/utilities/colors/)上访问文档：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/bf3957fb-8ac2-4200-915f-73be91b4a2bb.png)

Bootstrap 中的文本颜色类。

对于 CSS，我们只需要添加背景和标题上的一点样式：

```html
.about {
  background-image: url(../img/about-us-bg.jpg);
  background-repeat: no-repeat;
  background-size: cover;
}

.about h1.display-1::after {
  content: "";
  display: block;
  background: #BF0000;
  width: 90px;
  height: 2px;
  margin-top: 30px;
}
```

让我们看看它的样子：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/d9733fd1-16a6-48ac-af89-5821475342b4.png)

关于我们部分

这个关于我们部分非常简单；让我们继续到合作伙伴部分。

# 美化合作伙伴部分

对于合作伙伴部分，我们将 HTML 设置为以下内容：

```html
<!-- PARTNERS SECTION -->

    <div class="partners position-relative py-5">
      <div class="container py-5">
        <h3 class="display-3 custom-font-title text-white text-center">PARTNERS</h3>
        <div class="row d-flex justify-content-center py-5">
          <div class="my-auto text-center px-3">
            <img class="pb-2" src="img/partner1.png" alt="Partners Racing Club">
            <p class="font-weight-normal text-white">Advan Neova Cup</p>
          </div>
          <div class="my-auto text-center px-3">
            <img class="pb-2" src="img/partner2.png" alt="Partners Racing Club">
            <p class="font-weight-normal text-white">JDM Style Tuning</p>
          </div>
        </div>
        <div class="row d-flex align-items-center pb-5">
          <div class="mx-auto">
            <a href="#" class="btn btn-primary">Show more</a>
          </div>
        </div>
      </div>
    </div>

<!-- END PARTNERS SECTION -->
```

在上面的代码中，我们使用了`.justify-content-center`类来水平居中两个合作伙伴。其他的都很简单。

在 CSS 方面，我们唯一需要做的就是将背景颜色更改为黑色：

```html
.partners {
  background: #000;
}
```

完成了！有多容易呢？：

！[](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/77f400eb-da8f-4344-ab15-f25816c7a3ae.png)

合作伙伴部分

让我们进入最后一步，也就是页脚。

# 美化页脚

对于页脚，事情会变得更加复杂。HTML 将是这样的：

```html
<!-- FOOTER -->
    <nav class="footer">
      <div class="container d-md-flex align-items-center py-md-5">
        <a class="navbar-brand" href="#"><img src="img/logo-footer.png" class="img-fluid pl-3" alt="Logo Racing Club"></a>
        <ul class="nav d-block d-md-flex pt-5 pt-md-0">
          <li class="nav-item"><a class="nav-link text-white" href="upcoming.html">Upcoming events</a></li>
          <li class="nav-item"><a class="nav-link text-white" href="past.html">Past events</a></li>
          <li class="nav-item"><a class="nav-link text-white" href="faq.html">FAQ</a></li>
          <li class="nav-item"><a class="nav-link text-white" href="about.html">About us</a></li>
          <li class="nav-item"><a class="nav-link text-white" href="blog.html">Blog</a></li>
          <li class="nav-item"><a class="nav-link text-white" href="contact.html">Contact</a></li>
        </ul>

        <ul class="nav ml-auto d-block d-md-flex pb-5 pb-md-0">
          <li class="nav-item"><a class="nav-link text-white" href="login.html">Login</a></li>
          <li class="nav-item"><span class="nav-link"><iframe src="img/like.php?href=http%3A%2F%2Ffacebook.com%2Fphilippehongcreative&width=51&layout=button&action=like&size=small&show_faces=false&share=false&height=65&appId=235448876515718" width="51" height="20" style="border:none;overflow:hidden"></iframe></span></li>
        </ul>
      </div>
    </nav>
    <!-- END FOOTER -->
```

在许多 Bootstrap 类中，有一些响应式实用类可以应用，并且它们始终具有相同的引用：`xs`、`sm`、`md`和`lg`。例如，对于`.d-flex`类，您可以在需要时应用响应式实用类。通过添加`.d-md-flex`，您仅在中等屏幕上应用`display:flex`属性。这非常有用，并且可以应用于许多 Bootstrap 类。

通过良好使用类，我们需要编写的唯一 CSS 是以下内容：

```html
.footer {
  background: #000;
}

.footer .nav-link {
  text-decoration: none;
  font-family: 'built_titling', Helvetica, sans-serif;
  font-weight: 200;
  font-size: 20px;
  letter-spacing: 4px;
} 
```

这就是我们的页脚的样子：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/1e039c8d-f312-4a4a-a978-62a4c4a3dfbc.png)

我们的页脚部分

它是完全响应式的：

![](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/prac-web-dsn/img/0dffa5c5-80b5-4870-8064-0fb4318f6db7.png)

移动端的页脚部分

# 摘要

您看到了 Bootstrap 如何在开发阶段帮助您。如果您能掌握 Bootstrap 的使用，您就可以真正轻松高效地启动或实施任何项目。这就是为什么有这么多开发人员喜欢 Bootstrap，您也应该喜欢。

接下来呢？接下来，我们将介绍服务器端渲染以及为什么它是新的开发趋势。让我们开始吧。
