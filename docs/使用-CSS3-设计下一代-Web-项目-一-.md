# 使用 CSS3 设计下一代 Web 项目（一）

> 原文：[`zh.annas-archive.org/md5/F3C9A89111033834E71A833FAB58B7E3`](https://zh.annas-archive.org/md5/F3C9A89111033834E71A833FAB58B7E3)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

你会感到惊讶，但 CSS3 并不存在。实际上，这个术语用来将许多不同的规范（请参见[`www.w3.org/Style/CSS/current-work`](http://www.w3.org/Style/CSS/current-work)上的列表）分组，每个规范都有自己的工作团队和完成状态。有些仍然是工作草案，而其他一些已经是候选推荐。

本书试图向您展示今天可以使用这项技术做些什么。它分为 10 个项目，每个项目都严重依赖一些新的 CSS 功能，如背景渐变、弹性盒布局或 CSS 滤镜。

所有项目都经过开发和测试，可以在最新的 Chrome 和 Firefox 浏览器上运行良好。其中绝大多数即使在 Internet Explorer 10 上也能良好地呈现和表现。

在可能的情况下，提供了使事情即使在旧浏览器上也能正常工作的解决方法。通过这种方式，引入了不同的技术和工具，如使用 Modernizr 进行特性检测，优雅降级，通过条件注释触发回退属性，以及一堆高质量的 polyfill 库。

本书还专注于不同类型的工具，旨在帮助我们开发相当复杂的 CSS 文档。我说的是 Sass 和 Compass，它们为我们提供了一种更好地组织项目的新语法，以及一堆我们将在本书后面看到的有用函数。

处理供应商实验性前缀很烦人。在本书中，我们将发现如何使用一些库来为我们完成这项任务，无论是客户端还是服务器端。

嗯，这里没有更多要说的了，我希望你会发现这些项目至少和我一样有趣和有趣，从中你会学到新的技术、属性和工具，帮助你在日常工作中。

# 本书涵盖的内容

第一章，没有注册？没有派对！，将向您展示如何为即将到来的派对创建一个订阅表单。我们利用这一章来发现 CSS3 功能，如一些新的伪选择器，如何通过为必填字段或有效/无效字段添加特定样式来增强表单。

第二章，闪亮按钮，将向您展示如何通过使用圆角、多重背景、渐变和阴影等技术来创建一些 CSS3 增强的按钮。然后我们使用经典的`:hover`伪选择器和 CSS3 过渡来对其进行动画处理。

第三章，全能菜单，专注于开发一个根据我们用来查看它的设备而表现不同的菜单。我们使用媒体查询和一个很好的特性检测库来实现这一目标。

第四章，缩放用户界面，使用 CSS3 过渡混合 SVG 图形和新的`:target`伪选择器来创建一个完全功能的缩放用户界面，显示一个很酷的信息图表。

第五章，图像库，将向您展示如何使用纯 CSS3 图像幻灯片显示不同的过渡效果，如淡入淡出、滑动和 3D 旋转，以及多种导航模式。使用新的`:checked`伪选择器可以实现在不同效果之间切换。本章还介绍了 Sass，这是 CSS3 的扩展，我们可以使用它来编写更干净、更可读、更小的 CSS 文件。

第六章，视差滚动，专注于在页面滚动时触发真正的视差效果。这是通过使用 3D 变换属性，如`transform-style`和`perspective`来实现的。

第七章, *视频杀死了电台之星*，通过 CSS3 实验了一些酷炫的视频效果，包括静态和动画遮罩、模糊、黑白等。本章还涉及一些有趣的向后和跨浏览器兼容性问题。

第八章, *转动表盘*，展示了如何通过创建一个可以作为网页小部件使用的动画表盘来充分利用新的 CSS3 属性。该项目还介绍了 Compass：一个 Sass 插件，负责处理实验性前缀、重置样式表等。

第九章, *创建介绍*，通过创建一个使用摄像机在 3D 场景中移动的 3D 动画，将 CSS3 动画提升到另一个水平。

第十章, *CSS 图表*，将向您展示如何使用 CSS3 创建条形图和饼图，而无需使用除 CSS 和 HTML 之外的任何东西。通过正确的 polyfills，我们甚至可以使这些图表在旧版浏览器上表现良好。

# 本书所需内容

要开发本书提供的项目，您需要一个文本编辑器（例如 Sublime Text 2、Notepad++等）和一个 Web 服务器来运行代码。如果您从未安装过 Web 服务器，您可能希望使用预打包的解决方案，如 MAMP for Mac ([`www.mamp.info/en/mamp/index.html`](http://www.mamp.info/en/mamp/index.html))或 WampServer for Windows ([`www.wampserver.com/`](http://www.wampserver.com/))。这些软件包还会安装 PHP 和 MySQL，这些对于运行本书的项目并不需要，因此您可以简单地忽略它们。

一旦您下载、安装并启动了 Web 服务器，您就可以在 Web 服务器的文档根目录中创建项目。

# 本书适合对象

本书专为前端网页开发人员设计。它需要对 CSS 语法和最常见的 CSS2 属性和选择器有扎实的了解。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例，以及它们的含义解释。

文本中的代码单词显示如下："我们使用`:after`伪选择器来访问具有`label`类的元素后面的位置。"

代码块设置如下:

```css
html{
  height: 100%;
  background: black;
  background-image: url('../img/background.jpg');
  background-repeat: no-repeat;
  background-size: cover;
  background-position: top left;
  font-family: sans-serif;
  color: #051a00;
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示:

```css
#old_panel{
 background: rgb(150,130,90);
  padding: 9px 0px 20px 0px;
}
```

任何命令行输入或输出都以以下方式编写:

```css
sass scss/application.scss:css/application.css

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，如菜单或对话框中的单词，会在文本中显示为这样："让我们标记**border-radius**，**box-shadow**，**CSS Gradients**和**multiple backgrounds**。"

### 注意

警告或重要提示会以这样的方式出现在一个框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：不注册？不派对！

CSS3 对于表单来说是一个重大的飞跃。不仅有新的样式可能性可用，而且还可以使用新的强大的伪选择器来修改我们页面的外观，这取决于表单或其字段的状态。在本章中，我们将使用一个派对注册表单作为测试案例，展示如何通过新的 CSS 规范来增强这个组件。我们还将注意如何保持旧浏览器的正确行为。我们将涵盖以下主题：

+   HTML 结构

+   表单

+   基本样式

+   标记必填字段

+   选中的单选按钮技巧

+   计算无效字段

+   气球样式

# HTML 结构

让我们从一些 HTML5 代码开始，来塑造我们项目网页的结构。为此，在一个名为`no_signup_no_party`的新文件夹中创建一个名为`index.html`的文件，其中包含以下标记：

```css
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
  <title>No signup? No party!</title>
  <link rel="stylesheet" type="text/css" 
href="http://yui.yahooapis.com/3.7.3/build/cssreset/cssreset-
min.css">
  <link rel='stylesheet' type='text/css' 
href='http://fonts.googleapis.com/css?family=Port+Lligat+Sans'>
  <link rel='stylesheet' type='text/css' 
href='css/application.css'>
  <script 
src="img/html5.js">
</script>
</head>
<body>
  <article>
    <header>
      <h1>No signup? No party!</h1>
      <p>
        Would you like to join the most amazing party of the 
planet? Fill out this form with your info but.. hurry up! only a 
few tickets are still available!
      </p>
    </header>
    <form name="subscription">
      <!-- FORM FIELDS -->
      <input type="submit" value="Yep! Count me in!">
    </form>
    <footer>
      Party will be held at Nottingham Arena next sunday, for info 
call 555-192-132 or drop us a line at info@nottinghamparties.fun
    </footer>
  </article>
</body>
</html>
```

### 提示

**下载示例代码**

您可以通过您在[`www.packtpub.com`](http://www.packtpub.com)账户中购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

从标记中可以看出，我们正在利用 HTML5 提供的新结构。诸如`<article>`、`<header>`和`<footer>`之类的标签通过为内容添加语义含义来丰富页面。这些标签在语义上比`<div>`更好，因为它们解释了它们的内容。

### 注意

有关更多信息，建议您查看以下文章：[`html5doctor.com/lets-talk-about-semantics`](http://html5doctor.com/lets-talk-about-semantics)

除了口味文本之外，唯一需要详细解释的部分是`<head>`部分。在这个标签内，我们要求浏览器包含一些外部资产，这些资产将帮助我们前进。

## 重置样式表和自定义字体

首先，有一个重置样式表，这对于确保浏览器默认应用于 HTML 元素的所有 CSS 属性被移除非常有用。在这个项目中，我们使用了雅虎免费提供的样式表，基本上将所有属性设置为`none`或等效的值。

接下来，我们要求另一个样式表。这个来自谷歌服务的样式表叫做谷歌网络字体（[www.google.com/webfonts](http://www.google.com/webfonts)），它分发可以嵌入和在网页中使用的字体。自定义网络字体是用特殊的`@font-face`属性定义的，其中包含了浏览器必须实现的字体文件的链接。

```css
@font-face{
  font-family: YourFontName;
  src: url('yourfonturl.eot');
}
```

不幸的是，为了在浏览器之间达到最大可能的兼容性，需要更多的字体文件格式，因此需要更复杂的语句。以下语句有助于实现这种兼容性：

```css
@font-face{
  font-family: YourFontName;
  src: url('yourfonturl.eot');
  src: 
    url('yourfonturl.woff') format('woff'), 
    url('yourfonturl.ttf') format('truetype'), 
    url('yourfonturl.svg') format('svg');
  font-weight: normal;
  font-style: normal;
}
```

谷歌网络字体为我们提供了一个包含我们选择的字体语句的样式表，为我们节省了所有与字体转换相关的麻烦。

接下来，让我们在项目的`css`文件夹下创建一个空的样式表文件。

最后但同样重要的是，我们需要确保即使是较旧的 Internet Explorer 浏览器也能正确处理新的 HTML5 标签。`html5shiv`（[html5shiv.googlecode.com](http://html5shiv.googlecode.com)）是一个小的 JavaScript 文件，正是完成了这个任务。

# 创建表单

现在让我们通过在`<!--FORM FIELDS-->`标记下面添加以下代码来编写表单的 HTML 代码：

```css
<fieldset>
  <legend> 
    Some info about you:
  </legend>
  <input type="text" name="name" id="name" placeholder="e.g. 
Sandro" title="Your name, required" required>
  <label class="label" for="name"> Name: </label>
  <input type="text" name="surname" id="surname" placeholder="e.g. 
Paganotti" title="Your surname, required" required>
  <label class="label" for="surname"> Surname: </label>
  <input type="email" name="email" id="email" placeholder="e.g. 
sandro.paganotti@gmail.com" title="Your email address, a valid 
email is required" required>
  <label class="label" for="email"> E-mail: </label>
  <input type="text" name="twitter" id="twitter" placeholder="e.g. 
@sandropaganotti" title="Your twitter username, starting with @" 
pattern="@[a-zA-Z0-9]+">
  <label class="label" for="twitter"> Twitter:</label>
  <footer></footer>
</fieldset>
```

HTML5 提供了一些新属性，我们将简要探讨如下：

+   `placeholder`：这用于指定在字段为空时显示的一些帮助文本。

+   `required`：这用于将字段标记为必填项。这是一个布尔属性，告诉浏览器在提交表单之前确保字段不为空。该属性是新表单验证功能的一部分，基本上提供了一种在客户端指定一些输入约束的方式。不幸的是，每个浏览器以不同的方式处理`title`属性中包含的错误消息的显示，但我们将在本章稍后进行检查。

+   `pattern`：这是一种指定验证模式的强大且有时复杂的方式。它需要一个正则表达式作为值。然后该表达式将与用户插入的数据进行检查。如果失败，将显示`title`属性中包含的消息。

在给定的示例中，模式值为`@[a-zA-Z0-9]+`，表示“一个或多个出现（`+`符号）在`a-z`（所有小写字母）、`A-Z`（所有大写字母）和`0-9`（所有数字）范围内的字形”。

### 注意

更多可直接使用的模式可以在[`html5pattern.com/`](http://html5pattern.com/)找到。

就像 HTML5 引入的大多数功能一样，甚至在代码中看到的新表单属性在完全浏览器兼容性方面也存在问题。

### 注意

要了解当前浏览器对这些属性以及许多其他 HTML5 和 CSS3 功能的支持情况，建议访问[`caniuse.com/`](http://caniuse.com/)。

## 放错位置的标签

这段代码中还有另一个奇怪之处：标签放置在它们所链接的字段之后。尽管这种标记不常见，但仍然有效，并为我们提供了一些新的有趣选项来拦截表单元素的用户交互。这可能听起来神秘，但我们将在几页后详细分析这种技术。

让我们在刚刚编写的`fieldset`元素下面添加另一个`fieldset`元素：

```css
<fieldset class="preferences">
  <legend> Your party preferences: </legend>
  <input type="radio" name="beers" id="4_beers" value="4">
  <label class="beers" for="4_beers">4 beers</label>
  <input type="radio" name="beers" id="3_beers" value="3">
  <label class="beers" for="3_beers">3 beers</label>
  <input type="radio" name="beers" id="2_beers" value="2">
  <label class="beers" for="2_beers">2 beers</label>
  <input type="radio" name="beers" id="1_beers" value="1">
  <label class="beers" for="1_beers">1 beers</label>
  <input type="radio" name="beers" id="0_beers" value="0" 
required>
  <label class="beers" for="0_beers">0 beers</label>
  <span  class="label"> How many beers?: </span>
  <input type="radio" name="chips" id="4_chips" value="4">
  <label class="chips" for="4_chips">4 chips</label>
  <input type="radio" name="chips" id="3_chips" value="3">
  <label class="chips" for="3_chips">3 chips</label>
  <input type="radio" name="chips" id="2_chips" value="2">
  <label class="chips" for="2_chips">2 chips</label>
  <input type="radio" name="chips" id="1_chips" value="1">
  <label class="chips" for="1_chips">1 chips</label>
  <input type="radio" name="chips" id="0_chips" value="0" 
required>
  <label class="chips" for="0_chips">0 chips</label>
  <span class="label"> How many chips?: </span>
  <footer></footer>
</fieldset>
```

这里没有什么需要强调的；我们只是添加了两个单选按钮组。现在，如果我们尝试在浏览器中运行到目前为止所做的事情，我们将会感到失望，因为默认的浏览器样式已经被重置样式表移除了。

![放错位置的标签](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_01_01.jpg)

是时候添加一些基本样式了！

# 基本样式

我们需要做的是将表单居中，为文本选择合适的大小，选择一个背景，并调整标签和字段的位移。

让我们从背景开始。我们想要实现的是将一张尽可能大的图像放置在页面上，同时保持其比例。在“CSS2 时代”，这个简单的任务可能涉及一些 JavaScript 的使用，比如众所周知的 Redux jQuery 插件（[`bavotasan.com/2011/full-sizebackground-image-jquery-plugin/`](http://bavotasan.com/2011/full-sizebackground-image-jquery-plugin/)）。使用 CSS3 只需要几个语句：

```css
html{
  height: 100%;
  background: black;
  background-image: url('../img/background.jpg');
  background-repeat: no-repeat;
  background-size: cover;
  background-position: top left;
  font-family: sans-serif;
  color: #051a00;
}
```

![基本样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_01_01.1.jpg)

这里的关键是`background-size`属性，它接受以下值：

+   `length`：使用此值，我们可以使用任何测量单位来表示背景的大小，例如`background-size: 10px 10px;`。

+   `percentage`：使用此值，我们可以指定随元素大小变化的背景大小，例如`background-size: 10% 10%;`。

+   `cover`：此值将图像按比例缩放（而不是拉伸），以覆盖整个元素的整个区域。这意味着图像的一部分可能不可见，因为它可能比容器更大。

+   `contain`：此值将图像按比例缩放（而不是拉伸），使其在容器内保持整个图像的最大尺寸。显然，这可能会导致元素的某些区域未被覆盖。

因此，通过使用`cover`，我们确保整个页面将被我们的图像覆盖，但我们可以做得更多！如果我们在浏览器中运行到目前为止所做的所有工作，我们会发现如果我们将窗口放大太多，背景图像的像素会变得可见。为了避免这种情况，我们可以在这个图像的顶部使用另一个背景图像。我们可以使用小黑点来隐藏底层图像的像素，从而获得更好的效果。

好消息是，我们可以在不使用另一个元素的情况下做到这一点，因为 CSS3 允许在同一元素上使用多个背景。我们可以使用逗号（`,`）来分隔背景，要记住的是我们首先声明的将覆盖其他背景。因此，让我们稍微改变前面的代码：

```css
html{
  height: 100%;
  background: black;
  background-image: 
    url('../img/dots.png'), 
    url('../img/background.jpg');
  background-repeat: repeat, no-repeat;
  background-size: auto, cover;
  background-position: center center, top left;
  font-family: sans-serif;
  color: #051a00;
}
```

![基本样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_01_01.2.jpg)

此外，所有其他与背景相关的属性都以相同的方式起作用。如果我们省略一个值，那么将使用前一个值，因此，如果声明了两个背景图像，则写`background-repeat: repeat`与写`background-repeat: repeat, repeat`是相同的。

## 定义属性

让我们继续定义其余的必需属性，以完成项目的第一阶段：

```css
/* the main container */
article{
  width: 600px;
  margin: 0 auto;
  background: #6cbf00;
  border: 10px solid white;
  margin-top: 80px;
  position: relative;
  padding: 30px;
  border-radius: 20px;
}
/* move the title over the main container */
article h1{
  width: 600px;
  text-align: center;
  position: absolute;
  top: -62px;
/* using the custom font family provided by google */
  font-family: 'Port Lligat Sans', cursive;
  color: white;
  font-size: 60px;
  text-transform: uppercase;
}

/* the small text paragraphs */
article p, 
article > footer{
  padding-bottom: 1em;
  line-height: 1.4em;
}

/* the fieldsets' legends */
article legend{
  font-family: 'Port Lligat Sans', cursive;
  display: block;
  color: white;
  font-size: 25px;
  padding-bottom: 10px;
}

.label{
  display: block;
  float: left;
  clear: left;
}

/* positioning the submit button */
input[type=submit]{
  display:block;
  width: 200px;
  margin: 20px auto;
}

/* align texts input on the right */
input[type=text], input[type=email]{
  float: right;
  clear: right;
  width: 350px;
  border: none;
  padding-left: 5px;
}
input[type=text], 
input[type=email], 
.label{
  margin: 2px 0px 2px 20px;
  line-height: 30px;
  height: 30px;
}

span + input[type=radio], legend + input[type=radio]{
  clear: right
}

/* size of the small labels linked to each radio */
.preferences label.chips,
.preferences label.beers{
  width: 60px;
  background-image: none;
}

input[type="radio"]{
  padding-right: 4px;
}

input[type="radio"], 
.preferences label{
  float: right;
  line-height: 30px;
  height: 30px;
}
```

这里只有几件事情需要强调。首先，通过使用一些浮动，我们将所有字段移到右侧，标签移到左侧。接下来，我们定义了一些元素之间的距离。也许最神秘的陈述是以下陈述：

```css
span + input[type=radio], legend + input[type=radio]{
  clear: right
}
```

由于我们刚刚谈到的浮动，每组单选按钮的第一个元素变成了最右边的元素。因此，我们使用`selector1 + selector2`选择器来标识这个元素，该选择器表示指定的元素必须是兄弟元素。这被称为**相邻兄弟选择器**，并选择直接跟在匹配`selector1`选择器的元素后面的所有匹配`selector2`选择器的元素。最后，使用`clear:right`，我们简单地声明右侧不能有其他浮动元素。

让我们在浏览器中重新加载项目，以欣赏我们工作的结果：

![定义属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_01_02.jpg)

# 标记必填字段

让我们来看一个简单的技巧，自动在必填字段的标签旁边显示一个星号(*)。HTML5 表单验证模型引入了一些新的和非常有趣的伪选择器：

+   `:valid`：它仅匹配处于有效状态的字段。

+   `:invalid`：它的工作方式相反，仅匹配具有错误的字段。这包括将`required`属性设置为`true`的空字段。

+   `:required`：它仅匹配带有`required`标志的字段，无论它们是否已填写。

+   `:optional`：它适用于所有没有`required`标志的字段。

在我们的情况下，我们需要匹配所有跟随具有`required`属性的字段的标签。现在我们之前实现的 HTML5 结构派上了用场，因为我们可以利用`+`选择器来实现这一点。

```css
input:required + .label:after, input:required + * + .label:after{
  content: '*';
}
```

我们添加了一个小变化（`input:required + * + .label:after`）以拦截单选按钮的结构。

在继续之前，让我们分析一下这个句子。我们使用`:after`伪选择器来访问具有`label`类的元素后面的位置。然后，使用`content`属性，我们在该位置内注入了星号。

如果我们重新加载页面，我们可以验证现在所有属于带有`required`标志字段的标签都以星号结尾。有人可能指出屏幕阅读器无法识别这种技术。为了避免这种情况，我们可以利用 WAI-ARIA 规范的`aria-required`属性（[`www.w3.org/TR/WCAG20-TECHS/ARIA2`](http://www.w3.org/TR/WCAG20-TECHS/ARIA2)）。

![标记必填字段](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_01_03.jpg)

# 选中的单选按钮技巧

现在我们可以专注于单选按钮，但是如何以更好的方式呈现它们呢？有一个很酷的技巧；它利用了一个事实，即即使通过单击其链接的标签，也可以选中单选按钮。我们可以隐藏输入元素并样式化相应的标签，也许使用代表薯条和啤酒的图标。

让我们从单选按钮标签中删除文本并在鼠标悬停在它们上方时改变光标外观开始：

```css
.preferences label{
  float: right;
  text-indent: -100px;
  width: 40px !important;
  line-height: normal;
  height: 30px;
  overflow: hidden;
   cursor: pointer;
}
```

干得好！现在我们必须隐藏单选按钮。我们可以通过在单选按钮上放置与背景相同颜色的补丁来实现这一点。让我们这样做：

```css
input[type=radio]{
  position: absolute;
  right: 30px;
  margin-top: 10px;
}

input[type=radio][name=chips]{
  margin-top: 35px;
}

span + input[type=radio] + label, 
legend + input[type=radio] + label{
  clear: right;
  margin-right: 80px;
  counter-reset: checkbox;
}

.preferences input[type="radio"]:required + label:after{
  content: '';
  position: absolute;
  right: 25px;
  min-height: 10px;
  margin-top: -22px;
  text-align: right;
  background: #6cbf00;
  padding: 10px 10px;
  display: block;
}
```

如果我们现在尝试使用基于 WebKit 的浏览器或 Firefox 提交表单，我们会发现与单选按钮相关的验证气泡在两者上都正确显示。

## 在单选按钮标签中显示图标

让我们继续处理目前完全为空的单选按钮标签，因为我们使用`text-indent`属性将文本移开。我们现在要做的是在每个标签中放置一个微小的占位图像，并利用 CSS3 的`~`选择器，创建一个带有漂亮鼠标悬停效果的伪星级评分系统。

由于我们必须使用不同的图像（用于啤酒和薯条），所以我们必须复制一些语句。让我们从`.beers`标签开始：

```css
.preferences label.beers{
  background: transparent url('../img/beer_not_selected.png') 
no-repeat center center;
}

.preferences label.beers:hover ~ label.beers, 
.preferences label.beers:hover, 
.preferences input[type=radio][name=beers]:checked ~ label.beers{
  background-image: url('../img/beer.png');
  counter-increment: checkbox;
}
```

`elem1 ~ elem2`选择器适用于所有`elem2`标签，它们是`elem1`标签的兄弟标签，并且跟在它后面（尽管`elem2`标签不必是相邻的）。这样，我们可以使用选择器`.preferences label.beers:hover ~ label.beers`来定位跟随处于悬停状态的标签的所有标签。

使用 CSS3 的`:checked`伪类选择器，我们可以识别已选中的单选按钮，并通过应用刚讨论的相同技巧，我们可以使用`.preferences input[type=radio][name=beers]:checked ~ label.beers`来定位所有跟随已选中单选按钮的标签。通过组合这两个选择器和经典的`.preferences label.beers:hover`选择器，我们现在能够根据用户与单选按钮的交互改变占位图像。现在让我们添加一个最后的很酷的功能。我们已经使用`counter-increment`属性来跟踪所选标签的数量，因此我们可以利用这个计数器并显示它。

```css
.preferences input[type=radio][name=beers]:required + 
label.beers:after{
  content: counter(checkbox) " beers!";
}
```

让我们在浏览器中尝试一下结果：

![在单选按钮标签中显示图标](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_01_04.jpg)

现在，我们也必须为`.chips`标签复制相同的语句：

```css
.preferences label.chips{
  background: transparent 
url('../img/frenchfries_not_selected.png') 
no-repeat center center;
}

.preferences label.chips:hover ~ label.chips, 
.preferences label.chips:hover, 
.preferences input[type=radio][name=chips]:checked ~ label.chips {
 background-image: url('../img/frenchfries.png');
  counter-increment: checkbox;
}

.preferences input[type=radio][name=chips]:required + 
label.chips:after {
  content: counter(checkbox) " chips!";
}
```

在本章中我们所做的所有样式都有一个大问题；如果浏览器不支持 CSS3，它会成功隐藏单选按钮和文本标签，但无法添加它们的图像替换，使一切都无法使用。有几种方法可以防止这种情况发生。这里介绍的方法是使用**媒体查询**。

媒体查询将在以后的项目中详细介绍，基本上是由描述应用某些样式所需的一些条件的语句组成。让我们考虑以下例子：

```css
@media all and (max-width: 1000px){
  body{
    background: red;
  }
}
```

在这个例子中，只有当浏览器窗口的大小不超过`1000px`时，才会将 body 背景变成红色。媒体查询非常有用，可以将特定样式应用于目标设备（智能手机、平板电脑等），但它们还有另一个有趣的特性；如果浏览器支持它们，它也支持我们使用的 CSS3 规则，因此我们可以将在本节和上一节中编写的所有 CSS 都放在媒体查询语句中：

```css
@media all and (min-device-width: 1024px){

/* --- all of this and previous sections' statements --- */

}
```

通过这个技巧，我们解决了另一个微妙的问题。在 iPad 上尝试该项目，如果没有这个媒体查询语句，可能会在单选按钮上点击时出现问题。这是因为 iOS 上的标签不会响应点击。通过实现这个媒体查询，我们强制 iOS 设备回退到常规单选按钮。

# 计算和显示无效字段

在前一节中，我们使用了一些属性而没有解释它们；它们是`counter-reset`和`counter-increment`。此外，我们使用了一个类似函数的命令叫做`counter()`。在本节中，我们将通过创建一个机制来显示无效字段的数量来解释这些属性。**计数器**基本上是一个我们可以命名的变量，其值可以使用`counter-increment`来递增。接下来，这个计数器可以通过在`content`属性中使用`counter(变量名)`声明来显示。

让我们看一个小例子：

```css
<ul>
  <li>element</li>
  <li>element</li>
  <li>element</li>
</ul>
<p></p>

<style>

ul{
  counter-reset: elements;
}

li{
  counter-increment: elements;
}

p:after{
  content: counter(elements) ' elements';
}

</style>
```

尝试这小段代码会得到一个包含句子**3 个元素**的`p`元素。

![计数和显示无效字段](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_01_04.1.jpg)

我们可以将这些强大的属性与新的表单伪选择器结合起来，以获得一种显示有效和无效字段的方法。

## 实现计数器

让我们从创建两个计数器`invalid`和`fields`开始，并在每个`fieldset`元素中重置它们，因为我们想要为每个`fieldset`元素显示无效字段。然后，当我们找到一个无效字段时，我们递增两个计数器，当我们找到一个有效字段时，只递增`fields`计数器。

```css
fieldset{
  counter-reset: invalid fields;
}

input:not([type=submit]):not([type=radio]):invalid, 
input[type=radio]:required:invalid{
  counter-increment: invalid fields;
  border-left: 5px solid #ff4900;
}

input:not([type=submit]):not([type=radio]):valid, 
input[type=radio]:required{
  counter-increment: fields;
  border-left: 5px solid #116300;
}
```

`:not`伪选择器非常直观。它从括号内匹配的元素中减去左侧选择器匹配的元素。如果这看起来有点混乱，让我们试着阅读最后一个选择器：匹配所有`input`元素，其`type`值*不是*`submit`和*不是*`radio`，并响应`:valid`伪选择器。

我们快到了！现在我们有了计数器，让我们使用`footer`元素来显示它们：

```css
fieldset footer{
  clear: both;
  position: relative;
}

fieldset:not([fake]) footer:after{
  content: 'yay, section completed, move on!';
  text-align: right;
  display: block;
  font-size: 13px;
  padding-top: 10px;
}

/* the value of the content property must be on one single line */ 
fieldset > input:invalid ~ footer:after{
  content: counter(invalid) '/' counter(fields) " fields with 
problems; move the mouse over the fields with red marks to see 
details.\a Fields with * are required.";
  white-space: pre;
}
```

`:not([fake])`选择器像之前显示的媒体查询一样使用。我们只想确保只有支持`:valid`和`:invalid`伪选择器的浏览器才能解释这个选择器。

然而，这最后的添加有一些缺点；通常最好避免将演示与内容混合在一起。

# 气球样式

每个浏览器实际上以自己的方式显示表单错误，我们无法对此可视化做太多影响。唯一的例外是基于 WebKit 的浏览器，它们让我们改变这些消息的外观。以下代码显示了在这些浏览器中如何构建错误气球：

```css
<div>::-webkit-validation-bubble
  <div>::-webkit-validation-bubble-arrow-clipper
    <div>::-webkit-validation-bubble-arrow
    </div>
  </div>::-webkit-validation-bubble-message
  <div>
    <b>Browser validation message</b>
    element's title attribute
  </div>
</div>
```

我们可以通过使用前面代码中列出的特殊伪类来访问组成错误消息的所有元素。所以，让我们开始吧！

```css
::-webkit-validation-bubble{
  margin-left: 380px;
  margin-top: -50px;
  width: 200px;
}

input[type=radio]::-webkit-validation-bubble{
  margin-left: 50px;
  margin-top: -50px;
}

::-webkit-validation-bubble-arrow-clipper{
  -webkit-transform: rotate(270deg) translateY(-104px) 
translateX(40px);
}

::-webkit-validation-bubble-arrow{
  background: #000;
  border: none;
  box-shadow: 0px 0px 10px rgba(33,33,33,0.8);
}

::-webkit-validation-bubble-message{
  border: 5px solid black;
  background-image: none;
  box-shadow: 0px 0px 10px rgba(33,33,33,0.8);
}
```

通过`-webkit-transform`，我们对匹配的元素应用了一些变换。在这种情况下，我们将箭头从气球底部移动到左侧。

以下是我们完成的项目的一瞥：

![气球样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_01_05.jpg)

# 优雅降级

正如我们所预期的，这个项目并不完全支持所有浏览器，因为它实现了 HTML5 和 CSS3 的特性，当然，这些特性不包括在旧浏览器中。存在许多技术来解决这个问题；我们现在要看的是**优雅降级**。它基本上侧重于使项目的核心功能尽可能得到广泛支持，同时接受其他一切可能不受支持，因此不会显示。

我们的项目是优雅降级的一个很好的例子：当浏览器不支持特定属性时，其效果会被简单地忽略，而不会影响表单的基本功能。

为了证明这一点，让我们在 IE8 上尝试该项目，因为它基本上不支持 CSS3：

![优雅降级](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_01_06.jpg)

为了实现最佳的浏览器支持，我们可能还需要在 IE9 上隐藏页脚元素和单选按钮，否则它们会被显示，但行为不如预期。为此，我们需要在`index.html`文件的`head`部分结束前添加一个条件注释。我们将在后面的章节中看到条件注释是如何工作的，但现在让我们说它们允许我们指定一些标记，只有选择的浏览器才能解释。

```css
<!--[if IE 9]>
  <style>
    footer, input[name=beers], input[name=chips]{
      display: none;
    }
  </style>
<![endif]-->
```

# 摘要

在这个第一个项目中，我们探讨了 CSS3 如何通过从标记和字段状态中获取的有用信息来增强我们的表单。在下一章中，我们将把注意力集中在按钮上，探讨如何利用渐变和其他 CSS3 属性充分模拟真实世界的形状和行为，而不使用图像。


# 第二章：闪亮按钮

自从它们首次出现在尖端浏览器的夜间构建以来，CSS3 按钮一直被认为是一个热门话题。按钮是大多数用户界面中重要且广为人知的元素。对于 Web 开发人员而言，使它们成为热门话题的原因是 CSS3 按钮易于通过简单更改文本或样式表声明来修改。

在本章中，我们将仅使用 CSS3 创建模仿现实世界对应物的按钮。在这样做的同时，我们将探索新的 CSS 属性和技巧来实现我们的目标。我们将涵盖以下主题：

+   一个投币式按钮

+   `:before`和`:after`伪选择器

+   渐变

+   避免实验性前缀

+   阴影

+   添加标签

+   处理鼠标点击

+   CSS 中的小改变，大结果

+   一个开关

+   活动状态

+   选中状态

+   添加颜色

+   支持旧版浏览器

+   关于 CSS 渐变语法的最后说明

# 创建一个投币式按钮

在本章的第一部分，我们专注于创建一个逼真的投币式按钮。我们希望尽可能多地使用 CSS，并利用新功能而不使用图像。以下截图是结果的一瞥：

![Creating a coin-operated push button](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_02_00.01.jpg)

首先，让我们创建一个名为`shiny_buttons`的文件夹，我们将在其中存储所有项目文件。然后，我们需要一个填充了非常少标记的文件`index.html`：

```css
<!doctype html>
<html>
<head>
  <meta http-equiv="X-UA-Compatible" content="IE=edge"/>
  <meta charset="utf-8">
  <title>Shiny Buttons: from the reality to the web!</title>
  <link 
href='http://fonts.googleapis.com/css?family=Chango|Frijole|
Alegreya+SC:700' rel='stylesheet' type='text/css'>
  <link rel="stylesheet" type="text/css" 
href="http://yui.yahooapis.com/3.4.1/build/cssreset/cssreset-min.css">
  <link rel="stylesheet" type="text/css" 
href="css/application.css">
  <script 
src="img/html5.js"></script>
</head>
<body>
  <section>
    <article id="arcade_game">
 <a href="#" role="button" class="punch">punch</a>
 <a href="#" role="button" class="jump">jump</a>
    </article>

  </section>
</body>
</html>
```

正如标记所示，我们使用单个`<a>`元素来声明我们的按钮。锚标记可能看起来不够复杂，无法产生复杂的按钮，并且让我们相信我们需要更多的 HTML，但事实并非如此。我们可以仅使用此标记以及我们的 CSS3 声明来实现惊人的结果。

# `:before`和`:after`伪选择器

正如我们在上一章中发现的，伪选择器可以被视为元素并且可以在不需要向 HTML 页面添加额外标记的情况下进行样式化。如果我们将`<a>`元素设置为`position:relative`，并且将`:after`和`:before`都设置为`position:absolute`，我们可以使用相对于`<a>`位置的坐标来放置它们。让我们尝试通过在项目中的`css`文件夹中创建一个`application.css`文件来实现这一点：

```css
/* link */
#arcade_game a{
 display: block;
 position: relative;
  text-transform: uppercase;
  line-height: 100px;
  text-decoration: none;
  font-family: 'Frijole', cursive;
  font-size: 40px;
  width: 300px;
  padding: 10px 0px 10px 120px;
  margin: 0px auto;
  color: rgb(123,26,55);
}

/* :before and :after setup */
#arcade_game a:before, 
#arcade_game a:after{
  content: "";
 display: block;
 position: absolute;
  left: 0px;
  top: 50%;
}

/* :before */
#arcade_game a:before{
  z-index: 2;
  width: 70px;
  height: 70px;
  line-height: 70px;
  left: 15px;
  margin-top: -35px;
  border-radius: 35px;
  background-color: red; /* to be removed */
}

/* :after */
#arcade_game a:after{
  z-index: 1;
  width: 100px;
  height: 100px;
  border-radius: 50px;
  margin-top: -50px;
  background-color: green; /* to be removed */
}
```

如果我们在浏览器中加载到目前为止所做的工作，我们开始注意到一个投币式按钮的形状。两个圆，一个在另一个内部，位于标签的左侧，如下截图所示：

![The :before and :after pseudo-selectors](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_02_01.jpg)

我们所做的一切是创建圆形形状，就是施加一个边框半径等于盒子尺寸的一半。干得好！现在我们可以移除绿色和红色的圆形背景，然后继续探索渐变。

# 渐变

在使用 CSS 渐变时，我们指示浏览器的布局引擎根据我们的 CSS 方向绘制图案。**渐变**对应于运行时生成的、大小独立的图像，因此可以在允许`url()`表示法的任何地方使用。有四种类型的渐变：`linear-gradient`，`repeating-linear-gradient`，`radial-gradient`和`repeating-radial-gradient`。以下渐变代码示例提供了对它们的简要概述：

```css
<!doctype html>
<html>
<head>
  <meta charset="utf8">
  <title>Explore gradients</title>

  <style>
    .box{
      width: 400px;
      height: 80px;
      border: 3px solid rgb(60,60,60);
      margin: 10px auto;
      border-radius: 5px;
      font-size: 30px;
      text-shadow: 2px 2px white;
    }

    #linear{
 background-image: linear-gradient(top left, red, white, green);
    }

    #repeating_linear{
 background-image: repeating-linear-gradient(top left, red, white, red 30%);
    }

    #radial{
 background-image: radial-gradient(center center, ellipse cover, white, blue);
    }

    #repeating_radial{
 background-image: repeating-radial-gradient(center center, ellipse cover, white, blue, white 30px);
    }

    #collapsed_linear{
 background-image: linear-gradient(left, red, red 33%, white 33%, white 66%, green 66%);
    }

    #collapsed_radial{
 background-image: radial-gradient(center center, ellipse contain, white, white 55%, blue 55%);
    }

  </style>

</head>
<body>
  <section>

    <div id="linear" class="box">linear</div>
    <div id="repeating_linear" class="box">repeating_linear</div>
    <div id="radial" class="box">radial</div>
    <div id="repeating_radial" class="box">repeating_radial</div>
    <div id="collapsed_linear" class="box">collapsed_linear</div>
    <div id="collapsed_radial" class="box">collapsed_radial</div>

  </section>
</body>
</html>
```

## 渐变语法

在前面的渐变代码示例中，很明显每个语句都包含位置信息（例如`top left`或`45deg`）和颜色步骤，这些颜色步骤可以选择性地具有指示颜色停止的值。如果两种颜色停在完全相同的位置，我们将获得一个锐利的颜色变化而不是渐变。

径向渐变允许额外的参数。特别是，我们可以选择渐变的形状，圆形和椭圆形之间，以及渐变如何填充元素的区域。具体来说，我们可以在以下选项中进行选择：

+   `closest-side`：使用此参数，渐变会扩展直到与包含元素的最近一侧相遇

+   `closest-corner`：使用此参数，渐变会扩展到达包含元素的最近一角

+   `farthest-side`：使用此参数，渐变会扩展到达包含元素的最远一侧

+   `farthest-corner`：使用此参数，渐变会扩展到达包含元素的最远一角

+   `包含`：这是`closest-side`的别名

+   `cover`：这是`farthest-corner`的别名

以下截图显示了在浏览器中执行前面代码的结果：

![渐变语法](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_02_02.jpg)

不幸的是，之前的截图并没有说明我们在 web 浏览器中运行示例代码时看到的情况。事实上，如果我们在支持 CSS3 渐变的浏览器（例如 Google Chrome）中执行之前的代码，我们得到的是一列带有黑色边框的白色框。这是因为渐变被视为实验性质的，因此需要为每个我们想要支持的浏览器添加特定的前缀（例如，`-webkit-`，`-ms-`，`-o-`和`-moz-`）。这意味着我们必须为每个想要支持的浏览器重复声明。例如，在之前代码中的`#linear`选择器中，为了实现最大的兼容性，我们应该写成：

```css
#linear{
  background-image: -webkit-linear-gradient(top left, red, white, 
green);
  background-image: -ms-linear-gradient(top left, red, white, 
green);
  background-image: -o-linear-gradient(top left, red, white, 
green);
  background-image: -moz-linear-gradient(top left, red, white, 
green);
  background-image: linear-gradient(top left, red, white, green);
}
```

# 避免实验性前缀

我们需要找到一种方法来避免编写大量重复的 CSS 代码，以实现所有现有的浏览器实验性前缀。一个很好的解决方案是由 Lea Verou 创建的 Prefix Free（[`leaverou.github.com/prefixfree/`](http://leaverou.github.com/prefixfree/)），这是一个小型的 JavaScript 库，它可以检测用户的浏览器并动态添加所需的前缀。要安装它，我们只需要在项目中的`js`文件夹中下载`.js`文件，命名为`prefixfree.js`，并在`index.html`中的`css`请求之后添加相应的脚本标签。

```css
<script src="img/prefixfree.js"></script>
```

从现在开始，我们不再需要担心前缀，因为这个库会为我们完成繁重的工作。然而，也有一些小的缺点；有些属性不会自动检测和添加前缀（例如，`radial-gradient`和`repeating-radial-gradient`不会添加`-moz-`前缀），并且我们需要忍受一个短暂的延迟，大致等于脚本下载时间，才能正确地添加前缀。

因此，让我们继续向我们的按钮添加一些渐变：

```css
#arcade_game a:before, #arcade_game a:after{
  background: gray;  /* to be removed */
}

#arcade_game a:before{
  background-image: 
    -moz-radial-gradient(7px 7px, ellipse farthest-side, 
    rgba(255,255,255,0.8), rgba(255,255,255,0.6) 3px, 
    rgba(200,200,200,0.0) 20px);
 background-image: 
 radial-gradient(7px 7px, ellipse farthest-side, 
 rgba(255,255,255,0.8), rgba(255,255,255,0.6) 3px, 
 rgba(200,200,200,0.0) 20px);
}

#arcade_game a:after{
  background-image: 
    -moz-radial-gradient(7px 7px, ellipse farthest-side, 
    rgba(255,255,255,0.8), rgba(255,255,255,0.6) 3px, 
    rgba(200,200,200,0.0) 20px), 
    -moz-radial-gradient(50px 50px, rgba(255,255,255,0), 
    rgba(255,255,255,0) 40px, rgba(200,200,200,0.1) 43px, 
    rgba(255,255,255,0.0) 50px);
 background-image: 
 radial-gradient(7px 7px, ellipse farthest-side, 
 rgba(255,255,255,0.8), rgba(255,255,255,0.6) 3px, 
 rgba(200,200,200,0.0) 20px), 
 radial-gradient(50px 50px, rgba(255,255,255,0), 
 rgba(255,255,255,0) 40px, rgba(200,200,200,0.1) 43px, 
 rgba(255,255,255,0.0) 50px);
}
```

为了专注于向我们的按钮添加新功能的主题，前面的代码没有重复现有的`application.css`中的 CSS 声明。无论我们如何应用新的指令，我们都可以追加之前的声明或合并每个选择器的属性。无论如何，结果都是一样的。

使用上述代码，我们使用径向渐变创建了两个光点，模拟了我们按钮的形状和反射。CSS3 允许我们通过支持`rgba()`符号来创建这种效果，该符号接受`0`（透明）到`1`（不透明）之间的 alpha 值。

让我们在浏览器中尝试一下结果：

![避免实验性前缀](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_02_03.jpg)

## CSS3 渐变的即将到来的语法更改

关于 CSS3 渐变的最新编辑草案（[`www.w3.org/TR/2012/CR-css3-images-20120417/`](http://www.w3.org/TR/2012/CR-css3-images-20120417/)）在提供关键字定义位置信息时引入了一个小的语法更改。因此，我们不再需要写：

```css
linear-gradient(bottom, blue, red);
```

现在我们需要写成：

```css
linear-gradient(to top, blue, red);
```

对于径向渐变的语法，还有一些更改；因此，我们之前写的：

```css
radial-gradient(center center, ellipse cover, white, blue);
```

被更改为：

```css
radial-gradient(cover ellipse at center center, white, blue);
```

不幸的是，这种新的语法在撰写本书时在各种浏览器中的支持并不好。因此，我们将继续使用旧的语法，因为它有很好的支持。

# 阴影

CSS3 中实现阴影有两个不同的属性，具有相似的语法，`box-shadow`和`text-shadow`。让我们创建另一个示例来展示它们的工作原理：

```css
<!doctype html>
<html>
<head>
  <meta charset="utf8">
  <title>Explore Shadows!</title>

  <style>
    .box{
      width: 400px;
      height: 80px;
      border: 3px solid rgb(60,60,60);
      margin: 30px auto;
      border-radius: 5px;
      line-height: 80px;
      text-align: center;
    }  
    #outset{
      box-shadow: 10px 10px 3px rgb(0,0,0);
    }
    #inset{
      box-shadow: 10px 10px 3px rgb(0,0,0) inset;
    }
    #offset{
      box-shadow: 0px 0px 0px 10px rgb(0,0,0);
    }
    #text{
      text-shadow: 10px 10px 3px rgb(0,0,0);
    }

  </style>

  <script src="img/prefixfree.js"></script>
</head>
<body>
  <section>

    <div id="outset" class="box"></div>
    <div id="inset" class="box"></div>
    <div id="offset" class="box"></div>
    <div id="text" class="box">Some text</div>

  </section>
</body>
</html>
```

实质上，`box-shadow` 和 `text-shadow` 是相似的。这两个属性都有阴影偏移（前两个参数）和模糊（第三个参数）。只有 `box-shadow` 有一个可选的第四个参数，用于控制阴影的扩散或模糊的距离。

接下来是颜色，然后，仅对于 `box-shadow` 属性，还有一个额外的关键字 `inset`，它导致阴影落在元素内部而不是外部。最后，可以用逗号（`,`）分隔定义更多阴影。

以下截图显示了在浏览器中执行上述代码的结果：

![阴影](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_02_04.jpg)

有了这些新知识，我们现在可以向我们的按钮添加更多效果。让我们在 `application.css` 中添加一些属性：

```css
/* shadows */
#arcade_game a:before{
  box-shadow: 
    0px 0px 10px rgba(0,0,80,0.7), 
    0px 0px 4px rgba(0,0,0,0.4), 3px 3px 6px rgba(0,0,0, 0.5), 
    2px 2px 1px  rgba(255,255,255,0.3) inset, 
    10px 10px 20px rgba(0,0,0,0.1) inset;
}
#arcade_game a:after{
  box-shadow: 
    1px 0px 1px rgba(0,0,0, 0.7), 
    6px 0px 4px rgba(0,0,0, 0.6), 
    0px 1px 0px rgba(200,200,200,0.7) inset, 
    2px 2px 1px  rgba(255,255,255,0.3) inset;
}
```

然后，在浏览器中重新加载项目。

![阴影](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_02_05.jpg)

# 添加标签

每个按钮必须有自己的符号。为了获得这个结果，我们可以使用 HTML5 的 `data-*` 属性，比如 `data-symbol`。HTML5 认为所有 `data-*` 属性都是有效的，并且可以自由地由开发人员用来保存一些特定于应用程序的信息，就像在这种情况下一样。然后，我们可以使用 `content` 属性将自定义属性的值插入到按钮中。让我们看看如何做，但首先我们需要更新我们的 `<a>` 元素。所以让我们编辑 `index.html`：

```css
<a href="#" class="punch" data-symbol="!">PUNCH</a>
<a href="#" class="jump" data-symbol="★">JUMP</a>
```

### 注意

要输入黑星（★）（Unicode 字符：U+2605），我们可以从[`www.fileformat.info/info/unicode/char/2605/index.htm`](http://www.fileformat.info/info/unicode/char/2605/index.htm)复制粘贴，或者我们可以使用 Windows 中包含的字符映射。

接下来，我们需要在 `application.css` 中添加适当的说明：

```css
/* text */
#arcade_game a:before{
  font-family: 'Chango', cursive;
  text-align: center;
  color: rgba(255,255,255, 0.4);
  text-shadow: -1px -1px 2px rgba(10,10,10, 0.3);
  content: attr(data-symbol);
}
```

以下截图显示了浏览器中的结果：

![添加标签](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_02_06.jpg)

事实上，我们可以通过修改 `data-symbol` 属性的值来简单地改变按钮的符号。

# 处理鼠标点击

几乎完成了！现在我们需要使按钮更具响应性。为了实现这一点，我们可以利用 `:active` 伪选择器来修改一些阴影。让我们在 `application.css` 中添加以下行：

```css
/* active */
#arcade_game a:active:before{
  background-image: none;
  box-shadow: 
    0px 0px 7px rgba(0,0,80,0.7), 
    0px 0px 4px rgba(0,0,0,0.4), 
    10px 10px 20px rgba(0,0,0,0.3) inset;
 line-height: 65px;
}

#arcade_game a:active:after{
  background-image: 
    -moz-radial-gradient(7px 7px, ellipse farthest-side, 
    rgba(255,255,255,0.8), rgba(255,255,255,0.6) 3px, 
    rgba(200,200,200,0.0) 20px),
    -moz-radial-gradient(53px 53px, rgba(255,255,255,0), 
    rgba(255,255,255,0) 33px, rgba(255,255,255,0.3) 36px, 
    rgba(255,255,255,0.3) 36px, rgba(255,255,255,0) 36px);
  background-image: 
    radial-gradient(7px 7px, ellipse farthest-side, 
    rgba(255,255,255,0.8), rgba(255,255,255,0.6) 3px, 
    rgba(200,200,200,0.0) 20px),
    radial-gradient(53px 53px, rgba(255,255,255,0), 
    rgba(255,255,255,0) 33px, rgba(255,255,255,0.3) 36px, 
    rgba(255,255,255,0.3) 36px, rgba(255,255,255,0) 36px);
}
```

通过增加 `line-height` 属性的值，我们将符号向下移动了一点，给人一种它已经被按钮按下的错觉。让我们重新加载浏览器中的项目并检查结果：

![处理鼠标点击](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_02_07.jpg)

# CSS 中的小改变，大结果

我们现在已经完成了第一种按钮。在继续下一个之前，我们最好停顿一下，意识到我们编写的所有阴影和渐变基本上都是无色的；它们只是为底色添加了白色或黑色。这意味着我们可以为每个按钮选择不同的背景颜色。所以让我们在 `application.css` 中添加以下代码：

```css
 /* puch */
#arcade_game .punch:after, #arcade_game .punch:before{
  background-color: rgb(123,26,55);
}

#arcade_game .punch{
  color: rgb(123,26,55);
}

/* jump */
#arcade_game .jump:after, #arcade_game .jump:before{
  background-color: rgb(107,140,86);
}

#arcade_game .jump{
  color:  rgb(107,140,86);
}
```

以下截图显示了结果：

![CSS 中的小改变，大结果](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_02_08.jpg)

# 创建一个开关

好的，现在我们将样式一些复选框按钮，尝试匹配一些录音室按钮（"REC"）的外观。以下是最终结果的截图：

![创建一个开关](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_02_08.02.jpg)

首先，让我们在 `index.html` 中添加复选框，就在之前的 `article` 元素后面：

```css
<article id="old_panel">
  <form>
    <input type="checkbox" id="rec">
    <label class="rec" for="rec">RECORD</label>
    <input type="checkbox" id="at_field">
    <label class="at_field" for="at_field">AT FIELD</label>
  </form>
</article>
```

就像在上一章中所做的那样，我们现在想隐藏 `input` 元素。让我们通过在 `application.css` 中添加几行来实现这一点：

```css
#old_panel input{
  visibility: hidden;
  position: absolute;
  top: -999px;
  clip: 'rect(0,0,0,0)';
}

#old_panel label{
  display: block;
  position: relative;
  width: 300px;
  padding-left: 125px;
 cursor: pointer;
  line-height: 140px;
  height: 130px;
  font-family: 'Alegreya SC', serif;
  font-size: 40px;
  margin: 0px auto;
  text-shadow: 1px 1px 1px rgba(255,255,255, 0.3), -1px -1px 1px 
rgba(10,10,10, 0.3);
}
```

很好！我们希望这个元素像某种按钮一样工作，所以我们使用 `cursor` 属性强制光标采用指针图标。

## 创建一个遮罩

现在我们为 `article` 元素设置了背景颜色。这对我们即将构建的内容非常重要。

```css
#old_panel{
 background: rgb(150,130,90);
  padding: 9px 0px 20px 0px;
}
```

接下来，我们关注 `:before` 和 `:after` 伪选择器：

```css
#old_panel label:before{
  content: '';
  z-index: 1;
  display: block;
  position: absolute;
  bottom: 0px;
  left: 0px;
  width: 126px;
  height: 131px;
  background-image: 
    -moz-radial-gradient(50% 50%, circle, 
    rgba(0,0,0,0.0), 
    rgba(0,0,0,0.0) 50px, 
    rgb(150,130,90) 50px);
 background-image: 
 radial-gradient(50% 50%, circle, 
 rgba(0,0,0,0.0), 
 rgba(0,0,0,0.0) 50px, 
 rgb(150,130,90) 50px);
}
```

我们现在所做的是使用渐变作为一种遮罩。实质上，我们创建了一个半径为 `50px` 的透明圆，然后我们使用背景颜色来覆盖剩余的区域。

好的，现在是棘手的部分。为了模拟按钮的形状，我们创建一个带有圆角的框，然后使用`box-shadow`属性来产生高度的错觉。

```css
#old_panel label:after{
  content: 'OFF';
  display: block;
  position: absolute;
  font-size: 20px;
  text-align: center;
  line-height: 60px;
  z-index: 2;
  bottom: 30px;
  left: 30px;
  width: 60px;
  height: 65px;
  border-radius: 7px;
  background-image: 
    -moz-radial-gradient(30px -15px, circle, 
    rgba(255,255,255,0.1), rgba(255,255,255,0.1) 60px, 
    rgba(255,255,255,0.0) 63px);
  background-image: 
    radial-gradient(30px -15px, circle, 
    rgba(255,255,255,0.1), rgba(255,255,255,0.1) 60px, 
    rgba(255,255,255,0.0) 63px);
  box-shadow: 
    0px 1px 0px rgba(255,255,255,0.3) inset, 
    0px -11px 0px rgba(0,0,0,0.4) inset, 
    -3px 9px 0px 0px black, 
    3px 9px 0px 0px black, 
    0px 10px 0px 0px rgba(255,255,255,0.3), 
    -4px 9px 0px 0px rgba(255,255,255,0.3), 
    4px 9px 0px 0px rgba(255,255,255,0.3), 
 0px 0px 0px 30px rgb(150,130,90);

  border: 
    3px solid rgba(0,0,0,0.2);
    border-bottom: 3px solid rgba(0,0,0,0.4);
  background-clip: padding-box;
}
```

阴影的最后一个声明（高亮显示的声明）也被用作遮罩。它与背景颜色相同，并且在我们刚刚创建的框周围扩展了`30px`，覆盖了我们之前用前一个渐变声明的透明区域。

这到底是什么？让我们试着用一个方案来解释一下：

![创建遮罩](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_02_09.jpg)

前面的图显示了我们使用的三个形状，一个在另一个上面。如果我们关闭`box-shadow`，那么在`label:before`上设置的每个颜色都将在`label:before`的`background-image`属性创建的遮罩内可见。

为了查看我们到目前为止所做的工作，让我们在浏览器中加载项目：

![创建遮罩](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_02_10.jpg)

# 活动状态

现在我们需要像以前一样处理活动状态。为了模拟压力，我们降低了元素的高度，并改变了一些阴影的偏移。

```css
  #old_panel label:active:after{
    height: 54px;
    box-shadow: 
      0px 0px 0px 3px black,
      -3px 9px 0px 0px black,
      3px 9px 0px 0px black,
      0px 0px 0px 4px rgba(255,255,255,0.3),
      0px 10px 0px 0px rgba(255,255,255,0.3),
      -4px 9px 0px 0px rgba(255,255,255,0.1),
      4px 9px 0px 0px rgba(255,255,255,0.1),
      0px 0px 0px 30px rgb(150,130,90);
  }
```

让我们在浏览器中试一试：

![活动状态](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_02_11.jpg)

# 添加已选状态

现在，我们基本上要做的是将标签的文本从 OFF 更改为 ON，并删除`box-shadow`遮罩，以暴露我们将用来模拟从按钮传播光的背景颜色。

```css
#old_panel input:checked + label:not(:active):after{
  content: 'ON';
  background-clip: border-box;
  box-shadow: 
    0px 1px 0px rgba(255,255,255,0.3) inset, 
    0px -11px 0px rgba(0,0,0,0.4) inset, 
    -3px 9px 0px 0px black, 
    3px 9px 0px 0px black, 
    0px 10px 0px 0px rgba(255,255,255,0.3), 
    -4px 9px 0px 0px rgba(255,255,255,0.3), 
    4px 9px 0px 0px rgba(255,255,255,0.3);
}

#old_panel input:checked + label:not(:active):before{
  background-image: 
    -moz-radial-gradient(50% 57%, circle, 
    rgba(150,130,90,0.0), 
    rgba(150,130,90,0.3) 40px, 
    rgb(150,130,90) 55px);
  background-image: 
    radial-gradient(50% 57%, circle, rgba(150,130,90,0.0), 
    rgba(150,130,90,0.3) 40px, 
    rgb(150,130,90) 55px);
}
```

我们不希望在按钮仍然被按下时激活这种效果，因此我们添加了`:not(:active)`伪选择器。

# 添加颜色

让我们为每个按钮设置不同的颜色。这一次，我们需要为关闭状态和打开状态分别指定一种颜色：

```css
 /* -- record -- */
#old_panel input:checked + label.rec:not(:active):before, #old_panel input:checked + label.rec:not(:active):after{
  background-color: rgb(248,36,21);
}

#old_panel label.rec:before{
  background-color: rgb(145,67,62);
}
/* -- at field -- */
#old_panel input:checked + label.at_field:not(:active):before, #old_panel input:checked + label.at_field:not(:active):after{
  background-color: rgb(61,218,216);
}

#old_panel label.at_field:before{
  background-color: rgb(29,51,200);
}
```

以下的截图显示了结果：

![添加颜色](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_02_12.jpg)

# 支持旧版浏览器

这个项目不打算在旧版浏览器上优雅地降级，因此我们需要应用一种不同的技术来检测这个项目所需的功能是否缺失，并提供一种替代的 CSS2 样式表。

为此，我们依赖于一个名为`Modernizr.js`的 JavaScript 库（[`modernizr.com/`](http://modernizr.com/)），它显示了每个 HTML5/CSS3 功能的方法。这些方法根据所需功能的存在与否简单地返回`true`或`false`。然后，我们将使用`Modernizr.js`中包含的一个小库，称为 yepnope.js（[`yepnopejs.com`](http://yepnopejs.com)），动态选择我们想要加载的样式表。

首先，我们需要下载这个库。为此，我们必须在下载页面[`modernizr.com/download/`](http://modernizr.com/download/)上标记对应于我们想要测试的功能的复选框，然后点击**Generate**按钮，然后点击**Download**按钮，将文件保存为`modernizr.js`，保存在我们项目的`js`文件夹下。

好的，现在我们需要在我们的`index.html`文件的`<head>`标签中做一些更改，以使这个新技巧起作用。新的`<head>`部分如下所示：

```css
<head>
  <meta charset="utf8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />
  <title>Shiny Buttons: from the reality to the web!</title>
  <link 
href='http://fonts.googleapis.com/css?family=Chango|Frijole|Alegre
ya+SC:700' rel='stylesheet' type='text/css'>
  <link rel="stylesheet" type="text/css" 
href="http://yui.yahooapis.com/3.4.1/build/cssreset/cssreset-
min.css">
  <script 
src="img/html5.js"></script>
  <script src="img/modernizr.js"></script>
 <script>
 yepnope({
 test : Modernizr.borderradius && Modernizr.boxshadow && 
Modernizr.multiplebgs && Modernizr.cssgradients, 
 yep  : ['css/application.css','js/prefixfree.js'], 
 nope : 'css/olderbrowsers.css'
 });
 </script>

</head>
```

我们只需要记住创建一个`css/olderbrowsers.css`文件，其中包含一些 CSS2 指令，用于为旧版浏览器样式化这些元素，例如以下指令：

```css
#arcade_game a{
  display: block;
  margin: 20px auto;
  width: 200px;
  text-align: center;
  font-family: 'Frijole', cursive;
  font-size: 40px;
  color: white;
  text-decoration: none;
}

/* puch */
#arcade_game .punch{
  background-color: rgb(123,26,55);
}

/* jump */
#arcade_game .jump{
  background-color: rgb(107,140,86);
}

#old_panel{
  text-align: center;
}

#old_panel label{
  font-family: 'Alegreya SC', serif;
  font-size: 40px;
}
```

我们还必须考虑，仅依赖 JavaScript 有时可能是一个危险的选择，因为我们没有提供非 JavaScript 的替代方案。一个简单的解决方法可能是将`olderbrowsers.css`设置为默认样式表，然后仅在所需的 CSS3 属性得到支持时动态加载`application.css`。

然而，为了这样做，我们必须在`application.css`中添加一些行来避免`olderbrowsers.css`的属性：

```css
/* === [BEGIN] VOIDING BASE CSS2 === */

#arcade_game a{
  background-color: transparent !important;
  width: 300px !important;
  text-align: left !important;
}

#old_panel{
  text-align: left !important;
}

/* === [END] VOIDING BASE CSS2 === */
```

最后，我们可以按照以下方式更改我们之前的 HTML 代码：

```css
<link rel="stylesheet" type="text/css" 
href="css/olderbrowsers.css">
<script>
  yepnope({
    test : Modernizr.borderradius && Modernizr.boxshadow && 
Modernizr.multiplebgs && Modernizr.cssgradients, 
    yep  : ['css/application.css','js/prefixfree.js']
  });
</script>
```

# 支持 IE10

Internet Explorer 10 支持该项目中展示的所有 CSS 特性。然而，我们不得不面对一个事实，即 Prefix Free 在`radial-gradient`符号上没有添加`-ms-`实验性前缀。这并不是一个大问题，因为我们的按钮即使没有渐变也能正常工作，除了我们在 ON/OFF 开关中用作蒙版的`radial-gradient`符号。为了解决这个问题，我们可以在`application.css`中添加以下行：

```css
#old_panel label:before{
  background-image: 
  -ms-radial-gradient(50% 50%, circle, 
  rgba(0,0,0,0.0), 
  rgba(0,0,0,0.0) 50px, 
  rgb(150,130,90) 50px);
}
```

# 总结

这个项目详细介绍了渐变和阴影，演示了如何利用一小组 HTML 元素来实现惊人的效果。

在进入下一章之前，了解一下在线渐变生成器可能会很有用，它们可以让我们使用友好的 UI 来组合渐变，然后提供正确的 CSS 语法以包含在我们的样式表中。它们可以在[`www.colorzilla.com/gradient-editor/`](http://www.colorzilla.com/gradient-editor/)、[`www.cssbuttongenerator.com/`](http://www.cssbuttongenerator.com/)和[`css3generator.com/`](http://css3generator.com/)找到。

在下一章中，我们将学习如何通过创建一个在桌面和智能手机上都能工作的菜单来处理多个设备的可视化。


# 第三章：Omni 菜单

使用媒体查询，我们可以在满足某些设备或视口要求时激活或停用 CSS 指令。当我们需要处理需要根据用户设备具有不同表示的元素时，这是非常有用的。菜单通常就是这样的一个元素。在本章中，我们将开发一个主菜单系统，可以在桌面浏览器和移动设备上完美显示；我们可以称之为 Omni 菜单。我们将涵盖以下主题：

+   设置操作

+   第一级

+   第二级

+   移动部件

+   基本过渡

+   介绍动画

+   添加一些颜色

+   媒体查询

+   移动版本

+   提高速度

在下一节中，我们将开始创建一个基本的 HTML 菜单结构。通常情况下，我们可以将项目的所有文件存储在一个以项目名称（在本例中为`omni_menu`）命名的文件夹中。在开始之前，让我们先看一下最终结果的截图：

![Omni 菜单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_00.01.jpg)

# 设置操作

要为菜单设置样式，我们需要先定义标记。让我们编写一个小的 HTML 文件`index.html`，在其中我们将使用`li`和`ul`项目定义一个经典的两级菜单结构。接下来，我们将在转到本章的核心部分之前添加一些基本的 CSS。

```css
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta http-equiv="X-UA-Compatible" content="IE=edge" />

  <title> Omnimenu: good for desktop, good for mobile </title>

 <link rel="stylesheet" type="text/css" 
href="http://yui.yahooapis.com/3.7.3/build/cssreset/
cssreset-min.css" data-noprefix>

  <link rel="stylesheet" type="text/css" 
href="css/application.css">

  <script src="img/prefixfree.js"></script>
</head>
<body>
  <nav>
    <ul>
      <li data-section="about-me">
        <a href="#" class="item"> About me </a>
        <ul>
          <li><a href="#" class="item">Early years</a></li>
          <li><a href="#" class="item">First works</a></li>
          <li><a href="#" class="item">Today and tomorrow</a></li>
          <li class="cursor"><a href="#" class="item"> back </a>
          </li> 
        </ul>
      </li>
      <li data-section="portfolio">
        <a href="#" class="item"> Portfolio </a>
        <ul>
          <li> <a href="#" class="item"> Design </a> </li>
          <li> <a href="#" class="item"> Articles </a> </li>
          <li class="cursor"> <a href="#" class="item"> back </a>
          </li>
        </ul>
      </li>
      <li data-section="interests">
        <a href="#" class="item"> Interests </a>
        <ul>
          <li> <a href="#" class="item"> Skying </a> </li>
          <li> <a href="#" class="item"> Snowboarding </a> </li>
          <li> <a href="#" class="item"> Wakeboarding </a> </li>
          <li class="cursor"> <a href="#" class="item"> back </a>
          </li>
        </ul>
      </li>
      <li class="cursor"></li>
    </ul>
  </nav>

</body>
</html>
```

我们利用新的`data-*`属性来语义化地增强菜单第一级中的项目。我们稍后还将看到这些属性如何帮助我们更好地样式化这个结构。

现在让我们打开`application.css`，定义一个基本的 CSS 结构来居中这个菜单并添加一个漂亮的背景。对于项目的这一部分，我们不关注移动布局，所以我们可以使用经典的 960 像素方法：

```css
/* === [BEGIN] Style === */
html{
  height: 100%;
}

body{
 background-image: repeating-linear-gradient(315deg, #ddd, #ddd 
40px, #aaa 40px, #aaa 80px);
  padding: 20px;
  height: 100%;
}

nav{
  margin: 0 auto;
  width: 960px;
  font-family: sans-serif;
  font-size: 0.6em;
  background-color: rgb(86,86,86);
  background-image: linear-gradient(bottom, rgb(75,75,75), 
rgb(86,86,86));
  border-radius: 4px;
  box-shadow: 0 0 10px rgba(0,0,0,0.1), 0 -1.5em 0 rgba(0,0,0,0.1) 
inset, 0 1px 1px 1px rgba(0,0,0,0.1) inset;
}

nav > ul{
  padding: 0 10px;
}

/* === [END] Style === */
```

上述代码中的高亮部分定义了一个折叠的渐变，以获得条纹背景。接下来我们将`nav`元素的大小定义为`960px`，并在其上添加一些漂亮的渐变、阴影和边框半径。

如果我们在支持 CSS3 的浏览器中加载项目，我们可以查看我们的第一个样式效果：

![设置操作](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_01.jpg)

# 样式化第一级项目

许多两级菜单的典型格式是在同一行上水平显示第一级项目，然后隐藏第二级项目。我们将添加一些 CSS 代码到`application.css`中来实现这一点，如下所示：

```css
nav > ul > li{
 display: inline-block;
  vertical-align: top;
  line-height: 3em;
  width: 100px;
  z-index: 2;
  position: relative;
  border-left: 1px solid #313131;
  box-shadow: 1px 0 1px rgba(255,255,255,0.1) inset, -1px 0 1px 
rgba(255,255,255,0.1) inset;
}

nav > ul > li:nth-last-child(2){
  border-right: 1px solid #313131;
}

nav > ul > li > ul{
  position: absolute;
  left: -1px;
  top: 3em;
  clip: rect(0,0,0,0);
  opacity: 0;
}
```

## 使用 inline-block 显示

在上述代码中，我们使用了`display: inline-block`而不是通常使用的浮动元素。这两个属性通常用于将元素内联对齐，但不同之处在于`display: inline-block`不会破坏页面流，并且可以节省我们使用`clearfix`。然而，使用`display: inline-block`属性也有一个缺点。让我们在一个小的演示中看看：

```css
<!doctype html>
<html>
  <head>
    <title>inline-block demo</title>
    <style>
      div{
        display: inline-block;
        width: 100px;
        border: 1px solid black;
        height: 30px;
        line-height: 30px;
        text-align: center;
      }
    </style>
  </head>
  <body>
    <div> ONE </div>
    <div> TWO </div>
    <div> THREE </div><div> FOUR </div>
  </body>
</html>
```

如果我们在浏览器中加载我们的演示页面，结果如下：

![使用 inline-block 显示](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_02.jpg)

您会注意到**THREE**和**FOUR**之间没有空格，但**ONE**、**TWO**和**THREE**之间有空格。为什么会这样？这是因为`display: inline-block`考虑了 HTML 标记中元素之间的空格。为了避免这个问题，我们将确保在每个元素之间有一致的空格或换行。

## 使用新的伪选择器

现在，让我们转到下一个有趣的指令：`nth-last-child(2)`。这是 CSS3 引入的许多新伪选择器之一。使用`nth-last-child(n)`，我们可以定位从最后开始计数的第`n`个元素，而使用`nth-child(n)`，我们可以从顶部开始做同样的事情。这两个伪选择器也可以用来通过某种模式选择元素。例如，假设我们只想突出显示以下列表的偶数元素：

```css
<ul>
  <li>1</li>
  <li>2</li>
  <li>3</li>
  <li>4</li>
  <li>5</li>
  <li>6</li>
</ul>
```

我们可以通过以下简单的 CSS 代码实现这一点：

```css
li:nth-child(2n){
  background: yellow;
}
```

如果我们想要只针对索引大于三的元素进行目标定位，我们可以使用以下 CSS：

```css
li:nth-child(n+4){
  background: yellow;
}
```

以下截图显示了上一个示例的结果：

![使用新的伪选择器](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_03.jpg)

## 完成第一级

我们仍然需要添加一些 CSS 属性来完成我们第一级元素的样式：

```css
nav .item{
  color: #fff;
  text-shadow: 1px 1px 0 rgba(0,0,0,0.5);
  text-decoration: none;
  font-weight: bold;
  text-transform: uppercase;
  letter-spacing: 0.2em;
  padding-left: 10px;
  white-space: nowrap;
  display: block;
  cursor: pointer;
}
```

干得好！现在让我们在支持 CSS3 的浏览器中运行项目，以欣赏结果：

![完成第一级](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_04.jpg)

# 样式化子菜单

现在我们必须为第二级项目设置样式。好吧，说实话，我们在上一节中已经隐藏了它们，以获得漂亮的一级样式，但现在我们可以用更多的属性丰富第二级元素，并确保当用户将鼠标悬停在它们的一级父级上时它们会显示出来。

让我们从刚讨论的最后一部分开始。为了显示第二级元素，我们必须使用`:hover`伪选择器：

```css
nav > ul > li > .item:hover + ul, 
nav > ul > li > ul:hover{
  clip: auto;
  /* temporary property, to be removed */
  opacity: 1;
}
```

我们拦截了父级和所有子级的悬停，以便即使鼠标移动到它们上面，第二级菜单仍然显示。完成后，我们可以开始一些基本的样式：

```css
nav > ul > li > ul{
  padding: 0.7em 0px;
  border-bottom-left-radius: 5px;
  border-bottom-right-radius: 5px;
  border-top: none;
 background-color: rgb(117,189,70);
 background-color: rgba(119,172,48, 0.8);
  background-image: linear-gradient(left, rgba(117,189,70,1), 
rgba(117,189,70, 0.0));
}

nav > ul > li > ul > li > .item{
  text-align: left;
  min-width: 100px;
  padding: 0px 10px;
  line-height: 2.5em;
}

nav > ul > li > ul > li{
  display: block;
  position: relative;
  z-index: 4;
}
```

这里只有一件小事要强调。在上一段代码的突出部分中，有一个简单的回退机制，用于不支持 CSS3 的浏览器。如果我们首先声明一个`rgb 背景颜色`值，然后是一个`rgba`值，我们可以确保不支持 CSS3 的浏览器应用`rgb`指令并跳过`rgba`指令，而支持 CSS3 的浏览器则用`rgba`指令覆盖`rgb`指令。

好了，是时候在我们首选的 CSS3 浏览器中重新加载项目并测试结果了：

![样式化子菜单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_05.jpg)

在接下来的部分，我们将添加一些基本的 CSS 以响应鼠标移动。例如，当鼠标放在其父级一级菜单上时激活特定的子菜单。

# 移动部分

我们在第一级和第二级末尾添加了一个（尚未使用的）`<li class="cursor">`元素。我们想要创建的是一个能够在鼠标悬停在其上时移动到元素下方的块。这是一个很好的效果，为了实现它，我们将使用 CSS3 过渡。但首先让我们创建相同的效果，但没有动画：

```css
nav > ul{
  position: relative;
}

nav li.cursor{
  position: absolute;
  background-color: #75BD46;
  text-indent: 900px;
  border: none;
  height: 3em;
  z-index: 1;
  left: 11px;
  clip: rect(0,0,0,0);
  box-shadow: 
    0px 0px 10px rgba(0,0,0,0.1), 
    0px -1.5em 0px rgba(0,0,0,0.1) inset, 
    0px 1px 1px 1px rgba(0,0,0,0.1) inset;
}
nav li.cursor a{
  display: none;
}

nav > ul > li > ul > li.cursor{
  height: 2.5em;
  left: 0px;
  width: 100%;
  bottom: 0.7em;
  box-shadow: none;
  background-image: none;
  background-color: rgb(165,204,60);
  background-color: rgba(165,204,60,0.7);
  z-index: 3;
}

nav > ul li:hover ~ li.cursor{
 clip: auto;
}

nav > ul > li:hover + li + li + li.cursor{
  left: 11px;
}

nav > ul > li:hover + li + li.cursor{
  left: 112px;
}

nav > ul > li:hover + li.cursor{
  left: 213px;
}

nav > ul > li > ul > li:hover + li + li + li.cursor{
  bottom: 5.7em;
}

nav > ul > li > ul > li:hover + li + li.cursor{
  bottom: 3.2em;
}

nav > ul > li > ul > li:hover + li.cursor{
  bottom: 0.7em;
}

nav li.cursor .item{
  display: none;
}
```

突出显示的代码显示了我们用来切换`.cursor`元素可见性的特殊选择器。基本上，如果鼠标悬停在前面的`li`元素之一上，我们就显示它。

接下来，我们必须定义`.cursor`元素的绝对位置，这显然取决于我们正在悬停的`li`元素。为了实现这种行为，我们使用`+`选择器来精确地将光标移动到元素下方。对于第二级元素也是如此。

如果我们在浏览器中运行项目，可能会感到失望。效果与仅使用`:hover`伪选择器改变`li`背景的效果完全相同。

![移动部分](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_06.jpg)

好了，是时候添加我们隐藏的成分：过渡效果了。

# 添加过渡效果

过渡背后的逻辑简单而强大。我们可以指示浏览器在两个不同的属性值之间创建动画。就是这样！我们可以使用`transition`属性来指定当另一个 CSS 属性发生变化时（例如`width`），元素不应立即从一个值切换到另一个值，而是花费一定的时间，从而在两个值之间创建动画。以下示例说明了这种效果：

```css
<!doctype html>
<html>
  <head>
    <title>basic animation</title>
    <style>
      a{
        display: block;
        width: 300px;
        line-height: 100px;
        height: 100px;
        text-align: center;
        font-size: 50px;
        font-family: sans-serif;
        font-weight: bold;
        color: black;
        border: 10px solid black;
        text-decoration: none;
 transition: all 1s;
 -ms-transition: all 1s;
      }
      a:hover{
        color: red;
      }
    </style>
 <script src="img/prefixfree.js"></script>
  </head>
  <body>
    <a href="#"> HOVER ME </a>
  </body>
</html>
```

`all`关键字告诉浏览器在所有支持过渡的属性上从一个属性变化到另一个属性时花费一秒钟。在这种情况下，当我们悬停在`a`元素上时，`color`属性从`black`变为`red`，但不是立即变化；相反，它在一秒钟内覆盖了从黑色到红色的所有颜色，产生了一个非常酷的效果。

![添加过渡效果](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_07.jpg)

我们可以用很多其他属性和很多其他方式来做这个技巧，正如我们将在本书的后面章节中看到的那样。目前，我们可以利用我们所学到的知识来增强我们的项目。让我们在`application.css`中添加一个`transition`语句：

```css
nav li.cursor{
  -ms-transition: all 1s;
  transition: all 1s;
}
```

通过这个简单的属性，我们获得了一个全新的结果。现在每当我们悬停在一个元素上时，光标都会以非常平滑的动画移动到该元素下方。

![添加转换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_08.jpg)

### 注意

在撰写本书时，`prefixfree.js`不支持 Internet Explorer 10 中的转换和动画。因此，我们必须记住添加带有`-ms-`实验性前缀的转换属性的副本。这很可能会在将来发生变化，这既是因为微软将删除实验性供应商前缀的需要，也是因为这个 JavaScript 库的新版本。

现在我们必须处理另一个问题。二级菜单出现得太早，效果不佳。我们如何延迟其出现，直到`.cursor`元素在`li`元素下方达到正确位置？我们将在下一节中看到这一点。

# 引入动画

动画是一步向前的转换。通过它们，我们可以详细控制一个或多个属性之间的过渡。动画由一组关键帧组成，其中每个关键帧基本上是声明我们选择的属性在动画的特定进度百分比时必须具有哪些值的一种方式。让我们通过以下示例来探索这个特性：

```css
<!doctype html>
<html>
  <head>
    <title>basic animation</title>
    <style>
      div{
        position: absolute;
        top: 0px;
        left: 0px;
        width: 100px;
        height: 100px;
        border: 10px solid black;
        background-color: red;
        text-decoration: none;
        -ms-animation: fouredges 5s linear 2s infinite alternate;
 animation: fouredges 5s linear 2s infinite alternate;
      }

      @-ms-keyframes fouredges{
        0%   { top: 0px; left: 0px;}
        25%  { top: 0px; left: 100px;}
        50%  { top: 100px; left: 100px;}
        75%  { top: 100px; left: 0px;}
        100% { top: 0px; left: 0px;}
      }

 @keyframes fouredges{
 0%   { top: 0px; left: 0px;}
 25%  { top: 0px; left: 100px;}
 50%  { top: 100px; left: 100px;}
 75%  { top: 100px; left: 0px;}
 100% { top: 0px; left: 0px;}
 }

    </style>
    <script src="img/prefixfree.js"></script>
  </head>
  <body>
    <div></div>
  </body>
</html>
```

通过`@keyframes`语句，我们定义了在从`0%`到`100%`的过程中我们选择的一些属性的值。一旦这样做了，我们就可以使用`animation`属性以一些参数来定义，如下所示：

+   第一个参数：它指定我们要在元素上执行的动画的名称（例如，在上面的代码中是`fouredges`）。

+   第二个参数：它指定我们希望动画在单个循环中进行的总时间。

+   第三个参数：它指定加速函数。基本上，我们可以决定元素是否应该以恒定的速度移动（使用关键字`linear`）或者在动画的开始或结束阶段加速（使用`ease-in`、`ease-out`或`ease`）。

+   第四个参数：它指定我们希望应用于动画开始的延迟。

+   第五个参数：它指定我们希望动画重复的次数。`infinite`是这个参数的有效值，以及正数。

+   第六个参数：使用关键字`alternate`，我们可以要求浏览器切换动画的方向。换句话说，动画将首先从`0%`到`100%`，然后从`100%`到`0%`，再次循环。

如果我们在浏览器中尝试刚刚写的例子，我们会看到一个正方形沿着四个顶点路径移动：

![引入动画](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_09.jpg)

嗯，听起来很有趣，但这如何帮助我们的项目呢？简单！我们可以使用延迟动画（带有一些延迟的动画）来创建二级菜单的淡入效果。所以让我们移除之前添加的`opacity: 1`临时属性，并在`application.css`中添加一些 CSS：

```css
nav > ul > li > .item:hover + ul, 
nav > ul > li > ul:hover{
 animation: fadein 0.1s linear 0.9s;
  -ms-animation: fadein 0.1s linear 0.9s;
 animation-fill-mode: forwards;
  -ms-animation-fill-mode: forwards;
}

@keyframes fadein{
  1% {
    opacity: 0.0;
  }

  100% {
    opacity: 1.0;
  }
}

@-ms-keyframes fadein{
  1% {
    opacity: 0.0;
  }

  100% {
    opacity: 1.0;
  }
}
```

`animation-fill-mode: forwards`属性告诉浏览器在动画结束时不要恢复到`0%`，而是保持`100%`位置。

有了这些新的附加功能，我们现在可以在浏览器中尝试一个几乎完整的桌面版本。享受光标动画和二级菜单的淡入效果。

然而，通过上面的代码，我们已经移除了不支持 CSS3 动画的浏览器的支持，特别是 IE9 及以下版本。为了解决这个问题，有很多技术，其中大部分将在本书的过程中揭示。我们将实现的第一种技术是通过用稍微复杂一些的东西替换`<html>`标签，如下所示：

```css
<!--[if lte IE 9]> <html class="lteie9"> <![endif]-->
<!--[if !IE]> --> <html> <!-- <![endif]-->
```

通过使用条件注释，我们现在可以确定用户是否使用 IE9 或更低版本浏览我们的网站，因为新的`.lteie9`类被添加到`html`元素中。

因此，我们可以向我们的 CSS 文件添加一小段代码，只有在`.lteie9`存在时才会触发：

```css
.lteie9 nav > ul > li > .item:hover + ul, 
.lteie9 nav > ul > li > ul:hover{
  opacity: 1;
}
```

# 添加颜色

我们可以根据鼠标悬停在哪个元素上轻松更改`.cursor`元素的颜色。由于我们的`transition: all 1s`属性，我们还将观察颜色如何逐渐变化，从而创建一个非常好的效果。

让我们向`application.css`添加一些属性，以更改`.cursor`元素的颜色，并向二级菜单添加一些颜色：

```css
/* portfolio */
li[data-section=portfolio]:hover ~ li.cursor {
  background-color: #468DBD;
}

nav > ul > li[data-section=portfolio] > ul{
  background-color: rgb(70, 141, 189);
  background-color: rgba(60, 194, 204, 0.8);
  background-image: linear-gradient(left, rgba(70, 141, 189,1), 
rgba(70, 141, 189, 0.0));
}

nav > ul > li[data-section=portfolio] > ul > li.cursor{
  background-color: rgb(60, 194, 204);
  background-color: rgba(60, 194, 204, 0.7);
}

/* interests */
li[data-section=interests]:hover ~ li.cursor {
  background-color: #9E5CD0;
}

nav > ul > li[data-section=interests] > ul{
  background-color: rgb(158, 92, 208);
  background-color: rgba(186, 99, 195, 0.8);
  background-image: linear-gradient(left, rgba(158, 92, 208, 1), 
rgba(158, 92, 208, 0.0));
}

nav > ul > li[data-section=interests] > ul > li.cursor{
  background-color: rgb(186, 99, 195);
  background-color: rgba(186, 99, 195, 0.7);
}
```

在上面的代码中，我们针对三个不同的元素。首先是`.cursor`元素，当具有属性`data-section-portfolio`的`li`元素处于状态`:hover`时，接下来是对应于具有属性`data-section-portfolio`的`li`元素的二级菜单，最后是此二级菜单的`.cursor`元素。在这种情况下，利用`data-*`属性来语义化地标记菜单的每个项目特别有用。

让我们在浏览器中重新加载项目以查看和体验效果：

![添加颜色](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_10.jpg)

# 媒体查询

媒体查询是一种简单但非常强大的工具，可以根据某些浏览器和设备特性（如浏览器的视口大小、设备的宽度和高度以及方向）激活一些 CSS 属性。在深入细节之前，让我们编写一个小脚本来尝试这个功能：

```css
<!doctype html>
<html>
  <head>
    <title>media queries</title>
    <style>
    ul{
      margin: 0;
      padding: 0;
    }
    li{
      list-style-type: none;
      border: 2px solid black;
      margin: 5px;
      padding: 0px 10px;
      display: inline-block;
    }

 @media screen and (max-width: 400px){
      li{
        line-height: 20px;
        text-align: center;
        display: block;
      }

    }
    </style>
  </head>
  <body>
    <ul>
      <li>one</li>
      <li>two</li>
      <li>three</li>
      <li>four</li>
      <li>five</li>
      <li>six</li>
      <li>seven</li>
      <li>eight</li>
      <li>nine</li>
      <li>ten</li>
      <li>eleven</li>
      <li>twelve</li>
    </ul>
  </body>
</html>
```

在这个例子中，我们指示浏览器仅在满足所表达的条件时应用`@media`大括号之间的属性。让我们来看看它们：

+   `screen`：此关键字是可用媒体类型之一，用于指示必须实现封闭语句的媒体类型。在专门的 W3C 规范中描述了许多媒体类型（[`www.w3.org/TR/CSS2/media.html#media-types`](http://www.w3.org/TR/CSS2/media.html#media-types)），但只有少数几种（`screen`、`print`、`projection`）实际上受到今天浏览器的支持。

+   `max-width`：这是我们可以链接的许多条件关键字之一，以列出必须存在于设备中才能激活封闭语句的特征。`max-width`关键字可以解读为“最大为”，因此此条件在浏览器的视口大小超过给定值之前得到验证。

如果我们在兼容 CSS3 的浏览器中运行上面的代码，我们可以看到类似以下截图的内容：

![媒体查询](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_11.jpg)

但是，如果我们调整窗口大小到`400px`以下，媒体查询中的语句将被激活，结果将类似于以下截图：

![媒体查询](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_12.jpg)

很酷，不是吗？当然，除了`max-width`之外，还有其他条件关键字。让我们来看看它们：

+   `min-width`：此关键字可以解读为“视口宽度最小为 x”，其中 x 是分配给`min-width`属性的值。

+   `max-height`和`min-height`：这些关键词的工作方式与`*-width`相同，但它们适用于浏览器的视口高度。

+   `min-device-width`、`max-device-width`、`min-device-height`和`max-device-height`：这些关键字标识设备的实际尺寸；因此，如果我们只想针对大于 1900 x 1200 的屏幕进行定位，我们必须编写诸如`(min-device-width: 1900px)`和`(min-device-height: 1200px)`的规则。

+   `orientation`：此属性的值可以是`portrait`或`landscape`。它标识设备的当前方向。

甚至还有更多这样的条件关键字，但是在上一个列表中不存在的关键字并不那么有用，而且目前还没有任何浏览器支持。无论如何，完整列表可以在[`www.w3.org/TR/css3-mediaqueries/#media1`](http://www.w3.org/TR/css3-mediaqueries/#media1)上查看。

我们还可以在`<link>`声明中使用`media`属性来定义媒体查询，如下所示：

```css
<link rel="stylesheet" type="text/css" media="screen and 
(max-device-width: 480px)" href="css/small.css" />
```

在这种情况下，我们必须考虑不理解媒体查询语句的浏览器，因为它们将始终加载链接的 CSS，而不考虑条件。为了防止这种行为，至少在较旧版本的 Internet Explorer 中，我们可以使用条件注释将`<link>`元素包装起来：

```css
<!-- [if gte IE 9]> -->
<link rel="stylesheet" type="text/css" media="screen and 
(max-width: 480px)" href="css/small.css" />
<!-- <![endif]-->
```

好的，现在我们知道媒体查询是如何工作的，但是我们如何使用此功能来针对移动设备呢？我们可以使用`max-device-width`或`max-width`来做到这一点。

`max-device-width`属性检查设备的大小，这在桌面 Web 浏览器或笔记本电脑上模拟是困难的。使用此属性的另一个缺点是，我们不希望根据屏幕大小来更改布局；我们希望根据浏览器窗口的大小来更改布局。因此，首选属性是`max-width`，这是将为我们的菜单系统提供最大灵活性的行为。

现在我们已经选择了针对移动设备的行为，我们有另一个问题要解决。为了表示页面的桌面版本，然后让用户放大和缩小，移动设备会伪造它们的实际分辨率。为了强制移动浏览器暴露其真实尺寸并禁用缩放，我们可以使用`<meta>`标签。该标签基本上表示最大和最小缩放因子必须等于 1。在`index.html`文件中的`<head>`标签后面添加以下行：

```css
<meta name="viewport" content="width=device-width,initial-scale=1, maximum-scale=1">
```

干得好！现在我们只需要找到要用作触发器以启用我们的“移动”CSS 的大小。我们将使用`320px`，这是 iPhone 在纵向模式下的大小。因此，让我们在`css`文件夹下创建一个新的`application_mobile.css`文件，并在`index.html`文件中的上一个`link`元素下面添加以下`link`元素：

```css
<!-- [if gte IE 9]> -->
<link rel="stylesheet" type="text/css" media="screen and 
(max-width: 320px)" href="css/application_mobile.css"/>
<!-- <![endif]-->
```

# 为移动版本设置样式

现在我们准备开始为该项目的移动版本设置样式。为了实现这一点，我们将把菜单从水平形状转换为垂直形状。我们将不再使用二级菜单，而是创建一些卡片，并在单击相应的一级菜单项时使它们滑入。

因此，首先让我们编写必要的 CSS 来改变我们菜单的形状（在`application_mobile.css`中）：

```css
nav {
  width: 290px;
  height: 100%;
  font-size: 1em;
  text-align: center;
  border-radius: 0;
  box-shadow: 0 0 5px rgba(0,0,0,0.4);
  position: relative;
  overflow: hidden;
}

nav > ul{
  width: 290px;
  padding: 0;
  position: absolute;
  top: 0;
  left: 0;
  z-index: 1;
}

nav > ul > li{
  width: 100%;
  display: block;
  position: static;
  border-bottom: 1px solid #313131;
  box-shadow: 
    0 1px 1px rgba(255,255,255,0.1) inset, 
    0 -1px 1px rgba(255,255,255,0.1) inset, 
    0 -1.5em 0 rgba(0,0,0,0.1) inset;
}

nav > ul > li > .item {
  padding-right: 15px;
  position: relative;
 box-sizing: border-box;
  z-index: 1;
}

nav > ul > li > ul {
  display: block;
  padding: 0;
  padding-top: 3em;
  top: 0;
  left: 290px;
  height: 610px;
  width: 290px;
  clip: auto;
  opacity: 1;
 transition: left 1s;
  z-index: 2;
}
```

第一个突出显示的指令显示了我们如何利用一个非常有用的属性，称为`box-sizing`，它基本上表示在设置元素宽度时受影响的部分。选项如下：

+   `content-box`：在此选项中，宽度仅指围绕元素内容的框。填充、边距和边框宽度被排除。

+   `padding-box`：此选项与前一个选项相同，但这次宽度包括填充。边框和边距宽度仍然被排除。

+   `border-box`：此选项与前两个选项相同，但这次只有边距宽度被排除。

因此，当我们编写以下内容时，我们要求浏览器在`100%`宽度内处理 30px 的填充：

```css
box-sizing: border-box;
width: 100%;
padding: 0px 15px;
```

如果我们现在尝试在移动浏览器中加载项目（例如，从 iPhone 模拟器中），或者如果我们将桌面浏览器窗口调整到 320px 以下，我们可以尝试这种布局：

![为移动版本设置样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_13.jpg)

我们已经在 CSS 代码的移动版本（`application_mobile.css`）中添加了属性`transition: left 1s`，所以我们需要做的就是在相应的一级菜单被点击时将二级菜单移动到`left: 0px`，以使其重叠在一级菜单上。为了实现这一点，我们可以利用`:hover`伪选择器，在移动环境中，当用户触摸元素时会触发。因此我们可以写如下：

```css
nav > ul > li > .item:hover + ul{
 left: 0px;
 animation: none;
}

nav li.cursor{
  display:none;
  transition: none;
}

nav > ul > li > ul > li.cursor{
  display: block;
  top: 0px;
  text-indent: 0;
  left: 0px;
  line-height: 3em;
  height: 3em;
  clip: auto;
}

nav > ul > li > ul > li.cursor .item{
  display: block;
}

nav > ul > li > ul > li:first-child{
  border-top: 1px solid rgba(0,0,0,0.1);
}

nav > ul > li > ul > li{
  height: 3em;
  border-bottom: 1px solid rgba(0,0,0,0.1);
}

nav > ul > li > ul > li > .item{
  line-height: 3em;
  text-align: center;
}
```

最重要的语句是突出显示的那个；其他的只是为了调整一些细微的视觉细节。现在我们可以重新加载项目，欣赏我们刚刚编写的代码的效果：

![为移动版本添加样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_14.jpg)

## 在桌面浏览器上处理新布局

我们在最后一部分代码中所做的对移动设备有效，但在桌面浏览器上失败，因为`：hover`伪选择器的行为不同。尽管几乎不太可能有人会从宽度小于 320 像素的桌面计算机浏览器中探索这个项目，但我们可以使用一点 JavaScript 来解决这个问题。以下是要添加到`index.html`中的代码，放在`</head>`标签之前：

```css
<script 
src="http://ajax.googleapis.com/ajax/libs/jquery/1.7.2/jquery.min.
js"></script>
<script 
src="http://cdnjs.cloudflare.com/ajax/libs/modernizr/2.5.3/
modernizr.min.js"></script>
<script>
  $(document).ready(function(){
  if(!Modernizr.touch){
    $('ul > li > .item').on('click', function(ev){
      $('ul > li').attr('data-status',null);
      $(ev.target).parent().attr('data-status','selected');
    });
    $('ul > li > ul > li > .item').on('click', function(ev){
      $(ev.target).parents('li[data-section]').
attr('data-status',null);
    });
  }
  });
</script>
```

通过这段代码，我们检查浏览器是否不支持触摸事件（因此不支持我们需要的`:hover`行为），然后，如果为真，我们为用户点击的一级菜单元素添加`data-status='selected'`属性。

为了实现这个结果，我们使用了一个非常有趣的库，我们将在下一章中详细介绍：Modernizr ([`modernizr.com/`](http://modernizr.com/))。这个库包含一些方法，用于检查大多数 HTML5 和 CSS3 特性的存在（例如，`Modernizr.touch`），返回`true`或`false`。

此外，每个特性也以附加到`html`元素的类的形式表示。例如，如果支持触摸事件，`html`元素会接收`touch`类；否则，它会接收`no-touch`类。

完成这一步，我们需要做的就是将使用`:hover`的选择器限制为仅触摸设备，并处理新的`data-status="selected"`属性。为此，我们需要在`application_mobile.css`中稍微更改`nav > ul > li > .item:hover + ul`选择器，如下所示：

```css
nav > ul > li[data-status="selected"] > .item + ul,
.touch nav > ul > li > .item:hover + ul
```

## 最终调整

现在我们可以通过`:after`和`:before`伪选择器为这个项目添加一些更多的增强。所以让我们在`application_mobile.css`中添加这个最后的修饰：

```css
nav > ul > li > .item:after, 
nav > ul > li > ul > li.cursor:before{
  content: '>';
  display: block;
  font-size: 1em;
  line-height: 3em;
  position: absolute;
  top: 0px;
  text-shadow: 1px 1px 0px rgba(0,0,0,0.5);
  font-weight: bold;
  color: #fff;
}

nav > ul > li > ul > li.cursor:before{
  content: '<';
  left: 15px;
}

nav > ul > li > .item:after{
  right: 15px;
}
```

每当我们使用 CSS 生成的内容时，我们必须记住，我们注入的内容不会被屏幕阅读器处理；因此，我们必须通过注入仅非必要内容（例如在这种情况下）或提供备用机制来处理。

好的，让我们最后一次在移动浏览器模拟器中重新加载项目，看最终结果：

![最终调整](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_15.jpg)

# 提高速度

如果我们想要改进“滑入”动画的速度，我们可以实施的最有效的变化之一是从背景中去除透明度。为此，我们必须在`application_mobile.css`中添加一些 CSS，以覆盖从桌面版本继承的设置：

```css
nav > ul > li > ul{
  background-color: rgb(117,189,70);
  background-image: none;
}

nav > ul > li[data-section=interests] > ul{
  background-color: rgb(186, 99, 195);
}

nav > ul > li[data-section=portfolio] > ul{
  background-color: rgb(70, 141, 189);
}
```

# 在旧版浏览器中实现

我们在开发这个项目时非常小心，所以即使旧版浏览器不支持动画和渐变，基本结构仍然完美运行。以下是从 Internet Explorer 8 中截取的屏幕截图：

![在旧版浏览器中实现](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/dsn-nxgen-web-pj-c3/img/3264OT_03_16.jpg)

# 总结

在这一章中，我们尝试了媒体查询的强大功能，并开始探索动画和过渡效果。我们还发现了`display:inline-block`和浮动元素之间的区别，并开始收集一些关于移动性能的小贴士。当然，在接下来的章节中，我们会有时间深入了解这些新特性，发现许多其他有趣的 CSS3 属性。

然而，现在是时候翻开新的一页，开始着手处理一个涉及信息图表的新项目了！
