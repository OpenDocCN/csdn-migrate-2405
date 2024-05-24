# 精通响应式 Web 设计（一）

> 原文：[`zh.annas-archive.org/md5/14CB11AB973C4F1BAA6102D9FEAB3F3B`](https://zh.annas-archive.org/md5/14CB11AB973C4F1BAA6102D9FEAB3F3B)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在响应式 Web 设计之前，网页设计师和前端开发人员的工作主要集中在将印刷布局转化为网站和应用程序。元素和尺寸是固定的，它们需要适应和缩放的需求并不是我们今天必须考虑的概念的一部分。

设备有各种形状和大小。针对支持（或不支持）某些 HTML、CSS 和 JavaScript 技术、UX 原则、可用性最佳实践的操作系统和浏览器，以及了解移动设备如何影响我们生活的世界，现在是作为网页设计师和前端开发人员所做的工作的“复杂”部分。

在这本书中，我提供了大量关于 RWD 如何为更好的网站和 Web 应用程序提供路径的技术和概念信息。安装和使用 Sass，处理图像和视频，以及创建稳健的排版比例来构建响应式电子邮件是本书中您将能够阅读到的一些内容宝石。

升级的时候到了！

# 本书涵盖的内容

第一章，“利用 Sass 的力量进行响应式 Web 设计”，从安装 Sass 的最简单的步骤开始；然后我们学习如何让 Sass“监视”我们的 SCSS 文件。然后，有关基本 Sass 概念的易于理解的解释，如变量、混合、参数、嵌套、部分文件、`@import`指令、源映射和 Sass 注释。我们还学会了自动添加供应商前缀并使用 Prepros 自动编译我们的 SCSS 文件。我们讨论了创建混合以尽可能轻松地处理媒体查询，考虑内容如何定义断点。

第二章，“使用 HTML5 标记我们的内容”，澄清了 HTML 是一种标记语言，而不是代码。然后，我们讨论了最常用的 HTML5 元素，这些元素允许我们语义化地标记我们的内容。以简单的方式改善我们构建的可访问性与 ARIA 角色也是我们要解决的问题。我们还讨论了 RWD 所需的不同元标记，然后有一个将所有内容整合在一起的示例。

第三章，“移动优先还是桌面优先？”，揭示了为什么以及何时应该使用移动优先或桌面优先。通过示例，我们将学习如何使用自适应 Web 设计和响应式 Web 设计来改造网站。我们将了解*Respond.js*和条件类，以支持在构建移动优先时的旧版浏览器。

第四章，“CSS 网格、CSS 框架、UI 工具包和 Flexbox 用于响应式 Web 设计”，帮助我们理解什么是网格，如何使用它以及为什么。有了这个理解，我们在构建网站或 Web 应用程序时可以做出明智的决定。我们还使用*浮动*技术和 Flexbox 创建自定义 CSS 网格。我们将再次使用条件类来解决旧版浏览器的问题，并借助一个小脚本，我们可以使用`.ie10`特定选择器来处理 IE10 的怪癖。

第五章，“设计由大手指驱动的小型 UI”，展示了可用性和可访问性在本章中起着重要作用。我们还找到了关于目标区域的不同大小、控件的位置（链接、按钮、表单字段等）以及不同设备上的触摸区域的解释。还有三个关于如何创建菜单按钮的示例，以及三个关于移动导航模式的示例。

第六章，*响应式网页设计中的图像和视频处理*，是本书中最有趣的章节之一，因为 RWD 中的图像是一个“事物”。我们将讨论使用`<picture>`元素和`srcset`属性为不同的图像提供不同的方式。本章还介绍了使用 CSS、jQuery 和 JavaScript 使视频具有响应性。我们还将学习使用基于矢量的文件，如图标字体和 SVG。

第七章，*响应式网页设计中的有意义的排版*，讨论使用相对单位是理想的，因为它们提供了可伸缩性，而这正是 RWD 所关注的。本章的重点是我们将学习如何使用模块化比例来创建和谐的排版比例。我们还将使用*Flowtype.js*来提高我们文本的可读性。

第八章，*响应式电子邮件*，表明电子邮件在移动设备上的打开次数比在台式机上更多；响应式电子邮件在移动设备上的参与度比非响应式电子邮件更高；人们在台式机上点击电子邮件的次数比在移动设备上更多。我们还将创建一个电子邮件模板作为示例。我们将学习使用 CSS 重置块来规范那些古怪的电子邮件客户端，并了解到电子邮件的最佳宽度不超过 600 像素。

所有这些章节都有 CodePen 演示。

# 您需要为本书准备什么

在阅读本书的示例时，需要考虑以下几点：文本编辑器或 IDE（本书中使用 Sublime Text），互联网访问和在您的计算机上安装应用程序的管理员权限。

您可能还需要图像编辑软件，如 Photoshop、Fireworks 或 GIMP。如果您使用其他软件，也完全可以。

如果可能的话，您可以使用一种或两种真实的移动设备来体验示例和演示的正确环境。否则，使用 Chrome 的 DevTool 的*设备模式*功能也可以。

# 这本书是为谁写的

如果您已经了解一些 HTML 和 CSS，并且理解响应式网页设计的原则，那么这本书适合您。无论您是网页设计师还是网页开发人员，无论您是初学者还是经验丰富的网络专业人士，这本书都有您需要学习的内容。

对 HTML 和 CSS 的良好理解是必需的，因为 RWD 在很大程度上依赖于这些技术。对 jQuery 的一些了解也是推荐的，但不是强制的。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码单词、文件夹名称、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“`sizes`属性也可以与`<picture>`元素一起使用，但我们将专注于使用`sizes`属性与`<img>`标签。”

代码块设置如下：

```html
*, *:before, *:after {
    box-sizing: border-box;
}

//Moble-first Media Queries Mixin
@mixin forLargeScreens($width) {
    @media (min-width: $width/16+em) { @content }
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```html
*, *:before, *:after {
    box-sizing: border-box;
}

//Moble-first Media Queries Mixin
@mixin forLargeScreens($width) {
 @media (min-width: $width/16+em) { @content }
}

```

任何命令行输入或输出都会以以下方式书写：

```html
gem install sass

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会以这种方式出现在文本中：“点击**下一步**按钮会将您移动到下一个屏幕”。

### 注意

警告或重要提示会以这样的方式显示在一个框中。

### 提示

提示和技巧会以这样的方式出现。


# 第一章：利用 Sass 为响应式网页设计赋能

在我们深入掌握使用 HTML5 和 CSS3 进行响应式网页设计之前，我们需要就技术达成共识，就我们的情况而言，CSS 预处理器，特别是 Sass。

在本书中，所有的 CSS 都将以 SCSS 格式写成 Sass。我们编写 CSS 的方式已经改变，改进非常大。

CSS 预处理器如 Sass、LESS 和 Stylus 为网络/移动设计师和开发人员提供了新的超能力。是的，我用了*超能力*这个词，因为这正是我第一次使用 Sass 仅仅几个小时后的感受，而我使用的只是最基本的东西：

```html
.navigation-bar {
    display: flex;
    li {
        padding: 5px 10px;
    }
}
```

看到嵌套的`li`选择器了吗？是的，那就是 Sass 在起作用。当前面的代码被编译时，就会变成这样：

```html
.navigation-bar {
   display: flex; 
}
.navigation-bar li {
   padding: 5px 10px;
}
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载示例代码文件，用于您购买的所有 Packt Publishing 图书。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

让我们来看看本章给我们带来了什么：

+   Sass 是如何工作的？

+   要考虑的 Sass 的基本概念**响应式网页设计**（**RWD**）

# Sass 是如何工作的？

了解 Sass 的工作原理涉及理解几个基本的技术概念：

1.  Sass 可以基于两种不同的技术：Ruby 或 LibSass。在本书中，我们将使用基于 Ruby 的 Sass。

1.  Sass 是一个 Ruby gem。Gems 是用于 Ruby 的软件包。Ruby gem 是一种只能在 Ruby 上运行的软件。Ruby 是一种编程语言，就像 PHP、.NET、Java 等一样。

1.  我们可以通过命令行运行 Sass，但也可以使用第三方应用程序运行 Sass，从而不需要使用命令行。

1.  Sass 是一种用于创建 CSS 的编程/脚本语言。

1.  CSS 是一种非常重复的语言。Sass 允许作者优化这些重复的任务，更快、更高效地创建 CSS。

1.  Sass 工作流程的一部分是当 Sass 正在*监视*一个 SCSS 文件时，例如`book-styles.scss`。当它检测到该 SCSS 文件的更改时，它会将其编译成一个 CSS 文件`book-styles.css`。

### 提示

*监视一个 SCSS 文件*意味着 Sass 监视器在后台监视 SCSS 文件的任何更改。

## 安装 Sass

以下是我们将要遵循的步骤：

1.  下载 Ruby 安装程序

1.  打开命令行

1.  安装 Sass gem

### 下载 Ruby 安装程序

**Windows**：从以下链接下载 Ruby 安装程序：

[`rubyinstaller.org/downloads/`](http://rubyinstaller.org/downloads/)

**Mac**：Ruby 预装在所有的 Mac 上，所以不需要下载任何东西。

### 打开命令行

**Windows 和 Mac**：打开命令行。

### 提示

**Windows 提示！**

按下*Windows* + *R*，输入`CMD`，然后按*Enter*。

![打开命令行](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_01.jpg)

### 安装 Sass gem

在命令提示符中键入以下命令（无论您在哪个文件夹中都可以）：

Windows，使用以下命令：

```html
gem install sass

```

Mac，使用以下命令：

```html
sudo gem install sass

```

![安装 Sass gem](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_02.jpg)

安装 Sass 需要几秒钟时间。

### 提示

在撰写本文时，Sass 的最新版本是 3.4.14。版本/修订可能在书出版时有所不同。

就是这样！Sass 现在已经安装在您的计算机上。

## 使用 Sass

我将要向您展示的内容与其他任何 Sass 教程告诉您要做的完全不同。大多数教程都把事情复杂化了。这是您将阅读到的使用 Sass 的最简单的方法。

以下的屏幕截图是在 Windows 上的，但是这个过程可以在任何平台上完全相同地应用。

在接下来的步骤中，您将看到创建后的必要文件夹和文件的示例，而不是如何创建它们：

1.  在你的驱动器的任何位置创建一个`/Demo`文件夹：![使用 Sass](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_04.jpg)

1.  在该文件夹中，创建两个子文件夹，`/css`和`/scss`：![使用 Sass](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_05.jpg)

1.  创建一个`.scss`文件。进入`/scss`文件夹并创建一个名为`styles.scss`的文件：![使用 Sass](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_06.jpg)

### 提示

注意文件扩展名`.scss`？这是你的 Sass 文件。是的，现在里面什么都没有，它是空的。

1.  回到命令行一分钟，按照以下步骤操作：

1.  在命令行中，输入`cd <空格>`

1.  在`cd`后加一个空格意味着*改变目录*。从你的文件管理器中，将`/Demo`文件夹拖放到命令提示符/终端窗口中，然后按*Enter*。![使用 Sass](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_06a.jpg)

1.  你现在应该在`/Demo`文件夹中。

![使用 Sass](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_07.jpg)

1.  通过在命令行中输入以下内容，让 Sass *监视*你的`/scss`和`/css`文件夹：

```html
sass --watch scss:css­

```

1.  让 Sass 监视`/scss`和`/css`文件夹。![使用 Sass](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_08.jpg)

就是这样！你现在正在使用 Sass！

### 提示

`--watch`标志告诉 Sass 关注`/scss`和`/css`文件夹，这样当我们对`.scss`文件（在我们的例子中是`styles.scss`）进行更改时，Sass 将检测到更改并将 SCSS 编译成我们将在网站或应用程序中使用的最终 CSS 文件。

1.  编辑`.scss`文件并观察 Sass 将其编译成`.css`文件：

1.  打开你的文本编辑器（我用 Sublime Text）。

1.  打开`styles.scss`文件。

1.  向其中添加一些 CSS。

1.  保存`styles.scss`文件。

1.  从你的命令行/终端中，验证编译是否成功。

1.  打开你的`styles.css`文件，享受你的新作品。

![使用 Sass](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_09.jpg)

# RWD 的 Sass 基本概念

首先，Sass 是一种编程/脚本语言。我打赌你没有想到。是的，它是一种专注于提高网页设计师和开发人员创建 CSS 效率的编程/脚本语言。在本书中，我们将专注于 Sass 的简单部分，这些部分可以帮助我们更有效地编写 CSS，更重要的是，我们会在其中获得乐趣。

实施 RWD 是耗时的：编码、测试、创建资产、浏览器故障排除，然后再进行更多测试。我们简化编码过程的程度越高，重复性工作越少，我们就变得越有效率，为项目、团队、业务甚至最终用户增加的价值也就越多。Sass 将会做到这一点——帮助我们简化 CSS 的编码。

让我们先讨论以下概念：

+   Sass 或 SCSS

+   变量

+   混合

+   参数

+   嵌套

+   部分文件

+   @import

+   源映射

+   Sass 注释

## Sass 或 SCSS

我们可以用两种方式编写 Sass 风格的 CSS：Sass 语法和 SCSS 语法。

### 提示

不要误解；Sass 是大写 S，其余都是小写，而 SCSS 全部大写。

### Sass 语法

Sass 语法，也被称为*缩进语法*，是最初和唯一的编写 Sass 的方式。但它看起来与常规 CSS 有些不同，使学习曲线比实际需要的更陡峭。

这种语法没有使用任何大括号或分号。在某些情况下，它使用等号而不是冒号。与 SCSS 不同，缩进非常严格且是强制性的。许多开发人员对 Sass 语法的这些方面并不太喜欢。

这是一个基本的例子：

```html
.selector-a
    float: left

        .selector-b
            background: orange
```

这将编译成以下代码：

```html
.selector-a {
    float: left;
}

.selector-a, .selector-b {
    background: orange;
}
```

### SCSS 语法

当 SCSS 在 Sass 的第 3 个版本中引入时，对于我们这些不是程序员但想要利用 Sass 功能的人来说，事情变得更容易了。

### 注意

SCSS 代表**Sassy CSS**。

如果你已经写 CSS，那么你已经写了 SCSS。我们在编写 CSS 时已经使用的所有东西，在使用 SCSS 语法编写 Sass 时也是一样的。因此，学习曲线最初是不存在的。

然后，你会意识到你还可以使用一些增强你已经知道的 Sass 功能，这使得学习 Sass 成为一种很棒的体验，因为你可以相当快地变得擅长它。说实话，这感觉就像你正在获得超能力。我不是在开玩笑。

以下是我们之前看到的相同示例，使用 SCSS 语法：

```html
.selector-a {
    float: left;
}

.selector-a, .selector-b {
    background: orange;
}
```

等一下！那是 CSS！是的，它也是 SCSS。

让我们以不同的方式使用 SCSS 语法看同一个例子：

```html
.selector- {
    &a {
        float: left;
     }
    &a, &b {
        background: orange;
    }
}
```

在 SCSS 中，`&`符号允许我们将父选择器的名称添加到嵌套选择器中，而无需输入整个内容，使我们保持*DRY*的状态。

### 注意

DRY 表示不要重复自己。

这两个 SCSS 示例编译为以下代码：

```html
.selector-a {
    float: left;
}

.selector-a, .selector-b {
    background: orange;
}
```

### Sass 变量

首先让我们了解一些事情：

+   变量只是一种存储值以供以后使用的方法

+   这个值通常与一个简单的*用户友好*单词相关联

+   Sass 变量必须以美元符号(`$)`开头

+   变量的巨大好处是，如果我们需要更改值，我们只需在一个地方进行更改，而不是在整个文档中查找和替换值

### 提示

在列出多个变量时，每个变量的末尾应该有一个分号(`;`)。如果只有一个变量，则不需要分号。然而，即使只有一个变量，最好也以分号结束变量，这是一个好习惯。

以下是 Sass 变量的一个例子：

```html
$brandBlue: #416e8e;
```

### 提示

我建议您使用*驼峰命名法*来命名变量，以便将它们与以破折号分隔的类名和 CSS 属性区分开。在扫描 SCSS 文档时，这非常有帮助，因为变量更容易检测到。

正如我们所看到的，我们正在存储一个颜色值。我们使用的名称`brandBlue`肯定比`#416e8e`更用户友好。此外，我们使用了美元符号(`$`)并以分号(`;`)结束，以防我们需要添加更多变量。现在，如果以后需要更改值，我们只需要在一个位置进行更改。

变量应始终包含在 SCSS 文件的顶部，以便 Sass 知道在使用它们时应该去哪里。您还可以通过部分文件包含它们，但我们将在本章后面讨论部分文件是什么。

以下是如何使用 SCSS 变量的示例：

```html
$brandBlue: #416e8e;
body {
    background: $brandBlue;
}
```

上述代码编译为以下内容：

```html
body {
   background: #416e8e;
}
```

### Sass mixin

Mixin 是 Sass 最强大的功能之一。**Mixin**是一组 CSS 声明（属性和值），可以存储以供以后使用，就像变量一样。因此，我们不必一遍又一遍地输入所有这些 CSS 声明，只需输入 mixin 的名称。

关于 Sass mixin 需要考虑的几件事情如下：

+   它们以`@mixin`指令开头

+   使用`@include`指令调用 mixin

+   我们可以在 mixin 中存储任意数量的 CSS/SCSS 数据

+   尝试在创建 mixin 时使用*参数*，这样它就更具可扩展性

### 提示

我们还没有看到*参数*是什么，但现在提到这个词很重要，这样你就可以开始熟悉不同的 Sass 术语。我们将在下一节中介绍 Sass 参数。

让我们看一个 mixin 的例子：

```html
$brandBlue: #416e8e;
$supportGray: #ccc;
@mixin genericContainer {
    padding: 10px;
    border: $brandBlue 1px solid;
    background: $supportGray;
    box-shadow: 1px 1px 1px rgba(black, .3);
}
```

我们在 SCSS 文件中调用 mixin 如下：

```html
.selector-a {
    @include genericContainer;
}
```

编译后，在 CSS 中看起来像这样：

```html
.selector-a {
    padding: 10px;
    border: #416e8e 1px solid;
    background: #cccccc;
    box-shadow: 1px 1px 1px rgba(0, 0, 0, 0.3);
}
```

让我们回顾一下我们在 mixin 中所做的事情。

我们使用了`@mixin`指令：

```html
$brandBlue: #416e8e;
$supportGray: #ccc;
@mixin genericContainer {
    padding: 10px;
    border: $brandBlue 1px solid;
    background: $supportGray;
    box-shadow: 1px 1px 1px rgba(black, .3);
}
```

我们使用驼峰命名约定来区分 mixin 的名称和以破折号分隔的类名和 CSS 属性：

```html
$brandBlue: #416e8e;$supportGray: #ccc;
@mixin genericContainer {
    padding: 10px;
    border: $brandBlue 1px solid;
    background: $supportGray;
    box-shadow: 1px 1px 1px rgba(black, .3);
}
```

我们在 mixin 中使用了 Sass 变量：

```html
$brandBlue: #416e8e;$supportGray: #ccc;
@mixin genericContainer {
    padding: 10px;
    border: $brandBlue 1px solid;
    background: $supportGray;
    box-shadow: 1px 1px 1px rgba(black, .3);
}
```

在`box-shadow`颜色属性中使用关键字`black`，而不是使用十六进制`#000`或`rgb (0, 0, 0)`值：

```html
$brandBlue: #416e8e;$supportGray: #ccc;
@mixin genericContainer {
    padding: 10px;
    border: $brandBlue 1px solid;
    background: $supportGray;
    box-shadow: 1px 1px 1px rgba(black, .3);
}
```

为此，我们也可以像这样使用我们的变量名：

```html
$brandBlue: #416e8e;$supportGray: #ccc;
@mixin genericContainer {
    padding: 10px;
    border: $brandBlue 1px solid;
    background: $supportGray;
    box-shadow: 1px 1px 1px rgba($brandBlue, .3);
}
```

我们还省略了 alpha 值中的`0`（`.3`）。这实际上不是 Sass 的特性；这是 CSS 的特性：

```html
$brandBlue: #416e8e;$supportGray: #ccc;
@mixin genericContainer {
    padding: 10px;
    border: $brandBlue 1px solid;
    background: $supportGray;
    box-shadow: 1px 1px 1px rgba($brandBlue, .3);
}
```

### 提示

在以零开头的小数值上，零可以被省略。

同样，上述 mixin 编译为以下 CSS：

```html
.selector-a {
    padding: 10px;
    border: #416e8e 1px solid;
    background: #cccccc;
    box-shadow: 1px 1px 1px rgba(65, 110, 142, 0.3);
}
```

## Sass 参数

在我们的第一个 mixin 示例中，我们没有任何参数。这实际上并不理想，因为它不允许我们在相同的属性中使用不同的值。实际上，在 mixin 中不使用任何参数并不比每次需要它们时键入相同的属性和值有任何不同。我们并没有真正做到 DRY。

*参数*是 mixin 的一部分，您可以根据需要放入自己的值。参数使 mixin 值得创建。

在前面提到的 mixin 示例中，让我们添加一个参数：

```html
$brandBlue: #416e8e;$supportGray: #ccc;
@mixin genericContainer($padding) {
    padding: $padding;
    border: $brandBlue 1px solid;
    background: $supportGray;
    box-shadow: 1px 1px 1px rgba(black, .3);
}
```

`padding`参数允许我们设置任何我们想要的值。我们并不*强制*每次都将填充设置为`10px`。

这是我们如何设置参数的值：

```html
.selector-a {
    @include genericContainer(10px);
}
```

这编译为以下内容：

```html
.selector-a {
    padding: 10px;
    border: #416e8e 1px solid;
    background: #cccccc;
    box-shadow: 1px 1px 1px rgba(0, 0, 0, 0.3);
}
```

但是，参数存在潜在问题；如果我们不为`padding`设置值，编译时会出现错误。

因此，这里的解决方案是设置一个*默认*值；如果由于某种原因我们没有为`padding`定义一个值，Sass 将采用默认值并在编译时使用它而不会抛出错误。

以下是如何设置参数的默认值：

```html
$brandBlue: #416e8e;$supportGray: #ccc;
@mixin genericContainer($padding: 8px) {
    padding: $padding;
    border: $brandBlue 1px solid;
    background: $supportGray;
    box-shadow: 1px 1px 1px rgba(black, .3);
}
```

这是我们如何调用 mixin，而不声明任何`padding`值：

```html
.selector-a {
    @include genericContainer;
}
```

编译后的 CSS 如下：

```html
.selector-a {
    padding: 8px;
    border: #416e8e 1px solid;
    background: #cccccc;
    box-shadow: 1px 1px 1px rgba(0, 0, 0, 0.3);
}
```

### 如何在同一个 mixin 中使用多个参数

在前面的 mixin 基础上，让我们添加一些更多的参数，使其更加健壮和可扩展：

```html
@mixin genericContainer ($padding, $bdColor, $bgColor, $boxShdColor) {
    padding: $padding;
    border: $bdColor 1px solid;
    background: $bgColor;
    box-shadow: 1px 1px 1px $boxShdColor;
}
```

这是我们在包含 mixin 时如何声明参数的方式：

```html
.selector-a {
    @include genericContainer(2%, $brandBlue, #ccc, black);
}
```

我们可以使用相同的 mixin 并获得不同的样式，而无需重复输入所有属性。

前面的 mixin 及其参数编译为以下代码：

```html
.selector-a {
    padding: 2%;
    border: #416e8e 1px solid;
    background: #cccccc;
    box-shadow: 1px 1px 1px #000000;
}
```

### 在多个参数中设置默认值

有时，我们需要定义一些默认值，以防我们只需要声明一个或几个参数。换句话说，通过在我们的参数中声明默认值，我们将始终确保创建一个值，并且在编译我们的 SCSS 文件时不会出现任何错误。

以下是我们如何在参数中设置默认值：

```html
@mixin genericContainer ($padding: 5px, $bdColor: orange, $bgColor: #999, $boxShdColor: #333) {
    padding: $padding;
    border: $bdColor 1px solid;
    background: $bgColor;
    box-shadow: 1px 1px 1px $boxShdColor;
}
```

如果我们只需要声明*第一个*属性`padding`，我们可以这样做：

```html
.selector-a {
    @include genericContainer(25px);
}
```

这编译为以下内容：

```html
.selector-a {
    padding: 25px;
    border: orange 1px solid;
    background: #999999;
    box-shadow: 1px 1px 1px #333333;
}
```

### 提示

某些 Sass 编译器将简写的颜色十六进制值`#333`转换为长格式值`#333333`。

正如我们所看到的，只有第一个参数`padding`被声明。其他参数使用了它们的默认值并成功编译。

但是，假设我们仍然只想声明一个参数，而不是`padding`，它是参数列表中的第一个。假设我们想声明背景颜色！

在这种情况下，我们需要通过输入变量的名称来声明值：

```html
.selector-a { @include genericContainer($bgColor: $brandBlue); }
```

### 提示

如果我们只想声明一个与第一个参数不同的单个参数，我们需要声明整个参数名称。

还有更高级的声明参数的方法，但这对于本书的范围来说已经足够了。

## Sass 中的嵌套

Sass 中的嵌套是使我们的 SCSS 更易读的完美方式。就像在 HTML 中，标签基于其父元素进行嵌套一样，Sass 使用完全相同的结构。

以下是导航栏的两级选择器嵌套示例：

```html
$brandBlue: #416e8e;nav {
 ul {
 display: flex;
 margin: 0;
 padding: 0;
 list-style: none;
 }

 li {
 margin: 5px;
 background: #000;
 }
 a {
 display: block;
 padding: 5px 15px;
 text-decoration: none;
 color: $brandBlue;
 }
}
```

### 提示

注意深层嵌套！最佳实践建议最多嵌套三个级别。否则，我们将在未来遇到选择器特异性和可维护性问题。

您是否注意到我再次使用了`$brandBlue`颜色变量？前面的导航栏的 SCSS 编译为以下 CSS：

```html
nav ul {
    display: flex;
    margin: 0;
    padding: 0;
    list-style: none;
}
nav li {
    margin: 5px;
    background: #000;
}
nav a {
    display: block;
    padding: 5px 15px;
    text-decoration: none;
    color: #416e8e;
}
```

## Sass 中的局部文件（partials）

局部文件是我们创建的用于存放 SCSS 片段的 SCSS 文件。局部文件允许我们模块化我们的文件，例如，`_variables.scss`。局部文件以下划线符号（`_`）开头，并以扩展名`.scss`结尾。下划线符号告诉编译器，这个文件及其内容不需要编译成单独的 CSS 文件。

局部文件使用`@import`指令调用，就像在 CSS 中一样。主要区别在于无需指定下划线符号和文件扩展名。

让我们创建一个局部文件，并把这些颜色变量放在里面。我们将称这个局部文件为`_variables.scss`。`_variables.scss`局部中的变量（片段）如下：

```html
$brandBlue: #416e8e;
$brandRed: #c03;
$brandYellow: #c90;
```

然后我们假设我们的主 SCSS 文件名为`styles.scss`。现在我们有两个文件：`styles.scss`和`_variables.scss`。

### 提示

项目的主 SCSS 文件不以下划线符号开头。

我们使用`@import`指令将`_variables.scss`调用到`styles.scss`中：

```html
@import "variables";
```

注意，在引用局部文件时，下划线符号和文件扩展名是不需要的；它们可以被省略。但是，如果你想添加它们，也可以。省略它们可以使代码更清晰。

## Sass 扩展/继承功能

许多专业人士说，扩展或继承是 Sass 最有用的功能之一。其他人实际上建议远离它。本书的建议是：尽可能多地使用 Sass，并尝试不同的功能，这样你就可以形成自己的观点。当你有足够的经验时，你可以决定加入哪一方。

在 Sass 中**扩展**意味着我们可以在另一个选择器中使用选择器的属性，而不必再次输入所有这些属性。这就是所谓的**继承**。我们使用`@extend`指令来实现这一点。

例如，考虑以下选择器：

```html
$brandBlue: #416e8e; .generic-container {
    padding: 10px;
    border: $brandBlue 1px solid;
    background: #ccc;
    box-shadow: 1px 1px 1px rgba(black, .3);
}
```

假设我们想要在不同的选择器上继承这个选择器的所有属性。我们还要修改一个属性，因为它们几乎是相同的，使用`@extend`指令在第二个选择器中重用第一个选择器的样式：

```html
.box-customer-service {
    @extend .generic-container;
    padding: 25px;
}
```

这编译成以下内容：

```html
.generic-container, .box-customer-service {
    padding: 10px;
    border: #416e8e 1px solid;
    background: #cccccc;
    box-shadow: 1px 1px 1px rgba(0, 0, 0, 0.3);
}

.box-customer-service {
    padding: 25px;
}
```

注意`.generic-container`和`.box-customer-service`在同一条规则中；这意味着`.box-customer-service`继承了`.generic-container`的所有属性和值。然后，有一个单独的规则为`.box-customer-service`，只声明了`padding`属性，因为这是两个容器之间的唯一区别。

## Sass 注释

由于我们知道 CSS 文档是有效的 SCSS 文档，因此使用 CSS 注释语法也是有效的：

```html
/* This is a traditional CSS comment */
```

在 Sass 中，还有另一种方法。我们可以在开头使用双斜杠（`//`）进行注释。

```html
// This is a Sass-style comment
```

两种样式之间的区别在于使用`/**/`语法的传统 CSS 注释会添加到编译后的文件中，而使用`//`的 Sass 注释则不会添加。

Sass 语法中的注释非常有用，可以在不必担心所有这些注释被编译并使最终的 CSS 文件变得臃肿的情况下记录我们的 SCSS 文件。以下示例中的 Sass 注释不会被编译：

```html
$brandBlue: #416e8e; //Mixin for generic container across the app
.generic-container {
    padding: 10px;
    border: $brandBlue 1px solid;
    background: #ccc;
    box-shadow: 1px 1px 1px rgba(black, .3);
}
```

然而，传统的 CSS 注释确实被编译了：

```html
$brandBlue: #416e8e;
/* Mixin for generic container across the app */
.generic-container {
    padding: 10px;
    border: $brandBlue 1px solid;
    background: #ccc;
    box-shadow: 1px 1px 1px rgba(black, .3);
}
```

### 提示

现在，根据编译器上设置的选项，最终的 CSS 可以被最小化。因此，传统的 CSS 注释将被剥离以优化文件大小。

## 供应商前缀

供应商前缀基本上是为尚未被广泛使用或最终包含在 CSS3 规范中的 CSS3 属性或值添加特定的*标签*。

*供应商*部分指的是代表创建浏览器的公司名称的缩写标签：Mozilla、Opera 和 Microsoft。

不过，有一个例外，苹果。尽管苹果创建了 Safari，但供应商前缀是基于浏览器的布局引擎而不是公司名称。

+   Mozilla：`-moz-`

+   Opera：`-o-`

+   微软：`-ms-`

+   Webkit（苹果）：`-webkit-`

*前缀*部分指的是在 CSS 属性或 CSS 值之前添加供应商标签的描述。每个供应商前缀只在自己的浏览器中有效，因此对于上述列表，这里是它们所属的浏览器：

+   Mozilla：这个前缀`-moz-`在 Firefox 中有效

+   Opera：这个前缀`-o-`在 Opera 中有效

+   微软：这个前缀`-ms-`在 Internet Explorer 中有效

+   Webkit（苹果）：这个前缀`-webkit-`在 Safari 中有效

如果你想知道谷歌 Chrome 在这一切中的位置，这有一个简单的解释。

尽管谷歌创建了 Chrome，但 Chrome 没有特定的前缀。起初，Chrome 使用与 Safari 相同的布局引擎：Webkit。因此，基于 Webkit 的前缀不仅影响了 Safari，还影响了 Chrome 和其他基于 Chromium 的产品。

然而，谷歌浏览器不再使用 Webkit；它现在使用自己的布局引擎称为 Blink。然而，为了保持兼容性并避免进一步分裂网络，Chrome 仍然支持`-webkit-`前缀。

Opera 有一个类似的故事，他们有自己的布局引擎 Presto，然后切换到 Webkit。现在它使用 Blink。除了之前提到的浏览器供应商之外，还有其他浏览器供应商，他们也使用自己的前缀，比如 Konqueror 浏览器的前缀`-k-`。

这是一个带有供应商前缀的 CSS 属性的例子：

```html
-moz-box-sizing: border-box;
```

这里有一个带前缀的 CSS 值的例子：

```html
background-image: -webkit-linear-gradient(red, blue);
```

### 供应商前缀的顺序

事实上，我们列出供应商前缀的顺序并不重要；重要的是我们总是将非供应商前缀的版本放在最后。

以 linear-gradient 属性为例，我们应该这样做：

```html
*, *:before, *:after {
    background-image: -webkit-linear-gradient(red, blue);
    background-image: -moz-linear-gradient(red, blue);
    background-image: -ms-linear-gradient(red, blue);
    background-image: -o-linear-gradient(red, blue);
    background-image: linear-gradient(red, blue);
}
```

### 提示

如果你喜欢，你也可以使用`background: linear-gradient(red, blue);`。

非供应商前缀的声明应该始终放在最后，因为如果浏览器供应商修改其前缀或停止支持它，最后一行将始终覆盖上面的任何内容，因为级联。这使整个 CSS 规则更具未来性。此外，我们不必在供应商更改内容时重写样式表。

现在，许多 CSS3 属性和值不需要所有供应商前缀。大多数情况下，它们只需要一些供应商前缀，其他时候非供应商前缀的属性或值就足够了。

但是，我们如何知道哪些 CSS3 属性和值可以加前缀，哪些不需要，这样我们就可以创建受某些旧浏览器支持的样式，而不必记住太多信息？

答案是*自动化*供应商前缀的过程。

### 自动添加供应商前缀

供应商前缀带来了一些问题，如果我们希望一些 CSS3 属性在当前浏览器和/或某些旧浏览器中工作，我们就无法摆脱这些问题。供应商前缀是肮脏的工作，我们*不*必须这样做。

那么，我们如何在尽可能保持 DRY 的情况下自动化供应商前缀的过程呢？有几种方法。

#### 使用 Compass

Compass 是一个帮助我们更有效地编写 CSS 的 Sass 框架。Compass 有一个庞大的 mixin 库，我们可以使用它来处理供应商前缀。

Compass 的安装超出了本书的范围，因此我们将专注于处理供应商前缀的基本用法，并假设它已经安装在您的机器上。请参考 Compass 网站，了解如何安装它的详细说明（[`compass-style.org/`](http://compass-style.org/)）。

一旦我们安装了 Compass，我们需要导入包含我们需要的 mixin 的特定模块。

继续使用之前使用的线性渐变示例，让我们将 Compass 的`images`模块导入到我们的 SCSS 文件中。将其放在主 SCSS 文件的顶部：

```html
@import "compass/css3/images";
```

然后，我们可以使用相应的 mixin：

```html
header {
    @include background-image(linear-gradient(red, blue));
}
```

这将编译为以下内容：

```html
header {
    background-image: url('data:image/svg+xml;base64,…');
    background-size: 100%;
    background-image: -webkit-gradient(linear, 50% 0%, 50% 100%, color-stop(0%, red), color-stop(100%, blue));
    background-image: -moz-linear-gradient(red, blue);
    background-image: -webkit-linear-gradient(red, blue);
    background-image: linear-gradient(red, blue);
}
```

这里有一些新东西。

第一个声明使用了一个 base64 嵌入的 SVG 文件。这是因为旧版 IE 和旧版 Opera 存在渲染渐变的问题，因此 SVG 是它们的备用方案。按照今天的标准，处理这些问题是完全不必要的。

```html
header {
    background-image: url('data:image/svg+xml;base64,…');
    background-size: 100%;
    background-image: -webkit-gradient(linear, 50% 0%, 50% 100%, color-stop(0%, red), color-stop(100%, blue));
    background-image: -moz-linear-gradient(red, blue);
    background-image: -webkit-linear-gradient(red, blue);
    background-image: linear-gradient(red, blue);
}
```

`background-size: 100%;`参数用于使嵌入的 SVG 覆盖整个容器。再次处理这样的事情只是浪费时间。此外，我们的代码不断膨胀，试图支持旧技术。考虑下面的代码块：

```html
header {
    background-image: url('data:image/svg+xml;base64,…');
    background-size: 100%;
    background-image: -webkit-gradient(linear, 50% 0%, 50% 100%, color-stop(0%, red), color-stop(100%, blue));
    background-image: -moz-linear-gradient(red, blue);
    background-image: -webkit-linear-gradient(red, blue);
    background-image: linear-gradient(red, blue);
}
```

第三个声明是旧的 CSS 线性渐变语法，只有 Webkit 浏览器支持；这在我们的文件中会导致不必要的代码膨胀：

```html
header {
    background-image: url('data:image/svg+xml;base64,…');
    background-size: 100%;
    background-image: -webkit-gradient(linear, 50% 0%, 50% 100%, color-stop(0%, red), color-stop(100%, blue));
    background-image: -moz-linear-gradient(red, blue);
    background-image: -webkit-linear-gradient(red, blue);
    background-image: linear-gradient(red, blue);
}
```

第四和第五个声明基本上是为旧版 Firefox、Chrome 和 Safari 版本准备的：

```html
header {
    background-image: url('data:image/svg+xml;base64,…');
    background-size: 100%;
    background-image: -webkit-gradient(linear, 50% 0%, 50% 100%, color-stop(0%, red), color-stop(100%, blue));
    background-image: -moz-linear-gradient(red, blue);
 background-image: -webkit-linear-gradient(red, blue);
    background-image: linear-gradient(red, blue);
}
```

最后一个声明是没有供应商前缀的建议语法：

```html
header {
    background-image: url('data:image/svg+xml;base64,…');
    background-size: 100%;
    background-image: -webkit-gradient(linear, 50% 0%, 50% 100%, color-stop(0%, red), color-stop(100%, blue));
    background-image: -moz-linear-gradient(red, blue);
    background-image: -webkit-linear-gradient(red, blue);
 background-image: linear-gradient(red, blue);
}
```

正如我们所看到的，Compass 是一个非常方便的工具，它允许我们自定义输出。然而，这可能会变得比必要的工作更多。

在得出 Compass 是否是我们的最佳解决方案之前，有一些事情需要考虑：

+   需要安装 Compass。这通常是通过命令行完成的。

+   一旦安装了 Compass，我们就不必再使用命令行来使用它的 mixin。

+   Compass 有一个庞大的 mixin 库，可以帮助处理供应商前缀和许多其他事情。

+   每次我们需要处理特定的 CSS3 属性或值时，我们必须在我们的主 SCSS 文件中使用`@import`指令导入相应的模块。这意味着我们必须花费大量时间找到我们需要的模块并学会使用它们。

+   使用 Compass 的学习曲线是中等的，我们需要在其他技术方面有一定的了解才能使用 Compass，即使是最基本的使用也是如此。

+   Compass 有很好的文档，并且是一个不断发展的项目。

+   有一个类似的著名的 mixin 库叫做 Bourbon：[`bourbon.io/`](http://bourbon.io/)。

#### 使用“-prefix-free”

`-prefix-free`是由 Lea Verou 创建的 JavaScript 文件。当浏览器调用该脚本时，它会检测到，然后将该浏览器特定的前缀添加到 CSS 中。 `-prefix-free`文件足够智能，可以确定需要哪些前缀，并且只注入那些前缀。

使用`-prefix-free`很简单。只需调用 JavaScript 文件。根据 Lea Verou 的建议，最好在样式表之后包含此脚本，以减少**未样式内容的闪烁**（**FOUC**）。

您可以访问`-prefix-free`项目：[`leaverou.github.io/prefixfree/`](http://leaverou.github.io/prefixfree/)。

由于我们的 HTML 代码如此简短，我们可以遵循之前提到的提示：

```html
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Page Title</title>
    <link href="css/styles.css" rel="stylesheet">
    <script src="img/prefixfree.min.js"></script>
</head>
<body>
    Site content...
</body>
</html>
```

使用这种方法肯定是诱人的，因为调用一个简单的 JavaScript 文件来处理自动添加供应商前缀听起来就像是最好的主意。

让我们看一下在决定使用`-prefix-free`之前需要考虑的事项的简短列表：

+   它非常容易使用。

+   这是一个额外的 HTTP 请求。我们的网站/页面的请求越少，它们就越快，因此我们为用户提供的用户体验就越好。这对 SEO 也是有益的。

+   这是一个额外的文件要管理。是的，一旦我们上传了 JavaScript 文件，我们可能不需要再回头看它——除非我们要更新它，这意味着我们需要在本地进行广泛的测试，以免在生产环境中出现任何问题。

+   它会给用户的浏览器增加一些负担，因为所有事情都发生在浏览器中。

+   它在使用`@import`指令调用的文件中不起作用。这也可以被视为一件好事，因为如果我们使用`@import`来导入文件，我们就会面临一个不同甚至更大的问题。

+   如果我们从与我们的主站点不同的域名提供样式表，那么`-prefix-free`将无法在这些外部 CSS 文件上工作。

+   Chrome 和 Opera 在允许`-prefix-free`在本地工作方面存在问题。虽然这很容易解决，但它只是增加了我们工作流程的复杂性。

+   如果有内联样式，一些未添加前缀的 CSS 值和属性在 IE 中将无法工作。

有了这个列表，我们现在可以更好地做出一个更明智的决定，这将使项目、我们自己和我们的用户受益。

#### 使用 Autoprefixer

Autoprefixer 是一个*CSS 后处理器*，它使用 CanIUse.com 数据库为已编译的 CSS 文件添加供应商前缀。

术语*后处理器*意味着它在创建 CSS 之后（后）处理它。换句话说，如果我们有一个名为`styles.scss`的 SCSS 文件，当我们保存它时，该文件会被编译为`styles.css`。在那一刻，Autoprefixer 获取生成的`styles.css`文件，打开它，为每个属性和值添加所有必要的供应商前缀，保存文件，并关闭它。此外，您还可以配置它创建一个新的单独文件。完成后，我们可以在我们的网站/应用程序中使用此文件。

这种方法相对于任何其他自动供应商前缀方法的主要优势是它使用 CanIUse.com 数据库；这意味着一旦浏览器供应商不再需要其前缀用于 CSS 属性或值，我们只需通过 Autoprefixer 运行我们的 CSS 文件，它将在几秒钟内更新。

Autoprefixer 的主要缺点是它有太多的使用方式，对一些人来说可能有点压倒性。举几个例子，我们可以通过命令行使用它，但首先需要安装`Node.js`：

```html
npm install --global autoprefixer
autoprefixer *.css
```

我们也可以在 Compass 中使用 Autoprefixer，但首先需要安装 Ruby：

```html
gem install autoprefixer-rails
```

我们可以在 Mac 上使用 CodeKit，在 Windows/Mac/Linux 上使用 Prepros 或 Koala App。我们还可以为 Sublime Text、Brackets 或 Atom Editor 安装插件。还有 Grunt 和 Gulp 插件。

在决定使用 Autoprefixer 之前，让我们看一下需要考虑的事项的简要清单：

+   它使用 CanIUse.com 数据库的事实是远远超过任何其他自动供应商前缀应用程序的最佳功能和优势，因为我们始终可以确保我们的 CSS 文件具有最新的前缀，或者如果浏览器供应商删除了其中任何一个。

+   它可以集成到许多应用程序中。

+   对于新的网页设计师或开发人员来说，安装可能有点令人生畏。

+   Autoprefixer 已经预装在其他应用程序中，所以我们只需要运行这些应用程序，就可以自动使用 Autoprefixer，而无需进行任何设置。

Autoprefixer 可以从[`github.com/postcss/autoprefixer`](https://github.com/postcss/autoprefixer)下载。

#### 使用 Pleeease

是的，它是三个*e*的*Pleeease*。Pleeease 也是一个类似 Autoprefixer 的 CSS 后处理器，它也依赖于已安装的`Node.js`。它只能通过命令行运行，但实际上非常简单。Pleeease 使用 Autoprefixer，这意味着它也使用 CanIUse.com 数据库来定义哪些 CSS 属性和/或值需要前缀。

安装 Pleeease 后，我们需要创建一个配置文件（JSON 文件），其中我们需要定义的最重要的事情是源 CSS 文件和目标 CSS 文件：

```html
{
    "in": "style.css",
    "out": "styles.fixed.css"
}
```

一旦我们设置了配置文件，我们在命令行中运行这个命令：

```html
pleeease compile
```

Pleeease 获取`style.css`文件，添加所有必要的供应商前缀，并创建`styles.fixed.css`，这是我们在生产中使用的文件。

在这一点上，Pleeease 还有其他重要的事情：

+   将相同的媒体查询编译为一个`@media`块

+   将`@import`样式表内联（这很棒，因为我们最终只会得到一个单一的 CSS 文件用于生产）

+   最终文件进行了最小化/压缩

如果您习惯使用命令行和 JSON 文件，Pleeease 可以成为您工具库中非常有用的一部分。如果您更喜欢远离命令行，也没关系；还有其他更友好的方法来自动添加供应商前缀。

在决定是否使用 Pleeease 自动添加供应商前缀之前，有一些需要考虑的事项：

+   需要使用命令行进行安装和使用，但命令非常简单。

+   它使用 JSON 文件来配置其设置。

+   它使用 Autoprefixer，这意味着它也使用 CanIUse.com 数据库。这使得它在知道哪些属性和/或值需要或不需要前缀时非常强大。

+   它对最终的 CSS 文件进行了几项其他改进，比如将相同的媒体查询打包在一个`@media`规则中，最小化结果等等。

+   它可以与 Grunt、Gulp、Brunch 和 Node.js 工作流集成。

您可以从[`pleeease.io/`](http://pleeease.io/)下载 Pleeease。

#### 使用 Emmet

Emmet 使我们能够更快地编写 CSS 和 HTML。它是文本编辑器的插件，如 Sublime Text、Coda、TextMate，甚至 Dreamweaver。

Emmet 还帮助我们为 CSS3 属性和值添加供应商前缀，这是我们接下来要重点关注的。

### 提示

Emmet 以前被称为*Zen Coding*。

一旦 Emmet 插件安装在我们喜爱的文本编辑器中，我们在 SCSS 文件中输入以下内容：

```html
.selector-a {
    -trf
}
```

### 提示

`-trf`是 CSS3 属性*transform*的缩写。

然后我们在键盘上按下*Tab*，代码会自动更改为这样：

```html
.selector-a {
    -webkit-transform:;
    -ms-transform:;
    -o-transform:;
    transform:;
}
```

我们只需要在缩写的开头加一个破折号(`-`)来添加供应商前缀。这告诉 Emmet 在按下*Tab*键时需要添加必要的供应商前缀。

### 提示

在上一个例子中未定义变换值，因为我们想展示使用 Emmet 的结果。显然，我们最终需要添加这些值。

在决定是否使用 Emmet 自动添加供应商前缀之前，有一些事情需要考虑：

+   由我们来定义什么需要加前缀，什么不需要，所以我们可能最终会给不再需要前缀的属性和值加上前缀。因此，我们最终会使我们的 CSS 文件变得臃肿。

+   如果我们忘记在属性/值的开头添加破折号，它就不会被加前缀，也许这个属性/值确实需要前缀。因此，我们会花更多时间进行故障排除。

+   Emmet 与最流行的文本编辑器兼容，所以我们很可能能够使用它。

+   使用 Emmet 的学习曲线非常低。

+   Emmet 不依赖于使用命令行。

+   Emmet 有很好的文档，并且在不断发展。

您可以从[`emmet.io/`](http://emmet.io/)下载 Emmet。

#### 使用第三方应用程序

正如我们所见，以前用于自动添加供应商前缀的方法是各种各样的，从通过命令行使用的方法到让您在使用 JavaScript 解决方案之前找到特定模块导入的方法。

提到的所有功能中最重要的是 Autoprefixer 使用 CanIUse.com 数据库。这基本上是我们想要使用的，因为我们只需要编写 CSS3 属性和值，然后完全忘记供应商前缀，让 Autoprefixer 和 CanIUse.com 为我们添加它们。

幸运的是，已经有第三方应用程序安装了 Autoprefixer。这意味着我们不需要通过命令行设置任何东西，也不需要安装插件，或者类似的东西。只需安装应用程序，激活 Autoprefixer 复选框，然后开始使用！

之前我们提到了几个应用程序：CodeKit、Prepros 和 Koala 应用。它们基本上都做同样的事情，但它们在两个方面表现出色：

+   它们可以*监视*我们的 SCSS 文件并为我们编译它们。

+   它们可以通过 Autoprefixer 自动添加供应商前缀。

这两个功能对我们的工作流程有很大影响，使我们能够将精力集中在重要的事情上，比如 RWD 和更好的用户体验。

在决定使用第三方应用程序是否是添加供应商前缀的最佳解决方案之前，有一些事情需要考虑：

+   Prepros 和 CodeKit 是付费应用程序。Koala 是免费的，但通过小额捐赠支持作者对他的工作表示感激。然而，它们绝对不贵；当我们第一次编译文件时，收益是十倍的价值。

+   它们非常容易设置。

+   它们有很好的文档、社区，并且由作者不断开发。

+   对于许多与 CSS 和 HTML 一起工作的非前端开发人员来说，这些应用程序使他们能够专注于其他重要事项，如用户体验、设计、可用性和 SEO，而不必担心 JSON 文件、命令行、插件等等。

#### 推荐的供应商前缀方法

本书建议您使用 CodeKit、Prepros 或 Koala 应用程序来处理供应商前缀。这些应用程序不仅可以编译 SCSS 文件，还可以在保存这些 SCSS 文件时自动通过 Autoprefixer 运行它们。

所以让我们来看看 Prepros，它可以在 Windows、Linux 和 Mac 等最流行的操作系统上运行。

## 使用第三方程序进行编译

使用命令行编译我们的 SCSS 文件真的并不那么困难：

```html
--sass watch scss:css

```

这就是我们在命令行中需要做的一切，以便 Sass 监视`/scss`文件夹中的 SCSS 文件，并将它们编译到`/css`文件夹中。真的就是这么简单。

以前的情况是，每次我们需要在不同的项目上工作时，都需要运行这个命令。虽然我们可以用许多不同的方式来自动化这个过程，但有些人觉得使用命令行要么令人生畏，要么只是不必要的。

### Prepros 应用程序

Prepros 是一个面向网页设计师和开发人员的工具，涉及到常规工作流程的许多部分：编译、CSS 前缀、实时刷新、JavaScript 合并、文件最小化、图像优化、浏览器测试同步、为编译文件创建源映射、内置服务器、FTP 等等。

在本书的范围内，我们将重点介绍它如何帮助我们在自动添加供应商前缀的同时编译我们的 SCSS 文件。

您可以从[`prepros.io/`](https://prepros.io/)下载它。Prepros 是一个付费应用程序。不过，花 29 美元并不会让你破产。我向你保证，第一次编译之后，这个应用程序就会为自己赚回成本。

还有一种方法可以免费使用 Prepros 并享受应用程序的所有功能。不过，这是以不得不每 5 分钟左右关闭*购买应用程序*弹出窗口为代价的。

这是 Prepros 的当前欢迎界面（可能已经改变）：

![Prepros 应用程序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_10.jpg)

还记得安装 Sass 时的步骤吗？我们创建了一个`/Demo`文件夹，并在其中创建了两个子文件夹`/scss`和`/css`？我们将把`/Demo`文件夹拖放到 Prepros 界面上：

![Prepros 应用程序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_11.jpg)

一个悲伤的表情出现了，让我们知道项目是空的。这是真的，因为我们还没有向`/scss`文件夹中添加任何文件：

![Prepros 应用程序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_12.jpg)

所以，让我们在`/scss`文件夹中创建一个`.scss`文件：

![Prepros 应用程序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_13.jpg)

Prepros 将自动检测新的`styles.scss`文件并将其编译为`styles.css`文件，保存在`/css`文件夹中。

![Prepros 应用程序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_14.jpg)

单击`styles.scss`文件将显示文件的默认设置：

![Prepros 应用程序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_15.jpg)

让我们修改一些设置，以便 Prepros 可以自动执行以下操作：

+   添加供应商前缀。

+   创建源映射。

+   不压缩我们编译的 CSS（至少暂时不压缩）。

### 提示

`source map`是一个带有`.map`扩展名的文件，它与我们的 CSS 文件一起生成。这个映射文件包含了将我们的 CSS 文件的每一行链接到我们的 SCSS 文件和局部文件中相应行的必要信息。当我们需要通过任何现代网页浏览器的 DevTools 检查元素的样式时，这一点至关重要。

在**输出样式**部分，我们将把设置保留为**Expanded**。

![Prepros 应用程序](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_16.jpg)

四种输出样式之间的区别很简单：

#### 扩展输出

这是传统的 CSS 样式，其中每个选择器、属性和值都在单独的一行上：

```html
header {
    background: blue;
}
header .logo {
    float: left;
}
.container {
    float: right;
}
```

#### 嵌套输出

你可以看到第二个规则是缩进的，这意味着它属于`header`选择器：

```html
header {
    background: blue;
}
    header .logo {
       float: left;
  }
.container {
    float: right;
}
```

#### 紧凑输出

所有规则都在一行中，如下所示：

```html
header { background: blue; }
header .logo { float: left; }
.container { float: right; }
```

#### 压缩输出

这是被压缩的版本，这是我们在生产中应该使用的版本：

```html
header{background:blue;}header .logo{float:left;}.container{float:right;}
```

就是这样。我们现在让 Prepros 运行。它将添加所有供应商前缀，并在我们保存时编译 SCSS 文件。让我们看看它的运行情况。

#### 添加一些 CSS，让 Prepros 应用程序完成剩下的工作！

每次我们点击**保存**，Prepros 都会在屏幕右下角显示以下对话框中的一个。

**成功**将给我们以下输出：

![添加一些 CSS，让 Prepros 应用程序完成剩下的工作！](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_17.jpg)

**错误**将给我们以下输出：

![添加一些 CSS，让 Prepros 应用程序完成剩下的工作！](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_18.jpg)

让我们拿出我们的`styles.scss`文件，然后添加一个需要一些供应商前缀的简单 CSS 规则。

![添加一些 CSS，让 Prepros 应用程序完成剩下的工作！](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_19.jpg)

当我们保存`styles.scss`文件时，Prepros 会显示绿色/成功的对话框，并将我们的 SCSS 文件编译成`styles.css`。

这是编译后的文件，自动添加了所有前缀：

![添加一些 CSS，让 Prepros 应用程序完成剩下的工作！](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_20.jpg)

#### 定义要为前缀添加支持的旧版浏览器版本数量

随着浏览器的发展，CSS3 属性和值被标准化，越来越少的属性需要供应商前缀。我们的 CSS 文件应该反映这一点，这样我们就不会在样式表中填充不必要的前缀。

Prepros 允许我们定义在应用前缀时要支持多少个旧版浏览器版本。步骤如下：

1.  在顶部点击**更多选项**菜单：![定义要为前缀添加支持的旧版浏览器版本数量](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_21.jpg)

1.  从下拉菜单中点击**项目选项**：![定义要为前缀添加支持的旧版浏览器版本数量](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_22.jpg)

1.  点击**CSS**菜单选项：![定义要为前缀添加支持的旧版浏览器版本数量](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_23.jpg)

1.  滚动到底部，在**AutoPrefixer**字段中输入数字`2`：![定义要为前缀添加支持的旧版浏览器版本数量](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_24.jpg)

1.  完成这些操作后，保存`styles.scss`文件。我们会发现，CSS3 线性渐变属性在 Prepros 编译 CSS 文件后实际上不需要添加前缀：![定义要为前缀添加支持的旧版浏览器版本数量](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_01_25.jpg)

### 提示

如果你看不到线性渐变属性在开头被加上前缀，尝试将值更改为非常高的值，比如`40`，这样它就会显示*最后 40 个版本*。保存你的 SCSS 文档，然后再次检查你的 CSS 文件。

就是这样。

### 只有一个编译器

在我们继续之前，有一点非常重要的说明。到目前为止，我们已经讨论了通过`--watch`标志使用命令行以及使用 Prepros 来编译我们的 SCSS 文件。请注意，*只需要运行一个编译器*。同时运行 CMD 和 Prepros 编译相同的 SCSS 文件是不必要的。

## Sass mixins 来存放我们的媒体查询

有许多方法可以创建一个 Sass mixin 来存放媒体查询：只有变量的 mixin，为不支持媒体查询的旧版浏览器提供*No Queries*回退的 mixin，以及（对于 Compass）插件，比如 Breakpoint。还有其他技术，比如命名媒体查询。另一种技术是一个简单的三行 mixin，可以用于我们想要的任何东西。

它们都很好，而且非常强大。然而，在本书的范围内，我们将专注于两种简单的方法，这将使我们能够高效，保持简单，并利用 mixin 的功能。

到目前为止，你学到的关于 Sass 的一切，特别是关于 mixin 的部分，都体现在创建一个用于存放 RWD 媒体查询的部分文件中。

请记住，部分文件是我们创建的用于存放 SCSS 片段的 SCSS 文件。它们的文件名以下划线符号开头，以`.scss`扩展名结尾。

### 媒体查询 mixin 方法

命名媒体查询和断点的方法和网页设计师和前端开发人员一样多。每个人都有自己的方式和风格。

无论您使用哪种方法，重要的是开始使用 Sass mixin 来自动化这个过程。随着我们构建站点或应用程序并成为更好的网页设计师/前端开发人员，我们会发现其他解决方案可能效果更好。

有几种方法可以命名您的媒体查询 mixin：

+   让内容定义断点。换句话说，当您在测试期间调整浏览器窗口大小，并且看到内容中断或无法以理想的、可读的方式显示时——创建一个断点（这是推荐的方法）。

+   使用抽象名称命名媒体查询，如`small`、`medium`和`large`，或`s`、`m`和`l`。

+   使用特定设备名称（我不建议使用此方法）。

在本书中，我们将只关注前面列表中提到的第一种和第二种方法。

#### 让内容定义断点

由于我们不知道我们的内容会在哪里中断，我们需要一个初始 mixin，我们可以在构建响应式站点/应用程序时添加值，我们将从一些已知的、特定宽度的值开始。请理解这些值很可能会改变，并且会向这个 mixin 添加许多其他值。

我们将把这个文件命名为`_mediaqueries.scss`。媒体查询 mixin 看起来像这样：

```html
//Mobile-first
@mixin minw($point) {
    @if $point == 320 {
      @media (min-width:  20em) { @content; }
    }
    @else if $point == 640 {
      @media (min-width:  40em) { @content; }
    }
    @else if $point == 768 {
      @media (min-width:  47.5em) { @content; }
    }
}
```

这是我们在主 SCSS 文件中使用 mixin 的方法：

```html
header {
    width: 50%; //Properties for small screens
    background: red;
      @include minw(640) {
 width: 100%; //Properties for large screens
 background: blue;
 }
}
```

这是 mixin 编译的结果：

```html
header {
    width: 50%;
    background: red;
}
@media (min-width: 40em) {
 header {
 width: 100%;
 background: blue;
 }
}

```

在本书的媒体查询示例中，我们将使用`em`单位而不是像素来声明宽度值。这是因为使用`em`有助于更好地缩放所有值，独立于屏幕密度。让我们看看这里发生了什么。

##### Mixin

首先，我们看到 Sass 风格的注释，描述这个 mixin 是为移动优先方法而设计的：

```html
//Mobile-first
```

然后，我们有开放的`@mixin`指令。这个指令包含 mixin 的名称`minw`，它是*minimum-width*的缩写。我们将保持这个名称简单，因为我们将经常输入它，所以输入`minw`比输入*minimum-width*更快，同时仍然保持有意义的术语。

括号中，我们有`($point)`参数，它将存储我们在定义要使用的断点时指定的值：

```html
@mixin minw($point)
```

然后，我们有一个开放的`@if`语句。记住我们说过 Sass 是一种编程/脚本语言吗？有什么比`if-else`语句更能代表编程语言呢？

`@if`语句后面是等于(`==`) 320 像素宽度的`$point`变量。两个等号(`==`)表示它绝对等于值，即`320`：

```html
@if $point == 320
```

之后，我们有 CSS `@media` 指令，我们以前见过很多次。在这个指令中，我们以`em`为单位指定宽度，在这个例子中是`20em`。

```html
@media (min-width:  20em)
```

然后，我们有`@content`指令，允许我们在括号之间放任何内容：

```html
@media (min-width:  20em) { @content; }
```

接下来是带有`@else`语句的`$point`变量，两个等号(`==`)和值`640`。如果定义的值是`640`而不是`320`，那么 mixin 可以继续使用这个特定的媒体查询，适用于 640 像素宽度。

```html
@else if $point == 640
```

这意味着 640 像素是`40em`：

```html
@media (min-width:  40em) { @content; }
```

最后，我们有相同的媒体查询结构，适用于 768 像素宽度。768 像素等于`47.5em`。

在选择让内容定义断点的方法之前，请考虑以下几点：

+   使用特定宽度值（记住，这些值是基于内容的）作为媒体查询名称（320、640 或 768）的好处是，当我们使用 mixin 时，我们真正知道我们要定位的具体宽度是什么。

+   这意味着无论我们有多少个断点，我们都将始终知道我们要定位的宽度。

+   我们可以有尽可能多的断点，而且我们永远不必回到 mixin 去提醒我们哪个名称对应哪个宽度。

#### 命名媒体查询

这是许多前端开发人员喜爰的。这个 mixin 几乎与我们刚刚看到的那个相同；不同之处在于，它不是使用特定的宽度并知道这些宽度将改变并添加其他宽度，而是使用设备特定宽度的抽象名称，通常已经定义了断点列表。

这是这个 mixin 的样子：

```html
//Mobile-first
@mixin breakpoint($point) {
    @if $point == small {
        @media (min-width:  20em) { @content; }
    }
    @else if $point == medium {
        @media (min-width:  40em) { @content; }
    }
    @else if $point == large {
        @media (min-width:  48em) { @content; }
    }
}
```

这是我们如何使用它的方式：

```html
header {
    width: 50%; //Properties for small screens
    background: red;
    @include breakpoint(medium) {
 width: 100%; //Properties for large screens
 background: blue;
 }
}
```

这是编译后的样子：

```html
header {
    width: 50%;
    background: red;
}
@media (min-width: 40em) {
 header {
 width: 100%;
 background: blue;
 }
}

```

在选择命名媒体查询方法之前，请考虑以下几点：

+   如果你有很多断点，使用抽象名称可能会令人困惑。

+   在某个时候，你要么会用尽抽象名称，要么会有太多抽象名称，以至于你真的记不住哪个名称对应哪个宽度。

#### 基本 mixin

这是在处理媒体查询时推荐使用的 mixin，它具有以下优点：

+   它允许我们在定义宽度时继续以像素为单位思考，但输出是以相对单位（`em`）为单位。

+   这很容易理解和扩展。

+   如果我们使用桌面优先的方法，我们只需要将 mixin 名称从`mobileFirst`更改为`desktopFirst`，并将`min-width`关键字更改为`max-width`。

+   如果我们想使用基于像素的宽度，我们只需要从除法中去掉`16`：`/16+em`。

+   由于它不使用命名变量来表示不同的宽度，所以不需要记住哪个命名变量对应哪个宽度。

+   我们永远不会用尽命名变量，因为它不使用它们。

现在，考虑到我们的建议是让内容定义断点，这里是 mixin：

```html
@mixin mobileFirst($media) {
    @media (min-width: $media/16+em) { @content; }
}
```

就是这样——一个仅有三行的 mixin。这是我们如何使用它的方式：

```html
header {
    width: 50%; //Properties for small screensbackground: red;
    @include mobileFirst(640) {
 width: 100%; //Properties for large screensbackground: blue;
 }
}
```

这是它编译成的样子：

```html
header {
    width: 50%;background: red;
}
@media (min-width: 40em) {
    header {
      width: 100%;background: blue;
  }
}
```

现在，你可能会问自己，“`em`值是从哪里来的？”

这很简单。我们将期望的宽度除以 16。我们除以 16 的原因是因为`16px`是所有浏览器的默认字体大小。通过这样做，我们得到了以`em`单位为单位的值。

如果你想使用`16px`作为默认字体大小，请考虑以下示例：

+   *320px/16px = 20em*

+   *640px/16px = 40em*

+   *768px/16px = 47.5em*

如果你决定你的默认字体大小不是`16px`而是`18px`，那么同样的过程适用。将期望的宽度除以`18px`：

+   *320px/18px = 17.77em*

+   *640px/18px = 35.55em*

+   *768px/18px = 42.66em*

选择权在你手中。

### 提示

我们所有的示例都将基于`16px`的默认字体大小。

# 摘要

在本章中，我们涵盖了很多内容，但最好的还在后面。我们学会了如何安装 Sass 以及如何让它*监视*我们的 SCSS 文件。我们还了解到有两种不同的语法：Sass 和 SCSS。我们现在知道任何 CSS 文件都是有效的 SCSS 文件，如果我们现在知道如何编写 CSS，我们也知道如何编写 SCSS。我们讨论了 Sass 的不同基本概念，如变量、mixin、参数、嵌套、部分文件、`@import`指令、源映射和 Sass 注释。

我们还学会了什么是供应商前缀和帮助自动化这个过程的不同方法。我们决定使用 Prepros 来执行以下任务：监视、编译 SCSS 文件和自动添加前缀。我们学会了创建一个部分文件来容纳我们的媒体查询 mixin，名为`_mediaqueries.scss`。我们还学会了使用基本 mixin 来命名媒体查询的不同方法，这个 mixin 向我们展示了如何简单地处理媒体查询，同时遵循让内容定义断点的最佳实践。

在下一章中，我们将深入研究 HTML5 以及如何标记我们的内容以准备进行 RWD。准备好你的浮潜装备！


# 第二章：用 HTML5 标记我们的内容

许多人认为 HTML 是*代码*。嗯，不是的。HTML——任何版本的 HTML——都是*标记*语言。

标记语言是一种可以被人类阅读和理解的计算机语言。它使用标签来定义内容的各个部分。HTML 和 XML 都是标记语言。

为了更好地区分，编码语言涉及更复杂的抽象、脚本、数据库连接、通过复杂协议以某种形式传输数据等等。编码确实是一个神奇的世界。

HTML 可以做到这一切，但它远没有那么复杂，更容易理解。

在本章中，我们将专注于标记内容背后的科学。内容可以以许多不同的形式呈现：文本、图像、视频、表单、错误消息、成功消息、图标等等。此外，特定类型的内容在浏览器中的行为或用户与之交互的方式将告诉我们应该将特定内容标记为什么类型的 HTML 元素。

例如，许多网页设计师将锚链接`<a href="#">开始 30 天试用</a>`*看起来像*按钮。许多网页开发人员使相同的锚链接*行为像*按钮。为什么不直接使用`<input type="button" value="开始 30 天试用">`元素呢？更好的是，使用`<button>开始 30 天试用</button>`元素，它的行为完全相同，更容易样式化，并且允许添加 HTML 内容。

我们的目标是尽可能地保持语义标记。语义标记基本上意味着我们使用 HTML 标签来描述特定内容是什么。保持语义标记有很多好处：

+   对于继承我们工作的其他网页设计师或开发人员也非常有帮助，因为他们将花费更少的时间来逆向工程我们所做的工作，更多的时间来增强它。

+   在可访问性方面也非常有帮助，因为它允许辅助技术将元素命名为它们本来的样子：一个按钮实际上是一个`<button>`，而不是一个被样式化成按钮的链接`<a href="#">`。

+   语义标记对 SEO 有很大的好处，因为它可以让搜索引擎更快、更准确地索引内容。

密切关注内容对于链条中的每个人都有很大帮助——帮助我们在项目中，帮助项目本身，最终帮助我们的用户，无论是否使用辅助技术。

我可以给你的最好建议是在标记内容时*倾听内容*；它会和你交流。真的会。

我们将在本章中涵盖以下主题：

+   HTML5 元素的实际应用

+   使用**Web Accessibility Initiative - Accessible Rich Internet Applications** (**WAI-ARIA**)地标角色来增加可访问性

+   响应式网页设计的重要元标签

+   带有 ARIA 角色和元标签的完整 HTML5 示例页面

那么，现在我们可以使用哪些 HTML 元素，以确保我们的网站/应用在所有浏览器中都能正常显示呢？答案是*所有元素*。

2014 年 10 月 28 日，W3C 完成了 HTML5 标准。然而，所有主要浏览器多年来一直支持 HTML5 元素。

对我们来说，这意味着即使在 W3C 完成 HTML5 标准之前，我们已经可以使用任何 HTML5 元素。所以，如果你一直在使用 HTML5 构建网站/应用，继续使用吧；如果你还没有因为任何特定原因开始使用 HTML5，那么现在是开始的时候了。

# <main>元素

根据**Mozilla** **Developer Network** (**MDN**)的定义：

> *HTML 主要元素(`<main>`)可以用作文档的主要内容的容器。主要内容区域包括与部分的中心主题直接相关或扩展的内容，或应用程序的中心功能。这些内容应该是文档独有的，不包括在一组文档中重复的内容，例如侧边栏、导航链接、版权信息、站点标志和搜索表单（除非文档的主要功能是作为搜索表单）。与`<article>`和`<section>`不同，这个元素不会对文档大纲产生影响。*

以下是关于`<main>`元素的几个重要要点：

+   页面的顶层内容应包含在`<main>`元素中。

+   内容应该是独占且独特的。

+   `<main>`元素不应包含在`<header>`、`<footer>`、`<nav>`、`<aside>`或`<article>`元素内。

+   每个页面只能有一个`<main>`元素。

考虑以下例子：

```html
<body>
    <main class="main-container" role="main">Content goes here
    </main>
</body>
```

### 提示

为了谨慎起见，使用 HTML 实体表示特殊字符，例如，和字符(&)是`&amp;`，省略号字符(…)是`&hellip;`。

# `<article>`元素

根据 MDN 的定义：

> *HTML 文章元素(`<article>`)代表文档、页面、应用程序或站点中的独立组成部分，旨在独立分发或重复使用，例如在联合中。这可以是论坛帖子、杂志或报纸文章、博客文章或任何其他独立的内容项。每个`<article>`应该被识别，通常通过在`<article>`元素的子元素中包含标题(`h1`-`h6`元素)来实现。*

以下是关于`<article>`元素的几个重要要点：

+   任何自包含的内容应放在`<article>`元素内。

“自包含”意味着如果我们将`<article>`元素及其内部内容移到另一个上下文中，所有内容都是不言自明的，不需要其他东西来理解。

+   `<article>`可以嵌套在另一个`<article>`元素内。

+   一个页面可以有多个`<article>`元素。

考虑以下例子：

```html
<body>
    <main class="main-container" role="main">
       <article class="article-container flex-container">
           Content goes here
       </article>
    </main>
</body>
```

# `<section>`元素

根据 MDN 的定义：

> *HTML 节元素(`<section>`)代表文档的一个通用部分，即内容的主题分组，通常带有标题。每个`<section>`应该被识别，通常通过在`<section>`元素的子元素中包含标题(`h1`-`h6`元素)来实现。*

以下是关于`<section>`元素的几个重要要点：

+   `<section>`元素可用于封装一组相关内容。这些相关内容不一定需要在页面上下文之外有意义。

+   使用`<section>`元素的一种安全有效的方式是将其放在`<article>`元素内。当然也可以单独使用`<article>`元素。建议在使用`<section>`元素时包含标题元素(`<h1>`、`<h2>`、`<h3>`等)，但不是必需的。

+   什么时候使用`<section>`元素，什么时候使用`<article>`元素可能会令人困惑。如果不确定，可以选择任何一个元素。

+   一个页面可以有多个`<section>`。

考虑以下例子：

```html
<body>
   <main class="main-container" role="main">
      <article class="article-container flex-container">
         <section class="main-content">
            <header>
               <h1>The <code>&lt;main></code> element  </h1>
            </header>
            <p>As per the MDN definition:</p>            <blockquote>
 <p>The HTML Main Element (<code>&lt;main></code>)                     represents&hellip;</p>
            </blockquote>
         </section>
      </article>
   </main>
</body>
```

# <aside>元素

根据 MDN 的定义：

> *HTML`<aside>`元素代表页面上与其余内容有轻微关联的内容部分，可以被视为与该内容分开的部分。这些部分通常表示为侧边栏或插入内容。它们通常包含侧边栏上的定义，例如词汇表中的定义；也可能包含其他类型的信息，例如相关广告；作者的传记；网络应用程序；博客上的个人资料信息或相关链接。*

以下是关于`<aside>`元素的几个重要要点：

+   与主要内容相关的内容可以包含在`<aside>`元素中。如果这些内容与主要内容分开，它们仍然可以独立存在。

+   在单个页面中可以有多个`<aside>`。

考虑以下例子：

```html
<body>
    <main class="main-container" role="main">
        <article class="article-container flex-container">
            <section class="main-content">
              <header>
                  <h1>The <code>&lt;main></code> element  </h1>
              </header>
              <p>As per the MDN definition:</p>
              <blockquote>
                  <p>The HTML Main Element (<code>&lt;main></code>) 
  represents&hellip;</p>
              </blockquote>
            </section>
 <aside class="side-content" role="complementary">
 <h2>What Does "Semantic HTML" Mean?</h2>
 <p>Semantic markup basically means that we use HTML tags 
 to describe what a specific piece of content is.</p>
 </aside>
         </article>
      </main>
</body>
```

### 提示

*切题内容*意味着内容涉及手头的主题，但不是主要信息的一部分。如果`<aside>`元素内的内容被移除，主要信息不会受到影响。

# `<header>`元素

通常，我们认为网站/应用的顶部部分是页眉，这是正确的。该顶部部分的编辑名称是*标志*。

然而，从 HTML5 的角度来看，*标志*和*页眉*之间有区别。

标志是网站/应用的主要页眉，只能有一个。它通常包含标志、一些导航，可能还有搜索字段等。页眉可以被认为是任何部分的顶部区域，可以有多个页眉。

请注意，我们还没有讨论`<header>`元素，至少目前还没有。

标志可以使用`<header>`元素构建，但`<header>`元素也可以在同一页面的其他部分使用。

以下是 MDN 的定义：

> *HTML `<header>`元素代表一组介绍性或导航辅助信息。它可能包含一些标题元素，还可能包含其他元素，如标志、包装部分的页眉、搜索表单等。*

以下是关于`<header>`元素的几个重要要点：

+   一个很好的经验法则是在`<section>`元素内使用`<header>`元素。

+   如果我们认为有必要，可以将标题(`h1`到`h6`)包装在`<header>`元素内，但这并不是一种常见做法或必需的。

+   在单个页面中可以有多个`<header>`元素。

在以下示例中，有两个突出显示的`<header>`部分，标志和`<section>`元素内的页眉：

```html
<body>
   <header class="masthead" role="banner">
 <div class="logo">Mastering RWD with HTML5 &amp; CSS3</div>
 <div class="search" role="search">
 <form>
 <label>Search:
 <input type="text" class="field">
 <button>Search Now!</button>
 </label>
 </form>
 </div>
 </header>
   <main class="main-container" role="main">
      <article class="article-container flex-container">
         <section class="main-content">
            <header>
 <h1>The <code>&lt;main></code> element</h1>
 </header>
            <p>As per the MDN definition:</p>
            <blockquote>
               <p>The HTML Main Element (<code>&lt;main></code>) represents&hellip;</p>
            </blockquote>
         </section>
         <aside class="side-content" role="complementary">
            <h2>What Does "Semantic HTML" Mean?</h2>
            <p>Semantic markup basically means that we use HTML tags to describe what a specific piece of content is.</p>
         </aside>
      </article>
   </main>
</body>
```

# `<footer>`元素

根据 MDN 的定义：

> *HTML 页脚元素(`<footer>`)代表其最近的分区内容或分区根元素的页脚。页脚通常包含有关该部分作者的信息、版权数据或相关文档的链接。*

以下是关于`<footer>`元素的几个重要要点：

+   它应始终包含有关其包含的父元素的任何信息。

+   尽管术语*页脚*暗示着页面、文章或应用的*底部部分*，但`<footer>`元素不一定非要在底部。

+   在单个页面中可以有多个`<footer>`元素。

考虑以下例子：

```html
<body>
    <header class="masthead" role="banner">
      <div class="logo">Mastering RWD with HTML5 &amp; CSS3</div>
      <div class="search" role="search">
         <form>
            <label>Search:
               <input type="text" class="field">
               <button>Search Now!</button>
            </label>
         </form>
      </div>
    </header>
    <main class="main-container" role="main">
      <article class="article-container flex-container">
         <section class="main-content">
            <header>
               <h1>The <code>&lt;main></code> element</h1>
            </header>
            <p>As per the MDN definition:</p>
            <blockquote>
               <p>The HTML Main Element (<code>&lt;main></code>) represents&hellip;</p>
            </blockquote>
         </section>
         <aside class="side-content" role="complementary">
            <h2>What Does "Semantic HTML" Mean?</h2>
            <p>Semantic markup basically means that we use HTML tags to describe what a specific piece of content is.</p>
         </aside>
      </article>
      <footer class="main-footer" role="contentinfo">
 <p>Copyright &copy;</p>
 <ul class="nav-container" role="navigation">
 <li><a href="#">Footer Link 1</a></li>
 <li><a href="#">Footer Link 2</a></li>
 <li><a href="#">Footer Link 3</a></li>
 <li><a href="#">Footer Link 4</a></li>
 <li><a href="#">Footer Link 5</a></li>
 </ul>
 </footer>
   </main>
</body>
```

# `<nav>`元素

根据 MDN 的定义：

> *HTML 导航元素(`<nav>`)代表页面中链接到其他页面或页面内部部分的部分：一个带有导航链接的部分。*

以下是关于`<nav>`元素的几个重要要点：

+   它用于对链接列表或集合进行分组。这些链接可以指向外部资源或站点/应用内的其他页面。

+   在`<nav>`元素内使用无序列表`<ul>`来构造链接是一种常见做法，因为这样更容易进行样式设置。

+   在`<header>`元素中包含`<nav>`也是一种常见做法，但不是必需的。

+   并非所有链接组都必须在`<nav>`元素内。如果我们在`<footer>`标签内有一组链接列表，那么在`<nav>`中也没有必要包含这些链接。

+   在单个页面中可以有多个`<nav>`元素，例如主导航、实用导航和`<footer>`导航。

考虑以下例子：

```html
<body>
    <header class="masthead" role="banner">
      <div class="logo">Mastering RWD with HTML5 &amp; CSS3</div>
      <div class="search" role="search">
         <form>
            <label>Search:
               <input type="text" class="field">
               <button>Search Now!</button>
            </label>
         </form>
      </div>
    </header>
    <nav class="main-nav" role="navigation">
 <ul class="nav-container">
 <li><a href="#">Link 1</a></li>
 <li><a href="#">Link 2</a></li>
 <li><a href="#">Link 3</a></li>
 <li><a href="#">Link 4</a></li>
 </ul>
 </nav>
    <main class="main-container" role="main">
      <article class="article-container flex-container">
         <section class="main-content">
            <header>
               <h1>The <code>&lt;main></code> element</h1>
            </header>
            <p>As per the MDN definition:</p>
            <blockquote>
               <p>The HTML Main Element (<code>&lt;main></code>) represents&hellip;</p>
            </blockquote>
         </section>
         <aside class="side-content" role="complementary">
            <h2>What Does "Semantic HTML" Mean?</h2>
            <p>Semantic markup basically means that we use HTML tags to describe what a specific piece of content is.</p>
         </aside>
      </article>
      <footer class="main-footer" role="contentinfo">
         <p>Copyright &copy;</p>
         <ul class="nav-container" role="navigation">
            <li><a href="#">Footer Link 1</a></li>
            <li><a href="#">Footer Link 2</a></li>
            <li><a href="#">Footer Link 3</a></li>
            <li><a href="#">Footer Link 4</a></li>
            <li><a href="#">Footer Link 5</a></li>
         </ul>
      </footer>
    </main>
</body>
```

# 使用 WAI-ARIA 地标角色来增加可访问性

网络最被忽视的一个方面是可访问性，除非你是致力于这个主题的团体的一部分。作为网页设计师和开发者，我们很少考虑残障用户如何访问网页并使用屏幕阅读器和其他辅助技术来访问我们的网站或应用程序。我们实际上更关心支持旧版浏览器，而不是增加产品的可访问性。

在本章中，我们将介绍**WAI-ARIA landmark roles**是什么，以及如何在我们的标记中轻松实现它们，以增强我们文档的语义，为那些使用辅助技术的用户在任何现代浏览器上使用键盘浏览我们的网站/应用程序时提供更好和愉快的体验。

### 注意

**WAI-ARIA**代表**Web Accessibility Initiative – Accessible Rich Internet Applications**。

## WAI-ARIA landmark roles

WAI-ARIA landmark roles 也可以称为*ARIA roles*，所以这是我们将使用的术语。

当在 HTML5 元素中实现 ARIA 角色时，它看起来像这样：

```html
<header role="banner">
```

我们可以使用多个 ARIA 角色，但在本书中，我们将专注于那些更容易实现并且能够有效增强我们网站/应用程序可访问性的角色。

### 横幅角色

以下是一些重要的要点需要记住：

+   这个角色通常应用于页面的顶部`<header>`。

+   页眉区域包含页面的最突出的标题。

+   通常，具有`role="banner"`的内容会在整个站点中持续出现，而不是在单个特定页面中出现。

+   每个页面/文档只允许一个`role="banner"`。

考虑以下示例：

```html
<header class="masthead" role="banner">
    <div class="logo">Mastering RWD with HTML5 &amp; CSS3</div>
    <div class="search" role="search">
      <form>
         <label>Search:
            <input type="text" class="field">
            <button>Search Now!</button>
         </label>
      </form>
    </div>
</header>

```

### 导航角色

以下是一些重要的要点需要记住：

+   这个角色通常应用于`<nav>`元素，但也可以应用于其他容器，如`<div>`或`<ul>`。

+   它描述了一组导航元素/链接。这些链接可以是用于导航站点或者出现在页面上的链接。

+   每个页面可以有多个`role="navigation"`。

考虑以下示例，其中角色应用于主要的`<nav>`元素：

```html
<nav class="main-nav" role="navigation">
    <ul class="nav-container">
      <li><a href="#">Link 1</a></li>
      <li><a href="#">Link 2</a></li>
      <li><a href="#">Link 3</a></li>
      <li><a href="#">Link 4</a></li>
    </ul>
</nav>

```

考虑以下示例，其中角色应用于页脚导航的`<ul>`元素：

```html
<footer class="main-footer" role="contentinfo">
    <p>Copyright &copy;</p>
    <ul class="nav-container" role="navigation">
      <li><a href="#">Footer Link 1</a></li>
      <li><a href="#">Footer Link 2</a></li>
      <li><a href="#">Footer Link 3</a></li>
      <li><a href="#">Footer Link 4</a></li>
      <li><a href="#">Footer Link 5</a></li>
    </ul>
</footer>
```

对于我们将`navigation`角色添加到哪个元素并没有特定的偏好。如果我们将其添加到`<nav>`元素或`<ul>`元素中，效果是一样的。

### 主要角色

以下是一些重要的要点需要记住：

+   这个角色通常应用于页面的`<main>`元素。

+   页面的主要/中心主题的容器应该标记有这个角色。

+   每个页面/文档只允许一个`role="main"`。

考虑以下示例：

```html
<body>
    <main class="main-container" role="main">Content goes here
 </main>
</body>
```

### 内容信息角色

以下是一些重要的要点需要记住：

+   这个角色通常应用于页面的主要`<footer>`元素。

+   这是包含有关文档/站点/应用程序的信息的部分。

+   如果该部分包含例如版权链接、脚注、隐私声明链接或条款和条件链接，那么它是`role="contentinfo"`的一个很好的候选者。

+   每个页面/文档只允许一个`role="contentinfo"`。

考虑以下示例：

```html
<footer class="main-footer" role="contentinfo">
    <p>Copyright &copy;</p>
    <ul class="nav-container" role="navigation">
      <li><a href="#">Footer Link 1</a></li>
      <li><a href="#">Footer Link 2</a></li>
      <li><a href="#">Footer Link 3</a></li>
      <li><a href="#">Footer Link 4</a></li>
      <li><a href="#">Footer Link 5</a></li>
    </ul>
</footer>

```

### 搜索角色

以下是一些重要的要点需要记住：

+   这个角色通常应用于页面/应用程序搜索功能所属的`<form>`元素。

+   如果搜索表单包裹在`<div>`元素中，这个角色也可以应用于该`<div>`元素。如果是这种情况，那么就不需要将其添加到子`<form>`元素中。

+   每个页面可以有多个`role="search"`，只要控件是实际的搜索功能。例如，在联系表单上使用`role="search"`是不正确和不语义化的。

考虑以下示例，其中角色应用于站点的搜索`<form>`元素：

```html
<div class="search">
 <form role="search">
      <label>Search:
         <input type="text" class="field">
         <button>Search Now!</button>
      </label>
 </form>
</div>
```

### 表单角色

以下是一些重要的要点需要记住：

+   这个角色通常应用于包含某种表单的`<div>`元素，*除了*站点/应用的主搜索表单，例如联系表单、注册表单、付款表单等。

+   不应该应用于实际的`<form>`元素，因为该元素已经具有默认的角色语义，可以帮助技术支持。

考虑以下示例：

```html
<div class="contact-form" role="form">
    <header>
      <h2>Have Questions About HTML5?</h2>
    </header>
    <form>
      <div class="flex-container">
         <label class="label-col">Name: <input type="text" class="field name" id="name" required></label>
         <label class="label-col">Email: <input type="email" class="field email" id="email" required></label>
      </div>
      <label for="comments">Comments:</label>
      <textarea class="comments" id="comments" cols="50" required></textarea>
      <button>Send Question!</button>
    </form>
</div>

```

### 补充角色

以下是一些重要的要点：

+   这个角色通常应用于`<aside>`元素。

+   它应该用于包含支持内容的区域；即使与内容分开，它仍然可以独立理解。这基本上是`<aside>`元素的描述。

+   页面上可以有多个`role="complementary"`。

考虑以下示例：

```html
<aside class="side-content" role="complementary">
    <h2>What Does "Semantic HTML" Mean?</h2>
    <p>Semantic markup basically means that we use HTML tags to describe what a specific piece of content is.</p>
</aside>

```

### 注意

**WAI-ARIA 角色解释**

如果您对 ARIA 角色列表感兴趣，可以访问 Web 平台网站，那里的解释简单易懂：[`specs.webplatform.org/html-aria/webspecs/master/#docconformance`](https://specs.webplatform.org/html-aria/webspecs/master/#docconformance)

## RWD 的重要元标记

网页设计师和开发人员使用元标记的方式有很多，但这些广泛的解释超出了本书的范围，所以我们将专注于对 RWD 有用且按预期工作的一些要点。

以下元标记对我们的响应式网站/应用非常重要。这些元标记不仅适用于 HTML5 页面，它们也适用于任何 HTML 版本。

让我们开始吧。

### 视口元标记

`viewport`元标记是 RWD 中最重要的元标记。它是由苹果在其移动 Safari 浏览器中引入的。现在，其他移动浏览器也支持它。奇怪的是，这个元标记并不属于任何网页标准，但如果我们希望我们的响应式网站/应用在小屏幕上正确显示，它是必不可少的。

这个元标记的推荐语法如下：

```html
<meta name="viewport" content="width=device-width, initial-scale=1">
```

以下是一些重要的要点：

+   `name="viewport"`指令描述了元标记的类型。

+   `content="width=device-width, initial-scale=1"`指令执行了几项任务：

+   `width`属性定义了`viewport`元标记的大小。我们也可以使用特定的像素宽度，例如`width=960`。

+   `device-width`值是 CSS 像素中 100%缩放时屏幕的宽度。

+   `initial-scale`值定义了页面首次加载时应显示的缩放级别。1 等于 100%缩放，1.5 等于 150%缩放。

+   使用这种语法，用户可以根据需要进行缩放。这是用户体验的最佳实践。

### 注意

本书强烈不建议使用以下`viewport`属性：`maximum-scale=1`和`user-scalable=no`。通过使用这些`viewport`属性，我们剥夺了用户在我们的网站/应用中进行缩放的能力。我们永远不知道缩放对任何人都可能很重要，所以最好远离包含这些 viewport 属性。

为了帮助尚未响应式的网站在小屏幕上显示得更好，添加网站构建时的特定像素宽度。例如，如果一个网站宽度为 960px，就给它添加这个`viewport`元标记：

```html
<meta name="viewport" content="width=960">
```

如果您对`viewport`元标记的详细阅读感兴趣，MDN 解释得很好：[`developer.mozilla.org/en/docs/Mozilla/Mobile/Viewport_meta_tag`](https://developer.mozilla.org/en/docs/Mozilla/Mobile/Viewport_meta_tag)。

### X-UA-Compatible 元标记

`X-UA-Compatible`元标记仅针对 Internet Explorer 及其兼容性视图功能。众所周知，Microsoft 在 IE8 中引入了兼容性视图。

这个元标记的推荐语法如下：

```html
<meta http-equiv="X-UA-Compatible" content="IE=edge">
```

以下是一些重要的要点：

+   `http-equiv="X-UA-Compatible"`指令告诉 IE 需要使用特定的渲染引擎来渲染页面。

+   `content="IE=edge"`指令告诉 IE 应该使用其最新的渲染 HTML 和 JavaScript 引擎。

+   使用这个元标记来触发 IE 的最新 HTML 和 JavaScript 引擎非常好，因为 IE 的最新版本总是具有最新的安全更新和对更多功能的支持。

### 提示

不再需要使用`chrome=1`值，因为 Chrome Frame 在 2014 年 2 月被停用了。

### 注意

Google Chrome Frame 是一个针对旧版本 IE 的插件。安装后，它会替换 IE 中的某些模块，如渲染和 JavaScript 引擎，从而改善用户体验。换句话说，它就像在 IE 上安装了一个小版本的 Google Chrome。

### 字符集元标记

`charset`元标记告诉浏览器使用哪种字符集来解释内容。有人说包含它并不那么重要，因为服务器本身会通过 HTTP 头将字符集发送给浏览器。但在我们的页面中包含它总是一个好的措施。

如果 HTML 中没有声明`charset`，并且服务器没有将字符集发送给浏览器，那么一些特殊字符可能会显示不正确。

在 HTML5 中，这个元标记的推荐语法是这样的：

```html
<meta charset="utf-8">
```

以下是一些重要的要点需要记住：

+   这个元标记是专门为 HTML5 文档创建的。主要好处是写的代码更少。

+   对于 HTML 4 和 XHTML，你应该使用以下语法`：`

```html
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
```

+   另一个常见的值是`ISO-8859-1`，但`UTF-8`更广泛使用，因为浏览器正确解释内容的机会更大。

### 注意

**UTF-8**代表**Unicode 转换** **格式-8**。

# 一个带有 ARIA 角色和元标记的完整 HTML5 示例页面

现在我们已经了解了一些基本的 HTML5 元素，它们可以应用的 ARIA 角色，以及适合显示的正确元标记，让我们在一个完整的 HTML5 页面中将它们可视化：

```html
<!DOCTYPE html>
<html>
<head>
 <meta charset="utf-8">
 <meta http-equiv="X-UA-Compatible" content="IE=edge">
 <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Mastering RWD with HTML5 &amp; CSS3</title>
    <link rel="stylesheet" href="css/site-styles.css">
</head>
<body>
<header class="masthead" role="banner">
    <div class="logo">Mastering RWD with HTML5 &amp; CSS3</div>
    <div class="search" role="search">
      <form>
         <label>Search:
            <input type="text" class="field">
            <button>Search Now!</button>
         </label>
      </form>
    </div>
</header>
    <nav class="main-nav" role="navigation">
      <ul class="nav-container">
            <li><a href="#">Link 1</a></li>
            <li><a href="#">Link 2</a></li>
            <li><a href="#">Link 3</a></li>
            <li><a href="#">Link 4</a></li>
        </ul>
    </nav>
    <main class="main-container" role="main">
      <h1>Chapter 2: Marking Our Content with HTML5</h1>
      <p>Many consider that HTML is "code". Well, it's not. HTML, any version of it, is a "markup" language. </p>
      <article class="article-container flex-container">
         <section class="main-content">
            <header>
               <h1>The <code>&lt;main></code> element  </h1>
            </header>
            <p>As per the MDN definition:</p>
            <blockquote>
               <p>The HTML Main Element (<code>&lt;main></code>) represents&hellip;</p>
            </blockquote>
         </section>
         <aside class="side-content" role="complementary">
            <h2>What Does "Semantic HTML" Mean?</h2>
            <p>Semantic markup basically means that we use HTML tags to describe what a specific piece of content is.</p>
         </aside>
      </article>
      <div class="contact-form" role="form">
         <header>
            <h2>Have Questions About HTML5?</h2>
         </header>
         <form>
            <div class="flex-container">
               <label class="label-col">Name: <input type="text" class="field name" id="name" required></label>
               <label class="label-col">Email: <input type="email" class="field email" id="email" required></label>
            </div>
            <label for="comments">Comments:</label>
            <textarea class="comments" id="comments" cols="50" required></textarea>
            <button>Send Question!</button>
         </form>
      </div>
      <footer class="main-footer" role="contentinfo">
         <p>Copyright &copy;</p>
         <ul class="nav-container" role="navigation">
            <li><a href="#">Footer Link 1</a></li>
            <li><a href="#">Footer Link 2</a></li>
            <li><a href="#">Footer Link 3</a></li>
            <li><a href="#">Footer Link 4</a></li>
            <li><a href="#">Footer Link 5</a></li>
         </ul>
      </footer>
    </main>
</body>
</html>
```

作为奖励，让我们来看看将所有这些整合成一个漂亮响应式页面的 SCSS。

### 注意

以下的 SCSS 代码是使用桌面优先的方法构建的，因为我们将会逐步进入移动优先的方式。

这是 SCSS：

```html
//Media Query Mixin - Desktop-first
@mixin forSmallScreens($media) {
   @media (max-width: $media/16+em) { @content; }
}
//Nav
.main-nav {
    max-width: 980px;
    margin: auto;
    padding: 10px 5px;
    background: #555;
    @include forSmallScreens(420) {
       padding: 5px 0;
    }
}

//All Navigations
.nav-container {
    display: flex;
    justify-content: center;
    list-style-type: none;
    margin: 0;
    padding: 0;
    @include forSmallScreens(420) {
       flex-wrap: wrap;
    }
    li {
       display: flex;
       width: 100%;
       margin: 0 5px;
       text-align: center;
       @include forSmallScreens(420) {
          display: flex;
          justify-content: center;
          flex-basis: 45%;
          margin: 5px;
       }
    }
    a {
       @extend %highlight-section;
       display: flex;
       justify-content: center;
       align-items: center;
       width: 100%;
       padding: 10px;
       color: white;
    }
}

//Header
.masthead {
    display: flex;
    justify-content: space-between;
    max-width: 980px;
    margin: auto;
    padding: 10px;
    background: #333;
    border-radius: 3px 3px 0 0;
    @include forSmallScreens(700) {
       display: block;
       text-align: center;
    }
}

.logo {
    @extend %highlight-section;
    padding: 0 10px;
    color: white;
    line-height: 2.5;
    @include forSmallScreens(420) {
       font-size: .85em;
    }
}

//Search field
.search {
    @extend %highlight-section;
    padding: 5px;
    color: white;
    @include forSmallScreens(420) {
       font-size: .85em;
    }
    .field {
       width: auto;
       margin: 0 10px 0 0;
    }
    button {
       @include forSmallScreens(420) {
          width: 100%;
          margin-top: 10px;
       }
    }
}

//Main Container
.main-container {
    max-width: 980px;
    margin: auto;
    padding: 10px;
    background: #999;
    border-radius: 0 0 3px 3px;
}

//Article
.article-container {
    @extend %highlight-section;
    margin-bottom: 20px;
    padding: 10px;
}

    //Main Content of the Page
    .main-content {
       @extend %highlight-section;
       width: 75%;
       margin-right: 10px;
       padding: 10px;
       @include forSmallScreens(600) {
          width: 100%;
       }
       h1 {
          margin: 0;
       }
    }

    //Side Content
    .side-content {
       @extend %highlight-section;
       width: 25%;
       padding: 10px;
       font-size: .8em;
       background: #999;
       @include forSmallScreens(600) {
          width: 100%;
          margin-top: 12px;
       }
       h2 {
          margin: 0;
       }
       ol {
          padding-left: 20px;
       }
       a {
          color: #eee;
       }
    }

//Contact Form
.contact-form {
    @extend %highlight-section;
    width: 540px;
    margin: 0 auto 20px;
    padding: 20px;
    @include forSmallScreens(600) {
       width: 100%;
    }
    h2 {
       margin-top: 0;
    }
    label, button {
       display: block;
    }
    .comments {
       height: 100px;
    }
    .flex-container {
       justify-content: space-between;
       @include forSmallScreens(600) {
          display: flex;
       }
       @include forSmallScreens(400) {
          display: block;
       }
    }
    .label-col {
       width: 48%;
       @include forSmallScreens(400) {
          width: 100%;
       }
    }
}

//Form Elements
.field,
.comments {
    width: 100%;
    margin-bottom: 10px;
    padding: 5px;
    @include forSmallScreens(420) {
       width: 100%;
    }
}

//Footer
.main-footer {
    color: white;
    padding: 10px;
    background: #333;
    p {
       margin-top: 0;
    }
}

//Placeholder
%highlight-section {
    border: white 1px solid;
    border-radius: 3px;
    background: rgba(white, .1);
}

//Helper Classes
.flex-container {
    display: flex;
    @include forSmallScreens(600) {
       display: block;
    }
}

//General
*,
*:before,
*:after {
    box-sizing: border-box;
}

body {
    font-family: Arial, "Helvetica Neue", Helvetica, sans-serif;
}

blockquote {
    font-style: italic;
}
```

# 桌面和移动设备的输出截图

以下截图代表了线框和样式化模式下的原型/演示。您将能够看到桌面（宽 980 像素）以及移动设备（宽 320 像素）的输出。

在线框截图中，白色轮廓和不同色调的灰色背景基本上是视觉提示，帮助你理解每个元素的边界在哪里，而不必使用浏览器的开发工具。

另一方面，样式化截图向你展示了用少量 CSS 可以实现什么。线框和样式化页面都使用完全相同的标记。

页面的演示可以在这里看到：

+   访问[`codepen.io/ricardozea/pen/717c6ab2dab9646f814f0429153a6777`](http://codepen.io/ricardozea/pen/717c6ab2dab9646f814f0429153a6777)查看线框页面

+   访问[`codepen.io/ricardozea/pen/244886bac2434369bd038294df72fdda`](http://codepen.io/ricardozea/pen/244886bac2434369bd038294df72fdda)查看样式化页面

让我们看看截图。

桌面输出[线框]如下：

![桌面和移动设备的输出截图](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_02_01.jpg)

桌面输出[样式化]如下：

![桌面和移动设备的输出截图](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_02_02.jpg)

移动设备的输出[线框]如下：

![桌面和移动设备的输出截图](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_02_03.jpg)

移动设备的输出[样式化]如下：

![桌面和移动设备的输出截图](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-rsps-web-dsn/img/B02102_02_04.jpg)

# 总结

这是一个简短的章节，但它肯定充满了重要信息。

我们学到了 HTML 是标记而不是代码。我们还看到了各种 HTML5 元素的作用。这将帮助我们理解可以用哪些 HTML5 元素来标记我们提供的内容。

我们还学会了如何使用 ARIA 角色标记 HTML，以使我们的站点/应用对使用辅助技术的用户更加可访问。

我们还讨论了一些重要的元标记，这些标记将帮助您的页面和标记在不同设备上正确显示，并触发 Internet Explorer 中的最新 HTML 和 JavaScript 引擎。

最后，我们看到所有上述主题在一个实际的完整 HTML5 示例中实现，以及它的 SCSS。该示例是使用桌面优先方法构建的；这将使我们能够有条不紊地将我们的思维模式转变为移动优先技术。

下一章将讨论何时以及如何使用移动优先和/或桌面优先方法，以及如何使用每种方法论。拿出你的水晶球！
