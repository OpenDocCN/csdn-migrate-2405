# 精通 HTML5 表单（一）

> 原文：[`zh.annas-archive.org/md5/835835C6B2E78084A088423A2DB0B9BD`](https://zh.annas-archive.org/md5/835835C6B2E78084A088423A2DB0B9BD)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Web 浏览者可能永远不会了解应用程序的背景，比如 HTML5、CSS3、响应式网页设计或 PHP。他们想知道的是你的应用程序是否在他们的设备上运行，以及需要多少努力。

尽管多年来网页开发发生了变化，但创建网页的核心任务并未改变。我们创建一个文档并将其放在网上供人们查看。要将某物放在网上，我们需要学习一些在网上被接受的特殊语言。是的，我们说的是像 HTML 和 PHP 这样的脚本语言。

这本书的主要目标是确保填写你构建的表单的用户在各个方面都能享受并感到满意。这里的满意意味着表单的外观和感觉以及在导航时最小的页面调整，这可以是在台式电脑、移动设备或迷你笔记本上。

这本书的写作是考虑到读者应该享受一种逐步、示例驱动和基于视觉的学习方法。这本书将涵盖网页开发的许多方面，比如用于开发网页表单的语言，以及使网页表单看起来好看并接受访客信息的方法。

这本书将作为一个平台，让你学习如何创建美观且响应灵敏的表单，并将它们链接到数据库，表单信息将被存储在其中。

# 这本书涵盖了什么

第一章，*表单及其重要性*，解释了什么是网页表单，以及我们如何使用新的 HTML5 表单元素来创建这些表单。它还解释了网页表单的好处，以及在设计和开发表单时必须始终牢记的指南。

第二章，*表单验证*，解释了表单验证及其在表单中的必要性，以及新的 HTML5 元素及其属性，这些属性减少了客户端验证的工作量。它简要描述了验证约束和支持的 API，还向我们介绍了在浏览器上自定义错误消息的方法。

第三章，*表单样式*，解释了可以利用的 CSS3 属性，使表单更具展示性。它详细介绍了在不同浏览器中使用的供应商特定前缀，以及在增强表单外观和感觉时必须牢记的有效样式指南。

第四章，*与数据库连接*，简要解释了如何使用 PHP 和 MySQL 将表单链接到服务器，这是网页开发人员用来存储用户信息的工具。

第五章，*响应式网页表单*，解释了响应式设计和可以用来使我们的表单响应式的方法。它还讨论了制作响应式表单时应遵循的指南。

# 你需要为这本书准备什么

任何文本编辑器，如 Notepad++或 Bluefish 都可以用来编写 HTML 和 JavaScript 代码。在 Windows 中，Notepad 也可以用来创建一个简单的 HTML 文件，CSS 和 JavaScript 代码可以嵌入其中，然后可以在 Web 浏览器中打开。

好消息是几乎每个 Web 浏览器都配备了内置的 HTML 和 JavaScript 解释器，它在运行时在 Web 浏览器主机环境中编译代码并执行。

PHP 文件可以在用于编写 HTML、CSS 或 JavaScript 的任何编辑器中编写。在 Windows 中，Wamp 服务器用于将表单链接到服务器，phpMyAdmin 工具用于 MySQL 数据库。

# 这本书适合谁

这本书将帮助任何愿意提升使用 HTML5 和相关技术构建网页表单的技能的人。

这本书应该被那些有兴趣学习如何使用 HTML5、CSS3 和 PHP 来构建响应式、美观和动态网页表单的人阅读。

不同的读者会发现本书的不同部分有趣。

不必过多担心对以前的 W3C 规范和 PHP 有深入的了解，学习过 HTML 和 PHP 的初学者可以直接学习如何使用 HTML5、CSS3 和 PHP 构建网页表单，并收集客户信息。

# 约定

在本书中，您会发现一些区分不同信息类型的文本样式。以下是一些这些样式的示例，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下："我们可以通过使用`include`指令来包含其他上下文。"

代码块设置如下：

```html
<div class="gender">
  <label for="gender">Gender</label><br>
  <input type="radio" name="gender"><label>Male</label>
  <input type="radio" name="gender"><label>Female</label>
</div><br>
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```html
font-family: Helvetica, Arial, sans-serif;
  color: #000000;
  background: rgba(212,228,239,1);
  background: -moz-linear-gradient(top, rgba(212,228,239,1) 0%, rgba(134,174,204,1) 100%);
  background: -webkit-gradient(left top, left bottom, color-stop(0%, rgba(212,228,239,1)), color-stop(100%, rgba(134,174,204,1)));
```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的方式出现在文本中："为了将表单提交到服务器，我们创建了一个**提交**按钮"。

在本书中，我们已经使用了![约定](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_06.jpg)来表示 Mozilla Firefox、Google Chrome、Safari、Internet Explorer 和 Opera。

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：表单及其重要性

在网页中使用表单是从用户那里收集相关数据的最有效方式。表单是用户与应用程序真正交互的方式，无论是搜索表单、登录界面还是多页注册向导。表单可以包含姓名、性别、信用卡号、密码、图片或将文件上传到表单中。

在本章中，我们将涵盖以下主题：

+   网络表单及其好处

+   新的 HTML5 `<form>`元素

+   构建网络表单

+   构建网络表单的指南

# 理解网络表单

在我们开始学习 HTML5 表单之前，让我们先了解一下什么是网络表单。

网页上的表单提供了一个接口，使客户和用户之间的信息共享更加方便和安全，相比纸质表单。它们是各种`<input>`类型的集合，例如`textbox`、`radiobutton`和`checkbox`，允许用户执行各种操作并简化决策过程。

表单一直是网络的基本组成部分。没有它们，各种网络交易、讨论和高效搜索将根本不可能。网络表单得到大多数浏览器的支持，可以用于在购买产品后提供反馈、从搜索引擎检索搜索结果、联系任何服务等等。

通过一个简单的例子，让我们了解一下什么是网络表单。假设你曾经去过一家医院，接待员给了你一张打印的表格填写。你可能会看到许多字段，收集有关患者的信息。其中一些要求你在看起来像文本框或文本区域的地方写下患者的姓名和地址，以及房间类型等其他细节；你还被要求从选项中选择一个或多个单选按钮或复选框。HTML5 表单也是遵循相同的概念。你需要填写该表单的字段，并按下按钮将此信息发送到服务器，而不是去医院将表格交给接待员。

## 好处

网页中的表单相比纸质表单有很多优势。除了用于在线收集数据外，网络表单为用户和表单所有者提供了便利和速度。

网络表单的一些优点包括：

+   在线表单帮助客户与公司交流，因为它们包含数字化存储的数据，并将该数据推导为有意义的信息

+   表单所有者可以快速构建和分发 HTML5 界面，面向大众

+   表单所有者可以根据需要轻松更新和修改表单

+   层叠样式表（CSS）和 JavaScript 属性允许作者使用特定样式和功能自定义表单控件

+   网络表单节省时间和成本，因为它们不需要人力来收集信息。

+   它们为决策提供了可见性，例如在 eBay 等网站上在线购物

+   由于数据是由客户直接输入的，因此可以轻松地对其进行排序以获取所需的信息

即使表单有很多好处，构建它们并不是一件愉快的工作，如果涉及验证、错误处理和样式，有些表单可能会变得非常复杂，这可能会成为一个头疼的问题。我们可以使用服务器端语言验证或捕获错误，也可以使用 JavaScript，甚至两者都可以。无论哪种情况，网络表单可能会占用大量开发时间，这可能会成为一个问题。然而，通过引入新的`<form>`类型，HTML5 已经减轻了一些痛苦。

尽管 HTML5 有许多增强功能，但有些东西保持不变，比如：

+   当用户单击**提交**按钮时，表单仍然会将值发送到服务器

+   表单仍然被包含在`<form>`元素中，如下面的代码片段所示：

```html
<form action= "#">
  <input type= "text" name= "emailaddress">
  <input type= "submit" name= "submit">
</form>
```

+   表单控件仍然可以完全进行脚本处理

然而，对于 HTML5 表单，没有必要将`<form>`控件包含在`<form>`元素中。

# HTML 与 HTML5 表单

HTML5 表单相对于以前的版本提供了两个主要优势。它们是：

+   在 HTML5 的新`<form>`类型和内置验证的支持下，以前版本的 HTML 中需要繁琐的脚本和表单样式已经被移除，因为它将语义标记提升到了一个新的水平。

+   即使在浏览器中禁用了脚本，用户也可以体验到 HTML5 表单的好处

# 表单`<input>`类型、元素和属性

HTML5 表单专注于增强现有的简单 HTML 表单，以包含更多类型的控件，并解决今天 Web 开发人员面临的限制。其中最好的一点是，你现在几乎可以使用所有新的输入类型、元素和属性，HTML5 表单完全向后兼容。支持新 HTML5 元素的浏览器会增强其功能，否则不支持的浏览器会将其显示为文本框。

在本节中，我们将学习新的 HTML5`<form>`元素，如`<input>`类型、元素和属性，这些元素是为了增强表单的功能而引入的。

## `<form> <input> types`

+   `date`: `date` 类型允许用户选择没有时区的日期。

它在![<form> <input> types](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_01.jpg)中受支持。

语法：

```html
<input type= "date" name= "#">
```

属性：

+   `value`: 初始值。格式为 yyyy-mm-dd

+   `min`, `max`: 可以选择的最小和最大日期的范围

+   `datetime`: `datetime` 类型允许用户选择带有 UTC 时区设置的日期和时间。

格式为 yyyy-mm-dd HH:MM。

它在![<form> <input> types](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_02.jpg)中受支持。

语法：

```html
<input type= "datetime" name= "#">
```

+   `datetime-local`: `datetime-local` 类型允许用户选择没有时区的日期和时间。使用的格式是 yyyy-mm-dd HH:MM。

它在![<form> <input> types](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_03.jpg)中受支持。

语法：

```html
<input type= "datetime-local" name= "#">
```

+   `color`: `color` 类型会打开一个颜色选择器弹出窗口，用于选择`<input>`类型的颜色`#rrggbb`（十六进制值）。它可以用色块或轮式选择器表示。

选择的值必须是有效的简单颜色的十六进制值，如`#ffffff`。

它在![<form> <input> types](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_04.jpg)中受支持。

语法：

```html
<input type= "color" id= "#"name= "#">
```

属性：

+   `value`: 初始值

+   `number`: `number` 类型允许用户输入`整数`或`浮点数`。

它也被称为微调器。

我们可以对接受的数字设置限制。

它在![<form> <input> types](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_05.jpg)中受支持。

语法：

```html
<input type= "number" name= "#">
```

属性：

+   `value`: 初始值

+   `min`, `max`: 可以使用上/下箭头选择的最小和最大值的范围

+   `step`: 当滚动微调器时告诉我们要改变值的量

+   `range`: `range` 类型允许用户从一系列数字中输入`整数`或`浮点数`。它以滑块的形式显示。

使用这个，除非使用 JavaScript，否则不会显示确切的值，所以如果你希望用户选择确切的值，使用`<input type="number" />`。

我们可以对接受的数字设置限制。

它在![<form> <input> types](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_06.jpg)中受支持。

语法：

```html
<input type= "range" name= "#">
```

属性：

+   `value`: 初始值。默认值是滑块的中间值。

+   `min`, `max`: 可以选择的最小和最大值的范围。最小值的默认值为 0，最大值为 100。

+   `step`: 当滚动微调器时告诉我们要改变值的量。默认值为 1。

+   `email`: `email` 类型允许用户以电子邮件地址格式`email@example.com`输入文本。

点击**提交**按钮时，输入的文本会自动验证。

如果指定了多个属性，则可以输入多个电子邮件地址，用逗号分隔。

它在![<form> <input> types](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_07.jpg)中受支持。

语法：

```html
<input type= "email" name= "#">
```

属性：

+   `value`: 初始值（合法的电子邮件地址）

接受使用多个属性，即多个电子邮件 ID，并且每个属性由逗号分隔。

+   `搜索`：`<input>`类型`搜索`允许用户输入要搜索的文本。

搜索字段的行为类似于标准文本字段，并具有内置的清除文本功能，例如 WebKit 浏览器中的交叉按钮。

它在![<form> <input>类型](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_08.jpg)中得到支持。

语法：

```html
<input type= "search" name= "#">
```

属性：

+   `值`：初始值

+   `电话`：`tel`类型允许用户输入电话号码。`tel`不提供任何默认语法，因此如果您想确保特定格式，可以使用`pattern`进行额外验证。

目前尚无浏览器支持。

语法：

```html
<input type= "tel" name= "#">
```

属性：

+   `值`：初始值为电话号码

+   `月份`：`月份`类型允许用户选择一个月和一个没有时区的年份。

它在![<form> <input>类型](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_09.jpg)中得到支持。

语法：

```html
<input type= "month" name= "#" >
```

属性：

+   `值`：初始值。格式为 yyyy-mm。

+   `最小值`，`最大值`：可以选择的最小和最大值范围。

+   `时间`：`时间`类型允许用户选择一个具有小时、分钟、秒和没有时区的分数秒的时间值。

它在![<form> <input>类型](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_10.jpg)中得到支持。

语法：

```html
<input type= "time" name= "#">
```

+   `网址`：`网址`类型允许用户输入绝对 URL。

单击**提交**按钮时，输入的文本会自动验证。

它在![<form> <input>类型](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_11.jpg)中得到支持。

语法：

```html
<input type= "url" name= "#" >
```

属性：

+   `值`：初始值为绝对 URL

+   `周`：`周`类型允许用户选择一周和一年，没有时区。

它在![<form> <input>类型](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_12.jpg)中得到支持。

语法：

```html
<input type= "week" name= "#">
```

属性：

+   `值`：初始值。格式为 yyyy-mmW。

到目前为止，我们已经了解了各种`<input>`类型。现在让我们看看新的 HTML5`<form>`元素。

## `<form>`元素

+   `<datalist>`：`<datalist>`元素为用户提供了一个预定义选项列表，以便在输入数据时为表单控件提供`自动完成`功能。它用于在`<form>`元素上提供`自动完成`功能。

例如，如果用户在文本字段中输入一些文本，将会显示一个下拉列表，其中包含他们可以选择的预填充值。

它在![<form>元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_13.jpg)中得到支持。

例如：

```html
<input list= "browsers" name= "browser">
<datalist id= "browsers">
  <option value= "Internet Explorer">
  <option value= "Firefox">
</datalist>
```

+   `<keygen>`：`<keygen>`元素用于提供一种安全的用户认证方式。

当表单提交时，私钥存储在本地密钥库中，公钥打包并发送到服务器。

它在![<form>元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_14.jpg)中得到支持。

例如：

```html
<form action= "keygen.html" method= "get"><input type= "text" name= "username"><keygen name= "security"><input type= "submit">
</form>
```

+   `<output>`：`<output>`元素表示执行的计算结果，类似于脚本执行的计算结果。

它在![<form>元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_15.jpg)中得到支持。

例如：

```html
<form onsubmit="return false" oninput="o.value=parseInt(a.value)+parseInt(b.value)"><input name="a" type="number" step="any">+<input name="b" type="number" step= "any">
=<output name="o"></output></form>
```

现在让我们看看新的 HTML5`<form>`属性。

## `<form>`属性

+   `自动完成`：`autocomplete`属性允许用户根据先前的输入完成表单。我们可以为表单设置自动完成`on`选项，为特定输入字段设置`off`选项，或者反之亦然。

它适用于`<form>`和`<input>`类型，如`文本框`，`日期选择器`，`范围`，`颜色`，`网址`，`电话`，`搜索`和`电子邮件`。

它在![<form>属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_16.jpg)中得到支持。

例如：

```html
<input type="text" name="city" autocomplete="on">
```

+   `自动聚焦`：当添加`autofocus`属性时，`<input>`类型在页面加载时会自动获得焦点。

例如，当我们打开 Google 主页或任何搜索引擎时，焦点会自动转到文本框，用户在其中输入文本以执行搜索。

它适用于`<input>`类型，`文本框`，`搜索`，`网址`，`电子邮件`，`电话`和`密码`。

它在![<form>属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_17.jpg)中得到支持。

例如：

```html
<input type="text" name="city">
<input type="text" name="state" autofocus>
```

+   `占位符`：`placeholder`属性为用户提供了描述`<input>`字段预期值的提示。

当单击控件或获得焦点时，它会消失。

它应该仅用于简短的描述，否则使用`title`属性。

它适用于`textbox`、`search`、`url`、`email`、`tel`和`password`类型的`<input>`。

它在![<form>属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_18.jpg)中得到支持。

例如：

```html
<input type="text" name="name" placeholder="First Name">
```

+   `min`和`max`：`min`和`max`属性用于指定`<input>`类型的最小值和最大值。

它适用于`number`、`range`、`date`、`datetime`、`datetime-local`、`month`、`time`和`week`类型的`<input>`。

它在![<form>属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_19.jpg)中得到支持。

例如：

```html
<input type="number" min="1" max="5">
```

+   `list`：`list`属性指的是包含`<input>`元素的预定义选项的`<datalist>`元素。

它用于在`<form>`元素上提供`autocomplete`功能。

例如，如果用户在文本字段中输入一些文本，将会出现一个下拉列表，其中包含预填充的值供他们选择。

它适用于`textbox`、`search`、`url`、`email`、`tel`类型的`<input>`。

它在![<form>属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_20.jpg)中得到支持。

例如：

```html
<input list= "browsers" name= "browser">
<datalist id= "browsers">
  <option value= "Internet Explorer">
  <option value= "Firefox">
</datalist>
```

+   `formnovalidate`：`formnovalidate`属性指定在提交时不应验证表单。它覆盖了`<form>`元素的`novalidate`属性。

它适用于`submit`和`image`类型的`<input>`。

它在![<form>属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_21.jpg)中得到支持。

例如：

```html
<input type="email" name="email"><input type="submit" formnovalidate value="Submit">
```

+   `form`：`form`属性指定一个或多个表单，一个`<input>`类型属于这些表单，或者说，它允许用户将任何孤立的表单控件与页面上的任何`<form>`元素关联起来。

它在![<form>属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_22.jpg)中得到支持。

例如：

```html
<body>
  <form action="form.html" id="form1"><input type="text" name="fname"><br><input type="submit" value="Submit"></form>
  <p>The "Last name" field below is outside the form element, but it is still a part of the form</p>
  <input type="text" name="lname" form="form1">
</body>
```

+   `formaction`：`formaction`属性指定将提交表单的文件或应用程序的 URL。

它适用于`submit`和`image`类型的`<input>`。

它在![<form>属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_23.jpg)中得到支持。

例如：

```html
<input type="submit" value="Submit" formaction="form.html">
```

+   `formenctype`：`formenctype`属性指定提交到服务器时如何对表单数据进行编码。

它仅适用于`post`方法。

它适用于`submit`和`image`类型的`<input>`。

它在![<form>属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_24.jpg)中得到支持。

例如：

```html
<input type="submit" value="Submit" formenctype="multipart/form-data">
```

+   `formmethod`：`formmethod`属性指定用于提交表单数据的 HTTP 方法，如`GET`、`POST`、`PUT`和`DELETE`。

它适用于`submit`和`image`类型的`<input>`。

它在![<form>属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_25.jpg)中得到支持。

例如：

```html
<input type="submit" value="Submit" formmethod="post">
```

+   `formtarget`：`formtarget`属性指定提交表单后用于显示接收到的响应的目标窗口。

它适用于`submit`和`image`类型的`<input>`。

它在![<form>属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_26.jpg)中得到支持。

例如：

```html
<input type="submit" value="Submit" formtarget="_self">
```

值：

+   `blank`

+   自身

+   `parent`

+   `top`

+   框架名称

+   `multiple`：`multiple`属性允许用户为`<input>`类型输入多个值。

它适用于`email`和`file`类型的`<input>`。

它在![<form>属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_27.jpg)中得到支持。

例如：

```html
<input type= "file" name= "image"multiple>
```

+   `novalidate`：`novalidate`属性指定在单击**提交**按钮时不应验证表单。

它在![<form>属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_28.jpg)中得到支持。

例如：

```html
<form action= "form.html" novalidate>
  <input type= "text" name= "city">
  <input type= "text" name= "state" autofocus>
</form>
```

+   `step`：让我们通过一个例子来理解`step`属性。如果`step=` `2`，合法的数字可以是`2`、`0`、`2`、`4`和`6`。

它适用于`<input>`类型，包括`number`、`range`、`date`、`datetime`、`datetime-local`、`month`、`time`和`week`。

它在![<form>属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_29.jpg)中得到支持。

例如：

```html
<input type= "range" name= "#" step= "2">
```

+   `required`：添加`required`属性后，强制要求在提交表单之前必须填写输入字段。

目前，错误消息是特定于浏览器的，无法通过 CSS 控制。

它取代了用 JavaScript 实现的基本`<form>`验证，从而节省了开发时间。

它在![<form>属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_30.jpg)中得到支持。

例如：

```html
<input type= "text" name= "city"required>
```

+   `pattern`：使用 `pattern` 属性，您可以使用 `正则表达式`（`regex`）声明自己的验证要求。

它适用于 `<input>` 类型，如 `text`、`search`、`url`、`tel`、`email` 和 `password`。

如果用户输入的值不符合模式，它将显示一个浏览器通用的消息。

它在 ![<form> 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_31.jpg) 中得到支持。

例如：

```html
<input type= "text" name= "country_code" pattern= "[A-Za-z]{3}" placeholder= "Three letter country code">
```

# 构建 HTML5 表单

到目前为止，我们所学习的关于 HTML5 表单的只是理论知识，但现在是时候将这些知识提升到下一个水平了。将其提升到下一个水平意味着在这一部分，我们将构建一个带有对它们的结构和新的 `<form>` 类型的一些理解的样本表单，这些我们已经讨论过了。

在样式或功能（如设计和验证）方面，我们将花费更少的时间，而更多地关注 HTML5 的新 `<form>` 类型的核心。这种表单在支持 HTML5 特性的浏览器中得到最好的支持。

在这个例子中，我们将构建一个健康调查表单。

这个例子演示了一个简单的表单，使用了基本的 HTML 元素和新的 `<form>` 元素，代码应该是不言自明的。

现在，让我们来看看代码。以下代码是表单的 CSS，它保存在一个扩展名为 `.css` 的单独文件中（外部 CSS 文件），并链接到主 HTML 页面。拥有单独的 CSS 文件也是一个好的做法。

```html
html {
  background-color: #333;
  margin: 0px;
  padding: 0px;
}
body {
  font-size:12px;
  width: 517px;
  padding: 20px;
  margin: 10px auto;
  background-color: #eee;
  font-family: Helvetica, Arial, sans-serif;
  color: #333;
}
label{
  font-weight:bold;
}

/* General Form */
.heading{
  font-size:20px;
}
.gender{
  position:relative;
  top:-42px;
  left:185px;
}
.selectOption{
  width:239px;
}
.textboxAddress{
  width:474px;
}
.textboxAddressDetail{
  width:232px;
}
.legend{
  font-weight:bold;
  font-size:14px;
}
.submit{
  text-align:center;
}
```

以下代码是我们构建表单结构的主要 HTML 页面。`<fieldset>` 标签被包含在 `<form>` 标签内。

结构被分成了几个部分，以便更好地理解。此外， `<form>` 类型被加粗显示。

以下是用于显示个人信息表单的代码片段：

```html
<fieldset>
  <legend class="legend">Personal Information</legend>
  <div>
    <label for="name">Name</label><br>
    <input type="text" placeholder="First" autofocus>
    <input type="text" placeholder="Last">
  </div><br>
  <div>
    <label for="dob">Date of Birth</label><br>
    <input type="date" value="">
  </div>
  <div class="gender">
    <label for="gender">Gender</label><br>
    <input type="radio" name="gender"><label>Male</label>
    <input type="radio" name="gender"><label>Female</label>
  </div><br>
  <div>
    <label for="address">Address</label><br>
    <input type="text" class="textboxAddress" placeholder="Street Address"><br>
    <input type="text" class="textboxAddress" placeholder="Address Line 2"><br>
    <input type="text" class="textboxAddressDetail" placeholder="City">  
    <input type="text" class="textboxAddressDetail" placeholder="State/Province"><br>
    <input type="text" class="textboxAddressDetail" placeholder="Pincode">
    <select class="selectOption">
      <option value="Country">Select Country</option>
    </select>
  </div><br>
  <div>
    <label for="contact">Phone Number</label><br>
    <input type="tel" class="textboxAddressDetail" placeholder="Home"> 
    <input type="tel" class="textboxAddressDetail" placeholder="Work">
  </div><br>
  <div>
    <label for="email">Email Address</label><br>
    <input type="email" class="textboxAddressDetail" placeholder="email@example.com">
  </div>
</fieldset>
```

### 提示

**下载示例代码**

您可以从您在 [`www.packtpub.com`](http://www.packtpub.com) 购买的所有 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了本书，您可以访问 [`www.packtpub.com/support`](http://www.packtpub.com/support) 并注册，以便直接通过电子邮件接收文件。

代码的输出如下：

![构建 HTML5 表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_32.jpg)

这一部分询问受访者有关他们的个人信息，如姓名、地址和其他详细信息。我们使用了带有描述性文本的 `<label>` 并将其与表单控件绑定。

我们还在第一个文本框上使用了 `autofocus` 属性，这样当页面加载时，`<input>` 元素会自动获得焦点。`placeholder` 属性在第一个文本框中多次使用，作为`First`来提示受访者所需的内容。对于出生日期，我们使用了 `<input>` 类型 `date`，它会以日历形式打开。

还使用了基本的 HTML 元素 `<input>` 类型，如 `radiobutton`、`textbox` 和下拉列表。

同样，对于电话号码字段，使用了 `<input>` 类型 `tel`，对于电子邮件地址字段，使用了 `<input>` 类型 `email`。

以下是用于显示一般信息表单的代码片段：

```html
<fieldset>
  <legend class="legend">General Information</legend>
  <div>
    <label for="info">What is your</label><br>
    <input type="text" placeholder="Age?"> 
    <input type="text" placeholder="Weight?"> 
    <input type="text" placeholder="Height?">
  </div><br>
  <div>
    <label for="exerciceinfo">Do you regularly engage in any of the following exercises?</label><br>
    <div><input type="checkbox" name="smoke"><label>Walking</label><br>
    <input type="checkbox" name="smoke"><label>Running</label></div>
    <div><input type="checkbox" name="smoke"><label>Swimming</label><br>
    <input type="checkbox" name="smoke"><label>Biking</label></div>
    <div><input type="checkbox" name="smoke"><label>Others</label><br>
    <input type="checkbox" name="smoke"><label>I don't exercise</label></div>
  </div><br>
  <div>
    <label for="sleep">On average, how many hours a day do you sleep?</label><br>
    <input type="number" class="textboxAddressDetail">
  </div><br>
  <div>
    <label for="smoking">Have you ever smoked cigarettes, pipes or cigars?</label><br>
    <input type="radio" name="smoke"><label>Yes</label>
    <input type="radio" name="smoke"><label>No</label>
  </div><br>
  <div>
    <label for="drugs">Are you currently using or do you have a history of illegal drug use?</label><br>
    <input type="radio" name="drugs"><label>Yes</label>
    <input type="radio" name="drugs"><label>No</label>
  </div><br>
  <div>
    <label for="alcohol">Do you consume alcohol?</label><br>
    <input type="radio" name="alcohol"><label>Yes</label>
    <input type="radio" name="alcohol"><label>No</label>
  </div>
</fieldset>
```

代码的输出如下：

![构建 HTML5 表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_33.jpg)

表单的顶部部分询问受访者一般信息，如年龄、体重、身高以及其他关于他们日常生活的信息。

在这里，我们使用了基本的 HTML `<form>` `<input>` 类型，如 `textbox`、`radiobutton` 和 `checkbox`，以及新的 `<form>` 属性，如 `placeholder`，来从受访者那里获取输入。

以下代码片段显示了一个存储医疗信息的表单：

```html
<fieldset>
  <legend class="legend">Medical Information</legend>
  <div>
    <label for= "disease">Check all that apply to you or your immediate family?</label><br>
    <input type="checkbox" name="disease"><label>Asthma</label><br>
    <input type="checkbox" name="disease"><label>Cancer</label><br>
    <input type="checkbox" name="disease"><label>HIV and AIDS</label><br>
    <input type="checkbox" name="disease"><label>Diabetes</label><br>
    <input type="checkbox" name="disease"><label>Hypertension</label><br>
    <input type="checkbox" name="disease"><label>Malaria</label><br>
    <input type="checkbox" name="disease"><label>Seizure Disorder</label><br>
    <input type="checkbox" name="disease"><label>Psychiatric Disorders</label><br>
    <input type="checkbox" name="disease"><label>Mental Health</label><br>
    <input type="checkbox" name="disease"><label>Stroke</label><br>
    <input type="checkbox" name="disease"><label>Others</label><br>
    <input type="checkbox" name="disease"><label>Not Applicable</label>
  </div><br>
  <div>
    <label for= "symptons">Checkall symptoms you are currently experiencing</label><br>
    <input type="checkbox" name="symptoms"><label>Allergy</label><br>
    <input type="checkbox" name="symptoms"><label>Eye</label><br>
    <input type="checkbox" name="symptoms"><label>Lymphatic</label><br>
    <input type="checkbox" name="symptoms"><label>Fever</label><br>
    <input type="checkbox" name="symptoms"><label>Eating Disorder</label><br>
    <input type="checkbox" name="symptoms"><label>Hemtalogical</label><br>
    <input type="checkbox" name="symptoms"><label>Musculoskeletal Pain</label><br>
    <input type="checkbox" name="symptoms"><label>Skin</label><br>
    <input type="checkbox" name="symptoms"><label>Gastrointestinal</label><br>
    <input type="checkbox" name="symptoms"><label>Weight Loss</label><br>
    <input type="checkbox" name="symptoms"><label>Others</label><br>
    <input type="checkbox" name="symptoms"><label>Not Applicable</label>
  </div><br>
  <div>
    <label for="allergy">Please list any medication allergies that you have</label><br>
    <textarea name="allergy" rows="4" cols="57">
    </textarea>
  </div><br>
  <div>
    <label for="medications">Please list any medications you are currently taking</label><br>
    <textarea name= "medications" rows="4" cols="57">
    </textarea>
  </div><br>
  <div>
    <label for="pregnancy">If you are a woman, are you currently pregnant, or is there a possibility that you are pregnant?</label><br>
    <input type="radio" name="pregnancy"><label>Yes</label>
    <input type="radio" name="pregnancy"><label>No</label>
    <input type="radio" name="pregnancy"><label>Not Applicable</label>
  </div><br>
  <div>
    <label for="healthrating">In general, would you say your health is</label><br>
    * Taking 1 to be poor and 5 to be excellent<br>
    <input type="number" name="healthrating" min="1" max="5">
  </div><br>
    <label for="ratinghealth">When you think about your health care, how much do you agree or disagree with this statement: "I receive exactly what I want and need exactly when and how I want and need it."</label><br>
    * Taking 1 to be strongly dis-agree and 5 to be strongly agree<br>
    1<input type="range" name="ratinghealth" min="1" max="5">5
  </div> 
</fieldset>

<div class="submit">
  <input type="submit" value="Submit">
</div>
```

代码的输出如下：

![构建 HTML5 表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_01_34.jpg)

我们表单的最后部分询问受访者有关他们的医疗信息。为了获取受访者所患各种疾病或症状的信息，我们使用了基本的 HTML `<form>` `<input>` 类型 `checkbox`。

`Textarea`是一个自由文本字段，其中包含详细的文本，在我们的情况下，允许受访者输入信息，例如药物过敏和药物。`textarea`的行和列确定了表单中`textarea`文本字段的可显示大小。我们还可以通过设置`maxlength`来限制受访者输入详细信息。

`radiobutton`用于限制受访者从多个选项中选择一个选项。

使用`<input>`类型`number`，我们创建了一个微调器，这是一个精确的控件，用于选择由数字表示的字符串。在这里，我们通过将最小值设置为`1`和最大值设置为`5`来设置限制。

使用`<input>`类型`range`，我们创建了一个滑块，这是一个不精确的控件，用于将值设置为表示数字的字符串。在这里，我们通过将最小值设置为`1`和最大值设置为`5`来设置限制。

最后，`<input>`类型`submit`将数据发送到服务器。

# 指导方针

一个良好的实践或指导方针是设计和开发一个标准的方法，这总是表现出更好的结果。

创建有效表单的一些最佳实践如下：

+   使用相关内容分组来组织表单

+   最小化填写表单所需的帮助和提示的数量

+   采用灵活的数据输入

+   对于长表单，显示进度并保存选项

+   保持一致的方法

+   保持初始选择选项之间的清晰关系

+   使用内联验证输入，可能具有较高错误率

+   提供可操作的补救措施来纠正错误

+   在用户单击提交按钮后禁用**提交**按钮，以避免多次提交

+   清楚地传达关于数据提交的信息并提供反馈

+   保持 CSS 和 JavaScript 的单独文件

使用最佳实践：

+   提高跨浏览器兼容性

+   提高性能

+   节省时间并降低成本

+   项目理解变得容易

+   代码维护变得容易

# 总结

在本章中，我们了解了表单及其使用的好处。我们已经看到了基本的 HTML 表单和 HTML5 表单之间的区别。

我们了解了新的`<form>`控件，`date`，`week`，`tel`，`email`，`range`，`numbers`等等，我们不必依赖 JavaScript，以及它们在现代浏览器中的工作方式。

我们还构建了一个示例表单，以便熟悉表单，并在本章末尾学习了创建有效网络表单的最佳实践。

总的来说，我们已经看到了如何通过 HTML5 的帮助来减少脚本编写和开发时间，当用户需要创建具有完整功能的表单时。


# 第二章：表单验证

自从 Web 诞生以来，表单验证一直是开发人员头疼的问题。在 HTML5 出现之前，开发人员为了验证表单以获取用户所需的信息而编写了大量代码。

在本章中，我们将涵盖以下主题：

+   验证、它们的好处和类型

+   用于验证的 HTML5 `<input>`和属性

+   JavaScript 和 HTML5 验证的区别及示例

+   验证约束和支持的 API（应用程序编程接口）

+   浏览器显示的默认错误消息

# 表单验证

表单验证是一系列检查和通知，指导用户在向服务器提交信息时需要输入什么。我们也可以说，这是一种检查输入数据是否符合特定标准或要求的过程。

表单验证是检测无效控件数据并向最终用户显示这些错误的过程。该术语具有以下几个好处：

+   提供必要的指示和提示

+   提供元素的逻辑阅读和导航顺序

+   用户可以轻松地了解他们在输入数据时所犯的错误

+   确保可以使用键盘完成并提交表单

+   节省用户在 HTTP 请求或网络调用上的等待时间

+   节省服务器所有者的时间和内存，不必处理错误的输入

验证确保用户提供了足够的数据，例如在线购物通常包括地址、电子邮件地址等许多必需的细节，以便完成交易。

有许多方法可以执行表单验证，可以归类为以下几种：

+   客户端表单验证

+   服务器端表单验证

## 客户端表单验证

客户端验证可以在支持 HTML5 属性的浏览器上执行，甚至可以借助 JavaScript 在其他浏览器上执行。与繁琐的 JavaScript 验证相比，HTML5 属性减少了验证的工作量。

客户端表单验证的优点如下：

+   它通过在客户端快速响应来增强用户体验

+   在用户填写`<form>`控件后，验证可以在将表单提交到服务器之前发生

+   这种方法非常简单，因为它确保用户已经填写了必需的字段，并且填写表单时也会指导用户正确操作

+   这是一种快速的验证形式，因为它不需要任何服务器端脚本。

客户端表单验证的缺点如下：

+   它可以在客户端的浏览器中禁用，并且不提供任何安全机制

+   这种方法无法保护我们的应用程序免受在网络上传输数据时的各种安全问题

+   客户端验证提供的安全性较低，因为它很容易被篡改或绕过

## 服务器端表单验证

各种脚本语言，如 PHP、ASP 或 Perl，用于在服务器端对用户提交的数据进行筛选和过滤。

当我们知道某些检查只能在服务器端执行时，就会使用这种方法，因为需要安全性，比如在线购物，用户输入卡片详细信息进行付款。

服务器端表单验证的优点如下：

+   可以提交有效和完整的信息，而无需进行错误恢复消息和警告。

+   用户在浏览器中看到的每个页面都会下载到计算机上，其中包括具有验证代码的 JavaScript。因此，黑客可以创建一个新版本的页面，没有任何验证，并且可以通过输入无效数据来愚弄我们的服务器。在这种情况下，服务器端验证是有帮助的。

+   服务器端验证更安全，不容易被篡改或绕过。

服务器端表单验证的缺点如下：

+   这种方法需要更多的响应时间，导致用户体验不佳。

+   服务器端处理代码重新提交页面，以显示错误消息

+   为了最小化请求-响应生命周期，它同时验证所有表单字段

或多或少，我们都依赖 JavaScript 来验证表单。此外，我们应该始终记住，客户端表单验证不能替代完备的服务器端验证和处理错误。这是一种有效的方式，在客户端为用户输入提供即时反馈。在在线购物的情况下，用户选择了总件数，但在一定限制后，用户看到了超出限制的错误。所有这些验证都需要高端的服务器端验证，这在客户端是不可能的。请记住，在表单的情况下，请使用服务器端验证。

# HTML5 表单验证

引入 HTML5 验证的目的是通知用户页面包含一些必填信息，需要填写或使用浏览器内置的处理纠正用户的任何错误。我们应该利用浏览器具有的所有功能和知识，在将表单发送到服务器之前，捕捉表单中的错误。此外，我们不需要担心网络往返的时间和费用，或者从服务器获取关于某些愚蠢错误的响应。

新的`<input>`属性，如`required`和`pattern`，与 CSS 伪类选择器结合使用，使得编写检查和向用户显示反馈变得更加容易。还有其他高级验证技术，允许您使用 JavaScript 设置自定义有效性规则和消息，或确定元素是否无效以及原因。

在深入了解 HTML5 验证之前，让我们看看使用 JavaScript 执行客户端验证时的区别，以及我们如何使用 HTML5 `<form>` 控件进行验证。在下面的示例中，我们正在验证一个用户必须填写的简单文本框。

## 代码 1-使用 JavaScript 验证文本框

以下代码将使用 JavaScript 验证文本框：

```html
<head>
<script>
  function validateField()
  {
    var x=document.forms["Field"]["fname"].value;
    if (x==null || x==""){
      alert("Please enter your name");
      return false;
    }
  }
</script>
</head>
<body>
  <form name="Field" action="#" onsubmit="validateField()"method= "post">
  First name: <input type= "text" name= "fname">
  <input type= "submit" value= "Submit">
</form>
</body>
```

上述代码的输出将如下截图所示：

![代码 1-使用 JavaScript 验证文本框](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_01.jpg)

## 代码 2-使用 HTML5 <form>控件验证文本框

以下代码将使用 HTML5 验证文本框：

```html
<head>
<script>
</script>
</head>
<body>
  <form name= "Field" action= "#">
  First name: <input type= "text" name= "fname" required>
  <input type= "submit" value= "Submit">
</form>
</body>
```

上述代码的输出将如下截图所示：

![代码 2-使用 HTML5 <form>控件验证文本框](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_02.jpg)

在前两个代码示例中，我们看到第一个代码中的`<script>`部分被 HTML5 `<form>`控件的单个属性所取代，这不仅减少了代码行数，还消除了 JavaScript 的范围。

# 约束验证

浏览器在提交表单时运行的算法称为约束验证。为了约束数据或检查有效性，该算法利用了新的 HTML5 属性，如`min`、`max`、`step`、`pattern`和`required`，以及现有属性，如`maxlength`和`type`。

在 HTML5 中，基本约束有两种不同的声明方式：

+   通过为`<input>`元素的`type`属性选择最语义化的值

+   通过在验证相关属性上设置值，并允许以简单的方式描述基本约束，而无需使用 JavaScript

## HTML5 约束验证 API

如今，越来越多的浏览器支持约束验证 API，并且变得越来越可靠。然而，HTML5 约束验证并不能消除服务器端验证的需要。

在高层次上，此 API 涵盖以下功能：

+   表单字段具有有效性属性

+   表单字段还有一个通用的`checkValidity()`方法

+   最后，还有一个`setCustomValidity()`方法

### validity 对象

`validity`对象是一组键和布尔值，表示特定表单的有效性。简单来说，我们可以说它告诉了特定表单缺少什么。

让我们以数字字段类型为例来理解这一点。使用数字字段类型，我们可以指定表单字段应该是数字，并且我们可以设置限制；例如，数字应该大于 0 并且小于 25。`validity`属性实际上可以告诉您值是否不是数字，或者太低或太高。

DOM 节点的`validity`对象返回一个包含与节点中数据的有效性相关的多个布尔属性的`ValidityState`对象。在`ValidityState`对象中，每当我们获取对它的引用时，我们可以保持对它的控制，并且返回的有效性检查将根据需要进行更新，如下面的代码示例所示：

```html
<head>
<script>
  function validateInput(){
    var bool1= document.getElementById('handbook1').validity.customError;
    var result1=document.getElementById('result1').innerHTML = bool1;
  }
</script>
</head>
<body>
  <input type= "text" id="handbook1">
  <div>
  <label>Result1:</label><output id="result1" ></output>
  </div>
  <input type="button" value="Validate" onclick="validateInput()">
</body>
```

### checkValidity 方法

调用`checkValidity`方法来检查此方法返回的值，以了解成功和不成功的验证场景。它返回一个布尔值，当不需要知道字段为何无效时，或者在我们深入`validity`属性之前使用此方法来了解字段为何无效时，我们可以使用此方法。

该方法允许我们在没有用户输入的情况下检查表单的验证。

在用户或脚本代码提交表单时检查表单的验证，但该方法允许在任何时候进行验证，如下面的代码示例所示：

```html
<head>
<script>
  function validateInput(){
    //false
    var bool2=document.getElementById('handbook2').checkValidity(); //true
    var result1=document.getElementById('result1').innerHTML = bool1;
    var result2=document.getElementById('result2').innerHTML = bool2;
  }
</script>
</head>
<body>
  <input type= "text" id="handbook1" required>
  <input type= "text" id="handbook2" value="handbook">
  <div>
  <label>Result1:</label><output id="result1"></output>
  </div>
  <div>
  <label>Result2:</label><output id="result2"></output>
  </div>
  <input type="button" value="Validate" onclick="validateInput()">
</body>
```

上述代码的输出将如下截图所示：

![checkValidity 方法](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_03.jpg)

### setCustomValidity()方法

`setCustomValidity()`方法让我们可以逻辑地决定并创建自定义验证错误消息，并在提交无效输入到表单时显示它。这使我们可以使用 JavaScript 代码来建立除标准约束验证 API 提供的验证失败之外的验证失败。在报告问题时显示消息。

该方法还允许我们设置消息，并默认将字段设置为错误状态。如果参数是空字符串，则自定义错误将被清除或被视为有效。当我们不使用`setCustomValidity()`方法自定义错误消息时，将显示内置错误消息，如下面的代码示例所示：

```html
<script>
  function check(input){
    if (input.value != document.getElementById('email_addr').value) {
      input.setCustomValidity('Both the email addresses must match.');
    }
    else{
      input.setCustomValidity('');
    }
  }
</script>
<body>
  <form id="myForm">
  <div>
  <label>Enter Email Address:</label>
  <input type="email" id="email_addr" name="email_addr">
  </div>
  <div>
  <label>Repeat Email Address:</label>
  <input type="email" id="email_addr_repeat" name="email_addr_repeat">
  </div>
  <input type="submit" value="Validate" onclick="check(this)">
</form>
```

上述代码的输出将如下截图所示：

![setCustomValidity()方法](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_04.jpg)

### willValidate 属性

`willValidate`属性指示元素是否将根据表单的验证规则和约束进行验证。如果控件上设置了任何约束，例如`required`属性或`pattern`属性，`willValidate`字段将告诉您验证检查将被强制执行。

该属性在表单提交时返回**true**，如果元素将被验证；否则，它将返回**false**，如下面的代码示例所示：

```html
<script>
  function validateInput(){
    var bool1= document.getElementById('handbook1').willValidate; //true
    var bool2=document.getElementById('handbook2').willValidate; //undefined
    var bool3= document.getElementById('handbook3').willValidate; //false
    var result1=document.getElementById('result1').innerHTML = bool1;
    var result2=document.getElementById('result2').innerHTML = bool2;
    var result3=document.getElementById('result3').innerHTML = bool3;
  }
</script>
<body>
  <input type= "text" id="handbook1" required value= "handbook">
  <div id= "handbook2" type="text">
  <input type= "text" id="handbook3" disabled>
  <div>
  <label>Result1:</label><output id="result1" ></output>
  </div>
  <div>
  <label>Result2:</label><output id="result2" ></output>
  </div>
  <div>
  <label>Result3:</label><output id="result3" ></output>
  </div>
  <input type="button" value="Validate" onclick="validateInput()">
</body>
```

上述代码的输出将如下截图所示：

![willValidate 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_05.jpg)

### validationMessage 属性

`validationMessage`属性允许我们以编程方式查询本地化的错误消息，该控件不满足。如果控件不符合约束验证的条件，或者元素的值满足其约束，`validationMessage`设置为空字符串。

例如，如果必填字段没有输入，浏览器将向用户呈现其默认错误消息。一旦支持，这就是`validationMessage`字段返回的文本字符串，如下面的代码示例所示：

```html
<script>
  function validateInput(){
    var bool1= document.getElementById('handbook1').validationMessage;
    var bool2=document.getElementById('handbook2').validationMessage;
    var result1=document.getElementById('result1').innerHTML = bool1;
    var result2=document.getElementById('result2').innerHTML = bool2;
  }
</script>
<body>
  <input type= "text" id="handbook1" required/>
  <input type= "text" id="handbook2" value= "handbook">
  <div>
  <label>Result1:</label><output id="result1" ></output>
  </div>
  <div>
  <label>Result2:</label><output id="result2" ></output>
  </div>
  <input type="button" value="Validate" onclick="validateInput()">
</body>
```

上述代码的输出将如下截图所示：

![validationMessage 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_06.jpg)

HTML5 为我们提供了多种方式来强制表单的正确性；也就是说，HTML5 为任何给定的`<form>`控件提供了多种有效性约束。

如前所述，本节讨论了任何给定的`<form>`控件上的多种有效性约束。

### patternMismatch 属性

`patternMismatch`属性用于在`<form>`控件上设置任何模式规则，并返回`<input>`值是否与`pattern`属性定义的规则匹配。

#### validity.patternMismatch 属性

+   如果元素的值不匹配提供的`pattern`属性，则返回**true**；否则，返回**false**

+   当返回**true**时，元素将匹配`:invalid`CSS 伪类，如下面的代码示例所示：

```html
<script>
  function validateInput(){
    var bool1= document.getElementById('handbook1').validity.patternMismatch; //false
    var bool2= document.getElementById('handbook2').validity.patternMismatch; //true
    var result1=document.getElementById('result1').innerHTML = bool1;
    var result2=document.getElementById('result2').innerHTML = bool2;
  }
</script>
<body>
  <input type= "text" id="handbook1" pattern="[0-9]{5}"  value="123456">
  <input type= "text" id="handbook2" pattern="[a-z]{3}"  value="xyz">
  <div>
  <label>Result1:</label>	<output id="result1"></output>
  </div>
  <div>
  <label>Result2:</label>	<output id="result2"></output>
  </div>
  <input type="button" value="Validate" onclick="validateInput()">
</body>
```

上述代码的输出将如下截屏所示：

![validity.patternMismatch 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_07.jpg)

### customError 属性

customError 属性用于处理由应用程序代码计算和设置的错误。此属性验证是否设置了自定义错误消息。

它用于调用`setCustomValidity()`属性将表单控件置于`customError`状态。

#### validity.customError 属性

如果元素有自定义错误，则返回**true**；否则，返回**false**，如下面的代码示例所示：

```html
<script>
  function validateInput(){
    Var bool1=document.getElementById('handbook1').validity.customError; //false
    var bool2= document.getElementById('handbook2').setCustomValidity('Invalid Message');
    var bool3= document.getElementById('handbook2').validity.customError; //true
    var result1=document.getElementById('result1').innerHTML = bool1;
    var result2=document.getElementById('result2').innerHTML = bool2;
    var result3=document.getElementById('result3').innerHTML = bool3;
  }
</script>
<body>
  <input type= "text" id="handbook1">
  <input type= "text" id="handbook2">
  <div>
  <label>Result1:</label>  <output id="result1" ></output>
  </div>
  <div>
  <label>Result2:</label>  <output id="result2" ></output>
  </div>
  <div>
  <label>Result3:</label>  <output id="result3" ></output>
  </div>
  <input type="button" value="Validate" onclick="validateInput()">
</body>
```

上述代码的输出将如下截屏所示：

![有效性.customError 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_08.jpg)

### rangeOverflow 属性

`rangeOverflow`属性用于通知`<form>`控件的输入值大于最大值或输入值超出范围。

此属性检查`max`属性，以确保`<form>`控件具有最大输入值。

#### validity.rangeOverflow 属性

+   如果元素的值高于提供的最大值，则返回**true**；否则，返回**false**

+   当返回**true**时，元素将匹配`:invalid`和`:out-of-range`CSS 伪类，如下面的代码示例所示：

```html
<script>
  function validateInput(){
    var bool1= document.getElementById('handbook1').validity.rangeOverflow; //false
    var bool2=document.getElementById('handbook2').validity.rangeOverflow; //true
    var result1=document.getElementById('result1').innerHTML = bool1;
    var result2=document.getElementById('result2').innerHTML = bool2;
  }
</script>
<body>
  <input type= "number" id="handbook1" max="3" value="1">
  <input type= "number" id="handbook2" max="3" value="4">
  <div>
  <label>Result1:</label>  <output id="result1" ></output>
  </div>
  <div>
  <label>Result2:</label>  <output id="result2" ></output>
  </div>
  <input type="button" value="Validate" onclick="validateInput()">
</body>
```

上述代码的输出将如下截屏所示：

![有效性.rangeOverflow 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_09.jpg)

### rangeUnderflow 属性

`rangeUnderflow`属性用于通知`<form>`控件的输入值低于最小值。

此属性检查`min`属性，以确保`<form>`控件具有最小输入值。

#### 有效性.rangeUnderflow 属性

+   如果元素的值低于提供的最小值，则返回**true**；否则，返回**false**

+   当返回**true**时，元素将匹配`:invalid`和`:out-of-range`CSS 伪类，如下面的代码示例所示：

```html
<script>
  function validateInput(){
    var bool1= document.getElementById('handbook1').validity.rangeUnderflow; //true
    var bool2= document.getElementById('handbook2').validity.rangeUnderflow; //false
    var result1=document.getElementById('result1').innerHTML = bool1;
    var result2=document.getElementById('result2').innerHTML = bool2;
  }
</script>
<body>
  <input type= "number" id="handbook1" min="3" value="1">
  <input type= "number" id="handbook2" min="3" value="4">
  <div>
  <label>Result1:</label>  <output id="result1" ></output>
  </div>
  <div>
  <label>Result2:</label>  <output id="result2" ></output>
  </div>
  <input type="button" value="Validate" onclick="validateInput()">
</body>
```

上述代码的输出将如下截屏所示：

![有效性.rangeUnderflow 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_10.jpg)

### stepMismatch 属性

`stepMismatch`属性确保`<input>`值符合`min`、`max`和`step`值的规则或标准。例如，如果步长值为五，输入值为三，则在这种情况下会有步长不匹配。

#### 有效性.stepMismatch 属性

+   如果元素的值不符合`step`属性给定的规则，则返回**true**；否则，返回**false**

+   当返回**true**时，元素将匹配`:invalid`和`:out-of-range`CSS 伪类，如下面的代码示例所示：

```html
<script>
  function validateInput(){
    var bool1= document.getElementById('handbook1').validity.stepMismatch; //true
    var bool2= document.getElementById('handbook2').validity.stepMismatch; //false
    var result1=document.getElementById('result1').innerHTML = bool1;
    var result2=document.getElementById('result2').innerHTML = bool2;
  }
</script>
<body>
  <input type= "number" id="handbook1" step="3" value="1">
  <input type= "number" id="handbook2" step="3" value="6">
  <div>
  <label>Result1:</label>  <output id="result1" ></output>
  </div>
  <div>
  <label>Result2:</label>  <output id="result2" ></output>
  </div>
  <input type="button" value="Validate" onclick="validateInput()">
</body>
```

上述代码的输出将如下截屏所示：

![有效性.stepMismatch 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_11.jpg)

### tooLong 属性

此属性确保`<input>`字段不包含太多字符。

我们通过在`<form>`控件上添加`maxlength`属性来确保这一点。

#### validity.tooLong 属性

+   如果元素的值长于提供的最大长度，则返回**true**；否则，返回**false**

+   当返回**true**时，元素将匹配`:invalid`和`:out-of-range` CSS 伪类，如下面的代码示例所示：

```html
<script>
  function validateInput(){
    var bool1=  document.getElementById('handbook1').validity.tooLong; //false
    var bool2=    document.getElementById('handbook2').validity.tooLong; //true
    var result1=document.getElementById('result1').innerHTML = bool1;
    var result2=document.getElementById('result2').innerHTML = bool2;
    }
</script>
<body>
  <input type="text" id="handbook1" maxlength="5" value="12345678"/>
  <input type="text" id="handbook2" maxlength="5" value="xyz"/>
  <div>
  <label>Result1:</label>  <output id="result1" ></output>
  </div>
  <div>
  <label>Result2:</label>  <output id="result2" ></output>
  </div>
  <input type="button" value="Validate" onclick="validateInput()">
</body>
```

先前代码的输出将如下屏幕截图所示：

![validity.tooLong 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_17.jpg)

### typeMismatch 属性

`typeMismatch`属性用于通知`<input>`值与`<form>`控件不匹配，例如电子邮件、URL 和数字，并确保值的类型与其预期字段匹配。

#### validity.typeMismatch 属性

+   如果元素的值不符合正确的语法，则返回**true**；否则返回**false**

+   当返回**true**时，元素将匹配`:invalid` CSS 伪类，如下面的代码示例所示：

```html
<script>
  function validateInput(){
    var bool1= document.getElementById('handbook1').validity.typeMismatch; //false
    var bool2= document.getElementById('handbook2').validity.typeMismatch; //true
    var result1=document.getElementById('result1').innerHTML = bool1;
    var result2=document.getElementById('result2').innerHTML = bool2;
  }
</script>
<body>
  <input type="email" id="handbook1" value="handbook@books.com">
  <input type="email" id="handbook2" value="handbook">
  <div>
  <label>Result1:</label>  <output id="result1" ></output>
  </div>
  <div>
  <label>Result2:</label>  <output id="result2" ></output>
  </div>
  <input type="button" value="Validate" onclick="validateInput()">
</body>
```

先前代码的输出将如下屏幕截图所示：

![validity.typeMismatch 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_12.jpg)

### valueMissing 属性

`valueMissing`属性确保在`<form>`控件上设置了一些值。为了确保这一点，将`required`属性设置为**true**。

#### validity.valueMissing 属性

+   如果元素没有值但是必填字段，则返回**true**；否则返回**false**

+   当返回**true**时，元素将匹配`:invalid` CSS 伪类，如下面的代码示例所示：

```html
<script>
  function validateInput(){
    var bool1=document.getElementById('handbook1').validity.valueMissing; //false
    var bool2= document.getElementById('handbook2').validity.valueMissing; //true
    var result1=document.getElementById('result1').innerHTML = bool1;
    var result2=document.getElementById('result2').innerHTML = bool2;
  }
</script>
<body>
  <input type= "text" id="handbook1" required value="handbook">
  <input type= "text" id="handbook2" required value="">
  <div>
  <label>Result1:</label>  <output id="result1" ></output>
  </div>
  <div>
  <label>Result2:</label>  <output id="result2" ></output>
  </div>
  <input type="button" value="Validate" onclick="validateInput()">
</body>
```

先前代码的输出将如下屏幕截图所示：

![validity.valueMissing 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_13.jpg)

### valid 属性

`valid`属性用于检查字段是否有效。

#### validity.valid 属性

+   如果元素的值没有有效性问题，则返回**true**；否则返回**false**

+   当返回**true**时，元素将匹配`:invalid` CSS 伪类，如下面的代码示例所示：

```html
<script>
  function validateInput(){
    var bool1= document.getElementById('handbook1').validity.valid; //true
    var bool2= document.getElementById('handbook2').validity.valid; //false
    var result1=document.getElementById('result1').innerHTML = bool1;
    var result2=document.getElementById('result2').innerHTML = bool2;;
  }
</script>
<body>
  <input type= "text" id="handbook1" required value="handbook">
  <input type= "text" id="handbook2" required value="">
  <div>
  <label>Result1:</label>  <output id="result1" ></output>
  </div>
  <div>
  <label>Result2:</label>  <output id="result2" ></output>
  </div>
  <input type="button" value="Validate" onclick="validateInput()">
</body>
```

先前代码的输出将如下屏幕截图所示：

![validity.valid 属性](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_14.jpg)

以下表格显示了各种属性及其可能的值和相关违规：

| 属性 | 支持属性的<Input>类型 | 可能的值 | 约束描述 | 相关违规 |
| --- | --- | --- | --- | --- |
| `required` | 日期、月份、周、复选框、单选按钮、URL、电话、电子邮件、文本、密码、搜索、时间、范围、数字和标签，如`<select>`、`<textarea>`、`checkbox`和`radiobutton` | 返回布尔值`None`；存在时返回**true**，不存在时返回**false** | 必须填写值 | 约束违规：缺失 |
| `min` | 数字和范围 | 必须是有效数字 | 填写的参数必须大于或等于定义的值 | 约束违规：下溢 |
| 月、日期和周 | 必须是有效日期 |
| datetime-local、time 和 datetime | 必须是有效的日期和时间 |
| `maxlength` | `<textarea>`等标签和属性为`text`、`password`、`search`、`tel`、`url`和`email` | 必须是整数长度 | 属性的值不能大于填写的字符数 | 约束违规：太长 |
| `max` | 数字和范围 | 必须是有效数字 | 填写的参数必须小于或等于定义的值 | 约束违规：溢出 |
| 月、日期和周 | 必须是有效日期 |
| datetime-local、time 和 datetime | 必须是有效的日期和时间 |
| `pattern` | 文本、搜索、URL、电话、电子邮件和密码 | 它是使用 JavaScript 定义的正则表达式 | 属性的值必须完全匹配定义的模式 | 约束违规：模式不匹配 |
| `step` | 月 | 必须是整数月数 | 直到`step`的值设置为任何文字（在`step`菜单中可用的值），值将是`min`值加上`step`的整数倍 | 约束违规：步骤不匹配 |
| 日期 | 必须是整数天数 |
| 周 | 必须是整数周数 |
| 日期时间、本地日期时间和时间 | 必须是整数秒数 |
| 数字和范围 | 必须是整数 |

# 错误消息

现在，所有现代浏览器都支持大部分 HTML5 的功能。所有浏览器中功能的功能性是相同的，但也存在一些差异；其中之一就是浏览器显示的默认错误消息。

各种浏览器显示的默认错误消息如下截图所示：

![错误消息](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_15.jpg)

但是，我们可以通过`setCustomvalidity`来更改浏览器的默认错误消息。让我们通过一个例子来理解这一点。

以下代码将把浏览器的默认错误消息更改为自定义消息：

```html
<script>
  function check() 
  {
    varhtmlObject=document.getElementById("input");
    if (!htmlObject.checkValidity()) {
      htmlObject.setCustomValidity('This field is mandatory');
    }
  }
</script>
<body>
  <form id="myForm">
  <input id="input" type="text" required />
  <input type="submit" onclick="check(this)">
  </form>
</body>
```

上述代码将产生以下输出：

![错误消息](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_02_16.jpg)

# 总结

在本章中，我们学习了表单验证及其类型。我们还了解了不同类型验证的好处。我们还看到了在表单验证中使用的各种<input>类型和属性。

我们通过构建一个示例代码，看到了 JavaScript 验证和 HTML5 验证之间的区别。

接下来，我们学习了 HTML5 支持的约束验证和各种 API。

最后，我们看到了各种特定于浏览器的默认错误消息，并学习了如何更改浏览器的默认错误消息。


# 第三章：为表单添加样式

在早期的章节中，我们学习了如何使用 HTML5 构建表单，但是 web 设计师和开发人员使用 CSS3 来为 web 表单赋予丰富和优雅的外观。有了对 CSS3 的基本理解，本章我们将学习如何改善表单的外观和感觉。

在本章中，我们将涵盖以下主题：

+   CSS3 及其模块

+   为表单添加样式

+   有效样式表单的指南

# 用于 web 表单的 CSS3

CSS3 为我们带来了无限的新可能性，并允许样式化更好的 web 表单。CSS3 为我们提供了许多创建表单设计影响的新方法，带来了一些重要的变化。HTML5 引入了有用的新表单元素，如滑块和微调器，以及旧元素，如`textbox`和`textarea`，我们可以通过创新和 CSS3 使它们看起来非常酷。使用 CSS3，我们可以将旧的无聊表单变成现代、酷炫和吸引人的表单。

CSS3 完全向后兼容，因此我们不需要更改现有的表单设计。浏览器已经并且将始终支持 CSS2。

CSS3 表单可以分为模块。一些最重要的 CSS3 模块包括：

+   选择器（带伪选择器）

+   背景和边框

+   文本（带文本效果）

+   字体

+   渐变

表单的样式始终根据要求和 web 设计师或开发人员的创新而变化。在本章中，我们将研究那些可以为我们的表单添加样式并赋予其丰富和优雅外观的 CSS3 属性。

CSS3 的一些新属性需要供应商前缀，因为它们经常被使用，因为它们帮助浏览器读取代码。一般来说，对于某些属性，如`border-radius`，在 CSS3 中不再需要使用它们，但当浏览器无法解释代码时，它们会发挥作用。以下是主要浏览器的所有供应商前缀的列表：

+   `-moz-`：Firefox

+   `-webkit-`：Safari 和 Chrome 等 WebKit 浏览器

+   `-o-`：Opera

+   `-ms-`：Internet Explorer

在我们开始为表单添加样式之前，让我们快速复习一下表单模块，以便更好地理解和为表单添加样式。

# 选择器和伪选择器

选择器是用于选择要样式化的元素的模式。选择器可以包含一个或多个由组合符分隔的简单选择器。CSS3 选择器模块引入了三个新的属性选择器；它们被分组在**子字符串匹配属性选择器**的标题下。

这些新选择器如下：

+   `[att^=val]`：以...开始选择器

+   `[att$=val]`：以...结尾选择器

+   `[att*=val]`：包含选择器

这些新选择器中的第一个，我们将称之为“以...开始”选择器，允许选择具有指定属性（例如，超链接的`href`属性）以指定字符串（例如，`http://`，`https://`或`mailto:`）开始的元素。

同样，额外的两个新选择器，我们将称之为“以...结尾”和“包含”选择器，允许选择具有指定属性的元素，其中指定的属性要么以指定的字符串结尾，要么包含指定的字符串。

CSS 伪类只是选择器的附加关键字，告诉要选择的元素的特殊状态。例如，当用户悬停在选择器指定的元素上时，`:hover`将应用样式。伪类和伪元素可以将样式应用于元素，不仅与文档树的内容相关，还与外部因素相关，例如浏览器历史记录，如`:visited`，以及其内容的状态，例如`:checked`，在某些表单元素上。

新的伪类如下：

| 类型 | 详情 |
| --- | --- |
| `:last-child` | 用于匹配作为其父元素的最后一个子元素的元素。 |
| `:first-child` | 用于匹配作为其父元素的第一个子元素的元素。 |
| `:checked` | 用于匹配已选中的元素，如单选按钮或复选框。 |
| `:first-of-type` | 用于匹配指定元素类型的第一个子元素。 |
| `:last-of-type` | 用于匹配指定元素类型的最后一个子元素。 |
| `:nth-last-of-type(N)` | 用于匹配指定元素类型的倒数第 N 个子元素。 |
| `:only-child` | 用于匹配其父元素的唯一子元素的元素。 |
| `:only-of-type` | 用于匹配其类型的唯一子元素的元素。 |
| `:root` | 用于匹配文档的根元素。 |
| `:empty` | 用于匹配没有子元素的元素。 |
| `:target` | 用于匹配文档 URL 中标识符的当前活动元素的目标。 |
| `:enabled` | 用于匹配已启用的用户界面元素。 |
| `:nth-child(N)` | 用于匹配父元素的每第 N 个子元素。 |
| `:nth-of-type(N)` | 用于匹配父元素的每第 N 个子元素，从父元素的最后一个开始计数。 |
| `:disabled` | 用于匹配已禁用的用户界面元素。 |
| `:not(S)` | 用于匹配未被指定选择器匹配的元素。 |
| `:nth-last-child(N)` | 在父元素的子元素列表中，用于根据它们的位置匹配元素。 |

# 背景

CSS3 包含几个新的背景属性；此外，在 CSS3 中，还对背景的先前属性进行了一些更改；这些更改允许更好地控制背景元素。

添加的新背景属性如下。

## 背景剪切属性

`background-clip`属性用于确定背景图像的允许区域。

如果没有背景图像，则此属性仅具有视觉效果，例如当边框具有透明区域或部分不透明区域时；否则，边框会覆盖差异。

### 语法

`background-clip`属性的语法如下：

```html
background-clip: no-clip / border-box / padding-box / content-box;
```

### 值

`background-clip`属性的值如下：

+   `border-box`：使用此选项，背景延伸到边框的外边缘

+   `padding-box`：使用此选项，不会在边框下绘制背景

+   `content-box`：使用此选项，背景在内容框内绘制；只有内容覆盖的区域会被绘制

+   `no-clip`：这是默认值，与`border-box`相同

## 背景原点属性

`background-origin`属性指定背景图像或颜色相对于`background-position`属性的定位。

如果背景图像的`background-attachment`属性为固定，则此属性无效。

### 语法

以下是`background-attachment`属性的语法：

```html
background-origin: border-box / padding-box / content-box;
```

### 值

`background-attachment`属性的值如下：

+   `border-box`：使用此选项，背景延伸到边框的外边缘

+   `padding-box`：使用此选项，不会在边框下绘制背景

+   `content-box`：使用此选项，背景在内容框内绘制

## 背景大小属性

`background-size`属性指定背景图像的大小。

如果未指定此属性，则将显示图像的原始大小。

### 语法

以下是`background-size`属性的语法：

```html
background-size: length / percentage / cover / contain;
```

### 值

`background-size`属性的值如下：

+   `长度`：指定背景图像的高度和宽度。不允许负值。

+   `百分比`：以父元素的百分比来指定背景图像的高度和宽度。

+   `cover`：指定背景图像尽可能大，以完全覆盖背景区域。

+   `contain`：指定图像尺寸最大化，使其宽度和高度可以适应内容区域。

除了添加新属性，CSS3 还增强了一些旧的背景属性，如下所示。

## background-color 属性

如果元素的背景图像的底层图层不能使用，我们可以指定一个回退颜色，除了指定背景颜色。

我们可以通过在回退颜色之前添加一个斜杠来实现这一点。

```html
background-color: red / blue;
```

## background-repeat 属性

在 CSS2 中，当图像在末尾重复时，图像经常被切断。CSS3 引入了新的属性，我们可以用它来解决这个问题：

+   `space`：通过在图像瓦片之间使用此属性，等量的空间被应用，直到填满元素

+   `round`：通过使用此属性，直到图块适合元素，图像被缩小

## background-attachment 属性

有了新的可能值 `local`，我们现在可以在元素内容滚动时设置背景滚动。

这适用于可以滚动的元素。例如：

```html
body{background-image:url('example.gif');background-repeat:no-repeat;background-attachment:fixed;}
```

### 注意

CSS3 允许网页设计师和开发人员使用简单的逗号分隔列表来拥有多个背景图像。例如：

```html
background-image: url(abc.png), url(xyz.png);
```

## 边框

`border` 属性允许我们指定元素边框的样式和颜色，并且借助 CSS3，我们已经迈入了下一个级别。

使用 CSS3，我们可以创建圆角边框，添加阴影，并使用图像作为边框，而不需要使用诸如 Photoshop 等各种设计程序。

添加的新边框属性如下。

## border-radius 属性

使用 CSS 创建圆角边框从来都不容易。有许多可用的方法，但没有一种方法是直接的。此外，为了正确应用样式，必须同时使用 WebKit 和 Mozilla 的供应商前缀。

`border-radius` 属性可用于自定义按钮。我们还可以将 `border-radius` 应用于单个角落。有了这个属性的帮助，我们可以轻松地创建圆角边框。

### 语法

`border-radius` 属性的语法如下：

```html
border-radius: 1-4 length / % ;
```

### 值

以下是 `border-radius` 属性的值：

+   `length`：定义圆的半径大小

+   `%`：使用百分比值定义圆的半径大小

## box-shadow 属性

`box-shadow` 属性允许设计师和开发人员轻松创建多个下拉阴影。这些可以是盒子的外部或内部，指定颜色、大小、模糊和偏移的值。

通过简单地声明 `box-shadow` 一次，我们可以使用 `outer` 和 `inset` 版本，用逗号分隔。

### 语法

`box-shadow` 属性的语法如下：

```html
box-shadow: h-shadow v-shadow blur spread color inset;
```

### 值

以下显示了 `box-shadow` 属性的值：

+   `inset`：将外部（outset）阴影更改为内部阴影

+   `<h-shadow>`，`<v-shadow>`：指定阴影的位置

+   `<blur>`：这个值越大，模糊越大

+   `<spread>`：指定阴影的大小

+   `<color>`：指定阴影的颜色

## border-image 属性

`border-image` 属性有点棘手，但它允许我们创建具有自定义边框的框。有了这个功能，您可以定义一个图像来用作边框，而不是普通的边框。

我们可以使用图像甚至渐变来创建装饰性边框，而不仅仅是简单的圆角。

这个功能实际上分成了几个属性：

+   border-image

+   border-corner-image

### 语法

`border-image` 属性的语法如下：

```html
border-image: <source><slice><width><outset><repeat>;
```

### 值

`border-image` 属性的值如下：

+   `source`：指定用于边框的图像。

+   `slice`：指定边框的内部偏移量。

+   `width`：指定边框的宽度。

+   `outset`：指定边框图像区域延伸到边框框之外的程度。

+   `repeat`：指定边框是否应该被拉伸。如果是，那么它是圆形的还是拉伸的。

# 文本效果

我们已经看到许多具有各种文本效果的网站，它们正在迅速成为良好表单设计的当前和未来趋势。借助 CSS3，这些效果最好的一点是它们可以通过纯 CSS 实现，也就是说，不再需要图像替换和图像密集的设计。在本节中，我们将学习 CSS3 提供的一些新的文本效果。

新的文本特性如下。

## text-shadow 属性

`text-shadow`属性用于对文本内容应用阴影效果。我们可以通过使用一个简单的逗号为单个文本添加一个或多个效果。

这些效果包括阴影颜色、阴影效果的 x/y 偏移和阴影效果的模糊半径。效果可以重叠，但为了清晰起见，它们不应该重叠在文本内容上。

### 语法

`text-shadow`属性的语法如下：

```html
text-shadow: <color><offset-x><offset-y><blur-radius>;
```

## word-wrap 属性

`word-wrap`属性由浏览器用于在单词内部断开行，以防止文本超出边界，否则它将超出边界。它强制文本换行，即使必须在单词中间分割它。

### 语法

`word-wrap`属性的语法如下：

```html
word-wrap:break-word / normal;
```

### 值

`word-wrap`属性的值如下：

+   `word-break`：允许不可断开的单词被断开

+   `normal`：仅在允许的断点处断开单词

CSS3 提供的一些新的文本属性如下：

+   `hanging-punctuation`：指定标点符号字符是否可以放在行框外部

+   `punctuation-trim`：指定标点符号是否应该被修剪

+   `text-align-last`：描述块的最后一行或强制换行前的行如何对齐

+   `text-emphasis`：将强调标记应用于元素的文本，并将前景色应用于强调标记

+   `text-justify`：当`text-align`为`justify`时，指定使用的对齐方法

+   `text-outline`：指定文本的轮廓

+   `text-overflow`：指定文本溢出包含元素时需要采取的操作

+   `text-wrap`：指定文本的断行规则

+   `word-break`：对于非 CJK 脚本，指定断行规则

# 字体

在 CSS2 中，字体模块用于定义文本的大小、行高和粗细，以及其他属性，如样式和系列。

在 CSS 中，我们只能使用计算机上可用的预定义字体系列，但是 CSS3 为我们提供了使用用户定义字体的功能，这些字体可以用于设计网页表单。

## @font-face 规则

字体在决定页面或页面特定部分外观方面起着重要作用，这就是网页设计师和公司受益的地方，比如品牌营销。

`@font-face`属性已经将字体的使用带到了一个新的水平。

这个规则允许用户在网页表单或页面上指定任何真实的字体。更准确地说，这个规则允许从服务器下载特定的字体，并在网页表单或页面中使用它，如果用户尚未安装该特定字体。

### 语法

`@font-face`属性的语法如下：

```html
@font-face{
  font-family: <family-name>;
  src: <url>;
  unicode-range: <urange>;
  font-variant: <font-variant>;
  font-feature-settings: normal / <feature-tag-value>;
  font-stretch: <font-stretch>;
  font-weight: <weight>;
  font-style: <style>;
}
```

## 字体描述符

CSS3 提供了可以在`@font-face`规则内定义的新字体描述符。可以使用的各种字体描述符如下。

### src 字体描述符

`src`字体描述符用于定义字体的 URL。

值：`URL`。

### font-style 字体描述符

`font-style`字体描述符用于定义要使用的字体的样式。这是一个可选字段，默认值为`normal`。

值：`normal`，`italic`和`oblique`。

### font-stretch 字体描述符

`font-stretch`字体描述符用于定义字体应该被拉伸多少。这是一个可选字段，默认值为`normal`。

值：`normal`、`condensed`、`ultra-condensed`、`extra-condensed`、`semi-condensed`、`expanded`、`semi-expanded`、`extra-expanded`和`ultra-expanded`。

### 字体族字体描述符

`font-family`字体描述符用于定义字体的名称或类型。

值：`name`。

### unicode-range 字体描述符

`unicode-range`字体描述符用于定义字体支持的 Unicode 字符范围。这是一个可选字段，默认值为`U+0-10FFFF`。

值：`Unicode-range`。

### 字重描述符

`font-weight`字体描述符用于定义字体的粗细程度。这是一个可选字段，默认值为`normal`。

值：`normal`、`bold`、`100`、`200`、`300`、`400`、`500`、`600`、`700`、`800`和`900`。

# 渐变

CSS3 的一个令人惊奇的颜色特性是渐变。它们允许颜色之间的平滑过渡。

它们使用`background-image`属性声明，因为它们没有特殊属性。

渐变允许我们通过将颜色`hex`转换为`rgba`模式来创建透明度。

尽管有许多增强功能，但供应商前缀用于使表单与浏览器兼容，以便浏览器可以解释样式。

## 语法

渐变的语法如下：

```html
linear-gradient (<angle><to [left / right || top / bottom]><color [percentage/length]><color [percentage/length]>)
```

## 值

渐变的值包括以下内容：

+   `angle`：这指定了渐变的方向角度

+   `color`：这指定了颜色值，可选的选项是停止位置

# 样式化表单

快速复习了新的 CSS3 属性后，现在是时候自定义旧的和无聊的表单了。

在第一章中，我们构建了一个**健康调查表**。我们将重复使用该表单示例来讨论新的 CSS3 以及基本的 CSS 属性以及它们如何在表单中增强创造力。

为了进行样式设置，我们只需取表单的第一部分，即**个人信息**。经过一些不需要解释的小改动，以下是 HTML 代码：

```html
<form id="masteringhtml5_form">
  <label for="heading" class="heading">Health Survey Form</label>
  <fieldset class="fieldset_border">
    <legend class="legend">Personal Information</legend>
    <div>
      <label for="name">Name</label><br>
      <input  type="text" class="name txtinput" name="name" placeholder="First" autofocus>
      <input  type="text" class="name txtinput" name="name" placeholder="Last">
    </div><br>
    <div class="div_outer_dob">
      <div class="div_dob">
        <label for="dob">Date of Birth</label><br>
        <input type="date" value="date of birth" class="txtinput dateinput">
      </div>
      <div class="gender">
        <label for="gender">Gender</label><br>
        <input type="radio" name="gender"><label>Male</label>
        <input type="radio" name="gender"><label>Female</label>
      </div>
    </div>

    <div class="div_outer_address" >
      <label for="address">Address</label><br>
      <input type="text" class="txtinput textbox address_img" placeholder="Street Address"><br>
      <input type="text" class="txtinput textbox address_img" placeholder="Address Line 2"><br>
      <input type="text" class="txtinput  address_img" placeholder="City">
      <input type="text" class="txtinput  address_img" placeholder="State/Province"><br>
      <input type="text" class="txtinput  address_img" placeholder="Pincode">
      <select class="txtinput select address_img" >
        <option value="Country" class="select"  >Select Country</option>
        <option value="India" class="select"  >India</option>
        <option value="Australia" class="select"  >Australia</option>
      </select>
    </div><br>
    <div>
      <label for="contact">Phone Number</label><br>
      <input type="tel" class="txtinput  home_tel" placeholder="Home">
      <input type="tel" class="txtinput  work_tel" placeholder="Work">
    </div><br>
    <div>
      <label for="email">Email Address</label><br>
      <input type="email" class="txtinput  email" placeholder="email@example.com">
    </div>
    </fieldset>
    <br>

  <div class="submit">
    <input type="submit" class="submit_btn" value="Submit">
  </div>
</form>
```

由于我们的主要重点是样式，让我们来看看表单的 CSS。以下代码保存在一个带有`.css`扩展名的单独文件中（外部 CSS 文件），它链接到主 HTML 页面。应该遵循使用单独的 CSS 文件，因为它可以提高代码的可读性，同时也更容易维护样式。

此外，新属性和字体类型以粗体显示：

```html
/* General Form */
html{
  margin: 0px;
  padding: 0px;
  background: #000000;
}
@font-face{
  font-family: 'Conv_azoft-sans-bold-italic';
  src: url('fonts/azoft-sans-bold-italic.eot');
  src: url('fonts/azoft-sans-bold-italic.woff') format('woff'),  
  url('fonts/azoft-sans-bold-italic.ttf') format('truetype'), url('fonts/azoft-sans-bold-italic.svg') format('svg');
  font-weight: normal;
  font-style: normal;
}

body{
  font-size:12px;
  height: 100%; 
  width: 38%;
  padding: 20px;
  margin: 10px auto;
  font-family: Helvetica, Arial, sans-serif;
  color: #000000;
  background: rgba(212,228,239,1);
  background: -moz-linear-gradient(top, rgba(212,228,239,1) 0%, rgba(134,174,204,1) 100%);
  background: -webkit-gradient(left top, left bottom, color-stop(0%, rgba(212,228,239,1)), color-stop(100%, rgba(134,174,204,1)));
  background: -webkit-linear-gradient(top, rgba(212,228,239,1) 0%, rgba(134,174,204,1) 100%);
  background: -o-linear-gradient(top, rgba(212,228,239,1) 0%, rgba(134,174,204,1) 100%);
  background: -ms-linear-gradient(top, rgba(212,228,239,1) 0%, rgba(134,174,204,1) 100%);
  background: linear-gradient(to bottom, rgba(212,228,239,1) 0%, rgba(134,174,204,1) 100%);
}

input[type="radio"]{
  cursor:pointer;
}

#masteringhtml5_form .fieldset_border{
  border-color:#ffffff;
  border-style: solid;
}

#masteringhtml5_form .txtinput{ 
  font-family: Helvetica, Arial, sans-serif;
  border-style: solid;
  border-radius: 4px;
  border-width: 1px;
  border-color: #dedede;
  font-size: 18px;
  padding-left: 40px;
  width: 40%;
  color: #777;
  cursor:pointer;
}

#masteringhtml5_form .name{
  background: #fff url('images/user.png')  no-repeat;
}

#masteringhtml5_form  label{
  font-weight:bold;
  font-size:17px;
}

#masteringhtml5_form .legend{
  font-size: 18px;
  font-family: 'Conv_azoft-sans-bold-italic',Helvetica, Arial, sans-serif;
}

#masteringhtml5_form .heading{
  font-size: 24px;
  font-family: 'Conv_azoft-sans-bold-italic',Helvetica, Arial, sans-serif;
}

#masteringhtml5_form .txtinput.textbox{
  width:89%;
}

#masteringhtml5_form .address_img{
  background: #fff url('images/home.png')  no-repeat;
  background-position-y: -5px;
}

#masteringhtml5_form .txtinput.select{
  width:49%;
  color:#777777;
}

#masteringhtml5_form .div_outer_dob{
  width:100%;
}

#masteringhtml5_form .dateinput{
  width:79%;
  background: #fff url('images/date.png')  no-repeat;
  background-position-x: 1px;
  background-size: 29px 29px;
}

#masteringhtml5_form .home_tel{
  background: #fff url('images/tel.png')  no-repeat;
  background-position-x: 1px;
  background-size: 29px 29px;
}

#masteringhtml5_form .work_tel{
  background: #fff url('images/work.png')  no-repeat;
  background-size: 27px 25px;
}

#masteringhtml5_form .email{
  background: #fff url('images/email.png')  no-repeat;
}

#masteringhtml5_form .div_dob{
  width:50%;
  float:left;
}

#masteringhtml5_form .gender{
  width:50%;
  float:left;
}

#masteringhtml5_form .gender span{
  font-size:18px;
}

#masteringhtml5_form .div_outer_address{
  clear:both;
}

.legend{
  font-weight:bold;
  font-size:14px;
}

#masteringhtml5_form .submit{
  text-align:center; 
}

#masteringhtml5_form .submit_btn{
  color:#ffffff;
  cursor:pointer;
  border-radius:5px;
  width: 17%;
  height: 100%;
  font-size: 21px;
  height:100%;
  box-shadow: 5px 5px 10px 5px #888888;
  background: rgb(149,149,149);
  background: -moz-linear-gradient(top,  rgba(149,149,149,1) 0%, rgba(13,13,13,1) 46%, rgba(1,1,1,1) 50%, rgba(10,10,10,1) 53%, rgba(78,78,78,1) 76%, rgba(56,56,56,1) 87%, rgba(27,27,27,1) 100%); 
  background: -webkit-gradient(linear, left top, left bottom, color-stop(0%,rgba(149,149,149,1)), color-stop(46%,rgba(13,13,13,1)), color-stop(50%,rgba(1,1,1,1)), color-stop(53%,rgba(10,10,10,1)), color-stop(76%,rgba(78,78,78,1)), color-stop(87%,rgba(56,56,56,1)), color-stop(100%,rgba(27,27,27,1))); 
  background: -webkit-linear-gradient(top,  rgba(149,149,149,1) 0%,rgba(13,13,13,1) 46%,rgba(1,1,1,1) 50%,rgba(10,10,10,1) 53%,rgba(78,78,78,1) 76%,rgba(56,56,56,1) 87%,rgba(27,27,27,1) 100%); 
  background: -o-linear-gradient(top,  rgba(149,149,149,1) 0%,rgba(13,13,13,1) 46%,rgba(1,1,1,1) 50%,rgba(10,10,10,1) 53%,rgba(78,78,78,1) 76%,rgba(56,56,56,1) 87%,rgba(27,27,27,1) 100%); 
  background: -ms-linear-gradient(top,  rgba(149,149,149,1) 0%,rgba(13,13,13,1) 46%,rgba(1,1,1,1) 50%,rgba(10,10,10,1) 53%,rgba(78,78,78,1) 76%,rgba(56,56,56,1) 87%,rgba(27,27,27,1) 100%); 
  background: linear-gradient(to bottom,  rgba(149,149,149,1) 0%,rgba(13,13,13,1) 46%,rgba(1,1,1,1) 50%,rgba(10,10,10,1) 53%,rgba(78,78,78,1) 76%,rgba(56,56,56,1) 87%,rgba(27,27,27,1) 100%); 
}
```

前面的 HTML 和 CSS 代码的结果如下：

![样式化表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_03_01.jpg)

如果我们将新的 CSS3 表单与我们在第一章中构建的表单的第一部分进行比较，*表单及其重要性*，我们将看到两种表单的外观和感觉上的差异。

为了更好地比较，在第一章中表单的第一部分，*表单及其重要性*，如下所示：

![样式化表单](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/ms-h5-frm/img/4661OS_03_02.jpg)

现在，我们意识到了 CSS3 的强大之处，使用它我们很容易地将一个简单和无聊的表单转换成时尚和吸引人的东西。

让我们看看表单的 CSS 中使用的各种选择器及其重要性：

+   `<body>`：应用于`<body>`标签的 CSS 属性充当回退或默认属性，因为它充当包含其中多个其他标签的父标签。CSS 的回退属性包括`font-family`、`font-size`等。

使用`background`这样的属性，利用颜色（以 RBG 表示），并结合`linear-gradient`来设置。`linear-gradient`是用 RBG 颜色值描述的，从顶部开始，直到底部定义为百分比。它们是为了不同的浏览器支持而描述的，包括`-webkit`、`-O`和`-ms`等起始值。它显示了表单的蓝色背景。除此之外，还使用了各种其他 CSS 属性，如`font-size`、`height`和`width`。

+   `heading`和`legend`：对于我们的表单标题（**健康调查表**）和传奇标题（**个人信息**），我们实现了一个新的字体类型`Conv_azoft-sans-bold-italic`，它在`heading`和`legend`类中使用`@font-face`属性定义了`font-family`属性。

我们导入了字体类型文件`.eot`、`.woff`、`.ttf`和`.svg`，以支持不同浏览器，使用了`@font-face`属性。

此外，对于`legend`标签，我们利用了`fieldset_border`类来改变边框颜色和样式。

+   `dateinput`和`div_dob`：这两个类都是为了`<input>`类型`date`，让用户从下拉日历中选择他/她的出生日期。`div_dob`类是为了通过使用`float`属性在屏幕左侧排列元素。除此之外，`dateinput`类还用于使用`background`、`background-position`和`background-size`属性来放置日期图标，以便正确渲染。

+   `txtinput`：`txtinput`类用于样式化表单中使用的文本输入，并且除了使用以前的 CSS 属性，如`font-family`和`border-style`之外，我们还使用了一个名为`border-radius`的新属性，以使文本输入在所有边上都有圆角边框。

我们还为`cursor`类型添加了一个属性，作为指针，当鼠标指针移动到输入字段上时显示一个手点击图标。

`name`、`address_img`、`home_tel`、`work_tel`、`email`、`dropdown`和`calendar`类用于为文本输入字段设置背景图像，具体取决于`<input>`类型。我们利用了背景的各种属性，如`background`、`background-position`和`background-size`，以便正确渲染图标图像。

`autofocus`属性用于名字文本输入，以便在表单加载时自动聚焦光标。

+   `radiobutton`：`<input>`类型`radio`是一个旧的 HTML 输入，这里用于选择性别。我们还使用了`float`属性来将单选按钮对齐到出生日期的右侧。

我们还为`cursor`类型添加了一个属性，作为指针，当鼠标指针移动到输入字段上时显示一个手点击图标。

+   `submit`：为了将表单提交到服务器，我们创建了一个**提交**按钮。在`submit_btn`类中，我们使用了以前版本的属性，如颜色、宽度和高度，以及 CSS3 属性，如`border-radius`来使按钮的所有边都变圆，`box-shadow`和`background`与颜色属性一起使用`linear-gradients`来提供所需的效果。

我们还为`cursor`类型添加了一个属性，作为指针，当鼠标指针移动到输入字段上时显示一个手点击图标。

# 指南

在本节中，我们将看到用于有效样式化表单的 CSS3 指南。

CSS3 的一些最佳实践如下：

+   尽量避免使用内联样式表。应该使用外部 CSS 文件进行样式设置。

+   尽可能使用压缩的 CSS 文件，这是一种去除代码中不必要字符以减小文件大小的做法。

+   使用合并的 CSS 文件。

+   尽可能避免使用多个声明。

+   始终考虑渐进增强。

+   厂商前缀应该被组织和注释得很好。

+   对于与背景相关的属性，请使用回退。

+   在使用排版时，不应影响文本的可读性。

+   启用回退并在每个浏览器中测试表单。

+   尽量使用高效的 CSS 选择器。

+   尽量避免使用 CSS 表达式。

+   指定图像尺寸以提高网页的渲染速度。

+   使用 CSS 精灵以加快图像的渲染速度。

# 总结

在本章中，我们学习了 CSS3 的基础知识以及我们可以将 CSS3 分类为表单的模块，例如厂商前缀、渐变和背景。

然后，通过一个代码示例，我们学习了大多数可以用于改善表单外观和感觉的 CSS3 属性的实际实现。

最后，我们学习了有效样式化表单的最佳实践。
