# 面向孩子们的 JavaScript 项目（一）

> 原文：[`zh.annas-archive.org/md5/9C2A1F6AA0F3566A2BF5430895525455`](https://zh.annas-archive.org/md5/9C2A1F6AA0F3566A2BF5430895525455)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

从书名中您可以猜到，这本书是为孩子们设计和设置的，以便他们可以自学 JavaScript，并使用 JavaScript 创建一些项目。

通过以一种无与伦比的方式抽象核心网络编程，JavaScript 永远改变了网站和 Web 应用程序。无聊的静态网站和非交互式网站现在在 JavaScript 的触摸下变得非常棒。使用 JavaScript，您可以快速开发 Web 应用程序，甚至是智能手机应用程序，而不会牺牲质量。如果您开始使用 JavaScript，您可以非常高效地处理几乎不需要在硬件和软件上进行任何配置。请记住，这不是一本参考书，但您可以从中学习 JavaScript 的每个基本概念。因此，对于 10 岁及以上的孩子来说，这将是一本完美的书，可以发现 JavaScript 的世界。

# 本书涵盖了什么

第一章，*在控制台中探索 JavaScript*，讨论了 JavaScript 和 JavaScript 开发环境，包括 Google 开发者工具。在本章中，我们将安装必要的软件并打印一些简单的代码行。

第二章，*使用 JavaScript 解决问题*，涵盖了 JavaScript 的基础知识，从主要语法到控制台中的一些简单命令。我们将学习变量的工作原理以及使用算术运算符可以实现什么。我们还将运行一些简单的命令来解决控制台内的问题。

第三章，*介绍 HTML 和 CSS*，将真正利用 JavaScript，并涵盖 HTML，使读者能够不仅在控制台中使用 JavaScript，还可以在浏览器的视图中使用。我们还将解释 CSS 的基础知识，如 CSS 选择器和 CSS 布局。

第四章，*深入挖掘*，涵盖了 JavaScript 提供的一些更高级的功能。我们讨论了 for 和 while 循环，if 语句和 switch-case。

第五章，*啊哟！驶向战斗*，教会我们如何开发著名的游戏——战舰。在前几章的基础上，小孩们将学会如何将这些信息付诸实践。

第六章，*探索 jQuery 的好处*，全都是关于 jQuery，一个著名的 JavaScript 库，以及使用它的优势。

第七章，*介绍画布*，讨论了 HTML 画布，我们将学习如何在我们的项目中使用它。

第八章，*构建老鼠人*，教会我们开发一个著名的游戏——吃豆人，除了有老鼠，还有一些猫，还有很多很多的奶酪球可以吃！;)

第九章，*使用 OOP 整理您的代码*，教授面向对象编程（OOP）并讨论 JavaScript 是一种面向对象的语言。

第十章，*可能性*，向读者展示了使用他们在阅读本书时所学到的技能所能实现的可能性。

# 你需要什么来读这本书

在整本书中，我们使用 Google Chrome 作为我们的浏览器，在控制台上运行我们的 JavaScript 代码。我们使用 Atom 这个著名的文本编辑器来编写我们的代码。你可以使用任何现代的网络浏览器和文本编辑器，但我强烈建议你使用这些开源软件来完成本书中讨论的任何项目。

# 这本书适合谁

如果您以前从未编写过代码，或者您完全是网络编程世界的新手，那么这本书就是您的正确选择。这本书适合 10 岁及以上的孩子和完全不了解编程世界的成年人，他们想要介绍编程。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名显示如下：“点击`AtomSetup.exe`文件开始安装 Atom。”

一段代码设置如下：

```js
document.write("Hello");
document.write("World");
document.write("!");
```

**新术语**和**重要词汇**以粗体显示。屏幕上看到的词语，例如菜单或对话框中的词语，以这种方式出现在文本中：“点击**下一步**按钮将您移至下一个屏幕。”

### 注意

警告或重要提示以这样的框出现。

### 提示

提示和技巧是这样显示的。


# 第一章：在控制台中探索 JavaScript

在我们开始讨论代码行，对象，变量等之前，我们需要知道 JavaScript 是什么。 JavaScript 是一种用于向网页添加交互性并构建 Web 应用程序的编程语言。静态网站如今并不太受欢迎，因此我们使用 JavaScript 使我们的网站具有交互性。

有些人也将其称为脚本语言，因为它是一种简单的语言，不像其他语言那样需要编译器。 JavaScript 并不是设计为通用编程语言，而是设计为操纵网页。您可以使用 JavaScript 编写桌面应用程序。 JavaScript 还可以访问您计算机的硬件。您可以尝试使用**软件开发工具包**（**SDK**）（例如 PhoneGap 用于移动设备或 Microsoft 应用程序 SDK 用于桌面）制作桌面应用程序。 JavaScript 代码在网页上被解释，然后由浏览器运行。例如 Firefox，Safari，Google Chrome，UC 浏览器，Opera 等任何现代互联网浏览器都支持 JavaScript。

### 注意

*编译器*是一种处理代码并将其转换为机器语言的计算机程序。使网站*交互*意味着向网站添加由用户控制的功能。例如，在线注册表格，在线计算器等。*静态*网站具有固定的对象和内容，并向所有访问者显示相同的信息。

基本上，JavaScript 包含在 HTML 页面上或写在具有`.js`扩展名的单独文件中。如果您对 HTML 一无所知，不用担心，因为您将在第三章 *介绍 HTML 和 CSS*中学习到。那么，您可以在哪里使用 JavaScript？

答案很简单，您可以执行以下操作：

+   您可以创建一个活跃的用户界面。

+   您可以控制网络浏览器。

+   您可以验证用户输入（如果输入错误）。

+   您可以创建自定义网页，可以在浏览器上弹出，包含信息或图像。

+   您可以创建动态页面而无需**公共网关接口**（**CGI**）。 CGI 由 Web 服务器用于处理浏览器的信息。

### 注意

您应该记住的是 JavaScript 不是由 Sun Microsystem 开发的编程语言 Java。

在本书中，我们将使用**Google Chrome**作为默认浏览器，**Atom**作为文本编辑器。

如果您的计算机上尚未安装这两个软件，则需要下载并安装它们。

我们将使用 Atom 文本编辑器，因为它是跨平台编辑器，具有内置包管理器，智能自动完成功能，并具有许多其他优势。

# 安装谷歌浏览器

要安装谷歌浏览器，请转到[`www.google.com/chrome`](http://www.google.com/chrome)并单击**立即下载**，如下面的屏幕截图所示：

![安装谷歌浏览器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_01_01.jpg)

然后按下**接受并安装**按钮，如下面的屏幕截图所示：

![安装谷歌浏览器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_01_02.jpg)

安装将根据您的网络速度和计算机硬件配置而完成。

### 注意

如果您不想将谷歌浏览器设置为默认浏览器，请取消选中**将谷歌浏览器设置为我的默认浏览器**。

# 安装 Atom

要安装 Atom 文本编辑器，请转到[`atom.io/`](https://atom.io/)链接并单击**下载 Windows 安装程序**，如下面的屏幕截图所示：

![安装 Atom](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_01_03.jpg)

名为`AtomSetup.exe`的文件将开始下载。

单击`AtomSetup.exe`文件开始安装 Atom。

### 提示

确保在安装时赋予管理权限以获得更好的性能。

安装完成后，Atom 将自动启动。

如果您在另一个平台上，请使用**其他平台**链接：

+   如果您是 Mac 用户，请转到[`github.com/atom/atom/releases/latest`](https://github.com/atom/atom/releases/latest)链接，并下载`atom-X.X.X-full.nupkg`文件，其中`X.X.X`是 Atom 的版本号。双击该文件进行安装。

+   如果您是 Ubuntu 用户，您可以按照[`github.com/atom/atom/releases/latest`](https://github.com/atom/atom/releases/latest)链接并下载`atom-amd64.deb`文件。下载后，在相同的文件夹中启动您的**终端**，然后编写以下代码：

```js
sudo dpkg --install atom-amd64.deb

```

您可能需要管理员密码来安装它。安装完成后，您可以通过在终端中输入`Atom`并按*Enter*来运行 Atom。

# Chrome 开发者工具

让我们来看看用于 JavaScript 的**Chrome 开发者工具**，特别是*控制台*。由于 Google Chrome 已下载并安装在您的计算机上，打开 Google Chrome 浏览器，转到菜单（右上角），悬停在**更多工具**上，然后选择**开发者工具**，如下图所示：

![Chrome 开发者工具](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_01_04.jpg)

您将看到以下工具：

+   **元素**

+   **网络**

+   **资源**

+   **时间线**

+   **配置文件**

+   **资源**

+   **审核**

+   **控制台**

# 我们的第一个程序

现在，让我们检查 JavaScript 是否在您的计算机上运行。

从工具中选择**控制台**。如果找不到**控制台**，请点击**>>**符号，如下所示：

![我们的第一个程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_01_05.jpg)

一旦您的控制台打开，输入以下代码并在键盘上按*Enter*：

```js
document.write("Hello World");

```

如果您可以在左侧面板上看到如下所示的输出，那么您已成功在浏览器上配置了 JavaScript：

![我们的第一个程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_01_06.jpg)

您将看到以下输出：

**Hello World**

恭喜！

### 注意

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接将文件发送到您的电子邮件。

如果您看不到文本，请检查您的代码或以管理员权限安装 Google Chrome。

您还可以单击控制台的齿轮按钮。检查**禁用 JavaScript**是否未选中：

![我们的第一个程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_01_07.jpg)

您还可以使用此工具调试您的 JavaScript 代码。

如果您输入任何错误；考虑到您忘记了`Hello World`字符串的引号，您将会得到以下错误：

![我们的第一个程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_01_08.jpg)

为了加快编写代码的速度，您可以学习一些控制台和 Atom 文本编辑器的键盘快捷键。

以下是控制台的一些键盘快捷键：

+   *Ctrl* + *L*：清除控制台

+   *Tab*：自动完成常见前缀

+   右箭头：接受建议

+   *Ctrl* + *U*：清除控制台提示

+   上/下：下一行/上一行

+   *Enter*：执行命令

以下是 Atom 文本编辑器的一些键盘快捷键：

+   *Ctrl* + *B*：浏览打开文件列表

+   *Ctrl* +*Alt* + *R*：重新加载 Atom

+   *Ctrl* +*Shift* + *L*：更改语法高亮

+   *Alt* +*Shift* + *S*：显示可用代码片段

+   *Ctrl* +*Shift* + *M*：Markdown 预览

+   *Ctrl* +*Alt* + *I*：切换开发者工具

+   *Ctrl* + *N*：新文件

+   *Ctrl* +*Shift* + *N*：新窗口

+   *Ctrl* + *P*：打开文件（输入名称进行搜索）

+   *Ctrl* + *O*：打开文件

+   *Ctrl* +*Shift* + *O*：打开文件夹

+   *Ctrl* + *S*：保存

+   *Ctrl* +*Shift* + *S*：另存为

+   *Ctrl* + *W*：关闭标签

+   *Ctrl* +*Shift* + *W*：关闭窗口

+   *Ctrl* + *G*：转到行

+   *Ctrl* + *L*：选择行

+   *Ctrl* +*Shift* + *D*：复制行

+   *Ctrl* +*Shift* + *K*：删除行

+   *Ctrl* + 上/下：上移/下移行

+   *Ctrl* + */*：切换注释行

+   *Ctrl* + *Enter*：在下方插入新行

+   *Ctrl* + *[*/*]*：缩进/取消缩进所选行

+   *Ctrl* + *J*：连接行

+   *Ctrl* + *Alt* + *.*：完成括号

+   *Ctrl* + *M*：转到匹配的括号

+   *Ctrl* + *Alt* + *M*：选择匹配括号内的代码

+   *Ctrl* + *Alt* + */*：折叠/展开代码

+   *Ctrl* + *Alt* + *F*：折叠选定的代码

+   *Ctrl* + *Alt* + *[*/*]*：折叠/展开所有代码

+   *Ctrl* + *F*：在当前文件中查找

+   *Ctrl* + *Shift* + *F*：在项目中查找

+   *F3*：查找下一个

+   *Shift* + *F3*：查找上一个

+   *Ctrl* + *Enter*：替换所有

+   *Ctrl* + *Alt* + */*：在搜索中使用正则表达式

+   *Ctrl* + *Shift* + *=*/*-*：增加/减少文本大小

+   *Ctrl* + *0*（零）：重置文本大小

+   *F11*：切换全屏

# 为什么我们要使用 Chrome 开发者工具？

以下是 Chrome 开发者工具的使用方法：

+   易于查看错误

+   使用行号轻松编辑/调试代码

+   实时输出（无需刷新页面）

# 为什么我们要使用 Atom 作为文本编辑器？

以下是 Atom 作为文本编辑器的使用方法：

+   可嵌入性和可用性的零妥协组合

+   一个开源文本编辑器

+   每个 Atom 窗口本质上都是一个本地渲染的网页

# 练习

为了增进对 JavaScript 的了解，编写一个能打印您的名字的程序。

# 总结

在本章中，我们看到了如何下载 Google Chrome 和 Atom，并安装它们。

您学会了如何使用 Chrome 开发者工具（**控制台**）编写您的第一行代码。您还学会了一些 Chrome 开发者工具和 Atom 文本编辑器的键盘快捷键。

您还了解了 JavaScript 是什么，为什么学习 JavaScript 很重要，以及 JavaScript 与其他语言的不同之处。

现在我们可以进入 JavaScript 的世界。

您的旅程始于第二章，*使用 JavaScript 解决问题*。


# 第二章：使用 JavaScript 解决问题

在上一章中，你已经学会了如何使用 JavaScript 在控制台上打印东西。现在，让我们看看 JavaScript 语法、变量、算术运算符和注释背后的基本原理。

在计算机世界中，除了数据什么都没有。你可以读取、修改和创建新的数据；然而，任何不是数据的东西根本就不存在。在 JavaScript 中，我们需要处理数据来开发网站。

要理解 JavaScript 的基本语法，首先你需要知道 JavaScript 是*区分大小写*的。你不能在 JavaScript 中交换大小写字母。因此，在处理 JavaScript 语法时，你需要记住写代码不是唯一重要的任务，你还必须注意语法是否写得正确。

让我给你举个例子。在上一章中，你已经成功地使用`document.write();`语法在浏览器上打印了**Hello World**。

如果你写了`Document.write("Hello World");`会发生什么？是的！它不会成功运行。你会得到一个错误消息。这种错误被称为**未捕获的语法错误**。

JavaScript 语句通常写在一行上。你可以用分号结束你的语句，也可以不用。结束语句不是强制性的。然而，每个语句后面加上分号是一个好习惯。

让我们考虑以下例子：

```js
document.write("Hello");
document.write("World");
document.write("!");
```

它的输出将如下所示：

![使用 JavaScript 解决问题](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_01.jpg)

### 注意

JavaScript 关键字（如 for、while、if、switch、case 等）始终是小写的。内置对象（如 Date、Math、Number 等）以大写字母开头。

# 变量

我们已经知道计算机世界除了数据什么都没有。

有不同类型的数据（我们称之为*数据类型*），如下所示：

+   你的名字是一种数据

+   你的年龄是数据

+   你的成绩也是数据

然而，它们都是不同的。它们之间有什么区别？你的名字只包含一组*字符*，或者有些人也称之为**字符串**。你的年龄是一个**整数**类型的数据。你的成绩是一个**浮点数**类型的数据。JavaScript 中的奇妙之处在于，在写一个*变量*的名字之前，你不必指定数据类型。

### 注意

JavaScript 允许使用三种数据类型。字符串（例如，`"这是一个字符串的例子"`），数字（例如，`2015`，`3.1415`等），和布尔值（例如，`true`或`false`）。

我们讨论过*变量*了吗？好吧，你已经知道了数据类型。你需要*某物*来存储你的数据。这个*某物*就叫做*变量*。在 JavaScript 中，我们在变量名之前使用`var`。记住，`var`以小写字母开头。

让我们考虑以下例子：

```js
var x;
var y;
var sum;
var name;
```

假设我们有 14 个苹果和 6 个橙子。为了把它们存储在变量中，我们将使用以下方法：

```js
var apples = 14;
var oranges = 6;
```

下面的例子不一样。你能告诉为什么吗？

```js
var Apples = 14;
var apples = 14;
var APPLES = 14;
var appleS = 14;
```

是的，JavaScript 是区分大小写的。所有的变量在这里都是不同的，尽管变量的值是相同的。

现在，让我们做一些编码。之前在控制台上，你打印了你的名字作业。我希望你能毫无困难地完成。现在我们用一个变量来以不同的方式打印你的名字，怎么样？假设你的名字是`夏洛克·福尔摩斯`。这是什么类型的数据？

你说得对，它是*字符串*类型。通常对于字符串类型的数据，我们把字符串放在两个引号之间。

让我们考虑以下例子：

```js
var name = "Sherlock Holmes";
var occupation = "Detective"
```

要在控制台上打印它们，你需要输入每个语句并按*Enter*。看一下下面的图片：

![变量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_02.jpg)

### 注意

不要在控制台上复制和粘贴代码。你可能会得到一个语法错误。

当你按下*Enter*后，会出现一个额外的行，显示`undefined`。现在不用担心这个。这只是返回了一个控制台日志。

您将`福尔摩斯`字符串存储在`name`变量中，将`侦探`存储在`occupation`中。每次访问`name`或`occupation`时，您都可以访问到这些字符串。

假设您想要在屏幕上打印**福尔摩斯**。只需输入以下内容：

```js
document.write(name);
```

输入后，按*Enter*。您将看到**福尔摩斯**被打印在屏幕上，如下所示：

![变量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_03.jpg)

输入`document.write(occupation);`并按*Enter*，如下截图所示：

![变量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_04.jpg)

您可能会想知道为什么**福尔摩斯**和**侦探**之间没有空格。因为在控制台上，左侧的网页历史不会自动从上一个字符串之后移除，并且在您为第二个输出（`occupation`）按*Enter*之后，字符串会直接放在前一个字符串的后面。这种情况将一直发生，除非您使用*Ctrl* + *L*键盘快捷键清除控制台，并按*F5*键重新加载网页。

### 注意

当重新加载网页时，您存储的变量也将从内存中被擦除。不用担心，下一章节将教您如何在文件中使用存储的变量。

如果您想要连接两个（或多个）变量，您需要在两个变量之间添加加号（`+`），如下所示：

```js
document.write(name+occupation);
document.write(occupation+name);
```

您能告诉我这些命令的输出将是什么吗？

是的，您是对的。输出将如下所示：

**福尔摩斯侦探**

**侦探福尔摩斯**

### 注意

您的输出可能会在网页上显示为一行。如果您想要换行，可以添加`<br>`HTML 标签。最简单的方法是输入`document.write("<br>");`并按*Enter*。您的下一个输出将在新的一行上。

如果您想在两个字符串之间添加任何字符串（例如空格），而不是任何变量，只需输入以下内容：

```js
document.write(name+" "+occupation);
```

输出将如下所示：

**福尔摩斯侦探**

当您输入以下代码并按*Enter*时会发生什么？

```js
document.write("My name is "+name+" and I am a "+occupation);
```

是的！您是绝对正确的。输出将如下所示：

**我的名字是福尔摩斯，我是一名侦探**

![变量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_05.jpg)

现在，在控制台上添加另一个变量。考虑`福尔摩斯`是 24 岁。您还记得年龄是什么类型的数据吗？

是的，这是一个整数类型的数字。因此，输入以下代码并按*Enter*：

```js
var age = 24;
```

您现在有以下三个变量：

+   姓名

+   职业

+   年龄

让我们在网页上打印以下输出：

**我的名字是福尔摩斯，我今年 24 岁，我是一名侦探**

我们的控制台代码将是什么？

代码如下：

```js
document.write("My name is "+name+", I\'m "+age+" years old and I am a "+occupation);
```

输出如下所示：

![变量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_06.jpg)

### 提示

**打印引号/倒置逗号**

如果您想使用`document.write();`语法打印**莎士比亚说：“生存还是毁灭，这是一个问题！”**，您可能会输入以下代码：

```js
document.write("Shakespeare said, "To be, or not to be: that is the question!"");
```

然而，这将导致一个名为**SyntaxError**的错误。为了摆脱这个错误，您需要在两个倒置逗号之前使用反斜杠（`\`）。正确的代码将如下所示：

```js
document.write("Shakespeare said, \"To be, or not to be: that is the question!\"");
```

输出将如下所示：

**莎士比亚说：“生存还是毁灭，这是一个问题！”**

单引号（`'`）也适用相同的规则。

这里有一个快速练习给你：

1.  假设`汤姆`有一只猫（`露西`）。这只猫，`露西`，今年`2.4`岁。将姓名、猫的名字和年龄分别存储在三个不同的变量中，并使用控制台打印以下输出：

**汤姆的猫露西今年 2.4 岁。**

1.  假设您购买了`4`磅的苹果。每磅花费了您`$1.2`。将苹果的价格和数量分别存储在两个不同的变量中，并使用控制台打印以下输出：

**我买了 4 磅的苹果。每磅我需要支付 1.2 美元。**

# 评论

假设你已经做了很多编码和一些逻辑操作，并在 JavaScript 中使用了许多变量，如果出现任何错误，你希望我帮你处理代码。当你把代码发给我时，除非我对 JavaScript 有清楚的了解，或者你在重要的行上做了注释，否则我不会知道你输入了什么。

注释基本上是浏览器在运行时忽略的一行文本或代码。你可以把注释比作便利贴或提醒。

让我们考虑以下例子：

```js
Var name = "Sherlock Holmes"; // This is a string
Var occupation = "Detective"; // This variable stores information
Var age = 14; // This is an integer type of data.
```

如何创建多行注释？你可以这样提到注释：

```js
/*
  This is a multiline comment.
  The browser will ignore this.
  You can type any important information on your comment.
*/
```

你的多行注释应该在`/*`和`*/`之间，如下截图所示：

![注释](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_07.jpg)

# 算术运算符

在 JavaScript 中，就像其他编程语言一样，我们可以进行一些算术运算。在学校里，你可能已经学会了如何将两个数字相加，从一个数字中减去另一个数字，将两个数字相乘，并将一个数字除以另一个数字。你可以用几行代码在 JavaScript 中做所有这些事情。

在 JavaScript 中，我们使用以下算术符号进行运算：

| 运算符 | 描述 |
| --- | --- |
| + | 加法 |
| - | 减法 |
| * | 乘法 |
| / | 除法 |
| % | 找到余数（称为取模运算符） |

## 加法

假设你有两个变量`x`和`y`，它们的值分别是`3`和`4`。我们应该在控制台上做什么来存储变量的值？

是的，我们做以下操作：

```js
var x = 3; // 3 is stored on variable x
var y = 4; // 4 is stored on variable y
```

然后，按*Enter*。

再取另一个变量，它将保存`x`和`y`的总和，如下所示：

```js
var z = x+y; // This syntax stores the sum of x and y on z
```

你能告诉我当我们打印`z`时会发生什么吗？

```js
document.write(z);
```

是的，你是对的，这将打印**7**，如下截图所示：

![加法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_08.jpg)

## 减法

要从一个数字中减去另一个数字，你需要在它们之间放一个减号（-）。

让我们考虑以下例子：

```js
var x = 9; // 9 is assigned to the variable x.
var y = 3; // 3 is assigned to the variable y.
var z = x - y ; // This syntax subtracts y from x and stores on z.
document.write(z); // Prints the value of z.
```

这段代码的输出是**6**，如下截图所示：

![减法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_09.jpg)

## 乘法

要对存储在两个整数或浮点类型数据的变量或数字进行乘法，只需在变量或数字之间放一个星号（`*`）。

让我们看下面的例子：

```js
var x = 6; // 6 is assigned to the variable x.
var y = 2; // 2 is assigned to the variable y.
var z = x * y; // For two numbers you can type z = 6 * 2 ;
document.write(z); // Prints the value of z
```

这段代码的输出是**12**，如下截图所示：

![乘法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_10.jpg)

## 除法

要将一个数字除以另一个数字，你需要在数字之间放一个斜杠（`/`）。

让我们看下面的例子：

```js
var x = 14; // assigns 14 on variable x.
var y = 2; // assigns 2 on variable y. 
var z = x / y; // divides x with y and stores the value on z. 
document.write(z); // prints the value of z. 
```

这段代码的输出是**7**，如下截图所示：

![除法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_11.jpg)

## 取模

如果你想找到一个数字与另一个数字的模，你需要在数字之间放一个百分号（`%`）。

让我们考虑以下例子：

```js
var x = 34; // assigns 34 on the variable x. 
var y = 3; // assigns 3 on the variable y. 
var z = x % y ; // divides x with y and returns the reminder and stores on the variable z
document.write(z);
```

这段代码的输出是**1**，如下截图所示：

![取模](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_12.jpg)

### 提示

**取模（%）运算符是做什么的？**

好吧，从你的数学课上，你已经学会了如何将一个数字除以另一个。比如，你将 10 除以 2。结果将是 5，这是一个整数类型的数字。然而，如果你将 10 除以 3 会发生什么？答案不会是一个整数。值是 3.333333333333。你也可以说答案是 3，余数是 1。考虑以下：

`10 = 9 + 1;`

也就是，`(9+1)/3`

`= 9/3+1/3`

`= 3 + 1/3;`

因此，余数是 1。取模的作用是找出余数并返回它。因此，`10%3 = 1`。

现在，让我们总结我们迄今为止学到的所有算术运算符在一个单一的代码中。

你能告诉我以下行的输出是什么吗？

```js
var x = 5 ;
var y = 4 ;
var sum = x + y ;
var sub = x - y ;
var mul = x * y ;
var div = x / y ;
var mod = x % y ;
document.write("The summation of x and y is "+ sum + "<br>") ;
document.write("The subtraction of x and y is " + sub + "<br>") ;
document.write("The multiplication of x and y is " + mul + "<br>");
document.write("The division of x and y is " + div + "<br>") ;
document.write("The modulus of x and y is " + mod + "<br>") ;
```

你将得到以下输出：

**x 和 y 的总和是 9**

**x 和 y 的减法是 1**

**x 和 y 的乘积是 20**

**x 和 y 的除法是 1.25**

**x 和 y 的模是 1**

这个输出可以在以下截图中看到：

![取模](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_13.jpg)

我猜你做对了。现在，让我们在下面解释它们：

+   我们分别给`x`和`y`分配了`5`和`4`

+   我们将`x`和`y`的总和分配给`sum`变量，`x`和`y`的减法分配给`sub`变量，`x`和`y`的乘法分配给`mul`变量，`x`和`y`的除法分配给`div`变量，`x`和`y`的模数分配给`mod`变量

+   然后，我们使用`document.write();`语法打印它们

+   我们使用`<br>`HTML 标签来分隔每行的输出

考虑以下示例：

约翰有 56 支笔。他想把它们排成七行。每行将有相等数量的笔。编写一个代码，将打印出每行的笔数。

（提示：为笔的数量和行数取两个变量，将笔的数量除以行数并将值存储在一个新变量中。）

示例输出如下：

**约翰将不得不在每行放置 XX 支笔。 // XX 是笔的数量**

# 更多的运算符和操作

JavaScript 有更多的运算符，除了前面提到的那些。让我们深入一点。

## 增量或减量运算符

如果您有一个整数，想要将其增加 1 或任何数字，您可以输入以下内容：

```js
var x = 4; // assigns 4 on the variable x.
x = x + 1;
/* since x=4, and you are adding 1 with x, so the final value is 4 + 1 = 5, and 5 is stored on the same variable x. */
```

您也可以通过输入以下内容将变量增加 1：

```js
var x = 4; // assigns 4 on the variable x.
x++; // This is similar to x = x + 1.
```

如果您想要将变量增加多于 1，您会怎么做？好吧，您可以按照以下步骤：

```js
var x = 4; // assigns 4 on the variable x.
x = x + 3; // Say, you want to increment x by 3.
/* since x = 4, and you are adding 3 with x, so the final value is 4 + 3 = 7, and 7 is stored on the same variable x. */
```

您也可以通过输入以下内容来增加您的变量：

```js
var x = 4; // assigns 4 on the variable x.
x += 3; // This is similar to x = x + 3.
```

### 提示

请记住，您不应该在运算符（例如+，-，*，/等）和等号（=）之间放置空格。

输出将在控制台上看起来类似于以下截图：

![增量或减量运算符](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_14.jpg)

那么减量运算符呢？是的，你完全正确。减量操作与增量操作相同。唯一改变的是符号。您的加法（`+`）运算符将被减法运算符（`-`）替换。让我们看一个例子：

```js
var x = 9; // assigns 9 on the variable x.
x = x - 1;
/* since x = 9, and you are subtracting 1 from x, so the final value is 9 - 1 = 8, and 8 is stored on the same variable x. */
```

您还可以通过输入以下内容将变量减少`1`：

```js
var x = 9; // assigns 9 on the variable x.
x--; // This is similar to x = x - 1.
```

如果您想要将变量减少多于`1`，您可以按照以下步骤：

```js
var x = 9; // assigns 9 on the variable x.
x = x - 4; // Say, you want to decrement x by 4.
/* since x = 9, and you are subtracting 4 from x, so the final value is 9 - 4 = 5, and 5 is stored on the same variable x. */
```

您还可以通过输入以下内容将变量减少：

```js
var x = 9; // assigns 9 on the variable x.
x -= 4; // This is similar to x = x - 4.
```

这些代码的输出可以在以下截图中看到：

![增量或减量运算符](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_15.jpg)

这种类型的操作对于 JavaScript 中的逻辑操作非常重要。您将在第四章*深入了解*中了解它们的用途。

## 赋值运算符

赋值运算符将一个值分配给一个运算符。我相信你已经了解了赋值运算符，不是吗？好吧，你在一个变量和它的值之间使用一个等号(`=`)。通过这样做，您将值分配给变量。

让我们看看以下示例：

```js
var name = "Sherlock Holmes"
```

`Sherlock Holmes`字符串被分配给`name`变量。您已经学习了增量和减量运算符。你能告诉我以下代码的输出将是什么吗？

```js
var x = 3; 
x *= 2; 
document.write(x); 
```

输出将是**6**。

您还记得为什么会发生这种情况吗？

`x *= 2;`等式类似于`x = x * 2;`，因为`x`等于`3`，然后乘以`2`。最终的数字（`3 x 2 = 6`）被分配给相同的`x`变量。这就是为什么我们得到以下输出的原因：

![赋值运算符](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_16.jpg)

让我们进行以下练习：

以下代码的输出是什么？

```js
var w = 32;
var x = 12;
var y = 9;
var z = 5;
w++;
w--;
x*2;
y = x;
y--;
z%2;
document.write(" w = "+w+ ", x = "+x+ ", y =  "+ y+", z =  "+z  );
```

我们将得到以下输出：

**w = 32, x = 12, y = 11, z = 5**

这个输出可以在以下截图中看到：

![赋值运算符](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_17.jpg)

## JavaScript 比较和逻辑运算符

如果您想在 JavaScript 中做一些逻辑操作并比较两个数字或变量，您需要使用一些逻辑运算符。以下是一些比较运算符的示例：

| 运算符 | 描述 |
| --- | --- |
| == | 等于 |
| != | 不等于 |
| > | 大于 |
| < | 小于 |
| => | 等于或大于 |
| <= | 小于或等于 |

以下是使用这些运算符的一些示例：

![JavaScript 比较和逻辑运算符](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_02_18.jpg)

您将在接下来的章节中了解更多关于这些运算符的用法。

让我们讨论一些位逻辑运算符和位运算符：

| 运算符 | 描述 |
| --- | --- |
| && | 这意味着 AND 运算符。我们使用它来检查两个或更多语句是否为真。 |
| &#124;&#124; | 这意味着 OR 运算符。我们使用它来检查任何语句是否为真。 |
| ~ | 这意味着 NOT 运算符。 |
| ^ | 这意味着 XOR 运算符。 |
| >> | 这意味着右移运算符。 |
| << | 这意味着左移运算符。 |

它们可能对您现在来说很难学。不用担心，您现在不必使用它们。我们将在第四章，*深入了解*中使用它们。

# 总结

在本章中，您学习了 JavaScript 语法。我们讨论了 JavaScript 变量以及如何为变量赋值。您学会了如何对代码进行注释。您现在知道了为什么注释很重要。最后，您学会了一个重要的主题：运算符和操作。如今，JavaScript 如果不使用运算符和逻辑函数，就不会那么丰富。因此，学习逻辑运算是获得 JavaScript 良好知识的关键。

我建议您在家里练习本章中的所有代码。您只需在控制台上输入它们，避免复制和粘贴代码。这将妨碍您的学习。作为程序员必须有良好的打字速度，复制和粘贴代码不会提高这一技能。您可能在输入代码时遇到问题；然而，您会学到的。

您可以使用 JavaScript 解决任何算术问题。您还可以在控制台上检查您的逻辑是真还是假。如果您能做到这一点，我们可以继续下一章，第三章，*介绍 HTML 和 CSS*，在那里您将学习有关 HTML、CSS 等的知识。


# 第三章：介绍 HTML 和 CSS

您已经在上一章学习了 JavaScript 语法、算术运算符和注释。我们用控制台来实现这些目的。现在，您想学习一些有趣的东西，这将为您成为一名优秀的 JavaScript 程序员铺平道路吗？在本章中，我们将学习**超文本标记语言**（**HTML**）语法、**层叠样式表**（**CSS**）语法以及如何在 HTML 页面中使用 JavaScript。

HTML 是网页的源代码。您在 Web 浏览器上加载的所有网页都是用 HTML 构建的。转到任何网站（例如，[`www.google.com`](https://www.google.com)）并在键盘上按*Ctrl* + *U*（在 Mac 上，点击*command* + *U*），您将获得网页的源代码。这适用于所有现代 Web 浏览器，如 Firefox，Google Chrome，UC 等。

您将看到的整个代码都是 HTML。您还可能会找到一些带有 JavaScript 的行。因此，为了了解网页的结构（页面背后的代码），您需要了解 HTML。这是网络上最简单的语言之一。

# HTML

HTML 是一种标记语言。这是什么意思？嗯，标记语言使用特定的代码来处理和呈现文本，用于格式、样式和布局设计。有很多标记语言（例如，**业务叙述标记语言**（**BNML**），**ColdFusion 标记语言**（**CFML**），**Opera** **二进制标记语言**（**OBML**），**系统** **生物标记语言**（**SBML**），**虚拟人标记语言**（**VHML**）等）；然而，在现代网络中，我们使用 HTML。HTML 基于**标准通用标记语言**（**SGML**）。SGML 基本上用于设计文档纸。

### 注意

有许多 HTML 版本。HTML 5 是最新版本。在本书中，我们将使用最新版本的 HTML。

在开始学习 HTML 之前，让我问问您最喜欢的网站是什么。网站包含什么？一些网页？您可能会看到一些文本，一些图像，一两个文本字段，按钮以及每个网页上的一些其他元素。所有这些元素都是由 HTML 格式化的。

让我向您介绍一个网页。在您的互联网浏览器中，转到[`www.google.com`](https://www.google.com)。您将看到以下图像中显示的页面：

![HTML](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_01.jpg)

您在浏览器顶部看到的第一件事是网页的标题。让我们观察一下刚刚加载的页面：

+   在这里，标记的框，**1**，是我们加载的网页的标题。

+   第二个框，**2**，表示一些链接或文本。

+   页面中间的**Google**是一个图像。

+   第三个框，**3**，包含两个按钮。

+   你能告诉我页面右上角的**登录**是什么吗？是的，这是一个按钮。

让我们演示 HTML 的基本结构。术语*标签*将经常用于演示结构。

HTML 标签只是在小于号（`<`）和大于号（`>`）之间的一些预定义词。因此，标签的结构是`<WORD>`，其中`WORD`是互联网浏览器识别的预定义文本。这种类型的标签称为开放标签。还有另一种类型的标签，称为关闭标签。关闭标签的结构类似于`</WORD>`。您只需在小于号后面放一个斜杠。

在本节之后，您将能够使用 HTML 制作自己的网页。HTML 页面的结构类似于以下图像。这个图像有八个标签。让我们介绍所有这些标签及其活动，如下所示：

![HTML](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_02.jpg)

+   **1**：标签`<html>`是一个开放标签，在第**15**行关闭，使用`</html>`标签。

+   这些标签告诉您的互联网浏览器，这两个标签中的所有文本和脚本都是 HTML 文档。

+   **2**：这是`<head>`标签，是一个开放标签，在第**7**行关闭，使用`</head>`标签。

+   这些标签包含网页的标题、脚本、样式和元数据。

+   **3**：这是`<title>`标签，在第**4**行关闭，使用`</title>`标签。

+   此标签包含网页的标题。上一张图片的标题是**Google**。要在 Web 浏览器上看到这个，您需要输入以下内容：

```js
<title> Google </title>
```

+   **4**：这是`<title>`标签的关闭标签。

+   **5**：这是`<head>`标签的关闭标签。

+   **6**：这是`<body>`标签，在第**13**行关闭，使用`</body>`标签。

您在网页上看到的所有内容都是在这两个标签之间编写的。每个元素、图像、链接等都在这里格式化。要在浏览器上看到这是一个网页，您需要输入以下内容：

```js
<body>
This is a web page.
</body>
```

+   **7**：`</body>`标签在此处关闭。

+   **8**：`</html>`标签在此处关闭。

## 您的第一个网页

您刚刚学习了 HTML 页面的八个基本标签。现在您可以制作自己的网页。怎么做？为什么不和我一起尝试一下呢？

1.  打开您的文本编辑器（您已经在本书的第一章中安装了 Atom，*在控制台中探索 JavaScript*）。

1.  按下*Ctrl* + *N*，将打开一个新的`untitled`文件，如下图所示：![您的第一个网页](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_03.jpg)

1.  在空白页面上输入以下 HTML 代码：

```js
<html>
  <head>
    <title>
      My Webpage!
    </title>
  </head>
  <body>
    This is my webpage :)
  </body>
</html>
```

1.  然后，按下*Ctrl* + *Shift* + *S*，这将提示您在计算机上的某个位置保存您的代码：![您的第一个网页](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_04.jpg)

1.  在**文件名：**字段中输入一个合适的名称。我想将我的 HTML 文件命名为`webpage`，因此我输入了`webpage.html`。您可能想知道为什么我添加了一个扩展名（`.html`）。

### 注意

由于这是一个 HTML 文档，您需要在给网页命名后添加`.html`或`.htm`。`.htm`扩展名是`.html`的旧形式。它的限制是保持文件扩展名为三个字符，因此人们使用`.htm`而不是`.html`。您也可以使用`.htm`。

1.  按下**保存**按钮。这将在您的计算机上创建一个 HTML 文档。转到您刚刚保存 HTML 文件的目录。

### 注意

请记住，您可以给您的网页任何名称。但是，这个名称不会显示在您的浏览器上。这不是您网页的标题。最好不要在网页名称中保留空格。例如，您想将 HTML 文件命名为`这是我的第一个网页.html`。您的计算机在 Internet 浏览器上显示结果时不会遇到问题；但是，当您的网站在服务器上时，这个名称可能会遇到问题。因此，我建议您在需要添加空格的地方使用下划线（`_`），例如`This_is_my_first_webpage.html`。

1.  您会发现一个类似以下图像的文件：![您的第一个网页](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_05.jpg)

1.  现在，双击文件。您将在 Internet 浏览器上看到您的第一个网页！！您的第一个网页

您在`<title>`和`</title>`标签之间输入了`My Webpage!`，这就是为什么您的浏览器在第一个选择框中显示这个。**1**。您在`<body>`和`</body>`标签之间输入了`This is my webpage :)`。因此，您可以在第二个选择框中在浏览器上看到文本。**2**。

恭喜！您创建了您的第一个网页！

### 注意

你可以通过右键单击文件并选择**使用 Atom 打开**来编辑`webpage.html`文件的代码和其他文本。在重新在浏览器中打开文件之前，您必须保存（*Ctrl* + *S*）您的代码和文本。

## 更多 HTML 标签

有许多 HTML 标签可用于格式化网页的文本和对象。我们现在来学习其中一些吧？

| 描述 | 带示例的语法 | 浏览器上的结果 |
| --- | --- | --- |
| 粗体文本 | `<b>这是粗体</b>` | **这是粗体** |
| 斜体文本 | `<i>这是斜体</i>` | *这是斜体* |
| 下划线文本 | `<u>下划线文本</u>` | ![更多 HTML 标签](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_14.jpg) |
| 删除的文本 | `<del>删除我</del>` | ![更多 HTML 标签](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_15.jpg) |
| 下标文本 | `CO<sub>2</sub>` | CO2 |
| 上标 | `3x10<sup>8</sup>` | 3x108 |
| 最大标题 | `<h1>嗨，孩子们！</h1>` | ![更多 HTML 标签](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_16.jpg) |
| 最小标题 | `<h6>嗨，孩子们</h6>` | ![更多 HTML 标签](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_17.jpg) |
| 段落文本 | `<p>这是一个段落</p>` | 这是一个段落 |
| 断开标签 | `This <br>is <br>a break;` | This is a break; |

### 注意

有六个标题标签（`<h1>`到`<h6>`）。如果需要，你可以为一个文本添加多个标签。例如：`<b><i><u> JavaScript </b></i></u>`将有以下输出：![更多 HTML 标签](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_18.jpg)。关闭标签的顺序没有特定的顺序。最好的做法是遵循打开标签的顺序。

## 着色 HTML 文本

要给 HTML 文本着色，我们可以输入以下内容：

```js
<font color = "Green"> I am green </font>
```

你可以在两个引号之间输入任何标准颜色名称（`" "`）。你也可以使用十六进制颜色代码，如下所示：

```js
<font color = "#32CD32"> I am green </font>
```

这里，`32CD32`是绿色的十六进制代码。看看下面的图片。左边是代码，我们在其中使用了颜色名称和十六进制代码。右边是我们浏览器的输出： 

![着色 HTML 文本](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_07.jpg)

### 注意

十六进制颜色代码由六位数字组成（它是一个十六进制数）。它以井号或哈希号（`#`）开头，我们在其后放置六位十六进制数。十六进制数表示红色、蓝色和绿色的数量。每两位数字表示`00`到`FF`（十六进制数）。在这个例子中，我们使用`#32CD32`表示绿色。`32`、`CD`和`32`分别是十六进制中红色、蓝色和绿色的数量。

如果你不知道什么是十六进制数，记住我们使用十进制数，其中使用了 10 个数字（0、1、2、3、4、5、6、7、8 和 9）。然而，在十六进制数中，我们使用 16 个数字（0、1、2、3、4、5、6、7、8、9、A、B、C、D、E 和 F）。

我建议你使用这个网站（[`html-color-codes.info/`](http://html-color-codes.info/)）获取你喜欢的颜色的十六进制代码，而不用考虑十六进制代码。

## 链接 HTML 文本

要创建文本超链接，我们使用锚标签如下所示：

```js
<a href = "http://www.google.com"> Go to Google </a>
```

这段代码的输出将是一个链接。如果你点击链接，它会将你发送到我们在引号中使用的 URL（这里是[`www.google.com`](http://www.google.com)）。

如果你想在浏览器的新标签中打开你的链接，你需要添加一个目标，如下所示：

```js
<a href = "http://google.com" target = "_blank" > Go to Google </a>
```

这里，`target="_blank"`是一个属性，告诉你的浏览器在新标签中打开链接。还有一些其他属性。你可以在家里尝试它们，然后告诉我们你在浏览器上看到了什么。

其他属性还有`_parent`、`_self`和`_top`。以下图像具有带有`_blank`属性的代码。它在新标签中打开[`google.com`](http://google.com)。我建议你找出其他属性的作用：

![链接 HTML 文本](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_08.jpg)

## 插入图像

在 HTML 文档中插入图像非常容易。你只需要找到图像文件的扩展名。我们用来插入图像的标签如下所示：

```js
<img src = "Image_name.extension">
```

`src`属性是你的图像来源。如果你的图像放在 HTML 文件的同一个目录中，你不需要写整个文件来源。在本书中，我们将保持我们的图像文件在同一个目录中，我们保存我们的 HTML 文件。

假设我在保存 HTML 文档的同一个文件夹中有一张图片。图片的名称是`physics`，扩展名是`.png`。现在，要在 HTML 文档中添加这个图片，我需要添加以下代码：

```js
<img src= "physics.png">
```

![插入图像](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_09.jpg)

### 注意

在 HTML 文档中使用三种类型的图像。**可移植网络图形**（**PNG**），**图形交换格式**（**GIF**）和**联合图像专家组**（**JPG**或**JPEG**）。要找到图像的扩展名，请右键单击图像，转到**属性**，然后点击**详细信息**选项卡，直到找到**名称**字段。您将找到带有扩展名的图像名称。根据您的操作系统，您的机器上的程序可能有所不同。

如果您想设置图像的高度和宽度，您需要使用两个属性，如下所示：

```js
< img src = "physics.png" width="100" height="40">
```

这里，`100`和`40`是图像的像素。在以前的 HTML 版本中，它被定义为像素或百分比。

### 注意

像素是图像的最小单位。如果您希望在不同屏幕尺寸上看到相同比例的图像，最好使用百分比（`%`），否则，您可以使用像素（`px`）单位。

输出将类似于以下内容：

![插入图像](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_10.jpg)

还有更多的 HTML 标签；但是，我们已经涵盖了大部分用于构建网页的标签。您能想象以下代码的输出吗？

```js
<html>
  <head>
    <title>
      Example
    </title>
  </head>
  <body>
    <h1> This is a headline </h1>
    <h2> This is a headline </h2>
    <h3> This is a headline </h3>
    <h4> This is a headline </h4>
    <h5> This is a headline </h5>
    <h6> This is a headline </h6>
    <b>This is a bold text</b>. But <i>This is an italic text</i>. We can <u> underline</u> our text. <a href = "http://www.google.com">Go to Google </a> <br>
    <font color = "#AA2FF">This is colorful text</font>
    <br>
    <img src="img/math.png">
  </body>
</html>
```

代码的输出将类似于以下图像：

![插入图像](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_11.jpg)

# CSS

如果您想要使您的网页美观，您必须了解 CSS。CSS 是一种语言，允许您描述您的网页，为文本着色，更改文本的字体，并修改网页的布局。

CSS 语法有两个部分：

+   选择器

+   装饰器

在继续学习 CSS 之前，您需要介绍自己使用 HTML 标签：

```js
<style>

</style>
```

此标签应保留在`<head></head>`标签之间。因此，代码的结构将如下所示：

```js
<html>
  <head>
    <title>
    </title>
    <style>
      // your codes will be typed here
    </style>
  </head>
  <body>
  </body>
</html>
```

CSS 代码将被写在`<style></style>`标签之间。

要格式化文本，您需要记住用于文本的标签。假设您在 HTML 文档的正文中使用`<h1></h1>`标签中有一段文本，如下所示：

```js
<h1> This is an example of HTML text. </h1>
```

要应用 CSS，您需要在`<style> </style>`标签之间输入以下内容：

```js
<html>
  <head>
    <title>
    </title>
    <style>
      h1 {
      color:green;
      text-decoration: underline;
      text-align: center;
      }
    </style>
  </head>
  <body>
    <h1>This is an example of HTML text </h1>
  </body>
</html>
```

代码的输出将如下所示：

![CSS](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_12.jpg)

仔细看代码。我们在`<h1></h1>`标签中的文本中使用了以下 CSS：

```js
      h1 {
      color:green;
      text-decoration: underline;
      text-align: center;
      }
```

在这里，我们使用了一些 CSS 语法（`color`，`text-decoration`等）。还有许多 CSS 语法，也称为属性（每个属性可能包含多个值）。

# HTML 页面上的 JavaScript

您已经学会了如何在控制台上使用 JavaScript 打印内容。在 HTML 页面上怎么样？在这之前，让我们介绍一个 HTML 标签，`<script></script>`。我们的 JavaScript 代码将在这些标签之间。

由于有很多脚本语言，我们需要在这些标签之间定义我们正在使用的语言类型。因此，我们输入以下内容：

```js
<script type = "text/javascript">
  // Our JavaScript Codes will be here. 
</script>
```

让我们看一个例子。在上一章中，您学会了如何在控制台上使用 JavaScript 进行基本操作。现在，我们将在 HTML 页面的`<script></script>`标签之间执行一些操作。仔细看以下代码：

```js
<html>
  <head>
    <title>
      JavaScript Example
    </title>
  </head>
  <body>
    <script type="text/javascript">
      var x = 34;
      var y = 93;
      var sum = x+y;
      document.write("The sum of "+x+" and "+y+" is "+sum);
    </script>
  </body>
</html>
```

代码的输出将如下所示：

![HTML 页面上的 JavaScript](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_03_13.jpg)

我希望你能自己猜出代码的输出。

# 摘要

在本章中，您学会了 HTML，CSS 及其语法和用法。我们还介绍了如何在 HTML 文档中实现 JavaScript。现在，您可以构建自己的网页，并使用 JavaScript 使其更加美妙。我建议您不要跳过本章的任何部分，以便更好地理解下一章，第四章，*深入了解*。


# 第四章：深入了解

在我们迄今学到的大多数 JavaScript 程序中，代码行是按照它们在程序中出现的顺序执行的。每行代码只执行一次。因此，代码不包括测试条件是否为真或假，或者我们没有执行任何逻辑语句。

在本章中，您将学习一些逻辑编程。您将学习以下主题：

+   循环

+   if 语句

+   开关情况

您已经知道如何在 HTML 文档中嵌入 JavaScript 代码。在开始本章之前，您将学习一些 HTML 标签和 JavaScript 方法。这些方法和标签将在整本书中使用。

### 注意

在面向对象编程中，我们不直接对对象外部的数据执行任何操作；我们通过传递一个或多个参数来要求对象执行操作。这个任务被称为对象的方法。

# JavaScript 方法

在之前的章节中，您学会了如何使用`document.write()`打印内容。现在，您将学到更多内容。

我们将在控制台和 HTML 文档上检查这些方法，如下所示：

+   使用 JavaScript 显示警报或弹出框，我们使用以下方法：

```js
alert("Hello World");
```

在控制台上输入以下内容并按*Enter*，您将看到一个弹出框显示**Hello World**：

![JavaScript 方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_04_01.jpg)

您可以编写代码在 HTML 文档中显示类似以下内容的弹出框：

```js
<html>
  <head>
    <title>Alert</title>
  </head>
  <body>
    <script type="text/javascript">
      alert("Hello World");

    </script>
  </body>
</html>
```

输出将如下所示：

![JavaScript 方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_04_02.jpg)

+   如果您想从用户那里获取信息，您需要使用提示框来做到这一点。例如考虑以下内容：

+   您想要输入用户名并在主网页上打印它。

+   您可以使用`window.prompt()`方法来实现这一点。

+   `window.prompt()`的结构与以下内容类似：

```js
window.prompt("What is your name?"); // You can type anything between the inverted commas.
```

+   现在，您需要将信息存储在一个变量中。您已经从之前的章节中知道如何做到这一点。输入以下内容并按*Enter*：

```js
var name = window.prompt("what is your name?");
```

+   在控制台上运行此代码后，您将被要求在文本框中输入一些内容。输入信息后，您需要按**OK**按钮。您的信息现在存储在`name`变量中：![JavaScript 方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_04_03.jpg)

+   如果您想在网页上打印变量，您可以使用`document.write();`方法，如下所示：

```js
document.write("Hello "+name+"!");
```

+   这些步骤的输出如下截图所示：![JavaScript 方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_04_04.jpg)

+   HTML 文档中的代码如下所示：

```js
<html>
  <head>
    <title>Prompt</title>
  </head>
  <body>
    <script type="text/javascript">
      var name = window.prompt("What is your name?");
      document.write("Hello "+name+"!"); 
    </script>
  </body>
</html>
```

# HTML 按钮和表单

在上一章中，您学习了一些 HTML 标签。现在，我们将学习一些标签，这些标签将使学习 HTML 更有趣。

## 按钮

如果您想在 HTML 网页上添加按钮，您可以使用`<button></button>`标签。标签的结构如下所示：

```js
<button type="button">Click Here </button>
```

如果您想让按钮执行某些操作，例如打开一个 URL，您可以考虑以下代码：

```js
<a href="http://google.com/"><button type="button">Click Me </button> </a>
```

代码的输出如下：

![按钮](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_04_05.jpg)

## 形式

在 HTML 中，我们使用表单来表示包含交互控件以向 Web 服务器提交信息的文档部分。HTML 表单的基本结构如下所示：

```js
<form>
  User ID: <input type = "text"><br>
  Password: <input type ="password"><br>
</form>
```

代码的输出将如下所示：

![表单](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_04_06.jpg)

现在让我们深入一点！

# if 语句

假设约翰有 23 个苹果，汤姆有 45 个苹果。我们想要使用 JavaScript 编程来检查谁有更多的苹果。我们需要让我们的浏览器理解**if 语句**。

### 注意

if 语句比较两个变量。

要检查我们的条件，我们需要声明包含苹果数量的两个变量，如下所示：

```js
var john = 23;
var tom = 45;
```

要检查哪个数字更大，我们可以应用如下所示的 if 语句：

```js
if(john > tom)
{
  alert("John has more apples than tom");
}
```

假设我们不知道哪个变量更大。然后，我们需要检查这两个变量。因此，我们需要将以下代码包含到我们的程序中：

```js
if(tom > john )
{
  alert("Tom has more apples than John");
}
```

在 HTML 页面中的整个代码如下：

```js
<html>
  <head>
    <title>
      If statement
    </title>
  </head>
  <body>
    <script type="text/javascript">
      var john = 23;
      var tom = 45;
      if(john > tom){
        alert("John has more apples than Tom");
      }
    if(tom> john ){
      alert("Tom has more apples than John");
    }
    </script>
  </body>
</html>
```

输出将如下所示：

![If 语句](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_04_07.jpg)

您在前几章中学习了条件运算符。在 if 语句中，您可以使用所有这些条件运算符。以下是一些带有注释的示例：

```js
If(tom => john){
//This will check if the number of apples are equal or greater. 
}
If(tom <= john)
{
//This will check if the number of apples are equal or less. 
}
If(tom == john)
{
//This will check if the number of apples are equal. 
}
```

要检查多个条件，您需要使用 OR（`||`）或 AND（`&&`）。

考虑以下示例：

```js
If(john == 23 || john => tom)
{
/* This will check if John has 23 apples or the number of John's apple is equal to or greater than Tom's. This condition will be full filled if any of these two conditions are true. 
*/
}
If(tom == 23 && john <= tom)
{
/* This will check if Tom has 23 apples or the number of john's apple is less than Tom's or equal. This condition will be full filled if both of these two conditions are true. 
*/
}
```

# Switch-case

如果您有三个以上的条件，最好使用**switch-case**语句。switch-case 的基本结构如下所示：

```js
switch (expression) {
  case expression1:
    break;
  case expression2:
    break;
  case expression3:
    break;
//-------------------------------
//-------------------------------
//  More case
//-------------------------------
//  -------------------------------
  default:    
}
```

每个`case`都有一个`break`。但是，`default`不需要`break`。

假设汤姆有 35 支笔。他的朋友约翰、辛迪、劳拉和特里分别有 25、35、15 和 18 支笔。现在，约翰想要检查谁有 35 支笔。我们需要将汤姆的笔数与每个人的笔数进行比较。我们可以使用 switch-case 来处理这种情况。代码将如下所示：

```js
<html>
  <head>
    <title>
      Switch-Case
    </title>
  </head>
  <body>
    <script type="text/javascript">
      var Tom = 35;
      switch (Tom) {
        case 25: //Number of John's pens
          document.write("John has equal number of pens as Tom");
        break;
        case 35: //Number of Cindy's pens
          document.write("Cindy has equal number of pens as Tom");
        break;
        case 15: //Number of Laura's pens
          document.write("Laura has equal number of pens as Tom");
        break;
        case 18: //Number of Terry's pens
          document.write("Terry has equal number of pens as Tom");
        break; 
        default:
          document.write("No one has equal pens as Tom");
      }
    </script>
  </body>
</html>
```

输出将如下所示：

![Switch-case](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_04_08.jpg)

### 注意

现在，将第二个案例（`35`）的值更改为其他，并检查您的结果。

## 练习

1.  假设您每天都需要上学，除了星期六和星期天。编写一个代码，您将输入今天的日期数字，网页将向您显示是否需要去上学。（提示：使用 switch case。）

1.  假设您有一个花园，您在月份的偶数天给所有植物浇水。编写一个代码，它将向您显示您是否需要在那一天给植物浇水。（提示：使用 if 条件和模运算符（`%`）。）

# 循环

在本段中，我们将学习一个有趣的东西，称为**循环**。

假设您需要使用 JavaScript 打印一行 100 次。您会怎么做？

您可以在程序中多次输入`document.write("我想让您写的行");`，也可以使用循环。

循环的基本用法是多次执行某些操作。比如，您需要打印*1 + 2 + 4 + 6 +…………+100*系列的所有整数，直到 100。计算是相同的，您只需要多次执行。在这些情况下，我们使用循环。

我们将讨论两种类型的循环，即**for 循环**和**while 循环**。

## for 循环

for 循环的基本结构如下：

```js
for(starting ; condition ; increment/decrement)
{
  statement
}
```

`starting`参数是您循环的初始化。您需要初始化循环以启动它。`condition`参数是控制循环的关键元素。`increment/decrement`参数定义了您的循环如何增加/减少。

让我们看一个例子。您想要打印**javascript 很有趣**10 次。代码将如下所示：

```js
<html>
  <head>
    <title>For Loop</title>
  </head>
  <body>
  <script type="text/javascript">
    var java; 
    for(java=0;java<10;java++){
      document.write("javascript is fun"+"<br>");
    }
  </script>
  </body>
</html>
```

输出将类似于以下内容：

![for 循环](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_04_09.jpg)

是的！您打印了 10 次该行。如果您仔细查看代码，您将看到以下内容：

+   我们声明了一个名为`java`的变量

+   在`for`循环中，我们将`0`初始化为其值

+   我们添加了一个`java<10`的条件，使浏览器从`0`计数到`10`

+   我们通过`1`递增变量；这就是为什么我们添加了`java++`

### 练习

1.  使用 JavaScript 编写一个代码，将打印以下输出：

```js
I have 2 apples.
I have 4 apples.
I have 6 apples.
I have 8 apples.
I have 10 apples.
I have 12 apples.
I have 14 apples.
I have 16 apples.
I have 18 apples.
I have 20 apples.
```

1.  编写一个代码，打印从 2 到 500 的所有偶数。

## while 循环

您已经学会了如何使用 for 循环多次执行某些操作。现在，我们将学习另一个称为 while 循环的循环。while 循环的结构如下：

```js
initialize;
while(condition){
  statement; 
  increment/decrement; 
}
```

前面示例的代码将如下所示：

```js
<html>
  <head>
    <title>For Loop</title>
  </head>
  <body>
    <script type="text/javascript">
      var java = 0;
      while(java < 10){
        document.write("javascript is fun"+"<br>");
        java++;
      }
    </script>
  </body>
</html>
```

输出将与`for`循环相同。

### 练习

1.  编写一个代码，使用 while 循环打印从 1 到 600 的所有奇数值。（提示：使用模运算符。）

1.  编写一个代码，将打印以下输出：

```js
5 x 1  = 5
5 x 2  = 10
5 x 3  = 15
5 x 4  = 20
5 x 5  = 25
5 x 6  = 30
5 x 7  = 35
5 x 8  = 40
5 x 9  = 45
5 x 10 = 50
```

# 总结

在本章中，您学习了使用 JavaScript 的逻辑操作。您学习了循环、条件操作和其他 HTML 标签。

我们需要专注于这一章，因为我们在这里讨论了 JavaScript 中最重要的属性。如果你练习了这一章和前三章，你就可以成为 JavaScript 大师。我建议你在没有掌握这四章所有知识之前不要继续往下学习。如果你已经学习了我们之前讨论的所有主题，让我们继续第五章，“啊哟！航行进入战斗”。


# 第五章：啊呵！驶向战斗

在本章中，我们将使用 HTML、CSS 和 JavaScript 开发一个完整的游戏。我们将专注于 JavaScript 编码，因此，我们不会关心游戏的图形。我们将编写一个名为**战舰**的游戏。你们中的许多人以前听说过它。这是一个记忆游戏。你的想象力和直觉将帮助你赢得游戏。有几种不同的玩法。

让我们讨论一下游戏的外观。有一些相互连接的正方形几何物体，如下所示。行数和列数需要相等：

![啊呵！驶向战斗](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_05_01.jpg)

行和列通常用数字系统或字母来命名。假设行是 1，2，3，4，5，6，7，8，9 和 10。列是 A，B，C，D，E，F，G，H，I 和 J。我们可以用数字或字母来命名它们：

![啊呵！驶向战斗](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_05_02.jpg)

这是一个双人游戏。以下是它的规则：

+   两名玩家将秘密地在他们的矩阵/网格上放置他们的船只（可以是不同类型的船只或水上交通工具）。

+   玩家可以将他们的船只放置在垂直或水平位置；但不能对角线放置。

+   玩家必须在开始游戏之前将所有船只放在网格上。

+   他们的船只不能重叠。

+   当所有船只都放置好后，玩家就不能再移动他们的船只了。

+   放置所有船只后，第一个玩家将说明第二个玩家的坐标，如果有属于第二个玩家的船只，那艘船将被击中。

+   然后，第二个玩家将说明第一个玩家的坐标。如果有属于第一个玩家的船只，它将被击中。

+   坐标可能类似于**A2**、**B2**、**D5**等。第一个字母将是网格的*x*轴，数字将代表网格的*y*轴。

+   击沉对手的所有船只的玩家将获胜。

以下图显示了网格上放置的一些船只：

![啊呵！驶向战斗](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_05_03.jpg)

现在，我们将进入游戏的编程部分。

我们将遵循以下规则，以便我们的游戏不会变得难以编码：

1.  每个玩家将拥有一艘船只。

1.  船只将占据网格的四个部分。

1.  玩家将不得不在提示框中输入*x*和*y*轴坐标。

1.  网格将是 9 x 9。

1.  玩家将不得不为船只的水平或垂直位置放置`h`或`v`。

1.  为了简化绘图，我们将在网格的位置上放置点（**.**）。网格将类似于以下图像：![啊呵！驶向战斗](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_05_04.jpg)

1.  我们将需要一个**Fire**按钮来开始游戏。

# HTML 部分

HTML 部分将类似于以下代码：

```js
<html>
  <head>
  </head>
  <body>
    <h1> Battleship Game </h1>
  </body>
  <style>
// We will code in CSS here
  </style>
  <script type = "text/javascript">
//We will code in JavaScript here
  </script>
</html>
```

代码的输出将如下图所示：

![HTML 部分](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_05_05.jpg)

# CSS 部分

我们在`<style></style>`标签中使用 CSS 编码来设置 body。由于我们只关注 JavaScript 编码，我们不会关心游戏的视觉部分。为了使游戏的主体色彩丰富多彩，我们将使用以下代码：

```js
  <style>
    body { 
      background-color: #eff; 
    }
  </style>
```

# JavaScript 部分

这部分是我们游戏的主要部分，我们将最关注这部分。我们将在`<script></script>`标签中编写所有的代码。

对于网格，我们将需要一个二维数组。我们将使用一个`game`变量来存储数据，如下所示：

### 注意

许多程序可能需要处理具有共同特征的多个数据项。在这种情况下，将数据项放在数组中通常是方便的，它们将共享相同的名称。个别数据可以是字符、浮点数、整数等。但是，它们必须是相同的类型和类。

```js
var game = [    [".", ".", ".", ".", ".", ".", ".", ".", "."],
                [".", ".", ".", ".", ".", ".", ".", ".", "."],
                [".", ".", ".", ".", ".", ".", ".", ".", "."],
                [".", ".", ".", ".", ".", ".", ".", ".", "."],
                [".", ".", ".", ".", ".", ".", ".", ".", "."],
                [".", ".", ".", ".", ".", ".", ".", ".", "."],
                [".", ".", ".", ".", ".", ".", ".", ".", "."],
                [".", ".", ".", ".", ".", ".", ".", ".", "."],
                [".", ".", ".", ".", ".", ".", ".", ".", "."],
           ];
```

我们将使用一个变量来在 HTML 页面上显示二维数组：

```js
var board = document.createElement("PRE");
```

现在我们将这个添加到 body 并创建一个按钮：

```js
document.body.appendChild(board);
var button=document.createElement("BUTTON");
```

这个按钮将调用`fire`函数（我们稍后会编写这个函数）：

```js
button.onclick = fire;
```

现在，我们将在 body 部分放置按钮：

```js
var t=document.createTextNode("Fire!");
  document.body.appendChild(button);
  button.appendChild(t);
```

让我们创建一个绘制棋盘的函数：

```js
  function drawBoard() {
    var boardContents = "";
    var i;
    var j;
    for (i=0; i<9; i++) {
      for (j=0; j<9; j++) {
        boardContents = boardContents + game[i][j]+" ";
        // Append array contents for each board square
      }
      boardContents = boardContents + "<br>";
      // Append a line break at the end of each horizontal line
    }
    return boardContents;
    // Return string representing board in HTML
  }
```

现在，通过编写以下代码在 HTML 页面上绘制棋盘：

```js
board.innerHTML = drawBoard();
```

我们将使用`prompt()`函数询问玩家他想把船放在哪里：

```js
var x=prompt("Where would you like to place your ship? Enter an X coordinate: (0-8)");
  var y=prompt("Where would you like to place your ship? Enter a Y coordinate: (0-8)");
  var direction=prompt("Place (h)orizontally, (v)ertically");
  x = Number(x);  // Convert the string returned by "prompt" into a number
  y = Number(y);  // Convert the string returned by "prompt" into a number
```

如果玩家选择他们的船的水平方向，我们需要用以下代码替换点：

```js
if (direction[0] == "h") {
  var c;
  for (c = x; c < (x + 4); c++)
  {
    game[y][c] = '#';
  }
}
```

如果玩家选择他们的船的垂直方向，我们需要用以下代码替换点：

```js
if (direction[0] == "v") {
  var c;
  for (c = y; c < (y + 4); c++)
  {
    game[c][x] = '#';
  }
}
```

放置船后，我们需要重新绘制棋盘，如下所示：

```js
  board.innerHTML = drawBoard();
```

让我们创建`fire()`函数。

我们的`fire()`函数将如下所示：

```js
function fire() {
//We will write codes here.
}
```

当调用`fire()`函数时，我们需要从玩家那里获取输入，如下所示：

```js
  var fireX=prompt("Where would you like to fire? Enter an X coordinate: (0-8)");
  var fireY=prompt("Where would you like to fire? Enter a Y coordinate: (0-8)");
```

将输入转换为数字，如下所示：

```js
  fireX = Number(fireX);
  // Convert the string returned by "prompt" into a number
  fireY = Number(fireY);
  //  Convert the string returned by "prompt" into a number
```

如果输入与`#`字符不匹配，我们将使用以下代码打印`You Missed.`：

```js
  if (game[fireY][fireX] == ".") {
    // Check if the specified coordinate is occupied by the cruiser
    alert("You Missed.");
  }
```

如果输入命中了船，我们将打印一些消息并重新绘制棋盘：

```js
  else if (game[fireY][fireX] == "*") {
    alert("You already hit the ship there.");
  } else {
    alert("Kaboom! You hit a ship");
    game[fireY][fireX] = "*";
    board.innerHTML = drawBoard();
    // Redraw board with hit marker at specified coordinate
  }
```

现在，我们需要检查棋盘上是否还有船。我们将使用以下代码：

```js
  var shipfound;
  var i;
  var j;
  // Check if there are any ships remaining on the board
  for (i=0; i<9; i++) {
    for (j=0; j<9; j++) {
      if (game[i][j] != "." && game[i][j] != "*") {
        shipfound = true;
        // Taking a boolean data type to set it if a ship is found
      }
    }
  }
```

如果没有船剩下，我们将结束游戏：

```js
if (!shipfound) {
  // If no ships are found end the game
  alert("All ships have been sunk. Well done Captain! Game over");
  document.body.removeChild(button);
  // Remove the fire button from the page after game over
}
```

# 最终代码

我们的最终代码将类似于以下内容：

```js
<html>
  <head>
  </head>
  <body>
    <h1> Battleship Game </h1>
  </body>
  <style>
  body {
    background-color: #eff;
  }
  </style>
  <script>
    var game = [  [".", ".", ".", ".", ".", ".", ".", ".", "."],
                  [".", ".", ".", ".", ".", ".", ".", ".", "."],
                  [".", ".", ".", ".", ".", ".", ".", ".", "."],
                  [".", ".", ".", ".", ".", ".", ".", ".", "."],
                  [".", ".", ".", ".", ".", ".", ".", ".", "."],
                  [".", ".", ".", ".", ".", ".", ".", ".", "."],
                  [".", ".", ".", ".", ".", ".", ".", ".", "."],
                  [".", ".", ".", ".", ".", ".", ".", ".", "."],
                  [".", ".", ".", ".", ".", ".", ".", ".", "."],
               ];
    var board = document.createElement("PRE");
    // preparing the HTML <pre> element to display the board on the page
    document.body.appendChild(board);
    var button=document.createElement("BUTTON");
    // Preparing the "Fire! button to allow the player to fire at the ship
    button.onclick = fire;       // Clicking the button calls the fire() function
    var t=document.createTextNode("Fire!");
    document.body.appendChild(button);
    button.appendChild(t);
    function drawBoard() {
      var boardContents = "";
      var i;  var j;
      for (i=0; i<9; i++) {
        for (j=0; j<9; j++) {
          boardContents = boardContents + game[i][j]+" ";
          // Append array contents for each board square
        }
        boardContents = boardContents + "<br>";
        // Append a line break at the end of each horizontal line
      }  return boardContents;
      // Return string representing board in HTML
    }
    board.innerHTML = drawBoard();
    // Display the board on the page using the above function
    var x=prompt("Where would you like to place your cruiser? Enter an X coordinate: (0-8)");
    var y=prompt("Where would you like to place your cruiser? Enter a Y coordinate: (0-8)");
    var direction=prompt("Place (h)orizontally, (v)ertically");
    x = Number(x);  // Convert the string returned by "prompt" into a number
    y = Number(y);  // Convert the string returned by "prompt" into a number
    if (direction[0] == "h") {
      var c;
      for (c = x; c < (x + 4); c++)
      {
        game[y][c] = '4';
      }
    }
    // Draw cruiser vertically
    if (direction[0] == "v") {
      var c;
      for (c = y; c < (y + 4); c++)
      {
        game[c][x] = '4';
      }
    }
    board.innerHTML = drawBoard(); // Redraw board with cruiser added
    // Function for firing a shot when the "Fire! button is pressed
    function fire() {
      var fireX=prompt("Where would you like to fire? Enter an X coordinate: (0-8)");
      var fireY=prompt("Where would you like to fire? Enter a Y coordinate: (0-8)");
      fireX = Number(fireX);
      // Convert the string returned by "prompt" into a number
      fireY = Number(fireY);
      //  Convert the string returned by "prompt" into a number
      if (game[fireY][fireX] == ".") {
        // Check if the specified coordinate is occupied by the cruiser
        alert("Missed.");
      }
      else if (game[fireY][fireX] == "*") {
        alert("You already hit the ship there.");
      } else {
        alert("Kaboom! You hit a ship");
        game[fireY][fireX] = "*";
        board.innerHTML = drawBoard();
        // Redraw board with hit marker at specified coordinate
      } 
      var shipfound;  
      var i;  
      var j;
      // Check if there are any ships remaining on the board
      for (i=0; i<9; i++) {
        for (j=0; j<9; j++) {
          if (game[i][j] != "." && game[i][j] != "*") {
            shipfound = true;
            // Set to true if a ship is found
          }
        }
      }if (!shipfound) {
        // If no ships are found end the game
        alert("All ships have been sunk. Well done Captain! Game over");
        document.body.removeChild(button);
        // Remove the fire button from the page after game over
      }
    }
  </script>
</html>
```

如果您运行上述代码，您将看到以下提示：

![最终代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_05_06.jpg)

让我们玩我们创建的游戏。第一个玩家必须放置他的船。他必须输入船的坐标。

假设我们在*x*轴上输入`3`，在*y*轴上输入`2`。将我们的船放在垂直方向。游戏屏幕将如下所示：

![最终代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_05_07.jpg)

您可以看到您的船已经放好了。现在，您可以通过按下**Fire**按钮来射击对手（计算机）。您将被要求输入您想要射击的网格的坐标。如果您没有命中，您将看到我们编写的消息**You Missed.**

我希望您能玩您建立的游戏。

恭喜！

如果您想进一步开发您的游戏（例如增强图形，船只数量等），您只需要开发 CSS 和 JavaScript。

现在，我们将看到战舰游戏的更好代码，如下所示：

1.  在您的计算机的任何位置创建一个`js`文件夹。

1.  在`js`文件夹中，放置本章中包含的三个文件：`battleship.js`，`functions.js`和`jquery.min.js`。

1.  在`js`文件夹外，放置`battleship.css`和`index.html`文件。

在记事本中打开`index.html`文件，您将看到以下代码：

```js
<html>
  <head>
    <title>Battleship</title>
    <meta name="viewport" content="width=device-width" />
    <link href="battleship.css" rel="stylesheet" type="text/css"/>
  </head>
  <body>
    <h1>BATTLESHIP</h1>
    <div class="game-types">
      <h2 class='game-choice'>Choose a game type</h2>
      <dl class="game-description">
        <dt>Standard</dt>
        <dd>Classic Battleship with randomly placed ships</dd>
        <dt>Custom</dt>
        <dd>Choose any 5 ships and place them where you like. The computer will have the same 5 ships, randomly placed</dd>
      </dl>
      <div class='button-wrapper'>
        <button class="standard">Standard</button>
        <button class="custom">Custom</button>
      </div>
    </div>
    <div class='ship-picker'>
      <h2>Pick 5 Ships</h2>
      <h3>Selected ships</h3>
      <ul class="ship-list">
        <li>
          <p></p>
          <div class='remove'>X</div>
        </li>
        <li>
          <p></p>
          <div class='remove'>X</div>
        </li>
        <li>
          <p></p>
          <div class='remove'>X</div>
        </li>
        <li>
          <p></p>
          <div class='remove'>X</div>
        </li>
        <li>
          <p></p>
          <div class='remove'>X</div>
        </li>
      </ul>
      <ul class='ship-choices button-wrapper'>
        <li class="ship-choice">Carrier</li>
        <li class="ship-choice">Battleship</li>
        <li class="ship-choice">Submarine</li>
        <li class="ship-choice">Cruiser</li>
        <li class="ship-choice">Destroyer</li>
      </ul>
      <div class='button-wrapper'>
        <button class='build-fleet inactive'>Build Fleet</button>
      </div>
    </div>
    <div class="ship-placer">
      <div class="board placer-board">
        <div class="labels">
          <div class="row-label">
          </div>
          <div class="column-label">
          </div>
        </div>
        <div class="playable-area">
        </div>
      </div>
      <div class='ships-to-place'>
        <h3>Ships to place</h3>
        <ul>
        </ul>
      </div>

      <div class="clear"></div>
      <div class="instructions">
        <p>Use 'WASD' keys to rotate pieces</p>
      </div>

      <div class='button-wrapper'>
        <button class="start inactive">Start game</button>
      </div>
    </div>
    <div class="game-area">
      <div class="board-wrap">
        <h1 class="hidden">BATTLESHIP</h1>
        <div class="single-board-wrap">
          <div class="board human-board">
            <div class="labels">
              <div class="row-label">
              </div>
              <div class="column-label">
              </div>
            </div>
            <div class="playable-area">
            </div>
          </div>
          <h2>Human Board</h2>
        </div>
        <div class="single-board-wrap">
          <div class="board ai-board">
            <div class="labels">
              <div class="row-label">
              </div>
              <div class="column-label">
              </div>
            </div>
            <div class="playable-area">
            </div>
          </div>
          <h2>Opponent Board</h2>
        </div>
        <div class="button-wrapper">
          <button class="new-game">New Game</button>
          <button class="stats hidden">Show Stats</button>
        </div>
      </div>
      <div class="info-area">
        <h2>Enemy ships remaining</h2>
        <div class="scoreboard">
          <div class="ships-left">
          </div>
        </div>
        <div class="gamelog-container">
          <h2>GAME LOG</h2>
        </div>
      </div>
    </div>
    <script src="img/jquery.min.js"></script>
    <script src="img/functions.js"></script>
    <script src="img/battleship.js"></script>
  </body>
</html>
```

我们在 HTML 文件中包含了三个 JavaScript 文件。我们添加了一个 jQuery 文件，我们将在下一章中讨论。上述代码的输出将显示以下屏幕：

![最终代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_05_08.jpg)

您可以点击**标准**按钮来玩标准战场，或者点击**自定义**按钮来玩非标准战场。

如果您选择**标准**按钮，您将看到以下屏幕：

![最终代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_05_09.jpg)

现在，您可以猜测对手的船的位置并点击网格。屏幕右侧将有一个日志面板。您还可以从游戏日志面板的前面面板中看到您摧毁了多少艘船以及哪些船。

如果您选择**自定义**游戏，您将看到以下屏幕：

![最终代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/js-pj-kid/img/B04720_05_10.jpg)

添加完五艘船后，您可以玩游戏。如果需要，您可以多次添加相同的船只。

您可以将您的船垂直或水平放置，并点击瓷砖来击中对手的船。您一次只能点击一个瓷砖。

# 摘要

在本章中，我们构建了一个完整的游戏并进行了游戏。我们还玩了一个我们构建的游戏的更好版本。你需要记住的是，你必须了解我们之前讨论的所有代码背后的逻辑。本章附有更好版本游戏的源代码。我希望你能学习这些代码并编写自己的战舰游戏。在我们改进的战舰游戏中，我们使用了`jquery.js` JavaScript 文件。`jquery.js`文件有很多行代码（我们将在第六章中讨论这个问题，*探索 jQuery 的好处*）。

如果你掌握了本章讨论的所有代码，我们现在可以转到下一章。
