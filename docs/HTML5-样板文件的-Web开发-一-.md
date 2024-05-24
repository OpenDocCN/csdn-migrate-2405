# HTML5 样板文件的 Web开发（一）

> 原文：[`zh.annas-archive.org/md5/8C583EAEFA986CBF606CD0A7F72F11BE`](https://zh.annas-archive.org/md5/8C583EAEFA986CBF606CD0A7F72F11BE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

*使用 HTML5 Boilerplate 入门*将使您能够轻松掌握设置新项目并以最有效的方式将其部署到生产环境的方法，同时确保强大的性能。它将带您逐步创建网站，并教您充分利用 HTML5 Boilerplate 中提供的默认设置，无论是样式、标记还是代码，以便您尽可能少地解决跨浏览器问题来实现您的目标。

# 本书涵盖了什么内容

*第一章, 在我们开始之前*，涵盖了您需要为项目设置 HTML5 Boilerplate 而不费吹灰之力的一切。我们还广泛地研究了作为该项目一部分包含的文件以及它们如何帮助您。

*第二章, 开始您的项目*，涵盖了如何使用示例单页面网站开始使用 HTML5 Boilerplate。在本章中，我们将研究配置默认设置的基本要点，这些设置适用于您的项目。

*第三章，创建您的网站*，涵盖了如何自定义网站的样式和标记，以及如何利用 HTML5 Boilerplate 的默认样式选项的一些技巧。

*第四章, 添加交互性和完成您的网站*，将帮助您发现如何进行特性检测，使用 JavaScript 添加一些交互性，并完成您的网站实现。

*第五章, 自定义服务器*，介绍了如何通过使用 HTML5 Boilerplate 为托管您的网站的 Web 服务器定制配置，以确保您的网站尽快加载。

*第六章, 让您的网站更好*，探讨了可以用来为您的网站用户提供更好体验的可选功能，这些功能与 HTML5 Boilerplate 非常匹配。

*第七章, 使用构建脚本自动部署*，通过查看提供工具来压缩 CSS、JS、HTML 和图像的构建脚本，帮助您使您的网站准备好上线。

*附录*，您是专家，现在怎么办？涵盖了一些单元测试的基础知识，并提供了有关 HTML5 Boilerplate 提供的功能决策的额外研究信息。

# 您需要为本书做好准备

由于我们将在网站上工作，我们将需要以下基本工具来完成我们的工作：

+   一个您习惯使用的文本编辑器；推荐使用**SublimeText**。如果您还没有，请从[sublimetext.com/](http://sublimetext.com/)下载。

+   Apache Web 服务器（可从[httpd.apache.org](http://httpd.apache.org)获取）以应用 HTML5 Boilerplate 的服务器配置。

+   一个浏览器来验证您的网站在屏幕上的渲染。推荐使用 Chrome，因为它的开发者工具可用于调试。从[google.com/chrome](http://google.com/chrome)下载 Chrome。

+   Git，用于确保软件处于版本控制下；从[git-scm.com](http://git-scm.com)下载。

+   您显然还需要 HTML5 Boilerplate，您可以从[html5boilerplate.com](http://html5boilerplate.com)下载。

# 本书适合谁

这本书是为所有熟悉使用 HTML、CSS 和 JavaScript 创建 Web 项目的作者而写的。不需要深入的知识。了解 Web 服务器是什么以及如何配置是有好处的。此外，您不应该害怕使用命令行工具（不要害怕！书中有链接可以帮助您减少恐惧）。我们不指望您了解 HTML5 Boilerplate，只是让您尝试一次，看看它是否适合您。

# 约定

在这本书中，您会发现许多不同类型信息的文本样式。以下是一些样式的示例，以及它们的含义解释。

文本中的代码单词显示如下：“但是，`Normalize.css`确保这些默认样式在所有浏览器中保持一致。”

代码块设置如下： 

```js
header h1 {
background-image: url('/img/heading-banner.png');
width: 800px;
height: 300px;
}
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“以下屏幕截图显示了当用户将键盘焦点切换到“跳过导航”链接时，它是如何立即可见的。”

### 注意

警告或重要提示出现在这样的框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：在我们开始之前

当您开始一个新项目时，您会有多么高兴？我也是！新项目文件夹的气味非常令人兴奋。不幸的是，它很快就变成了一堆文件夹，子文件夹和匆忙编写的标记，然后你就知道了，这是发布日，你恐惧地意识到你的页面缺少一些基本的元数据（嗯，那些网站图标！），一些部分在某些浏览器中无法阅读——什么？打印时也需要好看？

HTML5 Boilerplate 的诞生是因为从头开始并错过了重要部分而感到沮丧。拥有一个清单并不像从一个已经带有您的清单所需文件的项目开始那么有用。

HTML5 Boilerplate 为您提供了最好的工具，让您可以开始下一个 Web 开发项目。

# HTML5 Boilerplate 的特点

在我们深入了解 HTML5 Boilerplate 的内部之前，让我们看看它的一些特点，这些特点将帮助您在下一个项目中使用。HTML5 Boilerplate 可以从`html5boilerplate.com`下载，并且根据 MIT 许可证可用于任何免费或商业产品。源代码可以在 Github 的 URL 上找到，即`github.com/h5bp/html5-boilerplate/`。

## 跨浏览器兼容性

HTML5 Boilerplate 带有一组文件，可以轻松进行跨浏览器开发。

### 文档类型

跨浏览器兼容性最重要的原因是使用不正确的文档类型声明。通过使用 HTML5 文档类型声明，您可以确保浏览器以标准模式呈现您的网站。

### 注意

如果您对文档类型有兴趣，我在`nimbupani.com/the-truth-about-doctypes.html`上详细介绍了它。

### Normalize.css

浏览器会在您未指定属性的元素上应用它们的默认样式。问题是，每个浏览器应用的样式是不同的。但是，`Normalize.css`确保这些默认样式在所有浏览器中保持一致。

### 注意

Nicolas Gallagher 在`necolas.github.com/normalize.css/`上详细介绍了`Normalize.css`背后的动机。

### 清除浮动

Clearfix 一直是清除浮动的一种流行方式。在 HTML5 Boilerplate 中，这已经简化为使用微清除解决方案，这是一组更小的选择器，可以实现相同的目标，并经过测试和验证，可以在 Opera 9 及更高版本，Safari 4 及更高版本，IE6 及更高版本，Firefox 3.5 及更高版本以及 Chrome 上使用。

### 注意

微清除解决方案的发明者 Nicolas Gallagher 在`nicolasgallagher.com/micro-clearfix-hack/`上更详细地介绍了使用的声明背后的选择。

### 搜索框样式

当您将输入元素的类型设置为搜索时，所有 WebKit 浏览器（如 Safari，Chrome，Mobile Safari，以及即将推出的）都会添加难以样式化的 UI chrome。HTML5 Boilerplate 带有一组样式，可以使搜索框在所有浏览器中的外观和感觉保持一致，同时也很容易进行样式设置。

### 条件类

`index.html`页面带有一组类，可以在 HTML 元素上轻松调整样式，以适应低于 9 的 IE 版本。

### Modernizr

Modernizr 是一个 JavaScript 库，用于测试 HTML5 技术的存在，并根据加载您网站的浏览器中的存在或不存在输出一组类。例如，如果浏览器不支持边框半径，Modernizr 会输出类`no-borderradius`，而在支持边框半径的浏览器上，它将输出类`borderradius`。Boilerplate 中包含了 Modernizr 的自定义构建。

### 注意

从[`modernizr.com/docs/`](http://modernizr.com/docs/)和[`www.slideshare.net/michaelenslow/its-a-mod-world-a-practical-guide-to-rocking-modernizr`](http://www.slideshare.net/michaelenslow/its-a-mod-world-a-practical-guide-to-rocking-modernizr)的幻灯片中了解有关使用 Modernizr 的更多信息。

### 没有 console.log 错误

在现代浏览器中工作时，通常会使用`console.log`函数来调试 JavaScript 代码。有多少次你忘记在生产中删除或注释掉它们，结果发现它们在不支持该函数使用的 Internet Explorer 或其他浏览器中抛出错误？你可以安全地使用`plugin.js`文件中包含的`log`函数，只在支持它的浏览器中记录语句。

### 辅助类

曾经需要隐藏文本来显示图片吗？如何为使用屏幕阅读器的人提供额外的文本或在所有浏览器中隐藏？HTML5 Boilerplate 提供了这两种情况的类，经过实地测试，可以在各种情况和所有浏览器中使用。

## 性能优化

`.htaccess`文件包含了最佳的缓存默认设置，这使得当页面由 Apache Web 服务器提供时，页面加载速度显著加快。还有其他 Web 服务器的配置文件可提供类似的功能。

## 渐进增强

HTML 元素有一个`no-js`类，可以用于为不支持 JavaScript 的浏览器提供替代样式。使用 Modernizr 时，当在支持 JavaScript 的浏览器中使用时，这个类名会被替换为`js`。

## 可访问的焦点样式

所有浏览器在点击链接时都会提供默认的焦点样式。HTML5 Boilerplate 确保这些样式仅在使用键盘导航时元素处于焦点状态时应用。

## 打印样式

一个良好的默认打印样式是我们在创建网页时经常忽略的东西。然而，HTML5 Boilerplate 已经为您提供了最佳性能的默认打印样式。

# 开始使用的工具

你可以使用你喜欢的编辑器开始使用 Boilerplate。如果你使用 Git 作为你的版本控制系统，我们还包括一个`.gitignore`文件，它会自动忽略文件，如`.DS_STORE`或其他不必要的文件，不会被标记为版本。可以用来处理 HTML5 Boilerplate 的一些编辑器如下：

+   Aptana Studio：HTML5 Boilerplate 可以直接在 Aptana Studio 中使用。选择一个 Web 项目，然后选择 Boilerplate 开始使用。Robert Gravelle 在[www.htmlgoodies.com/html5/tutorials/aptana-studio-3-guided-tour-and-tutorial-create-a-web-project-using-the-html-5-boilerplate-framework.html](http://www.htmlgoodies.com/html5/tutorials/aptana-studio-3-guided-tour-and-tutorial-create-a-web-project-using-the-html-5-boilerplate-framework.html)上有一篇文章，解释了如何在 Aptana Studio 项目中使用 HTML5 Boilerplate。

+   Visual Studio：在 Visual Studio 2010 中有两个可用的模板。一个是用于 Web 表单的，可以从`h5bpwebapptemplate.codeplex.com/`下载，另一个可以从[www.jondavis.net/techblog/post/2011/04/24/HTML5-Boilerplate-Visual-Studio-2010-Template.aspx](http://www.jondavis.net/techblog/post/2011/04/24/HTML5-Boilerplate-Visual-Studio-2010-Template.aspx)下载。

+   TextMate：这个 URL 托管了 HTML5 Boilerplate 的标记和样式的 TextMate 捆绑包，[www.dontcom.com/post/1546820479/html5-boilerplate-textmate-template-bundles](http://www.dontcom.com/post/1546820479/html5-boilerplate-textmate-template-bundles)。

## 注意

这些工具并非由 HTML5 Boilerplate 项目官方维护，因此可能已经过时。最好使用下一节中概述的流程。

# 获取文件的位置

有三种获取 HTML5 Boilerplate 的方法，如下：

+   从网站上：项目的最新稳定版本可在`html5boilerplate.com`上获得。

+   来自 Initializr：Jonathan Verecchia 在`initializr.com`上托管了一个更广泛的模块选择。这里的所有模块都来自该网站上可用的稳定版本。

+   从 Github 主页：HTML5 Boilerplate 托管在 Github 上。最新文件可从项目的 github 页面`github.com/h5bp/html5-boilerplate`获取。您可以放心地在启动新项目时使用这些文件，并且在从 Github 下载时保证获得这些文件的最新版本。

由于您刚刚开始使用 HTML5 Boilerplate，我强烈建议您从 Github 下载文件，甚至更好地通过 Git 这样做，这样当 Github 上的主文件更新时，您可以轻松更新它们。

### 注意

如果您对 Git 不熟悉，Roger Dudler 在 rogerdudler.github.com/git-guide/上维护了一个很好的入门介绍；如果您对版本控制的概念不熟悉，可以在`hoth.entp.com/output/git_for_designers.html`上找到一个很好的解释。

# H5BP 文件概述

HTML5 Boilerplate 的不同文件和文件夹解释如下：

+   `index.html`：这是我们建议您使用的所有 HTML 页面的标记。

+   `main.css`：样式位于名为`main.css`的单个样式表中，位于`css`文件夹中。

+   `normalize.css`：此文件位于单独位置，以便您可以立即使用最新更新的`normalize.css`版本。在生产中，理想情况下，您应将`main.css`和`normalize.css`合并为单个文件，以确保网络请求的最小数量，从而使您的页面加载更快。

+   `doc`：此文件夹包含了理解 HTML5 Boilerplate 文件所需的所有文档。

+   `img`：此文件夹应包含您将用于创建网站的所有图像。一开始是空的，但您应该在这里包含您使用的所有图像。

+   `js`：这是所有脚本的父文件夹。HTML5 Boilerplate 附带了一组脚本，使您更容易入门。此文件夹包含以下文件和文件夹：

+   `vendor`：此文件夹包含所有脚本库。您可以获取最新的压缩和未压缩版本的 jQuery 以及现代化的自定义版本。您将使用的任何其他库理想情况下都应放在此文件夹中。

+   `plugins.js`：您将使用的所有 jQuery 插件都应内联在此文件中。如果您使用了 jQuery 轮播插件，您将把代码复制到`plugins.js`中。

+   `main.js`：这将是您调用在页面上运行的脚本的文件。以 jQuery 轮播插件为例，我们将从此文件中调用插件在我们的页面上运行。

+   `404.html`：如果您有一个找不到的页面，那么可以提供此页面。确保它包含所有可用的信息，并且与网站中的其他页面具有相同的外观和感觉。

+   `humans.txt`：这是一个很棒的倡议，允许您指明谁在网站上工作（在 humanstxt.org 上阅读更多关于此倡议的信息）。我们强烈建议您使用此功能来指示您的工作，并告知任何好奇的人，这是谁的工作。

+   `crossdomain.xml`：如果您希望将 Flash 文件托管在其他地方以访问位于您的网站将托管的域上的资产，则此文件非常有用。您可以使用另一个域中的 Flash 音频播放器来使用托管在您的网站上的文件。在这种情况下，您需要仔细选择您的跨域策略（我们将在第五章中详细介绍此文件，*自定义服务器*）。

+   `robots.txt`：搜索引擎使用此文件来了解哪些文件要索引，哪些不要索引。

+   `.htaccess`：这是特定于您的网站的 Apache 服务器配置文件。默认情况下包含了大量最佳实践。

+   `favicion.ico`：大多数浏览器在您收藏网站上的页面或在标签上的页面标题旁边时使用网站图标。通过使用一个独特的可识别的图标，您将能够使您的网站脱颖而出，并且易于导航到。

+   `apple-touch-icon-*.png`：iOS 和 Android 设备允许将网站添加到手机主屏幕的书签。它们都使用这些触摸图标来表示您的网站。Boilerplate 附带了一组图标，以识别您需要创建图标的所有尺寸和格式。

+   `readme.md`：readme 包含了所有的许可信息，以及关于使用这些文件的功能和获取更多信息的列表。

# 寻求帮助

现在我们已经知道这些文件是什么，以及从哪里获取它们，重要的是您要熟悉如何寻求帮助，最重要的是在哪里寻求帮助。请记住，大多数 HTML5 Boilerplate 项目的维护者都是在业余时间工作。您在明确表达需要帮助的内容方面花费的时间越多，他们就能越快、越好地帮助您。以下是如何寻求帮助：

+   隔离问题：确切的问题是什么？使用 dabblet.com、codepen.io、jsfiddle.net 或 jsbin.com 创建一个最少标记、样式和脚本的测试案例来重现问题。大多数情况下，这样做本身就会让您找到问题所在。

+   如果您能够重现这个问题并将其隔离为 HTML5 Boilerplate 功能引起的问题，请转到`github.com/h5bp/html5boilerplate.com/issues`，使用搜索字段检查是否已经报告过。如果没有，请创建一个新问题，并附上测试案例的链接。

+   如果这个问题不是 HTML5 Boilerplate 的结果，而是您无法确定的交互作用，请转到`stackoverflow.com/questions/tagged/html5boilerplate`，创建一个链接到隔离测试案例的问题。确保将问题标记为 html5boilerplate 或 h5bp，这样维护者中的一个就可以迅速回答。

+   如果问题小到可以在 Twitter 上提问，请在[`twitter.com/h5bp`](https://twitter.com/h5bp)上发推文，附上测试案例的链接以及您需要帮助的具体部分。

### 注意

Lea Verou 在`coding.smashingmagazine.com/2011/09/07/help-the-community-report-browser-bugs/`上写了一篇关于提交浏览器错误报告的好文章，同样适用于寻求任何开源网页开发项目的帮助。

# 总结

在这一章中，我们已经了解了为什么 HTML5 Boilerplate 是网页开发者的绝佳工具箱。此外，我们已经了解了哪些功能对您的网页开发项目最有用，以及 HTML5 Boilerplate 中的每个文件都做了什么。我们还花了一些时间看看从哪里获取 HTML5 Boilerplate 的文件以及如何寻求帮助。在下一章中，我们将开始使用 HTML5 Boilerplate 进行一个示例项目。


# 第二章：开始你的项目

你希望尽快开始你的项目，并在本章中我们将看到一些使用 HTML5 Boilerplate 的最快方法。

有许多种 HTML5 Boilerplate 可供选择，我们将研究一些创建起始文件夹的机制，并查看一旦开始后你可以处理的即时任务。

# 创建你的初始项目文件夹

HTML5 Boilerplate 可以从网站上以三个版本获得，就像我们在上一章中看到的那样。以下是使用最新文件的两种最快方法：

+   下载 HTML5 Boilerplate 的最新版本，用于你开始的每个新项目

+   维护 HTML5 Boilerplate 的本地最新副本，并使用脚本将文件复制到你的项目中

现在我们将看看这两种方式。

## 下载 HTML5 Boilerplate 的最新版本

这是使用 HTML5 Boilerplate 最新文件的最简单方法。如果你熟悉 Git，你可以将 HTML5 Boilerplate 下载为一个文件夹。在你的命令行界面中，导航到你通常存储项目的文件夹，然后在命令行界面中输入以下命令：

```js
git clone git://github.com/h5bp/html5-boilerplate.git

```

这将在该文件夹中下载一个名为`html5-boilerplate`的文件夹。然后你可以将其重命名为你自己的项目并开始使用。

如果你不熟悉命令行界面，你可以将最新文件下载为 ZIP 文件并解压到一个你想要使用的项目的文件夹中。

如果你觉得这些选项很繁琐，我建议你使用 shell 脚本。但是，这需要你已经设置好 Git 并熟悉命令行界面。

### 注意

如果你使用 Windows，请确保下载**Cygwin**，网址为`sources.redhat.com/cygwin/cygwin-ug-net/cygwin-ug-net.html`，并在输入我提到的所有命令行时使用它。

在`nathanj.github.com/gitguide/tour.html`上还有一个关于在 Windows 上设置和使用 Git 的图解指南。

## 使用 shell 脚本

使用这个脚本，我们将为 HTML5 Boilerplate 设置一个本地存储库，以便随着项目中的更改进行更新。

前往你想要存储最新 HTML5 Boilerplate 文件副本的文件夹。在我的情况下，我想将它保存在一个名为`source`的文件夹中。

然后，使用前一节中提到的相同命令行脚本来下载文件的最新副本。脚本如下：

```js
git clone git://github.com/h5bp/html5-boilerplate.git

```

我们将让这个文件夹保持原样，而不是重命名文件夹。接下来，我们将把`createproject.sh` shell 脚本复制到这个文件夹中。

在你的 shell 中，导航到`html5 Boilerplate`文件夹，并按照以下命令行脚本中所示下载`createproject.sh`文件：

```js
curl https://raw.github.com/h5bp/ant-build-script/master/createproject.sh > createproject.sh

```

确保它是可执行的，通过在 shell 中执行以下命令：

```js
chmod +x createproject.sh

```

这些命令行脚本的执行如下截图所示：

![使用 shell 脚本](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_02_01.jpg)

然后从命令行执行以下脚本：

```js
./createproject.sh <project-name>

```

这将在`html5-boilerplate`文件夹的父文件夹中创建一个以项目名称命名的文件夹。如果你希望将项目文件放在其他地方，你也可以使用项目文件夹的绝对路径，如下面的脚本所示：

```js
./createproject.sh /Users/divya/projects/<project-name>

```

# 创建我们的项目

在本书中，我们将通过一个示例项目来理解如何使用 HTML5 Boilerplate。我们所有的项目源文件都可以在`nimbu.in/h5bp-book/sun-shine-festival-2012/`上找到。

假设我们需要为塞内加尔达喀尔的 Ngor 和 Terou Bi 举办的一个虚构的阳光和沙滩节创建一个网站，时间是 2012 年 11 月 12 日至 2012 年 11 月 16 日。我想将这个项目标记为`sun-sand-festival-2012`。

我将所有项目存储在一个`projects`文件夹中，所有框架和起始工具包存储在一个`source`文件夹中。

在我的源文件夹中，我有最初使用以下脚本创建的`html5-boilerplate`文件夹：

```js
git clone git://github.com/h5bp/html5-boilerplate.git

```

我通过使用以下脚本定期从 Github 托管的主存储库中拉取最新更改来保持其最新：

```js
git pull origin master

```

我还在同一个文件夹中有`createproject.sh` shell 脚本，我们将用它来创建我们的新项目。在 shell 界面中，我导航到`html5-boilerplate`文件夹并输入以下脚本：

```js
./createproject.sh ../projects/sun-sand-festival-2012

```

这将创建包含所有所需文件的项目文件夹，以便开始。创建的文件如下截图所示：

![创建我们的项目](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_02_02.jpg)

# House-keeping

现在我们的项目准备好了，让我们开始做一些基本的工作，这是我们在任何项目中都需要做的。在任何你习惯使用的文本编辑器中打开项目。

### 提示

我强烈推荐跨平台的**Sublime Text**文本编辑器，可从[www.sublimetext.com](http://www.sublimetext.com)下载。命令行大师可能想尝试使用**Vim**文本编辑器，可从[www.vim.org](http://www.vim.org)下载。

## 设置标签

我们的`index.html`页面包含一些需要填写的标签：

```js
<title></title>
<meta name="description" content="">
```

对于我们项目的标题标签，让我们输入以下内容：

```js
<title>Home | Sun and Sand Festival 2012, Dakar</title>
```

带有`name`描述的`meta`标签在网站在搜索引擎结果中列出时非常有用。此标签将用于呈现解释此页面内容的文本片段。让我们将其设置为以下内容：

```js
<meta name="description" content="Sun and Sand Festival is occurring between Nov 12 to Nov 16 2012 at the Ngor and Terou Bi, Dakar featuring performances by top Senegal artists">
```

## 编辑网站图标

添加网站图标是我们大多数人在开始项目时忘记做的下一个琐事。这是你可以在开始思考你将要创建的代码之前轻松达成的下一个目标。

网站图标有助于唯一标识您的网站。如下截图所示，拥有一个网站图标可以轻松识别您想要访问的标签或书签：

![编辑网站图标](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_02_03.jpg)

当你的页面被添加到 iOS 的主屏幕（如右侧的截图所示）和 Android 设备（如左侧的截图所示）时，触摸图标非常有用：

![编辑网站图标](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_02_04.jpg)

HTML5 Boilerplate 在根文件夹中附带了一组图标，这些图标的尺寸适合触摸屏图标（Android 和 iOS 设备都使用）和网站图标的所有所需图标。在制作图标时，您可以将它们用作指南。

HTML5 Boilerplate 附带以下一组图标：

+   **favicon.ico**：桌面浏览器用于在标签上或标题旁渲染图标的默认图标。

+   **apple-touch-icon.png**：如果没有指定其他内容，iOS 将使用此图标在主屏幕上呈现。不幸的是，这也意味着 iOS 将在此图标上添加自己的效果，如阴影、圆角和反射光。如果没有其他支持，这也是一个很好的后备图标格式，例如 iOS 1 和 BlackBerry OS 6。

+   **apple-touch-icon-precomposed.png**：这可以防止 iOS 在你的图标上应用任何效果，并使其呈现原样。提供此图标还将确保 Android 2.1 及以上设备在将你的网页添加到主屏幕时使用此图标。

+   **apple-touch-icon-57x57-precomposed.png**：这将被没有 Retina 显示屏的 iOS 设备使用。

+   **apple-touch-icon-72x72-precomposed.png**：这将被没有高分辨率显示屏的 iPad 使用。

+   **apple-touch-icons-114x114-precomposed.png**：这将被高分辨率的 iPhone Retina 显示屏使用。

+   **apple-touch-icons-144x144-precomposed.png**：这将被高分辨率的 iPad Retina 显示屏使用。

为什么我们有这么多图标的原因已经由 Mathias Bynens 在[`mathiasbynens.be/notes/touch-icons`](http://mathiasbynens.be/notes/touch-icons)中记录。

### 注意

Hans Christian Reinl 在 `drublic.de/blog/html5-boilerplate-favicons-psd-template/` 上托管了所有图标的 `PSD` 模板，你可以使用它来开始为你的项目创建图标。如果你需要关于如何创建这些图标的指导，Jon Hicks 在 [www.netmagazine.com/features/create-perfect-favicon](http://www.netmagazine.com/features/create-perfect-favicon) 上写了关于如何做的文章。

如果你有必要创建图标的图形元素，你可以开始将这些图标添加到项目的根文件夹中。当截止日期临近时，你很可能会忘记这样做。

对于我们的阳光和沙滩节例子，我们已经收集了关键的图形元素，下面的截图显示了从 `PSD` 模板生成的图标：

![编辑网站图标](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_02_05.jpg)

## 添加第三方库

如果你已经有一个将要使用的库列表，你可以开始将它们添加到文件夹中。

HTML5 Boilerplate 自带最新稳定版本的 jQuery，所以你已经有了。如果你想使用其他库，比如 jQuery UI，你可以将它们复制到 `libs` 文件夹中。

假设你想在项目中使用 jQuery UI，在 [www.jqueryui.com](http://www.jqueryui.com) 上可用，那么将最新版本的 jQuery UI 复制到 `libs` 文件夹中，然后在 `index.html` 标记的底部使用 `script` 标签引用它。

### 使用内容传送网络

通过使用**内容传送网络**（**CDN**），我们可以减少在我们的网络服务器上提供的资源数量，并通过引用由谷歌或微软普遍托管的资源，更有可能文件会被缓存，因为用户访问的许多其他网站也会引用这个特定的资源。

如果你仔细观察，你会注意到链接到 jQuery 的脚本的源与我们的 jQuery UI 源不同。这有两个原因，这两个原因在以下部分中有解释。

#### 协议相对 URL

通常，大多数链接到网络上资源的 URL 以 `http://` 开头。然而，有时页面托管在使用加密通信的服务器上。因此，你的页面将使用 `https://` 而不是典型的 `http://`。然而，由于你的脚本源仍然使用 `http://` 协议，IE 将向你的页面访问者抛出一个令人讨厌的对话框，询问以下问题：

![协议相对 URL](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_02_06.jpg)

你绝对不希望你的访问者因此而恐慌。所以，最简单的方法是完全删除 URL 中的协议（`http:`）部分，如下所示：

```js
//ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js

```

这样，浏览器将使用页面所使用的任何协议进行请求。你可以在附录部分了解更多关于协议相对 URL 的信息。

当然，这意味着如果你在本地测试，并且在浏览器上查看你的页面，浏览器将使用类似 `file://users/divya/projects` 的 URL，因此浏览器将尝试使用以下 URL 查找 jQuery 文件：

```js
file://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js

```

这个请求肯定会失败，因为在该路径下没有本地资源。因此，如果你使用协议相对 URL，你需要设置一个本地服务器来测试你的文件。在 Mac 或基于 Unix 的操作系统上，通过在你的 shell 界面中导航到项目文件夹并执行以下命令来轻松完成这个操作：

```js
python -m SimpleHTTPServer

```

这将启动一个服务器，你的项目的 `index.html` 文件将在 `http://localhost:8000` 上可用。

### 提示

如果你使用的是 Windows，将 Mongoose 可执行文件（写作时的最新版本是 `mongoose-3.3.exe`）从 `code.google.com/p/mongoose/` 复制到你的项目文件夹并启动它。然后你的项目的 `index.html` 将在 `http://localhost:8080` 上可用。

#### 谷歌 CDN 托管

Google 托管了许多流行的 JavaScript 库。在`code.google.com/apis/libraries/devguide.html`上可以找到托管在 Google 的 CDN 上的所有库的列表。

我们也可以利用 Google 的 CDN 来托管 jQuery UI，因为它也托管在上面。让我们通过将脚本文件的来源从`js/libs/jqueryui-jquery-ui-1.8.17.min.js`更改为以下内容来将其转换为使用 Google 的 CDN：

```js
//ajax.googleapis.com/ajax/libs/jqueryui/1.8.16/jquery-ui.min.js

```

但等等！让我们看看在 HTML5 Boilerplate 中如何引用 jQuery CDN。如下代码片段所示：

```js
<script src="img/jquery.min.js"></script>
<script>window.jQuery || document.write('<script src="img/jquery-1.8.2.min.js"><\/script>')
</script>
```

您是否注意到我们还引用了 jQuery 文件的本地副本？我们这样做只是为了在 Google 的 CDN 失败时仍然有本地副本可用。尽管这种情况并不经常发生，但在发生时有一个备用方案是很有用的。

`window.jQuery || document.write(…)` 这个语句有两个作用。具体如下：

+   检查 jQuery 对象是否存在：如果存在，这意味着 Google 的 CDN 起作用了。如果存在，就什么也不做。

+   如果`window.jQuery`对象不存在：这意味着 Google 的 CDN 失败了；它会立即呈现一个带有对项目`libs`文件夹中 jQuery 副本的引用的`script`标签。这告诉浏览器立即请求该资源。

我们可以对 jQuery UI 做类似的操作。

所有的 jQuery 插件都是 jQuery 对象内的对象。因此，我们只需要验证插件对象是否存在，如果不存在，就使用以下代码片段加载`libs`文件夹中的插件副本：

```js
<script>window.jQuery.ui || document.write('<script src="img/jqueryui-jquery-ui-1.8.17.min.js"><\/script>')
</script>
```

因此，我们引用 jQuery UI 的完整脚本文件如下所示：

```js
<script src="img/jquery-ui.min.js "></script>
<script>window.jQuery.ui || document.write('<script src="img/jqueryui-jquery-ui-1.8.16.custom.min.js"><\/script>')
</script>
```

### 注意

还有其他托管库的 CDN。`cdnjs.com`网址托管了许多 JavaScript 库。微软也在其 CDN 上托管了一些库；列表可在[www.asp.net/ajaxlibrary/cdn.ashx](http://www.asp.net/ajaxlibrary/cdn.ashx)上找到。

## 添加 Google Analytics ID

这是另一个在截止日期到来时被遗忘的小动作。HTML5 Boilerplate 已经为您提供了准备好的代码片段。您只需要包含您网站的唯一标识符即可。

请注意，HTML5 Boilerplate 将代码片段包含在页面的页脚中，这意味着指标只有在页面加载后才会发送。然而，有一些人认为分析应该在页面加载之前就发生，以衡量在页面加载完成之前离开页面的人数。如果您想这样做，您应该将分析代码片段移到`index.html`页面的`</head>`标签的正上方。

## 更新`humans.txt`

`humans.txt`公布了在网站上工作的人员。任何人都可以简单地访问`example.com/humanx.txt`立即知道在该网站上工作的人员的姓名。将您和您团队成员的姓名添加到 HTML5 Boilerplate 中的`humans.txt`文件中。

对于我们的阳光和沙滩节的示例，以下截图显示了我们的`humans.txt`的外观：

![更新 humans.txt](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_02_07.jpg)

# 总结

在本章中，我们看了如何使用 HTML5 Boilerplate 开始项目以及我们新项目中应该采取的第一步。在此过程中，我们了解了协议相对 URL 和链接到托管在 CDN 上的库。我们更新了`humans.txt`文件和要在项目中使用的图标。到目前为止，我们对示例项目所做的所有更改都可以在`nimbu.in/h5bp-book/chapter-2/`上找到。在下一章中，我们将看看为我们的项目编写一些代码。


# 第三章：创建您的网站

现在我们已经完成了关于我们项目的所有基本工作，让我们来看看构建这个网站的实际任务。我们将首先从标记开始，然后转入样式表，最后添加脚本交互性。

# 在标记上工作

我们对 Sun and Sand 音乐节项目有一个简单的设计构想。设计如下截图所示：

![在标记上工作](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_03_01.jpg)

从组织结构上看，页面的总体结构如下所述：

+   **页眉**：带有一组导航链接的横幅标志

+   **主要内容**：页面的主要部分，其中包含导航链接将链接到的部分

+   **左列**：这包含了主要内容

+   **右列**：这包含了对观众可能有趣但不是必要的次要信息

+   **页脚**：赞助商标志和带有音乐的音频播放器，这些音乐将参加音乐节

## 创建标记

**HTML5 Doctor**在`html5doctor.com/element-index/`上列出了您可以在网页中使用的所有元素。将其与我们之前制作的列表进行比较，看起来`header`标记很适合放置我们的标志和导航链接，而赞助商标志和音频播放器可以放在`footer`标记中。这就留下了我们的主要内容；看起来带有主要角色的`div`标记是最适合它的！

以下是我们最终得到的标记。第二章中的`index.html`页面，*开始您的项目*，也包含以下代码：

```js
<header>
  <a href="#main">Skip Navigation</a>

  <h1>Sun &amp; Sand Festival 2012</h1>
  <h2>Ngor&amp; Terou Bi, Dakar</h2>
  <nav class="site-nav">
  <a href="#tickets">Tickets</a>
  <ahref="#about">About</a>
  <a href="#line-up">Line-up</a>
  <a href="#contact">Contact</a>
  <a href="#gettinghere">Getting Here</a>
  </nav>
</header>
<div role="main">
  <section id="primary">
    <article id="tickets">

    </article>
    <article id="about">
    </article>
    <article id="lineup">

    </article>
    <article id="contact">

    </article>
    <article id="gettinghere">
    </article>
  </section>

  <aside id="secondary">
    <article>
      <h2>Get some sun!</h2>
      <ul>
      <li>Follow us on <a href="http://twitter.com/sunnsand">twitter</a>!</li>
      <li>Stalk us on <a href="http://facebook.com">facebook</a>!</li>
      <li>Get some sun through <a href="http://flickr.com/photos/sunnsand">flickr</a>!</li>
      </ul>
    </article>
  </aside>
</div>
<footer>
    <article class="sponsors">
    <a href="#">Boca-Cola</a>
    <a href="#">Darbucks</a>
    <a href="#">Kugle</a>
    <a href="#">Pling</a>
    </article>
    <audio src="img/audio.webm" controls></audio>
</footer>
```

### 提示

您可以从您在[`www.PacktPub.com`](http://www.PacktPu)购买的所有 Packt 图书的帐户中下载示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.PacktPub.com/support`](http://www.PacktPub.com/su)并注册，文件将直接通过电子邮件发送给您。

### 决定使用哪个元素

使用 HTML5，我们有大量元素可供选择，这可能会导致一些人选择困难。如果您的文档结构中有任何明显适合任何新元素的地方，请标记它们。如果没有，请继续使用`div`或任何其他明显适合的元素。

在我们的代码中，当我们有结构上不同的主要内容时，我们使用`section`元素，当我们有类似但重复的内容部分时，我们使用`article`元素。您对这些选择的看法可能会有所不同；在这种情况下，我建议您选择您感到舒适的内容。

如果您想了解更多关于新的 HTML5 元素的信息，我建议您查看*HTML5: Up & Running, Mark Pilgrim, O'Reilly*中关于语义的章节，该书由 Google Press 印刷，在`diveintohtml5.info/semantics.html`上可以找到。

### 编写有效的标记

编写有效的标记可以确保您的页面在所有呈现它的浏览器中表现一致。有效的标记是指符合浏览器遵循的 Web 标准的标记。这样，您将防止任何不可预测的行为。

编写有效的标记的最简单方法是使用可以在保存文件时立即验证的工具。

在第二章中，*开始您的项目*，我建议在 Web 开发中使用 Sublime Text 和 Vim。这两种工具都有内联验证，您可以使用它们来编写有效的标记。此外，这些工具还提供标签和元素的自动完成，使编写有效的标记变得微不足道。

如果您无法访问这些工具，我建议使用`validator.w3.org/`来验证您的标记。

对于您来说，自动化这些工具非常重要，以确保将您网站上的任何问题减少到最低限度。

# 创建样式

现在我们已经准备好了标记，让我们看看应该如何进行样式设置。HTML5 样板带有最佳默认样式的样式表。如果您打开`main.css`，您会在`Chrome 框架提示`样式规则和`辅助类`部分之间找到以下部分：

![创建样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_03_02.jpg)

这就是我们将撰写样式规则的地方。稍后，我们将看看如何使用**Sass** ([`sass-lang.com`](http://sass-lang.com))或**Less** ([`lesscss.org/`](http://lesscss.org/))来使用一些样式框架，以便更轻松地编写样式。

即使不写一行 CSS 代码，您会注意到我们的页面看起来就像以下截图中显示的网站：

![创建样式](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_03_03.jpg)

这个默认样式要归功于 HTML5 样板中可用的规范化样式规则。

## 为什么不使用 reset.css？

很长一段时间以来，建议使用`reset.css`，它可以在`html5doctor.com/html-5-reset-stylesheet/`上找到，并将每个可用元素的边距和填充重置为`0`，并使所有标题的字体大小与正文文本相同，而没有更高的字体重量。

HTML5 样板建议不要这样做。浏览器提供有用的浏览器默认值，这将使您的样式表更小，因为您不必重新声明这些样式。

使用`normalize.css`，您将不会在调试工具中看到以下类型的混乱：

![为什么不使用 reset.css？](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_03_04.jpg)

`normalize.css`的联合创始人之一 Nicolas Gallagher 在[nicolasgallagher.com/about-normalize-css/](http://www.w3.org/community/webed/wiki/Inheritance_and_cascade#Specificity)上详细介绍了为什么它比`reset.css`更好，对于那些仍然不确定 CSS 规范化的优点的人来说，这是一篇很好的文章。

## 我们可以使用的有用样式类

在第一章*开始之前*中，我们简要地看到 HTML5 样板带有一堆默认类，这些类对工作很有用。您可能已经注意到我们在样式规则中使用了其中一些类。

我们所有的辅助类都是最后定义的，因此当使用时它们可以覆盖所有其他样式。确保它们覆盖的属性在其他地方没有过度指定；您可以在[www.w3.org/community/webed/wiki/Inheritance_and_cascade#Specificity](http://www.w3.org/community/webed/wiki/Inheritance_and_cascade#Specificity)上阅读更多关于特异性的信息。

### 图像替换

在我们的项目中，我们希望为`Sun & Sand Festival 2012`标题添加一个时髦的徽标。HTML5 样板有一个方便的图像替换类可用于此目的。在标记中，我们只需向`h1`标签添加一个名为`ir`的类，如下面的代码所示：

```js
<h1 class="ir">Sun &amp; Sand Festival 2012</h1>
```

这样做的作用是将 HTML5 样板中图像替换类（`ir`）中指定的样式应用于隐藏文本。然后，您只需要向`h1`元素添加背景图像以及其宽度和高度，以便按照您的规范显示，如以下代码所示：

```js
header h1 {
background-image: url('/img/heading-banner.png');
width: 800px;
height: 300px;
}
```

这将导致标题看起来类似于以下截图：

![图像替换](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_03_05.jpg)

### 隐藏元素

我们的标记中有内容，我们希望只有在用户点击时才显示。在我们的网站中，当用户点击**到这里**链接时，我们希望显示一个 Google 地图。通过使用`iframe`，这样做非常简单，如下面的代码片段所示：

```js
<iframe width="425" height="350" frameborder="0" scrolling="no" marginheight="0" marginwidth="0" src="img/maps?f=q&amp;source=s_q&amp;hl=en&amp;geocode=&amp;q=ngor+terrou+bi,+dakar,+senegal&amp;aq=&amp;sll=37.0625,-95.677068&amp;sspn=90.404249,95.976562&amp;ie=UTF8&amp;hq=ngor&amp;hnear=Terrou-Bi,+Bd+Martin+Luther+King,+Gueule+Tapee,+Dakar+Region,+Guediawaye,+Dakar+221,+Senegal&amp;t=m&amp;fll=14.751996,-17.513559&amp;fspn=0.014276,0.011716&amp;st=109146043351405611748&amp;rq=1&amp;ev=p&amp;split=1&amp;ll=14.711109,-17.483921&amp;spn=0.014276,0.011716&amp;output=embed">
</iframe>
```

但这意味着，一旦您的页面在浏览器中加载，浏览器将立即尝试显示地图并从 Google 地图获取资源。但我们只希望在用户点击**到这里**链接时才显示这张地图。HTML5 样板提供了一个可以用于此类目的的类名。我们将应用一个名为`hidden`的类，以确保这些元素在明确设置为显示之前不会呈现。`hidden`类在以下代码片段中使用：

```js
<iframe class="hidden" width="425" height="350" frameborder="0" scrolling="no" marginheight="0" marginwidth="0" src="img/maps?f=q&amp;source=s_q&amp;hl=en&amp;geocode=&amp;q=ngor+terrou+bi,+dakar,+senegal&amp;aq=&amp;sll=37.0625,-95.677068&amp;sspn=90.404249,95.976562&amp;ie=UTF8&amp;hq=ngor&amp;hnear=Terrou-Bi,+Bd+Martin+Luther+King,+Gueule+Tapee,+Dakar+Region,+Guediawaye,+Dakar+221,+Senegal&amp;t=m&amp;fll=14.751996,-17.513559&amp;fspn=0.014276,0.011716&amp;st=109146043351405611748&amp;rq=1&amp;ev=p&amp;split=1&amp;ll=14.711109,-17.483921&amp;spn=0.014276,0.011716&amp;output=embed">
</iframe>
```

请注意，这会使内容从屏幕阅读器和浏览器显示中消失。

### 注意

屏幕阅读器是用于帮助那些无法在屏幕上查看文本的人阅读网页的设备。Victor Tsaran 在[www.yuiblog.com/blog/2007/05/14/video-intro-to-screenreaders/](http://www.yuiblog.com/blog/2007/05/14/video-intro-to-screenreaders/)上有一个关于屏幕阅读器的很好的介绍视频。

使这种情况发生的规则如下：

```js
.hidden {
display: none !important;
visibility: hidden;
}
```

这确保了所有屏幕阅读器（**JAWS**和**Windows-Eyes**是最流行的）都会隐藏所有具有此类名称的元素。

如果您希望内容对使用屏幕阅读器的用户可用，您应该使用我们将要学习的`visuallyhidden`类。

### 在不影响布局的情况下隐藏元素

有时，您不希望将某些内容呈现到屏幕上，但希望使用**跳转导航**链接使其对屏幕阅读器可用。这将确保那些使用屏幕阅读器的人可以立即跳转到内容的重点，而不必听一长串导航链接。因此，让我们将这个类添加到我们在页眉中的**跳转导航**链接中，如下面的代码所示：

```js
<a class="visuallyhidden" href="#main">Skip Navigation</a>
```

这使得链接从我们的屏幕上消失，但对于屏幕阅读器是可用的。下面的网页截图不显示**跳转导航**链接：

![在视觉上隐藏元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_03_07.jpg)

使这种情况发生的 CSS 规则如下：

```js
.visuallyhidden {
border: 0;
clip: rect(0 000);
height: 1px;
margin: -1px;
overflow: hidden;
padding: 0;
position: absolute;
width: 1px;
}
```

通常使用的解决方案涉及将它们绝对定位，并将高度设置为`0px`，但这会阻止苹果的 VoiceOver 屏幕阅读器读取内容。

另一种解决方案涉及使用`text-indent`属性将文本定位到屏幕之外，但当内容用从右到左的语言书写时，需要小心，这种解决方案会失败。

使用`clip`属性可以避免所有这些问题，同时使内容在所有屏幕阅读器上可读。

### 注意

乔纳森·斯努克在`snook.ca/archives/html_and_css/hiding-content-for-accessibility`上写道，`clip`属性是在视觉上隐藏内容但仍然可供屏幕阅读器使用的最佳方式。

那些广泛使用键盘导航的人也希望跳过导航。但是，因为它在视觉上是隐藏的，他们不会知道这个选项存在。对于这种情况，您希望在此元素获得焦点时可用。让我们添加一个额外的类`focusable`，使我们的**跳转导航**链接在通过键盘导航激活此链接时可见。

```js
<a class="visuallyhidden focusable" href="#main">Skip Navigation</a>
```

下面的截图显示了当用户将键盘焦点切换到**跳转导航**链接时，它会立即可见：

![在视觉上隐藏元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_03_06.jpg)

### 在不影响布局的情况下隐藏元素

在我们的网站上，我们希望在几天内以选项卡形式显示阵容，如下截图所示：

![在不影响布局的情况下隐藏元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_03_08.jpg)

以下是标记的简化视图：

```js
<article class="t-tabs t-section" id="lineup">
<nav class="t-tab__nav">
<a class="t-tab__navitem--active t-tab__navitem" href="#day-1">Day 1</a>
<a class="t-tab__navitem" href="#day-2">Day 2</a>
</nav>
<ul id="day-1" class="t-tab__body t-grid t-before-1-6 t-after-1-6">
<li class="t-grid__cell t-unit-1-2">
<a class="t-media--row" href="#">
<img width="100" height="100" class="t-media__aside t-image--artist" src="img/artist-kidjo.png">
<b class="t-media__body t-title-tabartist t-artist__name">Angelique Kidjo</b>
</a>
</li>
</ul>
<ul id="day-2" class="t-tab__body t-grid t-before-1-6 t-after-1-6">
<li class="t-grid__cell t-unit-1-2">
<a class="t-media--row" href="#">
<img width="100" height="100" class="t-media__aside t-image--artist" src="img/artist-sangre.png">
<b class="t-media__body t-title-tabartist t-artist__name">Oumou Sangre</b>
</a>
</li>
</ul>
</article>
```

最简单的方法是只显示**Day 1**，并使用`hidden`类隐藏其余的天数，如下面的代码片段所示：

```js
<article class="t-tabs t-section" id="lineup">
<nav class="t-tab__nav">
<a class="t-tab__navitem--active t-tab__navitem" href="#day-1">Day 1</a>
<a class="t-tab__navitem" href="#day-2">Day 2</a>
</nav>
<ul id="day-1" class="t-tab__body t-grid t-before-1-6 t-after-1-6">
<!--list content below -->
</ul>
<ul id="day-2" class="t-tab__body t-grid t-before-1-6 t-after-1-6 hidden">
<!--list content below -->

</ul>
</article>
```

通过隐藏元素，我们使其占用的尺寸消失为 0。这意味着以前由该内容占用的区域会坍塌。

当用户点击每天阵容的导航链接时，每天的内容将经常被隐藏和显示，这看起来会很突兀，如下截图所示：

![在不影响布局的情况下隐藏元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_03_09.jpg)

在这种情况下，我们可以使用辅助类`invisible`来使元素不渲染，但保持其尺寸；它在屏幕上不可见，也不可供屏幕阅读器使用。如下截图所示，**TICKETS**部分不会根据哪个选项卡处于活动状态而改变位置：

![在不影响布局的情况下隐藏元素](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_03_10.jpg)

### 清除浮动

我们将图像元素定位在艺术家姓名的左侧。我们通过将图像浮动到左侧来实现这一点。幸运的是，我们没有任何跟随浮动元素的内容。如果有的话，那么该内容将覆盖在浮动元素上。您可以通过在浮动元素的父容器上设置一个名为`clearfix`的类来防止发生这种情况。在我们的情况下，为了确保我们的浮动元素永远不会触发这种行为，我们将在艺术家图像元素的父元素上添加`clearfix`类：

```js
<a class="t-media--row  clearfix" href="#">
```

要了解`clearfix`类的工作原理，请阅读附录中的相关内容，*You Are an Expert, Now What?*

现在我们已经处理了基本要点，让我们将样式应用到页面上，使其看起来更像我们心目中的设计。以下代码片段显示了如何向我们的页面添加样式：

```js
html {
background: url('/img/waves-bg.png') repeat-x, 
url(/img/heading-banner-back.png) 50% 100px no-repeat, 
url(/img/bg-active.png) 50% 72px repeat-x, 
url('/img/bg.png') #e7dcbb;  
box-sizing: border-box;  
margin: 0 1em;
font: 100%/1.5 georgia, serif;
}

body {
max-width: 80%;
margin: 0 auto;
text-align: center;
}

.t-tabs {
min-height: 400px;
position: relative;
}

.t-tab__body {
position: absolute;
left: 0;
right: 0;  
}

.t-tab__navitem--active { 
position: relative;
}

.t-tab__navitem--active::after{
position: absolute;
bottom: -2em;
left: 0;
height: 2em;
width: 100%;
content: "";
border-radius: 0 0 20em 20em;
background: #305da1;
box-shadow: 0 -0.3em 0 0 #77aec3 inset, 0 0.3em 0 0 #1A9DC8;
}

/* TICKETS */
.t-tickets__currency {
font-family: georgia, serif;
text-align: center;
position: absolute;
transform-origin: 100% 100%;
transform: rotate(-90deg) translate(0, -2.1em);
 }

/* MEDIA OBJECT */
.t-media,
.t-media--column,
.t-media--row,
.t-media__body {  
text-align: left;  
list-style: none;
}
.t-media--row .t-media__aside {
float:left; 
margin-right: 16px;
}

/* Image replaced social media links */
.t-links__item--twitter,
.t-links__item--facebook,
.t-links__item--flickr {
padding: 0.25rem 1rem;
display: inline-block;
}

.ir.t-links__item--twitter,
.ir.t-links__item--facebook,
.ir.t-links__item--flickr {
background-size: contain;
background-repeat: no-repeat;
width: 1rem;
height: 1rem;
background-position: center center;
display: inline-block;
}

.ir.t-links__item--twitter {
background-image: url(/img/logo-twitter.svg);
}

.t-title--h1,
.t-title--h2,
.t-title--navsite,
.t-title-tabartist {
font-family: FolkSolidRegular, sans-serif;
text-transform: uppercase;  
color: #E4773A;
text-shadow:  3px 3px 1px #C84134, 
                4px 4px 1px #C84134;  
letter-spacing: 2px;  
}
```

## 编写有效的样式表

当我们浏览时，您可能已经注意到样式中没有任何拼写错误。编辑人员毫无疑问做得很好，但我意识到在编写样式表时您没有这样的助手！一个错误的拼写错误可能会给我们带来无法估量的创伤，因为我们要找出为什么某个特定的样式没有被应用。这就是为什么自动验证样式并尽可能自动完成样式声明也很重要。

Sublime Text 和 Vim 都提供 CSS 属性的自动补全，并且您还可以自动插入分号！如果您无法使用这些工具，您可以使用在线 CSS 验证器`jigsaw.w3.org/css-validator/`来测试您的 CSS。

还有另一种自动编写有效和高效样式规则的方法——使用编译成 CSS 的替代样式语言。接下来我们将研究一些这样的语言。

## 使用样式语言编写高效的样式表

很长一段时间以来，编写样式表的唯一方法是使用 W3C 在其规范中提供的语法。然而，通过使用一些编程逻辑来编写样式表，可以获得许多生产力上的好处。但是浏览器只能理解 W3C 规范规定的语法。这意味着任何使用额外可编程功能的样式语言都应该转换为浏览器可理解的典型样式表（这称为编译）。

最早为此设计的样式语言之一称为 Sass。现在，我们有了一些更多，最流行的是 Sass、Less 和 Stylus。在 Sass 和 Less 中，有效的 CSS 自动成为有效的 Sass 和 Less 代码。这使得从 CSS 转换到这些语言变得微不足道。

通常，您会在名为`main.scss`（如果您使用 Sass）、`main.less`（如果您使用 Less）或`main.styl`（如果您使用 Stylus）的文件中编写样式规则。使用每种语言自带的编译器，这些文件将分别编译为`styles.css`。

### 优点

使用样式语言有许多优点，例如以下：

+   这些语言使您始终可以编写语法有效的样式表，因为如果使用任何无效的语法，它们都会抛出错误。

+   所有这些语言都提供了一些在 CSS 中受欢迎的功能，例如变量、能够在其他类中重复使用样式规则而不必重复多次、算术计算、颜色函数等等。

+   在开发时，您可以选择输出扩展可读的样式，然后在生产中使用时输出紧凑的性能优化、去除空白的样式表。

### 缺点

然而，使用样式语言也有一些缺点，如下所述：

+   虽然很容易转换为 Sass 或 Less，但不可能对生成的样式表进行修改，并将这些更改传输到其原始的 Sass/Less/Style 文件中。因此，您需要小心确保没有人编辑生成的 CSS 文件。

+   团队合作需要整个团队共同使用其中一种语言。如果没有这样做，就不可能维护两个样式表的分支并使它们保持同步。

+   在调试时，如果您正在检查一个元素，大多数调试器只会显示样式表中的行号，而不是原始语言文件中的行号。这可能会使得难以找出在原始文件中特定规则的位置。

### 学习的地方？

如果您对了解更多关于这些语言感兴趣，请继续阅读一些好的入门地点。

#### Sass

官方网站是`sass-lang.com`。Chris Coyier 在`css-tricks.com/video-screencasts/88-intro-to-compass-sass/`上有一个关于 Sass 的很好的介绍视频。

#### Less

官方网站是`lesscss.org`。有一个 Less 的视频概述可在`net.tutsplus.com/tutorials/html-css-techniques/quick-tip-you-need-to-check-out-less-js/`上找到。

#### Stylus

官方官方网站在`learnboost.github.com/stylus`。有一个 Stylus 的视频概述可在`thechangelog.com/post/3036532096/stylus-expressive-robust-feature-rich-css-language`上找到。

### 使用样式语言的 HTML5 Boilerplate

如果您对任何这些语言有相当自信的掌握，那么您可以使用我们接下来将要看的任何可用端口来启动您的项目：

#### Sass

HTML5 Boilerplate 的 Sass 版本相当更新，需要**Compass**，这是在`github.com/sporkd/compass-html5-boilerplate`上的 Sass 框架。

#### Less

存在一个不太经常更新的 HTML5 Boilerplate 到 Less 的端口，位于`github.com/m6tt/less-boilerplate`。

#### Stylus

目前没有针对 Stylus 的 HTML5 Boilerplate 的完全功能性端口，尽管使用命令行将其转换为 stylus 似乎是最简单的方法。有关使用此方法的更多信息，请访问`learnboost.github.com/stylus/docs/executable.html`。

# 总结

哇！那是一个紧张的编码会话。在本章中，我们几乎基于 HTML5 Boilerplate 创建了一个完整的网站。我们看了如何编写标记、样式和脚本。此外，我们还探索了一些工具，使编写有效的标记和样式更容易。

到目前为止，我们对示例项目所做的所有更改都可以在`nimbu.in/h5bp-book/chapter-3/`上找到。

在下一章中，我们将看看如何使用 jQuery 为这个相当静态的页面添加一些交互性，并使其更容易在网站上进行导航。


# 第四章：添加交互性并完成您的网站

我们已经创建了网站的第一个版本。虽然网站看起来非常可读和可导航，但使交互更加流畅将使其成为一个显著更好的体验。

# 使用 jQuery

正如我们在第二章中看到的，*开始你的项目*，HTML5 Boilerplate 提供了一种方便且安全的方式来加载 jQuery。使用 jQuery，编写访问元素的脚本变得非常简单。

如果您正在编写自定义的 jQuery 脚本，要么启动您正在使用的插件，要么执行一些小的交互，请将其放在`js`文件夹中的`main.js`文件中。

# 使用其他库

如果您更喜欢使用其他库，您也可以以类似的方式加载和使用它们。

以下是我们加载 jQuery 的方式：

```js
<script src="img/jquery.min.js"></script>
<script>window.jQuery || document.write('<script src="img/jquery-1.8.2.min.js"><\/script>')
</script>
```

假设您想使用另一个库（如 MooTools），然后查看 Google Libraries API，看看该库是否可在`developers.google.com/speed/libraries/`上找到。如果可以找到，只需用该网站上的适当引用替换引用。例如，如果我们想用 MooTools 替换我们的 jQuery 链接，我们只需替换以下代码：

```js
<script src="img/jquery.min.js">
</script>
```

使用以下代码行：

```js
<script src="img/mootools-yui-compressed.js">
</script>
```

我们还将在本地的`js/vendor`文件夹中下载 Mootools 的压缩文件，并替换以下代码：

```js
<script>window.jQuery||document.write('<script src="img/jquery-1.7.2.min.js"><\/script>')
</script>
```

使用以下代码行：

```js
<script>window.jQuery||document.write('<script src="img/mootools-core-1.4.5-full-compat-yc.js"><\/script>')
</script>
```

有关为什么我们使用代码的本地副本的更多信息，请查看第二章，*开始你的项目*。但是我们对我们默认选择的 jQuery 非常满意，所以让我们继续使用它。

# 添加平滑滚动插件和交互

如果您还没有注意到，我们正在构建的网站是一个单页面网站！所需的所有内容都在同一页上找到。根据我们目前的网站设计，点击站点导航链接将大致滚动到导航链接所指的部分。我们希望这种交互是平滑的。让我们使用 jQuery 的平滑滚动插件来实现这一点。

让我们从 Github 仓库下载插件文件，托管在`github.com/kswedberg/jquery-smooth-scroll`上。

在其中，我们找到了插件的压缩版本（`jquery.smooth-scroll.min.js`），我们将在文本编辑器中打开它。

然后复制所有代码并粘贴到`plugins.js`文件中。

让我们添加一个类名`js-scrollitem`，以便我们可以区分这个元素是否有一个将在这些元素上使用的脚本。这样，意外删除通过 JavaScript 提示的交互所需的类名的机会将会更小。

现在，我们将编写代码在`main.js`文件中调用这个插件。在文本编辑器中打开`main.js`文件并输入：

```js
$('.js-scrollitem').smoothScroll();
```

这将使所有链接到同一页内具有`js-scrollitem`类的父容器的可点击链接通过插件平滑滚动。如果我们已经正确使用了 HTML5 Boilerplate 的默认设置，添加这个将足以开始平滑滚动。

接下来，我们希望行程部分中的导航链接根据点击的日期打开右侧的行程。目前，在下面的截图中，它只显示了第一天的行程，没有做其他任何事情：

![添加平滑滚动插件和交互](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_04_00.jpg)

让我们继续编辑`main.js`文件并添加启用此功能的代码。

首先，让我们添加我们将用于控制样式和代码内部的隐藏/显示行为的类名。此功能的代码如下：

```js
<nav class="t-tab__nav">
<a class="t-tab__navitem--active t-tab__navitemjs-tabitem" href="#day-1">Day 1</a>
<a class="t-tab__navitemjs-tabitem" href="#day-2">Day 2</a>
</nav>
```

现在，我们将编写代码来显示我们点击的元素。这段代码如下：

```js
var $navlinks = $('#lineup .js-tabitem');
var $tabs = $('.t-tab__body');

var hiddenClass = 'hidden';

var activeClass = 't-tab__navitem--active';

$navlinks.click(function() {
// our code for showing or hiding the current day's line up
$(this.hash).removeClass(hiddenClass);
});
```

通过检查我们迄今为止所做的工作，我们注意到它始终保持每天的行程可见，并且完成后不会隐藏它们！让我们也添加这一点，如下面的代码片段所示：

```js
var $navlinks = $('#lineup .js-tabitem');
var $tabs = $('.t-tab__body');

var hiddenClass = 'hidden';

var activeClass = 't-tab__navitem--active';

var $lastactivetab = null;

$navlinks.click(function() {
var $this = $(this);
  //take note of what was the immediately previous tab and tab nav that was active
  $lastactivetab = $lastactivetab || $tabs.not('.' + hiddenClass);
  // our code for showing or hiding the current day's line up
$lastactivetab.addClass(hiddenClass);
$(this.hash).removeClass(hiddenClass);
$lastactivetab = $(this.hash);
return false;
}
```

您会注意到活动标签导航项似乎仍然表明它是**第 1 天**！让我们通过更改我们的代码来修复这个问题，以便与选项卡导航锚点类似，如下面的代码片段所示：

```js
var $navlinks = $('#lineup .js-tabitem');
var $tabs = $('.t-tab__body');

var hiddenClass = 'hidden';

var activeClass = 't-tab__navitem--active';

var $lastactivetab = null;
var $lastactivenav = null;

$navlinks.click(function() {
var $this = $(this);
//take note of what was the immediately previous tab and tab nav that was active
$lastactivetab = $lastactivetab || $tabs.not('.' + hiddenClass);
$lastactivenav = $lastactivenav || $navlinks.filter('.' + activeClass);

  // our code for showing or hiding the current day's line up
$lastactivetab.addClass(hiddenClass);   
$(this.hash).removeClass(hiddenClass);   
$lastactivetab = $(this.hash);

  // change active navigation item
$lastactivenav.removeClass(activeClass);
$this.addClass(activeClass);
$lastactivenav = $this;

return false;
});
```

太棒了！我们已经准备好按天排列了。现在我们需要确保当用户单击**在地图上查找**链接时，我们的 Google Maps `iframe`会呈现。我们还希望使用相同的链接来隐藏地图，如果用户想要这样做的话。

首先，我们为用于触发地图显示/隐藏和地图的`iframe`的锚元素添加一些可识别的特征，如下面的代码片段所示：

```js
<p>The festival will be held on the beautiful beaches of NgorTerrou Bi in Dakar. 
<ahref="#" class="js-map-link">Locate it on a map</a>
</p>

<iframe id="venue-map" class="hidden" width="425" 
height="350" frameborder="0" scrolling="no" marginheight="0" marginwidth="0" src="img/maps?f=q&amp;source=s_q&amp;hl=en&amp;geocode=&amp;q=ngor+terrou+bi,+dakar,+senegal&amp;aq=&amp;sll=37.0625,-95.677068&amp;sspn=90.404249,95.976562&amp;ie=UTF8&amp;hq=ngor&amp;hnear=Terrou-Bi,+Bd+Martin+Luther+King,+Gueule+Tapee,+Dakar+Region,+Guediawaye,+Dakar+221,+Senegal&amp;t=m&amp;fll=14.751996,-17.513559&amp;fspn=0.014276,0.011716&amp;st=109146043351405611748&amp;rq=1&amp;ev=p&amp;split=1&amp;ll=14.711109,-17.483921&amp;spn=0.014276,0.011716&amp;output=embed">
</iframe>
```

然后，我们使用以下 JavaScript 来触发链接：

```js
  $maplink = $('.js-map-link');
  $maplinkText = $maplink.text();

  $maplink.toggle(function() {
    $('#venue-map').removeClass(hiddenClass);
    $maplink.text('Hide Map');
  }, function() {
    $('#venue-map').addClass(hiddenClass);
    $maplink.text($maplinkText);
  });
```

现在，让我们看看如何使我们的音频播放器在所有浏览器上工作。

# 使用 Modernizr 安全添加 HTML5 功能

我们在第一章中简要介绍了 Modernizr，*开始之前*，但我们还没有为它做过太多事情。强烈建议我们创建一个自定义的 Modernizr 构建。HTML5 Boilerplate 附带了一个 Modernizr 的自定义构建，其中包括自定义构建器（`modernizr.com/download/`）中的所有选项，包括额外的功能，如 HTML5Shiv、资源加载器（`modernizr.load`）、媒体查询测试，并根据 Modernizr 的测试结果向`html`标签添加 CSS 类名。

Modernizr 的自定义构建在 IE 中启用了 HTML5 元素（在`paulirish.com/2011/the-history-of-the-html5-shiv/`中了解更多信息）。但是，现在，通过我们的音频播放器，我们有机会使用另一个作为额外功能可用的 Modernizr 函数，即`modernizr.load`。

浏览器中的音频支持并不像我们期望的那样简单。由于许可限制，不同的浏览器期望不同的格式。一些浏览器甚至不支持 HTML5 音频。使用一个可以为我们抽象出所有这些问题的框架将是完美的。在`html5please.com`上看到，推荐建议是使用一个名为`mediaelement.js`的框架来帮助我们处理这些问题。

### 注意

`html5please.com`是一个网站，告诉您这些新功能中哪些是可用的，以及在不支持它们的浏览器上应该如何使用它们。

让我们仅在未检测到音频支持时使用这个框架作为我们的音频播放器。

首先，我们从`mediaelementjs.com`下载框架，并将构建文件夹中的所有文件复制到`js/vendor/mediaelement/`中。然后，我们应该在`index.html`中为我们的播放器添加跨浏览器友好的音频标记，如下面的代码片段所示：

```js
<article class="t-audio">
<audio controls preload="none" autobuffer>
<sourcesrc="img/festival.mp3" />
<sourcesrc="img/festival.ogg" />
</audio>
</article>
```

请注意，我们需要在`head`元素中指定样式表，以确保它在所有浏览器上都能完美工作（而不是及时加载），如下面的代码所示：

```js
<link rel="stylesheet" href="js/vendor/mediaelement/mediaelementplayer.css">
```

然后，我们在`main.js`文件中使用 Modernizr 仅在缺少音频支持时加载`mediaelement.js`，如下面的代码所示：

```js
Modernizr.load({
test: Modernizr.audio,
nope: {
'mediaelementjs': 'js/vendor/mediaelement/mediaelement-and-player.min.js'
},

callback: {
    'mediaelementjs': function() {
$('audio').mediaelementplayer();
}
} 
});
```

这段代码首先使用 Modernizr 测试音频是否受支持。如果不支持，那么我们将加载必要的资源来使音频在我们的`mediaelement.js`框架中工作。一旦加载了`mediaelement.js`，我们就调用它，这样它就会运行并将我们的音频文件转换为那些缺少音频支持的浏览器能够理解的格式。

![使用 Modernizr 安全添加 HTML5 功能](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_04_01.jpg)

前面的屏幕截图显示了我们的页面在不支持 HTML5 音频的浏览器上的呈现（回退到使用`mediaelement.js`的 Flash），以及在支持 HTML5 音频的浏览器上的呈现（使用浏览器提供的本机控件）。

## 何时使用 Modernizr.load？

`Modernizr.load`是一个很好的实用工具，当您有多个文件需要有条件地加载时，比如我们的音频播放器。

有时，您希望只有在用户单击链接或元素时才发生某些事情。您可以在用户单击元素后及时加载这些资产，而不是预先加载所有所需的资产，并使浏览器渲染页面变慢。

## 使用 Modernizr 加载 CSS 功能

Modernizr 还会在页面的`html`标签上输出其对各种 HTML5/CSS3 功能的测试结果，如下截图所示：

![使用 Modernizr 加载 CSS 功能](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_04_02.jpg)

这对于基于可用功能的体验进行样式设计非常有用。例如，我们注意到`html`元素中有一个名为`no-touch`的类名。这意味着加载此页面的浏览器不支持触摸界面。如果支持触摸，那么我们可以为所有链接添加更多的填充，以适应尝试点击它们的大手指。让我们在`css/style.css`文件中添加样式来实现这一点，如下所示：

```js
.touch a {
padding: 0.25em;
background: #CEC3A1;
border-radius: 0.5em;
display: inline-block;
}
```

这是我们的网站在支持触摸事件的浏览器上的外观（左侧）和不支持触摸事件的浏览器上的外观（右侧）：

![使用 Modernizr 加载 CSS 功能](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_04_03.jpg)

# 测试我们的网站

哇！这真是太多了！但是等等，我们还没有完成！我们已经编写了所有的代码，但是怎么样进行一些测试呢？那里有很多种浏览器的变体，不可能对每一种都进行测试。幸运的是，在大多数主要版本的浏览器上进行测试是相当简单的。

如果您使用 Windows，我建议您安装 Opera、Opera Next、Safari、Chrome、Chrome Canary、Firefox、Firefox Nightly、IE8 和 IE10 的最新版本。

如果您使用的是 Mac，获取上面列出的所有浏览器，除了 IE。如果您有能力的话，购买一个 Windows 操作系统，并将其安装为 Virtual Box 上的虚拟镜像（[www.virtualbox.org/](http://www.virtualbox.org/)）。微软提供了旧版 IE 的虚拟镜像供测试使用，您也可以使用 ievms（`github.com/xdissent/ievms`）在 Virtual Box 上安装。

对于一个更简单但不太严格的测试选项——比如当您还没有最终确定您的网站时——尝试[www.browserstack.com](http://www.browserstack.com)或`browserling.com`。

所有这些浏览器都有开发者工具，可以很容易地检测页面是否按预期渲染。

让我们在 Internet Explorer 7 中测试我们的 Sun and Sand Festival 网站。乍一看，一切似乎都按预期工作。但是看着标签，似乎一切都乱了！以下截图显示了我们在 Internet Explorer 浏览器上的页面：

![测试我们的网站](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_04_04.jpg)

为了调试这个问题，让我们使用 Firebug Lite 来检查这些元素上应用了哪些样式。您可以在 IE7 上安装 Firebug Lite（[`getfirebug.com/firebuglite`](http://getfirebug.com/firebuglite)）的书签。点击该书签将使我们能够在 IE7 上使用受限版本的 Firebug。

使用 Firebug，我们看到一个调试窗口，如下截图所示：

![测试我们的网站](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_04_05.jpg)

检查我们的`main.css`，似乎我们基于媒体查询的样式都被 IE7 解析和解释，而不管其中的条件如何！例如：

```js
.t-unit-1-2{
width: 100%;
}
```

先前的样式是在媒体查询`@media only screen and (max-width: 750px)`中声明的，这个查询应该只在满足条件时覆盖现有规则`(.t-unit-1-2 { width: 50%; })`。但是 IE7 简单地忽略了提到的功能，并盲目地应用它找到的所有样式规则。

由于条件 CSS 类名的存在，我们可以通过在原始 CSS 声明中添加额外的样式规则来轻松解决这个问题，以防止 IE6 到 IE8 覆盖原始样式。附录，*您是专家，现在怎么办？*详细介绍了条件 CSS 类名。

HTML5 Boilerplate 为您提供了三个类名，用于这种情况，描述如下：

+   `.lt-ie7`：以这个类名来定位所有低于 IE7 的 IE 版本。这将应用样式到 IE 6 及以下版本。

+   `.lt-ie8`：以这个类名来定位所有低于 IE8 的 IE 版本。这将应用样式到 IE6 和 IE7。

+   `.lt-ie9`：针对所有低于 IE9 的 IE 版本。这将应用样式到所有低于 IE9 的 IE 版本。

多亏了这个，我们现在可以应用针对 IE8 及以下版本的规则，这些版本不理解媒体查询中的条件，通过以下方式应用样式规则：

```js
.lt-ie9 .t-unit-1-2 {
width: 45%;
}
```

由于 IE8 及以下版本也不支持`box-sizing`属性（Mozilla 开发者网络在`developer.mozilla.org/En/CSS/Box-sizing`描述了此属性的效果），这意味着这些框的宽度将随着我们添加填充而扩展。让我们删除父元素的边距，以防止框堆叠，如下面的代码片段所示：

```js
.lt-ie9 .t-before-1-6,
.lt-ie9 .t-after-1-6 {
margin-left: 0;
margin-right: 0;
}
```

然而，这并没有完全解决我们的问题。然后，再往上看，我们注意到我们的网格单元，也就是具有类`t-grid__cell`的元素，其`display`属性设置为 inline-block。知道 IE7 不会将此应用于除具有自然内联属性的元素之外的任何元素，我们需要添加额外的声明才能使其工作，如下面的代码片段所示：

```js
.lt-ie9 .t-grid__cell {
display: inline;
}
```

最后，现在这样就可以了！

![测试我们的网站](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_04_06.jpg)

让我们滚动到页面底部。我们注意到价格都混乱了，因为 IE7 不支持 CSS3 变换，如下面的截图所示：

![测试我们的网站](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_04_07.jpg)

有了 Modernizr，我们只需要将这个规则添加到我们的样式表中：

```js
.no-csstransforms .t-tickets__currency {
position: static;
}
```

这将使任何不支持 CSS 变换的浏览器更易读，如下面的截图所示：

![测试我们的网站](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_04_08.jpg)

继续向下滚动，我们注意到我们的 SVG 图标在 IE8 及以下版本中丢失，因为它们不识别 SVG 文件，如下面的截图所示：

![测试我们的网站](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_04_09.jpg)

再次感谢 Modernizr！在我们的`main.js`文件中，我们将检查 Modernizr 中 SVG 测试的结果，然后用它们的等效 PNG 图像替换所有 SVG 图像。请注意，这意味着您需要为 HTML 页面中使用的每个 SVG 文件都有一个 PNG 等效文件。替换 SVG 为 PNG 文件的代码如下：

```js
if(Modernizr.svg == false) {
  $('img[src$=".svg"]').each(function() {
	this.src = /(.*)\.svg$/.exec(this.src)[1] + '.png';
 });
}
```

### 提示

**为什么使用 SVG？**

我们使用 SVG 图标，因为这些图标可以根据我们对响应式网站的需求进行缩放，SVG 是一种矢量图像格式。此外，与典型的 PNG 文件相比，它们非常轻量，并且可以比 PNG 格式加载得更快。

下面的截图显示了 IE7 如何以 PNG 格式呈现图标，这要感谢 Modernizr：

![测试我们的网站](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_04_10.jpg)

当您开始进行 Web 开发时，您应该花更多时间使用浏览器开发工具；Andi Smith 在`andismith.com/blog/2011/11/25-dev-tool-secrets/`写了一篇很好的文章，概述了每个工具的一些特性。

## 在非桌面浏览器上测试

让我们看看在小规模设备上网站的外观。最快最简单的方法是从[www.opera.com/developer/tools/mobile/](http://www.opera.com/developer/tools/mobile/)下载**Opera Mobile Emulator**，然后使用其中的几个选项之一加载我们的页面。这个模拟器显示在下面的截图中：

![在非桌面浏览器上测试](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_04_11.jpg)

在模拟器左侧选择一个选项，然后单击**启动**按钮，打开一个模拟 Opera 浏览器实例，模拟您选择的设备上的显示效果。

例如，下面的截图显示了我们的页面在**Opera Mobile Emulator**上的渲染实例，用于**Amazon Kindle Fire**：

![在非桌面浏览器上测试](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_04_12.jpg)

最好的部分是**Opera Mobile**浏览器是最现代的移动浏览器之一，这使得它成为您积极开发网站时进行测试的非常好的浏览器。它还适用于各种设备，这使得使用**Opera Mobile Emulator**测试各种设备宽度变得很容易，如果您正在使用媒体查询来调整页面以适应不同的设备尺寸。

如果您也拥有运行 iOS 6 的 iPhone，使用**Safari 6 进行远程调试**并使用 Safari 开发者工具检查代码是相当容易的（Max Firtman 在[`www.mobilexweb.com/blog/iphone-5-ios-6-html5-developers`](http://www.mobilexweb.com/blog/iphone-5-ios-6-html5-developers)上有更多信息）。

如果您有 Android 设备，您可以在 Chrome for Android 浏览器上启用调试，但您需要安装 Android 开发者工具才能这样做。关于如何做到这一点的更多帮助，请参阅 Chrome for Android 远程调试指南[`developers.google.com/chrome/mobile/docs/debugging`](https://developers.google.com/chrome/mobile /docs/debugging)。

### 注意

如果您有多个运行不同浏览器的移动设备，您还可以使用`html.adobe.com/edge/inspect/`上的**Adobe Edge Inspect**来测试这些页面在所有这些设备上的外观。

# 摘要

在本章中，我们看了如何使用 jQuery 插件为网站添加一些交互。我们还学习了如何使用`Modernizr.load`来加载脚本，以便轻松地有条件地检测对 HTML5 音频的支持，并为不支持的浏览器加载资源并正确呈现音频。我们还研究了一些使用浏览器开发者工具调试网站和验证页面在各种浏览器上显示方式的方法。

在下一章中，我们将学习如何在 Apache 和其他 Web 服务器上优化我们的网站。


# 第五章：自定义 Apache 服务器

我们的 Sun and Sand 节日网站基本上已经完成了！但在部署到生产环境之前，让我们确保我们已经优化了页面和相关文件所在的服务器的配置，以便最终用户可以尽快加载页面，同时我们检查可能导致我们的网站被黑客攻击的安全漏洞。

# 服务器端配置

在我们继续之前，让我们简要地看一下服务器的作用。服务器理解浏览器对站点页面的请求，然后寻找 URL 请求的文件。服务器然后以 HTTP 头的形式将文件发送回浏览器。**Apache**是网站最流行的服务器软件，HTML5 Boilerplate 附带了一个名为`.htaccess`的 Apache 配置文件。

# 设置 Apache 服务器

在我们查看 HTML5 Boilerplate 提供的 Apache 配置文件的各种功能之前，让我们设置一个本地 Apache 服务器，这样我们就可以看到这些功能的运行情况。

## 安装 Apache

我们将看一下在 Mac、Windows 和 Linux 上安装 Apache。

### Mac

您无需做任何特殊操作；Apache 已经安装好了。但是为了在这个项目中使用它，请确保将所有文件复制到您的主文件夹中的网站文件夹（`/~<username>`）。编辑`/etc/apache2/httpd.conf`文件以更改以下突出显示的代码：

```js
<Directory /usr/share/web>
AllowOverride None
        Options MultiViewsFollowSymlinks
        Order allow,deny
        Allow from all
        Header Set Cache-Control no-cache
</Directory>
```

到以下：

```js
<Directory /usr/share/web>
AllowOverrideAll
 Options MultiViewsFollowSymlinks
        Order allow,deny
        Allow from all
        Header Set Cache-Control no-cache
</Directory>
```

您还需要以相同的方式更改`/etc/apache2/<username>.conf`中的条目。

### Windows

您需要在 Windows 上下载并安装 Apache；可以从`httpd.apache.org/docs/2.2/platform/windows.html`下载。请注意，您需要将以下代码片段添加到`conf/httpd.conf`中，该文件位于找到 Apache 应用程序的文件夹内：

```js
<Directory "/apache/htdocs/">
AllowOverride All
Options None
Order deny, allow
</Directory>
```

### Linux

如果您使用 Ubuntu，可以在[`help.ubuntu.com/8.04/serverguide/C/httpd.html`](https://help.ubuntu.com/8.04/serverguide/C/httpd.html)找到友好的文档。要启用`.htaccess`文件，用于配置您的 Apache 服务器，您需要编辑`/etc/apache2/sites-available/default`，从以下代码片段中：

```js
<Directory /var/www/>
Options Indexes FollowSymLinksMultiViews
AllowOverride None
   Order allow,deny
allow from all
   # Uncomment this directive is you want to see apache2's
   # default start page (in /apache2-default) when you go to /
   #RedirectMatch ^/$ /apache2-default/
</Directory>
```

到以下代码片段：

```js
<Directory /var/www/>
Options Indexes FollowSymLinksMultiViews
AllowOverrideAll
   Order allow,deny
allow from all
   # Uncomment this directive is you want to see apache2's
   # default start page (in /apache2-default) when you go to /
   #RedirectMatch ^/$ /apache2-default/
</Directory>
```

## 配置 Apache

我们的 HTML5 Boilerplate 文件夹中包含一个名为`.htaccess`的文件。由于文件名以`.`开头，因此在 Finder/Windows 资源管理器或其他文件管理工具中列出文件时，`.htaccess`可能不会显示出来，如下面的截图所示：

![配置 Apache](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_05_01.jpg)

但是，如果您启用了操作系统上的隐藏文件显示，您将能够看到这个文件。

现在所需的就是将我们的网站文件（包括`.htaccess`文件）移动到我们刚刚设置的服务器上。Apache 会在所有文件夹中寻找`.htaccess`文件（除非通过配置设置告知不要这样做），因此将我们的`.htaccess`文件放在站点的父文件夹中就可以了。

一般来说，使用`.htaccess`文件进行测试并不是一个坏主意。但是，如果您想让您的网站真正快速，最好将配置直接放在 Apache 服务器的主配置文件（`httpd.conf`）中。不幸的是，并非所有的托管提供商都允许这样做。

如果您可以访问 Apache 服务器的主配置文件（`httpd.conf`），您应该从 HTML5 Boilerplate 的`.htaccess`文件中复制配置，并将其放在`httpd.conf`中的`Directory`标签内，如下面的代码片段所示：

```js
<Directory /path/to/website/root>
[htaccess rules]
</Directory>
```

然后，您应该删除`.htaccess`文件，因为指令已经在服务器的主配置文件中了。

# 开箱即用的功能

HTML5 Boilerplate 的`.htaccess`文件提供的大多数优势并不是立即显而易见的。如果您的网站流量较低，且不会发出太多网络请求，您可能不会注意到使用 HTML5 Boilerplate 的`.htaccess`文件会有显著的差异。但是，当您出现高活动量的峰值（这并不罕见！）或突然有很多您网站所需的图像和视频的网络请求时，HTML5 Boilerplate 的`.htaccess`会自动帮助您。

只要您将`.htaccess`文件放在项目文件夹中，或者按照前面指示的设置 Apache 的主配置文件，所有这些功能都可以立即使用。

## 删除 ETags

**实体标签**（**ETags**）验证浏览器缓存中的组件（如图像、文件等）是否与服务器上的组件匹配。不幸的是，ETags 带来的害处大于好处。大多数服务器默认启用 ETags，这就是为什么 HTML5 Boilerplate 的服务器配置文件阻止服务器提供它们的原因，如下面的代码片段所示：

```js
<IfModule mod_headers.c>
  Header unset ETag
</IfModule>
FileETag None
```

### 注意

Steve Souders 深入探讨了为什么 ETags 无法解决它们设计的问题以及为什么您应该删除它们，网址为`developer.yahoo.com/blogs/ydn/posts/2007/07/high_performanc_11/`。

## Gzip 组件

**Gzip**是最流行的压缩方法。通过使用 Gzip 压缩文件，您可以确保文件在低带宽连接下更快地传输。有时，节省的文件大小高达 70％，使其成为一个很好的性能配置默认值。

让我们看看没有`.htaccess` Gzip 功能时我们的文件有多大。为了做到这一点，我们只需注释掉该部分，如下面的代码片段所示：

```js
#<IfModule mod_deflate.c>
#
#  # Force deflate for mangled headers developer.yahoo.com/blogs/ydn/posts/2010/12/pushing-beyond-gzipping/
#  <IfModule mod_setenvif.c>
#    <IfModule mod_headers.c>
#      SetEnvIfNoCase ^(Accept-EncodXng|X-cept-Encoding|X{15}|~{15}|-{15})$ ^((gzip|deflate)\s*,?\s*)+|[X~-]{4,13}$ #HAVE_Accept-Encoding
#      RequestHeader append Accept-Encoding "gzip,deflate" env=HAVE_Accept-Encoding
#    </IfModule>
#  </IfModule>
#
#  # HTML, TXT, CSS, JavaScript, JSON, XML, HTC:
#  <IfModule filter_module>
#    FilterDeclare   COMPRESS
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $text/html
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $text/css
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $text/plain
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $text/xml
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $text/x-component
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $application/javascript
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $application/json
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $application/xml
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $application/xhtml+xml
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $application/rss+xml
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $application/atom+xml
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $application/vnd.ms-fontobject
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $image/svg+xml
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $image/x-icon
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $application/x-font-ttf
#    FilterProvider  COMPRESS  DEFLATE resp=Content-Type $font/opentype
#    FilterChain     COMPRESS
#    FilterProtocol  COMPRESS  DEFLATE change=yes;byteranges=no
#  </IfModule>
#
#  <IfModule !mod_filter.c>
#    # Legacy versions of Apache
#    AddOutputFilterByType DEFLATE text/html text/plain text/css application/json
#    AddOutputFilterByType DEFLATE application/javascript
#    AddOutputFilterByType DEFLATE text/xml application/xml text/x-component
#    AddOutputFilterByType DEFLATE application/xhtml+xml application/rss+xml application/atom+xml
#    AddOutputFilterByType DEFLATE image/x-icon image/svg+xml application/vnd.ms-fontobject application/x-font-ttf #font/opentype
#  </IfModule>
#
#</IfModule>
```

现在，让我们通过浏览器开发者工具中的网络工具来查看通过网络传递到我们浏览器的文件的大小（在本例中是 Chrome 开发者工具）：

![Gzip 组件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_05_02.jpg)

现在，让我们通过从`.htaccess`中删除行首的`#`来启用 Gzip 的适当规则。注意下面的截图中的差异：

![Gzip 组件](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_05_03.jpg)

如果您想了解更多关于 Gzip 的信息，第四章, *Smaller Components, Book of Speed, Stoyan Stefanov*，网址为[www.bookofspeed.com/chapter4.html](http://www.bookofspeed.com/chapter4.html)，将是一个很好的起点。

## 使用 Expires 头文件进行更好的缓存控制

服务器可以告诉浏览器它们可以将文件保存在缓存中的时间有多长。这对于不经常更改的静态文件非常有用，并且将减少页面加载时间。HTML5 Boilerplate 的`.htaccess`文件有一组默认值适用于大多数静态文件，如下面的代码片段所示：

```js
<IfModule mod_expires.c>
ExpiresActive on

# Perhaps better to whitelist expires rules? Perhaps.
ExpiresDefault                          "access plus 1 month"

# cache.appcache needs re-requests in FF 3.6 (thanks Remy ~Introducing HTML5)
ExpiresByType text/cache-manifest       "access plus 0 seconds"

# Your document html
ExpiresByType text/html                 "access plus 0 seconds"

# Data
ExpiresByType text/xml                  "access plus 0 seconds"
ExpiresByType application/xml           "access plus 0 seconds"
ExpiresByType application/json          "access plus 0 seconds"

# Feed
ExpiresByType application/rss+xml       "access plus 1 hour"
ExpiresByType application/atom+xml      "access plus 1 hour"

# Favicon (cannot be renamed)
ExpiresByType image/x-icon              "access plus 1 week"

# Media: images, video, audio
ExpiresByType image/gif                 "access plus 1 month"
ExpiresByType image/png                 "access plus 1 month"
ExpiresByType image/jpg                 "access plus 1 month"
ExpiresByType image/jpeg                "access plus 1 month"
ExpiresByType video/ogg                 "access plus 1 month"
ExpiresByType audio/ogg                 "access plus 1 month"
ExpiresByType video/mp4                 "access plus 1 month"
ExpiresByType video/webm                "access plus 1 month"

# HTC files  (css3pie)
ExpiresByType text/x-component          "access plus 1 month"

# Webfonts
ExpiresByType application/x-font-ttf    "access plus 1 month"
ExpiresByType font/opentype             "access plus 1 month"
ExpiresByType application/x-font-woff   "access plus 1 month"
ExpiresByType image/svg+xml             "access plus 1 month"
ExpiresByType application/vnd.ms-fontobject "access plus 1 month"

# CSS and JavaScript
ExpiresByType text/css                  "access plus 1 year"
ExpiresByType application/javascript    "access plus 1 year"
</IfModule>
```

这告诉服务器在每个类型的文件被访问后立即缓存请求，缓存时间由文本`"access plus…"`指定。例如，考虑以下代码片段：

```js
# CSS and JavaScript
ExpiresByType text/css                  "access plus 1 year"
ExpiresByType application/javascript    "access plus 1 year"
```

这个片段让服务器告诉浏览器请求 CSS 和 JavaScript 文件时，要至少缓存这些文件一年，除非用户故意清除他们的缓存。

### 注意

Yahoo 关于加速网站的最佳实践详细解释了 Expires 头文件的作用，网址为`developer.yahoo.com/performance/rules.html#expires`。

## 自定义 404 页面

HTML5 Boilerplate 提供了一个名为`404.html`的自定义 404 页面。但是，除非服务器知道在找不到资源时每次都要提供此文件，否则永远不会被使用。HTML5 Boilerplate 的`.htaccess`文件有一个配置，告诉服务器按如下方式使用此文件：

```js
ErrorDocument 404 /404.html
```

确保使用完整路径引用`404.html`。例如，在 Mac 上，如果您将其托管在您的`<username>`文件夹下的网站文件夹中，则完整路径将是`/~<username>/404.html`。

以下截图显示了当使用 HTML5 Boilerplate 的`.htaccess`文件时，浏览器如何呈现默认的 HTML5 Boilerplate 404 页面：

![自定义 404 页面](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_05_04.jpg)

## 强制使用最新的 IE 版本

Internet Explorer 利用`meta`标签来决定是否应该以兼容模式呈现站点，还是使用最新的渲染引擎来呈现它。

Google Chrome 发布了一个名为**Chrome Frame**的插件，可以从[`developers.google.com/chrome/chrome-frame/`](https://developers.google.com/chrome/chrome-frame/)下载，如果安装在用户的计算机上，当用户使用较旧版本的 Internet Explorer 时，将提供现代浏览器的体验。当您的页面在较旧版本的 Internet Explorer 上被查看时，您的网站可以选择使用这个插件。要自动选择使用这个插件，将`", chrome=1"`附加到`http-equiv` `meta`标签的`content`属性值。

这个标签可以在 HTML 文件本身中设置，这就是 HTML5 Boilerplate 所做的，如下面的代码片段所示：

```js
<meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
```

然而，由于 HTML5 Boilerplate 在`html`标签周围使用了条件注释，IE 将以**兼容视图**而不是 Chrome Frame 来呈现 HTML。因此，在`html`标签周围使用带有条件注释的`meta`标签是行不通的。HTML5 Boilerplate 的`.htaccess`文件将其设置为 HTTP 头，如下面的代码片段所示：

```js
<IfModule mod_headers.c>
  Header set X-UA-Compatible "IE=Edge,chrome=1"
  # mod_headers can't match by content-type, but we don't want to send this header on *everything*...
<FilesMatch "\.(js|css|gif|png|jpe?g|pdf|xml|oga|ogg|m4a|ogv|mp4|m4v|webm|svg|svgz|eot|ttf|otf|woff|ico|webp|appcache|manifest|htc|crx|oex|xpi|safariextz|vcf)$" >
    Header unset X-UA-Compatible
</FilesMatch>
</IfModule>
```

这将强制 IE 尊重发送的 HTTP 头，并使用最新的渲染引擎，而不管`meta`标签陈述的是什么。您还可以设置 IE 使用任何您喜欢的渲染引擎。我们在附录中深入讨论了这个功能，*你是专家，现在怎么办？*，在*什么是 meta x-ua-compatible？*一节下。

### 注意

我们经过了大量详细的测试和评论，这些测试和评论为我们推荐使用这种方法设置 IE 兼容模式提供了信息，这些信息可以在 Github 的**Issue 跟踪器**上找到，网址为[github.com/h5bp/html5-boilerplate/issues/378](http://github.com/h5bp/html5-boilerplate/issues/378)。

## 使用 UTF-8 编码

字符编码是一种以字节序列表示文本数据的方式。不同的脚本有不同的标准，例如希腊语、日语等，但是创建 HTML 规范的标准机构 W3C 强烈推荐在 Web 上提供的所有文本都使用**UTF-8**作为事实上的编码方案，以确保所有浏览器都能正确呈现您的文本数据。`.htaccess`文件以以下方式设置它：

```js
# Use UTF-8 encoding for anything served text/plain or text/html
AddDefaultCharset utf-8
# Force UTF-8 for a number of file formats
AddCharset utf-8 .css .js .xml .json .rss .atom
```

### 注意

Edward Z. Yang 在`htmlpurifier.org/docs/enduser-utf8.html#whyutf8`上写了一篇信息丰富的文章，解释了为什么 UTF-8 是字符编码的最佳选择；如果您对这个话题感兴趣，这篇文章值得一读。

## 提供正确的 MIME 类型

作为 HTTP 头发送的**多用途互联网邮件扩展**（**MIME**）类型有助于浏览器决定如何处理发送的内容。例如，浏览器需要知道文件是样式表还是可下载的文本文档。服务器发送资源时返回的 MIME 类型 HTTP 头提供了这些信息。HTML5 Boilerplate 的`.htaccess`文件确保服务器在提供内容时提供正确的 MIME 类型。

例如，在我们的塞内加尔音乐节网站中，我们需要让浏览器理解我们的 Web 字体是字体文件而不是乱码文本。在我们的 HTML5 Boilerplate`.htaccess`文件中，以下行确保服务器返回正确的 MIME 类型，以便浏览器可以做到这一点：

```js
AddType application/vnd.ms-fontobjecteot
AddType application/x-font-ttfttfttc
AddType font/opentypeotf
AddType application/x-font-woffwoff
```

### 注意

有关 MIME 类型的更多信息可以在**Mozilla 开发者网络**上找到，网址为`developer.mozilla.org/en/Properly_Configuring_Server_MIME_Types#What_are_MIME_types.3F`。

## 阻止访问隐藏文件夹

如果您使用**版本控制系统**（**VCS**）来管理网站的代码，则用于管理版本的隐藏文件夹（`.git`或`.svn`）可能也存在于您的生产服务器中。您不希望任何人访问这些文件并找到可能被用来黑客攻击您的网站的任何信息。HTML5 Boilerplate 通过`.htaccess`文件阻止服务器提供对这些文件的内容的请求，如以下代码片段所示：

```js
# Block access to "hidden" directories whose names begin with a period. This
# includes directories used by version control systems such as Subversion or Git.
<IfModule mod_rewrite.c>
RewriteCond %{SCRIPT_FILENAME} -d
RewriteCond %{SCRIPT_FILENAME} -f
RewriteRule "(^|/)\." - [F]
</IfModule>
```

## 阻止访问备份和源文件

例如，如果您的数据库在服务器上备份，例如`database.sql.bak`，您也不希望任何人访问，也不希望访问日志文件或任何源文件，例如用于 logo 的 Photoshop 文件 - 我们知道这种情况经常发生！`.htaccess`文件中的以下代码阻止访问这些文件：

```js
# Block access to backup and source files
# This files may be left by some text/html editors and
# pose a great security danger, when someone can access them
<FilesMatch "(\.(bak|config|sql|fla|psd|ini|log|sh|inc|swp|dist)|~)$">
  Order allow,deny
  Deny from all
  Satisfy All
</FilesMatch>
```

这告诉服务器查找以以下任何扩展名结尾的文件：`<filename>.bak`，`<filename>.config`等等，如果是这样，拒绝处理对这些文件的请求。它将返回`403 Forbidden`错误。

## 启动重写引擎

在进行任何 URL 重写之前，Apache 服务器要求您启动重写引擎。HTML5 Boilerplate 的`.htaccess`文件通过以下代码片段启用了这一点：

```js
<IfModule mod_rewrite.c>
  Options +FollowSymlinks
RewriteEngine On
# RewriteBase /
</IfModule>
```

如果您的站点在子文件夹中，请删除`RewriteBase`行前的`#`并将其设置为从根目录到子文件夹的完整路径。

## 防止不存在的重定向文件夹出现 404 错误

在 Apache 中，如果您希望重定向从不存在的路径请求的 URL 到另一个路径，您需要禁用`MultiViews`。

例如，如果您收到对`http://example.com/beaches/10`的请求，并且希望将其内部重定向到`http://example.com/index.php?q=10`，并且`beaches`文件夹不存在于您网站的根文件夹中，Apache 将抛出错误。HTML5 Boilerplate 的`.htaccess`文件通过使用以下代码语句防止这种情况发生：

```js
Options -MultiViews
```

# 其他自定义

提供了许多其他自定义选项，但它们都被注释掉，因为它们需要仔细考虑，有时可能会产生意想不到的后果。

## 抑制或强制 URL 开头的“www。”

大多数人没有意识到`http://example.com`和`http://www.example.com`在搜索引擎中被视为两个不同的站点。您可以强制重写 URL 以使用 www 或非 www。我更喜欢非 www URL，因为它比较短！

HTML5 Boilerplate 的`.htaccess`文件为您提供了这两种选择。默认情况下，配置会强制服务器将对`http://www.example.com`的请求重写为`http://example.com`。如果您喜欢另一种方式，可以让服务器将对`http://example.com`的请求重写为`http://www.example.com`，如以下步骤所述：

1.  注释掉以下代码片段中显示的默认选项：

```js
# Option 1:
# Rewrite "www.example.com -> example.com"
<IfModule mod_rewrite.c>
  RewriteCond %{HTTPS} !=on
  RewriteCond %{HTTP_HOST} ^www\.(.+)$ [NC]
  RewriteRule ^ http://%1%{REQUEST_URI} [R=301,L]
</IfModule>
```

1.  现在注释掉的默认部分应该看起来像以下代码片段：

```js
# Option 1:
# Rewrite "www.example.com -> example.com"

# <IfModule mod_rewrite.c>
#  RewriteCond %{HTTPS} !=on
#  RewriteCond %{HTTP_HOST} ^www\.(.+)$ [NC]
#  RewriteRule ^ http://%1%{REQUEST_URI} [R=301,L]
#</IfModule>
```

您可能已经注意到，我们所做的就是在每行前添加一个`#`字符和一个空格。

1.  现在，我们将通过取消注释来启用第二个选项。通过取消注释更改以下代码片段：

```js
# Option 2:
# To rewrite "example.com -> www.example.com" uncomment the following lines.
# Be aware that the following rule might not be a good idea if you
# use "real" subdomains for certain parts of your website.

# <IfModule mod_rewrite.c>
#   RewriteCond %{HTTPS} !=on
#   RewriteCond %{HTTP_HOST} !^www\..+$ [NC]
#   RewriteRule ^ http://www.%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
# </IfModule>
```

1.  取消注释的代码部分应该看起来像以下代码片段：

```js
# Option 2:
# To rewrite "example.com -> www.example.com" uncomment the following lines.
# Be aware that the following rule might not be a good idea if you
# use "real" subdomains for certain parts of your website.

<IfModule mod_rewrite.c>
RewriteCond %{HTTPS} !=on
RewriteCond %{HTTP_HOST} !^www\..+$ [NC]
RewriteRule ^ http://www.%{HTTP_HOST}%{REQUEST_URI} [R=301,L]
</IfModule>
```

我们所做的就是删除以`<IfModule mod_rewrite.c>`开头并以`</IfModule>`结尾的行前的`#`字符和空格。

无论您想使用哪个选项，请确保您不要同时启用这两个选项，因为这将阻止 Apache 提供您的页面。

## 从 iFrames 设置 cookies

IE 通常会阻止从 IFrame 中设置的 cookies。如果您需要设置这样的 cookies，特别是如果您有广告或社交网络插件，您需要发送**隐私偏好平台项目**（**P3P**）标头。

在`.htaccess`文件中查找与本节标题相同的注释，并更改以下行：

```js
# <IfModule mod_headers.c>
#   Header set P3P "policyref=\"/w3c/p3p.xml\", CP=\"IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT\""
# </IfModule>
```

在以下代码片段中：

```js
<IfModule mod_headers.c>
  Header set P3P "policyref=\"/w3c/p3p.xml\", CP=\"IDC DSP COR ADM DEVi TAIi PSA PSD IVAi IVDi CONi HIS OUR IND CNT\""
</IfModule>
```

### 注意

Eric Law 详细介绍了 IE 的 cookie 策略，可以在`blogs.msdn.com/b/ieinternals/archive/2009/08/20/wininet-ie-cookie-internals-faq.aspx`上阅读。

## PHP 安全默认值

如果你正在使用 PHP，HTML5 Boilerplate 的`.htaccess`文件中有很多配置选项，可以使你的 PHP 安装更安全。如果你使用 PHP，你可以使用与*抑制或强制 URL 开头的"www。"*一节中概述的相同过程打开它们。

鉴于我们的网站不使用 PHP，我们不需要打开它们。

## 停止广告 Apache 版本

你可以防止 Apache 广告其版本，以减少恶意程序员利用特定版本的漏洞的可能性。以下是 Apache 版本的广告方式：

![停止广告 Apache 版本](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_05_05.jpg)

这个先前的截图显示了 Apache 版本号作为 HTTP 头发送到浏览器。

### 注意

你可以使用大多数浏览器自带的开发者工具来验证 HTTP 头。在这种情况下，我们使用 Chrome 的开发者工具**资源**选项卡。关于如何使用这个工具的更多信息，请参考 Chrome 的帮助中心`developers.google.com/chrome-developer-tools/docs/network`。

这需要从服务器的主配置文件中进行配置，我们无法从`.htaccess`文件中进行配置。因此，让我们从 HTML5 Boilerplate 的`.htaccess`文件中删除以下指令，并替换为在`/etc/apache2/httpd.conf`中找到的指令（如果你使用 Windows 或 Linux，则该文件的路径将不同）：

```js
ServerTokens Prod
```

在将配置值应用到 Apache 服务器的主配置文件后，下面的截图显示了 Apache 发送的无版本 HTTP 头：

![停止广告 Apache 版本](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_05_06.jpg)

## 允许在特定 JS 和 CSS 文件中进行合并

有时，当请求发出时，你可能希望服务器将多个脚本或样式表文件合并为一个响应。请注意，这样做并不会加快页面加载速度，因为服务器需要自己的时间将这些文件拼接在一起。

这是我建议你在其他解决方案都失败时最后考虑的选项。理想情况下，你永远不应该这样做。

要做到这一点，首先取消`.htaccess`文件中的以下行：

```js
#<FilesMatch "\.combined\.js$">
#  Options +Includes
#  AddOutputFilterByType INCLUDES application/javascript application/json
#  SetOutputFilter INCLUDES
#</FilesMatch>
#<FilesMatch "\.combined\.css$">
#  Options +Includes
#  AddOutputFilterByType INCLUDES text/css
#  SetOutputFilter INCLUDES
#</FilesMatch>
```

改为以下代码片段：

```js
<FilesMatch "\.combined\.js$">
  Options +Includes
AddOutputFilterByType INCLUDES application/javascript application/json
SetOutputFilter INCLUDES
</FilesMatch>
<FilesMatch "\.combined\.css$">
  Options +Includes
AddOutputFilterByType INCLUDES text/css
SetOutputFilter INCLUDES
</FilesMatch>
```

然后，在`js`文件夹中，创建一个名为`script.combined.js`的文件。

在文本编辑器中打开`script.combined.js`文件，并使用以下语法将所有应该合并并输出到`script.combined.js`文件中的文件：

```js
#   <!--#include file="<path/to/file.js>" -->
#   <!--#include file="<path/to/another-file.js>" -->
```

如果你想要动态合并样式表，你可以这样做。在`css`文件夹中创建一个名为`style.combined.css`的文件。

在文本编辑器中打开`style.combined.css`文件，并使用以下语法将所有应该合并并输出到`style.combined.css`文件中的文件：

```js
#   <!--#include file="<path/to/file.css " -->
#   <!--#include file="<path/to/another-file.css>" -->
```

正如我之前提到的，这样做会使 Apache 对这些请求的响应变慢。你应该使用一个构建脚本来连接文件（我们将在第七章中研究构建脚本，*使用构建脚本自动部署*）。所以只有在没有其他选择的情况下取消这个设置。

## 在 CSS 的鼠标悬停效果中停止 IE 的屏幕闪烁

当你使用背景图片在链接上悬停时发生变化，IE 会出现闪烁。你可以通过更改`.htaccess`文件中的以下行来防止这种情况发生：

```js
# BrowserMatch "MSIE" brokenvary=1
# BrowserMatch "Mozilla/4.[0-9]{2}" brokenvary=1
# BrowserMatch "Opera" !brokenvary
# SetEnvIfbrokenvary 1 force-no-vary
```

改为以下代码片段：

```js
BrowserMatch "MSIE" brokenvary=1
BrowserMatch "Mozilla/4.[0-9]{2}" brokenvary=1
BrowserMatch "Opera" !brokenvary
SetEnvIfbrokenvary 1 force-no-vary
```

## 防止 SSL 证书警告

如果您只想在安全连接上提供您的网站，您需要获取一个**安全套接字层**（**SSL**）证书，浏览器将使用该证书来识别您的网站。如果证书上的域与传入请求上的域不匹配，例如，您为`https://secure.example.com`拥有 SSL 证书，而在该域上托管的页面上加载的资产是从`https://example.com`提供的，但所有文件都托管在同一个 Apache 服务器上；那么浏览器将抛出警告，并通知用户无法验证网页的真实性。

您可以确保对没有 SSL 证书的域的请求被重定向到您拥有 SSL 证书的域。如果需要，您可以取消注释以下代码片段：

```js
# <IfModule mod_rewrite.c>
#   RewriteCond %{SERVER_PORT} !⁴⁴³
#   RewriteRule ^ https://example-domain-please-change-me.com%{REQUEST_URI} [R=301,L]
# </IfModule>
```

以下是代码片段：

```js
<IfModule mod_rewrite.c>
RewriteCond %{SERVER_PORT} !⁴⁴³
RewriteRule ^ https://example-domain-please-change-me.com%{REQUEST_URI} [R=301,L]
</IfModule>
```

请注意，`https://example-domain-please-change-me.com`的 URL 需要指向您拥有 SSL 证书的域。

### 注意

有关 SSL 和 SSL 证书的更多详细信息，请参阅 Linux 文档项目中的`tldp.org/HOWTO/SSL-Certificates-HOWTO/x64.html`。

这涵盖了 HTML5 Boilerplate 的`.htaccess`文件提供的所有可选功能。让我们看看跨域策略以及如何设置它们。

## 您应该了解的跨域策略

当来自一个域的页面（例如`http://example.com`）需要来自另一个域（例如`http://foo.com`）的数据时，HTTP 请求被称为**跨域**请求。默认情况下，大多数浏览器不允许跨域请求数据，无论是数据还是 Flash 资产，以防止恶意访问。

但是，您可以在服务器上设置一个跨域策略文件（在上一个示例中，是从`http://foo.com`提供服务的服务器），允许浏览器访问这些资源。

Flash 需要在名为`crossdomain.xml`的文件中指定此策略文件，您可以在其中指定哪些域可以从服务器请求资产。

此文件包含在 HTML5 Boilerplate 中，默认情况下启用最严格的策略。如果您确实希望使用最不严格的策略，可以取消注释该选项，并注释掉最严格的选项。

### 注意

在放宽限制之前，确保充分了解允许跨域请求访问资产的影响。

您还可以通过设置 HTTP 标头来进行跨域 AJAX 请求，或限制对图像或字体的访问。这被称为**跨域资源共享**（**CORS**）策略。

## 跨域 AJAX 请求

只有在请求页面与请求数据的 URL 位于同一域上时，才能进行 AJAX 请求。CORS 是 HTML5 的一个新功能，允许您从任何域进行 AJAX 请求，前提是已经给予了请求域的权限。通过在服务器上设置一个 HTTP 标头，您可以克服这个限制。让我们看看如何做到这一点。

以下是您可以进行的跨域请求的示例：

```js
var CORSRequest = new XMLHttpRequest();
CORSRequest.onload = function(e){
  // Process returned data
}
CORSRequest.open('GET', 'http://nimbupani.com/data.json');
CORSRequest.send( null );
```

我们注意到浏览器会抛出错误，显示访问被禁止，如下面的截图所示：

![跨域 AJAX 请求](https://github.com/OpenDocCN/freelearn-html-css-zh/raw/master/docs/h5-blpt-webdev/img/8505_05_07.jpg)

现在，在我们托管在[`nimbupani.com`](http://nimbupani.com)上的`.htaccess`文件中，我们将取消注释以下指令：

```js
#  <IfModule mod_headers.c>
#    Header set Access-Control-Allow-Origin "*"
#  </IfModule>
```

让我们再试一下我们的代码。啊哈！现在可以了！

这是最不严格的设置，可以允许任何域在您的服务器上进行 AJAX 请求。由于这个原因，非常容易进行大量的请求，也可以假装是您的网站并欺骗访问者等。请谨慎使用此设置。

## 启用 CORS 的图像

通常，浏览器允许从任何其他域链接所有图像。这称为**热链接**。在`en.wikipedia.org/wiki/Inline_linking`上了解更多信息。如果一个高流量的网站链接到托管在您服务器上的资产，您的托管提供商甚至可能因为带宽的过度使用对您处以罚款（或者您的网站可能会崩溃！）。如果您想要阻止这种情况，例如，如果您不希望`http://example.com`使用指向您服务器上图像的`img`元素的`src`属性，您可以通过更改`.htaccess`文件中的以下行来启用更严格的策略：

```js
Header set Access-Control-Allow-Origin "*" env=IS_CORS
```

到以下行：

```js
Header set Access-Control-Allow-Origin "http://example.com" env=IS_CORS
```

在这里，用只允许访问该图像的域名替换`http://example.com`。服务器将阻止任何其他域访问您域上的图像。

如果您希望多个域访问您的图像，您将不得不编写一个复杂的正则表达式比较原点，如下面的代码片段所示：

```js
SetEnvIf Origin »
    "^http(s)?://(.+\.)?(example-1\.com|example-2\.com)$" origin_is=$0
  Header always set Access-Control-Allow-Origin %{origin_is}eenv=origin_is
```

在这种情况下，用您的域替换`example-1\.com`（注意在`.com`之前放置斜杠），同样适用于`example-2\.com`。

## Webfont 访问

大多数情况下，您将在与您将使用它们的相同域上托管字体。如果您在单独的域中托管字体，Firefox 将不会在没有正确的 HTTP 标头的情况下请求它们。这个指令已经在`.htaccess`文件中默认启用。如果您想要限制访问，您需要将这些行从以下内容更改：

```js
<IfModule mod_headers.c>
  <FilesMatch "\.(ttf|ttc|otf|eot|woff|font.css)$">
    Header set Access-Control-Allow-Origin "*"
  </FilesMatch>
</IfModule>
```

到以下代码片段：

```js
<IfModule mod_headers.c>
  <FilesMatch "\.(ttf|ttc|otf|eot|woff|font.css)$">
    Header set Access-Control-Allow-Origin "http://example.com"
  </FilesMatch>
</IfModule>
```

用您希望特别允许访问 Webfonts 的域名替换`http://example.com`。

### 注意

如果您想要了解 CORS 启用的图像、Webfont 和 AJAX 请求的工作原理，并了解与`crossdomain.xml`的区别，您应该阅读`code.google.com/p/html5security/wiki/CrossOriginRequestSecurity`上的 HTML5security 项目 wiki 页面。

# 使用其他服务器配置文件

我们已经看到了如何使用 Apache`.htaccess`文件中提供的功能。但是还有其他类型服务器的配置文件的存储库，如 Ngnix、Node、Google App Engine、IIS 和 Lighttpd。以下表格包含配置文件名及其对应的服务器软件：

| 配置文件名 | 服务器软件 |
| --- | --- |
| `.htaccess` | Apache Web 服务器在`httpd.apache.org/docs/2.2/howto/htaccess.html`上。 |
| `Web.config` | IIS Web 服务器在`learn.iis.net/page.aspx/376/delegating-configuration-to-webconfig-files/`上。 |
| `Node.js` | Node Web 服务器从`nodejs.org`。 |
| `Ngnix.conf` | Ngnix 服务器在`wiki.nginx.org/Configuration`上。 |
| `Lighttpd.conf` | Lighttpd 服务器在`redmine.lighttpd.net/projects/lighttpd/wiki/TutorialConfiguration`上。 |
| `App.yaml` 和 `gae.py` | Google App Engine 在`code.google.com/appengine/docs/python/config/appconfig.html`上。 |

这些服务器的配置文件可在`github.com/h5bp/server-configs`上找到。

## web.config

HTML5 Boilerplate 的`web.config`文件用于配置在 IIS7 服务器或更高版本上运行的站点的选项。

与`.htaccess`文件一样，将其放在您网站的根文件夹中，即可被识别并用于配置 IIS7 服务器。

## lighttpd.conf

与其他配置文件一样，将其放在 Lighttpd 服务器的根文件夹中以配置服务器。

## nginx.conf

Nginx 是一个轻量级服务器，受到使用 Ruby on Rails 框架的网站的欢迎。

与`.htaccess`文件一样，将此文件放在您网站的根文件夹中。此外，确保`nginx-mime.types`也在根文件夹中。这个文件是 Ngnix 所必需的，以确保它发送每个文件的正确 MIME 类型。

## node.js

对于`node.js`配置文件，使用方式不同。配置文件假定您正在使用 Express/Connect 框架来管理应用程序的资源请求。在服务器端应用程序代码中，您可以使用以下内容启动服务器：

```js
var h5bp = require('h5bp'); 
var app = express.createServer();
app.use(h5bp.server());
app.listen(3000);
```

这需要您使用 Node Package Manager（NPM）安装`h5bp`包和相同的`express`包。`h5bp`包有一系列配置，将在服务器启动时使用。如果您只想使用一些特定的配置，可以将它们作为选项传递给服务器函数，如下面的代码片段所示：

```js
app.use(h5bp.server({
server: true,
setContentType: true,
removeEtag: true
});
```

## Google App Engine

有些网站也是从 Google App Engine（[`code.google.com/appengine/`](http://code.google.com/appengine/)）提供的，这需要您的网站后端使用 Java、Python 或 Go 编写。

您需要确保`app.yaml`文件位于您网站的根文件夹中。

以下表格包含 HTML5 Boilerplate 服务器配置中所有功能的摘要：

| 功能名称 | Apache | Nginx | IIS | Lighttpd | Node.js | Google App Engine |
| --- | --- | --- | --- | --- | --- | --- |
| ETags | 是 | 是 | 是 | 是 | 否 | 否 |
| Gzip | 是 | 是 | 是 | 是 | 是 | 是 |
| 过期头 | 是 | 否 | 否 | 否 | 是 | 否 |
| 自定义 404 页面 | 是 | 是 | 是 | 否 | 否 | 否 |
| 强制使用最新的 IE 版本 | 是 | 是 | 是 | 是 | 是 | 是 |
| 使用 UTF-8 编码 | 是 | 是 | 是 | 否 | 否 | 否 |
| 提供正确的 MIME 类型 | 是 | 是 | 是 | 是 | 否 | 是 |
| 阻止访问隐藏文件夹 | 是 | 否 | 否 | 否 | 是 | 否 |
| 阻止访问备份和源文件 | 是 | 否 | 否 | 是（仅`~&.inc`） | 是 | 否 |
| 停止广告服务器信息 | 否 | 否 | 是 | 否 | 是 | 否 |
| 启动重写引擎 | 是 | 否 | 否 | 否 | 否 | 否 |
| 防止不存在的重定向文件夹出现 404 错误 | 是 | 否 | 否 | 否 | 否 | 否 |
| 抑制或强制 URL 开头的“www。” | 是 | 否 | 是 | 否 | 是 | 否 |
| 从 iFrames 设置 cookies | 是 | 否 | 是 | 否 | 否 | 否 |
| PHP 安全默认值 | 是 | 否 | 是 | 否 | 否 | 否 |
| 停止广告 Apache 版本 | 是 | 否 | 否 | 否 | 否 | 否 |
| 允许在 JS 和 CSS 文件中进行串联 | 是 | 否 | 是 | 否 | 否 | 否 |
| 在 CSS 滚动时停止 IE 中的屏幕闪烁 | 是 | 否 | 是 | 否 | 否 | 否 |
| 防止 SSL 证书警告 | 是 | 否 | 是 | 否 | 否 | 否 |
| 跨域 AJAX 请求 | 是 | 否 | 是 | 否 | 是 | 否 |
| 支持 CORS 的图像 | 是 | 否 | 否 | 否 | 否 | 否 |
| Webfont 访问 | 是 | 否 | 否 | 否 | 否 | 否 |

# 摘要

我们深入研究了在几个服务器和配置文件上提供页面的内部工作。我们查看了一些默认提供的良好配置以及一些可选配置，您可以通过仔细理解来启用它们。

现在我们的网站几乎准备好出门了，我们将看一些其他方法来使它变得更好。
