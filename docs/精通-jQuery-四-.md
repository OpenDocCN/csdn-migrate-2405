# 精通 jQuery（四）

> 原文：[`zh.annas-archive.org/md5/0EE28037989D2E7006D982EBB8295FFE`](https://zh.annas-archive.org/md5/0EE28037989D2E7006D982EBB8295FFE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十二章：使用 jQuery 与 Node-WebKit 项目

在这个现代化的时代，响应式设计是最新的热门词汇，使用 jQuery 构建的网站可以在任何设备或平台上正确工作。尽管如此，这需要一个互联网连接——如果我们可以开发一个同样的应用的离线版本呢？

进入 Node-WebKit（或现在称为 NW.js）。在本章中，我们将暂停探索 jQuery 并探索使用该库的较少知名的方式之一。你将看到如何利用 jQuery、HTML5 和桌面的强大功能，将它们混合在一起，以在任何桌面或笔记本环境中离线运行您站点的副本。我们将使用它来通过使用 jQuery 开发一个简单的文件大小查看器来进行一些有趣的开发，这可以轻松地开发成可以根据需要在线或离线运行的更复杂的内容。

在本章中，我们将涵盖以下主题：

+   介绍 Node-WebKit

+   构建一个简单的站点

+   打包和部署您的应用程序

+   深入了解

准备好探索 Node-WebKit 的世界了吗？让我们开始吧...

### 注意

你可能会在网上看到对 NW.js 的引用——这是自 2015 年 1 月以来 Node-WebKit 的新名称；在本章中，你可能会看到两个名称都被使用。

# 设置情景

想象一下情景，如果你愿意，客户要求你制作一个基于网络的应用程序；他们概述了一组特定的要求，如下所示：

+   它必须具有简单的 GUI

+   不应该有重复的内容——必须是一个适用于所有平台的版本

+   解决方案必须易于安装和运行

+   它需要是可移动的，以便在更换计算机时可以传输

如果你认为一个网站就足够了，请举手？现在，如果你没有仔细阅读需求，请举手...！

在这种情况下，一个网站是不够的；一个桌面应用程序将处理重复的要求，但可能不易使用，并且肯定不会跨平台。那么，我们从这里该怎么办呢？

# 介绍 Node-WebKit

Node-WebKit（或现在称为 NW.js）最初由英特尔创建，但在 2011 年开源，并可在 [`nwjs.io/`](http://nwjs.io/) 获取；该项目试图将 SPA 开发的优势与离线环境结合起来（在那里托管 Web 服务器并不实际）。

Node-WebKit 基于 Chromium，一个基于 WebKit 的浏览器进行了扩展，以便让你控制通常对 Web 开发人员不可用的用户界面元素。安全模型已经放宽（基于我们运行的代码是受信任的）并且它集成了 NodeJS；这打开了一系列的可能性，超出了 HTML5 API 的正常范围。

起初，这可能看起来像是一种复杂的混合。然而，请不要害怕，因为大多数最终解决方案仅由普通的 HTML、CSS 和 JavaScript 构建，最后加上一些图像来完成。

正如我们在本章中将要看到的，基本原理是生成一个普通的站点，然后将 HTML、CSS 和所有相关资源文件压缩成一个 ZIP 文件。我们只需将其重新命名为`.nw`扩展名，然后运行主要的`nw.exe`应用程序。只要我们已经设置了一个必需的`package.json`文件，它就会自动获取我们的应用程序并在屏幕上显示出来，如下所示：

![介绍 Node-WebKit](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00458.jpeg)

不过，这本书是关于 jQuery 的，对吗？是的，绝对是；这里就是最棒的部分：Node-WebKit 允许你运行标准的 JavaScript 和 jQuery，以及任何 Node 的第三方模块！这打开了各种机会；我们可以使用主要库或任何大量基于 jQuery 的附加库，比如 Three.js、AngularJS 或 Ember。

### 注意

我们真正需要记住的唯一关键部分是，使用 NW.js 有一些怪癖，比如使用文件夹对话框浏览和选择本地文件夹；我们稍后将在本章中更详细地介绍这一点。

此时，我相信你一定会问自己一个问题：为什么我要使用 nw.js（或 Node-WebKit）？这是一个非常合理的问题；我们以桌面应用程序的形式运行基于 Web 的站点可能看起来很不合逻辑！在这种明显的疯狂中，有一些合理的原因让我们这样做，所以让我们现在看一下它们，看看为什么将站点作为桌面应用程序运行是有意义的。

## 在桌面上运行 HTML 应用程序

作为开发人员，我们面临的最大头疼之一是确保用户在访问我们的站点时在所有需要支持的浏览器上拥有相同的体验。现在，我应该明确一点：在同样的体验方面，可能存在一些情况，这根本不可能实现，所以我们至少必须为那些不支持特定功能的浏览器提供一个优雅的退出路径。

幸运的是，这个问题正在逐渐减少。Node-WebKit 的好处在于，我们只需要支持 Chrome（因为 Node-WebKit 就是基于 Chrome 的）。

在大多数情况下，我们可以简单地重用为 Chrome 创建的代码；这使我们能够轻松地使用我们已经了解或使用的前端框架（包括 jQuery！）和 Node 模块推出跨平台应用程序。除此之外，还有几个原因可以让你使用 Node-WebKit 来帮助制作跨平台应用程序，如下所示：

+   访问 Blink 中提供的最新 Web 技术，Blink 是 Google Chrome 后面的渲染引擎。

+   NW.js 支持 *一次构建，到处运行* 的概念——这可能不适用于所有应用程序，但许多应用程序可以从在桌面、Web 和移动环境之间共享代码中受益。

+   如果你想让你的应用程序以特定大小运行或者在弹出窗口中做一些更高级的事情，你可以在桌面上获得这种控制。大多数解决方案还提供了一种访问文件系统并允许其他更高级控件的方式，这些是常规 Web 应用程序所不能提供的。

不想显得消极，但有一些需要注意的事项；主要关注的是可执行文件的大小。

使用原生 UI 库（如 jQuery）创建的站点或应用程序可能只有几千字节大小。使用 Node-WebKit 构建的等效版本会显著更大，因为它包含了一个精简版的 Node 和 Chromium。因此，你需要注意文件大小——你可以使用 第二章 *Customizing jQuery* 中的一些技巧来减小 jQuery 的大小。还有一些其他需要注意的问题；它们包括以下内容：

+   与原生应用程序相比，桌面 Web 应用程序通常需要更大量的 RAM 和 CPU 力量来运行和渲染。

+   在外观方面，如果你想要让你的应用程序在你计划部署的平台上看起来好看，那么你需要使用 CSS 重新创建常见的 UI 元素，或者创建一个全新的 UI，包括为每个操作系统提供的 UI 元素（如标题栏、菜单栏和上下文菜单）创建新的设计。

+   虽然 Node-WebKit 放宽了一些在使用浏览器应用程序时发现的安全问题（如同源策略），但你仍然只能访问 Node-WebKit 上下文；而且在某些情况下，你必须使用 WebKit 特定的标签，比如在创建选择目录对话框时使用 `nwdirectory`。最终效果是代码增加，如果你想要创建一个同时支持 Web 和桌面环境的文件。你可以缓解这个问题的影响：[`videlais.com/2014/08/23/lessons-learned-from-detecting-node-webkit/`](http://videlais.com/2014/08/23/lessons-learned-from-detecting-node-webkit/) 提供了一个有用的技巧来确定你所处的环境，并允许你引用该环境所需的适当文件。

### 注意

有关一些安全考虑的更多信息，请查看 NW.js Wiki 上的安全页面，网址为 [`github.com/nwjs/nw.js/wiki/Security`](https://github.com/nwjs/nw.js/wiki/Security)。

现在我们已经相互介绍了，让我们深入探讨并开始安装 Node，在我们开始构建基于 jQuery 的应用程序之前。值得注意的是，本章的重点将主要基于 Windows，因为这是作者使用的平台；对于使用 Linux 或 Mac 平台的人来说，需要进行一些更改。

# 准备我们的开发环境

在接下来的几页中，我们将构建一个简单的应用程序，该应用程序在主窗口中显示任何拖放的文件的文件大小，或者通过文件对话框选择。实际上，我们不会单独使用该应用程序，而是作为上传图像进行处理的基础，或者可能作为压缩应用程序的离线版本。我们有很多方法可以进一步开发它——我们将在本章后面的 *深入探讨* 部分中涉及一些想法。

与此同时，让我们开始安装 NW.js。在这之前，我们需要利用以下工具：

+   需要一个压缩程序；在 Windows 平台上，您可以使用内置功能或类似于 7-Zip ([`www.7-zip.org`](http://www.7-zip.org)) 的东西，如果更喜欢的话。

+   我们需要一个文本编辑器；在本章的过程中，我们将使用 Sublime 2 或 3，但如果您已经有个人偏爱，任何好的文本编辑器都应该足够。Sublime Text 可以从 [`www.sublimetext.com`](http://www.sublimetext.com) 下载，适用于 Mac、Linux 和 Windows 平台。

+   我们将利用 Node 和 Grunt 来安装额外的包。Node 可以在 [`www.nodejs.org`](http://www.nodejs.org) 上获得，所以请继续安装适合您平台的版本。安装完成后，请从 NodeJS 命令提示符中运行以下命令以安装 Grunt：

    ```js
    npm install -g grunt-cli

    ```

+   最后，但绝不是最不重要的，我们需要 Node-WebKit 库（当然），所以请访问 [`nwjs.io/`](http://nwjs.io/) 并下载适合您平台的版本。如果您展开文件夹，您应该会看到类似于此截图所示的内容：![准备我们的开发环境](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00459.jpeg)

顺便说一下，Node-WebKit 可以很容易地集成到现有的 Grunt 文件中，这意味着我们可以利用诸如`cssmin`之类的包来缩小我们为应用程序创建的 CSS 样式表。随着您对 Node-WebKit 的了解越来越深入，这绝对值得探索。

废话少说；是时候开始开发了！与其他事物一样，我们需要从某个地方开始。在我们看如何使用 jQuery 之前，让我们试试创建一个简单的 "Hello World" 示例。

# 安装和构建我们的第一个应用程序

我在想：你有多少次读过关于编程语言的书籍或在线文章，它们对无处不在的 "Hello World" 示例都提供了自己的见解？我敢打赌，这些年来肯定有不少次……是的，在你问之前，我们也不打算打破传统！在提供 "Hello World" 示例的任何人的脚步之后，这是我们自己的见解。

![安装和构建我们的第一个应用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00460.jpeg)

要构建这个，我们需要做以下事情：

1.  浏览到[`nwjs.io/`](http://nwjs.io/)并下载适用于您平台的软件包；我们暂时假设使用 Windows，但也有 Mac 和 Linux 平台的软件包可用。

1.  提取`node-webkit-vX.XX.XX-win-x64`文件夹（其中`XX`是版本号），将其重命名为`nodewebkit`，并将其复制到主 PC 驱动器——Linux 或 Mac 用户可以将此文件夹复制到他们的用户区域。完成后，在`nodewebkit`文件夹中创建一个名为`development`的新文件夹。

1.  接下来，我们需要安装 NodeJS。为此，请前往[`nodejs.org/download/`](http://nodejs.org/download/)以下载并安装适合您平台的版本，接受所有默认值。

Node-WebKit 可以使用任何可用的标准 Node 软件包。作为示例，我们将安装`markdown`包，该包将合适标记的纯文本转换为有效的 HTML。让我们继续安装它并看看它是如何工作的：

1.  在 NodeJS 命令提示符中，切换到`helloworld`文件夹，然后输入以下代码并按*Enter*：

    ```js
    npm install markdown

    ```

    ![安装和构建我们的第一个应用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00461.jpeg)

1.  关闭窗口，因为你不需要它。接下来，从附带本书的代码下载中的`helloWorld`文件夹中提取`index.html`和`package.json`文件的副本；将它们保存在项目区域中的`helloWorld`文件夹中。

1.  创建一个名为`helloWorld.zip`的新 ZIP 文件夹，然后将这两个文件添加到其中；将`helloWorld.zip`重命名为`helloWorld.nw`。

现在我们可以运行我们的应用程序了；有三种方式可以使用 Node-WebKit 来执行此操作：

+   在 NodeJS 命令提示符中，切换到`nodewebkit`文件夹，然后运行以下命令：

    ```js
    nw C:\nodewebkit\development\helloWorld.nw

    ```

+   双击`nw.exe`应用程序；这将拾取`package.json`文件并自动运行`helloworld.nw`文件

+   将`helloworld.nw`文件拖放到`nw.exe`上即可运行该应用程序

无论您喜欢使用哪种方式，运行它都会显示在本练习开始时显示的**Hello World**窗口。这是一个简单的、不带花哨的 Node-WebKit 使用示例——尽管它不会赢得任何奖项，但它展示了如何从现有 HTML 页面创建一个功能性应用程序是多么简单。

## 解析`package.json`文件

我们的应用程序的核心是`package.json`文件。这个清单文件告诉 Node-WebKit 如何打开应用程序，并控制浏览器的行为方式：

![解析`package.json`文件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00462.jpeg)

值得详细了解这个文件；它包含了项目的所有元数据，并遵循所有基于 Node 的软件包的标准格式。如果您不熟悉清单文件，您可以在[`browsenpm.org/package.json`](http://browsenpm.org/package.json)看到一个详细的示例，其中包含每个部分的交互式解释；Node-WebKit 的版本使用方式类似。

### 注意

关于 Node-WebKit 清单文件及其组成部分的更深入详细信息，请访问主 NW.js 站点上的文档 ([`github.com/nwjs/nw.js/wiki/manifest-format`](https://github.com/nwjs/nw.js/wiki/manifest-format))。

好的，现在是时候开始构建我们的示例应用程序了！

# 构建我们的简单应用程序

在接下来的几页中，我们将构建一个简单的应用程序，允许我们将文件拖放到拖放区域以渲染文件大小。它基于 Martin Angelov 的教程，可在 [`tutorialzine.com/2013/05/mini-ajax-file-upload-form/`](http://tutorialzine.com/2013/05/mini-ajax-file-upload-form/) 上获得；我们将专注于前端 UI 界面，并不考虑后端上传功能，以供我们的演示使用：

![构建我们的简单应用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00463.jpeg)

即使只是在前端用户界面上工作，仍然需要相当数量的代码；我们的重点将主要放在 jQuery 代码上，因此在更详细地探索之前，让我们先看一下演示的实际操作。要做到这一点，请执行以下步骤：

1.  在我们的演示中，我们使用了一小部分 PHP 代码，因此我们首先需要设置 Web 服务器空间，如 WAMP（适用于 PC—[`www.wampserver.de/en`](http://www.wampserver.de/en)）或 XAMPP（或 MAMP 适用于 Mac—[`www.mamp.info/en`](http://www.mamp.info/en)）。Linux 用户将在其发行版中获得某种可用内容。我们将在此演示中使用 WAMP—如果您的情况不同，请相应调整位置；在安装时使用默认设置。如果您喜欢跨浏览器解决方案，则 XAMPP 是一个不错的选择—它可在 [`www.apachefriends.org/index.html`](https://www.apachefriends.org/index.html) 上获得。

1.  接下来，我们需要从附带本书的代码下载中提取一个`FileSizeView`文件夹的副本。这包含了我们应用程序所需的标记。将文件夹保存在`C:\wamp\www`中。

1.  我们需要一个 Node-WebKit 的副本来运行我们的应用程序，所以请复制代码下载中的`nwjs`文件夹的内容到`FileSizeView`文件夹中。如果一切正常，您应该看到如下所示的文件：![构建我们的简单应用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00464.jpeg)

1.  在此阶段，如果我们双击`nw.exe`，我们应该可以看到我们的应用程序运行。另外，您将看到在本练习开始时显示的窗口。

好的，它显示了窗口；“它是如何工作的”，我听到你在问？嗯，从这个练习中有一些关键点需要注意，所以让我们花些时间更详细地讨论一下。

## 进一步探索我们的演示

如果您仔细查看`FileSizeView`文件夹，您会发现大部分内容围绕着`index.html`和`upload.php`文件展开，还有为使演示工作所需的相关 CSS、图像和 JavaScript 文件。此外，我们还有一些来自 Node-WebKit 文件夹的文件，这些文件提供了 Node 和 Chromium 的精简版本，用于托管我们的文件：

+   `nw.exe` 和 `nw.pak`：这是主要的 Node-WebKit 可执行文件和 JavaScript 库文件，分别运行我们的代码。

+   `package.json`：这是一个清单文件，在本章早些时候的*安装和构建我们的第一个应用程序*部分中就使用过；它向 Node-WebKit 提供了如何显示我们应用程序的指示。

+   `ffmpegsumo.dll`：用于提供视频和音频支持；对于我们的演示来说并不是必需的，但可以用于将来使用。

+   `filesizeview.nw`：这是我们打包的应用程序；这是 Node-WebKit 在检查`package.json`以验证应如何显示后运行的文件。

+   `gruntfile.js`：这是用于`grunt-node-webkit-builder`的 Grunt 文件，我们稍后会在*自动化流程*中使用它将我们的文件编译成一个应用程序。

+   `icudtl.dll`：这是 Node-WebKit 所需的网络库。

+   `libEGL.dll`和`libGLESv2.dll`：这些文件用于**Web 图形库**（**WebGL**）和 GPU 加速。

在一些可在线使用的 Node-WebKit 应用程序中，您可能会看到`D3DCompiler_43.dll`和`d3dx9_43.dll`文件。这些来自 DirectX 可再发行包，用于提供增强的 WebGL 支持。

## 解剖我们的内容文件

好的，那么我们有我们的主要 Node-WebKit 文件；我们还使用了什么呢？除了标准的 HTML 标记、图像和样式外，我们还使用了许多基于 jQuery 的插件和一些自定义的 jQuery 代码进行连接。

使用的主要插件文件是 jQuery、jQuery UI、jQuery Knob 和 BlueImp 文件上传插件。我们还使用一些自定义代码将它们组合在一起——它们位于`window.js`和`script.js`中。让我们更详细地查看这些，从`window.js`开始。

### 探究`window.js`

在`window.js`中，我们首先调用`nw.gui`，这是 Node-WebKit 的本机 UI 库，使用了`require()`；这是调用任何模块（如内部模块或外部第三方模块）的标准格式。然后我们将这分配给`gui`变量，然后使用它来获取我们应用程序窗口的句柄：

```js
var gui = require('nw.gui'), win = gui.Window.get();
```

需要注意的是，由于我们只能访问 Node-WebKit 上下文，我们必须使用专用库；我们无法通过标准的 JavaScript 调用访问窗口。

### 提示

要获取有关访问模块的更多信息，请查看位于[`github.com/nwjs/nw.js/wiki/Using-Node-modules`](https://github.com/nwjs/nw.js/wiki/Using-Node-modules)上的文档。

接下来，我们设置了两个委托文档处理程序，一个用于处理窗口的最小化，另一个用于完全关闭它：

```js
$(document).on('click', '#minimize', function () {
  win.minimize();
});

$(document).on('click', '#close', function () {
  win.close();
});
```

这只是我们可以做的一小部分；还有很多。前往[`github.com/nwjs/nw.js/wiki/Window`](https://github.com/nwjs/nw.js/wiki/Window)了解我们可以实现的可能性。

### 解析 BlueImp 插件配置

我们站点的主要功能是在`script.js`中托管的。它包含 BlueImp 文件上传插件的主配置对象以及一些额外的辅助函数。让我们更详细地看一下。

我们从常规的文档准备调用开始，然后将`#upload li`列表项的引用分配给一个变量，如下所示：

```js
$(function(){
  var ul = $('#upload ul');

  $('#drop a').click(function(){
    // Simulate a click on the file input button
    // to show the file browser dialog
    $(this).parent().find('input').click();
  });
```

接下来，我们配置文件上传插件。首先，我们将初始拖放区域设置为`#drop`选择器：

```js
  // Initialize the jQuery File Upload plugin
  $('#upload').fileupload({

    // This element will accept file drag/drop uploading
    dropZone: $('#drop'),
```

然后，我们设置`add`回调函数。这个函数负责显示已添加到列表中的每个列表项，无论是通过拖放还是通过浏览文件。我们首先创建一个模板，然后将其缓存在`tpl`变量中：

```js
  add: function (e, data) {
    var tpl = $('<li class="working"><input type="text" value="0" data-width="48" data-height="48"'+ ' data-fgColor="#0788a5" data-readOnly="1" data- bgColor="#3e4043"/><p></p><span></span></li>');
```

我们接着找到刚刚添加的文件名，然后计算并附加`filesize`函数到列表中：

```js
    tpl.find('p').text(data.files[0].name).append('<i>' + formatFileSize(data.files[0].size) + '</i>');

    // Add the HTML to the UL element
    data.context = tpl.appendTo(ul);
```

接下来，我们初始化 jQuery Knob 插件。虽然现在它还没有运行，但它将产生一个良好的圆形状态表，显示上传任何文件到远程位置的进度：

```js
    // Initialize the knob plugin
    tpl.find('input').knob();
```

目前，我们没有使用取消图标。这将是我们需要使用的事件处理程序，以确定是否在某个项目正在进行时取消上传：

```js
    tpl.find('span').click(function(){

      if(tpl.hasClass('working')){
        jqXHR.abort();
      }

      tpl.fadeOut(function(){
        tpl.remove();
      });
    });

    // Automatically upload the file once it is added to the queue
    var jqXHR = data.submit();
  },
```

这是`fileupload`对象内的关键方法处理程序。它负责在触发更改更新 jQuery Knob 插件之前，计算文件上传进度的百分比值，如下所示：

```js
  progress: function(e, data){
    var progress = parseInt(data.loaded / data.total * 100, 10);
    data.context.find('input').val(progress).change();
    if(progress == 100){
      data.context.removeClass('working');
    }
  },
```

如果文件上传失败，我们将设置一个`.error`类，这在附带的样式表中有适当的样式：

```js
  fail:function(e, data){
    // Something has gone wrong!
    data.context.addClass('error');
  }
});
```

除了主要的`fileupload`配置对象之外，我们还设置了一些辅助函数。第一个辅助函数阻止了正常操作，如果我们拖动任何内容到文档对象上，将尝试在浏览器窗口中显示它：

```js
$(document).on('drop dragover', function (e) {
  e.preventDefault();
});
```

第二个辅助函数处理文件大小从字节值转换为其对应的千字节、兆字节或千兆字节，然后返回用于在屏幕上渲染的值：

```js
function formatFileSize(bytes) {
  if (typeof bytes !== 'number') {
    return '';
  }

  if (bytes >= 1000000000) {
    return (bytes / 1000000000).toFixed(2) + ' GB';
  }

  if (bytes >= 1000000) {
    return (bytes / 1000000).toFixed(2) + ' MB';
  }

  return (bytes / 1000).toFixed(2) + ' KB';
  }
});
```

目前，我们的项目肯定有改进的空间：它可以在普通浏览器窗口中正常工作，但需要修改以使其在 Node-WebKit 环境中 100%正常运行。我们稍后将在*进一步探讨*部分讨论一些改进代码的想法，但现在，在我们考虑调试应用程序之前，有一个重要的提示需要说明。

### 自动创建我们的项目

我在本书中试图保持的一个关键主题是我们如何更聪明地做事；任何人都可以编写代码，但更聪明的开发者知道何时是时候自动化一些更乏味的任务，并将他们的时间用在能够带来更多价值的任务上。

我们可以改进创建和构建项目的方法之一是自动化生成我们的骨架项目。幸运的是，我们可以使用 Yeoman generator for node-webkit 应用程序（可在 [`github.com/Dica-Developer/generator-node-webkit`](https://github.com/Dica-Developer/generator-node-webkit) 找到），我们可以使用以下命令安装：

```js
npm install -yeoman

```

前面的命令后面是这样的：

```js
npm install –g generator-node-webkit

```

这显示了以下屏幕截图，显示了为测试项目输入详细信息的过程：

![自动化创建我们的项目](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00465.jpeg)

如果一切顺利，你应该看到预定义的文件夹结构已经就位，可以供你使用，如下图所示：

![自动化创建我们的项目](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00466.jpeg)

这样做会更容易创建所需的文件夹结构并在项目中保持一致性。

## 调试你的应用程序

此时，你应该有一个可以部署的工作应用程序。虽然必须说我们的应用程序在发布前还需要更多的工作，但是部署背后的原理是相同的，不论应用程序如何！在我们看部署之前，有一件小事我想讲一下。

还记得我在本章中提到 Sublime Text 将被广泛使用吗？这是有充分理由的：它非常适合构建应用程序，以至于我们可以运行和调试应用程序。为此，我们需要为 Sublime Text 创建一个新的构建系统文件（例如以下所述的 Windows）：

```js
{
  "cmd": ["nw.exe", "--enable-logging", "${project_path:${file_path}}"],
  "working_dir": "${project_path:${file_path}}",
  "path": "C:/Tools/nwjs/",
  "shell": true
}
```

为 Sublime 添加新的构建文件的过程很快—具体细节，请访问 [`github.com/nwjs/nw.js/wiki/Debugging-with-Sublime-Text-2-and-3`](https://github.com/nwjs/nw.js/wiki/Debugging-with-Sublime-Text-2-and-3)。在开发应用程序时使用这个技巧是很有用的，因为手动构建过程可能会变得非常乏味！

# 打包和部署你的应用程序

好了，我们有一个可以打包和部署的工作应用程序；我们如何将其转化为可以提供下载的内容？

打包 Node-WebKit 应用程序出奇的简单。有一些注意事项，但主要过程是将所有的 Node-WebKit 可分发文件和我们的内容一起放入一个文件夹中，然后将其作为重命名的压缩文件发布。

有几种不同的方法可以打包我们的文件，这取决于所使用的平台。让我们看看在 Windows 平台上使用一些选项的情况，首先是手动编译。

### 注意

对于那些使用苹果 Mac 或 Linux 的人，有关如何打包应用程序的详细信息，请访问[`github.com/rogerwang/node-webkit/wiki/How-to-package-and-distribute-your-apps`](https://github.com/rogerwang/node-webkit/wiki/How-to-package-and-distribute-your-apps)。

## 手动创建软件包

假设我们已经准备好部署我们的应用程序，这些是手动创建软件包时要遵循的基本步骤——对于此示例，我们将使用*构建我们的简单应用程序*部分中早期创建的文件：

1.  创建一个新的空 ZIP 文件，并添加`package.json`、`ffmpegsumo.dll`、`icudtl.dat`、`libEGL.dll`、`libGLESv2.dll`和`nw.pak`文件——这些文件是在 Chromium 和 Node 的精简版本中托管站点所需的。

1.  将`css`、`img`和`js`文件夹以及`index.html`添加到 ZIP 文件中。

1.  将 ZIP 文件重命名为`.nw`文件，然后运行`nw.exe`——这将使用`package.json`文件来确定应该运行什么。

### 注意

请注意，Node-WebKit 软件包不保护、混淆、数字签名或使软件包安全；这意味着，将您的软件包开源是一个更好的选择，即使只是为了避免任何与许可证相关的问题！

## 自动化过程

等等，创建一个软件包是一个手动过程，如果我们要添加很多更改，那么这个过程会变得很乏味，对吗？

绝对，智能的前进方式是自动化这个过程；然后，我们可以将其与 Grunt 软件包结合起来，例如`grunt-contrib-watch`（来自[`github.com/gruntjs/grunt-contrib-watch`](https://github.com/gruntjs/grunt-contrib-watch)），以便在进行任何更改后立即构建我们的软件包。有几种自动化的方法——我个人最喜欢使用`grunt-node-webkit-builder`，来自[`github.com/mllrsohn/grunt-node-webkit-builder`](https://github.com/mllrsohn/grunt-node-webkit-builder)。

### 注意

node-webkit-builder 插件由与 grunt-node-webkit-builder 背后的开发人员相同的开发人员创建；唯一的区别是，后者对与 Grunt 一起使用的额外支持。如果您想切换到使用 Grunt，您可以安装一个补充包，`grunt-node-webkit-builder-for-nw-updater`，可在[`www.npmjs.com/package/grunt-node-webkit-builder-for-nw-updater`](https://www.npmjs.com/package/grunt-node-webkit-builder-for-nw-updater)上找到。

让我们看看插件的运行情况——在继续演示之前，假设您已经安装了 NodeJS：

1.  在项目文件夹中的一个新文件中，添加以下代码并将其保存为`gruntfile.js`：

    ```js
    module.exports = function(grunt) {

      grunt.initConfig({
        nodewebkit: {
          options: {
            platforms: ['win'],
            buildDir: './builds',
            winIco: './img/filesize.ico'
          },
          src: ['./css/*.css', './img/*.*', './js/*.js', '*.html', '*.php', '*.json', '*.ico']
        }
      })

      grunt.loadNpmTasks('grunt-node-webkit-builder');
      grunt.registerTask('default', ['nodewebkit']);
    };
    ```

1.  接下来，我们需要安装 grunt-node-webkit-builder；因此，请启动 NodeJS 命令提示符的一个实例，然后导航到我们之前在*构建我们的简单应用程序*部分中使用过的项目文件夹。

1.  输入此命令，然后按*Enter*，等待其完成：

    ```js
    Npm install grunt-node-webkit-builder --save-dev

    ```

1.  在`package.json`文件中，您会看到已添加了以下行，如下所示：

    ```js
      "icon": "img/filesize.png"
      },
     "devDependencies": {
     "grunt": "~0.4.5",
     "grunt-node-webkit-builder": "~1.0.2"
     }
    }
    ```

    ### 提示

    如果您需要查看 `package.json` 将会是什么样子，请转到 [`github.com/3dd13/sample-nw`](https://github.com/3dd13/sample-nw)。有一个样本文件位于 [`github.com/3dd13/sample-nw/blob/master/package.json`](https://github.com/3dd13/sample-nw/blob/master/package.json)，显示了我们刚刚输入到我们自己版本文件中的代码的内容。

1.  在此阶段，我们现在准备构建我们的包。在提示符处，键入 `grunt`，然后等待它完成；您应该看到它构建了包，如下面的截图所示：![自动化过程](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00467.jpeg)

1.  如果您回到我们的文件存储的文件夹，现在应该可以看到一个名为 `builds` 的文件夹已经出现了；在其中导航将会显示类似于此截图的内容，在其中显示了 `win64` 构建文件夹的内容：![自动化过程](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00468.jpeg)

    在此阶段，我们可以双击 `FileSizeView.exe` 应用程序来启动该程序。这将以所有荣耀展示我们的应用程序，准备好使用。完美！我们现在可以部署文件了，对吧？

## 部署您的应用程序

嗯…慢点；你现在应该知道，我们总是可以做得更好！

绝对可以；在这种情况下，更好的方式是创建一个设置安装程序，这样我们只需要分发一个单个文件。这样更容易处理！它还有额外的好处，可以进一步压缩文件；在我们的示例中，使用开源的 Inno Setup 软件包，结果从大约 80 MB 降低到约 30 MB。让我们看看为在 Windows 平台上生成安装文件所需的内容：

1.  我们首先需要下载并安装 Inno Setup。前往 [`www.jrsoftware.org/isinfo.php`](http://www.jrsoftware.org/isinfo.php)，然后点击 **下载 Inno Setup**；`setup.exe` 文件可以从页面中部的表格中下载。

1.  双击 `setup.exe` 文件并完成流程，接受所有默认设置。

1.  在我们的项目文件夹中，我们需要创建一个名为 `setup` 的新文件夹。这将存储用于 Inno Setup 的源脚本和最终构建的文件。

1.  从代码下载中，继续提取 `filesizeview-1.0.iss` 并将其存储在 `setup` 文件夹中。

1.  双击文件以启动它，然后点击下面的高亮图标，如下面的截图所示，编译构建文件：![部署您的应用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00469.jpeg)

1.  完成后，Inno Setup 将自动启动新创建的安装程序，如此处所示：![部署您的应用程序](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00470.jpeg)

现在我们可以跟随安装过程直至完成，在愤怒中使用该应用程序之前。 Inno Setup 还通过包含一个 `unins000.exe` 文件来处理卸载过程，如果我们需要从系统中移除应用程序，我们可以使用它。

对于那些使用 Mac 的人，可能会有类似的软件包可用。作为起点，请尝试[`www.codepool.biz/tech-frontier/mac/make-pkg-installer-on-mac-os-x.html`](http://www.codepool.biz/tech-frontier/mac/make-pkg-installer-on-mac-os-x.html)中列出的说明。您还可以尝试在 Linux 上使用 Wine 使用 Inno Setup，说明列在[`derekstavis.github.io/posts/creating-a-installer-using-inno-setup-on-linux-and-mac-os-x/`](http://derekstavis.github.io/posts/creating-a-installer-using-inno-setup-on-linux-and-mac-os-x/)，尽管它们不适合初学者！

# 接下来的事情

哎呀！在过去的几页中，我们确实覆盖了很多内容！

但是，在生活的大计划中，我们只是触及了表面。我们可以在我们的应用程序中做更多的事情，甚至可以探索它来帮助我们在使用 Node-WebKit 和 jQuery 时提高技能。为了让你开始，这里有一些想法：

+   该应用程序是调整图像大小甚至压缩它们的理想基础；我们可以在线完成这些操作，但有一些影响，主要是关于保密性和图像大小的问题。

+   上传功能只有部分可用。我们使用 BlueImp 文件上传插件，但它实际上并没有做任何事情。在我们的应用程序中让它正常工作怎么样？

+   如何显示文件类型的图标，甚至是如果我们上传的是图像的小缩略图？

+   没有办法在不重新启动应用程序的情况下清除列表——修复这个问题应该很容易……

+   我们故意没有包括任何错误检查，以保持事情简单；现在加入一些如何？

+   我认为界面在某种程度上有些受限制：如果我们上传一个文件名非常长的文件，那么它就会被截断；截断有点混乱！

+   我们还没有添加任何菜单控件。虽然 Node-WebKit 非常适合速度不是问题的应用程序，但一旦我们添加了更多功能，能够进行导航仍然是很好的。要了解如何添加这样的菜单的示例，请参阅[`www.4elements.com/blog/2013/12`](http://www.4elements.com/blog/2013/12)。

希望在这里你能找到一些启发你进一步学习的想法。一旦掌握了基础知识，并允许我们必须使用 Node 特定标签的场合，就没有限制了！相当多的人已经制作了各种复杂性的应用程序并将它们发布在网上——一定要在网上进行一些研究，看看有什么可用的。以下是一些想法：

+   爱尔兰开发人员 Shane Gavin 创建了一个有用的基于视频的教程，介绍了使用 Node-WebKit 的方法。这探讨了在创建 Node-WebKit 应用程序时可以使用的一些技术，我们在我们的示例中使用了其中一些技术。教程可在[`nodehead.co`](http://www.nodehead.co)找到。

+   我相信我们都听说过或以某种形式玩过*乒乓球*或*打砖块*等游戏。我们可以使用 Phaser 游戏库在[`phaser.io`](http://phaser.io)上制作一些经典游戏（以及其他游戏）。看一看在[`github.com/kandran/pong`](https://github.com/kandran/pong)上展示的示例，该示例使用 Node-WebKit 创建了*乒乓球*。

+   David Neumann 写了一篇关于如何将免费教育游戏*Caterpillar Count*重新打包以在 Node-WebKit 中运行的博客文章；撇开游戏的性质不谈，这篇文章强调了一些关于转移过程的有用提示和技巧（[`blog.leapmotion.com/building-applications-for-simultaneous-deployment-on-web-and-native-platforms-or-how-i-learned-to-stop-worrying-and-love-node-webkit/`](http://blog.leapmotion.com/building-applications-for-simultaneous-deployment-on-web-and-native-platforms-or-how-i-learned-to-stop-worrying-and-love-node-webkit/)）。

+   对使用 HTML5 和 Node-WebKit 尝试你的网络摄像头感兴趣吗？去[`webcamtoy.com/`](http://webcamtoy.com/)吧——将标准代码调整为从 Node-WebKit 工作应该相对容易，因为它支持`getUserMedia`。

+   如果我们要处理视频或网络摄像头，我们可以考虑截图。有一个可用于 Node-WebKit 的包来帮助实现这一点（[`www.npmjs.com/package/node-webkit-screenshot`](https://www.npmjs.com/package/node-webkit-screenshot)）；它可以很容易地成为一个有用的小应用程序的基础。

+   我们之前讨论过使用其他 JavaScript 库，例如 Ember 或 Angular，这些库可以轻松与 Node-WebKit 和 jQuery 一起使用——有两个例子，你可以访问[`www.sitepoint.com/building-chat-app-node-webkit-firebase-angularjs/`](http://www.sitepoint.com/building-chat-app-node-webkit-firebase-angularjs/)和[`sammctaggart.com/build-a-markdown-editor-with-node-webkit-and-ember/`](http://sammctaggart.com/build-a-markdown-editor-with-node-webkit-and-ember/)。

现在网上的内容越来越多。图书馆最近进行了一些名称更改（如前所述），所以如果你想了解更多关于使用 Node-WebKit 的信息，那么值得搜索 Node-WebKit 和 NW.js 两个词以确保全面覆盖。

# 总结

近年来，在线和离线应用之间的分界线变得模糊，许多人使用移动设备访问互联网来代替正常的桌面浏览器。随着 Node-WebKit 的出现，这进一步扩大了许多融合这些界限的机会——让我们回顾一下我们在过去几页学到的东西。

我们以似乎是一个典型简单请求开始，大多数开发人员将自动考虑设计一个网站。然而，随着 Node-WebKit 的引入，我们可以探索创建我们的应用程序或网站的离线版本。我们稍微探讨了一下库的工作原理，以及从桌面运行这种应用程序的利弊。

接着，我们开始准备开发环境，然后简要介绍了安装 Node-WebKit 并使用它创建我们的第一个应用程序。我们深入研究了 `package.json` 文件，这对于运行我们的应用程序至关重要，然后开始构建我们的文件大小查看器应用程序。接下来更深入地看了应用程序背后使用的代码；我们还介绍了如何使用 Yeoman Node-WebKit 生成器创建应用程序的基本框架。

接着，我们看了一个快速调试 Node-WebKit 应用程序的小窍门，然后继续研究如何手动打包和部署应用程序，或者使用 Grunt 自动化部署它们。我们旅程的最后阶段涵盖了应用程序的部署。我们研究了使用 Inno Setup 生成 `setup.exe` 文件以供部署使用。然后我们在章节结束时看了一些在使用 Node-WebKit 开发时可以进一步发展的想法。

哎呀！我们确实涵盖了很多内容，但正如他们常说的那样，恶人永无休息之日。在下一章中，我们将重点研究 jQuery 使用中最重要的部分之一：优化和提高项目性能。


# 第十三章：第 13 章：在 jQuery 中增强性能

到目前为止，我们在书中涵盖了一系列不同的主题：从定制 jQuery 到使用动画，甚至是在 Node-WebKit 中使用 jQuery。

但是，有一个关键的主题我们还没有涉及。虽然使用 jQuery 可能非常令人满意，但我们必须注意在实际情况下优化我们的代码，以确保用户体验良好。许多开发人员可能只是目测代码，但这是耗时的。在本章中，我们将探讨优化 jQuery 代码的方法，介绍可以补充现有工作流程并帮助实际反馈你的更改的工具。我们将在本章中涵盖一些主题，其中将包括：

+   了解为什么性能很重要

+   添加元素时监视性能

+   监视 jQuery 的速度

+   自动化性能监控

+   使用 Node 自动清理我们的代码

+   实施增强性能的最佳实践

+   考虑使用 jQuery 的情况

准备好开始了吗？

### 注意

在本章中，我们将集中讨论使用 jQuery——你会发现很多给出的建议也可以应用于纯 JavaScript，在你的代码中更多地使用它（正如我们稍后在本章中将讨论的那样）。

# 了解为什么性能至关重要

想象一下情景——你的团队使用最新技术创建了一个杀手级的基于 Web 的应用程序，可以做任何事情，你准备坐下来享受成功的荣誉。除了一个小但相当关键的事情……

没有人购买。你的应用程序没有一个副本被售出——原因是什么？简单——它非常缓慢，而且没有经过适当的优化。在这个移动设备时代，一个慢速的应用程序将会让用户失去兴趣，无论你怎么推销。

我们应该关注应用程序的性能吗？绝对是！有很多理由要对我们应用程序的性能持批评态度；让我们来看几个：

+   移动设备的出现以及与之相关的上网成本意味着我们的内容必须经过优化，以确保网站在连接超时之前快速显示

+   将注意力集中在开发上而不是解决跨浏览器问题是非常容易的——每个怪癖本身可能并不多，但累积起来的影响很快就会显现出来。

+   一旦你开始编写经过深思熟虑的代码，那么它很快就会成为第二天性

当然，必须说的是，存在过早优化的风险，即我们花费大量时间为小收益优化代码，甚至在以后删除后可能会给自己带来问题的代码！

好吧，假设我们有优化代码的余地，我们应该怎么做呢？嗯，我们可以使用一些技巧；虽然我们可能渴望不辞劳苦地优化我们的代码，但并不总是值得这样做。更明智的方法是始终考虑整体情况，确保通过糟糕的样式表或大图像而失去了优化脚本的好处，例如！

让我们花一点时间考虑一下我们可用的一些选项——它们包括：

+   构建自定义版本的 jQuery

+   对我们的脚本进行最小化处理

+   调整选择器的使用

+   在事件冒泡中谨慎行事

+   持续使用适当的工具来检查我们的代码

+   最小化 DOM 操作

这些是我们可用的一些选项。不过，我们首先要做的是对我们的代码进行基准测试，以了解在进行任何更改之前它的性能如何。这个过程的第一步是对我们的脚本运行性能检查。让我们花一点时间来看看涉及到什么以及这是如何运作的。

# 使用 Firebug 监控 jQuery 速度

我们可以大谈性能的重要性，但没有什么比亲眼看到它并弄清楚我们如何改进代码以获得额外优势更好。手动确定何处进行更改是耗时且低效的。相反，我们可以利用一些工具来更清晰地指示我们代码中的问题所在。

有数十种工具可用于帮助我们对页面性能进行基准测试，其中包括与 jQuery 或基于 jQuery 的脚本和插件的交互。在接下来的几页中，我们将介绍一系列不同的方法。让我们从一个简单的可视检查开始，使用 Firebug，从 [`www.getfirebug.com`](http://www.getfirebug.com)。安装完成后，单击 **Net** | **JavaScript**，然后加载您的页面以获取有关加载到页面上的每个插件或脚本的统计信息。

在下面的图像中，我们可以看到来自 Packt Publishing 网站的结果：

![使用 Firebug 监控 jQuery 速度](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00471.jpeg)

相比之下，以下是从 [`www.jquery.com`](http://www.jquery.com) 显示的结果的图像：

![使用 Firebug 监控 jQuery 速度](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00472.jpeg)

### 提示

在加载页面之前，清除缓存以避免结果出现偏差。

从 Firebug 返回的统计信息为我们提供了一个良好的开端，但要更好地了解瓶颈在哪里，我们需要对我们的代码进行分析。幸运的是，使用控制台来优化代码非常简单。让我们看看如何使用控制台来优化代码，使用我们在第十一章中创建的 `tooltipv2.html` 演示的副本为例，*Authoring Advanced Plugins*。为了这个小演示的目的，我们将从本地 Web 服务器（如 WAMP）运行它：

1.  从代码下载中提取一个 tooltip 演示文件夹的副本，并将其存储在 WAMP 的 `www` 文件夹中。

1.  在`tooltipv2.js`中，按照下面的示例修改前几行代码 - 这样可以添加调用以分析我们的代码：

    ```js
    $(document).ready(function() {
      console.profile();
      $('#img-list li a.tooltips').quicktip({
    ```

1.  我们需要告诉浏览器何时停止分析，所以请继续按照下面的代码进行修改：

    ```js
      })
      console.profileEnd();
    });
    ```

1.  在浏览器中加载`tooltipv2.html`，然后打开 Firebug。如果一切顺利，我们应该会看到类似以下屏幕截图的内容，在其中我们看到了简要的配置文件报告的前几行：![使用 Firebug 监控 jQuery 速度](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00473.jpeg)

使用诸如 Firebug 这样的工具分析我们的网站可能会非常有启发性。想象一下，如果我们添加了更多的选择器会怎样，其中一些数字可能会比现在高得多。

### 提示

如果你只想关注花费的时间，与其使用`console .profile()`，不如改用`console.time()`和`console.timeEnd()`。

有许多工具可用于分析我们的网站。并非所有工具都专用于 jQuery，但它们仍然可以用于了解我们的脚本执行情况。以下是一些你可以尝试的示例，除了经典网站如[JSPerf.com](http://JSPerf.com) ([`www.jsperf.com`](http://www.jsperf.com))之外：

+   JSLitmus，来自[`code.google.com/p/jslitmus/`](http://code.google.com/p/jslitmus/)

+   BenchmarkJS，位于[`benchmarkjs.com/`](http://benchmarkjs.com/)，或者从 NPM 站点 [`www.npmjs.com/package/benchmark`](https://www.npmjs.com/package/benchmark)获取 - 一个如何使用它的示例可在[`gist.github.com/brianjlandau/245674`](https://gist.github.com/brianjlandau/245674)找到

+   在线服务，例如 SpeedCurve ([`www.speedcurve.com`](http://www.speedcurve.com)) 或 Calibreapp ([`calibreapp.com/`](https://calibreapp.com/))

+   FireQuery Reloaded，来自[`github.com/firebug/firequery/wiki`](https://github.com/firebug/firequery/wiki)，即将推出；请注意，写作时仍处于测试版阶段

+   DeviceTiming，来自[`github.com/etsy/DeviceTiming`](https://github.com/etsy/DeviceTiming)

绝对有大量选择可供使用 - 并非所有选择都适合每个人的需求；关键是要了解你正在测试什么，并学会如何解释它。

jQuery 核心团队成员 Dave Methin 写了一篇精彩的文章，概述了在没有正确解释来自诸如 JSPerf 使用结果的情况下盲目尝试优化代码的危险。开发者 Fionn Kelleher 在他指出，你的代码应该是一种艺术品 - 没有必要为了做而优化所有东西；更重要的是代码应该是可读的并且运行良好。

好吧 - 是时候继续了。我们已经介绍了监控的基础知识，但这是以手动方式为代价的。一个更好的选择是自动化。我们可以使用许多工具来实现这一点，与我们的老朋友 Grunt 一起，所以让我们深入了解一下，看看自动化监控涉及哪些内容。

# 自动化性能监控

举手之劳，作为一名开发者，有多少人使用过 YSlow？很好——相当多；不过，你有没有考虑过自动化这些检查呢？

没错！我们总是可以手动检查以了解性能瓶颈出现的位置；然而，更聪明的方法是使用我们的好朋友 Grunt 自动化这些检查。开发者 Andy Shora 创建了一个模块，专门用于此目的；我们可以从[`github.com/andyshora/grunt-yslow`](https://github.com/andyshora/grunt-yslow)获取它的源代码。让我们花点时间来让它运行起来，看看它是如何工作的：

1.  让我们开始创建一个用于存放文件的项目文件夹。为了本练习的目的，我假设它叫做`chapter13`（是的，我知道——非常原创）；如果你的名称不同，请更改。

1.  对于本练习，我们需要使用 NodeJS。我假设你已经从之前的练习中安装了它；如果没有，请访问[`www.nodejs.org`](http://www.nodejs.org)下载并安装适合你平台的版本。

1.  接下来，将以下内容添加到一个空文件中，并将其保存为我们项目文件夹内的`gruntfile.js`——你会注意到我们的测试将针对 jQuery 的网站进行（如下所示）：

    ```js
    'use strict';

    module.exports = function (grunt) {
      grunt.initConfig({
        yslow: {
          pages: {
            files: [{
              src: 'http://www.jquery.com',
            }],
            options: {
              thresholds: {
                weight: 500,
                speed: 5000,
                score: 90,
                requests: 15
              }
            }
          }
        }
      });

      grunt.loadNpmTasks('grunt-yslow');
      grunt.registerTask('default', ['yslow']);
    };
    ```

1.  在 NodeJS 命令提示符窗口中，输入以下命令以安装`grunt-yslow`包：

    ```js
    npm install –g grunt-yslow

    ```

1.  Node 将进行安装。完成后，在命令提示符处输入以下命令以执行测试：

    ```js
    grunt yslow

    ```

1.  如果一切正常，Node 将显示类似于以下截图的内容，其中显示了一个失败：![自动化性能监控](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00474.jpeg)

命令提示符窗口中显示的结果有点基本。为了更好地了解问题所在，我们可以安装 YSlow 插件。现在让我们来做这个：

### 提示

在撰写本文时，使用 Firefox 运行 YSlow 存在持续问题；请改用 Chrome 查看结果。如果你是 Mac 用户，那么你可以尝试从[`yslow.org/safari/`](http://yslow.org/safari/)获取 YSlow 插件。

1.  浏览至[`www.yslow.org`](http://www.yslow.org)，然后在**可用性**下点击 **Chrome**，然后点击 **添加** 将插件添加到 Chrome：![自动化性能监控](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00475.jpeg)

1.  安装完成后，我们可以在 YSlow 中运行报告。如果我们对主要的 jQuery 网站进行测试，那么我们将得到类似于以下截图中所见的结果：![自动化性能监控](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00476.jpeg)

    如果我们浏览各个给定的等级，我们可以清楚地看到还有改进的空间。专注于脚本，检查将显示至少有五个脚本应移至页面底部，因为在这些脚本完成之前，浏览器无法开始任何其他下载。

1.  若要查看这将产生什么影响，请在 Firebug 中查看相同页面。单击 **Net** | **JavaScript**，然后刷新页面以查看从页面调用的所有脚本。将鼠标悬停在 jQuery 链接上 - 这证明了文件越大，加载时间越长：![自动化性能监控](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00477.jpeg)

在前面的截图中，我们可以清楚地看到许多脚本，所有这些脚本都显示出长时间。在这种情况下，缩小那些尚未压缩的脚本将改善这些时间。

我们可以花时间尝试优化 jQuery，但这应该放在更大的背景下来考虑；如果我们的代码中仍然加载大型脚本，那么我们清楚地失去了优化 jQuery 的任何好处。

### 注意

值得注意的是，在 `gruntfile.js` 中的阈值已设置得比平常要高。在移动设备时代，确保页面内容可以快速下载非常重要；在这两个示例中，我们都会看到肯定有改进的空间！

让我们看看第二个示例，看看它与之前的有什么区别。在这种情况下，我们将使用 Packt Publishing 网站，网址为 [`www.packtpub.com`](http://www.packtpub.com)：

1.  让我们回到我们在本节开头创建的 `gruntfile.js` 文件。我们需要修改以下行：

    ```js
    files: [{
      src: 'http://www.packtpub.com',
    }],
    options: {
    ```

1.  保存文件，然后切换到 NodeJS 命令提示符，并输入以下命令：

    ```js
    grunt yslow

    ```

1.  如果一切顺利，Node 将显示我们对 `http://www.packtpub.com` 评估的结果，我们会看到另一个失败，如下面的截图所示：![自动化性能监控](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00478.jpeg)

如果我们像之前那样使用 YSlow 来查看，那么我们可以看到提出了一些建议，这些建议将改善性能。对我们来说，关键的建议是将六个脚本压缩为更少的文件（并对其进行缩小）。参考以下截图：

![自动化性能监控](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00479.jpeg)

在之前的截图中，我们看到 YSlow 提到了类似的问题，尽管数字没有在 jQuery 网站上那么高。当我们检查由主页面调用的脚本的加载时间时，真正的问题就出现了：

![自动化性能监控](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00480.jpeg)

尽管我们发出的请求较少，这是好事，但只有一个脚本被缩小了。这将抵消缩小的好处。我们可以通过缩小代码在一定程度上纠正这个问题。我们将在本章稍后的部分看看如何自动化此过程，在 *使用 NodeJS 缩小代码* 中会详细介绍。

## 使用 Google PageSpeed 获取见解

到目前为止，我们已经看到了如何监控页面，但是在非常技术性的层面上。我们的检查集中在从我们的页面调用的脚本的大小和返回时间上。

更好的选择是运行一个测试，比如 Google PageSpeed，使用 Grunt 包，可以从[`github.com/jrcryer/grunt-pagespeed`](https://github.com/jrcryer/grunt-pagespeed)获取；我们可以在这个截图中看到结果：

![使用 Google PageSpeed 获取洞察力](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00481.jpeg)

它不会查看页面上的特定脚本或元素，但会给出我认为更真实的页面性能视图。

### 注意

这个演示需要使用 Node 和 Grunt，所以在继续之前确保你已经安装了它们两个。

现在让我们看看它在 Packt Publishing 网站上的实际应用：

1.  我们将首先启动一个 NodeJS 命令提示符，然后切换到我们的项目文件夹区域。

1.  输入以下内容以安装`grunt-pagespeed`包：

    ```js
    npm install grunt-pagespeed --save-dev

    ```

1.  在一个新文件中，添加以下内容，并将其保存为`gruntfile.js`，保存在相同的文件夹中 - 在代码下载中有一个此文件的副本；提取并将`gruntfile-pagespeed.js`重命名为`gruntfile.js`：

    ```js
    Gruntfile.js:
    'use strict';

    module.exports = function (grunt) {
      grunt.initConfig({
        pagespeed: {
          options: {
            nokey: true,
            url: "https://www.packtpub.com"
          },
          prod: {
            options: {
              url: "https://www.packtpub.com/books/content/blogs",
              locale: "en_GB",
              strategy: "desktop",
              threshold: 80
            }
          }
        }
      });

      grunt.loadNpmTasks('grunt-pagespeed');
      grunt.registerTask('default', 'pagespeed');
    };
    ```

1.  在 NodeJS 命令提示符下，输入以下命令以生成报告：

    ```js
    grunt-pagespeed

    ```

1.  如果一切正常，我们应该会看到一个类似于我们练习开始时显示的报告。

`grunt-pagespeed`插件只是使用 Grunt 运行的几个示例中的一个。还有其他可用的基准任务，我们可以集成到持续监视我们网站的过程中。这些包括以下内容：

+   `grunt-topcoat-telemetry`: 从遥测中获取流畅性、加载时间和其他统计数据作为 CI 的一部分。这可以帮助您设置一个性能基准仪表板，类似于 Topcoat 使用的仪表板（[`bench.topcoat.io`](http://bench.topcoat.io)）。

+   `grunt-wpt`: 用于测量 WebPageTest 分数的 Grunt 插件。

+   `grunt-phantomas`: 请求的响应时间，响应的响应时间，首个`image`/`CSS`/`JS`的时间，在`DOM Ready`上等等。

### 注意

如果你更喜欢使用 Gulp，那么之前的 Grunt 插件可以使用`gulp-grunt`来运行，可以从[`npmjs.org/package/gulp-grunt`](https://npmjs.org/package/gulp-grunt)获取。

现在我们知道了我们的基准，是时候探索如何优化我们的代码了；大多数开发者要么手动查看代码，要么可能使用网站如[www.jshint.com](http://www.jshint.com)（甚至[jslint.com](http://jslint.com)）。这种方法没有错。但是，这不是最好的方法，因为这是对我们时间的低效使用，有可能错过改进我们代码的机会。

对代码进行代码检查的更聪明的方法是自动化这个过程 - 虽然它可能不会警告你需要进行重大更改，但它至少会确保我们的代码不会由于错误而无法优化。当然，它还会为我们提供一个坚实的基础，以便我们可以进一步进行优化。我们将在本章后面更多地介绍这个。

是时候进行演示了！让我们花一点时间设置使用 NodeJS 进行自动检查。

# 自动对 jQuery 代码进行代码检查

对代码进行清理，或者检查它是否存在错误，是 jQuery 开发的一个重要部分。它不仅有助于消除错误，还有助于识别脚本中未使用的代码。

不要忘记 - 优化不仅仅是调整选择器，甚至用 CSS 等效替换 jQuery 代码（正如我们在第六章中看到的那样，*用 jQuery 进行动画*）。我们首先需要确保有一个坚实的基础来工作 - 我们始终可以手动完成这个过程，但更明智的选择是使用像 Grunt 这样的任务运行器来自动化该过程。

让我们花点时间看看这是如何运作的 - 请注意，这假设你之前的练习中仍然安装了 NodeJS。这一次，我们将用它来安装`grunt-contrib-jshint`包，可从[`github.com/gruntjs/grunt-contrib-jshint`](https://github.com/gruntjs/grunt-contrib-jshint)获取：

1.  设置自动检查非常容易。首先，我们需要下载并安装`grunt-contrib-jshint`。打开 NodeJS 命令提示符，并在项目文件夹区域内输入以下内容：

    ```js
    npm install grunt-contrib-watch

    ```

1.  安装完成后，继续在新文件中添加以下内容，并将其保存为`gruntfile.js`，保存在项目文件夹中：

    ```js
    'use strict';

    module.exports = function (grunt) {
      // load jshint plugin
      grunt.loadNpmTasks('grunt-contrib-jshint');

      grunt.initConfig({
        jshint: {
          options: { jshintrc: '.jshintrc' },
          all: [ 'js/script.js' ]
        }
      });

      grunt.loadNpmTasks('grunt-contrib-jshint');
      grunt.registerTask('default', ['jshint']);
    };
    ```

1.  从代码下载中，我们需要提取我们的目标 JavaScript 文件。继续并在我们的项目区域的`js`子文件夹中保存`script.js`的副本。

1.  回到 NodeJS 命令提示符，并输入以下命令，对我们的代码运行`jshint`检查：

    ```js
    grunt jshint

    ```

1.  如果一切顺利，我们应该会看到它弹出三个需要修复的错误，如下一张截图所示：![自动检查 jQuery 代码](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00482.jpeg)

### 注意

你们中注意力集中的人可能会注意到，这是我们在第十一章中创建的快速提示插件的代码，*编写高级插件*。

我们可以更进一步！我们可以让 Grunt 在代码更新时自动运行检查，而不是手动运行检查。为实现这一点，我们需要安装`grunt-contrib-watch`包，并相应地更改 Grunt 文件。现在就来做吧：

1.  打开`gruntfile.js`的副本，然后在`grunt.initConfig`对象的结束`});`之前立即添加以下代码：

    ```js
        },
        watch: {
          scripts: {
            files: ['js/script.js'],
            tasks: ['jshint'],
            options: { spawn: false }
          }
        }
    ```

1.  在文件末尾添加以下行，以注册额外的任务：

    ```js
    grunt.loadNpmTasks('grunt-contrib-jshint');
    ```

1.  我们需要修改`registerTask`调用以使 Grunt 意识到我们的新任务。继续按照下面的修改：

    ```js
    grunt.registerTask('default', ['watch', 'hint']);
    ```

1.  切换回命令提示符窗口，然后在命令行中输入以下内容：

    ```js
    grunt watch

    ```

1.  切换回`script.js`，并在代码中的某处进行更改。如果一切顺利，Node 将启动并重新检查我们的代码。![自动检查 jQuery 代码](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00483.jpeg)

运行代码清楚地显示我们有一些问题需要解决。在这个阶段，我们会花时间来解决它们。一旦更改完成，Node 将启动并显示更新后的错误列表（或通过！）。

假设我们的代码适合用途，我们可以真正开始优化它。一个简单的方法是压缩代码，以帮助保持文件大小的低水平。当然，我们可以手动压缩它，但那是老掉牙的做法；是时候再次挖掘 Node 了！

# 使用 NodeJS 压缩代码

开发者工作流程中的关键部分应该是一个用于压缩站点中使用的脚本的过程。这样做有助于减少页面下载内容的大小。

当然，我们也可以手动执行此操作，但这是一个耗时的过程，几乎没有什么好处；一个更聪明的方法是让 NodeJS 为我们处理这个问题。这样做的美妙之处在于，我们可以配置 Node 以运行一个诸如`grunt-contrib-watch`之类的包；我们所做的任何更改都将自动被压缩。甚至可能会有一些情况，我们决定不生成一个压缩文件；如果我们不确定我们正在编写的代码是否会起作用。在这种时候，我们可以从我们的文本编辑器中启动 Grunt，如果我们正在使用 Sublime Text 等包。

### 提示

如果你想在 Sublime Text 中实现这种级别的控制，请查看`sublime-grunt`，可以从[`github.com/tvooo/sublime-grunt`](https://github.com/tvooo/sublime-grunt)获取。

好的，让我们开始设置我们的压缩过程。为此，我们将使用著名的包，UglifyJS（来自[`github.com/mishoo/UglifyJS2`](https://github.com/mishoo/UglifyJS2)），并让 Node 自动检查：

1.  对于这个演示，我们将使用 NodeJS，所以如果你还没有这样做，可以从[`www.nodejs.org`](http://www.nodejs.org)下载适合你平台的相应版本，接受所有默认值。

1.  对于这个演示，我们需要安装两个包。UglifyJS 提供了对源映射的支持，所以我们首先需要安装它。从 NodeJS 命令提示符，切换到项目文件夹，输入以下命令，然后按*Enter*：

    ```js
    npm install source-map

    ```

1.  接下来，输入以下命令，然后按*Enter*：

    ```js
    npm install uglify-js

    ```

1.  安装完成后，我们可以运行 UglifyJS。在命令提示符处，小心输入以下命令：

    ```js
    uglifyjs js/jquery.quicktipv2.js --output js/jquery.quicktipv2.min.js --compress dead_code=true,conditionals=true,booleans=true,unused=true,if_return=true,join_vars=true,drop_console=true --mangle --source-map js/jquery.quicktipv2.map

    ```

1.  如果一切正常，Node 将按照这个下一个屏幕截图所示的过程进行：![使用 NodeJS 压缩代码](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00484.jpeg)

1.  最后，在我们的项目区域中应该有三个文件，如下面的屏幕截图所示：![使用 NodeJS 压缩代码](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00485.jpeg)

我们现在可以在生产环境中自由使用我们代码的压缩版本。虽然在这个例子中我们没有节省太多，但你可以想象如果我们扩大这些数字来覆盖更大的脚本时的结果！

## 探索一些值得注意的点

压缩脚本的过程应该成为任何开发人员工作流程的一部分。NodeJS 使添加它变得容易，尽管有一些提示可以帮助使压缩文件更容易和更高效：

+   UglifyJS 的默认配置将只生成显示很少压缩的文件。要获得更好的结果，需要仔细阅读所有可用的选项，了解哪个选项可能适合您的需求，并且可能会产生最佳结果。

+   我们在压缩过程中包含了源映射选项。我们可以使用它来将出现的问题与原始源代码关联起来。启用源映射支持在不同的浏览器中会有所不同（对于支持它的浏览器）；例如，在 Firefox 中，按下 *F12* 键显示开发者工具栏，然后点击齿轮图标并选择 **显示原始源代码**：![探索一些值得注意的点](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00486.jpeg)

+   值得检查一下，您的项目中是否已经存在所使用文件的最小化版本。例如，您的项目是否使用了提供了最小化版本的插件？如果是这样的话，我们所需要做的就是将它们连接到一个文件中；再次对它们进行最小化可能会导致问题，并且破坏文件中的功能。

对文件进行最小化并不是一门黑魔法，但也不是一门精确的科学。在压缩文件之前，很难知道在文件大小方面会得到多大的改进。你可能会得到一些意想不到的结果。现在就值得探索一个这样的例子。

## 通过一个真实的示例来理解

在为这本书研究材料时，我尝试将 Packt Publishing 网站上使用的 Drupal 文件之一进行最小化，作为一个测试。原始文件大小为 590 KB；使用与我们演示中相同配置选项的压缩版本，生成了一个文件大小为 492 KB 的文件。

这告诉我们什么？嗯，有几点需要注意：

+   保持合理的期望是很重要的。压缩文件是我们使用的一种有用的技巧，但它并不总能产生我们需要的结果。

+   我们使用了 UglifyJS（版本 2）。这个工具非常易于使用，但在原始压缩能力方面存在一些折衷。在某些情况下，它可能不适合我们的需求，但这并不意味着它有缺陷。目前有几十种压缩工具可供选择；我们只需选择另一种替代方案即可！

+   要真正实现显著的大小减小，可能需要使用`gzip`来压缩文件，并配置服务器以动态解压缩。这将增加处理页面的开销，需要将其纳入我们的优化工作中。

相反，逐个检查每个脚本以确定哪些正在使用、哪些可以安全地删除可能是更好的选择。当然，我们可以手动执行此操作，但是嘿——您现在已经认识我了：为什么自己做当您可以将其推迟到其他事情去做呢（错误引用一个短语）？进入 Node！让我们来看看`unusedjs`，它可以帮助我们了解我们的脚本中有多少额外的代码。

### 提示

我们已经集中在压缩一个文件上，但是通过使用通配符条目，自动压缩任何文件的配置变得非常简单。

# 找出未使用的 JavaScript

到目前为止，我们已经看到了如何轻松地压缩代码而不需要任何努力——但是如果仅仅压缩还不够，我们需要删除多余的代码怎么办呢？

好吧，我们可以手动检查代码——这没什么错。这是一种完全可以接受的工作方式，但关键是这是一个手动过程，需要大量时间和精力——更不用说频繁尝试查找可以删除的代码而不会破坏其他代码了！

更明智的做法是设置 Node 为我们解决哪些代码正在使用以及哪些可以安全丢弃。网页性能专家 Gaël Métais 创建了 unused JS 来帮助解决此问题。它与 Node 一起工作，并且可以在 [`www.npmjs.com/package/unusedjs`](https://www.npmjs.com/package/unusedjs) 上获得。这是一个正在进行中的工作，但只要它被用作指南，它就可以为我们提供一个有用的基础，让我们知道在哪里可以进行更改。

让我们花点时间深入了解它是如何工作的。对于此演示，我们将使用我们在 第十二章 中创建的 Tooltip 插件演示，*使用 jQuery 与 Node-WebKit 项目*。

![找出未使用的 JavaScript](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00487.jpeg)

在使用此功能时，有几件事情需要记住：

+   在撰写时，此插件的状态仍然处于非常初期阶段——使用 alpha 版软件的常见风险仍然存在！它并不完美；它应该只作为指南使用，并且需自担风险。它不能很好地处理长脚本（比如 jQuery UI 库），但可以处理大约 2,500-3000 行。

+   您需要清除浏览历史记录，因此不要在对浏览历史记录至关重要的浏览器中使用它。

+   该插件使用 Node。如果您没有安装它，请转到 Node 网站 [`www.nodejs.org`](http://www.nodejs.org) 下载并安装适合您平台的版本。

+   我们还需要使用本地 Web 服务器，如 WAMP（用于 PC - [`www.wampserver.com/de`](http://www.wampserver.com/de) 或 [`www.wampserver.com/en/`](http://www.wampserver.com/en/)），或 MAMP（用于 Mac - [`www.mamp.info`](http://www.mamp.info)）进行演示。确保您已经设置和配置了某些内容以供使用。

假设我们已经安装并配置了 Node 和本地 Web 服务器供使用，让我们从设置 `unusedjs` 脚本开始。我们将使用 Firefox 运行演示，如果你更喜欢使用其他浏览器，请相应调整。让我们开始：

1.  我们需要从某个地方开始。第一步是安装 `unusedjs.`，在 NodeJS 提示符下运行以下命令：

    ```js
    npm install unusedjs -g

    ```

1.  通过在控制台中输入以下内容启动服务器：

    ```js
    unused-js-proxy

    ```

1.  点击三条杠图标，然后点击 **选项**，以显示选项对话框。确保以下条目设置如下图所示：![清除未使用的 JavaScript](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00488.jpeg)

1.  确保 **No Proxy** 字段为空。然后点击 **OK** 确认设置。

1.  接下来，我们需要清除浏览器会话中的缓存。这一点至关重要，如果不清除缓存，我们可能会得到扭曲的结果。

1.  在这个阶段，从随书代码下载中打开 `tooltipv2.html` 的副本，并等待页面完全加载。

1.  按下 *F12* 显示 Firefox 的控制台，并在提示符处输入以下内容：

    ```js
    _unusedjs.report()

    ```

1.  如果一切正常，当查看控制台结果时，我们应该看到类似以下截图的内容：![清除未使用的 JavaScript](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00489.jpeg)

尝试在控制台中输入 `_unusedjs.file(2)`。这个函数会显示代码的副本，并用红色突出显示未使用的部分，如下截图所示：

![清除未使用的 JavaScript](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00490.jpeg)

现在我们可以集中精力在突出显示的部分上，从我们自己的脚本中删除冗余代码。当然，这将取决于我们自己的要求，以及冗余代码是否将作为即将到来的工作的一部分而被使用。

### 提示

毫无疑问，我们不能简单地从诸如 jQuery 这样的库中删除代码。我们需要构建 jQuery 的自定义版本——我们在第一章中详细讨论了这一点，*安装 jQuery*。

现在我们已经建立了基准，并确定了我们的脚本中是否包含未使用的代码，现在是时候来优化它了。让我们看看我们的代码中可以使用的一些技巧和窍门；作为将最佳实践嵌入到我们的正常开发工作流程的基础。

# 实施最佳实践

想象一下情景——我们已经编写了我们的代码，并检查了以确保所有文件在可能的情况下都被最小化，而且我们没有包含大量冗余代码。此时，有些人可能会认为我们已经准备好发布代码，并将我们的努力提供给公众使用，对吗？

错误！在这个阶段发布代码而不检查我们的代码的速度和效率，是不负责任的。谷歌的联合创始人兼首席执行官拉里·佩奇在他说到这一点时表达得很完美：

|   | *"作为产品经理，你应该知道速度是产品功能的第一要素。"* |   |
| --- | --- | --- |
|   | --*Google 联合创始人兼首席执行官拉里·佩奇* |

速度绝对是王道！我们已经在满足 Larry 的评论方面有了一些进展，但我们可以做得更多。到目前为止，我们已经看过了将我们的代码最小化和生成自定义版本的 jQuery。我们可以通过评估我们编写的代码来进一步确保它被有效执行。每个人的需求自然会有所不同，所以我们需要使用一些技巧的组合来确保有效的执行。让我们看看其中的一些：

1.  毫无疑问，我们应该只在绝对必要时针对 DOM 执行任务。对 DOM 的每次命中可能对资源是昂贵的，使您的应用程序变慢。例如，考虑以下代码：

    ```js
    <script src="img/jquery-2.1.3.min.js"></script>
    <script type="text/javascript">
      $("document").ready(function() {
        console.log("READY EVENT (B) => " + (newDate().
    getTime() - performance.timing.navigationStart) + 'ms');
      });
      console.log("END OF HEAD TAG (A) => " + (new Date()
    .getTime() - performance.timing.navigationStart) + 'ms');
    </script>
    ```

1.  在空的`<body>`标签上，加载 jQuery 库并使其可用所花费的时间相对较少；一旦我们在页面上添加元素，这个值就会增加。为了看到差异，我使用了这段代码运行了一个小演示。在下面的图像中，加载空的`<body>`标签上的 jQuery 的结果在左侧，而在之前演示中使用`tooltipv2.html`的结果在右侧：![实施最佳实践](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00491.jpeg)

1.  如果使用的是 jQuery 的 1.11 版本，那么由于包含了支持旧版浏览器的代码，其效果甚至更加明显。要亲自看到效果，请尝试运行`test loading jquery.html`，然后切换到您的浏览器的开发者工具栏中的**Console**来查看测试结果。将 jQuery 版本更改为`1.11`以真正看到差异！

    为了保持性能，DOM 元素应该被缓存在变量中，然后在被操作后才添加：

    ```js
    // append() is called 100 times
    for (var i = 0; i < 100; i++) {
      $("#list").append(i + ", ");
    };

    // append() is called once
    var html = "";
    for (var i = 0; i < 100; i++) {
      html += i + ", ";
    }
    $("#list").append(html);
    ```

    ### 提示

    您可以通过在 JSPerf 上运行测试来查看结果的实际情况，网址为[`jsperf.com/append-on-loop/2`](http://jsperf.com/append-on-loop/2)。

1.  另一方面，如果我们需要修改与单个元素相关的几个属性，则使用对象会使操作变得更容易，但同时也会撤销我们的所有努力！

1.  检查选择器非常重要。jQuery 是从右向左读取它们的。尽可能使用 ID，因为它们比标准类选择器更快。还要确保您没有使用诸如`.myClass1 #container`之类的规则，其中 ID 跟在类选择器后面。这是低效的 - 我们失去了指定只能是单个值的好处，因为不断地迭代代码以确保我们已经涵盖了我们在代码中使用的类的所有实例。

    毫无疑问，所使用的任何选择器都应该被缓存。当引用多级深度的选择器时，最佳实践规定我们应该在左侧尽可能具体（即`.data`），在右侧尽可能不太具体：

    ```js
    // Unoptimized:
    $( ".data .gonzalez" );

    // Optimized:
    $( "div.data td.gonzalez" );
    ```

1.  最重要的是，避免使用`*`或类型等形式的通用选择器，例如`:radio`，除非您使您的选择器引用尽可能明确 - 这两者都非常慢！

1.  尽管这本书是关于 jQuery 的，但在性能不够时，可能需要使用经典 JavaScript 方法。例如，`for`循环比 jQuery 的`.each()`方法更有效，使用`querySelector` API 比使用 jQuery 选择器更好。

1.  如果您正在加载多个脚本，请考虑在页面末尾加载它们，一旦在页面上方（或在页面向下滚动之前显示的内容）加载了所有内容。jQuery 应始终用于逐步增强页面，而不是运行一段代码，如果禁用 jQuery，则会破坏页面。感知力可能起很大作用 - 您的页面可能没有做很多事情，但仍然被感知为慢。重新排序脚本（和内容）可以帮助改变这种感知。

1.  有些开发者可能仍然使用 jQuery 的 AJAX 对象来处理异步 HTTP 请求。虽然它能够运行，但不是处理此类请求的最干净的方式：

    ```js
    $.ajax({
      url: "/firstAction",
      success: function() {
        //whatever
        secondAction();
        return false;
      },
      error: error()
    });

    var secondAction = function() {
      $.ajax({
        url: "/secondAction",
        success: function() {
          // whatever
        },
        error: error()
      });
    };
    ```

    更明智的选择是使用 jQuery `promises()`，在那里我们可以将代码延迟到更容易阅读和调试的函数中。代码存储在何处并不重要；`promises()`将允许我们在代码的适当位置调用它：

    ```js
    $.when($.ajax( { url: "/firstAction" } ))

    // do second thing
    .then(
      // success callback
      function( data, textStatus, jqXHR ) {},
      // fail callback
      function(jqXHR, textStatus, errorThrown) {}
    )

    // do last thing
    .then(function() {});
    ```

1.  如果我们正在调用整个脚本，则探索使用条件加载器是有意义的，比如 RequireJS（使用纯 JavaScript），或`grunt-requirejs`（如果我们更喜欢使用 Node）。

    ### 提示

    毫无疑问，懒加载我们的代码的同样原则也适用于页面上的元素，例如图像；`jquery-lazy`是一个完美的 Node 模块示例，可以帮助实现这一点。它可在[`www.npmjs.com/package/jquery-lazy`](https://www.npmjs.com/package/jquery-lazy)找到。

1.  先前提到使用`promises()`的提示展示了一个完美的例子，说明我们仍然可以做出改进。有些开发者赞美代码链的优点，这样做似乎可以缩短代码。然而，这使得代码更难阅读，因此也更难调试；由此产生的代码混乱将导致错误和浪费时间，最终需要部分或完全重构代码。先前提示中的例子还突显了需要确保使用良好的命名约定，因为当链式命令时，我们无法具体指定回调函数的名称。

1.  这个下一个提示可能看起来有点矛盾，因为我们在本书中始终在谈论 jQuery，但是要使用更少的 JavaScript - 可以转移到 HTML 或 CSS 的任何内容都会对我们的性能产生积极影响。虽然使用 jQuery 很有趣，但它是基于 JavaScript 的，而 JavaScript 是 Web 堆栈中最脆弱的层，会影响性能。这的经典例子是创建动画。查看[`css-tricks.com/myth-busting-css-animations-vs-javascript/`](https://css-tricks.com/myth-busting-css-animations-vs-javascript/)，了解为什么在不必要时使用 jQuery（或 JavaScript）来驱动我们的动画是愚蠢的。

1.  考虑削减芥末，或者为能力较弱的浏览器放弃功能。当在能力较弱或移动浏览器上使用基于 jQuery 的站点时，这将带来更好的体验。在一些具有许多 polyfill 运行以支持功能（例如 CSS3 样式）的站点上，放弃这些 polyfill 的影响可能很大！

1.  要了解加载和解析 jQuery 所需时间的差异，请查看开发人员 Tim Kadlec 在[`timkadlec.com/2014/09/js-parse-and-execution-time/`](http://timkadlec.com/2014/09/js-parse-and-execution-time/)进行的测试。

我们可以在我们的代码中使用许多更多的技巧和诀窍。有关更多灵感来源，请参考以下链接作为起点：

+   [`www.slideshare.net/MatthewLancaster/automated-perf-optimization-jquery-conference`](http://www.slideshare.net/MatthewLancaster/automated-perf-optimization-jquery-conference)：由开发人员 Matthew Lancaster 于 2014 年在 jQuery 会议上演讲，这涵盖了一些有用的技巧；他特别强调我们可以在不费吹灰之力的情况下取得一些严重的收益，尽管我们应该始终警惕过度优化我们的代码！

+   [`crowdfavorite.com/blog/2014/07/javascript-profiling-and-optimization/`](http://crowdfavorite.com/blog/2014/07/javascript-profiling-and-optimization/)：本文介绍了作者用来帮助优化性能的过程；这给出了所涉及的味道。

+   [`chrisbailey.blogs.ilrt.org/2013/08/30/improving-jquery-performance-on-element-heavy-pages/`](http://chrisbailey.blogs.ilrt.org/2013/08/30/improving-jquery-performance-on-element-heavy-pages/)：这篇文章有点老，但仍然包含了一些优化我们代码的有用指针。

+   [`joeydehnert.com/2014/04/06/9-development-practices-that-helped-me-write-more-manageable-and-efficient-javascript-and-jquery/`](http://joeydehnert.com/2014/04/06/9-development-practices-that-helped-me-write-more-manageable-and-efficient-javascript-and-jquery/)：这里包含了一些非常有用的优化 jQuery 的技巧，有些与我们在本章中介绍的类似。

通过所有这些的关键点是，性能优化永远不应被视为一次性的活动；我们必须将其视为代码生命周期中的持续过程。为了帮助实现这一点，我们可以设计一个策略来掌握优化。让我们以这些提示作为我们需要考虑的策略的基础。

## 设计一个性能策略

到目前为止，我们集中在可以用来改善性能的技巧和窍门上。采取一种反应式的方法是可行的，但需要额外的时间来投入，而我们可以在编写代码时就将这些技巧和窍门融入其中。

考虑到这一点，制定一项策略来鼓励这种思维方式将是有益的。让我们来看看可以形成这样一项策略基础的几个关键点：

+   始终使用最新版本的 jQuery - 您将从代码改进、速度和已知问题的错误修复中受益。

+   在可能的情况下，合并和压缩脚本，以减少带宽使用。

+   使用原生函数而不是 jQuery 的等效函数 - 一个完美的例子是使用`for()`而不是`.each()`。

+   使用 ID 而不是类 - ID 只能分配一次，而 jQuery 将多次命中 DOM 以查找每个类，即使只有一个实例存在也是如此。

+   给选择器一个上下文。参考以下代码，简单指定一个类：

    ```js
    $('.class').css ('color' '#123456');
    ```

    相反，更明智的做法是使用上下文化的选择器，形式为`$(expression, context)`，从而产生：

    ```js
    $('.class', '#class-container').css ('color', '#123456');
    ```

    第二个选项运行速度更快，因为它只需要遍历#class-container 元素而不是整个 DOM。

+   在可能的情况下，缓存值，以避免直接操作 DOM。

+   使用`join()`而不是`concat()`来连接较长的字符串。

+   在使用`#`作为源链接的链接的点击事件上始终添加`return false`，或者使用`e.preventDefault()` - 如果不添加，将会跳转到页面顶部，在长页面上会很烦人。

+   在页面重量、请求和渲染时间方面为自己设定预算 - 请参阅[`timkadlec.com/2014/11/performance-budget-metrics/`](http://timkadlec.com/2014/11/performance-budget-metrics/)。这给优化提供了目的，并鼓励更长期的性能监控精神。

+   使用诸如 SpeedCurve 之类的性能监控服务来帮助监视您的网站，并在出现问题时提醒您。

+   在办公室展示性能 - 这有助于鼓励团队精神。如果团队中的某人提出的更改对性能产生了积极影响，则表彰他们并让其余团队成员知晓；这将有助于激励团队之间的健康竞争意识。

+   但是，如果一个改变破坏了性能，那么不要惩罚罪犯；这将使他们不愿参与。相反，试着培养解决问题的文化，然后学会如何防止它再次发生。如何运行像 PhantomJS 这样的测试来帮助检查和减少问题出现的风险呢？

+   自动化一切。有服务可以压缩图像或缩小脚本，但投入时间开发类似的内部流程可以节省时间和金钱。关键在于，手动执行诸如优化图像或压缩脚本的任务是没有意义的；你需要自己找出最适合你需求的方法。

+   是否决定使用 Grunt 或 Gulp 是一个关键考虑因素——它们是否提供了有用的附加功能，还是只是一个可以通过谨慎使用 NPM 来减少或消除的额外负担？开发者 Keith Cirkel 在[`blog.keithcirkel.co.uk/why-we-should-stop-using-grunt/`](http://blog.keithcirkel.co.uk/why-we-should-stop-using-grunt/)提出了一个有力的理由，认为只使用 NPM 就足够了；这是一个发人深省的观点！

+   花时间影响你的同事和那些更高层的人——他们通常可能不知道你在某个问题上可能遇到的困难，但实际上可能有能力帮助你解决问题！

+   花时间学习。我们往往花太多时间在客户工作上，而没有为自我发展留出足够的时间；花一些时间来纠正这一点。如果这意味着需要调整价格来弥补由于未花时间在客户工作上而导致的收入损失，那么这是需要考虑的事情。这一切都关乎于建立工作/娱乐/学习的平衡，这将在长期内得到回报。

这里有很多值得深思的东西——并不是每个技巧都适用。在某些情况下，一个或多个技巧的融合会产生你需要的结果。然而，花费时间在这上面是值得的，因为长期来看会得到丰厚的回报，并且有望在你的团队现有的工作文化中获得融入。

让我们继续。我们快要完成本章了，但在我们结束之前，让我们来看看如何为 jQuery 进行测试，我想问一个简单的问题：我们真的需要使用 jQuery 吗，如果需要，为什么？

# 关于使用 jQuery

在这一点上，如果你认为我完全失去了理智，那是可以理解的，特别是当我们刚刚在考虑优化代码的方法时，却建议完全将其从我们的代码中删除。你可能会问，为什么我会考虑放弃 jQuery 呢？

嗯，有几个充分的理由。任何人都可以编写 jQuery 代码，但聪明的开发者应该始终考虑他们是否应该使用 jQuery 来解决问题：

+   jQuery 是一个抽象库，它需要 JavaScript，并且是在开发当时的浏览器可能是一个真正的挑战的时候构建的。需要抽象掉浏览器的不一致性正在变得越来越少。重要的是要记住，我们应该使用 jQuery 来逐步增强普通的 JavaScript；jQuery 首先是为了让编写 JavaScript 更容易而设计的，并不是一种独立的语言。

+   浏览器在功能上比以往任何时候都更接近。随着 Firefox 放弃了大部分厂商前缀，库几乎不再需要消除不一致性。如果某个功能在 IE10 或最新版本的 Firefox 中可行，那么很可能在 Google Chrome 或 Opera 中也适用。当然，会有一些差异，但这实际上仅适用于一些尚未被广泛使用的更为深奥的 CSS3 样式。那么 - 如果浏览器如此接近，为什么还要使用 jQuery？

+   使用纯 JavaScript 总是比使用 jQuery 快，无论我们如何努力 - 这还有一个额外的好处，即 JavaScript 代码将产生比等效 JavaScript 代码（不包括库本身）更小的文件。如果我们只使用少量 JavaScript 代码，那么为什么要引用一个完整的库呢？当然，我们总是可以尝试构建 jQuery 的自定义版本，就像我们在 第一章 中看到的那样，*安装 jQuery* - 但无论我们如何尝试修剪库中的不必要代码，我们仍然会引入比我们需要的更多的代码！当然，我们当然可以使用 `gzip` 进一步压缩 jQuery 代码，但它仍然会比纯 JavaScript 多。

+   编写 jQuery 实在太容易了 - 它拥有庞大的社区，学习曲线很低。这为编写大量低质量的代码创造了完美的条件，我们只使用了 jQuery 中提供的一小部分功能。从长远来看，学习如何有效地使用纯 JavaScript，然后使用 jQuery 为其提供象征性的锦上添花将会更好。

但这里的关键点是我们不应完全放弃 jQuery - 现在是时候真正考虑是否需要使用它了。

当然 - 如果我们使用了大量在纯 JavaScript 中要么很难实现，要么根本无法实现的功能，那么就必须使用 jQuery。然而，我给你留下一个挑战，用拍照作为类比。像平常一样构图。然后停下来，闭上眼睛十秒钟，深吸几口气。现在问问自己，你是否还准备拍同样的照片。很可能你会改变主意。同样的道理也适用于使用 jQuery。如果你停下来认真考虑了自己的代码，我想你们中有多少人仍然决定继续使用它呢？

就个人而言，我认为 jQuery 仍将发挥作用，但我们已经到了一个不应该盲目或出于习惯使用它的时候，而是要在何时何地使用它代替纯 JavaScript 做出有意识的决定的时候。

要了解如何从 jQuery 切换到 JavaScript 来满足简单的需求，请参阅 Todd Motto 的文章 [`toddmotto.com/is-it-time-to-drop-jquery-essentials-to-learning-javascript-from-a-jquery-background/`](http://toddmotto.com/is-it-time-to-drop-jquery-essentials-to-learning-javascript-from-a-jquery-background/)。

# 摘要

维护高性能的网站是开发的关键部分。除了优化代码之外，还有更多内容，让我们花点时间回顾一下本章学到的东西。

我们首先了解了为何理解性能的重要性，并通过各种监视性能的方式，从在 Firebug 中查看统计数据到使用 Grunt 自动化我们的检查，进行了深入研究。

然后，我们继续了解如何自动地对我们的代码进行代码检查，作为优化代码的众多方式之一，然后对其进行缩小以供生产使用。然后，我们深入研究了如何判断我们的代码是否包含任何未使用的代码，这些代码可以安全地删除，以简化我们的代码。

然后，我们通过实施最佳实践来结束本章。这里的重点不是提供具体的例子，而是分享一些可应用于任何网站的技巧和窍门。然后，我们以此为基础设计了一种策略，帮助维护高性能的网站。

我们即将完成精通 jQuery 的旅程，但在结束之前，我们需要快速看一下如何测试我们的代码。开发者可能会使用 QUnit，因为它是 jQuery 家族项目的一部分；我们将在下一章中进一步探讨如何更深入地使用它。


# 第十四章：测试 jQuery

要测试还是不要测试，这是个问题…

为了用这位世界著名的侦探的话来说，对于这个问题的答案应该是很简单的！

如果你花了一些时间学习 jQuery，你肯定知道它的单元测试的重要性，而且最流行的方法就是使用它的测试库 QUnit。在本章中，我们将回顾如何使用它，然后看一些我们应该使用的最佳实践，以及探讨如何真正减少我们的工作流程，通过自动化我们对代码的测试。

在本章中，我们将涵盖以下主题：

+   重新审视 QUnit

+   使用 NodeJS 和 RequireJS 进行自动化测试

+   使用 QUnit 时的最佳实践

准备好了吗？让我们开始吧…

# 重新审视 QUnit

对任何代码进行测试对于成功构建任何在线应用程序或站点至关重要；毕竟，我们不希望在最终结果中出现错误，对吧？

测试可以手动进行，但存在人为因素的增加风险，我们无法始终确定测试是否完全相同。为了减少（甚至消除）这种风险，我们可以使用 jQuery 的单元测试套件 QUnit 来自动化测试。当然，我们可以手动运行 QUnit 测试，但 QUnit 的美妙之处在于它可以完全自动化，我们将在本章后面看到。

现在，让我们花一点时间回顾一下如何安装 QUnit 并运行一些基本测试的基础知识。

## 安装 QUnit

安装 QUnit 有三种方式。我们可以简单地在代码中包含两个链接，使用 [`qunitjs.com`](https://qunitjs.com) 提供的 JavaScript 和 CSS 文件。这些文件可以直接引用，因为它们是托管在由 MaxCDN 提供的 QUnit 的 CDN 链接上。

另一种方法是使用 NodeJS。为此，我们可以浏览到 NodeJS 网站 [`www.nodejs.org`](http://www.nodejs.org)，下载适合我们平台的版本，然后在 NodeJS 命令提示符上运行以下命令：

```js
npm install --save-dev qunitjs

```

我们甚至可以使用 Bower 来安装 QUnit；要做到这一点，我们首先需要安装 NodeJS，然后运行以下命令来安装 Bower：

```js
npm install -g bower

```

一旦安装了 Bower，就可以用这个命令安装 QUnit：

```js
bower install --save-dev qunit

```

在这个阶段，我们准备开始用 QUnit 创建我们的自动化测试。

### 注意

如果你想要真正地深入了解，你可以测试最新提交的 QUnit 版本——链接在 [`code.jquery.com/qunit/`](http://code.jquery.com/qunit/)；需要注意的是这不适用于生产环境！

## 创建一个简单的演示

现在我们已经安装了 QUnit，我们准备运行一个简单的测试。为了证明它的工作原理，我们将修改一个简单的演示，以便测试文本框中的字母数，并指示它是否超过或低于给定的限制，如下所示：

1.  我们将首先从附带本书的代码下载中提取我们演示所需的代码副本；请提取 `qunit.html` 文件以及 `css` 和 `js` 文件夹，并将它们存储在项目区域中：![创建一个简单的演示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00492.jpeg)

    ### 提示

    不必担心 `node_modules` 文件夹的存在；在后面的章节中，当安装 Node 时，我们将创建它。

1.  现在，我们需要修改我们的测试标记，所以请打开 `qunit.html`，然后按照指示进行修改：

    ```js
    <!DOCTYPE html>
    <html>
      <head>
        <title>Testing jQuery With QUnit</title>
        <meta charset="utf-8">
        <link rel="stylesheet" href="css/qunit.css" />
     <link rel="stylesheet" href="css/qunittest.css" />
     <script src="img/jquery.min.js"></script>
     <script src="img/qunit.js"></script>
     <script src="img/qunittest.js"></script>
      </head>
      <body>
        <form id="form1">
          <input type="text" id="textLength">
          <span id="results"></span>
     <div id="qunit"></div>
     <div id="qunit-fixture"></div>
        </form>
      </body>
    </html>
    ```

1.  接下来，打开你喜欢的文本编辑器，添加以下代码，并将其保存为 `js` 文件夹中的 `qunittest.js`。第一个代码块对文本字段的长度进行检查，并显示计数；如果超过了规定的八个字符的长度，则将该计数的背景设置为红色：

    ```js
    $(document).ready(function() {
      var txt = $("input[id$=textLength]");
      var span = $("#results");
      $(txt).keyup(function() {
        var length = $(txt).val().length;
        $(span).text(length + " characters long");
        $(span).css("background-color", length >= 8 ? "#FF0000" : "#00FF00");
      });
    ```

1.  在上一个代码块的下方立即添加以下代码行；这将调用 QUnit 来测试我们的文本字段的长度，并在字母计数下方显示结果：

    ```js
      $(txt).val("Hello World!");
      QUnit.test("Number of characters in text field is 8 or more", function(assert) {
        $(txt).trigger("keyup");
        assert.ok($(txt).val().length >= 8, "There are " + $(txt).val().length + " characters.");
      });
    });
    ```

1.  文件已就绪，我们可以运行测试了；请在浏览器中运行 `qunit.html`。如果一切顺利，我们应该看到我们测试的结果，这种情况下将显示一个通过：![创建一个简单的演示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00493.jpeg)

1.  在现实生活中，我们进行的并非每次测试都会成功；如果我们没有提供正确的数值或执行了给出意外结果的计算，就会出现测试失败的情况。要查看在 QUnit 中的效果，请按照以下步骤将这些代码添加到 `qunittest.js` 文件中，如下所示：

    ```js
      assert.ok($(txt).val().length >= 8, "There are " + $(txt).val().length + " characters.");
    });

     $(txt).val("Hello World!");
     QUnit.test("Number of characters in text field is 8 or less", function(assert) {
     $(txt).trigger("keyup");
     assert.ok($(txt).val().length <= 8, "There are " + $(txt).val().length + " characters.");
      });
    ```

1.  现在，刷新你的浏览器窗口；这一次，你应该看到测试已完成，但有一个失败，如下图所示：![创建一个简单的演示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00494.jpeg)

### 注意

在代码下载的 `completed version` 文件夹中有这个示例的已完成版本，它探讨了测试的结果。

尽管这被设计为一个简单的演示，但它仍然突出了创建简单测试并给出适当响应的简易性；让我们暂停片刻，考虑一下我们在这个练习中涵盖了什么。

每个测试的关键在于使用 `assert.ok()` 函数—它执行一个简单的布尔检查。在我们的例子中，我们检查文本长度是否为 8 个字符或更少，或者为 8 个字符或更多，并根据结果显示通过或失败。此外，我们可以要求 QUnit 显示标准文本，或者用个性化消息进行覆盖。这种方法应该足以开始对代码进行单元测试；随着时间的推移，如果需要，我们总是可以进一步开发测试。

这个库的美妙之处在于我们可以用它来使用 jQuery 或 JavaScript；本章中的示例基于使用前者，但 QUnit 足够灵活，可以用于后者，如果我们决定将来不再使用 jQuery。QUnit 是 jQuery 产品系列的一部分；与其他简单的测试库（如[Junit](http://junit.org/)）类似。

当我们利用 QUnit 的力量时，我们可以做大量事情——我们在这里看到的只是可能实现的表面一角。

### 注意

如果您想了解更多关于 QUnit 基础知识，那么我建议您参考*Dmitry Sheiko*的《Instant Testing with QUnit》，该书由 Packt Publishing 出版。也有很多在线教程可供参考；您可以从这个链接开始：[`code.tutsplus.com/tutorials/how-to-test-your-javascript-code-with-QUnit--net-9077`](http://code.tutsplus.com/tutorials/how-to-test-your-javascript-code-with-QUnit--net-9077)。

作为可能性的一个示例，我们将专注于一个特定功能，这将帮助您进一步提高您的 jQuery 开发技能：不要每次都手动运行测试，而是完全自动化它们，让它们自动运行。

# 使用 QUnit 进行自动化测试

慢着，QUnit 不是已经为我们自动运行了这些测试吗？

答案是肯定和否定。QUnit 自动化了测试，但只到一定程度；我们每次都需要手动运行一组测试。虽然这很有用，但你知道吗？我有点懒，也没有时间或意愿一直手动运行测试，我相信您也是如此。我们可以做得更好；可以使用 NodeJS/Grunt 和 PhantomJS 自动化我们的测试。

当然，设置需要一些努力，但当任何已识别的内容发生变化时，自动运行测试的节省时间是值得的。

![使用 QUnit 进行自动化测试](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00495.jpeg)

让我们来看看自动化我们测试所涉及的内容：

1.  我们将从安装 NodeJS 开始。要做到这一点，请浏览至[`nodejs.org/`](http://nodejs.org/)，并下载适合您系统的二进制文件；它适用于 Windows、Mac OS 和 Linux。

1.  安装完成后，打开 NodeJS 命令提示符，然后切换到我们在*创建一个简单演示*中创建的`qunit`文件夹。

1.  在命令提示符下，输入以下命令：

    ```js
    npm install –g grunt-cli

    ```

    NodeJS 需要创建两个文件才能正确运行；它们是`package.json`和`gruntfile.js`。让我们现在就去创建它们。

1.  切换到您选择的普通文本编辑器，然后在一个新文件中添加以下代码，将其保存为`package.json`：

    ```js
    {
      "name": "projectName",
      "version": "1.0.0",
      "devDependencies": {
        "grunt": "~0.4.1",
        "grunt-contrib-QUnit": ">=0.2.1",
        "grunt-contrib-watch": ">=0.3.1"
      }
    }
    ```

1.  切换到 NodeJS 命令提示符，然后输入以下内容：

    ```js
    npm install

    ```

1.  在一个单独的文件中，添加以下代码并将其保存为`gruntfile.js`：

    ```js
    module.exports = function(grunt) {
      grunt.initConfig({
        pkg: grunt.file.readJSON('package.json'),

        QUnit: {
          all: ['tests/*.html']
        },
        watch: {
          files: ['tests/js/*.js', 'tests/*.html'],
          tasks: ['QUnit']
        }
      });

      grunt.loadNpmTasks('grunt-contrib-watch');
      grunt.loadNpmTasks('grunt-contrib-QUnit');
      grunt.registerTask('default', ['QUnit, watch']);
    };
    ```

1.  再次切换到 NodeJS 命令提示符，然后输入以下内容：

    ```js
    npm install –g phantomjs

    ```

1.  如果一切顺利，我们应该看到类似以下截图的内容出现：![使用 QUnit 自动化测试](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00496.jpeg)

1.  现在让我们启动 Grunt 并设置它监视代码的任何更改；要做到这一点，请在 NodeJS 命令提示符中运行以下命令：

    ```js
    grunt watch

    ```

1.  打开我们在本章前面创建的 `qunittest.js` 的副本，然后保存文件 —— 我知道这听起来有点疯狂，但这是触发 Grunt 进程所必需的。

1.  如果一切顺利，我们应该在 NodeJS 窗口中看到这个结果出现：![使用 QUnit 自动化测试](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00497.jpeg)

1.  回滚到 `qunittest.js`，然后按照这里所示更改此行：

    ```js
    assert.ok($(txt).val().length <= 8, "There are " + $(txt).val().length + " characters.");
    ```

1.  保存文件，然后观察 Grunt 窗口，现在应该指示测试失败：![使用 QUnit 自动化测试](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00498.jpeg)

让我们转变方向，继续前进；尽管我们没有深入讨论过如何使用 QUnit，但在使用 QUnit 时，尽可能遵循最佳实践仍然很重要。让我们花一点时间考虑一些这些最佳实践，以便了解它们如何提高我们的编码技能。

# 探索使用 QUnit 时的最佳实践

任何开发者的目标应该是在可能的情况下遵循最佳实践；但实际情况并非总是如此，因此在必要时学会在什么情况下妥协是很重要的。假设这种情况不会经常发生，那么在使用 QUnit 时，我们可以尝试遵循一些最佳实践指南：

+   **使每个测试相互独立**：我们运行的每个测试都应该只测试一个特定的行为；如果我们在多个测试中测试相同的行为，那么如果行为需要更改，我们就必须更改所有的测试。

+   **不要做不必要的断言**：问问自己这个问题，“我们要测试什么行为？” 单元测试应该是对某个行为应该如何工作的设计草图，而不是详细描述代码发生的每件事情。尽可能地在每个测试中保持一个断言；如果我们的代码中已经在其他地方测试过某个断言，那么运行测试就没有意义了。

+   **一次只测试一个代码单元**：您的代码的架构设计必须支持独立测试单元（即类或非常小的类组），而不是将它们链接在一起。如果不这样做，您就会面临大量重叠的风险，这将导致代码的其他地方发生故障。如果您的应用程序或站点的设计不允许这样做，那么您的代码质量将会受到影响；可能需要使用**控制反转**（**IoC**）来测试您的工作。

    ### 注

    通常的做法是让自定义代码调用通用的、可重用的库（例如 QUnit）；IoC 将这个过程反转，以便在这种情况下，测试由 QUnit 调用我们的自定义代码执行。

+   **模拟所有外部服务和状态数据**: 单元测试的关键部分是尽可能减少外部服务对你的代码的影响——这些服务的行为可能会与你的测试重叠，并影响结果。

+   **避免模拟太多的对象或状态数据**: 如果你有任何控制应用程序或站点状态的数据，请尝试将任何模拟数据保持在低于 5%的水平；任何更高的数值都会使你的测试不太可靠。在运行连续测试之前，将它们重置回一个已知的值也是明智的，因为不同的测试可能会影响其他测试的这些值。如果你发现你必须按特定顺序运行测试，或者你对活动数据库或网络连接有依赖，那么你的设计或代码就不正确，你应该重新审视两者，理解为什么以及如何去除这些依赖关系。

+   **避免不必要的前提条件**: 避免在许多不相关的测试的开头运行常见的设置代码。这会使你的测试变得混乱，因为不清楚你的测试依赖于哪些假设，并且表明你并不只是在测试单个单元。关键是创造正确的条件，即使这可能很困难——诀窍在于尽可能简单地保持它们。

+   **不要对配置设置进行单元测试**: 在运行单元测试时检查你的配置设置没有任何好处；这可能会导致重复的代码，这是没有必要的。

+   **不要指定你的实现方式 - 而是指定结果**: 单元测试旨在专注于结果，而不是实现方式——你的函数是否产生了你期望的结果？以以下代码片段为例：

    ```js
    test("adds user in memory", function()  {
      var userMgr — makeUserMgr();
      userMgr.addUser("user", 'pass");
      equal (userMgr. —internalUsersCØ) . name , "user")
      equal (userMgr. —internalUsersCØ) . pass , "pass")
    });
    ```

    这看起来完全合理，对吧？如果不是因为它专注于*代码是如何实现的*，而不是结果，那就是完全有效的。

    测试代码的更好方式是使用这种方法：

    ```js
    test( "adds user in memory", function() var userMgr = makeUserMgr(); userMgr.addUser("user", "pass"); ok(userMgr. loginUser("user" , "pass"));
    });
    ```

    在这个例子中，我们不关注获得结果的路线，而是关注结果本身；它是否产生了我们需要看到的内容？

+   **清晰且一致地命名你的单元测试**: 一个成功的单元测试将清晰地表明其目的；一个有用的命名测试的方法是使用我称之为**SSR**原则，即**主题、场景和结果**。这意味着我们可以确定正在测试什么，测试应该何时运行，以及预期结果是什么。如果我们仅仅用主题来命名它，那么如果我们不知道我们试图维护什么，它就会变得难以维护！

这些提示只是浅尝辄止，作为良好实践应该遵循的内容；要进行更深入的讨论，值得阅读亚当·科拉瓦关于应用单元测试的文章，该文章位于[`www.parasoft.com/wp-content/uploads/pdf/unittestting.pdf`](http://www.parasoft.com/wp-content/uploads/pdf/unittestting.pdf)。但要记住的关键点是要保持简单、逻辑，并且不要试图过度复杂化你的测试，否则它们将变得毫无意义！

# 总结

我们现在已经到了本章的结尾；虽然篇幅不长，但涵盖了一些关于单元测试实践的有用观点，以及我们如何通过自动化测试来节省时间和精力。让我们快速回顾一下我们学到的内容。

我们开始时简要回顾了 QUnit 的原则以及如何安装它；我们简要介绍了最流行的方法，但也介绍了如何使用 CDN 和 Bower 在我们的代码中使用库。

接下来我们来看一些基本的测试示例；虽然这些示例非常简单，但它们突显了我们在单元测试中应该遵循的原则。这些原则在使用 QUnit 进行单元测试时进一步探讨。

我们现在已经到了本书的结尾。希望你喜欢我们在*掌握 jQuery*中的旅程，并且发现这不仅仅是关于编写代码，还涉及一些更加软性的话题，这些话题将有助于提高你作为 jQuery 开发者的技能。
