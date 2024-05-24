# 精通 jQuery（一）

> 原文：[`zh.annas-archive.org/md5/0EE28037989D2E7006D982EBB8295FFE`](https://zh.annas-archive.org/md5/0EE28037989D2E7006D982EBB8295FFE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

假设你是一个中级开发者，对编写代码相当熟悉，但觉得开发 jQuery 不应该只是在文本编辑器中敲击键盘那么简单。

你说得对；任何人都能写代码。为了成为更全面的开发者，我们必须思考更广泛。那些需要理解和调试的长串代码的时代已经过去了，取而代之的是帮助我们更明智地使用 jQuery 并更有效地利用我们忙碌生活中时间的决策。

作为作者，我坚持认为简单的解决方案通常比复杂的解决方案更有效；在本书中，我们将涉及各种主题，帮助提升你的技能，让你考虑所有选项，并理解编写 jQuery 代码的更多要点。

这将是一次很棒的旅程，比侦探小说的情节更扑朔迷离；问题是，“你准备好了吗？” 如果答案是肯定的，让我们开始吧…

# 本书内容概述

第一章, *安装 jQuery*，开启了我们掌握 jQuery 世界的旅程，你将会了解到下载和安装 jQuery 不仅仅是使用 CDN 或本地链接那么简单。我们将看看如何使用包管理器安装 jQuery，如何定制我们下载的元素，以及如何添加源映射等等，以帮助调整库的副本。

第二章, *自定义 jQuery*，进一步深入；你可能会发现 jQuery 的元素并不完全符合你的要求。在本章中，我们将看看如何创建和分发补丁，以便临时应用于扩展或更改 jQuery 核心功能。

第三章, *组织你的代码*，探讨了 jQuery 设计模式的使用，这是一个在维护良好组织的代码并使开发和调试更容易的有用概念。我们将看看一些模式的示例以及它们与 jQuery 的结合方式。

第四章, *处理表单*，介绍了表单功能的权威 - 对表单响应进行验证。我们将探讨如何更有效地进行表单验证，然后在一个使用 AJAX 的联系表单中将其发挥到极致，并开发一个文件上传表单。

第五章, *整合 AJAX*，探讨了如何通过使用回调来提高静态站点上数据加载的速度，以及如何使用 jQuery 的 Deferreds 和 Promises 功能来更好地管理这些请求。我们将探讨 AJAX 的最佳实践，并探索如何通过 jQuery 的 Deferreds 和 Promises 功能来更好地管理这些请求。

第六章, *jQuery 中的动画*，带我们进入发现如何更加聪明地管理 jQuery 中的动画，并探索如何最好地管理 jQuery 队列以防止动画积压的旅程。我们还将学习如何实现自定义动画，以及为什么 jQuery 并不总是移动页面元素的正确工具。

第七章, *高级事件处理*，探讨了许多开发者可能仅使用 .on() 或 .off() 来处理事件，但您将看到，如果您真的想充分利用 jQuery，这些方法使用起来更为复杂。在我们探索如何更好地管理这些事件处理程序在我们的代码中何时被调用之前，我们将创建一些自定义事件。

第八章, *使用 jQuery 效果*，继续我们的旅程，通过快速回顾在 jQuery 中使用效果，我们将探讨如何使用回调创建自定义效果，并学习如何更好地管理形成 jQuery 中使用效果的基础的队列。

第九章, *使用 Web 性能 API*，开启了本书的第二部分，我们将在其中探讨在使用 jQuery 时可用的一些更有趣的选项。在本章中，我们将了解如何使用 Page Visibility API 与 jQuery，并了解如何使用它来提供更平滑的外观，减少资源，并仍然在我们的页面上保持复杂的动画。感兴趣吗？当您访问这一章时，您会的！

第十章, *操作图像*，演示了如何通过使用 jQuery 和一些相对简单的数学知识，我们可以对图像应用各种效果。我们可以执行诸如模糊图像之类的简单操作，也可以创建自定义效果。然后，我们将使用其中一些技术来创建一个简单的签名页面，该页面可以导出图像，并对从您自己的网络摄像头提取的图像应用各种效果。

第十一章, *编写高级插件*，涵盖了使用 jQuery 的一个关键主题：创建和分发插件。随着越来越多的功能被移到使用插件，我们将介绍一些创建自己插件背后的技巧和窍门；您会发现，这不仅仅是编写代码那么简单！

第十二章，*使用 jQuery 与 Node-WebKit 项目*，探索了一个有趣的库，它将 Node、JavaScript/jQuery、CSS 和纯 HTML 的最佳元素结合起来，形成了一种模糊了桌面和在线世界界限的东西。我们将通过一些现有的在线代码，并将其转换为桌面应用程序的使用方式，然后将其打包并在网上提供下载。

第十三章，*增强 jQuery 的性能*，带您了解一些优化和增强代码性能的考虑因素、技巧和窍门。您将看到如何轻松地从 DOM 检查器（例如 Firebug）获取基础知识，直到使用 Grunt 自动化您的测试，并最终制定一种监视代码性能的策略。

第十四章，*测试 jQuery*，是我们在 jQuery 掌握世界之旅中的结束篇章，我们将探讨使用 QUnit 测试我们的代码以及如何利用 Grunt 自动化开发中一个否则常规但重要的任务。

# 您需要本书的什么

您需要工作通过本书中大多数示例的只是一个简单的文本或代码编辑器，一个 jQuery 库的副本，互联网访问和一个浏览器。我建议您安装 Sublime Text——无论是版本 2 还是 3；它与 Node 和 Grunt 很好地配合，我们将在本书的各个阶段使用它们。

一些示例使用了额外的软件，比如 Node 或 Grunt——在适当的章节中包含了相关细节，以及从其源中下载应用程序的链接。

# 本书适合谁

本书适合希望不仅仅是编写代码的前端开发人员，而是想要探索可用于扩展他们在 jQuery 开发中技能的提示和技巧的人。要充分利用本书，您应该具备良好的 HTML、CSS 和 JavaScript 知识，并且最好在 jQuery 方面处于中级水平。

# 惯例

在本书中，您会发现一些区分不同信息类型的文本样式。以下是一些这些样式的示例，以及它们含义的解释。

文本中的代码词语如下所示：“我们将从本书的代码下载中提取相关文件；对于这个演示，我们需要`clicktoggle.css`、`jquery.min.js`和`clicktoggle.html`。”

代码块设置如下：

```js
$(this).on("click", function() {
  if (clicked) {
    clicked = false;
      return b.apply(this, arguments);
    }
    clicked = true;
    return a.apply(this, arguments);
  });
});
```

当我们希望引起您对代码块特定部分的注意时，相关行或项目将以粗体显示：

```js
$('#section').hide(2000, 'swing', function() {
 $(this).html("Animation Completed");
});

```

任何命令行输入或输出如下所示：

```js
npm install jquery

```

新术语和重要单词都用粗体显示。你在屏幕上看到的字词，例如菜单或对话框中的字词，都会出现在文字中，就像这样：“当我们查看页面并选择**图像**标签后，经过短暂的延迟，我们应该看到六张新的图片。”

### 注意

警告或重要备注将出现在这样的一个框内。

### 贴士

贴士和技巧会以这种方式出现。


# 第一章：安装 jQuery

本地还是 CDN，我在想……？使用哪个版本……？要支持旧版 IE 吗……？

安装 jQuery 是一项无功的任务，任何开发者都不得不重复进行无数次——可以想象那个人问这个章节开头的一些问题。可以想象为什么大多数人选择使用 **内容传送网络**（**CDN**）链接，但安装 jQuery 不只是走捷径那么简单！

还有更多选项可供选择，我们可以非常具体地选择我们需要使用的内容——在本章中，我们将探讨一些可用的选项，以帮助进一步发展你的技能。我们将涵盖许多主题，其中包括：

+   下载并安装 jQuery

+   自定义 jQuery 下载

+   从 Git 构建

+   使用其他来源安装 jQuery

+   添加源映射支持

+   使用 Modernizr 作为备用方案

有兴趣吗？让我们开始吧。

# 下载并安装 jQuery

就像所有需要使用 jQuery 的项目一样，我们必须从某个地方开始——毫无疑问，你已经下载并安装了 jQuery 成千上万次了；让我们快速回顾一下，以使自己跟上进度。

如果我们浏览到[`www.jquery.com/download`](http://www.jquery.com/download)，我们可以通过两种方法下载 jQuery：下载压缩的生产版本或未压缩的开发版本。如果我们不需要支持旧版 IE（IE6、7 和 8），那么我们可以选择 2.x 分支。但是，如果你仍然有一些死忠粉丝无法（或不想）升级，那么必须使用 1.x 分支。

要包含 jQuery，我们只需要将这个链接添加到我们的页面中：

```js
<script src="img/jquery-X.X.X.js"></script>
```

### 提示

**下载示例代码**

你可以从[`www.packtpub.com`](http://www.packtpub.com)下载你购买的所有 Packt 图书的示例代码文件。如果你在其他地方购买了这本书，你可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，文件将直接通过电子邮件发送给你。

在这里，`X.X.X`表示页面中正在使用的 jQuery 或 Migrate 插件的版本号。

传统智慧认为 jQuery 插件（包括 Migrate 插件在内）应该添加到 `<head>` 标签中，尽管也有有效的理由将其添加到闭合的 `<body>` 标签之前的最后一个语句；将其放在这里可能有助于加快网站的加载速度。

这个论点并不是铁板一块；在某些情况下，将其放在 `<head>` 标签中可能是必要的，这个选择应该根据开发者的需求来决定。我个人偏好将其放在 `<head>` 标签中，因为它能够将脚本（以及 CSS）代码与页面主体中的主要标记分离开来，特别是在较轻的网站上。

我甚至看到一些开发人员争论说，如果在顶部而不是底部添加 jQuery，几乎没有*察觉到*的差异；一些系统，比如 WordPress，在`<head>`部分也包含 jQuery，所以两种方式都可以。关键在于，如果你感觉到速度变慢，那么将你的脚本移到`<body>`标签之前是一个更好的做法。

## 在开发中使用 jQuery

在这个阶段需要注意的一个有用的点是，最佳实践建议不要在开发阶段使用 CDN 链接；而应该下载未压缩的文件并在本地引用。一旦网站完成并准备上传，那么就可以使用 CDN 链接。

## 添加 jQuery Migrate 插件

如果你使用的是 jQuery 1.9 之前的任何版本，那么值得将 jQuery Migrate 插件添加到你的页面中。从这个版本开始，jQuery 核心团队对 jQuery 进行了一些重大更改；Migrate 插件将临时恢复功能，直到旧代码可以更新或替换为止。

该插件向 jQuery 对象添加了三个属性和一个方法，我们可以使用它们来控制其行为：

| 属性或方法 | 评论 |
| --- | --- |
| `jQuery.migrateWarnings` | 这是一个包含由页面上的代码生成的字符串警告消息的数组，按照生成的顺序排列。即使条件发生多次，消息也只会出现在数组中一次，除非调用了`jQuery.migrateReset()`。 |
| `jQuery.migrateMute` | 将此属性设置为`true`以防止在调试版本中生成控制台警告。如果设置了此属性，`jQuery.migrateWarnings`数组仍然会被维护，这允许在没有控制台输出的情况下进行程序化检查。 |
| `jQuery.migrateTrace` | 如果你想要警告但不想在控制台上显示跟踪信息，请将此属性设置为`false`。 |
| `jQuery.migrateReset()` | 此方法清除`jQuery.migrateWarnings`数组并“忘记”已经看到的消息列表。 |

添加插件同样很简单 —— 你只需要添加类似这样的链接，其中`X`表示所使用的插件版本号：

```js
<script src="img/jquery-migrate-X.X.X.js"></script>
```

如果你想了解更多关于插件并获取源代码，那么可以从[`github.com/jquery/jquery-migrate`](https://github.com/jquery/jquery-migrate)进行下载。

## 使用 CDN

我们同样可以使用 CDN 链接提供我们的 jQuery 库 —— jQuery 团队的主要链接由**MaxCDN**提供，当前版本可在[`code.jquery.com`](http://code.jquery.com)找到。当然，如果喜欢的话，我们也可以使用一些其他来源的 CDN 链接 —— 这些的提醒如下：

+   Google ([`developers.google.com/speed/libraries/devguide#jquery`](https://developers.google.com/speed/libraries/devguide#jquery))

+   Microsoft ([`www.asp.net/ajaxlibrary/cdn.ashx#jQuery_Releases_on_the_CDN_0`](http://www.asp.net/ajaxlibrary/cdn.ashx#jQuery_Releases_on_the_CDN_0))

+   CDNJS ([`cdnjs.com/libraries/jquery/`](http://cdnjs.com/libraries/jquery/))

+   jsDelivr (`http://www.jsdelivr.com/#%!jquery`)

但是不要忘记，如果需要的话，我们始终可以将 CDN 提供的文件保存在本地，并引用它。jQuery CDN 总是会有最新版本，尽管可能需要几天时间才能通过其他链接更新。

# 使用其他来源安装 jQuery

好的。好的，让我们继续编写一些代码吧！“接下来做什么？”我听到你在问。

啊哈！如果你认为从主要站点下载并安装 jQuery 是唯一的方法，那么你就错了！毕竟，这本书是关于精通 jQuery 的，所以你不会认为我只会谈论你已经熟悉的内容，对吧？

是的，我们有更多可供选择的选项来安装 jQuery，而不仅仅是使用 CDN 或主要下载页面。让我们开始看看如何使用 Node。

### 注意

每个演示都是基于 Windows 的，因为这是作者首选的平台；在可能的情况下，为其他平台提供了替代方案。

## 使用 NodeJS 安装 jQuery

到目前为止，我们已经看到了如何下载和引用 jQuery，即使用主要的 jQuery 站点下载或通过 CDN 使用。这种方法的缺点是需要手动更新我们的 jQuery 版本！相反，我们可以使用包管理器来帮助管理我们的资产。Node.js 就是这样一个系统。让我们来看一下安装 jQuery 需要执行的步骤：

1.  我们首先需要安装 Node.js —— 前往 [`www.nodejs.org`](http://www.nodejs.org) 以下载适用于你选择平台的软件包；在通过向导时接受所有默认设置（对于 Mac 和 PC）。

1.  接下来，打开一个 Node 命令提示符，然后切换到你的项目文件夹。

1.  在提示符中，输入以下命令：

    ```js
    npm install jquery

    ```

1.  Node 将会获取并安装 jQuery —— 当安装完成时，它会显示一条确认消息：![使用 NodeJS 安装 jQuery](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00324.jpeg)

1.  然后，你可以通过这个链接引用 jQuery：

    ```js
    <name of drive>:\website\node_modules\jquery\dist\jquery.min.js.
    ```

Node 现在已经安装并且准备就绪 —— 虽然我们将其安装在本地文件夹中，但实际上，我们很可能会将其安装在本地 Web 服务器的子文件夹中。例如，如果我们正在运行 WampServer，我们可以安装它，然后将它复制到 `/wamp/www/js` 文件夹中，并使用 `http://localhost/js/jquery.min.js` 引用它。

### 注意

如果你想查看 jQuery **Node 包管理器** (**NPM**) 包的源代码，那么请查看 [`www.npmjs.org/package/jquery`](https://www.npmjs.org/package/jquery)。

使用 Node 安装 jQuery 使我们的工作更简单，但代价是高昂的。Node.js（及其包管理器 NPM）主要用于安装和管理 JavaScript 组件，并期望包遵循**CommonJS**标准。这样做的缺点是，没有范围来管理通常在网站中使用的任何其他资产，例如字体、图像、CSS 文件甚至 HTML 页面。

“为什么会成为一个问题呢？”我听到你问。简单，当我们可以自动管理所有这些资产并仍然使用 Node 时，为什么要让生活变得困难呢？

## 使用 Bower 安装 jQuery

图书馆的一个相对较新的增加是支持使用 Bower 进行安装——基于 Node，它是一个包管理器，负责从互联网上获取和安装包。它设计得更加灵活，可以管理多种类型的资产（如图像、字体和 CSS 文件），并且不会干扰这些组件在页面中的使用方式（不像 Node）。

为了演示目的，我假设您已经从前一节安装了它；如果没有，请在继续以下步骤之前重新查看它：

1.  打开 Node 命令提示符，切换到您想要安装 jQuery 的驱动器，并输入此命令：

    ```js
    bower install jquery

    ```

这将下载并安装脚本，在完成时显示已安装版本的确认，如下面的屏幕截图所示：

![使用 Bower 安装 jQuery](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00325.jpeg)

该库安装在您 PC 上的`bower_components`文件夹中。它看起来类似于这个例子，我已经导航到了`jquery`子文件夹下面：

![使用 Bower 安装 jQuery](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00326.jpeg)

默认情况下，Bower 将 jQuery 安装在其`bower_components`文件夹中。在`bower_components/jquery/dist/`中，我们会找到一个未压缩的版本、压缩的发布版本和源映射文件。然后，我们可以使用以下行引用 jQuery 在我们的脚本中：

```js
<script src="img/jquery.js"></script>
```

不过，我们可以进一步进行。如果我们不想安装 Bower 默认情况下附带的额外文件，我们可以在命令提示符中简单地输入以下内容，仅安装 jQuery 的压缩版本 2.1：

```js
bower install http://code.jquery.com/jquery-2.1.0.min.js
```

现在，我们可以在这一点上真正聪明了；因为 Bower 使用 Node 的 JSON 文件来控制应安装的内容，我们可以利用这一点进行选择，并设置 Bower 同时安装其他组件。让我们来看看这将如何工作——在以下示例中，我们将使用 Bower 来安装 jQuery 2.1 和 1.10（后者为 IE6-8 提供支持）：

1.  在 Node 命令提示符中，输入以下命令：

    ```js
    bower init

    ```

    这将提示您回答一系列问题，此时您可以填写信息或按*Enter*接受默认值。

1.  查看项目文件夹；您应该在其中找到一个`bower.json`文件。在您喜欢的文本编辑器中打开它，然后按照此处显示的代码进行更改：

    ```js
    {
      "ignore": [ "**/.*", "node_modules", "bower_components", "test", "tests" ] ,
     "dependencies": {
     "jquery-legacy": "jquery#1.11.1",
     "jquery-modern": "jquery#2.10"
     }
    }
    ```

此时，您有一个准备好供使用的 `bower.json` 文件。Bower 建立在 Git 之上，所以为了使用您的文件安装 jQuery，通常需要将其发布到 Bower 存储库中。

相反，您可以安装一个额外的 Bower 包，这样您就可以安装您的自定义包而无需将其发布到 Bower 存储库中：

1.  在 Node 命令提示符窗口中，在提示符处输入以下内容

    ```js
    npm install -g bower-installer

    ```

1.  安装完成后，切换到你的项目文件夹，然后输入以下命令行：

    ```js
    bower-installer

    ```

1.  `bower-installer` 命令现在将下载并安装 jQuery 的两个版本，如下所示：![使用 Bower 安装 jQuery](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00327.jpeg)

此时，您已经使用 Bower 安装了 jQuery。在未来的某个时候，您可以自由升级或移除 jQuery，使用正常的 Bower 过程。

### 注意

如果您想了解更多关于如何使用 Bower 的信息，可以在网上找到大量参考资料；[`www.openshift.com/blogs/day-1-bower-manage-your-client-side-dependencies`](https://www.openshift.com/blogs/day-1-bower-manage-your-client-side-dependencies) 是一个帮助您熟悉使用 Bower 的好例子。此外，还有一篇有用的文章讨论了 Bower 和 Node，可以在 [`tech.pro/tutorial/1190/package-managers-an-introductory-guide-for-the-uninitiated-front-end-developer`](http://tech.pro/tutorial/1190/package-managers-an-introductory-guide-for-the-uninitiated-front-end-developer) 找到。

不过，安装 jQuery 的方式不止有 Bower 一种——例如，我们可以使用它来安装多个版本的 jQuery，但仍然受限于安装整个 jQuery 库。

我们可以通过仅引用库中所需的元素来改进这一点。感谢 jQuery 核心团队进行的大量工作，我们可以使用**异步模块定义**（**AMD**）方法来仅引用我们网站或在线应用程序中所需的模块。

## 使用 AMD 方法加载 jQuery。

在大多数情况下，当使用 jQuery 时，开发人员可能只会在其代码中包含对主要库的引用。这本身没有错，但它加载了很多我们不需要的额外代码。

一种更高效的方法，尽管需要一些时间来适应，是使用 AMD 方法。简而言之，jQuery 团队使库更加模块化；这使您可以使用诸如 require.js 的加载器在需要时加载单个模块。

对于每种方法并不都适用，特别是如果您是库的不同部分的重度用户。但是，对于您仅需要有限数量的模块的情况，则是一个完美的选择。让我们通过一个简单的示例来看看实际情况。

### 注意

在我们开始之前，我们需要一个额外的项目-代码使用 Fira Sans 常规自定义字体，该字体可以从 Font Squirrel 获取[`www.fontsquirrel.com/fonts/fira-sans`](http://www.fontsquirrel.com/fonts/fira-sans)。

让我们从以下步骤开始：

1.  Fira Sans 字体默认不带网络格式，因此我们需要将字体转换为网络字体格式。请上传`FiraSans-Regular.otf`文件到 Font Squirrel 的网络字体生成器[`www.fontsquirrel.com/tools/webfont-generator`](http://www.fontsquirrel.com/tools/webfont-generator)。当提示时，将转换后的文件保存到项目文件夹中的名为`fonts`的子文件夹中。

1.  我们需要将 jQuery 和 RequireJS 安装到我们的项目文件夹中，所以打开一个 Node.js 命令提示符并切换到项目文件夹。

1.  接下来，逐一输入以下命令，并在每个命令后按*Enter*：

    ```js
    bower install jquery
    bower install requirejs

    ```

1.  我们需要从附带本书的代码下载链接中提取`amd.html`和`amd.css`文件的副本-它包含一些简单的标记以及一个到`require.js`的链接；`amd.css`文件包含我们将在演示中使用的一些基本样式。

1.  现在，我们需要立即在`require.js`的链接下添加这个代码块-这处理了对 jQuery 和 RequireJS 的调用，我们同时调用了 jQuery 和 Sizzle，jQuery 的选择器引擎：

    ```js
      <script>
        require.config({
          paths: {
            "jquery": "bower_components/jquery/src",
            "sizzle": "bower_components/jquery/src/sizzle/dist/sizzle"
          }
        });
        require(["js/app"]);
      </script>
    ```

1.  现在 jQuery 已被定义，我们需要调用相关模块。在一个新文件中，继续添加以下代码，并将其保存为`app.js`，保存到我们项目文件夹内的一个名为`js`的子文件夹中：

    ```js
    define(["jquery/core/init", "jquery/attributes/classes"], function($) {
      $("div").addClass("decoration");
    });
    ```

    ### 注意

    我们使用`app.js`作为文件名，以与代码中的`require(["js/app"]);`引用相匹配。

1.  如果一切顺利，在浏览器中预览我们工作的结果时，我们将看到此消息：![使用 AMD 方法加载 jQuery](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00328.jpeg)

尽管我们只在这里使用了一个简单的例子，但已足以演示仅调用我们代码中需要使用的模块比调用整个 jQuery 库要容易。的确，我们仍然必须提供一个指向库的链接，但这只是告诉我们的代码在哪里找到它；我们的模块代码重达 29 KB（在 gzip 后为 10 KB），而完整库的未压缩版本为 242 KB！

### 注意

我们的代码已在附带本书的代码下载链接中提供了完整版本的代码，找到并运行`amd-finished.html`文件以查看结果。

现在，可能会有一些情况下，仅使用这种方法引用模块并不是正确的方法；如果您需要经常引用许多不同的模块，这可能适用。

更好的选择是构建 jQuery 库的自定义版本，该版本仅包含我们需要使用的模块，其余模块在构建过程中被删除。这需要更多的工作，但是值得努力-让我们看看涉及的过程。

# 定制从 Git 下载 jQuery

如果我们有兴趣，我们可以真正地大展拳脚，使用 JavaScript 任务运行器 Grunt 构建一个自定义版本的 jQuery。这个过程相对直接，但涉及一些步骤；如果你之前对 Git 有一些了解，那肯定会有所帮助！

### 注意

该演示假定您已经安装了 Node.js——如果尚未安装，请在继续练习之前先执行此操作。

好的，让我们开始执行以下步骤：

1.  如果系统中尚未安装 Grunt，首先需要安装 Grunt——打开 Node.js 命令提示符并输入以下命令：

    ```js
    npm install -g grunt-cli

    ```

1.  接下来，安装 Git——为此，请浏览[`msysgit.github.io/`](http://msysgit.github.io/)以下载该软件包。

1.  双击安装文件启动向导，接受所有默认设置就足够满足我们的需求。

    ### 注意

    如果你想了解更多关于如何安装 Git 的信息，请前往[`github.com/msysgit/msysgit/wiki/InstallMSysGit`](https://github.com/msysgit/msysgit/wiki/InstallMSysGit)了解更多详情。

1.  安装了 Git 后，从命令提示符中切换到 `jquery` 文件夹，并输入以下命令下载并安装构建 jQuery 所需的依赖项：

    ```js
    npm install

    ```

1.  构建过程的最后阶段是将库构建到我们所熟悉和喜爱的文件中；从同一个命令提示符中，输入以下命令： 

    ```js
    grunt

    ```

1.  浏览至 `jquery` 文件夹——其中将有一个名为 `dist` 的文件夹，其中包含我们的自定义 jQuery 构建版本，准备就绪，如下面的截图所示：![从 Git 定制 jQuery 的下载](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00329.jpeg)

## 移除冗余模块

如果库中有我们不需要的模块，我们可以运行自定义构建。我们可以设置 Grunt 任务，在构建库时移除这些模块，保留我们项目中需要的模块。

### 注意

要查看我们可以排除的所有模块的完整列表，请参阅[`github.com/jquery/jquery#modules`](https://github.com/jquery/jquery#modules)。

例如，要从我们的构建中移除 AJAX 支持，我们可以在第 5 步运行以下命令，如前所示：

```js
grunt custom:-ajax

```

这将导致文件在原始未经处理的版本上节省 30 KB，如下图所示：

![移除冗余模块](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00330.jpeg)

JavaScript 和映射文件现在可以像往常一样并入我们的项目中。

### 注意

要详细了解构建过程，请阅读 Dan Wellman 撰写的这篇文章（[`www.packtpub.com/books/content/building-custom-version-jquery`](https://www.packtpub.com/books/content/building-custom-version-jquery)）。

## 使用 GUI 作为替代方案

有一个在线 GUI 可用，执行几乎相同的任务，而无需安装 Git 或 Grunt。它可在[`projects.jga.me/jquery-builder/`](http://projects.jga.me/jquery-builder/)找到，尽管值得注意的是，它已经有一段时间没有更新了！

好的，所以我们已经安装了 jQuery；让我们再看看另一个有用的函数，它将在调试代码中出现错误时帮助我们。自 jQuery 1.9 版本以来，已经提供了对源映射的支持。让我们看看它们是如何工作的，并看一个简单的示例。

# 添加源映射支持

请想象一种情景，假如你创建了一个非常棒的网站，在运行良好，直到你开始收到关于网站上某些基于 jQuery 的功能出现问题的投诉。听起来耳熟吗？

在生产网站上使用未压缩版本的 jQuery 是不可取的选择；相反，我们可以使用源映射。简单来说，这些映射了 jQuery 的压缩版本与原始源代码中的相关行。

从历史上看，当实现源映射时，开发人员曾经遇到过很多麻烦，以至于 jQuery 团队不得不禁用自动使用映射！

### 提示

为了达到最佳效果，建议您使用本地 Web 服务器，例如 WAMP（PC）或 MAMP（Mac），查看此演示，并使用 Chrome 作为您的浏览器。

实现源映射并不困难；让我们来看看如何实现它们：

1.  从本书附带的代码下载链接中提取一个 `sourcemap` 文件夹的副本，并将其保存到本地项目区域。

1.  按下 *Ctrl* + *Shift* + *I* 在 Chrome 中打开 **开发者工具**。

1.  点击 **Sources**，然后双击 `sourcemap.html` 文件—在代码窗口中，最后点击 **17**，如下面的截图所示：![添加源映射支持](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00331.jpeg)

1.  现在，在 Chrome 中运行演示—我们将看到它暂停；回到开发者工具栏，其中第 **17** 行被突出显示。屏幕右侧显示了对 jQuery 库的相关调用：![添加源映射支持](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00332.jpeg)

1.  如果我们在右侧双击 `n.event.dispatch` 条目，Chrome 将刷新工具栏并显示来自 jQuery 库的原始源代码行（突出显示），如下所示：![添加源映射支持](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00333.jpeg)

投入时间去了解源映射是非常值得的—所有最新版本的浏览器都支持它，包括 IE11。尽管我们在这里只使用了一个简单的示例，但原则上完全相同，无论网站使用了多少代码。

### 注意

对于一个更深入的涵盖所有浏览器的教程，值得访问 [`blogs.msdn.com/b/davrous/archive/2014/08/22/enhance-your-javascript-debugging-life-thanks-to-the-source-map-support-available-in-ie11-chrome-opera-amp-firefox.aspx`](http://blogs.msdn.com/b/davrous/archive/2014/08/22/enhance-your-javascript-debugging-life-thanks-to-the-source-map-support-available-in-ie11-chrome-opera-amp-firefox.aspx)—值得一读！

## 添加源映射支持

在前一节中，我们刚刚预览了源映射，源映射支持已经添加到了库中。值得注意的是，当前版本的 jQuery 默认情况下不包含源映射。如果你需要下载更新版本或者首次添加支持，请按照以下步骤操作：

1.  源映射可以从主站点使用 `http://code.jquery.com/jquery-X.X.X.min.map` 下载，其中 `X` 表示正在使用的 jQuery 版本号。

1.  打开压缩版本的库的副本，然后在文件末尾添加这一行：

    ```js
    //# sourceMappingURL=jquery.min.map
    ```

1.  保存并将其存储在项目的 JavaScript 文件夹中。确保在同一个文件夹中有压缩和未压缩版本的库的副本。

让我们继续并看看加载 jQuery 的另一个关键部分：如果由于某种未知原因，jQuery 完全不可用，那么我们可以为我们的站点添加一个后备位置，允许优雅地降级。这是任何站点的一个小但至关重要的部分，并且比你的站点简单崩溃提供了更好的用户体验！

# 使用 Modernizr 作为后备方案

在使用 jQuery 时的最佳实践是确保为库提供后备，以防主要版本不可用。（是的，当它发生时很烦人，但它确实会发生！）

通常情况下，我们可能会在最佳实践建议中使用一些 JavaScript，例如以下示例。这个方法完全有效，但不提供优雅的后备方案。相反，我们可以使用 Modernizr 来执行检查并在所有失败时提供优雅的降级。

### 注意

Modernizr 是一个用于 HTML5/CSS3 的特性检测库，可以在功能不可用的情况下提供标准化的后备机制。你可以在 [`www.modernizr.com`](http://www.modernizr.com) 了解更多信息。

举个例子，在我们网站页面的末尾，代码可能看起来像这样。我们首先尝试使用 CDN 链接加载 jQuery，如果没有成功，再退回到本地副本或者其他备用方案：

```js
<body>
  <script src="img/modernizr.js"></script>
  <script type="text/javascript">
    Modernizr.load([{
      load: 'http://code.jquery.com/jquery-2.1.1.min.js',
      complete: function () {
        // Confirm if jQuery was loaded using CDN link
        // if not, fall back to local version
        if ( !window.jQuery ) {
          Modernizr.load('js/jquery-latest.min.js');
        }
      }
    },
      // This script would wait until fallback is loaded, before loading
      { load: 'jquery-example.js' }
    ]);
  </script>
</body>
```

通过这种方式，我们可以确保 jQuery 要么从本地加载，要么从 CDN 链接加载 —— 如果一切都失败了，那么我们至少可以优雅地退出。

# 加载 jQuery 的最佳实践

到目前为止，我们已经探讨了几种加载 jQuery 到我们页面的方式，除了通常的本地下载库或者在代码中使用 CDN 链接。现在我们已经安装了它，这是一个很好的机会来介绍一些在加载 jQuery 时应该尽量纳入我们页面的最佳实践：

+   始终尝试使用 CDN 在生产站点上包含 jQuery。我们可以利用 CDN 服务提供的高可用性和低延迟；该库可能已经预缓存，避免了再次下载的需要。

+   尝试在本地托管相同版本的库上实现一个备用。如果 CDN 链接不可用（它们不是 100%无懈可击的），那么本地版本将自动启用，直到 CDN 链接再次可用：

    ```js
    <script type="text/javascript" src="img/"></script>
    <script>window.jQuery || document.write('<script src="img/jquery-1.11.1.min.js"><\/script>')</script>
    ```

+   请注意，虽然这同样适用于使用 Modernizr，但如果 jQuery 的版本都不可用，它不提供优雅的备用。虽然人们希望永远不会出现这种情况，但至少我们可以使用 CSS 来提供优雅的退出！

+   使用协议相对/协议独立的 URL；浏览器将自动确定使用哪种协议。如果 HTTPS 不可用，它将回退到 HTTP。如果你仔细观察上一点的代码，它展示了协议独立 URL 的完美例子，通过从主 jQuery Core 网站调用 jQuery。

+   如果可能的话，将所有的 JavaScript 和 jQuery 引用放在页面底部——脚本会阻塞页面的其余部分渲染，直到它们完全渲染完成。

+   使用 jQuery 2.x 分支，除非你需要支持 IE6-8；在这种情况下，使用 jQuery 1.x——不要加载多个 jQuery 版本。

+   如果你使用 CDN 链接加载 jQuery，始终指定你想要加载的完整版本号，比如`jquery-1.11.1.min.js`。

+   如果你正在使用其他库，比如 Prototype、MooTools、Zepto 等，它们也使用`$`符号，那么尽量不要用`$`来调用 jQuery 函数，而是简单地使用 jQuery。你可以通过调用`$.noConflict()`函数将`$`的控制权交还给其他库。

+   对于高级浏览器功能检测，使用 Modernizr。

值得注意的是，可能有一些情况并不总是能够遵循最佳实践；情况可能需要我们对需求做出让步，不能使用最佳实践。然而，尽量将这种情况降至最低，其中一个论点是，如果大部分代码都不遵循最佳实践，那么我们的设计可能存在缺陷！

# 摘要

如果你以为只有手动下载或使用 CDN 链接是包含 jQuery 的唯一方法，那么希望本章打开了你的眼界，让我们花点时间回顾一下我们学到了什么。

我们开始时习惯性地看了大多数开发者可能在快速移动到其他来源之前快速地加载 jQuery 的方式。

我们从如何使用 Node 开始，然后转向使用 Bower 包管理器。接下来，我们看了我们如何可以使用 AMD 方法引用 jQuery 中的个别模块。然后，我们转移到并把注意力转向使用 Git 创建库的自定义版本。然后我们涵盖了如何使用源映射调试我们的代码，看看如何在 Google 的 Chrome 浏览器中启用对它们的支持。

在完成加载 jQuery 的旅程时，我们看到如果完全无法加载 jQuery 会发生什么，并且如何通过使用 Modernizr 来优雅地处理这个问题。然后，我们在章节结束时介绍了一些在引用 jQuery 时可以遵循的最佳实践。

在下一章中，我们将通过了解如何定制 jQuery 来加速进展。这可以通过在运行时替换或修改函数，或者应用补丁来实现；你准备好开始了吗？


# 第二章：自定义 jQuery

好的，我们已经下载了一个版本的 jQuery……接下来该怎么做呢，我在想？

这是一个非常好的问题——让我来揭开所有的秘密！

多年来，jQuery 已经成为一个技艺精湛的库，在世界各地的数百万个网站中被使用。虽然我们通常可以找到一种方法来使用该库来满足需求，但可能会有一些情况需要我们提供自己的补丁或修改，以满足我们的需求。

我们可以使用插件，但是这在一段时间后会变得很烦人——很快就会出现“这个插件，那个插件”综合症，我们变得过于依赖插件。相反，我们可以看一下 jQuery 本身的覆盖功能；是的，它有一些风险，但正如我们将看到的那样，它绝对值得。在本章中，我们将介绍覆盖 jQuery 的基础知识，一些这样做的利与弊，并通过一些替换功能的示例来逐步展示。我们将涵盖以下主题：

+   介绍鸭子打孔

+   替换或修改现有行为

+   创建一个基本的猴子补丁

+   考虑猴子补丁的利与弊

+   分发或应用补丁

准备开始你的冒险了吗……？让我们开始吧！

# 准备工作

在这一点上，我建议你在你的电脑上的某个地方创建一个项目文件夹——为了演示的目的，我假设它被称为`project`并位于你的主硬盘或`C:`驱动器的根目录下。

在文件夹中，继续创建几个子文件夹；这些文件夹需要被命名为`fonts`、`css`、`js`和`img`。

# 在运行时修补库

多年来，数百名开发人员花费了无数个小时为 jQuery 创建补丁，以修复某种描述的错误或在库中提供新功能。

通常的做法是针对核心 jQuery 库提交一个拉取请求供同行考虑。只要补丁按预期工作且不会在库的其他地方引起问题，那么它就会被提交到核心。

这种方法的缺点意味着我们受到 jQuery 的发布时间表的约束；虽然开发人员做得很出色，但在提交到核心之前可能需要一些时间。

## 介绍猴子补丁

该怎么办？我们是否等待，希望我们的补丁会被提交？

对于一些人来说，这可能不是问题——但对于其他人来说，耐心可能不是他们最强的美德，等待可能是他们最不想做的事情！幸运的是，我们可以通过使用一种称为猴子补丁的方法来解决这个问题。

现在——在你问之前——让我告诉你，我不主张任何形式的动物虐待！**猴子补丁**，或者另一种称为**鸭子打孔**的方式，是一种有效的技术，可以在运行时暂时覆盖 jQuery 核心库中现有的功能。猴子补丁也有其风险：主要的风险是冲突，如果更新在库中引入了同名的方法或函数。

### 注意

本章稍后，我们将研究一些需要考虑的风险。

话虽如此，如果小心和深思熟虑地使用猴子补丁，它可以被用来更新功能，直到一个更持久的修复方案被应用。我想，现在是时候进行演示了——我们将看看如何改进 jQuery 中的动画支持，但首先让我们看看如何在运行时替换或修改 jQuery 核心的基础知识。

# 替换或修改现有行为

那么，我们如何在 jQuery 的核心功能中进行（临时）更改？

一切都始于使用**立即调用的函数表达式**（**IIFE**）；然后我们简单地保存原始函数的一个版本，然后用我们的新函数覆盖它。

### 注意

你可能听过使用*自执行匿名函数*这个术语；这是一个误导性的短语，尽管它的含义与 IIFE 相同，但后者是一个更准确的描述。

让我们看看基本框架在实际中是什么样子的：

```js
(function($){
  // store original reference to the method
  var _old = $.fn.method;
  $.fn.method = function(arg1,arg2){
    if ( ... condition ... ) {
      return ....
    } 
    else { // do the default
      return _old.apply(this,arguments);
    }
  };
})(jQuery);
```

如果你期望有更复杂的东西，那么我很抱歉让你失望了；对于基本的猴子补丁，不需要太多的复杂性！补丁中需要加入的内容实际上取决于你试图修复或修改现有代码中的内容。

为了证明这确实是所需的全部内容，让我们看一个（虽然过于简化的）例子。在这个例子中，我们将使用一个标准的点击处理程序来展示狗对主人的反应……只是我们的狗似乎出现了个性问题。

# 创建一个基本的猴子补丁

“个性变化？”我听到你问。是的，没错；我们的狗似乎喜欢喵喵叫……（我想不出任何原因；我不知道有哪些原因！）

在我们的例子中，我们将使用一个简单的点击处理程序来证明（在某些情况下）我们的狗可以喵喵叫；然后我们将逐步了解如何说服它做它应该做的事情。

1.  让我们首先打开我们选择的文本编辑器，然后添加以下标记作为我们补丁的基础：

    ```js
    <!DOCTYPE html>
    <head>
      <title>Demo: Basic Duck Punching</title>
      <meta charset="utf-8">
      <script src="img/jquery.min.js"></script>
      <script src="img/duck.js"></script>
    </head>
    <body>
      <div>Hello World</div>
      <button>Make it a dog!</button>
    </body>
    </html>
    ```

1.  将其保存为`duck.html`文件。在另一个文件中，我们需要为我们的按钮添加动画效果，因此让我们首先添加一个简单的事件处理程序：

    ```js
    $(document).ready(function() {
      jQuery.fn.toBark = function() {
        this.text("The dog says: Miaow!")
        };
        $('button').on('click', function() {
          $('div').toBark();
        });
    })
    ```

    此时，如果我们在浏览器中运行演示，然后点击**让它成为狗！**，我们确实可以看到我们可怜的宠物有些问题，如下截图所示：

    ![创建一个基本的猴子补丁](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00334.jpeg)

    我们明显需要让它看到自己行为的错误，所以现在让我们来修复它。

1.  要解决问题，我们需要覆盖原来的`toBark()`函数。使用我们新的修复替代品；这将采用猴子补丁的形式。将以下代码插入到`.on()`点击处理程序的下方，留出一行空白以提高清晰度：

    ```js
    (function($) {
      var orig = $.fn.toBark;
      $.fn.toBark = function() {
        orig.apply(this,arguments);
        if (this.text() === 'The dog says: Miaow!') {
          this.append(" *Punch* Miaow! *Punch* *Punch* 
          Woof?... *Gives Dog a chew*");
        }
      };
    }(jQuery));
    ```

1.  如果一切顺利，我们现在至少应该看到我们的狗已经恢复了理智，虽然是逐渐地，如下截图所示：![创建一个基本的猴子补丁](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00335.jpeg)

尽管这个小练习虽然极为简化，但它阐明了一些关键点——花点时间更详细地研究一下这一点是值得的，所以现在让我们来做一下。

## 解析我们的猴子补丁

对核心库进行补丁的过程应该谨慎和慎重；技术过程可能很简单，但首先需要回答一些问题。我们将在本章后面讨论其中的一些问题，但现在，让我们假设我们需要应用一个补丁。

基本补丁采用了 IIFE 的格式——我们将所有功能都包含在一个单独的模块中；其范围受到其所放置环境的保护。

### 注

要了解 IIFE 的更详细解释，请参考[`en.wikipedia.org/wiki/Immediately-invoked_function_expression`](http://en.wikipedia.org/wiki/Immediately-invoked_function_expression)。

在我们的例子中，我们首先将原始函数存储为一个对象`orig`的副本。然后我们启动我们的新替换`.toBark()`函数，在其中我们首先调用`.toBark()`函数，但紧随其后进行替换：

```js
(function($) {
  var orig = $.fn.toBark;
  $.fn.toBark = function() {
    orig.apply(this,arguments);
    if (this.text() === 'The dog says: Miaow!') {
      this.append(" *Punch* Miaow! *Punch* *Punch* 
      Woof?... *Gives Dog a chew*");
    }
  };
}(jQuery));
```

我们补丁的一个关键部分是使用`.apply()`函数——这将调用一个函数，并将上下文设置为应用函数的对象。在这种情况下，在函数内部引用`this`关键字将指向该对象。

在我们的演示中使用的 IIFE 的格式有许多优点，如下：

+   我们可以减少作用域的查找——IIFE 允许您将常用的对象传递给匿名函数，因此它们可以在 IIFE 中被引用为本地作用域的对象

    ### 注

    由于 JavaScript 首先在本地范围内查找属性，这消除了全局查找的需要，提供更快的查找速度和性能。使用 IIFE 可以防止局部变量被全局变量覆盖。

+   IIFE 可通过压缩来优化代码——我们可以将对象作为本地值传递给 IIFE；压缩器可以将每个全局对象的名称缩减为单个字母，前提是没有一个变量已经具有相同的名称

使用 IIFE 的缺点是可读性；如果我们的 IIFE 包含大量代码，那么必须滚动到顶部才能弄清楚正在传递哪些对象。在更复杂的示例中，我们可以考虑使用 Greg Franko 开发的模式以解决这个问题：

```js
(function (library) {
  // Call the second IIFE and locally pass in the global jQuery, 
  window, and document objects
  library(window, document, window.jQuery);
}
// Locally scoped parameters
(function (window, document, $) {
  // Library code goes here
}));
```

需要注意的是，这种模式是将变量分为两个部分，以便我们可以避免过度上下滚动页面的需要；它仍会产生相同的最终结果。

我们将更深入地讨论在 jQuery 中使用模式，第三章中的*整理你的代码*。现在我们已经看到了一个补丁的作用，让我们继续并花点时间考虑一下我们可以从使用猴子补丁过程中获得的一些好处。

# 考虑猴子补丁的好处

好了，所以我们已经看到了一个典型的补丁是什么样子；然而，问题是，为什么我们要使用这种方法来打补丁核心库功能呢？

这是一个非常好的问题-这是一个有风险的方法（正如我们将在本章稍后在*考虑 Monkey Patching 的缺陷*部分看到的）。使用这种方法的关键是要有所考虑的方法；考虑到这一点，让我们花一点时间考虑一下插入 jQuery 的好处：

+   我们可以在运行时替换方法、属性或函数，其中它们缺乏功能或包含需要修复而不能等待官方补丁的 bug。

+   Duck punching jQuery 允许你修改或扩展 jQuery 的现有行为，而无需维护源代码的私有副本。

+   我们有一个安全网，可以将补丁应用于运行在内存中的对象，而不是源代码；换句话说，如果完全出错，我们可以简单地从站点中撤回补丁，并保持原始源代码不变。

+   Monkey patching 是一种很好的方法，用于分发与原始源代码并存的安全或行为修复；如果对补丁的弹性有任何疑问，我们可以在提交到源代码之前进行压力测试。

言归正传，让我们开始编写一些演示代码！我们将逐步介绍一些示例补丁，这些补丁同样适用于 jQuery，从动画开始。

# 更新 jQuery 中的动画支持

如果你花了任何时间用 jQuery 开发，你很可能创建了一些形式的动画，其中包括以固定频率管理更改-这听起来熟悉吗？

当然，我们可以使用`setInterval()`函数来实现这一点，但它-像`setTimeOut()`函数一样-并不理想。这两个函数在启动之前都有一个延迟，这个延迟因浏览器而异；它们都同样占用资源！

相反，我们可以使用**requestAnimationFrame**（**rAF**）API，这个 API 现在由大多数现代浏览器支持，根据来自[caniuse.com](http://caniuse.com)的这个图表，绿色标签显示了哪些浏览器版本支持**requestAnimationFrame**：

![更新 jQuery 中的动画支持](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00336.jpeg)

[requestAnimationFrame（rAF）API](http://caniuse.com)的伟大之处在于它占用的资源较少，不会影响页面上的其他元素，并且在失去焦点时被禁用（非常适合减少功耗！）。因此，你可能会认为默认情况下在 jQuery 中实现它是有道理的，对吗？

## 探索 requestAnimationFrame API 的过去

具有讽刺意味的是，jQuery 在 1.6.2 版本中使用了 rAF；在 1.6.3 中被取消了，主要是因为当窗口重新获得焦点时，动画会堆积起来。部分原因可以归因于 rAF 的（错误）使用方式，以及为了纠正这些问题需要进行重大更改。

### 注意

要查看一些与时序相关的问题，请访问[`xlo.co/requestanimationframe`](http://xlo.co/requestanimationframe)——该站点上有一些演示，完美地说明了为什么时序如此关键！

## 今天使用 requestAnimationFrame 方法

幸运的是，今天我们仍然可以使用 requestAnimationFrame 与 jQuery；jQuery 的开发者之一 Corey Frang 编写了一个插件，可以钩入并重写核心库中的`setInterval()`方法。

### 注意

该插件的原始版本可从 GitHub 下载，网址为[`github.com/gnarf/jquery-requestAnimationFrame/blob/master/src/jquery.requestAnimationFrame.js`](https://github.com/gnarf/jquery-requestAnimationFrame/blob/master/src/jquery.requestAnimationFrame.js)。

当我们使用 jQuery 时，这可能是我们可以做出的最简单的更改之一——在练习结束时，我们将探讨这个问题以及更多其他问题。现在，让我们继续编写一些代码吧！

## 创建我们的演示

对于我们的下一个演示，我们将使用开发者 Matt West 创建的 CodePen 示例的更新版本——原始演示可从[`codepen.io/matt-west/pen/bGdEC/`](http://codepen.io/matt-west/pen/bGdEC/)获取；我更新了外观并移除了 Corey 插件的供应商前缀元素，因为它们已不再需要。

为了让你对我们即将实现的内容有所了解，我们将重写主`setInterval`方法；尽管它可能看起来像是调用了 jQuery 方法，但实际上`setInterval`是一个纯 JavaScript 函数，如下所示：

```js
jQuery.fx.start = function() {
  if ( !timerId ) {
    timerId = setInterval( jQuery.fx.tick, jQuery.fx.interval );
  }
};
```

我还更改了字体——为了这个演示，我使用了 Noto Sans 字体，可以从[`www.fontsquirrel.com/fonts/noto-sans`](http://www.fontsquirrel.com/fonts/noto-sans)下载；如果您想使用其他字体，请随意相应地更改代码。

准备好了吗？让我们开始执行以下步骤：

1.  从随书附带的代码下载链接中提取`raf.css`、`raf.js`和`raf.html`文件，并将它们保存到项目文件夹中。

1.  在一个新文件中，添加以下代码——这是我们的猴子补丁或 Corey 原始插件的修改版本。我们首先初始化了一些变量，如下所示：

    ```js
    (function( jQuery ) {
      var animating,
          requestAnimationFrame = window.requestAnimationFrame,
          cancelAnimationFrame = window.cancelAnimationFrame;

          requestAnimationFrame = window["RequestAnimationFrame"];
          cancelAnimationFrame = window["CancelAnimationFrame"];
    ```

1.  接下来是动画函数，它从主`requestAnimationFrame`方法中调用：

    ```js
      function raf() {
        if ( animating ) {
          requestAnimationFrame( raf );
          jQuery.fx.tick();
        }
      }
    ```

1.  现在我们需要我们的主`requestAnimationFrame`方法；继续在`raf()`事件处理程序的下方直接添加以下代码行：

    ```js
    if ( requestAnimationFrame ) {
      // use rAF
      window.requestAnimationFrame = requestAnimationFrame;
      window.cancelAnimationFrame = cancelAnimationFrame;
      jQuery.fx.timer = function( timer ) {
        if ( timer() && jQuery.timers.push( timer ) && !animating ) {
          animating = true;
          raf();
        }
      };
      jQuery.fx.stop = function() {
        animating = false;
      };
    } ( jQuery ));
    ```

1.  将文件保存为`jquery.requestAnimationFrame.js`，放在主项目文件夹下名为`js`的子文件夹中。

1.  如果在浏览器中运行演示，当你按下**开始动画**时，你会看到进度条移动，如下图所示：![创建我们的演示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00337.jpeg)

1.  为了证明插件正在被使用，我们可以使用谷歌浏览器的**Developer Tools**中的**Timeline**选项——点击红色的**Record**图标，然后运行演示，然后停止它产生以下内容：![创建我们的演示](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00338.jpeg)

    ### 提示

    确保在**Timeline**下勾选了**JS Profiler**复选框——将会显示详细信息；可能需要向下滚动查看**Event**条目。

这可能是我们能在 jQuery 中最容易进行的覆盖功能的改变之一，但也可能是最具争议性的之一——后者是由我们如何使用它决定的。然而，关键点是，我们可以使用多种格式覆盖功能。

最安全的方法是使用插件；在我们的例子中，我们使用了一个修改过的插件——原始插件是从 jQuery 1.8 引入的，所以这里做的改动只是将它带入了现代化。我们当然也可以完全走向相反的方向，创建一个覆盖现有功能的函数——这更有风险，但如果小心操作，是值得的！让我们看一个简单的例子，通过覆盖`.hasClass()`来在适当时切换到 WebP 格式的图片。

# 添加 WebP 支持到 jQuery

在这一点上，我有一个小小的坦白：为 jQuery 添加全面的 WebP 支持可能会超出本书的范围，更别提填满大部分页面了！

### 注意

WebP 是谷歌创建的一种比标准 PNG 文件压缩更好的相对较新的图像格式，您可以在[`developers.google.com/speed/webp/`](https://developers.google.com/speed/webp/)上了解更多。目前，Chrome 和 Opera 原生支持这种格式；其他浏览器在添加支持后也将显示 WebP 图像。

下一个演示实际上是关于我们如何根据浏览器是否支持新格式来在屏幕上显示内容的两种不同方式之间进行切换的。一个很好的例子是，我们可以尽可能使用 CSS3 动画，并在那些不原生支持 CSS3 动画的浏览器上回退到使用 jQuery。

在我们的下一个演示中，我们将使用类似的原理创建一个 monkey patch，以覆盖`.hasClass()`方法，以便在支持的情况下自动切换到 WebP 格式的图片。

### 注意

如果你想了解更多，可以在[`blog.teamtreehouse.com/getting-started-webp-image-format`](http://blog.teamtreehouse.com/getting-started-webp-image-format)上找到一个有用的讨论，介绍了如何开始使用这种格式。

## 入门

为了展示这个演示，我们需要使用两种不同格式的图片；我先假设 JPEG 被用作我们的基本格式。另一张图片，当然，需要是 WebP 格式的！

如果您还没有准备好将图像转换为 WebP 格式的方法，那么您可以使用谷歌提供的工具来进行转换，这些工具可在[`developers.google.com/speed/webp/download`](https://developers.google.com/speed/webp/download)下载。这里提供了 Windows、Linux 和 Mac OS 的下载版本——在本练习中，我将假设您正在使用 Windows：

1.  在下载页面上，单击[`downloads.webmproject.org/releases/webp/index.html`](http://downloads.webmproject.org/releases/webp/index.html)，然后查找`libwebp-0.4.2-windows-x64.zip`（如果您仍在使用 32 位 Windows 平台，请选择`x86`版本）。

1.  下载后，将`libwebp-0.4.2-windows-x64`文件夹解压缩到项目文件夹中的一个安全文件夹中，然后导航到其中的`bin`文件夹。

1.  打开第二个资源管理器视图，然后导航到您存储图像的位置，并将其复制到`bin`文件夹中。

1.  打开命令提示符，然后导航到`C:\libwebp-0.4.2-windows-x64\bin`。

1.  在提示符下，输入此命令，将两个名称分别替换为您的 JPEG 和 WebP 图像的名称：

    ```js
    cwebp <name of JPG image> -o <name of WebP image>

    ```

1.  如果一切顺利，我们将会得到一个类似于以下屏幕截图的屏幕，并且我们的 WebP 格式图像将会出现在`bin`文件夹中：![开始](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00339.jpeg)

1.  最后一步是将图像复制到我们的项目文件夹中，以便在我们的演示的下一阶段中使用。

## 创建我们的补丁

现在我们准备好了图片，可以开始设置我们演示的标记了：

1.  现在，将以下代码复制到一个新文件中，并将其保存为`replacewebp.html`：

    ```js
    <!DOCTYPE html>
    <head>
      <title>Demo: supporting WebP images</title>
      <script src="img/jquery.js"></script>
      <script src="img/jquery.replacewebp.js"></script>
    </head>
    <body>
      <img class="webp" src="img/phalaenopsis.jpg" />
    </body>
    </html>
    ```

1.  接下来，我们需要添加我们的猴子补丁——在一个新文件中，添加以下代码并将其保存为`jquery.replacewebp.js`。这涉及到一些更复杂的内容，所以我们将分块介绍，从标准声明开始：

    ```js
    (function($){
      var hasClass = $.fn.hasClass;
      $.fn.hasClass = function(value) {
        var orig = hasClass.apply(this, arguments);
        var supported, callback;
    ```

1.  接下来是执行测试以查看我们的浏览器是否支持使用 WebP 图像格式的函数；将以下代码立即添加到变量分配的下方：

    ```js
    function testWebP(callback) {
      var webP = new Image();
      webP.src = "data:image/webp;   base64,UklGRi4AAABX"
      + "RUJQVlA4TCEAAAAvAUAAEB8wAiMw"
      + "AgSSNtse/cXjxyCCmrYNWPwmHRH9jwMA";
      webP.onload = webP.onerror = function () {
        callback(webP.height == 2);
      };
    };
    ```

1.  接下来，我们使用`testWebP`函数来确定我们的浏览器是否支持 WebP 图像格式——如果支持，我们将更改所使用的文件扩展名为`.webp`，如下所示：

    ```js
    window.onload = function() {
      testWebP(function(supported) {
        console.log("WebP 0.2.0 " + (supported ? "supported!" : "not 
        supported."));
        $('.webp').each(function() {
          if (supported) {
            src = $(this).attr('src');
            $(this).attr('src', src.substr(0, src.length-3) + 'webp');
            console.log("Image switched to WebP format");
          }
      })
    });
    }
    ```

1.  我们通过执行函数的原始版本来完成我们的函数，然后用与 IIFE 通常关联的关闭括号终止它：

    ```js
       return orig;
      };
    })(:jQuery);
    ```

1.  然后，我们需要再添加一个函数——这用于启动对`.hasClass()`的调用；继续添加以下代码行到猴子补丁函数的下方：

    ```js
    $(document).ready(function(){
      if ($("img").hasClass("webp")) {
        $("img").css("width", "80%");
      }
    });
    ```

1.  如果一切顺利，当我们运行我们的演示时，我们将看到一幅蝴蝶兰或蛾蝶兰的图像，如下面的屏幕截图所示：![创建我们的补丁](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00340.jpeg)

这一点并没有什么特别之处；实际上，你可能在想我们到底产生了什么，对吧？

啊哈！如果你使用 DOM 检查器（如 Firebug）检查源代码，就会看到这个问题的答案，如下所示：

![创建我们的补丁](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00341.jpeg)

注意它正在显示 JPEG 格式的图像？那是因为 Firefox 在出厂时不支持这种格式；只有 Google Chrome 支持：

![创建我们的补丁](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00342.jpeg)

如果您切换到使用 Google Chrome，则可以通过按下*Ctrl* + *Shift* + *I*来查看源代码。您可以清楚地看到所使用格式的变化。如果您仍然怀疑，甚至可以查看 Google Chrome 的**控制台**选项卡。在这里，它清楚地显示了引用了补丁，因为它显示了您期望看到的两条消息：

![创建我们的补丁](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00343.jpeg)

我们已经创建了我们的补丁，它似乎运行正常——这就是我们需要做的全部了，对吗？错，还有更多步骤我们应该考虑，其中一些甚至可能会阻止我们将补丁发布给更广泛的受众，至少暂时是这样。

有一些我们需要考虑的要点和可能需要采取的行动；让我们暂停一下，考虑一下我们需要从这里走向何方，就开发而言。

## 进一步的事情

在这个示例中，我们重写了一个现有方法来说明“鸭子打”——实际上，在发布之前，我们需要再花一些时间来完善我们的补丁！

这样做的主要原因是下载比我们实际需要的内容多；为了证明这一点，看一下在 Google Chrome 中运行演示时的**资源**选项卡：

![进一步的事情](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00344.jpeg)

就像我们需要进一步确认一样，**时间轴**选项卡中的这段摘录也确认了 JPEG 和 WebP 图像的存在以及对下载时间的影响：

![进一步的事情](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00345.jpeg)

我们在这里创建了一个补丁，以说明*可以*做什么；实际上，我们很可能会包含代码来执行不同的操作在我们的内容上。首先，我们可以做以下操作：

+   包括支持更多的图像格式——这可以包括 JPEG，GIF 或 SVG。

+   将代码硬编码为接受一个图像格式；通过使其更通用，我们可以扩展我们补丁的可用性。

+   jQuery 正朝着基于插件的架构发展；我们真的应该考虑修补核心代码吗？在代码中创建一个钩子可能会更有用，这样可以使用新插件扩展现有功能。

+   我们使用了`.hasClass()`作为覆盖现有方法的基础；这真的是最合适的做法吗？虽然乍一看可能很有用，但实际上，其他人可能不同意我们覆盖`.hasClass`的选择，并认为其他方法更有用。

有很多问题可能会被提出并需要回答；只有经过仔细考虑，我们才能最大程度地使我们的补丁成功，并有可能考虑提交到核心中。

让我们改变方法，转而考虑猴子补丁的一个关键部分。这个过程有其风险，所以让我们花点时间考虑一下这些风险以及这些风险可能对我们的工作产生的影响。

# 考虑猴子补丁的缺陷

现在我们已经看到一些示例在实际中的应用，值得花点时间考虑一下对库进行猴子补丁的一些风险，比如 jQuery：

+   主要风险，也是最容易造成麻烦的风险是冲突。想象一下，您已经创建了一个包含一些函数的补丁——我们将这些函数称为 `1`、`2` 和 `3`。添加另一个补丁，重要的是我们不要使用相同的函数名称；否则，很难确定 `1`、`2` 或甚至 `3` 哪一个先执行？

+   另一个风险是安全性。如果 jQuery 等库可以进行猴子补丁，那么有什么能阻止任何人引入破坏现有代码的恶意构造？可以认为此风险在客户端脚本中始终存在；与标准插件相比，当您覆盖核心 jQuery 功能时，风险更大。

+   总会有一个风险，即对核心库的升级可能会引入更改，不仅会破坏您的补丁，而且会删除或修改否则可以为您的补丁提供基础的功能。这将阻止使用 jQuery 的网站升级，并最终使其容易受到攻击。

+   添加过多没有经过仔细考虑的补丁将使您的 API 庞大且缓慢；这将降低响应速度并使其更难管理，因为我们必须花更多时间剖析代码，然后才能找到问题的关键所在。

+   任何猴子补丁都应该真正保留在您的网站内部；它们将基于直接修改 jQuery 的代码，而不是使用标准 jQuery 插件提供的预定义机制。作者可能没有像他们为插件所做的那样广泛地测试他们的猴子补丁；如果您使用别人的补丁，这会带来更大的风险。

+   如果一个补丁包含大量函数，则更改核心功能的影响范围更广更大；进行这些更改可能会破坏其他人的补丁或插件。

哎呀！这里有严重的问题！如果我们面临这些风险，那么为什么还要使用这个过程呢？

这是一个很好的问题；适当使用时，猴子补丁是一种有用的技术，可以提供额外的功能或纠正问题。它甚至可以作为提交之前对代码进行压力测试的手段。还有一个论点认为功能应该包含在插件中，有充分的理由：

+   插件可以发布供他人使用；如果插件可用，他们可以通过 GitHub 等网站贡献修复或更新。

+   插件可能与 jQuery 的更多版本兼容，而不仅仅是简单的补丁；后者可能专门用于修复特定问题。

+   制作一个覆盖多个修复的补丁可能会导致文件大小较大或核心功能的许多更改；这在插件框架内更好地管理，可以包括其他功能，如国际化。

+   jQuery Core 正在朝着更精简、更快速的架构发展；添加大量补丁将增加冗余功能的水平，并使其对其他开发人员的使用不太吸引人。

猴子补丁的关键不是滥用它；这是一个有效的工具，但只有在耗尽所有其他可能的解决方案后才真正有效。如果您急需修复问题并且不能等待官方更新，那么考虑猴子补丁 jQuery—只是要小心如何操作！

# 分发或应用补丁。

一旦我们的补丁完成，我们需要分发它；诱人的是简单地更新 jQuery 版本并与我们的插件一起发布，或在我们的网站中使用它。然而，使用这种方法有一些缺点：

+   我们无法利用浏览器的缓存功能；如果我们使用缓存版本的 jQuery，则要么不包含我们的修补代码，要么从服务器拉取一个新副本。

+   对 jQuery 的副本进行补丁意味着我们被锁定在那个版本的 jQuery 上。这会阻止最终用户能够使用他们自己的 jQuery 版本、CDN 链接，甚至是更新的 jQuery 版本（假设补丁仍然有效！）。

+   允许补丁在运行时独立运行意味着它只会修补源代码中的对象；如果出现严重错误，那么我们可以放弃该补丁，仍然保留干净（未补丁）的 jQuery 版本。对源代码进行更改并不会给我们带来这种便利。

相反，我们可以使用一些替代方法来应用补丁：

+   我们可以简单地在插件或网站内的单独文件中包含我们的补丁—这样可以保持核心 jQuery 库的清洁，尽管这意味着从服务器请求补丁文件的轻微开销。用户然后可以简单地链接到运行时文件的副本，并在情况发生变化时丢弃。

+   补丁也可以作为 Gist 分发—这使其独立于我们的网站或插件，并允许其他人评论或提出建议，这些建议可以纳入我们的代码中。

    ### 注意

    例如，我为`replacewebp.js`补丁创建了以下 Gist—这可以在 [`gist.github.com/alibby251/89765d464e03ed6e0bc1`](https://gist.github.com/alibby251/89765d464e03ed6e0bc1) 上找到，并且可以链接到项目中作为分发代码的手段：

    ```js
    <script src="img/89765d464e03ed6e0bc1.js"></script>
    ```

+   如果补丁在 GitHub 存储库中可用—作为现有项目的一部分或独立存在。GitHub 将允许用户提交拉取请求以帮助改进现有补丁，然后再考虑提交到核心。

+   我们还有另一种选择：补丁可以通过前端包管理器（如 Bower ([`www.bower.io`](http://www.bower.io)) 或 Jam ([`www.jamjs.org`](http://www.jamjs.org))）进行打包和交付。

    ### 注意

    有关通过 Bower 下载包装内容的更多信息，请参阅 [`bower.io/docs/creating-packages/`](http://bower.io/docs/creating-packages/)。

这些是我们可以使用的分发补丁的一些选项；使用其中一些选项意味着我们可以让我们的补丁面向最广泛的受众，并希望从他们的测试和反馈中受益！

# 概要

在过去的几页中，我们涵盖了大量内容，其中一些可能会让你头晕，所以让我们喘口气，思考一下我们所学到的内容。

我们从介绍库的打补丁开始，比如 jQuery，并介绍了“鸭子补丁”（或者叫做猴子补丁）。我们看了如何使用这种方法替换或修改 jQuery 的现有行为，然后开始创建一个基本的猴子补丁，并详细解释了其在代码中的应用。

接下来，我们将看一下使用猴子补丁可以获得的一些好处；我们谈到了涉及的风险以及在创建和应用补丁时需要考虑的一些缺陷。

然后我们转而逐步完成了一些演示，探讨了一些我们可以暂时修改代码的方式，最后看了一下如何将我们的补丁用于生产环境。

开发任何形式的补丁或插件都需要保持良好的代码才能成功。在下一章中，我们将看到如何通过学习设计模式来改善我们在这个领域的技能，以更好地组织我们的代码。


# 第三章：组织你的代码

是否组织代码，这是问题…

在我们迄今的旅程中，我们已经涵盖了下载 jQuery 的各种方式，以及如何用自定义代码覆盖核心功能，但是——误引用那位著名的侦探：我们应该如何组织我们的代码？

好吧，你可能会认为我在这里搞疯了，但请跟我坚持下去；精通 jQuery 这样的语言不仅仅是制作复杂的代码，而是编写结构良好、简洁、易于阅读的代码。

在这一章中，我们将回到基础，介绍 jQuery 中可用的一些设计模式。我们将看到本章讨论的一些技术如何帮助改善您的代码格式，并使您成为更好的编码人员。在本章中，我们将涵盖以下主题：

+   介绍设计模式以及为什么我们应该使用它们

+   分解设计模式的结构

+   探索不同设计模式的一些示例以及使用它们的好处

+   探索 jQuery 库中的模式使用

准备好开始了吗？让我们开始…

# 介绍设计模式

有多少次你看网站时对美丽的设计感到惊叹，只是发现代码看起来像传说中的一团糟？一个常见的误解是外观是设计师的领域；这并不正确，因为代码的设计同样重要。

我们如何绕过这个问题？很简单，我们可以使用**设计模式**或一组构造，帮助提供解决方案，并让我们更专注于项目中想要提供的功能。

最初是由建筑师克里斯托弗·亚历山大于 1977 年创立的，工程师们自那时以来一直使用这些早期原则，并发展成我们现在知道的设计模式。这项工作后来在 1995 年由**四人组**（GoF）在他们标志性的书籍*设计模式：可复用的面向对象软件元素*中进一步推广。

它们不仅推动了设计模式的应用范围，还提供了一些设计技巧和陷阱；它们还对提供今天经常使用的二十三种核心模式起到了重要作用（其中，我们将涵盖在 jQuery 开发中常用的模式）。我们将看看今天正在使用的一些模式，但首先，让我们回答一个简单的问题。设计模式真正意味着什么，它们如何帮助我们编写清晰简洁的代码，从而减少不必要的重复？

# 定义设计模式

在基本层面上，设计模式采用预定义模板或一组可重用原则的格式，帮助对不同方法进行分类，作为支持良好设计的一部分。

为什么使用它们？很简单，将设计模式纳入我们的项目有三大好处：

+   **设计模式是经过验证的解决方案**：它们基于解决软件开发中问题的坚实方法，并基于帮助创建所使用模式的开发人员的经验

+   **模式可重用**：尽管它们通常代表一个现成的解决方案，但它们可以根据我们的需求轻松适应。

+   **模式是表达性的**：它们包含一组结构和词汇，帮助您清晰而优雅地表达大型解决方案

此时，您可能会原谅以为模式必须是一门精确的科学，我们受到所使用模式框架的限制。事实并非如此；它们并不是一个确切的解决方案，而仅仅是一个帮助提供解决方案的方案。

更进一步地，我们应考虑在工作中使用设计模式的其他几个原因：

+   我们可以有效地编写或预防可能在开发过程中稍后造成重大问题的小问题——使用经过验证的技术消除了对我们代码结构的担忧，并使我们能够专注于我们解决方案的质量。

+   模式旨在提供通用解决方案，不将其限制在特定问题上，而是可应用于改善我们代码的结构。

+   一些模式，如果明智地选择，可以帮助减少代码量，避免重复；它们鼓励我们仔细查看我们的代码，减少重复，并坚持使用**不要重复自己**（**DRY**）原则，这是 jQuery 的基本原则之一。

+   模式不是一次性、一时半刻的解决方案；我们的工作可能有助于改善现有设计，甚至提供创造新模式的范围！这种持续改进有助于确保模式随着时间的推移变得更加健壮。

不论其目的如何，设计模式的一个关键原则是，除非它们经过模式社区的严格测试，否则它们并不总被视为设计模式。许多可能看起来像是模式；实际上，它们更可能是原型模式或者一个已经被创建但尚未被充分测试以被视为真正模式的模式。

任何设计模式的核心原则都基于亚历山大的信念，即它们应始终代表一个过程和一个产出。后一术语被故意地设定得模糊一些；它应该代表一些可视的东西，但具体的视觉输出内容将取决于所选模式的上下文。

所以，既然我们已经看到了设计模式是什么，让我们讨论一下它们是什么样子的。它们由特定的元素或结构组成吗？在我们查看一些示例之前，让我们首先考虑一下设计模式的组成和我们如何有效使用它。

# 解剖设计模式的结构

如果您仔细查看任何设计模式，您会发现它由一个规则组成，该规则建立了以下内容之间的关系：

+   一种上下文

+   在该上下文中产生的一系列力量

+   允许这些力量在上下文中自行解决的配置

这三个关键方面可以进一步分解为许多不同的元素，除了模式名称和描述之外：

| 元素 | 目的或功能 |
| --- | --- |
| 上下文概述 | 模式有效的上下文，以响应用户的需求。 |
| 问题陈述 | 解决的问题陈述，以便我们了解模式的意图。 |
| 解决方案 | 描述用户问题如何在易于理解的步骤和感知列表中解决。 |
| 设计 | 模式设计的描述，特别是用户与其交互时的行为。 |
| 实现 | 模式将如何实现的指南。 |
| 插图 | 模式中类的可视化表示，如 UML 图表。 |
| 示例 | 模式的最小形式实现。 |
| 先决条件 | 用于支持描述的模式使用的其他模式是什么？ |
| 关系 | 这种模式是否类似（或模仿）任何现有模式？ |
| 已知用法 | 这种模式是否已经在实际应用中使用？如果是，是在哪里以及如何使用？ |
| 讨论 | 团队或作者关于使用模式的好处的想法。 |

使用模式的美妙之处在于，虽然在规划和文档编制阶段可能需要一定的努力，但它们是有用的工具，有助于使团队中的所有开发人员保持一致。

在创建新模式之前，先看看现有模式是值得的——可能已经有人在使用，这样就减少了从头设计并经过漫长的测试过程的必要性，才能被其他开发人员接受。

# 模式分类

现在我们已经了解了典型设计模式的结构，让我们花点时间考虑一下可用的模式类型。模式通常分为以下三类，这是最重要的类别之一：

+   **创建型模式**：这些模式关注我们如何创建对象或类。虽然这听起来可能很简单（在某些方面，比如常识），但它们在需要控制对象创建过程的大型应用程序中可能非常有效。创建型模式的示例包括抽象、单例或建造者。

+   **结构设计模式**：这些模式关注如何管理对象之间的关系，以使您的应用程序以可扩展的方式构建架构。结构模式的一个关键方面是确保应用程序的一个部分的更改不会影响到所有其他部分。该组涵盖了诸如代理、适配器或外观等模式。

+   **行为模式**：这些模式关注对象之间的通信，包括观察者、迭代器和策略模式。

有了这个想法，让我们花点时间探索一些常用的设计，从**组合模式**开始。

## 组合模式

如果你花时间用 jQuery 开发，你有多频繁地编写类似于这样的代码：

```js
// Single elements
$("#mnuFile").addClass("active");
$("#btnSubmit").addClass("active");

// Collections of elements
$("div").addClass("active");
```

没有意识到的是，我们正在使用组合模式的两个实例——它是结构模式组中的一个成员；它允许您以相同的方式对单个对象或一组对象应用相同的处理，而不管我们要定位多少个项目。

简而言之，当我们对一个元素或一组元素应用方法时，会应用一个 jQuery 对象；这意味着我们可以以统一的方式处理任何一个集合。

那么，这意味着什么？让我们看看另外一些例子：

```js
// defining event handlers
$("#tablelist tbody tr").on("click", function(event) {
  alert($(this).text());
});
$('#btnDelete').on("click", function(event) {
  alert("This item was deleted.");
});
```

使用组合模式的优点在于，我们可以在每个实例中使用相同的方法，但对每个元素应用不同的值；它为最终用户提供了一个统一的界面，同时在后台无缝应用更改。

### 组合模式的优缺点

使用组合模式可以简单也可以复杂；使用这种模式有优点和缺点，我们应该考虑：

+   我们可以对顶级对象调用一个函数，并将其应用于结构中的任何一个或所有节点，产生相同的结果。

+   组合设计中的所有对象都是松散耦合的，因为它们都遵循相同的接口。

+   组合设计为对象提供了一个良好的结构，而不需要将它们保存在数组中或作为单独的变量。

使用组合模式也有一些缺点；以下是需要考虑的主要问题：

+   我们并不总是能够确定我们正在处理单个项还是多个项；API 对单个项和多个项使用相同的模式。

+   如果组合模式超出一定大小，您的站点的速度和性能将受到影响。

让我们继续看看更多的模式；接下来是**适配器模式**。

## 适配器模式

我们可以使用 jQuery 来切换分配给选择器的类；但在某些情况下，这可能会过于复杂，或者给选择器分配类可能会出现我们需要避免的问题。幸运的是，我们可以使用 `.css()` 函数直接将样式应用于我们的元素——这是在 jQuery 中使用适配器模式的一个很好的例子。

基于结构设计模式的一种模式，适配器模式将 jQuery 中元素的接口转换为与特定系统兼容的接口。在这种情况下，我们可以使用 `.css()` 形式的适配器为我们选择的元素分配 CSS 样式：

```js
// Setting opacity
$(".container").css({ opacity: 0.7 });

// Getting opacity
var currentOpacity = $(".container").css('opacity');
```

这样做的美妙之处在于一旦样式设置好了，我们可以使用相同的命令获取样式值。

### 适配器模式的优缺点

使用适配器设计模式有几个关键优点；其中一个关键优点是它能够链接两个不兼容的接口，否则这两个接口将必须保持独立。

另外，值得注意以下额外的好处：

+   适配器模式可用于在不影响其核心功能的情况下创建一个外壳，比如一个类，围绕现有的代码块。

+   这种模式有助于使代码可重用；如果情况需要，我们可以调整外壳以包含额外的功能或修改现有代码。

使用适配器模式会带来一些缺点，如果我们不小心的话：

+   使用关键字如 `.css()` 存在性能成本 —— 我们真的需要使用它们吗？或者，我们可以应用一个样式类或选择器，并将 CSS 样式移到样式表中吗？

+   使用关键字，比如 `.css()`，来操作 DOM，如果我们没有简化选择器，并且如果我们使用了像这样的东西，会导致性能受损：

    ```js
    $(".container input#elem").css("color", "red");
    ```

    这在小型站点或仅轻度使用此类操作的地方可能不明显；但在较大的站点上，它将是显而易见的！

+   适配器模式允许您链接 jQuery 命令；尽管这将有助于减少需要编写的代码量，但这将以可读性为代价。链式命令会使得在以后的日期更难调试代码，特别是如果涉及到开发人员的变更；保持代码简单和清晰是有意义的，即使只是为了保持理智！

让我们继续并再次看看另一种模式，即**外观模式**。

## 外观模式

起源于法语，"façade" 翻译为 *正面* 或 *面貌* ——这是对下一个模式的完美描述；它的外观可能非常具有迷惑性，就隐藏的代码量而言！

**外观模式**，结构模式组的另一个成员，为更大、更复杂的代码提供了一个简单的接口；在某种意义上，它抽象了一些复杂性，留下了我们可以随意操纵的简单定义。外观模式的显著示例包括 DOM 操作、动画，当然还有那个经典的 AJAX！

例如，简单的 AJAX 方法，比如 `$.get` 和 `$.post` 都调用相同的参数：

```js
$.get( url, data, callback, dataType );
$.post( url, data, callback, dataType );
```

这些在本身就是另外两个函数的外观：

```js
// $.get()
$.ajax({ 
  url: url,
  data: data,
  dataType: dataType
}).done( callback );

// $.post
$.ajax({
  type: "POST",
  url: url,
  data: data,
  dataType: dataType
}).done( callback );
```

这反过来是对大量复杂代码的伪装！这种情况下的复杂性源自于需要解决 XHR 的跨浏览器差异，并且使得使用 jQuery 中的 `get`、`post`、`deferred` 和 `promises` 等操作变得轻而易举。

### 创建一个简单的动画

在非常简单的层面上，`$.fn.animate` 函数是 jQuery 中的一个外观函数的例子，因为它使用多个内部函数来实现所需的结果。因此，这是一个使用动画代码的简单演示：

```js
$(document).ready(function() {
  $("#go1").click(function() {
    $("#block1")
      .animate({width: "85%"}, {queue: false, duration: 3000})
      .animate({fontSize: "24px"}, 1500)
      .animate({borderRightWidth: "15px"}, 1500);
  });

  $("#go2").click(function() {
    $("#block2")
      .animate({ width: "85%" }, 1000 )
      .animate({ fontSize: "24px" }, 1000 )
      .animate({ borderLeftWidth: "15px" }, 1000 );
  });

  $("#go3").click(function() {
    $("#go1").add( "#go2").click();
  });

  $("#go4").click(function() {
    $("div").css({width: "", fontSize: "", borderWidth: ""});
  });
})
```

上述代码将产生以下动画效果：

![创建一个简单的动画](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00346.jpeg)

我们可以在核心库中使用下图中显示的函数：

![创建一个简单的动画](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00347.jpeg)

### 注意

本节演示的代码在本书附带的代码下载链接中作为 `animation.html` 文件提供；要使此演示工作正常，您需要解压整个代码文件夹。

现在您已经看到了外观模式的应用，请考虑一下在我们的代码中使用它的好处。

### 外观模式的优缺点

使用外观模式隐藏复杂代码是一种非常有用的技术；除了易于实现之外，使用这种模式还有其他优点，如下所示：

+   增强您的 Web 应用程序的安全性

+   与其他模式结合使用效果很好

+   使内部代码容易修补

+   为最终用户提供简单的公共接口

与其他模式相比，在使用这种模式时没有真正显著的缺点；它为我们作为最终用户提供了统一的接口集，因此我们不必做出任何妥协。 值得注意的是，在抽象代码时，实施中会有成本—在使用外观模式时，这是我们在心中始终要记住的事情。

## 观察者模式

由于它是行为模式组的一部分，我们将已经熟悉下一个模式——如果您花时间创建自定义事件，那么您已经在使用**观察者模式**。

使用 jQuery 开发的一个关键部分是使用其经过验证的发布/订阅系统来创建自定义事件—通过使用 `.trigger()`, `.on()`, 或 `.off()` 可以访问这些事件。 我们可以将观察者模式定义为当特定对象订阅其他对象并在特定事件发生时被通知时的模式：

![观察者模式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00348.jpeg)

试想一下，我们有以下 HTML：

```js
<div id="div1">This is div 1</div>
<div id="div2">This is div 2</div>
```

我们希望内部的 `<div>` 元素触发一个名为 `customEvent` 的事件；当它们被点击时，就会发生这种情况：

```js
$('div').on('click', function(e) {
  $(this).trigger('customEvent');
});
```

现在，让我们使文档元素订阅 `customEvent`：

```js
$(document).on('custom', function(e) {
  console.log('document is handling custom event triggered by ' + 
  e.target.id);
});
```

当一个 `div` 元素之一触发自定义事件时，观察者/订阅者会收到通知，并且消息将记录到控制台中。

### 注：

对于纯粹主义者来说，你们可能更喜欢使用典型的发布/订阅模型——在 [`gist.github.com/cowboy/661855`](https://gist.github.com/cowboy/661855) 中提供了一个示例。

让我们考虑一下使用这种模式的好处以及在代码中可能需要做些让步来避免陷入与使用这种设计模式相关的一些陷阱。

### 观察者模式的优缺点

使用观察者模式强迫我们考虑应用程序各个部分之间的关系，远远超过我们可能习惯于考虑的水平。 它还非常擅长以下几点：

+   促进 jQuery 中的松耦合，其中每个组件都知道自己负责什么，不关心其他模块——这鼓励可重用代码。

+   让您遵循关注点分离原则；如果代码块是自包含的，它们可以在新项目中轻松重用。然后，我们可以订阅单个事件，而不必担心每个块中会发生什么。

+   帮助我们准确定位项目中的依赖关系所在，作为确定这些依赖关系是否可以通过一点努力来减少或完全消除的潜在依据。

使用观察者模式也有缺点；主要缺点是将一个订阅者从一个发布者转换到另一个发布者可能在代码方面代价高昂，并且难以维护我们代码的完整性。

为了说明这一点，让我们简要地看一下一个简单的例子，我们可以看到至少一个我们不得不为发布者的切换做出额外让步的实例。

### 创建一个基本示例

弄清楚观察者模式的工作原理至关重要；它是更深入的模式之一，并提供了比简单的协议集更多的机会，比如外观设计模式。考虑到这一点，让我们运行一个快速的演示来说明它的工作原理，如下所示：

+   让我们首先下载并提取本章的代码副本——我们需要`observer.html`文件，以及`css`和`js`文件夹。

+   如果您运行演示，您应该会看到两个标签变为红色，您可以单击它们；如果您尝试单击它们，您将看到计数增加，如此屏幕截图所示：

![创建一个基本示例](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00349.jpeg)

此时，让我们考虑一下代码——关键功能在`observer.js`文件中，我在此处完整复制了它：

```js
$(document).ready(function() {
  var clickCallbacks = $.Callbacks();
  clickCallbacks.add(function() {
    var count = parseInt(this.text(), 10);
    this.text(count + 1);
});
clickCallbacks.add(function(id) {
  $('span', '#last').text(id);
});
$('.click').click(function() {
  var $element = $(this).next('div') .find('[id^="clickCount"]');
  clickCallbacks.fireWith($element, [this.id]);
  });
});
```

注意一下，对于`.click`类，有一个单独的事件处理程序。我们在这里使用了一个回调函数，以允许 jQuery 执行下一个点击，即使它可能尚未完成前一个执行。在这种情况下，这不会是太大的问题，但如果我们必须更新多个不同的语句或应用更多的更改（通过使用额外的函数），那么回调将防止我们的代码产生错误。

在这里，我们订阅可观察对象，这在这种情况下是两个**点击我**语句；`.click`事件处理程序允许我们更新点击计数和**最后点击的元素**语句，而不会引发错误。

### 注意

要了解更多关于在 jQuery 中使用回调的复杂性，您可能需要浏览 API 文档，可以在[`api.jquery.com/jquery.callbacks/`](http://api.jquery.com/jquery.callbacks/)查看。

与此同时，让我们改变焦点，看看不同的模式。我们都知道 jQuery 以其 DOM 操作能力而闻名；接下来是迭代器模式，它基于 jQuery 的这一特定功能。

## 迭代器模式

现在，你听过或读过多少次 jQuery 以其 DOM 操作而闻名？我敢打赌，有相当多次，而且`.each()`关键字在这些示例中某个时候被使用过。

jQuery 中的 DOM 操作使用了行为组模式中的特殊变体——这就是它的用途；我们可以使用这种模式来遍历（或迭代）集合的所有元素，让 jQuery 处理内部工作。这种模式的一个简单示例可能是这样的：

```js
$.each(["richard","kieran","dave","alex"], function (index, value) {
  console.log(index + ": "" + value);
});

$("li a").each(function (index) {
  console.log(index + ": " + $(this).text());
});
```

在这两种情况下，我们都使用了`.each`函数来遍历数组或`li`选择器的每个实例；无需担心迭代器的内部工作原理。

我们的示例代码包含最少的代码，以便遍历页面中的每个选择器或类；值得一提的是，查看核心库中`jQuery.fn.each()`函数的代码量：

![迭代器模式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00350.jpeg)

这反过来调用了`jQuery.each()`函数——第一个函数仅供内部使用，如下图所示：

![迭代器模式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00351.jpeg)

然后，这又得到了一个特殊的快速情况，即对`.each()`函数最常见用法的补充：

![迭代器模式](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00352.jpeg)

### 迭代器模式的优缺点

在 DOM 中遍历元素的能力是 jQuery 的关键要素之一——作为迭代器模式的关键部分；使用这种模式有以下一些好处：

+   迭代器模式隐藏了遍历集合所需的大部分功能，而无需理解提供此功能的代码的内部工作原理

+   我们可以使用相同的一致模式来遍历任何对象或一组值

+   使用迭代器过程还可以帮助减少或消除我们代码中典型的`for`循环语法，使代码更易读

与其他模式不同，使用这种模式几乎没有什么缺点。它是 jQuery 的一个关键方面，所以只要不被迭代过多的对象滥用，这个简单的模式将证明非常有用！

## 惰性初始化模式

呵呵，这听起来像是我周日早晨可能会遵循的东西！好吧，我知道那是一个糟糕的笑话，但是开玩笑归开玩笑，这种基于创建的模式允许您推迟昂贵的过程，直到它们被需要。

在其最简单的层面上，我们可能会使用多个不同选项来配置插件，比如要显示的图像数量，是否应该显示叠加层，或者每个图像如何显示。听起来很简单，对吧？那么，惰性初始化在哪里呢？啊哈！这比你想象的简单。以以下代码为例：

```js
$(document).ready(function(){
  $("#wowslider-container1").wowSlider();
});
```

我们的示例使用了 WOW Slider 的初始化命令（可在 [`www.wowslider.com`](http://www.wowslider.com) 上获取）—使用这种模式的关键在于初始化过程；直到第一次在我们的页面上需要时才触发它。

懒惰初始化模式的一个更复杂的示例是回调；这些不会在 DOM 准备好之前进行处理：

```js
$(document).ready( function () {
  var jqxhr = $.ajax({
    url: "http://domain.com/api/",
    data: "display=latest&order=ascending"
  })
  .done( function( data ) ){
  $(".status").html( "content loaded" );
  console.log( "Data output:" + data );
  });
});
```

我们可能会直接在我们的代码中使用这个示例；更可能的是我们会在懒加载插件中使用它，比如 Mika Tuupola 在 [`www.appelsiini.net/projects/lazyload`](http://www.appelsiini.net/projects/lazyload) 上的版本。

### 懒惰初始化模式的优缺点

使用这种设计模式的关键优势很简单：延迟加载昂贵资源的加载；这有助于加快对站点的访问速度，并减少带宽使用（至少最初是如此）。

但是，使用这种方法还存在一些缺点，包括以下：

+   它需要通过设置标志来进行仔细管理，以测试所召唤对象是否准备好使用；如果不是，那么在多线程代码中可以生成竞争条件

+   任何懒变量或对象的先前使用都将绕过首次访问时的初始化原则，并意味着我们失去了不加载这些大对象或变量的任何好处。

+   这种方法需要使用映射来存储实例，以便在下次以前使用相同参数向存储实例请求时得到相同的实例

+   使用这种模式涉及时间成本，如果需要加载大型对象；如果最初不加载这些对象，并且有很大的可能性它们不会被使用，那么这种模式才真正起作用

最终，使用这种模式需要一些考虑和仔细规划；只要我们选择了不加载正确的对象，它就能很好地工作！说到策略，让我们继续，看看帮助我们确定在对象或变量状态改变时会发生什么的另一个模式，即**策略模式**。

## 策略模式

回想一下几年前，使用 Flash 在网站上做动画内容是最新的设计潮流；有些设计得非常好，尽管经常情况下网站速度慢，并且并不总是像它们应该的那样有效！而现在，CSS 动画更受欢迎—它们不需要浏览器插件来运行，可以存储在样式表中，比 Flash 更节约资源。

"为什么我们在讨论动画？"，我听到你问道，当这一章是关于设计模式时。这是一个很好的问题；答案很简单：尽管有些人可能没有意识到，但动画是我们接下来的设计模式的一个完美示例。在基本层面上，动画都是关于从一个状态变化到另一个状态—这构成了行为模式组中的策略模式的基础。

也被称为策略或状态模式，策略模式允许您在运行时选择适当的行为。简而言之，这就是模式的作用：

+   定义一个用于确定运行时应发生什么的算法（或函数）族

+   将每个算法（或函数）封装到其自包含的单元中，并使每个算法在该族内可互换

策略模式可以应用的一个很好的例子是在表单条目的验证中——我们需要一些规则来确定什么是有效或无效的内容；在输入内容之前，我们显然不会知道结果会是什么！

关键点在于验证规则可以封装在自己的块中（可能作为自己的对象）；一旦我们知道用户想要我们验证什么，我们就可以拉入相关的块（或规则）。

在更基本的层面上，有一个策略模式的更简单的例子；它采用动画内容的形式，比如使用`.toggle()`，我们在不同状态之间或者回到原状态之间进行切换：

```js
$('div').toggle(function(){}, function(){});
```

每个生成的状态都可以设置为自己的类；一旦我们知道请求的操作应该是什么，它们将在适当的时间被调用。为了帮助设置上下文，让我们创建一个简单的演示来看看它的运作方式。

### 构建一个简单的切换效果

好吧，虽然这是 jQuery 101，但当它完美地展示了我们所需要的内容时，为什么要把事情复杂化呢？

在此演示中，我们执行一个简单的切换动作来显示或隐藏两个`<p>`语句——关键点在于在按下按钮之前我们不知道接下来会发生什么。

要查看此操作，请下载本章的`code`文件夹的副本；运行`strategy.html`演示，然后单击**切换它们**以查看`<p>`语句的显示或隐藏，如下所示：

![构建一个简单的切换效果](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00353.jpeg)

魔术发生在这个函数中；它是使用`.toggle()`命令来根据需要切换每个`<p>`语句的可见性的简单用法：

```js
$(document).ready(function(){
  $("button").click(function() {
    $("p").toggle("slow");
  });
});
```

但是，我们可以轻松地将点击事件处理程序中包含的函数抽象为一个单独的 IIFE，然后在我们的代码中简单地调用该函数，如下所示：

```js
$(document).ready(function(){
  var hideParagraphs = function() {
    $("p").toggle("slow");
  };

  $("button").click(hideParagraphs);
});
```

代码已经更容易阅读——我们已经将大部分原始操作从事件处理程序中移除；这消除了以后需要更改代码时编辑事件处理程序的需要。

### 注意

如果你对立即调用的函数表达式(IIFEs)感兴趣，那么你可能想要查看维基百科的条目以获取更多细节，该条目位于[`en.wikipedia.org/wiki/Immediately-invoked_function_expression`](https://en.wikipedia.org/wiki/Immediately-invoked_function_expression)。

### 在不同动作之间切换

尽管我们在示例中集中讨论了动画，但我们中敏锐的人可能想知道同样的技术是否也适用于诸如 `switch()` 等命令。答案是肯定的；我们没有在这里讨论它，因为它是一个纯粹的 JavaScript 命令，但是你可以将相同的原则应用作为它的替代方案。

### 策略模式的优缺点

定义一个明智的策略是成功编码的关键；通过使用策略模式，我们可以获得一些好处：

+   代码更易于阅读；如果我们将函数抽象成它们自己的类，我们可以将它们从决策过程中分离出来，要么作为同一文件中的独立代码块，要么甚至作为自己文件中的独立文件

+   代码更易于维护；我们只需要进入类来更改或重构代码，而且我们只需要对核心代码进行最小的更改，以便为新的类或对象事件处理程序添加链接

+   我们可以保持关注点的分离——我们抽象的每个独立类或对象都不会意识到其他组件，但是当提供了每个策略对象的责任和相同的接口时，它们可以与其他对象通信

+   使用策略模式可以让你利用开放/封闭原则；每个抽象类或对象的行为可以通过启动现有行为的新类或对象实例来改变

### 提示

关于开放/封闭原则的更多细节，请参阅 [`en.wikipedia.org/wiki/Open/closed_principle`](http://en.wikipedia.org/wiki/Open/closed_principle)。

这些是我们需要注意的一些缺点：

+   使用策略模式可以让你遵守开放/封闭原则，但同时，你可能会启动一个包含许多不必要函数或动作的新类或对象的代码，从而使你的代码变得更加繁琐

+   有些情况下使用策略模式可能不适合你的目的；如果你的代码只包含少量函数，那么将它们抽象化所需的工作量可能会超过所带来的好处

+   使用策略模式将增加代码中的对象数量，使其变得更加复杂，并且可能需要更多资源来管理

策略讨论够多了；让我们继续看一个不同的协议，以**代理**设计模式的形式

## 代理模式

在使用 jQuery 时，可能会有这样的情况，你可能想编写一个通用事件处理程序来管理某些元素上的样式——一个很好的例子可能是从活动状态切换到禁用状态，或者甚至是选定状态；然后我们可以使用普通的 CSS 来为这些样式编写样式。

使用这种方法，一个通用的事件处理程序可能如下所示：

```js
$(".myCheckbox").on( "click", function () {
  // Within this function, "this" refers to the clicked element 
  $(this).addClass("active");
});
```

乍一看，这样做完全可以正常运行，但是如果我们在更改样式类之前引入延迟会怎么样？我们通常会使用 `setTimeOut()` 函数来实现这一点：

```js
$(".myCheckbox").on( "click", function () {
  setTimeout(function () {
    // "this" doesn't refer to our element, but to the window!
    $(this).addClass("selected");
    });
});
```

有人发现这里有一个小但相当关键的问题吗？将任何函数传递给`setTimeout`都会给出错误的值—它将引用窗口对象，而不是传递的对象！

解决此问题的一种方法是使用 jQuery 的`proxy()`函数；我们可以使用此函数来实现代理模式或中间层，以确保正确的值通过到`.addClass()`方法的正确上下文中。我们可以调整我们之前的示例，如下代码片段所示：

```js
$(".myCheckbox").on( "click", function () {
  setTimeout( $.proxy( function () {
    // "this" now refers to our element as we wanted
    $( this ).addClass( "active" );
    }, this), 500);
});
```

我们传递的最后一个`this`参数告诉`$.proxy()`我们的 DOM 元素是我们想要`this`引用的值—在这种情况下，它是复选框，而不是窗口。

### 代理模式的优缺点

代理模式是来自结构组的有用设计，可以帮助优化和维护快速站点；在其核心，该模式基于不加载昂贵元素直到绝对必要的原则。（最好根本不加载，如果可以的话！）

使用这种设计模式可以获得一些好处，如下所示：

+   我们可以使用代理模式为尚未加载或可能永远不会加载的更昂贵的对象提供占位符；这包括可能从应用程序外部加载的对象

+   使用代理可以充当包装器，为真实对象提供委托，同时保护它免受不必要的复杂性

+   将代理模式纳入我们的页面中可以帮助减少代码繁重站点的感知速度慢或响应不足。

使用这种模式的缺点包括以下内容：

+   代理模式存在一个风险，即代理模式可能会将易变资源的生命周期和状态隐藏在其客户端之外；这意味着代码必须等待正确的资源再次可用，或者产生错误。它需要知道它正在与原始资源交互，而不是与可能与原始资源类似的另一个资源交互。

+   如果我们正在使用代理模式来表示远程资源，则这将掩盖两者之间的通信使用；与本地资源的通信应与远程资源的通信区别对待。

经过谨慎的使用，代理模式可以证明非常有用，只要我们对我们决定加载或不加载到我们的页面中的内容保持理性。让我们改变方向，看看另一种设计模式；这个模式基于我们可能需要动态构建一个或多个元素的方式；这个概念是**生成器模式**的核心。

## 生成器模式

在任何项目的开发过程中，都可能会出现需要动态创建新元素的情况；这可以是构建单个`<div>`元素，也可以是各种元素的复杂组合。

我们可能希望在代码中直接定义最终的标记，这可能会变得混乱，或者我们可以将元素分离成一个独立的机制，允许我们简单地构建这些元素，以便稍后在代码中使用。

后者，或者称为建造者模式的技术名称，更可取； 它更容易阅读，并允许您清晰区分变量和代码的其他部分。 此特定模式属于创建模式组，并且是您将看到此类模式的少数常见示例之一。

### 注意

您可能会在网上或书籍中看到对**抽象模式**的引用——它与建造者模式非常相似。

我们可以使用 jQuery 的美元符号来构建我们的对象； 我们可以传递完整的元素标记，部分标记和内容，或者简单地使用 jQuery 进行构造，如下所示：

```js
$('<div class="foo">bar</div>');

$('<p id="newText">foo <b>bar</b></p>').appendTo("body");

var newPara = $("<p />").text("Hello world");

$("<input />")
      .attr({ "type": "text", "id":"sample"})
      .appendTo("#container");
```

创建后，我们可以使用变量缓存这些对象，并减少对服务器的请求次数。

值得注意的是，设计模式不仅限于脚本代码； 它们可以应用于使用类似原则的插件。 我们将在第十一章 中介绍更多适用于 jQuery 插件的设计模式，*编写高级 jQuery 插件*。

### 建造者模式的优缺点

使用建造者模式并不适用于所有情况；值得注意的是，通过使用它可以获得的好处，以便查看这些是否符合您的要求。 这些好处包括：

+   我们可以在 jQuery 内动态构建创建对象所需的标记，而无需显式创建每个对象

+   我们可以缓存标记，然后将其与主要功能分离，这样可以更轻松地阅读代码并减少对服务器的请求

+   核心标记将保持不可变，但我们可以对其应用不同的功能以改变值或外观

+   我们可以进一步将我们的建造者模式转换为状态机或公开方法或事件的机制，同时仍保留私有构造函数或析构函数方法

使用建造者模式有一些缺点； 关键缺点是滥用链接的使用，但我们还应考虑以下方面：

+   有可能定义无法轻松重用的标记； 这意味着我们可能需要创建一些包含标记的变量，所有这些变量都将占用应该用于其他用途的资源。

+   以下是一个代码片段的示例：

    ```js
    var input = new TagBuilder("button")
      .Attribute("name", "property.name")
      .Attribute("id", "property_id")
      .Class("btn btn-primary")
      .Html("Click me!");
    ```

    使用建造者模式允许链接操作，提供一致的 API，并遵循建造者模式。 但是，这种模式的主要缺点是使代码更难阅读，因此更难调试。

我们已经在概念层面上探讨了许多不同的设计模式类型； 对于一些人来说，将其与我们所知的 jQuery 核心联系起来可能仍然会很困难。

然而，美妙之处在于 jQuery 在整个代码库中都使用这些模式——为了帮助您将所学的一些知识付诸实践，让我们花一点时间来检查核心库并看看这些模式是如何在内部使用的一些示例。

# 探索 jQuery 库中模式的使用

现在，你可能会想：我仍然不确定这些模式与我的工作有何关联。是吗？

我想是的。在本章中，我们花时间研究了一些常用的模式，作为回归基础的一种方式；毕竟，提高自己的秘诀不仅仅是通过编写代码！

关键点在于，如果你花时间用 jQuery 开发，那么你已经在使用设计模式；为了加强你所学的内容，让我们来看看 jQuery 库本身的一些示例：

### 注意

为了演示目的，我使用了 jQuery 2.1.1；如果你使用不同版本，那么你可能会发现一些行号已经改变了。

1.  首先，在你选择的文本编辑器中打开`jquery.js`的一个副本——我们将从经典的`document.ready()`函数开始，它使用 Façade 模式，并且在大约**3375**行附近运行此函数，如下面的屏幕截图所示：![探索 jQuery 库中模式的使用](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00354.jpeg)

1.  你有多少次切换页面中元素的状态？我猜可能会有很多次；`toggle`命令是策略设计模式的一个典型例子，我们在这里决定一个元素的状态，如下所示：![探索 jQuery 库中模式的使用](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00355.jpeg)

1.  现在，我确定你已经点击过无数个元素或使用过`click`事件处理程序，对吗？我希望是的，因为这是我们在学习 jQuery 时可能开始使用的第一个事件处理程序。它也是观察者模式的一个很好的例子。以下是 jQuery 中相关的代码，大约在**7453**行附近：![探索 jQuery 库中模式的使用](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00356.jpeg)

jQuery 核心库中有更多设计模式的使用示例；希望这能展示它们在你自己的代码中的好处，并且它们不应该局限于 jQuery 本身的源代码！

# 概要

哎呀！我们确实涵盖了很多关于设计模式的理论；让我们稍事休息，回顾一下你在本章学到的东西。

我们从介绍设计模式是什么以及它们是如何产生的开始；然后我们继续探讨了使用它们的好处以及为什么我们应该考虑在我们的项目中使用它们。

接下来，我们来看一下设计模式的结构，我们将一个典型的设计拆分成其不同的元素，并看到每个元素在设计方案中扮演的角色。我们还看到了如何将设计模式分类为不同类型，即创建型、结构型和行为型。

我们接着来看一些常见的设计模式，我们将了解每种类型的作用，并且检视一些我们将如何使用它们的示例。然后，我们将审视本章涵盖的每个设计模式的优缺点，最后看看其中一些模式在 jQuery 库内是如何实际运用的，而不仅仅是在我们自己的代码中。

我认为现在的理论已经足够了；让我们继续并且实践起来。在下一章中，我们将学习如何通过一些技巧来精通表单开发，将你的表单开发技能提升一个档次。


# 第四章：与表单一起工作

你有多少次在网上购买产品，比如亚马逊之类的？我打赌多年来你已经做了相当多的次数——毕竟，你不能在深夜去书店，浏览书籍，然后选择一本，而不担心商店的关门时间或者不知道你是否会找到一本特定的书。

在线网站构建表单可能是您可能使用 jQuery 的关键领域之一；其成功的关键在于确保它正确验证，作为提供成功用户体验的一部分。

在本章节中，我们将回到基础知识，并深入探讨一些我们可以使用的技术，使用一些 HTML 和 jQuery 验证技巧来验证表单。您还将看到，创建成功的表单并不需要很多复杂的代码，而是同时确保我们考虑了表单的功能要求。

在接下来的几页中，我们将涵盖以下几个主题：

+   探讨验证的必要性

+   使用正则表达式添加表单验证

+   开发一个验证的插件架构

+   使用 jQuery/AJAX 创建一个高级联系表单

+   使用 jQuery 开发高级文件上传表单

准备好开始了吗？让我们开始吧……在我们开始之前，我建议你创建一个项目文件夹。为了本章的目的，我假设你已经这样做了，并且它被称为`forms`。

# 探讨表单验证的必要性

有不同的方法可以改进表单的可用性，但验证无疑是我们应该考虑的最重要的方面之一。你有多少次访问一个网站并填写你的详细信息，只是被告知出现了问题？听起来很熟悉，对吧？

验证表单对于维护信息的一致性至关重要；表单将处理已输入的信息，以确保其正确性。举个例子，以下是一些情况：

+   如果输入了电子邮件地址，让我们确保它具有有效的格式。电子邮件地址应包含一个句点，并在地址中的某个地方包含一个`@`符号。

+   打电话给某人？他们在哪个国家？如果我们已经设置表单以显示已选择国家的字段的特定格式，让我们确保电话号码遵循正确的格式。

我想你已经明白了。现在，这可能听起来好像我们在这里说的是显而易见的事情（不，我没有变疯！），但往往情况是，表单验证被留到了项目的最后阶段。最常见的错误通常是由以下原因造成的：

+   **格式化**：这是最终用户在字段中输入非法字符的地方，比如在电子邮件地址中输入空格。

+   **缺少必填字段**：你有多少次填写表单，然后发现你没有在必填字段中输入信息？

+   **匹配错误**：当两个字段需要匹配但却不匹配时，就会出现这种情况；一个经典的例子是密码或电子邮箱字段。

在这个阶段，你可能会认为我们将被大量的 jQuery 困住，以产生一个全方位的解决方案，对吧？

错了！很抱歉让你失望，但我一直坚持的口头禅是**KISS** 原则，或者**保持简单，蠢货**！这并不是对任何人的一种反映，而是为了让我们的设计生活变得更容易一些。正如我在前面的章节中提到的，我相信掌握 jQuery 这样的技术并不总是关于我们产生的代码！

这些是表单验证的关键元素：

+   告诉用户他们在表单上有问题

+   向用户显示问题所在的地方

+   向他们展示一个你期望看到的例子（比如一个电子邮箱地址）

在接下来的几页中，我们将看看如何向表单添加验证以及如何减少（或消除）最常见的错误。我们还将使用颜色和接近性来帮助加强我们的消息。然而，在我们能够进行验证之前，我们需要一些东西来验证，所以让我们快速创建一个表单作为我们练习的基础。

# 创建一个基本表单

与所有项目一样，我们需要从某个地方开始；在这种情况下，我们需要一个可以作为在本章节中给出的各种示例中添加验证的基础的表单。

在本书的代码下载中，查找并提取`basicform.html`和`basicform.css`文件到您的项目文件夹；当您运行`basicform.html`时，它将看起来类似于这个屏幕截图：

![Creating a basic form](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00357.jpeg)

如果我们看一下使用的标记，我们会发现这并不是什么新鲜事；它包含了我们在创建联系表单时将使用的标准 HTML5 字段，比如文本字段或文本区域：

```js
<form class="contact_form" action="" method="post" name="contact_form">
  <ul>
  <li>
  <label for="name">Name:</label>
  <input type="text" name="username" required>
  </li>
  <li>
  <label for="name">Email:</label>
  <input type="email" name="email" required>
  </li>

  </ul>
  <button class="submit" type="submit">Submit Form</button>
</form>
```

这里的关键是，我们的例子没有包含任何形式的验证——它让我们完全暴露在垃圾之中，用户可以输入任何东西，我们收到的提交表单会—嗯—是垃圾！在这种情况下，当您点击**提交**时，您将只会看到这个屏幕截图：

![Creating a basic form](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00358.jpeg)

不是很好，是吗？大多数桌面浏览器将在使用必填标签时接受任何内容而不进行一些验证，只要有一些东西，表单就会被提交。这个规则的例外是 Safari，它不会显示我们屏幕截图中显示的弹出通知。

我相信我们能做得更好，但可能不是以你期待的方式…感到好奇吗？

# 从简单的 HTML5 验证开始

表单验证的好处在于它可以很容易或很复杂地修复—这完全取决于我们解决问题的路线。

这里的关键是我们*可以*使用 jQuery 来提供表单验证；这是一个完全足够的解决方案，可以正常工作。但是，对于字段的简单验证，比如姓名或电子邮件地址，有一种替代方案：HTML5 验证，它使用 HTML5 约束验证 API。

### 注意

约束验证 API 使用 HTML5 属性，如`min`、`step`、`pattern`和`required`；这些在大多数浏览器中都可以工作，除了 Safari。

在我解释这个疯狂背后的逻辑之前，让我们快速看看如何修改我们的演示，以使用这种形式的验证：

1.  在你常用的文本编辑器中打开`basicform.html`文件的一个副本，然后查找这一行：

    ```js
    <li>
    <label for="name">Name:</label>
    <input type="text" name="username" required>
    </li>
    ```

1.  我们需要添加将用作验证检查的模式，所以继续按照指示修改代码：

    ```js
    <li>
      <label for="name">Name:</label>
      <input id="name" name="username" value="" required="required" 
      pattern="[A-Za-z]+\s[A-Za-z]+" title="firstnamelastname">
    </li>
    ```

1.  我们可以对`email`字段进行类似的更改，以引入 HTML5 验证；首先，查找这些行：

    ```js
    <li>
      <label for="email">Email:</label>
      <input type="email" name="email" id="email" required= 
      "required">
    </li>
    ```

1.  按照指示修改代码，为`email`添加 HTML 验证：

    ```js
    <li>
      <label for="email">Email:</label>
      <input type="email" name="email" id="email" 
      required="required" pattern="[^ @]*@[^ @]*\.[a-zA-Z]{2,}" 
      title="test@test.com">
    </li>
    ```

1.  将文件保存为`basicvalidation.html`；如果你在浏览器中预览结果，你会立即看到一个变化：![从简单的 HTML5 验证开始](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00359.jpeg)

这已经是一个进步了；虽然文本不太用户友好，但至少你可以看到表单期望看到**名字 姓氏**的格式，而不仅仅是名字，如所示。类似的变化也将出现在**电子邮件**中，当你按下**提交**按钮验证表单时。

### 提示

如果你仔细查看代码，你可能会注意到我已经开始使用`required="required"`标签，代替`required`。任何格式都可以正常工作——如果在你的浏览器中只使用`required`时出现了任何不一致，你可能会发现使用前一种标签是必要的。

## 使用 HTML5 而不是 jQuery

现在我们有一个使用 HTML 验证`name`和`email`字段的表单，是时候兑现我的承诺并解释我疯狂背后的逻辑了。

在某些情况下，通常诱人的做法是简单地回归到使用 jQuery 来处理一切。毕竟，如果我们已经在使用 jQuery，为什么要引用另一个 JavaScript 库呢？

如果不是这两个小问题，这似乎是一个合理的方法：

+   使用 jQuery 会增加网站的负担；对于简单的验证，这可以被视为一种过度投入，收益甚微。

+   如果 JavaScript 被关闭，那么可能会导致验证无法操作或在屏幕上显示错误或在控制台日志中显示错误。这会影响用户体验，因为访问者将很难提交一个经过验证的表单，或者更糟的是，简单地离开网站，这可能会导致销售额损失。

更好的方法是考虑使用 HTML5 验证来验证标准文本字段，并将 jQuery 的使用保留给更复杂的验证，正如我们将在本章后面看到的那样。这种方法的好处在于，我们将能够完成一些有限的验证，减少对标准字段的 jQuery 依赖，并以更渐进的增强方式使用它。

考虑到这一点，让我们继续，开始查看使用 jQuery 来进一步增强我们的表单，并提供更复杂的验证检查。

# 使用 jQuery 验证我们的表单

在某些情况下，如果浏览器不支持所使用的输入类型，则使用 HTML5 验证将失败；这是我们需要回到使用 JavaScript 或在本例中使用 jQuery 的时候。例如，日期作为输入类型在 IE11 中不受支持，如下所示：

```js
<input type="date" name="dob"/>
```

这就是上述代码将如何呈现的方式：

```js
<input type="text" name="dob"/>
```

麻烦的是，由于类型回退为文本，浏览器将无法正确验证字段。为了解决这个问题，我们可以使用 jQuery 实现一个检查——然后我们可以开始使用 jQuery 添加一些基本的验证，这些验证将覆盖浏览器中进行的现有本地 HTML 检查。

让我们来看看如何在实践中实现其中一些，通过一个简单的演示，如下所示：

1.  打开本书附带的代码下载中的`basicform.html`的副本。

1.  在`<head>`部分，添加一个指向 jQuery 的链接以及一个指向您的验证脚本的链接：

    ```js
    <script src="img/jquery.js"></script>
    <script src="img/basicvalidation.js"></script>
    ```

1.  将文件保存为`basicvalidation.html`。在一个新文件中，添加以下代码——这将执行一个检查，以确保您只验证了`email`字段：

    ```js
    $(document).ready(function () {
       var emailField = $("#email");
        if (emailField.is("input") && emailField.prop("type") === "email") {
      }
    });
    ```

1.  在关闭`}`之前的位置，让我们加入两个函数中的第一个；第一个函数将添加一个 CSS 钩子，允许您在成功或失败的情况下进行样式设置：

    ```js
    emailField.on("change", function(e) {
      emailField[0].checkValidity();
        if (!e.target.validity.valid) {
          $(this).removeClass("success").addClass("error")
        } else {
          $(this).removeClass("error").addClass("success")
        }
    });
    ```

1.  你们中间敏锐的人会注意到添加了两个 CSS 样式类；我们需要在样式表中允许这个，所以继续添加这些代码行：

    ```js
    .error { color: #f00; }
    .success { color: #060; }
    ```

1.  现在我们可以添加部分函数，该函数将更改浏览器显示的默认消息以显示自定义文本：

    ```js
    emailField.on("invalid", function(e) {
      e.target.setCustomValidity("");
      if (!e.target.validity.valid) {
      e.target.setCustomValidity("I need to see an email address 
      here, not what you've typed!");
    }
    else {
      e.target.setCustomValidity("");
    }
    });
    ```

1.  将文件保存为`basicvalidation.js`。如果您现在在浏览器中运行演示，您将看到当您添加一个有效的电子邮件地址时，文本会变为绿色，如下图所示：![使用 jQuery 验证我们的表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00360.jpeg)

1.  如果您刷新浏览器会话，并且这次不添加电子邮件地址，您将收到一个定制的电子邮件地址错误，而不是浏览器提供的标准错误，如下面的屏幕截图所示：![使用 jQuery 验证我们的表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00361.jpeg)

在这种情况下使用一点 jQuery 让我们能够自定义显示的消息——这是一个使用更友好的东西的好机会。请注意，默认消息与标准 HTML5 验证一起给出的消息可以很容易地……改进！

现在你已经看到了我们如何改变显示的消息，让我们专注于改进表单所进行的检查。标准的 HTML5 验证检查对于所有情况都不够；我们可以通过在我们的代码中引入正则表达式检查来改进它们。

# 使用正则表达式语句验证表单

到目前为止，你已经看到了可以使用 jQuery 来验证表单的一些命令，以及如何将你的检查限制在特定的字段类型（如电子邮件地址）上，或者覆盖屏幕上显示的错误消息。

但是，如果我们没有一种可以用来检查的验证模板，代码将失败——你们中的敏锐的人可能已经在我们的`basicvalidation.html`演示中注意到了这一点：

```js
pattern = "[^ @]*@[^ @]*\.[a-zA-Z]{2,}";
```

`pattern`变量用于定义正则表达式或**regex**语句。简单地说，这些是单行语句，指示我们应该如何验证表单中的任何条目。这些并不是专门用于查询的；它们同样适用于任何脚本语言，比如 PHP 或纯 JavaScript。让我们花一点时间看一些示例，以了解这个是如何工作的：

+   `[^ @]*`: 这个语句匹配任意数量的不是`@`符号或空格的字符。

+   `@`: 这是一个字面值

+   `\.`: 这是一个字面值

+   `[a-zA-Z]`: 这个语句表示任意字母，无论是大写还是小写

+   `[a-zA-Z]{2,}`: 这个语句表示两个或更多字母的任意组合。

如果我们把这些放在一起，模式正则表达式转换为一个电子邮件，其中包含任意一组字符，除了一个`@`符号，紧接着是一个`@`符号，然后是任意一组字符，除了一个`@`符号，一个句点，最后至少两个字母。

好了，理论已经够了；让我们开始编码吧！我们将通过一些示例进行工作，首先修改电子邮件验证，然后开发代码以覆盖网站地址的验证。

## 创建一个用于电子邮件的正则表达式验证函数

我们已经使用了一个正则表达式来验证我们的`email`地址字段；虽然这样做效果很好，但代码可以改进。我不喜欢在事件处理程序中包含验证检查；我更喜欢将其分离到一个独立的函数中。

幸运的是，这很容易纠正；让我们现在执行以下步骤来解决这个问题：

1.  我们将首先打开`basicvalidation.js`文件，并在`emailField.on()`事件处理程序之前立即添加一个辅助函数：

    ```js
    function checkEmail(email) {
      pattern = new RegExp("[^ @]*@[^ @]*\.[a-zA-Z]{2,}");
      return pattern.test(email);
    }
    ```

1.  此函数处理电子邮件地址的验证；为了使用它，我们需要修改`emailField.on()`处理程序，如下所示：

    ```js
    emailField.on("invalid", function(e) {
      e.target.setCustomValidity("");
     email = emailField.val();
     checkEmail(emailField);
      if (!e.target.validity.patternMismatch) {
        e.target.setCustomValidity("I need to see an email address 
        here, not what you've typed!");
    }
    ```

如果我们保存我们的工作然后在浏览器中预览它，我们应该在验证过程中看不到任何差异；我们可以放心地说，验证检查过程现在已经被分离为一个独立的函数。

## 进一步进行 URL 验证

使用与前面示例中使用的相同原理，我们可以为`urlField`字段开发一个类似的验证检查。只需复制两个`emailField.on()`事件处理程序和`checkEmail`函数，就可以产生类似下图所示的东西：

![深入了解 URL 验证](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00362.jpeg)

使用我们已经生成的代码，看看你是否能够创建一个使用这个正则表达式验证网站 URL 输入的东西：

```js
/^(https?:\/\/)?([\da-z\.-]+)\.([a-z\.]{2,6})([\/\w \.-]*)*\/?$/
```

如果你的代码工作，它应该产生一个类似于这个截图中显示的错误消息：

![深入了解 URL 验证](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00363.jpeg)

希望你已经成功使用了我们迄今为止产生的代码——如果你遇到了困难，在附带本书的代码下载中有一个可工作的示例。

因此，假设我们有一些可以工作的东西，有人发现我们的代码有问题吗？我们肯定有一些问题需要解决；让我们现在来看看它们：

+   注意，反馈并非百分之百动态？为了使我们的代码能够识别从错误到成功输入的更改，我们需要刷新我们的浏览器窗口——这一点根本不理想！

+   我们在 jQuery 文件中重复了很多代码——从架构上看，这是不好的做法，我们肯定可以改进已经编写的内容。

与其复制代码，不如彻底重写我们的 jQuery 为一个快速插件；从架构上来说，这将消除一些不必要的重复，并使我们能够以最小的更改扩展功能。它不会完美——这是我们将在本章稍后纠正的东西——但它会产生比我们现有代码更有效的结果。

# 构建一个简单的验证插件

到目前为止，我们的示例都是基于个别字段的，比如电子邮件地址或网站 URL。代码大量重复，这导致了冗余且效率低下的解决方案。

相反，让我们完全改变我们的方法，将我们的代码转换成一个通用插件。我们将使用相同的核心流程来验证我们的代码，这取决于插件中设置的正则表达式。

对于下一个练习，我们将使用 Cedric Ruiz 制作的一个插件。虽然它已经有几年了，但它说明了我们如何创建一个单一的核心验证过程，该过程使用一些过滤器来验证我们表单中输入的内容。让我们从执行以下步骤开始：

1.  从附带本书的代码下载中提取`quickvalidate.html`、`info.png`和`quickvalidate.css`文件的副本，并将它们保存在你的项目文件夹中。

1.  接下来，我们需要创建一个插件。在一个新文件中，添加以下代码，并将其保存为`jquery.quickvalidate.js`，保存在项目区域的`js`子文件夹中：

    ```js
    $.fn.quickValidate = function() {
      return this;
    };
    ```

1.  你需要开始给你的插件添加功能，从缓存表单和输入字段开始；在你的插件的`return this`语句之前立即添加这个功能：

    ```js
    var $form = this, $inputs = $form.find('input:text, input:password');
    ```

1.  接下来是规定每个字段应如何验证以及在验证失败时应显示的错误消息的过滤器，如下所示：

    ```js
    var filters = {
      required: {
        regex: /.+/,
        error: 'This field is required'
      },
      name: {
        regex: /^[A-Za-z]{3,}$/,
        error: 'Must be at least 3 characters long, and must only contain letters.'
      },
      pass: {
        regex: /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/,
        error: 'Must be at least 6 characters long, and contain at least one number, one uppercase and one lowercase letter.'
      },
      email: {
        regex: /^[\w\-\.\+]+\@[a-zA-Z0-9\.\-]+\.[a-zA-z0-9]{2,4}$/,
        error: 'Must be a valid e-mail address (user@gmail.com)'
      },
      phone: {
        regex: /^[2-9]\d{2}-\d{3}-\d{4}$/,
        error: 'Must be a valid US phone number (999-999-9999)'
      }
    };
    ```

1.  现在我们来到验证过程，这是魔术发生的地方。继续添加以下代码，立即在过滤器下方：

    ```js
    var validate = function(klass, value) {

      var isValid = true, f, error = '';
      for (f in filters) {
        var regex = new RegExp(f);
        if (regex.test(klass)) {
          if (!filters[f].regex.test(value)) {
            error = filters[f].error;
            isValid = false;
            break;
          }
        }
      }
    return { isValid: isValid, error: error }
    };
    ```

1.  如果您的代码正确识别出错误，您需要通知用户；否则，他们将不知道为什么表单似乎未正确提交。现在让我们通过添加一个函数来确定如果验证测试失败会发生什么，如下所示：

    ```js
    var printError = function($input) {
      var klass = $input.attr('class'),
      value = $input.val(),
      test = validate(klass, value),
      $error = $('<span class="error">' + test.error + '</span>'),
      $icon = $('<i class="error-icon"></i>');
      $input.removeClass('invalid').siblings('.error, .erroricon').remove();
      if (!test.isValid) {
        $input.addClass('invalid');
        $error.add($icon).insertAfter($input);
        $icon.hover(function() {
          $(this).siblings('.error').toggle();
        });
      }
    };
    ```

1.  我们已经确定了当验证过程失败时会发生什么，但尚未采取任何措施调用函数。现在让我们通过根据字段是否标记为必填来添加适当的调用来解决此问题，如下所示：

    ```js
    $inputs.each(function() {
      if ($(this).is('.required')) {
        printError($(this));
      }
    });
    ```

1.  如果我们字段中的内容发生更改，我们需要确定它是有效还是无效；这需要在输入文本时进行，所以现在让我们做这个，使用`keyup`事件处理程序：

    ```js
    $inputs.keyup(function() {
    printError($(this));
    });
    ```

1.  最后，如果在我们的表单中发现错误，我们需要阻止提交：

    ```js
    $form.submit(function(e) {
      if ($form.find('input.invalid').length) {
        e.preventDefault();
        alert('There are errors on this form – please check...');
      }
    return false;
    });
    ```

1.  保存您的工作；如果一切正常，当在浏览器中预览工作结果时，您应该会看到表单验证：![构建一个简单的验证插件](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00364.jpeg)

在这个阶段，我们有一个工作正常的插件，我们已经将核心验证代码重构为一组单一的流程，可以应用于每种字段类型（使用适当的过滤器）。

然而，我们可以做得更好；以下是一些问题，我们可以解决以进一步完善我们的代码：

+   虽然我们已经将代码重构为一组单一的核心验证流程，但过滤器仍然是核心代码的一部分。尽管可以轻松扩展不同类型的过滤器，但我们仍然仅限于文本或密码字段类型。添加任何标准的 HTML5 字段类型，例如`url`或`email`，都会导致错误，因为伪类型不受 jQuery 支持。

+   从架构的角度来看，最好将验证器过滤器保留在核心插件之外；这有助于保持验证器的简洁，并且不包含我们的目的不需要的代码。

+   我们的代码不允许任何功能，比如本地化、设置最大长度或验证表单对象，比如复选框。

我们可以花费大量时间开发我们的插件，使其采用更模块化的方法，但这值得吗？目前有数十个可供使用的表单验证插件；更明智的做法将是使用其中一个插件：

+   核心验证流程经过了反复测试，消除了担心我们的字段是否会正确验证的需要。开发任何形式的验证器插件，使其适用于超过几个字段，都是非常棘手的，要做到完全正确；毕竟，我们要验证还是不验证？不同的语言？例如邮政编码或邮政编码的不同格式？

+   大多数插件都会有某种架构，允许添加自定义验证器，这些验证器补充了作为标准包含的验证器，例如使用语言、特定的数字格式或奇偶数。在本章的后面，我们将充分利用这一点，以向我们的演示添加一些自定义验证器。

+   使用现有的插件可以让您专注于提供特定于您的环境的功能，并在您可以添加最大价值的地方添加功能——毕竟，尝试在其他人已经为我们完成工作的地方添加有效性是没有意义的，对吧？

有了这个想法，让我们继续看看如何使用现有的插件。现在大多数插件都具有某种模块化架构，允许您轻松定制它并添加额外的自定义验证器；毕竟，为什么要浪费时间重新发明轮子呢，对吧？

# 开发验证插件架构

在本章中，我们使用了各种 HTML5 和 jQuery 技术来验证我们的表单。总的来说，它们效果很好，但它们的简单性意味着我们会很快超越它们的有用性。

要充分利用表单验证的所有可能性，最好不要仅仅尝试验证字段，而是使用现有的插件来处理基本的验证过程，并允许您集中精力进行定制，并确保为您的表单提供正确的功能。

输入 jQuery Form Validator。这个插件是由 Victor Jonsson 创建的，已经存在多年，所以经过了测试；它还包含了我们需要定制的模块化架构，以在我们的表单中提供我们将提供的检查。让我们看看验证器的运作方式。

### 注意

原始插件及相关文档可在 [`formvalidator.net/`](http://formvalidator.net/) 上找到。

## 创建我们的基本表单

在我们开始向代码添加自定义验证器插件之前，我们需要一个要验证的基本表单。为此，我们将基于本章早期部分中创建的 `basicvalidation.html` 中的修改版本的表单的标记。

让我们先让我们的基本表单工作起来，确保标准验证生效。要做到这一点，请执行以下步骤：

1.  我们将从提取伴随本书的代码下载中的 `formvalidator.html` 和 `formvalidator.css` 文件的副本开始。将 HTML 文件保存在项目文件夹的根目录中，将 CSS 文件保存在 `css` 子文件夹中。

1.  在新文件中，添加以下代码行，并将其保存为 `formvalidator.js`，保存在项目区域的 `js` 子文件夹中：

    ```js
    $(document).ready(function() {
      $.validate();
    });
    ```

1.  这就是开始使用 Form Validator 插件所需的全部内容；如果您在浏览器中预览表单，您应该会看到以下截图——如果您输入了一个有效的名称和电子邮件地址但省略了网站 URL：![创建我们的基本表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00365.jpeg)

现在我们的表单已经准备好了，让我们真正开始开发表单内部使用的一些验证器，首先是`name`字段的新验证器。

## 创建自定义验证器

到目前为止，我们的表单依赖于使用标准的 HTML5 技术进行验证；这对大多数要求都适用，但它的能力是有限的。接下来是 jQuery；我们可以利用 FormValidator 的功能创建我们自己的自定义验证器，以满足我们自己的要求。

创建自定义验证器的关键部分是 `$.formutils.addValidator` 配置对象；FormValidator 处理了基本的插件架构，这样你就可以通过设计表单的正确检查来添加值。

在接下来的几页中，我们将通过两个基本示例进行工作：

1.  我们将从创建自定义验证器开始；在你选择的文本编辑器中，添加以下代码：

    ```js
    $.formUtils.addValidator({
      name : 'user_name',
      validatorFunction : function(value, $el, config, language, 
      $form) {
        return (value.indexOf(" ") !== -1)
      },
      errorMessage : 'Please enter your full name',
    });
    ```

1.  将文件保存为`user_name.js`，放在项目区域的`js`子文件夹内。打开之前创建的`formvalidator.js`文件，并根据下面的示例进行修改：

    ```js
    $(document).ready(function() {
     $.formUtils.loadModules('user_name');
      $.validate({
     modules: 'user_name'
      });
    });
    ```

1.  虽然你已经将验证规则添加到验证器中，但你需要在 HTML 标记内部激活它，如下所示：

    ```js
    <div class="form-group">
      <label class="control-name" for="name">Name: <span 
      class="asterisk">*</span></label>
      <input name="username" id="username" datavalidation="user_name">
    </div>
    ```

1.  如果一切正常，当你在浏览器中预览表单并点击 **提交** 按钮时，就会看到使用自定义验证器的效果，如下面的截图所示：

![创建自定义验证器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00366.jpeg)

在这个阶段，你可以简单地将它留在这个自定义验证器的位置，但我认为有更多的空间——比如电子邮件地址？

标准的 HTML5 验证将会检查电子邮件地址是否符合合适的格式，例如确保它包含`@`符号，域名后有一个小数点，以及域名后缀是有效的。然而，它不能阻止用户提交具有某些类型地址的表单，比如[www.hotmail.com](http://www.hotmail.com)（或现在的[www.outlook.com](http://www.outlook.com)）。

此时值得注意的是使用正则表达式进行电子邮件验证可能会引发一系列问题，所以要谨慎行事并进行彻底的测试——比如如何对`mail+tag@hotmail.com`进行验证？这是一个完全有效的地址，但大多数正则表达式都会失败……

### 注意

关于为什么使用正则表达式实际上可能带来更多问题的讨论可以在[`davidcel.is/blog/2012/09/06/stop-validating-email-addresses-with-regex/`](http://davidcel.is/blog/2012/09/06/stop-validating-email-addresses-with-regex/)上找到。

在我们的示例中，我们将添加一个简单的检查来防止使用 Hotmail、Gmail 或 Yahoo! 的电子邮件地址；让我们看看我们如何做到这一点：

1.  在文本编辑器中，将以下代码添加到一个新文件中，并将其保存为 `free_email.js`，放在 `js` 子文件夹内：

    ```js
    $.formUtils.addValidator({
      name : 'free_email',
      validatorFunction : function(value, $el, config, language, 
      $form) {
        varemailName = /^([\w-\.]+@(?!gmail.com)(?!yahoo.com)(?!hotmail.com)([\w-]+\.)+[\w- 
        ]{2,4})?$/;
        return (emailName.test(value))
      },
      errorMessage : 'Sorry - we do not accept free email accounts 
      such as Hotmail.com'
    });
    ```

1.  现在你的 `free_email` 验证器已经就位，当验证表单时，你需要调用它；为此，请返回到你在前一个练习中打开的 `formvalidator.js` 文件，并按照以下示例修改代码：

    ```js
    $(document).ready(function() {
     $.formUtils.loadModules('free_email');
      $.validate({ modules: 'free_email'});
    });
    ```

1.  这个练习的最后一步是从 HTML 标记中激活自定义验证器——还记得我们在上一个练习中是如何改变它的吗？同样的原理在这里也适用：

    ```js
    <div class="form-group">
      <label class="control-name" for="email">Email: <span 
      class="asterisk">*</span></label>
      <input type="text" name="email" id="email" datavalidation="free_email">
    </div>
    ```

1.  保存 `formvalidator.js` 和 `formvalidator.html` 文件；如果你预览你的工作结果，你会清楚地看到，如果你输入了一个无效的电子邮件地址，你的自定义消息会出现，如下面的截图所示：![Creating custom validators](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00367.jpeg)

现在，你们中间敏锐的人可能会发现我们一次只加载一个验证器；我相信你们肯定想知道如何同时加载多个验证器，对吧？

没问题，我们已经就位了验证器文件，所以我们需要做的就是修改我们的验证器对象，使其加载这两个模块。让我们快速看看如何修改我们的验证器对象：

1.  打开 `formvalidator.js` 文件的副本，并按照这里显示的代码进行修改：

    ```js
    $.formUtils.loadModules('free_email, user_name');
    $.validate({
      modules: 'free_email, user_name',
    });
    ```

这就是你需要做的一切。如果你保存文件并在浏览器中预览结果，你会发现它会验证 `name` 和 `email` 字段，就像前两个练习中所示的那样。

这为我们打开了一扇机会之门；在我们的两个示例中，我们创建了相当简单的验证器，但原则是相同的，无论我们的验证器有多么复杂或简单。

### 注意

如果你想了解更多关于如何创建自定义验证器的信息，那么阅读[`formvalidator.net/index.html#custom-validators`](http://formvalidator.net/index.html#custom-validators)中的文档是值得的。然后我们可以结合创建模块的基本原理和正则表达式示例，例如[`www.sitepoint.com/jquery-basic-regex-selector-examples/`](http://www.sitepoint.com/jquery-basic-regex-selector-examples/)中显示的那些，来创建一些有用的验证器检查。

让我们继续看看 FormValidator 插件的另一个有用部分——我们毕竟不都说同样的语言，是吗？如果我们都说同样的语言，生活会很无聊；相反，你应该考虑本地化你的验证消息，这样国际访问者就可以理解何时出现验证问题以及如何解决它。

## 本地化我们的内容

在这个现代化的在线工作时代，可能会有一些情况需要以不同的语言显示消息——例如，如果你的大多数访问者说荷兰语，那么用荷兰语的等价物覆盖标准消息将是有价值的。

尽管需要一些仔细的思考和规划，但添加语言支持仍然非常容易；让我们看看如何操作：

1.  对于这个练习，你需要修改验证器对象。在 `formvalidator.js` 文件中，在 `document.ready()` 语句之后立即添加以下代码：

    ```js
    varmyLanguage = {
      badUrl: "De ingangswaarde is geencorrecte URL"
    };
    ```

1.  我们需要引用语言的变化，因此，请继续将此配置行添加到验证器对象中：

    ```js
    $.validate({
      modules: 'free_email, user_name',
     language: myLanguage
    });
    ```

1.  保存文件。如果在浏览器中预览结果，你可以看到错误消息现在以荷兰语显示，如下所示：![本地化我们的内容](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00368.jpeg)

1.  我们不限于荷兰语；这里是相同的代码，但是错误消息是法语：

    ```js
    varmyLanguage = { badUrl: "La valeur d'entrée n'est pas une URL correcte" };
    ```

这是一个快速简单的方法，可以确保访问您网站的访客了解为什么您的表单未经验证以及他们如何修复它。值得注意的是，无论您的 PC 或移动设备的区域设置如何，设置的消息都会显示；建议您在更改表单消息中使用的语言之前检查任何分析日志以确认您的访问者来自哪个地区或国家。

## 集中我们的错误消息

在我们结束表单开发之前，还有一个功能可以添加到我们的表单中。

到目前为止，显示的任何验证错误消息都是针对每个单独字段的。这样做可以工作，但意味着我们没有一种立即知道哪些字段可能未通过验证的方法。当然，我们可以滚动浏览表单，但我懒得做这个；如果我们可以修改我们的代码以在顶部显示错误，那为什么还要滚动长表单呢？

绝对，使用 FormValidator 这样做非常简单；现在让我们来看看需要做什么：

1.  打开 `formvalidator.js` 文件的副本，并按照此处所示更改验证器对象；我们将 `errMessagePosition` 属性设置为 `top`，将 `validatorOnBlur` 属性设置为 `false`，以便在表单顶部显示消息：

    ```js
    $.validate({ modules: 'user_name, free_email', validateOnBlur: false, errorMessagePosition : 'top', language: myLanguage});
    ```

1.  如果现在运行表单，设置的任何错误消息都会显示在顶部，但它们看起来不太好看。现在，让我们通过对样式表进行一些微小的更改来修复这个问题：

    ```js
    div.form-error { 
      font-size: 14px; 
      background: none repeat scroll 0 0 #ffe5ed;
      border-radius: 4px; color: #8b0000;
      margin-bottom: 22px; padding: 6px 12px;
      width: 88%; margin-left: 0px; margin: 10px;
    }
    ```

1.  现在，让我们在浏览器中运行表单；如果一切顺利，你将看到顶部的错误已经正确格式化的表单。以下截图显示了如果你不填写网站 URL 会出现什么；请注意，我们的代码仍然显示了前一个示例中的荷兰语消息：![集中我们的错误消息](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00369.jpeg)

到目前为止，我们已经涵盖了一些与使用 jQuery 进行验证相关的主题。我们将继续并查看一下几个示例表单的操作。在我们这样做之前，我们需要完成一些最后的调整作为开发的结束部分。

## 结束开发

在预览最后一个练习时，更加细心的人会注意到一些样式似乎缺失了。这有一个很好的理由；让我解释一下。

作为最低要求，我们可以提供指示成功或失败的消息。这样做是有效的，但不是很好；更好的选择是提供一些额外的样式来真正突出我们的验证：

![结束开发](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00370.jpeg)

这很容易做到，所以让我们从执行以下步骤开始：

1.  打开`formvalidator.css`文件并添加以下代码行：

    ```js
    .has-error, .error { color: #f00; }
    .has-success, .valid { color: #060; }
    .error { background-image: url(../img/invalid.png); background-position: 98%; background-repeat: no-repeat; background-color: #ff9a9a; }
    .valid { background-image: url(../img/valid.png); background-position: 98%; background-repeat: no-repeat; background-color: #9aff9a; }
    ```

1.  我们需要将两个图标添加到项目区域的`img`子文件夹中——为此，我使用了位于[`www.iconfinder.com/icons/32520/accept_check_good_green_ok_success_tick_valid_validation_vote_yes_icon`](https://www.iconfinder.com/icons/32520/accept_check_good_green_ok_success_tick_valid_validation_vote_yes_icon)的红叉和绿勾图标。如果您想使用不同的图标，则可能需要相应调整样式规则。

1.  保存`formvalidator.css`。如果在浏览器中预览结果并在表单中输入详细信息，则在单击**提交表单**时，您应该看到与本练习开始时显示的屏幕截图类似的结果。

希望您会同意这看起来好多了！在伴随本书的代码下载中有一个`formvalidator.css`的副本；它包含了在表单中为其赋予非常精致外观的一些额外样式，正如我们在这个练习中所见。

### 提示

如果您想看到包含自定义内容的工作示例，请从代码下载中提取`formvalidatior-fullexample`JavaScript、CSS 和 HTML 文件，并将它们分别重命名为`formvalidator.js`、`formvalidator.css`和`formvalidator.html`。

## 注意最佳实践的使用

在我们的每个示例中，我们都将表单设置为一次显示所有字段——考虑到用户的目标和期望是一个关键点。他们试图实现什么？我们真的需要一次显示几十个字段吗？或者，我们可以使表单更简单吗？

尽管本书的重点自然是掌握 jQuery，但仅仅集中于编写代码是愚蠢的；我们还必须在构建表单及其相关验证时考虑一些外观和功能方面的问题。

举一个小例子，值得考虑的是，当字段可用时，我们是否可以使用 CSS 来模糊或聚焦字段。我们可以使用少量 CSS 来模糊或聚焦这些字段，类似于以下代码：

```js
input[type=email], input[type=text] { filter: blur(3px); opacity: .4; transition: all .4s; }

input[type=email]:focus, input[type=text]:focus { filter: none; opacity: 1; }
```

这里的想法是淡化我们已输入内容的字段，并将注意力集中在我们尚未完成或即将完成的字段上，如下面的屏幕截图所示：

![注意最佳实践的使用](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00371.jpeg)

一个小警告：如果我们在使用此样式时不小心，可能会导致字段失效，这将破坏练习的整个意义！现在让我们改变焦点，转向表单设计的一个关键部分：如果某些浏览器不支持我们在本章中使用的 CSS 样式会发生什么？

## 提供后备支持

在本章中，我们在设计大多数现代浏览器中可用的表单方面进行了尝试。尽管如此，在某些情况下，这可能不起作用；如果我们仍然必须迎合不支持的浏览器（例如 iOS7），那么我们需要提供某种形式的后备方案。

幸运的是，如果我们使用类似 Modernizr 这样的工具，在`html`元素上应用`formvalidation`类，以提供一种优雅的降级，那么这不会成为太大的问题。然后，我们可以利用这一点，在浏览器不支持伪选择器（例如`:valid`或`:invalid`）的情况下提供优雅的后备方案。

### 小贴士

如果你想使用自定义版本的 Modernizr，该版本将测试表单验证支持，请访问[`modernizr.com/download/#-shiv-cssclasses-teststyles-testprop-testallprops-prefixes-domprefixes-forms_validation-load`](http://modernizr.com/download/#-shiv-cssclasses-teststyles-testprop-testallprops-prefixes-domprefixes-forms_validation-load)。

足够的理论了，让我们来点乐子吧！在接下来的几页中，我们将通过两个练习来看一个更复杂的例子。它将基于一个简单的联系表单，我们将在其中添加表单上传功能——尽管请注意，这里会有一个陷阱……！

# 使用 AJAX 创建一个高级联系表单

在我们复杂示例的第一部分中，我们将开发一个表单，允许我们提交一些基本详细信息，并且允许首先出现在表单消息面板上，然后通过电子邮件进行确认。

对于本练习，我们将需要使用一些工具，如下所示：

+   使用默认设置安装的本地 Web 服务器——选项包括 WAMP（适用于 PC；[`www.wampserver.de/en`](http://www.wampserver.de/en)）或 MAMP（适用于 Mac；[`www.mamp.info/en/`](http://www.mamp.info/en/)）。Linux 用户很可能已经有了作为发行版一部分的某些内容。

+   免费的 Test Mail Server 工具（仅适用于 Windows），可在[`www.toolheap.com/test-mail-server-tool/`](http://www.toolheap.com/test-mail-server-tool/)获取，因为从本地 Web 服务器发送电子邮件可能很难设置，所以这个出色的工具会监视端口 25 并提供本地邮件功能。对于 Mac，您可以尝试按照[`discussions.apple.com/docs/DOC-4161`](https://discussions.apple.com/docs/DOC-4161)提供的说明进行操作；Linux 用户可以尝试按照[`cnedelcu.blogspot.co.uk/2014/01/how-to-set-up-simple-mail-server-debian-linux.html`](http://cnedelcu.blogspot.co.uk/2014/01/how-to-set-up-simple-mail-server-debian-linux.html)中概述的步骤进行操作。

+   从正在使用的个人电脑或笔记本电脑上访问电子邮件包——这是接收我们演示发送的电子邮件所必需的。

### 小贴士

另一个可能的选项，如果你更喜欢走跨浏览器的路线，是 XAMPP ([`www.apachefriends.org/index.html`](https://www.apachefriends.org/index.html))；这包括 Mercury Mail Transport 选项，因此如果你在 Windows 上工作，则不需要 Test Mail Server 工具。

好的，工具就位了，让我们开始执行以下步骤：

1.  我们将从打开此书附带的代码下载的副本并提取 `ajaxform` 文件夹开始；这包含了我们演示的标记、样式和各种文件。我们需要将该文件夹保存到 Web 服务器的 `WWW` 文件夹中，对于 PC 来说，通常是 `C:\wamp\www`。

1.  标记相对简单，与本章中已经见过的内容非常相似。

1.  我们需要对 `mailer.php` 文件进行一个小修改；用你选择的文本编辑器打开它，然后找到这一行：

    ```js
            $recipient = "<ENTER EMAIL HERE>";
    ```

1.  将 `<ENTER EMAIL HERE>` 更改为你可以使用的有效电子邮件地址，以便检查之后是否出现了电子邮件。

1.  这个演示的魔法发生在 `ajax.js` 文件中，所以现在让我们看看这个文件，并开始设置一些变量：

    ```js
    $(function() {
      var form = $('#ajaxform');
      var formMessages = $('#messages');
    ```

1.  当提交按钮被按下时，我们开始真正的魔法；首先我们阻止表单提交（因为这是默认操作），然后将表单数据序列化为字符串以便提交：

    ```js
    $(form).submit(function(e) {
      e.preventDefault();
      var formData = $(form).serialize();
    ```

1.  接下来是这个表单的 AJAX 操作的核心；这个函数设置请求类型，发送内容的位置以及要发送的数据：

    ```js
    $.ajax({ 
      type: 'POST',
      url: $(form).attr('action'),
      data: formData
    })
    ```

1.  然后我们添加两个函数来确定应该发生什么；第一个函数处理我们表单的成功提交：

    ```js
    .done(function(response) {
      $(formMessages).removeClass('error');
      $(formMessages).addClass('success');
      $(formMessages).text(response);

      $('#name').val('');
      $('#email').val('');
      $('#message').val('');
    })
    ```

1.  失败提交表单后的处理函数如下：

    ```js
    .fail(function(data) {
          $(formMessages).removeClass('success');
          $(formMessages).addClass('error');

          if (data.responseText !== '') {
            $(formMessages).text(data.responseText);
          } else {
            $(formMessages).text('Oops! An error occurred and your message could not be sent.');
           }
         });
       });
     });
    ```

1.  启动电子邮件工具。如果你在浏览器中预览表单并填写一些有效的细节，当你提交它时，你应该会看到这个截图：![使用 AJAX 创建高级联系表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00372.jpeg)

我们的表单现在已经就位，并且能够提交，在几秒钟内通过电子邮件确认。我们将在下一章中更深入地重新讨论在 jQuery 中使用 AJAX 的用法；现在，让我们继续开发我们的表单。

# 使用 jQuery 开发高级文件上传表单

正如一位善良的人不久前所说的那样，*"前进和上升！"*，现在是时候添加我们表单功能的第二部分了，以文件上传选项的形式。

不考虑这可能带来的风险（如上传病毒），添加文件上传功能相对简单；它需要客户端和服务器端组件才能正常工作。

在我们的示例中，我们将更多地关注客户端功能；为了演示目的，我们将文件上传到项目区域内的一个虚拟文件夹。为了让你了解我们将构建的内容，这是一个完成示例的截图：

![使用 jQuery 开发高级文件上传表单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/ms-jq/img/image00373.jpeg)

有了这个想法，让我们开始执行以下步骤：

1.  在`ajaxform.html`文件的副本中，我们需要向各种 JavaScript 和 CSS 文件添加一些额外的链接；所有这些添加都在随书附带的代码下载中可用，如下所示：

    ```js
    <link rel="stylesheet" href="css/bootstrap.min.css">
    <link rel="stylesheet" href="css/styles.css">
    <link rel="stylesheet" href="css/fileupload.css">
    <script src="img/jquery.min.js"></script>
    <script src="img/ajax.js"></script>
    <script src="img/jquery.ui.widget.js"></script>
    <script src="img/jquery.iframe-transport.js"></script>
    <script src="img/jquery.fileupload.js"></script>
    <script src="img/uploadfiles.js"></script>

    ```

1.  接下来，我们需要在`index.html`中添加一些标记；所以，在`ajaxform.html`中，首先按照这里显示的更改标题：

    ```js
    <div id="formtitle">
      <h2>File Upload Demo</h1>
    </div>
    <div id="form-messages"></div>
    ```

1.  现在我们需要添加文件上传代码；所以，在消息字段的结束`</div>`标签之后，立即添加以下代码：

    ```js
    <div class="container">
      Click the button to select files to send:
      <span class="btnbtn-success fileinput-button">
      <span>Select files...</span>
      <input id="fileupload" type="file" name="files[]" multiple>
      </span>
      <p>Upload progress</p>
      <div id="progress" class="progress progress-success 
      progress-striped">
      <div class="bar"></div>
      </div>
      <p>Files uploaded:</p>
      <ul id="files"></ul>
    </div>
    ```

1.  我们需要对我们的一个 jQuery 文件进行一点小小的修改；在`uploadfiles.js`中，找到以下开头的行：

    ```js
    $('#files').append('<li><img src="img/div>Now, amend the highlighted part to match the location of where you are hosting the files within your local web server. The `files` and `thumbnail` folders are created automatically by the scripts.
    ```

1.  要完成我们的演示，我们需要两个额外的文件：一个是`files.php`，另一个是`UploadHandler.php`；这些文件将处理文件的后端上传和电子邮件的发送。这些文件的副本都在随书附带的代码下载中。

1.  保存所有文件。如果使用本地 Web 服务器预览结果，则应该看到一个可用的表单，类似于此练习的第一部分；现在它还将显示您的上传表单。

### 注意

在随书附带的代码下载中的`combined`文件夹中有一个演示的工作版本。

此时，我们应该有一个可用的表单。但是等等……有没有人注意到什么？希望在这一点上，你应该已经注意到我们的表单中几乎没有验证了……！“嗯？”我听到你问。你完全正确，但是像所有好事一样，这也是有原因的。

我在这里故意没有添加任何验证，因为我想首先集中精力让表单功能正常运行，并最终从验证中小休一下，考虑到我们在过去几页中已经涵盖了很多内容。

然而，这确实为你提供了一个绝佳的机会（是的，这里有个陷阱）——要不要检查一下你是否能为示例添加验证？我在代码下载中没有提供答案——毕竟，并不存在绝对正确或错误的答案；验证取决于你表单的需求。不过，在本章中应该有足够的内容让你开始。我强烈建议你查看主网站[formvalidator.net](http://formvalidator.net)上的文档，因为它会提供更多答案！

# 摘要

哦！我们终于到达了本章的末尾，所以让我们花点时间回顾一下我们到目前为止所涵盖的内容。

我们从为什么表单验证很重要以及关键点是保持任何解决方案简单以确保表单成功开始。我们先看了简单的 HTML5 验证，然后讨论了何时使用 jQuery 代替标准 HTML5 验证的优点。

然后，我们开始了解使用 jQuery 进行简单验证，然后扩展到覆盖正则表达式语句的使用。接下来，我们看了一下开发一个快速而肮脏的验证插件，然后审查了保持更模块化架构以帮助通过使用自定义验证器来实现可扩展性的需求。

我们转而使用现有的插件来添加验证功能，因为这样可以让我们花更多时间确保我们满足我们的需求，而不仅仅是能够验证任何内容的简单优点。我们还研究了如何本地化我们的内容，并集中显示错误消息，然后在开发结束前进行了一些额外的样式调整。

然后，我们在章节结尾部分提出了最佳实践和提供备用支持的说明，然后以开发复杂表单的基础作为结束，文件上传功能作为使用本章提供的一些技术进行未来个人发展的基础。

在下一章中，我们将扩展一个我们在表单开发中简要介绍过的主题；是时候来看看那个经得起考验的技术，叫做 AJAX…
