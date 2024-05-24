# jQuery 响应式 Web 设计（三）

> 原文：[`zh.annas-archive.org/md5/2079BD5EE1D24C66E7A412EFF9093F43`](https://zh.annas-archive.org/md5/2079BD5EE1D24C66E7A412EFF9093F43)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：测试响应性

事实证明，在设备本身上检查设计没有比在我们的测试模拟器中消耗更多的时间，浏览器工具是使测试变得更快的解决方案，但不会能够复制一个与真实情况完全相同的网站。

尽管它们会非常接近，但我们可以将这种类型的测试定义为仅作为初始测试过程，然后在真实设备上进行测试，以确保所有功能都运行良好。

在本章中，我们将学习以下内容：

+   使用浏览器工具模拟设备

+   在设备模拟器上测试

+   响应式网站单元测试的提示

# 使用浏览器工具模拟设备

浏览器工具将无法模拟我们通常在设备上看到的方式，但它们有助于 CSS 断点测试，并显示您的响应式网站在 iPad、iPhone 或任何基于屏幕尺寸测量的 Android 手机等最流行设备上的外观。

屏幕调整大小不会捕捉浏览器及其渲染引擎之间的不一致性。例如，使用 Chrome 调整浏览器大小并不会告诉您仅在 Safari 移动浏览器上发生的 CSS 问题。

让我们来看看几个网站，这将帮助您作为开发人员确定您的网站在特定设备上的表现如何。

## 使用 Viewport Resizer 网站工具

Viewport Resizer 是一个网站工具，它在开发或发布网站后测试响应式网站时提供了便利。

在工具网站上列出的优点中，我们想要强调一些：

+   在运行时添加自定义屏幕尺寸

+   设备指标的视觉预览（鼠标悬停）

+   视口信息（大小、纵横比、方向和用户代理）

+   打印支持：仅 WebKit（Chrome 和 Safari）

不幸的是，这个工具在任何版本的 Internet Explorer 浏览器中仍然无法工作，这对于查找 Windows 手机上的视觉问题会很有帮助。

无需下载或安装它。您只需要访问 [`lab.maltewassermann.com/viewport-resizer`](http://lab.maltewassermann.com/viewport-resizer) 并将标有 **点击或收藏** 按钮的链接保存到您的收藏链接列表中。

以下是我们的网站在智能手机上使用此工具时的呈现示例：

![使用 Viewport Resizer 网站工具](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_09_01.jpg)

## 使用调查者网站工具

调查者是一个网站工具，它遵循了上一个工具的基础，并使得在正在开发的网站和已经发布的网站上测试响应性成为可能。

您可以通过访问 [`surveyor.io`](http://surveyor.io) 并指定要查看的 URL 和屏幕尺寸来测试网站（没有预定义的值可供选择）。

然后，您可以在所有断点上并排测试您的响应式设计，帮助您更好地了解正在使用的断点设计，促进所有比较。

### 提示

有时，此浏览器工具显示的滚动条可能会误导我们对网站分析，显示出实际上不存在的问题。在这种情况下，值得检查网站以及接下来的这个工具。

观察这个网站，并比较该网站被调整到平板电脑和智能手机版本之间的区别：

![使用 Surveyor 网站工具](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_09_02.jpg)

## 使用 ScreenFly 网站工具

这个工具也遵循了我们之前看到的网站调整大小的模式，在这种模式下，开发者输入 URL（它也适用于开发项目），并选择我们想要在网站上检查的分辨率。

这个工具为开发者提供了一些精确的屏幕尺寸模板供选择，以及市场上最常见的设备型号。而且它不需要记住所有模板，这让使用更加方便。或者，如果您想自定义自己的尺寸，只需点击**自定义屏幕尺寸**按钮即可。

访问网站[`quirktools.com/screenfly`](https://quirktools.com/screenfly)，您可以提供要测试的网站。默认情况下，它会在 Netbook 10 预览中显示您的网站，模拟设备宽度。您可以通过点击标题按钮并选择特定型号来选择其他设备。

ScreenFly 工具还有另一个有趣的功能，即共享链接，以便更轻松地进行客户和开发人员之间的沟通（仅适用于已经发布的网站）。

这对于改善客户和开发人员之间的沟通非常有用，展示某些功能或问题。为了做到这一点，只需点击**共享**按钮，并将链接发送给其他人。通过访问此链接，对方将看到类似于这样的屏幕：

![使用 ScreenFly 网站工具](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_09_03.jpg)

# Opera 移动模拟器

尽管 Opera 移动浏览器已经不再处于巅峰时期，但根据[StatCounter.com](http://StatCounter.com)网站的数据，它仍然占移动设备访问量的 16.62％。这也是为什么在这个移动浏览器中至少检查我们网站的主要基本功能仍然很重要的原因。

Opera Software 公司为开发人员提供了良好的支持，他们提供了一个内置 Mobile Opera 浏览器的模拟器。其浏览器也构成了模拟器的基础，您可以使用它来测试各种不同的移动设备。您可以在[`www.opera.com/developer/mobile-emulator`](http://www.opera.com/developer/mobile-emulator)下载该应用程序。

安装好后，只需选择所需的设备，如下面的屏幕截图所示，并点击**启动**按钮：

![Opera 移动模拟器](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_09_04.jpg)

# 响应式网站设计测试技巧

有了这些响应式设计工具，我们已经准备好创建适用于任何设备的灵活设计。

但在测试时，注意以下提示很重要：

+   不要在没有进行测试的情况下完成整个网站。最好的方法是在每个功能实施后立即进行测试，这样可以更容易找到问题所在。

+   回归测试非常重要，以防止级联错误。在测试完实现的功能后，请检查之前所做的内容是否没有在网站的其他部分引入新问题。

    ### 注意

    回归测试在对网站的现有区域进行增强之后寻找软件 bug。

+   检查图像和图标质量以及网站内容在结构上的流畅性。

+   对响应式网站进行性能分析，特别是在移动设备上查看时（我们将在下一章中专门看到这一点）。

# 练习 9 - 让我们在不同的屏幕尺寸下测试我们的网站

我们将选择我们之前看到的工具之一来测试我们的网站。

这是使用 Surveyor 工具模拟智能手机和平板电脑断点的屏幕截图：

![练习 9 - 在不同的屏幕尺寸下测试我们的网站](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_09_05.jpg)

在测试时，首先记录下所有发现的视觉问题，以及已实现的功能，然后立即开始修复它们。这个过程可以确保你不会失去注意力和浪费时间。

# 总结

在本章中，我们已经专注于通过使用工具和脚本来测试网站，以确保其在所有设备上的响应性。我们已经了解了通过使用网站工具，如 Viewport Resizer、Surveyor 和 ScreenFly 来检查我们的实现中可能存在的错误的重要性。此外，我们通过在原生 Opera Mobile 浏览器中打开网站来模拟许多移动设备并测试 Opera Mobile 模拟器。

在下一章中，我们将确保跨浏览器解决方案提供回退。我们将学习如何处理旧的浏览器，并通过展示优雅降级来呈现正确的设计。


# 第十章：确保浏览器支持

不同的浏览器具有自己的专有功能以及以自己的方式实现的标准功能的子集，这给我们带来了很多工作，以使这些功能适用于所有浏览器。

这些差异的原因是 W3C 规范不断更新，而且随着浏览器之间的不断竞争，它们始终试图将自己的产品推广为具有更好的功能性。

然而，jQuery 具有良好的跨浏览器兼容性，并且具有灵活性，可以弥补每个浏览器中功能实现的差距。这些桥梁被称为**Polyfills**。

Polyfills 是本章的主要内容，我们还将了解到：

+   检查浏览器支持的功能

+   polyfill 的含义

+   了解特性检测工具

+   用于 HTML5 和 CSS3 的 Polyfill 实现

# 检查浏览器支持的功能

在网站开发中，经验确实为程序员带来了很大的灵活性。虽然这些知识很快就会过时，但我们必须及时了解新的功能、选择器和增强功能，一旦它们与浏览器兼容。

根据我们的浏览器和设备，检查技术和功能的兼容性的三个主要网站是：[CanIUse.com](http://CanIUse.com), [MobileHTML5.org](http://MobileHTML5.org), 和 [QuirksMode.org](http://QuirksMode.org)。

## CanIUse.com

[CanIUse.com](http://CanIUse.com) 网站是这些参考网站中最著名的网站，我们可以在其中检查支持 HTML5、CSS3、SVG 等在桌面和移动浏览器中的兼容性表。

如果您访问 [`caniuse.com`](http://caniuse.com)，您将会看到它的数据是基于 StatCounter GlobalStats 收集的统计数据，而且数据是不断更新的。

阅读**注释**和**已知问题**选项也是很重要的（如下面的屏幕截图中所示），因为我们是社区的一部分，对整个开发网站的演进做出了很大的贡献。这些选项突出了应该考虑的例外情况或报告问题以及在特定场景中他们必须使用的技术。

![CanIUse.com](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_10_01.jpg)

## MobileHTML5.org

[MobileHTML5.org](http://MobileHTML5.org) 网站专注于移动和平板浏览器上 HTML5 功能的兼容性，通过在真实设备上进行测试来进行区分。这很重要，因为正如我们在前一章中所看到的，模拟的桌面浏览器视图与在移动设备上测试网站之间的视觉差异很小。

但是，当涉及到硬件和设备操作系统时，这些差异会显著增加，只有在真实设备上测试网站时，我们才可能发现潜在问题。

所列设备的种类令人印象深刻。以下截图展示了一些市场份额不再很大的旧设备的功能，甚至显示了最近推出的操作系统，如 FirefoxOS。

请自行访问网站 [`mobilehtml5.org`](http://mobilehtml5.org)，并检查更新的列表。

![MobileHTML5.org](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_10_02.jpg)

## QuirksMode.org

在 [QuirksMode.org](http:// QuirksMode.org) 网站上，我们可以通过在使用之前检查指定的选择器或伪类是否被浏览器接受，来防止在开发过程中出现未来的坏惊喜。否则，我们必须在一开始定义的每个浏览器上进行检查。

[QuirksMode.org](http://QuirksMode.org) 网站仅专注于存储和更新几乎每个 CSS 选择器和属性的浏览器支持信息。正如我们在 [`www.quirksmode.org/css/selectors`](http://www.quirksmode.org/css/selectors) 上看到的，此信息分为以下几类：

+   组合器

+   属性选择器

+   伪元素

+   伪类

以下是 [QuirksMode.org](http://QuirksMode.org) 网站上检查伪元素技术的一部分：

![QuirksMode.org](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_10_03.jpg)

# 定义回退

回退是在开发网站时的支持流程的一部分。其目标是为我们应用于网站的技术提供替代方案，但并非所有浏览器都支持此特定功能。

此术语可以分为 polyfills 和 webshims。

**Polyfill** 是一种特定的代码，用于模拟不原生支持某项特性的浏览器。Polyfills 总是尝试模仿原始浏览器特性，但有几种情况下可能会导致轻微的副作用，如增加加载时间或降低性能。

一个 polyfill 的例子是 html5shiv 脚本，我们只需将其放入代码中，它就会像没有任何变化一样起作用。我们稍后会谈论 html5shiv。

**Shims** 提供了一个回退，但通常具有自己的 API，并且可能需要修改代码以使 shim 起作用。这就是为什么我们有像 `yepnope.js` 这样的库来加载这些内容（如果需要的话）。我们稍后会看到使用 `yepnope.js` 的示例。

让我们看看两个功能检测工具，在我们提供回退时可能会有用。

# 功能检测工具

功能检测是我们能够为网站用户提供的渐进增强的第一步。

然后，我们必须测试浏览器是否已经实现了给定的功能。如果是这样，我们就不需要重新实现已经存在的任何东西，但如果浏览器确实缺少该功能，则建议为其提供正确的支持。

有时我们必须支持尚未完全实现特定功能的浏览器。然而，新功能在查看网站时会产生影响，并且网站的流行度通常会增加。

## CSS Browser Selector +

与 Modernizr 相比，跨浏览器响应式设计助手更简单，因为它的唯一功能是在网站加载时检测功能，并将其标记在代码中，使用放置在`<html>`标签中的类。

它易于实现，因此允许我们编写特定的 CSS 代码，并解决仅限于某些操作系统或浏览器的视觉问题，这是 CSS hacks 的终结！

此 JavaScript 库主要识别的主要项目是：

+   浏览器及其版本

+   渲染引擎

+   平台和操作系统

+   设备

+   屏幕检测的`max-width`和`min-width`

+   浏览器方向检测

+   语言检测

通过访问[`ridjohansen.github.io/css_browser_selector/`](http://ridjohansen.github.io/css_browser_selector/)网站自己尝试这个工具，并通过检查`<html>`元素来查看类。

这样，就可以解决特定浏览器的问题，甚至帮助创建类似这样的回退。考虑以下示例：

```js
.orientation_landscape .div-example {
  border: 2px solid red;
}
```

### 提示

我们拥有的用于创建异常的自定义代码越少，实施未来更新和更改就越好。如果可能的话，最好是确定错误的根本原因，而不仅仅是修复浏览器之间的视觉差异。

### 如何操作

下载后，我们只需在`<head>`标签内的代码中包含`css_browser_selector.js`文件：

```js
<script src="img/css_browser_selector.js"></script>
```

通过检测，可以加载脚本或不同的功能，但这不包括在此解决方案中。为了解决这个问题并访问更多类型的功能检测，建议使用更完整的解决方案：Modernizr。

## Modernizr

Modernizr 是一个 JavaScript 库，用于检测用户浏览器中的 HTML5 和 CSS3 功能，使得为每种情况编写条件化的 JavaScript 和 CSS 变得容易，无论浏览器是否支持某个功能。

它通过向`html`元素添加类来实现我们将来在 CSS 中选择的目的。此外，它创建了一个 JavaScript 对象，其中包含稍后用于支持数十个测试的结果。当从[`modernizr.com`](http://modernizr.com)下载 Modernizr 时，我们可以选择下载完整开发版本或只包含我们打算使用的部分的定制构建版本。

### 提示

Modernizr 的网站建议下载一个定制版本，该版本具有适合项目的功能，而不是使用来自 CDN 的完整版本，因为大多数情况下定制版本比完全开发的版本要小。

之后，我们可以像这样在头部部分的代码中包含`the modernizr.custom.85330.js`文件：

```js
<script src="img/modernizr.custom.85330.js"></script>
```

让我们观察一下在 Firefox 上查看时 `<html>` 标签中所有检测到并准备使用的功能的类是如何排列的：

```js
<html lang="en" class=" js no-flexbox flexboxlegacy canvas canvastext webgl no-touch geolocation postmessage no-websqldatabase indexeddb hashchange history draganddrop websockets rgba hsla multiplebgs backgroundsize borderimage borderradius boxshadow textshadow opacity cssanimations csscolumns cssgradients no-cssreflections csstransforms csstransforms3d csstransitions fontface generatedcontent video audio localstorage sessionstorage webworkers applicationcache svg inlinesvg smil svgclippaths">Now, let's look at the features detected, but this time viewed on Internet Explorer 8:<HTML class="ie8 js no-flexbox no-flexboxlegacy no-canvas no-canvastext no-webgl no-touch no-geolocation postmessage no-websqldatabase no-indexeddb hashchange no-history draganddrop no-websockets no-rgba no-hsla no-multiplebgs no-backgroundsize no-borderimage no-borderradius no-boxshadow no-textshadow no-opacity no-cssanimations no-csscolumns no-cssgradients no-cssreflections no-csstransforms no-csstransforms3d no-csstransitions fontface generatedcontent no-video no-audio localstorage sessionstorage no-webworkers no-applicationcache no-svg no-inlinesvg no-smil no-svgclippaths" lang=en xmlns:html5shiv>
```

这样，我们可以编写这种代码，在这种情况下，我们可以确保如果您的浏览器不支持`boxshadow`属性，我们可以制作两个边框模拟阴影效果：

```js
.box {
  border:1px solid #DDD;
  border-bottom: 1px solid #AAA;
  border-right: 1px solid #AAA;
}
.boxshadow div.box {
   border: none;
   -webkit-box-shadow: 1px 1px 3px #777;
      -moz-box-shadow: 1px 1px 3px #777;
           box-shadow: 1px 1px 3px #777;
}
```

下面的代码示例演示了如何在边框上创建阴影效果：

![Modernizr](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_10_10.jpg)

现在，让我们看看当解决方案需要在需求网站上添加另一个库时，我们可以使用 YepNope.js 做些什么。

### YepNope.js

YepNope.js 是一个用于异步条件加载外部 JavaScript 和 CSS 资源的 JavaScript 库。

以下是一个示例，说明了如何使用 Modernizr 测试 CSS 动画，以及在浏览器不支持`CSSTransforms`时使用 YepNope 作为回退：

```js
<script>
  Modernizr.load({
    test: Modernizr.csstransforms,
    yep : 'css/cssTransform.css',
    nope: ['css/noTransform.css','js/jQuery.pseudoTransforms.js ']
  }); 
</script>
```

### html5shiv

html5shiv 库可以在较旧版本的 IE 浏览器中启用对 HTML5 元素的支持，特别是 6 到 8，并为 IE9 提供了一些基本支持。

另外，这个解决方案还有另一个名为`html5shiv-printshiv.js`的文件，其中包含了一个可打印版本。它还允许通过 IE6 到 IE8 打印使用 HTML5 元素及其子元素时进行样式设置。

您可以通过简单地选择 Modernizr 下载页面上显示的选项来使用此功能，当该库包含在项目中时，如果浏览器不支持该 html5 元素，它将应用该 polyfill：

![html5shiv](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_10_07.jpg)

# Polyfill 实现

已经开发了数百种 polyfills 和 shims。并且随着新功能、元素或增强功能的创建，这个列表会不断增长。

现在我们将看到一些 polyfill 的实现，但是重要的是在开始创建新的 polyfill 之前，你要检查[`github.com/Modernizr/Modernizr/wiki/HTML5-Cross-Browser-Polyfills`](https://github.com/Modernizr/Modernizr/wiki/HTML5-Cross-Browser-Polyfills)网站，看看是否已经开发了一个 polyfill。

## MediaElements.js

MediaElements 是一个 polyfill，用于在旧版本浏览器中使用 Flash 技术模拟本机 HTML5 MediaElement API，从而为正在查看的`<video>`和`<audio>`元素创建一致的播放器设计。

在下面的示例中，我们将应用此库来改善浏览器在显示视频时的一致性。然而，要使每个浏览器都能播放您的音频/视频，还有很多工作要做，因为它们需要在不同格式（如`.mp4`、`.webm`和`.ogg`）的文件中托管多个版本。

### 如何做到

从[`www.mediaelementjs.com`](http://www.mediaelementjs.com)下载最新版本后，我们可以在`<head>`标签内包含 JavaScript 库和`stylesheet`文件：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/mediaelement-and-player.min.js"></script>
<link rel="stylesheet" href="../build/mediaelementplayer.min.css" />
```

以下代码用于为不同的浏览器提供更多的可访问性：

```js
<video width="640" height="360" id="player2" poster="../media/echo-hereweare.jpg" controls="controls" preload="none">
  <!-- MP4 source must come first for iOS and webkit browsers -->
  <source type="video/mp4" src="img/echo-hereweare.mp4" />

  <!-- WebM for Firefox and Opera -->
  <source type="video/webm" src="img/echo-hereweare.webm" />
  <source type="video/ogg" src="img/echo-hereweare.ogv" />

  <!-- Fallback flash player -->
  <object width="640" height="360" type="application/x-shockwave-flash" data="../build/flashmediaelement.swf">    
    <param name="movie" value="../build/flashmediaelement.swf" /> 
    <param name="flashvars" value="controls=true&amp;file=../media/echo-hereweare.mp4" />     
    <img src="img/echo-hereweare.jpg" width="640" height="360" alt="" title="No video playback capabilities" />
  </object>   
</video>
```

然后，你可以通过以下方式为文档中的任何`<video>`或`<audio>`元素初始化播放器：

```js
<script>
$('video').mediaelementplayer({
  success: function(player, node) {
    $('#' + node.id + '-mode').html('mode: ' + player.pluginType);
  }
});
</script>
```

在下面的截图中，显示了其默认视频播放器 UI 的示例：

![How to do it](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_10_08.jpg)

当执行播放器时，有许多选项可供配置。这些选项可以在[`mediaelementjs.com/#options`](http://mediaelementjs.com/#options)找到。

## SVG

**可缩放矢量图形**（**SVG**）是一种用于矢量图形的图像格式。它的使用具有许多优点，如文件大小压缩良好，可在不失清晰度的情况下缩放到任何大小，在视网膜显示屏上显示效果良好，并通过为设计师提供更多控制权来实现更多交互性。

然而，浏览器对其的接受尚不完整，需要备用方案。 *Alexey Ten* 制定了一种非常有趣的技术，因为它解决了诸如 Internet Explorer 8 和 Android 2.3 等浏览器的问题。

让我们了解一种更好的覆盖 SVG 实现的方法。

### 如何实现

有一些不同的方法可以在网站上放置 SVG 文件。我们将使用以下方法来处理它们：背景图像，作为 `svg` 标签和作为 `img` 标签。

#### 将 SVG 作为背景图像

Modernizr 具有 SVG 测试。因此，您可以声明具有 Modernizr 注入到 HTML 元素中的类名的备用方案：

```js
.my-element {
  background-image: url(image.svg);
}
.no-svg .my-element {
  background-image: url(image.png);
}
```

#### 将 SVG 作为 <svg> 标签

这是一种新技术，在旧浏览器中无法很好地理解突出显示的术语，并显示 `.svg` 文件的地方显示 `.png` 文件：

```js
<svg width="96" height="96">
  <image xlink:href="svg.svg" src="img/svg.png" width="96" height="96" />
</svg>
```

#### 将 SVG 作为简单的 <img> 标签

通过使用 Modernizr，我们将测试浏览器是否支持 SVG，然后再插入代码。如果不支持，则脚本将查找具有相同名称的 `.png` 文件，并显示该文件而不是 `.svg` 文件。

```js
<img src="img/image.svg" onerror="this.src=image.png">

<script>
if (!Modernizr.svg) {
  $('img[src$=svg]').each(function(index, item) {
    imagePath = $(item).attr('src');
    $(item).attr('src',imagePath.slice(0,-3)+'png');
  });
}
</script>
```

然而，为了保持网站的正常运行，需要一致的 URL 和文件名模式，否则脚本将无法定位到正确的资源。

## Respond.js

Respond.js 是一个快速且轻量级的 `min-width` / `max-width` 的 polyfill，它使媒体查询得以支持，它将样式表重新解释为 Internet Explorer 6 到 8 浏览器可以理解的格式，加载完成后。

我们的所有媒体查询不需要任何额外的更改。我们只需确保我们的 `@media` 语句编写正确即可。

### 小贴士

如果您有一些 CSS 文件，请确保在 CSS 文件之后包含 `respond.min.js`。

如果我们的 CSS 使用 `@import` 或以内联方式编码，则 Respond.js 无法读取它。相反，请使用典型的 `<link>` 方法。例如：

```js
<link rel="stylesheet" href="css/style.css" media="screen and (max-width:480px)" />
```

### 如何实现

在 DOM 底部（在 `</body>` 结束标记之前），我们需要包含 Respond.js 库，可以从 [`github.com/scottjehl/Respond`](https://github.com/scottjehl/Respond) 下载。如果您有 CSS 文件，请确保在 CSS 文件之后包含 `respond.min.js`：

```js
<script src="img/respond.min.js"></script>
```

已经完成。

# 总结

在本章中，我们确保为观众提供了备用方案以确保可访问性。我们学习了如何通过使用 CSS 浏览器选择器和 Modernizr 来检测浏览器特性和支持的功能。这些库通过提供支持来执行渐进增强给我们带来了很大的帮助。此外，我们还学习了有关 HTML5 的有趣的 polyfill，例如 html5shiv、MediaElements，以及 `SVG` 和 `FileAPI` 的技术。本章还包括了对 CSS 的有用 polyfill Respond。

在下一章中，我们将看到成千上万个插件，用于创建一个良好的响应式网站，这些插件补充了我们迄今为止阅读过的所有章节。


# 第十一章：有用的响应式插件

随着技术和趋势的不断发展，每天都会出现新的插件，这些插件对于开发响应式网站变得越来越有帮助。通过诸如[`www.smashingmagazine.com/`](http://www.smashingmagazine.com/)、[`bradfrostweb.com/blog/`](http://bradfrostweb.com/blog/) 和 [`www.lukew.com/ff/`](http://www.lukew.com/ff/)等博客及时了解它们非常重要。

在本章中，我们将重点介绍不同的插件，涵盖以下主题：

+   网站结构的插件，例如 Columns、Equalize 和 Packery

+   用于菜单导航的插件，例如 Sidr、EasyResponsiveTabstoAccordion、FlexNav 和其他杂项插件

# 网站结构的插件

在第二章中，我们已经看到了 Fluid Baseline Grid System、1140 Grid 和 Foundation 4 等插件，它们构成了一个开发工具包，将帮助我们快速开发网站。我们需要记住的目标是创建一个连贯的网站，并且避免浪费时间重新创建已经完成的事情。

还有一些其他的额外插件，例如 Columns、Equalize 和 Packery，之前没有提及，为了集中精力构建我们的网站，但它们非常有用。

## 使用 Columns 创建简单的响应式结构

让我们从 Columns 插件开始，它的目标是提供一种快速创建响应式布局的方式，就像网格系统一样。它的简单性使其轻巧，并且学习曲线非常快。Columns 使用 MIT 许可证，在 IE9 和现代浏览器上运行良好。如果要使用 IE8，将需要为 HTML5 和媒体查询提供 polyfills。

此插件建议用于只需要简单且快速的响应式结构实现的小型网站。这并不意味着它不适用于中型和大型网站，但在这种情况下，其他框架可能提供更多的选项和解决方案，这些网站可能需要。

此外，还有一个选项可以根据屏幕尺寸自动调整字体大小的最小和最大值。

实现这个功能，我们需要从[`github.com/elclanrs/jquery.columns/`](https://github.com/elclanrs/jquery.columns/)访问该网站并下载这个解决方案的文件。

然后，让我们将以下代码插入到我们 DOM 的 `<head>` 标签中：

```js
<link rel="stylesheet" href="css/jquery.columns.css">
```

现在，让我们使用这个 HTML 代码作为一个示例来说明插件的使用，但随意尝试在您当前的 HTML 结构上使用这个插件。请注意，类似 `row-1` 和 `col` 这样的类以及类似 `content-1` 和 `content-2` 这样的 ID 将根据断点定义结构将如何显示：

```js
<section id="slider" class="row-1">
  <div class='col'>
    <img src="img/1344x250" class="responsive" />
  </div>
</section>
<section id="content-1" class="row-2">
  <div class='col'>
    <h2>Maui waui</h2>
    <p>Lorem ipsum dolor sit amet...</p>
  </div>
  <div class='col'>
    <h2>Super duper</h2>
    <p>Lorem ipsum dolor sit amet...</p>
  </div>
</section>
<section id="content-2" class="row-4">
  <div class='col'>
    <h3>Something</h3>
    <p>Lorem ipsum dolor sit amet...</p>
  </div>
  <div class='col'>
    <h3>Nothing</h3>
    <p>Lorem ipsum dolor sit amet...</p>
  </div>
  <div class="col">
    <h3>Everything</h3>
    <p>Lorem ipsum dolor sit amet...</p>
  </div> 
  <div class="col">
    <h3>All of it</h3>
    <p>Lorem ipsum dolor sit amet...</p>
  </div> 
</section>
```

通过定义类，例如 `row-2` 或 `row-4`，我们正在定义该部分内有多少列，并且 ID 将在稍后更改这些列的显示时提供更多的控制。

基本上，对于这个例子，我们将使用两个断点：480（插件的标准）和 1024。在 DOM 底部（在 `</body>` 结束标签之前），我们需要包含 jQuery 代码和 Columns 脚本。然后，我们将通过调用 `quickSetup` 函数并配置列和断点来运行插件。

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.columns.js"></script>
<script>
$.columns.quickSetup({
  fontSize: [14, 16]
});
$.columns.setCols({
  'content-1': [ [1024, 1] ],
  'content-2': [ [1024, 2] ]
});
</script>
```

在此示例中，当屏幕尺寸大于 1024 像素时，`content-2` 部分从每行四列开始。然后，当屏幕尺寸小于 1024 像素时，我们设置每行 2 列，并且当尺寸小于 480 像素时，设置每行 1 列。

让我们看看应用于父元素在桌面和平板电脑屏幕上的插件的可视结果：

![使用 Columns 创建简单响应式结构](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_11_01.jpg)![使用 Columns 创建简单响应式结构](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_11_13.jpg)

此外，该插件允许动态添加列。但是，要反映此更改，需要在添加到 DOM 后的代码中调用 `$.columns.refresh()`。

## 使用 Equalize 调整元素尺寸

当将页面自定义为看起来像卡片时，当加载动态内容时可能会出现一个常见问题，即尺寸可能会变化。我们希望保持所有项目的外观相同。

如果我们将列表项元素浮动到左侧，则每个项的内容将影响到断行，并且而不是从左侧开始的第二行将开始缩进。因此，不良布局卡片断裂的问题将如下所示：

![使用 Equalize 调整元素尺寸](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_11_02.jpg)

或者如果我们定义了所有项目的相同尺寸，我们将失去动态尺寸。类似的情况也发生在元素的宽度上。

Equalize 用于使元素的高度或宽度相等。它是一个轻量级且非常有用的 jQuery 插件，只需要指定父元素的 ID 或类即可执行。基本上，它通过计算更大元素的尺寸并将其定义为其他元素来工作，避免了任何浮动问题。

此外，它接受所有以下 jQuery 尺寸方法来调整元素的大小：`height`、`outerHeight`、`innerHeight`、`width`、`outerWidth` 和 `innerWidth`。最常用的是 `height`，它是插件的默认设置。

让我们尝试重现之前看到的相同例子，以查看这个插件的运行情况。目标是实现 Equalize 插件，调整所有项为较大元素的相同尺寸，并保持浮动工作的响应性，而没有不必要的断点。

从 [`github.com/tsvensen/equalize.js/`](https://github.com/tsvensen/equalize.js/) 下载后，我们将从源代码中添加以下 HTML 代码开始：

```js
<ul id="equalize-height">
  <li>equalize</li>
  <li>equalize content height</li>
  <li>equalize</li>
  <li>equalize</li>
  <li>equalize</li>
  <li>equalize content</li>
  <li>equalize</li>
  <li>equalize</li>
  <li>equalize content height </li>
  <li>equalize</li>
</ul>
```

然后，在 DOM 底部（在 `</body>` 结束标签之前），我们需要包含 jQuery 和 Equalize 库。之后，我们将执行用于 `equalize-height` ID（`<li>` 元素的父元素）的脚本。

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/equalize.min.js"></script>
<script>
$(function() {
  $('#equalize-height').equalize();
});
</script>
```

查看以下图中的预期情况：

![使用 Equalize 进行元素尺寸调整](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_11_03.jpg)

## 使用 Packery 实现卡片网站布局

Packery 是一个使用算法在基于卡片的网站布局上填充空白间隙，优雅地调整它们的 jQuery 插件。基于卡片的布局趋势随 Google+而来，正在赢得全球粉丝。

### 注意

Packery 插件有一个针对非商业、个人或开源项目的 GPL v3 许可证。如果你想在公共网站上使用它，需要支付$25。

它的实现并不太困难，正如我们将在它的使用示例中看到的那样。但是为了做到这一点，我们首先需要从[`github.com/metafizzy/packery`](https://github.com/metafizzy/packery)下载它。

让我们从创建一个空的 HTML 文件开始。打包的源文件包括了你使用 Packery 所需的一切。所以，在下载后，让我们在`<head>`标签中包含建议的自定义 CSS，以更好地处理卡片的尺寸：

```js
<style>
img {max-width: 100%; height: auto;}
@media screen and (min-width: 1024px) and (max-width: 1280px) {
  /* DESKTOP - 4 columns */
  #container > div { width: 25%; }
  #container > div.w2 { width: 50%; }
  #container > div.w4 { width: 100%; }
}
@media screen and (min-width: 768px) and (max-width: 1023px) { 
  /* TABLET - 3 columns */
  #container > div { width: 33%; }
  #container > div.w2 { width: 66%; }
  #container > div.w4 { width: 100%; }
}
@media screen and (max-width: 767px) {
  /* SMARTPHONE - 1 column */
  #container > div { width: 100%; }
}
</style>
```

之后，让我们使用这段`HTML`代码，其中每个项目代表一张卡片：

```js
<div id="container" class="js-packery">
  <div class="w4"><img src="img/1280x250"></div>
  <div class="w2"><img src="img/640x250"></div>
  <div><img src="img/320x250"></div>
  <div><img src="img/320x250img "></div>
  <div><img src="img/320x250 "></div>
  <div><img src="img/320x250 "></div>
  <div class="w2"><img src="img/640x250 "></div>
  <div><img src="img/320x250 "></div>
  <div><img src="img/320x250 "></div>
</div>
```

在 DOM 的底部（在`</body>`结束标签之前），我们需要包含 jQuery 和 Packery 库。此外，我们将初始化 Packery 脚本，告知容器 ID，用于重新定位的子元素的类，以及列（或间距）之间所需的空间。

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/packery.pkgd.min.js"></script>
<script>
var $container = $('#container');
$container.packery({
  itemSelector: '#container > div',
  gutter: 0
});
</script>
```

这是平板电脑和台式机的视觉结果：

![使用 Packery 实现卡片网站布局](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_11_12.jpg)![使用 Packery 实现卡片网站布局](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_11_04.jpg)

# 菜单导航的插件

在第三章*建立响应式导航菜单*中，我们已经看到了八种不同的流行菜单技术，每种都用于自己的目的。不幸的是，没有一种"万金油"菜单可以在所有情况下很好地工作。

为了始终与渐进的用户体验紧密相连，我们必须研究如何通过新的 JavaScript/jQuery 插件来改进我们的网站作为一个产品，常常可以找到。

我们将看到三个补充插件，与我们之前见过的插件相比，它们在方法上带来了一些小的差异。它们是 Sidr、EasyResponsiveTabstoAccordion 和 FlexNav。

## 使用 Sidr 创建侧边菜单

Sidr 是一个用于创建侧边菜单的 jQuery 插件，在响应式网站上非常常见。它还允许多个 Sidr 菜单（在两侧），以及与外部内容一起使用。

让我们尝试通过创建一个标准的 HTML 文件，并添加插件中包含的 CSS 文件来实现以下示例，可以从[`github.com/artberri/sidr`](https://github.com/artberri/sidr)下载。我们会发现两种显示菜单的选项，一种是暗色调（`jquery.sidr.dark.css`），一种是浅色调（`jquery.sidr.light.css`）。我们可以使用它们或扩展它们来覆盖一些样式。

所以，在`<head>`标签中包含其中一个后，我们可能会设置初始样式，以在屏幕大小高于 767 像素时隐藏菜单标题。

```js
<link rel="stylesheet" href="css/jquery.sidr.light.css">
<style>
  #mobile-header {
    display: none;
  }
  @media only screen and (max-width: 767px){
    #mobile-header {
      display: block;
    }
  }
</style>
```

现在，让我们使用以下 HTML 代码作为示例来说明插件的使用方法：

```js
<div id="mobile-header">
  <a id="responsive-menu-button" href="#sidr-main">Menu</a>
</div>
<div id="navigation">
  <nav>
    <ul class="nav-bar"> 
      <li><a href="#">Menu item1</a></li>
      <li><a href="#">Menu item2</a></li>
      <li><a href="#">Menu item3</a></li>
      <li><a href="#">Menu item4</a></li>
      <li><a href="#">Menu item5</a></li>
      <li><a href="#">Menu item6</a></li>
    </ul>
  </nav>
</div>
```

在 DOM 底部（在 `</body>` 结束标签之前），我们需要包含 jQuery 和 Sidr 库。之后，我们将通过将 Sidr 的执行与负责打开侧边菜单的菜单按钮绑定来绑定 Sidr 的执行。

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.sidr.js"></script>
<script>
$('#responsive-menu-button').sidr({
  name:   'sidr-main',
  source: '#navigation'
});
</script>
```

我们定义的 `#sidr-main` ID 将是侧边栏菜单 `<div>` 的 ID，而 `#navigation` 是我们选择在此侧边栏内显示的菜单的 ID。

在下面的截图中，我们将看到此实现的结果。单击**菜单**链接后，将在小于 767 像素的屏幕上显示浅色主题菜单（此值由我们自定义）：

![使用 Sidr 创建侧边菜单](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_11_05.jpg)

## 了解 EasyResponsiveTabstoAccordion

EasyResponsiveTabstoAccordion 是一个轻量级的 jQuery 插件，特别是在小型设备（如平板电脑和智能手机）上显示时，可以优化普通、水平或垂直选项卡为手风琴。

此插件的目标是根据屏幕尺寸调整元素。此外，它通过首先显示第一个选项卡的内容，然后显示其他选项卡的内容，优先显示内容阅读。此插件实现的效果完全使用 jQuery 实现，有助于提供跨浏览器兼容性。

更好地理解其工作方式的方法是实践。从 [`github.com/samsono/Easy-Responsive-Tabs-to-Accordion/`](https://github.com/samsono/Easy-Responsive-Tabs-to-Accordion/) 下载后，让我们创建一个标准的 HTML 文档，并将 CSS 文件添加到 `<head>` 标签内：

```js
<link rel="stylesheet" href="css/responsive-tabs.css">
```

现在，我们将使用以下 HTML 代码作为选项卡内容的样本：

```js
<div id="mytab">          
  <ul class="resp-tabs-list">
    <li>Tab-1</li>
    <li>Tab-2</li>
    <li>Tab-3</li>
  </ul> 
  <div class="resp-tabs-container">                  
    <div>Lorem ipsum dolor sit amet…</div>
    <div>Integer laoreet placerat suscipit…</div>
    <div>Nam porta cursus lectus…</div>
  </div>
</div>
```

然后，在 DOM 底部（在 `</body>` 结束标签之前），我们需要包含 `jquery` 和 `easyResponsiveTabs` 库。然后，我们将通过提供容器元素的 ID 来执行脚本：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/easyResponsiveTabs.js"></script>
<script>
$(document).ready(function () {
  $('#mytab').easyResponsiveTabs({
    type: 'default', //Types: default, vertical, accordion
    width: 'auto',
    fit: true,
    closed: 'accordion',
    activate: function(event) {
      // Callback function if tab is switched if need
    }
  });
});
</script>
```

当在智能手机和屏幕尺寸大于 768 像素时，此插件的可视结果如下：

![了解 EasyResponsiveTabstoAccordion](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_11_06.jpg)

当执行脚本时，会有一些可选参数需要提供，例如：

+   `type: 'default'`：可以设置为 `default`、`vertical`、`accordion`

+   `width: 'auto'`：可以设置为 `auto` 或任何自定义宽度

+   `fit: true`：它有助于将整个内容适配到容器中

+   `closed: false`：它在启动时关闭面板

+   `activate: function(){}`：这是一个回调函数，用于包含一些在选项卡更改时触发的自定义代码

## 使用 FlexNav 为您的菜单增加灵活性

FlexNav 是一个 jQuery 插件，可以简化复杂且响应式的导航菜单的创建，而无需编写大量代码。它采用了首先适配移动端的方法，只需轻触目标即可在触摸屏上显示子菜单。

除了以设备无关的方式控制这些嵌套子项之外，该插件还改进了通过键盘 tab 支持导航的可访问性，并为旧浏览器提供了回退。

有关其实现，您将在 [`github.com/indyplanets/flexnav`](https://github.com/indyplanets/flexnav) 中找到可下载的文件。从标准 HTML 文档开始，需要在包含 CSS 文件的 `<head>` 标签中添加此代码：

```js
<link href="css/flexnav.css" rel="stylesheet" type="text/css" />
```

现在，我们将在简单的无序列表中包含以下 HTML 代码，添加类和数据属性：

```js
<ul class="flexnav" data-breakpoint="800">
  <li><a href="#">Item 1</a></li>
  <li><a href="#">Item 2</a>
    <ul>
      <li><a href="#">Sub 1 Item 1</a></li>
      <li><a href="#">Sub 1 Item 2</a></li>
    </ul>
  </li>
  <li><a href="#">Item 3</a>
    <ul>
      <li><a href="#">Sub 1 Item 1</a></li>
      <li><a href="#">Sub 1 Item 2</a></li>
      <li><a href="#">Sub 1 Item 3</a></li>
    </ul>
  </li>
</ul>
<div class="menu-button">Menu</div>
```

然后，在 DOM 底部（`</body>` 结束标记之前），我们将包含 jQuery 和 FlexNav 库。之后，我们将通过通知要转换为响应式的菜单元素的 ID 或类来执行脚本。

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.flexnav.min.js"></script>
<script>
$(".flexnav").flexNav();
</script>
```

这是在智能手机和平板电脑上查看时该插件可能提供的视觉示例：

![使用 FlexNav 为您的菜单增加灵活性](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_11_07.jpg)

当我们执行脚本时，也可以向插件提供一些选项，例如：

+   `'animationSpeed':'250'`: 这设置了接受 fast/slow 的动画速度

+   `'transitionOpacity': true`: 这指定了默认的不透明度动画

+   `'buttonSelector': '.menu-button'`: 这指定了默认菜单按钮类

+   `'hoverIntent': false`: 仅用于 hoverIntent 插件

+   `'hoverIntentTimeout': 150`: 仅用于 hoverIntent 插件

例如：

```js
<script>
$(".flexnav").flexNav({
  'buttonSelector': '.exclusive-button'
});
</script>
```

# 杂项

我们将看到的以下插件没有特定的类别。它们是 SVGeezy、Prefix free、Magnific Popup、Riloadr 和 Calendario。

## SVGeezy

SVGeezy 是一个 JavaScript 插件，用于处理 IE8 及更早版本以及 Android 2.3 及更早版本等浏览器的 SVG 图像。它的工作非常简单，因为它只会在我们的网站上检测到 SVG 图像，并自动搜索另一种图像（例如 PNG 格式）作为其回退。

回退图像必须具有相同的文件名。更改仅涉及文件格式。此格式可以在初始化脚本时指定。

如果您需要为这些旧浏览器提供支持，我们将看看如何做。首先，让我们访问并从 [`github.com/benhowdle89/svgeezy`](https://github.com/benhowdle89/svgeezy) 下载解决方案。

然后，创建一个新的标准 HTML 文档，并在 `<img>` 标签内添加 SVG 图像，如下所示：

```js
<img src="img/mylogo.svg" />
```

稍后，在 DOM 底部（`</body>` 结束标记之前），我们将包含 jQuery 和 SVGeezy 库。然后，我们将通过提供两个参数来执行插件：

+   第一个定义了一个类名，如果我们没有 SVG 回退图像或者根本不想为该特定图像提供回退，我们可以使用该类名。

+   第二个意味着如果浏览器不支持显示 SVG 图像，则会提供图像的扩展名。PNG 扩展名是最常见的。

```js
<script src="img/svgeezy.js"></script>
<script>
svgeezy.init('nocheck', 'png');
</script>
```

### 注意

我们还可以将 `nocheck` 改为 `false`，让插件检查所有图片。

## Prefix free

Prefix free 为我们提供了只使用无前缀的 CSS 属性的便利；插件会在必要时为 CSS 代码添加当前浏览器的前缀，从而使前缀代码独立存在。这样，我们就不需要再记住哪些属性需要前缀了，而且可能还可以避免以后重构代码，只是为了去掉或添加新的前缀。

### 注意

这个插件不一定具有响应性，但是由于它的目标是让现代浏览器更易访问，所以要防止使用旧的前缀，并在需要时不要忘记使用它们。

开始使用它并不难。首先，让我们从 [`github.com/LeaVerou/prefixfree`](https://github.com/LeaVerou/prefixfree) 下载它。

对于这个例子，让我们重新使用一些你已经有的 HTML，并在 DOM 的 `<head>` 标签中包含 `prefixfree.js`：

```js
<script src="img/prefixfree.js"></script>
```

### 提示

这个插件建议将其包含在头部，以减少出现的闪烁效果（也称为 FOUC 效果）。

这是之前和之后的比较，我们可以注意到我们节省了多少行代码。

这就是我们通常编写代码的方式：

```js
#element {
  margin: 0;
  -webkit-box-shadow: 1px 2px 3px #999;
  box-shadow: 1px 2px 3px #999;
  border-radius: 10px;

  -webkit-transition: all 1s;
  -moz-transition: all 1s;
  -o-transition: all 1s;
  -ms-transition: all 1s;
  transition: all 1s;

  background: -webkit-linear-gradient(to top, orange 50%, #eee 70%);
  background: -moz-linear-gradient(to top, orange 50%, #eee 70%);
  background: -o-linear-gradient(to top, orange 50%, #eee 70%);
  background: -ms-linear-gradient(to top, orange 50%, #eee 70%);
  background: linear-gradient(to top, orange 50%, #eee 70%);
}
```

这个也显示了，当使用 Prefix free 时，我们如何编写相同跨浏览器的代码：

```js
#element {
  margin: 0;
  box-shadow: 1px 2px 3px #999;
  border-radius: 10px;
  transition: all 1s;
  background: linear-gradient(to top, orange 50%, #eee 70%);
}
```

我们节省了很多行代码。难以置信，不是吗？在你的文档上试试，看看有哪些好处。

## Magnific Popup

Magnific Popup 是一个用于创建可响应的弹出窗口的 jQuery 插件，可以有多种用途，比如：

+   在叠加窗口中显示单个图像/图片库

+   带视频或地图的弹出窗口

+   模态弹出窗口

+   具有 CSS 动画的对话框

它专注于性能，并为任何设备的用户提供最佳体验。关于 Internet Explorer 浏览器，Magnific Popups 与版本 8 及更早期兼容。它通过提供一个轻量且模块化的解决方案来实现这一点，可以从 [`dimsemenov.com/plugins/magnific-popup/`](http://dimsemenov.com/plugins/magnific-popup/) 下载，并点击 **构建工具** 链接。

使用 CSS3 过渡而不是 JavaScript 动画显著改善了动画的性能。此外，这个插件有一种可扩展的微模板引擎，可以重用现有的元素，从而在使用相同模式的弹出窗口时加快弹出窗口的加载速度（例如图片库）。

让我们通过实践尝试这个例子。首先，我们将创建一个新的标准 HTML 文档。下载解决方案后，让我们将 CSS 文件添加到 `<head>` 标签中。这个文件不是它的工作所需，但里面有一些有用的样式，负责良好效果：

```js
<link rel="stylesheet" href="css/magnific-popup.css">
```

现在，我们将在代码中添加这两个链接，显示一个简单的图片弹出窗口和一个视频弹出窗口。

```js
<p><a class="image-link" href="image-sample.jpg">Open popup</a></p>
<p><a class="popup-youtube" href="http://www.youtube.com/watch?v=0O2aH4XLbto">Open video</a></p>
```

然后，在 DOM 的底部（在`</body>`关闭标签之前），我们需要包含`jquery`和`magnificPopup`库。之后，我们将执行脚本两次，并为每个目的通知类（我们先前指定了一个链接）：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.magnific-popup.min.js"></script>
<script>
$(document).ready(function() {
  $('.image-link').magnificPopup({type:'image'});
  $('.popup-youtube').magnificPopup({
    type: 'iframe',
    mainClass: 'mfp-fade'
  });
});
</script>
```

下面是在智能手机和平板电脑上查看的简单图像弹出实现的可视化：

![Magnific Popup](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_11_08.jpg)

在插件文档中可以详细了解到许多使用类型，位于[`dimsemenov.com/plugins/magnific-popup/documentation.html`](http://dimsemenov.com/plugins/magnific-popup/documentation.html)。

## Riloadr

Riloadr 是一个响应式图像加载器插件。在本节中，我们将看到它与 jQuery 一起使用的工作方式，尽管这并不是必需的，因为它与框架无关。

该插件是在响应式布局中传送上下文图像的替代解决方案，该布局在不同分辨率下使用不同大小的图像以改善页面加载时间和用户体验。

Riloadr 在图像标记元素中使用`data-src`和`data-base`属性，而不是常见的`src`属性。因此，这样我们就能在浏览器渲染网站之前处理图像元素并选择最佳图像进行显示。

有一些突出的特点使其与其他竞争对手区分开来，例如：

+   对图像加载过程的绝对控制

+   可以使用 CSS 属性（例如，`minWidth`，`maxWidth`和`minDevicePixelRatio`）设置无限断点

+   Riloadr 不会为相同的图像发出多个请求

+   您可以创建不同的 Riloadr 对象（命名组），并根据需要对每个对象进行配置

+   带宽测试，只有设备具有足够快的连接才能下载高分辨率图像

从[`github.com/tubalmartin/riloadr`](https://github.com/tubalmartin/riloadr)下载后，该插件的建议是将 CSS 和 JavaScript 文件放在`<head>`标签内：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/riloadr.jquery.min.js"></script>
```

一旦加载了 Riloadr，我们可以设置其图像组：

```js
<script>
var group1 = new Riloadr({
  breakpoints: [
    {name: '320', maxWidth: 320},
    {name: '640', maxWidth: 320, minDevicePixelRatio: 2},
    {name: '640', minWidth: 321, maxWidth: 640},
    {name: '1024', minWidth: 641}
  ]
});
</script>
```

### 注意

`minDevicePixelRatio`的配置与支持高 DPI 图像的设备有关，并加载用于 640 像素的图像（尺寸是正常尺寸的两倍）。

现在，我们只需在 HTML 代码中添加这个`<img>`标签，使用`data-src`和`data-base`。

注意，在`data-base`上，我们将使用`{breakpoint-name}`作为 Riloadr 捕获的动态值，并在先前定义的断点上标识该值。这个名称可以用作按尺寸存储图像的地方，而不会搞乱：

```js
<div>
  <img class="responsive" data-base="images/{breakpoint-name}/" data-src="img/image-name.jpg">
  <noscript>
    <img src="img/image-name.jpg">
  </noscript>
</div>
```

渲染上述代码时，浏览器将检测屏幕大小并选择正确的断点以适合其尺寸。然后，它将被我们之前定义的变量名称的内容替换，本例中为 320。如果浏览器识别到变量名称的内容是 640，则会发生同样的事情，这更适合。

### 注意

如果浏览器不支持 JavaScript 或发生了错误，`<noscript>` 标记将显示我们定义的图像。

以下截图显示了 Riloadr 的效果，仅在浏览器需要时加载具有不同尺寸的图像（取决于分辨率为 320 和 640 像素的断点）：

![Riloadr](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_11_09.jpg)

## Calendario

Calendario 是一个 jQuery 响应式插件，旨在提供适合改善用户与日历交互的布局，保持日历结构流动，以便轻松适应不同的屏幕。

在大屏幕上，它显示基于网格的布局，而在较小的屏幕上，它将其转换为垂直的月份天数堆叠，大大简化了其可视化。

### 注意

这个解决方案目前不适用于所有浏览器，因为其中一些浏览器不支持新的 CSS 属性，比如 `calc()`。这些浏览器包括 Internet Explorer 8、Opera Mini 和 Android 浏览器。

Calendario 可在 [`github.com/codrops/Calendario`](https://github.com/codrops/Calendario) 获得。

让我们首先添加插件中包含的 CSS 文件：

```js
<link rel="stylesheet" type="text/css" href="css/calendar.css" />
<link rel="stylesheet" type="text/css" href="css/custom_1.css" />
```

现在，我们将包含这个结构化的 HTML，稍后添加类和 ID 以供 JavaScript 处理：

```js
<div class="custom-calendar-wrap custom-calendar-full">
  <div class="custom-header clearfix">
    <h2>Calendario</h2>
    <div class="custom-month-year">
      <span id="custom-month" class="custom-month"></span>
      <span id="custom-year" class="custom-year"></span>
      <nav>
        <span id="custom-prev" class="custom-prev"></span>
        <span id="custom-next" class="custom-next"></span>
      </nav>
    </div>
  </div>
  <div id="calendar" class="fc-calendar-container"></div>
</div>
```

然后，在 DOM 的底部（在 `</body>` 结束标记之前），我们将需要包含 jQuery 和 Calendario 库。然后，我们将通过设置容器 ID 来初始化脚本，并创建两个有用的函数，用于通过日历进行月份导航：

```js
<script src="img/jquery-1.9.1.min.js"></script>
<script src="img/jquery.calendario.js"></script>
<script> 
$(function() {
  var cal = $('#calendar').calendario(),
    $month = $('#custom-month').html(cal.getMonthName()),
    $year = $('#custom-year').html(cal.getYear());

  $('#custom-next').on('click', function() {
    cal.gotoNextMonth( updateMonthYear );
  });
  $('#custom-prev').on('click', function() {
    cal.gotoPreviousMonth(updateMonthYear);
  } );

  function updateMonthYear() {        
    $month.html(cal.getMonthName());
    $year.html(cal.getYear());
  }
});
</script>
```

以下是在智能手机/平板电脑和桌面上查看此日历的屏幕截图：

![Calendario](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_11_11.jpg)

以及它在桌面上的显示方式：

![Calendario](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_11_10.jpg)

# 总结

在本章中，我们学习了三个类别的补充插件，这些插件补充了前几章的内容。对于结构插件，我们学习了如何使用 Columns 来创建简单的响应式结构，使用 Equalize 更好地分配页面上浮动元素的位置，以及使用 Packery 来创建卡片布局网站。我们还学习了使用 Sidr、EasyResponsiveTabstoAccordion 和 FlexNav 来显示菜单和选项卡的不同方法。在 *杂项* 部分，我们看到了如何使用 SVGeezy、Prefix free、MagnificPopup 插件、Riloadr 和 Calendario。

在最后一章中，我们将看到不同的技术来检测网站加载速度。性能主题非常广泛，但由于有效处理这一指标非常重要，因此在创建响应式网站时，我们将看到一些提高性能的技术。


# 第十二章：提高网站性能

加载时间是导致用户放弃页面的主要因素。如果页面加载时间超过 3-4 秒，用户会转到其他地方。

对于移动设备上的页面，需要快速加载的需求更加迫切，因为用户觉得页面加载时间比桌面设备上更长，这也是当前大多数网站（根据 KISSmetrics 的文章 *加载时间* 数据显示为 73%）的情况。

加载时间的一大部分被花在执行客户端处理和加载资源，如样式表、脚本文件和图像上。

在本章中，我们将学习通过以下方式改进响应式网站的性能:

+   使用内容交付网络

+   减少 HTTP 请求

+   缩小有效负荷的大小

+   优化客户端处理

+   使用工具检查网站性能

# 使用内容交付网络

**内容交付网络**（**CDN**）是分布在多个位置的一组网络服务器，从用户的角度来看，可以加快页面加载速度。

用于向特定用户传递内容的服务器通常是基于网络接近性的，并且此内容传递是以最快的响应时间完成的。此外，它会将内容缓存到浏览器中，以便下次不必再次检索，从而节省向服务器发出请求。

使用 CDN 服务提供商是一种具有成本效益的方法，一些已知的服务提供商包括 Akamai Technologies、Mirror Image Internet 和 Limelight Networks。

# 减少 HTTP 请求

减少页面包含的组件数量，从而减少加载网站所需的 HTTP 请求数量，这不仅与每个文件的 KB 数量有关。还有一个问题是每个 HTTP 连接在将文件返回给浏览器之前，服务器处理每个请求所消耗的短时间。

我们将看到一些减少请求数量的技术:

+   使用条件加载器

+   将多个脚本合并成一个脚本

+   将多个 CSS 文件合并成一个样式表

+   使用 CSS 精灵

## 使用条件加载器

条件加载器，如 RequireJS 或 yepnope.js，在本书之前我们已经谈到过，它们只会加载所需的代码。

## 合并和缩小资源（JavaScript 和 CSS）

理想的结果是在生产中整个网站将只有一个 CSS 文件和一个 JavaScript 文件。

解决这个问题的方法是将一堆 JavaScript 文件**合并**成一个，减少请求并加快页面首次加载速度，尽管在移动设备上可能无法有效缓存。

**缩小**是消除不必要字符的最佳做法，如额外空格、换行符、缩进和注释。根据我的个人测试，这种改进可以平均减少文件大小 20%。

### 提示

这个值并不准确，因为它取决于文件的大小、白色空间的数量等。

这种组合可以很好地提高性能，主要是因为它通常在网站显示内容之前执行。

有几个在线工具可以执行这项任务。我个人最喜欢的是 YUI 压缩器，你可以通过访问 [`refresh-sf.com/yui/`](http://refresh-sf.com/yui/) 和 Google Minify（[`code.google.com/p/minify/`](https://code.google.com/p/minify/)）来执行。

使用 YUI 压缩器的步骤非常简单。你只需要选择将要合并和压缩的文件，然后点击**压缩**按钮即可。

## CSS 精灵

正如我们所知，使用 CSS 精灵是图像合并的一种做法，因为它涉及将主题图像合并到一个图像中。通过合并（背景）图像，我们可以减少图像文件的总体大小，从而减少向服务器发出的 HTTP 请求数量。

### 提示

如果你使用 Photoshop 来创建图像精灵，一旦你创建了这些精灵，请保存 PSD 源文件以便进行进一步的更改。稍后，如果你想要在这个图像精灵中包含新的图标，可以在此图像的空白区域展开并/或右键单击。

以下是 Google 图像精灵的示例：

![CSS 精灵](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_12_01.jpg)

有两个在线工具我认为最好用来创建精灵图像：Stitches ([`draeton.github.io/stitches/`](http://draeton.github.io/stitches/)) 和 SpriteCow ([`www.spritecow.com/`](http://www.spritecow.com/))。

### 如何使用 SpriteCow 创建精灵

这个工具会生成你需要放在 CSS 文件中的初始 CSS 代码。

首先，你需要创建带有所有按钮和图标的图像（正如我们在前面的图像中看到的）。然后，在 [`www.spritecow.com/`](http://www.spritecow.com/)，有一个名为**打开图像**的按钮，将上传这个精灵。

然后点击**选择精灵**工具，并用它包围你想要自定义的图标的正方形进行选择。如果你的选择不太接近图标，不要担心，因为有一个自动调整可以改善这个选择。试试吧！

# 减小负载大小

在去除额外的 HTTP 请求之后，现在是尽可能减少剩余文件大小的时候了。这不仅可以加快页面加载速度，还有助于节省带宽消耗。

减少动态和静态资源的负载大小可以显著减少网络延迟。

我们将看看一些实现这一目标的做法，比如渐进式 JPEG、自适应图像、图像优化，以及更好地使用 HTML5 和 CSS3。

## 渐进式 JPEG

渐进式 JPEG 并不新鲜。它曾被认为是最佳实践之一。然而，随着互联网速度的提高，这个功能一度变得不明显。但是，现在，在移动设备上带宽有限的情况下，这个做法又浮出水面了。

将普通 JPEG 图像保存为基线和使用渐进选项之间的区别在以下截图中表示：

![渐进式 JPEG](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_12_02.jpg)

就尺寸而言，与普通 JPEG 图像相比，中等图像的渐进式尺寸大约增加了 10%。加载时间几乎相同或稍微增加了一些毫秒。

但是，与自适应图像相比，渐进式 JPEG 的预览效果使访问者感觉页面加载更快。

在移动设备上，加载不必要的高分辨率图像是对带宽、处理时间和缓存空间的巨大浪费。为了加快页面呈现速度并减少带宽和内存消耗，应该用较小版本的图像替换图像。

然而，正如我们在第五章中所学到的那样，*准备图像和视频*，强烈建议使用诸如 Foresight 或 Picturefill 等解决方案，因为它们首先检查请求设备是什么，然后允许浏览器下载任何图像。

## 图像优化

图像通常包含一定量的无用数据，这些数据在保持质量的同时也可以安全地移除。图像优化有两种方法：无损和有损压缩。

无损压缩可能会删除额外信息，例如嵌入的缩略图、数据中的注释、关于照片的元数据、相机型号、ISO 速度、闪光灯是否打开或关闭、镜头类型和焦距，可能会节省 5 到 20% 的文件大小。

优化图像的过程非常简单，因为它只需要选择哪些图像需要更改。

有很多在线工具可用于实现这一点。就我个人而言，我更喜欢使用离线工具来移除这些信息，因为它在图像的法律权利上提供了更多的安全性。

对于 PNG 图像，我推荐使用 PngGauntlet ([`pnggauntlet.com`](http://pnggauntlet.com))；对于 Mac，使用 Imageoptim ([`imageoptim.com`](http://imageoptim.com))。

Imageoptim 也适用于 JPEG，但对于 Windows，我们可以使用 RIOT ([`luci.criosweb.ro/riot/`](http://luci.criosweb.ro/riot/)) 来优化 JPEG 图像，这几乎和 Imageoptim 一样好。然而，如果图像看起来太大，比如高分辨率图片，最好的选择是 JPEGmini 工具 ([`www.jpegmini.com/`](http://www.jpegmini.com/))。

## 使用 HTML5 和 CSS3 简化页面

HTML5 规范包括新的结构元素，如`header`、`nav`、`article`和`footer`。使用这些语义元素比使用通用的嵌套`div`和`span`标签得到更简单和更高效的解析页面。

当使用 CSS3 功能时，几乎会出现与使用图像相同的情况，这些功能可以帮助创建轻量级页面，为视觉元素提供动态艺术支持，例如渐变、圆角边框、阴影、动画和转换。我们知道，在 CSS3 之前，每个提到的效果都需要一个代表该效果的图像，并且需要加载许多图像。考虑以下示例：

![使用 HTML5 和 CSS3 简化页面](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_12_08.jpg)

# 测试网站性能

我们将看到两个专注于分析网页并提出改进性能建议的浏览器工具，PageSpeed Insights 和 YSlow，基于一套极其专业且在不断发展的高性能网页规则。

此外，还有两个我推荐使用的在线工具，可以运行简单测试或进行高级测试，包括多步事务、视频捕获、内容阻止等功能——WebPageTest 和 Mobitest。

### 提示

测试网站性能是维护快速站点的关键；尽管这超出了本书的范围，但如果您想进一步探索这一问题，可以参考*Sanjeev Jaiswal*的*Instant PageSpeed Optimization*和*Steve Sounders*的*Even Faster Web Sites*，了解更多信息。

## PageSpeed Insights

PageSpeed Insights 是由谷歌开发的在线工具，旨在帮助开发人员优化网站性能。它评估页面对多种不同规则的符合性，这些规则涵盖了前端最佳实践。

PageSpeed Insights 提供了描述如何最佳实施规则并将其纳入开发流程的提示和建议。

您可以尝试访问[`developers.google.com/speed/pagespeed/insights/`](http://developers.google.com/speed/pagespeed/insights/)网站，自行使用此工具。

您可以在以下截图中注意到，每个显示的通知都有一个摘要内容，并且可以展开以获取更多详细信息和进一步的链接：

![PageSpeed Insights](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_12_03.jpg)

## YSlow

YSlow 是由 Yahoo!开发的浏览器插件，也专注于分析网页并提出改进性能的建议。它的一些特性如下：

+   根据预定义规则集或用户定义的规则集对网页进行评分

+   建议如何提高页面的性能并详细解释原因

+   总结页面的组件，便于更快地搜索关键问题

+   显示页面的整体统计信息

+   提供性能分析工具，包括 Smush.it™（用于图像优化的在线工具）和 JSLint（查找脚本中常见错误的代码检查器）

这个插件的网站可以从[`developer.yahoo.com/yslow/`](http://developer.yahoo.com/yslow/)访问，显示了每个最佳实践规则的默认权重的表格，这样我们就可以在其他问题之前优先处理关键问题([`yslow.org/faq/#faq_grading`](http://yslow.org/faq/#faq_grading))。

让我们看一下它的界面以及每个规则是如何描述的。通常，在开始修复之前，关于规则的简要解释（如下面的截图所示）就足够了：

![YSlow](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_12_04.jpg)

## WebPagetest

WebPagetest 是一个最初由 AOL 开发的工具，现在由 Google 支持。我们可以通过访问[`www.webpagetest.org/`](http://www.webpagetest.org/)来使用它，并进行简单测试或执行高级测试，包括多步事务、视频捕获和内容阻止。

丰富的诊断信息包括资源加载的瀑布图、页面速度优化检查，并提供改进建议，这些建议可能在我们输入网站 URL 后实现。然后我们将通知我们想要测试的站点，我们想要测试的语言环境，以及我们想要使用的浏览器。以下是 WebPagetest 的测试结果截图：

![WebPagetest](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_12_05.jpg)

## Mobitest

Mobitest 是一个很棒的工具，模拟了真实的移动设备加载网站，捕获页面大小、总加载时间和其他与性能相关的统计数据。虽然它是一个很好的检查工具，但它不能替代您从带宽有限的手机连接获得的真实统计数据。

访问[`mobitest.akamai.com/`](http://mobitest.akamai.com/)后，运行性能测试只需一个步骤，即输入网站 URL，选择设备/位置选项并提交。

有时候完成报告需要很长时间，所以这个工具取决于队列中排在我们前面的测试数量。

以下是一个生成的报告示例：

![Mobitest](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_12_06.jpg)

尽管这个站点很轻量，但仍然有可以实施的改进。让我们看看加载活动过程的生成图表，即瀑布图示例：

![Mobitest](https://github.com/OpenDocCN/freelearn-jquery-zh/raw/master/docs/rsps-web-dsn-jq/img/3602OS_12_07.jpg)

Mobitest 提供的瀑布图（水平条形图）演示了每个资源逐步请求、服务器处理和返回的过程。

因此，在第二行中，加载在另一个网站托管的静态图像需要很长时间，可以通过添加`expires`头部和使用 CDN 来改进。

# 摘要

在本章中，我们学习了一些最佳实践，比如使用 CDN 来改善内容传递和缓存静态图片，通过条件加载、文件合并、CSS 精灵减少 HTTP 请求，通过优化图片来减小载荷大小，将 JPEG 图像保存为渐进式，并且使用 HTML5 和 CSS3 简化页面结构。此外，我们还学习了如何使用 PageSpeed，YSlow，WebpageTest 和 Mobitest 等工具进行性能测试。
