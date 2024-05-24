# 使用 HTML5 和 JavaScript 开发 Windows 商店应用（一）

> 原文：[`zh.annas-archive.org/md5/8F13EC8AC7BDB8535E7218C5DDB48475`](https://zh.annas-archive.org/md5/8F13EC8AC7BDB8535E7218C5DDB48475)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 序言

*使用 HTML5 和 JavaScript 开发 Windows Store 应用* 是一本实践性强的指南，涵盖了 Windows Store 应用的基本重要特性以及示例代码，向您展示如何开发这些特性，同时学习 HTML5 和 CSS3 中的新特性，使您能够充分利用您的网页开发技能。

# 本书内容覆盖范围

第一章, *HTML5 结构*, 介绍了新 HTML5 规范中的语义元素、媒体元素、表单元素和自定义数据属性。

第二章, *使用 CSS3 进行样式设计*, 介绍了 CSS3 在开发使用 JavaScript 的 Windows Store 应用时会频繁用到的增强和特性。本章涵盖了以下主题：CSS3 选择器、网格和弹性盒布局、动画和转换、以及媒体查询。

第三章, *Windows 应用的 JavaScript*, 介绍了 JavaScript 的 Windows 库及其特性，并突出显示了用于开发应用的命名空间和控件。

第四章, *使用 JavaScript 开发应用*, 介绍了开始使用 JavaScript 开发 Windows 8 应用所需的工具和提供的模板。

第五章, *将数据绑定到应用*, 描述了如何在应用中实现数据绑定。

第六章, *使应用响应式*, 描述了如何使应用响应式，以便它能处理不同屏幕尺寸和视图状态的变化，并响应缩放。

第七章, *使用磁贴和通知使应用活跃*, 描述了应用磁贴和通知的概念，以及如何为应用创建一个简单的通知。

第八章, *用户登录*, 描述了 Live Connect API 以及如何将应用与该 API 集成以实现用户认证、登录和检索用户资料信息。

第九章, *添加菜单和命令*, 描述了应用栏、它如何工作以及它在应用中的位置。此外，我们还将学习如何声明应用栏并向其添加控件。

第十章, *打包和发布*, 介绍了我们将如何了解商店并学习如何使应用经历所有阶段最终完成发布。同时，我们还将了解如何在 Visual Studio 中与商店进行交互。

第十一章，*使用 XAML 开发应用*，描述了其他可供开发者使用的平台和编程语言。我们还将涵盖使用 XAML/C#创建应用程序的基本知识。

# 本书需要你具备的知识

为了实施本书中将要学习的内容并开始开发 Windows Store 应用，你首先需要 Windows 8。此外，你还需要以下开发工具和工具包：

+   微软 Visual Studio Express 2012 用于 Windows 8 是构建 Windows 应用的工具。它包括 Windows 8 SDK、Visual Studio 的 Blend 和项目模板。

+   Windows App Certification Kit

+   Live SDK

# 本书适合谁

这本书适合所有想开始为 Windows 8 创建应用的开发者。此外，它针对想介绍 standards-based web technology with HTML5 和 CSS3 的进步的开发者。另外，这本书针对想利用他们在 Web 开发中的现有技能和代码资产，并将其转向为 Windows Store 构建 JavaScript 应用的 Web 开发者。简而言之，这本书适合所有想学习 Windows Store 应用开发基础的人。

# 约定

在这本书中，你会发现有几种不同信息类型的文本样式。以下是这些样式的一些示例及其含义的解释。

文本中的代码词汇如下所示：“`createGrouped`方法在列表上创建一个分组投影，并接受三个函数参数。”

代码块如下所示：

```js
// Get the group key that an item belongs to.
  function getGroupKey(dataItem) {
  return dataItem.name.toUpperCase().charAt(0);   
}

// Get a title for a group
  function getGroupData(dataItem) {
  return {
    title: dataItem.name.toUpperCase().charAt(0);
  }; 
}
```

**新术语**和**重要词汇**以粗体显示。例如，你在屏幕上看到的、菜单或对话框中的单词，会在文本中以这种方式出现：“你将能够为应用程序 UI 设置选项；这些选项之一是支持的旋转。”

### 注意

警告或重要说明以这种方式出现在盒子里。

### 技巧

技巧和小窍门像这样出现。

# 读者反馈

读者对我们的书籍的反馈总是受欢迎的。告诉我们你对这本书的看法——你喜欢或可能不喜欢的地方。读者反馈对我们开发您真正能从中获得最大收益的标题非常重要。

要发送给我们一般性反馈，只需发送电子邮件到`<feedback@packtpub.com>`，并在消息主题中提及书籍标题。

如果你在某个主题上有专业知识，并且你对编写或贡献书籍感兴趣，请查看我们网站上的作者指南：[www.packtpub.com/authors](http://www.packtpub.com/authors)。

# 客户支持

既然你已经成为 Packt 书籍的骄傲拥有者，我们有很多东西可以帮助你充分利用你的购买。

## 勘误

尽管我们已经竭尽全力确保内容的准确性，但错误仍然可能发生。如果您在我们的书中发现任何错误——可能是文本或代码中的错误——我们非常感谢您能向我们报告。这样做可以避免其他读者感到沮丧，并帮助我们改进本书的后续版本。如果您发现任何错误，请访问[`www.packtpub.com/submit-errata`](http://www.packtpub.com/submit-errata)，选择您的书籍，点击**错误提交表单**链接，并输入您的错误详情。一旦您的错误得到验证，您的提交将被接受，并且错误将被上传到我们的网站或添加到该标题下的错误列表中。您可以通过[`www.packtpub.com/support`](http://www.packtpub.com/support)选择您的标题查看现有的错误。

## 版权侵犯

互联网上版权材料的侵犯是一个持续存在的问题，涵盖所有媒体。在 Packt，我们非常重视版权和许可的保护。如果您在互联网上以任何形式发现我们作品的非法副本，请立即提供位置地址或网站名称，以便我们可以寻求解决方案。

如果您发现任何可疑的版权侵犯材料，请通过`<copyright@packtpub.com>`联系我们并提供链接。

我们非常感谢您在保护我们的作者和我们提供有价值内容的能力方面所提供的帮助。

## 问题反馈

如果您在阅读本书的过程中遇到任何问题，可以通过`<questions@packtpub.com>`联系我们，我们会尽最大努力为您解决问题。


# 第一章： HTML5 结构

HTML5 引入了新的元素和属性，以更整洁的结构、更智能的表单和更丰富的媒体，这使得开发者的生活变得更加容易。HTML5 功能根据其功能分为几个组，新的结构元素属于语义组，包括结构元素、媒体元素、属性、表单类型、链接关系类型、国际化语义和附加语义的微数据。HTML5 有很多增加和增强的内容，所有这些都是为了更好地在网络上呈现内容。当你开发 Windows 8 应用时，你会使用其中许多功能；使用 Windows 8 开发的区别在于，至少在 Windows Store 应用层面，你不必担心浏览器的兼容性，因为 Windows 8 是一个使用最新网络标准的 HTML5 平台。你所使用的 HTML5 和 CSS3 的一切都为你代码中提供，并保证在应用程序中工作。最新版本的 Visual Studio（VS 2012）包括一个新 HTML 和 CSS 编辑器，提供对 HTML5 和 CSS3 元素和片段的全面支持。

在本章中，我们将涵盖以下主题：

+   语义元素

+   媒体元素

+   表单元素

+   自定义数据属性

# 理解语义元素

HTML5 标记语义比其前辈更强，这要归功于描述页面内容结构的新语义元素。语义元素的列表包括以下内容：

+   `<header>`标签定义了文档或节的头部。它在页面或节中包裹标题或一组标题，并且它还可以包含诸如徽标、横幅和主要导航链接等信息。在页面中你可以有多个`<header>`标签。

+   `<nav>`标签代表主要的导航链接。通常它绑定在头部。

+   `<section>`标签包裹可以按主题组合的相关内容。一个`<section>`标签可以包括一个`<header>`和`<footer>`标签。

+   `<footer>`标签代表关于页面或节的内容，例如，相关链接、隐私条款和版权信息。在页面中你可以有多个`<footer>`，它与`<header>`标签相同。

+   `<article>`标签代表可以独立于整个文档使用的独立内容，例如，一篇博客文章。`<article>`和`<section>`非常相似，因为两者都是独立的标签并包含相关内容；然而，如果它的内容可以通过原子或 RSS 提要进行联合（syndication），那么`<article>`元素更为合适。

+   `<aside>`标签代表与页面内容相关但分离的部分，因为它可以被移除而不会影响页面的主要内容。典型的用法是侧边栏。

+   `<address>`标签代表最近的`<article>`父元素的联系信息，如果存在的话，或者适用于整个文档的父`<body>`元素。

将这些新元素全部放在一个页面中会产生以下的标记：

```js
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Developing for Windows 8</title>
</head>
<body>
  <header>
    <a href="default.html">
      <h1>The Courses</h1>
      <img src="img/logo.png" alt="Book Logo">
    </a>
    <nav>
      <ul>
        <li><a href="home.html">Home</a></li>
        <li><a href="about.html">About</a></li>
      </ul>
    </nav>
  </header>
  <section>
    <article>
      <h2></h2>
      <p></p>
      <address>
        Written by <a href="mailto:xyz@abc.com">Demo Author</a>.<br>
        Found at: Demo.com <br>
        Address, Street<br>
        UK
      </address>
    </article>
    <article>
      <h2></h2>
      <p>content</p>
    </article>
  </section>
  <aside>
    <h2></h2>
    <ul>
      <li></li>
      <li></li>
      <li></li>
    </ul>
    <p></p>
  </aside>
  <footer>
    <p></p>
    <p>Copyright &copy; 2013 Packt</p>
  </footer>
</body>
</html>
```

# 引入内置媒体元素

HTML5 引入了新的媒体元素，如`<audio>`和`<video>`，这些可以被认为是 HTML 早期版本中图像之后的媒体类型的新的革命。这两个元素使得在 HTML 页面/文档中嵌入媒体变得非常简单，并通过**HTML5 媒体元素 API**提供内置媒体支持。根据 W3C 最新的规范，我们可以这样定义`<video>`和`<audio>`：

+   `<video>`标签是一个媒体元素，用于播放视频或电影以及带字幕的音频文件。

+   `<audio>`标签是一个媒体元素，其媒体数据是音频，即声音或音频流。

`<audio>`和`<video>`元素分别播放音频和视频文件。它们之间的唯一区别是，`<audio>`元素没有用于视觉内容的播放区域，这与`<video>`元素相反。

在 HTML5 之前，我们需要一个插件来播放音频或视频文件，这需要编写大量的标记代码。没有 HTML5，嵌入媒体元素从未如此简单；只需放入一个`<audio>`标签，就可以得到带有播放控制的媒体播放器，仅需两行代码。它几乎与之前的`<img />`标签一样。参考以下代码：

```js
<audio src="img/audio.mp3" controls>
</audio>
```

上一个例子会在 Internet Explorer 9 (IE9)上看起来像以下的屏幕截图，并且可能因浏览器而异：

![引入内置媒体元素](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_01_01.jpg)

上面的代码展示了`<audio>`标签的最简单形式，但`<audio>`标签还有更多的属性和选项。参考以下代码：

```js
<audio controls autoplay loop>
  <p>Your browser does not support the audio element. Click <a href="content/Elsie.mp3"> here </a> to download the file instead.
  </p>
  <source src="img/audio.mp3" type="audio/mp3" />
  <source src="img/audio.ogg" type="audio/ogg" />
</audio>
```

首先，注意`<audio>`元素内的`<p>`标签中的内容。这部分内容是备用文本，只有在浏览器不支持`<audio>`标签时才会使用。它通过告知用户这个问题，为旧版网页浏览器提供一个优雅的回退方案，并且我们可以添加一个链接允许下载这个音频文件。这样，用户就不会只是站在那里想知道发生了什么。这是最简单的回退方式；你也可以用 JavaScript 达到同样的效果。

上面的代码片段还展示了一些`<audio>`元素的属性。根据 W3C 规范，`src`、`controls`、`autoplay`、`loop`、`preload`、`mediagroup`和`muted`是两个媒体元素（即`<audio>`和`<video>`）共同的属性。

+   `controls`属性在网页上显示音频的标准 HTML5 控件，控件的设计在不同浏览器代理之间可能会有所不同。

+   `autoplay`属性在 DOM 加载完成后自动播放音频文件。

+   `loop` 属性 enable 自动重复。

+   `mediagroup` 属性通过媒体控制器将多个媒体元素链接在一起。

+   `muted` 属性设置了音频文件默认静音状态。

+   `preload` 属性向用户代理提供了关于作者认为将导致最佳用户体验的提示。它的值可以是 `none`、`metadata` 或 `auto`。

    +   `none`：这个值提示浏览器，网页不期望用户需要媒体资源。

    +   `metadata`：这个值提示浏览器获取资源元数据（维度、轨道列表、持续时间等）。

    +   `auto`：这个值提示浏览器在没有任何风险的情况下优先考虑用户的需求。空值，如只是添加了 `preload` 属性，映射到 `auto` 值。

您可以像 `controls="controls"` 一样为属性指定值，这将具有相同的行为。但为了简化代码和减少代码量，您可以省略这个属性的值；同样的适用于 `loop`、`autoplay` 和 `muted`。您可以通过使用 `src` 属性或 `<source>` 元素来指定媒体资源。

### 注意

属性覆盖了元素。

媒体资源（音频或视频）有一个 MIME 类型，另外还有一个编解码器，如下代码所示：

```js
<source src="img/video.ogv" type="video/ogg; codecs="theora, vorbis" />
```

为 `type` 属性设置值必须在 `<source>` 元素内完成。如果浏览器/用户代理不支持其类型，将避免下载资源。您可以为不同的浏览器添加多种格式的音频/视频，以确保播放支持。浏览器代理将查看 `<source>` 元素；如果它无法渲染第一个类型，它将跳到下一个 `<source>` 以验证其类型，依此类推。为此，您必须检查不同浏览器中 `<audio>` 和 `<video>` 元素支持的 MIME 类型列表。浏览器不仅检查 MIME 类型，还检查指定的编解码器。所以，即使浏览器代理可以渲染资源类型，如果编解码器不受支持，视频/音频也不会加载。

以下表格列出了主要视频格式在主要浏览器中的支持情况：

| 格式 | IE9+ | Chrome | Firefox | Opera | Safari |
| --- | --- | --- | --- | --- | --- |
| WebM (VP8 编解码器) | 是 | 是 | 是 | 是 | 否 |
| MP4 (H.264 编解码器) | 是 | 是 | 否 | 否 | 是 |
| OGV (OGG THEORA 编解码器) | 否 | 是 | 是 | 是 | 否 |

从前面的表格列表中，我们可以得出结论，在您的 HTML5 视频中提供 WebM 和 MP4 格式的媒体资源将保证在所有主要浏览器的最新版本中加载。这个理论在 Visual Studio 2012 中得到了加强，它为 HTML5 标签提供了完整的 Intellisense 支持。当你插入以下 HTML5 `<video>` 元素的代码片段时，它在 `<video>` 标签内列出 3 个 `<source>` 元素：

```js
<video controls="controls">
  <source src="img/file.mp4" type="video/mp4" />
  <source src="img/file.webm" type="video/webm" />
  <source src="img/file.ogv" type="video/ogg" />
</video>
```

`<video>`元素还包括一个`poster`属性，用于指定在没有视频数据可用或直到用户点击播放按钮时在视觉内容区域显示的图像的路径。出于广告目的，你可以使用图像或视频中的帧，让用户了解视频的样子。如果你没有指定海报图像，并且`autoplay`属性没有设置，浏览器可能会显示一个填充`<video>`元素尺寸的黑色盒子。例如，以下代码显示了两个相似视频的代码示例之间的区别，第二个视频指定了海报：

```js
<video id="video" controls width="400">
  <source src="img/video.mp4" type="video/mp4" />
</video>
<video id="videoWithPoster" controls width="400" poster="http://msdn.microsoft.com/br211386.5_GetStarted_484x272px.jpg">
  <source src="img/video.mp4" type="video/mp4" />
</video>
```

这段标记输出的结果将在屏幕上产生以下内容：

![介绍内置媒体元素](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_01_02.jpg)

你可能会注意到，在之前的示例中我们对两个视频指定了`width`值为`400`。`<video>`元素接受标准的 HTML`width`和`height`属性。如果没有设置`width`和`height`的值，视觉内容区域将扩展到视频的原生尺寸。建议在`<video>`元素上设置`width`和`height`属性，从而避免扩展到全尺寸，并且按照期望的观看尺寸对视频进行编码。

### 注意

`width`和`height`属性的值不接受单位。该值表示 CSS 像素，例如，`width=400`与`width=400px`相同。

有一些 JavaScript 方法、属性和 DOM 事件是 HTML5 标准的一部分，与这些新元素相关。你可以程序化地读取和设置属性，例如`src`路径和`<video>`标签的尺寸（`width`和`height`）。你可以使用 JavaScript 方法加载音频和视频，然后播放和暂停媒体资源。你还可以编写代码来处理媒体元素触发的不同 DOM 事件，例如`onplaying`、`onprogress`（加载进度）、`onplay`和`onpause`。例如，你可以通过移除`controls`属性并从单独的按钮调用播放和暂停媒体资源的函数来禁用元素显示的默认控件。

下面的代码列表显示了如何使用 JavaScript 播放和暂停视频。我们首先需要通过调用布尔属性`.paused`来检测视频文件当前的状态，如果为真，则相应地调用`play()`或`pause()`方法：

```js
var testVideo = document.getElementById('myVideo');
if (testVideo.paused)
  testVideo.play();
else
  testVideo.pause();
```

在之前的代码中，我们声明了一个变量`testVideo`，并将其赋值给 DOM 中的`myVideo`元素。假设该元素被分配了一个 ID，你可以使用名称、标签名或元素在 DOM 层次结构中的位置来检索元素。

## 高级媒体与 JavaScript

媒体元素拥有丰富的 API，可以纯 JavaScript 进行访问。利用 JavaScript，我们可以向媒体元素添加许多功能。您可以操纵媒体资源，给它样式，旋转视频，同步播放两个或更多的媒体元素，在媒体资源加载时显示进度条，动态调整视频大小等等。

以下代码示例为 `timeupdate` 事件添加了功能，该事件获取视频的当前播放时间（以秒为单位）并在一个单独的 div 中显示它。

以下是的 HTML 代码：

```js
<div id="tInfo"></div>
<video id="myVideo" autoplay controls>
  <source src="img/w8.mp4" type="video/mp4" />
</video>
```

以下的 JavaScript 代码：

```js
var video = document.getElementsById('myVideo');
var tInfo = document.getElementById('tInfo');
video.addEventListener('timeupdate',function(event){
tInfo.innerHTML = parseInt(video.currentTime);
}, false);
```

使用 JavaScript `addEventListener` 方法提供 `timeupdate` 事件的处理程序。它接受三个参数，具有以下基本语法：

```js
WinJS.Application.addEventListener(type, listener, capture);
```

`type` 参数指定了要注册的事件类型，而 `listener` 是与事件关联的事件处理函数，第三个参数 `capture` 是一个布尔值，用于指定事件处理程序是否注册在捕获阶段。

此外，您可以将 `<video>` 元素与画布结合使用，允许您实时操作视频数据并添加各种视觉特效。

# 介绍功能丰富的表单元素

表单和 `<form>` 元素是任何应用程序或网站的重要组成部分，从登录表单到完整的联系或注册表单。在 HTML4 中，`<form>` 元素非常简单，对于任何功能或高级样式，JavaScript 都是必需的。而对于任何交互，或者数据提交和验证，都要求服务器和客户端脚本，如果浏览器中禁用了脚本，其功能就会受到限制。HTML5 通过新的属性和输入类型对 `<form>` 元素进行了重大改进，并添加了诸如基于浏览器的验证和 CSS 样式等功能，为填写表单的用户提供了更好的体验，并为创建表单的开发人员提供了所有可能的简单性。

## 一个丰富的 `<input>` 标签

`<input>` 元素引入了 `type` 属性的新值。

HTML5 在 HTML4 我们已经熟悉的 `<input>` 类型中增加了 13 个新类型，如 `text` 和 `checkbox`。添加这些类型后，`<input>` 控制现在支持如 `range`、`date`、`number`、`telephone`、`email` 和 `URL` 等类型。而这些新的 `<input>` 类型为元素本身添加了智能行为。

以下是这些类型的表格列表：

| ```<input>``` 类型 | 描述 |
| --- | --- |
| ```---``` | ```---``` |
| ```tel``` | 它期望一个电话号码。 |
| ```search``` | 它提示用户输入他们想要搜索的文本，并在支持它的浏览器上向输入元素添加一个搜索图标。 |
| ```url``` | 它期望一个 URL。 |
| ```email``` | 它期望一个电子邮件地址或由逗号分隔的电子邮件地址列表。 |
| ```datetime``` | 它期望一个带有 UTC 时区的日期和时间。 |
| ```date``` | 它期望一个日期。 |
| ` | month | ` 它期望一个带有年份和月份的日期，但没有时区。 |
| ` | week | ` 它期望由周年号和周号组成的日期。 |
| ` | time | ` 它期望时间值，如小时、分钟、秒和分数秒。 |
| ` | datetime-local | ` 它期望日期和时间没有时区。 |
| ` | number | ` 它期望数字输入。 |
| ` | range | ` 它期望数字输入，并显示一个滑块。 |
| ` | color | ` 它期望颜色值，并显示颜色调色板以供选择。 |

除了向`<input>`类型添加新特性外，还增加了对新现有特性的支持，例如文件输入元素，现在支持使用`multiple`属性进行多文件选择。当表单提交时，**浏览**按钮将显示文件对话框，然后你可以从本地磁盘或`SkyDrive`中选择文件；文件可以作为表单数据的一部分发送到服务器。

您还可以利用表示任务进度的`progress`元素，如 W3C 所指定。它可以用来显示大文件正在上传或媒体资源正在加载的进度。任务的进度由此元素的两个属性决定：

+   `value`属性，表示进度已完成多少

+   `max`属性，表示直到任务完成所需的总工作量

以下代码使用`progress`元素和一个按钮，脚本将其参数中的值添加到其现有值中。当你加载示例并尝试它时，你将看到进度条 visually updating the completion progress。

以下是的 HTML 代码：

```js
<button id="clickBtn" onclick="updateProgress(10)">Update Progress</button>Progress: <progress id="prog" max="100"></progress>
```

以下是的 JavaScript 代码：

```js
<script>
//get the progress element and add the value to it with every click var progressBar = document.getElementById('prog');
function updateProgress(newValue){ 
progressBar.value = progressBar.value + newValue;
}
</script>
```

## 简单的验证

HTML5 的新`<input>`类型以及验证属性，如`required`和`pattern`，还有伪 CSS3 选择器允许基于浏览器的验证，这样你可以在不编写一行代码或脚本的情况下捕获表单的输入错误。这在过去是不可能的，需要自定义 JavaScript 代码或 JavaScript 库。基本上，它提供了无 JavaScript 的客户端表单验证。

我们将从最简单的验证开始，即填写一个必填字段。为了实现这一点，我们需要向`<input>`元素添加`required`属性。

`required`属性可以设置在类型为`text`、`URL`、`email`、`checkbox`或`radio`的`<input>`元素上，以及`select`和`textarea`元素上。它是一个布尔属性，只能设置在元素上。

我们通过简单地向`<input>`元素添加`required`属性来指定字段的值为必填。在下面的代码列表中，你会发现带有`required`属性的几个`<input>`元素：

```js
<form action="/" method="post">
  <label>Checkbox:</label>
    <input type="checkbox" required />
  <label>Radio:</label>
    <select>
      …
    </select>
  <label>Text:</label>
    <input type="search" required />
  <label>Range:</label>
    <input type="range" min="5" max="10" step="5" />
  <label>URL:</label>
    <input type="url"  required />
  <label>File:</label>
    <input type="file" accept=".mp3" />
    <input type="submit" name="submit" value=" Submit " />
</form>
```

一旦添加了`required`属性，然后当你点击**提交**按钮时，表单中的所有字段都将进行验证；如果任何字段不正确，将返回错误。必填字段会被突出显示，而且，默认消息会通知用户这些字段在表单中是必须的。

你可以看到下面的截图显示了前面代码的输出：

![轻松验证](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_01_03.jpg)

我们可以使用 CSS3 伪选择器`required`应用一个或多个样式（关于这方面的更多信息将在下一章中介绍）。例如，下面的样式添加了一个 CSS3 伪类`required`，它将寻找文档中具有`required`属性的所有`input`元素，并用`yellow` `border-color`来设置样式。

```js
input:required {
  border-color: Yellow;
}
```

如果你想对表单中所有非必填元素应用一种样式，那是非常简单的；只需添加`optional`伪类，并像我们对`required`类所做的那样给它一个样式。在下面的代码中，我们给所有没有`required`属性的`input`元素应用了`LightGray` `border-color`。

```js
input:optional {
  border-color: LightGray; 
}
```

HTML5 表单不仅对必填字段进行验证，而且还检查字段值的内容，并自动验证，就像在 URL 和`email`输入类型中一样，或者使用`pattern`属性。`pattern`属性使用正则表达式来定义元素值必须匹配的有效格式，例如，电话号码或社会保障号码。

下面的例子展示了`password`字段的语法，该字段是必填的，并且必须有有效的输入，最小长度为八个字符。在这里，默认的验证消息被`title`属性中提供的文本替换：

```js
<input type="password" required pattern="[^\s]{8}[^\s]*" title="Passwords must be at least 8 characters long."/>
```

还有更多属性可以增加验证技术，比如`placeholder`，它提供了一个在用户开始在元素内输入文字前以浅色文字显示的提示信息；这个提示可能是关于用户应该在字段中输入的值。例如，你可以在`email`字段中添加一个示例电子邮件地址，如：

```js
<input type="email" placeholder="email@example.com" />
```

你可以使用`maxlength`属性检查`text`或`textarea`输入中允许的最大字符数。此外，我们还有`min`、`max`和`step`属性与`range`元素一起使用，以验证该元素输入的值。`min`和`max`属性检查可以输入的最小和最大值，而`step`属性检查允许的值。

你还可以通过`accept`属性指定可接受的文件 MIME 类型。正如你在前面的代码列表中可能注意到的，`accept`属性被添加到了`<input type="file" />`元素中，这是唯一与之使用的元素。一旦你把这个属性添加到文件控件中，然后当你尝试使用 Windows 8 文件资源管理器浏览文件时，只有`accept`列表中的类型才会显示。

HTML5 表单验证是默认行为；不需要编写代码来激活它，但您可以通过在**提交**按钮或任何`<input>`元素上添加`formnovalidate`属性来关闭它。这个属性允许表单在没有经过验证的情况下提交。

# 分配自定义数据属性

随着 HTML5 的出现，我们现在有能力为任何 HTML5 元素分配自定义数据属性。W3C 将其定义为：

> **用于存储页面或应用程序私有自定义数据的属性，如果没有更合适的属性或元素，则可以使用该属性。**

这些新的自定义数据属性由两部分组成：

+   **属性名称**：它必须以`data-`前缀开头，后跟至少一个字符，且不应包含大写字母。

+   **属性值**：它必须是一个字符串值

让我们像下面的代码示例那样给`<div>`标签添加一个自定义属性：

```js
<div id="bookList" data-category="TechnicalBooks">
Developing for windows 8
</div>
```

你可以看到自定义属性名`data-category`和属性值`TechnicalBooks`被分配给`<div>`元素。这些数据可以通过使用原生的`getAttribute`和`setAttribute`方法来检索和更新，因为自定义数据属性被认为是它们所使用的页面的组成部分。下面的代码示例展示了如何使用原生的 JavaScript 来操作自定义属性：

```js
function getSetCategory() {
  var bookList = document.getElementById("bookList");
//get the value of the attribute
  var bookCategory = bookList.getAttribute('data-category');
//set the value for the attribute
  bookList.setAttribute('data-category', 'HealthBooks');
//remove the attribute
  bookList.removeAttribute('data-category');
}
```

HTML5 规范明确指出，数据属性不应用来替代已存在的属性或可能更具有语义 appropriate 的元素。例如，在`span`元素中添加一个 data-time 属性来指定时间值是不恰当的，如下面的代码所示：

```js
<span data-time="08:00">8am<span>
```

最合适且更具语义的元素是一个`time`元素，如下面的代码所示：

```js
<time datetime="08:00">8am</time>
```

当开发 Windows 8 应用时，我们可以使用 Windows 为 JavaScript 提供的库（`WinJS`）来实现将数据与 HTML 元素更高级的绑定。Win8 JavaScript 库利用 HTML 的`data-*`属性提供了一种简单的方式来程序化实现数据绑定。

# 概要

在 HTML5 中，有新的语义丰富的元素，可以传达它们使用的目的。有媒体元素允许您轻松地向应用程序添加音频和视频，还有新的输入类型和属性，您可以使用它们创建智能和交互式的表单，并实时地将它们与数据绑定，所有这些都比以往任何时候的标记和代码都要少。

在下一章中，我们将查看在为 Windows 8 开发时可用的丰富的新 CSS3 特性，以及我们如何使用它们来为我们的 HTML 应用样式和布局。


# 第二章．使用 CSS3 进行样式设计

HTML 定义了文档/页面结构并列出了包含的元素。但定义这些元素的布局、定位和样式是 CSS 的唯一责任。**层叠样式表（CSS）**，正如其名，基本上是一张包含一系列样式规则的表。每个 CSS 样式规则将一个**选择器**，它定义将要样式的内容，链接到一个声明块，其中包含一个或一组样式，进而定义要应用于相关选择器的效果(s)。基本样式规则的语法看起来像这样

```js
selector { property: value; property: value; }
```

在本章中，我们将回顾以下主题：CSS3 选择器、网格和 Flexbox、动画和转换，以及媒体查询。这些主题涵盖了在用 JavaScript 开发 Windows Store 应用时经常使用的 CSS3 的一些特性。

# CSS3 选择器的威力

CSS 选择器非常强大，在格式化 HTML 文档时非常方便。使用选择器有时会有些棘手，因为精确地选择你想要的内容，并确保应用的样式规则只影响你意图中的元素，是一项繁琐的任务。但是，当使用正确的选择器正确地完成时，结果是非常有价值的。掌握选择器的使用将导致更简单的 CSS，最小化冗余样式和通过类和 ID 对 HTML 进行过度定义的可能性，从而确保更好的性能。选择器可以是一个 HTML 元素、一个类、一个元素 ID，甚至可以是元素在 DOM 中的位置。

以下是一份 CSS 选择器的列表；我们将从基础的选择器开始，进而介绍 CSS3 中新增的选择器：

+   **星号(*)符号**：这是一个`万能`选择器，被称为通用类型选择器，用于定位文档中的每一个元素。它经常与 CSS 重置一起使用，以重置所有默认样式。

    ```js
    * { margin: 0; }
    ```

+   **HTML 元素**：它被称为类型选择器，用于根据它们的类型选择文档中的所有元素。例如，下面的选择器将定位 DOM 中的每一个`<p>`元素，把文本颜色改为红色，并加下划线。

    ```js
    p { color: red; text-decoration: underline; }
    ```

    ### 提示

    使用`<body>`元素作为选择器将定位文档的正文，从而选择每一个元素，就像你正在使用星号(*)一样。

+   **ID 选择器**：它由元素 id 属性中的值前缀哈希符号（`#`）指定。ID 应该是元素的名称，更重要的是，它必须是唯一的。名称应该是对元素的清晰引用。例如，对于一个`nav`元素来说，有一个`id`值为`mainMenu`会很清晰。例如：

    ```js
    <nav id="mainMenu"></nav>

    ```

    另外，唯一性意味着在页面上不应该有其他具有`id`值为`mainMenu`的元素。由于`id`应该始终是唯一的，选择器将在 HTML 文档中只针对一个元素。例如，如果你有如下的`<div>`元素，其`id`值为`logo`：

    ```js
    <div id="logo"></div>
    ```

    则相应的选择器将是：

    ```js
    #logo { float: left; width: 200px; } 
    ```

+   **类选择器**：它由一个类名前缀和一个点号（`.`）组成，目标是指具有匹配类名的所有元素。这个选择器的基本语法如下：

    ```js
    .highlighted { font-weight: bold; background-color:yellow; }
    ```

具有这个类名的任何元素都将拥有粗体文本和黄色背景颜色。当您想要为多个元素设置样式时，应该使用类，特别是有一组共通之处的元素。记住，与`id`属性相反，类名永远不能用来唯一标识一个元素。此外，`class`属性可能有多个值；同样，相同的类也可能适用于多个元素。尽管类选择器的使用可能看起来很通用，但您可以通过在前缀类型选择器来更具体地使用它。例如，下面的代码片段将只针对具有`highlighted`类的`<div>`元素：

```js
div.highlighted { font-weight: bold; background-color: yellow; } 
```

另外，您可以连锁类选择器来针对具有所有指定类名的所有元素。

## 属性选择器

属性选择器用于根据元素的属性来选择元素。它首先检查属性是否存在；如果存在，它再检查属性的值。属性应该被包含在方括号内。如果方括号内只包含属性名，它将检查该属性是否存在于元素中。这就是它也被称为存在选择器的原因。在下面的代码片段中，选择器将只针对具有`title`属性的锚元素：

```js
a[title] { text-decoration: none; color: #000; }
```

前面的语法在检查没有值的属性时很有帮助。如果你记得，在前一章节我们提到了一些属性不需要值，比如`<input>`元素的`required`属性，或者音频和视频元素的`loop`属性。下面的选择器将寻找所有具有`loop`属性的音频元素并隐藏它：

```js
audio[loop] { display: none; }
```

为了精确匹配指定的属性值，我们将使用带有等号（`=`）的等价属性，并将值用引号括起来。所以，如果我们想要针对所有`type`属性值为`email`的输入元素，语法将如下所示：

```js
input[type="email"] { text-decoration: none; color: #000; }
```

另外，在属性选择器类别下，我们有前缀选择器或“以...开始”的属性选择器，用于检查属性是否以某个值开始。以下语法将匹配所有`id`值以`home`开始的图片。例如，如果你想定位首页上的所有图片，可以将`home`添加到`id`中，从而有`homeLogo`、`homeBanner`等，并为其应用 10 像素的边距：

```js
img[id^='home'] { margin:10px; }
```

同样，我们有后缀选择器或“以...结尾”的属性选择器，它将选择所有属性值以你所指定的值结尾的元素。后缀选择器在等号（`=`）之前用美元（`$`）符号标记，语法如下：

```js
a[href$=".jpg"] { color: red; }
```

这将匹配所有`href`属性值以`.jpg`结尾的锚点元素：

另一个属性选择器是**子字符串**选择器，也称为“包含”选择器。正如其名，它匹配包含选择器中指定的值的属性值。它用星号（`*`）符号在等号（`=`）之前标记，语法如下：

```js
ul[id*="Nav"] { float: left; list-style-type: none; }
```

前面的语法将匹配所有含有`Nav`字符串的`<ul>`元素 ID。例如，你有多个用于导航目的的`<ul>`元素，并标记有诸如`secondaryNav`、`sidebarNav`等 ID：

我们也有一种**连字符**选择器，用`|=`标记，它用于匹配后面紧跟连字符的完全相等的属性值。你可能很少使用这个选择器，但它的典型用途是用于包含连字符的值，例如`lang`属性。下面的列表将目标定位在与"en"完全匹配，且后面紧跟连字符的元素上，并将返回`en`、`en-us`、`en-uk`等：

```js
ul[lang|="en"] { display: none; }
```

最后一个属性选择器将是**空白符**选择器，它针对的是在空格分隔的值列表中完全匹配指定属性值的元素。在以下代码片段中，我们有一个带有自定义`data-`属性的`<p>`元素，包含三个空格分隔的值，分别为`new events local`，选择器将匹配这个元素，因为它的`data-post-type`值与`events`完全匹配。

以下为 HTML 代码：

```js
<p data-post-type="new events local"></p>
```

CSS 代码如下：

```js
p[data-post-type~="events"] { float: left; color: red }
```

### 注意

注意，在 HTML5 中，任何以`data-`开头的属性都是有效的，与其前身只认为识别的属性有效的规定不同。

## 组合选择器

一个 CSS 选择器可以包含多个选择器，即简单选择器的组合。组合选择器包含多个简单选择器，由一个组合符连接。组合符是一个表示选择器之间关系的符号。CSS2 中已经有三个不同的组合符，CSS3 增加了一个额外的。以下列出四个选择器，所使用的组合符以及每个选择器匹配的内容：

| 选择器 | 组合符 | 目标 |
| --- | --- | --- |
| 后代 | 空格字符 | 匹配那些是指定元素后代的元素。 |
| 直接后代（子选择器） | > | 匹配那些是指定元素直接后代的元素。 |
| 相邻兄弟 | + | 匹配那些是指定元素相邻兄弟（紧随其后的）的元素。 |
| 一般兄弟 | ~ | 匹配那些是指定元素相邻兄弟的元素。 |

以下选择器描述如下：

+   **后代选择器**：由空格字符作为组合符，它将选择所有指定元素的后代元素。仿佛我们在第一个简单选择器上应用了一个额外的过滤器。第一个选择器代表父元素，第二个是要匹配的子（后代）元素。例如，以下代码片段会匹配所有`<li>`元素作为其父元素的锚点元素：

    HTML 代码如下：

    ```js
    <ul>
        <li><a href="#">Item 1</a></li>
        <li><a href="#">Item 2</a></li>
        <li><a href="#">Item 3</a></li>
    </ul>
    ```

    CSS 选择器如下：

    ```js
    li a { text-decoration: none; color: #000; } 
    ```

+   **直接后代选择器**：由大于号（`>`）作为组合符标记，基本形式为 E>F，匹配 E 元素的每个直接后代（子）F 元素。在以下代码片段中，只有`<div>`元素的直接子`<p>`元素会被染成蓝色，其余的则不会。

    HTML 代码如下：

    ```js
    <div>
        <p>some content inside a div</p>
    </div>
    <p> standalone content …</p>
    <div>
        <p> contentinside a div </p>
    </div>
    <header>
        <p> content inside a header </p>
    </header>
    ```

    CSS 代码如下：

    ```js
    div > p { color: Blue; } 
    ```

+   **相邻兄弟选择器**：由加号（`+`）作为组合符标记，匹配所有紧随父元素之后的兄弟元素。所以，兄弟元素之间不能有其他元素。如果这有点复杂，下面的例子会解释清楚。选择器只会把一个`<p>`元素染成红色。

    HTML 代码如下：

    ```js
    <h1>Heading</h1>
    <p>This p element is a sibling and adjacent to the h1 
    </p>
    <p>This p element is a sibling but not adjacent to the h1
    </p>
    ```

    CSS 代码如下：

    ```js
    h1 + p { color: Red; } 
    ```

+   **一般兄弟选择器**：由波浪号（`~`）作为组合符标记，是 CSS3 的新增功能。它用于选择所有给定元素的兄弟元素。所以，如果我们把选择器应用到前面的例子中的 HTML 代码上，两个`<p>`元素都会匹配并染成红色，因为它们都是`h1`的兄弟元素。

    ```js
    h1 ~ p { color: Red; } 
    ```

## 伪类选择器

伪类类似于类，但由于它是内置的，您不需要在 HTML 代码中显式添加它。此外，它在语法上也有所不同；类选择器前面有一个点（`.`），而伪类选择器前面有一个冒号（`:`）。在其基本形式中，伪类选择器将采用以下形式：

```js
selector:pseudo-class { property: value }
```

您可以指定没有选择器的伪类，它将调用默认类型选择器。所以，如果我们单独指定`:hover`，它将匹配所有元素，并将样式规则应用于文档中可以悬停的任何内容。否则，您可以更详细地将对特定 HTML 元素的伪类选择器。例如，以下代码片段将在悬停时为所有`<p>`元素应用粉红色：

```js
p:hover { color: pink; }
```

在 CSS3 之前，伪类就已经存在，您可能对著名的`:hover`、`:visited`和`:active`伪类很熟悉，这些伪类代表锚元素的不同的状态。CSS3 引入了许多更强大的伪类，如`:required`、`:valid`、`:nth-child(n)`、`:first-child`、`:last-child`、`:only-child`、`:first-of-type`、`:last-of-type`等。

## 伪元素选择器

伪元素代表元素的某些部分，如段落的第一行，或元素后面的部分。伪元素类似于一个伪类，它作为类的行为，但是内置的，不需要在 HTML 代码中定义。伪元素通过双冒号（`::`）来区分，这个语法是在 CSS3 中引入的。需要注意的是，在 CSS3 之前引入的所有伪元素都使用单个冒号（`:`），类似于伪类的语法。

以下代码片段将选择由`content`样式属性定义的`<p>`元素后的所有生成内容：

HTML 代码如下：

```js
<p>Paragraph content goes here</p>
```

CSS 代码如下：

```js
p::after {
  content: " 'I come after a paragraph' ";
  color: blue; background-color: yellow;
}
```

输出结果将是：

**段落内容放在这里 '我在段落后'**

下面是伪元素的表格：

| `::first-letter` | 匹配元素中的第一个字母。 |
| --- | --- |
| `::first-line` | 选择元素中的第一行。 |
| `::before` | 选择元素生成的内容之前。 |
| `::after` | 选择元素生成的内容之后。 |
| `::selection` | 选择用户可能已经高亮显示的任何内容，包括可编辑文本字段中的文本，如输入类型为文本的元素，或具有`contenteditable`属性的任何元素。 |

### 提示

虽然您可以通过使用 JavaScript 向您的 HTML 代码中添加类来以编程方式实现相同的行为，但通过向您的选择器中添加伪类和伪元素更为简单；此外，它还可以使您的代码更清晰。

# 使用 Grid 和 Flexbox 创建流体布局

当涉及到实施由 Microsoft 设定的构建吸引人、直观且互动的 Windows 8 应用的设计原则时，布局非常重要。通常，使用 HTML 结构元素（如`<div>`和`<table>`）和定位样式规则定义页面布局。

但是现在，使用 CSS3 高级布局功能（即**网格**布局和**Flexbox**（**灵活盒**）布局）有一种更灵活的方法来实现。这些布局系统允许您轻松实现适应性和流体布局。

## 网格布局

它为 Windows 8 应用提供了一种非常简单的方法来创建流体和适应性布局。由于网格可以自动扩展以填充所有可用空间，因此它非常适合实现全屏 UI。网格布局允许您使用 CSS 完全对齐和定位其子元素作为列和行，与它们在 HTML 代码中的顺序无关。与使用浮动或脚本的方法相比，它使布局更加流体。

下面的例子演示了我们传统上如何使用浮动来定位元素：

以下是 HTML 代码：

```js
<div class="container">
  <div class="leftDiv"></div>
  <div class="rightDiv"></div>
</div>
```

以下是 CSS 代码：

```js
.container { width: 200px; height:50px; border: 1px solid black; }
.leftDiv { float:left; width: 100px; height:50px;background-color:blue}
.rightDiv { float:right; width: 50px; height:50px;background-color:red}
```

前面的代码将导致以下多色盒子。容器有一个黑色边框围绕着里面的两个 div，左边的蓝色 div 和右边的红色 div，之间的空白是剩余未占用的空间：

![网格布局](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_02_01.jpg)

网格布局通过将元素的`display`样式规则属性设置为`-ms-grid`来指定，或者您可以为内联级别网格元素使用`-ms-inline-grid`属性。您可能注意到了`-ms`这个厂商前缀（Microsoft-specific），这是因为这个 CSS 特性的状态仍然是一个工作草案；添加这个厂商前缀允许它在 Internet Explorer 10 和 Windows 8 中使用 JavaScript 构建的 Windows 商店应用中工作。以下是示例：

```js
.divGrid {
  display: -ms-grid;
  -ms-grid-columns: 120px 1fr;
  -ms-grid-rows: 120px 1fr;
}
.column1row1 {
  -ms-grid-column: 1;
  -ms-grid-row: 1;
}
.column2row1 {
  -ms-grid-column: 2;
  -ms-grid-row: 1;
}
```

`display: -ms-grid;`属性创建了一个网格；之后，我们定义了列和行，并使用以下属性指定它们的大小：`-ms-grid-column`和`-ms-grid-row`。`-ms-grid-columns`属性指定了每列的宽度，而`-ms-grid-rows`指定了每行的 height, 在那个网格中。这两个属性中的宽度和高度值分别由一个空格字符分隔。在前面的例子中，`-ms-grid-columns: 120px 1fr;`属性创建了两个列；第一个宽度为 120 px，第二个宽度值为 1 fr，即一个分数单位，这意味着第二列的宽度将自动填充所有剩余的可用空间。行也适用同样的概念。在前面的代码片段中剩下的两个类将使用`-ms-grid-column`和`-ms-grid-row`属性将具有这些类的元素定位到网格的列和行中。

### 注意

**分数单位（fr）** 表示可用空间应该如何根据它们的分数值在列或行之间进行划分。例如，如果我们有一个四列布局，如下所示：`-ms-grid-columns: 100px 100px 1fr 2fr;`，第 3 列占据一个分数，第 4 列占据两个分数的剩余空间。因此，剩余空间现在为 3 个分数；第 3 列被设置为 1 个分数除以总数（3），所以第 3 列和第 4 列（2 个分数）将分配剩余空间的三分之二。

在前面的示例中，我们使用了 px 和 fr 单位来指定列和行的尺寸。此外，我们还可以使用标准长度单位（如 px 或 em），或者元素的宽度和高度的百分比。还可以使用以下关键字：

+   `auto`: 这个关键字使得列或行的尺寸伸展以适应内部内容。

+   `min-content`: 这个关键字将列或行的尺寸设置为任何子元素的最小尺寸。

+   `max-content`: 这个关键字将列或行的尺寸设置为任何子元素的最大尺寸。

+   `minmax(a,b)`: 这个关键字将列或行的尺寸设置为 a 和 b 之间的值，尽可能利用可用空间。

以下表格列出了与网格布局相关的属性：

| **-ms-grid-column** | 用于指定元素在网格中的列。编号系统是基于**1 的索引**类型。 |
| --- | --- |
| **-ms-grid-columns** | 用于指定每个网格列的宽度值。 |
| **-ms-grid-column-span** | 用于指定元素在网格中占据的列数。 |
| **-ms-grid-column-align** | 用于设置元素在列内的水平对齐值。 |
| **-ms-grid-row** | 用于指定元素在网格中的行。编号系统是基于 1 的索引类型。 |
| **-ms-grid-rows** | 用于指定每个网格行的宽度值。 |
| **-ms-grid-row-span** | 用于指定元素在网格中占据的行数。 |
| **-ms-grid-row-align** | 用于设置元素在行内的垂直对齐值。 |

此外，网格布局暴露出一组丰富的属性，使您能够轻松地适应用户界面的视图状态和应用程序的方向变化。我们将在设计应用程序时讨论这一点。

## 弹性盒布局（Flexbox layout）

我们拥有的第二种布局模型是 Flexbox 模式，这是 CSS3 中的又一次近期添加。与 Grid 布局类似，Flexbox 布局通过设置`display`属性启用，并且由于它仍是一个**万维网联盟（W3C）**工作草案，因此还需要一个微软特定的供应商前缀。Flexbox 布局用于使元素的相对位置和大体保持不变，即使屏幕和浏览器窗口的大小发生变化。与浮动相比，Flexbox 为元素的位置和大小提供了更好的控制。使用 Flexbox 布局的优势在于，它使元素在其内部具有相对定位和尺寸，因为它考虑了可用空间。这允许您创建一个流体布局，维持元素之间的相对位置和大小；因此，当浏览器或应用程序窗口的大小发生变化时，Flexbox 容器内的元素可以重新调整大小和位置。Flexbox 布局非常适合构建显示任何数字印刷媒体的应用程序，例如报纸或杂志。

与 Grid 布局一样，通过将`display`属性设置为`-ms-flexbox`，很容易创建一个带有 Flexbox 布局的容器。创建 Flexbox 容器后，我们可以开始使用以下属性操纵它内部的元素：

+   `-ms-flex-direction`：它使用以下关键字值指定子元素的取向：`row`（初始值）、`column`、`row-reverse`和`column-reverse`。我们将逐一介绍每个值，并展示它应用的效果，在下面的示例中。那么，更好的解释方法是什么呢？所以，假设我们有以下的 HTML 和 CSS 代码片段：

    ```js
    <div class="flexit">
      <div>1</div>
      <div>2</div>
      <div>3</div>
    </div>

    .flexit {
      width:160px;
      height:100px;
      border:2px solid brown;
      display:-ms-flexbox;
      -ms-flex-direction: row;
    }
    .flexit div {
      background-color:red;
      width:50px;
      height:25px;
      text-align:center;
      color:white;
    }
    .flexit div:first-child {
      background-color:green;
      height:30px;
    }
    .flexit div:last-child {
      background-color:blue;
      height:30px;
    }
    ```

    前面的语法创建了一个带有`flexit`类的 Flexbox 容器，该容器以 Flexbox 布局包裹了标记有文本 1、2 和 3 的子`<div>`元素以进行跟踪。我们对一些子元素应用了一些样式和背景颜色。

    因此，在`-ms-flex-direction`属性中的以下值将给我们以下表格中的结果。注意元素的出现顺序和定位如何在不添加任何标记的情况下发生变化：

    | 属性 | Flexbox 容器 | 元素的出现顺序和定位 |
    | --- | --- | --- |
    | 行 | ![Flexbox 布局](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_02_02.jpg) | 子元素从左至右定位，与 HTML 标记中的出现顺序相同。 |
    | 行反转 | ![Flexbox 布局](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_02_03.jpg) | 子元素从右至左定位，与 HTML 标记中的出现顺序相反。 |
    | 列 | ![Flexbox 布局](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_02_04.jpg) | 子元素从上至下定位，与从左至右的 HTML 标记中的出现顺序相同。 |
    | column-reverse | ![Flexbox 布局](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_02_05.jpg) | 子元素从底部向上定位，按照 HTML 标记出现的顺序。 |

+   `-ms-flex-align`：此属性指定了 Flexbox 容器中子元素的对齐方式。它接受以下关键字值：`start`、`end`、`center`、`stretch` 和 `baseline`。对齐总是垂直于在 `-ms-flex-direction` 属性中定义的布局轴；因此，如果方向是水平的话，它将对齐设置为垂直，反之亦然。例如，如果方向是 `row`（水平），则值 `start` 将设置对齐为顶部（垂直）。

+   `-ms-flex-pack`：此属性指定了如何将 Flexbox 容器中子元素之间的可用空间分配给定义在 `-ms-flex-direction` 属性中的轴线，与前面描述的对齐属性不同。它接受以下关键字值：`start`、`end`、`center` 和 `justify`。

+   `-ms-flex-wrap`：此属性允许子元素溢出并在下一行或列中换行，并指定该流动的方向。它接受以下关键字值：`none`、`wrap` 和 `wrap-reverse`。

# CSS 驱动的动画

**CSS 转换** 允许你以前只能通过脚本实现的方式来操作 HTML 元素。它使元素的旋转、平移、缩放和倾斜成为可能，并允许在 2D 和 3D 中转换元素。CSS 动画使你能够在一段时间内平滑地改变样式属性，与基于 JavaScript 的动画相比，使你能够设计出复杂动画且具有更好的渲染性能。将两者结合使用，你可以在应用上施展魔法。

## CSS3 动画

CSS3 革命化了网页开发中的动画效果。在此之前，制作动画需要使用动画图片、Flash 这类插件，或者进行一些复杂的脚本编程。尽管 jQuery 和其他支持库让开发者用 JavaScript 制作动画变得稍微容易一些，但它在性能上仍然无法与 CSS 动画相匹敌。基本来说，动画定义了一个效果，允许元素在一段时间内改变一种或多种样式，如颜色、大小、位置、透明度等。此外，借助 CSS3 动画，你可以在动画过程中允许多种中间样式的变化，而不仅仅是动画开始和结束时指定的那些。

为了创建一个动画，你需要使用 `@keyframe` CSS 规则，该规则用于指定动画过程中将发生变化的样式。以下代码片段创建了一个名为 `demo` 的 `@keyframe` 规则，将背景颜色从红色变为黄色，在中间 50% 的地方，将透明度变为零：

```js
@keyframes demo {
  from { background: red;    }
  50% { opacity: 0;         }
  to { background: yellow; }
}
```

之后，我们将在`@keyframe`规则中定义的动画绑定到我们想要应用效果的元素（或选择器）上。如果动画不绑定到任何元素，它将不会在任何地方应用。在将动画绑定到选择器时，我们需要指定至少两个动画属性：

+   名称

+   持续时间

例如：

```js
#logo { animation: demo 4s }
```

前面的示例将我们使用`@keyframe`规则创建的名为`demo`的动画，持续时间为 4 秒，绑定到 ID 为`#logo`的元素上。

动画一旦在 DOM 中定义，就会自动触发。你可以指定一定的延迟时间来避免这种情况，或者可以通过代码来触发动画。动画有以下六个主要属性，如下所示：

```js
div {
  animation-name: demo;
  animation-duration: 3s;
  animation-timing-function: ease-in;
  animation-delay: 3s;
  animation-iteration-count: 2;
  animation-direction: normal;
}
```

或者我们可以使用动画简写属性，通过这个属性，我们可以将这些属性组合到一行中：

```js
div { animation: demo 3s ease-in 3s 2 normal; }
```

由于浏览器支持问题，开发者仍然对使用 CSS3 动画或其他 HTML5 特性持谨慎态度。为了解决浏览器兼容性问题，一些样式规则必须定义带有厂商前缀的版本。例如，一个动画定义将被复制以支持其他浏览器，每个浏览器都有它自己的厂商前缀，如下所示：

```js
-webkit-animation: 5s linear 2s infinite alternate;
-moz-animation: 5s linear 2s infinite alternate;
-o-animation: 5s linear 2s infinite alternate;
animation: 5s linear 2s infinite alternate;

```

但是在为 Windows 8 开发时，你可以将其减少到只有一个，这就是标准。担心多浏览器支持是最不需要担心的问题，因为 Windows 8 支持所有对 Internet Explorer 10 有效的标准。

## CSS3 转换

CSS3 的另一个优点是 2D 和 3D 转换的概念，它使你能够以使用 CSS 无法实现的方式操纵应用中的元素。它使你能够在 2D 和全新的 3D 空间中对 HTML 元素进行旋转、缩放、倾斜和翻译，而无需插件或脚本，这是由 W3C 在**CSS 转换**规范下定义的。

使用`transform`属性创建转换，该属性包含一个或多个（由空格分隔）的转换函数，应用于指定的元素。属性值可以设置为一个或多个（由空格分隔）的转换函数，它们将按照列表的顺序应用。以下是一个示例代码，应用了旋转函数的`transform`属性：

```js
div { transform: rotate(90deg) translateX(100px); }
```

前面`transform`属性的结果是，元素首先旋转 90 度，然后（水平）向右移动 100 像素。

`transform`属性可用的函数列表包括`matrix()`、`matrix3d()`、`perspective()`、`rotate()`、`rotate3d()`、`rotateX()`、`rotateY()`、`rotateZ()`、`scale()`、`scale3d()`、`scaleX()`、`scaleY()`、`scaleZ()`、`skew()`、`skewX()`、`skewY()`、`translate()`、`translate3d()`、`translateX()`、`translateY()`和`translateZ()`。这些函数在 Visual Studio 的 CSS3 智能感知功能中提供，因此，在编写`transform`属性时，你会被提示选择其中一个函数。

### 提示

Visual Studio 2012 通过提供如 Regions、IntelliSense、供应商前缀和内置片段等特性，增强了对 CSS 的支持，从而使得使用 HTML5 和 CSS 开发 Windows 8 应用变得非常简单和方便。

# 介绍媒体查询

你的 Windows 8 应用应该具有流畅和响应式的用户界面，因为同一个应用将会在平板电脑、带有大型显示器的 PC 或手机上下载和打开。你的应用应该适应不同的视图状态（全屏纵向或横向、填充或吸附），并相应显示。当用户在纵向和横向之间翻转屏幕、缩放、吸附应用时，应用应该看起来不错且功能良好。要关注的东西太多，你可能会说？不用担心，因为如果你正在使用 JavaScript 应用进行开发，所有你的担忧的答案就是**CSS 媒体查询**！

通过使用 CSS 媒体查询，你可以通过轻松定义不同的样式来管理当前媒体的大小和视图状态对布局的影响，这些样式将应用于你的应用中的 HTML 元素。你可以为每个视图状态定义一个单独的媒体查询，或者可以将媒体查询组合起来，将同一组样式应用于多个视图状态。媒体查询的基本语法如下：

```js
@media MediaType TargetMediaProperty{MediaRule}
```

它是一个逻辑表达式，要么是 `true`，要么是 `false`，并且由以下内容组成：

+   **@media**：这是一个指示媒体查询的关键字。

+   **媒体类型**：它用于指定我们正在针对的媒体类型，可以有以下值之一：`screen` 用于计算机屏幕，`print` 用于以打印模式查看的文档，`all` 用于所有设备。

+   **目标媒体属性**：通过添加如方向和大小等条件，它用于创建更具体的查询。

+   **媒体规则**：它用于指定在媒体查询评估为 `true` 时将应用的一个或多个样式规则。

一个简单的例子如下：

```js
@media screen and (max-width: 1024px) {
  body { 
    background-color: orange;
  }
}
```

前面的媒体查询将检查媒体是否是屏幕，且窗口的宽度不超过 400 像素。如果是 `true`，它将把橙色背景颜色应用到 body 元素上。

以下代码片段检查方向：

```js
@media all and (orientation: portrait) {
...
}
```

我们还可以包含 Microsoft 特定的供应商属性 `-ms-view-state` 以检查应用可以处理的不同的视图状态。例如：

```js
@media all and (-ms-view-state: snapped) {
...
}
```

# 总结

在本章中，我们尝试涵盖并从新的丰富的 CSS3 特性中学到尽可能多的内容，并描述在开发 Windows 8 应用时哪些是可用的。我们详细地查看了 CSS 选择器，并学会了根据我们的需要使用它们来过滤 DOM 元素。我们学习了使用 Grid 和 Flexbox 显示属性的新布局技术。

我们看到了动画和变换属性所能带来的魔法，也初步了解了媒体查询的强大，它能帮助我们构建响应式布局。简而言之，CSS3 就是一个奇妙的领域，你需要熟悉其特性才能充分利用它的力量。

在下一章，我们将学习 Windows 库为 JavaScript 提供的主要功能，这是使用 JavaScript 构建的 Windows 商店应用的骨架。


# 第三章： Windows 应用的 JavaScript

在本章中，我们将介绍由微软引入的**Windows 库 for JavaScript**（简称`WinJS`库）提供的一些功能，该库用于通过 JavaScript 访问 Windows 运行时，以便为 Windows 商店应用提供支持。Windows 库 for JavaScript 是一个 CSS 和 JavaScript 文件的库。它包含一组强大且功能丰富的 JavaScript 对象、函数和方法，这些对象、函数和方法按命名空间组织，旨在使开发人员更容易使用 JavaScript 创建 Windows 商店应用。

我们还将学习关于`WinJS`的异步编程，并了解我们如何可以使用`WinJS.Utilities`命名空间提供的函数查询文档中的元素并操作这些元素。接下来，我们将学习`xhr`函数及其使用，最后介绍由 Windows 库 for JavaScript 提供的一组 UI 控件。

# 使用 Promise 对象的异步编程

当构建一个 Windows 8 应用时，重点是拥有一个响应式 UI，这是 Windows 8 商店应用的主要特点之一。在第二章*使用 CSS3 进行样式设计*中，我们看到了我们如何在样式级别实现这一点。响应式 UI 还包括具有响应式功能，后台运行的代码不仅会突然阻塞应用的 UI，而且会使它在执行某些逻辑或功能时对任何用户输入不作出响应。

JavaScript 作为一种编程语言是单线程的，这意味着一个长时间运行的同步执行过程将阻塞所有其他执行，直到该过程完成。因此，你应该尽可能避免同步执行。这个困境的解决方案是异步处理，这对于创建响应式、高性能的应用程序至关重要。实现异步处理的一种方式是使用**回调函数机制**。回调函数用作一个钩子点，在之前的异步操作终止后继续处理。一个典型的例子是对服务器端后端的调用。

```js
//code sample using jQuery
function longRunningComputation(callbackFunc){
    setTimeout(function(){
        //computation
       //once finished, invoke the callback with the result
       callbackFunc(computationResult);
    }, 1000);
}
```

这个函数然后按照如下方式调用：

```js
longRunningComputation(function(compResult) {
    //do something meaningful with the result

});
```

回调函数是异步调用的典型解决方案，但它们有一个缺点：它们创建了深层链，特别是在你将多个异步操作放在一个链中，而后续函数又依赖于前一个计算结果时。Windows 库 for JavaScript 以及 Windows 运行时提供了一个更优雅的解决方案，使用了一种名为**Promise**的机制，它简化了异步编程。Promise，正如它的名字所暗示的，表示将来会发生一些事情，当这些事情完成后，Promise 就被认为是得到了满足。

在下面的代码示例中，我们创建了一个名为`sumAsync`的函数，它将返回一个`WinJS.Promise`对象，并在我们其在`clickMe()`函数中调用它时异步执行：

```js
function clickMe() {
   sumAsync().then(
        function complete(result) {
            document.getElementById("result").textContent = "The promise has completed, with the result: " + result;
        },
        function error(result) {
            document.getElementById("result").innerHTML = "An Error has occurred </br>" + result;
        },
        function progress(result) {
            document.getElementById("result").innerHTML += "The promise is in progress, hold on please." + result;
        })
}
function sumAsync() {
    return new WinJS.Promise(function (comp, err, prog) {
        setTimeout(function () {
            try {
                var sum = 3 + 4;
                var i;
                for (i = 1; i < 100; i++) {
                    prog(i);
                }
                comp(sum);
            } catch (e) {
                err(e);
            }
        }, 1000);
    });
}
```

从前面的代码示例中我们可以推断出，`Promise`基本上是一个对象。这个对象实现了一个名为`then`的方法，该方法又采取了以下三个函数作为参数：

+   一个在`Promise`对象完成并成功满足时会被调用的函数

+   一个在`Promise`对象被满足时会调用的函数，称为`未来`

+   一个在`Promise`被满足时会被调用的函数，以指示进度信息，称为`延迟`

在 Visual Studio 中，当你向一个函数添加一个`then`方法时，你将在 IntelliSense 弹出窗口中提示输入这些参数，如下面的屏幕截图所示：

![使用 Promise 对象的异步编程](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_03_01.jpg)

你可以使用`then`方法与任何返回`Promise`的函数；因为它返回`Promise`，所以你可以链接多个`then`函数。例如：

```js
sumAsync() 
  .then(function () { return XAsync(); })
  .then(function () { return YAsync(); })
  .done(function () {  endProcessing();})
```

在前一个示例中，我们将多个`then`方法附加到函数上，并使用`done`方法完成处理。

### 注意

`done`方法接受与`then`相同的参数。然而，两者的区别在于`done`返回`undefined`而不是`Promise`，所以你不能链接它。此外，`done`方法如果在处理过程中没有提供`error`函数来处理任何错误，将抛出一个异常，而`then`函数不会抛出异常，而是返回`error`状态的`Promise`对象。

所有向 Windows Store 应用公开的 Windows 运行时 API 都被包装在`Promise`对象中，暴露出返回`Promise`对象的方法和函数，允许你在应用中轻松实现异步过程。

# 使用 WinJS.Utilities 查询 DOM

应用的界面由 HTML 和相应的样式描述。当应用启动时，你应该期待与界面不同的用户交互。用户将触摸应用的某些部分；他会滚动、缩放或添加/删除项目。此外，应用可能通过对话框或会话与用户交互，并通过在屏幕上发布通知来与用户交互。处理这些交互由代码完成，在我们的案例中，特别是由 JavaScript 代码完成。这时`WinJS.Utilities`就派上用场了，它提供了助手函数来完成这些任务；例如，添加/删除 CSS 类或插入 HTML 元素的功能。但在任何与用户交互之前，你必须使用 JavaScript 选择函数，这称为**查询 DOM**。

In Chapter 2, *Styling with CSS3*, we saw how to select parts of the DOM using CSS selectors. JavaScript has built-in functions to do so by using the traditional `document.getElementById` function. This function has a limited functionality and does not allow selecting from the DOM using the CSS selector syntax as the jQuery selectors do, however, now JavaScript includes `querySelector()` and `querySelectorAll()`. These two functions are more powerful and take CSS queries just as the jQuery selector syntax does. While the `querySelector()` function returns a single DOM element, the `querySelectorAll()` function returns a list of nodes. Both functions exist on the `document` and `element` objects. So, you can query the document to find all matching results in the entire document, or you can just query a single element to find all matching objects under it. For example:

```js
var postDiv = document.querySelector('#postDiv);
var allDivs = postDiv.querySelectorAll('div');
```

alongside these two JavaScript selection methods, the `WinJS.Utilities` namespace provides two functions with similar features for selecting elements, namely `id()` and `query()`. Basically, these functions wrap the `querySelector` and `querySelectorAll` functions but the return result value is different. The selector functions provided by `WinJS.Utilities` return a `QueryCollection` object, which in turn exposes various operations that perform actions over the elements of the collection, such as adding and removing a class and others.

The following code shows the syntax for using `id()` and `query()`. We first create a `WinJS.Utilities` object and call these two methods on it as shown:

```js
var utils = WinJS.Utilities; 
var postDiv = utils.id('postDiv');  
var allParagraphs = utils.query('p');
allParagraphs.setStyle("color", "red");
```

The following screenshot shows the IntelliSense window that lists the functions provided by the `WinJS.Utilities` namespace:

![Querying the DOM with WinJS.Utilities](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_03_02.jpg)

Querying the DOM is also useful when you need to apply a behavior to the elements of `document`. For example, you might want to add a functionality whenever the user clicks on a particular button. We do so by first querying for that element and then adding a `click` handler to it. The following code shows how:

```js
  WinJS.Utilities.id("Btn").listen("click", function () {
    var p = document.createElement("p");
    p.innerHTML = "i was just added";
    document.querySelector("#postDiv").appendChild(p);
});
```

In the previous code sample, the `listen()` method is used to wire an event handler to the `click` event of the button with the ID `Btn`; in this handler, we are creating a new `p` element and adding it to the `div` element with the ID `postDiv`.

### Note

The methods provided by the `WinJS.Utilities` namespace are like a simplified subset of the functions provided in jQuery.

The following is a list of some of the available methods that you can call on the objects returned in `QueryCollection`:

+   `addClass`

+   `clearStyle`

+   `getAttribute`

+   `hasClass`

+   `query(query)`

+   `removeClass`

+   `removeEventListener`

+   `setAttribute`

+   `setStyle`

+   `toggleClass`

+   `children`

# Understanding WinJS.xhr

The `xhr` function basically wraps the calls to `XMLHttpRequest` in a `Promise` object. The function is useful for cross-domain and intranet requests, as shown in the following code:

```js
  WinJS.xhr(options).then(
     function completed(result) {
….
      },
     function error(result) {
….
      },
     function progress(result) {
….
      },
```

由于`WinJS.xhr`函数异步处理并返回一个`Promise`对象，我们可以像 previous example 中所示，向它传递`then()`或`done()`方法。

你可以使用`WinJs.xhr`函数来连接 Web 服务并下载不同类型的内容，如文本或指定在`WinJS.xhr`的`responseType`选项中的 JSON 字符串。`responseType`选项取一个字符串值，指定从请求中期望的响应类型，类型如下：

+   `text`：这是默认值，期待一个字符串类型的响应。

+   `arraybuffer`：这期待一个用于表示二进制内容，如整数或浮点数数组的**ArrayBuffer**。

+   `blob`：这期待一个**Blob**（**Binary Large Object**），它是一个代表不可变原始数据的对象，通常文件大小较大。

+   `document`：这期待 XML 内容；也就是说，内容具有`text/xml`MIME 类型的内容。

+   `json`：这期待一个 JSON 字符串

+   `ms-stream`：这期待一个处理流数据的`msStream`对象，并用供应商特定的前缀（`ms`）标记，因为它尚未在 W3C 规范中定义。

除了`responseType`，还可以在`xhr`（`XMLHttpRequest`）对象上应用几个更多选项，这些都是可选的，除了`url`。这些选项如下：

+   `url`：这指定了一个字符串，它或者是 XML 数据或服务器端 XML Web 服务的绝对或相对 URL。

+   `type`：这指定了一个代表使用的 HTTP 方法的 string，例如`GET`、`POST`或`HEAD`。

+   `user`：这指定了一个代表用于身份验证的用户名的字符串，如果需要的话。

+   `password`：这指定了一个代表用于身份验证的密码的字符串，如果有的话。

+   `headers`：这指定了一个代表自定义 HTTP 头的对象。

+   `data`：这指定了一个包含将通过 HTTP 请求发送到服务器的数据的对象；这些数据直接传递给`XMLHttpRequest.send`方法。

+   `customRequestInitializer`：这指定了一个可以在`XMLHttpRequest`上用于预处理的函数。

让我们填充以下代码中如何从网站上检索一些文本的基本语法：

```js
WinJS.xhr(
{ url: 'http://www.msdn.microsoft.com/library', responseType: 'text' })
.done(function (request) 
{
    var text = request.responseText;
    document.getElementById("responseDiv").innerHTML = text;
},
function error(request) {
  var errorStatus = "Error returned: " + request.statusText;
  document.getElementById("errorDiv").innerHTML = errorStatus;
});
```

之前的代码示例将从一个指定的`url`字符串检索文本，并将其插入到`div`元素中，`responseDiv`；如果在处理过程中出现错误，我们通过`statusText`在错误处理函数中检索它。

### 注意

不建议使用`XMLHttpRequest`对象来请求可能需要很长时间才能完成的极其大型对象的传输，例如**Blob**和**FormData**对象。相反，你应该考虑使用 Windows 运行时 API 提供的文件上传 API 来进行此类操作。

# 引入一组新的控件

除了内容，您的应用程序还需要控件；常规的 HTML 控件，如按钮、选择列表和复选框；以及一些 Windows 8 独有的控件，如 AppBar 评分和设置。除了标准的内置 HTML 控件外，`WinJS`还提供了一组新的、功能丰富的控件，这些控件是为使用 JavaScript 的 Windows 商店应用程序设计的。这些控件基本上是`WinJS.UI`命名空间中可用的对象；因此，日期选择器控件看起来像`WinJS.UI.DatePicker`。以下是您在应用程序中使用的主要的`WinJS.UI`控件列表：

+   `DatePicker`：用于选择日期值的定制控件。

+   `TimePicker`：用于选择时间值的定制控件。

+   `Menu`：用于显示命令的菜单弹出控制。

+   `AppBar`：用于显示命令的应用程序工具栏。

+   `FlipView`：用于一次性显示一系列项目的集合。

+   `ListView`：用于以可自定义的网格或列表布局显示项目的控件。

+   `Flyout`：这是一个轻量级的控件，用于显示包含信息的弹出式控件，但它不会像对话框那样创建一个单独的窗口。

+   `Rating`：这是一个允许用户评分并可以显示三种类型评分—临时、平均或用户评分的控件。

+   `SemanticZoom`：这是一个可以让用户在缩放视图和放大视图之间缩放的控件，由两个提供每种视图的单独子控件提供：

+   `ToggleSwitch`：这是一个可以让用户在两个状态之间切换选项（开和关）的控制。

+   `Tooltip`：用于显示有关对象的弹出式控件，其中包含有关对象的更多信息，并支持丰富的内容（如图像）。

+   `ViewBox`：这是一个缩放其包含的单个子元素（不改变其宽高比）的控制，使其适合并填充可用空间。

    ### 注意

    这些控件会自动使用 Visual Studio 中创建的任何新的 Windows 8 商店应用程序项目中默认出现的两个样式表之一进行样式设计。这两个样式表（一个为深色主题，另一个为浅色主题）将给您的应用程序带来 Windows 8 的外观和感觉。

与标准的 HTML 控件不同，`WinJS.UI`控件没有专用的标记元素或属性标签；例如，您不能像正常添加标准 HTML 元素（如`<input/>`）那样，继续向您的标记中添加`WinJS.UI.Rating`元素（如`<rating/>`）。要添加一个`WinJS.UI`控件，您需要创建一个 HTML 元素，比如`div`，并使用`data-win-control`属性来指定您想要的控件类型。下面的代码显示了创建一个`WinJS.UI` `Rating`控件的语法：

```js
<div id="ratingControlDiv" data-win-control="WinJS.UI.Rating"> </div>
```

这将声明一个评分元素在标记中，但当你运行应用程序时，不会加载控件。为了激活你在标记中声明的任何`WinJS`控件，必须调用处理文档并初始化你创建的控件的`WinJS.UI.processAll()`函数。当你使用 Visual Studio 提供的任何模板创建应用程序时，`default.js`文件中在`app.onactivated`事件处理程序中包含了对`WinJS.UI.processAll`的调用。

当你运行应用程序时，你会看到如下的新`Rating`控件：

![介绍一组新的控件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_03_03.jpg)

你也可以通过调用其构造函数并在构造函数中传递将托管此控件的 HTML 元素来在代码中创建`WinJS`控件。例如，如果我们有一个`div`元素，其`id`属性为`ratingControlDiv`，创建`Rating`控件的 JavaScript 将如下所示：

```js
var ratingHost = document.getElementById("ratingControlDiv");
var ratingControl = new WinJS.UI.Rating(hostElement);
```

在这种情况下，将无需调用`WinJS.UI.processAll`函数，因为你没有在标记中创建 JavaScript 控件。

此外，设置`WinJS`控件的属性与设置标准 HTML 控件的属性不同；后者有专门用于此目的的属性。例如，类型为`range`的`input`元素有`min`和`max`属性，其值可以在标记中如以下代码所示设置：

```js
<input type="range" min="2" max="10" />
```

对于 JavaScript 控件，我们必须在标记中使用`data-win-options`属性来设置属性，它是一个包含一个或多个属性/值对的字符串（多个属性以逗号分隔），在基本形式下如以下代码所示：

```js
data-win-options="{propertyName: propertyValue}"
```

下面的语法将显示如何为`WinJS.UI.Rating`控件设置`minRating`和`maxRating`属性：

```js
<div id="ratingHostDiv" data-win-control="WinJS.UI.Rating"
    data-win-options="{ minRating: 2, maxRating: 10}"> 
</div>
```

# 总结

我们已经瞥见了`WinJS`在 Windows 8 中的某些功能和强大特性。我们学习了如何使用`Promise`对象实现异步编程。

此外，我们还介绍了`WinJS.Utilities`命名空间中提供的方法，这些方法允许我们检索和修改 HTML 文档的元素。我们还介绍了使用`WinJS.xhr()`函数检索不同类型内容的方法。

最后，我们学习了`WinJS`库提供的新一组控件以及如何创建这些 JavaScript 控件并设置它们的属性。

在下一章中，我们将开始使用 JavaScript 开发应用程序，首先介绍所需的工具，然后学习为 Windows 8 JavaScript 应用程序提供的模板。此外，我们将创建一个非常基础的应用程序，并了解 JavaScript 应用程序的解剖结构。我们还将学习 ListView 控件。


# 第四章：使用 JavaScript 开发应用程序

在本章中，我们将学习如何使用 JavaScript 开始开发 Windows 8 应用程序。首先，我们将学习有关工具的知识，然后我们将介绍如何获取开发者许可证。之后，我们将从为 Windows Store 应用程序开发提供的模板中选择一个，从一个空白模板构建一个示例应用程序，并对其进行修改，以便我们了解一些 JavaScript 应用程序的功能。

# 介绍工具

Windows 8 引入了一种新类型的应用程序——Windows Store 应用程序，这种应用程序只能在 Windows 8 上运行。所以，为了开始开发，你首先需要在你的电脑上安装 Windows 8，第二，你需要所需的开发工具。

获取 Windows 8 有两个选择；一种选择是从 MSDN 的订阅者下载处获取，如果你在那里有订阅的话。另一种选择是，如果你没有 MSDN 账户，你可以从通过 MSDN 网站上的[`msdn.microsoft.com/en-US/evalcenter/jj554510.aspx?wt.mc_id=MEC_132_1_4`](http://msdn.microsoft.com/en-US/evalcenter/jj554510.aspx?wt.mc_id=MEC_132_1_4)找到的*评估中心*获取 Windows 8 企业版的 90 天评估版本。

### 注意

请注意，评估版在过期后无法升级。

在安装 Windows 8 之后，你需要下载开发工具，这些工具在 MSDN 网站上免费提供，可以在[`msdn.microsoft.com/en-US/windows/apps/br229516.aspx`](http://msdn.microsoft.com/en-US/windows/apps/br229516.aspx)的*Windows 开发者中心*页面找到。Windows 开发者中心拥有全新的改进布局，是你获取所有工具和资源的首个起点，可以在**Windows Store 应用程序开发下载**部分找到。

必要的下载是包含 Visual Studio Express 的捆绑包，这将是你开发 Windows 应用程序的工具。这个下载的链接可以在**Windows 8 的 Visual Studio Express 2012**部分找到，并包括以下文件：

+   微软视觉工作室 Express 2012 for Windows 8

+   微软视觉工作室 2012 的 Blend

+   Windows 8 软件开发工具包（SDK）

+   Windows Store 应用程序项目模板（在微软视觉工作室 2012 中提供）

此外，你还可以在该页面上找到其他可用的下载，例如：

+   设计资源：这包括必要的 Photoshop 模板（`.psd`文件），其中包括模板、常用控件和常见组件，如合同、通知和磁贴，这些是设计应用程序所需的。

+   示例应用程序包：这包括数百个来自微软的代码示例，可以帮助你快速启动项目并了解大部分功能。这适用于所有或特定编程语言。

+   Windows 8 动手实验室：这包括一系列八个动手实验室模块，这些模块将引导您开发一个名为 Contoso Cookbook 的 Windows Store 应用。这包含了 Windows 8 中许多关键的新功能。这些实验室系列可通过 JavaScript 和 HTML，或 C#和**可扩展应用程序标记语言**（**XAML**）获得。

+   Live SDK：这包括一组控件和 API，我们可以使用它们来使应用与 Microsoft 账户集成**单点登录**（**SSO**），并访问来自 SkyDrive、Hotmail 和 Windows Live Messenger 的信息。

    ### 注意

    由于 Visual Studio 2012 仅支持 Windows 8 的 Windows Store 应用开发，因此即使安装了 Visual Studio 2012，您也无法在 Windows 7 上开发应用。而且，由于没有为 Windows Server 2012 提供开发者许可证，所以您也无法在 Windows Server 2012 上开发 Windows Store 应用。

    请注意，您可以使用 Visual Studio 2012 的其他任何版本来开发 Windows Store 应用，包括 Ultimate、Premium、Professional 和 Test Professional 版本。

## 获取免费开发者许可证

为了开始开发 Windows Store 应用，您需要拥有 Windows 8 的开发者许可证。这个许可证允许您在 Windows Store 测试和认证之前，在本地安装、开发、测试和评估应用。此外，开发者许可证是免费的，您不需要 Store 账户就可以获得一个；它只需要一个 Microsoft 账户，并且每个账户可以获取多个许可证。许可证在 30 天后过期，必须续订。如果您已经有了一个 Windows Store 账户，许可证将为您提供 90 天服务。在您在本地计算机上获得许可证之后，除非许可证过期或您删除它（可能通过格式化或卸载 Visual Studio），否则在该计算机上不会再提示您。获得一个许可证非常简单；您可以使用 Visual Studio 2012 来获取开发者许可证。当您第一次在 Windows 8 上运行它时，它会提示您获得一个开发者许可证；您只需要使用您的 Microsoft 账户登录即可。您总是可以尝试通过使用 Visual Studio 中的商店选项来获取或续订 Windows 8 的开发者许可证，我们将在第十章 *打包和发布* 中详细讨论打包和发布应用时，学习如何发布应用。

### 注意

请记住，如果您还没有这样做，第一次尝试运行应用时将被提示获取开发者许可证。

下面的屏幕截图显示了使用 Visual Studio 2012 Ultimate 的过程。请前往**项目** | **商店** | **获取开发者许可证**。

![获取免费开发者许可证](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_04_01.jpg)

如果您使用的是 Express 版，您将在顶部菜单中直接有一个**商店**选项，而不是在**项目**下面。您只需前往**商店** | **获取开发者许可证**。

### 注意

选择不获取或续签开发者许可证，当你尝试在 Visual Studio 中构建或部署应用时，将会导致错误（代码 DEP0100）。

安装 Windows 8 和所需工具并获得开发者许可证后，您就可以开始构建您的第一个应用了。您开始时需要选择一种编程语言来使用。如我们之前提到的，Windows 8 允许您基于您的编程语言知识库进行构建，并用您已经知道的编程语言进行开发（除非您想学习新东西）。如果您从事网页开发，可以选择 JavaScript 作为您的编程语言，并使用最新的网页开发技术（例如 HTML5 和 CSS3），这本书就是关于这些内容。如果您来自.NET 背景，可以选择 Visual C#或 Visual Basic 和 XAML。您还有使用 C++选项，分别是 C++和 XAML，或者 C++和 DirectX。

# 使用 Visual Studio 及其模板

所以现在我们有了工具。有了 Visual Studio 作为我们的游乐场和 JavaScript 作为我们的编程语言，我们已经准备就绪可以开始开发了。我们将从为 Windows Store 创建一个新项目开始。点击**文件** | **新建项目**。向下钻取到**已安装**，然后到**模板**，再到**JavaScript** | **Windows Store**，并选择一个模板类型，如下面的屏幕截图所示：

![使用 Visual Studio 及其模板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_04_02.jpg)

正如你在之前的屏幕截图中所看到的，在**新建项目**对话框的中心面板上有五种模板可供选择。这些模板随 Visual Studio 2012 提供，为您提供了良好的起点，并帮助您快速启动和加速应用的开发。这些项目模板，按照它们在**新建项目**对话框中出现的顺序，如下所示：

+   **空白应用**：这是一个基本的工程项目模板，创建一个空的 Windows Store 应用，可以编译和运行。然而，它不包含任何用户界面控件或数据。

+   **网格应用**：这是一个提供网格视图格式的内容的工程项目。它是允许用户浏览数据类别以查找内容的应用程序的良好起点。其使用的一些例子包括 RSS 阅读器、购物应用、新闻应用和媒体画廊应用。

+   **分割应用**：这是一个提供内容分割视图的项目，其中数据以两栏的主/详细视图显示，列表数据在一侧，每个单一数据项的详细信息在另一侧，就像 Outlook 一样。其使用的一些例子包括新闻阅读器应用、体育比分应用和电子邮件应用。

+   **固定布局应用**：这是一个基本且最小的模板项目，类似于使用**空白应用**模板创建的应用，不同之处在于此布局中的内容针对固定布局视口，即当窗口大小变化时容器会自动调整大小以适应显示区域；这种缩放是通过使用`ViewBox`控件来保证的。

+   **导航应用**：这是一个创建采用单页导航模型（Windows Store 应用推荐使用）的项目。您不能仅通过在标记中添加`锚点`链接来实现导航模型；相反，导航模型是通过使用`navigator.js`文件来实现的，该文件也可以在网格和分屏模板中找到，而**空白应用**和**固定布局应用**模板则不包含此文件，因此您必须手动添加该文件。

    ### 注意

    **网格应用**和**分屏应用**模板不仅是一个构建应用程序的好起点，而且也是很好的学习模板，能让您对应用程序是如何构建的以及它由什么组成有一个很好的了解。

三个模板**空白应用**、**网格应用**和**分屏应用**可供 Windows Store 开发中所有可用的编程语言使用。每个项目模板都包含了实现它所代表功能的必要文件，无需您进行任何开发；例如，创建一个新的网格应用并运行它，将会得到如下应用程序：

![使用 Visual Studio 及其模板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_04_03.jpg)

结果是一个准备好用于 Windows Store 的应用程序，其中包含带有启用导航的示例数据，甚至支持**粘贴和填充布局**，这是当分辨率在并排的两个应用程序之间分配时应用程序存在的布局。所有这一切甚至不需要编写一行代码！所以，想象一下，如果您通过为布局应用不同的样式并在内容中显示真实数据（比如说，新闻网站的 RSS 源），对这个最小化的应用进行一些定制，您将很快拥有一个超过 75%准备好上架的应用程序（还缺少一些功能，比如语义缩放、应用栏和设置）。

您还可以直接从 Visual Studio 下载示例。这些示例提供了完整且可运行的代码示例，可以编译并作为 Windows Store 应用运行，旨在展示 Windows 8 中可用的各种新的编程模型、平台、功能和组件。

## 项目项模板

除了项目模板之外，还有特定于 Windows Store 应用的语言项模板，在我们的案例中，称为**JavaScript 项模板**。这些项模板是可以添加到已存在项目中的应用程序文件，包含常用的代码和功能（可以把它看作是一个用户控件），并且有助于减少开发时间。可以通过右键点击顶部菜单中的**项目**，然后选择**添加** | **新建项**，来添加项模板。有四个 JavaScript 项模板可供使用；它们如下所示：

+   **页面控制**：这包含了应用程序中页面的基本内容和标记。其中包括一个带有返回按钮的头部区域和一个主要内容区域。每个**页面控制**模板将包括三个要添加到项目的文件（一个包含所需标记的 HTML 文件，一个包含与页面相关的代码的 JavaScript 文件，以及一个为页面提供特定样式的 CSS 文件）。

+   **文件打开选择器合同**：这将添加一个功能，使应用程序能够使用**文件选择器**对话框将其数据作为文件列表提供给其他请求文件的应用程序。它还将文件显示在 ListView 控件中。这个合同的一个典型用途是在创建一个照片选择器对话框时。

+   **搜索合同**：这将添加一个允许应用程序响应来自 Windows 8 中搜索磁贴的搜索查询的搜索合同。它包含一个搜索结果页面，用于向用户展示结果。如果您的应用程序有一些可以搜索的数据，添加这个合同是很重要的。

+   **分享目标合同**：这将向应用程序添加一个分享合同，允许应用程序与其他应用程序共享数据，并使其与 Windows 8 中的分享磁贴集成。所以，如果应用程序具有此合同，它将出现在分享 UI 中的应用程序列表中。这个模板的典型用途是允许用户将链接或照片发布到 Facebook，Twitter 或任何其他接收共享内容的其他应用程序。反之亦然，它还将允许应用程序接收共享内容；因此，应用程序可以表现得像 Facebook 或 Twitter。

下面的屏幕截图显示了带有前面列出的项目模板的**添加新项**对话框：

![项目模板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_04_04.jpg)

### 注意

我建议您将每个项目模板添加到单独的文件夹中，并且文件夹名称与其相关联。由于每个项目模板都增加了三个相关文件，如果您将它们分组到单独的文件夹中，解决方案将更加整洁和有序。例如，为页面创建一个文件夹，并在其中为每个页面创建一个文件夹；合同部分也是如此。

选择一个应用程序模板并将其加载到 Visual Studio 之后，您基本上已经创建了一个非常简单的应用程序；这个应用程序可以直接编译和运行。使用 Visual Studio，您可以在本地计算机或模拟器上运行应用程序。要在本地计算机上运行它，只需按*F5*键来构建，部署并启动应用程序。

### 注意

请注意，您可以选择不部署解决方案，但是应用程序不能直接运行；您需要从开始菜单中的其他应用程序中找到它，然后手动启动它。

还有一种通过以太网电缆直接连接远程设备运行的方法。要使用模拟器，您只需要从运行菜单中选择以下屏幕截图所示的选项：

![项目模板](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_04_05.jpg)

Windows 8 模拟器是一个极好的工具，能帮助你测试和调试应用；它允许你像在真实设备上一样测试功能，特别是如果你在开发过程中没有平板电脑或触控设备。它能让应用在横屏和竖屏之间改变分辨率，并在不同的应用布局和视图状态（嵌入式和全屏）之间切换。此外，你还可以测试应用对触摸和手势（如滑动和捏合缩放）的响应。在开发过程中，我们无法在笔记本电脑或 PC 上尝试所有这些功能和特性。

### 注意

当你在 Visual Studio 中以调试模式运行应用时，你可以更改代码和标记，并刷新应用以查看更改，而无需重新构建/重新运行。你可以使用**刷新 Windows 应用**按钮来实现，该按钮将在暂停、停止和重新启动调试按钮旁边出现，仅在你从 Visual Studio 中运行应用后出现。

# 开始使用空白应用

让我们使用**空白应用**模板开始创建一个最小应用；我们首先需要做的是启动 Visual Studio 2012，创建一个新项目，并前往**JavaScript** | **Windows Store** | **空白应用**。尽管空白应用在运行时看起来很空，但它包含了一些使用 JavaScript 创建的 Windows Store 应用所需的文件；其他所有模板都将包含这些文件。以下屏幕截图显示了此应用在**解决方案资源管理器**窗口中的结构：

![开始使用空白应用](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_04_06.jpg)

此前的屏幕截图展示了简单应用的骨架，包括以下文件：

+   `Windows Library for JavaScript 1.0`：Windows Library for JavaScript 是一个 CSS 和 JavaScript 文件的库。当你深入这个文件夹时，你会看到它包含两个子文件夹，如下所示：

    +   `css`：此文件夹包括两个主要的 CSS 样式表，它们是`ui-dark.css`和`ui-light.css`，这些样式表为应用提供了 Windows 8 的外观和感觉。正如它们的名称所暗示的，第一个将应用一个深色主题，而第二个将应用一个浅色主题。你可以在 HTML 页面中引用其中的一个来选择。

    +   `js`：此文件夹包括`base.js`和`ui.js`；这两个文件包含了提供控件、对象和帮助函数的 JavaScript API，所有这些都组织成名称空间，这将使使用 JavaScript 的开发体验变得更加容易。

+   `default.css`：这是包含应用 CSS 样式的样式表。

+   `images`：此文件夹包含展示应用及其身份所需的图片（两个标志、启动屏幕图片和商店标志）。

+   `default.js`：此 JavaScript 文件实现了应用的主要功能，并包含了处理应用生命周期的代码。在这个文件中，你可以编写与`default.html`页面相关的任何附加代码。

+   `default.html`：这是应用程序的起始和主页，当应用程序运行时首先加载。它提供了内容宿主（主窗口中加载每个页面）的标记。

+   `package.appxmanifest`：这是清单文件。它基本上通过指定描述应用程序的属性，如名称、描述、起始页面等，来描述 Windows 上的应用程序包。

+   `TestApp_TemporaryKey.pfx`（`AppName_TemporaryKey.pfx`）：这个文件签署了`.appxmanifest`文件。

让我们来看一下`default.html`页面，这是应用程序的起始页面（在这个案例中，也是唯一页面）：

```js
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>TestApp</title>
    <!-- WinJS references -->
  <link href="//Microsoft.WinJS.1.0/css/ui-dark.css" rel="stylesheet" />
  <script src="img/base.js"></script>
  <script src="img/ui.js"></script>

  <!-- TestApp references -->
  <link href="/css/default.css" rel="stylesheet" />
  <script src="img/default.js"></script>
</head>
<body>
  <p>Content goes here</p>
</body>
</html>
```

从`Doctype html`可以看出，页面是 HTML5 的。我们在`<head>`中放置了应用程序的标题，然后是 JavaScript（`WinJS`）文件的引用。引用用`WinJS` `references`注释标记。首先引用`.css`文件，这样脚本的加载就不会延迟或阻碍样式的加载，如果`.js`文件对样式表进行了某些修改，需要在加载样式之前加载样式。这里应用了深色主题；你可以简单地将其更改为浅色主题，通过如下更改引用：

```js
<link href="//Microsoft.WinJS.1.0/css/ui-light.css" rel="stylesheet" />
```

### 注意

不要修改`WinJS`的 CSS 和 JavaScript 文件。最好创建样式或 JavaScript 函数，在不同文件中覆盖现有的样式和功能，并将它们应用于应用程序。

在`WinJS`引用下，有对应用程序特定的样式表和 JavaScript 文件的引用，这些引用通过注释清晰地区分。

然后是 body 部分。在这里，以空白应用程序为例，body 只包含简单文本。

如果你尝试以当前状态启动应用程序，你会看到屏幕上覆盖着黑色背景，还会看到文本：**内容在此处**。在这个页面出现之前，你会注意到一个启动屏幕出现几秒钟，显示在清单文件中指定的启动屏幕图像。让我们尝试通过修改我们的起始页面并向 body 添加一些标记，给这个空白应用程序带来一些生命，就像你之前处理过的任何 HTML 页面一样。

用以下内容替换现有的段落元素：

```js
<body>
  <h1>The Test App</h1>
  <p>Add some content </p>
  <input id="contentInput" type="text" />
  <button id="sayButton">Have your say</button>
  <div id="contentOutput"></div>
</body>
```

运行应用程序；它将显示我们刚刚添加的标记。我们可以在`input`元素中输入任何文本，但点击按钮将没有效果。所以让我们为这个按钮创建一个事件处理程序，在`div`中输出我们在`input`元素中添加的内容。我们需要在`default.js`文件中创建事件处理程序，因为那里是我们编写与`default.html`页面交互的额外代码的地方。

首先让我们来看一下这个`default.js`文件。你会注意到里面有一些用单个函数包裹的代码，如下所示：

```js
(function () {
   "use strict";
  …
})();
```

这段代码代表了一个自执行的匿名函数，它包含所有你的代码以避免任何命名冲突，并保持全局命名空间干净，没有不必要的标识符。匿名函数的第一行代码声明了关键字`use strict`，它为 JavaScript 代码开启了严格模式。这种严格模式提供了更好的错误检查，例如防止你给只读属性赋值。在这行之后，你会看到剩下的代码，它通过添加`app.onactivated`和`app.oncheckpoint`事件处理程序来处理应用程序的激活和检查点状态。我们添加在`app.onactivated`事件处理程序内部的代码将在应用程序启动时添加。

现在回到按钮事件处理函数；我们创建一个如下函数：

```js
function buttonClickHandler(eventInfo) { 
  var text = document.getElementById("contentInput").value; 
  var outputString = "I say " + text + "!";
  document.getElementById("contentOutput").innerText = outputString; 
}
```

在最底部的`app.start()`调用之前的匿名函数内部添加这个函数。这个函数从`input`元素中获取文本并将其添加到`div`元素中。为了将这个函数添加到按钮的事件中（在本例中，是`onclick`事件），我们需要为按钮注册一个事件处理程序。建议通过调用`addEventListener`方法来完成。当应用程序被激活时，我们需要注册这个事件处理程序。因此，我们应该在`app.onactivated`事件处理程序内部添加它。代码如下所示：

```js
var app = WinJS.Application;
var activation = Windows.ApplicationModel.Activation;

app.onactivated = function (args) {
  if (args.detail.kind === activation.ActivationKind.launch) {
       if (args.detail.previousExecutionState !== activation.ApplicationExecutionState.terminated) {
      // TODO: This application has been newly launched. Initialize
         // your application here.
    } else {
  // TODO: This application has been reactivated from suspension.
  // Restore application state here.
     }
     args.setPromise(WinJS.UI.processAll());

     // Retrieve the button and register our event handler.
     var sayButton = document.getElementById("sayButton");
     sayButton.addEventListener("click", buttonClickHandler, false);
}
};
```

`app`变量是一个全局变量，代表提供应用程序级别功能的`Application`类的实例；例如，处理不同的应用程序事件，如我们之前代码列表中看到的`onactivated`事件。

在`onactivated`处理程序内部，代码检查发生的是哪种类型的激活；在本例中，是启动激活，这意味着该应用程序在没有运行时被用户激活。然后调用`WinJS.UI.processAll()`。这将扫描`default.html`文件中是否有任何`WinJS`控件，并将初始化它们。由于按钮不是一个`WinJS`控件，而是一个基本的 HTML 控件，我们可以在调用`WinJS.UI.processAll()`之前添加它，但最好在之后注册事件处理程序。

运行应用程序，在文本框中输入一些文本，当点击按钮时显示内容，如下面的屏幕截图所示：

![Blank App 入门](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_04_07.jpg)

# 理解 ListView 控件

在上一章中，我们介绍了一个由 Windows 库为 JavaScript 提供的新控件集；这些控件中的一个是 ListView 控件，标记为`WinJS.UI.ListView`。这个对象的基本作用是显示可自定义的列表或网格中的数据项。要创建一个 ListView 控件，我们需要向`div`元素添加`data-win-control`属性，并将其属性设置为`WinJS.UI.ListView`。在`default.html`页面中，在`body`标签内部添加以下代码：

```js
<body>
  <div id="sampleListView" data-win-control="WinJS.UI.ListView">
  </div>
</body>
```

这将创建一个空的 ListView。所以，如果我们运行该应用，将看不到任何东西。由于这是一个`WinJS`控件，它将在我们调用`WinJS.UI.processAll`函数后才在标记 up 中渲染。

让我们给`sampleListView`控件添加一些数据以显示。这些数据可能来自网络数据库或 JSON 数据源，将手动创建数据源，最好在单独的 JavaScript 文件中，这样更容易维护。所以，在 Visual Studio 中，在`js`文件夹下，添加一个新项目并选择一个 JavaScript 文件；将其命名为`data.js`。打开这个新创建的文件，创建一个带有严格模式的匿名函数，就像我们在`default.js`文件中看到的那样；在这个函数内部，让我们创建一个由对象组成的样本数组，这些对象构成了我们需要的数据源。给数组中的每个对象赋予三个属性`firstName`、`lastName`和`Age`。

最终代码将如下所示：

```js
(function () {
    "use strict";
    //create an array for a sample data source
    var dataArray = [
    { name: "John Doe", country: "England", age: "28" },
    { name: "Jane Doe", country: "England", age: "20" },
    { name: "Mark Wallace", country: "USA", age: "34" },
    { name: "Rami Rain", country: "Lebanon", age: "18" },
    { name: "Jean Trops", country: "France", age: "56" }

    ];

    //create a list object from the array
    var sampleDataList = new WinJS.Binding.List(dataArray);
})();
```

接下来，我们使用刚刚创建的数组来创建一个 List 对象；然后我们需要通过声明一个命名空间并将其作为公共成员添加来暴露这个 List 对象：

```js
    // Create a namespace to make the data publicly
    // accessible. 
    var publicMembers =
        {
            itemList: sampleDataList
        };
    WinJS.Namespace.define("DataSample", publicMembers);
```

为了使 ListView 控件能够访问这个列表，我们使用了`WinJS.Namespace.define`函数来创建一个命名空间，并将列表作为其成员之一，从而使列表公开可用，因为它是匿名函数中创建的，这使其保持私有。`WinJS.Namespace.define`函数接受两个参数，正如你在之前的代码中注意到的那样。第一个参数是要创建的命名空间的名字，第二个参数表示包含一个或多个键/值对的对象（`publicMembers`）。

在创建数据源并使其被 ListView 控件访问后，下一步是将数据源连接到 ListView 控件。这必须在`default.html`文件中完成。让我们从我们留下的示例空白应用开始。我们需要添加对我们刚刚创建的数据文件的引用，如下所示：

```js
<!-- Sample data file. -->
<script src="img/data.js"></script>
```

然后我们将`data-win-options`属性添加到`div`元素中，并使用我们在`data.js`中创建的数据源来设置`data-win-options`属性内的`itemDataSource`属性。将 ListView 控件的`itemDataSource`属性设置为`DataSample.itemList.dataSource`，如下所示：

```js
<div id="sampleListView" data-win-control="WinJS.UI.ListView" 
 data-win-options="{ itemDataSource : DataSample.itemList.dataSource }">  
</div>
```

`DataSample.itemList.dataSource`命名空间包括`DataSample`，这是我们之前注册的命名空间；`itemList`，是我们注册在命名空间上的对象的属性名称；最后是`dataSource`，它是`WinJS.Binding.List`方法的一个属性（我们之所以能在`itemList`上调用它，是因为后者被分配给了我们从数组创建的 List 对象）。

如果我们现在运行该应用，我们会看到 ListView 控件以无格式的方式显示我们创建的数组，如下所示：

```js
    { name: "John Doe", country: "England", age: "28" }
    { name: "Jane Doe", country: "England", age: "20" }
    { name: "Mark Wallace", country: "USA", age: "34" }
    { name: "Rami Rain", country: "Lebanon", age: "18" }
    { name: "Jean Trops", country: "France", age: "56" }
```

我们可以通过覆盖 Windows Library for JavaScript 中定义的`win-listview`类中的默认样式来样式化这个 ListView 控件，以样式化 ListView 控件。为了覆盖默认样式并将一些样式应用到此 ListView 控件上，请复制`win-listview`类并将其前缀与我们要创建的`div`元素的特定 ID 一起使用，如下所示：

```js
#sampleListView.win-listview {
  width: 500px;
  border: 1px solid gray;
}
```

我们可以在 ListView 内部添加更多的样式，并且可以使用`WinJS.Binding.Template`定义项目模板，以定义我们要使用来显示每个列表项及其样式的标记。创建`WinJS.Binding.Template`控件非常简单；在 HTML 页面上，添加一个`div`元素并将数据属性`data-win-control`的属性设置为`WinJS.Binding.Template`。在其中，再添加一个将作为模板内容的父元素的`div`元素，因为`WinJS.Binding.Template`必须有一个单一的根元素。在这个父元素内部，我们添加将要创建的标记，ListView 将使用它来填充它包含的每个数据项。现在模板将看起来像这样：

```js
<body>
<div id="sampleTemplate" data-win-control="WinJS.Binding.Template"> 
      <div style="width:200px; height: 100px">    
           <div>    
              <!-- Displays the "name" field. -->
              <h2> </h2>
              <!-- Displays the "country" field. -->
              <h3> </h3>
              <!-- Displays the "age" field. -->
              <h6 style="color:red"> </h6>
           </div>    
      </div>
</div>
</body>      
```

为了将每个元素链接到特定的数据项属性，我们在每个显示数据的元素上使用`data-win-bind`属性。`data-win-bind`属性使用此语法：`data-win-bind="propertyName: dataFieldName"`。因此，要设置`h2`、`h3`和`h6`元素上的 name 属性，我们使用以下代码：

```js
<!-- Displays the "name" field. -->
<h2 data-win-bind="innerText: name"></h2>
<!-- Displays the "age" field. -->
<h3 data-win-bind="innerText: country"></h3>
<!-- Displays the "age" field. -->
<h6 style="color:red" data-win-bind="innerText: age"></h6>
```

请注意，列表项模板（`WinJS.Binding.Template`）在标记 up 中应该在 ListView 控件之前，仅仅是因为 HTML 标记是层次化的，每个 UI 元素都将按遇到它们的顺序进行渲染。因此，当 ListView 控件正在渲染并绑定到`itemTemplate`元素时，这个`itemTemplate`元素必须首先存在；否则它会抛出错误。

最后，我们需要将我们刚刚创建的绑定模板应用于 ListView 控件。因此，使用`select`语法将 ListView 的`itemTemplate`属性设置为`sampleTemplate`，如下所示：

```js
<div id="sampleListView" data-win-control="WinJS.UI.ListView" 
data-win-options="{ itemDataSource : DataSample.itemList.dataSource, itemTemplate: select('#sampleTemplate') }">
</div>
```

如果我们现在运行该应用程序，ListView 控件将以一种更合适的方式显示数据。它看起来会是这样：

![了解 ListView 控件](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_04_08.jpg)

# 概要

在本章中，我们已经介绍了使用 JavaScript 创建 Windows Store 应用程序的基础知识。我们了解了工具，以及我们需要的开发入门知识。然后我们了解了如何使用 Visual Studio 2012，并查看了为使用 JavaScript 进行开发提供的模板。

我们了解了如何从零开始构建一个应用程序，在过程中我们看到了 JavaScript Windows Store 应用程序的解剖结构；我们将这个空白应用程序修改为以最简单的方式进行交互，只需点击一个按钮。最后，我们学习了如何使用 ListView 控件来显示数据。

在下一章中，我们将学习如何获取我们想要显示的数据。


# 第五章：绑定数据到应用

在本章中，我们将学习如何从不同的数据源实现数据绑定到应用中的元素。Windows 库为 JavaScript 提供了数据源对象，可以用来填充`WinJS`控件如`ListView`或`FlipView`的不同类型的数据。我们有`WinJS.Binding.List`对象，用于访问数组和 JSON 数据，还有`StorageDataSource`对象，提供对文件系统信息的访问。这两个数据源对象使我们能够查询并在数据源中绑定项目。此外，我们还将学习如何对数据源进行排序和筛选，并使用`ListView`控件显示其数据。

# 获取数据

**Windows 库用于 JavaScript 绑定的**（`WinJS.Binding`）提供了一种将数据和样式绑定到 HTML 元素的方法。Windows 库提供的 JavaScript 绑定默认是单向的，所以当数据发生变化时，HTML 元素会被更新；然而，HTML 元素的任何变化都不会反映到绑定到的数据上。让我们通过实际操作来了解这一点，并且我们从最基本的绑定类型开始，即 HTML 元素与仅包含数据的简单 JavaScript 对象之间的声明性绑定。

首先，我们将检查`WinJS.Binding.optimizeBindingReferences`属性，如果尚未设置，则将其设置为`true`。

### 提示

在执行声明性绑定时，始终设置`WinJS.Binding.optimizeBindingReferences`属性为`true`非常重要。此属性决定是否应自动为元素的 ID 设置绑定。在使用`WinJS.Binding`的应用程序中，应将此属性设置为`true`。

我们将创建一个包含两个属性的 sample `person` JavaScript 对象，`name`和`badgeColor`，如下面的代码所示：

```js
var person = { name: "John", badgeColor: "Blue"};
```

现在，我们将使用数据属性`data-win-bind`将 HTML `span`元素绑定到`person`对象，如下面的代码所示：

```js
<span id="nameSpan" data-win-bind="innerText: name"></span>
```

为了使绑定发生并且随后在`span`元素中显示名称，我们必须调用`WinJS.Binding.processAll()`方法，并传递给它 DOM 元素和`dataContext`对象；它会从这个指定的元素开始寻找`data-win-bind`属性，然后遍历该元素的的所有后代。

以下代码从 DOM 中获取`span`元素，然后将参数传递给`WinJS.Binding.processAll()`方法：

```js
var nameSpan = document.getElementById("nameSpan");
WinJS.Binding.processAll(nameSpan, person);
```

### 提示

如果你正在使用这个示例的 default.HTML 页面，你需要在调用`args.setPromise(WinJS.UI.processAll())`之后添加代码，以便所有控件都已初始化，如在第三章 *JavaScript for Windows Apps*中解释的那样。

运行项目后，你将在屏幕上看到**John**这个名字。前面的代码只实现了一个静态绑定，这意味着文本不会受到数据变化的影响。这是因为 JavaScript 对象本身无法通知应用程序当它发生变化。我们可以使用`WinJS.Binding.as`将这个对象变为可观察的对象，这将使得数据源在对象中的项发生变化时得到通知。以下代码片段将创建一个`bindingSource`对象，它表示我们创建的`person`对象的观测实例；因此，对`bindingSource`的任何更改都将反映在与它绑定的 HTML 元素上：

```js
var bindingSource = WinJS.Binding.as(person);
```

让我们看看动态数据绑定的实际效果。首先，向输入姓名值和`button`元素的`input type`中添加代码，如下面的代码所示：

```js
<input type="text" id="nameInpt" />
<button id="setNameBtn">Get name</button>
```

然后，我们编写模拟`person`数据对象变化的代码。我们通过在`setNameBtn`按钮的点击事件中设置`person`对象的`name`属性为在`input`元素中输入的新值来实现，如下面的代码所示：

```js
document.getElementById("setNameBtn").onclick = function () {
  var newName = document.getElementById("nameInpt").value;
  bindingSource.name = newName;
}
```

运行项目，尝试在`input`元素中输入新值，然后点击按钮查看名称是否发生变化。

我们不仅可以将数据绑定到 HTML 元素上，还可以在样式级别应用绑定。回到上一个例子，让我们将`style.background`值添加到数据属性中，并绑定到`person`对象的`badgeColor`字段，如下面的代码所示：

```js
data-win-bind="innerHTML: name; style.background: badgeColor"
```

做出上述更改后，刷新应用，名字将会用蓝色高亮显示。当你运行应用时，输出应该看起来像下面的截图（如果你引用的是`ui-light.css`样式表，输出将会是蓝色的一种更深的阴影）：

![获取数据](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_05_01.jpg)

在 Windows Store 应用中，还有其他几种数据访问和存储的方法；数据源可以是本地或远程，你选择的存储方式基本上取决于当前的场景。例如，一个需要保持连接并始终运行的 Windows Store 应用就需要访问来自远程在线源的数据。这些数据可能来源于网页 URL 或 RESTful 服务。理想情况下，使用我们在第三章*JavaScript for Windows Apps*中介绍的`WinJS.xhr`函数来消费这些网络服务。

`WinJS.xhr`函数将向一个 web URL 或服务发起异步请求，并在成功调用后返回响应中的数据。假设我们需要获取一些推文并解析结果；在这个案例中，调用非常直接。为此，提供 Twitter 搜索服务的 URL，该服务将搜索包含`windows 8`的所有推文，如下面的代码所示：

```js
WinJS.xhr({ 
url: "http://search.twitter.com/search.json?q=windows8"}).then(
function (result) {
});
```

输出将是一个包含与查询匹配的所有推文的 JSON 字符串，这是许多网站提供的数据格式。Windows 8 JavaScript 对 JSON 有原生支持，因此，我们可以通过调用`JSON.parse(jsonString)`将 JSON 字符串反序列化为一个对象。让我们将前面的代码添加如下：

```js
WinJS.xhr({
  url: "http://search.twitter.com/search.json?q=windows8"}).then(
  function (result) {
    var jsonData = JSON.parse(result.responseText);
  });
```

我们还可以使用 Windows 提供的`Windows.Storage` API 文件从文件中读取数据。如果我们有一个可读文件和一个代表它的`storageFile`实例，我们可以从文件中读取文本，或者我们可以使用缓冲区读取字节。为了从文件中读取文本，我们可以利用`fileIO`类提供的`readTextAsync(file)`函数，如下面的代码所示：

```js
Windows.Storage.FileIO.readTextAsync(sampleFile).then(
function (fileContents) {
  // some code to process the text read from the file
});
```

当之前的代码成功运行时，这个函数会返回一个通过变量`fileContents`传递的文本字符串，该字符串包含了文件的内容。

几乎同样的原则适用于从文件中读取字节；然而，我们调用`readTextAsync(file)`方法，并向其传递文件。在异步过程完成后，我们可以使用`then()`或`done()`方法捕捉响应中的缓冲区数据，如下面的代码所示：

```js
Windows.Storage.FileIO.readBufferAsync(sampleFile).then(
function (buffer) {
 var bufferData = Windows.Storage.Streams.DataReader.fromBuffer(buffer);
});
```

在前面的代码中，我们使用了`DataReader`类从缓冲区读取数据；这个类提供了从内存流读取字符串的功能，并处理缓冲区。

# 显示数据

我们已经学习了不同数据源的知识，并看到了几个获取数据的示例。现在我们将了解如何格式化和显示这些数据。在前面的示例中，我们看到了如何将数据绑定到任何 HTML 元素，但幸运的是还有更好的方法。更好的方法是使用 Windows 库 for JavaScript，它提供了控件和模板，使格式化和显示数据变得容易。最著名的控件是`ListView`和`FlipView`；在绑定和显示数据时，这两种方法应用相同的技巧，但在这个章节中我们将使用`ListView`。这不仅仅是因为个人偏好，而是利用`ListView`控件的功能，因为它提供了一种灵活的方式显示数据，并内置了对交叉滑动（触摸）手势的支持；此外，它还进行了性能优化。而且，它提供了一个与 Windows Store 应用一致的外观和行为。绑定和显示数据的步骤如下：

1.  获取数据。

1.  创建一个`WinJS.Binding.List`对象来包装数据。

1.  创建一个`ListView`元素。

1.  将`ListView`元素的`itemDataSource`设置为`WinJS.Binding.List`对象。

让我们继续使用之前用于通过网络 URL 获取推文的例子；代码返回了一个 JSON 字符串，这里就是我们的数据，所以下一步是创建一个`WinJS.Binding.List`对象，如下所示：

```js
WinJS.xhr({ 
  url: "http://search.twitter.com/search.json?q=windows8"}).then(
  function (result) {
    var jsonData = JSON.parse(result.responseText);
    //create a binding list object from the json
    var bindingList = new WinJS.Binding.List(json.results);
  });
```

我们刚刚完成了步骤 1 和 2；第 3 步涉及在 DOM 中创建一个`ListView`元素，并在 JavaScript 代码中获得它的实例。

在 HTML 中，我们使用如下内容：

```js
<div id="sampleListView" data-win-control="WinJS.UI.ListView" >
</div>
```

在 JavaScript 中，我们使用以下代码：

```js
//get an instance of the ListView Control
var listView = document.getElementById("sampleListView").winControl;
```

在第 4 步中，我们将`ListView`对象的`itemDataSource`属性设置为`bindingList`对象的`dataSource`属性，完整的代码将如下面的代码片段所示：

```js
WinJS.xhr({ 
  url: "http://search.twitter.com/search.json?q=windows8"}).then(
  function (result) {
    var jsonData = JSON.parse(result.responseText);
    //create a binding list object from the json
    var bindingList = new WinJS.Binding.List(jsonData.results);
    //get the list view element from the DOM
    var listView = 
    document.getElementById("sampleListView").winControl;
    //bind the data sources
    listView.itemDataSource = bindingList.dataSource
  });
```

如果您在`default.html`页面中添加`ListView`控件或其他`WinJS.UI`控件，请记得在函数`WinJS.UI.ProcessAll()`上的`then()`或`done()`调用中添加前面的代码，如下面的代码所示：

```js
args.setPromise(WinJS.UI.processAll().then(function () {
  //get the list view element from the DOM
  var listView = 
  document.getElementById("sampleListView").winControl;
  //bind the data sources
  listView.itemDataSource = bindingList.dataSource
}));
```

添加这段代码的原因是这个函数处理 Windows 库中的 JavaScript 控件并在 DOM 中渲染这些控件。

现在让我们构建并运行项目。输出将是一个包含推文的列表，每个推文都有其属性，如下面的截图所示：

![显示数据](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_05_02.jpg)

尽管`ListView`控件可以自动绑定数据，但看起来很乱，需要格式化。`WinJS`控件提供了模板，可以与`ListView`和`FlipView`对象结合使用，指定每个项目应如何显示以及它将显示哪些数据。可以通过指定应出现的`div`元素或使用`render`方法创建自己的`div`元素来声明定义模板。让我们亲身体验一下。在 DOM 内部，添加一个`div`元素，并通过`data-win-control`属性将其分配给`WinJS.Binding.Template`，如下所示：

```js
<div id="listTemplate" data-win-control="WinJS.Binding.Template"></div>
```

然后通过首先添加一个根`div`元素，然后在该根`div`内部添加绑定元素来创建模板的内部结构，如下面的代码片段所示：

```js
<div id="listTemplate" data-win-control="WinJS.Binding.Template">
  <div class="templateItem" style ="width:300px; height:100px;">
    <img src="img/#" style="float:left; width: 60px; height: 60px;" 
      data-win-bind="src: profile_img_url" />
    <b>From:</b><span data-win-bind="innerText: from_user_name"></span>
    <br />
    <b>Date:</b><span data-win-bind="innerText: created_at"></span>
    <br />
    <b>Text:</b><span data-win-bind="innerText: text"></span>
  </div>
</div>
```

您可能在之前的截图中注意到，列出的数据项包含用引号标记的属性，后面跟着一个冒号；例如，`"created_at":` 和 `"from_user":`。这些属性代表了从 Twitter 的 web 调用返回的`jsonData`对象中的数据，并且这些属性作为参数传递给`listTemplate`元素中的`data-win-bind`属性，以便在 DOM 中渲染。

接下来，我们应该将这个新创建的模板分配给前面创建的`ListView`控件，通过在`data-win-options`属性中指定一个`itemTemplate`值，如下面的代码所示：

```js
<div id="listViewSample" data-win-control="WinJS.UI.ListView" 
data-win-options="{ itemTemplate: select('#listTemplate') }">
</div>
```

运行项目后，您将看到与下一张截图类似的界面。由于正在从 Twitter 获取实时数据，值将根据特定查询而变化：

![显示数据](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_05_03.jpg)

# 排序和过滤数据

我们获取了数据，并使用模板来展示它并将它绑定到`WinJS`控件上。现在，如果我们需要对数据项进行排序，甚至根据某个特定标准筛选掉不需要的项，该怎么办呢？`WinJS`库提供的绑定列表 API 无缝地使用内置方法如`createSorted`和`createFiltered`来处理这一点。如果我们回到之前编写的代码，获取推文并创建`bindingList`变量，这是一个`WinJS.Binding.List`的实例，并尝试调用`createSorted`方法，你会注意到自动完成功能列出了为此功能提供的其他两个内置函数，如下面的屏幕截图所示：

![Sorting and filtering the data](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_05_04.jpg)

这两个方法将为它的数据创建一个名为“排序投影”的视图。`createSorted`方法将返回一个`SortedListProjection`对象，它代表了一个对其持有的数据进行排序的视图，同样，`createFiltered`方法将返回一个`FilteredListProjection`对象，代表了一个对其数据进行筛选的视图。这两个投影的主要优点是它们是完全可观察的，这意味着当列表中的数据发生变化时，其相应的投影将收到通知并更新自己。此外，当投影自身发生变化时，它会通知任何监听的对象其变化。

我们可以通过调用`createSorted`方法来对这个绑定列表进行排序，该方法接收处理排序逻辑的排序函数参数。让我们按用户名字母顺序排序我们获取的推文。使用以下代码：

```js
//to recall this was the bindinglist variable we had
var bindingList = new WinJS.Binding.List(json.results);
//create a sorted list instance from that bindingList
var sortedList = bindingList.createSorted(function (first, second) {
return (first.from_user_name).toString().localeCompare(second.from_user_name);
});
```

`createSorted`函数将在 sorter 函数参数内进行排序逻辑，在这个例子中，比较列表中的`from_user_name`字段并返回按字母顺序排序的列表。注意比较的字段是列表中数据项的字段。

一旦我们完成了排序，`ListView`控件的`itemDataSource`属性现在应该绑定到新创建的`sortedList`方法，以便看到以下代码：

```js
//pass the sortedList as a datasource
simpleListView.itemDataSource = sortedList.dataSource;
```

构建并运行项目，你会看到与以下屏幕截图类似的结果：

![Sorting and filtering the data](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_05_05.jpg)

筛选是通过调用`createFiltered`方法来完成的，该方法创建了一个实时筛选投影，覆盖此列表。筛选投影将反应列表中的变化，并且可能相应地发生变化。此方法接收一个类型为`function`的参数，这个参数的基本作用是在列表中的每个元素上执行回调方法。例如，我们希望对`bindingList`应用一个筛选器，该筛选器将检查`from_user_name`字符串的第二个字符是否为`'a'`，并只返回列表中匹配的项。`createFiltered`的`function`类型的参数将对列表中的每个字符串进行检查；如果条件为真，则将该字符串包含在筛选列表中。要使用筛选器，请参考以下代码片段：

```js
//to recall this was the bindinglist variable we had
var bindingList = new WinJS.Binding.List(json.results);//create a sorted list instance from that bindingList
var filterdList = bindingList.createFiltered(function (filter) {
return filter.from_user_name.toString().charAt(1) == 'a';
});
simpleListView.itemDataSource = filteredList.dataSource; 
```

运行项目，您将看到列表已根据筛选条件进行了筛选（您可以随意更改筛选条件，以便更好地看到筛选器的效果）。结果将类似于以下屏幕截图：

![对数据进行排序和筛选](https://github.com/OpenDocCN/freelearn-js-pt2-zh/raw/master/docs/dev-win-store-app-h5-js/img/7102EN_05_06.jpg)

# 总结

在本章中，我们已经涵盖了在 JavaScript 应用程序中处理数据的基本知识。我们学习了如何从本地对象获取数据，以及如何通过 Web 服务从 Web 获取数据，并处理返回响应中的数据。

然后我们介绍了如何显示我们从本地对象获取的数据，并将其绑定到`ListView`控件。最后，我们看到了如何在将数据显示在应用程序之前对其进行排序和筛选。

在下一章中，我们将学习如何使应用程序具有响应性，以便在视图状态发生变化时布局也发生变化，从而使内容始终以良好的格式呈现给用户。
