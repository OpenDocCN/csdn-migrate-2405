# ArcGIS JavaScript 开发示例（一）

> 原文：[`zh.annas-archive.org/md5/C5B34B58FB342061E6400E7ECE284E58`](https://zh.annas-archive.org/md5/C5B34B58FB342061E6400E7ECE284E58)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Web 技术正在迅速变化，ArcGIS JavaScript API 也是如此。无论您的开发经验如何，ArcGIS 都提供了一种简单的方式来创建和管理地理空间应用程序。它为您提供了地图和可视化、分析、3D、数据管理以及对实时数据的支持。

# 本书涵盖的内容

第一章，“API 基础”，旨在为整本书涉及的主题奠定坚实的基础。本章设置了跟随进一步解释的主题所需的基本环境，以及开发专业外观代码的基础。提供了对 dojo 和 JavaScript 编码的模块化模式的介绍，以及对基本 ArcGIS 概念的解释。用户将在需要时看到有关基本概念的简要解释，包括代码片段或图表。

第二章，“图层和小部件”，涉及 API 中使用的不同类型的图层以及每种类型的理想上下文。我们还将介绍 Esri 提供的一些最常用的内置小部件，供我们在应用程序中使用。

第三章，“编写查询”，将深入研究编写不同类型的查询、检索结果并显示它。我们将开发一个野火应用程序，以了解诸如识别、查找和查询任务等查询操作类型。我们还将学习如何使用 FeatureTable 小部件显示表格信息，并使用 Infotemplates 格式化弹出内容。

第四章，“构建自定义小部件”，将解释如何将所有代码组织成模块化小部件，并在我们的应用程序中使用它。我们将讨论如何全局配置 dojo 以及如何提供国际化支持。我们将通过构建涉及使用绘图工具栏的空间查询来扩展我们在上一章中开发的野火应用程序。

第五章，“使用渲染器”，深入探讨了颜色、符号、渲染器以及每种情况下如何有效使用它们的主题。本章还将处理数据可视化技术的微妙之处，以及创建符号和图片标记符号的技巧和窍门。我们将通过开发一个流量计应用程序来演示三种基本渲染器的效用：简单渲染器、唯一值渲染器和类别断点渲染器。

第六章，“处理实时数据”，将详细介绍什么构成实时数据，还将介绍如何可视化数据并获取最新更新的数据。我们将构建一个飓风追踪应用程序来演示这一点，并将利用 API 提供的几何引擎功能和现代浏览器提供的地理位置功能添加全球风数据仪表和天气小部件。

第七章，“地图分析和可视化技术”，将使您更接近成为地图数据科学家。本章将涵盖很多内容，从一些基础统计概念的复习开始。我们将看到代码的实际运行，并了解统计定义和要素图层统计模块如何为我们提供宝贵的统计量，这些统计量可以用于有意义地呈现地图数据。然后，我们将评估如何在渲染器中有效使用视觉变量，如 colorInfo、opacityInfo、rotationInfo 和 sizeInfo。我们将利用所学知识开始构建一个人口统计分析门户。

第八章，“高级地图可视化和图表库”，将使用三种不同的图表库，如 dojo、D3.js 和 Cedar，来扩展我们在上一章开始构建的人口统计门户，并为用户提供更多的视觉分析信息。

第九章，“使用时间感知图层进行可视化”，将解释如何使用 TimeSlider dijit 来可视化时空数据，以及如何通过将其纳入时间感知的美国干旱数据来使用自定义的 D3.js timeslider 和自定义的时间序列直方图。

# 本书所需的内容

对于本书，我们需要 NotePad++/Brackets 编辑器，Google Chrome/Mozilla Firefox 或任何现代浏览器，Visual Studio Community Edition 2015 和 Node.js for Windows。

# 本书适合谁

本书是为希望使用 ArcGIS JavaScript API 开发出色的地图应用程序的 JavaScript 开发人员而编写的，但更重要的是，空间思维将帮助用户走得更远。

# 约定

在本书中，您会发现许多文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“安装 IIS 后，您可以在`Program Files`文件夹内的`IIS Express`文件夹中找到可执行文件”

代码块设置如下：

```js
<link rel="stylesheet" href="http://js.arcgis.com/3.15/esri/css/esri.css">

<script src="http://js.arcgis.com/3.15/"></script>
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项会以粗体显示：

```js
**on(map, "layers-add-result", function (evt) {**
console.log("1.", earthQuakeLayer.id);
...
console.log("5.", worldCities.layerInfos);
});
```

任何命令行输入或输出都是这样写的：

```js
**1\. Earthquake Layer**
**2\. [Object,**
**Object,**
**. . .**
**Object]**
 **3\. esriGeometryPoint**
**4\. 1000**
**5\. [Object, Object, Object]**

```

**新术语**和**重要单词**以粗体显示。例如，在屏幕上看到的单词，比如菜单或对话框中的单词，会出现在文本中，就像这样：“单击 IIS Express 应用程序名称旁边的**添加**按钮，然后单击**安装**按钮。”

### 注意

警告或重要说明会以这样的方式出现在一个框中。

### 提示

提示和技巧会以这种方式出现。


# 第一章：API 的基础

您可能正在阅读这本书，因为您想要使用 ArcGIS JavaScript API 将空间能力集成到您的 Web 应用程序中，并使其变得更加令人惊叹，或者您希望很快成为一名 Web 地图数据科学家。无论是什么，我们都与您同在。但是在着手实际项目之前，我们不认为需要一些基础工作。本章就是关于这个的——为本书后面使用的概念奠定坚实的基础。本章在内容上设计多样，涵盖了以下主题的许多内容：

+   使用 API 编写您的第一个地图应用程序

+   复习坐标几何、范围和空间参考系统。

+   介绍 dojo 和 AMD 编码模式

+   了解 ArcGIS Server 和 REST API

+   搭建开发环境

# 搭建开发环境

这本书是一本*示例*书，我们将通过开发的应用程序来解释概念。因此，在本章开始时，确保您的开发环境已经运行起来是至关重要的。以下部分提到的大多数环境只是我们的偏好，可能不是必须的，以实现本书提供的代码示例。所有的代码示例都针对运行在基于 Windows 的操作系统和名为**Brackets**的**集成开发环境**（**IDE**）。如果您有不同的操作系统和 IDE 选择，我们欢迎您在您最舒适的环境中开发。

## 浏览器、Web 服务器和 IDE

为了开发、部署和执行任何 Web 应用程序，我们需要以下组件：

+   Web 浏览器

+   Web 服务器

+   集成开发环境（IDE）

### Web 浏览器

我们在整本书中都使用了 Google Chrome，因为它提供了一些很棒的开发者工具和 HTML 检查工具。我们认为 Mozilla 也是一个很好的用于开发的浏览器。

### Web 服务器

本书中开发的应用程序是使用 IIS Express 进行托管的。IIS Express 是一个轻量级的 Web 服务器，主要用于托管.NET Web 应用程序。尽管本书中的所有项目都是使用纯 HTML、CSS 和 JavaScript 开发的，但我们将使用 Esri .NET 资源代理来访问 ArcGIS 在线安全内容，并避免跨域问题。

读者可以通过安装 Web 平台安装程序或直接从 Microsoft 下载页面安装 IIS Express，如下步骤所示：

1.  要安装 IIS Express，请访问[`www.microsoft.com/web/downloads/platform.aspx`](https://www.microsoft.com/web/downloads/platform.aspx)使用 Web 平台安装程序进行安装。

1.  下载后，在搜索文本中搜索`IIS Express`。搜索结果将显示 IIS Express 应用程序。点击 IIS Express 应用程序名称后面的**添加**按钮，然后点击页面底部的**安装**按钮，如下面的屏幕截图所示：![Web server](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_01.jpg)

1.  从 Web 平台安装程序安装 IIS Express 可以确保我们可以获得 IIS Express 的最新版本，而直接下载链接可能无法提供最新版本的链接。在撰写本书时，最新的 IIS Express 直接下载链接可以在[`www.microsoft.com/en-us/download/details.aspx?id=34679`](https://www.microsoft.com/en-us/download/details.aspx?id=34679)找到。

1.  安装 IIS 后，您可以在`Program Files`文件夹内的`IIS Express`文件夹中找到可执行文件。默认位置通常是`C:\Program Files\IIS Express`。

1.  我们将在每个项目中提供一个可执行的批处理（`.bat`）文件，帮助启动 Web 服务器并将项目托管在指定的端口上。

1.  您可以在我们为本书开发的每个项目的可执行文件中找到以下代码行：

```js
"C:\Program Files\IIS Express\iisexpress.exe" /path:<app location>  /port:9098
```

1.  前面的行将在端口`9098`上托管应用程序。因此，要访问该应用程序，您只需要使用 URL-`http://localhost:9098/`。

### IDE

开发 JavaScript 代码的 IDE 选择很多，有经验的开发人员已经知道他们需要使用什么。我们在整本书中都使用了 Brackets 作为我们首选的 IDE。

## 设置 ArcGIS 开发者帐户

在本书的一些练习中，您将需要一个 ArcGIS 开发者帐户。这也是一个让您探索 ESRI 为开发人员提供的各种功能的机会。要设置开发者帐户，只需免费注册[`developers.arcgis.com/en/sign-up/`](https://developers.arcgis.com/en/sign-up/)。

## 你好，地图-快速启动代码

如果你和我们一样，你可能想立刻用编码的方式制作你的第一张地图。所以在这里。尝试将这些代码添加到 Brackets IDE 中的新 HTML 文件中。您还可以从代码存储库下载名为`B04959_01_CODE01`的 HTML 源代码，并双击 HTML 文件来运行它。

![Hello, Map – the jump-start code](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_23.jpg)

观察前面的代码行时，您可能已经注意到了这两件事：

+   我们不需要任何许可证、身份验证或密钥来运行此代码。换句话说，API 是免费的。您只需要使用 CDN 链接。

+   我们将在浏览器中看到这张美丽的制图地图，如下面的截图所示：![Hello, Map – the jump-start code](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_22.jpg)

+   我们鼓励您缩放或平移到您想要查看地图的位置。如果您还没有弄清楚如何缩放/平移地图，我们将立即处理：

单击并拖动或按任何箭头键会导致平移，但不会改变详细级别。

*Shift* +左键拖动、鼠标滚动、双击或单击地图上的*+*或*- *按钮会导致缩放和显示的详细级别发生变化。

### 注意

还有其他方法可以实现缩放/平移功能。这里提到的方法只是为了获得初步的理解。

## 理解快速启动代码

让我们试着理解刚才看到的代码。这段代码中有三个概念我们想解释。第一个涉及 API 的引用链接或我们用来下载 ArcGIS JavaScript API（v 3.15）及其相关样式表的**内容交付网络**（**CDN**）。第二个概念试图向您介绍所采用的编码模式，即**异步模块定义**（**AMD**）模式。这是最新版本的 dojo（v1.10）所使用的。下一个概念是关于您在浏览器中运行代码时看到的内容-地图和我们提供给它的参数。

### API 参考链接

首先要做的是引用 API 来开发基于 ArcGIS JavaScript API 的应用程序。Esri 是拥有该 API 的组织，但该 API 是免费的，可供公众使用。截至 2016 年 3 月，API 的最新版本是 3.15，相应的 dojo 工具包版本是 1.10。

以下库可能是您可能需要引用的唯一库，以使用 ArcGIS JavaScript API 的功能以及许多 dojo 工具包，如`core dojo`、`dijit`、`dgrid`等：

```js
<link rel="stylesheet" href="http://js.arcgis.com/3.15/esri/css/esri.css">

<script src="http://js.arcgis.com/3.15/"></script>
```

请参阅此链接，以获取 ArcGIS JavaScript API 的完整文档-[`developers.arcgis.com/javascript/jsapi/`](https://developers.arcgis.com/javascript/jsapi/)。

当您访问上述 URL 时，您将看到一个网页，提供了 API 的完整文档，包括**API 参考**、**指南**、**示例代码**、**论坛**和**主页**等多个选项卡。

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

你可以按照以下步骤下载代码文件：

+   使用你的电子邮件地址和密码登录或注册到我们的网站。

+   将鼠标指针悬停在顶部的**支持**选项卡上。

+   点击**代码下载和勘误**。

+   在**搜索**框中输入书名。

+   选择你要下载代码文件的书籍。

+   从下拉菜单中选择你购买这本书的地方。

+   点击**代码下载**。

你也可以通过点击 Packt Publishing 网站上书籍页面上的代码文件按钮来下载代码文件。可以通过在搜索框中输入书名来访问该页面。请注意，你需要登录到你的 Packt 账户。

文件下载后，请确保使用最新版本的解压缩软件解压文件夹：

+   Windows 上的 WinRAR / 7-Zip

+   Mac 上的 Zipeg / iZip / UnRarX

+   Linux 上的 7-Zip / PeaZip

API 参考列出了 API 下所有模块的详细信息、属性、方法和可用的事件。左侧窗格将大多数模块分组以便参考。例如，名为**esri/layers**的分组有多个从中继承的模块。以下截图显示了从**esri/layers**继承的不同模块的分组情况：

![API 参考链接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_02.jpg)

**指南**部分提供了重要主题的详细说明，比如**使用查询任务**，**使用 ArcGIS 在线小部件**，以及**使用符号和渲染器**。以下截图显示了设置地图范围的详细指南：

![API 参考链接](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_03.jpg)

**示例代码**选项卡是另一个有用的部分，其中包含数百个示例应用程序，用于演示 API 中的不同概念。这些示例代码最好的部分是它们带有一个沙盒设施，你可以用来通过修改代码来玩耍。

**论坛**选项卡会将你重定向到以下网址—[`geonet.esri.com/community/developers/web-developers/arcgis-api-for-javascript`](https://geonet.esri.com/community/developers/web-developers/arcgis-api-for-javascript)。

GeoNet 社区论坛是一个很好的地方，可以在那里提出问题并分享解决方案，与像你一样的开发者交流。

由于它与 dojo 框架的紧密集成，需要对 dojo 工具包有一定的了解，其参考文档可以在[`dojotoolkit.org/reference-guide/1.10/`](http://dojotoolkit.org/reference-guide/1.10/)上访问。

### 编码的 AMD 模式

如果你观察了代码结构，它可能如下所示：

![编码的 AMD 模式](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_04.jpg)

如果你不熟悉 JavaScript 编码的这种模式，它被称为 AMD 编码模式，ArcGIS JavaScript API 强调使用这种编码模式。在最初的章节中，我们将介绍很多关于这个的内容，以便熟悉 dojo 和 AMD。从代码结构中，你可能已经了解到代码*需要*某些模块，加载这些模块的函数要求它们按照相同的顺序。在我们的情况下，一些模块是 Esri 模块（`esri/..`）和 dojo 模块（`dojo/..`）。如果你想知道是否可以*需要*自定义定义的模块，答案绝对是肯定的，这将是我们在本书中的主要部分。

### esri/map 模块

代码中的高亮行构成了我们快速启动代码的核心：

```js
 **var map = new Map("mapDiv", {**
 **basemap: "national-geographic"**
 **});**

```

`map`模块接受两个参数。第一个参数是包含`map`对象的`div`容器。第二个参数是一个可选对象，它接受许多属性，可以用来设置地图的属性。

在我们的快速入门代码中，可选对象中的`basemap`属性设置了 Esri 提供的基础地图代码之一，名为`national-geographic`，用作背景地图显示。我们建议您尝试使用其他 Esri 提供的基础地图，例如以下内容：

+   卫星

+   深灰色

+   浅灰色

+   混合

+   拓扑

# 设置初始地图范围

有时，当应用程序打开时，您可能希望将其缩放到特定感兴趣的区域，而不是首先以世界范围显示地图，然后再缩放到您想要查看的区域。为了实现这一点，地图模块提供了一个属性来设置其初始范围，并在任何时候以编程方式更改其范围。

在此之前，让我们看看在地图的上下文中范围是什么。

### 注意

范围是包围地图上感兴趣区域的最小边界矩形。

## 刷新一些坐标几何

要了解范围，了解坐标几何将有所帮助。我们将把黄色的线段称为*折线*。蓝色线代表*多边形*（在我们的例子中是矩形）：

![刷新一些坐标几何](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_05.jpg)

现在，试着观察前述图表和以下图表之间的差异。

![刷新一些坐标几何](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_06.jpg)

以下是关于前述图表的一些说明：

+   点由一对坐标表示；图 1 中为（2，2），图 2 中为（-1，-1）

+   折线由一系列坐标表示

+   多边形也由一系列坐标表示，类似于折线

除了坐标和坐标轴之外，你可能已经发现两个图形的形状是相同的。这可能意味着两件事：

+   图表的*x*位置向左移动了 3 个单位，*y*位置向下移动了 3 个单位

+   或者可能意味着原点将其*x*和*y*位置移动了-3 个单位

第二种可能对我们来说更重要，因为它意味着图表的实际位置没有改变，只是原点或坐标轴改变了位置。因此，相对于坐标轴，图表形状（矩形、点和线）的坐标也发生了变化。

### 注意

相同的形状可以根据参考坐标系统的不同具有不同的坐标。在 GIS 的上下文中，这种坐标系统称为**空间参考**。

### 测验时间！

让我们测试一下我们的知识。尝试解决以下测验：

Q1\. 如果原点（矩形的左下角）是（100000，100000），点（三角形符号）的坐标将是什么？

Q2\. 由于多边形和折线都由一系列坐标表示，我们如何得出结论，给定一系列坐标，形状是多边形还是折线？

Q3\. 需要多少个坐标来表示一个矩形？

思考一下，我们很快就会给出答案。

### 空间参考系统

在数字屏幕上显示世界或世界的一部分作为地图时，我们需要使用空间参考系统来识别地图上位置的坐标，这是一个与我们的图表一样的二维表面。有许多标准的空间参考系统在使用中。我们需要知道的最基本的是，每个参考系统都有一个唯一的识别号，被 API 所识别。用于定义特定空间参考系统的完整参数（如使用的基准、原点坐标、使用的测量单位等）也可以用来识别特定的空间参考系统。

### 注意

用于识别 SRS 的唯一 ID 称为**Well-known ID**（**wkid**）。

列出用于定义空间参考系统的参数的字符串称为**Well-known Text**（**wkt**）。

正如你可能预料的那样，每个空间参考系统都与不同的测量系统相关联，如英尺、米或十进制度。

例如，`4326`是全球坐标系统**WGS 84**的 wkid。该参考系统的测量单位是十进制度。

`102100`是另一个全局坐标系统的 wkid，其测量单位为米。

以下 URL 提供了一系列 wkid 和对应的 wkt，网址为[`developers.arcgis.com/javascript/jshelp/pcs.html`](https://developers.arcgis.com/javascript/jshelp/pcs.html)和[`developers.arcgis.com/javascript/jshelp/gcs.html`](https://developers.arcgis.com/javascript/jshelp/gcs.html)。

### 测验结果

A 1\. （100002，100002）—相对于原点，该点在正 x 方向上离开 2 个单位，在正 y 方向上离开 2 个单位。

A 2\. 除非在几何对象中明确提到，否则坐标序列可以是折线或多边形。但是多边形具有一个使它与折线不同的属性——第一个和最后一个坐标必须相同。折线可以具有相同的第一个和最后一个坐标，但并非所有折线都满足这一标准。

A 3\. 如果你的答案是 4，那太棒了！但如果你的答案是 2，那你太棒了。

是的。只需要两个坐标就足以定义矩形，这要归功于它的垂直性质。这两个坐标可以是任意一对对角坐标，但为了 API 的方便起见，我们将采用左下角坐标和右上角坐标。左下角坐标在 4 个坐标值对中具有最小的*x*和*y*坐标值，而右上角坐标具有最大的*x*和*y*坐标值：

![测验结果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_07.jpg)

### 获取当前地图范围

将地图缩放到您想要设置为地图初始范围的范围。在快速启动代码中，地图变量是一个全局对象，因为它是在`require`函数之外声明的。

```js
<script>
    var map; //Global variable
    require([
      "esri/map"
    ],
      function (
        Map
      ) {
        map = new Map("myMap", {
          basemap: "national-geographic"
        });
});
});
</script>
```

这意味着我们可以在浏览器控制台中访问地图的属性。在缩放地图和所需的范围作为地图初始范围之后，使用*Ctrl* + *Shift* + *I*命令（在 Chrome 中）打开开发者工具。在 JavaScript 浏览器控制台中，尝试访问地图属性，`getMaxScale()`、`getMinZoom()`、`getMinScale()`、`getMaxZoom()`、`getScale()`和`extent`：

![获取当前地图范围](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_08.jpg)

比例实际上是地图测量从现实世界测量中缩小的因素。最大比例显示地图上的最大细节，而地图的最小比例显示最少的细节。`map.getMaxScale()`的值小于`map.getMinScale()`的值，因为比例值代表倒数。因此*1/591657527 < 1/9027*（在我们的实例中分别为 1/9027.977411 和 1/591657527.59…）。

另一方面，缩放级别是地图显示的离散缩放级别。大多数涉及 Basemaps 或 Tiledmaps（将在后面的章节中讨论）的地图只能在特定的缩放级别（称为缩放级别）上显示。最小缩放级别通常为`0`，并与地图的最大比例相关联。

`map.getScale()`给出了当前的比例，`map.extent`给出了地图的当前范围。我们可以使用这个`extent`对象来使用地图的`setExtent()`方法设置地图的范围。参考`map`模块的 API 文档，并导航到地图的`setExtent`方法。`setExtent()`方法接受两个参数——`Extent`对象和一个可选的 fit 对象。当我们点击文档中提供的超链接`Extent`对象时，它会将我们重定向到`Extent`模块的 API 文档页面：

![获取当前地图范围](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_09.jpg)

`Extent`的构造函数接受一个 JSON 对象并将其转换为范围对象。我们可以从地图范围的 JSON 字符串中获取这个 JSON 对象：

![获取当前地图范围](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_10.jpg)

前面的图像向我们展示了地图的范围的 JSON 字符串，我们已经放大到了地图的范围。以下的截图显示了坐标与我们打算放大的地图区域的关系（用矩形标出）：

![获取当前地图范围](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_11.jpg)

现在，我们可以复制 JSON 对象，创建一个`Extent`对象，并将其分配给地图的`setExtent`方法。但在此之前，我们需要导入`Extent`模块（`esri/geometry/Extent`）。以下截图解释了如何实现这一点。

![获取当前地图范围](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_12.jpg)

现在当我们刷新地图时，地图将自动放大到我们设置的范围。

### 加载模块的模板生成器

在之前的代码中，我们成功设置了地图的初始范围，我们需要使用两个模块：`esri/map`和`esri/geometry/Extent`。随着应用程序的增长，我们可能需要添加更多的模块来为应用程序添加额外的功能。对于新手用户来说，从 API 中找到模块名称并将其整合到应用程序中可能会很麻烦。可以通过一个网页应用程序模板生成器来简化这个过程，该生成器可以在[`swingley.github.io/arg/`](http://swingley.github.io/arg/)找到。

以下是应用程序的截图：

![加载模块的模板生成器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_13.jpg)

我们`require`函数所需的模块可以在应用程序顶部提供的文本框中输入。有两个多选列表框：一个列出 Esri 模块，另一个列出 dojo 模块。一旦我们开始输入我们应用程序所需的模块名称，列表就会显示与我们输入的名称匹配的建议模块。一旦我们从任一列表框中选择所需的模块，它就会被添加到`require`函数的模块列表中，并且适当的别名会作为参数添加到回调函数中。一旦选择了所有所需的模块，我们就可以使用右侧生成的基本模板。要设置地图的初始范围，可以通过搜索以下名称来加载所需的模块：

+   地图（`esri/map`）

+   范围（`esri/geometry/Extent`）

# 理解 dojo 和 AMD

顾名思义，AMD 编码模式依赖于将 JavaScript 代码模块化。有很多原因你可能需要开始编写模块化代码或模块：

+   模块是为了单一目的而编写的，而且专注于此

+   因此模块是可重用的

+   模块具有更清晰的全局范围

虽然有许多编写模块化 JavaScript 的格式，比如 CommonJS 和 ES Harmony，但我们只会处理 AMD，因为最新版本的 ArcGIS JavaScript API 和基于其上的 dojo 工具包使用 AMD 风格的编码。Dojo 加载器解析依赖项并在运行应用程序时异步加载模块。

## AMD 的关键组件

在本节中，我们将看一下`define`和`require`方法，这是 AMD 的关键组件。

### 定义方法

`define`方法定义了一个模块。一个模块可以有自己的私有变量和函数，只有被`define`函数返回的变量和函数才会被导入该模块的其他函数所暴露。`define`方法的一个示例如下：

![定义方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_14.jpg)

请注意我们代码示例中的以下内容：

+   `define`方法中的第一个参数是模块名称或 ID。这是可选的。`dojoGreeting`是我们模块的名称。

+   第二个参数是我们模块的依赖项数组。对于这个模块，我们不需要任何依赖项，所以我们只传递一个空数组。

+   第三个参数是一个回调函数，接受我们可能已加载的依赖项的任何别名。请注意，用作函数参数的别名应该与在依赖数组中定义的顺序相同。由于我们没有使用任何依赖项，所以我们不会将任何东西传递给这个回调函数。

+   在回调函数中，我们可以有许多私有作用域的变量和函数。我们想要从该模块中公开的任何变量或函数都应该包含在定义函数内的`return`语句中。

+   在我们的示例中，`_dojoGreeting`是一个由`define`方法返回的私有作用域变量。

### require 方法

`require`方法使用自定义定义的模块或在外部库中定义的模块。让我们使用刚刚定义的模块和`require`方法：

![require 方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_15.jpg)

就是这样。请密切关注`require`方法的参数：

+   第一个参数是模块依赖项的数组。第一个模块依赖项是我们刚刚定义的自定义模块`dojoGreeting`。

+   `dojo/dom`模块让我们可以与 HTML 中的`dom`元素交互。

+   `dojo/domReady!`是一个 AMD 插件，它会等待 DOM 加载完成后再返回。请注意，该插件在末尾使用了特殊字符“`!`”。在回调函数中，我们不需要分配别名，因为它的返回值是无意义的。因此，这应该是依赖数组中使用的最后一个模块之一。

+   回调函数使用`dojoGreeting`和`dom`作为`dojoGreeting`和`dojo/dom`模块的别名。如前所述，我们不需要为`dojo/domReady!`使用别名。

+   `dom`模块的`byId()`方法通过其 ID 返回一个`dom`节点的引用。它与`document.getElementById()`非常相似，只是`dom.byId()`可以在所有浏览器中使用。

+   在我们的 register 方法中，我们假设有一个 ID 为`greeting`的`div`元素。

## 一些很棒的 dojo 模块

你已经了解了两个 dojo 模块，即`dojo/dom`和`dojo/domReady`。现在，是时候熟悉一些其他很棒的`dojo`模块了，你应该尽可能在编写 ArcGIS JS API 应用程序时使用它们。坚持使用纯 dojo 和 Esri JS 模块将在代码完整性和跨浏览器统一性方面产生巨大的回报。更重要的是，Dojo 在常用的 JavaScript 功能方面为你带来了一些惊喜，其中一些我们将很快介绍。

### Dojo dom 模块

你已经使用了`dojo/dom`模块。但是还有其他的 dojo `dom`模块，它们可以让你操作和处理`dom`节点：

+   `dojo/dom-attr`：这是与`dom`属性相关的首选模块：

+   模块中的`has()`方法检查给定节点中是否存在属性

+   `get()`方法返回请求属性的值，如果该属性没有指定或默认值，则返回 null

+   正如你可能已经猜到的，有一个`set()`方法，你可以用它来设置属性的值

+   `dojo/dom-class`：该模块提供了与`dom`节点关联的 CSS 类的大部分操作

+   `dojo/dom-construct`：`dojo/dom-construct`模块让你可以轻松构建`dom`元素

### Dojo 事件处理程序模块

`dojo/on`模块是一个由大多数浏览器支持的事件处理程序模块。`dojo/on`模块可以处理大多数类型对象的事件。

### Dojo 数组模块

你应该优先使用 dojo 的数组模块，而不是原生 JavaScript 数组函数，原因有很多。Dojo 的数组模块名为`dojo/_base/array`。

#### dojo/_base/array

正如您所期望的那样，作为数组模块的一部分，有一个称为`forEach()`的迭代器方法，以及`indexOf()`和`lastIndexOf()`方法。现在来看最好的部分。有一个`filter()`方法，它返回一个根据特定条件过滤的数组。我们认为`map()`方法是一个宝石，因为它不仅遍历数组，还允许我们修改回调函数中的项目并返回修改后的数组。您是否曾想过检查数组的每个元素或至少一个元素是否满足特定条件？请查看此模块中的`every()`和`some()`方法。

这个示例代码解释了 dojo 数组模块的两个主要方法：

![dojo/_base/array](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_16.jpg)

上述代码将以下内容打印到浏览器的控制台窗口中：

```js
Day #1 is Monday
Day #2 is Tuesday
Day #3 is Wednesday
Day #4 is Thursday
Day #5 is Friday
Day #6 is Saturday
Day #7 is Sunday
```

# 了解 ArcGIS 服务器和 REST API

ArcGIS 服务器是 Esri 公司的产品，通过在网上共享地理空间数据来实现 WebGIS。我们的 JavaScript API 能够通过 REST API 消耗这个服务器提供的许多服务。这意味着 ArcGIS 服务器提供的所有这些服务都可以通过 URL 访问。现在，让我们看看 REST API 接口对开发人员有多么有帮助。

## 服务类型

当您运行本书中提供的第一个代码时，在网页上看到了一个地图。您在浏览器中看到的地图实际上是一组拼接在一起的图像。如果您在加载地图时观察了开发者工具中的**网络**选项卡，您会意识到这一点。这些单独的图像被称为**瓦片**。这些瓦片也是由 ArcGIS MAP 服务器提供的。以下是一个这样的瓦片的 URL：[`server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/2/1/2`](http://server.arcgisonline.com/ArcGIS/rest/services/World_Street_Map/MapServer/tile/2/1/2)。

这意味着通过 ArcGIS 服务器发布并可通过 API 访问的任何资源都是通过 URL，如下面的屏幕截图所示：

![服务类型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_17.jpg)

### 注意

ArcGIS 服务端点的格式将是：`<ArcGIS 服务器名称>/ArcGIS/rest/services/<文件夹名称>/<服务类型>`。

ArcGIS 服务器提供了一个用户界面来查看这些 REST 端点。这个界面通常被称为**服务目录**。

在计划使用特定的 GIS 服务之前，开发人员需要查看服务目录。服务目录支持多种格式，如 JSON 和 HTML，HTML 是默认格式。如果您无法查看服务目录，您需要联系您的 GIS 管理员，以启用您感兴趣的服务的服务浏览功能。

## 使用服务目录

让我们探索 Esri 提供的一个名为`sampleserver3.arcgisonline.com`的示例 GIS 服务器。

要查看任何 GIS 服务器的服务目录，语法是`<GIS 服务器名称>/ArcGIS/rest/services`。

因此，我们需要导航到的 URL 是：[`sampleserver3.arcgisonline.com/ArcGIS/rest/services`](http://sampleserver3.arcgisonline.com/ArcGIS/rest/services)。

您将在浏览器中看到这个屏幕：

![使用服务目录](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_18.jpg)

服务目录中感兴趣的项目是**文件夹**标题标签下的链接列表和**服务**标题标签下的链接列表。我们鼓励您导航到这些链接中的每一个，并查看它们公开的服务类型。您将找到以下类型的服务：

+   **MapServer**：这个服务地理空间数据

+   **FeatureServer**：这使得编辑功能成为可能

+   **ImageServer**：这个服务图像瓦片

我们有没有提到服务目录支持多种格式，比如 JSON？我们鼓励您在 URL 的末尾添加一个查询字符串参数，比如`?f=json`。要将服务目录视为 HTML，只需从 URL 中删除查询字符串参数。

### 地图服务器

地图服务器将 GIS 数据公开为 REST 端点。

让我们更多地了解名为`Parcels`的特定地图服务器，位于`BloomfieldHillsMichigan`文件夹中。导航到此 URL：[`sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer`](http://sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer)。

以下标题标签对我们特别感兴趣：图层、表和描述。现在，让我们更深入地研究地图服务器中的一个图层。这三个图层都值得浏览。为了解释起见，让我们选择第一个图层（图层 ID：`0`），可以直接导航到此 URL：[`sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer/0`](http://sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer/0)。

此 URL 中列出的所有标题标签都值得思考。我们将讨论其中一些：

+   **Geometry Type**描述了特定图层的几何类型。在我们调查的 URL 中，它被命名为`'esriGeometryPoint'`，这意味着它是一个点要素。

+   元数据，如`'Description'`，`'Copyright Text'`。

+   关于数据的地理范围的信息在标签`'Extent'`和`'Spatial Reference'`下。

+   `Drawing Info`标签定义了数据在地图上的呈现方式。

+   `'Fields'`显示了我们图层的表模式。实际字段名与字段类型和字段的别名一起提到。别名和字段类型信息对于对数据执行查询是必要的。`'esriFieldTypeString'`和`'esriFieldTypeSmallInteger'`的字段类型表示该字段应分别被视为字符串和数字。`'esriFieldTypeOID'`是一种特殊类型的字段，它保存了图层中要素的唯一对象 ID。

#### 查询端点

页面底部将有一个名为**支持的操作**的标题标签，列出了此层公开的各个端点的链接。可能会有一个名为**查询**的链接。这个链接是我们深入研究 ArcGIS Server 和 REST 端点的原因。点击链接或使用此直接 URL 导航到它：[`sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer/0/query`](http://sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer/0/query)。

![查询端点](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_19.jpg)

UI 提供了我们可以使用该特定图层（**建筑足迹**）进行查询的所有可能方式。查询操作似乎支持空间查询和平面表 SQL 查询。目前，让我们只讨论平面表查询。**Where**字段和**Return Fields (Comma Separated)**是处理平面表查询的字段。**Where**字段接受标准的 SQL `where`子句作为输入，**Return Fields**接受一个以逗号分隔的字段名称值，需要作为输出。但在开发的这个阶段，我们只是探索者，我们只需要看到这个接口返回的数据类型。将以下值输入到相应的文本框中：

+   **Where**: `1 = 1`

+   **Return Fields**: `*`

点击**查询（GET）**按钮并滚动到屏幕底部。

查询实际上返回了来自数据库的所有字段的所有图层数据，但 ArcGIS Server 将结果限制为 1000 个要素。请注意浏览器的 URL 已更改。以下 URL 是用于触发此查询的 REST GET 请求 URL：[`sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer/0/query?text=&geometry=&geometryType=esriGeometryPoint&inSR=&spatialRel=esriSpatialRelIntersects&relationParam=&objectIds=&where=1%3D1&time=&returnIdsOnly=false&returnGeometry=true&maxAllowableOffset=&outSR=&outFields=*&f=html`](http://sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer/0/query?text=&geometry=&geometryType=esriGeometryPoint&inSR=&spatialRel=esriSpatialRelIntersects&relationParam=&objectIds=&where=1%3D1&time=&returnIdsOnly=false&returnGeometry=true&maxAllowableOffset=&outSR=&outFields=*&f=html)。

以下 URL 从前述 URL 中删除所有可选和未定义的查询参数，也将产生相同的结果：[`sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer/0/query?where=1%3D1&outFields=*&f=html`](http://sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer/0/query?where=1%3D1&outFields=*&f=html)。

现在让我们通过缩小`Where`子句来更详细地分析结果数据。注意结果中第一个要素的**OBJECTID**字段：

1.  删除`Where`子句文本框中的值。

1.  在对象 ID 文本框中输入所注意的**OBJECTID**。我们注意到的对象 ID 是**5991**（但您也可以选择任何一个）。

1.  有一个名为格式的下拉菜单。选择名为`'json'`的下拉值

1.  点击**查询（GET）**按钮。

或者，这是实现相同操作的直接 URL：[`sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer/0/query?objectIds=5991outFields=*&f=pjson`](http://sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer/0/query?objectIds=5991outFields=*&f=pjson)。

现在，结果看起来非常详细。我们正在查看的是单个要素的数据。JSON 返回了几个特征键值对，其中包括`displayFieldName`、`fieldAliases`、`geometryType`、`spatialReference`、`fields`和`features`等键。

让我们看看`feature`键值对。`features`键的值是对象数组。每个对象都有名为`attributes`和`geometry`的键。属性保存对象的值，列出字段名称和其值的键值。在我们的案例中，`PARCELID`是字段名，`"1916101009"`是它的值：

![查询端点](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_20.jpg)

几何对象表示具有环对象数组的多边形要素。每个环都是浮点数数组。我们之前处理多边形时只是一个坐标数组。但是 ArcGIS Server 将多边形视为环的数组。要理解环的概念，请查看以下插图：

![查询端点](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_01_21.jpg)

在前面的插图中，我们处理了两个不相交的多边形，但在现实世界中被视为单个单位，比如房屋和车库。ArcGIS 用两个环表示多边形要素。第一个环由坐标组成，称为[[x1, y1], [x2, y2],…[x6,y6]]，第二个环由坐标组成，称为[[x7,y7],..[x10, y10]]。

# 总结

我们使用了 ArcGIS JS API 的 CDN 来访问 API，并尝试理解地图和 Esri 几何模块。我们试图通过复习坐标几何知识来更好地理解范围和空间参考。我们现在知道，范围只是一个可以使用两个坐标定义的最小边界矩形，空间参考系统类似于图表上的坐标轴。我们试图查看道具工具包提供的一些令人惊叹的模块，我们必须考虑在我们的代码中使用它们。ArcGIS Server 将其 GIS 数据和其他资源公开为 REST API，也就是说，它可以作为 URL 使用。您还了解到开发人员在开始通过 API 消耗任何服务之前，必须始终参考服务目录。我们在这本书中为通过项目工作制定了开发环境的偏好。下一章将涉及 API 中使用的不同类型的图层以及每种类型使用的理想上下文。我们还将介绍 Esri 提供的一些最常用的内置小部件，并在我们的应用程序中使用它们。


# 第二章：图层和小部件

构成我们网络地图应用程序的两个基本组件是图层和小部件。地图对象类似于一个容纳所有图层的画布，用户可以与之交互，例如平移和缩放地图。图层主要与特定数据源相关联。小部件由 JavaScript 逻辑和 HTML 模板（如果需要用户交互）组成。小部件可以与地图交互，也可以独立运行。Esri 开发了许多通用小部件，并将其捆绑到 API 中。我们将在本书中讨论如何使用这些小部件。我们还将在下一章中看到如何开发自定义小部件。本章为开发显示历史地震数据的完整网络地图应用程序奠定了起点。随着我们在本章中的进展，我们将在以下主题中获得牢固的立足点：

+   API 支持的数据源

+   在 API 的上下文中图层的概念

+   图层的功能分类

+   不同类型的图层及其属性

+   要素图层与 DynamicMapService 与图形图层

+   使用 Esri 的内置小部件

# API 支持的数据源

ArcGIS JavaScript API 是一种功能强大且灵活的客户端地图软件，它提供了对各种空间数据源的集成支持，目前正在生产中。它还支持可视化平面文件格式，如 CSV，其中包含一些纬度和经度信息。

为了充分利用 ArcGIS JavaScript API 提供的全部功能，了解它支持的数据源列表以及其公开的属性和方法是很重要的。

截至版本 3.14，ArcGIS JavaScript API 支持的数据源可以大致分为以下几类：

+   ArcGIS Server 服务

+   符合 OGC 标准的 GIS 服务

+   平面文件格式

+   自定义网络服务（最好是 REST 服务）

让我们回顾不同的数据源格式，并了解如何获取有关数据的必要信息，以在 ArcGIS JavaScript API 中使用。

## 平面文件格式

API 提供原生支持以渲染 KML 和 CSV 等平面文件格式。

### KML

**Keyhole 标记语言**（**KML**）是一种空间文件格式，最初由 Google 开发，目前由 OGC 维护。它支持点、线和多边形几何图形，甚至图像叠加。KML 是一种广为人知的 XML，以其多功能性而闻名，但它非常冗长，并且在 Google 地图中使用。KML 文件可以在任何文本编辑器中打开，如 Notepad++。

### CSV 文件

CSV 文件是一种存储以逗号分隔的字段值的表格数据的纯文本文件格式。CSV 文件包含有关纬度和经度或坐标值（如*X*和*Y*坐标）的信息。API 可以读取 CSV 文件，并将位置信息转换为 API 上的位置。

## ArcGIS Server

ArcGIS Server 可用于在 Web 上共享空间数据。在我们的情况下，如果我们有形状文件、个人地理数据库、文件地理数据库或企业地理数据库，我们可以使用 ArcGIS Server 将数据作为 REST 服务在 Web 上提供。ArcGIS JavaScript 能够消费这些服务并将其显示在地图上。在其他空间格式的情况下，例如 DWG，我们可以使用 ArcGIS 桌面或**特征操作引擎**（**FME**），这是一个用于转换为 Esri 文件格式并通过 ArcGIS Server 发布的空间 ETL 工具。

# 图层的概念

如果你曾经学过 GIS 的入门课程，你一定熟悉 GIS 图层相互叠加的经典形象。在 API 的上下文中，图层是作为 REST 端点或 JSON 对象可用的数据资源。（没错，你可以使用 JSON 字符串构建 Web 地图图层。）我们很快就会讨论这些地图图层的来源和类型，但在此之前，让我们列出任何地图图层的最重要考虑因素：

+   图层是任何数据源的容器对象

+   可以使用图层对象将数据添加到地图对象中

+   图层形成堆栈架构——添加的第一层位于底部

通常将*底图图层*放在底部

+   地图对象具有一个特殊的内置图层，用于包含所有地图图形

这被称为*图形图层*，并且始终位于顶层

+   所有其他功能图层都是在中间添加的

+   图层的可见性可以随时打开或关闭

## 向地图添加图层

在处理不同类型的图层之前，我们将讨论如何将任何图层添加到地图对象中，因为这个过程对于任何图层类型都是相同的，而且非常简单。在下图中，我们可以看到所有类型的图层：

![向地图添加图层](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_02_01.jpg)

有两种方法可以将任何图层添加到地图对象中。假设`prjMap`是定义的地图对象的名称，我们需要添加一个图层；你可以采用以下两种方法之一：

+   **方法 1**：

```js
//Method 1
prjMap.addLayer(layer1);
/*layer1 is the layer object we would like to add to the map. */
```

+   **方法 2**：

```js
//Method 2
prjMap.addLayers([layer1]);
```

就是这么简单！第二种方法是首选方法，因为某些小部件或功能必须等到地图中的所有图层加载完毕才能使用。使用第二种方法将使我们能够使用在所有图层加载完毕后触发的事件处理程序。我们将在本章末讨论这些事件处理程序。

## 图层的功能分类

从功能上讲，可以将添加到地图的不同类型的图层分类如下：

+   底图或瓦片地图图层

+   功能图层

+   图形图层

让我们分别讨论每一个。

### 底图图层

底图图层是可以用作参考背景地图的图层。通常，卫星图像、地形图（显示海拔高度的地图）或街道地图可以起到这个作用。底图通常是缓存的图像瓦片。这意味着底图是一个静态资源。由于它们是静态的，并且作为图像瓦片提供，我们无法与底图上看到的要素进行交互（例如查询或选择）。而且由于这是底图，这也是最底层的图层，也是首先添加到地图中的图层。

现在，API 提供了不同的方法来向地图添加`basemap`属性：

+   将`basemap`属性添加到地图对象中：

```js
var map = new Map("mapDiv", {basemap: "streets"});
```

+   使用 API 提供的内置`basemap`库。

这使我们能够在多个底图之间切换，例如卫星图像、街道地图、地形图、国家地理地图、OpenStreetMaps 等。

+   通过向地图对象添加瓦片地图图层来创建自己的底图（我们很快将讨论有关瓦片地图图层的内容）。

下载名为`B04959_02_CODE_01`的项目文件夹，并打开`index.html`以了解底图库小部件的使用方法：

![底图图层](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_02_02.jpg)

### 功能图层

功能图层显示所有最新更改，因此在性质上是动态的，而不同于底图或缓存瓦片图层的相对静态性质。功能图层是可以与之交互的图层。API 提供了对大多数这些图层执行不同操作的选项，例如：

+   选择要素

+   检索要素的属性和几何信息

+   对数据执行查询

+   渲染要素（使用不同的符号、颜色、宽度和其他图形属性对要素应用样式）

+   允许对要素进行创建、更新和删除（CRUD）操作

功能图层将*动态重投影*，基于 Basemap 的空间参考。这意味着功能图层的空间参考系统可能与 Basemap 不同，它们仍然会与 Basemap 对齐，因为 API 将从服务器请求功能图层的重投影数据。有不同类型的功能图层，例如动态图层和要素图层，我们将很快处理。

### 图形图层

图形图层在操作方面具有最大的灵活性。在这里，您可以向属性对象添加尽可能多的数据。您可以分配或修改其几何（使用**绘图**工具栏或甚至以编程方式），添加符号，查询它（对于功能图层，查询或更新操作可能被禁用），删除它，用它来选择功能图层中的要素，或者仅将其用作标注工具。但是图形图层的寿命也是最短的，因为它在会话结束后不会持久存在-这些只是存储在客户端上。由于这些属性，将图形图层作为最顶层是有意义的，不是吗？

### 注意

处理图形图层时，开发人员需要注意输入数据源的空间参考。`esri/geometry/webMercatorUtils`是一个方便的模块，可以让我们将 Web 墨卡托坐标转换为地理坐标，反之亦然。

## 图层类型

我们对图层的功能分类有了一瞥。API 提供了一系列模块，用于从不同数据源加载图层，这些数据源通常属于我们研究过的功能分类之一。我们将回顾 API 提供的一些最重要的图层类型以及它公开的方法和属性。

### ArcGIS Tiledmap 服务图层

这是由 ArcGIS Server 提供的缓存 Tiledmap 图层：

| 名称 | 值 |
| --- | --- |
| 模块名称 | `esri/layers/ArcGISTiledMapServiceLayer` |
| 数据源类型 | `ArcGIS REST Service` |
| 图层类型 | `BaseMap /Tiled Cache Layer` |
| 响应类型 | `Cached image tiles` |
| 构造函数 | `new ArcGISTiledMapServiceLayer(url, options?)` |
| 首选别名 | `ArcGISTiledMapServiceLayer` |

### 提示

**首选别名**

API 提供的首选别名作为代码约定的一部分，并可以在[`developers.arcgis.com/javascript/jsapi/argument_aliases.html`](https://developers.arcgis.com/javascript/jsapi/argument_aliases.html)上访问。

为什么我们需要使用不同的 Basemap，当我们已经有 Esri 提供的很多选项呢？嗯，我们发现了来自 NOAA 的美学和视觉信息丰富的瓦片地图服务，显示了世界地形和海底地形（海底高程差异）的彩色阴影浮雕：

![ArcGIS Tiledmap 服务图层](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_02_03.jpg)

您可以考虑将其用作 Basemap，用于显示任何全球现象，如灾害或地震。我们该如何做呢？如果您查看此模块的构造函数，它会查找一个必需的`URL`参数和一个可选的`options`参数。

我们谈论的 NOAA 服务的 URL 是[`maps.ngdc.noaa.gov/arcgis/rest/services/etopo1/MapServer`](http://maps.ngdc.noaa.gov/arcgis/rest/services/etopo1/MapServer)。

现在，让我们尝试将其作为`ArcGISTiledMapLayer`来使用（代码参考：`B04959_02_CODE1.html`）：

```js
require([
"esri/map",
"esri/layers/ArcGISTiledMapServiceLayer",
"dojo/domReady!"
    ], function (
            Map, ArcGISTiledMapServiceLayer
        ) {
var map = new Map("mapDiv");
vartileMap = new ArcGISTiledMapServiceLayer("http://maps.ngdc.noaa.gov/arcgis/rest/services/etopo1/MapServer");
map.addLayer(tileMap);
        });
```

这就是您需要编写的所有代码，以在屏幕上看到美丽的地图。

Tiledmap 服务的服务目录为我们提供了许多有用的信息，开发人员在使用应用程序中的 Tiledmap 服务之前应该考虑。让我们查看先前提到的`ArcGISTiledMapServiceLayer`的服务目录。在下一节提供的服务目录截图中，开发人员可以了解有关数据源的许多信息：

+   空间参考

+   TileInfo

+   初始范围和 FullExtent

+   最小比例和最大比例

+   贡献到瓦片的图层

### 空间参考

瓦片地图服务或底图的**空间参考**是开发人员在编码的初始阶段经常忽视的重要属性之一。瓦片地图服务的**空间参考**设置为整个地图的空间参考。添加到地图中的操作图层，如动态地图服务和要素图层，符合此**空间参考**，无论它们各自的空间参考是什么。

![空间参考](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_02_04.jpg)

#### TileInfo

**TileInfo**提供了有关`TiledMapService`遵循的平铺方案的信息。**详细级别**可用于设置地图的缩放范围。

#### 范围和比例信息

范围和比例信息为我们提供了有关可见瓦片范围的信息。

从项目文件夹`B04959_02_CODE_02`下载完整的代码，并查看您美丽的瓦片地图的效果。

### ArcGIS DynamicMapService 图层

这个模块，顾名思义，是来自 ArcGIS Server REST API 的动态托管资源：

| 名称 | 值 |
| --- | --- |
| 模块名称 | `esri/layers/ArcGISDynamicMapServiceLayer` |
| 数据源类型 | `ArcGIS REST 服务` |
| 图层类型 | `功能图层` |
| 响应类型 | `动态生成的图像` |
| 构造函数 | `new ArcGISDynamicMapServiceLayer(url, options?)` |

动态地图图层实际上代表了非缓存地图服务公开的所有数据。出于同样的原因，动态地图图层是一种复合图层，因为地图服务通常具有多个图层。

我们将在一会儿看到这意味着什么。我们将参考服务目录（是的，这是一个花哨的术语，用于指导我们导航到地图服务 URL 时出现的界面）。

在浏览器中打开此地图服务的 URL - [`maps.ngdc.noaa.gov/arcgis/rest/services/SampleWorldCities/MapServer`](http://maps.ngdc.noaa.gov/arcgis/rest/services/SampleWorldCities/MapServer)。

您将能够看到地图服务公开的所有数据图层。因此，当您使用此地图服务时，所有数据将作为单个 DynamicMapService 图层的一部分显示在地图上：

![The ArcGIS DynamicMapService layer](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_02_05.jpg)

### 注意

如果您无法看到先前显示的任何服务的服务目录，则并不意味着该服务已离线；可能是在生产机器上关闭了服务浏览。

确保尝试通过附加名为`f`值为`json`的查询参数来尝试 URL，例如，`{{url}}?f=json`。

之前，我们讨论了如何将`ArcGISTiledMapServiceLayer`添加到地图中。以下代码在现有的瓦片图层上添加了`ArcGISDynamicMapService`图层：

```js
require(["esri/map",
"esri/layers/ArcGISTiledMapServiceLayer",
"esri/layers/ArcGISDynamicMapServiceLayer",
"dojo/domReady!"
],
function (
Map,
ArcGISTiledMapServiceLayer,
ArcGISDynamicMapServiceLayer
) {
var map = new Map("mapDiv");
varshadedTiledLayer = new ArcGISTiledMapServiceLayer('http://maps.ngdc.noaa.gov/arcgis/rest/services/web_mercator/etopo1_hillshade/MapServer');

**varworldCities = new ArcGISDynamicMapServiceLayer("http://maps.ngdc.noaa.gov/arcgis/rest/services/SampleWorldCities/MapServer");**

map.addLayers([shadedTiledLayer, worldCities]);
    });
```

现在，如果您已经注意到，`ArcGISDynamicMapServiceLayer`和`ArcGISTiledMapServiceLayer`都使用地图服务。那么，我们如何知道哪个地图服务应该用作瓦片地图服务，哪个可以用作 DynamicMapService 呢？您可能已经猜到了。服务目录就是答案。服务目录中有一个特定的标题，您必须在其中查找区分缓存瓦片地图服务和非缓存地图服务的地图服务。这就是**TileInfo**。

### 注意

区分缓存瓦片地图服务和非缓存地图服务的属性称为 Tile Info。

TileInfo 包含有关详细信息的信息。详细级别确定地图将显示的离散比例级别。这些详细级别也称为缩放级别，地图的缩放控件中的标记与这些缩放级别对应。

现在，瓦片地图服务和动态地图服务响应的提供方式是相似的。两者都是作为图像提供的。瓦片地图服务为每个范围提供多个图像瓦片，而动态地图服务仅为给定范围提供一个图像。

如果您注意到您的**网络**选项卡，将会有一个名为`export`的`GET`请求方法附加到我们声明的 DynamicMapService。这是从服务器获取动态地图图像的`GET`请求：

![ArcGIS DynamicMapService 图层](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_02_06.jpg)

观察前面`GET`请求的查询字符串中的名称-值对。您会注意到以下字段名：

+   `dpi`字段名定义了每英寸点数的图像分辨率

+   `transparent`字段名定义了响应图像是透明的，因此可以查看背景 Basemap

+   `format`字段名的值为`png`，这是响应图像的格式

+   `bbox`字段名的值请求图像所请求的范围（由四个坐标—`Xmin`、`Ymin`、`Xmax`和`Ymax`组成）。

+   `bboxSR`字段名的值定义了`bbox`坐标的空间参考，`imageSR`定义了请求响应图像的空间参考

+   最后一个字段名为`f`定义了响应的格式；当然是一个`image`

### 注意

**练习**

在前面的`GET`请求中，将`f`字段名的值从`image`更改为`html`，然后查看您会得到什么。

如果您查看 API 页面，您会发现此模块提供了许多属性和方法。以下表格显示了一些最重要的方法：

| 方法名 | 描述 |
| --- | --- |
| `exportMapImage(imageParameters?, callback_function?)` | 这使用`imageParameters`对象指定的值导出地图。回调函数事件返回地图图像。 |
| `refresh()` | 这将通过向服务器发出新请求来刷新地图。 |
| `setDPI(dotsPerInch)` | 这使得可以设置导出地图的每英寸点数的图像分辨率。 |
| `setLayerDefinitions(stringArray of Layerdefintions)` | 这使我们能够过滤动态地图服务显示的数据。 |
| `setVisibleLayers(Array_of_LayerIds)` | 这只显示传递参数作为 ID 的图层。 |

现在，请确保您具备以下要求以显示 DynamicMapService：

+   仅显示`Cities`图层

+   为动态地图图像提供 0.5 的透明度

+   仅显示人口超过 100 万的城市

以下代码片段指导您如何完成此操作（代码参考：`B04959_02_CODE2.html`）：

```js
varworldCities = new ArcGISDynamicMapServiceLayer("http://maps.ngdc.noaa.gov/arcgis/rest/services/SampleWorldCities/MapServer", {
"id": "worldCities",
**"opacity": 0.5,**
"showAttribution": false
});
**worldCities.setVisibleLayers([0]);**
**worldCities.setLayerDefinitions(["POP > 1000000"]);**

```

### 注意

当任何地图对象的选项对象中的`showAttribution`属性设置为`true`时，数据源的所有归因都显示在地图的右下角。

`setLayerDefinitions(stringArray of Layerdefintions)`方法接受`where`子句的字符串数组。在传递动态地图服务的图层定义时，请记住以下几点。

定义表达式（`where`子句）的索引应与应用表达式的图层的索引相匹配。例如，如果`Cities`图层在前面的地图服务中的索引为`5`，则图层定义将如下所示：

```js
VarlayerDefintion = [];
**layerDefinition[5] = "POP > 1000000";**
worldCities.setLayerDefinitions(layerDefinition);
```

一旦满足这些条件，生成的地图将如下所示。半透明的蓝色点是人口超过一百万的世界城市：

![ArcGIS DynamicMapService 图层](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_02_07.jpg)

### 要素图层

要素图层是地图服务的一个单独图层，具有几何类型。地图服务中的单独图层可以是要素图层，甚至是栅格图层；例如，[`sampleserver4.arcgisonline.com/ArcGIS/rest/services/Elevation/ESRI_Elevation_World/MapServer/1`](http://sampleserver4.arcgisonline.com/ArcGIS/rest/services/Elevation/ESRI_Elevation_World/MapServer/1)和[`maps.ngdc.noaa.gov/arcgis/rest/services/web_mercator/hazards/MapServer/0`](http://maps.ngdc.noaa.gov/arcgis/rest/services/web_mercator/hazards/MapServer/0)都是地图服务的单独图层，但前一个 URL 是栅格图层资源，后一个是要素图层资源。栅格图层在服务目录中没有几何类型属性，而要素图层具有点、多点、折线或多边形几何类型之一。

要素图层是非常灵活的实体，因为它支持高级查询、选择、渲染，有时甚至支持编辑功能。要素图层（或栅格图层）是通过它所属的地图服务中的索引来识别的：

| 名称 | 值 |
| --- | --- |
| 模块名称 | `esri/layers/FeatureLayer` |
| 数据源类型 | `ArcGIS REST 服务` |
| 图层类型 | `功能图层` |
| 响应类型 | `要素集合（要素具有几何、属性和符号）` |
| 构造函数 | `new FeatureLayer(url, options?)` |

将要素图层/图层添加到地图上与添加 DynamicMapService 图层或 Tiledmap 服务图层相同：

```js
define([
"esri/map",
"esri/layers/FeatureLayer"
],
function(
Map,
FeatureLayer
){
var map = new Map("mapDiv");
var featureLayer1 = new FeatureLayer(featureLayer1URL);
var featureLayer2 = new FeatureLayer(featureLayer2URL);
**map.addLayers([featureLayer1, featureLayer2]);**
});
```

#### 要素图层构造函数

`FeatureLayer`构造函数有两个参数——`FeatureLayer` URL 和一个可选的`options`对象。`options`对象提供了一堆选项来配置`FeatureLayer`构造函数。其中最重要的`options`属性之一被命名为`mode`。

`mode`属性定义了要素图层在地图上的渲染方式。由于要素图层流式传输要素的实际几何，不像地图服务（提供动态生成的图像）或 Tiledmap 服务（只提供预先渲染的缓存瓦片），要素图层在地图上的渲染有一些性能考虑。要素图层可以通过四种模式进行渲染。这四种模式是 API 提供的常量的数值值。如果要素图层模块的回调函数别名是要素图层，那么可以使用以下装饰来访问这四种模式：

+   `FeatureLayer.MODE_SNAPSHOT`

+   这一次性地从服务器获取所有要素并驻留在客户端上

+   这在应用额外的过滤器时进行更新

+   `FeatureLayer.MODE_ONDEMAND`

+   根据需要获取要素

+   连续的小额开销

+   默认`MODE`

+   `FeatureLayer.MODE_SELECTION`

+   只有使用`selectFeatures()`方法选择的要素才会显示

+   `FeatureLayer.MODE_AUTO`

+   在`MODE_SNAPSHOT`和`MODE_ONDEMAND`之间切换（此选择由 API 进行）

+   两全其美

我们将尝试为历史地震添加一个`FeatureLayer`构造函数到地图上。提供这些要素图层的地图服务可以在[`maps.ngdc.noaa.gov/arcgis/rest/services/web_mercator/hazards/MapServer`](http://maps.ngdc.noaa.gov/arcgis/rest/services/web_mercator/hazards/MapServer)找到。

地震图层是地图服务中的第五个图层。但你也可以尝试其他要素图层。以下是一个代码片段，让你将要素图层添加到地图对象中（代码参考：`B04959_02_CODE3.html`）：

```js
define(["esri/map",
"esri/layers/FeatureLayer",
"dojo/domReady!"],
function (Map, FeatureLayer
) {
varearthQuakeLayerURL = 'http://maps.ngdc.noaa.gov/arcgis/rest/services/web_mercator/hazards/MapServer/5';
earthQuakeLayer = new FeatureLayer(earthQuakeLayerURL, {
id: "Earthquake Layer",
outFields : ["EQ_MAGNITUDE", "INTENSITY", "COUNTRY", "LOCATION_NAME", "DAMAGE_DESCRIPTION", "DATE_STRING" ],
opacity: 0.5,
mode: FeatureLayer.MODE_ONDEMAND,
definitionExpression: "EQ_MAGNITUDE > 6",
});

map.addLayers([earthQuakeLayer]);
});
```

前面的代码可以解释如下：

+   `id`属性为要素图层分配一个 ID

+   `opacity`属性让我们为地图定义不透明度

+   `definitionExpression`属性是一个`where`子句，让我们过滤在地图上显示的要素

+   `outFields`属性让我们定义要素图层提供的字段

这是`FeatureLayer`叠加在 DynamicMapService 图层和 Tiledmap 服务图层上的屏幕截图。半透明的彩色圆圈代表曾经发生过任何地震的地点，其震级超过 6 里氏标度：

![The FeatureLayer constructor](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_02_08.jpg)

当您在地图上平移或缩放时，将获取要素并触发相应的`GET`请求，该请求将*按需*获取要素。如果在加载要素图层后立即打开开发者控制台中的**网络**选项卡，您将能够了解很多事情：

+   API 使用要素图层的`query`方法来获取要素。

+   在查询字符串中，将包含查询参数，例如`geometry`，`spatialRel`，`geometryType`和`inSR`，这些参数定义了需要获取要素的范围。查询字符串中还可以找到其他`FeatureLayer`构造函数选项，例如`outFields`和`where`子句（对应于`definitionExpression`）。

+   如果单击**预览**或**响应**选项卡，您将注意到`GET`请求获取了一系列要素。每个要素都有一个属性对象和一个几何对象。属性对象将包含`outFields`数组中提到的字段名称和特定要素的相应字段值：![The FeatureLayer constructor](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_02_09.jpg)

我们将在下一章中讨论如何查询和选择要素图层中的要素。目前，我们最好知道以下方法对要素图层对象做了什么：

| 方法 | 描述 |
| --- | --- |
| `clear()` | 清除所有图形 |
| `clearSelection()` | 清除当前选择 |
| `getSelectedFeatures()` | 获取当前选择的要素 |
| `hide()` | 将图层的可见性设置为`false` |
| `isEditable()` | 如果`FeatureLayer`可编辑，则返回`true` |
| `setInfoTemplate(infoTemplate)` | 指定或更改图层的`info`模板 |
| `setOpacity(opacity)` | 图层的初始不透明度（其中`1`为不透明，`0`为透明） |
| `show()` | 将图层的可见性设置为`true` |

#### Infotemplates

Infotemplates 提供了一种简单的方式来提供 HTML 弹出窗口，显示有关要素的信息，当我们点击时。我们将在下一章中详细讨论 Infotemplates。

![Infotemplates](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_02_10.jpg)

### 图形图层

我们已经讨论了一些关于图形图层的内容。我们知道地图对象默认包含一个图形图层，并且可以使用地图对象的`graphics`属性引用它。我们还可以创建自己的图形图层并将其添加到地图中。但是，地图提供的默认图形图层始终位于顶部。

让我们更多地了解图形图层和添加到图形图层的`Graphic`对象。图形图层是`Graphic`对象的容器。

`Graphic`对象具有以下值：

+   几何

+   符号

+   属性

+   Infotemplate

#### 几何

几何将具有类型（点、多点、折线、多边形和范围）、空间参考和构成几何图形的坐标。

#### 符号

符号是一个更复杂的对象，因为它与其所代表的几何图形相关联。此外，符号的样式是由用于填充符号的颜色或图片以及符号的大小来定义的。

让我们回顾一小段代码，以更好地理解这一点。这是一个为多边形构造符号的简单代码段：

![Symbol](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_02_11.jpg)

#### 属性

图形的属性是一个键值对对象，用于存储有关图形的信息。

#### InfoTemplate

`InfoTemplate`是一个 HTML 模板，可以用来在我们点击时显示有关图形的相关信息。

## 地图和图层属性

图层之间有许多共同的属性，这些属性为我们提供了有关图层的相关信息。例如，`fullExtent`、`id`、`infoTemplates`、`initialExtent`、`layerInfos`、`maxRecordCount`、`maxScale`、`minScale`、`opacity`、`spatialReference`、`units`、`url`和`visibleLayers`对于动态地图图层和瓦片地图图层来说是相同的，而`dynamicLayerInfos`和`layerDefinitions`等属性则特定于 DynamicMapService 图层。那么，`tileInfo`属性是特定于瓦片地图图层的吗？

尝试通过将属性记录到控制台来探索这些属性。例如，如果您需要打印要素图层中的字段列表，请使用要素图层的`fields`属性。

以下是将有关要素图层和 DynamicMapService 图层的某些信息记录到控制台的代码片段（代码参考：`B04959_02_CODE5.html`）：

```js
on(map, "layers-add-result", function (evt) {
console.log("1.", earthQuakeLayer.id);
console.log("2.", earthQuakeLayer.fields);
console.log("3.", earthQuakeLayer.geometryType);
console.log("4.", earthQuakeLayer.maxRecordCount);

console.log("5.", worldCities.layerInfos);
});
```

以下是您将在控制台中获得的屏幕输出：

```js
**1\. Earthquake Layer**
**2\. [Object,**
**Object,**
**. . .**
**Object]**
 **3\. esriGeometryPoint**
**4\. 1000**
**5\. [Object, Object, Object]**

```

`Featurelayer.fields`返回一个字段对象数组。每个对象包含`alias`、`length`、`name`、`nullable`和`type`等属性。`DynamicLayer.layerInfos`返回一个`layerInfo`对象数组。`layerInfo`对象提供有关图层的信息：

![地图和图层属性](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_02_12.jpg)

## 地图和图层事件

改变地图的范围，向地图添加图层，向地图添加一组图层，甚至点击地图或鼠标 - API 对所有这些都有事件处理程序。在使用事件时，让我们坚持使用 dojo 的 on 模块来处理事件。找到使用 dojo 的`"dojo/on"`模块处理事件的原型：

![地图和图层事件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_02_13.jpg)

| 目标 | 事件 | 描述 |
| --- | --- | --- |
| 地图 | `extent-change` | 地图范围发生变化时触发 |
| 地图 | `layers-add-result` | 在使用`map.addLayers()`方法后，所有添加到地图的图层加载完成时触发 |
| 地图 | `load` | 这个很明显 |
| 地图 | `basemap-change` |   |
| 要素图层 | `selection-complete` | 从要素图层中选择要素后 |

在前面的代码片段中，记录了某些图层属性，您可能已经注意到整个代码片段都包含在一个`on`语句中：

```js
**on(map, "layers-add-result", function (evt) {**
console.log("1.", earthQuakeLayer.id);
...
console.log("5.", worldCities.layerInfos);
});
```

我们需要在`on`事件中打印出所有与图层相关的属性，因为我们需要等到所有图层加载完成，否则大多数属性都将返回未定义。这个名为`layers-add-result`的特定事件仅在所有添加到地图的图层数组加载完成后触发。

# 使用 Esri 小部件 - 神灯

小部件是 dojo 的基石。小部件是可以在 dojo 中构建、配置和扩展的 UI 组件，以执行特定任务。因此，当有人为我们提供了一个完成我们需要做的任务的小部件时，我们只需稍微配置一下，然后将其提供给小部件应该驻留的容器节点引用即可实例化它。

所以，好消息是 Esri 为我们提供了内置小部件，可以完成很多事情，比如查询要素、地理编码地址（将文本地址转换为地图上的位置）、添加小部件以显示地图图例、添加小部件以搜索属性，甚至添加小部件以在多个基础地图之间切换。所有 Esri 构建的小部件都可以在 API 参考页面的目录部分中找到，位于`esri/dijits`下。

## BaseMapGallery 小部件

嗯，你一定不会惊讶这个小部件确实存在吧？在本章开头处理`TiledMapLayers`时，我们已经提醒过你了。Basemap 图层小部件为我们提供了一个小部件，我们可以从基础地图库中切换基础地图。查看以下集成基础地图到我们应用程序的原型代码（代码参考：`B04959_02_CODE6`）：

```js
require(["esri/map",
"esri/dijit/BasemapGallery"], function (Map, BasemapGallery){
varbasemapGallery = new BasemapGallery({
showArcGISBasemaps: true,
map: map
        }, "basemapGalleryDiv");
});
```

## 图例小部件

地图图例列出了地图中的图层和所有图层使用的符号。自己构建图例涉及获取`layerinfos`和`drawinginfos`，并将它们列在`div`中——这个过程听起来很麻烦。幸运的是，Esri 为我们提供了`dijit`（可能是 dojo 和 widget 的混成词）来构建图例：

![图例小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_02_14.jpg)

我们使用以下代码来启动**图例**小部件（代码参考：`B04959_02_CODE6`）

```js
require(["esri/map",
"esri/dijit/Legend"],  function (Map, Legend){
    on(map, "layers-add-result", function (evt) {
varlegendDijit = new Legend({
map: map,
            }, "legendDiv");
legendDijit.startup();
        });
});
```

# 摘要

本章我们涵盖了很多内容。我们试图确定数据添加到地图的过程。我们确定了数据源，如 ArcGIS 服务器服务、OGC 数据、CSV、KML 等。然后，我们介绍了支持显示和进一步操作三种主要 ArcGIS REST 服务数据源的 API 提供的模块，即 ArcGIS Tiledmap 服务图层、ArcGIS DynamicMapService 图层和要素图层。您还学会了如何实例化图层以及如何浏览它们的属性和事件。我们还处理了一种特殊类型的图层，即图形图层，它是地图中最顶层的图层，并且用作地图中所有图形的容器对象。我们品尝了 Esri 提供的大量内置小部件。在下一章中，我们将深入研究编写空间查询和检索结果。您还将学习如何使用几何服务和几何引擎来处理几何操作。


# 第三章：编写查询

|   | *"提问的艺术和科学是所有知识的源泉。"* |   |
| --- | --- | --- |
|   | --*托马斯·伯格* |

查询是通过 API 向地图提出问题的门户。它们在 API 术语中被视为*任务*，因为形成查询并获取答案的过程是一系列必须正确执行的操作。在本章中，我们将开发一个野火位置应用程序，以了解以下概念：

+   构建和执行查询任务

+   构建和执行识别任务

+   构建和执行查找任务

+   查询、查找和识别任务的承诺、延迟和结果对象

+   使用`FeatureTable dijit`

+   使用`Infotemplates`

# 开发野火应用程序

在本章中，我们将开发一个应用程序，该应用程序将显示美国的活跃野火位置，并显示任何位置的野火潜在风险的背景地图。我们还将尝试通过利用 API 提供的组件来提供搜索/查询功能。以下屏幕截图提供了我们在本章结束时将开发的最终应用程序的大致呈现：

![开发野火应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_01.jpg)

该应用程序将具有以下组件：

+   深灰色底图

+   两个操作地图服务，一个显示美国的野火潜在风险（栅格数据），另一个显示活跃的野火位置（点数据）

+   一个图例 dijit（dojo 小部件），显示添加到地图上的图层的符号

+   一个报告小部件，显示所有活跃野火位置的记录

+   一个查询小部件，您可以根据数据中的区域范围查询活跃的野火位置（此信息在数据的一个字段中可用）

+   一个查找小部件，您可以在其中输入任何文本，所有与搜索文本匹配的州或火灾名称都将被获取

+   一个地图点击事件，将在地图点击位置标识并显着显示野火潜在风险

+   有两个操作数据源；一个是位于[`maps7.arcgisonline.com/arcgis/rest/services/USDA_USFS_2014_Wildfire_Hazard_Potential/MapServer`](http://maps7.arcgisonline.com/arcgis/rest/services/USDA_USFS_2014_Wildfire_Hazard_Potential/MapServer)的野火潜在风险地图服务，另一个是位于[`livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/Wildfire_Activity/MapServer`](http://livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/Wildfire_Activity/MapServer)的活跃野火数据

+   后一个地图服务是一个*安全*地图服务，这意味着我们需要一个 ArcGIS Online 帐户或 ArcGIS 开发者帐户来使用它。除了前述数据源，要访问 ArcGIS Online 数据的大量数据以及发布在世界生活地图集（[`doc.arcgis.com/en/living-atlas/`](http://doc.arcgis.com/en/living-atlas/)）中的数据，我们需要执行以下操作：

+   在 ArcGIS 开发者门户中注册应用程序并获取应用程序的令牌

+   在我们的应用程序中加入 ArcGIS 代理代码

## 在开发者门户中注册应用程序

使用我们的 ArcGIS 开发者凭据（我们在第一章的*设置开发环境*部分中创建的）登录到 ArcGIS 开发者门户（[`developers.arcgis.com/`](https://developers.arcgis.com/)）。

接下来，通过单击以下屏幕截图中突出显示的适当图标，导航到开发者门户的**应用程序**页面。您甚至可以通过访问[`developers.arcgis.com/applications/`](https://developers.arcgis.com/applications/)来实现。

![在开发者门户中注册应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_02.jpg)

当我们点击**注册新应用程序**按钮时，我们将被提示输入关于我们的应用程序的详细信息，如下图所示。提供所需的详细信息后，如果我们再次点击**注册新应用程序**按钮，我们将被带到另一个屏幕，显示应用程序的令牌。这个短暂的令牌可以用于访问任何受 ArcGIS Online 地图服务保护的服务。例如，尝试在浏览器中访问这个—[`livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/Wildfire_Activity/MapServer`](http://livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/Wildfire_Activity/MapServer)。

您将被重定向到一个需要您输入令牌的页面。当您提供在上一个屏幕中获得的令牌时，您可以看到我们打算查看的地图服务的服务目录。以下屏幕截图解释了这个过程：

![在开发者门户中注册应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_03.jpg)

## 在应用程序中使用代理

在这个项目中，我们需要使用 Esri 资源代理来访问安全的 ArcGIS Online 数据源。资源代理是处理来自客户端到 ArcGIS Server 的请求并将来自 ArcGIS Server 的响应转发回客户端的服务器端代码。Esri 提供了一个专门适用于 ArcGIS Server 和 ArcGIS Online 的代理实现。Github 代码可以在[`github.com/Esri/resource-proxy`](https://github.com/Esri/resource-proxy)找到。

我们将只使用包含以下重要文件的资源代理的 ASP.NET 变体：

+   `proxy.ashx`

+   `proxy.config`

+   `Web.config`

`proxy.ashx`文件包含用于发出请求并将响应转发回客户端的服务器端代码逻辑。我们需要配置`proxy.config`并在其中包含我们的 ArcGIS 开发者凭据。以下是`proxy.config`页面的示例截图：

![在应用程序中使用代理](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_04.jpg)

要配置`proxy.config`文件，请执行以下步骤：

1.  在`proxy.config`文件中，修改`serverUrl`标签中`url`、`username`和`password`的属性值。对于`tokenServiceUri`属性，值应始终为`https://www.arcgis.com/sharing/generateToken`。

1.  对于`url`属性，值将是 ArcGIS Server 服务的位置。指定特定的 URL（在这种情况下，您将设置`matchAll="false"`）或只是根 URL（如前面的屏幕截图所示；在这种情况下，`matchAll`值将是`"true"`）。

### 注意

有关配置`proxy.config`文件的更多详细信息，请参阅[`github.com/Esri/resource-proxy/blob/master/README.md#proxy-configuration-settings`](https://github.com/Esri/resource-proxy/blob/master/README.md#proxy-configuration-settings)。

1.  配置代理页面后，我们需要在应用程序中添加几行代码。我们需要加载`esri/config`模块，并在我们的应用程序代码中使用以下行：

```js
esriConfig.defaults.io.proxyUrl = "/proxy/proxy.ashx";
esriConfig.defaults.io.alwaysUseProxy = true;
```

在我们的应用程序中，`proxy.ashx`页面位于应用程序根目录下的`proxy`文件夹中。如果代理页面位于不同的应用程序中，我们需要更改`esriConfig.defaults.io.proxyUrl`变量的值。当我们将`esriConfig.defaults.io.alwaysUseProxy`值设置为`true`时，所有请求都将由代理处理。如果我们只需要特定的 URL 由代理处理，我们可能需要添加几行代码，如下所示：

```js
urlUtils.addProxyRule({
urlPrefix: "route.arcgis.com",
proxyUrl: "/proxy/proxy.ashx"
    });
```

`urlUtils`函数由`esri/urlUtils`模块提供。

以下图表显示了从客户端到安全 ArcGIS Server 服务的 HTTP REST 请求的流程：

![在应用程序中使用代理](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_05.jpg)

## 引导应用程序

本书中的所有应用程序都使用 Bootstrap 地图库进行样式设置和引导。这些库的源代码可以在[`github.com/Esri/bootstrap-map-js`](https://github.com/Esri/bootstrap-map-js)找到。

下载所需的库后，我们需要将以下 CSS 和 JavaScript 库添加到我们的应用程序中：

```js
<head>
<!-- Bootstrap-map-js& custom styles -->
<link href="css/lib/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" type="text/css" href="css/lib/bootstrapmap.css">
<link rel="stylesheet" href="//netdna.bootstrapcdn.com/font-awesome/4.0.3/css/font-awesome.css">
</head>
<body>

<script src="http://code.jquery.com/jquery-1.10.1.min.js"></script>
<script src="js/lib/bootstrap.min.js"></script>
</body>
```

添加这些库后，我们需要添加另一个 JavaScript 文件作为 dojo 模块，而不是作为脚本引用。在我们的应用程序中，讨论中的 JavaScript 库位于`/js/lib/bootstrapmap.js`。

将此库作为 require 函数中的模块添加时，我们需要省略文件扩展名。以下屏幕截图说明了这一说法：

![引导应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_06.jpg)

因此，我们将使用`bootstrapmap`模块而不是`esri/map`模块来创建地图。`bootstrapmap`模块接受`esri/map`提供的所有属性和方法，因为`bootstrapmap`模块只是`esri/map`模块的包装。

# 查询操作类型

在 ArcGIS Server 提供的数据上可以进行各种类型的查询操作。在本章中，我们将处理 API 提供的三种最重要的查询操作：

+   查询任务

+   查找任务

+   识别任务

## 查询任务

查询任务让我们只操作一个图层，因此查询任务的构造函数要求我们提供要素图层的 URL。查询任务让我们使用属性（字段值；例如，查询人口超过 200 万的城市）或使用位置（例如，查找所有位于地图当前范围或自定义绘制范围内的加油站）。当满足查询条件的要素数量大于服务器设置的限制（ArcGIS Server 中的`maxRecordCount`设置）时，我们可以使用名为*分页*的功能以批处理模式检索所有要素。

## 查找任务

查找任务可以在地图服务和多个字段上操作。查找任务基本上在给定地图服务中的所有图层的所有字段中搜索给定的文本。当我们不知道要搜索的字段，因此无法构造适当的 SQL`where`子句来查询数据时，这是一个理想的操作依赖。

## 识别任务

识别任务主要是基于位置的搜索操作，返回与给定几何图形（例如地图点击点）相交的给定地图服务中所有图层的所有数据。

在所有前面的任务中，我们可以限制进行搜索操作的字段或图层。以下矩阵总结了三种不同类型的查询操作可用的所有选项：

![识别任务](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_07.jpg)

# 构建和执行查询任务

**查询任务**旨在查询`featureLayer`。因此，要实例化`querytask`，我们需要提供`featurelayer`的 URL。在 API 的 3.15 版本中，该模块被命名为`esri/tasks/QueryTask`。

## QueryTask 构造函数

`QueryTask`构造函数的语法如下：

```js
newQueryTask(url, options?)
```

`QueryTask`构造函数的示例如下：

```js
require([
"esri/tasks/QueryTask", ...
], function(QueryTask, ... ) {
varqueryTask = new QueryTask("<Feature Layer URL>")
});
```

### 构造函数参数

启用查询功能的要素图层的 URL，以验证要素图层上的查询功能是否已启用，我们必须访问地图服务的服务目录，并检查“查询”是否是我们想要查询的要素图层支持的操作之一。

例如，在我们处理的 Active Wildfire 地图服务中，我们想要查询包含有关 Active Wildfire 图层的数据的图层。地图服务中只有一个图层，因此要素图层的图层索引为`0`。

要素图层的 URL 是[`livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/Wildfire_Activity/MapServer/0`](http://livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/Wildfire_Activity/MapServer/0)。

当我们访问此链接并滚动到页面底部找到**支持的操作**部分时，我们将看到查询操作被列在那里：

![构造函数参数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_08.jpg)

使用 Query 任务执行查询涉及以下步骤：

![构造函数参数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_09.jpg)

## 实例化 QueryTask 对象

查询任务基于 Active Wildfire 要素图层。因此，我们将使用要素图层的 URL 来实例化`QueryTask`对象。以下代码行解释了如何实例化`QueryTask`：

```js
var wildFireActivityURL = "http://livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/Wildfire_Activity/MapServer/0";
var queryTask = new QueryTask(wildFireActivityURL);
```

## 构建查询对象

`QueryTask`对象只是定义要查询的图层或数据，但我们需要使用`Query`对象来定义实际的查询是什么。`Query`对象由`esri/tasks/Query`模块提供。

查询对象执行以下操作：

+   它形成一个 SQL`where`子句来按属性查询。

+   它使用空间几何体执行查询。

+   它指示查询执行时的空间关系。

+   它请求从服务器获取要素字段的数组。

+   它指示查询结果是否需要返回几何信息。

查询对象有一个名为`where`的属性。该属性接受 SQL 的`where`子句，并获取满足`where`子句的数据。

`where`子句的格式如下：

```js
query.where = "<Query Expression 1><AND/OR><Query Expression 2> …<AND/OR><QueryExpression n>"
```

其中`Query Expression`是`"<FieldName><operator><value>";`。`<FieldName>`是要查询的要素中字段的名称。

`<operator>`是一种 SQL 运算符，例如`LIKE`，`=`,`>`,`<`。

以下代码片段演示了`where`子句的使用：

```js
query.where = "STATE = 'OK' OR STATE = 'WY'";
```

当我们想要从`feature`类中检索所有要素时，`where`子句需要设置为**真**表达式，例如`1=1`。真表达式是在所有情况下都评估为`true`的表达式。

您可以使用真表达式检索所有要素：

```js
query.where = "1=1";
```

### 注意

在实践中，使用此表达式返回的要素数量由服务器设置`MaxRecordCount`确定，如下截图所示。默认值为`1000`。可以在 ArcGIS 服务器设置中更改此限制。

在评估字符串时，请记住将字符串值括在单引号内：

```js
locQuery.where = "STATE_NAME = 'OK'";
```

输出要素集中所需的字段可以作为字段名称数组传递给`query`对象参数`outFields`：

```js
query.outFields = ["FIRE_NAME", "STATE ", "LATITUDE", "LONGITUDE"];
```

我们可以通过将值`true`或`false`传递给`query`对象参数`returnGeometry`来指示是否需要要素的几何信息：

```js
query.returnGeometry = true;
```

以下截图显示了如何构造一个完整的`Query`对象，该对象可以从`Query`任务对象中设置的要素图层中检索所有要素：

![构建查询对象](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_10.jpg)

### 通过空间几何体查询

我们可以从具有与另一个输入几何体的空间关系的要素图层中获取要素。我们需要定义输入几何体和要检索的要素之间的空间关系。当未定义时，默认空间关系变为交集。这意味着我们正在尝试获取与输入几何体相交的要素。

![通过空间几何体查询](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_11.jpg)

查询对象还提供了其他类型的空间关系作为常量：

+   `Query.SPATIAL_REL_CONTAINS`：这将检索完全包含在输入几何体中的所有要素

+   `Query.SPATIAL_REL_INTERSECTS`：这是默认的空间关系，获取与输入要素相交的所有要素

+   `Query.SPATIAL_REL_TOUCHES`：在这里，获取所有与输入几何体相接触的要素

通常，输入几何体可能是来自另一个要素、类或`draw`对象的几何体，或者在我们的情况下，当前地图的范围，如下面的代码片段所示：

```js
var query = new Query();
query.outFields = ["FIRE_NAME", "STATE", "LATITUDE", "LONGITUDE"];
query.returnGeometry = false;
query.where = "1=1";
query.geometry = map.extent;
query.returnGeometry = false;
```

## 执行查询

当我们需要执行查询并检索结果时，我们需要在查询任务对象中调用查询执行方法。可以执行查询任务以获取满足查询条件的实际特征。在某些情况下，我们可能只需要满足查询条件的特征数量或查询结果的空间范围。可以在查询任务对象上执行五种类型的查询操作：

+   查询特征

+   查询数量

+   查询范围

+   查询对象 ID

+   关系查询

所有操作都接受查询对象作为第一个参数，并返回一个延迟对象。让我们了解三个最重要的查询任务操作的用途：查询数量，查询范围和查询特征。

### 查询数量

当我们只想要满足查询条件的特征数量时，可以使用这个操作。以下屏幕截图显示了在一组查询特征上进行数量查询操作，给定一个查询对象（带有查询范围）。结果将是满足查询对象的特征数量：

![查询数量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_12.jpg)

通过数量查询特征的图示

当我们使用查询任务的`executeForCount()`方法时，仍然使用查询对象作为方法参数。这可以是属性查询、空间查询或两者的组合。这个方法的主要目的是快速评估查询操作返回的特征数量。有时，这可能是您需要向用户显示的唯一信息。

让我们继续创建一个用户界面来获取满足我们查询条件的特征数量。以下屏幕截图显示了一个带有文本框输入查询文本和**获取数量**按钮的引导面板。我们还提供了另一个隐藏的`div`。`div`包含一个显示特征数量的标签。

![查询数量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_13.jpg)

点击**获取数量**按钮时应该执行查询操作。当在查询文本框中没有提供输入时，查询将评估为真值表达式；也就是说，将返回地图范围内所有特征的数量。以下代码就是实现这一点的：

```js
on(dom.byId("queryBtn"), "click", function () {
query.outFields = ["FIRE_NAME", "STATE", "LATITUDE", "LONGITUDE"];
query.returnGeometry = false;
query.where = dom.byId("queryTxt").value || "1=1";
query.geometry = map.extent;
varqueryCountDeferred = queryTask.executeForCount(query);
queryCountDeferred.then(function (count) {
dom.byId("FeatCountDiv").style.display = "block";
dom.byId("featCountLbl").innerHTML = "Result: " + count + " Features";
}, function (err) {
console.log(err);
});
});
```

在上述代码片段中，`on`是由 dojo 提供的事件处理程序模块（`dojo/on`）。`dom`模块的`byId()`方法用于获取具有 ID—`queryBtn`的`dom`元素的引用。我们在`queryBtn`的`click`事件上执行了上述代码片段。请注意，在突出显示的代码中，我们处理了当查询文本框没有输入时的情况。`executeForCount()`方法返回一个延迟对象。当`Deferred`对象被解析时，使用`.then()`方法触发回调。在`.then`方法中，我们定义了两个函数；第一个函数在操作成功时触发，第二个函数在操作抛出错误时触发。我们还可以在`queryTask`对象上使用`execute-for-count-complete`事件来检索结果。

`result`对象只返回数量。

请参考以下 API 文档，以获取有关此方法返回的结果对象的更多信息—[`developers.arcgis.com/javascript/jsapi/querytask-amd.html#event-execute-for-count-complete`](https://developers.arcgis.com/javascript/jsapi/querytask-amd.html#event-execute-for-count-complete)。

我们在地图上的操作结果将如下屏幕截图所示：

![查询数量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_14.jpg)

我们还在用户界面中引入了**获取特征**按钮，以检索满足查询条件的实际特征记录，并在 HTML 表格中显示它们。我们将在`queryTask`对象上执行`execute()`方法来实现这一点。

### 查询特征

这种方法提供了有关正在查询的特征的最大信息。

查询特征操作的图示如下：

![查询要素](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_15.jpg)

`QueryTask`对象中的`execute()`方法用于查询要素。此方法返回一个`Deferred`对象。此成功事件处理程序返回一个`Featureset`对象。`Featureset`对象返回一个包含要素数组的数组，以及有关要素的几何类型和空间参考的其他辅助信息。

要素集包含以下内容：

+   **features**：图形数组。图形数组中的每个项目都具有以下属性：

+   **attributes**：与图形关联的字段和字段值的名称值对

+   **geometry**：定义图形的几何

+   **geometryType**：要素的几何类型。

+   **spatialReference**：要素的空间参考。

在我们的应用程序中，我们将尝试在单击按钮时调用`execute`方法，并构造一个 HTML 字符串，该字符串将使用称为`FeatureSet`的结果将其显示为 HTML 表。以下屏幕截图演示了如何遍历结果要素集并创建 HTML 表字符串：

![查询要素](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_16.jpg)

单击**获取要素**按钮时，用于获取要素计数的查询对象也用于执行此查询操作。因此，理想情况下，每次更改查询文本或地图范围时，**获取要素**按钮和 HTML 查询结果将被隐藏，我们需要在单击**获取要素**按钮之前单击**获取计数**按钮。我们编写了一个函数，隐藏显示要素计数的 div，并清除 HTML 表。代码如下所示：

```js
function clearQueryTbl() {
dom.byId("FeatCountDiv").style.display = "none";
dom.byId("QueryTbl").innerHTML = '';
}
```

以下屏幕截图展示了我们在地图上的代码运行情况：

![查询要素](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_17.jpg)

### 查询范围

当我们想要知道满足查询的要素的范围时，我们可以使用这种方法。这将在许多方面帮助我们：

+   我们可以了解现象的空间范围

+   我们可以将地图缩放到要素的范围，而无需实际接收要素

以下图表说明了“范围”操作的查询：

![查询范围](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_18.jpg)

# 构建和执行 IdentifyTask

`IdentifyTask`可以在地图服务中操作多个图层，并从与给定几何图形相交的所有要素中获取信息。我们将使用 IdentifyTask 在地图上单击并获取单击位置处的潜在野火价值。要执行`IdentifyTask`，我们需要遵循三个步骤：

1.  实例化 IdentifyTask。

1.  构造 Identify 参数。

1.  执行 IdentifyTask。

## 实例化 IdentifyTask

实例化 IdentifyTask 涉及加载所需的模块并使用地图服务 URL 进行实例化。执行`IdentifyTask`所需的模块如下：

+   `esri/tasks/IdentifyTask`

+   `esri/tasks/IdentifyParameters`

我们将在野火潜力地图服务上操作 IdentifyTask。地图服务包含单个栅格图层和表示野火潜力级别的像素值。以下代码片段显示了如何实例化 IdentifyTask：

```js
varwildfirePotentialURL = "http://maps7.arcgisonline.com/arcgis/rest/services/USDA_USFS_2014_Wildfire_Hazard_Potential/MapServer";
varidentifyTask = new IdentifyTask(wildfirePotentialURL);
```

## 构造识别参数对象

Identify 参数提供了许多属性来定义正在执行的识别操作。在处理多个图层时，我们可以使用`layerIds`属性来限制可以执行识别的图层。`geometry`属性让我们设置用于选择地图服务中的要素的几何图形。在我们的应用程序中，我们使用地图`click`点作为 IdentifyParameter 的输入几何图形。当使用点几何时，我们还需要为 IdentifyParameters 中的容差属性定义值。容差值是指可以被视为输入几何的一部分的输入点几何周围的像素数。

在下面的截图中，我们构造了一个识别参数对象，该对象被地图`click`事件处理程序包裹。地图`click`事件处理程序的`mapPoint`属性为识别操作提供了输入几何对象：

![构造识别参数对象](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_19.jpg)

## 执行 IdentifyTask

`execute()`方法可以用于执行 IdentifyTask。`execute()`方法返回`Deferred`对象，`Deferred`对象的成功回调返回`IdentifyResult`数组对象。

识别结果表示地图服务中一个图层中的单个已识别要素。该对象具有以下属性：

+   `displayFieldName`：这是图层的主要显示字段的名称

+   `feature`：`feature`对象包含一个数组对象和一个几何对象

+   `layerId`：这是包含要素的图层的唯一 ID

+   `layerName`：这是图层的名称

由于识别结果是一个数组对象，我们只显示一个值，我们将从识别结果对象中取出第一个值（`result[0]`），如下截图所示。我们需要显示的值在一个名为`CLASS_DESC`的属性字段中。由于这个值是由一个以冒号（`:`）分隔的类代码前缀和类描述组成的（例如，`5`：非常高），我们将根据冒号分隔字符串并仅使用描述部分。

以下截图显示了用于执行识别操作以及将识别结果显示为`map`点击位置的标签的代码，该位置由指针光标表示：

![执行 IdentifyTask](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_20.jpg)

# 构建和执行查找任务

查找任务基本上是对地图服务中所有字段进行基于属性的搜索。查找任务的结果与 IdentifyTask 的结果相同，只是多了一个`foundFieldName`的值，表示搜索文本所在的字段名称。与 Query 任务和 IdentifyTask 类似，执行查找任务的三个步骤如下：

1.  实例化一个查找任务。

1.  构建查找参数。

1.  执行查找任务。

让我们逐一讨论这三个步骤。

## 实例化查找任务

要执行查找任务，需要加载以下模块：

+   `esri/tasks/FindTask`

+   `esri/tasks/FindParameters`

我们需要提供地图服务的 URL 来实例化查找任务。以下代码段显示了我们将如何在应用程序中执行此操作：

```js
var find = new FindTask("http://livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/Wildfire_Activity/MapServer");
```

## 构建查找参数

要构建查找参数，我们需要使用`esri/task/FindParameters`模块。查找参数模块具有诸如`searchText`、`layerIds`和`seachFields`之类的属性，让我们定义查找任务。`searchText`属性是需要搜索的文本，这需要来自 UI 文本框。`layerIds`让我们定义查找任务应该操作的`layerIds`。我们还可以限制进行搜索的字段。以下截图显示了我们如何构建查找任务的 UI 并构造查找参数对象：

![构建查找参数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_21.jpg)

## 执行查找任务

`Find`任务的`execute()`方法可用于执行它。调用此方法将返回一个`Deferred`对象，在其成功回调函数中返回一个查找结果对象。我们将尝试构建一个 HTML 表格，就像我们为 Query 任务结果所做的那样，并在`FindTbl div`中显示它。以下代码行用于完成此操作：

```js
var findTaskDeferred = find.execute(findParams);
findTaskDeferred.then(function (result) {
  vartblString = '<table class="table table-striped table-hover">';
  tblString += '<thead><tr><th>FIRE NAME</th>';
  tblString += '<th>STATE</th>';
  tblString += '<th>LOCATION</th>';
  array.forEach(result, function (searchitem) {
    tblString += '<tr><td>' + searchitem.feature.attributes["Fire Name"] + '</td>';
    tblString += '<td>' + searchitem.feature.attributes["State"] + '</td>';
    tblString += '<td> (' + searchitem.feature.attributes["Longitude"] + ',' + searchitem.feature.attributes["Latitude"] + ')</td></tr>';
  });
  tblString += '</tbody></table >';
  dom.byId("FindTbl").innerHTML = tblString;
}, function (err) {
  console.log(err);
});
```

在下面的截图中，我们可以看到当我们插入搜索文本`W`时，搜索文本已从两个不同的字段**Fire Name**和**State**中获取：

![执行查找任务](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_22.jpg)

# 构建要素表

要素表构建一个表，显示给定要素图层的所有信息，并将其放置在给定的`dom`元素中。要素表是 Esri 小部件，可以通过加载`esri/dijit/FeatureTable`模块来使用。该模块允许我们选择要显示的字段。下面的截图显示了如何构建要素表以及它在应用程序中的显示方式：

![构建要素表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_23.jpg)

# 构建弹出窗口

当您的 Web 应用程序的用户点击感兴趣的要素时，他们应该看到有关他们点击的要素的一系列有用信息。弹出窗口是向用户显示特定上下文属性信息的媒介。弹出窗口补充了地图的空间信息。

最简单的弹出窗口只显示所有或选定的属性值。更高级和直观的弹出窗口在弹出窗口中使用图表和图像。

帮助创建弹出窗口的模块包括`esri/InfoTemplate`、`esri/dijit/PopupTemplate`、`esri/dijit/InfoWindow`和`esri/dijit/Popup`。

`esri/dijit/PopupTemplate`扩展了`esri/InfoTemplate`，而`esri/dijit/Popup`扩展了`esri/dijit/InfoWindow`。因此，让我们简要介绍一下`InfoTemplate`，然后转向`Popup`模板。

## 构建 Infotemplates

可以使用占位符创建`InfoTemplate`对象。占位符通常是属性字段名，以美元符号（`$`）开头，用大括号（`{}`）括起来，例如`${Fieldname}`。

当我们需要检索感兴趣要素提供的所有字段时，字段名可以被`*`替换，例如`${*}`。

要素图层和图形对象都有`InfoTemplate`属性。创建的`infotemplate`可以设置为这些图层。`InfoTemplate`构造函数接受两个参数，标题和内容：

| 模块 | 值 |
| --- | --- |
| 模块名称 | `esri/InfoTemplate` |
| 父对象 | 要素图层、图形对象、动态图层和地图的信息窗口 |
| 构造函数 | `new InfoTemplate (title, content)` |

下面的截图为`Active wildfire`要素图层创建了`infotemplate`，并在弹出窗口中显示了州名、火灾名称和被点击的野火要素的面积范围等字段。`Infotemplate`的标题也是由占位符创建的：

![构建 Infotemplates](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_03_24.jpg)

本章的代码清单可以在名为`B04959_03_CODE`的代码文件夹中找到。

# 摘要

本章解释了搜索和查询数据的不同方法。我们构建了一个应用程序，可以执行查询任务、查找任务，以及识别任务。我们还发现了名为`dijit`的要素表以及`Infotemplates`的实用性。在下一章中，我们将看到如何将所有代码组织成模块化小部件，并在应用程序中使用它。我们还将讨论涉及使用绘图工具栏的空间查询的构造，以及创建由应用程序用户定义的输入几何体。


# 第四章：构建自定义小部件

本章的主要目标是开发一个自定义小部件，可以执行空间查询并在简单的 HTML 表格中显示结果。在构建自定义小部件的过程中，您将学习以下主题：

+   如何使用道场创建一个简单的类

+   如何全局配置道场

+   道场小部件的生命周期是什么

+   如何创建模板小部件

+   如何为国际化提供支持

+   如何组织道场代码

+   绘图工具栏的工作原理

+   如何使用本章讨论的所有功能构建自定义小部件

# 创建一个简单的类

Dojo 类提供了一种继承和扩展其他模块以使用模板并创建小部件的方法。道场中的类位于一个模块中，并且模块返回类声明。要在模块中声明类，我们需要加载一个名为`dojo/_base/declare`的模块，该模块提供了声明类的支持。

以下屏幕截图显示了一个简单的道场类声明：

![创建一个简单的类](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_01.jpg)

在这个屏幕截图中，`declare`是`dojo/_base/declare`模块的回调函数装饰。类声明接受三个参数：*classname*、*superclass*和*properties*。

classname 参数是可选的。当提供了一个 classname 字符串时，声明被称为**命名类**。当它被省略时，就像我们的情况一样，它被称为**匿名类**。我们将继续使用匿名类，因为命名类必须在特定条件下使用。

超类是我们想要扩展的模块或模块数组。如果超类参数为 null（如我们的片段中），这意味着我们的类声明本身就是一个超类。

类声明中的第三个参数是类属性。我们可以在这里定义类构造函数、其他类属性和类方法。

## 配置道场

Dojo 有一个名为`dojoConfig`的全局对象，其中包含所有的配置参数。我们可以修改`dojoConfig`对象来配置选项和默认行为，以适应道场工具包的各个方面。

`dojoConfig`对象让我们定义在我们的 Web 应用程序中定义的自定义模块的位置，并使用包名标记它。因此，当我们需要加载这些自定义模块时，我们可以使用包名来引用文件夹位置。

### 注意

在引用 Esri JS API 之前，必须声明`dojoConfig`对象。

![配置道场](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_02.jpg)

还有其他配置选项，如`async`、`parseOnLoad`、`waitSeconds`和`cacheBust`。有关`dojoConfig`主题的详细信息，请参阅道场工具包文档[`dojotoolkit.org/documentation/tutorials/1.10/dojo_config/`](https://dojotoolkit.org/documentation/tutorials/1.10/dojo_config/)。

+   `async`选项定义了道场核心是否应异步加载。推荐的值是`true`。

+   `locale`选项允许我们覆盖浏览器提供给道场的默认语言。这将帮助我们为不同的目标语言环境开发应用程序，并使用道场的`i18n`模块测试我们的小部件是否支持国际化。

+   `cacheBust`选项是一个非常有用的选项，当配置为`true`时，将时间字符串附加到模块的每个 URL，从而避免模块缓存。

让我们看看这些选项对我们有什么作用：

```js
<script>
        var dojoConfig = {
            has: {
                "dojo-debug-messages": true
            },
            parseOnLoad: false,
            locale: 'en-us',
            async: true,  
            cacheBust: true,
            packages: [
                {
                    name: "widgets",
                    location: "/js/widgets"
            },
                {
                    name: "utils", 
                    location: "/js/utils"
                }
         ]
        };
    </script>
    <script src="//js.arcgis.com/3.14/"></script>
    <script src="js/app.js"></script>
```

![配置道场](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_03.jpg)

在`dojoConfig`对象中将 cacheBust 配置为 True 的效果

# 开发独立的小部件

在道场中编写类的主要目的是开发独立的小部件。道场专门为我们提供了一个支持小部件开发的模块：`dijit/_WidgetBase`。我们还需要其他辅助模块，如`dijit`模板模块、道场解析和道场国际化模块，以在 Web 应用程序中开发一个完整的小部件。

`WidgetBase`模块关联的关键方面是小部件的生命周期概念。小部件的生命周期为我们提供了在小部件的不同阶段使用的方法，即从小部件的初始化，到其`dom`节点完全加载并可被应用程序利用，直到小部件的销毁。

此模块应作为类声明中的超类数组传递。以下是一个基本小部件的片段：

```js
define([
    //class
    "dojo/_base/declare",

    //widgit class
    "dijit/_WidgetBase",

    "dojo/domReady!"
], function (
    declare,
    _WidgetBase
) {
 **return declare([_WidgetBase], {**
/*Class declaration inherits "dijit/_WidgetBase" module*/

        constructor: function () {}
    });
});
```

## dijit 生命周期

`_WidgetBase`选项提供了程序流将按特定顺序执行的几种方法。按顺序执行的一些最重要的方法如下信息图所示：

![dijit 生命周期](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_04.jpg)

小部件生命周期信息图

上述图表可以描述如下：

+   **constructor**：这是小部件实例化时调用的第一个方法。`constructor`函数可以用作一个名为`domNode`的特殊属性。这可以包含对`domNode`的引用，小部件将放置在其中。`constructor`函数的第一个参数将是一个`options`对象，我们可以向其中发送任何我们想发送给小部件的对象值：

```js
constructor: function (options, srcRefNode) {
            this.domNode = srcRefNode;
        }
```

+   **postCreate**：此方法在小部件的所有属性执行后立即执行。所有小部件的事件处理程序将在此处定义。应在`postCreate()`方法中添加一行特定的代码，以便所有在`WidgetBase`中定义的定义都能正确继承。在下面的代码片段中，已经突出显示了特定的代码行：

```js
postCreate: function(){
            **this.inherited(arguments);**
        }
```

+   **postCreate()**：这个方法也是托管特殊`this.own()`方法的正确位置。在此方法中定义的事件处理程序将在小部件实例被销毁时释放事件处理程序。

+   **Startup**：此方法在构造完 dom 节点后触发。因此，任何对 dom 节点的修改都将在此处完成。这是通过该方法外部调用小部件执行的方法。

## 创建模板化小部件

模板化小部件允许开发人员在运行时将 HTML 文件作为模板字符串加载。所有特定于小部件的 dom 节点都应在此 HTML 模板中定义。Dojo 提供了另外两个模块，以使我们使用模板更轻松、更高效。这些模块名为`dijit/_TemplatedMixin`和`dijit/_WidgetsInTemplateMixin`。除了这两个模块，我们还需要加载一个名为`dojo/text!`的 dojo 插件，它实际上将 HTML 页面加载为模板字符串。插件的工作方式是在`dojo/text!`中的感叹号(`!`)后附加 HTML 文件路径：

```js
    "dojo/text!app_widgets/widgettemplate/template/_widget.html"
```

类属性应包括一个名为`templateString`的特定属性。此属性的值将是用于表示`dojo/text!<filename.html>`插件的回调函数装饰。

让我们看一个基本的代码片段，涵盖了之前讨论的所有主题，并尝试开发一个模板小部件：

![创建模板化小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_05.jpg)

我们的模板文件非常无害，只包含一个简单的`h1`标题标签。正是`templateString`属性保存了这个 HTML 字符串。

`app_widgets/widgettemplate/template/_widget.html`文件的内容如下：

```js
<h1>This is Templated widget</h1>
```

现在，让我们看看如何实例化这个小部件。如前所述，我们需要在小部件中调用`startup`方法来执行此小部件。我们将从另一个 JavaScript 文件中调用这个方法，该文件将传递一个对 dom 节点的引用，其中我们的小部件将被放置：

![创建模板化小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_06.jpg)

/js/widgets/app.js 的内容

这个文件将从`index.html`文件中调用，该文件具有名为`templatedWidgetDiv`的`dom`元素：

```js
<!DOCTYPE html>
<html>

<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge,chrome=1">
    <title></title>
    <meta name="description" content="">
    <meta name="viewport" content="width=device-width">
    <link rel="stylesheet" type="text/css" href="css/style.css">

</head>

<body>
    <h1>Using Dojo Classes</h1>
    <div id="templatedWidgetDiv"/>
    <script>
        /* dojo config */
        var dojoConfig = {
            has: {
                "dojo-debug-messages": true
            },
            parseOnLoad: false,
            locale: 'en-us',
            async: true,  
            cacheBust: true,
            packages: [
                {
                    name: "app_widgets",
                    location: "/js/widgets"
            },
                {
                    name: "utils", 
                    location: "/js/utils"
                }
         ]
        };
    </script>
    <!--Call the esri JS API library-->
    <script src="//js.arcgis.com/3.14/"></script>
    <!--Call the /js/utils/app.js file-->
    <script src="js/app.js"></script> 
</body>

</html>
```

# 小部件文件夹结构

现在是讨论小部件文件夹结构的时候了。在开发大型项目时，文件夹结构是项目构建过程的重要部分，我们需要在项目的初始阶段定义。我们将提供关于如何决定文件夹结构的一般指导方针。这可以根据您的偏好和项目需求进行修改。

## 创建项目文件夹的指南

创建项目文件夹的指南如下图所示：

![创建项目文件夹的指南](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_07.jpg)

让我们详细讨论每一个。

### 创建单一入口点

我们不需要在索引页面上拥挤所有小部件的实例化。最好是我们可以定义一个模块，可以作为实例化我们需要的所有小部件的单一入口点。

我们的 HTML 页面将只包含对 JS API 和这个单一入口 JavaScript 模块的引用：

```js
    <!--Call the esri JS API library-->
    <script src="//js.arcgis.com/3.15/"></script>
    <!--Call the javaScript file which serves as the single point of entry-->
 **<script src="js/app.js"></script>**

```

作为单一入口点的文件的内容如下：

![创建单一入口点](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_08.jpg)

### 定义 dojoConfig

我们之前讨论过这一点。`dojoConfig` 对象将在索引页面中声明。这是一个全局对象，其值可以通过加载名为 `dojo/_base/config` 的模块在程序的任何地方访问。

### 模块化代码

这是 AMD 编码模式的核心原则。模块化的概念意味着我们应该解耦任何功能上不同的代码。正如我们所知，dojo 模块返回一个可公开访问的对象。这个对象可以是一个类声明，就像我们之前看到的那样。模块的另一个用途是可以用作应用程序的配置文件。

已经创建了一个基于 dojo 模块的示例 `config` 文件供您参考：

```js
define(function () {
    /* Private variables*/
    var baseMapUrl = "http://maps.ngdc.noaa.gov/arcgis/rest/services/web_mercator/etopo1_hillshade/MapServer";
    var NOAAMapService = "http://maps.ngdc.noaa.gov/arcgis/rest/services/web_mercator/hazards/MapServer";
    var earthquakeLayerId = 5;
    var volcanoLayerId = 6;
    /*publicly accessible object returned by the COnfig module */
    return {
        app: {
            currentVersion: "1.0.0"
        },

        // valid themes: "claro", "nihilo", "soria", "tundra", "bootstrap", "metro"
        theme: "bootstrap",

        // url to your proxy page, must be on same machine hosting you app. See proxy folder for readme.
        proxy: {
            url: "proxy/proxy.ashx",
            alwaysUseProxy: false,
            proxyRuleUrls: [NOAAMapService]
        },

        map: {

            // basemap: valid options: "streets", "satellite", "hybrid", "topo", "gray", "oceans", "national-geographic", "osm"
            defaultBasemap: "streets",
            visibleLayerId: [this.earthquakeLayerId, this.volcanoLayerId];

            earthQuakeLayerURL: this.NOAAMapService + "/" + this.earthquakeLayerId,
            volcanoLayerURL: this.NOAAMapService + "/" + this.volcanoLayerId
        }
    }
});
```

### 提供国际化支持

根据用户的区域设置自定义应用程序中显示的文本称为**国际化**。Dojo 提供了一个名为 `dojo/i18n!` 的插件来提供这种支持。当我们提到插件时，这意味着它在感叹号 (`!`) 之后期望一个文件路径作为参数。文件路径指的是一个 JavaScript 模块，其中提到了一个名为 `root` 的对象，并列出了所有支持的区域设置。

例如，`dojo/i18n!app_widgets/widget_i18n/nls/strings` 指的是在 `app_widgets/widget_i18n/nls` 文件夹中定义的 `strings` 模块（请记住 `app_widgets` 是指向 `/js/widgets` 位置的包名称）。

当前的区域设置由用户的浏览器确定。在 dojo 中，`locale` 通常是一个五个字母的字符串；前两个字符代表语言，第三个字符是连字符，最后两个字符代表国家。

例如，看一下以下内容：

+   `en-us` 值代表英语作为语言和美国作为国家

+   `ja-jp` 值代表日语作为语言和日本作为国家

+   `zh-cn` 值代表简体中文作为语言和中国作为国家

+   `zh-tw` 值代表简体中文作为语言和台湾作为国家![提供国际化支持](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_09.jpg)

#### 提供国际化支持的步骤

提供国际化支持的步骤如下：

1.  在小部件所在的文件夹中创建一个名为 `nls` 的文件夹。

1.  定义一个具有名为 `root` 的对象并在 `root` 对象下列出所有支持的区域设置的模块。例如，看一下以下内容：

```js
"zh-cn" : true,
"de-at" : true
```

1.  `root` 对象将包含所有支持语言的字符串变量，例如 `widgetTitle` 和 `description`。

1.  为每个定义的区域设置创建一个文件夹，例如 `zh-cn` 和 `de-at`。

1.  在每个 `language` 文件夹中创建与 `root` 模块同名的模块。

1.  新模块将包含`root`对象的所有属性。属性的值将包含相应值的特定语言翻译。

1.  加载名为`dojo/i18n!`的模块，后面跟上根模块的路径。

1.  在`declare`构造函数中，将`i18n`模块的`callback`函数声明分配给名为`this.nls`的属性：

```js
define([
    //class
    "dojo/_base/declare",
    "dojo/_base/lang",

    //widgit class
    "dijit/_WidgetBase",

    //templated widgit
    "dijit/_TemplatedMixin",

    // localization
 **"dojo/i18n!app_widgets/widget_i18n/nls/strings",**

    //loading template file
    "dojo/text!app_widgets/widget_i18n/template/_widget.html",

    "dojo/domReady!"
], function (
    declare, lang,
    _WidgetBase,
    _TemplatedMixin,
    nls,
    dijitTemplate
) {
    return declare([_WidgetBase, _TemplatedMixin], {
        //assigning html template to template string
        templateString: dijitTemplate,
        constructor: function (options, srcRefNode) {
            console.log('constructor called');
            // widget node
            this.domNode = srcRefNode;
 **this.nls = nls;**
        },
        // start widget. called by user
        startup: function () {
            console.log('startup called');
        }
    });
});
```

### 小部件文件夹结构概述

让我们再次审查`widget`文件夹结构，以便在开始任何项目之前将其用作模板：

1.  我们需要一个主文件（比如`index.html`）。主文件应该有`dojoConfig`对象，引用应用程序中使用的所有 CSS，以及 Esri CSS。它还应该有对 API 的引用和对作为入口点的模块的引用（`app.js`）。

1.  所有小部件都放在`js`文件夹中。

1.  所有站点范围的 CSS 和图像分别放入应用程序`root`目录中的`CSS`和`image`文件夹中。

1.  所有小部件将放置在`js`文件夹内的`widgets`文件夹中。每个小部件也可以放置在`widgets`文件夹内的单独文件夹中。

1.  模板将放置在`widget`文件夹内的`template`文件夹中。

1.  将国际化所需的资源放在名为`nls`的文件夹中：![小部件文件夹结构概述](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_10.jpg)

# 构建自定义小部件

我们将扩展上一章中开发的应用程序，添加高级功能和模块化的代码重构。让我们在应用程序中创建一个自定义小部件，该小部件可以执行以下操作：

+   允许用户在地图上绘制多边形。多边形将以半透明红色填充和虚线黄色轮廓进行符号化。

+   多边形应该获取多边形边界内的所有重大森林火灾事件。

+   这将显示为图形，数据应该在网格中。

+   必须提供国际化支持。

## 小部件所需的模块

让我们列出定义类及其相应预期回调函数装饰所需的模块。

### 用于类声明和 OOPS 的模块

| 模块 | 值 |
| --- | --- |
| `dojo/_base/declare` | `declare` |
| `dijit/_WidgetBase` | `_WidgetBase` |
| `dojo/_base/lang` | `lang` |

### 使用 HTML 模板的模块

| 模块 | 值 |
| --- | --- |
| `dijit/_TemplatedMixin` | `_TemplatedMixin` |
| `dojo/text!` | `dijitTemplate` |

### 用于使用事件的模块

| 模块 | 值 |
| --- | --- |
| `dojo/on` | `on` |
| `dijit/a11yclick` | `a11yclick` |

### 用于操作 dom 元素及其样式的模块

| 模块 | 值 |
| --- | --- |
| `dojo/dom-style` | `domStyle` |
| `dojo/dom-class` | `domClass` |
| `dojo/domReady!` |   |

### 用于使用绘制工具栏和显示图形的模块

| 模块 | 值 |
| --- | --- |
| `esri/toolbars/draw` | `Draw` |
| `esri/symbols/SimpleFillSymbol` | `SimpleFillSymbol` |
| `esri/symbols/SimpleLineSymbol` | `SimpleLineSymbol` |
| `esri/graphic` | `Graphic` |
| `dojo/_base/Color` | `Color` |

### 用于查询数据的模块

| 模块 | 值 |
| --- | --- |
| `esri/tasks/query` | `Query` |
| `esri/tasks/QueryTask` | `QueryTask` |

### 国际化支持的模块

| 模块 | 值 |
| --- | --- |
| `dojo/i18n!` | `nls` |

## 使用绘制工具栏

绘制工具栏使我们能够在地图上绘制图形。此工具栏与事件相关联。完成绘制操作后，它将返回在地图上绘制的对象作为几何图形。按照以下步骤使用绘制工具栏创建图形：

![使用绘制工具栏](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_11.jpg)

### 初始化绘制工具栏

绘图工具栏由名为`esri/toolbars/draw`的模块提供。绘图工具栏接受地图对象作为参数。在`postCreate`函数中实例化绘图工具栏。绘图工具栏还接受一个名为`options`的额外可选参数。`options`对象中的一个属性名为`showTooltips`。这可以设置为`true`，以便在绘制时看到相关的工具提示。工具提示中的文本可以自定义。否则，将显示与绘制几何图形相关的默认工具提示：

```js
return declare([_WidgetBase, _TemplatedMixin], {
    //assigning html template to template string
    templateString: dijitTemplate,
    isDrawActive: false,
    map: null,
 **tbDraw: null,**
    constructor: function (options, srcRefNode) {
      this.map = options.map;
    },
    startup: function () {},
    postCreate: function () {
      this.inherited(arguments);
 **this.tbDraw = new Draw(this.map, {showTooltips : true});**
    }
...
```

绘图工具栏可以在按钮的“单击”或“触摸”事件（在智能手机或平板电脑上）上激活，该按钮旨在指示“绘制”事件的开始。Dojo 提供了一个模块，可以处理“触摸”和“单击”事件。该模块名为`dijit/a11yclick`。

要激活绘图工具栏，我们需要提供要绘制的符号类型。绘图工具栏提供了一组常量，对应于绘制符号的类型。这些常量是`POINT`，`POLYGON`，`LINE`，`POLYLINE`，`FREEHAND_POLYGON`，`FREEHAND_POLYLINE`，`MULTI_POINT`，`RECTANGLE`，`TRIANGLE`，`CIRCLE`，`ELLIPSE`，`ARROW`，`UP_ARROW`，`DOWN_ARROW`，`LEFT_ARROW`和`RIGHT_ARROW`。

激活绘图工具栏时，必须使用这些常量来定义所需的绘图操作类型。我们的目标是在单击绘图按钮时绘制多边形。代码如下截图所示：

![初始化绘图工具栏](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_12.jpg)

### 绘图操作

一旦激活绘图工具栏，绘图操作就开始了。对于点几何，绘图操作只需单击一次。对于折线和多边形，单击会向折线添加一个顶点，双击结束草图。对于自由手折线或多边形，“单击”和“拖动”操作绘制几何图形，“松开鼠标”操作结束绘制。

### 绘制结束事件处理程序

绘图操作完成后，我们需要一个事件处理程序来处理绘图工具栏绘制的形状。API 提供了一个`draw-end`事件，该事件在绘图操作完成后触发。必须将此事件处理程序连接到绘图工具栏。此事件处理程序将在小部件的`postCreate()`方法中的`this.own()`函数内定义。事件结果可以传递给命名或匿名函数：

```js
postCreate: function () {
...
 **this.tbDraw.on("draw-end", lang.hitch(this, this.querybyGeometry));**
    },
...
querybyGeometry: function (evt) {
      this.isBusy(true);
      //Get the Drawn geometry
      var geometryInput = evt.geometry;
...
}
```

### 符号化绘制的形状

在`draw-end`事件回调函数中，我们将以结果对象的形式获得绘制形状的几何图形。要将此几何图形添加回地图，我们需要对其进行符号化。符号与其所代表的几何图形相关联。此外，符号的样式由用于填充符号和其大小的颜色或图片定义。仅需对多边形进行符号化，我们需要使用`SimpleFillSymbol`和`SimpleLineSymbol`模块。我们可能还需要`esri/color`模块来定义填充颜色。

让我们回顾一小段代码，以更好地理解这一点。这是一个简单的代码片段，用于构造一个具有半透明实心红色填充和黄色虚线的多边形符号：

![符号化绘制的形状](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_13.jpg)

在前面的截图中，`SimpleFillSymbol.STYLE_SOLID`和`SimpleLineSymbol.STYLE_DASHDOT`是`SimpleFIllSymbol`和`SimpleLineSymbol`模块提供的常量，用于为多边形和线条设置样式。

在符号的构造中定义了两种颜色：一种用于填充多边形，另一种用于着色轮廓。颜色可以由四个组件定义。它们如下：

+   红色

+   绿色

+   蓝色

+   不透明度

红色、绿色和蓝色分量的取值范围为`0`到`255`，不透明度的取值范围为`0`到`1`。根据 RGB 颜色理论，可以使用红色、绿色和蓝色分量的组合来产生任何颜色。因此，要创建黄色，我们使用红色分量的最大值（`255`）和绿色分量的最大值（`255`）；我们不希望蓝色分量对我们的颜色产生影响，所以使用`0`。不透明度值为`0`表示 100%透明，不透明度值为`1`表示 100%不透明。我们使用`0.2`作为填充颜色。这意味着我们的多边形需要 20%的不透明度，或者 80%的透明度。该组件的默认值为`1`。

符号只是一个通用对象。这意味着任何多边形几何体都可以使用该符号来渲染自己。现在，我们需要一个容器对象在地图上显示以前定义的符号绘制的几何体。由`esri/Graphic`模块提供的图形对象充当容器对象，可以接受几何体和符号。图形对象可以添加到地图的图形图层中。

### 注意

地图对象中始终存在一个图形图层，可以通过使用地图的`graphics`属性（`this.map.graphics`）来访问。

![对绘制的形状进行符号化](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_14.jpg)

## 执行查询

小部件的主要功能是根据用户的绘制输入定义和执行查询。以下图像将为我们提供构造`querytask`和处理执行的一般方法：

![执行查询](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_15.jpg)

### 初始化 QueryTask 和 Query 对象

我们将使用在上一章中使用的 Active Wildfire 要素图层。在提供输入几何体时，我们将使用从`draw-end`事件中获取的几何体，而不是使用地图的当前范围几何体，就像我们在上一章中所做的那样。我们将获取绘制几何体内的所有要素，因此我们将使用真值表达式（`1=1`）作为`where`子句。以下代码解释了如何构造`query`对象以及如何执行和存储`queryTask`作为延迟变量：

```js
var queryTask = new QueryTask(this.wildFireActivityURL);
var query = new Query();
query.where = "1=1";
query.geometry = geometryInput;
query.returnGeometry = true;
query.outFields = ["FIRE_NAME", "AREA_", "AREA_MEAS"];
var queryDeferred = queryTask.execute(query);
```

### 查询事件处理程序

`QueryTask`对象上的`execute`方法返回一个延迟变量。这意味着我们应该使用`.then()`操作来引出任务执行结果。成功处理程序返回一个`featureset`。`featureset`是一组要素。要素包含图形以及一些属性。

现在，有两个操作需要执行以显示查询结果：

1.  通过适当地对查询结果进行符号化并将其添加为地图上的适当图形来突出显示查询结果。

1.  在简单的 HTML 表格中显示满足查询条件的 Active Wildfires 的详细信息。HTML 表格应该来自 HTML 模板文件。

#### 定义 HTML 模板

我们需要一个 HTML 模板来渲染小部件。该小部件将具有以下组件：

+   一个按钮的`click`事件将切换绘制事件

+   一个按钮用于清除绘制的图形，以及结果图形和 HTML 表格

+   一个`dom`元素来保存正在构建的 HTML 表格。

以下屏幕截图解释了 HTML 模板的构造方式：

![定义 HTML 模板](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_16.jpg)

应该使用`dojo/text!`插件将此 HTML 文件作为插件加载。完成后，可以使用此符号访问代码中由`dojo-attach-point`引用的所有`dom`元素。还应该实现处理`toggleDraw`按钮和`clear`按钮的点击事件的函数。以下屏幕截图显示了这个的基本实现：

![定义 HTML 模板](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_17.jpg)

#### 对查询结果进行符号化

查询返回的要素是野火位置，所有位置都具有点几何。我们可以使用`SimpleMarkerSymbol`或`PictureMarkerSymbol`来对查询返回的要素进行符号化。`PictureMarker`符号接受以下属性：

+   `angle`

+   `xoffset`

+   `yoffset`

+   `type`

+   `url`

+   `contentType`

+   `width`

+   `height`

我们将使用应用程序的 PNG 资源来定义`PictureMarkerSymbol`：

```js
  var symbolSelected = new PictureMarkerSymbol({
  "angle": 0,
  "xoffset": 0,
  "yoffset": 0,
  "type": "esriPMS",
  "url": "images/fire_sel.png",
  "contentType": "image/png",
  "width": 24,
  "height": 24
});
```

#### 将图形添加到地图

将所有查询结果特征转换为具有我们刚刚定义的`PictureMarkerSymbol`的图形。此外，我们还将为每个图形添加一个`infotemplate`。`infotemplate`的内容将从查询结果属性中获取。可以通过迭代查询结果对象返回的要素来构建 HTML 表。以下屏幕截图清楚地说明了整个过程：

![将图形添加到地图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_04_18.jpg)

完整的代码清单可以在名为`B049549_04_CODE02`的文件夹中找到。

# 摘要

在本章中，您学习了如何在 dojo 中创建类和自定义小部件，还学习了一个 dojo 小部件的生命周期。然后，我们遵循了为任何与 dojo 相关的项目创建文件夹结构的指南。我们还看了如何使用 dojo 模块提供的国际化功能来支持不同的语言。最后，我们创建了一个自定义小部件，该小部件使用绘图工具来接受用户绘制的多边形，并将其用于查询要素图层。我们还在 HTML 表和地图上显示了结果。在接下来的章节中，我们将学习如何更好地直观地对图形进行符号化，使用一种称为渲染的技术。渲染是一种很好的可视化技术，它让我们能够根据要素中特定属性的值以不同方式对要素进行符号化。在后续章节中，我们将扩展可视化技术，以涵盖数据的非空间表示，如图表和图形。
