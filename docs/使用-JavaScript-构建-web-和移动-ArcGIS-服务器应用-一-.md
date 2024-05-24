# 使用 JavaScript 构建 web 和移动 ArcGIS 服务器应用（一）

> 原文：[`zh.annas-archive.org/md5/D4C4E9CDA66F2E731D34B3C600414B4D`](https://zh.annas-archive.org/md5/D4C4E9CDA66F2E731D34B3C600414B4D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

ArcGIS Server 是用于开发 Web 的 GIS 应用程序的主要平台。您可以使用多种编程语言来开发 ArcGIS Server 应用程序，包括 JavaScript，Flex 和 Silverlight。JavaScript 已成为在此平台上开发应用程序的首选语言，因为它既可用于 Web 应用程序，也可用于移动应用程序，并且不需要在浏览器中安装插件。Flex 和 Silverlight 在移动开发方面都表现不佳，并且都需要在浏览器中运行应用程序时使用插件。

本书将教会您如何使用 ArcGIS API for JavaScript 构建基于 Web 的 GIS 应用程序。通过实际的，动手学习方式，您将学习如何使用 ArcGIS Server 开发完全功能的应用程序，并开发一套高需求的技能。

您将学习如何从各种来源创建地图并添加地理图层，包括瓦片和动态地图服务。此外，您还将学习如何向地图添加图形，并使用`FeatureLayer`将地理要素流式传输到浏览器。大多数应用程序还包括由 ArcGIS Server 实现的特定功能。您将学习如何使用 ArcGIS Server 提供的各种任务，包括查询，通过属性查找要素，地理处理任务等。最后，您将了解使用 ArcGIS API for JavaScript 开发移动应用程序有多么容易。

# 本书涵盖内容

第一章，HTML，CSS 和 JavaScript 简介，介绍了在使用 ArcGIS API for JavaScript 开发 GIS 应用程序之前的基本 HTML，CSS 和 JavaScript 概念。

第二章，创建地图和添加图层，教会你如何创建地图并向地图添加图层。您将学习如何创建`Map`类的实例，向地图添加数据图层，并在网页上显示这些信息。`Map`类是 API 中最基本的类，因为它为数据图层提供了画布，以及应用程序中发生的任何后续活动。但是，在添加数据图层之前，您的地图是无用的。可以向地图添加几种类型的数据图层，包括瓦片，动态和要素。读者将在本章中了解更多关于这些图层类型的信息。

第三章，向地图添加图形，教会读者如何在地图上显示临时点，线和多边形，并在`GraphicsLayer`中存储。`GraphicsLayer`是一个单独的图层，始终位于其他图层的顶部，并存储与地图相关的所有图形。

第四章，要素图层，除了继承自`GraphicsLayer`的其他功能，还具有执行查询和选择的能力。要素图层还用于在线编辑要素。要素图层与瓦片和动态地图服务图层不同，因为要素图层将几何信息带到客户端计算机，由 Web 浏览器绘制和存储。要素图层可能减少了对服务器的往返。客户端可以请求所需的要素，并对这些要素执行选择和查询，而无需从服务器请求更多信息。

第五章，*使用小部件和工具栏*，介绍了可以将其放入应用程序以提高生产力的开箱即用小部件。包括 BasemapGallery、Bookmarks、Print、Geocoding、Legend、Measurement、Scalebar、Gauge 和 Overview map 小部件。此外，ArcGIS API for JavaScript 还包括用于向应用程序添加各种工具栏的辅助类，包括导航和绘图工具栏。

第六章，*执行空间和属性查询*，介绍了 ArcGIS Server 查询任务，允许您对已公开的地图服务中的数据图层执行属性和空间查询。您还可以结合这些查询类型执行组合属性和空间查询。

第七章，*识别和查找要素*，介绍了在任何 GIS 应用程序中都可以找到的两个常见操作。这些操作要求用户在识别的情况下在地图上单击要素，或者在查找要素的情况下执行查询。在任何情况下，都会返回有关特定要素的信息。在本章中，读者将学习如何使用`IdentifyTask`和`FindTask`对象获取有关要素的信息。

第八章，*将地址转换为点，将点转换为地址*，介绍了使用 Locator 任务执行地理编码和反向地理编码。地理编码是将坐标分配给地址的过程，而反向地理编码是将地址分配给坐标的过程。

第九章，*网络分析任务*，允许您对街道网络执行分析，例如从一个地址到另一个地址找到最佳路线，找到最近的学校，识别位置周围的服务区域，或者用一组服务车辆响应一组订单。

第十章，*地理处理任务*，允许您执行在 ArcGIS Desktop 中使用 ModelBuilder 构建的自定义模型。模型可以在桌面环境或通过通过 Web 应用程序访问的集中服务器中以自动方式运行。ArcToolbox 中的任何工具，无论是您的 ArcGIS 许可级别的工具还是您构建的自定义工具，都可以在模型中使用，并与其他工具链接在一起。构建完成后，这些模型可以在集中服务器上运行，并通过 Web 应用程序访问。在本章中，我们将探讨如何通过 ArcGIS API for JavaScript 访问这些地理处理任务。

第十一章，*与 ArcGIS Online 集成*，详细介绍了如何使用 ArcGIS API for JavaScript 访问使用[ArcGIS.com](http://ArcGIS.com)创建的数据和地图。网站[ArcGIS.com](http://ArcGIS.com)用于处理地图和其他类型的地理信息。在这个网站上，您将找到用于构建和共享地图的应用程序。您还将找到有用的底图、数据、应用程序和工具，可以查看和使用，以及可以加入的社区。对于应用程序开发人员来说，真正令人兴奋的消息是您可以使用 ArcGIS API for JavaScript 将[ArcGIS.com](http://ArcGIS.com)内容集成到您的自定义开发的应用程序中。在本章中，您将探索如何将[ArcGIS.com](http://ArcGIS.com)地图添加到您的应用程序中。

第十二章，*创建移动应用程序*，详细介绍了如何使用 ArcGIS API for JavaScript 构建移动 GIS 应用程序。ArcGIS Server 目前支持 iOS、Android 和 BlackBerry 操作系统。该 API 与 dojox/mobile 集成。在本章中，您将了解到 API 的紧凑构建，使得通过 web-kit 浏览器以及内置手势支持成为可能。

附录，*使用 ArcGIS 模板和 Dojo 设计应用程序*，涵盖了许多 Web 开发人员最困难的任务之一，即设计和创建用户界面。ArcGIS API for JavaScript 和 Dojo 极大地简化了这项任务。Dojo 的布局 dijits 提供了一种简单、高效的方式来创建应用程序布局，Esri 提供了许多示例应用程序布局和模板，您可以使用它们快速启动。在本附录中，读者将学习快速设计应用程序的技巧。

# 您需要为这本书做好准备

要完成本书中的练习，您需要访问一个 Web 浏览器，最好是 Google Chrome 或 Firefox。每一章都包含了旨在补充所呈现材料的练习。练习将使用 ArcGIS API for JavaScript Sandbox 来编写和测试您的代码。Sandbox 可以在[`developers.arcgis.com/en/javascript/sandbox/sandbox.html`](http://developers.arcgis.com/en/javascript/sandbox/sandbox.html)找到。练习将访问 ArcGIS Server 的公开实例，因此您不需要安装 ArcGIS Server。

# 这本书是为谁准备的

如果您是一名应用程序开发人员，希望使用 ArcGIS Server 和 JavaScript API 开发 Web 和移动 GIS 应用程序，那么这本书非常适合您。它主要面向初学者和中级 GIS 开发人员或应用程序开发人员，他们可能更传统，以前可能没有开发过 GIS 应用程序，但现在被要求在这个平台上实施解决方案。不需要具有 ArcGIS Server、JavaScript、HTML 或 CSS 的先前经验，但这当然是有帮助的。

# 约定

在本书中，您将找到一些区分不同信息类型的文本样式。以下是这些样式的一些示例，以及它们的含义解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下："将`onorientationchange()`事件添加到`<body>`标签。"

代码块设置如下：

```js
routeParams = new RouteParameters();
routeParams.stops = new FeatureSet();
routeParams.outSpatialReference = {wkid:4326};
routeParams.stops.features.push(stop1);
routeParams.stops.features.push(stop2);
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```js
**function computeServiceArea(evt) {**
 **map.graphics.clear();**
 **var pointSymbol = new SimpleMarkerSymbol();**
 **pointSymbol.setOutline = new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([255, 0, 0]), 1);**
 **pointSymbol.setSize(14);**
 **pointSymbol.setColor(new Color([0, 255, 0, 0.25]));** 
}
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，比如菜单或对话框中的单词，会以这样的形式出现在文本中："单击**运行**按钮"。

### 注意

警告或重要说明会出现在这样的框中。

### 提示

提示和技巧会以这样的形式出现。


# 第一章：HTML、CSS 和 JavaScript 简介

在开始使用 ArcGIS API for JavaScript 开发 GIS 应用程序之前，您需要了解某些基本概念。对于那些已经熟悉 HTML、JavaScript 和 CSS 的人，您可能希望跳到下一章。但是，如果您对这些概念中的任何一个都不熟悉，请继续阅读。我们将以非常基本的水平来介绍这些主题，仅仅足够让您开始。关于这些主题的更高级的教程资源有很多，包括书籍和在线教程。您可以参考附录，*使用 ArcGIS 模板和 Dojo 设计应用程序*，获取更全面的资源列表。

在本章中，我们将涵盖以下主题：

+   基本 HTML 页面概念

+   JavaScript 基础知识

+   基本 CSS 原则

# 基本 HTML 页面概念

在我们深入讨论创建地图和添加信息层的细节之前，您需要了解在使用 ArcGIS API for JavaScript 开发应用程序时代码将放置的上下文。您编写的代码将放置在 HTML 页面或 JavaScript 文件中。HTML 文件通常具有`.html`或`.htm`文件扩展名，JavaScript 文件具有`.js`扩展名。创建基本 HTML 页面后，您可以按照使用 ArcGIS API for JavaScript 创建基本地图所需的步骤进行操作。

网页的核心是一个 HTML 文件。编写这个基本文件非常重要，因为它构成了您的应用程序的基础。在基本 HTML 编码中犯的错误可能会导致问题，当您的 JavaScript 代码尝试访问这些 HTML 标签时会出现问题。

以下是一个非常简单的 HTML 页面的代码示例。这个示例是一个 HTML 页面可以变得多么简单。它只包含了主要的 HTML 标签`<DOCTYPE>`，`<html>`，`<head>`，`<title>`和`<body>`。使用您喜欢的文本或网络编辑器输入以下代码。我使用 Notepad++，但还有许多其他好的编辑器可用。将此示例保存为`helloworld.html`：

```js
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">

<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <title>Topographic Map</title>

  </head>
  <body>
      Hello World
  </body>
</html>
```

目前有不同类型的 HTML 正在使用。新的 HTML5 受到了很多关注，您可能会看到几乎专门用于开发新应用程序的这种实现；因此，我们将在整本书中专注于 HTML5。但是，我想让您知道还有其他正在使用的 HTML 版本，最常见的是 HTML 4.01（在上面的代码示例中看到）和 XHTML 1.0。

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载您购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册以直接通过电子邮件接收文件。

## HTML DOCTYPE 声明

您的 HTML 页面的第一行将包含`DOCTYPE`声明。这用于告诉浏览器应如何解释 HTML 页面。在本书中，我们将专注于 HTML5，因此您将看到的以下示例使用 HTML5 的`DOCTYPE`声明。另外两个常见的`DOCTYPE`声明是 HTML 4.01 Strict 和 XHTML 1.0 Strict：

+   HTML 5 使用以下代码：

```js
<!DOCTYPE html>
```

+   HTML 4.01 Strict 使用以下代码：

```js
<!DOCTYPE html PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
```

+   XHTML 1.0 Strict 使用以下代码：

```js
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Strict//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd">
```

## 主要标签

至少，您的所有网页都需要包含`<html>`，`<head>`和`<body>`标签。`<html>`标签定义整个 HTML 文档。所有其他标签必须放在此标签内。定义网页在浏览器中显示方式的标签放在`<body>`标签内。例如，您的地图应用程序将包含一个`<div>`标签，该标签位于`<body>`标签内，用作显示地图的容器。

在浏览器中加载`helloworld.html`页面将产生您在下面截图中看到的内容。您编写的大部分 ArcGIS API for JavaScript 代码将放置在`<head></head>`标签之间，并在`<script>`标签内或单独的 JavaScript 文件中。随着经验的积累，您可能会开始将 JavaScript 代码放在一个或多个 JavaScript 文件中，然后从 JavaScript 部分引用它们。我们将在后面探讨这个话题。现在，只需专注于将您的代码放在`<head>`标签内。

![主要标签](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_01_01.jpg)

## 验证 HTML 代码

正如前面提到的，非常重要的是您的 HTML 标签被正确编码。你可能会说，这都很好，但我怎么知道我的 HTML 已经被正确编码了呢？嗯，有许多 HTML 代码验证器可以用来检查您的 HTML。W3C HTML 验证器（[`validator.w3.org/`](http://validator.w3.org/)）如下面的截图所示，可以通过 URI、文件上传或直接输入来验证 HTML 代码：

![验证 HTML 代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_01_02.jpg)

假设您的 HTML 代码成功验证自身，您将会看到一个屏幕上显示成功验证的消息，如下面的截图所示：

![验证 HTML 代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_01_03.jpg)

另一方面，它将用红色显示的错误消息来识别任何问题。错误会被详细描述，这样更容易纠正问题。通常一个错误会导致许多其他错误，所以看到一个长长的错误列表并不罕见。如果是这种情况，不要惊慌。修复一个错误通常会解决许多其他错误。

![验证 HTML 代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_01_04.jpg)

要纠正前面文档中的错误，您需要将文本`Hello World`用类似`<p>Hello World</p>`的段落标签括起来。

# JavaScript 基础知识

正如其名称所暗示的，ArcGIS API for JavaScript 要求您在开发应用程序时使用 JavaScript 语言。在开始构建应用程序之前，您需要了解一些基本的 JavaScript 编程概念。

JavaScript 是一种轻量级的脚本语言，嵌入在所有现代的 Web 浏览器中。尽管 JavaScript 当然可以存在于 Web 浏览器环境之外的其他应用程序中，但它最常用于与 Web 应用程序的集成。

所有现代的 Web 浏览器，包括 Internet Explorer，Firefox 和 Chrome，都内置了 JavaScript。在 Web 应用程序中使用 JavaScript 使我们能够创建动态应用程序，而无需往返服务器获取数据，因此应用程序更具响应性和用户友好性。然而，JavaScript 确实有能力向服务器提交请求，并且是**异步 JavaScript 和 XML**（**AJAX**）堆栈中的核心技术。

### 注意

关于 JavaScript 的一个常见误解是它是 Java 的简化版本。这两种语言实际上是无关的，除了名字以外。

## 代码中的注释

始终通过注释来记录您的 JavaScript 代码是最佳实践。至少，这些注释应包括代码的作者、最后修订日期和代码的一般目的。此外，在代码的各个部分，您应该包括注释部分，定义应用程序特定部分的目的。这些文档的目的是使您或任何其他程序员在需要以某种方式更新代码时更容易快速上手。

您在代码中包含的任何注释都不会被执行。JavaScript 解释器只是简单地忽略它们。在 JavaScript 中，可以通过几种方式进行注释，包括单行和多行注释。单行注释以`//`开头，以及您添加到该行的任何其他字符。以下代码示例显示了如何创建单行注释：

```js
//this is a single line comment.  This line will not be executed
```

JavaScript 中的多行注释以`/*`开头，以`*/`结尾。之间的任何行都被视为注释，不会被执行。以下代码示例显示了多行注释的示例：

```js
**/***
 Copyright 2012 Google Inc.

 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

 http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.
***/**

```

## 变量

变量的概念是您在使用任何编程语言时需要了解的基本概念。变量只是我们用来与某种数据值关联的名称。在较低级别上，这些变量是计算机内存中划出的存储数据的空间。

您可以将变量视为具有名称并包含某种数据的盒子。当我们最初创建变量时，它是空的，直到分配数据。基本上，变量使我们能够存储和操作数据。在下图中，我们创建了一个名为`ssn`的变量。最初，此变量为空，但然后被赋予值`450-63-3567`。分配给变量的数据值可以是各种类型，包括数字、字符串、布尔值、对象和数组。

![变量](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_01_05.jpg)

在 JavaScript 中，变量使用`var`关键字声明。一般来说，您分配给变量的名称完全取决于您。但是，在创建变量时，有一些规则需要遵循。变量可以包含文本和数字，但不应以数字开头。始终使用字母或下划线开头变量名。此外，变量名中不允许包含空格，也不允许包含特殊字符，如百分号和和号。除此之外，您可以自由创建变量名，但应尽量分配描述变量将被分配的数据的变量名。使用相同的`var`关键字声明多个变量也是完全合法的，如下面的代码示例所示：

```js
var i, j, k;
```

您还可以将变量声明与数据分配结合在一起，如以下示例所示：

```js
var i = 10;
var j = 20;
var k = 30;
```

您可能还注意到每个 JavaScript 语句都以分号结束。分号表示 JavaScript 语句的结束，并且应始终包含在 JavaScript 中。

## JavaScript 和大小写敏感性

我需要强调的一个非常重要的观点是，JavaScript 是一种大小写敏感的语言，您需要非常小心，因为这可能会在您的代码中引入一些难以跟踪的错误。所有变量、关键字、函数和标识符都必须以一致的大写字母拼写。当您考虑到 HTML 不区分大小写时，这会变得更加令人困惑。这往往是新 JavaScript 开发人员的绊脚石。在下面的代码片段中，我创建了三个变量，拼写相同。但是，由于它们没有遵循相同的大写规则，您最终会得到三个不同的变量：

```js
Var myName = 'Eric';
var myname = 'John';
var MyName = 'Joe';
```

## 变量数据类型

JavaScript 支持各种类型的数据，可以分配给您的变量。与.NET 或 C++等强类型语言不同，JavaScript 是一种弱类型语言。这意味着您不必指定将占用变量的数据类型。JavaScript 解释器会在运行时为您执行此操作。您可以将文本字符串、数字、布尔值、数组或对象分配给您的变量。

数字和字符串在大多数情况下都很简单。字符串只是由单引号或双引号括起来的文本。例如：

```js
varbaseMapLayer = "Terrain";
varoperationalLayer = 'Parcels';
```

数字不包含在引号内，可以是整数或浮点数：

```js
var currentMonth = 12;
var layered = 3;
var speed = 34.35;
```

我要指出的一件事是，新程序员可能会感到困惑的一点是，可以通过用单引号或双引号括起来的值将数值赋给字符串变量。例如，没有单引号或双引号的值 3.14 是一个数值数据类型，而带有单引号或双引号的值 3.14 被分配了一个字符串数据类型。

其他数据类型包括布尔值，它们只是真或假的值，以及数组，它们是数据值的集合。数组基本上用作多个值的容器。例如，您可以在数组中存储地理数据图层名称的列表，并根据需要单独访问它们。

数组允许您在单个变量中存储多个值。例如，您可能希望存储要添加到地图中的所有图层的名称。您可以使用数组将它们全部存储在一个变量中，而不是为每个图层创建单独的变量。然后，您可以使用*for*循环通过索引号循环访问数组中的单个值。下面的代码示例展示了在 JavaScript 中创建数组的一种方法：

```js
var myLayers=new Array(); 
myLayers[0]="Parcels";       
myLayers[1]="Streets";
myLayers[2]="Streams";
```

您还可以简化创建数组变量的过程，就像下面的代码示例中所示，数组已经创建为括号括起来的逗号分隔列表：

```js
var myLayers = ["Parcels", "Streets", "Streams"];
```

您可以通过使用索引来访问数组中的元素，就像下面的代码示例中所示。数组访问是从零开始的，这意味着数组中的第一个项目占据`0`位置，数组中的每个后续项目都增加了一个：

```js
var layerName = myLayers[0];  //returns Parcels
```

## 决策支持语句

JavaScript 和其他编程语言中的`if/else`语句是一种控制语句，允许在代码中进行决策。这种类型的语句在语句的顶部执行测试。如果测试返回`true`，则与`if`块关联的语句将运行。如果测试返回`false`，则执行跳转到第一个`else if`块。这种模式将继续，直到测试返回`true`或执行到达`else`语句。下面的代码示例显示了这种语句的工作原理：

```js
var layerName = 'streets';
if (layerName == 'aerial') {
    alert("An aerial map");
}
else if (layerName == "hybrid") {
    alert("A hybrid map");
}
else {
    alert("A street map");
}
```

## 循环语句

循环语句使您能够一遍又一遍地运行相同的代码块。JavaScript 中有两种基本的循环机制。*for*循环执行指定次数的代码块，而*while*循环在条件为真时执行代码块。一旦条件变为假，循环机制就会停止。

下面的代码示例显示了`for`循环的语法。您会注意到它需要一个起始值，这将是一个整数和一个条件语句。您还可以提供一个增量。*for*循环内的代码块将在给定条件下执行，而该值小于结束值时：

```js
for (start value; condition statement; increment)
{
  the code block to be executed
 }
```

在下面的例子中，起始值设置为`0`并分配给一个名为`i`的变量。条件语句是当`i`小于或等于`10`时，`i`的值每次循环都会增加`1`，使用`++`运算符。每次通过循环时，都会打印`i`的值：

```js
var i = 0;
for (i = 0; i <= 10; i++) {
    document.write("The number is " + i);
    document.write("<br/>");
}
```

JavaScript 中的另一种基本循环机制是*while*循环。当您想要在条件为真时执行代码块时，可以使用此循环。一旦条件设置为假，执行就会停止。*while*循环接受一个参数，即将被测试的条件。在下面的例子中，当`i`小于或等于`10`时，代码块将被执行。最初，`i`被设置为`0`的值。在代码块的末尾，您会注意到`i`增加了一个（`i = i + 1`）：

```js
var i = 0;
while (i <= 10)
{
    document.write("The number is " + i);
    document.write("<br/>");
    i = i + 1;
}
```

## 函数

现在让我们来讨论非常重要的函数主题。函数只是在调用时执行的命名代码块。您在本书和开发工作中编写的绝大部分代码都将出现在函数中。

最佳实践要求您将代码分成执行小的、离散的操作单元的函数。这些代码块通常在网页的`<head>`部分内部的`<script>`标记中定义，但也可以在`<body>`部分中定义。然而，在大多数情况下，您会希望将函数定义在`<head>`部分，以便在页面加载后确保它们可用。

要创建一个函数，您需要使用`function`关键字，后面跟着您定义的函数名称，以及作为参数变量传递的执行函数所需的任何变量。如果您的函数需要将一个值返回给调用代码，您将需要使用`return`关键字，与您想要传回的数据一起使用。

函数还可以接受参数，这些参数只是用于将信息传递到函数中的变量。在下面的代码示例中，`prod()`函数传递了两个变量：`a`和`b`。这些信息以变量的形式可以在函数内部使用：

```js
var x;
function multiplyValues(a,b){
    x = a * b;return x;
}
```

## 对象

现在我们已经了解了一些基本的 JavaScript 概念，我们将解决本节中最重要的概念。为了有效地使用 ArcGIS API for JavaScript 编程地图应用程序，您需要对对象有一个良好的基本理解。因此，这是一个您需要掌握的关键概念，以了解如何开发 Web 地图应用程序。

ArcGIS API for JavaScript 广泛使用对象。我们将详细介绍这个编程库的细节，但现在我们将介绍高级概念。对象是复杂的结构，能够将多个数据值和动作聚合到一个结构中。这与我们的原始数据类型（如数字、字符串和布尔值）有很大的不同，后者只能保存一个值。对象是更复杂的结构。

对象由数据和动作组成。数据以属性的形式包含有关对象的信息。例如，在 ArcGIS API for JavaScript 中找到的`Map`对象中有许多属性，包括地图范围、与地图相关的图形、地图的高度和宽度、与地图相关的图层 ID 等。这些属性包含有关对象的信息。

对象还有我们通常称为方法的动作，但我们也可以将构造函数和事件分为这个类别。方法是地图可以执行的操作，比如添加图层、设置地图范围或获取地图比例。

构造函数是用于创建对象的新实例的特殊用途函数。对于某些对象，还可以将参数传递到构造函数中，以便更好地控制所创建的对象。以下代码示例显示了如何使用构造函数创建`Map`对象的新实例。您可以通过我突出显示的`new`关键字来判断这个方法是一个构造函数。`new`关键字后面跟着对象的名称和用于控制`new`对象的任何参数，定义了对象的构造函数。在这种情况下，我们创建了一个新的`Map`对象，并将其存储在一个名为`map`的变量中。传递了三个参数到构造函数中，以控制`Map`对象的各个方面，包括`basemap`、地图的`center`和`zoom`比例级别：

```js
var map = **new** Map("mapDiv", { 
  basemap: "streets",
  center:[-117.148, 32.706], //long, lat
  zoom: 12
});
```

事件是在对象上发生的动作，由最终用户或应用程序触发。这包括诸如地图点击、鼠标移动或图层添加到地图等事件。

属性和方法通过点表示法访问，其中对象实例名称与属性或方法之间用点分隔。例如，要访问当前地图范围，您可以在代码中输入`map.extent`。以下是显示如何访问对象属性的一些代码示例：

```js
var theExtent = map.extent;
var graphics = map.graphics;
```

方法也是如此，只是方法名称的末尾有括号。数据可以通过参数传递到方法中。在以下代码的第一行中，我们将一个名为`pt`的变量传递给`map.centerAt(pt)`方法：

```js
map.centerAt(pt);
map.panRight();
```

# 基本 CSS 原则

**层叠样式表**（**CSS**）是一种用于描述 HTML 元素在网页上应如何显示的语言。例如，CSS 通常用于定义页面或一组页面的常见样式元素，如字体、背景颜色、字体大小、链接颜色以及与网页视觉设计相关的许多其他内容。看一下以下代码片段：

```js
<style>
  html, body {
    height: 100%;
    width: 100%;
    margin: 0;
    padding: 0;
  }

  #map{

    padding:0;
    border:solid 2px #94C7BA;
    margin:5px;
  }
  #header {
    border: solid 2px #94C7BA;
    padding-top:5px;
    padding-left:10px;
    background-color:white;

    color:#594735;

    font-size:14pt;
    text-align:left;
    font-weight:bold;
    height:35px;
    margin:5px;
    overflow:hidden;
  }
  .roundedCorners{
    -webkit-border-radius: 4px;
    -moz-border-radius: 4px;
    border-radius: 4px;
  }
  .shadow{

    -webkit-box-shadow: 0px 4px 8px #adadad;
    -moz-box-shadow: 0px 4px 8px #adadad;
    -o-box-shadow: 0px 4px 8px #adadad;
    box-shadow: 0px 4px 8px #adadad;
  }
</style>
```

## CSS 语法

CSS 遵循一定的规则，定义了要选择哪个 HTML 元素以及如何对该元素进行样式设置。CSS 规则有两个主要部分：选择器和一个或多个声明。选择器通常是您要设置样式的 HTML 元素。在下图中，选择器是`p`。HTML 中的`<p>`元素表示段落。CSS 规则的第二部分由一个或多个声明组成，每个声明都包括属性和值。属性表示要更改的样式属性。在我们的示例中，我们将`color`属性设置为`red`。实际上，我们通过这个 CSS 规则定义了段落中的所有文本应该是红色的。

我们使用了`p {color:red}`，如下图所示：

![CSS 语法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_01_06.jpg)

您可以在 CSS 规则中包含多个声明，就像在以下示例中所示的那样。声明始终用大括号括起来，每个声明以分号结束。此外，属性和值之间应该放置一个冒号。在这个特定的例子中，已经做出了两个声明：一个是段落的颜色，另一个是段落的文本对齐。请注意，声明之间用分号分隔：

```js
p {color:red;text-align:center}
```

CSS 注释用于解释您的代码。您应该养成像在任何其他编程语言中一样总是对 CSS 代码进行注释的习惯。注释始终被浏览器忽略。注释以斜杠后跟一个星号开始，并以一个星号后跟一个斜杠结束。之间的所有内容都被视为注释并被忽略。

```js
/*
h1 {font-size:200%;}
h2 {font-size:140%;}
h3 {font-size:110%;}
*/
```

除了为特定 HTML 元素指定选择器之外，您还可以使用`id`选择器为任何具有与`id`选择器匹配的`id`值的 HTML 元素定义样式。通过井号(`#`)定义 CSS 中的`id`选择器，后跟`id`值。

例如，在以下代码示例中，您会看到三个`id`选择器：`rightPane`，`leftPane`和`map`。在 ArcGIS API for JavaScript 应用程序中，您几乎总是有一个地图。当您定义一个将用作地图容器的`<div>`标记时，您定义一个`id`选择器并为其分配一个值，通常是单词`map`。在这种情况下，我们使用 CSS 来定义地图的几种样式，包括 5 像素的边距以及特定颜色的实心样式边框和边框半径：

```js
#rightPane {
    background-color:white;
    color:#3f3f3f;
    border: solid 2px #224a54;
    width: 20%;
}
#leftPane {
    margin: 5px;
    padding: 2px;
    background-color:white;
    color:#3f3f3f;
    border: solid 2px #224a54;
    width: 20%;
}
#map {
    margin: 5px;
    border: solid 4px #224a54;
    -mox-border-radius: 4px;
}
```

![CSS 语法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_01_07.jpg)

与用于为单个元素分配样式的`id`选择器不同，`class`选择器用于指定一组具有相同 HTML 类属性的元素的样式。类选择器用句点定义，后跟类名。您还可以指定只有具有特定类的特定 HTML 元素应受样式影响。以下是示例：

```js
.center {text-align:center;}
p.center {text-align:center;}
```

你的 HTML 代码将引用类选择器如下：

```js
<p class="center">This is a paragraph</p>
```

有三种方法可以将 CSS 插入到应用程序中：内联、内部样式表和外部样式表。

## 内联样式

为 HTML 元素定义 CSS 规则的第一种方法是通过使用内联样式。这种方法并不推荐，因为它混合了样式和表示，并且难以维护。在某些情况下，需要定义一组非常有限的 CSS 规则时，这是一个选项。要使用内联样式，只需在相关的 HTML 标记内放置`style`属性：

```js
<p style="color:sienna;margin-left:20px">This is a paragraph.</p>
```

## 内部样式表

内部样式表将所有的 CSS 规则移动到特定的网页中。只有该特定页面内的 HTML 元素才能访问这些规则。所有的 CSS 规则都在`<head>`标记内定义，并且被包含在`<style>`标记内，如下面的代码示例所示：

```js
<head>
    <style type="text/css">
        hr {color:sienna;}
        p {margin-left:20px;}
        body {background-image:url("images/back40.gif");}
    </style>
</head>
```

## 外部样式表

外部样式表只是一个包含 CSS 规则的文本文件，并且保存为`.css`文件扩展名。然后通过 HTML 的`<link>`标记将该文件链接到想要实现外部样式表中定义的样式的所有网页。这是一种常用的方法，用于将样式与主网页分禅，并且使你能够通过使用单个外部样式表来改变整个网站的外观。

现在让我们着重讨论层叠样式表中的“层叠”部分。正如你现在所知道的，样式可以在外部样式表、内部样式表或内联中定义。还有一个我们没有讨论的第四个级别，那就是浏览器默认样式。不过你对此没有任何控制。在 CSS 中，内联样式具有最高优先级，这意味着它将覆盖在内部样式表、外部样式表或浏览器默认样式中定义的样式。如果没有定义内联样式，那么在内部样式表中定义的任何样式规则将优先于外部样式表中定义的样式。这里的一个警告是，如果在 HTML 的`<head>`中将外部样式表的链接放在内部样式表之后，外部样式表将覆盖内部样式表！

这些都是需要记住的很多内容！只需记住，层叠样式表中定义的样式规则会覆盖层次结构中较高位置定义的样式规则，如下图所示：

![外部样式表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_01_08.jpg)

这些是你需要了解的关于 CSS 的基本概念。你可以使用 CSS 来定义网页上几乎任何东西的样式，包括背景、文本、字体、链接、列表、图像、表格、地图和任何其他可见对象。

# 分离 HTML、CSS 和 JavaScript

你可能想知道所有这些代码放在哪里。你应该把所有的 HTML、CSS 和 JavaScript 代码放在同一个文件中，还是分成不同的文件？对于非常简单的应用程序和示例，将所有代码放在一个扩展名为`.html`或`.htm`的单个文件中并不罕见。在这种情况下，CSS 和 JavaScript 代码将驻留在 HTML 页面的`<head>`部分。然而，使用这些代码堆栈创建应用程序的首选方法是将表示与内容和行为分开。应用程序的用户界面项目应该驻留在一个 HTML 页面中，该页面只包含用于定义应用程序内容的标签，以及应用程序的任何 CSS（表示）或 JavaScript（行为）文件的引用。最终结果是一个单独的 HTML 页面和一个或多个 CSS 和 JavaScript 文件。这将导致类似于以下截图所示的文件夹结构，其中我们有一个名为`index.html`的单个文件和几个包含 CSS、JavaScript 和其他资源（如图像）的文件夹。`css`和`js`文件夹将包含一个或多个文件。

![分离 HTML、CSS 和 JavaScript](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_01_0.jpg)

CSS 文件可以通过`<link>`标签链接到 HTML 页面中。在下面的代码示例中，您将看到一个代码示例，展示了如何使用`<link>`标签导入 CSS 文件。CSS 文件的链接应该在 HTML 页面的`<head>`标签中定义：

```js
<!DOCTYPE html>

<html>
  <head>
    <title>GeoRanch Client Portal</title>
    <meta name="viewport" content="initial-scale=1.0, user-scalable=no">
    <link rel="stylesheet" href="bootstrap/css/bootstrap.css">
  </head>
  <body>
  </body>
</html>
```

JavaScript 文件可以通过`<script>`标签导入到您的 HTML 页面中，就像下面的代码示例中所示。这些`<script>`标签可以放在您网页的`<head>`标签中，就像下面的 JavaScript 代码中引用 ArcGIS API 一样，或者可以放在页面末尾的`</body>`标签之前，就像`creategeometries.js`文件中所做的那样。通常建议将 JavaScript 文件导入到接近`</body>`标签的位置，因为当浏览器下载 JavaScript 文件时，在下载完成之前不会下载其他任何内容。这可能会导致应用程序加载缓慢的情况。

在头部添加`<script>`标签是推荐的做法，用于 JavaScript 库，比如需要在与 body 中的 HTML 元素交互之前解析的 Dojo。这就是为什么 ArcGIS API for JavaScript 在头部加载的原因：

```js
<!DOCTYPE html>
<html>
  <head>
    <title>GeoRanch Client Portal</title>
    <meta name="viewport" content="initial-scale=1.0, user-scalable=no">

    **<script src="http://js.arcgis.com/3.7/"></script>**
  </head>
  <body>
    **<script src="js/creategeometries.js"></script>**
  </body>
</html>
```

将您的代码拆分成多个文件可以清晰地分离您的代码，而且维护起来应该更容易。

# 摘要

在开始详细讨论 ArcGIS API for JavaScript 之前，您需要了解一些基本的 HTML、CSS 和 JavaScript 概念。本章已经提供了这些内容，但您需要继续学习与这些主题相关的许多其他概念。现在，您已经知道足够多，可以开始尝试了。

您开发的 HTML 和 CSS 代码定义了应用程序的外观，而应用程序提供的功能是通过 JavaScript 控制的。这些是非常不同的技能集，许多人擅长其中一种，但不一定擅长另一种。大多数应用程序开发人员将专注于通过 JavaScript 开发应用程序的功能，并将 HTML 和 CSS 留给设计师！然而，重要的是您至少对所有这些主题的基本概念有很好的理解。在下一章中，我们将深入学习 ArcGIS API for JavaScript，并开始学习如何创建`Map`对象以及如何向地图添加动态和瓦片地图服务图层。


# 第二章：创建地图和添加图层

既然我们已经了解了 HTML、CSS 和 JavaScript 的一些基础知识，现在是时候真正开始工作，学习如何构建一些出色的 GIS Web 应用程序了！本章的内容将向您介绍一些基本概念，这些概念定义了您如何创建地图并以图层的形式添加信息。

在本章中，我们将涵盖以下主题：

+   JavaScript API for ArcGIS 沙盒

+   使用 ArcGIS JavaScript API 创建应用程序的基本步骤

+   关于地图的更多信息

+   使用地图服务图层

+   切片地图服务图层

+   动态地图服务图层

+   地图导航

+   使用地图范围

# 介绍

在学习新的编程语言或应用程序编程接口（API）时，我们都必须从某个地方开始。在使用 ArcGIS JavaScript API 创建 Web 地图应用程序时也是如此。您不仅需要了解一些基本的 JavaScript 概念，还需要掌握 HTML、CSS，当然还有 ArcGIS JavaScript API，它实际上是建立在 Dojo JavaScript 框架之上的。一下子就要掌握这么多知识，所以在本章中，我将让您创建一个非常基本的应用程序，这将成为您在接下来的章节中可以构建的基础。模仿是学习编程技能的一种绝佳方式，因此在本章中，我只会让您输入您看到的代码，并且我会在途中提供一些解释。我将把对代码的详细描述留到以后的章节中。

为了让您对 ArcGIS JavaScript API 有所了解，您将在本章中创建一个简单的地图应用程序，该应用程序创建地图，添加了一些数据图层，并提供了一些基本的地图导航功能。

使用 ArcGIS JavaScript API 创建任何 Web 地图应用程序都必须遵循一些基本步骤。您将在本章中首次看到这些步骤的每一个，并且我们将在本书的后面更详细地描述它们。每次使用 JavaScript API 创建新应用程序时，都将遵循这些基本步骤。在创建应用程序的最初几次，这些步骤可能会显得有些奇怪，但您很快就会理解它们的作用和必要性。很快，您就可以将这些步骤视为您在每个应用程序中使用的模板。

让我们开始吧！

# ArcGIS JavaScript API 沙盒

在本书中，您将使用 ArcGIS JavaScript API 沙盒来编写和测试您的代码。沙盒可以在[`developers.arcgis.com/en/javascript/sandbox/sandbox.html`](http://developers.arcgis.com/en/javascript/sandbox/sandbox.html)找到，并且加载后将显示如下屏幕截图所示。您将在左窗格中编写代码，并单击“运行”按钮以在右窗格中查看结果，如下屏幕截图所示：

![ArcGIS JavaScript API 沙盒](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_01.jpg)

# 使用 ArcGIS JavaScript API 创建应用程序的基本步骤

创建任何 GIS Web 应用程序都需要遵循几个步骤，这些步骤将始终需要执行，如果您打算将地图作为应用程序的一部分。考虑到您正在阅读本书，我无法想象您不想这样做！简而言之，您需要遵循以下几个步骤：

1.  为页面创建 HTML 代码。

1.  引用 ArcGIS JavaScript API 和样式表。

1.  加载模块。

1.  确保 DOM 可用。

1.  创建地图。

1.  定义页面内容。

1.  页面样式。

这只是对需要做的事情的简要描述。我们将在接下来的页面中更详细地讨论这些步骤。

## 为 Web 页面创建 HTML 代码

在上一章中，您学习了 HTML、CSS 和 JavaScript 的基本概念。现在，您将开始将这些技能付诸实践。您首先需要创建一个简单的 HTML 文档，最终将作为地图的容器。由于我们使用 ArcGIS API for JavaScript Sandbox，这一步已经为您完成。但是，我希望您花一些时间来检查代码，以便对概念有一个良好的理解。在 Sandbox 的左窗格中，您可以看到以下代码示例中突出显示的代码引用了网页的基本 HTML 代码。显然，其中还有其他 HTML 和 JavaScript 代码，但以下代码构成了网页的基本组件。这段代码包括了几个基本标签，包括`<html>`、`<head>`、`<title>`、`<body>`和其他一些标签：

```js
<!DOCTYPE html>
**<html>**
**<head>**
 **<title>Create a Map</title>**
 **<meta http-equiv="Content-Type" content="text/html; charset=utf-8">**
 **<meta name="viewport" content="initial-scale=1, maximum-scale=1,user-scalable=no">**
  <link rel="stylesheet" href="http://js.arcgis.com/3.7/js/dojo/dijit/themes/claro/claro.css">
  <link rel="stylesheet" href="http://js.arcgis.com/3.7/js/esri/css/esri.css">
 **<style>**
 **html, body, #mapDiv {**
 **padding: 0;**
 **margin: 0;**
 **height: 100%;**
 **}**
 **</style>**

  <script src="http://js.arcgis.com/3.7/"></script>
  <script>
    dojo.require("esri.map");

    function init(){
     var map = new esri.Map("mapDiv", {
        center: [-56.049, 38.485],
        zoom: 3,
        basemap: "streets"
      });
    }
    dojo.ready(init);
  </script>

**</head>**
**<body class="claro">**
 **<div id="mapDiv"></div>**
**</body>**
**</html>**

```

## 引用 ArcGIS API for JavaScript

要开始使用 ArcGIS API for JavaScript，您需要添加对样式表和 API 的引用。在 Sandbox 中，以下代码已经添加到`<head>`标签内：

```js
  <link rel="stylesheet" href="http://js.arcgis.com/3.7/js/esri/css/esri.css">

<script src="http://js.arcgis.com/3.7/"></script>
```

`<script>`标签加载了 ArcGIS API for JavaScript。在撰写本章时，当前版本为 3.7。当 API 的新版本发布时，您需要相应地更新这个数字。`<link>`标签加载了`esri.css`样式表，其中包含了 Esri 小部件和组件的特定样式。

可选地，您可以包含对 Dojo Dijit 主题之一的样式表的引用。ArcGIS API for JavaScript 直接构建在 Dojo JavaScript 框架上。Dojo 带有四个预定义的主题，控制着添加到您的应用程序中的用户界面小部件的外观：Claro、Tundra、Soria 和 Nihilo。在以下代码示例中，我引用了 Claro 主题：

```js
<link rel="stylesheet" href="http://js.arcgis.com/3.7/js/dojo/dijit/themes/claro/claro.css">
```

其他可用的样式表可以像以下代码示例中所示进行引用。您不必引用任何样式表，但如果您打算添加 Dojo 用户界面组件（Dijits），那么您需要加载其中一个样式表来控制组件的样式：

```js
<link rel="stylesheet" href="http://js.arcgis.com/3.7/js/dojo/dijit/themes/tundra/tundra.css">
<link rel="stylesheet" href="http://js.arcgis.com/3.7/js/dojo/dijit/themes/nihilo/nihilo.css">
<link rel="stylesheet" href="http://js.arcgis.com/3.7/js/dojo/dijit/themes/soria/soria.css">
```

网站[www.dojotoolkit.org](http://www.dojotoolkit.org)提供了一个主题测试器，您可以使用它来感受每个主题对用户界面组件显示的影响。主题测试器位于[`archive.dojotoolkit.org/nightly/dojotoolkit/dijit/themes/themeTester.html`](http://archive.dojotoolkit.org/nightly/dojotoolkit/dijit/themes/themeTester.html)。以下截图显示了 Dijit 主题测试器界面：

![引用 ArcGIS API for JavaScript](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_02.jpg)

## 加载模块

在创建`Map`对象之前，您必须首先引用提供地图的资源。这是通过使用`require()`函数来实现的。

### 遗留样式还是 AMD Dojo？

使用旧的 Dojo 遗留样式还是新的 AMD 目前是许多开发人员的挫折之源。**异步模型定义**（**AMD**）是在 Dojo 的 1.7 版本中引入的。ArcGIS Server API for JavaScript 的 3.4 版本发布是第一个使用新的 AMD 样式重写所有模块的版本。目前，旧的遗留样式和 AMD 样式都可以正常工作，但建议使用新的 AMD 样式编写任何新的应用程序。我们将在本书中遵循这个惯例，但请记住，在 3.4 版本发布之前编写的应用程序和一些 Esri 示例仍反映了旧的编码风格。

`require()`函数用于将资源导入到您的网页中。ArcGIS API for JavaScript 提供了各种资源，包括`esri/map`资源，必须在创建地图或处理几何、图形和符号之前提供。一旦提供了对资源的引用，您就可以使用`Map`构造函数来创建`Map`。以下几点展示了如何在 Sandbox 中运行代码：

+   在开始向沙盒添加代码之前，如果需要，请删除以下突出显示的代码。我让您删除的代码来自对 ArcGIS API for JavaScript 的传统编码风格。我们将使用新的 AMD 风格。在将来的 Sandbox 版本中，可能不需要删除这些代码行。我预计 Esri 最终将基本代码块迁移到更新的 AMD 风格：

```js
<script>
 **dojo.require("esri.map");**

 **function init(){**
 **var map = new esri.Map("mapDiv", {**
 **center: [-56.049, 38.485],**
 **zoom: 3,**
 **basemap: "streets"**
 **});**
 **}**
 **dojo.ready(init);**
  </script>
```

+   您导入的资源需要包含在新的`<script>`标签中。将以下突出显示的代码行添加到`<script>`标签内的沙盒中。`require()`函数内部使用的参数名称可以是任何您喜欢的名称。但是，Esri 和 Dojo 都提供了一组首选参数。我建议在为`require`回调函数传递参数时使用 Esri 首选参数列表。Dojo 也使用其首选参数别名。例如，在您添加的以下代码中，我们提供了对`esri/map`资源的引用，然后在匿名函数内部，我们提供了一个首选参数`Map`。在`require()`函数中引用的每个资源都将有一个相关的参数，这将为该资源提供一个对象的钩子：

```js
<script>
**require(["esri/map", "dojo/domReady!"], function(Map) {**

 **});**

</script>
```

## 确保文档对象模型可用

当网页加载时，组成页面的所有 HTML 元素都会被加载和解释。这被称为**文档对象模型**（**DOM**）。非常重要的是，您的 JavaScript 在所有元素加载之前不要尝试访问任何这些元素。显然，如果您的 JavaScript 代码尝试访问尚未加载的元素，将会导致错误。为了控制这一点，Dojo 有一个`ready()`函数，您可以将其包含在`require()`函数内部，这样它将仅在所有 HTML 元素和任何模块加载后执行。或者，您可以使用`dojo/domReady!`插件来确保所有 HTML 元素都已加载。我们将使用第二种方法进行此练习。

在前面的代码中，我们已经使用了带有`dojo/domReady!`的插件添加到`require()`函数中。

### 注意

虽然在基本的 HTML 文件中直接添加 JavaScript 代码是完全可能的，但最好的做法是创建一个单独的 JavaScript 文件（.js）。我们在本书中编写的大部分代码都将在 HTML 文件中完成，以简化操作，但随着您的应用程序变得更加复杂，您将希望遵循将 JavaScript 代码编写到单独文件的做法。

## 创建地图

通过`esri/map`创建新地图，这是您在先前步骤中导入的`esri/map`模块中找到的`Map`类的引用。在`require()`函数内部，您将使用构造函数创建一个新的`Map`对象。`Map`对象的构造函数接受两个参数，包括一个引用到网页上放置地图的`<div>`标签以及一个可用于定义各种地图设置选项的选项参数。`options`参数被定义为一个包含一组键/值对的 JSON 对象。

也许最显眼的选项是`basemap`，它允许您从[ArcGIS.com](http://ArcGIS.com)选择预定义的底图，可以包括`streets`、`satellite`、`hybrid`、`topo`、`gray`、`oceans`、`national-geographic`或`osm`。`zoom`选项用于定义地图的起始缩放级别，可以是与预定义缩放比例级别对应的整数值。`minZoom`和`maxZoom`选项定义地图的最小和最大比例缩放级别。`center`选项定义地图的中心点，最初将显示并使用包含纬度/经度坐标对的`Point`对象。还有许多其他选项，您可以将其作为参数传递给`Map`对象的构造函数。

首先，我们将通过添加以下代码的突出显示行来创建一个名为`map`的全局变量以及`require()`函数：

```js
<script>
 **var map;**
 **require(["esri/map", "dojo/domReady!"], function(Map) {**
 **});**
 </script>
```

将以下突出显示的代码块添加到`require()`函数中。这行代码是新`Map`对象的构造函数。传递给构造函数的第一个参数是指向地图将放置的`<div>`标签的 ID 的引用。我们还没有定义这个`<div>`标签，但我们将在下一步中这样做。传递给`Map`构造函数的第二个参数是一个定义选项的 JSON 对象，包括将作为地图中心的地理坐标、缩放级别和`topo`底图。

```js
basemap.require(["esri/map", "dojo/domReady!"], function(Map) {
 **map = new Map("mapDiv", {**
 **basemap: "topo",**
 **center: [-122.45,37.75], // long, lat**
 **zoom: 13,**
 **sliderStyle: "small"**
 **});**
});
```

## 创建页面内容

最后一步之一是创建 HTML `<div>`标签，作为地图的容器。您总是希望为`<div>`标签分配一个唯一的 ID，以便您的 JavaScript 代码可以引用该位置。在 Sandbox 中，这个带有唯一标识符`mapDiv`的`<div>`标签已经为您创建。您可以在下面的代码的突出显示行中看到这一点。此外，您还需要为`<body>`标签定义类属性，该属性应引用您引用的 Dojo 样式表。

在下面的代码中，您可以看到 Sandbox 中已经创建的`<body>`标签完成了前面两个任务：

```js
<body class="claro">
 **<div id="mapDiv"></div>**
</body>
```

## 为页面添加样式

您可以向`<head>`标签添加样式信息，以定义网页的各种样式方面。在这种情况下，样式已经在 Sandbox 中为您创建，如下面的代码所示。在这种情况下，样式包括设置地图以填满整个浏览器窗口：

```js
<style>
    html, body, #mapDiv {
      padding:0;
      margin:0;
      height:100%;
    }
</style>
```

## 完整的代码

这个简单应用程序的代码应该如下所示：

```js
<!DOCTYPE html>
<html>
  <head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=7, IE=9, IE=10">
    <meta name="viewport" content="initial-scale=1, maximum-scale=1,user-scalable=no"/>
    <title>Simple Map</title>
    <link rel="stylesheet" href="http://js.arcgis.com/3.7/js/esri/css/esri.css">
    <link rel="stylesheet" href="http://js.arcgis.com/3.7/js/dojo/dijit/themes/claro/claro.css">
    <style>
      html, body, #map {
        height: 100%;
        width: 100%;
        margin: 0;
        padding: 0;
      }    
    </style>
    <script src="http://js.arcgis.com/3.7/"></script>
    <script>
      var map;

      require(["esri/map", "dojo/domReady!"], function(Map) {
        map = new Map("map", {
          basemap: "topo",
          center: [-122.45,37.75], // long, lat
          zoom: 13,
          sliderStyle: "small"
        });
      });
    </script>
  </head>

  <body class="claro">
    <div id="map"></div>
  </body>
</html>
```

点击**Run**按钮执行代码，如果一切编码正确，您应该看到以下输出：

![完整的代码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_16.jpg)

# 关于地图的更多信息

在前面描述的过程中，我们介绍了使用 ArcGIS API for JavaScript 构建每个应用程序时需要遵循的流程。您学会了如何创建一个初始化 JavaScript 函数。初始化脚本的目的是创建地图，添加图层，并执行任何其他必要的设置例程，以启动应用程序。创建地图通常是您要做的第一件事，在本节中，我们将更仔细地看看您创建`Map`类实例的各种选项。

在面向对象编程中，通过构造函数来创建类实例是经常通过构造函数来完成的。构造函数是用于创建或初始化新对象的函数。在这种情况下，构造函数用于创建新的`Map`对象。构造函数通常接受一个或多个参数，这些参数可用于设置对象的初始状态。

`Map`构造函数可以接受两个参数，包括地图应该驻留的容器和地图的各种选项。但是，在调用地图的构造函数之前，您必须首先引用提供地图的资源。这是通过导入`esri/map`资源来实现的。一旦提供了对资源的引用，您就可以使用构造函数来创建地图。`<div>` ID 是构造函数的必需参数，用于指定地图的容器。此外，您还可以传递多个选项，以控制地图的各个方面，包括底图图层、地图中心的初始显示、导航控件的显示、平移期间的图形显示、滑块的控制、详细级别等等。

让我们更仔细地看一下在地图构造函数中如何指定选项。选项是构造函数中的第二个参数，总是用括号括起来。这定义了 JSON 对象的内容。在括号内，每个选项都有一个特定的名称，后面跟着一个冒号，然后是控制该选项的数据值。如果您需要向构造函数提交多个选项，每个选项之间用逗号分隔。以下代码示例显示了如何向`Map`构造函数提交选项：

```js
      var map = new Map("mapDiv", {
        center: [-56.049, 38.485],
        zoom: 3,
        basemap: "streets"
      });
```

在这种情况下，我们正在为地图坐标定义选项，该坐标将作为地图的中心，以及缩放级别和街道的底图图层。这些选项用花括号括起来，并用逗号分隔。

# 使用地图服务层

没有数据层的地图有点像一块空白的画布。您添加到地图上的数据层赋予了它意义，并为分析设置了舞台。提供可以添加到地图上的数据层的两种主要类型的地图服务：动态地图服务层和瓦片地图服务层。

动态地图服务层引用创建地图图像并将图像返回给应用程序的地图服务。这种地图服务可能由一个或多个信息层组成。例如，以下屏幕截图中显示的人口统计地图服务由九个不同的图层组成，代表不同地理级别的人口统计信息：

![使用地图服务层](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_03.jpg)

虽然它们在客户端应用程序中显示可能需要更长的时间，因为它们必须*即时生成*，但动态地图服务层比瓦片地图服务层更灵活。在动态地图服务层中，您可以通过图层定义控制显示的要素，设置服务内各个图层的可见性，并为图层定义时间信息。例如，在前面屏幕截图中详细介绍的**人口统计**地图服务层中，您可能选择在应用程序中仅显示**人口普查区组**。这就是动态地图服务层提供的灵活性，而这是瓦片地图服务层所不具备的。

瓦片地图服务层引用预定义的地图瓦片缓存，而不是动态渲染的图像。理解瓦片地图服务的概念最简单的方法是将其想象成覆盖在地图表面上的网格。网格中的每个单元格大小相同，并将用于将地图切割成称为瓦片的单个图像文件。这些单独的瓦片作为图像文件存储在服务器上，并根据地图范围和比例尺的需要进行检索。这个过程通常在各种地图比例尺上重复。最终结果是生成了各种地图比例尺的瓦片集缓存。当地图在应用程序中显示时，它看起来是无缝的，即使它由许多单独的瓦片组成。

![使用地图服务层](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_04.jpg)

这些瓦片或缓存地图层通常用作包括图像、街道地图、地形图在内的底图，或者用于不经常更改的数据层。瓦片地图服务往往显示更快，因为它们没有每次请求地图时都要创建图像的开销。

操作层通常覆盖在瓦片地图的顶部，这些层通常是动态层。虽然它们在性能方面可能会慢一些，但动态地图服务层具有能够动态定义外观的优势。

## 使用图层类

使用 JavaScript API 中的图层类，您可以引用由 ArcGIS Server 和其他地图服务器托管的地图服务。所有图层类都继承自`Layer`基类。`Layer`类没有构造函数，因此您不能从这个类中专门创建对象。这个类只是定义了所有从`Layer`继承的类的属性、方法和事件。

如下图所示，`DynamicMapServiceLayer`、`TiledMapServiceLayer`和`GraphicsLayer`都直接继承自`Layer`类。`DynamicMapServiceLayer`和`TiledMapserviceLayer`也充当基类。`DynamicMapServiceLayer`是动态地图服务的基类，而`TiledMapServiceLayer`是平铺地图服务的基类。第三章，“向地图添加图形”，完全致力于图形和`GraphicsLayer`，因此我们将在本书的后面讨论这种类型的图层。`Layer`、`DynamicMapServiceLayer`和`TiledMapServiceLayer`都是基类，这意味着您不能在应用程序中从这些类中专门创建对象。

![使用图层类](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_05.jpg)

## 平铺地图服务图层

如前所述，平铺地图服务图层引用了预定义图像的缓存，这些图像被平铺在一起以创建无缝的地图显示。这些通常用作基础地图。

![平铺地图服务图层](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_06.jpg)

当引用由 ArcGIS Server 公开的平铺（缓存）地图服务时，使用`ArcGISTiledMapServiceLayer`类。由于这种类型的对象针对已缓存的平铺地图集工作，因此通常可以提高性能。`ArcGISTiledMapServiceLayer`的构造函数需要一个指向地图服务的 URL 指针，以及允许您为地图服务分配 ID 并控制透明度和可见性的选项。

在下面的代码示例中，请注意`ArcGISTiledMapServiceLayer`的构造函数需要一个参数，该参数引用地图服务。在创建图层实例后，可以使用`Map.addLayer()`方法将其添加到地图中，该方法接受一个包含对平铺地图服务图层的引用的变量：

```js
var basemap = new ArcGISTiledMapServiceLayer("http://server.arcgisonline.com/ArcGIS/rest/services/World_Topo_Map/MapServer");
map.addLayer(basemap);
```

`ArcGISTiledMapServiceLayer`主要用于快速显示缓存的地图数据。您还可以控制数据显示的级别。例如，您可能希望在用户缩放到 0-6 级时显示来自概括的`ArcGISTiledMapService`的数据，显示州际和高速公路，然后在用户进一步放大时切换到更详细的`ArcGISTiledMapService`。您还可以控制添加到地图的每个图层的透明度。

## 动态地图服务图层

正如其名称所示，`ArcGISDynamicMapServiceLayer`类用于创建由 ArcGIS Server 提供的动态地图。与`ArcGISTiledMapServiceLayer`一样，`ArcGISDynamicMapServiceLayer`的构造函数需要一个指向地图服务的 URL，以及可选参数，用于为服务分配 ID，确定地图图像的透明度，以及设置图层的初始可见性为 true 或 false 的可见性选项。`ArcGISDynamicMapServiceLayer`类名可能有些误导。尽管它似乎是指一个单独的数据图层，但实际上并非如此。它指的是地图服务而不是数据图层。地图服务内的单独图层可以通过`setVisibleLayers()`方法打开/关闭。

![动态地图服务图层](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_07.jpg)

创建`ArcGISDynamicMapServiceLayer`的实例看起来与`ArcGISTiledMapServiceLayer`非常相似。以下代码示例说明了这一点。构造函数接受一个指向地图服务的 URL。第二个参数定义了可选参数，您可以提供以控制透明度、可见性和图像参数：

```js
var operationalLayer = new ArcGISDynamicMapServiceLayer("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Demographics/ESRI_Population_World/MapServer",{"opacity":0.5});
map.addLayer(operationalLayer);
```

将上述两行代码添加到 ArcGIS API for JavaScript Sandbox 中，如下所示的代码：

```js
  <script>
    var map;
    require(["esri/map", **"esri/layers/ArcGISDynamicMapServiceLayer"**, "dojo/domReady!"], function(Map, **ArcGISDynamicMapServiceLayer**) {
      map = new Map("mapDiv", {
        basemap: "topo",
        center: [-122.45,37.75], // long, lat
        **zoom: 5,**
        sliderStyle: "small"
      });
      **var operationalLayer = new ArcGISDynamicMapServiceLayer("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Demographics/ESRI_Population_World/MapServer",{"opacity":0.5});**
 **map.addLayer(operationalLayer);**
    });
  </script>
```

运行上述代码，查看动态图层添加到地图中，如下截图所示：

![动态地图服务图层](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_08.jpg)

使用`ArcGISDynamicMapServiceLayer`的实例，您可以执行许多操作。显然，您可以创建显示服务中数据的地图，但您还可以从服务中的图层查询数据，通过图层定义控制要素显示，控制单个图层的可见性，设置与时间相关的信息，将地图导出为图像，控制背景透明度等等。

## 向地图添加图层

`addLayer()`方法将图层的实例（`ArcGISDynamicMapServiceLayer`或`ArcGISTiledMapServiceLayer`）作为第一个参数，并且可选的索引指定它应该放置在哪里。在下面的代码示例中，我们创建了一个指向服务 URL 的`ArcGISDynamicMapServiceLayer`的新实例。然后调用`Map.addLayer()`来传递图层的新实例。服务中的图层现在将在地图上可见。

```js
var operationalLayer = new ArcGISDynamicMapServiceLayer("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Demographics/ESRI_Population_World/MapServer");
map.addLayer(operationalLayer);
```

`addLayers()`方法接受一个图层对象数组，并一次性添加它们。

除了能够向地图添加图层，您还可以使用`Map.removeLayer()`或`Map.removeAllLayers()`从地图中删除图层。

## 从地图服务设置可见图层

您可以使用`setVisibleLayers()`方法控制动态地图服务图层中各个图层的可见性。这仅适用于动态地图服务图层，而不适用于瓦片地图服务图层。该方法接受一个整数数组，对应于地图服务中的数据图层。

这个数组是从零开始的，所以地图服务中的第一个图层占据位置`0`。在下面的截图中，**人口统计**地图服务中的`Demographics/ESRI_Census_USA`占据索引`0`：

![设置地图服务中可见图层](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_09.jpg)

因此，如果我们只想显示来自该服务的**人口普查区块点**和**人口普查区块组**要素，我们可以使用`setVisibleLayers()`，如下面的代码示例所示：

```js
var dynamicMapServiceLayer = new ArcGISDynamicMapServiceLayer("https://gis.sanantonio.gov/ArcGIS/rest/services/Demographics/MapServer");
dynamicMapServiceLayer.setVisibleLayers([1,2]);
map.addLayer(dynamicMapServiceLayer);
```

## 设置定义表达式

在 ArcGIS for Desktop 中，您可以使用定义表达式来限制将显示的数据图层中的要素。定义表达式只是针对图层中的列和行设置的 SQL 查询。只有满足查询的属性的要素才会显示。例如，如果您只想显示人口超过一百万的城市，表达式将是类似于`POPULATION > 1000000`。ArcGIS API for JavaScript 包含一个`setLayerDefinitions()`方法，接受一个可以应用于`ArcGISDynamicMapServiceLayer`的定义数组，以控制生成地图中要素的显示。下面的代码示例显示了如何做到这一点：

![设置定义表达式](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_10.jpg)

首先创建一个数组，用于保存多个`where`子句，这些子句将作为每个图层的定义表达式。在这种情况下，我们为第一层和第六层定义了图层定义。数组是从零开始的，所以第一个数组位于索引`0`。然后将`where`子句放入数组中，然后传递到`setLayerDefinitions()`方法中。然后 ArcGIS Server 会根据每个图层的`where`子句渲染匹配的要素。

## 地图导航

现在您已经了解了一些关于地图和驻留在其中的图层的知识，是时候学习如何在应用程序中控制地图导航了。在大多数情况下，您的用户将需要能够使用平移和缩放功能在地图周围导航。ArcGIS API for JavaScript 提供了许多用户界面小部件和工具栏，您可以使用这些小部件和工具栏来允许用户使用缩放和平移功能更改当前地图范围。地图导航也可以通过键盘导航和鼠标导航进行。除了这些用户界面组件和硬件接口之外，地图导航也可以通过编程方式进行控制。

### 地图导航小部件和工具栏

向您的应用程序提供地图导航控制的最简单方法是通过添加各种小部件和工具栏。创建新地图并添加图层时，默认情况下会包括一个缩放滑块。此滑块允许用户放大和缩小地图。缩放滑块如下截图所示。您无需在程序上做任何事情即可使缩放滑块出现在地图上；它默认存在。但是，如果需要，您可以通过在创建`Map`对象的实例时将滑块选项设置为`false`来简单地删除应用程序中的滑块：

```js
{"slider":false,"nav":true,"opacity":0.5,"imageParameters":imageParameters}
```

以下截图显示了带有缩放滑块的地图：

![地图导航小部件和工具栏](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_11.jpg)

您还可以添加平移按钮，单击时将地图平移到箭头指向的方向。默认情况下，平移按钮不会出现在地图上。创建`Map`对象时，必须明确将`nav`选项设置为`true`：

```js
{"nav":true,"opacity":0.5,"imageParameters":imageParameters}
```

以下截图显示了平移选项：

![地图导航小部件和工具栏](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_12.jpg)

ArcGIS API for JavaScript 还为您提供了向应用程序添加几种类型的工具栏的能力，包括包含放大和缩小、平移、全范围、下一个范围和上一个范围按钮的导航工具栏。工具栏的创建将在后面的章节中详细介绍，因此我们将保存该讨论以供以后讨论。

![地图导航小部件和工具栏](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_13.jpg)

### 使用鼠标和键盘进行地图导航

用户还可以使用鼠标和/或键盘设备控制地图导航。默认情况下，用户可以执行以下操作：

+   拖动鼠标进行平移

+   使用鼠标向前滚动以放大

+   使用鼠标向后滚动以缩小

+   按下*Shift*并拖动鼠标以放大

+   按下*Shift* + *Ctrl*并拖动鼠标以缩小

+   按下*Shift*并单击以恢复到中心

+   双击以居中和放大

+   按下*Shift*并双击以居中和放大

+   使用箭头键进行平移

+   使用*+*键放大到某个级别

+   使用*-*键缩小一个级别

可以使用多个`Map`方法之一来禁用前述选项。例如，要禁用滚轮缩放，您将使用`Map.disableScrollWheelZoom()`方法。这些导航功能也可以在地图加载后移除。

### 获取和设置地图范围

您要掌握的第一件事情之一是获取和设置地图范围。默认情况下，应用程序中地图的初始范围是创建地图服务时地图文档文件（`.mxd`）上次保存时的地图范围。在某些情况下，这可能正是您想要的，但是如果您需要设置除默认值之外的地图范围，您将有几个选项。

可以在`Map`对象的构造函数中定义的可选参数之一是中心参数。您可以将此可选参数与缩放对象一起使用，以设置初始地图范围。在下面的代码示例中，您将看到这一点，我们为地图的中心定义了一个坐标对，以及一个缩放级别为`3`：

```js
var map = new Map("mapDiv", {
        center: [-56.049, 38.485],
        zoom: 3,
        basemap: "streets"
      });
```

地图的初始范围不是必需的参数，因此如果您省略此信息，地图将简单地使用默认范围。在下面的代码示例中，只指定了容器的 ID：

```js
var map = new Map("map");
```

创建`Map`对象后，还可以使用`Map.setExtent()`方法来更改范围，方法是传入一个`Extent`对象，如下面的代码示例所示：

```js
var extent = new Extent(-95.271, 38.933, -95.228, 38.976);
map.setExtent(extent);
```

或者，您可以像下面的代码示例中那样单独设置`Extent`属性。

```js
var extent = new Extent();
extent.xmin = -95.271;
extent.ymin = 38.933;
extent.xmax = -95.228;
extent.ymax = 38.976;
map.setExtent(extent);
```

在应用程序中使用多个地图服务时，可以通过地图的构造函数或使用其中一个服务的`Map.fullExtent`方法来设置初始地图范围。例如，通常使用提供基础图层功能的地图服务，其中包含航空影像以及包含自己本地操作数据源的地图服务。下面的代码示例使用了`fullExtent()`方法：

```js
map = new Map("mapDiv", {extent:esri.geometry.geographicToWebMercator(myService2.fullExtent) });
```

当前范围可以通过`Map.extent`属性或`onExtentChange`事件来获取。请注意，`Map.setExtent`属性是只读的，因此不要尝试通过此属性设置地图范围。

# 地图事件

在编程世界中，事件是应用程序中发生的动作。通常，这些事件是由最终用户触发的，可以包括鼠标点击、鼠标拖动和键盘操作，但也可以包括数据的发送和接收、组件修改等。

JavaScript 的 ArcGIS API 是一个异步 API，遵循发布/订阅模式，应用程序向监听器注册（发布）事件。下图说明了这个过程。监听器负责监视应用程序的这些事件，然后触发响应事件的`handler`函数。可以将多个事件注册到同一个监听器上。`dojo on()`方法作为事件到处理程序的功能。

![地图事件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_14.jpg)

正如您可能记得的那样，ArcGIS Server JavaScript API 是建立在 Dojo 之上的。使用 Dojo，事件通过`dojo on()`方法注册到处理程序。此方法需要三个参数。请看下面截图中显示的代码示例，以更好地理解如何注册事件：

![地图事件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_02_15.jpg)

我们使用`on()`方法并传入`map`、`click`和`displayCoordinates`等参数。前两个参数表示我们要注册的对象和事件。在这种情况下，这意味着我们正在注册`Map`对象上找到的`click`事件。每次用户在地图范围内点击鼠标时，都会触发此事件。最后一个参数`displayCoordinates`表示事件的监听器。因此，每当`Map`对象上的`click`事件被触发时，它将触发`displayCoordinates`函数，该函数将运行并报告地图的当前范围。尽管事件和它们注册的处理程序会根据您的情况而改变，但注册的方法是相同的。

每次事件发生时，都会生成一个`Event`对象。这个`Event`对象包含额外的事件信息，比如点击的鼠标按钮或者按下的键盘按键。这个对象会自动传递到事件处理程序中，可以进行检查。在下面的代码示例中，您可以看到`Event`对象作为参数传递到处理程序中。这是一个动态对象，其属性将根据触发的事件类型而改变。

```js
function addPoint(evt) {
    alert(evt.mapPoint.x, evt.mapPoint.y);
}
```

API 中许多不同的对象上都有许多不同的事件可用。但是，重要的是要记住，您不必为每个事件注册监听器。只有对应用程序必要的事件才应该注册。当发生一个未注册监听器的事件时，该事件将被简单地忽略。

`Map`对象包含许多不同的事件，您可以对其做出响应，包括各种鼠标事件、范围更改事件、底图更改事件、键盘事件、图层事件、平移和缩放事件等。您的应用程序可以对任何这些事件做出响应。在接下来的章节中，我们将研究其他对象上可用的事件。

在不再需要时，将事件与其处理程序断开连接是一种良好的编程实践。通常在用户从页面导航离开或关闭浏览器窗口时执行此操作。以下代码示例显示了如何通过简单调用`remove()`方法来实现这一点：

```js
var mapClickEvent = on(myMap, "click", displayCoordinates);
mapClickEvent.remove();
```

# 总结

在本章中，我们涵盖了很多内容。使用 ArcGIS API for JavaScript 创建的所有应用程序都需要一定的步骤。我们将其称为样板代码。这包括定义对 API 和样式表的引用、加载模块、创建初始化函数以及其他一些步骤。在`initialization`函数中，您很可能会创建地图、添加各种图层，并执行其他在应用程序使用之前需要执行的设置操作。在本章中，您学会了如何执行这些任务。

此外，我们还研究了可以添加到地图的各种图层类型，包括切片地图服务图层和动态地图服务图层。切片地图服务图层是预先创建并缓存在服务器上的，通常用作应用程序中的底图。动态地图服务图层必须在每次请求时动态创建，因此可能需要更长时间来生成。但是，动态地图服务图层可以用于执行许多类型的操作，包括查询、设置定义表达式等。

此外，您还学习了如何以编程方式控制地图范围。最后，我们介绍了事件的主题，您学会了如何将事件连接到事件处理程序，这只是一个在特定事件触发时运行的 JavaScript 函数。在下一章中，我们将仔细研究如何向应用程序添加图形。


# 第三章：将图形添加到地图

图形是在地图的图层上绘制的点、线或多边形，这些图层独立于与地图服务相关的任何其他数据图层。大多数人将图形对象与在地图上显示图形的符号相关联。然而，在 ArcGIS Server 中，每个图形可以由多达四个对象组成，包括图形的几何、与图形相关的符号、描述图形的属性和定义当单击图形时出现的信息窗口格式的信息模板。尽管图形可以由多达四个对象组成，但并不总是有必要这样做。您选择与图形关联的对象将取决于您正在构建的应用程序的需求。例如，在显示 GPS 坐标的地图应用程序中，您可能不需要关联属性或显示图形的信息窗口。然而，在大多数情况下，您将为图形定义几何和符号。

图形是存储在地图上单独图层中的临时对象。它们在应用程序使用时显示，并在会话完成时删除。名为图形图层的单独图层存储与您的地图相关的所有图形。在第二章中，*创建地图和添加图层*，我们讨论了各种类型的图层，包括动态地图服务图层和切片地图服务图层。与其他类型的图层一样，`GraphicsLayer`也继承自`Layer`类。因此，`Layer`类中找到的所有属性、方法和事件也将存在于`GraphicsLayer`中。

图形显示在应用程序中存在的任何其他图层的顶部。以下屏幕截图显示了点和多边形图形的示例。这些图形可以由用户创建，也可以由应用程序根据已提交的任务绘制。例如，商业分析应用程序可能提供一个工具，允许用户绘制自由手绘多边形来表示潜在的贸易区域。

多边形图形将显示在地图的顶部，并且可以用作拉取与潜在贸易区域相关的人口统计信息的地理处理任务的输入。

![将图形添加到地图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_03_01.jpg)

许多 ArcGIS Server 任务将它们的结果作为图形返回。`QueryTask`对象可以执行属性和空间查询。然后，查询的结果以`FeatureSet`对象的形式返回到应用程序中，它只是一个要素数组。然后，您可以访问每个要素作为图形，并使用循环结构在地图上绘制它们。也许您想要查找并显示所有与百年洪水平原相交的土地地块。`QueryTask`对象可以执行空间查询，然后将结果返回到您的应用程序中，然后它们将显示为地图上的多边形图形。

在本章中，我们将涵盖以下主题：

+   图形的四个部分

+   为图形创建几何

+   符号化图形

+   为图形分配属性

+   在信息窗口中显示图形属性

+   创建图形

+   将图形添加到图形图层

# 图形的四个部分

图形由四个部分组成：**几何**、**符号**、**属性**和**信息模板**，如下图所示：

![图形的四个部分](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_03_02.jpg)

图形具有描述其位置的几何表示。几何与符号一起定义了图形的显示方式。图形还可以具有提供有关图形的描述信息的属性。属性被定义为一组名称-值对。例如，描绘野火位置的图形可以具有描述火灾名称以及烧毁的英亩数的属性。信息模板定义了在图形出现时应显示哪些属性以及它们应该如何显示。创建后，图形对象必须存储在`GraphicsLayer`对象中，然后才能显示在地图上。这个`GraphicsLayer`对象作为将要显示的所有图形的容器。

图形的所有元素都是可选的。但是，图形的几何和符号几乎总是被分配的。如果没有这两个项目，地图上就没有东西可以显示，而且没有显示图形的意义。

下图显示了创建图形并将其添加到图形图层的典型过程。在这种情况下，我们应用了图形的几何以及一个符号来描绘图形。但是，我们还没有专门为这个图形分配属性或信息模板。

![图形的四个部分](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_03_03.jpg)

# 为图形创建几何

图形几乎总是有一个几何组件，这对于它们在地图上的放置是必要的。这些几何对象可以是点、多点、折线、多边形或范围，并且可以通过这些对象的构造函数进行程序化创建，或者可以作为查询等任务的输出返回。

在创建任何这些几何类型之前，需要导入`esri/geometry`资源。这个几何资源包含了`Geometry`、`Point`、`Multipoint`、`Polyline`、`Polygon`和`Extent`的类。

`Geometry`是由`Point`、`MultiPoint`、`Polyline`、`Polygon`和`Extent`继承的基类。

如下代码行所示，`Point`类通过 X 和 Y 坐标定义位置，并且可以定义为地图单位或屏幕单位：

```js
new Point(-118.15, 33.80);
```

# 符号化图形

您创建的每个图形都可以通过 API 中找到的各种符号类之一进行符号化。点图形通过`SimpleMarkerSymbol`类进行符号化，可用形状包括圆圈、十字、菱形、正方形和 X。还可以通过`PictureMarkerSymbol`类对点进行符号化，该类使用图像来显示图形。线性特征通过`SimpleLineSymbol`类进行符号化，可以包括实线、虚线、点线或组合。多边形通过`SimpleFillSymbol`类进行符号化，可以是实心、透明或斜纹。如果您希望在多边形中使用图像进行重复图案，可以使用`PictureFillSymbol`类。文本也可以添加到图形图层，并通过`TextSymbol`类进行符号化。

点或多点可以通过`SimpleMarkerSymbol`类进行符号化，该类具有各种可以设置的属性，包括样式、大小、轮廓和颜色。样式是通过`SimpleMarkerSymbol.setStyle()`方法设置的，该方法接受以下常量之一，对应于绘制的符号类型（圆圈、十字、菱形等）：

+   `STYLE_CIRCLE`

+   `STYLE_CROSS`

+   `STYLE_DIAMOND`

+   `STYLE_PATH`

+   `STYLE_SQUARE`

+   `STYLE_X`

点图形也可以有轮廓颜色，这是通过`SimpleLineSymbol`类创建的。还可以设置图形的大小和颜色。查看以下代码示例，了解如何完成这些操作：

```js
var markerSymbol = new SimpleMarkerSymbol();
markerSymbol.setStyle(SimpleMarkerSymbol.STYLE_CIRCLE);
markerSymbol.setSize(12);
markerSymbol.setColor(new Color([255,0,0,0.5]));
```

![符号化图形](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_03_06.jpg)

线性特征使用`SimpleLineSymbol`类进行符号化，可以是实线或点划线的组合。其他属性包括颜色，使用`dojo/Color`定义，以及`setWidth`属性设置线条的粗细。以下代码示例详细解释了该过程：

```js
var polyline = new Polyline(msr);
//a path is an array of points
var path = [new Point(-123.123, 45.45, msr),…..];
polyline.addPath(path);
var lineSymbol = new SimpleLineSymbol().setWidth(5);

//create polyline graphic using polyline and line symbol
var polylineGraphic = new Graphic(polyline, lineSymbol);
map.graphics.add(polylineGraphic);
```

运行上述代码时获得以下屏幕截图：

![符号化图形](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_03_07.jpg)

多边形通过`SimpleFillSymbol`类进行符号化，允许以实线、透明或交叉图案绘制多边形。多边形还可以具有由`SimpleLineSymbol`对象指定的轮廓。以下代码示例详细解释了该过程。

```js
var polygon = new Polygon(msr);
//a polygon is composed of rings
var ring = [[-122.98, 45.55], [-122.21, 45.21], [-122.13, 45.53],……];
polygon.addRing(ring);
var fillSymbol = new SimpleFillSymbol().setColor(new Color([255,0,0,0.25]));
//create polygon graphic using polygon and fill symbol
var polygonGraphic = new Graphic(polygon, fillSymbol);
//add graphics to map's graphics layer
map.graphics.add(polygonGraphic);
```

运行上述代码时获得以下屏幕截图：

![符号化图形](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_03_08.jpg)

# 为图形分配属性

图形的属性是描述该对象的名称-值对。在许多情况下，图形是作为`QueryTask`等任务操作的结果生成的。在这种情况下，每个图形由几何和属性组成，然后您需要相应地对每个图形进行符号化。与图层关联的字段属性成为图形的属性。在某些情况下，可以通过`outFields`等属性限制属性。如果您的图形是以编程方式创建的，您需要使用`Graphic.setAttributes()`方法在代码中分配属性，如以下代码示例所示：

```js
Graphic.setAttributes( {"XCoord":evt.mapPoint.x, "YCoord".evt.mapPoint.y,"Plant":"Mesa Mint"});
```

# 在信息模板中显示图形属性

除了属性之外，图形还可以具有定义属性数据在弹出窗口中显示方式的信息模板。在以下代码示例中定义了一个点属性变量，其中包含键-值对。在这种特殊情况下，我们有包括地址、城市和州的键。每个名称或键都有一个值。该变量是新点图形构造函数的第三个参数。信息模板定义了弹出窗口的格式，并包含一个标题和一个可选的内容模板字符串。

```js
var pointESRI = new Point(Number(theX), Number(theY),msr);
var markerSymbol = new SimpleMarkerSymbol();
markerSymbol.setStyle(SimpleMarkerSymbol.STYLE_SQUARE);
markerSymbol.setSize(12);
markerSymbol.setColor(new Color([255,0,0]));
var pointAttributes = {address:"101 Main Street", city:"Portland", state:"Oregon"};
var pointInfoTemplate = new InfoTemplate("Geocoding Results");
//create point graphic using point and marker symbol
var pointGraphic = new Graphic(pointESRI, markerSymbol, pointAttributes).setInfoTemplate(pointInfoTemplate);
//add graphics to maps' graphics layer
map.graphics.add(pointGraphic);
```

上述代码生成以下屏幕截图：

![在信息模板中显示图形属性](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_03_13.jpg)

# 创建图形

一旦您定义了图形的几何、符号和属性，就可以使用这些参数创建一个新的图形对象，并将其作为`Graphic`对象的构造函数的输入。在以下代码示例中，我们将为几何（`pointESRI`）、符号（`markerSymbol`）、点属性（`pointAttributes`）和信息模板（`pointInfoTemplate`）创建变量，然后将这些变量作为输入应用于我们的名为`pointGraphic`的新图形的构造函数。最后，将该图形添加到图形图层中。

```js
var pointESRI = new Point(Number(theX), Number(theY, msr);
var markerSymbol = new SimpleMarkerSymbol();
markerSymbol.setStyle(SimpleMarkerSymbol.STYLE_SQUARE);
markerSymbol.setSize(12);
markerSymbol.setColor(new Color([255,0,0]));

var pointAttributes = {address:"101 Main Street", city:"Portland", state:"Oregon"};
var pointInfoTemplate = new InfoTemplate("Geocoding Results");
//create the point graphic using point and marker symbol
var pointGraphic = new Graphic(pointESRI, markerSymbol, pointAttributes).setInfoTemplate(pointTemplate);

//add graphics to maps' graphics layer
map.graphics.add(pointGraphic);
```

# 将图形添加到图形图层

在地图上显示任何图形之前，您必须将它们添加到图形图层中。每个地图都有一个图形图层，其中包含一个最初为空的图形数组，直到您添加图形为止。该图层可以包含任何类型的图形对象。这意味着您可以同时混合点、线和多边形。图形通过`add()`方法添加到图层中，也可以通过`remove()`方法单独删除。如果需要同时删除所有图形，则可以使用`clear()`方法。图形图层还具有可以注册的多个事件，包括`click`、`mouse-down`等。

## 多个图形图层

API 支持多个图形图层，这样可以更轻松地组织不同类型的图形。图层可以根据需要轻松添加或删除。例如，您可以将代表县的多边形图形放在一个图形图层中，将代表交通事故的点图形放在另一个图形图层中。然后，您可以根据需要轻松添加或删除任一图层。

# 是时候练习图形了。

在这个练习中，您将学习如何在地图上创建和显示图形。我们将创建一个专题地图，显示科罗拉多州按县的人口密度。您还将介绍查询任务。正如您将在以后的章节中学到的那样，任务可以在 ArcGIS Server 中执行，并包括空间和属性查询、要素识别和地理编码等内容。最后，您将学习如何将属性附加到您的图形要素并在信息窗口中显示它们：

1.  在[`developers.arcgis.com/en/javascript/sandbox/sandbox.html`](http://developers.arcgis.com/en/javascript/sandbox/sandbox.html)上打开 JavaScript 沙盒。

1.  从以下代码块中突出显示的`<script>`标记中删除 JavaScript 内容：

```js
  <script>
 **dojo.require("esri.map");**

 **function init(){**
 **var map = new esri.Map("mapDiv", {**
 **center: [-56.049, 38.485],**
 **zoom: 3,**
 **basemap: "streets"**
 **});**
 **}**
 **dojo.ready(init);**
  </script>
```

1.  创建您将在应用程序中使用的变量。

```js
<script>
 **var map, defPopSymbol, onePopSymbol, twoPopSymbol,** threePopSymbol, fourPopSymbol, fivePopSymbol;
</script>
```

1.  添加如下突出显示的代码中所见的`require()`函数：

```js
<script>
  var map, defPopSymbol, onePopSymbol, twoPopSymbol, threePopSymbol, fourPopSymbol, fivePopSymbol;
 **require(["esri/map", "esri/tasks/query", "esri/tasks/QueryTask", "esri/symbols/SimpleFillSymbol", "esri/InfoTemplate", "dojo/domReady!"],**
 **function(Map, Query, QueryTask, SimpleFillSymbol, InfoTemplate) {** 

 **});**
</script>
```

我们在以前的练习中介绍了`esri/map`资源，因此不需要额外的解释。`esri/tasks/query`和`esri/tasks/QueryTask`资源是新的，我们将在以后的章节中介绍它们。然而，为了完成这个练习，有必要在这一点上向您介绍这些资源。这些资源使您能够在数据图层上执行空间和属性查询。

1.  在`require()`函数内部，您需要创建一个`Map`对象，并通过添加以下突出显示的代码来添加一个`basemap: streets`图层。您将设置初始地图范围以显示科罗拉多州的状态：

```js
<script>
  var map, defPopSymbol, onePopSymbol, twoPopSymbol, threePopSymbol, fourPopSymbol, fivePopSymbol;
    require(["esri/map", "esri/tasks/query", "esri/tasks/QueryTask", "esri/symbols/SimpleFillSymbol", "esri/InfoTemplate", "dojo/_base/Color", "dojo/domReady!"], 
      function(Map, Query, QueryTask, SimpleFillSymbol, InfoTemplate, Color) { 
 **map = new Map("map", {**
 **basemap: "streets",**
 **center: [-105.498,38.981], // long, lat**
 **zoom: 6,**
 **sliderStyle: "small"**
 **});**
      });
</script>
```

1.  在`require()`函数内部，在创建`Map`对象的代码块正下方，添加突出显示的代码行以创建一个新的透明多边形符号。这将创建一个新的`SimpleFillSymbol`对象并将其分配给`defPopSymbol`变量。我们使用`255,255,255,和 0`的 RGB 值来确保填充颜色完全透明。这是通过值`0`来实现的，它确保我们的着色将完全透明。稍后，我们将添加额外的符号对象，以便我们可以显示一个按县人口密度着色的地图。但现在，我们只是想创建一个符号，以便您可以理解在地图上创建和显示图形的基本过程。以下代码详细解释了这个过程：

```js
map = new Map("mapDiv", {
  basemap: "streets",
  center: [-105.498,38.981], // long, lat
  zoom: 6,
  sliderStyle: "small"
});
**defPopSymbol = new SimpleFillSymbol().setColor(new Color([255,255,255, 0])); //transparent**

```

在下一步中，您将预览`Query`任务如何在应用程序中使用。我们将在以后的章节中详细介绍这个任务，但现在，这是一个介绍。`Query`任务可用于在地图服务中的数据图层上执行空间和属性查询。在这个练习中，我们将使用`Query`任务对通过 ESRI 服务提供的县边界图层执行属性查询。

1.  让我们首先检查我们将在查询中使用的地图服务和图层。打开一个网络浏览器，转到[`sampleserver1.arcgisonline.com/ArcGIS/rest/services/Specialty/ESRI_StateCityHighway_USA/MapServer`](http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Specialty/ESRI_StateCityHighway_USA/MapServer)。该地图服务提供美国各州和县的人口普查信息，还包括一条高速公路图层。在这个练习中，我们对具有索引号为 2 的县图层感兴趣。单击**counties**选项以获取有关此图层的详细信息。该图层中有许多字段，但我们实际上只对能够按州名查询的字段和提供每个县人口密度信息的字段感兴趣。`STATE_NAME`字段提供每个县的州名，`POP90_SQMI`字段提供每个县的人口密度。

1.  返回沙盒。在创建符号的代码行的下面，通过添加以下一行代码来初始化一个新的`QueryTask`对象来创建一个新的`QueryTask`对象。这行代码的作用是创建一个指向我们在浏览器中刚刚检查的`ESRI_StateCityHighway_USA`地图服务的新`QueryTask`对象，并明确指向索引为`2`的图层，即我们的县图层。以下代码详细解释了这个过程。

```js
var queryTask = new QueryTask("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Specialty/ESRI_StateCityHighway_USA/MapServer/2");
```

1.  所有`QueryTask`对象都需要输入参数，以便它们知道要针对图层执行什么。这是通过`Query`对象实现的。在刚刚输入的行的下面添加以下一行代码：

```js
var query = new Query();
```

1.  现在，我们将定义新的`Query`对象上的一些属性，这些属性将使我们能够执行属性查询。在创建`query`变量的行的下面添加以下三行代码：

```js
var query = new Query();
**query.where = "STATE_NAME = 'Colorado'";**
**query.returnGeometry = true;**
**query.outFields = ["POP90_SQMI"];**

```

1.  `where`属性用于创建一个 SQL 语句，该语句将针对该图层执行。在这种情况下，我们声明我们只想返回那些州名为`Colorado`的县记录。将`returnGeometry`属性设置为`true`表示我们希望 ArcGIS Server 返回与我们的查询匹配的所有要素的几何定义。这是必要的，因为我们需要在地图上将这些要素绘制为图形。最后，`outFields`属性用于定义我们希望与几何一起返回的字段。稍后在创建县人口密度的色彩编码地图时将使用这些信息。

1.  最后，我们将使用`queryTask`上的`execute`方法来执行针对我们已指定的图层（counties）的查询，使用我们`query`对象上定义的参数。添加以下一行代码：

```js
queryTask.execute(query, addPolysToMap);
```

除了将`query`对象传递给 ArcGIS Server 之外，我们还指示`addPolysToMap`将作为回调函数。此函数将在 ArcGIS Server 执行查询并返回结果后执行。`addPolysToMap`函数负责使用返回给它的`featureSet`对象绘制记录。

1.  正如我在上一步中提到的，当 ArcGIS Server 返回`featureSet`对象时，回调函数`addPolysToMap`将被执行，该对象包含与我们的属性查询匹配的记录。在创建回调函数之前，让我们首先讨论代码将实现的内容。`addPolysToMap`函数将接受一个名为`featureSet`的参数。当执行`queryTask`对象时，ArcGIS Server 会将一个`featureSet`对象返回给您的代码。`featureSet`对象包含查询返回的图形对象。在`addPolysToMap`函数内部，您将看到一行`var features = featureSet.features;`。`features`属性返回一个包含其中所有图形的数组。在定义了一个新的 feature 变量之后，我们创建了一个`for`循环，用于循环遍历这些图形并将其绘制到地图上。通过添加以下代码块来创建回调函数：

```js
function addPolysToMap(featureSet) {
  var features = featureSet.features;
  var feature;
  for (var i=0, il=features.length; i<il; i++) {
    feature = features[i];
    map.graphics.add(features[i].setSymbol(defPopSymbol));
  }
}
```

正如我之前提到的，您必须将创建的每个图形添加到`GraphicsLayer`对象中。这是通过`add()`方法完成的，就像您在前面的代码块中看到的那样。您还会注意到，我们将之前创建的符号附加到每个图形（县边界）上。

1.  通过单击**运行**按钮执行代码，如果一切编码正确，您应该看到以下截图作为输出。请注意，每个县都用我们定义的符号轮廓化了。

![练习图形时间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_03_16.jpg)

现在，我们将向应用程序添加额外的代码，根据人口对每个县进行颜色编码。在`require()`函数内注释掉`defPopSymbol`变量，并添加五个新符号，如下所示：

```js
//defPopSymbol = new SimpleFillSymbol().setColor(new Color([255,255,255, 0])); //transparent
onePopSymbol = new SimpleFillSymbol().setColor(new Color([255,255,128, .85])); //yellow
twoPopSymbol = new SimpleFillSymbol().setColor(new Color([250,209,85, .85])); 
threePopSymbol = new SimpleFillSymbol().setColor(new Color([242,167,46, .85])); //orange
fourPopSymbol = new SimpleFillSymbol().setColor(new Color([173,83,19, .85])); 
fivePopSymbol = new SimpleFillSymbol().setColor(new Color([107,0,0, .85])); //dark maroon
```

我们在这里所做的基本上是创建一个基于人口密度为每个县分配符号的颜色渐变。我们还对每个符号应用了透明度值为 0.85，以便我们能够透过每个县。这将使我们能够看到放置在包含城市名称的图层下面的底图。

回想一下，在之前的练习中，我们创建了`queryTask`和`Query`对象，并在`Query`上定义了一个`outFields`属性，以返回`POP90_SQMI`字段。现在，我们将使用在该字段中返回的值来确定应用于每个县的符号，该符号基于该县的人口密度。更新`addPolysToMap`函数，使其出现在以下代码块中，然后我们将讨论我们所做的事情：

```js
function addPolysToMap(featureSet) {
  var features = featureSet.features;
  var feature;
  for (var i=0, il=features.length; i<il; i++) {
    feature = features[i];
    attributes = feature.attributes;
    pop = attributes.POP90_SQMI;

    if (pop < 10)
    {
                            map.graphics.add(features[i].setSymbol(onePopSymbol));
    }
    else if (pop >= 10 && pop < 95)
   {                      map.graphics.add(features[i].setSymbol(twoPopSymbol));
   }
   else if (pop >= 95 && pop < 365)
   {                  map.graphics.add(features[i].setSymbol(threePopSymbol));
   }
   else if (pop >= 365 && pop < 1100)
   {                map.graphics.add(features[i].setSymbol(fourPopSymbol));
   }
   else
   {                map.graphics.add(features[i].setSymbol(fivePopSymbol));
   }
  }
}
```

在前面的代码块中，我们所做的是从每个图形中获取人口密度信息，并将其保存到名为`pop`的变量中。然后使用`if/else`代码块根据该县的人口密度为图形分配符号。例如，具有人口密度（如`POP90_SQMI`字段中定义的）为`400`的县将被分配为由`fourPopSymbol`定义的符号。因为我们在一个`for`循环中检查科罗拉多州的每个县，所以每个县图形都将被分配一个符号。

通过单击**运行**按钮执行代码，如果一切编码正确，您应该看到以下截图作为输出。请注意，每个县都已根据我们之前定义的符号进行了颜色编码。

![练习图形时间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_03_17.jpg)

现在，您将学习如何将属性附加到图形，并在单击图形时在信息窗口中显示它们。

信息窗口是在单击图形时显示的 HTML 弹出窗口。通常，它包含单击图形的属性，但也可以包含您作为开发人员指定的自定义内容。这些窗口的内容是通过指定窗口标题和要在窗口中显示的内容的`InfoTemplate`对象指定的。创建`InfoTemplate`对象的最简单方法是使用通配符，该通配符将自动将数据集的所有字段插入到信息窗口中。我们将添加一些额外的输出字段，以便在信息窗口中显示更多内容。修改`query.outFields`行，以包括以下代码行中突出显示的字段：

```js
query.outFields = ["**NAME**","POP90_SQMI","**HOUSEHOLDS**","**MALES**","**FEMALES**","**WHITE**","**BLACK**","**HISPANIC**"];
```

然后，在`queryTask.execute`行的下面添加以下代码行：

```js
resultTemplate = InfoTemplate("County Attributes", "${*}");
```

传递给构造函数的第一个参数（`"County Attributes"`）是窗口的标题。第二个参数是一个通配符，表示应在窗口中打印属性的所有名称-值对。因此，我们添加到`query.outFields`的新字段应全部包含在单击图形时的信息窗口中。

最后，我们使用`Graphic.setInfoTemplate()`方法将新创建的`InfoTemplate`对象分配给图形。通过添加以下突出显示的代码来修改您的`if/else`语句：

```js
if (pop < 10)
{
                        map.graphics.add(features[i].setSymbol(onePopSymbol).**setInfoTemplate(resultTemplate)**);
}
else if (pop >= 10 && pop < 95)
{
                        map.graphics.add(features[i].setSymbol(twoPopSymbol).**setInfoTemplate(resultTemplate)**);
}
else if (pop >= 95 && pop < 365)
{
                        map.graphics.add(features[i].setSymbol(threePopSymbol).**setInfoTemplate(resultTemplate)**);
}
else if (pop >= 365 && pop < 1100)
{
                        map.graphics.add(features[i].setSymbol(fourPopSymbol).**setInfoTemplate(resultTemplate)**);
}
else
{
                        map.graphics.add(features[i].setSymbol(fivePopSymbol).**setInfoTemplate(resultTemplate)**);
}
```

通过单击**运行**按钮执行代码。单击地图中的任何县，您应该看到类似以下屏幕截图的信息窗口：

![练习图形](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_03_18.jpg)

您可以在`ArcGISJavaScriptAPI`文件夹的`graphicexercise.html`文件中查看此练习的解决方案代码，以验证您的代码是否已正确编写。

# 摘要

在本章中，您了解到图形通常用于表示作为工作应用程序内执行操作的结果生成的信息。通常，这些图形是作为已执行的任务的结果返回的，例如属性或空间查询。这可以包括点、线、多边形和文本。这些都是临时对象，仅在当前浏览器会话期间显示。每个图形可以由几何、符号、属性和信息模板组成，并通过图形图层添加到地图中，该图层始终是应用程序中最顶层的图层。这确保了图层的内容始终可见。在下一章中，我们将向您介绍要素图层，它可以执行图形图层可以执行的所有操作以及更多！


# 第四章：要素图层

ArcGIS API for JavaScript 提供了一个用于处理客户端图形要素的要素图层。这个`FeatureLayer`对象继承自`GraphicsLayer`对象，但也提供了额外的功能，比如执行查询和选择，以及支持定义表达式。它也可以用于 Web 编辑。您应该已经熟悉了之前章节中的图形图层。

要素图层与瓦片和动态地图服务图层不同，它将要素的几何信息从 ArcGIS Server 传输到 Web 浏览器，然后在地图上绘制。它还可以用于表示来自非空间表的数据，以及包含几何的要素类。

从 ArcGIS Server 流式传输数据到浏览器可能会减少与服务器的往返次数，并提高应用程序的性能。客户端可以请求其需要的要素，并对这些要素执行选择和查询，而无需从服务器请求更多信息。`FeatureLayer`对象特别适用于响应用户交互的图层，如鼠标点击或悬停。这样做的折衷是，如果您使用包含大量要素的要素图层，最初将要素传输到客户端可能需要很长时间。要素图层支持几种显示模式，可以帮助减轻处理大量要素的负担。我们将在本章中研究每种显示模式。

要素图层遵守地图服务中图层上配置的任何定义表达式、比例依赖和其他属性。使用要素图层，您可以访问相关表，执行查询，显示时间切片，处理要素附件，以及执行其他有用的操作。

![要素图层](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_04_07.jpg)

在本章中，我们将涵盖以下主题：

+   创建 FeatureLayer 对象

+   定义显示模式

+   设置定义表达式

+   要素选择

+   渲染要素图层

+   练习使用 FeatureLayer

# 创建 FeatureLayer 对象

要素图层必须引用地图服务或要素服务中的图层。如果您只想从服务器检索几何和属性并自行符号化，可以使用地图服务。如果您想要从服务的源地图文档中受益于符号，则使用要素服务。此外，如果您计划使用要素图层进行编辑，则使用要素服务。要素图层遵守源地图文档中配置的任何要素编辑模板。

在下面的代码示例中，您将了解如何使用其构造函数创建`FeatureLayer`对象的详细信息。对于瓦片和动态图层，您只需提供指向 rest 端点的指针，但对于要素图层，您需要指向服务中的特定图层。在下面的代码示例中，我们将从服务中的第一个图层创建一个`FeatureLayer`对象，该图层由数字`0`表示。`FeatureLayer`的构造函数还接受选项，如显示模式、输出字段和信息模板。在这里，显示模式设置为`SNAPSHOT`，这可能表示我们正在处理一个相当小的数据集。我们将在下一节中讨论可以为要素图层定义的各种显示模式以及何时应该使用它们：

```js
var earthquakes = new FeatureLayer("http://servicesbeta.esri.com/ArcGIS/rest/services/Earthquakes/Since_1970/MapServer/0",{ mode: FeatureLayer.MODE_SNAPSHOT, outFields: ["Magnitude"]});
```

## 可选的构造函数参数

除了将地图或要素服务中的必需图层作为第一个参数传递给`FeatureLayer`对象之外，还可以将定义各种选项的 JSON 对象传递给构造函数。可以传递各种各样的选项给构造函数。我将讨论最常用的选项。

`outFields`属性可用于限制与`FeatureLayer`对象一起返回的字段。出于性能原因，最好只包括应用程序所需的字段，而不是接受默认的返回所有字段。只返回绝对需要的字段，这将确保应用程序的性能更好。在以下突出显示的代码中，我们已经定义了`outFields`属性，只返回`Date`和`Magnitude`字段：

```js
var earthquakes = new FeatureLayer("http://servicesbeta.esri.com/ArcGIS/rest/services/Earthquakes/Since_1970/MapServer/0",{ mode: FeatureLayer.MODE_SNAPSHOT, **outFields: ["Date", "Magnitude"]**});
```

`refreshInterval`属性定义了刷新图层的频率（以分钟为单位）。当您有包含经常更改的数据的`FeatureLayer`对象时，包括新记录，或者可能已更新或删除的记录时，可以使用此属性。以下突出显示的代码设置了 5 分钟的刷新间隔：

```js
var earthquakes = new FeatureLayer("http://servicesbeta.esri.com/ArcGIS/rest/services/Earthquakes/Since_1970/MapServer/0",{ mode: FeatureLayer.MODE_SNAPSHOT, outFields: ["Magnitude"], **refreshInterval: 5**});
```

要定义在单击要素时应在信息窗口中显示的属性和样式，您可以设置`infoTemplate`属性，如下面的代码示例所示：

```js
function initOperationalLayer**() {var infoTemplate = new InfoTemplate("${state_name}", "Population (2000):  ${pop2000:NumberFormat}")**;
  var featureLayer = new FeatureLayer("http://sampleserver6.arcgisonline.com/arcgis/rest/services/USA/MapServer/2",{mode: FeatureLayer.MODE_ONDEMAND,outFields: ["*"], **infoTemplate: infoTemplate**});

   map.addLayer(featureLayer);
   map.infoWindow.resize(155,75);
 **}**

```

如果您知道 Internet Explorer 将是应用程序的主要浏览器，您可能希望将`displayOnPan`属性设置为`false`。默认情况下，此属性设置为`true`，但将其设置为`false`将在平移操作期间关闭图形，从而提高 Internet Explorer 上应用程序的性能。以下代码块详细解释了这个过程：

```js
var earthquakes = new FeatureLayer("http://servicesbeta.esri.com/ArcGIS/rest/services/Earthquakes/Since_1970/MapServer/0",{ mode: FeatureLayer.MODE_SNAPSHOT, outFields: ["Magnitude"], **displayOnPan: false}**);
```

显示模式，由`mode`参数定义，可能是最重要的可选参数。因此，我们将在接下来的几节中更详细地介绍这个内容。

# 定义显示模式

创建要素图层时，您需要指定检索要素的模式。因为模式决定了何时以及如何将要素从服务器传输到客户端，您的选择会影响应用程序的速度和外观。您可以在以下图表中看到模式选择：

![定义显示模式](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_04_01.jpg)

## 快照模式

快照模式检索图层中的所有要素，并将它们流式传输到客户端浏览器，然后将它们添加到地图中。因此，在使用此模式之前，您需要仔细考虑图层的大小。通常情况下，您只会在处理小型数据集时使用此模式。快照模式下的大型数据集可能会显著降低应用程序的性能。快照模式的好处是，由于从图层返回了所有要素到客户端，因此无需返回服务器以获取额外数据。这提高了应用程序性能的潜力。

ArcGIS 对一次最多返回的要素数量施加了限制，尽管这个数字可以通过 ArcGIS Server 管理进行配置。在实际操作中，您只会在处理小型数据集时使用此模式：

```js
var earthquakes = new FeatureLayer("http://servicesbeta.esri.com/ArcGIS/rest/services/Earthquakes/Since_1970/MapServer/0",{ **mode: FeatureLayer.MODE_SNAPSHOT**, outFields: ["Magnitude"]});
```

## 按需模式

按需模式仅在需要时检索要素。这意味着当前视图范围内的所有要素都会被返回。因此，每次进行缩放或平移操作时，要素都会从服务器流式传输到客户端。这在大型数据集中效果很好，因为在快照模式下效率不高。这确实需要往返服务器以获取每次地图范围变化时的要素，但对于大型数据集来说，这是可取的。以下代码示例向您展示了如何将`FeatureLayer`对象设置为`ONDEMAND`模式：

```js
var earthquakes = new FeatureLayer("http://servicesbeta.esri.com/ArcGIS/rest/services/Earthquakes/Since_1970/MapServer/0",{ **mode: FeatureLayer.MODE_ONDEMAND**, outFields: ["Magnitude"]});
```

## 仅选择模式

仅选择模式不会最初请求要素。相反，只有在客户端进行选择时才返回要素。所选要素会从服务器流式传输到客户端，然后在客户端上保存。以下代码示例向您展示了如何将`FeatureLayer`对象设置为`SELECTION`模式：

```js
var earthquakes = new FeatureLayer("http://servicesbeta.esri.com/ArcGIS/rest/services/Earthquakes/Since_1970/MapServer/0",{ **mode: FeatureLayer.MODE_SELECTION**, outFields: ["Magnitude"]});
```

# 设置定义表达式

定义表达式用于限制流向客户端的要素，仅限于符合属性约束的要素。`FeatureLayer`包含一个`setDefinitionExpression()`方法，用于创建定义表达式。满足指定条件的所有要素将返回以在地图上显示。表达式是使用传统的 SQL 表达式构建的，如以下代码示例所示：

```js
FeatureLayer.setDefinitionExpression("PROD_GAS='Yes'");
```

您可以使用`FeatureLayer.getDefinitionExpression()`方法检索当前设置的定义表达式，该方法返回包含表达式的字符串。

# 要素选择

要素图层还支持要素选择，这只是图层中用于查看、编辑、分析或输入到其他操作的要素子集。使用空间或属性条件将要素添加到选择集或从选择集中删除，并且可以轻松地用不同于图层正常显示中使用的符号绘制。`FeatureLayer`上的`selectFeatures(query)`方法用于创建选择集，并以`Query`对象作为输入。这在以下代码示例中已经解释过了：

```js
var selectQuery = new Query();
selectQuery.geometry = geometry;
**featureLayer.selectFeatures(selectQuery,FeatureLayer.SELECTION_NEW);**

```

我们还没有讨论`Query`对象，但是您可以想象，它用于定义属性或空间查询的输入参数。在此特定代码示例中，已定义了空间查询。

以下屏幕截图显示了已选择的要素。已将选择符号应用于所选要素：

![要素选择](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_04_5.jpg)

在图层上设置的任何定义表达式，无论是通过应用程序还是在地图文档文件内的图层上设置，都将受到尊重。设置用于所选要素的符号非常简单，只需创建一个符号，然后在 FeatureLayer 上使用`setSelectionSymbol()`方法。所选要素将自动分配此符号。您可以选择定义新的选择集，将要素添加到现有选择集，或从选择集中删除要素，通过各种常量，包括`SELECTION_NEW`，`SELECTION_ADD`和`SELECTION_SUBTRACT`。新的选择集在以下代码示例中定义：

```js
featureLayer.selectFeatures(selectQuery,**FeatureLayer.SELECTION_NEW**);
```

此外，您可以定义回调和错误处理函数来处理返回的要素或处理任何错误。

# 渲染要素图层

渲染器可用于为要素图层或图形图层定义一组符号。这些符号可以基于属性具有不同的颜色和/或大小。ArcGIS Server API for JavaScript 中的五种渲染器类型包括`SimpleRenderer`，`ClassBreaksRenderer`，`UniqueValueRenderer`，`DotDensityRenderer`和`TemporalRenderer`。我们将在本节中检查每个渲染器。

无论您使用何种类型的渲染器，渲染过程都将是相同的。您首先需要创建渲染器的实例，为渲染器定义符号，最后将渲染器应用于要素图层。此渲染过程已在以下图表中说明：

![渲染要素图层](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_04_06.jpg)

以下代码示例显示了创建和应用渲染器到`FeatureLayer`对象的基本编程结构：

```js
var renderer = new ClassBreaksRenderer(symbol, "POPSQMI");
renderer.addBreak(0, 5, new SimpleFillSymbol().setColor(new Color([255, 0, 0, 0.5])));
renderer.addBreak(5.01, 10, new SimpleFillSymbol().setColor(new Color([255, 255, 0, 0.5])));
renderer.addBreak(10.01, 25, new SimpleFillSymbol().setColor(new Color([0, 255, 0, 0.5])));
renderer.addBreak(25.01, Infinity, new SimpleFillSymbol().setColor(new Color([255, 128, 0, 0.5])));
featureLayer.setRenderer(renderer);
```

最简单的渲染器类型是`SimpleRenderer`，它只是为所有图形应用相同的符号。

`UniqueValueRenderer`可用于根据通常包含字符串数据的匹配属性对图形进行符号化。

![渲染要素图层](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_04_08.jpg)

例如，如果您有一个州要素类，您可能希望根据区域名称对每个要素进行符号化。每个区域都将有不同的符号。以下代码示例显示了如何以编程方式创建`UniqueValueRenderer`并向结构添加值和符号：

```js
var renderer = new UniqueValueRenderer(defaultSymbol, "REGIONNAME");
renderer.addValue("West", new SimpleLineSymbol().setColor(new Color([255, 255, 0, 0.5])));
renderer.addValue("South", new SimpleLineSymbol().setColor(new Color([128, 0, 128, 0.5])));
renderer.addValue("Mountain", new SimpleLineSymbol().setColor(new Color([255, 0, 0, 0.5])));
```

`ClassBreaksRenderer`用于处理存储为数值属性的数据。每个图形将根据该特定属性的值以及数据中的断点进行符号化。在下面的屏幕截图中，您可以看到已应用于堪萨斯县级数据的`ClassBreaksRenderer`的示例：

![Rendering a feature layer](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_04_09.jpg)

断点定义了符号将发生变化的值。例如，对于包裹要素类，您可能希望根据`PROPERTYVALUE`字段中的值对包裹进行符号化。您首先需要创建`ClassBreaksRenderer`的新实例，然后为数据定义断点。如果需要，可以使用`Infinity`和`-Infinity`值作为数据的下限和上限边界，如下面的代码示例所示，我们在这里使用`Infinity`关键字来表示大于 250,000 的任何值的类断点：

```js
var renderer = new ClassBreaksRenderer(symbol, "PROPERTYVALUE");
renderer.addBreak(0, 50000, new SimpleFillSymbol().setColor(new Color([255, 0, 0, 0.5])));
renderer.addBreak(50001, 100000, new SimpleFillSymbol().setColor(new Color([255, 255, 0, 0.5])));
renderer.addBreak(100001, 250000, 50000, new SimpleFillSymbol().setColor(new Color([0, 255, 0, 0.5])));
renderer.addBreak(250001, Infinity, new SimpleFillSymbol().setColor(new Color([255, 128, 0, 0.5])));
```

`TemporalRenderer`提供了基于时间的要素渲染。这种类型的渲染器通常用于显示历史信息或近实时数据。它允许您定义如何渲染观测和轨迹。

以下代码示例解释了如何使用`ClassBreaksRenderer`创建`TemporalRenderer`并将其应用于`featureLayer`对象。`ClassBreaksRenderer`用于按大小定义符号；大小越大，符号越大：

```js
// temporal renderer
var observationRenderer = new ClassBreaksRenderer(new SimpleMarkerSymbol(), "magnitude");

observationRenderer.addBreak(7, 12, new SimpleMarkerSymbol(SimpleMarkerSymbol.STYLE_SQUARE, 24, new SimpleLineSymbol().setStyle(SimpleLineSymbol.STYLE_SOLID).setColor(new Color([100,100,100])),new Color([0,0,0,0])));

observationRenderer.addBreak(6, 7, new SimpleMarkerSymbol(SimpleMarkerSymbol.STYLE_SQUARE, 21, new SimpleLineSymbol().setStyle(SimpleLineSymbol.STYLE_SOLID).setColor(new Color([100,100,100])),new Color([0,0,0,0])));

observationRenderer.addBreak(5, 6, new SimpleMarkerSymbol(SimpleMarkerSymbol.STYLE_SQUARE, 18,new SimpleLineSymbol().setStyle(SimpleLineSymbol.STYLE_SOLID).setColor(new Color([100,100,100])),new Color([0,0,0,0])));

observationRenderer.addBreak(4, 5, new SimpleMarkerSymbol(SimpleMarkerSymbol.STYLE_SQUARE, 15,new SimpleLineSymbol().setStyle(SimpleLineSymbol.STYLE_SOLID).setColor(new Color([100,100,100])),new Color([0,0,0,0])));

observationRenderer.addBreak(3, 4, new SimpleMarkerSymbol(SimpleMarkerSymbol.STYLE_SQUARE, 12,new SimpleLineSymbol().setStyle(SimpleLineSymbol.STYLE_SOLID).setColor(new Color([100,100,100])),new Color([0,0,0,0])));

observationRenderer.addBreak(2, 3, new SimpleMarkerSymbol(SimpleMarkerSymbol.STYLE_SQUARE, 9,new SimpleLineSymbol().setStyle(SimpleLineSymbol.STYLE_SOLID).setColor(new Color([100,100,100])),new Color([0,0,0,0])));

observationRenderer.addBreak(0, 2, new SimpleMarkerSymbol(SimpleMarkerSymbol.STYLE_SQUARE, 6,new SimpleLineSymbol().setStyle(SimpleLineSymbol.STYLE_SOLID).setColor(new Color([100,100,100])),new Color([0,0,0,0])));

var infos = [{ minAge: 0, maxAge: 1, color: new Color([255,0,0])},{ minAge: 1, maxAge: 24, color: new Color([49,154,255])},{ minAge: 24, maxAge: Infinity, color: new Color([255,255,8])}];

var ager = new TimeClassBreaksAger(infos, TimeClassBreaksAger.UNIT_HOURS);
var renderer = new TemporalRenderer(observationRenderer, null, null, ager);
featureLayer.setRenderer(renderer);
```

这里定义了一个`ager`符号，它确定随着时间的推移特征符号的变化。

我们将讨论的最后一种渲染器是`DotDensityRenderer`。以下屏幕截图显示了使用`DotDensityRenderer`创建的地图：

![Rendering a feature layer](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_04_10.jpg)

这种类型的渲染器使您能够创建数据的点密度可视化，显示离散空间现象的空间密度，如人口密度。

以下代码示例解释了基于`pop`字段创建`DotDensityRenderer`，并定义了`dotValue`为 1000 和`dotSize`等于 2。这将为 1000 人口创建每两个像素大小的一个点：

```js
var dotDensityRenderer = new DotDensityRenderer({fields: [{name: "pop",color: new Color([52, 114, 53])}],dotValue: 1000,dotSize: 2});

layer.setRenderer(dotDensityRenderer);
```

# 练习使用 FeatureLayer

在这个练习中，您将使用`FeatureLayer`对象在图层上设置定义表达式，将匹配定义表达式的要素绘制为图形，并响应要素上的悬停事件。

执行以下步骤完成练习：

1.  在[`developers.arcgis.com/en/javascript/sandbox/sandbox.html`](http://developers.arcgis.com/en/javascript/sandbox/sandbox.html)中打开 JavaScript 沙箱。

1.  从我在下面的代码块中突出显示的`<script>`标签中删除 JavaScript 内容：

```js
  <script>
 **dojo.require("esri.map");**

**functioninit(){**
**var map = new esri.Map("mapDiv", {**
 **center: [-56.049, 38.485],**
 **zoom: 3,**
 **basemap: "streets"**
 **});**
 **}**
 **dojo.ready(init);**
  </script>
```

1.  在`<script>`标签内创建应用程序中将使用的变量：

```js
<script>
 **var map;**
</script>
```

1.  创建`require()`函数，定义在此应用程序中将使用的资源：

```js
<script type="text/javascript" language="Javascript">
  var map;
 **require(["esri/map", "esri/layers/FeatureLayer",    "esri/symbols/SimpleFillSymbol",** 
**"esri/symbols/SimpleLineSymbol", "esri/renderers/SimpleRenderer", "esri/InfoTemplate", "esri/graphic", "dojo/on",** 
**"dojo/_base/Color", "dojo/domReady!"],** 
 **function(Map,FeatureLayer, SimpleFillSymbol,** 
 **SimpleLineSymbol, SimpleRenderer, InfoTemplate,  Graphic, on, Color) {**

 **});**

</script>
```

1.  在您的网络浏览器中，导航到[`sampleserver1.arcgisonline.com/ArcGIS/rest/services/Demographics/ESRI_Census_USA/MapServer/5`](http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Demographics/ESRI_Census_USA/MapServer/5)。

我们将在此练习中使用`states`图层。我们要做的是对`states`图层应用定义表达式，只显示那些具有中位年龄大于`36`的州。这些州将显示为地图上的图形，并在用户将鼠标悬停在满足定义表达式的州上时，将显示包含该州的中位年龄、男性中位年龄和女性中位年龄的信息窗口。此外，该州将用红色轮廓显示。我们将从`states`图层中使用的字段包括`STATE_NAME`、`MED_AGE`、`MED_AGE_M`和`MED_AGE_F`。

1.  创建`Map`对象如下代码示例所示：

```js
<script type="text/javascript" language="Javascript">
              var map;
        require(["esri/map", "esri/layers/FeatureLayer",  "esri/symbols/SimpleFillSymbol", 
             "esri/symbols/SimpleLineSymbol", "esri/renderers/SimpleRenderer", "esri/InfoTemplate", "esri/graphic", "dojo/on", 
             "dojo/_base/Color", "dojo/domReady!"], 
          function(Map,FeatureLayer, SimpleFillSymbol, 
                  SimpleLineSymbol, SimpleRenderer, InfoTemplate, Graphic, on, Color) {
 **map = new Map("mapDiv", {**
 **basemap: "streets",**
 **center: [-96.095,39.726], // long, lat**
 **zoom: 4,**
 **sliderStyle: "small"**
 **});** 

            });

    </script>
```

1.  添加一个`map.load`事件，触发创建`map.graphics.mouse-out`事件，清除任何现有的图形和信息窗口。以下代码示例详细解释了这一点：

```js
map = new Map("map", {
     basemap: "streets",
     center: [-96.095,39.726], // long, lat
     zoom: 4,
     sliderStyle: "small"
});

 **map.on("load", function() {**
 **map.graphics.on("mouse-out", function(evt) {**
 **map.graphics.clear();**
 **map.infoWindow.hide();**
 **});**
 **});**

```

1.  创建一个指向您之前检查过的`states`图层的新`FeatureLayer`对象。您还将指定使用`SNAPSHOT`模式返回要素，定义输出字段，并设置定义表达式。为此，将以下代码添加到您的应用程序中：

```js
map.on("load", function() {
  map.graphics.on("mouse-out", function(evt) {
    map.graphics.clear();
    map.infoWindow.hide();
  });
}); 

**var olderStates = new FeatureLayer("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Demographics/ESRI_Census_USA/MapServer/5", {**
 **mode: FeatureLayer.MODE_SNAPSHOT,**
 **outFields: ["STATE_NAME", "MED_AGE", "MED_AGE_M", "MED_AGE_F"]**
**});**
**olderStates.setDefinitionExpression("MED_AGE > 36");**

```

在这里，我们使用`new`关键字定义了一个指向代码中指定的`rest`端点上的`states`图层的新`FeatureLayer`实例。在定义`FeatureLayer`的新实例时，我们包括了一些属性，包括`mode`和`outFields`。mode 属性可以设置为`SNAPSHOT`、`ONDEMAND`或`SELECTION`。由于`states`图层包含相对较少的要素，我们可以在这种情况下使用`SNAPSHOT`模式。这种模式在将图层添加到地图时检索图层中的所有要素，因此不需要额外的服务器访问来检索图层中的其他要素。我们还指定了`outFields`属性，这是一个将被返回的字段数组。当用户悬停在州上时，我们将显示这些字段在信息窗口中。最后，我们在图层上设置了我们的定义表达式，只显示那些中位年龄大于`36`的要素（州）。

1.  在这一步中，您将创建一个符号并将渲染器应用到从定义表达式返回的要素（州）上。您还将将`FeatureLayer`添加到地图中。将以下代码添加到您在上一步中添加的代码的下方：

```js
var olderStates = new FeatureLayer("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Demographics/ESRI_Census_USA/MapServer/5", {
  mode: FeatureLayer.MODE_SNAPSHOT,
  outFields: ["STATE_NAME", "MED_AGE", "MED_AGE_M", "MED_AGE_F"]
 });
 olderStates.setDefinitionExpression("MED_AGE > 36");

**var symbol = new SimpleFillSymbol(SimpleFillSymbol.STYLE_SOLID, new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([255,255,255,0.35]), 1),new Color([125,125,125,0.35]));**
 **olderStates.setRenderer(new SimpleRenderer(symbol));**
**map.addLayer(olderStates);**

```

1.  使用您之前定义的输出字段，创建一个`InfoTemplate`对象。将以下代码添加到您在上一步中添加的代码的下方。注意嵌在括号内并以美元符号开头的输出字段的包含：

```js
var infoTemplate = new InfoTemplate();
infoTemplate.setTitle("${STATE_NAME}");
infoTemplate.setContent("<b>Median Age: </b>${MED_AGE_M}<br/>"
  + "<b>Median Age - Male: </b>${MED_AGE_M}<br/>"
  + "<b>Median Age - Female: </b>${MED_AGE_F}");
map.infoWindow.resize(245,125);
```

1.  然后，添加以下代码以创建一个图形，当用户将鼠标悬停在一个州上时将显示该图形：

```js
var highlightSymbol = new SimpleFillSymbol(SimpleFillSymbol.STYLE_SOLID, 
new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID,
  new Color([255,0,0]), new Color([125,125,125,0.35])));
```

1.  最后一步是显示我们在前面步骤中创建的高亮符号和信息模板。每当用户将鼠标悬停在一个州上时，就会发生这种情况。在您之前输入的代码的最后一行下面添加以下代码块。在这里，我们使用`on()`将事件（鼠标悬停）与一个函数连接起来，每次事件发生时都会做出响应。在这种情况下，`mouse-over`事件处理程序将清除`GraphicsLayer`对象中的任何现有图形，创建您在上一步中创建的信息模板，创建高亮符号并将其添加到`GraphicsLayer`，然后显示`InfoWindow`对象。这在以下代码块中已经解释过了：

```js
olderStates.on("mouse-over", function(evt) {
  map.graphics.clear();
  evt.graphic.setInfoTemplate(infoTemplate);
  var content = evt.graphic.getContent();
  map.infoWindow.setContent(content);
  var title = evt.graphic.getTitle();
  map.infoWindow.setTitle(title);
  var highlightGraphic = new  Graphic(evt.graphic.geometry,highlightSymbol);
  map.graphics.add(highlightGraphic);
  map.infoWindow.show(evt.screenPoint,map.getInfoWindowAnchor(evt.screenPoint));
});
```

您可能希望查看解决方案文件（`featurelayer.html`）中的`ArcGISJavaScriptAPI`文件夹，以验证您的代码是否已正确编写。

单击**运行**按钮执行代码，如果一切编码正确，您应该看到以下输出。您应该看到一个类似以下截图的地图。将鼠标悬停在其中一个高亮显示的州上，就会看到一个信息窗口，如下截图所示：

![使用 FeatureLayer 进行练习的时间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_04_11.jpg)

# 摘要

ArcGIS Server 的 JavaScript API 提供了一个`FeatureLayer`对象，用于处理客户端图形要素。这个对象继承自图形图层，但也提供了额外的功能，比如执行查询和选择以及支持定义表达式。特征图层还可以用于 Web 编辑。它与瓦片和动态地图服务图层不同，因为特征图层将几何信息传输到客户端计算机，由 Web 浏览器绘制。这可能会减少与服务器之间的往返次数，并且可以提高服务器端应用程序的性能。客户端可以请求所需的要素，并对这些要素执行选择和查询，而无需从服务器请求更多信息。`FeatureLayer`对象特别适用于响应用户交互的图层，如鼠标点击或悬停。


# 第五章：使用小部件和工具栏

作为 GIS Web 应用程序开发人员，您希望专注于构建特定于您正在构建的应用程序的功能。花费宝贵的时间和精力添加基本的 GIS 功能，如缩放和平移到您的应用程序中，会分散您的主要关注点。许多应用程序还需要添加概览地图、图例或比例尺到用户界面中。幸运的是，API 提供了用户界面小部件，您可以直接将其放入您的应用程序中，并进行一些配置，它们就可以使用了。

ArcGIS API for JavaScript 还包括辅助类，用于向您的应用程序添加导航和绘图工具栏。在本章中，您将学习如何将这些用户界面组件轻松添加到应用程序中。

让我们首先来看一下 Esri 在其资源中心网站上放置的一个导航示例。打开一个 Web 浏览器，转到[`developers.arcgis.com/en/javascript/samples/toolbar_draw/`](http://developers.arcgis.com/en/javascript/samples/toolbar_draw/)。看一下以下的屏幕截图：

![使用小部件和工具栏](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_01.jpg)

首先浏览前面的屏幕截图，您可能会认为绘图工具栏只是一个您可以放入应用程序中的用户界面组件，但实际情况并非如此。ArcGIS API for JavaScript 提供了一个名为`esri/toolbars/Draw`的工具栏辅助类，以帮助完成此任务。此外，API 还提供了一个处理导航任务的类。这些辅助类的作用是为您节省绘制缩放框、捕获鼠标点击和其他用户发起的事件的工作。任何有经验的 GIS Web 开发人员都会告诉您，这并不是一件小事。将这些基本导航功能添加到 API 提供的辅助类中可以轻松节省数小时的开发工作。

在这一章中，我们将涵盖以下主题：

+   将工具栏添加到应用程序中

+   用户界面小部件

+   要素编辑

# 将工具栏添加到应用程序中

使用辅助类`Navigation`和`Draw`，API 提供了两种基本类型的工具栏，您可以将其添加到应用程序中。还有一个编辑工具栏，可用于通过 Web 浏览器编辑要素或图形。我们将在后面的章节中讨论这个工具栏。

## 创建工具栏的步骤

**Navigation**和**Draw**工具栏不仅仅是您可以放入应用程序中的用户界面组件。它们是辅助类，您需要采取几个步骤才能实际创建具有适当按钮的工具栏。对于工具栏的待办事项清单可能看起来有点令人生畏，但做一两次后，它就变得非常简单。以下是执行此操作的步骤，我们将详细讨论每一项：

1.  为每个按钮定义 CSS 样式。

1.  在工具栏内创建按钮。

1.  创建`esri/toolbars/Navigation`或`esri/toolbars/Draw`的实例。

1.  将按钮事件连接到处理程序函数。

### 定义 CSS 样式

您需要做的第一件事是为您打算在工具栏上包含的每个按钮定义 CSS 样式。工具栏上的每个按钮都需要一个图像、文本或两者，以及按钮的宽度和高度。这些属性都在 CSS 中定义在`<style>`标签内，如下面的代码片段所示。在下面的代码示例中，为`Navigation`工具栏定义了许多按钮。让我们来看一下**缩小**按钮，并跟随整个过程，以使事情变得更简单一些。我在下面的代码中突出显示了**缩小**按钮。与所有其他按钮一样，我们定义了一个用于按钮的图像（`nav_zoomout.png`），以及按钮的宽度和高度。此外，此样式的标识符被定义为`.zoomoutIcon`。

```js
<style type="text/css">
  @import"http://js.arcgis.com/3.7/js/dojo/dijit/themes/claro/claro.css";
    .zoominIcon{ background-image:url(images/nav_zoomin.png);width:16px; height:16px; }
 **.zoomoutIcon{ background-image:url(images/nav_zoomout.png);width:16px; height:16px; }**
    .zoomfullextIcon{ background-image:url(images/nav_fullextent.png); width:16px;height:16px; }
    .zoomprevIcon{ background-image:url(images/nav_previous.png); width:16px;height:16px; }
    .zoomnextIcon{ background-image:url(images/nav_next.png);width:16px; height:16px; }
    .panIcon{ background-image:url(images/nav_pan.png);width:16px; height:16px; }
    .deactivateIcon{ background-image:url(images/nav_decline.png); width:16px;height:16px; }
</style>
```

## 创建按钮

按钮可以在`<div>`容器内定义，该容器具有`BorderContainer`的`data-dojo-type`为`ContentPane` dijit，如下面的代码示例所示。在创建每个按钮时，你需要定义它应该引用的 CSS 样式以及按钮被点击时应该发生什么。按钮使用`iconClass`属性来引用 CSS 样式。在我们的示例中，**缩小**按钮的`iconClass`属性引用了我们之前定义的`zoomoutIcon`样式。`zoomoutIcon`样式定义了要用于按钮的图像以及按钮的宽度和高度。看一下下面的代码片段：

```js
<div id="mainWindow" data-dojo-type="dijit/layout/BorderContainer"data-dojo-props="design:'headline'">
  <div id="header"data-dojo-type="dijit/layout/ContentPane"data-dojo-props="region:'top'">
    <button data-dojo-type="dijit/form/Button"iconClass="zoominIcon">Zoom In</button>
 **<button data-dojo-type="dijit/form/Button"iconClass="zoomoutIcon" >Zoom Out</button>**
    <button data-dojo-type="dijit/form/Button"iconClass="zoomfullextIcon" >Full Extent</button>
    <button data-dojo-type ="dijit/form/Button"iconClass="zoomprevIcon" >Prev Extent</button>
    <button data-dojo-type="dijit/form/Button"iconClass="zoomnextIcon" >Next Extent</button>
    <button data-dojo-type="dijit/form/Button"iconClass="panIcon">Pan</button>
    <button data-dojo-type="dijit/form/Button"iconClass="deactivateIcon" >Deactivate</button>
  </div>
</div>
```

前面的代码块定义了工具栏上的按钮。每个按钮都是使用 Dijit（Dojo 的一个子项目）提供的`Button`用户界面控件创建的。每个控件都包含在网页的`<body>`标签内的`<button>`标签中，所有按钮都被包含在包含`ContentPane` dijit 的`<div>`标签中。

## 创建`Navigation`工具栏的实例

现在按钮的视觉界面已经完成，我们需要创建一个`esri/toolbars/Navigation`的实例，并连接事件和事件处理程序。创建`Navigation`类的实例就像调用构造函数并传入对`Map`的引用一样简单，很快你就会看到。但是，首先要确保添加对`esri/toolbars/navigation`的引用。以下代码示例添加了对`Navigation`工具栏的引用，创建了工具栏，将点击事件连接到按钮，并激活了工具。相关的代码行已经被突出显示和注释，以便你理解每个部分：

```js
<script>
  var map, **toolbar**, symbol, geomTask;

    require([
      "esri/map", 
      **"esri/toolbars/navigation",**
      "dojo/parser", "dijit/registry",

    "dijit/layout/BorderContainer", "dijit/layout/ContentPane", 
      "dijit/form/Button", "dojo/domReady!"
      ], function(
      Map, **Navigation**,
      parser, registry
    ) {
      parser.parse();

    map = new Map("map", {
      basemap: "streets",
      center: [-15.469, 36.428],
      zoom: 3
      });

      map.on("load", createToolbar);

    **// loop through all dijits, connect onClick event**
 **// listeners for buttons to activate navigation tools**
      **registry.forEach(function(d) {**
 **// d is a reference to a dijit**
 **// could be a layout container or a button**
 **if ( d.declaredClass === "dijit.form.Button" ) {**
 **d.on("click", activateTool);**
 **}**
 **});**

    **//activate tools**
      **function activateTool() {**
 **var tool = this.label.toUpperCase().replace(/ /g, "_");**
 **toolbar.activate(Navigation[tool]);**
 **}**

      **//create the Navigation toolbar**
      **function createToolbar(themap) {**
 **toolbar = new Navigation(map);**

      });
    </script>
```

希望前面的`Navigation`工具栏示例已经说明了通过 JavaScript API 向你的 Web 地图应用程序添加导航工具栏的步骤。你不再需要担心添加 JavaScript 代码来绘制和处理范围矩形或捕获鼠标坐标进行平移操作。此外，工具栏的用户界面组件可以通过 Dijit 库提供的各种用户界面控件轻松创建。`Draw`类同样可以轻松支持在类似工具栏中绘制点、线和多边形。

# 用户界面小部件

JavaScript API 提供了许多开箱即用的小部件，可以在应用程序中使用以提高生产力。包括`BasemapGallery`、`Bookmarks`、`Print`、`Geocoder`、`Gauge`、`Measurement`、`Popup`、`Legend`、`Scalebar`、`OverviewMap`、`Editor`、`Directions`、`HistogramTimeSlider`、`HomeButton`、`LayerSwipe`、`LocateButton`、`TimeSlider`和`Analysis`小部件。小部件与我们之前讨论的`Navigation`或`Draw`工具栏的按钮和工具不同。这些小部件是开箱即用的功能，你只需几行代码就可以将它们放入应用程序中，而不是工具栏，后者只是需要大量 HTML、CSS 和 JavaScript 代码的辅助类。

## `BasemapGallery`小部件

`BasemapGallery`小部件显示了来自[ArcGIS.com](http://ArcGIS.com)的基础地图集合和/或用户定义的地图或图像服务。从集合中选择一个基础地图时，当前的基础地图将被移除，新选择的基础地图将出现。当向基础地图库添加自定义地图时，它们需要与库中的其他图层具有相同的空间参考。当使用[ArcGIS.com](http://ArcGIS.com)的图层时，这将是 Web Mercator 参考，wkids 为 102100、102113 或 3857（wkids 是空间参考系统的唯一标识符）。出于性能原因，还建议所有基础地图都是切片图层。

![BasemapGallery 小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_02.jpg)

创建`BasemapGallery`小部件时，可以在构造函数中提供一些参数，如前面的屏幕截图所示，包括显示 ArcGIS 底图、定义一个或多个自定义底图以包含在库中、提供 Bing 地图密钥以及地图的引用等。创建`BasemapGallery`小部件后，需要调用`startup()`方法来准备用户交互。看一下以下的代码片段：

```js
require(["esri/dijit/Basemap", ... 
], function(Basemap, ... ) {
     var basemaps = [];
     var waterBasemap = new Basemap({
       layers: [waterTemplateLayer],
       title: "Water Template",
       thumbnailUrl: "images/waterThumb.png"
     });
     basemaps.push(waterBasemap);
...
});
```

在上一个代码示例中，创建了一个新的`Basemap`对象，其中包含标题、缩略图图像和一个包含单个图层的数组。然后将该`Basemap`对象推送到将添加到小部件中的底图数组中。

## 书签小部件

`Bookmarks`小部件用于向最终用户显示一组命名的地理范围。从小部件中点击书签名称将自动将地图范围设置为书签提供的范围。使用该小部件，您可以添加新书签，删除现有书签和更新书签。书签在 JavaScript 代码中定义为 JSON 对象，其中包含定义书签名称、范围和边界坐标的属性。要将书签添加到小部件中，您需要调用`Bookmark.addBookmark()`。看一下以下的屏幕截图：

![书签小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_03.jpg)

然后看一下以下的代码片段：

```js
require([
"esri/map", "esri/dijit/Bookmarks", "dojo/dom", ... 
], function(Map, Bookmarks, dom, ... ) {
     var map = new Map( ... );
     var bookmarks = new Bookmarks({
       map: map, 
       bookmarks: bookmarks
     }, dom.byId('bookmarks'));
...
});
```

在上一个代码示例中，创建了一个新的`Bookmarks`对象。它附加到地图，并添加了一个 JSON 格式的书签列表。

## 打印小部件

`Print`小部件是一个备受欢迎的工具，它简化了从 Web 应用程序打印地图的过程。它使用默认或用户定义的地图布局。该小部件需要使用 ArcGIS Server 10.1 或更高版本的导出 Web 地图任务。看一下以下的图：

![打印小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_04.jpg)

然后看一下以下的代码片段：

```js
require([
"esri/map", "esri/dijit/Print", "dojo/dom"... 
], function(Map, Print, dom, ... ) {
     var map = new Map( ... );
     var printer = new Print({
       map: map,
       url: "    http://servicesbeta4.esri.com/arcgis/rest/services/Utilities/ExportWebMap/GPServer/Export%20Web%20Map%20Task"
    }, dom.byId("printButton"));
...
});
```

在上一个代码示例中，创建了一个新的`Print`小部件。使用 URL 属性将小部件指向**Print**任务，并将小部件附加到页面上的 HTML 元素。

## 地理编码器小部件

地理编码器小部件允许您轻松地向应用程序添加地理编码功能。该小部件包括一个文本框，当最终用户开始输入地址时，结果会自动过滤。通过将`autoComplete`属性设置为`true`来启用自动完成。默认情况下，`Geocoder`小部件使用 ESRI World Locator 服务。您可以通过设置`geocoder`属性来更改这一点。看一下以下的屏幕截图：

![地理编码器小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_05.jpg)

您还可以自动将值附加到用户输入的任何字符串中。例如，在本地应用程序中，您可能希望始终将特定城市和州附加到输入的任何地址中。这是通过`suffix`属性完成的。要使地图显示地理编码地址的位置，您可以将`autoNavigate`设置为`true`。从定位器返回多个潜在位置是完全可能的。您可以通过设置`maxLocations`属性来设置返回位置的最大数量。在接下来的练习中，您将学习如何将`Geocoder`小部件添加到您的应用程序中。

### 练习使用地理编码器小部件

在这个练习中，您将学习如何将`Geocoder`小部件添加到应用程序中。

1.  打开 ArcGIS JavaScript API Sandbox，网址为[`developers.arcgis.com/en/javascript/sandbox/sandbox.html`](http://developers.arcgis.com/en/javascript/sandbox/sandbox.html)。

1.  修改`<style>`标签，使其显示如下：

```js
<style>
html, body, #mapDiv {
height:100%;
width:100%;
margin:0;
padding:0;
}
body {
background-color:#FFF;
overflow:hidden;
font-family:"Trebuchet MS";
}
#search {
display: block;
position: absolute;
z-index: 2;
top: 20px;
left: 75px;
}
</style>
```

1.  从`<script>`标签中删除以下 JavaScript 内容，如下所示：

```js
<script>
**dojo.require("esri.map");**

**function init(){**
**var map = new esri.Map("mapDiv", {**
**center: [-56.049, 38.485],**
**zoom: 3,**
**basemap: "streets"**
 **});**
 **}**
**dojo.ready(init);**
</script>
```

1.  您已经有一个用于地图的`<div>`容器。在此步骤中，您将创建第二个`<div>`标记，用作“地理编码”小部件的容器。按照以下突出显示的代码添加小部件的容器。确保为`<div>`标记指定特定的`id`为`search`。这对应于我们在文件顶部定义的 CSS 样式，并在以下代码片段中突出显示。它将 HTML 的`<div>`标记连接到 CSS：

```js
<body class="tundra">
  <**div id="search"></div>**
  <div id="mapDiv"></div>
</body>
```

1.  创建变量来保存地图和`geocoder`对象，如下所示：

```js
<script>
**var map, geocoder;**
</script>
```

1.  在`<script>`标签中，添加`require()`函数并创建`Map`对象，如下所示：

```js
<script>
var map, geocoder;

**require([**
 **"esri/map", "esri/dijit/Geocoder", "dojo/domReady!"**
 **], function(Map, Geocoder) {**
**map = new Map("mapDiv",{**
**basemap: "streets",**
**center:[-98.496,29.430], //long, lat**
**zoom: 13** 
 **});**
 **});**
</script>
```

1.  按照以下方式创建地理编码小部件：

```js
require([
    "esri/map", "esri/dijit/Geocoder", "dojo/domReady!"
  ], function(Map, Geocoder) {
    map = new Map("map",{
        basemap: "streets",
        center:[-98.496,29.430], //long, lat
        zoom: 13 
    });

 **var geocoder = new Geocoder({**
 **map: map,**
 **autoComplete: true,**
 **arcgisGeocoder: {**
 **name: "Esri World Geocoder",**
 **suffix: " San Antonio, TX"**
 **}**
 **},"search");**
 **geocoder.startup();**

});
```

整个脚本应如下所示：

```js
<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8">
<meta http-equiv="X-UA-Compatible" content="IE=7, IE=9,IE=10">
<meta name="viewport" content="initial-scale=1,maximum-scale=1,user-scalable=no"/>
<title>Geocoding Widget API for JavaScript | SimpleGeocoding</title>
<link rel="stylesheet"href="http://js.arcgis.com/3.7/js/esri/css/esri.css">
<style>
html, body, #mapDiv {
height:100%;
width:100%;
margin:0;
padding:0;
      }
      #search {
display: block;
position: absolute;
z-index: 2;
top: 20px;
left: 74px;
      }
</style>
<script src="http://js.arcgis.com/3.7/"></script>
<script>
var map, geocoder;

require([
        "esri/map", "esri/dijit/Geocoder", "dojo/domReady!"
      ], function(Map, Geocoder) {
map = new Map("mapDiv",{
basemap: "streets",
center:[-98.496,29.430], //long, lat
zoom: 13 
        });

var geocoder = new Geocoder({
map: map,
autoComplete: true,
arcgisGeocoder: {
name: "Esri World Geocoder",
suffix: " San Antonio, TX"
          }
        },"search");
geocoder.startup();

      });
</script>
</head>
<body>
<div id="search"></div>
<div id="mapDiv"></div>
</body>
</html>
```

1.  单击“运行”按钮执行代码。您应该看到类似以下屏幕截图的内容。注意“地理编码器”小部件。![练习使用地理编码器小部件的时间到了](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_06.jpg)

1.  开始输入“圣安东尼奥，德克萨斯州”的地址。您可以使用`1202 Sand Wedge`作为示例。在开始输入地址时，自动完成应该开始。当您看到地址时，请从列表中选择它。小部件将对地址进行地理编码，并将地图定位，使地址位于地图的中心，如下面的屏幕截图所示：![练习使用地理编码器小部件的时间到了](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_07.jpg)

## 仪表小部件

“仪表”小部件在半圆仪表界面中显示来自`FeatureLayer`或`GraphicsLayer`的数字数据。您可以定义仪表指示器的颜色、驱动仪表的数字数据的字段、标签字段、引用的图层、最大数据值、标题等。请查看以下屏幕截图：

![仪表小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_08.jpg)

然后查看以下代码片段：

```js
require([
  "esri/dijit/Gauge", ... 
], function(Gauge, ... ) {
var gaugeParams = {
    "caption": "Hurricane windspeed.",
    "color": "#c0c",
    "dataField": "WINDSPEED", 
    "dataFormat": "value",
    "dataLabelField": "EVENTID",
    "layer": fl, //fl previously defined as FeatureLayer
    "maxDataValue": 120, 
    "noFeatureLabel": "No name",
    "title": "Atlantic Hurricanes(2000)",
    "unitLabel": "MPH"
  };
var gauge = new Gauge(gaugeParams, "gaugeDiv");
  ...
});
```

前面的代码示例显示了创建“仪表”小部件。许多参数被传递到仪表的构造函数中，包括标题、颜色、数据字段、图层、最大数据值等。

## 测量小部件

“测量”小部件提供了三种工具，使最终用户能够测量长度和面积，并获取鼠标的坐标。请查看以下屏幕截图：

![测量小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_09.jpg)

“测量”小部件还允许您更改测量单位，如下所示：

```js
var measurement = new Measurement({
  map: map
}, dom.byId("measurementDiv"));
measurement.startup();
```

前面的代码示例显示了如何创建“测量”小部件的实例并将其添加到应用程序中。

## 弹出小部件

“弹出”小部件在功能上类似于默认的信息窗口，用于显示有关要素或图形的属性信息。实际上，从 API 的 3.4 版本开始，该小部件现在是显示属性的默认窗口，而不是`infoWindow`参数。但是，它还包含其他功能，如缩放和突出显示要素、处理多个选择以及最大化窗口的按钮。界面还可以使用 CSS 进行样式设置。请参考以下屏幕截图，作为“弹出”小部件中可以显示的内容的示例。

![弹出小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_10.jpg)

从版本 3.4 开始，“弹出”小部件支持以**从右到左**（**RTL**）方向呈现文本，以支持希伯来语和阿拉伯语等 RTL 语言。如果页面方向使用`dir`属性设置为 RTL，则 RTL 支持将自动应用。默认值为**从左到右**（**LTR**）。请查看以下代码片段：

```js
//define custom popup options
var popupOptions = {
  markerSymbol: new SimpleMarkerSymbol("circle", 32, null, new Color([0, 0, 0, 0.25])),
  marginLeft: "20", 
  marginTop: "20"
};
//create a popup to replace the map's info window
var popup = new Popup(popupOptions, dojo.create("div"));

map = new Map("map", {
  basemap: "topo",
  center: [-122.448, 37.788],
  zoom: 17,
  infoWindow: popup
});
```

在上一个代码示例中，创建了一个 JSON`popupOptions`对象来定义弹出窗口的符号和边距。然后将此`popupOptions`对象传递给`Popup`对象的构造函数。最后，将`Popup`对象传递给`infoWindow`参数，该参数指定应将`Popup`对象用作信息窗口。

## 图例小部件

`Legend`小部件显示地图中一些或所有图层的标签和符号。它具有尊重比例依赖性的能力，以便在缩放应用程序时，图例值更新以反映各种比例范围下的图层可见性。`Legend`小部件支持`ArcGISDynamicMapServiceLayer`、`ArcGISTiledMapServiceLayer`和`FeatureLayer`。

![图例小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_11.jpg)

创建`Legend`小部件的新实例时，可以指定控制图例内容和显示特性的各种参数。`arrangement`参数可用于指定图例在其容器 HTML 元素中的对齐方式，并可定义为左对齐或右对齐。`autoUpdate`属性可设置为`true`或`false`，如果设置为`true`，则当地图比例尺发生变化或图层被添加或从地图中移除时，图例将自动更新其参数。`layerInfos`参数用于指定要在图例中使用的图层子集，`respectCurrentMapScale`可以设置为`true`，以根据每个图层的比例范围触发自动图例更新。最后，需要调用`startup()`方法来显示新创建的图例：

```js
var layerInfo = dojo.map(results, function(layer,index){return {layer: layer.layer,title: layer.layer.name};});if(layerInfo.length > 0){var legendDijit = new Legend({map: map,layerInfos: layerInfo},"legendDiv");legendDijit.startup();}
```

上述代码示例显示了如何创建一个图例小部件并将其添加到应用程序中。

## 概览地图小部件

`OverviewMap`小部件用于在较大区域的上下文中显示主地图的当前范围。此概览地图在主地图范围更改时更新。主地图的范围在概览地图中表示为一个矩形。此范围矩形也可以拖动以更改主地图的范围。

概览地图可以显示在主地图的一个角落，并在不使用时隐藏。它也可以放置在主地图窗口之外的`<div>`元素内，或者临时最大化，以便轻松访问感兴趣的远程区域。看一下下面的屏幕截图：

![概览地图小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_12.jpg)

`OverviewMap`小部件在对象的构造函数中接受许多可选参数。这些参数允许您控制概览地图相对于主地图的放置位置、用于概览地图的基础图层、范围矩形的填充颜色、最大化按钮的外观以及概览地图的初始可见性。看一下下面的代码片段：

```js
var overviewMapDijit = new OverviewMap({map:map, visible:true});
overviewMapDijit.startup();
```

上述代码示例说明了创建`OverviewMap`小部件。

## 比例尺小部件

`Scalebar`小部件用于向地图或特定的 HTML 节点添加比例尺。`Scalebar`小部件以英制或公制值显示单位。从 API 的 3.4 版本开始，如果将`scalebarUnits`属性设置为`dual`，它可以同时显示英制和公制值。您还可以通过`attachTo`参数控制比例尺的位置。默认情况下，比例尺位于地图的左下角。看一下下面的屏幕截图：

![比例尺小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_13.jpg)

然后看一下下面的代码片段：

```js
var scalebar = new esri.dijit.Scalebar({map:map,scalebarUnit:'english'});
```

上述代码示例说明了使用英制单位创建`Scalebar`小部件。

## 方向小部件

`Directions`小部件使得计算两个或多个输入位置之间的方向变得容易。生成的方向，在下面的屏幕截图中显示，显示了详细的逐步转向说明和可选地图。如果地图与小部件关联，方向的路线和停靠点将显示在地图上。地图上显示的停靠点是交互式的，因此您可以单击它们以显示带有停靠点详细信息的弹出窗口，或者将停靠点拖动到新位置以重新计算路线。看一下下面的屏幕截图：

![方向小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_14.jpg)

看一下下面的代码片段：

```js
var directions = new Directions({
map: map
},"dir");

directions.startup();
```

上一个代码示例显示了创建`Directions`对象。

## HistogramTimeSlider dijit

`HistogramTimeSlider` dijit 为地图上启用时间的图层提供了数据的直方图图表表示。通过 UI，用户可以使用`TimeSlider`小部件的扩展来临时控制数据的显示。

！[HistogramTimeSlider dijit]（graphics/7965OT_05_15.jpg）

看一下以下代码片段：

```js
require(["esri/dijit/HistogramTimeSlider", ... ],
function(HistogramTimeSlider, ... ){
  var slider = new HistogramTimeSlider({
    dateFormat: "DateFormat(selector: 'date', fullYear: true)",
    layers : [ layer ],
    mode: "show_all",
    timeInterval: "esriTimeUnitsYears"
  }, dojo.byId("histogram"));
  map.setTimeSlider(slider);
});
```

在上一个代码示例中，创建了一个`HistogramTimeSlider`对象并将其与地图关联。

## HomeButton 小部件

`HomeButton`小部件只是一个按钮，您可以将其添加到应用程序中，它将地图返回到初始范围。看一下以下截图：

！[HomeButton 小部件]（graphics/7965OT_05_16.jpg）

然后看一下以下代码片段：

```js
require([
      "esri/map", 
**"esri/dijit/HomeButton"**,
      "dojo/domReady!"
    ], function(
      Map, **HomeButton**
    )  {

var map = new Map("map", {
center: [-56.049, 38.485],
zoom: 3,
basemap: "streets"
      });

**var home = new HomeButton({**
**map: map**
 **}, "HomeButton");**
**home.startup();**

    });
```

上一个代码示例显示了创建`HomeButton`小部件。

## LocateButton 小部件

`LocateButton`小部件可用于查找并缩放到用户当前位置。此小部件使用地理位置 API 来查找用户当前位置。找到位置后，地图将缩放到该位置。该小部件提供选项，允许开发人员定义以下内容：

+   HTML5 地理位置提供了查找位置的选项，如`maximumAge`和`timeout`。 `timeout`属性定义了用于确定设备位置的最长时间，而`maximumAge`属性定义了在找到设备的新位置之前的最长时间。

+   定义自定义符号，用于在地图上突出显示用户当前位置的能力。

+   找到位置后要缩放的比例。！[LocateButton 小部件]（graphics/7965OT_05_17.jpg）

看一下以下代码片段：

```js
geoLocate = new LocateButton({
map: map,
highlightLocation: false
}, "LocateButton");
geoLocate.startup();
```

上一个代码示例显示了如何创建`LocateButton`小部件的实例并将其添加到地图中。

## TimeSlider 小部件

`TimeSlider`小部件用于可视化启用时间的图层。 `TimeSlider`小部件配置为具有两个拇指，因此仅显示两个拇指位置的时间范围内的数据。 `setThumbIndexes（）`方法确定每个拇指的初始位置。在这种情况下，在初始开始时间添加了一个拇指，另一个拇指定位在更高的时间步骤。看一下以下屏幕截图：

！[TimeSlider 小部件]（graphics/7965OT_05_18.jpg）

看一下以下代码片段：

```js
var timeSlider = new TimeSlider({
style: "width: 100%;"
}, dom.byId("timeSliderDiv"));
map.setTimeSlider(timeSlider);

var timeExtent = new TimeExtent();
timeExtent.startTime = new Date("1/1/1921 UTC");
timeExtent.endTime = new Date("12/31/2009 UTC");
timeSlider.setThumbCount(2);
timeSlider.createTimeStopsByTimeInterval(timeExtent, 2, "esriTimeUnitsYears");
timeSlider.setThumbIndexes([0,1]);
timeSlider.setThumbMovingRate(2000);
timeSlider.startup
```

上面的代码示例说明了如何创建`TimeSlider`对象的实例并设置各种属性，包括开始和结束时间。

## 图层滑动小部件

`LayerSwipe`小部件提供了一个简单的工具，用于在地图顶部显示图层或图层的一部分。您可以使用此小部件在地图上显示一个或多个图层的内容，以便比较多个图层的内容。该小部件提供水平，垂直和范围查看模式。

！[LayerSwipe 小部件]（graphics/7965OT_05_19.jpg）

看一下以下代码片段：

```js
varswipeWidget = new LayerSwipe({
type: "vertical",
map: map,
layers: [swipeLayer]
}, "swipeDiv");
swipeWidget.startup();
```

上一个代码示例显示了如何创建`LayerSwipe`的实例并将其添加到地图中。

## 分析小部件

在 ArcGIS API for JavaScript 的 3.7 版本中引入了许多新的分析小部件。分析小部件提供对 ArcGIS 空间分析服务的访问，允许您通过 API 对托管数据执行常见的空间分析。上一个屏幕截图显示了`SummarizeNearby`小部件的一部分，这是 12 个分析小部件之一。分析小部件包括以下 12 个小部件：

+   `AnalysisBase`

+   聚合点

+   创建缓冲区

+   创建驾驶时间区域

+   溶解边界

+   丰富图层

+   提取数据

+   查找热点

+   查找最近

+   合并图层

+   图层叠加

+   附近总结

+   `SummarizeWithin`

需要[ArcGIS.com](http://ArcGIS.com)订阅才能使用这些小部件。您不仅需要使用您的[ArcGIS.com](http://ArcGIS.com)帐户存储数据，还需要登录以作为基于信用的服务运行分析作业。执行分析任务和托管要素服务对个人帐户用户不可用。

# 特性编辑

当使用企业地理数据库格式存储的数据时，ArcGIS API for JavaScript 支持简单要素编辑。这意味着您的数据需要存储在由 ArcSDE 管理的企业地理数据库中。

编辑工作基于“最后提交者获胜”的概念。例如，如果两个人正在编辑图层中的同一要素，并且两者都提交了修改，最后提交更改的编辑者将覆盖第一个编辑者所做的任何更改。显然，在某些情况下，这可能会造成问题，因此在实现应用程序中的编辑之前，您需要检查您的数据可能受到的影响。

编辑的其他特性包括对域和子类型的支持，模板样式编辑以及编辑独立表和附件的能力。要使用编辑选项，您需要使用`FeatureService`和`FeatureLayer`。编辑请求通过 HTTP post 请求提交到服务器，大多数情况下需要使用代理。

编辑支持包括要素编辑，包括创建和删除简单要素，以及通过移动、切割、联合或重塑来修改要素的能力。此外，要素属性可以被编辑，文档可以附加到要素，并且可以向要素添加评论。

## 要素服务

Web 编辑需要要素服务来提供数据的符号和要素几何。要素服务只是启用了要素访问功能的地图服务。此功能允许地图服务以便于 Web 应用程序使用和更新的方式公开要素几何和它们的符号。

在构建 Web 编辑应用程序之前，您需要做一些工作来创建一个公开要进行编辑的图层的要素服务。这涉及设置地图文档，并可选择定义一些编辑模板。模板允许您预先配置一些常用要素类型的符号和属性。例如，为了准备编辑流，您可以为“主要河流”、“次要河流”、“小溪”和“支流”配置模板。模板是可选的，但它们使应用程序的最终用户轻松创建常见要素。

完成地图后，您需要将其发布到启用了要素访问功能的 ArcGIS Server。这将创建 REST URL 或端点，用于地图服务和要素服务。您将使用这些 URL 在应用程序中引用服务。

通过`FeatureLayer`对象，Web API 可以访问要素服务，我们在之前的章节中已经进行了检查。要素图层可以执行各种操作，并且可以引用地图服务或要素服务。但是，当您将`FeatureLayer`用于编辑目的时，您需要引用要素服务。

通过编辑功能，您的 Web 应用程序告诉`FeatureLayer`哪些属性已更改，以及（如果适用）几何图形如何更改。`FeatureLayer`对象还在编辑后显示更新的要素。您可以在要素图层上调用`applyEdits()`方法来应用编辑，然后将其提交到数据库。

## 编辑小部件

ArcGIS API for JavaScript 提供了小部件，使您更容易将编辑功能添加到您的 Web 应用程序中。这些小部件包括`Editor`、`TemplatePicker`、`AttributeInspector`和`AttachmentEditor`小部件。`Editor`小部件是默认的编辑界面，包括您编辑图层所需的一切，并允许您选择可用的工具的数量和类型。`TemplatePicker`显示一个预配置的模板，其中包含地图文档中每个图层的符号。这种模板样式编辑允许用户简单地选择一个图层并开始编辑。`AttributeInspector`小部件提供了一个界面，用于编辑要素的属性，并确保有效的数据输入。最后，`AttachmentEditor`将可下载文件与要素关联起来。我们将更详细地研究这些小部件。

### 编辑器小部件

`Editor`小部件显示在以下截图中，提供了 API 包含的默认编辑界面。它结合了其他小部件的功能，为您提供了编辑图层所需的一切。您可以选择小部件上可用的工具的数量和类型。

`Editor`小部件在进行编辑后立即保存您的编辑，例如，当您完成绘制一个点时。如果您决定不使用`Editor`小部件，您必须确定何时以及多久应用编辑。看一下以下截图：

![编辑器小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_20.jpg)

在以下代码示例中，通过将`params`对象传递到构造函数中来创建一个新的`Editor`对象。输入的`params`对象是开发人员定义编辑应用程序功能的地方。在这种情况下，只定义了必需的选项。必需的选项是地图、要编辑的要素图层和几何服务的 URL。看一下以下代码片段：

```js
var settings = {map: map,
  geometryService: new GeometryService("http://servicesbeta.esri.com/arcgis/rest/services/Geometry/GeometryServer"),layerInfos:featureLayerInfos};

var params = {settings: settings};**var editorWidget = new Editor(params);editorWidget.startup();**

```

`Editor`小部件使用要素服务中的可编辑图层提供开箱即用的编辑功能。它结合了开箱即用的`TemplatePicker`、`AttachmentEditor`、`AttributeInspector`和`GeometryService`，以提供要素和属性编辑。对于大多数编辑应用程序，您应该利用`Editor`小部件。该小部件允许您执行以下图表中列出的所有功能：

![编辑器小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_21.jpg)

要在您的代码中使用`Editor`小部件，您需要首先使用`dojo.require`加载小部件。创建`Editor`的新实例所需的参数包括对`Map`对象和几何服务的引用。

### 模板选择器小部件

`TemplatePicker`小部件向用户显示了一组预配置的要素，每个要素都代表服务中的一个图层。通过从模板中选择一个符号，然后单击地图来添加要素，编辑可以非常简单地启动。模板中显示的符号来自您在要素服务的源地图中定义的编辑模板或应用程序中定义的符号。`TemplatePicker`也可以用作简单的图例。看一下以下截图：

![模板选择器小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_22.jpg)

看一下以下代码片段：

```js
function initEditing(results) {var templateLayers = dojo.map(results,function(result){return result.layer;});**var templatePicker = new TemplatePicker({featureLayers: templateLayers,grouping: false,rows: 'auto',columns: 3},'editorDiv');templatePicker.startup();**var layerInfos = dojo.map(results, function(result) {return {'featureLayer':result.layer};});var settings = {map: map,**templatePicker: templatePicker,**layerInfos:layerInfos};var params = {settings: settings};var editorWidget = new Editor(params);editorWidget.startup();}
```

在上一个代码示例中，创建了一个新的`TemplatePicker`对象并将其附加到`Editor`小部件上。

### 属性检查器小部件

如下截图所示，`AttributeInspector`小部件为在 Web 上编辑要素属性提供了一个界面。它还通过将输入与预期数据类型进行匹配来确保用户输入的数据有效。还支持域。例如，如果对字段应用了编码值域，则允许的值会出现在下拉列表中，限制了输入其他值的可能性。如果字段需要日期值，则会出现一个日历，帮助用户提供有效的日期。看一下以下截图：

![AttributeInspector 小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_23.jpg)

`AttributeInspector`小部件公开了图层上所有可用的属性以供编辑。如果要限制可用属性，必须编写自己的界面来输入和验证值。看一下以下代码片段：

```js
var layerInfos = [{
  'featureLayer': petroFieldsFL,
  'showAttachments': false,
  'isEditable': true,
  'fieldInfos': [
  {'fieldName': 'activeprod', 'isEditable':true, 'tooltip': 'Current Status', 'label':'Status:'},
  {'fieldName': 'field_name', 'isEditable':true, 'tooltip': 'The name of this oil field', 'label':'Field Name:'},
  {'fieldName': 'approxacre', 'isEditable':false,'label':'Acreage:'},
  {'fieldName': 'avgdepth', 'isEditable':false,'label':'Average Depth:'},
  {'fieldName': 'cumm_oil', 'isEditable':false,'label':'Cummulative Oil:'},
  {'fieldName': 'cumm_gas', 'isEditable':false,'label':'Cummulative Gas:'}
]
  }];

 **var attInspector = new AttributeInspector({**
 **layerInfos:layerInfos**
 **}, domConstruct.create("div"));**

  //add a save button next to the delete button
  var saveButton = new Button({ label: "Save", "class":"saveButton"});
 domConstruct.place(saveButton.domNode,attInspector.deleteBtn.domNode, "after");

saveButton.on("click", function(){
  updateFeature.getLayer().applyEdits(null, [updateFeature], null);    
});

**attInspector.on("attribute-change", function(evt) {**
 **//store the updates to apply when the save button is clicked** 
 **updateFeature.attributes[evt.fieldName] = evt.fieldValue;**
**});**

**attInspector.on("next", function(evt) {**
 **updateFeature = evt.feature;**
 **console.log("Next " + updateFeature.attributes.objectid);**
**});**

**attInspector.on("delete", function(evt){**
 **evt.feature.getLayer().applyEdits(null,null,[feature]);**
 **map.infoWindow.hide();**
**});**

map.infoWindow.setContent(attInspector.domNode);
map.infoWindow.resize(350, 240);
```

在上面的代码示例中，创建了一个`AttributeInspector`小部件并将其添加到应用程序中。此外，设置了几个事件处理程序，包括属性`change`、`next`和`delete`，以处理各种属性更改。

### AttachmentEditor 小部件

在某些情况下，您可能希望将可下载文件与要素关联起来。例如，您可能希望用户能够单击代表水表的要素并看到指向水表图像的链接。在 ArcGIS Web API 中，这样一个关联的可下载文件称为要素附件。

如下面的屏幕截图所示，`AttachmentEditor`小部件是一个帮助用户上传和查看要素附件的小部件。`AttachmentEditor`小部件包括当前附件的列表（带有**删除**按钮），以及一个**浏览**按钮，可用于上传更多附件。`AttachmentEditor`小部件在信息窗口内工作良好，但也可以放置在页面的其他位置。

![AttachmentEditor 小部件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_24.jpg)

为了使用要素附件，必须在源要素类上启用附件。您可以在 ArcCatalog 或 ArcMap 中的**目录**窗口中为要素类启用附件。如果`Editor`小部件检测到附件已启用，它将包括`AttachmentEditor`。看一下以下代码片段：

```js
   var map;require(["esri/map","esri/layers/FeatureLayer",**"esri/dijit/editing/AttachmentEditor",**"esri/config","dojo/parser", "dojo/dom","dijit/layout/BorderContainer", "dijit/layout/ContentPane", "dojo/domReady!"], function(Map, FeatureLayer, **AttachmentEditor**, esriConfig,parser, dom) {parser.parse();// a proxy page is required to upload attachments// refer to "Using the Proxy Page" for more information:https://developers.arcgis.com/en/javascript/jshelp/ags_proxy.htmlesriConfig.defaults.io.proxyUrl = "/proxy";map = new Map("map", { basemap: "streets",center: [-122.427, 37.769],zoom: 17});map.on("load", mapLoaded);function mapLoaded() {var featureLayer = new FeatureLayer("http://sampleserver3.arcgisonline.com/ArcGIS/rest/services/SanFrancisco/311Incidents/FeatureServer/0",{mode: FeatureLayer.MODE_ONDEMAND});map.infoWindow.setContent("<div id='content' style='width:100%'></div>");map.infoWindow.resize(350,200);**var attachmentEditor = new AttachmentEditor({}, dom.byId("content"));attachmentEditor.startup();**featureLayer.on("click", function(evt) {var objectId = evt.graphic.attributes[featureLayer.objectIdField];map.infoWindow.setTitle(objectId);**attachmentEditor.showAttachments(evt.graphic,featureLayer);**map.infoWindow.show(evt.screenPoint, map.getInfoWindowAnchor(evt.screenPoint));});map.addLayer(featureLayer);}});
```

上面的代码显示了如何创建一个`AttachmentEditor`对象并将其添加到应用程序中。

### 编辑工具栏

有时您可能不想使用默认的`Editor`小部件，如下面的屏幕截图所示：

![编辑工具栏](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_05_25.jpg)

这些情况包括您希望编写自己的编辑逻辑，特别是关于客户端显示要素和图形的情况。在这些情况下，您可以使用**编辑**工具栏。**编辑**工具栏只是 API 的一部分，是一个 JavaScript 辅助类。它有助于放置和移动顶点和图形。这个工具栏类似于我们在本书前面讨论过的**导航**和**绘图**工具栏。

# 总结

小部件和工具栏为您的应用程序提供了一种简单的方式来添加预构建的功能，而无需编写大量代码。可用小部件的范围在 API 的各个版本中不断增加，预计在未来的版本中将提供许多新的小部件。工具栏与小部件类似，是提供导航、绘图功能和编辑工具功能的辅助类。但是，开发人员需要定义工具栏和按钮的外观。在下一章中，您将学习如何使用`Query`和`QueryTask`类创建空间和属性查询。
