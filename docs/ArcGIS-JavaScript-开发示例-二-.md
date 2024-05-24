# ArcGIS JavaScript 开发示例（二）

> 原文：[`zh.annas-archive.org/md5/C5B34B58FB342061E6400E7ECE284E58`](https://zh.annas-archive.org/md5/C5B34B58FB342061E6400E7ECE284E58)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：使用渲染器

渲染器为我们提供了一种直观地使用不同符号和颜色来可视化数据的媒介。渲染器不仅是一种数据可视化技术，而且越来越被认为是一种数据分析工具。正确使用渲染器将帮助我们看到数据中的空间模式，并显示各种现象的地理分布。对基本制图学、色彩理论甚至统计学的理解将帮助我们创建更好的渲染器，最终更好地洞察可用数据。本章将涵盖以下主题：

+   学习 API 提供的不同符号和颜色

+   学习如何创建`SimpleRenderer`方法

+   学习如何高效创建`UniqueValueRenderer`方法

+   学习何时使用`ClassBreakRenderer`和`HeatmapRenderers`

+   讨论`ScaleDependantRenderers`可以有用的情景

+   智能制图简介

# 使用颜色

处理颜色的 Esri 模块称为`esri/Color`。在处理颜色模块之前，让我们对颜色有一个基本的了解。

## RGB 颜色模型

可见光谱中的任何颜色（紫罗兰到红色之间的颜色范围）都可以用红（R）、绿（G）或蓝（B）颜色的组合来表示。这就是**RGB 颜色模型**。还有其他颜色模型，但让我们现在先使用 RGB 颜色模型。每种颜色 R、G 或 B 都可以用 0 到 255 的比例来表示。

以下图片显示了三种原色（R、G 和 B）及其叠加效果之间的关系：

![RGB 颜色模型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_01.jpg)

当三种颜色（R、G 和 B）以相等比例混合时，产生的颜色总是位于灰度范围内的某个位置。以下几点值得注意：

+   例如，如果`R=0`，`G=0`，`B=0`，混合产生黑色。

+   如果`R=255`，`G=255`，`B=255`，混合产生白色。

+   任何其他数字值，当等量混合时，产生灰色的阴影。

例如，如果`R=125`，`G=125`，`B=125`，它将是灰色。

+   颜色模型还显示，当红色和绿色混合在一起时（`R=255`，`G=255`，`B=0`），我们得到黄色。

+   当仅混合红色和蓝色时（`R=255`，`G=0`，`B=255`），我们得到品红色。

+   当绿色和蓝色混合时，我们得到青色（`R=0`，`G=255`，`B=255`）。

## Esri 颜色模块

要使用 RGB 颜色模型定义颜色，可以使用以下格式：

```js
var r = g = b = 125;
var color = new Color([r, g, b]);
```

在上面的片段中，`color`是`esri/Color`模块的一个实例，`r`、`g`和`b`分别是红色、绿色和蓝色的值。颜色应始终按照（`r`、`g`和`b`）的顺序添加为数组对象。如预期的那样，`color`变量存储了灰色。如果我们需要向颜色添加透明度，我们可以定义透明度值，称为`alpha`，它是一个介于`0`和`1.0`之间的整数，其中`0`表示完全透明，`1.0`表示不透明。透明度值将作为数组中的第四个值添加：

```js
define(["esri/Color"], function(Color){
var r = g = b = 100;
var alpha = 0.5; // 50 % transparency
var color2 = new Color ([r, g, b, alpha]);
})
```

RGB 值可以表示为十六进制数。例如，`[255, 0, 0]`可以表示为`#FF0000`。API 还允许我们通过其英文命名字符串来表示颜色，例如`blue`：

```js
define(["esri/Color"], function(Color){
var colorString = "red";
var colorHex = "#FF0000"; 
var color1 = new Color(colorString);
var color2 = new Color(colorHex);
```

# 使用符号

符号是基于它们试图符号化的几何图形。因此，用于表示点、线和多边形的符号彼此不同。除了几何图形之外，定义符号所需的三个重要参数是以下：

+   风格

+   颜色

+   维度（或大小）

通常提供风格作为模块常量。例如，`SimpleLineSymbol.STYLE_DASHDOT`、`SimpleFillSymbol.STYLE_SOLID`和`SimpleMarkerSymbol.STYLE_CIRCLE`，其中`SimpleLineSymbol`、`SimpleFillSymbol`和`SimpleMarkerSymbol`分别用于符号化线、多边形和点要素：

+   这些符号的颜色可以由我们在前面章节中讨论的颜色模块定义。

+   基于几何类型，尺寸意味着不同的东西。例如，对于线符号，我们使用称为 `width` 的参数来指代线的厚度，而对于点，我们使用名为 `size` 的参数来定义其尺寸。

让我们先讨论基于三角形的几何符号，然后再处理非基于几何的和特殊符号。

基于几何的符号如下：

+   `SimpleLineSymbol`: 用于表示线几何

+   `SimpleMarkerSymbol`: 用于表示点几何

+   `SimpelFillSymbol`: 用于表示多边形几何

## SimpleLineSymbol

线符号构造函数是最简单的，因为它只需用样式、颜色和宽度三个参数来定义。

| 名称 | 值 |
| --- | --- |
| 模块名称 | `esri/symbols/SimpleLineSymbol` |
| 构造函数 | `new SimpleLineSymbol(style, color, and width)` |

`style` 是一个模块常量。该模块提供以下样式：

+   `STYLE_DASH` (创建由短划线组成的线)

+   `STYLE_DASHDOT` (创建由短划线点组成的线)

+   `STYLE_DOT` (创建由点组成的线)

该模块提供了其他样式常量，如 `STYLE_LONGDASH`, `STYLE_LONGDASHDOT`, `STYLE_NULL`, `STYLE_SHORTDASH`, `STYLE_SHORTDASHDOT`, `STYLE_SHORTDASHDOTDOT`, `STYLE_SHORTDOT`, 和 `STYLE_SOLID`。

`STYLE_SOLID` 是默认样式，提供了一个连续的实线。

我们可以使用 `simpleLineSymbol.setColor(color)` 方法设置线的颜色；这里，`color` 是 Esri `Color` 对象，`simpleLineSymbol` 是 `SimpleLineSymbol` 对象的一个实例。`style` 常量可以使用 `setStyle(style)` 方法设置。`SimpleLineSymbol.toJson()` 是一个重要的方法，它将 `SimpleLineSymbol` 转换为 ArcGIS 服务器 JSON 表示。

以下代码片段将创建一条红色实线：

```js
var simpleLineSymbol = new SimpleLineSymbol();
var color = new Color("red");
simpleLineSymbol.setColor(color);
simpleLineSymbol.setWidth(2);
```

## SimpleMarkerSymbol

`SimpleMarkerSymbol` 方法用于表示一个点。与表示线的复杂性相比，表示点几何有一个额外的复杂性，即它接受一个轮廓参数，该参数本身是一个 `SimpleLineSymbol` 对象。

![SimpleMarkerSymbol](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_02.jpg)

| 名称 | 值 |
| --- | --- |
| 模块名称 | `esri/symbols/SimpleMarkerSymbol` |
| 构造函数 | `new SimpleMarkerSymbol(style, size, outline, color)` |

该模块提供了以下样式常量：

+   `STYLE_CIRCLE`

+   `STYLE_DIAMOND`

+   `STYLE_SQUARE`

`setAngle(angle)` 方法按指定角度顺时针旋转符号。`setColor(color)` 方法设置符号的颜色。`setOffset` (`x` 和 `y`) 设置屏幕单位中标记的 `x` 和 `y` 偏移量。`setOutline(outline)` 设置标记符号的轮廓。`setSize(size)` 允许我们以像素为单位设置标记的大小。`setStyle(style)` 设置标记符号样式。`toJson()` 将对象转换为其 ArcGIS 服务器 JSON 表示。

## ArcGIS 符号沙盘

如果选择合适的颜色和样式以及其他属性来表示一个符号似乎是一个困难的选择，下面的网页试图通过提供一个沙盒来生成任何类型的符号和定义类似符号所需的代码来帮助你。该网页位于 [`developers.arcgis.com/javascript/samples/playground/index.html`](http://developers.arcgis.com/javascript/samples/playground/index.html)。

导航到此 URL 将使您进入类似以下截图的页面。我们可以选择几乎任何类型的符号：

![ArcGIS symbol playground](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_03.jpg)

选择其中一个将导航到另一个页面，您可以在该页面上选择属性并生成符号代码。

![ArcGIS symbol playground](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_04.jpg)

嗯，我们很容易生成了生成半透明、红色、菱形 `SimpleMarkerSymbol`（无轮廓）所需的代码：

```js
// Modules required: 
// esri/symbols/SimpleMarkerSymbol
// esri/symbols/SimpleLineSymbol

var marker = new SimpleMarkerSymbol();
marker.setStyle(SimpleMarkerSymbol.STYLE_DIAMOND);
marker.setColor(new Color([255, 0, 0, 0.55]));
marker.setSize(25);
```

## SimpleFillSymbol

`SimpleFillSymbol`模块帮助我们为多边形生成符号。

+   模块名称：`esri/symbols/SimpleFillSymbol`

+   `new SimpleFillSymbol(style, outline, color)`

`STYLE`参数的一些模块常量如下：

+   `STYLE_BACKWARD_DIAGONAL`

+   `STYLE_CROSS`

+   `STYLE_NULL`

`SimpleFillSymbol.STYLE_SOLID`是默认样式。

## PictureMarkerSymbol

当我们需要描绘一个图标来象征一个点几何体时，我们可以使用这个模块。我们不需要将颜色信息作为参数提供，而是需要一个图像 URL 来显示一个图片作为标记符号。

| 名称 | 值 |
| --- | --- |
| 模块 | `esri/symbols/PictureMarkerSymbol` |
| 构造函数 | `new PictureMarkerSymbol(url, width, height)` |

在[`developers.arcgis.com/javascript/samples/portal_symbols/index.html`](http://developers.arcgis.com/javascript/samples/portal_symbols/index.html)找到的网页上可以帮助我们搜索适当的`PictureMarkerSymbol`。

导航到此 URL 将打开下面显示的页面。当选择图片图标时，下方会生成代码。可以重用此代码来重新创建在网页中选择的`PictureMarkerSymbology`。

生成的代码是`PictureMarkerSymbol`的 JSON 表示。JSON 对象提供以下属性：

+   `angle`

+   `xoffset`

+   `yoffset`

+   `type`

+   `url`

+   `contentType`

+   `width`

+   `height`

+   `imageData`

在这些中，`imageData`和`url`是多余的，所以如果我们可以使用 URL 属性，我们可以避免`imageData`属性。`imageData`属性只是图像的`Base64`表示。为了避免这种情况，我们可以取消网页右上角的一个框，上面写着**启用 Base64 编码**之类的字样。

此外，如果`angle`、`xoffset`和`yoffset`的值为 0，我们也可以省略这些。

![PictureMarkerSymbol](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_05.jpg)

使用此网页提供的图标的 URL 以及 ArcGIS Symbol Playground 将使我们能够进一步自定义`PictureMarkerSymbol`。

![PictureMarkerSymbol](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_06.jpg)

要自定义`PictureMakerSymbol`，请使用以下内容：

```js
// Modules required: 
// esri/symbols/PictureMarkerSymbol

var marker = new PictureMarkerSymbol();
marker.setHeight(64);
marker.setWidth(64);
marker.setUrl("http://static.arcgis.com/images/Symbols/Basic/RedStickpin.png");
```

### PictureFillSymbol

`PictureFillSymbol`进一步让我们用图像填充多边形几何体。

![PictureFillSymbol](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_07.jpg)

### TextSymbol

文本符号可以用来代替标签。文本符号缺乏几何信息，因此需要附加到几何体上。

![TextSymbol](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_08.jpg)

从 ArcGIS Symbol Playground 生成的以下片段演示了生成`TextSymbol`的组件：

```js
// Modules required: 
// esri/symbols/TextSymbol
// esri/symbols/Font

var font = new Font();
font.setWeight(Font.WEIGHT_BOLD);
font.setSize(65);
var textSym = new TextSymbol();
textSym.setFont(font);
textSym.setColor(new Color([255, 0, 0, 1]));
textSym.setText("Sample Text");
```

# 使用渲染器

当应用程序使用从 Web 地图或 GIS 服务引用的图层时，Web 地图或服务本身提供了默认的绘图属性，确定图层的绘制方式。开发人员可以选择通过使用颜色、符号和渲染器来改变和增强要素的显示方式来覆盖这种行为。

您可以使用`setSymbol()`方法将符号应用于单个图形。当您想要将符号应用于动态、要素或图形图层中的所有图形时，可以使用渲染器。

渲染器使得可以快速地对许多要素进行符号化，可以使用单个符号或基于属性值使用多个符号。

ArcGIS API for JavaScript 中提供的一些渲染器如下：

+   `SimpleRenderer`：将相同的符号应用于图层中的所有图形

+   `UniqueValueRenderer`：根据每个图形的唯一属性值应用特定的符号

+   `ClassBreaksRenderer`：根据属性值的范围应用不同大小或颜色的符号

+   `DotDensityRenderer`：显示离散空间现象的空间密度变化

+   `HeatmapRenderer`：将点数据转换为显示高密度或加权区域集中度的光栅显示，使用模糊半径和强度值

+   `TemporalRenderer`：这可视化地图当前范围内的实时或历史观测，考虑相对要素老化和观测事件发生的轨迹，如飓风。

+   `ScaleDependentRenderer`：这根据地图的当前比例尺对同一图层应用不同的渲染器。

## 为场景选择渲染器

API 文档中的符号和渲染器指南提供了一个很好的指南，介绍了如何使用符号和渲染器。文档可以在[`developers.arcgis.com/javascript/jshelp/inside_renderers.html`](https://developers.arcgis.com/javascript/jshelp/inside_renderers.html)上访问。

`UniqueValueRenderer`和`ClassBreaksRenderer`是基于属性的渲染器。这意味着属性值决定了要素的符号化方式。要确定在特定情况下使用`UniqueValueRenderer`还是`ClassBreaksRenderer`，需要考虑需要进行分类的字段值的性质。

### 注意

如果要渲染的字段上的唯一值集合较小且离散，请考虑使用`UniqueValueRenderer`。

如果要渲染的字段上的唯一值集合具有广泛范围和/或是连续的，请考虑使用`ClassBreaksRenderer`。

`UniqueValueRenderer`和`ClassBreaksRenderer`具有`defaultSymbol`属性，当值或断点无法匹配时会使用。在开发过程中，您可以使用具有高对比度颜色的默认符号，快速验证是否有任何要素未能匹配渲染器的标准。

## 开发流量计应用程序

我们将开发一个流量计应用程序，以演示如何使用以下渲染器：

+   简单渲染器

+   独特值渲染器

+   类别分隔渲染器

+   热力图渲染器

### 数据源

流量计数据由 Esri 提供，作为其世界地图集的一部分。这意味着我们需要有 ArcGIS 开发者登录才能访问内容。流量计数据的地图服务的 URL 是[`livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/StreamGauge/MapServer/`](http://livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/StreamGauge/MapServer/)。

地图服务提供了美国各地的流量计读数，显示了测量区域的当前水位。我们试图开发的应用程序旨在演示不同的渲染技术在流量计数据上的应用。下一节中即将呈现的快照提供了我们在本章结束时将开发的最终应用程序的初步呈现。

如果您没有 ArcGIS 开发者帐户，请参考第三章*编写查询*，了解如何注册帐户并在应用程序代理中使用凭据的说明。

## 简单渲染器

`SimpleRenderer`由`esri/renderers/SimpleRenderer`模块提供，其构造函数接受任何适当的符号或 JSON。由于所有的流量计位置都是点位置，我们将使用`SimpleMarkerSymbol`来对其进行符号化。

由于我们已经讨论了如何从相应的模块构建`PictureMarkerSymbol`，我们将看到如何使用符号的 JSON 形式。使用符号的 JSON 表示意味着我们不再需要为每个符号和颜色单独加载模块。以下快照显示了 JSON 是如何形成并在`SimpleRenderer`构造函数中使用的：

![简单渲染器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_09.jpg)

在前面的代码中，在渲染器分配为`SimpleRenderer`之后，必须使用`setRenderer()`方法将渲染器对象设置为要素图层。此外，一旦渲染应用到要素图层上，图例应该被刷新：

```js
streamLyr.setRenderer(renderer);
streamLyr.redraw();
legend.refresh();
```

## 应用独特值渲染器

唯一值渲染器由`esri/renderers/UniqueValueRenderer`模块提供。唯一值渲染器允许我们为数据中一组唯一值定义不同的符号。最多可以提供三个属性字段来确定数据的唯一性。唯一值渲染器期望`uniqueValueInfos`对象。该对象基本上是唯一值和用于表示该值的符号之间的映射。因此，所有具有特定值的要素将由相应的映射符号渲染。我们可以为渲染器提供`defaultSymbol`对象，该对象将用于表示在`uniqueValueInfos`对象中未定义的任何值。以下是 JSON 表示唯一值渲染器对象，用于表示洪水阶段的唯一值。我们要表示的洪水阶段的唯一值如下：

+   `主要`

+   `适度`

+   `次要`

+   `行动`

```js
var rendererJson = {
  "type": "uniqueValue",
  "field1": "STAGE",
  "defaultSymbol": {},
  "uniqueValueInfos": [{
    "value": "major",
    "symbol": {
      "color": [163, 193, 163],
      "size": 6,
      "type": "esriSMS",
      "style": "esriSMSCircle"
    }
        }, {
    "value": "moderate",
    "symbol": {
      "color": [253, 237, 178],
      "size": 6,
      "type": "esriSMS",
      "style": "esriSMSCircle"
    }
        }, {
    "value": "minor",
    "symbol": {
      "color": [242, 226, 206],
      "size": 6,
      "type": "esriSMS",
      "style": "esriSMSCircle"
    }
        }, {
    "value": "action",
    "symbol": {
      "color": [210, 105, 30],
      "size": 6,
      "type": "esriSMS",
      "style": "esriSMSCircle"
    }
  }]
};
var renderer = new UniqueValueRenderer(rendererJson);
```

上述代码在应用程序中呈现如下：

![应用唯一值渲染器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_10.jpg)

以下属性可用于特征图层，根据多个视觉属性（如`颜色`、`旋转`、`大小`和`不透明度`）进行渲染：

| 渲染器方法 | 目的 |
| --- | --- |
| `setColorInfo()` | 这显示使用颜色渐变的连续值数组 |
| `setRotationInfo()` | 这会旋转一个符号以指示方向的变化（例如，行驶的车辆或飓风事件） |
| `setSizeInfo()` | 这会根据一系列数据值的范围更改符号大小或宽度 |
| `setOpacityInfo` | 这会更改用于显示图层的 alpha 值 |

## 类别分隔渲染器

当字段被分类和视觉区分时，它会分布在一系列值上，我们可以使用`ClassBreaksRenderer`。可以通过加载`esri/renderers/ClassBreaksRenderer`模块来使用`ClassBreaksRenderer`。

类别分隔渲染器与唯一值渲染器非常相似，因为类别分隔渲染器的构造函数期望一个`classBreakInfos`对象，这与`uniqueValueInfos`对象类似。

`classBreakInfos`是一个`classBreakInfo`对象数组，它将类范围和符号进行了映射。类范围由类的最小值（`classMinValue`）和类的最大值（`classMaxValue`）定义。

![类别分隔渲染器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_11.jpg)

以下快照显示了如何使用`classBreakInfo`数组构建`ClassBreakRenderer` JSON 对象，并在地图上呈现：

![类别分隔渲染器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_12.jpg)

## 热力图渲染器

`HeatmapRenderer`将点数据渲染成突出显示更高密度或加权值的光栅可视化。该渲染器使用正态分布曲线在垂直和水平方向上分布值。

这个平均函数被水平和垂直应用，以产生一个模糊的影响区域，而不是一个特定的单一点。

`HeatmapRenderer`模块构造函数接受一个颜色数组。第一种颜色用于表示*最小影响*的区域，数组中的最后一种颜色用于表示像素的最高影响。我们还可以为`HeatmapRenderer`构造函数定义其他参数，如`blurRadius`、最大像素强度和最小像素强度。以下代码快照用于生成`HeatmapRenderer`：

![热力图渲染器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_13.jpg)

## 点密度渲染器

`DotDensityRenderer`提供了创建数据的点密度可视化的能力。点密度地图可以用来可视化离散空间现象的空间密度变化。我们可以使用多个字段以不同颜色在同一地图上可视化多个变量。例如，我们可以使用不同的颜色来显示各种族群的分布。地图上的密度随着用户的放大或缩小而变化。使用`ScaleDependentRenderer`为每个比例或缩放范围设置唯一的点密度渲染器，以便`dotValue`和`dotSize`可以在多个比例范围内变化。

## BlendRenderer

`ClassBreakRenderer`或`UniqueValueRenderer`的问题在于，您必须为任何给定值分配特定的颜色。当基于明确的边界值分配离散颜色不可取时，我们可以使用`BlendRenderer`。

`BlendRenderer`让您对数据进行模糊分类。它允许您为不同字段的值分配不同的颜色，并使用一些不透明度来表示值的大小。由于我们对每个字段使用了不透明度，最终的渲染将是这些颜色的混合。这张图显示了如何混合颜色和不透明度变量以提供渲染：

![BlendRenderer](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_14.jpg)

以下地图显示了美国各地主要少数民族群体的地图。这样的插图可以给出主要特征的感觉，同时不完全压制其他细节：

![BlendRenderer](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_15.jpg)

## 智能映射

`SmartMapping`模块提供了许多辅助方法，帮助我们选择最佳的渲染方法。以下插图显示了`SmartMapping`模块提供的方法列表：

![SmartMapping](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_05_16.jpg)

### 注意

智能映射模块：`esri/renderers/smartMapping`

## 类别渲染器的分类方法

类别渲染器辅助方法，如`createClassedColorRenderer()`和`createClassedSizeRenderer()`，需要`classificationMethod`作为参数。如果我们需要理解每个值的重要性，选择这个值是非常重要的。

以下分类方法可用：

+   等间隔

+   自然断点

+   四分位数

+   标准差

默认方法是等间隔的。

等间隔分类将数据平均分成预定义数量的类别。这样的分类可能不一定反映数据的偏斜。例如，如果数据范围是 0-100 万，而大部分数据集中在 30 万-50 万之间，那么与其将数据分类为 0-25 万、25 万-50 万、50 万-75 万和 75 万-100 万，更好的分类方案是在 30 万-50 万之间有更多的分类范围。

自然断点、四分位数和标准差等分类方法有助于更好地分隔数据；因此，我们的数据可视化技术将在统计上更加准确。这个主题将在第七章中进行更详细的讨论，*地图分析和可视化技术*。

# 总结

本章深入探讨了颜色、符号、渲染器以及每种方法可以有效使用的情况。本章还涉及了数据可视化技术的细微差别，以及创建符号和图片标记符号的技巧和窍门。我们通过开发一个流量计应用程序来展示了三种基本渲染器的实用性：简单渲染器、唯一值渲染器和分级渲染器。在接下来的章节中，我们将探讨高级可视化技术，以在空间和时间尺度上对数据进行视觉分类。


# 第六章：处理实时数据

不断更新的数据给我们在检索和渲染它们方面带来了重大挑战。在本章中，我们将通过开发一个旨在跟踪飓风的应用程序来处理实时数据的两种基本方法。在本章中，您将学习以下主题：

+   了解实时数据的性质，如飓风数据

+   使用 ArcGIS 提供的内置选项来可视化数据

+   获取最新数据的方法

+   设置图层的刷新间隔的方法

# 应用程序背景

我们将处理由国家飓风中心（NHC）提供的飓风数据。NHC 提供了描述热带飓风活动路径和预测的地图服务。NHC 提供的实时数据可以在[`livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/Hurricane_Active/MapServer`](http://livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/Hurricane_Active/MapServer)找到。

地图服务提供以下数据：

+   **预测位置**

+   **观测位置**

+   **预测路径**

+   **观测路径**

+   **不确定性锥**

+   **警报和警告**

+   **热带风暴力**

预测和观测位置代表飓风的中心，而路径代表连接的预测和观测位置，以便了解飓风的移动方向。

![应用程序背景](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_06_01.jpg)

在**服务目录**标题下，单击**ArcGIS.com 地图**以全面了解地图服务中的数据。

# 可视化地图数据

ArcGIS Online 是可视化和使用 ArcGIS Server 上托管的数据的有效媒介。在 ArcGIS Online 中打开地图服务时，会显示默认的符号，并且我们可以了解我们在应用程序中将要使用的数据的范围。

在以下截图中，我们可以看到**预测位置**要素图层及其默认符号。使用的符号是 PictureMarkerSymbol，它可以让我们了解过去三天（72 小时）飓风的强度。

![可视化地图数据](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_06_02.jpg)

以下截图全面展示了地图服务中的所有数据，包括预测位置和路径，以及观测位置：

![可视化地图数据](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_06_03.jpg)

关闭目录中的所有图层，只打开**观测位置**图层。**观测位置**图层只是由简单的渲染器渲染的。符号不会根据任何字段值的大小而变化。它只显示过去 72 小时内测得的风暴活动的位置。

![可视化地图数据](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_06_04.jpg)

现在 ArcGIS Online 为我们提供了各种设置其符号的选项。当我们在目录中点击图层的名称时，会打开以下屏幕。它显示了基于哪些样式可以更改符号。在以下截图中，**强度**的风暴被选择为显示的字段，并且符号的大小基于**强度**值的数量：

![可视化地图数据](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_06_05.jpg)

数据可以根据各种分类技术进行分类，例如**等间隔**、**分位数**、**自然间隔**等。

![可视化地图数据](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_06_06.jpg)

最后，**观测路径**实际上显示了过去 72 小时飓风所经过的路径，并使用唯一值渲染器来渲染数据。

![可视化地图数据](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_06_07.jpg)

# 构建飓风追踪应用程序

现在我们已经通过 ArcGIS Online 服务了解了我们的数据，我们可以使用地图服务 URL 构建自己的网络地图应用程序。在我们的应用程序中，我们打算包括以下内容：

+   向地图添加显示过去和现在飓风位置的图层

+   添加全球风数据

+   添加一个仪表小部件来显示风速

+   添加一个当前天气小部件，显示用户浏览器位置的当前天气信息

+   添加一个**当前飓风列表**小部件，显示当前飓风的更新列表以及选择时每个飓风的详细信息

## 符号化活跃的飓风层

我们有多个要处理的要素层。让我们尝试构建一个图层字典。在以下代码片段中，我们将尝试创建一个对象数组，其中每个对象都具有诸如 URL 和标题之类的属性。URL 是指要素层的 URL，标题属性是指我们想要引用要素层的标题：

```js
var windDataURL = "http://livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/NOAA_METAR_current_wind_speed_direction/MapServer";

var activeHurricaneURL = "http://livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/Hurricane_Active/MapServer";

var layerDict = [
          {
            title: "Forecast Error Cone",
            URL: activeHurricaneURL + "/4"
          },
          {
            title: "Forecast Tracks",
            URL: activeHurricaneURL + "/2"
          },
          {
            title: "Observed Track",
            URL: activeHurricaneURL + "/3"
          },
          {
            title: "Watches and Warnings",
            URL: activeHurricaneURL + "/5"
          },
          {
            title: "Forecast Positions",
            URL: activeHurricaneURL + "/0"
          },
          {
            title: "Past Positions",
            URL: activeHurricaneURL + "/1"
          },
          {
            title: "Wind Data",
            URL: windDataURL + "/0"
          }
        ];
```

这有助于我们使用图层名称或标题属性检索要素层。让我们使用`dojo/_base/array`模块提供的`array.map()`方法将每个对象的相应要素层添加到`layerDict`数组中。`array.map()`方法，如果你还记得第一章, *API 的基础*，实际上是遍历数组中的元素并返回一个数组。然后，可以修改正在迭代的每个项目。在我们的情况下，我们正在尝试对每个项目执行以下操作：

1.  从每个项目的 URL 创建一个要素层。

1.  将要素层添加到地图中。

1.  在`layerDict`数组中的每个项目对象中添加一个额外的图层属性。

以下代码片段解释了这个过程：

```js
var layerDict = array.map(layerDict, function (item) {
          var featLayer = new FeatureLayer(item.URL, {
            mode: FeatureLayer.MODE_ONDEMAND,
            outFields: ["*"]
              //infoTemplate: infoTemplate
          });
          map.addLayer(featLayer);
          item.layer = featLayer;
          return item;
        });
```

现在`layerDict`数组中的每个对象都将具有一个额外的图层属性，该属性保存了由 URL 引用的要素层。

要检索要素层，我们可以使用`dojo/_base/array`模块提供的`array.filter()`方法中的图层名称。`filter`方法()遍历每个对象项，并根据我们的谓词条件返回一个过滤后的数组。

以下代码行返回标题为“预测误差锥”的要素层，并将其保存在名为`foreCastErrorConeFeatureLayer`的变量中：

```js
var foreCastErrorConeFeatureLayer = array.filter(layerDict, function (item) 
{
  return item.title == "Forecast Error Cone";
})[0].layer;
```

我们正在尝试对一些要素层中的要素进行符号化。我们将从过去的位置开始。过去的位置特征层默认情况下由一个带有中心点的圆表示。我们将尝试使用红旗来表示它。将采取以下方法来对其进行符号化：

1.  导入`esri/symbols/PictureMarkerSymbol`模块。

1.  查找代表红旗的 PNG 的 URL，并使用它创建一个`PictureMarkerSymbol`。

1.  导入`esri/renderers/SimpleRenderer`模块，并创建一个`SimpleRenderer`，为渲染器分配我们刚刚创建的`PictureMarkerSymbol`的符号。

1.  为要素层设置我们刚刚创建的简单渲染器的渲染器。

以下代码行清楚地解释了这个过程：

```js
var pastPositionLayer = array.filter(layerDict, function (item) {
    return item.title == "Past Positions";
})[0].layer;

var pastPositionSymbol = new PictureMarkerSymbol({
  "angle": 0,
  "type": "esriPMS",
  "url": http://static.arcgis.com/images/Symbols/Basic/RedFlag.png",
  "contentType": "image/png",
  "width": 18,
  "height": 18
});

var pastPositionRenderer = new SimpleRenderer(pastPositionSymbol);
pastPositionLayer.setRenderer(pastPositionRenderer);
```

现在，我们可以尝试渲染预测误差锥层。预测误差锥是代表预测预测中的不确定性的多边形要素层。每种飓风类型都有两个多边形要素。一个多边形代表 72 小时的预测误差多边形，另一个代表 120 小时的预测误差多边形。这些信息在要素层的`FCSTPRD`字段中可用。

让我们创建一个唯一值渲染器，并根据`FCSTPRD`字段名称的值以不同的方式对每种类型的多边形进行符号化。要创建唯一值渲染器，我们需要采取以下方法：

1.  导入`esri/renderers/UniqueValueRenderer`，`esri/symbols/SimpleLineSymbol`和`esri/symbols/SimpleFillSymbol`模块。

1.  为渲染器创建一个默认符号。由于我们知道对于所有我们的`预测误差`多边形，`FCSTPRD`字段值将是`72`或`120`，我们将创建一个具有空符号的`SimpleFillSymbol`，并将其轮廓设置为 null 线符号。

1.  从`esri/renderers/UniqueValueRenderer`模块创建一个`UniqueValueRenderer`对象。将其分配为我们刚刚创建的默认符号以及`FCSTPRD`作为渲染基础的字段名。

1.  使用`addValue()`方法向渲染器添加值。`addValue()`方法接受每个唯一值（`72` / `120`）及其对应的符号。

1.  将渲染器设置为`预测误差锥体要素图层`。

```js
**//Get the Forecast Error Cone feature layer**
var foreCastErrorConeFeatureLayer = array.filter(layerDict, function (item) {
  return item.title == "Forecast Error Cone";
})[0].layer;

**//Create a Null SimpleFillSymbol**
var defaultSymbol = new SimpleFillSymbol().setStyle(SimpleFillSymbol.STYLE_NULL);

**//With a null Line Symbol as its outline**
defaultSymbol.outline.setStyle(SimpleLineSymbol.STYLE_NULL);

var renderer = new UniqueValueRenderer(defaultSymbol, "FCSTPRD");

**//add symbol for each possible value**
renderer.addValue('72', new SimpleFillSymbol().setColor(new Color([255, 0, 0, 0.5])));
renderer.addValue('120', new SimpleFillSymbol().setColor(new Color([255, 255, 0, 0.5])));

**//Set Renderer**
foreCastErrorConeFeatureLayer.setRenderer(renderer);
```

我们已经尝试使用`PictureMarkerSymbol`标志化要素图层，并使用`SimpleRenderer`进行渲染。对于另一个要素图层，我们使用了唯一值渲染器，以不同的方式渲染具有特定字段不同值的要素。现在让我们尝试一种称为`CartographicLineSymbol`的特殊符号。

`CartographicLineSymbol`提供了额外的属性，如端点和连接，定义了线的端点和边缘连接的呈现方式。要了解有关这两个属性的更多信息，请访问 API 页面[`developers.arcgis.com/javascript/jsapi/cartographiclinesymbol-amd.html`](https://developers.arcgis.com/javascript/jsapi/cartographiclinesymbol-amd.html)。

我们想要使用`CartographicLineSymbol`来标志预测轨迹要素图层。以下显示了如何使用该符号并渲染特定要素图层：

1.  导入`esri/symbols/CartographicLineSymbol`模块。

1.  对于样式参数，使用`STYLE_DASHDOT`，颜色参数为黄色，像素宽度为`5`，端点类型为`CAP_ROUND`，连接类型为`JOIN_MITER`。

1.  使用`SimpleRenderer`的符号。

1.  将渲染器设置为预测轨迹要素图层。

以下代码片段对先前的方法进行了编码：

```js
var lineSymbol = new CartographicLineSymbol(
  CartographicLineSymbol.STYLE_DASHDOT,
  new Color([255, 255, 0]), 5,
  CartographicLineSymbol.CAP_ROUND,
  CartographicLineSymbol.JOIN_MITER, 5
);
var CartoLineRenderer = new SimpleRenderer(lineSymbol);

forecastTrackLayer.setRenderer(CartoLineRenderer);
```

当先前的渲染器应用于过去位置图层、**预测轨迹**和**预测误差锥体**图层时，我们的地图如下所示：

![标志化活动飓风图层](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_06_08.jpg)

# 添加全球风数据仪表

全球风数据也是 ArcGIS 实时数据提供的地图服务，提供各个位置的全球级风数据。我们的目标是合并一个仪表部件，根据悬停的风位置改变其仪表读数。风数据已经被适当地默认标志化。

以下屏幕截图显示了基于我们的全球风数据的仪表部件。地图中的箭头是风特征位置，箭头的方向表示风的方向，箭头的颜色和大小表示风的速度。两个示例中的仪表读数表示悬停在其上的特征（由一个粗黄色圆圈突出显示）。

![添加全球风数据仪表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_06_09.jpg)

风数据的 URL 已在我们先前的代码片段中提供，并已添加到`layerDict`数组中：

```js
var activeHurricaneURL = "http://livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/Hurricane_Active/MapServer";
```

由于此 URL 已添加到`layerDict`数组中，我们可以继续创建一个表示来自其标题`"Wind Data"`的风数据的要素图层：

```js
var windFeatureLayer = array.filter(layerDict, function (item) {
          return item.title == "Wind Data";
        })[0].layer;
```

现在让我们添加一个仪表部件，可以利用来自该图层的数据。该仪表由 Esri 的`dijit`（dojo 部件）`esri/dijit/Gauge`提供。仪表构造函数非常简单。它接受一个`GaugeParameter`对象和容器 dom ID。

`GaugeParameter`对象需要我们构建。在创建`GaugeParameter`对象之前，请记住以下几点：

1.  `layer`属性接受表示要素图层的引用。

1.  `dataField`属性指示应使用哪个字段来获取仪表读数。

1.  `dataFormat`属性接受两个值——`value`或`percent`。当选择百分比时，仪表的最大值会自动计算，并且仪表读数显示为最大值的百分比。当`dataFormat`值选择为`value`时，悬停的要素的实际值将显示为仪表读数。

1.  `dataLabelField`属性可用于表示站点名称或关于所悬停特征的任何其他辅助属性，这些属性可以标识特征。这应该与`title`属性结合使用，它表示`dataLabelField`属性表示的内容。

1.  `color`属性让我们设置仪表读数的颜色。

1.  如果`value`被选择为`dataFormat`的值，我们还需要为`maxDataValue`属性提供一个值。

以下代码是我们用来创建你在之前截图中看到的风速计小部件的代码：

```js
var windGaugeParams = {
          caption: "Wind Speed Meter",
          dataFormat: "value",
          dataField: 'WIND_SPEED',
          dataLabelField: "STATION_NAME",
          layer: windFeatureLayer,
          color: "#F00",
          maxDataValue: 80,
          title: 'Station Name',
          unitLabel: " mph"
        };
var windGauge = new Gauge(windGaugeParams, "gauge");
windGauge.startup();
```

# 跟踪最新的活跃飓风

让我们创建一个小部件来跟踪最新的活跃飓风。我们已经有了代表活跃飓风位置的所有图层。我们的目标是获取所有活跃飓风的最新位置，并在小部件中显示出来。

以下截图显示了我们的小部件在开发后的样子：

![跟踪最新的活跃飓风](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_06_10.jpg)

小部件中的下拉框列出了所有流行的活跃飓风的名称。以下网格显示了所选飓风的详情。

以下思路已经纳入到了这个小部件的开发中：

1.  使用缓存破坏查询来获取风暴名称的唯一列表，并用这个列表填充下拉框。

1.  在下拉框的选择更改时，获取所选风暴的最新要素。

1.  在小部件中填充所选风暴的详情。

1.  每 30 秒获取更新的详情。

## 获取风暴的唯一列表

为了获取我们数据中的唯一值，查询对象有一个名为`returnDistinctValues`的属性，其值应为布尔值`true`。以下代码片段解释了该属性的用法：

```js
query.returnDistinctValues = true;
```

此外，查询对象的 outfield 属性应该只列出那些需要唯一值的字段。在我们的情况下，字段名是`STORMNAME`。请参考以下代码片段以了解这一点：

```js
query.outFields = ["STORMNAME"];
```

为了每次都能获得更新的结果，我们需要避免缓存的查询结果。所以我们可能需要使用一个类似于`1=1`的模式，而不是使用一个真值表达式。

```js
"random_number = random_number".
```

这将帮助我们获得非缓存的查询结果。非缓存的查询结果确保我们在一定时间内查看到的是最新数据。让我们编写一个可以创建这样的查询字符串的函数：

```js
var _bust_cache_query_string: function () {
  var num = Math.random();
  return num + "=" + num;
}
```

现在我们可以在每次需要为查询对象的`where`属性分配一个值时使用这个函数：

```js
query.where = this._bust_cache_query_string();
```

在查询对象中使用`returnDistinctValues`属性时，我们需要将`returnGeometry`属性设置为布尔值`false`。以下代码解释了如何形成查询任务和查询对象，以及如何使用查询结果来填充下拉框。在代码的结尾，我们将调用一个`_update_hutticane_details()`方法。这个方法获取所选`StormName`的最新详情：

```js
events: function () {
  //initialize query task
  var queryTask = new QueryTask("http://livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/Hurricane_Active/MapServer/1");

  //initialize query
  var query = new Query();
  query.returnGeometry = false;
  query.where = "1=1 AND " + this._bust_cache_query_string();
  query.outFields = ["STORMNAME"];
  query.returnDistinctValues = true;
  var that = this;

  queryTask.execute(query, function (result) {
    console.log(result);

    var i;
    //Remove all existing items

    for (i = that.cbxactiveHurricane.options.length - 1; i >= 0; i--) {
      that.cbxactiveHurricane.remove(i);
    }
    //Fill n the new values
    array.forEach(result.features, function (feature) {
      console.debug(feature.attributes.STORMNAME);
      that.cbxactiveHurricane.options[that.cbxactiveHurricane.options.length] = new Option(feature.attributes.STORMNAME, feature.attributes.STORMNAME);
    });
    that._update_hutticane_details();
  });

this.updateTimmer = setInterval(lang.hitch(this, this._update_hutticane_details), 30000);
}
```

在前面的代码行中，观察最后三行。我们使用一个`timer`函数，每 30 秒调用一次`_update_hutticane_details()`。这是一个获取飓风最新详情的函数。

## 获取最新数据并在网格上显示

在前面的代码片段中，当我们尝试构建查询对象时，我们使用了`returnDistinctValues`属性来根据字段名获取不同的值。现在我们将使用查询对象的`orderByFields`属性来根据字段名对要素进行排序。为了首先获取最新的要素，字段名应该代表一个时间字段。在我们的情况下，字段名是`DTG`。为了确保我们获取查询结果的最新时间作为第一个要素，我们可以在构建查询对象时使用以下代码行。`orderByField`接受一个字符串数组，每个项目都提到了要根据哪个字段名进行排序，以及排序是升序(`ASC`)还是降序(`DESC`)。默认顺序是升序：

```js
query.orderByFields = ["DTG DESC"];
```

以下代码行演示了如何构建所需的查询对象以及如何使用结果来填充小部件中关于最新风暴的信息：

```js
_update_hutticane_details: function () {
  var selected_hurricane = this.cbxactiveHurricane.value;

  var queryTask = new QueryTask("http://livefeeds.arcgis.com/arcgis/rest/services/LiveFeeds/Hurricane_Active/MapServer/1");
  var query = new Query();
  query.returnGeometry = true;
  query.where = "STORMNAME='"+ selected_hurricane +"' AND " + this._bust_cache_query_string();
  query.outFields = ["*"];
  **query.orderByFields = ["DTG DESC"];**
  var that = this;
  queryTask.execute(query, function (result) {
    console.log(result);
    if (result.features.length>0){
      that._mslp.innerHTML = result.features[0].attributes.MSLP;
      that._basin.innerHTML = result.features[0].attributes.BASIN;
      that._stormnum.innerHTML = result.features[0].attributes.STORMNUM;
      that._stormtype.innerHTML = result.features[0].attributes.STORMTYPE;
      that._intensity.innerHTML = result.features[0].attributes.INTENSITY;
      that._ss.innerHTML = result.features[0].attributes.SS;
    }
  });
}
```

请注意上一段代码中的`where`子句。我们仅选择了从下拉框中选择的`StormName`的详细信息，并使用缓存破坏函数获取最新数据：

```js
query.where = "STORMNAME='"+ selected_hurricane +"' AND " + this._bust_cache_query_string();
```

### 刷新要素图层

显示时间数据的要素图层可能需要在各种间隔时间刷新。我们可以使用要素图层来刷新间隔属性以设置此功能：

```js
featureLayer. refreshInterval = 5; // in minutes
```

这是我们之前处理的缓存破坏技术的补充。

# 创建天气小部件

我们将尝试在我们的应用程序中创建一个天气小部件，该小部件显示用户所在位置的当前天气状况。用户的位置实际上是指现代浏览器中地理位置 API 识别的浏览器位置。当浏览器无法找到用户的位置时，我们将尝试找到地图中心的天气数据。创建天气小部件为我们提供了以下机会和挑战：

+   天气数据在实时不断更新，并且是一个时空现象，意味着随着地点和时间的变化而变化

+   它为我们提供了使用外部天气 API 的机会，这是一个非 ArcGIS 基础的数据

+   它为我们提供了一个探索客户端几何操作的机会，例如缓冲区和地理和 Web 墨卡托坐标之间的转换

## 开放天气 API

我们需要找到一个数据源来获取最新的天气数据。幸运的是，开放天气 API 是获取不同格式的天气数据的简单免费选项。付费计划提供更大的使用级别。对于我们的目的，免费版本效果很好。

该 API 提供 REST 端点，可提供以下类型的数据：

+   当前天气数据

+   5 天/3 小时预报

+   5 天/3 小时预报

+   历史数据

+   紫外线指数

+   天气地图图层

+   气象站

我们将使用当前天气数据端点来获取给定位置的天气详情。

要访问 API，您需要注册 API 密钥。以下 URL 解释了如何获取`appid`并在 REST 查询中使用它：[`openweathermap.org/appid#get`](http://openweathermap.org/appid#get)。

我们将使用的基本 URL 是这个：

```js
var url = "http://api.openweathermap.org/data/2.5/weathers";
```

我们将提供纬度和经度值以发出请求到开放天气 API。我们尝试使用`esriRequest`对象进行 HTTP `GET`请求，需要导入`esri/request`模块。以下片段解释了如何构建`esriRequest`对象：

```js
var request = esriRequest({
  // Location of the data
  url: this.url + '?lat=' + this.lat + '&lon=' + this.lon + '&appid=' + this.apikey,

  handleAs: "json"
});
```

如果观察正在构建的 URL，它需要三个参数，即`lat`、`lon`和`appid`。

`appid`参数接受我们之前生成的应用程序密钥。我们将遵循两种方法来获取纬度和经度值：

1.  如果浏览器支持地理位置 API，则从浏览器位置获取纬度和经度值。

1.  如果浏览器不支持地理位置 API，则将地图范围的中心点投影到地理坐标，并用于获取该位置的天气数据。

## 使用地理位置 API

使用地理位置 API 就像调用导航器对象的`geolocation.getCurrentPosition()`方法一样简单。该方法返回一个回调对象，其中包含浏览器的位置。以下代码行显示了如何调用`geolocation`API 以获取浏览器的当前位置：

```js
getLocation: function () {
  if (navigator.geolocation) {
    navigator.geolocation.getCurrentPosition(lang.hitch(this, this.showPosition));
  } else {
    console.log("Geolocation is not supported by this browser.");
  }
}
```

在上述代码中，调用对象是一个名为`showPosition()`的函数。`showPosition()`函数将位置作为回调对象。可以使用`coords`属性访问位置的坐标。

### 在输入数据上使用几何引擎

`coords`对象具有三个属性，即：

+   `纬度`

+   `经度`

+   `准确性`

我们清楚地了解了纬度和经度，但精度是什么？精度是表示由 API 提供的坐标可能存在的误差的数值数量，单位为米。换句话说，位置在一个误差圆内是准确的。当我们提到它是一个误差圆时，能否在地图上将其可视化，这样我们就可以知道浏览器的大致位置，也许可以证实结果。我们尝试了一下；看起来相当准确。为了创建一个误差圆，我们采取了以下方法：

1.  使用纬度和经度值创建一个点几何体。

1.  使用 API 提供的`webMercatorUtils`将点从地理坐标转换为 Web 墨卡托坐标。

1.  使用 API 提供的`geometryEngine`模块，围绕投影点创建一个缓冲区，缓冲区半径等于位置的精度。

1.  使用`SimpleFillSymbol`对缓冲区几何进行符号化。

以下代码行清楚地解释了前面的过程：

```js
showPosition: function (position) {
  console.log(position);
  this.accuracy = position.coords.accuracy;
  this.lat = position.coords.latitude;
  this.lon = position.coords.longitude;

  //error circle
  var location_geom = new Point(this.lon, this.lat, new SpatialReference({ wkid: 4326 }));
  var loc_geom_proj = webMercatorUtils.geographicToWebMercator(location_geom);
  var location_buffer = geometryEngine.geodesicBuffer(loc_geom_proj, this.accuracy, "meters", false);

  console.log(location_buffer);
  var symbol = new SimpleFillSymbol().setColor(new Color([255, 0, 0, 0.5]));
  this.map.graphics.add(new Graphic(location_buffer, symbol));
  //this.map.setExtent(location_buffer.getExtent());
  this.getWeatherData();
}
```

我们将使用从`showPosition()`方法获取的纬度和经度来获取该位置的天气数据。

## 在小部件中显示天气数据

我们之前讨论了如何使用`esriRequest`模块向天气 API 发出 HTTP GET 请求，并请求获取浏览器提供的纬度和经度的当前天气数据。该请求是一个 promise，我们将使用`then`方法来解析它。

下面的代码块演示了`esriRequest` promise 是如何被解析以及如何用来显示当前天气数据的：

```js
request.then(function (data) {
  console.log("Data: ", data);
  that.weather.innerHTML = Math.round(data.main.temp - 270) + " deg C " +
  data.weather[0].main + ' (' + data.weather[0].description + ')';
  var imagePath = "http://openweathermap.org/img/w/" + data.weather[0].icon + ".png";
  // Set the image 'src' attribute
  domAttr.set(that.weatherIcon, "src", imagePath);
  that.windSpeed.innerHTML = data.wind.speed + ' kmph';
  that.cloudiness.innerHTML = data.clouds.all + ' %';
  that.pressure.innerHTML = data.main.pressure;
  that.humidity.innerHTML = data.main.humidity + ' %';
  that.pressure.innerHTML = data.main.pressure + ' Pa'
  that.sunrise.innerHTML = that._processDate(data.sys.sunrise);
  that.sunset.innerHTML = that._processDate(data.sys.sunset);
  that.coords.innerHTML = data.coord.lon + ', ' + data.coord.lat;
}
```

在之前的代码中，温度总是以开尔文返回。因此，为了将其转换为摄氏度，我们需要减去`270`。时间转换是使用名为`_processDate()`的函数应用的。由 open weather API 发布的时间是基于 UTC 的 Unix 时间。

我们编写的`_processDate()`函数如下所示：

```js
_processDate: function (dateStr) {
  if (dateStr == null) {
    return "";
  }
  var a = new Date(dateStr * 1000);
  return dateLocale.format(a, {
    selector: "date",
    datePattern: "yyyy-MM-dd HH.mm v"
  });
}
```

在前面的函数中使用的`dateLocale`对象是一个 dojo 模块（`dojo/date/locale`），它提供了处理的`date`对象的本地化时间版本。小部件如下所示。红色圆圈就是我们谈论的误差圆。我们还能够创建一个小的天气图标，总结天气状况。

![在小部件中显示天气数据](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_06_11.jpg)

如果你好奇之前小部件的 HTML 模板会是什么样子，我们有一件事要说——我们让你失望了吗？在这里：

```js
<div>
  <form role="form">
    <div class="form-group">
      <label dojoAttachPoint="weather"></label>
      <img dojoAttachPoint="weatherIcon"/>
    </div>
  </form>
  <table class="table table-striped">
    <tbody>
      <tr>
        <td>Wind</td>
        <td dojoAttachPoint="windSpeed"></td>
      </tr>
      <tr>
        <td>Cloudiness</td>
        <td dojoAttachPoint="cloudiness"></td>
      </tr>
      <tr>
        <td>Pressure</td>
        <td dojoAttachPoint="pressure"></td>
      </tr>
      <tr>
        <td>Humidity</td>
        <td dojoAttachPoint="humidity"></td>
      </tr>
      <tr>
        <td>Sunrise</td>
        <td dojoAttachPoint="sunrise"></td>
      </tr>
      <tr>
        <td>Sunset</td>
        <td dojoAttachPoint="sunset"></td>
      </tr>
      <tr>
        <td>Geo coords</td>
        <td dojoAttachPoint="coords"></td>
      </tr>
    </tbody>
  </table>
</div>
```

无害的 HTML 模板是我们开发天气小部件所需的全部内容，我们用它来显示我们所在位置的当前天气数据。

# 总结

在本章中，我们详细介绍了实时数据的构成以及如何可视化和获取最新特性。我们将讨论如何处理时态图层以及如何在后续章节中可视化时空图层。因此，我们将能够构建持续刷新的有效网络应用程序。在接下来的章节中，我们将讨论使用要素图层的统计功能的高级可视化技术，并学习有关图表库的知识。


# 第七章：地图分析和可视化技术

对地图数据进行分析将揭示许多空间模式，否则这些模式将保持隐藏。 API 提供了许多方法来使用数据上的高级统计查询来获取这些信息。结合 API 提供的直观数据可视化方法，您将更接近成为地图数据科学家。在本章中，我们将首先尝试了解一些基本的统计概念，然后通过在 API 提供的分析和渲染模块的帮助下在代码中实际应用这些概念。具体来说，我们将涵盖以下主题：

+   介绍我们将要开发的人口统计分析门户

+   基本统计量介绍

+   API 提供的模块来计算要素统计信息

+   分类方法的简要介绍

+   使用代码支持的解释来开发具有视觉变量的渲染器

+   执行多变量映射

+   使用智能映射执行自动映射

# 构建人口统计分析门户

我们将构建一个人口统计分析门户，以展示 API 的高级分析功能。人口统计是指根据各种社会经济因素对居住在某一地区的人口进行分类，例如年龄、教育程度、国籍、家庭收入中位数、种族、性别等。人口统计数据主要基于人口普查数据和其他可靠来源。

人口统计数据可用于执行各种分析，并且对政府做出政策决策和企业做出营销决策同样有用。人口统计数据的力量在于执行适当的分析，以便我们可以提取有关居住在某一地区的人口与周围人口的有用信息。让我们考虑这个网址，它提供了关于街区层面的家庭收入中位数的详细统计数据 - [`demographics5.arcgis.com/arcgis/rest/services/USA_Demographics_and_Boundaries_2015/MapServer`](http://demographics5.arcgis.com/arcgis/rest/services/USA_Demographics_and_Boundaries_2015/MapServer)。

该地图服务显示了 2015 年美国最新的人口统计数据。在提供的数百个人口统计参数中，我们对 2015 年美国家庭收入中位数感兴趣。收入金额以当前美元表示，包括通货膨胀或生活成本增加的调整。中位数是将家庭收入分布为两个相等部分的值。有关此地图的更多信息，包括使用条款，请访问此网址：[`doc.arcgis.com/en/living-atlas/item/?itemId=6db428407492470b8db45edaa0de44c1&subType=demographics`](http://doc.arcgis.com/en/living-atlas/item/?itemId=6db428407492470b8db45edaa0de44c1&subType=demographics)

这些数据是 Esri 的 Living Atlas 项目的一部分。要使用这些数据，您将需要 ArcGIS Online 组织订阅或 ArcGIS 开发人员帐户。要访问此项目，您需要执行以下操作之一：

+   使用组织订阅的成员帐户登录

+   使用开发人员帐户登录

+   如果您没有帐户，可以在此链接[https://developers.arcgis.com/en/sign-up/]注册 ArcGIS 的免费试用版或免费的 ArcGIS 开发人员帐户

# 基本统计量

让我们讨论一些基本统计数据，以便我们可以充分利用 API 提供的统计功能。在进一步进行之前，我们可能需要清楚地了解五个基本统计参数：

+   最小值

+   最大值

+   平均值

+   标准差

+   标准化

## 最小值

顾名思义，这意味着数据集中的最小值。在我们的案例中，对于街区级别的家庭收入，`最小`统计数据表示具有最低家庭收入中位数的街区。

## 最大值

与`最小`类似，`最大`统计量定义了所有考虑的街区中的最大家庭收入中位数值。

## 总和

`Sum`是一个简单而有效的统计量，它给出了所有考虑的数据的总值。

## 平均值

`Average`统计定义了所有值的算术平均值。平均值是通过将`Sum`统计量除以用于计算的数据值的计数来推导的。

```js
Average = Sum / Count
```

## 标准差

标准差可能是从任何给定数据中推导出的最重要的统计量。标准差是数据的分散程度或数据偏离平均值或平均值的度量。当我们知道标准差时，通常可以观察到：

+   68%的数值在平均值加减一个标准差的范围内

+   95%的数值在平均值加减两倍标准差的范围内

+   99.7%的数值在平均值加减三倍标准差的范围内

这是基于大多数数据遵循正态分布曲线的事实。当我们对数据进行排序并绘制数值时，直方图看起来像钟形曲线。

## 标准化

了解标准差和平均值的概念后，我们可以对数据进行标准化。这个过程被称为**标准化**，从这个过程中得到的统计量被称为**标准分数**（`z-score`）。当我们有大量值的数据集时，标准化是总结数据和量化数据的有效方法。

因此，要将任何值转换为标准分数（`z-score`），我们需要首先从平均值中减去该值，然后除以标准差。

```js
z-score = (Value – Mean)/Standard_Deviation
```

# API 提供的统计功能

让我们调查 API 在这些基本统计量方面提供了什么。稍后我们将在我们的应用程序中使用这些统计量，以更好地了解数据。我们还将在我们的可视化技术中使用这些技术。

## StatisticDefinition 模块

API 提供了一个名为`StatisticalDefinition`的模块，可以与查询任务和查询模块一起使用，提取我们刚刚讨论的基本统计量。

模块名称：`esri/tasks/StatisticDefinition`

以下是用于定义统计定义对象的属性：

+   `onStatisticField`：用于定义将计算统计量的字段

+   `outStatisticFieldName`：输出字段的名称

+   `statisticType`：用于定义统计类型。接受的统计类型包括：

+   `min`：获取最小统计量

+   `max`：获取最大统计量

+   `sum`：获取总和统计量

+   `avg`：推导平均值统计量

+   `stddev`：推导标准差统计量

让我们尝试在本章开头提供的人口统计图层 URL 上使用这些并推导这些统计量。

以下截图显示了一个代码片段，并解释了如何为人口统计地图服务中的县级图层推导这些统计量：

![StatisticDefinition 模块](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_07_01.jpg)

可以使用这个简单的代码片段提取所需的统计数据。

代码执行后，控制台屏幕应该如下所示：

```js
**Object {MAX_MEDHINC_CY: 113282, MIN_MEDHINC_CY: 18549, STDDEV_MEDHINC_CY: 10960.43202775655, AVG_MEDHINC_CY: 42115.877187400576}**
**Object {Plus1StdDev: 53076.309215157125, Plus2StdDev: 64036.741242913675, Plus3StdDev: 74997.17327067023, Minus1StdDev: 31155.445159644027, Mius2StdDev: 20195.013131887477…}**

```

稍后将使用推导的统计量，如`Plus1StdDev`、`Plus2StdDev`、`Plus3StdDev`、`Minus1StdDev`、`Minus2StdDev`和`Minus3StdDev`来更好地呈现数据。

## 分类方法

当我们有大量数据时，我们使用渲染方法对其进行分类。我们需要确定一个适当的分类方法来创建类别间断点。API 支持以下分类方法：

+   等间隔

+   自然断点

+   分位数

+   标准差

让我们简要讨论使用每种分类方法的影响。

### 等间隔

这种分类方法将数据分成相等的部分。我们需要知道数据范围以使用这种分类方法。当数据分散且分布良好时，应使用此方法。

![等间隔](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_07_02.jpg)

### 自然断点

自然断点是基于 Jenks 断点算法的分类方法。基本上，该算法在数据更加聚集的位置创建更多的断点。这是通过寻求最小化每个类的平均偏差来实现的，同时最大化每个类与其他组的平均值的偏差。换句话说，该方法旨在减少类内的方差，并最大化类间的方差。

![自然断点](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_07_03.jpg)

### 分位数

这种方法对数据进行分类，使每个组中的数据点数量相等。

### 标准差

如前所述，标准差是数据偏离平均值的度量。使用这种分类方法，我们可以找出数据偏离平均值超出三个标准差的程度（异常值的情况），在两个和三个标准差之间的数据（较高和较低的值），以及距离平均值一个标准差内的数据。

![标准差](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_07_04.jpg)

## 归一化概念

对数据值进行归一化对于计算许多事情都很有用。考虑以下情景：

+   **Case 1**：我们需要符号化每个州的人口密度。基于人口字段的符号化会给出错误的度量或传达错误的信息。我们可能只需要将每个州的人口除以其地理面积，以得到人口密度的度量。

同样，如果我们需要传达年轻人口（年龄<35 岁）占总人口的百分比，我们需要将拥有年轻人口的字段除以显示总人口的字段。

+   **Case 2**：当尝试符号化整个世界的收入分布时，我们可能会遇到大范围的值。如果我们使用颜色或不透明度渲染器，一些国家将位于光谱的较高端，而一些国家将位于底部，中间有许多国家，但实际上并没有使用太多的颜色信息。在这种情况下，使用对数刻度来显示收入分布将更有用。

+   **Case 3**：当我们需要计算值作为总数的百分比时，例如犯罪数据或每个州参加马拉松比赛的参与者人数，我们需要将该值除以总数。

许多渲染器都有`normalizationField`和`normalizationType`属性来实现这种归一化。

`normalizationField`让我们定义用于归一化的字段。例如，对于*Case 1*，`Area`字段和`Total Population`字段是`normalizationField`。

`normalizationType`是需要对值执行的归一化类型。`normalizationType`的三个可能值是 field、log 和 percent-of-total。例如，对于*Case 1*，我们需要使用`normalizationType`作为`field`。对于*Case 2*，我们需要使用`log`，对于*Case 3*，我们需要使用`percent-of-total`作为`normalizationType`。

## 要素图层统计

在 API 的 3.13 版本中，引入了这个插件，可以方便地计算要素图层的统计信息。使用要素图层统计插件，我们可以计算以下统计信息：

+   要素图层上的基本统计信息

+   类别断点统计

+   字段中的唯一值

+   查看图层的建议比例范围

+   获取样本要素

+   计算直方图

可以使用以下代码片段将插件添加到要素图层中：

```js
var featureLayerStats = new FeatureLayerStatistics({
          layer: CountyDemogrpahicsLayer
        });
```

在前面的代码片段中，`CountyDemogrpahicsLayer`是要添加`FeatureLayerStatistics`插件的要素图层的名称。

插件中使用的方法所期望的通常参数是`field`和`classificationMethod`。`field`插件是指根据其计算统计数据的属性字段的名称。`classificationMethod`是指根据先前讨论的分类方法之一，计算统计数据的方法：

```js
var featureLayerStatsParams = {
          field: "MEDHINC_CY",
          classificationMethod : 'natural-breaks'
        };
```

插件上的方法总是返回一个 promise。以下代码片段计算了在`featureLayerStatsParams`中定义的字段上的基本统计值：

```js
featureLayerStats.getFieldStatistics(featureLayerStatsParams).then(function (result) {
          console.log("Successfully calculated %s for field %s, %o", "field statistics", featureLayerStatsParams.field, result);
        }).otherwise(function (error) {
          console.log("An error occurred while calculating %s, Error: %o", "field statistics", error);
        });
```

结果在浏览器控制台中如下所示：

```js
**Successfully calculated field statistics for field MEDHINC_CY,**
**Object {  **
 **source:"service-query",**
 **min:20566,**
 **max:130615,**
 **avg:46193.26694241171,**
 **stddev:12564.308382029049,**
 **count:3143,**
 **sum:145185438,**
 **variance:157861845.1187254**
 **}**

```

之前的结果提供了与我们之前使用的统计定义模块得到的相同或更多的信息。

以下代码片段计算了在`featureLayerStatsParams`中定义的字段上的类别分隔值：

```js
featureLayerStats.getClassBreaks(featureLayerStatsParams).then(function (result) {
          console.log("Successfully calculated %s for field %s, %o", "class breaks", featureLayerStatsParams["field"], JSON.stringify(result));
        }).otherwise(function (error) {
          console.log("An error occurred while calculating %s, Error: %o", "class breaks", error);
        });
```

美化后的结果如下：

```js
**{**
 **"minValue": 20566,**
 **"maxValue": 130615,**
 **"classBreakInfos": [**
 **{**
 **"minValue": 20566,**
 **"maxValue": 27349.802772469,**
 **"label": " < -1.5 Std. Dev.",**
 **"minStdDev": null,**
 **"maxStdDev": -1.5**
 **},**
 **{**
 **"minValue": 27349.802772469,**
 **"maxValue": 39912.112219098,**
 **"label": "-1.5 - -0.50 Std. Dev.",**
 **"minStdDev": -1.5,**
 **"maxStdDev": -0.5**
 **},**
 **{**
 **"minValue": 39912.112219098,**
 **"maxValue": 52474.421665726,**
 **"label": "-0.50 - 0.50 Std. Dev.",**
 **"minStdDev": -0.5,**
 **"maxStdDev": 0.5,**
 **"hasAvg": true**
 **},**
 **{**
 **"minValue": 52474.421665726,**
 **"maxValue": 65036.731112354,**
 **"label": "0.50 - 1.5 Std. Dev.",**
 **"minStdDev": 0.5,**
 **"maxStdDev": 1.5**
 **},**
 **{**
 **"minValue": 65036.731112354,**
 **"maxValue": 77599.040558982,**
 **"label": "1.5 - 2.5 Std. Dev.",**
 **"minStdDev": 1.5,**
 **"maxStdDev": 2.5**
 **},**
 **{**
 **"minValue": 77599.040558982,**
 **"maxValue": 130615,**
 **"label": " > 2.5 Std. Dev.",**
 **"minStdDev": 2.5,**
 **"maxStdDev": null**
 **}**
 **],**
 **"source": "service-generate-renderer"**
**}**

```

# 使用连续和分级渲染器

连续渲染器是指在连续数值范围上对要素进行符号化的渲染器，与唯一值渲染器不同。我们需要为这些渲染器定义几个`stops`或`breakpoints`。这些`stops`定义了一个类，渲染器会检查每个值属于哪个类。根据类别，数据会通过可视化变量（如颜色、大小、透明度甚至旋转）进行可视化。

利用可用的统计数据，我们可以使用 API 提供的`ClassBreaksRenderer`轻松创建分级和连续渲染器。`ClassBreaksRenderer`根据某些数值属性的值对每个图形进行符号化。

模块名称：`esri/renderers/ClassBreaksRenderer`

通过使用属性如`colorInfo`、`opacityInfo`和`sizeInfo`，可以在此模块上设置颜色、大小或透明度。`ClassBreaksRenderer`上提供了以下方法：

+   `setColorInfo`(`colorInfo`): 设置`colorInfo`属性

+   `setOpacityInfo`(`opacityInfo`): 根据 info 参数设置渲染器的透明度信息

+   `setRotationInfo`(`rotationInfo`): 修改渲染器的旋转信息

+   `setSizeInfo`(`sizeInfo`): 设置渲染器的大小信息，以根据数据值修改符号大小

让我们更详细地讨论这些。以下图表提供了一个开发渲染器的简要指南：

![使用连续和分级渲染器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_07_05.jpg)

## ColorInfo

`ColorInfo`是一个用于定义图层颜色渐变的对象。我们只需要在`stops`处提供离散的颜色值，有时也可以在渐变中只提供颜色值：

一个简单的`ColorInfo`对象示例如下：

```js
renderer.setColorInfo({
  field: "MEDHINC_CY",
  minDataValue: featureLayerStats.min,
  maxDataValue: featureLayerStats.max,
  colors: [
    new Color([255, 255, 255]),
    new Color([127, 127, 0])
  ]
});
```

要创建一个分级颜色渲染器，我们需要定义一个`stops`对象来定义离散颜色，而不是连续颜色。一个`stops`对象将包含每个`stop`处的颜色。在定义`stops`时，我们*不*需要定义`minDataValue`或`maxDataValue`。让我们讨论一下在哪里可以获得适合我们渲染器的合适颜色方案。

### 选择颜色方案

以下网站为我们提供了一种简单的选择颜色方案的方法，可用于构建`colorInfo`对象或颜色渐变：[`colorbrewer2.org/`](http://colorbrewer2.org/)

在这个网站上，你可以做以下事情：

1.  选择数据类别的数量，默认值为`3`。API 的默认类别数为`5`。因此将下拉值更改为`5`类别。

1.  选择您数据的性质：

+   **sequential**: 用于显示递增的数量，如人口或人口密度。![选择颜色方案](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_07_06.jpg)

+   **diverging**: 用于强调值的差异，特别是在极端端点。例如，当映射收入中位数时，收入范围的较低端可能显示为红色，较高端显示为蓝色。![选择颜色方案](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_07_07.jpg)

+   **定性**：当我们需要使用不同颜色区分不同值或类时，使用此颜色方案。![选择颜色方案](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_07_08.jpg)

1.  选择多色调或单色调颜色方案。

1.  基于以下约束条件限制颜色色调：

+   目的：

+   色盲友好

+   打印友好

+   复印机安全

+   背景：

+   道路

+   城市

+   边界

1.  将颜色方案导出为：

+   JavaScript 数组对象——这是最方便的函数

+   Adobe PDF

![选择颜色方案](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_07_09.jpg)

### 创建一个分级颜色渲染器

如前所述，要创建一个分级颜色渲染器，我们需要定义一个`stops`对象来定义离散颜色，而不是连续颜色。`stops`对象将包含每个停止点的颜色。`stops`对象是分配给渲染器对象的数组对象。`stops`数组对象包含具有以下属性的对象：

+   `value`

+   `color`

+   `label`

`stops`对象大多看起来像这样：

```js
**var stops =**
**[**
 **{**
 **"value": 27349.802772469,**
 **"color": {      "b": 226,      "g": 235,       "r": 254,      "a": 1    },**
 **"label": " < -1.5 Std. Dev."**
 **},**
 **{**
 **"value": 39912.112219098,**
 **"color": {      "b": 185,      "g": 180,      "r": 251,      "a": 1    },**
 **"label": "-1.5 - -0.50 Std. Dev."**
 **},**
 **{**
 **"value": 52474.421665726,**
 **"color": {      "b": 161,      "g": 104,      "r": 247,      "a": 1    },**
 **"label": "-0.50 - 0.50 Std. Dev."**
 **},**
 **{**
 **"value": 65036.731112354,**
 **"color": {      "b": 138,      "g": 27,      "r": 197,      "a": 1    },**
 **"label": "0.50 - 1.5 Std. Dev."**
 **},**
 **{**
 **"value": 77599.040558982,**
 **"color": {      "b": 119,      "g": 1,      "r": 122,      "a": 1    },**
 **"label": "1.5 - 2.5 Std. Dev."**
 **}**
**]**

```

现在让我们找到一种自动填充`stops`对象的方法。记住，我们可以从`colorbrewer2.org`网站上选择的颜色方案中获取颜色数组。`color`数组可以用来填充`stops`对象中每个对象的`color`属性。`stops`对象中每个对象的`value`属性可以从`featureLayerStatistics`计算的返回对象中派生出来。`featureLayerStatistics`计算为每个类提供`最小值`、`最大值`和`标签`值。我们可以将每个类的最大值分配给`stops`对象中每个对象的`value`属性：

```js
**//Create a params object for use getClassBreaks method in** 
**// FeatureLayerStatistics module**
**//Define the field upon which Stats is computed,**
**//The classification method which should be one among the following:**
**//standard-deviation, equal-interval, natural-breaks, quantile**
**//Number of classes the data should be classified. Default is 5**
var featureLayerStatsParams_color = {
          field: "MEDHINC_CY",
          classificationMethod: selectedClassificationMethod, 
          numClasses: 5
        };

**//Compute the Class Break Statitics. This returns a promise**

var color_stats_promise = featureLayerStats.getClassBreaks(featureLayerStatsParams_color);
color_stats_promise.then(function (color_stat_result) {

**//The classBreakInfos property of the color_stat_result has all the** 
**//class break values** 

var colorStops = [];

**//Color JavaScript array exported from colorbrewer2.org**
var colors = ['#feebe2', '#fbb4b9', '#f768a1', '#c51b8a', '#7a0177']; 

**//Loop through each Break info provided by the Feature Layer Stats**
              array.forEach(color_stat_result.classBreakInfos, function (classBreakInfo, i) {
                        colorStops.push({
**//Get value property from the Break value's maximum value**
                            value: classBreakInfo.maxValue,
**//Get color from the color Array**
                            color: new Color(colors[i]),
**//Get label value from the label value provided by the Feature Layer //Stats**
                            label: classBreakInfo.label
                        });
                    });

**//Define Default renderer symbol**
var symbol = new SimpleFillSymbol();
symbol.setColor(new Color([255, 0, 0]));
symbol.setOutline(new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([0, 0, 0]), 0.5));

var colorBreakRenderer = new ClassBreaksRenderer(symbol);

**//Set the color stops to the stops property to setColorInfo method of //the renderer**
colorBreakRenderer.setColorInfo({
              field:"MEDHINC_CY",
              stops: colorStops
          });
});
```

![创建一个分级颜色渲染器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_07_10.jpg)

## opacityInfo

`opacityInfo`是一个定义特征不透明度如何计算的对象。`opacityInfo`对象可用于为`ClassBreaksRenderer`中的类设置不透明度级别。`opacityInfo`对象也可用于设置连续不透明度渲染器。

与`colorInfo`对象类似，您可以指定不透明度值作为数组，以及最小和最大数据值，或者您可以定义`stops`对象，在其中可以定义不透明度值。

使用`opacityInfo`创建一个连续渲染器：

```js
var minOpacity = 0.2;
var maxOpacity = 1;

var opacityInfo = {
  field: "DIVINDX_CY",
  minDataValue:  0,
  maxDataValue:  100,
  opacityValues:   [minOpacity, maxOpacity]
};
```

### 使用 opacityInfo 创建一个类别不透明度渲染器

让我们使用`opacityInfo`来渲染另一个字段，表示每个县的多样性指数。多样性指数在从`0`到`100`的范围内测量多样性。多样性指数是 Esri 专有的指数，定义为从同一地区随机选择的两个人属于不同种族或民族群体的可能性。多样性指数仅测量区域的多样性程度，而不是其种族构成。

我们的目标是以更高的不透明度值显示多样性指数较高的县，以及以较低的不透明度值显示多样性指数较低的县。可以使用以下代码段将不透明度值在最小值和最大值之间分割：

```js
var opacity = minOpacity + i * maxOpacity / (opacity_stat_result.classBreakInfos.length - 1);
```

在上一段代码中，`opacity_stat_result`是`FeatureLayerSatistics`模块的`getClassBreaks()`方法的承诺结果：

```js
var featureLayerStatsParams_opacity = {
  field: "DIVINDX_CY",
  classificationMethod: selectedClassificationMethod, //standard-deviation, equal-interval, natural-breaks, quantile and standard-deviation
  numClasses: 5
};

var opacity_stats_promise = featureLayerStats.getClassBreaks(featureLayerStatsParams_opacity);
opacity_stats_promise.then(function (opacity_stat_result) {

  var opacityStops = [];
  array.forEach(opacity_stat_result.classBreakInfos, function (classBreakInfo, i) {
    var minOpacity = 0;
    var maxOpacity = 1;
//Calculate opacity by dividing between 
    var opacity = minOpacity + i * maxOpacity / (opacity_stat_result.classBreakInfos.length - 1);
    opacityStops.push({
      value: classBreakInfo.maxValue,
      opacity: opacity
    });
  });

var symbol = new SimpleFillSymbol();
symbol.setColor(new Color([255, 0, 0]));
var opacityBreakRenderer = new ClassBreaksRenderer(symbol);
opacityBreakRenderer.setOpacityInfo({
   field:"MEDHINC_CY",
   stops: stops
});

CountyDemogrpahicsLayer.setRenderer(opacityBreakRenderer);
CountyDemogrpahicsLayer.redraw();
```

![使用 opacityInfo 创建一个类别不透明度渲染器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_07_11.jpg)

## SizeInfo

`SizeInfo`对象定义了特征大小与数据值成比例的符号大小。

API 帮助页面提到符号大小可以代表两种不同类型的数据——距离和非距离。距离数据类型指的是字段上的实际距离，非距离数据类型指的是符号的地图大小。使用`sizeInfo`根据树冠的实际直径表示树冠是距离数据类型的一个例子。根据交通密度表示道路大小，或者根据人口密度或中位收入表示州的大小，可以增强要素的地图呈现。

## RotationInfo

`RotationInfo`可用于定义标记符号的旋转方式。`RotationInfo`可用于表示风向、车辆方向等。必须存在指定旋转角度的字段来定义`RotationInfo`。允许使用两种旋转角度单位。

+   **地理**：这表示从地理北方顺时针方向的角度。风速和汽车方向通常用地理角度表示。

+   **算术**：这表示逆时针方向测量的角度。

以下图显示了地理和算术角度之间的差异：

![RotationInfo](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_07_12.jpg)

## 多变量映射

到目前为止，我们一直在讨论使用单个字段名称或变量来渲染要素的功能。我们还讨论了可以用来渲染要素的各种视觉变量，如颜色、不透明度、大小、旋转等。如果我们能够结合这些视觉变量，并根据多个字段值来渲染要素呢？

例如，在县级别进行映射时，我们可以考虑使用颜色来表示人口密度，使用不透明度来表示家庭收入中位数，并使用大小来表示联邦教育支出占人口字段的百分比。我们选择使用的字段数量限于四个视觉变量，即：颜色、不透明度、大小和旋转。

多变量映射是由`ClassBreaksRenderer`中的`visualVariables`属性启用的。让我们尝试使用两个视觉变量，即`colorInfo`和`opacityInfo`，我们用它们来演示两个不同的人口统计参数，即家庭收入中位数和多样性指数。我们当前的目标是使用颜色来表示家庭收入中位数，并同时根据多样性指数确定要素的不透明度值：

```js
function applySelectedRenderer(selectedClassificationMethod) {
        var featureLayerStatsParams_color = {
          field: "MEDHINC_CY",
          classificationMethod: selectedClassificationMethod, //standard-deviation, equal-interval, natural-breaks, quantile and standard-deviation
          numClasses: 5
        };
        var featureLayerStatsParams_opacity = {
          field: "DIVINDX_CY",
          classificationMethod: selectedClassificationMethod, //standard-deviation, equal-interval, natural-breaks, quantile and standard-deviation
          numClasses: 5,
          //normalizationField: 'TOTPOP_CY'
        };

        var color_stats_promise = featureLayerStats.getClassBreaks(featureLayerStatsParams_color);
        var opacity_stats_promise = featureLayerStats.getClassBreaks(featureLayerStatsParams_opacity);
        all([color_stats_promise, opacity_stats_promise]).then(function (results) {
          var color_stat_result = results[0];
          var opacity_stat_result = results[1];

          var colorStops = [];
          var colors = ['#d7191c', '#fdae61', '#ffffbf', '#abd9e9', '#2c7bb6'];
          array.forEach(color_stat_result.classBreakInfos, function (classBreakInfo, i) {
            colorStops.push({
              value: classBreakInfo.maxValue,
              color: new Color(colors[i]),
              label: classBreakInfo.label
            });
          });
          var opacityStops = [];
          array.forEach(opacity_stat_result.classBreakInfos, function (classBreakInfo, i) {
            var minOpacity = 0;
            var maxOpacity = 1;
            var opacity = minOpacity + i * maxOpacity / (opacity_stat_result.classBreakInfos.length - 1);
            opacityStops.push({
              value: classBreakInfo.maxValue,
              opacity: opacity
            });
          });

          var visualVariables = [
            {
              "type": "colorInfo",
              "field": "MEDHINC_CY",
              "stops": colorStops
                            }

            ,
            {
              "type": "opacityInfo",
              "field": "DIVINDX_CY",
              "stops": opacityStops
                        }

                        ];
          console.log(JSON.stringify(visualVariables));
          var symbol = new SimpleFillSymbol();
          symbol.setColor(new Color([0, 255, 0]));
          symbol.setOutline(new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([0, 0, 0]), 0.5));

          var colorBreakRenderer = new ClassBreaksRenderer(symbol);
          colorBreakRenderer.setVisualVariables(visualVariables);
          CountyDemogrpahicsLayer.setRenderer(colorBreakRenderer);
          CountyDemogrpahicsLayer.redraw();
          legend.refresh();
        });
      }
```

![多变量映射](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_07_13.jpg)

# 智能映射

有了所有这些统计数据的知识，现在是时候使用 API 提供的智能映射模块进行智能映射了。想象一下，一个模块可以根据一些基本输入自动调用渲染器参数，例如需要生成渲染器的要素图层和分类方法。

模块名称：`esri/renderers/smartMapping`

智能映射模块提供了几种方法，每种方法都会生成一个渲染器。智能映射模块可以生成的渲染器包括：

+   基于颜色的分类渲染器

+   基于大小的分类渲染器

+   基于类型的渲染器

+   热力图渲染器

智能映射甚至可以根据底图进行渲染。例如，某些颜色或不透明度渲染器在较暗的底图（如卫星图）上效果良好，而某些渲染器在较亮的底图（如街道地图）上效果良好。

通过三个简单的步骤，您可以让 API 决定颜色方案，并为您创建类颜色渲染器：

+   从 Esri 样式`choropleth`模块（导入`esri/styles/choropleth`）构建一个方案对象

+   使用以下属性构建一个分类颜色参数对象：

+   `basemap`

+   `classificationMethod`

+   `layer`

+   `field`

+   `scheme`——从之前构建的方案对象中选择`primaryScheme`属性

+   `numClasses`

+   将一个分类颜色参数对象分配为智能映射模块的`createClassedColorRenderer()`方法的参数

+   将智能映射方法返回的渲染器属性分配给要素图层的`setRenderer()`方法作为参数

+   重绘要素图层并刷新图例对象

以下代码解释了如何使用智能映射创建一个分类颜色渲染器：

```js
**//Call this function with the classification method as input**
function applySmartRenderer(selectedClassificationMethod) {

**//Create a scheme object assigning a theme** 
var schemes = esriStylesChoropleth.getSchemes({
 **//The following options are available for theme:** 
 **// high-to-low, above-and-below, centered-on, or extremes.**
  theme: "high-to-low",
  basemap: map.getBasemap(),
  geometryType: "polygon"
});
console.log(JSON.stringify(schemes));

**//Create a classed color Render Parameter object**
var classedColorRenderParams = {
  basemap: map.getBasemap(),
  classificationMethod: selectedClassificationMethod,
  field: 'MEDHINC_CY',
  layer: CountyDemogrpahicsLayer,
  scheme: schemes.primaryScheme,
  numClasses: 5
};

SmartMapping.createClassedColorRenderer(classedColorRenderParams).then(function (result) {
  CountyDemogrpahicsLayer.setRenderer(result.renderer);
 **//Redraw the feature layer**
  CountyDemogrpahicsLayer.redraw();
 **//Update the legend**
  legend.refresh();
}).otherwise(function (error) {
  console.log("An error occurred while performing%s, Error: %o", "Smart Mapping", error);
});
```

以下屏幕截图显示了使用智能制图模块创建的分级颜色渲染器，分别为等间隔、自然断点、分位数和标准偏差四种不同的分类。用户可以自行决定根据地图数据的目的和受众群体，选择最适合的分类方法。

我们可以通过编辑`scheme`对象来手动定义颜色方案，该对象是`createClassedColorRenderer()`方法的参数对象中的一个属性。

智能制图

# 总结

我们离成为地图数据科学家又近了一步。在本章中，我们涵盖了很多内容，从简要统计概念的复习开始。然后我们看到了代码如何运行，统计定义和要素图层统计模块如何给我们提供宝贵的统计量，可以用来有意义地渲染地图数据。然后我们评估了如何有效地使用视觉变量，如`colorInfo`、`opacityInfo`、`rotationInfo`和`sizeInfo`在渲染器中。我们还尝试结合这些视觉变量进行多变量渲染。最后，我们尝试使用智能制图模块进行自动渲染。在下一章中，我们将讨论图表和其他高级可视化技术，为用户提供分析信息。


# 第八章：高级地图可视化和图表库

在地图上渲染可能不是可视化空间数据的唯一方式。为了让数据有所侧重，我们可能需要借助于非空间分析和图表功能，这些功能由 dojo 和其他流行的库提供，以补充地图的空间可视化功能。在本章中，我们将通过图表库和其他可视化方法（如数据聚类）扩展我们在上一章开始构建的人口统计分析门户网站。本章涉及以下主要主题：

+   使用 dojo 进行图表绘制

+   使用 D3 库进行图表绘制

+   使用 Cedar 进行图表绘制

# 使用 dojo 进行图表绘制

ArcGIS API 与 dojo 的图表绘制非常好地集成在一起。图表功能由 dojo 的实验模块提供，因此称为`dojox`，其中的`x`指的是模块的实验性质。然而，这些模块足够稳定，可以集成到任何生产环境中。以下模块被认为是使用 dojo 开发图表功能的最基本模块：

+   `dojox/charting`

+   `dojox/charting/themes/<themeName>`

+   `dojox/charting/Chart2D`

+   `dojox/charting/plot2d/Pie`

## Dojo 图表主题

`dojox`图表库提供了许多主题，必须在`dojox`提供的主题列表中选择一个主题名称。可以在以下网址找到`dojox`提供的所有主题列表：[`archive.dojotoolkit.org/nightly/dojotoolkit/dojox/charting/tests/theme_preview.html`](http://archive.dojotoolkit.org/nightly/dojotoolkit/dojox/charting/tests/theme_preview.html)

dojox 图表库提供的主题如下：

| JulieThreeDChrisTomClaroPrimaryColorsElectricChargedRenkooAdobebricksAlgaeBahamationBlueDusk | DesertDistinctiveDollarGrasshopperGrasslandsGreySkiesHarmonyIndigoNationIrelandMiamiNiceMidwestMintyPurpleRain | CubanShirtsRoyalPurplesSageToLimeShroomsTufteWatersEdgeWetlandPlotKit.bluePlotKit.cyanPlotKit.greenPlotKit.orangePlotKit.purplePlotKit.red |
| --- | --- | --- |

测试这些不同图表主题的理想位置是在[`archive.dojotoolkit.org/nightly/dojotoolkit/dojox/charting/tests/test_themes.html?Julie`](http://archive.dojotoolkit.org/nightly/dojotoolkit/dojox/charting/tests/test_themes.html?Julie)。

![Dojo 图表主题](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_08_01.jpg)

## 使用弹出模板进行图表绘制

基本的图表功能可以使用`popup`模板的`mediaInfos`属性在要素图层的弹出窗口中显示。我们将使用上一章中使用的县级人口统计要素图层来创建此图表。我们对以下字段感兴趣：

| 字段 | 描述 |
| --- | --- |
| `NAME` | 县的名称 |
| `STATE_NAME` | 州的名称 |
| `TOTPOP_CY` | 县的总人口数量 |
| `MEDHINC_CY` | 县的家庭收入中位数 |
| `DIVINDX_CY` | 计算的县的多样性指数 |
| `WHITE_CY` | 白人男性和女性的数量 |
| `BLACK_CY` | 黑人男性和女性的数量 |
| `AMERIND_CY` | 美洲印第安人（男性和女性）的数量 |
| `ASIAN_CY` | 亚洲人（男性和女性）的数量 |
| `PACIFIC_CY` | 太平洋岛民（男性和女性）的数量 |
| `OTHRACE_CY` | 其他种族（男性和女性）的数量 |

创建`mediaInfos`对象涉及构建`fieldInfos`对象，如果需要更改字段名称或在图表中为它们指定别名。`mediaInfos`对象接受一个`theme`属性。提到一个 dojo 图表主题名称或您创建的自定义主题：

```js
var template = new PopupTemplate({
  title: "USA Demograpahics",
  description: "Median household income at {NAME}, {STATE_NAME} is ${MEDHINC_CY}",
 **//define field infos so we can specify an alias in the chart**
  fieldInfos: [
    { 
      fieldName: "WHITE_CY",
      label: "White Americans"
    },
    { 
      fieldName: "BLACK_CY",
      label: "Blacks"
    },
    { 
      fieldName: "AMERIND_CY",
      label: "American Indians"
    },
    {   fieldName: "ASIAN_CY",
      label: "Asians"
    },
    { 
      fieldName: "PACIFIC_CY",
      label: "Pacific Islanders"
    },
    { 
      fieldName: "OTHRACE_CY",
      label: "Other Race Count"
    }
    ],
  mediaInfos: [{ //define the bar chart
    caption: "",
    type: "piechart", // image, piechart, barchart,columnchart,linechart
    value: 
    {
      theme: "Dollar",
      fields: ["WHITE_CY", "BLACK_CY", "AMERIND_CY", "ASIAN_CY", "PACIFIC_CY", "OTHRACE_CY"]
    }
    }]
});
```

![使用弹出模板进行图表绘制](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_08_02.jpg)

# dojox 模块提供的 2D 图表类型

我们已经看到了饼图的效果。让我们讨论一些`dojox`模块提供的更多图表类型以及一些更受欢迎的图表类型的实用性。注意柱状图和柱形图之间的差异，以及散点图和仅标记的图之间的差异。

| 图表类型 | 描述 |
| --- | --- |
| 区域 | 数据线下的区域将被填充 |
| 条形 | 指代水平条 |
| 分组条 | 具有分组数据集的水平条 |
| 分组列 | 具有分组数据集的垂直条 |
| 列 | 指代具有垂直条的图表 |
| 网格 | 用于向图表添加网格层 |
| 线条 | 基本线图 |
| 标记 | 具有标记的线图 |
| 仅标记 | 仅显示数据点 |
| 饼图 | 通过在圆形直径上表示数据来表示数据的分布 |
| 散点图 | 用于绘制数据 |
| 堆叠 | 数据集相对于先前数据集的图表 |
| 堆叠区域 | 堆叠数据集，填充图表线下的区域 |
| 堆叠条 | 具有水平条的堆叠数据集 |
| 堆叠列 | 堆叠具有垂直条的数据集 |
| 堆叠线 | 使用线堆叠数据集 |

## 道场图表方法

图表模块有四个重要的方法，将帮助我们创建图表。它们是：

+   `addPlot()`：定义图表的类型和定义图表的其他辅助属性。

+   `setTheme()`：让我们为图表设置道场主题。主题也可以自定义。

+   `addSeries()`：定义图表使用的数据。

+   `render()`：渲染图表。

### 定义您的情节

使用`addPlot()`方法可以定义您的情节。情节接受名称和参数数组：

```js
var chart1 = new Chart2D(chartDomNode);
chart1.addPlot("default", plotArguments);
```

让我们看看`plotArguments`对象包括什么。`plotArguments`的属性根据我们选择使用的图表类型而变化。如果我们选择使用线条、区域或数据点来定义数据的图表类型，则应将线条、区域或标记等属性设置为布尔值。线条选项确定是否使用线条连接数据点。如果选择区域类型，则将填充数据线下的区域。标记选项将确定是否在数据点处放置标记。

`plotArguments`可以接受以下属性：

+   `type`：要呈现的图表类型

+   `lines`：布尔值，指示图表数据是否需要被线条包围

+   `areas`：布尔值，表示数据是否被区域包围

+   `markers`：布尔值，确定是否在数据点处放置标记

对于诸如堆叠线或堆叠区域的图表类型，我们可以使用张力和阴影等属性来增强图表的可视化效果。张力平滑连接数据点的线条，阴影属性将在线条上添加阴影。`shadow`属性本身是一个接受名为`dx`、`dy`和`dw`的三个属性的对象，它定义了阴影线的*x*偏移、*y*偏移和宽度：

```js
chart1.addPlot("default", {type: "StackedLines", lines: true, markers: false, tension : 3, shadows: {dx:2, dy: 2, dw: 2}});
```

在渲染条形图时，使用`gap`属性表示条形之间的像素数：

```js
chart1.addPlot("default", {type: "Bars", gap: 3});
```

### 定义主题

使用前面提到的主题列表，我们可以使用`setTheme()`方法为我们的图表设置主题：

```js
chart.setTheme(dojoxTheme);
```

### 推送数据

我们可以使用`addSeries()`方法将数据推送到图表中：

```js
chart.addSeries("PopulationSplit", chartSeriesArray);
```

`addSeries()`方法接受两个参数。第一个参数提到数据的名称，第二个参数。第二个参数是一个包含实际数据的数组对象。它可以是一维数据，例如`[10,20,30,40,50]`，也可以是二维数据，在这种情况下，可以提到数据的`x`和`y`属性：

```js
chart.addSeries("Students",[
{x: 1, y: 200 },
{x: 2, y: 185 }
]
});
```

如果是饼图，可以省略`x`分量。

### 图表插件

有一些插件可以添加到道场的图表模块中，为图表功能增加价值。这些插件为图表数据提供交互性，大多数插件会显示有关数据项的额外信息，或者强调悬停在其上的数据项。有些插件通过可视化元素（如图例）提供对数据的整体感知。插件完成的一些功能包括：

+   向图表添加工具提示

+   移动饼图片段并放大它

+   添加图例

+   突出显示数据项

插件模块，如`dojox/charting/widget/Legend`，提供了对`Legend`小部件的支持。`dojox/charting/action2d/Tooltip`模块支持图表数据的工具提示支持。包括`dojox/charting/action2d/Magnify`模块将放大悬停在其上的图表数据，从而增强了与图表的交互性。`dojox/charting/action2d/MoveSlice`模块将图表数据视为一个切片，并移动悬停在其上的图表数据的位置。这与`Magnify`插件一起，有助于有效地给出用户与图表数据的交互感。`dojox/charting/action2d/Highlight`模块用不同的高亮颜色（如青色）突出显示悬停在其上的数据。

实施插件也非常容易。以下代码行实现了诸如`Highlight`、`Tooltip`和`MoveSlice`的插件在 dojo 图表对象上的使用：

```js
new Highlight(chart, "default");
new Tooltip(chart, "default");
new MoveSlice(chart, "default");
```

让我们在要素图层的`infotemplate`属性上的动态`div`中创建一个完整的图表。

我们也将在此演示中使用县级人口统计特征图层。我们的目标是创建一个饼图，以显示我们单击的任何县的种族分布。我们将调用一个函数来动态创建每个要素的`Infowindow`内容：

```js
var template = new InfoTemplate();
template.setTitle("<b>${STATE_NAME}</b>");

**//Get the info template content from the getWindowContent function**
template.setContent(getWindowContent);

var statesLayer = new FeatureLayer("http://demographics5.arcgis.com/arcgis/rest/services/USA_Demographics_and_Boundaries_2015/MapServer/15", {
  mode: FeatureLayer.MODE_ONDEMAND,
  infoTemplate: template,
  outFields: ["NAME", "STATE_NAME", "TOTPOP_CY", "MEDHINC_CY", "DIVINDX_CY", "WHITE_CY", "BLACK_CY", "AMERIND_CY", "ASIAN_CY", "PACIFIC_CY", "OTHRACE_CY"]
});
```

在返回`Infotemplate`内容的函数中，我们将执行以下操作：

1.  创建一个包含两个内容窗格的`Tab`容器。

1.  第一个内容将显示有关所选县和家庭收入中位数数据的详细信息。

1.  第二个内容窗格将包含 dojo 饼图。

1.  在渲染饼图之前，我们将计算每个种族组占总人口的百分比。

1.  此外，我们将为每个种族组分配一个标签。在使用图例时将使用此标签。

1.  此外，饼图数据对象接受一个工具提示属性，我们将在其中提及标签以及数据值。

1.  我们将尝试使用图表插件，如`Highlight`、`Tooltip`和`Moveslice`来突出显示所选的子数据项。

现在让我们尝试在代码中实现这些步骤。我们将编写一个函数来构建图表，并将图表内容作为`dom`元素返回。我们将使用`infotemplate`的`setContent()`方法来设置以下函数返回的`dom`元素：

```js
function getWindowContent(graphic) {
  // Make a tab container.
  var tc = new TabContainer({
    style: "width:100%;height:100%;"
  }, domConstruct.create("div"));

// Make two content panes, one showing Median household income       //details. And the second showing the pie chart

  var cp1 = new ContentPane({
    title: "Details",
    content: "<a target='_blank' href='http://en.wikipedia.org/wiki/" + graphic.attributes.NAME + "'>Wikipedia Entry</a><br/>" +  "<br/> Total Population: " + graphic.attributes.TOTPOP_CY + " <br/> Median House Income: $" + graphic.attributes.MEDHINC_CY
  });
 **// Display a dojo pie chart for the racial distribution in %**
  var cp2 = new ContentPane({
    title: "Pie Chart"
  });
  tc.addChild(cp1);
  tc.addChild(cp2);

  // Create the chart that will display in the second tab.
  var c = domConstruct.create("div", {
    id: "demoChart"
  }, domConstruct.create("div"));
  var chart = new Chart2D(c);
  domClass.add(chart, "chart");

  // Apply a color theme to the chart.
  chart.setTheme(dojoxTheme);

  chart.addPlot("default", {
    type: "Pie",
    radius: 70,
    htmlLabels: true
  });
  tc.watch("selectedChildWidget", function (name, oldVal, newVal) {
    if (newVal.title === "Pie Chart") {
      chart.resize(180, 180);
    }
  });

  // Calculate percent of each ethnic race
  //"WHITE_CY", "BLACK_CY", "AMERIND_CY", "ASIAN_CY", "PACIFIC_CY", "OTHRACE_CY"
  var total = graphic.attributes.TOTPOP_CY;
  var white = {
    value: number.round(graphic.attributes.WHITE_CY / total * 100, 2),
    label: "White Americans"
  };
  var black = {
    value: number.round(graphic.attributes.BLACK_CY / total * 100, 2),
    label: "African Americans"
  };
  var AmericanIndians = {
    value: number.round(graphic.attributes.AMERIND_CY / total * 100, 2),
    label: "American Indians"
  };
  var Asians = {
    value: number.round(graphic.attributes.ASIAN_CY / total * 100, 2),
    label: "Asians"
  }
  var Pacific = {
    value: number.round(graphic.attributes.PACIFIC_CY / total * 100, 2),
    label: "Pacific Islanders"
  };
  var OtherRace = {
    value: number.round(graphic.attributes.OTHRACE_CY / total * 100, 2), 
    label: "Other Race"
  };
  var chartFields = [white, black, AmericanIndians, Asians, Pacific, OtherRace];
  var chartSeriesArray = [];
  array.forEach(chartFields, function (chartField) {
    var chartObject = {
      y: chartField.value,
      tooltip: chartField.label + ' : ' + chartField.value + ' %',
      text: chartField.label
    }
    chartSeriesArray.push(chartObject);

  });

  chart.addSeries("PopulationSplit", chartSeriesArray);
  //highlight the chart and display tooltips when you mouse over a slice.
  new Highlight(chart, "default");
  new Tooltip(chart, "default");
  new MoveSlice(chart, "default");

  cp2.set("content", chart.node);
  return tc.domNode;
}
```

当实现此代码时，我们将在单击任何县后弹出一个弹出窗口。弹出窗口包含两个选项卡——第一个选项卡提供有关该选项卡的**总人口**和该县的**家庭收入中位数**的详细信息。整个弹出窗口的标题将提及县名和州名。第一个选项卡的内容将包含动态生成的维基百科链接到县和州。

弹出容器的第一个选项卡如下截图所示：

![图表插件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_08_03.jpg)

弹出窗口的第二个选项卡显示了 dojo 图表。我们的图表上有一个图例元素。当我们在饼图中悬停在任何数据上时，它会被切片，稍微放大，并突出显示。

![图表插件](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_08_04.jpg)

# 使用 D3.js 进行图表绘制

D3.js 是一个用于基于数据操作文档的 JavaScript 库。D3 代表数据驱动文档，该库提供了强大的可视化组件和基于数据驱动的 DOM 操作方法。

要在我们的 JavaScript 应用程序中使用 D3，我们可以从[D3 网站](http://d3js.org/)下载该库。

或者我们可以在我们的脚本标签中使用 CDN：

```js
<script src="//d3js.org/d3.v3.min.js" charset="utf-8"></script>
```

更加面向 dojo 的方法是将其作为`dojoconfig`中的一个包添加，并在`define`函数中使用它作为一个模块。

以下是将 D3 作为`dojoConfig`的包添加的片段：

```js
var dojoConfig = {
  packages: 
  [
    {
      name: "d3",
      location: "http://cdnjs.cloudflare.com/ajax/libs/d3/3.5.5",
      main: "d3.min"
    }
  ]
};
```

在`define`函数中使用`d3`库：

```js
define([
  "dojo/_base/declare",
  "d3",
  "dojo/domReady!"
  ], 
function 
(
  declare,
  d3
) 
{
  //Keep Calm and use D3 with dojo
});
```

## 使用 D3 创建柱状图

让我们使用县级人口统计数据使用 D3 创建一个柱状图。我们的目标是使用柱状图显示围绕感兴趣县的家庭收入中位数的四个度量。这四个度量是：

+   国家最小值或 5 百分位数的值（平均值-三倍标准差）

+   被点击的县的家庭收入中位数

+   国家家庭收入中位数的国家平均值

+   国家最大值或 95 百分位数的值

以下图片是我们打算构建图表的模拟：

![使用 D3 创建柱状图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_08_05.jpg)

有几个原因我们选择使用 D3 来演示构建这个图表。D3 完全由数据驱动，因此灵活，特别适合数据可视化。许多可视化库都是基于 D3 构建的，了解 D3 甚至可以帮助我们构建直观的图表和数据可视化。

### D3 选择

D3 工作在选择上。D3 中的选择与 jQuery 选择非常相似。要选择`body`标签，你只需要声明：

```js
d3.select("body")
```

要选择所有具有名为`chart`的特定样式类的`div`标签，请使用以下代码片段：

```js
d3.select(".chart").selectAll("div")
```

要将`svg`（可缩放矢量图形）标签或任何其他 HTML 标签附加到`div`或`body`标签，使用`append`方法。SVG 元素用于呈现大多数图形元素：

```js
d3.select("body").append("svg")
```

与`enter()`方法一起使用，表示元素接受输入：

```js
d3.select("body").enter().append("svg")
```

### D3 数据

D3 由数据驱动，正如其名称所示。我们只需要向 D3 选择提供数据，就可以渲染一个简单的图表。数据可以简单到一个数组：

```js
var data = [45, 87, 15, 16, 23, 11];

  var d3Selection = d3.select(".chart").selectAll("div").data(data).enter().append("div");

  d3Selection.style("width", function (d) {
    return d * 3 + "px";
  }).text(function (d) {
    return d;
  });
```

在上一个代码片段中，我们所做的就是为 D3 选择的样式对象设置宽度属性。然后我们得到了这个：

![D3 数据](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_08_06.jpg)

每个`div`的宽度值以像素为单位，取自数据数组中每个元素的值乘以 20，柱内的文本值再次取自各个数据的值。在得到这个美丽的图表之前，有一些事情需要做——我们需要为`div`设置 CSS 样式。这是我们使用的一个简单的 CSS 代码片段：

```js
.chart div {
    font: 10px sans-serif;
    background-color: steelblue;
    text-align: right;
    padding: 3px;
    margin: 1px;
    color: white;
}
```

### D3 缩放

在上一个代码片段中，为了显示一个简单的 D3 图表，我们使用了一个乘数值`20`，用于每个数据值获取`div`宽度的像素值。由于我们的容器`div`大约有 400 像素宽，这个乘数值是合适的。但是对于动态数据，我们应该使用什么样的乘数值呢？经验法则是我们应该使用某种缩放机制来缩放像素值，以便我们的最大数据值舒适地适应图表容器`div`中。D3 提供了一种机制来缩放我们的数据并计算缩放因子，我们可以方便地使用它来缩放我们的数据。

D3 提供了一个`scale.linear()`方法来计算缩放因子。此外，我们还需要使用另外两个方法，即`domain()`和`range()`，来实际计算缩放因子。`domain()`方法接受一个包含两个元素的数组。第一个元素应该提到最小的数据值或`0`（适当的话），第二个元素应该提到数据的最大值。我们可以使用 D3 函数`d3.max`来找到数据的最大值：

```js
d3.max(data)
```

`range`函数还接受一个包含两个元素的数组，应列出容器 div 元素的像素范围：

```js
var x = d3.scale.linear()
    .domain([0, d3.max(data)])
    .range([0, 750]);
```

一旦我们找到缩放因子`x`，我们就可以将其用作数据项值的乘数，以得出像素值：

```js
d3.select(".chart").selectAll("div").data(data)
  .enter().append("div").style("width", function (d) {
    return x(d) + "px"; 
  }).text(function (d) {
    return d;
  });
```

### 将 SVG 集成到 D3 图表中

SVG，虽然在其整体上令人生畏，但在处理数据可视化时提供了几个优势，并支持在 HTML 中呈现许多原始形状。需要注意的一点是 SVG 坐标系统从左上角开始，我们在计算元素所需位置时需要记住这一点。

附加 SVG 元素类似于将`div`附加到我们的图表类：

```js
var svg = d3.select(".chart").append("svg")
    .attr("width", 500)
    .attr("height", 500)
    .append("g")
    .attr("transform", "translate(20,20)";
```

在前面的片段中，我们实际上可以设置样式和其他属性，例如宽度和高度。`transform`是一个重要的属性，通过它我们可以移动`svg`元素的位置（记住 SVG 坐标系原点在左上角）。

![将 SVG 集成到 D3 图表中](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_08_07.jpg)

由于我们将构建一个柱状图，因此在计算 D3 线性缩放时，由`range()`方法接受的数组中的第一个元素不应是最小值，而应是像素中的最大高度值。数组中的第二个元素是最小像素值：

```js
  var y = d3.scale.linear()
    .range([700, 0]);
```

相反，`x`缩放因子应基于序数比例（意思是，我们不使用数字来计算条的宽度和间距）：

```js
var x = d3.scale.ordinal()
    .rangeRoundBands([0, width], .1);
```

从之前讨论的特征统计模块中，我们应该能够得到特征层中特定字段的平均值和标准差。

根据前面的两条信息，我们知道如何计算 2.5^(th)百分位数（底部 2.5%的收入）和 97.5^(th)百分位数（顶部 2.5%的收入水平）。我们打算将所选特征的收入中位数与这些值进行比较。计算 2.5^(th)和 97.5^(th)百分位数的公式如下所示：

| *1st percentile = mean - 2,33 * SD* | *99th percentile = mean + 2,33 * SD* |
| --- | --- |
| *2.5th percentile = mean - 1.96 * SD* | *97.5th percentile = mean + 1.96 * SD* |
| *5th percentile = mean - 1.65 * SD* | *95th percentile = mean + 1.65 * SD* |

根据以前的统计计算，我们知道以下数据：

```js
mean = $46193
SD = $12564
```

我们需要计算如下的 2.5^(th)和 97.5^(th)百分位数：

```js
2.5th percentile value = mean – 1.96 * SD
                       =   46193 – 1.96*(12564)  
                       =             21567.56  
```

而对于 97.5^(th)：

```js
97.5th percentile = mean + 1.96 * SD
                  = 46193 + 1.96*(12564)
                  = 70818.44
```

因此，这将是我们图表的数据：

```js
var data = [
  {
    "label": "Top 2.5%ile",
    "Income": 70818
  },
  {
    "label": "Bottom 2.5%ile",
    "Income": 21568
  },
  {
    "label": "National Avg",
    "Income": 46193
  },
  {
    "label": "Selected Value",
    "Income": 0
  }
];
```

`Income`值为`Selected Value`标签设置为`0`。当我们点击`feature`类中的特征时，此值将被更新。我们还将定义一个`margin`对象以及用于图表的`width`和`height`变量。我们定义的`margin`对象如下所示：

```js
 var margin = {
      top: 20,
      right: 20,
      bottom: 30,
      left: 60
    },
    width = 400 - margin.left - margin.right,
    height = 400 - margin.top - margin.bottom;
```

在构建图表时，我们将考虑以下步骤：

1.  确定*x*缩放因子和*y*缩放因子。

1.  定义*x*和*y*轴。

1.  清除`chart`类的`div`的所有现有内容。

1.  根据`margin`对象以及`width`和`height`值定义*x*和*y*域值。

1.  定义将容纳我们的图表的 SVG 元素。

1.  在 SVG 中添加轴以及作为矩形图形元素的图表数据。

我们将在一个函数中编写功能，并根据需要调用该函数：

```js
function drawChart() {

// Find X and Y scaling factor

  var x = d3.scale.ordinal()
    .rangeRoundBands([0, width], .1);

  var y = d3.scale.linear()
    .range([height, 0]);

  // Define the X & y axes

  var xAxis = d3.svg.axis()
    .scale(x)
    .orient("bottom");

  var yAxis = d3.svg.axis()
    .scale(y)
    .orient("left")
    .ticks(10);

  //clear existing 
  d3.select(".chart").selectAll("*").remove();
  var svg = d3.select(".chart").append("svg")
    .attr("width", width + margin.left + margin.right)
    .attr("height", height + margin.top + margin.bottom)
    .append("g")
    .attr("transform", "translate(" + margin.left + "," + margin.top + ")");

  // Define the X & y domains 
  x.domain(data. map(function (d) {
    return d.label;
  }));
  y.domain([0, d3.max(data, function (d) {
    return d.population;
  })]);

  svg.append("g")
    .attr("class", "x axis")
    .attr("transform", "translate(0," + height + ")")
    .call(xAxis);

  svg.append("g")
    .attr("class", "y axis")
    .call(yAxis)
    .append("text")
    .attr("transform", "translate(-60, 150) rotate(-90)")
    .attr("y", 6)
    .attr("dy", ".71em")
    .style("text-anchor", "end")
    .text("Population");

  svg.selectAll(".bar")
    .data(data)
    .enter().append("rect")
    .attr("class", "bar")
    .style("fill", function (d) {
      if (d.label == "Selected Value")
        return "yellowgreen";
    })
    .attr("x", function (d) {
      return x(d.label);
    })
    .attr("width", x.rangeBand())
    .attr("y", function (d) {
      return y(d.population);
    })
    .attr("height", function (d) {
      return height - y(d.population);
    });
}
```

我们可以在特征层的`click`事件上调用之前的函数。在我们的项目中，特征`click`事件在一个单独的文件中定义，而 D3 图表代码在另一个文件中。因此，我们可以通过 dojo 主题发送点击结果：

```js
//map.js file

define("dojo/topic",..){
on(CountyDemogrpahicsLayer, "click", function(evt){
            topic.publish("app/feature/selected", evt.graphic);
        });
}
```

可以通过主题模块下的`subscribe()`方法在任何其他文件中访问结果。在前面的片段中，可以通过引用名为`app/feature/selected`的名称来访问结果：

```js
//chart_d3.js file

topic.subscribe("app/feature/selected", function () {
    var val = arguments[0].attributes.MEDHINC_CY;
    var title = arguments[0].attributes.NAME + ', ' + arguments[0].attributes.STATE_NAME;;
    array.forEach(data, function (item) {
      if (item.label === "Selected Value") {
        item.Income = val;
      }
    });

    drawChart(title);
    console.log(JSON.stringify(data));
  });
```

以下截图是我们代码的输出的表示。D3 图表代表一个具有四个柱的典型柱状图。前三个数据值根据我们的代码是静态的，因为我们可以从特征层数据中计算出顶部和底部的 2.5^(th)百分位数以及国家平均值。最后一栏是特征层中所选特征的实际值。在下面的快照中，我们点击了纽约州的拿骚县，数据值略高于 10 万美元，远高于顶部的 2.5^(th)百分位数标记：

![将 SVG 集成到 D3 图表中](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_08_08.jpg)

在下面的截图中，我们选择了一个收入中位数最低的县。请注意*Y*轴如何根据数据的最大值重新校准自身。

![将 SVG 集成到 D3 图表中](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_08_09.jpg)

使用 D3 进行 SVG 组件的图表绘制可能会很麻烦，但对这些的基本了解在需要进行高级定制时会大有裨益。

# 使用 Cedar 进行图表绘制

Cedar 是由 Esri 提供的一个基于 ArcGIS Server 数据创建和共享数据可视化的 beta 版本库。它是建立在 D3 和 Vega 图形库之上的。Cedar 让我们可以使用简单的模板创建高效的数据可视化和图表。

## 加载 Cedar 库

我们可以使用两种方法加载 Cedar。我们可以使用脚本标签，也可以使用 AMD 模式。后一种方法更受推荐。

### 使用脚本标签加载

通过包含脚本标签加载 Cedar 及其依赖项。这将使 Cedar 全局可用于我们的应用程序：

```js
<script type="text/javascript" src="http://cdnjs.cloudflare.com/ajax/libs/d3/3.5.5/d3.min.js"></script>
<script type="text/javascript" src="http://vega.github.io/vega/vega.min.js"></script>
<script type="text/javascript" src="https://rawgit.com/Esri/cedar/master/src/cedar.js"></script>

<script>
  var chart = new Cedar({"type": "bar"});
  ...
</script>
```

### 使用 AMD 模式加载

或者，我们可以使用 ArcGIS API for JavaScript 捆绑的 dojo 加载程序，将 Cedar 及其依赖项声明为包来加载它们：

```js
var package_path = window.location.pathname.substring(0, window.location.pathname.lastIndexOf('/'));
var dojoConfig = {
packages: [{
    name: "application",
    location: package_path + '/js/lib'
  },
  {
    name: "d3",
    location: "http://cdnjs.cloudflare.com/ajax/libs/d3/3.5.5",
    main: "d3.min"
  },
  {
    name: 'vega',
    location: 'http://vega.github.io/vega/',
    main: 'vega.min'
  }, {
    name: 'cedar',
    location: package_path + '/js/cedar',
    main: 'cedar'
  }]
};
```

`dojo`包需要在`/js/cedar`位置找到一组 Cedar 库文件。我们可以从以下 github 存储库下载所需的文件：[`github.com/Esri/cedar/tree/develop/src`](https://github.com/Esri/cedar/tree/develop/src)。

我们需要在先前提到的 URL 找到的所有文件。将这些文件放在应用程序的`/js/cedar`文件夹中。

![使用 AMD 模式加载](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_08_10.jpg)

现在我们可以在我们自己的定义函数中加载 Cedar 模块，就像以下代码片段中所示的那样：

```js
define([
  "cedar",
  "dojo/domReady!"
], function (Cedar) 
{
  var chart = new Cedar({
  ...

  });

  chart.show({
    elementId: "#cedarchartdiv",
    width: 900
  });
});
```

要创建一个简单的图表，我们只需要定义两个属性：

+   `type`—定义我们试图构建的图表类型（`bar`、`bubble`、`scatter`、`pie`等）。

+   数据集—定义数据应该来自哪里；这可以是来自 URL 或值（数组）。数据集还接受查询和映射等属性。

+   数据集的映射属性定义了呈现地图所需的对象。相应类型图表的规范可以在`/js/cedar/charts/<chart_type>.js`找到。

对于条形图，映射属性需要两个对象，*x*和*y*。让我们尝试为我们的县级人口统计图创建一个总结。在这里，我们试图总结按州分组的所有县的家庭收入中位数的平均值。以下简单的代码可以做到这一切，并显示一个简单的条形图：

```js
var chart = new Cedar({
  "type": "bar",
  "dataset": {
    "url": "/proxy/proxy.ashx?http://demographics5.arcgis.com/arcgis/rest/services/USA_Demographics_and_Boundaries_2015/MapServer/15",
    "query": {
      "groupByFieldsForStatistics": "ST_ABBREV",

//Find the average value of Median Household Income
      "outStatistics": [{
        "statisticType": "avg",
        "onStatisticField": "MEDHINC_CY",
        "outStatisticFieldName": "AVG_MEDHINC_CY"
      }]
    },
    "mappings": {
      "sort": "AVG_MEDHINC_CY",
      "x": {
        "field": "ST_ABBREV",
        "label": "State"
      },
      "y": {
        "field": "AVG_MEDHINC_CY",
        "label": "Avg. Median Household Income"
      }
    }
  }
});

chart.tooltip = {
  "title": "{ST_ABBREV}",
  "content": "{AVG_MEDHINC_CY} population in {ST_ABBREV}"
}

//show the chart
chart.show({
  elementId: "#cedarchartdiv",
  width: 900
});
```

先前的代码行就是配置 Cedar 库所需的全部内容，它为我们提供了所有州的平均收入水平的出色可视化，并按升序排列。

![使用 AMD 模式加载](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_08_11.jpg)

这种类型的图表给我们提供了数据的整体图片。让我们动手尝试构建一个散点图，它可以让我们映射多个变量。

我们的目标是将所有州的收入水平沿*X*轴进行映射，将多样性指数沿*Y*轴进行映射，并根据州对数据点进行不同的着色。

州级数据的人口统计 URL 是：[`demographics5.arcgis.com/arcgis/rest/services/USA_Demographics_and_Boundaries_2015/MapServer/21`](http://demographics5.arcgis.com/arcgis/rest/services/USA_Demographics_and_Boundaries_2015/MapServer/21)

映射对象应该有一个名为 color 的额外参数：

```js
//Get data from the Query Task

var query = new Query();
var queryTask = new QueryTask("http://demographics5.arcgis.com/arcgis/rest/services/USA_Demographics_and_Boundaries_2015/MapServer/21");
query.where = "1 = 1";
query.returnGeometry = false;
query.outFields = ["MEDHINC_CY", "DIVINDX_CY", "NAME", "TOTPOP_CY"];
queryTask.execute(query).then(function (data) {
  /*scatter*/
  var scatter_chart = new Cedar({
    "type": "scatter",
    "dataset": {
      "data": data,
      "mappings": {
        "x": {
          "field": "MEDHINC_CY",
          "label": "Median Houseold Income"
        },
        "y": {
          "field": "DIVINDX_CY",
          "label": "Diversity Index"
        },
        "color": {
          "field": "NAME",
          "label": "State"
        }
      }
    }
  });

  scatter_chart.tooltip = {
    "title": "{NAME}",
    "content": "Median Income:{MEDHINC_CY}<br/>Diversity:{DIVINDX_CY}"
  }

  scatter_chart.show({
    elementId: "#cedarScatterPlotDiv",
    width: 870,
    height: 600
  });
```

以下截图是先前给出的代码实现的结果。图表根据不同颜色的值生成图例。在我们的情况下，不同的州被着不同的颜色。如果被着色的值的数量较少，例如如果我们使用颜色来表示被分类为一些区域的州，如北部、东北部、南部、西南部和其他基本方向，这种着色方式会更合适。

![使用 AMD 模式加载](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_08_12.jpg)

创建气泡图表会提供一个额外的处理方式——使用气泡的大小表示第三个变量：

```js
var bubble_chart = new Cedar({
      "type": "bubble",
      "dataset": {
        "data": data,
        "mappings": {
          "x": {
            "field": "MEDHINC_CY",
            "label": "Median Houseold Income"
          },
          "y": {
            "field": "DIVINDX_CY",
            "label": "Diversity Index"
          },
          "size": {
            "field": "TOTPOP_CY",
            "label": "Population"
          }
        }
      }
    });

    bubble_chart.tooltip = {
      "title": "{NAME}",
      "content": "Median Income:{MEDHINC_CY}<br/>Diversity:{DIVINDX_CY}"
    }

    bubble_chart.show({
      elementId: "#cedarBubblePlotDiv"
    });
```

以下截图显示了一个气泡图；气泡的*x*位置代表县的家庭收入中位数，气泡的*y*位置代表县的多样性指数，气泡的半径或大小代表县的总人口：

![使用 AMD 模式加载](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/arcgis-js-dev-ex/img/B04959_08_13.jpg)

我们从在`Infotemplate`中创建一个简单的可定制图表开始，它可以可视化一个变量，到一个可以同时可视化三个变量的图表，从而增强我们对数据的理解，并增加其价值。

# 摘要

我们已经介绍了如何结合空间数据来提供对我们数据的全面洞察。虽然使用`Infotemplate`和 dojo 图表很方便，但使用 D3 提供了更大的灵活性和对图形元素的更大控制。Esri 提供的开源数据可视化库 Cedar 非常适合轻松创建全新的数据可视化。一旦我们掌握了这些技术以及统计方法，并学会从不同角度看待我们的数据，我们就可以自称为地图数据科学的旗手。我们在可视化空间数据的方式中还缺少一个组成部分。那个组成部分就是时间。在下一章中，我们将看到如何将时空数据可视化，以及在高级图表功能和 ArcGIS JavaScript API 本身所获得的知识。
