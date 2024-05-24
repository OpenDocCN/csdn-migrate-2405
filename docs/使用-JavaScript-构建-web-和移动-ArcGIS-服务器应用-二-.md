# 使用 JavaScript 构建 web 和移动 ArcGIS 服务器应用（二）

> 原文：[`zh.annas-archive.org/md5/D4C4E9CDA66F2E731D34B3C600414B4D`](https://zh.annas-archive.org/md5/D4C4E9CDA66F2E731D34B3C600414B4D)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：执行空间和属性查询

使用 ArcGIS Server 查询任务，您可以对地图服务中已公开的数据图层执行属性和空间查询。您还可以组合这些查询类型以执行组合的属性和空间查询。例如，您可能需要找到所有土地地块的评估价值大于 10 万美元并与百年洪水平面相交的情况。这将是一个包含空间和属性组件的组合查询的示例。在本章中，您将学习如何使用 ArcGIS API for JavaScript 中的`Query`、`QueryTask`和`FeatureSet`对象执行属性和空间查询。

本章将涵盖以下主题：

+   在 ArcGIS Server 中引入任务

+   属性和空间查询概述

+   查询对象

+   使用 QueryTask 执行查询

+   是时候练习空间查询了

# 在 ArcGIS Server 中引入任务

在本书的接下来的几章中，我们将讨论可以使用 ArcGIS API for JavaScript 执行的许多类型的任务。任务使您能够执行空间和属性查询，基于文本搜索查找要素，对地址进行地理编码，识别要素，并执行包括缓冲和距离测量在内的各种几何操作。所有任务都可以通过`esri/tasks`资源访问。

ArcGIS API for JavaScript 中的所有任务都遵循相同的模式。一旦您使用了一个或多个任务一段时间后，这种模式就很容易识别。输入对象用于向任务提供输入参数。使用这些输入参数，任务执行其特定功能，然后返回一个包含任务结果的输出对象。下图说明了每个任务如何接受输入参数对象并返回可在您的应用程序中使用的输出对象。

![在 ArcGIS Server 中引入任务](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_06_01.jpg)

# 属性和空间查询概述

正如您将在其他任务中看到的那样，查询是使用一系列对象执行的，这些对象通常包括任务的输入、任务的执行以及从任务返回的结果集。属性或空间查询的输入参数存储在一个包含可以为查询设置的各种参数的`Query`对象中。`QueryTask`对象使用`Query`对象中提供的输入执行任务，并以`FeatureSet`对象的形式返回结果集，其中包含一系列`Graphic`要素，然后您可以在地图上绘制这些要素。

`Query`对象作为`QueryTask`的输入，由包括`geometry`、`where`和`text`在内的属性定义。`geometry`属性用于输入将在空间查询中使用的几何，可以是点、线或多边形几何。`where`属性用于定义属性查询，而`text`属性用于执行包含`like`运算符的`where`子句。`Query`对象还可以包含许多可选属性，包括定义作为查询结果返回的字段、返回几何的输出空间参考以及满足查询条件的要素的实际几何。

![属性和空间查询概述](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_06_02.jpg)

上图定义了创建属性和空间查询时将使用的对象序列。

## 查询对象

为了使`QueryTask`对象对地图服务中的图层执行查询，它需要使用`Query`对象定义的输入参数。输入参数定义查询是空间、属性还是两者的组合。属性查询可以由`where`或`text`属性定义。这些属性用于定义 SQL 属性查询。我们将在后面的部分中查看`Query.where`和`Query.text`之间的区别。

空间查询要求您设置`Query.geometry`属性以定义要在空间查询中使用的输入几何形状。

可以通过构造函数创建`Query`对象的新实例，如下面的代码示例所示：

```js
var query = new Query();
```

### 定义查询属性

正如我在本节的介绍中提到的，您可以在`Query`对象上设置各种参数。必须要么为属性查询（`Query.where`或`Query.text`）定义属性，要么为空间查询定义`Query.geometry`属性。您还可以同时使用属性和空间查询属性。

#### 属性查询

`Query`对象提供了两个属性，可以在属性查询中使用：`Query.where`和`Query.text`。在下面的代码示例中，我设置了`Query.where`属性，以便只返回`STATE_NAME`字段等于`'Texas'`的记录。这只是一个标准的 SQL 查询。请注意，我用引号括起了 Texas 这个词。在对文本列执行属性查询时，您需要用单引号或双引号括起要评估的文本。如果您对包含其他数据类型（如数字或布尔值）的列执行属性查询，则不需要这样做：

```js
query.where = "STATE_NAME = 'Texas'";
```

您还可以使用`Query.text`属性执行属性查询。这是一种使用`like`创建`where`子句的简便方法。查询中使用的字段是地图文档中定义的图层的显示字段。您可以在服务目录中确定图层的显示字段。下面的屏幕截图中说明了`ZONING_NAME`是显示字段。使用`Query.text`属性查询的就是这个显示字段。

![属性查询](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_06_06.jpg)

```js
//Query.text uses the Display Name for the layer
query.text= stateName;
```

在下面的代码示例中，我们使用`query.text`执行属性查询，返回用户在网页上的表单字段中输入的州名的所有字段：

```js
query = new Query();
query.returnGeometry = false;
query.outFields = ['*'];
query.text = dom.byId("stateName").value;
queryTask.execute(query, showResults);
```

#### 空间查询

要对图层执行空间查询，您需要传递一个有效的几何对象用于空间过滤器，以及空间关系。有效的几何包括`Extent`、`Point`、`Polyline`和`Polygon`的实例。空间关系通过`Query.spatialRelationship`属性设置，并在查询期间应用。空间关系是通过以下常量值之一来定义的：`SPATIAL_REL_INTERESECTS`、`SPATIAL_REL_CONTAINS`、`SPATIAL_REL_CROSSES`、`SPATIAL_REL_ENVELOPE_INTERSECTS`、`SPATIAL_REL_OVERLAPS`、`SPATIAL_REL_TOUCHES`、`SPATIAL_REL_WITHIN`和`SPATIAL_REL_RELATION`。以下屏幕截图中的表描述了每个空间关系值：

![空间查询](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_06_10.jpg)

以下代码示例将`Point`对象设置为传递到空间过滤器中的几何体，并设置空间关系：

```js
query.geometry = evt.mapPoint;
query.spatialRelationship = SPATIAL_REL_INTERSECTS;
```

#### 限制返回的字段

出于性能原因，您应该限制在`FeatureSet`对象中返回的字段，只返回应用程序中需要的字段。附加到`FeatureSet`对象的每一列信息都是必须从服务器传递到浏览器的额外数据，这可能导致您的应用程序执行速度比应该慢。要限制返回的字段，您可以将包含应该返回的字段列表的数组分配给`Query.outFields`属性，如下面的代码示例所示。要返回所有字段，可以使用`outFields = ['*']`。

此外，您可以通过`Query.returnGeometry`属性控制每个要素的几何返回。默认情况下，将返回几何；但是，在某些情况下，您的应用程序可能不需要几何。例如，如果您需要使用图层的属性信息填充表格，则不一定需要几何。在这种情况下，您可以设置`Query.returnGeometry = false`：

```js
query.outFields = ["NAME", "POP2000", "POP2007", "POP00_SQMI", "POP07_SQMI"];
query.returnGeometry = false;
```

## 使用 QueryTask 执行查询

一旦您在`Query`对象中定义了输入属性，就可以使用`QueryTask`执行查询。在执行查询之前，必须首先创建`QueryTask`对象的实例。通过在对象的构造函数中传递要对其执行查询的图层的 URL 来创建`QueryTask`对象。以下代码示例显示了如何创建`QueryTask`对象。请注意，它在 URL 的末尾包含一个索引编号，该索引编号引用地图服务中的特定图层进行查询：

```js
myQueryTask = new QueryTask("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Demographics/ESRI_CENSUS_USA/MapServer/5");
```

创建后，`QueryTask`对象可用于使用`QueryTask.execute()`方法对具有输入`Query`对象的图层执行查询。`QueryTask.execute()`接受三个参数，包括输入的`Query`对象以及成功和错误回调函数。`QueryTask.execute()`的语法在以下代码中提供。输入的`Query`对象作为第一个参数传递：

```js
QueryTask.execute(parameters,callback?,errback?)
```

假设查询在没有任何错误的情况下执行，将调用成功的回调函数，并将`FeatureSet`对象传递到函数中。如果在执行查询期间发生错误，则会执行错误回调函数。成功和错误回调函数都是可选的；但是，您应该始终定义函数来处理这两种情况。

此时，您可能想知道这些`callback`和`errback`函数。ArcGIS Server 中的大多数任务返回`dojo/Deferred`的实例。`Deferred`对象是一个类，用作在`Dojo`中管理异步线程的基础。ArcGIS Server 中的任务可以是同步的，也可以是异步的。

异步和同步定义了客户端（使用任务的应用程序）与服务器交互并从任务中获取结果的方式。当服务设置为同步时，客户端等待任务完成。通常，同步任务执行速度快（几秒钟或更短）。异步任务通常需要更长时间来执行，客户端不等待任务完成。用户可以在任务执行时继续使用应用程序。当服务器上的任务完成时，它调用回调函数并将结果传递到该函数中，然后可以以某种方式使用这些结果。它们通常显示在地图上。

让我们看一个更完整的代码示例。在以下代码示例中，请注意我们首先创建一个名为`myQueryTask`的新变量，它指向`ESRI_CENSUS_USA`地图服务中的第 6 层（索引编号基于`0`）。然后，我们创建包含查询输入属性的`Query`对象，最后，我们使用`QueryTask`上的`execute()`方法执行查询。`execute()`方法返回一个包含查询结果的`FeatureSet`对象，并且这些要素通过在`execute()`方法中指定的`showResults`回调函数进行处理。如果在执行任务期间发生错误，则将调用`errorCallback()`函数：

```js
**myQueryTask = new QueryTask("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Demographics/ESRI_CENSUS_USA/MapServer/5");**
//build query filter
myQuery = new Query();
myQuery.returnGeometry = false;
myQuery.outFields = ["STATE_NAME", "POP2007", "MALES", "FEMALES"];
myQuery.text = 'Oregon';
//execute query
**myQueryTask.execute(myQuery, showResults, errorCallback);**
function showResults(fs) {
    //do something with the results
    //they are returned as a featureset object
}

function errorCallback() {
  alert("An error occurred during task execution");
}
```

## 获取查询结果

正如我之前提到的，查询的结果存储在包含图形数组的`FeatureSet`对象中，如果需要，您可以在地图上绘制这些图形。

数组中的每个要素（图形）都可以包含几何、属性、符号和信息模板，如第三章中所述，“将图形添加到地图”。通常，这些要素被绘制在地图上作为图形。以下代码示例显示了在查询完成执行时执行的回调函数。`FeatureSet`对象被传递到回调函数中，并在地图上绘制图形：

```js
function addPolysToMap(featureSet) {
  var features = featureSet.features;
  var feature;
  for (i=0, il=features.length; i<il; i++) {
    feature = features[i];
    attributes = feature.attributes;
    pop = attributes.POP90_SQMI;
    map.graphics.add(features[i].setSymbol(sym));
  }
}
```

# 练习空间查询的时间

在这个练习中，您将学习如何使用 ArcGIS API for JavaScript 中的`Query`、`QueryTask`和`FeatureSet`对象执行空间查询。使用波特兰市的 Zoning 图层，您将查询地块记录并在地图上显示结果。

执行以下步骤完成练习：

1.  在[`developers.arcgis.com/en/javascript/sandbox/sandbox.html`](http://developers.arcgis.com/en/javascript/sandbox/sandbox.html)上打开 JavaScript 沙盒。

1.  从以下代码片段中我标记的`<script>`标签中删除 JavaScript 内容：

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

1.  创建应用程序中将使用的变量。

```js
<script>
**var map, query, queryTask;**
**var symbol, infoTemplate**;
</script>
```

1.  添加如下标记的`require()`函数：

```js
<script>
  var map, query, queryTask;
  var symbol, infoTemplate;

 **require([**
 **"esri/map", "esri/tasks/query", "esri/tasks/QueryTask","esri/tasks/FeatureSet", "esri/symbols/SimpleFillSymbol",**
 **"esri/symbols/SimpleLineSymbol", "esri/InfoTemplate","dojo/_base/Color", "dojo/on", "dojo/domReady!"**
 **], function(Map, Query, QueryTask, FeatureSet,SimpleFillSymbol, SimpleLineSymbol, InfoTemplate, Color,on) {**

 **});**

</script>
```

1.  在`require()`函数内部，创建将在应用程序中使用的`Map`对象。地图将以肯塔基州路易斯维尔市为中心：

```js
require([
    "esri/map", "esri/tasks/query", "esri/tasks/QueryTask", "esri/tasks/FeatureSet", "esri/symbols/SimpleFillSymbol",
    "esri/symbols/SimpleLineSymbol", "esri/InfoTemplate", "dojo/_base/Color", "dojo/on", "dojo/domReady!"
  ], function(Map, Query, QueryTask, FeatureSet, SimpleFillSymbol, SimpleLineSymbol, InfoTemplate, Color, on) {

 **map = new Map("mapDiv",{**
 **basemap: "streets",**
 **center:[-85.748, 38.249], //long, lat**
 **zoom: 13** 
 **});**

})
```

1.  创建将用于显示查询结果的符号：

```js
require([
    "esri/map", "esri/tasks/query", "esri/tasks/QueryTask", "esri/tasks/FeatureSet", "esri/symbols/SimpleFillSymbol",
    "esri/symbols/SimpleLineSymbol", "esri/InfoTemplate", "dojo/_base/Color", "dojo/on", "dojo/domReady!"
  ], function(Map, Query, QueryTask, FeatureSet, SimpleFillSymbol, SimpleLineSymbol, InfoTemplate, Color, on) {
    map = new Map("map",{
      basemap: "streets",
      center:[-85.748, 38.249], //long, lat
      zoom: 13 
    });

  **symbol = new SimpleFillSymbol(SimpleFillSymbol.STYLE_SOLID,** 
 **new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([111, 0, 255]), 2), new Color([255,255,0,0.25]));**
 **infoTemplate = new InfoTemplate("${OBJECTID}", "${*}");**

});
```

1.  现在，在`require()`函数内部，我们将初始化`queryTask`变量，然后注册`QueryTask.complete`事件。添加以下标记的代码行：

```js
require([
    "esri/map", "esri/tasks/query", "esri/tasks/QueryTask", "esri/tasks/FeatureSet", "esri/symbols/SimpleFillSymbol",
    "esri/symbols/SimpleLineSymbol", "esri/InfoTemplate", "dojo/_base/Color", "dojo/on", "dojo/domReady!"
  ], function(Map, Query, QueryTask, FeatureSet, SimpleFillSymbol, SimpleLineSymbol, InfoTemplate, Color, on) {

    map = new Map("mapDiv",{
        basemap: "streets",
        center:[-85.748, 38.249], //long, lat
        zoom: 13 
    });

    symbol = new SimpleFillSymbol(SimpleFillSymbol.STYLE_SOLID,
    new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([111, 0, 255]), 2), new Color([255,255,0,0.25]));
    infoTemplate = new InfoTemplate("${OBJECTID}", "${*}");

 **queryTask = new QueryTask("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Louisville/LOJIC_LandRecords_Louisville/MapServer/2");**
 **queryTask.on("complete", addToMap);**

});
```

`QueryTask`的构造函数必须是指向通过地图服务公开的数据图层的有效 URL 指针。在这种情况下，我们正在创建对 LOJIC_LandRecords_Louisville 地图服务中的 Zoning 图层的引用。这表明我们将对该图层执行查询。如果您还记得之前的章节，`dojo.on()`用于注册事件。在这种情况下，我们正在为我们的新`QueryTask`对象注册`complete`事件。当查询完成时，此事件将触发，并且在这种情况下将调用作为`on()`参数指定的`addToMap()`函数。

1.  现在我们将通过创建`Query`对象来定义任务的输入参数。在第一行中，我们创建一个新的`Query`实例，然后设置`Query.returnGeometry`和`Query.outFields`属性。将`Query.returnGeometry`设置为`true`表示 ArcGIS Server 应返回与查询匹配的要素的几何定义，而在`Query.outFields`中，我们指定了一个通配符，表示应返回与查询结果相关的 Zoning 图层的所有字段。在上一步中输入的代码下面添加以下标记的代码行：

```js
require([
"esri/map", "esri/tasks/query", "esri/tasks/QueryTask", "esri/tasks/FeatureSet", "esri/symbols/SimpleFillSymbol",
"esri/symbols/SimpleLineSymbol", "esri/InfoTemplate", "dojo/_base/Color", "dojo/on", "dojo/domReady!"
], function(Map, Query, QueryTask, FeatureSet, SimpleFillSymbol, SimpleLineSymbol, InfoTemplate, Color, on) {
  map = new Map("mapDiv",{
      basemap: "streets",
      center:[-85.748, 38.249], //long, lat
      zoom: 13 
  });

  symbol = new SimpleFillSymbol(SimpleFillSymbol.STYLE_SOLID,
  new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([111, 0, 255]), 2), new Color([255,255,0,0.25]));
  infoTemplate = new InfoTemplate("${OBJECTID}", "${*}");

    queryTask = new QueryTask("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Louisville/LOJIC_LandRecords_Louisville/MapServer/2");
    queryTask.on("complete", addToMap);

 **query = new Query();**
 **query.returnGeometry = true;**
 **query.outFields = ["*"];**

});
```

1.  添加一行代码，将`Map.click`事件注册到`doQuery`函数。`doQuery`函数将接收用户在地图上点击的点。这个地图点将被用作空间查询中的几何体。在下一步中，我们将创建`doQuery`函数，该函数将接受地图上点击的点：

```js
require([
        "esri/map", "esri/tasks/query", "esri/tasks/QueryTask", "esri/tasks/FeatureSet", "esri/symbols/SimpleFillSymbol", 
        "esri/symbols/SimpleLineSymbol", "esri/InfoTemplate",  "dojo/_base/Color", "dojo/on", "dojo/domReady!"
        ], function(Map, Query, QueryTask, FeatureSet, SimpleFillSymbol, SimpleLineSymbol, InfoTemplate, Color, on) {

map = new Map("mapDiv",{
  basemap: "streets",
  center:[-85.748, 38.249], //long, lat
  zoom: 13 
});

symbol = new SimpleFillSymbol(SimpleFillSymbol.STYLE_SOLID, 
    new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, newColor([111, 0, 255]), 2), new Color([255,255,0,0.25]));
infoTemplate = new InfoTemplate("${OBJECTID}", "${*}");

**map.on("click", doQuery);**

queryTask = new QueryTask("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Louisville/LOJIC_LandRecords_Louisville/MapServer/2");
queryTask.on("complete", addToMap);

**query = new Query();**
**query.returnGeometry = true;**
**query.outFields = ["*"];**

});
```

1.  现在我们将创建`doQuery`函数，该函数使用在`require()`函数中设置的`Query`属性以及用户在地图上点击的地图点执行`QueryTask`。`doQuery`函数接受在地图上点击的点，可以使用`mapPoint`属性检索。`mapPoint`属性返回一个`Point`对象，然后用于设置`Query.geometry`属性，该属性将用于查找用户在地图上点击的分区地块。最后，执行`QueryTask.execute()`方法。任务执行后，将返回包含与查询匹配的记录的`FeatureSet`对象。现在的问题是结果返回在哪里？在`require()`函数的闭合大括号下面添加以下代码块：

```js
function doQuery(evt) {
    //clear currently displayed results
    map.graphics.clear();

    query.geometry = evt.mapPoint;
    query.outSpatialReference = map.spatialReference;
    queryTask.execute(query);
}
```

1.  记住，我们注册了`QueryTask.complete`事件来运行`addToMap()`函数。我们还没有创建这个函数。添加以下代码来创建`addToMap()`函数。此函数将接受作为查询结果返回的`FeatureSet`对象，并在地图上绘制要素。还要注意为要素定义了信息模板。这将创建一个`InfoWindow`对象来显示返回要素的属性：

```js
function addToMap(results) {
  var featureArray = results.featureSet.features;
  var feature = featureArray[0];
  map.graphics.add(feature.setSymbol(symbol).setInfoTemplate(infoTemplate));
}
```

您可以在`spatialquery.html`文件中查看此练习的解决方案代码。

1.  单击**运行**按钮来执行代码。您应该会看到以下截图中的地图。如果没有，请检查您的代码是否准确。

单击地图上的任意位置来运行查询。您应该会看到高亮显示的分区多边形，类似于您在以下截图中看到的：

![Time to practice with spatial queries](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_06_08.jpg)

现在，单击高亮显示的分区多边形以显示详细的信息窗口，其中包含与多边形相关联的属性。

![Time to practice with spatial queries](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_06_09.jpg)

在刚刚完成的任务中，您学会了如何使用`Query`和`QueryTask`对象创建一个空间查询，以定位用户在地图上点击的点所相交的分区多边形。

# 摘要

在这一章中，我们介绍了 ArcGIS Server 中任务的概念。ArcGIS Server 为 Web 地图应用程序中常用操作提供了许多任务。属性和空间查询是 Web 地图应用程序中常见的操作。为了支持这些查询，ArcGIS API for JavaScript 提供了一个`QueryTask`对象，可以用来在服务器上执行这些查询。创建时，`QueryTask`对象接受一个指向地图服务器中将被查询的图层的 URL。通过`Query`对象提供了`QueryTask`的各种输入参数。输入参数可以包括`where`属性来执行属性查询，`geometry`属性来执行空间查询，`outFields`属性来定义应该返回的字段集，以及其他一些支持属性。在服务器上完成查询后，将`FeatureSet`对象返回给应用程序中定义的回调函数。回调函数可以显示`FeatureSet`（它只是一个`Graphic`对象数组）在地图上。在下一章中，您将学习如何使用另外两个任务：`IdentifyTask`和`FindTask`。两者都可以用来返回要素的属性。


# 第七章：识别和查找要素

在本章中，我们将介绍与返回要素属性相关的两个 ArcGIS Server 任务：IdentifyTask 和 FindTask。识别要素是 GIS 应用程序中的另一个常见操作。此任务返回在地图上单击的要素的属性。属性信息通常显示在弹出窗口中。通过 ArcGIS API for JavaScript 的 IdentifyTask 类实现此功能。与我们所见的其他任务过程一样，IdentifyTask 对象使用输入参数对象，本例中称为 IdentifyParameters。IdentifyParameters 对象包含各种参数，用于控制识别操作的结果。这些参数使您能够对单个图层、服务中的最顶层图层、服务中的所有可见图层或服务中的所有图层以及搜索容差执行识别。IdentifyResult 的实例用于保存任务的结果。

您可以使用 ArcGIS API for JavaScript 执行一些在 ArcGIS Desktop 中最常用的功能的任务。FindTask 就是这样一个工具。与 ArcGIS 桌面版本一样，此任务可用于在图层中查找与字符串值匹配的要素。在使用 FindTask 对象执行查找操作之前，您需要在 FindParameters 的实例中设置操作的各种参数。FindParameters 使您能够设置各种选项，包括搜索文本、要搜索的字段等。使用 FindParameters 对象，FindTask 然后针对一个或多个图层和字段执行其任务，然后返回包含与搜索字符串匹配的 layerID、layerName 和要素的 FindResult 对象。

在本章中，我们将涉及以下主题：

+   使用 IdentifyTask 获取要素属性

+   使用 FindTask 获取要素属性

# 使用 IdentifyTask 获取要素属性

使用 IdentifyTask 可以返回图层中字段的属性到您的应用程序。在本节中，您将学习如何使用与 IdentifyTask 相关的各种对象来返回此信息。

## 介绍 IdentifyTask

与 ArcGIS Server 中的其他任务一样，IdentifyTask 功能在 API 中分为三个不同的类，包括 IdentifyParameters，IdentifyTask 和 IdentifyResult。这三个类如下图所示：

![介绍 IdentifyTask](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_07_01.jpg)

## IdentifyParameters 对象

IdentifyTask 的输入参数对象是 IdentifyParameters。使用 IdentifyParameters 类可以为您的识别操作设置多个属性。参数包括用于选择要素的几何（IdentifyParameters.geometry）、要执行识别的图层 ID（IdentifyParameters.layerIds）以及在其中执行识别的指定几何的容差（IdentifyParameters.tolerance）。

在您可以使用 ArcGIS Server 提供的识别功能之前，您需要导入如下所示的识别资源。

```js
require(["esri/tasks/IdentifyTask", ... ], function(IdentifyTask,... ){ ... });
```

在 IdentifyParameters 对象上设置各种参数之前，您需要首先创建此对象的实例。可以使用如下所示的代码完成此操作。此构造函数的代码不接受任何参数：

```js
var identifyParams = new IdentifyParameters();
```

现在您已经创建了 IdentifyParameters 的新实例，可以设置如下所示的各种属性：

```js
identifyParams.geometry = evt.MapPoint;identifyParams.layerIds[0,1,2]; 
identifyParams.returnGeometry = true;identifyParams.tolerance = 3; 
```

在大多数情况下，使用用户在地图上单击的点执行识别操作。您可以使用从地图单击事件返回的点来获取这一点，就像在前面的代码示例中所看到的那样。应该搜索的图层可以使用图层 ID 数组来定义，这些 ID 被传递到`IdentifyParameters.layerIds`属性中。数组应包含引用要搜索的图层的数值。您可以通过查看服务目录来获取图层索引号。容差属性尤为重要。它设置了几何图形周围的像素距离。请记住，大多数情况下几何图形将是一个点，因此您可以将其视为在您设置的任何容差值周围放置的圆。该值将以屏幕像素为单位。执行`IdentifyTask`属性时，将返回任何在或与圆内的要识别的图层中的要素。

您可能需要尝试不同的容差值，以获得最适合您的应用程序的值。如果值设置得太低，您可能面临识别操作未识别任何要素的风险，反之，如果值设置得太高，您可能会得到太多的要素返回。找到合适的平衡可能很困难，对一个应用程序有效的容差值可能对另一个应用程序无效。

## `IdentifyTask`属性

`IdentifyTask`使用`IdentifyParameters`中指定的参数在一个或多个图层上执行识别操作。与我们已经检查过的其他任务一样，`IdentifyTask`需要一个指向标识要在识别操作中使用的地图服务的 URL 的指针。

`IdentifyTask`的新实例可以使用以下代码示例创建。该任务的构造函数简单地接受一个指向包含可以执行识别操作的图层的地图服务的 URL。

```js
var identify =new IdentifyTask("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Specialty/ESRI_StatesCitiesRivers_USA/MapServer");
```

一旦创建了`IdentifyTask`对象的新实例，您可以通过`IdentifyTask.execute()`方法启动执行此任务，该方法接受一个`IdentifyParameters`对象以及可选的`success`回调和`error`回调函数。在以下代码示例中，调用了`IdentifyTask.execute()`方法。将`IdentifyParameters`的实例作为参数传递到该方法中，并引用一个`addToMap()`方法，该方法将处理返回给该方法的结果。

```js
identifyParams = new IdentifyParameters();
identifyParams.tolerance = 3;
identifyParams.returnGeometry = true;
identifyParams.layerIds = [0,2];
identifyParams.geometry = evt.mapPoint;

**identifyTask.execute(identifyParams, function(idResults) { addToMap(idResults, evt); });**

**function addToMap(idResults, evt) {**
 **//add the results to the map**
**}**

```

使用`IdentifyTask`执行的识别操作的结果存储在`IdentifyResult`的实例中。我们将在下一节中检查这个结果对象。

### IdentifyResult

`IdentifyTask`操作返回的结果是`IdentifyResult`对象的数组。每个`IdentifyResult`对象包含从识别操作返回的要素，以及找到该要素的图层 ID 和图层名称。以下代码说明了如何通过回调函数处理`IdentifyResult`对象数组：

```js
function addToMap(**idResults**, evt) {
  bldgResults = {displayFieldName:null,features:[]};
  parcelResults = {displayFieldName:null,features:[]};
  for (vari=0, **i<idResults.length**; i++) {
 **var idResult = idResults[i];**
    if (**idResult.layerId === 0**) {
      if (!bldgResults.displayFieldName) 
        {bldgResults.displayFieldName = idResult.displayFieldName};
        bldgResults.features.push(**idResult.feature**);
      }
    else if (**idResult.layerId === 2**) {
        if (!parcelResults.displayFieldName)
         {parcelResults.displayFieldName = idResult.displayFieldName};
         parcelResults.features.push(**idResult.feature**);
       }
    }
dijit.byId("bldgTab").setContent(layerTabContent(bldgResults,"bldgResults"));
dijit.byId("parcelTab").setContent(layerTabContent(parcelResults,"parcelResults"));
map.infoWindow.show(evt.screenPoint,
map.getInfoWindowAnchor(evt.screenPoint));
}
```

## 练习时间-实现标识功能

在这个练习中，您将学习如何在应用程序中实现标识功能。您将创建一个简单的应用程序，当用户单击地图时，它将在信息窗口中显示建筑物和土地包裹的属性信息。我们已经为您预先编写了一些代码，这样您就可以专注于与要素识别直接相关的功能。在我们开始之前，我会让您将预先编写的代码复制并粘贴到沙箱中。

执行以下步骤完成练习：

1.  在[`developers.arcgis.com/en/javascript/sandbox/sandbox.html`](http://developers.arcgis.com/en/javascript/sandbox/sandbox.html)打开 JavaScript 沙箱。

1.  从我在以下代码片段中突出显示的`<script>`标签中删除 JavaScript 内容：

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

1.  创建您将在应用程序中使用的变量：

```js
<script>
**var map;**
**var identifyTask, identifyParams;**
</script>
```

1.  创建`require()`函数，定义您将在此应用程序中使用的资源：

```js
<script>
  var map;
var identifyTask, identifyParams;
**require([**
 **"esri/map",  "esri/dijit/Popup","esri/layers/ArcGISDynamicMapServiceLayer","esri/tasks/IdentifyTask",** 
 **"esri/tasks/IdentifyResult","esri/tasks/IdentifyParameters","esri/dijit/InfoWindow","esri/symbols/SimpleFillSymbol",** 
 **"esri/symbols/SimpleLineSymbol","esri/InfoTemplate", "dojo/_base/Color" ,"dojo/on",**
 **"dojo/domReady!"**
 **], function(Map, Popup, ArcGISDynamicMapServiceLayer,IdentifyTask, IdentifyResult, IdentifyParameters,InfoWindow,** 
 **SimpleFillSymbol, SimpleLineSymbol, InfoTemplate,Color, on) {**

 **});**
</script>
```

1.  创建`Map`对象的新实例：

```js
<script>
  var map;
var identifyTask, identifyParams;
require([
    "esri/map",  "esri/dijit/Popup","esri/layers/ArcGISDynamicMapServiceLayer","esri/tasks/IdentifyTask", 
    "esri/tasks/IdentifyResult","esri/tasks/IdentifyParameters","esri/dijit/InfoWindow","esri/symbols/SimpleFillSymbol", 
    "esri/symbols/SimpleLineSymbol", "esri/InfoTemplate", "dojo/_base/Color" ,"dojo/on",
      "dojo/domReady!"
      ], function(Map, Popup, ArcGISDynamicMapServiceLayer,IdentifyTask, IdentifyResult, IdentifyParameters,InfoWindow, 
  SimpleFillSymbol, SimpleLineSymbol, InfoTemplate, Color,on) {
    //setup the popup window 
var popup = new Popup({
fillSymbol: new SimpleFillSymbol(SimpleFillSymbol.STYLE_SOLID,new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID,new Color([255,0,0]), 2), new Color([255,255,0,0.25]))
        }, dojo.create("div"));

**map = new Map("map", {**
 **basemap: "streets",**
 **center: [-83.275, 42.573],**
 **zoom: 18,**
 **infoWindow: popup**
**});**

    });
</script>
```

1.  创建一个新的动态地图服务图层并将其添加到地图中：

```js
map = new Map("map", {
  basemap: "streets",
  center: [-83.275, 42.573],
  zoom: 18,
  infoWindow: popup
});

var landBaseLayer = new ArcGISDynamicMapServiceLayer("http://sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer",{opacity:.55});
map.addLayer(landBaseLayer);
```

1.  添加一个`Map.click`事件，将触发执行一个函数，当地图被点击时将会响应：

```js
map = new Map("map", {
  basemap: "streets",
  center: [-83.275, 42.573],
  zoom: 18,
  infoWindow: popup
});

varlandBaseLayer = new ArcGISDynamicMapServiceLayer("http://sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer",{opacity:.55});
map.addLayer(landBaseLayer);

**map.on("click", executeIdentifyTask);**

```

1.  创建一个`IdentifyTask`对象：

```js
  identifyTask = newIdentifyTask("http://sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer");
```

1.  创建一个`IdentifyParameters`对象并设置各种属性：

```js
identifyTask = newIdentifyTask("http://sampleserver3.arcgisonline.com/ArcGIS/rest/services/BloomfieldHillsMichigan/Parcels/MapServer");

**identifyParams = new IdentifyParameters();**
**identifyParams.tolerance = 3;**
**identifyParams.returnGeometry = true;**
**identifyParams.layerIds = [0,2];**
**identifyParams.layerOption = IdentifyParameters.LAYER_OPTION_ALL;**
**identifyParams.width  = map.width;**
**identifyParams.height = map.height;**

```

1.  创建`executeIdentifyTask()`函数，该函数是响应`Map.click`事件的函数。在之前的步骤中，您已经为`Map.click`事件设置了事件处理程序。`executeIdentifyTask()`函数被指定为处理此事件发生时的 JavaScript 函数。在此步骤中，您将通过添加以下代码来创建此函数。`executeIdentifyTask()`函数接受一个参数，即`Event`对象的实例。每个事件都会生成一个`Event`对象，该对象具有各种属性。在`Map.click`事件的情况下，此`Event`对象具有包含被点击的点的属性。这可以通过`Event.mapPoint`属性检索，并在设置`IdentifyParameters.geometry`属性时使用。`IdentifyTask.execute()`方法还返回一个`Deferred`对象。然后，您将一个回调函数添加到此`Deferred`对象中，该函数解析结果。添加以下代码以创建`executeIdentifyTask()`函数。此函数应该在`require()`函数之外创建：

```js
function executeIdentifyTask(evt) {
        identifyParams.geometry = evt.mapPoint;
        identifyParams.mapExtent = map.extent;

        var deferred = identifyTask.execute(identifyParams);

        deferred.addCallback(function(response) {     
          // response is an array of identify result objects    
          // Let's return an array of features.
          return dojo.map(response, function(result) {
            var feature = result.feature;
            feature.attributes.layerName = result.layerName;
            if(result.layerName === 'Tax Parcels'){
              console.log(feature.attributes.PARCELID);
              var template = new esri.InfoTemplate("", "${PostalAddress} <br/> Owner of record: ${First OwnerName}");
              feature.setInfoTemplate(template);
            }
            else if (result.layerName === 'Building Footprints'){
              var template = new esri.InfoTemplate("", "Parcel ID:${PARCELID}");
              feature.setInfoTemplate(template);
            }
            return feature;
          });
        });

// InfoWindow expects an array of features from each deferred
// object that you pass. If the response from the task execution 
// above is not an array of features, then you need to add acallback
// like the one above to post-process the response and return an
        // array of features.
        map.infoWindow.setFeatures([ deferred ]);
        map.infoWindow.show(evt.mapPoint);
      }
```

1.  您可能希望查看您的`ArcGISJavaScriptAPI`文件夹中的解决方案文件（`identify.html`），以验证您的代码是否已正确编写。

1.  通过单击**Run**按钮执行代码，如果一切编码正确，您应该看到以下输出：![练习时间-实现识别功能](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_07_02.jpg)

# 使用`FindTask`获取要素属性

您可以使用`FindTask`根据字符串值搜索由 ArcGIS Server REST API 公开的地图服务。搜索可以在单个图层的单个字段上进行，也可以在图层的多个字段上进行，或者在多个图层的多个字段上进行。与我们已经检查过的其他任务一样，查找操作由三个互补的对象组成，包括`FindParameters`、`FindTask`和`FindResult`。`FindParameters`对象充当输入参数对象，由`FindTask`用于完成其工作，而`FindResult`包含任务返回的结果。看一下以下图：

![使用`FindTask`获取要素属性](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965OT_07_03.jpg)

## FindParameters

`FindParameters`对象用于指定查找操作的搜索条件，并包括一个`searchText`属性，其中包括将要搜索的文本，以及指定要搜索的字段和图层的属性。除此之外，将`returnGeometry`属性设置为`true`表示您希望返回与查找操作匹配的要素的几何，并可用于突出显示结果。

以下代码示例显示了如何创建`FindParameters`的新实例并分配各种属性。在使用与查找操作相关的任何对象之前，您需要导入`esri/tasks/find resource`。`searchText`属性定义了将在字段之间搜索的字符串值，该字段在`searchFields`属性中定义。将要搜索的图层通过分配给`layerIds`属性的索引号数组来定义。索引号对应于地图服务中的图层。`geometry`属性定义了是否应在结果中返回要素的几何定义。有时您可能不需要要素的几何，例如当属性只需在表内填充时。在这种情况下，您将把`geometry`属性设置为`false`。

```js
var findParams = new FindParameters();
findParams.searchText = dom.byId("ownerName").value;
findParams.searchFields = ["LEGALDESC","ADDRESS"]; //fields to search
findParams.returnGeometry = true;
findParams.layerIds = [0]; //layers to use in the find
findParams.outSpatialReference = map.spatialReference;
```

您可以使用`contains`属性来确定是否要查找搜索文本的精确匹配。如果设置为`true`，它将搜索包含`searchText`属性的值。这是一个不区分大小写的搜索。如果设置为`false`，它将搜索`searchText`字符串的精确匹配。精确匹配是区分大小写的。

## FindTask

`FindTask`在上图中执行了对`FindParameters`中指定的图层和字段进行查找操作，并返回一个`FindResult`对象，其中包含找到的记录。看一下以下代码片段：

```js
findTask = new FindTask("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/TaxParcel/TaxParcelQuery/MapServer/");
findTask.execute(findParams,showResults);

function showResults(results) {
    //This function processes the results
}
```

就像`QueryTask`一样，您必须指定一个指向将在查找操作中使用的地图服务的 URL 指针，但您不需要包括指定要使用的确切数据图层的整数值。这是不必要的，因为在`FindParameters`对象中定义了要在查找操作中使用的图层和字段。创建后，您可以调用`FindTask.execute()`方法来启动查找操作。`FindParameters`对象作为第一个参数传递到此方法中，您还可以定义可选的`success`和`error`回调函数。这在上面的代码示例中显示。`success`回调函数传递了一个`FindResults`的实例，其中包含了查找操作的结果。

## FindResult

`FindResult`包含`FindTask`操作的结果，还包含可以表示为图形的要素，找到要素的图层 ID 和名称，以及包含搜索字符串的字段名称。看一下以下代码片段：

```js
function showResults(results) {
//This function works with an array of FindResult that the taskreturns
  map.graphics.clear();
  var symbol = new SimpleFillSymbol(SimpleFillSymbol.STYLE_SOLID, 
  new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID,
  new Color([98,194,204]), 2), new Color([98,194,204,0.5]));
  //create array of attributes
  var items = array.map(results,function(result){
    var graphic = result.feature;
    graphic.setSymbol(symbol);
    map.graphics.add(graphic);
    return result.feature.attributes;
  });
  //Create data object to be used in store
  var data = {
    identifier: "PARCELID", //This field needs to have unique values
    label: "PARCELID", //Name field for display. Not pertinent toagrid but may be used elsewhere.
    items: items
  };
  //Create data store and bind to grid.
  store = new ItemFileReadStore({ data:data });
  var grid = dijit.byId('grid');
  grid.setStore(store);
  //Zoom back to the initial map extent
  map.centerAndZoom(center, zoom);
}
```

# 摘要

与要素相关的属性的返回是 GIS 中最常见的操作之一。ArcGIS Server 有两个可以返回属性的任务：`IdentifyTask`和`FindTask`。`IdentifyTask`属性用于返回在地图上单击的要素的属性。`FindTask`也返回要素的属性，但使用简单的属性查询来返回属性。在本章中，您学习了如何使用 ArcGIS API for JavaScript 来使用这两个任务。在下一章中，您将学习如何使用`Locator`任务执行地理编码和反向地理编码。


# 第八章：将地址转换为点和将点转换为地址

在 Web 地图应用程序中，绘制地址或感兴趣点在地图上是最常用的功能之一。要在地图上将地址绘制为一个点，首先需要获取纬度和经度坐标。地理编码是将物理地址转换为地理坐标的过程。为了将您的地址添加到地图上，它们必须经过一个将坐标分配给地址的地理编码过程。在 ArcGIS Server 中，地理编码是通过使用定位器服务来实现的，并通过 ArcGIS Server JavaScript API 中的`Locator`类来执行，该类访问这些服务以提供地址匹配功能以及反向地理编码。与 ArcGIS Server 提供的其他任务一样，地理编码需要各种输入参数，包括一个`Address`对象来匹配地址，或者在反向地理编码的情况下是一个`Point`对象。然后，这些信息被提交到地理编码服务，并返回一个包含地址匹配的`AddressCandidate`对象，然后可以在地图上绘制。

在本章中，我们将涵盖以下主题：

+   介绍地理编码

+   在 ArcGIS API for JavaScript 中使用定位器服务进行地理编码

+   地理编码过程

+   反向地理编码过程

+   练习定位器服务的时间

# 介绍地理编码

我们首先来看一个地理编码的例子，以便让您更好地了解这个过程。如果您有一个位于 Main St 150 号的地址，您必须先对该地址进行地理编码，然后才能将其绘制为地图上的一个点。如果 150 Main St 位于一个地址范围为 100 到 200 Main St 的街道段上，地理编码过程将会插值 150 Main St 的位置，使其正好位于这个街道段的中间。然后，地理编码软件将 150 Main St 分配给对应于 100 和 200 Main St 之间中点的地理位置。现在您已经有了该地址的坐标，可以在地图上绘制它。这个过程在下图中描述：

![介绍地理编码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_08_01.jpg)

最常见的地理编码级别是街道段地理编码，它根据已知的地理编码在包含地址的街区或街道段的交叉口上分配纬度/经度坐标。这种地理编码方法使用了前面描述的插值过程。这种方法在地址间隔规则的城市地区中最准确。然而，它在准确地地理编码间隔不规则的地址和位于死胡同中的地址时存在问题。农村地区的坐标也因为不完整而臭名昭著，这导致这些地区的地理编码率较低。

# 在 ArcGIS API for JavaScript 中使用定位器服务进行地理编码

ArcGIS Server 的`Locator`服务可以执行地理编码和反向地理编码。使用 ArcGIS Server API for JavaScript，您可以将地址提交给`Locator`服务，并检索地址的地理坐标，然后可以在地图上绘制。以下图示了这个过程。一个由 JavaScript 中的 JSON 对象定义的地址是`Locator`对象的输入，它对地址进行地理编码，并将结果返回到一个`AddressCandidate`对象中，然后可以在地图上显示为一个点。这种模式与我们在前几章中看到的其他任务相同，其中一个输入对象（`Address`对象）为任务（`Locator`）提供输入参数，该任务将作业提交给 ArcGIS Server。然后，结果对象（`AddressCandidate`）被返回到一个回调函数中，该函数处理返回的数据。

![在 ArcGIS API for JavaScript 中使用定位器服务进行地理编码](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_08_02.jpg)

## 输入参数对象

`Locator`任务的输入参数对象将采用地理编码的 JSON 地址对象或反向地理编码的`Point`对象的形式。从编程的角度来看，这些对象的创建方式不同。我们将在下一节讨论每个对象。

### 输入 JSON 地址对象

`Locator`服务可以接受`Point`（用于反向地理编码）或代表地址的`JSON`对象。JSON 对象定义了一个以对象形式格式化的地址，如下面的代码示例所示。该地址被定义为一系列在括号内定义的名称/值对，在这种情况下，名称/值对为街道、城市、州和邮政编码，但名称/值对将根据您在定位器中定义的地理编码服务的类型而变化。

```js
var address = {
    street: "380 New York",
    city: "Redlands",
    state: "CA",
    zip: "92373"
}
```

### 输入 Point 对象

对于反向地理编码，`Locator`服务的输入采用`esri/geometry/Point`对象的形式，通常是通过用户在地图上的点击或应用程序逻辑来定义。`Point`对象通过`Map.click`事件返回，可以被检索并用作`Locator`服务的输入对象。

## 定位器对象

`Locator`类包含可用于使用输入`Point`或`Address`对象执行地理编码或反向地理编码操作的方法和事件。`Locator`需要一个指向您在 ArcGIS Server 中定义的地理编码服务的 URL 指针。下面是一个代码示例，展示了如何创建`Locator`对象的新实例：

```js
var locator = new Locator("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Locators/ESRI_Geocode_USA/GeocodeServer")
```

一旦创建了`Locator`类的新实例，就可以调用`addressToLocations()`方法对地址进行地理编码，或者调用`locationToAddress()`方法执行反向地理编码。这些方法会在操作完成时触发一个事件。在地址地理编码的情况下，会触发`address-to-locations-complete()`事件，在反向地理编码操作完成时会触发`on-location-to-address-complete()`事件。在任何情况下，然后会将`AddressCandidate`对象返回给事件。

### AddressCandidate 对象

`AddressCandidate`对象是`Locator`操作的结果。该对象中存储了各种属性，包括地址、属性、位置和分数。属性属性包含字段名称和值的名称/值对。位置是候选地址的 x 和 y 坐标。分数属性是一个介于 0 和 100 之间的数值，表示地址的质量，得分越高，表示匹配度越好。多个地址可以存储在该对象中作为候选对象数组。

现在，我们将更仔细地查看用于提交地址和点的定位器方法。`Locator.addressToLocations()`方法发送一个请求来对单个地址进行地理编码。创建一个输入地址对象，并将其用作`Locator`对象上找到的`addressToLocations()`方法的参数。地理编码操作的结果以`AddressCandidate`对象的形式返回。然后可以将地址作为图形绘制在地图上。

反向地理编码也可以通过`Locator`对象的`locationToAddress()`方法执行。通过地图上的用户点击或应用程序逻辑创建的`Point`对象被创建并作为参数传递到`locationToAddress()`方法中。还会传递第二个参数到该方法中，指示应从距离点多少米的地方找到匹配的地址。与`addressToLocations()`方法一样，`Locator`返回一个`AddressCandidate`对象，并包含一个地址（如果找到的话）。

## 地理编码过程

我们可以用 ArcGIS API for JavaScript 总结地理编码过程。通过引用 ArcGIS Server 实例上的地理编码服务，创建了一个`Locator`对象。然后，以 JSON 对象形式创建的输入地址通过`addressToLocations()`方法提交给`Locator`对象。这将返回一个或多个`AddressCandidate`对象，然后可以在地图上绘制。看一下下面的图表：

![地理编码过程](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_08_03.jpg)

## 反向地理编码过程

让我们也来回顾一下反向地理编码过程。这个过程也使用了一个`Locator`对象，它引用了一个地理编码服务的 URL。`Point`几何对象是通过在地图上点击位置或其他应用程序生成的事件而创建的。然后，通过`locationToAddress()`方法将这个`Point`对象与一个距离值一起提交给`Locator`。以米为单位提供的`distance`属性确定了`Locator`将尝试在其中找到地址的半径。

如果在半径范围内找到地址，则会创建一个`AddressCandidate`对象，并且可以将其解码为地址。看一下下面的图表：

![反向地理编码过程](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_08_04.jpg)

# 练习使用 Locator 服务的时间

在这个练习中，您将学习如何使用`Locator`类对地址进行地理编码，并将结果叠加在 ArcGIS Online 提供的底图上。打开 JavaScript 沙箱，网址为[`developers.arcgis.com/en/javascript/sandbox/sandbox.html`](http://developers.arcgis.com/en/javascript/sandbox/sandbox.html)，然后执行以下步骤：

1.  在您的`ArcGISJavaScriptAPI`文件夹中，用文本编辑器打开名为`geocode_begin.html`的文件。我使用的是 Notepad++，但您可以使用您最熟悉的任何文本编辑器。本练习的一些代码已经为您编写，这样您就可以专注于地理编码功能。

1.  复制并粘贴文件中的代码，以完全替换沙箱中当前的代码。

1.  添加以下引用，用于本练习中将要使用的对象：

```js
var map, **locator**;
require([
        "esri/map", **"esri/tasks/locator", "esri/graphic",**
 **"esri/InfoTemplate", "esri/symbols/SimpleMarkerSymbol",**
 **"esri/symbols/Font", "esri/symbols/TextSymbol",**
 **"dojo/_base/array", "dojo/_base/Color",**
 **"dojo/number", "dojo/parser", "dojo/dom"**, **"dijit/registry"**,"dijit/form/Button", "dijit/form/Textarea",
        "dijit/layout/BorderContainer","dijit/layout/ContentPane", "dojo/domReady!"
      ], function(
        Map, **Locator, Graphic,**
 **InfoTemplate, SimpleMarkerSymbol,** 
 **Font, TextSymbol,**
 **arrayUtils, Color,**
 **number, parser, dom, registry**
      ) {
        parser.parse();
```

1.  现在在`require()`函数中，我们将初始化`locator`变量，然后将其注册到`Locator`.`address-to-locations-complete`。在用于创建`Map`对象的代码块之后，添加以下两行代码：

```js
locator = newLocator("http://geocode.arcgis.com/arcgis/rest/services/World/GeocodeServer");
locator.on("address-to-locations-complete", showResults);
```

`Locator`的构造函数必须是一个有效的 URL 指针，指向一个定位器服务。在这种情况下，我们使用的是 World Geocoding Service。我们还为`Locator`对象注册了`Locator.address-to-locations-complete`事件。当地理编码完成时，此事件将触发，并在这种情况下调用作为`on()`参数指定的`showResults()`函数。

1.  让我们还为将触发地理编码的按钮注册`click`事件，只需在刚刚创建的两行代码之后添加以下代码。这将触发一个名为`locate()`的 JavaScript 函数的执行，我们将在下一步中创建：

```js
registry.byId("locate").on("click", locate);
```

1.  在这一步中，您将创建一个`locate()`函数，该函数将执行多项任务，包括清除任何现有图形，从网页上的输入文本框创建一个`Address` JSON 对象，定义几个选项，并调用`Locator.addressToLocations()`方法。在您输入的最后一行代码之后，添加以下代码块，如下所示：

```js
function locate() {
  map.graphics.clear();
  var address = {
    "SingleLine": dom.byId("address").value
  };
locator.outSpatialReference = map.spatialReference;
var options = {
  address: address,
  outFields: ["Loc_name"]
}
locator.addressToLocations(options);
}
```

此函数中的第一行代码清除了地图上的任何现有图形。当用户在一个会话中输入多个地址时，这是必需的。接下来，我们将创建一个名为`address`的变量，它是一个包含用户输入地址的 JSON 对象。然后，我们设置输出空间参考，并创建一个包含地址和输出字段的`options`变量，作为 JSON 对象。最后，我们调用`Locator.addressToLocations()`方法，并传入`options`变量。

1.  `showResults()`函数将接收`Locator`服务返回的结果，并在地图上绘制它们。在这种情况下，我们将仅显示得分在 0 到 100 之间的地址大于 80 的地址。`showResults()`函数的一部分已经为您编写了。通过添加以下突出显示的代码行来创建一个新变量来保存`AddressCandidate`对象：

```js
function showResults(evt) {
 **var candidate;**
  var symbol = new SimpleMarkerSymbol();
  var infoTemplate = new InfoTemplate(
    "Location", 
    "Address: ${address}<br />Score: ${score}<br />Sourcelocator: ${locatorName}"
   );
   symbol.setStyle(SimpleMarkerSymbol.STYLE_SQUARE);
   symbol.setColor(new Color([153,0,51,0.75]));
```

1.  在创建`geom`变量的代码行后，开始一个循环，该循环将遍历从`Locator`返回的每个地址：

```js
arrayUtils.every(evt.addresses, function(candidate) {

 });
```

1.  开始一个`if`语句，检查`AddressCandidate.score`属性是否大于 80 的值。我们只想显示匹配值高的地址：

```js
arrayUtils.every(evt.addresses, function(candidate) {
 **if (candidate.score > 80) {**

 **}**
});
```

1.  在`if`块内，创建一个包含地址、得分和`AddressCandidate`对象的字段值的新属性的 JSON 变量。除此之外，`location`属性将保存到`geom`变量中：

```js
arrayUtils.every(evt.addresses, function(candidate) {
     if (candidate.score > 80) {
       var attributes = { 
         address: candidate.address, 
         score: candidate.score, 
         locatorName: candidate.attributes.Loc_name 
       };   
       geom = candidate.location;

     }
});
```

1.  使用您之前创建的或为您创建的`geometry`、`symbol`、`attributes`和`infoTemplate`变量创建一个新的`Graphic`对象，并将它们添加到`GraphicsLayer`：

```js
arrayUtils.every(evt.addresses, function(candidate) {
     if (candidate.score > 80) {
       var attributes = { 
         address: candidate.address, 
         score: candidate.score, 
         locatorName: candidate.attributes.Loc_name 
       };   
       geom = candidate.location;
 **var graphic = new Graphic(geom, symbol, attributes, infoTemplate);**
 **//add a graphic to the map at the geocoded location**
 **map.graphics.add(graphic);**

     }
    });
```

1.  为位置添加文本符号：

```js
arrayUtils.every(evt.addresses, function(candidate) {
     if (candidate.score > 80) {
       var attributes = { 
         address: candidate.address, 
         score: candidate.score, 
         locatorName: candidate.attributes.Loc_name 
       };   
       geom = candidate.location;
var graphic = new Graphic(geom, symbol, attributes, infoTemplate);
       //add a graphic to the map at the geocoded location
       map.graphics.add(graphic);
**//add a text symbol to the map listing the location of the matchedaddress.**
 **var displayText = candidate.address;**
 **var font = new Font(**
 **"16pt",**
 **Font.STYLE_NORMAL,** 
 **Font.VARIANT_NORMAL,**
 **Font.WEIGHT_BOLD,**
 **"Helvetica"**
 **);** 

 **var textSymbol = new TextSymbol(**
 **displayText,**
 **font,**
 **new Color("#666633")**
 **);**
 **textSymbol.setOffset(0,8);**
 **map.graphics.add(new Graphic(geom, textSymbol));**

     }
    });
```

1.  在找到一个得分大于 80 的地址后跳出循环。许多地址将有多个匹配项，这可能会令人困惑。看一下以下代码片段：

```js
arrayUtils.every(evt.addresses, function(candidate) {
     if (candidate.score > 80) {
       var attributes = { 
         address: candidate.address, 
         score: candidate.score, 
         locatorName: candidate.attributes.Loc_name 
       };   
       geom = candidate.location;
var graphic = new Graphic(geom, symbol, attributes,infoTemplate);
       //add a graphic to the map at the geocoded location
       map.graphics.add(graphic);
//add a text symbol to the map listing the location of thematched address.
       var displayText = candidate.address;
       var font = new Font(
         "16pt",
         Font.STYLE_NORMAL, 
         Font.VARIANT_NORMAL,
         Font.WEIGHT_BOLD,
         "Helvetica"
       );          

        var textSymbol = new TextSymbol(
          displayText,
          font,
          new Color("#666633")
         );
         textSymbol.setOffset(0,8);
         map.graphics.add(new Graphic(geom, textSymbol));
         **return false; //break out of loop after one candidate with score greater  than 80 is found.**
     }
    });
```

1.  您可能需要通过检查位于`your ArcGISJavaScriptAPI/solution`文件夹中的解决方案文件`geocode_end.html`来仔细检查您的代码。

1.  当您单击**运行**按钮时，您应该看到以下地图。如果没有，请检查您的代码是否准确。![Time to practice with the Locator service](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_08_05.jpg)

1.  输入一个地址或接受默认值，然后单击**定位**，如下面的屏幕截图所示：![Time to practice with the Locator service](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_08_06.jpg)

# 摘要

ArcGIS Server 的`Locator`服务可以执行地理编码和反向地理编码。使用 ArcGIS API for JavaScript，您可以将地址提交给`Locator`服务，并检索地址的地理坐标，然后可以在地图上绘制出来。地址由 JavaScript 中的 JSON 对象定义，是`Locator`对象的输入，`Locator`对象对地址进行地理编码，并将结果返回为`AddressCandidate`对象，然后可以将其显示为地图上的点。这种模式与我们在前几章中看到的其他任务相同，其中输入对象（`Address`对象）为任务（`Locator`）提供输入参数，任务将作业提交给 ArcGIS Server。然后将结果对象（`AddressCandidate`）返回给回调函数，该函数处理返回的数据。在下一章中，您将学习如何使用各种网络分析任务。


# 第九章：网络分析任务

网络分析服务允许您在街道网络上执行分析，例如从一个地址到另一个地址找到最佳路线，找到最近的学校，确定位置周围的服务区域，或者使用一组服务车辆响应一组订单。可以使用它们的 REST 端点访问这些服务。可以执行服务的三种类型的分析：路由、最近设施和服务区域。我们将在本章中检查每种服务类型。所有网络分析服务都要求您在 ArcGIS Server 上安装网络分析插件。

在本章中，我们将涵盖以下主题：

+   RouteTask

+   练习路由的时间

+   最近设施任务

+   服务区域任务

# RouteTask

在 JavaScript API 中进行路由允许您使用`RouteTask`对象在两个或多个位置之间找到路线，并可选择获取驾驶方向。`RouteTask`对象使用网络分析服务计算路线，可以包括简单和复杂的路线，如多个停靠点、障碍和时间窗口。

`RouteTask`对象在网络中的多个位置之间使用最小成本路径。网络上的阻抗可以包括时间和距离变量。以下截图显示了`RouteTask`实现的输出：

![RouteTask](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_09_1.jpg)

与我们在本课程中研究的其他任务一样，路由是通过一系列对象完成的，包括`RouteParameters`、`RouteTask`和`RouteResult`。以下图示说明了这三个路由对象：

![RouteTask](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_09_2.jpg)

`RouteParameters`对象提供了输入参数给`RouteTask`，`RouteTask`使用输入参数向 ArcGIS Server 提交路由请求。结果以`RouteResult`对象的形式从 ArcGIS Server 返回。

`RouteParameters`对象作为`RouteTask`对象的输入，并可以包括停靠和障碍位置、阻抗、是否返回驾驶方向和路线等。您可以在 JavaScript API 的[`developers.arcgis.com/en/javascript/jsapi/routeparameters-amd.html`](https://developers.arcgis.com/en/javascript/jsapi/routeparameters-amd.html)获取所有参数的完整列表。还提供了一个简短的代码示例，显示如何创建`RouteParameters`的实例，添加停靠点并定义输出空间参考：

```js
routeParams = new RouteParameters();
routeParams.stops = new FeatureSet();
routeParams.outSpatialReference = {wkid:4326};
routeParams.stops.features.push(stop1);
routeParams.stops.features.push(stop2);
```

`RouteTask`对象使用`RouteParameters`提供的输入参数执行路由操作。`RouteTask`的构造函数接受一个指向标识要用于分析的网络服务的 URL 的指针。调用`RouteTask`上的`solve()`方法执行路由任务，使用提供的输入参数对网络分析服务执行路由任务：

```js
routeParams = new RouteParameters();
routeParams.stops = new FeatureSet();
routeParams.outSpatialReference = {wkid:4326};
routeParams.stops.features.push(stop1);
routeParams.stops.features.push(stop2);
**routeTask.solve(routeParams);**

```

`RouteResult`对象从网络分析服务返回给`RouteTask`提供的回调函数。然后回调函数通过向用户显示数据来处理数据。返回的数据在很大程度上取决于提供给`RouteParameters`对象的输入。`RouteParameters`上最重要的属性之一是`stops`属性。这些是要包括在点之间最佳路线分析中的点。停靠点被定义为`DataLayer`或`FeatureSet`的实例，并且是要包括在分析中的一组停靠点。

障碍的概念在路由操作中也很重要。障碍在规划路线时限制移动。障碍可以包括车祸、街道段上的施工工作或其他延误，如铁路道口。障碍被定义为`FeatureSet`或`DataLayer`，并通过`RouteParameters.barriers`属性指定。以下代码显示了如何在您的代码中创建障碍的示例：

```js
var routeParameters = new RouteParameters();
//Add barriers as a FeatureSet
routeParameters.barriers = new FeatureSet();
routeParameters.barriers.features.push(map.graphics.add(new Graphic(evt.mapPoint, barrierSymbol)));
```

只有当`RouteParameters.returnDirections`设置为`true`时，才会返回方向。当你选择返回方向时，你还可以使用各种属性来控制返回的方向。你可以控制方向的语言（`RouteParameters.directionsLanguage`）、长度单位（`RouteParameters.directionsLengthUnits`）、输出类型（`RouteParameters.directionsOutputType`）、样式名称（`RouteParameters.StyleName`）和时间属性（`RouteParameters.directionsTimeAttribute`）。除了方向之外返回的数据还包括点之间的路线、路线名称和停靠点数组。

还可以指定如果其中一个停靠点无法到达，则任务应该失败。这是通过`RouteParameters.ignoreInvalidLocations`属性来实现的。这个属性可以设置为`true`或`false`。你还可以通过诸如`RouteParameters.startTime`（指定路线开始的时间）和`RouteParameters.useTimeWindows`（定义分析中应该使用时间范围）等属性将时间引入到分析中。

# 练习路由

在这个练习中，你将学习如何在你的应用程序中实现路由。你将创建一个`RouteParameters`的实例，通过允许用户在地图上点击点来添加停靠点，并解决路线。返回的路线将显示为地图上的线符号。按照以下指示创建一个包括路由的应用程序：

1.  在[`developers.arcgis.com/en/javascript/sandbox/sandbox.html`](http://developers.arcgis.com/en/javascript/sandbox/sandbox.html)打开 JavaScript 沙盒。

1.  从我在下面的代码片段中突出显示的`<script>`标签中删除 JavaScript 内容：

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

1.  为我们在这个练习中将要使用的对象添加以下引用：

```js
  <script>
    require([
        "esri/map",
        "esri/tasks/RouteParameters",
        "esri/tasks/RouteTask",

        "esri/tasks/FeatureSet",
        "esri/symbols/SimpleMarkerSymbol",
        "esri/symbols/SimpleLineSymbol",
        "esri/graphic",
        "dojo/_base/Color"
      ],
      function(Map, RouteParameters, RouteTask, FeatureSet, SimpleMarkerSymbol, SimpleLineSymbol, Graphic, Color ){

    });
  </script>
```

1.  在`require()`函数内，创建`Map`对象，如下面的代码片段所示，并定义变量来保存用于显示目的的路线对象和符号：

```js
  <script>
    require([
        "esri/map",
        "esri/tasks/RouteParameters",
        "esri/tasks/RouteTask",
        "esri/tasks/RouteResult",
        "esri/tasks/FeatureSet",
        "esri/symbols/SimpleMarkerSymbol",
        "esri/symbols/SimpleLineSymbol",
        "esri/graphic",
        "dojo/_base/Color"
      ],
      function(Map, RouteParameters, RouteTask, RouteResult, FeatureSet, SimpleMarkerSymbol, SimpleLineSymbol, Graphic, Color ){
 **var map, routeTask, routeParams;**
 **var stopSymbol, routeSymbol, lastStop;**

 **map = new Map("mapDiv", {** 
 **basemap: "streets",**
 **center:[-123.379, 48.418], //long, lat**
 **zoom: 14**
 **});**
      });
    </script>
```

1.  在创建`Map`对象的代码块的下方，为`Map.click()`事件添加事件处理程序。这个操作应该触发`addStop()`函数：

```js
map = new Map("mapDiv", { 
    basemap: "streets",
    center:[-123.379, 48.418], //long, lat
    zoom: 14
});
**map.on("click", addStop);**

```

1.  创建`RouteTask`和`RouteParameters`对象。将`RouteParameters.stops`属性设置为一个新的`FeatureSet`对象。同时，设置`RouteParameters.outSpatialReference`属性：

```js
map = new Map("mapDiv", { 
    basemap: "streets",
    center:[-123.379, 48.418], //long, lat
    zoom: 14
});
map.on("click", addStop);
**routeTask = new RouteTask("http://tasks.arcgisonline.com/ArcGIS/rest/services/NetworkAnalysis/ESRI_Route_NA/NAServer/Route");**
**routeParams = new RouteParameters();**
**routeParams.stops = new FeatureSet();**
**routeParams.outSpatialReference = {"wkid":4326};**

```

以下是包含这个网络分析服务的服务目录的屏幕截图：

![练习路由](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_09_10.jpg)

1.  为`RouteTask.solve-complete()`事件的完成和`RouteTask.error()`事件添加事件处理程序。路由任务成功完成应该触发`showRoute()`函数的执行。任何错误应该触发`errorHandler()`函数的执行：

```js
       routeParams = new RouteParameters();
       routeParams.stops = new FeatureSet();
       routeParams.outSpatialReference = {"wkid":4326};

       **routeTask.on("solve-complete", showRoute);**
 **routeTask.on("error", errorHandler);**

```

1.  为路线的起点和终点创建符号对象，以及定义这些点之间路线的线。以下代码应该添加在你在上一步中添加的两行代码的下方：

```js
stopSymbol = new SimpleMarkerSymbol().setStyle(SimpleMarkerSymbol.STYLE_CROSS).setSize(15);
stopSymbol.outline.setWidth(4);
routeSymbol = new SimpleLineSymbol().setColor(new Color([0,0,255,0.5])).setWidth(5);
```

1.  创建`addStop()`函数，当用户在地图上点击时将被触发。这个函数将接受一个`Event`对象作为它唯一的参数。可以从这个对象中提取在地图上点击的点。这个函数将在地图上添加一个点图形，并将图形添加到`RouteParameters.stops`属性；在第二次地图点击时，它将调用`RouteTask.solve()`方法，传入一个`RouteParameters`的实例：

```js
function addStop(evt) {
     var stop = map.graphics.add(new Graphic(evt.mapPoint, stopSymbol));
     routeParams.stops.features.push(stop);

     if (routeParams.stops.features.length >= 2) {
       routeTask.solve(routeParams);
       lastStop = routeParams.stops.features.splice(0, 1)[0];
     }
  }
```

1.  创建`showRoute()`函数，接受一个`RouteResult`的实例。在这个函数中，你需要做的唯一的事情就是将路线作为线添加到`GraphicsLayer`中：

```js
**function showRoute(solveResult) {**
 **map.graphics.add(solveResult.result.routeResults[0].route.setSymbol(routeSymbol));**
 **}**

```

1.  最后，添加错误回调函数，以防路由出现问题。这个函数应该向用户显示错误消息，并删除任何剩余的图形：

```js
function errorHandler(err) {
  alert("An error occurred\n" + err.message + "\n" + err.details.join("\n"));

  routeParams.stops.features.splice(0, 0, lastStop);
  map.graphics.remove(routeParams.stops.features.splice(1,   1)[0]);
}
```

1.  你可能想要在`ArcGISJavaScriptAPI`文件夹中查看解决方案文件（`routing.html`），以验证你的代码是否已经正确编写。

1.  单击**运行**按钮。您应该看到地图如下截图所示。如果没有，您可能需要重新检查代码的准确性。![练习路由时间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_09_3.jpg)

1.  在地图上的某个地方单击。您应该看到一个点标记，如下截图所示：![练习路由时间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_09_4.jpg)

1.  在地图上的其他地方单击。这应该显示第二个标记以及两点之间的最佳路线，如下截图所示：![练习路由时间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_09_5.jpg)

# 最近设施任务

`ClosestFacility`任务测量了事件和设施之间的旅行成本，并确定彼此之间最近的事件和设施。在寻找最近的设施时，您可以指定要找到多少个以及旅行方向是朝向还是远离它们。最近设施求解器显示事件和设施之间的最佳路线，报告它们的旅行成本，并返回驾驶方向。

![最近设施任务](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_09_6.jpg)

解决最近设施操作涉及的类包括`ClosestFacilityParameters`、`ClosestFacilityTask`和`ClosestFacilitySolveResults`，如下所示：

![最近设施任务](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_09_7.jpg)

`ClosestFacilityParameters`类包括默认截止、是否返回事件、路线和方向等输入参数。这些参数用作`ClosestFacilityTask`类的输入，该类包含一个`solve()`方法。最后，结果以`ClosestFacilitySolveResults`对象的形式从 ArcGIS 服务器传递回客户端。

`ClosestFacilityParameters`对象用作`ClosestFacilityTask`的输入。现在将讨论此对象上一些常用的属性。`incidents`和`facilities`属性用于设置分析的位置。任务返回的数据可以通过`returnIncidents`、`returnRoutes`和`returnDirections`属性进行控制，这些属性只是`true`或`false`值，指示是否应在结果中返回信息。`travelDirection`参数指定是否应该到设施或从设施出发旅行，`defaultCutoff`是分析将停止遍历的截止值。以下代码示例显示了如何创建`ClosestFacilityParameters`的实例并应用各种属性：

```js
params = new ClosestFacilityParameters();
params.defaultCutoff = 3.0;
params.returnIncidents = false;
params.returnRoutes = true;
params.returnDirections = true;
```

当您创建一个新的`ClosestFacilityTask`实例时，您需要指向代表网络分析服务的 REST 资源。创建后，`ClosestFacilityTask`类接受`ClosestFacilityParameters`提供的输入参数，并使用`solve()`方法将它们提交给网络分析服务。

这是通过以下代码示例来说明的。`solve()`方法还接受回调和错误回调函数：

```js
**cfTask = new ClosestFacilityTask("http://<domain>/arcgis/rest/services/network/ClosestFacility");**
params = new ClosestFacilityParameters();
params.defaultCutoff = 3.0;
params.returnIncidents = false;
params.returnRoutes = true;
params.returnDirections = true;
**cfTask.solve(params, processResults);**

```

从`ClosestFacilityTask`操作返回的结果是一个`ClosestFacilitySolveResult`对象。此对象可以包含各种属性，包括`DirectionsFeatureSet`对象，这是一个方向数组。这个`DirectionsFeatureSet`对象包含路线的逐步方向文本和几何信息。每个要素的属性提供与相应路段相关的信息。返回的属性包括方向文本、路段长度、沿路段行驶的时间以及到达路段的预计到达时间。`ClosestFacilitySolveResults`中包含的其他属性包括包含设施和事件的数组，表示返回的路线的折线数组，返回的任何消息以及包含障碍的数组。

# 服务区任务

新的 ServiceArea 任务在下面的截图中进行了说明，计算了输入位置周围的服务区域。该服务区域以分钟为单位定义，是一个包含在该时间范围内所有可访问街道的区域。

![服务区域任务](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_09_08.jpg)

涉及服务区域操作的类包括 ServiceAreaParameters、ServiceAreaTask 和 ServiceAreaSolveResults。这些对象在下图中进行了说明：

![服务区域任务](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_09_9.jpg)

ServiceAreaParameters 类包括诸如默认中断、涉及的设施、障碍和限制、行进方向等输入参数。这些参数用作 ServiceAreaTask 类的输入，该类调用 solve()。在 ServiceAreaParameters 中定义的参数传递给 ServiceAreaTask。最后，结果以 ServiceAreaSolveResults 对象的形式从 ArcGIS Server 传递回客户端。ServiceAreaParameters 对象用作 ServiceAreaTask 的输入。本章的这一部分讨论了该对象上一些常用的属性。defaultBreaks 属性是定义服务区域的数字数组。例如，在以下代码示例中，提供了一个值为 2 的单个值，表示我们希望返回设施周围的 2 分钟服务区域。returnFacilities 属性设置为 true 时，表示设施应与结果一起返回。还可以通过 barriers 属性设置各种点、折线和多边形障碍。分析的行进方向可以是到设施或从设施，通过 travelDirection 属性进行设置。ServiceAreaParameters 上还可以设置许多其他属性。以下提供了一个代码示例：

```js
params = new ServiceAreaParameters();
params.defaultBreaks = [2];
params.outSpatialReference = map.spatialReference;
params.returnFacilities = false;
```

ServiceAreaTask 类使用街道网络在位置周围找到服务区域。ServiceAreaTask 的构造函数应该指向代表网络分析服务的 REST 资源。要提交解决服务区域任务的请求，您需要在 ServiceAreaTask 上调用 solve()方法。

ServiceAreaTask 操作返回的结果是一个 ServiceAreaSolveResult 对象。该对象可以包含各种属性，包括 ServiceAreaPolygons 属性，这是从分析中返回的服务区域多边形数组。此外，其他属性包括设施、消息和障碍。

# 总结

路由使您能够向应用程序添加在两个或多个位置之间找到路径并生成驾驶路线的功能。此功能是通过执行网络分析的 RouteTask 对象来实现的。这种功能以及其他网络分析服务需要使用 ArcGIS Server 的网络分析插件。其他网络分析任务包括最近设施任务，它允许您测量事件和设施之间的旅行成本，并确定彼此之间最近的设施，以及服务区域任务，它计算了输入位置周围的服务区域。在下一章中，您将学习如何从应用程序执行地理处理任务。


# 第十章：地理处理任务

地理处理是指以逻辑方式自动化和链接 GIS 操作，以完成某种 GIS 任务。例如，您可能希望对流图层进行缓冲，然后将植被图层裁剪到这个新创建的缓冲区。在 ArcGIS for Desktop 中可以构建模型，并且可以在桌面环境或通过 Web 应用程序访问的集中服务器上以自动化方式运行。ArcToolbox 中的任何工具，无论是您 ArcGIS 许可级别的内置工具还是您构建的自定义工具，都可以在模型中使用，并与其他工具链接在一起。本章将探讨如何通过 ArcGIS API for JavaScript 访问这些地理处理任务。

在本章中，我们将涵盖以下主题：

+   ArcGIS Server 中的模型

+   使用地理处理器-你需要知道

+   理解地理处理任务的服务页面

+   地理处理任务

+   运行任务

+   练习地理处理任务的时间到了！地理处理任务

上图显示了使用 ModelBuilder 构建的模型的组件。这些模型可以作为地理处理任务发布到 ArcGIS Server，然后通过你的应用程序访问。

# ArcGIS Server 中的模型

在 ArcGIS for Desktop 中使用 ModelBuilder 构建模型。构建完成后，这些模型可以作为地理处理任务发布到 ArcGIS Server。然后，Web 应用程序使用在 ArcGIS API for JavaScript 中找到的`Geoprocessor`对象来访问这些任务并检索信息。由于这些模型和工具需要计算密集型和 ArcGIS 软件，它们在 ArcGIS Server 上运行。作业通过您的应用程序提交到服务器，服务完成后会获取结果。通过`Geoprocessor`对象可以提交作业和检索结果。这个过程在下图中有所说明：

![ArcGIS Server 中的模型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_10_2.jpg)

# 使用地理处理器-你需要知道的

在使用地理处理服务时，有三件事情是你需要知道的：

+   首先，您需要知道模型或工具所在的 URL。一个示例 URL 是[`sampleserver1.arcgisonline.com/ArcGIS/rest/services/Demographics/ESRI_Population_World/GPServer/PopulationSummary`](http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Demographics/ESRI_Population_World/GPServer/PopulationSummary)。

+   当您访问此链接时，您还可以找到有关输入和输出参数的信息，任务是异步还是同步，以及更多信息。说到输入和输出参数，您需要知道与这些参数相关的数据类型以及每个参数是否是必需的。

+   最后，您需要知道任务是异步还是同步，以及根据这一知识如何配置您的代码。所有这些信息都可以在地理处理任务的服务页面上找到。![使用地理处理器-你需要知道的](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_10_3.jpg)

# 理解地理处理任务的服务页面

地理处理服务的服务页面包括有关服务的元数据信息。这包括执行类型，可以是同步或异步。在下面的屏幕截图中看到的服务的情况下，**PopulationSummary**服务是一个同步任务，这表明应用程序将等待结果返回。这种执行类型通常用于执行速度快的任务。异步任务被提交为作业，然后应用程序可以在地理处理服务执行其工作时继续运行。任务完成时，它会通知您的应用程序处理已完成并且结果已准备就绪。

其他信息包括参数名称、参数数据类型、参数是输入还是输出类型、参数是必需还是可选、几何类型、空间参考和字段。

![了解地理处理任务的服务页面](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_10_4.jpg)

## 输入参数

关于提交给地理处理任务的输入参数，您必须记住一些细节。几乎所有地理处理任务都需要一个或多个参数。这些参数可以是必需的或可选的，并且被创建为 JSON 对象。在本节中，您将看到一个代码示例，向您展示如何创建这些 JSON 对象。在创建参数作为 JSON 对象时，您必须记住按照它们在服务页面上出现的确切顺序创建它们。参数名称也必须与服务页面上的名称完全相同。请参阅以下屏幕截图，了解如何阅读服务的输入参数的示例：

![输入参数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_10_5.jpg)

以下代码示例是正确的，因为参数名称拼写与服务页面上看到的完全相同（还要注意大小写相同），并且按正确顺序提供：

```js
var params = {
    Input_Observation_Point: featureSetPoints,
    Viewshed_Distance: 250
};
```

相比之下，以下代码示例将是不正确的，因为参数是以相反顺序提供的：

```js
var params = {
    Viewshed_Distance: 250,
    Input_Observation_Point: featureSetPoints
};
```

前面的屏幕截图显示了提交给地理处理任务的输入参数。在编写 JSON 输入参数对象时，非常重要的是您提供与服务页面上给出的确切参数名称，并且按照页面上出现的顺序提供参数。请注意，在我们的代码示例中，我们提供了两个参数：`Input_Observation_Point`和`Viewshed_Distance`。这两个参数都是必需的，并且我们已经将它们命名为它们在服务页面上出现的名称，并且它们的顺序是正确的。

# 地理处理任务

ArcGIS API for JavaScript 中的`Geoprocessor`类表示 GP 任务资源，这是地理处理服务中的单个任务。输入参数通过调用`Geoprocessor.execute()`或`Geoprocessor.submitJob()`传递给`Geoprocessor`类。我们将在后面讨论这两个调用之间的区别。执行地理处理任务后，结果将返回到`Geoprocessor`对象，然后由回调函数处理。创建`Geoprocessor`类的实例只需要传入指向 ArcGIS Server 暴露的地理处理服务的 URL。它需要您导入`esri/tasks/gp`。以下代码示例向您展示如何创建`Geoprocessor`对象的实例：

```js
gp = new Geoprocessor(url);
```

## 运行任务

一旦您了解了 ArcGIS Server 实例可用的地理处理模型和工具以及输入和输出参数，您就可以开始编写执行任务的代码。地理处理作业被提交到 ArcGIS Server 以进行同步或异步执行。同步执行意味着客户端调用执行任务，然后在继续应用程序代码之前等待结果。在异步执行中，客户端提交作业，继续运行其他函数，并稍后检查作业的完成情况。默认情况下，客户端每秒检查一次作业是否完成。服务页面告诉您如何为每个地理处理任务提交作业。只需在服务页面上查找执行类型。执行类型在模型发布为服务时设置。作为开发人员，在发布后，您无法控制类型。

### 同步任务

同步任务需要您的应用程序代码提交作业并等待响应，然后才能继续。因为您的最终用户必须等待结果返回才能继续与应用程序交互，所以这种类型的任务应该仅用于返回数据非常快的任务。如果任务需要的时间超过几秒钟，应将其定义为异步而不是同步。当数据在非常短的时间内返回时，用户很快就会对应用程序感到沮丧。

您需要使用`Geoprocessor.execute()`方法，其中包括属性输入参数和提供的回调函数。当地理处理任务返回提交的作业结果时，将执行回调函数。这些结果存储在`ParameterValue`数组中。

### 异步任务

异步任务需要您提交作业，同时继续在等待过程完成时处理其他函数，然后定期与 ArcGIS Server 检查以检索结果。异步任务的优势在于它不会强迫您的最终用户等待结果。相反，任务被提交，您的最终用户继续与应用程序交互，直到任务完成处理。处理完成后，将在您的应用程序中触发回调函数，您可以处理返回的结果。

`Geoprocessor.submitJob()`方法用于提交地理处理任务的作业。您需要提供输入参数、回调函数和状态回调函数。状态回调函数每次应用程序检查结果时执行。默认情况下，每秒检查一次状态。但是，可以使用`Geoprocessor.setUpdateDelay()`方法更改此间隔。每次检查状态时，都会返回一个`JobInfo`对象，其中包含指示作业状态的信息。当`JobInfo.jobStatus`设置为`STATUS_SUCCEEDED`时，将调用完成回调函数。

提供了异步任务流程的可视化图表，可能有助于加强这些类型任务的操作方式。创建输入参数并将其输入到`Geoprocessor`对象中，该对象使用这些参数向 ArcGIS Server 提交地理处理作业。然后，`Geoprocessor`对象以固定间隔执行`statusCallback()`函数。此函数检查地理处理服务，以查看作业是否已完成。返回一个`JobInfo`对象，其中包含指示其完成状态的状态指示器。此过程持续进行，直到作业完成，此时将调用完成回调函数，并传递作业的结果。

![异步任务](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_10_6.jpg)

# 练习地理处理任务的时间

在本练习中，您将编写一个简单的应用程序，通过访问 Esri 提供的**CreateDriveTimePolygons**模型，在地图上显示行驶时间多边形。该应用程序将在地图上点击的点周围创建 1、2 和 3 分钟的行驶时间多边形。

1.  在[`developers.arcgis.com/en/javascript/sandbox/sandbox.html`](http://developers.arcgis.com/en/javascript/sandbox/sandbox.html)上打开 JavaScript 沙箱。

1.  从我在以下代码片段中突出显示的`<script>`标签中删除 JavaScript 内容：

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

1.  为本练习中将使用的对象添加以下引用：

```js
<script>
**require([**
 **"esri/map",**
 **"esri/graphic",**
 **"esri/graphicsUtils",**
 **"esri/tasks/Geoprocessor",**
 **"esri/tasks/FeatureSet",**
 **"esri/symbols/SimpleMarkerSymbol",**
 **"esri/symbols/SimpleLineSymbol",**
 **"esri/symbols/SimpleFillSymbol",**
**"dojo/_base/Color"],**
**function(Map, Graphic, graphicsUtils, Geoprocessor, FeatureSet, SimpleMarkerSymbol, SimpleLineSymbol, SimpleFillSymbol, Color){**

 **});**
</script>
```

1.  按照以下代码片段中所示创建`Map`对象，并定义变量以保存`Geoprocessor`对象和行驶时间：

```js
<script>
require([
      "esri/map",
      "esri/graphic",
      "esri/graphicsUtils",
      "esri/tasks/Geoprocessor",
      "esri/tasks/FeatureSet",
      "esri/symbols/SimpleMarkerSymbol",
      "esri/symbols/SimpleLineSymbol",
      "esri/symbols/SimpleFillSymbol",
"dojo/_base/Color"],
function(Map, Graphic, graphicsUtils, Geoprocessor, FeatureSet, SimpleMarkerSymbol, SimpleLineSymbol, SimpleFillSymbol, Color){
**var map, gp;**
**var driveTimes = "1 2 3";**

**// Initialize map, GP and image params**
**map = new Map("mapDiv", {** 
 **basemap: "streets",**
 **center:[-117.148, 32.706], //long, lat**
 **zoom: 12**
**});**    });
</script>
```

1.  在`require()`函数内部，创建新的`Geoprocessor`对象并设置输出空间参考：

```js
// Initialize map, GP and image params
map = new Map("mapDiv", { 
  basemap: "streets",
  center:[-117.148, 32.706], //long, lat
  zoom: 12
});

**gp = newGeoprocessor("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Network/ESRI_DriveTime_US/GPServer/CreateDriveTimePolygons");**
**gp.setOutputSpatialReference({wkid:102100});**

```

1.  为`Map.click()`事件设置事件监听器。每次用户在地图上单击时，都会触发计算行驶时间的地理处理任务的执行：

```js
gp = new Geoprocessor("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Network/ESRI_DriveTime_US/GPServer/CreateDriveTimePolygons");
gp.setOutputSpatialReference({wkid:102100});
**map.on("click", computeServiceArea);**

```

1.  现在，您将创建`computeServiceArea()`函数，该函数作为`Map.click()`事件的处理程序。此函数将清除任何现有的图形，创建一个新的点图形，表示用户在地图上单击的点，并执行地理处理任务。首先，在定义处理程序的代码行的下方创建`computeServiceArea()`函数的存根：

```js
gp = new Geoprocessor("http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Network/ESRI_DriveTime_US/GPServer/CreateDriveTimePolygons");
gp.setOutputSpatialReference({wkid:102100});
map.on("click", computeServiceArea);

**function computeServiceArea(evt) {**

**}**

```

1.  清除任何现有的图形，并创建将表示在地图上单击的点的新`SimpleMarkerSymbol`：

```js
function computeServiceArea(evt) {
 **map.graphics.clear();**
 **var pointSymbol = new SimpleMarkerSymbol();**
 **pointSymbol.setOutline = new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([255, 0, 0]), 1);**
 **pointSymbol.setSize(14);**
 **pointSymbol.setColor(new Color([0, 255, 0, 0.25]));**
}
```

1.  当触发`Map.click()`事件时，将创建一个`Event`对象并将其传递给`computeServiceArea()`函数。此对象在我们的代码中由`evt`变量表示。在此步骤中，您将通过传递`Event.mapPoint`属性创建一个新的`Graphic`对象，该属性包含从地图单击返回的`Point`几何以及您在上一步中创建的`SimpleMarkerSymbol`实例。然后，将此新图形添加到`GraphicsLayer`中，以便在地图上显示：

```js
function computeServiceArea(evt) {
  map.graphics.clear();
  varpointSymbol = new SimpleMarkerSymbol();
  pointSymbol.setOutline = new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([255, 0, 0]), 1);
  pointSymbol.setSize(14);
  pointSymbol.setColor(new Color([0, 255, 0, 0.25]));

 **var graphic = new Graphic(evt.mapPoint,pointSymbol);**
 **map.graphics.add(graphic);**
}
```

1.  现在，创建一个名为`features`的数组，并将`graphic`对象放入数组中。这些图形的数组最终将被传递到将传递给地理处理任务的`FeatureSet`对象中：

```js
functioncomputeServiceArea(evt) {
  map.graphics.clear();
  var pointSymbol = new SimpleMarkerSymbol();
  pointSymbol.setOutline = new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([255, 0, 0]), 1);
  pointSymbol.setSize(14);
  pointSymbol.setColor(new Color([0, 255, 0, 0.25]));

  var graphic = new Graphic(evt.mapPoint,pointSymbol);
  map.graphics.add(graphic);

 **var features= [];**
 **features.push(graphic);**
}
```

1.  创建一个新的`FeatureSet`对象，并将图形数组添加到`FeatureSet.features`属性中：

```js
function computeServiceArea(evt) {
  map.graphics.clear();
  var pointSymbol = new SimpleMarkerSymbol();
  pointSymbol.setOutline = new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([255, 0, 0]), 1);
  pointSymbol.setSize(14);
  pointSymbol.setColor(new Color([0, 255, 0, 0.25]));

  var graphic = new Graphic(evt.mapPoint,pointSymbol);
  map.graphics.add(graphic);

  var features= [];
  features.push(graphic);
 **var featureSet = new FeatureSet();**
 **featureSet.features = features;**
}
```

1.  创建一个 JSON 对象，该对象将保存要传递给地理处理任务的输入参数，并调用`Geoprocessor.execute()`方法。输入参数包括`Input_Location`和`Drive_Times`。请记住，每个输入参数必须拼写与服务页面中看到的完全相同，包括大小写。参数的顺序也非常重要，并且也在服务页面上定义。我们将`Input_Location`参数定义为`FeatureSet`对象。`FeatureSet`对象包含一个图形数组，在本例中只有一个单个图形点。`Drive_Times`对象已经使用我们之前创建的`driveTimes`变量硬编码为 1、2 和 3 的值。最后，我们调用`Geoprocessor.execute()`方法，传入输入参数以及将处理结果的回调函数。接下来我们将创建这个回调函数：

```js
function computeServiceArea(evt) {
map.graphics.clear();
varpointSymbol = new SimpleMarkerSymbol();
pointSymbol.setOutline = new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([255, 0, 0]), 1);
pointSymbol.setSize(14);
pointSymbol.setColor(new Color([0, 255, 0, 0.25]));

var graphic = new Graphic(evt.mapPoint,pointSymbol);
map.graphics.add(graphic);

var features= [];
features.push(graphic);
varfeatureSet = new FeatureSet();
featureSet.features = features;
**var params = { "Input_Location":featureSet, "Drive_Times":driveTimes };**
**gp.execute(params, getDriveTimePolys);**
}
```

1.  在最后一步中，我们定义了一个名为`getDriveTimePolys()`的回调函数，当地理处理任务完成行驶时间分析时将被触发。让我们创建这个`getDriveTimePolys()`函数。在`computeServiceArea()`函数的结束大括号下方，开始`getDriveTimePolys()`的存根：

```js
**function getDriveTimePolys(results, messages) {**

**}**

```

1.  `getDriveTimePolys()`函数接受两个参数，包括结果对象和返回的任何消息。定义一个新的`features`变量，其中包含地理处理任务返回的`FeatureSet`对象：

```js
function getDriveTimePolys(results, messages) {
 **var features = results[0].value.features;**
}
```

1.  地理处理任务将返回三个`Polygon`图形。每个`Polygon`图形表示我们硬编码为输入参数的行驶时间（1、2 和 3 分钟）。创建一个`for`循环来处理每个多边形：

```js
function getDriveTimePolys(results, messages) {
  var features = results[0].value.features;

 **for (var f=0, fl=features.length; f<fl; f++) {**

 **}**
}
```

1.  在`for`循环内，使用不同的颜色对每个多边形进行符号化。第一个图形将是红色，第二个是绿色，第三个是蓝色。`FeatureSet`对象中将有三个多边形。使用以下代码块为每个定义不同的多边形符号，并将图形添加到`GraphicsLayer`中：

```js
function getDriveTimePolys(results, messages) {
var features = results[0].value.features;

for (var f=0, fl=features.length; f<fl; f++) {
 **var feature = features[f];**
 **if(f == 0) {**
 **var polySymbolRed = new SimpleFillSymbol();**
 **polySymbolRed.setOutline(new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([0,0,0,0.5]), 1));**
 **polySymbolRed.setColor(new Color([255,0,0,0.7]));**
 **feature.setSymbol(polySymbolRed);**
 **}**
 **else if(f == 1) {**
 **var polySymbolGreen = new SimpleFillSymbol();**
 **polySymbolGreen.setOutline(new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([0,0,0,0.5]), 1));**
 **polySymbolGreen.setColor(new Color([0,255,0,0.7]));**
 **feature.setSymbol(polySymbolGreen);**
 **}**
 **else if(f == 2) {**
 **var polySymbolBlue = new SimpleFillSymbol();**
 **polySymbolBlue.setOutline(new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([0,0,0,0.5]), 1));**
 **polySymbolBlue.setColor(new Color([0,0,255,0.7]));**
 **feature.setSymbol(polySymbolBlue);**
 **}**
 **map.graphics.add(feature);** 
}
```

1.  将地图范围设置为`GraphicsLayer`的范围，该范围现在包含您刚刚创建的三个多边形：

```js
function getDriveTimePolys(results, messages) {
  var features = results[0].value.features;

  for (var f=0, fl=features.length; f<fl; f++) {
    var feature = features[f];
    if(f === 0) {
      var polySymbolRed = new SimpleFillSymbol();
      polySymbolRed.setOutline(new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([0,0,0,0.5]), 1));
      polySymbolRed.setColor(new Color([255,0,0,0.7]));
      feature.setSymbol(polySymbolRed);
    }
    else if(f == 1) {
      var polySymbolGreen = new SimpleFillSymbol();
      polySymbolGreen.setOutline(new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([0,0,0,0.5]), 1));
      polySymbolGreen.setColor(new Color([0,255,0,0.7]));
      feature.setSymbol(polySymbolGreen);
    }
    else if(f == 2) {
      var polySymbolBlue = new SimpleFillSymbol();
      polySymbolBlue.setOutline(new SimpleLineSymbol(SimpleLineSymbol.STYLE_SOLID, new Color([0,0,0,0.5]), 1));
      polySymbolBlue.setColor(new Color([0,0,255,0.7]));
      feature.setSymbol(polySymbolBlue);
    }
    map.graphics.add(feature);
  }
 **map.setExtent(graphicsUtils.graphicsExtent(map.graphics.graphics), true);**
}
```

1.  添加一个`<div>`标签，用于保存应用程序的说明：

```js
<body>
<div id="mapDiv"></div>
**<div id="info" class="esriSimpleSlider">**
 **Click on the map to use a Geoprocessing(GP) task to generate and zoom to drive time polygons. The drive time polygons are 1, 2, and 3 minutes.**
**</div>**
</body>
```

1.  修改代码顶部的`<style>`标签，如以下代码的突出显示部分所示：

```js
<style>
**html, body, #mapDiv {**
**height: 100%;**
**margin: 0;**
**padding: 0;**
**width: 100%;**
 **}**
 **#info {**
**bottom: 20px;**
**color: #444;**
**height: auto;**
**font-family: arial;**
**left: 20px;**
**margin: 5px;**
**padding: 10px;**
**position: absolute;**
**text-align: left;**
**width: 200px;**
**z-index: 40;**
 **}**
</style>
```

1.  您可能希望在`ArcGISJavaScriptAPI`文件夹中查看解决方案文件（`drivetimes.html`），以验证您的代码是否已正确编写。

1.  点击**运行**按钮。您应该在以下截图中看到地图。如果没有，您可能需要重新检查代码的准确性。![练习地理处理任务的时间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_10_7.jpg)

1.  在地图上的某个地方点击。只需片刻，您应该看到行驶时间多边形显示出来。请耐心等待。有时这可能需要一点时间。![练习地理处理任务的时间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_10_8.jpg)

# 摘要

ArcGIS Server 可以公开地理处理服务，如模型和工具，您的应用程序可以访问。这些工具在 ArcGIS Server 上运行，因为它们需要进行计算密集型的操作，并且需要 ArcGIS 软件。作业通过您的应用程序提交到服务器，任务完成后返回结果。地理处理任务可以是同步或异步的，并且由 ArcGIS Server 管理员配置为其中一种类型运行。作为应用程序员，重要的是要了解您正在访问的地理处理服务的类型，因为您对服务的方法调用取决于这些信息。此外，要知道任务是同步还是异步，您还需要知道地理处理模型或工具的 URL 以及输入和输出参数。在下一章中，您将学习如何将 ArcGIS Online 的数据和地图添加到您的应用程序中。


# 第十一章：与 ArcGIS Online 集成

ArcGIS Online 是一个专为处理地图和其他类型地理信息而设计的网站。在这个网站上，您将找到用于构建和共享地图的应用程序。您还将找到有用的底图、数据、应用程序和工具，您可以查看和使用，以及您可以加入的社区。对于应用程序开发人员来说，真正令人兴奋的消息是，您可以使用 ArcGIS Server JavaScript API 将 ArcGIS Online 内容集成到您的自定义开发的应用程序中。在本章中，您将探索如何将 ArcGIS Online 地图添加到您的应用程序中。

在本章中，我们将涵盖以下主题：

+   使用 webmap ID 将 ArcGIS Online 地图添加到您的应用程序

+   使用 JSON 将 ArcGIS Online 地图添加到您的应用程序

+   是时候练习 ArcGIS Online 了

# 使用 webmap ID 将 ArcGIS Online 地图添加到您的应用程序

ArcGIS Server JavaScript API 包括两个用于处理 ArcGIS Online 地图的实用方法。这两种方法都可以在`esri/arcgis/utils`资源中找到。`createMap()`方法用于从 ArcGIS Online 项目创建地图。

ArcGIS Online 图库中的每张地图都有一个唯一的 ID。当您开始创建集成来自 ArcGIS Online 的地图的自定义应用程序时，这个唯一的 ID，称为 webmap，将变得重要。要获取要添加到 JavaScript API 应用程序中的地图的 webmap ID，只需单击在 ArcGIS Online 中找到的共享地图。地址栏将包含地图的 webmap ID。您需要记下这个 ID。以下截图显示了如何从浏览器的地址栏中获取特定地图的 webmap ID：

![使用 webmap ID 将 ArcGIS Online 地图添加到您的应用程序](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_11_01.jpg)

一旦您获得了要集成到自定义 JavaScript API 应用程序中的 ArcGIS Online 地图的 webmap ID，您将需要调用`getItem()`方法，传入 webmap ID。`getItem()`方法返回一个`dojo`/`Deferred`对象。`Deferred`对象专门用于可能不会立即完成的任务。它允许您定义在任务完成时将执行的`success`和`failure`回调函数。在这种情况下，成功完成将向`success`函数传递一个`itemInfo`对象。

这个`itemInfo`对象将用于在您的自定义应用程序中从 ArcGIS Online 创建地图。您将看到一个代码示例，说明了这些主题中的一些内容。

```js
**var agoId = "fc160a96a98d4052ae191cc486961b61";**
**var itemDeferred = arcgisUtils.getItem(agoId);**

**itemDeferred.addCallback(function(itemInfo) {**
var mapDeferred = arcgisUtils.createMap(itemInfo, "map", {
mapOptions: {
  slider: true
  },
  geometryServiceURL: "http://sampleserver3.arcgisonline.com/ArcGIS/rest/services/Geometry/GeometryServer"
  });
mapDeferred.addCallback(function(response) {
map = response.map;
  map.on("resize", resizeMap);
  });
mapDeferred.addErrback(function(error) {
console.log("Map creation failed: " , json.stringify(error));
  });
**itemDeferred.addErrback(function(error) {**
console.log("getItem failed: ", json.stringify(error));
  });
}
```

我们将在两个单独的示例中涵盖整个功能。现在我们将检查`getItem()`方法的使用以及为成功或失败设置回调函数。这些代码行在前面的代码示例中有所突出。在第一行代码中，我们创建一个名为`agoId`的变量，并将其分配给我们想要使用的 webmap ID。接下来，我们调用`getItem()`，传入包含我们的 webmap ID 的`agoId`变量。这将创建一个新的`dojo`/`Deferred`对象，我们将其分配给一个名为`itemDeferred`的变量。使用这个对象，我们可以创建`success`和`error`回调函数。`success`函数称为`addCallback`，它传递一个`itemInfo`对象，我们将使用它来创建我们的地图。我们将在下一节中介绍地图的实际创建过程。在某种错误条件发生时，将调用`addErrback`函数。现在让我们看看地图是如何创建的。以下代码片段的突出显示行说明了地图的创建：

```js
var agoId = "fc160a96a98d4052ae191cc486961b61";
var itemDeferred = arcgisUtils.getItem(agoId);

itemDeferred.addCallback(function(itemInfo) {
**varmapDeferred = arcgisUtils.createMap(itemInfo, "map", {**
**mapOptions: {**
 **slider: true**
 **},**
 **geometryServiceURL: "http://sampleserver3.arcgisonline.com/ArcGIS/rest/services/Geometry/GeometryServer"**
 **});**
**mapDeferred.addCallback(function(response) {**
**map = response.map;**
 **map.on("resize", resizeMap);**
 **});**
**mapDeferred.addErrback(function(error) {**
**console.log("Map creation failed: " , json.stringify(error));**
 **});**
itemDeferred.addErrback(function(error) {
console.log("getItem failed: ", json.stringify(error));
  });
}
```

`createMap()`方法用于实际从 ArcGIS Online 创建地图。此方法接受`itemInfo`的实例，该实例是从成功调用`getItem()`返回的；或者，您可以简单地提供 webmap ID。与我们之前检查的`getItem()`方法一样，`createMap()`也返回一个`dojo`/`Deferred`对象，您可以使用它来分配成功和错误回调函数。成功函数接受一个包含我们用来检索实际地图的`map`属性的`response`对象。当发生阻止地图创建的错误时，错误函数运行。

# 使用 JSON 将 ArcGIS Online 地图添加到您的应用程序

使用 webmap ID 创建地图的替代方法是使用 JSON 对象创建地图，该对象是 web 地图的表示。这在应用程序无法访问 ArcGIS Online 的情况下非常有用。看一下下面的代码片段：

```js
var webmap = {};
webmap.item = {
  "title":"Census Map of USA",
  "snippet": "Detailed description of data",
  "extent": [[-139.4916, 10.7191],[-52.392, 59.5199]]
};
```

接下来，指定组成地图的图层。在前面的片段中，添加了来自 ArcGIS Online 的世界地形底图，以及一个叠加层，该叠加层向地图添加了额外的信息，如边界、城市、水体和地标以及道路。添加了一个操作图层，显示美国人口普查数据：

```js
webmap.itemData = {
"operationalLayers": [{
  "url": " http://sampleserver1.arcgisonline.com/ArcGIS/rest/services/Demographics/ESRI_Census_USA/MapServer",
  "visibility": true,
  "opacity": 0.75,
  "title": "US Census Map",
  "itemId": "204d94c9b1374de9a21574c9efa31164"
}],
"baseMap": {
  "baseMapLayers": [{
  "opacity": 1,
  "visibility": true,
  "url": "http://services.arcgisonline.com/ArcGIS/rest/services/World_Terrain_Base/MapServer"
  },{
  "isReference": true,
  "opacity": 1,
  "visibility": true,
  "url": "http://services.arcgisonline.com/ArcGIS/rest/services/Reference/World_Reference_Overlay/MapServer"
  }],
  "title": "World_Terrain_Base"
},
"version": "1.1"
};
```

一旦`webmap`被定义，使用`createMap()`从定义构建地图：

```js
var mapDeferred = arcgisUtils.createMap(webmap, "map", {
mapOptions: {
slider: true
  }
});
```

# 在 ArcGIS Online 中练习的时间

在这个练习中，您将学习如何将 ArcGIS Online 地图集成到您的应用程序中。这个简单的应用程序将显示来自 ArcGIS Online 的美国超市访问公共地图。这张地图显示了整个美国的数据。分析中包括的超市年销售额为 100 万美元或更多。贫困人口通过从人口普查中获取的街区组贫困率（例如，10%）来表示，然后根据该百分比对该街区组中的每个街区进行符号化。看一下下面的截图：

![在 ArcGIS Online 中练习的时间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_11_02.jpg)

绿点代表生活在距离超市一英里内的贫困人口。红点代表生活在超过一英里步行距离的贫困人口，但可能在 10 分钟的车程内，假设他们有车。灰点代表给定区域的总人口。执行以下步骤：

1.  在编写应用程序之前，让我们探索 ArcGIS Online，看看如何找到地图并检索它们的唯一标识符。打开一个网页浏览器，转到[`arcgis.com`](http://arcgis.com)。

1.  在搜索框中，输入`超市`，如下面的截图所示：![在 ArcGIS Online 中练习的时间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_11_03.jpg)

1.  这将返回一个结果列表。我们将把**超市访问地图**结果添加到我们的应用程序中：![在 ArcGIS Online 中练习的时间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_11_04.jpg)

1.  单击地图缩略图下的**打开**链接。![在 ArcGIS Online 中练习的时间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_11_05.jpg)

1.  这将在 ArcGIS Online 查看器中打开地图。您需要复制下面截图中显示的 web 地图编号。我建议您要么在某个地方写下这个编号，要么复制并粘贴到记事本中。这是地图的唯一 ID：![在 ArcGIS Online 中练习的时间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_11_06.jpg)

1.  在[`developers.arcgis.com/en/javascript/sandbox/sandbox.html`](http://developers.arcgis.com/en/javascript/sandbox/sandbox.html)打开 JavaScript 沙盒。

1.  从我以下划线标记的`<script>`标签中删除 JavaScript 内容：

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

1.  添加我们在这个练习中将使用的对象的以下引用：

```js
<script>
**require([**
 **"dojo/parser",**
 **"dojo/ready",**
 **"dojo/dom",**
 **"esri/map",** 
 **"esri/arcgis/utils",**
 **"esri/dijit/Scalebar",**
 **"dojo/domReady!"**
 **], function(**
**parser,ready,dom,Map,arcgisUtils,Scalebar) {**
 **});**
</script>
```

1.  在这个简单的例子中，我们将在应用程序中硬编码 webmap ID。在`require()`函数内部，创建一个名为`agoId`的新变量，并将其分配给您获取的 webmap ID，如下所示：

```js
<script>
require([
        "dojo/parser",
        "dojo/ready",
        "dojo/dom",
        "esri/map", 
        "esri/arcgis/utils",
        "esri/dijit/Scalebar",
        "dojo/domReady!"
      ], function(
parser,ready,dom,Map,arcgisUtils,Scalebar) {

 **var agoId = "153c17de00914039bb28f6f6efe6d322";** 

    });

</script>
```

1.  在这个练习的最后两个步骤中，我们将处理`arcgisUtils.getItem()`和`arcgisUtils.createMap()`方法。这两种方法都返回所谓的`Dojo`/`Deferred`对象。您需要对`Deferred`对象有基本的了解，否则代码就不会有太多意义。`dojo`/`Deferred`对象专门用于可能不会立即完成的任务。它允许您定义成功和失败的回调函数，当任务完成时将执行这些函数。成功的回调函数将由`Deferred.addCallback()`调用，而失败函数将采用`Deferred.errCallback()`的形式。在`getItem()`的情况下，成功完成将向成功函数传递一个`itemInfo`对象。这个`itemInfo`对象将用于在您的自定义应用程序中从 ArcGIS Online 创建地图。由于某种原因未能完成将导致生成一个错误被传递给`Deferred.addErrback()`函数。将以下代码块添加到您的应用程序中，然后我们将进一步讨论其细节：

```js
<script>
require([
        "dojo/parser",
        "dojo/ready",
        "dojo/dom",
        "esri/map", 
        "esri/arcgis/utils",
        "esri/dijit/Scalebar",
        "dojo/domReady!"
      ], function(
parser,ready,dom,Map,arcgisUtils,Scalebar) {

    var agoId = "153c17de00914039bb28f6f6efe6d322";
 **var itemDeferred = arcgisUtils.getItem(agoId);**

 **itemDeferred.addCallback(function(itemInfo) {**
 **var mapDeferred = arcgisUtils.createMap(itemInfo,"mapDiv", {**
 **mapOptions: {**
 **slider: true,**
 **nav:true**
 **}**
 **});**

 **});**
 **itemDeferred.addErrback(function(error) {**
 **console.log("getItem failed: ",json.stringify(error));**
 **});**

 **});**

</script>
```

在第一行代码中，我们调用`getItem()`函数，传入`agoId`变量，该变量引用来自 ArcGIS Online 的**超市访问地图**。此方法返回一个`Dojo`/`Deferred`对象，存储在名为`itemDeferred`的变量中。

`getItem()`函数获取有关 ArcGIS Online 项目（webmap）的详细信息。传递给回调的对象是一个具有以下规范的通用对象：

```js
{
item: <Object>,
itemData: <Object>
}
```

假设对`getItem()`的调用成功，然后将这个通用的项目对象传递给`addCallback()`函数。在回调函数内部，我们然后调用`getMap()`方法，传入`itemInfo`对象，地图容器的引用以及定义地图功能的任何可选参数。在这种情况下，地图参数包括导航滑块和导航按钮的存在。`getMap()`方法然后返回另一个`Dojo`/`Deferred`对象，存储在`mapDeferred`变量中。在下一步中，您将定义处理将被传回的`Deferred`对象的代码块。

1.  传递给`mapDeferred.addCallback()`函数的对象将采用以下形式：

```js
{
  Map: <esri/Map>,
itemInfo: {
item: <Object>,
itemData: <Object>
  }
}
```

1.  添加以下代码来处理返回的信息：

```js
<script>
require([
        "dojo/parser",
        "dojo/ready",
        "dojo/dom",
        "esri/map", 
        "esri/arcgis/utils",
        "esri/dijit/Scalebar",
        "dojo/domReady!"
      ], function(
parser,ready,dom,Map,arcgisUtils,Scalebar) {

    var agoId = "153c17de00914039bb28f6f6efe6d322";
    var itemDeferred = arcgisUtils.getItem(agoId);

    itemDeferred.addCallback(function(itemInfo) {
    var mapDeferred = arcgisUtils.createMap(itemInfo,"mapDiv", {
      mapOptions: {
      slider: true,
      nav:true
        }
      });
          **mapDeferred.addCallback(function(response) {**
 **map = response.map;**
 **});**
 **mapDeferred.addErrback(function(error) {**
 **console.log("Map creation failed: ", json.stringify(error));**
 **});**

      });
      itemDeferred.addErrback(function(error) {
          console.log("getItem failed: ",json.stringify(error));
      });

  });

</script>
```

成功函数（`mapDeferred.addCallback`）从响应中提取地图并将其分配给地图容器。

1.  您可能希望查看解决方案文件（`arcgisdotcom.html`）在您的`ArcGISJavaScriptAPI`文件夹中，以验证您的代码是否已正确编写。

1.  单击**运行**按钮后，您应该看到以下地图。如果没有，您可能需要重新检查代码的准确性：![在 ArcGIS Online 上练习的时间](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-web-mobi-arcgis-svr-app-js/img/7965_11_07.jpg)

# 总结

ArcGIS Online 正变得越来越重要，作为创建和共享地图和其他资源的平台。作为开发人员，您可以将这些地图集成到自定义应用程序中。每张地图都有一个唯一的标识符，您可以使用它来将地图拉入使用 ArcGIS Server 和 JavaScript API 开发的自定义应用程序中。因为从 ArcGIS Online 返回这些地图可能需要一些时间，`getItem()`和`createMap()`方法返回`Dojo`/`Deferred`对象，这些对象提供了成功和失败的回调函数。一旦成功从 ArcGIS Online 获取地图，它们就可以像任何其他地图服务一样在您的应用程序中呈现。在下一章中，您将学习如何在 JavaScript 中使用 ArcGIS API 进行移动应用程序开发。
