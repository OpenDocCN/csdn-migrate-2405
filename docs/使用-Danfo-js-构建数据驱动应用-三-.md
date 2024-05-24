# 使用 Danfo.js 构建数据驱动应用（三）

> 原文：[`zh.annas-archive.org/md5/074CFA285BE35C0386726A8DBACE1A4F`](https://zh.annas-archive.org/md5/074CFA285BE35C0386726A8DBACE1A4F)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用 Plotly.js 进行数据可视化

绘图和可视化是数据分析中非常重要的任务，因此我们将一个完整的章节来专门讨论它们。数据分析师通常会在**探索性数据分析**（**EDA**）阶段执行绘图和数据可视化。这可以极大地帮助识别数据中隐藏的有用模式，并建立数据建模的直觉。

在本章中，您将学习如何使用**Plotly.js**创建丰富和交互式的图表，这些图表可以嵌入到任何 Web 应用程序中。

具体来说，我们将涵盖以下主题：

+   关于 Plotly.js 的简要介绍

+   Plotly.js 的基础知识

+   使用 Plotly.js 创建基本图表

+   使用 Plotly.js 创建统计图表

# 技术要求

为了跟上本章的内容，您应该具备以下条件：

+   现代浏览器，如 Chrome、Safari、Opera 或 Firefox

+   **Node.js**和可选地，安装在您系统上的**Danfo Notebook**（**Dnotebook**）

+   稳定的互联网连接以下载数据集

有关 Dnotebook 的安装说明，请参见*第二章*，*Dnotebook - 用于 JavaScript 的交互式计算环境*。

注意

如果您不想安装任何软件或库，可以在[`playnotebook.jsdata.org/`](https://playnotebook.jsdata.org/)上使用 Dnotebook 的在线版本。

**Danfo.js**带有一个用于轻松制作图表的绘图**应用程序编程接口**（**API**），在幕后，它使用 Plotly。这是我们在本章介绍 Plotly.js 的主要原因，因为在这里获得的知识将帮助您轻松定制下一章中使用 Danfo.js 创建的图表。

# 关于 Plotly.js 的简要介绍

Plotly.js ([`plotly.com/javascript/`](https://plotly.com/javascript/))，根据作者的说法，是一个建立在流行的 D3.js ([`d3js.org/`](https://d3js.org/))和 stack.gl ([`github.com/stackgl`](https://github.com/stackgl))库之上的开源、高级、声明性图表库。

它支持超过 40 种图表类型，包括以下类型：

+   基本图表，如散点图、线图、条形图和饼图

+   统计图表，如箱线图、直方图和密度图

+   科学图表，如热图、对数图和等高线图

+   金融图表，如瀑布图、蜡烛图和时间序列图

+   地图，如气泡图、区域图和 Mapbox 地图

+   **三维**（**3D**）散点图和曲面图，以及 3D 网格

要使用 Plotly.js，您需要访问浏览器的`React`和`Vue`。在下一节中，我们将看到如何安装 Plotly.js。

## 通过`script`标签使用 Plotly.js

为了在`script`标签中使用 Plotly.js。在下面的代码片段中，我们将在简单的 HTML 文件的头部添加 Plotly.js 的`script`标签：

```js
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
    <script src="img/plotly-1.2.0.min.js"></script> 
</head>
<body>

</body>
</html>
```

一旦您按照上面的代码片段添加了 Plotly.js 的`script`标签，保存 HTML 文件并在浏览器中打开它。输出将是一个空白页面，但在幕后，Plotly.js 被添加并在页面中可用。我们可以通过按照这里的步骤制作一个简单的图表来测试这一点：

1.  在 HTML 主体中创建一个`div`标签，图表将在其中绘制。我们将给这个一个`myPlot`，如下所示：

```js
<body>
 <div id="myPlot">
</body
```

1.  在您的 HTML 页面中，创建样本`x`和`y`数据，然后绘制`scatter`图，如下面的代码片段所示：

```js
...
<body>
    <div id="myPlot"></div>
    <script>
        let data = [{
            x: [1, 3, 5, 6, 8, 9, 5, 8],
            y: [2, 4, 6, 8, 0, 2, 1, 2],
            mode: 'markers',
            type: 'scatter'
        }]
        Plotly.newPlot("myPlot", data)
    </script>
</body>
...
```

在浏览器中打开 HTML 文件将给出以下输出：

![图 5.1 - 使用 Plotly 制作的简单散点图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_01.jpg)

图 5.1 - 使用 Plotly 制作的简单散点图

在 Dnotebook 中，我们将在本章中经常使用，您可以通过首先在顶部单元格中使用`load_package`函数加载并使用 Plotly，如下面的代码片段所示：

```js
load_package(["https://cdn.plot.ly/plotly-1.58.4.min.js"])
```

然后，在一个新的单元格中，您可以添加以下代码：

```js
let data = [{
  x: [1,3,5,6,8,9,5,8],
  y: [2,4,6,8,0,2,1,2],
  mode: 'markers',
  type: 'scatter'
}]

Plotly.newPlot(this_div(), data)
```

运行上述代码单元将给出以下输出：

![图 5.2 - 在 Dnotebook 上使用 Plotly 制作的简单散点图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_02.jpg)

图 5.2 - 在 Dnotebook 上使用 Plotly 制作的简单散点图

您可以看到，前面部分的代码与 HTML 版本相同，只有一个细微的区别 - 将`this_div`函数传递给`Plotly.newPlot`。

`this_div`函数只是一个 Dnotebook 的辅助函数，它创建并返回代码单元块下方的`div`标签的 ID。这意味着每当您在 Dnotebook 中处理图表时，都可以使用`this_div`函数获取`div`标签。

注意

接下来，我们将使用`this_div`而不是指定`div`标签 ID。这是因为我们将主要在 Dnotebook 环境中工作。要在 HTML 或其他`this_div`中使用代码，将`this_div`指定为要使用的`div`标签的 ID。

现在您知道如何安装 Plotly，我们将继续下一节，关于创建基本图表。

# Plotly.js 的基础知识

使用 Plotly.js 的一个主要优势是它很容易上手，并且有很多配置可以指定，使您的图表更好。在本节中，我们将介绍一些重要的可用配置选项，并向您展示如何指定这些选项。

在我们继续之前，让我们了解如何将数据传递给 Plotly。

## 数据格式

要创建`x`和`y`键，如下面的代码示例所示：

```js
const trace1 = { 
  x: [20, 30, 40],
  y: [2, 4, 6]
}
```

注意

在 Plotly 中，数据点通常称为**trace**。这是因为您可以在单个图表中绘制多个数据点。这里提供了一个示例：

`var data = [trace1, trace2]`

`Plotly.newPlot("my_div", data);`

`x`和`y`数组可以包含字符串和数字数据。如果它们包含字符串数据，数据点将按原样绘制，即逐点。这是一个例子：

```js
var trace1 = {
    x:['2020-10-04', '2021-11-04', '2023-12-04'],
    y: ["cat", "goat", "pig"],
    type: 'scatter'
};
Plotly.newPlot(this_div(),  trace1);
```

运行上述代码单元将产生以下输出：

![图 5.3 - 使用 Plotly 绘制日期与字符串值的图表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_03.jpg)

图 5.3 - 使用 Plotly 绘制日期与字符串值的图表

另一方面，如果您的数据是数字的，Plotly 将自动排序，然后选择默认比例。看下面的例子：

```js
var trace1 = {
    x: ['2020-10-04', '2021-11-04', '2023-12-04'],
    y: [90, 20, 10],
    type: 'scatter'
};
var data = [trace1];
Plotly.newPlot(this_div(), data);
```

运行上述代码单元将产生以下输出：

![图 5.4 - 使用 Plotly 绘制日期与数值的图表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_04.jpg)

图 5.4 - 使用 Plotly 绘制日期与数值的图表

在我们进入配置部分之前，让我们看一个在同一图表中绘制多个轨迹的示例。首先，我们设置我们的数据，如下面的代码片段所示：

```js
var trace1 = {
    x:['2020-10-04', '2021-11-04', '2023-12-04'],
    y: [90, 20, 10],
    type: 'scatter'
};
var trace2 = {
    x: ['2020-10-04', '2021-11-04', '2023-12-04'],
    y: [25, 35, 65],
    mode: 'markers',
    marker: {
        size: [20, 20, 20],
    }
};
var data = [trace1, trace2];
Plotly.newPlot(this_div(), data);
```

运行上述代码单元将产生以下输出：

![图 5.5 - 多个轨迹共享相同的 x 轴的图表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_05.jpg)

图 5.5 - 多个轨迹共享相同的 x 轴的图表

注意

在单个图表中绘制多个轨迹时，建议轨迹共享一个公共轴。这样可以使您的图表更易于阅读。

如果您想知道是否可以向数据数组添加更多轨迹，答案是肯定的 - 您可以添加任意数量的轨迹，但必须考虑可解释性，因为添加更多轨迹可能不容易解释。

现在您知道如何将数据传递到图表中，让我们了解一些基本的配置选项，您可以在制作图表时传递给 Plotly。

## 图表的配置选项

配置可以用于设置图表的交互性和模式栏等属性。配置是一个对象，通常作为`Plotly.newPlot`调用的最后一个参数传递，如下面的代码片段所示：

```js
config = { … }
Plotly.newPlot("my_div", data, layout, config)
```

在接下来的几节中，我们将介绍一些常见的配置选项，这些选项将在*第八章*中使用，*创建一个无代码数据分析/处理系统*。如果您想知道有哪些可用的配置选项，可以在这里阅读更多信息：[`plotly.com/javascript/configuration-options/`](https://plotly.com/javascript/configuration-options/)。

### 配置模式栏

**模式栏**是一个水平工具栏，提供了许多选项，可用于与图表进行交互。默认情况下，只有在悬停在图表上时，模式栏才会变为可见，尽管可以更改这一点，我们将在下一节中看到。

#### 使模式栏始终可见

要使模式栏始终可见，可以将`displayModeBar`属性设置为`true`，如下面的代码片段所示：

```js
var trace1 = {
    x: ['2020-10-04', '2021-11-04', '2023-12-04'],
    y: [90, 20, 10],
    type: 'scatter'
};
var data = [trace1];
var layout = {
    title: 'Configure modebar'
};
var config = {
  displayModeBar: true
};
Plotly.newPlot(this_div(), data, layout, config);
```

运行上述代码单元将产生以下输出：

![图 5.6 - 配置模式栏始终显示](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_06.jpg)

图 5.6 - 配置模式栏始终显示

如果不需要模式栏，则将`displayModeBar`函数设置为`false`将确保即使在悬停在其上时，模式栏也会被隐藏。

#### 从模式栏中删除按钮

您可以通过将您不想要的按钮的名称传递给`modeBarButtonsToRemove` `config`属性来从模式栏中移除按钮，我们将在本节中进行演示。

使用与*使模式栏始终可见*部分相同的示踪，我们将从模式栏中移除缩放按钮。您可以在下面的截图中看到在移除之前的放大按钮：

![图 5.7 - 移除缩放按钮之前](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_07.jpg)

图 5.7 - 移除缩放按钮之前

在上面的截图中，我们展示了移除缩放按钮之前的图表。接下来，我们将设置`config`选项以移除该按钮，如下面的代码片段所示：

```js
var config = {
  displayModeBar: true,
  modeBarButtonsToRemove: ['zoomIn2d']
};
Plotly.newPlot(this_div(), data, layout, config);
```

运行上述代码单元将产生以下输出：

![图 5.8 - 移除缩放按钮后的图表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_08.jpg)

图 5.8 - 移除缩放按钮后的图表

使用前面示例中演示的方法，您可以从您的图表中移除任何按钮。您可以在这里查看可以移除的所有模式栏按钮的名称：[`plotly.com/javascript/configuration-options/#remove-modebar-buttons`](https://plotly.com/javascript/configuration-options/#remove-modebar-buttons)。

#### 向模式栏添加自定义按钮

Plotly 提供了一种方法，可以向模式栏添加具有自定义行为的按钮。当我们想要通过自定义行为扩展我们的图表时，这将非常有用，例如，链接到您的个人网站。

在下面的示例中，我们将添加一个自定义按钮，当用户单击时显示`This` `is` `an` `example` `of` `a` `plot` `that` `answers` `a` `question` `on` `click`。

注意

在 Dnotebook 中添加自定义按钮将不起作用，因此我们将在 HTML 文件中进行操作。您可以设置一个带有 Plotly 脚本的 HTML 文件，就像我们在*通过脚本标签使用 Plotly.js*部分中演示的那样。

在您的 HTML 文件的 body 部分中，添加以下代码：

```js
<div id="mydiv"></div>
<script>
        ...
        var config = {
            displayModeBar: true,
          modeBarButtonsToAdd: [
                {
                    name: 'about',
                    icon: Plotly.Icons.question,
                    click: function (gd) {
                        alert('This is an example of a plot that answers a question on click')
                    }
                }]
        }
        Plotly.newPlot("mydiv", data, layout, config);
 </script>
```

保存并在浏览器中打开上述 HTML 文件，然后单击您刚刚创建的按钮。它应该显示一个带有您指定的文本的警报，类似于下面截图中显示的内容：

![图 5.9 - 带有自定义按钮的图表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_09.jpg)

图 5.9 - 带有自定义按钮的图表

在我们之前展示的代码片段中，注意`modeBarButtonsToAdd`配置选项。这个选项是我们定义要添加的按钮以及点击它时发生的事情的地方。创建自定义按钮时可以指定的主要属性列在这里：

+   `name`：按钮的名称。

+   `icon`：显示在模式栏中的图标/图片。这可以是自定义图标或任何内置的 Plotly 图标（[`github.com/plotly/plotly.js/blob/master/src/fonts/ploticon.js`](https://github.com/plotly/plotly.js/blob/master/src/fonts/ploticon.js)）。

+   `click`：定义单击按钮时发生的情况。在这里，您可以指定任何 JavaScript 函数，甚至更改图表的行为。

接下来，让我们看看如何制作静态图表。

### 制作静态图表

默认情况下，Plotly 图表是交互式的。如果要使它们静态，可以在 `config` 对象中指定以下选项：

```js
var config = {
  staticPlot: true
}
```

当我们只想显示一个没有干扰交互的图表时，静态图表是很有用的。

接下来，我们将向您展示如何创建响应式图表。

### 制作响应式图表

要使图表响应式，使其能够自动调整大小以适应显示的窗口，可以将 `responsive` 属性设置为 `true`，就像下面的代码片段中所示：

```js
var config = {
   responsive: true
}
```

响应式图表在创建将在不同屏幕尺寸上显示的网页时非常有用。

在下一节中，我们将向您展示如何下载并设置图表的下载选项。

### 自定义下载图表选项

默认情况下，当显示模式栏时，可以将 Plotly 图表保存为**便携式网络图形**（**PNG**）文件。这可以进行自定义，您可以设置下载图像类型，以及其他属性，如文件名、高度、宽度等。

为了实现这一点，您可以在 `config` 对象中设置 `toImageButtonOptions` 属性，就像我们在下面的代码片段中演示的那样：

```js
var config = {
  toImageButtonOptions: {
    format: 'jpeg', // one of png, svg, jpeg, webp
    filename: 'my_image', // the name of the file
    height: 600,
    width: 700,
  }
}
```

最后，在下一节中，我们将演示如何将图表的区域设置更改为其他语言。

### 更改默认区域设置

在为讲其他语言的人制作图表时，区域设置是很重要的。这可以极大地提高图表的可解释性。

按照下面的步骤，我们将把默认区域设置从英语更改为法语：

1.  获取特定的区域设置，并将其添加到您的 HTML 文件中（或者在 Dnotebook 中使用 `load_scripts` 加载它），就像下面的代码片段中所示的那样：

```js
...
<head>
    <script src="img/plotly-1.58.4.min.js"></script>
    <script src="img/plotly-locale-fr-latest.js"></script>  <!-- load locale -->
</head>
...
```

在 Dnotebook 中，可以使用 `load_package` 来完成这个操作，如下所示：

```js
load_package(["https://cdn.plot.ly/plotly-1.58.4.min.js", "https://cdn.plot.ly/plotly-locale-fr-latest.js"])
```

1.  在您的 `config` 对象中，指定区域设置，就像下面的代码片段中所示的那样：

```js
var config = {
   locale: "fr"
}
```

让我们看一个完整的示例及相应的输出。将以下代码添加到 HTML 文件的主体中：

```js
<div id="mydiv"></div>
 <script>
      var trace1 = {
            x: ['2020-10-04', '2021-11-04', '2023-12-04'],
            y: [90, 20, 10],
            type: 'scatter'
        };
        var trace2 = {
            x: ['2020-10-04', '2021-11-04', '2023-12-04'],
            y: [25, 35, 65],
            mode: 'markers',
            marker: {
                size: [20, 20, 20],
            }
        };
        var data = [trace1, trace2];
        var layout = {
            title: 'Change Locale',
            showlegend: false
        };
        var config = {
            locale: "fr"
        };
        Plotly.newPlot("mydiv", data, layout, config);
    </script>
```

在浏览器中加载 HTML 页面会显示以下图表，其中 `locale` 设置为法语：

![图 5.10 - 区域设置为法语的图表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_10.jpg)

图 5.10 - 区域设置为法语的图表

现在您知道如何配置您的图表，我们将继续讨论图表配置的另一个重要方面：**布局**。

## Plotly 布局

`layout` ([`plotly.com/javascript/reference/layout/`](https://plotly.com/javascript/reference/layout/)) 是传递给 `Plotly.newPlot` 函数的第三个参数。它用于配置绘制图表的区域/布局，以及标题、文本、图例等属性。

有六个布局属性可以设置——标题、图例、边距、大小、字体和颜色。我们将演示如何使用它们，并附有示例。

### 配置图表标题

`title` 属性配置图表标题，即显示在图表顶部的文本。要添加标题，只需将文本传递给 `layout` 对象中的 `title` 属性，就像下面的代码片段中演示的那样：

```js
var layout = {
    title: 'This is an example title,
};
```

要更加明确，特别是如果需要配置标题文本的位置，可以设置 `title` 的 `text` 属性，就像下面的代码片段中所示的那样：

```js
var layout = {
  title: {text: 'This is an example title'}
};
```

使用上述格式，我们可以轻松地配置其他属性，比如使用其他属性来设置标题位置，如下所述：

+   `x`：一个介于 0 和 1 之间的数字，用于设置标题文本相对于显示它的容器的 `x` 位置。

+   `y`：也是一个介于 0 和 1 之间的数字，用于设置标题文本相对于显示它的容器的`y`位置。

+   `xanchor`：可以是`auto`，`left`，`center`或`right`对齐。它设置标题相对于其`x`位置的水平对齐。

+   `yanchor`：可以是`auto`，`top`，`middle`或`bottom`对齐。它设置标题相对于其`y`位置的垂直对齐。

让我们看一个将`title`配置为显示在图表右上角的示例，如下所示：

```js
var trace1 = {
    x:['2020-10-04', '2021-11-04', '2023-12-04'],
    y: [90, 20, 10],
    type: 'scatter'
};
var data = [trace1];
var layout = {
  title: { text: 'This is an example title',
          x: 0.8,
          y: 0.9,
          xanchor: "right"}
};
Plotly.newPlot(this_div(), data, layout, config);
```

这将产生以下输出：

![图 5.11 - 标题配置为右上角的图表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_11.jpg)

图 5.11 - 标题配置为右上角的图表

您还可以设置标题的**填充**。填充可以接受以下参数：

+   `t`：设置标题的顶部填充

+   `b`：设置标题的底部填充

+   `r`：设置右填充，仅在`xanchor`属性设置为`right`时有效

+   `l`：设置左填充，仅在`xanchor`属性设置为`left`时有效

例如，要设置标题的`right`填充，您可以将`xanchor`属性设置为`right`，然后配置`pad`的`r`属性，如下面的代码片段所示：

```js
 var layout = {
  title: {text: 'This is an example title',
          xanchor: "right",
          pad: {r: 100}}
};
```

请注意，前面代码片段中填充参数为`100`表示 100px。

在下一节中，我们将看看如何配置图表的图例。

### 配置 Plotly 图例

图例描述了图表中显示的数据。当您在单个图表中显示多种形式的数据时，图例非常重要。

默认情况下，当图表中有多个数据迹时，Plotly 会显示一个图例。您也可以通过将`layout`的`showLegend`属性显式设置为`true`来显示图例，如下面的代码片段所示：

```js
var layout = {
  showLegend: true
};
```

一旦图例被激活，您可以通过设置以下属性来自定义它的显示方式：

+   `bgcolor`：设置图例的背景颜色。默认情况下，它设置为`#fff`（白色）。

+   `bordercolor`：设置图例边框的颜色。

+   `borderwidth`：设置图例边框的宽度（以 px 为单位）。

+   `font`：一个具有以下属性的对象：

a) `family`：任何支持的 HTML 字体系列。

b) `size`：图例文本的大小。

c) `color`：图例文本的颜色。

在下面的代码片段中，我们展示了使用这些属性来配置图例的示例：

```js
var trace1 = {
    x: ['2020-10-04', '2021-11-04', '2023-12-04'],
    y: [90, 20, 10],
    type: 'scatter'
};
var trace2 = {
    x: ['2020-10-04', '2021-11-04', '2023-12-04'],
    y: [25, 35, 65],
    mode: 'markers',
    marker: {
        size: [20, 20, 20],
    }
};
var data = [trace1, trace2];
var layout = {
  title: {text: 'This is an example title'},
  showLegend: true,
  legend: {bgcolor: "#fcba03",
          bordercolor: "#444",
          borderwidth: 1,
          font: {family: "Arial", size: 30, color: "#fff"}}
};
Plotly.newPlot(this_div(), data, layout, config);
```

前面的代码产生以下输出：

![图 5.12 - 显示自定义配置的图例](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_12.jpg)

图 5.12 - 显示自定义配置的图例

接下来，我们将展示如何配置整体布局的边距。

### 配置布局边距

`margin`属性配置图表在屏幕上的位置。它支持所有的 margin 属性（`l`，`r`，`t`和`b`）。在下面的代码片段中，我们使用所有四个属性来演示设置布局边距：

```js
... 
var layout = {
  title: {text: 'This is an example title'},
  margin: {l: 200, r: 200, t: 230, b: 100}
};
Plotly.newPlot(this_div(), data, layout, config);
```

这将产生以下输出：

![图 5.13 - 配置了边距的图表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_13.jpg)

图 5.13 - 配置了边距的图表

注意前面截图中图表周围的空间？那就是设置的边距。重要的是要注意，边距也是以 px 为单位的。

接下来，我们将看看如何设置布局大小。

### 配置布局大小

有时，我们可能希望有一个更大或更小的布局，可以使用`width`，`height`或者方便的`autosize`属性进行配置，如下面的代码片段所示：

```js
...
var layout = {
  title: {text: 'This is an example title'},
  width: 1000,
  height: 500
};
Plotly.newPlot(this_div(), data, layout, config);
```

这将产生以下输出：

![图 5.14 - 配置了大小的图表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_14.jpg)

图 5.14 - 配置了大小的图表

当我们希望 Plotly 自动设置布局的大小时，`autosize`属性可以设置为`true`。

注意

要查看可以在`layout`中配置的其他属性，您可以访问 Plotly 的官方 API 参考页面：[`plotly.com/javascript/reference/layout`](https://plotly.com/javascript/reference/layout)。

在接下来的部分，我们将向您展示如何根据您想要传达的信息制作不同类型的图表。

# 使用 Plotly.js 创建基本图表

Plotly.js 支持许多基本图表，可以快速用于传达信息。Plotly 中可用的一些基本图表示例包括散点图、线图、条形图、饼图、气泡图、点图、树状图、表格等。您可以在这里找到支持的基本图表的完整列表：[`plotly.com/javascript/basic-charts/`](https://plotly.com/javascript/basic-charts/)。

在本节中，我们将介绍一些基本图表，如散点图、条形图和气泡图。

首先，我们将从散点图开始。

### 使用 Plotly.js 创建散点图

**散点图**通常用于将两个变量相互绘制。该图显示为一组点，因此称为*散点图*。以下截图显示了散点图的示例：

![图 5.15 - 散点图示例，显示票价与年龄间的边距](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_15.jpg)

图 5.15 - 散点图示例，显示票价与年龄间的边距

要使用 Plotly 制作散点图，您只需指定图表类型，就像我们在下面的示例中所示的那样：

```js
var trace1 = {
    x: [2, 5, 7, 12, 15, 20],
    y: [90, 80, 10, 20, 30, 40],
    type: 'scatter'
};
var data = [trace1];
Plotly.newPlot(this_div(), data);
```

这给出了以下输出：

![图 5.16 - 销售与边距的散点图示例](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_16.jpg)

图 5.16 - 销售与边距的散点图示例

默认情况下，点是使用线连接在一起的。您可以通过设置模式类型来更改此行为。模式类型可以是以下任何一种：

+   `标记`

+   `线`

+   `文本`

+   `无`

您还可以使用多种模式，通过加号连接它们在一起，例如，`标记+文本+线`或`标记+线`。

在下面的示例中，我们将`标记`和`文本`作为我们的模式类型：

```js
var trace1 = {
    x: [2, 5, 7, 12, 15, 20],
    y: [90, 80, 10, 20, 30, 40],
    type: 'scatter',
    mode: 'markers+text'
};
var data = [trace1];
Plotly.newPlot(this_div(), data);
```

这给出了以下输出：

![图 5.17 - 散点图，模式类型设置为标记+文本](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_17.jpg)

图 5.17 - 散点图，模式类型设置为标记+文本

如前所述，您可以在单个图表中绘制多个散点图，并且可以根据需要配置每个轨迹。在下面的示例中，我们绘制了三个散点图，并配置了不同的模式：

```js
var trace1 = {
  x: [1, 2, 3, 4, 5],
  y: [1, 6, 3, 6, 1],
  mode: 'markers',
  type: 'scatter',
  name: 'Trace 1',
};
var trace2 = {
  x: [1.5, 2.5, 3.5, 4.5, 5.5],
  y: [4, 1, 7, 1, 4],
  mode: 'lines',
  type: 'scatter',
  name: 'Trace 2',
};
var trace3 = {
  x: [1, 2, 3, 4, 5],
  y: [4, 1, 7, 1, 4],
  mode: 'markers+text',
  type: 'scatter',
  name: 'Trace 3',
};
var data = [ trace1, trace2, trace3];
var layout = {
  title:'Data Labels Hover',
  width: 1000
};
Plotly.newPlot(this_div(), data, layout);
```

运行上述代码单元会得到以下输出：

![图 5.18 - 散点图，带有三个轨迹](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_18.jpg)

图 5.18 - 散点图，带有三个轨迹

现在您已经在本节中学习了基本图表的概念，您可以轻松地根据自定义数据点创建散点图，并使用所需的属性自定义大小。

接下来，我们将简要介绍条形图。

### 创建条形图

条形图是 Plotly.js 中提供的另一种流行类型的图表。它用于显示使用矩形条之间的高度或长度与它们代表的值成比例的数据点之间的关系。条形图主要用于绘制**分类数据**。

注意

分类数据或分类变量是具有固定或有限数量可能值的变量。英文字母就是分类数据的一个例子。

要在 Plotly.js 中制作条形图，您需要传递一个具有相应条高度/长度的分类数据点，然后将类型设置为`bar`，就像下面的示例中所示的那样：

```js
var data = [
  {
    x: ['Apple', 'Mango', 'Pear', 'Banana'],
    y: [20, 20, 15, 40],
    type: 'bar'
  }
];
Plotly.newPlot(this_div(), data);
```

运行上述代码单元会得到以下输出：

![图 5.19 - 带有四个变量的简单条形图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_19.jpg)

图 5.19 - 带有四个变量的简单条形图

您可以在单个布局中绘制多个条形图，方法是创建多个轨迹并将它们作为数组传递。例如，在下面的代码片段中，我们创建了两个轨迹和一个图表：

```js
var trace1 = {
    x: ['Apple', 'Mango', 'Pear', 'Banana'],
    y: [20, 20, 15, 40],
    type: 'bar'
  }
var trace2 = {
    x: ['Goat', 'Lion', 'Spider', 'Tiger'],
    y: [25, 10, 14, 36],
    type: 'bar'
  }
var data = [trace1, trace2]
Plotly.newPlot(this_div(), data);
```

运行上述代码单元会得到以下输出：

![图 5.20 - 带有两个轨迹的条形图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_20.jpg)

图 5.20 - 带有两个轨迹的条形图

在同一类别内绘制多个跟踪时，可以指定`barmode`属性。`barmode`属性可以是`stack`或`group`模式之一。例如，在下面的代码片段中，我们以`stack`模式制作了两个跟踪的条形图：

```js
var trace1 ={
    x: ['Apple', 'Mango', 'Pear', 'Banana'],
    y: [20, 20, 15, 40],
    type: 'bar',
    name: "Bar1"
  }
var trace2 = {
    x: ['Apple', 'Mango', 'Pear', 'Banana'],
    y: [25, 10, 14, 36],
    type: 'bar',
   name: "Bar2"
  }
var data = [trace1, trace2]
var layout = {
  barmode: 'stack'
}
Plotly.newPlot(this_div(), data, layout);
```

运行上述代码单元格会产生以下输出：

![图 5.21 – 两个跟踪的堆叠模式条形图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_21.jpg)

图 5.21 – 两个跟踪的堆叠模式条形图

在下面的代码片段中，我们将`barmode`属性更改为`group`（默认模式）：

```js
...
var layout = {
  barmode: 'group'
}
...
```

这将产生以下输出：

![图 5.22 – 两个跟踪的组模式条形图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_22.jpg)

图 5.22 – 两个跟踪的组模式条形图

您可以在制作条形图时指定许多其他选项，但我们在本节中不会覆盖所有选项。您可以在官方文档中查看所有配置选项，以及创建良好条形图的清晰示例：[`plotly.com/javascript/bar-charts/`](https://plotly.com/javascript/bar-charts/)。

在下一节中，我们将简要介绍气泡图。

### 创建气泡图

气泡图是另一种非常受欢迎的图表类型，可用于覆盖信息。它基本上是散点图的扩展，指定了点的大小。让我们看下面的代码示例：

```js
var trace1 = {
  x: [1, 2, 3, 4],
  y: [10, 11, 12, 13],
  mode: 'markers',
  marker: {
    size: [40, 60, 80, 100]
  }
};
var data = [trace1]
Plotly.newPlot(this_div(), data, layout);
```

运行上述代码单元格会产生以下输出：

![图 5.23 – 一个简单的气泡图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_23.jpg)

图 5.23 – 一个简单的气泡图

在气泡图的上一个代码片段中，您可以看到主要更改是模式和指定大小的标记。大小与点一一映射，如果要为每个气泡应用大小，必须指定大小。

您还可以通过传递颜色数组来更改单个气泡的颜色，如下面的代码片段所示：

```js
...
  marker: {
    size: [40, 60, 80, 100],
    color: ['rgb(93, 164, 214)', 'rgb(255, 144, 14)',  'rgb(44, 160, 101)', 'rgb(255, 65, 54)'],
  }
...
```

运行上述代码单元格会产生以下输出：

![图 5.24 – 一个简单的气泡图，带有不同的颜色](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_24.jpg)

图 5.24 – 一个简单的气泡图，带有不同的颜色

气泡图非常有用，如果您需要了解更多信息或查看一些更高级的示例，可以在 Plotly 的文档中查看示例页面：[`plotly.com/javascript/bubble-charts/`](https://plotly.com/javascript/bubble-charts/)。

您可以在制作许多其他类型的基本图表，但遗憾的是我们无法覆盖所有。Plotly 文档中的*基本图表*页面（[`plotly.com/javascript/basic-charts/`](https://plotly.com/javascript/basic-charts/)）是学习如何制作这些出色图表的好地方，我们鼓励您去看一看。

在下一节中，我们将向您介绍一些统计图表。

# 使用 Plotly.js 创建统计图表

统计图表是统计学家或数据科学家主要使用的不同类型的图表，用于传达信息。统计图的一些示例包括直方图、箱线图、小提琴图、密度图等。在下一小节中，我们将简要介绍三种类型的统计图表-直方图、箱线图和小提琴图。

## 使用 Plotly.js 创建直方图图表

直方图用于表示数值/连续数据的分布或传播。直方图类似于条形图，有时人们可能会混淆两者。区分它们的简单方法是它们可以显示的数据类型。直方图使用连续变量而不是分类变量，并且只需要一个值作为数据。

在下面的代码片段中，我们展示了一个使用生成的随机数的直方图示例：

```js
var x = [];
for (let i = 0; i < 1000; i ++) { //generate random numbers
x[i] = Math.random();
}
var trace = {
    x: x,
    type: 'histogram',
  };
var data = [trace];
Plotly.newPlot(this_div(), data);
```

在上述代码片段中，您将观察到`trace`属性仅指定了`x`数据。这符合我们之前提到的内容-直方图只需要一个值。我们还指定绘图类型为`histogram`，运行代码单元格会产生以下输出：

![图 5.25 – 具有随机 x 值的直方图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_25.jpg)

图 5.25 – 具有随机 x 值的直方图

指定`y`值而不是`x`将导致水平直方图，如下例所示：

```js
...
var trace = {
    y: y,
    type: 'histogram',
  };
...
```

运行上述代码单元格会产生以下输出：

![图 5.26 – 具有随机 y 值的直方图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_26.jpg)

图 5.26 – 具有随机 y 值的直方图

您还可以通过创建多个踪迹并将`barmode`属性设置为`stack`来创建堆叠、叠加或分组的直方图，如下例所示：

```js
var x1 = [];
var x2 = [];
for (var i = 0; i < 1000; i ++) {
x1[i] = Math.random();
x2[i] = Math.random();
}
var trace1 = {
  x: x1,
  type: "histogram",
};
var trace2 = {
  x: x2,
  type: "histogram",
};
var data = [trace1, trace2];
var layout = {barmode: "stack"};
Plotly.newPlot(this_div(), data, layout);
```

运行上述代码单元格会产生以下输出：

![图 5.27 – 堆叠模式下的直方图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_27.jpg)

图 5.27 – 堆叠模式下的直方图

通过改变`barmode`叠加，我们得到以下输出：

```js
…
var layout = {barmode: "overlay"};
…
```

运行上述代码单元格会产生以下输出：

![图 5.28 – 叠加模式下的直方图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_28.jpg)

图 5.28 – 叠加模式下的直方图

要查看更多关于绘制直方图以及各种配置选项的示例，您可以在这里查看直方图文档页面：[`plotly.com/javascript/histograms/`](https://plotly.com/javascript/histograms/)。

在下一节中，我们将介绍箱线图。

## 使用 Plotly.js 创建箱线图

**箱线图**是描述性统计中非常常见的一种图表类型。它使用四分位数图形地呈现数值数据组。箱线图还有延伸在其上下的线，称为**须**。须代表上下**四分位数**之外的变异性。

提示

四分位数将指定数量的数据点分为四部分或四分之一。第一四分位数是最低的 25%数据点，第二四分位数在 25%和 50%之间（达到中位数），第三四分位数在 50%到 75%之间（高于中位数），最后，第四四分位数表示最高的 25%数字。

以下的图表可以帮助你更好地理解箱线图：

![图 5.29 – 描述箱线图的图表（来源：重新绘制自 https://aiaspirant.com/box-plot/）](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_29.jpg)

图 5.29 – 描述箱线图的图表（来源：重新绘制自 https://aiaspirant.com/box-plot/）

在 Plotly.js 中，我们通过传递数据并将`trace`类型设置为`box`来制作箱线图。我们在下面的例子中演示了这一点：

```js
var y0 = [];
var y1 = [];
for (var i = 0; i < 50; i ++) {//generate some random numbers
y0[i] = Math.random();
y1[i] = Math.random() + 1;
}
var trace1 = {
  y: y0,
  type: 'box'
};
var trace2 = {
  y: y1,
  type: 'box'
};
var data = [trace1, trace2];
Plotly.newPlot(this_div(), data);
```

运行上述代码单元格会产生以下输出：

![图 5.30 – 一个简单的箱线图，有两个踪迹](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_30.jpg)

图 5.30 – 一个简单的箱线图，有两个踪迹

我们可以将箱线图的布局配置为水平格式，而不是默认的垂直格式。在下一节中，我们将演示如何做到这一点。

### 制作水平箱线图

通过在踪迹中指定`x`值而不是`y`值，您可以制作水平图。我们在下面的代码片段中演示了这一点：

```js
var x0 = [];
var x1 = [];
for (var i = 0; i < 50; i ++) {
x0[i] = Math.random();
x1[i] = Math.random() + 1;
}
var trace1 = {
  x: x0,
  type: 'box'
};
var trace2 = {
  x: x1,
  type: 'box'
};
var data = [trace1, trace2];
Plotly.newPlot(this_div(), data);
```

运行上述代码单元格会产生以下输出：

![图 5.31 – 一个简单的箱线图，有两个踪迹](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_31.jpg)

图 5.31 – 一个简单的箱线图，有两个踪迹

您还可以制作分组的箱线图，如下一节所示。

### 制作分组的箱线图

多个共享相同*x*轴的踪迹可以被分组成一个单独的箱线图，如下面的代码片段所示：

```js
var x = ['Season 1', 'Season 1', 'Season 1', 'Season 1', 'Season 1', 'Season 1',
         'Season 2', 'Season 2', 'Season 2', 'Season 2', 'Season 2', 'Season 2']
var trace1 = {
  y: [2, 2, 6, 1, 5, 4, 2, 7, 9, 1, 5, 3],
  x: x,
  name: 'Blues FC',
  marker: {color: '#3D9970'},
  type: 'box'
};
var trace2 = {
  y: [6, 7, 3, 6, 0, 5, 7, 9, 5, 8, 7, 2],
  x: x,
  name: 'Reds FC',
  marker: {color: '#FF4136'},
  type: 'box'
};
var trace3 = {
  y: [1, 3, 1, 9, 6, 6, 9, 1, 3, 6, 8, 5],
  x: x,
  name: 'Greens FC',
  marker: {color: '#FF851B'},
  type: 'box'
};
var data = [trace1, trace2, trace3];
var layout = {
  yaxis: {
    title: 'Points in two seasons',
  },
  boxmode: 'group'
};
Plotly.newPlot(this_div(), data, layout);
```

运行上述代码单元格会产生以下输出：

![图 5.32 – 三个踪迹分组在一起的箱线图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_32.jpg)

图 5.32 – 三个踪迹分组在一起的箱线图

您可以在制作箱线图时设置许多其他选项，但我们将让您在此处阅读更多关于它们的箱线图文档：[`plotly.com/javascript/box-plots/`](https://plotly.com/javascript/box-plots/)。

在下一节中，我们将简要介绍小提琴图。

## 使用 Plotly.js 创建小提琴图

**小提琴图**是箱线图的扩展。它也使用四分位数描述数据点，就像箱线图一样，只有一个主要区别——它还显示数据的分布。

以下图表显示了小提琴图和箱线图之间的共同特性：

![图 5.33 - 小提琴图和箱线图之间的共同特性（重新绘制自 https://towardsdatascience.com/violin-plots-explained-fb1d115e023d)](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_33.jpg)

图 5.33 - 小提琴图和箱线图之间的共同特性（重新绘制自 https://towardsdatascience.com/violin-plots-explained-fb1d115e023d）

小提琴图的曲线区域显示了数据的基础分布，并传达了比箱线图更多的信息。

在 Plotly 中，您可以通过将类型更改为`violin`来轻松制作小提琴图。例如，在下面的代码片段中，我们正在重用箱线图部分的代码，只有两个主要更改：

```js
var x = ['Season 1', 'Season 1', 'Season 1', 'Season 1', 'Season 1', 'Season 1',
         'Season 2', 'Season 2', 'Season 2', 'Season 2', 'Season 2', 'Season 2']
var trace1 = {
  y: [2, 2, 6, 1, 5, 4, 2, 7, 9, 1, 5, 3],
  x: x,
  name: 'Blues FC',
  marker: {color: '#3D9970'},
  type: 'violin'
};
var trace2 = {
  y: [6, 7, 3, 6, 0, 5, 7, 9, 5, 8, 7, 2],
  x: x,
  name: 'Reds FC',
  marker: {color: '#FF4136'},
  type: 'violin'
};
var trace3 = {
  y: [1, 3, 1, 9, 6, 6, 9, 1, 3, 6, 8, 5],
  x: x,
  name: 'Greens FC',
  marker: {color: '#FF851B'},
  type: 'violin',
};
var data = [trace1, trace2, trace3];
var layout = {
  yaxis: {
    title: 'Points in two seasons',
  },
  violinmode: 'group'
}; 
Plotly.newPlot(this_div(), data, layout);
```

运行上述代码单元格将得到以下输出：

![图 5.34 - 三个迹线组合在一起的小提琴图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_34.jpg)

图 5.34 - 三个迹线组合在一起的小提琴图

就像其他图表类型一样，您也可以配置小提琴图的显示方式。例如，我们可以在小提琴图中显示基础箱线图，如下面的代码片段所示：

```js
var x = ['Season 1', 'Season 1', 'Season 1', 'Season 1', 'Season 1', 'Season 1',
         'Season 2', 'Season 2', 'Season 2', 'Season 2', 'Season 2', 'Season 2']
var trace = {
  y: [1, 3, 1, 9, 6, 6, 9, 1, 3, 6, 8, 5],
  x: x,
  name: 'Greens FC',
  marker: {color: '#FF851B'},
  type: 'violin',
  box: {
    visible: true
  },
};
var data = [trace];
var layout = {
  yaxis: {
    title: 'Point in two seasons',
  },
};
Plotly.newPlot(this_div(), data, layout);
```

运行上述代码单元格将得到以下输出：

![图 5.35 - 显示基础箱线图的小提琴图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_5_35.jpg)

图 5.35 - 显示基础箱线图的小提琴图

要查看其他配置选项以及一些高级设置，您可以在这里查看小提琴图的文档：[`plotly.com/javascript/violin/`](https://plotly.com/javascript/violin/)。

通过这样，我们已经结束了对 Plotly.js 的介绍部分。在下一章中，我们将向您展示如何使用 Danfo.js 快速轻松地为这个特定库支持的任何类型的数据制作图表。

# 摘要

在本章中，我们介绍了使用 Plotly.js 进行绘图和可视化。首先，我们简要介绍了 Plotly.js，包括安装设置。然后，我们转向图表配置和布局定制。最后，我们向您展示了如何创建一些基本和统计图表。

您在本章中所学到的知识将帮助您轻松创建交互式图表，您可以将其嵌入到您的网站或 Web 应用程序中。

在下一章中，我们将介绍使用 Danfo.js 进行数据可视化，您将看到如何利用 Plotly.js 的知识，可以直接从您的 DataFrame 或 Series 轻松创建令人惊叹的图表。


# 第七章：使用 Danfo.js 进行数据可视化

在前一章中，您学会了如何使用 Plotly.js 创建丰富和交互式的图表，可以嵌入到任何 Web 应用程序中。我们还提到了 Danfo.js 如何在内部使用 Plotly 来直接在 DataFrame 或 Series 上制作图表。在本章中，我们将向您展示如何使用 Danfo.js 绘图 API 轻松创建这些图表。具体来说，在本章中，我们将涵盖以下内容：

+   设置 Danfo.js 进行绘图

+   使用 Danfo.js 创建折线图

+   使用 Danfo.js 创建散点图

+   使用 Danfo.js 创建箱线图和小提琴图

+   使用 Danfo.js 创建直方图

+   使用 Danfo.js 创建条形图

# 技术要求

为了跟随本章的内容，您应该具备以下条件：

+   现代浏览器，如 Chrome、Safari、Opera 或 Firefox

+   Node.js、Danfo.js，以及可选的 Dnotebook 已安装在您的系统上。

+   稳定的互联网连接以下载数据集

有关 Danfo.js 的安装说明可以在*第三章*中找到，*使用 Danfo.js 入门*，而有关 Dnotebook 的安装步骤可以在*第二章*中找到，*Dnotebook-用于 JavaScript 的交互式计算环境*。

# 设置 Danfo.js 进行绘图

默认情况下，Danfo.js 提供了一些基本的图表类型。这些图表可以在任何 DataFrame 或 Series 对象上调用，如果传递了正确的参数，它将显示相应的图表。

在撰写本文时，Danfo.js 附带以下图表：

+   折线图

+   箱线图和小提琴图

+   表格

+   饼图

+   散点图

+   条形图

+   直方图

这些图表通过`plot`函数公开。也就是说，如果您有一个 DataFrame 或 Series 对象，在它们上调用`plot`函数将公开这些图表。

`plot`方法需要一个`div` ID，用于显示图表。例如，假设`df`是一个 DataFrame，我们可以按照下面的代码片段调用`plot`函数：

```js
const df = new DataFrame({...})
df.plot("my_div_id").<chart type>
```

图表类型可以是`line`、`bar`、`scatter`、`hist`、`pie`、`box`、`violin`或`table`。

每种图表类型都将接受特定于图表的参数，但它们都共享一个名为`config`的公共参数。`config`对象用于自定义图表以及布局。将`config`参数视为我们在*第五章*中使用的布局和配置属性的组合。

`config`参数是一个具有以下格式的对象：

```js
config = {
  layout: {…}, // plotly layout parameters like title, font, e.t.c.
  ... // other Plotly configuration parameters like showLegend, displayModeBar, e.t.c.
}
```

在接下来的部分中，我们将展示使用不同图表类型的一些示例，以及如何配置它们。

注意

在接下来的部分中，我们将下载并使用两个真实世界的数据集。这意味着您需要互联网连接来下载数据集。

## 将 Danfo.js 添加到您的代码中

要使用 Danfo.js 进行绘图，您需要将其添加到您的项目中。如果您正在使用我们的示例中将要使用的 Dnotebook，则可以使用`load_package`函数加载 Danfo.js 和 Plotly.js，如下面的代码片段所示：

```js
load_package(["https://cdn.plot.ly/plotly-1.58.4.min.js","https://cdn.jsdelivr.net/npm/danfojs@0.2.3/lib/bundle.min.js"])
```

上述代码将在 Dnotebook 中安装 Danfo.js 和 Plotly.js。Danfo.js 使用安装的 Plotly.js 来制作图表。除非显式加载 Plotly，否则图表将无法工作。

注意

较旧版本的 Danfo.js（0.2.3 之前）附带了 Plotly.js。在新版本中已经删除，如此处显示的发布说明中所述：[`danfo.jsdata.org/release-notes#latest-release-node-v-0-2-5-browser-0-2-4`](https://danfo.jsdata.org/release-notes#latest-release-node-v-0-2-5-browser-0-2-4)。

如果您在 HTML 文件中制作图表，请确保在头部添加`script`标签，如下面的代码片段所示：

```js
...
<head>
<script src="img/plotly-1.2.0.min.js"></script> 
<script src="img/bundle.min.js"></script>
</head>
...
```

最后，在诸如 React 或 Vue 之类的 UI 库中，确保通过 npm 或 yarn 等包管理器安装 Danfo.js 和 Plotly.js。

## 下载数据集以绘制

在本节中，我们将下载一个真实的金融数据集，这个数据集将用于我们所有的示例。在 Dnotebook 中，您可以在顶部单元格中下载数据集，并在其他单元格中使用如下：

```js
var financial_df;
dfd.read_csv("https://raw.githubusercontent.com/plotly/datasets/master/finance-charts-apple.csv")
    .then(data => {
          financial_df  = data
    })
```

注意

确保使用`var`声明`financial_df`。这样可以使`financial_df`在 Dnotebook 的每个单元格中都可用。如果在 React 或纯 HTML 中工作，则建议使用`let`或`const`。

我们可以使用`head`函数和`table`来显示`financial_df`的前五行，如下面的代码片段所示：

```js
table(financial_df.head())
```

运行上述代码会产生以下输出：

![图 6.1 - 表格显示金融数据集的前五行](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_1.jpg)

图 6.1 - 表格显示金融数据集的前五行

现在我们有了数据集，我们可以开始制作一些有趣的图表。首先，我们将从一个简单的折线图开始。

# 使用 Danfo.js 创建折线图

折线图是简单的图表类型，主要用于 Series 数据或单列。它们可以显示数据点的趋势。要在单列上制作折线图 - 比如，在`financial_df`中的`AAPL.Open`，我们可以这样做：

```js
var layout = {
    yaxis: {
      title: 'AAPL open points',
    }
}
var config = {
  displayModeBar: false,
  layout
}
financial_df ['AAPL.Open'].plot(this_div()).line(config)
```

运行上述代码会产生以下输出：

![图 6.2 - 金融数据集的前五行](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_2.jpg)

图 6.2 - 金融数据集的前五行

请注意，我们使用 DataFrame 子集（`financial_df["column name"]`）来获取单个列 - `AAPl.Open` - 作为一个 Series。然后，我们调用`.line`图表类型并传入一个`config`对象。`config`对象接受`layout`属性以及 Danfo.js 和 Plotly 使用的其他参数。

如果要绘制特定列，可以将列名数组传递给`config`参数，如下面的代码片段所示：

```js
var layout = {
    yaxis: {
      title: 'AAPL open points',
    }
}
var config = {
  columns: ["AAPL.Open", "AAPL.Close"],
  displayModeBar: true,
  layout
}
financial_df.plot(this_div()).line(config)
```

运行上述代码会产生以下输出：

![图 6.3 - 将两列绘制为折线图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_3.jpg)

图 6.3 - 将两列绘制为折线图

默认情况下，图表的*x*轴是 DataFrame 或 Series 的索引。对于`financial_df` DataFrame，当我们使用`read_csv`函数下载数据集时，索引是自动生成的。如果要更改索引，可以使用`set_index`函数，如下面的代码片段所示：

```js
var new_df = financial_df.set_index({key: "Date"})
table(new_df.head())
```

输出如下：

![图 6.4 - 表格显示前五行，索引设置为日期](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_4.jpg)

图 6.4 - 表格显示前五行，索引设置为日期

如果我们制作与之前相同的图表，我们会发现*x*轴会自动格式化为日期：

![图 6.5 - 两列（AAPL.open，AAPL.close）针对日期索引的图表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_5.jpg)

图 6.5 - 两列（AAPL.open，AAPL.close）针对日期索引的图表

您可以通过将它们传递到`layout`属性或`config`对象的主体中来指定其他 Plotly 配置选项，例如宽度、字体等。例如，要配置字体、文本大小、布局宽度，甚至添加自定义按钮到您的图表，您可以这样做：

```js
var layout = {

  ...  legend: {bgcolor: "#fcba03", 
          bordercolor: "#444", 
          borderwidth: 1, 
          font: {family: "Arial", size: 10, color: "#fff"}
  },
  ...}
var config = {
  columns: ["AAPL.Open", "AAPL.Close"],
  displayModeBar: true,
  modeBarButtonsToAdd: [{ 
      name: 'about', 
      icon: Plotly.Icons.question, 
      click: function (gd) { 
        alert('An example of configuring Danfo.Js Plots') 
      } 
    }] ,
  layout
}
new_df.plot(this_div()).line(config)
```

运行上述代码单元格会产生以下输出：

![图 6.6 - 具有各种配置以及指定布局属性的折线图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_6.jpg)

图 6.6 - 具有各种配置以及指定布局属性的折线图

有了上述信息，您就可以开始从数据集中制作漂亮的折线图了。在下一节中，我们将介绍 Danfo.js 中可用的另一种类型的图表 - 散点图。

# 使用 Danfo.js 创建散点图

我们可以通过将绘图类型指定为`scatter`来轻松制作散点图。例如，使用前一节中的代码，*使用 Danfo.js 创建折线图*，我们只需将绘图类型从`line`更改为`scatter`，就可以得到所选列的散点图，如下面的代码块所示：

```js
var layout = {
  title: "Time series plot of AAPL open and close points",
  width: 1000,
  yaxis: {
    title: 'AAPL open points',
  },
  xaxis: {
    title: 'Date',
  }
}
var config = {
  columns: ["AAPL.Open", "AAPL.Close"],
  layout
}
new_df.plot(this_div()).scatter(config)
```

运行上述代码单元格会产生以下输出：

![图 6.7 - 两列的散点图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_7.jpg)

图 6.7 - 两列的散点图

如果您需要在 DataFrame 中指定两个特定列之间的散点图，可以在`config`对象中指定`x`和`y`值，如下面的代码所示：

```js
var layout = {
  title: "Time series plot of AAPL open and close points",
  width: 1000,
  yaxis: {
    title: 'AAPL open points',
  },
  xaxis: {
    title: 'Date',
  }
}
var config = {
  x: "AAPL.Low",
  y: "AAPL.High",
  layout
}
new_df.plot(this_div()).scatter(config)
```

运行上述代码单元格会产生以下输出：

![图 6.8 - 明确指定 x 和 y 列的散点图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_8.jpg)

图 6.8 - 明确指定 x 和 y 列的散点图

要自定义布局或设置`config`，您可以将相应的选项传递给`config`对象，就像我们在*使用 Danfo.js 创建折线图*部分中所做的那样。

在下一节中，我们将简要介绍两种类似的图表类型 - 箱线图和小提琴图。

# 使用 Danfo.js 创建箱线图和小提琴图

箱线图和小提琴图非常相似，通常会使用相同的参数。因此，我们将在本节中同时介绍它们。

在以下示例中，我们将首先制作一个箱线图，然后仅通过更改绘图类型选项将其更改为小提琴图。

## 为系列创建箱线图和小提琴图

要为系列或 DataFrame 中的单个列创建箱线图，首先，我们要对其进行子集化以获取系列，然后我们将在其上调用绘图类型，如下面的代码片段所示：

```js
var layout = {
  title: "Box plot on a Series",
}
var config = {
  layout
}
new_df["AAPL.Open"].plot(this_div()).box(config)
```

运行上述代码单元格会产生以下输出：

![图 6.9 - 系列的箱线图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_9.jpg)

图 6.9 - 系列的箱线图

现在，为了将前述图更改为小提琴图，您只需将绘图类型更改为`violin`，如下面的代码片段所示：

```js
...
new_df["AAPL.Open"].plot(this_div()).violin(config)
…
```

运行上述代码单元格会产生以下输出：

![图 6.10 - 系列的小提琴图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_10.jpg)

图 6.10 - 系列的小提琴图

当我们需要一次为多个列制作箱线图时会发生什么？好吧，在下一节中，我们将向您展示。

## 多列的箱线图和小提琴图

为了在 DataFrame 中为多个列创建箱线图/小提琴图，您可以将列名数组传递给绘图，就像我们在下面的代码片段中演示的那样：

```js
var layout = {
  title: "Box plot on multiple columns",
}
var config = {
  columns: ["AAPL.Open", "AAPL.Close", "AAPL.Low", "AAPL.High"],
  layout
}
new_df.plot(this_div()).box(config)
```

运行上述代码单元格会产生以下输出：

![图 6.11 - 一次绘制多列的箱线图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_11.jpg)

图 6.11 - 一次绘制多列的箱线图

通过重用先前的代码，我们可以通过更改绘图类型轻松将箱线图更改为小提琴图，如下所示：

```js
…
new_df.plot(this_div()).violin(config)
...
```

我们得到以下输出：

![图 6.12 - 一次绘制多列的小提琴图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_12.jpg)

图 6.12 - 一次绘制多列的小提琴图

最后，如果我们想要指定`x`和`y`值会发生什么？我们将在下一节中展示这一点。

## 具体的 x 和 y 值的箱线图和小提琴图

我们可以使用特定的`x`和`y`值制作箱线图和小提琴图。`x`和`y`值是必须在 DataFrame 中存在的列名。

注意

建议箱线图的`x`值是分类的，即具有固定数量的类别。这样可以确保可解释性。

在以下示例中，我们将向您展示如何明确指定`x`和`y`值到一个图中：

```js
var layout = {
  title: "Box plot on x and y values",
}
var config = {
  x: "direction",
  y: "AAPL.Open",
  layout
}
new_df.plot(this_div()).box(config)
```

运行上述代码单元格会产生以下输出：

![图 6.13 - 从特定 x 和 y 值绘制箱线图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_13.jpg)

图 6.13 - 从特定 x 和 y 值绘制箱线图

请注意，`x`值是一个名为`direction`的分类变量。该列有两个固定的类别 - `Increasing`和`Decreasing`。

和往常一样，我们可以通过更改类型获得相应的小提琴图：

```js
...
new_df.plot(this_div()).violin(config)
…
```

运行上述代码单元格会产生以下输出：

![图 6.14 - 从特定 x 和 y 值绘制小提琴图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_14.jpg)

图 6.14 - 从特定 x 和 y 值绘制小提琴图

现在，如果我们为`x`和`y`同时指定了连续值会发生什么？好吧，在以下示例中让我们找出来：

```js
var layout = {
  title: "Box plot on two continuous variables",
}
var config = {
  x: "AAPL.Low",
  y: "AAPL.Open",
  layout
}
new_df.plot(this_div()).box(config)
```

运行上述代码单元格会产生以下输出：

![图 6.15 - 两个连续变量的箱线图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_15.jpg)

图 6.15 - 两个连续变量的箱线图

从上述输出可以看出，图表变得几乎无法解释，并且无法实现使用箱线图/小提琴图的目标。因此，建议对于分类`x`值使用箱线图/小提琴图。

在下一节中，我们将介绍用于制作直方图的`hist`绘图类型。

# 使用 Danfo.js 创建直方图

正如我们之前解释的，直方图是数据分布的表示。绘图命名空间提供的`hist`函数可以用于从 DataFrame 或 Series 制作直方图，我们将在下一节中进行演示。

## 从 Series 创建直方图

要从 Series 创建直方图，可以在 Series 上调用`hist`函数，或者如果在 DataFrame 上绘图，可以使用列名对 DataFrame 进行子集化，如下面的示例所示：

```js
var layout = {
   title: "Histogram on a Series data",
}
var config = { 
  layout 
} 
new_df["AAPL.Open"].plot(this_div()).hist(config)
```

运行上述代码单元格会得到以下输出：

![图 6.16 - Series 数据的直方图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_16.jpg)

图 6.16 - Series 数据的直方图

接下来，我们将一次为 DataFrame 中的多个列制作直方图。

## 从多列创建直方图

如果要为 DataFrame 中的多个列制作直方图，可以将列名作为列名数组传递，如下面的代码片段所示：

```js
var layout = {
  title: "Histogram of two columns",
}
var config = { 
  columns: ["dn", "AAPL.Adjusted"],
  layout 
} 
new_df.plot(this_div()).hist(config)
```

运行上述代码单元格会得到以下输出：

![图 6.17 - 两列的直方图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_17.jpg)

图 6.17 - 两列的直方图

如果需要指定单个值`x`或`y`来生成直方图，可以将`x`或`y`值传递给`config`对象。

注意

一次只能指定`x`或`y`中的一个。这是因为直方图是一种单变量图表。因此，如果指定了`x`值，直方图将是垂直的，如果指定了`y`，它将是水平的。

在下面的示例中，通过指定`y`值制作了水平直方图：

```js
var layout = {
  title: "A horizontal histogram",
}
var config = { 
  y: "dn",
  layout 
} 
new_df.plot(this_div()).hist(config)
```

运行上述代码单元格会得到以下输出：

![图 6.18 - 水平直方图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_18.jpg)

图 6.18 - 水平直方图

默认情况下，直方图是垂直的，相当于设置了`x`参数。

在下一节中，我们将介绍条形图。

# 使用 Danfo.js 创建条形图

条形图以矩形条形呈现分类数据，其长度与它们代表的值成比例。

`bar`函数也可以在`plot`命名空间上调用，并且还可以应用各种配置选项。在接下来的几节中，我们将演示如何从 Series 以及具有多个列的 DataFrame 创建条形图。

## 从 Series 创建条形图

要从 Series 制作简单的条形图，可以执行以下操作：

```js
var layout = { 
   title: "A simple bar chart on a series",
} 
var config = {  
  layout  
}  
new_df["AAPL.Volume"].plot(this_div()).bar(config)
```

运行上述代码单元格会得到以下输出：

![图 6.19 - Series 上的条形图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_19.jpg)

图 6.19 - Series 上的条形图

从上图可以看出，我们有大量的条形。这是因为`AAPL.Volume`列是一个连续变量，每个点都创建了一个条形。

为了避免这种无法解释的图表，建议对具有固定数量的数值类别的变量使用条形图。我们可以通过创建一个简单的 Series 来演示这一点，如下面的代码所示：

```js
custom_sf = new dfd.Series([1, 3, 2, 6, 10, 34, 40, 51, 90, 75])
custom_sf.plot(this_div()).bar(config)
```

运行上述代码单元格会得到以下输出：

![图 6.20 - 具有固定值的 Series 上的条形图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_20.jpg)

图 6.20 - 具有固定值的 Series 上的条形图

在下一节中，我们将向您展示如何从指定的列名列表中制作分组条形图。

## 从多列创建条形图

要从列名列表创建分组条形图，可以将列名传递给`config`对象，如下面的示例所示：

```js
var layout = { 
  title: "A bar chart on two columns", 
} 
var config = {  
  columns: ["price", "cost"],
  layout  
}   
var df = new dfd.DataFrame({'price': [20, 18, 489, 675, 1776],
                           'cost': [40, 22, 21, 60, 19],
                           'count': [4, 25, 281, 600, 1900]},
                        {index: [1990, 1997, 2003, 2009, 2014]})
df.plot(this_div()).bar(config)
```

运行上述代码单元格会得到以下输出：

![图 6.21 - 两列的条形图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_6_21.jpg)

图 6.21 - 两列的条形图

请注意，在前面的示例中，我们创建了一个新的 DataFrame。这是因为金融数据集不包含条形图所需的数据类型，正如我们之前所说的。

这就是本章的结束。恭喜您走到了这一步！我们相信您已经学到了很多，并且可以在个人项目中应用在这里获得的知识。

# 总结

在本章中，我们介绍了使用 Danfo.js 进行绘图和可视化。首先，我们向您展示了如何在新项目中设置 Danfo.js 和 Plotly，然后继续下载数据集，将其加载到 DataFrame 中。接下来，我们向您展示了如何创建基本图表，如折线图、条形图和散点图，然后是统计图表，如直方图以及箱线图和小提琴图。最后，我们向您展示了如何配置使用 Danfo.js 创建的图表。

在本章和第五章《使用 Plotly.js 进行数据可视化》中所获得的知识将在创建数据驱动的应用程序以及自定义仪表板时发挥实际作用。

在下一章中，您将学习有关数据聚合和分组操作，从而了解如何执行数据转换，如合并、连接和串联。


# 第八章：数据聚合和分组操作

对分组数据进行`groupby`操作（聚合或转换）以生成一组新值。然后将结果值组合成单个数据组。

这种方法通常被称为**split-apply-combine**。这个术语实际上是由 Hadley Wickham 创造的，他是许多流行的**R**包的作者，用来描述分组操作。*图 7.1*以图形方式描述了 split-apply-combine 的概念：

![图 7.1 – groupby 说明](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_01.jpg)

图 7.1 – groupby 说明

在本章中，我们将探讨执行分组操作的方法：如何按列键对数据进行分组，并在分组数据上联合或独立地执行数据聚合。

本章还将展示如何通过键访问分组数据。它还提供了如何为您的数据创建自定义聚合函数的见解。

本章将涵盖以下主题：

+   数据分组

+   遍历分组数据

+   使用`.apply`方法

+   分组数据的数据聚合

# 技术要求

为了跟随本章，您应该具有以下内容：

+   像 Chrome、Safari、Opera 或 Firefox 这样的现代浏览器

+   **Node.js**、**Danfo.js**和**Dnotebook**已安装在您的系统上

本章的代码在此处可用：[`github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter07`](https://github.com/PacktPublishing/Building-Data-Driven-Applications-with-Danfo.js/tree/main/Chapter07)。

# 数据分组

Danfo.js 只提供了通过特定列中的值对数据进行分组的能力。对于当前版本的 Danfo.js，分组的指定列数只能是一列或两列。

在本节中，我们将展示如何按单个列和双列进行分组。

## 单列分组

首先，让我们通过创建一个 DataFrame 然后按单个列对其进行分组来开始：

```js
let data = { 'A': [ 'foo', 'bar', 'foo', 'bar',
                    'foo', 'bar', 'foo', 'foo' ],
                     'C': [ 1, 3, 2, 4, 5, 2, 6, 7 ],
            'D': [ 3, 2, 4, 1, 5, 6, 7, 8 ] };
let df = new dfd.DataFrame(data);
let group_df = df.groupby([ "A"]);
```

上述代码涉及以下步骤：

1.  首先，我们使用`object`方法创建一个 DataFrame。

1.  然后我们调用`groupby`方法。

1.  然后，我们指定 DataFrame 应该按列`A`进行分组。

`df.groupby(['A'])`返回一个`groupby`数据结构，其中包含对数据进行分组所需的所有必要方法。

我们可以决定对由`A`分组的所有列执行数据操作，或者指定任何其他列。

上述代码输出以下表：

![图 7.2 – DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_02.jpg)

图 7.2 – DataFrame

在下面的代码中，我们将看到如何对分组数据执行一些常见的`groupby`操作：

```js
group_df.mean().print()
```

使用上述代码片段中创建的`groupby_df`操作，我们调用`groupby`的`mean`方法。该方法计算每个组的平均值，如下图所示：

![图 7.3 – groupby DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_03.jpg)

图 7.3 – groupby DataFrame

下图以图形方式显示了上述代码的操作以及如何生成上述表的输出：

![图 7.4 – groupby 方法的图形描述](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_04.jpg)

图 7.4 – groupby 方法的图形描述

根据本章开头讨论的 split-apply-combine 方法，`df.groupby(['A'])`将 DataFrame 分成两个键-`foo`和`bar`。

将 DataFrame 分组为`foo`和`bar`键后，其他列（`C`和`D`）中的值分别根据它们的行对齐分配给每个键。为了强调这一点，如果我们选择`bar`键，从*图 7.2*中，我们可以看到列`C`在`bar`行中有三个数据点（`3`、`4`、`2`）。

因此，如果我们要执行数据聚合操作，比如计算分配给`bar`键的数据的平均值，分配给`bar`键的列`C`的数据点将具有平均值`3`，这对应于*图 7.3*中的表。

注意

与前面段落中描述的相同操作发生在`foo`键上，所有其他数据点都被分配

如我之前所说，这次对分组均值方法的调用适用于所有按`A`分组的列。让我们选择一个特定应用组操作的列，如下所示：

```js
let col_c = group_df.col(['C'])
col_c.sum().print()
```

首先，我们调用`groupby`中的`col`方法。该方法接受一个列名的数组。上述代码的主要目的是获取每个分组键（`foo`和`bar`）的列`C`的总和，这给出以下表格输出：

![图 7.5 – 列 C 的分组操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_05.jpg)

图 7.5 – 列 C 的分组操作

同样的操作可以应用于分组数据中的任何其他列，如下所示：

```js
let col_d = group_df.col(['D'])
col_d.count().print()
```

这段代码片段遵循与上述代码相同的方法，只是将`count` `groupby`操作应用于列`D`，这给出了以下输出：

![图 7.6 – 列 D 的 groupby“count”操作](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_06.jpg)

图 7.6 – 列 D 的 groupby“count”操作

DataFrame 也可以按两列进行分组；单列分组所示的操作也适用于双列分组，我们将在下一小节中看到。

## 双列分组

首先，让我们创建一个 DataFrame 并添加一个额外的列，如下所示：

```js
let data = { 'A': [ 'foo', 'bar', 'foo', 'bar',
                    'foo', 'bar', 'foo', 'foo' ],
              ' B': [ 'one', 'one', 'two', 'three',
                  'two', 'two', 'one', 'three' ],
               'C': [ 1, 3, 2, 4, 5, 2, 6, 7 ],
               'D': [ 3, 2, 4, 1, 5, 6, 7, 8 ] };
let df = new dfd.DataFrame(data);
let group_df = df.groupby([ "A", "B"]);
```

我们添加了一个额外的列`B`，其中包含分类数据 - `one`，`two`和`three`。DataFrame 按列`A`和`B`进行分组，如下表所示：

![图 7.7 – 包含列 B 的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_07.jpg)

图 7.7 – 包含列 B 的 DataFrame

我们也可以像单列分组一样计算平均值，如下所示：

```js
group_df.mean().print()
```

这将根据列`A`和`B`的分组键对列`C`和`D`应用平均值。例如，在*图 7.7*中，我们可以看到我们有一个来自列`A`和`B`的分组键，名为（`foo`，`one`）。这个键在数据中出现了两次。

上述代码输出以下表格：

![图 7.8 – 按 A 和 B 分组的 groupby 均值 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_08.jpg)

图 7.8 – 按 A 和 B 分组的 groupby 均值 DataFrame

在*图 7.7*中，列`C`的值为`1`和`6`，属于（`foo`，`one`）键。同样，`D`的值为`3`和`7`，属于相同的键。如果我们计算平均值，我们会发现它对应于*图 7.8*中的第一列。

我们还可以继续按列`A`和`B`对分组的一列进行求和。让我们选择列`C`：

```js
let col_c = group_df.col(['C']);
col_c.sum().print();
```

我们从分组数据中获取了列`C`，然后计算了每个分组键的总和，如下表所示：

![图 7.9 – 每组列 C 的总和](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_09.jpg)

图 7.9 – 每组列 C 的总和

在本节中，我们看到了如何按单列或双列分组数据。我们还研究了执行数据聚合和访问分组 DataFrame 的列数据。在下一节中，我们将看看如何访问按分组键分组的数据。

# 遍历分组数据

在本节中，我们将看到如何根据分组键访问分组数据，循环遍历这些分组数据，并对其执行数据聚合操作。

## 通过单列和双列分组数据进行迭代

在本节中，我们将看到 Danfo.js 如何提供迭代通过`groupby`操作创建的每个组的方法。这些数据是按`groupby`列中包含的键进行分组的。

键存储为一个名为`data_tensors`的类属性中的字典或对象。该对象包含分组键作为其键，并将与键关联的 DataFrame 数据存储为对象值。

使用上一个 DataFrame，让我们按列`A`进行分组，然后遍历`data_tensors`：

```js
let group_df = df.groupby([ "A"]);
console.log(group_df.data_tensors)
```

我们按列`A`对 DataFrame 进行分组，然后打印出`data_tensors`，如下截图所示：

![图 7.10 – data_tensors 输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_10.jpg)

图 7.10 – data_tensors 输出

*图 7.10*包含了关于`data_tensors`属性包含的更详细信息，但整个内容可以总结为以下结构：

```js
{
  foo: DataFrame,
  bar: DataFrame
}
```

键是列`A`的值，键的值是与这些键关联的 DataFrame。

我们可以迭代`data_tensors`并打印出`DataFrame`表格，以查看它们包含的内容，如下面的代码所示：

```js
let grouped_data = group_df.data_tensors;
for (let key in grouped_data) {
  grouped_data[key].print();
}
```

首先，我们访问`data_tensors`，这是一个`groupby`类属性，并将其赋值给一个名为`grouped_data`的变量。然后我们循环遍历`grouped_data`，访问每个键，并将它们对应的 DataFrame 打印为表格，如下面的截图所示：

![图 7.11 – groupby 键和它们的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_11.jpg)

图 7.11 – groupby 键和它们的 DataFrame

此外，我们可以将与前面代码相同的方法应用到由两列分组的数据上，如下所示：

```js
let group_df = df.groupby([ "A", "B"]); 
let grouped_data = group_df.data_tensors;
for (let key in grouped_data) {
  let key_data = grouped_data[key];
  for (let key2 in key_data) {
    grouped_data[key][key2].print();
  }
}
```

以下是我们在前面的代码片段中遵循的步骤：

1.  首先，`df` DataFrame 按两列（`A`和`B`）进行分组。

1.  我们将`data_tensors`赋值给一个名为`grouped_data`的变量。

1.  我们循环遍历`grouped_data`以获取键。

1.  我们循环遍历`grouped_data`对象，也循环遍历其内部对象（`key_data`）每个键，由于为`grouped_data`生成的对象数据格式，如下所示：

```js
{
  foo : {
    one: DataFrame,
    two: DataFrame,
    three: DataFrame
  },
  bar: {
    one: DataFrame,
    two: DataFrame,
    three: DataFrame
  }
}
```

代码片段给我们提供了以下输出：

![图 7.12 – DataFrame 的两列分组输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_12.jpg)

图 7.12 – DataFrame 的两列分组输出

在本节中，我们学习了如何迭代分组数据。我们看到了`data_tensor`的对象格式如何根据数据的分组方式而变化，无论是单列还是双列。

我们看到了如何迭代`data_tensor`以获取键和它们关联的数据。在下一小节中，我们将看到如何在不手动循环`data_tensor`的情况下获取与每个键关联的数据。

### 使用`get_groups`方法

Danfo.js 提供了一个名为`get_groups()`的方法，可以轻松访问每个键值 DataFrame，而无需循环遍历`data_tensors`对象。每当我们需要访问属于一组键组合的特定数据时，这将非常方便。

让我们从单列分组开始，如下所示：

```js
let group_df = df.groupby([ "A"]);
group_df.get_groups(["foo"]).print()
```

我们按列`A`进行分组，然后调用`get_groups`方法。`get_groups`方法接受一个键组合作为数组。

对于单列分组，我们只有一个键组合。因此，我们传入名为`foo`的其中一个键，然后打印出相应的分组数据，如下面的截图所示：

![图 7.13 – foo 键的 get_groups](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_13.jpg)

图 7.13 – foo 键的 get_groups

同样的方法也可以应用于所有其他键，如下所示：

```js
group_df.get_groups(["bar"]).print()
```

前面的代码给我们提供了以下输出：

![图 7.14 – bar 键的 get_groups](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_14.jpg)

图 7.14 – bar 键的 get_groups

与单列`groupby`相同的方法也适用于两列分组：

```js
let group_df = df.groupby([ "A", "B"]);
group_df.get_groups(["foo","one"]).print()
```

请记住，`get_groups`方法接受键的组合作为数组。因此，对于两列分组，我们传入要使用的列`A`和`B`的键组合。因此，我们获得以下输出：

![图 7.15 – 获取 foo 键和一个组合的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_15.jpg)

图 7.15 – 获取 foo 键和一个组合的 DataFrame

可以对任何其他键组合做同样的操作。让我们尝试`bar`和`two`键，如下所示：

```js
group_df.get_groups(["bar","two"]).print()
```

我们获得以下输出：

![图 7.16 – bar 和 two 键的 DataFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_16.jpg)

图 7.16 – bar 和 two 键的 DataFrame

在本节中，我们介绍了如何迭代分组数据，数据可以按单列或双列进行分组。我们还看到了内部的`data_tensor`数据对象是如何根据数据的分组方式进行格式化的。我们还看到了如何在不循环的情况下访问与每个分组键相关联的数据。

在下一节中，我们还将研究如何使用.apply 方法创建自定义数据聚合函数。

# 使用.apply 方法

在本节中，我们将使用`.apply`方法创建自定义数据聚合函数，可以应用于我们的分组数据。

`.apply`方法使得可以将自定义函数应用于分组数据。这是本章前面讨论的分割-应用-合并方法的主要函数。

Danfo.js 中实现的`groupby`方法只包含了一小部分用于组数据的数据聚合方法，因此`.apply`方法使用户能够从分组数据中构建特殊的数据聚合方法。

使用前面的数据，我们将创建一个新的 DataFrame，不包括前一个 DataFrame 中的列`B`，然后创建一个将应用于分组数据的自定义函数：

```js
let group_df = df.groupby([ "A"]);
const add = (x) => {
  return x.add(2);
};
group_df.apply(add).print();
```

在前面的代码中，我们按列`A`对 DataFrame 进行分组，然后创建一个名为`add`的自定义函数，将值`2`添加到分组数据中的所有数据点。

注意

要传递到这个函数的参数`add`和类似的函数，如`sub`、`mul`和`div`，可以是 DataFrame、Series、数组或整数值。 

前面的代码生成了以下输出：

![图 7.17 - 将自定义函数应用于组数据](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_17.jpg)

图 7.17 - 将自定义函数应用于组数据

让我们创建另一个自定义函数，从每个分组数据中减去最小值：

```js
let data = { 'A': [ 'foo', 'bar', 'foo', 'bar',
                    'foo', 'bar', 'foo', 'foo' ],
            'B': [ 'one', 'one', 'two', 'three',
                  'two', 'two', 'one', 'three' ],
            'C': [ 1, 3, 2, 4, 5, 2, 6, 7 ],
            'D': [ 3, 2, 4, 1, 5, 6, 7, 8 ] };
let df = new DataFrame(data);
let group_df = df.groupby([ "A", "B"]);

const subMin = (x) => {
  return x.sub(x.min());
};

group_df.apply(subMin).print();
```

首先，我们创建了一个包含列`A`、`B`、`C`和`D`的 DataFrame。然后，我们按列`A`和`C`对 DataFrame 进行分组。

创建一个名为`subMin`的自定义函数，用于获取分组数据的最小值，并从分组数据中的每个数据点中减去最小值。

然后，通过.apply 方法将这个自定义函数应用于`group_df`分组数据，因此我们得到了以下输出表：

![图 7.18 - subMin 自定义应用函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_18.jpg)

图 7.18 - subMin 自定义应用函数

如果我们看一下前面图中的表，我们可以看到一些组数据只出现一次，比如属于`bar`和`two`、`bar`和`one`、`bar`和`three`以及`foo`和`three`键的组数据。

前一个键的组数据只有一个项目，因此最小值也是组中包含的单个值；因此，`C_apply`和`D_apply`列的值为`0`。

我们可以调整`subMin`自定义函数，只有在键对有多行时才从每个值中减去最小值，如下所示：

```js
const subMin = (x) => {
  if (x.values.length > 1) {
    return x.sub(x.min());
  } else {
    return x;
  }
};

group_df.apply(subMin).print();
```

自定义函数给出了以下输出表：

![图 7.19 - 自定义 apply 函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_19.jpg)

图 7.19 - 自定义 apply 函数

下图显示了前面代码的图形表示：

![图 7.20 - groupby 和 subMin apply 方法示例](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_20.jpg)

图 7.20 - groupby 和 subMin apply 方法示例

`.apply`方法还使我们能够对数据进行分组后的数据归一化处理。

在机器学习中，我们有所谓的**标准化**，它涉及将数据重新缩放到范围-1 和 1 之间。标准化的过程涉及从数据中减去数据的平均值，然后除以标准差。

使用前面的 DataFrame，让我们创建一个自定义函数，对数据进行标准化处理：

```js
let data = { 'A': [ 'foo', 'bar', 'foo', 'bar',
                    'foo', 'bar', 'foo', 'foo' ],
            'C': [ 1, 3, 2, 4, 5, 2, 6, 7 ],
            'D': [ 3, 2, 4, 1, 5, 6, 7, 8 ] };
let df = new DataFrame(data);
let group_df = df.groupby([ "A"]);

// (x - x.mean()) / x.std()
const norm = (x) => {
  return x.sub(x.mean()).div(x.std());
};

group_df.apply(norm).print();
```

在前面的代码中，我们首先按列`A`对数据进行分组。然后，我们创建了一个名为`norm`的自定义函数，其中包含正在应用于数据的标准化过程，以产生以下输出：

![图 7.21 - 对分组数据进行标准化](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_21.jpg)

图 7.21 - 对分组数据进行标准化

我们已经看到了如何使用`.apply`方法为`groupby`操作创建自定义函数。因此，我们可以根据所需的操作类型创建自定义函数。

在下一节中，我们将研究数据聚合以及如何将不同的数据聚合操作分配给分组数据的不同列。

# 对分组数据进行数据聚合

数据聚合涉及收集数据并以摘要形式呈现，例如显示其统计数据。聚合本身是为统计目的收集数据并将其呈现为数字的过程。在本节中，我们将看看如何在 Danfo.js 中执行数据聚合

以下是所有可用的聚合方法列表：

+   `mean()`: 计算分组数据的平均值

+   `std()`: 计算标准差

+   `sum()`: 获取组中值的总和

+   `count()`: 计算每组的总值数

+   `min()`: 获取每组的最小值

+   `max()`: 获取每组的最大值

在本章的开头，我们看到了如何在组数据上调用先前列出的一些聚合方法。`groupby`类还包含一个名为`.agg`的方法，它允许我们同时对不同列应用不同的聚合操作。

## 对单列分组进行数据聚合

我们将创建一个 DataFrame，并按列对 DataFrame 进行分组，然后在不同列上应用两种不同的聚合方法：

```js
let data = { 'A': [ 'foo', 'bar', 'foo', 'bar',
      'foo', 'bar', 'foo', 'foo' ],
    'C': [ 1, 3, 2, 4, 5, 2, 6, 7 ],
    'D': [ 3, 2, 4, 1, 5, 6, 7, 8 ] };
let df = new DataFrame(data);
let group_df = df.groupby([ "A"]);

group_df.agg({ C:"mean", D: "count" }).print();
```

我们创建了一个 DataFrame，然后按列`A`对 DataFrame 进行分组。然后通过调用`.agg`方法对分组数据进行聚合。

`.agg`方法接受一个对象，其键是 DataFrame 中列的名称，值是我们要应用于每个列的聚合方法。在前面的代码块中，我们指定了键为`C`和`D`，值为`mean`和`count`：

![图 7.22 - 对组数据进行聚合方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_22.jpg)

图 7.22 - 对组数据进行聚合方法

我们已经看到了如何在单列分组上进行数据聚合。现在让我们看看如何在由双列分组的 DataFrame 上执行相同的操作。

## 对双列分组进行数据聚合

对于双列分组，让我们应用相同的聚合方法：

```js
let data = { 'A': [ 'foo', 'bar', 'foo', 'bar',
      'foo', 'bar', 'foo', 'foo' ],
    'B': [ 'one', 'one', 'two', 'three',
      'two', 'two', 'one', 'three' ],
    'C': [ 1, 3, 2, 4, 5, 2, 6, 7 ],
    'D': [ 3, 2, 4, 1, 5, 6, 7, 8 ] };
let df = new DataFrame(data);
let group_df = df.groupby([ "A", "B"]);

group_df.agg({ C:"mean", D: "count" }).print();
```

前面的代码给出了以下输出：

![图 7.23 - 对两列分组数据进行聚合方法](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_23.jpg)

图 7.23 - 对两列分组数据进行聚合方法

在本节中，我们已经看到了如何使用`.apply`方法为分组数据创建自定义函数，以及如何对分组数据的每一列执行联合数据聚合。这里显示的示例可以扩展到任何特定数据，并且可以根据需要创建自定义函数。

## 在真实数据上应用 groupby 的简单示例

我们已经看到了如何在虚拟数据上使用`groupby`方法。在本节中，我们将看到如何使用`groupby`来分析数据。

我们将使用此处提供的流行的`titanic`数据集：[`web.stanford.edu/class/archive/cs/cs109/cs109.1166/stuff/titanic.csv`](https://web.stanford.edu/class/archive/cs/cs109/cs109.1166/stuff/titanic.csv)。我们将看看如何根据性别和阶级估计幸存泰坦尼克号事故的平均人数。

让我们将`titanic`数据集读入 DataFrame 并输出其中的一些行：

```js
const dfd = require('danfojs-node')
async function analysis(){
  const df = dfd.read_csv("titanic.csv")
  df.head().print()
}
analysis()
```

前面的代码应该输出以下表格：

![图 7.24 - DataFrame 表](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_24.jpg)

图 7.24 - DataFrame 表

从数据集中，我们想要估计根据性别（`Sex`列）和他们的旅行等级（`Pclass`列）生存的人数。

以下代码显示了如何估计先前描述的平均生存率：

```js
const dfd = require('danfojs-node')
async function analysis(){
  const df = dfd.read_csv("titanic.csv")
  df.head().print()

  //groupby Sex column
  const sex_df = df.groupby(["Sex"]).col(["Survived"]).mean()
  sex_df.head().print()

  //groupby Pclass column
  const pclass_df = df.groupby(["Pclass"]).col(["Survived"]).mean()
  pclass_df.head().print()
}
analysis()
```

以下表格显示了每个性别的平均生存率：

![图 7.25 - 基于性别的平均生存率](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_25.jpg)

图 7.25 - 基于性别的平均生存率

以下表格显示了每个等级的平均生存率：

![图 7.26 - 基于 Pclass 的平均生存率](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/bd-dtdvn-app-danfo/img/B17076_07_26.jpg)

图 7.26 - 基于 Pclass 的平均生存率

在本节中，我们简要介绍了如何使用`groupby`操作来分析现实生活中的数据。

# 总结

在本章中，我们广泛讨论了在 Danfo.js 中实现的`groupby`操作。我们讨论了对数据进行分组，并提到目前，Danfo.js 仅支持按单列和双列进行分组；计划在未来的版本中使其更加灵活。我们还展示了如何遍历分组数据并访问组键及其关联的分组数据。我们看了如何在不循环的情况下获得与组键相关的分组数据。

我们还看到了`.apply`方法如何为我们提供了创建自定义数据聚合函数的能力，最后，我们演示了如何同时对分组数据的不同列执行不同的聚合函数。

本章使我们具备了对数据进行分组的知识，更重要的是，它向我们介绍了 Danfo.js 的内部工作原理。有了这个，我们可以将`groupby`方法重塑成我们想要的味道，并且有能力为 Danfo.js 做出贡献。

在下一章中，我们将继续介绍更多应用基础知识，包括如何使用 Danfo.js 构建数据分析 Web 应用程序，一个无代码环境。我们还将看到如何将 Danfo.js 方法转换为 React 组件。
