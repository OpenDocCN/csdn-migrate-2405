# Three.js 学习手册（二）

> 原文：[`zh.annas-archive.org/md5/5001B8D716B9182B26C655FCB6BE8F50`](https://zh.annas-archive.org/md5/5001B8D716B9182B26C655FCB6BE8F50)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：学习使用几何图形

在之前的章节中，你学到了很多关于如何使用 Three.js 的知识。你知道如何创建一个基本场景，添加光照，并为你的网格配置材质。在第二章中，*组成 Three.js 场景的基本组件*，我们提到了 Three.js 提供的可用几何图形，但并没有详细讨论，你可以使用这些几何图形来创建你的 3D 对象。在本章和下一章中，我们将带你了解所有 Three.js 提供的几何图形（除了我们在上一章中讨论的`THREE.Line`）。在本章中，我们将看一下以下几何图形：

+   `THREE.CircleGeometry`

+   `THREE.RingGeometry`

+   `THREE.PlaneGeometry`

+   `THREE.ShapeGeometry`

+   `THREE.BoxGeometry`

+   `THREE.SphereGeometry`

+   `THREE.CylinderGeometry`

+   `THREE.TorusGeometry`

+   `THREE.TorusKnotGeometry`

+   `THREE.PolyhedronGeometry`

+   `THREE.IcosahedronGeometry`

+   `THREE.OctahedronGeometry`

+   `THREE.TetraHedronGeometry`

+   `THREE.DodecahedronGeometry`

在下一章中，我们将看一下以下复杂的几何图形：

+   `THREE.ConvexGeometry`

+   `THREE.LatheGeometry`

+   `THREE.ExtrudeGeometry`

+   `THREE.TubeGeometry`

+   `THREE.ParametricGeometry`

+   `THREE.TextGeometry`

让我们来看看 Three.js 提供的所有基本几何图形。

# Three.js 提供的基本几何图形

在 Three.js 中，我们有一些几何图形会产生二维网格，还有更多的几何图形会创建三维网格。在本节中，我们首先看一下 2D 几何图形：`THREE.CircleGeometry`、`THREE.RingGeometry`、`THREE.PlaneGeometry`和`THREE.ShapeGeometry`。之后，我们将探索所有可用的基本 3D 几何图形。

## 二维几何图形

二维对象看起来像平面对象，正如其名称所示，只有两个维度。列表中的第一个二维几何图形是`THREE.PlaneGeometry`。

### `THREE.PlaneGeometry`

`PlaneGeometry`对象可用于创建一个非常简单的二维矩形。有关此几何图形的示例，请参阅本章源代码中的`01-basic-2d-geometries-plane.html`示例。使用`PlaneGeometry`创建的矩形如下截图所示：

![THREE.PlaneGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_01.jpg)

创建这个几何图形非常简单，如下所示：

```js
new THREE.PlaneGeometry(width, height,widthSegments,heightSegments);
```

在`THREE.PlaneGeometry`的示例中，你可以更改这些属性，直接看到它对生成的 3D 对象的影响。这些属性的解释如下表所示：

| 属性 | 必填 | 描述 |
| --- | --- | --- |
| `width` | 是 | 这是矩形的宽度。 |
| `height` | 是 | 这是矩形的高度。 |
| `widthSegments` | 否 | 这是宽度应该分成的段数。默认为`1`。 |
| `heightSegments` | 否 | 这是高度应该分成的段数。默认为`1`。 |

正如你所看到的，这不是一个非常复杂的几何图形。你只需指定大小，就完成了。如果你想创建更多的面（例如，当你想创建一个棋盘格图案时），你可以使用`widthSegments`和`heightSegments`属性将几何图形分成更小的面。

在我们继续下一个几何图形之前，这里有一个关于本示例使用的材质的快速说明，我们在本章的大多数其他示例中也使用这种材质。我们使用以下方法基于几何图形创建网格：

```js
function createMesh(geometry) {

  // assign two materials
  var meshMaterial = new THREE.MeshNormalMaterial();
  meshMaterial.side = THREE.DoubleSide;
  var wireframeMaterial = new THREE.MeshBasicMaterial();
  wireFrameMaterial.wireframe = true;

  // create a multimaterial
  var mesh = THREE.SceneUtils.createMultiMaterialObject(geometry,[meshMaterial,wireframeMaterial]);
  return mesh;
}
```

在这个函数中，我们基于提供的网格创建了一个多材质网格。首先使用的材质是`THREE.MeshNormalMaterial`。正如你在上一章中学到的，`THREE.MeshNormalMaterial`根据其法向量（面的方向）创建了彩色的面。我们还将这种材质设置为双面的（`THREE.DoubleSide`）。如果不这样做，当对象的背面对着摄像机时，我们就看不到它了。除了`THREE.MeshNormalMaterial`，我们还添加了`THREE.MeshBasicMaterial`，并启用了它的线框属性。这样，我们可以很好地看到对象的 3D 形状和为特定几何体创建的面。

### 提示

如果你想在创建后访问几何体的属性，你不能简单地说`plane.width`。要访问几何体的属性，你必须使用对象的`parameters`属性。因此，要获取本节中创建的`plane`对象的`width`属性，你必须使用`plane.parameters.width`。

### THREE.CircleGeometry

你可能已经猜到了`THREE.CircleGeometry`创建了什么。使用这个几何体，你可以创建一个非常简单的二维圆（或部分圆）。让我们先看看这个几何体的例子，`02-basic-2d-geometries-circle.html`。在下面的截图中，你可以找到一个例子，我们在其中使用了一个小于`2 * PI`的`thetaLength`值：

![THREE.CircleGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_02.jpg)

注意，`2 * PI`代表弧度中的一个完整圆。如果你更喜欢使用度而不是弧度，那么在它们之间进行转换非常容易。以下两个函数可以帮助你在弧度和度之间进行转换，如下所示：

```js
function deg2rad(degrees) {
  return degrees * Math.PI / 180;
}

function rad2deg(radians) {
  return radians * 180 / Math.PI;
}
```

在这个例子中，你可以看到并控制使用`THREE.CircleGeometry`创建的网格。当你创建`THREE.CircleGeometry`时，你可以指定一些属性来定义圆的外观，如下所示：

| 属性 | 必需 | 描述 |
| --- | --- | --- |
| `radius` | 否 | 圆的半径定义了它的大小。半径是从圆心到边缘的距离。默认值为`50`。 |
| `segments` | 否 | 此属性定义用于创建圆的面的数量。最小数量为`3`，如果未指定，则默认为`8`。较高的值意味着更平滑的圆形。 |
| `thetaStart` | 否 | 此属性定义从哪里开始绘制圆。这个值可以从`0`到`2 * PI`，默认值为`0`。 |
| `thetaLength` | 否 | 此属性定义圆完成的程度。如果未指定，它默认为`2 * PI`（完整圆）。例如，如果你为这个值指定了`0.5 * PI`，你将得到一个四分之一圆。使用这个属性和`thetaStart`属性一起来定义圆的形状。 |

你可以使用以下代码片段创建一个完整的圆：

```js
new THREE.CircleGeometry(3, 12);
```

如果你想从这个几何体创建半个圆，你可以使用类似于这样的代码：

```js
new THREE.CircleGeometry(3, 12, 0, Math.PI);
```

在继续下一个几何体之前，快速说明一下 Three.js 在创建这些二维形状（`THREE.PlaneGeometry`、`THREE.CircleGeometry`和`THREE.ShapeGeometry`）时使用的方向：Three.js 创建这些对象时是*竖立的*，所以它们位于*x*-*y*平面上。这是非常合乎逻辑的，因为它们是二维形状。然而，通常情况下，特别是对于`THREE.PlaneGeometry`，你可能希望将网格放在地面上（`x`-`z`平面）——一些可以放置其余对象的地面区域。创建一个水平定向的二维对象的最简单方法是将网格围绕其*x*轴向后旋转一四分之一圈（`-PI/2`），如下所示：

```js
mesh.rotation.x =- Math.PI/2;
```

这就是关于`THREE.CircleGeometry`的全部内容。下一个几何体`THREE.RingGeometry`看起来很像`THREE.CircleGeometry`。

### THREE.RingGeometry

使用`THREE.RingGeometry`，您可以创建一个二维对象，不仅与`THREE.CircleGeometry`非常相似，而且还允许您在中心定义一个孔（请参阅`03-basic-3d-geometries-ring.html`）：

![THREE.RingGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_03.jpg)

`THREE.RingGeometry`没有任何必需的属性（请参阅下一个表格以获取默认值），因此要创建此几何体，您只需指定以下内容：

```js
Var ring = new THREE.RingGeometry();
```

您可以通过将以下参数传递到构造函数来进一步自定义环形几何的外观：

| 属性 | 强制 | 描述 |
| --- | --- | --- |
| `innerRadius` | 否 | 圆的内半径定义了中心孔的大小。如果将此属性设置为`0`，则不会显示孔。默认值为`0`。 |
| `outerRadius` | 否 | 圆的外半径定义了其大小。半径是从圆的中心到其边缘的距离。默认值为`50`。 |
| `thetaSegments` | 否 | 这是用于创建圆的对角线段数。较高的值意味着更平滑的环。默认值为`8`。 |
| `phiSegments` | 否 | 这是沿着环的长度所需使用的段数。默认值为`8`。这实际上不影响圆的平滑度，但增加了面的数量。 |
| `thetaStart` | 否 | 这定义了从哪里开始绘制圆的位置。此值可以范围从`0`到`2 * PI`，默认值为`0`。 |
| `thetaLength` | 否 | 这定义了圆完成的程度。当未指定时，默认为`2 * PI`（完整圆）。例如，如果为此值指定`0.5 * PI`，则将获得一个四分之一圆。将此属性与`thetaStart`属性一起使用以定义圆的形状。 |

在下一节中，我们将看一下二维形状的最后一个：`THREE.ShapeGeometry`。

### THREE.ShapeGeometry

`THREE.PlaneGeometry`和`THREE.CircleGeometry`在自定义外观方面的方式有限。如果要创建自定义的二维形状，可以使用`THREE.ShapeGeometry`。使用`THREE.ShapeGeometry`，您可以调用一些函数来创建自己的形状。您可以将此功能与 HTML 画布元素和 SVG 中也可用的`<path>`元素功能进行比较。让我们从一个示例开始，然后我们将向您展示如何使用各种函数来绘制自己的形状。本章的源代码中可以找到`04-basic-2d-geometries-shape.html`示例。以下屏幕截图显示了此示例：

![THREE.ShapeGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_04.jpg)

在此示例中，您可以看到一个自定义创建的二维形状。在描述属性之前，让我们首先看一下用于创建此形状的代码。在创建`THREE.ShapeGeometry`之前，我们首先必须创建`THREE.Shape`。您可以通过查看先前的屏幕截图来追踪这些步骤，从底部右侧开始。以下是我们创建`THREE.Shape`的方法：

```js
function drawShape() {
  // create a basic shape
  var shape = new THREE.Shape();

  // startpoint
  shape.moveTo(10, 10);

  // straight line upwards
  shape.lineTo(10, 40);

  // the top of the figure, curve to the right
  shape.bezierCurveTo(15, 25, 25, 25, 30, 40);

  // spline back down
  shape.splineThru(
    [new THREE.Vector2(32, 30),
      new THREE.Vector2(28, 20),
      new THREE.Vector2(30, 10),
    ])

  // curve at the bottom
  shape.quadraticCurveTo(20, 15, 10, 10);

  // add 'eye' hole one
  var hole1 = new THREE.Path();
  hole1.absellipse(16, 24, 2, 3, 0, Math.PI * 2, true);
  shape.holes.push(hole1);

  // add 'eye hole 2'
  var hole2 = new THREE.Path();
  hole2.absellipse(23, 24, 2, 3, 0, Math.PI * 2, true);
  shape.holes.push(hole2);

  // add 'mouth'
  var hole3 = new THREE.Path();
  hole3.absarc(20, 16, 2, 0, Math.PI, true);
  shape.holes.push(hole3);

  // return the shape
  return shape;
}
```

在此代码片段中，您可以看到我们使用线条、曲线和样条创建了此形状的轮廓。之后，我们使用`THREE.Shape`的`holes`属性在此形状中打了一些孔。不过，在本节中，我们谈论的是`THREE.ShapeGeometry`而不是`THREE.Shape`。要从`THREE.Shape`创建几何体，我们需要将`THREE.Shape`（在我们的情况下从`drawShape()`函数返回）作为参数传递给`THREE.ShapeGeometry`，如下所示：

```js
new THREE.ShapeGeometry(drawShape());
```

此函数的结果是一个可用于创建网格的几何体。当您已经拥有一个形状时，还有一种创建`THREE.ShapeGeometry`的替代方法。您可以调用`shape.makeGeometry(options)`，它将返回`THREE.ShapeGeometry`的一个实例（有关选项的解释，请参见下一个表格）。

让我们首先看一下您可以传递给`THREE.ShapeGeometry`的参数：

| 属性 | 强制 | 描述 |
| --- | --- | --- |
| `shapes` | 是 | 这些是用于创建`THREE.Geometry`的一个或多个`THREE.Shape`对象。您可以传入单个`THREE.Shape`对象或`THREE.Shape`对象的数组。 |

| `options` | 否 | 您还可以传入一些应用于使用`shapes`参数传入的所有形状的`options`。这些选项的解释在这里给出：

+   `curveSegments`：此属性确定从形状创建的曲线有多光滑。默认值为`12`。

+   `material`：这是用于指定形状创建的面的`materialIndex`属性。当您将`THREE.MeshFaceMaterial`与此几何体一起使用时，`materialIndex`属性确定用于传入形状的面的材料。

+   `UVGenerator`：当您在材质中使用纹理时，UV 映射确定纹理的哪一部分用于特定的面。使用`UVGenerator`属性，您可以传入自己的对象，用于为传入的形状创建面的 UV 设置。有关 UV 设置的更多信息，请参阅第十章*加载和使用纹理*。如果没有指定，将使用`THREE.ExtrudeGeometry.WorldUVGenerator`。

|

`THREE.ShapeGeometry`最重要的部分是`THREE.Shape`，您可以使用它来创建形状，因此让我们看一下您可以使用的绘制函数列表来创建`THREE.Shape`（请注意，这些实际上是`THREE.Path`对象的函数，`THREE.Shape`是从中扩展的）。

| 名称 | 描述 |
| --- | --- |
| `moveTo(x,y)` | 将绘图位置移动到指定的*x*和*y*坐标。 |
| `lineTo(x,y)` | 从当前位置(例如，由`moveTo`函数设置)画一条线到提供的*x*和*y*坐标。 |
| `quadraticCurveTo(aCPx, aCPy, x, y)` | 您可以使用两种不同的方式来指定曲线。您可以使用此`quadraticCurveTo`函数，也可以使用`bezierCurveTo`函数(请参阅下一行表)。这两个函数之间的区别在于您如何指定曲线的曲率。以下图解释了这两个选项之间的区别:![THREE.ShapeGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_05.jpg)对于二次曲线，我们需要指定一个额外的点(使用`aCPx`和`aCPy`参数)，曲线仅基于该点和，当然，指定的终点(*x*和*y*参数)。对于三次曲线(由`bezierCurveTo`函数使用)，您需要指定两个额外的点来定义曲线。起点是路径的当前位置。 |
| `bezierCurveTo(aCPx1, aCPy1, aCPx2, aCPy2, x, y)` | 根据提供的参数绘制曲线。有关说明，请参见上一个表条目。曲线是基于定义曲线的两个坐标(`aCPx1`，`aCPy1`，`aCPx2`和`aCPy2`)和结束坐标(*x*和*y*)绘制的。起点是路径的当前位置。 |
| `splineThru(pts)` | 此函数通过提供的坐标集(`pts`)绘制流线。此参数应该是`THREE.Vector2`对象的数组。起点是路径的当前位置。 |
| `arc(aX, aY, aRadius, aStartAngle, aEndAngle, aClockwise)` | 这绘制一个圆(或圆的一部分)。圆从路径的当前位置开始。在这里，`aX`和`aY`被用作从当前位置的偏移量。请注意，`aRadius`设置圆的大小，`aStartAngle`和`aEndAngle`定义了绘制圆的一部分的大小。布尔属性`aClockwise`确定圆是顺时针绘制还是逆时针绘制。 |
| `absArc(aX, aY, aRadius, aStartAngle, aEndAngle, AClockwise)` | 参见`arc`的描述。位置是绝对的，而不是相对于当前位置。 |
| `ellipse(aX, aY, xRadius, yRadius, aStartAngle, aEndAngle, aClockwise)` | 查看`arc`的描述。另外，使用`ellipse`函数，我们可以分别设置*x*半径和*y*半径。 |
| `absEllipse(aX, aY, xRadius, yRadius, aStartAngle, aEndAngle, aClockwise)` | 查看`ellipse`的描述。位置是绝对的，而不是相对于当前位置。 |
| `fromPoints(vectors)` | 如果您将一个`THREE.Vector2`（或`THREE.Vector3`）对象数组传递给此函数，Three.js 将使用从提供的向量到直线创建路径。 |
| `holes` | `holes`属性包含一个`THREE.Shape`对象数组。数组中的每个对象都作为一个孔渲染。这个部分开头我们看到的示例就是一个很好的例子。在那个代码片段中，我们将三个`THREE.Shape`对象添加到了这个数组中。一个是主`THREE.Shape`对象的左眼，一个是右眼，一个是嘴巴。 |

在这个示例中，我们使用新的`THREE.ShapeGeometry(drawShape()))`构造函数从`THREE.Shape`对象创建了`THREE.ShapeGeometry`。`THREE.Shape`对象本身还有一些辅助函数，您可以用来创建几何体。它们如下：

| 名称 | 描述 |
| --- | --- |
| `makeGeometry(options)` | 这从`THREE.Shape`返回`THREE.ShapeGeometry`。有关可用选项的更多信息，请查看我们之前讨论的`THREE.ShapeGeometry`的属性。 |
| `createPointsGeometry(divisions)` | 这将形状转换为一组点。`divisions`属性定义了返回多少个点。如果这个值更高，将返回更多的点，生成的线条将更平滑。分割应用于路径的每个部分。 |
| `createSpacedPointsGeometry(divisions)` | 即使这将形状转换为一组点，但这次将分割应用于整个路径。 |

当您创建一组点时，使用`createPointsGeometry`或`createSpacedPointsGeometry`；您可以使用创建的点来绘制一条线，如下所示：

```js
new THREE.Line( shape.createPointsGeometry(10), new THREE.LineBasicMaterial( { color: 0xff3333, linewidth: 2 } ) );
```

当您在示例中点击**asPoints**或**asSpacedPoints**按钮时，您将看到类似于这样的东西：

![THREE.ShapeGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_06.jpg)

这就是关于二维形状的全部内容。下一部分将展示和解释基本的三维形状。

## 三维几何体

在这个关于基本三维几何体的部分，我们将从我们已经看过几次的几何体`THREE.BoxGeometry`开始。

### THREE.BoxGeometry

`THREE.BoxGeometry`是一个非常简单的 3D 几何体，允许您通过指定其宽度、高度和深度来创建一个立方体。我们添加了一个示例`05-basic-3d-geometries-cube.html`，您可以在其中尝试这些属性。以下屏幕截图显示了这个几何体：

![THREE.BoxGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_07.jpg)

正如您在此示例中所看到的，通过更改`THREE.BoxGeometry`的`width`，`height`和`depth`属性，您可以控制生成网格的大小。当您创建一个新的立方体时，这三个属性也是必需的，如下所示：

```js
new THREE.BoxGeometry(10,10,10);
```

在示例中，您还可以看到一些您可以在立方体上定义的其他属性。以下表格解释了所有这些属性：

| 属性 | 必需 | 描述 |
| --- | --- | --- |
| `宽度` | 是 | 这是立方体的宽度。这是立方体顶点沿*x*轴的长度。 |
| `height` | 是 | 这是立方体的高度。这是立方体顶点沿*y*轴的长度。 |
| `depth` | 是 | 这是立方体的深度。这是立方体顶点沿*z*轴的长度。 |
| `widthSegments` | 否 | 这是我们沿着立方体*x*轴将一个面分成的段数。默认值为`1`。 |
| `heightSegments` | 否 | 这是我们沿着立方体*y*轴将一个面分成的段数。默认值为`1`。 |
| `depthSegments` | 否 | 这是我们沿着立方体的*z*轴将一个面分成的段数。默认值为`1`。 |

通过增加各种段属性，您可以将立方体的六个主要面分成更小的面。如果您想要在立方体的部分上设置特定的材质属性，使用`THREE.MeshFaceMaterial`是很有用的。`THREE.BoxGeometry`是一个非常简单的几何体。另一个简单的是`THREE.SphereGeometry`。

### THREE.SphereGeometry

使用`SphereGeometry`，您可以创建一个三维球体。让我们直接进入示例`06-basic-3d-geometries-sphere.html`：

![THREE.SphereGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_08.jpg)

在上一张截图中，我们向您展示了基于`THREE.SphereGeometry`创建的半开放球体。这种几何体非常灵活，可以用来创建各种与球体相关的几何体。然而，一个基本的`THREE.SphereGeometry`可以像这样轻松创建：`new THREE.SphereGeometry()`。以下属性可用于调整结果网格的外观：

| 属性 | 强制 | 描述 |
| --- | --- | --- |
| --- | --- | --- |
| `半径` | 否 | 用于设置球体的半径。这定义了结果网格的大小。默认值为`50`。 |
| `widthSegments` | 否 | 这是垂直使用的段数。更多的段意味着更光滑的表面。默认值为`8`，最小值为`3`。 |
| `heightSegments` | 否 | 这是水平使用的段数。段数越多，球体表面越光滑。默认值为`6`，最小值为`2`。 |
| `phiStart` | 否 | 这确定了沿着其*x*轴开始绘制球体的位置。这可以从`0`到`2 * PI`范围内，并且默认值为`0`。 |
| `phiLength` | 否 | 这确定了球体从`phiStart`处绘制的距离。`2 * PI`将绘制一个完整的球体，`0.5 * PI`将绘制一个开放的四分之一球体。默认值为`2 * PI`。 |
| `thetaStart` | 否 | 这确定了沿着其*x*轴开始绘制球体的位置。这可以从`0`到`PI`范围内，并且默认值为`0`。 |
| `thetaLength` | 否 | 这确定了从`phiStart`处绘制球体的距离。`PI`值是一个完整的球体，而`0.5 * PI`将只绘制球体的顶半部分。默认值为`PI`。 |

`radius`，`widthSegments`和`heightSegments`属性应该很清楚。我们已经在其他示例中看到了这些类型的属性。`phiStart`，`phiLength`，`thetaStart`和`thetaLength`属性在没有示例的情况下有点难以理解。不过幸运的是，您可以从`06-basic-3d-geometries-sphere.html`示例的菜单中尝试这些属性，并创建出有趣的几何体，比如这些：

![THREE.SphereGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_09.jpg)

列表中的下一个是`THREE.CylinderGeometry`。

### THREE.CylinderGeometry

使用这个几何体，我们可以创建圆柱体和类似圆柱体的对象。对于所有其他几何体，我们也有一个示例（`07-basic-3d-geometries-cylinder.html`），让您可以尝试这个几何体的属性，其截图如下：

![THREE.CylinderGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_10.jpg)

当您创建`THREE.CylinderGeometry`时，没有任何强制参数。因此，您可以通过调用`new THREE.CylinderGeometry()`来创建一个圆柱体。您可以传递多个属性，就像在示例中看到的那样，以改变这个圆柱体的外观。这些属性在下表中解释：

| 属性 | 强制 | 描述 |
| --- | --- | --- |
| --- | --- | --- |
| `radiusTop` | 否 | 这设置了圆柱体顶部的大小。默认值为`20`。 |
| `radiusBottom` | 否 | 这设置了圆柱体底部的大小。默认值为`20`。 |
| `height` | 否 | 此属性设置圆柱体的高度。默认高度为`100`。 |
| `radialSegments` | 否 | 这确定了圆柱体半径上的段数。默认值为`8`。更多的段数意味着更平滑的圆柱体。 |
| `heightSegments` | 否 | 这确定了圆柱体高度上的段数。默认值为`1`。更多的段数意味着更多的面。 |
| `openEnded` | 否 | 这确定网格在顶部和底部是否封闭。默认值为`false`。 |

这些都是您可以用来配置圆柱体的非常基本的属性。然而，一个有趣的方面是当您为顶部（或底部）使用负半径时。如果这样做，您可以使用这个几何体来创建类似沙漏的形状，如下面的截图所示。需要注意的一点是，正如您从颜色中看到的那样，这种情况下的上半部分是里面翻转的。如果您使用的材质没有配置`THREE.DoubleSide`，您将看不到上半部分。

![THREE.CylinderGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_11.jpg)

下一个几何体是`THREE.TorusGeometry`，你可以用它来创建类似甜甜圈的形状。

### THREE.TorusGeometry

圆环是一个简单的形状，看起来像一个甜甜圈。以下截图显示了`THREE.TorusGeometry`的示例：

![THREE.TorusGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_12.jpg)

就像大多数简单的几何体一样，在创建`THREE.TorusGeometry`时没有任何强制性参数。下表列出了创建此几何体时可以指定的参数：

| 属性 | 强制性 | 描述 |
| --- | --- | --- |
| `radius` | 否 | 这设置了完整圆环的大小。默认值为`100`。 |
| `tube` | 否 | 这设置了管道（实际甜甜圈）的半径。此属性的默认值为`40`。 |
| `radialSegments` | 否 | 这确定了沿着圆环长度使用的段数。默认值为`8`。在演示中查看更改此值的效果。 |
| `tubularSegments` | 否 | 这确定了沿着圆环宽度使用的段数。默认值为`6`。在演示中查看更改此值的效果。 |
| `arc` | 否 | 通过这个属性，您可以控制圆环是否绘制完整圆。这个值的默认值是`2 * PI`（一个完整的圆）。 |

其中大多数都是非常基本的属性，`arc`属性是一个非常有趣的属性。通过这个属性，您可以定义甜甜圈是完整的圆还是部分圆。通过调整这个属性，您可以创建非常有趣的网格，比如下面这个弧度设置为`0.5 * PI`的网格：

![THREE.TorusGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_13.jpg)

`THREE.TorusGeometry`是一个非常直接的几何体。在下一节中，我们将看一个几何体，它几乎与它的名字相同，但要复杂得多：`THREE.TorusKnotGeometry`。

### THREE.TorusKnotGeometry

使用`THREE.TorusKnotGeometry`，您可以创建一个圆环结。圆环结是一种特殊的结，看起来像一个围绕自身缠绕了几次的管子。最好的解释方法是看`09-basic-3d-geometries-torus-knot.html`示例。下面的截图显示了这个几何体：

![THREE.TorusKnotGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_14.jpg)

如果您打开这个示例并尝试调整`p`和`q`属性，您可以创建各种美丽的几何体。`p`属性定义了结的轴向绕组次数，`q`定义了结在其内部绕组的程度。如果这听起来有点模糊，不用担心。您不需要理解这些属性就可以创建美丽的结，比如下面截图中显示的一个（对于那些对细节感兴趣的人，维基百科在这个主题上有一篇很好的文章[`en.wikipedia.org/wiki/Torus_knot`](http://en.wikipedia.org/wiki/Torus_knot)）：

![THREE.TorusKnotGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_15.jpg)

通过这个几何体的示例，你可以尝试不同的`p`和`q`的组合，看看它们对这个几何体的影响：

| 属性 | 强制性 | 描述 |
| --- | --- | --- |
| `radius` | 否 | 这设置了整个环面的大小。默认值为`100`。 |
| `tube` | 否 | 这设置了管道（实际甜甜圈）的半径。这个属性的默认值为`40`。 |
| `radialSegments` | 否 | 这确定了沿着环面结的长度使用的段数。默认值为`64`。在演示中查看更改此值的效果。 |
| `tubularSegments` | 否 | 这确定了沿着环面结的宽度使用的段数。默认值为`8`。在演示中查看更改此值的效果。 |
| `p` | 否 | 这定义了结的形状，默认值为`2`。 |
| `q` | 否 | 这定义了结的形状，默认值为`3`。 |
| `heightScale` | 否 | 使用这个属性，你可以拉伸环面结。默认值为`1`。 |

列表中的下一个几何体是基本几何体中的最后一个：`THREE.PolyhedronGeometry`。

### THREE.PolyhedronGeometry

使用这个几何体，你可以轻松创建多面体。多面体是一个只有平面面和直边的几何体。不过，大多数情况下，你不会直接使用这个几何体。Three.js 提供了许多特定的多面体，你可以直接使用，而不需要指定`THREE.PolyhedronGeometry`的顶点和面。我们将在本节的后面讨论这些多面体。如果你确实想直接使用`THREE.PolyhedronGeometry`，你必须指定顶点和面（就像我们在第三章中为立方体所做的那样，*在 Three.js 中使用不同的光源*）。例如，我们可以像这样创建一个简单的四面体（也可以参见本章中的`THREE.TetrahedronGeometry`）：

```js
var vertices = [
  1,  1,  1, 
  -1, -1,  1, 
  -1,  1, -1, 
  1, -1, -1
];

var indices = [
  2, 1, 0, 
  0, 3, 2, 
  1, 3, 0, 
  2, 3, 1
];

polyhedron = createMesh(new THREE.PolyhedronGeometry(vertices, indices, controls.radius, controls.detail));
```

要构建`THREE.PolyhedronGeometry`，我们传入`vertices`、`indices`、`radius`和`detail`属性。生成的`THREE.PolyhedronGeometry`对象显示在`10-basic-3d-geometries-polyhedron.html`示例中（在右上角的菜单中选择**类型**为：**自定义**）：

![THREE.PolyhedronGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_16.jpg)

当你创建一个多面体时，你可以传入以下四个属性：

| 属性 | 强制性 | 描述 |
| --- | --- | --- |
| `vertices` | 是 | 这些是组成多面体的点。 |
| `indices` | 是 | 这些是需要从顶点创建的面。 |
| `radius` | 否 | 这是多面体的大小。默认为`1`。 |
| `detail` | 否 | 使用这个属性，你可以给多面体添加额外的细节。如果将其设置为`1`，多面体中的每个三角形将分成四个更小的三角形。如果将其设置为`2`，这四个更小的三角形将再次分成四个更小的三角形，依此类推。 |

在本节的开头，我们提到 Three.js 自带了一些多面体。在接下来的小节中，我们将快速展示这些多面体。

所有这些多面体类型都可以通过查看`09-basic-3d-geometries-polyhedron.html`示例来查看。

#### THREE.IcosahedronGeometry

`THREE.IcosahedronGeometry` 创建了一个由 12 个顶点创建的 20 个相同三角形面的多面体。创建这个多面体时，你只需要指定`radius`和`detail`级别。这个截图显示了使用`THREE.IcosahedronGeometry`创建的多面体：

![THREE.IcosahedronGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_17.jpg)

#### THREE.TetrahedronGeometry

四面体是最简单的多面体之一。这个多面体只包含了由四个顶点创建的四个三角形面。你可以像创建 Three.js 提供的其他多面体一样创建`THREE.TetrahedronGeometry`，通过指定`radius`和`detail`级别。下面是一个使用`THREE.TetrahedronGeometry`创建的四面体的截图：

![THREE.TetrahedronGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_18.jpg)

#### THREE.Octahedron Geometry

Three.js 还提供了一个八面体的实现。顾名思义，这个多面体有 8 个面。这些面是由 6 个顶点创建的。以下截图显示了这个几何图形：

![THREE.Octahedron Geometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_19.jpg)

#### THREE.DodecahedronGeometry

Three.js 提供的最后一个多面体几何图形是`THREE.DodecahedronGeometry`。这个多面体有 12 个面。以下截图显示了这个几何图形：

![THREE.DodecahedronGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_05_20.jpg)

这是关于 Three.js 提供的基本二维和三维几何图形的章节的结束。

# 总结

在本章中，我们讨论了 Three.js 提供的所有标准几何图形。正如你所看到的，有很多几何图形可以直接使用。为了更好地学习如何使用这些几何图形，尝试使用这些几何图形。使用本章的示例来了解你可以用来自定义 Three.js 提供的标准几何图形的属性。当你开始使用几何图形时，最好选择一个基本的材质；不要直接选择复杂的材质，而是从`THREE.MeshBasicMaterial`开始，将线框设置为`true`，或者使用`THREE.MeshNormalMaterial`。这样，你将更好地了解几何图形的真实形状。对于二维形状，重要的是要记住它们是放置在*x*-*y*平面上的。如果你想要水平放置一个二维形状，你需要围绕*x*轴旋转网格为`-0.5 * PI`。最后，要注意，如果你旋转一个二维形状，或者一个*开放*的三维形状（例如圆柱体或管道），记得将材质设置为`THREE.DoubleSide`。如果不这样做，你的几何图形的内部或背面将不会显示出来。

在本章中，我们专注于简单直接的网格。Three.js 还提供了创建复杂几何图形的方法。在下一章中，你将学习如何创建这些复杂几何图形。


# 第六章：高级几何形状和二进制操作

在上一章中，我们向你展示了 Three.js 提供的所有基本几何形状。除了这些基本几何形状，Three.js 还提供了一组更高级和专业化的对象。在本章中，我们将向你展示这些高级几何形状，并涵盖以下主题：

+   如何使用高级几何形状，比如`THREE.ConvexGeometry`，`THREE.LatheGeometry`和`THREE.TubeGeometry`。

+   如何使用`THREE.ExtrudeGeometry`从 2D 形状创建 3D 形状。我们将根据使用 Three.js 提供的功能绘制的 2D 形状来做这个，我们将展示一个例子，其中我们基于外部加载的 SVG 图像创建 3D 形状。

+   如果你想自己创建自定义形状，你可以很容易地修改我们在前几章中讨论的形状。然而，Three.js 还提供了一个`THREE.ParamtericGeometry`对象。使用这个对象，你可以基于一组方程创建几何形状。

+   最后，我们将看看如何使用`THREE.TextGeometry`创建 3D 文本效果。

+   此外，我们还将向你展示如何使用 Three.js 扩展 ThreeBSP 提供的二进制操作从现有的几何形状创建新的几何形状。

我们将从列表中的第一个开始，`THREE.ConvexGeometry`。

# THREE.ConvexGeometry

使用`THREE.ConvexGeometry`，我们可以围绕一组点创建凸包。凸包是包围所有这些点的最小形状。最容易理解的方法是通过一个例子来看。如果你打开`01-advanced-3d-geometries-convex.html`的例子，你会看到一个随机点集的凸包。以下截图显示了这个几何形状：

![THREE.ConvexGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_06_01.jpg)

在这个例子中，我们生成一组随机点，并基于这些点创建`THREE.ConvexGeometry`。在例子中，你可以点击**redraw**，这将生成 20 个新点并绘制凸包。我们还将每个点添加为一个小的`THREE.SphereGeometry`对象，以清楚地展示凸包的工作原理。`THREE.ConvexGeometry`没有包含在标准的 Three.js 发行版中，所以你必须包含一个额外的 JavaScript 文件来使用这个几何形状。在你的 HTML 页面顶部，添加以下内容：

```js
<script src="../libs/ConvexGeometry.js"></script>
```

以下代码片段显示了这些点是如何创建并添加到场景中的：

```js
function generatePoints() {
  // add 10 random spheres
  var points = [];
  for (var i = 0; i < 20; i++) {
    var randomX = -15 + Math.round(Math.random() * 30);
    var randomY = -15 + Math.round(Math.random() * 30);
    var randomZ = -15 + Math.round(Math.random() * 30);
    points.push(new THREE.Vector3(randomX, randomY, randomZ));
  }

  var group = new THREE.Object3D();
  var material = new THREE.MeshBasicMaterial({color: 0xff0000, transparent: false});
  points.forEach(function (point) {
    var geom = new THREE.SphereGeometry(0.2);
    var mesh = new THREE.Mesh(geom, material);
    mesh.position.clone(point);
    group.add(mesh);
  });

  // add the points as a group to the scene
  scene.add(group);
}
```

正如你在这段代码片段中看到的，我们创建了 20 个随机点（`THREE.Vector3`），并将它们推入一个数组中。接下来，我们遍历这个数组，并创建`THREE.SphereGeometry`，其位置设置为这些点之一（`position.clone(point)`）。所有点都被添加到一个组中（更多内容请参阅第七章），所以我们可以通过旋转组来轻松旋转它们。

一旦你有了这组点，创建`THREE.ConvexGeometry`就非常容易，如下面的代码片段所示：

```js
// use the same points to create a convexgeometry
var convexGeometry = new THREE.ConvexGeometry(points);
convexMesh = createMesh(convexGeometry);
scene.add(convexMesh);
```

包含顶点（`THREE.Vector3`类型）的数组是`THREE.ConvexGeometry`的唯一参数。关于`createMesh()`函数（这是我们在第五章中自己创建的函数）我们在这里调用。在上一章中，我们使用这种方法使用`THREE.MeshNormalMaterial`创建网格。对于这个例子，我们将其更改为半透明的绿色`THREE.MeshBasicMaterial`，以更好地显示我们创建的凸包和构成这个几何形状的单个点。

下一个复杂的几何形状是`THREE.LatheGeometry`，它可以用来创建类似花瓶的形状。

# THREE.LatheGeometry

`THREE.LatheGeometry`允许您从平滑曲线创建形状。这条曲线由许多点（也称为节点）定义，通常称为样条。这个样条围绕对象的中心*z*轴旋转，产生类似花瓶和钟形的形状。再次，理解`THREE.LatheGeometry`的最简单方法是看一个例子。这个几何图形显示在`02-advanced-3d-geometries-lathe.html`中。以下来自示例的截图显示了这个几何图形：

![THREE.LatheGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_06_02.jpg)

在前面的截图中，您可以看到样条作为一组小红色球体。这些球体的位置与其他参数一起传递给`THREE.LatheGeometry`。在这个例子中，我们将这个样条旋转了半圈，基于这个样条，我们提取了您可以看到的形状。在我们查看所有参数之前，让我们看一下用于创建样条的代码以及`THREE.LatheGeometry`如何使用这个样条：

```js
function generatePoints(segments, phiStart, phiLength) {
  // add 10 random spheres
  var points = [];
  var height = 5;
  var count = 30;
  for (var i = 0; i < count; i++) {
    points.push(new THREE.Vector3((Math.sin(i * 0.2) + Math.cos(i * 0.3)) * height + 12, 0, ( i - count ) + count / 2));
  }

  ...

  // use the same points to create a LatheGeometry
  var latheGeometry = new THREE.LatheGeometry (points, segments, phiStart, phiLength);
  latheMesh = createMesh(latheGeometry);
  scene.add(latheMesh);
}
```

在这段 JavaScript 中，您可以看到我们生成了 30 个点，它们的*x*坐标是基于正弦和余弦函数的组合，而*z*坐标是基于`i`和`count`变量的。这创建了在前面截图中以红点可视化的样条。

基于这些要点，我们可以创建`THREE.LatheGeometry`。除了顶点数组之外，`THREE.LatheGeometry`还需要一些其他参数。以下表格列出了所有的参数：

| 属性 | 强制 | 描述 |
| --- | --- | --- |
| `points` | 是 | 这些是用于生成钟形/花瓶形状的样条的点。 |
| `segments` | 否 | 这是在创建形状时使用的段数。这个数字越高，结果形状就越*圆润*。这个默认值是`12`。 |
| `phiStart` | 否 | 这确定在生成形状时在圆上从哪里开始。这可以从`0`到`2*PI`。默认值是`0`。 |
| `phiLength` | 否 | 这定义了形状生成的完整程度。例如，一个四分之一的形状将是`0.5*PI`。默认值是完整的`360`度或`2*PI`。 |

在下一节中，我们将看一种通过从 2D 形状中提取 3D 几何图形的替代方法。

## 通过挤出创建几何图形

Three.js 提供了几种方法，可以将 2D 形状挤出为 3D 形状。通过挤出，我们指的是沿着它的*z*轴拉伸 2D 形状以将其转换为 3D。例如，如果我们挤出`THREE.CircleGeometry`，我们得到一个看起来像圆柱体的形状，如果我们挤出`THREE.PlaneGeometry`，我们得到一个类似立方体的形状。

挤出形状的最通用方法是使用`THREE.ExtrudeGeometry`对象。

### THREE.ExtrudeGeometry

使用`THREE.ExtrudeGeometry`，您可以从 2D 形状创建 3D 对象。在我们深入了解这个几何图形的细节之前，让我们先看一个例子：`03-extrude-geometry.html`。以下来自示例的截图显示了这个几何图形：

![THREE.ExtrudeGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_06_03.jpg)

在这个例子中，我们取出了在上一章中创建的 2D 形状，并使用`THREE.ExtrudeGeometry`将其转换为 3D。正如您在这个截图中所看到的，形状沿着*z*轴被挤出，从而得到一个 3D 形状。创建`THREE.ExtrudeGeometry`的代码非常简单：

```js
var options = {
  amount: 10,
  bevelThickness: 2,
  bevelSize: 1,
  bevelSegments: 3,
  bevelEnabled: true,
  curveSegments: 12,
  steps: 1
};

shape = createMesh(new THREE.ExtrudeGeometry(drawShape(), options));
```

在这段代码中，我们使用`drawShape()`函数创建了形状，就像在上一章中所做的那样。这个形状与一个`options`对象一起传递给`THREE.ExtrudeGeometry`构造函数。使用`options`对象，您可以精确地定义形状应该如何被挤出。以下表格解释了您可以传递给`THREE.ExtrudeGeometry`的选项。

| 属性 | 强制 | 描述 |
| --- | --- | --- |
| `shapes` | 是 | 需要一个或多个形状（`THREE.Shape`对象）来从中挤出几何图形。请参阅前一章关于如何创建这样的形状。 |
| `amount` | 否 | 这确定形状应该被挤出的距离（深度）。默认值为`100`。 |
| `bevelThickness` | 否 | 这确定倒角的深度。倒角是前后面和挤出之间的圆角。该值定义了倒角进入形状的深度。默认值为`6`。 |
| `bevelSize` | 否 | 这确定倒角的高度。这加到形状的正常高度上。默认值为`bevelThickness - 2`。 |
| `bevelSegments` | 否 | 这定义了用于倒角的段数。使用的段数越多，倒角看起来就越平滑。默认值为`3`。 |
| `bevelEnabled` | 否 | 如果设置为`true`，则添加倒角。默认值为`true`。 |
| `curveSegments` | 否 | 这确定在挤出形状的曲线时将使用多少段。使用的段数越多，曲线看起来就越平滑。默认值为`12`。 |
| `steps` | 否 | 这定义了沿着深度将挤出分成多少段。默认值为`1`。较高的值将导致更多的单独面。 |
| `extrudePath` | 否 | 这是沿着形状应该被挤出的路径（`THREE.CurvePath`）。如果未指定，则形状沿着 *z* 轴被挤出。 |
| `material` | 否 | 这是用于正面和背面的材质的索引。如果要为正面和背面使用不同的材料，可以使用`THREE.SceneUtils.createMultiMaterialObject`函数创建网格。 |
| `extrudeMaterial` | 否 | 这是用于倒角和挤出的材料的索引。如果要为正面和背面使用不同的材料，可以使用`THREE.SceneUtils.createMultiMaterialObject`函数创建网格。 |
| `uvGenerator` | 否 | 当您在材质中使用纹理时，UV 映射确定了纹理的哪一部分用于特定的面。使用`uvGenerator`属性，您可以传入自己的对象，为传入的形状创建 UV 设置。有关 UV 设置的更多信息，请参阅第十章*加载和使用纹理*。如果未指定，将使用`THREE.ExtrudeGeometry.WorldUVGenerator`。 |
| `frames` | 否 | 弗雷内框架用于计算样条的切线、法线和副法线。这在沿着`extrudePath`挤出时使用。您不需要指定这个，因为 Three.js 提供了自己的实现，`THREE.TubeGeometry.FrenetFrames`，这也是默认值。有关弗雷内框架的更多信息，请参阅[`en.wikipedia.org/wiki/Differential_geometry_of_curves#Frenet_frame`](http://en.wikipedia.org/wiki/Differential_geometry_of_curves#Frenet_frame)。 |

您可以使用`03-extrude-geometry.html`示例中的菜单来尝试这些选项。

在这个例子中，我们沿着 *z* 轴挤出了形状。正如您在选项中所看到的，您还可以使用`extrudePath`选项沿着路径挤出形状。在下面的几何图形`THREE.TubeGeometry`中，我们将这样做。

### THREE.TubeGeometry

`THREE.TubeGeometry`创建沿着 3D 样条线挤出的管道。您可以使用一些顶点指定路径，`THREE.TubeGeometry`将创建管道。您可以在本章的源代码中找到一个可以尝试的示例（`04-extrude-tube.html`）。以下屏幕截图显示了这个示例：

![THREE.TubeGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_06_04.jpg)

正如您在这个例子中所看到的，我们生成了一些随机点，并使用这些点来绘制管道。通过右上角的控件，我们可以定义管道的外观，或者通过单击**newPoints**按钮生成新的管道。创建管道所需的代码非常简单，如下所示：

```js
var points = [];
for (var i = 0 ; i < controls.numberOfPoints ; i++) {
  var randomX = -20 + Math.round(Math.random() * 50);
  var randomY = -15 + Math.round(Math.random() * 40);
  var randomZ = -20 + Math.round(Math.random() * 40);

  points.push(new THREE.Vector3(randomX, randomY, randomZ));
}

var tubeGeometry = new THREE.TubeGeometry(new THREE.SplineCurve3(points), segments, radius, radiusSegments, closed);

var tubeMesh = createMesh(tubeGeometry);
scene.add(tubeMesh);
```

我们首先需要获取一组`THREE.Vector3`类型的顶点，就像我们为`THREE.ConvexGeometry`和`THREE.LatheGeometry`所做的那样。然而，在我们可以使用这些点来创建管道之前，我们首先需要将这些点转换为`THREE.SplineCurve3`。换句话说，我们需要通过我们定义的点定义一个平滑的曲线。我们可以通过将顶点数组简单地传递给`THREE.SplineCurve3`的构造函数来实现这一点。有了这个样条和其他参数（我们稍后会解释），我们就可以创建管道并将其添加到场景中。

`THREE.TubeGeometry`除了`THREE.SplineCurve3`之外还需要一些其他参数。下表列出了`THREE.TubeGeometry`的所有参数：

| 属性 | 强制性 | 描述 |
| --- | --- | --- |
| `path` | 是 | 这是描述管道应该遵循的路径的`THREE.SplineCurve3`。 |
| `segments` | 否 | 这些是用于构建管道的段。默认值为`64`。路径越长，您应该指定的段数就越多。 |
| `radius` | 否 | 这是管道的半径。默认值为`1`。 |
| `radiusSegments` | 否 | 这是沿着管道长度使用的段数。默认值为`8`。使用的越多，管道看起来就越*圆*。 |
| `closed` | 否 | 如果设置为`true`，管道的起点和终点将连接在一起。默认值为`false`。 |

我们将在本章中展示的最后一个挤出示例并不是真正不同的几何形状。在下一节中，我们将向您展示如何使用`THREE.ExtrudeGeometry`从现有的 SVG 路径创建挤出。

### 从 SVG 挤出

当我们讨论`THREE.ShapeGeometry`时，我们提到 SVG 基本上遵循绘制形状的相同方法。SVG 与 Three.js 处理形状的方式非常接近。在本节中，我们将看看如何使用来自[`github.com/asutherland/d3-threeD`](https://github.com/asutherland/d3-threeD)的一个小库，将 SVG 路径转换为 Three.js 形状。

对于`05-extrude-svg.html`示例，我使用了蝙蝠侠标志的 SVG 图形，并使用`ExtrudeGeometry`将其转换为 3D，如下面的屏幕截图所示：

![从 SVG 挤出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_06_05.jpg)

首先，让我们看看原始的 SVG 代码是什么样的（当您查看此示例的源代码时，也可以自行查看）：

```js
<svg version="1.0"   x="0px" y="0px" width="1152px" height="1152px" xml:space="preserve">
  <g>
  <path  id="batman-path" style="fill:rgb(0,0,0);" d="M 261.135 114.535 C 254.906 116.662 247.491 118.825 244.659 119.344 C 229.433 122.131 177.907 142.565 151.973 156.101 C 111.417 177.269 78.9808 203.399 49.2992 238.815 C 41.0479 248.66 26.5057 277.248 21.0148 294.418 C 14.873 313.624 15.3588 357.341 21.9304 376.806 C 29.244 398.469 39.6107 416.935 52.0865 430.524 C 58.2431 437.23 63.3085 443.321 63.3431 444.06 ... 261.135 114.535 "/>
  </g>
</svg>
```

除非你是 SVG 大师，否则这对你来说可能毫无意义。但基本上，你在这里看到的是一组绘图指令。例如，`C 277.987 119.348 279.673 116.786 279.673 115.867`告诉浏览器绘制三次贝塞尔曲线，而`L 489.242 111.787`告诉我们应该画一条线到特定位置。幸运的是，我们不必自己编写代码来解释这些。使用 d3-threeD 库，我们可以自动转换这些。这个库最初是为了与优秀的**D3.js**库一起使用而创建的，但通过一些小的调整，我们也可以单独使用这个特定的功能。

### 提示

**SVG**代表**可缩放矢量图形**。这是一种基于 XML 的标准，可用于创建 Web 的基于矢量的 2D 图像。这是一种开放标准，受到所有现代浏览器的支持。然而，直接使用 SVG 并从 JavaScript 进行操作并不是非常直接的。幸运的是，有几个开源的 JavaScript 库可以使处理 SVG 变得更加容易。**Paper.js**、**Snap.js**、**D3.js**和**Raphael.js**是其中一些最好的。

以下代码片段显示了我们如何加载之前看到的 SVG，将其转换为`THREE.ExtrudeGeometry`，并显示在屏幕上：

```js
function drawShape() {
  var svgString = document.querySelector("#batman-path").getAttribute("d");
  var shape = transformSVGPathExposed(svgString);
  return shape;
}

var options = {
  amount: 10,
  bevelThickness: 2,
  bevelSize: 1,
  bevelSegments: 3,
  bevelEnabled: true,
  curveSegments: 12,
  steps: 1
};

shape = createMesh(new THREE.ExtrudeGeometry(drawShape(), options));
```

在此代码片段中，您将看到对`transformSVGPathExposed`函数的调用。此函数由 d3-threeD 库提供，并将 SVG 字符串作为参数。我们直接从 SVG 元素获取此 SVG 字符串，方法是使用以下表达式：`document.querySelector("#batman-path").getAttribute("d")`。在 SVG 中，`d`属性包含用于绘制形状的路径语句。添加一个漂亮的闪亮材质和聚光灯，您就重新创建了此示例。

本节我们将讨论的最后一个几何图形是`THREE.ParametricGeometry`。使用此几何图形，您可以指定一些用于以编程方式创建几何图形的函数。

### THREE.ParametricGeometry

使用`THREE.ParametricGeometry`，您可以基于方程创建几何图形。在深入研究我们自己的示例之前，一个好的开始是查看 Three.js 已经提供的示例。下载 Three.js 分发时，您会得到`examples/js/ParametricGeometries.js`文件。在此文件中，您可以找到几个示例方程，您可以与`THREE.ParametricGeometry`一起使用。最基本的示例是创建平面的函数：

```js
function plane(u, v) {	
  var x = u * width;
  var y = 0;
  var z = v * depth;
  return new THREE.Vector3(x, y, z);
}
```

此函数由`THREE.ParametricGeometry`调用。`u`和`v`值将从`0`到`1`范围，并且将针对从`0`到`1`的所有值调用大量次数。在此示例中，`u`值用于确定向量的*x*坐标，而`v`值用于确定*z*坐标。运行时，您将获得宽度为`width`和深度为`depth`的基本平面。

在我们的示例中，我们做了类似的事情。但是，我们不是创建一个平面，而是创建了一种波浪般的图案，就像您在`06-parametric-geometries.html`示例中看到的那样。以下屏幕截图显示了此示例：

![THREE.ParametricGeometry](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_06_06.jpg)

要创建此形状，我们将以下函数传递给`THREE.ParametricGeometry`：

```js
radialWave = function (u, v) {
  var r = 50;

  var x = Math.sin(u) * r;
  var z = Math.sin(v / 2) * 2 * r;
  var y = (Math.sin(u * 4 * Math.PI) + Math.cos(v * 2 * Math.PI)) * 2.8;

  return new THREE.Vector3(x, y, z);
}

var mesh = createMesh(new THREE.ParametricGeometry(radialWave, 120, 120, false));
```

正如您在此示例中所看到的，只需几行代码，我们就可以创建非常有趣的几何图形。在此示例中，您还可以看到我们可以传递给`THREE.ParametricGeometry`的参数。这些参数在下表中有解释：

| 属性 | 强制 | 描述 |
| --- | --- | --- |
| `function` | 是 | 这是根据提供的`u`和`v`值定义每个顶点位置的函数 |
| `slices` | 是 | 这定义了应将`u`值分成的部分数 |
| `stacks` | 是 | 这定义了应将`v`值分成的部分数 |

在转到本章的最后一部分之前，我想最后说明一下如何使用`slices`和`stacks`属性。我们提到`u`和`v`属性被传递给提供的`function`参数，并且这两个属性的值范围从`0`到`1`。使用`slices`和`stacks`属性，我们可以定义传入函数的调用频率。例如，如果我们将`slices`设置为`5`，`stacks`设置为`4`，则函数将使用以下值进行调用：

```js
u:0/5, v:0/4
u:1/5, v:0/4
u:2/5, v:0/4
u:3/5, v:0/4
u:4/5, v:0/4
u:5/5, v:0/4
u:0/5, v:1/4
u:1/5, v:1/4
...
u:5/5, v:3/4
u:5/5, v:4/4
```

因此，此值越高，您就可以指定更多的顶点，并且创建的几何图形将更加平滑。您可以使用`06-parametric-geometries.html`示例右上角的菜单来查看此效果。

要查看更多示例，您可以查看 Three.js 分发中的`examples/js/ParametricGeometries.js`文件。该文件包含创建以下几何图形的函数：

+   克莱因瓶

+   平面

+   平坦的莫比乌斯带

+   3D 莫比乌斯带

+   管

+   Torus knot

+   球体

本章的最后一部分涉及创建 3D 文本对象。

# 创建 3D 文本

在本章的最后一部分，我们将快速了解如何创建 3D 文本效果。首先，我们将看看如何使用 Three.js 提供的字体来渲染文本，然后我们将快速了解如何使用自己的字体来实现这一点。

## 渲染文本

在 Three.js 中渲染文本非常容易。你所要做的就是定义你想要使用的字体和我们在讨论`THREE.ExtrudeGeometry`时看到的基本挤出属性。以下截图显示了在 Three.js 中渲染文本的`07-text-geometry.html`示例：

![渲染文本](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_06_07.jpg)

创建这个 3D 文本所需的代码如下：

```js
var options = {
  size: 90,
  height: 90,
  weight: 'normal',
  font: 'helvetiker',
  style: 'normal',
  bevelThickness: 2,
  bevelSize: 4,
  bevelSegments: 3,
  bevelEnabled: true,
  curveSegments: 12,
  steps: 1
};

// the createMesh is the same function we saw earlier
text1 = createMesh(new THREE.TextGeometry("Learning", options));
text1.position.z = -100;
text1.position.y = 100;
scene.add(text1);

text2 = createMesh(new THREE.TextGeometry("Three.js", options));
scene.add(text2);
};
```

让我们看看我们可以为`THREE.TextGeometry`指定的所有选项：

| 属性 | 强制性 | 描述 |
| --- | --- | --- |
| `size` | No | 这是文本的大小。默认值为`100`。 |
| `height` | No | 这是挤出的长度（深度）。默认值为`50`。 |
| `weight` | No | 这是字体的粗细。可能的值是`normal`和`bold`。默认值是`normal`。 |
| `font` | No | 这是要使用的字体的名称。默认值是`helvetiker`。 |
| `style` | No | 这是字体的粗细。可能的值是`normal`和`italic`。默认值是`normal`。 |
| `bevelThickness` | No | 这是斜角的深度。斜角是正面和背面以及挤出之间的圆角。默认值为`10`。 |
| `bevelSize` | No | 这是斜角的高度。默认值为`8`。 |
| `bevelSegments` | No | 这定义了斜角使用的段数。段数越多，斜角看起来越平滑。默认值为`3`。 |
| `bevelEnabled` | No | 如果设置为`true`，则添加斜角。默认值为`false`。 |
| `curveSegments` | No | 这定义了在挤出形状的曲线时使用的段数。段数越多，曲线看起来越平滑。默认值为`4`。 |
| `steps` | No | 这定义了挤出物将被分成的段数。默认值为`1`。 |
| `extrudePath` | No | 这是形状应该沿着的路径。如果没有指定，形状将沿着*z*轴挤出。 |
| `material` | No | 这是要用于正面和背面的材质的索引。使用`THREE.SceneUtils.createMultiMaterialObject`函数来创建网格。 |
| `extrudeMaterial` | No | 这是用于斜角和挤出的材质的索引。使用`THREE.SceneUtils.createMultiMaterialObject`函数来创建网格。 |
| `uvGenerator` | No | 当你在材质中使用纹理时，UV 映射决定了纹理的哪一部分用于特定的面。使用`UVGenerator`属性，你可以传入自己的对象，用于为传入的形状创建面的 UV 设置。有关 UV 设置的更多信息可以在第十章中找到，*加载和使用纹理*。如果没有指定，将使用`THREE.ExtrudeGeometry.WorldUVGenerator`。 |
| `frames` | No | 弗雷内框架用于计算样条的切线、法线和副法线。这在沿着`extrudePath`挤出时使用。你不需要指定这个，因为 Three.js 提供了自己的实现，`THREE.TubeGeometry.FrenetFrames`，它也被用作默认值。有关弗雷内框架的更多信息可以在[`en.wikipedia.org/wiki/Differential_geometry_of_curves#Frenet_frame`](http://en.wikipedia.org/wiki/Differential_geometry_of_curves#Frenet_frame)找到。 |

Three.js 中包含的字体也被添加到了本书的资源中。你可以在`assets/fonts`文件夹中找到它们。

### 提示

如果你想在 2D 中渲染字体，例如将它们用作材质的纹理，你不应该使用`THREE.TextGeometry`。`THREE.TextGeometry`内部使用`THREE.ExtrudeGeometry`来构建 3D 文本，而 JavaScript 字体引入了很多开销。渲染简单的 2D 字体比仅仅使用 HTML5 画布更好。使用`context.font`，你可以设置要使用的字体，使用`context.fillText`，你可以将文本输出到画布上。然后你可以使用这个画布作为纹理的输入。我们将在第十章*加载和使用纹理*中向你展示如何做到这一点。

也可以使用其他字体与这个几何图形，但是你首先需要将它们转换为 JavaScript。如何做到这一点将在下一节中展示。

## 添加自定义字体

Three.js 提供了一些字体，你可以在场景中使用。这些字体基于**typeface.js**提供的字体（[`typeface.neocracy.org:81/`](http://typeface.neocracy.org:81/)）。Typeface.js 是一个可以将 TrueType 和 OpenType 字体转换为 JavaScript 的库。生成的 JavaScript 文件可以包含在你的页面中，然后可以在 Three.js 中使用该字体。

要转换现有的 OpenType 或 TrueType 字体，可以使用[`typeface.neocracy.org:81/fonts.html`](http://typeface.neocracy.org:81/fonts.html)上的网页。在这个页面上，你可以上传一个字体，它将被转换为 JavaScript。请注意，这并不适用于所有类型的字体。字体越简单（更直线），在 Three.js 中使用时渲染正确的机会就越大。

要包含该字体，只需在你的 HTML 页面顶部添加以下行：

```js
<script type="text/javascript" src="../assets/fonts/bitstream_vera_sans_mono_roman.typeface.js">
</script>
```

这将加载字体并使其可用于 Three.js。如果你想知道字体的名称（用于`font`属性），你可以使用以下一行 JavaScript 代码将字体缓存打印到控制台上：

```js
console.log(THREE.FontUtils.faces);
```

这将打印出类似以下的内容：

![添加自定义字体](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_06_08.jpg)

在这里，你可以看到我们可以使用`helvetiker`字体，`weight`为`bold`或`normal`，以及`bitstream vera sans mono`字体，`weight`为`normal`。请注意，每种字体重量都有单独的 JavaScript 文件，并且需要单独加载。确定字体名称的另一种方法是查看字体的 JavaScript 源文件。在文件的末尾，你会找到一个名为`familyName`的属性，如下面的代码所示。这个属性也包含了字体的名称：

```js
"familyName":"Bitstream Vera Sans Mono"
```

在本章的下一部分中，我们将介绍 ThreeBSP 库，使用二进制操作`intersect`、`subtract`和`union`创建非常有趣的几何图形。

# 使用二进制操作来合并网格

在本节中，我们将看一种不同的创建几何图形的方法。到目前为止，在本章和上一章中，我们使用了 Three.js 提供的默认几何图形来创建有趣的几何图形。使用默认属性集，你可以创建美丽的模型，但是你受限于 Three.js 提供的内容。在本节中，我们将向你展示如何组合这些标准几何图形来创建新的几何图形——一种称为**构造实体几何**（**CSG**）的技术。为此，我们使用了 Three.js 扩展 ThreeBSP，你可以在[`github.com/skalnik/ThreeBSP`](https://github.com/skalnik/ThreeBSP)上找到。这个额外的库提供了以下三个函数：

| 名称 | 描述 |
| --- | --- |
| `intersect` | 此函数允许你基于两个现有几何图形的交集创建一个新的几何图形。两个几何图形重叠的区域将定义这个新几何图形的形状。 |
| `union` | union 函数可用于合并两个几何体并创建一个新的几何体。您可以将其与我们将在第八章中查看的`mergeGeometry`功能进行比较，*创建和加载高级网格和几何体*。 |
| `subtract` | 减法函数是 union 函数的相反。您可以通过从第一个几何体中去除重叠区域来创建一个新的几何体。 |

在接下来的几节中，我们将更详细地查看每个函数。以下截图显示了仅使用`union`和`subtract`功能后可以创建的示例。

![使用二进制操作合并网格](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_06_09.jpg)

要使用这个库，我们需要在页面中包含它。这个库是用 CoffeeScript 编写的，这是 JavaScript 的一个更用户友好的变体。要使其工作，我们有两个选项。我们可以添加 CoffeeScript 文件并即时编译它，或者我们可以预编译为 JavaScript 并直接包含它。对于第一种方法，我们需要执行以下操作：

```js
<script type="text/javascript" src="../libs/coffee-script.js"></script>
<script type="text/coffeescript" src="../libs/ThreeBSP.coffee"></script>
```

`ThreeBSP.coffee`文件包含了我们在这个示例中需要的功能，`coffee-script.js`可以解释用于 ThreeBSP 的 Coffee 语言。我们需要采取的最后一步是确保`ThreeBSP.coffee`文件在我们开始使用 ThreeBSP 功能之前已经被完全解析。为此，我们在文件底部添加以下内容：

```js
<script type="text/coffeescript">
  onReady();
</script>
```

我们将初始的`onload`函数重命名为`onReady`，如下所示：

```js
function onReady() {
  // Three.js code
}
```

如果我们使用 CoffeeScript 命令行工具将 CoffeeScript 预编译为 JavaScript，我们可以直接包含生成的 JavaScript 文件。不过，在这之前，我们需要安装 CoffeeScript。您可以在 CoffeeScript 网站上按照安装说明进行安装[`coffeescript.org/`](http://coffeescript.org/)。安装完 CoffeeScript 后，您可以使用以下命令行将 CoffeeScript ThreeBSP 文件转换为 JavaScript：

```js
coffee --compile ThreeBSP.coffee
```

这个命令创建了一个`ThreeBSP.js`文件，我们可以像其他 JavaScript 文件一样在我们的示例中包含它。在我们的示例中，我们使用了第二种方法，因为它比每次加载页面时编译 CoffeeScript 要快。为此，我们只需要在我们的 HTML 页面顶部添加以下内容：

```js
<script type="text/javascript" src="../libs/ThreeBSP.js"></script>
```

现在 ThreeBSP 库已加载，我们可以使用它提供的功能。

## 减法函数

在我们开始使用`subtract`函数之前，有一个重要的步骤需要记住。这三个函数使用网格的绝对位置进行计算。因此，如果您在应用这些函数之前将网格分组在一起或使用多个材质，可能会得到奇怪的结果。为了获得最佳和最可预测的结果，请确保您正在使用未分组的网格。

让我们首先演示“减法”功能。为此，我们提供了一个示例`08-binary-operations.html`。通过这个示例，您可以尝试这三种操作。当您首次打开二进制操作示例时，您会看到以下启动屏幕：

![减法功能](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_06_10.jpg)

有三个线框：一个立方体和两个球体。**Sphere1**，中心球体，是执行所有操作的对象，**Sphere2**位于右侧，**Cube**位于左侧。在**Sphere2**和**Cube**上，您可以定义四种操作之一：**subtract**，**union**，**intersect**和**none**。这些操作是从**Sphere1**的视角应用的。当我们将**Sphere2**设置为 subtract 并选择**showResult**（并隐藏线框）时，结果将显示**Sphere1**减去**Sphere1**和**Sphere2**重叠的区域。请注意，这些操作中的一些可能需要几秒钟才能在您按下**showResult**按钮后完成，因此在*busy*指示器可见时请耐心等待。

下面的截图显示了减去另一个球体后的球体的结果动作：

![减去函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_06_11.jpg)

在这个示例中，首先执行了“Sphere2”定义的操作，然后执行了“Cube”的操作。因此，如果我们减去“Sphere2”和“Cube”（我们沿着 x 轴稍微缩放），我们会得到以下结果：

![减去函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_06_12.jpg)

理解“减去”功能的最佳方法就是玩弄一下示例。在这个示例中，ThreeBSP 代码非常简单，并且在`redrawResult`函数中实现，我们在示例中点击“showResult”按钮时调用该函数：

```js
function redrawResult() {
  scene.remove(result);
  var sphere1BSP = new ThreeBSP(sphere1);
  var sphere2BSP = new ThreeBSP(sphere2);
  var cube2BSP = new ThreeBSP(cube);

  var resultBSP;

  // first do the sphere
  switch (controls.actionSphere) {
    case "subtract":
      resultBSP = sphere1BSP.subtract(sphere2BSP);
    break;
    case "intersect":
      resultBSP = sphere1BSP.intersect(sphere2BSP);
    break;
    case "union":
      resultBSP = sphere1BSP.union(sphere2BSP);
    break;
    case "none": // noop;
  }

  // next do the cube
  if (!resultBSP) resultBSP = sphere1BSP;
  switch (controls.actionCube) {
    case "subtract":
      resultBSP = resultBSP.subtract(cube2BSP);
    break;
    case "intersect":
      resultBSP = resultBSP.intersect(cube2BSP);
    break;
    case "union":
      resultBSP = resultBSP.union(cube2BSP);
    break;
    case "none": // noop;
  }

  if (controls.actionCube === "none" && controls.actionSphere === "none") {
  // do nothing
  } else {
    result = resultBSP.toMesh();
    result.geometry.computeFaceNormals();
    result.geometry.computeVertexNormals();
    scene.add(result);
  }
}
```

在这段代码中，我们首先将我们的网格（你可以看到的线框）包装在一个`ThreeBSP`对象中。这使我们能够在这些对象上应用“减去”、“交集”和“联合”功能。现在，我们可以在包装在中心球体周围的`ThreeBSP`对象上调用我们想要的特定功能，这个函数的结果将包含我们创建新网格所需的所有信息。要创建这个网格，我们只需在`sphere1BSP`对象上调用`toMesh()`函数。在结果对象上，我们必须确保所有的法线都通过首先调用`computeFaceNormals`然后调用`computeVertexNormals()`来正确计算。这些计算函数需要被调用，因为通过运行二进制操作之一，几何体的顶点和面会发生变化，这会影响面的法线。显式地重新计算它们将确保你的新对象被平滑地着色（当材质上的着色设置为`THREE.SmoothShading`时）并正确渲染。最后，我们将结果添加到场景中。

对于“交集”和“联合”，我们使用完全相同的方法。

## 交集函数

在前一节中我们解释的一切，对于“交集”功能来说并没有太多需要解释的了。使用这个功能，只有重叠的部分是留下来的网格。下面的截图是一个示例，其中球体和立方体都设置为相交：

![交集函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_06_13.jpg)

如果你看一下示例并玩弄一下设置，你会发现很容易创建这些类型的对象。记住，这可以应用于你可以创建的每一个网格，甚至是我们在本章中看到的复杂网格，比如`THREE.ParametricGeometry`和`THREE.TextGeometry`。

“减去”和“交集”功能一起运行得很好。我们在本节开头展示的示例是通过首先减去一个较小的球体来创建一个空心球体。之后，我们使用立方体与这个空心球体相交，得到以下结果（带有圆角的空心立方体）：

![交集函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_06_14.jpg)

ThreeBSP 提供的最后一个功能是“联合”功能。

## 联合函数

ThreeBSP 提供的最后一个功能是最不有趣的。使用这个功能，我们可以将两个网格组合在一起创建一个新的网格。因此，当我们将这个应用于两个球体和立方体时，我们将得到一个单一的对象——联合函数的结果：

![联合函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_06_15.jpg)

这并不是真的很有用，因为 Three.js 也提供了这个功能（参见第八章，“创建和加载高级网格和几何体”，在那里我们解释了如何使用`THREE.Geometry.merge`），而且性能稍微更好。如果启用旋转，你会发现这个联合是从中心球体的角度应用的，因为它是围绕那个球体的中心旋转的。其他两个操作也是一样的。

# 摘要

在本章中，我们看到了很多内容。我们介绍了一些高级几何图形，甚至向你展示了如何使用一些简单的二进制操作来创建有趣的几何图形。我们向你展示了如何使用高级几何图形，比如`THREE.ConvexGeometry`、`THREE.TubeGeometry`和`THREE.LatheGeometry`来创建非常漂亮的形状，并且可以尝试这些几何图形来获得你想要的结果。一个非常好的特性是，我们还可以将现有的 SVG 路径转换为 Three.js。不过，请记住，你可能仍然需要使用诸如 GIMP、Adobe Illustrator 或 Inkscape 等工具来微调路径。

如果你想创建 3D 文本，你需要指定要使用的字体。Three.js 自带了一些你可以使用的字体，但你也可以创建自己的字体。然而，请记住，复杂的字体通常不会正确转换。最后，使用 ThreeBSP，你可以访问三种二进制操作，可以应用到你的网格上：联合、减去和相交。使用联合，你可以将两个网格组合在一起；使用减去，你可以从源网格中移除重叠部分的网格；使用相交，只有重叠部分被保留。

到目前为止，我们看到了实体（或线框）几何图形，其中顶点相互连接形成面。在接下来的章节中，我们将看一种用称为粒子的东西来可视化几何图形的替代方法。使用粒子，我们不渲染完整的几何图形——我们只将顶点渲染为空间中的点。这使你能够创建外观出色且性能良好的 3D 效果。


# 第七章：粒子、精灵和点云

在之前的章节中，我们讨论了 Three.js 提供的最重要的概念、对象和 API。在本章中，我们将研究到目前为止我们跳过的唯一概念：粒子。使用粒子（有时也称为精灵），非常容易创建许多小对象，你可以用来模拟雨、雪、烟雾和其他有趣的效果。例如，你可以将单个几何体渲染为一组粒子，并分别控制这些粒子。在本章中，我们将探索 Three.js 提供的各种粒子特性。更具体地说，在本章中，我们将研究以下主题：

+   使用`THREE.SpriteMaterial`创建和设置粒子的样式

+   使用点云创建一组分组的粒子

+   从现有几何体创建点云

+   动画粒子和粒子系统

+   使用纹理来设置粒子的样式

+   使用`THREE.SpriteCanvasMaterial`使用画布设置粒子的样式

让我们先来探讨一下什么是粒子，以及如何创建一个。不过，在我们开始之前，关于本章中使用的一些名称，有一个快速说明。在最近的 Three.js 版本中，与粒子相关的对象的名称已经发生了变化。我们在本章中使用的`THREE.PointCloud`，以前被称为`THREE.ParticleSystem`，`THREE.Sprite`以前被称为`THREE.Particle`，材质也经历了一些名称的变化。因此，如果你看到使用这些旧名称的在线示例，请记住它们谈论的是相同的概念。在本章中，我们使用了最新版本 Three.js 引入的新命名约定。

# 理解粒子

就像我们对大多数新概念一样，我们将从一个例子开始。在本章的源代码中，你会找到一个名为`01-particles.html`的例子。打开这个例子，你会看到一个非常不起眼的白色立方体网格，如下面的截图所示：

![理解粒子](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_07_01.jpg)

在这个截图中，你看到的是 100 个精灵。精灵是一个始终面向摄像机的二维平面。如果你创建一个没有任何属性的精灵，它们会被渲染为小的、白色的、二维的正方形。这些精灵是用以下代码创建的：

```js
function createSprites() {
  var material = new THREE.SpriteMaterial();
  for (var x = -5; x < 5; x++) {
    for (var y = -5; y < 5; y++) {
      var sprite = new THREE.Sprite(material);
      sprite.position.set(x * 10, y * 10, 0);
      scene.add(sprite);
    }
  }
}
```

在这个例子中，我们使用`THREE.Sprite(material)`构造函数手动创建精灵。我们传入的唯一项是一个材质。这必须是`THREE.SpriteMaterial`或`THREE.SpriteCanvasMaterial`。我们将在本章的其余部分更深入地研究这两种材质。

在我们继续研究更有趣的粒子之前，让我们更仔细地看一看`THREE.Sprite`对象。`THREE.Sprite`对象扩展自`THREE.Object3D`对象，就像`THREE.Mesh`一样。这意味着你可以使用大多数从`THREE.Mesh`中了解的属性和函数在`THREE.Sprite`上。你可以使用`position`属性设置其位置，使用`scale`属性缩放它，并使用`translate`属性相对移动它。

### 提示

请注意，在较旧版本的 Three.js 中，你无法使用`THREE.Sprite`对象与`THREE.WebGLRenderer`一起使用，只能与`THREE.CanvasRenderer`一起使用。在当前版本中，`THREE.Sprite`对象可以与两种渲染器一起使用。

使用`THREE.Sprite`，你可以非常容易地创建一组对象并在场景中移动它们。当你使用少量对象时，这很有效，但是当你想要使用大量`THREE.Sprite`对象时，你很快就会遇到性能问题，因为每个对象都需要被 Three.js 单独管理。Three.js 提供了另一种处理大量精灵（或粒子）的方法，使用`THREE.PointCloud`。使用`THREE.PointCloud`，Three.js 不需要单独管理许多个`THREE.Sprite`对象，而只需要管理`THREE.PointCloud`实例。

要获得与之前看到的屏幕截图相同的结果，但这次使用`THREE.PointCloud`，我们执行以下操作：

```js
function createParticles() {

  var geom = new THREE.Geometry();
  var material = new THREE.PointCloudMaterial({size: 4, vertexColors: true, color: 0xffffff});

  for (var x = -5; x < 5; x++) {
    for (var y = -5; y < 5; y++) {
      var particle = new THREE.Vector3(x * 10, y * 10, 0);
      geom.vertices.push(particle);
      geom.colors.push(new THREE.Color(Math.random() * 0x00ffff));
    }
  }

  var cloud = new THREE.PointCloud(geom, material);
  scene.add(cloud);
}
```

正如您所看到的，对于每个粒子（云中的每个点），我们需要创建一个顶点（由`THREE.Vector3`表示），将其添加到`THREE.Geometry`中，使用`THREE.Geometry`和`THREE.PointCloudMaterial`创建`THREE.PointCloud`，并将云添加到场景中。`THREE.PointCloud`的示例（带有彩色方块）可以在`02-particles-webgl.html`示例中找到。以下屏幕截图显示了此示例：

![理解粒子](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_07_02.jpg)

在接下来的几节中，我们将进一步探讨`THREE.PointCloud`。

# 粒子，THREE.PointCloud 和 THREE.PointCloudMaterial

在上一节的最后，我们快速介绍了`THREE.PointCloud`。`THREE.PointCloud`的构造函数接受两个属性：几何体和材质。材质用于着色和纹理粒子（稍后我们将看到），几何体定义了单个粒子的位置。用于定义几何体的每个顶点和每个点都显示为一个粒子。当我们基于`THREE.BoxGeometry`创建`THREE.PointCloud`时，我们会得到 8 个粒子，每个粒子代表立方体的每个角落。不过，通常情况下，您不会从标准的 Three.js 几何体之一创建`THREE.PointCloud`，而是手动将顶点添加到从头创建的几何体中（或使用外部加载的模型），就像我们在上一节的最后所做的那样。在本节中，我们将深入探讨这种方法，并查看如何使用`THREE.PointCloudMaterial`来设置粒子的样式。我们将使用`03-basic-point-cloud.html`示例来探索这一点。以下屏幕截图显示了此示例：

![粒子，THREE.PointCloud 和 THREE.PointCloudMaterial](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_07_03.jpg)

在此示例中，我们创建了`THREE.PointCloud`，并用 15000 个粒子填充它。所有粒子都使用`THREE.PointCloudMaterial`进行样式设置。要创建`THREE.PointCloud`，我们使用了以下代码：

```js
function createParticles(size, transparent, opacity, vertexColors, sizeAttenuation, color) {

  var geom = new THREE.Geometry();
  var material = new THREE.PointCloudMaterial({size: size, transparent: transparent, opacity: opacity, vertexColors: vertexColors, sizeAttenuation: sizeAttenuation, color: color});

  var range = 500;
  for (var i = 0; i < 15000; i++) {
    var particle = new THREE.Vector3(Math.random() * range - range / 2, Math.random() * range - range / 2, Math.random() * range - range / 2);
    geom.vertices.push(particle);
    var color = new THREE.Color(0x00ff00);
    color.setHSL(color.getHSL().h, color.getHSL().s, Math.random() * color.getHSL().l);
    geom.colors.push(color);
  }

  cloud = new THREE.PointCloud(geom, material);
  scene.add(cloud);
}
```

在此列表中，我们首先创建`THREE.Geometry`。我们将粒子表示为`THREE.Vector3`添加到此几何体中。为此，我们创建了一个简单的循环，以随机位置创建`THREE.Vector3`并将其添加。在同一个循环中，我们还指定了颜色数组`geom.colors`，当我们将`THREE.PointCloudMaterial`的`vertexColors`属性设置为`true`时使用。最后要做的是创建`THREE.PointCloudMaterial`并将其添加到场景中。

下表解释了您可以在`THREE.PointCloudMaterial`上设置的所有属性：

| 名称 | 描述 |
| --- | --- |
| `color` | 这是`ParticleSystem`中所有粒子的颜色。将`vertexColors`属性设置为 true，并使用几何体的颜色属性指定颜色会覆盖此属性（更准确地说，顶点的颜色将与此值相乘以确定最终颜色）。默认值为`0xFFFFFF`。 |
| map | 使用此属性，您可以将纹理应用于粒子。例如，您可以使它们看起来像雪花。此属性在此示例中未显示，但在本章后面会有解释。 |
| size | 这是粒子的大小。默认值为`1`。 |
| sizeAnnutation | 如果将其设置为 false，则所有粒子的大小都将相同，而不管它们距离摄像机的位置有多远。如果将其设置为 true，则大小基于距离摄像机的距离。默认值为`true`。 |
| vertexColors | 通常，`THREE.PointCloud`中的所有粒子都具有相同的颜色。如果将此属性设置为`THREE.VertexColors`并且填充了几何体中的颜色数组，则将使用该数组中的颜色（还请参阅此表中的颜色条目）。默认值为`THREE.NoColors`。 |
| opacity | 这与 transparent 属性一起设置了粒子的不透明度。默认值为`1`（不透明）。 |
| 透明 | 如果设置为 true，则粒子将以不透明度属性设置的不透明度进行渲染。默认值为`false`。 |
| 混合 | 这是渲染粒子时使用的混合模式。有关混合模式的更多信息，请参见第九章*动画和移动摄像机*。 |
| 雾 | 这决定了粒子是否受到添加到场景中的雾的影响。默认值为`true`。 |

上一个示例提供了一个简单的控制菜单，您可以使用它来实验特定于`THREE.ParticleCloudMaterial`的属性。

到目前为止，我们只将粒子呈现为小立方体，这是默认行为。然而，您还有一些其他方式可以用来设置粒子的样式：

+   我们可以应用`THREE.SpriteCanvasMaterial`（仅适用于`THREE.CanvasRenderer`）来使用 HTML 画布元素的结果作为纹理

+   使用`THREE.SpriteMaterial`和基于 HTML5 的纹理在使用`THREE.WebGLRenderer`时使用 HTML 画布的输出

+   使用`THREE.PointCloudMaterial`的`map`属性加载外部图像文件（或使用 HTML5 画布）来为`THREE.ParticleCloud`的所有粒子设置样式

在下一节中，我们将看看如何做到这一点。

# 使用 HTML5 画布对粒子进行样式设置

Three.js 提供了三种不同的方式，您可以使用 HTML5 画布来设置粒子的样式。如果您使用`THREE.CanvasRenderer`，您可以直接从`THREE.SpriteCanvasMaterial`引用 HTML5 画布。当您使用`THREE.WebGLRenderer`时，您需要采取一些额外的步骤来使用 HTML5 画布来设置粒子的样式。在接下来的两节中，我们将向您展示不同的方法。

## 使用 HTML5 画布与 THREE.CanvasRenderer

使用`THREE.SpriteCanvasMaterial`，您可以使用 HTML5 画布的输出作为粒子的纹理。这种材质是专门为`THREE.CanvasRenderer`创建的，并且只在使用这个特定的渲染器时才有效。在我们看如何使用这种材质之前，让我们先看看您可以在这种材质上设置的属性：

| 名称 | 描述 |
| --- | --- |
| `颜色` | 这是粒子的颜色。根据指定的`混合`模式，这会影响画布图像的颜色。 |
| `program` | 这是一个以画布上下文作为参数的函数。当粒子被渲染时，将调用此函数。对这个 2D 绘图上下文的调用的输出显示为粒子。 |
| `不透明度` | 这决定了粒子的不透明度。默认值为`1`，即不透明。 |
| `透明` | 这决定了粒子是否是透明的。这与`不透明度`属性一起使用。 |
| `混合` | 这是要使用的混合模式。有关更多详细信息，请参见第九章*动画和移动摄像机*。 |
| `旋转` | 这个属性允许您旋转画布的内容。通常需要将其设置为 PI，以正确对齐画布的内容。请注意，这个属性不能传递给材质的构造函数，而需要显式设置。 |

要查看`THREE.SpriteCanvasMaterial`的实际效果，您可以打开`04-program-based-sprites.html`示例。以下屏幕截图显示了这个例子：

![使用 HTML5 画布与 THREE.CanvasRenderer](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_07_04.jpg)

在这个例子中，粒子是在`createSprites`函数中创建的：

```js
function createSprites() {

  var material = new THREE.SpriteCanvasMaterial({
    program: draw,
    color: 0xffffff});
   material.rotation = Math.PI;

  var range = 500;
  for (var i = 0; i < 1000; i++) {
    var sprite = new THREE.Sprite(material);
    sprite.position = new THREE.Vector3(Math.random() * range - range / 2, Math.random() * range - range / 2, Math.random() * range - range / 2);
    sprite.scale.set(0.1, 0.1, 0.1);
    scene.add(sprite);
  }
}
```

这段代码看起来很像我们在上一节中看到的代码。主要变化是，因为我们正在使用`THREE.CanvasRenderer`，我们直接创建`THREE.Sprite`对象，而不是使用`THREE.PointCloud`。在这段代码中，我们还使用`program`属性定义了`THREE.SpriteCanvasMaterial`，该属性指向`draw`函数。这个`draw`函数定义了粒子的外观（在我们的例子中，是*Pac-Man*中的幽灵）：

```js
var draw = function(ctx) {
  ctx.fillStyle = "orange";
  ...
  // lots of other ctx drawing calls
  ...
  ctx.beginPath();
  ctx.fill();
}
```

我们不会深入讨论绘制形状所需的实际画布代码。这里重要的是我们定义了一个接受 2D 画布上下文（`ctx`）作为参数的函数。在该上下文中绘制的一切都被用作`THREE.Sprite`的形状。

## 使用 HTML5 画布与 WebGLRenderer

如果我们想要在`THREE.WebGLRenderer`中使用 HTML5 画布，我们可以采取两种不同的方法。我们可以使用`THREE.PointCloudMaterial`并创建`THREE.PointCloud`，或者我们可以使用`THREE.Sprite`和`THREE.SpriteMaterial`的`map`属性。

让我们从第一种方法开始创建`THREE.PointCloud`。在`THREE.PointCloudMaterial`的属性中，我们提到了`map`属性。使用`map`属性，我们可以为粒子加载纹理。在 Three.js 中，这个纹理也可以是来自 HTML5 画布的输出。一个展示这个概念的例子是`05a-program-based-point-cloud-webgl.html`。以下截图显示了这个例子：

![使用 HTML5 画布与 WebGLRenderer](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_07_05.jpg)

让我们来看看我们编写的代码来实现这个效果。大部分代码与我们之前的 WebGL 示例相同，所以我们不会详细介绍。为了得到这个例子所做的重要代码更改如下所示：

```js
var getTexture = function() {
  var canvas = document.createElement('canvas');
  canvas.width = 32;
  canvas.height = 32;

  var ctx = canvas.getContext('2d');
  ...
  // draw the ghost
  ...
  ctx.fill();
  var texture = new THREE.Texture(canvas);
  texture.needsUpdate = true;
  return texture;
}

function createPointCloud(size, transparent, opacity, sizeAttenuation, color) {

  var geom = new THREE.Geometry();

  var material = new THREE.PointCloudMaterial ({size: size, transparent: transparent, opacity: opacity, map: getTexture(), sizeAttenuation: sizeAttenuation, color: color});

  var range = 500;
  for (var i = 0; i < 5000; i++) {
    var particle = new THREE.Vector3(Math.random() * range - range / 2, Math.random() * range - range / 2, Math.random() * range - range / 2);
    geom.vertices.push(particle);
  }

  cloud = new THREE.PointCloud(geom, material);
  cloud.sortParticles = true;
  scene.add(cloud);
}
```

在`getTexture`中，这两个 JavaScript 函数中的第一个，我们基于 HTML5 画布元素创建了`THREE.Texture`。在第二个函数`createPointCloud`中，我们将这个纹理分配给了`THREE.PointCloudMaterial`的`map`属性。在这个函数中，您还可以看到我们将`THREE.PointCloud`的`sortParticles`属性设置为`true`。这个属性确保在粒子被渲染之前，它们根据屏幕上的*z*位置进行排序。如果您看到部分重叠的粒子或不正确的透明度，将此属性设置为`true`（在大多数情况下）可以解决这个问题。不过，您应该注意，将此属性设置为`true`会影响场景的性能。当这个属性设置为 true 时，Three.js 将不得不确定每个单独粒子到相机的距离。对于一个非常大的`THREE.PointCloud`对象，这可能会对性能产生很大的影响。

当我们谈论`THREE.PointCloud`的属性时，还有一个额外的属性可以设置在`THREE.PointCloud`上：`FrustumCulled`。如果将此属性设置为 true，这意味着如果粒子超出可见相机范围，它们将不会被渲染。这可以用来提高性能和帧速率。

这样做的结果是，我们在`getTexture()`方法中绘制到画布上的一切都用于`THREE.PointCloud`中的粒子。在接下来的部分中，我们将更深入地了解从外部文件加载的纹理是如何工作的。请注意，在这个例子中，我们只看到了纹理可能实现的一小部分。在第十章中，*加载和使用纹理*，我们将深入了解纹理的可能性。

在本节的开头，我们提到我们也可以使用`THREE.Sprite`与`map`属性一起创建基于画布的粒子。为此，我们使用了与前面示例中相同的方法创建`THREE.Texture`。然而，这一次，我们将它分配给`THREE.Sprite`，如下所示：

```js
function createSprites() {
  var material = new THREE.SpriteMaterial({
    map: getTexture(),
    color: 0xffffff
  });

  var range = 500;
  for (var i = 0; i < 1500; i++) {
    var sprite = new THREE.Sprite(material);
    sprite.position.set(Math.random() * range - range / 2, Math.random() * range - range / 2, Math.random() * range - range / 2);
    sprite.scale.set(4,4,4);
    scene.add(sprite);
  }
}
```

在这里，你可以看到我们使用了一个标准的`THREE.SpriteMaterial`对象，并将画布的输出作为`THREE.Texture`分配给了材质的`map`属性。您可以通过在浏览器中打开`05b-program-based-sprites-webgl.html`来查看这个例子。这两种方法各有优缺点。使用`THREE.Sprite`，您可以更好地控制每个粒子，但当您处理大量粒子时，性能会降低，复杂性会增加。使用`THREE.PointCloud`，您可以轻松管理大量粒子，但对每个单独的粒子的控制较少。

# 使用纹理来设置粒子的样式

在之前的例子中，我们看到了如何使用 HTML5 画布来设置`THREE.PointCloud`和单个`THREE.Sprite`对象的样式。由于您可以绘制任何您想要的东西，甚至加载外部图像，您可以使用这种方法向粒子系统添加各种样式。然而，有一种更直接的方法可以使用图像来设置您的粒子的样式。您可以使用`THREE.ImageUtils.loadTexture()`函数将图像加载为`THREE.Texture`。然后可以将`THREE.Texture`分配给材质的`map`属性。

在本节中，我们将向您展示两个示例并解释如何创建它们。这两个示例都使用图像作为粒子的纹理。在第一个示例中，我们创建了一个模拟雨的场景，`06-rainy-scene.html`。以下屏幕截图显示了这个示例：

![使用纹理来设置粒子的样式](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_07_06.jpg)

我们需要做的第一件事是获取一个代表雨滴的纹理。您可以在`assets/textures/particles`文件夹中找到一些示例。在第九章*动画和移动相机*中，我们将解释纹理的所有细节和要求。现在，您需要知道的是纹理应该是正方形的，最好是 2 的幂（例如，64 x 64，128 x 128，256 x 256）。对于这个例子，我们将使用这个纹理：

![使用纹理来设置粒子的样式](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_07_07.jpg)

这个图像使用了黑色背景（需要正确混合）并显示了雨滴的形状和颜色。在我们可以在`THREE.PointCloudMaterial`中使用这个纹理之前，我们首先需要加载它。可以用以下代码行来完成：

```js
var texture = THREE.ImageUtils.loadTexture("../assets/textures/particles/raindrop-2.png");
```

有了这行代码，Three.js 将加载纹理，我们可以在我们的材质中使用它。对于这个例子，我们定义了这样的材质：

```js
var material = new THREE.PointCloudMaterial({size: 3, transparent: true, opacity: true, map: texture, blending: THREE.AdditiveBlending, sizeAttenuation: true, color: 0xffffff});
```

在本章中，我们已经讨论了所有这些属性。这里需要理解的主要是`map`属性指向我们使用`THREE.ImageUtils.loadTexture()`函数加载的纹理，并且我们将`THREE.AdditiveBlending`指定为`blending`模式。这种`blending`模式意味着当绘制新像素时，背景像素的颜色会添加到这个新像素的颜色中。对于我们的雨滴纹理，这意味着黑色背景不会显示出来。一个合理的替代方案是用透明背景替换我们纹理中的黑色，但遗憾的是这在粒子和 WebGL 中不起作用。

这样就处理了`THREE.PointCloud`的样式。当您打开这个例子时，您还会看到粒子本身在移动。在之前的例子中，我们移动了整个粒子系统；这一次，我们在`THREE.PointCloud`内部定位了单个粒子。这样做实际上非常简单。每个粒子都表示为构成用于创建`THREE.PointCloud`的几何体的顶点。让我们看看如何为`THREE.PointCloud`添加粒子：

```js
var range = 40;
for (var i = 0; i < 1500; i++) {
  var particle = new THREE.Vector3(Math.random() * range - range / 2, Math.random() * range * 1.5, Math.random() * range - range / 2);

  particle.velocityX = (Math.random() - 0.5) / 3;
  particle.velocityY = 0.1 + (Math.random() / 5);
  geom.vertices.push(particle);
}
```

这与我们之前看到的例子并没有太大不同。在这里，我们为每个粒子（`THREE.Vector3`）添加了两个额外的属性：`velocityX`和`velocityY`。第一个定义了粒子（雨滴）水平移动的方式，第二个定义了雨滴下落的速度。水平速度范围从-0.16 到+0.16，垂直速度范围从 0.1 到 0.3。现在每个雨滴都有自己的速度，我们可以在渲染循环中移动单个粒子：

```js
var vertices = system2.geometry.vertices;
vertices.forEach(function (v) {
  v.x = v.x - (v.velocityX);
  v.y = v.y - (v.velocityY);

  if (v.x <= -20 || v.x >= 20) v.velocityX = v.velocityX * -1;
  if (v.y <= 0) v.y = 60;
});
```

在这段代码中，我们从用于创建`THREE.PointCloud`的几何体中获取所有`vertices`（粒子）。对于每个粒子，我们取`velocityX`和`velocityY`并使用它们来改变粒子的当前位置。最后两行确保粒子保持在我们定义的范围内。如果`v.y`位置低于零，我们将雨滴添加回顶部，如果`v.x`位置达到任何边缘，我们通过反转水平速度使其反弹回来。

让我们看另一个例子。这一次，我们不会下雨，而是下雪。此外，我们不仅使用单一纹理，还将使用五个单独的图像（来自 Three.js 示例）。让我们首先再次看一下结果（参见`07-snowy-scene.html`）：

![使用纹理来设置粒子样式](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_07_08.jpg)

在前面的截图中，您可以看到我们不仅使用单个图像作为纹理，还使用了多个图像。您可能想知道我们是如何做到这一点的。您可能还记得，我们只能为`THREE.PointCloud`有一个单一的材质。如果我们想要有多个材质，我们只需要创建多个粒子系统，如下所示：

```js
function createPointClouds(size, transparent, opacity, sizeAttenuation, color) {

  var texture1 = THREE.ImageUtils.loadTexture("../assets/textures/particles/snowflake1.png");
  var texture2 = THREE.ImageUtils.loadTexture("../assets/textures/particles/snowflake2.png");
  var texture3 = THREE.ImageUtils.loadTexture("../assets/textures/particles/snowflake3.png");
  var texture4 = THREE.ImageUtils.loadTexture("../assets/textures/particles/snowflake5.png");

  scene.add(createPointCloud("system1", texture1, size, transparent, opacity, sizeAttenuation, color));
  scene.add(createPointCloud ("system2", texture2, size, transparent, opacity, sizeAttenuation, color));
  scene.add(createPointCloud ("system3", texture3, size, transparent, opacity, sizeAttenuation, color));
  scene.add(createPointCloud ("system4", texture4, size, transparent, opacity, sizeAttenuation, color));
}
```

在这里，您可以看到我们分别加载纹理，并将创建`THREE.PointCloud`的所有信息传递给`createPointCloud`函数。这个函数看起来像这样：

```js
function createPointCloud(name, texture, size, transparent, opacity, sizeAttenuation, color) {
  var geom = new THREE.Geometry();

  var color = new THREE.Color(color);
  color.setHSL(color.getHSL().h, color.getHSL().s, (Math.random()) * color.getHSL().l);

  var material = new THREE.PointCloudMaterial({size: size, transparent: transparent, opacity: opacity, map: texture, blending: THREE.AdditiveBlending, depthWrite: false, sizeAttenuation: sizeAttenuation, color: color});

  var range = 40;
  for (var i = 0; i < 50; i++) {
    var particle = new THREE.Vector3(Math.random() * range - range / 2, Math.random() * range * 1.5, Math.random() * range - range / 2);
    particle.velocityY = 0.1 + Math.random() / 5;
    particle.velocityX = (Math.random() - 0.5) / 3;
    particle.velocityZ = (Math.random() - 0.5) / 3;
    geom.vertices.push(particle);
  }

  var cloud = new THREE.ParticleCloud(geom, material);
  cloud.name = name;
  cloud.sortParticles = true;
  return cloud;
}
```

在这个函数中，我们首先定义了应该渲染为特定纹理的粒子的颜色。这是通过随机改变传入颜色的*亮度*来完成的。接下来，材质以与之前相同的方式创建。这里唯一的变化是`depthWrite`属性设置为`false`。这个属性定义了这个对象是否影响 WebGL 深度缓冲区。通过将其设置为`false`，我们确保各种点云不会相互干扰。如果这个属性没有设置为`false`，您会看到当一个粒子在另一个`THREE.PointCloud`对象的粒子前面时，有时会显示纹理的黑色背景。这段代码的最后一步是随机放置粒子并为每个粒子添加随机速度。在渲染循环中，我们现在可以像这样更新每个`THREE.PointCloud`对象的所有粒子的位置：

```js
scene.children.forEach(function (child) {
  if (child instanceof THREE.ParticleSystem) {
    var vertices = child.geometry.vertices;
    vertices.forEach(function (v) {
      v.y = v.y - (v.velocityY);
      v.x = v.x - (v.velocityX);
      v.z = v.z - (v.velocityZ);

      if (v.y <= 0) v.y = 60;
      if (v.x <= -20 || v.x >= 20) v.velocityX = v.velocityX * -1;
      if (v.z <= -20 || v.z >= 20) v.velocityZ = v.velocityZ * -1;
    });
  }
});
```

通过这种方法，我们可以拥有不同纹理的粒子。然而，这种方法有点受限。我们想要的不同纹理越多，我们就必须创建和管理更多的点云。如果您有一组不同样式的有限粒子，最好使用我们在本章开头展示的`THREE.Sprite`对象。

# 使用精灵地图

在本章的开头，我们使用了`THREE.Sprite`对象来使用`THREE.CanvasRenderer`和`THREE.WebGLRenderer`渲染单个粒子。这些精灵被放置在 3D 世界的某个地方，并且它们的大小是基于与摄像机的距离（有时也称为**billboarding**）。在本节中，我们将展示`THREE.Sprite`对象的另一种用法。我们将向您展示如何使用`THREE.Sprite`创建类似于**抬头显示**（**HUD**）的 3D 内容的图层，使用额外的`THREE.OrthographicCamera`实例。我们还将向您展示如何使用精灵地图为`THREE.Sprite`对象选择图像。

作为示例，我们将创建一个简单的`THREE.Sprite`对象，它从屏幕左侧移动到右侧。在背景中，我们将渲染一个带有移动摄像机的 3D 场景，以说明`THREE.Sprite`独立于摄像机移动。以下截图显示了我们将为第一个示例创建的内容（`08-sprites.html`）：

![使用精灵地图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_07_09.jpg)

如果您在浏览器中打开此示例，您将看到类似 Pac-Man 幽灵的精灵在屏幕上移动，并且每当它碰到右边缘时，颜色和形状都会发生变化。我们首先要做的是看一下我们如何创建`THREE.OrthographicCamera`和一个单独的场景来渲染`THREE.Sprite`：

```js
var sceneOrtho = new THREE.Scene();
var cameraOrtho = new THREE.OrthographicCamera( 0, window.innerWidth, window.innerHeight, 0, -10, 10 );
```

接下来，让我们看看`THREE.Sprite`的构造以及精灵可以采用的各种形状是如何加载的：

```js
function getTexture() {
  var texture = new THREE.ImageUtils.loadTexture("../assets/textures/particles/sprite-sheet.png");
  return texture;
}

function createSprite(size, transparent, opacity, color, spriteNumber) {
  var spriteMaterial = new THREE.SpriteMaterial({
    opacity: opacity,
    color: color,
    transparent: transparent,
    map: getTexture()});

  // we have 1 row, with five sprites
  spriteMaterial.map.offset = new THREE.Vector2(1/5 * spriteNumber, 0);
  spriteMaterial.map.repeat = new THREE.Vector2(1/5, 1);
  spriteMaterial.blending = THREE.AdditiveBlending;

  // makes sure the object is always rendered at the front
  spriteMaterial.depthTest = false;
  var sprite = new THREE.Sprite(spriteMaterial);
  sprite.scale.set(size, size, size);
  sprite.position.set(100, 50, 0);
  sprite.velocityX = 5;

  sceneOrtho.add(sprite);
}
```

在`getTexture()`函数中，我们加载了一个纹理。但是，我们加载的不是每个*ghost*的五个不同图像，而是加载了一个包含所有精灵的单个纹理。纹理看起来像这样：

![使用精灵地图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_07_10.jpg)

通过`map.offset`和`map.repeat`属性，我们选择要在屏幕上显示的正确精灵。使用`map.offset`属性，我们确定了我们加载的纹理在*x*轴（u）和*y*轴（v）上的偏移量。这些属性的比例范围从 0 到 1。在我们的示例中，如果我们想选择第三个幽灵，我们将 u 偏移（*x*轴）设置为 0.4，因为我们只有一行，所以我们不需要改变 v 偏移（*y*轴）。如果我们只设置这个属性，纹理会在屏幕上压缩显示第三、第四和第五个幽灵。要只显示一个幽灵，我们需要放大。我们通过将 u 值的`map.repeat`属性设置为 1/5 来实现这一点。这意味着我们放大（仅对*x*轴）以仅显示纹理的 20％，这正好是一个幽灵。

我们需要采取的最后一步是更新`render`函数：

```js
webGLRenderer.render(scene, camera);
webGLRenderer.autoClear = false;
webGLRenderer.render(sceneOrtho, cameraOrtho);
```

我们首先使用普通相机和移动的球体渲染场景，然后再渲染包含我们的精灵的场景。请注意，我们需要将 WebGLRenderer 的`autoClear`属性设置为`false`。如果不这样做，Three.js 将在渲染精灵之前清除场景，并且球体将不会显示出来。

以下表格显示了我们在前面示例中使用的`THREE.SpriteMaterial`的所有属性的概述：

| 名称 | 描述 |
| --- | --- |
| `color` | 这是精灵的颜色。 |
| `map` | 这是要用于此精灵的纹理。这可以是一个精灵表，就像本节示例中所示的那样。 |
| `sizeAnnutation` | 如果设置为`false`，精灵的大小不会受到其与相机的距离影响。默认值为`true`。 |
| `opacity` | 这设置了精灵的透明度。默认值为`1`（不透明）。 |
| `blending` | 这定义了在渲染精灵时要使用的混合模式。有关混合模式的更多信息，请参见第九章*动画和移动相机*。 |
| `fog` | 这确定精灵是否受到添加到场景中的雾的影响。默认为`true`。 |

您还可以在此材质上设置`depthTest`和`depthWrite`属性。有关这些属性的更多信息，请参见第四章*使用 Three.js 材质*。

当然，在 3D 中定位`THREE.Sprites`时，我们也可以使用精灵地图（就像本章开头所做的那样）。以下是一个示例（`09-sprites-3D.html`）的屏幕截图：

![使用精灵地图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_07_11.jpg)

通过前表中的属性，我们可以很容易地创建前面屏幕截图中看到的效果：

```js
function createSprites() {

  group = new THREE.Object3D();
  var range = 200;
  for (var i = 0; i < 400; i++) {
    group.add(createSprite(10, false, 0.6, 0xffffff, i % 5, range));
  }
  scene.add(group);
}

function createSprite(size, transparent, opacity, color, spriteNumber, range) {

  var spriteMaterial = new THREE.SpriteMaterial({
    opacity: opacity,
    color: color,
    transparent: transparent,
    map: getTexture()}
  );

  // we have 1 row, with five sprites
  spriteMaterial.map.offset = new THREE.Vector2(0.2*spriteNumber, 0);
  spriteMaterial.map.repeat = new THREE.Vector2(1/5, 1);
  spriteMaterial.depthTest = false;

  spriteMaterial.blending = THREE.AdditiveBlending;

  var sprite = new THREE.Sprite(spriteMaterial);
  sprite.scale.set(size, size, size);
  sprite.position.set(Math.random() * range - range / 2, Math.random() * range - range / 2, Math.random() * range - range / 2);
  sprite.velocityX = 5;

  return sprite;
}
```

在这个示例中，我们基于我们之前展示的精灵表创建了 400 个精灵。您可能已经了解并理解了这里显示的大多数属性和概念。由于我们已经将单独的精灵添加到了一个组中，因此旋转它们非常容易，可以像这样完成：

```js
group.rotation.x+=0.1;
```

到目前为止，在本章中，我们主要是从头开始创建精灵和点云。不过，一个有趣的选择是从现有几何体创建`THREE.PointCloud`。

# 从高级几何体创建 THREE.PointCloud

正如您记得的那样，`THREE.PointCloud`根据提供的几何体的顶点渲染每个粒子。这意味着，如果我们提供一个复杂的几何体（例如环结或管道），我们可以基于该特定几何体的顶点创建`THREE.PointCloud`。在本章的最后一节中，我们将创建一个环结，就像我们在上一章中看到的那样，并将其渲染为`THREE.PointCloud`。

我们已经在上一章中解释了环结，所以在这里我们不会详细介绍。我们使用了上一章的确切代码，并添加了一个单一的菜单选项，您可以使用它将渲染的网格转换为`THREE.PointCloud`。您可以在本章的源代码中找到示例（`10-create-particle-system-from-model.html`）。以下截图显示了示例：

![从高级几何创建 THREE.PointCloud](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_07_12.jpg)

在前面的截图中，您可以看到用于生成环结的每个顶点都被用作粒子。在这个例子中，我们添加了一个漂亮的材质，基于 HTML 画布，以创建这种发光效果。我们只会看一下创建材质和粒子系统的代码，因为在本章中我们已经讨论了其他属性：

```js
function generateSprite() {

  var canvas = document.createElement('canvas');
  canvas.width = 16;
  canvas.height = 16;

  var context = canvas.getContext('2d');
  var gradient = context.createRadialGradient(canvas.width / 2, canvas.height / 2, 0, canvas.width / 2, canvas.height / 2, canvas.width / 2);

  gradient.addColorStop(0, 'rgba(255,255,255,1)');
  gradient.addColorStop(0.2, 'rgba(0,255,255,1)');
  gradient.addColorStop(0.4, 'rgba(0,0,64,1)');
  gradient.addColorStop(1, 'rgba(0,0,0,1)');

  context.fillStyle = gradient;
  context.fillRect(0, 0, canvas.width, canvas.height);

  var texture = new THREE.Texture(canvas);
  texture.needsUpdate = true;
  return texture;
}

function createPointCloud(geom) {
  var material = new THREE.PointCloudMaterial({
    color: 0xffffff,
    size: 3,
    transparent: true,
    blending: THREE.AdditiveBlending,
    map: generateSprite()
  });

  var cloud = new THREE.PointCloud(geom, material);
  cloud.sortParticles = true;
  return cloud;
}

// use it like this
var geom = new THREE.TorusKnotGeometry(...);
var knot = createPointCloud(geom);
```

在这段代码片段中，您可以看到两个函数：`createPointCloud()`和`generateSprite()`。在第一个函数中，我们直接从提供的几何体（在本例中是一个环结）创建了一个简单的`THREE.PointCloud`对象，并使用`generateSprite()`函数设置了纹理（`map`属性）为一个发光的点（在 HTML5 画布元素上生成）。`generateSprite()`函数如下：

![从高级几何创建 THREE.PointCloud](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_07_13.jpg)

# 总结

这一章就到这里了。我们解释了粒子、精灵和粒子系统是什么，以及如何使用可用的材质来设计这些对象。在本章中，您看到了如何直接在`THREE.CanvasRenderer`和`THREE.WebGLRenderer`中使用`THREE.Sprite`。然而，如果您想创建大量的粒子，您应该使用`THREE.PointCloud`。使用`THREE.PointCloud`，所有粒子共享相同的材质，您可以通过将材质的`vertexColors`属性设置为`THREE.VertexColors`，并在用于创建`THREE.PointCloud`的`THREE.Geometry`的`colors`数组中提供颜色值来更改单个粒子的颜色。我们还展示了如何通过改变它们的位置轻松地对粒子进行动画。这对于单个`THREE.Sprite`实例和用于创建`THREE.PointCloud`的几何体的顶点是一样的。

到目前为止，我们已经根据 Three.js 提供的几何创建了网格。这对于简单的模型如球体和立方体非常有效，但当您想要创建复杂的 3D 模型时，并不是最佳方法。对于这些模型，通常会使用 3D 建模应用程序，如 Blender 或 3D Studio Max。在下一章中，您将学习如何加载和显示这些 3D 建模应用程序创建的模型。


# 第八章：创建和加载高级网格和几何

在这一章中，我们将看一下创建高级和复杂几何和网格的几种不同方法。在第五章，“学习使用几何”，和第六章，“高级几何和二进制操作”中，我们向您展示了如何使用 Three.js 的内置对象创建一些高级几何。在这一章中，我们将使用以下两种方法来创建高级几何和网格：

+   **组合和合并**：我们解释的第一种方法使用了 Three.js 的内置功能来组合和合并现有的几何。这样可以从现有对象创建新的网格和几何。

+   **从外部加载**：在本节中，我们将解释如何从外部来源加载网格和几何。例如，我们将向您展示如何使用 Blender 以 Three.js 支持的格式导出网格。

我们从*组合和合并*方法开始。使用这种方法，我们使用标准的 Three.js 分组和`THREE.Geometry.merge()`函数来创建新对象。

# 几何组合和合并

在本节中，我们将介绍 Three.js 的两个基本功能：将对象组合在一起和将多个网格合并成单个网格。我们将从将对象组合在一起开始。

## 将对象组合在一起

在之前的一些章节中，当您使用多个材质时已经看到了这一点。当您使用多个材质从几何创建网格时，Three.js 会创建一个组。您的几何的多个副本被添加到这个组中，每个副本都有自己特定的材质。这个组被返回，所以看起来像是使用多个材质的网格。然而，实际上，它是一个包含多个网格的组。

创建组非常容易。您创建的每个网格都可以包含子元素，可以使用 add 函数添加子元素。将子对象添加到组中的效果是，您可以移动、缩放、旋转和平移父对象，所有子对象也会受到影响。让我们看一个例子（`01-grouping.html`）。以下屏幕截图显示了这个例子：

![将对象组合在一起](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_01.jpg)

在这个例子中，您可以使用菜单来移动球体和立方体。如果您勾选**旋转**选项，您会看到这两个网格围绕它们的中心旋转。这并不是什么新鲜事，也不是很令人兴奋。然而，这两个对象并没有直接添加到场景中，而是作为一个组添加的。以下代码概括了这个讨论：

```js
sphere = createMesh(new THREE.SphereGeometry(5, 10, 10));
cube = createMesh(new THREE.BoxGeometry(6, 6, 6));

group = new THREE.Object3D();
group.add(sphere);
group.add(cube);

scene.add(group);
```

在这段代码片段中，您可以看到我们创建了`THREE.Object3D`。这是`THREE.Mesh`和`THREE.Scene`的基类，但本身并不包含任何内容或导致任何内容被渲染。请注意，在最新版本的 Three.js 中，引入了一个名为`THREE.Group`的新对象来支持分组。这个对象与`THREE.Object3D`对象完全相同，您可以用`new THREE.Group()`替换前面代码中的`new THREE.Object3D()`以获得相同的效果。在这个例子中，我们使用`add`函数将`sphere`和`cube`添加到这个对象，然后将它添加到`scene`中。如果您查看这个例子，您仍然可以移动立方体和球体，以及缩放和旋转这两个对象。您也可以在它们所在的组上进行这些操作。如果您查看组菜单，您会看到位置和缩放选项。您可以使用这些选项来缩放和移动整个组。这个组内部对象的缩放和位置是相对于组本身的缩放和位置的。

缩放和定位非常简单。但需要记住的一点是，当您旋转一个组时，它不会单独旋转其中的对象；它会围绕自己的中心旋转（在我们的示例中，您会围绕`group`对象的中心旋转整个组）。在这个示例中，我们使用`THREE.ArrowHelper`对象在组的中心放置了一个箭头，以指示旋转点：

```js
var arrow = new THREE.ArrowHelper(new THREE.Vector3(0, 1, 0), group.position, 10, 0x0000ff);
scene.add(arrow);
```

如果您同时选中**分组**和**旋转**复选框，组将会旋转。您会看到球体和立方体围绕组的中心旋转（由箭头指示），如下所示：

![将对象分组](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_02.jpg)

在使用组时，您仍然可以引用、修改和定位单个几何体。您需要记住的是，所有位置、旋转和平移都是相对于父对象进行的。在下一节中，我们将看看合并，您将合并多个单独的几何体，并最终得到一个单个的`THREE.Geometry`对象。

## 将多个网格合并成单个网格

在大多数情况下，使用组可以让您轻松操作和管理大量网格。然而，当您处理大量对象时，性能将成为一个问题。使用组时，您仍然在处理需要单独处理和渲染的单个对象。使用`THREE.Geometry.merge()`，您可以合并几何体并创建一个组合的几何体。在下面的示例中，您可以看到这是如何工作的，以及它对性能的影响。如果您打开`02-merging.html`示例，您会看到一个场景，其中有一组随机分布的半透明立方体。在菜单中使用滑块，您可以设置场景中立方体的数量，并通过单击**重绘**按钮重新绘制场景。根据您运行的硬件，随着立方体数量的增加，您会看到性能下降。在我们的案例中，如下截图所示，在大约 4,000 个对象时，刷新率会从正常的 60 fps 降至约 40 fps：

![将多个网格合并成单个网格](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_03.jpg)

如您所见，您可以向场景中添加的网格数量存在一定限制。不过，通常情况下，您可能不需要那么多网格，但是在创建特定游戏（例如像*Minecraft*这样的游戏）或高级可视化时，您可能需要管理大量单独的网格。使用`THREE.Geometry.merge()`，您可以解决这个问题。在查看代码之前，让我们运行相同的示例，但这次选中**合并**框。通过标记此选项，我们将所有立方体合并为单个`THREE.Geometry`，并添加该对象，如下截图所示：

![将多个网格合并成单个网格](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_04.jpg)

如您所见，我们可以轻松渲染 20,000 个立方体而不会出现性能下降。为此，我们使用以下几行代码：

```js
var geometry = new THREE.Geometry();
for (var i = 0; i < controls.numberOfObjects; i++) {
  var cubeMesh = addcube();
  cubeMesh.updateMatrix();
  geometry.merge(cubeMesh.geometry,cubeMesh.matrix);
}
scene.add(new THREE.Mesh(geometry, cubeMaterial));
```

在此代码片段中，`addCube()`函数返回`THREE.Mesh`。在较早版本的 Three.js 中，我们可以使用`THREE.GeometryUtils.merge`函数将`THREE.Mesh`对象合并到`THREE.Geometry`对象中。但在最新版本中，这个功能已经被弃用，取而代之的是`THREE.Geometry.merge`函数。为了确保合并的`THREE.Geometry`对象被正确定位和旋转，我们不仅向`merge`函数提供`THREE.Geometry`，还提供其变换矩阵。当我们将这个矩阵添加到`merge`函数时，我们合并的立方体将被正确定位。

我们这样做了 20,000 次，最后得到一个单一的几何图形，我们将其添加到场景中。如果您查看代码，您可能会看到这种方法的一些缺点。由于您得到了一个单一的几何图形，您无法为每个单独的立方体应用材质。然而，这可以通过使用`THREE.MeshFaceMaterial`来解决。然而，最大的缺点是您失去了对单个立方体的控制。如果您想要移动、旋转或缩放单个立方体，您无法做到（除非您搜索正确的面和顶点并单独定位它们）。

通过分组和合并方法，您可以使用 Three.js 提供的基本几何图形创建大型和复杂的几何图形。如果您想创建更高级的几何图形，那么使用 Three.js 提供的编程方法并不总是最佳和最简单的选择。幸运的是，Three.js 还提供了其他几种选项来创建几何图形。在下一节中，我们将看看如何从外部资源加载几何图形和网格。

## 从外部资源加载几何图形

Three.js 可以读取多种 3D 文件格式，并导入这些文件中定义的几何图形和网格。以下表格显示了 Three.js 支持的文件格式：

| 格式 | 描述 |
| --- | --- |
| JSON | Three.js 有自己的 JSON 格式，您可以用它来声明性地定义几何图形或场景。尽管这不是官方格式，但在想要重用复杂几何图形或场景时，它非常易于使用并非常方便。 |
| OBJ 或 MTL | OBJ 是由**Wavefront Technologies**首次开发的简单 3D 格式。它是最广泛采用的 3D 文件格式之一，用于定义对象的几何形状。MTL 是 OBJ 的伴随格式。在 MTL 文件中，指定了 OBJ 文件中对象的材质。Three.js 还有一个名为 OBJExporter.js 的自定义 OBJ 导出器，如果您想要从 Three.js 导出模型到 OBJ，可以使用它。 |
| Collada | Collada 是一种用于以基于 XML 的格式定义*数字资产*的格式。这也是一种被几乎所有 3D 应用程序和渲染引擎支持的广泛使用的格式。 |
| STL | **STL**代表**STereoLithography**，广泛用于快速原型制作。例如，3D 打印机的模型通常定义为 STL 文件。Three.js 还有一个名为 STLExporter.js 的自定义 STL 导出器，如果您想要从 Three.js 导出模型到 STL，可以使用它。 |
| CTM | CTM 是由**openCTM**创建的文件格式。它用作以紧凑格式存储 3D 三角形网格的格式。 |
| VTK | VTK 是由**可视化工具包**定义的文件格式，用于指定顶点和面。有两种可用格式：二进制格式和基于文本的 ASCII 格式。Three.js 仅支持基于 ASCII 的格式。 |
| AWD | AWD 是用于 3D 场景的二进制格式，最常与[`away3d.com/`](http://away3d.com/)引擎一起使用。请注意，此加载器不支持压缩的 AWD 文件。 |
| Assimp | 开放资产导入库（也称为**Assimp**）是导入各种 3D 模型格式的标准方式。使用此加载器，您可以导入使用**assimp2json**转换的大量 3D 格式的模型，有关详细信息，请访问[`github.com/acgessler/assimp2json`](https://github.com/acgessler/assimp2json)。 |
| VRML | **VRML**代表**虚拟现实建模语言**。这是一种基于文本的格式，允许您指定 3D 对象和世界。它已被 X3D 文件格式取代。Three.js 不支持加载 X3D 模型，但这些模型可以很容易地转换为其他格式。更多信息可以在[`www.x3dom.org/?page_id=532#`](http://www.x3dom.org/?page_id=532#)找到。 |
| Babylon | Babylon 是一个 3D JavaScript 游戏库。它以自己的内部格式存储模型。有关此内容的更多信息，请访问[`www.babylonjs.com/`](http://www.babylonjs.com/)。 |
| PDB | 这是一种非常专业的格式，由**蛋白质数据银行**创建，用于指定蛋白质的外观。Three.js 可以加载和可视化以这种格式指定的蛋白质。 |
| PLY | 这种格式被称为**多边形**文件格式。这通常用于存储来自 3D 扫描仪的信息。 |

在下一章中，当我们讨论动画时，我们将重新访问其中一些格式（并查看另外两种格式，MD2 和 glTF）。现在，我们从 Three.js 的内部格式开始。

## 以 Three.js JSON 格式保存和加载

你可以在 Three.js 中的两种不同场景中使用 Three.js 的 JSON 格式。你可以用它来保存和加载单个`THREE.Mesh`，或者你可以用它来保存和加载完整的场景。

### 保存和加载 THREE.Mesh

为了演示保存和加载，我们创建了一个基于`THREE.TorusKnotGeometry`的简单示例。通过这个示例，你可以创建一个环结，就像我们在第五章 *学习使用几何图形*中所做的那样，并使用**保存**按钮从**保存和加载**菜单中保存当前几何图形。对于这个例子，我们使用 HTML5 本地存储 API 进行保存。这个 API 允许我们在客户端的浏览器中轻松存储持久信息，并在以后的时间检索它（即使浏览器已关闭并重新启动）。

我们将查看`03-load-save-json-object.html`示例。以下截图显示了这个例子：

![保存和加载 THREE.Mesh](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_05.jpg)

从 Three.js 中以 JSON 格式导出非常容易，不需要你包含任何额外的库。要将`THREE.Mesh`导出为 JSON，你需要做的唯一的事情是：

```js
var result = knot.toJSON();
localStorage.setItem("json", JSON.stringify(result));
```

在保存之前，我们首先将`toJSON`函数的结果，一个 JavaScript 对象，使用`JSON.stringify`函数转换为字符串。这将产生一个看起来像这样的 JSON 字符串（大部分顶点和面都被省略了）：

```js
{
  "metadata": {
    "version": 4.3,
    "type": "Object",
    "generator": "ObjectExporter"
  },
  "geometries": [{
    "uuid": "53E1B290-3EF3-4574-BD68-E65DFC618BA7",
    "type": "TorusKnotGeometry",
    "radius": 10,
    "tube": 1,
    "radialSegments": 64,
    "tubularSegments": 8,
    "p": 2,
    "q": 3,
    "heightScale": 1
  }],
  ...
}
```

正如你所看到的，Three.js 保存了关于`THREE.Mesh`的所有信息。要使用 HTML5 本地存储 API 保存这些信息，我们只需要调用`localStorage.setItem`函数。第一个参数是键值（`json`），我们稍后可以使用它来检索我们作为第二个参数传递的信息。

从本地存储中加载`THREE.Mesh`回到 Three.js 也只需要几行代码，如下所示：

```js
var json = localStorage.getItem("json");

if (json) {
  var loadedGeometry = JSON.parse(json);
  var loader = new THREE.ObjectLoader();

  loadedMesh = loader.parse(loadedGeometry);
  loadedMesh.position.x -= 50;
  scene.add(loadedMesh);
}
```

在这里，我们首先使用我们保存的名称（在本例中为`json`）从本地存储中获取 JSON。为此，我们使用 HTML5 本地存储 API 提供的`localStorage.getItem`函数。接下来，我们需要将字符串转换回 JavaScript 对象（`JSON.parse`），并将 JSON 对象转换回`THREE.Mesh`。Three.js 提供了一个名为`THREE.ObjectLoader`的辅助对象，你可以使用它将 JSON 转换为`THREE.Mesh`。在这个例子中，我们使用加载器上的`parse`方法直接解析 JSON 字符串。加载器还提供了一个`load`函数，你可以传入包含 JSON 定义的文件的 URL。

正如你在这里看到的，我们只保存了`THREE.Mesh`。我们失去了其他一切。如果你想保存完整的场景，包括灯光和相机，你可以使用`THREE.SceneExporter`。

### 保存和加载场景

如果你想保存完整的场景，你可以使用与我们在前一节中看到的相同方法来保存几何图形。`04-load-save-json-scene.html`是一个展示这一点的工作示例。以下截图显示了这个例子：

![保存和加载场景](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_06.jpg)

在这个例子中，您有三个选项：**exportScene**，**clearScene**和**importScene**。使用**exportScene**，场景的当前状态将保存在浏览器的本地存储中。要测试导入功能，您可以通过单击**clearScene**按钮来删除场景，并使用**importScene**按钮从本地存储加载它。执行所有这些操作的代码非常简单，但在使用之前，您必须从 Three.js 分发中导入所需的导出器和加载器（查看`examples/js/exporters`和`examples/js/loaders`目录）：

```js
<script type="text/javascript" src="../libs/SceneLoader.js"></script>
<script type="text/javascript" src="../libs/SceneExporter.js"></script>
```

在页面中包含这些 JavaScript 导入后，您可以使用以下代码导出一个场景：

```js
var exporter = new THREE.SceneExporter();
var sceneJson = JSON.stringify(exporter.parse(scene));
localStorage.setItem('scene', sceneJson);
```

这种方法与我们在上一节中使用的方法完全相同，只是这次我们使用`THREE.SceneExporter()`来导出完整的场景。生成的 JSON 如下：

```js
{
  "metadata": {
    "formatVersion": 3.2,
    "type": "scene",
    "generatedBy": "SceneExporter",
    "objects": 5,
    "geometries": 3,
    "materials": 3,
    "textures": 0
  },
  "urlBaseType": "relativeToScene", "objects": {
    "Object_78B22F27-C5D8-46BF-A539-A42207DDDCA8": {
      "geometry": "Geometry_5",
      "material": "Material_1",
      "position": [15, 0, 0],
      "rotation": [-1.5707963267948966, 0, 0],
      "scale": [1, 1, 1],
      "visible": true
    }
    ... // removed all the other objects for legibility
  },
  "geometries": {
    "Geometry_8235FC68-64F0-45E9-917F-5981B082D5BC": {
      "type": "cube",
      "width": 4,
      "height": 4,
      "depth": 4,
      "widthSegments": 1,
      "heightSegments": 1,
      "depthSegments": 1
    }
    ... // removed all the other objects for legibility
  }
  ... other scene information like textures
```

当您再次加载此 JSON 时，Three.js 会按原样重新创建对象。加载场景的方法如下：

```js
var json = (localStorage.getItem('scene'));
var sceneLoader = new THREE.SceneLoader();
sceneLoader.parse(JSON.parse(json), function(e) {
  scene = e.scene;
}, '.');
```

传递给加载程序的最后一个参数（`'.'`）定义了相对 URL。例如，如果您有使用纹理的材质（例如，外部图像），那么这些材质将使用此相对 URL 进行检索。在这个例子中，我们不使用纹理，所以只需传入当前目录。与`THREE.ObjectLoader`一样，您也可以使用`load`函数从 URL 加载 JSON 文件。

有许多不同的 3D 程序可以用来创建复杂的网格。一个流行的开源程序是 Blender（[www.blender.org](http://www.blender.org)）。Three.js 有一个针对 Blender（以及 Maya 和 3D Studio Max）的导出器，直接导出到 Three.js 的 JSON 格式。在接下来的部分中，我们将指导您配置 Blender 以使用此导出器，并向您展示如何在 Blender 中导出复杂模型并在 Three.js 中显示它。

## 使用 Blender

在开始配置之前，我们将展示我们将要实现的结果。在下面的截图中，您可以看到一个简单的 Blender 模型，我们使用 Three.js 插件导出，并在 Three.js 中使用`THREE.JSONLoader`导入：

![使用 Blender](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_07.jpg)

### 在 Blender 中安装 Three.js 导出器

要让 Blender 导出 Three.js 模型，我们首先需要将 Three.js 导出器添加到 Blender 中。以下步骤适用于 Mac OS X，但在 Windows 和 Linux 上基本相同。您可以从[www.blender.org](http://www.blender.org)下载 Blender，并按照特定于平台的安装说明进行操作。安装后，您可以添加 Three.js 插件。首先，使用终端窗口找到 Blender 安装的`addons`目录：

![在 Blender 中安装 Three.js 导出器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_08.jpg)

在我的 Mac 上，它位于这里：`./blender.app/Contents/MacOS/2.70/scripts/addons`。对于 Windows，该目录可以在以下位置找到：`C:\Users\USERNAME\AppData\Roaming\Blender Foundation\Blender\2.7X\scripts\addons`。对于 Linux，您可以在此处找到此目录：`/home/USERNAME/.config/blender/2.7X/scripts/addons`。

接下来，您需要获取 Three.js 分发并在本地解压缩。在此分发中，您可以找到以下文件夹：`utils/exporters/blender/2.65/scripts/addons/`。在此目录中，有一个名为`io_mesh_threejs`的单个子目录。将此目录复制到您的 Blender 安装的`addons`文件夹中。

现在，我们只需要启动 Blender 并启用导出器。在 Blender 中，打开**Blender 用户首选项**（**文件** | **用户首选项**）。在打开的窗口中，选择**插件**选项卡，并在搜索框中输入`three`。这将显示以下屏幕：

![在 Blender 中安装 Three.js 导出器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_09.jpg)

此时，找到了 Three.js 插件，但它仍然被禁用。勾选右侧的小复选框，Three.js 导出器将被启用。最后，为了检查一切是否正常工作，打开**文件** | **导出**菜单选项，您将看到 Three.js 列为导出选项。如下截图所示：

![在 Blender 中安装 Three.js 导出器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_10.jpg)

安装了插件后，我们可以加载我们的第一个模型。

### 从 Blender 加载和导出模型

例如，我们在`assets/models`文件夹中添加了一个名为`misc_chair01.blend`的简单 Blender 模型，您可以在本书的源文件中找到。在本节中，我们将加载此模型，并展示将此模型导出到 Three.js 所需的最小步骤。

首先，我们需要在 Blender 中加载此模型。使用**文件** | **打开**并导航到包含`misc_chair01.blend`文件的文件夹。选择此文件，然后单击**打开**。这将显示一个看起来有点像这样的屏幕：

![从 Blender 加载和导出模型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_11.jpg)

将此模型导出到 Three.js JSON 格式非常简单。从**文件**菜单中，打开**导出** | **Three.js**，输入导出文件的名称，然后选择**导出 Three.js**。这将创建一个 Three.js 理解的 JSON 文件。此文件的部分内容如下所示：

```js
{

  "metadata" :
  {
    "formatVersion" : 3.1,
    "generatedBy"   : "Blender 2.7 Exporter",
    "vertices"      : 208,
    "faces"         : 124,
    "normals"       : 115,
    "colors"        : 0,
    "uvs"           : [270,151],
    "materials"     : 1,
    "morphTargets"  : 0,
    "bones"         : 0
  },
...
```

然而，我们还没有完全完成。在前面的截图中，您可以看到椅子包含木纹理。如果您查看 JSON 导出，您会看到椅子的导出也指定了一个材质，如下所示：

```js
"materials": [{
  "DbgColor": 15658734,
  "DbgIndex": 0,
  "DbgName": "misc_chair01",
  "blending": "NormalBlending",
  "colorAmbient": [0.53132, 0.25074, 0.147919],
  "colorDiffuse": [0.53132, 0.25074, 0.147919],
  "colorSpecular": [0.0, 0.0, 0.0],
  "depthTest": true,
  "depthWrite": true,
  "mapDiffuse": "misc_chair01_col.jpg",
  "mapDiffuseWrap": ["repeat", "repeat"],
  "shading": "Lambert",
  "specularCoef": 50,
  "transparency": 1.0,
  "transparent": false,
  "vertexColors": false
}],
```

此材质为`mapDiffuse`属性指定了一个名为`misc_chair01_col.jpg`的纹理。因此，除了导出模型，我们还需要确保 Three.js 也可以使用纹理文件。幸运的是，我们可以直接从 Blender 保存这个纹理。

在 Blender 中，打开**UV/Image Editor**视图。您可以从**文件**菜单选项的左侧下拉菜单中选择此视图。这将用以下内容替换顶部菜单：

![从 Blender 加载和导出模型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_12.jpg)

确保选择要导出的纹理，我们的情况下是`misc_chair_01_col.jpg`（您可以使用小图标选择不同的纹理）。接下来，单击**图像**菜单，使用**另存为图像**菜单选项保存图像。将其保存在与模型相同的文件夹中，使用 JSON 导出文件中指定的名称。此时，我们已经准备好将模型加载到 Three.js 中。

此时将加载到 Three.js 中的代码如下：

```js
var loader = new THREE.JSONLoader();
loader.load('../assets/models/misc_chair01.js', function (geometry, mat) {
  mesh = new THREE.Mesh(geometry, mat[0]);

  mesh.scale.x = 15;
  mesh.scale.y = 15;
  mesh.scale.z = 15;

  scene.add(mesh);

}, '../assets/models/');
```

我们之前已经见过`JSONLoader`，但这次我们使用`load`函数而不是`parse`函数。在此函数中，我们指定要加载的 URL（指向导出的 JSON 文件），一个在对象加载时调用的回调，以及纹理所在的位置`../assets/models/`（相对于页面）。此回调接受两个参数：`geometry`和`mat`。`geometry`参数包含模型，`mat`参数包含材质对象的数组。我们知道只有一个材质，因此当我们创建`THREE.Mesh`时，我们直接引用该材质。如果您打开`05-blender-from-json.html`示例，您可以看到我们刚刚从 Blender 导出的椅子。

使用 Three.js 导出器并不是从 Blender 加载模型到 Three.js 的唯一方法。Three.js 理解许多 3D 文件格式，而 Blender 可以导出其中的一些格式。然而，使用 Three.js 格式非常简单，如果出现问题，通常可以很快找到。 

在下一节中，我们将看一下 Three.js 支持的一些格式，并展示一个基于 Blender 的 OBJ 和 MTL 文件格式的示例。

## 从 3D 文件格式导入

在本章的开头，我们列出了 Three.js 支持的一些格式。在本节中，我们将快速浏览一些这些格式的例子。请注意，对于所有这些格式，都需要包含一个额外的 JavaScript 文件。您可以在 Three.js 分发的`examples/js/loaders`目录中找到所有这些文件。

### OBJ 和 MTL 格式

OBJ 和 MTL 是配套格式，经常一起使用。OBJ 文件定义了几何图形，而 MTL 文件定义了所使用的材质。OBJ 和 MTL 都是基于文本的格式。OBJ 文件的一部分看起来像这样：

```js
v -0.032442 0.010796 0.025935
v -0.028519 0.013697 0.026201
v -0.029086 0.014533 0.021409
usemtl Material
s 1
f 2731 2735 2736 2732
f 2732 2736 3043 3044
```

MTL 文件定义了材质，如下所示：

```js
newmtl Material
Ns 56.862745
Ka 0.000000 0.000000 0.000000
Kd 0.360725 0.227524 0.127497
Ks 0.010000 0.010000 0.010000
Ni 1.000000
d 1.000000
illum 2
```

Three.js 对 OBJ 和 MTL 格式有很好的理解，并且也受到 Blender 的支持。因此，作为一种替代方案，您可以选择以 OBJ/MTL 格式而不是 Three.js JSON 格式从 Blender 中导出模型。Three.js 有两种不同的加载器可供使用。如果您只想加载几何图形，可以使用`OBJLoader`。我们在我们的例子（`06-load-obj.html`）中使用了这个加载器。以下截图显示了这个例子：

![OBJ 和 MTL 格式](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_13.jpg)

要在 Three.js 中导入这个模型，您必须添加 OBJLoader JavaScript 文件：

```js
<script type="text/javascript" src="../libs/OBJLoader.js"></script>
```

像这样导入模型：

```js
var loader = new THREE.OBJLoader();
loader.load('../assets/models/pinecone.obj', function (loadedMesh) {
  var material = new THREE.MeshLambertMaterial({color: 0x5C3A21});

  // loadedMesh is a group of meshes. For
  // each mesh set the material, and compute the information
  // three.js needs for rendering.
  loadedMesh.children.forEach(function (child) {
    child.material = material;
    child.geometry.computeFaceNormals();
    child.geometry.computeVertexNormals();
  });

  mesh = loadedMesh;
  loadedMesh.scale.set(100, 100, 100);
  loadedMesh.rotation.x = -0.3;
  scene.add(loadedMesh);
});
```

在这段代码中，我们使用`OBJLoader`从 URL 加载模型。一旦模型加载完成，我们提供的回调就会被调用，并且我们将模型添加到场景中。

### 提示

通常，一个很好的第一步是将回调的响应打印到控制台上，以了解加载的对象是如何构建的。通常情况下，使用这些加载器，几何图形或网格会作为一组组的层次结构返回。了解这一点会使得更容易放置和应用正确的材质，并采取任何其他额外的步骤。此外，查看一些顶点的位置来确定是否需要缩放模型的大小以及摄像机的位置。在这个例子中，我们还调用了`computeFaceNormals`和`computeVertexNormals`。这是为了确保所使用的材质（`THREE.MeshLambertMaterial`）能够正确渲染。

下一个例子（`07-load-obj-mtl.html`）使用`OBJMTLLoader`加载模型并直接分配材质。以下截图显示了这个例子：

![OBJ 和 MTL 格式](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_14.jpg)

首先，我们需要将正确的加载器添加到页面上：

```js
<script type="text/javascript" src="../libs/OBJLoader.js"></script>
<script type="text/javascript" src="../libs/MTLLoader.js"></script>
<script type="text/javascript" src="../libs/OBJMTLLoader.js"></script>
```

我们可以这样从 OBJ 和 MTL 文件加载模型：

```js
var loader = new THREE.OBJMTLLoader();
loader.load('../assets/models/butterfly.obj', '../assets/models/butterfly.mtl', function(object) {
  // configure the wings
  var wing2 = object.children[5].children[0];
  var wing1 = object.children[4].children[0];

  wing1.material.opacity = 0.6;
  wing1.material.transparent = true;
  wing1.material.depthTest = false;
  wing1.material.side = THREE.DoubleSide;

  wing2.material.opacity = 0.6;
  wing2.material.depthTest = false;
  wing2.material.transparent = true;
  wing2.material.side = THREE.DoubleSide;

  object.scale.set(140, 140, 140);
  mesh = object;
  scene.add(mesh);

  mesh.rotation.x = 0.2;
  mesh.rotation.y = -1.3;
});
```

在查看代码之前，首先要提到的是，如果您收到了一个 OBJ 文件、一个 MTL 文件和所需的纹理文件，您需要检查 MTL 文件如何引用纹理。这些应该是相对于 MTL 文件的引用，而不是绝对路径。代码本身与我们为`THREE.ObjLoader`看到的代码并没有太大的不同。我们指定了 OBJ 文件的位置、MTL 文件的位置以及在加载模型时要调用的函数。在这种情况下，我们使用的模型是一个复杂的模型。因此，我们在回调中设置了一些特定的属性来修复一些渲染问题，如下所示：

+   源文件中的不透明度设置不正确，导致翅膀不可见。因此，为了解决这个问题，我们自己设置了`opacity`和`transparent`属性。

+   默认情况下，Three.js 只渲染对象的一面。由于我们从两个方向观察翅膀，我们需要将`side`属性设置为`THREE.DoubleSide`值。

+   当需要将翅膀渲染在彼此之上时，会导致一些不必要的伪影。我们通过将`depthTest`属性设置为`false`来解决这个问题。这对性能有轻微影响，但通常可以解决一些奇怪的渲染伪影。

但是，正如您所看到的，您可以轻松地直接将复杂的模型加载到 Three.js 中，并在浏览器中实时渲染它们。不过，您可能需要微调一些材质属性。

### 加载 Collada 模型

Collada 模型（扩展名为`.dae`）是另一种非常常见的格式，用于定义场景和模型（以及我们将在下一章中看到的动画）。在 Collada 模型中，不仅定义了几何形状，还定义了材料。甚至可以定义光源。

要加载 Collada 模型，您必须采取与 OBJ 和 MTL 模型几乎相同的步骤。首先要包括正确的加载程序：

```js
<script type="text/javascript" src="../libs/ColladaLoader.js"></script>
```

在这个例子中，我们将加载以下模型：

![加载 Collada 模型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_15.jpg)

再次加载卡车模型非常简单：

```js
var mesh;
loader.load("../assets/models/dae/Truck_dae.dae", function (result) {
  mesh = result.scene.children[0].children[0].clone();
  mesh.scale.set(4, 4, 4);
  scene.add(mesh);
});
```

这里的主要区别是返回给回调的对象的结果。`result`对象具有以下结构：

```js
var result = {

  scene: scene,
  morphs: morphs,
  skins: skins,
  animations: animData,
  dae: {
    ...
  }
};
```

在本章中，我们对`scene`参数中的对象感兴趣。我首先将场景打印到控制台上，看看我感兴趣的网格在哪里，即`result.scene.children[0].children[0]`。剩下的就是将其缩放到合理的大小并添加到场景中。对于这个特定的例子，最后需要注意的是，当我第一次加载这个模型时，材料没有正确渲染。原因是纹理使用了`.tga`格式，这在 WebGL 中不受支持。为了解决这个问题，我不得不将`.tga`文件转换为`.png`并编辑`.dae`模型的 XML，指向这些`.png`文件。

正如你所看到的，对于大多数复杂模型，包括材料，通常需要采取一些额外的步骤才能获得所需的结果。通过仔细观察材料的配置（使用`console.log()`）或用测试材料替换它们，问题通常很容易发现。

### 加载 STL、CTM、VTK、AWD、Assimp、VRML 和 Babylon 模型

我们将快速浏览这些文件格式，因为它们都遵循相同的原则：

1.  在网页中包括`[NameOfFormat]Loader.js`。

1.  使用`[NameOfFormat]Loader.load()`加载 URL。

1.  检查回调的响应格式是什么样的，并渲染结果。

我们已经为所有这些格式包含了一个示例：

| 名称 | 示例 | 截图 |
| --- | --- | --- |
| STL | `08-load-STL.html` | ![加载 STL、CTM、VTK、AWD、Assimp、VRML 和 Babylon 模型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_16.jpg) |
| CTM | `09-load-CTM.html` | ![加载 STL、CTM、VTK、AWD、Assimp、VRML 和 Babylon 模型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_17.jpg) |
| VTK | `10-load-vtk.html` | ![加载 STL、CTM、VTK、AWD、Assimp、VRML 和 Babylon 模型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_18.jpg) |
| AWD | `11-load-awd.html` | ![加载 STL、CTM、VTK、AWD、Assimp、VRML 和 Babylon 模型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_19.jpg) |
| Assimp | `12-load-assimp.html` | ![加载 STL、CTM、VTK、AWD、Assimp、VRML 和 Babylon 模型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_20.jpg) |
| VRML | `13-load-vrml.html` | ![加载 STL、CTM、VTK、AWD、Assimp、VRML 和 Babylon 模型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_21.jpg) |
| Babylon | 巴比伦加载程序与表中的其他加载程序略有不同。使用此加载程序，您不会加载单个`THREE.Mesh`或`THREE.Geometry`实例，而是加载一个完整的场景，包括灯光。`14-load-babylon.html` | ![加载 STL、CTM、VTK、AWD、Assimp、VRML 和 Babylon 模型](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_22.jpg) |

如果您查看这些示例的源代码，您可能会发现，对于其中一些示例，我们需要在模型正确渲染之前更改一些材料属性或进行一些缩放。我们之所以需要这样做，是因为模型是在其外部应用程序中创建的方式不同，给它不同的尺寸和分组，而不是我们在 Three.js 中通常使用的。

我们几乎展示了所有支持的文件格式。在接下来的两个部分中，我们将采取不同的方法。首先，我们将看看如何从蛋白质数据银行（PDB 格式）渲染蛋白质，最后我们将使用 PLY 格式中定义的模型创建一个粒子系统。

### 显示来自蛋白质数据银行的蛋白质

蛋白质数据银行（[www.rcsb.org](http://www.rcsb.org)）包含许多不同分子和蛋白质的详细信息。除了这些蛋白质的解释外，它们还提供了以 PDB 格式下载这些分子结构的方法。Three.js 提供了一个用于 PDB 格式文件的加载器。在本节中，我们将举例说明如何解析 PDB 文件并使用 Three.js 进行可视化。

加载新文件格式时，我们总是需要在 Three.js 中包含正确的加载器，如下所示：

```js
<script type="text/javascript" src="../libs/PDBLoader.js"></script>
```

包含此加载器后，我们将创建以下分子描述的 3D 模型（请参阅`15-load-ptb.html`示例）：

![显示来自蛋白质数据银行的蛋白质](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_23.jpg)

加载 PDB 文件的方式与之前的格式相同，如下所示：

```js
var loader = new THREE.PDBLoader();
var group = new THREE.Object3D();
loader.load("../assets/models/diamond.pdb", function (geometry, geometryBonds) {
  var i = 0;

  geometry.vertices.forEach(function (position) {
    var sphere = new THREE.SphereGeometry(0.2);
    var material = new THREE.MeshPhongMaterial({color: geometry.colors[i++]});
    var mesh = new THREE.Mesh(sphere, material);
    mesh.position.copy(position);
    group.add(mesh);
  });

  for (var j = 0; j < geometryBonds.vertices.length; j += 2) {
    var path = new THREE.SplineCurve3([geometryBonds.vertices[j], geometryBonds.vertices[j + 1]]);
    var tube = new THREE.TubeGeometry(path, 1, 0.04)
    var material = new THREE.MeshPhongMaterial({color: 0xcccccc});
    var mesh = new THREE.Mesh(tube, material);
    group.add(mesh);
  }
  console.log(geometry);
  console.log(geometryBonds);

  scene.add(group);
});
```

如您从此示例中所见，我们实例化`THREE.PDBLoader`，传入我们想要加载的模型文件，并提供一个在加载模型时调用的回调函数。对于这个特定的加载器，回调函数被调用时带有两个参数：`geometry`和`geometryBonds`。`geometry`参数提供的顶点包含了单个原子的位置，而`geometryBounds`用于原子之间的连接。

对于每个顶点，我们创建一个颜色也由模型提供的球体：

```js
var sphere = new THREE.SphereGeometry(0.2);
var material = new THREE.MeshPhongMaterial({color: geometry.colors[i++]});
var mesh = new THREE.Mesh(sphere, material);
mesh.position.copy(position);
group.add(mesh)
```

每个连接都是这样定义的：

```js
var path = new THREE.SplineCurve3([geometryBonds.vertices[j], geometryBonds.vertices[j + 1]]);
var tube = new THREE.TubeGeometry(path, 1, 0.04)
var material = new THREE.MeshPhongMaterial({color: 0xcccccc});
var mesh = new THREE.Mesh(tube, material);
group.add(mesh);
```

对于连接，我们首先使用`THREE.SplineCurve3`对象创建一个 3D 路径。这个路径被用作`THREE.Tube`的输入，并用于创建原子之间的连接。所有连接和原子都被添加到一个组中，然后将该组添加到场景中。您可以从蛋白质数据银行下载许多模型。

以下图片显示了一颗钻石的结构：

![显示来自蛋白质数据银行的蛋白质](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_24.jpg)

### 从 PLY 模型创建粒子系统

与其他格式相比，使用 PLY 格式并没有太大的不同。您需要包含加载器，提供回调函数，并可视化模型。然而，在最后一个示例中，我们将做一些不同的事情。我们将使用此模型的信息创建一个粒子系统，而不是将模型呈现为网格（请参阅`15-load-ply.html`示例）。以下截图显示了这个示例：

![从 PLY 模型创建粒子系统](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_08_25.jpg)

渲染上述截图的 JavaScript 代码实际上非常简单，如下所示：

```js
var loader = new THREE.PLYLoader();
var group = new THREE.Object3D();
loader.load("../assets/models/test.ply", function (geometry) {
  var material = new THREE.PointCloudMaterial({
    color: 0xffffff,
    size: 0.4,
    opacity: 0.6,
    transparent: true,
    blending: THREE.AdditiveBlending,
    map: generateSprite()
  });

  group = new THREE.PointCloud(geometry, material);
  group.sortParticles = true;

  scene.add(group);
});
```

如您所见，我们使用`THREE.PLYLoader`来加载模型。回调函数返回`geometry`，我们将这个几何体作为`THREE.PointCloud`的输入。我们使用的材质与上一章中最后一个示例中使用的材质相同。如您所见，使用 Three.js，很容易将来自各种来源的模型组合在一起，并以不同的方式呈现它们，只需几行代码。

# 总结

在 Three.js 中使用外部来源的模型并不难。特别是对于简单的模型，您只需要采取几个简单的步骤。在处理外部模型或使用分组和合并创建模型时，有几件事情需要记住。首先，您需要记住的是，当您将对象分组时，它们仍然作为单独的对象可用。应用于父对象的变换也会影响子对象，但您仍然可以单独变换子对象。除了分组，您还可以将几何体合并在一起。通过这种方法，您会失去单独的几何体，并获得一个新的单一几何体。当您需要渲染成千上万个几何体并且遇到性能问题时，这种方法尤其有用。

Three.js 支持大量外部格式。在使用这些格式加载器时，最好查看源代码并记录回调中收到的信息。这将帮助您了解您需要采取的步骤，以获得正确的网格并将其设置到正确的位置和比例。通常，当模型显示不正确时，这是由其材质设置引起的。可能是使用了不兼容的纹理格式，不正确地定义了不透明度，或者格式包含了不正确的链接到纹理图像。通常最好使用测试材质来确定模型本身是否被正确加载，并记录加载的材质到 JavaScript 控制台以检查意外的值。还可以导出网格和场景，但请记住，Three.js 的`GeometryExporter`、`SceneExporter`和`SceneLoader`仍在进行中。

在本章和前几章中使用的模型大多是静态模型。它们不是动画的，不会四处移动，也不会改变形状。在下一章中，您将学习如何为模型添加动画，使其栩栩如生。除了动画，下一章还将解释 Three.js 提供的各种摄像机控制。通过摄像机控制，您可以在场景中移动、平移和旋转摄像机。
