# Three.js 学习手册（三）

> 原文：[`zh.annas-archive.org/md5/5001B8D716B9182B26C655FCB6BE8F50`](https://zh.annas-archive.org/md5/5001B8D716B9182B26C655FCB6BE8F50)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：动画和移动相机

在前几章中，我们看到了一些简单的动画，但没有太复杂的。在第一章中，*使用 Three.js 创建您的第一个 3D 场景*，我们介绍了基本的渲染循环，在接下来的章节中，我们使用它来旋转一些简单的对象，并展示了一些其他基本的动画概念。在本章中，我们将更详细地了解 Three.js 如何支持动画。我们将详细讨论以下四个主题：

+   基本动画

+   移动相机

+   变形和皮肤

+   加载外部动画

我们从动画背后的基本概念开始。

# 基本动画

在我们看例子之前，让我们快速回顾一下在第一章中展示的渲染循环。为了支持动画，我们需要告诉 Three.js 每隔一段时间渲染一次场景。为此，我们使用标准的 HTML5 `requestAnimationFrame`功能，如下所示：

```js
render();

function render() {

  // render the scene
  renderer.render(scene, camera);
  // schedule the next rendering using requestAnimationFrame
  requestAnimationFrame(render);
}
```

使用这段代码，我们只需要在初始化场景完成后一次调用`render()`函数。在`render()`函数本身中，我们使用`requestAnimationFrame`来安排下一次渲染。这样，浏览器会确保`render()`函数以正确的间隔被调用（通常大约每秒 60 次）。在`requestAnimationFrame`添加到浏览器之前，使用`setInterval(function, interval)`或`setTimeout(function, interval)`。这些会在每个设置的间隔调用指定的函数。这种方法的问题在于它不考虑其他正在进行的事情。即使您的动画没有显示或在隐藏的标签中，它仍然被调用并且仍在使用资源。另一个问题是，这些函数在被调用时更新屏幕，而不是在浏览器最佳时机，这意味着更高的 CPU 使用率。使用`requestAnimationFrame`，我们不告诉浏览器何时需要更新屏幕；我们要求浏览器在最合适的时机运行提供的函数。通常，这会导致大约 60fps 的帧速率。使用`requestAnimationFrame`，您的动画将运行得更顺畅，对 CPU 和 GPU 更友好，而且您不必担心自己的时间问题。

## 简单动画

使用这种方法，我们可以通过改变它们的旋转、缩放、位置、材质、顶点、面和您能想象到的任何其他东西来非常容易地对对象进行动画处理。在下一个渲染循环中，Three.js 将渲染更改的属性。一个非常简单的例子，基于我们在第一章中已经看到的一个例子，可以在`01-basic-animation.html`中找到。以下截图显示了这个例子：

![简单动画](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_01.jpg)

这个渲染循环非常简单。只需改变相关网格的属性，Three.js 会处理其余的。我们是这样做的：

```js
function render() {
  cube.rotation.x += controls.rotationSpeed;
  cube.rotation.y += controls.rotationSpeed;
  cube.rotation.z += controls.rotationSpeed;

  step += controls.bouncingSpeed;
  sphere.position.x = 20 + ( 10 * (Math.cos(step)));
  sphere.position.y = 2 + ( 10 * Math.abs(Math.sin(step)));

  scalingStep += controls.scalingSpeed;
  var scaleX = Math.abs(Math.sin(scalingStep / 4));
  var scaleY = Math.abs(Math.cos(scalingStep / 5));
  var scaleZ = Math.abs(Math.sin(scalingStep / 7));
  cylinder.scale.set(scaleX, scaleY, scaleZ);

  renderer.render(scene, camera);
  requestAnimationFrame(render);
}
```

这里没有什么特别的，但它很好地展示了我们在本书中讨论的基本动画背后的概念。在下一节中，我们将快速地进行一个侧步。除了动画，另一个重要的方面是，当在更复杂的场景中使用 Three.js 时，您将很快遇到的一个方面是使用鼠标在屏幕上选择对象的能力。

## 选择对象

尽管与动画没有直接关系，但由于我们将在本章中研究相机和动画，这是对本章中解释的主题的一个很好的补充。我们将展示如何使用鼠标从场景中选择对象。在我们查看示例之前，我们将首先看看所需的代码：

```js
var projector = new THREE.Projector();

function onDocumentMouseDown(event) {
  var vector = new THREE.Vector3(event.clientX / window.innerWidth ) * 2 - 1, -( event.clientY / window.innerHeight ) * 2 + 1, 0.5);
  vector = vector.unproject(camera);

  var raycaster = new THREE.Raycaster(camera.position, vector.sub(camera.position).normalize());

  var intersects = raycaster.intersectObjects([sphere, cylinder, cube]);

  if (intersects.length > 0) {
    intersects[ 0 ].object.material.transparent = true;
    intersects[ 0 ].object.material.opacity = 0.1;
  }
}
```

在这段代码中，我们使用`THREE.Projector`和`THREE.Raycaster`来确定我们是否点击了特定的对象。当我们点击屏幕时会发生以下情况：

1.  首先，根据我们在屏幕上点击的位置创建了`THREE.Vector3`。

1.  接下来，使用`vector.unproject`函数，我们将屏幕上的点击位置转换为我们 Three.js 场景中的坐标。换句话说，我们从屏幕坐标转换为世界坐标。

1.  接下来，我们创建`THREE.Raycaster`。使用`THREE.Raycaster`，我们可以在场景中发射射线。在这种情况下，我们从相机的位置（`camera.position`）发射射线到我们在场景中点击的位置。

1.  最后，我们使用`raycaster.intersectObjects`函数来确定射线是否击中了提供的任何对象。

最终步骤的结果包含了被射线击中的任何对象的信息。提供了以下信息：

```js
distance: 49.9047088522448
face: THREE.Face3
faceIndex: 4
object: THREE.Mesh
point: THREE.Vector3
```

被点击的网格是对象，`face`和`faceIndex`指向被选中的网格的面。`distance`值是从相机到点击对象的距离，`point`是点击网格的确切位置。您可以在`02-selecting-objects.html`示例中测试这一点。您点击的任何对象都将变为透明，并且选择的详细信息将被打印到控制台。

如果您想看到发射的射线路径，可以从菜单中启用`showRay`属性。以下屏幕截图显示了用于选择蓝色球体的射线：

![选择对象](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_02.jpg)

现在我们完成了这个小插曲，让我们回到我们的动画中。到目前为止，我们已经在渲染循环中改变了属性以使对象动画化。在下一节中，我们将看一下一个小型库，它可以更轻松地定义动画。

## 使用 Tween.js 进行动画

Tween.js 是一个小型的 JavaScript 库，您可以从[`github.com/sole/tween.js/`](https://github.com/sole/tween.js/)下载，并且您可以使用它来轻松定义属性在两个值之间的过渡。所有开始和结束值之间的中间点都为您计算。这个过程称为**缓动**。

例如，您可以使用这个库来在 10 秒内将网格的*x*位置从 10 改变为 3，如下所示：

```js
var tween = new TWEEN.Tween({x: 10}).to({x: 3}, 10000).easing(TWEEN.Easing.Elastic.InOut).onUpdate( function () {
  // update the mesh
})
```

在这个例子中，我们创建了`TWEEN.Tween`。这个缓动将确保*x*属性在 10,000 毫秒的时间内从 10 改变为 3。Tween.js 还允许您定义属性随时间如何改变。这可以使用线性、二次或其他任何可能性来完成（请参阅[`sole.github.io/tween.js/examples/03_graphs.html`](http://sole.github.io/tween.js/examples/03_graphs.html)获取完整的概述）。随时间值的变化方式称为**缓动**。使用 Tween.js，您可以使用`easing()`函数进行配置。

从 Three.js 中使用这个库非常简单。如果您打开`03-animation-tween.html`示例，您可以看到 Tween.js 库的实际效果。以下屏幕截图显示了示例的静态图像：

![使用 Tween.js 进行动画](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_03.jpg)

在这个例子中，我们从第七章中取了一个粒子云，*粒子、精灵和点云*，并将所有粒子动画化到地面上。这些粒子的位置是基于使用 Tween.js 库创建的缓动动画，如下所示：

```js
// first create the tweens
var posSrc = {pos: 1}
var tween = new TWEEN.Tween(posSrc).to({pos: 0}, 5000);
tween.easing(TWEEN.Easing.Sinusoidal.InOut);

var tweenBack = new TWEEN.Tween(posSrc).to({pos: 1}, 5000);
tweenBack.easing(TWEEN.Easing.Sinusoidal.InOut);

tween.chain(tweenBack);
tweenBack.chain(tween);

var onUpdate = function () {
  var count = 0;
  var pos = this.pos;

  loadedGeometry.vertices.forEach(function (e) {
    var newY = ((e.y + 3.22544) * pos) - 3.22544;
    particleCloud.geometry.vertices[count++].set(e.x, newY, e.z);
  });

  particleCloud.sortParticles = true;
};

tween.onUpdate(onUpdate);
tweenBack.onUpdate(onUpdate);
```

通过这段代码，我们创建了两个缓动：`tween`和`tweenBack`。第一个定义了位置属性从 1 过渡到 0 的方式，第二个则相反。通过`chain()`函数，我们将这两个缓动链接在一起，因此这些缓动在启动时将开始循环。我们在这里定义的最后一件事是`onUpdate`方法。在这个方法中，我们遍历粒子系统的所有顶点，并根据缓动提供的位置（`this.pos`）来改变它们的位置。

我们在模型加载时启动缓动，因此在以下函数的末尾，我们调用了`tween.start()`函数：

```js
var loader = new THREE.PLYLoader();
loader.load( "../assets/models/test.ply", function (geometry) {
  ...
  tween.start()
  ...
});
```

当缓动开始时，我们需要告诉 Tween.js 库何时更新它所知道的所有缓动。我们通过调用`TWEEN.update()`函数来实现这一点：

```js
function render() {
  TWEEN.update();
  webGLRenderer.render(scene, camera);
  requestAnimationFrame(render);
}
```

有了这些步骤，缓动库将负责定位点云的各个点。正如你所看到的，使用这个库比自己管理过渡要容易得多。

除了通过动画和更改对象来动画场景，我们还可以通过移动相机来动画场景。在前几章中，我们已经多次通过手动更新相机的位置来实现这一点。Three.js 还提供了许多其他更新相机的方法。

# 与相机一起工作

Three.js 有许多相机控件可供您在整个场景中控制相机。这些控件位于 Three.js 发行版中，可以在`examples/js/controls`目录中找到。在本节中，我们将更详细地查看以下控件：

| 名称 | 描述 |
| --- | --- |
| `FirstPersonControls` | 这些控件的行为类似于第一人称射击游戏中的控件。使用键盘四处移动，用鼠标四处张望。 |
| `FlyControls` | 这些是类似飞行模拟器的控件。使用键盘和鼠标进行移动和转向。 |
| `RollControls` | 这是`FlyControls`的简化版本。允许您在*z*轴周围移动和翻滚。 |
| `TrackBallControls` | 这是最常用的控件，允许您使用鼠标（或轨迹球）轻松地在场景中移动、平移和缩放。 |
| `OrbitControls` | 这模拟了围绕特定场景轨道上的卫星。这允许您使用鼠标和键盘四处移动。 |

这些控件是最有用的控件。除此之外，Three.js 还提供了许多其他控件可供使用（但本书中未进行解释）。但是，使用这些控件的方式与前表中解释的方式相同：

| 名称 | 描述 |
| --- | --- |
| `DeviceOrientationControls` | 根据设备的方向控制摄像机的移动。它内部使用 HTML 设备方向 API ([`www.w3.org/TR/orientation-event/`](http://www.w3.org/TR/orientation-event/))。 |
| `EditorControls` | 这些控件是专门为在线 3D 编辑器创建的。这是由 Three.js 在线编辑器使用的，您可以在[`threejs.org/editor/`](http://threejs.org/editor/)找到。 |
| `OculusControls` | 这些是允许您使用 Oculus Rift 设备在场景中四处张望的控件。 |
| `OrthographicTrackballControls` | 这与`TrackBallControls`相同，但专门用于与`THREE.OrthographicCamera`一起使用。 |
| `PointerLockControls` | 这是一个简单的控制，可以使用渲染场景的 DOM 元素锁定鼠标。这为简单的 3D 游戏提供了基本功能。 |
| `TransformControls` | 这是 Three.js 编辑器使用的内部控件。 |
| `VRControls` | 这是一个使用`PositionSensorVRDevice` API 来控制场景的控制器。有关此标准的更多信息，请访问[`developer.mozilla.org/en-US/docs/Web/API/Navigator.getVRDevices`](https://developer.mozilla.org/en-US/docs/Web/API/Navigator.getVRDevices)。 |

除了使用这些相机控制，您当然也可以通过设置`position`来自行移动相机，并使用`lookAt()`函数更改其指向的位置。

### 提示

如果您曾经使用过较旧版本的 Three.js，您可能会错过一个名为`THREE.PathControls`的特定相机控件。使用此控件，可以定义路径（例如使用`THREE.Spline`）并沿该路径移动相机。在最新版本的 Three.js 中，由于代码复杂性，此控件已被移除。Three.js 背后的人目前正在开发替代方案，但目前还没有可用的替代方案。

我们将首先看一下`TrackballControls`控件。

## TrackballControls

在使用`TrackballControls`之前，您首先需要将正确的 JavaScript 文件包含到您的页面中：

```js
<script type="text/javascript" src="../libs/TrackballControls.js"></script>
```

包括这些内容后，我们可以创建控件并将其附加到相机上，如下所示：

```js
var trackballControls = new THREE.TrackballControls(camera);
trackballControls.rotateSpeed = 1.0;
trackballControls.zoomSpeed = 1.0;
trackballControls.panSpeed = 1.0;
```

更新相机的位置是我们在渲染循环中做的事情，如下所示：

```js
var clock = new THREE.Clock();
function render() {
  var delta = clock.getDelta();
  trackballControls.update(delta);
  requestAnimationFrame(render);
  webGLRenderer.render(scene, camera);
}
```

在上面的代码片段中，我们看到了一个新的 Three.js 对象，`THREE.Clock`。`THREE.Clock`对象可用于精确计算特定调用或渲染循环完成所需的经过时间。您可以通过调用`clock.getDelta()`函数来实现这一点。此函数将返回此调用和上一次调用`getDelta()`之间的经过时间。要更新相机的位置，我们调用`trackballControls.update()`函数。在此函数中，我们需要提供自上次调用此更新函数以来经过的时间。为此，我们使用`THREE.Clock`对象的`getDelta()`函数。您可能想知道为什么我们不只是将帧速率（1/60 秒）传递给`update`函数。原因是，使用`requestAnimationFrame`，我们可以期望 60 fps，但这并不是保证的。根据各种外部因素，帧速率可能会发生变化。为了确保相机平稳转动和旋转，我们需要传递确切的经过时间。

此示例的工作示例可以在`04-trackball-controls-camera.html`中找到。以下截图显示了此示例的静态图像：

![TrackballControls](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_04.jpg)

您可以以以下方式控制相机：

| 控制 | 动作 |
| --- | --- |
| 左键并移动 | 围绕场景旋转和滚动相机 |
| 滚轮 | 放大和缩小 |
| 中键并移动 | 放大和缩小 |
| 右键并移动 | 在场景中移动 |

有一些属性可以用来微调相机的行为。例如，您可以通过设置`rotateSpeed`属性来设置相机旋转的速度，并通过将`noZoom`属性设置为`true`来禁用缩放。在本章中，我们不会详细介绍每个属性的作用，因为它们几乎是不言自明的。要了解可能性的完整概述，请查看`TrackballControls.js`文件的源代码，其中列出了这些属性。

## FlyControls

我们将要看的下一个控件是`FlyControls`。使用`FlyControls`，您可以使用在飞行模拟器中找到的控件在场景中飞行。示例可以在`05-fly-controls-camera.html`中找到。以下截图显示了此示例的静态图像：

![FlyControls](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_05.jpg)

启用`FlyControls`的方式与`TrackballControls`相同。首先，加载正确的 JavaScript 文件：

```js
<script type="text/javascript" src="../libs/FlyControls.js"></script>
```

接下来，我们配置控件并将其附加到相机上，如下所示：

```js
var flyControls = new THREE.FlyControls(camera);
flyControls.movementSpeed = 25;
flyControls.domElement = document.querySelector('#WebGL-output');
flyControls.rollSpeed = Math.PI / 24;
flyControls.autoForward = true;
flyControls.dragToLook = false;
```

再次，我们不会深入研究所有具体的属性。查看`FlyControls.js`文件的源代码。让我们只挑选出需要配置的属性来使控制器工作。需要正确设置的属性是`domElement`属性。该属性应指向我们渲染场景的元素。在本书的示例中，我们使用以下元素作为输出：

```js
<div id="WebGL-output"></div>
```

我们设置属性如下：

```js
flyControls.domElement = document.querySelector('#WebGL-output');
```

如果我们没有正确设置这个属性，鼠标移动会导致奇怪的行为。

你可以用`THREE.FlyControls`来控制相机：

| 控制 | 动作 |
| --- | --- |
| 左键和中键 | 开始向前移动 |
| 右鼠标按钮 | 向后移动 |
| 鼠标移动 | 四处看看 |
| W | 开始向前移动 |
| S | 向后移动 |
| A | 向左移动 |
| D | 向右移动 |
| R | 向上移动 |
| F | 向下移动 |
| 左、右、上、下箭头 | 向左、向右、向上、向下看 |
| G | 向左翻滚 |
| E | 向右翻滚 |

我们将要看的下一个控制是`THREE.RollControls`。

## RollControls

`RollControls`的行为与`FlyControls`基本相同，所以我们在这里不会详细介绍。`RollControls`可以这样创建：

```js
var rollControls = new THREE.RollControls(camera);
rollControls.movementSpeed = 25;
rollControls.lookSpeed = 3;
```

如果你想玩玩这个控制，看看`06-roll-controls-camera.html`的例子。请注意，如果你只看到一个黑屏，把鼠标移到浏览器底部，城市景观就会出现。这个相机可以用以下控制移动：

| 控制 | 动作 |
| --- | --- |
| 左鼠标按钮 | 向前移动 |
| 右鼠标按钮 | 向后移动 |
| 左、右、上、下箭头 | 向左、向右、向前、向后移动 |
| W | 向前移动 |
| A | 向左移动 |
| S | 向后移动 |
| D | 向右移动 |
| Q | 向左翻滚 |
| E | 向右翻滚 |
| R | 向上移动 |
| F | 向下移动 |

我们将要看的基本控制的最后一个是`FirstPersonControls`。

## FirstPersonControls

正如其名称所示，`FirstPersonControls`允许你像第一人称射击游戏一样控制相机。鼠标用来四处看看，键盘用来四处走动。你可以在`07-first-person-camera.html`中找到一个例子。以下截图显示了这个例子的静态图像：

![FirstPersonControls](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_06.jpg)

创建这些控制遵循了我们到目前为止看到的其他控制所遵循的相同原则。我们刚刚展示的例子使用了以下配置：

```js
var camControls = new THREE.FirstPersonControls(camera);
camControls.lookSpeed = 0.4;
camControls.movementSpeed = 20;
camControls.noFly = true;
camControls.lookVertical = true;
camControls.constrainVertical = true;
camControls.verticalMin = 1.0;
camControls.verticalMax = 2.0;
camControls.lon = -150;
camControls.lat = 120;
```

当你自己使用这个控制时，你应该仔细看看的唯一属性是最后两个：`lon`和`lat`属性。这两个属性定义了当场景第一次渲染时相机指向的位置。

这个控制的控制非常简单：

| 控制 | 动作 |
| --- | --- |
| 鼠标移动 | 四处看看 |
| 左、右、上、下箭头 | 向左、向右、向前、向后移动 |
| W | 向前移动 |
| A | 向左移动 |
| S | 向后移动 |
| D | 向右移动 |
| R | 向上移动 |
| F | 向下移动 |
| Q | 停止所有移动 |

对于下一个控制，我们将从第一人称视角转向太空视角。

## OrbitControl

`OrbitControl`控制是围绕场景中心的物体旋转和平移的好方法。在`08-controls-orbit.html`中，我们包含了一个展示这个控制如何工作的例子。以下截图显示了这个例子的静态图像：

![OrbitControl](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_07.jpg)

使用`OrbitControl`和使用其他控制一样简单。包括正确的 JavaScript 文件，设置控制与相机，再次使用`THREE.Clock`来更新控制：

```js
<script type="text/javascript" src="../libs/OrbitControls.js"></script>
...
var orbitControls = new THREE.OrbitControls(camera);
orbitControls.autoRotate = true;
var clock = new THREE.Clock();
...
var delta = clock.getDelta();
orbitControls.update(delta);
```

`THREE.OrbitControls`的控制集中在使用鼠标上，如下表所示：

| 控制 | 动作 |
| --- | --- |
| 左鼠标点击+移动 | 围绕场景中心旋转相机 |
| 滚轮或中键点击+移动 | 放大和缩小 |
| 右鼠标点击+移动 | 在场景中四处移动 |
| 左、右、上、下箭头 | 在场景中四处移动 |

摄像机和移动已经介绍完了。在这一部分，我们已经看到了许多控制，可以让你创建有趣的摄像机动作。在下一节中，我们将看一下更高级的动画方式：变形和蒙皮。

# 变形和骨骼动画

当您在外部程序（例如 Blender）中创建动画时，通常有两种主要选项来定义动画：

+   **变形目标**：使用变形目标，您定义了网格的变形版本，即关键位置。对于这个变形目标，存储了所有顶点位置。要使形状动画化，您需要将所有顶点从一个位置移动到另一个关键位置并重复该过程。以下屏幕截图显示了用于显示面部表情的各种变形目标（以下图像由 Blender 基金会提供）：![变形和骨骼动画](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_09.jpg)

+   **骨骼动画**：另一种选择是使用骨骼动画。使用骨骼动画，您定义网格的骨架，即骨骼，并将顶点附加到特定的骨骼上。现在，当您移动一个骨骼时，任何连接的骨骼也会适当移动，并且根据骨骼的位置、移动和缩放移动和变形附加的顶点。下面再次由 Blender 基金会提供的屏幕截图显示了骨骼如何用于移动和变形对象的示例：![变形和骨骼动画](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_10.jpg)

Three.js 支持这两种模式，但通常使用变形目标可能会获得更好的结果。骨骼动画的主要问题是从 Blender 等 3D 程序中获得可以在 Three.js 中进行动画处理的良好导出。使用变形目标比使用骨骼和皮肤更容易获得良好的工作模型。

在本节中，我们将研究这两种选项，并另外查看 Three.js 支持的一些外部格式，其中可以定义动画。

## 使用变形目标的动画

变形目标是定义动画的最直接方式。您为每个重要位置（也称为关键帧）定义所有顶点，并告诉 Three.js 将顶点从一个位置移动到另一个位置。然而，这种方法的缺点是，对于大型网格和大型动画，模型文件将变得非常庞大。原因是对于每个关键位置，所有顶点位置都会重复。

我们将向您展示如何使用两个示例处理变形目标。在第一个示例中，我们将让 Three.js 处理各个关键帧（或我们从现在开始称之为变形目标）之间的过渡，在第二个示例中，我们将手动完成这个过程。

### 使用 MorphAnimMesh 的动画

在我们的第一个变形示例中，我们将使用 Three.js 分发的模型之一——马。了解基于变形目标的动画如何工作的最简单方法是打开`10-morph-targets.html`示例。以下屏幕截图显示了此示例的静态图像：

![使用 MorphAnimMesh 的动画](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_11.jpg)

在此示例中，右侧的马正在进行动画和奔跑，而左侧的马站在原地。左侧的这匹马是从基本模型即原始顶点集渲染的。在右上角的菜单中，您可以浏览所有可用的变形目标，并查看左侧马可以采取的不同位置。

Three.js 提供了一种从一个位置移动到另一个位置的方法，但这意味着我们必须手动跟踪我们所在的当前位置和我们想要变形成的目标，并且一旦达到目标位置，就要重复这个过程以达到其他位置。幸运的是，Three.js 还提供了一个特定的网格，即`THREE.MorphAnimMesh`，它会为我们处理这些细节。在我们继续之前，这里有关于 Three.js 提供的另一个与动画相关的网格`THREE.MorphBlendMesh`的快速说明。如果您浏览 Three.js 提供的对象，您可能会注意到这个对象。使用这个特定的网格，您可以做的事情几乎与`THREE.MorphAnimMesh`一样多，当您查看源代码时，甚至可以看到这两个对象之间的许多内容是重复的。然而，`THREE.MorphBlendMesh`似乎已经被弃用，并且在任何官方的 Three.js 示例中都没有使用。您可以使用`THREE.MorphAnimMesh`来完成`THREE.MorhpBlendMesh`可以完成的所有功能，因此请使用`THREE.MorphAnimMesh`来进行这种功能。以下代码片段显示了如何从模型加载并创建`THREE.MorphAnimMesh`：

```js
var loader = new THREE.JSONLoader();
loader.load('../assets/models/horse.js', function(geometry, mat) {

  var mat = new THREE.MeshLambertMaterial({ morphTargets: true, vertexColors: THREE.FaceColors});

  morphColorsToFaceColors(geometry);
  geometry.computeMorphNormals();
  meshAnim = new THREE.MorphAnimMesh(geometry, mat );
  scene.add(meshAnim);

},'../assets/models' );

function morphColorsToFaceColors(geometry) {

  if (geometry.morphColors && geometry.morphColors.length) {

    var colorMap = geometry.morphColors[ 0 ];
    for (var i = 0; i < colorMap.colors.length; i++) {
      geometry.faces[ i ].color = colorMap.colors[ i ];
      geometry.faces[ i ].color.offsetHSL(0, 0.3, 0);
    }
  }
}
```

这与我们加载其他模型时看到的方法相同。然而，这次外部模型还包含了变形目标。我们创建`THREE.MorphAnimMesh`而不是创建普通的`THREE.Mesh`对象。加载动画时需要考虑几件事情：

+   确保您使用的材质将`THREE.morphTargets`设置为`true`。如果没有设置，您的网格将不会动画。

+   在创建`THREE.MorphAnimMesh`之前，请确保在几何体上调用`computeMorphNormals`，以便计算所有变形目标的法线向量。这对于正确的光照和阴影效果是必需的。

+   还可以为特定变形目标的面定义颜色。这些可以从`morphColors`属性中获得。您可以使用这个来变形几何体的形状，也可以变形各个面的颜色。使用`morphColorsToFaceColors`辅助方法，我们只需将面的颜色固定为`morphColors`数组中的第一组颜色。

+   默认设置是一次性播放完整的动画。如果为同一几何体定义了多个动画，您可以使用`parseAnimations()`函数和`playAnimation(name,fps)`来播放其中一个定义的动画。我们将在本章的最后一节中使用这种方法，从 MD2 模型中加载动画。

剩下的就是在渲染循环中更新动画。为此，我们再次使用`THREE.Clock`来计算增量，并用它来更新动画，如下所示：

```js
function render() {

  var delta = clock.getDelta();
  webGLRenderer.clear();
  if (meshAnim) {
    meshAnim.updateAnimation(delta *1000);
    meshAnim.rotation.y += 0.01;
  }

  // render using requestAnimationFrame
  requestAnimationFrame(render);
  webGLRenderer.render(scene, camera);
}
```

这种方法是最简单的，可以让您快速设置来自具有定义变形目标的模型的动画。另一种方法是手动设置动画，我们将在下一节中展示。

### 通过设置 morphTargetInfluence 属性创建动画

我们将创建一个非常简单的示例，其中我们将一个立方体从一个形状变形为另一个形状。这一次，我们将手动控制我们将变形到哪个目标。您可以在`11-morph-targets-manually.html`中找到这个示例。以下截图显示了这个示例的静态图像：

![通过设置 morphTargetInfluence 属性创建动画](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_12.jpg)

在这个例子中，我们手动为一个简单的立方体创建了两个变形目标，如下所示：

```js
// create a cube
var cubeGeometry = new THREE.BoxGeometry(4, 4, 4);
var cubeMaterial = new THREE.MeshLambertMaterial({morphTargets: true, color: 0xff0000});

// define morphtargets, we'll use the vertices from these geometries
var cubeTarget1 = new THREE.CubeGeometry(2, 10, 2);
var cubeTarget2 = new THREE.CubeGeometry(8, 2, 8);

// define morphtargets and compute the morphnormal
cubeGeometry.morphTargets[0] = {name: 'mt1', vertices: cubeTarget2.vertices};
cubeGeometry.morphTargets[1] = {name: 'mt2', vertices: cubeTarget1.vertices};
cubeGeometry.computeMorphNormals();

var cube = new THREE.Mesh(cubeGeometry, cubeMaterial);
```

当您打开这个示例时，您会看到一个简单的立方体。在右上角的滑块中，您可以设置`morphTargetInfluences`。换句话说，您可以确定初始立方体应该变形成指定为`mt1`的立方体的程度，以及它应该变形成`mt2`的程度。当您手动创建变形目标时，您需要考虑到变形目标与源几何体具有相同数量的顶点。您可以使用网格的`morphTargetInfluences`属性来设置影响：

```js
var controls = new function () {
  // set to 0.01 to make sure dat.gui shows correct output
  this.influence1 = 0.01;
  this.influence2 = 0.01;

  this.update = function () {
    cube.morphTargetInfluences[0] = controls.influence1;
    cube.morphTargetInfluences[1] = controls.influence2;
  };
}
```

请注意，初始几何图形可以同时受多个形态目标的影响。这两个例子展示了形态目标动画背后的最重要的概念。在下一节中，我们将快速查看使用骨骼和蒙皮进行动画。

## 使用骨骼和蒙皮进行动画

形态动画非常直接。Three.js 知道所有目标顶点位置，只需要将每个顶点从一个位置过渡到下一个位置。对于骨骼和蒙皮，情况会变得有点复杂。当您使用骨骼进行动画时，您移动骨骼，Three.js 必须确定如何相应地转换附加的皮肤（一组顶点）。在这个例子中，我们使用从 Blender 导出到 Three.js 格式（`models`文件夹中的`hand-1.js`）的模型。这是一个手的模型，包括一组骨骼。通过移动骨骼，我们可以对整个模型进行动画。让我们首先看一下我们如何加载模型：

```js
var loader = new THREE.JSONLoader();
loader.load('../assets/models/hand-1.js', function (geometry, mat) {
  var mat = new THREE.MeshLambertMaterial({color: 0xF0C8C9, skinning: true});
  mesh = new THREE.SkinnedMesh(geometry, mat);

  // rotate the complete hand
  mesh.rotation.x = 0.5 * Math.PI;
  mesh.rotation.z = 0.7 * Math.PI;

  // add the mesh
  scene.add(mesh);

  // and start the animation
  tween.start();

}, '../assets/models');
```

加载用于骨骼动画的模型与加载任何其他模型并无太大不同。我们只需指定包含顶点、面和骨骼定义的模型文件，然后基于该几何图形创建一个网格。Three.js 还提供了一个特定的用于这样的蒙皮几何的网格，称为`THREE.SkinnedMesh`。确保模型得到更新的唯一一件事是将您使用的材质的`skinning`属性设置为`true`。如果不将其设置为`true`，则不会看到任何骨骼移动。我们在这里做的最后一件事是将所有骨骼的`useQuaternion`属性设置为`false`。在这个例子中，我们将使用一个`tween`对象来处理动画。这个`tween`实例定义如下：

```js
var tween = new TWEEN.Tween({pos: -1}).to({pos: 0}, 3000).easing(TWEEN.Easing.Cubic.InOut).yoyo(true).repeat(Infinity).onUpdate(onUpdate);
```

通过这个 Tween，我们将`pos`变量从`-1`过渡到`0`。我们还将`yoyo`属性设置为`true`，这会导致我们的动画在下一次运行时以相反的方式运行。为了确保我们的动画保持运行，我们将`repeat`设置为`Infinity`。您还可以看到我们指定了一个`onUpdate`方法。这个方法用于定位各个骨骼，接下来我们将看一下这个方法。

在我们移动骨骼之前，让我们先看一下`12-bones-manually.html`示例。以下屏幕截图显示了这个示例的静态图像：

![使用骨骼和蒙皮进行动画](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_13.jpg)

当您打开此示例时，您会看到手做出抓取的动作。我们通过在从我们的 Tween 动画调用的`onUpdate`方法中设置手指骨骼的*z*旋转来实现这一点，如下所示：

```js
var onUpdate = function () {
  var pos = this.pos;

  // rotate the fingers
  mesh.skeleton.bones[5].rotation.set(0, 0, pos);
  mesh.skeleton.bones[6].rotation.set(0, 0, pos);
  mesh.skeleton.bones[10].rotation.set(0, 0, pos);
  mesh.skeleton.bones[11].rotation.set(0, 0, pos);
  mesh.skeleton.bones[15].rotation.set(0, 0, pos);
  mesh.skeleton.bones[16].rotation.set(0, 0, pos);
  mesh.skeleton.bones[20].rotation.set(0, 0, pos);
  mesh.skeleton.bones[21].rotation.set(0, 0, pos);

  // rotate the wrist
  mesh.skeleton.bones[1].rotation.set(pos, 0, 0);
};
```

每当调用此更新方法时，相关的骨骼都设置为`pos`位置。要确定需要移动哪根骨骼，最好打印出`mesh.skeleton`属性到控制台。这将列出所有骨骼及其名称。

### 提示

Three.js 提供了一个简单的辅助工具，您可以用它来显示模型的骨骼。将以下内容添加到代码中：

```js
helper = new THREE.SkeletonHelper( mesh );
helper.material.linewidth = 2;
helper.visible = false;
scene.add( helper );
```

骨骼被突出显示。您可以通过启用`12-bones-manually.html`示例中显示的`showHelper`属性来查看此示例。

正如您所看到的，使用骨骼需要更多的工作，但比固定的形态目标更灵活。在这个例子中，我们只移动了骨骼的旋转；您还可以移动位置或更改比例。在下一节中，我们将看一下从外部模型加载动画。在该部分，我们将重新访问这个例子，但现在，我们将从模型中运行预定义的动画，而不是手动移动骨骼。

# 使用外部模型创建动画

在第八章*创建和加载高级网格和几何体*中，我们看了一些 Three.js 支持的 3D 格式。其中一些格式也支持动画。在本章中，我们将看一下以下示例：

+   **使用 JSON 导出器的 Blender**：我们将从 Blender 中创建的动画开始，并将其导出到 Three.js JSON 格式。

+   **Collada 模型**：Collada 格式支持动画。在此示例中，我们将从 Collada 文件加载动画，并在 Three.js 中呈现它。

+   **MD2 模型**：MD2 模型是旧版 Quake 引擎中使用的简单格式。尽管该格式有点过时，但仍然是存储角色动画的非常好的格式。

我们将从 Blender 模型开始。

## 使用 Blender 创建骨骼动画

要开始使用 Blender 中的动画，您可以加载我们在 models 文件夹中包含的示例。您可以在那里找到`hand.blend`文件，然后将其加载到 Blender 中。以下截图显示了这个示例的静态图像：

![使用 Blender 创建骨骼动画](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_14.jpg)

在本书中，没有足够的空间详细介绍如何在 Blender 中创建动画，但有一些事情需要记住：

+   您的模型中的每个顶点至少必须分配给一个顶点组。

+   您在 Blender 中使用的顶点组的名称必须对应于控制它的骨骼的名称。这样，Three.js 可以确定移动骨骼时需要修改哪些顶点。

+   只有第一个“动作”被导出。因此，请确保要导出的动画是第一个。

+   在创建关键帧时，最好选择所有骨骼，即使它们没有改变。

+   在导出模型时，请确保模型处于静止姿势。如果不是这种情况，您将看到一个非常畸形的动画。

有关在 Blender 中创建和导出动画以及上述要点的原因的更多信息，您可以查看以下优秀资源：[`devmatrix.wordpress.com/2013/02/27/creating-skeletal-animation-in-blender-and-exporting-it-to-three-js/`](http://devmatrix.wordpress.com/2013/02/27/creating-skeletal-animation-in-blender-and-exporting-it-to-three-js/)。

当您在 Blender 中创建动画时，可以使用我们在上一章中使用的 Three.js 导出器导出文件。在使用 Three.js 导出器导出文件时，您必须确保检查以下属性：

![使用 Blender 创建骨骼动画](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_15.jpg)

这将导出您在 Blender 中指定的动画作为骨骼动画，而不是形变动画。使用骨骼动画，骨骼的移动被导出，我们可以在 Three.js 中重放。

在 Three.js 中加载模型与我们之前的示例相同；但是，现在模型加载后，我们还将创建一个动画，如下所示：

```js
var loader = new THREE.JSONLoader();
loader.load('../assets/models/hand-2.js', function (model, mat) {

  var mat = new THREE.MeshLambertMaterial({color: 0xF0C8C9, skinning: true});
  mesh = new THREE.SkinnedMesh(model, mat);

  var animation = new THREE.Animation(mesh, model.animation);

  mesh.rotation.x = 0.5 * Math.PI;
  mesh.rotation.z = 0.7 * Math.PI;
  scene.add(mesh);

  // start the animation
  animation.play();

}, '../assets/models');
```

要运行此动画，我们只需创建一个`THREE.Animation`实例，并在此动画上调用`play`方法。在看到动画之前，我们还需要执行一个额外的步骤。在我们的渲染循环中，我们调用`THREE.AnimationHandler.update(clock.getDelta())`函数来更新动画，Three.js 将使用骨骼来设置模型的正确位置。这个示例(`13-animation-from-blender.html`)的结果是一个简单的挥手。

以下截图显示了这个示例的静态图像：

![使用 Blender 创建骨骼动画](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_16.jpg)

除了 Three.js 自己的格式，我们还可以使用其他几种格式来定义动画。我们将首先看一下加载 Collada 模型。

## 从 Collada 模型加载动画

从 Collada 文件加载模型的工作方式与其他格式相同。首先，您必须包含正确的加载器 JavaScript 文件：

```js
<script type="text/javascript" src="../libs/ColladaLoader.js"></script>
```

接下来，我们创建一个加载器并使用它来加载模型文件：

```js
var loader = new THREE.ColladaLoader();
loader.load('../assets/models/monster.dae', function (collada) {

  var child = collada.skins[0];
  scene.add(child);

  var animation = new THREE.Animation(child, child.geometry.animation);
  animation.play();

  // position the mesh
  child.scale.set(0.15, 0.15, 0.15);
  child.rotation.x = -0.5 * Math.PI;
  child.position.x = -100;
  child.position.y = -60;
});
```

Collada 文件不仅可以包含单个模型，还可以存储完整的场景，包括摄像机、灯光、动画等。使用 Collada 模型的一个好方法是将`loader.load`函数的结果打印到控制台，并确定要使用的组件。在这种情况下，场景中只有一个`THREE.SkinnedMesh`（`child`）。要渲染和动画化这个模型，我们所要做的就是设置动画，就像我们为基于 Blender 的模型所做的那样；甚至渲染循环保持不变。以下是我们如何渲染和动画化模型的方法：

```js
function render() {
  ...
  meshAnim.updateAnimation( delta *1000 );
  ...
}
```

而这个特定 Collada 文件的结果看起来像这样：

![从 Collada 模型加载动画](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_17.jpg)

另一个使用变形目标的外部模型的例子是 MD2 文件格式。

## 从 Quake 模型加载的动画

MD2 格式是为了对 Quake 中的角色进行建模而创建的，Quake 是一款 1996 年的伟大游戏。尽管新的引擎使用了不同的格式，但你仍然可以在 MD2 格式中找到许多有趣的模型。要使用这种格式的文件，我们首先必须将它们转换为 Three.js 的 JavaScript 格式。你可以在以下网站上在线进行转换：

[`oos.moxiecode.com/js_webgl/md2_converter/`](http://oos.moxiecode.com/js_webgl/md2_converter/)

转换后，你会得到一个以 Three.js 格式的 JavaScript 文件，你可以使用`MorphAnimMesh`加载和渲染。由于我们已经在前面的章节中看到了如何做到这一点，我们将跳过加载模型的代码。不过代码中有一件有趣的事情。我们不是播放完整的动画，而是提供需要播放的动画的名称：

```js
mesh.playAnimation('crattack', 10);
```

原因是 MD2 文件通常包含许多不同的角色动画。不过，Three.js 提供了功能来确定可用的动画并使用`playAnimation`函数播放它们。我们需要做的第一件事是告诉 Three.js 解析动画：

```js
mesh.parseAnimations();
```

这将导致一个动画名称列表，可以使用`playAnimation`函数播放。在我们的例子中，你可以在右上角的菜单中选择动画的名称。可用的动画是这样确定的：

```js
mesh.parseAnimations();

var animLabels = [];
for (var key in mesh.geometry.animations) {
  if (key === 'length' || !mesh.geometry.animations.hasOwnProperty(key)) continue;
  animLabels.push(key);
}

gui.add(controls,'animations',animLabels).onChange(function(e) {
  mesh.playAnimation(controls.animations,controls.fps);
});
```

每当从菜单中选择一个动画时，都会使用指定的动画名称调用`mesh.playAnimation`函数。演示这一点的例子可以在`15-animation-from-md2.html`中找到。以下截图显示了这个例子的静态图像：

![从 Quake 模型加载的动画](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_09_18.jpg)

# 摘要

在本章中，我们看了一些不同的方法，你可以为你的场景添加动画。我们从一些基本的动画技巧开始，然后转移到摄像机的移动和控制，最后使用变形目标和骨骼/骨骼动画来动画模型。当你有了渲染循环后，添加动画就变得非常容易。只需改变网格的属性，在下一个渲染步骤中，Three.js 将渲染更新后的网格。

在之前的章节中，我们看了一下你可以用来皮肤化你的物体的各种材料。例如，我们看到了如何改变这些材料的颜色、光泽和不透明度。然而，我们还没有详细讨论过的是如何使用外部图像（也称为纹理）与这些材料一起。使用纹理，你可以轻松地创建看起来像是由木头、金属、石头等制成的物体。在下一章中，我们将探讨纹理的各个方面以及它们在 Three.js 中的使用方式。


# 第十章：加载和使用纹理

在第四章中，*使用 Three.js 材质*，我们向您介绍了 Three.js 中可用的各种材质。然而，在那一章中，我们没有讨论如何将纹理应用到网格上。在本章中，我们将讨论这个主题。更具体地说，在本章中，我们将讨论以下主题：

+   在 Three.js 中加载纹理并将其应用于网格

+   使用凹凸和法线贴图为网格应用深度和细节

+   使用光照图创建假阴影

+   使用环境贴图为材质添加详细的反射

+   使用高光贴图来设置网格特定部分的*光泽*

+   微调和自定义网格的 UV 映射

+   使用 HTML5 画布和视频元素作为纹理的输入

让我们从最基本的示例开始，向您展示如何加载和应用纹理。

# 在材质中使用纹理

在 Three.js 中有不同的纹理使用方式。您可以使用它们来定义网格的颜色，但也可以使用它们来定义光泽、凹凸和反射。我们首先看的例子是最基本的方法，即使用纹理来定义网格的每个像素的颜色。

## 加载纹理并将其应用于网格

纹理的最基本用法是将其设置为材质上的映射。当您使用此材质创建网格时，网格的颜色将基于提供的纹理着色。

加载纹理并在网格上使用它可以通过以下方式完成：

```js
function createMesh(geom, imageFile) {
  var texture = THREE.ImageUtils.loadTexture("../assets/textures/general/" + imageFile)

  var mat = new THREE.MeshPhongMaterial();
  mat.map = texture;

  var mesh = new THREE.Mesh(geom, mat);
  return mesh;
}
```

在这个代码示例中，我们使用`THREE.ImageUtils.loadTexture`函数从特定位置加载图像文件。您可以使用 PNG、GIF 或 JPEG 图像作为纹理的输入。请注意，加载纹理是异步完成的。在我们的场景中，这不是一个问题，因为我们有一个`render`循环，每秒渲染大约 60 次。如果您想要等待直到纹理加载完成，您可以使用以下方法：

```js
texture = THREE.ImageUtils.loadTexture('texture.png', {}, function() { renderer.render(scene); });
```

在这个示例中，我们向`loadTexture`提供了一个回调函数。当纹理加载时，将调用此回调。在我们的示例中，我们不使用回调，而是依赖于`render`循环最终在加载纹理时显示纹理。

您几乎可以使用任何您喜欢的图像作为纹理。然而，最好的结果是当您使用一个边长是 2 的幂的正方形纹理时。因此，边长为 256 x 256、512 x 512、1024 x 1024 等尺寸效果最好。以下图像是一个正方形纹理的示例：

![加载纹理并将其应用于网格](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_01.jpg)

由于纹理的像素（也称为**texels**）通常不是一对一地映射到面的像素上，因此需要对纹理进行放大或缩小。为此，WebGL 和 Three.js 提供了一些不同的选项。您可以通过设置`magFilter`属性来指定纹理的放大方式，通过设置`minFilter`属性来指定缩小方式。这些属性可以设置为以下两个基本值：

| 名称 | 描述 |
| --- | --- |
| `THREE.NearestFilter` | 此滤镜使用它能找到的最近的像素的颜色。当用于放大时，这将导致块状，当用于缩小时，结果将丢失很多细节。 |
| `THREE.LinearFilter` | 此滤镜更先进，使用四个相邻像素的颜色值来确定正确的颜色。在缩小时仍会丢失很多细节，但放大会更加平滑，不那么块状。 |

除了这些基本值，我们还可以使用 mipmap。**Mipmap**是一组纹理图像，每个图像的尺寸都是前一个的一半。当加载纹理时会创建这些图像，并允许更平滑的过滤。因此，当您有一个正方形纹理（作为 2 的幂），您可以使用一些额外的方法来获得更好的过滤效果。这些属性可以使用以下值进行设置：

| 名称 | 描述 |
| --- | --- |
| `THREE.NearestMipMapNearestFilter` | 此属性选择最佳映射所需分辨率的 mipmap，并应用我们在前表中讨论的最近过滤原则。放大仍然很粗糙，但缩小看起来好多了。 |
| `THREE.NearestMipMapLinearFilter` | 此属性不仅选择单个 mipmap，还选择两个最接近的 mipmap 级别。在这两个级别上，应用最近的过滤器以获得两个中间结果。这两个结果通过线性过滤器传递以获得最终结果。 |
| `THREE.LinearMipMapNearestFilter` | 此属性选择最佳映射所需分辨率的 mipmap，并应用我们在前表中讨论的线性过滤原则。 |
| `THREE.LinearMipMapLinearFilter` | 此属性不仅选择单个 mipmap，还选择两个最接近的 mipmap 级别。在这两个级别上，应用线性过滤器以获得两个中间结果。这两个结果通过线性过滤器传递以获得最终结果。 |

如果您没有明确指定`magFilter`和`minFilter`属性，Three.js 将使用`THREE.LinearFilter`作为`magFilter`属性的默认值，并使用`THREE.LinearMipMapLinearFilter`作为`minFilter`属性的默认值。在我们的示例中，我们将使用这些默认属性。基本纹理的示例可以在`01-basic-texture.html`中找到。以下屏幕截图显示了此示例：

![加载纹理并将其应用于网格](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_02.jpg)

在此示例中，我们加载了一些纹理（使用您之前看到的代码）并将它们应用于各种形状。在此示例中，您可以看到纹理很好地包裹在形状周围。在 Three.js 中创建几何图形时，它会确保正确应用任何使用的纹理。这是通过一种称为**UV 映射**的东西完成的（本章后面将详细介绍）。通过 UV 映射，我们告诉渲染器应将纹理的哪一部分应用于特定的面。最简单的示例是立方体。其中一个面的 UV 映射如下所示：

```js
(0,1),(0,0),(1,0),(1,1)
```

这意味着我们对这个面使用完整的纹理（UV 值范围从 0 到 1）。

除了我们可以使用`THREE.ImageUtils.loadTexture`加载的标准图像格式之外，Three.js 还提供了一些自定义加载程序，您可以使用这些加载程序加载以不同格式提供的纹理。以下表格显示了您可以使用的其他加载程序：

| 名称 | 描述 |
| --- | --- |

| `THREE.DDSLoader` | 使用此加载程序，您可以加载以 DirectDraw Surface 格式提供的纹理。这种格式是一种专有的微软格式，用于存储压缩纹理。使用此加载程序非常简单。首先，在 HTML 页面中包含`DDSLoader.js`文件，然后使用以下内容使用纹理：

```js
var loader = new THREE.DDSLoader();
var texture = loader.load( '../assets/textures/  seafloor.dds' );

var mat = new THREE.MeshPhongMaterial();
mat.map = texture;
```

您可以在本章的源代码中看到此加载程序的示例：`01-basic-texture-dds.html`。在内部，此加载程序使用`THREE.CompressedTextureLoader`。|

| `THREE.PVRLoader` | Power VR 是另一种专有文件格式，用于存储压缩纹理。Three.js 支持 Power VR 3.0 文件格式，并可以使用以此格式提供的纹理。要使用此加载程序，请在 HTML 页面中包含`PVRLoader.js`文件，然后使用以下内容使用纹理：

```js
var loader = new THREE.DDSLoader();
var texture = loader.load( '../assets/textures/ seafloor.dds' );

var mat = new THREE.MeshPhongMaterial();
mat.map = texture;
```

您可以在本章的源代码中看到此加载程序的示例：`01-basic-texture-pvr.html`。请注意，并非所有的 WebGL 实现都支持此格式的纹理。因此，当您使用此格式但未看到纹理时，请检查控制台以查看错误。在内部，此加载程序还使用`THREE.CompressedTextureLoader`。|

| `THREE.TGALoader` | Targa 是一种光栅图形文件格式，仍然被大量 3D 软件程序使用。使用`THREE.TGALoader`对象，您可以在 3D 模型中使用以此格式提供的纹理。要使用这些图像文件，您首先必须在 HTML 中包含`TGALoader.js`文件，然后可以使用以下内容加载 TGA 纹理：

```js
var loader = new THREE.TGALoader();
var texture = loader.load( '../assets/textures/crate_color8.tga' );

var mat = new THREE.MeshPhongMaterial();
mat.map = texture;
```

本章的源代码中提供了此加载器的示例。您可以通过在浏览器中打开`01-basic-texture-tga.html`来查看此示例。|

在这些示例中，我们使用纹理来定义网格像素的颜色。我们还可以将纹理用于其他目的。以下两个示例用于定义如何应用阴影到材质上。您可以使用这个来在网格表面创建凸起和皱纹。

## 使用凸起贴图创建皱纹

**凸起贴图**用于增加材质的深度。您可以通过打开`02-bump-map.html`示例来看到其效果。请参考以下截图查看示例：

![使用凸起贴图创建皱纹](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_03.jpg)

在此示例中，您可以看到左侧墙看起来比右侧墙更详细，并且在比较时似乎具有更多的深度。这是通过在材质上设置额外的纹理，所谓的凸起贴图来实现的：

```js
function createMesh(geom, imageFile, bump) {
  var texture = THREE.ImageUtils.loadTexture("../assets/textures/general/" + imageFile)
  var mat = new THREE.MeshPhongMaterial();
  mat.map = texture;

  var bump = THREE.ImageUtils.loadTexture(
    "../assets/textures/general/" + bump)
  mat.bumpMap = bump;
  mat.bumpScale = 0.2;

  var mesh = new THREE.Mesh(geom, mat);
  return mesh;
}
```

您可以在此代码中看到，除了设置`map`属性之外，我们还将`bumpMap`属性设置为纹理。另外，通过`bumpScale`属性，我们可以设置凸起的高度（或如果设置为负值则为深度）。此示例中使用的纹理如下所示：

![使用凸起贴图创建皱纹](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_04.jpg)

凸起贴图是灰度图像，但您也可以使用彩色图像。像素的强度定义了凸起的高度。凸起贴图只包含像素的相对高度。它并不表示坡度的方向。因此，使用凸起贴图可以达到的细节水平和深度感知是有限的。要获得更多细节，您可以使用法线贴图。

## 使用法线贴图实现更详细的凸起和皱纹

在法线贴图中，高度（位移）不会被存储，而是存储了每个图像的法线方向。不详细介绍，使用法线贴图，您可以创建看起来非常详细的模型，而仍然只使用少量的顶点和面。例如，查看`03-normal-map.html`示例。以下截图显示了此示例：

![使用法线贴图实现更详细的凸起和皱纹](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_05.jpg)

在此截图中，您可以看到左侧有一个非常详细的抹灰立方体。光源在立方体周围移动，您可以看到纹理对光源的自然响应。这提供了一个非常逼真的模型，只需要一个非常简单的模型和几个纹理。以下代码片段显示了如何在 Three.js 中使用法线贴图：

```js
function createMesh(geom, imageFile, normal) {
  var t = THREE.ImageUtils.loadTexture("../assets/textures/general/" + imageFile);
  var m = THREE.ImageUtils.loadTexture("../assets/textures/general/" + normal);

  var mat2 = new THREE.MeshPhongMaterial();
  mat2.map = t;
  mat2.normalMap = m;

  var mesh = new THREE.Mesh(geom, mat2);
  return mesh;
}
```

这里使用的方法与凸起贴图相同。不过这次，我们将`normalMap`属性设置为法线纹理。我们还可以通过设置`normalScale`属性`mat.normalScale.set(1,1)`来定义凸起的外观。通过这两个属性，您可以沿着*x*和*y*轴进行缩放。不过，最好的方法是保持这些值相同以获得最佳效果。请注意，再次强调，当这些值低于零时，高度会反转。以下截图显示了纹理（左侧）和法线贴图（右侧）：

![使用法线贴图实现更详细的凸起和皱纹](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_06.jpg)

然而，法线贴图的问题在于它们不太容易创建。您需要使用专门的工具，如 Blender 或 Photoshop。它们可以使用高分辨率渲染或纹理作为输入，并从中创建法线贴图。

Three.js 还提供了一种在运行时执行此操作的方法。`THREE.ImageUtils`对象有一个名为`getNormalMap`的函数，它接受 JavaScript/DOM`Image`作为输入，并将其转换为法线贴图。

## 使用光照贴图创建虚假阴影

在之前的示例中，我们使用特定的贴图来创建看起来真实的阴影，这些阴影会对房间中的光照做出反应。还有另一种选择可以创建假阴影。在本节中，我们将使用光照贴图。**光照贴图**是一个预渲染的阴影（也称为预烘烤阴影），您可以使用它来营造真实阴影的错觉。以下截图来自`04-light-map.html`示例，展示了这个效果：

![使用光照贴图创建假阴影](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_07.jpg)

如果您看一下之前的示例，会发现有两个非常漂亮的阴影，似乎是由两个立方体投射出来的。然而，这些阴影是基于一个看起来像下面这样的光照贴图的：

![使用光照贴图创建假阴影](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_08.jpg)

正如您所看到的，光照贴图中指定的阴影也显示在地面上，营造出真实阴影的错觉。您可以使用这种技术创建高分辨率的阴影，而不会产生沉重的渲染惩罚。当然，这仅适用于静态场景。使用光照贴图与使用其他纹理基本相同，只有一些小差异。以下是我们使用光照贴图的方法：

```js
var lm = THREE.ImageUtils.loadTexture('../assets/textures/lightmap/lm-1.png');
var wood = THREE.ImageUtils.loadTexture('../assets/textures/general/floor-wood.jpg');
var groundMaterial = new THREE.MeshBasicMaterial({lightMap: lm, map: wood});
groundGeom.faceVertexUvs[1] = groundGeom.faceVertexUvs[0];
```

要应用光照贴图，我们只需要将材质的`lightMap`属性设置为我们刚刚展示的光照贴图。然而，还需要额外的步骤才能让光照贴图显示出来。我们需要明确定义 UV 映射（纹理在面上的哪一部分）以便独立应用和映射光照贴图。在我们的示例中，我们只使用了基本的 UV 映射，这是在创建地面时由 Three.js 自动创建的。更多信息和为什么需要明确定义 UV 映射的背景可以在[`stackoverflow.com/questions/15137695/three-js-lightmap-causes-an-error-webglrenderingcontext-gl-error-gl-invalid-op`](http://stackoverflow.com/questions/15137695/three-js-lightmap-causes-an-error-webglrenderingcontext-gl-error-gl-invalid-op)找到。

当阴影贴图正确放置后，我们需要将立方体放置在正确的位置，以便看起来阴影是由它们投射出来的。

Three.js 提供了另一种纹理，您可以使用它来模拟高级的 3D 效果。在下一节中，我们将看看如何使用环境贴图来模拟反射。

## 使用环境贴图创建假反射

计算环境反射非常消耗 CPU，并且通常需要使用光线追踪器方法。如果您想在 Three.js 中使用反射，仍然可以做到，但您需要模拟它。您可以通过创建对象所在环境的纹理并将其应用于特定对象来实现这一点。首先，我们将展示我们的目标结果（请参阅`05-env-map-static.html`，也显示在以下截图中）：

![使用环境贴图创建假反射](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_09.jpg)

在这个截图中，您可以看到球体和立方体反射了环境。如果您移动鼠标，还可以看到反射与您在城市环境中的相机角度相对应。为了创建这个示例，我们执行以下步骤：

1.  **创建 CubeMap 对象**：我们需要做的第一件事是创建一个`CubeMap`对象。`CubeMap`是一组可以应用于立方体每一面的六个纹理。

1.  **使用这个 CubeMap 对象创建一个盒子**：带有`CubeMap`的盒子是您在移动相机时看到的环境。它给人一种错觉，好像您站在一个可以四处看的环境中。实际上，您是在一个立方体内部，内部渲染了纹理，给人一种空间的错觉。

1.  **将 CubeMap 对象应用为纹理**：我们用来模拟环境的`CubeMap`对象也可以作为网格的纹理。Three.js 会确保它看起来像环境的反射。

一旦您获得了源材料，创建`CubeMap`就非常简单。您需要的是六张图片，它们共同组成一个完整的环境。因此，您需要以下图片：向前看（`posz`）、向后看（`negz`）、向上看（`posy`）、向下看（`negy`）、向右看（`posx`）和向左看（`negx`）。Three.js 将这些拼接在一起，以创建一个无缝的环境映射。有几个网站可以下载这些图片。本例中使用的图片来自[`www.humus.name/index.php?page=Textures`](http://www.humus.name/index.php?page=Textures)。

一旦您获得了六张单独的图片，您可以按照以下代码片段中所示的方式加载它们：

```js
function createCubeMap() {

  var path = "../assets/textures/cubemap/parliament/";
  var format = '.jpg';
  var urls = [
    path + 'posx' + format, path + 'negx' + format,
    path + 'posy' + format, path + 'negy' + format,
    path + 'posz' + format, path + 'negz' + format
  ];

  var textureCube = THREE.ImageUtils.loadTextureCube( urls );
  return textureCube;
}
```

我们再次使用`THREE.ImageUtils` JavaScript 对象，但这次，我们传入一个纹理数组，并使用`loadTextureCube`函数创建`CubeMap`对象。如果您已经有了 360 度全景图像，您也可以将其转换为一组图像，以便创建`CubeMap`。只需转到[`gonchar.me/panorama/`](http://gonchar.me/panorama/)来转换图像，您最终会得到六张带有名称如`right.png`、`left.png`、`top.png`、`bottom.png`、`front.png`和`back.png`的图像。您可以通过创建以下方式的`urls`变量来使用这些图像：

```js
var urls = [
  'right.png',
  'left.png',
  'top.png',
  'bottom.png',
  'front.png',
  'back.png'
];
```

或者，您还可以在加载场景时让 Three.js 处理转换，方法是创建`textureCube`，如下所示：

```js
var textureCube = THREE.ImageUtils.loadTexture("360-degrees.png", new THREE.UVMapping());
```

使用`CubeMap`，我们首先创建一个盒子，可以这样创建：

```js
var textureCube = createCubeMap();
var shader = THREE.ShaderLib[ "cube" ];
shader.uniforms[ "tCube" ].value = textureCube;
var material = new THREE.ShaderMaterial( {
  fragmentShader: shader.fragmentShader,
  vertexShader: shader.vertexShader,
  uniforms: shader.uniforms,
  depthWrite: false,
  side: THREE.BackSide
});
cubeMesh = new THREE.Mesh(new THREE.BoxGeometry(100, 100, 100), material);
```

Three.js 提供了一个特定的着色器，我们可以使用`THREE.ShaderMaterial`来基于`CubeMap`创建一个环境（`var shader = THREE.ShaderLib[ "cube" ];`）。我们使用`CubeMap`配置此着色器，创建一个网格，并将其添加到场景中。如果从内部看，这个网格代表我们所处的虚假环境。

这个相同的`CubeMap`对象应该应用于我们想要渲染的网格，以创建虚假的反射：

```js
var sphere1 = createMesh(new THREE.SphereGeometry(10, 15, 15), "plaster.jpg");
sphere1.material.envMap = textureCube;
sphere1.rotation.y = -0.5;
sphere1.position.x = 12;
sphere1.position.y = 5;
scene.add(sphere1);

var cube = createMesh(new THREE.CubeGeometry(10, 15, 15), "plaster.jpg","plaster-normal.jpg");
sphere2.material.envMap = textureCube;
sphere2.rotation.y = 0.5;
sphere2.position.x = -12;
sphere2.position.y = 5;
scene.add(cube);
```

如您所见，我们将材质的`envMap`属性设置为我们创建的`cubeMap`对象。结果是一个场景，看起来我们站在一个宽阔的室外环境中，网格反映了这个环境。如果您使用滑块，可以设置材质的`reflectivity`属性，正如其名称所示，这决定了材质反射了多少环境。

除了反射，Three.js 还允许您为折射（类似玻璃的对象）使用`CubeMap`对象。以下屏幕截图显示了这一点：

![使用环境映射创建虚假反射](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_10.jpg)

要获得这种效果，我们只需要将纹理加载更改为以下内容：

```js
var textureCube = THREE.ImageUtils.loadTextureCube( urls, new THREE.CubeRefractionMapping());
```

您可以使用材质上的`refraction`属性来控制`refraction`比例，就像使用`reflection`属性一样。在本例中，我们为网格使用了静态环境映射。换句话说，我们只看到了环境反射，而没有看到环境中的其他网格。在下面的屏幕截图中（您可以通过在浏览器中打开`05-env-map-dynamic.html`来查看），我们将向您展示如何创建一个反射，同时还显示场景中的其他对象：

![使用环境映射创建虚假反射](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_22.jpg)

要显示场景中其他对象的反射，我们需要使用一些其他 Three.js 组件。我们需要的第一件事是一个名为`THREE.CubeCamera`的额外相机：

```js
Var cubeCamera = new THREE.CubeCamera(0.1, 20000, 256);
scene.add(cubeCamera);
```

我们将使用`THREE.CubeCamera`来拍摄包含所有渲染对象的场景快照，并使用它来设置`CubeMap`。您需要确保将此相机定位在您想要显示动态反射的`THREE.Mesh`的确切位置上。在本例中，我们将仅在中心球上显示反射（如前一个屏幕截图中所示）。该球位于位置 0, 0, 0，因此在本例中，我们不需要显式定位`THREE.CubeCamera`。

我们只将动态反射应用于球体，因此我们需要两种不同的材质：

```js
var dynamicEnvMaterial = new THREE.MeshBasicMaterial({envMap: cubeCamera.renderTarget });
var envMaterial = new THREE.MeshBasicMaterial({envMap: textureCube });
```

与我们之前的例子的主要区别是，对于动态反射，我们将`envMap`属性设置为`cubeCamera.renderTarget`，而不是我们之前创建的`textureCube`。对于这个例子，我们在中心球体上使用`dynamicEnvMaterial`，在其他两个对象上使用`envMaterial`：

```js
sphere = new THREE.Mesh(sphereGeometry, dynamicEnvMaterial);
sphere.name = 'sphere';
scene.add(sphere);

var cylinder = new THREE.Mesh(cylinderGeometry, envMaterial);
cylinder.name = 'cylinder';
scene.add(cylinder);
cylinder.position.set(10, 0, 0);

var cube = new THREE.Mesh(boxGeometry, envMaterial);
cube.name = 'cube';
scene.add(cube);
cube.position.set(-10, 0, 0);
```

现在剩下的就是确保`cubeCamera`渲染场景，这样我们就可以将其输出用作中心球体的输入。为此，我们更新`render`循环如下：

```js
function render() {
  sphere.visible = false;
  cubeCamera.updateCubeMap( renderer, scene );
  sphere.visible = true;
  renderer.render(scene, camera);
  ...
  requestAnimationFrame(render);
}
```

正如你所看到的，我们首先禁用了`sphere`的可见性。我们这样做是因为我们只想看到来自其他两个对象的反射。接下来，我们通过调用`updateCubeMap`函数使用`cubeCamera`渲染场景。之后，我们再次使`sphere`可见，并像平常一样渲染场景。结果是，在球体的反射中，你可以看到立方体和圆柱的反射。

我们将看到的基本材质的最后一个是高光贴图。

## 高光贴图

使用**高光贴图**，你可以指定一个定义材质光泽度和高光颜色的贴图。例如，在下面的截图中，我们使用了高光贴图和法线贴图来渲染一个地球。你可以在浏览器中打开`06-specular-map.html`来查看这个例子。其结果也显示在下面的截图中：

![高光贴图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_11.jpg)

在这个截图中，你可以看到海洋被突出显示并反射光线。另一方面，大陆非常黑暗，不反射（太多）光线。为了达到这种效果，我们没有使用任何特定的法线纹理，而只使用了法线贴图来显示高度和以下高光贴图来突出显示海洋：

![高光贴图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_12.jpg)

基本上，像素的值越高（从黑色到白色），表面看起来就越有光泽。高光贴图通常与`specular`属性一起使用，你可以用它来确定反射的颜色。在这种情况下，它被设置为红色：

```js
var specularTexture=THREE.ImageUtils.loadTexture("../assets/textures/planets/EarthSpec.png");
var normalTexture=THREE.ImageUtils.loadTexture("../assets/textures/planets/EarthNormal.png");

var planetMaterial = new THREE.MeshPhongMaterial();
planetMaterial.specularMap = specularTexture;
planetMaterial.specular = new THREE.Color( 0xff0000 );
planetMaterial.shininess = 1;

planetMaterial.normalMap = normalTexture;
```

还要注意的是，通常使用低光泽度可以实现最佳效果，但根据光照和你使用的高光贴图，你可能需要进行实验以获得期望的效果。

# 纹理的高级用法

在上一节中，我们看到了一些基本的纹理用法。Three.js 还提供了更高级纹理用法的选项。在本节中，我们将看一下 Three.js 提供的一些选项。

## 自定义 UV 映射

我们将从更深入地了解 UV 映射开始。我们之前解释过，使用 UV 映射，你可以指定纹理的哪一部分显示在特定的面上。当你在 Three.js 中创建几何体时，这些映射也会根据你创建的几何体类型自动创建。在大多数情况下，你不需要真正改变这个默认的 UV 映射。理解 UV 映射工作原理的一个好方法是看一个来自 Blender 的例子，如下面的截图所示：

![自定义 UV 映射](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_13.jpg)

在这个例子中，你可以看到两个窗口。左侧的窗口包含一个立方体几何体。右侧的窗口是 UV 映射，我们加载了一个示例纹理来展示映射的方式。在这个例子中，我们选择了左侧窗口的一个单独面，并且右侧窗口显示了这个面的 UV 映射。你可以看到，面的每个顶点都位于右侧 UV 映射的一个角落（小圆圈）。这意味着完整的纹理将被用于这个面。这个立方体的所有其他面也以相同的方式映射，因此结果将显示一个每个面都显示完整纹理的立方体；参见`07-uv-mapping.html`，也显示在下面的截图中：

![自定义 UV 映射](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_14.jpg)

这是 Blender 中（也是 Three.js 中）立方体的默认设置。让我们通过只选择纹理的三分之二来改变 UV（在下面的截图中看到所选区域）：

![自定义 UV 映射](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_15.jpg)

如果我们现在在 Three.js 中展示这个，你会看到纹理被应用的方式不同，如下截图所示：

![自定义 UV 映射](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_16.jpg)

自定义 UV 映射通常是从诸如 Blender 之类的程序中完成的，特别是当模型变得更加复杂时。这里最重要的部分是记住 UV 映射在两个维度上运行，从 0 到 1。要自定义 UV 映射，你需要为每个面定义应该显示纹理的部分。你需要通过定义组成面的每个顶点的`u`和`v`坐标来实现这一点。你可以使用以下代码来设置`u`和`v`值：

```js
geom.faceVertexUvs[0][0][0].x = 0.5;
geom.faceVertexUvs[0][0][0].y = 0.7;
geom.faceVertexUvs[0][0][1].x = 0.4;
geom.faceVertexUvs[0][0][1].y = 0.1;
geom.faceVertexUvs[0][0][2].x = 0.4;
geom.faceVertexUvs[0][0][2].y = 0.5;
```

这段代码将把第一个面的`uv`属性设置为指定的值。记住每个面由三个顶点定义，所以要设置一个面的所有`uv`值，我们需要设置六个属性。如果你打开`07-uv-mapping-manual.html`例子，你可以看到当你手动改变`uv`映射时会发生什么。以下截图展示了这个例子：

![自定义 UV 映射](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_23.jpg)

接下来，我们将看一下纹理如何通过一些内部 UV 映射技巧来重复。

## 重复包装

当你在 Three.js 中应用纹理到一个几何体上时，Three.js 会尽可能地优化应用纹理。例如，对于立方体，这意味着每一面都会显示完整的纹理，对于球体，完整的纹理会被包裹在球体周围。然而，有些情况下你可能不希望纹理在整个面或整个几何体上展开，而是希望纹理重复出现。Three.js 提供了详细的功能来控制这一点。一个可以用来调整重复属性的例子在`08-repeat-wrapping.html`中提供。以下截图展示了这个例子：

![重复包装](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_17.jpg)

在这个例子中，你可以设置控制纹理重复的属性。

在这个属性产生期望效果之前，你需要确保你将纹理的包装设置为`THREE.RepeatWrapping`，如下代码片段所示：

```js
cube.material.map.wrapS = THREE.RepeatWrapping;
cube.material.map.wrapT = THREE.RepeatWrapping;
```

`wrapS`属性定义了你希望纹理在*x*轴上的行为，`wrapT`属性定义了纹理在*y*轴上的行为。Three.js 为此提供了两个选项，如下所示：

+   `THREE.RepeatWrapping`允许纹理重复出现。

+   `THREE.ClampToEdgeWrapping`是默认设置。使用`THREE.ClampToEdgeWrapping`，纹理不会整体重复，而只有边缘的像素会重复。

如果你禁用了**repeatWrapping**菜单选项，将会使用`THREE.ClampToEdgeWrapping`选项，如下所示：

![重复包装](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_18.jpg)

如果我们使用`THREE.RepeatWrapping`，我们可以设置`repeat`属性，如下代码片段所示：

```js
cube.material.map.repeat.set(repeatX, repeatY);
```

`repeatX`变量定义了纹理在*x*轴上重复的次数，`repeatY`变量定义了在*y*轴上的重复次数。如果这些值设置为`1`，纹理就不会重复；如果设置为更高的值，你会看到纹理开始重复。你也可以使用小于 1 的值。在这种情况下，你会看到你会放大纹理。如果你将重复值设置为负值，纹理会被镜像。

当你改变`repeat`属性时，Three.js 会自动更新纹理并使用新的设置进行渲染。如果你从`THREE.RepeatWrapping`改变到`THREE.ClampToEdgeWrapping`，你需要显式地更新纹理：

```js
cube.material.map.needsUpdate = true;
```

到目前为止，我们只使用了静态图像作为纹理。然而，Three.js 也有选项可以使用 HTML5 画布作为纹理。

## 渲染到画布并将其用作纹理

在本节中，我们将看两个不同的示例。首先，我们将看一下如何使用画布创建一个简单的纹理并将其应用于网格，然后，我们将进一步创建一个可以用作凹凸贴图的画布，使用随机生成的图案。

### 使用画布作为纹理

在第一个示例中，我们将使用**Literally**库（来自[`literallycanvas.com/`](http://literallycanvas.com/)）创建一个交互式画布，您可以在其上绘制；请参见以下截图的左下角。您可以在`09-canvas-texture`中查看此示例。随后的截图显示了此示例：

![使用画布作为纹理](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_19.jpg)

您在此画布上绘制的任何内容都会直接呈现在立方体上作为纹理。在 Three.js 中实现这一点非常简单，只需要几个步骤。我们需要做的第一件事是创建一个画布元素，并且对于这个特定的示例，配置它以便与`Literally`库一起使用，如下所示：

```js
<div class="fs-container">
  <div id="canvas-output" style="float:left">
  </div>
</div>
...
var canvas = document.createElement("canvas");
$('#canvas-output')[0].appendChild(canvas);
$('#canvas-output').literallycanvas(
  {imageURLPrefix: '../libs/literally/img'});
```

我们只需从 JavaScript 中创建一个`canvas`元素，并将其添加到特定的`div`元素中。通过`literallycanvas`调用，我们可以创建绘图工具，您可以直接在画布上绘制。接下来，我们需要创建一个使用画布绘制作为其输入的纹理：

```js
function createMesh(geom) {

  var canvasMap = new THREE.Texture(canvas);
  var mat = new THREE.MeshPhongMaterial();
  mat.map = canvasMap;
  var mesh = new THREE.Mesh(geom,mat);

  return mesh;
}
```

正如代码所示，您在创建新纹理时所需做的唯一事情就是在传入画布元素的引用时，`new THREE.Texture(canvas)`。这将创建一个使用画布元素作为其材质的纹理。剩下的就是在每次渲染时更新材质，以便在立方体上显示画布绘制的最新版本，如下所示：

```js
function render() {
  stats.update();

  cube.rotation.y += 0.01;
  cube.rotation.x += 0.01;

  cube.material.map.needsUpdate = true;
  requestAnimationFrame(render);
  webGLRenderer.render(scene, camera);
}
```

为了通知 Three.js 我们想要更新纹理，我们只需将纹理的`needsUpdate`属性设置为`true`。在这个示例中，我们已经将画布元素用作最简单的纹理输入。当然，我们可以使用相同的思路来处理到目前为止看到的所有不同类型的地图。在下一个示例中，我们将把它用作凹凸贴图。

### 使用画布作为凹凸贴图

正如我们在本章前面看到的，我们可以使用凹凸贴图创建一个简单的皱纹纹理。在这个地图中，像素的强度越高，皱纹越深。由于凹凸贴图只是一个简单的黑白图像，所以我们可以在画布上创建这个图像，并将该画布用作凹凸贴图的输入。

在下一个示例中，我们使用画布生成一个随机灰度图像，并将该图像用作我们应用于立方体的凹凸贴图的输入。请参见`09-canvas-texture-bumpmap.html`示例。以下截图显示了此示例：

![使用画布作为凹凸贴图](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_20.jpg)

这需要的 JavaScript 代码与我们之前解释的示例并没有太大不同。我们需要创建一个画布元素，并用一些随机噪声填充这个画布。对于噪声，我们使用**Perlin noise**。Perlin noise ([`en.wikipedia.org/wiki/Perlin_noise`](http://en.wikipedia.org/wiki/Perlin_noise)) 生成一个非常自然的随机纹理，正如您在前面的截图中所看到的。我们使用来自[`github.com/wwwtyro/perlin.js`](https://github.com/wwwtyro/perlin.js)的 Perlin noise 函数来实现这一点：

```js
var ctx = canvas.getContext("2d");
function fillWithPerlin(perlin, ctx) {

  for (var x = 0; x < 512; x++) {
    for (var y = 0; y < 512; y++) {
      var base = new THREE.Color(0xffffff);
      var value = perlin.noise(x / 10, y / 10, 0);
      base.multiplyScalar(value);
      ctx.fillStyle = "#" + base.getHexString();
      ctx.fillRect(x, y, 1, 1);
    }
  }
}
```

我们使用`perlin.noise`函数根据画布元素的*x*和*y*坐标创建一个从 0 到 1 的值。这个值用于在画布元素上绘制一个单个像素。对所有像素执行此操作会创建一个随机地图，您也可以在上一张截图的左下角看到。然后可以轻松地将此地图用作凹凸贴图。以下是创建随机地图的方法：

```js
var bumpMap = new THREE.Texture(canvas);

var mat = new THREE.MeshPhongMaterial();
mat.color = new THREE.Color(0x77ff77);
mat.bumpMap = bumpMap;
bumpMap.needsUpdate = true;

var mesh = new THREE.Mesh(geom, mat);
return mesh;
```

### 提示

在这个例子中，我们使用 HTML 画布元素渲染了 Perlin 噪声。Three.js 还提供了一种动态创建纹理的替代方法。`THREE.ImageUtils`对象有一个`generateDataTexture`函数，你可以使用它来创建特定大小的`THREE.DataTexture`纹理。这个纹理包含在`image.data`属性中的`Uint8Array`，你可以直接使用它来设置这个纹理的 RGB 值。

我们用于纹理的最终输入是另一个 HTML 元素：HTML5 视频元素。

## 使用视频输出作为纹理

如果你读过前面关于渲染到画布的段落，你可能会考虑将视频渲染到画布并将其用作纹理的输入。这是一个选择，但是 Three.js（通过 WebGL）已经直接支持使用 HTML5 视频元素。查看`11-video-texture.html`。参考以下截图，了解这个例子的静态图像：

![使用视频输出作为纹理](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_10_21.jpg)

使用视频作为纹理的输入，就像使用画布元素一样，非常容易。首先，我们需要有一个视频元素来播放视频：

```js
<video  id="video"
  style="display: none;
  position: absolute; left: 15px; top: 75px;"
  src="../assets/movies/Big_Buck_Bunny_small.ogv"
  controls="true" autoplay="true">
</video>
```

这只是一个基本的 HTML5 视频元素，我们设置为自动播放。接下来，我们可以配置 Three.js 以将此视频用作纹理的输入，如下所示：

```js
var video  = document.getElementById('video');
texture = new THREE.Texture(video);
texture.minFilter = THREE.LinearFilter;
texture.magFilter = THREE.LinearFilter;
texture.generateMipmaps = false;
```

由于我们的视频不是正方形的，我们需要确保在材质上禁用 mipmap 生成。我们还设置了一些简单的高性能滤镜，因为材质经常变化。现在剩下的就是创建一个网格并设置纹理。在这个例子中，我们使用了`MeshFaceMaterial`和`MeshBasicMaterial`：

```js
var materialArray = [];
materialArray.push(new THREE.MeshBasicMaterial({color: 0x0051ba}));
materialArray.push(new THREE.MeshBasicMaterial({color: 0x0051ba}));
materialArray.push(new THREE.MeshBasicMaterial({color: 0x0051ba}));
materialArray.push(new THREE.MeshBasicMaterial({color: 0x0051ba}));
materialArray.push(new THREE.MeshBasicMaterial({map: texture }));
materialArray.push(new THREE.MeshBasicMaterial({color: 0xff51ba}));

var faceMaterial = new THREE.MeshFaceMaterial(materialArray);
var mesh = new THREE.Mesh(geom,faceMaterial);
```

现在剩下的就是确保在我们的`render`循环中更新纹理，如下所示：

```js
if ( video.readyState === video.HAVE_ENOUGH_DATA ) {
  if (texture) texture.needsUpdate = true;
}
```

在这个例子中，我们只是将视频渲染到立方体的一侧，但由于这是一个普通的纹理，我们可以随心所欲地使用它。例如，我们可以使用自定义 UV 映射沿着立方体的边缘分割它，或者甚至将视频输入用作凹凸贴图或法线贴图的输入。

在 Three.js 版本 r69 中，引入了一个专门用于处理视频的纹理。这个纹理（`THREE.VideoTexture`）包装了你在本节中看到的代码，你可以使用`THREE.VideoTexture`方法作为一种替代方法。以下代码片段显示了如何使用`THREE.VideoTexture`创建纹理（你可以通过查看`11-video-texture.html`示例来查看这个过程）：

```js
var video = document.getElementById('video');
texture = new THREE.VideoTexture(video);
```

# 总结

因此，我们结束了关于纹理的这一章。正如你所看到的，Three.js 中有许多不同类型的纹理，每种都有不同的用途。你可以使用 PNG、JPG、GIF、TGA、DDS 或 PVR 格式的任何图像作为纹理。加载这些图像是异步进行的，所以记得要么使用渲染循环，要么在加载纹理时添加回调。使用纹理，你可以从低多边形模型创建出色的对象，甚至可以使用凹凸贴图和法线贴图添加虚假的详细深度。使用 Three.js，还可以使用 HTML5 画布元素或视频元素轻松创建动态纹理。只需定义一个以这些元素为输入的纹理，并在需要更新纹理时将`needsUpdate`属性设置为`true`。

通过这一章，我们基本上涵盖了 Three.js 的所有重要概念。然而，我们还没有看到 Three.js 提供的一个有趣的功能——**后期处理**。通过后期处理，你可以在场景渲染后添加效果。例如，你可以模糊或着色你的场景，或者使用扫描线添加类似电视的效果。在下一章中，我们将看看后期处理以及如何将其应用到你的场景中。


# 第十一章：自定义着色器和渲染后期处理

我们即将结束这本书，在本章中，我们将看一下我们尚未涉及的 Three.js 的主要特性：渲染后期处理。除此之外，在本章中，我们还将介绍如何创建自定义着色器。本章我们将讨论的主要内容如下：

+   为后期处理设置 Three.js

+   讨论 Three.js 提供的基本后期处理通道，比如`THREE.BloomPass`和`THREE.FilmPass`

+   使用蒙版将效果应用于场景的一部分

+   使用`THREE.TexturePass`来存储渲染结果

+   使用`THREE.ShaderPass`添加更基本的后期处理效果，比如棕褐色滤镜，镜像效果和颜色调整

+   使用`THREE.ShaderPass`进行各种模糊效果和更高级的滤镜

+   通过编写一个简单的着色器创建自定义后期处理效果

在第一章的*介绍 requestAnimationFrame*部分，*使用 Three.js 创建您的第一个 3D 场景*，我们设置了一个渲染循环，我们在整本书中都用来渲染和动画我们的场景。对于后期处理，我们需要对这个设置进行一些更改，以允许 Three.js 对最终渲染进行后期处理。在第一部分中，我们将看看如何做到这一点。

# 为后期处理设置 Three.js

为了为后期处理设置 Three.js，我们需要对我们当前的设置进行一些更改。我们需要采取以下步骤：

1.  创建`THREE.EffectComposer`，我们可以用来添加后期处理通道。

1.  配置`THREE.EffectComposer`，使其渲染我们的场景并应用任何额外的后期处理步骤。

1.  在渲染循环中，使用`THREE.EffectComposer`来渲染场景，应用通道，并显示输出。

和往常一样，我们有一个可以用来实验并用于自己用途的例子。本章的第一个例子可以从`01-basic-effect-composer.html`中访问。您可以使用右上角的菜单修改此示例中使用的后期处理步骤的属性。在这个例子中，我们渲染了一个简单的地球，并为其添加了类似旧电视的效果。这个电视效果是在使用`THREE.EffectComposer`渲染场景之后添加的。以下截图显示了这个例子：

![为后期处理设置 Three.js](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_01.jpg)

## 创建 THREE.EffectComposer

让我们首先看一下您需要包含的额外 JavaScript 文件。这些文件可以在 Three.js 分发的`examples/js/postprocessing`和`examples/js/shaders`目录中找到。

使`THREE.EffectComposer`工作所需的最小设置如下：

```js
<script type="text/javascript" src="../libs/postprocessing/EffectComposer.js"></script>
<script type="text/javascript" src="../libs/postprocessing/MaskPass.js"></script>
<script type="text/javascript" src="../libs/postprocessing/RenderPass.js"></script>
<script type="text/javascript" src="../libs/shaders/CopyShader.js"></script>
<script type="text/javascript" src="../libs/postprocessing/ShaderPass.js"></script>
```

`EffectComposer.js`文件提供了`THREE.EffectComposer`对象，允许我们添加后期处理步骤。`MaskPass.js`，`ShaderPass.js`和`CopyShader.js`在`THREE.EffectComposer`内部使用，`RenderPass.js`允许我们向`THREE.EffectComposer`添加渲染通道。没有这个通道，我们的场景将根本不会被渲染。

在这个例子中，我们添加了两个额外的 JavaScript 文件，为我们的场景添加了类似电影的效果：

```js
<script type="text/javascript" src="../libs/postprocessing/FilmPass.js"></script>
<script type="text/javascript" src="../libs/shaders/FilmShader.js"></script>
```

我们需要做的第一件事是创建`THREE.EffectComposer`。您可以通过将`THREE.WebGLRenderer`传递给它的构造函数来实现：

```js
var webGLRenderer = new THREE.WebGLRenderer();
var composer = new THREE.EffectComposer(webGLRenderer);
```

接下来，我们向这个合成器添加各种*通道*。

### 为后期处理配置 THREE.EffectComposer

每个通道按照添加到`THREE.EffectComposer`的顺序执行。我们添加的第一个通道是`THREE.RenderPass`。接下来的通道渲染了我们的场景，但还没有输出到屏幕上：

```js
var renderPass = new THREE.RenderPass(scene, camera);
composer.addPass(renderPass);
```

要创建`THREE.RenderPass`，我们传入要渲染的场景和要使用的相机。使用`addPass`函数，我们将`THREE.RenderPass`添加到`THREE.EffectComposer`中。下一步是添加另一个通行证，将其结果输出到屏幕上。并非所有可用的通行证都允许这样做——稍后会详细介绍——但是在这个例子中使用的`THREE.FilmPass`允许我们将其通行证的结果输出到屏幕上。要添加`THREE.FilmPass`，我们首先需要创建它并将其添加到 composer 中。生成的代码如下：

```js
var renderPass = new THREE.RenderPass(scene,camera);
var effectFilm = new THREE.FilmPass(0.8, 0.325, 256, false);
effectFilm.renderToScreen = true;

var composer = new THREE.EffectComposer(webGLRenderer);
composer.addPass(renderPass);
composer.addPass(effectFilm);
```

正如您所看到的，我们创建了`THREE.FilmPass`并将`renderToScreen`属性设置为`true`。这个通行证被添加到`THREE.EffectComposer`之后的`renderPass`之后，所以当使用这个 composer 时，首先渲染场景，通过`THREE.FilmPass`，我们也可以在屏幕上看到输出。

### 更新渲染循环

现在我们只需要对渲染循环进行一点修改，以使用 composer 而不是`THREE.WebGLRenderer`：

```js
var clock = new THREE.Clock();
function render() {
  stats.update();

  var delta = clock.getDelta();
  orbitControls.update(delta);

  sphere.rotation.y += 0.002;

  requestAnimationFrame(render);
  composer.render(delta);
}
```

我们唯一的修改是删除了`webGLRenderer.render(scene, camera)`，并用`composer.render(delta)`替换它。这将在`EffectComposer`上调用渲染函数，而`EffectComposer`又使用传入的`THREE.WebGLRenderer`，由于我们将`FilmPass`的`renderToScreen`设置为`true`，因此`FilmPass`的结果显示在屏幕上。

有了这个基本设置，我们将在接下来的几节中看看可用的后期处理通行证。

# 后期处理通行证

Three.js 提供了许多后期处理通行证，您可以直接在`THREE.EffectComposer`中使用。请注意，最好尝试本章中的示例，以查看这些通行证的结果并理解发生了什么。以下表格概述了可用的通行证：

| 通行证名称 | 描述 |
| --- | --- |
| `THREE.BloomPass` | 这是一种效果，使光亮区域渗入较暗区域。这模拟了相机被极其明亮的光所淹没的效果。 |
| `THREE.DotScreenPass` | 这在屏幕上应用了一层代表原始图像的黑点。 |
| `THREE.FilmPass` | 这通过应用扫描线和失真来模拟电视屏幕。 |
| `THREE.GlitchPass` | 这在屏幕上显示一个电子故障，以随机时间间隔。 |
| `THREE.MaskPass` | 这允许您对当前图像应用蒙版。后续通行证仅应用于蒙版区域。 |
| `THREE.RenderPass` | 这根据提供的场景和相机渲染场景。 |
| `THREE.SavePass` | 当执行此通行证时，它会复制当前的渲染步骤，以便以后使用。这个通行证在实践中并不那么有用，我们不会在任何示例中使用它。 |
| `THREE.ShaderPass` | 这允许您为高级或自定义后期处理通行证传递自定义着色器。 |
| `THREE.TexturePass` | 这将当前 composer 的状态存储在一个纹理中，您可以将其用作其他`EffectComposer`实例的输入。 |

让我们从一些简单的通行证开始。

## 简单的后期处理通行证

对于简单的通行证，我们将看看我们可以用`THREE.FilmPass`，`THREE.BloomPass`和`THREE.DotScreenPass`做些什么。对于这些通行证，有一个例子可用，`02-post-processing-simple`，允许您尝试这些通行证，并查看它们如何以不同的方式影响原始输出。以下屏幕截图显示了这个例子：

![Simple postprocessing passes](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_02.jpg)

在这个例子中，我们同时显示了四个场景，并且在每个场景中，添加了不同的后期处理通行证。左上角的一个显示了`THREE.BloomPass`，右上角的一个显示了`THREE.FilmPass`，左下角的一个显示了`THREE.DotScreenPass`，右下角的一个显示了原始渲染。

在这个例子中，我们还使用`THREE.ShaderPass`和`THREE.TexturePass`来重用原始渲染的输出作为其他三个场景的输入。因此，在我们查看各个 pass 之前，让我们先看看这两个 pass：

```js
var renderPass = new THREE.RenderPass(scene, camera);
var effectCopy = new THREE.ShaderPass(THREE.CopyShader);
effectCopy.renderToScreen = true;

var composer = new THREE.EffectComposer(webGLRenderer);
composer.addPass(renderPass);
composer.addPass(effectCopy);

var renderScene = new THREE.TexturePass(composer.renderTarget2);
```

在这段代码中，我们设置了`THREE.EffectComposer`，它将输出默认场景（右下角的场景）。这个 composer 有两个 passes。`THREE.RenderPass`渲染场景，而`THREE.ShaderPass`在配置为`THREE.CopyShader`时，如果将`renderToScreen`属性设置为`true`，则将输出渲染到屏幕上。如果你看例子，你会发现我们展示了同一个场景四次，但每次都应用了不同的效果。我们可以使用`THREE.RenderPass`从头开始渲染场景四次，但这样有点浪费，因为我们可以重用第一个 composer 的输出。为此，我们创建了`THREE.TexturePass`并传入了`composer.renderTarget2`的值。现在我们可以使用`renderScene`变量作为其他 composer 的输入，而无需从头开始渲染场景。让我们首先重新审视`THREE.FilmPass`，看看我们如何使用`THREE.TexturePass`作为输入。

### 使用 THREE.FilmPass 创建类似电视的效果

在本章的第一部分，我们已经看过如何创建`THREE.FilmPass`，现在让我们看看如何将这个效果与上一节的`THREE.TexturePass`一起使用：

```js
var effectFilm = new THREE.FilmPass(0.8, 0.325, 256, false);
effectFilm.renderToScreen = true;

var composer4 = new THREE.EffectComposer(webGLRenderer);
**composer4.addPass(renderScene);**
composer4.addPass(effectFilm);
```

使用`THREE.TexturePass`的唯一步骤是将它作为你的 composer 中的第一个 pass 添加。接下来，我们只需添加`THREE.FilmPass`，效果就会应用上。`THREE.FilmPass`本身有四个参数：

| 属性 | 描述 |
| --- | --- |
| `noiseIntensity` | 这个属性允许你控制场景看起来有多粗糙。 |
| `scanlinesIntensity` | `THREE.FilmPass`向场景添加了一些扫描线。使用这个属性，你可以定义这些扫描线的显示程度。 |
| `scanLinesCount` | 可以使用这个属性控制显示的扫描线数量。 |
| `grayscale` | 如果设置为`true`，输出将被转换为灰度。 |

实际上，你可以有两种方式传入这些参数。在这个例子中，我们将它们作为构造函数的参数传入，但你也可以直接设置它们，如下所示：

```js
effectFilm.uniforms.grayscale.value = controls.grayscale;
effectFilm.uniforms.nIntensity.value = controls.noiseIntensity;
effectFilm.uniforms.sIntensity.value = controls.scanlinesIntensity;
effectFilm.uniforms.sCount.value = controls.scanlinesCount;
```

在这种方法中，我们使用了`uniforms`属性，它用于直接与 WebGL 通信。在本章稍后讨论创建自定义着色器时，我们将更深入地了解`uniforms`；现在你只需要知道，通过这种方式，你可以直接更新后处理 passes 和着色器的配置，并直接看到结果。

### 使用 THREE.BloomPass 向场景添加泛光效果

你在左上角看到的效果称为泛光效果。当应用泛光效果时，场景的亮区域会更加突出，并且“渗透”到暗区域。创建`THREE.BloomPass`的代码如下所示：

```js
var effectCopy = new THREE.ShaderPass(THREE.CopyShader);
effectCopy.renderToScreen = true;
...
var bloomPass = new THREE.BloomPass(3, 25, 5, 256);
var composer3 = new THREE.EffectComposer(webGLRenderer);
composer3.addPass(renderScene);
composer3.addPass(bloomPass);
composer3.addPass(effectCopy);
```

如果你将这个与我们用`THREE.FilmPass`使用的`THREE.EffectComposer`进行比较，你会注意到我们添加了一个额外的 pass，`effectCopy`。这一步，我们也用于正常的输出，不会添加任何特殊效果，只是将最后一个 pass 的输出复制到屏幕上。我们需要添加这一步，因为`THREE.BloomPass`不能直接渲染到屏幕上。

下表列出了你可以在`THREE.BloomPass`上设置的属性：

| 属性 | 描述 |
| --- | --- |
| `Strength` | 这是泛光效果的强度。数值越高，亮区域就会更亮，而且会“渗透”到暗区域。 |
| `kernelSize` | 这个属性控制泛光效果的偏移量。 |
| `sigma` | 使用`sigma`属性，你可以控制泛光效果的锐度。数值越高，泛光效果看起来就越模糊。 |
| `分辨率` | `分辨率` 属性定义了绽放效果的创建精度。如果设置得太低，结果会显得有点方块。 |

更好地理解这些属性的方法就是使用之前提到的例子`02-post-processing-simple`进行实验。以下截图显示了具有高内核和 sigma 大小以及低强度的绽放效果：

![使用 THREE.BloomPass 为场景添加绽放效果](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_03.jpg)

我们将要看的最后一个简单效果是 `THREE.DotScreenPass`。

### 将场景输出为一组点

使用 `THREE.DotScreenPass` 与使用 `THREE.BloomPass` 非常相似。我们刚刚看到了 `THREE.BloomPass` 的效果。现在让我们看看 `THREE.DotScreenPass` 的代码：

```js
var dotScreenPass = new THREE.DotScreenPass();
var composer1 = new THREE.EffectComposer(webGLRenderer);
composer1.addPass(renderScene);
composer1.addPass(dotScreenPass);
composer1.addPass(effectCopy);
```

通过这种效果，我们再次必须添加 `effectCopy` 将结果输出到屏幕。`THREE.DotScreenPass` 也可以通过一些属性进行配置，如下所示：

| 属性 | 描述 |
| --- | --- |
| `中心` | 通过 `中心` 属性，你可以微调点的偏移方式。 |
| `角度` | 点是以一定的方式对齐的。通过 `角度` 属性，你可以改变这种对齐方式。 |
| `缩放` | 通过这个，我们可以设置要使用的点的大小。`缩放`越低，点就越大。 |

对其他着色器适用于这个着色器。通过实验，更容易找到正确的设置。

![将场景输出为一组点](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_04.jpg)

### 在同一屏幕上显示多个渲染器的输出

本节不涉及如何使用后期处理效果的细节，而是解释如何在同一屏幕上获取所有四个 `THREE.EffectComposer` 实例的输出。首先，让我们看看用于此示例的渲染循环：

```js
function render() {
  stats.update();

  var delta = clock.getDelta();
  orbitControls.update(delta);

  sphere.rotation.y += 0.002;

  requestAnimationFrame(render);

  webGLRenderer.autoClear = false;
  webGLRenderer.clear();

  webGLRenderer.setViewport(0, 0, 2 * halfWidth, 2 * halfHeight);
  composer.render(delta);

  webGLRenderer.setViewport(0, 0, halfWidth, halfHeight);
  composer1.render(delta);

  webGLRenderer.setViewport(halfWidth, 0, halfWidth, halfHeight);
  composer2.render(delta);

  webGLRenderer.setViewport(0, halfHeight, halfWidth, halfHeight);
  composer3.render(delta);

  webGLRenderer.setViewport(halfWidth, halfHeight, halfWidth, halfHeight);
  composer4.render(delta);
}
```

这里要注意的第一件事是，我们将 `webGLRenderer.autoClear` 属性设置为 `false`，然后显式调用 `clear()` 函数。如果我们不在每次在 composer 上调用 `render()` 函数时这样做，之前渲染的场景将被清除。通过这种方法，我们只在渲染循环的开始清除一切。

为了避免所有的 composer 在同一空间渲染，我们将`webGLRenderer`的视口设置为屏幕的不同部分。这个函数接受四个参数：`x`、`y`、`宽度`和`高度`。正如你在代码示例中看到的，我们使用这个函数将屏幕分成四个区域，并让 composer 分别渲染到它们的个别区域。请注意，如果需要，你也可以在多个场景、相机和`WebGLRenderer`上使用这种方法。

在本节开始的表格中，我们还提到了 `THREE.GlitchPass`。使用这个渲染通道，你可以为你的场景添加一种电子故障效果。这种效果和你之前看到的其他效果一样容易使用。要使用它，首先在你的 HTML 页面中包含以下两个文件：

```js
<script type="text/javascript" src="../libs/postprocessing/GlitchPass.js"></script>
<script type="text/javascript" src="../libs/postprocessing/DigitalGlitch.js"></script>
```

然后，创建 `THREE.GlitchPass` 对象，如下所示：

```js
var effectGlitch = new THREE.GlitchPass(64);
effectGlitch.renderToScreen = true;
```

结果是一个场景，其中结果被正常渲染，只是在随机间隔发生故障，如下截图所示：

![在同一屏幕上显示多个渲染器的输出](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_19.jpg)

到目前为止，我们只链接了一些简单的通道。在下一个例子中，我们将配置一个更复杂的 `THREE.EffectComposer` 并使用蒙版将效果应用到屏幕的一部分。

## 使用蒙版创建高级 EffectComposer 流

在之前的例子中，我们将后期处理通道应用到了整个屏幕上。然而，Three.js 也有能力只将通道应用到特定区域。在本节中，我们将执行以下步骤：

1.  创建一个用作背景图像的场景。

1.  创建一个看起来像地球的球体的场景。

1.  创建一个看起来像火星的球体的场景。

1.  创建 `EffectComposer`，将这三个场景渲染成一个单一的图像。

1.  将 *colorify* 效果应用到渲染为火星的球体上。

1.  对渲染为地球的球体应用棕褐色效果。

这可能听起来很复杂，但实际上实现起来非常容易。首先，让我们来看看我们在`03-post-processing-masks.html`示例中的目标结果。以下截图显示了这些步骤的结果：

![使用蒙版的高级 EffectComposer 流程](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_05.jpg)

首先，我们需要做的是设置我们将渲染的各种场景，如下所示：

```js
var sceneEarth = new THREE.Scene();
var sceneMars = new THREE.Scene();
var sceneBG = new THREE.Scene();
```

要创建地球和火星球体，我们只需使用正确的材质和纹理创建球体，并将它们添加到各自的场景中，如下面的代码所示：

```js
var sphere = createEarthMesh(new THREE.SphereGeometry(10, 40, 40));
sphere.position.x = -10;
var sphere2 = createMarshMesh(new THREE.SphereGeometry(5, 40, 40));
sphere2.position.x = 10;
sceneEarth.add(sphere);
sceneMars.add(sphere2);
```

我们还需要像对待普通场景一样向场景中添加一些灯光，但我们不会在这里展示（有关更多详细信息，请参见第三章，“Three.js 中可用的不同光源”，）。唯一需要记住的是，灯光不能添加到不同的场景，因此您需要为两个场景创建单独的灯光。这就是我们需要为这两个场景做的所有设置。

对于背景图像，我们创建`THREE.OrthoGraphicCamera`。请记住，从第二章，“Three.js 场景的基本组件”中，正交投影中对象的大小不取决于距离，因此这也是创建固定背景的好方法。以下是我们创建`THREE.OrthoGraphicCamera`的方法：

```js
var cameraBG = new THREE.OrthographicCamera(-window.innerWidth, window.innerWidth, window.innerHeight, -window.innerHeight, -10000, 10000);
cameraBG.position.z = 50;

var materialColor = new THREE.MeshBasicMaterial({ map: THREE.ImageUtils.loadTexture("../assets/textures/starry-deep-outer-space-galaxy.jpg"), depthTest: false });
var bgPlane = new THREE.Mesh(new THREE.PlaneGeometry(1, 1), materialColor);
bgPlane.position.z = -100;
bgPlane.scale.set(window.innerWidth * 2, window.innerHeight * 2, 1);
sceneBG.add(bgPlane);
```

我们不会对这部分详细说明，但我们必须采取一些步骤来创建背景图像。首先，我们从背景图像创建材质，并将此材质应用于简单的平面。接下来，我们将此平面添加到场景中，并将其缩放以完全填满整个屏幕。因此，当我们使用这个相机渲染这个场景时，我们的背景图像会被拉伸到屏幕的宽度。

现在我们有了三个场景，我们可以开始设置我们的通道和`THREE.EffectComposer`。让我们首先看一下完整的通道链，之后我们再看看各个通道：

```js
var composer = new THREE.EffectComposer(webGLRenderer);
composer.renderTarget1.stencilBuffer = true;
composer.renderTarget2.stencilBuffer = true;

composer.addPass(bgPass);
composer.addPass(renderPass);
composer.addPass(renderPass2);

composer.addPass(marsMask);
composer.addPass(effectColorify1);
composer.addPass(clearMask);

composer.addPass(earthMask);
composer.addPass(effectSepia);
composer.addPass(clearMask);

composer.addPass(effectCopy);
```

要使用蒙版，我们需要以不同的方式创建`THREE.EffectComposer`。在这种情况下，我们需要创建一个新的`THREE.WebGLRenderTarget`，并将内部使用的渲染目标的`stencilBuffer`属性设置为`true`。模板缓冲区是一种特殊类型的缓冲区，用于限制渲染区域。因此，通过启用模板缓冲区，我们可以使用我们的蒙版。首先，让我们来看一下添加的前三个通道。这三个通道分别渲染背景、地球场景和火星场景，如下所示：

```js
var bgPass = new THREE.RenderPass(sceneBG, cameraBG);
var renderPass = new THREE.RenderPass(sceneEarth, camera);
renderPass.clear = false;
var renderPass2 = new THREE.RenderPass(sceneMars, camera);
renderPass2.clear = false;
```

这里没有什么新的，除了我们将两个通道的`clear`属性设置为`false`。如果我们不这样做，我们只会看到`renderPass2`的输出，因为它会在开始渲染之前清除一切。如果你回顾一下`THREE.EffectComposer`的代码，接下来的三个通道是`marsMask`，`effectColorify`和`clearMask`。首先，我们来看一下这三个通道是如何定义的：

```js
var marsMask = new THREE.MaskPass(sceneMars, camera );
var clearMask = new THREE.ClearMaskPass();
var effectColorify = new THREE.ShaderPass(THREE.ColorifyShader );
effectColorify.uniforms['color'].value.setRGB(0.5, 0.5, 1);
```

这三个通道中的第一个是`THREE.MaskPass`。创建`THREE.MaskPass`时，您需要像为`THREE.RenderPass`一样传入一个场景和一个相机。`THREE.MaskPass`将在内部渲染此场景，但不会在屏幕上显示，而是使用此信息创建蒙版。当`THREE.MaskPass`添加到`THREE.EffectComposer`时，所有后续通道将仅应用于`THREE.MaskPass`定义的蒙版，直到遇到`THREE.ClearMaskPass`。在这个例子中，这意味着`effectColorify`通道，它添加了蓝色的发光效果，仅应用于`sceneMars`中渲染的对象。

我们使用相同的方法在地球对象上应用了一个棕褐色滤镜。我们首先基于地球场景创建一个蒙版，并在`THREE.EffectComposer`中使用这个蒙版。在`THREE.MaskPass`之后，我们添加我们想要应用的效果（在这种情况下是`effectSepia`），一旦完成，我们添加`THREE.ClearMaskPass`来移除蒙版。对于这个特定的`THREE.EffectComposer`的最后一步是我们已经看到的。我们需要将最终结果复制到屏幕上，我们再次使用`effectCopy`通道来实现。

在使用`THREE.MaskPass`时还有一个有趣的额外属性，那就是`inverse`属性。如果将此属性设置为`true`，则蒙版将被反转。换句话说，效果将应用于除传入`THREE.MaskPass`的场景之外的所有内容。这在下面的截图中显示出来：

![使用蒙版的高级 EffectComposer 流程](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_06.jpg)

到目前为止，我们已经使用了 Three.js 提供的标准通道来实现我们的效果。Three.js 还提供了`THREE.ShaderPass`，可以用于自定义效果，并带有大量可以使用和实验的着色器。 

## 使用 THREE.ShaderPass 进行自定义效果

使用`THREE.ShaderPass`，我们可以通过传入自定义着色器为我们的场景应用大量额外的效果。这一部分分为三个部分。首先，我们将看一下以下一组简单着色器：

| 名称 | 描述 |
| --- | --- |
| `THREE.MirrorShader` | 这会为屏幕的一部分创建一个镜像效果。 |
| `THREE.HueSaturationShader` | 这允许你改变颜色的*色调*和*饱和度*。 |
| `THREE.VignetteShader` | 这应用了一个晕影效果。这个效果在图像中心周围显示出暗色边框。 |
| `THREE.ColorCorrectionShader` | 使用这个着色器，你可以改变颜色分布。 |
| `THREE.RGBShiftShader` | 这个着色器分离了颜色的红色、绿色和蓝色分量。 |
| `THREE.BrightnessContrastShader` | 这改变了图像的亮度和对比度。 |
| `THREE.ColorifyShader` | 这将在屏幕上应用颜色叠加。 |
| `THREE.SepiaShader` | 这在屏幕上创建了一个棕褐色的效果。 |
| `THREE.KaleidoShader` | 这为场景添加了一个万花筒效果，围绕场景中心提供了径向反射。 |
| `THREE.LuminosityShader` | 这提供了一个亮度效果，显示了场景的亮度。 |
| `THREE.TechnicolorShader` | 这模拟了旧电影中可以看到的双色技术色彩效果。 |

接下来，我们将看一些提供一些模糊相关效果的着色器：

| 名称 | 描述 |
| --- | --- |
| `THREE.HorizontalBlurShader` 和 `THREE.VerticalBlurShader` | 这些将模糊效果应用到整个场景。 |
| `THREE.HorizontalTiltShiftShader` 和 `THREE.VerticalTiltShiftShader` | 这些重新创建了*移轴*效果。使用移轴效果，可以确保只有图像的一部分是清晰的，从而创建看起来像微缩的场景。 |
| `THREE.TriangleBlurShader` | 这使用基于三角形的方法应用了模糊效果。 |

最后，我们将看一些提供高级效果的着色器：

| 名称 | 描述 |
| --- | --- |
| `THREE.BleachBypassShader` | 这会创建一个*漂白副本*效果。使用这个效果，图像上会应用一个类似银色的叠加。 |
| `THREE.EdgeShader` | 这个着色器可以用来检测图像中的锐利边缘并突出显示它们。 |
| `THREE.FXAAShader` | 这个着色器在后期处理阶段应用了抗锯齿效果。如果在渲染过程中应用抗锯齿效果太昂贵，可以使用这个。 |
| `THREE.FocusShader` | 这是一个简单的着色器，可以使中心区域清晰渲染，边缘模糊。 |

我们不会详细介绍所有的着色器，因为如果您了解了一个着色器的工作原理，您基本上就知道了其他着色器的工作原理。在接下来的章节中，我们将重点介绍一些有趣的着色器。您可以使用每个章节提供的交互式示例来尝试其他着色器。

### 提示

Three.js 还提供了两种高级的后期处理效果，允许您在场景中应用*bokeh*效果。Bokeh 效果可以使场景的一部分产生模糊效果，同时使主要主题非常清晰。Three.js 提供了`THREE.BrokerPass`，您可以使用它来实现这一点，或者使用`THREE.BokehShader2`和`THREE.DOFMipMapShader`，您可以与`THREE.ShaderPass`一起使用。这些着色器的示例可以在 Three.js 网站上找到，网址为[`threejs.org/examples/webgl_postprocessing_dof2.html`](http://threejs.org/examples/webgl_postprocessing_dof2.html)和[`threejs.org/examples/webgl_postprocessing_dof.html`](http://threejs.org/examples/webgl_postprocessing_dof.html)。

我们先从一些简单的着色器开始。

### 简单着色器

为了尝试基本的着色器，我们创建了一个示例，您可以在其中玩耍着色器，并直接在场景中看到效果。您可以在`04-shaderpass-simple.html`中找到这个示例。以下截图显示了这个示例：

![简单着色器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_07.jpg)

通过右上角的菜单，您可以选择要应用的特定着色器，并通过各种下拉菜单设置所选着色器的属性。例如，下面的截图显示了`RGBShiftShader`的效果：

![简单着色器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_08.jpg)

当您改变着色器的属性之一时，结果会直接更新。对于这个例子，我们直接在着色器上设置了改变的值。例如，当`RGBShiftShader`的值发生变化时，我们会像这样更新着色器：

```js
this.changeRGBShifter = function() {
  rgbShift.uniforms.amount.value = controls.rgbAmount;
  rgbShift.uniforms.angle.value = controls.angle;
}
```

让我们来看看其他一些着色器。以下图像显示了`VignetteShader`的结果：

![简单着色器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_09.jpg)

`MirrorShader`有以下效果：

![简单着色器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_10.jpg)

通过后期处理，我们还可以应用极端的效果。`THREE.KaleidoShader`就是一个很好的例子。如果您从右上角的菜单中选择这个着色器，您会看到以下效果：

![简单着色器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_11.jpg)

简单着色器就介绍到这里。正如您所看到的，它们非常多才多艺，可以创造出非常有趣的效果。在这个例子中，我们每次应用了一个着色器，但您可以向`THREE.EffectComposer`添加尽可能多的`THREE.ShaderPass`步骤。

### 模糊着色器

在这一部分，我们不会深入代码；我们只会展示各种模糊着色器的结果。您可以使用`05-shaderpass-blur.html`示例来进行实验。以下场景使用`HorizontalBlurShader`和`VerticalBlurShader`进行了模糊处理，您将在接下来的段落中了解到这两种着色器：

![模糊着色器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_12.jpg)

前面的图像显示了`THREE.HorizontalBlurShader`和`THREE.VerticalBlurShader`。您可以看到效果是一个模糊的场景。除了这两种模糊效果，Three.js 还提供了另一个着色器来模糊图像，即`THREE.TriangleShader`，如下所示。例如，您可以使用这个着色器来描绘运动模糊，就像下面的截图所示：

![模糊着色器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_13.jpg)

最后一个类似模糊的效果是由`THREE.HorizontalTiltShiftShader`和`THREE.VerticalTiltShiftShader`提供的。这个着色器不会使整个场景模糊，而只会模糊一个小区域。这提供了一种称为*tilt shift*的效果。这经常用于从普通照片中创建微缩场景。以下图像显示了这种效果：

![模糊着色器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_14.jpg)

### 高级着色器

对于高级着色器，我们将做与之前的模糊着色器相同的事情。我们只会展示着色器的输出。有关如何配置它们的详细信息，请查看`06-shaderpass-advanced.html`示例。以下截图显示了这个示例：

![高级着色器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_15.jpg)

前面的例子展示了`THREE.EdgeShader`。使用这个着色器，您可以检测场景中物体的边缘。

下一个着色器是`THREE.FocusShader`。这个着色器只在屏幕中心呈现焦点，如下截图所示：

![高级着色器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_16.jpg)

到目前为止，我们只使用了 Three.js 提供的着色器。但是，自己创建着色器也非常容易。

# 创建自定义后期处理着色器

在本节中，您将学习如何创建一个自定义着色器，可以在后期处理中使用。我们将创建两种不同的着色器。第一个将把当前图像转换为灰度图像，第二个将通过减少可用颜色的数量将图像转换为 8 位图像。请注意，创建顶点和片段着色器是一个非常广泛的主题。在本节中，我们只是触及了这些着色器可以做什么以及它们是如何工作的表面。有关更深入的信息，您可以在[`www.khronos.org/webgl/`](http://www.khronos.org/webgl/)找到 WebGL 规范。一个充满示例的额外好资源是 Shadertoy，网址为[`www.shadertoy.com/`](https://www.shadertoy.com/)。

## 自定义灰度着色器

要为 Three.js（以及其他 WebGL 库）创建自定义着色器，您需要实现两个组件：顶点着色器和片段着色器。顶点着色器可用于更改单个顶点的位置，片段着色器用于确定单个像素的颜色。对于后期处理着色器，我们只需要实现片段着色器，并且可以保留 Three.js 提供的默认顶点着色器。在查看代码之前要强调的一个重要点是，GPU 通常支持多个着色器管线。这意味着在顶点着色器步骤中，多个着色器可以并行运行，这也适用于片段着色器步骤。

让我们首先看一下应用灰度效果到我们的图像的着色器的完整源代码（`custom-shader.js`）：

```js
THREE.CustomGrayScaleShader = {

  uniforms: {

    "tDiffuse": { type: "t", value: null },
    "rPower":  { type: "f", value: 0.2126 },
    "gPower":  { type: "f", value: 0.7152 },
    "bPower":  { type: "f", value: 0.0722 }

  },

  vertexShader: [
    "varying vec2 vUv;",
    "void main() {",
      "vUv = uv;",
      "gl_Position = projectionMatrix * modelViewMatrix * vec4( position, 1.0 );",
    "}"
  ].join("\n"),

  fragmentShader: [

    "uniform float rPower;",
    "uniform float gPower;",
    "uniform float bPower;",
    "uniform sampler2D tDiffuse;",

    "varying vec2 vUv;",

    "void main() {",
      "vec4 texel = texture2D( tDiffuse, vUv );",
      "float gray = texel.r*rPower + texel.g*gPower+ texel.b*bPower;",
      "gl_FragColor = vec4( vec3(gray), texel.w );",
    "}"
  ].join("\n")
};
```

从代码中可以看出，这不是 JavaScript。当您编写着色器时，您会用**OpenGL 着色语言**（**GLSL**）编写它们，它看起来很像 C 编程语言。有关 GLSL 的更多信息，请访问[`www.khronos.org/opengles/sdk/docs/manglsl/`](http://www.khronos.org/opengles/sdk/docs/manglsl/)。

让我们首先看一下这个顶点着色器：

```js
"varying vec2 vUv;","void main() {",
  "vUv = uv;",
  "gl_Position = projectionMatrix * modelViewMatrix * vec4( position, 1.0 );",
  "}"
```

对于后期处理，这个着色器实际上不需要做任何事情。您在上面看到的代码是 Three.js 实现顶点着色器的标准方式。它使用`projectionMatrix`，这是从相机的投影，以及`modelViewMatrix`，它将对象的位置映射到世界位置，来确定在屏幕上渲染对象的位置。

对于后期处理，这段代码中唯一有趣的事情是`uv`值，它指示从纹理中读取的 texel，通过"`varying` `vec2` `vUv`"变量传递到片段着色器。我们将使用`vUV`值在片段着色器中获取正确的像素进行处理。让我们看看片段着色器并了解代码在做什么。我们从以下变量声明开始：

```js
"uniform float rPower;",
"uniform float gPower;",
"uniform float bPower;",
"uniform sampler2D tDiffuse;",

"varying vec2 vUv;",
```

在这里，我们看到`uniforms`属性的四个实例。`uniforms`属性的实例具有从 JavaScript 传递到着色器的值，并且对于处理的每个片段都是相同的。在这种情况下，我们传递了三个浮点数，由`f`类型标识（用于确定要包含在最终灰度图像中的颜色的比例），以及一个纹理（`tDiffuse`），由`t`类型标识。此纹理包含来自`THREE.EffectComposer`的上一次传递的图像。Three.js 确保它正确地传递给此着色器，我们可以从 JavaScript 自己设置`uniforms`属性的其他实例。在我们可以从 JavaScript 使用这些 uniforms 之前，我们必须定义此着色器可用的`uniforms`属性。这是在着色器文件的顶部完成的：

```js
uniforms: {

  "tDiffuse": { type: "t", value: null },
  "rPower":  { type: "f", value: 0.2126 },
  "gPower":  { type: "f", value: 0.7152 },
  "bPower":  { type: "f", value: 0.0722 }

},
```

此时，我们可以从 Three.js 接收配置参数，并已经接收到我们想要修改的图像。让我们来看一下将每个像素转换为灰色像素的代码：

```js
"void main() {",
  "vec4 texel = texture2D( tDiffuse, vUv );",
  "float gray = texel.r*rPower + texel.g*gPower + texel.b*bPower;",
  "gl_FragColor = vec4( vec3(gray), texel.w );"
```

这里发生的是，我们从传入的纹理中获取正确的像素。我们通过使用`texture2D`函数来实现这一点，其中我们传入我们当前的图像（`tDiffuse`）和我们想要分析的像素（`vUv`）的位置。结果是一个包含颜色和不透明度（`texel.w`）的纹素（纹理中的像素）。

接下来，我们使用此`texel`的`r`、`g`和`b`属性来计算灰度值。此灰度值设置为`gl_FragColor`变量，最终显示在屏幕上。有了这个，我们就有了自己的自定义着色器。使用此着色器就像使用其他着色器一样。首先，我们只需要设置`THREE.EffectComposer`：

```js
var renderPass = new THREE.RenderPass(scene, camera);

var effectCopy = new THREE.ShaderPass(THREE.CopyShader);
effectCopy.renderToScreen = true;

var shaderPass = new THREE.ShaderPass(THREE.CustomGrayScaleShader);

var composer = new THREE.EffectComposer(webGLRenderer);
composer.addPass(renderPass);
composer.addPass(shaderPass);
composer.addPass(effectCopy);
```

在渲染循环中调用`composer.render(delta)`。如果我们想在运行时更改此着色器的属性，我们只需更新我们定义的`uniforms`属性：

```js
shaderPass.enabled = controls.grayScale;
shaderPass.uniforms.rPower.value = controls.rPower;
shaderPass.uniforms.gPower.value = controls.gPower;
shaderPass.uniforms.bPower.value = controls.bPower;
```

结果可以在`07-shaderpass-custom.html`中看到。以下屏幕截图显示了此示例：

![自定义灰度着色器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_17.jpg)

让我们创建另一个自定义着色器。这次，我们将把 24 位输出减少到较低的位数。

## 创建自定义位着色器

通常，颜色表示为 24 位值，给我们大约 1600 万种不同的颜色。在计算机的早期，这是不可能的，颜色通常表示为 8 位或 16 位颜色。使用此着色器，我们将自动将我们的 24 位输出转换为 8 位的颜色深度（或任何您想要的）。

由于它与我们之前的示例没有变化，我们将跳过顶点着色器，直接列出`uniforms`属性的实例：

```js
uniforms: {

  "tDiffuse": { type: "t", value: null },
  "bitSize":  { type: "i", value: 4 }

}
```

以下是片段着色器本身：

```js
fragmentShader: [

  "uniform int bitSize;",

  "uniform sampler2D tDiffuse;",

  "varying vec2 vUv;",

  "void main() {",

    "vec4 texel = texture2D( tDiffuse, vUv );",
    "float n = pow(float(bitSize),2.0);",
    "float newR = floor(texel.r*n)/n;",
    "float newG = floor(texel.g*n)/n;",
    "float newB = floor(texel.b*n)/n;",

    "gl_FragColor = vec4(newR, newG, newB, texel.w );",

  "}"

].join("\n")
```

我们定义了两个`uniforms`属性的实例，用于配置此着色器。第一个是 Three.js 用于传递当前屏幕的实例，第二个是我们自己定义的整数（`type:` `"i"`），用作我们希望以颜色深度渲染结果的实例。代码本身非常简单：

+   我们首先从纹理和基于传入的`vUv`像素位置的`tDiffuse`中获取`texel`。

+   通过计算`bitSize`属性的 2 的`bitSize`次幂（`pow(float(bitSize),2.0))`来计算我们可以拥有的颜色数量。

+   接下来，我们通过将值乘以`n`，四舍五入，`(floor(texel.r*n))`，然后再除以`n`，来计算`texel`的颜色的新值。

+   结果设置为`gl_FragColor`（红色、绿色和蓝色值以及不透明度），并显示在屏幕上。

您可以在与我们之前的自定义着色器相同的示例中查看此自定义着色器的结果，即`07-shaderpass-custom.html`。以下屏幕截图显示了此示例：

![创建自定义位着色器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_11_18.jpg)

这就是关于后期处理的章节。

# 总结

在本章中，我们讨论了许多不同的后期处理选项。正如你所看到的，创建`THREE.EffectComposer`并将通道链接在一起实际上非常容易。你只需要记住一些事情。并非所有的通道都会输出到屏幕上。如果你想要输出到屏幕，你可以始终使用`THREE.ShaderPass`和`THREE.CopyShader`。向 composer 添加通道的顺序很重要。效果是按照这个顺序应用的。如果你想要重用来自特定`THREE.EffectComposer`实例的结果，你可以使用`THREE.TexturePass`。当你的`THREE.EffectComposer`中有多个`THREE.RenderPass`时，确保将`clear`属性设置为`false`。如果不这样做，你只会看到最后一个`THREE.RenderPass`步骤的输出。如果你只想对特定对象应用效果，你可以使用`THREE.MaskPass`。当你完成遮罩后，用`THREE.ClearMaskPass`清除遮罩。除了 Three.js 提供的标准通道之外，还有大量的标准着色器可用。你可以将这些与`THREE.ShaderPass`一起使用。使用 Three.js 的标准方法非常容易创建用于后期处理的自定义着色器。你只需要创建一个片段着色器。

到目前为止，我们基本上涵盖了关于 Three.js 的所有知识。在下一章，也就是最后一章，我们将看一看一个名为**Physijs**的库，你可以用它来扩展 Three.js 的物理功能，并应用碰撞、重力和约束。
