# Three.js 学习手册（一）

> 原文：[`zh.annas-archive.org/md5/5001B8D716B9182B26C655FCB6BE8F50`](https://zh.annas-archive.org/md5/5001B8D716B9182B26C655FCB6BE8F50)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

在过去的几年中，浏览器变得更加强大，并成为交付复杂应用程序和图形的平台。其中大部分是标准的 2D 图形。大多数现代浏览器已经采用了 WebGL，这使您不仅可以在浏览器中创建 2D 应用程序和图形，还可以利用 GPU 的功能创建美丽且性能良好的 3D 应用程序。

然而，直接编程 WebGL 非常复杂。您需要了解 WebGL 的内部细节，并学习复杂的着色器语言，以充分利用 WebGL。Three.js 围绕 WebGL 的功能提供了一个非常易于使用的 JavaScript API，因此您可以在不详细了解 WebGL 的情况下创建美丽的 3D 图形。

Three.js 提供了大量功能和 API，您可以使用它们直接在浏览器中创建 3D 场景。在本书中，您将通过大量互动示例和代码样本学习 Three.js 提供的所有不同 API。

# 本书涵盖的内容

第一章《使用 Three.js 创建您的第一个 3D 场景》介绍了开始使用 Three.js 所需的基本步骤。您将立即创建您的第一个 Three.js 场景，并在本章结束时，您将能够直接在浏览器中创建和动画化您的第一个 3D 场景。

第二章《构成 Three.js 场景的基本组件》解释了在使用 Three.js 时需要了解的基本组件。您将了解灯光、网格、几何图形、材质和摄像机。在本章中，您还将概述 Three.js 提供的不同光源和您可以在场景中使用的摄像机。

第三章《使用 Three.js 中可用的不同光源》深入探讨了您可以在场景中使用的不同光源。它展示了示例并解释了如何使用聚光灯、方向光、环境光、点光源、半球光和区域光。此外，它还展示了如何在光源上应用镜头眩光效果。

第四章《使用 Three.js 材质》讨论了 Three.js 中可用的可以在网格上使用的材质。它展示了您可以设置的所有属性，以配置用于特定用途的材质，并提供了可供在 Three.js 中使用的材质进行实验的交互式示例。

第五章《学习使用几何图形》是探索 Three.js 提供的所有几何图形的两章中的第一章。在本章中，您将学习如何在 Three.js 中创建和配置几何图形，并可以使用提供的交互式示例来尝试使用几何图形（如平面、圆形、形状、立方体、球体、圆柱体、圆环、圆环结和多面体）。

第六章《高级几何图形和二进制操作》延续了第五章《学习使用几何图形》的内容。它向您展示了如何配置和使用 Three.js 提供的更高级的几何图形，例如凸多边形和车削。在本章中，您还将学习如何从 2D 形状挤出 3D 几何图形，以及如何使用二进制操作组合几何图形来创建新的几何图形。

第七章，“粒子、精灵和点云”，解释了如何使用 Three.js 中的点云。您将学习如何从头开始创建点云以及从现有几何体创建点云。在本章中，您还将学习如何通过使用精灵和点云材质来修改单个点的外观方式。

第八章，“创建和加载高级网格和几何体”，向您展示了如何从外部来源导入网格和几何体。您将学习如何使用 Three.js 的内部 JSON 格式来保存几何体和场景。本章还解释了如何从格式如 OBJ、DAE、STL、CTM、PLY 等加载模型。

第九章，“动画和移动摄像机”，探讨了各种类型的动画，您可以使用它们使您的场景栩栩如生。您将学习如何与 Three.js 一起使用 Tween.js 库，以及如何使用基于变形和骨骼的动画模型。

第十章，“加载和使用纹理”，扩展了第四章，“使用 Three.js 材质”，在那里介绍了材质。在本章中，我们深入了解纹理的细节。本章介绍了各种可用的纹理类型以及如何控制纹理应用到网格上的方式。此外，在本章中，您将学习如何直接使用 HTML5 视频和画布元素的输出作为纹理的输入。

第十一章，“自定义着色器和渲染后处理”，探讨了如何使用 Three.js 对渲染的场景应用后处理效果。通过后处理，您可以对渲染的场景应用模糊、移轴、深褐色等效果。此外，您还将学习如何创建自己的后处理效果，并创建自定义的顶点和片段着色器。

第十二章，“向您的场景添加物理和声音”，解释了如何向 Three.js 场景添加物理效果。通过物理效果，您可以检测物体之间的碰撞，使它们对重力做出反应，并施加摩擦力。本章向您展示了如何使用 Physijs JavaScript 库来实现这一点。此外，本章还向您展示了如何向 Three.js 场景添加定位音频。

# 您需要为本书做好准备

您只需要一款文本编辑器（例如 Sublime）来玩弄示例，以及一款现代的网络浏览器来访问这些示例。一些示例需要本地网络服务器，但您将在第一章，“使用 Three.js 创建您的第一个 3D 场景”中学习如何设置一个非常轻量级的网络服务器，以便在本书中使用这些示例。

# 这本书是为谁准备的

这本书非常适合已经了解 JavaScript 并希望开始创建在任何浏览器中运行的 3D 图形的人。您不需要了解任何高级数学或 WebGL；所需的只是对 JavaScript 和 HTML 的一般了解。所需的材料和示例可以免费下载，本书中使用的所有工具都是开源的。因此，如果您想学习如何创建在任何现代浏览器中运行的美丽、交互式的 3D 图形，这本书就是为您准备的。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例及其含义的解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄都以以下方式显示：“您可以在这段代码中看到，除了设置`map`属性外，我们还将`bumpMap`属性设置为纹理。”

代码块设置如下：

```js
function createMesh(geom, imageFile, bump) {
  var texture = THREE.ImageUtils.loadTexture("../assets/textures/general/" + imageFile)
  var mat = new THREE.MeshPhongMaterial();
  mat.map = texture;
  var bump = THREE.ImageUtils.loadTexture("../assets/textures/general/" + bump)
  mat.bumpMap = bump;
  mat.bumpScale = 0.2;
  var mesh = new THREE.Mesh(geom, mat);
  return mesh;
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目会以粗体显示：

```js
var effectFilm = new THREE.FilmPass(0.8, 0.325, 256, false);
effectFilm.renderToScreen = true;

var composer4 = new THREE.EffectComposer(webGLRenderer);
**composer4.addPass(renderScene);**
composer4.addPass(effectFilm);
```

任何命令行输入或输出都以以下方式编写：

```js
**# git clone https://github.com/josdirksen/learning-threejs**

```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如在菜单或对话框中，会以这样的方式出现在文本中：“您可以通过转到**首选项** | **高级**并勾选**在菜单栏中显示开发菜单**来完成此操作。”

### 注意

警告或重要说明会以这样的方式显示在一个框中。

### 提示

提示和技巧会以这样的方式出现。


# 第一章：使用 Three.js 创建您的第一个 3D 场景

现代浏览器正在逐渐获得更强大的功能，可以直接从 JavaScript 中访问。您可以轻松地使用新的 HTML5 标签添加视频和音频，并通过 HTML5 画布创建交互式组件。与 HTML5 一起，现代浏览器还开始支持 WebGL。使用 WebGL，您可以直接利用图形卡的处理资源，并创建高性能的 2D 和 3D 计算机图形。直接从 JavaScript 编程 WebGL 以创建和动画 3D 场景是一个非常复杂和容易出错的过程。Three.js 是一个使这变得更容易的库。以下列表显示了 Three.js 使得易于实现的一些功能：

+   创建简单和复杂的 3D 几何体

+   通过 3D 场景中的动画和移动对象

+   将纹理和材质应用到您的对象上

+   利用不同的光源照亮场景

+   从 3D 建模软件加载对象

+   向您的 3D 场景添加高级后处理效果

+   使用自定义着色器

+   创建点云

使用几行 JavaScript 代码，您可以创建从简单的 3D 模型到逼真的实时场景的任何东西，如下图所示（通过在浏览器中打开[`www.vill.ee/eye/`](http://www.vill.ee/eye/)来查看）：

![使用 Three.js 创建您的第一个 3D 场景](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_01_01.jpg)

在本章中，我们将直接深入了解 Three.js，并创建一些示例，向您展示 Three.js 的工作原理，并可以用来进行实验。我们不会立即深入所有技术细节；这是您将在接下来的章节中学习的内容。在本章中，我们将涵盖以下内容：

+   使用 Three.js 所需的工具

+   下载本书中使用的源代码和示例

+   创建您的第一个 Three.js 场景

+   使用材质、光线和动画改进第一个场景

+   介绍一些辅助库，用于统计和控制场景

我们将从简短介绍 Three.js 开始这本书，然后迅速转向第一个示例和代码样本。在我们开始之前，让我们快速看看最重要的浏览器以及它们对 WebGL 的支持。

在撰写本文时，WebGL 与以下桌面浏览器兼容：

| 浏览器 | 支持 |
| --- | --- |
| Mozilla Firefox | 该浏览器自 4.0 版本起就支持 WebGL。 |
| 谷歌 Chrome | 该浏览器自 9.0 版本起就支持 WebGL。 |
| Safari | 安装在 Mac OS X Mountain Lion、Lion 或 Snow Leopard 上的 Safari 版本 5.1 及更高版本支持 WebGL。确保您在 Safari 中启用了 WebGL。您可以通过转到**首选项** &#124; **高级**并勾选**在菜单栏中显示开发菜单**来实现这一点。之后，转到**开发** &#124; **启用 WebGL**。 |
| Opera | 该浏览器自 12.00 版本起就支持 WebGL。您仍然需要通过打开**opera:config**并将**WebGL**和**启用硬件加速**的值设置为`1`来启用此功能。之后，重新启动浏览器。 |
| 互联网浏览器 | 很长一段时间以来，IE 是唯一不支持 WebGL 的主要浏览器。从 IE11 开始，微软已经添加了对 WebGL 的支持。 |

基本上，Three.js 可以在任何现代浏览器上运行，除了较旧版本的 IE。因此，如果您想使用较旧版本的 IE，您需要采取额外的步骤。对于 IE 10 及更早版本，有*iewebgl*插件，您可以从[`github.com/iewebgl/iewebgl`](https://github.com/iewebgl/iewebgl)获取。此插件安装在 IE 10 及更早版本中，并为这些浏览器启用了 WebGL 支持。

在移动设备上也可以运行 Three.js；对 WebGL 的支持和性能会有所不同，但两者都在迅速改善：

| 设备 | 支持 |
| --- | --- |
| Android | Android 的原生浏览器不支持 WebGL，通常也缺乏对现代 HTML5 功能的支持。如果您想在 Android 上使用 WebGL，可以使用最新版本的 Chrome、Firefox 或 Opera 移动版。 |
| IOS | IOS 8 也支持 IOS 设备上的 WebGL。IOS Safari 8 版本具有出色的 WebGL 支持。 |
| Windows mobile | Windows 手机自 8.1 版本起支持 WebGL。 |

使用 WebGL，您可以创建在台式机和移动设备上运行非常流畅的交互式 3D 可视化。

### 提示

在本书中，我们将主要关注 Three.js 提供的基于 WebGL 的渲染器。然而，还有一个基于 CSS 3D 的渲染器，它提供了一个简单的 API 来创建基于 CSS 3D 的 3D 场景。使用 CSS 3D 的一个重要优势是，这个标准几乎在所有移动和桌面浏览器上都得到支持，并且允许您在 3D 空间中渲染 HTML 元素。我们将展示如何在第七章中使用 CSS 3D 浏览器，*粒子、精灵和点云*。

在本章中，您将直接创建您的第一个 3D 场景，并且可以在之前提到的任何浏览器中运行。我们暂时不会介绍太多复杂的 Three.js 功能，但在本章结束时，您将已经创建了下面截图中可以看到的 Three.js 场景：

![使用 Three.js 创建您的第一个 3D 场景](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_01_02.jpg)

在这个第一个场景中，您将学习 Three.js 的基础知识，并创建您的第一个动画。在开始这个示例之前，在接下来的几节中，我们将首先看一下您需要轻松使用 Three.js 的工具，以及如何下载本书中展示的示例。

# 使用 Three.js 的要求

Three.js 是一个 JavaScript 库，因此创建 Three.js WebGL 应用程序所需的只是一个文本编辑器和一个支持的浏览器来渲染结果。我想推荐两款 JavaScript 编辑器，这是我在过去几年中开始专门使用的：

+   WebStorm：这个来自 JetBrains 指南的编辑器对编辑 JavaScript 有很好的支持。它支持代码补全、自动部署和直接从编辑器进行 JavaScript 调试。除此之外，WebStorm 还具有出色的 GitHub（和其他版本控制系统）支持。您可以从[`www.jetbrains.com/webstorm/`](http://www.jetbrains.com/webstorm/)下载试用版。

+   Notepad++：Notepad++是一个通用的编辑器，支持多种编程语言的代码高亮显示。它可以轻松地布局和格式化 JavaScript。请注意，Notepad++仅适用于 Windows。您可以从[`notepad-plus-plus.org/`](http://notepad-plus-plus.org/)下载 Notepad++。

+   Sublime 文本编辑器：Sublime 是一个很棒的编辑器，对编辑 JavaScript 有很好的支持。除此之外，它还提供了许多非常有用的选择（如多行选择）和编辑选项，一旦您习惯了它们，就会提供一个非常好的 JavaScript 编辑环境。Sublime 也可以免费测试，并且可以从[`www.sublimetext.com/`](http://www.sublimetext.com/)下载。

即使您不使用这些编辑器，也有很多可用的编辑器，开源和商业的，您可以用来编辑 JavaScript 并创建您的 Three.js 项目。您可能想看看的一个有趣的项目是[`c9.io`](http://c9.io)。这是一个基于云的 JavaScript 编辑器，可以连接到 GitHub 账户。这样，您就可以直接访问本书中的所有源代码和示例，并对其进行实验。

### 提示

除了这些文本编辑器，您可以使用它们来编辑和实验本书中的源代码，Three.js 目前还提供了一个在线编辑器。

使用这个编辑器，您可以在[`threejs.org/editor/`](http://threejs.org/editor/)找到，可以使用图形化的方法创建 Three.js 场景。

我提到大多数现代 Web 浏览器都支持 WebGL，并且可以用于运行 Three.js 示例。我通常在 Chrome 中运行我的代码。原因是大多数情况下，Chrome 对 WebGL 有最好的支持和性能，并且具有非常好的 JavaScript 调试器。通过这个调试器，您可以快速定位问题，例如使用断点和控制台输出。这在下面的截图中有所体现。在本书中，我会给您一些关于调试器使用和其他调试技巧的指导。

![使用 Three.js 的要求](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_01_03.jpg)

现在关于 Three.js 的介绍就到此为止；让我们获取源代码并从第一个场景开始吧。

# 获取源代码

本书的所有代码都可以从 GitHub ([`github.com/`](https://github.com/))访问。GitHub 是一个在线的基于 Git 的存储库，您可以用它来存储、访问和管理源代码的版本。有几种方式可以获取源代码：

+   克隆 Git 存储库

+   下载并提取存档

在接下来的两段中，我们将稍微详细地探讨这些选项。

## 使用 Git 克隆存储库

Git 是一个开源的分布式版本控制系统，我用它来创建和管理本书中的所有示例。为此，我使用了 GitHub，一个免费的在线 Git 存储库。您可以通过[`github.com/josdirksen/learning-threejs`](https://github.com/josdirksen/learning-threejs)浏览此存储库。

要获取所有示例，您可以使用`git`命令行工具克隆此存储库。为此，您首先需要为您的操作系统下载一个 Git 客户端。对于大多数现代操作系统，可以从[`git-scm.com`](http://git-scm.com)下载客户端，或者您可以使用 GitHub 本身提供的客户端（适用于 Mac 和 Windows）。安装 Git 后，您可以使用它来获取本书存储库的*克隆*。打开命令提示符并转到您想要下载源代码的目录。在该目录中，运行以下命令：

```js
**# git clone https://github.com/josdirksen/learning-threejs**

```

这将开始下载所有示例，如下截图所示：

![使用 Git 克隆存储库](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_01_04.jpg)

`learning-three.js`目录现在将包含本书中使用的所有示例。

## 下载和提取存档

如果您不想使用 Git 直接从 GitHub 下载源代码，您也可以下载一个存档。在浏览器中打开[`github.com/josdirksen/learning-threejs`](https://github.com/josdirksen/learning-threejs)，并点击右侧的**Download ZIP**按钮，如下所示：

![下载和提取存档](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_01_05.jpg)

将其提取到您选择的目录中，您就可以使用所有示例了。

## 测试示例

现在您已经下载或克隆了源代码，让我们快速检查一下是否一切正常，并让您熟悉目录结构。代码和示例按章节组织。有两种不同的查看示例的方式。您可以直接在浏览器中打开提取或克隆的文件夹，并查看和运行特定示例，或者您可以安装本地 Web 服务器。第一种方法适用于大多数基本示例，但当我们开始加载外部资源，例如模型或纹理图像时，仅仅打开 HTML 文件是不够的。在这种情况下，我们需要一个本地 Web 服务器来确保外部资源被正确加载。在接下来的部分中，我们将解释一些不同的设置简单本地 Web 服务器的方法。如果您无法设置本地 Web 服务器但使用 Chrome 或 Firefox，我们还提供了如何禁用某些安全功能的说明，以便您甚至可以在没有本地 Web 服务器的情况下进行测试。

根据您已经安装了什么，设置本地 Web 服务器非常容易。在这里，我们列举了一些示例。根据您系统上已经安装了什么，有许多不同的方法可以做到这一点。

### 基于 Python 的 Web 服务器应该在大多数 Unix/Mac 系统上工作

大多数 Unix/Linux/Mac 系统已经安装了 Python。在这些系统上，您可以非常容易地启动本地 Web 服务器：

```js
 **> python -m SimpleHTTPServer**
 **Serving HTTP on 0.0.0.0 port 8000 ...**

```

在您检出/下载源代码的目录中执行此操作。

### 如果您已经使用 Node.js，可以使用基于 npm 的 Web 服务器

如果您已经使用 Node.js 做了一些工作，那么您很有可能已经安装了 npm。使用 npm，您有两个简单的选项来设置一个快速的本地 Web 服务器进行测试。第一个选项使用`http-server`模块，如下所示：

```js
 **> npm install -g http-server**
 **> http-server**
**Starting up http-server, serving ./ on port: 8080**
**Hit CTRL-C to stop the server**

```

或者，您还可以使用`simple-http-server`选项，如下所示：

```js
**> npm install -g simple-http-server**
**> nserver**
**simple-http-server Now Serving: /Users/jos/git/Physijs at http://localhost:8000/**

```

然而，这种第二种方法的缺点是它不会自动显示目录列表，而第一种方法会。

### Mac 和/或 Windows 的 Mongoose 便携版

如果您没有安装 Python 或 npm，那么有一个名为 Mongoose 的简单、便携式 Web 服务器可供您使用。首先，从[`code.google.com/p/mongoose/downloads/list`](https://code.google.com/p/mongoose/downloads/list)下载您特定平台的二进制文件。如果您使用 Windows，将其复制到包含示例的目录中，并双击可执行文件以启动 Web 浏览器，为其启动的目录提供服务。

对于其他操作系统，您还必须将可执行文件复制到目标目录，但是不是双击可执行文件，而是必须从命令行启动它。在这两种情况下，本地 Web 服务器将在端口`8080`上启动。以下屏幕截图概括了本段讨论的内容：

![Mac 和/或 Windows 的 Mongoose 便携版](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_01_06.jpg)

通过单击章节，我们可以显示和访问该特定章节的所有示例。如果我在本书中讨论一个示例，我将引用特定的名称和文件夹，以便您可以直接测试和玩耍代码。

### 在 Firefox 和 Chrome 中禁用安全异常

如果您使用 Chrome 运行示例，有一种方法可以禁用一些安全设置，以便您可以使用 Chrome 查看示例，而无需使用 Web 服务器。要做到这一点，您必须以以下方式启动 Chrome：

+   对于 Windows，执行以下操作：

```js
**chrome.exe --disable-web-security**

```

+   在 Linux 上，执行以下操作：

```js
**google-chrome --disable-web-security**

```

+   在 Mac OS 上，通过以下方式禁用设置：

```js
**open -a Google\ Chrome --args --disable-web-security**

```

以这种方式启动 Chrome，您可以直接从本地文件系统访问所有示例。

对于 Firefox 用户，我们需要采取一些不同的步骤。打开 Firefox，在 URL 栏中键入`about:config`。这是您将看到的内容：

![在 Firefox 和 Chrome 中禁用安全异常](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_01_07.jpg)

在此屏幕上，点击**我会小心，我保证！**按钮。这将显示您可以使用的所有可用属性，以便微调 Firefox。在此屏幕上的搜索框中，键入`security.fileuri.strict_origin_policy`，并将其值更改为`false`，就像我们在以下屏幕截图中所做的那样：

![在 Firefox 和 Chrome 中禁用安全异常](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_01_08.jpg)

此时，您还可以使用 Firefox 直接运行本书提供的示例。

现在，您已经安装了 Web 服务器，或者禁用了必要的安全设置，是时候开始创建我们的第一个 Three.js 场景了。

# 创建 HTML 骨架

我们需要做的第一件事是创建一个空的骨架页面，我们可以将其用作所有示例的基础，如下所示：

```js
<!DOCTYPE html>

<html>

  <head>
    <title>Example 01.01 - Basic skeleton</title>
    <script src="../libs/three.js"></script>
    <style>
      body{
        /* set margin to 0 and overflow to hidden, to use the complete page */

        margin: 0;
        overflow: hidden;
      }
    </style>
  </head>
  <body>

    <!-- Div which will hold the Output -->
    <div id="WebGL-output">
    </div>

    <!-- Javascript code that runs our Three.js examples -->
    <script>

      // once everything is loaded, we run our Three.js stuff.
      function init() {
        // here we'll put the Three.js stuff
      };
      window.onload = init;

    </script>
  </body>
</html>
```

### 提示

**下载示例代码**

您可以从[`www.packtpub.com`](http://www.packtpub.com)的帐户中下载示例代码文件，用于您购买的所有 Packt Publishing 图书。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，以便直接通过电子邮件接收文件。

从此列表中可以看出，骨架是一个非常简单的 HTML 页面，只有几个元素。在`<head>`元素中，我们加载了我们将在示例中使用的外部 JavaScript 库。对于所有示例，我们至少需要加载 Three.js 库`three.js`。在`<head>`元素中，我们还添加了几行 CSS。这些样式元素在创建全屏 Three.js 场景时移除任何滚动条。在此页面的`<body>`元素中，您可以看到一个单独的`<div>`元素。当我们编写我们的 Three.js 代码时，我们将把 Three.js 渲染器的输出指向该元素。在此页面的底部，您已经可以看到一些 JavaScript。通过将`init`函数分配给`window.onload`属性，我们确保在 HTML 文档加载完成时调用此函数。在`init`函数中，我们将插入所有特定于 Three.js 的 JavaScript。

Three.js 有两个版本：

+   **Three.min.js**：这是您在互联网上部署 Three.js 网站时通常使用的库。这是使用**UglifyJS**创建的 Three.js 的缩小版本，是正常 Three.js 库的四分之一大小。本书中使用的所有示例和代码都基于于 2014 年 10 月发布的 Three.js **r69**。

+   **Three.js**：这是正常的 Three.js 库。我们在示例中使用这个库，因为当您能够阅读和理解 Three.js 源代码时，调试会更加容易。

如果我们在浏览器中查看此页面，结果并不令人震惊。正如您所期望的那样，您只会看到一个空白页面。

在下一节中，您将学习如何添加前几个 3D 对象并将其渲染到我们在 HTML 骨架中定义的`<div>`元素中。

# 渲染和查看 3D 对象

在这一步中，您将创建您的第一个场景，并添加一些对象和一个相机。我们的第一个示例将包含以下对象：

| 对象 | 描述 |
| --- | --- |
| `Plane` | 这是一个作为我们地面区域的二维矩形。在本章的第二个截图中，它被渲染为场景中间的灰色矩形。 |
| `Cube` | 这是一个三维立方体，我们将以红色渲染。 |
| `Sphere` | 这是一个三维球体，我们将以蓝色渲染。 |
| `Camera` | 相机决定了输出中你将看到什么。 |
| `Axes` | 这些是*x*、*y*和*z*轴。这是一个有用的调试工具，可以看到对象在 3D 空间中的渲染位置。*x*轴为红色，*y*轴为绿色，*z*轴为蓝色。 |

我将首先向您展示代码中的外观（带有注释的源代码可以在`chapter-01/02-first-scene.html`中找到），然后我将解释发生了什么：

```js
function init() {
  var scene = new THREE.Scene();
  var camera = new THREE.PerspectiveCamera(45, window.innerWidth /window.innerHeight, 0.1, 1000);

  var renderer = new THREE.WebGLRenderer();
  renderer.setClearColorHex(0xEEEEEE);
  renderer.setSize(window.innerWidth, window.innerHeight);

  var axes = new THREE.AxisHelper(20);
  scene.add(axes);

  var planeGeometry = new THREE.PlaneGeometry(60, 20, 1, 1);
  var planeMaterial = new THREE.MeshBasicMaterial({color: 0xcccccc});
  var plane = new THREE.Mesh(planeGeometry, planeMaterial);

  plane.rotation.x = -0.5 * Math.PI;
  plane.position.x = 15
  plane.position.y = 0
  plane.position.z = 0

  scene.add(plane);

  var cubeGeometry = new THREE.BoxGeometry(4, 4, 4)
  var cubeMaterial = new THREE.MeshBasicMaterial({color: 0xff0000, wireframe: true});
  var cube = new THREE.Mesh(cubeGeometry, cubeMaterial);

  cube.position.x = -4;
  cube.position.y = 3;
  cube.position.z = 0;

  scene.add(cube);

  var sphereGeometry = new THREE.SphereGeometry(4, 20, 20);
  var sphereMaterial = new THREE.MeshBasicMaterial({color: 0x7777ff, wireframe: true});
  var sphere = new THREE.Mesh(sphereGeometry, sphereMaterial);

  sphere.position.x = 20;
  sphere.position.y = 4;
  sphere.position.z = 2;

  scene.add(sphere);

  camera.position.x = -30;
  camera.position.y = 40;
  camera.position.z = 30;
  camera.lookAt(scene.position);

  document.getElementById("WebGL-output")
    .appendChild(renderer.domElement);
    renderer.render(scene, camera);
};
window.onload = init;
```

如果我们在浏览器中打开此示例，我们会看到与我们的目标相似的东西（请参阅本章开头的截图），但仍有很长的路要走，如下所示：

![渲染和查看 3D 对象](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_01_09.jpg)

在我们开始让这个更加美丽之前，我将逐步向您介绍代码，以便您了解代码的作用：

```js
var scene = new THREE.Scene();
var camera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 0.1, 1000);
var renderer = new THREE.WebGLRenderer();
renderer.setClearColorHex()
renderer.setClearColor(new THREE.Color(0xEEEEEE));
renderer.setSize(window.innerWidth, window.innerHeight);
```

在示例的顶部，我们定义了`scene`，`camera`和`renderer`。`scene`对象是一个容器，用于存储和跟踪我们要渲染的所有对象和我们要使用的所有灯光。没有`THREE.Scene`对象，Three.js 就无法渲染任何东西。关于`THREE.Scene`对象的更多信息可以在下一章中找到。我们想要渲染的球体和立方体将在示例的后面添加到场景中。在这个第一个片段中，我们还创建了一个`camera`对象。`camera`对象定义了我们在渲染场景时会看到什么。在第二章中，*Three.js 场景的基本组件*，您将了解有关您可以传递给`camera`对象的参数的更多信息。接下来我们定义`renderer`。`renderer`对象负责根据`camera`对象的角度在浏览器中计算`scene`对象的外观。在这个示例中，我们创建了一个使用您的图形卡来渲染场景的`WebGLRenderer`。

### 提示

如果您查看 Three.js 的源代码和文档（您可以在[`threejs.org/`](http://threejs.org/)找到），您会注意到除了基于 WebGL 的渲染器之外，还有其他不同的渲染器可用。有一个基于画布的渲染器，甚至还有一个基于 SVG 的渲染器。尽管它们可以工作并且可以渲染简单的场景，但我不建议使用它们。它们非常消耗 CPU，并且缺乏诸如良好的材质支持和阴影等功能。

在这里，我们将`renderer`的背景颜色设置为接近白色（`new THREE.Color(0XEEEEEE)`），并使用`setClearColor`函数告诉`renderer`需要渲染的场景有多大。

到目前为止，我们有一个基本的空场景，一个渲染器和一个摄像头。然而，还没有要渲染的东西。以下代码添加了辅助轴和平面：

```js
  var axes = new THREE.AxisHelper( 20 );
  scene.add(axes);

  var planeGeometry = new THREE.PlaneGeometry(60,20);
  var planeMaterial = new THREE.MeshBasicMaterial({color: 0xcccccc});
  var plane = new THREE.Mesh(planeGeometry,planeMaterial);

  plane.rotation.x=-0.5*Math.PI;
  plane.position.x=15
  plane.position.y=0
  plane.position.z=0
  scene.add(plane);
```

正如您所看到的，我们创建了一个`axes`对象，并使用`scene.add`函数将这些轴添加到我们的场景中。接下来，我们创建了平面。这是分两步完成的。首先，我们使用新的`THREE.PlaneGeometry(60,20)`代码定义了平面的外观。在这种情况下，它的宽度为`60`，高度为`20`。我们还需要告诉 Three.js 这个平面的外观（例如，它的颜色和透明度）。在 Three.js 中，我们通过创建一个材质对象来实现这一点。对于这个第一个示例，我们将创建一个基本材质（`THREE.MeshBasicMaterial`），颜色为`0xcccccc`。接下来，我们将这两者合并成一个名为`plane`的`Mesh`对象。在将`plane`添加到场景之前，我们需要将其放在正确的位置；我们首先围绕 x 轴旋转它 90 度，然后使用位置属性在场景中定义其位置。如果您已经对此感兴趣，请查看第二章的代码文件夹中的`06-mesh-properties.html`示例，该示例显示并解释了旋转和定位。然后我们需要做的就是像我们对`axes`所做的那样将`plane`添加到`scene`中。

`cube`和`sphere`对象以相同的方式添加，但`wireframe`属性设置为`true`，告诉 Three.js 渲染线框而不是实心对象。现在，让我们继续进行这个示例的最后部分：

```js
  camera.position.x = -30;
  camera.position.y = 40;
  camera.position.z = 30;
  camera.lookAt(scene.position);

  document.getElementById("WebGL-output")
    .appendChild(renderer.domElement);
    renderer.render(scene, camera);
```

在这一点上，我们想要渲染的所有元素都已经添加到了正确的位置。我已经提到相机定义了什么将被渲染。在这段代码中，我们使用`x`、`y`和`z`位置属性来定位相机，使其悬浮在我们的场景上方。为了确保相机看向我们的对象，我们使用`lookAt`函数将其指向我们场景的中心，默认情况下位于位置（0, 0, 0）。剩下的就是将渲染器的输出附加到我们 HTML 骨架的`<div>`元素上。我们使用标准的 JavaScript 来选择正确的输出元素，并使用`appendChild`函数将其附加到我们的`div`元素上。最后，我们告诉`renderer`使用提供的`camera`对象来渲染`scene`。

在接下来的几节中，我们将通过添加光源、阴影、更多材质甚至动画使这个场景更加美观。

# 添加材质、光源和阴影

在 Three.js 中添加新的材质和光源非常简单，几乎与我们在上一节中解释的方式相同。我们首先通过以下方式向场景添加光源（完整的源代码请查看`03-materials-light.html`）：

```js
  var spotLight = new THREE.SpotLight( 0xffffff );
  spotLight.position.set( -40, 60, -10 );
  scene.add( spotLight );
```

`THREE.SpotLight`从其位置（`spotLight.position.set(-40, 60, -10)`）照亮我们的场景。然而，如果这次渲染场景，您不会看到与上一个场景的任何不同。原因是不同的材质对光的反应不同。我们在上一个示例中使用的基本材质（`THREE.MeshBasicMaterial`）在场景中不会对光源产生任何影响。它们只是以指定的颜色渲染对象。因此，我们必须将`plane`、`sphere`和`cube`的材质更改为以下内容：

```js
var planeGeometry = new THREE.PlaneGeometry(60,20);
var planeMaterial = new THREE.MeshLambertMaterial({color: 0xffffff});
var plane = new THREE.Mesh(planeGeometry, planeMaterial);
...
var cubeGeometry = new THREE.BoxGeometry(4,4,4);
var cubeMaterial = new THREE.MeshLambertMaterial({color: 0xff0000});
var cube = new THREE.Mesh(cubeGeometry, cubeMaterial);
...
var sphereGeometry = new THREE.SphereGeometry(4,20,20);
var sphereMaterial = new THREE.MeshLambertMaterial({color: 0x7777ff});
var sphere = new THREE.Mesh(sphereGeometry, sphereMaterial);
```

在这段代码中，我们将对象的材质更改为`MeshLambertMaterial`。这种材质和`MeshPhongMaterial`是 Three.js 提供的在渲染时考虑光源的材质。

然而，如下截图所示的结果仍然不是我们要找的：

![添加材质、光源和阴影](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_01_10.jpg)

我们已经接近了，立方体和球看起来好多了。然而，还缺少的是阴影。

渲染阴影需要大量的计算能力，因此在 Three.js 中默认情况下禁用阴影。不过，启用它们非常容易。对于阴影，我们需要在几个地方更改源代码，如下所示：

```js
renderer.setClearColor(new THREE.Color(0xEEEEEE, 1.0));
renderer.setSize(window.innerWidth, window.innerHeight);
renderer.shadowMapEnabled = true;
```

我们需要做的第一个更改是告诉`renderer`我们想要阴影。您可以通过将`shadowMapEnabled`属性设置为`true`来实现这一点。如果您查看这个更改的结果，您暂时不会注意到任何不同。这是因为我们需要明确定义哪些对象投射阴影，哪些对象接收阴影。在我们的示例中，我们希望球体和立方体在地面上投射阴影。您可以通过在这些对象上设置相应的属性来实现这一点：

```js
plane.receiveShadow = true;
...
cube.castShadow = true;
...
sphere.castShadow = true;
```

现在，我们只需要做一件事就可以得到阴影了。我们需要定义我们场景中哪些光源会产生阴影。并非所有的光源都能产生阴影，您将在下一章中了解更多相关信息，但是我们在这个示例中使用的`THREE.SpotLight`可以。我们只需要设置正确的属性，如下代码行所示，阴影最终将被渲染出来：

```js
spotLight.castShadow = true;
```

有了这个，我们得到了一个包含来自光源的阴影的场景，如下所示：

![添加材质、光源和阴影](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_01_11.jpg)

我们将添加到这个第一个场景的最后一个特性是一些简单的动画。在第九章*动画和移动摄像机*中，您将了解更高级的动画选项。

# 通过动画扩展您的第一个场景

如果我们想要对场景进行动画，我们需要做的第一件事是找到一种在特定间隔重新渲染场景的方法。在 HTML5 和相关的 JavaScript API 出现之前，做到这一点的方法是使用`setInterval(function,interval)`函数。使用`setInterval`，我们可以指定一个函数，例如，每 100 毫秒调用一次。这个函数的问题在于它不考虑浏览器中正在发生的事情。如果您正在浏览另一个标签页，这个函数仍然会每隔几毫秒触发一次。此外，`setInterval`与屏幕重绘不同步。这可能导致更高的 CPU 使用率和性能不佳。

## 介绍 requestAnimationFrame

现代浏览器幸运地有一个解决方案，使用`requestAnimationFrame`函数。使用`requestAnimationFrame`，您可以指定一个由浏览器定义的间隔调用的函数。您可以在提供的函数中进行任何绘图，浏览器将确保尽可能平滑和高效地绘制。使用这个函数非常简单（完整的源代码可以在`04-materials-light-animation.html`文件中找到），您只需创建一个处理渲染的函数：

```js
function renderScene() {
  requestAnimationFrame(renderScene);
  renderer.render(scene, camera);
}
```

在这个`renderScene`函数中，我们再次调用`requestAnimationFrame`，以保持动画进行。我们需要在代码中改变的唯一一件事是，在我们创建完整的场景后，我们不再调用`renderer.render`，而是调用`renderScene`函数一次，以启动动画：

```js
...
document.getElementById("WebGL-output")
  .appendChild(renderer.domElement);
renderScene();
```

如果您运行这个代码，与之前的例子相比，您不会看到任何变化，因为我们还没有进行任何动画。在添加动画之前，我想介绍一个小的辅助库，它可以为我们提供有关动画运行帧率的信息。这个库来自与 Three.js 相同作者，它渲染了一个小图表，显示了我们为这个动画获得的每秒帧数。

要添加这些统计信息，我们首先需要在 HTML 的`<head>`元素中包含库，如下所示：

```js
<script src="../libs/stats.js"></script>
```

我们添加一个`<div>`元素，用作统计图的输出，如下所示：

```js
<div id="Stats-output"></div>
```

唯一剩下的事情就是初始化统计信息并将它们添加到这个`<div>`元素中，如下所示：

```js
function initStats() {
  var stats = new Stats();
  stats.setMode(0);
  stats.domElement.style.position = 'absolute';
  stats.domElement.style.left = '0px';
  stats.domElement.style.top = '0px';
  document.getElementById("Stats-output")
    .appendChild( stats.domElement );
     return stats;
}
```

这个函数初始化了统计信息。有趣的部分是`setMode`函数。如果我们将其设置为`0`，我们将测量每秒帧数（fps），如果我们将其设置为`1`，我们可以测量渲染时间。对于这个例子，我们对 fps 感兴趣，所以设置为`0`。在我们的`init()`函数的开头，我们将调用这个函数，这样我们就启用了`stats`，如下所示：

```js
function init(){

  var stats = initStats();
  ...
}
```

唯一剩下的事情就是告诉`stats`对象我们何时处于新的渲染周期。我们通过在`renderScene`函数中添加对`stats.update`函数的调用来实现这一点，如下所示。

```js
function renderScene() {
  stats.update();
  ...
  requestAnimationFrame(renderScene);
  renderer.render(scene, camera);
}
```

如果您运行带有这些添加的代码，您将在左上角看到统计信息，如下面的截图所示：

![介绍 requestAnimationFrame](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_01_12.jpg)

## 为立方体添加统计信息

有了`requestAnimationFrame`和配置好的统计信息，我们有了一个放置动画代码的地方。在本节中，我们将扩展`renderScene`函数的代码，以使我们的红色立方体围绕所有轴旋转。让我们先向您展示代码：

```js
function renderScene() {
  ...
  cube.rotation.x += 0.02;
  cube.rotation.y += 0.02;
  cube.rotation.z += 0.02;
  ...
  requestAnimationFrame(renderScene);
  renderer.render(scene, camera);
}
```

看起来很简单，对吧？我们所做的是每次调用`renderScene`函数时，都增加每个轴的`rotation`属性 0.02，这样就会显示一个立方体平滑地围绕所有轴旋转。让蓝色的球弹跳并不难。

## 弹跳球

为了让球弹跳，我们再次向`renderScene`函数中添加了几行代码，如下所示：

```js
  var step=0;
  function renderScene() {
    ...
    step+=0.04;
    sphere.position.x = 20+( 10*(Math.cos(step)));
    sphere.position.y = 2 +( 10*Math.abs(Math.sin(step)));
    ...
    requestAnimationFrame(renderScene);
    renderer.render(scene, camera);
  }
```

使用立方体，我们改变了“旋转”属性；对于球体，我们将在场景中改变其“位置”属性。我们希望球体能够从场景中的一个点弹跳到另一个点，并呈现出一个漂亮、平滑的曲线。如下图所示：

![弹跳球](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_01_13.jpg)

为此，我们需要改变它在*x*轴上的位置和在*y*轴上的位置。`Math.cos`和`Math.sin`函数帮助我们使用步长变量创建平滑的轨迹。我不会在这里详细介绍这是如何工作的。现在，你需要知道的是`step+=0.04`定义了弹跳球的速度。在第八章中，*创建和加载高级网格和几何体*，我们将更详细地看看这些函数如何用于动画，并且我会解释一切。这是球在弹跳中间的样子：

![弹跳球](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_01_14.jpg)

在结束本章之前，我想在我们的基本场景中再添加一个元素。当处理 3D 场景、动画、颜色和类似属性时，通常需要一些试验来获得正确的颜色或速度。如果你能有一个简单的 GUI，可以让你随时改变这些属性，那就太方便了。幸运的是，有这样的工具！

# 使用 dat.GUI 使实验更容易

Google 的几名员工创建了一个名为**dat.GUI**的库（你可以在[`code.google.com/p/dat-gui/`](http://code.google.com/p/dat-gui/)上找到在线文档），它可以让你非常容易地创建一个简单的用户界面组件，可以改变你代码中的变量。在本章的最后部分，我们将使用 dat.GUI 为我们的示例添加一个用户界面，允许我们改变以下内容：

+   控制弹跳球的速度

+   控制立方体的旋转

就像我们为统计数据所做的那样，我们首先将这个库添加到我们 HTML 页面的`<head>`元素中，如下所示：

```js
<script src="../libs/dat.gui.js"></script>
```

接下来我们需要配置的是一个 JavaScript 对象，它将保存我们想要使用 dat.GUI 改变的属性。在我们的 JavaScript 代码的主要部分，我们添加以下 JavaScript 对象，如下所示：

```js
var controls = new function() {
  this.rotationSpeed = 0.02;
  this.bouncingSpeed = 0.03;
}
```

在这个 JavaScript 对象中，我们定义了两个属性——`this.rotationSpeed`和`this.bouncingSpeed`——以及它们的默认值。接下来，我们将这个对象传递给一个新的 dat.GUI 对象，并为这两个属性定义范围，如下所示：

```js
var gui = new dat.GUI();
gui.add(controls, 'rotationSpeed', 0, 0.5);
gui.add(controls, 'bouncingSpeed', 0, 0.5);
```

`rotationSpeed`和`bouncingSpeed`属性都设置为`0`到`0.5`的范围。现在我们所需要做的就是确保在我们的`renderScene`循环中，直接引用这两个属性，这样当我们通过 dat.GUI 用户界面进行更改时，它立即影响我们对象的旋转和弹跳速度，如下所示：

```js
function renderScene() {
  ...
  cube.rotation.x += controls.rotationSpeed;
  cube.rotation.y += controls.rotationSpeed;
  cube.rotation.z += controls.rotationSpeed;
  step += controls.bouncingSpeed;
  sphere.position.x = 20 +(10 * (Math.cos(step)));
  sphere.position.y = 2 +(10 * Math.abs(Math.sin(step)));
  ...
}
```

现在，当你运行这个示例（`05-control-gui.html`），你会看到一个简单的用户界面，你可以用它来控制弹跳和旋转速度。下面是弹跳球和旋转立方体的屏幕截图：

![使用 dat.GUI 使实验更容易](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_01_15.jpg)

如果你在浏览器中查看示例，你可能会注意到当你改变浏览器的大小时，场景并不会自动缩放。在下一节中，我们将把这作为本章的最后一个特性添加进去。

# 当浏览器大小改变时自动调整输出大小

当浏览器大小改变时改变摄像机可以很简单地完成。我们需要做的第一件事是注册一个事件监听器，就像这样：

```js
window.addEventListener('resize', onResize, false);
```

现在，每当浏览器窗口大小改变时，我们将调用`onResize`函数。在这个`onResize`函数中，我们需要更新摄像机和渲染器，如下所示：

```js
function onResize() {
  camera.aspect = window.innerWidth / window.innerHeight;
  camera.updateProjectionMatrix();
  renderer.setSize(window.innerWidth, window.innerHeight);
}
```

对于摄像机，我们需要更新`aspect`属性，它保存了屏幕的宽高比，对于`renderer`，我们需要改变它的大小。最后一步是将`camera`、`renderer`和`scene`的变量定义移到`init()`函数之外，这样我们就可以从不同的函数（比如`onResize`函数）中访问它们，如下所示：

```js
var camera;
var scene;
var renderer;

function init() {
  ...
  scene = new THREE.Scene();
  camera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 0.1, 1000);
  renderer = new THREE.WebGLRenderer();
  ...
}
```

要看到这种效果，打开`06-screen-size-change.html`示例并调整浏览器窗口大小。

# 总结

第一章就到这里。在本章中，我们向您展示了如何设置开发环境，如何获取代码，以及如何开始使用本书提供的示例。您还学会了，要使用 Three.js 渲染场景，首先必须创建一个`THREE.Scene`对象，添加相机、光线和要渲染的对象。我们还向您展示了如何通过添加阴影和动画来扩展基本场景。最后，我们添加了一些辅助库。我们使用了 dat.GUI，它允许您快速创建控制用户界面，并添加了`stats.js`，它提供了有关场景渲染帧率的反馈。

在下一章中，我们将扩展我们在这里创建的示例。您将了解更多关于在 Three.js 中可以使用的最重要的构建模块。


# 第二章：构成 Three.js 场景的基本组件

在上一章中，您学习了 Three.js 的基础知识。我们展示了一些例子，您创建了您的第一个完整的 Three.js 场景。在本章中，我们将深入了解 Three.js，并解释构成 Three.js 场景的基本组件。在本章中，您将探索以下主题：

+   在 Three.js 场景中使用的组件

+   您可以使用`THREE.Scene`对象做什么

+   几何体和网格之间的关系

+   正交相机和透视相机之间的区别

我们首先来看一下如何创建一个场景并添加对象。

# 创建一个场景

在上一章中，您创建了`THREE.Scene`，所以您已经了解了 Three.js 的基础知识。我们看到，为了让场景显示任何内容，我们需要三种类型的组件：

| 组件 | 描述 |
| --- | --- |
| 相机 | 这决定了屏幕上的渲染内容。 |
| 灯光 | 这些对材质的显示和创建阴影效果有影响（在第三章中详细讨论，“在 Three.js 中使用不同的光源”）。 |
| 对象 | 这些是从相机的透视角度渲染的主要对象：立方体、球体等。 |

`THREE.Scene`作为所有这些不同对象的容器。这个对象本身并没有太多的选项和功能。

### 注意

`THREE.Scene`是一种有时也被称为场景图的结构。场景图是一种可以容纳图形场景所有必要信息的结构。在 Three.js 中，这意味着`THREE.Scene`包含了所有渲染所需的对象、灯光和其他对象。有趣的是，需要注意的是，场景图并不只是对象的数组；场景图由树结构中的一组节点组成。在 Three.js 中，您可以添加到场景中的每个对象，甚至`THREE.Scene`本身，都是从名为`THREE.Object3D`的基本对象扩展而来。`THREE.Object3D`对象也可以有自己的子对象，您可以使用它们来创建一个 Three.js 将解释和渲染的对象树。

## 场景的基本功能

探索场景功能的最佳方法是查看一个例子。在本章的源代码中，您可以找到`01-basic-scene.html`的例子。我将使用这个例子来解释场景具有的各种功能和选项。当我们在浏览器中打开这个例子时，输出将看起来有点像下一个截图中显示的内容：

![场景的基本功能](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_01.jpg)

这看起来很像我们在上一章中看到的例子。即使场景看起来相当空，它已经包含了一些对象。从下面的源代码中可以看出，我们使用了`THREE.Scene`对象的`scene.add(object)`函数来添加`THREE.Mesh`（您看到的地面平面）、`THREE.SpotLight`和`THREE.AmbientLight`。当您渲染场景时，`THREE.Camera`对象会被 Three.js 自动添加，但是在使用多个相机时，手动将其添加到场景中是一个好的做法。查看下面这个场景的源代码：

```js
var scene = new THREE.Scene();
var camera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 0.1, 1000);
**scene.add(camera);**
...
var planeGeometry = new THREE.PlaneGeometry(60,40,1,1);
var planeMaterial = new THREE.MeshLambertMaterial({color: 0xffffff});
var plane = new THREE.Mesh(planeGeometry,planeMaterial);
...
**scene.add(plane);**
var ambientLight = new THREE.AmbientLight(0x0c0c0c);
**scene.add(ambientLight);**
...
var spotLight = new THREE.SpotLight( 0xffffff );
...
**scene.add( spotLight );**

```

在我们深入研究`THREE.Scene`对象之前，我将首先解释您可以在演示中做什么，之后我们将查看一些代码。在浏览器中打开`01-basic-scene.html`的例子，并查看右上角的控件，如下截图所示：

![场景的基本功能](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_02.jpg)

有了这些控件，你可以向场景中添加一个立方体，移除最后添加到场景中的立方体，并在浏览器的控制台中显示场景当前包含的所有对象。控件部分的最后一个条目显示了场景中对象的当前数量。当你启动场景时，你可能会注意到场景中已经有四个对象。这些是地面平面、环境光、聚光灯以及我们之前提到的摄像机。我们将查看控制部分中的每个功能，并从最简单的`addCube`开始：

```js
this.addCube = function() {

  var cubeSize = Math.ceil((Math.random() * 3));
  var cubeGeometry = new THREE.BoxGeometry(cubeSize,cubeSize,cubeSize);
  var cubeMaterial = new THREE.MeshLambertMaterial({color: Math.random() * 0xffffff });
  var cube = new THREE.Mesh(cubeGeometry, cubeMaterial);
  cube.castShadow = true;
 **cube.name = "cube-" + scene.children.length;**
  cube.position.x=-30 + Math.round(Math.random() * planeGeometry.width));
  cube.position.y= Math.round((Math.random() * 5));
  cube.position.z=-20 + Math.round((Math.random() * planeGeometry.height));

  scene.add(cube);
 **this.numberOfObjects = scene.children.length;**
};
```

到目前为止，这段代码应该已经很容易阅读了。这里没有引入太多新概念。当你点击**addCube**按钮时，会创建一个新的`THREE.BoxGeometry`对象，其宽度、高度和深度设置为 1 到 3 之间的随机值。除了随机大小，立方体还会获得随机颜色和随机位置。

### 注意

我们在这里引入的一个新元素是，我们还使用其`name`属性为立方体命名。它的名称设置为`cube-`，后面跟着当前场景中的对象数量（`scene.children.length`）。名称对于调试非常有用，但也可以用于直接访问你场景中的对象。如果你使用`THREE.Scene.getObjectByName(name)`函数，你可以直接检索特定对象，并且例如，改变它的位置，而不必使 JavaScript 对象成为全局变量。你可能会想知道最后一行代码是做什么的。`numberOfObjects`变量被我们的控制 GUI 用来列出场景中的对象数量。因此，每当我们添加或移除一个对象时，我们都会将这个变量设置为更新后的计数。

我们可以从控制 GUI 中调用的下一个函数是`removeCube`。顾名思义，点击**removeCube**按钮会从场景中移除最后添加的立方体。在代码中，它看起来像这样：

```js
  this.removeCube = function() {
    var allChildren = scene.children;
    var lastObject = allChildren[allChildren.length-1];
    if (lastObject instanceof THREE.Mesh) {
      scene.remove(lastObject);
      this.numberOfObjects = scene.children.length;
    }
  }
```

要向场景中添加对象，我们使用`add`函数。要从场景中移除对象，我们使用，不太意外地，`remove`函数。由于 Three.js 将其子对象存储为列表（新对象添加到末尾），我们可以使用`children`属性，该属性包含场景中所有对象的数组，从`THREE.Scene`对象中获取最后添加的对象。我们还需要检查该对象是否是`THREE.Mesh`对象，以避免移除摄像机和灯光。在我们移除对象之后，我们再次更新 GUI 属性`numberOfObjects`，该属性保存了场景中对象的数量。

我们的 GUI 上的最后一个按钮标有**outputObjects**。你可能已经点击过这个按钮，但似乎什么也没发生。这个按钮会将当前场景中的所有对象打印到网页浏览器控制台中，如下面的截图所示：

![场景的基本功能](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_03.jpg)

将信息输出到控制台日志的代码使用了内置的`console`对象：

```js
  this.outputObjects = function() {
    console.log(scene.children);
  }
```

这对于调试非常有用，特别是当你给你的对象命名时，它非常有用，可以帮助你找到场景中特定对象的问题。例如，`cube-17`的属性看起来像这样（如果你事先知道名称，也可以使用`console.log(scene.getObjectByName("cube-17")`来仅输出单个对象）：

```js
__webglActive: true
__webglInit: true
_listeners: Object
_modelViewMatrix: THREE.Matrix4
_normalMatrix: THREE.Matrix3
castShadow: true
children: Array[0]
eulerOrder: (...)
frustumCulled: true
geometry: THREE.BoxGeometryid: 8
material: THREE.MeshLambertMaterial
matrix: THREE.Matrix4
matrixAutoUpdate: true
matrixWorld: THREE.Matrix4
matrixWorld
NeedsUpdate: false
name: "cube-17"
parent: THREE.Scene
position: THREE.Vector3
quaternion: THREE.Quaternion
receiveShadow: false
renderDepth: null
rotation: THREE.Euler
rotationAutoUpdate: true
scale: THREE.Vector3
type: "Mesh"
up: THREE.Vector3
useQuaternion: (...)
userData: Object
uuid: "DCDC0FD2-6968-44FD-8009-20E9747B8A73"
visible: true
```

到目前为止，我们已经看到了以下与场景相关的功能：

+   `THREE.Scene.Add`：向场景中添加对象

+   `THREE.Scene.Remove`：从场景中移除对象

+   `THREE.Scene.children`：获取场景中所有子对象的列表

+   `THREE.Scene.getObjectByName`：通过名称从场景中获取特定对象

这些是最重要的与场景相关的功能，通常情况下，你不会需要更多。然而，还有一些辅助功能可能会派上用场，我想根据处理立方体旋转的代码来展示它们。

正如您在上一章中看到的，我们使用了*渲染循环*来渲染场景。让我们看看这个示例的循环：

```js
function render() {
  stats.update();
  scene.traverse(function(obj) {
    if (obj instanceof THREE.Mesh && obj != plane ) {
      obj.rotation.x+=controls.rotationSpeed;
      obj.rotation.y+=controls.rotationSpeed;
      obj.rotation.z+=controls.rotationSpeed;
   }
  });

  requestAnimationFrame(render);
  renderer.render(scene, camera);
}
```

在这里，我们看到了使用`THREE.Scene.traverse()`函数。我们可以将一个函数传递给`traverse()`函数，该函数将对场景的每个子对象调用。如果子对象本身有子对象，请记住`THREE.Scene`对象可以包含一个对象树。`traverse()`函数也将对该对象的所有子对象调用。您可以遍历整个场景图。

我们使用`render()`函数来更新每个立方体的旋转（请注意，我们明确忽略了地面平面）。我们也可以通过使用`for`循环迭代`children`属性数组来自己完成这个操作，因为我们只是将对象添加到了`THREE.Scene`中，并没有创建嵌套结构。

在我们深入讨论`THREE.Mesh`和`THREE.Geometry`的细节之前，我想展示一下可以在`THREE.Scene`对象上设置的两个有趣的属性：`fog`和`overrideMaterial`。

## 向场景添加雾效

使用`fog`属性可以向整个场景添加雾效果；物体离得越远，就会越隐匿不见，如下面的截图所示：

![向场景添加雾效](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_04.jpg)

在 Three.js 中启用雾效果非常简单。只需在定义场景后添加以下代码行：

```js
scene.fog=new THREE.Fog( 0xffffff, 0.015, 100 );
```

在这里，我们定义了一个白色的雾（`0xffffff`）。前两个属性可以用来调整雾的外观。`0.015`值设置了`near`属性，`100`值设置了`far`属性。使用这些属性，您可以确定雾从哪里开始以及它变得多快密。使用`THREE.Fog`对象，雾是线性增加的。还有一种不同的设置场景雾的方法；为此，请使用以下定义：

```js
scene.fog=new THREE.FogExp2( 0xffffff, 0.01 );
```

这次，我们不指定`near`和`far`，而只指定颜色（`0xffffff`）和雾的密度（`0.01`）。最好稍微尝试一下这些属性，以获得想要的效果。请注意，使用`THREE.FogExp2`时，雾不是线性增加的，而是随着距离呈指数增长。

## 使用 overrideMaterial 属性

我们讨论场景的最后一个属性是`overrideMaterial`。当使用此属性时，场景中的所有对象将使用设置为`overrideMaterial`属性的材质，并忽略对象本身设置的材质。

像这样使用它：

```js
scene.overrideMaterial = new THREE.MeshLambertMaterial({color: 0xffffff});
```

在上面的代码中使用`overrideMaterial`属性后，场景将呈现如下截图所示：

![使用 overrideMaterial 属性](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_05.jpg)

在上图中，您可以看到所有的立方体都使用相同的材质和颜色进行渲染。在这个示例中，我们使用了`THREE.MeshLambertMaterial`对象作为材质。使用这种材质类型，我们可以创建看起来不那么闪亮的对象，这些对象会对场景中存在的灯光做出响应。在第四章中，*使用 Three.js 材质*，您将了解更多关于这种材质的信息。

在本节中，我们看了 Three.js 的核心概念之一：`THREE.Scene`。关于场景最重要的一点是，它基本上是一个容器，用于渲染时要使用的所有对象、灯光和相机。以下表格总结了`THREE.Scene`对象的最重要的函数和属性：

| 函数/属性 | 描述 |
| --- | --- |
| `add(object)` | 用于将对象添加到场景中。您还可以使用此函数，正如我们稍后将看到的，来创建对象组。 |
| `children` | 返回已添加到场景中的所有对象的列表，包括相机和灯光。 |
| `getObjectByName(name, recursive)` | 当您创建一个对象时，可以为其指定一个独特的名称。场景对象具有一个函数，您可以使用它直接返回具有特定名称的对象。如果将 recursive 参数设置为`true`，Three.js 还将搜索整个对象树以找到具有指定名称的对象。 |
| `remove(object)` | 如果您有场景中对象的引用，也可以使用此函数将其从场景中移除。 |
| `traverse(function)` | children 属性返回场景中所有子对象的列表。使用 traverse 函数，我们也可以访问这些子对象。通过 traverse，所有子对象都会逐个传递给提供的函数。 |
| `fog` | 此属性允许您为场景设置雾。雾会渲染出一个隐藏远处物体的薄雾。 |
| `overrideMaterial` | 使用此属性，您可以强制场景中的所有对象使用相同的材质。 |

在下一节中，我们将更详细地了解您可以添加到场景中的对象。

# 几何图形和网格

到目前为止，在每个示例中，您都看到了使用几何图形和网格。例如，要将一个球体添加到场景中，我们做了以下操作：

```js
var sphereGeometry = new THREE.SphereGeometry(4,20,20);
var sphereMaterial = new THREE.MeshBasicMaterial({color: 0x7777ff);
var sphere = new THREE.Mesh(sphereGeometry,sphereMaterial);
```

我们定义了对象的形状和其几何图形（`THREE.SphereGeometry`），我们定义了这个对象的外观（`THREE.MeshBasicMaterial`）和其材质，并将这两者组合成一个网格（`THREE.Mesh`），可以添加到场景中。在本节中，我们将更详细地了解几何图形和网格是什么。我们将从几何图形开始。

## 几何图形的属性和函数

Three.js 自带了一大堆可以在 3D 场景中使用的几何图形。只需添加一个材质，创建一个网格，基本上就完成了。以下截图来自示例`04-geometries`，显示了 Three.js 中可用的一些标准几何图形：

![几何图形的属性和函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_06.jpg)

在第五章和第六章中，我们将探索 Three.js 提供的所有基本和高级几何图形。现在，我们将更详细地了解几何图形的实际含义。

在 Three.js 中，以及大多数其他 3D 库中，几何图形基本上是 3D 空间中点的集合，也称为顶点，以及连接这些点的一些面。例如，一个立方体：

+   一个立方体有八个角。每个角可以定义为*x*、*y*和*z*坐标。因此，每个立方体在 3D 空间中有八个点。在 Three.js 中，这些点被称为顶点，单个点被称为顶点。

+   一个立方体有六个面，每个角有一个顶点。在 Three.js 中，一个面始终由三个顶点组成一个三角形。因此，在立方体的情况下，每个面由两个三角形组成，以形成完整的面。

当您使用 Three.js 提供的几何图形之一时，您不必自己定义所有顶点和面。对于一个立方体，您只需要定义宽度、高度和深度。Three.js 使用这些信息，在正确的位置创建一个具有八个顶点和正确数量的面（在立方体的情况下为 12 个）的几何图形。即使您通常会使用 Three.js 提供的几何图形或自动生成它们，您仍然可以使用顶点和面完全手工创建几何图形。以下代码行显示了这一点：

```js
var vertices = [
  new THREE.Vector3(1,3,1),
  new THREE.Vector3(1,3,-1),
  new THREE.Vector3(1,-1,1),
  new THREE.Vector3(1,-1,-1),
  new THREE.Vector3(-1,3,-1),
  new THREE.Vector3(-1,3,1),
  new THREE.Vector3(-1,-1,-1),
  new THREE.Vector3(-1,-1,1)
];

var faces = [
  new THREE.Face3(0,2,1),
  new THREE.Face3(2,3,1),
  new THREE.Face3(4,6,5),
  new THREE.Face3(6,7,5),
  new THREE.Face3(4,5,1),
  new THREE.Face3(5,0,1),
  new THREE.Face3(7,6,2),
  new THREE.Face3(6,3,2),
  new THREE.Face3(5,7,0),
  new THREE.Face3(7,2,0),
  new THREE.Face3(1,3,4),
  new THREE.Face3(3,6,4),
];

var geom = new THREE.Geometry();
geom.vertices = vertices;
geom.faces = faces;
geom.computeFaceNormals();
```

这段代码展示了如何创建一个简单的立方体。我们在`vertices`数组中定义了构成这个立方体的点。这些点连接在一起形成三角形面，并存储在`faces`数组中。例如，`new THREE.Face3(0,2,1)`使用`vertices`数组中的点`0`、`2`和`1`创建了一个三角形面。请注意，你必须注意用于创建`THREE.Face`的顶点的顺序。定义它们的顺序决定了 Three.js 认为它是一个正面面（面向摄像机的面）还是一个背面面。如果你创建面，应该对正面面使用顺时针顺序，对背面面使用逆时针顺序。

### 提示

在这个例子中，我们使用了`THREE.Face3`元素来定义立方体的六个面，每个面有两个三角形。在 Three.js 的早期版本中，你也可以使用四边形而不是三角形。四边形使用四个顶点而不是三个来定义面。在 3D 建模世界中，使用四边形还是三角形更好是一个激烈的争论。基本上，使用四边形在建模过程中通常更受欢迎，因为它们比三角形更容易增强和平滑。然而，在渲染和游戏引擎中，使用三角形通常更容易，因为每个形状都可以被渲染为三角形。

使用这些顶点和面，我们现在可以创建一个`THREE.Geometry`的新实例，并将顶点分配给`vertices`属性，将面分配给`faces`属性。我们需要采取的最后一步是在我们创建的几何形状上调用`computeFaceNormals()`。当我们调用这个函数时，Three.js 确定了每个面的*法向*向量。这是 Three.js 用来根据场景中的各种光源确定如何给面上色的信息。

有了这个几何形状，我们现在可以创建一个网格，就像我们之前看到的那样。我创建了一个例子，你可以用来玩弄顶点的位置，并显示各个面。在例子`05-custom-geometry`中，你可以改变立方体所有顶点的位置，看看面的反应。下面是一个截图（如果控制 GUI 挡住了视线，你可以通过按下*H*键来隐藏它）：

![几何形状的属性和函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_07.jpg)

这个例子使用了与我们其他例子相同的设置，有一个渲染循环。每当你改变下拉控制框中的属性时，立方体就会根据一个顶点的改变位置进行渲染。这并不是一件轻而易举的事情。出于性能原因，Three.js 假设网格的几何形状在其生命周期内不会改变。对于大多数的几何形状和用例来说，这是一个非常合理的假设。然而，为了让我们的例子工作，我们需要确保以下内容被添加到渲染循环的代码中：

```js
mesh.children.forEach(function(e) {
  e.geometry.vertices=vertices;
  e.geometry.verticesNeedUpdate=true;
  e.geometry.computeFaceNormals();
});
```

在第一行中，我们将屏幕上看到的网格的顶点指向一个更新后的顶点数组。我们不需要重新配置面，因为它们仍然连接到与之前相同的点。设置更新后的顶点后，我们需要告诉几何形状顶点需要更新。我们通过将几何形状的`verticesNeedUpdate`属性设置为`true`来做到这一点。最后，我们通过`computeFaceNormals`函数对面进行重新计算，以更新完整的模型。

我们将要看的最后一个几何功能是`clone()`函数。我们提到几何图形定义了对象的形状和形状，结合材质，我们创建了一个可以添加到场景中由 Three.js 渲染的对象。使用`clone()`函数，正如其名称所示，我们可以复制几何图形，并且例如，使用它来创建一个具有不同材质的不同网格。在相同的示例`05-custom-geometry`中，你可以在控制 GUI 的顶部看到一个**clone**按钮，如下面的截图所示：

![几何图形的属性和函数](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_08.jpg)

如果你点击这个按钮，将会克隆（复制）当前的几何图形，创建一个新的对象并添加到场景中。这段代码相当简单，但由于我使用的材质而变得有些复杂。让我们退一步，首先看一下立方体的绿色材质是如何创建的，如下面的代码所示：

```js
var materials = [
  new THREE.MeshLambertMaterial( { opacity:0.6, color: 0x44ff44, transparent:true } ),
  new THREE.MeshBasicMaterial( { color: 0x000000, wireframe: true } )
];
```

正如你所看到的，我并没有使用单一的材质，而是使用了一个包含两种材质的数组。原因是除了显示一个透明的绿色立方体，我还想向你展示线框，因为线框非常清楚地显示了顶点和面的位置。

当创建网格时，Three.js 当然支持使用多种材质。你可以使用`SceneUtils.createMultiMaterialObject`函数来实现这一点，如下面的代码所示：

```js
var mesh = THREE.SceneUtils.createMultiMaterialObject( geom, materials);
```

这个函数在这里所做的是不仅创建一个`THREE.Mesh`对象，而是为你指定的每种材质创建一个，并将这些网格放在一个组中（一个`THREE.Object3D`对象）。这个组可以像你使用场景对象一样使用。你可以添加网格，通过名称获取对象等。例如，为了确保组的所有子对象都投射阴影，你可以这样做：

```js
mesh.children.forEach(function(e) {e.castShadow=true});
```

现在，让我们回到我们正在讨论的`clone()`函数：

```js
this.clone = function() {

  var clonedGeom = mesh.children[0].geometry.clone();
  var materials = [
    new THREE.MeshLambertMaterial( { opacity:0.6, color: 0xff44ff, transparent:true } ),
    new THREE.MeshBasicMaterial({ color: 0x000000, wireframe: true } )
  ];

  var mesh2 = THREE.SceneUtils.createMultiMaterialObject(clonedGeom, materials);
  mesh2.children.forEach(function(e) {e.castShadow=true});
  mesh2.translateX(5);
  mesh2.translateZ(5);
  mesh2.name="clone";
  scene.remove(scene.getObjectByName("clone"));
  scene.add(mesh2);
}
```

当点击**clone**按钮时，将调用这段 JavaScript 代码。在这里，我们克隆了我们的立方体的第一个子对象的几何图形。记住，网格变量包含两个子对象；它包含两个网格，一个用于我们指定的每种材质。基于这个克隆的几何图形，我们创建一个新的网格，恰当地命名为`mesh2`。我们使用平移函数移动这个新的网格（关于这一点我们将在第五章中详细讨论），移除之前的克隆（如果存在），并将克隆添加到场景中。

### 提示

在前面的部分中，我们使用了`THREE.SceneUtils`对象的`createMultiMaterialObject`来为我们创建的几何图形添加线框。Three.js 还提供了另一种使用`THREE.WireFrameHelper`添加线框的方法。要使用这个辅助程序，首先要像这样实例化辅助程序：

```js
**var helper = new THREE.WireframeHelper(mesh, 0x000000);**

```

你提供你想要显示线框的网格和线框的颜色。Three.js 现在将创建一个你可以添加到场景中的辅助对象，`scene.add(helper)`。由于这个辅助对象内部只是一个`THREE.Line`对象，你可以设置线框的外观。例如，要设置线框线的宽度，使用`helper.material.linewidth = 2;`。 

现在关于几何图形的内容就到此为止。

## 网格的函数和属性

我们已经学会了创建网格时需要一个几何图形和一个或多个材质。一旦我们有了网格，我们将其添加到场景中并进行渲染。有一些属性可以用来改变这个网格在场景中的位置和外观。在这个第一个示例中，我们将看到以下一组属性和函数：

| 功能/属性 | 描述 |
| --- | --- |
| `position` | 这确定了这个对象相对于其父对象位置的位置。大多数情况下，对象的父对象是一个`THREE.Scene`对象或一个`THREE.Object3D`对象。 |
| `rotation` | 通过这个属性，您可以设置对象围绕任意轴的旋转。Three.js 还提供了围绕轴旋转的特定函数：`rotateX()`、`rotateY()`和`rotateZ()`。 |
| `scale` | 这个属性允许您沿着*x*、*y*和*z*轴缩放对象。 |
| `translateX(amount)` | 这个属性将对象沿着*x*轴移动指定的距离。 |
| `translateY(amount)` | 这个属性将对象沿着*y*轴移动指定的距离。 |
| `translateZ(amount)` | 这个属性将对象沿着*z*轴移动指定的距离。对于平移函数，您还可以使用`translateOnAxis(axis, distance)`函数，它允许您沿着特定轴平移网格一定距离。 |
| `visible` | 如果将此属性设置为`false`，`THREE.Mesh`将不会被 Three.js 渲染。 |

和往常一样，我们为您准备了一个示例，让您可以尝试这些属性。如果您在浏览器中打开`06-mesh-properties.html`，您将获得一个下拉菜单，您可以在其中改变所有这些属性，并直接看到结果，如下面的截图所示：

![网格的函数和属性](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_09.jpg)

让我带您了解一下，我将从位置属性开始。我们已经看到这个属性几次了，所以让我们快速解决这个问题。通过这个属性，您可以设置对象的*x*、*y*和*z*坐标。这个位置是相对于其父对象的，通常是您将对象添加到的场景，但也可以是`THREE.Object3D`对象或另一个`THREE.Mesh`对象。当我们查看分组对象时，我们将在第五章中回到这一点，*学习使用几何图形*。我们可以以三种不同的方式设置对象的位置属性。我们可以直接设置每个坐标：

```js
cube.position.x=10;
cube.position.y=3;
cube.position.z=1;
```

但是，我们也可以一次性设置它们所有，如下所示：

```js
cube.position.set(10,3,1);
```

还有第三个选项。`position`属性是一个`THREE.Vector3`对象。这意味着，我们也可以这样设置这个对象：

```js
cube.postion=new THREE.Vector3(10,3,1)
```

在查看此网格的其他属性之前，我想快速地侧重一下。我提到这个位置是相对于其父级的位置。在上一节关于`THREE.Geometry`的部分中，我们使用了`THREE.SceneUtils.createMultiMaterialObject`来创建一个多材质对象。我解释说，这实际上并不返回一个单一的网格，而是一个包含基于相同几何形状的每种材质的网格的组合；在我们的情况下，它是一个包含两个网格的组合。如果我们改变其中一个创建的网格的位置，您可以清楚地看到它实际上是两个不同的`THREE.Mesh`对象。然而，如果我们现在移动这个组合，偏移量将保持不变，如下面的截图所示。在第五章中，*学习使用几何图形*，我们将更深入地研究父子关系以及分组如何影响缩放、旋转和平移等变换。

![网格的函数和属性](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_10.jpg)

好的，接下来列表中的是`rotation`属性。在本章和上一章中，您已经看到了这个属性被使用了几次。通过这个属性，您可以设置对象围绕其中一个轴的旋转。您可以以与设置位置相同的方式设置这个值。完整的旋转，您可能还记得数学课上学过，是*2 x π*。您可以在 Three.js 中以几种不同的方式配置这个属性：

```js
cube.rotation.x = 0.5*Math.PI;
cube.rotation.set(0.5*Math.PI, 0, 0);
cube.rotation = new THREE.Vector3(0.5*Math.PI,0,0);
```

如果您想使用度数（从 0 到 360）而不是弧度，我们需要将其转换为弧度。可以像这样轻松地完成这个转换：

```js
Var degrees = 45;
Var inRadians = degrees * (Math.PI / 180);
```

您可以使用`06-mesh-properties.html`示例来尝试这个属性。

我们列表中的下一个属性是我们还没有讨论过的：`scale`。名称基本上总结了您可以使用此属性做什么。您可以沿着特定轴缩放物体。如果将缩放设置为小于 1 的值，物体将缩小，如下面的屏幕截图所示：

![网格的函数和属性](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_11.jpg)

当您使用大于 1 的值时，物体将变大，如下面的屏幕截图所示：

![网格的函数和属性](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_12.jpg)

本章我们将要看的网格的下一个部分是**translate**功能。使用 translate，您也可以改变物体的位置，但是不是定义物体应该在的绝对位置，而是定义物体相对于当前位置应该移动到哪里。例如，我们有一个添加到场景中的球体，其位置已设置为`(1,2,3)`。接下来，我们沿着*x*轴平移物体：`translateX(4)`。它的位置现在将是`(5,2,3)`。如果我们想将物体恢复到原始位置，我们可以这样做：`translateX(-4)`。在`06-mesh-properties.html`示例中，有一个名为**translate**的菜单选项。从那里，您可以尝试这个功能。只需设置*x*、*y*和*z*的平移值，然后点击**translate**按钮。您将看到物体根据这三个值被移动到一个新的位置。

我们在右上角菜单中可以使用的最后一个属性是**visible**属性。如果单击**visible**菜单项，您会看到立方体变得不可见，如下所示：

![网格的函数和属性](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_13.jpg)

当您再次单击它时，立方体将再次可见。有关网格、几何体以及您可以对这些对象进行的操作的更多信息，请参阅第五章、*学习使用几何体*和第七章、*粒子、精灵和点云*。

# 不同用途的不同摄像机

Three.js 中有两种不同的摄像机类型：正交摄像机和透视摄像机。在第三章、*使用 Three.js 中可用的不同光源*中，我们将更详细地了解如何使用这些摄像机，因此在本章中，我将坚持基础知识。解释这些摄像机之间的区别的最佳方法是通过几个示例来看。

## 正交摄像机与透视摄像机

在本章的示例中，您可以找到一个名为`07-both-cameras.html`的演示。当您打开此示例时，您将看到类似于这样的东西：

![正交摄像机与透视摄像机](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_14.jpg)

这被称为透视视图，是最自然的视图。从这个图中可以看出，物体距离摄像机越远，呈现的越小。

如果我们将摄像机更改为 Three.js 支持的另一种类型，即正交摄像机，您将看到相同场景的以下视图：

![正交摄像机与透视摄像机](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_15.jpg)

使用正交摄像机，所有的立方体都以相同的大小呈现；物体与摄像机之间的距离并不重要。这在 2D 游戏中经常使用，比如*模拟城市 4*和*文明*的旧版本。

![正交摄像机与透视摄像机](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_16.jpg)

在我们的示例中，我们将最常使用透视摄像机，因为它最接近现实世界。切换摄像机非常容易。每当您在`07-both-cameras`示例上点击切换摄像机按钮时，都会调用以下代码片段：

```js
this.switchCamera = function() {
  if (camera instanceof THREE.PerspectiveCamera) {
    camera = new THREE.OrthographicCamera( window.innerWidth / - 16, window.innerWidth / 16, window.innerHeight / 16, window.innerHeight / - 16, -200, 500 );
    camera.position.x = 120;
    camera.position.y = 60;
    camera.position.z = 180;
    camera.lookAt(scene.position);
    this.perspective = "Orthographic";
  } else {
    camera = new THREE.PerspectiveCamera(45, window.innerWidth / window.innerHeight, 0.1, 1000);

    camera.position.x = 120;
    camera.position.y = 60;
    camera.position.z = 180;

    camera.lookAt(scene.position);
    this.perspective = "Perspective";
  }
};
```

在这个表中，你可以看到我们创建相机的方式有所不同。让我们先看一下`THREE.PerspectiveCamera`。这个相机接受以下参数：

| 参数 | 描述 |
| --- | --- |
| `fov` | **FOV**代表**视野**。这是从相机位置可以看到的场景的一部分。例如，人类几乎有 180 度的视野，而一些鸟类甚至可能有完整的 360 度视野。但由于普通电脑屏幕无法完全填满我们的视野，通常会选择一个较小的值。大多数情况下，游戏中选择的 FOV 在 60 到 90 度之间。*良好的默认值：50* |
| `aspect` | 这是我们要渲染输出的区域的水平和垂直尺寸之间的纵横比。在我们的情况下，由于我们使用整个窗口，我们只使用该比率。纵横比决定了水平 FOV 和垂直 FOV 之间的差异，如你可以在下图中看到的那样。*良好的默认值：window.innerWidth / window.innerHeight* |
| `near` | `near`属性定义了 Three.js 应该从相机位置渲染场景的距离。通常情况下，我们将其设置为一个非常小的值，直接从相机位置渲染所有东西。*良好的默认值：0.1* |
| `far` | `far`属性定义了相机从相机位置能看到的距离。如果我们设置得太低，可能会导致我们的场景的一部分不被渲染，如果设置得太高，在某些情况下可能会影响渲染性能。*良好的默认值：1000* |
| `zoom` | `zoom`属性允许你放大或缩小场景。当你使用小于`1`的数字时，你会缩小场景，如果你使用大于`1`的数字，你会放大。请注意，如果你指定一个负值，场景将被倒置渲染。*良好的默认值：1* |

以下图像很好地概述了这些属性如何共同确定你所看到的内容：

![正交相机与透视相机](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_17.jpg)

相机的`fov`属性确定了水平 FOV。基于`aspect`属性，确定了垂直 FOV。`near`属性用于确定近平面的位置，`far`属性确定了远平面的位置。在近平面和远平面之间的区域将被渲染。

要配置正交相机，我们需要使用其他属性。正交投影对使用的纵横比或我们观察场景的 FOV 都不感兴趣，因为所有的物体都以相同的大小渲染。当你定义一个正交相机时，你所做的就是定义需要被渲染的长方体区域。正交相机的属性反映了这一点，如下所示：

| 参数 | 描述 |
| --- | --- |
| `left` | 这在 Three.js 文档中被描述为*相机截头锥左平面*。你应该把它看作是将要被渲染的左边界。如果你将这个值设置为`-100`，你就看不到任何在左侧更远处的物体。 |
| `right` | `right`属性的工作方式类似于`left`属性，但这次是在屏幕的另一侧。任何更远的右侧都不会被渲染。 |
| `top` | 这是要渲染的顶部位置。 |
| `bottom` | 这是要渲染的底部位置。 |
| `near` | 从这一点开始，基于相机的位置，场景将被渲染。 |
| `far` | 到这一点，基于相机的位置，场景将被渲染。 |
| `zoom` | 这允许你放大或缩小场景。当你使用小于`1`的数字时，你会缩小场景；如果你使用大于`1`的数字，你会放大。请注意，如果你指定一个负值，场景将被倒置渲染。默认值为`1`。 |

所有这些属性可以总结在下图中：

![正交相机与透视相机](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_18.jpg)

## 观察特定点

到目前为止，您已经了解了如何创建摄像机以及各种参数的含义。在上一章中，您还看到需要将摄像机定位在场景中的某个位置，并且从摄像机的视角进行渲染。通常，摄像机指向场景的中心：位置（0,0,0）。然而，我们可以很容易地改变摄像机的观察对象，如下所示：

```js
camera.lookAt(new THREE.Vector3(x,y,z));
```

我添加了一个示例，其中摄像机移动，它所看的点用红点标记如下：

![观察特定点](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_19.jpg)

如果您打开`08-cameras-lookat`示例，您将看到场景从左向右移动。实际上场景并没有移动。摄像机正在看不同的点（请参见中心的红点），这会产生场景从左向右移动的效果。在这个示例中，您还可以切换到正交摄像机。在那里，您会发现改变摄像机观察的点几乎与`THREE.PerspectiveCamera`具有相同的效果。然而，值得注意的是，使用`THREE.OrthographicCamera`，您可以清楚地看到无论摄像机看向何处，所有立方体的大小都保持不变。

![观察特定点](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_02_20.jpg)

### 提示

当您使用`lookAt`函数时，您将摄像机对准特定位置。您还可以使用它来使摄像机在场景中跟随物体移动。由于每个`THREE.Mesh`对象都有一个`THREE.Vector3`对象的位置，您可以使用`lookAt`函数指向场景中的特定网格。您只需要这样做：`camera.lookAt(mesh.position)`。如果您在渲染循环中调用此函数，您将使摄像机跟随物体在场景中移动。

# 总结

我们在这第二个介绍章节中讨论了很多内容。我们展示了`THREE.Scene`的所有函数和属性，并解释了如何使用这些属性来配置您的主场景。我们还向您展示了如何创建几何体。您可以使用`THREE.Geometry`对象从头开始创建它们，也可以使用 Three.js 提供的任何内置几何体。最后，我们向您展示了如何配置 Three.js 提供的两个摄像机。`THREE.PerspectiveCamera`使用真实世界的透视渲染场景，而`THREE.OrthographicCamera`提供了在游戏中经常看到的虚假 3D 效果。我们还介绍了 Three.js 中几何体的工作原理。您现在可以轻松地创建自己的几何体。

在下一章中，我们将看看 Three.js 中可用的各种光源。您将了解各种光源的行为，如何创建和配置它们以及它们如何影响特定材质。


# 第三章：使用 Three.js 中可用的不同光源

在第一章中，您学习了 Three.js 的基础知识，在上一章中，我们更深入地了解了场景中最重要的部分：几何体、网格和相机。您可能已经注意到，在那一章中我们跳过了灯光，尽管它们构成了每个 Three.js 场景的重要部分。没有灯光，我们将看不到任何渲染。由于 Three.js 包含大量的灯光，每种灯光都有特定的用途，我们将用整个章节来解释灯光的各种细节，并为下一章关于材质使用做好准备。

### 注

WebGL 本身并不直接支持照明。如果没有 Three.js，您将不得不编写特定的 WebGL 着色器程序来模拟这些类型的灯光。您可以在[`developer.mozilla.org/en-US/docs/Web/WebGL/Lighting_in_WebGL`](https://developer.mozilla.org/en-US/docs/Web/WebGL/Lighting_in_WebGL)找到有关在 WebGL 中模拟照明的良好介绍。

在这一章中，您将学习以下主题：

+   在 Three.js 中可用的光源

+   何时应该使用特定的光源

+   您如何调整和配置所有这些光源的行为

+   作为奖励，我们还将快速看一下如何创建镜头眩光

与所有章节一样，我们有很多示例供您用来实验灯光的行为。本章中展示的示例可以在提供的源代码的`chapter-03`文件夹中找到。

# Three.js 提供的不同类型的照明

Three.js 中有许多不同的灯光可用，它们都具有特定的行为和用途。在这一章中，我们将讨论以下一组灯光：

| 名称 | 描述 |
| --- | --- |
| `THREE.AmbientLight` | 这是一种基本的光，其颜色被添加到场景中对象的当前颜色中。 |
| `THREE.PointLight` | 这是空间中的一个单点，光从这个点向所有方向扩散。这种光不能用来创建阴影。 |
| `THREE.SpotLight` | 这种光源具有类似台灯、天花板上的聚光灯或火炬的锥形效果。这种光可以投射阴影。 |
| `THREE.DirectionalLight` | 这也被称为无限光。这种光的光线可以被视为平行的，就像太阳的光一样。这种光也可以用来创建阴影。 |
| `THREE.HemisphereLight` | 这是一种特殊的光，可以用来通过模拟反射表面和微弱照亮的天空来创建更自然的室外照明。这种光也不提供任何与阴影相关的功能。 |
| `THREE.AreaLight` | 使用这种光源，您可以指定一个区域，而不是空间中的单个点，从这个区域发出光。`THREE.AreaLight`不会投射任何阴影。 |
| `THREE.LensFlare` | 这不是一个光源，但使用`THREE.LensFlare`，您可以为场景中的灯光添加镜头眩光效果。 |

这一章分为两个主要部分。首先，我们将看一下基本的灯光：`THREE.AmbientLight`、`THREE.PointLight`、`THREE.SpotLight`和`THREE.DirectionalLight`。所有这些灯光都扩展了基本的`THREE.Light`对象，提供了共享功能。这里提到的灯光都是简单的灯光，需要很少的设置，并且可以用来重新创建大部分所需的照明场景。在第二部分中，我们将看一下一些特殊用途的灯光和效果：`THREE.HemisphereLight`、`THREE.AreaLight`和`THREE.LensFlare`。您可能只在非常特殊的情况下需要这些灯光。

# 基本灯光

我们将从最基本的灯光开始：`THREE.AmbientLight`。

## THREE.AmbientLight

当你创建`THREE.AmbientLight`时，颜色是全局应用的。这种光没有特定的方向，`THREE.AmbientLight`不会对任何阴影产生影响。你通常不会将`THREE.AmbientLight`作为场景中唯一的光源，因为它会使所有的物体都呈现相同的颜色，而不考虑形状。你会将它与其他光源一起使用，比如`THREE.SpotLight`或`THREE.DirectionalLight`，来软化阴影或为场景增加一些额外的颜色。最容易理解的方法是查看`chapter-03`文件夹中的`01-ambient-light.html`示例。通过这个示例，你可以得到一个简单的用户界面，用于修改这个场景中可用的`THREE.AmbientLight`。请注意，在这个场景中，我们还有`THREE.SpotLight`，它提供了额外的照明并产生阴影。

在下面的截图中，你可以看到我们使用了第一章的场景，并使`THREE.AmbientLight`的颜色可配置。在这个示例中，你还可以关闭聚光灯，看看`THREE.AmbientLight`单独的效果：

![THREE.AmbientLight](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_01.jpg)

我们在这个场景中使用的标准颜色是`#0c0c0c`。这是颜色的十六进制表示。前两个值指定颜色的红色部分，接下来的两个值指定绿色部分，最后两个值指定蓝色部分。

在这个示例中，我们使用了一个非常昏暗的浅灰色，主要用于使我们的网格投射到地面平面上的硬阴影变得柔和。你可以通过右上角的菜单将颜色更改为更显眼的黄/橙色（`#523318`），然后物体将在上面产生太阳般的光芒。这在下面的截图中显示：

![THREE.AmbientLight](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_02.jpg)

正如前面的图片所示，黄/橙色应用到了所有的物体，并在整个场景上投射出绿色的光晕。在使用这种光时，你应该记住的是，你应该非常谨慎地选择颜色。如果你选择的颜色太亮，你很快就会得到一个完全过饱和的图像。

现在我们已经看到它的作用，让我们看看如何创建和使用`THREE.AmbientLight`。接下来的几行代码向你展示了如何创建`THREE.AmbientLight`，并展示了如何将其连接到 GUI 控制菜单，我们将在第十一章中介绍，*自定义着色器和渲染后处理*：

```js
var ambiColor = "#0c0c0c";
var ambientLight = new THREE.AmbientLight(ambiColor);
scene.add(ambientLight);
...

var controls = new function() {
  this.ambientColor = ambiColor  ;
}

var gui = new dat.GUI();
gui.addColor(controls, 'ambientColor').onChange(function(e) {
  ambientLight.color = new THREE.Color(e);
});
```

创建`THREE.AmbientLight`非常简单，只需要几个步骤。`THREE.AmbientLight`没有位置，是全局应用的，所以我们只需要指定颜色（十六进制），`new THREE.AmbientLight(ambiColor)`，并将这个光添加到场景中，`scene.add(ambientLight)`。在示例中，我们将`THREE.AmbientLight`的颜色绑定到控制菜单。要做到这一点，可以使用我们在前两章中使用的相同类型的配置。唯一的变化是，我们使用`gui.addColor(...)`函数，而不是使用`gui.add(...)`函数。这在控制菜单中创建一个选项，我们可以直接改变传入变量的颜色。在代码中，你可以看到我们使用了 dat.GUI 的`onChange`特性：`gui.addColor(...).onChange(function(e){...})`。通过这个函数，我们告诉`dat.GUI`每次颜色改变时调用传入的函数。在这种特定情况下，我们将`THREE.AmbientLight`的颜色设置为一个新值。

### 使用 THREE.Color 对象

在我们继续下一个光源之前，这里有一个关于使用`THREE.Color`对象的快速说明。在 Three.js 中，当您构造一个对象时，通常可以将颜色指定为十六进制字符串(`"#0c0c0c"`)或十六进制值(`0x0c0c0c`)，这是首选的方法，或者通过指定 0 到 1 的范围上的单独的 RGB 值(`0.3`，`0.5`，`0.6`)。如果您想在构造后更改颜色，您将不得不创建一个新的`THREE.Color`对象或修改当前`THREE.Color`对象的内部属性。`THREE.Color`对象具有以下函数来设置和获取有关当前对象的信息：

| 名称 | 描述 |
| --- | --- |
| `set(value)` | 将此颜色的值设置为提供的十六进制值。此十六进制值可以是字符串、数字或现有的`THREE.Color`实例。 |
| `setHex(value)` | 将此颜色的值设置为提供的数值十六进制值。 |
| `setRGB(r,g,b)` | 根据提供的 RGB 值设置此颜色的值。值的范围从 0 到 1。 |
| `setHSL(h,s,l)` | 根据提供的 HSL 值设置此颜色的值。值的范围从 0 到 1。有关如何使用 HSL 配置颜色的良好解释可以在[`en.wikibooks.org/wiki/Color_Models:_RGB,_HSV,_HSL`](http://en.wikibooks.org/wiki/Color_Models:_RGB,_HSV,_HSL)找到。 |
| `setStyle(style)` | 根据指定颜色的 CSS 方式设置此颜色的值。例如，您可以使用`"rgb(255,0,0)"`，`"#ff0000"`，`"#f00"`，甚至`"red"`。 |
| `copy(color)` | 将提供的`THREE.Color`实例的颜色值复制到此颜色。 |
| `copyGammaToLinear(color)` | 这主要是在内部使用。根据提供的`THREE.Color`实例设置此对象的颜色。首先将颜色从伽马颜色空间转换为线性颜色空间。伽马颜色空间也使用 RGB 值，但使用的是指数比例而不是线性比例。 |
| `copyLinearToGamma(color)` | 这主要是在内部使用。根据提供的`THREE.Color`实例设置此对象的颜色。首先将颜色从线性颜色空间转换为伽马颜色空间。 |
| `convertGammaToLinear()` | 将当前颜色从伽马颜色空间转换为线性颜色空间。 |
| `convertLinearToGamma()` | 将当前颜色从线性颜色空间转换为伽马颜色空间。 |
| `getHex()` | 以数字形式返回此颜色对象的值：`435241`。 |
| `getHexString()` | 以十六进制字符串形式返回此颜色对象的值：`"0c0c0c"`。 |
| `getStyle()` | 以基于 CSS 的值返回此颜色对象的值：`"rgb(112,0,0)"`。 |
| `getHSL(optionalTarget)` | 以 HSL 值的形式返回此颜色对象的值。如果提供`optionalTarget`对象，Three.js 将在该对象上设置`h`、`s`和`l`属性。 |
| `offsetHSL(h, s, l)` | 将提供的`h`、`s`和`l`值添加到当前颜色的`h`、`s`和`l`值中。 |
| `add(color)` | 将提供的颜色的`r`、`g`和`b`值添加到当前颜色。 |
| `addColors(color1, color2)` | 这主要是在内部使用。添加`color1`和`color2`，并将当前颜色的值设置为结果。 |
| `addScalar(s)` | 这主要是在内部使用。将一个值添加到当前颜色的 RGB 分量中。请记住，内部值使用 0 到 1 的范围。 |
| `multiply(color)` | 这主要是在内部使用。将当前 RGB 值与`THREE.Color`的 RGB 值相乘。 |
| `multiplyScalar(s)` | 这主要是在内部使用。将当前 RGB 值与提供的值相乘。请记住，内部值使用 0 到 1 的范围。 |
| `lerp(color, alpha)` | 这主要是在内部使用。找到介于此对象颜色和提供的颜色之间的颜色。alpha 属性定义了你希望结果在当前颜色和提供的颜色之间的距离。 |
| `equals(color)` | 如果提供的`THREE.Color`实例的 RGB 值与当前颜色的值匹配，则返回`true`。 |
| `fromArray(array)` | 这与`setRGB`具有相同的功能，但现在 RGB 值可以作为数字数组提供。 |
| `toArray` | 这将返回一个包含三个元素的数组，`[r, g, b]`。 |
| `clone()` | 这将创建这种颜色的精确副本。 |

在这个表中，你可以看到有很多种方法可以改变当前的颜色。很多这些函数在 Three.js 内部被使用，但它们也提供了一个很好的方式来轻松改变光和材质的颜色。

在我们继续讨论`THREE.PointLight`，`THREE.SpotLight`和`THREE.DirectionalLight`之前，让我们首先强调它们的主要区别，即它们如何发光。以下图表显示了这三种光源是如何发光的：

![使用 THREE.Color 对象](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_03.jpg)

你可以从这个图表中看到以下内容：

+   `THREE.PointLight`从一个特定点向所有方向发光

+   `THREE.SpotLight`从一个特定点发射出锥形的光

+   `THREE.DirectionalLight`不是从单一点发光，而是从一个二维平面发射光线，光线是平行的

我们将在接下来的几段中更详细地看这些光源；让我们从`THREE.Pointlight`开始。

## THREE.PointLight

在 Three.js 中，`THREE.PointLight`是一个从单一点发出的照射所有方向的光源。一个很好的例子是夜空中发射的信号弹。就像所有的光源一样，我们有一个具体的例子可以用来玩`THREE.PointLight`。如果你在`chapter-03`文件夹中查看`02-point-light.html`，你可以找到一个例子，其中`THREE.PointLight`在一个简单的 Three.js 场景中移动。以下截图显示了这个例子：

![THREE.PointLight](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_04.jpg)

在这个例子中，`THREE.PointLight`在我们已经在第一章中看到的场景中移动，*使用 Three.js 创建你的第一个 3D 场景*。为了更清楚地看到`THREE.PointLight`在哪里，我们沿着相同的路径移动一个小橙色的球体。当这个光源移动时，你会看到红色的立方体和蓝色的球体在不同的侧面被这个光源照亮。

### 提示

你可能会注意到在这个例子中我们没有看到任何阴影。在 Three.js 中，`THREE.PointLight`不会投射阴影。由于`THREE.PointLight`向所有方向发光，计算阴影对于 GPU 来说是一个非常繁重的过程。

与我们之前看到的`THREE.AmbientLight`不同，你只需要提供`THREE.Color`并将光源添加到场景中。然而，对于`THREE.PointLight`，我们有一些额外的配置选项：

| 属性 | 描述 |
| --- | --- |
| `color` | 这是光的颜色。 |
| `distance` | 这是光照射的距离。默认值为`0`，这意味着光的强度不会根据距离而减少。 |
| `intensity` | 这是光的强度。默认值为`1`。 |
| `position` | 这是`THREE.Scene`中光的位置。 |
| `visible` | 如果将此属性设置为`true`（默认值），则此光源将打开，如果设置为`false`，则光源将关闭。 |

在接下来的几个例子和截图中，我们将解释这些属性。首先，让我们看看如何创建`THREE.PointLight`：

```js
var pointColor = "#ccffcc";
var pointLight = new THREE.PointLight(pointColor);
pointLight.position.set(10,10,10);
scene.add(pointLight);
```

我们创建了一个具有特定`color`属性的光（这里我们使用了一个字符串值；我们也可以使用一个数字或`THREE.Color`），设置了它的`position`属性，并将其添加到场景中。

我们首先要看的属性是 `intensity`。通过这个属性，你可以设置光的亮度。如果你将其设置为 `0`，你将看不到任何东西；将其设置为 `1`，你将得到默认的亮度；将其设置为 `2`，你将得到两倍亮度的光；依此类推。例如，在下面的截图中，我们将光的强度设置为 `2.4`：

![THREE.PointLight](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_05.jpg)

要改变光的强度，你只需要使用 `THREE.PointLight` 的 `intensity` 属性，如下所示：

```js
pointLight.intensity = 2.4;
```

或者你可以使用 dat.GUI 监听器，像这样：

```js
var controls = new function() {
  this.intensity = 1;
}
var gui = new dat.GUI();
  gui.add(controls, 'intensity', 0, 3).onChange(function (e) {
    pointLight.intensity = e;
  });
```

`PointLight` 的 `distance` 属性非常有趣，最好通过一个例子来解释。在下面的截图中，你会看到同样的场景，但这次是一个非常高的 `intensity` 属性（我们有一个非常明亮的光），但是有一个很小的 `distance`：

![THREE.PointLight](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_06.jpg)

`SpotLight` 的 `distance` 属性确定了光从光源传播到其强度属性为 0 的距离。你可以像这样设置这个属性：`pointLight.distance = 14`。在前面的截图中，光的亮度在距离为 `14` 时慢慢减弱到 `0`。这就是为什么在例子中，你仍然可以看到一个明亮的立方体，但光无法到达蓝色的球体。`distance` 属性的默认值是 `0`，这意味着光不会随着距离的增加而减弱。

## THREE.SpotLight

`THREE.SpotLight` 是你经常会使用的灯光之一（特别是如果你想要使用阴影）。`THREE.SpotLight` 是一个具有锥形效果的光源。你可以把它比作手电筒或灯笼。这种光源有一个方向和一个产生光的角度。以下表格列出了适用于 `THREE.SpotLight` 的所有属性：

| 属性 | 描述 |
| --- | --- |
| `angle` | 这决定了从这个光源发出的光束有多宽。这是用弧度来衡量的，默认值为 `Math.PI/3`。 |
| `castShadow` | 如果设置为 `true`，这个光将投射阴影。 |
| `color` | 这是光的颜色。 |
| `distance` | 这是光照的距离。默认值为 `0`，这意味着光的强度不会根据距离而减弱。 |
| `exponent` | 对于 `THREE.SpotLight`，从光源越远，发出的光的强度就会减弱。`exponent` 属性确定了这种强度减弱的速度。值越低，从这个光源发出的光就会到达更远的物体，而值越高，它只会到达非常接近 `THREE.SpotLight` 的物体。 |
| `intensity` | 这是光的强度。默认值为 1。 |
| `onlyShadow` | 如果将此属性设置为 `true`，这个光将只投射阴影，不会为场景增加任何光。 |
| `position` | 这是光在 `THREE.Scene` 中的位置。 |
| `shadowBias` | 阴影偏移将投射的阴影远离或靠近投射阴影的物体。你可以使用这个来解决一些在处理非常薄的物体时出现的奇怪效果（一个很好的例子可以在 [`www.3dbuzz.com/training/view/unity-fundamentals/lights/8-shadows-bias`](http://www.3dbuzz.com/training/view/unity-fundamentals/lights/8-shadows-bias) 找到）。如果你看到奇怪的阴影效果，这个属性的小值（例如 `0.01`）通常可以解决问题。这个属性的默认值是 `0`。 |
| `shadowCameraFar` | 这确定了从光源创建阴影的距离。默认值为 `5,000`。 |
| `shadowCameraFov` | 这确定了用于创建阴影的视场有多大（参见第二章中的 *不同用途的不同相机* 部分，*三.js 场景的基本组件*）。默认值为 `50`。 |
| `shadowCameraNear` | 这决定了从光源到阴影应该创建的距离。默认值为`50`。 |
| `shadowCameraVisible` | 如果设置为`true`，您可以看到这个光源是如何投射阴影的（请参见下一节的示例）。默认值为`false`。 |
| `shadowDarkness` | 这定义了阴影的深度。这在场景渲染后无法更改。默认值为`0.5`。 |
| `shadowMapWidth`和`shadowMapHeight` | 这决定了用多少像素来创建阴影。当阴影边缘有锯齿状或看起来不平滑时，增加这个值。这在场景渲染后无法更改。两者的默认值都是`512`。 |
| `target` | 对于`THREE.SpotLight`，它指向的方向很重要。使用`target`属性，您可以指定`THREE.SpotLight`瞄准场景中的特定对象或位置。请注意，此属性需要一个`THREE.Object3D`对象（如`THREE.Mesh`）。这与我们在上一章中看到的相机不同，相机在其`lookAt`函数中使用`THREE.Vector3`。 |
| `visible` | 如果设置为`true`（默认值），则此光源打开，如果设置为`false`，则关闭。 |

创建`THREE.SpotLight`非常简单。只需指定颜色，设置您想要的属性，并将其添加到场景中，如下所示：

```js
var pointColor = "#ffffff";
var spotLight = new THREE.SpotLight(pointColor);
spotLight.position.set(-40, 60, -10);
spotLight.castShadow = true;
spotLight.target = plane;
scene.add(spotLight);
```

`THREE.SpotLight`与`THREE.PointLight`并没有太大的区别。唯一的区别是我们将`castShadow`属性设置为`true`，因为我们想要阴影，并且我们需要为这个`SpotLight`设置`target`属性。`target`属性确定了光的瞄准位置。在这种情况下，我们将其指向了名为`plane`的对象。当您运行示例（`03-spot-light.html`）时，您将看到如下截图所示的场景：

![THREE.SpotLight](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_07.jpg)

在这个示例中，您可以设置一些特定于`THREE.SpotLight`的属性。其中之一是`target`属性。如果我们将此属性设置为蓝色的球体，光将聚焦在球体的中心，即使它在场景中移动。当我们创建光时，我们将其瞄准地面平面，在我们的示例中，我们也可以将其瞄准其他两个对象。但是，如果您不想将光瞄准到特定对象，而是瞄准到空间中的任意点，您可以通过创建一个`THREE.Object3D()`对象来实现：

```js
var target = new THREE.Object3D();
target.position = new THREE.Vector3(5, 0, 0);
```

然后，设置`THREE.SpotLight`的`target`属性：

```js
spotlight.target = target
```

在本节开始时的表格中，我们展示了一些可以用来控制`THREE.SpotLight`发出光线的属性。`distance`和`angle`属性定义了光锥的形状。`angle`属性定义了光锥的宽度，而`distance`属性则设置了光锥的长度。下图解释了这两个值如何共同定义将从`THREE.SpotLight`接收光线的区域。

![THREE.SpotLight](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_08.jpg)

通常情况下，您不需要设置这些值，因为它们已经有合理的默认值，但是您可以使用这些属性，例如，创建一个具有非常窄的光束或快速减少光强度的`THREE.SpotLight`。您可以使用最后一个属性来改变`THREE.SpotLight`产生光线的方式，即`exponent`属性。使用这个属性，您可以设置光强度从光锥的中心向边缘迅速减少的速度。在下面的图像中，您可以看到`exponent`属性的效果。我们有一个非常明亮的光（高`intensity`），随着它从中心向锥体的边缘移动，光强度迅速减弱（高`exponent`）：

![THREE.SpotLight](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_09.jpg)

您可以使用此功能来突出显示特定对象或模拟小手电筒。我们还可以使用小的`exponent`值和`angle`创建相同的聚焦光束效果。在对这种第二种方法进行谨慎说明时，请记住，非常小的角度可能会很快导致各种渲染伪影（伪影是图形中用于不需要的失真和奇怪渲染部分的术语）。

在继续下一个光源之前，我们将快速查看`THREE.SpotLight`可用的与阴影相关的属性。您已经学会了通过将`THREE.SpotLight`的`castShadow`属性设置为`true`来获得阴影（当然，还要确保我们为应该投射阴影的对象设置`castShadow`属性，并且在我们场景中的`THREE.Mesh`对象上设置`receiveShadow`属性，以显示阴影）。Three.js 还允许您对阴影的渲染进行非常精细的控制。这是通过我们在本节开头的表中解释的一些属性完成的。通过`shadowCameraNear`、`shadowCameraFar`和`shadowCameraFov`，您可以控制这种光如何在何处投射阴影。这与我们在前一章中解释的透视相机的视野工作方式相同。查看此操作的最简单方法是将`shadowCameraVisible`设置为`true`；您可以通过选中菜单中的调试复选框来执行此操作。如下截图所示，这显示了用于确定此光的阴影的区域：

![THREE.SpotLight](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_10.jpg)

在结束本节之前，我将给出一些建议，以防您在阴影方面遇到问题：

+   启用`shadowCameraVisible`属性。这显示了受此光影响的阴影区域。

+   如果阴影看起来很块状，您可以增加`shadowMapWidth`和`shadowMapHeight`属性，或者确保用于计算阴影的区域紧密包裹您的对象。您可以使用`shadowCameraNear`、`shadowCameraFar`和`shadowCameraFov`属性来配置此区域。

+   请记住，您不仅需要告诉光源投射阴影，还需要通过设置`castShadow`和`receiveShadow`属性告诉每个几何体是否会接收和/或投射阴影。

+   如果您在场景中使用薄物体，渲染阴影时可能会出现奇怪的伪影。您可以使用`shadowBias`属性轻微偏移阴影，这通常可以解决这类问题。

+   您可以通过设置`shadowDarkness`属性来改变阴影的深浅。如果您的阴影太暗或不够暗，更改此属性可以让您微调阴影的渲染方式。

+   如果您想要更柔和的阴影，可以在`THREE.WebGLRenderer`上设置不同的`shadowMapType`值。默认情况下，此属性设置为`THREE.PCFShadowMap`；如果将此属性设置为`PCFSoftShadowMap`，则可以获得更柔和的阴影。

## THREE.DirectionalLight

`THREE.DirectionalLight`是我们将要看的基本灯光中的最后一个。这种类型的光可以被认为是非常遥远的光。它发出的所有光线都是平行的。一个很好的例子是太阳。太阳离我们如此遥远，以至于我们在地球上接收到的光线（几乎）是平行的。`THREE.DirectionalLight`和我们在上一节中看到的`THREE.SpotLight`之间的主要区别是，这种光不会像`THREE.SpotLight`那样随着距离`THREE.DirectionalLight`的目标越来越远而减弱（您可以使用`distance`和`exponent`参数来微调这一点）。`THREE.DirectionalLight`照亮的完整区域接收到相同强度的光。

要查看此操作，请查看此处显示的`04-directional-light`示例：

![THREE.DirectionalLight](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_11.jpg)

正如你在上面的图像中所看到的，没有一个光锥应用到了场景中。一切都接收到了相同数量的光。只有光的方向、颜色和强度被用来计算颜色和阴影。

就像`THREE.SpotLight`一样，你可以设置一些控制光强度和投射阴影方式的属性。`THREE.DirectionalLight`有很多与`THREE.SpotLight`相同的属性：`position`、`target`、`intensity`、`distance`、`castShadow`、`onlyShadow`、`shadowCameraNear`、`shadowCameraFar`、`shadowDarkness`、`shadowCameraVisible`、`shadowMapWidth`、`shadowMapHeight`和`shadowBias`。关于这些属性的信息，你可以查看前面关于`THREE.SpotLight`的部分。接下来的几段将讨论一些额外的属性。

如果你回顾一下`THREE.SpotLight`的例子，你会发现我们必须定义光锥，阴影应用的范围。因为对于`THREE.DirectionalLight`，所有的光线都是平行的，我们没有光锥，而是一个长方体区域，就像你在下面的截图中看到的一样（如果你想亲自看到这个，请将摄像机远离场景）：

![THREE.DirectionalLight](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_12.jpg)

落入这个立方体范围内的一切都可以从光中投射和接收阴影。就像对于`THREE.SpotLight`一样，你定义这个范围越紧密，你的阴影看起来就越好。使用以下属性定义这个立方体：

```js
directionalLight.shadowCameraNear = 2;
directionalLight.shadowCameraFar = 200;
directionalLight.shadowCameraLeft = -50;
directionalLight.shadowCameraRight = 50;
directionalLight.shadowCameraTop = 50;
directionalLight.shadowCameraBottom = -50;
```

你可以将这与我们在第二章中关于摄像机的部分中配置正交相机的方式进行比较。

### 注意

有一个`THREE.DirectionalLight`可用的属性我们还没有讨论：`shadowCascade`。当你想在`THREE.DirectionalLight`上使用阴影时，这个属性可以用来创建更好的阴影。如果你将属性设置为`true`，Three.js 将使用另一种方法来生成阴影。它将阴影生成分割到由`shadowCascadeCount`指定的值。这将导致在相机视点附近更详细的阴影，而在远处更少详细的阴影。要使用这个功能，你需要尝试不同的设置，如`shadowCascadeCount`、`shadowCascadeBias`、`shadowCascadeWidth`、`shadowCascadeHeight`、`shadowCascadeNearZ`和`shadowCascadeFarZ`。你可以在[`alteredqualia.com/three/examples/webgl_road.html`](http://alteredqualia.com/three/examples/webgl_road.html)找到一个使用了这种设置的示例。

# 特殊灯光

在这个特殊灯光的部分，我们将讨论 Three.js 提供的另外两种灯光。首先，我们将讨论`THREE.HemisphereLight`，它有助于为室外场景创建更自然的光照，然后我们将看看`THREE.AreaLight`，它从一个大区域发出光，而不是从一个单一点发出光，最后，我们将向您展示如何在场景中添加镜头眩光效果。

## THREE.HemisphereLight

我们要看的第一个特殊灯光是`THREE.HemisphereLight`。使用`THREE.HemisphereLight`，我们可以创建更自然的室外光照。没有这种光，我们可以通过创建`THREE.DirectionalLight`来模拟室外，它模拟太阳，也许添加额外的`THREE.AmbientLight`来为场景提供一些一般的颜色。然而，这看起来并不真实。当你在室外时，不是所有的光都直接来自上方：大部分是被大气层散射和地面以及其他物体反射的。Three.js 中的`THREE.HemisphereLight`就是为这种情况而创建的。这是一个更自然的室外光照的简单方法。要查看一个示例，请看`05-hemisphere-light.html`：

![THREE.HemisphereLight](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_13.jpg)

### 注意

请注意，这是第一个加载额外资源的示例，无法直接从本地文件系统运行。因此，如果您还没有这样做，请查看第一章，“使用 Three.js 创建您的第一个 3D 场景”，了解如何设置本地 Web 服务器或禁用浏览器中的安全设置以使加载外部资源正常工作。

在此示例中，您可以打开和关闭`THREE.HemisphereLight`并设置颜色和强度。创建半球光与创建任何其他光一样简单：

```js
var hemiLight = new THREE.HemisphereLight(0x0000ff, 0x00ff00, 0.6);
hemiLight.position.set(0, 500, 0);
scene.add(hemiLight);
```

您只需指定从天空接收到的颜色、从地面接收到的颜色以及这些光的强度。如果以后想要更改这些值，可以通过以下属性访问它们：

| 属性 | 描述 |
| --- | --- |
| `groundColor` | 这是从地面发出的颜色 |
| `color` | 这是从天空发出的颜色 |
| `intensity` | 这是光线照射的强度 |

## THREE.AreaLight

我们将要看的最后一个真实光源是`THREE.AreaLight`。使用`THREE.AreaLight`，我们可以定义一个发光的矩形区域。`THREE.AreaLight`不包含在标准的 Three.js 库中，而是在其扩展中，因此在使用此光源之前，我们必须采取一些额外的步骤。在查看细节之前，让我们先看一下我们的目标结果（`06-area-light.html`打开此示例）；以下屏幕截图概括了我们想要看到的结果：

![THREE.AreaLight](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_14.jpg)

在此屏幕截图中，我们定义了三个`THREE.AreaLight`对象，每个对象都有自己的颜色。您还可以看到这些灯如何影响整个区域。

当我们想要使用`THREE.AreaLight`时，不能使用我们之前示例中使用的`THREE.WebGLRenderer`。原因是`THREE.AreaLight`是一个非常复杂的光源，会导致普通的`THREE.WebGLRenderer`对象严重影响性能。它在渲染场景时使用了不同的方法（将其分解为多个步骤），并且可以比标准的`THREE.WebGLRenderer`对象更好地处理复杂的光（或者说非常多的光源）。

要使用`THREE.WebGLDeferredRenderer`，我们必须包含 Three.js 提供的一些额外的 JavaScript 源。在 HTML 骨架的头部，确保您定义了以下一组`<script>`源：

```js
<head>
  <script type="text/javascript" src="../libs/three.js"></script>
  <script type="text/javascript" src="../libs/stats.js"></script>
  <script type="text/javascript" src="../libs/dat.gui.js"></script>

  <script type="text/javascript" src="../libs/WebGLDeferredRenderer.js"></script>
  <script type="text/javascript" src="../libs/ShaderDeferred.js"></script>
  <script type="text/javascript" src="../libs/RenderPass.js"></script>
  <script type="text/javascript" src="../libs/EffectComposer.js"></script>
  <script type="text/javascript" src="../libs/CopyShader.js"></script>
  <script type="text/javascript" src="../libs/ShaderPass.js"></script>
  <script type="text/javascript" src="../libs/FXAAShader.js"></script>
  <script type="text/javascript" src="../libs/MaskPass.js"></script>
</head>
```

包括这些库后，我们可以使用`THREE.WebGLDeferredRenderer`。我们可以以与我们在其他示例中讨论的方式使用此渲染器。只需要一些额外的参数：

```js
var renderer = new THREE.WebGLDeferredRenderer({width: window.innerWidth,height: window.innerHeight,scale: 1, antialias: true,tonemapping: THREE.FilmicOperator, brightness: 2.5 });
```

目前不要太担心这些属性的含义。在第十章，“加载和使用纹理”中，我们将深入探讨`THREE.WebGLDeferredRenderer`并向您解释它们。有了正确的 JavaScript 库和不同的渲染器，我们就可以开始添加`Three.AreaLight`。

我们几乎以与所有其他光源相同的方式执行此操作：

```js
var areaLight1 = new THREE.AreaLight(0xff0000, 3);
areaLight1.position.set(-10, 10, -35);
areaLight1.rotation.set(-Math.PI / 2, 0, 0);
areaLight1.width = 4;
areaLight1.height = 9.9;
scene.add(areaLight1);
```

在这个例子中，我们创建了一个新的`THREE.AreaLight`。这个光源的颜色值为`0xff0000`，强度值为`3`。和其他光源一样，我们可以使用`position`属性来设置它在场景中的位置。当你创建`THREE.AreaLight`时，它将被创建为一个水平平面。在我们的例子中，我们创建了三个垂直放置的`THREE.AreaLight`对象，所以我们需要围绕它们的*x*轴旋转`-Math.PI/2`。最后，我们使用`width`和`height`属性设置了`THREE.AreaLight`的大小，并将它们添加到了场景中。如果你第一次尝试这样做，你可能会想知道为什么在你放置光源的地方看不到任何东西。这是因为你看不到光源本身，只能看到它发出的光，只有当它接触到物体时才能看到。如果你想重现我在例子中展示的效果，你可以在相同的位置（`areaLight1.position`）添加`THREE.PlaneGeometry`或`THREE.BoxGeometry`来模拟发光的区域，如下所示：

```js
var planeGeometry1 = new THREE.BoxGeometry(4, 10, 0);
var planeGeometry1Mat = new THREE.MeshBasicMaterial({color: 0xff0000})
var plane = new THREE.Mesh(planeGeometry1, planeGeometry1Mat);
plane.position = areaLight1.position;
scene.add(plane);
```

你可以使用`THREE.AreaLight`创建非常漂亮的效果，但可能需要进行一些实验来获得期望的效果。如果你从右上角拉下控制面板，你可以调整三个灯的颜色和强度，立即看到效果，如下所示：

![THREE.AreaLight](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_15.jpg)

## 镜头耀斑

本章最后要探讨的主题是**镜头耀斑**。你可能已经熟悉镜头耀斑了。例如，当你直接对着太阳或其他强光拍照时，它们会出现。在大多数情况下，你可能会想避免这种情况，但对于游戏和 3D 生成的图像来说，它提供了一个很好的效果，使场景看起来更加真实。

Three.js 也支持镜头耀斑，并且非常容易将它们添加到你的场景中。在最后一节中，我们将向场景添加一个镜头耀斑，并创建输出，你可以通过打开`07-lensflares.html`来看到：

![LensFlare](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_16.jpg)

我们可以通过实例化`THREE.LensFlare`对象来创建镜头耀斑。我们需要做的第一件事就是创建这个对象。`THREE.LensFlare`接受以下参数：

```js
flare = new THREE.LensFlare(texture, size, distance, blending, color, opacity);
```

这些参数在下表中有解释：

| 参数 | 描述 |
| --- | --- |
| `texture` | 纹理是决定耀斑形状的图像。 |
| `size` | 我们可以指定耀斑的大小。这是以像素为单位的大小。如果指定为`-1`，则使用纹理本身的大小。 |
| `distance` | 这是从光源（`0`）到相机（`1`）的距离。使用这个来将镜头耀斑定位在正确的位置。 |
| `blending` | 我们可以为耀斑指定多个纹理。混合模式决定了这些纹理如何混合在一起。在`LensFlare`中默认使用的是`THREE.AdditiveBlending`。关于混合的更多内容在下一章中有介绍。 |
| `color` | 这是耀斑的颜色。 |

让我们来看看用于创建这个对象的代码（参见`07-lensflares.html`）：

```js
var textureFlare0 = THREE.ImageUtils.loadTexture
      ("../assets/textures/lensflare/lensflare0.png");

var flareColor = new THREE.Color(0xffaacc);
var lensFlare = new THREE.LensFlare(textureFlare0, 350, 0.0, THREE.AdditiveBlending, flareColor);

lensFlare.position = spotLight.position;
scene.add(lensFlare);
```

我们首先加载一个纹理。在这个例子中，我使用了 Three.js 示例提供的镜头耀斑纹理，如下所示：

![LensFlare](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_17.jpg)

如果你将这个图像与本节开头的截图进行比较，你会发现它定义了镜头耀斑的外观。接下来，我们使用`new THREE.Color( 0xffaacc );`来定义镜头耀斑的颜色，这会使镜头耀斑呈现红色的光晕。有了这两个对象，我们就可以创建`THREE.LensFlare`对象。在这个例子中，我们将耀斑的大小设置为`350`，距离设置为`0.0`（直接在光源处）。

在创建了`LensFlare`对象之后，我们将它定位在光源的位置并将其添加到场景中，如下截图所示：

![LensFlare](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_18.jpg)

这已经看起来不错，但是如果你把这个与本章开头的图像进行比较，你会注意到我们缺少页面中间的小圆形伪影。我们创建这些伪影的方式与主要的光晕几乎相同，如下所示：

```js
var textureFlare3 = THREE.ImageUtils.loadTexture
      ("../assets/textures/lensflare/lensflare3.png");

lensFlare.add(textureFlare3, 60, 0.6, THREE.AdditiveBlending);
lensFlare.add(textureFlare3, 70, 0.7, THREE.AdditiveBlending);
lensFlare.add(textureFlare3, 120, 0.9, THREE.AdditiveBlending);
lensFlare.add(textureFlare3, 70, 1.0, THREE.AdditiveBlending);
```

不过，这一次我们不创建一个新的`THREE.LensFlare`，而是使用刚刚创建的`LensFlare`提供的`add`函数。在这个方法中，我们需要指定纹理、大小、距离和混合模式，就这样。请注意，`add`函数可以接受两个额外的参数。你还可以将新的眩光的`color`和`opacity`属性设置为`add`。我们用于这些新眩光的纹理是一个非常轻的圆形，如下面的截图所示：

![LensFlare](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_03_19.jpg)

如果你再次观察场景，你会看到伪影出现在你用`distance`参数指定的位置。

# 总结

在本章中，我们涵盖了关于 Three.js 中可用的不同类型的光的大量信息。在本章中，你学到了配置光线、颜色和阴影并不是一门精确的科学。为了得到正确的结果，你应该尝试不同的设置，并使用 dat.GUI 控件来微调你的配置。不同的光有不同的行为方式。`THREE.AmbientLight`颜色被添加到场景中的每一个颜色中，通常用于平滑硬色和阴影。`THREE.PointLight`在所有方向上发光，但不能用于创建阴影。`THREE.SpotLight`是一种类似手电筒的灯光。它呈圆锥形，可以配置为随距离衰减，并且能够投射阴影。我们还看了`THREE.DirectionalLight`。这种光可以与远处的光进行比较，比如太阳，它的光线是平行的，强度不会随着离配置的目标越远而减弱。除了标准的光，我们还看了一些更专业的光。为了获得更自然的室外效果，你可以使用`THREE.HemisphereLight`，它考虑了地面和天空的反射；`THREE.AreaLight`不是从单一点发光，而是从一个大面积发光。我们向你展示了如何使用`THREE.LensFlare`对象添加摄影镜头眩光。

到目前为止的章节中，我们已经介绍了一些不同的材质，而在本章中，你看到并不是所有的材质对可用的光都有相同的反应。在下一章中，我们将概述 Three.js 中可用的材质。


# 第四章：使用 Three.js 材质

在之前的章节中，我们稍微谈到了材质。您已经了解到，材质与`THREE.Geometry`一起形成`THREE.Mesh`。材质就像物体的皮肤，定义了几何体外观的外部。例如，皮肤定义了几何体是金属外观、透明还是显示为线框。然后，生成的`THREE.Mesh`对象可以添加到场景中，由 Three.js 渲染。到目前为止，我们还没有真正详细地研究过材质。在本章中，我们将深入探讨 Three.js 提供的所有材质，并学习如何使用这些材质来创建好看的 3D 物体。我们将在本章中探讨的材质如下表所示：

| 名称 | 描述 |
| --- | --- |
| `MeshBasicMaterial` | 这是一种基本材质，您可以使用它来给您的几何体一个简单的颜色或显示几何体的线框。 |
| `MeshDepthMaterial` | 这是一种使用从相机到网格的距离来确定如何着色的材质。 |
| `MeshNormalMaterial` | 这是一种简单的材质，它基于法向量确定面的颜色。 |
| `MeshFacematerial` | 这是一个容器，允许您为几何体的每个面指定一个独特的材质。 |
| `MeshLambertMaterial` | 这是一种考虑光照的材质，用于创建*暗淡*的非光亮外观的物体。 |
| `MeshPhongMaterial` | 这是一种考虑光照的材质，可用于创建光亮的物体。 |
| `ShaderMaterial` | 这种材质允许您指定自己的着色器程序，直接控制顶点的位置和像素的颜色。 |
| `LineBasicMaterial` | 这是一种可以用在`THREE.Line`几何体上创建彩色线条的材质。 |
| `LineDashMaterial` | 这与`LineBasicMaterial`相同，但这种材质还允许您创建虚线效果。 |

如果您查看 Three.js 的源代码，您可能会遇到`THREE.RawShaderMaterial`。这是一种专门的材质，只能与`THREE.BufferedGeometry`一起使用。这种几何体是一种针对静态几何体进行优化的特殊形式（例如，顶点和面不会改变）。我们不会在本章中探讨这种材质，但在第十一章中，*自定义着色器和渲染后处理*，当我们讨论创建自定义着色器时，我们将使用它。在代码中，您还可以找到`THREE.SpriteCanvasMaterial`，`THREE.SpriteMaterial`和`THREE.PointCloudMaterial`。这些是您在为个别点设置样式时使用的材质。我们不会在本章中讨论这些，但我们将在第七章中探讨它们，*粒子、精灵和点云*。

材质有许多共同的属性，因此在我们查看第一个材质`MeshBasicMaterial`之前，我们将先看一下所有材质共享的属性。

# 理解共同的材质属性

您可以快速看到所有材质之间共享的属性。Three.js 提供了一个材质基类`THREE.Material`，列出了所有共同的属性。我们将这些共同的材质属性分为以下三类：

+   **基本属性**：这些是您经常使用的属性。使用这些属性，您可以控制物体的不透明度，它是否可见，以及如何引用它（通过 ID 或自定义名称）。

+   **混合属性**：每个物体都有一组混合属性。这些属性定义了物体如何与其背景相结合。

+   **高级属性**：有许多高级属性控制着低级的 WebGL 上下文如何渲染物体。在大多数情况下，您不需要去处理这些属性。

请注意，在本章中，我们跳过了与纹理和贴图相关的任何属性。大多数材质允许您使用图像作为纹理（例如，类似木头或石头的纹理）。在第十章中，*加载和使用纹理*，我们将深入探讨各种可用的纹理和映射选项。一些材质还具有与动画相关的特定属性（皮肤和`morphTargets`）；我们也会跳过这些属性。这些将在第九章中进行讨论，*动画和移动摄像机*。

我们从列表中的第一个开始：基本属性。

## 基本属性

`THREE.Material`对象的基本属性列在下表中（您可以在`THREE.BasicMeshMaterial`部分中看到这些属性的实际应用）：

| 属性 | 描述 |
| --- | --- |
| `id` | 用于标识材质的属性，在创建材质时分配。第一个材质从`0`开始，每创建一个额外的材质，增加`1`。 |
| `uuid` | 这是一个唯一生成的 ID，用于内部使用。 |
| `name` | 您可以使用此属性为材质分配一个名称。这可用于调试目的。 |
| `opacity` | 这定义了对象的透明度。与`transparent`属性一起使用。此属性的范围是从`0`到`1`。 |
| `transparent` | 如果将其设置为`true`，Three.js 将以设置的不透明度渲染此对象。如果将其设置为`false`，对象将不透明，只是颜色更浅。如果使用使用 alpha（透明度）通道的纹理，则还应将此属性设置为`true`。 |
| `overdraw` | 当使用`THREE.CanvasRenderer`时，多边形会被渲染得更大一些。当使用此渲染器时看到间隙时，将其设置为`true`。 |
| `visible` | 这定义了此材质是否可见。如果将其设置为`false`，则在场景中看不到对象。 |
| `Side` | 使用此属性，您可以定义材质应用于几何体的哪一侧。默认值为`THREE.Frontside`，将材质应用于对象的前面（外部）。您还可以将其设置为`THREE.BackSide`，将其应用于后面（内部），或`THREE.DoubleSide`，将其应用于两侧。 |
| `needsUpdate` | 对于材质的一些更新，您需要告诉 Three.js 材质已更改。如果此属性设置为`true`，Three.js 将使用新的材质属性更新其缓存。 |

对于每种材质，您还可以设置一些混合属性。

## 混合属性

材质具有一些通用的与混合相关的属性。混合确定我们渲染的颜色如何与它们后面的颜色相互作用。当我们谈论组合材质时，我们会稍微涉及这个主题。混合属性列在下表中：

| 名称 | 描述 |
| --- | --- |
| `blending` | 这决定了此对象上的材质与背景的混合方式。正常模式是`THREE.NormalBlending`，只显示顶层。 |
| `blendsrc` | 除了使用标准混合模式，您还可以通过设置`blendsrc`，`blenddst`和`blendequation`来创建自定义混合模式。此属性定义了对象（源）如何混合到背景（目标）中。默认的`THREE.SrcAlphaFactor`设置使用 alpha（透明度）通道进行混合。 |
| `blenddst` | 此属性定义了背景（目标）在混合中的使用方式，默认为`THREE.OneMinusSrcAlphaFactor`，这意味着此属性也使用源的 alpha 通道进行混合，但使用`1`（源的 alpha 通道）作为值。 |
| `blendequation` | 这定义了如何使用`blendsrc`和`blenddst`值。默认是将它们相加（`AddEquation`）。使用这三个属性，您可以创建自定义混合模式。 |

最后一组属性主要用于内部使用，控制了如何使用 WebGL 来渲染场景的具体细节。

## 高级属性

我们不会详细介绍这些属性。这些与 WebGL 内部工作方式有关。如果您确实想了解有关这些属性的更多信息，OpenGL 规范是一个很好的起点。您可以在[`www.khronos.org/registry/gles/specs/2.0/es_full_spec_2.0.25.pdf`](http://www.khronos.org/registry/gles/specs/2.0/es_full_spec_2.0.25.pdf)找到此规范。以下表格提供了这些高级属性的简要描述：

| 名称 | 描述 |
| --- | --- |
| `depthTest` | 这是一个高级的 WebGL 属性。使用此属性，您可以启用或禁用`GL_DEPTH_TEST`参数。此参数控制是否使用*深度*来确定新像素的值。通常情况下，您不需要更改此设置。有关更多信息，请参阅我们之前提到的 OpenGL 规范。 |
| `depthWrite` | 这是另一个内部属性。此属性可用于确定此材质是否影响 WebGL 深度缓冲区。如果您使用 2D 叠加对象（例如中心），则应将此属性设置为`false`。通常情况下，您不需要更改此属性。 |
| `polygonOffset`，`polygonOffsetFactor`和`polygonOffsetUnits` | 使用这些属性，您可以控制`POLYGON_OFFSET_FILL` WebGL 特性。通常不需要这些。要详细了解它们的作用，可以查看 OpenGL 规范。 |
| `alphatest` | 可以设置为特定值（`0`到`1`）。每当像素的 alpha 值小于此值时，它将不会被绘制。您可以使用此属性来消除一些与透明度相关的伪影。 |

现在，让我们看看所有可用的材质，以便您可以看到这些属性对呈现输出的影响。

# 从一个简单的网格开始

在本节中，我们将看一些简单的材质：`MeshBasicMaterial`，`MeshDepthMaterial`，`MeshNormalMaterial`和`MeshFaceMaterial`。我们从`MeshBasicMaterial`开始。

在我们查看这些材质的属性之前，这里有一个关于如何传递属性以配置材质的快速说明。有两个选项：

+   您可以将参数作为参数对象传递给构造函数，就像这样：

```js
var material = new THREE.MeshBasicMaterial(
{
  color: 0xff0000, name: 'material-1', opacity: 0.5, transparency: true, ...
});
```

+   或者，您还可以创建一个实例并单独设置属性，就像这样：

```js
var material = new THREE.MeshBasicMaterial();
material.color = new THREE.Color(0xff0000);
material.name = 'material-1';
material.opacity = 0.5;
material.transparency = true;
```

通常，最好的方法是在创建材质时知道所有属性的值时使用构造函数。这两种风格使用的参数格式相同。唯一的例外是`color`属性。在第一种风格中，我们可以直接传入十六进制值，Three.js 会自己创建一个`THREE.Color`对象。在第二种风格中，我们必须显式创建一个`THREE.Color`对象。在本书中，我们将使用这两种风格。

## THREE.MeshBasicMaterial

`MeshBasicMaterial`是一个非常简单的材质，不考虑场景中可用的光源。使用此材质的网格将呈现为简单的平面多边形，您还可以选择显示几何的线框。除了我们在此材质的早期部分看到的常见属性之外，我们还可以设置以下属性：

| 名称 | 描述 |
| --- | --- |
| `color` | 此属性允许您设置材质的颜色。 |
| `wireframe` | 这允许您将材质呈现为线框。这对于调试很有用。 |
| `Wireframelinewidth` | 如果启用线框，此属性定义线框的宽度。 |
| `Wireframelinecap` | 此属性定义线框模式下线条端点的外观。可能的值为`butt`，`round`和`square`。默认值为`round`。实际上，更改此属性的结果非常难以看到。此属性不受`WebGLRenderer`支持。 |
| `wireframeLinejoin` | 这定义了线条连接点的可视化方式。可能的值为`round`，`bevel`和`miter`。默认值为`round`。如果您仔细观察，可以在低`opacity`和非常大的`wireframeLinewidth`值的示例中看到这一点。此属性不受`WebGLRenderer`支持。 |
| `Shading` | 这定义了如何应用着色。可能的值为`THREE.SmoothShading`，`THREE.NoShading`和`THREE.FlatShading`。默认值为`THREE.SmoothShading`，这会产生一个平滑的对象，您看不到单独的面。此属性在此材质的示例中未启用。例如，请查看`MeshNormalMaterial`部分。 |
| `vertexColors` | 您可以使用此属性为每个顶点定义单独的颜色。默认值为`THREE.NoColors`。如果将此值设置为`THREE.VertexColors`，渲染器将考虑`THREE.Geometry`的`colors`属性上设置的颜色。此属性在`CanvasRenderer`上不起作用，但在`WebGLRenderer`上起作用。查看`LineBasicMaterial`示例，我们在其中使用此属性为线条的各个部分着色。您还可以使用此属性为此材质类型创建渐变效果。 |
| `fog` | 此属性确定此材质是否受全局雾设置的影响。这在实际中没有显示，但如果将其设置为`false`，我们在第二章中看到的全局雾不会影响对象的渲染方式。 |

在前几章中，我们看到了如何创建材质并将其分配给对象。对于`THREE.MeshBasicMaterial`，我们可以这样做：

```js
var meshMaterial = new THREE.MeshBasicMaterial({color: 0x7777ff});
```

这将创建一个新的`THREE.MeshBasicMaterial`并将`color`属性初始化为`0x7777ff`（紫色）。

我添加了一个示例，您可以使用它来玩转`THREE.MeshBasicMaterial`属性和我们在上一节中讨论的基本属性。如果您在`chapter-04`文件夹中打开`01-basic-mesh-material.html`示例，您将看到一个如下截图所示的旋转立方体：

![THREE.MeshBasicMaterial](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_04_01.jpg)

这是一个非常简单的对象。在右上角的菜单中，您可以玩转属性并选择不同的网格（还可以更改渲染器）。例如，一个球体，`opacity`为`0.2`，`transparent`设置为`true`，`wireframe`设置为`true`，`wireframeLinewidth`为`9`，并使用`CanvasRenderer`渲染如下：

![THREE.MeshBasicMaterial](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_04_02.jpg)

在此示例中，您可以设置的一个属性是`side`属性。使用此属性，您可以定义材质应用到`THREE.Geometry`的哪一侧。当您选择平面网格时，您可以测试此属性的工作原理。由于通常材质仅应用于材质的正面，因此旋转平面将在一半时间内不可见（当它向您展示背面时）。如果将`side`属性设置为`double`，则平面将始终可见，因为材质应用于几何体的两侧。但请注意，当`side`属性设置为`double`时，渲染器将需要做更多的工作，因此这可能会影响场景的性能。

## THREE.MeshDepthMaterial

列表中的下一个材料是`THREE.MeshDepthMaterial`。使用这种材料，物体的外观不是由灯光或特定的材料属性定义的；而是由物体到摄像机的距离定义的。您可以将其与其他材料结合使用，轻松创建淡出效果。这种材料具有的唯一相关属性是以下两个控制是否要显示线框的属性：

| 名称 | 描述 |
| --- | --- |
| `wireframe` | 这决定是否显示线框。 |
| `wireframeLineWidth` | 这决定线框的宽度。 |

为了演示这一点，我们修改了来自第二章的立方体示例（`chapter-04`文件夹中的`02-depth-material`）。请记住，您必须单击**addCube**按钮才能填充场景。以下屏幕截图显示了修改后的示例：

![THREE.MeshDepthMaterial](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_04_03.jpg)

尽管该材料没有许多额外的属性来控制物体的渲染方式，但我们仍然可以控制物体颜色淡出的速度。在本例中，我们暴露了摄像机的`near`和`far`属性。您可能还记得来自第二章的内容，*构成 Three.js 场景的基本组件*，通过这两个属性，我们设置了摄像机的可见区域。比`near`属性更接近摄像机的任何对象都不会显示出来，而比`far`属性更远的任何对象也会超出摄像机的可见区域。

摄像机的`near`和`far`属性之间的距离定义了物体淡出的亮度和速度。如果距离非常大，物体远离摄像机时只会稍微淡出。如果距离很小，淡出效果将更加明显（如下面的屏幕截图所示）：

![THREE.MeshDepthMaterial](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_04_04.jpg)

创建`THREE.MeshDepthMaterial`非常简单，对象不需要任何参数。在本例中，我们使用了`scene.overrideMaterial`属性，以确保场景中的所有对象都使用这种材料，而无需为每个`THREE.Mesh`对象显式指定它：

```js
var scene = new THREE.Scene();
scene.overrideMaterial = new THREE.MeshDepthMaterial();
```

本章的下一部分实际上并不是关于特定材料，而是展示了如何将多种材料组合在一起的方法。

## 组合材料

如果您回顾一下`THREE.MeshDepthMaterial`的属性，您会发现没有选项来设置立方体的颜色。一切都是由材料的默认属性为您决定的。然而，Three.js 有将材料组合在一起创建新效果的选项（这也是混合发挥作用的地方）。以下代码显示了我们如何将材料组合在一起：

```js
var cubeMaterial = new THREE.MeshDepthMaterial();
var colorMaterial = new THREE.MeshBasicMaterial({color: 0x00ff00, transparent: true, blending: THREE.MultiplyBlending})
var cube = new THREE.SceneUtils.createMultiMaterialObject(cubeGeometry, [colorMaterial, cubeMaterial]);
cube.children[1].scale.set(0.99, 0.99, 0.99);
```

我们得到了以下使用`THREE.MeshDepthMaterial`的亮度和`THREE.MeshBasicMaterial`的颜色的绿色立方体（打开`03-combined-material.html`查看此示例）。以下屏幕截图显示了示例：

![组合材料](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_04_05.jpg)

让我们看看您需要采取哪些步骤才能获得这个特定的结果。

首先，我们需要创建两种材质。对于`THREE.MeshDepthMaterial`，我们不需要做任何特殊处理；但是，对于`THREE.MeshBasicMaterial`，我们将`transparent`设置为`true`并定义一个`blending`模式。如果我们不将`transparent`属性设置为`true`，我们将只得到实心的绿色物体，因为 Three.js 不知道考虑已渲染的颜色。将`transparent`设置为`true`后，Three.js 将检查`blending`属性，以查看绿色的`THREE.MeshBasicMaterial`对象应如何与背景交互。在这种情况下，背景是用`THREE.MeshDepthMaterial`渲染的立方体。在第九章中，*动画和移动相机*，我们将更详细地讨论可用的各种混合模式。

然而，对于这个例子，我们使用了`THREE.MultiplyBlending`。这种混合模式将前景颜色与背景颜色相乘，并给出所需的效果。这个代码片段中的最后一行也很重要。当我们使用`THREE.SceneUtils.createMultiMaterialObject()`函数创建一个网格时，几何图形会被复制，并且会返回两个完全相同的网格组。如果我们在没有最后一行的情况下渲染这些网格，您应该会看到闪烁效果。当对象被渲染在另一个对象的上方并且其中一个对象是透明的时，有时会发生这种情况。通过缩小使用`THREE.MeshDepthMaterial`创建的网格，我们可以避免这种情况。为此，请使用以下代码：

```js
cube.children[1].scale.set(0.99, 0.99, 0.99);
```

下一个材质也是一个我们无法影响渲染中使用的颜色的材质。

## THREE.MeshNormalMaterial

理解这种材质如何渲染的最简单方法是先看一个例子。打开`chapter-04`文件夹中的`04-mesh-normal-material.html`示例。如果您选择球体作为网格，您将看到类似于这样的东西：

![THREE.MeshNormalMaterial](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_04_06.jpg)

正如你所看到的，网格的每个面都以稍微不同的颜色呈现，即使球体旋转，颜色也基本保持不变。这是因为每个面的颜色是基于面外指向的*法线*。这个法线是垂直于面的向量。法线向量在 Three.js 的许多不同部分中都有用到。它用于确定光的反射，帮助将纹理映射到 3D 模型上，并提供有关如何照亮、着色和着色表面像素的信息。幸运的是，Three.js 处理这些向量的计算并在内部使用它们，因此您不必自己计算它们。以下屏幕截图显示了`THREE.SphereGeometry`的所有法线向量：

![THREE.MeshNormalMaterial](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_04_07.jpg)

这个法线指向的方向决定了使用`THREE.MeshNormalMaterial`时面的颜色。由于球体的所有面的法线都指向不同的方向，我们得到了您在示例中看到的多彩球体。作为一个快速的旁注，要添加这些法线箭头，您可以像这样使用`THREE.ArrowHelper`：

```js
for (var f = 0, fl = sphere.geometry.faces.length; f < fl; f++) {
  var face = sphere.geometry.faces[ f ];
  var centroid = new THREE.Vector3(0, 0, 0);
  centroid.add(sphere.geometry.vertices[face.a]);
  centroid.add(sphere.geometry.vertices[face.b]);
  centroid.add(sphere.geometry.vertices[face.c]);
  centroid.divideScalar(3);

  var arrow = new THREE.ArrowHelper(face.normal, centroid, 2, 0x3333FF, 0.5, 0.5);
  sphere.add(arrow);
}
```

在这段代码片段中，我们遍历了`THREE.SphereGeometry`的所有面。对于每个`THREE.Face3`对象，我们通过添加构成该面的顶点并将结果除以 3 来计算中心（质心）。我们使用这个质心和面的法线向量来绘制一个箭头。`THREE.ArrowHelper`接受以下参数：`direction`、`origin`、`length`、`color`、`headLength`和`headWidth`。

您可以在`THREE.MeshNormalMaterial`上设置的其他一些属性：

| 名称 | 描述 |
| --- | --- |
| `wireframe` | 这决定是否显示线框。 |
| `wireframeLineWidth` | 这决定线框的宽度。 |
| `shading` | 这配置了平面着色和平滑着色。 |

我们已经看到了`wireframe`和`wireframeLinewidth`，但在我们的`THREE.MeshBasicMaterial`示例中跳过了`shading`属性。使用`shading`属性，我们可以告诉 Three.js 如何渲染我们的对象。如果使用`THREE.FlatShading`，每个面将按原样呈现（正如您在前面的几个屏幕截图中看到的），或者您可以使用`THREE.SmoothShading`，它会使我们对象的面变得更加平滑。例如，如果我们使用`THREE.SmoothShading`来渲染球体，结果看起来像这样：

![THREE.MeshNormalMaterial](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_04_08.jpg)

我们几乎完成了简单的材料。最后一个是`THREE.MeshFaceMaterial`。

## THREE.MeshFaceMaterial

基本材料中的最后一个实际上不是一个材料，而是其他材料的容器。`THREE.MeshFaceMaterial`允许您为几何体的每个面分配不同的材料。例如，如果您有一个立方体，它有 12 个面（请记住，Three.js 只使用三角形），您可以使用这种材料为立方体的每一面分配不同的材料（例如，不同的颜色）。使用这种材料非常简单，如下面的代码所示：

```js
var matArray = [];
matArray.push(new THREE.MeshBasicMaterial( { color: 0x009e60 }));
matArray.push(new THREE.MeshBasicMaterial( { color: 0x009e60 }));
matArray.push(new THREE.MeshBasicMaterial( { color: 0x0051ba }));
matArray.push(new THREE.MeshBasicMaterial( { color: 0x0051ba }));
matArray.push(new THREE.MeshBasicMaterial( { color: 0xffd500 }));
matArray.push(new THREE.MeshBasicMaterial( { color: 0xffd500 }));
matArray.push(new THREE.MeshBasicMaterial( { color: 0xff5800 }));
matArray.push(new THREE.MeshBasicMaterial( { color: 0xff5800 }));
matArray.push(new THREE.MeshBasicMaterial( { color: 0xC41E3A }));
matArray.push(new THREE.MeshBasicMaterial( { color: 0xC41E3A }));
matArray.push(new THREE.MeshBasicMaterial( { color: 0xffffff }));
matArray.push(new THREE.MeshBasicMaterial( { color: 0xffffff }));

var faceMaterial = new THREE.MeshFaceMaterial(matArray);

var cubeGeom = new THREE.BoxGeometry(3,3,3);
var cube = new THREE.Mesh(cubeGeom, faceMaterial);
```

我们首先创建一个名为`matArray`的数组来保存所有的材料。接下来，我们创建一个新的材料，在这个例子中是`THREE.MeshBasicMaterial`，每个面的颜色都不同。有了这个数组，我们实例化`THREE.MeshFaceMaterial`，并将它与立方体几何一起使用来创建网格。让我们深入了解一下代码，并看看您需要做什么才能重新创建以下示例：一个简单的 3D 魔方。您可以在`05-mesh-face-material.html`中找到此示例。以下屏幕截图显示了此示例：

![THREE.MeshFaceMaterial](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_04_09.jpg)

这个魔方由许多小立方体组成：沿着*x*轴有三个立方体，沿着*y*轴有三个立方体，沿着*z*轴有三个立方体。这是如何完成的：

```js
var group = new THREE.Mesh();
// add all the rubik cube elements
var mats = [];
mats.push(new THREE.MeshBasicMaterial({ color: 0x009e60 }));
mats.push(new THREE.MeshBasicMaterial({ color: 0x009e60 }));
mats.push(new THREE.MeshBasicMaterial({ color: 0x0051ba }));
mats.push(new THREE.MeshBasicMaterial({ color: 0x0051ba }));
mats.push(new THREE.MeshBasicMaterial({ color: 0xffd500 }));
mats.push(new THREE.MeshBasicMaterial({ color: 0xffd500 }));
mats.push(new THREE.MeshBasicMaterial({ color: 0xff5800 }));
mats.push(new THREE.MeshBasicMaterial({ color: 0xff5800 }));
mats.push(new THREE.MeshBasicMaterial({ color: 0xC41E3A }));
mats.push(new THREE.MeshBasicMaterial({ color: 0xC41E3A }));
mats.push(new THREE.MeshBasicMaterial({ color: 0xffffff }));
mats.push(new THREE.MeshBasicMaterial({ color: 0xffffff }));

var faceMaterial = new THREE.MeshFaceMaterial(mats);

for (var x = 0; x < 3; x++) {
  for (var y = 0; y < 3; y++) {
    for (var z = 0; z < 3; z++) {
      var cubeGeom = new THREE.BoxGeometry(2.9, 2.9, 2.9);
      var cube = new THREE.Mesh(cubeGeom, faceMaterial);
      cube.position.set(x * 3 - 3, y * 3, z * 3 - 3);

      group.add(cube);
    }
  }
}
```

在这段代码中，我们首先创建`THREE.Mesh`，它将容纳所有的单独立方体（`group`）；接下来，我们为每个面创建材料并将它们推送到`mats`数组中。请记住，立方体的每一面都由两个面组成，所以我们需要 12 种材料。从这些材料中，我们创建`THREE.MeshFaceMaterial`。然后，我们创建三个循环，以确保我们创建了正确数量的立方体。在这个循环中，我们创建每个单独的立方体，分配材料，定位它们，并将它们添加到组中。您应该记住的是，立方体的位置是相对于这个组的位置的。如果我们移动或旋转组，所有的立方体都会随之移动和旋转。有关如何使用组的更多信息，请参阅第八章*创建和加载高级网格和几何体*。

如果您在浏览器中打开了示例，您会看到整个魔方立方体旋转，而不是单独的立方体。这是因为我们在渲染循环中使用了以下内容：

```js
group.rotation.y=step+=0.01;
```

这导致完整的组围绕其中心（0,0,0）旋转。当我们定位单独的立方体时，我们确保它们位于这个中心点周围。这就是为什么在前面的代码行中看到`cube.position.set(x * 3 - 3, y * 3, z * 3 - 3);`中的-3 偏移量。

### 提示

如果您查看这段代码，您可能会想知道 Three.js 如何确定要为特定面使用哪种材料。为此，Three.js 使用`materialIndex`属性，您可以在`geometry.faces`数组的每个单独的面上设置它。该属性指向我们在`THREE.FaceMaterial`对象的构造函数中添加的材料的数组索引。当您使用标准的 Three.js 几何体之一创建几何体时，Three.js 会提供合理的默认值。如果您想要其他行为，您可以为每个面自己设置`materialIndex`属性，以指向提供的材料之一。

`THREE.MeshFaceMaterial`是我们基本材质中的最后一个。在下一节中，我们将看一下 Three.js 中提供的一些更高级的材质。

# 高级材质

在这一部分，我们将看一下 Three.js 提供的更高级的材质。我们首先会看一下`THREE.MeshPhongMaterial`和`THREE.MeshLambertMaterial`。这两种材质对光源有反应，分别可以用来创建有光泽和无光泽的材质。在这一部分，我们还将看一下最多才多艺，但最难使用的材质之一：`THREE.ShaderMaterial`。使用`THREE.ShaderMaterial`，你可以创建自己的着色器程序，定义材质和物体的显示方式。

## THREE.MeshLambertMaterial

这种材质可以用来创建无光泽的表面。这是一种非常易于使用的材质，可以响应场景中的光源。这种材质可以配置许多我们之前见过的属性：`color`、`opacity`、`shading`、`blending`、`depthTest`、`depthWrite`、`wireframe`、`wireframeLinewidth`、`wireframeLinecap`、`wireframeLineJoin`、`vertexColors`和`fog`。我们不会详细讨论这些属性，而是专注于这种材质特有的属性。这样我们就只剩下以下四个属性了：

| 名称 | 描述 |
| --- | --- |
| `ambient` | 这是材质的*环境*颜色。这与我们在上一章看到的环境光一起使用。这种颜色与环境光提供的颜色相乘。默认为白色。 |
| `emissive` | 这是材质发出的颜色。它并不真正作为光源，但这是一个不受其他光照影响的纯色。默认为黑色。 |
| `wrapAround` | 如果将此属性设置为`true`，则启用半兰伯特光照技术。使用半兰伯特光照，光的衰减更加温和。如果有一个有严重阴影的网格，启用此属性将软化阴影并更均匀地分布光线。 |
| `wrapRGB` | 当`wrapAround`设置为 true 时，你可以使用`THREE.Vector3`来控制光的衰减速度。 |

这种材质的创建方式和其他材质一样。下面是它的创建方式：

```js
var meshMaterial = new THREE.MeshLambertMaterial({color: 0x7777ff});
```

有关此材质的示例，请查看`06-mesh-lambert-material.html`。以下截图显示了此示例：

![THREE.MeshLambertMaterial](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_04_10.jpg)

正如你在前面的截图中看到的，这种材质看起来相当无光泽。我们还可以使用另一种材质来创建有光泽的表面。

## THREE.MeshPhongMaterial

使用`THREE.MeshPhongMaterial`，我们可以创建一个有光泽的材质。你可以用于此的属性基本上与无光泽的`THREE.MeshLambertMaterial`对象相同。我们再次跳过基本属性和已经讨论过的属性：`color`、`opacity`、`shading`、`blending`、`depthTest`、`depthWrite`、`wireframe`、`wireframeLinewidth`、`wireframeLinecap`、`wireframelineJoin`和`vertexColors`。

这种材质的有趣属性如下表所示：

| 名称 | 描述 |
| --- | --- |
| `ambient` | 这是材质的*环境*颜色。这与我们在上一章看到的环境光一起使用。这种颜色与环境光提供的颜色相乘。默认为白色。 |
| `emissive` | 这是材质发出的颜色。它并不真正作为光源，但这是一个不受其他光照影响的纯色。默认为黑色。 |
| `specular` | 此属性定义材质有多光泽，以及以什么颜色发光。如果设置为与`color`属性相同的颜色，你会得到一个更金属质感的材质。如果设置为灰色，会得到一个更塑料质感的材质。 |
| `shininess` | 此属性定义镜面高光的光泽程度。光泽的默认值为`30`。 |
| `metal` | 当此属性设置为`true`时，Three.js 使用略有不同的方式来计算像素的颜色，使对象看起来更像金属。请注意，效果非常微小。 |
| `wrapAround` | 如果将此属性设置为`true`，则启用半兰伯特光照技术。使用半兰伯特光照，光线的衰减更加微妙。如果网格有严重的黑暗区域，启用此属性将软化阴影并更均匀地分布光线。 |
| `wrapRGB` | 当`wrapAround`设置为`true`时，您可以使用`THREE.Vector3`来控制光线衰减的速度。 |

初始化`THREE.MeshPhongMaterial`对象的方式与我们已经看到的所有其他材质的方式相同，并且显示在以下代码行中：

```js
var meshMaterial = new THREE.MeshPhongMaterial({color: 0x7777ff});
```

为了给你最好的比较，我们为这种材质创建了与`THREE.MeshLambertMaterial`相同的示例。您可以使用控制 GUI 来尝试这种材质。例如，以下设置会创建一个看起来像塑料的材质。您可以在`07-mesh-phong-material.html`中找到这个示例。以下屏幕截图显示了这个示例：

![THREE.MeshPhongMaterial](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_04_11.jpg)

我们将探讨的高级材质中的最后一个是`THREE.ShaderMaterial`。

## 使用 THREE.ShaderMaterial 创建自己的着色器

`THREE.ShaderMaterial`是 Three.js 中最多功能和复杂的材质之一。使用这种材质，您可以传递自己的自定义着色器，直接在 WebGL 上下文中运行。着色器将 Three.js JavaScript 网格转换为屏幕上的像素。使用这些自定义着色器，您可以精确定义对象的渲染方式，以及如何覆盖或更改 Three.js 的默认设置。在本节中，我们暂时不会详细介绍如何编写自定义着色器。有关更多信息，请参阅第十一章, *自定义着色器和渲染后处理*。现在，我们只会看一个非常基本的示例，展示如何配置这种材质。

`THREE.ShaderMaterial`有许多可以设置的属性，我们已经看到了。使用`THREE.ShaderMaterial`，Three.js 传递了有关这些属性的所有信息，但是您仍然必须在自己的着色器程序中处理这些信息。以下是我们已经看到的`THREE.ShaderMaterial`的属性：

| 名称 | 描述 |
| --- | --- |
| `wireframe` | 这将材质呈现为线框。这对于调试目的非常有用。 |
| `Wireframelinewidth` | 如果启用线框，此属性定义了线框的线宽。 |
| `linewidth` | 这定义了要绘制的线的宽度。 |
| `Shading` | 这定义了如何应用着色。可能的值是`THREE.SmoothShading`和`THREE.FlatShading`。此属性在此材质的示例中未启用。例如，查看`MeshNormalMaterial`部分。 |
| `vertexColors` | 您可以使用此属性定义应用于每个顶点的单独颜色。此属性在`CanvasRenderer`上不起作用，但在`WebGLRenderer`上起作用。查看`LineBasicMaterial`示例，我们在该示例中使用此属性来给线的各个部分上色。 |
| `fog` | 这决定了这种材质是否受全局雾设置的影响。这并没有展示出来。如果设置为`false`，我们在第二章, *组成 Three.js 场景的基本组件*中看到的全局雾不会影响对象的渲染方式。 |

除了这些传递到着色器的属性之外，`THREE.ShaderMaterial`还提供了一些特定属性，您可以使用这些属性将附加信息传递到自定义着色器中（它们目前可能看起来有点晦涩；有关更多详细信息，请参见第十一章*自定义着色器和渲染后处理*），如下所示：

| 名称 | 描述 |
| --- | --- |
| `fragmentShader` | 此着色器定义了传入的每个像素的颜色。在这里，您需要传递片段着色器程序的字符串值。 |
| `vertexShader` | 此着色器允许您更改传入的每个顶点的位置。在这里，您需要传递顶点着色器程序的字符串值。 |
| `uniforms` | 这允许您向着色器发送信息。相同的信息被发送到每个顶点和片段。 |
| `defines` | 转换为#define 代码片段。使用这些片段，您可以在着色器程序中设置一些额外的全局变量。 |
| `attributes` | 这些可以在每个顶点和片段之间改变。它们通常用于传递位置和与法线相关的数据。如果要使用这个，您需要为几何图形的所有顶点提供信息。 |
| `lights` | 这决定了是否应该将光数据传递到着色器中。默认值为`false`。 |

在我们看一个例子之前，我们将简要解释`ShaderMaterial`的最重要部分。要使用这种材质，我们必须传入两种不同的着色器：

+   `vertexShader`：这在几何图形的每个顶点上运行。您可以使用此着色器通过移动顶点的位置来转换几何图形。

+   `fragmentShader`：这在几何图形的每个片段上运行。在`vertexShader`中，我们返回应该显示在这个特定片段上的颜色。

到目前为止，在本章中我们讨论的所有材质，Three.js 都提供了`fragmentShader`和`vertexShader`，所以你不必担心这些。

在本节中，我们将看一个简单的例子，该例子使用了一个非常简单的`vertexShader`程序，该程序改变了立方体顶点的*x*、*y*和*z*坐标，以及一个`fragmentShader`程序，该程序使用了来自[`glslsandbox.com/`](http://glslsandbox.com/)的着色器创建了一个动画材质。

接下来，您可以看到我们将使用的`vertexShader`的完整代码。请注意，编写着色器不是在 JavaScript 中完成的。您需要使用一种称为**GLSL**的类似 C 的语言来编写着色器（WebGL 支持 OpenGL ES 着色语言 1.0——有关 GLSL 的更多信息，请参见[`www.khronos.org/webgl/`](https://www.khronos.org/webgl/)）：

```js
<script id="vertex-shader" type="x-shader/x-vertex">
  uniform float time;

  void main()
  {
    vec3 posChanged = position;
    posChanged.x = posChanged.x*(abs(sin(time*1.0)));
    posChanged.y = posChanged.y*(abs(cos(time*1.0)));
    posChanged.z = posChanged.z*(abs(sin(time*1.0)));

    gl_Position = projectionMatrix * modelViewMatrix * vec4(posChanged,1.0);
  }
</script>
```

我们不会在这里详细讨论，只关注这段代码的最重要部分。要从 JavaScript 与着色器通信，我们使用一种称为 uniforms 的东西。在这个例子中，我们使用`uniform float time;`语句来传递外部值。根据这个值，我们改变传入顶点的*x*、*y*和*z*坐标（作为 position 变量传入）：

```js
vec3 posChanged = position;
posChanged.x = posChanged.x*(abs(sin(time*1.0)));
posChanged.y = posChanged.y*(abs(cos(time*1.0)));
posChanged.z = posChanged.z*(abs(sin(time*1.0)));
```

`posChanged`向量现在包含了基于传入的时间变量的这个顶点的新坐标。我们需要执行的最后一步是将这个新位置传递回 Three.js，这总是这样完成的：

```js
gl_Position = projectionMatrix * modelViewMatrix * vec4(posChanged,1.0);
```

`gl_Position`变量是一个特殊变量，用于返回最终位置。接下来，我们需要创建`shaderMaterial`并传入`vertexShader`。为此，我们创建了一个简单的辅助函数，我们可以像这样使用：`var meshMaterial1 = createMaterial("vertex-shader","fragment-shader-1");`在下面的代码中：

```js
function createMaterial(vertexShader, fragmentShader) {
  var vertShader = document.getElementById(vertexShader).innerHTML;
  var fragShader = document.getElementById(fragmentShader).innerHTML;

  var attributes = {};
  var uniforms = {
    time: {type: 'f', value: 0.2},
    scale: {type: 'f', value: 0.2},
    alpha: {type: 'f', value: 0.6},
    resolution: { type: "v2", value: new THREE.Vector2() }
  };

  uniforms.resolution.value.x = window.innerWidth;
  uniforms.resolution.value.y = window.innerHeight;

  var meshMaterial = new THREE.ShaderMaterial({
    uniforms: uniforms,
    attributes: attributes,
    vertexShader: vertShader,
    fragmentShader: fragShader,
    transparent: true

  });
  return meshMaterial;
}
```

参数指向 HTML 页面中`script`元素的 ID。在这里，您还可以看到我们设置了一个 uniforms 变量。这个变量用于将信息从我们的渲染器传递到我们的着色器。我们这个例子的完整渲染循环如下代码片段所示：

```js
function render() {
  stats.update();

  cube.rotation.y = step += 0.01;
  cube.rotation.x = step;
  cube.rotation.z = step;

  cube.material.materials.forEach(function (e) {
    e.uniforms.time.value += 0.01;
  });

  // render using requestAnimationFrame
  requestAnimationFrame(render);
  renderer.render(scene, camera);
}
```

您可以看到，我们每次运行渲染循环时都会将时间变量增加 0.01。此信息传递到`vertexShader`中，并用于计算我们立方体顶点的新位置。现在打开`08-shader-material.html`示例，您会看到立方体围绕其轴收缩和增长。以下屏幕截图显示了此示例的静态图像：

![使用 THREE.ShaderMaterial 创建自定义着色器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_04_12.jpg)

在此示例中，您可以看到立方体的每个面都具有动画图案。分配给立方体每个面的片段着色器创建了这些图案。正如您可能已经猜到的那样，我们为此使用了`THREE.MeshFaceMaterial`（以及我们之前解释的`createMaterial`函数）：

```js
var cubeGeometry = new THREE.CubeGeometry(20, 20, 20);

var meshMaterial1 = createMaterial("vertex-shader", "fragment-shader-1");
var meshMaterial2 = createMaterial("vertex-shader", "fragment-shader-2");
var meshMaterial3 = createMaterial("vertex-shader", "fragment-shader-3");
var meshMaterial4 = createMaterial("vertex-shader", "fragment-shader-4");
var meshMaterial5 = createMaterial("vertex-shader", "fragment-shader-5");
var meshMaterial6 = createMaterial("vertex-shader", "fragment-shader-6");

var material = new THREE.MeshFaceMaterial([meshMaterial1, meshMaterial2, meshMaterial3, meshMaterial4, meshMaterial5, meshMaterial6]);

var cube = new THREE.Mesh(cubeGeometry, material);
```

我们尚未解释的部分是关于`fragmentShader`。在此示例中，所有`fragmentShader`对象都是从[`glslsandbox.com/`](http://glslsandbox.com/)复制的。该网站提供了一个实验性的游乐场，您可以在其中编写和共享`fragmentShader`对象。我不会在这里详细介绍，但在此示例中使用的`fragment-shader-6`如下所示：

```js
<script id="fragment-shader-6" type="x-shader/x-fragment">
  #ifdef GL_ES
  precision mediump float;
  #endif

  uniform float time;
  uniform vec2 resolution;

  void main( void )
  {

    vec2 uPos = ( gl_FragCoord.xy / resolution.xy );

    uPos.x -= 1.0;
    uPos.y -= 0.5;

    vec3 color = vec3(0.0);
    float vertColor = 2.0;
    for( float i = 0.0; i < 15.0; ++i ) {
      float t = time * (0.9);

      uPos.y += sin( uPos.x*i + t+i/2.0 ) * 0.1;
      float fTemp = abs(1.0 / uPos.y / 100.0);
      vertColor += fTemp;
      color += vec3( fTemp*(10.0-i)/10.0, fTemp*i/10.0, pow(fTemp,1.5)*1.5 );
    }

    vec4 color_final = vec4(color, 1.0);
    gl_FragColor = color_final;
  }
</script>
```

最终传递给 Three.js 的颜色是使用`gl_FragColor = color_final`设置的颜色。更多了解`fragmentShader`的方法是探索[`glslsandbox.com/`](http://glslsandbox.com/)提供的内容，并使用代码创建自己的对象。在我们转移到下一组材质之前，这里是一个使用自定义`vertexShader`程序的更多示例([`www.shadertoy.com/view/4dXGR4`](https://www.shadertoy.com/view/4dXGR4))：

![使用 THREE.ShaderMaterial 创建自定义着色器](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_04_13.jpg)

有关片段和顶点着色器的更多内容，请参阅第十一章，“自定义着色器和渲染后处理”。

# 您可以用于线几何体的材质

我们将要查看的最后几种材质只能用于特定几何体：`THREE.Line`。顾名思义，这只是一个仅由顶点组成且不包含任何面的单条线。Three.js 提供了两种不同的材质，您可以用于线，如下所示：

+   `THREE.LineBasicMaterial`：线的基本材质允许您设置`colors`，`linewidth`，`linecap`和`linejoin`属性

+   `THREE.LineDashedMaterial`：具有与`THREE.LineBasicMaterial`相同的属性，但允许您通过指定虚线和间距大小来创建*虚线*效果

我们将从基本变体开始，然后再看虚线变体。

## THREE.LineBasicMaterial

对于`THREE.Line`几何体可用的材质非常简单。以下表格显示了此材质可用的属性：

| 名称 | 描述 |
| --- | --- |
| `color` | 这确定了线的颜色。如果指定了`vertexColors`，则忽略此属性。 |
| `linewidth` | 这确定了线的宽度。 |
| `linecap` | 此属性定义了线框模式下线条末端的外观。可能的值是`butt`，`round`和`square`。默认值是`round`。在实践中，更改此属性的结果很难看到。此属性不受`WebGLRenderer`支持。 |
| `linejoin` | 定义线接头的可视化方式。可能的值是`round`，`bevel`和`miter`。默认值是`round`。如果仔细观察，可以在使用低`opacity`和非常大的`wireframeLinewidth`的示例中看到这一点。此属性不受`WebGLRenderer`支持。 |
| `vertexColors` | 通过将此属性设置为`THREE.VertexColors`值，可以为每个顶点提供特定的颜色。 |
| `fog` | 这确定了这个对象是否受全局雾化属性的影响。 |

在我们查看 `LineBasicMaterial` 的示例之前，让我们先快速看一下如何从一组顶点创建 `THREE.Line` 网格，并将其与 `LineMaterial` 结合起来创建网格，如下所示的代码：

```js
var points = gosper(4, 60);
var lines = new THREE.Geometry();
var colors = [];
var i = 0;
points.forEach(function (e) {
  lines.vertices.push(new THREE.Vector3(e.x, e.z, e.y));
  colors[ i ] = new THREE.Color(0xffffff);
  colors[ i ].setHSL(e.x / 100 + 0.5, (  e.y * 20 ) / 300, 0.8);
  i++;
});

lines.colors = colors;
var material = new THREE.LineBasicMaterial({
  opacity: 1.0,
  linewidth: 1,
  vertexColors: THREE.VertexColors });

var line = new THREE.Line(lines, material);
```

这段代码片段的第一部分 `var points = gosper(4, 60);` 用作获取一组 *x* 和 *y* 坐标的示例。这个函数返回一个 gosper 曲线（更多信息，请查看 [`en.wikipedia.org/wiki/Gosper_curve`](http://en.wikipedia.org/wiki/Gosper_curve)），这是一个填充 2D 空间的简单算法。接下来我们创建一个 `THREE.Geometry` 实例，对于每个坐标，我们创建一个新的顶点，并将其推入该实例的 lines 属性中。对于每个坐标，我们还计算一个颜色值，用于设置 colors 属性。

### 提示

在这个例子中，我们使用 `setHSL()` 方法设置颜色。与提供红色、绿色和蓝色的值不同，使用 HSL，我们提供色调、饱和度和亮度。使用 HSL 比 RGB 更直观，更容易创建匹配的颜色集。关于 HSL 的非常好的解释可以在 CSS 规范中找到：[`www.w3.org/TR/2003/CR-css3-color-20030514/#hsl-color`](http://www.w3.org/TR/2003/CR-css3-color-20030514/#hsl-color)。

现在我们有了几何体，我们可以创建 `THREE.LineBasicMaterial`，并将其与几何体一起使用，创建一个 `THREE.Line` 网格。你可以在 `09-line-material.html` 示例中看到结果。以下截图显示了这个示例：

![THREE.LineBasicMaterial](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_04_14.jpg)

我们将在本章讨论的下一个和最后一个材质，与 `THREE.LineBasicMaterial` 仅略有不同。使用 `THREE.LineDashedMaterial`，我们不仅可以给线条上色，还可以添加*虚线*效果。

## THREE.LineDashedMaterial

这种材质与 `THREE.LineBasicMaterial` 具有相同的属性，还有两个额外的属性，可以用来定义虚线的宽度和虚线之间的间隙，如下所示：

| 名称 | 描述 |
| --- | --- |
| `scale` | 这会缩放 `dashSize` 和 `gapSize`。如果比例小于 `1`，`dashSize` 和 `gapSize` 会增加，如果比例大于 `1`，`dashSize` 和 `gapSize` 会减少。 |
| `dashSize` | 这是虚线的大小。 |
| `gapSize` | 这是间隙的大小。 |

这种材质几乎与 `THREE.LineBasicMaterial` 完全相同。它的工作原理如下：

```js
lines.computeLineDistances();
var material = new THREE.LineDashedMaterial({ vertexColors: true, color: 0xffffff, dashSize: 10, gapSize: 1, scale: 0.1 });
```

唯一的区别是你必须调用 `computeLineDistances()`（用于确定构成一条线的顶点之间的距离）。如果不这样做，间隙将无法正确显示。这种材质的示例可以在 `10-line-material-dashed.html` 中找到，并且看起来像以下截图：

![THREE.LineDashedMaterial](https://github.com/OpenDocCN/freelearn-js-zh/raw/master/docs/lrn-3js/img/2215OS_04_15.jpg)

# 总结

Three.js 提供了许多可以用来渲染几何体的材质。这些材质从非常简单的 `(THREE.MeshBasicMaterial)` 到复杂的 `(THREE.ShaderMaterial)` 都有，其中你可以提供自己的 `vertexShader` 和 `fragmentShader` 程序。材质共享许多基本属性。如果你知道如何使用单个材质，你可能也知道如何使用其他材质。请注意，并非所有材质都会对场景中的光源做出反应。如果你想要一个考虑光照效果的材质，可以使用 `THREE.MeshPhongMaterial` 或 `THREE.MeshLamberMaterial`。仅仅通过代码来确定某些材质属性的效果是非常困难的。通常，一个好主意是使用 dat.GUI 方法来尝试这些属性。

另外，请记住大部分材质的属性都可以在运行时修改。但有些属性（例如 `side`）是不能在运行时修改的。如果你改变了这样的值，你需要将 `needsUpdate` 属性设置为 `true`。关于在运行时可以和不可以改变的完整概述，请参考以下页面：[`github.com/mrdoob/three.js/wiki/Updates`](https://github.com/mrdoob/three.js/wiki/Updates)。

在这一章和前面的章节中，我们谈到了几何体。我们在示例中使用了它们并探索了其中一些。在下一章中，你将学习关于几何体的一切，以及如何与它们一起工作。
