# ReactVR 入门手册（二）

> 原文：[`zh.annas-archive.org/md5/BB76013B3798515A13405091AD7CB582`](https://zh.annas-archive.org/md5/BB76013B3798515A13405091AD7CB582)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：与 Poly 和 Gon 家族合作

当刚开始接触计算机图形的人看到一些最初的 VR 图形时，他们的第一反应是“哦，不是多边形！”我的一个朋友在看到她的第一个大型多人在线角色扮演游戏时，感到恼火时说了这句话。它并不像《Money for Nothing》那样低多边形，但它非常接近。《Money for Nothing》是第一个使用计算机图形并且看起来像这样的音乐视频之一：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/4b7e52a0-ee86-4846-9565-3bb646d51bac.jpg)

多边形是呈现实时图形的最佳方式。在本节中，我们将不得不制作其中的一些！您可能已经熟悉**计算机辅助**（设计/草图/绘图）（CAD）软件或计算机建模软件；或者您可能是一个完全的新手。有很多不同的 CAD 系统，我们将使用 Blender，一个免费的可用/开源 CAD 系统，来说明带入虚拟现实中一些重要的方式。

在本章中，您将学到：

+   如何执行基本多边形建模

+   如何从 Blender 中以 OBJ 形式导出模型

+   如何应用基本 UV 纹理映射

+   如何导出纹理贴图

+   如何创建 MTL 文件以正确显示实时 OBJ 纹理和材质

# 多边形及我们为什么喜欢它们

我认为对“哦，不是多边形”感到困惑的原因是，多边形，除非它们被提升到艺术形式，如前面的音乐视频中那样，否则可能是一种创建东西的非常粗糙的方式。例如，这看起来并不像一个苹果：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/d544809d-1289-4dab-bfd9-cf2f02312be5.jpg)

许多 CAD 系统确实有其他表示形式，如**非**均匀有理 B 样条（NURBS），这是一种曲线，或者基本上没有多边形但是它们所代表的原始图形。例如，一个球可能是任意光滑的，没有面或平坦区域。

如果一切都是立方体和球体，世界将会很无聊。除非是 Minecraft，那将会很酷。除了 Minecraft，许多 CAD 系统通过**构造实体几何**（CSG）来构建更有趣的对象，通过在其他原始图形上钻孔和添加基本原始图形来制作更复杂的对象。

# 为什么 VR 不使用一些这些技术？

一般来说，它们很慢。需要有东西将精确、准确的数学模型转换成视频硬件可以显示的东西。一些视频卡和高级 API 可以用其他东西构建对象，计算平滑曲线等等，但迄今为止，在 VR 和游戏行业中最常见的工作流程仍围绕着多边形和纹理。

因此，我们可以将多边形视为一种给定的形式。现代视频卡和高端手机在渲染对象时具有相当多的能力，尽管为了保持 VR 的帧率，我们确实需要注意多边形的数量。

好消息是，你可以用相当低的多边形数量制作出非常好看的 VR 对象。例如，看看我们的苹果。刚刚显示的低分辨率版本只有 44 个面（多边形）和 24 个顶点（点）。如果我们将多边形数量增加到 492 个，它看起来会好得多：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/7f6942ba-3cca-400f-b13a-d64b9e730552.png)在这些例子中，我使用的是 Blender 版本 v2.79。你可以使用任何能读写 OBJ 文件的 CAD 程序，几乎所有的 CAD 程序都可以。我使用 Blender 是因为它是免费的，所以任何读者都可以跟着学习，而不用担心购买昂贵的 CAD 程序。

Blender 非常功能齐全，当然可以用于生产工作，尽管描述每种可能的 CAD 系统并推荐其中一种超出了本书的范围（而且我从不喜欢公开讨论宗教！）。不过从前面的模型中，你可以看到 Blender 的局限性；这个模型有相当奇怪的**纹理映射**，而且分辨率降低太多会在纹理贴图上产生一些奇怪的条纹。

当然，我们可以像在 2030 年的 PC 上运行一样向系统投放多边形，几乎比我们现在拥有的快 512 倍，如果摩尔定律成立的话。我们的苹果会看起来像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/64396fd3-0e9c-42a9-a7a6-36959e3393a1.png)

这与中等分辨率的苹果并没有太大的不同，尽管那些奇怪的纹理线已经消失了。看起来相当不错（这不是一个完整的细节渲染）。为了使分辨率更低的多边形，我在 Blender 中进行了快速的减面。减面是 Blender 的一种方式，可以将具有大量多边形的模型减少到更少的多边形，这是一种非常方便的方式，可以将非常复杂的模型制作成虚拟现实准备。手动进行减面，并对模型应用新的纹理，可能会消除接缝。

对于高级建模者，你可以使用你的模型的低多边形版本，结合高多边形版本，制作一个法线贴图，这与凹凸贴图不同，可以让模型看起来比实际多边形更多。

你可能需要尝试一些法线贴图；这真的取决于浏览器和模型。

现在，你可能会想你更愿意使用拥有 25,206 个面的苹果。这可能有效，但这是一个相当大的模型。很多人会问“我可以使用多少多边形？”虽然这是一个很难回答的问题。这就好像问你妈妈她能把多少杂货装进车里一样？很大程度上取决于装的是什么杂货。如果她要带回一包 24 卷的舒适卫生纸，我可以告诉你，根据我的个人经验，一两卷才能装进一辆两座位的跑车里。（放心，我不是在炫耀，我的跑车已经 12 年了。）

将你的多边形预算想象成与你可能拥有的其他物体相比更好。那个高分辨率的苹果？以同样的速度（非常粗略地说），你可以拥有超过 48 个中等分辨率的苹果。

如果你要为你的太空画廊顾客提供茶点，你更愿意提供 1 个还是 48 个？

保持你的物体尽可能低分辨率，并且仍然保持你需要的视觉外观。你可能需要访问低多边形物体或一个可以减少多边形的好 CAD 系统。

说了这些之后，我从之前的模型中得到了一些相当合理的帧速率。我的目标不是给你一个绝对的数字，而是要展示顶点预算有多么重要。

# 什么是多边形？讨论顶点、多边形和边

如果你使用建模程序，你将不必处理这些对象的定义的复杂性。然而，偶尔你可能需要深入了解细节，因此有必要了解一些背景知识。如果你是计算机图形方面的老手，你可能已经了解很多。我确实提供了一些建议，关于如何最好地将它们引入 React VR，所以最好进行复习。

多边形是由顶点（点）、边和面组成的*n*边对象。面可以朝内或朝外，也可以是双面的。对于大多数实时 VR，我们使用单面多边形；当我们首次将平面放置在世界中时，我们注意到这一点，根据方向的不同，你可能看不到它。

为了真正展示这一切是如何运作的，我将展示 OBJ 文件的内部格式。通常情况下，你不会手动编辑这些文件——我们已经超越了由几千个多边形构建的 VR 时代（我的第一个 VR 世界有一个代表下载的火车，它有六个多边形，每个点都是精心手工制作的），因此手动编辑并不是必要的，但你可能需要编辑 OBJ 文件以包含正确的路径或进行模型师无法原生完成的更改——所以让我们深入了解吧！

多边形是通过在 3D 空间中创建点并用面连接它们来构建的。你可以认为顶点是通过线连接的（大多数建模工具都是这样工作的），但在 React VR 所基于的原生 WebGL 中，它实际上只是面。这些点并不是真正存在的，而是更多地“锚定”了多边形的角落。

例如，这是在 Blender 中建模的一个简单三角形：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/869b944a-86fe-4fd3-8ba9-3a327af75f96.png)

在这种情况下，我用三个顶点和一个面（在这种情况下只是一个纯色，绿色；如果你正在阅读一本实体书或电子墨水阅读器（Kindle），当然会是灰色的一种）构建了一个三角形。边缘以黄色或浅色显示，是为了模型师的方便，不会被显式渲染。

这是我们画廊内三角形的样子：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/45d4186a-0ae8-4d29-9194-cdad9424788a.jpg)

如果你仔细看 Blender 的照片，你会注意到物体并不在世界中心。当导出时，它将以你在 Blender 中应用的平移导出。这就是为什么三角形在基座上略微偏离中心。好消息是我们在外太空中，漂浮在轨道上，因此不必担心重力。（React VR 没有物理引擎，尽管添加一个是很简单的。）

你可能注意到的第二件事是，在 Blender 中三角形周围的黄色线条（在打印中是浅灰色线条）在 VR 世界中并不持续存在。这是因为文件被导出为一个面，连接了三个顶点。

顶点的复数是顶点，不是 vertexes。如果有人问你关于 vertexes，你可以笑话他们，几乎和有人把 Bézier 曲线发音为“bez ee er”一样多。

好吧，公平地说，我曾经那样做过，现在我总是说 Beh zee a。

好了，开玩笑的时间到此为止，现在让我们让它看起来比一个平面绿色三角形更有趣。这是通过通常称为纹理映射的东西来完成的。

老实说，“纹理”和“材质”这个词经常被互换使用，尽管最近它们已经在一定程度上稳定下来，材质指的是物体外观的任何东西，除了它的形状；材质可以是它有多光滑，有多透明等等。**纹理**通常只是物体的颜色 - 瓷砖是红色的，皮肤可能有雀斑 - 因此通常被称为纹理贴图，用 JPG、TGA 或其他图像格式表示。

没有真正的跨软件文件格式用于材料或**着色器**（通常是代表材料的计算机代码）。当渲染时，有一些标准的着色器语言，尽管这些语言并不总是在 CAD 程序中使用。

你需要了解你的 CAD 程序使用的是什么，并熟练掌握它如何处理材料（和纹理贴图）。这远远超出了本书的范围。

OBJ 文件格式（通常是 React VR 使用的）允许使用多种不同的纹理贴图来正确构建材料。它还可以通过文件中编码的参数指示材料本身。首先，让我们看看三角形由什么组成。我们通过`Model`关键字导入 OBJ 文件：

```jsx
<Model
    source={{
        obj: asset('OneTri.obj'),
        mtl: asset('OneTri.mtl'),
        }}
    style={{
            transform: [
                { translate: [ -0, -1, -5\. ] },
                { scale: .1 },
            ]
        }}
/>
```

首先，让我们打开`MTL`（材质）文件（因为.obj 文件使用.mtl 文件）。OBJ 文件格式是由 Wavefront 开发的：

```jsx
# Blender MTL File: 'OneTri.blend'
# Material Count: 1

newmtl BaseMat
Ns 96.078431
Ka 1.000000 1.000000 1.000000
Kd 0.040445 0.300599 0.066583
Ks 0.500000 0.500000 0.500000
Ke 0.000000 0.000000 0.000000
Ni 1.000000
d 1.000000
illum 2
```

其中很多是例行公事，但重要的是以下参数：

+   `Ka`：环境颜色，以 RGB 格式

+   `Kd`：漫反射颜色，以 RGB 格式

+   `Ks`：镜面反射颜色，以 RGB 格式

+   `Ns`：镜面反射指数，从 0 到 1,000

+   `d`：透明度（d 代表*dissolved*）。请注意，WebGL 通常无法显示折射材料，或显示真实的体积材料和光线追踪，所以`d`只是光线被阻挡的百分比。`1`（默认值）是完全不透明的。请注意，.obj 规范中的`d`适用于 illum 模式 2。

透明材料，在撰写本书时，不受 React VR 支持。然而，目前正在开发中，所以也许很快它们会被支持。

+   Tr：透明度的替代表示；0 是完全不透明。

+   `illum` <#>（从 0 到 10 的数字）。并非所有照明模型都受 WebGL 支持。当前的列表是：

1.  颜色开启，环境关闭。

1.  颜色开启，环境开启。

1.  高亮（和颜色）<=这是正常设置。

1.  还有其他照明模式，但目前没有被 WebGL 使用。当然，这可能会改变。

+   `Ni`是光学密度。这对 CAD 系统很重要，但在 VR 中支持它的机会相当低，除非有很多技巧。计算机和显卡的速度一直在不断提高，所以也许光学密度和实时光线追踪最终会得到支持，这要感谢摩尔定律（统计上，计算能力大约每两年翻一番）。

非常重要：确保在所有模型声明中包含“lit”关键字，否则加载程序将假定你只有一个发光的对象，并将忽略材料文件中的大部分参数！

你已经被警告了。它看起来会很奇怪，你会完全困惑。别问我为什么我知道！

OBJ 文件本身包含了几何图形的描述。这些通常不是你可以手动编辑的东西，但是看到整体结构是很有用的。对于之前显示的简单对象，它是相当容易管理的：

```jsx
# Blender v2.79 (sub 0) OBJ File: 'OneTri.blend'
# www.blender.org
mtllib OneTri.mtl
o Triangle
v -7.615456 0.218278 -1.874056
v -4.384528 15.177612 -6.276536
v 4.801097 2.745610 3.762014
vn -0.445200 0.339900 0.828400
usemtl BaseMat
s off
f 3//1 2//1 1//1
```

首先，您会看到一个注释（用`#`标记），告诉您是什么软件制作的，以及原始文件的名称。这可能会有所不同。`mtllib` 是对特定材质文件的调用，我们已经看过了。`o` 行（如果有组，还有`g` 行）定义了对象和组的名称；尽管 React VR 目前并不真正使用这些，但在大多数建模软件中，这将列在对象的层次结构中。`v` 和 `vn` 关键字是有趣的地方，尽管这些仍然不是可见的东西。`v` 关键字在 x、y、z 空间中创建一个顶点。稍后将连接构建的顶点成多边形。`vn` 建立了这些对象的法线，`vt` 将创建相同点的纹理坐标。稍后再详细讨论纹理坐标。

`usemtl BaseMat` 建立了在接下来的面中将使用的材质，该材质在您的.mtl 文件中指定。

`s off` 意味着关闭了平滑。平滑和顶点法线可以使物体看起来光滑，即使它们由很少的多边形制成。例如，看看这两个茶壶；第一个没有平滑。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/98c63628-9ac2-47a4-b90d-156e10875858.png)

看起来很像计算机图形，对吧？现在，看看在整个文件中指定了“s 1”参数，并且法线包含在文件中的相同茶壶。这是相当正常的（双关语），我的意思是大多数 CAD 软件会为您计算法线。您可以使法线光滑、锐利，并在需要时添加边缘。这可以在不增加多边形的情况下增加细节，并且渲染速度快。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/7d3ee609-8afd-4706-9f42-0d2ddc9a11c9.png)

光滑的茶壶看起来更真实，对吧？好吧，我们还没看到最好的！让我们讨论纹理。

我过去不喜欢寿司是因为口感。我们不是在谈论那种口感。

纹理映射很像是用一张圣诞包装纸包裹一个奇形怪状的物体。就像在圣诞节收到那个奇怪的礼物，不太知道该怎么做一样，有时包装并没有明确的正确方式。盒子很容易，但大多数有趣的物体并不总是一个盒子。我在网上找到了这张带有标题“*我希望是 X-Box*.*”*的照片。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/a90e54eb-6ec1-4097-bc3e-74cf3d60e917.jpg)

“包裹”是通过 CAD 系统中的 U、V 坐标完成的。让我们来看一个带有正确 UV 坐标的三角形。然后我们去拿我们的包装纸，也就是说，我们拿一张图像文件作为纹理，就像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/20e61ca4-70bf-478c-a278-f17f9a5bcb81.jpg)

然后我们在 CAD 程序中将其包装起来，指定它作为纹理贴图。然后我们将三角形导出，并放入我们的世界中。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/647e8ee1-d882-4fb8-b15a-40c7d0ca2f65.jpg)

您可能期望在纹理贴图上看到“左侧和底部”。在我们的建模软件（仍然是 Blender）中仔细观察后，我们发现默认的 UV 映射（使用 Blender 的标准工具）尝试尽可能多地使用纹理贴图，但从艺术角度来看，可能并不是我们想要的。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/4e7c5e33-dd23-44c0-832c-77d075b43ca1.png)

这并不是要表明 Blender 是“你做错了”，而是要说明在导出之前您必须检查纹理映射。此外，如果您尝试导入没有 U、V 坐标的对象，请再次检查它们！

如果您正在手动编辑.mtl 文件，并且您的纹理没有显示出来，请仔细检查.obj 文件，并确保您有`vt`行；如果没有，纹理将不会显示出来。这意味着纹理映射的 U、V 坐标没有设置。

纹理映射并不是一件简单的事情；关于它有很多艺术性的东西，甚至有整本书专门讲述纹理和光照。话虽如此，如果您从互联网上下载了一些东西并希望让它看起来更好一些，您可以通过 Blender 和任何 OBJ 文件来取得相当大的进展。我们将向您展示如何修复它。最终目标是获得一个更可用和高效的 UV 贴图。并非所有的 OBJ 文件导出器都会导出正确的纹理贴图，而且您在网上找到的.obj 文件可能有 UV 设置，也可能没有。

您可以使用 Blender 来修复模型的展开。虽然这不是一个 Blender 教程，但我会在这里向您展示足够的内容，让您可以通过一本关于 Blender 的书（Packt 有几本很好的 Blender 书）来快速入门。您也可以使用您喜欢的 CAD 建模程序，比如 Max、Maya、Lightwave、Houdini 等等。（如果我错过了您喜欢的软件，请原谅我！）。

这很重要，所以我会在信息框中再次提到它。如果您已经使用了不同的多边形建模器或 CAD 页面，您不必学习 Blender；您的程序肯定会正常工作。您可以略过这一部分。

如果你不想学习 Blender，你可以从 Github 链接下载我们构建的所有文件。如果你要通过示例进行工作，你将需要一些图像文件。本章的文件位于：[`bit.ly/VR_Chap7`](http://bit.ly/VR_Chap7)。

# 获取 3D 模型的途径

这就引出了一个简短的分歧。首先，你从哪里得到这些模型？

获取 3D 模型的最佳方式是自己制作。如果你这样做，你可能不会读到这里，因为你已经知道多边形是什么，以及如何给它们贴图。然而，更有可能的是你会去付费或免费的模型网站下载你觉得吸引人的东西，用于你想要创建的世界。这只是为了节省时间。以下是我多年来发现有用的一些网站的简要介绍。其中一些网站可能有非常昂贵的模型，因为它们经常迎合高端图形公司（电视、建筑、电影、设计师），以及高质量但昂贵的游戏艺术。游戏艺术是你要寻找的，以做好 VR；一些网站现在有“低多边形”或 VR/AR 类别。其中一些，特别是 ShareCG 和 Renderosity，在某些地方往往非常业余。网站本身很棒，但上传的文件经常没有编辑控制；因此，你可能会找到侵犯版权的东西（星球大战和星际迷航模型），这是因为律师的明显原因，你在其他网站上找不到这些东西。另一方面，你可能会在这些网站上找到别人正在赚钱的你自己的内容，因此想找到你自己的律师。

说到律师，你需要检查任何你下载的文件的许可证。例如，你可能有权使用这些模型进行渲染，但不能进行分发。这可能允许你在游戏中使用这些模型，或者可能需要额外（更昂贵）的许可证。

一些网站（绝非独家）可以下载模型，包括：

+   [Turbosquid.com](http://Turbosquid.com)

+   [CGStudio.com](http://CGStudio.com)

+   [creativemarket.com/3d](http://creativemarket.com/3d)

+   [CGTrader.com](http://CGTrader.com)

+   [Grabcad.com](http://Grabcad.com)

+   [ShareCG.com](http://ShareCG.com)（本书中的一些模型来自这里）

+   [3dwarehouse.sketchup.com](http://3dwarehouse.sketchup.com)

为什么你会在这些网站上找到这么好的模型？为什么一些模型看起来如此奇怪，艺术性如此之高？许多艺术家有一些不需要排他性的合同，或者人们正在制作一个游戏，但最终没有发布。他们可以上传这些未使用或较少使用的模型，让其他人使用，并甚至从销售中获利。

你可以花上几天的时间在所有这些网站上搜索适合你网站的完美内容。

你已经被警告了！

还有许多旨在用于 3D 打印的 3D 模型网站。这些模型可能非常密集（高多边形），但可能有一些你可以使用的内容。

我喜欢使用一个叫做“Poser”的程序来进行人体建模，尽管许多 CGI 艺术家更喜欢自己制作。DAZ3D 也出售人体模型，其中许多可以与 Poser 一起使用。这两个网站都是廉价、合理质量渲染的良好资源网站（取决于你设置场景的技能）。Poser 程序有许多专门用于对象、场景、模型和纹理的网站可供使用。由于高多边形数量和非常密集的纹理，Poser 人体模型在 VR 中显示效果不佳，但这些网站可能仍然有物体和附加工具，通常价格非常合理。

一些拥有良好 Poser 模型的网站，以及许多其他免费物体的网站是：

+   [my.smithmicro.com/poser-3d-animation-software.html](http://my.smithmicro.com/poser-3d-animation-software.html)

+   [DAZ3D.com](http://DAZ3D.com)

+   [Contentparadise.com](http://Contentparadise.com)

+   [Renderosity.com](http://Renderosity.com)

本书中的几幅图像是用 Poser 和 DAZ Studio 完成的。

# 总结

在这一章中，你学会了使用 Blender 进行多边形建模的基础知识。你已经了解了多边形预算的重要性，如何导出这些模型，以及关于 OBJ/MTL 文件格式的细节。你还学会了我们可以在哪里获取我们世界的 3D 模型。

这些物体看起来可能很普通；然而，在下一节中，你将学会如何在茶壶周围包裹一张纸。这不仅是一种给人们礼物的技能，它对于使我们的虚拟世界看起来真实将是至关重要的。


# 第七章：坐在（虚拟）茶壶旁

在上一章中，我们了解了很多关于多边形以及如何在实时图形中使用它们的知识。我们将继续使用多边形，并学习更多关于给它们贴图的知识。

在本章中，我们将学习以下内容：

+   如何使用 Blender 的基础知识

+   如何应用基本的 UV 纹理映射

+   如何导出纹理映射

+   如何创建 MTL 文件以正确显示实时 OBJ 纹理和材质

+   为我们的茶壶画廊整合一切

Blender 只是许多多边形建模器之一，您可以使用它来制作用于 WebVR 的虚拟对象。如果您已经熟悉多边形建模的概念，并且创建和编辑 UV 映射，那么您实际上不需要本章的大部分内容。一旦我们完成 UV 映射，我们就将模型导入到世界中。我还将本章的静态文件放在了[`bit.ly/VR_Chap7`](http://bit.ly/VR_Chap7)，这样您就可以下载它们，而不是自己构建它们。

UV 建模可能会很乏味。如果您只是下载文件，我不会介意的。但请浏览以下内容，因为我们构建这些模型时，我们将把它们放在虚拟世界中。

# 在 Blender 中的茶壶

要学习如何 UV 映射，让我们在 Blender 中放一个茶壶。今天，这将运行得相当顺利，但通常茶壶不会适合在 Blender 中。

您可以在[blender.org](http://www.blender.org)下载 Blender。在那里，我强烈推荐网站上的教程[bit.ly/BlendToots](http://bit.ly/BlendToots)。Packt 还有很多关于 Blender 的好书。您可以在[`bit.ly/BlenderBooks`](http://bit.ly/BlenderBooks)找到这些书。如果您还没有通过这些教程，对基本的光标移动和选择可能会感到有些困惑或沮丧；看到光标移动的动画比写作更有帮助。特别是，请观看*入门*下的光标选择教程：[`bit.ly/BlendStart`](http://bit.ly/BlendStart)。

为了开始贴图，我们将使用 Martin Newell 的著名的“犹他州茶壶”。这是计算机图形学中更著名的“测试模型”之一。这是原始的犹他州茶壶，目前在加利福尼亚州山景城的计算机历史博物馆展出（由 Marshall Astor 提供）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/cea99f22-c6bf-43ba-9d63-a22b5c08e0eb.jpg)

计算机图形学版本被*压扁*在演示中，这种压扁是固定的。您可以在[`bit.ly/DrBlinn`](http://bit.ly/DrBlinn)了解更多信息。

这是 Blender 中的茶壶。您可以通过在首选项中打开额外形状来到这里：

1.  点击菜单文件，然后用户首选项（文件->用户首选项），然后点击额外对象：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/d9c25243-15ab-461b-b28f-c76b97fc0164.png)

1.  不要忘记然后点击屏幕底部的按钮“保存用户设置”，否则下次进入时对象将不在那里。保存后，关闭 Blender 用户首选项窗口。

1.  然后，在 3D 窗口底部的菜单上，点击“添加->网格->额外->茶壶+”：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/7924a823-1062-4737-8076-f3c7e934e84a.png)

1.  一旦你这样做了，仅供教学目的，选择左下角窗格上的分辨率为 3，如图所示。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/60d476ca-e3a2-4cd4-83da-3507fe2e2404.png)

增加茶壶的分辨率是相当不错的；如果我早点注意到这一点，写这一章节时就可以节省我一个小时在互联网上搜索了。我们将其更改为 3，以使多边形更大，这样在进行本教程时更容易点击。

1.  然后，您要在 3D 窗口中点击茶壶（左键）以选择它；然后茶壶将有一个橙色的轮廓。然后通过点击对象菜单旁边的“对象模式”一词，返回到编辑模式，然后选择“编辑模式”：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/565c43a6-b8eb-47d2-8590-2893b57c37a4.png)

一旦你进入编辑模式，我们需要在选择茶壶的多边形时能够看到 UV 贴图。最初，可能不会有 UV 贴图；继续跟着我们，我们会创建一个。

1.  将鼠标放在时间轴窗口上方的细线上，在屏幕底部的窗口（以下截图中用红色圈出的区域）上拖动窗口*向上*。这将为窗口留出足够的空间。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/1218c37e-12e8-4ad4-a848-0e84e3687ce4.png)

1.  我们不做动画，所以我们不需要那个窗口，我们会把它改成 UV 显示。要做到这一点，点击时间轴显示的小时钟图标（哇，还记得模拟时钟吗？），选择 UV/Image Editor：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/58e2c261-e51d-4359-b0a2-456fd1651d1f.png)这只是改变窗口布局的一种方式。在 Blender 中令人困惑的一点是，你可能会因为不小心点击了一些东西而真正搞乱你的用户界面，但其中一个很棒的地方是你可以通过鼠标点击轻松地创建窗口、子窗口、拉出、架子等等。我刚刚向你展示的方法是教学中最直接的方式，但对于真正的工作，你应该按照自己的意愿自定义窗口。

一旦你改变了这个视图，请注意你可以像其他 Blender 窗口一样放大、平移和移动窗口。关于如何放大、平移等等，你应该观看位于[`bit.ly/BlendStart`](http://bit.ly/BlendStart)的教程视频文件。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/c7a5a7e1-be11-42f2-b8da-ba53509765a2.png)

1.  所以，我们可以看到我们的模型使用我们的纹理是什么样子的；点击“打开”并找到一个你想要映射到你的茶壶（或模型）上的纹理文件。我正在使用`ButcherTile_Lettered.jpg`。

1.  完成后，进行第一次 UV 展开！在上窗口的菜单中，点击 Mesh->UV Unwrap->Unwrap，就像这样：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/fd838f50-b071-4ba8-9552-fc1641598535.png)

在底部窗口，它会显示出纹理的展开情况。

看起来很糟糕。你的结果可能会因不同的模型而有所不同。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/f14a37bb-044d-4182-975b-3f2ea1dd80ed.png)

为什么这个 UV 贴图看起来很糟糕？从实时图形的角度来看，它并不糟糕；它将所有多边形都打包到一个纹理贴图上，这将有助于视频卡的内存：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/f315f1e9-805d-42af-b1fb-aa20b20bc79f.png)

对于一些物体来说，这可能没问题。如果你看右上角和右下角，我们可以看到壶嘴和手柄，它们看起来有点奇怪。渲染出来可能会有点滑稽；让我们看看它的效果。为了做到这一点，我们必须分配一些纹理，然后导出茶壶。（我们稍后会介绍导出；现在，我们只需要看到我们在 Blender 中还有额外的工作要做。）

请注意，你可以通过在 Blender 内部渲染来快速查看，但这可能会让你失望，因为 Blender 几乎肯定会以完全不同的方式渲染你的模型。总体的颜色和纹理将是相同的，但 React VR 和 WebGL 能够实现的更微妙（也更重要）的纹理细节将会丢失（或者更好的是，使用离线、非实时渲染器）；相反，如果你真的在 Blender 中工作或者想要更好的效果，渲染可以产生惊人的作品。

例如，在 Blender 中，使用循环渲染器，渲染我们的茶壶花了 11.03 秒。

在 React VR 中，为了保持至少 60 帧每秒，这必须在不到 0.016 秒内完成。而 Blender 花了 600 多倍的时间来生成相同的图像；难道它不应该看起来更好吗？茶壶看起来并不差，但 UV 映射只是很奇怪。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/9b253590-7dce-4ade-bf21-b0e3239a6587.png)

我们可以看到方块在茶壶上有点奇怪地拉长了。（如果你停下来想想我们在做什么，我们只是在茶壶上放了一个瓷砖图案；这就是计算机图形的奇迹。我正在使用棋盘格图案，所以我们可以看到壶上的拉伸。以后，我会用 Substance Designer 制作一个更好的纹理。）

你可以在 Blender 中进行实验，点击多边形（在编辑模式中），看看该多边形在 UV 映射中的位置。为了辩护 Blender，这个映射并不是很糟糕，只是不是我们想要的。有时（几乎总是），需要一个人来真正创作艺术。

# 修复茶壶的 UV 映射

为了更容易地给壶上纹理，首先让我们为壶嘴、手柄和盖子创建单独的材料。这将使我们的纹理地图更大，拉伸得更少。你也可以通过将纹理打包在一个更大的位图中来做到这一点，老实说，有时这对于 VR 来说更好一些；总体方法是相同的，只是更多地打包在一个较小的区域内。

让我们为壶、手柄、壶嘴和盖子创建四种材料（你应该仍然处于编辑模式）。

1.  点击那个看起来有点像闪亮的地球的小图标。然后，点击“+”键四次，如图所示，然后点击“新建”：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/1e79d266-1f7f-435b-af00-67f763c45aaa.png)

1.  一旦你点击了“+”键四次，你将有四个我们正在创建的材料的插槽。然后你点击“新建”来实际添加一个材料。这似乎有点笨拙，但这就是 Blender 的工作方式：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/c681b81f-f816-4361-9236-b4959d235118.png)

1.  点击“新建”时，你会得到一个 Material.001：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/f47e3f20-36b1-48b7-8f38-5df633f7670b.png)

1.  你可以点击红圈中的区域并更改名称。这样，创建四种材料，如下所示：

1.  创建一个壶材料（将是陶瓷涂层金属）。

1.  创建一个盖子材料（和壶一样的纹理）。

1.  创建一个壶嘴材料（让我们把它做成铜制的）。

1.  创建一个手柄材料（让我们把它做成磨损的橡胶）。

我们并不真的需要创建这些材质；你可以在几个 UV 上叠加相同的纹理贴图，但我想对茶壶进行一次新的尝试（正如我们所看到的，它是一个实心的陶瓷制品），看到不同的材质是有益的。

现在这些额外的材质已经创建，你可以移动 UV 以更好地映射对象。UV 映射是一个庞大的主题，需要一定的技术和艺术技能才能做好，或者 PC 可以自动完成。这超出了本书的范围，但我会向你展示一个快速而粗糙的方法来对一些常见的物体进行 UV 映射。你在网上找到的许多文件可能没有应用良好的 UV 映射，所以你可能会发现自己处于这样一种情况，你认为自己不需要学习建模，但会用它来纠正 UV 映射（这在多边形建模时是一个相当高端的活动！）。

一旦你创建了这四种材质，你可以将每个部分独立地映射到自己的 UV 映射上；当我们在 VR 世界中展示时，我们将为每个部分使用不同的纹理贴图。如果你想制作一个单独的陶瓷壶，你可以使用相同的纹理贴图，但我们破旧的金属壶可能看起来更好。

这是艺术；美在于观者的眼中。

一旦你像上面那样确定了四种材质，选择每个主要区域的多边形，然后点击“分配”使它们成为这种材质的一部分：

1.  按下键盘上的“A”键（或选择->（取消）选择所有| A）取消选择所有的多边形。然后我们将选择每个区域的多边形，盖子、把手、壶嘴和壶（主体）。

1.  切换到“多边形选择”。Blender 有不同的选择模式-点、线、多边形。对于这个，你需要切换到选择多边形，点击这个图标：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/bb39fef6-4c4a-4cbe-beac-66c590740113.png)

1.  点击主壶多边形，使用*Shift + 点击*选择多个多边形。Blender 拥有丰富的选择工具，如框选等，可以参考教程：[`bit.ly/BlendStart`](http://bit.ly/BlendStart)

1.  一旦你选择了主体的多边形，点击“分配”按钮将该多边形分配给一个材质，比如“壶”材质。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/1ca11b68-d453-4d9d-8074-347fdd697398.png)

1.  一旦你分配了多边形，点击“视图->前视”，然后点击“网格->UV 展开->圆柱投影”。然后在我们之前设置的图像编辑器中会有一个 UV 映射，尽管它会从你分配的图像上拉伸出来。

1.  要解决这个问题，在屏幕下半部分的菜单中，选择 UVs->Pack Islands：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/84ef1212-462e-4063-8b3e-a6602ef5e9a5.png)

这是基本的纹理映射。你可以对此进行很多调整（这可能会让人沮丧）。Blender 有许多有用的自动 UV 分配工具；在 3D（建模）窗口中，正如我们之前看到的那样，Mesh->UV Unwrap->（选项）提供了许多解包的方法。我发现从视图投影以及圆柱投影，都可以从严格的上/下/左/右视图中很好地展开 UV。在说了这些之后，一些艺术性就会发挥作用。壶嘴、壶盖和手柄比壶身小，所以如果你希望你的纹理与主要的壶和纹理更或多或少地对齐，你可能需要浪费一些 UV 空间并将这些部分缩小。

或者你可以从 GitHub 文件中下载`teapot2.obj`和`teapot2_Mats.mtl`，并节省一些理智：[`bit.ly/VR_Chap7`](http://bit.ly/VR_Chap7)。

这四个 UV 映射不错（但是请随意学习，研究，做得更好！我不是艺术家！）。主体的 UV 映射，壶的材质在这里显示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/914310a7-3d31-4dbb-8dfd-1ebb347d5712.png)

盖子材质的 UV 映射：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/6e8328b9-eee9-45dd-a3e4-b0a4a8d8e48f.png)

手柄材质的 UV 映射（故意缩小，以使方块与主壶更或多或少对齐）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/1f517cbe-5870-4e70-ba01-979dabba3e21.png)

壶嘴材质的 UV 映射（故意缩小，以使方块与主壶更或多或少对齐）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/3f615e41-95ec-45e2-bead-6b691258b85f.png)

使用这些 UV 分配，我们的茶壶显示两次，在每次之间略微旋转，看起来好多了：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/83dd97bd-c0d4-4ac1-a030-6558a7f31993.png)

你可以对 UV 进行很多调整。在前面的截图中，如果我们要在壶上映射大部分是瓷砖方块的纹理，我们可以看到，尽管手柄和壶嘴与主体相匹配得很好，但是盖子，虽然看起来没有我们第一张图片那样拉伸，但仍然比其他方块小一点。解决这个问题的方法是进入 3D 面板，仅选择盖子多边形（首先按下"a"直到没有选择任何内容），转到属性选项卡中的材质，点击盖子材质，“选择”以选择所有多边形，然后转到 UV 窗口，将 UV 映射的多边形缩小一点。

然而，在我们的情况下，无论如何，我们都希望为这些物品制作完全不同的材料，所以在这一点上过于担心 UV 可能是错误的。

你的效果可能会有所不同。

# 导入材料

同时，我们可以利用 React VR 在材料方面提供的所有功能。不幸的是，MTL 文件并不总是具有可能的值。如果您使用的是现代材料，具有基本颜色、凹凸贴图或法线贴图、高度、镜面（光泽）或金属（类似于光泽）贴图，我发现您可能需要手动编辑 MTL 文件。

你可能会认为有这么多的计算机图形程序，我们不会到这一步。不幸的是，不同的渲染系统，特别是基于节点的系统，对于 OBJ 导出器来说太复杂，无法真正理解；因此，通常随 OBJ 文件一起使用的大多数 MTL 文件（材料）只有基本颜色作为纹理贴图。

如果您使用 Quixel 或 Substance Designer 等程序，大多数**基于物理的渲染**（**PBR**）材料由以下大部分纹理贴图（图像）组成，这也受到 OBJ 文件格式的支持：

+   **基本颜色**：这通常是材料的外观，几乎总是与大多数 CAD 系统一起导出到 OBJ（MTL）文件中作为`map_Ka`。

+   **漫反射贴图**：通常与基本颜色相同，它是物体的“漫反射”颜色。您可以将其实现为`map_Ka`。

+   **凹凸贴图**：凹凸贴图是“高度”信息，但不会物理变形多边形。它们看起来像是被雕刻的，但如果你仔细看，多边形实际上并没有位移。*这可能会在 VR 中引起问题*。你的一只眼睛会说*这是凹陷的*，但你的立体深度感知会说*不是*。然而，在适当的情况下，凹凸可以让事物看起来非常好。在 MTL 文件中写为*bump*。

+   **高度贴图**：与凹凸贴图非常相似，高度贴图通常会在物体表面上物理位移多边形。然而，在大多数网络渲染中，它只会位移建模的多边形，因此比离线渲染器要不太有用。（游戏引擎可以进行微位移。）

+   **法线贴图**：法线贴图是一种 RGB 表示，比高度或凹凸贴图更复杂，后者是灰度。法线贴图是 RGB 贴图，可以使多边形向*左*或*右*位移，而不仅仅是上下。现代游戏引擎会从高分辨率（数十万到数百万）模型计算法线贴图到低分辨率模型。它使得简单多边形的物体看起来像是由数百万多边形构建而成。它可能会或可能不会在物体上产生物理变形（取决于着色器）。它不受 OBJ/MTL 文件格式直接支持，但受到 WebGL 和 three.js 的支持，尽管实现留给读者自行完成。

+   **高光贴图**：这控制着物体的光泽度。通常是灰色贴图（没有颜色信息）。更具体地说，高光贴图控制着纹理的某个区域是否有光泽。这是 map_Ns。Map_Ks 也是高光贴图，但控制着高光的颜色。例如，可以用于汽车上的“幽灵漆”。

+   **光泽度**：与高光不完全相同，但经常被混淆。光泽度是指高光的亮度；它可以是宽泛但有光泽，如暗橡胶，也可以是紧致而有光泽，如糖苹果或铬。基本上是应用于高光贴图的*值*。通常与 PBR 一起使用，不受 OBJ/MTL 文件格式支持。

+   **粗糙度**：与高光和光泽度贴图非常相似，通常是替代或与前者一起使用。通常与 PBR 一起使用，不受 OBJ/MTL 文件格式支持。

+   反射率：一般来说，OBJ 文件格式用于离线渲染，进行射线追踪反射，近似模拟真实世界的工作方式。出于性能原因，WebGL 并不对所有内容进行射线追踪，但可以使用反射贴图模拟反射。在 OBJ 文件中，反射的程度是静态的；你无法直接制作斑驳的反射。这个贴图在 OBJ 文件中被编码为*refl*，但在 OBJ/MTL 文件格式中，React VR 不模拟它。

+   **透明度**：映射为*d*和*map_d*。（d 在原始 MTL 文件中代表“密度”）。这不是折射透明度；光线要么穿过要么不穿过。对于玻璃瓶之类的物体很有用，但 React VR 不使用。

+   **贴花**：这会在物体顶部应用模板，并且非常有用，可以避免重复的纹理外观，并在顶部添加文字。在 MTL 中，文件被编码为*decal*。这可能非常有用，并且在 React VR 中支持贴花。但是，我发现大多数建模者不会导出它，因此您可能需要手动编辑材质文件以包含贴花。这并不太糟糕，因为通常您的世界中的不同模型将具有不同的贴花（例如标志、污渍等）。

# 修复甲板板

现在我们已经学会了如何进行 UV 映射，让我们修复那些用来表示甲板板的立方体。在对基本的 React VR 对象进行纹理处理时，我们发现，立方体在所有六个面上都表示相同的纹理。因此，当我们制作一个薄的立方体，就像我们为基座的顶部和底部或甲板板所做的那样时，纹理贴图在侧面看起来“挤压”。红色箭头显示了挤压的纹理；这是因为我们有一个高度只有.1，宽度为 5 的盒子，而纹理是正方形的（双重红色箭头），所以看起来被挤压了。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/3744dade-d866-4648-a30c-814e04b1085a.png)

我们可以在 Blender 中用一个立方体来修复这个问题。我们还将添加我们下载的额外纹理贴图。

我有 Substance Designer，这是一个很棒的纹理工具；还有许多其他工具，比如 Quixel。它将根据您的设置输出不同的纹理贴图。您还可以使用各种软件包来烘焙纹理。WebGL 将允许您使用着色器，但这有些复杂。它通过 React Native 支持，但目前有点困难，因此让我们讨论不同材质值的个别纹理贴图的情况。通常在.obj 文件中，这将会分解为这样的情况（.obj 没有现代 GPU 着色器的概念）：

1.  在 Blender 中创建一个立方体，并调整其大小（在编辑模式中），使其比宽或高短得多。这将成为我们的甲板板。在我们的 VR 世界中，我们将其设置为 5x5x.1，因此让 Blender 立方体也设置为 5x5x.1。

1.  然后，我们粗略地对其进行纹理贴图，如下所示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/d1cebd8a-ccad-4a5c-b6e8-432306bf50a0.png)

1.  将其导出为 OBJ 并选择以下参数；重要的参数是-Z 向前，Y 向上（Y 向上！）和 Strip Path（否则，它将包括您的物理磁盘位置，显然无法从 Web 服务器中调用）：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/991b6521-104d-4a12-86c4-0b8828b62ee2.png)

一旦完成这些，我们将以困难但直接的方式来做，即修改甲板板的 MTL 文件，直接包含我们想要的纹理：

```jsx
# Blender MTL File: 'DeckPlate_v1.blend'
# Material Count: 1 newmtl Deck_Plate

Ns 96.078431
Ka 1.000000 1.000000 1.000000
Kd 0.640000 0.640000 0.640000
Ks 0.500000 0.500000 0.500000
Ke 0.000000 0.000000 0.000000
Ni 1.000000
d 1.000000
illum 2
map_Kd 1_New_Graph_Base_Color.jpg
bump -bm 0.01 1_New_Graph_Height.jpg # disp will be mostly ignored, unless you have a high-polygon cube
# disp -mm .1 5 1_New_Graph_Height.png
map_Ks 1_New_Graph_Metallic.jpg
```

位移纹理有点无用；当前的渲染引擎会应用位移贴图，但不会自动细分任何多边形以实现微位移。因此，你必须生成具有尽可能多多边形的几何体来进行位移。

如果你生成了那么多多边形，更好的方法是在建模程序中直接烘烤位移，并导出已经位移的多边形。这样无论如何都是相同数量的多边形，而且你有更多的控制。你也可以选择性地减少多边形数量，并仍然保留你的表面细节。

烘烤位移会显着增加场景中的顶点和多边形数量，所以这是一个权衡。在离线渲染器（非虚拟现实渲染）中使用位移贴图通常是为了减少多边形数量，但并不总是适用于虚拟现实。可能虚拟现实着色器会进行微位移和自适应细分，因为技术不断前进。

如果你得到一个刺眼的白色纹理，或者某些东西看起来不像你期望的那样，双重检查 node.js 控制台，并寻找 404，就像这样：

`Transforming modules 100.0% (557/557), done.`

`::1 - - [20/Sep/2017:21:57:12 +0000] "GET /static_assets/1_New_Graph_Metallic_Color.jpg HTTP/1.1" **404** 57 "http://localhost:8081/vr`

`/?hotreload" "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:57.0) Gecko/20100101 Firefox/57.0"`

这意味着你拼错了纹理名称。

然后，我们将使用面向对象的设计编码来修改我们创建的类，这将更新所有的甲板板！将平台调用更改为新的甲板板 OBJ 文件，而不是一个盒子。

# 完成的虚拟现实世界

你的完整代码应该是这样的：

```jsx
import React, {Component } from 'react';

import {
  AppRegistry,
  asset,
  AmbientLight,
  Box,
  DirectionalLight,
  Div,
  Model,
  Pano,
  Plane,
  Text,
  Vector,
  View,
  } from 'react-vr';

class Pedestal extends Component {
    render() {
        return (
          <View>
          <Box 
          dimWidth={.4}
          dimDepth={.4}
          dimHeight={.5}
          lit
          texture={asset('travertine_striata_vein_cut_honed_filled_Base_Color.jpg')}
          style={{
            transform: [ { translate: [ this.props.MyX, -1.4, this.props.MyZ] } ]
            }}
        />
          <Box 
          dimWidth={.5}
          dimDepth={.5}
          dimHeight={.1}
          lit
          texture={asset('travertine_striata_vein_cut_honed_filled_Base_Color.jpg')}
          style={{
            transform: [ { translate: [ this.props.MyX, -1.1, this.props.MyZ] } ]
            }}
        />
          <Box 
          dimWidth={.5}
          dimDepth={.5}
          dimHeight={.1}
          lit
          texture={asset('travertine_striata_vein_cut_honed_filled_Base_Color.jpg')}
          style={{
            transform: [ { translate: [ this.props.MyX, -1.7, this.props.MyZ] } ]
            }}
          />
     </View>
    )
     }
     }

         class Platform extends Component {
             render() {
                 return ( 
                    <Model
                    source={{
                        obj: asset('DeckPlate_v1.obj'),
                        mtl: asset('DeckPlate_v1_AllMats.mtl'),
                        }}
                        lit
                        style={{
                            transform: [ {
                            translate: [ this.props.MyX, -1.8, this.props.MyZ]
                        }] }}
                    /> 

        );
          }
         }

export default class SpaceGallery extends React.Component {
    render() {
        return (
          <View>
            <Pano source={asset('BabbageStation_v6_r5.jpg')}/>
            <AmbientLight

    intensity = {.3}

    />
    <DirectionalLight
    intensity = {.7}
    style={{
        transform:[{
            rotateZ: -45
        }]
    }}
         /> 
         <Platform MyX={ 0.0} MyZ={-5.1}/>
         <Platform MyX={ 0.0} MyZ={ 0.0}/>
         <Platform MyX={ 0.0} MyZ={ 5.1}/>
         <Platform MyX={ 5.1} MyZ={-5.1}/>
         <Platform MyX={ 5.1} MyZ={ 0.0}/>
         <Platform MyX={ 5.1} MyZ={ 5.1}/>
         <Platform MyX={-5.1} MyZ={-5.1}/>
         <Platform MyX={-5.1} MyZ={ 0.0}/>
         <Platform MyX={-5.1} MyZ={ 5.1}/>

         <Pedestal MyX={ 0.0} MyZ={-5.1}/>
         <Pedestal MyX={ 0.0} MyZ={ 0.0}/>
         <Pedestal MyX={ 0.0} MyZ={ 5.1}/>
         <Pedestal MyX={ 5.1} MyZ={-5.1}/>
         <Pedestal MyX={ 5.1} MyZ={ 0.0}/>
         <Pedestal MyX={ 5.1} MyZ={ 5.1}/>
         <Pedestal MyX={-5.1} MyZ={-5.1}/>
         <Pedestal MyX={-5.1} MyZ={ 0.0}/>
         <Pedestal MyX={-5.1} MyZ={ 5.1}/>

         <Model
            source={{
                obj: asset('teapot2.obj'),
                mtl: asset('teapot2.mtl'),
                }}
                lit
                style={{
                    transform: [{ translate: [ -5.1, -1, -5.1 ] }]
                    }}
            />
            <Model
            source={{
                obj: asset('Teapot2_NotSmooth.obj'),
                mtl: asset('teapot2.mtl'),
                }}
                lit
                style={{
                    transform: [{ translate: [ -5.1, -1, 0 ] },
                    { rotateY: -30 },
                    { scale: 0.5} ]

                    }}
            />

            <Model
            source={{
                obj: asset('Chap6_Teapot_V2.obj'),
                mtl: asset('Chap6_Teapot_V2.mtl'),
                }}
                lit
                style={{
                    transform: [{ translate: [ -5.1, -1, 5.2 ] },
                    { rotateY: -30 },
                    { scale: 0.5} ]
                }}
            />

            <Model
            source={{
                obj: asset('Chap6_Teapot_V5_SpoutDone.obj'),
                mtl: asset('Chap6_Teapot_V5_SpoutDone.mtl'),
                }}
                lit
                style={{
                    transform: [{ translate: [ 5.1, -1, 0 ] },
                    { rotateY: -30 },
                    { rotateX: 45 },
                    { scale: 0.5} ]

                    }}
            />

            <Model
            source={{
                obj: asset('Chap6_Teapot_V5_SpoutDone.obj'),
                mtl: asset('Chap6_Teapot_V5_SpoutDone.mtl'),
                }}
                lit
                style={{
                    transform: [{ translate: [ 5.1, -1, 5.1 ] },
                    { rotateY: 46 },
                    { scale: 0.5} ]

                    }}
            />
        <Text
            style={{
                backgroundColor: '#777879',
                fontSize: 0.1,
                fontWeight: '400',
                layoutOrigin: [0.0, 0.5],
                paddingLeft: 0.2,
                paddingRight: 0.2,
                textAlign: 'center',
                textAlignVertical: 'center',
                transform: [ 
                    {translate: [-5.2, -1.4, -4.6] }]
                    }}>
            Utah teapot
        </Text>
        <Text
            style={{
                backgroundColor: '#777879',
                fontSize: 0.1,
                fontWeight: '400',
                layoutOrigin: [0.0, 0.5],
                paddingLeft: 0.2,
                paddingRight: 0.2,
                textAlign: 'center',
                textAlignVertical: 'center',
                transform: [ 
                    {translate: [0, -1.3, -4.6] }]
                    }}>
            One Tri
        </Text>

        &amp;amp;lt;Model
        lit
        source={{
            obj: asset('OneTriSkinnyWUVTexture_1.obj'),
            mtl: asset('OneTriSkinnyWUVTexture_1.mtl'),
            }}
            style={{
                transform: [
                    { translate: [ -0, -.8, -5.2 ] },
                    { rotateY: 10 },
                    { scale: .2 },
]
                }}
        />

         <Text
         style={{
             backgroundColor: '#777879',
             fontSize: 0.2,
             fontWeight: '400',
             layoutOrigin: [0.0, 0.5],
             paddingLeft: 0.2,
             paddingRight: 0.2,
             textAlign: 'center',
             textAlignVertical: 'center',
             transform: [ 
                {translate: [0, 1, -6] }]
         }}>
    Space Gallery
  </Text>
</View>
);
    }
};

AppRegistry.registerComponent('SpaceGallery', () => SpaceGallery);
```

这是一个很多要输入的内容，也是很多 UV 建模。你可以在这里下载所有这些文件：[`bit.ly/VR_Chap7`](http://bit.ly/VR_Chap7)

在上述代码中，我使用了这个：

`<Platform MyX='0' MyZ='-5.1'/>`

这样做是可以的，但更正确的做法是这样的：

`<Platform MyX={0} MyZ={-5.1}/>`

如果你懂 JSX 和 React，这将是一个明显的错误，但不是每个人都会注意到它（老实说，作为 C++程序员，我一开始也没有注意到）。花括号`{}`内的任何内容都是*代码*，而任何带引号的都是文本。文档中说：

*Props - 组件可以接受参数，例如* `<Greeting name='Rexxar'/>`*中的名称。这些参数称为属性或 props，并通过 this.props 变量访问。例如，从这个例子中，名称可以作为`{this.props.name}`访问。您可以在组件、props 和状态下阅读更多关于这种交互的信息。

关于参数的提及仅适用于文本属性。对于数字属性，使用引号语法如`'0.5*'*`似乎可以工作，但会产生奇怪的后果。我们将在第十一章中看到更多内容，*走进野生*，但基本上，对于数字变量，您*应该*使用`{0.5}`（大括号）。

# 总结

在本章中，我们学习了如何使用 Blender 进行多边形建模，以及如何覆盖纹理分配并将纹理包裹在模型周围。我们学会了制作可以使您的世界看起来更真实的纹理。

然而，世界仍然是静态的。在下一章中，您将学习如何使事物移动，真正让您的世界生动起来。


# 第八章：给你的世界注入生命

在上一章中，我们通过材料使物体看起来更真实。我们知道这对于 VR 来说并不是完全必要的，正如我们在第一章中讨论的那样，*虚拟现实到底是什么*，但这确实有所帮助。现在，我们将学习如何通过使它们移动来使事物看起来真实。这样做有两个好处：移动的东西看起来更有生命力，而且还有助于视差深度感知。

React VR 具有许多 API，这将使包含流畅和自然的动画变得非常容易。在大多数传统 CGI 中，使动画流畅并不容易；您必须慢慢开始运动，加速到速度，然后轻轻地减速，否则运动看起来是假的。

我们将在本章中涵盖以下主题：

+   用于动画化对象的`Animated` API

+   一次性动画

+   连续动画

+   生命周期事件，如`componentDidMount()`

+   如何将声音注入到世界中

运动和声音在使世界看起来活跃方面起到了很大作用。让我们来做吧！

# 动画 API

React 和 React VR 使这变得容易，因为动画 API 具有许多动画类型，使这变得简单易懂，无需进行数学计算或使用关键帧，就像传统动画一样。您可以逐渐增加事物，弹跳和停顿。这些属性是 spring，decay 和 timing；有关这些的更多详细信息，请参阅在线文档[`bit.ly/ReactAnims`](http://bit.ly/ReactAnims)。

动画是可以的，但我们需要知道我们要去哪里。为此，动画 API 具有两种值类型：标量（单个值）和矢量的 ValueXY。您可能会想知道为什么在这种情况下，矢量只是*X*和*Y* - ValueXY 是用于 UI 元素的，它们的性质是平的。如果您需要动画化 X，Y 和 Z 位置，您将使用三个标量。

首先，我们将创建一个旋转的动画茶壶。这将特别有助于了解我们的纹理映射是如何工作的。如果您一直在跟着代码，您的`SpaceGallery`应用程序应该已经具备我们开始编写本章所需的大部分内容。如果没有，您可以下载源文件开始：[`bit.ly/VR_Chap7`](http://bit.ly/VR_Chap7)。如果您真的不想输入所有这些，我把最终文件放在了：[`bit.ly/VR_Chap8`](http://bit.ly/VR_Chap8)。

假设你已经下载或完成了上一章，从第七章中拿出`index.vr.js`，*与（虚拟）茶壶一起坐下*，在文件的顶部但在`import`语句下面输入以下新类`TurningPot()`（请注意，我们仍然在`SpaceGallery`应用程序中）。

```jsx
 class TurningPot extends React.Component {
    constructor(props) {
      super(props);
      this.state = {
        yRotation: new Animated.Value(0),
      };
    }
```

这设置了我们的动画值/变量—`yRotation`。我们已经将它创建为一个标量，这是可以的，因为我们将把它映射到`rotateY`。

不要忘记`import`动画关键字。

接下来，我们将使用一个叫做`componentDidMount`的生命周期重写。生命周期重写是在加载和创建（渲染）VR 世界期间特定时间调用的事件；在这种情况下，`componentDidMount`函数在挂载后被调用（根据事件名称中“Did”片段的含义）。挂载意味着对象已加载、可用，并在 three.js 内创建；换句话说，它在世界中。`componentWillMount`函数在该组件即将被挂载但尚不存在时被调用；我们不使用这个函数，因为我们希望对象在实际可见对象时移动，尽管它对加载对象、初始化状态等非常有用。

请注意，我们还没有完成声明，所以最终的闭合`{`括号还没有出现：

```jsx
   componentDidMount() {
        Animated.timing( 
          this.state.yRotation, // Animate variable `yRotation`
          {
            duration: 10000,    // Time
            toValue: 360,       // Spin around a full circle
          }
        ).start();              // Start the animation
      } 
```

`componentDidMount()`是一个重要的对象生命周期 API 调用，用于做像我们正在做的事情；开始动画。

这个事件很可能会在浏览器加载完所有内容之前发生，所以你可能会错过实际的开始。如果这是一个问题，你可以重载一些其他方法来确保它在正确的时间触发，或者引入一个小的延迟。

# 飞行的茶壶

现在是重要的事情，渲染本身。使用`Animated.View`关键字编写以下方法：

```jsx
    render() {
      return (
        <Animated.View // Base: Image, Text, View
          style={{
            flex: 1,
            width: 1,
            height: 1,
            transform: [ 
              {rotateY: this.state.yRotation}, // Map yRotation to rotateY
            ]
          }}
          >
          <Model
          source={{
              obj: asset('teapot2.obj'),
              mtl: asset('teapot2_Mats.mtl'),
              }}
              lit
              style={{
                  transform: [{ translate: [0, -0.7, -5.1 ] }]
                  }}
          />
      </Animated.View>
      );
    }

  }
```

现在保存这个文件。如果你在 URL [`localhost:8081/vr/?hotreload`](http://localhost:8081/vr/?hotreload) 中使用了`?hotreload`，并且输入了一切正确，你会看到茶壶在你面前自动旋转。否则，点击浏览器中的“刷新”按钮。

等等，什么？刚刚发生了什么？为什么壶在飞！

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/3d7472ee-4acd-416d-a9f8-be46ea8c09c7.png)

茶壶围绕*我们*，即`<view>`的中心旋转，而不是围绕它自己的轴旋转。为什么会这样？记住翻译顺序很重要。在这种情况下，我们有一个单独的平移和旋转：

```jsx
 render() {
      return (
        <Animated.View 
...
          {rotateY: this.state.yRotation}, // Map yRotation to rotateY
...
          <Model
...
                  transform: [{ translate: [0, -0.7, -5.1 ] }]
...
      </Animated.View>
      );
```

这里发生的是视图在旋转，然后模型在变换。我们希望以相反的顺序进行。一个解决方案是将模型保持在原地，并将`render()`循环更改为以下内容（注意粗体部分）：

```jsx
    render() {
      return (
        <Animated.View // Base: Image, Text, View
          style={{
            transform: [ 
 {translate: [0, -0.7, -5.1 ] },
 {rotateY: this.state.yRotation}, // Map `yRotation' to rotateY 
            ]
          }}
          >
          <Model
          source={{
              obj: asset('teapot2.obj'),
              mtl: asset('teapot2_Mats.mtl'),
              }}
              lit
              // we comment this out because we translate the view above
 // style={{
              // transform: [{ translate: [0, -0.7, -5.1 ] }]
              // }}
          />
      </Animated.View>
      );
    }

```

# 一旦旋转，永远

当我们保存这个文件并在 VR 浏览器中再次查看它时，我们会看到壶转动一次。请注意，我们可能看不到启动，并且当壶完成转动时，它会优雅地完成，而不是计算机动画的“猛然停止”：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/73217953-051c-4706-a152-02c25c5e7148.png)

这太棒了，但是壶转动然后停止了。我们可能希望它继续转动。所以让我们这样做！

修改组件创建以执行以下操作（是的，我们有点摆脱了所有酷炫的 Animate 关键字）：

```jsx
  class TurningPot extends React.Component {
    constructor(props) {
      super(props);
      this.state = {yRotation: 0};
      this.lastUpdate = Date.now();
      this.rotate = this.rotate.bind(this); 
    }
```

好的，在这部分，注意几件事。我们使用的变量称为`yRotation`；我们还使用了单词`rotate`，这实际上是一个新函数：

```jsx
    rotate() { //custom function, called when it is time to rotate
        const now = Date.now();
        const delta = now - this.lastUpdate;
        this.lastUpdate = now;
        console.log("Spinning the pot");

        //note: the 20 is the rotation speed; bad form to
        //hard code it- this is for instructional purposes only
        this.setState({yRotation: this.state.yRotation + delta / 20} );
        //requestAnimationFrame calls the routine specified, not a variable
        this.frameHandle = requestAnimationFrame(this.rotate);
      } 
```

我们还需要改变对象的加载/卸载例程，既开始旋转，也结束定时器回调：

```jsx
   componentDidMount() { //do the first rotation
        this.rotate();
    } 
    componentWillUnmount() { //Important clean up functions
        if (this.frameHandle) {
          cancelAnimationFrame(this.frameHandle);
          this.frameHandle = null;
        }
      } 
```

`<View>`本身不会改变；它只是像驱动函数一样旋转对象；这一次，我们使用一个名为`render()`的自定义函数来驱动它。

检查经过的时间非常重要，因为不同的平台会有不同的帧率，取决于硬件、GPU 和许多其他因素。为了确保所有类型的计算机和移动设备看到壶以相同的速度旋转，我们使用`now`变量并计算`now`和`this.lastUpdate`之间的差值，得到一个增量时间。我们使用增量来确定实际的旋转速度。

# 最终代码

现在我们已经解决了所有这些问题，我们有一个良好渲染的旋转茶壶。在编码过程中，我们还修复了一个糟糕的编程错误；壶的速度被硬编码为 20 左右。从编程的最大化来看，最好是将其作为`const`，“永远不要将常量嵌入程序主体中”：

```jsx
import React, {Component } from 'react';

import {
  Animated,
  AppRegistry,
  asset,
  AmbientLight,
  Box,
  DirectionalLight,
  Div,
  Model,
  Pano,
  Plane,
  Text,
  Vector,
  View,
  } from 'react-vr';

  class TurningPot extends React.Component {
    constructor(props) {
      super(props);
      this.state = {yRotation: 0};
      this.lastUpdate = Date.now();
      this.rotate = this.rotate.bind(this); 
    }
    rotate() { //custom function, called when it is time to rotate
        const now = Date.now();
        const delta = now - this.lastUpdate;
        const potSpeed = 20;
        this.lastUpdate = now;
        this.setState({yRotation: this.state.yRotation + delta / potSpeed} );
        //requestAnimationFrame calls the routine specified, not a variable
        this.frameHandle = requestAnimationFrame(this.rotate);
      } 
    componentDidMount() { //do the first rotation
        this.rotate();
    } 
    componentWillUnmount() { //Important clean up functions
        if (this.frameHandle) {
          cancelAnimationFrame(this.frameHandle);
          this.frameHandle = null;
        }
      } 
    render() {
      return (
        <Animated.View // Base: Image, Text, View
          style={{
            transform: [ // `transform` is an ordered array
              {translate: [0, -0.5, -5.1 ] },
              {rotateY: this.state.yRotation}, // Map `yRotation' to rotateY 
            ]
          }}
          >
          <Model
          source={{
              obj: asset('teapot2.obj'),
              mtl: asset('teapot2_Mats.mtl'),
              }}
              lit
              //style={{
              // transform: [{ translate: [0, -0.7, -5.1 ] }]
              // }}
          />
      </Animated.View>
      );
    }

  }

class Pedestal extends Component {
    render() {
        return (
          <View>
          <Box 
          dimWidth={.4}
          dimDepth={.4}
          dimHeight={.5}
          lit
          texture={asset('travertine_striata_vein_cut_honed_filled_Base_Color.jpg')}
          style={{
            transform: [ { translate: [ this.props.MyX, -1.4, this.props.MyZ] } ]
            }}
        />
          <Box 
          dimWidth={.5}
          dimDepth={.5}
          dimHeight={.1}
          lit
          texture={asset('travertine_striata_vein_cut_honed_filled_Base_Color.jpg')}
          style={{
            transform: [ { translate: [ this.props.MyX, -1.1, this.props.MyZ] } ]
            }}
        />
          <Box 
          dimWidth={.5}
          dimDepth={.5}
          dimHeight={.1}
          lit
          texture={asset('travertine_striata_vein_cut_honed_filled_Base_Color.jpg')}
          style={{
            transform: [ { translate: [ this.props.MyX, -1.7, this.props.MyZ] } ]
            }}
          />
     </View>
    )
     }
     }

         class Platform extends Component {
             render() {
                 return ( 
                    <Model
                    source={{
                        obj: asset('DeckPlate_v1.obj'),
                        mtl: asset('DeckPlate_v1_AllMats.mtl'),
                        }}
                        lit
                        style={{
                            transform: [ {
                            translate: [ this.props.MyX, -1.8, this.props.MyZ]
                        }] }}
                    /> 

    );
          }
         }

export default class SpaceGallery extends React.Component {
    render() {
        return (
          <View>
            <Pano source={asset('BabbageStation_v6_r5.jpg')}/>
            <AmbientLight

    intensity = {.3}

    />
    <DirectionalLight
    intensity = {.7}
    style={{
        transform:[{
            rotateZ: -45
        }]
    }}
         /> 
         <Platform MyX='0' MyZ='-5.1'/>
         <Platform MyX='0' MyZ='0'/>
         <Platform MyX='0' MyZ='5.1'/>
         <Platform MyX='5.1' MyZ='-5.1'/>
         <Platform MyX='5.1' MyZ='0'/>
         <Platform MyX='5.1' MyZ='5.1'/>
         <Platform MyX='-5.1' MyZ='-5.1'/>
         <Platform MyX='-5.1' MyZ='0'/>
         <Platform MyX='-5.1' MyZ='5.1'/>

         <Pedestal MyX='0' MyZ='-5.1'/>
         <Pedestal MyX='0' MyZ='5.1'/>
         <Pedestal MyX='5.1' MyZ='-5.1'/>

         <Pedestal MyX='5.1' MyZ='5.1'/>
         <Pedestal MyX='-5.1' MyZ='-5.1'/>
         <Pedestal MyX='-5.1' MyZ='0'/>
         <Pedestal MyX='-5.1' MyZ='5.1'/>

         <Model
            source={{
                obj: asset('teapot2.obj'),
                mtl: asset('teapot2_Mats.mtl'),
                }}
                lit
                style={{
                    transform: [{ translate: [ -5.1, -1, -5.1 ] }]
                    }}
            />

        <Text
            style={{
                backgroundColor: '#777879',
                fontSize: 0.1,
                fontWeight: '400',
                layoutOrigin: [0.0, 0.5],
                paddingLeft: 0.2,
                paddingRight: 0.2,
                textAlign: 'center',
                textAlignVertical: 'center',
                transform: [ 
                    {translate: [-5.2, -1.4, -4.6] }]
                    }}>
            Utah Teapot
        </Text>
        <Text
            style={{
                backgroundColor: '#777879',
                fontSize: 0.1,
                fontWeight: '400',
                layoutOrigin: [0.0, 0.5],
                paddingLeft: 0.2,
                paddingRight: 0.2,
                textAlign: 'center',
                textAlignVertical: 'center',
                transform: [ 
                    {translate: [0, -1.3, -4.6] }]
                    }}>
            Spinning Pot
        </Text> 

         <Text
         style={{
             backgroundColor: '#777879',
             fontSize: 0.2,
             fontWeight: '400',
             layoutOrigin: [0.0, 0.5],
             paddingLeft: 0.2,
             paddingRight: 0.2,
             textAlign: 'center',
             textAlignVertical: 'center',
             transform: [ 
                {translate: [0, 1, -6] }]
         }}>
    Space Gallery
  </Text>
  <TurningPot/>

</View>
);
    }
};

AppRegistry.registerComponent('SpaceGallery', () => SpaceGallery);
```

# 声音

VR 中的声音实际上非常复杂。我们的耳朵听到的声音与别人的耳朵听到的声音不同。许多 VR 系统都采用简单的“如果在右边，对我的右耳来说更响”的立体声定位，但这并不是实际声音工作的方式。对于 VR 和它们所需的高帧率，就像我们的光照效果跳过完整的光线追踪一样，这种声音定位是可以的。

更复杂的 VR 系统将使用一种叫做**头部相关传递函数**（HRTF）的东西。HRTF 是指当你转动头部时声音如何变化。换句话说，声音如何根据*你的*头部“传递”？每个人都有自己的 HRTF；它考虑了他们的耳朵形状、头部的骨密度以及鼻子和口腔的大小和形状。我们的耳朵，再加上我们的成长方式，在这个过程中我们训练我们的大脑，让我们能够用 HRTF 做出惊人的事情。例如，人类可以通过只从两个点听到声音来在三维空间中定位某物。这就像只用一只眼睛就能看立体影像一样！HRTF 给了我们视觉所不能给的；它给了我们对周围发生的事情的空间意识，即使我们看不见。

使用 HRTF 进行虚拟现实需要每个在虚拟世界中听到声音的人都将他们的 HRTF 加载到 VR 世界的声音系统中。此外，这个 HRTF 必须在无反射室（墙壁上覆盖有泡沫衬里以消除回声的房间）中进行测量。这显然并不常见。

因此，大多数 VR 声音只是左右平移。

这是 VR 可以取得重大突破的领域。声音非常重要，让我们能够在三维空间中感知事物；这是沉浸的重要方面。许多人认为立体声平移就是 3D；这只是声音在一个耳朵比另一个耳朵更响。在音频系统中，这是*平衡*旋钮。在耳机中，听起来会很奇怪，但实际上并没有定位声音。在现实世界中，你的右耳会在左耳之前（或之后）听到声音，当你转动头部时，你的耳朵的曲线会改变这种延迟，你的大脑会说“啊，声音就在*那里*”。

没有 HRTF 测量，立体声平移是唯一能做的事情，但 HRTF 要好得多。好消息是，现在音频硬件和计算能力非常强大，有了 HRTF 或合理的软件来模拟平均 HRTF，更复杂的声音处理是可能的。期待未来在这个领域的进展。

React VR 的强大再次拯救了我们。我们不必担心这一切；我们只需要把声音放在我们的世界里。

说真的，不要因为所有这些谈话而感到沮丧，只要意识到声音很难（和图形渲染一样重要），但在这一点上，你真正需要做的就是获得一个好的单声道（不是立体声）声音，并在场景文件中描述它。

这就是 React VR 的全部意义。描述你想要的东西；你不需要告诉人们如何做。不过，你需要知道幕后发生了什么。

# 在我们的世界中放置声音

现在，让我们真的发出一些声音。[Freesound.com](http://Freesound.com)是一个获取免费游戏声音的好地方。那里的大部分声音都需要归属。给那些帮助建立你的世界的人以信用是正确的做法。去这个网站下载几个你喜欢的声音文件。我在`freesound.com`找到的一些是这些：

+   通过 Geodylabs 煮沸的锅水（[`bit.ly/BoilingPot1`](http://bit.ly/BoilingPot1)）

+   通过 dobroide（[`bit.ly/Boiling2`](http://bit.ly/Boiling2)）煮沸的水

+   通过 abrez（[`bit.ly/Boiling3`](http://bit.ly/Boiling3)）煮沸的水

我以`.mp3`文件格式下载了这些；这应该是相当跨平台的。把它们复制到`static_assets`目录中一个名为`sounds`的新文件夹中。我只在实际世界中使用了其中一个，但你可以尝试其他的。有时你不知道它是否有效，直到你在世界中听到它。

声音是一个必须附加到视图、图像或文本的节点——React VR 的唯一组件。你可能想把它附加到一个盒子、模型或其他东西上；只需用`<View>`包裹对象，并把`sound`组件放在其中，如下所示：

```jsx
 <View>
    <Model
       source={{
        obj: asset('teapot2.obj'),
        mtl: asset('teapot2_Mats.mtl'),
        }}
        lit
        style={{
            transform: [{ translate: [ -5.1, -1, -5.1 ] }]
            }}
    >
    </Model>
 <Sound 
        loop
        source={{wav: asset('sounds/211491__abrez__boiling-water.mp3') }}
        />
    </View>
```

有一件有趣的事情是，声音并不是来自我们的茶壶所在的地方（当你第一次看到这个世界时，它在左上角）。为什么呢？看看前面的代码；我们只是简单地在`Model`周围包裹了`View`标签；所以它的变换与声音不同。

有些声音比其他的效果更好；你需要进行实验或录制自己的声音。修复变换留给读者作为练习。（实际上，这很容易，但确保你不要把变换粘贴为子 XML 元素。）正确的代码是这样的：

```jsx
<View
    style={{
 transform: [{ translate: [-5.1, -1, -5.1] }]
 }}
>
    <Model
        source={{
            obj: asset('teapot2.obj'),
            mtl: asset('teapot2_Mats.mtl'),
        }}
        lit
    >
    </Model>
    <Sound
        loop
        source={{ wav: asset('sounds/211491__abrez__boiling-water.mp3') }} />
</View>
```

# 总结

我们学会了如何通过程序性地改变对象的位置和使用更高级的方法来构建动画，比如使用定时器和动画 API。我们明显看到了如果使用错误的`<View>`来进行动画会发生什么，并开发了一种让对象永远动画的方法。Energizer 兔会感到自豪。我们还添加了声音，这对虚拟世界来说是非常重要的事情。

定时器可以做很多事情；我强烈建议你研究在线文档并进行实验！

到目前为止，我们一直在 React VR 范围内。有时，有些事情是 React 不允许我们做的。在下一章中，我们将转向原生（即原生 React）！

有人能把那个沸腾的锅炉关掉吗？


# 第九章：自己动手-本机模块和 Three.js

React VR 使得在不需要了解 three.js 的情况下进行 VR 变得容易。three.js 是帮助实现 WebGL 的包装类，WebGL 本身是一种本机 OpenGL 渲染库的形式。

React VR 相当包容，但像所有 API 一样，它无法做到一切。幸运的是，React VR 预料到了这一点；如果 React VR 不支持某个功能并且您需要它，您可以自己构建该功能。

在本章中，您将涵盖以下主题：

+   从 React VR 代码内部使用 three.js

+   基本的 three.js 程序代码

+   设置 three.js 以与我们的 React VR 组件进行交互

+   使用 three.js 在视觉上执行低级别的操作

# 本机模块和视图

也许您确实了解 three.js 并且需要使用它。**React Native 模块**是您的代码可以直接包含原始的 three.js 编程。如果您需要以编程方式创建本机的 three.js 对象，修改材质属性，或者使用 React VR 没有直接暴露的其他 three.js 代码，这将非常有用。

您可能有一些执行业务逻辑的 JavaScript 代码，并且不想或无法将其重写为 React VR 组件。您可能需要从 React VR 访问 three.js 或 WebVR 组件。您可能需要构建一个具有多个线程的高性能数据库查询，以便主渲染循环不会变慢。所有这些都是可能的，React Native 可以实现。

这是一个相当高级的主题，通常不需要编写引人入胜、有效的 WebVR 演示；但是，了解 React VR 和 React 是如此可扩展，这仍然是令人难以置信的。

# 制作一个 three.js 立方体演示

首先，让我们看一个简单的盒子演示。让我们从一个新生成的站点开始。转到您的 node.js 命令行界面，并关闭任何正在运行的*npm start*窗口，并通过发出以下命令重新创建一个新的、新鲜的站点：

```jsx
f:\ReactVR>React-vr init GoingNative
```

第一个任务是转到`vr`文件夹并编辑`client.js`。到目前为止，我们还没有必须编辑此文件；它包含样板 React VR 代码。今天，我们将编辑它，因为我们不只是在做样板。以下代码中的粗体行是我们将添加到`client.js`中的行：

```jsx
// Auto-generated content.
// This file contains the boilerplate to set up your React app.
// If you want to modify your application, start in "index.vr.js"

// Auto-generated content.
import {VRInstance} from 'react-vr-web';
import {Module} from 'react-vr-web';
import * as THREE from 'three';

function init(bundle, parent, options) {
const scene = new THREE.Scene();
const cubeModule = new CubeModule();
const vr = new VRInstance(bundle, 'GoingNative', parent, {
 // Add custom options here
 cursorVisibility: 'visible',
 nativeModules: [ cubeModule ],
 scene: scene,
 ...options,
 });

 const cube = new THREE.Mesh(
 new THREE.BoxGeometry(1, 1, 1),
 new THREE.MeshBasicMaterial()
 );
 cube.position.z = -4;
 scene.add(cube);
 cubeModule.init(cube);

 vr.render = function(timestamp) {
 // Any custom behavior you want to perform on each frame goes here
//animate the cube
 const seconds = timestamp / 1000;
 cube.position.x = 0 + (1 * (Math.cos(seconds)));
 cube.position.y = 0.2 + (1 * Math.abs(Math.sin(seconds)));
 };
 // Begin the animation loop
 vr.start();
 return vr;
};

window.ReactVR = {init};
```

我们还需要创建 CubeModule 对象。如果它变得复杂，您可以将其放在一个单独的文件中。现在，我们可以将其添加到 client.js 的底部：

```jsx
export default class CubeModule extends Module {
  constructor() {
    super('CubeModule');
  }
  init(cube) {
    this.cube = cube;
  }
  changeCubeColor(color) {
    this.cube.material.color = new THREE.Color(color);
  }
}
```

不需要做其他更改。现在你会看到一个弹跳的纯白色立方体。我们没有改变 index.vr.js，所以它仍然显示着 hello 文本。这表明 React VR 和原生代码，在这种情况下是 three.js，同时运行。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/716e2f93-e93a-4c21-be6e-c24d931de8b0.png)

好的，我们放了一个弹跳的立方体。这段代码的好处是它展示了一些高度的集成；然而，这是以一种非常干净的方式完成的。例如，这一行代码——`const scene = new THREE.Scene()`——给你一个可访问的 three.js 场景，所以我们可以用 three.js 做任何我们想做的事情，然而，所有的 React VR 关键词都能正常工作，因为它将使用现有的场景。你不需要从一边导入/导出场景到另一边并维护句柄/指针。这一切都是干净的、声明式的，就像 React VR 应该是的那样。我们在正常的 React VR 语法之外创建了常规场景和对象。

在我们之前的动画中，我们改变了`index.vr.js`。在这种情况下，对于 three.js 对象，我们直接在`client.js`的这部分进行更改；就在代码生成器建议的地方：

`vr.render = function(timestamp) {`

// 在这里执行每帧的自定义行为

# 使原生代码与 React VR 交互

如果我们继续让这个对象与世界其他部分进行交互，你就能真正看到 React VR 的强大之处。为了做到这一点，我们需要改变`index.vr.js`。我们还将第一次使用`VrButton`。

注意 `VrButton` 中的拼写。我在这个问题上纠结了一段时间。我自然地会输入"VR"而不是"Vr"，但它确实遵循了 React VR 的大小写规范。

线索是，在控制台中你会看到 `VRButton is not defined`，这通常意味着你在`import`语句中忘记了它。在这种特殊情况下，你会看到 React 的一个奇怪之处；你可以输入 `import { YoMomma } from 'react-vr';` 而不会出错；试试看。React VR 显然太害怕回答 YoMomma 了。

当我们点击按钮时，沉浸感的一个重要部分是它们发出的点击声音。任何将手机调成静音且没有震动的人都知道我的意思；你按一下手机，什么声音都没有，以为它坏了。所以，让我们去[FreeSound.org](http://FreeSound.org)下载一些点击声音。

我找到了 *IanStarGem* 制作的 *Switch Flip #1*，并且它是根据知识共享许可证授权的。所以，让我们把它放在 `static_assets` 文件夹中：

1.  首先，我们需要包括我们的`NativeModule`的声明；通常，你会在`import`指令之后的顶部这样做，如下所示：

```jsx
// Native Module defined in vr/client.js const  cubeModule  =  NativeModules.CubeModule;
```

请注意，你可以将你的对象称为`CubeModule`，但你可能会在实现与定义之间感到困惑。这样打字会更容易。JavaScript 可能会很宽容。这可能是好事，也可能不是。

1.  无论如何，在`index.vr.js`中，我们需要设置我们的新初始状态，否则会出现黑屏和错误：

```jsx
class GoingNative extends React.Component {
 constructor(props) {
 super(props);
 this.state = { btnColor: 'white', cubeColor: 'yellow' };
 cubeModule.changeCubeColor(this.state.cubeColor);
 }
```

1.  在同一个文件中，在`render()`语句的下面，将`<View>`的定义更改为以下内容（注意我们仍然在视图中，并且尚未关闭它）：

```jsx
      <View
        style={{
          transform:[{translate: [0, 0, -3]}],
          layoutOrigin: [0.5, 0, 0],
          alignItems: 'center',
        }}>
```

我们在这里稍微作弊，也就是说，将视图向后移动，这样物体就在我们面前。

由于 React VR 不是 CAD 系统，你无法进行可视化编辑，因此在编写代码时必须考虑物品的定位。

对于一些复杂的情况，布局图纸也可能有所帮助。

1.  在`<Pano>`语句之后，并在`</View>`结束标记之前，插入以下内容（更改模板生成的 Text 语句）：

```jsx
  <VrButton
    style={{
      backgroundColor: this.state.btnColor,
      borderRadius: 0.05,
      margin: 0.05,
    }}
    onEnter={() => { this.setState({ btnColor: this.state.cubeColor }) }}
    onExit={() => { this.setState({ btnColor: 'white' }) }}
    onClick={() => {
      let hexColor = Math.floor(Math.random() * 0xffffff).toString(16);
      // Ensure we always have 6 digits by padding with leading zeros.
      hexColor = '#' + (('000000' + hexColor).slice(-6));
      this.setState({ cubeColor: hexColor, btnColor: hexColor });
      // Asynchronous call to custom native module; sends the new color.
      cubeModule.changeCubeColor(hexColor);
    }}
    onClickSound={asset('freesound__278205__ianstargem__switch-flip-1.wav')}
  >
    <Text style={{
      fontSize: 0.15,
      paddingTop: 0.025,
      paddingBottom: 0.025,
      paddingLeft: 0.05,
      paddingRight: 0.05,
      textAlign: 'center',
      textAlignVertical: 'center',
    }}>
      button
    </Text>
  </VrButton>
```

当你刷新浏览器时，立方体仍然会四处弹跳，但你可以点击按钮看到立方体变色。当你将鼠标或控制器的光标悬停在按钮上（显示为`<Text>`组件），你会看到按钮变成立方体的当前颜色。

一个很好的做法是在静态变量中预先生成立方体的新颜色（这样它不会像 let 一样消失），然后使鼠标悬停的颜色变成那种颜色。

白色背景上的默认颜色也应该修复。

继续尝试吧；这是一个有趣的练习。

当我们播放声音时，在浏览器的控制台中会出现以下错误：

```jsx
VrSoundEffects: must load sound before playing ../static_assets/freesound__278205__ianstargem__switch-flip-1.wav
```

你可能还会看到以下错误：

```jsx
Failed to fetch audio: ../static_assets/freesound__278205__ianstargem__switch-flip-1.wav
The buffer passed to decodeAudioData contains invalid content which cannot be decoded successfully.
```

1.  解决这个问题的方法是确保你的浏览器有正确的音频格式。正确的格式有：

1.  音频文件需要是单声道；这样它们才能被转换成 3D 空间。

1.  音频文件需要是 48 千赫或更低。这似乎在 Firefox 55 和 59 之间有所改变，但尽可能通用是最安全的。

1.  如果你的文件格式错误，或者你听不到声音，有两种可能的解决方法：

1.  你可以使用 Audacity 或其他音频编辑工具来修复这些问题。

1.  你可以让我来修复它！我已经在书中的文件中下载并转换了文件。但是，如果你不尝试修复，你就学不到。你可以只下载 48 千赫单声道文件，避免转换，但实际上这些相当罕见。使用 Audacity 转换声音很容易和免费，你只需要学一点这个程序就可以了。在 VR 按钮内，我们需要做的就是加载修改后的单声道声音文件：

```jsx
onClickSound={asset('freesound__278205__ianstargem__switch-flip-48kmono.wav')}
```

我在早期的部分提到过这一点，但值得重申的是，如果您遇到无法解释的错误，并且大声说“我知道文件在那里并且可以播放！”，请尝试检查声音文件的格式。

# 总结到目前为止的代码

我们添加了很多代码；让我们总结一下我们的进展。React VR 有时可能会令人困惑，因为它是 JavaScript 和 XML“ish”代码（JSX）的混合，所以这里是完整的`index.vr.js`：

```jsx
import React from 'react';
import {
  AppRegistry,
  Animated,
  asset,
  Easing,
  NativeModules,
  Pano,
  Sound,
  Text,
  View,
  VrButton
} from 'react-vr';

const cubeModule = NativeModules.CubeModule;

class GoingNative extends React.Component {
  constructor(props) {
    super(props);
    this.state = { btnColor: 'white', cubeColor: 'yellow' };
    cubeModule.changeCubeColor(this.state.cubeColor);
  }
  render() {
    return (
      <View
        style={{
          transform: [{ translate: [0, 0, -3] }],
          layoutOrigin: [0.5, 0, 0],
          alignItems: 'center',
        }}>
        <Pano source={asset('chess-world.jpg')} />
        <VrButton
          style={{
            backgroundColor: this.state.btnColor,
            borderRadius: 0.05,
            margin: 0.05,
          }}
          onEnter={() => { this.setState({ btnColor: this.state.cubeColor }) }}
          onExit={() => { this.setState({ btnColor: 'white' }) }}
          onClick={() => {
            let hexColor = Math.floor(Math.random() * 0xffffff).toString(16);
            // Ensure we always have 6 digits by padding with leading zeros.
            hexColor = '#' + (('000000' + hexColor).slice(-6));
            this.setState({ cubeColor: hexColor, btnColor: hexColor });
            // Asynchronous call to custom native module; sends the new color.
            cubeModule.changeCubeColor(hexColor);
          }}
          onClickSound={asset('freesound__278205__ianstargem__switch-flip-48kmono.wav')}
        >
          <Text style={{
            fontSize: 0.15,
            paddingTop: 0.025,
            paddingBottom: 0.025,
            paddingLeft: 0.05,
            paddingRight: 0.05,
            textAlign: 'center',
            textAlignVertical: 'center',
          }}>
            button
    </Text>
        </VrButton>
      </View>
    );
  }
};

AppRegistry.registerComponent('GoingNative', () => GoingNative);
```

在`vr`文件夹（文件夹名称为小写）中的`client.js`文件中将包含以下内容：

```jsx
import {VRInstance} from 'react-vr-web';
import {Module} from 'react-vr-web';
import * as THREE from 'three';

function init(bundle, parent, options) {
const scene = new THREE.Scene();
const cubeModule = new CubeModule();
const vr = new VRInstance(bundle, 'GoingNative', parent, {
    cursorVisibility: 'visible',
    nativeModules: [ cubeModule ],
    scene: scene,
    ...options,
  });

  const cube = new THREE.Mesh(
    new THREE.BoxGeometry(1, 1, 1),
    new THREE.MeshBasicMaterial()
  );
  cube.position.z = -4;
  scene.add(cube);

  cubeModule.init(cube);

  vr.render = function(timestamp) {
    const seconds = timestamp / 1000;
    cube.position.x = 0 + (1 * (Math.cos(seconds)));
    cube.position.y = 0.2 + (1 * Math.abs(Math.sin(seconds)));
  };
  vr.start();
  return vr;
};

window.ReactVR = {init};

export default class CubeModule extends Module {
  constructor() {
    super('CubeModule');
  }
  init(cube) {
    this.cube = cube;
  }
  changeCubeColor(color) {
    this.cube.material.color = new THREE.Color(color);
  }
}

```

# 更多视觉效果

我们做了一些很棒的交互，这是很棒的，尽管直接使用 three.js 的另一个重要原因是在渲染方面做一些 React VR 无法做到的事情。实际上，React VR 可以通过本地方法做一些令人惊叹的事情，所以让我们确切地做到这一点。

首先，让我们将我们的立方体从四处弹跳改为旋转。当我们添加一些视觉效果时，它会看起来更令人印象深刻。

让我们也添加一些球体。我们希望有一些东西可以反射。我选择反射作为一个令人印象深刻的事情，目前在 WebVR 中你实际上不能做到，尽管我们可以通过环境映射做一些非常接近的事情。关于环境映射是什么的讨论比较长，你可以去这里了解：[`bit.ly/ReflectMap`](http://bit.ly/ReflectMap)。

将以下代码添加到您现有的`index.vr.js`中，在`</VrButton>`下方：

```jsx
     <Sphere
      radius={0.5}
      widthSegments={20}
      heightSegments={12}
      style={{
        color: 'blue',
        transform: [{ translate: [-1, 0, -3] }],
      }}
      lit />
    <Sphere
      radius={1.5}
      widthSegments={20}
      heightSegments={12}
      style={{
        color: 'crimson',
        transform: [{ translate: [1, -2, -3] }],
      }}
      lit />
```

我们还将在顶层`<View>`内的`index.vr.js`中添加环境光和定向光：

```jsx
  <AmbientLight  intensity={.3} />
  <DirectionalLight
    intensity={.7}
    style={{ transform: [{
        rotateZ: 45
      }]
    }}
  />
```

继续加载，并确保您看到一个漂亮的蓝色球和一个大红色球。请注意，我编码比平常稍微密集一些，这样这本书就不会消耗更多的树木或光子。我们大部分的更改将在`client.js`中进行。首先，在`init`下初始化我们需要的所有变量：

```jsx
 var materialTorus;
 var materialCube;
 var torusCamera;
 var cubeCamera;
 var renderFrame;
 var torus;
 var texture;
 var cube;
```

然后，我们将为场景设置自定义背景。有趣的是，在我们有`<Pano>`语句时，这并不会显示出来，但这是件好事，因为我们现在正在用`three.js`编码；它不理解 VR，所以背景不太对。这会在图像上显示出来，但最好由读者自行修复。要为`three.js`设置自定义背景，继续按照以下方式添加代码：

```jsx
  var textureLoader = new THREE.TextureLoader();
  textureLoader.load('../static_assets/chess-world.jpg', function (texture) {
    texture.mapping = THREE.UVMapping;
    scene.background = texture;
  });
```

然后，我们将创建一个圆环和之前创建的立方体（记住，这一切仍然在`init`语句中）：

```jsx
  torusCamera = new THREE.CubeCamera(.1, 100, 256);
  torusCamera.renderTarget.texture.minFilter = THREE.LinearMipMapLinearFilter;
  scene.add(torusCamera);

  cubeCamera = new THREE.CubeCamera(.1, 100, 256);
  cubeCamera.renderTarget.texture.minFilter = THREE.LinearMipMapLinearFilter;
  scene.add(cubeCamera);

```

我们在这里做的是创建了一些额外的摄像头。我们将把这些摄像头移动到圆环和我们的弹跳立方体所在的位置，然后将这些摄像头渲染到一个屏幕外的缓冲区（看不见）。现在我们已经创建了这些摄像头，我们可以创建我们的立方体和圆环 three.js 对象；请注意，这对我们之前的立方体有一点改变：

```jsx
  materialTorus = new THREE.MeshBasicMaterial({ envMap: torusCamera.renderTarget.texture });
  materialCube = new THREE.MeshBasicMaterial({ envMap: cubeCamera.renderTarget.texture });

  torus = new THREE.Mesh(new THREE.TorusKnotBufferGeometry(2, .6, 100, 25), materialTorus);
  torus.position.z = -10; torus.position.x = 1;
  scene.add(torus);

  cube = new THREE.Mesh( new THREE.BoxGeometry(1, 1, 1), materialCube);
  cube.position.z = -4;
  scene.add(cube);

  renderFrame = 0;
  cubeModule.init(cube);
```

请注意，`cubeModule.init(cube);`语句应该已经存在。现在，我们只需要真正地将假锡箔包裹在我们的物体周围；我们将在`vr.render`函数中完成这个操作。以下是整个函数：

```jsx
vr.render = function (timestamp) {
    // Any custom behavior you want to perform on each frame goes here
    const seconds = timestamp / 2000;
    cube.position.x = 0 + (1 * (Math.cos(seconds)));
    cube.position.y = 0.2 + (1 * Math.abs(Math.sin(seconds)));
    cube.position.y = 0.2 + (1 * Math.sin(seconds));

    var time = Date.now();
    torus.rotation.x += 0.01;
    torus.rotation.y += 0.02;

    //we need to turn off the reflected objects, 
    //or the camera will be inside.
    torus.visible = false;
    torusCamera.position.copy(torus.position);
    torusCamera.update(vr.player.renderer, scene)
    materialTorus.envMap = torusCamera.renderTarget.texture;
    torus.visible = true;

    cube.visible = false;
    cubeCamera.position.copy(cube.position);
    cubeCamera.update(vr.player.renderer, scene);
    materialCube.envMap = cubeCamera.renderTarget.texture;
    cube.visible = true;

    renderFrame++;

  };
  // Begin the animation loop
  vr.start();
  return vr;
};
```

我稍微改变了盒子，去掉了正弦波周围的`Math.abs(..)`函数，这样它就会在一个完整的圆圈中旋转；这样我们就可以看到反射贴图的优点和缺点。

希望我们已经把所有内容都粘贴进去了。你可以面带微笑地观看显示。漂亮的铬结对象！当你盯着它看时，你会注意到有些地方不太对劲。你可以看到在方框中伪造的反射和真实的反射之间的区别。它看起来有点“不对劲”，但铬结看起来不错。

看看以下图像中红色高亮和绿色的区别：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/4fba2cf3-bfb4-46b2-826c-83a442cd8a85.png)创建良好的 VR 主要是关于合理的妥协。在反射的情况下，它们看起来可能很棒，就像前面的图像所示的那样，但它们也可能看起来有点不舒服。盒子或平面镜子就是一个不好的例子。曲面物体看起来更自然，正如你所看到的。

游戏和实时编程与仔细的设计一样重要，也是对真实世界的忠实再现。记住，我们不是在创造真实的东西；我们所要做的就是创造一个看起来真实的东西。

在 three.js 中有一个真正的反射器叫做`THREE.Reflector`，如果你想建造一个平面镜子。在 three.js 的示例中有很好的文档记录。

借助这些技术和 React Native 桥接，您可以在不深入常规 three.js 编程的情况下，在 React VR 中做一些令人惊叹的事情。

# 下一步

现在您已经看到了材料的基本 three.js 语法，您可以查看各种 three.js 示例，并复制其中的一些代码。不要只看屏幕上的示例。您还会想在 VR 中尝试它们。一些游戏技巧，比如镜头反射或屏幕空间反射，在 VR 中看起来并不好。一如既往，测试，测试和测试。

我还略微改变了按钮的颜色，当我们切换到 VR 模式时，我们没有光标，所以按钮按下并不总是有效。在下一章中，我将向您展示如何解决这个问题，或者您可以自行调查。

我还在源文件中加载了一个类似金属的反射纹理，名为`static_assets/metal_reflect.jpg`。您不必进行相机渲染来获得看起来闪亮的东西，特别是如果它是一种暗淡的反射，并且可能不希望额外增加帧速率（所有这些相机渲染都需要时间）。如果是这种情况，您可以做一个简单的环境贴图，跳过相机加载和渲染。

# 扩展 React VR — 本机视图

您还可以通过一种称为**本机视图**的东西来扩展 React VR 本身。视图这个词可能让您想到相机渲染，尽管在这种情况下，意思有点不同。把它们看作是本机 three.js 的新 React VR 对象更为合适。它们非常有用。您可以使用我们刚刚介绍的 three.js 代码来混合原始的 three.js 编程，但是以这种方式使用声明式编程的能力有限。有没有更适合 React VR 的方法？您可以通过本机视图来实现这一点。

# 扩展语言

当您实现本机视图时，您可以控制属性和代码与其余运行时代码的交互方式。这些注入通常是视觉的，尽管您也可以注入声音。

您还可以实现新的本机对象。编程方式与我们迄今为止所做的类似；您实现基本属性，将新关键字暴露给运行时，然后将它们编码，就好像它们是 React VR 语言的一部分。还有其他关键字和函数，让您能够根据属性和类型描述您的新 React VR 视图。

要创建本机视图，可以查看文档：[`bit.ly/RCTNativeView.  `](http://bit.ly/RCTNativeView)

你现在已经到了可以用 React VR 做一些令人惊叹的事情的地步了，我完全相信你可以分解我的例子，扩展它们，并且玩得开心。

# 总结

在本章中，我们讨论了如何在 React VR 中使用 three.js 的全部功能。在学习这一点的同时，我们演示了如何放置本地代码和 React VR 本地桥接。我们直接通过 JavaScript 构建了`three.js`网格，并添加了使世界更加生动的声音。我们还使用了 React Native Views 和本地桥接来进行自定义渲染，包括反射贴图 - 我们为 VR 添加了 Chrome（而不是用 Chrome 查看 VR）。我们还展示了如何通过`vr.player.renderer`访问 React VR 相机来进行更多的 three.js 处理。

有了完整的 three.js，我们真的可以用 React VR 做任何我们想做的事情。然而，我们应该在需要的地方使用 React VR，在需要更多细节的地方使用 three.js，否则 React VR 将成为螺栓上的糖霜。它可能会生锈并容易脱落。


# 第十章：引入真实世界

正如您在上一章第九章中学到的，*自己动手-本地模块和 Three.js*，我们可以将本地代码和 JavaScript 代码包含到我们的世界中。除了通过使其在视觉上更有趣来为我们的世界注入生命外，我们还可以将外部世界引入其中。

在本章中，您将学习如何使用 React 和 JavaScript 将网络带入 VR 世界。您将学习如何在 VR 中使用现有的高性能代码。

首先，我们需要一个 VR 世界来开始。这一次，我们要去火星了！

在本章中，您将学习以下主题：

+   执行 JSON/Web API 调用

+   `Fetch`语句

+   跨域资源共享（CORS）

+   诊断的网络选项卡

+   `Cylindrical Pano`语句

+   类似于 flexbox 的文本对齐（React Native 的一部分）

+   条件渲染

+   样式表

# 前往火星（初始世界创建）

您可能会认为太空中没有天气，但实际上是有的，我们在那里有天气站。我们将前往火星获取我们的天气。这将是一个实时程序，将从火星科学实验室或其名为**好奇号**的探测车获取天气数据。

好奇号是一辆体积为 SUV 大小的火星探测车，于 2011 年 11 月 26 日发射到火星，于 2012 年 8 月 6 日着陆。如果您开着 SUV 去那里，即使您能买到汽油，也需要大约 670 年才能到达那里。火星探测车最初设计为两年的任务，但其任务被延长了，这对我们来说是幸运的。

开着 SUV 去火星获取天气报告将是一件麻烦事。我甚至不知道加油站在哪里。

# 创建初始世界

首先，就像以前做过的那样，转到存储世界的目录并创建一个，如下所示：

```jsx
react-vr init MarsInfo
```

然后，从[`github.com/jgwinner/ReactVRBook/tree/master/Chapter10/MarsInfo`](https://github.com/jgwinner/ReactVRBook/tree/master/Chapter10/MarsInfo)下载资产。

尽管我上传了所有文件来使其工作，而不仅仅是静态资产，但您真的应该尝试自己编写代码。从下载文件并运行它们中，您并不会真正学到任何东西。

犯错误是塑造性格的过程。我上传了文件并将继续维护它们，以防有*太多*的性格。

现在我们有了一个初始世界，我们将开始设置 Web 服务以获取数据。

# Jason 和 JSON

当您听到人们谈论 JSON 时，希望您不会想到这个家伙：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/96fa4baa-8e01-4ee7-97ab-1a1193891460.jpg)

我在网上找到了这张图片，标记为创意共享；这是来自加拿大拉瓦尔的 Pikawil 拍摄的蒙特利尔 Comic-Con 上的 Jason Voorhees 服装（角色扮演）。

认真地说，JSON 是通过 Web 服务引入外部世界的最常见方式；然而，正如我们已经看到包括原生代码和 JavaScript 的方式，您可以以各种方式集成您的系统。

React VR 的另一个巨大优势是它基于 React，因此您可以在 React VR 中常见的事情，也可以在 React VR 中做，只是有一些重要的区别。

# 为什么 JSON 与 React 无关

起初，您可能会想，"在 React VR 中如何进行 AJAX 请求？"

实际上并不是。React VR 和 React Native 对获取数据的方式没有任何忠诚度。事实上，就 React 而言，它甚至不知道图片中有*服务器*。

React 只是使用来自两个地方的数据（props 和 state）简单地渲染组件。

这是学术答案。真实答案要广泛一些。您可以以任何您喜欢的方式获取数据。在说完这些之后，通常大多数 React 程序员将使用这些 API 和/或框架之一：

+   Fetch：几乎是一个标准，它内置在 React 中，因为它通常已经包含；有关用法说明和示例，请参阅[`bit.ly/FetchAPI`](http://bit.ly/FetchAPI)

+   Axios：Axios 围绕着承诺（异步完成 API）展开，尽管它也可以在单线程应用程序中以更简单的方式使用；有关更多详细信息，请参阅[`bit.ly/AxiosReadme`](http://bit.ly/AxiosReadme)

+   Superagent：如果您不喜欢承诺，但喜欢回调；有关更多信息，请参阅[`bit.ly/SuperagentAPI`](http://bit.ly/SuperagentAPI)

在这些示例中，我们将展示 fetch，因为没有必要安装不同的模块和设置回调。在说完这些之后，您可能希望构建一个稍微更具响应性的应用程序，该应用程序使用某种类型的回调或异步完成，以便在等待外部数据时执行某些操作。Fetch 确实通过承诺进行异步完成，因此我们将进行条件渲染以利用这一点，并保持响应性 VR 应用程序。

你可能已经写了很多这样的代码。React VR，正如前面讨论的那样，是一个用于 VR 对象的渲染系统，因此你可以使用各种外部 JavaScript 系统。

# 找到 API——从火星一直到地球

现在，我们将从火星获取天气数据。不，我并不是在开玩笑。参考[`bit.ly/MarsWeatherAPI`](http://bit.ly/MarsWeatherAPI)，如果你感兴趣，这里描述了 API 并提供了一些科学背景。这个 API 被设置为从 XML 数据中获取并以 JSON 或 JSONP 格式返回。以下是结果数据，你也可以参考：[`marsweather.ingenology.com/v1/latest/`](http://marsweather.ingenology.com/v1/latest/)。

```jsx
{
  "report": {
    "terrestrial_date": "2019-04-21",
    "sol": 2250,
    "ls": 66.0,
    "min_temp": -80.0,
    "min_temp_fahrenheit": -112.0,
    "max_temp": -27.0,
    "max_temp_fahrenheit": -16.6,
    "pressure": 878.0,
    "pressure_string": "Higher",
    "abs_humidity": null,
    "wind_speed": null,
    "wind_direction": "--",
    "atmo_opacity": "Sunny",
    "season": "Month 4",
    "sunrise": "2019-04-21T11:02:00Z",
    "sunset": "2019-04-21T22:47:00Z"
  }
}
```

我们可以相当容易地将这转换为我们的 JSON 对象。首先，让我们测试连接性，并对实际返回的 JSON 文本进行合理检查。我们在浏览器中测试了前面的 JSON 数据，但我们需要测试代码以确保它能正常工作。要做到这一点，请按照以下步骤：

1.  在`index.vr.js`中找到 MarsInfo `Component {`的声明，添加以下内容：

```jsx
export default class MarsInfo extends Component {
    componentDidMount() {
        fetch(`http://marsweather.ingenology.com/v1/latest/`,
            {
                method: 'GET'
            })
            .then(console.log(result))
    }

    render() {
```

1.  粘贴这个并运行它。

1.  在浏览器中打开控制台（在 Firefox Nightly 中按*Ctrl*+*Shift*+*K*）。虽然我们刚刚展示的代码非常合理，在浏览器中运行良好，但当我们运行时，会出现错误：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/43f4c4e3-5168-4392-9908-550e7b62b00f.png)

问题是什么？是 CORS。这是一种机制，用于使跨源或不来自同一服务器的 Web 内容安全可靠。基本上，这是 Web 服务器表明“我可以嵌入到另一个网页中”的一种方式。例如，你的银行不希望你的银行详细信息被嵌入到其他网站的网页中；你的支票账户可能会很容易地受到威胁，你会认为自己正在登录真正的银行——而实际上并非如此。

请注意，我本可以使用一个不会出现这些错误的 API，但你可能会遇到自己内容的相同问题，所以我们将讨论如何发现 CORS 问题以及如何解决它。

1.  要找出我们为什么会出现这个错误，我们需要查看协议头；点击工具->Web 开发者->网络，打开网络选项卡：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/737cb7a4-23ee-4587-8a4d-a0b584397150.png)

这个窗口对于解决原生 JSON 请求问题和网站集成非常有价值。

1.  一旦打开控制台，你会看到不同的 HTTP 操作；点击那个没有完成的操作：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/21eea88e-d6be-4bd8-a82e-7b69caf419a4.png)

然后我们将查看返回的数据。

1.  查看以下截图的右侧；在这里，您可以单击响应和头部来检查数据。我们可以看到网站确实返回了数据；但是，我们的浏览器（Firefox）通过生成 CORS 错误来阻止显示：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/9d3e593d-284b-40f8-9807-bfa13a15937d.png)

代码是正确的，但网站没有包括重要的 CORS 头，因此根据 CORS 安全规则，网站将其阻止。您可以在以下网址了解有关 CORS 的更多信息：[`bit.ly/HTTPCORS`](http://bit.ly/HTTPCORS)。

如果出现此错误，可能可以通过向请求添加头部来解决。要添加头部，您需要修改`fetch`请求；`fetch`请求还允许使用`'cors'`模式。然而，出于某种原因，对于这个特定的网站，`'cors'`选项似乎对我不起作用；对于其他网站，可能效果更好。其语法如下：

```jsx
fetch(`http://marsweather.ingenology.com/v1/latest/`,
    {
        method: 'GET',
        mode: 'cors',
    })
```

为了更好地控制我们的请求，创建一个头部对象并将其传递给`fetch`命令。这也可以用于所谓的**预检查**，即简单地进行两个请求：一个是为了找出 CORS 是否受支持，第二个请求将包括来自第一个请求的值。

1.  要构建请求或预检查请求，请设置如下头部：

```jsx
var myHeaders = new Headers();
myHeaders.append('Access-Control-Request-Method', 'GET');
myHeaders.append('Access-Control-Request-Headers', 'Origin, Content-Type, Accept');

fetch(`http://marsweather.ingenology.com/v1/latest/`,
    {
        headers: myHeaders,
        method: 'GET',
        mode: 'cors',
    })
```

头部值`'Access-Control-Request-Headers'`可以设置为服务器将返回的自定义头部选项（如果支持 CORS），以验证客户端代码是否是有效的 CORS 请求。截至 2016 年，规范已经修改以包括通配符，但并非所有服务器都会更新。如果出现 CORS 错误，您可能需要进行实验并使用网络选项卡来查看发生了什么。

在这种情况下，我们需要使用“预检查”的选项，但即使在修改了 React VR 网络代码之后，这在[marsweather.ingenology.com](http://marsweather.ingenology.com)上也没有起作用，因此他们的服务器很可能还没有升级到现代网络安全标准。

这种情况可能会发生！在我们的情况下，确实没有通用的解决方法。我找到了一个 Firefox 插件，可以让您绕过 CORS 限制（请记住，问题不是来自服务器，而是浏览器在看到服务器*已经*发送的有效负载时关闭您的代码），但这需要人们下载插件并进行调试。

我们需要找到一个更好的 API。NASA 拥有一个出色的 Web API 目录，我们将使用他们的火星探测器相机 API。你可以免费获取数十万张照片中的任何一张。一旦我们使用不同的 Web API，我们将得到我们一直在寻找的正确的 CORS 标头，一切都运行得很好。一旦我们向具有现代安全标准的服务器发出请求，我们会注意到它自动包含了 Firefox 需要的`access-control-allow-origin`（在这里是通配符），如下图所示，取自网络选项卡：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/5d3aadc5-181d-42fc-a1c2-8cc58ed417f0.png)

因此，我们将看实际图片，而不是火星上的天气。

# 来自 NASA 的更好的 API

要查看一些很棒的 Web API，你可以访问：[`bit.ly/NasaWebAPI`](http://bit.ly/NasaWebAPI)并查看你可以使用的 API 列表，或者更好的是，使用你已经编写的一些 Web API。React VR 使得通过 React 和 React Native 的强大功能集成这些 API 变得非常容易。我们将使用火星照片 API。要启用它，你可能需要一个开发者密钥。当你发出请求时，你可以将你的 API 密钥添加到 URL 中，或者使用`DEMO_KEY`。这将成为 API 调用的一部分，例如，[`api.nasa.gov/mars-photos/api/v1/rovers/curiosity/photos?sol=1000&api_key=DEMO_KEY`](https://api.nasa.gov/mars-photos/api/v1/rovers/curiosity/photos?sol=1000&api_key=DEMO_KEY)。请注意，URL 末尾没有句号。

如果在开发代码时出现错误，你可能使用了`DEMO_KEY`太多次；获取你自己的开发者 API 非常快速和简单；有关说明可以在我提到的网站上找到：[`bit.ly/NasaWebAPI`](http://bit.ly/NasaWebAPI)。

要从 NASA 获取数据，我们只需稍微更改`fetch`命令，如下所示；事实证明，我们不需要自定义标头：

1.  将`index.vr.js`更改为以下内容，直到`render()`语句：

```jsx
export default class MarsInfo extends Component {
    constructor() {
        super();
        this.state = {
            currentPhoto: 2,
            photoCollection: { photos: []}
        };
    };
    componentDidMount() {
        fetch('https://api.nasa.gov/mars-photos/api/v1/rovers/curiosity/photos?sol=1197&api_key=DEMO_KEY',
            { method: 'GET' })
            .then(response => response.json())
            .then(console.log("Got a response"))
            .then(json => this.setState({ photoCollection:json }))

    };
```

这就是我们从 NASA 获取火星数据并将其放入集合中所需做的一切。太棒了！以下是我们所做的一些注意事项：

+   `photoCollection`对象被初始化为空数组（集合）。这样我们在获取数据之前和之后可以使用类似的代码。

+   但是，你仍然应该检查是否有失败。

+   我们将`currentPhoto`值初始化为`2`，有点像是在“作弊”。这样做的原因是，当我写这本书的时候，如果你让`currentPhoto`默认为第一张图片，你在火星的第一个视图会很无聊。前几张图片都是测试图片，相当普通，所以我让你把`currentPhoto`改成`2`，这样我们就能看到一些有趣的东西。如果你有一个返回特定数据的 API，你也可以做同样的事情。

+   这段代码只是获取数据；它不会渲染它。为此，我们将开发一个单独的对象来保持我们的代码模块化。

1.  出于调试目的，我们还将在`render()`线程中添加一行，以查看我们确切拥有的数据。插入以下`console.log`语句：

```jsx
  render() {
      console.log("Render() main thread, photo collection:", this.state.photoCollection);
      return (
```

这对于解决渲染代码和理解当前状态以及其变化非常有用。运行这段代码，我们可以在控制台中看到返回的对象。首先，我们从`render()`线程中得到一行，显示一个空的`photo collection`：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/207bd55f-cb86-4cdf-b080-9be5d5110377.png)

注意`photo collection`是空的；这是有道理的，因为我们是这样初始化的。几秒钟后——在这段时间内*你可以查看虚拟世界*——你会看到另一个`render()`更新和更改的数据：

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/f4110a61-08cd-4deb-a3b1-8ca1530e8bc9.png)

在这种特殊情况下（第 1,1197 天），有*很多*图片。JSON 处理这些数据非常出色，同时我们在 VR 世界中四处张望。

另一个需要注意的事情是`render()`循环只被调用了两次。如果你习惯于游戏开发范式，这可能看起来很奇怪，因为正如我们讨论过的，为了建立沉浸感，我们需要超过 60 帧每秒。如果我们只渲染了两次，我们怎么能做到呢？

React VR 并不实际生成图像，而是由 three.js 完成。当 React VR“渲染”时，它只是采用 React VR 语法，并应用任何 props 或状态更改，并为那些已经改变的对象调用`render()`。

为了显示我们检索到的数据，我们将构建一个新对象。

1.  创建一个名为`CameraData`的新文件，并将其作为一个单独的组件。我们还将改变`index.vr.js`中的`render()`方法。

# 每个人都需要一个样式表

样式不仅仅适用于你的头发；在这种情况下，使用样式表将有助于使我们的代码更简单、更清洁、更易于维护。样式重用非常容易。样式不是一种单独的语言；它们像 React 中的其他所有内容一样都是 JavaScript。React VR 中的所有核心对象都接受一个名为`styles`的 prop。我们将在我们的文件中定义这个样式并重用它。

创建以下样式定义，以便我们可以在`CameraData.js`组件中使用它们（请注意，您可以将其放在文件的任何位置）：

```jsx
const styles = StyleSheet.create({
    manifestCard: {
        flex: 1,
        flexDirection: 'column',
        width: 2,
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'green',
        opacity: 0.8,
        borderRadius: 0.1,
        borderColor: '#000',
        borderWidth: 0.02,
        padding: 0.1,
        layoutOrigin: [-1, 0.3],
        transform: [
            {
                rotateY: -30,
                translate: [1, 0, -2]
            }
        ]
    },

    manifestText: {
        textAlign: 'center',
        fontSize: 0.1
    },
    frontCard: {
        flex: 1,
        flexDirection: 'column',
        width: 2,
        alignItems: 'center',
        justifyContent: 'center',
        backgroundColor: 'green',
        borderRadius: 0.1,
        borderColor: '#000',
        borderWidth: 0.02,
        padding: 0.05,
        transform: [{ translate: [-1, 1, -3] }],
    },
    panoImage: {
        width: 500,
        height: 500,
        layoutOrigin: [-.5, 0],
    },
    baseView: {
        layoutOrigin: [0, 0],
    },
});
```

如果省略`width`样式，对象将以完全不同的方式进行变换和移动。我还不确定这是否是一个错误，还是一种不同类型的布局样式，但请注意，如果您的`transform`语句没有移动文本或视图对象，可能是因为您的文本样式没有`width:`属性。

# 构建图像和状态 UI

接下来，我们需要以两种不同的方式渲染相机数据。第一种是当我们还没有`CameraData`时，换句话说，就是在应用程序启动时，或者如果我们没有互联网连接；第二种是当我们获取数据并需要显示它时。我们还希望保持这些例程相当模块化，以便在启动状态变化时可以轻松地重新绘制需要的对象。

请注意，React VR 自动完成了很多工作。如果一个对象的 props 或状态没有改变，它就不会被告知重新渲染自己。在这种情况下，我们的主线程已经具有了修改更改的 JSON 处理，因此主循环中不需要创建任何内容来重新渲染相机数据。

1.  添加以下代码：

```jsx
export default class CameraData extends Component {
    render() {
        if (!this.props) {
            return this.renderLoadingView();
        }
        var photos = this.props.photoCollection.photos;
        if (!photos) {
            return this.renderLoadingView();
        }
        var photo = photos[this.props.currentPhoto];
        if (!photo) {
            return this.renderLoadingView();
        }
        return this.renderPhoto(photo);
    };

```

请注意，我们还没有完成组件，所以不要输入最终的`};`。让我们讨论一下我们添加了什么。先前的主`render()`循环实质上是检查哪些值是有效的，并调用两个例程中的一个来实际进行渲染，要么是`renderPhoto(photo)`，要么是`renderLoadingView()`。我们可以假设如果我们没有照片，我们正在加载它。前面的代码的好处是在使用之前检查我们的 props 并确保它们是有效的。

许多计算机课程和自助书籍剥离了错误处理以“专注于重要的事情”。

错误处理是你的应用程序中*最*重要的事情。在这种情况下，它特别重要，因为当我们检索数据时，我们还没有加载照片，所以我们没有东西可以显示。如果我们不处理这个问题，我们会得到一个错误。我剥离的是`console.log`语句；如果你下载本书的源代码，你会发现更多的详细注释和跟踪语句。

现在，让我们继续进行实际的渲染。这看起来欺骗性地简单，主要是因为所有序列化、获取和有选择地渲染的辛苦工作已经完成。这就是编程应该努力做到的—清晰、健壮、易于理解和维护。

一些代码示例变得很长，所以我把闭合括号和标签放在它们要关闭的对象的末尾。我建议你买一个大的台式屏幕，以更宽广的方式编码；当你花一个小时追踪丢失或放错的`/>`时，你会感激大尺寸的显示设备。这只会提高生产力。

1.  添加以下代码：

```jsx
renderLoadingView() {
    console.log('CameraData props during renderLoadingView', this.props);
    return (
        <View style={styles.frontCard} >
            <Text style={styles.manifestText}>Loading</Text>
            <Text style={styles.manifestText}>image data</Text>
            <Text style={styles.manifestText}>from NASA</Text>
            <Text style={styles.manifestText}>...</Text>
        </View>
    );
};
renderPhoto(photo) {
return (
   <View style={styles.baseView}>
      <CylindricalPanel
         layer={{
            width: 1000,
            height: 1000,
            density: 4680,
            radius: 20 }}>
         <Image
            source={{ uri: photo.img_src }}
            style={styles.panoImage}>
         </Image>
      </CylindricalPanel>
      <Model
         source={{
            obj: asset('ArrowDown.obj'),
            mtl: asset('ArrowDown.mtl'), }}
         lit
         style={{
            transform: [{ translate: [-2.5, -1, -5.1] }] }} />
      <Model
         source={{
            obj: asset('ArrowUp.obj'),
            mtl: asset('ArrowUp.mtl'), }}
         lit
         style={{
            transform: [{ translate: [1.3, -1, -5.1] }] }} />
      <View style={styles.manifestCard}>
         <Text style={styles.manifestText}>
            {photo.camera.full_name}</Text>
         <Text style={styles.manifestText}>
            {photo.rover.name} Rover #{photo.rover.id}</Text>
         <Text style={styles.manifestText}>
            Landed on: {photo.rover.landing_date}</Text>
         <Text style={styles.manifestText}>
            Launched on: {photo.rover.launch_date}</Text>
         <Text style={styles.manifestText}>
            Total Photos: {photo.rover.total_photos}</Text>
         <Text style={styles.manifestText}>
            Most recent: {photo.rover.max_date} Latest earth date</Text>
         <Text style={styles.manifestText}>
            Viewing: {photo.rover.max_sol} Mars Sol</Text>
         <Text style={styles.manifestText}>
            Taken: {photo.earth_date} Earth (GMT)</Text>
      </View>
   </View>
);
}
}
```

如果你迄今为止已经输入了所有的代码，当世界加载时，你会看到一个绿色的对话框，告诉你它正在接收数据。几秒钟后，它将被照片 2 和来自火星的数据的详细元信息所取代。

![](https://github.com/OpenDocCN/freelearn-react-zh/raw/master/docs/gtst-react-vr/img/acd7e7e7-b883-4ad2-94ea-dfab4bf0a77a.jpg)

如果你想同时打开两个虚拟世界，例如，为了检查一些导入而不产生我们正在编程中的往返网络请求，你可以通过转到设置好的第二个世界，而不是`npm start`，使用`react-native start --port 9091`命令来实现。

我之前简要提到过这一点，但重要的是要注意 React 是多线程的；当它们的 props 或状态改变时，元素会改变它们的渲染，而无需告诉它们。这是多线程的，而不需要改变代码。这使你能够在世界填充数据时移动摄像机并查看。

这使虚拟世界看起来更加“真实”；它对输入做出响应，就像它是现实一样。它就是—我们创造了虚拟现实。

# 如何（不）让人生病

你可能已经注意到，我们把用户界面——图标和屏幕——放得有点远；到目前为止，我们把所有东西都放在至少五米外。为什么呢？

这是因为容纳-聚焦冲突。

当你的眼睛“注视”着某样东西，就像我们在第一章“虚拟现实到底是什么？”中讨论的那样，如果那个东西离你的脸很近，你的眼睛会试图对其进行聚焦。然而，你的头戴式显示器是一个固定焦距的设备，无论物体离你有多近或多远，它总是显示清晰的图像。在现实世界中，比如说，距离小于 3 到 4 英尺的物体会需要你的眼睛进行更多的聚焦，而距离 10 英尺的物体则需要较少的聚焦。

因此，你的眼睛会聚焦在一个你本应该需要更多聚焦的图像上，但你所看到的已经是清晰的（因为一切都是清晰的），所以你期望在现实世界中看到的和在头戴式显示器中看到的有所不同。

这不会导致任何实际的视觉问题——一切都是清晰的和聚焦的。

你可能会感到眼睛疲劳和一种模糊的不适感，这种感觉会随着使用头戴式显示器的时间变得更糟。

避免这种情况的方法是尽量将 UI 元素放得比我们在这个例子中展示的更远。比如不要将浮动屏幕放在眼镜的位置。如果你这样做，人们会看着它们，他们的眼睛会期望对着距离大约六英寸的东西进行聚焦，但从聚焦的角度来看，这个物体的距离已经超过了手臂的长度。这会让你的用户感到疲劳。

这就是为什么大多数虚拟现实让你看着远处的大屏幕进行选择。你可能希望将 UI 元素放在手腕上，甚至那样也有点冒险。

我觉得人们使用虚拟现实的次数越多，他们的眼睛和聚焦就会得到重新训练，然而，我不知道有没有任何医学研究显示这种效果。我之所以提到这一点，是因为我的一只眼睛近视，另一只眼睛远视；当我戴上眼镜时，我的聚焦会发生变化。有趣的是，如果我戴上“没有镜片”的眼镜，我的聚焦仍然会发生变化。我觉得人类大脑是无限适应的，我们可以克服调节-调节冲突。

然而，用户的体验可能会有所不同，所以不要让他们因为把东西放得太近（距离小于一米）而感到疲劳。

# 总结

在本章中，你学到了很多东西。我们通过构建消耗 JSON API 的网络服务调用，使我们的世界真正实现了互动。我们看到了一些获取数据的方法，并使用了更多或更少内置的`fetch`语句。这些 API 调用现在是异步的，所以我们可以环顾四周，欣赏火星，而我们请求的相机数据正在加载。

我们已经看到了如何通过处理跨站脚本问题来构建安全的世界。我们创建了合理的文本并进行了条件渲染。我们还讨论了错误处理。

做所有这些需要一些时间，我们在开发过程中有几次花了几个小时来排列对象。有几次我被关闭，因为我在一个小时内超过了`DEMO_KEY`检索次数。这就是为什么我建议你获取自己的 API 密钥，然后你就可以请求更多的图片。

这一章相当长，虽然检索了真实世界的数据，但世界还不是完全互动的。在下一章中，你将学习如何使你的世界与我们的输入互动。这就是为什么我在前面的视图中加入了+和-箭头。查看下一章，找出如何将它们连接到页面通过我们的火星数据。我会展示一个不同的世界，但展示如何使按钮互动。你可以通过做简单的属性更改来使加号和减号按钮变得真实。
