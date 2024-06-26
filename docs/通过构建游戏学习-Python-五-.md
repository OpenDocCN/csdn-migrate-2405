# 通过构建游戏学习 Python（五）

> 原文：[`zh.annas-archive.org/md5/8d68d722c94aedcc91006ddf3f78c65a`](https://zh.annas-archive.org/md5/8d68d722c94aedcc91006ddf3f78c65a)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十四章：了解 PyOpenGL

几何形状和图形在游戏开发中起着至关重要的作用。当涉及到先进的图形技术的开发时，我们往往忽视它们的重要性。然而，许多流行的游戏仍然使用这些形状和图形来渲染游戏角色。数学概念，如变换、向量运动以及放大和缩小的能力，在操纵游戏对象时具有重要作用。Python 有几个模块来支持这种操纵。在本章中，我们将学习一个强大的 Python 功能——PyOpenGL 模块。

在探索 PyOpenGL 时，我们将学习如何使用基本图形（即顶点和边）创建复杂的几何形状。我们将从安装 Python PyOpenGL 并开始用它绘图开始。我们将使用它制作几个对象，如三角形和立方体。我们不会使用 pygame 来创建这些形状；相反，我们将使用纯数学概念来定义顶点和边的直角坐标点。我们还将探索不同的 PyOpenGL 方法，如裁剪和透视。我们将涵盖每一个方法，以了解 PyOpenGL 如何用于创建吸引人的游戏角色。

在本章结束时，您将熟悉创建基本图形的传统和数学方法。这种创建形状的方式为程序员和设计师提供了操纵他们的游戏对象和角色的能力。您还将学习如何在游戏中实现放大和缩小的功能，以及如何通过绘制几何基本图形来使用颜色属性。

本章将涵盖以下主题：

+   理解 PyOpenGL

+   使用 PyOpenGL 制作对象

+   理解 PyOpenGL 方法

+   理解颜色属性

# 技术要求

您需要以下要求清单才能完成本章：

+   建议使用 Pygame 编辑器（IDLE）版本 3.5+。

+   您将需要 Pycharm IDE（参考第一章，*了解 Python-设置 Python 和编辑器*，了解安装过程）。

+   本章的代码资产可以在本书的 GitHub 存储库中找到：[`github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter14`](https://github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter14)

查看以下视频以查看代码的运行情况：

[`bit.ly/2oJMfLM`](http://bit.ly/2oJMfLM)

# 理解 PyOpenGL

在过去，包含经过 3D 加速硬件处理的三维场景的图形程序是每个游戏程序员都想要的东西。尽管按照今天的标准来看这是正常的，但硬件与多年前并不相同。大部分游戏的图形必须使用低处理设备中的软件进行渲染。因此，除了创建这样的场景，渲染也需要相当长的时间，最终会使游戏变慢。游戏界面的出现，也被称为图形卡，为游戏行业带来了革命；程序员现在只需要关注界面、动画和自主游戏逻辑，而不必关心处理能力。因此，90 年代后创建的游戏具有更丰富的游戏性和一丝人工智能（多人游戏）。

众所周知，图形卡可以处理渲染和优化场景等三维功能。但是，要使用这些功能，我们需要一个在我们的项目和这些接口之间进行通信的编程接口。我们在本章中要使用的**应用程序编程接口**（**API**）是 OpenGL。OpenGL 是一个跨平台（程序可以在任何机器上运行）的 API，通常用于渲染 2D 和 3D 图形。该 API 类似于用于促进与图形处理单元的交互的库，并且通过使用硬件加速渲染来加速图形渲染方法。它作为图形驱动程序的一部分预装在大多数机器上，尽管您可以使用*GL 视图* *实用程序*来检查其版本。在我们开始编写程序以便使用 PyOpenGL 绘制几何形状和图形之前，我们需要在我们的机器上安装它。

# 安装 PyOpenGL

即使 OpenGL 已经存在于您的系统上，您仍然需要单独安装 PyOpenGL 模块，以便所需的 OpenGL 驱动程序和 Python 框架可以相互通信。Pycharm IDE 提供了一个服务，可以定位 Python 解释器并安装 PyOpenGL，从而消除了手动安装的开销。按照以下步骤在 Pycharm IDE 中安装 PyOpenGL：

1.  单击顶部导航栏中的“文件”，然后单击“设置”。然后，将鼠标悬停在左侧导航窗口上，并选择项目：解释器选项。

1.  选择当前项目的 Python 解释器，即 Python 3.8+（后跟您的项目名称），并从解释器下拉菜单旁边的菜单屏幕上按下添加（+）按钮。

1.  在搜索栏中搜索 PyOpenGL，然后按“安装包”按钮。

或者，如果您想要外部安装 PyOpenGL，您可以将其下载为 Python 蛋文件。

*Python 蛋*是一个逻辑结构，包含了 Python 项目特定版本的发布，包括其代码、资源和元数据。有多种格式可用于物理编码 Python 蛋，也可以开发其他格式。但是，Python 蛋的一个关键原则是它们应该是可发现和可导入的。也就是说，Python 应用程序应该能够轻松高效地找出系统上存在哪些蛋，并确保所需蛋的内容是可导入的。

这些类型的文件被捆绑在一起，以创建可以通过简单的安装过程从**Python 企业应用套件**（**PEAK**）下载的 Python 模块。要下载 Python 蛋文件，您必须下载 Python `easy_install`模块。转到[`peak.telecommunity.com/DevCenter/EasyInstall`](http://peak.telecommunity.com/DevCenter/EasyInstall)，然后下载并运行`ez_setup.py`文件。成功安装 easy install 后，在命令行/终端中运行以下命令以安装 PyOpenGL：

```py
easy_install PyOpenGL
```

Easy install 不仅用于安装 PyOpenGL，还可以借助它下载或升级大量的 Python 模块。例如，`easy_install` SQLObject 用于安装 SQL PyPi 包。

通常情况下，当我们需要使用包时，我们需要将它们导入到我们的项目中。在这种情况下，您可以创建一个演示项目（`demo.py`）来开始测试 OpenGL 项目。这样我们就可以使用诸如代码可维护性和调试之类的功能，我们将使用 Pycharm IDE 制作 PyOpenGL 项目，而不是使用 Python 的内置 IDE。打开任何新项目，并按照以下步骤检查 PyOpenGL 是否正在运行：

1.  使用以下命令导入 PyOpenGL 的每个类：

```py
      from OpenGL.GL import *
```

1.  现在，使用以下命令导入所需的 OpenGL 函数：

```py
      from OpenGL.GLU import *
```

1.  接下来，您应该将`pygame`导入到您的项目中：

```py
      from pygame.locals import *
```

1.  使用`pygame`命令为您的项目初始化显示：

```py
      import pygame
      from pygame.locals import *
      window_screen = pygame.display.set_mode((640, 480), 
        HWSURFACE|OPENGL|DOUBLEBUF)
```

1.  运行您的项目并分析结果。如果出现新屏幕，您可以继续制作项目。但是，如果提示说 PyOpenGL 未安装，请确保按照前面的安装过程进行操作。

前面的四行很容易理解。让我们逐一讨论它们。第一步非常简单-它告诉解释器导入 PyOpenGL 以及其多个类，这些类可用于不同的功能。以这种方式导入可以减少逐个导入 PyOpenGL 的每个类的工作量。第一个导入是强制性的，因为这一行导入以`gl`关键字开头的不同 OpenGL 函数。例如，我们可以使用诸如`glVertex3fv()`之类的命令，用于绘制不同的 3D 形状（我们稍后会介绍这个）。

导入语句的下一行，即`from OpenGL.GLU import *`，是为了我们可以使用以`glu`开头的命令，例如`gluPerspective()`。这些类型的命令对于更改显示屏的视图以及渲染的对象非常有用。例如，我们可以使用这样的`glu`命令进行裁剪和剪裁等转换。

类似于 PyOpenGL GL 库，GLU 是一个 Python 库，用于探索相关数据集内部或之间的关系。它们主要用于在影响渲染对象的形状和尺寸的同时对显示屏进行更改。要了解有关 GLU 内部的更多信息，请查看其官方文档页面：[`pyopengl.sourceforge.net/pydoc/OpenGL.GLU.html`](http://pyopengl.sourceforge.net/pydoc/OpenGL.GLU.html)。

下一行只是将`pygame`导入到我们的项目中。使用 OpenGL 创建的表面是 3D 的，它需要`pygame`模块来渲染它。在使用`gl`或`glu`模块的任何命令之前，我们需要调用`pygame`模块使用`set_mode()`函数创建一个显示（感受`pygame`模块的强大）。由`pygame`模块创建的显示将是 3D 而不是 2D，同时使用 OpenGL 库的`set_mode`函数。之后，我们告诉 Python 解释器创建一个 OpenGL 表面并将其作为`window_screen`对象返回。传递给`set_mode`函数的元组（高度，宽度）表示表面大小。

在最后一步，我希望您关注以下可选参数：

+   `HWSURFACE`：它在硬件中创建表面。主要用于创建加速的 3D 显示屏，但仅在全屏模式下使用。

+   `OPENGL`：它向 pygame 建议创建一个 OpenGL 渲染表面。

+   `DOUBLEBUF`：它代表双缓冲，pygame 建议对`HWSURFACE`和`OPENGL`使用。它减少了屏幕上颜色闪烁的现象。

还有一些其他可选参数，如下：

+   `FULLSCREEN`：这将使屏幕显示渲染为全屏视图。

+   `RESIZABLE`：这允许我们调整窗口屏幕的大小。

+   `NOFRAME`：这将使窗口屏幕无边框，无控件等。有关 pygame 可选参数的更多信息，请访问[`www.pygame.org/docs/ref/display.html#pygame.display.set_mode`](https://www.pygame.org/docs/ref/display.html#pygame.display.set_mode)。

现在我们已经在我们的机器上安装了 PyOpenGL 并为屏幕对象设置了一个窗口，我们可以开始绘制对象和基本图形。

# 使用 PyOpenGL 制作对象

OpenGL 主要用于绘制不同的几何形状或基元，所有这些都可以用于创建 3D 画布的场景。我们可以制作多边形（多边形）形状，如三角形、四边形或六边形。应该向基元提供多个信息，如顶点和边，以便 PyOpenGL 可以相应地渲染它们。由于与顶点和边相关的信息对于每个形状都是不同的，因此我们有不同的函数来创建不同的基元。这与 pygame 的 2D 函数（`pygame.draw`）不同，后者用于使用相同的单个函数创建多个形状。例如，三角形有三个顶点和三条边，而四边形有四个顶点。

如果您具有数学背景，对顶点和边的了解对您来说将是小菜一碟。但对于那些不了解的人来说，任何几何形状的顶点都是两条或两条以上线相交的角或点。例如，三角形有三个顶点。在下图中，**A**、**B**和**C**是三角形 ABC 的顶点。同样，边是连接一个顶点到另一个顶点的线段。在下面的三角形中，AB、BC 和 AC 是三角形 ABC 的边：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/26d029c3-1800-45d8-aedd-b1a92e547f8a.png)

要使用 PyOpenGL 绘制这样的几何形状，我们需要首先调用一些基本的 OpenGL 基元，这些基元列在下面：

1.  首先，使用要绘制的任何基元调用`glBegin()`函数。例如，应调用`glBegin(GL_TRIANGLES)`来通知解释器我们将要绘制的三角形形状。

1.  关于顶点（A、B、C）的下一个重要信息对于绘制形状至关重要。我们使用`glVertex()`函数发送有关顶点的信息。

1.  除了有关顶点和边的信息之外，您还可以使用`glColor()`函数提供有关形状颜色的其他信息。

1.  在提供足够的基本信息之后，您可以调用`glEnd()`方法通知 OpenGL 已经提供了足够的信息。然后，它可以开始绘制指定的形状，如`glBegin`方法提供的常量所示。

以下代码是使用 PyOpenGL 绘制三角形形状的伪代码（参考前面的插图以了解 PyOpenGL 函数的操作）：

```py
#Draw a geometry for the scene
def Draw():
 #translation (moving) about 6 unit into the screen and 1.5 unit to left
     glTranslatef(-1.5,0.0,-6.0)
     glBegin(GL_TRIANGLES) #GL_TRIANGLE is constant for TRIANGLES 
     glVertex3f( 0.0, 1.0, 0.0) #first vertex 
     glVertex3f(-1.0, -1.0, 0.0) #second vertex 
     glVertex3f( 1.0, -1.0, 0.0) #third vertex 
     glEnd() 
```

下图显示了三角形的法线。法线是一个数学术语，表示单位向量（具有 1 的大小和方向，请参考第十章，*使用海龟升级蛇游戏*，了解更多关于向量的信息）。这个信息（法线）很重要，因为它告诉 PyOpenGL 每个顶点的位置。例如，`glVertex3f(0, 1, 0)`会在*y*轴上放置一个顶点。因此，(*x*, *y*, *z*)表示*x*轴、*y*轴和*z*轴上的大小，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/cfe2348d-185f-47f9-b2b2-73ed7cdd6841.png)

现在我们知道如何创建基本的三角形基元，让我们看一下以下表格，了解可以使用 PyOpenGL 绘制的其他不同类型的基元：

| **常量关键字** | **形状** |
| --- | --- |
| `GL_POINTS` | 将点或点绘制到屏幕上 |
| `GL_LINES` | 绘制线条（单独的线条） |
| `GL_TRIANGLES` | 绘制三角形 |
| `GL_QUADS` | 绘制四边形（四边形） |
| `GL_POLYGON` | 绘制多边形（任何边或顶点） |

现在我们能够使用基元常量绘制任何基元，前提是我们有关于它们顶点的信息。让我们创建以下四边形：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/3ae798eb-a9ce-4cdf-804d-e163c4c08409.png)

以下是绘制前述立方体基元的伪代码：

```py
glBegin(GL_QUADS)
glColor(0.0, 1.0, 0.0) # vertex at y-axis
glVertex(1.0, 1.0, 0.0) # Top left
glVertex(1.0, 1.0, 0.0) # Top right
glVertex(1.0, 1.0, 0.0) # Bottom right
glVertex(1.0, 1.0, 0.0) # Bottom left
glEnd()
```

在上一行代码中，我们首先定义了`GL_QUADS`常量，以通知 PyOpenGL 我们正在绘制的基本图元的名称。然后，我们使用`glColor`方法添加了颜色属性。同样，我们使用`glVertex`方法定义了立方体的四个主要顶点。作为`glVertex`方法的参数传递的坐标代表了平面上的*x*、*y*和*z*轴。

现在我们能够使用 PyOpenGL 绘制不同的几何形状，让我们了解 PyOpenGL 的不同渲染函数/基本图元，以便我们可以制作其他复杂的结构。

# 理解 PyOpenGL 方法

众所周知，计算机屏幕具有二维视图（高度和宽度）。为了显示由 OpenGL 创建的三维场景，场景必须经过几次矩阵变换，通常称为投影。这允许将 3D 场景呈现为 2D 视图。在各种变换方法中，常用于投影的有两种（裁剪和归一化）。这些矩阵变换应用于 3D 坐标系，并缩减为 2D 坐标系。`GL_PROJECTION`矩阵经常用于执行与投影相关的变换。投影变换的数学推导是另一回事，我们永远不会使用它们，但理解它的工作原理对于任何游戏程序员来说都是重要的。让我们来看看`GL_PROJECTION`的工作原理：

+   **裁剪**：这将把场景的顶点坐标转换为场景的裁剪坐标。裁剪是一个调整场景长度的过程，以便从`视口`（窗口显示）中裁剪掉一些部分。

+   **归一化**：这个过程被称为**标准化设备坐标**（**NDC**），它通过将裁剪坐标除以裁剪坐标的`w`分量来将裁剪坐标转换为设备坐标。例如，裁剪坐标 x[c]、y[c]和 z[c]通过与 w[c]进行比较。不在-w[c]到+w[c]范围内的顶点被丢弃。这里的下标*c*表示裁剪坐标系。

因此，更容易推断矩阵变换的过程，包括`GL_PROJECTION`，包括两个步骤：裁剪，紧接着是归一化到设备坐标。以下图示了裁剪的过程：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/4af7b0fe-7069-405c-9ba1-131b483d844d.png)

我们可以清楚地观察到裁剪（有时称为剔除）的过程只在裁剪坐标中执行，这些坐标由 2D 视口的大小定义。要找出哪些裁剪坐标已被丢弃，我们需要看一个例子。假设*x*、*y*和*z*是裁剪坐标，它们的值与*w*（*x*、*y*）的坐标进行比较，决定任何顶点（或形状的一部分）是否保留在屏幕上或被丢弃。如果任何坐标位于-w[c]的值以下和+w[c]的值以上，那个顶点就被丢弃。在上图中，顶点 A 位于+w[c]之上，而顶点 B 和 C 位于-w[c]之下，因此两个顶点都被丢弃。此外，顶点 D 和 E 位于(-w[c]，+w[c])的值范围内，因此它们保留在视图中。w[c]的值由视口的宽度确定。因此，OpenGL 的投影矩阵（`GL_PROJECTION`）接受 3D 坐标并执行投影，将其转换为可以呈现在 2D 计算机显示屏上的 2D 坐标。尽管可能会丢失一些信息，但它被认为是将 3D 场景渲染到 2D 屏幕上的最有效方法之一。

然而，我们还没有完成——在投影完成后，我们必须将 3D 场景转换为 2D，这需要使用另一个 OpenGL 矩阵变换，称为`GL_MODELVIEW`。然而，这种转换的步骤是相当不同的。首先进行矩阵变换，将坐标系乘以*视距*。

为了将它们转换为 2D 组件，为每个*z*分量提供了。要理解模型视图矩阵，我们必须理解构成其组成部分的两个矩阵：模型矩阵和视图矩阵。模型矩阵在模型世界中执行多个转换，如旋转、缩放和平移，而视图矩阵调整相对于摄像机位置的场景。视图矩阵负责处理对象在玩家观看场景时的外观，类似于第一人称角色的屏幕/视点。

现在我们了解了 OpenGL 的变换矩阵，让我们制作一个简单的程序（`resize.py`），可以相应地调整显示屏的大小：

1.  首先导入 OpenGL。

```py
      from OpenGL.GL import *
      from OpenGL.GLU import *
```

1.  制作一个简单的函数`change_View()`，以显示屏的大小为参数，如下所示：

```py
      def change_View():
          pass
```

1.  从*步骤 3*到*步骤 6*中的代码应该添加到`change_View()`函数中。添加一个对`ViewPort`的函数调用，它以初始值和显示大小为参数，如下所示：

```py
      glViewport(0, 0 , WIDTH, HEIGHT)
```

1.  现在，是时候添加投影矩阵了。要添加`GL_PROJECTION`，我们必须调用`glMatrixMode()`方法，检查被调用的矩阵的模式，如下所示：

```py
      glMatrixMode(GL_PROJECTION) #first step to apply projection matrix
```

1.  在应用投影矩阵后，应调用两个重要的方法，即`glLoadIdentity()`和`gluPerspective()`，它们为投影矩阵设置了“基准”：

```py
      aspect_ratio = float(width/height)
      glLoadIdentity()
      gluPerspective(40., aspect_ratio, 1., 800.)
```

1.  设置投影矩阵后，下一步是设置模型视图矩阵。可以通过调用`glMatrixMode()`方法激活模型视图矩阵模式：

```py
      glMatrixMode(GL_MODELVIEW)
      glLoadIdentity()
```

前面的六个步骤向我们展示了如何调整显示屏，将 3D 场景显示在 2D 显示屏中。*步骤 1*和*步骤 2*专注于导入 OpenGL。在*步骤 3*中，我们调用了`glViewport()`方法，并传递了一个参数，范围从(`0`, `0`)到(`width`, `height`)，这告诉 OpenGL 我们要使用整个屏幕来显示场景。下一步调用了`glMatrixMode()`方法，告诉 OpenGL 每次函数调用都将应用投影矩阵。

*步骤 5*调用了两个新方法，正如`glLoadIdentity()`的签名所述，用于使投影矩阵成为单位矩阵，这意味着投影矩阵的所有坐标都应该更改为`1`。最后，我们调用另一个方法`gluPerspective()`，它设置了分类/标准投影矩阵。您可能已经注意到`gluPerspective()`方法以`glu`开头而不是`gl`，因此，此函数是从 GLU 库中调用的。`gluPerspective`方法传递了四个浮点参数，即相机视点的视场角，宽高比和两个裁剪平面点（近和远）。因此，裁剪是通过`gluPerspective`函数完成的。要了解裁剪是如何完成的，请参考我们在本主题开头讨论的星形几何形状的示例。

现在，是时候将我们学到的知识付诸实践，制作一个与 PyOpenGL 结构交互的程序。我们还将定义另一个属性，使对象更具吸引力。这被称为*颜色属性*。我们将定义一个立方体，以及关于顶点和边的数学信息。

# 理解颜色属性

在现实世界的场景中，与物体相关联的颜色有很多，但是计算机设备并不足够智能或者能力强大到可以区分和捕捉所有这些颜色。因此，几乎不可能在数字形式中容纳每一种可能的颜色。因此，科学家们为我们提供了一种表示不同颜色的方法：*RGB*模式。这是三种主要颜色组件的组合：红色、绿色和蓝色。通过组合这些组件，我们可以创建几乎所有可能的颜色。每个组件的值范围从 0 到 255；对每个组件的代码的更改会导致新的颜色。

OpenGL 中使用的颜色属性与现实世界的颜色反射属性非常相似。我们观察到的物体的颜色实际上并不是它的颜色；相反，它是物体反射的颜色。物体可能具有某种波长的属性，物体可以吸收某种颜色并反射出另一种颜色。例如，树木吸收阳光除了绿色。我们感知并假设它是绿色的，但实际上物体没有颜色。这种光反射的概念在 OpenGL 中得到了很好的应用——通常我们定义一个可能具有明确颜色代码的光源。此外，我们还将定义物体的颜色代码，然后将其与光源相乘。结果的颜色代码或光是从物体反射出来的结果，被认为是物体的颜色。

在 OpenGL 中，颜色以包含四个组件的元组形式给出，其中三个是红色、绿色和蓝色。第四个组件代表 alpha 信息，表示物体的透明级别。在 OpenGL 中，与 RGB 组件的值为 0 到 255 不同，我们提供的值范围是 0 到 1。例如，黄色是红色和绿色的组合，因此它的 alpha 信息是(1, 1, 0)。请参考[`community.khronos.org/t/color-tables/22518`](https://community.khronos.org/t/color-tables/22518)了解更多关于 OpenGL 颜色代码的信息。

以下函数/特性在 OpenGL 的颜色属性中可用：

+   `glClearColor()`: 这个函数设置一个清晰的颜色，这意味着它填充在尚未绘制的区域上的颜色。颜色代码的值可以作为一个元组给出，范围从 0 到 1。例如，`glClearColor(1.0, 1.0, 1.0, 0.0)`表示用白色填充。

+   `glShadeModel()`: 这个函数启用了 OpenGL 的光照特性。通常传递给`glShadeModel`的参数是`GL_FLAT`，用于给形状的面或边缘上色，比如立方体和金字塔。如果你想给曲面对象上色而不是给面体对象上色，你可以使用`GL_SMOOTH`。

+   `glEnable()`: 这实际上不是与颜色属性相关的方法，但是用于启用它们。例如，`glEnable(GL_COLOR_MATERIAL)`将启用*材料*，这允许我们与表面和光源进行交互。此外，通过调整设置，材料的属性主要用于使任何物体更轻和更锐利。

现在我们熟悉了颜色属性的概念和创建颜色属性的方法，让我们编写一个简单的程序，使用 PyOpenGL 的颜色属性来绘制一个立方体。

# 头脑风暴网格

在我们开始编码之前，头脑风暴一下并获取必要的信息总是一个好习惯，这样我们才能创建一个程序。因为我们将创建一个渲染立方体的程序——一个有八个顶点、12 条边和六个面的表面——我们需要明确定义这样的信息。我们可以将这些属性定义为嵌套元组——单个元组内的元组。

以一个顶点作为参考，我们可以同时获取其他顶点的位置。假设一个立方体有一个顶点在（`1`，`-1`，`-1`）。现在，假设立方体的所有边都是 1 个单位长，我们可以得到顶点的坐标。以下代码显示了立方体的顶点列表：

```py
cube_Vertices = (
    (1, -1, -1),
    (1, 1, -1),
    (-1, 1, -1),
    (-1, -1, -1),
    (1, -1, 1),
    (1, 1, 1),
    (-1, -1, 1),
    (-1, 1, 1),
    )
```

同样，有 12 条边（边是从一个顶点到另一个顶点画出的线）。由于有八个顶点（0 到 7），让我们编写一些代码，使用八个顶点定义 12 条边。在以下代码中，作为元组传递的标识符表示从一个顶点到另一个顶点画出的边或面。例如，元组（`0`，`1`）表示从顶点 0 到顶点 1 画出的边：

```py
cube_Edges = (
    (0,1),
    (0,3),
    (0,4),
    (2,1),
    (2,3),
    (2,7),
    (6,3),
    (6,4),
    (6,7),
    (5,1),
    (5,4),
    (5,7),
    )
```

最后，必须提供的最后一部分信息是关于表面的。一个立方体有六个面，每个面包含四个顶点和四条边。我们可以这样提供这些信息：

```py
cube_Surfaces = (
 (0,1,2,3),
 (3,2,7,6),
 (6,7,5,4),
 (4,5,1,0),
 (1,5,7,2),
 (4,0,3,6) 
 )
```

注意提供顶点、边和表面的顺序很重要。例如，在`cube_Surfaces`数据结构中，如果你交换了元组的第二个项目和第一个项目，立方体的形状将会恶化。这是因为每个信息都与顶点信息相关联，也就是说，表面（`0`，`1`，`2`，`3`）包含了第一个、第二个、第三个和第四个顶点。

现在我们已经完成了头脑风暴，并收集了关于我们要绘制的形状的一些有用信息，是时候开始使用 PyOpenGL 及其库来渲染立方体了，这个库通常被称为*GLU 库*。

# 理解 GLU 库

现在我们已经收集了关于我们形状的边、面和顶点的信息，我们可以开始编写模型了。我们已经学习了如何使用`glBegin()`和`glVertex3fv()`等方法使用 OpenGL 绘制形状。让我们使用它们，并创建一个可以绘制立方体结构的函数：

1.  首先导入 OpenGL 和 GLU 库。在导入库之后，将我们在头脑风暴中定义的有关顶点、边和表面的信息添加到同一个文件中：

```py
      from OpenGL.GL import *
      from OpenGL.GLU import *
```

1.  接下来，定义函数并获取表面和顶点。这个过程非常简单；我们将从绘制立方体的表面开始。我们应该使用`GL_QUADS`属性来绘制四面体表面（困惑吗？请参考本章的*使用 OpenGL 制作对象*部分获取更多信息）：

```py
      def renderCube():
          glBegin(GL_QUADS)
          for eachSurface in cube_Surfaces:
              for eachVertex in eachSurface:
                  glColor3fv((1, 1, 0)) #yellow color code
                  glVertex3fv(cube_Surfaces[eachVertex])
          glEnd()
```

1.  最后，在`renderCube()`方法中，编写一些可以绘制线段的代码。使用`GL_LINES`参数来绘制线段：

```py
     glBegin(GL_LINES)
       for eachEdge in cube_Edges:
           for eachVertex in eachEdge:
               glVertex3fv(cube_Vertices[eachVertex])
       glEnd()
```

这个三行的过程足以创建复杂的几何形状。现在，你可以对这些立方体执行多个操作。例如，你可以使用鼠标触控板旋转物体。正如我们所知，处理这样的用户事件需要一个`pygame`模块。因此，让我们定义一个函数，来处理事件，并使用 PyOpenGL 的一些特性。从`import pygame`语句开始你的代码，并添加以下代码：

```py
def ActionHandler():
    pygame.init()
    screen = (800, 500)
    pygame.display.set_mode(screen, DOUBLEBUF|OPENGL) #OPENGL is essential

    #1: ADD A CLIPPING TRANSFORMATION
    gluPerspective(85.0, (screen[0]/screen[1]), 0.1, 50) 

    # 80.0 -> field view of camera 
    #screen[0]/screen[1] -> aspect ration (width/height)
    #0.1 -> near clipping plane
    #50 -> far clipping plane
    glRotatef(18, 2, 0, 0) #start point
```

前面的代码片段非常容易理解，因为我们从本章的开始就一直在做这个。在这里，我们使用了`pygame`模块，它使用 OpenGL 场景或接口设置游戏屏幕。我们添加了一个变换矩阵，它使用`gluPerspective()`函数执行裁剪。最后，我们在实际旋转之前添加了立方体的初始位置（在开始时可能在哪里）。

现在我们已经介绍了 OpenGL 的基本知识，让我们使用 pygame 的事件处理方法来操纵立方体的结构，就像这样：

```py
while True:

        for anyEvent in pygame.event.get():
            if anyEvent.type == pygame.QUIT:
                pygame.quit()
                quit()

            if anyEvent.type == pygame.MOUSEBUTTONDOWN:
                print(anyEvent)
                print(anyEvent.button) #printing mouse event

                #mouse button 4 and 5 are at the left side of the mouse
                #mouse button 4 is used as forward and backward navigation
                if anyEvent.button == 4: 
 glTranslatef(0.0,0.0,1.0) #produces translation 
                      of (x, y, z)
 elif anyEvent.button == 5:
 glTranslatef(0.0,0.0,-1.0)
```

在处理基于鼠标按钮导航的事件之后，让我们使用 PyOpenGL 提供的一些方法来渲染立方体。我们将使用`glRotatef()`等方法来执行矩阵变换。在处理事件的地方之后，写入以下代码：

```py

        glRotatef(1, 3, 1, 1) 
#The glRotatef is used to perform matrix transformation which performs a rotation 
#of counterclockwise with an angle of degree about origin through the point #provided as (x, y, z). 
        #-----------------------------------------------------------------
        #indicates the buffer that needs to be cleared
        #GL_COLOR_BUFFER_BIT: enabled for color drawing
        #GL_DEPTH_BUFFER_BIT: depth buffer which needs to be cleared

        glClear(GL_COLOR_BUFFER_BIT|GL_DEPTH_BUFFER_BIT)

        #render cube
        renderCube()
        pygame.display.flip()
        pygame.time.wait(12)

#call main function only externally
ActionHandler()
```

上述代码的突出部分表示调整大小的变换，最终导致了使用 ZOOM-UP 和 ZOOM-DOWN 功能。现在，您可以运行程序，观察立方体在 pygame 屏幕中心以黄色渲染。尝试使用外部鼠标和导航按钮（按钮 4 和 5）进行放大和缩小。您还可以观察项目中如何使用裁剪：每当我们使一个立方体变得如此之大以至于超出裁剪平面时，立方体的一些部分将从视口中移除。

通过这种方式，我们可以结合两个强大的 Python 游戏模块，即*pygame*和*PyOpenGL*，制作 3D 场景和界面。我们只是简单地介绍了创建一些形状和如何变换它们的方法。现在，轮到您去发现更多关于 PyOpenGL 的知识，并尝试制作一个更加用户友好和吸引人的游戏，提供丰富的纹理和内容。

# 总结

在本章中，我们涵盖了许多有趣的主题，主要涉及表面和几何形状。虽然在本章中我们使用了术语*矩阵*，但我们并没有使用数学方法进行矩阵计算，因为 Python 内置了执行此类操作的一切。尽管如此，我们应该记住这句古老的格言，*游戏程序员不需要拥有数学博士学位*，因为只要我们想制作游戏，基本的数学水平就足够了。在这里，我们只学习了平移、缩放和旋转，如果我们想制作一个 3D 场景，这已经足够了。我们没有陷入使用数学方法进行平移或缩放的概念中——相反，我们学习了使用编程方法。

我们首先学习了如何使用 pygame 的`setting`方法设置 OpenGL 显示屏。由于 OpenGL 是一个广阔而深奥的研究领域，无法在单一章节中涵盖所有内容。因此，我们只涵盖了如何加载/存储三维模型以及如何通过应用裁剪、旋转和调整大小变换将它们应用到 OpenGL 渲染表面上。我们还研究了颜色属性，并将它们与 PyOpenGL 和 pygame 一起使用。本章的主要目标是让您更容易理解如何使用 OpenGL 创建 3D 形状，同时提供关键的几何信息，如顶点、边和表面。现在您将能够使用 OpenGL 创建 3D 形状、图形和可视化。您现在也知道如何将 OpenGL 的颜色属性与其他着色模式区分开来。

在下一章中，我们将学习另一个重要的模块，名为*Pymunk*。这是一个非常强大的物理库，为游戏角色增加了物理能力。我们将学习在需要讨论真实世界环境时使用的不同术语，如速度和加速度，这些术语用于处理碰撞和游戏角色的移动。在学习这些概念的同时，我们还将制作一个愤怒的小鸟游戏，并将其部署到各种平台上。


# 第十五章：通过构建愤怒的小鸟游戏来了解 Pymunk

Python 作为数据科学和机器学习领域的独立语言已有半个世纪之久，但在游戏开发行业并不够流行，直到像 pymunk 这样的开源软件包出现。这些开源软件包为游戏开发人员提供了一个简单的界面，通过模拟来模仿真实世界的环境，从而允许他们创建与玩家输入相关联的单个或多个物体。这一进步将连续物理模型引入了 Python 游戏开发中，其中一些物体被允许休息以提高效率，并且只有在碰撞原则下才会被引入光线。通过这种模型，我们可以正确而有效地处理多个物体的碰撞。

通过本章的学习，您将了解 Pythonic 2D 物理库的基础知识，从而知道如何使用类和子模块来构建像愤怒的小鸟这样的复杂游戏，通过考虑质量、运动、惯性、弹性和力矩等物理属性来模拟真实世界的环境。您还将学习如何创建 2D 刚体并将它们与玩家的输入相关联，以模拟物理冲量。这将导致刚体在模拟环境（空间）内的运动。您还将学习如何使用时间间隔步长（dt）通过更新促进刚体在该空间内运动的物理属性。

到目前为止，您一直在检查两个游戏实体之间的碰撞（在第十一章中，*使用 Pygame 制作 Outdo Turtle - Snake Game UI*，您检查了蛇与边界墙之间的碰撞，而在第十二章*，学习角色动画、碰撞和移动*中，您检查了鸟与垂直管道之间的碰撞），但本章将更加启发人，因为您将逐个检查三个游戏对象之间的碰撞，并通过创建碰撞处理程序执行操作。

本章将涵盖以下主题：

+   了解 pymunk

+   创建角色控制器

+   创建多边形类

+   探索 Pythonic 物理模拟

+   实施弹弓动作

+   处理碰撞

+   创建关卡

+   处理用户事件

+   可能的修改

# 技术要求

您必须具备以下要求才能完成本章：

+   Pygame 编辑器（IDLE）版本 3.5 或更高版本。

+   PyCharm IDE（参考第一章，*了解 Python - 设置 Python 和编辑器*，了解安装过程）。

+   `pymunk`模块（可在[`www.pymunk.org/en/latest/`](http://www.pymunk.org/en/latest/)找到的开源库）。

+   本章的代码可以在本书的 GitHub 存储库中找到：[`github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter15`](https://github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter15)

+   愤怒的小鸟的精灵表外部链接：[`www.spriters-resource.com/mobile/angrybirds/sheet/59982/`](https://www.spriters-resource.com/mobile/angrybirds/sheet/59982/)。

观看以下视频以查看代码的运行情况：

[`bit.ly/2oG246k`](http://bit.ly/2oG246k)

# 了解 pymunk

在现实环境中，物体以各种方向任意移动。因此，为了模仿这种运动，游戏必须处理物体的不同物理行为。例如，当我们把一个物体扔到空中时，由于重力的存在，物体会在某个时刻撞击地面。同样，我们还必须处理每次物体从表面弹回时速度的减小。例如，如果我们拿一个球扔到空中，一段时间后，它必须以原始速度 V[o]撞击地面，然后在表面弹起，以速度 V[f]上升。因此，很明显 V[o] > V[f]。在游戏环境中实现这种物体行为将给玩家留下良好的印象。

作为自然科学的一个分支，物理学试图通过模拟和数学推导来模拟真实世界的行为。物理学定义了不同的术语，如质量、惯性、冲量、弹性、摩擦等。这些术语定义了物体在不同环境中暴露时的特性。不要陷入物理学的复杂性，让我们开始做生意。真正的问题是，为什么我们需要在游戏中加入物理学？这个问题的答案很简单：与现实世界的物体一样，游戏也有物体/角色。这些角色由游戏的玩家控制。大多数玩家喜欢玩模拟真实世界现象的游戏。

在使用`pymunk`模块之前，您必须了解一些物理术语，如下所示：

+   **质量**: 从字面上讲，质量指的是任何物体的重量。在考虑其物理定义时，物体的质量是物体中物质的量的度量。

+   **力**: 力是由物体与另一个物体的*相互作用*而产生的对物体的推或拉。

+   **重力**: 导致苹果向地面掉落的力。重力是吸引两个物体彼此的力。

+   **弹性**: 受变形的物体的属性，它们会重新塑形并恢复到原来的形状。例如，弹簧和橡皮筋即使受到力的作用也会恢复到原来的形状。

+   **力矩**: 力矩是导致物体围绕特定点或轴旋转的属性。

如果您以前没有玩过愤怒的小鸟，请确保查看此链接：[`freeangrybirdsgame.org/play/angry_birds_online.html`](http://freeangrybirdsgame.org/play/angry_birds_online.html)。在玩游戏时，观察角色、结构和弹弓动作的数量。

如果我们愤怒的小鸟游戏中的两个角色（鸟和猪）都有水平移动，那将会很无聊。例如，当玩家从弹弓或弹弓射出一只愤怒的小鸟时，如果它不遵循抛射运动（45 度运动），而只是水平运动（90 度运动）会怎么样？这违反了物理定律之一，即*地球对你产生吸引力*。也许我们可以说这就是为什么这很重要。违反这样的定律会使游戏变得愚蠢和荒谬，这可能会损害游戏的声誉。为了在游戏中模拟这种真实世界的物理现象，Python 社区开发了一个 2D 物理库。我们可以使用这个库为游戏对象应用不同的特性，如质量、惯性、冲量和摩擦。

首先，我建议您查看 pymunk 的官方文档[`www.pymunk.org/en/latest/pymunk.html.`](http://www.pymunk.org/en/latest/pymunk.html)。由于`pymunk`的软件包和模块经常更新，您将在官方文档页面上看到大量资源。只是不要被它们的数量所压倒——我们只需要其中的一些资源来制作使用 pymunk 2D 物理库的游戏。

现在您已经阅读了文档，我假设您可能已经看到了几个子模块和类。我们将需要其中一些，我们将讨论所有这些。我们将从 pymunk 开始，这是最受欢迎和广泛使用的子模块。它被命名为`vec2d`。要观察`vec2d`的工作原理，您必须复习我们在第九章中学到的基础知识，*数据模型实现*。简而言之，我们使用不同的数据模型来实现向量操作（我们使用`__add__（）`来添加向量，`__str__（）`来格式化向量等）。我们已经学习了关于向量操作的知识，但是以一种 Pythonic 的方式；现在，让我们以一种模块化的方式来学习。Python 开发者社区已经为`vec2d`创建了一个子模块；也就是说，`Vec2d`类，以执行任何与向量相关的操作。

在查看`Vec2d`类的示例之前，让我们先设置 PyCharm 项目。打开 PyCharm 编辑器并创建一个新项目。我会称其为*愤怒的小鸟*。提供项目名称后，按“创建”按钮创建项目。当 PyCharm 准备好您的项目后，请创建一个名为`test.py`的新 Python 文件。在编写任何代码之前，我们必须在当前项目中安装`pymunk`模块。

按照以下步骤操作（要获取有关如何在 PyCharm 中安装任何第三方库的详细说明，请参阅第一章，*了解 Python - 设置 Python 和编辑器*）：

1.  单击“文件”|“设置”。将打开“设置”窗口。

1.  在左侧选项卡上，单击“项目：愤怒的小鸟”选项卡。它将列出已在 Python 解释器中安装的所有模块。

1.  要添加新模块，请单击“包”选项卡旁边的(+)按钮。

1.  搜索`pymunk`并安装该模块（确保您的互联网连接正常）。

现在`pymunk`模块已成功安装，让我们回到`Vec2d`类。正如我们之前提到的，这个类可以用来执行向量操作。这是一种替代使用数据模型进行向量操作的方法。让我们看一个使用`Vec2d`类创建向量的简单示例：

```py
from pymunk.vec2d import Vec2d
print(Vec2d(2, 7))

#add two vectors
print(Vec2d(2, 7) + Vec2d((3, 4)))

#results
Vec2d(2, 7)
Vec2d(5, 11)
```

除了执行数学计算之外，`Vec2d`还可以执行不同的高级功能计算。例如，如果您想要找到两个向量之间的距离，我们可以调用“get_distance（）”函数，如下所示：

```py
print(Vec2d(3,4).get_distance(Vec2d(9,0)))
7.211102550927978
```

上述函数使用公式√（x2 − x1）² +（y2 − y1）² 计算两个向量点之间的距离，其中（x1，y1）和（x2，y2）是两个向量坐标。要了解有关距离公式的更多信息，请转到[`www.purplemath.com/modules/distform.htm`](https://www.purplemath.com/modules/distform.htm)。

现在我们已经探索了`Vec2d`，我们将学习关于`pymunk`类。有超过 10 个类，但我们只会学习重要的类。您可以通过访问它们的官方文档页面来了解它们。让我们逐一学习。

# 探索 pymunk 的内置类

首先，我们将从`Space`类开始。这个类指的是所有游戏角色将驻留的占位符。游戏角色的移动也将在此空间中定义。随着游戏的进行，刚性物体的属性（具有质量、摩擦、弹性和惯性等物理属性）将在此空间中发生变化。例如，不同空间中的物体将具有不同的速度和加速度。在愤怒的小鸟游戏中，愤怒的小鸟的速度将与玩家最初从弹弓上射出它然后与游戏中的结构（横梁和柱子，我们将在一分钟内介绍）发生碰撞时不同。

`pymunk`模块中定义了许多方法，因此我们将从最重要的方法开始：`add_collision_handler(collision_type_a, collision_type_b)`。回想一下第十一章，*使用 Pygame 制作贪吃蛇游戏 UI*，你制作了一个贪吃蛇游戏，并自己添加了碰撞处理程序，添加了一些逻辑，暗示*当两个对象的位置相同时，它们被认为发生了碰撞*。这种方法是以更简单的方式做同样的事情，只需调用`pymunk`内置函数。由`pymunk`创建的碰撞处理程序将接受两个参数：`type_a`和`type_b`。您必须记住这两种类型都是整数。我们将使用它们明确定义两个对象。例如，在愤怒的小鸟游戏中，将有三个主要角色：鸟、木头和猪（要下载所需的资源，请查看*技术要求*部分中提到的 GitHub 链接）。由于我们有三个角色，我们必须为每个角色添加碰撞处理程序，如下所示：

+   **当鸟和猪碰撞时**：我们将调用`add_collision_handler(0, 1)`，其中`0`表示鸟角色的整数类型，1 表示猪游戏角色的整数类型。

+   **当鸟和木头碰撞时**：我们将调用`add_collision_handler(0, 2)`，其中`2`表示木头游戏角色的整数类型。（请记住，在整个游戏过程中，0 必须代表鸟角色，不能用于任何其他角色）。

+   **当猪和木头碰撞时**：我们将调用`add_collision_handler(1, 2)`。

通过这样做，我们将感受到`Space`类内定义的碰撞处理程序的强大。此函数检查两个对象是否发生碰撞，并返回`CollisionHander`，用于表示`type_a`和`type_b`之间的碰撞。

现在我们已经了解了如何处理 pymunk 中的碰撞，我们将学习`pymunk`模块中最重要和最常用的两个类：`Body`和`Shape`。首先，我们将开始学习 pymunk`Body`类及其属性。然后，我们将探索 pymunk`Shape`类，学习如何向几何图形添加不同的物理属性，如弹性、质量和力矩。

# 探索 pymunk Body 类

在制作像愤怒的小鸟这样的复杂游戏时，我们必须定义多个游戏角色，比如鸟、猪和木结构。以下插图提供了这些游戏角色的视觉效果：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/435e22c6-65cf-4688-aaf9-6dd2d3186c91.png)

所有这些都是图像（在 Pygame 的意义上，它们是精灵）。除非我们将它们转换为刚体，否则不能直接使用。Pygame 定义物理测量（质量、运动、摩擦和冲量）的方式意味着它将这些精灵转换为刚体。这就是`Body`类的强大之处：`Body`类接受任何形状（圆形、多边形、精灵等）并注入质量、力矩、力和许多其他属性，如下所示：

```py
import pymunk
space = pymunk.Space() #creating Space instance
body = pymunk.Body() #creating Body instance
object = pymunk.Circle(body, 4)
object.density = 2
#print body measurements
print("Mass : {:.0f} and Moment: {:.0f}".format(body.mass, body.moment))

space.add(body, object)
print("Mass: {:.0f} and Moment: {:.0f}",format(body.mass, body.moment))
```

前面代码的结果如下：

```py
Mass : 0 and Moment: 0
Mass: 101 and Moment: 804
```

在上述代码中，我们首先定义了`space`。正如我们之前提到的，`Space`是一个代表物体的占位符的类。仔细看一下`space.add(body, object)`语句：我们使用`add()`方法将对象添加到`space`中。同样，我们创建了`Body`类的一个实例。`Body`类并不一定意味着物体或游戏角色；相反，它是一个虚拟的地方，我们可以在其中添加游戏角色。`object = pymunk.Circle(body, 4)`语句将创建一个半径为`4`单位的圆形物体，并将其添加到`Body`的范围内。创建圆形物体后，我们添加了密度（物体的强度属性：物体所占体积单位质量；请参考以下链接了解有关密度的更多信息：[`www.nuclear-power.net/nuclear-engineering/thermodynamics/thermodynamic-properties/what-is-density-physics/`](https://www.nuclear-power.net/nuclear-engineering/thermodynamics/thermodynamic-properties/what-is-density-physics/)）。

在将`density`属性添加到对象后，我们打印了两个物体：第一个是当物体未添加到空间中时的情况，另一个是圆形物体（连同`density`）添加到空间中的情况。我们打印了两个物体。如预期的那样，第一个物体未添加到空间中，我们没有为该物体定义任何属性，因此其质量和力矩显示为零。同样，在物体添加到`space`后，它们的质量和力矩分别变为 101 和 804 标准单位。

现在，让我们学习另一个重要的`pymunk`模块类，名为`Shape`。

# 探索 pymunk Shape 类

`Shape`类有三个不同的类别：`Circle`、`Poly`和`Segment`。然而，了解`Shape`类本身就足以让我们理解这些类别。让我们学习一下我们可以从以下几点调用形状的一些重要物理属性（全部小写）：

+   `copy()`：执行当前形状的深复制。

+   `density`：形状的密度。这是一个非常重要的属性，用于计算附加形状的物体的质量和转动惯量。我们在*pymunk Body class*部分的示例中看到了这个属性。

+   `elasticity`：定义形状的弹性。此属性用于定义形状的弹跳性质。如果弹性值为 0，则该形状无法弹跳。对于完美的弹跳，弹性值应为 1。

+   `friction`：定义形状的摩擦系数。`0`的`friction`值定义了无摩擦的表面，而`1`定义了完全光滑（无粗糙）的表面。

+   `mass`：定义形状的重量。当`mass`较大时，物体无法弹跳和自由移动。

+   `moment`：计算形状的力矩。

为了观察上述属性的应用，我们不创建`Shape`类的实例。相反，我们使用`Circle`、`Poly`和`Segment`类。

`Circle`类（我们在上一节中使用过）可以这样实例化：

```py
pymunk.Circle(body, radius_of_circular_shape)
```

在圆形物体的情况下，也可以定义密度、弹性、摩擦、质量和力矩等属性。我们将在制作愤怒的小鸟游戏时看到这方面的例子。

同样，我们可以使用`Poly`类创建多边形形状。以下语法表示使用`Poly`类创建实例：

```py
pymunk.Poly(body, vertices, transform = None, radius = 0)
```

在上一行代码中，`body`是`Body`类的实例，代表形状的虚拟空间。`vertices`参数定义了多边形凸包的顶点。凸包是由`Poly`类使用顶点自动计算的。剩下的两个参数，*transform*和*radius*是可选的。`transform`是`Transform`类的对象（参考[`www.pymunk.org/en/latest/pymunk.html#pymunk.Poly`](http://www.pymunk.org/en/latest/pymunk.html#pymunk.Poly)了解更多关于`transform`的信息），它将变换应用到多边形的每个顶点，而`radius`参数设置了创建的多边形形状的半径。

你可能会想知道在制作愤怒的小鸟游戏时`Poly`类的应用是什么。在这个游戏中，我们有两个主要角色，以及由`Poly`类制作的木结构，包括梁和柱。在制作愤怒的小鸟游戏时会进一步讨论这些内容。

最后，我们还有另一个有用的类，称为`Segment`类。让我们来探讨如何创建它的实例：

```py
pymunk.Segment(body, point1, point2, radius)
```

`Segment`类负责定义两点之间的线段形状：`point1`和`point2`。这是一个重要的类，因为它定义了游戏的表面。`radius`参数定义了从`point1`到`point2`绘制的线段的厚度。还可以为这个形状添加一些前面提到的属性，比如`mass`、`density`、`elasticity`和`friction`。大多数情况下，摩擦用于定义游戏表面的粗糙程度。即使在愤怒的小鸟游戏中，我们也可以使用`Segment`类创建游戏表面，并将物体与一定程度的摩擦（0—1）关联起来，这定义了表面的精细度和粗糙度水平。数值 0 代表 100%的精细，而 1 代表完全粗糙。

现在我们已经全面掌握了与`pymunk`模块相关的所有类和属性，我们可以开始编写愤怒的小鸟游戏了。

# 创建一个角色控制器

如果你还没有玩过愤怒的小鸟，我强烈鼓励你去试一试。在网上搜索愤怒的小鸟并玩上几分钟。在玩游戏时，观察主要角色（小鸟和猪）、它们的动作以及它们与木结构的互动。木结构由不同的梁和柱结构组成，其中不同数量的木结构依次嵌套。

在查看原始游戏后，你可以开始编写自己的愤怒的小鸟游戏。我们之前在 PyCharm 中安装`pymunk`模块时制作了愤怒的小鸟项目。我们将使用相同的项目文件夹来创建这个游戏。创建一个新的 Python 文件并命名为`characters.py`。

在这个愤怒的小鸟项目中，我们不会在一个单独的文件中编写整个代码。在编写像愤怒的小鸟这样复杂的游戏时，对于不同的任务，我们创建不同的模块是很重要的。这样做，我们可以在测试游戏时更容易地找到错误。在这个愤怒的小鸟游戏中，我们将创建四个 Python 文件：`characters.py`、`polygon.py`、`main.py`和`level.py`。

我们刚刚创建的第一个文件将包含主要的游戏角色：小鸟和猪。木梁和柱结构将在下一个文件中创建；也就是`polygon.py`。但现在，让我们集中在`characters.py`文件上。

`characters.py`文件将包含两个类：一个是`Bird`，另一个是`Pig`。然后，我们将定义几个属性来控制每个类的运动，也就是物理属性。以下代码表示了`characters.py`文件的内容：

```py
import pymunk as p #aliasing pymunk as p
from pymunk import Vec2d #for vector manipulation
```

在导入必要的模块之后，让我们为`Bird`角色定义一个类（愤怒的小鸟的移动由玩游戏的玩家控制）：

```py

class RoundBird():
    def __init__(self, distance, angle, x_pos, y_pos, space):
        weight = 5
  r = 12 #radius
  value_of_inertia = p.moment_for_circle(weight, 0, r, (0, 0))
        obj_body = p.Body(weight, value_of_inertia)
        obj_body.position = x_pos, y_pos
        power_value = distance * 53
  impulse = power_value * Vec2d(1, 0)
        angle = -angle
        obj_body.apply_impulse_at_local_point(impulse.rotated(angle))
        obj_shape = p.Circle(obj_body, r, (0, 0))
        obj_shape.elasticity = 0.95 #bouncing angry bird
  obj_shape.friction = 1 #for roughness
  obj_shape.collision_type = 0 #for checking collisions later
  space.add(obj_body, obj_shape)
        #class RoundBird attribute ----
  self.body = obj_body
        self.shape = obj_shape
```

在上述代码行中，我们为愤怒的小鸟角色定义了所有的物理和位置属性。我们首先定义构造函数。构造函数的参数如下：

+   两个物体位置之间的`distance`，通常通过距离公式计算（[`www.purplemath.com/modules/distform.htm`](https://www.purplemath.com/modules/distform.htm)），并传递给`Bird`类。

+   `angle`以度为单位执行`Bird`角色的移动。

+   **`x_pos`**，**`y_pos`**表示`Bird`的位置。

+   `space`表示`Bird`被渲染的`space`对象。

在构造函数中，我们为`Bird`角色添加了多个物理属性。例如，`elasticity= 0.95`表示弹跳能力（标准），`friction = 1`（表面粗糙度水平），power = work done（距离）* time（53）。小鸟的质量（重量）为 20，`birdLife`类属性表示每当 Bird 角色与地面或其他角色（Pig 或木结构）发生碰撞时减少的数量。

摩擦、弹性和功都不是随机的（我没有随意使用它们）。它们在官方文档页面上有定义。请参考以下网址查看图表：[`www.pymunk.org/en/latest/pymunk.html#pymunk.Shape`](http://www.pymunk.org/en/latest/pymunk.html#pymunk.Shape)。

`Bird`类的两个重要方法（在上述代码中突出显示）是由`pymunk`模块定义的内置函数。第一个方法`moment_for_circle()`计算空心圆的转动惯量（任何物体对其速度变化的抵抗）。传递给函数的参数是物体的*质量*，即*内半径*和*外半径*。观察传递为`0`的内半径，这意味着愤怒的小鸟（游戏的主要角色）是一个实心圆。如果内半径是`0`，这意味着这是一个实心圆形物体。外半径定义了愤怒的小鸟的圆形尺寸。同样，观察`collision_type = 0`属性。这个语句将为 Bird 游戏角色添加整数类型。在使用`add_collision_handler(type_a, type_b)`检查两个对象之间的碰撞时，我们使用这个碰撞类型值来表示角色的`0`值是`Bird`。对于`Bird`角色，我们的碰撞类型等于`0`。`Pig`类将其碰撞类型定义为`1`。

同样，下一个方法`apply_impulse_at_local_point(impulse, point = (0, 0))`将对物体施加局部冲量。这将表示当施加力时愤怒的小鸟的动量将发生多大变化。参考[`study.com/academy/lesson/impulse-definition-equation-calculation-examples.html`](https://study.com/academy/lesson/impulse-definition-equation-calculation-examples.html)了解更多关于冲量和动量的知识。

接下来，我们需要为`Pig`角色定义类。以下代码应该在`Bird`类之后编写：

```py

class RoundPig():
    def __init__(self, x_pos, y_pos, space):
        self.life = 20 #life will be decreased after 
          collision of pig with bird
  weight = 5
  r = 14 #radius
  value_of_inertia = p.moment_for_circle(weight, 0, r, (0, 0))
        obj_body = p.Body(weight, value_of_inertia)   
 #creates virtual space to render shape  obj_body.position = x_pos, y_pos
        #add circle to obj body
  obj_shape = p.Circle(obj_body, r, (0, 0))
        obj_shape.elasticity = 0.95
  obj_shape.friction = 1
  obj_shape.collision_type = 1
  space.add(obj_body, obj_shape)
        self.body = obj_body
        self.shape = obj_shape
```

上述代码与`Bird`类类似。与之前一样，我们为`Pig`角色定义了相同级别的弹性和摩擦。我们为对象添加了惯性和质量效应。对于`Pig`角色，`collision_type`被添加为`1`，这意味着在检查 Pig 和 Bird 之间的碰撞时，我们可以简单地调用`add_collision_handler(0, 1)`，其中`0`表示 Bird，`1`表示 Pig。

现在我们已经为愤怒的小鸟游戏创建了两个主要的类，即`RoundBird`和`RoundPig`，在`characters.py`文件中，我们将创建另一个游戏角色，即木结构（横梁和柱子）。

# 创建多边形类

对于每个游戏实体，我们都创建了单独的类，即 Bird 和 Pig。由于我们最终的游戏实体是木结构（玩家用弹弓射击的目标），我们将创建一个不同的 Python 文件，并为该实体创建一个类。但在此之前，让我们先了解有关精灵表的一个重要概念。

在 Python 游戏开发中使用的图像通常称为精灵，它们是静态图像，基于用户的操作（例如在键盘上点击箭头键时移动蛇）进行一些操作（矢量移动）。在前几章中（第十二章，*了解角色动画、碰撞和移动*，和第十三章，*使用 Pygame 编写俄罗斯方块游戏*），我们使用了精灵（单个图像），但没有使用精灵表（包含多个静态图像的表）。以下是一个精灵表的示例，特定于我们的愤怒的小鸟游戏：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/8fc3993a-cdcb-416e-8e57-0c281a714bcb.png)

这些图像文件通常不包含游戏角色的单个图像。正如您所看到的，它们通常包含大量不同的游戏角色。但大多数情况下，我们只需要整个精灵表中的单个图像。因此，问题是，我们如何从这样的精灵表中提取单个图像？我们使用`Pygame`模块的`Rect`类来实现。您还记得 Pygame 模块中的`Rect`类（第十一章，*使用 Pygame 创建 Outdo Turtle-蛇游戏 UI*）吗？该类基于左、上、宽度和高度维度创建一个矩形对象。为了从上述精灵表中提取图像，我们将在其中一个精灵周围绘制一个矩形，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/b14363a3-3d91-4b5b-8802-46f4df5f996e.png)

这种映射是通过`Rect`类的帮助完成的。`Rect`类将创建一个具有四个屏幕点（左、上、宽度和高度）尺寸的矩形。通过更改`Rect`对象的任何四个维度，我们可以提取精灵表的部分或子表面。

现在，让我们通过创建一个木结构来看看它的作用。首先，从以下 GitHub 链接下载精灵资源：[`github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter15/res`](https://github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter15/res)。您将看到各种图像，以及代码资源。`res`文件夹内将有两个文件夹：一个用于照片，另一个用于声音。您必须复制整个文件夹并将其粘贴到 PyCharm 编辑器中愤怒的小鸟项目文件夹中。

导入资源后，我建议您打开`wood.png`文件。该文件包含不同的木结构。在创建多边形时，我们必须使用`Rect`类裁剪其中一个图像。

在同一个愤怒的小鸟项目中，创建另一个名为`polygon.py`的 Python 文件。我们将从导入必要的模块开始：

```py
import pymunk as pym
from pymunk import Vec2d
import Pygame as pg
import math
```

现在，让我们创建`Polygon`类：

```py
class Polygon():
    def __init__(self, position, length, height, space, mass=5.0):
        value_moment = 1000
  body_obj = pym.Body(mass, value_moment)
        body_obj.position = Vec2d(position)
        shape_obj = pym.Poly.create_box(body_obj, (length, height))
        shape_obj.color = (0, 0, 255)
        shape_obj.friction = 0.5
  shape_obj.collision_type = 2 #adding to check collision later
  space.add(body_obj, shape_obj)
        self.body = body_obj
        self.shape = shape_obj
       wood_photo = 
          pg.image.load("../res/photos/wood.png").convert_alpha()
 wood2_photo = 
          pg.image.load("../res/photos/wood2.png").convert_alpha()
 rect_wood = pg.Rect(251, 357, 86, 22)
 self.beam_image = wood_photo.subsurface(rect_wood).copy()
 rect_wood2 = pg.Rect(16, 252, 22, 84)
 self.column_image = wood2_photo.subsurface(rect_wood2).copy()
```

我们为`Polygon`类定义的属性与我们为`Bird`和`Pig`类所做的非常相似：我们初始化了摩擦力，并添加了`collision_type`，以便用整数`2`引用多边形形状。构造函数接受一个参数，即`position`，告诉我们要渲染的多边形的位置，多边形的长度和高度，将渲染多边形的`space`对象，以及多边形形状的`mass`。

在上述代码中唯一的新颖之处是代码的高亮部分。我们使用 Pygame 的`load`方法将`wood.png`和`wood2.png`图像加载到 Python 项目中。`convert_alpha()`方法充当优化器，并将创建一个适合快速 blitting 的新图像表面。`Rect`类需要四个维度来创建一个矩形表面（参见第十一章，*使用 Pygame 制作贪吃蛇游戏 UI*）。提供的尺寸值并非随机给出，而是代表我们需要提取的精灵表面的子表面的值。例如，`self.beam_image = wood.subsurface(rect).copy()`命令将从`wood.png`文件中提取水平横梁图像（由红色矩形包围的木块），如下所示；

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/d6bcbc7a-2df6-4a23-a251-a9414936d9de.png)

现在我们已经提取了水平和垂直的木质图像（横梁和柱子），我们可以开始绘制包含它们的多边形。然而，出现了一个问题。尽管我们一直在使用 Pygame 和`pymunk`，但它们的坐标系统并不相同：`pymunk`使用的坐标系统的原点在左下角，而 Pygame 则使用的坐标系统的原点在左上角。因此，我们将编写一个函数，将`pymunk`坐标系统转换为兼容的 Pygame 坐标系统：

```py
def convert_to_pygame(self, pos):
    """Function that will transform pymunk coordinates to 
         Pygame coordinates"""
  return int(pos.x), int(-pos.y+610)
```

上述函数很重要，因为游戏表面将由`Pygame`模块制作。因此，我们必须跟踪横梁和柱子必须呈现的位置。现在，让我们开始在表面上绘制`polygon`：

```py
def draw_poly(self, element, screen):
    """Draw beams and columns"""
  polygon = self.shape

    if element == 'beams':
        pos = polygon.body.position
        pos = Vec2d(self.convert_to_pygame(pos))
        angle_degrees = math.degrees(polygon.body.angle)
        rotated_beam = pg.transform.rotate(self.beam_image,
  angle_degrees)
 offset = Vec2d(rotated_beam.get_size()) / 2.
  pos = pos - offset
 final_pos = pos
 screen.blit(rotated_beam, (final_pos.x, final_pos.y))
```

上述函数将用于在屏幕上放置一个横梁，其中一个对象作为参数传递给它。函数的第一个参数是*element*，告诉函数要绘制哪个多边形：是横梁还是柱子？我们将在下面的代码中添加一些逻辑来绘制柱子，但现在让我们观察到目前为止我们已经写的内容。代码首先获取*shape*对象。然后，我们检查元素是否为`beam`。如果是`beam`，那么我们获取图像的位置并将其转换为`Vec2d`坐标位置。代码的高亮部分（获取旋转横梁图像的角度）将确保横梁图像在红色矩形（虚拟）区域内，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/26e3cbaf-cfb1-4870-bf97-c7e89d53e932.png)

只需从上述代码中删除高亮行并观察结果。您会发现由于`Vec2d`坐标系统的偏移，横梁不会完全对齐。同样，让我们添加一些代码，以便我们可以将柱子绘制到屏幕上：

```py
if element == 'columns':
    pos = polygon.body.position
    pos = Vec2d(self.convert_to_pygame(pos))
    angle_degrees = math.degrees(polygon.body.angle) + 180
  rotated_column = pg.transform.rotate(self.column_image,
  angle_degrees)
 offset = Vec2d(rotated_column.get_size()) / 2.
  pos = pos - offset
 final_pos = pos
    screen.blit(rotated_column, (final_pos.x, final_pos.y))
```

在上述代码中，前几行将`pymunk`坐标转换为 Pygame 坐标。由于柱子应该在 Pygame 表面上呈现，因此这种转换是必要的。同样，在获取位置坐标之后，我们取一个坐标角度，并确保向其添加 180 或 0，以使其保持原始图像而不旋转。获取图像后，我们对其进行变换，并创建一个新图像作为`rotated_column`图像。请记住，如果旋转角度不是 90 的倍数，图像将会变形。在上一行代码中，如果不从旋转图像中移除`offset`，则图像将向下移动表面，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/57833fcb-c2b1-4370-a67a-c2dcda32c369.png)

在上述截图中，红线代表表面。因此，如果不从柱子的体位置中移除偏移量，柱子将显示在表面下方。

现在我们已经完成了`Polygon`类，该类在从主类中调用`draw_poly()`函数时将渲染横梁或柱子，现在是时候制作我们的主类了，这是所有类的指导者。这个类将负责创建所有类的实例，并调用不同类中定义的方法来将游戏对象渲染到 Pygame 游戏表面中。

# 探索 Python 的物理模拟

首先，让我们从回顾我们迄今为止所做的工作开始。我们首先定义了两个主要的游戏实体：`Bird`和`Pig`。为了模拟真实世界的物理现象，为这些角色定义了所有主要的物理属性，如质量、惯性和摩擦力。在创建了这两个主要的游戏角色之后，我们又创建了另一个 Python 文件，以便我们可以创建`Polygon`类。这个类是为了在游戏中渲染木结构，借助横梁和柱子。现在，我们将创建另一个名为`main.py`的 Python 文件。这将是游戏的主控制器。

使用以下代码在`main.py`文件中声明基本物理。我们将从导入一些必要的模块开始：

```py
import os
import sys
import math
import time
import Pygame
import pymunk
from characters import RoundBird #our characters.py file have Bird class
```

在导入了必要的模块之后，我们需要从之前添加的精灵中裁剪一些子表面。显然，我们不希望从精灵表中获取所有内容，因此我们将只提取其中的部分内容来创建游戏角色。然而，由于我们的主要角色，愤怒的小鸟，只有一个图像，并且不在精灵表中，我们不需要为愤怒的小鸟和弹弓裁剪图像。然而，对于`Pig`角色，我们必须创建一个`Rect`对象，因为`Pig`图像在精灵表中是捆绑在一起的。因此，我们将使用以下代码加载图像：

```py
Pygame.init()
screen = Pygame.display.set_mode((1200, 650))
redbird = Pygame.image.load(
 "../res/photos/red-bird3.png").convert_alpha()
background_image = Pygame.image.load(
 "../res/photos/background3.png").convert_alpha()
sling_image = Pygame.image.load(
 "../res/photos/sling-3.png").convert_alpha()
full_sprite = Pygame.image.load(
 "../res/photos/full-sprite.png").convert_alpha()
rect_screen = Pygame.Rect(181, 1050, 50, 50)
cropped_image = full_sprite.subsurface(rect_screen).copy()
pig_image = Pygame.transform.scale(cropped_image, (30, 30)) 
#(30, 30) resulting height and width of pig 
```

在前面的代码中，我们首先使用 Pygame 模块定义了一个游戏屏幕。之后，我们加载了所有存在的单个图像的图像，而不是精灵表，比如`red-bird3.png`、`background3.png`和`sling-3.png`。正如我们之前提到的，猪的图像是`full-sprite.png`中一组图像的一部分。由于我们只需要一张猪的图像，我们将执行类似于提取横梁和柱子时进行的过程。我们将创建一个具有猪形状确切尺寸的`Rect`对象，然后使用它从精灵表中提取猪的图像。然后，我们将裁剪该图像并将其存储为一个裁剪对象，最终将其转换为高度和宽度分别为`30`、`30`的对象。

现在我们已经提取了游戏对象所需的图像，让我们开始通过声明每个对象的物理变量和位置变量来认真对待这项工作：

```py
running = True  #base physics code space_obj = pymunk.Space()
space_obj.gravity = (0.0, -700.0)
```

正如我们所知，愤怒的小鸟游戏是通过使用鼠标拉伸弹弓进行弹射动作来进行的。因此，我们必须声明一些变量来处理这些弹弓动作：

```py
mouse_distance = 0 #distance after stretch rope_length = 90  angle = 0 mouse_x_pos = 0 mouse_y_pos = 0   mouse_pressed = False time_of_release = 0   initial_x_sling, initial_y_sling = 135, 450 #sling position at rest (not stretched) next_x_sling, next_y_sling = 160, 450
```

在前面的代码中，我们已经定义了不同的变量，以便在弹弓动作之前和之后跟踪鼠标的位置。我们将在之后声明`sling_action()`函数，该函数将操作这些值。现在，让我们创建一个列表，用于跟踪在空间中显示的猪、鸟、横梁和柱子的数量：

```py
total_pig = []
total_birds = []
beams = []
columns = []
#color code WHITE = (255, 255, 255)
RED = (255, 0, 0)
BLACK = (0, 0, 0)
BLUE = (0, 0, 255)
```

现在我们已经为愤怒的小鸟游戏定义了所有必要的变量（如果需要，我们将稍后添加更多变量），现在是时候为屏幕创建一个表面了。这个表面不是一个背景表面；相反，它是所有结构所在的一些地面。愤怒的小鸟也会从这个表面上弹起，因此我们必须为这个地面添加一些物理属性，如下所示：

```py
# Static floor static_floor_body = pymunk.Body(body_type=pymunk.Body.STATIC)
static_lines_first = [pymunk.Segment(static_floor_body, (0.0, 060.0), (1200.0, 060.0), 0.0)]
static_lines_second = [pymunk.Segment(static_floor_body, (1200.0, 060.0), (1200.0, 800.0), 0.0)]

#lets add elasticity and friction to surface for eachLine in static_lines_first:
    eachLine.elasticity = 0.95
  eachLine.friction = 1
  eachLine.collision_type = 3
  for eachLine in static_lines_second:
    eachLine.elasticity = 0.95
  eachLine.friction = 1
  eachLine.collision_type = 3 space_obj.add(static_lines_first)
```

前面的代码行将创建一些静态地面。在实例化静态物体时，我们可以通过添加`pymunk.Body.STATIC`常量来明确设置`body-type`为`STATIC`。在定义静态物体之后，我们必须使用`Segment`类来创建一条线段，连接一个点和另一个点（回想一下*探索 pymunk Space 类*部分中的`Segment`类）。对于每个线段，我们已经添加了`elasticity`来支持弹跳属性，`friction`来表示粗糙度，以及`collision_type`来检查其他游戏对象是否与地面表面发生碰撞，这将在*检查碰撞*部分中稍后进行检查。在创建这些静态表面之后，我们将它们添加到`Space`对象中，这将把它们渲染到屏幕上。

在定义静态表面之后，我们需要定义弹弓动作，即玩家在拉动弹弓绳索时会发生什么。我们将在下一节中实现这一点。

# 实施弹弓动作

在这一节中，我们将实施弹弓动作。玩家将通过弹弓动作与游戏角色进行交互。但在实施弹弓动作之前，我们必须注意一些事情：玩家可以拉动弹弓绳索多远？冲量的角度是多少（玩家释放绳索后的运动轨迹）？鼠标动作点与绳索当前伸展点之间的距离是多少？所有这些问题都必须通过声明函数来解决。首先，我们需要将 pymunk 坐标转换为 Pygame 坐标，以便我们可以正确地将游戏对象与屏幕对齐（这种转换的原因在*创建多边形类*部分中讨论过）。

以下函数将把`pymunk`坐标转换为 Pygame 坐标：

```py
def convert_to_pygame(pos):
    """ function that performs conversion of pymunk coordinates to
        Pygame coordinates"""
  return int(pos.x), int(-pos.y+600)
```

尽管 pymunk 的*x*坐标与 Pygame 的*x*坐标相同，但由于 pymunk 的原点在左下角，我们必须将其更改为左上角。同样，让我们定义另一个函数，即`vector`，它将把传递的点转换为向量。以下代码表示`vector`函数的实现：

```py
def vector(a, b):
    #return vector from points
  p = b[0] - a[0]
    q = b[1] - a[1]
    return (p, q)
```

参考第九章，*数据模型实现*，了解更多关于如何使用位置向量创建向量的信息。这里，参数*a*和*b*表示从参考点转换为向量的点。现在我们已经创建了一个向量，让我们定义一个函数，它将返回两点之间的距离：

```py
def distance(x0, y0, x1, y1):
    """function to calculate the distance between two points"""
  dx = x1 - x0
    dy = y1 - y0
    dist = ((dx ** 2) + (dy ** 2)) ** 0.5
  return dist
```

前面的代码将计算两点之间的距离公式，即`(x0, y0)`和`(x1, y1)`，使用`sqrt((x1 - x0) + (y0 - yo))`距离公式，其中`sqrt`代表`平方根 (math.sqrt(4) = 2)`。**运算符代表幂。例如，`dx ** 2`等同于`(dx)²`。

现在我们已经计算出距离，我们需要学习如何计算单位向量。单位向量是具有大小为 1 的向量。我们并不真正关心大小，但单位向量的重要性在于它告诉我们向量的方向。一旦我们有了单位向量，我们就可以通过任何因子放大它，以获得特定方向的新向量。在创建弹弓动作时，了解单位向量的重要性很重要，因为这将为我们提供有关弹弓伸展方向的信息。要找到与向量相同方向的单位向量，我们必须将它除以它的大小。使用数学推导，让我们构建一个函数并创建一个单位向量：

```py
def unit_vector(v):
    """ returns the unit vector of a point v = (a, b) """
    mag = ((v[0]**2)+(v[1]**2))**0.5
  if mag == 0:
        mag = 0.000000000000001
  unit_p = v[0] / mag #formula to calculate unit vector: vector[i]/magnitude
    unit_q = v[1] / mag
    return (unit_p, unit_q)
```

在前面的代码中，h 的值由`sqrt(a² + b²)`大小公式确定。要找到单位向量，向量的每个分量(`v[0]`, `v[1]`)都要除以大小(`mag`)。

现在，我们已经声明了不同的函数来定义弹弓动作的位置、大小和方向，我们可以开始定义执行弹弓动作的方法。下图表示了弹弓，它有两端，但没有绳子连接：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/6db8057c-d225-45c0-9c97-58a21268b9e5.png)

在这里，我们的主要任务将是将小鸟（主角）添加到这个弹弓上，并为其定义位置。让我们从在`sling_action`中定义一些全局变量开始：

```py

def sling_action():
    """will Set up sling action according to player input events"""
  global mouse_distance
    global rope_length
    global angle
    global mouse_x_pos
    global mouse_y_pos
```

在上一行代码中，我们声明了一些全局变量。然而，这些属性在*探索 Python 物理模拟*部分的开头被初始化为一些初始值。这意味着我们将不得不进行一些操作来更新这些变量的值。`mouse_distance`变量将包含从弹弓静止位置到玩家拉伸弹弓绳索的位置的距离值。同样，`rope_length`表示玩家拉伸弹弓绳索时的绳长。角度表示冲量的角度，它被计算为斜率角度。弹弓绳索的斜率表示玩家拉伸时绳索的陡峭程度。`mouse-x-pos`和`mouse-y-pos`表示弹弓绳索被拉伸时鼠标的当前位置。

现在，在`sling_action`函数中，我们需要解决三件事：

1.  将愤怒的小鸟添加到弹弓的绳索上（如下面的截图所示）。

1.  使小鸟停留在绳索上，即使弹弓的绳索被拉伸。

1.  解决弹弓绳索被完全拉伸的情况。

要了解这些事件是什么，请看下面的图片：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/5635bd69-faaa-46bf-8169-e990b113e4c0.png)

现在，让我们在`sling_action`函数中解决所有上述的行动：

```py
#add code inside sling_action function """ Fixing bird to the sling rope (Addressing picture 1)""" vec = vector((initial_x_sling, initial_y_sling), (mouse_x_pos, mouse_y_pos))
unit_vec = unit_vector(vec)
uv_1 = unit_vec[0]
uv_2 = unit_vec[1]

mouse_distance = distance(initial_x_sling, initial_y_sling, mouse_x_pos, mouse_y_pos) 
#mouse_distance is a distance between sling initials point to the point at which currrent bird is 
fix_pos = (uv_1*rope_length+initial_x_sling, uv_2*rope_length+initial_y_sling)
highest_length = 102 #when stretched
```

上述代码将在弹弓动作中为愤怒的小鸟角色创建一个视图。首先，通过两个坐标点（`sling_original`，`mouse_current`）创建了`v`向量，例如，((2, 3), (4, 5))，其中(2, 3)表示静止位置的弹弓或弹弓的中心点，而(4, 5)表示玩家激活鼠标动作时的位置。我们将从这个向量创建一个单位向量，以了解玩家拉伸的方向。然后，我们将计算`mouse_distance`，通过调用先前定义的`distance()`函数来计算。这个距离表示从静止弹弓中心到当前鼠标位置的距离。(`mouse_x_pos`，`mouse_y_pos`)的值表示绳索被拉伸后小鸟的最终位置。`uv_1`和`uv_2`单位向量将确保小鸟保持在绳索上，这由鼠标的位置表示。例如，如果鼠标指针指向上方，绳索和小鸟将向上拉伸。

类似地，让我们解决第二种情况，即使愤怒的小鸟在绳索被完全拉伸时仍然停留在绳索上。我们将在以下代码中实现它：

```py
#to make bird stay within rope x_redbird = mouse_x_pos - 20 y_redbird = mouse_y_pos - 20 if mouse_distance > rope_length:
    pux, puy = fix_pos
    pux -= 20
  puy -= 20
  first_pos = pux, puy
    screen.blit(redbird, first_pos)
    second_pos = (uv_1*highest_length+initial_x_sling, uv_2*highest_length+initial_y_sling) #current position ==> second_pos

 Pygame.draw.line(screen, (255, 0, 0), (next_x_sling, next_y_sling), second_pos, 5) 
    #front side catapult rope
  screen.blit(redbird, first_pos)
    Pygame.draw.line(screen, (255, 0, 0), (initial_x_sling, initial_y_sling), second_pos, 5)  
 #ANOTHER SIDE of catapult
```

在上述代码中发生了很多事情，但这些操作更容易和更数学化。你必须试着理解逻辑，而不是试图理解语法。让我们深入代码，揭示每行代码背后的原因。我们首先将鼠标位置减少 20 个单位，以确保在拉伸时，鸟仍然停留在绳子的边缘。尝试将这个值改为 40 并观察效果。接下来，我们检查`mouse_distance`是否大于`rope_length`，以确保拉伸的距离在限制范围内。我们不希望鼠标距离大于最大绳长。在这种情况下，我们将取鼠标距离并将其减少，直到它小于绳子的最大长度。

之后，我们将在绳子的末端`blit`红色小鸟（愤怒的小鸟图像）。同样，我们也必须`blit`绳子。在前面的图片中，观察绳子拉动的地方，绳子变成了红色。如果我们从静态弹弓的中心`blit`绳子到最大可能的长度，就会产生这种红色。观察代码的粗体部分；我们已经画了一条代表绳子的线，颜色代码为（255, 0, 0），也就是红色。这有两个语句：一个在每一边。因此，我们已经实现了用户将绳子拉伸到其最大定义长度的条件。

现在，我们必须解决第三种情况，也就是当玩家将绳子拉到最大长度时会发生什么？在前一行代码中，我们检查了`if mouse_distance > rope_length`，因此如果玩家拉伸小于`rope_length`，它应该在代码的`else`部分中解决，如下所示：

```py
else:
    #when rope is not fully stretched
  mouse_distance += 10
  third_pos = (uv_1*mouse_distance+initial_x_sling, 
      uv_2*mouse_distance+initial_y_sling)
    Pygame.draw.line(screen, (0, 0, 0), (next_x_sling, next_y_sling), 
      third_pos, 5)
    screen.blit(redbird, (x_redbird, y_redbird))
    Pygame.draw.line(screen, (0, 0, 0), (initial_x_sling, 
       initial_y_sling), third_pos, 5)
```

与前面的代码类似，我们使距离不小于 10，这意味着当用户稍微拉伸绳子时，它的`mouse_distance`将等于或大于 10。然后，我们创建`third_pos`来定义渲染绳子和愤怒的小鸟的位置。`uv_1`和`uv_2`是指示拉伸方向的单位向量。在获得位置后，我们`blit`愤怒的小鸟，然后画一条线表示绳子。这将是黑色的，并且将在前面和后面完成。

现在，我们已经为所有情况定义了场景，让我们添加一行代码来计算冲动的角度。只要绳子有拉伸，就会产生这个角度。tan（冲动角度）等于拉伸绳子的斜率。斜率被定义为上升除以下降或（`dy`/`dx`），其中`dy`是`y`的变化，`dx`是`x`的变化。因此，冲动角度可以计算为`tan^(-1)(dy / dx)`。要了解有关此公式的起源和应用的更多信息，请查看[`www.intmath.com/plane-analytic-geometry/1b-gradient-slope-line.php`](https://www.intmath.com/plane-analytic-geometry/1b-gradient-slope-line.php)。

让我们使用这个公式来计算冲动的角度，如下所示：

```py
#this is angle of impulse (angle at which bird is projected)
change_in_y = mouse_y_pos - initial_y_sling
change_in_x = mouse_x_pos - initial_x_sling
if change_in_x == 0: 
    #if no change in x, we make fall within the area of sling
    dx = 0.00000000000001 angle = math.atan((float(change_in_y))/change_in_x) #tan-1(dy / dx)
```

冲动的前角度将是确定愤怒的小鸟在弹弓动作后路径的必要条件。

最后，我们已经完成了弹弓动作。现在，让我们跳到下一节，解决两个游戏对象之间的碰撞。

# 解决碰撞

回顾一下，回答以下问题：我们如何知道两个游戏对象何时发生了碰撞？你有答案吗？每当两个对象在坐标系内的相同位置时，它们被认为发生了碰撞。然而，在 pymunk 的情况下，我们不需要检查是否发生了碰撞。相反，一个方法调用将为我们检查这一点。例如，调用`space.add_collision_handler(0, 1)`将添加一个碰撞处理程序，以检查鸟和猪角色之间是否发生了碰撞。这里，`0`整数代表了`Bird`类内部定义的`collision_type`。`Pig`类定义的`collision_type`是`1`。因此，这些`collision_type`必须是唯一的，以便每个游戏实体可以唯一地识别它们。

尽管我们有一个更简单的方法来添加一个处理程序来检查碰撞，但程序仍然要求细节；也就是说，当两个游戏对象发生碰撞时会发生什么？必须执行什么操作？这是通过使用`post_solve`来解决的。我们将明确告诉碰撞处理程序，如果*X*和*Y*之间发生碰撞，那么应该调用特定的方法；例如，`space.add_collision_handler(0, 1).post_solve = perform_some_action`。

每当游戏对象之间发生碰撞时，让我们定义每个动作。我们将首先定义一个必须在 Bird 和 Pig 之间发生碰撞时执行的动作。让我们编写一个执行此操作的函数：

```py
def post_solve_bird_pig(arbiter, space_obj, _):
    """Action to perform after collision between bird and pig"""   object1, object2 = arbiter.shapes #Arbiter class obj
  bird_body = object1.body
    pig_body = object2.body
    bird_position = convert_to_pygame(bird_body.position)
    pig_position = convert_to_pygame(pig_body.position)
    radius = 30
  Pygame.draw.circle(screen, (255, 0, 0), bird_position, radius, 4)  
 #screen => Pygame surface  Pygame.draw.circle(screen, RED, pig_position, radius, 4)
    #removal of pig
  pigs_to_remove = []
    for pig in total_pig:
        if pig_body == pig.body:
            pig.life -= 20 #decrease life
  pigs_to_remove.append(pig)

    for eachPig in pigs_to_remove:
        space_obj.remove(eachPig.shape, eachPig.shape.body)
        total_pig.remove(eachPig)
```

在上述代码中，该方法接受一个`Arbiter`类的对象：`arbiter`。`arbiter`对象将封装所有碰撞的对象/形状，甚至存储所有碰撞对象的位置。由于游戏对象被绘制到 Pygame 屏幕中，我们需要知道它们在 Pygame 坐标系中的确切位置。因此，需要将 pymunk 坐标转换为 Pygame 坐标。类似地，我们为`post_solve`函数定义的过程是在 Pig 和 Bird 之间发生碰撞后立即执行的动作。该动作将减少猪的生命，然后最终将其从空间中移除。`space.remove()`语句将从屏幕中移除游戏对象。

同样，让我们定义另一个必须在 Bird 和木结构之间发生碰撞后执行的动作。与前面的代码类似，在碰撞后，木梁和柱必须从空间或屏幕中移除。以下函数将处理此类动作：

```py
def post_solve_bird_wood(arbiter, space_obj, _):
    """Action to perform after collision between bird and wood structure"""
  #removing polygon
  removed_poly = []
    if arbiter.total_impulse.length > 1100:
        object1, object2 = arbiter.shapes
        for Each_column in columns:
            if object2 == Each_column.shape:
                removed_poly.append(Each_column)
        for Each_beam in beams:
            if object2 == Each_beam.shape:
                removed_poly.append(Each_beam)
        for Each_poly in removed_poly:
            if Each_poly in columns:
                columns.remove(Each_poly)
            if Each_poly in beams:
                beams.remove(Each_poly)
        space_obj.remove(object2, object2.body)
        #you can also remove bird if you want
```

与以前类似，`arbiter`对象将保存有关碰撞形状和位置的信息。在这里，`total_impulse`属性将返回应用于解决碰撞的冲量。要了解有关`Arbiter`类的更多信息，请转到[`www.pymunk.org/en/latest/pymunk.html`](http://www.pymunk.org/en/latest/pymunk.html)。现在，在获取碰撞的影响后，我们将检查`arbiter`是否具有`beam`或`column`的形状，因为 arbiter 对象将包含碰撞对象的列表。在循环遍历`arbiter`对象内存储的`beam`和`column`之后，我们将其从空间中移除。

最后，我们将处理最后的碰撞——当`Pig`与木结构发生碰撞时必须执行的动作。让我们添加一个实现它的方法：

```py
def post_solve_pig_wood(arbiter, space_obj, _):
    """Action to perform after collision between pig and wood"""
  removed_pigs = []
    if arbiter.total_impulse.length > 700:
        pig_shape, wood_shape = arbiter.shapes
        for pig in total_pig:
            if pig_shape == pig.shape:
                pig.life -= 20    if pig.life <= 0: #when life is 0
  removed_pigs.append(pig)
    for Each_pig in removed_pigs:
        space_obj.remove(Each_pig.shape, Each_pig.shape.body)
        total_pig.remove(Each_pig)

```

与前两种方法类似，此函数还将检查`arbiter`对象的内容，该对象负责封装有关碰撞对象的形状和碰撞发生位置的所有信息。使用`Arbiter`类对象的内容，我们已经检查了冲击后的长度，然后要么删除了`Pig`角色，要么减少了其生命单位。

下一步是添加碰撞处理程序。由于我们已经声明了所有必须在两个对象之间发生碰撞后执行的`post_solve`动作，让我们使用`post_solve`将其添加到碰撞处理程序中，如下所示：

```py
# bird and pigs space.add_collision_handler(0, 1).post_solve=post_solve_bird_pig
# bird and wood space.add_collision_handler(0, 2).post_solve=post_solve_bird_wood
# pig and wood space.add_collision_handler(1, 2).post_solve=post_solve_pig_wood
```

在添加碰撞处理程序之后，我们需要添加一个事件处理程序，处理玩游戏的玩家的事件。但在此之前，更容易处理级别。我所说的级别实际上是使用横梁和柱子创建结构。尽管我们从精灵表中提取了横梁和柱子，但我们从未用它们创建过结构。让我们使用横梁和柱子创建一些木结构。

# 创建级别

我们不仅创建了三个主要的游戏实体，还创建了一个碰撞处理程序和`sling_action`函数。但我们还没有完成。我们必须使用`beam`和`column`游戏对象的帮助将木结构添加到空间中。`beam`是一个水平的木制矩形结构，而`column`是一个垂直的木制矩形结构。在这一部分，我们将创建另一个类，并通过定义不同的木结构来为游戏定义一个级别。您将需要创建一个新的 Python 文件并将其命名为`level.py`。在该文件中，开始编写以下代码来定义木结构：

```py
from characters import RoundPig #HAVE TO ADD PIG IN STRUCTURE
from polygon import Polygon #POLYGON 
```

在导入必要的模块之后，我们可以开始创建一个`Level`类：

```py
class Level():
    #each level will be construct by beam, column, pig
    #will create wooden structure
    def __init__(self, pigs_no, columns_no, beams_no, obj_space):
        self.pigs = pigs_no #pig number
        self.columns = columns_no 
        self.beams = beams_no
        self.space = obj_space
        self.number = 0 #to create build number
        self.total_number_of_birds = 4 #total number of initial bird
```

在上述代码中，我们创建了一个`Level`类，它有一个构造函数，接受`pigs`、`columns`、`beams`和`space`作为参数。这些参数对你来说应该不陌生。所有这些都代表不同类的对象。同样地，我们使用构造函数初始化了类变量。`number`属性的使用将在一分钟内讨论。在使用之前，描述它的用法是没有意义的。还有一个带有`total_number_of_birds`签名的属性，它表示玩家在弹弓上投射的愤怒小鸟的数量。现在，让我们为游戏建立第一个级别：

```py
def build_0(self):

    pig_no_1 = RoundPig(980, 100, self.space)
    pig_no_2 = RoundPig(985, 182, self.space)
    self.pigs.append(pig_no_1)
    self.pigs.append(pig_no_2)
    pos = (950, 80)
    self.columns.append(Polygon(pos, 20, 85, self.space))
    pos = (1010, 80)
    self.columns.append(Polygon(pos, 20, 85, self.space))
    pos = (980, 150)
    self.beams.append(Polygon(pos, 85, 20, self.space))
    pos = (950, 200)
    self.columns.append(Polygon(pos, 20, 85, self.space))
    pos = (1010, 200)
    self.columns.append(Polygon(pos, 20, 85, self.space))
    pos = (980, 240)
    self.beams.append(Polygon(pos, 85, 20, self.space))
    self.total_number_of_birds = 4
```

在上述代码中，我们以窗口方式排列了`beam`和`column`（一个层叠在另一个上面）。我们还在结构内部添加了两只猪。要创建这样的横梁和柱子，我们必须创建`Polygon`类的实例（我们在*创建多边形类*部分中创建了它）。虽然函数中的代码看起来很长，但这里并没有创造新的逻辑。我们只是实例化了不同的横梁和柱子，并提供了一个渲染位置。`pos`的值是一个元组，表示多边形应该放置在空间中的位置。

现在，让我们在同一个`level.py`文件中创建另一个方法，并将这个级别命名为`0`。记住，这是`Level`类的方法：

```py
def load_level(self):
    try:
        level_name = "build_"+str(self.number)
 getattr(self, level_name)()
    except AttributeError:
        self.number = 0
  level_name = "build_"+str(self.number)
        getattr(self, level_name)()
```

最后，这里是我们在创建类的构造函数时初始化的`number`属性的应用。这个`load_level()`方法将执行字符串连接来构建代表`level_levelNumber`的函数名。例如，上述代码的高亮部分将产生`build_name = "build_0"` [最初 number = 0]和`getattr(self, "build_0)()`，这等同于`build_0()`。

`get_attr(object, p)`等同于`object.p`。如果你觉得可能会出现属性错误异常，这个方法就很重要。例如，`get_attr(object, p, 10)`会在出现异常时返回 10。因此，这个方法可以用来提供一个默认值。当给定名称的属性在对象中不存在时，就会出现属性错误。

由于这个`load_level()`方法应该从一个文件中被显式调用，我们将在`main.py`文件中执行这个操作。打开你的`main.py`文件，然后继续我们离开的地方的代码。写下以下代码来调用最近创建的`load_level()`方法：

```py
#write it in main.py file
from level import Level
level = Level(total_pig, columns, beams, space)
level.number = 0 level.load_level()
```

在上一行代码中，我们从`level`模块中导入`Level`类。我们通过传递`pig`、`columns`、`beams`和`space`的列表来创建`Level`类的一个实例。同样地，我们将`number`的初始值设为`0`，这意味着`load_level()`方法应该调用`build_0`方法的开始。你可以通过添加更难的级别来增加`number`的值。

既然我们已经将级别加载到我们的`main.py`文件中，现在是时候处理用户操作事件了。我们将在下一节中使用 Pygame 来处理鼠标事件。

# 处理用户事件

在这一节中，我们将处理用户事件。这对你来说不是新鲜事。自从第五章 *通过构建蛇游戏学习关于 Curses*以来，我们一直在各种情况下处理用户操作事件。在构建蛇游戏时，我们处理了键盘事件，而对于 Flappy Bird，我们处理了鼠标点击事件。在处理这些事件时，我们发现使用`pygame`模块是最简单和最通用的方法；我们只需要一行代码来监听传入的操作并相应地处理它们。

但是在愤怒的小鸟的情况下，处理鼠标动作有点棘手。当我们将鼠标动作超出空间范围并尝试执行弹弓动作时，问题就会出现。这是不允许的，因此我们必须检查鼠标动作是否应与弹弓动作相关联（先前创建的拉动弹弓绳子的函数）。因此，让我们学习如何通过编写以下代码来处理用户的输入事件：

```py
while running:
    # handle Input events
  for eachEvent in Pygame.event.get():
        if eachEvent.type == Pygame.QUIT:
            running = False
 elif eachEvent.type == Pygame.KEYDOWN and event.key == 
          Pygame.K_ESCAPE:
            running = False 
```

现在我们已经检查了`QUIT`动作事件，我们可以开始处理鼠标事件（当用户使用鼠标从弹弓中发射愤怒的小鸟时）。

```py
if (Pygame.mouse.get_pressed()[0] and mouse_x_pos > 100 and
  mouse_x_pos < 250 and mouse_y_pos > 370 and mouse_y_pos < 550):
    mouse_pressed = True if (event.type == Pygame.MOUSEBUTTONUP and
  event.button == 1 and mouse_pressed):
    # Release new bird
  mouse_pressed = False
 if level.number_of_birds > 0:
        level.number_of_birds -= 1
  time_of_release = time.time()*1000
  x_initial = 154
  y_initial = 156
```

在上述代码中，我们首先检查鼠标动作是否在范围内。我们检查鼠标点击是否在空间范围内`(mouse_x_pos > 100 and mouse_x_pos < 250 and mouse_y_pos > 370 and mouse_y_pos < 550)`。如果是，我们将`mouse_pressed`变量赋值为`True`。

接下来，我们将执行释放小鸟的动作。释放每只鸟后，我们检查是否还有其他鸟。如果有，我们减少一只鸟的数量，并将*x-initial, y-initial*的值分别赋为 154, 156。这些值是弹弓静止时的中心坐标。现在，当弹弓被拉伸时，将会有一个新值，我们将称之为`mouse-x-pos`，`mouse-y-pos`。请记住，我们不必计算从(`mouse_x_pos`, `mouse_y_pos`)到(`x-initial`, `y-initial`)的距离，因为我们在创建`sling_action`函数时已经这样做了。因此，我们将使用我们在那里计算的`mouse_distance`来执行释放小鸟的动作：

```py
#add code after x-initial and y-initial declaration
if mouse_distance > rope_length:
    mouse_distance = rope_length
if mouse_x_pos < initial_x_sling+5:
    bird = RoundBird(mouse_distance, angle, x_initial, y_initial, 
           space_obj)
    total_birds.append(bird)
else:
    bird = RoundBird(-mouse_distance, angle, x_initial, y_initial, 
           space_obj)
    total_birds.append(bird)
if level.number_of_birds == 0:
    game_finish_time = time.time()
```

在上述代码中，我们正在将附加到绳子的当前`Bird`对象添加到鸟列表中。这个列表将为我们提供有关当前鸟与弹弓中心的距离、冲量角度和`space`对象的信息。现在我们已经处理了玩家的输入动作，让我们使用以下代码将每个对象`blit`到空间中：

```py
mouse_x_pos, mouse_y_pos = Pygame.mouse.get_pos()
# Blit the background image screen.fill((130, 200, 100))
screen.blit(background_image, (0, -50))

# Blitting the first part of sling image rect = Pygame.Rect(50, 0, 70, 220)
screen.blit(sling_image, (138, 420), rect)

# Blit the remaining number of angry bird  if level.total_number_of_birds > 0:
    for i in range(level.total_number_of_birds-1):
        x = 100 - (i*35)
        screen.blit(redbird, (x, 508))
```

在上述代码中，我们得到了当前鼠标位置（鼠标动作在空间中的位置）。然后，我们使用之前加载的背景图像绘制了背景。同样，我们将弹弓图像`blit`到屏幕上。现在，我们必须`blit`等待排队放入弹弓的愤怒小鸟，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/16caf933-bc34-4ec3-902d-99d371fb6621.png)

由于`total_number_of_birds`是在`Level`类中定义的属性，我们必须通过创建一个实例来使用它。除非鸟的数量大于 0，我们才创建一个表示鸟数量的列表。在`for`循环代码中，我们必须减少鸟的数量 1，因为一只鸟将被放入弹弓。在获取实际剩余鸟的数量后，我们必须获取将这些鸟渲染到空间中的位置。尽管*y*位置（高度）是恒定的，即 508 个单位，但*x*位置是通过提供每个鸟之间的空间来计算的，单位为`i*35`，其中`i`表示`for`循环创建的可迭代对象。例如，对于第 2 只鸟，空间中的位置将是（2*35, 508）。

现在，我们将调用弹弓动作。当鼠标在范围内按下并且小鸟在空间中具有一定的冲量角度时，我们必须使用以下代码调用`sling_action`方法：

```py
# Draw sling action checking user input if mouse_pressed and level.total_number_of_birds > 0:
    sling_action()
else: #blit bird when there is no stretch of sling
  if time.time()*1000 - time_of_release > 300 and 
      level.number_of_birds > 0:
        screen.blit(redbird, (130, 426))
```

如果我们有`mouse_pressed`并且鸟的数量大于 0，我们执行弹弓动作；否则，我们只在位置（`130`，`426`）上进行`blit`。在代码的`else`部分，我们不执行弹弓动作。确定是否必须执行弹弓动作的方法是观察鼠标是否已经按下（释放）以及释放后的`time_of_release`。如果当前时间有显著差异，我们不执行弹弓动作。如果有显著差异，那意味着鸟还没有被释放。为了释放鸟，当前时间必须等于`time_of_release`。这是当我们在释放之前在弹弓中进行`blit` redbird 的情况。

执行`sling_action`后，我们可以使用以下代码跟踪必须从范围内移除的鸟和猪的数量：

```py
removed_bird_after_sling = []
removed_pigs_after_sling = []  # Draw total_birds for bird in total_birds:
    if bird.shape.body.position.y < 0:
        removed_bird_after_sling.append(bird)
    pos = convert_to_pygame(bird.shape.body.position)
    x_pos, y_pos = pos
    x_pos -= 22 #Pygame compatible
  y_pos -= 20
  screen.blit(redbird, (x_pos, y_pos)) #blit bird
    Pygame.draw.circle(screen, BLUE,
  pos, int(bird.shape.radius), 2) #creates blue circle 
                                                       at the edge of bird
```

在代码的突出部分，我们检查鸟是否撞到了地面。如果是，那意味着我们必须将鸟添加到`removed_bird_after_sling`列表中。类似地，我们获取鸟角色的 Pygame 坐标并在（`x_pos`，`y_pos`）位置上进行`blit`。撞击后，鸟周围会出现一个蓝色圆圈。

类似地，我们必须在撞击后移除鸟和猪。编写以下代码来实现这一点：

```py
# Remove total_birds and total_pig for bird in removed_bird_after_sling:
    space_obj.remove(bird.shape, bird.shape.body)
    total_birds.remove(bird)
for pig in removed_pigs_after_sling:
    space_obj.remove(pig.shape, pig.shape.body)
    total_pig.remove(pig)
```

类似地，让我们将猪绘制到空间中：

```py
# Draw total_pig for Each_pig in total_pig:

    pig = Each_pig.shape
    if pig.body.position.y < 0: #when pig hits ground or fall to the ground
        removed_pigs_after_sling.append(pig)

    pos = convert_to_pygame(pig.body.position) #pos is a tuple
  x_pos, y_pos = pos

    angle_degrees = math.degrees(pig.body.angle)
    pig_rotated_img = Pygame.transform.rotate(pig_image, angle_degrees) 
    #small random rotation within wooden frame
  width,height = pig_rotated_img.get_size()
    x_pos -= width*0.5
  y_pos -= height*0.5
  screen.blit(pig_rotated_img, (x_pos, y_pos))
    Pygame.draw.circle(screen, BLUE, pos, int(pig.radius), 2)
```

猪撞到地面后，我们必须将其添加到`removed_pigs_after_sling`列表中。我们使用 Pygame 坐标获取身体的位置。类似地，我们对`pig`对象执行变换。旋转变换在 0.5 单位内。这种自动变换将使猪在空间中平稳移动而不保持静止。如果将旋转值更改为超过 2 个单位，猪的位置将急剧恶化。

两个主要的游戏实体已经渲染到空间中；即猪和鸟。现在，是时候向游戏屏幕添加一些其他游戏实体了；即横梁和柱子。我们之前创建了一个`beam`和`column`列表来跟踪横梁和柱子的数量。让我们使用它来渲染游戏中的结构：

```py
# Draw columns and Beams
#beam and column are object of Poly class for column in columns:
    column.draw_poly('columns', screen)
for beam in beams:
    beam.draw_poly('beams', screen)
```

现在，是时候更新物理：鸟在弹弓动作后应该以多快的速度前进，以及为了游戏的稳定性应该建立多少帧的更新。首先，让我们定义时间步长的长度：

```py
time_step_change = 1.0/50.0/2.
```

在先前定义的时间间隔（`dt`或时间步长）中，观察到我们使用 2 个单位的`dt`将空间的模拟向前推进了 50 次。如果将`dt`的值从 2 增加到 4 或更多，模拟将变慢。根据 pymunk 的官方文档：*使用更小的`dt`执行更多步骤会创建稳定的模拟*。这里，值 50 代表了定义的步骤，而 2 的`dt`创建了总共向空间前进 100 个单位的移动。空间中的前向模拟代表了愤怒的小鸟向木结构投射的速度。

现在，使用这个时间间隔，让我们将这些步骤添加到模拟中：

```py

#time_step_change = 1.0/50.0/2. for x in range(2):
    space_obj.step(time_step_change) # This causes two updates for frame  # Blitting second part of the sling rect_for_sling = Pygame.Rect(0, 0, 60, 200)
screen.blit(sling_image, (120, 420), rect_for_sling)

Pygame.display.flip() #updating the game objects
clock.tick(50)
```

使用`space`对象调用的`step`方法将更新给定时间步长（`dt`或时间步长）的空间。请参考[`www.pymunk.org/en/latest/_modules/pymunk/space.html`](http://www.pymunk.org/en/latest/_modules/pymunk/space.html) 了解更多关于`step`方法的信息。

最后，让我们运行游戏。点击“Run”选项卡，然后点击`main.py`文件。运行愤怒的小鸟游戏的结果如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/7a557345-aa33-4389-a25e-af62ee6dd70c.png)

最后，我们的游戏完成了。您可以通过更改它们的值并观察结果来测试我们为游戏实体定义的不同物理属性。如果我是您，我可能会更改`dt`的步长值，并检查它如何影响对象的模拟。显然，将`dt`的值从较低更改为较高会使“弹弓动作”触发后对象的速度变慢。例如，更改步长值（`dt = 4`），您会发现愤怒的小鸟比以前慢。这是由于模拟向前移动增加了额外的单位。

虽然我们的游戏可以完全正常地玩和测试，但还有一些调整可以实现，使我们的游戏更具吸引力。例如，我们可以为游戏添加音效并增加更多关卡。我们将在下一节中讨论这一点。

# 可能的修改

在测试我们的游戏时，可能会出现没有太多空间进行进一步修改的情况。但是，我想到了一个重要的修改：为游戏添加`soundFx`。为了在用户与虚拟世界交流时提供积极的体验，音效起着重要作用。考虑到这一点，Python 的`Pygame`模块提供了一个接口，以便我们可以为游戏添加配乐。

首先，要为游戏添加音效，我们需要将音乐加载到游戏中。在 GitHub 上查看本书的资源文件夹：[`github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter15/res`](https://github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter15/res)。然后，查看`sounds`文件夹，其中包含可以添加到游戏项目中的音乐文件。我将使用`angry-birds.ogg`文件（您可以使用任何您喜欢的文件，甚至可以从互联网上下载）。

以下代码将音乐文件加载到您的 Python 项目中。确保代码编写在`main.py`文件中：

```py
def load_music():
    """Function that will load the music"""
  song_name = '../res/sounds/angry-birds.ogg'
  Pygame.mixer.music.load(song_name)
    Pygame.mixer.music.play(-1)
```

在前面的函数定义中，我们首先定义了音乐文件的路径，并将其存储为`song_name`变量中的字符串。现在，要加载播放文件，我们可以使用`mixer.music`类，该类具有预定义的`load()`方法，该方法将歌曲加载到 Python 项目中。要播放刚刚加载的音乐，我们将调用`play()`方法。play 方法接受两个参数：loop 和 start。这两个参数都是可选的。循环值将为`-1`，这意味着必须连续播放加载的音乐。例如，如果要连续播放音乐，例如六次，可以在其上调用`play`方法并带有`loop = 5`参数。例如，`play(5)`将使音乐连续播放 6 次。

现在，让我们在同一个`main.py`文件中调用上述函数。您可以这样调用：

```py
load_music()
```

这就是如果我们想要将音乐加载到我们的 Python 游戏中。现在，您可以玩游戏并享受配乐。

我们可以进行的下一个修改是添加不同的关卡。返回 Python 项目并打开`level.py`文件。它将包含`Level`类以及一个名为`build_0`的单个函数。您可以添加任意多个关卡。在本节中，我们将为游戏添加另一个关卡，并将其命名为`build_1`。以下函数应该编写在`level.py`文件的`Level`类中：

```py
def build_1(self):
    """Function that will render level 1"""
 obj_pig = RoundPig(1000, 100, self.space)
    self.pigs.append(obj_pig)
    pos = (900, 80)
    self.columns.append(Polygon(pos, 20, 85, self.space))
    pos = (850, 80)
    self.columns.append(Polygon(pos, 20, 85, self.space))
    pos = (850, 150)
    self.columns.append(Polygon(pos, 20, 85, self.space))
    pos = (1050, 150)
    self.columns.append(Polygon(pos, 20, 85, self.space))
    pos = (1105, 210)
    self.beams.append(Polygon(pos, 85, 20, self.space))
    self.total_number_of_birds = 4 #reduce the number to 
       make game more competitive 
```

在前面的代码中，我们定义了一个函数，用于创建一个木结构。仔细观察代码-我们创建了`Pig`和`Polygon`类的实例。猪角色被创建在空间中的位置(1000, 10)。同样，三根柱子依次创建并垂直对齐。`pos`局部变量表示这些游戏实体必须呈现的空间位置。要使用这些游戏实体创建任何随机结构，可以测试`pos`变量的不同值。但是，请确保您定义的位置在空间内并且在空间的左下角。例如，给定位置(50, 150)会使任何游戏实体更靠近弹弓，并且不会使游戏具有竞争性。因此，在构建这样的结构时，请确保实体远离弹弓。

现在，当你运行第二关的程序时，你将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/9d4c448c-af97-457d-8144-795c8bd35bef.png)

你可以添加任意多的关卡。你只需要一点创造力来制作游戏关卡-形成横梁和柱子结构，这样玩家就很难打破。如果你想添加进一步的修改，你可以为游戏添加得分。你可以为游戏实体(猪、横梁和柱子)分配一些值，每当鸟与这些游戏实体发生碰撞时，你可以将该值添加到玩家的得分中。我们在第十二章中实现了类似的逻辑，*学习角色动画、碰撞和移动*。

最后，我们的游戏是可玩的，你可以测试每个游戏实体的声音效果和物理属性。你可以测试弹性属性如何为游戏表面提供真实世界的模拟。你还可以测试空间的模拟速度。要了解更多关于模拟步骤和步长时间间隔的信息，请查看[`www.pymunk.org/en/latest/_modules/pymunk/space.html`](http://www.pymunk.org/en/latest/_modules/pymunk/space.html)上提供的在线资源。

我很享受写这一章，也很享受制作这个游戏。我希望你也一样。在下一章中，我们将学习每个 Python 游戏开发者都必须具备的其他重要技能-为游戏添加一个人工角色。这个角色将在同一个游戏中与人类玩家进行游戏和竞争。确切地说，我们将在游戏中创建一个类似人类的玩家，并为其添加智能，就像我们人类一样。下一章将是有趣而有教育意义的。让我们开始吧！

# 总结

在这一章中，我们探讨了如何通过为游戏角色和环境添加真实世界的物理属性来创建 Pythonic 2D 物理模拟空间。我们首先学习了各种`pymunk`模块的基础知识，比如 vec2d、子模块、不同的类和属性，这些将构建 2D 刚体。这些刚体具有模拟真实世界物体特性的能力，比如质量、惯性、运动和弹性。利用这些特性，我们能够为每个游戏实体提供独特的特征，即鸟、猪、横梁和柱子。

本章的主要目的是让你了解如何有效地使用`pymunk`模块来创建像愤怒的小鸟这样复杂的游戏。像愤怒的小鸟这样的游戏被认为是复杂的，不是因为它包含了各种实体，而是因为它们必须模拟真实世界的物理属性。由于`pymunk`包含了不同的类来处理这样的环境，我们使用它来创建游戏环境、表面和游戏实体，比如愤怒的小鸟、猪和多边形。在本章中，你还学会了如何处理超过两个游戏角色之间的碰撞和移动。到目前为止，我们已经学会了如何创建一个处理程序来处理两个游戏对象之间的碰撞（蛇和边界之间以及小鸟和垂直管道之间的碰撞），但本章帮助你了解了如何轻松地创建一个碰撞处理程序来处理多个游戏实体之间的碰撞。

下一章将是有趣且具有挑战性的。我们将学习如何创建**非玩家角色**（**NPC**）—一个足够聪明以与人类玩家竞争的人工玩家。我们将通过定义人类玩家在相同情况下执行的移动和动作来创建这些 NPC。例如，当人类玩家看到面前有墙时，他们会采取行动来避免碰撞。类似的策略也将被输入到人工玩家中，以便他们能够做出聪明的举动，并能够有效地与人类玩家竞争。


# 第十六章：学习游戏人工智能-构建一个玩家机器人

- 游戏开发人员的目标是创建具有挑战性和乐趣的游戏。尽管许多程序员尝试过，但许多游戏失败的主要原因是，人类玩家喜欢在游戏中受到人工玩家的挑战。创造这样的人工玩家的结果通常被称为**非玩家角色**（**NPC**）或人工玩家。虽然创建这样的玩家很有趣（只对程序员来说），但除非我们为这些人工玩家注入一些智能，否则它不会为游戏增添任何价值。创建这样的 NPC 并使它们以某种程度的意识和智能（与人类智能相当）与人类玩家互动的过程称为**人工智能**（**AI**）。

在本章中，我们将创建一个*智能系统*，该系统将能够与人类玩家竞争。该系统将足够智能，能够进行类似于人类玩家的移动。系统将能够自行检查碰撞，检查不同的可能移动，并进行最有利的移动。哪种移动是有利的将高度依赖于目标。人工玩家的目标将由程序员明确定义，并且基于该目标，计算机玩家将能够做出智能的移动。例如，在蛇 AI 游戏中，计算机玩家的目标是进行一次移动，使它们更接近蛇食物，而在**第一人称射击**（**FPS**）游戏中，人工玩家的目标是接近人类玩家并开始向人类玩家开火。

通过本章结束时，您将学会如何通过定义机器状态来创建一个人工系统，以定义人工玩家在任何情况下会做什么。同样，我们将以蛇 AI 为例，以说明如何向计算机玩家添加智能。我们将为游戏角色创建不同的实体：玩家、计算机和青蛙（蛇食物），并探索面向对象和模块化编程的强大功能。在本章中，您将主要找到我们已经涵盖的内容，并学会如何有效地使用它以制作有生产力的游戏。

本章将涵盖以下主题：

+   理解人工智能

+   开始蛇 AI

+   添加计算机玩家

+   为计算机玩家添加智能

+   构建游戏和青蛙实体

+   构建表面渲染器和处理程序

+   可能的修改

# 技术要求

为了有效地完成本章，必须获得以下要求清单：

+   Pygame 编辑器（IDLE）-建议使用 3.5+版本

+   PyCharm IDE（参见第一章，*了解 Python-设置 Python 和编辑器*，安装程序）

+   资产（蛇和青蛙`.png`文件）-可在 GitHub 链接获取：[`github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter16`](https://github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter16)

查看以下视频以查看代码的运行情况：

[`bit.ly/2n79HSP`](http://bit.ly/2n79HSP)

# 理解人工智能

随着众多算法和模型的出现，今天的游戏开发者利用它们来创建人工角色，然后让它们与人类玩家竞争。在现实世界的游戏中，被动地玩游戏并与自己竞争已经不再有趣，因此，程序员故意设置了几种难度和状态，使游戏更具挑战性和乐趣。程序员使用的几种方法中，最好且最流行的之一是让计算机与人类竞争。听起来有趣且复杂吗？问题是如何可能创建这样的算法，使其能够与聪明的人类竞争。答案很简单。作为程序员，我们将定义几种聪明的移动，使计算机能够以与人类类似的方式应对这些情况。

在玩游戏时，人类足够聪明，可以保护他们的游戏角色免受障碍物和失败。因此，在本章中，我们的主要目标是为 NPC 提供这样的技能。我们将使用之前制作的贪吃蛇游戏（第十一章，*使用 Pygame 制作贪吃蛇游戏 UI*），稍微完善一下，并为其添加一个具有一定意识的计算机玩家，它将知道食物（蛇吃的东西）在哪里，以及障碍物在哪里。确切地说，我们将为我们的计算机角色定义不同的移动，使其拥有自己的生活。

首先，回顾一下第四章，*数据结构和函数*。在那一章中，我们创建了一个简单的井字游戏，并在其中嵌入了一个简单的*智能*算法。在那个井字游戏中，我们能够让人类玩家与计算机竞争。我们首先定义了模型，处理了用户事件，然后最终添加了不同的移动，以便计算机自行游戏。我们还测试了游戏，计算机能够在某些情况下击败玩家。因此，我们在第四章，*数据结构和函数*中已经学习了基本的 AI 概念。然而，在本章中，我们将更深入地探索 AI 的世界，并揭示关于*智能算法*的其他有趣内容，这些内容可以添加到我们之前制作的贪吃蛇游戏中。

要了解 AI 算法的工作原理，我们必须对状态机图表有相当多的了解。状态机图表（通常源自*计算理论*）定义了 NPC 在不同情况下必须做什么。我们将在下一个主题中学习状态机图表或动画图表。

# 实现状态。

每个游戏的状态数量都不同，这取决于游戏的复杂程度。例如，在像 FPS 这样的游戏中，NPC 或敌人必须有不同的状态：随机寻找人类玩家，在玩家位置随机生成一定数量的敌人，向人类玩家射击等等。每个状态之间的关系由状态机图表定义。这个图表（不一定是图片）代表了从一个状态到另一个状态的转变。例如，敌人在什么时候应该向人类玩家开火？在什么距离应该生成随机数量的敌人？

以下图表代表不同的状态，以及这些状态何时必须从一个状态改变到另一个状态：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/8dc4199a-500c-48da-ab7b-e1879473d42a.png)

观察前面的图表，你可能会觉得它并不陌生。我们之前在为井字游戏添加智能计算机玩家时做过类似的事情。在图中，我们从随机的敌人移动开始，因为我们不希望每个敌人都在同一个地方渲染。同样，在敌人被渲染后，它们被允许接近人类玩家。敌人的移动没有限制。因此，可以实现敌人位置和人类玩家位置之间的简单条件检查，以执行敌人的矢量移动（第十章，*用海龟升级蛇游戏*）。同样，在每次位置改变后，敌人的位置与人类玩家的位置进行检查，如果它们彼此靠近，那么敌人可以开始朝向人类玩家开火。

在每个状态之间，都有一些步骤的检查，以确保计算机玩家足够智能，可以与人类玩家竞争。我们可以观察到以下伪代码，它代表了前述的机器状态：

```py
#pseudocode for random movement
state.player_movement():
    if state.hits_boundary:
        state.change_movement()
```

在前面的伪代码中，每个状态定义了必须执行的代码，以执行诸如`player_movement`、`hits_boundary`和`change_movements`之类的检查操作。此外，在接近人类玩家的情况下，伪代码看起来像下面这样：

```py
#pseudocode for check if human player and computer are near
if state.player == "explore":
    if human(x, y) == computer(x, y):
        state.fire_player()
    else:
        state.player_movement()
```

前面的伪代码并不是实际代码，但它为我们提供了关于我们可以期望 AI 为我们做什么的蓝图。在下一个主题中，我们将看到如何利用伪代码和状态机的知识，为我们的蛇游戏创建不同的实体。

# 开始蛇 AI

如在 FPS 的情况下讨论的那样，蛇 AI 的情况下可以使用类似的机器状态。在蛇 AI 游戏中，我们的计算机玩家需要考虑的两个重要状态如下：

+   计算机玩家有哪些有效的移动？

+   从一个状态转换到另一个状态的关键阶段是什么？

关于前面的几点，第一点指出，每当计算机玩家接近边界线或墙壁时，必须改变计算机玩家的移动（确保它保持在边界线内），以便计算机玩家可以与人类玩家竞争。其次，我们必须为计算机蛇玩家定义一个目标。在 FPS 的情况下，如前所述，计算机敌人的主要目标是找到人类玩家并执行*射击*操作，但是在蛇 AI 中，计算机玩家必须接近游戏中的食物。蛇 AI 中真正的竞争在于人类和计算机玩家谁能更快地吃到食物。

现在我们知道了必须为 NPC（计算机玩家）定义的动作，我们可以为游戏定义实体。与我们在第十一章中所做的类似，*使用 Pygame 制作 Outdo Turtle - 蛇游戏 UI*，我们的蛇 AI 有三个主要实体，它们列举如下：

+   **类**`Player`：它代表人类玩家，所有动作都与人类相关——事件处理、渲染和移动。

+   **类**`Computer`：它代表计算机玩家（一种 AI 形式）。它执行诸如更新位置和更新目标之类的动作。

+   **类**`Frog`：它代表游戏中的食物。人类和计算机之间的竞争目标是尽快接近青蛙。

除了这三个主要的游戏实体之外，还有两个剩余的游戏实体来定义外围任务，它们如下：

+   **类**`Collision`：它代表将具有方法以检查任何实体（玩家或计算机）是否与边界发生碰撞。

+   **类**`App`：它代表将渲染显示屏并检查任何实体是否吃掉青蛙的类。

现在，借助这些实体蓝图，我们可以开始编码。我们将首先添加一个`Player`类，以及可以渲染玩家并处理其移动的方法。打开你的 PyCharm 编辑器，在其中创建一个新的项目文件夹，然后在其中添加一个新的 Python 文件，并将以下代码添加到其中：

```py
from pygame.locals import *
from random import randint
import pygame
import time
from operator import *
```

在前面的代码中，每个模块对你来说都很熟悉，除了`operator`。在编写程序时（特别是在检查游戏实体与边界墙之间的碰撞时），使用数学函数来执行操作比直接使用数学运算符要非常有帮助。例如，如果要检查`if value >= 2`，我们可以通过使用`operator`模块内定义的函数来执行相同的操作。在这种情况下，我们可以调用`ge`方法，它表示*大于等于*：`if ge(value, 2)`。类似于`ge`方法，我们可以调用诸如以下的不同方法：

+   `gt(a, b)`: 检查 a > b—如果 a > b 则返回`True`；否则返回`False`

+   `lt(a, b)`**:** 检查 a < b—如果 a < b 则返回`True`；否则返回`False`

+   `le(a, b)`: 检查 a <= b—如果 a <= b 则返回`True`；否则返回`False`

+   `eq(a, b)`: 检查 a == b—如果 a == b 则返回`True`；否则返回`False`

现在你已经导入了必要的模块，让我们开始有趣的事情，创建`Player`类：

```py
class Player:
    x = [0] #x-position
    y = [0] #y-position
    size = 44 #step size must be same for Player, Computer, Food
  direction = 0 #to track which direction snake is moving
  length = 3 #initial length of snake    MaxMoveAllow = 2
  updateMove = 0    def __init__(self, length):
        self.length = length
        for i in range(0, 1800):
            self.x.append(-100)
            self.y.append(-100)

        # at first rendering no collision
  self.x[0] = 1 * 44
  self.x[0] = 2 * 44
```

在前面的代码中，我们开始定义类属性：(`x`，`y`)代表蛇的初始位置，`size`代表蛇块的步长，`direction`（值范围从 0 到 4）代表蛇移动的当前方向，`length`是蛇的原始长度。名为`direction`的属性的值将在 0 到 3 之间变化，其中 0 表示蛇向*右*移动，1 表示蛇向*左*移动，类似地，2 和 3 分别表示*上*和*下*方向。

接下来的两个类属性是`MaxMoveAllow`和`update`。这两个属性将在名为`updateMove`的函数中使用（在下面的代码中显示），它们确保玩家不被允许使蛇移动超过两次。玩家可能会一次输入多于两个箭头键，但如果所有效果或箭头键同时反映，蛇将移动不协调。为了避免这种情况，我们定义了`maxMoveAllowed`变量，以确保最多同时处理两次箭头键按下。

同样地，我们在类内部定义了构造函数，用于执行类属性的初始化。在渲染蛇玩家在随机位置之后（通过`for`循环完成），我们编写了一条语句，确保在游戏开始时没有碰撞（高亮部分）。代码暗示了蛇的每个方块之间的位置必须相隔三个单位。如果将`self.x[0] = 2*44`的值更改为`self.x[0] = 1 *44`，那么蛇头和其之间将发生碰撞。因此，为了确保在游戏开始时（玩家开始玩之前）没有碰撞，我们必须在方块之间提供特定的位置间隔。

现在，让我们使用`MaxMoveAllow`和`updateMove`属性来创建`update`函数：

```py
def update(self):

    self.updateMove = self.updateMove + 1
  if gt(self.updateMove, self.MaxAllowedMove):

        # update previous to new position
  for i in range(self.length - 1, 0, -1):
            self.x[i] = self.x[i - 1]
            self.y[i] = self.y[i - 1]

        # updating the position of snake by size of block (44)
  if self.direction == 0:
            self.x[0] = self.x[0] + self.size
        if self.direction == 1:
            self.x[0] = self.x[0] - self.size
        if self.direction == 2:
            self.y[0] = self.y[0] - self.size
        if self.direction == 3:
            self.y[0] = self.y[0] + self.size

        self.updateMove = 0
```

前面的代码对你来说并不陌生。你以前多次见过这样的逻辑（在第六章，“面向对象编程”中，以及第十一章，“用 Pygame 制作贪吃蛇游戏 UI”中，处理蛇的位置时）。简而言之，前面的代码行改变了人类玩家的当前位置，根据按下的箭头键。你可以在代码中看到，我们还没有处理任何箭头键（我们将在`App`类中处理），但我们已经创建了一个名为`direction`的属性，它可以跟踪哪个键被按下。如果`direction`等于`0`，这意味着右箭头键被按下，因此我们增加*x*位置与块大小。

同样，如果`direction`是`1`，我们通过减去块大小`44`来改变*x*位置值，这意味着蛇将朝负*x*轴移动。（这不是新信息；可以在第九章，“数据模型实现”中找到详细讨论。）

现在，为了确保每个`direction`属性与值 0 到 3 相关联，我们将为每个创建函数，如下所示：

```py
def moveRight(self):
    self.direction = 0   def moveLeft(self):
    self.direction = 1   def moveUp(self):
    self.direction = 2   def moveDown(self):
    self.direction = 3   def draw(self, surface, image):
 for item in range(0, self.length):
 surface.blit(image, (self.x[item], self.y[item]))
```

观察前面的代码，你可能已经注意到`direction`属性的重要性。每个移动都有一个相关联的值，可以在处理用户事件时使用`pygame`模块（我们将在本章后面讨论）。但是，现在只需看一下`draw`函数，它接受蛇（人类玩家）的`surface`和`image`作为参数，并相应地进行 blits。你可能会有这样的问题：为什么不使用传统方法（自第八章，“Turtle Class – Drawing on the Screen”以来一直在使用的方法）来处理用户事件，而是使用`direction`属性？这个问题是合理的，显然你也可以以这种方式做，但在 Snake AI 的情况下，实施这样的代码存在重大缺点。由于 Snake AI 有两个主要玩家或游戏实体（人类和计算机），它们每个都必须有独立的移动。因此，对每个实体使用传统方法处理事件将会很繁琐和冗长。更好的选择是使用一个属性来跟踪哪个键被按下，并为每个玩家独特地处理它，这正是我们将要做的，使用`direction`属性。

现在我们已经完成了主要的人类玩家，我们将转向计算机玩家。我们将开始为`Computers`类编写代码，它将在下一个主题中处理计算机的移动。

# 添加计算机玩家

最后，我们来到了本章的主要部分——重点部分——将计算机蛇角色添加到游戏中变得更容易。与外观一样，计算机的移动处理技术必须类似于人类玩家。我们可以重用`Player`类中编写的代码。唯一不同的是`Player`类的*目标*。对于人类玩家，目标未定义，因为移动的目标由玩家的思想实现。例如，人类玩家可以通过控制蛇的移动方向来有效地玩游戏。如果蛇食物在左边，那么人类玩家不会按右箭头键，使蛇朝相反方向移动。但是，计算机不够聪明，无法自行考虑赢得游戏的最佳方式。因此，我们必须明确指定计算机玩家的目标。为个别玩家/系统指定目标的技术将导致智能系统，并且其应用范围广泛——从游戏到机器人。

目前，让我们复制写在`Player`类内部的代码，并将其添加到名为`Computer`的新类中。以下代码表示了`Computer`类的创建，以及它的构造函数：

```py
class Computer:
    x = [0]
    y = [0]
    size = 44 #size of each block of snake
  direction = 0
  length = 3    MaxAllowedMove = 2
  updateMove = 0    def __init__(self, length):
        self.length = length
        for item in range(0, 1800):
            self.x.append(-100)
            self.y.append(-100)

      # making sure no collision with player
  self.x[0] = 1 * 44
  self.y[0] = 4 * **44** 
```

与`Player`类类似，它有四个属性，其中`direction`的初始值为`0`，这意味着在计算机实际开始玩之前，蛇将自动向右（正*x*轴）方向移动。此外，构造函数中初始化的所有内容都与`Player`类相似，除了代码的突出部分。代码的最后一行是`y[0]`，它从`4*44`开始。回想一下在人类玩家的情况下，代码的相同部分是`2*44`，表示列位置。编写这段代码，我们暗示游戏开始时人类玩家蛇和计算机玩家蛇之间不应该发生碰撞。但是，`x[0]`的值是相同的，因为我们希望每条蛇都从同一行开始，但不在同一列。通过这样做，我们避免了它们的碰撞，并且每个玩家的蛇将被正确渲染。

同样，我们必须添加`update`方法，它将根据`direction`属性反映计算机蛇的*x*、*y*位置的变化。以下代码表示了`update`方法，它将确保计算机蛇只能同时使用两个箭头键移动的组合：

```py
def update(self):

    self.updateMove = self.updateMove + 1
  if gt(self.updateMove, self.MaxAllowedMove):

        # Previous position changes one by one
  for i in range(self.length - 1, 0, -1):
            self.x[i] = self.x[i - 1]
            self.y[i] = self.y[i - 1]

        # head position change
  if self.direction == 0:
            self.x[0] = self.x[0] + self.size
        if self.direction == 1:
            self.x[0] = self.x[0] - self.size
        if self.direction == 2:
            self.y[0] = self.y[0] - self.size
        if self.direction == 3:
            self.y[0] = self.y[0] + self.size

        self.updateMove = 0
```

前面的代码与`Player`类类似，所以我不会费心解释它。您可以参考`Player`类的`update`函数，了解这个方法是如何工作的。与`Player`类类似，我们必须添加四个方法，这些方法将相应地改变`direction`变量的值：

```py
def moveRight(self):
    self.direction = 0   def moveLeft(self):
    self.direction = 1   def moveUp(self):
    self.direction = 2   def moveDown(self):
    self.direction = 3
```

编写的代码将能够更新计算机玩家的*direction*，但这还不足以做出聪明的移动。比如，如果蛇食在右侧，到目前为止编写的代码将无法跟踪食物的位置，因此计算机蛇可能会去相反的地方。因此，我们必须明确指定计算机玩家将朝着靠近蛇食的位置移动。我们将在下一个主题中介绍这一点。

# 为计算机玩家添加智能

到目前为止，已经定义了两个游戏实体，它们都处理玩家的移动。与`Player`类不同，另一个游戏实体（计算机玩家）不会自行决定下一步的移动。因此，我们必须明确要求计算机玩家做出一步将蛇靠近食物的移动。通过这样做，计算机玩家和人类玩家之间将会有巨大的竞争。这看起来实现起来相当复杂；然而，这个想法仍然保持不变，正如之前讨论的那样，以及机器状态图。

通过机器状态图，AI 玩家必须考虑两件事：

+   检查蛇食的位置，并采取行动以靠近它。

+   检查蛇的当前位置，并确保它不会撞到边界墙。

第一步将实现如下：

```py
def target(self, food_x, food_y):
    if gt(self.x[0] , food_x):

        self.moveLeft()

    if lt(self.x[0] , food_x):
        self.moveRight()

    if self.x[0] == food_x:
        if lt(self.y[0] , food_y):
            self.moveDown()

        if gt(self.y[0] , food_y):
            self.moveUp()

def draw(self, surface, image):
     for item in range(0, self.length):
         surface.blit(image, (self.x[item], self.y[item]))
```

在上一行代码中，我们调用了不同的先前创建的方法，如`moveLeft()`，`moveRight()`等。这些方法将导致蛇根据`direction`属性值移动。`target()`方法接受两个参数：`food_x`和`food_y`，它们组合地指代蛇食物的位置。操作符`gt`和`lt`用于执行与蛇的*x*-head 和*y*-head 位置的比较操作。例如，如果蛇食物在负*x*-轴上，那么将对蛇的*x*-位置和食物的*x*-位置进行比较（`gt(self.x[0], food_x)`）。显然，`food_x`在负*x*-轴上，这意味着蛇的*x*-位置更大，因此调用`moveLeft()`。正如方法的签名所暗示的，我们将转向，并将计算机玩家蛇朝着负*x*-轴移动。对食物的每个(*x*, *y*)位置进行类似的比较，每次调用不同的方法，以便我们可以引导计算机玩家朝着蛇食物移动。

现在我们已经添加了简单的计算机玩家，它能够通过多个障碍物，让我们在下一个主题中添加`Frog`和`Collision`类。`Frog`类负责在屏幕上随机位置渲染青蛙（蛇的食物），`Collision`将检查蛇之间是否发生碰撞，或者蛇与边界墙之间是否发生碰撞。

# 构建游戏和青蛙实体

如前所述，我们将在本主题中向我们的代码中添加另外两个类。这些类在我们的 Snake AI 中有不同的用途。`Game`实体将通过检查传递给它们的成员方法的参数来检查是否发生任何碰撞。对于`Game`实体，我们将定义一个简单但强大的方法，名为`checkCollision()`，它将根据碰撞返回`True`或`False`的布尔值。

以下代码表示`Game`类及其成员方法：

```py
class Game:
    def checkCollision(self, x1, y1, x2, y2, blockSize):
        if ge(x1 , x2) and le(x1 , x2 + blockSize):
            if ge(y1 , y2) and le(y1, y2 + blockSize):
                return True
 return False 
```

对`checkCollision()`方法的调用将在主类中进行（稍后将定义）。但是，你会注意到传递的参数（*x*和*y*值）将是蛇的当前位置，从中调用此方法。假设你创建了`Game`类的一个实例，并传递了人类玩家的（`x1`，`y1`，`x2`和`y2`）位置值。这样做，你就是在为人类玩家调用`checkCollision`方法。条件语句将检查蛇的位置值是否与边界墙相同。如果是，它将返回`True`；否则，它将返回`False`。

接下来重要的游戏实体是`Frog`。这个类在随机位置渲染`Frog`的图像，每次被任何玩家（人类或计算机）吃掉后都会重新渲染。以下代码表示了`Frog`类的声明：

```py
class Frog:
    x = 0
  y = 0
  size = 44    def __init__(self, x, y):
        self.x = x * self.size
        self.y = y * self.size

    def draw(self, surface, image):
        surface.blit(image, (self.x, self.y))
```

在上述代码中，我们定义了*x*-位置、*y*-位置和`draw`方法，以便渲染青蛙图像。通过创建`Frog`类来调用这个方法。

在下一个主题中，我们将通过创建和实现最后一个实体：主`App`实体来完成我们的程序。这将是我们游戏的中央指挥官。

# 构建表面渲染器和处理程序

首先，让我们回顾一下我们到目前为止所做的事情。我们开始编写代码，定义了两个主要的游戏实体：`Player`和`Computer`。这两个实体在行为和渲染方法方面都非常相似，只是在`Computer`类中引入了额外的`target()`方法，以确保计算机玩家足够聪明，能够与人类玩家竞争。同样，我们声明了另外两个实体：`Game`和`Frog`。这两个类为贪吃蛇 AI 提供了后端功能，比如添加碰撞逻辑，以及检查蛇食物应该渲染的位置。我们在这些不同的实体中创建了多个方法，但我们从未创建过实例/对象。这些实例可以从主要的单一类中创建，我们现在要实现这个类。我将称这个类为`App`类。

看一下以下代码片段，以便为`App`类编写代码：

```py
class App:
    Width = 800 #window dimension
  Height = 600
  player = 0 #to track either human or computer 
 Frog = 0 #food    def __init__(self):
        self._running = True
  self.surface = None
  self._image_surf = None
  self._Frog_surf = None
  self.game = Game()
        self.player = Player(5) #instance of Player with length 5 (5            
        blocks) 
        self.Frog = Frog(8, 5) #instance of Frog with x and y position
        self.computer = Computer(5) #instance of Computer player with 
        length 5 
```

前面的代码定义了一些属性，比如游戏控制台的`Height`和`Width`。同样，它有一个构造函数，用于初始化不同的类属性，以及创建`Player`、`Frog`和`Computer`实例。

接下来，要从计算机加载图像并将其添加到 Python 项目中（参考第十一章，*使用 Pygame 创建 Outdo Turtle-贪吃蛇游戏 UI*，了解更多关于`load`方法的信息）。游戏的资源，比如蛇身和食物，可以在这个 GitHub 链接上找到：[`github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter16`](https://github.com/PacktPublishing/Learning-Python-by-building-games/tree/master/Chapter16)。但是，你也可以自己创建并进行实验。我之前在第十一章，*使用 Pygame 创建 Outdo Turtle-贪吃蛇游戏 UI*中教过你如何使用 GIMP 和简单的绘图应用程序创建透明精灵。试着回顾一下这些概念，并自己尝试一下。现在，我要将两个图像加载到 Python 项目中。

最好使用.png 文件作为精灵，并且不要在文件名中包含数字值。例如，名为`snake12.png`的蛇身文件名是无效的。文件名应该不包含数字值。同样，确保将这些`.png`文件添加到 Python 项目文件夹中。回顾一下第十一章，*使用 Pygame 创建 Outdo Turtle-贪吃蛇游戏 UI*，查看如何将图像加载到 Python 项目中。

以下代码将加载两个图像文件到 Python 项目中：

```py
def loader(self):
 pygame.init()
 self.surface = pygame.display.set_mode((self.Width, self.Height), 
 pygame.HWSURFACE)

 self._running = True
  self._image_surf = pygame.image.load("snake.png").convert()
 self._Frog_surf = pygame.image.load("frog-main.png").convert()
```

在前面的代码行中，我们使用`pygame.display`模块创建了一个`surface`对象。然后，我们将两个图像——`snake.png`和`frog-main.png`——加载到 Python 项目中。`convert()`方法将改变渲染对象的像素格式，使其在任何表面上都能完美工作。

同样，如果一个游戏有事件，并且与用户交互，那么必须实现`on_event`方法：

```py
def on_event(self, event):
 if event.type == QUIT:
 self._running = False
def on_cleanup(self):
    pygame.quit() 
```

最后，让我们定义`main`函数：

```py
def main(self):
    self.computer.target(self.Frog.x, self.Frog.y)
    self.player.update()
    self.computer.update()
```

在前面的函数中，我们调用了`target`方法，以确保计算机玩家能够使用其中定义的功能。如前所述，`target()`方法接受食物的*x*、*y*坐标，计算机会决定靠近食物。同样，调用了`Player`和`Computer`类的`update`方法。

现在让我们定义`renderer()`方法。这个方法将把蛇和食物绘制到游戏表面上。这是使用`pygame`和`draw`模块完成的：

```py
def renderer(self):
    self.surface.fill((0, 0, 0))
    self.player.draw(self.surface, self._image_surf)
    self.Frog.draw(self.surface, self._Frog_surf)
    self.computer.draw(self.surface, self._image_surf)
    pygame.display.flip()
```

如果你觉得你不理解`renderer()`方法的工作原理，去第十一章，*使用 Pygame 创建 Outdo Turtle-贪吃蛇游戏 UI*。简而言之，这个方法将不同的对象（`image_surf`和`Frog_surf`）绘制到游戏屏幕上。

最后，让我们创建一个`handler`方法。这个方法将处理用户事件。根据用户按下的箭头键，将调用不同的方法，比如`moveUp()`、`moveDown()`、`moveLeft()`和`moveRight()`。这四个方法都在`Player`和`Computer`实体中创建。以下代码定义了`handler`方法：

```py
def handler(self):
    if self.loader() == False:
        self._running = False   while (self._running):
        keys = pygame.key.get_pressed()

        if (keys[K_RIGHT]):
            self.player.moveRight()

        if (keys[K_LEFT]):
            self.player.moveLeft()

        if (keys[K_UP]):
            self.player.moveUp()

        if (keys[K_DOWN]):
            self.player.moveDown()     self.main()
        self.renderer()

        time.sleep(50.0 / 1000.0);
```

前面的`handler`方法已经被创建了很多次（我们看到了高级和简单的方法），这个是最简单的一个。我们使用了`pygame`模块来监听传入的按键事件，并根据需要处理它们，通过调用不同的方法。例如，当用户按下向下箭头键时，就会调用`moveDown()`方法。最后的`sleep`方法将嵌入计时器，以便在两次连续的按键事件之间有所区别。

最后，让我们调用这个`handler`方法：

```py
if __name__ == "__main__":
    main = App()
    main.handler()
```

让我们运行游戏并观察输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/d6ac8fdd-419c-4f70-911f-1a8a03bde72f.png)

正如预期的那样，这个游戏还需要添加一些东西，包括：当人类玩家和电脑玩家吃到食物时会发生什么，以及蛇与自身碰撞时会发生什么？如果你一直正确地跟随本书，这对你来说应该是小菜一碟。我们已经多次添加了相同的逻辑（在第七章，*列表推导和属性*；第十章，*用海龟升级蛇游戏*；和第十一章，*用 Pygame 超越海龟-蛇游戏 UI*）。但除了这个逻辑，还要关注两条相似的蛇：一条必须根据人类玩家的行动移动，另一条则独立移动。计算机蛇知道与边界墙的碰撞和食物的位置。一旦你运行游戏，计算机玩家将立即做出反应，并试图做出聪明的移动，早于人类玩家。这就是在现实游戏行业中应用人工智能。虽然你可能认为蛇 AI 示例更简单，但在现实世界中，AI 也是关于机器独立行动，无论算法有多复杂。

但是，游戏中必须进行一些调整，这将在下一个主题“可能的修改”中进行讨论。

# 游戏测试和可能的修改

首先，我建议你回头观察我们定义`Game`类的部分。我们在其中定义了`checkCollision()`方法。这个方法可以用于多种目的：首先，检查玩家是否与蛇食物发生碰撞；其次，检查玩家是否与边界墙发生碰撞。这个时候你一定会有一个“恍然大悟”的时刻。第七章，*列表推导和属性*，到第十一章，*用 Pygame 超越海龟-蛇游戏 UI*，都是关于使用这种技术来实现碰撞原理的，即*如果食物对象的（x，y）位置与任何玩家的（x，y）坐标相同，则称为发生碰撞*。

让我们添加代码来检查任何玩家是否与食物发生了碰撞：

```py
# Does human player snake eats Frog for i in range(0, self.player.length):
    if self.game.checkCollision(self.Frog.x, self.Frog.y, 
    self.player.x[i], self.player.y[i], 44):
        #after each player eats frog; next frog should be spawn in next  
        position
        self.Frog.x = randint(2, 9) * 44
  self.Frog.y = randint(2, 9) * 44
  self.player.length = self.player.length + 1   # Does computer player eats Frog for i in range(0, self.player.length):
    if self.game.checkCollision(self.Frog.x, self.Frog.y, 
        self.computer.x[i], self.computer.y[i], 44):
        self.Frog.x = randint(2, 9) * 44
  self.Frog.y = randint(2, 9) * 44
```

同样，让我们使用相同的函数来检查人类玩家的蛇是否撞到了边界墙。你可能认为在计算机玩家的情况下也需要检查这一点，但这是没有意义的，因为在`Computer`类中定义的`target`方法不会让这种情况发生。换句话说，计算机玩家永远不会撞到边界墙，因此检查是否发生碰撞是没有意义的。但是，在人类玩家的情况下，我们将使用以下代码进行检查：

```py
# To check if the human player snake collides with its own body for i in range(2, self.player.length):
    if self.game.checkCollision(self.player.x[0], self.player.y[0], 
   self.player.x[i], self.player.y[i], 40):
        print("You lose!")
        exit(0)
 pass
```

我们将在这里结束这个话题，但是您可以通过添加一个游戏结束屏幕使这个游戏更具吸引力，我们已经学会了如何使用`pygame`在第十一章中创建。您可以创建一个表面并在其中渲染一个带有标签的字体，以创建这样一个游戏结束屏幕，而不是最后的`pass`语句。

但是，在结束本章之前，让我们来看看我们游戏的最终输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/lrn-py-bd-gm/img/2c8da6fd-a322-4771-9da9-f4c1773a3e55.png)

在游戏中您可能注意到的另一件事是，计算机玩家的蛇*长度*是恒定的，即使它吃了食物。我故意这样做，以免我的游戏屏幕被污染太多。但是，如果您想增加计算机玩家的蛇长度（每次蛇吃食物时），您可以在计算机玩家蛇吃青蛙后添加一个语句：

```py
self.computer.length = self.computer.length + 1
```

最后，我们来到了本章的结束。我们学到了不同的东西，也复习了旧知识。与人工智能相关的概念是广泛的；我们只是尝试触及表面。您可以通过访问以下网址找到使用 Python 在游戏中的其他 AI 含义：[`www.pygame.org/tags/ai`](https://www.pygame.org/tags/ai)。

# 总结

在本章中，我们探讨了在游戏中实现 AI 的基本方法。然而，AI 的工作方式在很大程度上取决于奖励智能系统的每一步。我们使用了机器状态图来定义计算机玩家的可能状态，并用它来执行每个实体的不同动作。在这一章中，我们采用了不同的编程范式；事实上，这是对我们迄今为止学到的一切的回顾，另外还使用了智能算法来处理 NPC。

对于每个定义的实体，我们都创建了一个类，并采用了基于属性和方法的封装和模型的面向对象范式。此外，我们定义了不同的类，如`Frog`和`Game`，以实现碰撞的逻辑。为了实现单一逻辑，我们为每个游戏实体（`Player`和`Computer`）创建了单独的类。您可以将其理解为多重继承。本书的主要目的是让读者了解如何使用 Python 创建游戏机器人。此外，某种程度上，目的是在单一章节中复习我们在整本书中学到的所有编程范式。

正如古谚所说：*已知乃一滴，未知则是海洋*。我希望您仍然渴望更多地了解 Python。我建议您加强基本的编程技能并经常进行实验，这将确实帮助您实现成为游戏开发人员的梦想工作。游戏行业是巨大的，掌握 Python 知识将会产生巨大影响。Python 是一种美丽的语言，因此您将受到更深入学习的激励，而这本书将是您迈向成为 Python 专家的第一步。
