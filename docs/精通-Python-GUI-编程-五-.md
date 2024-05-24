# 精通 Python GUI 编程（五）

> 原文：[`zh.annas-archive.org/md5/0baee48435c6a8dfb31a15ece9441408`](https://zh.annas-archive.org/md5/0baee48435c6a8dfb31a15ece9441408)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：使用 QtOpenGL 创建 3D 图形

从游戏到数据可视化到工程模拟，3D 图形和动画是许多重要软件应用的核心。几十年来，事实上的**应用程序编程接口**（**API**）标准一直是 OpenGL。

用于跨平台 3D 图形的 API 一直是 OpenGL。尽管存在许多 Python 和 C 的 API 实现，Qt 提供了一个直接集成到其小部件中的 API，使我们能够在 GUI 中嵌入交互式的 OpenGL 图形和动画。

在本章中，我们将在以下主题中探讨这些功能：

+   OpenGL 的基础知识

+   使用`QOpenGLWidget`嵌入 OpenGL 绘图

+   动画和控制 OpenGL 绘图

# 技术要求

对于本章，你需要一个基本的 Python 3 和 PyQt5 设置，就像我们在整本书中一直在使用的那样，并且你可能想从[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter13`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter13)下载示例代码。你还需要确保你的图形硬件和驱动程序支持 OpenGL 2.0 或更高版本，尽管如果你使用的是过去十年内制造的传统台式机或笔记本电脑，这几乎肯定是真的。

查看以下视频，看看代码是如何运行的：[`bit.ly/2M5xApP`](http://bit.ly/2M5xApP)

# OpenGL 的基础知识

OpenGL 不仅仅是一个库；它是一个与图形硬件交互的 API 的**规范**。这个规范的实现是由你的图形硬件、该硬件的驱动程序和你选择使用的 OpenGL 软件库共享的。因此，你的基于 OpenGL 的代码的确切行为可能会因其中任何一个因素而略有不同，就像同样的 HTML 代码在不同的网络浏览器中可能会稍有不同地呈现一样。

OpenGL 也是一个**有版本的**规范，这意味着 OpenGL 的可用功能和推荐用法会随着你所针对的规范版本的不同而改变。随着新功能的引入和旧功能的废弃，最佳实践和建议也在不断发展，因此为 OpenGL 2.x 系统编写的代码可能看起来完全不像为 OpenGL 4.x 编写的代码。

OpenGL 规范由 Khronos Group 管理，这是一个维护多个与图形相关的标准的行业联盟。撰写本文时的最新规范是 4.6，发布于 2019 年 2 月，可以在[`www.khronos.org/registry/OpenGL/index_gl.php`](https://www.khronos.org/registry/OpenGL/index_gl.php)找到。然而，并不总是跟随最新规范是一个好主意。计算机运行给定版本的 OpenGL 代码的能力受到硬件、驱动程序和平台考虑的限制，因此，如果你希望你的代码能够被尽可能广泛的用户运行，最好是针对一个更旧和更成熟的版本。许多常见的嵌入式图形芯片只支持 OpenGL 3.x 或更低版本，一些低端设备，如树莓派（我们将在第十五章，*树莓派上的 PyQt*中看到）只支持 2.x。

在本章中，我们将限制我们的代码在 OpenGL 2.1，因为它得到了 PyQt 的良好支持，大多数现代计算机应该能够运行它。然而，由于我们将坚持基础知识，我们所学到的一切同样适用于 4.x 版本。

# 渲染管线和绘图基础知识

将代码和数据转化为屏幕上的像素需要一个多阶段的过程；在 OpenGL 中，这个过程被称为**渲染管线。** 这个管线中的一些阶段是可编程的，而其他的是固定功能的，意味着它们的行为是由 OpenGL 实现预先确定的，不能被改变。

让我们从头到尾走一遍这个管道的主要阶段：

1.  **顶点规范**：在第一个阶段，绘图的**顶点**由您的应用程序确定。**顶点**本质上是 3D 空间中的一个点，可以用来绘制形状。顶点还可以包含关于点的元数据，比如它的颜色。

1.  **顶点处理**：这个可用户定义的阶段以各种方式处理每个顶点，计算每个顶点的最终位置；例如，在这一步中，您可能会旋转或移动顶点规范中定义的基本形状。

1.  **顶点后处理**：这个固定功能阶段对顶点进行一些额外的处理，比如裁剪超出视图空间的部分。

1.  **基元组装**：在这个阶段，顶点被组合成基元。一个基元是一个 2D 形状，比如三角形或矩形，从中可以构建更复杂的 3D 形状。

1.  **光栅化**：这个阶段将基本图元转换为一系列单独的像素点，称为片段，通过在顶点之间进行插值。

1.  **片段着色**：这个用户定义阶段的主要工作是确定每个片段的深度和颜色值。

1.  **逐样本操作**：这个最后阶段对每个片段执行一系列测试，以确定其最终的可见性和颜色。

作为使用 OpenGL 的程序员，我们主要关注这个操作的三个阶段 - 顶点规范、顶点处理和片段着色。对于顶点规范，我们将简单地在 Python 代码中定义一些点来描述 OpenGL 绘制的形状；对于其他两个阶段，我们需要学习如何创建 OpenGL 程序和着色器。

# 程序和着色器

尽管名字上是着色器，但它与阴影或着色无关；它只是在 GPU 上运行的代码单元的名称。在前一节中，我们谈到了渲染管线的一些阶段是可用户定义的；事实上，其中一些*必须*被定义，因为大多数 OpenGL 实现不为某些阶段提供默认行为。为了定义这些阶段，我们需要编写一个着色器。

至少，我们需要定义两个着色器：

+   **顶点着色器**：这个着色器是顶点处理阶段的第一步。它的主要工作是确定每个顶点的空间坐标。

+   **片段着色器**：这是管线倒数第二个阶段，它唯一的必要工作是确定单个片段的颜色。

当我们有一组着色器组成完整的渲染管线时，这被称为一个程序。

着色器不能用 Python 编写。它们必须用一种叫做**GL 着色语言**（**GLSL**）的语言编写，这是 OpenGL 规范的一部分的类似 C 的语言。没有 GLSL 的知识，就不可能创建严肃的 OpenGL 绘图，但幸运的是，写一组足够简单的着色器对于基本示例来说是相当简单的。

# 一个简单的顶点着色器

我们将组成一个简单的 GLSL 顶点着色器，我们可以用于我们的演示；创建一个名为`vertex_shader.glsl`的文件，并复制以下代码：

```py
#version 120
```

我们从一个注释开始，指明我们正在使用的 GLSL 版本。这很重要，因为每个 OpenGL 版本只兼容特定版本的 GLSL，GLSL 编译器将使用这个注释来检查我们是否不匹配这些版本。

可以在[`www.khronos.org/opengl/wiki/Core_Language_(GLSL)`](https://www.khronos.org/opengl/wiki/Core_Language_(GLSL))找到 GLSL 和 OpenGL 版本之间的兼容性图表。

接下来，我们需要进行一些**变量声明**：

```py
attribute highp vec4 vertex;
uniform highp mat4 matrix;
attribute lowp vec4 color_attr;
varying lowp vec4 color;
```

在类似 C 的语言中，变量声明用于创建变量，定义关于它的各种属性，并在内存中分配空间。我们的每个声明有四个标记；让我们按顺序来看一下这些：

+   第一个标记是`attribute`，`uniform`或`varying`中的一个。这表明变量将分别用于每个顶点（`attribute`），每个基本图元（`uniform`）或每个片段（`varying`）。因此，我们的第一个变量将对每个顶点都不同，但我们的第二个变量将对同一基本图元中的每个顶点都相同。

+   第二个标记指示变量包含的基本数据类型。在这种情况下，它可以是`highp`（高精度数字），`mediump`（中等精度数字）或`lowp`（低精度数字）。我们可以在这里使用`float`或`double`，但这些别名有助于使我们的代码跨平台。

+   第三个术语定义了这些变量中的每一个是指向**向量**还是矩阵。你可以将向量看作是 Python 的`list`对象，将矩阵看作是一个每个项目都是相同长度的`list`对象的`list`对象。末尾的数字表示大小，所以`vec4`是一个包含四个值的列表，`mat4`是一个 4x4 值的矩阵。

+   最后一个标记是变量名。这些名称将在整个程序中使用，因此我们可以在管道中更深的着色器中使用它们来访问来自先前着色器的数据。

这些变量可以用来将数据插入程序或将数据传递给程序中的其他着色器。我们将在本章后面看到如何做到这一点，但现在要明白，在我们的着色器中，`vertex`，`matrix`和`color_attr`代表着将从我们的 PyQt 应用程序接收到的数据。

在变量声明之后，我们将创建一个名为`main()`的函数：

```py
void main(void)
{
  gl_Position = matrix * vertex;
  color = color_attr;
}
```

`vertex`着色器的主要目的是使用`vertex`的坐标设置一个名为`gl_Position`的变量。在这种情况下，我们将其设置为传入着色器的`vertex`值乘以`matrix`值。正如你将在后面看到的，这种安排将允许我们在空间中操作我们的绘图。

在创建 3D 图形时，矩阵和向量是关键的数学概念。虽然在本章中我们将大部分时间都从这些数学细节中抽象出来，但如果你想深入学习 OpenGL 编程，了解这些概念是个好主意。

我们着色器中的最后一行代码可能看起来有点无意义，但它允许我们在顶点规范阶段为每个顶点指定一个颜色，并将该颜色传递给管道中的其他着色器。着色器中的变量要么是输入变量，要么是输出变量，这意味着它们期望从管道的前一个阶段接收数据，或者将数据传递给下一个阶段。在顶点着色器中，使用`attribute`或`uniform`限定符声明变量会将变量隐式标记为输入变量，而使用`varying`限定符声明变量会将其隐式标记为输出变量。因此，我们将`attribute`类型的`color_attr`变量的值复制到`varying`类型的`color`变量中，以便将该值传递给管道中更深的着色器；具体来说，我们想将其传递给`fragment`着色器。

# 一个简单的片段着色器

我们需要创建的第二个着色器是`fragment`着色器。请记住，这个着色器的主要工作是确定每个基本图元上每个点（或*片段*）的颜色。

创建一个名为`fragment_shader.glsl`的新文件，并添加以下代码：

```py
#version 120

varying lowp vec4 color;

void main(void)
{
  gl_FragColor = color;
}
```

就像我们的`vertex`着色器一样，我们从一个指定我们要针对的 GLSL 版本的注释开始。然后，我们将声明一个名为`color`的变量。

因为这是`fragment`着色器，将变量指定为`varying`会使其成为输入变量。使用`color`这个名称，它是我们着色器的输出变量，意味着我们将从该着色器接收它分配的颜色值。

然后在`main()`中，我们将该颜色分配给内置的`gl_FragColor`变量。这个着色器的有效作用是告诉 OpenGL 使用`vertex`着色器传入的颜色值来确定单个片段的颜色。

这是我们可以得到的最简单的`fragment`着色器。更复杂的`fragment`着色器，例如在游戏或模拟中找到的着色器，可能实现纹理、光照效果或其他颜色操作；但对于我们的目的，这个着色器应该足够了。

现在我们有了所需的着色器，我们可以创建一个 PyQt 应用程序来使用它们。

# 使用 QOpenGLWidget 嵌入 OpenGL 绘图

为了了解 OpenGL 如何与 PyQt 一起工作，我们将使用我们的着色器制作一个简单的 OpenGL 图像，通过 PyQt 界面我们将能够控制它。从第四章中创建一个 Qt 应用程序模板的副本，*使用 QMainWindow 构建应用程序*，并将其命名为`wedge_animation.py`。将其放在与您的`shader`文件相同的目录中。

然后，首先在`MainWindow.__init__()`中添加此代码：

```py
        self.resize(800, 600)
        main = qtw.QWidget()
        self.setCentralWidget(main)
        main.setLayout(qtw.QVBoxLayout())
        oglw = GlWidget()
        main.layout().addWidget(oglw)
```

此代码创建我们的中央小部件并向其添加一个`GlWidget`对象。`GlWidget`类是我们将创建的用于显示我们的 OpenGL 绘图的类。要创建它，我们需要对可以显示 OpenGL 内容的小部件进行子类化。

# OpenGLWidget 的第一步

有两个 Qt 类可用于显示 OpenGL 内容：`QtWidgets.QOpenGLWidget`和`QtGui.QOpenGLWindow`。在实践中，它们的行为几乎完全相同，但`OpenGLWindow`提供了稍微更好的性能，如果您不想使用任何其他 Qt 小部件（即，如果您的应用程序只是全屏 OpenGL 内容），可能是更好的选择。在我们的情况下，我们将把我们的 OpenGL 绘图与其他小部件组合在一起，因此我们将使用`QOpenGLWidget`作为我们的类的基础：

```py
class GlWidget(qtw.QOpenGLWidget):
    """A widget to display our OpenGL drawing"""
```

要在我们的小部件上创建 OpenGL 内容，我们需要重写两个`QOpenGLWidget`方法：

+   `initializeGL()`，它只运行一次来设置我们的 OpenGL 绘图

+   `paintGL()`在我们的小部件需要绘制自己时（例如，响应`update()`调用）调用

我们将从`initializeGL()`开始：

```py
    def initializeGL(self):
        super().initializeGL()
        gl_context = self.context()
        version = qtg.QOpenGLVersionProfile()
        version.setVersion(2, 1)
        self.gl = gl_context.versionFunctions(version)
```

我们需要做的第一件事是访问我们的 OpenGL API。API 由一组函数、变量和常量组成；在诸如 PyQt 之类的面向对象平台中，我们将创建一个包含这些函数作为方法以及变量和常量作为属性的特殊 OpenGL 函数对象。

为此，我们首先从`QOpenGLWidget`方法中检索一个 OpenGL**上下文**。上下文表示我们当前绘制的 OpenGL 表面的接口。从上下文中，我们可以检索包含我们的 API 的对象。

因为我们需要访问特定版本的 API（2.1），我们首先需要创建一个`QOpenGLVersionProfile`对象，并将其`version`属性设置为`(2, 1)`。这可以传递给上下文的`versionFunctions()`方法，该方法将返回一个`QOpenGLFunctions_2_1`对象。这是包含我们的 OpenGL 2.1 API 的对象。

Qt 还为其他版本的 OpenGL 定义了 OpenGL 函数对象，但请注意，根据您的平台、硬件以及您获取 Qt 的方式，可能会或可能不会支持特定版本。

我们将`functions`对象保存为`self.gl`；我们所有的 API 调用都将在这个对象上进行。

既然我们可以访问 API，让我们开始配置 OpenGL：

```py
        self.gl.glEnable(self.gl.GL_DEPTH_TEST)
        self.gl.glDepthFunc(self.gl.GL_LESS)
        self.gl.glEnable(self.gl.GL_CULL_FACE)
```

与 Qt 类似，OpenGL 使用定义的常量来表示各种设置和状态。配置 OpenGL 主要是将这些常量传递给各种 API 函数，以切换各种设置。

在这种情况下，我们执行三个设置：

+   将`GL_DEPTH_TEST`传递给`glEnable()`会激活**深度测试**，这意味着 OpenGL 将尝试弄清楚其绘制的点中哪些在前景中，哪些在背景中。

+   `glDepthFunc()`设置将确定是否绘制深度测试像素的函数。在这种情况下，`GL_LESS`常量表示将绘制深度最低的像素（即最接近我们的像素）。通常，这是您想要的设置，也是默认设置。

+   将`GL_CULL_FACE`传递给`glEnable()`会激活**面剔除**。这意味着 OpenGL 不会绘制观看者实际看不到的物体的侧面。这也是有意义的，因为它节省了本来会被浪费的资源。

这三个优化应该有助于减少我们的动画使用的资源；在大多数情况下，您会想要使用它们。还有许多其他可以启用和配置的选项；有关完整列表，请参见[`www.khronos.org/registry/OpenGL-Refpages/gl2.1/xhtml/glEnable.xml`](https://www.khronos.org/registry/OpenGL-Refpages/gl2.1/xhtml/glEnable.xml)。请注意，有些选项只适用于使用 OpenGL 的旧固定功能方法。

如果你看到使用`glBegin()`和`glEnd()`的 OpenGL 代码，那么它使用的是非常古老的 OpenGL 1.x 固定功能绘图 API。这种方法更容易，但更有限，所以不应该用于现代 OpenGL 编程。

# 创建一个程序

在实现 OpenGL 绘图的下一步是创建我们的程序。您可能还记得，OpenGL 程序是由一组着色器组成的，形成一个完整的管道。

在 Qt 中，创建程序的过程如下：

1.  创建一个`QOpenGLShaderProgram`对象

1.  将您的着色器代码添加到程序中

1.  将代码链接成完整的程序

以下代码将实现这一点：

```py
        self.program = qtg.QOpenGLShaderProgram()
        self.program.addShaderFromSourceFile(
            qtg.QOpenGLShader.Vertex, 'vertex_shader.glsl')
        self.program.addShaderFromSourceFile(
            qtg.QOpenGLShader.Fragment, 'fragment_shader.glsl')
        self.program.link()
```

着色器可以从文件中添加，就像我们在这里使用`addShaderFromSourceFile()`做的那样，也可以从字符串中添加，使用`addShaderFromSourceCode()`。我们在这里使用相对文件路径，但最好的方法是使用 Qt 资源文件（参见第六章中的*使用 Qt 资源文件*部分，*Qt 应用程序的样式*）。当文件被添加时，Qt 会编译着色器代码，并将任何编译错误输出到终端。

在生产代码中，您会想要检查`addShaderFromSourceFile()`的布尔输出，以查看您的着色器是否成功编译，然后再继续。

请注意，`addShaderFromSourceFile()`的第一个参数指定了我们要添加的着色器的类型。这很重要，因为顶点着色器和片段着色器有非常不同的要求和功能。

一旦所有着色器都加载完毕，我们调用`link()`将所有编译的代码链接成一个准备执行的程序。

# 访问我们的变量

我们的着色器程序包含了一些我们需要能够访问并放入值的变量，因此我们需要检索这些变量的句柄。`QOpenGLProgram`对象有两种方法，`attributeLocation()`和`uniformLocation()`，分别用于检索属性和统一变量的句柄（对于`varying`类型没有这样的函数）。

让我们为我们的`vertex`着色器变量获取一些句柄：

```py
        self.vertex_location = self.program.attributeLocation('vertex')
        self.matrix_location = self.program.uniformLocation('matrix')
        self.color_location = self.program.attributeLocation('color_attr')
```

这些方法返回的值实际上只是整数；在内部，OpenGL 只是使用顺序整数来跟踪和引用对象。然而，这对我们来说并不重要。我们可以将其视为对象句柄，并将它们传递到 OpenGL 调用中，以访问这些变量，很快您就会看到。

# 配置投影矩阵

在 OpenGL 中，**投影矩阵**定义了我们的 3D 模型如何投影到 2D 屏幕上。这由一个 4x4 的数字矩阵表示，可以用来计算顶点位置。在我们进行任何绘图之前，我们需要定义这个矩阵。

在 Qt 中，我们可以使用`QMatrix4x4`对象来表示它：

```py
        self.view_matrix = qtg.QMatrix4x4()
```

`QMatrix4x4`对象非常简单，它是一个按四行四列排列的数字表。然而，它有几种方法，允许我们以这样的方式操纵这些数字，使它们代表 3D 变换，比如我们的投影。

OpenGL 可以使用两种投影方式——**正交**，意味着所有深度的点都被渲染为相同的，或者**透视**，意味着视野随着我们远离观察者而扩展。对于逼真的 3D 绘图，您将希望使用透视投影。这种投影由**视锥体**表示。

视锥体是两个平行平面之间的一个常规几何固体的一部分，它是用来描述视野的有用形状。要理解这一点，把你的手放在头两侧。现在，把它们向前移动，保持它们刚好在你的视野之外。注意，为了做到这一点，你必须向外移动（向左和向右）。再试一次，把你的手放在头上和头下。再一次，你必须垂直向外移动，以使它们远离你的视野。

您刚刚用手做的形状就像一个金字塔，从您的眼睛延伸出来，其顶点被切成与底部平行的形状，换句话说，是一个视锥体。

要创建表示透视视锥体的矩阵，我们可以使用`matrix`对象的`perspective()`方法：

```py
        self.view_matrix.perspective(
            45,  # Angle
            self.width() / self.height(),  # Aspect Ratio
            0.1,  # Near clipping plane
            100.0  # Far clipping plane
        )
```

`perspective()`方法需要四个参数：

+   从近平面到远平面扩展的角度，以度为单位

+   近平面和远平面的纵横比（相同）

+   近平面向屏幕的深度

+   远平面向屏幕的深度

不用深入复杂的数学，这个矩阵有效地表示了我们相对于绘图的视野。当我们开始绘图时，我们将看到，我们移动对象所需做的就是操纵矩阵。

例如，我们可能应该从我们将要绘制的地方稍微后退一点，这样它就不会发生在视野的最前面。这种移动可以通过`translate()`方法来实现：

```py
        self.view_matrix.translate(0, 0, -5)
```

`translate`需要三个参数——x 量、y 量和 z 量。在这里，我们指定了一个 z 平移量为`-5`，这将使对象深入屏幕。

现在这一切可能看起来有点混乱，但是，一旦我们开始绘制形状，事情就会变得更清晰。

# 绘制我们的第一个形状

现在我们的 OpenGL 环境已经初始化，我们可以继续进行`paintGL()`方法。这个方法将包含绘制我们的 3D 对象的所有代码，并且在小部件需要更新时将被调用。

绘画时，我们要做的第一件事是清空画布：

```py
    def paintGL(self):
        self.gl.glClearColor(0.1, 0, 0.2, 1)
        self.gl.glClear(
            self.gl.GL_COLOR_BUFFER_BIT | self.gl.GL_DEPTH_BUFFER_BIT)
        self.program.bind()
```

`glClearColor()`用于用指定的颜色填充绘图的背景。在 OpenGL 中，颜色使用三个或四个值来指定。在三个值的情况下，它们代表红色、绿色和蓝色。第四个值，当使用时，代表颜色的**alpha**或不透明度。与 Qt 不同，其中 RGB 值是从`0`到`255`的整数，OpenGL 颜色值是从`0`到`1`的浮点数。我们前面的值描述了深紫蓝色；可以随意尝试其他值。

您应该在每次重绘时使用`glClearColor`重新绘制背景；如果不这样做，之前的绘画操作仍然可见。如果您进行动画或调整绘图大小，这将是一个问题。

`glClear()`函数用于清除 GPU 上的各种内存缓冲区，我们希望在重绘之间重置它们。在这种情况下，我们指定了一些常量，导致 OpenGL 清除颜色缓冲区和深度缓冲区。这有助于最大化性能。

最后，我们`bind()`程序对象。由于 OpenGL 应用程序可以有多个程序，我们调用`bind()`告诉 OpenGL 我们即将发出的命令适用于这个特定的程序。

现在我们可以绘制我们的形状了。

OpenGL 中的形状是用顶点描述的。您可能还记得，顶点本质上是 3D 空间中的一个点，由*X*、*Y*和*Z*坐标描述，并定义了一个基本图元的一个角或端点。

让我们创建一个顶点列表来描述一个楔形的前面是三角形：

```py
        front_vertices = [
            qtg.QVector3D(0.0, 1.0, 0.0),  # Peak
            qtg.QVector3D(-1.0, 0.0, 0.0),  # Bottom left
            qtg.QVector3D(1.0, 0.0, 0.0)  # Bottom right
            ]
```

我们的顶点数据不必分组成任何类型的不同对象，但是为了方便和可读性，我们使用`QVector3D`对象来保存三角形中每个顶点的坐标。

这里使用的数字代表网格上的点，其中`(0, 0, 0)`是我们 OpenGL 视口的中心在最前面的点。x 轴从屏幕左侧的`-1`到右侧的`1`，y 轴从屏幕顶部的`1`到底部的`-1`。z 轴有点不同；如果想象视野（我们之前描述的视锥体）作为一个形状从显示器背面扩展出来，负 z 值会推进到视野的更深处。正 z 值会移出屏幕朝着（最终在后面）观察者。因此，通常我们将使用负值或零值的 z 来保持在可见范围内。

默认情况下，OpenGL 将以黑色绘制，但是有一些颜色会更有趣。因此，我们将定义一个包含一些颜色的`tuple`对象：

```py
        face_colors = (
            qtg.QColor('red'),
            qtg.QColor('orange'),
            qtg.QColor('yellow'),
        )
```

我们在这里定义了三种颜色，每个三角形顶点一个。这些是`QColor`对象，但是请记住 OpenGL 需要颜色作为值在`0`和`1`之间的向量。

为了解决这个问题，我们将创建一个小方法将`QColor`转换为 OpenGL 友好的向量：

```py
    def qcolor_to_glvec(self, qcolor):
        return qtg.QVector3D(
            qcolor.red() / 255,
            qcolor.green() / 255,
            qcolor.blue() / 255
        )
```

这段代码相当不言自明，它将创建另一个带有转换后的 RGB 值的`QVector3D`对象。

回到`paintGL()`，我们可以使用列表推导将我们的颜色转换为可用的东西：

```py
        gl_colors = [
            self.qcolor_to_glvec(color)
            for color in face_colors
        ]
```

此时，我们已经定义了一些顶点和颜色数据，但是我们还没有发送任何数据到 OpenGL；这些只是我们 Python 脚本中的数据值。要将这些传递给 OpenGL，我们需要在`initializeGL()`中获取的那些变量句柄。

我们将传递给我们的着色器的第一个变量是`matrix`变量。我们将使用我们在`initializeGL()`中定义的`view_matrix`对象：

```py
        self.program.setUniformValue(
            self.matrix_location, self.view_matrix)
```

`setUniformValue()`可以用来设置`uniform`变量的值；我们可以简单地传递`uniformLocation()`获取的`GLSL`变量的句柄和我们创建的`matrix`对象来定义我们的投影和视野。

您还可以使用`setAttributeValue()`来设置`attribute`变量的值。例如，如果我们希望所有顶点都是红色，我们可以添加这个：

```py
        self.program.setAttributeValue(
            self.color_location, gl_colors[0])
```

但我们不要这样做；如果每个顶点都有自己的颜色会看起来更好。

为此，我们需要创建一些**属性数组。**属性数组是将传递到属性类型变量中的数据数组。请记住，在 GLSL 中标记为属性的变量将为每个顶点应用一个不同的值。因此，实际上我们告诉 OpenGL，*这里有一些数据数组，其中每个项目都应用于一个顶点*。

代码看起来像这样：

```py
        self.program.enableAttributeArray(self.vertex_location)
        self.program.setAttributeArray(
            self.vertex_location, front_vertices)
        self.program.enableAttributeArray(self.color_location)
        self.program.setAttributeArray(self.color_location, gl_colors)
```

第一步是通过使用要设置数组的变量的句柄调用`enableAttributeArray()`来启用`GLSL`变量上的数组。然后，我们使用`setAttributeArray()`传递数据。这实际上意味着我们的`vertex`着色器将在`front_vertices`数组中的每个项目上运行。每次该着色器运行时，它还将从`gl_colors`列表中获取下一个项目，并将其应用于`color_attr`变量。

如果您像这样使用多个属性数组，您需要确保数组中有足够的项目来覆盖所有顶点。如果我们只定义了两种颜色，第三个顶点将为`color_attr`提取垃圾数据，导致未定义的输出。

现在我们已经排队了我们第一个基元的所有数据，让我们使用以下代码进行绘制：

```py
        self.gl.glDrawArrays(self.gl.GL_TRIANGLES, 0, 3)
```

`glDrawArrays()`将发送我们定义的所有数组到管道中。`GL_TRIANGLES`参数告诉 OpenGL 它将绘制三角形基元，接下来的两个参数告诉它从数组项`0`开始绘制三个项。

如果此时运行程序，您应该会看到我们绘制了一个红色和黄色的三角形。不错！现在，让我们让它成为 3D。

# 创建一个 3D 对象

为了制作一个 3D 对象，我们需要绘制楔形对象的背面和侧面。我们将首先通过列表推导来计算楔形的背面坐标：

```py
        back_vertices = [
            qtg.QVector3D(x.toVector2D(), -0.5)
            for x in front_vertices]
```

为了创建背面，我们只需要复制每个正面坐标并将 z 轴向后移一点。因此，我们使用`QVector3D`对象的`toVector2D()`方法来产生一个只有 x 和 y 轴的新向量，然后将其传递给一个新的`QVector3D`对象的构造函数，同时指定新的 z 坐标作为第二个参数。

现在，我们将把这组顶点传递给 OpenGL 并进行绘制如下：

```py
        self.program.setAttributeArray(
            self.vertex_location, reversed(back_vertices))
        self.gl.glDrawArrays(self.gl.GL_TRIANGLES, 0, 3)
```

通过将这些写入`vertex_location`，我们已经覆盖了已经绘制的正面顶点，并用背面顶点替换了它们。然后，我们对`glDrawArrays()`进行相同的调用，新的顶点集将被绘制，以及相应的颜色。

您将注意到我们在绘制之前会颠倒顶点的顺序。当 OpenGL 显示一个基元时，它只显示该基元的一面，因为假定该基元是某个 3D 对象的一部分，其内部不需要被绘制。OpenGL 根据基元的点是顺时针还是逆时针绘制来确定应该绘制哪一面的基元。默认情况下，绘制逆时针的基元的近面，因此我们将颠倒背面顶点的顺序，以便绘制顺时针并显示其远面（这将是楔形的外部）。

让我们通过绘制其侧面来完成我们的形状。与前面和后面不同，我们的侧面是矩形，因此每个侧面都需要四个顶点来描述它们。

我们将从我们的另外两个列表中计算出这些顶点：

```py
        sides = [(0, 1), (1, 2), (2, 0)]
        side_vertices = list()
        for index1, index2 in sides:
            side_vertices += [
                front_vertices[index1],
                back_vertices[index1],
                back_vertices[index2],
                front_vertices[index2]
            ]
```

`sides`列表包含了`front_vertices`和`back_vertices`列表的索引，它们定义了每个三角形的侧面。我们遍历这个列表，对于每一个，定义一个包含四个顶点描述楔形一个侧面的列表。

请注意，这四个顶点是按逆时针顺序绘制的，就像正面一样（您可能需要在纸上草图来看清楚）。

我们还将定义一个新的颜色列表，因为现在我们需要更多的颜色：

```py
        side_colors = [
            qtg.QColor('blue'),
            qtg.QColor('purple'),
            qtg.QColor('cyan'),
            qtg.QColor('magenta'),
        ]
        gl_colors = [
            self.qcolor_to_glvec(color)
            for color in side_colors
        ] * 3
```

我们的侧面顶点列表包含了总共 12 个顶点（每个侧面 4 个），所以我们需要一个包含 12 个颜色的列表来匹配它。我们可以通过只指定 4 种颜色，然后将 Python 的`list`对象乘以 3 来产生一个重复的列表，总共有 12 个项目。

现在，我们将把这些数组传递给 OpenGL 并进行绘制：

```py
        self.program.setAttributeArray(self.color_location, gl_colors)
        self.program.setAttributeArray(self.vertex_location, side_vertices)
        self.gl.glDrawArrays(self.gl.GL_QUADS, 0, len(side_vertices))
```

这一次，我们使用`GL_QUADS`作为第一个参数，而不是`GL_TRIANGLES`，以指示我们正在绘制四边形。

OpenGL 可以绘制多种不同的基元类型，包括线、点和多边形。大多数情况下，您应该使用三角形，因为这是大多数图形硬件上最快的基元。

现在我们所有的点都绘制完毕，我们来清理一下：

```py
        self.program.disableAttributeArray(self.vertex_location)
        self.program.disableAttributeArray(self.color_location)
        self.program.release()
```

在我们简单的演示中，这些调用并不是严格必要的，但是在一个更复杂的程序中，它们可能会为您节省一些麻烦。OpenGL 作为一个状态机运行，其中操作的结果取决于系统的当前状态。当我们绑定或启用特定对象时，OpenGL 就会指向该对象，并且某些操作（例如设置数组数据）将自动指向它。当我们完成绘图操作时，我们不希望将 OpenGL 指向我们的对象，因此在完成后释放和禁用对象是一个良好的做法。

如果现在运行应用程序，您应该会看到您惊人的 3D 形状：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/67c57d27-65dc-43bf-ada2-e4e1549f0e6d.png)

哎呀，不太 3D，是吧？实际上，我们*已经*绘制了一个 3D 形状，但你看不到，因为我们直接在它上面看。在下一节中，我们将创建一些代码来使这个形状动起来，并充分欣赏它的所有维度。

# OpenGL 绘图的动画和控制

为了感受我们绘图的 3D 特性，我们将在 GUI 中构建一些控件，允许我们围绕绘图进行旋转和缩放。

我们将从在`MainWindow.__init__()`中添加一些按钮开始，这些按钮可以用作控件：

```py
        btn_layout = qtw.QHBoxLayout()
        main.layout().addLayout(btn_layout)
        for direction in ('none', 'left', 'right', 'up', 'down'):
            button = qtw.QPushButton(
                direction,
                autoExclusive=True,
                checkable=True,
                clicked=getattr(oglw, f'spin_{direction}'))
            btn_layout.addWidget(button)
        zoom_layout = qtw.QHBoxLayout()
        main.layout().addLayout(zoom_layout)
        zoom_in = qtw.QPushButton('zoom in', clicked=oglw.zoom_in)
        zoom_layout.addWidget(zoom_in)
        zoom_out = qtw.QPushButton('zoom out', clicked=oglw.zoom_out)
        zoom_layout.addWidget(zoom_out)
```

我们在这里创建了两组按钮；第一组将是一组单选样式的按钮（因此一次只能有一个被按下），它们将选择对象的旋转方向——无（不旋转）、左、右、上或下。每个按钮在激活时都会调用`GlWidget`对象上的相应方法。

第二组包括一个放大和一个缩小按钮，分别在`GlWidget`上调用`zoom_in()`或`zoom_out()`方法。通过将这些按钮添加到我们的 GUI，让我们跳到`GlWidget`并实现回调方法。

# 在 OpenGL 中进行动画

动画我们的楔形纯粹是通过操纵`view`矩阵并重新绘制我们的图像。我们将在`GlWidget.initializeGL()`中通过创建一个实例变量来保存旋转值：

```py
        self.rotation = [0, 0, 0, 0]
```

此列表中的第一个值表示旋转角度；其余的值是`view`矩阵将围绕的点的*X*、*Y*和*Z*坐标。

在`paintGL()`的末尾，我们可以将这些值传递给`matrix`对象的`rotate()`方法：

```py
        self.view_matrix.rotate(*self.rotation)
```

现在，这将不起作用，因为我们的旋转值都是`0`。要进行旋转，我们将不得不改变`self.rotation`并触发图像的重绘。

因此，我们的旋转回调看起来像这样：

```py
    def spin_none(self):
        self.rotation = [0, 0, 0, 0]

    def spin_left(self):
        self.rotation = [-1, 0, 1, 0]

    def spin_right(self):
        self.rotation = [1, 0, 1, 0]

    def spin_up(self):
        self.rotation = [1, 1, 0, 0]

    def spin_down(self):
        self.rotation = [-1, 1, 0, 0]
```

每个方法只是改变了我们旋转向量的值。角度向前（`1`）或向后（`1`）移动一个度数，围绕一个适当的点产生所需的旋转。

现在，我们只需要通过触发重复的重绘来启动动画。在`paintGL()`的末尾，添加这一行：

```py
        self.update()
```

`update()`在`event`循环中安排了一次重绘，这意味着这个方法会一遍又一遍地被调用。每次，我们的`view`矩阵都会按照`self.rotation`中设置的角度进行旋转。

# 放大和缩小

我们还想要实现缩放。每次点击放大或缩小按钮时，我们希望图像可以稍微靠近或远离一点。

这些回调看起来像这样：

```py
    def zoom_in(self):
        self.view_matrix.scale(1.1, 1.1, 1.1)

    def zoom_out(self):
        self.view_matrix.scale(.9, .9, .9)
```

`QMatrix4x4`的`scale()`方法会使矩阵将每个顶点点乘以给定的数量。因此，我们可以使我们的对象缩小或放大，产生它更近或更远的错觉。

我们可以在这里使用`translate()`，但是在旋转时使用平移可能会导致一些混乱的结果，我们很快就会失去对我们对象的视野。

现在，当您运行应用程序时，您应该能够旋转您的楔形并以其所有的 3D 光辉看到它：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/58b84077-1876-4e42-81a2-61c883b69a2d.png)

这个演示只是 OpenGL 可以做的开始。虽然本章可能没有使您成为 OpenGL 专家，但希望您能更加自如地深入挖掘本章末尾的资源。

# 总结

在本章中，您已经了解了如何使用 OpenGL 创建 3D 动画，以及如何将它们集成到您的 PyQt 应用程序中。我们探讨了 OpenGL 的基本原理，如渲染管道、着色器和 GLSL。我们学会了如何使用 Qt 小部件作为 OpenGL 上下文来绘制和动画一个简单的 3D 对象。

在下一章中，我们将学习使用`QtCharts`模块交互地可视化数据。我们将创建基本的图表和图形，并学习如何使用模型-视图架构构建图表。

# 问题

尝试这些问题来测试您从本章中学到的知识：

1.  OpenGL 渲染管线的哪些步骤是可由用户定义的？为了渲染任何东西，必须定义哪些步骤？您可能需要参考文档[`www.khronos.org/opengl/wiki/Rendering_Pipeline_Overview`](https://www.khronos.org/opengl/wiki/Rendering_Pipeline_Overview)。

1.  您正在为一个 OpenGL 2.1 程序编写着色器。以下内容看起来正确吗？

```py
   #version 2.1

   attribute highp vec4 vertex;

   void main (void)
   {
   gl_Position = vertex;
   }
```

1.  以下是“顶点”还是“片段”着色器？你如何判断？

```py
   attribute highp vec4 value1;
   varying highp vec3 x[4];
   void main(void)
   {
     x[0] = vec3(sin(value1[0] * .4));
     x[1] = vec3(cos(value1[1]));
     gl_Position = value1;
     x[2] = vec3(10 * x[0])
   }
```

1.  给定以下“顶点”着色器，您需要编写什么代码来为这两个变量分配简单的值？

```py
   attribute highp vec4 coordinates;
   uniform highp mat4 matrix1;

   void main(void){
     gl_Position = matrix1 * coordinates;
   }
```

1.  您启用面剔除以节省一些处理能力，但发现绘图中的几个可见基元现在没有渲染。问题可能是什么？

1.  以下代码对我们的 OpenGL 图像有什么影响？

```py
   matrix = qtg.QMatrix4x4()
   matrix.perspective(60, 4/3, 2, 10)
   matrix.translate(1, -1, -4)
   matrix.rotate(45, 1, 0, 0)
```

1.  尝试使用演示，看看是否可以添加以下功能：

+   +   更有趣的形状（金字塔、立方体等）

+   移动对象的更多控制

+   阴影和光照效果

+   对象中的动画形状变化

# 进一步阅读

欲了解更多信息，请参考以下内容：

+   现代 OpenGL 编程的完整教程可以在[`paroj.github.io/gltut`](https://paroj.github.io/gltut)找到。

+   Packt Publications 的*Learn OpenGL*，网址为[`www.packtpub.com/game-development/learn-opengl`](https://www.packtpub.com/game-development/learn-opengl)，是学习 OpenGL 基础知识的良好资源

+   中央康涅狄格州立大学提供了一份关于 3D 图形矩阵数学的免费教程，网址为[`chortle.ccsu.edu/VectorLessons/vectorIndex.html`](https://chortle.ccsu.edu/VectorLessons/vectorIndex.html)。


# 第十四章：使用 QtCharts 嵌入数据图

世界充满了数据。从服务器日志到财务记录，传感器遥测到人口普查统计数据，程序员们需要筛选和提取意义的原始数据似乎没有尽头。除此之外，没有什么比一个好的图表或图形更有效地将一组原始数据提炼成有意义的信息。虽然 Python 有一些很棒的图表工具，比如`matplotlib`，PyQt 还提供了自己的`QtCharts`库，这是一个用于构建图表、图形和其他数据可视化的简单工具包。

在本章中，我们将探讨以下主题中使用`QtCharts`进行数据可视化：

+   创建一个简单的图表

+   显示实时数据

+   Qt 图表样式

# 技术要求

除了我们在整本书中一直使用的基本 PyQt 设置之外，您还需要为`QtCharts`库安装 PyQt 支持。这种支持不是默认的 PyQt 安装的一部分，但可以通过 PyPI 轻松安装，如下所示：

```py
$ pip install --user PyQtChart
```

您还需要`psutil`库，可以从 PyPI 安装。我们已经在第十二章中使用过这个库，*使用 QPainter 创建 2D 图形*，所以如果您已经阅读了那一章，那么您应该已经有了它。如果没有，可以使用以下命令轻松安装：

```py
$ pip install --user psutil
```

最后，您可能希望从[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter14`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter14)下载本章的示例代码。

查看以下视频以查看代码的运行情况：[`bit.ly/2M5y67f`](http://bit.ly/2M5y67f)

# 创建一个简单的图表

在第十二章 *使用 QPainter 创建 2D 图形*中，我们使用 Qt 图形框架和`psutil`库创建了一个 CPU 活动图。虽然这种构建图表的方法效果很好，但是创建一个缺乏简单美观性的基本图表需要大量的工作。`QtChart`库也是基于 Qt 图形框架的，但简化了各种功能完备的图表的创建。

为了演示它的工作原理，我们将构建一个更完整的系统监控程序，其中包括几个图表，这些图表是从`psutil`库提供的数据派生出来的。

# 设置 GUI

要开始我们的程序，将 Qt 应用程序模板从第四章 *使用 QMainWindow 构建应用程序*复制到一个名为`system_monitor.py`的新文件中。

在应用程序的顶部，我们需要导入`QtChart`库：

```py
from PyQt5 import QtChart as qtch
```

我们还需要`deque`类和`psutil`库，就像我们在[第十二章](https://cdp.packtpub.com/mastering_gui_programming_with_python/wp-admin/post.php?post=37&action=edit#post_35) *使用 QPainter 创建 2D 图形*中所需要的那样：

```py
from collections import deque
import psutil
```

我们的程序将包含几个图表，每个图表都在自己的选项卡中。因此，我们将在`MainWindow.__init__()`中创建一个选项卡小部件来容纳所有的图表：

```py
        tabs = qtw.QTabWidget()
        self.setCentralWidget(tabs)
```

现在 GUI 的主要框架已经就位，我们将开始创建我们的图表类并将它们添加到 GUI 中。

# 构建磁盘使用情况图

我们将创建的第一个图表是一个条形图，用于显示计算机上每个存储分区使用的磁盘空间。每个检测到的分区都将有一个条形表示其使用空间的百分比。

让我们从为图表创建一个类开始：

```py
class DiskUsageChartView(qtch.QChartView):

    chart_title = 'Disk Usage by Partition'

    def __init__(self):
        super().__init__()
```

该类是从`QtChart.QChartView`类派生的；这个`QGraphicsView`的子类是一个可以显示`QChart`对象的小部件。就像 Qt 图形框架一样，`QtChart`框架也是基于模型-视图设计的。在这种情况下，`QChart`对象类似于`QGraphicsScene`对象，它将附加到`QChartView`对象以进行显示。

让我们创建我们的`QChart`对象，如下所示：

```py
        chart = qtch.QChart(title=self.chart_title)
        self.setChart(chart)
```

`QChart`对象接收一个标题，但是，除此之外，不需要太多的配置；请注意，它也没有说它是条形图。与您可能使用过的其他图表库不同，`QChart`对象不确定我们正在创建什么样的图表。它只是数据图的容器。

实际的图表类型是通过向图表添加一个或多个**系列**对象来确定的。一个系列代表图表上的单个绘制数据集。`QtChart`包含许多系列类，所有这些类都是从`QAbstractSeries`派生的，每个类代表不同类型的图表样式。

其中一些类如下：

| 类 | 图表类型 | 有用于 |
| --- | --- | --- |
| `QLineSeries` | 直线图 | 从连续数据中采样的点 |
| `QSplineSeries` | 线图，但带有曲线 | 从连续数据中采样的点 |
| `QBarSeries` | 条形图 | 按类别比较值 |
| `QStackedBarSeries` | 堆叠条形图 | 按类别比较细分值 |
| `QPieSeries` | 饼图 | 相对百分比 |
| `QScatterSeries` | 散点图 | 点的集合 |

可以在[`doc.qt.io/qt-5/qtcharts-overview.html`](https://doc.qt.io/qt-5/qtcharts-overview.html)找到可用系列类型的完整列表。我们的图表将比较多个分区的磁盘使用百分比，因此在这些选项中使用最合理的系列类型似乎是`QBarSeries`类。每个分区将是一个*类别*，并且将与之关联一个单个值（使用百分比）。

让我们创建`QBarSeries`类，如下：

```py
        series = qtch.QBarSeries()
        chart.addSeries(series)
```

创建系列对象后，我们可以使用`addSeries()`方法将其添加到我们的图表中。从这个方法的名称，您可能会怀疑，我们实际上可以将多个系列添加到图表中，它们不一定都是相同类型的。例如，我们可以在同一个图表中结合条形和线系列。但在我们的情况下，我们只会有一个系列。

要向我们的系列附加数据，我们必须创建一个称为**条形集**的东西：

```py
        bar_set = qtch.QBarSet('Percent Used')
        series.append(bar_set)
```

Qt 条形图旨在显示类别数据，但也允许比较这些类别中的不同数据集。例如，如果您想要比较公司产品在美国各个城市的相对销售成功情况，您可以使用城市作为类别，并为每种产品创建一个条形集。

在我们的情况下，类别将是系统上的分区，我们只有一个数据集要查看每个分区的数据 - 即磁盘使用百分比。

因此，我们将创建一个要附加到我们系列的单个条形集：

```py
        bar_set = qtch.QBarSet('Percent Used')
        series.append(bar_set)
```

`QBarSet`构造函数接受一个参数，表示数据集的标签。这个`QBarSet`对象是我们要附加实际数据的对象。

因此，让我们继续检索数据：

```py
        partitions = []
        for part in psutil.disk_partitions():
            if 'rw' in part.opts.split(','):
                partitions.append(part.device)
                usage = psutil.disk_usage(part.mountpoint)
                bar_set.append(usage.percent)
```

这段代码利用了`pustil`的`disk_partitions()`函数列出系统上所有可写的分区（我们对只读设备不感兴趣，例如光驱，因为它们的使用是无关紧要的）。对于每个分区，我们使用`disk_usage()`函数检索有关磁盘使用情况的命名元组信息。这个元组的`percent`属性包含磁盘使用百分比，因此我们将该值附加到我们的条形集。我们还将分区的设备名称附加到分区列表中。

到目前为止，我们的图表包含一个数据系列，并且可以显示数据的条形。但是，从图表中提取出很多意义将会很困难，因为没有**轴**来标记数据。为了解决这个问题，我们需要创建一对轴对象来表示*x*和*y*轴。

我们将从*x*轴开始，如下：

```py
        x_axis = qtch.QBarCategoryAxis()
        x_axis.append(partitions)
        chart.setAxisX(x_axis)
        series.attachAxis(x_axis)
```

`QtCharts`提供了不同类型的轴对象来处理组织数据的不同方法。我们的*x*轴由类别组成——每个类别代表计算机上找到的一个分区——因此，我们创建了一个`QBarCategoryAxis`对象来表示*x*轴。为了定义使用的类别，我们将一个字符串列表传递给`append()`方法。

重要的是，我们的类别的顺序要与数据附加到条形集的顺序相匹配，因为每个数据点根据其在系列中的位置进行分类。

创建后，轴必须同时附加到图表和系列上；这是因为图表需要了解轴对象，以便能够正确地标记和缩放轴。这是通过将轴对象传递给图表的`setAxisX()`方法来实现的。系列还需要了解轴对象，以便能够为图表正确地缩放绘图，我们通过将其传递给系列对象的`attachAxis()`方法来实现。

我们的*y*轴表示百分比，所以我们需要一个处理`0`到`100`之间的值的轴类型。我们将使用`QValueAxis`对象，如下所示：

```py
        y_axis = qtch.QValueAxis()
        y_axis.setRange(0, 100)
        chart.setAxisY(y_axis)
        series.attachAxis(y_axis)
```

`QValueAxis`表示显示数字值刻度的轴，并允许我们为值设置适当的范围。创建后，我们可以将其附加到图表和系列上。

此时，我们可以在`MainView.__init__()`中创建图表视图对象的实例，并将其添加到选项卡小部件中：

```py
        disk_usage_view = DiskUsageChartView()
        tabs.addTab(disk_usage_view, "Disk Usage")
```

如果此时运行应用程序，您应该会得到分区使用百分比的显示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/a5c9d296-9255-447f-bb1a-c03e0f2da444.png)

您的显示可能会有所不同，这取决于您的操作系统和驱动器配置。前面的图看起来很不错，但我们可以做一个小小的改进，即在我们的条形上实际放置百分比标签，以便读者可以看到精确的数据值。这可以通过在`DiskUsageChartView.__init__()`中添加以下行来完成：

```py
        series.setLabelsVisible(True)
```

现在当我们运行程序时，我们会得到带有标签的条形，如下所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/fa104c14-f8df-45ab-8620-39906e58bc21.png)

嗯，看来这位作者需要一个更大的硬盘了！

# 显示实时数据

现在我们已经看到了创建静态图表有多么容易，让我们来看看创建实时更新图表的过程。基本上，过程是相同的，但是我们需要定期使用新数据更新图表的数据系列。为了演示这一点，让我们制作一个实时 CPU 使用率监视器。

# 构建 CPU 使用率图表

让我们在一个名为`CPUUsageView`的新类中启动我们的 CPU 监视器：

```py
class CPUUsageView(qtch.QChartView):

    num_data_points = 500
    chart_title = "CPU Utilization"

    def __init__(self):
        super().__init__()
        chart = qtch.QChart(title=self.chart_title)
        self.setChart(chart)
```

就像我们在磁盘使用图表中所做的那样，我们基于`QChartView`创建了这个类，并在构造函数中创建了一个`QChart`对象。我们还定义了一个标题，并且，就像我们在第十二章中所做的那样，*使用 QPainter 创建 2D 图形*，配置了一次显示多少个数据点。不过这次我们要显示更多的点，这样我们就可以得到更详细的图表了。

创建图表对象后，下一步是创建系列对象：

```py
        self.series = qtch.QSplineSeries(name="Percentage")
        chart.addSeries(self.series)
```

这次，我们使用`QSplineSeries`对象；我们也可以使用`QLineSeries`，但是样条版本将使用三次样条曲线连接我们的数据点，使外观更加平滑，这类似于我们在第十二章中使用贝塞尔曲线所实现的效果，*使用 QPainter 创建 2D 图形*。

接下来，我们需要使用一些默认数据填充系列对象，如下所示：

```py
        self.data = deque(
            [0] * self.num_data_points, maxlen=self.num_data_points)
        self.series.append([
            qtc.QPoint(x, y)
            for x, y in enumerate(self.data)
        ])
```

我们再次创建一个`deque`对象来存储数据点，并用零填充它。然后，我们通过使用列表推导式从我们的`deque`对象创建一个`QPoint`对象的列表，将这些数据附加到我们的系列中。与`QBarSeries`类不同，数据直接附加到`QSplineSeries`对象；对于基于线的系列，没有类似于`QBarSet`类的东西。

现在我们的系列已经设置好了，让我们来处理轴：

```py
        x_axis = qtch.QValueAxis()
        x_axis.setRange(0, self.num_data_points)
        x_axis.setLabelsVisible(False)
        y_axis = qtch.QValueAxis()
        y_axis.setRange(0, 100)
        chart.setAxisX(x_axis, self.series)
        chart.setAxisY(y_axis, self.series)
```

因为我们的数据主要是(*x*, *y*)坐标，我们的两个轴都是`QValueAxis`对象。然而，我们的*x*轴坐标的值基本上是没有意义的（它只是`deque`对象中 CPU 使用值的索引），因此我们将通过将轴的`labelsVisible`属性设置为`False`来隐藏这些标签。

请注意，这次我们在使用`setAxisX()`和`setAxisY`设置图表的*x*和*y*轴时，将系列对象与轴一起传递。这样做会自动将轴附加到系列上，并为每个轴节省了额外的方法调用。

由于我们在这里使用曲线，我们应该进行一次外观优化：

```py
        self.setRenderHint(qtg.QPainter.Antialiasing)
```

`QChartView`对象的`renderHint`属性可用于激活**抗锯齿**，这将改善样条曲线的平滑度。

我们的图表的基本框架现在已经完成；现在我们需要一种方法来收集数据并更新系列。

# 更新图表数据

更新数据的第一步是创建一个调用`psutil.cpu_percent()`并更新`deque`对象的方法：

```py
    def refresh_stats(self):
        usage = psutil.cpu_percent()
        self.data.append(usage)
```

要更新图表，我们只需要更新系列中的数据。有几种方法可以做到这一点；例如，我们可以完全删除图表中的所有数据，并`append()`新值。

更好的方法是`replace()`值，如下所示：

```py
        new_data = [
            qtc.QPoint(x, y)
            for x, y in enumerate(self.data)]
        self.series.replace(new_data)
```

首先，我们使用列表推导从我们的`deque`对象生成一组新的`QPoint`对象，然后将列表传递给系列对象的`replace()`方法，该方法交换所有数据。这种方法比清除所有数据并重新填充系列要快一些，尽管任何一种方法都可以。

现在我们有了刷新方法，我们只需要定期调用它；回到`__init__()`，让我们添加一个定时器：

```py
        self.timer = qtc.QTimer(
            interval=200, timeout=self.refresh_stats)
        self.timer.start()
```

这个定时器将每 200 毫秒调用`refresh_stats()`，更新系列，因此也更新了图表。

回到`MainView.__init__()`，让我们添加 CPU 图表：

```py
        cpu_view = CPUUsageView()
        tabs.addTab(cpu_view, "CPU Usage")
```

现在，您可以运行应用程序，单击 CPU 使用率选项卡，查看类似于以下图表的图表：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/57289362-6e4b-409f-bd5a-6d2d74860221.png)

尝试进行一些 CPU 密集型任务，为图表生成一些有趣的数据。

# 在图表周围进行平移和缩放

由于我们的刷新方法每秒调用五次，因此该系列中的数据对于这样一个小图表来说相当详细。这样密集的图表可能是用户希望更详细地探索的内容。为了实现这一功能，我们可以利用`QChart`对象的方法来在图表图像周围进行平移和缩放，并允许用户更好地查看数据。

要为`CPUUsageView`类配置交互控件，我们可以重写`keyPressEvent()`方法，就像我们在第十二章中的游戏中所做的那样，*使用 QPainter 创建 2D 图形*：

```py
    def keyPressEvent(self, event):
        keymap = {
            qtc.Qt.Key_Up: lambda: self.chart().scroll(0, -10),
            qtc.Qt.Key_Down: lambda: self.chart().scroll(0, 10),
            qtc.Qt.Key_Right: lambda: self.chart().scroll(-10, 0),
            qtc.Qt.Key_Left: lambda: self.chart().scroll(10, 0),
            qtc.Qt.Key_Greater: self.chart().zoomIn,
            qtc.Qt.Key_Less: self.chart().zoomOut,
        }
        callback = keymap.get(event.key())
        if callback:
            callback()
```

这段代码与我们在坦克游戏中使用的代码类似——我们创建一个`dict`对象来将键码映射到回调函数，然后检查我们的事件对象，看看是否按下了其中一个映射的键。如果是的话，我们就调用`callback`方法。

我们映射的第一个方法是`QChart.scroll()`。`scroll()`接受*x*和*y*值，并将图表在图表视图中移动相应的量。在这里，我们将箭头键映射到`lambda`函数，以适当地滚动图表。

我们映射的其他方法是`zoomIn()`和`zoomOut()`。它们确切地执行它们的名称所暗示的操作，分别放大或缩小两倍。如果我们想要自定义缩放的量，那么我们可以交替调用`zoom()`方法，该方法接受一个表示缩放因子的浮点值。

如果您现在运行此程序，您应该会发现可以使用箭头键移动图表，并使用尖括号放大或缩小（请记住在大多数键盘上按*Shift*以获得尖括号）。

# Qt 图表样式

Qt 图表默认看起来很好，但让我们面对现实吧——在样式方面，没有人想被困在默认设置中。幸运的是，QtCharts 为我们的可视化组件提供了各种各样的样式选项。

为了探索这些选项，我们将构建第三个图表来显示物理和交换内存使用情况，然后根据我们自己的喜好进行样式化。

# 构建内存图表

我们将像在前面的部分中一样开始这个图表视图对象：

```py
class MemoryChartView(qtch.QChartView):

    chart_title = "Memory Usage"
    num_data_points = 50

    def __init__(self):
        super().__init__()
        chart = qtch.QChart(title=self.chart_title)
        self.setChart(chart)
        series = qtch.QStackedBarSeries()
        chart.addSeries(series)
        self.phys_set = qtch.QBarSet("Physical")
        self.swap_set = qtch.QBarSet("Swap")
        series.append(self.phys_set)
        series.append(self.swap_set)
```

这个类的开始方式与我们的磁盘使用图表类似——通过子类化`QChartView`，定义图表，定义系列，然后定义一些条形集。然而，这一次，我们将使用`QStackedBarSeries`。堆叠条形图与常规条形图类似，只是每个条形集是垂直堆叠而不是并排放置。这种图表对于显示一系列相对百分比很有用，这正是我们要显示的。

在这种情况下，我们将有两个条形集——一个用于物理内存使用，另一个用于交换内存使用，每个都是总内存（物理和交换）的百分比。通过使用堆叠条形图，总内存使用将由条形高度表示，而各个部分将显示该总内存的交换和物理组件。

为了保存我们的数据，我们将再次使用`deque`对象设置默认数据，并将数据附加到条形集中：

```py
        self.data = deque(
            [(0, 0)] * self.num_data_points,
            maxlen=self.num_data_points)
        for phys, swap in self.data:
            self.phys_set.append(phys)
            self.swap_set.append(swap)
```

这一次，`deque`对象中的每个数据点需要有两个值：第一个是物理数据，第二个是交换数据。我们通过使用每个数据点的两元组序列来表示这一点。

下一步，再次是设置我们的轴：

```py
        x_axis = qtch.QValueAxis()
        x_axis.setRange(0, self.num_data_points)
        x_axis.setLabelsVisible(False)
        y_axis = qtch.QValueAxis()
        y_axis.setRange(0, 100)
        chart.setAxisX(x_axis, series)
        chart.setAxisY(y_axis, series)
```

在这里，就像 CPU 使用图表一样，我们的*x*轴只表示数据的无意义索引号，所以我们只是要隐藏标签。另一方面，我们的*y*轴表示一个百分比，所以我们将其范围设置为`0`到`100`。

现在，我们将创建我们的`refresh`方法来更新图表数据：

```py
    def refresh_stats(self):
        phys = psutil.virtual_memory()
        swap = psutil.swap_memory()
        total_mem = phys.total + swap.total
        phys_pct = (phys.used / total_mem) * 100
        swap_pct = (swap.used / total_mem) * 100

        self.data.append(
            (phys_pct, swap_pct))
        for x, (phys, swap) in enumerate(self.data):
            self.phys_set.replace(x, phys)
            self.swap_set.replace(x, swap)
```

`psutil`库有两个函数用于检查内存使用情况：`virtual_memory()`返回有关物理 RAM 的信息；`swap_memory()`返回有关交换文件使用情况的信息。我们正在应用一些基本算术来找出交换和物理内存使用的总内存百分比，然后将这些数据附加到`deque`对象中，并通过迭代来替换条形集中的数据。

最后，我们将在`__init__()`中再次添加我们的定时器来调用刷新方法：

```py
        self.timer = qtc.QTimer(
            interval=1000, timeout=self.refresh_stats)
        self.timer.start()
```

图表视图类现在应该是完全功能的，所以让我们将其添加到`MainWindow`类中并进行测试。

为此，在`MainWindow.__init__()`中添加以下代码：

```py
        cpu_time_view = MemoryChartView()
        tabs.addTab(cpu_time_view, "Memory Usage")
```

如果此时运行程序，应该会有一个每秒更新一次的工作内存使用监视器。这很好，但看起来太像默认设置了；所以，让我们稍微调整一下样式。

# 图表样式

为了给我们的内存图表增添一些个性，让我们回到`MemoryChartView.__init__()`，开始添加代码来样式化图表的各个元素。

我们可以做的最简单但最有趣的改变之一是激活图表的内置动画：

```py
        chart.setAnimationOptions(qtch.QChart.AllAnimations)
```

`QChart`对象的`animationOptions`属性确定图表创建或更新时将运行哪些内置图表动画。选项包括`GridAxisAnimations`，用于动画绘制轴；`SeriesAnimations`，用于动画更新系列数据；`AllAnimations`，我们在这里使用它来激活网格和系列动画；以及`NoAnimations`，你可能猜到了，用于关闭所有动画（当然，这是默认设置）。

如果你现在运行程序，你会看到网格和轴扫过来，并且每个条形从图表底部平滑地弹出。动画本身是预设的每个系列类型；请注意，我们除了设置缓和曲线和持续时间外，无法对其进行自定义：

```py
        chart.setAnimationEasingCurve(
            qtc.QEasingCurve(qtc.QEasingCurve.OutBounce))
        chart.setAnimationDuration(1000)
```

在这里，我们将图表的`animationEasingCurve`属性设置为一个具有*out bounce*缓和曲线的`QtCore.QEasingCurve`对象。我们还将动画时间延长到整整一秒。如果你现在运行程序，你会看到动画会反弹并持续时间稍长。

我们还可以通过启用图表的阴影来进行另一个简单的调整，如下所示：

```py
        chart.setDropShadowEnabled(True)
```

将`dropShadowEnabled`设置为`True`将导致在图表绘图区域周围显示一个阴影，给它一个微妙的 3D 效果。

通过设置图表的`theme`属性，我们可以实现外观上的更明显的变化，如下所示：

```py
        chart.setTheme(qtch.QChart.ChartThemeBrownSand)
```

尽管这被称为图表主题，但它主要影响了绘图所使用的颜色。Qt 5.12 附带了八种图表主题，可以在[`doc.qt.io/qt-5/qchart.html#ChartTheme-enum`](https://doc.qt.io/qt-5/qchart.html#ChartTheme-enum)找到。在这里，我们配置了*Brown Sand*主题，它将使用土地色调来展示我们的数据绘图。

对于我们的堆叠条形图，这意味着堆栈的每个部分将从主题中获得不同的颜色。

我们可以通过设置图表的背景来进行另一个非常显著的改变。这可以通过将`backgroundBrush`属性设置为自定义的`QBrush`对象来实现：

```py
        gradient = qtg.QLinearGradient(
            chart.plotArea().topLeft(), chart.plotArea().bottomRight())
        gradient.setColorAt(0, qtg.QColor("#333"))
        gradient.setColorAt(1, qtg.QColor("#660"))
        chart.setBackgroundBrush(qtg.QBrush(gradient))
```

在这种情况下，我们创建了一个线性渐变，并使用它来创建了一个背景的`QBrush`对象（有关更多讨论，请参阅第六章，*Qt 应用程序的样式*）。

背景也有一个`QPen`对象，用于绘制绘图区域的边框：

```py
        chart.setBackgroundPen(qtg.QPen(qtg.QColor('black'), 5))
```

如果你现在运行程序，可能会发现文字有点难以阅读。不幸的是，没有一种简单的方法可以一次更新图表中所有的文字外观 - 我们需要逐个进行。我们可以从图表的标题文字开始，通过设置`titleBrush`和`titleFont`属性来实现：

```py
        chart.setTitleBrush(
            qtg.QBrush(qtc.Qt.white))
        chart.setTitleFont(qtg.QFont('Impact', 32, qtg.QFont.Bold))
```

修复剩下的文字不能通过`chart`对象完成。为此，我们需要查看如何对图表中的其他对象进行样式设置。

# 修饰轴

图表轴上使用的标签的字体和颜色必须通过我们的轴对象进行设置：

```py
        axis_font = qtg.QFont('Mono', 16)
        axis_brush = qtg.QBrush(qtg.QColor('#EEF'))
        y_axis.setLabelsFont(axis_font)
        y_axis.setLabelsBrush(axis_brush)
```

在这里，我们使用`setLabelsFont()`和`setLabelsBrush()`方法分别设置了*y*轴的字体和颜色。请注意，我们也可以设置*x*轴标签的字体和颜色，但由于我们没有显示*x*标签，所以没有太大意义。

轴对象还可以让我们通过`gridLinePen`属性来设置网格线的样式：

```py
        grid_pen = qtg.QPen(qtg.QColor('silver'))
        grid_pen.setDashPattern([1, 1, 1, 0])
        x_axis.setGridLinePen(grid_pen)
        y_axis.setGridLinePen(grid_pen)
```

在这里，我们设置了一个虚线银色的`QPen`对象来绘制*x*和*y*轴的网格线。顺便说一句，如果你想改变图表上绘制的网格线数量，可以通过设置轴对象的`tickCount`属性来实现：

```py
        y_axis.setTickCount(11)
```

默认的刻度数是`5`，最小值是`2`。请注意，这个数字包括顶部和底部的线，所以为了让网格线每 10%显示一条，我们将轴设置为`11`个刻度。

为了帮助用户区分紧密排列的网格线，我们还可以在轴对象上启用**阴影**：

```py
        y_axis.setShadesVisible(True)
        y_axis.setShadesColor(qtg.QColor('#884'))
```

如你所见，如果你运行应用程序，这会导致网格线之间的每个交替区域根据配置的颜色进行着色，而不是使用默认的背景。

# 修饰图例

在这个图表中我们可能想要修复的最后一件事是**图例**。这是图表中解释哪种颜色对应哪个条形集的部分。图例由`QLegend`对象表示，它会随着我们添加条形集或系列对象而自动创建和更新。

我们可以使用`legend()`访问器方法来检索图表的`QLegend`对象：

```py
        legend = chart.legend()
```

默认情况下，图例没有背景，只是直接绘制在图表背景上。我们可以改变这一点以提高可读性，如下所示：

```py
        legend.setBackgroundVisible(True)
        legend.setBrush(
            qtg.QBrush(qtg.QColor('white')))
```

我们首先通过将`backgroundVisible`设置为`True`来打开背景，然后通过将`brush`属性设置为`QBrush`对象来配置背景的刷子。

文本的颜色和字体也可以进行配置，如下所示：

```py
        legend.setFont(qtg.QFont('Courier', 14))
        legend.setLabelColor(qtc.Qt.darkRed)
```

我们可以使用`setLabelColor()`设置标签颜色，或者使用`setLabelBrush()`方法更精细地控制刷子。

最后，我们可以配置用于指示颜色的标记的形状：

```py
        legend.setMarkerShape(qtch.QLegend.MarkerShapeCircle)
```

这里的选项包括`MarkerShapeCircle`，`MarkerShapeRectangle`和`MarkerShapeFromSeries`，最后一个选择适合正在绘制的系列的形状（例如，线条或样条图的短线，或散点图的点）。

此时，您的内存图表应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/039075c6-d675-44f1-84d3-393b24627858.png)

不错！现在，尝试使用自己的颜色、刷子、笔和字体值，看看您能创造出什么！

# 摘要

在本章中，您学会了如何使用`QtChart`可视化数据。您创建了一个静态表格，一个动画实时表格，以及一个带有自定义颜色和字体的花哨图表。您还学会了如何创建柱状图、堆叠柱状图和样条图。

在下一章中，我们将探讨在树莓派上使用 PyQt 的用法。您将学习如何安装最新版本的 PyQt，以及如何利用树莓派的独特功能将您的 PyQt 应用程序与电路和外部硬件进行接口。

# 问题

尝试这些问题来测试您对本章的了解：

1.  考虑以下数据集的描述。为每个数据集建议一种图表样式：

+   按日期的 Web 服务器点击次数

+   每个销售人员每月的销售数据

+   公司部门过去一年的支持票比例

+   几百株豆类植物的产量与植物高度的图表

1.  以下代码中尚未配置哪个图表组件，结果将是什么？

```py
   data_list = [
       qtc.QPoint(2, 3),
       qtc.QPoint(4, 5),
       qtc.QPoint(6, 7)]
   chart = qtch.QChart()
   series = qtch.QLineSeries()
   series.append(data_list)
   view = qtch.QChartView()
   view.setChart(chart)
   view.show()
```

1.  以下代码有什么问题？

```py
   mainwindow = qtw.QMainWindow()
   chart = qtch.QChart()
   series = qtch.QPieSeries()
   series.append('Half', 50)
   series.append('Other Half', 50)
   mainwindow.setCentralWidget(chart)
   mainwindow.show()
```

1.  您想创建一个柱状图，比较鲍勃和爱丽丝本季度的销售数据。需要添加什么代码？请注意，这里不需要轴：

```py
   bob_sales = [2500, 1300, 800]
   alice_sales = [1700, 1850, 2010]

   chart = qtch.QChart()
   series = qtch.QBarSeries()
   chart.addSeries(series)

   # add code here

   # end code
   view = qtch.QChartView()
   view.setChart(chart)
   view.show()
```

1.  给定一个名为`chart`的`QChart`对象，写一些代码，使图表具有黑色背景和蓝色数据绘图。

1.  使用您为`内存使用情况`图表使用的技术为系统监视器脚本中的另外两个图表设置样式。尝试不同的刷子和笔，看看是否可以找到其他要设置的属性。

1.  `QPolarChart`是`QChart`的一个子类，允许您构建极坐标图。在 Qt 文档中调查极坐标图的使用，并查看是否可以创建一个适当数据集的极坐标图。

1.  `psutil.cpu_percent()`接受一个可选参数`percpu`，它将创建一个显示每个 CPU 核使用信息的值列表。更新您的应用程序以使用此选项，并分别在一个图表上显示每个 CPU 核的活动。

# 进一步阅读

有关更多信息，请参考以下链接：

+   `QtCharts`概述可以在[`doc.qt.io/qt-5/qtcharts-index.html`](https://doc.qt.io/qt-5/qtcharts-index.html)找到

+   `psutil`库的更多文档可以在[`psutil.readthedocs.io/en/latest/`](https://psutil.readthedocs.io/en/latest/)找到

+   加州大学伯克利分校的这篇指南为不同类型的数据选择合适的图表提供了一些指导：[`guides.lib.berkeley.edu/data-visualization/type`](http://guides.lib.berkeley.edu/data-visualization/type)


# 第十五章：PyQt 树莓派

树莓派是过去十年中最成功和令人兴奋的计算机之一。这款由英国非营利组织于 2012 年推出的微型**高级 RISC 机器**（**ARM**）计算机，旨在教育孩子们计算机科学知识，已成为业余爱好者、改装者、开发人员和各类 IT 专业人士的普遍工具。由于 Python 和 PyQt 在其默认操作系统上得到了很好的支持，树莓派也是 PyQt 开发人员的绝佳工具。

在本章中，我们将在以下部分中查看在树莓派上使用 PyQt5 开发：

+   在树莓派上运行 PyQt5

+   使用 PyQt 控制**通用输入/输出**（**GPIO**）设备

+   使用 GPIO 设备控制 PyQt

# 技术要求

为了跟随本章的示例，您需要以下物品：

+   一台树莓派——最好是 3 型 B+或更新的型号

+   树莓派的电源供应、键盘、鼠标、显示器和网络连接

+   安装了 Raspbian 10 或更高版本的微型 SD 卡；您可以参考官方文档[`www.raspberrypi.org/documentation/installation/`](https://www.raspberrypi.org/documentation/installation/)上的说明来安装 Raspbian

在撰写本文时，Raspbian 10 尚未发布，尽管可以将 Raspbian 9 升级到测试版本。如果 Raspbian 10 不可用，您可以参考本书的附录 B，*将 Raspbian 9 升级到 Raspbian 10*，了解升级的说明。

为了编写基于 GPIO 的项目，您还需要一些电子元件来进行接口。这些零件通常可以在电子入门套件中找到，也可以从当地的电子供应商那里购买。

第一个项目将需要以下物品：

+   一个面包板

+   三个相同的电阻（阻值在 220 到 1000 欧姆之间）

+   一个三色 LED

+   四根母对公跳线

第二个项目将需要以下物品：

+   一个面包板

+   一个 DHT11 或 DHT22 温湿度传感器

+   一个按钮开关

+   一个电阻（值不重要）

+   三根母对公跳线

+   Adafruit DHT 传感器库，可使用以下命令从 PyPI 获取：

```py
$ sudo pip3 install Adafruit_DHT
```

您可以参考 GitHub 存储库[`github.com/adafruit/Adafruit_Python_DHT`](https://github.com/adafruit/Adafruit_Python_DHT)获取更多信息。

您可能还想从[`github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter15`](https://github.com/PacktPublishing/Mastering-GUI-Programming-with-Python/tree/master/Chapter15)下载示例代码。

查看以下视频以查看代码运行情况：[`bit.ly/2M5xDSx`](http://bit.ly/2M5xDSx)

# 在树莓派上运行 PyQt5

树莓派能够运行许多不同的操作系统，因此安装 Python 和 PyQt 完全取决于您选择的操作系统。在本书中，我们将专注于树莓派的官方（也是最常用的）操作系统**Raspbian**。

Raspbian 基于 Debian GNU/Linux 的稳定版本，目前是 Debian 9（Stretch）。不幸的是，本书中的代码所需的 Python 和 PyQt5 版本对于这个 Debian 版本来说太旧了。如果在阅读本书时，Raspbian 10 尚未发布，请参考附录 B，*将 Raspbian 9 升级到 Raspbian 10*，了解如何将 Raspbian 9 升级到 Raspbian 10 的说明。

Raspbian 10 预装了 Python 3.7，但我们需要自己安装 PyQt5。请注意，您不能使用`pip`在树莓派上安装 PyQt5，因为所需的 Qt 二进制文件在 PyPI 上不适用于 ARM 平台（树莓派所基于的平台）。但是，PyQt5 的一个版本可以从 Raspbian 软件存储库中获取。这将*不*是 PyQt5 的最新版本，而是在 Debian 开发过程中选择的最稳定和兼容发布的版本。对于 Debian/Raspbian 10，这个版本是 PyQt 5.11。

要安装它，首先确保您的设备连接到互联网。然后，打开命令行终端并输入以下命令：

```py
$ sudo apt install python3-pyqt5
```

**高级打包工具**（**APT**）实用程序将下载并安装 PyQt5 及所有必要的依赖项。请注意，此命令仅为 Python 3 安装 PyQt5 的主要模块。某些模块，如`QtSQL`、`QtMultimedia`、`QtChart`和`QtWebEngineWidgets`，是单独打包的，需要使用额外的命令进行安装：

```py
$ sudo apt install python3-pyqt5.qtsql python3-pyqt5.qtmultimedia python3-pyqt5.qtchart python3-pyqt5.qtwebengine
```

有许多为 PyQt5 打包的可选库。要获取完整列表，可以使用`apt search`命令，如下所示：

```py
$ apt search pyqt5
```

APT 是在 Raspbian、Debian 和许多其他 Linux 发行版上安装、删除和更新软件的主要方式。虽然类似于`pip`，APT 用于整个操作系统。

# 在树莓派上编辑 Python

尽管您可以在自己的计算机上编辑 Python 并将其复制到树莓派上执行，但您可能会发现直接在设备上编辑代码更加方便。如果您喜欢的代码编辑器或**集成开发环境**（**IDE**）在 Linux 或 ARM 上不可用，不要担心；Raspbian 提供了几种替代方案：

+   **Thonny** Python IDE 预装了默认的 Raspbian 镜像，并且非常适合本章的示例

+   **IDLE**，Python 的默认编程环境也是预装的

+   **Geany**，一个适用于许多语言的通用编程文本编辑器，也是预装的

+   传统的代码编辑器，如**Vim**和**Emacs**，以及 Python IDE，如**Spyder**、**Ninja IDE**和**Eric**，可以使用添加/删除软件工具（在程序菜单的首选项下找到）或使用`apt`命令从软件包存储库安装

无论您选择哪种应用程序或方法，请确保将文件备份到另一台设备，因为树莓派的 SD 卡存储并不是最稳健的。

# 在树莓派上运行 PyQt5 应用程序

一旦 Python 和 PyQt5 安装在您的树莓派上，您应该能够运行本书中到目前为止我们编写的任何应用程序。基本上，树莓派是一台运行 GNU/Linux 的计算机，本书中的所有代码都与之兼容。考虑到这一点，您*可以*简单地将其用作运行 PyQt 应用程序的小型、节能计算机。

然而，树莓派有一些独特的特性，最显著的是其 GPIO 引脚。这些引脚使树莓派能够以一种非常简单和易于访问的方式与外部数字电路进行通信。Raspbian 预装了软件库，允许我们使用 Python 控制这些引脚。

为了充分利用这一特性提供给我们的独特平台，我们将在本章的其余部分中专注于使用 PyQt5 与树莓派的 GPIO 功能结合，创建 GUI 应用程序，以与现实世界的电路进行交互，这只有像树莓派这样的设备才能做到。

# 使用 PyQt 控制 GPIO 设备

对于我们的第一个项目，我们将学习如何可以从 PyQt 应用程序控制外部电路。您将连接一个多色 LED，并使用`QColorDialog`来控制其颜色。收集第一个项目中列出的组件，并让我们开始吧。

# 连接 LED 电路

让我们通过在面包板上连接电路的组件来开始这个项目。关闭树莓派并断开电源，然后将其放在面包板附近。

在连接电路到 GPIO 引脚之前，关闭树莓派并断开电源总是一个好主意。这将减少在连接错误的情况下破坏树莓派的风险，或者如果您意外触摸到组件引脚。

这个电路中的主要组件是三色 LED。尽管它们略有不同，但这个元件的最常见引脚布局如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/1d1018be-3dc8-4a65-ad28-831c18015ade.png)

基本上，三色 LED 是将红色 LED、绿色 LED 和蓝色 LED 组合成一个包。它提供单独的输入引脚，以便分别向每种颜色发送电流，并提供一个共同的地引脚。通过向每个引脚输入不同的电压，我们可以混合红色、绿色和蓝色光，从而创建各种各样的颜色，就像我们在应用程序中混合这三种元素来创建 RGB 颜色一样。

将 LED 添加到面包板上，使得每个引脚都在面包板的不同行上。然后，连接其余的组件如下：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/37d2d5a0-2e88-4956-8fbb-04b724336b0b.png)

如前图所示，我们正在进行以下连接：

+   LED 上的地针直接连接到树莓派左侧第三个外部引脚。

+   LED 上的红色引脚连接到一个电阻，然后连接到右侧的下一个引脚（即引脚 8）

+   LED 上的绿色引脚连接到另一个电阻，然后连接到右侧的下一个空闲引脚（即引脚 10）

+   LED 上的蓝色引脚连接到最后一个电阻，然后连接到 Pi 上右侧的下一个空闲引脚（引脚 12）

重要的是要仔细检查您的电路，并确保您已将电线连接到树莓派上的正确引脚。树莓派上并非所有的 GPIO 引脚都相同；其中一些是可编程的，而其他一些具有硬编码目的。您可以通过在终端中运行`pinout`命令来查看 Pi 上的引脚列表；您应该看到以下输出：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/5f9f8eee-267d-4935-ab36-6c1c18bd542d.png)

前面的屏幕截图显示了引脚的布局，就好像您正面对着树莓派，USB 端口朝下。请注意，其中有几个引脚标有**GND**；这些始终是地引脚，因此您可以将电路的地连接到其中任何一个引脚。其他引脚标有**5V**或**3V3**；这些始终是 5 伏或 3.3 伏。其余带有 GPIO 标签的引脚是可编程引脚。您的电线应连接到引脚**8**（**GPIO14**）、**10**（**GPIO15**）和**12**（**GPIO18**）。

仔细检查您的电路连接，然后启动树莓派。是时候开始编码了！

# 编写驱动程序库

现在我们的电路已连接好，我们需要编写一些代码来控制它。为此，我们将在树莓派上使用`GPIO`库。从第四章中创建一个 PyQt 应用程序模板的副本，*使用 QMainWindow 构建应用程序*，并将其命名为`three_color_led_gui.py`。

我们将从导入`GPIO`库开始：

```py
from RPi import GPIO
```

我们首先要做的是创建一个 Python 类，作为我们电路的 API。我们将称之为`ThreeColorLed`，然后开始如下：

```py
class ThreeColorLed():
    """Represents a three color LED circuit"""

    def __init__(self, red, green, blue, pinmode=GPIO.BOARD, freq=50):
        GPIO.setmode(pinmode)
```

我们的`__init__()`方法接受五个参数：前三个参数是红色、绿色和蓝色 LED 连接的引脚号；第四个参数是用于解释引脚号的引脚模式；第五个参数是频率，我们稍后会讨论。首先，让我们谈谈引脚模式。

如果你查看`pinout`命令的输出，你会注意到在树莓派上用整数描述引脚有两种方法。第一种是根据板子上的位置，从 1 到 40。第二种是根据它的 GPIO 编号（即在引脚描述中跟在 GPIO 后面的数字）。`GPIO`库允许你使用任一种数字来指定引脚，但你必须通过向`GPIO.setmode()`函数传递两个常量中的一个来告诉它你要使用哪种方法。`GPIO.BOARD`指定你使用位置编号（如 1 到 40），而`GPIO.BCM`表示你要使用 GPIO 名称。正如你所看到的，我们默认在这里使用`BOARD`。

每当你编写一个以 GPIO 引脚号作为参数的类时，一定要允许用户指定引脚模式。这些数字本身没有引脚模式的上下文是没有意义的。

接下来，我们的`__init__()`方法需要设置输出引脚：

```py
        self.pins = {
            "red": red,
            "green": green,
            "blue": blue
            }
        for pin in self.pins.values():
            GPIO.setup(pin, GPIO.OUT)
```

GPIO 引脚可以设置为`IN`或`OUT`模式，取决于你是想从引脚状态读取还是向其写入。在这个项目中，我们将从软件发送信息到电路，所以我们需要将所有引脚设置为`OUT`模式。在将引脚号存储在`dict`对象中后，我们已经通过使用`GPIO.setup()`函数迭代它们并将它们设置为适当的模式。

设置好后，我们可以使用`GPIO.output()`函数告诉单个引脚是高电平还是低电平，如下所示：

```py
        # Turn all on and all off
        for pin in self.pins.values():
            GPIO.output(pin, GPIO.HIGH)
            GPIO.output(pin, GPIO.LOW)
```

这段代码简单地打开每个引脚，然后立即关闭（可能比你看到的更快）。我们可以使用这种方法来设置 LED 为几种简单的颜色；例如，我们可以通过将红色引脚设置为`HIGH`，其他引脚设置为`LOW`来使其变为红色，或者通过将蓝色和绿色引脚设置为`HIGH`，红色引脚设置为`LOW`来使其变为青色。当然，我们希望产生更多种颜色，但我们不能简单地通过完全打开或关闭引脚来做到这一点。我们需要一种方法来在每个引脚的电压之间平稳地变化，从最小值（0 伏）到最大值（5 伏）。

不幸的是，树莓派无法做到这一点。输出是数字的，而不是模拟的，因此它们只能完全开启或完全关闭。然而，我们可以通过使用一种称为**脉宽调制**（**PWM**）的技术来*模拟*变化的电压。

# PWM

在你家里找一个有相对灵敏灯泡的开关（LED 灯泡效果最好）。然后，尝试每秒钟打开和关闭一次。现在越来越快地按开关，直到房间里的灯几乎看起来是恒定的。你会注意到房间里的光似乎比你一直开着灯时要暗，即使灯泡只是完全开启或完全关闭。

PWM 的工作方式相同，只是在树莓派上，我们可以如此快速（当然是无声地）地打开和关闭电压，以至于在打开和关闭之间的切换看起来是无缝的。此外，通过在每个周期中调整引脚打开时间和关闭时间的比例，我们可以模拟在零电压和最大电压之间的变化电压。这个比例被称为**占空比**。

关于脉宽调制的概念和用法的更多信息可以在[`en.wikipedia.org/wiki/Pulse-width_modulation`](https://en.wikipedia.org/wiki/Pulse-width_modulation)找到。

要在我们的引脚上使用 PWM，我们首先要通过在每个引脚上创建一个`GPIO.PWM`对象来设置它们：

```py
        self.pwms = dict([
             (name, GPIO.PWM(pin, freq))
             for name, pin in self.pins.items()
            ])
```

在这种情况下，我们使用列表推导来生成另一个包含每个引脚名称和`PWM`对象的`dict`。通过传入引脚号和频率值来创建`PWM`对象。这个频率将是引脚切换开和关的速率。

一旦我们创建了我们的`PWM`对象，我们需要启动它们：

```py
        for pwm in self.pwms.values():
            pwm.start(0)
```

`PWM.start()`方法开始引脚的闪烁。传递给`start()`的参数表示占空比的百分比；这里，`0`表示引脚将在 0%的时间内打开（基本上是关闭）。值为 100 将使引脚始终完全打开，而介于两者之间的值表示引脚在每个周期内接收的打开时间的量。

# 设置颜色

现在我们的引脚已经配置为 PWM，我们需要创建一个方法，通过传入红色、绿色和蓝色值，使 LED 显示特定的颜色。大多数软件 RGB 颜色实现（包括`QColor`）将这些值指定为 8 位整数（0 到 255）。然而，我们的 PWM 值表示占空比，它表示为百分比（0 到 100）。

因此，由于我们需要多次将 0 到 255 范围内的数字转换为 0 到 100 范围内的数字，让我们从一个静态方法开始，该方法将执行这样的转换：

```py
    @staticmethod
    def convert(val):
        val = abs(val)
        val = val//2.55
        val %= 101
        return val
```

该方法确保我们将获得有效的占空比，而不管输入如何，都使用简单的算术运算：

+   首先，我们使用数字的绝对值来防止传递任何负值。

+   其次，我们将值除以 2.55，以找到它代表的 255 的百分比。

+   最后，我们对数字取 101 的模，这样百分比高于 100 的数字将循环并保持在范围内。

现在，让我们编写我们的`set_color()`方法，如下所示：

```py
    def set_color(self, red, green, blue):
        """Set color using RGB color values of 0-255"""
        self.pwms['red'].ChangeDutyCycle(self.convert(red))
        self.pwms['green'].ChangeDutyCycle(self.convert(green))
        self.pwms['blue'].ChangeDutyCycle(self.convert(blue))
```

`PWM.ChangeDutyCycle()`方法接受 0 到 100 的值，并相应地调整引脚的占空比。在这个方法中，我们只是将我们的输入 RGB 值转换为适当的比例，并将它们传递给相应的 PWM 对象。

# 清理

我们需要添加到我们的类中的最后一个方法是清理方法。树莓派上的 GPIO 引脚可以被视为一个状态机，其中每个引脚都有高状态或低状态（即打开或关闭）。当我们在程序中设置这些引脚时，这些引脚的状态将在程序退出后保持设置。

请注意，如果我们连接了不同的电路到我们的 Pi，这可能会导致问题；在连接电路时，如果在错误的时刻将引脚设置为`HIGH`，可能会烧坏一些组件。因此，我们希望在退出程序时将所有东西关闭。

这可以使用`GPIO.cleanup()`函数完成：

```py
    def cleanup(self):
        GPIO.cleanup()
```

通过将这个方法添加到我们的 LED 驱动程序类中，我们可以在每次使用后轻松清理 Pi 的状态。

# 创建 PyQt GUI

现在我们已经处理了 GPIO 方面，让我们创建我们的 PyQt GUI。在`MainWindow.__init__()`中，添加以下代码：

```py
        self.tcl = ThreeColorLed(8, 10, 12)
```

在这里，我们使用连接到面包板的引脚号创建了一个`ThreeColorLed`实例。请记住，默认情况下，该类使用`BOARD`号码，因此这里的正确值是`8`、`10`和`12`。如果要使用`BCM`号码，请确保在构造函数参数中指定这一点。

现在让我们添加一个颜色选择对话框：

```py
        ccd = qtw.QColorDialog()
        ccd.setOptions(
            qtw.QColorDialog.NoButtons
            | qtw.QColorDialog.DontUseNativeDialog)
        ccd.currentColorChanged.connect(self.set_color)
        self.setCentralWidget(ccd)
```

通常，我们通过调用`QColorDialog.getColor()`来调用颜色对话框，但在这种情况下，我们希望将对话框用作小部件。因此，我们直接实例化一个对话框，并设置`NoButtons`和`DontUseNativeDialog`选项。通过去掉按钮并使用对话框的 Qt 版本，我们可以防止用户取消或提交对话框。这允许我们将其视为常规小部件并将其分配为主窗口的中央小部件。

我们已经将`currentColorChanged`信号（每当用户选择颜色时发出）连接到一个名为`set_color()`的`MainWindow`方法。我们将在接下来添加这个方法，如下所示：

```py
    def set_color(self, color):
        self.tcl.set_color(color.red(), color.green(), color.blue())
```

`currentColorChanged`信号包括表示所选颜色的`QColor`对象，因此我们可以简单地使用`QColor`属性访问器将其分解为红色、绿色和蓝色值，然后将该信息传递给我们的`ThreeColorLed`对象的`set_color()`方法。

现在脚本已经完成。您应该能够运行它并点亮 LED-试试看！

请注意，您选择的颜色可能不会完全匹配 LED 的颜色输出，因为不同颜色 LED 的相对亮度不同。但它们应该是相当接近的。

# 使用 GPIO 设备控制 PyQt

使用 GPIO 引脚从 Python 控制电路非常简单。只需调用`GPIO.output()`函数，并使用适当的引脚编号和高或低值。然而，现在我们要看相反的情况，即从 GPIO 输入控制或更新 PyQt GUI。

为了演示这一点，我们将构建一个温度和湿度读数。就像以前一样，我们将从连接电路开始。

# 连接传感器电路

DHT 11 和 DHT 22 传感器都是温度和湿度传感器，可以很容易地与树莓派一起使用。两者都打包为四针元件，但实际上只使用了三根引脚。一些元件套件甚至将 DHT 11/22 安装在一个小 PCB 上，只有三根活动引脚用于输出。

无论哪种情况，如果您正在查看 DHT 的正面（即，格栅一侧），则从左到右的引脚如下：

+   输入电压——5 或 3 伏特

+   传感器输出

+   死引脚（在 4 针配置中）

+   地线

DHT 11 或 DHT 22 对于这个项目都同样适用。11 更小更便宜，但比 22 慢且不太准确。否则，它们在功能上是一样的。

将传感器插入面包板中，使每个引脚都在自己的行中。然后，使用跳线线将其连接到树莓派，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/a29672ae-3bab-464d-891e-54cde52127fe.png)

传感器的电压输入引脚可以连接到任何一个 5V 引脚，地线可以连接到任何一个 GND 引脚。此外，数据引脚可以连接到树莓派上的任何 GPIO 引脚，但在这种情况下，我们将使用引脚 7（再次，按照`BOARD`编号）。

仔细检查您的连接，确保一切正确，然后打开树莓派的电源，我们将开始编码。

# 创建传感器接口

要开始我们的传感器接口软件，首先创建另一个 Qt 应用程序模板的副本，并将其命名为`temp_humid_display.py`。

我们将首先导入必要的库，如下所示：

```py
import Adafruit_DHT
from RPi import GPIO
```

`Adafruit_DHT`将封装与 DHT 单元通信所需的所有复杂部分，因此我们只需要使用高级功能来控制和读取设备的数据。

在导入下面，让我们设置一个全局常量：

```py
SENSOR_MODEL = 11
GPIO.setmode(GPIO.BCM)
```

我们正在设置一个全局常量，指示我们正在使用哪个型号的 DHT；如果您有 DHT 22，则将此值设置为 22。我们还设置了树莓派的引脚模式。但这次，我们将使用`BCM`模式来指定我们的引脚编号。Adafruit 库只接受`BCM`编号，因此在我们所有的类中保持一致是有意义的。

现在，让我们开始为 DHT 创建传感器接口类：

```py
class SensorInterface(qtc.QObject):

    temperature = qtc.pyqtSignal(float)
    humidity = qtc.pyqtSignal(float)
    read_time = qtc.pyqtSignal(qtc.QTime)
```

这一次，我们将基于`QObject`类来创建我们的类，以便在从传感器读取值时发出信号，并在其自己的线程中运行对象。DHT 单元有点慢，当我们请求读数时可能需要一秒或更长时间来响应。因此，我们希望在单独的执行线程中运行其接口。正如您可能记得的来自第十章 *使用 QTimer 和 QThread 进行多线程处理*，当我们可以使用信号和插槽与对象交互时，这很容易实现。

现在，让我们添加`__init__()`方法，如下所示：

```py
    def __init__(self, pin, sensor_model, fahrenheit=False):
        super().__init__()
        self.pin = pin
        self.model = sensor_model
        self.fahrenheit = fahrenheit
```

构造函数将接受三个参数：连接到数据线的引脚，型号（11 或 22），以及一个布尔值，指示我们是否要使用华氏或摄氏温标。我们暂时将所有这些参数保存到实例变量中。

现在我们想要创建一个方法来告诉传感器进行读数：

```py
    @qtc.pyqtSlot()
    def take_reading(self):
        h, t = Adafruit_DHT.read_retry(self.model, self.pin)
        if self.fahrenheit:
            t = ((9/5) * t) + 32
        self.temperature.emit(t)
        self.humidity.emit(h)
        self.read_time.emit(qtc.QTime.currentTime())
```

正如您所看到的，`Adafruit_DHT`库消除了读取传感器的所有复杂性。我们只需使用传感器的型号和引脚号调用`read_entry()`，它就会返回一个包含湿度和温度值的元组。温度以摄氏度返回，因此对于美国用户，如果对象配置为这样做，我们将进行计算将其转换为华氏度。然后，我们发出三个信号——分别是温度、湿度和当前时间。

请注意，我们使用`pyqtSlot`装饰器包装了这个函数。再次回想一下第十章中的内容，*使用 QTimer 和 QThread 进行多线程处理*，这将消除将这个类移动到自己的线程中的一些复杂性。

这解决了我们的传感器驱动程序类，现在让我们构建 GUI。

# 显示读数

在本书的这一部分，创建一个 PyQt GUI 来显示一些数字应该是轻而易举的。为了增加趣味性并创建时尚的外观，我们将使用一个我们还没有讨论过的小部件——`QLCDNumber`。

首先，在`MainWindow.__init__()`中创建一个基本小部件，如下所示：

```py
        widget = qtw.QWidget()
        widget.setLayout(qtw.QFormLayout())
        self.setCentralWidget(widget)
```

现在，让我们应用一些我们在第六章中学到的样式技巧，*Qt 应用程序样式*：

```py
        p = widget.palette()
        p.setColor(qtg.QPalette.WindowText, qtg.QColor('cyan'))
        p.setColor(qtg.QPalette.Window, qtg.QColor('navy'))
        p.setColor(qtg.QPalette.Button, qtg.QColor('#335'))
        p.setColor(qtg.QPalette.ButtonText, qtg.QColor('cyan'))
        self.setPalette(p)
```

在这里，我们为这个小部件及其子级创建了一个自定义的`QPalette`对象，给它一个类似于蓝色背光 LCD 屏幕的颜色方案。

接下来，让我们创建用于显示我们的读数的小部件：

```py
        tempview = qtw.QLCDNumber()
        humview = qtw.QLCDNumber()
        tempview.setSegmentStyle(qtw.QLCDNumber.Flat)
        humview.setSegmentStyle(qtw.QLCDNumber.Flat)
        widget.layout().addRow('Temperature', tempview)
        widget.layout().addRow('Humidity', humview)
```

`QLCDNumber`小部件是用于显示数字的小部件。它类似于一个八段数码管显示，例如您可能在仪表板或数字时钟上找到的。它的`segmentStyle`属性在几种不同的视觉样式之间切换；在这种情况下，我们使用`Flat`，它用前景颜色填充了段。

现在布局已经配置好了，让我们创建一个传感器对象：

```py
        self.sensor = SensorInterface(4, SENSOR_MODEL, True)
        self.sensor_thread = qtc.QThread()
        self.sensor.moveToThread(self.sensor_thread)
        self.sensor_thread.start()
```

在这里，我们创建了一个连接到 GPIO4 引脚（即 7 号引脚）的传感器，传入我们之前定义的`SENSOR_MODEL`常量，并将华氏度设置为`True`（如果您喜欢摄氏度，可以随时将其设置为`False`）。之后，我们创建了一个`QThread`对象，并将`SensorInterface`对象移动到其中。

接下来，让我们连接我们的信号和插槽，如下所示：

```py
        self.sensor.temperature.connect(tempview.display)
        self.sensor.humidity.connect(humview.display)
        self.sensor.read_time.connect(self.show_time)
```

`QLCDNumber.display()`插槽可以连接到发出数字的任何信号，因此我们直接连接我们的温度和湿度信号。然而，发送到`read_time`信号的`QTime`对象将需要一些解析，因此我们将其连接到一个名为`show_time()`的`MainWindow`方法。

该方法看起来像以下代码块：

```py
    def show_time(self, qtime):
        self.statusBar().showMessage(
            f'Read at {qtime.toString("HH:mm:ss")}')
```

这个方法将利用`MainWindow`对象方便的`statusBar()`方法，在状态区域显示最后一次温度读数的时间。

因此，这解决了我们的 GUI 输出显示；现在我们需要一种方法来触发传感器定期进行读数。我们可以采取的一种方法是创建一个定时器来定期执行它：

```py
        self.timer = qtc.QTimer(interval=(60000))
        self.timer.timeout.connect(self.sensor.take_reading)
        self.timer.start()
```

在这种情况下，这个定时器将每分钟调用`sensor.take_reading()`，确保我们的读数定期更新。

我们还可以在界面中添加`QPushButton`，以便用户可以随时获取新的读数：

```py
        readbutton = qtw.QPushButton('Read Now')
        widget.layout().addRow(readbutton)
        readbutton.clicked.connect(self.sensor.take_reading)
```

这相当简单，因为我们只需要将按钮的`clicked`信号连接到传感器的`take_reading`插槽。但是硬件控制呢？我们如何实现外部触发温度读数？我们将在下一节中探讨这个问题。

# 添加硬件按钮

从传感器读取值可能是有用的，但更有用的是能够响应电路中发生的事件并作出相应的行动。为了演示这个过程，我们将在电路中添加一个硬件按钮，并监视它的状态，以便我们可以在按下按钮时进行温度和湿度读数。

# 扩展电路

首先，关闭树莓派的电源，让我们向电路中添加一些组件，如下图所示：

![](https://github.com/OpenDocCN/freelearn-python-zh/raw/master/docs/ms-gui-prog-py/img/b493a2fa-96bd-4435-9ba8-d2ae3ee2fe9c.png)

在这里，我们基本上添加了一个按钮和一个电阻。按钮需要连接到树莓派上的引脚 8 的一侧，而电阻连接到地面的另一侧。为了保持布线整洁，我们还利用了面包板侧面的公共地和公共电压导轨，尽管这是可选的（如果您愿意，您可以直接将东西连接到树莓派上的适当 GND 和 5V 引脚）。

在入门套件中经常找到的按钮有四个连接器，每侧两个开关。确保您的连接在按钮被按下之前不连接。如果您发现即使没有按下按钮，它们也总是连接在一起，那么您可能需要将按钮在电路中旋转 90 度。

在这个电路中，按钮在被按下时将简单地将我们的 GPIO 引脚连接到地面，这将允许我们检测按钮按下。当我们编写软件时，我们将更详细地了解它是如何工作的。

# 实现按钮驱动程序

在脚本的顶部开始一个新的类，作为我们按钮的驱动程序：

```py
class HWButton(qtc.QObject):

    button_press = qtc.pyqtSignal()
```

再次，我们使用`QObject`，以便我们可以发出 Qt 信号，当我们检测到按钮被按下时，我们将这样做。

现在，让我们编写构造函数，如下所示：

```py
    def __init__(self, pin):
        super().__init__()
        self.pin = pin
        GPIO.setup(pin, GPIO.IN, pull_up_down=GPIO.PUD_UP)
```

在调用`super().__init__()`之后，我们的`__init__()`方法的第一件事是通过将`GPIO.IN`常量传递给`setup()`函数来将我们的按钮的 GPIO 引脚配置为输入引脚。

我们在这里传递的`pull_up_down`值非常重要。由于我们连接电路的方式，当按钮被按下时，引脚将连接到地面。但是当按钮没有被按下时会发生什么？嗯，在这种情况下，它处于**浮动**状态，其中输入将是不可预测的。为了在按钮没有被按下时保持引脚处于可预测的状态，`pull_up_down`参数将导致在没有其他连接时将其拉到`HIGH`或`LOW`。在我们的情况下，我们希望它被拉到`HIGH`，因为我们的按钮将把它拉到`LOW`；传递`GPIO.PUD_UP`常量将实现这一点。

这也可以以相反的方式工作；例如，我们可以将按钮的另一侧连接到 5V，然后在`setup()`函数中将`pull_up_down`设置为`GPIO.PUD_DOWN`。

现在，我们需要弄清楚如何检测按钮何时被按下，以便我们可以发出信号。

这项任务的一个简单方法是**轮询**。轮询简单地意味着我们将定期检查按钮，并在上次检查时发生变化时发出信号。

为此，我们首先需要创建一个实例变量来保存按钮的上一个已知状态：

```py
       self.pressed = GPIO.input(self.pin) == GPIO.LOW
```

我们可以通过调用`GPIO.input()`函数并传递引脚号来检查按钮的当前状态。此函数将返回`HIGH`或`LOW`，指示引脚是否为 5V 或地面。如果引脚为`LOW`，那么意味着按钮被按下。我们将将结果保存到`self.pressed`。

接下来，我们将编写一个方法来检查按钮状态的变化：

```py
    def check(self):
        pressed = GPIO.input(self.pin) == GPIO.LOW
        if pressed != self.pressed:
            if pressed:
                self.button_press.emit()
            self.pressed = pressed
```

这个检查方法将采取以下步骤：

1.  首先，它将比较`input()`的输出与`LOW`常量，以查看按钮是否被按下

1.  然后，我们比较按钮的当前状态与保存的状态，以查看按钮的状态是否发生了变化

1.  如果有，我们需要检查状态的变化是按下还是释放

1.  如果是按下（`pressed`为`True`），那么我们发出信号

1.  无论哪种情况，我们都会使用新状态更新`self.pressed`

现在，剩下的就是定期调用这个方法来轮询变化；在`__init__()`中，我们可以使用定时器来做到这一点，如下所示：

```py
        self.timer = qtc.QTimer(interval=50, timeout=self.check)
        self.timer.start()
```

在这里，我们创建了一个定时器，每 50 毫秒超时一次，当这样做时调用`self.check()`。这应该足够频繁，以至于可以捕捉到人类可以执行的最快的按钮按下。

轮询效果很好，但使用`GPIO`库的`add_event_detect()`函数有一种更干净的方法来做到这一点：

```py
        # Comment out timer code
        #self.timer = qtc.QTimer(interval=50, timeout=self.check)
        #self.timer.start()
        GPIO.add_event_detect(
            self.pin,
            GPIO.RISING,
            callback=self.on_event_detect)
```

`add_event_detect()`函数将在另一个线程中开始监视引脚，以侦听`RISING`事件或`FALLING`事件，并在检测到此类事件时调用配置的`callback`方法。

在这种情况下，我们只需调用以下实例方法：

```py
    def on_event_detect(self, *args):
        self.button_press.emit()
```

我们可以直接将我们的`emit()`方法作为回调传递，但是`add_event_detect()`将使用引脚号调用回调函数作为参数，而`emit()`将不接受。

使用`add_event_detect()`的缺点是它引入了另一个线程，使用 Python 的`threading`库，这可能会导致与 PyQt 事件循环的微妙问题。轮询是一个完全可行的替代方案，可以避免这种复杂性。

这两种方法都适用于我们的简单脚本，所以让我们回到`MainWindow.__init__()`来为我们的按钮添加支持：

```py
        self.hwbutton = HWButton(8)
        self.hwbutton.button_press.connect(self.sensor.take_reading)
```

我们所需要做的就是创建一个`HWButton`类的实例，使用正确的引脚号，并将其`button_press`信号连接到传感器的`take_reading()`插槽。

现在，如果您在树莓派上启动所有内容，当您按下按钮时，您应该能够看到更新。

# 总结

树莓派是一项令人兴奋的技术，不仅因为其小巧、低成本和低资源使用率，而且因为它使得将编程世界与真实电路的连接变得简单和易于访问，这是以前没有的。在本章中，您学会了如何配置树莓派来运行 PyQt 应用程序。您还学会了如何使用 PyQt 和 Python 控制电路，以及电路如何控制软件中的操作。

在下一章中，我们将使用`QtWebEngineWidgets`将全球网络引入我们的 PyQt 应用程序，这是一个完整的基于 Chromium 的浏览器，内置在 Qt Widget 中。我们将构建一个功能齐全的浏览器，并了解网络引擎库的各个方面。

# 问题

尝试回答以下问题，以测试您从本章中获得的知识：

1.  您刚刚购买了一个预装了 Raspbian 的树莓派来运行您的 PyQt5 应用程序。当您尝试运行您的应用程序时，您遇到了一个错误，试图导入`QtNetworkAuth`，这是您的应用程序所依赖的。问题可能是什么？

1.  您已经为传统扫描仪设备编写了一个 PyQt 前端。您的代码通过一个名为`scanutil.exe`的专有驱动程序实用程序与扫描仪通信。它目前正在运行在 Windows 10 PC 上，但您的雇主希望通过将其移动到树莓派来节省成本。这是一个好主意吗？

1.  您已经获得了一个新的传感器，并希望尝试将其与树莓派一起使用。它有三个连接，标有 Vcc、GND 和 Data。您将如何将其连接到树莓派？您还需要更多信息吗？

1.  您正在点亮连接到最左边的第四个 GPIO 引脚的 LED。这段代码有什么问题？

```py
   GPIO.setmode(GPIO.BCM)
   GPIO.setup(8, GPIO.OUT)
   GPIO.output(8, 1)
```

1.  您正在调暗连接到 GPIO 引脚 12 的 LED。以下代码有效吗？

```py
   GPIO.setmode(GPIO.BOARD)
   GPIO.setup(12, GPIO.OUT)
   GPIO.output(12, 0.5)
```

1.  您有一个运动传感器，当检测到运动时，数据引脚会变为`HIGH`。它连接到引脚`8`。以下是您的驱动代码：

```py
   class MotionSensor(qtc.QObject):

       detection = qtc.pyqtSignal()

       def __init__(self):
           super().__init__()
           GPIO.setmode(GPIO.BOARD)
           GPIO.setup(8, GPIO.IN)
           self.state = GPIO.input(8)

       def check(self):
           state = GPIO.input(8)
           if state and state != self.state:
               detection.emit()
           self.state = state
```

您的主窗口类创建了一个`MotionSensor`对象，并将其`detection`信号连接到回调方法。然而，没有检测到任何东西。缺少了什么？

1.  以创造性的方式将本章中的两个电路结合起来；例如，您可以创建一个根据湿度和温度变化颜色的灯。

# 进一步阅读

有关更多信息，请参阅以下内容：

+   有关树莓派的`GPIO`库的更多文档可以在[`sourceforge.net/p/raspberry-gpio-python/wiki/Home/`](https://sourceforge.net/p/raspberry-gpio-python/wiki/Home/)找到

+   Packt 提供了许多详细介绍树莓派的书籍；您可以在[`www.packtpub.com/books/content/raspberry-pi`](https://www.packtpub.com/books/content/raspberry-pi)找到更多信息。
