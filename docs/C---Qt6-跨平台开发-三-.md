# C++ Qt6 跨平台开发（三）

> 原文：[`zh.annas-archive.org/md5/E50463D8611423ACF3F047AAA5FD4529`](https://zh.annas-archive.org/md5/E50463D8611423ACF3F047AAA5FD4529)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第八章：图形和动画

在本章中，您将学习 Qt 图形框架的基础知识以及如何在屏幕上渲染图形。您将了解 Qt 中如何进行一般绘图。我们将从讨论使用**QPainter**进行 2D 图形开始。我们将探讨如何使用绘图工具绘制不同的形状。然后，您将了解**QGraphicsView**和**QGraphicsScene**使用的图形视图架构。之后，我们将讨论 Qt Quick 使用的**场景图**机制。在本章中，您还将学习如何通过添加动画和状态使用户界面更有趣。

在本章中，我们将讨论以下内容：

+   了解 Qt 的图形框架

+   `QPainter`和 2D 图形

+   图形视图框架

+   OpenGL 实现

+   Qt Quick 场景图

+   QML 中的动画

+   Qt 中的状态机

通过本章，您将了解 Qt 使用的图形框架。您将能够在屏幕上绘制并向 UI 元素添加动画。

# 技术要求

本章的技术要求包括 Qt 6.0.0 和 Qt Creator 4.14.0 的最低版本，安装在 Windows 10、Ubuntu 20.04 或 macOS 10.14 等最新版本的桌面平台上。

本章中使用的所有代码都可以从以下 GitHub 链接下载：[`github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter08`](https://github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter08)。

重要说明

本章中使用的屏幕截图来自 Windows 平台。您将在您的机器上基于底层平台看到类似的屏幕。

# 了解 Qt 的图形框架

Qt 是最受欢迎的 GUI 应用程序框架之一。开发人员可以使用 Qt 构建出色的跨平台 GUI 应用程序，而不必担心底层图形实现。Qt **渲染硬件接口**（**RHI**）将 Qt 应用程序的图形指令解释为目标平台上可用的图形 API。

RHI 是硬件加速图形 API 的抽象接口。`rhi`模块中最重要的类是`QRhi`。`QRhi`实例由特定图形 API 的后端支持。后端的选择在运行时确定，并由创建`QRhi`实例的应用程序或库决定。您可以通过将以下行添加到项目文件中来添加模块：

```cpp
QT += rhi
```

RHI 支持的不同类型的图形 API 如下：

+   **OpenGL**

+   **OpenGL ES**

+   **Vulkan**

+   **Direct3D**

+   **金属**

*图 8.1*显示了 Qt 图形框架中的主要图层：

![图 8.1 - Qt 6 图形堆栈的主要图层](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_8.1_B16231.jpg)

图 8.1 - Qt 6 图形堆栈的主要图层

让我们熟悉一下前面图中显示的图形 API。**OpenGL**是最受欢迎的图形 API，具有跨语言和跨平台应用程序支持。它用于与 GPU 交互，实现硬件加速渲染。**OpenGL ES**是 OpenGL API 的一种适用于嵌入式设备的变体。它允许在嵌入式和移动设备上渲染高级 2D 和 3D 图形。**iOS 设备上的 OpenGL ES**也称为**EAGL**。OpenGL ES 也可在 Web 平台上作为 WebGL 使用。OpenGL 和 OpenGL ES 由技术硬件和软件公司的联盟 Khronos Group 开发和维护。您可以在以下链接了解有关 OpenGL 的更多信息：

https://www.opengl.org/about/

**Vulkan**是一个新一代的图形 API，有助于为现代 GPU 创建跨平台和高性能的应用程序。它由 Khronos Group 创建。Vulkan 的显式 API 设计允许在各种桌面、嵌入式和移动平台上进行高效实现。Qt 6 提供了对 Vulkan API 的支持。要使用 Vulkan，Qt 应用程序需要 LunarG Vulkan SDK。在以下链接中探索更多关于 Vulkan 的信息：

https://www.lunarg.com/vulkan-sdk/

**Direct3D**是微软专有的图形 API，提供了利用底层 GPU 功能进行 2D 和 3D 图形渲染的函数。微软公司为 Windows 平台创建了它。它是一个低级 API，可用于使用渲染管线绘制基元或使用计算着色器执行并行操作。

Direct3D 暴露了 3D 图形硬件的高级图形能力，包括模板缓冲、W 缓冲、Z 缓冲、透视纹理映射、空间反锯齿、可编程 HLSL 着色器和特效。Direct3D 与其他 DirectX 技术的集成使其能够提供包括视频映射、硬件 2D 叠加平面中的 3D 渲染，甚至精灵，并允许在交互媒体中使用 2D 和 3D 图形的多个功能。Direct3D 旨在通常虚拟化 3D 硬件接口。相比之下，OpenGL 旨在成为可以在软件中模拟的 3D 硬件加速渲染系统。这两个 API 在设计上有根本的不同。以下链接提供了对 Direct3D 的进一步了解：

https://docs.microsoft.com/en-in/windows/win32/getting-started-with-direct3d

**Metal**是苹果的低级计算机图形 API，它提供了对**图形处理单元**（**GPU**）的几乎直接访问，使您能够优化 iOS、macOS 和 tvOS 应用程序的图形和计算能力。它还具有低开销的架构，包括预编译的 GPU 着色器、细粒度资源管理和多线程支持。在 Metal 宣布之前，苹果为 macOS 提供了 OpenGL，为 iOS 提供了 OpenGL ES，但由于高度抽象的硬件，存在性能问题。另一方面，Metal 由于其苹果特定的 API，比 OpenGL 具有更好的性能。Metal 通过支持多达 100 倍于 OpenGL 的绘制调用，实现了全新一代的专业图形输出。您可以在以下链接中了解更多关于 Metal 的信息：

https://developer.apple.com/documentation/metal

在本节中，我们熟悉了 Qt 的图形框架和 RHI。您现在对这个框架有了基本的了解。在下一节中，我们将进一步讨论使用 QPainter 进行 2D 图形。

# QPainter 和 2D 图形

Qt 具有先进的窗口、绘图和排版系统。Qt GUI 模块中最重要的类是`QWindow`和`QGuiApplication`。该模块包括用于 2D 图形、图像、字体和高级排版的类。此外，GUI 模块还包括用于集成窗口系统、OpenGL 集成、事件处理、2D 图形、基本图像、字体和文本的类。Qt 的用户界面技术在内部使用这些类，但也可以直接用于编写使用低级 OpenGL 图形 API 的应用程序。

根据平台，`QWindow`类支持使用 OpenGL 和 OpenGL ES 进行渲染。Qt 包括`QOpenGLPaintDevice`类，它允许使用 OpenGL 加速的`QPainter`渲染和几个便利类。这些便利类通过隐藏扩展处理的复杂性和 OpenGL ES 2.0 与桌面 OpenGL 之间的差异，简化了 OpenGL 中的编写代码。`QOpenGLFunctions`是一个便利类，它提供了跨平台访问桌面 OpenGL 上的 OpenGL ES 2.0 函数，而无需手动解析 OpenGL 函数指针。

要在基于 qmake 的应用程序中使用这些 API 和类，您必须在项目文件（.pro）中包含`gui`模块，如下所示：

```cpp
QT += gui 
```

如果您正在使用基于*Cmake*的构建系统，则将以下内容添加到`CMakeLists.txt`文件中：

```cpp
find_package(Qt6 COMPONENTS Gui REQUIRED)
target_link_libraries(mytarget PRIVATE Qt6::Gui)
```

`QPainter`类主要用于绘图操作，为绘制矢量图形、文本和图像到不同表面或`QPaintDevice`实例（包括`QImage`、`QOpenGLPaintDevice`、`QWidget`和`QPrinter`）提供 API。对于 Qt Widgets 用户界面，Qt 使用软件渲染器。

以下是 Qt GUI 的高级绘图 API：

+   绘制系统

+   坐标系统

+   绘制和填充

我们将在接下来的章节中探讨这些 API。

## 理解绘制系统

Qt 的绘制系统提供了几个方便的类来在屏幕上绘制。最重要的类是`QPainter`、`QPaintDevice`和`QPaintEngine`。您可以使用`QPainter`在小部件和其他绘图设备上绘制。这个类可以用来从简单的线条到复杂的形状（比如在`paintEvent()`函数内部或在`paintEvent()`调用的函数内部绘制`QPainter`）绘制东西。`QPaintDevice`是允许使用`QPainter`实例进行 2D 绘制的对象的基类。`QPaintEngine`提供了定义`QPainter`如何在指定平台上的指定设备上绘制的接口。`QPaintEngine`类是`QPainter`和`QPaintDevice`内部使用的抽象类。

让我们来看看与绘制相关的类的层次结构，以更好地了解在使用绘制系统时如何选择合适的类。

![图 8.2 – Qt 中绘制类的层次结构](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_8.2_B16231.jpg)

图 8.2 – Qt 中绘制类的层次结构

前面的层次结构方法说明了所有绘图方法都遵循相同的机制。因此，很容易为新功能添加规定，并为不受支持的功能提供默认实现。

让我们在下一节讨论坐标系统。

## 使用坐标系统

`QPainter`类控制坐标系统。它与`QPaintDevice`和`QPaintEngine`类一起构成了 Qt 的绘制系统的基础。绘图设备的默认坐标系统的原点在左上角。`QPainter`的主要功能是执行绘图操作。而`QPaintDevice`类是一个二维空间的抽象，可以使用`QPainter`进行绘制，`QPaintEngine`类提供了一个绘图器，用于在不同类型的设备上绘制。`QPaintDevice`类是可以进行绘制的对象的基类，它从`QWidget`、`QImage`、`QPixmap`、`QPicture`和`QOpenGLPaintDevice`类继承了其绘图能力。

您可以在以下文档中了解更多关于坐标系统的信息：

https://doc.qt.io/qt-6/coordsys.html

## 绘制和填充

`QPainter`提供了一个高度优化的绘图器，用于大多数 GUI 上的绘图需求。它可以绘制各种类型的形状，从简单的图形基元（如`QPoint`、`QLine`、`QRect`、`QRegion`和`QPolygon`类）到复杂的矢量路径。矢量路径由`QPainterPath`类表示。`QPainterPath`作为绘制操作的容器，允许构建和重复使用图形形状。它可用于填充、轮廓和裁剪。`QPainter`还可以绘制对齐的文本和像素图。要填充`QPainter`绘制的形状，可以使用`QBrush`类。它具有颜色、样式、纹理和渐变属性，并且通过颜色和样式进行定义。

在下一节中，我们将使用到目前为止讨论的 API 来使用`QPainter`进行绘制。

## 使用 QPainter 进行绘制

`QPainter`有几个便利函数来绘制大多数基本形状，例如`drawLine()`、`drawRect()`、`drawEllipse()`、`drawArc()`、`drawPie()`和`drawPolygon()`。您可以使用`fillRect()`函数填充形状。`QBrush`类描述了`QPainter`绘制的形状的填充图案。刷子可以用于定义样式、颜色、渐变和纹理。

让我们看一下下面的`paintEvent()`函数，我们在其中使用`QPainter`来绘制文本和不同的形状：

```cpp
void PaintWindow::paintEvent(QPaintEvent *event)
{
    QPainter painter;
    painter.begin(this);
    //draws a line
    painter.drawLine(QPoint(50, 50), QPoint(200, 50));
    //draws a text
    painter.drawText(QPoint(50, 100), "Text");
    //draws an ellipse
    painter.drawEllipse(QPoint(100,150),50,20);
    //draws an arc
    QRectF drawingRect(50, 200, 100, 50);
    int startAngle = 90 * 16;
    int spanAngle = 180 * 16;
    painter.drawArc(drawingRect, startAngle, spanAngle);
    //draws a pie
    QRectF drawingRectPie(150, 200, 100, 50);
    startAngle = 60 * 16;
    spanAngle = 70 * 16;
    painter.drawPie(drawingRectPie, startAngle, spanAngle);
    painter.end();
    QWidget::paintEvent(event);
}
```

在前面的示例中，我们创建了一个`QPainter`实例，并使用可用的默认绘图函数绘制了一条线、文本、椭圆、弧和扇形。当您将上述代码添加到自定义类中并运行项目时，您将看到以下输出：

![图 8.3 – 使用 QPainter 绘图示例的输出](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_8.3_B16231.jpg)

图 8.3 – 使用 QPainter 绘图示例的输出

Qt 提供了几个离屏绘图类，每个类都有其自己的优缺点。`QImage`、`QBitmap`、`QPixmap`和`QPicture`是涉及的类。在大多数情况下，您必须在`QImage`和`QPixmap`之间进行选择。

Qt 中的`QImage`类允许轻松读取、写入和操作图像。如果您正在处理资源、合并多个图像并进行一些绘图，则应使用`QImage`类：

```cpp
QImage image(128, 128, QImage::Format_ARGB32); 
QPainter painter(&image);
```

第一行创建了一个 128 像素正方形的图像，每个像素编码为 32 位整数 - 每个通道的不透明度、红色、绿色和蓝色各占 8 位。第二行创建了一个可以在`QImage`实例上绘制的`QPainter`实例。接下来，我们执行了您在上一节中看到的绘图，完成后，我们将图像写入 PNG 文件，代码如下：

```cpp
image.save("image.png"); 
```

`QImage`支持多种图像格式，包括 PNG 和 JPEG。`QImage`还有一个`load`方法，可以从文件或资源加载图像。

`QBitmap`类是一个单色离屏绘图设备，提供深度为 1 位的位图。`QPixmap`类提供了一个离屏绘图设备。`QPicture`类是一个序列化`QPainter`命令的绘图设备。

您还可以使用`QImageReader`和`QImageWriter`类来更精细地控制图像的加载和保存。要添加对 Qt 提供的图像格式之外的图像格式的支持，可以使用`QImageIOHandler`和`QImageIOPlugin`创建图像格式插件。`QPainterPath`类有助于绘制可以创建和重复使用的不同图形形状。以下代码片段演示了如何使用`QPainterPath`：

```cpp
void MyWidget:: paintEvent(QPaintEvent *event)
{
    QPainter painter(this);
    QPolygon polygon;
    polygon << QPoint(100, 185) << QPoint(175, 175)
            << QPoint(200, 110) << QPoint(225, 175)
            << QPoint(300, 185) << QPoint(250, 225)
            << QPoint(260, 290) << QPoint(200, 250)
            << QPoint(140, 290) << QPoint(150, 225)
            << QPoint(100, 185);
    QBrush brush;
    brush.setColor(Qt::yellow);
    brush.setStyle(Qt::SolidPattern);
    QPen pen(Qt::black, 3, Qt::DashDotDotLine, 
             Qt::RoundCap, Qt::RoundJoin);
    painter.setPen(pen);
    QPainterPath path;
    path.addPolygon(polygon);
    painter.drawPolygon(polygon);
    painter.fillPath(path, brush);
    QWidget:: paintEvent(event);
}
```

在上述代码中，我们创建了一个自定义绘制的多边形对象，并使用所需的绘图路径。

注意

请注意，在进行绘制操作时，请确保在绘制背景和绘制内容之间没有延迟。否则，如果延迟超过 16 毫秒，您将在屏幕上看到闪烁。您可以通过将背景渲染到一个像素图中，然后在该像素图上绘制内容来避免这种情况。最后，您可以将该像素图绘制到小部件上。这种方法称为**双缓冲**。

在本节中，我们不仅学习了如何在屏幕上绘制图像，还学习了如何在屏幕外绘制图像并将其保存为图像文件。在下一节中，我们将学习图形视图框架的基础知识。

# 引入图形视图框架

Graphics View 框架是一个强大的图形引擎，允许您可视化和与大量自定义的 2D 图形项进行交互。如果您是一名经验丰富的程序员，可以使用图形视图框架手动绘制 GUI 并进行完全手动动画化。为了一次绘制数百或数千个相对轻量级的自定义项，Qt 提供了一个独立的视图框架，即 Graphics View 框架。如果您正在从头开始创建自己的小部件集，或者需要一次在屏幕上显示大量项，每个项都有自己的位置和数据，您可以利用 Graphics View 框架。这对于处理和显示大量数据的应用程序尤为重要，例如地理信息系统或计算机辅助设计软件。

Graphics View 提供了一个表面，用于管理和与大量自定义创建的 2D 图形项进行交互，并提供用于可视化这些项的视图小部件，支持缩放和旋转。该框架包括一个事件传播架构，可以为场景的项提供交互功能。这些项响应键盘事件；鼠标按下、移动、释放和双击事件；以及跟踪鼠标移动。Graphics View 使用二进制空间分区（BSP）树来提供非常快速的项发现，使其能够实时可视化大型场景，即使有数百万个项也可以。

该框架遵循基于项的模型/视图编程方法。它包括三个组件，`QGraphicsScene`、`QGraphicsView`和`QGraphicsItem`。

`QGraphicsItem`公开了一个接口，您的子类可以重写该接口以管理鼠标和键盘事件、拖放、接口层次结构和碰撞检测。每个项都有自己的本地坐标系，并且助手函数允许您快速将项的坐标转换为场景的坐标。Graphics View 框架使用一个或多个`QGraphicsView`实例来显示`QGraphicsScene`类的内容。为了查看场景的不同部分，可以将多个视图附加到同一个场景，每个视图都有自己的平移和旋转。由于`QGraphicsView`小部件是一个滚动区域，因此可以将滚动条附加到视图，并允许用户在其中滚动。视图接收键盘和鼠标输入，为场景生成场景事件，并将这些场景事件分派给场景，然后将这些相同的事件分派给场景的项。以前，该框架被用于游戏开发。

重要提示

我们将跳过关于框架用法和示例的细节，因为在 Qt Quick 2 出现后，它失去了流行度。Qt Quick 2 配备了场景图形 API，提供了以前由 Graphics View 框架提供的大部分功能。如果您仍然想了解更多关于 Graphics View 框架的信息，可以阅读以下文档：

https://doc.qt.io/qt-6/graphicsview.html

在本节中，我们讨论了 Qt 的 Graphics View 框架。在下一节中，我们将学习关于 Qt 与 OpenGL 集成。

# 了解 Qt OpenGL 模块

Qt Quick 和 Qt Widgets 是 Qt 中用户界面（UI）开发的两种主要方法。它们存在以支持各种类型的 UI，并构建在分别针对每种 UI 进行了优化的独立图形引擎上。在 Qt 中，可以将 OpenGL 图形 API 代码与这两种 UI 类型结合使用。当应用程序包含自己的 OpenGL 依赖代码或与第三方基于 OpenGL 的渲染器集成时，这将非常有用。OpenGL/OpenGL ES XML API 注册表用于生成 OpenGL 头文件。

Qt OpenGL 模块旨在与需要 OpenGL 访问的应用程序一起使用。Qt OpenGL 模块中的便利类帮助开发人员更轻松、更快地构建应用程序。这个模块负责与 Qt 5 应用程序和 Qt GUI 保持兼容。`QOpenGLWidget`是一个可以将 OpenGL 场景添加到使用`QWidget`的 UI 中的部件。

随着 Qt RHI 作为 Qt 的渲染基础的引入，在 Qt 6 中，大多数以`QOpenGL`表示的类已经移动到了 Qt OpenGL 模块中。这些类仍然可用，并且对仅依赖于 OpenGL 的应用程序提供完全支持。它们不再被认为是必不可少的，因为 Qt 已经扩展到支持其他图形 API，如 Direct3D、Metal 和 Vulkan。

现有的应用程序代码大部分仍将继续工作，但现在应该在项目文件中包含 Qt OpenGL，并且如果以前是通过 Qt GUI 间接包含的话，也应该包含头文件。

Qt 6 不再直接使用兼容 OpenGL 的 GLSL 源代码片段。着色器现在以 Vulkan 风格的 GLSL 编写，反射并转换为其他着色语言，并打包成可序列化的`QShader`对象，供`QRhi`消费。

Qt 6 中的着色器准备流水线如下：

![图 8.4 - 在 Qt 博客中描述的着色器准备流水线的插图](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_8.4_B16231.jpg)

图 8.4 - 在 Qt 博客中描述的着色器准备流水线的插图

在 Qt 6.1 中，Qt 数据可视化仅支持 OpenGL RHI 后端。它需要将环境变量`QSG_RHI_BACKEND`设置为`opengl`。您可以在系统级别进行设置，或者在`main()`中定义如下：

```cpp
qputenv("QSG_RHI_BACKEND","opengl");
```

让我们在下一节讨论框架如何与 Qt Widgets 一起使用。

## Qt OpenGL 和 Qt Widgets

Qt Widgets 通常由高度优化和准确的软件光栅化器进行渲染，最终的内容通过适合应用程序运行平台的方法显示在屏幕上。然而，Qt Widgets 和 OpenGL 可以结合使用。`QOpenGLWidget`类是这样做的主要入口点。这个类可以用于为部件树的特定部分启用 OpenGL 渲染，并且 Qt OpenGL 模块的类可以用于帮助处理任何应用程序端的 OpenGL 代码。

重要说明

基于`QWindow`或`QWidget`的 OpenGL 实现的应用程序，没有其他选择，只能在运行时直接调用 OpenGL API。对于 Qt Quick 和 Qt Quick 3D 应用程序，Qt 6 除了 OpenGL 外，还引入了对 Direct3D 11、Vulkan 和 Metal 的支持。在 Windows 上，默认选择仍然是 Direct3D，因此通过支持除 OpenGL 以外的图形 API，简化了 ANGLE 的移除。

在本节中，我们学习了如何使用 Qt 的 OpenGL 模块。让我们继续下一节，详细讨论 Qt Quick 中的图形。

# Qt Quick 中的图形

Qt Quick 旨在利用硬件加速渲染。它将默认构建在最适合目标平台的低级图形 API 上。例如，在 Windows 上，它将默认使用 Direct3D，而在 macOS 上，它将默认使用 Metal。对于渲染，Qt Quick 应用程序使用场景图。场景图渲染器可以进行更有效的图形调用，从而提高性能。场景图具有可访问的 API，允许您创建复杂但快速的图形。Qt Quick 2D 渲染器也可以用于渲染 Qt Quick。这个光栅绘图引擎允许 Qt Quick 应用程序在不支持 OpenGL 的平台上进行渲染。

Qt 默认情况下使用目标平台上最合适的图形 API。但是，可以配置 Qt 的渲染路径以使用特定的 API。在许多情况下，选择特定的 API 可以提高性能，并允许开发人员在支持特定图形 API 的平台上部署。要更改`QQuickWindow`中的渲染路径，可以使用`QRhi`接口。

在接下来的几节中，我们将看一些功能，这些功能将进一步增强您在 Qt Quick 中与图形相关的技能。让我们从讨论如何在 Qt Quick 中使用 OpenGL 开始。

## Qt OpenGL 和 Qt Quick

在支持 OpenGL 的平台上，可以手动选择它作为活动的图形 API。为了在使用 Qt Quick 时使用这个功能，应用程序应该手动将渲染后端设置为 OpenGL，同时调整项目文件并包含头文件。

在 Qt 6 中，没有直接使用 Qt Quick 进行 OpenGL 渲染的方法。基于 QRhi 的 Qt Quick 场景图的渲染路径现在是新的默认值。除了默认值之外，配置使用哪个 QRhi 后端以及因此使用哪个图形 API 的方法与 Qt 5.15 基本保持不变。Qt 6 中的一个关键区别是改进的 API 命名。现在，可以通过调用`QQuickWindow::setGraphicsApi()`函数来设置 RHI 后端，而在早期，这是通过调用`QQuickWindow::setSceneGraphBackend()`函数来实现的。

您可以在以下文章中了解更多关于这些变化的信息：

https://www.qt.io/blog/graphics-in-qt-6.0-qrhi-qt-quick-qt-quick-3d

## 使用 QPainter 自定义 Qt Quick 项

您还可以在 Qt Quick 应用程序中使用`QPainter`。这可以通过对`QQuickPaintedItem`进行子类化来实现。借助这个子类，您可以使用`QPainter`实例来渲染内容。为了渲染其内容，`QQuickPaintedItem`子类使用间接的 2D 表面，可以使用软件光栅化或使用**OpenGL 帧缓冲对象**（**FBO**）。渲染是一个两步操作。在绘制之前，绘制表面被光栅化。然而，使用场景图进行绘制比这种光栅化方法要快得多。

让我们探索 Qt Quick 使用的场景图机制。

# 了解 Qt Quick 场景图

Qt Quick 2 使用专用的场景图，使用图形 API 进行遍历和渲染，包括 OpenGL、OpenGL ES、Metal、Vulkan 或 Direct 3D。使用场景图进行图形渲染而不是传统的命令式绘图系统（`QPainter`等），允许在渲染开始之前保留场景，并且在整个原语集合渲染之前就已知。这允许各种优化，包括批处理渲染以减少状态更改和丢弃被遮挡的原语。

假设一个 GUI 包括一个包含 10 个元素的列表，每个元素都有不同的背景颜色、文本和图标。这将给我们 30 个绘制调用和相同数量的状态更改，使用传统的绘图技术。相反，场景图重新组织原语以便绘制，这样一个调用就可以绘制所有的背景、图标和文本，将绘制调用的总数减少到三个。这种批处理和状态更改的减少可以显著提高一些硬件的性能。

场景图与 Qt Quick 2 密不可分，不能独立使用。`QQuickWindow`类管理和渲染场景图，自定义`Item`类型可以通过调用`QQuickItem::updatePaintNode()`将它们的图形原语添加到场景图中。

场景图以图形方式表示一个`Item`场景，并且是一个自包含的结构，具有足够的信息来渲染所有的项。一旦配置，它可以在项的状态不管如何被操作和渲染。在一些平台上，场景图甚至在单独的渲染线程上进行渲染，而 GUI 线程则准备下一帧的状态。

在接下来的部分中，我们将深入探讨场景图结构，然后学习渲染机制。此外，在使用 Qt Quick 3D 时，我们将混合使用场景图和本机图形 API。

## Qt Quick 场景图结构

场景图由各种预定义的节点类型组成，每种类型都有特定的用途。尽管我们称之为场景图，但节点树是更精确的定义。树是从 QML 场景中的`QQuickItem`类型构建的，然后场景由渲染器在内部处理，绘制场景。节点本身没有活动的绘制代码。

尽管节点树大多是由现有的 Qt Quick QML 类型在内部构建的，用户可以添加包括代表 3D 模型的完整子树在内的自己的内容。

+   节点

+   材料

`QSGGeometryNode`对用户来说是最重要的节点。它通过指定几何图形和材料来创建定制的图形。`QSGGeometry`类描述了图形原语的形状或网格，并用于定义几何图形。它可以定义一切，无论是线条、矩形、多边形、一组不连续的矩形，还是复杂的 3D 网格。材料定义了特定形状的像素如何填充。一个节点可以有多个子节点。几何节点按照子节点顺序进行渲染，父节点可以在其子节点后面找到。

材料描述了`QSGGeometryNode`中几何图形的内部是如何填充的。它封装了用于图形管线的顶点和片段阶段的图形着色器，并提供了很大的灵活性，即使大多数 Qt Quick 项目只使用非常基本的材料，如纯色和纹理填充。

场景图 API 是低级的，优先考虑性能而不是便利性。从头开始创建最基本的自定义几何图形和材料需要大量的代码输入。因此，API 包括一些方便的类，使最常用的自定义节点易于访问。

在接下来的部分中，我们将讨论场景图中的渲染是如何进行的。

## 使用场景图进行渲染

场景图在`QQuickWindow`类中进行内部渲染，没有公共 API 可以访问它。但是，在渲染管道中有一些点，用户可以插入应用程序代码。这些点可以用于添加自定义场景图内容，或者通过直接调用场景图的图形 API（OpenGL、Vulkan、Metal 等）来插入任意的渲染命令。渲染循环确定了集成点。

场景图中有两种类型的渲染循环：

+   `basic`是单线程渲染器。

+   `threaded`是一个多线程渲染器，它在不同的线程上进行渲染。

Qt 尝试根据平台和底层图形能力选择适当的渲染循环。当这不够用时，或者在测试期间，可以使用环境变量`QSG_RENDER_LOOP`来强制使用特定类型的渲染器循环。您可以通过启用`qt.scenegraph.general`日志类别来查找正在使用的渲染循环类型。

在大多数使用场景图的应用程序中，渲染是在单独的渲染线程上进行的。这是为了提高多核处理器的并行性，并更好地利用等待阻塞交换缓冲调用等停顿时间。这提供了显著的性能改进，但它限制了与场景图的交互发生的位置和时间。

以下图表描述了如何使用线程化渲染循环和 OpenGL 渲染帧。除了 OpenGL 上下文的特定之外，其他图形 API 的步骤也是相同的：

![图 8.5 - 在线程化渲染循环中遵循的渲染顺序](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_8.5_B16231.jpg)

图 8.5 - 在线程化渲染循环中遵循的渲染顺序

目前，在 Windows 上默认使用 Direct3D 11 或更高版本的线程化渲染器。您可以通过将环境中的`QSG_RENDER_LOOP`设置为`threaded`来强制使用线程化渲染器。但是，线程化渲染循环取决于图形 API 实现的节流。在 macOS 上使用 Xcode 10 或更高版本和 OpenGL 构建时，不支持线程化渲染循环。对于 Metal，没有这样的限制。

如果您的系统无法提供基于 Vsync 的节流功能，则通过将环境变量`QSG_RENDER_LOOP`设置为`basic`来使用基本渲染循环。以下步骤描述了在基本或非线程化渲染循环中如何渲染帧：

![图 8.6 - 非线程化渲染循环中的渲染顺序](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_8.6_B16231.jpg)

图 8.6 - 非线程化渲染循环中的渲染顺序

当平台的标准 OpenGL 库未被使用时，默认情况下在启用 OpenGL 的平台上使用非线程化渲染循环。这主要是为后者制定的预防策略，因为并未验证所有 OpenGL 驱动程序和窗口系统的组合。即使使用非线程化渲染循环，您可能需要将代码编写为使用线程化渲染器，否则您的代码将无法移植。

要了解更多有关场景图渲染器工作原理的信息，请访问以下链接：

https://doc-snapshots.qt.io/qt6-dev/qtquick-visualcanvas-scenegraph.html

在本节中，您了解了场景图背后的渲染机制。在下一节中，我们将讨论如何将场景图与原生图形 API 混合使用。

## 使用原生图形的场景图

场景图提供了两种方法来将场景图与原生图形 API 混合。第一种方法是直接向底层图形引擎发出命令，第二种方法是在场景图中生成纹理节点。应用程序可以通过连接到`QQuickWindow::beforeRendering()`和`QQuickWindow::afterRendering()`信号来直接在与场景图相同的上下文中进行 OpenGL 调用。使用 Metal 或 Vulkan 等 API 的应用程序可以通过`QSGRendererInterface`请求原生对象，例如场景图的命令缓冲区。然后用户可以在 Qt Quick 场景内部或外部渲染内容。混合两者的优势是执行渲染不需要额外的帧缓冲区或内存，并且可以避免潜在的昂贵的纹理步骤。缺点是 Qt Quick 选择何时调用信号。OpenGL 引擎只允许在那个时间绘制。

从 Qt 6.0 开始，在调用`QQuickWindow::beginExternalCommands()`和`QQuickWindow::endExternalCommands()`函数之前必须调用原生图形 API 的直接使用。这种方法与`QPainter::beginNativePainting()`相同，目的也相同。它允许场景图识别当前记录的渲染通道内的任何缓存状态或对状态的假设。如果存在任何内容，则会因为代码可能直接与原生图形 API 交互而使其无效。

重要提示

在将 OpenGL 内容与场景图渲染相结合时，应用程序不能使 OpenGL 上下文保持绑定缓冲区、启用属性或模板缓冲区中的特定值等。如果忘记了这一点，就会看到意外的行为。自定义渲染代码必须具有线程意识。

场景图还提供了几个日志类别的支持。这些对于查找性能问题和错误的根本原因非常有用。场景图除了公共 API 外还具有适配层。该层允许您实现某些特定于硬件的适配。它具有内部和专有的插件 API，允许硬件适配团队充分利用其硬件。

重要提示

如果您观察到与图形相关的问题，或者想要找出当前使用的渲染循环或图形 API 的类型，请通过将环境变量`QSG_INFO`设置为`1`或至少启用`qt.scenegraph.general`和`qt.rhi.*`来启动应用程序。在初始化期间，这将打印一些关键信息，以便调试图形问题。

## 使用 Qt Quick 3D 进行 3D 图形

**Qt Quick 3D** 是 Qt Quick 的附加组件，提供了用于创建 3D 内容和 3D 用户界面的高级 API。它扩展了 Qt Quick 场景图，允许您将 3D 内容集成到 2D Qt Quick 应用程序中。Qt Quick 3D 是用于在 Qt Quick 平台上创建 3D 内容和 3D 用户界面的高级 API。我们提供了空间内容扩展到现有的 Qt Quick 场景图，以及该扩展场景图的渲染器，而不是依赖外部引擎，这会引入同步问题和额外的抽象层。在使用空间场景图时，也可以混合使用 Qt Quick 2D 和 3D 内容。

在您的`.qml`文件中的以下`import`语句可用于将 QML 类型导入您的应用程序：

```cpp
import QtQuick3D 
```

除了基本的 Qt Quick 3D 模型外，以下模块导入还提供了其他功能：

```cpp
import QtQuick3D.Effects
import QtQuick3D.Helpers
```

Qt Quick 3D 可以在商业许可下购买。在构建源代码时，请确保首先构建`qtdeclarative`和`qtshadertools`存储库中的模块和工具，因为没有它们，Qt Quick 3D 无法使用。

让我们在下一节讨论着色器工具和着色器效果。

# 着色器效果

对于将着色器导入到 3D 场景中，Qt Quick 3D 有自己的框架。**着色器效果**使得可以通过顶点和片段着色器直接利用图形处理单元的全部原始能力。使用过多的着色器效果可能会导致增加的功耗和有时的性能下降，但是当谨慎使用时，着色器可以允许将复杂和视觉上吸引人的效果应用于视觉对象。

这两个着色器都绑定到`vertexShader`和`fragmentShader`属性。每个着色器的代码都需要一个由 GPU 执行的`main(){...}`函数。以`qt_`为前缀的变量由 Qt 提供。要了解着色器代码中的变量，请查看 OpenGL API 参考文档。

在使用 Qt Quick 的 QML 应用程序中使用`ShaderEffect`或对`QSGMaterialShader`进行子类化时，应用程序必须提供一个`.qsb`文件形式的烘焙着色器包。Qt Shader Tools 模块包括一个名为`.qsb`文件的命令行工具。特别是`ShaderEffect` QML 类型和`QSGMaterial`子类可以使用 qsb 输出。它还可以用于检查`.qsb`包的内容。输入文件扩展名用于确定着色器的类型。因此，扩展名必须是以下之一：

+   `.vert` – 顶点着色器

+   `.frag` – 片段着色器

+   `.comp` – 计算着色器

该示例假定`myeffect.vert`和`myeffect.frag`包含 Vulkan 风格的 GLSL 代码，通过`qsb`工具处理以生成`.qsb`文件。现在，通过以下命令将该 Vulkan 风格着色器用`qsb`进行转换： 

```cpp
>qsb --glsl 100es,120,150 --hlsl 50 --msl 12 -o <Output_File.qsb> <Input_File.frag>
```

您可以在以下命令中看到使用上述语法的示例：

```cpp
>C:\Qt\6.0.2\mingw81_64\bin>qsb --glsl 100es,120,150 --hlsl 50 --msl 12 -o myeffect.frag.qsb myeffect.frag
```

不需要同时指定`vertexShader`和`fragmentShader`。实际上，许多`ShaderEffect`实现只会提供片段着色器，而不是依赖内置的顶点着色器。

您可以在以下链接中了解有关着色器工具的更多信息：

https://doc.qt.io/qt-6/qtshadertools-qsb.html

让我们在一个示例中使用着色器效果：

```cpp
import QtQuick
import QtQuick.Window
Window {
    width: 512
    height: 512
    visible: true
    title: qsTr("Shader Effects Demo")
    Row {
        anchors.centerIn: parent
        width: 300
        spacing: 20
        Image {
            id: originalImage
            width: 128; height: 94
            source: "qrc:/logo.png"
        }
        ShaderEffect {
            width: 160; height: width
            property variant source: originalImage
            vertexShader: "grayeffect.vert.qsb"
            fragmentShader: "grayeffect.frag.qsb"
        }
    }
}
```

在前面的示例中，我们将两个图像排成一行。第一个是原始图像，第二个是带有着色器效果的图像。

在这一部分，您了解了 Qt Quick 中不同类型的着色器效果以及如何使用`qsb`工具创建兼容的片段文件。在下一部分，您将学习如何使用`Canvas`进行绘制。

# 使用 Canvas QML 类型

`Canvas`输出为图像。它提供了一个使用`Context2D`对象进行绘制并实现绘制信号处理程序的 2D 画布。 

让我们看一下以下示例：

```cpp
import QtQuick
import QtQuick.Window
Window {
    width: 512
    height: 512
    visible: true
    title: qsTr("Canvas Demo")
    Canvas {
        id: canvas
        anchors.fill: parent
        onPaint: {
            var context = getContext("2d")
            context.lineWidth = 2
            context.strokeStyle = "red"
            context.beginPath()
            context.moveTo(100,100)
            context.lineTo(250,100)
            context.lineTo(250,150)
            context.lineTo(100,150)
            context.closePath()
            context.stroke()
        }
    }
}
```

在前面的示例中，首先我们从`getContext("2d")`获取了上下文。然后我们用红色边框绘制了一个矩形。输出如下所示：

![图 8.7 – 使用 Canvas 绘制矩形的示例应用程序的输出](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_8.7_B16231.jpg)

图 8.7 – 使用 Canvas 绘制矩形的示例应用程序的输出

在这一部分，你已经熟悉了使用`Canvas`进行绘制。在下一部分，我们将讨论 Qt Quick 中的粒子系统。

# 理解粒子模拟

使用粒子系统，您可以模拟爆炸、烟花、烟雾、雾气和风等效果。Qt Quick 包括一个粒子系统，可以实现这些复杂的 2D 模拟，包括对重力和湍流等环境效果的支持。粒子最常用于游戏中，以为当前选定的列表项或活动通知器添加微妙且视觉上吸引人的效果。

`ParticleSystem`、`Painters`、`Emitters`和`Affectors`是这个粒子系统中的四种主要 QML 类型。`ParticleSystem`系统包括 painter、emitter 和 affector 类型。`ParticleSystem`类型连接所有这些类型并管理共享的时间轴。它们必须共享相同的`ParticleSystem`才能相互交互。在此约束条件下，您可以拥有尽可能多的粒子系统，因此逻辑上的分离是为所有要交互的类型使用一个`ParticleSystem`类型，或者如果类型数量较少且易于控制，则只使用一个。

要使用`ParticleSystem`，请使用以下行导入模块：

```cpp
 import QtQuick.Particles
```

发射器产生粒子。发射器在发射后不能再改变粒子。您可以使用`affectors`类型来影响发射后的粒子。

每种`affector`类型对粒子的影响都不同：

+   `Age`：修改粒子的寿命

+   `Attractor`：将粒子吸引到特定位置

+   `摩擦`：根据粒子当前速度减慢移动

+   `重力`：设置一个角度上的加速度

+   `湍流`：基于噪声图像的液体行为

+   `Wander`：随机改变路线

+   `GroupGoal`：改变粒子组的状态

+   `SpriteGoal`：改变精灵粒子的状态

让我们通过以下示例了解`ParticleSystem`的用法：

```cpp
    ParticleSystem {
        id: particleSystem
        anchors.fill: parent
        Image {
            source: "qrc:/logo.png"
            anchors.centerIn: parent
        }
        ImageParticle {
            system: particleSystem
            source: "qrc:/particle.png"
            colorVariation: 0.5
            color: "#00000000"
        }
        Emitter {
            id: emitter
            system: particleSystem
            enabled: true
            x: parent.width/2; y: parent.height/2
            maximumEmitted: 8000; emitRate: 6000
            size: 4 ; endSize: 24
            sizeVariation: 4
            acceleration: AngleDirection {
             angleVariation: 360; magnitude: 360; 
           }
        }
    }
```

在前面的代码中，我们使用了 Qt 标志，它在周围发射粒子。我们创建了一个`ImageParticle`的实例，它创建了由`Emitter`发射的粒子。`AngleDirection`类型用于决定粒子发射的角度和方向。由于我们希望粒子在标志周围发射，所以我们为两个属性都使用了`360`。前面示例的输出如*图 8.8*所示：

![图 8.8 – 上述粒子系统示例的输出](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_8.8_B16231.jpg)

图 8.8 – 上述粒子系统示例的输出

您可以在以下网站上了解更多关于这些 QML 类型的信息：

https://qmlbook.github.io/

在这一部分，我们讨论了 Qt Quick 中不同类型的绘制机制和组件。在下一部分，我们将学习如何在 Qt Widgets 中进行动画。

# Qt Widgets 中的动画

动画框架通过允许动画化 GUI 元素的属性来简化动画 GUI 元素的过程。`QPropertyAnimation`类是动画 GUI 元素的更常见的方式之一。这个类是动画框架的一部分，它使用 Qt 的定时器系统在指定的时间段内改变 GUI 元素的属性。

为了为我们的 GUI 应用程序创建动画，Qt 为我们提供了几个子系统，包括定时器、时间轴、动画框架、状态机框架和图形视图框架。

让我们讨论如何在以下代码中使用`QPushButton`的属性动画：

```cpp
QPropertyAnimation *animatateButtonA = new
QPropertyAnimation(ui->pushButtonA, "geometry");
animatateButtonA->setDuration(2000);
animatateButtonA->setStartValue(ui->pushButtonA->geometry());
animatateButtonA->setEndValue(QRect(100, 150, 200, 300));
```

在前面的代码片段中，我们将一个按钮从一个位置动画到另一个位置，并改变了按钮的大小。您可以通过在调用`start()`函数之前将缓动曲线添加到属性动画中来控制动画。您还可以尝试不同类型的缓动曲线，看哪种对您最有效。

属性动画和动画组都是从`QAbstractAnimator`类继承的。因此，您可以将一个动画组添加到另一个动画组中，创建一个更复杂的嵌套动画组。Qt 目前提供两种类型的动画组类，`QParallelAnimationGroup`和`QSequentialAnimationGroup`。

让我们使用`QSequentialAnimationGroup`组来管理其中的动画状态：

```cpp
QSequentialAnimationGroup *group = new QSequentialAnimationGroup;
group->addAnimation(animatateButtonA);
group->addAnimation(animatateButtonB);
group->addAnimation(animatateButtonC);
```

您可以在以下链接中了解更多关于 Qt 的动画框架：

https://doc.qt.io/qt-6/animation-overview.html

在本节中，我们讨论了 Qt Widgets 中的动画。在下一节中，您将学习如何在 Qt Quick 中进行动画。

# Qt Quick 中的动画和过渡

在本节中，您将学习如何在 Qt Quick 中创建动画并添加过渡效果。要创建动画，您需要为要动画化的属性类型选择适当的动画类型，然后将动画应用于所需的行为。

Qt Quick 有不同类型的动画，例如以下：

+   `Animator`：它是一种特殊类型的动画，直接作用于 Qt Quick 的场景图。

+   `AnchorAnimation`：用于动画化锚点更改。

+   `ParallelAnimation`：并行运行动画。

+   `ParentAnimation`：用于动画化父级更改。

+   `PathAnimation`：沿着路径动画化一个项目。

+   `PauseAnimation`：它允许在动画期间暂停。

+   `PropertyAnimation`：它动画化属性值的变化。

+   `SequentialAnimation`：按顺序运行动画。

+   `ScriptAction`：在动画期间，允许执行 JavaScript。

+   `PropertyAction`：它可以在动画期间立即更改属性，而无需动画化属性更改。

*图 8.9*显示了动画类的层次结构：

![图 8.9 - Qt Quick 中动画类的层次结构](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_8.9_B16231.jpg)

图 8.9 - Qt Quick 中动画类的层次结构

`PropertyAnimation`提供了一种方式来动画化属性值的变化。`PropertyAnimation`的不同子类如下：

+   `ColorAnimation`：动画化颜色值的变化

+   `NumberAnimation`：动画化`qreal`类型值的变化

+   `RotationAnimation`：动画化旋转值的变化

+   `Vector3dAnimation`：动画化`QVector3d`值的变化

可以以多种方式定义动画：

+   在`Transition`中

+   在`Behavior`中

+   作为`property`

+   在`signal`处理程序中

+   独立的

通过应用动画类型来动画化属性值。为了创建平滑的过渡效果，动画类型将插值属性值。状态转换也可以将动画分配给状态变化：

+   `SmoothedAnimation`：它是一个专门的`NumberAnimation`子类。在动画中，当目标值发生变化时，`SmoothAnimation`确保平滑变化。

+   `SpringAnimation`：具有质量、阻尼和 epsilon 等专门属性，提供弹簧式动画。

可以通过不同方式为对象设置动画：

+   直接属性动画

+   预定义的目标和属性

+   动画作为行为

+   状态变化期间的过渡

动画是通过将动画对象应用于属性值来逐渐改变属性，从而创建的。通过在属性值变化之间插值来实现平滑的动作。属性动画允许通过缓动曲线进行不同的插值和时间控制。

以下代码片段演示了使用预定义属性的两个`PropertyAnimation`对象：

```cpp
Rectangle {
    id: rect
    width: 100; height: 100
    color: "green"
    PropertyAnimation on x { to: 200 }
    PropertyAnimation on y { to: 200 }
}
```

在前面的示例中，动画将在`Rectangle`加载后立即开始，并自动应用于其`x`和`y`值。在这里，我们使用了`<AnimationType> on <Property>`语法。因此，不需要将目标和属性值设置为`x`和`y`。

动画可以按顺序或并行显示。顺序动画依次播放一组动画，而并行动画同时播放一组动画。因此，当动画被分组在`SequentialAnimation`或`ParallelAnimation`中时，它们将被顺序或并行播放。`SequentialAnimation`也可以用于播放`Transition`动画，因为过渡动画会自动并行播放。您可以将动画分组以确保组内的所有动画都应用于同一属性。

让我们在下面的示例中使用`SequentialAnimation`来对矩形的`color`进行动画处理：

```cpp
import QtQuick
import QtQuick.Window
Window {
    width: 640
    height: 480
    visible: true
    title: qsTr("Sequential Animation Demo")
    Rectangle {
        anchors.centerIn: parent
        width: 100; height: 100
        radius: 50
        color: "red"
        SequentialAnimation on color {
            ColorAnimation { to: "red"; duration: 1000 }
            ColorAnimation { to: "yellow"; duration: 1000 }
            ColorAnimation { to: "green"; duration: 1000 }
            running:true
            loops: Animation.Infinite
        }
    }
}
```

在前面的示例中，我们使用了`<AnimationType> on <Property>`语法在`color`属性上使用了`SequentialAnimation`。因此，子`ColorAnimation`对象会自动添加到此属性，不需要设置`target`或`property`动画值。

您可以使用`Behavior`动画来设置默认的属性动画。在`Behavior`类型中指定的动画将应用于属性，并使任何属性值的变化发生动画。要有意地启用或禁用行为动画，可以使用`enabled`属性。您可以使用多种方法将行为动画分配给属性。其中一种方法是`Behavior on <property>`声明。它可以方便地将行为动画分配到属性上。

`Animator`类型与普通的`Animation`类型不同。让我们创建一个简单的例子，通过使用`Animator`来旋转图像：

```cpp
import QtQuick
import QtQuick.Window
Window {
    width: 640
    height: 480
    visible: true
    title: qsTr("Animation Demo")
    Image {
        anchors.centerIn: parent
        source: "qrc:/logo.png"
        RotationAnimator on rotation {
            from: 0; to: 360;
            duration: 1000
            running:true
            loops: Animation.Infinite
        }
    }
}
```

在前面的示例中，我们使用了`RotationAnimator`类型，用于动画处理`Image`QML 类型的旋转。

在本节中，我们讨论了 Qt Quick 中不同类型的动画，并创建了几个示例。在下一节中，我们将讨论如何控制动画。

## 控制动画

`Animation`类型是所有动画类型的祖先。这种类型不允许创建`Animation`对象。它为用户提供了使用动画类型所需的属性和方法。所有动画类型都包括`start()`、`stop()`、`resume()`、`pause()`、`restart()`和`complete()`，它们控制动画的执行方式。

动画在开始和结束值之间的插值由缓动曲线定义。不同的缓动曲线可能超出定义的插值范围。缓动曲线使得更容易创建动画效果，如弹跳、加速、减速和循环动画。

在 QML 对象中，每个属性动画可能具有不同的缓动曲线。曲线可以通过各种参数进行控制，其中一些参数是特定于特定曲线的。请访问缓动文档以获取有关缓动曲线的更多信息。

在本节中，您了解了如何在 Qt Quick 中控制动画。在下一节中，您将学习如何使用状态和过渡。

# Qt Quick 中的状态、状态机和转换

Qt Quick 状态是属性配置，其中属性的值可以更改以反映不同的状态。状态更改会导致属性的突然变化；动画平滑过渡，以创建视觉上吸引人的状态更改。声明性状态机框架提供了用于在 QML 中创建和执行状态图的类型。考虑使用 QML 状态和转换来创建用户界面，其中多个视觉状态独立于应用程序的逻辑状态。

您可以通过添加以下语句将状态机模块和 QML 类型导入到您的应用程序中：

```cpp
import QtQml.StateMachine
```

请注意，在 QML 中有两种定义状态的方式。一种由`QtQuick`提供，另一种由`QtQml.StateMachine`模块提供。

重要提示

在单个 QML 文件中使用`QtQuick`和`QtQml.StateMachine`时，请确保在`QtQuick`之后导入`QtQml.StateMachine`。在这种方法中，`State`类型由声明性状态机框架提供，而不是由`QtQuick`提供。为了避免与 QtQuick 的`State`项产生任何歧义，您可以将`QtQml.StateMachine`导入到不同的命名空间中。

为了插值由状态更改引起的属性更改，`Transition`类型可以包括动画类型。将转换绑定到`transitions`属性以将其分配给对象。

按钮可以有两种状态：`pressed`和`released`。对于每个状态，我们可以分配不同的属性配置。转换将动画化从`pressed`到`released`的过渡。同样，在从`released`到`pressed`状态切换时也会有动画。

让我们看看以下示例。

使用`Rectangle` QML 类型创建一个圆形 LED，并向其添加`MouseArea`。将默认状态分配为`OFF`，颜色为`绿色`。在鼠标按下时，我们希望将 LED 颜色更改为`红色`，一旦释放鼠标，LED 再次变为`绿色`：

```cpp
Rectangle {
     id:led
     anchors.centerIn: parent
     width: 100
     height: 100
     radius: 50
     color: "green"
     state: "OFF"
     MouseArea {
        anchors.fill: parent
        onPressed: led.state = "ON"
        onReleased: led.state = "OFF"
    }
}
```

接下来，定义状态。在此示例中，我们有两个状态，`ON`和`OFF`。在这里，我们根据状态更改来操作`color`属性：

```cpp
states: [
       State {
            name: "ON"
            PropertyChanges { target: led; color: "red"}
       },
       State {
            name: "OFF"
            PropertyChanges { target: led; color: "green"}
       }
   ]
```

您可以向转换添加动画。让我们向转换添加`ColorAnimation`，使其平滑而有吸引力：

```cpp
transitions: [
    Transition {
        from: "ON"
        to: "OFF"
        ColorAnimation { target: led; duration: 100}
     },
     Transition {
         from: "OFF"
         to: "ON"
         ColorAnimation { target: led; duration: 100}
     }
]
```

在上面的示例中，我们使用了两个状态，`ON`和`OFF`。我们使用`MouseArea`根据鼠标按下和释放事件来更改状态。当状态为`ON`时，矩形颜色变为`红色`，当状态为`OFF`时，颜色变为`绿色`。在这里，我们还使用了`Transition`来在状态之间切换。

当`to`和`from`属性绑定到状态的名称时，转换将与状态更改相关联。对于简单或对称的转换，将`to`属性设置为通配符符号`"*"`意味着转换适用于任何状态更改：

```cpp
transitions: Transition {
    to: "*"
    ColorAnimation { target: led; duration: 100 }
}
```

您可以在以下链接中了解有关状态机 QML API 的更多信息：

https://doc.qt.io/qt-6/qmlstatemachine-qml-guide.html

在本节中，您了解了 Qt Quick 中的状态机。在下一节中，您将学习如何在 Qt Widgets 中使用状态机。

# Qt Widgets 中的状态机

状态机框架中的类可用于创建和执行状态图。状态机框架为在 Qt 应用程序中有效地嵌入状态图元素和语义提供了 API 和执行模型。该框架与 Qt 的元对象系统紧密集成。

在 Qt 6 中，状态机框架发生了重大变化。API 在 Qt 6.0.x 核心模块中丢失了。在 Qt 6.1 中，该模块被恢复为`statemachine`，以便在`.pro`文件中使用该框架。

如果您正在使用基于`qmake`的构建系统，则将以下行添加到您的`.pro`文件中：

```cpp
QT += statemachine
```

如果您正在使用基于*CMake*的构建系统，则将以下内容添加到`CMakeLists.txt`中：

```cpp
find_package(Qt6 COMPONENTS StateMachine REQUIRED)
target_link_libraries(mytarget PRIVATE Qt6::StateMachine)
```

您需要在 C++源文件中包含以下标头：

```cpp
#include <QStateMachine>
#include <QState>
```

让我们创建一个简单的 Qt Widgets 应用程序，实现状态机。通过添加`QLabel`和`QPushButton`修改 UI 表单：

1.  将以下代码添加到您自定义的 C++类的构造函数中：

```cpp
QState *green = new QState();
green->assignProperty(ui->pushButton, "text", "Green");
green->assignProperty(ui->led, 
"styleSheet","background-color: rgb(0, 190, 0);");
green->setObjectName("GREEN");
```

1.  在上面的代码中，我们创建了一个状态来显示绿色 LED。接下来，我们将为红色 LED 创建另一个状态：

```cpp
QState *red = new QState();
red->setObjectName("RED");
red->assignProperty(ui->pushButton, "text", "Red");
red->assignProperty(ui->led, "styleSheet", "background-color: rgb(255, 0, 0);");
```

1.  为按钮切换时的状态改变事件添加转换：

```cpp
green->addTransition(ui->pushButton,  
&QAbstractButton::clicked,red);
red->addTransition(ui->pushButton,
&QAbstractButton::clicked,green);
```

1.  现在创建一个状态机实例并向其添加状态：

```cpp
QStateMachine *machine = new QStateMachine(this);
machine->addState(green);
machine->addState(red);
machine->setInitialState(green);
```

1.  最后一步是启动状态机：

```cpp
machine->start();
```

1.  当您运行上面的示例时，您将看到一个输出窗口，如下所示：

![图 8.10 - 在 Qt Widgets 中使用状态机的应用输出](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_8.10_B16231.jpg)

图 8.10 - 在 Qt Widgets 中使用状态机的应用输出

前面的图表强调了在父状态机中，只能将子状态机的状态指定为转换目标。另一方面，父状态机的状态不能被指定为子状态机中的转换目标。

以下文章很好地捕捉了在使用状态机时的性能考虑：

https://www.embedded.com/how-to-ensure-the-best-qt-state-machine-performance/

在本节中，我们学习了状态机及其在 Qt Widgets 中的使用。我们讨论了如何在 Qt Widgets 和 Qt Quick 中实现状态机。让我们总结一下本章学到的内容。

# 摘要

在本章中，我们讨论了不同的图形 API，并学习了如何使用`QPainter`类在屏幕上和屏幕外绘制图形。我们还研究了图形视图框架和场景图渲染机制。我们看到了 Qt 如何在整个本章中提供`QPaintDevice`接口和`QPainter`类来执行图形操作。我们还讨论了图形视图类、OpenGL 框架和着色器工具。在本章末尾，我们探讨了 Qt Widgets 和 Qt Quick 中的动画和状态机框架。

在*第九章*，*测试和调试*中，我们将学习在 Qt 中进行调试和测试。这将帮助您找到问题的根本原因并修复缺陷。


# 第九章：测试和调试

调试和测试是软件开发的重要部分。在本章中，您将学习如何调试 Qt 项目，不同的调试技术以及 Qt 支持的调试器。调试是发现错误或不良行为根本原因并解决它的过程。我们还将讨论使用 Qt 测试框架进行单元测试。Qt Test 是一个用于 Qt 应用程序和库的单元测试框架。它具有大多数单元测试框架提供的所有功能。此外，它还提供了对**图形用户界面**（**GUI**）的支持。该模块有助于以方便的方式为基于 Qt 的应用程序和库编写单元测试。您还将学习使用不同 GUI 测试工具测试 GUI 的技术。

具体来说，我们将讨论以下主题：

+   在 Qt 中调试

+   调试策略

+   调试 C++应用程序

+   调试 Qt Quick 应用程序

+   在 Qt 中进行测试

+   与 Google 的 C++测试框架集成

+   测试 Qt Quick 应用程序

+   GUI 测试工具

在本章结束时，您将熟悉调试和测试技术，以用于您的 Qt 应用程序。

# 技术要求

本章的技术要求包括在最新版本的桌面平台（如 Windows 10、Ubuntu 20.04 或 macOS 10.14）上安装的 Qt 6.0.0 和 Qt Creator 4.14.0 的最低版本。

本章中使用的所有代码都可以从以下 GitHub 链接下载：[`github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter09`](https://github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter09)。

重要提示

本章中使用的屏幕截图来自 Windows 平台。您将在您的机器上基于底层平台看到类似的屏幕。

# 在 Qt 中调试

在软件开发中，技术问题经常出现。为了解决这些问题，我们必须首先识别并解决所有问题，然后才能将应用程序发布到公众以保持质量和声誉。调试是一种定位这些潜在技术问题的技术。

在接下来的章节中，我们将讨论软件工程师使用的流行调试技术，以确保其软件的稳定性和质量。

## Qt 支持的调试器

Qt 支持多种不同类型的调试器。您使用的调试器可能会因项目所用的平台和编译器而有所不同。以下是与 Qt 广泛使用的调试器列表：

+   **GNU Symbolic Debugger**（**GDB**）是由 GNU 项目开发的跨平台调试器。

+   **Microsoft Console Debugger**（**CDB**）是微软为 Windows 开发的调试器。

+   **Low Level Virtual Machine Debugger**（**LLDB**）是由 LLVM 开发组开发的跨平台调试器。

+   **QML/JavaScript Debugger**是 Qt 公司提供的 QML 和 JavaScript 调试器。

如果您在 Windows 上使用 MinGW 编译器，则不需要对 GDB 进行任何手动设置，因为它通常包含在 Qt 安装中。如果您使用其他操作系统，如 Linux，在将其链接到 Qt Creator 之前，您可能需要手动安装它。Qt Creator 会自动检测 GDB 的存在并将其添加到其调试器列表中。

您还可以通过指定`--vgdb=yes`或`--vgdb=full`来使用`gdbserver`。您可以指定`--vgdb-error=number`来在显示一定数量的错误后激活`gdbserver`。如果将值设置为`0`，则`gdbserver`将在初始化时激活，允许您在应用程序启动之前设置断点。值得注意的是，`vgdb`包含在**Valgrind**发行版中。它不需要单独安装。

如果您喜欢的平台是 Windows，您可以在计算机上安装 CDB。默认情况下，Visual Studio 的内置调试器将不可用。因此，在安装 Windows SDK 时，您必须选择调试工具作为可选组件单独安装 CDB 调试器。Qt Creator 通常会识别 CDB 的存在，并将其添加到**选项**下的调试器列表中。

Android 调试比在常规桌面环境中调试要困难一些。Android 开发需要不同的软件包，如 JDK、Android SDK 和 Android NDK。在桌面平台上，您需要**Android 调试桥**（**ADB**）驱动程序来允许 USB 调试。您必须在 Android 设备上启用开发者模式并接受 USB 调试才能继续。

macOS 和 iOS 上使用的调试器是**LLDB**。它默认包含在 Xcode 中。Qt Creator 将自动检测其存在并将其链接到一个工具包。如果您熟悉调试器并知道自己在做什么，还可以将非 GDB 调试器添加到您喜爱的 IDE 中。

调试器插件根据计算机上可用的内容，为每个软件包确定合适的本地调试器。您可以通过添加新的调试器来克服这种偏好。您可以在**选项**菜单下的**Kits**设置中的**调试器**选项卡中找到可用的调试器，如*图 9.1*所示：

![图 9.1 - 选取屏幕下的调试器选项卡显示添加按钮](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_9.1_B16231.jpg)

图 9.1 - 选取屏幕下的调试器选项卡显示添加按钮

在**调试器**选项卡中，您可以在右侧看到**添加**、**克隆**和**删除**按钮。您可以克隆现有的调试器配置并修改以满足您的要求。或者，如果您了解调试器的详细信息和配置，那么您可以使用**添加**按钮创建新的调试器配置。您还可以通过单击**删除**按钮删除有问题或过时的调试器配置。不要忘记单击**应用**按钮以保存更改。请注意，您无法修改自动检测到的调试器配置。

在本节中，我们了解了各种支持的调试器。在下一节中，我们将讨论如何调试应用程序。

# 调试策略

有不同的调试策略来找到问题的根本原因。在尝试定位应用程序中的错误之前，深入了解程序或库至关重要。如果您不知道自己在做什么，就无法找到错误。只有对系统及其运行方式有深入了解，才能够识别应用程序中的错误。以往的经验可以帮助检测类似类型的错误以及解决错误。个人专家的知识决定了开发人员能够多快地定位错误。您可以添加调试打印语句和断点来分析程序的流程。您可以进行前向分析或后向分析来跟踪错误的位置。

在调试时，以下步骤用于查找根本原因并解决问题：

1.  确定问题。

1.  定位问题。

1.  分析问题。

1.  解决问题。

1.  修复副作用。

无论编程语言或平台如何，调试应用程序时最重要的是知道代码的哪一部分导致了问题。您可以通过多种方式找到有问题的代码。

如果缺陷是由您的 QA 团队或用户提出的，请询问问题发生的时间。查看日志文件或任何错误消息。注释掉怀疑的代码部分，然后再次构建和运行应用程序，以查看问题是否仍然存在。如果问题是可重现的，通过打印消息和注释掉代码行来进行前向和后向分析，直到找到导致问题的代码行。

您还可以在内置调试器中设置断点，以搜索目标功能中的变量更改。如果其中一个变量已更新为意外值，或者对象指针已成为无效指针，则可以轻松识别它。检查您在安装程序中使用的所有模块，并确保您和您的用户使用的是应用程序的相同版本号。如果您使用的是不同版本或不同分支，请检出带有指定版本标签的分支，然后调试代码。

在下一节中，我们将讨论如何通过打印调试消息和添加断点来调试您的 C++代码。

# 调试 C++应用程序

`QDebug`类可用于将变量的值打印到应用程序输出窗口。`QDebug`类似于标准库中的`std::cout`，但它的好处是它是 Qt 的一部分，这意味着它支持 Qt 类，并且可以在不需要转换的情况下显示其值。

要启用调试消息，我们必须包含`QDebug`头文件，如下所示：

```cpp
#include <QDebug>
```

Qt 提供了几个用于生成不同类型调试消息的全局宏。它们可以用于不同的目的，如下所述：

+   `qDebug()`提供自定义调试消息。

+   `qInfo()`提供信息性消息。

+   `qWarning()`报告警告和可恢复错误。

+   `qCritical()`提供关键错误消息和报告系统错误。

+   `qFatal()`在退出之前提供致命错误消息。

您可以使用`qDebug()`来查看您的功能是否正常工作。在查找错误完成后，删除包含`qDebug()`的代码行，以避免不必要的控制台日志。让我们看看如何使用`qDebug()`来打印变量到输出窗格的示例。创建一个样本`QWidget`应用程序，并添加一个函数`setValue(int value)`，并在函数定义内添加以下代码：

```cpp
int value = 500;
qDebug() << "The value is : " << value;
```

上述代码将在 Qt Creator 底部的输出窗口中显示以下输出：

```cpp
The value is : 500
```

您可以通过查看函数的使用次数和在应用程序内调用的次数来确定值是否被另一个函数更改。如果调试消息多次打印，则它是从多个位置调用的。检查是否将正确的值发送到所有调用函数。在查找问题完成后，删除包含`qDebug()`的代码行，以消除输出控制台窗口中不必要的控制台日志。或者，您可以实现条件编译。

让我们进一步了解 Qt Creator 中的调试和调试选项：

1.  您可以在菜单栏中看到一个**调试**菜单。单击它时，您将看到一个上下文菜单，其中包含如*图 9.2*所示的子菜单：![图 9.2 - Qt Creator 中的调试菜单](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_9.2_B16231.jpg)

图 9.2 - Qt Creator 中的调试菜单

1.  要开始调试，请按*F5*或单击 Qt Creator 左下角的开始**调试**按钮，如下所示：![图 9.3 - Qt Creator 中的开始调试按钮](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_9.3_B16231.jpg)

图 9.3 - Qt Creator 中的开始调试按钮

1.  如果 Qt Creator 以错误消息抱怨调试器，则检查您的项目包是否有调试器。

1.  如果错误仍然存在，请关闭 Qt Creator 并转到您的项目文件夹，您可以在那里删除`.pro.user`文件。

1.  然后在 Qt Creator 中重新加载项目。Qt Creator 将重新配置您的项目，并且调试模式现在应该可用。

调试应用程序的一个很好的方法是设置断点：

1.  当您在 Qt Creator 中右键单击脚本的行号时，将会看到一个包含三个选项的弹出菜单。

1.  您还可以单击行号添加断点。单击行号设置断点。您将在行号上看到一个红点出现。

1.  接下来，按下键盘上的*F5*键或单击**Debug**按钮。运行应用程序以调试模式，您会注意到第一个红点上方出现了一个黄色箭头：![图 9.4 -  Qt Creator 显示调试窗口和断点](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_9.4_B16231.jpg)

图 9.4 - Qt Creator 显示调试窗口和断点

1.  调试器已在第一个断点处停止。现在，变量及其含义和类型将显示在 Qt Creator 右侧的**Locals**和**Expression**窗口中。

1.  这种方法可以快速检查应用程序。要删除断点，只需再次单击红点图标或从右键单击上下文菜单中删除：

![图 9.5 - 上下文菜单显示断点标记的右键单击选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_9.5_B16231.jpg)

图 9.5 - 上下文菜单显示断点标记的右键单击选项

重要的是要记住，必须在调试模式下运行应用程序。这是因为在调试模式下编译时，您的应用程序或库将具有额外的调试符号，允许调试器从二进制源代码中访问信息，例如标识符、变量和函数的名称。这就是为什么在调试模式下编译的应用程序或库二进制文件在文件大小上更大的原因。

您可以在以下文档中了解更多功能及其用法：

[`doc.qt.io/qt-6/debug.html`](https://doc.qt.io/qt-6/debug.html%20)

重要提示

一些防病毒应用程序会阻止调试器检索信息。Avira 就是这样的防病毒软件。如果在生产 PC 上安装了它，调试器在 Windows 平台上可能会失败。

在下一节中，我们将讨论如何调试 Qt Quick 应用程序并定位 QML 文件中的问题。

# 调试 Qt Quick 应用程序

在上一节中，我们讨论了如何调试 C++代码。但您可能仍然想知道如何调试 QML 中编写的代码。Qt 还提供了调试 QML 代码的功能。在开发 Qt Quick 应用程序时，有很多选项可以解决问题。在本节中，我们将讨论与 QML 相关的各种调试技术以及如何使用它们。

就像`QDebug`类一样，在 QML 中有不同的控制台 API 可用于调试。它们如下：

+   `Log`：用于打印一般消息。

+   `Assert`：用于验证表达式。

+   `Timer`：用于测量调用之间花费的时间。

+   `Trace`：用于打印 JavaScript 执行的堆栈跟踪。

+   `Count`：用于查找对函数的调用次数。

+   `Profile`：用于对 QML 和 JavaScript 代码进行分析。

+   `Exception`：用于打印错误消息。

控制台 API 提供了几个方便的函数来打印不同类型的调试消息，例如`console.log()`、`console.debug()`、`console.info()`、`console.warn()`和`console.error()`。您可以按以下方式打印带有参数值的消息：

```cpp
console.log("Value is:", value)
```

您还可以通过在`Components.onCompleted:{…}`中添加消息来检查组件的创建：

```cpp
Components.onCompleted: { 
     console.log("Component created") 
}
```

要验证表达式是否为真，您可以使用`console.assert()`，例如以下示例：

```cpp
console.assert(value == 100, "Reached the maximum limit");
```

您会发现`console.time()`和`console.timeEnd()`记录了调用之间花费的时间。`console.trace()`打印了 JavaScript 执行的堆栈跟踪。堆栈跟踪详细信息包括函数名、文件名、行号和列号。

`console.count()`返回代码执行次数以及消息。当使用`console.profile()`时，QML 和 JavaScript 分析被激活，当调用`console.profileEnd()`时被停用。您可以使用`console.exception()`打印错误消息以及 JavaScript 执行的堆栈跟踪。

您可以以与前一节讨论的相同方式添加断点，如下所示：

+   进入堆栈中的代码，单击工具栏上的**Step Into**按钮或按下*F11*键。

+   要退出，请按*Shift* + *F11*。要命中断点，请在方法末尾添加断点，然后单击**Continue**。

+   打开 QML 调试器控制台输出窗格，以在当前上下文中运行 JavaScript 命令。

在运行 Qt Quick 应用程序时，您可以找到问题并观察值。这将帮助您找到导致意外行为并需要修改的代码部分。

在本节中，我们了解了在 QML 环境中进行调试。在下一节中，我们将讨论 Qt 中的测试框架。

# 在 Qt 中进行测试

**单元测试**是使用自动化工具测试简单应用程序、类或函数的一种方法。在讨论如何将其纳入我们的方法之前，我们将讨论它是什么以及为什么我们希望这样做。单元测试是将应用程序分解为最小的功能单元，然后在倡议框架内使用真实世界的情况对每个单元进行测试的过程。单元是可以测试的应用程序的最小组件。在过程式编程中，单元测试通常侧重于函数或过程。

在面向对象编程中，单元通常是接口、类或单个函数。单元测试早期识别实施过程中的问题。这涵盖了程序员实现中的缺陷，以及单元规范中的缺陷或不完整部分。在创建过程中，单元测试是由要测试的单元的开发人员开发的短代码片段。有许多单元测试工具可用于测试您的 C++代码。让我们探讨 Qt 测试框架的优势和特点。

## 在 Qt 中进行单元测试

Qt Test 是用于基于 Qt 的应用程序和库的单元测试平台。Qt Test 包括传统单元测试应用程序中的所有功能，以及用于测试图形用户界面的插件。它有助于更轻松地为基于 Qt 的程序和库编写单元测试。*图 9.6*显示了**选项**下的**测试**部分：

![图 9.6–显示 Qt Creator 选项菜单下的 Qt Test 首选项的屏幕截图](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_9.6_B16231.jpg)

图 9.6–显示 Qt Creator 选项菜单下的 Qt Test 首选项的屏幕截图

以前，单元测试可能是手动完成的，特别是对于 GUI 测试，但现在有一个工具可以让您编写代码自动验证代码，这乍一看似乎有些违反直觉，但它确实有效。Qt Test 是一个基于 Qt 的专门单元测试框架。

您必须在项目文件（.pro）中添加`testlib`以使用 Qt 的内置单元测试模块：

```cpp
QT += core testlib
```

接下来，运行`qmake`以将模块添加到您的项目中。为了使测试系统找到并实现它，您必须使用`QTest`头文件并将测试函数声明为私有槽。`QTest`头文件包含与 Qt Test 相关的所有函数和语句。要使用`QTest`功能，只需在您的 C++文件中添加以下行：

```cpp
#include <QTest>
```

您应该为每种可能的情况编写测试用例，然后在基线代码更改时运行测试，以确保系统继续按预期行为。这是一个非常有用的工具，可以确保任何编程更新不会破坏现有功能。

让我们使用 Qt Creator 内置的向导创建一个简单的测试应用程序。从**新建项目**菜单中选择**自动测试项目**，如*图 9.7*所示：

![图 9.7–项目向导中的新自动测试项目选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_9.7_B16231.jpg)

图 9.7–项目向导中的新自动测试项目选项

生成测试项目框架后，您可以修改生成的文件以满足您的需求。打开测试项目的`.pro`文件，并添加以下代码行：

```cpp
QT += testlib
QT -= gui
CONFIG += qt console warn_on depend_includepath testcase
CONFIG -= app_bundle
TEMPLATE = app
SOURCES +=  tst_testclass.cpp
```

让我们创建一个名为`TestClass`的 C++类。我们将把我们的测试函数添加到这个类中。这个类必须派生自`QObject`。让我们看一下`tst_testclass.cpp`：

```cpp
#include <QtTest>
class TestClass : public QObject
{
    Q_OBJECT
public:
    TestClass() {}
    ~TestClass(){}
private slots:
    void initTestCase(){}
    void cleanupTestCase() {}
    void test_compareStrings();
    void test_compareValues();
};
```

在前面的代码中，我们声明了两个测试函数来测试样本字符串和值。您需要为声明的测试用例实现测试函数的测试场景。让我们比较两个字符串并进行简单的算术运算。您可以使用诸如`QCOMPARE`和`QVERIFY`之类的宏来测试值：

```cpp
void TestClass::test_compareStrings()
{
    QString string1 = QLatin1String("Apple");
    QString string2 = QLatin1String("Orange");
    QCOMPARE(string1.localeAwareCompare(string2), 0);
}
void TestClass::test_compareValues()
{
    int a = 10;
    int b = 20;
    int result = a + b;
    QCOMPARE(result,30);
}
```

要执行所有测试用例，您必须在文件底部添加诸如`QTEST_MAIN()`的宏。`QTEST_MAIN()`宏扩展为一个简单的`main()`方法，用于运行所有测试函数。`QTEST_APPLESS_MAIN()`宏适用于简单的独立非 GUI 测试，其中不使用`QApplication`对象。如果不需要 GUI 但需要事件循环，则使用`QTEST_GUILESS_MAIN()`：

```cpp
QTEST_APPLESS_MAIN(TestClass)
#include "tst_testclass.moc"
```

为了使测试用例成为一个独立的可执行文件，我们添加了`QTEST_APPLESS_MAIN()`宏和类的`moc`生成文件。您可以使用许多其他宏来测试应用程序。有关更多信息，请访问以下链接：

[`doc.qt.io/qt-6/qtest.html#macros`](http://doc.qt.io/qt-6/qtest.html#macros%20)

当您运行上面的示例时，您将看到如下所示的测试结果输出：

```cpp
********* Start testing of TestClass *********
Config: Using QtTest library 6.1.0, Qt 6.1.0 (x86_64-little_endian-llp64 shared (dynamic) release build; by GCC 8.1.0), windows 10
64bit HCBT_CREATEWND event start
PASS   : TestClass::initTestCase()
FAIL!  : TestClass::test_compareStrings() Compared values are not the same
   Actual   (string1.localeAwareCompare(string2)): -1
   Expected (0)                                  : 0
..\TestProject\tst_testclass.cpp(26) : failure location
PASS   : TestClass::test_compareValues()
PASS   : TestClass::cleanupTestCase()
Totals: 3 passed, 1 failed, 0 skipped, 0 blacklisted, 7ms
********* Finished testing of TestClass *********
```

您可以看到一个测试用例失败，因为它未满足测试标准。类似地，您可以添加更多的测试用例，并从另一个类中获取参数来测试功能。您还可以使用**运行所有测试**选项从 Qt Creator 菜单栏的**测试**上下文菜单中运行所有测试，如*图 9.8*所示：

![图 9.8 - 工具菜单下的测试选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_9.8_B16231.jpg)

图 9.8 - 工具菜单下的测试选项

您还可以在左侧的项目资源管理器视图中查看所有测试用例。从项目资源管理器下拉菜单中选择**测试**。您可以在此窗口中启用或禁用某些测试用例。*图 9.9*显示了我们之前编写的两个测试用例。您还可以看到我们没有在这个测试项目中使用其他测试框架：

![图 9.9 - 项目资源管理器下拉菜单中的测试资源管理器选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_9.9_B16231.jpg)

图 9.9 - 项目资源管理器下拉菜单中的测试资源管理器选项

您可以使用几个`QTest`便利函数来模拟 GUI 事件，如键盘或鼠标事件。让我们看一个简单的代码片段的用法：

```cpp
QTest::keyClicks(testLineEdit, "Enter");
QCOMPARE(testLineEdit->text(), QString("Enter"));
```

在前面的代码中，测试代码模拟了`lineedit`控件上的键盘文本`Enter`事件，然后验证了输入的文本。您还可以使用`QTest::mouseClick()`来模拟鼠标点击事件。您可以按照以下方式使用它：

```cpp
QTest::mouseClick(testPushBtn, Qt::LeftButton);
```

Qt 的测试框架在**测试驱动开发**（**TDD**）中也很有用。在 TDD 中，您首先编写一个测试，然后编写实际的逻辑代码。由于没有实现，测试最初会失败。然后，您编写必要的最少代码以通过测试，然后再进行下一个测试。这是在实现必要功能之前迭代开发功能的方法。

在本节中，我们学习了如何创建测试用例并模拟 GUI 交互事件。在下一节中，您将学习如何使用 Google 的 C++测试框架。

# 与 Google 的 C++测试框架集成

**GoogleTest**是由 Google 开发的测试和模拟框架。**GoogleMock**项目已合并到 GoogleTest 中。GoogleTest 需要支持至少 C++11 标准的编译器。它是一个跨平台的测试框架，支持 Windows、Linux 和 macOS 等主要桌面平台。它可以帮助您使用高级功能（如模拟）编写更好的 C++测试。您可以将 Qt Test 与 GoogleTest 集成，以充分利用两个框架的优势。如果您打算使用两个测试框架的功能，则应将 GoogleTest 用作主要测试框架，并在测试用例中使用 Qt Test 的功能。

Qt Creator 内置支持 GoogleTest。您可以在**选项**屏幕的**测试**部分中找到**Google 测试**选项卡，并设置全局的 GoogleTest 偏好，如*图 9.10*所示：

![图 9.10 - 选项菜单下测试部分中的 Google 测试选项卡](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_9.10_B16231.jpg)

图 9.10 - 选项菜单下测试部分中的 Google 测试选项卡

您可以从以下链接下载 GoogleTest 源代码：

[`github.com/google/googletest`](https://github.com/google/googletest%20)

您可以在以下文档中了解更多关于功能及其用法的信息：

[`google.github.io/googletest/primer.html`](https://google.github.io/googletest/primer.html%20)

下载源代码后，在创建示例应用程序之前构建库。您还可以将统一的 GoogleTest 源代码与测试项目一起构建。生成库后，按照以下步骤运行您的 GoogleTest 应用程序：

1.  要使用 Qt Creator 内置的向导创建一个简单的 GoogleTest 应用程序，请从**新建项目**菜单中选择**自动测试项目**。然后按照屏幕操作直到出现**项目和测试信息**。

1.  在**项目和测试信息**屏幕上，选择**Google 测试**作为**测试框架**。然后按照*图 9.11*所示添加**测试套件名称**和**测试用例名称**字段的信息：![图 9.11 - 项目创建向导中的 Google 测试选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_9.11_B16231.jpg)

图 9.11 - 项目创建向导中的 Google 测试选项

1.  接下来，您可以填写`.pro`文件。![图 9.12 - 在项目创建向导中添加 GoogleTest 源目录的选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_9.12_B16231.jpg)

图 9.12 - 在项目创建向导中添加 GoogleTest 源目录的选项

1.  单击**下一步**，按照说明生成项目的框架。

1.  要使用 GoogleTest，您必须将头文件添加到测试项目中：

```cpp
#include "gtest/gtest.h"
```

1.  您可以看到主函数已经被向导创建：

```cpp
#include "tst_calculations.h"
#include "gtest/gtest.h"
int main(int argc,char *argv[])
{
    ::testing::InitGoogleTest(&argc,argv);
    return RUN_ALL_TESTS();
}
```

1.  您可以使用以下语法创建一个简单的测试用例：

```cpp
TEST(TestCaseName, TestName) { //test logic }
```

1.  GoogleTest 还提供了诸如`ASSERT_*`和`EXPECT_*`的宏来检查条件和值：

```cpp
ASSERT_TRUE(condition)
ASSERT_EQ(expected,actual)
ASSERT_FLOAT_EQ(expected,actual)
EXPECT_DOUBLE_EQ (expected, actual)
```

在大多数情况下，在运行多个测试之前进行一些自定义的初始化工作是标准的程序。如果您想评估测试的时间/内存占用情况，您将不得不编写一些特定于测试的代码。测试装置有助于设置特定的测试要求。`fixture`类是从`::testing::Test`类派生的。请注意，使用`TEST_F`宏而不是`TEST`。您可以在构造函数或`SetUp()`函数中分配资源和进行初始化。同样，您可以在析构函数或`TearDown()`函数中释放资源。测试装置中的测试函数定义如下：

```cpp
TEST_F(TestFixtureName, TestName) { //test logic }
```

1.  创建和使用测试装置，创建一个从`::testing::Test`类派生的类，如下所示：

```cpp
class PushButtonTests: public ::testing::Test
{
protected:
    virtual void SetUp()
    {
        pushButton = new MyPushButton(0);
        pushButton ->setText("My button");
    }
};
TEST_F(PushButtonTests, sizeConstraints)
{
    EXPECT_EQ(40, pushButton->height());
    EXPECT_EQ(200, pushButton->width());
    pushButton->resize(300,300);
    EXPECT_EQ(40, pushButton->height());
    EXPECT_EQ(200, pushButton->width());
}
TEST_F(PushButtonTests, enterKeyPressed)
{
    QSignalSpy spy(pushButton, SIGNAL(clicked()));
    QTest::keyClick(pushButton, Qt::Key_Enter);
    EXPECT_EQ(spy.count(), 1);
}
```

在上述代码中，我们在`SetUp()`函数中创建了一个自定义的按钮。然后我们测试了两个测试函数来测试大小和*Enter*键处理。

1.  当您运行上述测试时，您将在输出窗口中看到测试结果。

GoogleTest 在运行时为使用`TEST_F()`指定的每个测试构建一个新的测试装置。它通过调用`SetUp()`函数立即进行初始化并运行测试。然后调用`TearDown()`进行清理，并移除测试装置。重要的是要注意，同一测试套件中的不同测试可以具有不同的测试装置对象。在构建下一个测试装置之前，GoogleTest 始终删除先前的测试装置。它不会为多个测试重用测试装置。一个测试对测试装置所做的任何修改对其他测试没有影响。

我们讨论了如何使用简单的测试用例创建 GoogleTest 项目以及如何设计测试夹具或测试套件。现在您可以为现有的 C++应用程序创建测试用例。GoogleTest 是一个非常成熟的测试框架。它还集成了早期在 GoogleMock 下可用的模拟机制。探索不同的功能并尝试测试用例。

还有一个现成的 GUI 工具，集成了两个测试框架，用于测试您的 Qt 应用程序。**GTest Runner**是一个基于 Qt 的自动化测试运行器和 GUI，具有强大的功能，适用于 Windows 和 Linux 平台。但是，该代码目前没有得到积极维护，并且尚未升级到 Qt 6。您可以在以下链接了解有关 GTest Runner 功能和用法的更多信息：

[`github.com/nholthaus/gtest-runner`](https://github.com/nholthaus/gtest-runner%20)

在本节中，您学习了如何同时使用`QTest`和`GoogleTest`。您已经了解了两种测试框架的特点。您可以使用 GoogleTest 框架的 GoogleMock 功能创建模拟对象。现在您可以为自定义的 C++类或自定义小部件编写自己的测试夹具。在下一节中，我们将讨论 Qt Quick 中的测试。

# 测试 Qt Quick 应用程序

`TestCase` QML 类型。以`test_`开头的函数被识别为需要执行的测试用例。测试工具会递归搜索`tst_ *.qml`文件所需的源目录。您可以将所有测试`.qml`文件放在一个目录下，并定义`QUICK_TEST_SOURCE_DIR`。如果未定义，则只有当前目录中可用的`.qml`文件将在测试执行期间包含在内。Qt 不保证 Qt Quick 测试模块的二进制兼容性。您必须使用模块的适当版本。

您需要将`QUICK_TEST_MAIN()`添加到 C++文件中，以开始执行测试用例，如下所示：

```cpp
#include <QtQuickTest>
QUICK_TEST_MAIN(testqml)
```

您需要添加`qmltest`模块以启用 Qt Quick 测试。将以下代码添加到`.pro`文件中：

```cpp
QT += qmltest
TEMPLATE = app
TARGET = tst_calculations
CONFIG += qmltestcase
SOURCES += testqml.cpp
```

让我们看一个基本算术计算的演示，以了解模块的工作原理。我们将进行一些计算，如加法、减法和乘法，并故意犯一些错误，以便测试用例失败：

```cpp
import QtQuick
import QtTest
TestCase {
    name: "Logic Tests"
    function test_addition() {
        compare(4 + 4, 8, "Logic: 4 + 4 = 8")
    }
    function test_subtraction() {
        compare(9 - 5, 4, "Logic: 9 - 5 = 4")
    }
    function test_multiplication() {
        compare(3 * 3, 6, "Logic: 3 * 3 = 6")
    }
}
```

当您运行上述示例时，您将看到以下测试结果的输出：

```cpp
********* Start testing of testqml *********
Config: Using QtTest library 6.1.0, Qt 6.1.0 (x86_64-little_endian-llp64 shared (dynamic) release build; by GCC 8.1.0), windows 10
PASS   : testqml::Logic Tests::initTestCase()
PASS   : testqml::Logic Tests::test_addition()
FAIL!  : testqml::Logic Tests::test_multiplication()Logic: 3 * 3 = 6
   Actual   (): 9
   Expected (): 6
C:\Qt6Book\Chapter09\QMLTestDemo\tst_calculations.qml(15) : failure location
PASS   : testqml::Logic Tests::test_subtraction()
PASS   : testqml::Logic Tests::cleanupTestCase()
Totals: 4 passed, 1 failed, 0 skipped, 0 blacklisted, 3ms
********* Finished testing of testqml *********
```

请注意，`cleanupTestCase()`在测试执行完成后立即调用。此函数可用于在一切被销毁之前进行清理。

您还可以执行数据驱动的测试，如下所示：

```cpp
import QtQuick
import QtTest
TestCase {
    name: "DataDrivenTests"
    function test_table_data() {
        return [
            {tag: "10 + 20 = 30", a: 10, b: 20, result: 30         
},
            {tag: "30 + 60 = 90", a: 30, b: 60, result: 90  
},
            {tag: "50 + 50 = 100", a: 50, b: 50, result: 50 
},
        ]
    }
    function test_table(data) {
        compare(data.a + data.b, data.result)
    }
}
```

请注意，可以使用以`_data`结尾的函数名向测试提供表格数据。当您运行上述示例时，您将看到以下测试结果的输出：

```cpp
********* Start testing of main *********
Config: Using QtTest library 6.1.0, Qt 6.1.0 (x86_64-little_endian-llp64 shared (dynamic) release build; by GCC 8.1.0), windows 10
PASS   : main::DataDrivenTests::initTestCase()
PASS   : main::DataDrivenTests::test_table(10 + 20 = 30)
PASS   : main::DataDrivenTests::test_table(30 + 60 = 90)
FAIL!  : main::DataDrivenTests::test_table(50 + 50 = 100) Compared values are not the same
   Actual   (): 100
   Expected (): 50
C:\Qt6Book\Chapter09\QMLDataDrivenTestDemo\tst_datadriventests.qml(14) : failure location
PASS   : main::DataDrivenTests::cleanupTestCase()
Totals: 4 passed, 1 failed, 0 skipped, 0 blacklisted, 3ms
********* Finished testing of main *********
```

您还可以在 QML 中运行基准测试。Qt 基准测试框架将多次运行以`benchmark_`开头的函数，并记录运行的平均时间值。这类似于 C++版本中的`QBENCHMARK`宏，用于获得`QBENCHMARK_ONCE`宏的效果。让我们看一个基准测试的示例：

```cpp
import QtQuick
import QtTest
TestCase {
    id: testObject
    name: "BenchmarkingMyItem"
    function benchmark_once_create_component() {
        var component = Qt.createComponent("MyItem.qml")
        var testObject = component.createObject(testObject)
        testObject.destroy()
        component.destroy()
    }
}
```

在上面的示例中，我们创建了一个自定义的 QML 元素。我们想要测量创建该元素所需的时间。因此，我们编写了上述基准测试代码。普通的基准测试会多次运行并显示操作的持续时间。在这里，我们对创建进行了基准测试一次。这种技术在评估您的 QML 代码的性能时非常有用。

当您运行上述示例时，您将看到以下测试结果的输出：

```cpp
********* Start testing of testqml *********
Config: Using QtTest library 6.1.0, Qt 6.1.0 (x86_64-little_endian-llp64 shared (dynamic) release build; by GCC 8.1.0), windows 10
PASS   : testqml::BenchmarkingMyItem::initTestCase()
PASS   : testqml::BenchmarkingMyItem::benchmark_once_create_component()
PASS   : testqml::BenchmarkingMyItem::benchmark_once_create_component()
RESULT : testqml::benchmark_once_create_component:
     0 msecs per iteration (total: 0, iterations: 1)
PASS   : testqml::BenchmarkingMyItem::cleanupTestCase()
QWARN  : testqml::UnknownTestFunc() QQmlEngine::setContextForObject(): Object already has a QQmlContext
Totals: 4 passed, 0 failed, 0 skipped, 0 blacklisted, 5ms
********* Finished testing of testqml *********
```

要多次运行基准测试，可以从测试用例中删除`once`关键字，如下所示：`function benchmark_create_component() {...}`。您还可以使用`Qt.createQmlObject()`测试动态创建的对象。

还有一个名为**qmlbench**的基准测试工具，用于基准测试 Qt 应用程序的整体性能。这是一个功能丰富的基准测试工具，可在**qt-labs**下使用。该工具还有助于测量用户界面的刷新率。您可以在以下链接中了解更多关于此工具的信息：

[`github.com/qt-labs/qmlbench`](https://github.com/qt-labs/qmlbench%20)

与 C++实现一样，您还可以在 QML 中模拟键盘事件，例如`keyPress()`、`keyRelease()`和`keyClick()`。事件将传递到当前正在聚焦的 QML 对象。让我们看看以下示例：

```cpp
import QtQuick
import QtTest
MouseArea {
    width: 100; height: 100
    TestCase {
        name: "TestRightKeyPress"
        when: windowShown
        function test_key_click() {
            keyClick(Qt.Key_Right)
        }
    }
}
```

在前面的例子中，键盘事件是在显示 QML 查看窗口后传递的。在此之前尝试传递事件将不成功。为了跟踪窗口何时显示，使用了`when`和`windowShown`属性。

当您运行前面的例子时，您将看到以下测试结果的输出：

```cpp
********* Start testing of testqml *********
Config: Using QtTest library 6.1.0, Qt 6.1.0 (x86_64-little_endian-llp64 shared (dynamic) release build; by GCC 8.1.0), windows 10
PASS   : testqml::TestRightKeyPress::initTestCase()
QWARN  : testqml::TestRightKeyPress::test_key_click() QQmlEngine::setContextForObject(): Object already has a QQmlContext
PASS   : testqml::TestRightKeyPress::test_key_click()
PASS   : testqml::TestRightKeyPress::cleanupTestCase()
Totals: 3 passed, 0 failed, 0 skipped, 0 blacklisted, 25ms
********* Finished testing of testqml *********
```

您可以使用`SignalSpy`来监视信号发射。在以下示例中，我们使用`SignalSpy`来检测`Button`上的`clicked`信号。当信号被发射时，`clickSpy`计数会增加：

```cpp
import QtQuick
import QtQuick.Controls
import QtTest
Button {
    id: pushButton
    SignalSpy {
        id: clickSpy
        target: pushButton
        signalName: "clicked"
    }
    TestCase {
        name: "PushButton"
        function test_click() {
            compare(clickSpy.count, 0)
            pushButton.clicked();
            compare(clickSpy.count, 1)
        }
    }
}
```

当您运行前面的例子时，您将看到以下测试结果的输出：

```cpp
********* Start testing of testqml *********
Config: Using QtTest library 6.1.0, Qt 6.1.0 (x86_64-little_endian-llp64 shared (dynamic) release build; by GCC 8.1.0), windows 10
PASS   : testqml::PushButton::initTestCase()
PASS   : testqml::PushButton::test_click()
PASS   : testqml::PushButton::cleanupTestCase()
Totals: 3 passed, 0 failed, 0 skipped, 0 blacklisted, 5ms
********* Finished testing of testqml *********
```

`QUICK_TEST_MAIN_WITH_SETUP`宏用于在运行任何 QML 测试之前执行 C++代码。这对于在 QML 引擎上设置上下文属性非常有用。测试应用程序可以包括多个`TestCase`实例。运行所有测试用例后，应用程序将终止。您可以从**Tests**资源管理器中启用或禁用测试用例：

![图 9.13 - 测试资源管理器显示具有可用测试用例的快速测试](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_9.13_B16231.jpg)

图 9.13 - 测试资源管理器显示具有可用测试用例的快速测试

在本节中，我们讨论了测试 QML 对象的不同测试方法。在下一节中，我们将熟悉 GUI 测试，并了解一些流行的工具。

# GUI 测试工具

您可以轻松地将一个或多个类评估为单元测试，但我们必须手动编写所有测试用例。GUI 测试是一项特别具有挑战性的任务。我们如何记录用户交互，例如鼠标点击，而不需要在 C++或 QML 中编写代码？这个问题困扰着开发人员。市场上有许多 GUI 测试工具可帮助我们做到这一点。其中一些价格昂贵，一些是开源的。我们将在本节中讨论一些此类工具。

但您可能不需要一个完整的 GUI 测试框架。一些问题可以通过简单的技巧解决。例如，在处理 GUI 时，您可能还需要检查不同属性，如可视元素的对齐和边界。其中最简单的方法之一是添加一个`Rectangle`来检查边界，如下面的代码所示：

```cpp
Rectangle {
    id: container
    anchors {
        left: parent.left
        leftMargin: 100
        right: parent.right
        top: parent.top
        bottom: parent.bottom
    }
    Rectangle {
        anchors.fill : parent
        color: "transparent"
        border.color: "blue"    }
    Text {
        text: " Sample text"
        anchors.centerIn: parent
        Rectangle {
            anchors.fill : parent
            color: "transparent"
            border.color: "red"
        }
    }
}
```

当您运行前面的代码片段时，您将看到 GUI 中的元素边界以颜色显示，如下一张截图所示：

![图 9.14 - 使用矩形输出 GUI 元素的视觉边界](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_9.14_B16231.jpg)

图 9.14 - 使用矩形输出 GUI 元素的视觉边界

在前面的例子中，您可以看到文本元素被放置在带有蓝色边框的矩形内部。如果没有蓝色边框，您可能会想知道为什么它没有在 GUI 中央放置。您还可以看到每个元素的边界和边距。当文本元素的宽度小于字体宽度时，您将观察到裁剪。您还可以找出用户界面元素之间是否有重叠区域。通过这种方式，您可以在不使用`SG_VISUALIZE`环境变量的情况下找到 GUI 特定元素的问题。

让我们讨论一些 GUI 测试工具。

## Linux 桌面测试项目（LDTP）

**Linux 桌面测试项目**（**LDTP**）提供了一个高质量的测试自动化基础设施和尖端工具，用于测试和改进 Linux 桌面平台。LDTP 是一个在所有平台上运行的 GUI 测试框架。它使用可访问性库在应用程序的用户界面中进行探测。该框架还包括根据用户与 GUI 交互的方式记录测试用例的工具。

要单击按钮，请使用以下语法：

```cpp
click('<window name>','<button name>')
```

要获取给定对象的当前滑块值，请使用以下代码：

```cpp
getslidervalue('<window name>','<slider name>')
```

要为您的 GUI 应用程序使用 LDTP，必须为所有 QML 对象添加可访问名称。您可以使用对象名称作为可访问名称，如下所示：

```cpp
Button {
     id: quitButton
     objectName: "quitButton"
     Accessible.name: objectName 
}
```

在上述代码中，我们为 QML 控件添加了可访问名称，以便 LDTP 工具可以找到此按钮。LDTP 需要用户界面的窗口名称来定位子控件。假设窗口名称是**Example**，那么要生成单击事件，请在 LDTP 脚本上使用以下命令：

```cpp
>click('Example','quitButton')
```

上述 LDTP 命令定位`quitButton`并生成按钮单击事件。

您可以在以下链接了解其特点和用途：

[`ldtp.freedesktop.org/user-doc/`](https://ldtp.freedesktop.org/user-doc/%20)

## GammaRay

KDAB 开发了一个名为`QObject`内省机制的软件内省工具。这个工具可以在本地机器和远程嵌入式目标上使用。它扩展了指令级调试器的功能，同时遵循底层框架的标准。这对于使用场景图、模型/视图、状态机等框架的复杂项目特别有用。有几种工具可用于检查对象及其属性。然而，它与 Qt 复杂框架的深度关联使其脱颖而出。

您可以从以下链接下载 GammaRay：

[`github.com/KDAB/GammaRay/wiki/Getting-GammaRay`](https://github.com/KDAB/GammaRay/wiki/Getting-GammaRay%20)

您可以在以下链接了解其特点和用途：

[`www.kdab.com/development-resources/qt-tools/gammaray/`](https://www.kdab.com/development-resources/qt-tools/gammaray/%20)

## Squish

**Squish**是一个用于桌面、移动、嵌入式和 Web 应用程序的跨平台 GUI 测试自动化工具。您可以使用 Squish 自动化 GUI 测试，用于使用 Qt Widgets 或 Qt Quick 编写的跨平台应用程序。Squish 被全球数千家组织用于通过功能回归测试和系统测试测试其 GUI。

您可以在以下链接了解有关该工具的更多信息：

[`www.froglogic.com/squish/`](https://www.froglogic.com/squish/%20)

在本节中，我们讨论了各种 GUI 测试工具。探索它们，并尝试在您的项目中使用它们。让我们总结一下本章的学习成果。

# 总结

在本章中，我们学习了调试是什么，以及如何使用不同的调试技术来识别 Qt 应用程序中的技术问题。除此之外，我们还看了 Qt 在各种操作系统上支持的各种调试器。最后，我们学习了如何使用单元测试来简化一些调试措施。我们讨论了单元测试，并学习了如何使用 Qt 测试框架。您看到了如何调试 Qt Quick 应用程序。我们还讨论了 Qt 支持的各种其他测试框架和工具。现在，您可以为自定义类编写单元测试。如果有人意外修改了某些特定逻辑，单元测试将失败并自动发出警报。

在*第十章*，*部署 Qt 应用程序*，您将学习如何在各种平台上部署 Qt 应用程序。这将帮助您为目标平台创建可安装的软件包。


# 第十章：部署 Qt 应用程序

在之前的章节中，您学习了如何使用 Qt 6 开发和测试应用程序。您的应用程序已经准备就绪并在您的桌面上运行，但它并不是独立的。您必须遵循一定的步骤来发布您的应用程序，以便最终用户可以使用。这个过程被称为**部署**。一般来说，最终用户希望有一个可以双击打开以运行您的软件的单个文件。软件部署包括使软件可用于其预期用户的不同步骤和活动，这些用户可能没有任何技术知识。

在本章中，您将学习如何在不同平台上部署 Qt 项目。在整个过程中，您将了解可用的部署工具以及创建部署软件包时需要考虑的重要要点。

在本章中，我们将涵盖以下主题：

+   部署策略

+   静态与动态构建

+   在桌面平台上部署

+   Qt 安装程序框架

+   其他安装工具

+   在 Android 上部署

通过本章结束时，您将能够创建一个可部署的软件包并与他人共享。

# 技术要求

本章的技术要求包括 Qt 6.0.0 和 Qt Creator 4.14.0 的最低版本，安装在最新的桌面平台上，如 Windows 10 或 Ubuntu 20.04 或 macOS 10.14。

本章中使用的所有代码都可以从以下 GitHub 链接下载：[`github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter10/HelloWorld`](https://github.com/PacktPublishing/Cross-Platform-Development-with-Qt-6-and-Modern-Cpp/tree/master/Chapter10/HelloWorld)。

重要说明

本章使用的屏幕截图是在 Windows 平台上进行的。您将在您的设备上看到基于底层平台的类似屏幕。

# 理解部署的必要性

使软件在目标设备上运行的过程，无论是测试服务器、生产环境、用户的桌面还是移动设备，都被称为**软件部署**。通常，最终用户希望有一个可以打开以访问您的应用程序的单个文件。用户不希望经历多个过程来获取各种外来文件。通常，用户寻找可以双击或轻点启动的软件。用户不希望经历一系列步骤来获取一些未知文件。在本章中，我们将讨论在部署 Qt 应用程序时需要考虑的步骤和事项。我们将讨论在 Windows、Mac、Linux 和 Android 平台上部署应用程序。

到目前为止，我们一直在运行我们迄今为止构建的应用程序的调试版本。您应该生成发布二进制文件以生成部署软件包。这两种选择之间的区别在于调试版本包含有关您编写的代码的信息，如果遇到问题，这将使调试变得更加容易。但是，您不希望向用户发送多个文件，因为这对他们来说是没有用的。用户只想运行您的应用程序。这就是为什么您必须向他们提供您应用程序的发布版本。因此，为了发布应用程序，我们将以发布模式创建它，这将为我们提供一个发布二进制文件，我们可以交付给我们的用户。一旦您获得了二进制文件，您将需要根据您想要部署应用程序的平台创建单独的软件包。如果您想在 Windows 上部署，您将采取特定的方法，同样适用于 Linux、macOS 或 Android。

标准的 Qt 部署包包括一个单独的可执行文件，但需要其他文件的存在才能运行。除了可执行文件，还需要以下文件：

+   动态库

+   第三方库

+   附加模块

+   可分发文件

+   Qt 插件

+   翻译文件

+   帮助文件

+   许可证

当我们在 Qt Creator 中启动一个 Qt 项目时，默认情况下设置为使用动态链接。因此，我们的应用程序将需要 Qt 动态链接库。我们还需要您喜欢的编译器的 C++运行时（MinGW/MSVC/Clang/GCC）和标准库实现。这些通常作为 Windows 上的`.dll`文件、Linux 上的`.so`文件以及 macOS 上的`.so`或`.dylib`文件提供。如果您的项目是一个庞大复杂的项目，您可能有多个库。您的应用程序包还可能需要第三方库，如 opengl、libstdc++、libwinpthread 和 openssl。

如果您的应用程序基于 Qt Quick，那么您还需要标准模块，如 QtQuick、QtQml、QtStateMachine、QtCharts 和 Qt3D。它们以动态库的形式提供，还有一些额外的文件提供 QML 模块元数据，或者纯 QML 文件。不幸的是，实现 Qt 的 C++和 QML API 的动态库是不足以让我们的可执行文件运行的。Qt 还使用插件来启用扩展，以及用于相当标准的 GUI 功能，如图像文件加载和显示的插件。同样，一些插件封装了 Qt 运行的平台。

如果您正在使用 Qt 的翻译支持，那么您还需要部署翻译文件。我们将在第十一章“国际化”中更多地讨论翻译。如果您正在使用 Qt 帮助框架甚至简单的 PDF 手册，您可能还需要部署文档文件。您还可能需要部署一些图标、脚本或许可协议供您的应用程序使用。您还必须确保 Qt 库可以自行定位平台插件、文档和翻译，以及预期的可执行文件。

## 在静态和动态库之间进行选择

您可以使用静态链接或动态链接构建您的 Qt 应用程序。在构建应用程序时，链接器使用这两种方法之一将所有使用的库函数的副本复制到可执行文件中。我们假设您已经了解这两种方法。在本节中，我们将讨论何时使用静态链接和何时使用动态链接来构建您的 Qt 应用程序。

在 Linux 中是`.a`文件扩展名，在 Windows 中是`.lib`文件扩展名。

在 Linux 中是`.so`文件扩展名，在 Windows 中是`.dll`文件扩展名。

静态构建由单个可执行文件组成。但在动态构建中，您必须注意动态库。静态构建更简单，因为它们可能已经在可执行文件中包含了 Qt 插件和 QML 导入。静态构建还便于指定`-static`配置选项。这种 Qt 应用程序部署模式仅适用于商业许可。如果您是开源开发人员，应避免静态链接应用程序。由于本书中使用的是开源 Qt 版本，我们不会详细介绍静态构建。相反，我们将坚持使用常规的动态构建和部署。

您可以在以下链接了解有关使用上述方法部署 Qt 应用程序的更多信息：

[`doc.qt.io/qt-6/deployment.html`](https://doc.qt.io/qt-6/deployment.html)。

在接下来的章节中，我们将专注于主要的桌面和移动平台。我们不会讨论嵌入式平台，因为这超出了本书的范围。

# 在桌面平台上部署

您已经看到，在部署 Qt 应用程序时有很多要考虑的事情。幸运的是，Qt 提供了一个工具，可以通过扫描生成的应用程序二进制文件，识别所有依赖项，并将它们复制到部署目录中来协助我们进行这个过程。我们将在各种平台上部署我们的应用程序以实现不同的目标，但概念将保持不变。一旦我们构建好我们的二进制文件，我们需要做的第一件事就是添加依赖项，以便用户可以无困难地执行应用程序。

我们可以以两种方式加载依赖项。我们可以手动操作，也可以使用 Qt 框架或第三方提供的某些工具。在 Windows 上，我们可以使用`windeployqt`来加载我们的依赖项。在 macOS 上，我们可以使用`macdeployqt`来为我们的二进制文件加载依赖项。还有另一个工具叫做`linuxdeployqt`，您可以使用它来为您的二进制文件添加依赖项。`linuxdeployqt`非常适合我们的需求，在本章中我们将讨论它。然而，这个 Linux 部署实用工具不是官方的，也不受 Qt 支持。一旦生成了您的二进制文件，您需要找到并添加依赖项。您可以手动操作，也可以根据您所在的位置使用这些工具之一来部署您的应用程序。

在本章中，我们将使用一个简单的*HelloWorld*示例来讨论如何在不同平台上部署应用程序。我们将找到依赖项并创建一个独立的包。让我们从 Windows 部署开始。

## 在 Windows 上部署

大多数为 Windows 构建的桌面应用程序通常以两种方式交付。首先，应用程序作为一个独立的应用程序交付，无需安装。在这种方法中，应用程序通常作为一个带有所有依赖库的可执行文件（`.exe`）出现在同一目录中。这种类型的应用程序称为`.exe`或`.msi`格式。您将学习如何创建一个可安装的`.exe`文件。在本节中，我们将讨论如何使用这两种方法创建独立部署包。

按照以下步骤创建一个便携式应用程序：

1.  首先创建一个简单的 Qt 应用程序。您可以选择 Qt Widget 或 Qt Quick-based 应用程序。这里我们将讨论基于 Qt Widget 的应用程序。这两种类型的应用程序的过程是相同的。

1.  创建示例应用程序后，您可以选择通过在`main.cpp`文件中添加几行代码来添加应用程序名称、版本、组织名称和域，如下所示：

```cpp
QApplication app (argc, argv);
app.setOrganizationName("Awesome Company");
app.setOrganizationDomain("www.abc.com");
app.setApplicationName("Deployment Demo");
app.setApplicationVersion("1.0.0");
```

1.  创建应用程序后，以**发布**模式构建它。您可以在构建设置中更改**构建**模式。**发布**模式会创建一个较小的二进制文件，因为它会消除调试符号。您可以通过单击并选择**发布**选项来快速从套件选择器部分更改构建模式，如*图 10.1*所示：![图 10.1 - Qt Creator 中的发布选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.1_B16231.jpg)

图 10.1 - Qt Creator 中的发布选项

1.  您可以看到二进制文件是在**发布**目录中创建的。在这个例子中，我们使用了*影子构建*。您还可以从**构建设置**屏幕下的**常规**部分更改发布目录：![图 10.2 - 具有发布二进制文件的目录](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.2_B16231.jpg)

图 10.2 - 具有发布二进制文件的目录

1.  现在，创建一个部署目录，并从**发布**目录中复制可执行文件。

1.  现在，双击可执行文件。您会注意到应用程序无法启动，并出现了几个错误对话框。错误对话框会提到缺少哪个库。如果您没有看到这些错误，那么您可能已经在系统环境中添加了库路径。您可以在未安装 Qt 库的干净系统上尝试：![图 10.3 - 显示 Qt 库依赖的错误](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.3_B16231.jpg)

图 10.3 - 显示 Qt 库依赖的错误

1.  下一步是找到在 IDE 之外独立运行应用程序所需的缺失的 Qt 库。

1.  由于我们在这里使用的是 Qt 的开源版本和动态链接方法，您会注意到缺失的库将具有`.dll`扩展名。在这里，我们看到缺失的库是`Qt6Core.dll`。

1.  错误的数量将取决于程序中使用的模块数量。您可以从`QTDIR/6.x.x/<CompilerName>/bin`目录中找到 Qt 依赖库。在这里，`QTDIR`是 Qt 6 安装的位置。在我们的示例中，我们使用了*Qt 6.1.0*作为版本，*mingw81_64*作为编译器，因此路径是`D:/Qt/6.1.0/mingw81_64/bin`。这个路径可能会根据您的 Qt 安装路径、Qt 版本和选择的编译器而有所不同。以下截图显示了`bin`目录下动态库的存在：![图 10.4 – bin 目录中所需的 Qt 库](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.4_B16231.jpg)

图 10.4 – bin 目录中所需的 Qt 库

1.  如*图 10.4*所示，将缺失的`.dll`文件复制到最近创建的部署目录中。

1.  重复这个过程，直到您将错误消息中提到的所有丢失的库都复制到部署目录中。您可能还需要部署特定于编译器的库以及您的应用程序。您还可以使用**Dependency Walker**（**depends.exe**）工具找到依赖库。这个工具是一个专门针对 Windows 的免费工具。它提供了一个依赖库列表。然而，在最近的版本中，这个工具并不是很有用，经常无法提供所需的信息。您还可以尝试一些其他工具，比如 PeStudio、MiTeC EXE Explorer 和 CFF Explorer。请注意，我没有探索过这些工具。

1.  一旦您复制了所有丢失的库，请尝试再次运行应用程序。这一次，您会注意到一个新的错误弹出。这次，消息与平台插件有关：![图 10.5 – 错误对话框指示缺少 Qt 平台插件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.5_B16231.jpg)

图 10.5 – 错误对话框指示缺少 Qt 平台插件

1.  在部署目录中创建一个名为`platforms`的目录：![图 10.6 – 显示 Qt Windows 平台插件的目录](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.6_B16231.jpg)

图 10.6 – 显示 Qt Windows 平台插件的目录

1.  然后，将`qwindows.dll`文件从`C:\Qt\6.x.x\<compiler_name>\plugins\platforms`复制到新的`platforms`子目录中。*图 10.7*说明了部署目录中文件的组织结构：![图 10.7 – 在发布目录中复制平台插件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.7_B16231.jpg)

图 10.7 – 在发布目录中复制平台插件

1.  现在，双击`HelloWorld.exe`文件。您会注意到**HelloWorld!** GUI 立即出现。现在，Qt Widgets 应用程序可以在没有安装 Qt 6 的 Windows 平台上运行：![图 10.8 – 运行已解决依赖关系的独立应用程序](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.8_B16231.jpg)

图 10.8 – 运行已解决依赖关系的独立应用程序

1.  下一步，也是最后一步，是将文件夹压缩并与您的朋友分享。

恭喜！您已成功部署了您的第一个独立应用程序。然而，这种方法对于一个有许多依赖文件的大型项目来说效果不佳。Qt 提供了几个方便的工具来处理这些挑战，并轻松创建安装包。在下一节中，我们将讨论 Windows 部署工具以及它如何帮助我们处理这些挑战。

## Windows 部署工具

Windows 部署工具随 Qt 6.x 安装包一起提供。您可以在`<QTDIR>/bin/`下找到它，命名为`windeployqt.exe`。您可以从 Qt 命令提示符中运行这个工具，并将可执行文件作为参数传递，或者使用目录作为参数。如果您正在构建一个 Qt Quick 应用程序，您还需要额外添加`.qml`文件的目录路径。

让我们看看`windeployqt`中一些重要的命令行选项。在下面的列表中探索一些有用的选项：

+   `-?`或`-h`或`--help`显示命令行选项的帮助信息。

+   `--help-all`显示包括 Qt 特定选项在内的帮助信息。

+   `--libdir <path>`将依赖库复制到路径。

+   `--plugindir <path>`将依赖插件复制到路径。

+   `--no-patchqt`指示不要修补 Qt6Core 库。

+   `--no-plugins`指示跳过插件部署。

+   `--no-libraries`指示跳过库部署。

+   `--qmldir <directory>`从源目录扫描 QML 导入。

+   `--qmlimport <directory>`将给定路径添加到 QML 模块搜索位置。

+   `--no-quick-import`指示跳过 Qt Quick 导入的部署。

+   `--no-system-d3d-compiler`指示跳过 D3D 编译器的部署。

+   `--compiler-runtime`在桌面上部署编译器运行时。

+   `--no-compiler-runtime`防止在桌面上部署编译器运行时。

+   `--no-opengl-sw`防止部署软件光栅化器库。

您可以在`bin`文件夹中找到`windeployqt`工具，如下面的屏幕截图所示：

![图 10.9 - bin 目录中的 windeployqt 工具](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.9_B16231.jpg)

图 10.9 - bin 目录中的 windeployqt 工具

使用`windeployqt`的最简单方法是将其路径添加到**Path**变量中。要将其添加到**Path**，在 Windows 机器上打开**系统属性**，然后单击**高级系统设置**。您会发现**系统属性**窗口出现了。在**系统属性**窗口的底部，您会看到**环境变量…**按钮。单击它，然后选择**Path**变量，如下面的屏幕截图所示。然后，单击**编辑…**按钮。添加 Qt bin 目录的路径，然后单击**确定**按钮：

![图 10.10 - 将 bin 目录添加到系统环境路径](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.10_B16231.jpg)

图 10.10 - 将 bin 目录添加到系统环境路径

关闭**系统属性**屏幕并启动 Qt 命令提示符。然后，您可以使用以下语法为基于 Qt Widget 的应用程序创建部署包：

```cpp
>windeployqt <your-executable-path>
```

如果您正在使用 Qt Quick，请按照下一个语法：

```cpp
>windeployqt --qmldir <qmlfiles-path> <your-executable-path>
```

之后，该工具将复制识别出的依赖项到部署目录，确保我们将所有所需的组件放在一个位置。它还将构建插件和其他 Qt 资源的子目录结构，这是您所期望的。如果 ICU 和其他文件不在 bin 目录中，则必须在运行该工具之前将它们添加到**Path**变量中。

让我们从相同的*HelloWorld*示例开始。要使用`windeployqt`创建示例的部署，请执行以下步骤：

1.  创建一个部署目录，并将`HelloWorld.exe`文件复制到部署目录。

1.  现在您可以调用部署工具，如下所示：

```cpp
D:\Chapter10\HelloWorld\deployment>windeployqt HelloWorld.exe
```

1.  输入命令后，工具将开始收集有关依赖项的信息：

```cpp
>D:\Chapter10\HelloWorld\deployment\HelloWorld.exe 64 bit, release executable
Adding Qt6Svg for qsvgicon.dll
Direct dependencies: Qt6Core Qt6Widgets
All dependencies   : Qt6Core Qt6Gui Qt6Widgets
To be deployed     : Qt6Core Qt6Gui Qt6Svg Qt6Widgets
```

1.  您会注意到该工具不仅列出了依赖项，还将所需的文件复制到目标目录。

1.  打开部署目录，您会发现已添加了多个文件和目录：![图 10.11 - windeployqt 复制了所有必需的文件到部署目录](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.11_B16231.jpg)

图 10.11 - windeployqt 复制了所有必需的文件到部署目录

1.  在前一节中，我们不得不自己识别和复制所有依赖项，但现在这项任务已委托给了`windeployqt`工具。

1.  如果您正在使用*Qt Quick 应用程序*，请运行以下命令：

```cpp
>D:\Chapter10\qmldeployment>windeployqt.exe --qmldir D:\Chapter10\HelloWorld D:\Chapter10\qmldeployment
```

1.  您会看到该工具已经收集了依赖项，并将所需的文件复制到部署目录：

```cpp
D:\Chapter10\qmldeployment\HelloWorld.exe 64 bit, release executable [QML]
Scanning D:\Chapter10\HelloWorld:
QML imports:
  'QtQuick' D:\Qt\6.1.0\mingw81_64\qml\QtQuick
  'QtQuick.Window' D:\Qt\6.1.0\mingw81_64\qml\QtQuick\Window
  'QtQml' D:\Qt\6.1.0\mingw81_64\qml\QtQml
  'QtQml.Models' D:\Qt\6.1.0\mingw81_64\qml\QtQml\Models
  'QtQml.WorkerScript' D:\Qt\6.1.0\mingw81_64\qml\QtQml\WorkerScript
Adding Qt6Svg for qsvgicon.dll
Direct dependencies: Qt6Core Qt6Gui Qt6Qml
All dependencies   : Qt6Core Qt6Gui Qt6Network Qt6OpenGL Qt6Qml Qt6Quick Qt6QuickParticles Qt6Sql
To be deployed     : Qt6Core Qt6Gui Qt6Network Qt6OpenGL Qt6Qml Qt6Quick Qt6QuickParticles Qt6Sql Qt6Svg
```

1.  现在，您可以双击启动独立应用程序。

1.  下一步是压缩文件夹并与朋友分享。

Windows 部署工具的命令行选项可用于微调识别和复制过程。基本说明可以在以下链接中找到：

[`doc.qt.io/qt-6/windows-deployment.html`](https://doc.qt.io/qt-6/windows-deployment.html)。

[`wiki.qt.io/Deploy_an_Application_on_Windows`](https://wiki.qt.io/Deploy_an_Application_on_Windows).

干杯！您已经学会了使用 Windows 部署工具部署 Qt 应用程序。但是，还有很多工作要做。Qt 安装程序框架提供了几个方便的工具，用于处理这些挑战并轻松创建可安装的软件包。在下一节中，我们将讨论 Linux 部署工具以及如何使用它创建独立应用程序。

## 在 Linux 上部署

在 Linux 发行版中，我们有多种选项来部署我们的应用程序。您可以使用安装程序，但也可以选择应用程序包的选项。在 Debian、Ubuntu 或 Fedora 上有一种称为 `apt` 的技术，您的应用程序可以通过这种方式使用。但是，您也可以选择一个更简单的方法，比如 app image 选项，它将为您提供一个文件。您可以将该文件提供给用户，他们只需双击即可运行应用程序。

Qt 文档提供了在 Linux 上部署的特定说明。您可以在以下链接中查看：

[`doc.qt.io/qt-6/linux-deployment.html`](https://doc.qt.io/qt-6/linux-deployment.html).

Qt 并未为 Linux 发行版提供类似于 `windeployqt` 的现成工具。这可能是由于 Linux 发行版的数量众多。但是，有一个名为 `linuxdeployqt` 的非官方开源 Linux 部署工具。它接受应用程序作为输入，并通过将项目资源复制到包中将其转换为自包含软件包。用户可以将生成的包作为 `AppDir` 或 `AppImage` 获取，或者可以将其包含在跨发行版软件包中。使用诸如 CMake、qmake 和 make 等系统，它可以作为构建过程的一部分来部署用 C、C++ 和其他编译语言编写的应用程序。它可以打包运行基于 Qt 的应用程序所需的特定库和组件。

您可以从以下链接下载 `linuxdeployqt`：

[`github.com/probonopd/linuxdeployqt/releases`](https://github.com/probonopd/linuxdeployqt/releases).

下载后，您将得到 `linuxdeployqt-x86_64.AppImage`，在运行之前执行 `chmod a+x`。

您可以在 [`github.com/probonopd/linuxdeployqt`](https://github.com/probonopd/linuxdeployqt) 上阅读完整的文档并找到源代码。

如果您想轻松地获得单个应用程序包，那么请使用 `-appimage` 标志运行 `linuxdeployqt`。

还有一些其他部署工具，如 **Snap** 和 **Flatpak**，可以打包应用程序及其依赖项，使其在多个 Linux 发行版上运行而无需进行任何修改。

您可以在以下链接中了解如何创建一个 snap：[`snapcraft.io/docs/creating-a-snap`](https://snapcraft.io/docs/creating-a-snap%20)

您可以通过访问以下链接了解更多关于 Flatpak 的信息：[`docs.flatpak.org/en/latest/qt.html`](https://docs.flatpak.org/en/latest/qt.html%20)

在下一节中，我们将讨论 macOS 部署工具以及如何使用它为您的 Mac 用户创建独立应用程序。

## 在 macOS 上部署

您可以按照前几节讨论的类似过程来为 macOS 生成安装程序文件。我们将讨论您可以遵循的步骤来生成应用程序包。您可以在 macOS 上测试该软件包并将其发送给您的 Mac 用户。该过程与在 Linux 上基本相同。毕竟，macOS 是基于 Unix 的。因此，您可以在 macOS 上创建我们称之为 bundle 的安装程序。

您可以在`QTDIR/bin/macdeployqt`中找到 macOS 部署工具。它旨在自动化创建包含 Qt 库作为私有框架的可部署应用程序包的过程。Mac 部署工具还部署 Qt 插件，除非您指定`-no-plugins`选项。默认情况下，Qt 插件（如平台、图像格式、打印支持和辅助功能）始终被部署。只有在应用程序使用时，才会部署 SQL 驱动程序和 SVG 插件。设计师插件不会被部署。如果要在应用程序包中包含第三方库，必须在构建后手动将库复制到包中。

几年前，苹果推出了一个名为`.dmg`的新文件系统。为了与 Qt 当前支持的所有 macOS 版本兼容，`macdeployqt`默认使用较旧的 HFS+文件系统。要选择不同的文件系统，请使用`-fs`选项。

您可以在以下链接找到详细的说明：[`doc.qt.io/qt-6/macos-deployment.html`](https://doc.qt.io/qt-6/macos-deployment.html)。

在下一节中，我们将讨论 Qt Installer Framework 以及如何使用它为用户创建完整的安装包。

# 使用 Qt Installer Framework

**Qt Installer Framework**（**QIFW**）是一个跨平台工具和实用程序集合，用于为支持的桌面 Qt 平台创建安装程序，包括 Linux、Windows 和 macOS。它允许您在所有支持的桌面 Qt 平台上分发应用程序，而无需重写源代码。Qt Installer Framework 工具创建包含一系列页面的安装程序，帮助用户完成安装、更新和卸载过程。您提供可安装的内容以及有关其的信息，如产品名称、安装程序和法律协议。

您可以通过向预定义页面添加小部件或添加整个页面来个性化安装程序，以提供更多选项给消费者。您可以通过编写脚本向安装程序添加操作。根据您的用例，您可以为最终用户提供离线或在线安装，或两者兼有。它在 Windows、Linux 和 Mac 上都能很好地运行。我们将使用它为我们的应用程序创建安装程序，并且将详细讨论在 Windows 上的工作原理。Linux 和 macOS 的过程与 Windows 类似。因此，我们只会讨论 Windows 平台。您可以在您喜欢的平台上尝试类似的步骤。

您可以在以下链接了解有关预定义页面的更多信息：[`doc.qt.io/qtinstallerframework/ifw-use-cases-install.html`](https://doc.qt.io/qtinstallerframework/ifw-use-cases-install.html)。

在开始之前，请确认 Qt Installer Framework 已安装在您的计算机上。如果不存在，请启动**Qt 维护工具**，并从**选择组件**页面安装，如下截图所示：

![图 10.12 - Qt 维护工具中的 Qt Installer Framework 下载选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.12_B16231.jpg)

图 10.12 - Qt 维护工具中的 Qt Installer Framework 下载选项

安装应用程序成功后，您将在`QTDIR\Tools\QtInstallerFramework\`下找到安装文件：

![图 10.13 - Windows 上 Qt Installer Framework 目录中的工具](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.13_B16231.jpg)

图 10.13 - Windows 上 Qt Installer Framework 目录中的工具

您可以看到在 Qt Installer Framework 目录中创建了五个可执行文件：

+   - `archivegen`工具用于将文件和目录打包成 7zip 存档。

+   - `binarycreator`工具用于创建在线和离线安装程序。

+   - `devtool`用于使用新的安装程序基础更新现有安装程序。

+   - `installerbase`工具是打包所有数据和元信息的核心安装程序。

+   - `repogen`工具用于生成在线存储库。

在本节中，我们将使用`binarycreator`工具为我们的 Qt 应用程序创建安装程序。此工具可用于生成离线和在线安装程序。某些选项具有默认值，因此您可以将它们省略。

要在 Windows 机器上创建离线安装程序，您可以在 Qt 命令提示符中输入以下命令：

```cpp
><location-of-ifw>\binarycreator.exe -t <location-of-ifw>\installerbase.exe -p <package_directory> -c <config_directory>\<config_file> <installer_name>
```

类似地，在 Linux 或 Mac 机器上创建离线安装程序，您可以在 Qt 命令提示符中输入以下命令：

```cpp
><location-of-ifw>/binarycreator -t <location-of-ifw>/installerbase -p <package_directory> -c <config_directory>/<config_file> <installer_name>
```

例如，要创建离线安装程序，请执行以下命令：

```cpp
>binarycreator.exe --offline-only -c installer-config\config.xml -p packages-directory -t installerbase.exe SDKInstaller.exe
```

上述说明将创建一个包含所有依赖项的 SDK 的离线安装程序。

要创建仅在线安装程序，可以使用`--online-only`，它定义了从 Web 服务器上的在线存储库安装的所有软件包。例如，要创建在线安装程序，请执行以下命令：

```cpp
>binarycreator.exe -c installer-config\config.xml -p packages-directory -e org.qt-project.sdk.qt,org.qt-project.qtcreator -t installerbase.exe SDKInstaller.exe
```

您可以在以下页面了解有关`binarycreator`和不同选项的更多信息：[`doc.qt.io/qtinstallerframework/ifw-tools.html#binarycreator`](https://doc.qt.io/qtinstallerframework/ifw-tools.html#binarycreator)。

使用`binarycreator`的最简单方法是将其路径添加到`QIFW` bin 目录中，然后单击**OK**按钮。以下屏幕截图说明了如何执行此操作：

![图 10.14–将 QIFW bin 目录添加到系统环境路径](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.14_B16231.jpg)

图 10.14–将 QIFW bin 目录添加到系统环境路径

关闭**系统属性**屏幕并启动 Qt 命令提示符。

让我们继续部署我们的示例* HelloWorld *应用程序。我们将为我们的用户创建一个可安装的软件包，这样他们就可以双击并安装它：

1.  创建一个与安装程序设计相匹配并允许将来扩展的目录结构。目录中必须存在`config`和`packages`子目录。QIFW 部署的目录放在哪里并不重要；重要的是它具有这种结构。

1.  创建一个包含构建安装程序二进制文件和在线存储库的说明的配置文件。在 config 目录中创建一个名为`config.xml`的文件，并添加以下内容：

```cpp
<?xml version="1.0" encoding="UTF-8"?>
<Installer>
    <Name>Deployment Example </Name>
    <Version>1.0.0</Version>
    <Title>Deployment Example</Title>
    <Publisher>Packt</Publisher>
    <StartMenuDir>Qt6 HelloWorld</StartMenuDir>
    <TargetDir>@HomeDir@/HelloWorld</TargetDir>
</Installer>
```

`Title`标签提供了安装程序在标题栏中显示的名称。应用程序名称使用`Name`标签添加到页面名称和介绍性文本中。软件版本号由`Version`标签指定。`Publisher`标签定义了软件的发布者。产品在 Windows 开始菜单中的默认程序组名称由`StartMenuDir`标签指定。向用户呈现的默认目标目录是当前用户主目录中的`InstallationDirectory`，由`TargetDir`标签指定。您可以在文档中了解更多标签。

您还可以在`config.xml`中指定应用程序包图标。在 Windows 上，它使用`.ico`进行扩展，并可用作`.exe`文件的应用程序图标。在 Linux 上，您可以使用`.png`扩展名指定图标，并将其用作窗口图标。在 macOS 上，您可以使用`.icns`指定图标，并将其用作新生成的包的图标。

1.  现在在`packages`目录内创建一个子目录。这将是您的`component`名称。您可以使用您的组织名称和应用程序名称或您的组织域作为`component`，例如`CompanyName.ApplicationName`。目录名称充当类似域的标识符，用于标识所有组件。

1.  创建一个包含有关可能安装的组件的详细信息的软件包信息文件。在这个简单的例子中，安装程序只需处理一个组件。让我们在`packages\{component}\meta`目录中创建一个名为`package.xml`的软件包信息文件。

1.  在 meta 目录中添加文件，其中包含有关组件的信息，以提供给安装程序。

让我们创建`package.xml`并将以下内容添加到其中：

```cpp
<?xml version="1.0"?>
<Package>
    <DisplayName>Hello World</DisplayName>
    <Description>This is a simple deployment example.
    </Description>
    <Version>1.0.1</Version>
    <ReleaseDate>2021-05-19</ReleaseDate>
</Package>
```

以下元素的信息将在安装过程中的组件选择页面上显示：

+   `DisplayName`标签指定了组件在组件列表中的名称。

+   `Description`标签指定了在选择组件时显示的文本。

+   `Version`标签使您能够在更新可用时向用户推广更新。

+   `Default`标签指定组件是否默认选择。值`true`将组件设置为已选择。

+   您可以向安装程序添加许可信息。指定了在许可检查页面上显示的许可协议文本的文件名由`License`标签指定。

1.  您可以将所需内容复制到`package`目录下的`data`子目录中。将之前使用`windeployqt`创建的所有文件和目录复制到`data`子目录中。以下屏幕截图显示了复制到`data`子目录中的内容：![图 10.15 – windeployqt 生成的内容复制到 data 子目录中](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.15_B16231.jpg)

图 10.15 – windeployqt 生成的内容复制到 data 子目录中

1.  下一步是使用`binarycreator`工具创建安装程序。在 Qt 命令提示符中输入以下指令：

```cpp
>binarycreator.exe -c config/config.xml -p packages HelloWorld.exe
```

1.  您可以看到在我们的部署目录中生成了一个安装程序文件：![图 10.16 – 部署目录中创建的安装程序包](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.16_B16231.jpg)

```cpp
$./binarycreator -c config/config.xml -p packages HelloWorld
```

1.  我们得到了期望的结果。现在，让我们运行安装程序，验证部署包是否已正确创建。

1.  双击安装程序文件开始安装。您将看到一个漂亮的安装向导出现在屏幕上：![图 10.17 – 运行部署示例的安装向导](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.17_B16231.jpg)

图 10.17 – 安装向导运行部署示例

1.  按照页面提示完成安装。退出安装向导。

1.  现在，从 Windows 的**开始**菜单启动应用程序。您应该很快就会看到**HelloWorld**用户界面出现。

1.  您还可以在**添加/删除程序**中找到已安装的应用程序：![图 10.18 – Windows 程序列表中的部署示例条目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.18_B16231.jpg)

图 10.18 – Windows 程序列表中的部署示例条目

1.  您可以使用与安装包一起安装的维护工具来更新、卸载和添加应用程序组件。您可以在安装目录中找到该工具，如下面的屏幕截图所示：

![图 10.19 – 安装目录中的维护工具](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.19_B16231.jpg)

图 10.19 – 安装目录中的维护工具

恭喜！您已为示例应用程序创建了一个安装程序包。现在，您可以将开发的 Qt 应用程序发送给用户和朋友。

您还可以通过自定义设置向导页面进行进一步定制。您可以在以下链接找到可与 QIFW 一起使用的安装程序的完整模板列表：

[`doc.qt.io/qtinstallerframework/ifw-customizing-installers.html`](https://doc.qt.io/qtinstallerframework/ifw-customizing-installers.html)

[`doc.qt.io/qtinstallerframework/qtifwexamples.html`](https://doc.qt.io/qtinstallerframework/qtifwexamples.html)。

您可以在这里探索框架的更多功能：[`doc.qt.io/qtinstallerframework/ifw-overview.html`](https://doc.qt.io/qtinstallerframework/ifw-overview.html)。

在本节中，我们创建了一个可安装的软件包，以供最终用户使用。在下一节中，我们将学习在 Android 平台上部署。

# 在 Android 上部署

除了桌面平台如 Windows、Linux 和 macOS 之外，移动平台同样重要，因为用户数量庞大。许多开发人员希望将他们的应用程序提供给移动平台。让我们看看如何做到这一点。我们将简要讨论 Android 上的部署注意事项。

在*第五章*，*跨平台开发*中，您已经学会了如何创建一个`.apk`文件，这是 Android 平台的部署包。因此，我们不会再讨论这些步骤。在本节中，我们将讨论上传到 Play 商店之前的一些必要更改：

1.  使用 kit 选择屏幕从 Android Kit 创建一个简单的*HelloWorld*应用程序。

1.  将构建模式更改为**发布**模式。

1.  打开项目的构建设置。您会在屏幕上看到几个选项：![图 10.20 - 屏幕截图显示构建设置中的 Android 清单选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.20_B16231.jpg)

图 10.20 - 屏幕截图显示构建设置中的 Android 清单选项

1.  您可以在**应用程序签名**部分下看到**密钥库**字段。单击**浏览...**按钮选择现有的密钥库文件，或使用**创建...**按钮创建新的密钥库文件。它可以保护密钥材料免受未经授权的使用。这是一个可选步骤，只有在签署部署二进制文件时才需要。

1.  当您单击**创建...**按钮时，您将看到一个对话框，其中有几个字段。填写相关字段，然后单击**保存**按钮。*图 10.21*显示了密钥库创建对话框：![图 10.21 - 屏幕截图显示密钥库创建屏幕](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.21_B16231.jpg)

图 10.21 - 屏幕截图显示密钥库创建屏幕

1.  将密钥库文件保存在任何地方，确保文件名以`.keystore`结尾。

下一步是对应用程序包进行签名。这也是一个可选步骤，只有在发布到 Play 商店时才需要。您可以在官方文档中了解有关应用程序签名的更多信息，网址为[`developer.android.com/studio/publish/app-signing`](https://developer.android.com/studio/publish/app-signing)。

1.  您可以选择目标 Android 版本，并通过在 Qt Creator 中创建`AndroidManifect.xml`文件来配置您的 Android 应用程序。要做到这一点，单击**构建 Android APK**屏幕上的**创建** **模板**按钮。您将看到一个对话框出现，如下图所示：![图 10.22 - 屏幕截图显示清单文件创建向导](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.22_B16231.jpg)

图 10.22 - 屏幕截图显示清单文件创建向导

1.  打开清单文件。您将看到 Android 应用程序的几个选项。

1.  您可以设置包名称、版本代码、SDK 版本、应用程序图标、权限等。如果添加一个独特的图标，那么您的应用程序在设备上不会显示默认的 Android 图标。这将使您的应用程序在屏幕上独特且易于发现。

1.  让我们将*HelloWorld*作为应用程序名称，并将 Qt 图标作为我们的应用程序图标，如下图所示：![图 10.23 - Android 清单文件显示不同的可用选项](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.23_B16231.jpg)

图 10.23 - Android 清单文件显示不同的可用选项

1.  如果使用任何第三方库，如 OpenSSL，则添加额外的库。

1.  单击 Qt Creator 左下角的**运行**按钮，在 Android 设备上构建和运行应用程序。您还可以单击**运行**按钮下方的**部署**按钮来创建部署二进制文件。

1.  您会看到屏幕上出现一个新的对话框。此对话框允许您选择物理 Android 硬件或软件仿真虚拟设备。

1.  连接您的 Android 设备并单击**刷新设备列表**按钮。不要忘记从 Android 设备设置中启用**开发者选项**。当您的 Android 设备提示时，请允许**USB 调试**：![图 10.24 – Android 设备选择对话框](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.24_B16231.jpg)

图 10.24 – Android 设备选择对话框

1.  如果您想使用虚拟设备，请单击**创建 Android 虚拟设备**按钮。您将看到以下屏幕出现：![](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.25_B16231.jpg)

图 10.25 – Android 虚拟设备创建屏幕

1.  如果屏幕警告您无法创建新 AVD，则请从 Android SDK 管理器中更新 Android 平台工具和系统映像。您可以按照以下命令行更新这些内容：

```cpp
>sdkmanager "platform-tools" "platforms;android-30"
>sdkmanager "system-images;android-30;google_apis;x86"
>sdkmanager --licenses
```

1.  然后，运行以下命令来运行`avdmanager`：

```cpp
>avdmanager create avd -n Android30 -k "system-images;android-30;google_apis;x86"
```

1.  最后一步是单击`build`文件夹中的`.apk`扩展名：![图 10.26 – 生成在 build 目录中的 Android 安装程序文件](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/xplat-dev-qt6-mod-cpp/img/Figure_10.26_B16231.jpg)

图 10.26 – 生成在 build 目录中的 Android 安装程序文件

1.  在内部，Qt 运行`androiddeployqt`实用程序。有时，该工具可能无法创建包，并显示以下错误：

```cpp
error: aidl.exe …Failed to GetFullPathName
```

在这种情况下，请将您的应用程序放在较短的文件路径中，并确保您的文件路径中没有目录包含空格。然后，构建应用程序。

1.  您可以将`.apk`文件分发给您的朋友或用户。用户必须在其 Android 手机或平板电脑上接受一个选项，即**从未知来源安装**。为了避免这种情况，您应该在 Play 商店上发布您的应用程序。

1.  但是，如果您想在 Google Play 商店上分发您的应用程序，那么您必须注册为 Google Play 开发者并对软件包进行签名。Google 会收取一笔小额费用，以允许开发者发布他们的应用程序。

1.  请注意，Qt 将 Android 应用视为闭源。因此，如果您希望保持 Android 应用代码私有，您将需要商业 Qt 许可证。

恭喜！您已成功生成了一个可部署的 Android 应用程序。与 iOS 不同，Android 是一个开放系统。您可以将`.apk`文件复制或分发到运行相同 Android 版本的其他 Android 设备上并进行安装。

在本节中，我们为我们的 Android 设备创建了一个可安装的软件包。在下一节中，我们将学习更多安装工具。

# 其他安装工具

在本节中，我们将讨论一些其他工具，您可以使用这些工具创建安装程序。请注意，我们不会详细讨论这些工具。我尚未验证这些安装框架是否与 Qt 6 兼容。您可以访问各自工具的网站并从其文档中了解更多信息。除了 Qt 提供的安装框架和工具之外，您还可以在 Windows 机器上使用以下工具：

+   **CQtDeployer**是一个应用程序，用于提取可执行文件的所有依赖库并为您的应用程序创建启动脚本。该工具声称可以更快地部署应用程序并提供灵活的基础设施。它支持 Windows 和 Linux 平台。您可以在以下链接了解更多关于该工具的信息：[`github.com/QuasarApp/CQtDeployer`](https://github.com/QuasarApp/CQtDeployer)。

+   **Nullsoft Scriptable Install System**（**NSIS**）是来自 Nullsoft 的基于脚本的安装工具，该公司也创建了 Winamp。它已成为专有商业工具（如 InstallShield）的流行替代品。NSIS 的当前版本具有现代图形用户界面、LZMA 压缩、多语言支持和简单的插件系统。您可以在[`nsis.sourceforge.io/Main_Page`](https://nsis.sourceforge.io/Main_Page)了解更多有关该工具的信息。

+   **InstallShield**是一款专有软件应用程序，允许您创建安装程序和软件捆绑包。InstallShield 通常用于在 Windows 平台桌面和服务器系统上安装软件，但也可以用于管理各种便携式和移动设备上的软件应用程序和软件包。查看其功能并试用试用版。您可以在以下链接下载试用版并了解更多信息：[`www.revenera.com/install/products/installshield.html`](https://www.revenera.com/install/products/installshield.html)。

+   **Inno Setup**是一个由 Delphi 创建的免费软件脚本驱动安装系统。它于 1997 年首次发布，但仍然凭借其出色的功能集和稳定性与许多商业安装程序竞争。在以下链接了解更多关于此安装程序的信息：[`jrsoftware.org/isinfo.php`](https://jrsoftware.org/isinfo.php)。

您可以选择任何安装框架并部署您的应用程序。最终，它应该能够满足您的安装目标。

在本节中，我们讨论了一些可能有益于您需求的安装工具。现在让我们总结一下本章的要点。

# 概要

我们首先讨论了应用程序部署问题，并学习了静态库和动态库之间的区别。然后我们讨论了 Qt 中的不同部署工具，以及 Windows 部署和安装的特定情况。凭借这些知识，我们在 Windows 上部署了一个示例应用程序，并使用了 Qt 安装程序框架创建了一个安装程序。此外，我们还发现了在 Linux 和 macOS 上部署应用程序，并磨练了在各种平台上部署应用程序的技能。之后，我们解释了在将基于 Qt 的 Android 应用程序发布到 Play 商店之前需要考虑的一些重要问题。

最后，我们看了一些第三方安装程序工具。总之，您已经学会了在各种平台上开发、测试和部署 Qt 应用程序。有了这些知识，您应该能够创建自己的安装包并与世界分享。

在*第十一章*，*国际化*中，我们将学习开发一个支持翻译的 Qt 应用程序。
