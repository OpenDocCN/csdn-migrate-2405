# Qt5 C++ GUI 编程秘籍（二）

> 原文：[`annas-archive.org/md5/9BC2D959B55E8629DCD159B600A4BD90`](https://annas-archive.org/md5/9BC2D959B55E8629DCD159B600A4BD90)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：OpenGL 实现

在本章中，我们将涵盖以下内容：

+   在 Qt 中设置 OpenGL

+   你好，世界！

+   渲染 2D 形状

+   渲染 3D 形状

+   OpenGL 中的纹理

+   OpenGL 中的光照和纹理滤镜

+   使用键盘控制移动对象

+   QML 中的 3D 画布

# 介绍

在本章中，我们将学习如何使用**开放图形库**（**OpenGL**），这是一个强大的渲染**应用程序编程接口**（**API**），并将其与 Qt 结合使用。OpenGL 是一个跨语言、跨平台的 API，用于通过计算机的图形芯片内的**图形处理单元**（**GPU**）在屏幕上绘制 2D 和 3D 图形。在本章中，我们将学习 OpenGL 2.x 而不是 3.x，因为对于初学者来说，固定功能管线比较新的可编程管线更容易理解。Qt 支持这两个版本，因此一旦您学会了 OpenGL 渲染的基本概念，切换到 OpenGL 3.x 及以上版本就不会有问题。

# 在 Qt 中设置 OpenGL

在这个示例中，我们将学习如何在 Qt 中设置 OpenGL。

## 操作方法…

1.  首先，让我们通过转到**文件** | **新建文件或项目**来创建一个新的 Qt 小部件应用程序。

1.  接下来，我们将删除`mainwindow.ui`文件，因为我们在本示例中不会使用它。右键单击`mainwindow.ui`文件，然后从下拉菜单中选择**删除文件**。然后，将出现一个消息框并要求您确认。选中**永久删除文件**并按**确定**按钮。

1.  之后，打开您的项目文件（`.pro`），并通过在`QT +=`后面添加`opengl`关键字来将 OpenGL 模块添加到您的项目中，如下所示：

```cpp
QT += core gui opengl
```

1.  您还需要在项目文件中添加另一行，以便在启动时加载 OpenGL 和**GLu**（**OpenGL 实用程序**）库。没有这两个库，您的程序将无法运行：

```cpp
LIBS += -lopengl32 -lglu32
```

1.  然后，打开`mainwindow.h`并从中删除一些内容：

```cpp
#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <QMainWindow>

namespace Ui {
  class MainWindow;
}
class MainWindow : public QMainWindow
{
  Q_OBJECT
  public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();
  private:
    Ui::MainWindow *ui;
};
#endif // MAINWINDOW_H
```

1.  接下来，将以下代码添加到您的`mainwindow.h`中：

```cpp
#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include <QOpenGLWindow>

class MainWindow : public QOpenGLWindow
{
  Q_OBJECT
  public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

  protected:
    virtual void initializeGL();
    virtual void resizeGL(int w, int h);
    virtual void paintGL();
    void paintEvent(QPaintEvent *event);
    void resizeEvent(QResizeEvent *event);
};

#endif // MAINWINDOW_H
```

1.  完成后，我们将继续进行源文件，即`mainwindow.cpp`。我们刚刚添加到头文件中的函数，如`initializeGL()`、`resizeGL()`等，现在可以暂时留空；我们将在下一节中使用这些函数：

```cpp
#include "mainwindow.h"
#include "ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent):
  QMainWindow(parent),
  ui(new Ui::MainWindow)
MainWindow::MainWindow(QWidget *parent)
{
  ui->setupUi(this);
  setSurfaceType(QWindow::OpenGLSurface);
}

MainWindow::~MainWindow()
{
  delete ui;
}
void MainWindow::initializeGL()
{
  void MainWindow::resizeGL(int w, int h)
{
}
void MainWindow::paintGL()
{
}
void MainWindow::paintEvent(QPaintEvent *event)
{
}
void MainWindow::resizeEvent(QResizeEvent *event)
{
}
```

1.  最后，通过将以下代码添加到您的`main.cpp`文件中，为主窗口设置标题并将其调整大小为 640x480：

```cpp
#include "mainwindow.h"
#include <QApplication>

int main(int argc, char *argv[])
{
  QApplication a(argc, argv);
  MainWindow w;
  w.setTitle("OpenGL Hello World!");
  w.resize(640, 480);
  w.show();
  return a.exec();
}
```

1.  如果您现在编译并运行项目，您将看到一个带有黑色背景的空窗口。不要担心，您的程序现在正在使用 OpenGL 运行！操作方法…

## 它是如何工作的…

必须在项目文件（`.pro`）中添加 OpenGL 模块，以便访问与 OpenGL 相关的头文件，如 QtOpenGL、QOpenGLFunctions 等。我们使用了`QOpenGLWindow`类而不是`QMainWindow`用于主窗口，因为它被设计为轻松创建执行 OpenGL 渲染的窗口，并且与 QOpenGLWidget 相比具有更好的性能，因为它在其小部件模块中没有依赖项。我们必须调用`setSurfaceType(QWindow::OpenGLSurface)`来告诉 Qt 我们更喜欢使用 OpenGL 来将图像渲染到屏幕上，而不是使用 QPainter。`QOpenGLWindow`类为我们提供了几个虚拟函数（`initializeGL()`、`resizeGL()`、`paintGL()`等），方便我们设置 OpenGL 并执行图形渲染。

## 还有更多…

OpenGL 是一个跨语言、跨平台的 API，用于通过计算机的图形芯片内的**图形处理单元**（**GPU**）在屏幕上绘制 2D 和 3D 图形。

计算机图形技术多年来发展迅速，以至于软件行业几乎无法跟上其步伐。2008 年，维护和开发 OpenGL 的 Khronos Group 公司宣布发布 OpenGL 3.0 规范，这在整个行业中引起了巨大的轰动和争议。这主要是因为 OpenGL 3.0 应该废弃 OpenGL API 中的整个固定功能流水线，对于大公司来说，从固定功能流水线一夜之间转换为可编程流水线是不可能的任务。这导致 Khronos Group 同时维护两个不同的 OpenGL 主要版本，即 OpenGL 2.x 和 3.x。

在本章中，我们将学习 OpenGL 2.x 而不是 3.x，因为对于初学者来说，固定功能流水线比可编程流水线更容易理解。对于学习计算机图形编程的基础知识来说，这是非常直接和不容易混淆的。Qt 支持这两个版本，因此一旦学会了 OpenGL 渲染的基本概念，切换到 OpenGL 3.x（及以上版本）应该没有问题。

Qt 在适当时候内部使用 OpenGL。此外，新的 Qt Quick 2 渲染器基于 OpenGL，现在是 Qt 图形提供的核心部分。这使得 OpenGL 与 Qt 的兼容性比其他任何图形 API（如 DirectX）都更好。

# 你好世界！

在这个示例中，我们将学习 OpenGL 的流水线以及如何将简单的形状渲染到窗口中。我们将继续使用上一个示例项目中的示例。

## 操作步骤…

1.  首先，转到`mainwindow.h`并在源代码顶部添加以下头文件：

```cpp
#include <QSurfaceFormat>
#include <QOpenGLFunctions>
#include <QtOpenGL>
#include <GL/glu.h>
```

1.  接下来，在`mainwindow.h`中声明两个私有变量：

```cpp
private:
  QOpenGLContext* context;
  QOpenGLFunctions* openGLFunctions;
```

1.  之后，转到`mainwindow.cpp`并将表面格式设置为兼容性配置文件。我们还将 OpenGL 版本设置为 2.1，并使用我们刚刚声明的格式创建 OpenGL 上下文。然后，使用我们刚刚创建的上下文来访问仅与我们刚刚设置的 OpenGL 版本相关的 OpenGL 函数，通过调用`context->functions()`：

```cpp
MainWindow::MainWindow(QWidget *parent)
{
 setSurfaceType(QWindow::OpenGLSurface);
 QSurfaceFormat format;
 format.setProfile(QSurfaceFormat::CompatibilityProfile);
 format.setVersion(2, 1); // OpenGL 2.1
 setFormat(format);

 context = new QOpenGLContext;
 context->setFormat(format);
 context->create();
 context->makeCurrent(this);

 openGLFunctions = context->functions();
}
```

1.  接下来，我们将开始向`paintGL()`函数中添加一些代码：

```cpp
void MainWindow::paintGL()
{
 // Initialize clear color (cornflower blue)
 glClearColor(0.39f, 0.58f, 0.93f, 1.f);

 // Clear color buffer
 glClear(GL_COLOR_BUFFER_BIT);

 // Render quad
 glBegin(GL_QUADS);
 glVertex2f(-0.5f, -0.5f);
 glVertex2f(0.5f, -0.5f);
 glVertex2f(0.5f, 0.5f);
 glVertex2f(-0.5f, 0.5f);
 glEnd();

 glFlush();
}
```

1.  在`paintEvent()`函数中调用`paintGL()`之前，屏幕上不会出现任何内容：

```cpp
void MainWindow::paintEvent(QPaintEvent *event)
{
 paintGL();
}
```

1.  如果现在编译并运行项目，您应该能够看到一个白色矩形在蓝色背景前被绘制出来：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_04_02.jpg)

## 工作原理…

我们必须将 OpenGL 版本设置为 2.1，并将表面格式设置为兼容性配置文件，以便访问在较新版本中不再存在的固定功能流水线。或者，如果要使用 OpenGL 3.x 及以上版本，可以将表面格式设置为`QSurfaceFormat::CoreProfile`。

我们调用了`glClearColor()`和`glClear(GL_COLOR_BUFFER_BIT)`来清除先前的`渲染缓冲区`（或者通俗地说，上一个帧），并用我们提供的颜色填充整个画布。在渲染图像后，我们将重复这一步骤，以便在进行下一帧之前清除整个屏幕。我们调用了`glBegin(GL_QUAD)`来告诉 OpenGL 我们将在屏幕上绘制一个四边形。之后，我们向 OpenGL 提供了所有顶点（或点）的位置，以便它知道如何将四边形放置在屏幕上，通过四次调用`glVertex2f()`，因为四边形只能通过连接四个不同的点来构造。然后，我们调用了`glEnd()`来告诉 OpenGL 我们已经完成了四边形。

在完成屏幕上的图像绘制后，始终调用`glFlush()`，以便 OpenGL 清除内存中的所有不需要的信息，为下一次绘制腾出空间。

最后，在`paintEvent()`函数中必须调用`paintGL()`，否则屏幕上将什么都不会被绘制。就像我们在前几章中学到的那样，所有的绘图都发生在`paintEvent()`函数中，只有在 Qt 认为有必要刷新屏幕时才会调用它。要强制 Qt 更新屏幕，需要手动调用`update()`。

# 渲染 2D 形状

由于我们已经学会了如何在屏幕上绘制第一个矩形，我们将在本节中进一步增强它。我们将采用前面的例子，并从那里继续。

## 如何做...

1.  首先，转到`mainwindow.cpp`中的`paintGL()`函数，并用新代码替换上一个示例中的四边形。这次，我们画了一个四边形和一个三角形：

```cpp
void MainWindow::paintGL()
{
  // Initialize clear color (cornflower blue)
  glClearColor(0.39f, 0.58f, 0.93f, 1.f);

  // Clear color buffer
  glClear(GL_COLOR_BUFFER_BIT);

 glBegin(GL_QUADS);
 glVertex2f(-0.5f, -0.5f);
 glVertex2f(0.5f, -0.5f);
 glVertex2f(0.5f, 0.5f);
 glVertex2f(-0.5f, 0.5f);
 glEnd();

 glBegin(GL_QUADS);
 glColor3f(1.f, 0.f, 0.f); glVertex2f(-0.8f, -0.8f);
 glColor3f(1.f, 1.f, 0.f); glVertex2f(0.3f, -0.8f);
 glColor3f(0.f, 1.f, 0.f); glVertex2f(0.3f, 0.3f);
 glColor3f(0.f, 0.f, 1.f); glVertex2f(-0.8f, 0.3f);
 glEnd();

 glBegin(GL_TRIANGLES);
 glColor3f(1.f, 0.f, 0.f); glVertex2f(-0.4f, -0.4f);
 glColor3f(0.f, 1.f, 0.f); glVertex2f(0.8f, -0.1f);
 glColor3f(0.f, 0.f, 1.f); glVertex2f(-0.1f, 0.8f);
 glEnd();

  glFlush();
}
```

1.  接下来，在`resizeGL()`函数中，添加以下代码来调整视口和正交视图，以便渲染的图像正确地遵循窗口的纵横比：

```cpp
void MainWindow::resizeGL(int w, int h)
{
  // Initialize Projection Matrix
  glMatrixMode(GL_PROJECTION);
  glLoadIdentity();

  glViewport(0, 0, w, h);

  qreal aspectRatio = qreal(w) / qreal(h);
  glOrtho(-1 * aspectRatio, 1 * aspectRatio, -1, 1, 1, -1);
}
```

1.  然后，在`resizeEvent()`函数中，调用`resize()`函数并强制主窗口刷新屏幕：

```cpp
void MainWindow::resizeEvent(QResizeEvent *event)
{
 resizeGL(this->width(), this->height());
 this->update();
}
```

1.  之后，在`initializeGL()`函数中，我们调用`resizeGL()`一次，以便第一个渲染的图像的纵横比是正确的（在任何窗口调整大小事件触发之前）：

```cpp
void MainWindow::initializeGL()
{
 resizeGL(this->width(), this->height());
}
```

1.  完成后，编译并运行程序。你应该会看到类似这样的东西：![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_04_03.jpg)

## 工作原理...

OpenGL 支持的几何基元类型包括点、线、线条、线环、多边形、四边形、四边形条带、三角形、三角形条带和三角形扇形。在这个例子中，我们画了一个四边形和一个三角形，每个形状都提供了一组顶点和颜色，以便 OpenGL 知道如何渲染形状。彩虹色是通过给每个顶点赋予不同的颜色来创建的。OpenGL 会自动在每个顶点之间插值颜色并在屏幕上显示。稍后渲染的形状将始终出现在其他形状的前面。在这种情况下，三角形稍后被渲染，因此它出现在矩形的前面。

我们需要在每次调整大小时计算主窗口的纵横比，以便渲染的图像不会被拉伸，导致奇怪的外观。在调用`glViewport()`和`glOrtho()`之前，始终通过调用`glMatrixMode()`和`glLoadIdentity()`重置投影矩阵，以便在调整主窗口大小时正确渲染形状。如果不重置投影矩阵，我们将使用上一帧的矩阵，从而产生错误的投影。

### 注意

记得在调整窗口大小时调用`update()`，否则屏幕将不会更新。

# 渲染 3D 形状

在上一节中，我们已经学会了如何在屏幕上绘制简单的 2D 形状。然而，为了充分利用 OpenGL API，我们还需要学习如何使用它来渲染 3D 图像。简而言之，3D 图像只是使用堆叠的 2D 形状创建的一种幻觉，使它们看起来像 3D。

这里的主要成分是深度值，它决定了哪些形状应该出现在其他形状的前面或后面。位于另一个表面后面（深度比另一个形状浅）的基本形状将不会被渲染（或部分渲染）。OpenGL 提供了一种简单的方法来实现这一点，而不需要太多的技术麻烦。

## 如何做...

1.  首先，在你的`mainwindow.h`中添加`QTimer`头文件：

```cpp
#include <QTimer>
```

1.  然后，在你的`MainWindow`类中添加一个私有变量：

```cpp
private:
  QOpenGLContext* context;
  QOpenGLFunctions* openGLFunctions;
 float rotation;

```

1.  我们还在`mainwindow.h`中添加了一个公共槽，以备后用：

```cpp
public slots:
  void updateAnimation();
```

1.  之后，在`mainwindow.cpp`的`initializeGL()`函数中添加`glEnable(GL_DEPTH_TEST)`以启用深度测试：

```cpp
void MainWindow::initializeGL()
{
 //  Enable Z-buffer depth test
 glEnable(GL_DEPTH_TEST);
  resizeGL(this->width(), this->height());
}
```

1.  接下来，我们将修改`resizeGL()`函数，以便使用透视视图而不是正交视图：

```cpp
void MainWindow::resizeGL(int w, int h)
{
  // Set the viewport
  glViewport(0, 0, w, h);
  qreal aspectRatio = qreal(w) / qreal(h);

  // Initialize Projection Matrix
  glMatrixMode(GL_PROJECTION);
  glLoadIdentity();

 glOrtho(-1 * aspectRatio, 1 * aspectRatio, -1, 1, 1, -1);
 gluPerspective(75, aspectRatio, 0.1, 400000000);

 // Initialize Modelview Matrix
 glMatrixMode(GL_MODELVIEW);
 glLoadIdentity();
}
```

1.  之后，我们还需要修改`paintGL()`函数。首先，将`GL_DEPTH_BUFFER_BIT`添加到`glClear()`函数中，因为我们还需要清除上一帧的深度信息，然后再渲染下一帧。然后，删除我们在之前示例中使用的代码，该代码在屏幕上渲染了一个四边形和一个三角形：

```cpp
void MainWindow::paintGL()
{
  // Initialize clear color (cornflower blue)
  glClearColor(0.39f, 0.58f, 0.93f, 1.f);

 // Clear color buffer
 glClear(GL_COLOR_BUFFER_BIT);
 glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);

 glBegin(GL_QUADS);
 glColor3f(1.f, 0.f, 0.f); glVertex2f(-0.8f, -0.8f);
 glColor3f(1.f, 1.f, 0.f); glVertex2f(0.3f, -0.8f);
 glColor3f(0.f, 1.f, 0.f); glVertex2f(0.3f, 0.3f);
 glColor3f(0.f, 0.f, 1.f); glVertex2f(-0.8f, 0.3f);
 glEnd();

 glBegin(GL_TRIANGLES);
 glColor3f(1.f, 0.f, 0.f); glVertex2f(-0.4f, -0.4f);
 glColor3f(0.f, 1.f, 0.f); glVertex2f(0.8f, -0.1f);
 glColor3f(0.f, 0.f, 1.f); glVertex2f(-0.1f, 0.8f);
 glEnd();

  glFlush();
}
```

1.  然后，在调用`glFlush()`之前，我们将添加以下代码来绘制一个 3D 立方体：

```cpp
// Reset modelview matrix
glMatrixMode(GL_MODELVIEW);
glLoadIdentity();

// Transformations
glTranslatef(0.0, 0.0, -3.0);
glRotatef(rotation, 1.0, 1.0, 1.0);

// FRONT
glBegin(GL_POLYGON);
  glColor3f(0.0, 0.0, 0.0);
  glVertex3f(0.5, -0.5, -0.5); glVertex3f(0.5, 0.5, -0.5);
  glVertex3f(-0.5, 0.5, -0.5); glVertex3f(-0.5, -0.5, -0.5);
glEnd();

// BACK
glBegin(GL_POLYGON);
  glColor3f(0.0, 1.0, 0.0);
  glVertex3f(0.5, -0.5, 0.5); glVertex3f(0.5, 0.5, 0.5);
  glVertex3f(-0.5, 0.5, 0.5); glVertex3f(-0.5, -0.5, 0.5);
glEnd();

// RIGHT
glBegin(GL_POLYGON);
  glColor3f(1.0, 0.0, 1.0);
  glVertex3f(0.5, -0.5, -0.5); glVertex3f(0.5, 0.5, -0.5);
  glVertex3f(0.5, 0.5, 0.5); glVertex3f(0.5, -0.5, 0.5);
glEnd();

// LEFT
glBegin(GL_POLYGON);
  glColor3f(1.0, 1.0, 0.0);
  glVertex3f(-0.5, -0.5, 0.5); glVertex3f(-0.5, 0.5, 0.5);
  glVertex3f(-0.5, 0.5, -0.5); glVertex3f(-0.5, -0.5, -0.5);
glEnd();

// TOP
glBegin(GL_POLYGON);
  glColor3f(0.0, 0.0, 1.0);
  glVertex3f(0.5, 0.5, 0.5); glVertex3f(0.5, 0.5, -0.5);
  glVertex3f(-0.5, 0.5, -0.5); glVertex3f(-0.5, 0.5, 0.5);
glEnd();

// BOTTOM
glBegin(GL_POLYGON);
  glColor3f(1.0, 0.0, 0.0);
  glVertex3f(0.5, -0.5, -0.5); glVertex3f(0.5, -0.5, 0.5);
  glVertex3f(-0.5, -0.5, 0.5); glVertex3f(-0.5, -0.5, -0.5);
glEnd();
```

1.  完成后，向`MainWindow`类的构造函数中添加一个定时器，如下所示：

```cpp
MainWindow::MainWindow(QWidget *parent)
{
  setSurfaceType(QWindow::OpenGLSurface);
  QSurfaceFormat format;
  format.setProfile(QSurfaceFormat::CompatibilityProfile);
  format.setVersion(2, 1); // OpenGL 2.1
  setFormat(format);

  context = new QOpenGLContext;
  context->setFormat(format);
  context->create();
  context->makeCurrent(this);

  openGLFunctions = context->functions();

 QTimer *timer = new QTimer(this);
 connect(timer, SIGNAL(timeout()), this, SLOT(updateAnimation()));
 timer->start(100);

 rotation = 0;
}
```

1.  最后，每当定时器调用`updateAnimation()`槽时，我们将旋转变量增加 10。我们还手动调用`update()`函数来更新屏幕：

```cpp
void MainWindow::updateAnimation()
{
  rotation += 10;
  this->update();
}
```

1.  如果现在编译并运行程序，您应该会在主窗口中看到一个旋转的立方体！如何做...

## 它是如何工作的...

在任何 3D 渲染中，深度非常重要，因此我们需要通过调用`glEnable(GL_DEPTH_TEST)`在 OpenGL 中启用深度测试功能。当我们清除缓冲区时，我们还必须指定`GL_DEPH_BUFFER_BIT`，以便深度信息也被清除，以便下一幅图像能够正确渲染。

我们使用`gluPerspective()`来设置透视投影矩阵，以便图形看起来具有深度和距离。透视视图的相反是正交视图，这是 OpenGL 中的默认视图，我们在之前的示例中使用过。正交投影是一种平行投影，其中物体看起来是平的，不具有深度和距离的概念：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_04_05.jpg)

在这个例子中，我们使用了一个定时器，每 100 毫秒（0.1 秒）增加旋转值 10。然后在将顶点数据提供给 OpenGL 之前，通过调用`glRotatef()`将旋转值应用于立方体。我们还调用了`glTranslatef()`将立方体稍微向后移动，以便它不会太靠近相机视图。

记得手动调用`update()`，以便屏幕得到刷新，否则立方体将不会被动画化。

# OpenGL 中的纹理

OpenGL 允许我们将图像（也称为纹理）映射到 3D 形状或多边形上。这个过程也被称为纹理映射。在这种情况下，Qt 似乎是与 OpenGL 最佳组合，因为它提供了一种简单的方式来加载属于常见格式（BMP、JPEG、PNG、TARGA、TIFF 等）的图像，而不需要自己实现。我们将使用旋转立方体的先前示例，并尝试将其与纹理映射！

## 如何做...

1.  首先，打开`mainwindow.h`并将以下标题添加到其中：

```cpp
#include <QGLWidget>
```

1.  接下来，声明一个数组，用于存储由 OpenGL 创建的纹理 ID。在渲染时我们将使用它：

```cpp
private:
  QOpenGLContext* context;
  QOpenGLFunctions* openGLFunctions;

  float rotation;
 GLuint texID[1];

```

1.  之后，打开`mainwindow.cpp`并将以下代码添加到`initializeGL()`中以加载纹理文件：

```cpp
void MainWindow::initializeGL()
{
  // Enable Z-buffer depth test
  glEnable(GL_DEPTH_TEST);

 // Enable texturing
 glEnable(GL_TEXTURE_2D);

 QImage image("bricks");
 QImage texture = QGLWidget::convertToGLFormat(image);

 glGenTextures(1, &texID[0]);
 glBindTexture(GL_TEXTURE_2D, texID[0]);

 glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
 glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);

 glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, texture.width(), texture.height(), 0, GL_RGBA, GL_UNSIGNED_BYTE, texture.bits());

  // Make sure render at the correct aspect ratio
  resizeGL(this->width(), this->height());
}
```

1.  然后，将以下代码添加到`paintGL()`函数中，将纹理应用到 3D 立方体上：

```cpp
glEnable(GL_TEXTURE_2D);
glBindTexture(GL_TEXTURE_2D, texID[0]);

// FRONT
glBegin(GL_POLYGON);
  glColor3f(0.0, 0.0, 0.0);
  glTexCoord2f(0.0f, 0.0f); glVertex3f(0.5, -0.5, -0.5);
  glTexCoord2f(1.0f, 0.0f); glVertex3f(0.5, 0.5, -0.5);
  glTexCoord2f(1.0f, 1.0f); glVertex3f(-0.5, 0.5, -0.5);
  glTexCoord2f(0.0f, 1.0f); glVertex3f(-0.5, -0.5, -0.5);
glEnd();

// BACK
glBegin(GL_POLYGON);
  glColor3f(0.0, 1.0, 0.0);
  glTexCoord2f(1.0f, 0.0f); glVertex3f(0.5, -0.5, 0.5);
  glTexCoord2f(1.0f, 1.0f); glVertex3f(0.5, 0.5, 0.5);
  glTexCoord2f(0.0f, 1.0f); glVertex3f(-0.5, 0.5, 0.5);
  glTexCoord2f(0.0f, 0.0f); glVertex3f(-0.5, -0.5, 0.5);
glEnd();

// RIGHT
glBegin(GL_POLYGON);
  glColor3f(1.0, 0.0, 1.0);
  glTexCoord2f(0.0f, 1.0f); glVertex3f(0.5, -0.5, -0.5);
  glTexCoord2f(0.0f, 0.0f); glVertex3f(0.5, 0.5, -0.5);
  glTexCoord2f(1.0f, 0.0f); glVertex3f(0.5, 0.5, 0.5);
  glTexCoord2f(1.0f, 1.0f); glVertex3f(0.5, -0.5, 0.5);
glEnd();

// LEFT
glBegin(GL_POLYGON);
  glColor3f(1.0, 1.0, 0.0);
  glTexCoord2f(1.0f, 1.0f); glVertex3f(-0.5, -0.5, 0.5);
  glTexCoord2f(0.0f, 1.0f); glVertex3f(-0.5, 0.5, 0.5);
  glTexCoord2f(0.0f, 0.0f); glVertex3f(-0.5, 0.5, -0.5);
  glTexCoord2f(1.0f, 0.0f); glVertex3f(-0.5, -0.5, -0.5);
glEnd();

// TOP
glBegin(GL_POLYGON);
  glColor3f(0.0, 0.0, 1.0);
  glTexCoord2f(1.0f, 0.0f); glVertex3f(0.5, 0.5, 0.5);
  glTexCoord2f(1.0f, 1.0f); glVertex3f(0.5, 0.5, -0.5);
  glTexCoord2f(0.0f, 1.0f); glVertex3f(-0.5, 0.5, -0.5);
  glTexCoord2f(0.0f, 0.0f); glVertex3f(-0.5, 0.5, 0.5);
glEnd();

// Red side - BOTTOM
glBegin(GL_POLYGON);
  glColor3f(1.0, 0.0, 0.0);
  glTexCoord2f(0.0f, 0.0f); glVertex3f( 0.5, -0.5, -0.5);
  glTexCoord2f(1.0f, 0.0f); glVertex3f( 0.5, -0.5, 0.5);
  glTexCoord2f(1.0f, 1.0f); glVertex3f(-0.5, -0.5, 0.5);
  glTexCoord2f(0.0f, 1.0f); glVertex3f(-0.5, -0.5, -0.5);
glEnd();

glDisable(GL_TEXTURE_2D);
```

1.  如果现在编译并运行程序，您应该会看到一个围绕屏幕旋转的砖块立方体！如何做...

## 它是如何工作的...

变量`GLuint texID[1]`是一个数组，用于存储由 OpenGL 在我们调用`glGenTexture()`时生成的纹理 ID，OpenGL 在渲染期间使用它来从内存中分配纹理。在这种情况下，我们将数组的大小设置为`1`，因为在这个示例中我们只使用一个纹理。我们必须告诉 OpenGL 通过调用`glEnable(GL_TEXTURE_2D)`来启用纹理处理，然后再进行与纹理相关的任何操作。我们使用了两个`QImage`类来加载纹理，第一个称为`image`用于加载图像文件，第二个称为`texture`用于将图像转换为 OpenGL 兼容格式。然后我们调用`glGenTextures()`使用 OpenGL 生成一个空纹理，之后我们调用`glBindTexture()`来选择特定的纹理。这一步是必要的，以便之后调用的函数将应用于我们刚刚选择的纹理。

接下来，我们调用了两次`glTexParameteri()`来将纹理缩小和纹理放大设置为点采样。这将告诉 OpenGL 纹理应该如何渲染。之后，我们调用了`glTexImage2D()`来提供由 Qt 加载的纹理文件中的像素信息到我们刚刚创建的空 OpenGL 纹理中。在开始渲染 3D 立方体之前，调用`glEnabled(GL_TEXTURE_2D)`和`glBindTexture()`来启用 OpenGL 中的纹理处理并选择我们想要使用的纹理。然后，在调用`glVertex3f()`之前，我们必须调用`glTexCoord2f()`来告诉 OpenGL 纹理应该如何映射。我们提供纹理的坐标，OpenGL 会为我们解决其余的问题。

完成后，调用`glDisable(GL_TEXTURE_2D)`来禁用纹理处理。

# OpenGL 中的照明和纹理滤镜

在这个示例中，我们将学习如何在 OpenGL 中对我们使用的纹理应用不同类型的滤镜效果，如点采样、双线性插值和三线性插值。

## 如何做...

1.  再次，我们将使用之前的示例，并在旋转的立方体附近添加一个光源。打开`mainwindow.cpp`并将以下代码添加到`initializeGL()`函数中：

```cpp
// Trilinear interpolation
glTexParameterf(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
glTexParameterf(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);

glTexParameteri(GL_TEXTURE_2D, GL_GENERATE_MIPMAP, GL_TRUE);

glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, texture.width(), texture.height(), 0, GL_RGBA, GL_UNSIGNED_BYTE, texture.bits());

// Enable smooth shading
glShadeModel(GL_SMOOTH);

// Lighting
glEnable(GL_LIGHT1);
GLfloat lightAmbient[]= { 0.5f, 0.5f, 0.5f, 1.0f };
GLfloat lightDiffuse[]= { 1.0f, 1.0f, 1.0f, 1.0f };
GLfloat lightPosition[]= { 3.0f, 3.0f, -5.0f, 1.0f };
glLightfv(GL_LIGHT1, GL_AMBIENT, lightAmbient);
glLightfv(GL_LIGHT1, GL_DIFFUSE, lightDiffuse);
glLightfv(GL_LIGHT1, GL_POSITION, lightPosition);

// Make sure render at the correct aspect ratio
resizeGL(this->width(), this->height());
```

1.  接下来，转到`paintGL()`函数并添加以下代码：

```cpp
glEnable(GL_LIGHTING);

// FRONT
glBegin(GL_POLYGON);
  glNormal3f(0.0f, 0.0f, 1.0f);
  glTexCoord2f(0.0f, 0.0f); glVertex3f(0.5, -0.5, -0.5);
  glTexCoord2f(1.0f, 0.0f); glVertex3f(0.5, 0.5, -0.5);
  glTexCoord2f(1.0f, 1.0f); glVertex3f(-0.5, 0.5, -0.5);
  glTexCoord2f(0.0f, 1.0f); glVertex3f(-0.5, -0.5, -0.5);
glEnd();

// BACK
glBegin(GL_POLYGON);
  glNormal3f(0.0f, 0.0f,-1.0f);
  glTexCoord2f(1.0f, 0.0f); glVertex3f(0.5, -0.5, 0.5);
  glTexCoord2f(1.0f, 1.0f); glVertex3f(0.5, 0.5, 0.5);
  glTexCoord2f(0.0f, 1.0f); glVertex3f(-0.5, 0.5, 0.5);
  glTexCoord2f(0.0f, 0.0f); glVertex3f(-0.5, -0.5, 0.5);
glEnd();

// RIGHT
glBegin(GL_POLYGON);
  glNormal3f(0.0f, 1.0f, 0.0f);
  glTexCoord2f(0.0f, 1.0f); glVertex3f(0.5, -0.5, -0.5);
  glTexCoord2f(0.0f, 0.0f); glVertex3f(0.5, 0.5, -0.5);
  glTexCoord2f(1.0f, 0.0f); glVertex3f(0.5, 0.5, 0.5);
  glTexCoord2f(1.0f, 1.0f); glVertex3f(0.5, -0.5, 0.5);
glEnd();

// LEFT
glBegin(GL_POLYGON);
  glNormal3f(0.0f,-1.0f, 0.0f);
  glTexCoord2f(1.0f, 1.0f); glVertex3f(-0.5, -0.5, 0.5);
  glTexCoord2f(0.0f, 1.0f); glVertex3f(-0.5, 0.5, 0.5);
  glTexCoord2f(0.0f, 0.0f); glVertex3f(-0.5, 0.5, -0.5);
  glTexCoord2f(1.0f, 0.0f); glVertex3f(-0.5, -0.5, -0.5);
glEnd();

// TOP
glBegin(GL_POLYGON);
  glNormal3f(1.0f, 0.0f, 0.0f);
  glTexCoord2f(1.0f, 0.0f); glVertex3f(0.5, 0.5, 0.5);
  glTexCoord2f(1.0f, 1.0f); glVertex3f(0.5, 0.5, -0.5);
  glTexCoord2f(0.0f, 1.0f); glVertex3f(-0.5, 0.5, -0.5);
  glTexCoord2f(0.0f, 0.0f);glVertex3f(-0.5, 0.5, 0.5);
glEnd();

// Red side - BOTTOM
glBegin(GL_POLYGON);
  glNormal3f(-1.0f, 0.0f, 0.0f);
  glTexCoord2f(0.0f, 0.0f); glVertex3f(0.5, -0.5, -0.5);
  glTexCoord2f(1.0f, 0.0f); glVertex3f(0.5, -0.5, 0.5);
  glTexCoord2f(1.0f, 1.0f); glVertex3f(-0.5, -0.5, 0.5);
  glTexCoord2f(0.0f, 1.0f); glVertex3f(-0.5, -0.5, -0.5);
glEnd();

glDisable(GL_LIGHTING);
```

1.  如果现在编译并运行程序，您应该看到照明效果的应用！![如何做...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_04_07.jpg)

## 它是如何工作的...

在固定管线中，向场景中添加光源非常容易。首先，我们需要选择 OpenGL 要使用的着色模型。在我们的情况下，我们通过调用`glShaderModel(GL_SMOOTH)`选择了平滑着色模型。或者，您也可以通过调用`glShaderModel(GL_FLAT)`选择平面着色模型：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_04_08.jpg)

之后，通过调用`glEnable(GL_LIGHT1)`来启用 OpenGL 中的第一个光源。由于固定管线中允许的光源数量有限，光源的名称都是静态的：`GL_LIGHT1`，`GL_LIGHT2`，`GL_LIGHT3`等等。接下来，我们创建了三个数组，用于存储环境光的颜色、漫射光的颜色和漫射光的位置。环境光是环境照明，影响整个场景，没有位置。另一方面，漫射光具有位置和光影响区域。然后，我们通过调用`glLightfv()`函数将这些信息提供给 OpenGL。然后，在`paintGL()`中，在开始渲染立方体之前，我们必须通过调用`glEnable(GL_LIGHTING)`来启用照明。如果没有它，你将看不到应用于立方体的任何照明效果。

除此之外，我们还需要为立方体的每个表面添加一个表面法线值。表面法线指示表面朝向何处，并用于光照计算。完成后，不要忘记通过调用`glDisable(GL_LIGHTING)`来禁用照明。

除了向场景添加光照外，我们还通过调用`glTexParameteri()`将纹理过滤设置为三线性插值，使纹理看起来更加平滑。您还可以尝试其他两种过滤，点过滤和双线性过滤，只需取消注释代码即可。

以下图像显示了三种不同类型的过滤之间的区别：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_04_09.jpg)

双线性和三线性过滤需要 mipmap 才能工作，我们可以通过调用`glTexParameteri(GL_TEXTURE_2D, GL_GENERATE_MIPMAP, GL_TRUE)`来要求 OpenGL 生成。Mipmaps 是预先计算的、优化的纹理序列，每个纹理都是同一图像的逐渐降低分辨率的表示。当远离摄像机移动时，OpenGL 会将物体的纹理切换到分辨率较低的 mipmap，这对于避免视觉伪影非常有效。

## 还有更多…

在 3D 场景中，光照是一个非常重要的方面，它有助于定义物体的 3D 形状。光不仅使面对光的表面变得更亮，而且还使其他被阻挡的表面变暗。

在 OpenGL 中，至少在固定功能管道中，您只能向场景中添加有限数量的灯光。灯光的数量受图形芯片的限制-有些支持多达四个灯光，有些支持多达八个，有些支持多达 16 个。然而，由于固定功能管道正在逐渐被淘汰，人们开始使用可编程管道，这个问题已经得到解决。在可编程管道中，您可以在场景中拥有任意数量的灯光；然而，光照模型将需要完全由您在着色器中编码，这并不是一项容易的任务。

在固定功能管道中，如果要添加的灯光多于图形芯片支持的数量，可以关闭远离摄像机视图的灯光，并只打开靠近摄像机视图的一些灯光。这种方法的缺点是，例如在迷宫中行走时，可能会看到灯光不断闪烁。

# 使用键盘控制移动对象

在本主题中，我们将学习如何使用键盘控制在 OpenGL 中移动对象。Qt 提供了一种简单的方法来检测键盘事件，即使用虚拟函数`keyPressEvent()`和`keyReleaseEvent()`。我们将使用之前的示例并进行扩展。

## 如何做…

1.  打开`mainwindow.h`并声明两个名为`moveX`和`moveZ`的浮点数：

```cpp
private:
  QOpenGLContext* context;
  QOpenGLFunctions* openGLFunctions;

  float rotation;
  GLuint texID[1];

 float moveX;
 float moveZ;

```

1.  之后，声明`keyPressEvent()`函数，如下所示：

```cpp
public:
  explicit MainWindow(QWidget *parent = 0);
  ~MainWindow();

  void keyPressEvent(QKeyEvent *event);

```

1.  然后，打开`mainwindow.cpp`并设置我们刚刚声明的两个变量的默认值：

```cpp
MainWindow::MainWindow(QWidget *parent)
{
  setSurfaceType(QWindow::OpenGLSurface);

  QSurfaceFormat format;
  format.setProfile(QSurfaceFormat::CompatibilityProfile);
  format.setVersion(2, 1); // OpenGL 2.1
  setFormat(format);

  context = new QOpenGLContext;
  context->setFormat(format);
  context->create();
  context->makeCurrent(this);

  openGLFunctions = context->functions();

  QTimer *timer = new QTimer(this);
  connect(timer, SIGNAL(timeout()), this, SLOT(updateAnimation()));
  timer->start(100);

  rotation = 0;

 moveX = 0;
 moveZ = 0;
}
```

1.  接下来，我们将实现`keyPressEvent()`函数：

```cpp
void MainWindow::keyPressEvent(QKeyEvent *event)
{
  if (event->key() == Qt::Key_W)
  {
    moveZ -= 0.2;
  }

  if (event->key() == Qt::Key_S)
  {
    moveZ += 0.2;
  }

  if (event->key() == Qt::Key_A)
  {
    moveX -= 0.2;
  }

  if (event->key() == Qt::Key_D)
  {
    moveX += 0.2;
  }
}
```

1.  之后，在绘制 3D 立方体之前调用`glTranslatef()`，并将`moveX`和`moveZ`都放入函数中。此外，我们禁用了旋转，以便更容易看到移动：

```cpp
// Transformations
glTranslatef(0.0, 0.0, -3.0);
glRotatef(rotation, 1.0, 1.0, 1.0);
glTranslatef(moveX, 0.0, moveZ);

// Texture mapping
glEnable(GL_TEXTURE_2D);
glBindTexture(GL_TEXTURE_2D, texID[0]);

glEnable(GL_LIGHTING);
```

1.  如果现在编译并运行程序，您应该能够通过按*W*、*A*、*S*和*D*来移动立方体：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_04_10.jpg)

## 它是如何工作的...

基本上，我们在这里所做的是在按下键时添加或减去`moveX`和`moveZ`的值。在`keyPressEvent()`中，我们检查键盘按下的按钮是否是*W*、*A*、*S*或*D*。然后，我们相应地从变量中添加或减去 0.2。要获取 Qt 使用的键名称的完整列表，请访问[`doc.qt.io/qt-5/qt.html#Key-enum`](http://doc.qt.io/qt-5/qt.html#Key-enum)。

当我们按住相同的键不放时，Qt 会在一段时间后重复按键事件。键盘输入间隔在不同的操作系统之间有所不同。您可以通过调用`QApplication::setKeyboardInterval()`来设置间隔，但这可能在每个操作系统中都不起作用。我们在绘制立方体之前调用了`glTranslatef(moveX, 0.0, moveZ)`，这会在按下*W*、*A*、*S*或*D*时移动立方体。

# QML 中的 3D 画布

在这个示例中，我们将学习如何使用 Qt 强大的 QML 脚本语言呈现 3D 图像。

## 如何做…

1.  让我们通过在 Qt Creator 中创建一个新项目来开始这个示例。这一次，我们将创建**Qt Canvas 3D 应用程序**，而不是我们在所有先前示例中选择的其他选项：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_04_11.jpg)

1.  之后，Qt Creator 会询问您是否要创建一个基于`three.js`的项目。保持选项选中，然后按**下一步**按钮继续：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_04_12.jpg)

1.  创建项目后，您会注意到一些 JavaScript（`.js`）文件已经添加到项目的资源中。这是正常的，因为 Qt Canvas 3D 应用程序使用 JavaScript 和 WebGL 技术在屏幕上呈现 3D 图像。在这种情况下，它正在运行一个基于 WebGL 的渲染库称为 three.js，这使我们的编程工作与编写纯 WebGL 代码相比更简单和更容易：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_04_13.jpg)

1.  接下来，向我们的项目资源中添加一个图像文件，因为我们将在此示例中使用它。通过在**项目**窗格中右键单击`qml.qrc`，然后选择**在编辑器中打开**，以使用 Qt Creator 打开`qml.qrc`。一旦 Qt Creator 打开了资源文件，点击**添加**按钮，然后点击**添加文件**按钮，然后从计算机中选择要使用的图像文件。在我的情况下，我添加了一个名为`bricks.png`的图像，它将用作我们的 3D 对象的表面纹理：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_04_14.jpg)

1.  之后，使用 Qt Creator 打开`glcode.js`。您会看到文件中已经有大量的代码编写。这基本上是使用`three.js`库在屏幕上渲染一个简单的 3D 立方体。您可以立即构建项目并运行它，看看它的样子。但是，我们将稍微更改代码以自定义其输出。

1.  在`initializeGL（）`函数中，我们将向场景添加一个定向光，加载刚刚添加到项目资源中的纹理文件，然后将纹理应用于定义 3D 立方体表面属性的材质。此外，我们将通过将其在所有维度上的比例设置为`3`，使立方体的比例略微变大：

```cpp
function initializeGL(canvas) {
  scene = new THREE.Scene();
  camera = new THREE.PerspectiveCamera(75, canvas.width / canvas.height, 0.1, 1000);
  camera.position.z = 5;

 var directionalLight = new THREE.DirectionalLight(0xffffff);
 directionalLight.position.set(1, 1, 1).normalize();
 scene.add(directionalLight);

 var texture = THREE.ImageUtils.loadTexture('bricks.jpg');

 var material = new THREE.MeshBasicMaterial({ map: texture });
 var cubeGeometry = new THREE.BoxGeometry(3, 3, 3);
  cube = new THREE.Mesh(cubeGeometry, material);
  cube.rotation.set(0.785, 0.785, 0.0);
  scene.add(cube);

  renderer = new THREE.Canvas3DRenderer(
    { canvas: canvas, antialias: true, devicePixelRatio: canvas.devicePixelRatio });
  renderer.setSize(canvas.width, canvas.height);
}
```

1.  然后，在`paintGL（）`函数中，添加一行额外的代码来在渲染场景之前旋转 3D 立方体：

```cpp
function paintGL(canvas) {
  cube.rotation.y -= 0.005;
  renderer.render(scene, camera);
}
```

1.  我个人觉得窗口大小有点太大，所以我还在`main.qml`文件中更改了窗口的宽度和高度：

```cpp
import QtQuick 2.4
import QtCanvas3D 1.0
import QtQuick.Window 2.2
import "glcode.js" as GLCode

Window {
  title: qsTr("Qt_Canvas_3D")
 width: 480
 height: 320
  visible: true

  Canvas3D {
    id: canvas3d
    anchors.fill: parent
    focus: true

    onInitializeGL: {
      GLCode.initializeGL(canvas3d);
    }

    onPaintGL: {
      GLCode.paintGL(canvas3d);
    }

    onResizeGL: {
      GLCode.resizeGL(canvas3d);
    }
  }
}
```

1.  完成后，让我们构建并运行项目。您应该能够在屏幕上看到一个带有砖纹理的 3D 立方体，缓慢旋转：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_04_15.jpg)

## 工作原理...

最初，`three.js`是一个跨浏览器的 JavaScript 库/ API，它使用 WebGL 技术在 Web 浏览器中显示动画的 3D 计算机图形。然而，Qt Canvas 3D 也使用 Web 技术，特别是 WebGL 技术，来呈现 3D 图像，就像在 Web 浏览器上一样。这意味着不仅`three.js`在 Qt Canvas 3D 上受到支持，而且所有基于 WebGL 技术的不同类型的库都将在 Qt Canvas 3D 上无缝运行。但是，Qt Canvas 3D 仅适用于基于 QML 的项目，不适用于 C ++。

### 注意

如果您有兴趣了解更多关于`three.js`的信息，请访问他们的网站[`threejs.org`](http://threejs.org)。


# 第五章：使用 Qt5 构建触摸屏应用程序

在本章中，我们将涵盖以下内容：

+   为移动应用程序设置 Qt

+   使用 QML 设计基本用户界面

+   触摸事件

+   QML 中的动画

+   使用模型视图显示信息

+   集成 QML 和 C++

# 介绍

Qt 不仅是 PC 平台的跨平台软件开发工具包，还支持 iOS 和 Android 等移动平台。Qt 的开发人员在 2010 年推出了 Qt Quick，它提供了一种简单的方式来构建高度动态的自定义用户界面，用户可以轻松地通过最少的编码创建流畅的过渡和效果。Qt Quick 使用一种称为**QML**的声明性脚本语言，类似于 Web 开发中使用的 JavaScript 语言。高级用户还可以在 C++中创建自定义函数，并将其移植到 Qt Quick 中以增强其功能。目前，Qt Quick 支持 Windows、Linux、Mac、iOS 和 Android 等多个平台。

# 为移动应用程序设置 Qt

在这个例子中，我们将学习如何在 Qt Quick 中设置我们的 Qt 项目，并使其能够构建和导出到移动设备。

## 操作步骤...

1.  首先，让我们通过转到**文件** | **新建文件或新建项目**来创建一个新项目。然后，将弹出一个窗口供您选择项目模板。选择**Qt Quick 应用程序**并单击**选择**按钮：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_01.jpg)

1.  之后，插入项目名称并选择项目位置。单击**下一步**按钮，它将要求您选择项目所需的最低 Qt 版本。请确保选择计算机上存在的版本，否则您将无法正确运行它。完成后，单击**下一步**按钮继续。

1.  然后，Qt Creator 将询问您要为项目使用哪个**工具**。这些“工具”基本上是您可以用来为不同平台编译项目的不同编译器。由于我们正在为移动平台开发应用程序，因此我们将启用 Android 工具（或者如果您使用 Mac，则启用 iOS 工具）以构建和导出应用程序到移动设备。请注意，如果您首次使用 Android 工具，则需要配置它，以便 Qt 可以找到 Android SDK 的目录。完成后，单击**下一步**：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_02.jpg)

1.  创建项目后，Qt Creator 将自动打开项目中的一个文件，名为`main.qml`。您将在屏幕上看到类似于这样的东西，与您通常的 C/C++项目非常不同：

```cpp
import QtQuick 2.3
import QtQuick.Window 2.2

Window {
  visible: true

  MouseArea {
    anchors.fill: parent
    onClicked: {
      Qt.quit();
    }
  }

  Text {
    text: qsTr("Hello World")
    anchors.centerIn: parent
  }
}
```

1.  现在通过单击 Qt Creator 左下角的绿色箭头按钮构建和运行项目。如果将默认工具设置为**桌面**，将弹出一个窗口，看起来像这样：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_03.jpg)

1.  我们可以通过转到**项目**界面并选择要使用的工具来在不同的工具之间切换。您还可以管理计算机上所有可用的工具，或者从**项目**界面向项目添加新的工具：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_04.jpg)

1.  如果这是您第一次构建和运行项目，您需要在**构建**设置下为 Android 工具创建一个模板。一旦单击了**创建模板**按钮，Qt 将生成运行应用程序所需的所有文件。如果您不打算在项目中使用 Gradle，请禁用**将 Gradle 文件复制到 Android 目录**选项。否则，在尝试编译和部署应用程序到移动设备时可能会遇到问题：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_05.jpg)

1.  创建模板后，单击**运行**按钮，现在您应该看到一个弹出窗口，询问应该导出到哪个设备：![操作步骤...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_06.jpg)

1.  选择当前连接到计算机的设备，然后按**确定**按钮。等待一会儿，直到项目构建完成，然后您应该在移动设备上看到类似于这样的东西：![如何操作...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_07.jpg)

## 工作原理...

Qt Quick 应用程序项目与表单应用程序项目有很大不同。您将大部分时间编写 QML 脚本，而不是编写 C/C++代码。

构建和导出应用程序到 Android 平台需要**Android 软件开发工具包**（**SDK**）、**Android 本机开发工具包**（**NDK**）、**Java 开发工具包**（**JDK**）和**Apache Ant**。或者，您也可以使用 Gradle 代替 Apache Ant 来构建您的 Android 工具包。您只需要启用**使用 Gradle 代替 Ant**选项，并提供 Qt Gradle 的安装路径。请注意，Android Studio 目前不受 Qt Creator 支持：

![工作原理...](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_31.jpg)

如果您在 Android 设备上运行应用程序，请确保已启用 USB 调试模式。要启用 USB 调试模式，您需要先在 Android 设备上启用开发者选项，方法是转到**设置** | **关于手机**，然后点击**版本号**七次。之后，转到**设置** | **开发者选项**，您将在菜单中看到**Android 调试**选项。启用该选项后，您现在可以将应用程序导出到设备进行测试。

要构建 iOS 平台，您需要在 Mac 上运行 Qt Creator，并确保最新的 XCode 也安装在您的 Mac 上。

要在 iOS 设备上测试您的应用程序，您需要在 Apple 注册开发者帐户，在开发者门户注册您的设备，并将配置文件安装到 XCode 中，这比 Android 要棘手得多。一旦您从 Apple 获得了开发者帐户，您将获得访问开发者门户的权限。

# 使用 QML 设计基本用户界面

在这个例子中，我们将学习如何使用 Qt Quick Designer 来设计程序的用户界面。

## 如何操作...

1.  首先，创建一个新的 Qt Quick 应用程序项目，就像我们在之前的示例中所做的那样。如果愿意，您也可以使用之前的项目文件。

1.  您将在项目资源中看到两个 QML 文件——`main.qml`和`MainForm.ui.qml`。前者是我们实现应用程序逻辑的地方，后者是我们设计用户界面的地方。我们将从 UI 设计开始，所以让我们打开`MainForm.ui.qml`。一旦被 Qt Creator 打开，您将看到一个与我们在之前章节中使用的完全不同的 UI 编辑器。这个编辑器称为 Qt Quick Designer，专门用于设计 Qt Quick 项目的 UI。该编辑器的组件描述如下：

+   **库**：**库**窗口显示了您可以添加到 UI 画布的所有预定义的 QML 类型。您还可以从**导入**选项卡导入自定义的 Qt Quick 组件并在此处显示它们。

+   **导航器**：**导航器**窗口以树形结构显示当前 QML 文件中的项目。

+   **连接**：您可以使用**连接**窗口中提供的工具将对象连接到信号，为对象指定动态属性，并在两个对象的属性之间创建绑定。

+   **状态**：**状态**窗口显示了项目的不同状态。您可以通过单击**状态**窗口右侧的**+**按钮为项目添加新状态。

+   **画布**：画布是您设计程序用户界面的地方。您可以从**库**窗口将 Qt Quick 组件拖放到画布上，并立即看到它在程序中的外观。

+   **属性**：这是您更改所选项目属性的地方。

1.  在**导航器**窗口下选择**矩形**对象下的所有内容（**mouseArea**和**Text**）并删除它们。

1.  我们将制作一个简单的登录界面。从**库**窗口中，将两个文本小部件拖放到画布上。

1.  将两个文本小部件的文本属性设置为**用户名：**和**密码：**![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_32.jpg)

1.  从**库**窗口中拖动两个矩形到画布上，然后将两个文本输入小部件拖到画布上，并将它们各自作为父级添加到刚刚添加到画布上的矩形上。将矩形的`border`属性设置为`1`，`radius`设置为`5`。然后，将一个文本字段的`echo mode`设置为`Password`。

1.  现在，我们将通过将鼠标区域小部件与矩形和文本小部件组合来手动创建一个按钮小部件。将鼠标区域小部件拖到画布上，然后将矩形和文本小部件拖到画布上，并将它们都作为父级添加到鼠标区域上。将矩形的颜色设置为`#bdbdbd`，然后将其`border`属性设置为`1`，`radius`设置为`5`。然后，将文本设置为`登录`，并确保鼠标区域的大小与矩形相同。

1.  之后，将另一个矩形拖到画布上，作为登录表单的容器，使其看起来整洁。将其`border color`设置为`#5e5858`，`border`属性设置为`2`。然后，将其`radius`属性设置为`5`，使其角看起来有点圆润。

1.  确保我们在上一步中添加的矩形在**导航器**窗口中的层次结构顶部，以便它出现在所有其他小部件后面。您可以通过按位于**导航器**窗口顶部的箭头按钮来排列层次结构中的小部件位置：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_08.jpg)

1.  接下来，我们将导出三个小部件——鼠标区域和两个文本输入小部件——作为根项目的别名属性，以便以后可以从`main.qml`文件中访问这些小部件。通过单击小部件名称后面的小图标，并确保图标变为**On**状态来导出小部件：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_09.jpg)

1.  到目前为止，您的 UI 应该看起来像这样：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_10.jpg)

1.  现在让我们打开`main.qml`。Qt Creator 默认情况下不会在 Qt Quick Designer 中打开此文件，而是会在脚本编辑器中打开。这是因为所有与 UI 设计相关的任务都是在`MainForm.ui.qml`中完成的，而`main.qml`仅用于定义将应用于 UI 的逻辑和函数。但是，您可以通过单击编辑器左侧边栏上的**Design**按钮，使用 Qt Quick Designer 打开它以预览 UI。

1.  在脚本顶部，添加第三行以导入对话框模块到`main.qml`，如下所示：

```cpp
import QtQuick 2.5
import QtQuick.Window 2.2
import QtQuick.Dialogs 1.2
```

1.  接下来，用以下代码替换下面的代码：

```cpp
Window {
  visible: true
  width: 360
  height: 360

  MainForm {
    anchors.fill: parent
    loginButton.onClicked: {
      messageDialog.text = "Username is " + userInput.text + " and password is " + passInput.text
        messageDialog.visible = true
    }
  }

  MessageDialog {
    id: messageDialog
    title: "Fake login"
    text: ""
    onAccepted: {
      console.log("You have clicked the login button")
      Qt.quit()
    }
  }
}
```

1.  在 PC 上构建并运行此程序，当您单击**登录**按钮时，应该会显示一个消息框的简单程序：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_11.jpg)

## 工作原理…

自 Qt 5.4 以来，引入了一个名为`.ui.qml`的新文件扩展名。QML 引擎处理它就像处理普通的`.qml`文件一样，但禁止在其中编写任何逻辑实现。它用作 UI 定义模板，可以在不同的`.qml`文件中重用。UI 定义和逻辑实现的分离改善了 QML 代码的可维护性，并创建了更好的工作流程。

**Qt Quick - 基本**下的所有小部件都是我们可以使用来混合和匹配并创建新类型小部件的最基本小部件。在前面的示例中，我们学习了如何将三个小部件组合在一起——文本、鼠标区域和矩形，以形成一个按钮小部件。

然而，如果您懒得做，可以通过转到**库**窗口中的**导入**选项卡并单击**<添加导入>**按钮，将预制模块导入到您的 Qt Quick 项目中。然后，从下拉列表中选择要添加到项目中的模块。一旦您在 QML 脚本和 C++编程方面有所进步，还可以创建自己的 Qt Quick 模块：

![工作原理…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_12.jpg)

我们在`main.qml`中导入了`QtQuick.dialogs`模块，并创建了一个消息框，当用户按下**登录**按钮时显示用户填写的用户名和密码，以证明 UI 功能正在工作。如果小部件没有从`MainForm.ui.qml`中导出，我们将无法在`main.qml`中访问其属性。

在这一点上，我们可以将程序导出到 iOS 和 Android，但是在一些具有更高分辨率或更高**每英寸像素密度**（**DPI**）单位的设备上，UI 可能看起来不准确。我们将在本章后面解决这个问题。

# 触摸事件

在这一部分，我们将学习如何使用 Qt Quick 开发在移动设备上运行的触摸驱动应用程序。

## 如何做…

1.  首先，创建一个新的 Qt Quick 应用程序项目。

1.  在 Qt Creator 中，右键单击`qml.qrc`，然后选择**在编辑器中打开**。然后，单击**添加** | **添加文件**，将`tux.png`添加到项目中：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_13.jpg)

1.  接下来，打开`MainForm.ui.qml`。从**库**窗口将图像小部件拖动到画布上。然后，将图像的源设置为`tux.png`，并将其`fillmode`设置为`PreserveAspectFit`。之后，将其`width`设置为`200`，将其`height`设置为`220`。

1.  确保鼠标区域小部件和图像小部件都通过单击其各自的小部件名称旁边的小图标作为根项目的别名属性导出。

1.  在那之后，通过单击编辑器左侧边栏上的**编辑**按钮切换到脚本编辑器。我们需要将鼠标区域小部件更改为多点触摸区域小部件，如下所示：

```cpp
MultiPointTouchArea {
  id: touchArea
  anchors.fill: parent
  touchPoints: [
    TouchPoint { id: point1 },
    TouchPoint { id: point2 }
  ]
}
```

1.  我们还将`Image`小部件设置为默认自动放置在窗口中心：

```cpp
Image {
  id: tux
  x: (window.width / 2) - (tux.width / 2)
  y: (window.height / 2) - (tux.height / 2)
  width: 200
  height: 220
  fillMode: Image.PreserveAspectFit
  source: "tux.png"
}
```

最终的 UI 应该看起来像这样：

![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_14.jpg)

1.  完成后，让我们打开`main.qml`。首先清除`MainForm`对象中除`anchors.fill: parent`之外的所有内容，如下所示：

```cpp
import QtQuick 2.5
import QtQuick.Window 2.2

Window {
  visible: true

  MainForm {
    anchors.fill: parent
  }
}
```

1.  在`MainForm`对象中声明几个变量，这些变量将用于重新调整图像小部件。如果您想了解以下代码中使用的`property`关键字的更多信息，请查看本示例末尾的*还有更多…*部分：

```cpp
property int prevPointX: 0
property int prevPointY: 0
property int curPointX: 0
property int curPointY: 0

property int prevDistX: 0
property int prevDistY: 0
property int curDistX: 0
property int curDistY: 0

property int tuxWidth: tux.width
property int tuxHeight: tux.height
```

1.  接下来，我们将定义当手指触摸多点区域小部件时会发生什么。在这种情况下，如果多个手指触摸到多点触摸区域，我们将保存第一个和第二个触摸点的位置。我们还保存图像小部件的宽度和高度，以便以后可以使用这些变量来计算手指开始移动时图像的比例：

```cpp
touchArea.onPressed:
{
  if (touchArea.touchPoints[1].pressed)
  {
    if (touchArea.touchPoints[1].x < touchArea.touchPoints[0].x)
      prevDistX = touchArea.touchPoints[1].x - touchArea.touchPoints[0].x
    else
      prevDistX = touchArea.touchPoints[0].x - touchArea.touchPoints[1].x

    if (touchArea.touchPoints[1].y < touchArea.touchPoints[0].y)
      prevDistY = touchArea.touchPoints[1].y - touchArea.touchPoints[0].y
    else
      prevDistY = touchArea.touchPoints[0].y - touchArea.touchPoints[1].y

    tuxWidth = tux.width
    tuxHeight = tux.height
  }
}
```

以下图像显示了当两根手指触摸屏幕时，在触摸区域边界内注册的触摸点的示例。`touchArea`.`touchPoints[0]`是第一个注册的触摸点，`touchArea.touchPoints[1]`是第二个。然后我们计算两个触摸点之间的 X 和 Y 距离，并将它们保存为`prevDistX`和`prevDistY`：

![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_15.jpg)

1.  在那之后，我们将定义当我们的手指在屏幕上移动时会发生什么，同时仍然保持与触摸区域的边界接触。在这一点上，我们将使用我们在上一步中保存的变量来计算图像的比例。同时，如果我们检测到只有一个触摸点，那么我们将移动图像而不是改变其比例：

```cpp
touchArea.onUpdated:{
  if (!touchArea.touchPoints[1].pressed)
  {
    tux.x += touchArea.touchPoints[0].x - touchArea.touchPoints[0].previousX
    tux.y += touchArea.touchPoints[0].y - touchArea.touchPoints[0].previousY
  }
  else
  {
    if (touchArea.touchPoints[1].x < touchArea.touchPoints[0].x)
    curDistX = touchArea.touchPoints[1].x - touchArea.touchPoints[0].x
    else
      curDistX = touchArea.touchPoints[0].x - touchArea.touchPoints[1].x

    if (touchArea.touchPoints[1].y < touchArea.touchPoints[0].y)
      curDistY = touchArea.touchPoints[1].y - touchArea.touchPoints[0].y
    else
      curDistY = touchArea.touchPoints[0].y - touchArea.touchPoints[1].y

      tux.width = tuxWidth + prevDistX - curDistX
      tux.height = tuxHeight + prevDistY - curDistY
  }
}
```

以下图像显示了移动触摸点的示例 - `touchArea.touchPoints[0]`从点 A 移动到点 B，而`touchArea.touchPoints[1]`从点 C 移动到点 D。然后，我们可以通过查看先前的 X、Y 变量与当前变量之间的差异来确定触摸点移动了多少单位：

![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_16.jpg)

1.  现在，您可以构建并将程序导出到您的移动设备上。您将无法在不支持多点触摸的平台上测试此程序。一旦程序在支持多点触摸的移动设备（或支持多点触摸的台式机/笔记本电脑）上运行，请尝试两件事：只在屏幕上放一个手指并移动它，以及在屏幕上放两个手指并朝相反方向移动它们。您应该看到的是，如果您只使用一个手指，企鹅将被移动到另一个位置，如果您使用两个手指，它将被放大或缩小：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_33.jpg)

## 它是如何工作的…

当手指触摸设备的屏幕时，多点触摸区域小部件会触发`onPressed`事件，并在内部数组中注册每个触摸点的位置。我们可以通过告诉 Qt 要访问的触摸点来获取这些数据。第一个触摸点将带有索引号`0`，第二个触摸点将是`1`，依此类推。然后，我们将这些数据保存到变量中，以便以后可以检索它们以计算企鹅图像的缩放。

当一个或多个手指在移动时仍然与屏幕保持接触，多点触摸区域将触发`onUpdate`事件。然后，我们将检查触摸点的数量 - 如果只找到一个触摸点，我们将根据手指移动的距离移动企鹅图像。如果有多个触摸点，我们将比较两个触摸点之间的距离，并将其与我们之前保存的变量进行比较，以确定我们应该如何重新调整图像的大小。

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_34.jpg)

我们还必须检查第一个触摸点是否在第二个触摸点的左侧还是右侧。这样我们就可以防止图像在手指移动的反方向上被缩放，并产生不准确的结果。

至于企鹅的移动，我们将只获取当前触摸位置和上一个触摸位置之间的差异，将其添加到企鹅的坐标中，然后完成。单点触摸事件通常比多点触摸事件简单得多，更直接。

## 还有更多…

在 Qt Quick 中，所有组件都具有内置属性，如宽度、高度、颜色等，默认情况下附加到组件上。但是，Qt Quick 还允许您创建自己的自定义属性，并将其附加到您在 QML 脚本中声明的组件上。对象类型的自定义属性可以通过在 QML 文档中的对象声明之前添加`property`关键字来定义，例如：

```cpp
property int myValue;
```

您还可以使用冒号（`:`）将自定义属性绑定到值，如下所示：

```cpp
property int myValue: 100;
```

要了解 Qt Quick 支持的属性类型的更多信息，请查看此链接：[`doc.qt.io/qt-5/qtqml-typesystem-basictypes.html`](http://doc.qt.io/qt-5/qtqml-typesystem-basictypes.html)

# QML 中的动画

Qt 允许我们在不编写大量代码的情况下轻松地为 UI 组件添加动画。在这个例子中，我们将学习如何通过应用动画使我们程序的 UI 更有趣。

## 如何做…

1.  我们将再次从头开始。因此，在 Qt Creator 中创建一个新的 Qt Quick 应用程序项目，并打开`MainForm.ui.qml`。

1.  转到**库**窗口中的**导入**选项卡，并将一个名为**QtQuick.Controls**的 Qt Quick 模块添加到您的项目中。

1.  之后，您将在**QML 类型**选项卡中看到一个名为**Qt Quick - Controls**的新类别，其中包含许多可以放置在画布上的新小部件。

1.  接下来，将三个按钮小部件拖到画布上，并将它们的高度设置为`45`。然后，转到**属性**窗口上的**布局**选项卡，并为所有三个按钮小部件启用左右锚点。确保锚点的目标设置为**父级**，边距保持为`0`。这将使按钮根据主窗口的宽度水平调整大小。之后，将第一个按钮的*y*值设置为`0`，第二个为`45`，第三个为`90`。UI 现在应该是这样的：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_17.jpg)

1.  现在，用编辑器打开`qml.qrc`并将`fan.png`添加到项目中：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_18.jpg)

1.  然后，在画布上添加两个鼠标区域小部件。之后，在画布上拖动一个矩形小部件和一个图像小部件。将矩形和图像作为父级部件添加到我们刚刚添加的鼠标区域上。

1.  将矩形的颜色设置为`#0000ff`，并将`fan.png`应用到图像小部件。您的 UI 现在应该是这样的：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_19.jpg)

1.  然后，通过单击小部件名称右侧的图标，将`MainForm.ui.qml`中的所有小部件导出为根项目的别名属性：

1.  接下来，我们将为 UI 应用动画和逻辑，但我们不会在`MainForm.ui.qml`中进行。相反，我们将在`main.qml`中完成所有操作。

1.  在`main.qml`中，删除鼠标区域的默认代码，并为窗口添加宽度和高度，以便我们有更多的空间进行预览：

```cpp
import QtQuick 2.5
import QtQuick.Window 2.2

Window {
  visible: true
  width: 480
  height: 550

  MainForm {
    anchors.fill: parent
  }
}
```

1.  之后，在`MainForm`小部件中添加定义按钮行为的代码：

```cpp
button1 {
  Behavior on y { SpringAnimation { spring: 2; damping: 0.2 } }

  onClicked: {
    button1.y = button1.y + (45 * 3)
  }
}

button2 {
  Behavior on y { SpringAnimation { spring: 2; damping: 0.2 } }

  onClicked: {
    button2.y = button2.y + (45 * 3)
  }
}

button3 {
  Behavior on y { SpringAnimation { spring: 2; damping: 0.2 } }

  onClicked: {
    button3.y = button3.y + (45 * 3)
  }
}
```

1.  然后，按照`fan`图像和其附加的鼠标区域小部件的行为：

```cpp
fan {
  RotationAnimation on rotation {
    id: anim01
    loops: Animation.Infinite
    from: 0
    to: -360
    duration: 1000
  }
}

mouseArea1 {
  onPressed: {
    if (anim01.paused)
      anim01.resume()
    else
      anim01.pause()
  }
}
```

1.  最后但并非最不重要的是，添加矩形和鼠标区域小部件的行为：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_21.jpg)

1.  如果现在编译并运行程序，您应该会看到窗口顶部有三个按钮，底部左侧有一个移动的矩形，底部右侧有一个旋转的风扇。如果您点击任何按钮，它们将以流畅的动画略微向下移动。如果您点击矩形，它将从蓝色变为红色。同时，如果您在风扇图像正在动画时点击它，它将暂停动画，如果再次点击它，它将恢复动画：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_22.jpg)

## 工作原理

Qt 的 C++版本支持的大多数动画元素，如过渡、顺序动画、并行动画等，在 Qt Quick 中也是可用的。如果您熟悉 C++中的 Qt 动画框架，您应该能够很容易地掌握这个。

在这个例子中，我们为所有三个按钮添加了一个弹簧动画元素，它专门跟踪它们各自的*y*轴。如果 Qt 检测到*y*值已经改变，小部件将不会立即跳到新位置，而是进行插值运算，沿着画布移动，并在到达目的地时执行一些摇晃动画，模拟弹簧效果。我们只需写一行代码，剩下的交给 Qt 处理。

至于风扇图像，我们为其添加了旋转动画元素，并将`持续时间`设置为`1000`毫秒，这意味着它将在一秒内完成一次完整的旋转。我们还设置它循环播放动画。当我们点击它附加的鼠标区域小部件时，我们只需调用`pause()`或`resume()`来启用或禁用动画。

接下来，对于矩形小部件，我们为其添加了两个状态，一个称为`BLUE`，一个称为`RED`，每个状态都带有一个在状态改变时将应用于矩形的`颜色`属性。同时，我们为矩形附加的鼠标区域小部件添加了一个顺序动画组，并向组中添加了两个属性动画元素。您还可以混合不同类型的组动画；Qt 可以很好地处理这一点。

# 使用模型视图显示信息

Qt 包括一个模型视图框架，它保持数据组织和管理方式与向用户呈现方式之间的分离。在本节中，我们将学习如何利用模型视图，特别是通过使用列表视图来显示信息，并同时应用我们自己的定制使其看起来漂亮。

## 操作步骤…

1.  创建一个新的 Qt Quick 应用程序项目，并用 Qt Creator 打开`qml.qrc`。将六个图像`home.png`、`map.png`、`profile.png`、`search.png`、`settings.png`和`arrow.png`添加到项目中：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_35.jpg)

1.  之后，打开`MainForm.ui.qml`。删除画布上的所有默认小部件，并从库窗口的**Qt Quick - Views**类别下拖动一个**列表视图**小部件到画布上。然后，通过单击**布局**窗口中间的按钮，将其**锚点**设置为**填充父级大小**：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_23.jpg)

1.  接下来，切换到脚本编辑器，因为我们将定义列表视图的外观：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_24.jpg)![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_36.jpg)

1.  之后，打开`main.qml`并用以下代码替换原代码：

```cpp
import QtQuick 2.4
import QtQuick.Window 2.2

Window {
  visible: true
  width: 480
  height: 480

  MainForm {
    anchors.fill: parent

    MouseArea {
      onPressed: row1.opacity = 0.5
      onReleased: row1.opacity = 1.0
    }
  }
}
```

1.  构建并运行程序，现在您的程序应该是这个样子：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_25.jpg)

## 工作原理…

Qt Quick 允许我们轻松定制列表视图的每一行外观。`delegate`定义了每一行的外观，而`model`是您存储在列表视图上显示的数据的地方。

在这个例子中，我们在每一行上添加了一个渐变的背景，然后我们还在项目的两侧添加了一个图标、一个标题、一个描述，以及一个鼠标区域小部件，使列表视图的每一行都可以点击。委托是不静态的，因为我们允许模型更改标题、描述和图标，使每一行看起来都是独特的。

在`main.qml`中，我们定义了鼠标区域小部件的行为，当按下时，它的不透明度值会降低一半，释放时会恢复完全不透明。由于所有其他元素，如标题、图标等，都是鼠标区域小部件的子元素，它们也会自动遵循其父小部件的行为，并变得半透明。

此外，我们终于解决了移动设备高分辨率和 DPI 显示问题。这是一个非常简单的技巧——首先，我们定义了一个名为`sizeMultiplier`的变量。`sizeMultiplier`的值是将窗口宽度除以预定义值（例如`480`）的结果，这是我们用于 PC 的当前窗口宽度。然后，将`sizeMultiplier`乘以所有与大小和位置有关的小部件变量，包括字体大小。请注意，在这种情况下，应该使用文本的`pixelSize`属性而不是`pointSize`，这样当乘以`sizeMultiplier`时，您将获得正确的显示。以下截图显示了在移动设备上使用和不使用`sizeMultiplier`时应用的样子：

![工作原理…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_26.jpg)

请注意，一旦您用`sizeMultiplier`变量乘以所有东西，您可能会在编辑器中得到一个混乱的 UI。这是因为编辑器中的`width`变量可能返回为`0`。因此，将`0`乘以`480`，您可能会得到结果`0`，这会使整个 UI 看起来很滑稽。然而，在运行实际程序时，它会看起来很好。如果您想在编辑器中预览 UI，请将`sizeMultiplier`临时设置为`1`。

# 集成 QML 和 C++

Qt 支持在 C++类和 QML 引擎之间进行桥接。这种组合允许开发人员充分利用 QML 的简单性和 C++的灵活性。您甚至可以集成来自外部库的 Qt 不支持的功能，然后将生成的数据传递给 Qt Quick 以在 UI 中显示。在这个例子中，我们将学习如何将我们的 UI 组件从 QML 导出到 C++框架，并在显示在屏幕上之前操纵它们的属性。

## 如何做…

1.  我们将再次从头开始。因此，在 Qt Creator 中创建一个新的 Qt Quick 应用程序项目，并打开`MainForm.ui.qml`。

1.  我们可以保留鼠标区域和文本小部件，但将文本小部件放在窗口底部。将文本小部件的**文本**属性更改为**使用 C++更改此文本**，并将其字体大小设置为`18`。之后，转到**布局**选项卡，并启用**垂直中心锚点**和**水平中心锚点**，以确保它始终位于窗口中间的某个位置，无论如何重新调整窗口。将**垂直中心锚点**的**边距**设置为`120`：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_27.jpg)

1.  接下来，从**库**窗口将**Rectangle**小部件拖动到画布上，并将其颜色设置为`#ff0d0d`。将其**宽度**和**高度**设置为`200`，并启用垂直和水平中心锚点。之后，将水平中心锚点的**边距**设置为`-14`。您的 UI 现在应该看起来像这样：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_28.jpg)

1.  完成后，在 Qt Creator 中右键单击项目目录，然后选择**添加新内容**。然后，将弹出一个窗口，让您选择文件模板。选择**C++类**并按**选择…**。之后，它将要求您填写类的信息来定义 C++类。在这种情况下，在**类名**字段中插入**MyClass**，并选择**QObject**作为**基类**。然后，确保**包括 QObject**选项已被选中，现在可以单击**下一步**按钮，然后单击**完成**按钮。现在将创建并添加两个文件—`myclass.h`和`myclass.cpp`—到您的项目中：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_29.jpg)

1.  现在，打开`myclass.h`并在类构造函数下方添加变量和函数，如下所示：

```cpp
#ifndef MYCLASS_H
#define MYCLASS_H
#include <QObject>

class MyClass : public QObject
{
  Q_OBJECT
  public:
    explicit MyClass(QObject *parent = 0);

    // Object pointer
    QObject* myObject;

    // Must call Q_INVOKABLE so that this function can be used in QML
    Q_INVOKABLE void setMyObject(QObject* obj);

  signals:

  public slots:
};

#endif // MYCLASS_H
```

1.  之后，打开`myclass.cpp`并定义`setMyObject()`函数：

```cpp
#include "myclass.h"

MyClass::MyClass(QObject *parent) : QObject(parent)
{
}

void MyClass::setMyObject(QObject* obj)
{
  // Set the object pointer
  myObject = obj;
}
```

1.  现在可以关闭`myclass.cpp`并打开`main.qml`。在文件顶部添加第三行，导入我们刚在 C++中创建的自定义库：

```cpp
import QtQuick 2.4
import QtQuick.Window 2.2
import MyClassLib 1.0
```

1.  然后，在`Window`对象中定义`MyClass`并在`MainForm`对象中调用其函数`setMyObject()`，如下所示：

```cpp
Window {
  visible: true
  width: 480
  height: 320

  MyClass
  {
    id: myclass
  }

  MainForm {
    anchors.fill: parent
    mouseArea.onClicked: {
      Qt.quit();
    }
    Component.onCompleted:       myclass.setMyObject(messageText);
  }
}
```

1.  最后，打开`main.cpp`并将自定义类注册到 QML 引擎。我们还在这里使用 C++代码更改文本小部件和矩形的属性：

```cpp
#include <QGuiApplication>
#include <QQmlApplicationEngine>
#include <QtQml>
#include <QQuickView>
#include <QQuickItem>
#include <QQuickView>
#include "myclass.h"

int main(int argc, char *argv[])
{
  // Register your class to QML
  qmlRegisterType<MyClass>("MyClassLib", 1, 0, "MyClass");

  QGuiApplication app(argc, argv);

  QQmlApplicationEngine engine;
  engine.load(QUrl(QStringLiteral("qrc:/main.qml")));

  QObject* root = engine.rootObjects().value(0);

  QObject* messageText =     root->findChild<QObject*>("messageText");
  messageText->setProperty("text", QVariant("C++ is now in     control!"));
  messageText->setProperty("color", QVariant("green"));

  QObject* square = root->findChild<QObject*>("square");
  square->setProperty("color", QVariant("blue"));

  return app.exec();
}
```

1.  现在构建和运行程序，您应该看到矩形和文本的颜色与您在 Qt Quick 中定义的完全不同。这是因为它们的属性已被 C++代码更改：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_05_30.jpg)

## 它是如何工作的…

QML 旨在通过 C++代码轻松扩展。Qt QML 模块中的类使 QML 对象可以从 C++中加载和操作。

只有从`QObject`基类继承的类才能与 QML 集成，因为它是 Qt 生态系统的一部分。一旦类已经在 QML 引擎中注册，我们就可以从 QML 引擎获取根项目，并使用它来查找我们想要操作的对象。之后，使用`setProperty()`函数来更改小部件的任何属性。

请注意，`Q_INVOKABLE`宏在您打算在 QML 中调用的函数前是必需的。没有它，Qt 不会将函数暴露给 Qt Quick，您将无法调用它。


# 第六章：XML 解析变得容易

在本章中，我们将涵盖以下内容：

+   使用流读取器处理 XML 数据

+   使用流写入器写入 XML 数据

+   使用 QDomDocument 类处理 XML 数据

+   使用 QDomDocument 类写入 XML 数据

+   使用 Google 的地理编码 API

# 介绍

XML 是一种名为**可扩展标记语言**的文件格式的文件扩展名，用于以结构化格式存储信息。XML 格式广泛用于 Web 以及其他应用程序。例如，HTML 是用于创建网页的文件格式，基于 XML 格式。从 Microsoft Office 2007 开始，Microsoft Office 使用基于 XML 的文件格式，如`.docx`、`.xlsx`、`.pptx`等。

# 使用流读取器处理 XML 数据

在本节中，我们将学习如何处理从 XML 文件中提取的数据，并使用流读取器进行提取。

## 操作方法…

让我们按照以下步骤创建一个简单的程序，通过读取和处理 XML 文件：

1.  像往常一样，在你想要的位置创建一个新的**Qt Widgets 应用程序**项目。

1.  接下来，打开任何文本编辑器，创建一个看起来像下面这样的 XML 文件，然后将其保存为`scene.xml`：

```cpp
<?xml version="1.0" encoding="UTF-8"?> 
<scene>
  <object tag="building">
    <name>Library</name>
    <position>120.0,0.0,50.68</position>
    <rotation>0.0,0.0,0.0</rotation>
    <scale>1.0,1.0,1.0</scale>
  </object>
  <object tag="building">
    <name>Town Hall</name>
    <position>80.2,0.0,20.5</position>
    <rotation>0.0,0.0,0.0</rotation>
    <scale>1.0,1.0,1.0</scale>
  </object>
  <object tag="prop">
    <name>Tree</name>
    <position>10.46,-0.2,80.2</position>
    <rotation>0.0,0.0,0.0</rotation>
    <scale>1.0,1.0,1.0</scale>
  </object>
</scene>
```

1.  接下来，返回到 Qt Creator 并打开`mainwindow.h`。在脚本顶部添加以下头文件，就在`#include <QMainWindow>`之后：

```cpp
#include <QXmlStreamReader>
#include <QDebug>
#include <QFile>
#include <QFileDialog>
```

1.  然后，打开`mainwindow.ui`，从左侧的小部件框中拖动一个**Push Button**到 UI 编辑器中。将按钮的对象名称更改为`loadXmlButton`，显示文本更改为**加载 XML**：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_06_01.jpg)

1.  之后，右键单击按钮，选择**转到槽…**。一个窗口将弹出，显示可供选择的信号列表。

1.  选择默认的`clicked()`选项，然后按**确定**按钮。Qt 现在会在你的头文件和源文件中插入一个名为`on_loadXmlButton_clicked()`的槽函数。

1.  现在，将以下代码添加到`on_loadXmlButton_clicked()`函数中：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_06_02.jpg)

1.  现在构建并运行项目，你会看到一个弹出的窗口，看起来就像你在第 4 步中制作的窗口：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_06_03.jpg)

1.  点击**加载 XML**按钮，你会看到文件选择窗口弹出在屏幕上。选择在第 2 步中创建的 XML 文件，然后按**选择**按钮。之后，你应该在 Qt Creator 的应用程序输出窗口中看到以下调试文本，这表明程序已成功从你刚刚选择的 XML 文件中加载了数据：![操作方法…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_06_04.jpg)

## 工作原理…

在这个例子中，我们要做的是使用`QXmlStreamReader`类从 XML 文件中提取和处理数据。想象一下，你正在制作一个电脑游戏，你正在使用 XML 文件来存储游戏场景中所有对象的属性。在这种情况下，XML 格式在以结构化方式存储数据方面发挥着重要作用，这使得数据的提取变得容易。

首先，我们需要在源文件中添加与 XML 相关的类的头文件，这种情况下是`QXmlStreamReader`类。`QXmlStreamReader`内置在 Qt 的核心库中，因此不需要使用任何附加模块，这也意味着它是在 Qt 中处理 XML 数据的推荐类。

一旦我们点击了**加载 XML**按钮，`on_loadXmlButton_clicked()`槽将被调用；这是我们编写处理 XML 数据的代码的地方。

首先，我们使用文件对话框来选择要处理的 XML 文件。然后，将所选文件的文件名和路径发送到`QFile`类中，以打开和读取 XML 文件的文本数据。之后，文件的数据被发送到`QXmlStreamReader`类进行处理。

我们使用 while 循环来读取整个 XML 文件，并检查流读取器处理的每个元素。我们确定元素是开始元素还是结束元素。如果是开始元素，我们将检查元素的名称，以确定元素是否应包含我们需要的任何数据。

然后，我们将提取数据，可以是属性或文本的形式。一个元素可能有多个属性，这就是为什么我们必须循环遍历所有属性并逐个提取它们。

## 还有更多…

除了 Web 浏览器之外，许多商业游戏引擎和交互应用程序也使用 XML 格式来存储游戏场景、网格和产品中使用的其他形式的资产信息。这是因为 XML 格式相对于其他文件格式提供了许多优势，如紧凑的文件大小、高灵活性和可扩展性、易于文件恢复，以及允许用于高效和性能关键应用程序的关系树结构，如搜索引擎、智能数据挖掘服务器、科学模拟等。

让我们简单了解一下 XML 文件的格式。我们将使用前面示例中使用的`scene.xml`，它看起来像这样：

```cpp
<?xml version="1.0" encoding="UTF-8"?> 
<scene>
  <object tag="building">
    <name>Library</name>
    <position>120.0,0.0,50.68</position>
    <rotation>0.0,0.0,0.0</rotation>
    <scale>1.0,1.0,1.0</scale>
  </object>
  <object tag="building">
    <name>Town Hall</name>
    <position>80.2,0.0,20.5</position>
    <rotation>0.0,0.0,0.0</rotation>
    <scale>1.0,1.0,1.0</scale>
  </object>
  <object tag="prop">
    <name>Tree</name>
    <position>10.46,-0.2,80.2</position>
    <rotation>0.0,0.0,0.0</rotation>
    <scale>1.0,1.0,1.0</scale>
  </object>
</scene>
```

在 XML 中，标签是以`<`符号开始，以`>`符号结束的一行标记文本。例如，`<scene>`是一个名为`scene`的标签，`<object>`是一个名为`object`的标签，依此类推。标签有三种类型：

+   开始标签，例如`<scene>`

+   结束标签，例如`</scene>`

+   空元素标签，例如`<scene />`

每当你写一个开始标签时，它必须以一个结束标签结束，否则你的 XML 数据将无效。然而，空元素标签是一个独立的标签，不需要在其后面加上结束标签。

在`scene.xml`的顶部，你会看到一个名为`xml`的标签，其中存储了 XML 格式的版本和编码类型，本例中为 XML 版本 1.0 和 UTF-8（8 位 Unicode）编码。这一行称为 XML 声明，它必须存在于你的任何 XML 文件中以验证其格式。

之后，你会看到带有属性的标签，例如`<object tag="building">`。这意味着`object`标签包含一个名为`tag`的属性，其中包含一个值`building`。你可以在一个标签中放置尽可能多的属性，例如`<object tag="building" color="red" name="LA Community Hospital" coordinate="34.0191757,-118.2567239">`。这些属性中的每一个都存储着可以使用 Qt 轻松检索的独特数据。

除此之外，你还可以在开始标签和结束标签之间存储数据，例如`<name>Town Hall</name>`。然而，这种方法与空元素标签无关，因为它是一个独立的标签，不需要跟随一个关闭标签。因此，你只能在空元素标签中存储属性。

### 注意

要了解更多关于 XML 格式的信息，请访问[`www.w3schools.com/xml`](http://www.w3schools.com/xml)。

# 使用流写入器写入 XML 数据

由于我们已经学会了如何处理从 XML 文件中获取的数据，在前面的示例中，我们将继续学习如何将数据保存到 XML 文件中。我们将继续使用前面的示例并对其进行扩展。

## 如何做…

我们将通过以下步骤学习如何将数据保存到 XML 文件中：

1.  首先，在`mainwindow.ui`中添加另一个按钮，并将其对象名称设置为`saveXmlButton`，标签设置为**保存 XML**：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_06_05.jpg)

1.  接下来，右键单击按钮，选择**转到槽…**。一个窗口将弹出，显示可供选择的信号列表。选择`clicked()`选项，然后单击**确定**。一个名为`on_saveXmlButton_clicked()`的信号函数将被 Qt 自动添加到你的`mainwindow.h`和`mainwindow.cpp`文件中：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_06_06.jpg)

1.  在`on_saveXmlButton_clicked()`函数中添加以下代码：

```cpp
QXmlStreamWriter xml;

QString filename = QFileDialog::getSaveFileName(this, "Save Xml", ".", "Xml files (*.xml)");
QFile file(filename);
if (!file.open(QFile::WriteOnly | QFile::Text))
  qDebug() << "Error saving XML file.";
xml.setDevice(&file);

xml.setAutoFormatting(true);
xml.writeStartDocument();

xml.writeStartElement("contact");
xml.writeAttribute("category", "Friend");
xml.writeTextElement("name", "John Doe");
xml.writeTextElement("age", "32");
xml.writeTextElement("address", "114B, 2nd Floor, Sterling Apartment, Morrison Town");
xml.writeTextElement("phone", "0221743566");
xml.writeEndElement();

xml.writeStartElement("contact");
xml.writeAttribute("category", "Family");
xml.writeTextElement("name", "Jane Smith");
xml.writeTextElement("age", "24");
xml.writeTextElement("address", "13, Ave Park, Alexandria");
xml.writeTextElement("phone", "0025728396");
xml.writeEndElement();

xml.writeEndDocument();
```

1.  构建并运行程序，你应该会在程序界面上看到一个额外的按钮：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_06_07.jpg)

1.  单击**保存 XML**按钮，屏幕上会出现一个保存文件对话框。输入你想要的文件名，然后单击**保存**按钮。

1.  用任何文本编辑器打开你刚保存的 XML 文件。文件的内容应该是这样的：

```cpp
<?xml version="1.0" encoding="UTF-8"?>
<contact category="Friend">
  <name>John Doe</name>
  <age>32</age>
  <address>114B, 2nd Floor, Sterling Apartment, Morrison Town</address>
  <phone>0221743566</phone>
</contact>
<contact category="Family">
  <name>Jane Smith</name>
  <age>24</age>
  <address>13, Ave Park, Alexandria</address>
  <phone>0025728396</phone>
</contact>
```

## 工作原理…

保存过程与前面示例中加载 XML 文件的过程基本相似。唯一的区别是，我们不再使用`QXmlStreamReader`类，而是改用`QXmlStreamWriter`类。

我们仍然使用文件对话框和`QFile`类来保存 XML 文件。这次，我们必须在将`QFile`类传递给流写入器之前，将打开模式从`QFile::ReadOnly`更改为`QFile::WriteOnly`。

在我们开始向新的 XML 文件写入任何数据之前，我们必须将自动格式设置为`true`，否则将不会有间距；它还会向 XML 文件添加新行和缩进，使其看起来整洁且易于阅读。但是，如果这是你的意图（使用户难以阅读和编辑），那么你可以忽略`setAutoFormatting()`函数。

接下来，通过调用`writeStartDocument()`开始编写 XML 文件，然后写入要保存到文件中的所有元素，最后调用`writeEndDocument()`函数停止写入。

为了使读取过程正常工作，每个元素都必须有开始和结束标记。元素的属性将存储在开始标记中，而文本数据将存储在开始和结束标记之间。

如果我们要写入一个包含一组子元素的元素，那么在写入子元素之前必须调用`writeStartElement()`。然后，在保存所有子元素后，调用`writeEndElement()`来关闭该组并添加结束标记。`writetextElement()`函数会自动为您添加结束标记，因此您不必担心这个。

您可以调用`writeAttribute()`函数向元素添加属性。对于特定元素，您可以添加任意数量的属性。

# 使用`QDomDocument`类处理 XML 数据

Qt 允许多种方式解析 XML 数据，包括我们在前面示例中介绍的常见方法。这一次，我们将学习如何使用另一个名为`QDomDocument`的类从 XML 文件中读取数据。

## 操作步骤…

使用`QDomDocument`类处理 XML 数据非常简单：

1.  首先，我们需要通过打开项目（`.pro`）文件并在`core`和`gui`后面添加文本`xml`来将 XML 模块添加到我们的项目中，如下所示：

```cpp
QT += core gui xml
```

1.  然后，就像我们在本章的第一个示例中所做的那样，创建一个用户界面，上面有一个按钮，上面写着**加载 XML**：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_06_08.jpg)

1.  之后，右键单击按钮，选择**转到槽…**，然后选择`clicked()`选项。按下**确定**按钮，Qt 将在您的源代码中添加一个槽函数。

1.  转到`mainwindow.h`并添加以下头文件，以便我们可以使用这些类：

```cpp
#include <QDomDocument>
#include <QDebug>
#include <QFile>
#include <QFileDialog>
```

1.  接下来，转到`mainwindow.cpp`并插入以下代码到按钮的`clicked()`槽函数中：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_06_09.jpg)

1.  现在编译并运行程序。单击**加载 XML**按钮，然后选择第一个示例中使用的 XML 文件。你应该会看到以下输出：![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_06_10.jpg)

## 工作原理…

与`QXmlStreamReader`相比，`QDomDocument`类在加载或保存 XML 数据时不太直接。然而，`QDomDocument`通过确保每个元素都递归地链接到其相应的父元素，就像树结构一样，以严格的方式来完成。与`QXmlStreamReader`不同，`QDomDocument`允许我们在稍后的时间保存数据到之前创建的元素中。

由于`QDomDocument`不是 Qt 核心库的一部分，我们必须手动将 XML 模块添加到我们的项目中。否则，我们将无法访问`QDomDocument`和与之相关的其他类。

首先，我们加载 XML 文件并提取其内容到`QDomDocument`类。然后，我们获取其文档元素，它充当根文档，并获取其直接子元素。然后，我们将每个子节点转换为`QDomElement`并获取它们的标签名称。

通过检查标签名称，我们能够确定我们从每个元素中期望的数据类型。由于这是具有标签名称`object`的第一层元素，我们不期望从中获取任何数据；我们再次重复第 3 步，但这一次，我们将在具有标签名称`object`的元素上执行此操作，并获取其所有直接子元素，这意味着文档元素的孙元素。

同样，通过检查标签名称，我们能够知道我们从其子元素中期望什么数据。如果标签名称与我们期望的匹配（在本例中为`name`、`position`、`rotation`、`scale`），那么我们可以通过调用`QDomElement::text()`获取其数据。

# 使用`QDomDocument`类编写 XML 数据

在这个例子中，我们将学习如何使用`QDomDocument`类将数据写入 XML 文件。我们将继续上一个例子，并添加一些内容。

## 如何做…

要学习如何使用`QDomDocument`类将数据保存到 XML 文件中，请执行以下操作：

1.  首先，将第二个按钮添加到 UI 中，名为**保存 XML**：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_06_11.jpg)

1.  右键单击**保存 XML**按钮，然后选择**转到槽…**。然后，选择**clicked()**选项并单击**确定**。现在将在源文件中添加一个新的`clicked()`槽函数。

1.  之后，在按钮的`clicked()`槽函数中编写以下代码：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_06_12.jpg)![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_06_15.jpg)

1.  现在编译并运行程序，然后单击**保存 XML**按钮。在保存文件对话框中输入所需的文件名，然后单击**保存**。

1.  使用任何文本编辑器打开您在第 4 步中保存的 XML 文件，您应该会看到类似于以下内容：

```cpp
<!DOCTYPE contact>
<contact category="Family">
  <name>John Doe</name>
  <age>32</age>
  <address>114B, 2nd Floor, Sterling Apartment, Morrisontown</address>
  <phone>0221743566</phone>
</contact>
<contact category="Friend">
  <name>John Doe</name>
  <age>32</age>
  <address>114B, 2nd Floor, Sterling Apartment, Morrisontown</address>
  <phone>0221743566</phone>
</contact>
```

## 它是如何工作的…

与上一个例子类似，我们首先初始化文件对话框并声明一个`QDomDocument`对象。

然后，通过调用`QDomDocument::createElement()`创建根元素。从`QDomDocument`创建的任何元素都不会自动成为其直接子元素，除非我们将新创建的元素附加为其子元素。

要创建`QDomDocument`的孙元素，只需将新创建的元素附加到根元素即可。通过使用`append()`函数，我们可以轻松地将 XML 数据排列成树形结构，而无需费心思考。在我看来，这就是使用`QDomDocument`而不是`QXmlStreamReader`的优势。

然后，我们可以通过调用`QDomElement::setAttribute()`为元素添加属性。我们还可以通过调用`QDomDocument::createTextNode()`创建文本节点，并将其附加到 XML 结构中的任何元素。

在我们完成构造 XML 数据之后，我们可以将所有数据以文本形式输出到`QTextStream`类，并允许其将数据保存到文件中。

# 使用谷歌的地理编码 API

在这个例子中，我们将学习如何使用谷歌的地理编码 API 获取特定位置的完整地址。

## 如何做…

让我们创建一个程序，通过以下步骤利用地理编码 API：

1.  首先，创建一个新的**Qt 小部件应用程序**项目。

1.  接下来，打开`mainwindow.ui`并添加一些文本标签、输入字段和一个按钮，使您的 UI 看起来类似于这样：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_06_13.jpg)

1.  之后，打开您的项目（`.pro`）文件，并将网络模块添加到您的项目中。您只需在`core`和`gui`之后添加`network`文本即可完成此操作，如下所示：

```cpp
QT += core gui network
```

1.  然后，打开`mainwindow.h`并在`#include <QMainWindow>`之后的源代码中添加以下头文件：

```cpp
#include <QDebug>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QNetworkReply>
#include <QXmlStreamReader>
```

1.  接下来，手动声明一个槽函数并将其命名为`getAddressFinished()`：

```cpp
private slots:
  void getAddressFinished(QNetworkReply* reply);
```

1.  在那之后，声明一个名为`addressRequest`的`private`变量：

```cpp
private:
  QNetworkAccessManager* addressRequest;
```

1.  完成后，再次打开`mainwindow.ui`，右键单击**获取地址**按钮，然后选择**转到槽…**。然后选择**clicked()**选项并按**确定**。槽函数现在将添加到`mainwindow.h`和`mainwindow.cpp`源文件中。

1.  现在，打开`mainwindow.cpp`并将以下代码添加到类构造函数中：

```cpp
MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent),
  ui(new Ui::MainWindow)
{
  ui->setupUi(this);

  addressRequest = new QNetworkAccessManager();
  connect(addressRequest, SIGNAL(finished(QNetworkReply*)),   SLOT(getAddressFinished(QNetworkReply*)));
}
```

1.  然后，我们将以下代码添加到我们刚刚手动声明的`getAddressFinished()`槽函数中：

```cpp
void MainWindow::getAddressFinished(QNetworkReply* reply)
{
  QByteArray bytes = reply->readAll();

  //qDebug() << QString::fromUtf8(bytes.data(), bytes.size());

  QXmlStreamReader xml;
  xml.addData(bytes);

  while(!xml.atEnd())
  {
    if (xml.isStartElement())
    {
      QString name = xml.name().toString();
      //qDebug() << name;

      if (name == "formatted_address")
      {
        QString text = xml.readElementText();
        qDebug() << "Address:" << text;
        return;
      }
    }

    xml.readNext();
  }

  if (xml.hasError())
  {
    qDebug() << "Error loading XML:" << xml.errorString();
    return;
  }

  qDebug() << "No result.";
}
```

1.  最后，将以下代码添加到 Qt 创建的`clicked()`槽函数中：

```cpp
void MainWindow::on_getAddressButton_clicked()
{
  QString latitude = ui->latitude->text();
  QString longitude = ui->longitude->text();

  QNetworkRequest request;
  request.setUrl(QUrl("http://maps.googleapis.com/maps/api/geocode/xml?latlng=" + latitude + "," + longitude + "&sensor=false"));
  addressRequest->get(request);
}
```

1.  现在构建并运行程序，您应该能够通过插入经度和纬度值并单击**获取地址**按钮来获取地址：![如何做…](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/qt5-cpp-gui-prog-cb/img/B02820_06_14.jpg)

1.  让我们尝试使用经度`-73.9780838`和纬度`40.6712957`。单击**获取地址**按钮，您将在应用程序输出窗口中看到以下结果：

```cpp
Address: "180-190 7th Ave, Brooklyn, NY 11215, USA"
```

## 它是如何工作的…

我无法告诉您谷歌如何从其后端系统获取地址，但我可以教您如何使用`QNetworkRequest`从谷歌请求数据。基本上，您只需要将网络请求的 URL 设置为我在先前源代码中使用的 URL，并将纬度和经度信息附加到 URL。之后，我们只能等待来自谷歌 API 服务器的响应。

请注意，当向谷歌发送请求时，我们需要指定 XML 作为期望的格式；否则，它可能会返回 JSON 格式的结果。这可以通过在网络请求 URL 中添加`xml`关键字来实现，如下所示：

```cpp
request.setUrl(QUrl("http://maps.googleapis.com/maps/api/geocode/xml?latlng=" + latitude + "," + longitude + "&sensor=false"));
```

当程序从谷歌接收到响应时，将调用`getAddressFinished()`槽函数，我们将能够通过`QNetworkReply`获取谷歌发送的数据。

谷歌通常会以 XML 格式回复一个长文本，其中包含大量我们不需要的数据。我们使用`QXmlStreamReader`来解析数据，因为在这种情况下，我们不必关心 XML 结构的父子关系。

我们只需要在 XML 数据中存储的`formatted_address`元素中的文本。由于有多个名为`formatted_address`的元素，我们只需要找到第一个并忽略其余的。

您还可以通过向谷歌提供地址并从其网络响应中获取位置坐标来进行反向操作。

## 还有更多…

谷歌的地理编码 API 是谷歌地图 API Web 服务的一部分，为您的地图应用程序提供地理数据。除了地理编码 API，您还可以使用他们的位置 API、地理位置 API、时区 API 等来实现您想要的结果。

### 注意

有关谷歌地图 API Web 服务的更多信息，请访问此链接：[`developers.google.com/maps/web-services`](https://developers.google.com/maps/web-services)
