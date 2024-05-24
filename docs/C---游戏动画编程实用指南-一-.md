# C++ 游戏动画编程实用指南（一）

> 原文：[`annas-archive.org/md5/1ec3311f50b2e1eb4c8d2a6c29a60a6b`](https://annas-archive.org/md5/1ec3311f50b2e1eb4c8d2a6c29a60a6b)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

现代游戏动画有点像黑魔法。没有太多资源详细介绍如何构建基于轨道驱动的动画系统，或者高级主题，比如双四元数蒙皮。这本书的目标就是填补这个空白。本书的目标是为动画编程的黑魔法投下一些光，使这个主题对每个人都变得可接近。

本书采用“理论到实现”的方法，您将首先学习每个讨论主题的理论。一旦您理解了理论，就可以实施它以获得实际经验。

本书着重于动画编程的概念和实现细节，而不是所使用的语言或图形 API。通过专注于这些基本概念，您将能够实现一个动画系统，而不受语言或图形 API 的限制。

# 本书适合的读者

本书适用于想要学习如何构建现代动画系统的程序员。跟随本书的唯一要求是对 C++有一定的了解。除此之外，本书涵盖了从如何打开一个新窗口，到创建一个 OpenGL 上下文，渲染一个动画模型，以及高级动画技术的所有内容。

# 本书涵盖的内容

[*第一章*]（B16191_01_Final_JC_ePub.xhtml#_idTextAnchor013）*，创建游戏窗口*，解释了如何创建一个新的 Visual Studio 项目，创建一个 Win32 窗口，设置一个 OpenGL 3.3 渲染上下文，并启用垂直同步。本书的代码示例是针对 OpenGL 3.3 编译的。所有 OpenGL 代码都与最新版本的 OpenGL 和 OpenGL 4.6 兼容。

[*第二章*]（B16191_02_Final_JC_ePub.xhtml#_idTextAnchor026）*，实现向量*，涵盖了游戏动画编程中的向量数学。

[*第三章*]（B16191_03_Final_JC_ePub.xhtml#_idTextAnchor048）*，实现矩阵*，讨论了游戏动画编程中的矩阵数学。

[*第四章*]（B16191_04_Final_JC_ePub.xhtml#_idTextAnchor069）*，实现四元数*，解释了如何在游戏动画编程中使用四元数数学。

[*第五章*]（B16191_05_Final_JC_ePub.xhtml#_idTextAnchor094）*，实现变换*，解释了如何将位置、旋转和缩放组合成一个变换对象。这些变换对象可以按层次排列。

[*第六章*]（B16191_06_Final_JC_ePub.xhtml#_idTextAnchor104）*，构建抽象渲染器*，向您展示如何在 OpenGL 3.3 之上创建一个抽象层。本书的其余部分将使用这个抽象层进行渲染。通过使用抽象层，我们可以专注于动画编程的核心概念，而不是用于实现它的 API。抽象层针对 OpenGL 3.3，但代码也适用于 OpenGL 4.6。

[*第七章*]（B16191_07_Final_JC_ePub.xhtml#_idTextAnchor128）*，了解 glTF 文件格式*，介绍了 glTF 文件格式。glTF 是一种标准的开放文件格式，受大多数 3D 内容创建工具支持。能够加载一个通用格式将让您加载几乎任何创建工具中制作的动画。

[*第八章*]（B16191_08_Final_JC_ePub.xhtml#_idTextAnchor142）*创建曲线、帧和轨道*，介绍了如何插值曲线以及曲线如何用于动画存储在层次结构中的变换。

[*第九章*]（B16191_09_Final_JC_ePub.xhtml#_idTextAnchor155）*，实现动画片段*，解释了如何实现动画片段。动画片段会随时间修改变换层次结构。

[*第十章*]（B16191_10_Final_JC_ePub.xhtml#_idTextAnchor167）*，网格蒙皮*，介绍了如何变形网格，使其与采样动画片段生成的姿势相匹配。

[*第十一章*]（B16191_11_Final_JC_ePub.xhtml#_idTextAnchor185）*，优化动画管道*，向您展示如何优化动画管道的部分，使其更快速和更适合生产。

*第十二章**，动画之间的混合*，解释了如何混合两个动画姿势。这种技术可以用来平滑地切换两个动画，而不会出现任何视觉跳动。

*第十三章**，实现逆运动学*，介绍了如何使用逆运动学使动画与环境互动。例如，您将学习如何使动画角色的脚在不平坦的地形上不穿透地面。

*第十四章**，使用双四元数进行蒙皮*，介绍了游戏动画中的双四元数数学。双四元数可用于避免在动画关节处出现捏合。

*第十五章**，渲染实例化人群*，展示了如何将动画数据编码到纹理中，并将姿势生成移入顶点着色器。您将使用这种技术来使用实例化渲染大型人群。

# 为了充分利用本书

为了充分利用本书，需要一些 C++的经验。您不必是一个经验丰富的 C++大师，但您应该能够调试简单的 C++问题。有一些 OpenGL 经验是一个加分项，但不是必需的。没有使用高级 C++特性。提供的代码针对 C++ 11 或最新版本进行编译。

本书中的代码是针对 OpenGL 3.3 Core 编写的。本书中呈现的 OpenGL 代码是向前兼容的；在出版时，OpenGL 的最高兼容版本是 4.6。在*第六章*，构建抽象渲染器，您将在 OpenGL 之上实现一个薄的抽象层。在本书的其余部分，您将针对这个抽象层进行编码，而不是直接针对 OpenGL。

本书中呈现的代码应该可以在运行 Windows 10 或更高版本的任何笔记本电脑上编译和运行。跟随本书的唯一硬件要求是能够运行 Visual Studio 2019 或更高版本的计算机。

Visual Studio 2019 的最低硬件要求是：

+   Windows 10，版本 1703 或更高版本

+   1.8 GHz 或更快的处理器

+   2GB 的 RAM

这些要求可以在以下网址找到：[`docs.microsoft.com/en-us/visualstudio/releases/2019/system-requirements`](https://docs.microsoft.com/en-us/visualstudio/releases/2019/system-requirements)

下载示例代码文件

您可以从[`www.packt.com`](http://www.packt.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了这本书，您可以访问[`www.packt.com/support`](http://www.packt.com/support)并注册，文件将直接通过电子邮件发送给您。

您可以按照以下步骤下载代码文件：

1.  在[`www.packt.com`](http://www.packt.com)上登录或注册。

1.  选择“支持”选项卡。

1.  点击“代码下载和勘误”。

1.  在搜索框中输入书名，按照屏幕上的指示操作。

下载文件后，请确保使用最新版本的以下软件解压或提取文件夹：

+   Windows 上的 WinRAR/7-Zip

+   Mac 上的 Zipeg/iZip / UnRarX

+   Linux 上的 7-Zip/PeaZip

本书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Game-Animation-Programming`](https://github.com/PacktPublishing/Game-Animation-Programming)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。快去看看吧！

## 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如：“将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。”

代码块设置如下：

```cpp
public:
    Pose();
    Pose(const Pose& p);
    Pose& operator=(const Pose& p);
    Pose(unsigned int numJoints);
```

任何命令行输入或输出都会以以下方式书写：

```cpp
# cp /usr/src/asterisk-addons/configs/cdr_mysql.conf.sample
     /etc/asterisk/cdr_mysql.conf
```

**粗体**：表示一个新术语、一个重要词或者屏幕上看到的词，例如在菜单或对话框中，也会在文本中显示为这样。例如：“从管理面板中选择**系统信息**。”

注意

警告或重要说明会显示在这样。

提示和技巧会显示在这样。

# 第一章：创建游戏窗口

在本章中，你将设置一个简单的 Win32 窗口，并将一个 OpenGL 上下文绑定到它上。本书中将始终使用 OpenGL 3.3 核心。实际的 OpenGL 代码将非常少。

大部分特定于 OpenGL 的代码将被抽象成辅助对象和函数，这将使你能够专注于动画而不是任何特定的图形 API。你将在*第六章**，构建一个抽象渲染器*中编写抽象层，但现在，重要的是创建一个可以绘制的窗口。

在本章结束时，你应该能够做到以下几点：

+   打开一个 Win32 窗口

+   创建并绑定一个 OpenGL 3.3 核心上下文

+   使用 glad 加载 OpenGL 3.3 核心函数

+   为创建的窗口启用垂直同步

+   了解本书的可下载示例

# 技术要求

要跟随本书中的代码，你需要一台安装了最新版本的 Windows 10 的计算机，并安装了 Visual Studio。所有可下载的代码示例都是使用 Visual Studio 2019 构建的。你可以从[`visualstudio.microsoft.com/`](https://visualstudio.microsoft.com/)下载 Visual Studio。

你可以在 GitHub 上找到本书的所有示例代码[`github.com/PacktPublishing/Game-Animation-Programming`](https://github.com/PacktPublishing/Game-Animation-Programming)。

# 创建一个空项目

在本书中，你将尽可能地从头开始创建代码。因此，外部依赖将会很少。要开始，请按照以下步骤在 Visual Studio 中创建一个新的空白 C++项目：

1.  打开 Visual Studio，通过**文件**|**新建**|**项目**创建一个新项目：![图 1.1：创建一个新的 Visual Studio 项目](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_1.1_B16191.jpg)

图 1.1：创建一个新的 Visual Studio 项目

1.  你将在弹出窗口的左侧看到项目模板。导航到**已安装**|**Visual C++**|**其他**。然后，选择**空项目**：![图 1.2：创建一个空的 C++项目](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_1.2_B16191.jpg)

图 1.2：创建一个空的 C++项目

1.  输入项目名称并选择项目位置。最后，点击**创建**。

![图 1.3：指定新项目名称](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_1.3_B16191.jpg)

图 1.3：指定新项目名称

如果你按照前面的步骤操作，你应该有一个新的空白项目。在本章的其余部分，你将添加一个应用程序框架和一个启用了 OpenGL 的窗口。

# 创建应用程序类

维护杂乱的窗口入口函数将会很困难。相反，你需要创建一个抽象的`Application`类。这个类将包含一些基本函数，比如`Initialize`、`Update`、`Render`和`Shutdown`。本书提供的所有代码示例都将构建在`Application`基类之上。

创建一个新文件，`Application.h`。`Application`类的声明在以下代码示例中提供。将这个声明添加到新创建的`Application.h`文件中：

```cpp
#ifndef _H_APPLICATION_
#define _H_APPLICATION_
class Application {
private:
    Application(const Application&);
    Application& operator=(const Application&);
public:
    inline Application() { }
    inline virtual ~Application() { }
    inline virtual void Initialize() { }
    inline virtual void Update(float inDeltaTime) { }
    inline virtual void Render(float inAspectRatio) { }
    inline virtual void Shutdown() { }
};
#endif
```

`Initialize`、`Update`、`Render`和`Shutdown`函数是应用程序的生命周期。所有这些函数将直接从 Win32 窗口代码中调用。`Update`和`Render`需要参数。要更新一个帧，需要知道当前帧和上一帧之间的时间差。要渲染一个帧，需要知道窗口的宽高比。

生命周期函数是虚拟的。本书可下载材料中的每一章都有一个示例，它是`Application`类的子类，演示了该章节的概念。

接下来，你将向项目添加一个 OpenGL 加载器。

# 添加一个 OpenGL 加载器

本章依赖于一些外部代码，称为`glad`。在 Windows 上创建一个新的 OpenGL 上下文时，它将使用一个传统的 OpenGL 上下文。OpenGL 的扩展机制将允许你使用这个传统上下文来创建一个新的现代上下文。

一旦现代上下文被创建，您将需要获取所有 OpenGL 函数的函数指针。这些函数需要使用 `wglGetProcAdress` 加载，它返回一个函数指针。

以这种方式加载每个 OpenGL 函数将非常耗时。这就是使用 OpenGL 加载器的地方；`glad` 将为您完成所有这些工作。OpenGL 加载器是一个库或一些代码，调用 `wglGetProcAdress` 来定义 OpenGL API 的函数。

在 Windows 上有几个 OpenGL 加载器可用；本书将使用 `glad`。`glad` 是一个只包含几个文件的小型库。它有一个简单的 API；您调用一个函数就可以访问所有的 OpenGL 函数。`glad` 有一个基于 web 的界面；您可以在 [`glad.dav1d.de/`](https://glad.dav1d.de/) 找到它。

重要提示

在使用 X 窗口系统（例如许多流行的 Linux 发行版）时，加载 OpenGL 函数的函数是 `glXGetProcAddress`。与 Windows 一样，Linux 也有可用的 OpenGL 加载器。并非所有操作系统都需要 OpenGL 加载器；例如，macOS、iOS 和 Android 不需要加载器。iOS 和 Android 都运行在 OpenGL ES 上。

# 获取 glad

您可以从 [`glad.dav1d.de/`](https://glad.dav1d.de/) 获取 `glad`，这是一个基于 web 的生成器：

1.  转到该网站，从 **gl** 下拉菜单中选择 **Version 3.3**，从 **Profile** 下拉菜单中选择 **Core**：![图 1.4：配置 glad](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_1.4_B16191.jpg)

图 1.4：配置 glad

1.  滚动到底部，点击 **Generate** 按钮。这应该开始下载一个包含所有所需代码的 ZIP 文件。

本书中提供的代码与 OpenGL 版本 3.3 或更高版本向前兼容。如果要使用更新的 OpenGL 版本，例如 4.6，将 API 下拉菜单下的 gl 更改为所需的版本。在下一节中，您将向主项目添加此 ZIP 文件的内容。

## 将 glad 添加到项目

一旦下载了 `glad.zip`，解压其内容。将 ZIP 文件中的以下文件添加到您的项目中。不需要维护目录结构；所有这些文件都可以放在一起：

+   `src/glad.c`

+   `include/glad/glad.h`

+   `include/KHR/khrplatform.h`

这些文件将被包含为普通项目文件——您不需要设置 `include` 路径——但这意味着文件的内容需要被编辑：

1.  打开 `glad.c`，并找到以下 #include：

`#include <glad/glad.h>`

1.  用 `glad.h` 的相对路径替换 `include` 路径：

`#include "glad.h"`

1.  同样，打开 `glad.h`，并找到以下 #include：

`#include <KHR/khrplatform.h>`

1.  用 `khrplatform.h` 的相对路径替换 `include` 路径：

`#include "khrplatform.h"`

`glad` 现在应该已经添加到项目中，不应该有编译错误。在下一节中，您将开始实现 Win32 窗口。

# 创建窗口

在本节中，您将创建一个窗口。这意味着您将直接使用 Win32 API 调用来打开窗口并从代码中控制其生命周期。您还将设置一个调试控制台，可以与窗口一起运行，这对于查看日志非常有用。

重要提示

深入讨论 Win32 API 超出了本书的范围。有关任何 Win32 API 的其他信息，请参阅微软开发者网络（MSDN）[`docs.microsoft.com/en-us/windows/win32/api/`](https://docs.microsoft.com/en-us/windows/win32/api/)。

为了使日志记录变得更容易，在调试模式下将同时打开两个窗口。一个是标准的 Win32 窗口，另一个是用于查看日志的控制台窗口。这可以通过条件设置链接器来实现。在调试模式下，应用程序应链接到控制台子系统。在发布模式下，应链接到窗口子系统。

可以通过项目的属性或使用`#pragma`注释在代码中设置链接器子系统。一旦子系统设置为控制台，`WinMain`函数就可以从`main`中调用，这将启动一个附加到控制台的窗口。

还可以通过代码执行其他链接器操作，例如链接到外部库。您将使用`#pragma`命令与 OpenGL 进行链接。

通过创建一个新文件`WinMain.cpp`来开始窗口实现。该文件将包含所有窗口逻辑。然后，执行以下操作：

1.  将以下代码添加到文件开头。它创建了`#define`常量，减少了通过包含`<windows.h>`引入的代码量：

```cpp
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define WIN32_EXTRA_LEAN
#include "glad.h"
#include <windows.h>
#include <iostream>
#include "Application.h"
```

1.  需要提前声明窗口入口函数和窗口事件处理函数。这是我们需要打开一个新窗口的两个 Win32 函数：

```cpp
int WINAPI WinMain(HINSTANCE, HINSTANCE, PSTR, int);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
```

1.  使用`#pragma`注释在代码中链接到`OpenGL32.lib`，而不是通过项目的属性窗口。将以下代码添加到`WinMain.cpp`中：

```cpp
#if _DEBUG
    #pragma comment( linker, "/subsystem:console" )
    int main(int argc, const char** argv) {
        return WinMain(GetModuleHandle(NULL), NULL,
                GetCommandLineA(), SW_SHOWDEFAULT);
    }
#else
    #pragma comment( linker, "/subsystem:windows" )
#endif
#pragma comment(lib, "opengl32.lib")
```

现在需要声明一些 OpenGL 函数。通过`wglCreateContextAttribsARB`创建现代 OpenGL 上下文，但是没有引用此函数。这是需要通过`wglGetProcAddress`加载的函数之一，因为它是一个扩展函数。

`wglCreateContextAttribsARB`的函数签名可以在`wglext.h`中找到。`wglext.h`头文件由 Khronos 托管，并且可以在 OpenGL 注册表的[`www.khronos.org/registry/OpenGL/index_gl.php`](https://www.khronos.org/registry/OpenGL/index_gl.php)上找到。

无需包含整个`wglext.h`头文件；您只需要与创建现代上下文相关的函数。以下代码直接从文件中复制。它包含了相关`#define`常量和函数指针类型的声明：

```cpp
#define WGL_CONTEXT_MAJOR_VERSION_ARB     0x2091
#define WGL_CONTEXT_MINOR_VERSION_ARB     0x2092
#define WGL_CONTEXT_FLAGS_ARB             0x2094
#define WGL_CONTEXT_CORE_PROFILE_BIT_ARB  0x00000001
#define WGL_CONTEXT_PROFILE_MASK_ARB      0x9126
typedef HGLRC(WINAPI* PFNWGLCREATECONTEXTATTRIBSARBPROC) 
             (HDC, HGLRC, const int*);
```

前面的代码定义了一个`wglCreatecontextAttribsARB`的函数指针类型。除此之外，还有一些`#define`常量，用于创建 OpenGL 3.3 核心上下文。本书的示例将启用`vsynch`，可以通过`wglSwapIntervalEXT`来实现。

正如您猜到的那样，这个函数也需要使用 OpenGL 的扩展机制加载。它还需要两个额外的支持函数：`wglGetExtensionStringEXT`和`wglGetSwapIntervalEXT`。这三个函数都可以在`wgl.h`中找到，该文件由 Khronos 在先前链接的 OpenGL 注册表中托管。

不要包含`wgl.h`，而是将以下代码添加到`WinMain.cpp`中。该代码定义了`wglGetExtensionStringEXT`、`wglSwapIntervalEXT`和`wglGetSwapIntervalEXT`的函数指针签名，从`wgl.h`中复制出来：

```cpp
typedef const char* 
        (WINAPI* PFNWGLGETEXTENSIONSSTRINGEXTPROC) (void);
typedef BOOL(WINAPI* PFNWGLSWAPINTERVALEXTPROC) (int);
typedef int (WINAPI* PFNWGLGETSWAPINTERVALEXTPROC) (void);
```

前面的代码是必须的，用于与 OpenGL 一起工作。通常会复制代码，而不是直接包含这些头文件。在下一节中，您将开始处理实际的窗口。

## 全局变量

需要两个全局变量以便轻松清理窗口：指向当前运行应用程序的指针和全局 OpenGL **顶点数组对象**（**VAO**）的句柄。不是每个绘制调用都有自己的 VAO，整个示例的持续时间将绑定一个 VAO。

为此，请创建以下全局变量：

```cpp
Application* gApplication = 0;
GLuint gVertexArrayObject = 0;
```

在本书的其余部分，将不会有其他全局变量。全局变量可能会使程序状态更难以跟踪。这两个存在的原因是稍后在应用程序关闭时轻松引用它们。接下来，您将开始实现`WinMain`函数以打开一个新窗口。

## 打开一个窗口

接下来，您需要实现窗口入口函数`WinMain`。此函数将负责创建窗口类，注册窗口类并打开一个新窗口：

1.  通过创建`Application`类的新实例并将其存储在全局指针中来开始定义`WinMain`的定义：

```cpp
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE 
                   hPrevInstance, PSTR szCmdLine, 
                   int iCmdShow) {
gApplication = new Application();
```

1.  接下来，需要填写`WNDCLASSEX`的一个实例。这里没有什么特别的，它只是一个标准的窗口定义。唯一需要注意的是`WndProc`函数是否设置正确：

```cpp
    WNDCLASSEX wndclass;
    wndclass.cbSize = sizeof(WNDCLASSEX);
    wndclass.style = CS_HREDRAW | CS_VREDRAW;
    wndclass.lpfnWndProc = WndProc;
    wndclass.cbClsExtra = 0;
    wndclass.cbWndExtra = 0;
    wndclass.hInstance = hInstance;
    wndclass.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wndclass.hIconSm = LoadIcon(NULL, IDI_APPLICATION);
    wndclass.hCursor = LoadCursor(NULL, IDC_ARROW);
    wndclass.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wndclass.lpszMenuName = 0;
    wndclass.lpszClassName = "Win32 Game Window";
    RegisterClassEx(&wndclass);
```

1.  一个新的应用程序窗口应该在监视器的中心启动。为此，使用`GetSystemMetrics`来找到屏幕的宽度和高度。然后，调整`windowRect`到屏幕中心的所需大小：

```cpp
    int screenWidth = GetSystemMetrics(SM_CXSCREEN);
    int screenHeight = GetSystemMetrics(SM_CYSCREEN);
    int clientWidth = 800;
    int clientHeight = 600;
    RECT windowRect;
    SetRect(&windowRect, 
            (screenWidth / 2) - (clientWidth / 2), 
            (screenHeight / 2) - (clientHeight / 2), 
            (screenWidth / 2) + (clientWidth / 2), 
            (screenHeight / 2) + (clientHeight / 2));
```

1.  要确定窗口的大小，不仅仅是客户区域，需要知道窗口的样式。以下代码示例创建了一个可以最小化或最大化但不能调整大小的窗口。要调整窗口的大小，使用位或(`|`)运算符与`WS_THICKFRAME`定义：

```cpp
    DWORD style = (WS_OVERLAPPED | WS_CAPTION | 
        WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX); 
    // | WS_THICKFRAME to resize
```

1.  一旦定义了所需的窗口样式，调用`AdjustWindowRectEx`函数来调整客户区矩形的大小，以包括所有窗口装饰在其大小中。当最终大小已知时，可以使用`CreateWindowEx`来创建实际的窗口。窗口创建完成后，存储对其设备上下文的引用：

```cpp
    AdjustWindowRectEx(&windowRect, style, FALSE, 0);
    HWND hwnd = CreateWindowEx(0, wndclass.lpszClassName, 
                "Game Window", style, windowRect.left, 
                windowRect.top, windowRect.right - 
                windowRect.left, windowRect.bottom - 
                windowRect.top, NULL, NULL, 
                hInstance, szCmdLine);
    HDC hdc = GetDC(hwnd);
```

1.  现在窗口已经创建，接下来你将创建一个 OpenGL 上下文。为此，你首先需要找到正确的像素格式，然后将其应用到窗口的设备上下文中。以下代码向你展示了如何做到这一点：

```cpp
    PIXELFORMATDESCRIPTOR pfd;
    memset(&pfd, 0, sizeof(PIXELFORMATDESCRIPTOR));
    pfd.nSize = sizeof(PIXELFORMATDESCRIPTOR);
    pfd.nVersion = 1;
    pfd.dwFlags = PFD_SUPPORT_OPENGL | PFD_DRAW_TO_WINDOW 
                  | PFD_DOUBLEBUFFER;
    pfd.iPixelType = PFD_TYPE_RGBA;
    pfd.cColorBits = 24;
    pfd.cDepthBits = 32;
    pfd.cStencilBits = 8;
    pfd.iLayerType = PFD_MAIN_PLANE;
    int pixelFormat = ChoosePixelFormat(hdc, &pfd);
    SetPixelFormat(hdc, pixelFormat, &pfd);
```

1.  设置了像素格式后，使用`wglCreateContext`创建一个临时的 OpenGL 上下文。这个临时上下文只是用来获取指向`wglCreateContextAttribsARB`的指针，它将用于创建一个现代上下文：

```cpp
    HGLRC tempRC = wglCreateContext(hdc);
    wglMakeCurrent(hdc, tempRC);
    PFNWGLCREATECONTEXTATTRIBSARBPROC
       wglCreateContextAttribsARB = NULL;
    wglCreateContextAttribsARB =
       (PFNWGLCREATECONTEXTATTRIBSARBPROC)
       wglGetProcAddress("wglCreateContextAttribsARB");
```

1.  存在并绑定了一个临时的 OpenGL 上下文，所以下一步是调用`wglCreateContextAttribsARB`函数。这个函数将返回一个 OpenGL 3.3 Core 上下文配置文件，绑定它，并删除旧的上下文：

```cpp
    const int attribList[] = {
        WGL_CONTEXT_MAJOR_VERSION_ARB, 3,
        WGL_CONTEXT_MINOR_VERSION_ARB, 3,
        WGL_CONTEXT_FLAGS_ARB, 0,
        WGL_CONTEXT_PROFILE_MASK_ARB,
        WGL_CONTEXT_CORE_PROFILE_BIT_ARB,
        0, };
    HGLRC hglrc = wglCreateContextAttribsARB(
                       hdc, 0, attribList);
    wglMakeCurrent(NULL, NULL);
    wglDeleteContext(tempRC);
    wglMakeCurrent(hdc, hglrc);
```

1.  在激活 OpenGL 3.3 Core 上下文后，可以使用`glad`来加载所有 OpenGL 3.3 Core 函数。调用`gladLoadGL`来实现这一点：

```cpp
    if (!gladLoadGL()) {
        std::cout << "Could not initialize GLAD\n";
    }
    else {
        std::cout << "OpenGL Version " << 
        GLVersion.major << "." << GLVersion.minor <<
          "\n";
    }
```

1.  现在应该已经初始化了一个 OpenGL 3.3 Core 上下文，并加载了所有核心 OpenGL 函数。接下来，你将在窗口上启用`vsynch`。`vsynch`不是一个内置函数；它是一个扩展，因此需要使用`wglGetExtensionStringEXT`来查询对它的支持。`vsynch`的扩展字符串是`WGL_EXT_swap_control`。检查它是否在扩展字符串列表中：

```cpp
    PFNWGLGETEXTENSIONSSTRINGEXTPROC
       _wglGetExtensionsStringEXT =
       (PFNWGLGETEXTENSIONSSTRINGEXTPROC)
       wglGetProcAddress("wglGetExtensionsStringEXT");
    bool swapControlSupported = strstr(
         _wglGetExtensionsStringEXT(), 
         "WGL_EXT_swap_control") != 0;
```

1.  如果`WGL_EXT_swap_control`扩展可用，需要加载它。实际的函数是`wglSwapIntervalEXT`，可以在`wgl.h`中找到。向`wglSwapIntervalEXT`传递参数可以打开`vsynch`：

```cpp
    int vsynch = 0;
    if (swapControlSupported) {
        PFNWGLSWAPINTERVALEXTPROC wglSwapIntervalEXT = 
            (PFNWGLSWAPINTERVALEXTPROC)
            wglGetProcAddress("wglSwapIntervalEXT");
        PFNWGLGETSWAPINTERVALEXTPROC 
            wglGetSwapIntervalEXT =
            (PFNWGLGETSWAPINTERVALEXTPROC)
            wglGetProcAddress("wglGetSwapIntervalEXT");
        if (wglSwapIntervalEXT(1)) {
            std::cout << "Enabled vsynch\n";
            vsynch = wglGetSwapIntervalEXT();
        }
        else {
            std::cout << "Could not enable vsynch\n";
        }
    }
    else { // !swapControlSupported
        cout << "WGL_EXT_swap_control not supported\n";
    }
```

1.  还有一点小事情要做，以完成 OpenGL 启用窗口的设置。OpenGL 3.3 Core 要求在所有绘制调用中绑定一个 VAO。你将创建一个全局 VAO，在`WinMain`中绑定它，并在窗口被销毁之前永远不解绑。以下代码创建了这个 VAO 并绑定它：

```cpp
    glGenVertexArrays(1, &gVertexArrayObject);
    glBindVertexArray(gVertexArrayObject);
```

1.  调用`ShowWindow`和`UpdateWindow`函数来显示当前窗口；这也是初始化全局应用程序的好地方。根据应用程序的`Initialize`函数所做的工作量，窗口可能会在一小段时间内出现冻结：

```cpp
    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);
    gApplication->Initialize();
```

1.  现在你已经准备好实现实际的游戏循环了。你需要跟踪上一帧的时间，以计算帧之间的时间差。除了游戏逻辑，循环还需要处理窗口事件，通过查看当前消息堆栈并相应地分派消息：

```cpp
    DWORD lastTick = GetTickCount();
    MSG msg;
    while (true) {
        if (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE)) {
            if (msg.message == WM_QUIT) {
                break;
            }
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
```

1.  处理完窗口事件后，`Application`实例需要更新和渲染。首先，找到上一帧和当前帧之间的时间差，将其转换为秒。例如，以 60 FPS 运行的游戏应该有 16.6 毫秒或 0.0166 秒的时间差：

```cpp
        DWORD thisTick = GetTickCount();
        float dt = float(thisTick - lastTick) * 0.001f;
        lastTick = thisTick;
        if (gApplication != 0) {
            gApplication->Update(dt);
        }
```

1.  渲染当前运行的应用程序只需要更多的维护工作。每帧都要用`glViewport`设置 OpenGL 视口，并清除颜色、深度和模板缓冲区。除此之外，确保在渲染之前所有的 OpenGL 状态都是正确的。这意味着正确的 VAO 被绑定，深度测试和面剔除被启用，并且设置了适当的点大小：

```cpp
        if (gApplication != 0) {
            RECT clientRect;
            GetClientRect(hwnd, &clientRect);
            clientWidth = clientRect.right - 
                          clientRect.left;
            clientHeight = clientRect.bottom - 
                           clientRect.top;
            glViewport(0, 0, clientWidth, clientHeight);
            glEnable(GL_DEPTH_TEST);
            glEnable(GL_CULL_FACE);
            glPointSize(5.0f);
            glBindVertexArray(gVertexArrayObject);
            glClearColor(0.5f, 0.6f, 0.7f, 1.0f);
            glClear(GL_COLOR_BUFFER_BIT | 
            GL_DEPTH_BUFFER_BIT | GL_STENCIL_BUFFER_BIT);
            float aspect = (float)clientWidth / 
                           (float)clientHeight;
            gApplication->Render(aspect);
        }
```

1.  当前`Application`实例更新和渲染后，需要呈现后备缓冲区。这是通过调用`SwapBuffers`来完成的。如果启用了`vsynch`，则需要在`SwapBuffers`之后立即调用`glFinish`：

```cpp
        if (gApplication != 0) {
            SwapBuffers(hdc);
            if (vsynch != 0) {
                glFinish();
            }
        }
```

1.  窗口循环到此结束。窗口循环退出后，可以安全地从`WinMain`函数返回：

```cpp
    } // End of game loop
    if (gApplication != 0) {
        std::cout << "Expected application to 
                      be null on exit\n";
        delete gApplication;
    }
    return (int)msg.wParam;
}
```

如果要使用 OpenGL 的其他版本而不是 3.3，调整 Step 8 中`attribList`变量中的主要和次要值。即使`WinMain`函数已经编写，你仍然无法编译这个文件；因为`WndProc`从未被定义过。`WndProc`函数处理诸如鼠标移动或窗口调整大小等事件。在下一节中，你将实现`WndProc`函数。

## 创建事件处理程序

为了拥有一个正常运行的窗口，甚至编译应用程序，在这一点上，事件处理函数`WndProc`必须被定义。这里的实现将非常简单，主要关注如何销毁窗口：

1.  在`WinMain.cpp`中开始实现`WndProc`函数：

```cpp
LRESULT CALLBACK WndProc(HWND hwnd, UINT iMsg, 
                    WPARAM wParam, LPARAM lParam) {
    switch (iMsg) {
```

1.  当接收到`WM_CLOSE`消息时，需要关闭`Application`类并发出销毁窗口消息。应用程序关闭后，不要忘记删除它：

```cpp
    case WM_CLOSE:
        if (gApplication != 0) {
            gApplication->Shutdown();
            delete gApplication;
            gApplication = 0;
            DestroyWindow(hwnd);
        }
        else {
            std::cout << "Already shut down!\n";
        }
        break;
```

1.  当接收到销毁消息时，窗口的 OpenGL 资源需要被释放。这意味着删除全局顶点数组对象，然后删除 OpenGL 上下文：

```cpp
    case WM_DESTROY:
        if (gVertexArrayObject != 0) {
            HDC hdc = GetDC(hwnd);
            HGLRC hglrc = wglGetCurrentContext();
            glBindVertexArray(0);
            glDeleteVertexArrays(1, &gVertexArrayObject);
            gVertexArrayObject = 0;
            wglMakeCurrent(NULL, NULL);
            wglDeleteContext(hglrc);
            ReleaseDC(hwnd, hdc);
            PostQuitMessage(0);
        }
        else {
            std::cout << "Multiple destroy messages\n";
        }
        break;
```

1.  绘制和擦除背景消息是安全忽略的，因为 OpenGL 正在管理对窗口的渲染。如果收到的消息不是已经处理的消息之一，将其转发到默认的窗口消息函数：

```cpp
    case WM_PAINT:
    case WM_ERASEBKGND:
        return 0;
    }
    return DefWindowProc(hwnd, iMsg, wParam, lParam);
}
```

现在你已经编写了窗口事件循环，应该能够编译和运行一个空白窗口。在接下来的部分，你将探索本书的可下载示例。

# 探索样本

本书中提供的所有代码都可以在书的可下载内容中找到。有一个名为`AllChapters`的大型示例，其中包含单个应用程序中的每个示例。有一个`Bin` ZIP 文件，其中包含`AllChapters`示例的预编译可执行文件。

每个章节还包含多个子文件夹的单独文件夹。每个章节都包含`Sample00`，这是书中编写的代码，没有额外的内容。随后编号的示例添加了内容。

`AllChapters`示例看起来与各个章节文件夹中的示例有些不同。该应用程序使用 Nuklear ([`github.com/vurtun/nuklear`](https://github.com/vurtun/nuklear)) 来显示其用户界面。显示的用户界面部分是屏幕右上角的统计计数器。它看起来像这样：

![图 1.5：AllChapters 示例的统计计数器](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_1.5_B16191.jpg)

图 1.5：AllChapters 示例的统计计数器

顶部框包含有关应用程序打开的显示器的一些常规信息。这些信息包括显示频率、是否启用`vsynch`以及以毫秒为单位的帧预算。

下面的第二个框包含高级帧定时。如果在最近的 60 帧中有一帧过时，显示的时间将变成红色。一些过时的帧是不可避免的；如果帧速率降至 59.9，文本将在一秒钟内显示为红色。偶尔在这里看到红色是可以接受的；只有当数字完全变成红色时才会引起关注。

第三个框中包含两个 GPU 定时器；这些定时器测量样本在 GPU 上的运行速度。这对于调试任何繁重的绘制调用非常有用。最后一个框包含 CPU 定时器，有助于找出问题的哪个阶段存在瓶颈。

重要说明

在整本书中，您将使用 C++ `stl`容器。标准库在调试模式下有点慢，主要是由于错误检查。建议仅在发布模式下对任何示例进行性能分析。

这些示例应该很好地演示了您将在接下来的每一章中学到的内容。它们还为您提供了一个可以与您的代码进行比较的示例。

# 摘要

在本章中，您探讨了设置新的 Win32 窗口的过程。建立了一个 OpenGL 3.3 核心上下文来渲染窗口，并启用了`vsynch`。您了解了 OpenGL 加载器以及`glad`如何加载所有相关的 OpenGL 函数。

这个窗口将作为您构建的基础；所有未来的示例都是基于您在本章中创建的框架。在下一章中，您将开始探索渲染和动画所需的一些数学知识。


# 第二章：实现向量

在本章中，您将学习向量数学的基础知识。本书的其余部分大部分编码都依赖于对向量有很好的理解。向量将用于表示位移和方向。

在本章结束时，您将实现一个强大的向量库，并能够执行各种向量操作，包括分量和非分量操作。

本章将涵盖以下主题：

+   引入向量

+   创建一个向量

+   理解分量操作

+   理解非分量操作

+   插值向量

+   比较向量

+   探索更多向量

重要信息：

在本章中，您将学习如何以直观、可视的方式实现向量，这依赖于代码而不是数学公式。如果您对数学公式感兴趣，或者想尝试一些交互式示例，请访问[`gabormakesgames.com/vectors.html`](https://gabormakesgames.com/vectors.html)。

# 引入向量

什么是向量？向量是一个 n 元组的数字。它表示作为大小和方向测量的位移。向量的每个元素通常表示为下标，例如*(V*0*，V*1*，V*2*，… V*N*)*。在游戏的背景下，向量通常有两个、三个或四个分量。

例如，三维向量测量三个独特轴上的位移：*x*、*y*和*z*。向量的元素通常用表示它们代表的轴的下标，而不是索引。*(V*X*，V*Y*，V*Z*)*和*(V*0*，V*1*，V*2*)*可以互换使用。

在可视化向量时，它们通常被绘制为箭头。箭头的基部位置并不重要，因为向量测量的是位移，而不是位置。箭头的末端遵循每个轴上的位移。

例如，以下图中的所有箭头代表相同的向量：

![图 2.1：在多个位置绘制的向量(2, 5)](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_2.1_B16191.jpg)

图 2.1：在多个位置绘制的向量(2, 5)

每个箭头的长度相同，指向相同的方向，无论它们的位置如何。在下一节中，您将开始实现将在本书的其余部分中使用的向量结构。

# 创建一个向量

向量将被实现为结构，而不是类。向量结构将包含一个匿名联合，允许以数组或单独元素的形式访问向量的分量。

要声明`vec3`结构和函数头，请创建一个新文件`vec3.h`。在此文件中声明新的`vec3`结构。`vec3`结构需要三个构造函数——一个默认构造函数，一个以每个分量作为元素的构造函数，以及一个以浮点数组指针作为参数的构造函数：

```cpp
#ifndef _H_VEC3_
#define _H_VEC3_
struct vec3 {
    union {
        struct  {
            float x;
            float y;
            float z;
        };
        float v[3];
    };
    inline vec3() : x(0.0f), y(0.0f), z(0.0f) { }
    inline vec3(float _x, float _y, float _z) :
        x(_x), y(_y), z(_z) { }
    inline vec3(float *fv) :
        x(fv[0]), y(fv[1]), z(fv[2]) { }
};
#endif 
```

`vec3`结构中的匿名联合允许使用`.x`、`.y`和`.z`表示法访问数据，或者使用`.v`表示法作为连续数组访问。在继续实现在`vec3`结构上工作的函数之前，您需要考虑比较浮点数以及是否使用 epsilon 值。

## Epsilon

比较浮点数是困难的。您需要使用一个 epsilon 来比较两个浮点数，而不是直接比较它们。epsilon 是一个任意小的正数，是两个数字需要具有的最小差异，才能被视为不同的数字。在`vec3.h`中声明一个 epsilon 常量：

```cpp
#define VEC3_EPSILON 0.000001f
```

重要提示：

您可以在[`bitbashing.io/comparing-floats.html`](https://bitbashing.io/comparing-floats.html)了解更多关于浮点数比较的信息

通过创建`vec3`结构和定义`vec3` epsilon，您已经准备好开始实现一些常见的向量操作。在下一节中，您将开始学习和实现几种分量操作。

# 理解分量操作

几个向量操作只是分量操作。分量操作是指对向量的每个分量或两个向量的相似分量进行的操作。相似的分量是具有相同下标的分量。您将要实现的分量操作如下：

+   向量相加

+   向量减法

+   向量缩放

+   向量相乘

+   点积

让我们更详细地看看这些。

## 向量相加

将两个向量相加会产生一个第三个向量，它具有两个输入向量的合并位移。向量相加是一种分量操作；要执行它，您需要添加相似的分量。

要可视化两个向量的相加，将第二个向量的基部放在第一个向量的尖端。接下来，从第一个向量的基部到第二个向量的尖端画一个箭头。这个箭头代表了相加的结果向量：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_2.2_B16191.jpg)

图 2.2：向量相加

要在代码中实现向量相加，添加输入向量的相似分量。创建一个新文件`vec3.cpp`。这是您将定义与`vec3`结构相关的函数的地方。不要忘记包含`vec3.h`。重载`+运算符`以执行向量相加。不要忘记将函数签名添加到`vec3.h`中：

```cpp
vec3 operator+(const vec3 &l, const vec3 &r) {
    return vec3(l.x + r.x, l.y + r.y, l.z + r.z);
}
```

在考虑向量相加时，请记住向量表示位移。当添加两个向量时，结果是两个输入向量的合并位移。

## 向量减法

与添加向量一样，减去向量也是一种分量操作。您可以将减去向量视为将第二个向量的负值添加到第一个向量。当可视化为箭头时，减法指向从第二个向量的尖端到第一个向量的尖端。

为了直观地减去向量，将两个向量放置在同一个起点。从第二个箭头的尖端到第一个箭头的尖端画一个向量。得到的箭头就是减法结果向量：

![图 2.3：向量减法](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_2.3_B16191.jpg)

图 2.3：向量减法

要实现向量减法，减去相似的分量。通过在`vec3.cpp`中重载`-`运算符来实现减法函数。不要忘记将函数声明添加到`vec3.h`中：

```cpp
vec3 operator-(const vec3 &l, const vec3 &r) {
    return vec3(l.x - r.x, l.y - r.y, l.z - r.z);
}
```

步骤和逻辑与向量相加非常相似。将向量减法视为添加一个负向量可能会有所帮助。

## 缩放向量

当向量被缩放时，它只在大小上改变，而不改变方向。与加法和减法一样，缩放是一种分量操作。与加法和减法不同，向量是由标量而不是另一个向量进行缩放的。

在视觉上，一个缩放的向量指向与原始向量相同的方向，但长度不同。下图显示了两个向量：*(2, 1)*和*(2, 4)*。两个向量具有相同的方向，但第二个向量的大小更长：

![图 2.4：向量缩放](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_2.4_B16191.jpg)

图 2.4：向量缩放

要实现向量缩放，将向量的每个分量乘以给定的标量值。

通过在`vec3.cpp`中重载`*`运算符来实现缩放函数。不要忘记将函数声明添加到`vec3.h`中：

```cpp
vec3 operator*(const vec3 &v, float f) {
    return vec3(v.x * f, v.y * f, v.z * f);
}
```

通过将向量缩放*-1*来对向量取反。当对向量取反时，向量保持其大小，但改变其方向。

## 向量相乘

向量乘法可以被认为是一种非均匀缩放。与将向量的每个分量乘以标量不同，要将两个向量相乘，需要将向量的每个分量乘以另一个向量的相似分量。

您可以通过在`vec3.cpp`中重载`*`运算符来实现向量乘法。不要忘记将函数声明添加到`vec3.h`中：

```cpp
vec3 operator*(const vec3 &l, const vec3 &r) {
    return vec3(l.x * r.x, l.y * r.y, l.z * r.z);
}
```

通过将两个向量相乘生成的结果将具有不同的方向和大小。

## 点积

点积用于衡量两个向量的相似程度。给定两个向量，点积返回一个标量值。点积的结果具有以下属性：

+   如果向量指向相同的方向，则为正。

+   如果向量指向相反的方向，则为负。

+   如果向量垂直，则为*0*。

如果两个输入向量都具有单位长度（您将在本章的*法向量*部分了解单位长度向量），点积将具有*-1*到*1*的范围。

两个向量*A*和*B*之间的点积等于*A*的长度乘以*B*的长度乘以两个向量之间的角的余弦：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_02_001.jpg)

计算点积的最简单方法是对输入向量中相似的分量进行求和：

*![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_02_002.png)*

在`vec3.cpp`中实现`dot`函数。不要忘记将函数定义添加到`vec3.h`中：

```cpp
float dot(const vec3 &l, const vec3 &r) {
    return l.x * r.x + l.y * r.y + l.z * r.z;
}
```

点积是视频游戏中最常用的操作之一。它经常用于检查角度和光照计算。

通过点积，您已经实现了向量的常见分量操作。接下来，您将了解一些可以在向量上执行的非分量操作。

# 理解非分量操作

并非所有向量操作都是分量式的；一些操作需要更多的数学。在本节中，您将学习如何实现不基于分量的常见向量操作。这些操作如下：

+   如何找到向量的长度

+   法向量是什么

+   如何对向量进行归一化

+   如何找到两个向量之间的角度

+   如何投影向量以及拒绝是什么

+   如何反射向量

+   叉积是什么以及如何实现它

让我们更详细地看看每一个。

## 向量长度

向量表示方向和大小；向量的大小是它的长度。找到向量长度的公式来自三角学。在下图中，一个二维向量被分解为平行和垂直分量。注意这如何形成一个直角三角形，向量是斜边：

![图 2.5：一个向量分解为平行和垂直分量](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_2.5_B16191.jpg)

图 2.5：一个向量分解为平行和垂直分量

直角三角形的斜边长度可以用毕达哥拉斯定理找到，*A*2 *+ B*2 *= C*2。通过简单地添加一个*Z*分量，这个函数可以扩展到三维—*X*2 *+ Y*2 *+ Z*2 *= length*2\。

您可能已经注意到了一个模式；一个向量的平方长度等于其分量的和。这可以表示为一个点积—*Length*2*(A) = dot(A, A)*：

重要说明：

找到向量的长度涉及平方根运算，应尽量避免。在检查向量的长度时，可以在平方空间中进行检查以避免平方根。例如，如果您想要检查向量*A*的长度是否小于*5*，可以表示为*(dot(A, A) < 5 * 5)*。

1.  要实现平方长度函数，求出向量的每个分量的平方的和。在`vec3.cpp`中实现`lenSq`函数。不要忘记将函数声明添加到`vec3.h`中：

```cpp
float lenSq(const vec3& v) {
    return v.x * v.x + v.y * v.y + v.z * v.z;
}
```

1.  要实现长度函数，取平方长度函数的结果的平方根。注意不要用`sqrtf`调用`0`。在`vec3.cpp`中实现`lenSq`函数。不要忘记将函数声明添加到`vec3.h`中：

```cpp
float len(const vec3 &v) {
    float lenSq = v.x * v.x + v.y * v.y + v.z * v.z;
    if (lenSq < VEC3_EPSILON) {
        return 0.0f;
    }
    return sqrtf(lenSq);
}
```

重要说明：

您可以通过取它们之间的差的长度来找到两个向量之间的距离。例如，*float distance = len(vec1 - vec2)*。

## 归一化向量

长度为*1*的向量称为法向量（或单位向量）。通常，单位向量用于表示没有大小的方向。两个单位向量的点积总是在*-1*到*1*的范围内。

除了*0*向量外，任何向量都可以通过将向量按其长度的倒数进行缩放来归一化：

1.  在`vec3.cpp`中实现`normalize`函数。不要忘记将函数声明添加到`vec3.h`中：

```cpp
void normalize(vec3 &v) {
    float lenSq = v.x * v.x + v.y * v.y + v.z * v.z;
    if (lenSq < VEC3_EPSILON) { return; }
    float invLen = 1.0f / sqrtf(lenSq);    
    v.x *= invLen;
    v.y *= invLen;
    v.z *= invLen;
}
```

1.  在`vec3.cpp`中实现`normalized`函数。不要忘记将函数声明添加到`vec3.h`中：

```cpp
vec3 normalized(const vec3 &v) {
    float lenSq = v.x * v.x + v.y * v.y + v.z * v.z;
    if (lenSq < VEC3_EPSILON) { return v; }
    float invLen = 1.0f / sqrtf(lenSq);
    return vec3(
        v.x * invLen,
        v.y * invLen,
        v.z * invLen
    );
}
```

`normalize`函数接受一个向量的引用并就地对其进行归一化。另一方面，`normalized`函数接受一个常量引用并不修改输入向量。相反，它返回一个新的向量。

## 向量之间的角度

如果两个向量是单位长度，它们之间的角度是它们的点积的余弦：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_02_003.jpg)

如果两个向量未被归一化，则点积需要除以两个向量长度的乘积：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_02_004.jpg)

要找到实际角度，而不仅仅是其余弦，我们需要在两侧取余弦的反函数，即反余弦函数：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_02_005.jpg)

在`vec3.cpp`中实现`angle`函数。不要忘记将函数声明添加到`vec3.h`中：

```cpp
float angle(const vec3 &l, const vec3 &r) {
    float sqMagL = l.x * l.x + l.y * l.y + l.z * l.z;
    float sqMagR = r.x * r.x + r.y * r.y + r.z * r.z;
    if (sqMagL<VEC3_EPSILON || sqMagR<VEC3_EPSILON) {
        return 0.0f;
    }
    float dot = l.x * r.x + l.y * r.y + l.z * r.z;
    float len = sqrtf(sqMagL) * sqrtf(sqMagR);
    return acosf(dot / len);
}
```

重要说明：

`acosf`函数以弧度返回角度。要将弧度转换为度数，乘以`57.2958f`。要将度数转换为弧度，乘以`0.0174533f`。

## 向量投影和拒绝

将向量*A*投影到向量*B*上会产生一个新的向量，该向量在*B*的方向上具有*A*的长度。直观地理解向量投影的好方法是想象向量*A*投射到向量*B*上的阴影，如图所示：

![图 2.6：向量 A 投射到向量 B 上的阴影](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_2.6_B16191.jpg)

图 2.6：向量 A 投射到向量 B 上的阴影

要计算*A*在*B*上的投影(*proj*B *A*)，必须将向量*A*分解为相对于向量*B*的平行和垂直分量。平行分量是*A*在*B*方向上的长度，这就是投影。垂直分量是从*A*中减去平行分量，这就是拒绝：

![图 2.7：向量投影和拒绝显示平行和垂直向量](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_2.7_B16191.jpg)

图 2.7：向量投影和拒绝显示平行和垂直向量

如果被投影的向量（在这个例子中是向量*B*）是一个法向量，那么在*B*方向上的*A*的长度可以通过*A*和*B*的点积来简单计算。然而，如果两个输入向量都没有被归一化，点积需要除以向量*B*的长度（被投影的向量）。

现在，相对于*B*的平行分量已知，向量*B*可以被这个分量缩放。同样，如果*B*不是单位长度，结果将需要除以向量*B*的长度。

拒绝是投影的反面。要找到*A*在*B*上的拒绝，从向量*A*中减去*A*在*B*上的投影：

1.  在`vec3.cpp`中实现`project`函数。不要忘记将函数声明添加到`vec3.h`中：

```cpp
vec3 project(const vec3 &a, const vec3 &b) {
    float magBSq = len(b);
    if (magBSq < VEC3_EPSILON) {
        return vec3();
    }
    float scale = dot(a, b) / magBSq;
    return b * scale;
}
```

1.  在`vec3.cpp`中实现`reject`函数。不要忘记在`vec3.h`中声明这个函数：

```cpp
vec3 reject(const vec3 &a, const vec3 &b) {
    vec3 projection = project(a, b);
    return a - projection;
}
```

向量投影和拒绝通常用于游戏编程。重要的是它们在一个健壮的向量库中得到实现。

## 向量反射

向量反射可以有两种意思：镜像反射或弹跳反射。以下图显示了不同类型的反射：

![图 2.8：镜像和反弹反射的比较](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_2.8_B16191.jpg)

图 2.8：镜像和弹跳反射的比较

反弹反射比镜面反射更有用和直观。要使反弹投影起作用，将向量*A*投影到向量*B*上。这将产生一个指向反射相反方向的向量。对这个投影取反，并从向量 A 中减去两次。以下图演示了这一点：

![图 2.9：可视化反弹反射](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_2.9_B16191.jpg)

图 2.9：可视化反弹反射

在`vec3.cpp`中实现`reflect`函数。不要忘记将函数声明添加到`vec3.h`中：

```cpp
vec3 reflect(const vec3 &a, const vec3 &b) {
    float magBSq = len(b);
    if (magBSq < VEC3_EPSILON) {
        return vec3();
    }
    float scale = dot(a, b) / magBSq;
    vec3 proj2 = b * (scale * 2);
    return a - proj2;
}
```

矢量反射对物理学和人工智能很有用。我们不需要用反射来进行动画，但是最好实现这个功能以防需要时使用。

## 叉积

给定两个输入向量，叉积返回一个垂直于两个输入向量的第三个向量。叉积的长度等于两个向量形成的平行四边形的面积。

以下图展示了叉积在视觉上的样子。输入向量不一定要相隔 90 度，但以这种方式可更容易地将它们可视化：

![图 2.10：可视化叉积](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_2.10_B16191.jpg)

图 2.10：可视化叉积

找到叉积涉及一些矩阵运算，这将在下一章中更深入地介绍。现在，您需要创建一个 3x3 矩阵，其中顶行是结果向量。第二行和第三行应该填入输入向量。结果向量的每个分量的值是矩阵中该元素的次要。

3x3 矩阵中元素的次要是什么？它是较小的 2x2 子矩阵的行列式。假设你想要找到第一个分量的值，忽略第一行和第一列，得到一个较小的 2x2 子矩阵。以下图显示了每个分量的较小子矩阵：

![图 2.11：每个分量的子矩阵](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_2.11_B16191.jpg)

图 2.11：每个分量的子矩阵

要找到 2x2 矩阵的行列式，需要进行叉乘。将左上角和右下角的元素相乘，然后减去右上角和左下角元素的乘积。以下图显示了结果向量的每个元素的情况：

![图 2.12：结果向量中每个分量的行列式](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_2.12_B16191.jpg)

图 2.12：结果向量中每个分量的行列式

在`vec3.cpp`中实现`cross`乘积。不要忘记将函数声明添加到`vec3.h`中：

```cpp
vec3 cross(const vec3 &l, const vec3 &r) {
    return vec3(
        l.y * r.z - l.z * r.y,
        l.z * r.x - l.x * r.z,
        l.x * r.y - l.y * r.x
    );
}
```

点积与两个向量之间的夹角的余弦有关，而叉积与两个向量之间的正弦有关。两个向量之间的叉积的长度是两个向量的长度乘积，乘以它们之间的正弦值：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_02_006.jpg)

在下一节中，您将学习如何使用三种不同的技术在向量之间进行插值。

# 插值向量

两个向量可以通过缩放两个向量之间的差异并将结果添加回原始向量来进行线性插值。这种线性插值通常缩写为`lerp`。`lerp`的量是介于*0*和*1*之间的归一化值；这个归一化值通常用字母*t*表示。以下图显示了两个向量之间的`lerp`，以及* t *的几个值：

![图 2.13：线性插值](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_2.13_B16191.jpg)

图 2.13：线性插值

当*t = 0*时，插值向量与起始向量相同。当*t = 1*时，插值向量与结束向量相同。

在`vec3.cpp`中实现`lerp`函数。不要忘记将函数声明添加到`vec3.h`中：

```cpp
vec3 lerp(const vec3 &s, const vec3 &e, float t) {
    return vec3(
        s.x + (e.x - s.x) * t,
        s.y + (e.y - s.y) * t,
        s.z + (e.z - s.z) * t
    );
}
```

在两个向量之间进行线性插值将始终采用从一个向量到另一个向量的最短路径。有时，最短路径并不是最佳路径；您可能需要在最短弧线上插值两个向量。在最短弧线上插值被称为球面线性插值（`slerp`）。下图显示了几个*t*值的`slerp`和`lerp`过程之间的差异：

![图 2.14：比较 slerp 和 lerp](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_2.14_B16191.jpg)

图 2.14：比较 slerp 和 lerp

要实现`slerp`，找到两个输入向量之间的角度。假设角度已知，则`slerp`的公式如下

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_02_007.jpg)

在`vec3.cpp`中实现`slerp`函数。不要忘记将函数声明添加到`vec3.h`中。要注意当*t*的值接近*0*时，`slerp`会产生意外的结果。当*t*的值接近*0*时，可以退回到`lerp`或归一化的 lerp（下一节将介绍）：

```cpp
vec3 slerp(const vec3 &s, const vec3 &e, float t) {
    if (t < 0.01f) {
        return lerp(s, e, t);
    }
    vec3 from = normalized(s);
    vec3 to = normalized(e);
    float theta = angle(from, to);
    float sin_theta = sinf(theta);
    float a = sinf((1.0f - t) * theta) / sin_theta;
    float b = sinf(t * theta) / sin_theta;
    return from * a + to * b;
}
```

最后一个要介绍的插值方法是`nlerp`。`nlerp`是对`slerp`的近似。与`slerp`不同，`nlerp`在速度上不是恒定的。`nlerp`比`slerp`快得多，实现起来更容易；只需对`lerp`的结果进行归一化。下图比较了`lerp`、`slerp`和`nlerp`，其中*t = 0.25*：

![图 2.15：比较 lerp、slerp 和 nlerp](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_2.15_B16191.jpg)

图 2.15：比较 lerp、slerp 和 nlerp

在`vec3.cpp`中实现`nlerp`函数。不要忘记将函数声明添加到`vec3.h`中：

```cpp
vec3 nlerp(const vec3 &s, const vec3 &e, float t) {
    vec3 linear(
        s.x + (e.x - s.x) * t,
        s.y + (e.y - s.y) * t,
        s.z + (e.z - s.z) * t
    );
    return normalized(linear);
}
```

一般来说，`nlerp`比`slerp`更好。它是一个非常接近的近似，计算成本更低。唯一需要使用`slerp`的情况是如果需要恒定的插值速度。在本书中，您将使用`lerp`和`nlerp`来在向量之间进行插值。

在下一节中，您将学习如何使用 epsilon 值来比较向量的相等和不相等。

# 比较向量

需要实现的最后一个操作是向量比较。比较是一个逐分量的操作；每个元素都必须使用一个 epsilon 进行比较。另一种衡量两个向量是否相同的方法是将它们相减。如果它们相等，相减将产生一个长度为零的向量。

在`vec3.cpp`中重载`==`和`!=`运算符。不要忘记将函数声明添加到`vec3.h`中：

```cpp
bool operator==(const vec3 &l, const vec3 &r) {
    vec3 diff(l - r);
    return lenSq(diff) < VEC3_EPSILON;
}
bool operator!=(const vec3 &l, const vec3 &r) {
    return !(l == r);
}
```

重要提示：

找到用于比较操作的正确 epsilon 值是困难的。在本章中，您将`0.000001f`声明为 epsilon。这个值是一些试验的结果。要了解更多关于比较浮点值的信息，请访问[`bitbashing.io/comparing-floats.html`](https://bitbashing.io/comparing-floats.html)。

在下一节中，您将实现具有两个和四个分量的向量。这些向量将仅用作存储数据的便捷方式；它们实际上不需要在其上实现任何数学操作。

# 探索更多向量

在本书的后面某个时候，您还需要使用两个和四个分量的向量。两个和四个分量的向量不需要定义任何数学函数，因为它们将被专门用作传递数据到 GPU 的容器。

与您实现的三分量向量不同，两个和四个分量的向量需要同时存在为整数和浮点向量。为了避免重复代码，将使用模板来实现这两种结构：

1.  创建一个新文件`vec2.h`，并添加`vec2`结构的定义。所有`vec2`构造函数都是内联的；不需要`cpp`文件。`TVec2`结构是模板化的，使用`typedef`声明`vec2`和`ivec2`：

```cpp
template<typename T>
struct TVec2 {
    union {
        struct {
            T x;
            T y;
        };
        T v[2];
    };
    inline TVec2() : x(T(0)), y(T(0)) { }
    inline TVec2(T _x, T _y) :
        x(_x), y(_y) { }
    inline TVec2(T* fv) :
        x(fv[0]), y(fv[1]) { }
};
typedef TVec2<float> vec2;
typedef TVec2<int> ivec2;
```

1.  同样地，创建一个`vec4.h`文件，其中将保存`vec4`结构：

```cpp
template<typename T>
struct TVec4 {
    union {
        struct {
            T x;
            T y;
            T z;
            T w;
        };
        T v[4];
    };
    inline TVec4<T>(): x((T)0),y((T)0),z((T)0),w((T)0){}
    inline TVec4<T>(T _x, T _y, T _z, T _w) :
        x(_x), y(_y), z(_z), w(_w) { }
    inline TVec4<T>(T* fv) :
        x(fv[0]), y(fv[ ]), z(fv[2]), w(fv[3]) { }
};
typedef TVec4<float> vec4;
typedef TVec4<int> ivec4;
typedef TVec4<unsigned int> uivec4;
```

`vec2`，`ivec2`，`vec4`和`ivec4`结构的声明与`vec3`结构的声明非常相似。所有这些结构都可以使用组件下标或作为线性内存数组的指针来访问。它们的构造函数也非常相似。

# 摘要

在本章中，您已经学会了创建强大动画系统所需的向量数学知识。动画是一个数学密集型的主题；本章中学到的技能是完成本书其余部分所必需的。您已经为三维向量实现了所有常见的向量运算。`vec2`和`vec4`结构没有像`vec3`那样的完整实现，但它们只用于将数据发送到 GPU。

在下一章中，您将继续学习关于游戏相关数学的知识，学习关于矩阵的知识。


# 第三章：实现矩阵

在游戏动画的背景下，矩阵代表一个仿射变换。它将点从一个空间线性映射到另一个空间。一个网格由顶点表示，这些顶点只是空间中的点。通过将它们乘以一个矩阵，这些顶点被移动。

在本章中，您将学习矩阵数学以及如何在代码中实现矩阵。到本章结束时，您将建立一个强大的矩阵库，可以在任何项目中使用。矩阵很重要；它们在图形管线中扮演着重要角色。没有使用矩阵，很难渲染任何东西。

您只需要实现一个 4 x 4 的方阵。到本章结束时，您应该能够做到以下几点：

+   了解矩阵是什么

+   了解列主要矩阵存储

+   将矩阵相乘

+   反转矩阵

+   通过使用矩阵来转换点和向量

+   了解如何创建矩阵以查看三维世界

重要信息

在本章中，您将实现一个 4 x 4 的矩阵。矩阵的实现将依赖于代码来演示概念，而不是通过数学定义的格式。如果您对矩阵背后的正式数学感兴趣，请查看[`gabormakesgames.com/matrices.html`](https://gabormakesgames.com/matrices.html)。

# 技术要求

本章的可下载材料中提供了两个示例。`Sample00`显示了整个章节中编写的矩阵代码。`Sample01`显示了一个使用显式低阶矩阵来实现矩阵逆函数的替代实现。

# 什么是矩阵？

矩阵是一个二维数组。一个方阵是宽度和高度相同的矩阵。在本章中，您将实现一个 4 x 4 的矩阵；也就是说，一个有四行四列的矩阵。这个矩阵的元素将被存储为一个线性数组。

一个 4 x 4 的矩阵可以被看作是有四个分量的四个向量，或者是一个`vec4s`数组。如果这些向量代表矩阵的列，那么矩阵是列主要的。如果这些向量代表矩阵的行，那么它是行主要的。

假设一个 4 x 4 的矩阵包含字母* A，B，C，D … P *的字母表，它可以被构造为行主要或列主要矩阵。这在下面的*图 3.1*中有所示：

![图 3.1：比较行主要和列主要矩阵](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_3.1_B16191.jpg)

图 3.1：比较行主要和列主要矩阵

大多数数学书籍和 OpenGL 使用列主要矩阵。在本章中，您也将实现列主要矩阵。了解矩阵中包含的内容是很重要的。矩阵的对角线包含缩放信息，最后一列包含平移：

![图 3.2：矩阵中存储了什么？](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_3.2_B16191.jpg)

图 3.2：矩阵中存储了什么？

上面的 3 x 3 子矩阵包含三个向量；每个向量都是矩阵旋转的基向量。基向量是存储在矩阵中的上、右和前方向。您可能已经注意到旋转和比例组件在矩阵中占据了相同的空间。

## 矩阵存储

现在您知道矩阵布局将是列矩阵，下一个问题是如何存储实际的矩阵。矩阵存储是一个令人困惑的话题。

由于矩阵在内存中存储为线性数组，让我们弄清楚应该把元素放在哪里。行主要矩阵在内存中一次存储一行。列主要矩阵一次存储一列。

由于行主要和列主要矩阵都包含相同的向量，最终的线性映射结果是相同的，无论矩阵的主要性如何。下面的*图 3.3*演示了这一点：

![图 3.3：矩阵存储映射到线性数组](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_3.3_B16191.jpg)

图 3.3：矩阵存储映射到线性数组

您将要构建的矩阵类是一个列主矩阵，使用列存储；这意味着矩阵的物理内存布局与其元素的逻辑放置之间会有差异。很容易将具有线性内存布局的矩阵视为行矩阵，但请记住，这些行中的每一行实际上都是一列。

重要说明

将二维网格映射到线性存储的典型方法是`"行 * 列数 + 列"`。这种映射对于存储列主要矩阵是行不通的。当查看矩阵时，列 2，行 3 的元素应该具有线性索引 7，但是先前的映射得到的是 14。为了适应列主存储，映射公式是`"列 * 行数 + 行"`。

了解矩阵在内存中的存储方式很重要，它将影响数据的存储方式以及 API 如何访问这些数据。在下一节中，您将开始实现一个矩阵结构。

# 创建矩阵

在本节中，您将创建一个新的 4x4 矩阵。这个矩阵将以一个包含 16 个浮点数的数组的形式存储。将使用一个联合来以更易于使用的方式访问矩阵中的数据：

重要说明

单位矩阵是一个特殊的矩阵，它将任何东西乘以单位矩阵的结果都是原始矩阵。单位矩阵不进行映射。单位矩阵中所有元素都包含 0，除了主对角线，它完全由 1 组成。

1.  创建一个新文件，`mat4.h`。这个文件需要声明`mat4`结构。

1.  将以下结构声明添加到`mat4.h`，它通过声明一个由 16 个元素组成的平面数组作为联合的第一个成员来开始一个联合：

```cpp
struct mat4 {
    union {
        float v[16];
```

1.  联合的下一个成员是`vec4`变量的结构。每个`vec4`变量代表矩阵的一列；它们以存储在这些列中的基向量命名：

```cpp
        struct {
            vec4 right;
            vec4 up;
            vec4 forward;
            vec4 position;
        };
```

1.  根据基向量的元素访问成员可能是有用的。以下结构包含了命名对；第一个字母代表基向量，第二个字母代表该向量的分量：

```cpp
        struct { 
        //         row 1    row 2    row 3    row 4
        /*col 1*/float xx;float xy;float xz;float xw;
        /*col 2*/float yx;float yy;float yz;float yw;
        /*col 3*/float zx;float zy;float zz;float zw;
        /*col 4*/float tx;float ty;float tz;float tw;
        };
```

1.  下一个结构将允许您使用列-行表示法访问矩阵：

```cpp
        struct {
           float c0r0;float c0r1;float c0r2;float c0r3;
           float c1r0;float c1r1;float c1r2;float c1r3;
           float c2r0;float c2r1;float c2r2;float c2r3;
           float c3r0;float c3r1;float c3r2;float c3r3;
        };
```

1.  最后的结构将允许您使用行-列表示法访问矩阵：

```cpp
        struct {
           float r0c0;float r1c0;float r2c0;float r3c0;
           float r0c1;float r1c1;float r2c1;float r3c1;
           float r0c2;float r1c2;float r2c2;float r3c2;
           float r0c3;float r1c3;float r2c3;float r3c3;
        };
    }; // End union
```

1.  添加一个`inline`构造函数，可以创建单位矩阵：

```cpp
    inline mat4() :
       xx(1), xy(0), xz(0), xw(0),
       yx(0), yy(1), yz(0), yw(0),
       zx(0), zy(0), zz(1), zw(0),
       tx(0), ty(0), tz(0), tw(1) {}
```

1.  添加一个`inline`构造函数，可以从一个浮点数组创建矩阵：

```cpp
    inline mat4(float *fv) :
       xx( fv[0]), xy( fv[1]), xz( fv[2]), xw( fv[3]),
       yx( fv[4]), yy( fv[5]), yz( fv[6]), yw( fv[7]),
       zx( fv[8]), zy( fv[9]), zz(fv[10]), zw(fv[11]),
       tx(fv[12]), ty(fv[13]), tz(fv[14]), tw(fv[15]) { }
```

1.  添加一个`inline`构造函数，可以通过指定矩阵中的每个元素来创建矩阵：

```cpp
    inline mat4(
        float _00, float _01, float _02, float _03,
        float _10, float _11, float _12, float _13,
        float _20, float _21, float _22, float _23,
        float _30, float _31, float _32, float _33) :
        xx(_00), xy(_01), xz(_02), xw(_03),
        yx(_10), yy(_11), yz(_12), yw(_13),
        zx(_20), zy(_21), zz(_22), zw(_23),
        tx(_30), ty(_31), tz(_32), tw(_33) { }
}; // end mat4 struct
```

您刚刚声明的矩阵结构是最终的`mat4`结构；匿名联合提供了访问矩阵数据的五种不同方式。矩阵数据可以作为一个平面数组访问，作为四个列分别存储为`vec4`，或作为三个助记符之一访问。这三个助记符使用它们的基向量、它们的行然后列，或它们的列然后行来命名元素。

接下来，您将开始编写操作`mat4`结构的函数。您将实现常见的矩阵操作，如添加、缩放和相乘矩阵，并了解如何使用矩阵来转换向量和点。

# 常见的矩阵操作

在本节中，您将学习如何实现一些常见的矩阵操作。这些操作将在本书的后面章节中用于显示动画模型。具体来说，本节将涵盖如何比较、添加、缩放和相乘矩阵，以及如何使用矩阵来转换向量和点。

## 比较矩阵

比较矩阵是一个逐分量的操作。只有当两个矩阵的所有分量都相同时，它们才相同。要比较两个矩阵，循环遍历并比较它们的所有分量。由于比较的是浮点数，应该使用一个 epsilon。

创建一个新文件 `mat4.cpp`。在这个文件中实现矩阵的相等和不相等运算符。相等运算符应该检查两个矩阵是否相同；不相等运算符返回相等运算符的相反值。不要忘记将函数声明添加到 `mat4.h` 中：

```cpp
bool operator==(const mat4& a, const mat4& b) {
    for (int i = 0; i < 16; ++i) {
        if (fabsf(a.v[i] - b.v[i]) > MAT4_EPSILON) {
            return false;
        }
    }
    return true;
}
bool operator!=(const mat4& a, const mat4& b) {
    return !(a == b);
}
```

重要提示

`MAT4_EPSILON` 常量应该在 `mat4.h` 中定义。`0.000001f` 是一个很好的默认值。

当按组件比较矩阵时，您正在检查字面上的相等。还有其他定义矩阵相等的方法；例如，可以使用它们的行列式来比较两个矩阵的体积，而不考虑形状。矩阵的行列式将在本章后面介绍。

在下一节中，您将学习如何将矩阵相加。

## 矩阵相加

两个矩阵可以按组件相加。要将两个矩阵相加，求出它们各自的分量之和，并将结果存储在一个新矩阵中。矩阵加法可以与标量乘法一起使用，以在多个矩阵之间进行插值或混合。稍后，您将学习如何使用这个属性来实现动画蒙皮。

在 `mat4.cpp` 中实现矩阵加法函数。不要忘记将函数声明添加到 `mat4.h` 中：

```cpp
mat4 operator+(const mat4& a, const mat4& b) {
    return mat4(
        a.xx+b.xx, a.xy+b.xy, a.xz+b.xz, a.xw+b.xw,
        a.yx+b.yx, a.yy+b.yy, a.yz+b.yz, a.yw+b.yw,
        a.zx+b.zx, a.zy+b.zy, a.zz+b.zz, a.zw+b.zw,
        a.tx+b.tx, a.ty+b.ty, a.tz+b.tz, a.tw+b.tw
    );
}
```

矩阵加法很简单，但在显示动画网格中起着重要作用。在下一节中，您将学习如何将矩阵按标量值进行缩放。

## 矩阵缩放

矩阵可以通过浮点数进行缩放；这种缩放是一种按组件的操作。要缩放一个矩阵，将每个元素乘以提供的浮点数。

在 `mat4.cpp` 中实现矩阵缩放。不要忘记将函数声明添加到 `mat4.h` 中：

```cpp
mat4 operator*(const mat4& m, float f) {
    return mat4(
        m.xx * f, m.xy * f, m.xz * f, m.xw * f,
        m.yx * f, m.yy * f, m.yz * f, m.yw * f,
        m.zx * f, m.zy * f, m.zz * f, m.zw * f,
        m.tx * f, m.ty * f, m.tz * f, m.tw * f
    );
}
```

先缩放矩阵，然后将它们相加，可以让您在多个矩阵之间进行"lerp"或"mix"，只要这些矩阵都表示线性变换。在下一节中，您将学习如何将矩阵相乘。

## 矩阵乘法

矩阵乘法将两个矩阵的变换合并为一个矩阵。只有当两个矩阵的内部维度相同时，才能将两个矩阵相乘。以下是一些例子：

+   一个 4 x **4** 矩阵和一个 **4** x 4 矩阵可以相乘，因为内部维度都是 4。

+   一个 4 x **4** 矩阵和一个 **4** x 1 矩阵可以相乘，因为内部维度都是 4。

+   一个 4 x **4** 矩阵和一个 **1** x 4 矩阵不能相乘，因为内部维度 4 和 1 不匹配。

矩阵乘法的结果矩阵将具有相乘在一起的矩阵的外部维度。以下是一个例子：

+   一个 **4** x 4 矩阵和一个 4 x **4** 矩阵将产生一个 4 x 4 矩阵。

+   一个 **4** x 4 矩阵和一个 4 x **1** 矩阵将产生一个 4 x 1 矩阵。

+   一个 **1** x 4 矩阵和一个 4 x **2** 矩阵将产生一个 1 x 2 矩阵。

假设有两个矩阵，*A* 和 *B*。矩阵 *A* 在 *X* 轴上平移 10 个单位。矩阵 *B* 绕 *Y* 轴旋转 30 度。如果这两个矩阵相乘为 *A * B*，得到的矩阵将绕 *Y* 轴旋转 30 度，然后在 *X* 轴上平移 10 个单位。

矩阵乘法不是累积的。考虑上一个例子，但是将 *B * A* 相乘。当相乘 *B * A* 时，得到的矩阵将在 *X* 轴上平移 10 个单位，然后绕 *Y* 轴旋转 30 度。乘法顺序很重要；*A * B* 不同于 *B * A*。

这带来了一个新问题——矩阵应该以什么顺序相乘？如果 *M = A * B * C*，那么这些矩阵应该以什么顺序连接？*A*，*B*，然后 *C* 还是 *C*，*B*，然后 *A*？如果是 *A*，*B*，然后 *C*，矩阵乘法被定义为从左到右。但如果是 *C*，*B*，然后 *A*，矩阵乘法是从右到左。

为了与 OpenGL 保持一致，在本章中，您将实现从右到左的矩阵乘法。但是两个矩阵如何相乘呢？矩阵的每个元素都有一行和一列。任何元素的结果值都是左矩阵的该行与右矩阵的该列的点积。

例如，假设您想要找到两个矩阵相乘时第 2 行第 3 列的元素的值。这意味着取左侧矩阵的第 2 行和右侧矩阵的第 3 列进行点乘。*图 3.4*演示了这一点：

![图 3.4：矩阵相乘](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_3.4_B16191.jpg)

图 3.4：矩阵相乘

您可能已经注意到，在前面的图中，即使矩阵是列主序的，元素的下标也是先行后列。下标引用了矩阵的物理拓扑结构；它与矩阵中存储的内容或矩阵的布局方式无关。无论矩阵的主序是什么，下标索引都保持不变。执行以下步骤来实现矩阵乘法：

1.  为了使矩阵相乘的代码保持简洁，您需要创建一个辅助宏。该宏将假定有两个矩阵`a`和`b`。该宏将取两个数字，`a`的行和`b`的列，进行点乘，结果将是这两者的点积。在`mat4.cpp`中定义`M4D`宏：

```cpp
#define M4D(aRow, bCol) \
    a.v[0 * 4 + aRow] * b.v[bCol * 4 + 0] + \
    a.v[1 * 4 + aRow] * b.v[bCol * 4 + 1] + \
    a.v[2 * 4 + aRow] * b.v[bCol * 4 + 2] + \
    a.v[3 * 4 + aRow] * b.v[bCol * 4 + 3]
```

1.  在`mat4.cpp`中放置了`M4D`宏后，实现矩阵乘法函数。不要忘记将函数声明添加到`mat4.h`中。记住，例如`(2, 1)`元素应该取矩阵`a`的第 2 行和矩阵`b`的第 1 列进行点乘：

```cpp
mat4 operator*(const mat4 &a, const mat4 &b) {
   return mat4(
      M4D(0,0), M4D(1,0), M4D(2,0), M4D(3,0),//Col 0
      M4D(0,1), M4D(1,1), M4D(2,1), M4D(3,1),//Col 1
      M4D(0,2), M4D(1,2), M4D(2,2), M4D(3,2),//Col 2
      M4D(0,3), M4D(1,3), M4D(2,3), M4D(3,3) //Col 3
   );
}
```

矩阵相乘最重要的特性是将编码在两个矩阵中的变换合并为一个单独的矩阵。这很有用，因为您可以预先乘以某些矩阵，以执行更少的每帧乘法。接下来，您将了解矩阵如何将其变换数据应用于向量和点。

# 变换向量和点

点和向量的变换方式与矩阵相乘的方式相同。实际上，被变换的向量可以被视为具有 4 列 1 行的矩阵。这意味着变换向量就是将一个 4 x 4 矩阵和一个 4 x 1 矩阵相乘的问题。

当矩阵变换向量时，它会影响向量的方向和大小。当矩阵变换点时，它只是在空间中平移点。那么，向量和点之间有什么区别呢？向量的*w*分量为*0*，点的*W*分量为*1*。以下步骤将指导您实现矩阵-向量乘法：

1.  为了使矩阵-向量乘法更易于阅读，您需要再次创建一个宏。该宏将取矩阵的行并对该行与提供的列向量进行点积。在`mat4.cpp`中实现`M4VD`宏：

```cpp
#define M4V4D(mRow, x, y, z, w) \
    x * m.v[0 * 4 + mRow] + \
    y * m.v[1 * 4 + mRow] + \
    z * m.v[2 * 4 + mRow] + \
    w * m.v[3 * 4 + mRow]
```

1.  在`mat4.cpp`中放置了`M4V4D`宏后，实现矩阵-向量乘法函数。不要忘记将函数定义添加到`mat4.h`中：

```cpp
vec4 operator*(const mat4& m, const vec4& v) {
    return vec4(
        M4V4D(0, v.x, v.y, v.z, v.w),
        M4V4D(1, v.x, v.y, v.z, v.w),
        M4V4D(2, v.x, v.y, v.z, v.w),
        M4V4D(3, v.x, v.y, v.z, v.w) 
    );
}
```

1.  本书中的大部分数据将被存储为三分量向量，而不是四分量。每次需要通过矩阵进行变换时，都无需创建一个新的四分量向量；相反，您将为此创建一个专门的函数。

1.  在`mat4.cpp`中定义一个新函数：`transformVector`。不要忘记将函数声明添加到`mat4.h`中。该函数将使用提供的矩阵对`vec3`进行变换，假设该向量表示方向和大小：

```cpp
vec3 transformVector(const mat4& m, const vec3& v) {
    return vec3(
        M4V4D(0, v.x, v.y, v.z, 0.0f),
        M4V4D(1, v.x, v.y, v.z, 0.0f),
        M4V4D(2, v.x, v.y, v.z, 0.0f) 
    );
}
```

1.  接下来，在`mat4.cpp`中定义`transformPoint`函数。它应该将向量和矩阵相乘，假设向量的 W 分量为 1：

```cpp
vec3 transformPoint(const mat4& m, const vec3& v) {
    return vec3(
        M4V4D(0, v.x, v.y, v.z, 1.0f),
        M4V4D(1, v.x, v.y, v.z, 1.0f),
        M4V4D(2, v.x, v.y, v.z, 1.0f)
    );
}
```

1.  为`transformPoint`定义一个重载，它带有额外的*W*分量。*W*分量是一个引用——它是可读写的。函数执行后，*w*分量将保存*W*的值，如果输入向量是`vec4`的话：

```cpp
vec3 transformPoint(const mat4& m, const vec3& v, float& w) {
    float _w = w;
    w = M4V4D(3, v.x, v.y, v.z, _w);
    return vec3(
        M4V4D(0, v.x, v.y, v.z, _w),
        M4V4D(1, v.x, v.y, v.z, _w),
        M4V4D(2, v.x, v.y, v.z, _w)
    );
}
```

在本书的其余部分，大多数数据都存储在`vec3`结构中。这意味着将使用`transformVector`和`transformPoint`，而不是重载的乘法运算符。这应有助于减少对被转换数据的歧义。接下来，您将学习如何求矩阵的逆。

# 求逆矩阵

将矩阵乘以其逆矩阵总是会得到单位矩阵。逆矩阵具有非逆矩阵的相反映射。并非所有矩阵都有逆矩阵。只有行列式非零的矩阵才能被求逆。

求逆矩阵是一个重要的操作；用于将三维对象转换为屏幕上显示的视图矩阵是相机位置和旋转的逆矩阵。另一个逆矩阵变得重要的地方是蒙皮，这将在*第十章**，网格蒙皮*中介绍。

找到矩阵的逆矩阵相当复杂，因为它需要其他支持函数（如转置和伴随矩阵）。在本节中，您将首先构建这些支持函数，然后在它们都构建完成后构建逆函数。因此，首先需要转置矩阵。

## 转置

要转置矩阵，需要沿着其主对角线翻转矩阵的每个元素。例如，*2, 1*元素将变为*1, 2*元素。两个下标都相同的元素，如*1, 1*，将保持不变：

1.  在`mat4.cpp`中实现`transpose`函数。不要忘记将函数声明添加到`mat4.h`中：

```cpp
#define M4SWAP(x, y) \
    {float t = x; x = y; y = t; }
void transpose(mat4 &m) {
    M4SWAP(m.yx, m.xy);
    M4SWAP(m.zx, m.xz);
    M4SWAP(m.tx, m.xw);
    M4SWAP(m.zy, m.yz);
    M4SWAP(m.ty, m.yw);
    M4SWAP(m.tz, m.zw);
}
```

1.  在`mat4.cpp`中创建一个`transposed`函数。`transposed`函数修改传入的矩阵。不要忘记将函数声明添加到`mat4.h`中：

```cpp
mat4 transposed(const mat4 &m) {
    return mat4(
        m.xx, m.yx, m.zx, m.tx,
        m.xy, m.yy, m.zy, m.ty,
        m.xz, m.yz, m.zz, m.tz,
        m.xw, m.yw, m.zw, m.tw
    );
}
```

如果需要将矩阵从行优先顺序转换为列优先顺序，或者反之，则转置矩阵是有用的。在下一节中，您将学习如何计算方阵的行列式。

## 行列式和低阶矩阵的小数

要找到 4 x 4 矩阵的行列式，首先要了解低阶矩阵的行列式和小数是什么。行列式函数是递归的；要找到 4 x 4 矩阵的行列式，我们需要找到几个 3 x 3 和 2 x 2 矩阵的行列式。

矩阵的行列式始终是一个标量值；只有方阵有行列式。如果矩阵被转置，其行列式保持不变。

在接下来的几节中，您将学习如何找到 2 x 2 矩阵的行列式，任意大小矩阵的小数矩阵以及任意大小矩阵的余子式。这些方法是拉普拉斯展开的基本组成部分，您将用它们来找到任意大小矩阵的行列式。

### 2 x 2 行列式

要找到 2 x 2 矩阵的行列式，需要减去对角线元素的乘积。以下图示了这一点：

![图 3.5：2 x 2 矩阵和行列式的公式](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_3.5_B16191.jpg)

图 3.5：2 x 2 矩阵和行列式的公式

### 小数

矩阵中的每个元素都有一个小数。元素的小数是消除该元素的行和列后得到的较小矩阵的行列式。例如，考虑一个 3 x 3 矩阵——元素*2, 1*的小数是什么？

首先，从矩阵中消除第 2 行和第 1 列。这将导致一个较小的 2 x 2 矩阵。这个 2 x 2 矩阵的行列式就是元素*2, 1*的小数。以下图示了这一点：

![图 3.6：3 x 3 矩阵中元素 2, 1 的小数](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_3.6_B16191.jpg)

图 3.6：3 x 3 矩阵中元素 2, 1 的小数

这个公式也适用于更高维度的矩阵。例如，4x4 矩阵中一个元素的余子式是一些较小的 3x3 矩阵的行列式。余子式矩阵是一个矩阵，其中每个元素都是输入矩阵对应元素的余子式。

### 余子式

要找到矩阵的余子式，首先计算余子式矩阵。得到余子式矩阵后，将矩阵中的每个元素*(i, j)*乘以*-1*的*i+j*次幂。加-1(i+j)power 的值形成一个方便的棋盘格图案，其中*+*始终位于左上角：

![图 3.7：-1 到 i+j 次幂的棋盘格图案](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Figure_3.7_B16191.jpg)

图 3.7：-1 到 i+j 次幂的棋盘格图案

前面的图表显示了 Add -1(i+j)创建的棋盘格图案。请注意，图案始终从左上角的正元素开始。

### 拉普拉斯展开

任何方阵的行列式（如果存在）都可以通过拉普拉斯展开来找到。要执行此操作，首先找到余子式矩阵。接下来，将原始矩阵的第一行中的每个元素乘以余子式矩阵中相应的第一行的元素。行列式是这些乘积的总和：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_03_001.jpg)

### 伴随矩阵

在您可以反转矩阵之前的最后一个操作是找到矩阵的伴随矩阵。矩阵的伴随矩阵是余子式矩阵的转置。实现伴随矩阵很简单，因为您已经知道如何找到矩阵的余子式以及如何对矩阵进行转置。

### 逆

要找到矩阵的逆，需要将矩阵的伴随矩阵除以其行列式。由于标量矩阵除法未定义，因此需要将伴随矩阵乘以行列式的倒数。

重要说明

在本章中，您将构建一个矩阵乘法函数，该函数使用宏来避免对低阶矩阵的需求。本书的可下载材料中的`Chapter03/Sample01`示例提供了一个实现，该实现利用了低阶矩阵，并且更容易通过调试器进行调试。

要实现矩阵的逆函数，首先需要能够找到 4x4 矩阵的行列式和伴随矩阵。这两个函数都依赖于能够找到矩阵中元素的余子式：

1.  在`mat4.cpp`中创建一个新的宏。该宏将找到矩阵中一个元素的余子式，给定一个浮点数数组，以及从矩阵中切割的三行和三列：

```cpp
#define M4_3X3MINOR(x, c0, c1, c2, r0, r1, r2) \
   (x[c0*4+r0]*(x[c1*4+r1]*x[c2*4+r2]-x[c1*4+r2]* \
   x[c2*4+r1])-x[c1*4+r0]*(x[c0*4+r1]*x[c2*4+r2]- \
   x[c0*4+r2]*x[c2*4+r1])+x[c2*4+r0]*(x[c0*4+r1]* \
   x[c1*4+r2]-x[c0*4+r2]*x[c1*4+r1]))
```

1.  使用定义的`M4_3X3MINOR`宏，在`mat4.cpp`中实现`determinant`函数。由于行列式将每个元素乘以余子式，因此需要对一些值进行取反。不要忘记将函数声明添加到`mat4.h`中：

```cpp
float determinant(const mat4& m) {
   return  m.v[0] *M4_3X3MINOR(m.v, 1, 2, 3, 1, 2, 3)  
         - m.v[4] *M4_3X3MINOR(m.v, 0, 2, 3, 1, 2, 3)  
         + m.v[8] *M4_3X3MINOR(m.v, 0, 1, 3, 1, 2, 3)  
         - m.v[12]*M4_3X3MINOR(m.v, 0, 1, 2, 1, 2, 3); 
}
```

1.  接下来，在`mat4.cpp`中实现`adjugate`函数。不要忘记将函数声明添加到`mat4.h`中。使用`M4_3X3MINOR`宏找到余子式矩阵，然后对适当的元素取反以创建余子式矩阵。最后，返回余子式矩阵的转置：

```cpp
mat4 adjugate(const mat4& m) {
   //Cof (M[i, j]) = Minor(M[i, j]] * pow(-1, i + j)
   mat4 cofactor;
   cofactor.v[0] = M4_3X3MINOR(m.v, 1, 2, 3, 1, 2, 3);
   cofactor.v[1] =-M4_3X3MINOR(m.v, 1, 2, 3, 0, 2, 3);
   cofactor.v[2] = M4_3X3MINOR(m.v, 1, 2, 3, 0, 1, 3);
   cofactor.v[3] =-M4_3X3MINOR(m.v, 1, 2, 3, 0, 1, 2);
   cofactor.v[4] =-M4_3X3MINOR(m.v, 0, 2, 3, 1, 2, 3);
   cofactor.v[5] = M4_3X3MINOR(m.v, 0, 2, 3, 0, 2, 3);
   cofactor.v[6] =-M4_3X3MINOR(m.v, 0, 2, 3, 0, 1, 3);
   cofactor.v[7] = M4_3X3MINOR(m.v, 0, 2, 3, 0, 1, 2);
   cofactor.v[8] = M4_3X3MINOR(m.v, 0, 1, 3, 1, 2, 3);
   cofactor.v[9] =-M4_3X3MINOR(m.v, 0, 1, 3, 0, 2, 3);
   cofactor.v[10]= M4_3X3MINOR(m.v, 0, 1, 3, 0, 1, 3);
   cofactor.v[11]=-M4_3X3MINOR(m.v, 0, 1, 3, 0, 1, 2);
   cofactor.v[12]=-M4_3X3MINOR(m.v, 0, 1, 2, 1, 2, 3);
   cofactor.v[13]= M4_3X3MINOR(m.v, 0, 1, 2, 0, 2, 3);
   cofactor.v[14]=-M4_3X3MINOR(m.v, 0, 1, 2, 0, 1, 3);
   cofactor.v[15]= M4_3X3MINOR(m.v, 0, 1, 2, 0, 1, 2);
   return transposed(cofactor);
}
```

1.  现在`determinant`和`adjugate`函数已经完成，实现 4x4 矩阵的`inverse`函数应该很简单。在`mat4.cpp`中实现`inverse`函数。不要忘记将函数声明添加到`mat4.h`中：

```cpp
mat4 inverse(const mat4& m) {
    float det = determinant(m);

    if (det == 0.0f) {
        cout << " Matrix determinant is 0\n";
        return mat4();
    }
    mat4 adj = adjugate(m);
    return adj * (1.0f / det);
}
```

1.  `inverse`函数接受一个常量矩阵引用，并返回一个新的矩阵，该矩阵是提供矩阵的逆矩阵。在`mat4.cpp`中实现一个`invert`便利函数。这个便利函数将内联地反转矩阵，修改参数。不要忘记将函数声明添加到`mat4.h`中：

```cpp
void invert(mat4& m) {
    float det = determinant(m);
    if (det == 0.0f) {
        std::cout << "Matrix determinant is 0\n";
        m = mat4();
        return;
    }
    m = adjugate(m) * (1.0f / det);
}
```

矩阵的求逆是一个相对昂贵的函数。只编码位置和旋转的矩阵可以更快地求逆，因为 3x3 旋转矩阵的逆矩阵与其转置矩阵相同。

在实现`lookAt`函数时，您将学习如何实现这个快速的逆函数。

# 创建相机矩阵

矩阵也用于相机变换，包括透视变换。透视变换将视锥体映射到 NDC 空间。NDC 空间通常在所有轴上的范围为-1 到+1。与世界/眼坐标不同，NDC 空间是左手坐标系。

在本节中，您将学习如何创建相机变换矩阵。第一个相机矩阵是一个视锥体，看起来像一个顶部被切掉的金字塔。视锥体代表相机可见的一切。您还将学习如何创建不同的投影，并实现一个“look at”函数，让您轻松创建视图矩阵。

## 视锥体

在视觉上，视锥体看起来像一个顶部被切掉的金字塔。视锥体有六个面；它代表相机可以看到的空间。在`mat4.cpp`中创建`frustum`函数。该函数接受 left、right、bottom、top、near 和 far 值：

```cpp
mat4 frustum(float l, float r, float b, 
             float t, float n, float f) {
    if (l == r || t == b || n == f) {
        std::cout << "Invalid frustum\n";
        return mat4(); // Error
    }
    return mat4(
        (2.0f * n) / (r - l),0, 0, 0,
        0,  (2.0f * n) / (t - b), 0, 0,
        (r+l)/(r-l), (t+b)/(t-b), (-(f+n))/(f-n), -1,
        0, 0, (-2 * f * n) / (f - n), 0
    );
}
```

重要提示

推导视锥体矩阵的细节超出了本书的范围。有关如何推导该函数的更多信息，请查看[`www.songho.ca/opengl/gl_projectionmatrix.html`](http://www.songho.ca/opengl/gl_projectionmatrix.html)。

`frustum`函数可用于构建视锥体，但函数参数不直观。在下一节中，您将学习如何从更直观的参数创建视锥体。

## 透视

透视矩阵是由视野（通常以度为单位）、宽高比和近远距离构建的。它是创建视锥体的一种简单方式。

在`mat4.cpp`中实现`perspective`函数。不要忘记将函数声明添加到`mat4.h`中：

```cpp
mat4 perspective(float fov, float aspect, float n,float f){
    float ymax = n * tanf(fov * 3.14159265359f / 360.0f);
    float xmax = ymax * aspect;
    return frustum(-xmax, xmax, -ymax, ymax, n, f);
}
```

`perspective`函数将在本书其余部分的几乎所有视觉图形演示中使用。这是创建视锥体的一种非常方便的方式。

## 正交

正交投影没有透视效果。正交投影线性映射到 NDC 空间。正交投影通常用于二维游戏。它经常用于实现等距透视。

在`mat4.cpp`中实现`ortho`函数。不要忘记将函数声明添加到`mat4.h`中：

```cpp
mat4 ortho(float l, float r, float b, float t, 
           float n, float f) {
    if (l == r || t == b || n == f) {
        return mat4(); // Error
    }
    return mat4(
        2.0f / (r - l), 0, 0, 0,
        0, 2.0f / (t - b), 0, 0,
        0, 0, -2.0f / (f - n), 0,
        -((r+l)/(r-l)),-((t+b)/(t-b)),-((f+n)/(f-n)), 1
    );
}
```

正交视图投影通常用于显示 UI 或其他二维元素。

## 观察

视图矩阵是相机变换的逆矩阵（相机的位置、旋转和缩放）。您将实现一个`lookAt`函数，直接生成该矩阵，而不是创建相机的变换矩阵然后求逆。

`lookAt`函数通常接受一个`位置`、相机所看的`目标点`和一个参考`上方向`。其余的工作是找到倒置的基向量，并确定位置在哪里。

由于基向量是正交的，它们的逆矩阵与它们的转置矩阵相同。位置可以通过将位置列向量与倒置的基向量的点积取反来计算。

在`mat4.cpp`中实现`lookAt`函数。不要忘记将函数声明添加到`mat4.h`中。记住，视图矩阵将游戏世界映射到正*Z*轴：

```cpp
mat4 lookAt(const vec3& position, const vec3& target, 
            const vec3& up) {
    vec3 f = normalized(target - position) * -1.0f;
    vec3 r = cross(up, f); // Right handed
    if (r == vec3(0, 0, 0)) {
        return mat4(); // Error
    }
    normalize(r);
    vec3 u = normalized(cross(f, r)); // Right handed
    vec3 t = vec3(
        -dot(r, position),
        -dot(u, position),
        -dot(f, position)
    );
    return mat4(
        // Transpose upper 3x3 matrix to invert it
        r.x, u.x, f.x, 0,
        r.y, u.y, f.y, 0,
        r.z, u.z, f.z, 0,
        t.x, t.y, t.z, 1
    );
}
```

`lookAt`函数是构建视图矩阵最方便的方法。本书其余部分的所有代码示例都将使用`lookAt`函数来设置视图矩阵。

# 总结

在本章中，您学习了处理四维方阵所需的数学知识，并实现了一个可重用的矩阵库。矩阵通常用于编码变换信息；它们几乎在图形管线的每一步都被用来在屏幕上显示模型。

在下一章中，您将学习如何使用四元数编码旋转数据。


# 第四章：实现四元数

在本章中，您将学习有关四元数的知识。四元数用于编码旋转。四元数是以*x*i *+ y*j *+ z*k *+ w*形式的复数。想象一下*i，*j，

和*k*作为每个代表三维轴的占位符。*w*是一个实数。虽然四元数不直接编码角轴对，但很容易将它们想象为

就像那样——围绕任意轴旋转。

在本章结束时，您应该对四元数是什么以及如何使用它们有很强的理解，并且您将在代码中实现了一个强大的四元数类。本章将涵盖以下主题：

+   创建四元数的不同方法

+   检索四元数的角度和轴

+   基本的分量操作

+   两个四元数的长度和点积

+   反转四元数

+   组合四元数

+   通过四元数变换向量

+   在四元数之间插值

+   将四元数和矩阵转换

为什么四元数很重要？大多数人形动画只使用旋转——不需要平移或缩放。例如，想象一下肘关节。肘部的自然运动只是旋转。如果您想要将肘部平移到空间中，您需要旋转肩膀。四元数编码旋转，并且它们插值得很好。

重要信息：

在本章中，您将以直观的代码优先方法实现四元数。如果您对四元数背后更正式的数学感兴趣，请查看[`gabormakesgames.com/quaternions.html`](https://gabormakesgames.com/quaternions.html)。

# 创建四元数

四元数用于编码旋转数据。在代码中，四元数将有四个分量。它们类似于`vec4`，因为它们有`x`、`y`、`z`和`w`分量。

与`vec4`一样，`w`分量最后出现。

`quat`结构应该有两个构造函数。默认构造函数创建一个单位四元数，`(0, 0, 0, 1)`。`(0, 0, 0, 1)`单位四元数就像`1`。任何数乘以`1`仍然保持不变。同样，任何四元数乘以单位四元数仍然保持不变：

创建一个新文件`quat.h`，声明四元数结构。`quat`结构将在本书的其余部分中用于表示旋转：

```cpp
#ifndef _H_QUAT_
#define _H_QUAT_
#include "vec3.h"
#include "mat4.h"
struct quat {
   union {
       struct {
           float x;
           float y;
           float z;
           float w;
       };
       struct {
           vec3 vector;
           float scalar;
       };
       float v[4];
   };
   inline quat() :
       x(0), y(0), z(0), w(1) { }
   inline quat(float _x, float _y, float _z, float _w)
               : x(_x), y(_y), z(_z), w(_w) {}
};
#endif
```

`quat`结构内的匿名联合将允许您通过`X`、`Y`、`Z`和`W`下标符号访问四元数内的数据，作为矢量和标量对，或作为浮点值数组。

接下来，您将学习如何开始创建四元数。

## 角轴

四元数通常使用旋转轴和角度创建。关于轴的旋转*θ*可以在球面上表示为任何有向弧，其长度为![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_001.png)，位于垂直于旋转轴的平面上。正角度产生绕轴的逆时针旋转。

创建一个新文件`quat.cpp`。在`quat.cpp`中实现`angleAxis`函数。不要忘记将函数声明添加到`quat.h`中：

```cpp
#include "quat.h"
#include <cmath>
quat angleAxis(float angle, const vec3& axis) {
    vec3 norm = normalized(axis);
    float s = sinf(angle * 0.5f);
    return quat(norm.x * s,
                norm.y * s,
                norm.z * s,
                cosf(angle * 0.5f)
    );
}
```

为什么！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_002.png)？四元数可以跟踪两个完整的旋转，即*720*度。这使得四元数的周期为*720*度。sin/cos 的周期是*360*度。将*θ*除以*2*将四元数的范围映射到 sin/cos 的范围。

在本节中，您学习了如何编码旋转的角度和轴

四元数。在下一节中，您将学习如何构建一个角度和一个轴

用于两个向量之间的旋转，并将其编码为四元数。

## 从一个向量到另一个向量创建旋转

任何两个单位向量都可以表示球面上的点。这些点之间的最短弧位于包含这两个点和球心的平面上。这个平面

垂直于这两个向量之间的旋转轴。

要找到旋转轴，需要对输入向量进行归一化。找到输入向量的叉积。这就是旋转轴。找到输入向量之间的角度。从*第二章*，*实现向量*中，两个向量之间角度的公式为![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_003.png)。由于两个输入向量都被归一化了，这简化为![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_004.png)，这意味着*θ*的余弦是输入向量的点积：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_005.png)

你会记得从*第二章*，*实现向量*中，点积与两个向量之间夹角的余弦有关，而叉积与两个向量之间夹角的正弦有关。在创建四元数时，点积和叉积具有以下属性：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_006.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_007.png)

叉积可以扩展为*x*、*y*和*z*分量，前面的方程开始看起来像是从角度和旋转轴创建四元数的代码。找到两个向量之间的角度会很昂贵，但可以计算出半角而不知道角度是多少。

要找到半角，找到*v1*和*v2*输入向量之间的中间向量。使用*v1*和这个中间向量构造一个四元数。这将创建一个导致所需旋转的四元数。

有一个特殊情况——当*v1*和*v2*平行时会发生什么？或者如果*v1== -v2*？用于找到旋转轴的叉积会产生一个*0*向量。如果发生这种特殊情况，找到两个向量之间最垂直的向量来创建一个纯四元数。

执行以下步骤来实现`fromTo`函数：

1.  开始在`quat.cpp`中实现`fromTo`函数，并在`quat.h`中添加函数声明。首先对`from`和`to`向量进行归一化，确保它们不是相同的向量：

```cpp
quat fromTo(const vec3& from, const vec3& to) {
   vec3 f = normalized(from);
   vec3 t = normalized(to);
   if (f == t) {
      return quat();
   }
```

1.  接下来，检查两个向量是否互为相反。如果是的话，`from`向量的最正交轴可以用来创建一个纯四元数：

```cpp
   else if (f == t * -1.0f) {
      vec3 ortho = vec3(1, 0, 0);
      if (fabsf(f.y) <fabsf(f.x)) {
         ortho = vec3(0, 1, 0);
      }
      if (fabsf(f.z)<fabs(f.y) && fabs(f.z)<fabsf(f.x)){
         ortho = vec3(0, 0, 1);
      }
      vec3 axis = normalized(cross(f, ortho));
      return quat(axis.x, axis.y, axis.z, 0);
   }
```

1.  最后，创建一个`from`和`to`向量之间的半向量。使用半向量和起始向量的叉积来计算旋转轴，使用两者的点积来找到旋转角度：

```cpp
   vec3 half = normalized(f + t); 
   vec3 axis = cross(f, half);
   return quat(axis.x, axis.y, axis.z, dot(f, half));
}
```

`fromTo`函数是创建四元数的最直观方式之一。接下来，你将学习如何检索定义四元数的角度和轴。

# 检索四元数数据

由于可以从角度和轴创建四元数，因此可以合理地期望能够从四元数中检索相同的角度和轴。要检索旋转轴，需要对四元数的向量部分进行归一化。旋转角度是实部的反余弦的两倍。

在`quat.cpp`中实现`getAngle`和`getAxis`函数，并在`quat.h`中为两个函数添加函数声明：

```cpp
vec3 getAxis(const quat& quat) {
    return normalized(vec3(quat.x, quat.y, quat.z));
}
float getAngle(const quat& quat) {
    return 2.0f * acosf(quat.w);
}
```

能够检索定义四元数的角度和轴将在以后一些四元数操作中需要。

接下来，你将学习常用的四元数分量操作。

# 常见的四元数操作

与向量一样，四元数也有分量操作。常见的

分量操作包括加法、减法、乘法或否定

四元数。分量乘法将四元数相乘

通过单个标量值。

由于这些函数是分量操作，它们只是对输入四元数的相似分量执行适当的操作。在`quat.cpp`中实现这些函数，并在`quat.h`中为每个函数添加声明：

```cpp
quat operator+(const quat& a, const quat& b) {
    return quat(a.x+b.x, a.y+b.y, a.z+b.z, a.w+b.w);
}
quat operator-(const quat& a, const quat& b) {
    return quat(a.x-b.x, a.y-b.y, a.z-b.z, a.w-b.w);
}
quat operator*(const quat& a, float b) {
    return quat(a.x * b, a.y * b, a.z * b, a.w * b);
}
quat operator-(const quat& q) {
    return quat(-q.x, -q.y, -q.z, -q.w);
}
```

这些分量级的操作本身并没有太多实际用途。它们是构建四元数功能的基本组件。接下来，您将学习有关比较四元数的不同方法。

# 比较操作

比较两个四元数可以逐分量进行。即使两个四元数在分量级别上不相同，它们仍然可以表示相同的旋转。这是因为一个四元数及其逆旋转到相同的位置，但它们采取不同的路径。

1.  在`quat.cpp`中重载`==`和`!=`运算符。将这些函数的声明添加到`quat.h`中：

```cpp
bool operator==(const quat& left, const quat& right) {
    return (fabsf(left.x - right.x) <= QUAT_EPSILON &&
            fabsf(left.y - right.y) <= QUAT_EPSILON &&
            fabsf(left.z - right.z) <= QUAT_EPSILON &&
            fabsf(left.w - right.w) <= QUAT_EPSILON);
}
bool operator!=(const quat& a, const quat& b) {
    return !(a == b);
}
```

1.  要测试两个四元数是否代表相同的旋转，需要测试两者之间的绝对差异。在`quat.cpp`中实现`sameOrientation`函数。将函数声明添加到`quat.h`中：

```cpp
bool sameOrientation(const quat&l, const quat&r) {
    return (fabsf(l.x - r.x) <= QUAT_EPSILON  &&
            fabsf(l.y - r.y) <= QUAT_EPSILON  &&
            fabsf(l.z - r.z) <= QUAT_EPSILON  &&
            fabsf(l.w - r.w) <= QUAT_EPSILON) ||
           (fabsf(l.x + r.x) <= QUAT_EPSILON  &&
            fabsf(l.y + r.y) <= QUAT_EPSILON  &&
            fabsf(l.z + r.z) <= QUAT_EPSILON  &&
            fabsf(l.w + r.w) <= QUAT_EPSILON);
}
```

大多数情况下，您将希望使用相等运算符来比较四元数。`sameOrientation`函数不太有用，因为四元数的旋转可以在四元数被反转时发生变化。

在下一节中，您将学习如何实现四元数点积。

# 点积

与向量一样，点积测量两个四元数的相似程度。实现与向量实现相同。相乘相同的分量并求和结果。

在`quat.cpp`中实现四元数点积函数，并将其声明添加到`quat.h`中：

```cpp
float dot(const quat& a, const quat& b) {
    return a.x * b.x + a.y * b.y + a.z * b.z + a.w * b.w;
}
```

与向量一样，四元数的长度是四元数与自身的点积。在下一节中，您将学习如何找到四元数的平方长度和长度。

# 长度和平方长度

与向量一样，四元数的平方长度与四元数与自身的点积相同。四元数的长度是平方长度的平方根：

1.  在`quat.cpp`中实现`lenSq`函数，并在`quat.h`中声明该函数：

```cpp
float lenSq(const quat& q) {
  return q.x * q.x + q.y * q.y + q.z * q.z + q.w * q.w;
}
```

1.  在`quat.cpp`中实现`len`函数。不要忘记将函数声明添加到`quat.h`中：

```cpp
float len(const quat& q) {
  float lenSq = q.x*q.x + q.y*q.y + q.z*q.z + q.w*q.w;
  if (lenSq< QUAT_EPSILON) {
     return 0.0f;
  }
  return sqrtf(lenSq);
}
```

代表旋转的四元数应始终具有*1*的长度。在下一节中，您将了解始终具有*1*长度的单位四元数。

# 四元数

四元数可以像向量一样被归一化。归一化的四元数只代表旋转，而非归一化的四元数会引入扭曲。在游戏动画的背景下，应该对四元数进行归一化，以避免给变换添加扭曲。

要归一化一个四元数，将四元数的每个分量除以其长度。结果四元数的长度将为*1*。可以实现如下：

1.  在`quat.cpp`中实现`normalize`函数，并在`quat.h`中声明它：

```cpp
void normalize(quat& q) {
   float lenSq = q.x*q.x + q.y*q.y + q.z*q.z + q.w*q.w;
   if (lenSq < QUAT_EPSILON) { 
      return; 
   }
   float i_len = 1.0f / sqrtf(lenSq);
   q.x *= i_len;
   q.y *= i_len;
   q.z *= i_len;
   q.w *= i_len;
}
```

1.  在`quat.cpp`中实现`normalized`函数，并在`quat.h`中声明它：

```cpp
quat normalized(const quat& q) {
   float lenSq = q.x*q.x + q.y*q.y + q.z*q.z + q.w*q.w;
   if (lenSq < QUAT_EPSILON) {
      return quat();
   }
   float il = 1.0f / sqrtf(lenSq); // il: inverse length
   return quat(q.x * il, q.y * il, q.z * il,q.w * il);
}
```

有一种快速的方法可以求任意单位四元数的倒数。在下一节中，您将学习如何找到四元数的共轭和倒数，以及它们在单位四元数方面的关系。

# 共轭和逆

游戏大多使用归一化的四元数，在反转四元数时非常方便。归一化四元数的逆是它的共轭。共轭

四元数的翻转其旋转轴：

1.  在`quat.cpp`中实现`conjugate`函数，并记得在`quat.h`中声明该函数：

```cpp
quat conjugate(const quat& q) {
    return quat(
        -q.x,
        -q.y,
        -q.z,
         q.w
    );
}
```

1.  四元数的逆是四元数的共轭除以四元数的平方长度。在`quat.cpp`中实现四元数`inverse`函数。将函数声明添加到`quat.h`中：

```cpp
quat inverse(const quat& q) {
   float lenSq = q.x*q.x + q.y*q.y + q.z*q.z + q.w*q.w;
   if (lenSq < QUAT_EPSILON) { 
      return quat(); 
   }
   float recip = 1.0f / lenSq;
   return quat(-q.x * recip,
               -q.y * recip,
               -q.z * recip,
                q.w * recip
   );
}
```

如果您需要找出一个四元数是否已经归一化，可以检查平方长度。归一化四元数的平方长度始终为*1*。如果四元数已经归一化，其共轭和逆将是相同的。这意味着您可以使用更快的`conjugate`函数，而不是`inverse`函数。在下一节中，您将学习如何将两个四元数相乘。

# 乘法四元数

两个四元数可以通过将它们相乘来连接。与矩阵类似，操作是从右到左进行的；首先应用右四元数的旋转，然后是左四元数的。

假设有两个四元数*q*和*p*。它们带有`0`、`1`、`2`和`3`下标，分别对应`X`、`Y`、`Z`和`W`分量。这些四元数可以用*ijk*符号表示，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_008.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_009.png)

要将这两个四元数相乘，将*p*的各个分量分配给*q*的各个分量。分配实部很简单。将*p*3 分配给*q*会是这样的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_010.png)

分配虚部看起来非常相似。实部和虚部分别组合；虚部的顺序很重要。例如，将*p*o*i*分配给*q*会是这样的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_011.png)

完全分配*p*给*q*看起来是这样的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_012.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_013.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_014.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_015.png)

开始简化虚数平方的情况。虚数的平方根是*-1*。如果将*-1*提高到*-1*的幂，结果也是*-1*。这意味着任何* i*2*、*j*2*或*k*2*的实例都可以被替换为*-1*，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_016.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_017.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_018.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_019.png)

其他虚数呢？在谈论四元数时，

*ijk= -1*，每个分量的平方值也是*-1*，这意味着

*i*2*= j*2*= k*2*=ijk*。四元数的这个性质可以用来简化方程的其余部分。

以*jk*为例。从*ijk= -1*开始，尝试将*jk*隔离到方程的一边。

为此，将两边都乘以*i*，得到*i(ijk)= -i*。分配*i*，得到*i*2 *jk= -i*。你已经知道*i*2 的值是*-1*。将其代入得到

*-jk= -i*。两边都乘以*-1*，就找到了*jk*的值—*jk=i*。

可以以类似的方式找到*ki*和*ij*的值；它们分别是*ki=j*和*k=ij*。现在可以用*j*替换任何*ki*的实例，用*k*替换*ij*的实例，用*i*替换*jk*的实例。代入这些值后得到：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_020.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_021.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_022.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_019.png)

剩下的虚数是*ik*、*ji*和*kj*。就像叉乘一样，顺序很重要：*ik= -ki*。由此可推断*ik= -j*，*ji= -k*，*kj= -1*。代入这些值后得到：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_024.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_025.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_026.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_027.png)

具有不同虚部的数字不能相加。重新排列前面的公式，使相似的虚部相邻。这导致四元数乘法的最终方程式：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_028.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_029.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_030.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_031.png)

要在代码中实现这个公式，需要从下标化的*ijk*符号改回带有`X`、`Y`、`Z`和`W`下标的向量表示。在`quat.cpp`中实现四元数乘法函数，并不要忘记将函数声明添加到`quat.h`中：

```cpp
quat operator*(const quat& Q1, const quat& Q2) {
   return quat( 
       Q2.x*Q1.w + Q2.y*Q1.z - Q2.z*Q1.y + Q2.w*Q1.x,
      -Q2.x*Q1.z + Q2.y*Q1.w + Q2.z*Q1.x + Q2.w*Q1.y,
       Q2.x*Q1.y - Q2.y*Q1.x + Q2.z*Q1.w + Q2.w*Q1.z,
      -Q2.x*Q1.x - Q2.y*Q1.y - Q2.z*Q1.z + Q2.w*Q1.w
   );
}
```

观察前面的代码时，请注意四元数的实部有一个正分量，但向量部分有一个负分量。重新排列四元数，使负数始终在最后。使用向量表示写下来：

*qp*x*= p*x *q*w*+ p*w *q*x*+ p*y *q*z*- p*z *q*y

*qp*y= *p*y *q*w+ *p*w *q*y+ *p*z *q*x- *p*x *q*z

*qp*z= *p*z *q*w+ *p*w *q*z+ *p*x *q*y- *p*y *q*x

*qp*w= *p*w *q*w- *p*x *q*x- *p*y *q*y- *p*z *q*z

在前述等式中有两个有趣的部分。如果你仔细观察前三行的最后两列，减法的列是叉乘。前两列只是通过其他四元数的标量部分来缩放每个四元数的向量部分。

如果你看最后一行，点积和点积的负数都在其中。最后一行基本上是将两个四元数的实部相乘，然后减去它们的向量部分的点积。这意味着另一种乘法实现可能是这样的：

```cpp
quat operator*(const quat& Q1, const quat& Q2) {
  quat result;
  result.scalar = Q2.scalar * Q1.scalar -
  dot(Q2.vector, Q1.vector);
  result.vector = (Q1.vector * Q2.scalar) +
  (Q2.vector * Q1.scalar)+cross(Q2.vector, Q1.vector);
  return result;
}
```

原始实现稍微更高效，因为它不需要调用其他函数。本书的示例代码将使用第一种实现。

接下来，你将学习如何通过四元数来转换向量。

# 转换向量

要将向量和四元数相乘，首先必须将向量转换为纯四元数。什么是纯四元数？它是一个其`W`分量为`0`且向量部分被归一化的四元数。假设你有一个四元数*q*和一个向量*v*。首先，将*v*转换为纯四元数，表示为*v*'：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_035.png)

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_036.png)

接下来，将*q*乘以*v*'，然后将结果乘以*q*的逆。这个乘法的结果是一个纯四元数，其向量部分包含了旋转后的向量。四元数变成了以下形式：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_038.png)

为什么*v*'要先乘以*q*，然后再乘以*q*^-1？乘以*q*会使向量旋转的角度是*q*的两倍。乘以*q*^-1 会将向量带回到预期的范围内。这个公式可以进一步简化。

推导这个公式超出了本书的范围。给定一个四元数*q*和

对于向量*v*，简化的向量四元数乘法公式如下所示。

*q*v 指的是四元数的向量部分，*q*s 指的是实数（或标量）部分：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_042.png)

在`quat.cpp`中实现前述四元数向量乘法公式。不要忘记将函数声明添加到`quat.h`中：

```cpp
vec3 operator*(const quat& q, const vec3& v) {
    return q.vector * 2.0f * dot(q.vector, v) +
        v * (q.scalar * q.scalar - dot(q.vector, q.vector)) +
        cross(q.vector, v) * 2.0f * q.scalar;
}
```

将向量乘以四元数总是会得到一个被四元数旋转的向量。在下一节中，你将学习如何在四元数之间进行插值。

# 插值四元数

四元数可以以类似的方式进行插值，用于在两个关键帧之间旋转。由于大多数骨骼动画是通过随时间旋转关节来实现的，因此在四元数之间进行插值将是一个非常常见的操作。

一个非常常见的操作。

## 邻域

四元数代表的是旋转，而不是方向。从球的一部分旋转到另一部分可以通过两种旋转中的一种来实现。旋转可以采取最短或最长的弧。通常，使四元数沿着最短的弧旋转是可取的。在两个四元数之间进行插值时，将采取哪种路径——最短的弧还是最长的弧？

这个问题被称为邻域问题。要解决它，检查被插值的四元数的点积。如果点积是正的，将采取较短的弧。如果点积是负的，将采取较长的弧。

如果点积是负的，如何纠正插值以采取最短的弧？答案是对其中一个四元数取反。以下是四元数邻域化的一个示例代码：

```cpp
quat SampleFunction(const quat& a, const quat& b) {
    if (dot(a, b) < 0.0f) {
        b = -b;
    }
    return slerp(a, b, 0.5f);
}
```

只有在插值两个四元数时才需要邻域。接下来，你将学习如何混合线性插值（lerp）、归一化线性插值（nlerp）和球形线性插值（slerp）四元数。请记住，这些函数期望四元数已经处于所需的邻域内。

## 理解 mix 函数

当混合两个或多个四元数时，每个四元数都会被某个权重值缩放，然后将结果缩放的四元数相加。所有输入四元数的权重值必须加起来等于*1*。

如果所有输入四元数的长度都为单位长度，那么结果四元数也将是单位长度。这个函数实现了与`lerp`相同的结果，但它并不是真正的`lerp`函数，因为四元数仍然沿着弧线移动。为避免混淆，这个函数将被称为`mix`，而不是`lerp`。

`mix`函数假设输入四元数在所需的邻域内。在`quat.cpp`中实现`mix`函数，并不要忘记将函数声明添加到`quat.h`中：

```cpp
quat mix(const quat& from, const quat& to, float t) {
    return from * (1.0f - t) + to * t;
}
```

## 理解 nlerp 函数

四元数之间的`nlerp`是球面插值的一种快速且良好的近似。它的实现几乎与`vec3`类的`nlerp`实现相同。

像`mix`一样，`nlerp`也假设输入向量在所需的邻域内。在`quat.cpp`中实现`nlerp`函数，并不要忘记将函数声明添加到`quat.h`中：

```cpp
quat nlerp(const quat& from, const quat& to, float t) {
    return normalized(from + (to - from) * t);
}
```

## slerp 简介

只有在需要一致速度时才应该使用`slerp`。在大多数情况下，`nlerp`将是更好的插值方法。根据插值步长的不同，`slerp`最终可能会回退到`nlerp`。

为了在两个四元数之间进行球面插值，创建两者之间的增量四元数。调整增量四元数的角度，然后使用四元数乘法将其与起始四元数连接起来。

如何调整四元数的角度？要调整四元数的角度，将其提升到所需的幂。例如，要将四元数调整为只旋转一半，可以将其提升到*0.5*的幂。

## 幂

要将四元数提升到某个幂，需要将其分解为一个角度和一个轴。然后，可以通过幂和调整的角度构建一个新的四元数。如果一个四元数围绕*v*轴旋转*θ*角度，将其提升到某个幂*t*，可以按照以下方式进行：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-cpp-gm-ani-prog/img/Formula_04_044.png)

在`quat.cpp`中实现`power operator`。不要忘记将函数声明添加到`quat.h`中：

```cpp
quat operator^(const quat& q, float f) {
    float angle = 2.0f * acosf(q.scalar);
    vec3 axis = normalized(q.vector);
    float halfCos = cosf(f * angle * 0.5f);
    float halfSin = sinf(f * angle * 0.5f);
    return quat(axis.x * halfSin,
                axis.y * halfSin,
                axis.z * halfSin,
                halfCos
    );
}
```

## 实现 slerp

现在您知道如何将四元数提升到幂，实现`slerp`就变得简单了。如果起始和结束四元数非常接近，`slerp`往往会产生意外的结果。如果起始和结束四元数接近，就回退到`nlerp`。

要在两个四元数之间进行插值，找到从起始旋转到结束旋转的增量四元数。这个增量四元数就是插值路径。将角度提升到两个四元数之间插值的幂（通常表示为*t*），然后将起始四元数相乘。

在`quat.cpp`中实现`slerp`函数。不要忘记将函数声明添加到`quat.h`中。与其他插值函数一样，`slerp`假设被插值的四元数在所需的邻域内：

```cpp
quat slerp(const quat& start, const quat& end, float t) {
    if (fabsf(dot(start, end)) > 1.0f - QUAT_EPSILON) {
        return nlerp(start, end, t);
    }
    quat delta = inverse(start) * end;
    return normalized((delta ^ t) * start);
}
```

`slerp`的输入向量应该是归一化的，这意味着在`slerp`函数中可以使用`conjugate`而不是`inverse`。大多数情况下，`nlerp`将会被用于`slerp`。在下一节中，您将学习如何创建一个指向特定方向的四元数。

# 观察旋转

给定一个方向和一个指示向上方向的参考，可以创建一个朝向该方向并具有正确方向的四元数。这个函数将被称为`lookRotation`，而不是`lookAt`，以避免与矩阵`lookAt`函数混淆。

要实现`lookRotation`函数，找到一个将旋转到所需方向的四元数。为此，创建一个世界`forward`向量*(0, 0, 1)*和`desired direction`之间的四元数。这个四元数将旋转到`right`目标，但不考虑`up`可能的方向。

要纠正这个四元数的`up`方向，首先必须找到一个垂直于当前前向方向和期望的`up`方向的向量。这可以通过这两个向量的叉积来实现。

这个叉积的结果将用于构造三个正交向量——前向向量、这个新向量和一个指向上的向量。你刚刚找到的将指向右边。

接下来，您需要找到一个既垂直于`forward`又垂直于`right`方向的向量；这将是正交的`up`向量。要找到这个向量，可以取方向和这个`right`向量的叉积，结果就是物体空间的`up`向量。

找到一个从期望的`up`向量旋转到物体`up`向量的四元数。将旋转到目标方向的四元数和从`desired up`到`object up`的四元数相乘。

在`quat.cpp`中实现`lookRotation`函数。不要忘记将函数声明添加到`quat.h`中：

```cpp
quat lookRotation(const vec3& direction, const vec3& up) {
    // Find orthonormal basis vectors
    vec3 f = normalized(direction); // Object Forward
    vec3 u = normalized(up); // Desired Up
    vec3 r = cross(u, f); // Object Right
    u = cross(f, r); // Object Up
    // From world forward to object forward
    quat worldToObject = fromTo(vec3(0, 0, 1), f); 
    // what direction is the new object up?
    vec3 objectUp = worldToObject * vec3(0, 1, 0);
    // From object up to desired up
    quat u2u = fromTo(objectUp, u);
    // Rotate to forward direction first
    // then twist to correct up
    quat result = worldToObject * u2u; 
    // Don't forget to normalize the result
    return normalized(result);
}
```

矩阵`lookAt`函数创建一个视图矩阵，这是相机变换的逆。这意味着`lookAt`的旋转和`lookRotation`的结果将互为逆运算。在下一节中，您将学习如何将矩阵转换为四元数，以及四元数转换为矩阵。

# 在矩阵和四元数之间进行转换

由于矩阵和四元数都可以用于编码旋转数据，因此能够在它们之间进行转换将非常有用。为了使在两者之间进行转换更容易，您必须开始考虑基向量的旋转，这些向量代表了*x*、*y*和*z*轴。

4x4 矩阵的上 3x3 子矩阵包含三个基向量。第一列是`right`向量，第二列是`up`向量，第三列是`forward`向量。只使用`forward`和`up`向量，`lookRotation`函数可以将矩阵转换为四元数。

要将四元数转换为矩阵，只需将世界基向量（世界的*x*、*y*和*z*轴）乘以四元数。将结果向量存储在矩阵的相应分量中：

1.  在`quat.cpp`中实现`quatToMat4`函数。不要忘记将函数声明添加到`quat.h`中：

```cpp
mat4 quatToMat4(const quat& q) {
    vec3 r = q * vec3(1, 0, 0);
    vec3 u = q * vec3(0, 1, 0);
    vec3 f = q * vec3(0, 0, 1);
    return mat4(r.x, r.y, r.z, 0,
                u.x, u.y, u.z, 0,
                f.x, f.y, f.z, 0,
                0  , 0  , 0  , 1
    );
}
```

1.  矩阵使用相同的组件存储旋转和缩放数据。为了解决这个问题，基向量需要被归一化，并且需要使用叉积来确保结果向量是正交的。在`quat.cpp`中实现`mat4ToQuat`函数，不要忘记将函数声明添加到`quat.h`中：

```cpp
quat mat4ToQuat(const mat4& m) {
    vec3 up = normalized(vec3(m.up.x, m.up.y, m.up.z));
    vec3 forward = normalized(
         vec3(m.forward.x, m.forward.y, m.forward.z));
    vec3 right = cross(up, forward);
    up = cross(forward, right);
    return lookRotation(forward, up);
}
```

能够将四元数转换为矩阵将在以后需要将旋转数据传递给着色器时非常有用。着色器不知道四元数是什么，但它们内置了处理矩阵的功能。将矩阵转换为四元数对于调试和在外部数据源只提供矩阵旋转的情况下也将非常有用。

# 总结

在本章中，您实现了一个强大的四元数库。四元数对本书的其余部分非常重要，因为所有动画旋转数据都记录为四元数。您学会了如何创建四元数和常见的四元数操作，通过乘法组合四元数，通过四元数转换向量，插值四元数和实用函数来创建四元数，给定前向和上方向，并在矩阵和四元数之间进行转换。

在下一章中，您将使用向量、矩阵和四元数的综合知识来定义一个变换对象。
