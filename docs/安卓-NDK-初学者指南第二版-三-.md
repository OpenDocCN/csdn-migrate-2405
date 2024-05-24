# 安卓 NDK 初学者指南第二版（三）

> 原文：[`zh.annas-archive.org/md5/A3DD702F9D1A87E6BE95B1711A85BCDE`](https://zh.annas-archive.org/md5/A3DD702F9D1A87E6BE95B1711A85BCDE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第六章：使用 OpenGL ES 渲染图形

> *面对现实，Android NDK 的主要兴趣之一是编写多媒体应用程序和游戏。实际上，这些程序消耗大量资源并需要响应性。这就是为什么在 Android NDK 中最早可用的 API（直到最近几乎也是唯一的一个）是图形 API：**嵌入式系统开放图形库**（简称 **OpenGL ES**）。*
> 
> *OpenGL 是由硅谷图形公司创建的一个标准 API，现在由 Khronos Group 管理（见[`www.khronos.org/`](http://www.khronos.org/)）。OpenGL 为所有桌面上的标准 **GPU**（**图形处理单元**，如你的显卡等）提供了一个通用接口。OpenGL ES 是在许多嵌入式平台上可用的衍生 API，例如 Android 或 iOS。它是编写可移植和高效图形代码的最佳选择。OpenGL 可以渲染 2D 和 3D 图形。*

目前 Android 支持的 OpenGL ES 有三个主要版本：

+   OpenGL ES 1.0 和 1.1 在所有 Android 设备上得到支持（除了 1.1，只在一些非常旧的设备上支持）。它提供了一个老式的图形 API，具有**固定管线**（即，一组可配置的操作，用于转换和渲染几何体）。规范没有完全实现，但大多数功能是可用的。这仍然是简单 2D 或 3D 图形或移植旧版 OpenGL 代码的好选择。

+   现在，几乎所有的手机，即使是较旧的型号，从 API 级别 8 开始都支持 OpenGL ES 2。它用现代的可编程管线替换了固定管线，包括**顶点**和**片段着色器**。它稍微复杂一些，但功能也更强大。对于更复杂的 2D 或 3D 游戏，这是一个不错的选择，同时仍然保持非常好的兼容性。请注意，OpenGL ES 1.X 通常会在幕后由 OpenGL 2 的实现进行模拟。*

+   OpenGL ES 3.0 从 API 级别 18 开始在现代设备上可用，而 OpenGL ES 3.1 则从 API 级别 21 开始可用（不过，这些 API 级别上的并非所有设备都支持它）。它们为 GLES 2 带来了一系列新改进（**纹理压缩**作为标准特性，**遮挡查询、实例渲染**等属于 3.0，**计算着色器**、**间接绘制**命令等属于 3.1），并与桌面版 OpenGL 的兼容性更好。它与 OpenGL ES 2 向后兼容。

本章将教你如何使用 OpenGL ES 2 创建一些基本的 2D 图形。更具体地说，你将了解到如何：

+   初始化 OpenGL ES

+   从资产中打包的 PNG 文件加载纹理

+   使用顶点和片段着色器绘制精灵

+   渲染粒子效果

+   适应各种分辨率图形

由于 OpenGL ES 以及一般的图形是一个广泛的课题，本章仅涵盖入门的基础知识。

# 初始化 OpenGL ES

创建出色的 2D 和 3D 图形的第一步是初始化 OpenGL ES。尽管不是特别复杂，但这项任务需要一些样板代码将渲染上下文绑定到 Android 窗口。这些部分在**嵌入式系统图形库**（**EGL**）的帮助下粘合在一起，它是 OpenGL ES 的伴随 API。

在本节的第一部分，我们将用 OpenGL ES 替换前一章中实现的原始绘图系统。黑色到白色的渐变效果将展示 EGL 初始化是正常工作的。

### 注意

本书提供的项目结果名为`DroidBlaster_Part5`。

# 动手操作——初始化 OpenGL ES

让我们重写`GraphicsManager`以初始化 OpenGL ES 上下文：

1.  通过执行以下操作来修改`jni/GraphicsManager.hpp`：

    +   包含`EGL/egl.h`以将 OpenGL ES 绑定到 Android 平台，以及`GLES2/gl2.h`以渲染图形。

    +   添加一个`stop()`方法，在离开活动时解绑 OpenGL 渲染上下文并释放图形资源。

    +   定义`EGLDisplay`、`EGLSurface`和`EGLContext`成员变量，这些变量表示对系统资源的句柄，如下所示：

        ```java
        ...
        #include "Types.hpp"

        #include <android_native_app_glue.h>
        #include <GLES2/gl2.h>
        #include <EGL/egl.h>
        ...

        class GraphicsManager {
        public:
            ...
            status start();
            void stop();
            status update();

        private:
            ...
            int32_t mRenderWidth; int32_t mRenderHeight;
            EGLDisplay mDisplay; EGLSurface mSurface; EGLContext mContext;

            GraphicsElement* mElements[1024]; int32_t mElementCount;
        };
        #endif
        ```

1.  通过用基于 OpenGL 的代码替换`jni/GraphicsManager.cpp`中基于 Android 原始图形 API 的先前代码来重新实现它。首先，在构造函数初始化列表中添加新成员：

    ```java
    #include "GraphicsManager.hpp"
    #include "Log.hpp"

    GraphicsManager::GraphicsManager(android_app* pApplication) :
        mApplication(pApplication),
        mRenderWidth(0), mRenderHeight(0),
        mDisplay(EGL_NO_DISPLAY), mSurface(EGL_NO_CONTEXT),
     mContext(EGL_NO_SURFACE),
        mElements(), mElementCount(0) {
        Log::info("Creating GraphicsManager.");
    }
    ...
    ```

1.  在`start()`方法中必须完成繁重的工作：

    +   首先，声明一些变量。注意 EGL 如何定义自己的类型，并用`EGLint`和`EGLBoolean`重新声明基本类型，以支持平台独立性。

    +   然后，在常量属性列表中定义所需的 OpenGL 配置。这里，我们想要 OpenGL ES 2 和一个 16 位表面（红色 5 位，绿色 6 位，蓝色 5 位）。我们也可以选择 32 位表面以获得更好的色彩保真度（但在某些设备上性能较差）。属性列表以`EGL_NONE`结束符结束：

        ```java
        ...
        status GraphicsManager::start() {
            Log::info("Starting GraphicsManager.");
            EGLint format, numConfigs, errorResult; GLenum status;
            EGLConfig config;
            // Defines display requirements. 16bits mode here.
            const EGLint DISPLAY_ATTRIBS[] = {
                EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
                EGL_BLUE_SIZE, 5, EGL_GREEN_SIZE, 6, EGL_RED_SIZE, 5,
                EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
                EGL_NONE
            };
            // Request an OpenGL ES 2 context.
            const EGLint CONTEXT_ATTRIBS[] = {
                EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE
            };
        ...
        ```

1.  使用`eglGetDisplay()`和`eglInitialize()`连接到默认**显示**，即 Android 主窗口。然后，使用`eglChooseConfig()`找到合适的**帧缓冲区**配置（OpenGL 术语，指的是渲染表面，可能还包括其他缓冲区，如**Z 缓冲区**或**模板缓冲区**）。配置根据请求的属性进行选择：

    ```java
    ...
        mDisplay = eglGetDisplay(EGL_DEFAULT_DISPLAY);
        if (mDisplay == EGL_NO_DISPLAY) goto ERROR;
        if (!eglInitialize(mDisplay, NULL, NULL)) goto ERROR;

        if(!eglChooseConfig(mDisplay, DISPLAY_ATTRIBS, &config, 1,
            &numConfigs) || (numConfigs <= 0)) goto ERROR;
    ...
    ```

1.  使用选择的配置（通过`eglGetConfigAttrib()`获取）重新配置 Android 窗口。这个操作是 Android 特定的，使用 Android `ANativeWindow` API 执行。

    之后，使用先前选择的显示和配置创建显示表面和 OpenGL 上下文。上下文包含与 OpenGL 状态相关的所有数据（启用的设置，禁用的设置等）：

    ```java
    ...
        if (!eglGetConfigAttrib(mDisplay, config,
            EGL_NATIVE_VISUAL_ID, &format)) goto ERROR;
        ANativeWindow_setBuffersGeometry(mApplication->window, 0, 0,
            format);

        mSurface = eglCreateWindowSurface(mDisplay, config,
            mApplication->window, NULL);
        if (mSurface == EGL_NO_SURFACE) goto ERROR;
        mContext = eglCreateContext(mDisplay, config, NULL,
            CONTEXT_ATTRIBS);
        if (mContext == EGL_NO_CONTEXT) goto ERROR;
    ...
    ```

1.  使用`eglMakeCurrent()`激活创建的渲染上下文。最后，根据使用`eglQuerySurface()`获取的表面属性定义显示视口。Z 缓冲区不需要，可以禁用：

    ```java
    ...
        if (!eglMakeCurrent(mDisplay, mSurface, mSurface, mContext)
       || !eglQuerySurface(mDisplay, mSurface, EGL_WIDTH, &mRenderWidth)
       || !eglQuerySurface(mDisplay, mSurface, EGL_HEIGHT, &mRenderHeight)
       || (mRenderWidth <= 0) || (mRenderHeight <= 0)) goto ERROR;

        glViewport(0, 0, mRenderWidth, mRenderHeight);
        glDisable(GL_DEPTH_TEST);
        return STATUS_OK;

    ERROR:
        Log::error("Error while starting GraphicsManager");
        stop();
        return STATUS_KO;
    }
    ...
    ```

1.  当应用程序停止运行时，将应用程序从 Android 窗口解绑并释放 EGL 资源：

    ```java
    ...
    void GraphicsManager::stop() {
        Log::info("Stopping GraphicsManager.");

        // Destroys OpenGL context.
        if (mDisplay != EGL_NO_DISPLAY) {
            eglMakeCurrent(mDisplay, EGL_NO_SURFACE, EGL_NO_SURFACE,
                           EGL_NO_CONTEXT);
            if (mContext != EGL_NO_CONTEXT) {
                eglDestroyContext(mDisplay, mContext);
                mContext = EGL_NO_CONTEXT;
            }
            if (mSurface != EGL_NO_SURFACE) {
                eglDestroySurface(mDisplay, mSurface);
                mSurface = EGL_NO_SURFACE;
            }
            eglTerminate(mDisplay);
            mDisplay = EGL_NO_DISPLAY;
        }
    }
    ...
    ```

## *刚才发生了什么？*

我们已经初始化并将 OpenGL ES 和 Android 原生窗口系统通过 EGL 连接在一起。得益于这个 API，我们已经查询了一个符合我们预期的显示配置，并创建了一个 Framebuffer 来渲染我们的场景。EGL 是由 Khronos 组（如 OpenGL）指定的标准 API。平台通常实现自己的变体（例如 iOS 上的 EAGL 等），因此显示窗口初始化仍然与操作系统相关。因此，实际上可移植性相当有限。

此初始化过程将创建一个 OpenGL 上下文，这是启用 OpenGL 图形管道的第一步。应特别注意 OpenGL 上下文，在 Android 上它们经常丢失：当你离开或返回主屏幕时，当接到电话时，设备进入休眠状态时，当你切换到另一个应用程序时等等。由于丢失的上下文将无法使用，因此尽快释放图形资源非常重要。

### 提示

OpenGL ES 规范支持为单一显示表面创建多个上下文。这允许将渲染操作分配给线程或渲染到多个窗口。然而，这在 Android 硬件上支持不佳，应避免使用。

OpenGL ES 现已初始化，但除非我们开始在显示屏幕上渲染一些图形，否则不会显示任何内容。

# 行动时间——清除和交换缓冲区

让我们用颜色从黑变白的方式来清除显示缓冲区：

1.  在`jni/GraphicsManager.cpp`中，每次更新步骤时使用`eglSwapBuffers()`刷新屏幕。

    为了提供视觉反馈，在用`glClear()`清除 Framebuffer 之前，借助`glClearColor()`逐渐改变显示背景色：

    ```java
    ...
    status GraphicsManager::update() {
        static float clearColor = 0.0f;
        clearColor += 0.001f;
        glClearColor(clearColor, clearColor, clearColor, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);

        if (eglSwapBuffers(mDisplay, mSurface) != EGL_TRUE) {
            Log::error("Error %d swapping buffers.", eglGetError());
            return STATUS_KO;
        } else {
            return STATUS_OK;
        }
    }
    ```

1.  更新`Android.mk`文件以链接`EGL`和`GLESv2`库：

    ```java
    LOCAL_PATH := $(call my-dir)

    include $(CLEAR_VARS)

    LS_CPP=$(subst $(1)/,,$(wildcard $(1)/*.cpp))
    LOCAL_MODULE := droidblaster
    LOCAL_SRC_FILES := $(call LS_CPP,$(LOCAL_PATH))
    LOCAL_LDLIBS := -landroid -llog -lEGL -lGLESv2
    LOCAL_STATIC_LIBRARIES := android_native_app_glue

    include $(BUILD_SHARED_LIBRARY)

    $(call import-module,android/native_app_glue)
    ```

## *刚才发生了什么？*

启动应用程序。如果一切正常，你的设备屏幕将从黑色逐渐过渡到白色。与之前章节中看到的用原始`memset()`清除显示或逐个设置像素点相比，我们现在调用高效的 OpenGL ES 绘图原语。请注意，该效果仅在应用程序首次启动时出现，因为清除颜色存储在一个静态变量中。要使其再次出现，请杀死应用程序并重新启动。

渲染场景需要清除 framebuffer 并交换显示缓冲区。后者操作是在调用`eglSwapBuffers()`时触发的。在 Android 上，交换与屏幕刷新率同步以避免图像**撕裂**；这是一个**VSync**。刷新率根据设备而异。一个常见的值是 60 Hz，但有些设备有不同的刷新率。

在内部，渲染是在后台缓冲区执行的，该缓冲区与显示给用户的前台缓冲区交换。前台缓冲区变成后台缓冲区，反之亦然（指针交换）。这种技术通常称为**页面翻转**。根据驱动程序实现，交换链可以扩展到第三个缓冲区。在这种情况下，我们称之为**三重缓冲**。

我们的 OpenGL 管道现在已经正确初始化，能够显示屏幕上的图形。然而，你可能会发现“管道”这个概念还有点模糊。让我们看看它背后隐藏了什么。

# 对 OpenGL 管道的深入理解

我们之所以称之为管道，是因为图形数据经过一系列步骤进行转换。以下图表展示了 OpenGL ES 2 管道的简化表示：

![对 OpenGL 管道的深入理解](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645OS_06_05.jpg)

+   **顶点处理**：作为**顶点缓冲对象**或**顶点数组**输入的顶点网格，在顶点着色器中逐个进行转换。顶点着色器可以移动或旋转单个顶点，将它们投影到屏幕上，调整纹理坐标，计算光照等。它会生成一个输出顶点，该顶点可以在管道中进一步处理。

+   **图元装配**：单独的顶点被连接成三角形、点、线等。当发送绘制调用时，客户端代码指定了更多的连接信息。它可以是索引缓冲区（每个索引通过其等级指向一个顶点）或预定义的规则，如剥离或扇形连接。如**背面剔除**或**剪辑**等转换在此阶段进行。

+   **光栅化**：图元被插值成片段，片段是包含与一个像素渲染相关的所有数据（如颜色、法线等）的术语。一个片段关联一个像素。这些片段为片段着色器提供数据。

+   **片段处理**：片段着色器是一个处理每个片段以计算要显示的像素的程序。这是应用纹理映射的阶段，使用顶点着色器计算并由光栅化器插值的坐标。可以计算不同的着色算法以渲染特定效果（例如，**卡通着色**）。

+   **像素处理**：片段着色器输出的像素必须与现有的帧缓冲区（渲染表面）合并，其中一些像素可能已经被绘制。在此阶段应用透明效果或混合。

顶点和片段着色器可以用**GL 着色语言**（**GLSL**）进行编程。它们仅在 OpenGL ES 2 和 3 中可用。OpenGL ES 1 提供了一个固定功能的管道，具有预定义的可能转换集合。

这只是 OpenGL 渲染管线处理流程的简要概述。要了解更多信息，请查看 OpenGL.org 维基页面 [`www.opengl.org/wiki/Rendering_Pipeline_Overview`](http://www.opengl.org/wiki/Rendering_Pipeline_Overview)。

# 使用资源管理器加载纹理

我猜你需要的不仅仅是改变屏幕颜色！但在我们应用程序中展示出色的图形之前，我们需要加载一些外部资源。

在第二部分，我们将通过 Android 资源管理器加载纹理到 OpenGL ES 中，这是从 NDK R5 开始提供的 API。它允许程序员访问项目 `assets` 文件夹中存储的任何资源。这些资源在应用程序编译期间被打包到最终的 APK 存档中。资源被视为原始二进制文件，你的应用程序需要通过相对于 `assets` 文件夹的文件名来解释和访问（一个文件 `assets/mydir/myfile` 可以通过 `mydir/myfile` 路径访问）。文件以只读模式提供，可能会被压缩。

如果你已经写过一些 Java Android 应用程序，那么你就会知道 Android 也通过编译时在 res 项目文件夹中生成的 ID 提供资源访问。这在 Android NDK 上并不直接可用。除非你准备使用 JNI 桥接，否则资源是打包 APK 中资源的唯一方式。

现在我们将加载一种现今最流行的图片格式之一，**便携式网络图形**（**PNG**）编码的纹理。为此，我们将在 NDK 模块中集成 **libpng**。

### 注意事项

最终的项目以 `DroidBlaster_Part6` 的名称随本书提供。

# 动手操作——使用资源管理器读取资源

让我们创建一个类来读取 Android 资源文件：

1.  创建 `jni/Resource.hpp` 来封装对资源文件的访问。我们将使用在 `android/asset_manager.hpp` 中定义的 `AAsset` API（该 API 已包含在 `android_native_app_glue.h` 中）。

    声明三个主要操作：`open()`、`close()` 和 `read()`。我们还需要在 `getPath()` 中获取资源的路径。

    Android 资源管理 API 的入口点是一个不透明的 `AAsetManager` 结构。我们可以从它那里访问代表资源文件的第二个不透明结构 `AAsset`：

    ```java
    #ifndef _PACKT_RESOURCE_HPP_
    #define _PACKT_RESOURCE_HPP_

    #include "Types.hpp"

    #include <android_native_app_glue.h>

    class Resource {
    public:
        Resource(android_app* pApplication, const char* pPath);

        const char* getPath() { return mPath; };

        status open();
        void close();
        status read(void* pBuffer, size_t pCount);

        bool operator==(const Resource& pOther);

    private:
        const char* mPath;
        AAssetManager* mAssetManager;
        AAsset* mAsset;
    };

    #endif
    ```

1.  在 `jni/Resource.cpp` 中实现 `Resource` 类。

    资源管理器由 **Native App Glue** 模块在其 `android_app->activity` 结构中提供：

    ```java
    #include "Resource.hpp"

    #include <sys/stat.h>

    Resource::Resource(android_app* pApplication, const char* pPath):
        mPath(pPath),
        mAssetManager(pApplication->activity->assetManager),
        mAsset(NULL) {
    }
    ...
    ```

1.  资源管理器通过 `AassetManager_open()` 打开资源。这是此方法的唯一职责，除了列出文件夹。我们使用默认的打开模式 `AASSET_MODE_UNKNOWN`（关于这一点稍后会详细介绍）：

    ```java
    ...
    status Resource::open() {
        mAsset = AAssetManager_open(mAssetManager, mPath,
                                    AASSET_MODE_UNKNOWN);
        return (mAsset != NULL) ? STATUS_OK : STATUS_KO;
    }
    ...
    ```

1.  与经典应用程序中的文件一样，使用完毕后必须通过 `AAsset_close()` 关闭打开的资源，以便释放系统分配的任何资源：

    ```java
    ...
    void Resource::close() {
        if (mAsset != NULL) {
            AAsset_close(mAsset);
            mAsset = NULL;
        }
    }
    ...
    ```

1.  最后，代码使用`AAsset_read()`在资源文件上操作以读取数据。这与标准的 Posix 文件 API 非常相似。在这里，我们尝试在内存缓冲区中读取`pCount`数据，并获取实际读取的数据量（如果我们到达资源的末尾）：

    ```java
    ...
    status Resource::read(void* pBuffer, size_t pCount) {
        int32_t readCount = AAsset_read(mAsset, pBuffer, pCount);
        return (readCount == pCount) ? STATUS_OK : STATUS_KO;
    }

    bool Resource::operator==(const Resource& pOther) {
        return !strcmp(mPath, pOther.mPath);
    }
    ```

## *刚才发生了什么？*

我们已经了解了如何调用 Android Asset API 来读取存储在`assets`目录中的文件。Android 资源是只读的，应该只用于保存静态资源。Android Asset API 在`android/assert_manager.h`包含文件中定义。

## 关于 Asset Manager API 的更多信息

Android 资源管理器提供了一组小方法来访问目录：

+   `AAssetManager_openDir()`提供了探索资源目录的可能性。与`AAssetDir_getNextFileName()`和`AAssetDir_rewind()`结合使用。打开的目录必须使用`AAssetDir_close()`关闭：

    ```java
    AAssetDir* AAssetManager_openDir(AAssetManager* mgr,
                                     const char* dirName);
    ```

+   `AAssetDir_getNextFileName()`列出指定资源目录中所有可用的文件。每次调用它时都会返回一个文件名，或者当所有文件都列出时返回`NULL`：

    ```java
    const char* AAssetDir_getNextFileName(AAssetDir* assetDir);
    ```

+   `AAssetDir_rewind()`提供了可能从文件迭代过程的开头使用`AAssetDir_getNextFileName()`重新开始迭代过程的功能：

    ```java
    void AAssetDir_rewind(AAssetDir* assetDir);
    ```

+   `AAssetDir_close()`释放打开目录时分配的所有资源。这个方法必须与`AAssetManager_openDir()`成对调用：

    ```java
    void AAssetDir_close(AAssetDir* assetDir);
    ```

文件可以使用类似于 POSIX 文件 API 的 API 打开：

+   `AAssetManager_open()`打开一个资源文件以读取其内容，将其内容作为缓冲区获取，或访问其文件描述符。打开的资源必须使用`AAsset_close()`关闭：

    ```java
    AAsset* AAssetManager_open(AAssetManager* mgr,
                               const char* filename, int mode);
    ```

+   `AAsset_read()`尝试在提供的缓冲区中读取请求的字节数。实际读取的字节数将被返回，如果发生错误则返回负值：

    ```java
    int AAsset_read(AAsset* asset, void* buf, size_t count);
    ```

+   `AAsset_seek()`直接跳转到文件中指定的偏移量，忽略之前的数据：

    ```java
    off_t AAsset_seek(AAsset* asset, off_t offset, int whence);
    ```

+   `AAsset_close()`关闭资源，并释放打开文件时分配的所有资源。这个方法必须与`AAssetManager_open()`成对调用：

    ```java
    void AAsset_close(AAsset* asset);
    ```

+   `AAsset_getBuffer()`返回一个指向包含整个资源内容的内存缓冲区的指针，如果出现问题则返回`NULL`。该缓冲区可能是内存映射的。请注意，因为 Android 会压缩某些资源（取决于它们的扩展名），所以缓冲区可能不是直接可读的：

    ```java
    const void* AAsset_getBuffer(AAsset* asset);
    ```

+   `AAsset_getLength()`给出资源的总大小（以字节为单位）。在读取资源之前，这个方法可能有助于预分配正确大小的缓冲区：

    ```java
    off_t AAsset_getLength(AAsset* asset);
    ```

+   `Aasset_getRemainingLength()`与`AAsset_getLength()`类似，不同之处在于它考虑了已经读取的字节数：

    ```java
    off_t AAsset_getRemainingLength(AAsset* asset);
    ```

+   `AAsset_openFileDescriptor()`返回一个原始的 Unix 文件描述符。这在 OpenSL 中用于读取音乐文件：

    ```java
    int AAsset_openFileDescriptor(AAsset* asset, off_t* outStart, off_t* outLength);
    ```

+   `AAsset_isAllocated()`指示资源返回的缓冲区是否是内存映射的：

    ```java
    int AAsset_isAllocated(AAsset* asset);
    ```

我们将在后续章节中详细介绍这些方法。

打开资源文件的可用模式有：

+   `AASSET_MODE_BUFFER`：这有助于执行快速的小读取

+   `AASSET_MODE_RANDOM`：这有助于向前和向后读取数据块

+   `AASSET_MODE_STREAMING`：这有助于顺序读取数据，偶尔向前搜索

+   `AASSET_MODE_UNKNOWN`：这有助于保持系统默认设置

大多数情况下`AASSET_MODE_UNKNOWN`会是正确的选择。

### 提示

安装大型的 APK 可能会出现问题，即使它们部署在 SD 卡上（参见 Android 清单中的`installLocation`选项）。因此，处理大量兆字节的资源的良好策略是只将必要的资源放在 APK 中。在运行时将剩余的文件下载到 SD 卡，或者将它们包装在第二个 APK 中。

既然我们已经有了要读取的 PNG 资源文件，那么我们使用`libpng`来加载它们。

# 行动时间——编译并嵌入 libpng 模块

让我们在 DroidBlaster 中从 PNG 文件加载一个 OpenGL 纹理。

1.  访问网站[`www.libpng.org/pub/png/libpng.html`](http://www.libpng.org/pub/png/libpng.html)，下载`libpng`源代码包（本书中是版本 1.6.10）。

    ### 注意

    本书中提供了原始的`libpng` 1.6.10 存档，位于`Libraries/libpng`文件夹中。

    在`$ANDROID_NDK/sources/`内创建一个名为`libpng`的文件夹。将`libpng`包中的所有文件移动到这个文件夹中。

    将文件`libpng/scripts/pnglibconf.h.prebuilt`复制到根文件夹`libpng`中的其他源文件中。将其重命名为`pnglibconf.h`。

    ### 注意

    文件夹`$ANDROID_NDK/sources`是一个特殊的文件夹，默认情况下被认为是模块文件夹。它包含可重用的库。更多信息请参见第九章，*将现有库移植到 Android*。

1.  使用以下代码中给定的内容编写`$ANDROID_NDK/sources/libpng/Android.mk`文件：

    ```java
    LOCAL_PATH:= $(call my-dir)

    include $(CLEAR_VARS)

    LS_C=$(subst $(1)/,,$(wildcard $(1)/*.c))

    LOCAL_MODULE := png
    LOCAL_SRC_FILES := \
        $(filter-out example.c pngtest.c,$(call LS_C,$(LOCAL_PATH)))
    LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
    LOCAL_EXPORT_LDLIBS := -lz

    include $(BUILD_STATIC_LIBRARY)
    ```

1.  现在，打开`DroidBlaster`目录中的`jni/Android.mk`。

    使用`LOCAL_STATIC_LIBRARIES`和`import-module`指令链接和导入`libpng`。这与我们对 Native App Glue 模块所做的类似：

    ```java
    LOCAL_PATH := $(call my-dir)

    include $(CLEAR_VARS)

    LS_CPP=$(subst $(1)/,,$(wildcard $(1)/*.cpp))
    LOCAL_MODULE := droidblaster
    LOCAL_SRC_FILES := $(call LS_CPP,$(LOCAL_PATH))
    LOCAL_LDLIBS := -landroid -llog -lEGL -lGLESv2
    LOCAL_STATIC_LIBRARIES := android_native_app_glue png

    include $(BUILD_SHARED_LIBRARY)

    $(call import-module,android/native_app_glue)
    $(call import-module,libpng)

    ```

## *刚才发生了什么？*

在上一章中，我们嵌入了现有的 Native App Glue 模块以创建一个完全本地的应用程序。这次我们创建了自己的第一个本地可重用模块来集成`libpng`。通过编译`DroidBlaster`确保它能正常工作。如果你查看`libpng`源文件的**控制台**视图，它应该为每个目标平台编译。请注意，NDK 提供增量编译，并且不会重新编译已经编译的源文件：

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645OS_06_01.jpg)

本地库模块（在这里是`libpng`）在位于其自身目录根部的 Makefile 中定义。然后它从另一个 Makefile 模块引用，通常是应用程序模块（在这里是`Droidblaster`）。

在这里，`libpng`库的 Makefile 通过自定义宏`LS_C`选择所有的 C 文件。这个宏是从`LOCAL_SRC_FILES`指令中调用的。我们使用标准的“Make”函数`filter-out()`排除了`example.c`和`pngtest.c`，它们只是测试文件。

所有的先决条件包含文件都通过`LOCAL_EXPORT_C_INCLUDES`指令提供给客户端模块，该指令指向这里的源目录`LOCAL_PATH`。像`libzip`（选项`-lz`）这样的先决条件库也通过`LOCAL_EXPORT_LDLIBS`指令提供给客户端模块。所有包含`_EXPORT_`术语的指令都会将指令附加到客户端模块自身的指令中。

有关 Makefiles、指令和标准函数的更多信息，请查看第九章，*将现有库移植到 Android*。

# 行动时间——加载 PNG 图像

既然`libpng`已经编译完成，让我们用它来读取一个真正的 PNG 文件：

1.  编辑`jni/GraphicsManager.hpp`并包含`Resource`头文件。

    创建一个名为`TextureProperties`的新结构，包含以下内容：

    +   表示纹理资源的资源

    +   一个 OpenGL 纹理标识符（这是一种句柄）

    +   宽度和高度

        ```java
        ...
        #include "Resource.hpp"
        #include "Types.hpp"
        ...

        struct TextureProperties {
            Resource* textureResource;
            GLuint texture;
            int32_t width;
            int32_t height;
        };
        ...
        ```

1.  向`GraphicsManager`追加一个`loadTexture()`方法，以读取 PNG 并将其加载到 OpenGL 纹理中。

    纹理保存在`mTextures`数组中以便缓存和最终确定。

    ```java
    ...
    class GraphicsManager {
    public:
        ...
        status start();
        void stop();
        status update();

        TextureProperties* loadTexture(Resource& pResource);

    private:
        ...
        int32_t mRenderWidth; int32_t mRenderHeight;
        EGLDisplay mDisplay; EGLSurface mSurface; EGLContext mContext;

        TextureProperties mTextures[32]; int32_t mTextureCount;
        GraphicsElement* mElements[1024]; int32_t mElementCount;
    };
    #endif
    ```

1.  编辑`jni/GraphicsManager.cpp`以包含名为`png.h`的新头文件，并更新构造函数初始化列表：

    ```java
    #include "GraphicsManager.hpp"
    #include "Log.hpp"

    #include <png.h>

    GraphicsManager::GraphicsManager(android_app* pApplication) :
        mApplication(pApplication),
        mRenderWidth(0), mRenderHeight(0),
        mDisplay(EGL_NO_DISPLAY), mSurface(EGL_NO_CONTEXT),
        mContext(EGL_NO_SURFACE),
     mTextures(), mTextureCount(0),
        mElements(), mElementCount(0) {
        Log::info("Creating GraphicsManager.");
    }
    ...
    ```

1.  当`GraphicsManager`停止使用`glDeleteTetxures()`时，释放与纹理相关的资源。这个函数可以一次删除多个纹理，这就是为什么此方法预期是一个序数和一个数组的原因。但在这里我们不会使用这种可能性：

    ```java
    ...
    void GraphicsManager::stop() {
        Log::info("Stopping GraphicsManager.");
        for (int32_t i = 0; i < mTextureCount; ++i) {
            glDeleteTextures(1, &mTextures[i].texture);
        }
        mTextureCount = 0;

        // Destroys OpenGL context.
        if (mDisplay != EGL_NO_DISPLAY) {
            ...
        }
    }
    ...
    ```

1.  为了完全独立于数据源，`libpng`提供了一个机制来整合自定义读取操作。这通过回调的形式，将请求的数据量读取到由`libpng`提供的缓冲区中。

    结合 Android Asset API 实现此回调，以访问应用资产的读取数据。资产文件通过`png_get_io_ptr()`给出的`Resource`实例作为非类型指针进行读取。这个指针将在设置回调函数时（使用`png_set_read_fn()`）由我们提供。我们将在下一步中看到如何执行此操作：

    ```java
    ...
    void callback_readPng(png_structp pStruct,
        png_bytep pData, png_size_t pSize) {
        Resource* resource = ((Resource*) png_get_io_ptr(pStruct));
        if (resource->read(pData, pSize) != STATUS_OK) {
            resource->close();
        }
    }
    ...
    ```

1.  实现`loadTexture()`。首先，在缓存中查找`texture`。纹理在内存和性能方面开销很大，应该谨慎管理（与所有 OpenGL 资源一样）：

    ```java
    ...
    TextureProperties* GraphicsManager::loadTexture(Resource& pResource) {
        for (int32_t i = 0; i < mTextureCount; ++i) {
            if (pResource == *mTextures[i].textureResource) {
                Log::info("Found %s in cache", pResource.getPath());
                return &mTextures[i];
            }
        }
    ...
    ```

1.  如果你无法在缓存中找到纹理，那么让我们读取它。首先定义一些读取 PNG 文件所需的变量。

    然后，使用`AAsset` API 打开图像，并检查图像签名（文件的前 8 个字节），以确保文件是 PNG 格式（注意，文件可能仍然已损坏）：

    ```java
    ...
        Log::info("Loading texture %s", pResource.getPath());
        TextureProperties* textureProperties; GLuint texture; GLint format;
        png_byte header[8];
        png_structp pngPtr = NULL; png_infop infoPtr = NULL;
        png_byte* image = NULL; png_bytep* rowPtrs = NULL;
        png_int_32 rowSize; bool transparency;

        if (pResource.open() != STATUS_OK) goto ERROR;
        Log::info("Checking signature.");
        if (pResource.read(header, sizeof(header)) != STATUS_OK)
            goto ERROR;
        if (png_sig_cmp(header, 0, 8) != 0) goto ERROR;
    ...
    ```

1.  分配读取 PNG 图像所需的所有结构。之后，通过将我们在此教程中早先实现的`callback_readPng()`以及我们的`Resource`读取器传递给`libpng`，准备读取操作。通过`png_get_io_ptr()`在回调中获取的`Resource`指针。

    同时，使用`setjmp()`设置错误管理。这种机制允许像`goto`一样通过调用栈跳转代码。如果发生错误，控制流程将返回到首次调用`setjmp()`的位置，但会进入`if`块（这里为`goto ERROR`）。这是我们提供以下脚本的时刻：

    ```java
    ...
        Log::info("Creating required structures.");
        pngPtr = png_create_read_struct(PNG_LIBPNG_VER_STRING,
            NULL, NULL, NULL);
        if (!pngPtr) goto ERROR;
        infoPtr = png_create_info_struct(pngPtr);
        if (!infoPtr) goto ERROR;

        // Prepares reading operation by setting-up a read callback.
        png_set_read_fn(pngPtr, &pResource, callback_readPng);
        // Set-up error management. If an error occurs while reading,
        // code will come back here and jump
        if (setjmp(png_jmpbuf(pngPtr))) goto ERROR;
    ...
    ```

1.  忽略已经读取的文件签名中的前 8 个字节，使用`png_set_sig_bytes()`和`png_read_info()`：

    使用`png_get_IHDR()`开始读取 PNG 文件头：

    ```java
    ...
        // Ignores first 8 bytes already read.
        png_set_sig_bytes(pngPtr, 8);
        // Retrieves PNG info and updates PNG struct accordingly.
        png_read_info(pngPtr, infoPtr);
        png_int_32 depth, colorType;
        png_uint_32 width, height;
        png_get_IHDR(pngPtr, infoPtr, &width, &height,
            &depth, &colorType, NULL, NULL, NULL);
    ...
    ```

1.  PNG 文件可以用多种格式编码：RGB、RGBA、带有调色板的 256 色、灰度等。R、G 和 B 颜色通道可以编码到 16 位。幸运的是，`libpng`提供了转换函数来解码不常见的格式，并将它们转换为更经典的 RGB 和亮度格式（每个通道 8 位，可选带或不带 alpha 通道）。

    使用`png_set`函数选择正确的转换。通过`png_read_update_info()`验证转换。

    同时，选择相应的 OpenGL 纹理格式：

    ```java
    ...
        // Creates a full alpha channel if transparency is encoded as
        // an array of palette entries or a single transparent color.
        transparency = false;
        if (png_get_valid(pngPtr, infoPtr, PNG_INFO_tRNS)) {
            png_set_tRNS_to_alpha(pngPtr);
            transparency = true;
        }
        // Expands PNG with less than 8bits per channel to 8bits.
        if (depth < 8) {
            png_set_packing (pngPtr);
        // Shrinks PNG with 16bits per color channel down to 8bits.
        } else if (depth == 16) {
            png_set_strip_16(pngPtr);
        }
        // Indicates that image needs conversion to RGBA if needed.
        switch (colorType) {
        case PNG_COLOR_TYPE_PALETTE:
            png_set_palette_to_rgb(pngPtr);
            format = transparency ? GL_RGBA : GL_RGB;
            break;
        case PNG_COLOR_TYPE_RGB:
            format = transparency ? GL_RGBA : GL_RGB;
            break;
        case PNG_COLOR_TYPE_RGBA:
            format = GL_RGBA;
            break;
        case PNG_COLOR_TYPE_GRAY:
            png_set_expand_gray_1_2_4_to_8(pngPtr);
            format = transparency ? GL_LUMINANCE_ALPHA:GL_LUMINANCE;
            break;
        case PNG_COLOR_TYPE_GA:
            png_set_expand_gray_1_2_4_to_8(pngPtr);
            format = GL_LUMINANCE_ALPHA;
            break;
        }
        // Validates all transformations.
        png_read_update_info(pngPtr, infoPtr);
    ...
    ```

1.  为`libpng`分配必要的临时缓冲区以保存图像数据，以及一个用于存储每行输出图像地址的第二个缓冲区。注意，行顺序是反转的，因为 OpenGL 使用的坐标系（左下角为第一个像素）与 PNG（左上角为第一个像素）不同。

    ```java
    ...
        // Get row size in bytes.
        rowSize = png_get_rowbytes(pngPtr, infoPtr);
        if (rowSize <= 0) goto ERROR;
        // Ceates the image buffer that will be sent to OpenGL.
        image = new png_byte[rowSize * height];
        if (!image) goto ERROR;
        // Pointers to each row of the image buffer. Row order is
        // inverted because different coordinate systems are used by
        // OpenGL (1st pixel is at bottom left) and PNGs (top-left).
        rowPtrs = new png_bytep[height];
        if (!rowPtrs) goto ERROR;
        for (int32_t i = 0; i < height; ++i) {
            rowPtrs[height - (i + 1)] = image + i * rowSize;
        }
    ...
    ```

1.  然后，使用`png_read_image()`开始读取图像内容。

    最后，完成时，释放所有临时资源：

    ```java
    ...
        // Reads image content.
        png_read_image(pngPtr, rowPtrs);
        // Frees memory and resources.
        pResource.close();
        png_destroy_read_struct(&pngPtr, &infoPtr, NULL);
        delete[] rowPtrs;
    ```

1.  最后，完成时，释放所有临时资源：

    ```java
    ...
    ERROR:
        Log::error("Error loading texture into OpenGL.");
        pResource.close();
        delete[] rowPtrs; delete[] image;
        if (pngPtr != NULL) {
            png_infop* infoPtrP = infoPtr != NULL ? &infoPtr: NULL;
            png_destroy_read_struct(&pngPtr, infoPtrP, NULL);
        }
        return NULL;
    }
    ```

## *刚才发生了什么？*

将我们的本地库模块`libpng`与资产管理器 API 结合使用，使我们能够加载资产目录中打包的 PNG 文件。PNG 是一种相对简单的图像格式，易于集成。此外，它支持压缩，有利于限制 APK 的大小。请注意，一旦加载，PNG 图像缓冲区将被解压缩，可能会消耗大量内存。因此，一旦可以，请尽快释放它们。有关 PNG 格式的详细信息，请参见[`www.w3.org/TR/PNG/`](http://www.w3.org/TR/PNG/)。

现在，我们的 PNG 图像已加载，我们可以从中生成 OpenGL 纹理。

# 是时候生成 OpenGL 纹理了——采取行动。

由`libpng`填充的`image`缓冲区现在包含原始纹理数据。下一步是从此生成纹理：

1.  让我们继续我们之前的方法`GraphicsManager::loadTexture()`。

    使用`glGenTextures()`生成新的纹理标识符。

    使用`glBindTexture()`指示我们正在处理一个纹理。

    使用 `glTexParameteri()` 配置纹理参数，以指定纹理的过滤和包裹方式。使用 `GL_NEAREST`，因为对于没有缩放效果的 2D 游戏来说，平滑并不是必需的。纹理重复也不必要，可以通过 `GL_CLAMP_TO_EDGE` 来防止：

    ```java
    ...
        png_destroy_read_struct(&pngPtr, &infoPtr, NULL);
        delete[] rowPtrs;

     GLenum errorResult;
     glGenTextures(1, &texture);
     glBindTexture(GL_TEXTURE_2D, texture);
     // Set-up texture properties.
     glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER,
     GL_NEAREST);
     glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER,
     GL_NEAREST);
     glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S,
     GL_CLAMP_TO_EDGE);
     glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T,
     GL_CLAMP_TO_EDGE);
    ...
    ```

1.  使用 `glTexImage2D()` 将图像数据推送到 OpenGL 纹理中。

    这将解绑纹理，使 OpenGL 管线恢复到之前的状态。这不是严格必要的，但有助于避免未来绘制调用（即，使用不需要的纹理进行绘制）时的配置错误。

    最后，不要忘记释放临时图像缓冲区。

    你可以使用 `glGetError()` 来检查纹理是否已正确创建：

    ```java
    ...
        // Loads image data into OpenGL.
     glTexImage2D(GL_TEXTURE_2D, 0, format, width, height, 0, format,
     GL_UNSIGNED_BYTE, image);
     // Finished working with the texture.
     glBindTexture(GL_TEXTURE_2D, 0);
     delete[] image;
     if (glGetError() != GL_NO_ERROR) goto ERROR;
     Log::info("Texture size: %d x %d", width, height);
    ...
    ```

1.  最后，在返回之前，将 `texture` 缓存起来：

    ```java
    ...
        // Caches the loaded texture.
     textureProperties = &mTextures[mTextureCount++];
     textureProperties->texture = texture;
     textureProperties->textureResource = &pResource;
     textureProperties->width = width;
     textureProperties->height = height;
     return textureProperties;

    ERROR:
        ...
    }
    ...
    ```

1.  在 `jni/DroidBlaster.hpp` 文件中，包含 `Resource` 头文件，并定义两个资源，其中一个用于飞船，另一个用于小行星：

    ```java
    ...
    #include "PhysicsManager.hpp"
    #include "Resource.hpp"
    #include "Ship.hpp"
    #include "TimeManager.hpp"
    #include "Types.hpp"

    class DroidBlaster : public ActivityHandler {
        ...
    private:
        ...
        EventLoop mEventLoop;

        Resource mAsteroidTexture;
        Resource mShipTexture;

        Asteroid mAsteroids;
        Ship mShip;
    };
    #endif
    ```

1.  打开 `jni/DroidBlaster.cpp` 文件，并在构造函数中初始化 `texture` 资源。

    ```java
    ...
    DroidBlaster::DroidBlaster(android_app* pApplication):
        mTimeManager(),
        mGraphicsManager(pApplication),
        mPhysicsManager(mTimeManager, mGraphicsManager),
        mEventLoop(pApplication, *this),

        mAsteroidTexture(pApplication, "droidblaster/asteroid.png"),
        mShipTexture(pApplication, "droidblaster/ship.png"),

        mAsteroids(pApplication, mTimeManager, mGraphicsManager,
                mPhysicsManager),
        mShip(pApplication, mGraphicsManager) {
        ...
    }
    ...
    ```

1.  为了确保代码正常工作，在 `onActivate()` 中加载纹理。只有在 `GraphicsManager` 初始化 OpenGL 之后，才能加载纹理：

    ```java
    ...
    status DroidBlaster::onActivate() {
        Log::info("Activating DroidBlaster");

        if (mGraphicsManager.start() != STATUS_OK) return STATUS_KO;
        mGraphicsManager.loadTexture(mAsteroidTexture);
        mGraphicsManager.loadTexture(mShipTexture);

        mAsteroids.initialize();
        mShip.initialize();

        mTimeManager.reset();
        return STATUS_OK;
    }
    ...
    ```

在运行 `DroidBlaster` 之前，将 `asteroid.png` 和 `ship.png` 添加到 `droidblaster/assets` 目录中（如果需要，请创建它）。

### 注意

PNG 文件随本书在 `DroidBlaster_Part6/assets` 目录中提供。

## *刚才发生了什么？*

运行应用程序，你不会看到太多差别。实际上，我们已经加载了两个 PNG 纹理，但我们并没有真正渲染它们。然而，如果你检查日志，你应该能看到痕迹显示纹理已经被正确加载并从缓存中检索，如下面的截图所示：

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645OS_06_04.jpg)

在 OpenGL 中，纹理是对象（按照 OpenGL 的方式），形式为在 **图形处理单元**（**GPU**）上分配的内存数组，用于存储特定的数据。将图形数据存储在 GPU 内存中，比存储在主内存中提供了更快的内存访问速度，这有点像 CPU 上的缓存。这种效率是有代价的：纹理加载成本高，必须在启动时尽可能多地执行。

### 提示

纹理的像素被称为 **Texels**（纹理像素）。Texel 是“**Texture Pixel**”（纹理像素）的缩写。在场景渲染期间，纹理（因此 Texels）会被投影到 3D 对象上。

## 关于纹理的更多信息

在处理纹理时，要记住的一个重要要求是它们的尺寸；OpenGL 纹理的尺寸必须是 2 的幂（例如，128 或 256 像素）。其他尺寸在大多数设备上都会失败。这些尺寸简化了一种称为 **MIPmapping**（**Multum In Parvo**（**MIP**），意为小中见大）的技术。MIPmaps 是同一纹理的较小版本（见下图的例子），根据渲染对象距离的选择性应用。它们可以提高性能并减少锯齿伪影。

![关于纹理的更多信息](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645OS_06_08.jpg)

纹理配置是通过`glTexParameteri()`设置的。它们只需在创建纹理时指定。以下两种主要类型的参数可以应用：

+   使用`GL_TEXTURE_MAG_FILTER`和`GL_TEXTURE_MIN_FILTER`进行**纹理过滤**。

    这些参数控制了纹理放大和缩小的处理方式，即当纹理分别小于或大于光栅化图元时的处理过程。下一个图中展示了这两种可能的值。

+   `GL_LINEAR`根据最近的纹理颜色（也称为双线性过滤）对屏幕上绘制的纹理进行插值。这种计算产生平滑效果。`GL_NEAREST`不进行任何插值，直接显示最近的纹理颜色。这个值比`GL_LINEAR`稍微好一点性能。![关于纹理的更多信息](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645OS_06_06.jpg)

    存在一些变体，可以与 MIPmaps 结合使用以指示如何应用缩小；其中一些变体包括`GL_NEAREST_MIPMAP_NEAREST`、`GL_LINEAR_MIPMAP_NEAREST`、`GL_NEAREST_MIPMAP_LINEAR`和`GL_LINEAR_MIPMAP_LINEAR`（后者被称为**三线性过滤**）。

+   使用`GL_TEXTURE_WRAP_S`和`GL_TEXTURE_WRAP_T`进行**纹理包裹**。

    这些参数控制了当纹理坐标超出[0.0, 1.0]范围时纹理的重复方式。S 代表 X 轴，T 代表 Y 轴。它们的不同命名用于避免与位置坐标混淆。它们通常被称为 U 和 V。以下图展示了可能的一些值及其效果：

    ![关于纹理的更多信息](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645OS_06_07.jpg)

在处理纹理时需要记住的一些良好实践包括：

+   切换纹理是一项代价高昂的操作，因此尽可能避免 OpenGL 管道状态变化（绑定新纹理和通过`glEnable()`更改选项都是状态变化的例子）。

+   纹理可能是最消耗内存和带宽的资源。考虑使用**压缩**纹理格式以大幅提高性能。遗憾的是，纹理压缩算法相当依赖于硬件。

+   创建大的纹理图集，尽可能多地打包数据，甚至来自多个对象。这被称为**纹理图集**。例如，如果你查看飞船和小行星的纹理，你会发现其中打包了几个精灵图像（我们甚至可以打包更多）：![关于纹理的更多信息](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645OS_06_09.jpg)

这篇纹理介绍提供了对 OpenGL ES 可以实现的效果的简要概述。关于纹理的更多信息，请查看 OpenGL.org 维基页面：[`www.opengl.org/wiki/Texture`](http://www.opengl.org/wiki/Texture)。

# 绘制 2D 精灵图像

2D 游戏基于**精灵**，它们是在屏幕上组合的图像片段。它们可以代表一个对象、角色、静态元素或动画元素。精灵可以使用图像的 alpha 通道显示透明效果。通常，一个图像将包含一个精灵的多个帧，每个帧代表不同的动画步骤或不同的对象。

### 提示

如果你需要一个强大的跨平台图像编辑器，可以考虑使用**GNU 图像处理程序**（**GIMP**）。这个程序在 Windows、Linux 和 Mac OS X 上都可以使用，是一款功能强大且开源的软件。你可以从[`www.gimp.org/`](http://www.gimp.org/)下载它。

使用 OpenGL 绘制精灵的技术有很多种。其中一种称为**Sprite Batch**。这是使用 OpenGL ES 2 创建 2D 游戏的最有效方法之一。它基于一个顶点数组（存储在主内存中），每个帧都会用所有要渲染的精灵重新生成。渲染是借助一个简单的顶点着色器将 2D 坐标投影到屏幕上，以及一个输出原始精灵纹理颜色的片段着色器来完成的。

我们现在将实现一个精灵批次，在`DroidBlaster`中渲染飞船和多颗小行星。

### 注意

最终的项目与本一起提供，名为`DroidBlaster_Part7`。

# 动手时间——初始化 OpenGL ES

现在让我们看看如何在 DroidBlaster 中实现精灵批次：

1.  修改`jni/GraphicsManager.hpp`。创建`GraphicsComponent`类，它为所有以精灵批次开始的渲染技术定义了一个通用接口。定义一些新的方法，例如：

    +   `getProjectionMatrix()`提供用于在屏幕上投影 2D 图形的 OpenGL 矩阵

    +   `loadShaderProgram()`用于加载顶点和片段着色器，并将它们链接成一个 OpenGL 程序

    +   `registerComponent()`记录要初始化和渲染的`GraphicsComponent`列表

    创建`RenderVertex`私有结构，表示单个精灵顶点的结构。 

    同时，声明几个新的成员变量，例如：

    +   `mProjectionMatrix`用于存储正交投影（与 3D 游戏中使用的透视投影相对）。

    +   `mShaders`、`mShaderCount`、`mComponents`和`mComponentCount`用来追踪所有资源。

    最后，移除前一章用于渲染原始图形的所有`GraphicsElement`相关内容，如下代码所示：

    ```java
    ...
    class GraphicsComponent {
    public:
        virtual status load() = 0;
        virtual void draw() = 0;
    };
    ...
    ```

1.  接下来，在`GraphicsManager`中定义几个新方法：

    +   `getProjectionMatrix()`提供用于在屏幕上投影 2D 图形的 OpenGL 矩阵

    +   `loadShaderProgram()`用于加载顶点和片段着色器，并将它们链接成一个 OpenGL 程序

    +   `registerComponent()`记录要初始化和渲染的`GraphicsComponent`列表

    创建`RenderVertex`私有结构，表示单个精灵顶点的结构。

    同时，声明几个新的成员变量，例如：

    +   `mProjectionMatrix`用于存储正交投影（与 3D 游戏中使用的透视投影相对）

    +   `mShaders`、`mShaderCount`、`mComponents`和`mComponentCount`用于跟踪所有资源。

    最后，移除前一章用于渲染原始图形的所有`GraphicsElement`相关内容：

    ```java
    ...
    class GraphicsManager {
    public:
        GraphicsManager(android_app* pApplication);
        ~GraphicsManager();

        int32_t getRenderWidth() { return mRenderWidth; }
        int32_t getRenderHeight() { return mRenderHeight; }
        GLfloat* getProjectionMatrix() { return mProjectionMatrix[0]; }

     void registerComponent(GraphicsComponent* pComponent);

        status start();
        void stop();
        status update();

        TextureProperties* loadTexture(Resource& pResource);
        GLuint loadShader(const char* pVertexShader,
     const char* pFragmentShader);

    private:
        struct RenderVertex {
     GLfloat x, y, u, v;
        };

        android_app* mApplication;

        int32_t mRenderWidth; int32_t mRenderHeight;
        EGLDisplay mDisplay; EGLSurface mSurface; EGLContext mContext;
        GLfloat mProjectionMatrix[4][4];

        TextureProperties mTextures[32]; int32_t mTextureCount;
        GLuint mShaders[32]; int32_t mShaderCount;

        GraphicsComponent* mComponents[32]; int32_t mComponentCount;
    };
    #endif
    ```

1.  打开`jni/GraphicsManager.cpp`。

    更新构造函数初始化列表和析构函数。再次，移除所有与`GraphicsElement`相关的部分。

    使用`registerComponent()`替代`registerElement()`实现注册：

    ```java
    ...
    GraphicsManager::GraphicsManager(android_app* pApplication) :
        mApplication(pApplication),
        mRenderWidth(0), mRenderHeight(0),
        mDisplay(EGL_NO_DISPLAY), mSurface(EGL_NO_CONTEXT),
        mContext(EGL_NO_SURFACE),
        mProjectionMatrix(),
        mTextures(), mTextureCount(0),
        mShaders(), mShaderCount(0),
        mComponents(), mComponentCount(0) {
        Log::info("Creating GraphicsManager.");
    }

    GraphicsManager::~GraphicsManager() {
        Log::info("Destroying GraphicsManager.");
    }

    void GraphicsManager::registerComponent(GraphicsComponent* pComponent)
    {
        mComponents[mComponentCount++] = pComponent;
    }
    ...
    ```

1.  修改`onStart()`，使用显示尺寸初始化**正交**投影矩阵数组（我们将在第九章中看到如何更容易地使用 GLM 计算矩阵），并加载组件。

    ### 提示

    投影矩阵是一种数学方法，用于将组成场景的 3D 对象投影到 2D 平面上，即屏幕。在正交投影中，投影与显示表面垂直。这意味着无论物体距离观察点远近，其大小都完全相同。正交投影适用于 2D 游戏。**透视**投影中，物体越远看起来越小，通常用于 3D 游戏。

    如需了解更多信息，请查看[`en.wikipedia.org/wiki/Graphical_projection`](http://en.wikipedia.org/wiki/Graphical_projection)。

    ```java
    ...
    status GraphicsManager::start() {
        ...
        glViewport(0, 0, mRenderWidth, mRenderHeight);
        glDisable(GL_DEPTH_TEST);

        // Prepares the projection matrix with viewport dimesions.
     memset(mProjectionMatrix[0], 0, sizeof(mProjectionMatrix));
     mProjectionMatrix[0][0] =  2.0f / GLfloat(mRenderWidth);
     mProjectionMatrix[1][1] =  2.0f / GLfloat(mRenderHeight);
     mProjectionMatrix[2][2] = -1.0f; mProjectionMatrix[3][0] = -1.0f;
     mProjectionMatrix[3][1] = -1.0f; mProjectionMatrix[3][2] =  0.0f;
     mProjectionMatrix[3][3] =  1.0f;

     // Loads graphics components.
     for (int32_t i = 0; i < mComponentCount; ++i) {
     if (mComponents[i]->load() != STATUS_OK) {
     return STATUS_KO;
            }
        }
        return STATUS_OK;
        ...
    }
    ...
    ```

1.  在`stop()`中释放所有使用`loadShaderProgram()`加载的资源。

    ```java
    ...
    void GraphicsManager::stop() {
        Log::info("Stopping GraphicsManager.");
        for (int32_t i = 0; i < mTextureCount; ++i) {
            glDeleteTextures(1, &mTextures[i].texture);
        }
        mTextureCount = 0;

        for (int32_t i = 0; i < mShaderCount; ++i) {
     glDeleteProgram(mShaders[i]);
     }
     mShaderCount = 0;

        // Destroys OpenGL context.
        ...
    }
    ...
    ```

1.  在`update()`中清除显示后但在刷新之前，渲染所有已注册的组件：

    ```java
    ...
    status GraphicsManager::update() {
        glClear(GL_COLOR_BUFFER_BIT);

        for (int32_t i = 0; i < mComponentCount; ++i) {
     mComponents[i]->draw();
        }

        if (eglSwapBuffers(mDisplay, mSurface) != EGL_TRUE) {
        ...
    }
    ...
    ```

1.  创建新的方法`loadShader()`。其作用是编译并加载作为可读 GLSL 程序的给定着色器。为此：

    +   使用`glCreateShader()`生成新的顶点着色器。

    +   使用`glShaderSource()`将顶点着色器源代码上传到 OpenGL。

    +   使用`glCompileShader()`编译着色器，并使用`glGetShaderiv()`检查编译状态。编译错误可以通过`glGetShaderInfoLog()`读取。

    对给定的片段着色器重复该操作：

    ```java
    ...
    GLuint GraphicsManager::loadShader(const char* pVertexShader,
            const char* pFragmentShader) {
        GLint result; char log[256];
        GLuint vertexShader, fragmentShader, shaderProgram;

        // Builds the vertex shader.
        vertexShader = glCreateShader(GL_VERTEX_SHADER);
        glShaderSource(vertexShader, 1, &pVertexShader, NULL);
        glCompileShader(vertexShader);
        glGetShaderiv(vertexShader, GL_COMPILE_STATUS, &result);
        if (result == GL_FALSE) {
            glGetShaderInfoLog(vertexShader, sizeof(log), 0, log);
            Log::error("Vertex shader error: %s", log);
            goto ERROR;
        }

        // Builds the fragment shader.
        fragmentShader = glCreateShader(GL_FRAGMENT_SHADER);
        glShaderSource(fragmentShader, 1, &pFragmentShader, NULL);
        glCompileShader(fragmentShader);
        glGetShaderiv(fragmentShader, GL_COMPILE_STATUS, &result);
        if (result == GL_FALSE) {
            glGetShaderInfoLog(fragmentShader, sizeof(log), 0, log);
            Log::error("Fragment shader error: %s", log);
            goto ERROR;
        }
    ...
    ```

1.  编译后，将编译好的顶点和片段着色器链接在一起。为此：

    +   使用`glCreateProgram()`创建一个程序对象。

    +   使用`glAttachShader()`指定要使用的着色器。

    +   使用`glLinkProgram()`将它们链接在一起，创建最终程序。此时将检查着色器的一致性和与硬件的兼容性。可以使用`glGetProgramiv()`检查结果。

    +   最后，移除着色器，因为一旦链接到程序中，它们就不再有用。

        ```java
        ...
            shaderProgram = glCreateProgram();
            glAttachShader(shaderProgram, vertexShader);
            glAttachShader(shaderProgram, fragmentShader);
            glLinkProgram(shaderProgram);
            glGetProgramiv(shaderProgram, GL_LINK_STATUS, &result);
            glDeleteShader(vertexShader);
            glDeleteShader(fragmentShader);
            if (result == GL_FALSE) {
                glGetProgramInfoLog(shaderProgram, sizeof(log), 0, log);
                Log::error("Shader program error: %s", log);
                goto ERROR;
            }

            mShaders[mShaderCount++] = shaderProgram;
            return shaderProgram;

        ERROR:
            Log::error("Error loading shader.");
            if (vertexShader > 0) glDeleteShader(vertexShader);
            if (fragmentShader > 0) glDeleteShader(fragmentShader);
            return 0;
        }
        ...
        ```

1.  创建`jni/Sprite.hpp`，它定义了一个包含所有用于动画和绘制单个精灵所需数据的类。

    创建一个`Vertex`结构体，定义精灵顶点的内容。我们需要一个 2D 位置和纹理坐标，这些坐标限定精灵图片。

    然后，定义一些方法：

    +   可以使用 `setAnimation()` 和 `animationEnded()` 更新和检索精灵动画。位置为了简单起见，是公开可用的。

    +   为了稍后定义的 `SpriteBatch` 组件提供特权访问。它能够 `load()` 和 `draw()` 精灵。

        ```java
        #ifndef _PACKT_GRAPHICSSPRITE_HPP_
        #define _PACKT_GRAPHICSSPRITE_HPP_

        #include "GraphicsManager.hpp"
        #include "Resource.hpp"
        #include "Types.hpp"

        #include <GLES2/gl2.h>

        class SpriteBatch;

        class Sprite {
            friend class SpriteBatch;
        public
            struct Vertex {
                GLfloat x, y, u, v;
            };

            Sprite(GraphicsManager& pGraphicsManager,
                Resource& pTextureResource, int32_t pHeight, int32_t pWidth);

            void setAnimation(int32_t pStartFrame, int32_t pFrameCount,
                float pSpeed, bool pLoop);
            bool animationEnded() { return mAnimFrame > (mAnimFrameCount-1); }

            Location location;

        protected:
            status load(GraphicsManager& pGraphicsManager);
            void draw(Vertex pVertex[4], float pTimeStep);
        ...
        ```

1.  最后，定义一些属性：

    +   包含精灵表及其对应资源的纹理

    +   **精灵帧数据**：`mWidth` 和 `mHeight`，以及水平、垂直和总帧数 `mFrameXCount`、`mFrameYCount` 和 `mFrameCount`

    +   **动画数据**：动画的第一帧和总帧数 `mAnimStartFrame` 和 `mAnimFrameCount`，动画速度 `mAnimSpeed`，当前显示的帧 `mAnimFrame`，以及循环指示器 `mAnimLoop`：

        ```java
        ...
        private:
            Resource& mTextureResource;
            GLuint mTexture;
            // Frame.
            int32_t mSheetHeight, mSheetWidth;
            int32_t mSpriteHeight, mSpriteWidth;
            int32_t mFrameXCount, mFrameYCount, mFrameCount;
            // Animation.
            int32_t mAnimStartFrame, mAnimFrameCount;
            float mAnimSpeed, mAnimFrame;
            bool mAnimLoop;
        };
        #endif
        ```

1.  编写 `jni/Sprite.cpp` 构造函数，并将成员初始化为默认值：

    ```java
    #include "Sprite.hpp"
    #include "Log.hpp"

    Sprite::Sprite(GraphicsManager& pGraphicsManager,
            Resource& pTextureResource,
        int32_t pHeight, int32_t pWidth) :
        location(),
        mTextureResource(pTextureResource), mTexture(0),
        mSheetWidth(0), mSheetHeight(0),
        mSpriteHeight(pHeight), mSpriteWidth(pWidth),
        mFrameCount(0), mFrameXCount(0), mFrameYCount(0),
        mAnimStartFrame(0), mAnimFrameCount(1),
        mAnimSpeed(0), mAnimFrame(0), mAnimLoop(false)
    {}
    ...
    ```

1.  帧信息（水平、垂直和总帧数）需要在 `load()` 时重新计算，因为纹理尺寸仅在加载时才知道：

    ```java
    ...
    status Sprite::load(GraphicsManager& pGraphicsManager) {
        TextureProperties* textureProperties =
                pGraphicsManager.loadTexture(mTextureResource);
        if (textureProperties == NULL) return STATUS_KO;
        mTexture = textureProperties->texture;
        mSheetWidth = textureProperties->width;
        mSheetHeight = textureProperties->height;

        mFrameXCount = mSheetWidth / mSpriteWidth;
        mFrameYCount = mSheetHeight / mSpriteHeight;
        mFrameCount = (mSheetHeight / mSpriteHeight)
                    * (mSheetWidth / mSpriteWidth);
        return STATUS_OK;
    }
    ...
    ```

1.  动画从精灵表中的给定帧开始，并在一定数量的帧数后结束，这个数量会根据速度变化。动画可以在结束时循环回到开始处重新播放：

    ```java
    ...
    void Sprite::setAnimation(int32_t pStartFrame,
        int32_t pFrameCount, float pSpeed, bool pLoop) {
        mAnimStartFrame = pStartFrame;
        mAnimFrame = 0.0f, mAnimSpeed = pSpeed, mAnimLoop = pLoop;
        mAnimFrameCount = pFrameCount;
    }
    ...
    ```

1.  在 `draw()` 中，首先根据精灵动画和自上一帧以来的时间更新要绘制的帧。我们需要的是帧在精灵表中的索引：

    ```java
    ...
    void Sprite::draw(Vertex pVertices[4], float pTimeStep) {
        int32_t currentFrame, currentFrameX, currentFrameY;
        // Updates animation in loop mode.
        mAnimFrame += pTimeStep * mAnimSpeed;
        if (mAnimLoop) {
            currentFrame = (mAnimStartFrame +
                             int32_t(mAnimFrame) % mAnimFrameCount);
        } else {
            // Updates animation in one-shot mode.
            if (animationEnded()) {
                currentFrame = mAnimStartFrame + (mAnimFrameCount-1);
            } else {
                currentFrame = mAnimStartFrame + int32_t(mAnimFrame);
            }
        }
        // Computes frame X and Y indexes from its id.
        currentFrameX = currentFrame % mFrameXCount;
        // currentFrameY is converted from OpenGL coordinates
        // to top-left coordinates.
        currentFrameY = mFrameYCount - 1
                      - (currentFrame / mFrameXCount);
    ...
    ```

1.  精灵由四个顶点组成，绘制在输出数组 `pVertices` 中。这些顶点中的每一个都由精灵位置（`posX1`、`posY1`、`posX2`、`posY2`）和纹理坐标（`u1`、`u2`、`v1`、`v2`）组成。动态计算并在提供的内存缓冲区 `pVertices` 中生成这些顶点。这个内存缓冲区稍后将提供给 OpenGL 以渲染精灵：

    ```java
    ...
        // Draws selected frame.
        GLfloat posX1 = location.x - float(mSpriteWidth / 2);
        GLfloat posY1 = location.y - float(mSpriteHeight / 2);
        GLfloat posX2 = posX1 + mSpriteWidth;
        GLfloat posY2 = posY1 + mSpriteHeight;
        GLfloat u1 = GLfloat(currentFrameX * mSpriteWidth)
                        / GLfloat(mSheetWidth);
        GLfloat u2 = GLfloat((currentFrameX + 1) * mSpriteWidth)
                        / GLfloat(mSheetWidth);
        GLfloat v1 = GLfloat(currentFrameY * mSpriteHeight)
                        / GLfloat(mSheetHeight);
        GLfloat v2 = GLfloat((currentFrameY + 1) * mSpriteHeight)
                        / GLfloat(mSheetHeight);

        pVertices[0].x = posX1; pVertices[0].y = posY1;
        pVertices[0].u = u1;    pVertices[0].v = v1;
        pVertices[1].x = posX1; pVertices[1].y = posY2;
        pVertices[1].u = u1;    pVertices[1].v = v2;
        pVertices[2].x = posX2; pVertices[2].y = posY1;
        pVertices[2].u = u2;    pVertices[2].v = v1;
        pVertices[3].x = posX2; pVertices[3].y = posY2;
        pVertices[3].u = u2;    pVertices[3].v = v2;
    }
    ```

1.  在 `jni/SpriteBatch.hpp` 中指定方法，例如：

    +   `registerSprite()` 添加一个新的精灵以进行绘制

    +   `load()` 初始化所有已注册的精灵

    +   `draw()` 有效地渲染所有已注册的精灵

    我们将需要成员变量：

    +   在 `mSprites` 和 `mSpriteCount` 中绘制的精灵集合

    +   `mVertices`、`mVertexCount`、`mIndexes` 和 `mIndexCount`，它们定义了顶点和索引缓冲区

    +   由 `mShaderProgram` 标识的着色器程序。

    顶点和片段着色器参数是：

    +   `aPosition`，它是精灵角的其中一个位置。

    +   `aTexture`，它是精灵角纹理坐标。它定义了在精灵表中显示的精灵。

    +   `uProjection` 是正交投影矩阵。

    +   `uTexture`，包含精灵图片。

        ```java
        #ifndef _PACKT_GRAPHICSSPRITEBATCH_HPP_
        #define _PACKT_GRAPHICSSPRITEBATCH_HPP_

        #include "GraphicsManager.hpp"
        #include "Sprite.hpp"
        #include "TimeManager.hpp"
        #include "Types.hpp"

        #include <GLES2/gl2.h>

        class SpriteBatch : public GraphicsComponent {
        public:
            SpriteBatch(TimeManager& pTimeManager,
                    GraphicsManager& pGraphicsManager);
            ~SpriteBatch();

            Sprite* registerSprite(Resource& pTextureResource,
                int32_t pHeight, int32_t pWidth);

            status load();
            void draw();

        private:
            TimeManager& mTimeManager;
            GraphicsManager& mGraphicsManager;

            Sprite* mSprites[1024]; int32_t mSpriteCount;
            Sprite::Vertex mVertices[1024]; int32_t mVertexCount;
            GLushort mIndexes[1024]; int32_t mIndexCount;
            GLuint mShaderProgram;
            GLuint aPosition; GLuint aTexture;
            GLuint uProjection; GLuint uTexture;
        };
        #endif
        ```

1.  实现 `jni/SpriteBach.cpp` 构造函数以初始化默认值。组件必须注册到 `GraphicsManager` 以便加载和渲染。

    在析构函数中，当组件被销毁时，必须释放已分配的精灵。

    ```java
    #include "SpriteBatch.hpp"
    #include "Log.hpp"

    #include <GLES2/gl2.h>

    SpriteBatch::SpriteBatch(TimeManager& pTimeManager,
            GraphicsManager& pGraphicsManager) :
        mTimeManager(pTimeManager),
        mGraphicsManager(pGraphicsManager),
        mSprites(), mSpriteCount(0),
        mVertices(), mVertexCount(0),
        mIndexes(), mIndexCount(0),
        mShaderProgram(0),
        aPosition(-1), aTexture(-1), uProjection(-1), uTexture(-1)
    {
        mGraphicsManager.registerComponent(this);
    }

    SpriteBatch::~SpriteBatch() {
        for (int32_t i = 0; i < mSpriteCount; ++i) {
            delete mSprites[i];
        }
    }
    ...
    ```

1.  索引缓冲区相对静态。当注册精灵时，我们可以预先计算其内容。每个索引指向顶点缓冲区中的一个顶点（0 代表第一个顶点，1 代表第二个，依此类推）。由于一个精灵由 2 个 3 顶点的三角形组成（形成一个四边形），我们需要每个精灵 6 个索引：

    ```java
    ...
    Sprite* SpriteBatch::registerSprite(Resource& pTextureResource,
            int32_t pHeight, int32_t pWidth) {
        int32_t spriteCount = mSpriteCount;
        int32_t index = spriteCount * 4; // Points to 1st vertex.

        // Precomputes the index buffer.
        GLushort* indexes = (&mIndexes[0]) + spriteCount * 6;
        mIndexes[mIndexCount++] = index+0;
        mIndexes[mIndexCount++] = index+1;
        mIndexes[mIndexCount++] = index+2;
        mIndexes[mIndexCount++] = index+2;
        mIndexes[mIndexCount++] = index+1;
        mIndexes[mIndexCount++] = index+3;

        // Appends a new sprite to the sprite array.
        mSprites[mSpriteCount] = new Sprite(mGraphicsManager,
                pTextureResource, pHeight, pWidth);
        return mSprites[mSpriteCount++];
    }
    ...
    ```

1.  将 GLSL 顶点和片段着色器写成常量字符串。

    着色器代码是写在类似于 C 语言中可以编写的`main()`函数内的。像任何正常的计算机程序一样，着色器需要变量来处理数据：属性（如顶点位置这样的逐顶点数据）、统一变量（每次绘制调用的全局参数）以及变化量（如纹理坐标这样的逐片段插值值）。

    在这里，纹理坐标通过`vTexture`传递给片段着色器。顶点位置从 2D 向量转换为 4D 向量，进入预定义的 GLSL 变量`gl_Position`。片段着色器在`vTexture`中获取插值的纹理坐标。此信息用作预定义函数`texture2D()`中的索引，以访问纹理颜色。颜色保存在预定义的输出变量`gl_FragColor`中，它表示最终的像素：

    ```java
    ...
    static const char* VERTEX_SHADER =
       "attribute vec4 aPosition;\n"
       "attribute vec2 aTexture;\n"
       "varying vec2 vTexture;\n"
       "uniform mat4 uProjection;\n"
       "void main() {\n"
       "    vTexture = aTexture;\n"
       "    gl_Position =  uProjection * aPosition;\n"
       "}";

    static const char* FRAGMENT_SHADER =
        "precision mediump float;\n"
        "varying vec2 vTexture;\n"
        "uniform sampler2D u_texture;\n"
        "void main() {\n"
        "  gl_FragColor = texture2D(u_texture, vTexture);\n"
        "}";
    ...
    ```

1.  在`load()`中加载着色器程序并获取着色器属性和统一变量标识符。然后，初始化精灵，如下代码所示：

    ```java
    ...
    status SpriteBatch::load() {
        GLint result; int32_t spriteCount;

        mShaderProgram = mGraphicsManager.loadShader(VERTEX_SHADER,
                FRAGMENT_SHADER);
        if (mShaderProgram == 0) return STATUS_KO;
        aPosition = glGetAttribLocation(mShaderProgram, "aPosition");
        aTexture = glGetAttribLocation(mShaderProgram, "aTexture");
        uProjection = glGetUniformLocation(mShaderProgram,"uProjection");
        uTexture = glGetUniformLocation(mShaderProgram, "u_texture");

        // Loads sprites.
        for (int32_t i = 0; i < mSpriteCount; ++i) {
            if (mSprites[i]->load(mGraphicsManager)
                    != STATUS_OK) goto ERROR;
        }
        return STATUS_OK;

    ERROR:
        Log::error("Error loading sprite batch");
        return STATUS_KO;
    }
    ...
    ```

1.  编写`draw()`，它执行 OpenGL 精灵渲染逻辑。

    首先，选择精灵着色器并传递其参数：矩阵和纹理统一变量：

    ```java
    ...
    void SpriteBatch::draw() {
        glUseProgram(mShaderProgram);
        glUniformMatrix4fv(uProjection, 1, GL_FALSE,
                mGraphicsManager.getProjectionMatrix());
        glUniform1i(uTexture, 0);
    ...
    ```

    然后，使用`glEnableVertexAttribArray()`和`glVertexAttribPointer()`指示 OpenGL 如何存储顶点缓冲区中的位置和 UV 坐标。这些调用基本上描述了`mVertices`结构。注意顶点数据是如何与着色器属性链接的：

    ```java
    ...
        glEnableVertexAttribArray(aPosition);
        glVertexAttribPointer(aPosition, // Attribute Index
                              2, // Size in bytes (x and y)
                              GL_FLOAT, // Data type
                              GL_FALSE, // Normalized
                              sizeof(Sprite::Vertex),// Stride
                              &(mVertices[0].x)); // Location
        glEnableVertexAttribArray(aTexture);
        glVertexAttribPointer(aTexture, // Attribute Index
                              2, // Size in bytes (u and v)
                              GL_FLOAT, // Data type
                              GL_FALSE, // Normalized
                              sizeof(Sprite::Vertex), // Stride
                              &(mVertices[0].u)); // Location
    ...
    ```

    使用混合函数激活透明度，以在背景或其他精灵上方绘制精灵：

    ```java
    ...
        glEnable(GL_BLEND);
        glBlendFunc(GL_SRC_ALPHA, GL_ONE_MINUS_SRC_ALPHA);
    ...
    ```

    ### 提示

    有关 OpenGL 提供的混合模式的更多信息，请查看[`www.opengl.org/wiki/Blending`](https://www.opengl.org/wiki/Blending)。

1.  现在我们可以开始渲染循环，批量渲染所有精灵。

    第一个外部循环基本上遍历纹理。实际上，OpenGL 中的管道状态变化是代价高昂的。像`glBindTexture()`这样的方法应该尽可能少调用，以保证性能：

    ```java
    ...
        const int32_t vertexPerSprite = 4;
        const int32_t indexPerSprite = 6;
        float timeStep = mTimeManager.elapsed();
        int32_t spriteCount = mSpriteCount;
        int32_t currentSprite = 0, firstSprite = 0;
        while (bool canDraw = (currentSprite < spriteCount)) {
            // Switches texture.
            Sprite* sprite = mSprites[currentSprite];
            GLuint currentTexture = sprite->mTexture;
            glActiveTexture(GL_TEXTURE0);
            glBindTexture(GL_TEXTURE_2D, sprite->mTexture);
    ...
    ```

    内部循环为所有具有相同纹理的精灵生成顶点：

    ```java
    ...
            // Generate sprite vertices for current textures.
            do {
                sprite = mSprites[currentSprite];
                if (sprite->mTexture == currentTexture) {
                    Sprite::Vertex* vertices =
                            (&mVertices[currentSprite * 4]);
                    sprite->draw(vertices, timeStep);
                } else {
                    break;
                }
            } while (canDraw = (++currentSprite < spriteCount));
    ...
    ```

1.  每当纹理发生变化时，使用`glDrawElements()`渲染一批发射的精灵。之前指定的顶点缓冲区与这里给出的索引缓冲区结合，使用正确的纹理渲染正确的精灵。此时，绘制调用被发送到 OpenGL，执行着色器程序：

    ```java
    ...
            glDrawElements(GL_TRIANGLES,
                    // Number of indexes
                    (currentSprite - firstSprite) * indexPerSprite,
                    GL_UNSIGNED_SHORT, // Indexes data type
                    // First index
                    &mIndexes[firstSprite * indexPerSprite]);

            firstSprite = currentSprite;
        }
    ...
    ```

    当所有精灵渲染完毕后，恢复 OpenGL 状态：

    ```java
    ...
        glUseProgram(0);
        glDisableVertexAttribArray(aPosition);
        glDisableVertexAttribArray(aTexture);
        glDisable(GL_BLEND);
    }
    ```

1.  使用新的精灵系统更新`jni/Ship.hpp`。你可以移除之前的`GraphicsElement`内容：

    ```java
    #include "GraphicsManager.hpp"
    #include "Sprite.hpp"

    class Ship {
    public:
        ...
        void registerShip(Sprite* pGraphics);
        ...
    private:
        GraphicsManager& mGraphicsManager;
        Sprite* mGraphics;
    };
    #endif
    ```

    文件`jni/Ship.cpp`除了`Sprite`类型之外，变化不大。

    ```java
    ...
    void Ship::registerShip(Sprite* pGraphics) {
        mGraphics = pGraphics;
    }
    ...
    ```

    在`jni/DroidBlaster.hpp`中包含新的`SpriteBatch`组件：

    ```java
    ...
    #include "Resource.hpp"
    #include "Ship.hpp"
    #include "SpriteBatch.hpp"
    #include "TimeManager.hpp"
    #include "Types.hpp"

    class DroidBlaster : public ActivityHandler {
        ...
    private:
        ...
        Asteroid mAsteroids;
        Ship mShip;
        SpriteBatch mSpriteBatch;
    };
    #endif
    ```

1.  在`jni/DroidBlaster.cpp`中，定义一些具有动画属性的新常量。

    然后，使用`SpriteBatch`组件注册飞船和小行星的图形。

    再次移除与`GraphicsElement`相关的前一段内容：

    ```java
    ...
    static const int32_t SHIP_SIZE = 64;
    static const int32_t SHIP_FRAME_1 = 0;
    static const int32_t SHIP_FRAME_COUNT = 8;
    static const float SHIP_ANIM_SPEED = 8.0f;

    static const int32_t ASTEROID_COUNT = 16;
    static const int32_t ASTEROID_SIZE = 64;
    static const int32_t ASTEROID_FRAME_1 = 0;
    static const int32_t ASTEROID_FRAME_COUNT = 16;
    static const float ASTEROID_MIN_ANIM_SPEED = 8.0f;
    static const float ASTEROID_ANIM_SPEED_RANGE = 16.0f;

    DroidBlaster::DroidBlaster(android_app* pApplication):
       ...
        mAsteroids(pApplication, mTimeManager, mGraphicsManager,
                mPhysicsManager),
        mShip(pApplication, mGraphicsManager),
        mSpriteBatch(mTimeManager, mGraphicsManager) {
        Log::info("Creating DroidBlaster");

        Sprite* shipGraphics = mSpriteBatch.registerSprite(mShipTexture,
     SHIP_SIZE, SHIP_SIZE);
     shipGraphics->setAnimation(SHIP_FRAME_1, SHIP_FRAME_COUNT,
     SHIP_ANIM_SPEED, true);
        mShip.registerShip(shipGraphics);

        // Creates asteroids.
        for (int32_t i = 0; i < ASTEROID_COUNT; ++i) {
            Sprite* asteroidGraphics = mSpriteBatch.registerSprite(
     mAsteroidTexture, ASTEROID_SIZE, ASTEROID_SIZE);
     float animSpeed = ASTEROID_MIN_ANIM_SPEED
     + RAND(ASTEROID_ANIM_SPEED_RANGE);
     asteroidGraphics->setAnimation(ASTEROID_FRAME_1,
     ASTEROID_FRAME_COUNT, animSpeed, true);
            mAsteroids.registerAsteroid(
                    asteroidGraphics->location, ASTEROID_SIZE,
                    ASTEROID_SIZE);
        }
    }
    ...
    ```

1.  我们不再需要在`onActivate()`中手动加载纹理。Sprite 会为我们处理这些。

    最后，在`onDeactivate()`中释放图形资源：

    ```java
    ...
    status DroidBlaster::onActivate() {
        Log::info("Activating DroidBlaster");

        if (mGraphicsManager.start() != STATUS_OK) return STATUS_KO;

        // Initializes game objects.
        mAsteroids.initialize();
        mShip.initialize();

        mTimeManager.reset();
        return STATUS_OK;
    }

    void DroidBlaster::onDeactivate() {
        Log::info("Deactivating DroidBlaster");
        mGraphicsManager.stop();
    }
    ...
    ```

## *刚才发生了什么？*

启动 DroidBlaster。你现在应该看到一个被可怕旋转小行星环绕的动画飞船：

![刚才发生了什么?](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645OS_06_02.jpg)

在这一部分，我们看到了如何通过 Sprite Batch 技术有效地绘制一个精灵。实际上，在 OpenGL 程序中性能不佳的一个常见原因是状态变化。改变 OpenGL 设备状态（例如，绑定一个新的缓冲区或纹理，使用`glEnable()`更改选项等）是一个代价高昂的操作，应尽可能避免。因此，为了最大化 OpenGL 的性能，一个好的实践是按顺序排列绘制调用，并且只改变所需的状态。

### 提示

最优秀的 OpenGL ES 文档可以在苹果开发者网站上找到，地址是[`developer.apple.com/library/IOS/documentation/3DDrawing/Conceptual/OpenGLES_ProgrammingGuide/`](https://developer.apple.com/library/IOS/documentation/3DDrawing/Conceptual/OpenGLES_ProgrammingGuide/)。

但首先，让我们更深入地了解 OpenGL 在内存中存储顶点的方式以及 OpenGL ES 着色器的基础知识。

## 顶点数组与顶点缓冲对象

**顶点数组**（**VA**）和**顶点缓冲对象**（**VBO**）是 OpenGL ES 中管理顶点的两种主要方式。与纹理一样，可以同时将多个 VA/VBO 绑定到一个顶点着色器上。

在 OpenGL ES 中有两种主要方式来管理顶点：

+   在主内存中（即在 RAM 中），我们讨论的是顶点数组（简称 VA）。顶点数组在每个绘制调用时从 CPU 传输到 GPU。因此，它们的渲染速度较慢，但更新起来要容易得多。因此，当顶点网格经常变化时，它们是适当的。这解释了为什么要使用顶点数组来实现 Sprite Batches；每次渲染新帧时都会更新每个 Sprite（位置以及纹理坐标，以切换到新帧）。

+   在驱动器内存中（通常在 GPU 内存或**VRAM**中），我们讨论的是**顶点缓冲对象**。顶点缓冲绘制速度快，但更新成本更高。因此，它们通常用于渲染永远不会改变的静态数据。你仍然可以通过顶点着色器对其进行变换，我们将在下一部分看到。注意，在初始化期间可以向驱动器提供一些提示（`GL_DYNAMIC_DRAW`），以允许快速更新，但代价是更复杂的缓冲管理（即多重缓冲）。

变换后，顶点在图元装配阶段连接在一起。它们可以通过以下方式组装：

+   当列表以 3x3 排列（可能导致顶点重复），扇形，条形等方式时；在这种情况下，我们使用`glDrawArrays()`。

+   使用指定为 3x3 的索引缓冲区，其中顶点相互连接。索引缓冲区通常是实现更好性能的最佳方式。需要排序索引以利于缓存。使用`glDrawElements()`与相关的 VBO 或 VA 绘制索引。![顶点数组与顶点缓冲对象对比](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645OS_06_10.jpg)

当你处理顶点时，需要记住的一些好的实践是：

+   尽可能在每个缓冲区中打包尽可能多的顶点，甚至来自多个网格。实际上，从一组顶点切换到另一组，无论是 VA 还是 VBO，都是比较慢的。

+   避免在运行时更新静态顶点缓冲区。

+   使顶点结构的大小为 2 的幂（以字节为单位）以利于数据对齐。通常，相对于传输未对齐的数据，更倾向于填充数据，因为 GPU 处理数据的方式。

有关顶点管理的更多信息，请查看 OpenGL.org 维基的[`www.opengl.org/wiki/Vertex_Specification`](http://www.opengl.org/wiki/Vertex_Specification)和[`www.opengl.org/wiki/Vertex_Specification_Best_Practices`](http://www.opengl.org/wiki/Vertex_Specification_Best_Practices)。

# 渲染粒子效果

DroidBlaster 需要一个背景来使其看起来更美观。由于动作发生在太空中，那么一个流星如何给速度感？

这种效果可以通过几种方式模拟。一种可能的选择是显示一个粒子效果，其中每个粒子对应一个星星。OpenGL 通过**点精灵**提供了这一特性。点精灵是一种特殊的元素，只需要一个顶点就能绘制一个精灵。结合整个顶点缓冲区，可以高效地同时绘制许多精灵。

点精灵可以使用顶点和片段着色器。为了更高效，我们可以利用它们直接在着色器内部处理粒子移动的能力。因此，我们将不需要每次粒子变化时重新生成顶点缓冲区，就像使用精灵批次时必须做的那样。

### 注意

最终项目随本书提供，名为`DroidBlaster_Part8`。

# 动手操作 - 渲染星域

现在让我们看看如何在`DroidBlaster`中应用这个粒子效果：

1.  在`jni/GraphicsManager.hpp`中，定义一个加载顶点缓冲区的新方法。

    添加一个数组来存储顶点缓冲区资源：

    ```java
    ...
    class GraphicsManager {
    public:
        ...
        GLuint loadShader(const char* pVertexShader,
                const char* pFragmentShader);
        GLuint loadVertexBuffer(const void* pVertexBuffer,
     int32_t pVertexBufferSize);

    private:
        ...
        GLuint mShaders[32]; int32_t mShaderCount;
        GLuint mVertexBuffers[32]; int32_t mVertexBufferCount;

        GraphicsComponent* mComponents[32]; int32_t mComponentCount;
    };
    #endif
    ```

1.  在`jni/GraphicsManager.cpp`中，更新构造函数初始化列表，并在`stop()`中释放顶点缓冲区资源：

    ```java
    ...
    GraphicsManager::GraphicsManager(android_app* pApplication) :
        ...
        mTextures(), mTextureCount(0),
        mShaders(), mShaderCount(0),
        mVertexBuffers(), mVertexBufferCount(0),
        mComponents(), mComponentCount(0) {
        Log::info("Creating GraphicsManager.");
    }

    ...

    void GraphicsManager::stop() {
        Log::info("Stopping GraphicsManager.");
        ...

        for (int32_t i = 0; i < mVertexBufferCount; ++i) {
     glDeleteBuffers(1, &mVertexBuffers[i]);
     }
     mVertexBufferCount = 0;

        // Destroys OpenGL context.
        ...
    }
    ...
    ```

1.  创建新的方法`loadVertexBuffer()`，将给定内存位置的数据上传到 OpenGL 顶点缓冲区。与在计算机内存中使用动态顶点缓冲区的 SpriteBatch 示例相比，下面的顶点缓冲区是静态的，位于 GPU 内存中。这使得它更快但也相对不灵活。为此：

    +   使用`glGenBuffers()`生成缓冲区标识符。

    +   使用`glBindBuffer()`指示我们正在处理一个顶点缓冲区。

    +   使用`glBufferData()`将顶点数据从给定的内存位置推送到 OpenGL 顶点缓冲区。

    +   解绑顶点缓冲区，将 OpenGL 恢复到之前的状态。这并非严格必要，但对于纹理来说是有帮助的，可以避免未来绘制调用时的配置错误。

    +   你可以使用`glGetError()`检查顶点缓冲区是否已正确创建：

        ```java
        ...
        GLuint GraphicsManager::loadVertexBuffer(const void* pVertexBuffer,
                int32_t pVertexBufferSize) {
            GLuint vertexBuffer;
            // Upload specified memory buffer into OpenGL.
            glGenBuffers(1, &vertexBuffer);
            glBindBuffer(GL_ARRAY_BUFFER, vertexBuffer);
            glBufferData(GL_ARRAY_BUFFER, pVertexBufferSize, pVertexBuffer,
                    GL_STATIC_DRAW);
            // Unbinds the buffer.
            glBindBuffer(GL_ARRAY_BUFFER, 0);
            if (glGetError() != GL_NO_ERROR) goto ERROR;

            mVertexBuffers[mVertexBufferCount++] = vertexBuffer;
            return vertexBuffer;

        ERROR:
            Log::error("Error loading vertex buffer.");
            if (vertexBuffer > 0) glDeleteBuffers(1, &vertexBuffer);
            return 0;
        }
        ...
        ```

1.  在`jni/StarField.hpp`中定义新的`StarField`组件。

    重写`GraphicsComponent`方法，就像之前做的那样。

    定义一个特定的`Vertex`结构，包含 3 个坐标`x`、`y`和`z`。

    星场由`mStarCount`中的星星数量和一个代表单个星星的纹理`mTextureResource`来特征化。

    我们需要一些 OpenGL 资源：一个顶点缓冲区、一个纹理以及一个包含其变量的着色器程序：

    +   `aPosition`，代表星星的位置。

    +   `uProjection`，即正交投影矩阵。

    +   `uTime`是`TimeManager`给出的总经过时间。这是模拟星星移动的必要条件。

    +   `uHeight`，即显示的高度。当星星到达屏幕边界时，它们将被回收。

    +   `uTexture`，包含星星图片。

        ```java
        #ifndef _PACKT_STARFIELD_HPP_
        #define _PACKT_STARFIELD_HPP_

        #include "GraphicsManager.hpp"
        #include "TimeManager.hpp"
        #include "Types.hpp"

        #include <GLES2/gl2.h>

        class StarField : public GraphicsComponent {
        public:
            StarField(android_app* pApplication, TimeManager& pTimeManager,
                    GraphicsManager& pGraphicsManager, int32_t pStarCount,
                    Resource& pTextureResource);

            status load();
            void draw();

        private:
            struct Vertex {
                GLfloat x, y, z;
            };

            TimeManager& mTimeManager;
            GraphicsManager& mGraphicsManager;

            int32_t mStarCount;
            Resource& mTextureResource;

            GLuint mVertexBuffer; GLuint mTexture; GLuint mShaderProgram;
            GLuint aPosition; GLuint uProjection;
            GLuint uTime; GLuint uHeight; GLuint uTexture;
        };
        #endif
        ```

1.  创建`jni/StarField.cpp`并实现其构造函数：

    ```java
    #include "Log.hpp"
    #include "StarField.hpp"

    StarField::StarField(android_app* pApplication,
        TimeManager& pTimeManager, GraphicsManager& pGraphicsManager,
        int32_t pStarCount, Resource& pTextureResource):
            mTimeManager(pTimeManager),
            mGraphicsManager(pGraphicsManager),
            mStarCount(pStarCount),
            mTextureResource(pTextureResource),
            mVertexBuffer(0), mTexture(-1), mShaderProgram(0),
            aPosition(-1),
            uProjection(-1), uHeight(-1), uTime(-1), uTexture(-1) {
        mGraphicsManager.registerComponent(this);
    }
    ...
    ```

1.  星场的逻辑主要在顶点着色器中实现。每个由单个顶点表示的星星根据时间、速度（是恒定的）和星星距离从上到下移动。它越远（距离由`z`顶点分量确定），滚动越慢。

    GLSL 函数`mod`，代表取模，当星星到达屏幕底部时重置其位置。最终的星星位置保存在预定义变量`gl_Position`中。

    星星在屏幕上的大小也是其距离的函数。大小以像素单位保存在预定义变量`gl_PointSize`中：

    ```java
    ...
    static const char* VERTEX_SHADER =
       "attribute vec4 aPosition;\n"
       "uniform mat4 uProjection;\n"
       "uniform float uHeight;\n"
       "uniform float uTime;\n"
       "void main() {\n"
       "    const float speed = -800.0;\n"
       "    const float size = 8.0;\n"
       "    vec4 position = aPosition;\n"
       "    position.x = aPosition.x;\n"
       "    position.y = mod(aPosition.y + (uTime * speed * aPosition.z),"
       "                                              uHeight);\n"
       "    position.z = 0.0;\n"
       "    gl_Position =  uProjection * position;\n"
       "    gl_PointSize = aPosition.z * size;"
       "}";
    ...
    ```

    片段着色器要简单得多，只在屏幕上绘制星星纹理：

    ```java
    ...
    static const char* FRAGMENT_SHADER =
        "precision mediump float;\n"
        "uniform sampler2D uTexture;\n"
        "void main() {\n"
        "  gl_FragColor = texture2D(uTexture, gl_PointCoord);\n"
        "}";
    ...
    ```

1.  在`load()`函数中，借助`GraphicsManager`中实现的`loadVertexBuffer()`方法生成顶点缓冲区。每个星星由一个顶点表示。屏幕上的位置和深度是随机生成的。深度在[0.0, 1.0]范围内确定。完成此操作后，释放临时内存缓冲区，该缓冲区保存星星场数据：

    ```java
    ...
    status StarField::load() {
        Log::info("Loading star field.");
        TextureProperties* textureProperties;

        // Allocates a temporary buffer and populate it with point data:
        // 1 vertices composed of 3 floats (X/Y/Z) per point.
        Vertex* vertexBuffer = new Vertex[mStarCount];
        for (int32_t i = 0; i < mStarCount; ++i) {
            vertexBuffer[i].x = RAND(mGraphicsManager.getRenderWidth());
            vertexBuffer[i].y = RAND(mGraphicsManager.getRenderHeight());
            vertexBuffer[i].z = RAND(1.0f);
        }
        // Loads the vertex buffer into OpenGL.
        mVertexBuffer = mGraphicsManager.loadVertexBuffer(
            (uint8_t*) vertexBuffer, mStarCount * sizeof(Vertex));
        delete[] vertexBuffer;
        if (mVertexBuffer == 0) goto ERROR;
    ...
    ```

1.  然后，加载`star`纹理并从上面定义的着色器生成程序。获取它们的属性和统一标识符：

    ```java
    ...
        // Loads the texture.
        textureProperties =
                mGraphicsManager.loadTexture(mTextureResource);
        if (textureProperties == NULL) goto ERROR;
        mTexture = textureProperties->texture;

        // Creates and retrieves shader attributes and uniforms.
        mShaderProgram = mGraphicsManager.loadShader(VERTEX_SHADER,
                FRAGMENT_SHADER);
        if (mShaderProgram == 0) goto ERROR;
        aPosition = glGetAttribLocation(mShaderProgram, "aPosition");
        uProjection = glGetUniformLocation(mShaderProgram,"uProjection");
        uHeight = glGetUniformLocation(mShaderProgram, "uHeight");
        uTime = glGetUniformLocation(mShaderProgram, "uTime");
        uTexture = glGetUniformLocation(mShaderProgram, "uTexture");

        return STATUS_OK;

    ERROR:
        Log::error("Error loading starfield");
        return STATUS_KO;
    }
    ...
    ```

1.  最后，通过在一次绘制调用中发送静态顶点缓冲区、纹理和着色器程序来渲染`star`场。为此：

    +   禁用混合，即透明度的管理。实际上，星星“粒子”很小，稀疏，并且是在黑色背景上绘制的。

    +   首先选择顶点缓冲区`glBindBuffer()`。当在加载时生成了一个静态顶点缓冲区时，这个调用是必要的。

    +   使用`glVertexAttribPointer()`指示顶点数据的结构，并通过`glEnableVertexAttribArray()`关联到哪个着色器属性。请注意，这次`glVertexAttribPointer()`的最后一个参数不是指向缓冲区的指针，而是顶点缓冲区内的索引。实际上，顶点缓冲区是静态的，位于 GPU 内存中，因此我们不知道它的地址。

    +   使用`glActiveTexture()`和`glBindTexture()`选择要绘制的纹理。

    +   使用`glUseProgram()`选择着色器程序。

    +   使用`glUniform`函数变体绑定程序参数。

    +   最后，通过`glDrawArrays()`向 OpenGL 发送绘制调用。

    然后，你可以恢复 OpenGL 管道状态：

    ```java
    ...
    void StarField::draw() {
        glDisable(GL_BLEND);

        // Selects the vertex buffer and indicates how data is stored.
        glBindBuffer(GL_ARRAY_BUFFER, mVertexBuffer);
        glEnableVertexAttribArray(aPosition);
        glVertexAttribPointer(aPosition, // Attribute Index
                              3, // Number of components
                              GL_FLOAT, // Data type
                              GL_FALSE, // Normalized
                              3 * sizeof(GLfloat), // Stride
                              (GLvoid*) 0); // First vertex

        // Selects the texture.
        glActiveTexture(GL_TEXTURE0);
        glBindTexture(GL_TEXTURE_2D, mTexture);

        // Selects the shader and passes parameters.
        glUseProgram(mShaderProgram);
        glUniformMatrix4fv(uProjection, 1, GL_FALSE,
                mGraphicsManager.getProjectionMatrix());
        glUniform1f(uHeight, mGraphicsManager.getRenderHeight());
        glUniform1f(uTime, mTimeManager.elapsedTotal());
        glUniform1i(uTexture, 0);

        // Renders the star field.
        glDrawArrays(GL_POINTS, 0, mStarCount);

        // Restores device state.
        glBindBuffer(GL_ARRAY_BUFFER, 0);
        glUseProgram(0);
    }
    ```

1.  在`jni/DroidBlaster.hpp`中，定义新的`StarField`组件以及一个新的纹理资源：

    ```java
    ...
    #include "Ship.hpp"
    #include "SpriteBatch.hpp"
    #include "StarField.hpp"
    #include "TimeManager.hpp"
    #include "Types.hpp"

    class DroidBlaster : public ActivityHandler {
        ...
    private:
        ...
        Resource mAsteroidTexture;
        Resource mShipTexture;
        Resource mStarTexture;

        Asteroid mAsteroids;
        Ship mShip;
        StarField mStarField;
        SpriteBatch mSpriteBatch;
    };
    #endif
    ```

1.  在`jni/DroidBlaster.cpp`构造函数中实例化它，使用`50`个星星：

    ```java
    ...

    static const int32_t STAR_COUNT = 50;

    DroidBlaster::DroidBlaster(android_app* pApplication):
        mTimeManager(),
        mGraphicsManager(pApplication),
        mPhysicsManager(mTimeManager, mGraphicsManager),
        mEventLoop(pApplication, *this),

        mAsteroidTexture(pApplication, "droidblaster/asteroid.png"),
        mShipTexture(pApplication, "droidblaster/ship.png"),
        mStarTexture(pApplication, "droidblaster/star.png"),

        mAsteroids(pApplication, mTimeManager, mGraphicsManager,
                mPhysicsManager),
        mShip(pApplication, mGraphicsManager),
        mStarField(pApplication, mTimeManager, mGraphicsManager,
                STAR_COUNT, mStarTexture),
        mSpriteBatch(mTimeManager, mGraphicsManager) {
        Log::info("Creating DroidBlaster");
        ...
    }
    ```

在运行`DroidBlaster`之前，将`droidblaster/star.png`文件添加到 assets 目录中。这些文件随本书一起提供，位于`DroidBlaster_Part8/assets`目录。

## *刚才发生了什么？*

运行`DroidBlaster`。在随机速度滚动屏幕时，星域应该看起来像下面的截图所示：

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645OS_06_03.jpg)

所有这些星星都是作为点精灵渲染的，其中每个点代表一个由以下确定的四边形：

+   **屏幕上的一个位置**：该位置表示点精灵的中心。

+   **一个点的大小**：大小隐式定义了点精灵四边形的尺寸。

点精灵是创建粒子效果的一种有趣方式，但它们有一些缺点，包括：

+   它们可能的大小或多或少受到硬件能力的限制。你可以通过使用`glGetFloatv()`查询`GL_ALIASED_POINT_SIZE_RANGE`来找到最大尺寸；以下示例将展示这一点：

    ```java
    float pointSizeRange[2];
    glGetFloatv(GL_ALIASED_POINT_SIZE_RANGE, pointSizeRange);
    ```

+   如果你绘制更大的点精灵，你会注意到粒子在它们的中心被剪裁（即遮罩），整个精灵边界没有超出屏幕。

因此，根据你的需要，使用传统的顶点可能更合适。

谈到顶点，你可能已经注意到我们没有创建一个顶点数组，而是创建了一个顶点缓冲对象。实际上，点精灵完全在顶点着色器中评估。这种优化允许我们使用静态几何体（使用提示`GL_STATIC_DRAW`的`glBufferData()`），驱动程序可以有效地管理它。请注意，顶点缓冲对象也可以被标记为需要更新，使用提示`GL_DYNAMIC_DRAW`（意味着缓冲区将频繁变化）或`GL_STREAM_DRAW`（意味着缓冲区将使用一次后丢弃）。创建 VBO 的过程与在 OpenGL 中创建任何其他类型对象的过程类似，涉及生成新的标识符，选择它，并最终将数据上传到驱动程序内存。如果你理解这个过程，你就理解了 OpenGL 的工作方式。

## 使用 GLSL 编程着色器

着色器是用 GLSL 编写的，这是一种相对高级的编程语言，允许定义函数（带有 in、out 和 inout 参数）、条件语句、循环、变量、数组、结构、算术运算符等等。它尽可能地抽象了硬件的特定性。GLSL 允许使用以下类型的变量：

| **attributes** | 这些包含每个顶点的数据，例如顶点位置或纹理坐标。每次着色器执行时只处理一个顶点。 |
| --- | --- |
| **const** | 它表示编译时常量或只读函数参数。 |
| **uniforms** | 这些是一种全局参数，可以根据每个图元（即每次绘制调用）进行更改。对于整个网格来说，它具有相同的值。这方面的一个例子可能是模型视图矩阵（对于顶点着色器）或纹理（对于片段着色器）。 |
| **varying** | 这些是根据顶点着色器输出计算的每个像素的插值值。它们在顶点着色器中是输出参数，在片段着色器中是输入参数。在 OpenGL ES 3 中，“varying”参数有新的语法：在顶点着色器中使用 `out`，在像素着色器中使用 `in`。 |

可以声明此类变量的主要参数类型如下表所示：

| **void** | 这仅用于函数结果。 |
| --- | --- |
| **bool** | 这是一个布尔值。 |
| **float** | 这是一个浮点数。 |
| **int** | 这是一个有符号整数。 |
| **vec2, vec3, vec4** | 这是一个浮点数向量。存在其他类型的向量，例如用于布尔值的 `bvec` 或用于有符号整数的 `ivec`。 |
| **mat2, mat3, mat4** | 这些是 2x2、3x3 和 4x4 浮点矩阵。 |
| **sampler2D** | 这提供了对 2D 纹理纹理元素（texel）的访问。 |

请注意 GLSL 规范提供了一些预定义的变量，如下表所示：

| **highp vec4 gl_Position** | 顶点着色器输出 | 这是变换后的顶点位置。 |
| --- | --- | --- |
| **mediump float gl_PointSize** | 顶点着色器输出 | 这是点精灵的大小，以像素为单位（关于这一点将在下一部分中讨论）。 |
| **mediump vec4 gl_FragCoord** | 片段着色器输入 | 这些是片段在帧缓冲区内的坐标。 |
| **mediump vec4 gl_FragColor** | 片段着色器输出 | 这是要为片段显示的颜色。 |

提供了许多函数，主要是算术函数，例如 `sin()`、`cos()`、`tan()`、`radians()`、`degrees()`、`mod()`、`abs()`、`floor()`、`ceil()`、`dot()`、`cross()`、`normalize()`、`texture2D()` 等等。

在处理着色器时，以下是一些需要记住的最佳实践：

+   不要在运行时编译或链接着色器。

+   注意不同硬件具有不同的功能，特别是允许的变量数量有限。

+   在定义精度说明符时（例如`highp`、`medium`或`lowp`），在性能和准确性之间找到一个好的折中方案。不要犹豫，重新定义它们以获得一致的行为。注意，`float`精度说明符应在 GLES 片段着色器中定义。

+   尽可能避免条件分支。

想了解更多信息，请查看 OpenGL.org 维基页面：[`www.opengl.org/wiki/OpenGL_Shading_Language`](http://www.opengl.org/wiki/OpenGL_Shading_Language)，[`www.opengl.org/wiki/Vertex_Shader`](http://www.opengl.org/wiki/Vertex_Shader)和[`www.opengl.org/wiki/Fragment_Shader`](http://www.opengl.org/wiki/Fragment_Shader)。

注意，这些页面的内容适用于 OpenGL，但不一定适用于 GLES。

# 适配各种分辨率的图形

在编写游戏时，需要处理的一个复杂主题是安卓屏幕尺寸的碎片化。低端手机的分辨率只有几百像素，而一些高端设备提供的分辨率则超过两千。

有多种方法可以处理不同的屏幕尺寸。我们可以适配图形资源，使用屏幕周围的黑色带，或者将响应式设计应用于游戏。

另一个简单的解决方案是使用固定大小离屏渲染游戏场景。然后将离屏帧缓冲区复制到屏幕上，并缩放到适当的大小。这种“一刀切”技术并不能提供最佳质量，在低端设备上可能会有些慢（特别是如果它们的分辨率低于离屏帧缓冲区）。然而，应用它相当简单。

### 注意

本书的附赠项目中提供了名为`DroidBlaster_Part9`的结果项目。

# 动手时间——通过离屏渲染适配分辨率

让我们在离屏渲染游戏场景：

1.  更改`jni/GraphicsManager.hpp`，然后执行以下步骤：

    +   定义获取屏幕宽度和高度的新方法，以及它们对应的成员变量

    +   创建一个新函数`initializeRenderBuffer()`，用于创建离屏缓冲区以渲染场景：

        ```java
        ...
        class GraphicsManager {
        public:
            ...
            int32_t getRenderWidth() { return mRenderWidth; }s
            int32_t getRenderHeight() { return mRenderHeight; }
            int32_t getScreenWidth() { return mScreenWidth; }
         int32_t getScreenHeight() { return mScreenHeight; }
            GLfloat* getProjectionMatrix() { return mProjectionMatrix[0]; }

        ...
        ```

1.  在同一文件中，执行以下步骤：

    +   声明一个新的`RenderVertex`结构，包含四个分量 - `x`、`y`、`u`和`v`

    +   定义帧缓冲区所需的 OpenGL 资源，即纹理、顶点缓冲区、着色器程序及其变量：

        ```java
        ...
        private:
            status initializeRenderBuffer();

         struct RenderVertex {
         GLfloat x, y, u, v;
            };

            android_app* mApplication;

            int32_t mRenderWidth; int32_t mRenderHeight;
            int32_t mScreenWidth; int32_t mScreenHeight;
            EGLDisplay mDisplay; EGLSurface mSurface; EGLContext mContext;
            GLfloat mProjectionMatrix[4][4];
            ...

            // Rendering resources.
         GLint mScreenFrameBuffer;
         GLuint mRenderFrameBuffer; GLuint mRenderVertexBuffer;
         GLuint mRenderTexture; GLuint mRenderShaderProgram;
         GLuint aPosition; GLuint aTexture;
         GLuint uProjection; GLuint uTexture;
        };
        #endif
        ```

1.  更新`jni/GraphicsManager.cpp`构造函数初始化列表，以初始化默认值：

    ```java
    #include "GraphicsManager.hpp"
    #include "Log.hpp"

    #include <png.h>

    GraphicsManager::GraphicsManager(android_app* pApplication) :
        ...
        mComponents(), mComponentCount(0),
        mScreenFrameBuffer(0),
     mRenderFrameBuffer(0), mRenderVertexBuffer(0),
     mRenderTexture(0), mRenderShaderProgram(0),
     aPosition(0), aTexture(0),
     uProjection(0), uTexture(0) {
        Log::info("Creating GraphicsManager.");
    }
    ...
    ```

1.  更改`start()`方法，分别将显示表面宽度与高度保存到`mScreenWidth`和`mScreenHeight`中。

    然后，调用`initializeRenderBuffer()`：

    ```java
    ...
    status GraphicsManager::start() {
        ...
        Log::info("Initializing the display.");
        mSurface = eglCreateWindowSurface(mDisplay, config,
            mApplication->window, NULL);
        if (mSurface == EGL_NO_SURFACE) goto ERROR;
        mContext = eglCreateContext(mDisplay, config, NULL,
            CONTEXT_ATTRIBS);
        if (mContext == EGL_NO_CONTEXT) goto ERROR;

        if (!eglMakeCurrent(mDisplay, mSurface, mSurface, mContext)
       || !eglQuerySurface(mDisplay, mSurface, EGL_WIDTH, &mScreenWidth)
     || !eglQuerySurface(mDisplay, mSurface, EGL_HEIGHT, &mScreenHeight)
     || (mScreenWidth <= 0) || (mScreenHeight <= 0)) goto ERROR;

     // Defines and initializes offscreen surface.
     if (initializeRenderBuffer() != STATUS_OK) goto ERROR;

        glViewport(0, 0, mRenderWidth, mRenderHeight);
        glDisable(GL_DEPTH_TEST);
        ...
    }
    ...
    ```

1.  为离屏渲染定义顶点和片段着色器。这与我们至今所见的类似：

    ```java
    ...
    static const char* VERTEX_SHADER =
        "attribute vec2 aPosition;\n"
        "attribute vec2 aTexture;\n"
        "varying vec2 vTexture;\n"
        "void main() {\n"
        "    vTexture = aTexture;\n"
        "    gl_Position = vec4(aPosition, 1.0, 1.0 );\n"
        "}";

    static const char* FRAGMENT_SHADER =
        "precision mediump float;"
        "uniform sampler2D uTexture;\n"
        "varying vec2 vTexture;\n"
        "void main() {\n"
        "  gl_FragColor = texture2D(uTexture, vTexture);\n"
        "}\n";
    ...
    ```

1.  在`initializeRenderBuffer()`中，创建一个预定义的顶点数组，该数组将要被加载到 OpenGL 中。它代表了一个带有完整纹理的单一四边形。

    计算基于固定目标宽度`600`像素的新渲染高度。

    使用`glGetIntegerv()`和特殊值`GL_FRAMEBUFFER_BINDING`从最终场景渲染的位置获取当前屏幕帧缓冲区：

    ```java
    ...
    const int32_t DEFAULT_RENDER_WIDTH = 600;

    status GraphicsManager::initializeRenderBuffer() {
        Log::info("Loading offscreen buffer");
        const RenderVertex vertices[] = {
            { -1.0f, -1.0f, 0.0f, 0.0f },
            { -1.0f,  1.0f, 0.0f, 1.0f },
            {  1.0f, -1.0f, 1.0f, 0.0f },
            {  1.0f,  1.0f, 1.0f, 1.0f }
        };

        float screenRatio = float(mScreenHeight) / float(mScreenWidth);
        mRenderWidth = DEFAULT_RENDER_WIDTH;
        mRenderHeight = float(mRenderWidth) * screenRatio;
        glGetIntegerv(GL_FRAMEBUFFER_BINDING, &mScreenFrameBuffer);
    ...
    ```

1.  创建一个用于离屏渲染的纹理，就像我们之前看到的那样。在`glTexImage2D()`中，传递`NULL`值作为最后一个参数，只创建表面而不初始化其内容：

    ```java
    ...
        glGenTextures(1, &mRenderTexture);
        glBindTexture(GL_TEXTURE_2D, mRenderTexture);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S,
                GL_CLAMP_TO_EDGE);
        glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T,
                GL_CLAMP_TO_EDGE);
        glTexImage2D(GL_TEXTURE_2D, 0, GL_RGB, mRenderWidth,
                mRenderHeight, 0, GL_RGB, GL_UNSIGNED_SHORT_5_6_5, NULL);
    ...
    ```

1.  然后，使用`glGenFramebuffers()`创建一个离屏帧缓冲区。

    使用`glBindFramebuffer()`将之前的纹理附着到它上面。

    最后，恢复设备状态：

    ```java
    ...
        glGenFramebuffers(1, &mRenderFrameBuffer);
        glBindFramebuffer(GL_FRAMEBUFFER, mRenderFrameBuffer);
        glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0,
                GL_TEXTURE_2D, mRenderTexture, 0);
        glBindTexture(GL_TEXTURE_2D, 0);
        glBindFramebuffer(GL_FRAMEBUFFER, 0);
    ...
    ```

1.  创建用于将纹理渲染到屏幕的着色器程序，并获取其属性和制服：

    ```java
    ...
        mRenderVertexBuffer = loadVertexBuffer(vertices,
                sizeof(vertices));
        if (mRenderVertexBuffer == 0) goto ERROR;

        mRenderShaderProgram = loadShader(VERTEX_SHADER, FRAGMENT_SHADER);
        if (mRenderShaderProgram == 0) goto ERROR;
        aPosition = glGetAttribLocation(mRenderShaderProgram,"aPosition");
        aTexture = glGetAttribLocation(mRenderShaderProgram, "aTexture");
        uTexture = glGetUniformLocation(mRenderShaderProgram,"uTexture");

        return STATUS_OK;

    ERROR:
        Log::error("Error while loading offscreen buffer");
        return STATUS_KO;
    }
    ...
    ```

1.  在活动结束时，不要忘记在`stop()`中释放分配的资源：

    ```java
    ...
    void GraphicsManager::stop() {
        ...

        if (mRenderFrameBuffer != 0) {
     glDeleteFramebuffers(1, &mRenderFrameBuffer);
     mRenderFrameBuffer = 0;
     }
     if (mRenderTexture != 0) {
     glDeleteTextures(1, &mRenderTexture);
     mRenderTexture = 0;
     }

        // Destroys OpenGL context.
        ...
    }
    ...
    ```

1.  最后，使用新的离屏帧缓冲区来渲染场景。为此，你需要：

    使用`glBindFramebuffer()`选择帧缓冲区。

    指定渲染视口，它必须与离屏帧缓冲区的尺寸相匹配，如下所示：

    ```java
    ...
    status GraphicsManager::update() {
        glBindFramebuffer(GL_FRAMEBUFFER, mRenderFrameBuffer);
     glViewport(0, 0, mRenderWidth, mRenderHeight);
        glClear(GL_COLOR_BUFFER_BIT);

        // Render graphic components.
        for (int32_t i = 0; i < mComponentCount; ++i) {
            mComponents[i]->draw();
        }
    ...
    ```

1.  渲染完成后，恢复正常的屏幕帧缓冲区和正确的视口尺寸。

    然后，选择以下参数作为源：

    +   离屏纹理，它附着在离屏帧缓冲区上。

    +   着色器程序，它基本上除了在屏幕帧缓冲区上投影顶点和缩放纹理之外什么也不做。

    +   顶点缓冲区，它包含一个带有纹理坐标的单个四边形，如下代码所示：

        ```java
        ...
            glBindFramebuffer(GL_FRAMEBUFFER, mScreenFrameBuffer);
         glClear(GL_COLOR_BUFFER_BIT);
         glViewport(0, 0, mScreenWidth, mScreenHeight);

         glActiveTexture(GL_TEXTURE0);
         glBindTexture(GL_TEXTURE_2D, mRenderTexture);
         glUseProgram(mRenderShaderProgram);
         glUniform1i(uTexture, 0);

         // Indicates to OpenGL how position and uv coordinates are stored.
         glBindBuffer(GL_ARRAY_BUFFER, mRenderVertexBuffer);
         glEnableVertexAttribArray(aPosition);
         glVertexAttribPointer(aPosition, // Attribute Index
         2, // Number of components (x and y)
         GL_FLOAT, // Data type
         GL_FALSE, // Normalized
         sizeof(RenderVertex), // Stride
         (GLvoid*) 0); // Offset
         glEnableVertexAttribArray(aTexture);
         glVertexAttribPointer(aTexture, // Attribute Index
         2, // Number of components (u and v)
         GL_FLOAT, // Data type
         GL_FALSE, // Normalized
         sizeof(RenderVertex), // Stride
         (GLvoid*) (sizeof(GLfloat) * 2)); // Offset
        ...
        ```

1.  最后，通过将离屏缓冲区渲染到屏幕上来结束。

    然后，你可以像这样再次恢复设备状态：

    ```java
    ...
        glDrawArrays(GL_TRIANGLE_STRIP, 0, 4);
     glBindBuffer(GL_ARRAY_BUFFER, 0);

        // Shows the result to the user.
        if (eglSwapBuffers(mDisplay, mSurface) != EGL_TRUE) {
        ...
    }
    ...
    ```

## *刚才发生了什么？*

在多个设备上启动应用程序。每个设备应该显示一个比例相似的景象。实际上，现在图形渲染到一个附着在纹理上的离屏帧缓冲区。然后根据目标屏幕分辨率进行缩放，以提供不同设备上的相同体验。这个简单且经济的解决方案有一个缺点，即根据选择的固定分辨率，低端设备可能会受到影响，而高端设备则会显得模糊。

### 注意

处理各种屏幕分辨率是一方面。管理它们的多种宽高比则是另一方面。这个问题有几种解决方案，比如使用黑边条、拉伸屏幕，或者定义一个只包含重要信息的可显示的最小和最大区域。

通常，离屏渲染场景通常被称为**渲染到纹理**。这种技术常用于实现阴影、反射或后期处理效果。掌握这项技术是实现高质量游戏的关键。

# 总结

OpenGL 和一般的图形是一个复杂且技术性很强的 API。一本书不足以完全涵盖它，但使用纹理和缓冲对象绘制 2D 图形为更高级的内容打开了大门！

更具体地说，你已经学会了如何初始化一个 OpenGL ES 上下文并将其绑定到一个 Android 窗口。然后，你了解了如何将 libpng 转换为一个模块，并从 PNG 资源中加载纹理。我们使用了这个纹理，并结合顶点缓冲区和着色器来渲染精灵和粒子。最后，我们找到了一个简单的离屏渲染和缩放技术解决方案，以解决 Android 分辨率碎片化问题。

OpenGL ES 是一个复杂的 API，需要深入理解才能获得最佳性能和品质。这同样适用于自 Android KitKat 以来可用的 OpenGL ES 3，我们在这里并未涉及。不妨查看以下内容：

+   查阅[OpenGL ES 和 GLSL 规范](http://www.khronos.org/registry/gles/)。

+   访问[Android 开发者网站](http://developer.android.com/guide/topics/graphics/opengl.html)获取更多信息。

在这里获得的知识，使得通往 OpenGL ES 2 或 3 的道路变得完全可行！现在，让我们在下一章中探索如何通过 OpenSL ES 达到第四维度，即音乐维度。
