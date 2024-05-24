# 安卓 NDK 初学者指南第二版（五）

> 原文：[`zh.annas-archive.org/md5/A3DD702F9D1A87E6BE95B1711A85BCDE`](https://zh.annas-archive.org/md5/A3DD702F9D1A87E6BE95B1711A85BCDE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：将现有库移植到 Android

> 人们关注 Android NDK 主要有两个原因：首先是为了性能，其次是为了可移植性。在前面的章节中，我们看到了如何从本地代码访问主要的本地 Android API 以提高效率。在本章中，我们将把整个 C/C++生态系统带到 Android，至少探索这条路径，因为几十年的 C/C++开发很难适应移动设备有限的内存！确实，C 和 C++仍然是现今最广泛使用的编程语言之一。
> 
> 在之前的 NDK 版本中，由于对 C++的支持不完整，特别是**异常**和**运行时类型信息**（**RTTI**，一个基本的 C++反射机制，用于在运行时获取数据类型，例如 Java 中的`instanceof`），可移植性受到限制。任何需要这些特性的库，如果不修改代码或安装自定义 NDK（由社区从官方源代码重建的**Crystax NDK**，可在[`www.crystax.net/`](http://www.crystax.net/)获取），都无法移植。幸运的是，许多这些限制已经解除（除了宽字符支持）。

尽管不一定困难，但移植现有库并非易事。可能会缺少一些 API（尽管 POSIX 支持良好），一些`#define`指令需要调整，一些依赖项以及依赖项的依赖项需要移植。一些库将容易移植，而另一些则需要更多努力。

在本章中，为了将现有代码移植到 Android，我们将学习如何进行以下代码操作：

+   激活**标准模板库**（**STL**）

+   移植**Box2D**物理引擎

+   预构建并使用**Boost**框架

+   深入了解如何编写 NDK 模块**Makefiles**

在本章结束时，你应该了解本地构建过程，并知道如何适当使用 Makefiles。

# 激活标准模板库

标准模板库是一个标准化的容器、迭代器、算法和辅助类的库，可以简化大多数常见的编程操作，如动态数组、关联数组、字符串、排序等。这个库在开发者中得到了多年的认可并被广泛传播。在 C++中开发而不使用 STL，就像一只手背在身后编程一样！

在第一部分中，让我们将 GNU STL 嵌入 DroidBlaster，以便简化集合管理。

### 注意

本书提供的项目名为`DroidBlaster_Part16`。

# 动手实践——在 DroidBlaster 中激活 GNU STL

让我们在 DroidBlaster 中激活并使用 STL。编辑`jni/Application.mk`文件，旁边是`jni/Android.mk`，并写入以下内容。就这样！你的应用程序现在启用了 STL，多亏了这一行：

```java
APP_ABI := armeabi armeabi-v7a x86
APP_STL := gnustl_static
```

## *刚才发生了什么？*

在 `Application.mk` 文件中，我们只用一行代码就激活了 GNU STL！这个通过 `APP_STL` 变量选择的 STL 实现，替换了默认的 NDK C/C++ 运行时。目前支持以下三种 STL 实现：

+   **GNU STL**（更常见的名称是 **libstdc++**），官方 GCC STL：这通常是在 NDK 项目中使用 STL 的首选。支持异常和 RTTI。

+   **STLport**（多平台 STL）：这个实现现在没有积极维护，并且缺少一些功能。在万不得已的情况下选择它。支持异常和 RTTI。

+   **Libc++**：这是 LLVM 的一部分（Clang 编译器背后的技术），旨在提供一个功能性的 C++ 11 运行时。请注意，这个库现在正在成为 OS-X 上的默认 STL，并且将来可能会变得更加流行。支持异常和 RTTI。Libc++ 的支持仍然是不完整的和实验性的。Libc++ 通常与 Clang 编译器一起选择（在 *掌握模块 Makefiles* 部分了解更多信息）。

安卓还提供了另外两个 C++ 运行时：

+   **系统**：当没有激活任何 STL 实现时，这是 NDK 的默认运行时。其代码名称为 **Bionic**，并提供了一组最小化的头文件（`cstdint`，`cstdio`，`cstring` 等）。Bionic 不提供 STL 功能，以及异常和**运行时类型信息**（**RTTI**）。关于其限制的更多详情，请查看 `$ANDROID_NDK/docs/system/libc/OVERVIEW.html`。

+   **Gabi**：这类似于系统运行时，不同之处在于它支持异常和 RTTI。

在本章专门讨论 **Boost** 的部分，我们将看到如何在编译过程中启用异常和 RTTI。

每个运行时都可以静态或动态链接（默认系统 C/C++ 运行时除外）。动态加载的运行时以 `_shared` 作为后缀，静态加载的则以 `_static` 作为后缀。你可以传递给 `APP_STL` 的运行时标识符完整列表如下：

+   `system`

+   `gabi++_static` 和 `gabi++_shared`

+   `stlport_static` 和 `stlport_shared`

+   `gnustl_static` 和 `gnustl_shared`

+   `c++_static` 和 `c++_shared`

请记住，共享库需要在运行时手动加载。如果你忘记加载一个共享库，那么在加载依赖库模块时，运行时就会引发错误。由于编译器无法提前预测哪些函数将被调用，因此库将完全加载到内存中，即使它们的大部分内容未被使用。

另一方面，静态库实际上是与依赖库一起加载的。实际上，在运行时并不真正存在静态库。在编译时链接时，它们的内容被复制到依赖库中。由于链接器确切地知道库的哪部分被嵌入模块调用，因此它可以剥离其代码，只保留需要的部分。

### 提示

**剥离**是丢弃二进制文件中不必要符号的过程。这有助于在链接后减少（可能是大量！）二进制文件大小。这可以与 Java 中的 Proguard 收缩后处理进行比较。

然而，如果静态库被多次包含，链接将导致二进制代码重复。这种情况可能导致内存浪费，或者更令人担忧的是，例如全局变量重复的问题。但是，共享库中的静态 C++构造函数只被调用一次。

### 提示

请记住，除非你知道自己在做什么，否则应该避免在项目中多次使用静态库。

另一个需要考虑的问题是，Java 应用程序只能加载共享库，这些共享库可以链接到共享或静态库。例如，`NativeActivity`的主库是一个共享库，通过`android.app.lib_name`清单属性指定。从另一个库引用的共享库必须在之前手动加载。NDK 不会自动处理。

在 JNI 应用程序中，共享库可以通过`System.loadLibrary()`轻松加载，但`NativeActivity`是“透明”的活动。因此，如果你决定使用共享库，唯一的解决方案是编写自己的 Java 活动，从`NativeActivity`继承并调用适当的`loadLibrary()`指令。例如，如果我们使用`gnustl_shared`，DroidBlaster 活动可能如下所示：

```java
package com.packtpub.DroidBlaster

import android.app.NativeActivity

public class MyNativeActivity extends NativeActivity {
     static {
         System.loadLibrary("gnustl_shared");
         System.loadLibrary("DroidBlaster");
     }
}
```

### 提示

如果你更愿意直接从本地代码加载本地库，你可以使用 NDK 提供的系统调用`dlopen()`。

既然已经启用了 STL，让我们在 DroidBlaster 中使用它。

# 行动时间——使用 STL 流读取文件

让我们使用 STL 从 SD 卡读取资源，而不是应用程序资源目录，如下步骤所示：

1.  显然，如果我们不在代码中主动使用 STL，那么启用 STL 是毫无用处的。让我们借此机会从资源文件切换到外部文件（位于`sdcard`或内部存储）。

    打开现有文件`jni/Resource.hpp`，进行以下操作：

    +   包含`fstream`和`string`STL 头文件。

    +   使用`std::string`对象作为文件名，并用`std::ifstream`对象（即输入文件流）替换资产管理成员。

    +   改变`getPath()`方法，使其从新的`string`成员返回 C 字符串。

    +   移除`descriptor()`方法和`ResourceDescriptor`类（描述符只与 Asset API 一起工作），如下所示：

        ```java
        #ifndef _PACKT_RESOURCE_HPP_
        #define _PACKT_RESOURCE_HPP_

        #include "Types.hpp"

        #include <android_native_app_glue.h>
        #include <fstream>
        #include <string>

        ...
        class Resource {
        public:
            Resource(android_app* pApplication, const char* pPath);

            const char* getPath() { return mPath.c_str(); };

            status open();
            void close();
            status read(void* pBuffer, size_t pCount);

            off_t getLength();

            bool operator==(const Resource& pOther);

        private:
            std::string mPath;
            std::ifstream mInputStream;
        };
        #endif
        ```

1.  打开相应的实现文件`jni/Resource.cpp`。用基于 STL 流和字符串的资产管理 API 替换之前的实现。文件将以二进制模式打开，如下所示：

    ```java
    #include "Resource.hpp"

    #include <sys/stat.h>

    Resource::Resource(android_app* pApplication, const char* pPath):
        mPath(std::string("/sdcard/") + pPath),
        mInputStream(){
    }

    status Resource::open() {
        mInputStream.open(mPath.c_str(), std::ios::in | std::ios::binary);
     return mInputStream ? STATUS_OK : STATUS_KO;
    }

    void Resource::close() {
        mInputStream.close();
    }

    status Resource::read(void* pBuffer, size_t pCount) {
        mInputStream.read((char*)pBuffer, pCount);
        return (!mInputStream.fail()) ? STATUS_OK : STATUS_KO;
    }
    ...
    ```

1.  要读取文件长度，我们可以使用来自`sys/stat.h`头文件的`stat()` POSIX 原始函数：

    ```java
    ...
    off_t Resource::getLength() {
        struct stat filestatus;
        if (stat(mPath.c_str(), &filestatus) >= 0) {
            return filestatus.st_size;
        } else {
            return -1;
        }
    }
    ...
    ```

1.  最后，我们可以使用 STL 字符串比较运算符来比较两个`Resource`对象：

    ```java
    ...
    bool Resource::operator==(const Resource& pOther) {
        return mPath == pOther.mPath;
    }
    ```

1.  对于阅读系统的这些更改应该是几乎透明的，除了背景音乐（BGM），其内容是通过资产文件描述符播放的。

    现在，我们需要提供一个真实的文件。因此，在`jni/SoundService.cpp`中，通过将`SLDataLocator_AndroidFD`结构替换为`SLDataLocation_URI`来更改数据源，如下所示：

    ```java
    #include "Log.hpp"
    #include "Resource.hpp"
    #include "SoundService.hpp"

    #include <string>
    ...
    status SoundManager::playBGM(Resource& pResource) {
        SLresult result;
        Log::info("Opening BGM %s", pResource.getPath());

        // Set-up BGM audio source.
        SLDataLocator_URI dataLocatorIn;
        std::string path = pResource.getPath();
        dataLocatorIn.locatorType = SL_DATALOCATOR_URI;
        dataLocatorIn.URI = (SLchar*) path.c_str();

        SLDataFormat_MIME dataFormat;
        dataFormat.formatType    = SL_DATAFORMAT_MIME;
        ...
    }
    ...
    ```

1.  在`AndroidManifest.xml`文件中，添加读取 SD 卡文件的权限，如下所示： 

    ```java
    <?xml version="1.0" encoding="utf-8"?>
    <manifest 
        package="com.packtpub.droidblaster2d" android:versionCode="1"
        android:versionName="1.0">

        <uses-permission
            android:name="android.permission.READ_EXTERNAL_STORAGE" />

        ...
    </manifest>
    ```

将所有资产资源从资产目录复制到你的设备 SD 卡（或根据你的设备，内部存储）中的`/sdcard/droidblaster`。

## *刚才发生了什么？*

我们已经看到了如何通过 STL 流访问位于 SD 卡上的二进制文件。我们还把 OpenSL ES 播放器从文件描述符切换到了文件名定位器。文件名本身是在这里从 STL 字符串创建的。STL 字符串是一个真正的优势，因为它们让我们摆脱了复杂的 C 字符串操作原语。

### 提示

几乎所有的 Android 设备都可以在挂载在`/sdcard`目录的附加存储位置存储文件。这里“几乎”是重要的词。从第一款 Android G1 开始，“sdcard”的含义已经改变。一些最近的设备有一个实际上是内部的外部存储（例如，某些平板电脑上的闪存），还有一些其他设备可以使用第二个存储位置（尽管在大多数情况下，第二个存储是挂载在`/sdcard`内部的）。此外，`/sdcard`路径本身并不是刻在大理石上的。因此，为了安全地检测附加存储位置，唯一的解决方案是依靠 JNI 调用`android.os.Environment.getExternalStorageDirectory()`。你也可以通过`getExternalStorageState()`检查存储是否可用。请注意，API 方法名称中的“External”一词仅出于历史原因。此外，需要在 manifest 中请求`WRITE_EXTERNAL_STORAGE`权限。

STL 提供的功能远不止 Files 和 Strings。其中最受欢迎的可能是 STL 容器。让我们在 DroidBlaster 中看看一些使用示例。

# 动手时间——使用 STL 容器

现在让我们按照以下步骤将原始数组替换为标准的 STL 容器：

1.  打开`jni/GraphicsManager.hpp`头文件并包含以下头文件：

    +   `Vector`，它定义了一个 STL 容器，封装了 C 数组（并带有一些更有趣的特性，如动态调整大小）

    +   `Map`，它封装了相当于 Java HashMap 的东西（也就是关联数组）

    然后，在`TextureProperties`结构中移除`textureResource`成员。使用`map`容器代替`mTextures`的原始数组（使用`std`命名空间前缀）。第一个参数是键类型，第二个是值类型。

    最后，将所有其他原始数组替换为以下所示的`vector`：

    ```java
    ...
    #include <android_native_app_glue.h>
    #include <GLES2/gl2.h>
    #include <EGL/egl.h>

    #include <map>
    #include <vector>
    ...
    struct TextureProperties {
        GLuint texture;
        int32_t width;
        int32_t height;
    };

    class GraphicsManager {
        ...
        // Graphics resources.
        std::map<Resource*, TextureProperties> mTextures;
        std::vector<GLuint> mShaders;
        std::vector<GLuint> mVertexBuffers;

        std::vector<GraphicsComponent*> mComponents;

        // Rendering resources.
        ...
    };
    #endif
    ```

1.  编辑`jni/GraphicsManager.cpp`并在构造函数初始化列表中初始化新的 STL 容器，如下所示：

    ```java
    #include "GraphicsManager.hpp"
    #include "Log.hpp"

    #include <png.h>

    GraphicsManager::GraphicsManager(android_app* pApplication) :
        ...
        mProjectionMatrix(),
        mTextures(), mShaders(), mVertexBuffers(), mComponents(),
        mScreenFrameBuffer(0),
        mRenderFrameBuffer(0), mRenderVertexBuffer(0),
        ... {
        Log::info("Creating GraphicsManager.");
    }
    ...
    ```

1.  当组件注册时，使用`vector::push_back()`方法将组件插入到`mComponents`列表中，如下所示：

    ```java
    ...
    void GraphicsManager::registerComponent(GraphicsComponent* pComponent)
    {
        mComponents.push_back(pComponent);
    }
    ...
    ```

1.  在`start()`中，我们可以使用迭代器遍历向量，以初始化每个已注册的组件，如下所示：

    ```java
    ...
    status GraphicsManager::start() {
        ...
        mProjectionMatrix[3][3] =  1.0f;

        // Loads graphics components.
        for (std::vector<GraphicsComponent*>::iterator
                componentIt = mComponents.begin();
                componentIt < mComponents.end(); ++componentIt) {
            if ((*componentIt)->load() != STATUS_OK) return STATUS_KO;
        }
        return STATUS_OK;
        ...
    }
    ...
    ```

1.  在`stop()`中，我们可以遍历 map（其中 second 表示条目的值）和向量集合，以释放这次分配的每个 OpenGL 资源，如下所示：

    ```java
    ...
    void GraphicsManager::stop() {
        Log::info("Stopping GraphicsManager.");
        // Releases textures.
        std::map<Resource*, TextureProperties>::iterator textureIt;
        for (textureIt = mTextures.begin(); textureIt != mTextures.end();
                ++textureIt) {
            glDeleteTextures(1, &textureIt->second.texture);
        }

        // Releases shaders.
        std::vector<GLuint>::iterator shaderIt;
        for (shaderIt = mShaders.begin(); shaderIt < mShaders.end();
                ++shaderIt) {
            glDeleteProgram(*shaderIt);
        }
        mShaders.clear();

        // Releases vertex buffers.
        std::vector<GLuint>::iterator vertexBufferIt;
        for (vertexBufferIt = mVertexBuffers.begin();
                vertexBufferIt < mVertexBuffers.end(); ++vertexBufferIt) {
            glDeleteBuffers(1, &(*vertexBufferIt));
        }
        mVertexBuffers.clear();

        ...
    }
    ...
    ```

1.  还要在`update()`中遍历存储的组件以渲染它们，如下所示：

    ```java
    ...
    status GraphicsManager::update() {
        // Uses the offscreen FBO for scene rendering.
        glBindFramebuffer(GL_FRAMEBUFFER, mRenderFrameBuffer);
        glViewport(0, 0, mRenderWidth, mRenderHeight);
        glClear(GL_COLOR_BUFFER_BIT);

        // Render graphic components.
        std::vector<GraphicsComponent*>::iterator componentIt;
        for (componentIt = mComponents.begin();
                componentIt < mComponents.end(); ++componentIt) {
            (*componentIt)->draw();
        }

        // The FBO is rendered and scaled into the screen.
        glBindFramebuffer(GL_FRAMEBUFFER, mScreenFrameBuffer);
        ...
    }
    ...
    ```

1.  由于纹理是昂贵的资源，在加载和缓存新实例之前，使用`map`检查纹理是否已经加载，如下所示：

    ```java
    ...
    TextureProperties* GraphicsManager::loadTexture(Resource& pResource) {
        // Looks for the texture in cache first.
        std::map<Resource*, TextureProperties>::iterator textureIt =
                                               mTextures.find(&pResource);
        if (textureIt != mTextures.end()) {
            return &textureIt->second;
        }

        Log::info("Loading texture %s", pResource.getPath());
        ...
        Log::info("Texture size: %d x %d", width, height);

        // Caches the loaded texture.
        textureProperties = &mTextures[&pResource];
        textureProperties->texture = texture;
        textureProperties->width = width;
        textureProperties->height = height;
        return textureProperties;
        ...
    }
    ...
    ```

1.  使用定义的`vector`对象保存着色器和顶点缓冲区。再次使用`push_back()`向向量中添加一个元素，如下所示：

    ```java
    ...
    GLuint GraphicsManager::loadShader(const char* pVertexShader,
            const char* pFragmentShader) {
       ...
        if (result == GL_FALSE) {
            glGetProgramInfoLog(shaderProgram, sizeof(log), 0, log);
            Log::error("Shader program error: %s", log);
            goto ERROR;
        }

        mShaders.push_back(shaderProgram);
        return shaderProgram;

        ...
    }

    GLuint GraphicsManager::loadVertexBuffer(const void* pVertexBuffer,
            int32_t pVertexBufferSize) {
        ...
        if (glGetError() != GL_NO_ERROR) goto ERROR;

        mVertexBuffers.push_back(vertexBuffer);
        return vertexBuffer;
        ...
    }
    ```

1.  现在，打开`jni/SpriteBatch.hpp`。

    再次，包含并使用`vector`对象，而不是原始数组：

    ```java
    ...
    #ifndef _PACKT_GRAPHICSSPRITEBATCH_HPP_
    #define _PACKT_GRAPHICSSPRITEBATCH_HPP_

    #include "GraphicsManager.hpp"
    #include "Sprite.hpp"
    #include "TimeManager.hpp"
    #include "Types.hpp"

    #include <GLES2/gl2.h>
    #include <vector>

    class SpriteBatch : public GraphicsComponent {
        ...
        TimeManager& mTimeManager;
        GraphicsManager& mGraphicsManager;

        std::vector<Sprite*> mSprites;
        std::vector<Sprite::Vertex> mVertices;
        std::vector<GLushort> mIndexes;
        GLuint mShaderProgram;
        GLuint aPosition; GLuint aTexture;
        GLuint uProjection; GLuint uTexture;
    };
    #endif
    ```

1.  在`jni/SpriteBatch.cpp`中，用向量替换原始数组的用法，如下所示：

    ```java
    ...
    SpriteBatch::SpriteBatch(TimeManager& pTimeManager,
            GraphicsManager& pGraphicsManager) :
        mTimeManager(pTimeManager),
        mGraphicsManager(pGraphicsManager),
        mSprites(), mVertices(), mIndexes(),
        mShaderProgram(0),
        aPosition(-1), aTexture(-1), uProjection(-1), uTexture(-1)
    {
        mGraphicsManager.registerComponent(this);
    }

    SpriteBatch::~SpriteBatch() {
        std::vector<Sprite*>::iterator spriteIt;
        for (spriteIt = mSprites.begin(); spriteIt < mSprites.end();
                ++spriteIt) {
            delete (*spriteIt);
        }
    }

    Sprite* SpriteBatch::registerSprite(Resource& pTextureResource,
            int32_t pHeight, int32_t pWidth) {
        int32_t spriteCount = mSprites.size();
        int32_t index = spriteCount * 4; // Points to 1st vertex.

        // Precomputes the index buffer.
        mIndexes.push_back(index+0); mIndexes.push_back(index+1);
        mIndexes.push_back(index+2); mIndexes.push_back(index+2);
        mIndexes.push_back(index+1); mIndexes.push_back(index+3);
        for (int i = 0; i < 4; ++i) {
            mVertices.push_back(Sprite::Vertex());
        }

        // Appends a new sprite to the sprite array.
        mSprites.push_back(new Sprite(mGraphicsManager,
                pTextureResource, pHeight, pWidth));
        return mSprites.back();
    }
    ...
    ```

1.  在加载和绘制过程中，遍历`vector`。你可以在`load()`中使用一个`iterator`，如下所示：

    ```java
    ...
    status SpriteBatch::load() {
        ...
        uTexture = glGetUniformLocation(mShaderProgram, "u_texture");

        // Loads sprites.
        std::vector<Sprite*>::iterator spriteIt;
        for (spriteIt = mSprites.begin(); spriteIt < mSprites.end();
                ++spriteIt) {
            if ((*spriteIt)->load(mGraphicsManager)
                    != STATUS_OK) goto ERROR;
        }
        return STATUS_OK;

    ERROR:
        Log::error("Error loading sprite batch");
        return STATUS_KO;
    }

    void SpriteBatch::draw() {
        ...
        // Renders all sprites in batch.
        const int32_t vertexPerSprite = 4;
        const int32_t indexPerSprite = 6;
        float timeStep = mTimeManager.elapsed();
        int32_t spriteCount = mSprites.size();
        int32_t currentSprite = 0, firstSprite = 0;
        while (bool canDraw = (currentSprite < spriteCount)) {
            Sprite* sprite = mSprites[currentSprite];
            ...
        }
        ...
    }
    ```

1.  最后，在`jni/Asteroid.hpp`中声明一个`std::vector`，如下所示：

    ```java
    #ifndef _PACKT_ASTEROID_HPP_
    #define _PACKT_ASTEROID_HPP_

    #include "GraphicsManager.hpp"
    #include "PhysicsManager.hpp"
    #include "TimeManager.hpp"
    #include "Types.hpp"

    #include <vector>

    class Asteroid {
    public:
        ...
        PhysicsManager& mPhysicsManager;

        std::vector<PhysicsBody*> mBodies;
        float mMinBound;
        float mUpperBound; float mLowerBound;
        float mLeftBound; float mRightBound;
    };
    #endif
    ```

1.  在`jni/Asteroid.cpp`中使用向量插入和遍历 body，如下代码所示：

    ```java
    #include "Asteroid.hpp"
    #include "Log.hpp"

    static const float BOUNDS_MARGIN = 128;
    static const float MIN_VELOCITY = 150.0f, VELOCITY_RANGE = 600.0f;

    Asteroid::Asteroid(android_app* pApplication,
            TimeManager& pTimeManager, GraphicsManager& pGraphicsManager,
            PhysicsManager& pPhysicsManager) :
        mTimeManager(pTimeManager),
        mGraphicsManager(pGraphicsManager),
        mPhysicsManager(pPhysicsManager),
        mBodies(),
        mMinBound(0.0f),
        mUpperBound(0.0f), mLowerBound(0.0f),
        mLeftBound(0.0f), mRightBound(0.0f) {
    }

    void Asteroid::registerAsteroid(Location& pLocation,
            int32_t pSizeX, int32_t pSizeY) {
        mBodies.push_back(mPhysicsManager.loadBody(pLocation,
                pSizeX, pSizeY));
    }

    void Asteroid::initialize() {
        mMinBound = mGraphicsManager.getRenderHeight();
        mUpperBound = mMinBound * 2;
        mLowerBound = -BOUNDS_MARGIN;
        mLeftBound = -BOUNDS_MARGIN;
        mRightBound = (mGraphicsManager.getRenderWidth() + BOUNDS_MARGIN);

        std::vector<PhysicsBody*>::iterator bodyIt;
        for (bodyIt = mBodies.begin(); bodyIt < mBodies.end(); ++bodyIt) {
            spawn(*bodyIt);
        }
    }

    void Asteroid::update() {
        std::vector<PhysicsBody*>::iterator bodyIt;
        for (bodyIt = mBodies.begin(); bodyIt < mBodies.end(); ++bodyIt) {
            PhysicsBody* body = *bodyIt;
            if ((body->location->x < mLeftBound)
             || (body->location->x > mRightBound)
             || (body->location->y < mLowerBound)
             || (body->location->y > mUpperBound)) {
                spawn(body);
            }
        }
    }
    ...
    ```

## *刚才发生了什么？*

在整个应用程序中已经使用了 STL 容器来替换原始的 C 数组。例如，我们使用 STL 容器向量而不是原始 C 数组来管理一组`Asteroid`游戏对象。我们还使用 STL map 容器替换了纹理缓存。STL 容器具有许多优点，如自动处理内存管理（数组调整大小操作等），以减轻我们的负担。

STL 绝对是一个巨大的改进，它避免了重复和容易出错的代码。许多开源库需要它，现在可以毫不费力地移植。关于它的更多文档可以在[`www.cplusplus.com/reference/stl`](http://www.cplusplus.com/reference/stl)以及 SGI 的网站（第一个 STL 的发布者）上找到，地址是[`www.sgi.com/tech/stl`](http://www.sgi.com/tech/stl)。

在性能开发中，标准的 STL 容器并不总是最佳选择，特别是在内存管理和分配方面。实际上，STL 是一个通用的库，是为了常见情况而编写的。对于性能至关重要的代码，可以考虑使用其他库。以下是一些例子：

+   **EASTL**：这是由 Electronic Arts 开发的，考虑到游戏而设计的 STL 替代品。在仓库中可以找到其摘录，地址是[`github.com/paulhodge/EASTL`](https://github.com/paulhodge/EASTL)。一份详细介绍 EASTL 技术细节的必读论文可以在 Open Standards 网站上找到，地址是[`www.open-std.org/jtc1/sc22/wg21/docs/papers/2007/n2271.html`](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2007/n2271.html)。

+   **Bitsquid Foundation 库**：这是另一个针对游戏设计的 STL 替代品，可以在[`bitbucket.org/bitsquid/foundation/`](https://bitbucket.org/bitsquid/foundation/)找到。

+   **RDESTL**：这是一个开源的 STL 子集，基于 EASTL 技术论文，该论文在 EASTL 代码发布前几年就已经发表。代码仓库可以在[`code.google.com/p/rdestl/`](http://code.google.com/p/rdestl/)找到。

+   **Google SparseHash**：这是一个高性能的关联数组库（注意，RDESTL 在这方面也相当不错）。

这远非详尽无遗。只需定义你的确切需求，以做出最合适的选择。

### 注意

对于大多数应用或库来说，STL 仍然是最佳选择。在放弃它之前，分析你的源代码，确保这样做是真正必要的。

# 将 Box2D 移植到 Android

拥有 STL 工具，我们已准备好将几乎任何库移植到 Android。实际上，许多第三方库已经被移植，还有更多正在路上。然而，当没有可用的资源时，你就得依靠自己的技能。

为了了解如何处理这种情况，我们现在将使用 NDK 移植 Box2D。Box2D 是一个高度流行的物理模拟引擎，由 Erin Catto 于 2006 年发起。许多 2D 游戏，无论是业余的还是专业的，如愤怒的小鸟，都嵌入了这个强大的开源库。它支持多种语言，包括 Java，但其主要语言是 C++。

Box2D 是针对复杂主题的一个答案，即物理模拟。数学、数值积分、软件优化等都是模拟二维环境中刚体运动和碰撞的多种技术。刚体是 Box2D 的基本元素，其特点如下：

+   一个几何**形状**（多边形、圆形等）

+   物理属性（如**密度**、**摩擦**、**恢复系数**等）

+   运动**约束**和**关节**（将物体连接在一起并限制其运动）

所有这些物体都在一个名为*世界*的模拟环境中，根据时间进行模拟。

既然你已经了解了 Box2D 的基础知识，那么让我们将其移植并集成到 DroidBlaster 中，以模拟碰撞。

### 注意

本书提供的项目名为`DroidBlaster_Part17`。

# 动手操作——在 Android 上编译 Box2D

首先，按照以下步骤在 Android NDK 上移植 Box2D：

Box2D 2.3.1 归档文件包含在本书的`Libraries/box2d`目录中。

1.  解压 Box2D 源代码归档文件（本书中使用的是 2.3.1 版）到`${ANDROID_NDK}/sources/`（注意目录必须命名为`box2d`）。

    在`box2d`目录的根目录中创建并打开一个`Android.mk`文件。

    首先，将当前目录保存到`LOCAL_PATH`变量中。这一步始终是必要的，因为 NDK 构建系统在编译过程中的任何时候都可能切换到另一个目录。

1.  之后，列出所有要编译的 Box2D 源文件，如下所示。我们只关心可以在 `${ANDROID_NDK}/sources/box2d/Box2D/Box2D` 中找到的源文件名。使用 `LS_CPP` 辅助函数以避免复制每个文件名。

    ```java
    LOCAL_PATH:= $(call my-dir)

    LS_CPP=$(subst $(1)/,,$(wildcard $(1)/$(2)/*.cpp))

    BOX2D_CPP:= $(call LS_CPP,$(LOCAL_PATH),Box2D/Collision) \
                $(call LS_CPP,$(LOCAL_PATH),Box2D/Collision/Shapes) \
                $(call LS_CPP,$(LOCAL_PATH),Box2D/Common) \
                $(call LS_CPP,$(LOCAL_PATH),Box2D/Dynamics) \
                $(call LS_CPP,$(LOCAL_PATH),Box2D/Dynamics/Contacts) \
                $(call LS_CPP,$(LOCAL_PATH),Box2D/Dynamics/Joints) \
                $(call LS_CPP,$(LOCAL_PATH),Box2D/Rope)
    ...
    ```

1.  然后，为静态库编写 Box2D 模块定义。首先调用 `$(CLEAR_VARS)` 脚本。这个脚本必须在任何模块定义之前包含，以移除其他模块可能做出的任何更改，并避免任何不希望出现的副作用。然后，定义以下设置：

    +   `LOCAL_MODULE` 中的模块名称：模块名称以 _static 结尾，以避免与即将定义的共享版本名称冲突。

    +   在 `LOCAL_SRC_FILES` 中的模块源文件（使用之前定义的 `BOX2D_CPP`）。

    +   在`LOCAL_EXPORT_C_INCLUDES`中将头文件目录导出到客户端模块。

    +   在 `LOCAL_C_INCLUDES` 中用于模块编译的内部头文件。这里，用于 Box2D 编译的头文件和客户端模块需要的头文件是相同的（在其他库中通常也是相同的）。因此，以下方式重用之前定义的 `LOCAL_EXPORT_C_INCLUDES`：

        ```java
        ...
        include $(CLEAR_VARS)

        LOCAL_MODULE:= box2d_static
        LOCAL_SRC_FILES:= $(BOX2D_CPP)
        LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
        LOCAL_C_INCLUDES := $(LOCAL_EXPORT_C_INCLUDES)
        ...
        Finally, request Box2D module compilation as a static library as follows:
        ...
        include $(BUILD_STATIC_LIBRARY)
        ...
        Optionally, the same process can be repeated to build a shared version of the same library by selecting a different module name and invoking $(BUILD_SHARED_LIBRARY) instead, as shown in the following:
        ...
        include $(CLEAR_VARS)

        LOCAL_MODULE:= box2d_shared
        LOCAL_SRC_FILES:= $(BOX2D_CPP)
        LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
        LOCAL_C_INCLUDES := $(LOCAL_EXPORT_C_INCLUDES)

        include $(BUILD_SHARED_LIBRARY)

        ```

    ### 注意

    `Android.mk` 文件位于 `Libraries/box2d` 目录中。

1.  打开 DroidBlaster 的 `Android.mk` 文件，并将 `box2d_static` 添加到 `LOCAL_STATIC_LIBRARIES` 中以链接它。使用 `import-module` 指令指出要包含哪个 `Android.mk` 模块文件。请记住，由于 `NDK_MODULE_PATH` 变量指向默认的 `${ANDROID_NDK}/sources`，因此可以找到模块，如下所示：

    ```java
    LOCAL_PATH := $(call my-dir)

    include $(CLEAR_VARS)

    LS_CPP=$(subst $(1)/,,$(wildcard $(1)/*.cpp))
    LOCAL_MODULE    := droidblaster
    LOCAL_SRC_FILES := $(call LS_CPP,$(LOCAL_PATH))
    LOCAL_LDLIBS    := -landroid -llog -lEGL -lGLESv1_CM -lOpenSLES

    LOCAL_STATIC_LIBRARIES:=android_native_app_glue png \
                            box2d_static

    include $(BUILD_SHARED_LIBRARY)

    $(call import-module,android/native_app_glue)
    $(call import-module,libpng)
    $(call import-module,box2d)
    ```

如果您在 Eclipse 中看到有关 Box2D 包含文件的警告，可以选择激活包含文件的解析。为此，在 Eclipse 的 **项目属性** 中，导航到 **C/C++ 通用/路径和符号** 部分，然后是 **包含** 选项卡，并添加 Box2d 目录 `${env_var:ANDROID_NDK}/sources/box2d`。

## *刚才发生了什么？*

启动 DroidBlaster 编译。Box2D 编译无误。借助 NDK，我们将第二个开源库（继 `libpng` 之后）移植到了 Android！我们终于可以重用社区已经创建的众多轮子之一了！将原生库移植到 Android 主要涉及编写一个 `Android.mk` 模块 makefile 来描述源文件、依赖项、编译标志等，正如我们现在为我们的主模块 DroidBlaster 所做的那样。

我们已经看到了模块中一些最关键的变量，它们如下所示：

+   `LOCAL_MODULE`：这声明了一个唯一的模块名称，最终的库名称取决于其值。

+   `LOCAL_SRC_FILES`：这列出了所有相对于模块根目录的待编译文件。

+   `LOCAL_C_INCLUDES`：这定义了 `include` 文件目录。

+   `LOCAL_EXPORT_C_INCLUDES`：这定义了 `include` 文件目录，但这次是用于包含模块。

构建 Box2D 模块的顺序由以下指令之一给出：

+   `BUILD_STATIC_LIBRARY`：这将模块编译为静态库。

+   `BUILD_SHARED_LIBRARY`：这次也会编译模块，但作为共享库

模块可以像 STL 一样编译为静态或共享库。编译是动态执行的（即按需），每次客户端应用程序导入模块或更改其编译设置时都会执行。希望 NDK 能够增量编译源代码。

### 提示

要为仅包含头文件的库（如 Boost 或 GLM（用于 OpenGL ES 矩阵计算的库）的部分）创建模块，请定义一个没有 `LOCAL_SRC_FILES` 的模块。只需要 `LOCAL_MODULE` 和 `LOCAL_EXPORT_C_INCLUDES`。

从客户端 `Android.mk` 的角度来看（即我们的 `DroidBlaster` makefile），NDK `import-module` 指令大致上触发包含子模块 `Android.mk` 文件。没有它，NDK 将无法发现依赖模块、编译它们并包含它们的头文件。所有模块，包括主模块和子模块，都生成在 `<PROJECT_DIR>/libs` 中，主应用程序模块的中间二进制文件在 `<PROJECT_DIR>/obj` 中。

### 提示

`import-module` 指令应位于文件末尾，以避免更改模块定义。

以下是主 `Android.mk` Makefile 中链接“子模块”库的三种方法：

+   静态库必须在 `LOCAL_STATIC_LIBRARIES` 变量中列出（例如我们对 Box2D 所做的那样）

+   共享库需要在 `LOCAL_SHARED_LIBRARIES` 变量中列出

+   共享系统库应该在 `LOCAL_LDLIBS` 中列出（例如我们对 OpenGL ES 所做的那样）

有关 Makefiles 的更多信息，请参见 *掌握模块 Makefiles* 部分。

编写 Makefile 是移植过程的重要组成部分。然而，它并不总是足够的。根据库的原始平台，移植库可能会更加复杂。例如，已经移植到 iOS 的代码通常更容易移植到 Android。在更复杂的情况下，可能需要修补代码以使其在 Android 上正常工作。当你被这样一个艰难且非琐碎的任务所困扰时，这实际上是非常频繁的，请始终考虑以下事项：

+   确保所需的库存在，如果不存在，请先移植它们。

+   如果随库提供了主配置头文件（通常是这样），请查找它。这是调整启用或禁用功能、移除不需要的依赖或定义新宏的好地方。

+   注意与系统相关的宏（即 `#ifdef _LINUX` ...），这是查找代码中需要更改的第一地方之一。通常，需要定义宏，比如 `_ANDROID_`，并将其适当地插入到代码中。

+   注释掉非必要代码，以检查库是否可以编译以及其核心功能是否可能工作。实际上，如果你还不确定它是否能工作，就不要费力修复所有问题。

幸运的是，Box2D 并未依赖于特定的平台，因为它主要依赖于纯 C/C++计算，而不是外部 API。在这种情况下，代码移植变得更容易。现在 Box2D 已经编译完成，让我们在自己的代码中运行它。

# 动手操作——运行 Box2D 物理引擎的时间到了。

让我们按照以下步骤用 Box2D 重写 DroidBlaster 物理引擎：

1.  打开`jni/PhysicsManager.hpp`头文件，并插入 Box2D 的`include`文件。

    定义一个常数`PHYSICS_SCALE`，以将物体位置从物理坐标系转换为游戏坐标系。实际上，Box2D 使用自己的比例以获得更好的精度。

    然后，用一个新的结构体`PhysicsCollision`替换`PhysicsBody`，这将指示哪些物体进入了碰撞，如下所示：

    ```java
    #ifndef PACKT_PHYSICSMANAGER_HPP
    #define PACKT_PHYSICSMANAGER_HPP

    #include "GraphicsManager.hpp"
    #include "TimeManager.hpp"
    #include "Types.hpp"

    #include <Box2D/Box2D.h>
    #include <vector>

    #define PHYSICS_SCALE 32.0f

    struct PhysicsCollision {
        bool collide;

        PhysicsCollision():
            collide(false)
        {}
    };
    ...
    ```

1.  然后，让`PhysicsManager`继承自`b2ContactListener`。接触监听器会在每次更新模拟时收到新的碰撞通知。我们的`PhysicsManager`继承了一个名为`BeginContact()`的方法，用于对碰撞做出反应。

    我们还需要三种方法，如下所示：

    +   `loadBody()`用于在物理引擎中创建一个新的实体

    +   `loadTarget()`用于创建向目标（我们的太空船）移动的实体

    +   `start()`用于在游戏开始时初始化引擎

    同时，定义以下成员变量：

    +   `mWorld`代表整个 Box2D 模拟，其中包含我们将要创建的所有物体

    +   `mBodies`是我们已注册的所有物理实体的列表

    +   `mLocations`包含`b2Body`在游戏坐标系（而不是物理坐标系，其尺度不同）中的位置的副本

    +   `mBoundsBodyObj`定义了我们的太空船可以移动的边界

        ```java
        ...
        class PhysicsManager : private b2ContactListener {
        public:
            PhysicsManager(TimeManager& pTimeManager,
                    GraphicsManager& pGraphicsManager);
            ~PhysicsManager();

            b2Body* loadBody(Location& pLocation, uint16 pCategory,
                uint16 pMask, int32_t pSizeX, int32_t pSizeY,
                float pRestitution);
            b2MouseJoint* loadTarget(b2Body* pBodyObj);
            void start();
            void update();

        private:
            PhysicsManager(const PhysicsManager&);
            void operator=(const PhysicsManager&);

            void BeginContact(b2Contact* pContact);

            TimeManager& mTimeManager;
            GraphicsManager& mGraphicsManager;

            b2World mWorld;
            std::vector<b2Body*> mBodies;
            std::vector<Location*> mLocations;
            b2Body* mBoundsBodyObj;
        };
        #endif
        ```

1.  实现`jni/PhysicsManager.cpp`。

    迭代常数决定了模拟的精确度。在这里，Box2D 主要处理碰撞和简单移动。因此，将速度和位置迭代分别固定为`6`和`2`就足够了（稍后会详细介绍它们的意义）。

    初始化新的`PhysicsManager`成员，并让它在`mWorld`对象上通过`SetContactListener()`监听碰撞事件，如下所示：

    ```java
    #include "PhysicsManager.hpp"
    #include "Log.hpp"

    static const int32_t VELOCITY_ITER = 6;
    static const int32_t POSITION_ITER = 2;

    PhysicsManager::PhysicsManager(TimeManager& pTimeManager,
            GraphicsManager& pGraphicsManager) :
      mTimeManager(pTimeManager), mGraphicsManager(pGraphicsManager),
      mWorld(b2Vec2_zero), mBodies(),
      mLocations(),
      mBoundsBodyObj(NULL) {
        Log::info("Creating PhysicsManager.");
        mWorld.SetContactListener(this);
    }

    PhysicsManager::~PhysicsManager() {
        std::vector<b2Body*>::iterator bodyIt;
        for (bodyIt = mBodies.begin(); bodyIt < mBodies.end(); ++bodyIt) {
            delete (PhysicsCollision*) (*bodyIt)->GetUserData();
        }
    }
    ...
    ```

1.  当游戏开始时，初始化 Box2D 世界的边界。这些边界与转换为*物理系统坐标系*的显示窗口大小相匹配。实际上，物理系统使用自己的预定义比例以保持浮点值精度。我们需要四个边缘来定义这些边界，如下所示：

    ```java
    ...
    void PhysicsManager::start() {
        if (mBoundsBodyObj == NULL) {
            b2BodyDef boundsBodyDef;
            b2ChainShape boundsShapeDef;
            float renderWidth = mGraphicsManager.getRenderWidth()
                                    / PHYSICS_SCALE;
            float renderHeight = mGraphicsManager.getRenderHeight()
                                    / PHYSICS_SCALE;
            b2Vec2 boundaries[4];
            boundaries[0].Set(0.0f, 0.0f);
            boundaries[1].Set(renderWidth, 0.0f);
            boundaries[2].Set(renderWidth, renderHeight);
            boundaries[3].Set(0.0f, renderHeight);
            boundsShapeDef.CreateLoop(boundaries, 4);

            mBoundsBodyObj = mWorld.CreateBody(&boundsBodyDef);
            mBoundsBodyObj->CreateFixture(&boundsShapeDef, 0);
        }
    }
    ```

1.  在`loadBody()`中初始化并注册小行星或飞船的物理实体。

    物体定义描述了一个动态物体（相对于静态物体），它是唤醒的（即由 Box2D 积极模拟），并且不能旋转（对于多边形形状，这一属性尤为重要，意味着它总是朝上的）。

    还请注意我们如何在`userData`字段中保存`PhysicsCollision`自身的引用，以便稍后在 Box2D 回调中访问它。

    定义身体形状，我们将其近似为圆形。请注意，Box2D 需要一个半尺寸，从物体的中心到其边界，如下代码片段所示：

    ```java
    b2Body* PhysicsManager::loadBody(Location& pLocation,
            uint16 pCategory, uint16 pMask, int32_t pSizeX, int32_t pSizeY,
            float pRestitution) {
        PhysicsCollision* userData = new PhysicsCollision();

        b2BodyDef mBodyDef;
        b2Body* mBodyObj;
        b2CircleShape mShapeDef; b2FixtureDef mFixtureDef;

        mBodyDef.type = b2_dynamicBody;
        mBodyDef.userData = userData;
        mBodyDef.awake = true;
        mBodyDef.fixedRotation = true;

        mShapeDef.m_p = b2Vec2_zero;
        int32_t diameter = (pSizeX + pSizeY) / 2;
        mShapeDef.m_radius = diameter / (2.0f * PHYSICS_SCALE);
        ...
    ```

1.  身体夹具是将身体定义、形状和物理属性联系在一起的“胶水”。我们还使用它来设置身体的类别和掩码，以及过滤对象之间的碰撞（例如，在 DroidBlaster 中，行星可以与飞船碰撞，但它们之间不能相互碰撞）。一个位表示一个类别。

    最后，在 Box2D 物理世界中有效实例化你的 `body`，如下代码所示：

    ```java
        ...
        mFixtureDef.shape = &mShapeDef;
        mFixtureDef.density = 1.0f;
        mFixtureDef.friction = 0.0f;
        mFixtureDef.restitution = pRestitution;
        mFixtureDef.filter.categoryBits = pCategory;
        mFixtureDef.filter.maskBits = pMask;
        mFixtureDef.userData = userData;

        mBodyObj = mWorld.CreateBody(&mBodyDef);
        mBodyObj->CreateFixture(&mFixtureDef);
        mBodyObj->SetUserData(userData);
        mLocations.push_back(&pLocation);
        mBodies.push_back(mBodyObj);
        return mBodyObj;
    }
    ...
    ```

1.  实现 `loadTarget()` 方法，创建一个 Box2D 鼠标关节以模拟飞船移动。这样的 `Joint` 定义了一个空的靶标，身体（在此处指定参数）像弹性一样向其移动。这里使用的设置（`maxForce`、`dampingRatio` 和 `frequencyHz`）控制飞船如何反应，可以通过调整它们来确定，如下代码所示：

    ```java
    ...
    b2MouseJoint* PhysicsManager::loadTarget(b2Body* pBody) {
        b2BodyDef emptyBodyDef;
        b2Body* emptyBody = mWorld.CreateBody(&emptyBodyDef);

        b2MouseJointDef mouseJointDef;
        mouseJointDef.bodyA = emptyBody;
        mouseJointDef.bodyB = pBody;
        mouseJointDef.target = b2Vec2(0.0f, 0.0f);
        mouseJointDef.maxForce = 50.0f * pBody->GetMass();
        mouseJointDef.dampingRatio = 0.15f;
        mouseJointDef.frequencyHz = 3.5f;

        return (b2MouseJoint*) mWorld.CreateJoint(&mouseJointDef);
    }
    ...
    ```

1.  编写 `update()` 方法。

    +   首先，清除在上一轮迭代中 `BeginContact()` 缓冲的任何碰撞标志。

    +   然后，通过调用 `Step()` 进行模拟。时间周期指定必须模拟的时间。迭代常数决定了模拟的准确性。

    +   最后，遍历所有物理体以提取它们的坐标，将它们从 Box2D 坐标转换为游戏坐标，并将结果存储到我们自己的 `Location` 对象中，如下代码所示：

        ```java
        ...
        void PhysicsManager::update() {
            // Clears collision flags.
            int32_t size = mBodies.size();
            for (int32_t i = 0; i < size; ++i) {
                PhysicsCollision* physicsCollision =
                       ((PhysicsCollision*) mBodies[i]->GetUserData());
                physicsCollision->collide = false;
            }
            // Updates simulation.
            float timeStep = mTimeManager.elapsed();
            mWorld.Step(timeStep, VELOCITY_ITER, POSITION_ITER);

            // Caches the new state.
            for (int32_t i = 0; i < size; ++i) {
                const b2Vec2& position = mBodies[i]->GetPosition();
                mLocations[i]->x = position.x * PHYSICS_SCALE;
                mLocations[i]->y = position.y * PHYSICS_SCALE;
            }
        }
        ...
        ```

1.  使用继承自 `b2ContactListener` 的 `BeginContact()` 方法结束。这个回调通知两个物体（名为 `A` 和 `B`）之间新发生的碰撞。事件信息存储在 `b2contact` 结构中，其中包含各种属性，例如摩擦力、恢复系数以及通过其夹具涉及的两个物体。这些夹具本身包含对我们自己的 `PhysicsCollision` 的引用。当 Box2D 检测到一个接触时，我们可以使用以下链接切换 `PhysicsCollision` 碰撞标志：

    ```java
    ...
    void PhysicsManager::BeginContact(b2Contact* pContact) {
        void* userDataA = pContact->GetFixtureA()->GetUserData();
        void* userDataB = pContact->GetFixtureB()->GetUserData();
        if (userDataA != NULL && userDataB != NULL) {
            ((PhysicsCollision*)userDataA)->collide = true;
            ((PhysicsCollision*)userDataB)->collide = true;
        }
    }
    ```

1.  在 `jni/Asteroid.hpp` 中，将 `PhysicsBody` 的使用替换为 Box2D `b2Body` 结构，如下代码所示：

    ```java
    ...
    class Asteroid {
        ...
    private:
        void spawn(b2Body* pBody);

        TimeManager& mTimeManager;
        GraphicsManager& mGraphicsManager;
        PhysicsManager& mPhysicsManager;

        std::vector<b2Body*> mBodies;
        float mMinBound;
        float mUpperBound; float mLowerBound;
        float mLeftBound; float mRightBound;
    };
    #endif
    ```

1.  在 `jni/Asteroid.cpp` 中，将常数和边界缩放到物理坐标系：

    ```java
    #include "Asteroid.hpp"
    #include "Log.hpp"

    static const float BOUNDS_MARGIN = 128 / PHYSICS_SCALE;
    static const float MIN_VELOCITY = 150.0f / PHYSICS_SCALE;
    static const float VELOCITY_RANGE = 600.0f / PHYSICS_SCALE;

    ...
    void Asteroid::initialize() {
        mMinBound = mGraphicsManager.getRenderHeight() / PHYSICS_SCALE;
        mUpperBound = mMinBound * 2;
        mLowerBound = -BOUNDS_MARGIN;
        mLeftBound = -BOUNDS_MARGIN;
        mRightBound = (mGraphicsManager.getRenderWidth() / PHYSICS_SCALE)
                          + BOUNDS_MARGIN;

        std::vector<b2Body*>::iterator bodyIt;
        for (bodyIt = mBodies.begin(); bodyIt < mBodies.end(); ++bodyIt) {
            spawn(*bodyIt);
        }
    }
    ...
    ```

1.  然后，更新行星体的注册方式。用类别和掩码注册物理属性。在这里，行星被声明为属于类别 1（十六进制表示为 `0X1`），在评估碰撞时只考虑组 2（十六进制表示为 `0X2`）中的物体：

    ```java
    ...
    void Asteroid::registerAsteroid(Location& pLocation,
            int32_t pSizeX, int32_t pSizeY) {
        mBodies.push_back(mPhysicsManager.loadBody(pLocation,
                0X1, 0x2, pSizeX, pSizeY, 2.0f));
    }
    ...
    ```

    替换并更新剩余的代码，以适应使用新的 `b2Body` 结构而不是 `PhysicsBody` 结构：

    ```java
    ...
    void Asteroid::update() {
        std::vector<b2Body*>::iterator bodyIt;
        for (bodyIt = mBodies.begin(); bodyIt < mBodies.end(); ++bodyIt) {
            b2Body* body = *bodyIt;
            if ((body->GetPosition().x < mLeftBound)
             || (body->GetPosition().x > mRightBound)
             || (body->GetPosition().y < mLowerBound)
             || (body->GetPosition().y > mUpperBound)) {
                spawn(body);
            }
        }
    }
    ...
    ```

1.  最后，也更新 `spawn()` 代码以初始化 `PhysicsBody`，如下代码所示：

    ```java
    ...
    void Asteroid::spawn(b2Body* pBody) {
        float velocity = -(RAND(VELOCITY_RANGE) + MIN_VELOCITY);
        float posX = mLeftBound + RAND(mRightBound - mLeftBound);
        float posY = mMinBound + RAND(mUpperBound - mMinBound);
        pBody->SetTransform(b2Vec2(posX, posY), 0.0f);
        pBody->SetLinearVelocity(b2Vec2(0.0f, velocity));
    }
    ```

1.  打开 `jni/Ship.hpp` 文件，将其转换为 Box2D body。

    向 `registerShip()` 方法中添加一个新的 `b2Body` 参数。

    然后，定义以下两个附加方法：

    +   `update()`，其中包含一些新的游戏逻辑，当飞船与行星碰撞时销毁飞船

    +   `isDestroyed()` 指示飞船是否已被销毁

    声明以下必要的变量：

    +   `mBody` 用于在 Box2D 中管理飞船的表示

    +   `mDestroyed` 和 `mLives` 用于游戏逻辑

        ```java
        ...
        #include "GraphicsManager.hpp"
        #include "PhysicsManager.hpp"
        #include "SoundManager.hpp"
        ...

        class Ship {
        public:
            Ship(android_app* pApplication,
                 GraphicsManager& pGraphicsManager,
                 SoundManager& pSoundManager);

            void registerShip(Sprite* pGraphics, Sound* pCollisionSound,
         b2Body* pBody);

            void initialize();
            void update();

            bool isDestroyed() { return mDestroyed; }

        private:
            GraphicsManager& mGraphicsManager;
            SoundManager& mSoundManager;
            Sprite* mGraphics;
            Sound* mCollisionSound;
            b2Body* mBody;
            bool mDestroyed; int32_t mLives;
        };
        #endif
        ```

1.  在 `jni/Ship.cpp` 中声明一些新的常量。

    接着，适当初始化新的成员变量。注意，在 `initialize()` 中不再需要播放碰撞声音：

    ```java
    #include "Log.hpp"
    #include "Ship.hpp"

    static const float INITAL_X = 0.5f;
    static const float INITAL_Y = 0.25f;
    static const int32_t DEFAULT_LIVES = 10;

    static const int32_t SHIP_DESTROY_FRAME_1 = 8;
    static const int32_t SHIP_DESTROY_FRAME_COUNT = 9;
    static const float SHIP_DESTROY_ANIM_SPEED = 12.0f;

    Ship::Ship(android_app* pApplication,
            GraphicsManager& pGraphicsManager,
            SoundManager& pSoundManager) :
      mGraphicsManager(pGraphicsManager),
      mGraphics(NULL),
      mSoundManager(pSoundManager),
      mCollisionSound(NULL),
      mBody(NULL),
      mDestroyed(false), mLives(0) {
    }

    void Ship::registerShip(Sprite* pGraphics, Sound* pCollisionSound,
                            b2Body* pBody) {
        mGraphics = pGraphics;
        mCollisionSound = pCollisionSound;
        mBody = pBody;
    }

    void Ship::initialize() {
        mDestroyed = false;
     mLives = DEFAULT_LIVES;

        b2Vec2 position(
           mGraphicsManager.getRenderWidth() * INITAL_X / PHYSICS_SCALE,
           mGraphicsManager.getRenderHeight() * INITAL_Y / PHYSICS_SCALE);
        mBody->SetTransform(position, 0.0f);
        mBody->SetActive(true);
    }
    ...
    ```

1.  在 `update()` 中，检查飞船体是否与小行星发生碰撞。为此，检查存储在飞船 `b2Body` 自定义用户数据中的 `PhysicsCollision` 结构。记住，其内容是在 `PhysicsManager::BeginContact()` 方法中设置的

    当飞船发生碰撞时，我们可以减少其生命值并播放碰撞声音。

    如果它没有生命值了，我们可以开始播放销毁动画。当这种情况发生时，物体应该是非激活状态，以避免与更多的小行星发生碰撞。

    当飞船完全被销毁时，我们可以保存其状态，以便游戏循环可以适当作出反应，如下代码所示：

    ```java
    ...
    void Ship::update() {
        if (mLives >= 0) {
            if (((PhysicsCollision*) mBody->GetUserData())->collide) {
                mSoundManager.playSound(mCollisionSound);
                --mLives;
                if (mLives < 0) {
                    Log::info("Ship has been destroyed");
                    mGraphics->setAnimation(SHIP_DESTROY_FRAME_1,
                        SHIP_DESTROY_FRAME_COUNT, SHIP_DESTROY_ANIM_SPEED,
                        false);
                    mBody->SetActive(false);
                } else {
                    Log::info("Ship collided");
                }
            }
        }
        // Destroyed.
        else {
            if (mGraphics->animationEnded()) {
                mDestroyed = true;
            }
        }
    }
    ```

1.  更新 `jni/MoveableBody.hpp` 组件，使其在 `registerMoveableBody()` 中返回一个 `b2Body` 结构。

    添加以下两个新的成员：

    +   `mBody` 用于物理体

    +   `mTarget` 用于鼠标关节：

        ```java
        #ifndef _PACKT_MOVEABLEBODY_HPP_
        #define _PACKT_MOVEABLEBODY_HPP_

        #include "InputManager.hpp"
        #include "PhysicsManager.hpp"
        #include "Types.hpp"

        class MoveableBody {
        public:
            MoveableBody(android_app* pApplication,
               InputManager& pInputManager, PhysicsManager& pPhysicsManager);

            b2Body* registerMoveableBody(Location& pLocation,
                    int32_t pSizeX, int32_t pSizeY);

            void initialize();
            void update();

        private:
            PhysicsManager& mPhysicsManager;
            InputManager& mInputManager;

            b2Body* mBody;
            b2MouseJoint* mTarget;
        };
        #endif
        ```

1.  调整 `jni/MoveableBody.cpp` 中的常量以适应新的比例，并在构造函数中初始化新成员：

    ```java
    #include "Log.hpp"
    #include "MoveableBody.hpp"

    static const float MOVE_SPEED = 10.0f / PHYSICS_SCALE;

    MoveableBody::MoveableBody(android_app* pApplication,
          InputManager& pInputManager, PhysicsManager& pPhysicsManager) :
      mInputManager(pInputManager),
      mPhysicsManager(pPhysicsManager),
      mBody(NULL), mTarget(NULL) {
    }

    b2Body* MoveableBody::registerMoveableBody(Location& pLocation,
            int32_t pSizeX, int32_t pSizeY) {
        mBody = mPhysicsManager.loadBody(pLocation, 0x2, 0x1, pSizeX,
                pSizeY, 0.0f);
        mTarget = mPhysicsManager.loadTarget(mBody);
        mInputManager.setRefPoint(&pLocation);
        return mBody;
    }
    ...
    ```

1.  然后，设置并更新 `physicsbody` 以跟随飞船的目标。目标根据用户输入移动，如下代码所示：

    ```java
    ...
    void MoveableBody::initialize() {
        mBody->SetLinearVelocity(b2Vec2(0.0f, 0.0f));
    }

    void MoveableBody::update() {
        b2Vec2 target = mBody->GetPosition() + b2Vec2(
            mInputManager.getDirectionX() * MOVE_SPEED,
            mInputManager.getDirectionY() * MOVE_SPEED);
        mTarget->SetTarget(target);
    }
    ```

1.  最后，编辑 `jni/DroidBlaster.cpp` 并更改飞船注册代码以适应新的变化，如下代码所示：

    ```java
    ...

    DroidBlaster::DroidBlaster(android_app* pApplication):
        ... {
        Log::info("Creating DroidBlaster");

        Sprite* shipGraphics = mSpriteBatch.registerSprite(mShipTexture,
                SHIP_SIZE, SHIP_SIZE);
        shipGraphics->setAnimation(SHIP_FRAME_1, SHIP_FRAME_COUNT,
                SHIP_ANIM_SPEED, true);
        Sound* collisionSound =
                mSoundManager.registerSound(mCollisionSound);
        b2Body* shipBody = mMoveableBody.registerMoveableBody(
                shipGraphics->location, SHIP_SIZE, SHIP_SIZE);
        mShip.registerShip(shipGraphics, collisionSound, shipBody);

        // Creates asteroids.
        ...
    }
    ...
    ```

1.  不要忘记在 `onActivate()` 中启动 `PhysicsManager`，如下代码所示：

    ```java
    ...
    status DroidBlaster::onActivate() {
        Log::info("Activating DroidBlaster");
        // Starts managers.
        if (mGraphicsManager.start() != STATUS_OK) return STATUS_KO;
        if (mSoundManager.start() != STATUS_OK) return STATUS_KO;
        mInputManager.start();
        mPhysicsManager.start();

        ...
    }
    ...
    ```

1.  在 `onStep()` 中通过更新并检查飞船状态来结束。当它被销毁时，按以下方式退出游戏循环：

    ```java
    ...
    status DroidBlaster::onStep() {
        mTimeManager.update();
        mPhysicsManager.update();

        // Updates modules.
        mAsteroids.update();
        mMoveableBody.update();
        mShip.update();

        if (mShip.isDestroyed()) return STATUS_EXIT;
        return mGraphicsManager.update();
    }
    ...
    ```

## *刚才发生了什么？*

我们已经使用 Box2D 物理引擎创建了一个物理模拟。更具体地说，我们已经了解了如何执行以下操作：

+   创建一个 Box2D 世界以描述物理模拟

+   定义实体的物理表示（飞船和小行星）

+   步进模拟

+   筛选并检测实体之间的碰撞

+   提取模拟状态（即坐标）以供图形表示使用

Box2D 使用自己的分配器来优化内存管理。因此，要创建和销毁 Box2D 对象，需要系统地使用提供的工厂方法（`CreateX()`, `DestroyX()`）。大多数情况下，Box2D 会自动为你管理内存。当一个对象被销毁时，所有相关的 *子对象* 也会被销毁（例如，当世界被销毁时，物体也会被销毁）。但是，如果你需要提前摆脱这些对象，即手动操作，请始终先销毁物体。

Box2D 是一段复杂的代码，并且相当难以正确调整。让我们深入了解一下它的世界描述方式以及如何处理碰撞。

## 深入 Box2D 世界

Box2D 的核心接入点是 `b2World` 对象，它存储了一系列物理体以进行模拟。Box2D 的物体由以下部分组成：

+   `b2BodyDef`：这定义了物体类型（`b2_staticBody, b2_dynamicBody` 等）和初始属性，如位置、角度（以弧度为单位）等。

+   `b2Shape`：这用于碰撞检测，并根据其密度导出物体质量。它可以是 `b2PolygonShape`、`b2CircleShape` 等等。

+   `b2FixtureDef`：这把物体形状、物体定义及其物理属性（如密度）联系在一起。

+   `b2Body`：这是世界中的一个物体实例（即每个游戏对象一个）。它由一个物体定义、一个形状和一个夹具创建。

物体具有以下几个物理特性：

+   **形状**：这代表 DroidBlaster 中的一个圆形，尽管也可以使用多边形或盒子。

+   **密度**：这用 kg/m² 表示，根据物体的形状和大小计算其质量。值应大于或等于 `0.0`。保龄球的密度大于足球。

+   **摩擦力**：这表示一个物体在另一个物体上滑动的程度（例如，汽车在道路上或结冰的路面上）。值通常在 `0.0` 到 `1.0` 范围内，其中 `0.0` 表示没有摩擦力，`1.0` 表示摩擦力很大。

+   **恢复系数**：这表示一个物体在碰撞中的反应程度，例如弹跳的球。值 `0.0` 表示没有恢复，`1.0` 表示完全恢复。

运行时，物体受到以下影响：

+   **力**：这使物体线性移动。

+   **扭矩**：这代表施加在物体上的旋转力。

+   **阻尼**：这类似于摩擦力，尽管它不仅仅发生在物体与其他物体接触时。将它视为阻力减缓物体速度的效果。

Box2D 调整用于包含从 `0.1` 到 `10`（以米为单位）规模对象的世界。当超出这个范围使用时，数值近似可能导致模拟不准确。因此，非常有必要将坐标从 Box2D 参考系缩放到游戏，或直接到图形参考系，其中物体应在（大致）范围 [`0.1`, `10`] 内。这就是我们定义 `SCALE_FACTOR` 来缩放坐标转换的原因。

## 关于碰撞检测的更多内容

在 Box2D 中存在多种检测和处理碰撞的方法。最基本的一种是在世界或物体更新后检查存储的所有接触。然而，这可能导致在 Box2D 内部迭代期间意外发生的接触被遗漏。

我们看到的一种更好的检测接触的方法是 `b2ContactListener`，它可以注册到世界对象上。以下四个回调可以被重写：

+   `BeginContact (b2Contact)`：这检测两个物体开始碰撞的时刻。

+   `EndContact(b2Contact)`: 这是 `BeginContact()` 的对应部分，表示物体不再发生碰撞。对 `BeginContact()` 的调用总是紧跟着一个匹配的 `EndContact()`。

+   `PreSolve (b2Contact, b2Manifold)`: 在检测到碰撞但还未进行碰撞解决时调用，即计算碰撞产生的冲量之前。`b2Manifold` 结构在单个位置保存有关接触点、法线等信息。

+   `PostSolve(b2Contact, b2ContactImpulse)`: 在 Box2D 计算出实际的冲量（即物理反应）之后调用。

前两个回调对于触发游戏逻辑很有用（例如，销毁实体）。最后两个回调对于在计算过程中改变物理模拟很有用（更具体地，通过*禁用*接触来忽略某些碰撞），或者获取更准确的详细信息。例如，使用 `PreSolve()` 创建一个单向平台，只有当实体从上方掉落时才会与之碰撞（而不是从下方跳起时）。使用 `PostSolve()` 来检测碰撞强度并相应地计算伤害。

`PreSolve()` 和 `PostSolve()` 方法可以在 `BeginContact()` 和 `EndContact()` 之间被多次调用，而这些方法本身在一个世界更新期间可以被调用零次到多次。一个接触可以在一个模拟步骤中开始，并在几个步骤后结束。在这种情况下，事件解决回调会在“中间”步骤中连续发生。因为模拟步骤中可能会发生很多碰撞。因此，回调可能会被多次调用，应该尽可能高效。

当在 `BeginContact()` 回调中分析碰撞时，我们缓冲了一个碰撞标志。这是必要的，因为 Box2D 在触发回调时重用传递的 `b2Contact` 参数。此外，由于这些回调是在计算模拟时调用的，物理物体不能立即销毁，只能在模拟步骤结束后销毁。因此，强烈建议复制那里的任何信息以进行`后处理`（例如，销毁实体）。

## 碰撞模式与过滤

我想指出，Box2D 提供了一个所谓的`bullet`模式，可以通过相应的布尔成员在物体定义上激活：

```java
mBodyDef.bullet = true;
```

对于像子弹这样快速移动的对象，子弹模式是必要的！默认情况下，Box2D 使用**离散碰撞检测**，它只考虑最终位置上的物体进行碰撞检测，会漏掉位于初始位置和最终位置之间的任何物体。然而，对于一个快速移动的物体，应该考虑整个路径。这更正式地称为**连续碰撞检测**（**CCD**）。显然，CCD 是代价高昂的，应当谨慎使用。请参考以下图表：

![碰撞模式与过滤](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_09_02.jpg)

有时我们希望检测到物体重叠而不产生碰撞（比如一辆车到达终点线）：这称为传感器。通过以下方式在夹具中将`isSensor`布尔成员设置为`true`可以轻松设置传感器：

```java
mFixtureDef.isSensor = true;
```

可以通过监听器通过`BeginContact()`和`EndContact()`查询传感器，或者通过在`b2Contact`类上使用`IsTouching()`快捷方式。

碰撞的另一个重要方面是不发生碰撞，或者更准确地说，过滤碰撞。在`PreSolve()`中可以通过禁用接触来执行一种过滤。这是最灵活和强大的解决方案，但也是最复杂的。

但是，正如我们所看到的，可以通过使用类别和掩码技术以更简单的方式进行过滤。每个物体分配一个或多个类别（每个类别在短整数中由一个位表示，即`categoryBits`成员）和一个描述它们可以与之碰撞的物体类别的掩码（每个被过滤的类别由设置为 0 的位表示，即`maskBits`成员），如下图所示：

![碰撞模式和过滤](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_09_04.jpg)

在前图中，`Body A`属于类别`1`和`3`，并与类别`2`和`4`的物体发生碰撞，这对于这个可怜的`Body B`来说也是如此，除非它的掩码过滤掉了与`Body A`类别（即`1`和`3`）的碰撞。换句话说，两个物体 A 和 B 必须都同意发生碰撞！

Box2D 也有碰撞组的概念。一个物体的碰撞组可以是以下任意一个：

+   **正整数**：这意味着具有相同碰撞组值的其它物体可以发生碰撞

+   **负整数**：这意味着具有相同碰撞组值的其它物体将被过滤

使用碰撞组也可以作为 DroidBlaster 中避免小行星之间碰撞的解决方案，尽管它不如类别和掩码灵活。注意，组别在类别之前被过滤。

比 category 和 group 过滤器更灵活的解决方案是`b2ContactFilter`类。这个类有一个`ShouldCollide(b2Fixture, b2Fixture)`方法，你可以自定义它以执行你自己的过滤。实际上，category/group 过滤器本身就是以这种方式实现的。

## 进一步了解 Box2D

这篇关于 Box2D 的简短介绍仅让你了解了 Box2D 的能力！以下非详尽列表被留在了阴影中：

+   用于连接两个物体的关节

+   使用**光线投射**来查询物理世界（例如，枪指向哪个位置）

+   接触属性：法线、冲量、流形等

### 提示

Box2D 现在有一个小兄弟叫做**LiquidFun**，用于模拟流体。你可以下载并在[`google.github.io/liquidfun/`](http://google.github.io/liquidfun/)查看它的效果。

Box2D 有一个非常棒的文档，其中包含有用的信息，可以在 [`www.box2d.org/manual.html`](http://www.box2d.org/manual.html) 找到。此外，Box2D 带有一个测试床目录（在 `Box2D/Testbed/Tests` 中），其中包含许多用例。查看它们以更好地了解其功能。由于物理模拟有时可能相当棘手，我还建议您访问相当活跃的 Box2D 论坛，地址是 [`www.box2d.org/forum/`](http://www.box2d.org/forum/)。

# 在 Android 上预编译 Boost

如果说 STL 是 C++ 程序中最常见的框架，那么 Boost 可能就是第二位。它就像一把瑞士军刀！这个工具箱包含大量用于处理最常见需求的实用工具，甚至更多。

大多数 Boost 功能以头文件形式提供，这意味着我们无需编译它。包含头文件就足以使用它的优势。最流行的 Boost 功能就是这种情况：**智能指针**，这是一个引用计数的指针类，可以自动处理内存分配和释放。它们几乎免费地避免了大多数内存泄漏和指针误用。

然而，Boost 的某些部分需要先编译，比如线程或单元测试库。我们现在将了解如何使用 Android NDK 构建它们并编译一个单元测试可执行文件。

### 注意

本书提供了名为 `DroidBlaster_Part18` 的项目结果。

# 动手时间 – 预编译 Boost 静态库

让我们按照以下步骤将 Boost 作为静态库预编译到 Android 上：

1.  从 [`www.boost.org/`](http://www.boost.org/) 下载 Boost（本书中使用的是 1.55.0 版本）。将归档文件解压到 `${ANDROID_NDK}/sources` 目录下，并将目录命名为 `boost`。

    打开命令行窗口，进入 `boost` 目录。在 Windows 上运行 `bootstrap.bat` 或在 Linux 和 Mac OS X 上运行 `./bootstrap.sh` 来构建 **b2**。这个程序，之前名为 **BJam**，是一种类似于 **Make** 的自定义构建工具。

    ### 注意

    本书中提供了 Boost 1.55.0 归档文件，位于 `Libraries/boost` 目录。

    更改 DroidBlaster 中的 NDK 构建命令，以生成详细的编译日志。为此，在 Eclipse 的 **项目属性** 中，导航到 **C/C++ Build** 部分。在那里，您应该看到以下构建命令：`ndk-build NDK_DEBUG=1`。将其更改为 `build NDK_DEBUG=0 V=1` 以在发布模式下编译并生成详细日志。

1.  重新构建 DroidBlaster（您可能需要先清理项目）。例如，如果您查看下面的编译摘录，您应该会看到一些与下面摘录相似的日志。这个日志虽然几乎难以阅读，但它提供了构建 DroidBlaster 运行的所有命令的信息。

    +   用于构建 DroidBlaster 的工具链（`arm-linux-androideabi-4.6`）

    +   DroidBlaster 所构建的系统（`linux-x86_64`）

    +   编译器可执行文件（`arm-linux-androideabi-g++`）

    +   归档器可执行文件（`arm-linux-androideabi-ar`）

    +   还包括传递给它们的所有编译标志（这里针对 ARM 处理器）

    我们可以将以下内容作为确定`Boost`编译标志（在这锅标志汤中！）的灵感来源：

    ```java
    ...
    /opt/android-ndk/toolchains/arm-linux-androideabi-4.6/prebuilt/linux-x86_64/bin/arm-linux-androideabi-g++ -MMD -MP -MF ./obj/local/armeabi/objs/DroidBlaster/Asteroid.o.d -fpic -ffunction-sections -funwind-tables -fstack-protector -no-canonical-prefixes -march=armv5te -mtune=xscale -msoft-float -fno-exceptions -fno-rtti -mthumb -Os -g -DNDEBUG -fomit-frame-pointer -fno-strict-aliasing -finline-limit=64 -I/opt/android-ndk/sources/android/native_app_glue -I/opt/android-ndk/sources/libpng -I/opt/android-ndk/sources/box2d -I/opt/android-ndk/sources/cxx-stl/gnu-libstdc++/4.6/include -I/opt/android-ndk/sources/cxx-stl/gnu-libstdc++/4.6/libs/armeabi/include -I/opt/android-ndk/sources/cxx-stl/gnu-libstdc++/4.6/include/backward -Ijni -DANDROID  -Wa,--noexecstack -Wformat -Werror=format-security      -I/opt/android-ndk/platforms/android-16/arch-arm/usr/include -c  jni/Asteroid.cpp -o ./obj/local/armeabi/objs/DroidBlaster/Asteroid.o

    ...
    /opt/android-ndk/toolchains/arm-linux-androideabi-4.6/prebuilt/linux-x86_64/bin/arm-linux-androideabi-ar crsD ./obj/local/armeabi/libandroid_native_app_glue.a ./obj/local/armeabi/objs/android_native_app_glue/android_native_app_glue.o
    ...
    ```

1.  在`boost`目录中，打开`tools/build/v2/user-config.jam`文件。这个文件，如它的名字所示，是一个配置文件，可以设置以定制`Boost`编译。初始内容只包含注释，可以删除。开始包含以下内容：

    ```java
    import feature ;
    import os ;

    if [ os.name ] = CYGWIN || [ os.name ] = NT {
        androidPlatform = windows ;
    } else if [ os.name ] = LINUX {
        if [ os.platform ] = X86_64 {
            androidPlatform = linux-x86_64 ;
        } else {
            androidPlatform = linux-x86 ;
        }
    } else if [ os.name ] = MACOSX {
        androidPlatform = darwin-x86 ;
    }
    ...
    ```

1.  编译是静态执行的。默认情况下，**BZip**在 Android 上不可用，因此被禁用（不过我们可以单独编译它）：

    ```java
    ...
    modules.poke : NO_BZIP2 : 1 ;
    ...
    ```

1.  获取指向 NDK 在磁盘上位置的`android_ndk`环境变量。

    声明我们可以称之为“配置”的`android4.6_armeabi`。

    然后，重新配置 Boost 以在静态模式下使用 NDK ARM GCC 工具链（`g++`，`ar`和`ranlib`），归档器负责创建静态库。我们可以使用第 2 步日志中找到的信息来填充它们各自的路徑。

    `sysroot`指令指示编译和链接针对哪个 Android API 版本。在 NDK 中指定的目录包含特定于此版本的`include`文件和库，如下代码所示：

    ```java
    ...
    android_ndk = [ os.environ ANDROID_NDK ] ;
    using gcc : android4.6_armeabi :
        $(android_ndk)/toolchains/arm-linux-androideabi-4.6/prebuilt/$(androidPlatform)/bin/arm-linux-androideabi-g++ :
        <archiver>$(android_ndk)/toolchains/arm-linux-androideabi-4.6/prebuilt/$(androidPlatform)/bin/arm-linux-androideabi-ar
        <ranlib>$(android_ndk)/toolchains/arm-linux-androideabi-4.6/prebuilt/$(androidPlatform)/bin/arm-linux-androideabi-ranlib
        <compileflags>--sysroot=$(android_ndk)/platforms/android-16/arch-arm
        <compileflags>-I$(android_ndk)/sources/cxx-stl/gnu-libstdc++/4.6/include
        <compileflags>-I$(android_ndk)/sources/cxx-stl/gnu-libstdc++/4.6/libs/armeabi/include
    ...
    ```

1.  Boost 需要异常和 RTTI。使用`–fexceptions`和`–frtti`标志启用它们，如下代码所示：

    ```java
    ...
        <compileflags>-fexceptions
        <compileflags>-frtti
    ...
    ```

1.  需要定义几个选项来调整`Boost`的编译。这里我们可以借鉴第 2 步中发现的编译标志，例如：

    +   `-march=armv5te`以指定目标平台

    +   `-mthumb`，表示生成的代码应使用 thumb 指令（也可以使用`-marm`来使用 ARM 指令））

    +   `-0s`以启用编译器优化

    +   `-DNDEBUG`以请求以发布模式编译

    还包括或调整其他附加标志，例如：

    +   `-D__arm__`，`-D__ARM_ARCH_5__`等，有助于从代码中确定目标平台

    +   `-DANDROID`，`-D__ANDROID__`有助于确定目标操作系统

    +   `-DBOOST_ASIO_DISABLE_STD_ATOMIC`以禁用`std::atomic`的使用，它在 Android 上是错误的（这是只能通过（不好）的“经验”学到的…）。

        ```java
            <compileflags>-march=armv5te
            <compileflags>-mthumb
            <compileflags>-mtune=xscale
            <compileflags>-msoft-float
            <compileflags>-fno-strict-aliasing
            <compileflags>-finline-limit=64
            <compileflags>-D__arm__
            <compileflags>-D__ARM_ARCH_5__
            <compileflags>-D__ARM_ARCH_5T__
            <compileflags>-D__ARM_ARCH_5E__
            <compileflags>-D__ARM_ARCH_5TE__
            <compileflags>-MMD
            <compileflags>-MP
            <compileflags>-MF
            <compileflags>-fpic
            <compileflags>-ffunction-sections
            <compileflags>-funwind-tables
            <compileflags>-fstack-protector
            <compileflags>-no-canonical-prefixes
            <compileflags>-Os
            <compileflags>-fomit-frame-pointer
            <compileflags>-fno-omit-frame-pointer
            <compileflags>-DANDROID
            <compileflags>-D__ANDROID__
            <compileflags>-DNDEBUG
            <compileflags>-D__GLIBC__
            <compileflags>-DBOOST_ASIO_DISABLE_STD_ATOMIC
            <compileflags>-D_GLIBCXX__PTHREADS
            <compileflags>-Wa,--noexecstack
            <compileflags>-Wformat
            <compileflags>-Werror=format-security
            <compileflags>-lstdc++
            <compileflags>-Wno-long-long
                ;
        ```

1.  从指向 boost 目录的终端，使用以下命令行启动编译。我们需要排除**Python**模块，因为它需要默认在 NDK 上不可用的附加库。

    ```java
    ./b2 --without-python toolset=gcc-android4.6_armeabi link=static runtime-link=static target-os=linux architecture=arm --stagedir=android-armeabi threading=multi

    ```

最终的静态库生成在`android-armeabi/lib/`目录中。

对 ArmV7 和 X86 平台重复相同的步骤，为每个平台创建一个新的配置。对于 ArmV7，暂存目录必须是`armeabi-v7a`，对于 X86，必须是`android-x86`。

### 注意

最终的`user-config.jam`随本书一起提供，位于`Libraries/boost`目录中。

## *刚才发生了什么？*

我们定制了 Boost 配置，使用原始的 Android GCC 工具链作为独立的编译器（即，不使用 NDK 包装器）。我们声明了各种标志以适应 Android 目标平台的编译。然后，我们使用其专用的构建工具`b2`手动构建 Boost。现在，每次更新或修改 Boost，代码都需要使用`b2`重新手动编译。

我们还通过`V=1`参数强制 NDK-Build 生成详细的日志。这对于排除编译问题或了解 NDK-Build 编译的内容和方式非常有帮助。

最后，我们通过将`NDK_DEBUG`设置为`0`来启用发布编译模式，即进行代码优化。也可以通过在`jni/Application.mk`中设置`APP_OPTIM := release`来实现。GCC 中有五个主要的优化级别，它们如下所示：

+   **-O0**：这禁用任何优化。当`APP_OPTIM`设置为`debug`时，NDK 会自动设置此选项（关于这一点，在本章关于 Makefiles 的最后一部分会有更多介绍）。

+   **-O1**：这允许进行基本优化，而不会过多增加编译时间。这些优化不需要任何速度和空间的权衡，这意味着它们可以产生更快的代码，而不会增加可执行文件的大小。

+   **-O2**：这允许进行高级优化（包括`-O1`），但会增加编译时间。与`–O1`一样，这些优化不需要速度和空间的权衡。

+   **-O3**：这执行积极的优化（包括`-O2`），可能会增加可执行文件的大小，例如**函数内联**。这通常是有益的，但有时可能会适得其反（例如，增加内存使用也可能增加缓存未命中）。

+   **-Os**：这优先优化编译代码的大小（`–O2`的子集），其次才是速度。

尽管在发布模式下通常使用`-Os`或`–O2`，但对于性能关键代码也可以考虑使用`-O3`。`-0x`标志是各种 GCC 优化标志的快捷方式，启用`–O2`并附加额外的“细粒度”标志（例如，`-finline-functions`）也是一个选项。无论您选择哪种选项，找到最佳选择的最简单方法就是进行基准测试！要获取有关众多 GCC 优化选项的更多信息，请查看[`gcc.gnu.org/`](http://gcc.gnu.org/)。

现在 Boost 模块已经预建好了，我们可以将它的任何库嵌入到我们的应用程序中。

# 动手时间——编译与 Boost 链接的可执行文件

让我们通过以下步骤使用 Boost 单元测试库来构建我们自己的单元测试可执行文件：

1.  仍然在`boost`目录下，创建一个新的`Android.mk`文件，将新预建的库声明为 Android 模块，以便 NDK 应用程序可以使用。这个文件需要为每个库包含一个模块声明。例如，定义一个名为`boost_unit_test_framework`的模块：

    +   `LOCAL_SRC_FILES`引用了我们使用 b2 构建的静态库`libboost_unit_test_framework.a`。

    使用 `$(TARGET_ARCH_ABI)` 变量来确定正确的路径，这取决于目标平台。它的值可以是 `armeabi`、`armeabi-v7a` 或 `x86`。如果你为 X86 编译 DroidBlaster，NDK 将在 `androidx86/lib` 中查找 `libboost_unit_test_framework.a`。

    +   `LOCAL_EXPORT_C_INCLUDES` 会自动将 Boost 根目录添加到包含模块的包含文件目录列表中。

    +   指明这个模块是一个预构建的库，使用 `$(PREBUILT_STATIC_LIBRARY)` 指令：

        ```java
        LOCAL_PATH:= $(call my-dir)

        include $(CLEAR_VARS)

        LOCAL_MODULE:= boost_unit_test_framework
        LOCAL_SRC_FILES:= android-$(TARGET_ARCH_ABI)/lib/libboost_unit_test_framework.a
        LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)

        include $(PREBUILT_STATIC_LIBRARY)
        ```

    可以在同一个文件中声明更多的模块，使用相同的行集（例如，`boost_thread`）。

    ### 注意

    本书中提供的最终 `user-config.jam` 文件位于 `Libraries/boost` 目录中。

1.  回到 `DroidBlaster` 项目，并创建一个名为 `test` 的新目录，其中包含单元测试文件 `test/Test.cpp`。编写一个测试来检查例如 `TimeManager` 的行为，如下代码所示：

    ```java
    #include "Log.hpp"
    #include "TimeManager.hpp"

    #include <unistd.h>

    #define BOOST_TEST_MODULE DroidBlaster_test_module
    #include <boost/test/included/unit_test.hpp>

    BOOST_AUTO_TEST_SUITE(suiteTimeManager)

    BOOST_AUTO_TEST_CASE(testTimeManagerTest_elapsed)
    {
        TimeManager timeManager;
        timeManager.reset();

        sleep(1);
        timeManager.update();
        BOOST_REQUIRE(timeManager.elapsed() > 0.9f);
        BOOST_REQUIRE(timeManager.elapsed() < 1.2f);

        sleep(1);
        timeManager.update();
        BOOST_REQUIRE(timeManager.elapsed() > 0.9f);
        BOOST_REQUIRE(timeManager.elapsed() < 1.2f);
    }

    BOOST_AUTO_TEST_SUITE_END()
    ```

1.  要在应用程序中包含 Boost，我们需要将它与支持异常和 RTTI 的 STL 实现链接起来。在 `Application.mk` 文件中全局启用它们，如下代码所示：

    ```java
    APP_ABI := armeabi armeabi-v7a x86
    APP_STL := gnustl_static
    APP_CPPFLAGS := -fexceptions –frtti

    ```

1.  最后，打开 DroidBlaster 的 `jni/Android.mk` 文件，在 `import-module` 部分之前创建一个名为 `DroidBlaster_test` 的第二个模块。这个模块编译额外的 `test/Test.cpp` 测试文件，并且必须链接到 Boost 单元测试库。将此模块构建为可执行文件，而不是共享库，使用 `$(BUILD_EXECUTABLE)`。

    最后，在 `import-module` 部分导入 `Boost` 模块本身，如下代码所示：

    ```java
    ...
    include $(BUILD_SHARED_LIBRARY)

    include $(CLEAR_VARS)

    LS_CPP=$(subst $(1)/,,$(wildcard $(1)/*.cpp))
    LS_CPP_TEST=$(subst $(1)/,,$(wildcard $(1)/../test/*.cpp))
    LOCAL_MODULE := DroidBlaster_test
    LOCAL_SRC_FILES := $(call LS_CPP,$(LOCAL_PATH)) \

    $(call LS_CPP_TEST,$(LOCAL_PATH))
    LOCAL_LDLIBS := -landroid -llog -lEGL -lGLESv2 -lOpenSLES
    LOCAL_STATIC_LIBRARIES := android_native_app_glue png box2d_static \
        libboost_unit_test_framework

    include $(BUILD_EXECUTABLE)

    $(call import-module,android/native_app_glue)
    $(call import-module,libpng)
    $(call import-module,box2d)
    $(call import-module,boost)

    ```

1.  构建项目。如果你查看 `libs` 文件夹，除了共享库之外，你应该能看到一个 `droidblaster_test` 文件。这是一个可执行文件，我们可以在模拟器或已获得权限的设备上运行（假设你有部署和更改文件权限的权利）。部署这个文件并运行它（这里在一个 Arm V7 模拟器实例上）：

    ```java
    adb push libs/armeabi-v7a/droidblaster_test /data/data/
    adb shell /data/data/droidblaster_test

    ```

![行动时间 – 编译一个链接到 Boost 的可执行文件](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_09_01.jpg)

## *刚才发生了什么？*

我们已经使用 Boost 预构建模块创建了一个完全本地的可执行文件，并且可以在 Android 上运行它。Boost 预构建静态库已经从 `Boost` 目录中的 Boost `Android.mk` 模块文件“发布”。

实际上，构建本地库有四种主要方法。我们在 Box2D 部分已经看到了 `BUILD_STATIC_LIBRARY` 和 `BUILD_SHARED_LIBRARY`。还有两个共存的选择，如下所示：

+   `PREBUILT_STATIC_LIBRARY` 用于使用现有的（即预构建的）二进制静态库。

+   `PREBUILT_SHARED_LIBRARY` 用于使用现有的二进制共享库

这些指令表明库已经准备好进行链接。

在主模块文件内部，正如我们在 Box2D 中看到的，需要列出链接的子模块：

+   `LOCAL_SHARED_LIBRARIES` 用于共享库

+   `LOCAL_STATIC_LIBRARIES` 用于静态库

无论库是否是预构建的，都适用相同的规则。无论是静态的、动态的、预构建的还是按需构建的模块，都必须使用 NDK 的`import-module`指令在最终的 main 模块中导入。

当一个预构建的库被链接到主模块时，源文件并不是必需的。显然，头文件仍然是必需的。因此，如果你想在不对第三方公开源代码的情况下提供一个库，预构建库是一个合适的选择。另一方面，按需编译允许从你的主`Application.mk`项目文件中调整所有包含库的编译标志（如优化标志、ARM 模式等）。

为了正确链接 Boost，我们还在整个项目中启用了异常和运行时类型信息（RTTI）。通过在`Application.mk`文件中的`APP_CPPFLAGS`指令或者相关库的`LOCAL_CPPFLAGS`文件中添加`-fexceptions`和`-frtti`，可以很容易地激活异常和 RTTI。默认情况下，Android 编译时带有`-fno-exceptions`和`-fno-rtti`标志。

事实上，异常处理会让编译后的代码体积变大且效率降低。它会阻止编译器执行一些巧妙的优化。然而，异常处理是否比错误检查更糟糕，甚至不如完全不检查，这是一个高度有争议的问题。实际上，谷歌的工程师在最初的版本中放弃了异常处理，因为 GCC 3.x 为 ARM 处理器生成的异常处理代码质量不佳。但是现在构建链使用了 GCC 4.x，这个缺陷已经不存在了。与手动错误检查和处理异常情况相比，这种开销大多数时候可能并不显著。因此，是否选择异常处理取决于你（以及你使用的嵌入式库）！

### 提示

C++中的异常处理并不容易，它要求严格的纪律！它们必须严格用于异常情况，并要求精心设计的代码。可以查看**资源获取即初始化**（**RAII**）习惯用法来正确处理它们。更多信息，请查看[`en.wikipedia.org/wiki/Resource_Acquisition_Is_Initialization`](http://en.wikipedia.org/wiki/Resource_Acquisition_Is_Initialization)。

显然，Boost 提供的功能远比单元测试有趣得多。在其官方文档[`www.boost.org/doc/libs`](http://www.boost.org/doc/libs)中探索其全部丰富特性。注意，由于 Boost 在 Android 平台上没有得到积极维护和测试，因此它可能会经常出现破坏性更改或错误。

既然我们已经实际了解了如何编写模块 Makefiles，让我们进一步了解它们。

# 掌握模块 Makefiles

Android Makefiles 是 NDK 构建过程的重要组成部分。因此，为了正确构建和管理项目，理解它们的工作方式是很重要的。

## Makefile 变量

编译设置是通过一组预定义的 NDK 变量来定义的。我们已经看到了三个最重要的变量：`LOCAL_PATH, LOCAL_MODULE`和`LOCAL_SRC_FILES`，但还有许多其他变量存在。我们可以区分以下四种类型的变量，每种类型的前缀都不同：

+   `LOCAL_`变量：这些专门用于单个模块编译，在`Android.mk`文件中定义。

+   `APP_`变量：这些指的是应用范围内的选项，在`Application.mk`中设置。

+   `NDK_`变量：这些主要是内部变量，通常指的是环境变量（例如，`NDK_ROOT`, `NDK_APP_CFLAGS`或`NDK_APP_CPPFLAGS`）。有两个值得注意的例外：`NDK_TOOLCHAIN_VERSION`和`NDK_APPLICATION_MK`。后者可以传递给 NDK-Build 参数，以定义不同的`Application.mk`位置。

+   带有`PRIVATE_`前缀的变量：这些仅用于 NDK 内部使用。

以下表格包含了一个非详尽的`LOCAL`变量列表：

| 变量 | 描述 |
| --- | --- |
| `LOCAL_PATH` | 用于指定源文件的根位置。必须在`Android.mk`文件中的`include $(CLEAR_VARS)`之前定义。 |
| `LOCAL_MODULE` | 用于定义模块名称，它必须在所有模块中保持唯一。 |
| `LOCAL_MODULE_FILENAME` | 用于重写编译模块的默认名称，对于共享库是：`- lib<模块名称>.so`，对于静态库是：`- lib<模块名称>.a`。不能指定自定义文件扩展名，因此`.so`或`.a`仍会附加在后面。 |
| `LOCAL_SRC_FILES` | 用于定义要编译的源文件列表，每个文件以空格分隔，相对于`LOCAL_PATH`。 |
| `LOCAL_C_INCLUDES` | 用于指定 C 和 C++语言的头文件目录。该目录可以是相对于`${ANDROID_NDK}`目录的，但除非你需要包含特定的 NDK 文件，否则建议使用绝对路径（可以从 Makefile 变量如`$(LOCAL_PATH)`构建）。 |
| `LOCAL_CPP_EXTENSION` | 用于更改默认的 C++文件扩展名，即`.cpp`（例如，`.cc`或`.cxx`）。可以指定以空格分隔的文件扩展名列表。扩展名对于 GCC 确定哪个文件与哪种语言相关是必要的。 |
| `LOCAL_CFLAGS`, `LOCAL_CPPFLAGS`, `LOCAL_LDLIBS` | 用于指定编译和链接的任何选项、标志或宏定义。第一个适用于 C 和 C++，第二个仅适用于 C++，最后一个用于链接器。 |
| `LOCAL_SHARED_LIBRARIES`, `LOCAL_STATIC_LIBRARIES` | 分别声明与其他模块（非系统库）的共享和静态模块依赖关系。`LOCAL_SHARED_LIBRARIES`管理依赖关系，而`LOCAL_LDLIBS`应用于声明系统库。 |
| `LOCAL_ARM_MODE`, `LOCAL_ARM_NEON`, `LOCAL_DISABLE_NO_EXECUTE`, `LOCAL_FILTER_ASM` | 处理器和汇编器/二进制代码生成的高级变量。对于大多数程序来说它们不是必需的。 |
| `LOCAL_EXPORT_C_INCLUDES`, `LOCAL_EXPORT_CFLAGS`, `LOCAL_EXPORT_CPPFLAGS`, `LOCAL_EXPORT_LDLIBS` | 在导入模块中定义额外的选项或标志，这些选项或标志应附加到客户端模块选项中。例如，如果一个模块 A 定义了`LOCAL_EXPORT_LDLIBS := -llog`，因为它需要一个 Android 日志模块。那么，依赖于模块 A 的模块 B 将自动链接到`–llog`。`LOCAL_EXPORT_`变量在编译导出它们的模块时不使用。如果需要，它们还需要在它们的`LOCAL`对应项中指定。 |

关于这些变量的文档可以在`${ANDROID_NDK}/docs/ANDROID-MK.html`找到。

下表包含了`APP`变量的非详尽列表（所有都是可选的）：

| 变量 | 描述 |
| --- | --- |
| `APP_PROJECT_PATH` | 指定应用程序项目的根目录。 |
| `APP_MODULES` | 要编译的模块及其标识符的列表。还包括依赖的模块。例如，可以用来强制生成静态库。 |
| `APP_OPTIM` | 设置为`release`或`debug`，以使编译设置适应您想要的构建类型。当未明确指定时，NDK 使用 AndroidManifest 中的可调试标志来确定构建类型。 |
| `APP_CFLAGS``APP_CPPFLAGS``APP_LDFLAGS` | 全局指定编译和链接的任何选项、标志或宏定义。第一个适用于 C 和 C++，第二个仅适用于 C++，最后一个适用于链接器。 |
| `APP_BUILD_SCRIPT` | 重新定义 Android.mk 文件的存放位置（默认在项目的`jni`目录中）。 |
| `APP_ABI` | 应用程序支持的 ABI（即“CPU 架构”）列表，以空格分隔。目前支持的值有`armeabi`、`armeabi-v7a`、`x86`、`mips`或`all`。每个模块针对每个 ABI 重新编译一次。因此，支持的 ABI 越多，构建所需的时间就越长。 |
| `APP_PLATFORM` | 目标 Android 平台的名称。此信息默认在`project.properties`文件中找到。 |
| `APP_STL` | 要使用的 C++运行时。可能的值有`system`、`gabi++_static`、`gabi++_shared`、`stlport_static`、`stlport_shared`、`gnustl_static`、`gnustl_shared`、`c++_static`和`c++_shared`。 |

关于这些变量的文档可以在`${ANDROID_NDK}/docs/APPLICATION-MK.html`找到。

## 启用 C++ 11 支持和 Clang 编译器

`NDK_TOOLCHAIN_VERSION`变量可以在`Application.mk`文件中重新定义，以显式选择编译工具链。对于 NDK R10，可能的值有`4.6`（现已弃用）、`4.8`和`4.9`，这些值分别对应于 GCC 版本。未来 NDK 版本中可能更改的可能版本号。要找到它们，请查看`$ANDROID_NDK/toolchains`目录。

Android NDK 从 GCC 4.8 工具链开始提供 C++ 11 支持。通过添加`-std=c++11`编译标志并激活 GNU STL（STL Port 在此书编写时不受支持，而 Libc++只部分支持），可以获得适当的 C++11 支持。以下是激活了 C++11 的`Android.mk`提取示例：

```java
...
NDK_TOOLCHAIN_VERSION := 4.8
APP_CPPFLAGS += -std=c++11
APP_STL := gnustl_shared
...
```

### 提示

切换到 GCC4.8 和 C++11 可能不会一帆风顺。实际上，这个编译器，比如说，比之前要严格一些。如果你在使用这个新工具链编译旧代码时遇到麻烦，尝试使用`–fpermissive`标志（或者重写你的代码！）。

此外，请注意，尽管 C++11 的支持已经很广泛，但你可能仍然会遇到一些问题或缺失的功能。

要启用基于 LLVM 的编译器 Clang（因被苹果使用而著名），代替 GCC，只需将`NDK_TOOLCHAIN_VERSION`设置为`clang`。你也可以指定编译器版本，比如`clang3.4`或`clang3.5`。同样，可能的版本号可能会在 NDK 的未来版本中发生变化。要找到它们，请查看`$ANDROID_NDK/toolchains`目录。

## Makefile 指令

Makefile 是一种真正的语言，包含编程指令和函数。

Makefiles 可以分解为几个子 Makefiles，通过`include`指令包含。变量初始化有两种方式：

+   简单赋值（`operator :=`），在变量初始化时展开变量

+   递归赋值（`operator =`），每次调用时重新评估受影响的表达式

以下条件判断和循环指令可用：`ifdef/endif`，`ifeq/endif`，`ifndef/endif`，以及`for…in/do/done`。例如，仅当定义了变量时，才显示消息，可以这样做：

```java
ifdef my_var
    # Do something...
endif
```

更高级的内容，如函数式`if`、`and`、`or`等，可供使用，但很少被使用。Makefiles 还提供了一些有用的内置函数，如下表所示：

| `$(info <message>)` | 允许将消息打印到标准输出。这是编写 Makefiles 时最关键的工具！信息消息中允许使用变量。 |
| --- | --- |
| `$(warning <message>)`，`$(error <message>)` | 允许打印警告或致命错误，停止编译。这些消息可以被 Eclipse 解析。 |
| `$(foreach <variable>`, `<list>`, `<operation>)` | 对变量列表执行操作。在应用操作之前，列表中的每个元素都会在第一个参数变量中展开。 |
| `$(shell <command>)` | 在 Make 外部执行命令。这将为 Makefiles 带来 Unix Shell 的所有强大功能，但非常依赖于系统。如果可能，避免使用它。 |
| `$(wildcard <pattern>)` | 根据模式选择文件和目录名称。 |
| `$(call <function>)` | 允许评估一个函数或宏。我们见过的宏之一是 `my-dir`，它返回最后一个执行的 Makefile 的目录路径。这就是为什么每个 `Android.mk` 文件的开头都会写上 `LOCAL_PATH := $(call my-dir)`，以保存当前 Makefile 目录。 |

使用 `call` 指令可以轻松编写自定义函数。这些函数看起来类似于递归赋值的变量，不同之处在于可以定义参数：`$(1)` 代表第一个参数，`$(2)` 代表第二个参数，依此类推。函数的调用可以在单行中执行，如下代码所示：

```java
my_function=$(<do_something> ${1},${2})
$(call my_function,myparam)
```

字符串和文件操作函数也是可用的，如下表所示：

| `$(join <str1>, <str2>)` | 连接两个字符串。 |
| --- | --- |
| `$(subst <from>,``<replacement>,<string>)`,`$(patsubst <pattern>,``<replacement>,<string>)` | 将字符串中的每个子串替换为另一个。第二个更强大，因为它允许使用模式（必须以 "%" 开头）。 |
| `$(filter <patterns>, <text>)``$(filter-out <patterns>, <text>)` | 从匹配模式的文本中过滤字符串。这对于过滤文件很有用。例如，以下行过滤任何 C 文件：`$(filter %.c, $(my_source_list))` |
| `$(strip <string>)` | 移除任何不必要的空白。 |
| `$(addprefix <prefix>,<list>)`,`$(addsuffix <suffix>, <list>)` | 分别向列表中的每个元素添加前缀和后缀，每个元素由空格分隔。 |
| `$(basename <path1>, <path2>, ...)` | 返回一个移除了文件扩展名的字符串。 |
| `$(dir <path1>, <path2>)`,`$(notdir <path1>, <path2>)` | 分别提取路径中的目录和文件名。 |
| `$(realpath <path1>, <path2>, ...)`,`$(abspath <path1>, <path2>, ...)` | 返回每个路径参数的规范路径，但第二个不评估符号链接。 |

这只是对 Makefiles 功能的概览。更多信息，请参考在 [`www.gnu.org/software/make/manual/make.html`](http://www.gnu.org/software/make/manual/make.html) 可用的完整 Makefile 文档。如果你对 Makefiles 过敏，可以看看 CMake。CMake 是一个简化的 Make 系统，已经在市场上构建了许多开源库。CMake 在 Android 上的端口可以在 [`code.google.com/p/android-cmake`](http://code.google.com/p/android-cmake) 找到。

## 动手英雄 - 掌握 Makefiles

我们可以用多种方式玩转 Makefiles：

+   尝试赋值运算符。例如，在你的 `Android.mk` 文件中写下以下代码片段，它使用了 `:=` 运算符：

    ```java
    my_value   := Android
    my_message := I am an $(my_value)
    $(info $(my_message))
    my_value   := Android eating an apple
    $(info $(my_message))
    ```

+   观察启动编译时的结果。然后，使用 `=` 执行相同的操作。打印当前优化模式。使用 `APP_OPTIM` 和内部变量 `NDK_APP_CFLAGS`，观察 `release` 和 `debug` 模式之间的区别：

    ```java
    $(info Optimization level: $(APP_OPTIM) $(NDK_APP_CFLAGS))
    ```

+   检查变量是否正确定义，例如：

    ```java
    ifndef LOCAL_PATH
        $(error What a terrible failure! LOCAL_PATH not defined...)
    endif
    ```

+   尝试使用 `foreach` 指令打印项目根目录及其 `jni` 文件夹内的文件和目录列表（并确保使用递归赋值）：

    ```java
    ls = $(wildcard $(var_dir))
    dir_list := . ./jni
    files := $(foreach var_dir, $(dir_list), $(ls))
    ```

+   尝试创建一个宏，将消息和时间记录到标准输出：

    ```java
    log=$(info $(shell date +'%D %R'): $(1))
    $(call log,My message)
    ```

+   最后，测试 `my-dir` 宏的行为，了解为什么每个 `Android.mk` 文件的开头都会系统性地写出 `LOCAL_PATH := $(call my-dir)`：

    ```java
    $(info MY_DIR    =$(call my-dir))
    include $(CLEAR_VARS)
    $(info MY_DIR    =$(call my-dir))
    ```

## CPU 架构（ABI）

当前 Android ARM 设备上的原生 C/C++ 代码遵循一个**应用程序二进制接口**（**ABI**）。ABI 规定了二进制代码格式（指令集、调用约定等）。GCC 将代码翻译成这种二进制格式。因此，ABI 与处理器密切相关。可以在 `Application.mk` 文件中通过 `APP_ABI` 变量选择目标 ABI。在 Android 上支持五种主要 ABI，如下所示：

+   **thumb**：这是默认选项，应与所有 ARM 设备兼容。Thumb 是一种特殊的指令集，它用 16 位而不是 32 位编码指令，以提高代码大小（对内存受限的设备很有用）。与 ArmEABI 相比，指令集受到严格限制。

+   **armeabi**（或 Arm v5）：这应该能在所有 ARM 设备上运行。指令编码为 32 位，但可能比 Thumb 代码更简洁。Arm v5 不支持浮点加速等高级扩展，因此比 Arm v7 慢。

+   **armeabi-v7a**：这支持如 Thumb-2（类似于 Thumb，但增加了额外的 32 位指令）和 VFP 等扩展，以及一些可选扩展，如 NEON。为 Arm V7 编译的代码不能在 Arm V5 处理器上运行。

+   **x86**：这是针对“*PC-like*”架构（即 Intel/AMD）的，更具体地说，是针对 Intel Atom 处理器的。这个 ABI 提供了特定的扩展，如 MMX 或 SSE。

+   **mips**：这是针对由 Imagination Technologies 开发的 MIPS 处理器（该公司还生产 PowerVR 图形处理器）。在撰写本书时，只有少数设备存在。

默认情况下，每个 ABI 编译的二进制文件都嵌入在 APK 中。在安装时选择最合适的。Google Play 还支持上传针对每个 ABI 的不同 APK，以限制应用程序大小。

## 高级指令集（NEON、VFP、SSE、MSA）

如果你正在阅读这本书，代码性能可能是你的主要标准之一。为了达到这个目标，ARM 创建了一个 SIMD 指令集（即单指令多数据，简称 Single Instruction Multiple Data，即使用一条指令并行处理多个数据），名为 NEON，它与 VFP（浮点加速）单元一起引入。NEON 并不是所有芯片都可用（例如，Nvidia Tegra 2 不支持它），但在密集型多媒体应用中相当受欢迎。它们也是一些处理器（例如，Cortex-A8）弱 VFP 单元的良好补偿方式。

### 提示

NEON 代码可以写在单独的汇编文件中，使用专门的 `asm volatile` 块和汇编指令，或者写在 C/C++ 文件中，或者作为内联函数（将 NEON 指令封装在 GCC C 例程中）。使用内联函数时要小心，因为 GCC 经常无法生成高效的机器代码（或者需要很多巧妙的提示）。通常建议编写真正的汇编代码。

X86 CPU 具有一套与 ARM 不同的扩展指令集：MMX、SSE、SSE2 和 SSE3。SSE 指令集相当于英特尔的 NEON SIMD 指令。最新的 SSE4 指令通常不被当前 X86 处理器支持。显然，SSE 和 NEON 不兼容，这意味着专门为 NEON 编写的代码需要重写以适应 SSE，反之亦然。

### 提示

Android 提供了一个 `cpu-features.h` API（包含 `android_getCpuFamily()` 和 `android_getCpuFeatures()` 方法），可以在运行时检测宿主设备上的可用特性。它有助于检测 CPU（ARM、X86）及其能力（支持 ArmV7、NEON、VFP 等）。

NEON、SSE 和现代处理器通常不易掌握。互联网上有很多可以借鉴的例子。参考技术文档可以在 ARM 网站 [`infocenter.arm.com/`](http://infocenter.arm.com/) 和英特尔开发者手册 [`www.intel.com/`](http://www.intel.com/) 上找到。

MIPS 也有自己的 SIMD 指令集 MSA。它提供了诸如向量算术和分支操作，或者整数和浮点值之间的转换等功能。更多信息请查看 [`www.imgtec.com/mips/architectures/simd.asp`](http://www.imgtec.com/mips/architectures/simd.asp)。

所有这些信息都很有趣，但它并没有回答你可能问自己的问题：从 ARM 移植代码到 X86（或反之）有多难？答案是“视情况而定”：

+   如果你使用纯 C/C++ 本地代码，没有特定的指令集，只需将 `x86` 或 `mips` 追加到 `APP_ABI` 变量，代码应该是可移植的。

+   如果你的代码包含汇编代码，你将需要为其他 ABI 重写相应部分或提供备用方案。

+   如果你的代码包含特定的指令集，如 NEON（使用 C/C++ 内联函数或汇编代码），你将需要为其他 ABI 重写相应部分或提供备用方案。

+   如果你的代码依赖于特定的内存对齐，你可能需要使用显式对齐。确实，当你编译一个数据结构时，编译器可能会使用填充来适当地对齐内存中的数据，以便更快地访问内存。然而，对齐要求根据 ABI 的不同而不同。

例如，ARM 上的 64 位变量对齐到 8，这意味着，例如，double 必须有一个内存地址，该地址是 8 的倍数。X86 内存可以更紧凑地排列。

### 提示

数据对齐在绝大多数情况下都不是问题，除非你显式依赖于数据位置（例如，如果你使用序列化）。即使你没有对齐问题，调整或优化结构布局以避免无用的填充并获得更好的性能总是有趣的。

因此，大部分时间，将代码从一个 ABI 移植到另一个 ABI 应该是相当简单的。在特定情况下，当需要特定的 CPU 特性或汇编代码时，提供备用方案。最后，注意，有些罕见的内存对齐问题可能会出现。

### 提示

正如我们在预构建 Boost 部分所看到的，每个 ABI 都有其自己的编译标志来优化编译。尽管 NDK 使用的默认 GCC 选项是适当的基础，但调整它们可以提高效率和性能。例如，你可以在 X86 平台上使用`-mtune=atom -mssse3 -mfpmath=sse`来优化发布代码。

# 总结

本章介绍了 NDK 的一个基本方面：可移植性。得益于构建工具链最近的改进，Android NDK 现在可以利用庞大的 C/C++生态系统。它开启了一个高效的生产环境，在这个环境中，代码可以与其他平台共享，旨在高效地创建新的尖端应用。

更具体地说，你学会了如何在 NDK makefile 系统中通过一个简单的标志来激活 STL。我们将 Box2D 库移植成了一个可以在 Android 项目中重复使用的 NDK 模块。你也了解了如何使用原始的 NDK 工具链预构建 Boost，而不需要任何封装。我们启用了异常和 RTTI，并深入探讨了如何编写模块 makefiles。

我们强调了使用 NDK 作为杠杆创建专业应用的路径。但不要期望所有的 C/C++库都能如此容易地移植。说到路径，我们几乎到了尽头。至少，这是关于 DroidBlaster 的最后章节。

接下来的章节也是最后一章，将介绍 RenderScript，这是一种先进的技术，可以最大限度地提高你的 Android 应用性能。
