# 安卓 NDK 初学者指南第二版（四）

> 原文：[`zh.annas-archive.org/md5/A3DD702F9D1A87E6BE95B1711A85BCDE`](https://zh.annas-archive.org/md5/A3DD702F9D1A87E6BE95B1711A85BCDE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：使用 OpenSL ES 播放声音

> *多媒体不仅仅是关于图形，还关乎声音和音乐。这一领域的应用程序在 Android 市场中是最受欢迎的。事实上，音乐一直是推动移动设备销售的重要动力，音乐爱好者始终是首选目标群体。这就是为什么像 Android 这样的操作系统可能没有一定的音乐才能就无法走得更远！嵌入式系统的开放声音库，通常称为 OpenSL ES，是声音领域的 OpenGL。尽管它相对底层，但它是所有与声音相关的任务，无论是输入还是输出，都是一流的 API。*

当谈论 Android 上的声音时，我们应该区分 Java 和本地世界。实际上，两边拥有完全不同的 API：一方面是**MediaPlayer**、**SoundPool**、**AudioTrack**和**JetPlayer**，另一方面是**OpenSL ES**。

+   MediaPlayer 是更高级且易于使用的。它不仅处理音乐，还处理视频。当只需要简单的文件播放时，它是首选的方法。

+   SoundPool 和 AudioTrack 更底层，播放声音时更接近低延迟。AudioTrack 虽然最灵活，但也最复杂。它允许在运行中手动修改声音缓冲区。

+   JetPlayer 更专注于 MIDI 文件的播放。这个 API 对于多媒体应用程序或游戏中的动态音乐合成可能很有趣（请参阅 Android SDK 提供的 JetBoy 示例）。

+   OpenSL ES 旨在为嵌入式系统提供跨平台的音频管理 API；换句话说，就是音频领域的 OpenGL ES。与 GLES 一样，其规范由 Khronos 组织领导。在 Android 上，OpenSL ES 实际上是在 AudioTrack API 之上实现的。

OpenSL ES 首次在 Android 2.3 Gingerbread 版本中发布，之前的版本（Android 2.2 及以下）并未提供。尽管 Java 中有大量的 API，但 OpenSL ES 是唯一在本地端提供的，且仅限于此。

然而，OpenSL ES 仍不够成熟。OpenSL 规范仍然没有得到完全支持，预计会有一些限制。此外，尽管 OpenSL 1.1 版本已经发布，但 Android 上实现的 OpenSL 规范仍然是 1.0.1 版本。因此，由于 OpenSL ES 的实现仍在不断发展，未来可能会出现一些重大变化。

只有系统编译时包含适当配置文件的设备才能通过 OpenSL ES 使用 3D 音频功能。实际上，当前的 OpenSL ES 规范提供了三种不同的配置文件，分别是针对不同类型设备的游戏、音乐和电话配置文件。在本书撰写之时，这些配置文件都不被支持。

然而，OpenSL ES 有其优点。首先，它可能更容易集成到本地应用程序的架构中，因为它本身是用 C/C++编写的。它不需要背负垃圾收集器。本地代码不是解释执行的，可以通过汇编代码进行深度优化。这些都是考虑使用它的众多原因之一。

本章是介绍在 Android NDK 上 OpenSL ES 的音乐功能。我们将发现如何进行以下操作：

+   在 Android 上初始化 OpenSL ES

+   播放背景音乐

+   使用声音缓冲队列播放声音

+   录制声音并播放

音频，特别是实时音频是一个高度技术化的课题。本章涵盖了将声音和音乐嵌入到您自己的应用程序中的基础知识。

# 初始化 OpenSL ES

如果不先初始化 OpenSL，它将不会非常有用。像往常一样，这一步需要一些样板代码。OpenSL 的繁琐并不会改善这种情况。让我们通过创建一个新的`SoundManager`类来包装与 OpenSL ES 相关的逻辑，以此开始本章内容。

### 注意

本书提供的最终项目名为`DroidBlaster_Part10`。

# 动手实践——创建 OpenSL ES 引擎和输出

让我们创建一个专门用于声音的新管理器：

1.  创建一个新文件`jni/SoundManager.hpp`。

    首先，包含 OpenSL ES 标准头文件`SLES/OpenSLES.h`。后两个定义了对象和方法，专门为 Android 创建。然后，创建`SoundManager`类以执行以下操作：

    +   使用`start()`方法初始化 OpenSL ES

    +   使用`stop()`方法停止声音并释放 OpenSL ES

    OpenSL ES 中有两种主要的伪对象结构（即包含应用于结构本身的函数指针的结构，例如具有此的 C++ 对象）：

    +   **对象**：这些由`SLObjectItf`表示，提供了一些常见方法来获取分配的资源和对对象接口的访问。这可以大致与 Java 中的对象相比较。

    +   **接口**：这些提供了访问对象特性的途径。一个对象可以有多个接口。根据主机设备的不同，某些接口可能可用或不可用。这些大致可以与 Java 中的接口相比较。

    在`SoundManager`中，声明两个`SLObjectItf`实例，一个用于 OpenSL ES 引擎，另一个用于扬声器。引擎可以通过`SLEngineItf`接口获得：

    ```java
    #ifndef _PACKT_SoundManager_HPP_
    #define _PACKT_SoundManager_HPP_

    #include "Types.hpp"

    #include <android_native_app_glue.h>
    #include <SLES/OpenSLES.h>

    class SoundManager {
    public:
        SoundManager(android_app* pApplication);

        status start();
        void stop();

    private:
        android_app* mApplication;

        SLObjectItf mEngineObj; SLEngineItf mEngine;
        SLObjectItf mOutputMixObj;
    };
    #endif
    ```

1.  在`jni/SoundManager.cpp`中实现`SoundManager`及其构造函数：

    ```java
    #include "Log.hpp"
    #include "Resource.hpp"
    #include "SoundManager.hpp"

    SoundManager::SoundManager(android_app* pApplication) :
        mApplication(pApplication),
        mEngineObj(NULL), mEngine(NULL),
        mOutputMixObj(NULL) {
        Log::info("Creating SoundManager.");
    }
    ...
    ```

1.  编写`start()`方法，该方法将创建一个 OpenSL 引擎对象和一个`Output Mix`对象。我们需要每个对象三个变量来进行初始化：

    +   每个对象需要支持接口的数量（`engineMixIIDCount`和`outputMixIIDCount`）。

    +   所有接口对象应支持的接口数组（`engineMixIIDs`和`outputMixIIDs`），例如引擎的`SL_IID_ENGINE`。

    +   一个布尔值数组，用于指示接口对程序是必需的还是可选的（`engineMixReqs`和`outputMixReqs`）。

        ```java
        ...
        status SoundManager::start() {
            Log::info("Starting SoundManager.");
            SLresult result;
            const SLuint32      engineMixIIDCount = 1;
            const SLInterfaceID engineMixIIDs[]   = {SL_IID_ENGINE};
            const SLboolean     engineMixReqs[]   = {SL_BOOLEAN_TRUE};
            const SLuint32      outputMixIIDCount = 0;
            const SLInterfaceID outputMixIIDs[]   = {};
            const SLboolean     outputMixReqs[]   = {};
            ...
        ```

1.  继续编写`start()`方法：

    +   使用`slCreateEngine()`方法初始化 OpenSL ES 引擎对象（即基本类型`SLObjectItf`）。当我们创建一个 OpenSL ES 对象时，我们必须指出将要使用的特定接口。在这里，我们请求`SL_IID_ENGINE`接口，它允许创建其他 OpenSL ES 对象。引擎是 OpenSL ES API 的核心对象。

    +   然后，在引擎对象上调用`Realize()`。任何 OpenSL ES 对象在使用前都需要*实现*以分配所需的内部资源。

    +   最后，获取`SLEngineItf`特定的接口。

    +   引擎接口使我们能够使用`CreateOutputMix()`方法实例化一个音频输出混合。在这里定义的音频输出混合将声音传送到默认扬声器。它是自主的（播放的声音会自动发送到扬声器），因此在这里无需请求任何特定接口。

        ```java
            ...
            // Creates OpenSL ES engine and dumps its capabilities.
            result = slCreateEngine(&mEngineObj, 0, NULL,
                engineMixIIDCount, engineMixIIDs, engineMixReqs);
            if (result != SL_RESULT_SUCCESS) goto ERROR;
            result = (*mEngineObj)->Realize(mEngineObj,SL_BOOLEAN_FALSE);
            if (result != SL_RESULT_SUCCESS) goto ERROR;
            result = (*mEngineObj)->GetInterface(mEngineObj, SL_IID_ENGINE,
                &mEngine);
            if (result != SL_RESULT_SUCCESS) goto ERROR;

            // Creates audio output.
            result = (*mEngine)->CreateOutputMix(mEngine, &mOutputMixObj,
                outputMixIIDCount, outputMixIIDs, outputMixReqs);
            result = (*mOutputMixObj)->Realize(mOutputMixObj,
                SL_BOOLEAN_FALSE);

            return STATUS_OK;

        ERROR:
            Log::error("Error while starting SoundManager");
            stop();
            return STATUS_KO;
        }
        ...
        ```

1.  编写`stop()`方法以销毁在`start()`中创建的内容：

    ```java
    ...
    void SoundManager::stop() {
        Log::info("Stopping SoundManager.");

        if (mOutputMixObj != NULL) {
            (*mOutputMixObj)->Destroy(mOutputMixObj);
            mOutputMixObj = NULL;
        }
        if (mEngineObj != NULL) {
            (*mEngineObj)->Destroy(mEngineObj);
            mEngineObj = NULL; mEngine = NULL;
        }
    }
    ```

1.  编辑`jni/DroidBlaster.hpp`并将我们的新`SoundManager`嵌入其中：

    ```java
    ...
    #include "Resource.hpp"
    #include "Ship.hpp"
    #include "SoundManager.hpp"
    #include "SpriteBatch.hpp"
    #include "StarField.hpp"
    ...

    class DroidBlaster : public ActivityHandler {
        ...
    private:
        TimeManager     mTimeManager;
        GraphicsManager mGraphicsManager;
        PhysicsManager  mPhysicsManager;
        SoundManager    mSoundManager;
        EventLoop mEventLoop;

        ...
    };
    #endif
    ```

1.  在`jni/DroidBlaster.cpp`中创建、启动和停止声音服务：

    ```java
    ...
    DroidBlaster::DroidBlaster(android_app* pApplication):
        mTimeManager(),
        mGraphicsManager(pApplication),
        mPhysicsManager(mTimeManager, mGraphicsManager),
        mSoundManager(pApplication),
        mEventLoop(pApplication, *this),
        ...
        mShip(pApplication, mTimeManager, mGraphicsManager) {
        ...
    }

    ...

    status DroidBlaster::onActivate() {
        Log::info("Activating DroidBlaster");

        if (mGraphicsManager.start() != STATUS_OK) return STATUS_KO;
        if (mSoundManager.start() != STATUS_OK) return STATUS_KO;

        mAsteroids.initialize();
        ...
    }

    void DroidBlaster::onDeactivate() {
        Log::info("Deactivating DroidBlaster");
        mGraphicsManager.stop();
        mSoundManager.stop();
    }
    ```

1.  最后，在`jni/Android.mk`文件中链接到`libOpenSLES.so`：

    ```java
    ...
    LS_CPP=$(subst $(1)/,,$(wildcard $(1)/*.cpp))
    LOCAL_MODULE := droidblaster
    LOCAL_SRC_FILES := $(call LS_CPP,$(LOCAL_PATH))
    LOCAL_LDLIBS := -landroid -llog -lEGL -lGLESv2 -lOpenSLES
    LOCAL_STATIC_LIBRARIES := android_native_app_glue png
    ...
    ```

## *刚才发生了什么？*

运行应用程序并检查是否有错误记录。我们初始化了 OpenSL ES 库，这使我们可以直接从本地代码访问高效的声音处理原语。当前的代码除了初始化之外，不执行任何操作。扬声器还不会发出声音。

OpenSL ES 的入口点是`SLEngineItf`，它主要是一个 OpenSL ES 对象工厂。它可以创建到输出设备（扬声器或其他设备）的通道，以及声音播放器或记录器（甚至更多！），我们将在本章后面看到。

`SLOutputMixItf`是表示音频输出的对象。通常，这将是设备扬声器或耳机。尽管 OpenSL ES 规范允许枚举可用的输出（以及输入）设备，但 NDK 实现还不足以获取或选择适当的设备（`SLAudioIODeviceCapabilitiesItf`，获取此类信息的官方接口）。因此，在处理输出和输入设备选择时（目前只需指定记录器的输入设备），最好坚持使用默认值，即在`SLES/OpenSLES.h`中定义的`SL_DEFAULTDEVICEID_AUDIOINPUT`和`SL_DEFAULTDEVICEID_AUDIOOUTPUT`。

当前 Android NDK 实现只允许每个应用程序有一个引擎（这不应成为问题），最多可以创建 32 个对象。但是请注意，任何对象的创建都可能失败，因为这取决于可用的系统资源。

## 关于 OpenSL ES 理念的更多内容

OpenSL ES 与其图形同伴 GLES 不同，部分原因是因为它没有悠久的历史负担。它是基于对象和接口的（或多或少）面向对象原则构建的。以下定义来自官方规范：

+   一个**对象**是对一组资源的抽象，这些资源被分配用于一组明确定义的任务，以及这些资源的状态。对象在创建时确定了其类型。对象类型决定了对象可以执行的任务集。这可以看作类似于 C++ 中的类。

+   一个**接口**是对一组相关功能的抽象，特定对象提供这些功能。接口包括一组方法，即接口的函数。接口也有一个类型，它决定了接口的确切方法集。我们可以将接口本身定义为其类型与相关对象的组合。

+   一个**接口 ID**用于识别接口类型。此标识符在源代码中使用，以引用接口类型。

OpenSL ES 对象的设置需要以下几个步骤：

1.  通过构建方法（通常属于引擎）实例化它。

1.  实现它以分配必要的资源。

1.  获取对象接口。一个基本对象只具有非常有限的操作集（`Realize()`、`Resume()`、`Destroy()`等）。接口提供了对真实对象功能的访问，并描述了可以在对象上执行的操作，例如，一个 `Play` 接口用于播放或暂停声音。

可以请求任何接口，但只有对象支持的接口才能成功获取。你不能为一个音频播放器获取录音接口，因为它会返回（有时很烦人！）`SL_RESULT_FEATURE_UNSUPPORTED`（错误代码 12）。从技术角度来说，OpenSL ES 接口是一个包含函数指针（由 OpenSL ES 实现初始化）的结构，带有一个自参数来模拟 C++ 中的对象和 `this`。

```java
struct SLObjectItf_ {
    SLresult (*Realize) (SLObjectItf self, SLboolean async);
    SLresult (*Resume) ( SLObjectItf self, SLboolean async);
    ...
}
```

在这里，`Realize()`、`Resume()` 等是可以应用于 `SLObjectItf` 对象的对象方法。接口的处理方式与此相同。

有关 OpenSL ES 可以提供哪些更详细信息，请参考 Khronos 网站上的规范[`www.khronos.org/opensles`](http://www.khronos.org/opensles)，以及 Android NDK 文档目录中的 OpenSL ES 文档。目前，Android 的实现并没有完全遵守该规范。因此，在发现只有规范中有限的一部分（特别是示例代码）在 Android 上有效时，请不要感到失望。

# 播放音乐文件

OpenSL ES 已初始化，但扬声器中传出的唯一声音却是沉默！那么，是否可以找到一段不错的**背景音乐**（**BGM**）并使用 Android NDK 原生播放呢？OpenSL ES 提供了读取如 MP3 文件等音乐文件的必要功能。

### 注意

本书提供的项目名为 `DroidBlaster_Part11`。

# 动手操作——播放背景音乐

让我们使用 OpenSL ES 打开并播放一个 MP3 音乐文件：

1.  MP3 文件通过 OpenSL 使用指向所选文件的 POSIX 文件描述符打开。通过定义新的结构 `ResourceDescriptor` 并添加新的方法 `descriptor()` 来改进本章前面创建的 `jni/ResourceManager.cpp`：

    ```java
    ...
    struct ResourceDescriptor {
     int32_t mDescriptor;
     off_t mStart;
     off_t mLength;
    };

    class Resource {
    public:
        ...
        status open();
        void close();
        status read(void* pBuffer, size_t pCount);

        ResourceDescriptor descriptor();

        bool operator==(const Resource& pOther);

    private:
        ...
    };
    #endif
    ```

1.  实现 `jni/ResourceManager.cpp`。当然，使用资产管理器 API 打开描述符并填充 `ResourceDescriptor` 结构：

    ```java
    ...
    ResourceDescriptor Resource::descriptor() {
        ResourceDescriptor lDescriptor = { -1, 0, 0 };
        AAsset* lAsset = AAssetManager_open(mAssetManager, mPath,
                                            AASSET_MODE_UNKNOWN);
        if (lAsset != NULL) {
            lDescriptor.mDescriptor = AAsset_openFileDescriptor(
                lAsset, &lDescriptor.mStart, &lDescriptor.mLength);
            AAsset_close(lAsset);
        }
        return lDescriptor;
    }
    ...
    ```

1.  回到 `jni/SoundManager.hpp` 并定义两个方法 `playBGM()` 和 `stopBGM()` 来播放/停止背景 MP3 文件。

    声明一个 OpenSL ES 对象用于音乐播放，以及以下接口：

    +   `SLPlayItf` 播放和停止音乐文件

    +   `SLSeekItf` 控制位置和循环

        ```java
        ...
        #include <android_native_app_glue.h>
        #include <SLES/OpenSLES.h>
        #include <SLES/OpenSLES_Android.h>

        class SoundManager {
        public:
            ...
            status start();
            void stop();

            status playBGM(Resource& pResource);
         void stopBGM();

        private:
            ...
            SLObjectItf mEngineObj; SLEngineItf mEngine;
            SLObjectItf mOutputMixObj;

            SLObjectItf mBGMPlayerObj; SLPlayItf mBGMPlayer;
         SLSeekItf mBGMPlayerSeek;
        };
        #endif
        ```

1.  开始实施 `jni/SoundManager.cpp`。

    包含 `Resource.hpp` 以获取资产文件描述符的访问权限。

    在构造函数中初始化新成员，并更新 `stop()` 以自动停止背景音乐（否则一些用户可能会不高兴！）：

    ```java
    #include "Log.hpp"
    #include "Resource.hpp"
    #include "SoundManager.hpp"

    SoundManager::SoundManager(android_app* pApplication) :
        mApplication(pApplication),
        mEngineObj(NULL), mEngine(NULL),
        mOutputMixObj(NULL),
        mBGMPlayerObj(NULL), mBGMPlayer(NULL), mBGMPlayerSeek(NULL) {
        Log::info("Creating SoundManager.");
    }

    ...

    void SoundManager::stop() {
        Log::info("Stopping SoundManager.");
        stopBGM();

        if (mOutputMixObj != NULL) {
            (*mOutputMixObj)->Destroy(mOutputMixObj);
            mOutputMixObj = NULL;
        }
        if (mEngineObj != NULL) {
            (*mEngineObj)->Destroy(mEngineObj);
            mEngineObj = NULL; mEngine = NULL;
        }
    }
    ...
    ```

1.  实现 `playBGM()` 以增强管理器的播放功能。

    首先，通过两个主要结构 `SLDataSource` 和 `SLDataSink` 描述我们的音频设置。第一个描述音频输入通道，第二个描述音频输出通道。

    在这里，我们将数据源配置为 MIME 源，以便从文件描述符自动检测文件类型。文件描述符当然是通过调用 `ResourceManager::descriptor()` 打开的。

    数据接收端（即目标通道）配置为本章第一部分初始化 OpenSL ES 引擎时创建的 `OutputMix` 对象（并指向默认音频输出，即扬声器或耳机）：

    ```java
    ...
    status SoundManager::playBGM(Resource& pResource) {
        SLresult result;
        Log::info("Opening BGM %s", pResource.getPath());

        ResourceDescriptor descriptor = pResource.descriptor();
        if (descriptor.mDescriptor < 0) {
            Log::info("Could not open BGM file");
            return STATUS_KO;
        }

        SLDataLocator_AndroidFD dataLocatorIn;
        dataLocatorIn.locatorType = SL_DATALOCATOR_ANDROIDFD;
        dataLocatorIn.fd          = descriptor.mDescriptor;
        dataLocatorIn.offset      = descriptor.mStart;
        dataLocatorIn.length      = descriptor.mLength;

        SLDataFormat_MIME dataFormat;
        dataFormat.formatType    = SL_DATAFORMAT_MIME;
        dataFormat.mimeType      = NULL;
        dataFormat.containerType = SL_CONTAINERTYPE_UNSPECIFIED;

        SLDataSource dataSource;
        dataSource.pLocator = &dataLocatorIn;
        dataSource.pFormat  = &dataFormat;

        SLDataLocator_OutputMix dataLocatorOut;
        dataLocatorOut.locatorType = SL_DATALOCATOR_OUTPUTMIX;
        dataLocatorOut.outputMix   = mOutputMixObj;

        SLDataSink dataSink;
        dataSink.pLocator = &dataLocatorOut;
        dataSink.pFormat  = NULL;
    ...
    ```

1.  然后，创建 OpenSL ES 音频播放器。与往常一样，首先通过引擎实例化 OpenSL ES 对象，然后实现它。两个接口 `SL_IID_PLAY` 和 `SL_IID_SEEK` 是必须的：

    ```java
    ...
        const SLuint32 bgmPlayerIIDCount = 2;
        const SLInterfaceID bgmPlayerIIDs[] =
            { SL_IID_PLAY, SL_IID_SEEK };
        const SLboolean bgmPlayerReqs[] =
            { SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE };

        result = (*mEngine)->CreateAudioPlayer(mEngine,
            &mBGMPlayerObj, &dataSource, &dataSink,
            bgmPlayerIIDCount, bgmPlayerIIDs, bgmPlayerReqs);
        if (result != SL_RESULT_SUCCESS) goto ERROR;
        result = (*mBGMPlayerObj)->Realize(mBGMPlayerObj,
            SL_BOOLEAN_FALSE);
        if (result != SL_RESULT_SUCCESS) goto ERROR;

        result = (*mBGMPlayerObj)->GetInterface(mBGMPlayerObj,
            SL_IID_PLAY, &mBGMPlayer);
        if (result != SL_RESULT_SUCCESS) goto ERROR;
        result = (*mBGMPlayerObj)->GetInterface(mBGMPlayerObj,
            SL_IID_SEEK, &mBGMPlayerSeek);
        if (result != SL_RESULT_SUCCESS) goto ERROR;
    ...
    ```

1.  最后，使用 `play` 和 `seek` 接口，将播放模式切换为循环模式（即音乐持续播放），从曲目开始（即 `0` 毫秒）直到其结束（`SL_TIME_UNKNOWN`），然后开始播放（使用 `SL_PLAYSTATE_PLAYING` 的 `SetPlayState()`）。

    ```java
    ...
        result = (*mBGMPlayerSeek)->SetLoop(mBGMPlayerSeek,
            SL_BOOLEAN_TRUE, 0, SL_TIME_UNKNOWN);
        if (result != SL_RESULT_SUCCESS) goto ERROR;
        result = (*mBGMPlayer)->SetPlayState(mBGMPlayer,
            SL_PLAYSTATE_PLAYING);
        if (result != SL_RESULT_SUCCESS) goto ERROR;

        return STATUS_OK;

    ERROR:
        Log::error("Error playing BGM");
        return STATUS_KO;
    }
    ...
    ```

1.  使用最后一个方法 `stopBGM()` 来停止并销毁播放器：

    ```java
    ...
    void SoundManager::stopBGM() {
        if (mBGMPlayer != NULL) {
            SLuint32 bgmPlayerState;
            (*mBGMPlayerObj)->GetState(mBGMPlayerObj,
                &bgmPlayerState);
            if (bgmPlayerState == SL_OBJECT_STATE_REALIZED) {
                (*mBGMPlayer)->SetPlayState(mBGMPlayer,
                    SL_PLAYSTATE_PAUSED);

                (*mBGMPlayerObj)->Destroy(mBGMPlayerObj);
                mBGMPlayerObj = NULL;
                mBGMPlayer = NULL; mBGMPlayerSeek = NULL;
            }
        }
    }
    ```

1.  在 `jni/DroidBlaster.hpp` 中添加一个指向音乐文件的资源：

    ```java
    ...
    class DroidBlaster : public ActivityHandler {
        ...
    private:
        ...
        Resource mAsteroidTexture;
        Resource mShipTexture;
        Resource mStarTexture;
        Resource mBGM;
        ...
    };
    #endif
    ```

1.  最后，在 `jni/DroidBlaster.cpp` 中，在启动 `SoundManager` 后立即开始播放音乐：

    ```java
    ...
    DroidBlaster::DroidBlaster(android_app* pApplication):
        ...
        mAsteroidTexture(pApplication, "droidblaster/asteroid.png"),
        mShipTexture(pApplication, "droidblaster/ship.png"),
        mStarTexture(pApplication, "droidblaster/star.png"),
        mBGM(pApplication, "droidblaster/bgm.mp3"),
        ...
        mSpriteBatch(mTimeManager, mGraphicsManager) {
        ...
    }
    ...
    status DroidBlaster::onActivate() {
        Log::info("Activating DroidBlaster");

        if (mGraphicsManager.start() != STATUS_OK) return STATUS_KO;
        if (mSoundManager.start() != STATUS_OK) return STATUS_KO;
        mSoundManager.playBGM(mBGM);

        mAsteroids.initialize();
        mShip.initialize();

        mTimeManager.reset();
        return STATUS_OK;
    }
    ...
    ```

将一个 MP3 文件复制到 `droidblaster` 的 `assets` 目录中，并将其命名为 `bgm.mp3`。

### 注意

BGM 文件随本书在 `DroidBlaster_Part11/assets` 目录中提供。

## *刚才发生了什么？*

我们已经了解到如何从 MP3 文件播放音乐片段。播放会一直循环，直到游戏终止。当使用 MIME 数据源时，文件类型会自动检测。目前在 Gingerbread 中支持多种格式，包括 Wave PCM、Wave alaw、Wave ulaw、MP3、Ogg Vorbis 等。目前不支持 MIDI 播放。更多信息请查看 `$ANDROID_NDK/docs/opensles/index.html`。

这里展示的示例代码是 OpenSL ES 工作方式的典型例子。OpenSL ES 引擎对象，基本上是一个对象工厂，创建一个`AudioPlayer`。在其原始状态下，这个对象做不了太多事情。首先，它需要实现以分配必要的资源。然而，这还不够。它需要检索正确的接口，如`SL_IID_PLAY`接口，以改变音频播放器的状态为播放/停止。然后，OpenSL API 才能有效使用。

这是一项相当大的工作，考虑到结果验证（因为任何调用都可能失败），这会使代码变得混乱。深入了解这个 API 可能需要比平时更多的时间，但一旦理解，这些概念就变得相当容易处理。

你可能会惊讶地发现，`startBGM()`和`stopBGM()`分别会重新创建和销毁音频播放器。原因是目前没有办法在不完全重新创建 OpenSL ES `AudioPlayer`对象的情况下更改 MIME 数据源。因此，尽管这种技术在播放长片段时是可行的，但不适合动态播放短声音。

# 播放声音

从 MIME 源播放 BGM 的技术非常实用，但遗憾的是，不够灵活。重新创建`AudioPlayer`对象是不必要的，每次访问资源文件在效率上也不好。

因此，在响应事件快速播放声音并动态生成它们时，我们需要使用声音缓冲队列。每个声音在内存缓冲区预加载或生成，并在请求播放时放入队列中。无需在运行时访问文件！

在当前 OpenSL ES Android 实现中，声音缓冲区可以包含 PCM 数据。**脉冲编码调制**（**PCM**）是一种专门用于表示数字声音的数据格式。这是 CD 和一些 Wave 文件中使用的格式。PCM 可以是单声道（所有扬声器上相同的声音）或立体声（如果可用，左右扬声器有不同的声音）。

PCM 没有压缩，在存储效率上不高（只需比较一张音乐 CD 和一个装满 MP3 的数据 CD）。然而，这种格式是无损的，提供最佳质量。质量取决于采样率：模拟声音以一系列的测量（即`sample`）数字形式表示声音信号。

以 44100 Hz（即每秒 44100 次测量）采样的声音样本质量更好，但也比以 16000 Hz 采样的声音占用更多空间。此外，每个测量可以表示得更精细或较不精细（即编码）。在当前 Android 实现中：

+   声音可以使用 8000 Hz、11025 Hz、12000 Hz、16000 Hz、22050 Hz、24000 Hz、32000 Hz、44100 Hz 或 48000 Hz 的采样率。

+   样本可以以 8 位无符号或 16 位有符号（更精细的精度）在小端（**little-endian**）或大端（**big-endian**）编码。

在以下分步教程中，我们将使用一个以 16 位小端编码的原始 PCM 文件。

### 注意

结果项目随本书提供，名为 `DroidBlaster_Part12`。

# 动手操作——创建并播放声音缓冲区队列

让我们使用 OpenSL ES 来播放存储在内存缓冲区中的爆炸声：

1.  再次更新 `jni/Resource.hpp`，以添加一个新方法 `getLength()`，它提供 `asset` 文件的字节大小：

    ```java
    ...
    class Resource {
    public:
        ...

        ResourceDescriptor descriptor();
        off_t getLength();
        ...
    };

    #endif
    ```

1.  在 `jni/Resource.cpp` 中实现这个方法：

    ```java
    ...
    off_t Resource::getLength() {
        return AAsset_getLength(mAsset);
    }
    ...
    ```

1.  创建 `jni/Sound.hpp` 来管理声音缓冲区。

    定义一个方法 `load()` 来加载一个 PCM 文件，以及 `unload()` 来释放它。

    同时，定义适当的获取器。将原始声音数据及其大小保存在缓冲区中。声音是从 `Resource` 加载的：

    ```java
    #ifndef _PACKT_SOUND_HPP_
    #define _PACKT_SOUND_HPP_

    class SoundManager;

    #include "Resource.hpp"
    #include "Types.hpp"

    class Sound {
    public:
        Sound(android_app* pApplication, Resource* pResource);

        const char* getPath();
        uint8_t* getBuffer() { return mBuffer; };
        off_t getLength() { return mLength; };

        status load();
        status unload();

    private:
        friend class SoundManager;

        Resource* mResource;
        uint8_t* mBuffer; off_t mLength;
    };
    #endif
    ```

1.  在 `jni/Sound.cpp` 中完成的声音加载实现非常简单；它创建一个与 PCM 文件大小相同的缓冲区，并将所有原始文件内容加载到其中：

    ```java
    #include "Log.hpp"
    #include "Sound.hpp"

    #include <SLES/OpenSLES.h>
    #include <SLES/OpenSLES_Android.h>

    Sound::Sound(android_app* pApplication, Resource* pResource) :
        mResource(pResource),
        mBuffer(NULL), mLength(0)
    {}

    const char* Sound::getPath() {
        return mResource->getPath();
    }

    status Sound::load() {
        Log::info("Loading sound %s", mResource->getPath());
        status result;

        // Opens sound file.
        if (mResource->open() != STATUS_OK) {
            goto ERROR;
        }

        // Reads sound file.
        mLength = mResource->getLength();
        mBuffer = new uint8_t[mLength];
        result = mResource->read(mBuffer, mLength);
        mResource->close();
        return STATUS_OK;

    ERROR:
        Log::error("Error while reading PCM sound.");
        return STATUS_KO;
    }

    status Sound::unload() {
        delete[] mBuffer;
        mBuffer = NULL; mLength = 0;

        return STATUS_OK;
    }
    ```

1.  创建 `jni/SoundQueue.hpp` 来封装播放器对象及其队列的创建。创建三个方法来：

    +   当应用程序启动时初始化 `queue` 以分配 OpenSL 资源

    +   完成队列以释放 OpenSL 资源

    +   播放预定义长度的声音缓冲区

    可以通过 `SLPlayItf` 和 `SLBufferQueueItf` 接口操作声音队列：

    ```java
    #ifndef _PACKT_SOUNDQUEUE_HPP_
    #define _PACKT_SOUNDQUEUE_HPP_

    #include "Sound.hpp"

    #include <SLES/OpenSLES.h>
    #include <SLES/OpenSLES_Android.h>

    class SoundQueue {
    public:
        SoundQueue();

        status initialize(SLEngineItf pEngine, SLObjectItf pOutputMixObj);
        void finalize();
        void playSound(Sound* pSound);

    private:
        SLObjectItf mPlayerObj; SLPlayItf mPlayer;
        SLBufferQueueItf mPlayerQueue;
    };
    #endif
    ```

1.  实现 `jni/SoundQueue.cpp`：

    ```java
    #include "Log.hpp"
    #include "SoundQueue.hpp"

    SoundQueue::SoundQueue() :
        mPlayerObj(NULL), mPlayer(NULL),
        mPlayerQueue() {
    }
    ...
    ```

1.  编写 `initialize()`，从 `SLDataSource` 和 `SLDataSink` 开始描述输入和输出通道。使用 `SLDataFormat_PCM` 数据格式（而不是 `SLDataFormat_MIME`），其中包含采样、编码和字节序信息。声音需要是单声道的（即，如果有左右扬声器，只有一个声音通道）。队列是使用特定于 Android 的扩展 `SLDataLocator_AndroidSimpleBufferQueue()` 创建的：

    ```java
    ...
    status SoundQueue::initialize(SLEngineItf pEngine,
            SLObjectItf pOutputMixObj) {
        Log::info("Starting sound player.");
        SLresult result;

        // Set-up sound audio source.
        SLDataLocator_AndroidSimpleBufferQueue dataLocatorIn;
        dataLocatorIn.locatorType =
            SL_DATALOCATOR_ANDROIDSIMPLEBUFFERQUEUE;
        // At most one buffer in the queue.
        dataLocatorIn.numBuffers = 1;

        SLDataFormat_PCM dataFormat;
        dataFormat.formatType = SL_DATAFORMAT_PCM;
        dataFormat.numChannels = 1; // Mono sound.
        dataFormat.samplesPerSec = SL_SAMPLINGRATE_44_1;
        dataFormat.bitsPerSample = SL_PCMSAMPLEFORMAT_FIXED_16;
        dataFormat.containerSize = SL_PCMSAMPLEFORMAT_FIXED_16;
        dataFormat.channelMask = SL_SPEAKER_FRONT_CENTER;
        dataFormat.endianness = SL_BYTEORDER_LITTLEENDIAN;

        SLDataSource dataSource;
        dataSource.pLocator = &dataLocatorIn;
        dataSource.pFormat = &dataFormat;

        SLDataLocator_OutputMix dataLocatorOut;
        dataLocatorOut.locatorType = SL_DATALOCATOR_OUTPUTMIX;
        dataLocatorOut.outputMix = pOutputMixObj;

        SLDataSink dataSink;
        dataSink.pLocator = &dataLocatorOut;
        dataSink.pFormat = NULL;
    ...
    ```

1.  然后，创建并实现声音播放器。我们将需要它的 `SL_IID_PLAY` 和 `SL_IID_BUFFERQUEUE` 接口，这得益于前一步配置的数据定位器：

    ```java
    ...
        const SLuint32 soundPlayerIIDCount = 2;
        const SLInterfaceID soundPlayerIIDs[] =
            { SL_IID_PLAY, SL_IID_BUFFERQUEUE };
        const SLboolean soundPlayerReqs[] =
            { SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE };

        result = (*pEngine)->CreateAudioPlayer(pEngine, &mPlayerObj,
            &dataSource, &dataSink, soundPlayerIIDCount,
            soundPlayerIIDs, soundPlayerReqs);
        if (result != SL_RESULT_SUCCESS) goto ERROR;
        result = (*mPlayerObj)->Realize(mPlayerObj, SL_BOOLEAN_FALSE);
        if (result != SL_RESULT_SUCCESS) goto ERROR;

        result = (*mPlayerObj)->GetInterface(mPlayerObj, SL_IID_PLAY,
            &mPlayer);
        if (result != SL_RESULT_SUCCESS) goto ERROR;
        result = (*mPlayerObj)->GetInterface(mPlayerObj,
            SL_IID_BUFFERQUEUE, &mPlayerQueue);
        if (result != SL_RESULT_SUCCESS) goto ERROR;
    ...
    ```

1.  最后，通过将队列设置为播放状态来启动队列。这实际上并不意味着会播放声音。队列是空的，所以不可能。但是，如果声音被入队，它将自动播放：

    ```java
    ...
        result = (*mPlayer)->SetPlayState(mPlayer,
            SL_PLAYSTATE_PLAYING);
        if (result != SL_RESULT_SUCCESS) goto ERROR;
        return STATUS_OK;

    ERROR:
        Log::error("Error while starting SoundQueue");
        return STATUS_KO;
    }
    ...
    ```

1.  当我们不再需要它们时，需要释放 OpenSL ES 对象：

    ```java
    ...
    void SoundQueue::finalize() {
        Log::info("Stopping SoundQueue.");

        if (mPlayerObj != NULL) {
            (*mPlayerObj)->Destroy(mPlayerObj);
            mPlayerObj = NULL; mPlayer = NULL; mPlayerQueue = NULL;
        }
    }
    ...
    ```

1.  最后，编写 `playSound()`，它首先停止任何正在播放的声音，然后将新的声音缓冲区入队以播放。这是立即播放声音的最简单策略：

    ```java
    ...
    void SoundQueue::playSound(Sound* pSound) {
        SLresult result;
        SLuint32 playerState;
        (*mPlayerObj)->GetState(mPlayerObj, &playerState);
        if (playerState == SL_OBJECT_STATE_REALIZED) {
            int16_t* buffer = (int16_t*) pSound->getBuffer();
            off_t length = pSound->getLength();

            // Removes any sound from the queue.
            result = (*mPlayerQueue)->Clear(mPlayerQueue);
            if (result != SL_RESULT_SUCCESS) goto ERROR;
            // Plays the new sound.
            result = (*mPlayerQueue)->Enqueue(mPlayerQueue, buffer,
                                              length);
            if (result != SL_RESULT_SUCCESS) goto ERROR;
        }
        return;

    ERROR:
        Log::error("Error trying to play sound");
    }
    ```

1.  打开 `jni/SoundManager.hpp` 并包含新创建的头文件。

    创建两个新的方法：

    +   `registerSound()` 以加载和管理一个新的声音缓冲区

    +   `playSound()` 将声音缓冲区发送到声音播放队列

    定义一个 `SoundQueue` 数组，以便最多可以同时播放四个声音。

    声音缓冲区存储在一个固定大小的 C++数组中：

    ```java
    ...
    #include "Sound.hpp"
    #include "SoundQueue.hpp"
    #include "Types.hpp"
    ...

    class SoundManager {
    public:
        SoundManager(android_app* pApplication);
        ~SoundManager();

        ...

        Sound* registerSound(Resource& pResource);
     void playSound(Sound* pSound);

    private:
        ...
        static const int32_t QUEUE_COUNT = 4;
     SoundQueue mSoundQueues[QUEUE_COUNT]; int32_t mCurrentQueue;
     Sound* mSounds[32]; int32_t mSoundCount;
    };
    #endif
    ```

1.  更新 `jni/SoundManager.cpp` 中的构造函数，并创建一个新的析构函数来释放资源：

    ```java
    ...
    SoundManager::SoundManager(android_app* pApplication) :
        mApplication(pApplication),
        mEngineObj(NULL), mEngine(NULL),
        mOutputMixObj(NULL),
        mBGMPlayerObj(NULL), mBGMPlayer(NULL), mBGMPlayerSeek(NULL),
        mSoundQueues(), mCurrentQueue(0),
     mSounds(), mSoundCount(0) {
        Log::info("Creating SoundManager.");
    }

    SoundManager::~SoundManager() {
     Log::info("Destroying SoundManager.");
     for (int32_t i = 0; i < mSoundCount; ++i) {
     delete mSounds[i];
     }
     mSoundCount = 0;
    }
    ...
    ```

1.  更新 `start()` 以初始化 `SoundQueue` 实例。然后，加载通过 `registerSound()` 注册的声音资源：

    ```java
    ...
    status SoundManager::start() {
        ...
        result = (*mEngine)->CreateOutputMix(mEngine, &mOutputMixObj,
            outputMixIIDCount, outputMixIIDs, outputMixReqs);
        result = (*mOutputMixObj)->Realize(mOutputMixObj,
            SL_BOOLEAN_FALSE);

        Log::info("Starting sound player.");
     for (int32_t i= 0; i < QUEUE_COUNT; ++i) {
     if (mSoundQueues[i].initialize(mEngine, mOutputMixObj)
     != STATUS_OK) goto ERROR;
        }

        for (int32_t i = 0; i < mSoundCount; ++i) {
     if (mSounds[i]->load() != STATUS_OK) goto ERROR;
        }
        return STATUS_OK;

    ERROR:
        ...
    }
    ...
    ```

1.  当应用程序停止时，完成`SoundQueue`实例的最终化，以释放 OpenSL ES 资源。同时，释放声音缓冲区：

    ```java
    ...
    void SoundManager::stop() {
        Log::info("Stopping SoundManager.");
        stopBGM();

        for (int32_t i= 0; i < QUEUE_COUNT; ++i) {
     mSoundQueues[i].finalize();
        }

        // Destroys audio output and engine.
        ...

        for (int32_t i = 0; i < mSoundCount; ++i) {
     mSounds[i]->unload();
        }
    }
    ...
    ```

1.  在`registerSound()`中保存并缓存声音：

    ```java
    ...
    Sound* SoundManager::registerSound(Resource& pResource) {
        for (int32_t i = 0; i < mSoundCount; ++i) {
            if (strcmp(pResource.getPath(), mSounds[i]->getPath()) == 0) {
                return mSounds[i];
            }
        }

        Sound* sound = new Sound(mApplication, &pResource);
        mSounds[mSoundCount++] = sound;
        return sound;
    }
    ...
    ```

1.  最后，编写`playSound()`，它将缓冲区发送到`SoundQueue`进行播放。使用简单的轮询策略来同时播放多个声音。将每个新的声音发送到队列中下一个可用的位置进行播放。显然，这种播放策略对于不同长度的声音来说并不是最优的：

    ```java
    ...
    void SoundManager::playSound(Sound* pSound) {
        int32_t currentQueue = ++mCurrentQueue;
        SoundQueue& soundQueue = mSoundQueues[currentQueue % QUEUE_COUNT];
        soundQueue.playSound(pSound);
    }
    ```

1.  当 DroidBlaster 飞船与行星碰撞时，我们将播放一个声音。由于碰撞尚未处理（有关使用**Box2D**处理碰撞的内容，请参见第十章），我们将在飞船初始化时简单地播放一个声音。

    为此，在`jni/Ship.hpp`中，在构造函数中获取对`SoundManager`的引用，并在`registerShip()`中播放一个碰撞声音缓冲区：

    ```java
    ...
    #include "GraphicsManager.hpp"
    #include "Sprite.hpp"
    #include "SoundManager.hpp"
    #include "Sound.hpp"

    class Ship {
    public:
        Ship(android_app* pApplication,
             GraphicsManager& pGraphicsManager,
             SoundManager& pSoundManager);

        void registerShip(Sprite* pGraphics, Sound* pCollisionSound);

        void initialize();

    private:
        GraphicsManager& mGraphicsManager;
        SoundManager& mSoundManager;

        Sprite* mGraphics;
        Sound* mCollisionSound;
    };
    #endif
    ```

1.  然后，在`jni/Ship.cpp`中，在存储了所有必要的引用之后，在初始化飞船时播放声音：

    ```java
    ...
    Ship::Ship(android_app* pApplication,
            GraphicsManager& pGraphicsManager,
            SoundManager& pSoundManager) :
      mGraphicsManager(pGraphicsManager),
      mGraphics(NULL),
      mSoundManager(pSoundManager),
     mCollisionSound(NULL) {
    }

    void Ship::registerShip(Sprite* pGraphics, Sound* pCollisionSound) {
        mGraphics = pGraphics;
        mCollisionSound = pCollisionSound;
    }

    void Ship::initialize() {
        mGraphics->location.x = INITAL_X
                * mGraphicsManager.getRenderWidth();
        mGraphics->location.y = INITAL_Y
                * mGraphicsManager.getRenderHeight();
        mSoundManager.playSound(mCollisionSound);
    }
    ```

1.  在`jni/DroidBlaster.hpp`中，定义一个对包含碰撞声音的文件的引用：

    ```java
    ...
    class DroidBlaster : public ActivityHandler {
        ...

    private:
        ...
        Resource mAsteroidTexture;
        Resource mShipTexture;
        Resource mStarTexture;
        Resource mBGM;
        Resource mCollisionSound;

        ...
    };
    #endif
    ```

1.  最后，在`jni/DroidBlaster.cpp`中，注册新的声音并将其传递给`Ship`类：

    ```java
    #include "DroidBlaster.hpp"
    #include "Sound.hpp"
    #include "Log.hpp"
    ...
    DroidBlaster::DroidBlaster(android_app* pApplication):
        ...
        mAsteroidTexture(pApplication, "droidblaster/asteroid.png"),
        mShipTexture(pApplication, "droidblaster/ship.png"),
        mStarTexture(pApplication, "droidblaster/star.png"),
        mBGM(pApplication, "droidblaster/bgm.mp3"),
        mCollisionSound(pApplication, "droidblaster/collision.pcm"),

        mAsteroids(pApplication, mTimeManager, mGraphicsManager,
                mPhysicsManager),
        mShip(pApplication, mGraphicsManager, mSoundManager),
        mStarField(pApplication, mTimeManager, mGraphicsManager,
                STAR_COUNT, mStarTexture),
        mSpriteBatch(mTimeManager, mGraphicsManager) {
        Log::info("Creating DroidBlaster");

        Sprite* shipGraphics = mSpriteBatch.registerSprite(mShipTexture,
                SHIP_SIZE, SHIP_SIZE);
        shipGraphics->setAnimation(SHIP_FRAME_1, SHIP_FRAME_COUNT,
                SHIP_ANIM_SPEED, true);
        Sound* collisionSound =
     mSoundManager.registerSound(mCollisionSound);
     mShip.registerShip(shipGraphics, collisionSound);
        ...
    }
    ...
    ```

## *刚才发生了什么？*

我们已经了解了如何在缓冲区中预加载声音，并在需要时播放它们。这种声音播放技术与之前看到的背景音乐（BGM）技术的不同之处在于使用了缓冲队列。缓冲队列正是其名称所揭示的：一个**先进先出**（**FIFO**）的声音缓冲集合，一个接一个地播放。当前一个缓冲区播放完毕后，缓冲区会被加入队列以便播放。

缓冲区可以被回收利用。这种技术与流式文件结合使用时至关重要：两个或多个缓冲区被填充并发送到队列中。当第一个缓冲区播放完毕后，第二个缓冲区开始播放，同时第一个缓冲区被填充新数据。尽可能快地，在队列空之前将第一个缓冲区加入队列。这个过程会一直重复，直到播放结束。此外，缓冲区是原始数据，因此可以在飞行中进行处理或过滤。

在本教程中，因为`DroidBlaster`不需要同时播放多个声音，也没有流式播放的需求，所以缓冲队列的大小被简单地设置为一个缓冲区（第 7 步，`dataLocatorIn.numBuffers = 1;`）。此外，我们希望新的声音能够抢占旧的声音，这就解释了为什么队列会被系统地清空。当然，你的 OpenSL ES 架构应根据你的需求来调整。如果需要同时播放多个声音，应该创建多个音频播放器（以及相应的缓冲队列）。

声音缓冲区以 PCM 格式存储，这种格式不能自描述其内部格式。采样率、编码和其他格式信息需要在应用程序代码中选定。尽管这对于大多数情况是合适的，但如果不够灵活，解决方案可以是加载一个 Wave 文件，其中包含所有必要的头信息。

### 提示

一个很好的开源工具，用于过滤和序列化声音是**Audacity**。它允许改变采样率以及修改声道（单声道/立体声）。Audacity 能够以原始 PCM 数据的形式导入和导出声音。

## 使用回调来检测声音队列事件

可以使用回调来检测声音是否播放完毕。通过在队列上调用`RegisterCallback()`方法可以设置一个回调（但其他类型的对象也可以注册回调）。例如，回调可以接收这个，也就是一个`SoundManager`自身的引用，以便在需要时允许使用任何上下文信息进行处理。尽管这是可选的，但设置一个事件掩码可以确保仅在触发`SL_PLAYEVENT_HEADATEND`（播放器已播放完缓冲区）事件时调用回调。`OpenSLES.h`中还有其他一些播放事件可用：

```java
...
void callback_sound(SLBufferQueueItf pBufferQueue, void *pContext) {
 // Context can be casted back to the original type.
 SoundService& lService = *(SoundService*) pContext;
    ...
    Log::info("Ended playing sound.");
}
...
status SoundService::start() {
    ...
    result = (*mEngine)->CreateOutputMix(mEngine, &mOutputMixObj,
        outputMixIIDCount, outputMixIIDs, outputMixReqs);
    result = (*mOutputMixObj)->Realize(mOutputMixObj,
        SL_BOOLEAN_FALSE);

    // Registers a callback called when sound is finished.
 result = (*mPlayerQueue)->RegisterCallback(mPlayerQueue,
 callback_sound, this);
 if (result != SL_RESULT_SUCCESS) goto ERROR;
 result = (*mPlayer)->SetCallbackEventsMask(mPlayer,
 SL_PLAYEVENT_HEADATEND);
 if (result != SL_RESULT_SUCCESS) goto ERROR;

    Log::info("Starting sound player.");
    ...
}
...
```

现在，当一个缓冲区播放完毕时，会记录一条消息。可以执行诸如入队新缓冲区（例如处理流式传输）的操作。

## 安卓上的低延迟

回调类似于系统中断或应用事件，它们的处理必须是短而快的。如果需要进行高级处理，不应该在回调内部执行，而应该在另一个线程上执行——原生线程是完美的候选者。

实际上，回调是在一个系统线程上触发的，这个线程与请求 OpenSL ES 服务的线程不同（在我们的案例中，就是`NativeActivity`原生线程）。当然，涉及到线程时，就会遇到从回调中访问你自己的变量时的线程安全问题。虽然使用互斥锁保护代码很诱人，但这并不是处理实时音频的最佳方式。它们对调度的效果（例如**优先级反转**问题）可能会导致播放过程中的故障。

因此，建议使用线程安全的技术，比如使用无锁队列与回调进行通信。无锁技术可以通过使用 GCC 内置的原子函数来实现，例如`__sync_fetch_and_add()`（它不需要包含任何头文件）。关于使用 Android NDK 进行原子操作的信息，可以查看`${ANDROID_NDK}/docs/ANDROID-ATOMICS.html`。

尽管编写正确的无锁代码对于在安卓上实现低延迟至关重要，但另一个需要考虑的重要点是，并非所有的安卓平台和设备都适合这样做！实际上，低延迟支持在安卓系统中出现得相当晚，从操作系统版本 4.1/4.2 开始提供。如果你需要低延迟，可以使用以下 Java 代码片段来检查它的支持情况：

```java
import android.content.pm.PackageManager;
...
PackageManager pm = getContext().getPackageManager();
boolean claimsFeature = pm.hasSystemFeature(PackageManager.FEATURE_AUDIO_LOW_LATENCY);
```

然而，请注意！许多设备即使安装了最新的系统版本，由于驱动问题也无法实现低延迟。

当你确定目标平台支持低延迟后，要注意使用适当的采样率和缓冲区大小。实际上，当使用最佳配置时，Android 音频系统提供了一个“快速路径”，不进行任何重采样。为此，从 API 级别 17 或更高版本开始，在 Java 端使用`android.media.AudioManager.getProperty()`：

```java
import android.media.AudioManager;
...
AudioManager am = (AudioManager) getSystemService(Context.AUDIO_SERVICE);
String sampleRateStr =
        am.getProperty(AudioManager.PROPERTY_OUTPUT_SAMPLE_RATE);
int sampleRate = !TextUtils.isEmpty(sampleRateStr) ?
                                Integer.parseInt(sampleRateStr) : -1;
String framesPerBufferStr =
        am.getProperty(AudioManager.PROPERTY_OUTPUT_FRAMES_PER_BUFFER);
int framesPerBuffer = !TextUtils.isEmpty(framesPerBufferStr) ?
                           Integer.parseInt(framesPerBufferStr) : -1;
```

若要了解更多关于这个主题的信息，请查看[高性能音频](https://developers.google.com/events/io/sessions/325993827)的演讲。

# 录制声音

Android 设备都是关于交互的。交互不仅来自触摸和传感器，还来自音频输入。大多数 Android 设备提供了麦克风来录制声音，并允许应用程序如 Android 桌面搜索提供语音功能来记录查询。

如果声音输入可用，OpenSL ES 提供了对录音机的本地访问。它与缓冲队列协作，从输入设备获取数据并填充输出声音缓冲区。这个设置与`AudioPlayer`的处理非常相似，除了数据源和数据接收器位置互换。

## 实战英雄——录音与播放声音

为了了解录音是如何工作的，可以在应用程序启动时录音，并在录音完成后播放。将`SoundManager`转变为录音器可以通过四个步骤完成：

1.  使用`startSoundRecorder()`状态来初始化声音录音机。在`startSoundPlayer()`之后立即调用它。

1.  使用`void recordSound()`，开始使用设备麦克风录制声音缓冲区。在应用程序在`onActivate()`激活时调用此方法，例如背景音乐播放开始后。

1.  一个新的回调静态`void callback_recorder(SLAndroidSimpleBufferQueueItf, void*)`用来通知录音队列事件。你需要注册这个回调，以便在录音事件发生时触发它。在这里，我们关心的是缓冲区满的事件，即声音录制完成时。

1.  `void playRecordedSound()`用于录制声音后播放。在例如`callback_recorder()`中声音录制完成时播放它。这从技术上来说并不完全正确，因为可能存在竞态条件，但作为示例是足够的。

    ### 注意

    本书提供的成品项目名为`DroidBlaster_PartRecorder`。

在进一步操作之前，录音需要特定的 Android 权限，当然还需要一个合适的 Android 设备（你不会希望应用程序在背后记录你的秘密对话吧！）。这个授权需要在 Android 清单中请求：

```java
<?xml version="1.0" encoding="utf-8"?>
<manifest 
    package="com.packtpub.droidblaster2d" android:versionCode="1"
    android:versionName="1.0">
    ...
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
</manifest>
```

## 创建并发布录音器

声音通常是通过从 OpenSL ES 引擎创建的录音对象进行录音的。录音器提供了两个有趣的接口：

+   `SLRecordItf`：这个接口用于开始和停止录制。其标识符为`SL_IID_RECORD`。

+   `SLAndroidSImpleBufferQueueItf`：这个接口管理录音机的声音队列。这是由 NDK 提供的 Android 扩展，因为当前的 OpenSL ES 1.0.1 规范不支持录制到队列中。其标识符为`SL_IID_ANDROIDSIMPLEBUFFERQUEUE`：

    ```java
    const SLuint32 soundRecorderIIDCount = 2;
    const SLInterfaceID soundRecorderIIDs[] =
            { SL_IID_RECORD, SL_IID_ANDROIDSIMPLEBUFFERQUEUE };
    const SLboolean soundRecorderReqs[] =
            { SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE };
    SLObjectItf mRecorderObj;
    (*mEngine)->CreateAudioRecorder(mEngine, &mRecorderObj,
            &dataSource, &dataSink,
            soundRecorderIIDCount, soundRecorderIIDs, soundRecorderReqs);
    ```

要创建录音机，你需要声明你的音频源和接收器，类似于以下内容。数据源不是声音，而是默认的录音设备（如麦克风）。另一方面，数据接收器（即输出通道）不是扬声器，而是 PCM 格式的声音缓冲区（具有请求的采样率、编码和字节序）。由于标准 OpenSL 缓冲队列无法工作，因此必须使用 Android 扩展`SLDataLocator_AndroidSimpleBufferQueue`来处理录音机：

```java
SLDataLocator_AndroidSimpleBufferQueue dataLocatorOut;
dataLocatorOut.locatorType =
    SL_DATALOCATOR_ANDROIDSIMPLEBUFFERQUEUE;
dataLocatorOut.numBuffers = 1;

SLDataFormat_PCM dataFormat;
dataFormat.formatType = SL_DATAFORMAT_PCM;
dataFormat.numChannels = 1;
dataFormat.samplesPerSec = SL_SAMPLINGRATE_44_1;
dataFormat.bitsPerSample = SL_PCMSAMPLEFORMAT_FIXED_16;
dataFormat.containerSize = SL_PCMSAMPLEFORMAT_FIXED_16;
dataFormat.channelMask = SL_SPEAKER_FRONT_CENTER;
dataFormat.endianness = SL_BYTEORDER_LITTLEENDIAN;

SLDataSink dataSink;
dataSink.pLocator = &dataLocatorOut;
dataSink.pFormat = &dataFormat;

SLDataLocator_IODevice dataLocatorIn;
dataLocatorIn.locatorType = SL_DATALOCATOR_IODEVICE;
dataLocatorIn.deviceType = SL_IODEVICE_AUDIOINPUT;
dataLocatorIn.deviceID = SL_DEFAULTDEVICEID_AUDIOINPUT;
dataLocatorIn.device = NULL;

SLDataSource dataSource;
dataSource.pLocator = &dataLocatorIn;
dataSource.pFormat = NULL;
```

当应用程序结束时，别忘了释放录音机对象，就像其他所有 OpenSL 对象一样。

## 录制声音

要录制声音，你需要根据录制时长创建一个适当大小的声音缓冲区。你可以调整`Sound`类，以允许创建给定大小的空缓冲区。大小取决于采样率。例如，对于`2`秒的录制，采样率为`44100` Hz 和`16`位质量，声音缓冲区大小如下所示：

```java
recordSize   = 2 * 44100 * sizeof(int16_t);
recordBuffer = new int16_t[mRecordSize];
```

在`recordSound()`中，首先通过`SLRecordItf`停止录音机，以确保它没有在录制。然后，清除队列以确保你的录音缓冲区立即使用。最后，你可以排队一个新的缓冲区并开始录制：

```java
(*mRecorder)->SetRecordState(mRecorder, SL_RECORDSTATE_STOPPED);
(*mRecorderQueue)->Clear(mRecorderQueue);
(*mRecorderQueue)->Enqueue(mRecorderQueue, recordBuffer,
    recordSize * sizeof(int16_t));
(*mRecorder)->SetRecordState(mRecorder,SL_RECORDSTATE_RECORDING);
```

### 提示

完全可以排队新的声音缓冲区，以便处理完当前录制的内容。这允许创建连续的录制链，换句话说，就是录制流。排队的声音只有在之前的缓冲区填满后才会被处理。

## 录制回调

你最终需要知道你的声音缓冲区何时完成录制。为此，注册一个在录音事件发生时触发的回调（例如，一个缓冲区已满）。应设置一个事件掩码，以确保仅在缓冲区已满时调用回调（`SL_RECORDEVENT_BUFFER_FULL`）。在`OpenSLES.h`中有其他一些可用，但并非所有都受支持（如`SL_RECORDEVENT_HEADATLIMIT`等）：

```java
(*mRecorderQueue)->RegisterCallback(mRecorderQueue,
                                    callback_recorder, this);
(*mRecorder)->SetCallbackEventMask(mRecorder,
                                   SL_RECORDEVENT_BUFFER_FULL);
```

最后，当`callback_recorder()`被触发时，停止录制并通过`playRecordedSound()`播放已录制的缓冲区。录制的缓冲区需要像前一部分一样排入音频播放器的队列中以便播放。为了简化，你可以使用特定的`SoundQueue`来播放声音。

# 总结

总结一下，在本章中我们了解了如何在 Android 上初始化 OpenSL ES。引擎对象是管理所有 OpenSL 对象的主要入口点。OpenSL 中的对象遵循特定的生命周期：创建、实现和销毁。然后，我们学习了如何从编码文件播放背景音乐以及使用声音缓冲队列在内存中播放声音。最后，我们发现了如何以线程安全和非阻塞的方式录制并播放声音。

你是否更喜欢 OpenSL ES 而不是 Java API？如果你只需要一个高级别的好用 API，那么 Java API 可能更适合你的需求。如果你需要更精细的播放或录音控制，低级 Java API 和 OpenSL ES 之间没有显著差异。在这种情况下，选择应该是基于架构的。如果你的代码主要是 Java，那么你或许应该选择 Java。

如果你需要复用现有的与声音相关的库，优化性能，或者执行高强度计算，比如实时声音过滤，OpenSL ES 可能是正确的选择。OpenSL ES 也是实现低延迟的方式，尽管 Android 在这方面还没有完全达到（存在碎片化，特定设备问题等）。至少，这个详尽的 API 很可能会提供最佳性能。它没有垃圾收集的开销，并且在本地代码中鼓励进行积极的优化。

无论你做出什么选择，要知道 Android NDK 还有更多内容可以提供。在处理了第六章*使用 OpenGL ES 渲染图形*和第七章*使用 OpenSL ES 播放声音*之后，下一章将介绍如何本地处理输入：键盘、触摸和传感器。


# 第八章：处理输入设备和传感器

> *Android 的一切都是关于互动。诚然，这意味着通过图形、音频、振动等方式进行反馈。但没有输入就没有互动！当今智能手机的成功源于它们多样化和现代的输入方式：触摸屏、键盘、鼠标、GPS、加速度计、光线检测器、声音记录器等等。正确处理和结合它们是丰富您的应用程序并使其成功的关键。*

尽管 Android 处理许多输入外设，但 Android NDK 在其支持上长期以来非常有限（甚至可以说是最少），直到 R5 版本的发布！我们现在可以通过原生 API 直接访问。可用的设备实例包括：

+   键盘，可以是物理键盘（带有滑出式键盘）或虚拟键盘（在屏幕上显示）

+   方向键（上、下、左、右和动作按钮），通常简称为 D-Pad。

+   轨迹球，包括光学轨迹球

+   触摸屏，使现代智能手机成功

+   鼠标或触摸板（自 NDK R5 起，但仅在 Honeycomb 设备上可用）

我们还可以访问以下硬件传感器：

+   加速度计，测量施加在设备上的线性加速度。

+   陀螺仪，测量角速度。它通常与磁力计结合使用，以准确快速地计算方向。陀螺仪是最近引入的，并且大多数设备上还不可用。

+   磁力计，提供环境磁场，从而得出基本方向。

+   光传感器，例如，自动适应屏幕亮度。

+   近距离传感器，例如，在通话期间检测耳朵的距离。

除了硬件传感器外，Gingerbread 版本还引入了“软件传感器”。这些传感器源自硬件传感器的数据：

+   重力传感器，测量重力的方向和大小

+   线性加速度传感器，测量设备“移动”时排除重力的部分

+   旋转矢量，表示设备在空间中的方向

重力传感器和线性加速度传感器源自加速度计。另一方面，旋转矢量由磁力计和加速度计派生。由于这些传感器通常需要计算一段时间，因此它们在获取最新值时通常会有轻微的延迟。

为了更深入地了解输入设备和传感器，本章将介绍如何：

+   处理屏幕触摸

+   检测键盘、方向键和轨迹球事件

+   将加速度计传感器转变为游戏手柄

# 与触摸事件互动

当今智能手机最具标志性的创新是触摸屏，它已经取代了现已过时的鼠标。正如其名，触摸屏可以检测手指或手写笔在设备表面的触摸。根据屏幕的质量，可以处理多个触摸（在 Android 中也称为光标），从而增加了互动的可能性。

让我们从在 `DroidBlaster` 中处理触摸事件开始本章的内容。为了简化示例，我们只处理单一的“触摸”。目标是使飞船向触摸的方向移动。触摸越远，飞船移动越快。超过预定义的范围 `TOUCH_MAX_RANGE`，飞船的速度将达到其速度极限，如下图所示：

![与触摸事件交互](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645OS_08_01.jpg)

### 注意

本书提供的项目名为 `DroidBlaster_Part13`。

# 动手实践——处理触摸事件

让我们在 `DroidBlaster` 中拦截触摸事件：

1.  正如在 第五章《编写一个完全原生的应用程序》中创建 `ActivityHandler` 来处理应用程序事件一样，创建 `jni/InputHandler.hpp` 来处理输入事件。输入 API 在 `android/input.h` 中声明。创建 `onTouchEvent()` 来处理触摸事件。这些事件被封装在 `AInputEvent` 结构中。其他输入外设将在本章后面描述：

    ```java
    #ifndef _PACKT_INPUTHANDLER_HPP_
    #define _PACKT_INPUTHANDLER_HPP_

    #include <android/input.h>

    class InputHandler {
    public:
        virtual ~InputHandler() {};

        virtual bool onTouchEvent(AInputEvent* pEvent) = 0;
    };
    #endif
    ```

1.  修改 `jni/EventLoop.hpp` 头文件，包含并处理 `InputHandler` 实例。

    类似于活动事件，定义一个内部方法 `processInputEvent()`，该方法由静态回调 `callback_input()` 触发：

    ```java
    ...
    #include "ActivityHandler.hpp"
    #include "InputHandler.hpp"

    #include <android_native_app_glue.h>

    class EventLoop {
    public:
    EventLoop(android_app* pApplication,
                ActivityHandler& pActivityHandler,
                InputHandler& pInputHandler);
        ...
    private:
        ...
        void processAppEvent(int32_t pCommand);
        int32_t processInputEvent(AInputEvent* pEvent);

        static void callback_appEvent(android_app* pApplication,
                int32_t pCommand);
        static int32_t callback_input(android_app* pApplication,
     AInputEvent* pEvent);

        ...
        ActivityHandler& mActivityHandler;
        InputHandler& mInputHandler;
    };
    #endif
    ```

1.  我们需要在 `jni/EventLoop.cpp` 源文件中处理输入事件，并通知相关的 `InputHandler`。

    首先，将 Android 输入队列连接到 `callback_input()`。`EventLoop` 本身（即 `this`）通过 `android_app` 结构的 `userData` 成员匿名传递。这样，回调能够将输入处理委托回我们自己的对象，即 `processInputEvent()`。

    ```java
    ...
    EventLoop::EventLoop(android_app* pApplication,
        ActivityHandler& pActivityHandler, InputHandler& pInputHandler):
            mApplication(pApplication),
            mActivityHandler(pActivityHandler),
            mEnabled(false), mQuit(false),
            mInputHandler(pInputHandler) {
        mApplication->userData = this;
        mApplication->onAppCmd = callback_appEvent;
     mApplication->onInputEvent = callback_input;
    }

    ...

    int32_t EventLoop::callback_input(android_app* pApplication,
     AInputEvent* pEvent) {
     EventLoop& eventLoop = *(EventLoop*) pApplication->userData;
     return eventLoop.processInputEvent(pEvent);
    }
    ...
    ```

1.  触摸屏事件属于 `MotionEvent` 类型（与按键事件相对）。通过 Android 原生输入 API（此处为 `AinputEvent_getSource()`），可以根据它们的来源（`AINPUT_SOURCE_TOUCHSCREEN`）来区分它们。

    ### 注意

    请注意 `callback_input()` 以及扩展的 `processInputEvent()` 返回一个整数值（本质上是一个布尔值）。这个值表示输入事件（例如，按下的按钮）已经被应用程序处理，不需要系统进一步处理。例如，当按下返回按钮时返回 `1`，以停止事件处理，防止活动被终止。

    ```java
    ...
    int32_t EventLoop::processInputEvent(AInputEvent* pEvent) {
        if (!mEnabled) return 0;

        int32_t eventType = AInputEvent_getType(pEvent);
        switch (eventType) {
        case AINPUT_EVENT_TYPE_MOTION:
            switch (AInputEvent_getSource(pEvent)) {
            case AINPUT_SOURCE_TOUCHSCREEN:
                return mInputHandler.onTouchEvent(pEvent);
                break;
            }
            break;
        }
        return 0;
    }
    ```

1.  创建 `jni/InputManager.hpp` 以处理触摸事件并实现我们的新 `InputHandler` 接口。

    按如下方式定义方法：

    +   `start()` 执行必要的初始化。

    +   `onTouchEvent()` 在触发新事件时更新管理器状态。

    +   `getDirectionX()` 和 `getDirectionY()` 指示飞船的方向。

    +   `setRefPoint()` 指的是飞船的位置。实际上，方向被定义为触摸点和飞船位置（即参考点）之间的向量。

    同时，声明必要的成员变量，尤其是`mScaleFactor`，它包含了从屏幕坐标到游戏坐标的正确比例（记住我们使用的是固定大小）。

    ```java
    #ifndef _PACKT_INPUTMANAGER_HPP_
    #define _PACKT_INPUTMANAGER_HPP_

    #include "GraphicsManager.hpp"
    #include "InputHandler.hpp"
    #include "Types.hpp"

    #include <android_native_app_glue.h>

    class InputManager : public InputHandler {
    public:
        InputManager(android_app* pApplication,
                 GraphicsManager& pGraphicsManager);

        float getDirectionX() { return mDirectionX; };
        float getDirectionY() { return mDirectionY; };
        void setRefPoint(Location* pRefPoint) { mRefPoint = pRefPoint; };

        void start();

    protected:
        bool onTouchEvent(AInputEvent* pEvent);

    private:
        android_app* mApplication;
        GraphicsManager& mGraphicsManager;

        // Input values.
        float mScaleFactor;
        float mDirectionX, mDirectionY;
        // Reference point to evaluate touch distance.
        Location* mRefPoint;
    };
    #endif
    ```

1.  创建`jni/InputManager.cpp`，从构造函数开始：

    ```java
    #include "InputManager.hpp"
    #include "Log.hpp"

    #include <android_native_app_glue.h>
    #include <cmath>

    InputManager::InputManager(android_app* pApplication,
            GraphicsManager& pGraphicsManager) :
        mApplication(pApplication), mGraphicsManager(pGraphicsManager),
        mDirectionX(0.0f), mDirectionY(0.0f),
        mRefPoint(NULL) {
    }
    ...
    ```

1.  编写`start()`方法以清除成员变量并计算缩放因子。这个缩放因子是必要的，因为在第六章，*使用 OpenGL ES 渲染图形*中提到，我们需要将输入事件提供的屏幕坐标（这取决于设备）转换为游戏坐标：

    ```java
    ...
    void InputManager::start() {
        Log::info("Starting InputManager.");
        mDirectionX = 0.0f, mDirectionY = 0.0f;
        mScaleFactor = float(mGraphicsManager.getRenderWidth())
                           / float(mGraphicsManager.getScreenWidth());
    }
    ...
    ```

1.  有效的事件处理在`onTouchEvent()`中实现。根据参考点与触摸点之间的距离，计算出水平方向和垂直方向。这个距离通过`TOUCH_MAX_RANGE`限制在一个任意的`65`单位范围内。因此，当参考点到触摸点的距离超出`TOUCH_MAX_RANGE`像素时，飞船将达到最大速度。

    当你移动手指时，通过`AMotionEvent_getX()`和`AMotionEvent_getY()`获取触摸坐标。当不再检测到触摸时，方向向量重置为`0`：

    ```java
    ...
    bool InputManager::onTouchEvent(AInputEvent* pEvent) {
        static const float TOUCH_MAX_RANGE = 65.0f; // In game units.

        if (mRefPoint != NULL) {
            if (AMotionEvent_getAction(pEvent)
                            == AMOTION_EVENT_ACTION_MOVE) {
                float x = AMotionEvent_getX(pEvent, 0) * mScaleFactor;
                float y = (float(mGraphicsManager.getScreenHeight())
                         - AMotionEvent_getY(pEvent, 0)) * mScaleFactor;
                // Needs a conversion to proper coordinates
                // (origin at bottom/left). Only moveY needs it.
                float moveX = x - mRefPoint->x;
                float moveY = y - mRefPoint->y;
                float moveRange = sqrt((moveX * moveX) + (moveY * moveY));

                if (moveRange > TOUCH_MAX_RANGE) {
                    float cropFactor = TOUCH_MAX_RANGE / moveRange;
                    moveX *= cropFactor; moveY *= cropFactor;
                }

                mDirectionX = moveX / TOUCH_MAX_RANGE;
                mDirectionY   = moveY / TOUCH_MAX_RANGE;
            } else {
                mDirectionX = 0.0f; mDirectionY = 0.0f;
            }
        }
        return true;
    }
    ```

1.  创建一个简单的组件`jni/MoveableBody.hpp`，其作用是根据输入事件移动`PhysicsBody`：

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

        PhysicsBody* registerMoveableBody(Location& pLocation,
                int32_t pSizeX, int32_t pSizeY);

        void initialize();
        void update();

    private:
        PhysicsManager& mPhysicsManager;
        InputManager& mInputManager;

        PhysicsBody* mBody;
    };
    #endif
    ```

1.  在`jni/MoveableBody.cpp`中实现这个组件。

    在`registerMoveableBody()`中，将`InputManager`和物体绑定：

    ```java
    #include "Log.hpp"
    #include "MoveableBody.hpp"

    MoveableBody::MoveableBody(android_app* pApplication,
          InputManager& pInputManager, PhysicsManager& pPhysicsManager) :
        mInputManager(pInputManager),
        mPhysicsManager(pPhysicsManager),
        mBody(NULL) {
    }

    PhysicsBody* MoveableBody::registerMoveableBody(Location& pLocation,
    int32_t pSizeX, int32_t pSizeY) {
        mBody = mPhysicsManager.loadBody(pLocation, pSizeX, pSizeY);
        mInputManager.setRefPoint(&pLocation);
        return mBody;
    }
    ...
    ```

1.  最初，物体没有速度。

    然后，每次更新时，速度都会反映当前的输入状态。这个速度由第五章，*编写一个完全原生的应用程序*中创建的`PhysicsManager`接收，以更新实体的位置：

    ```java
    ...
    void MoveableBody::initialize() {
        mBody->velocityX = 0.0f;
        mBody->velocityY = 0.0f;
    }

    void MoveableBody::update() {
        static const float MOVE_SPEED = 320.0f;
        mBody->velocityX = mInputManager.getDirectionX() * MOVE_SPEED;
        mBody->velocityY = mInputManager.getDirectionY() * MOVE_SPEED;
    }
    ```

    在`jni/DroidBlaster.hpp`中引用新的`InputManager`和`MoveableComponent`：

    ```java
    ...
    #include "EventLoop.hpp"
    #include "GraphicsManager.hpp"
    #include "InputManager.hpp"
    #include "MoveableBody.hpp"
    #include "PhysicsManager.hpp"
    #include "Resource.hpp"
    ...

    class DroidBlaster : public ActivityHandler {
        ...
    private:
        TimeManager     mTimeManager;
        GraphicsManager mGraphicsManager;
        PhysicsManager  mPhysicsManager;
        SoundManager    mSoundManager;
        InputManager    mInputManager;
        EventLoop mEventLoop;
        ...
        Asteroid mAsteroids;
        Ship mShip;
        StarField mStarField;
        SpriteBatch mSpriteBatch;
        MoveableBody mMoveableBody;
    };
    #endif
    ```

1.  最后，调整`jni/DroidBlaster.cpp`构造函数，以实例化`InputManager`和`MoveableComponent`。

    在构造时，将`InputManager`添加到`EventLoop`中，后者负责分派输入事件。

    飞船是被移动的实体。因此，需要将它的位置引用传递给`MoveableBody`组件：

    ```java
    ...
    DroidBlaster::DroidBlaster(android_app* pApplication):
        mTimeManager(),
        mGraphicsManager(pApplication),
        mPhysicsManager(mTimeManager, mGraphicsManager),
        mSoundManager(pApplication),
        mInputManager(pApplication, mGraphicsManager),
     mEventLoop(pApplication, *this, mInputManager),
        ...
        mAsteroids(pApplication, mTimeManager, mGraphicsManager,
        mPhysicsManager),
        mShip(pApplication, mGraphicsManager, mSoundManager),
        mStarField(pApplication, mTimeManager, mGraphicsManager,
                STAR_COUNT, mStarTexture),
        mSpriteBatch(mTimeManager, mGraphicsManager),
        mMoveableBody(pApplication, mInputManager, mPhysicsManager) {
        ...
        Sprite* shipGraphics = mSpriteBatch.registerSprite(mShipTexture,
                SHIP_SIZE, SHIP_SIZE);
        shipGraphics->setAnimation(SHIP_FRAME_1, SHIP_FRAME_COUNT,
                SHIP_ANIM_SPEED, true);
        Sound* collisionSound =
                mSoundManager.registerSound(mCollisionSound);
        mMoveableBody.registerMoveableBody(shipGraphics->location,
     SHIP_SIZE, SHIP_SIZE);
        mShip.registerShip(shipGraphics, collisionSound);

        // Creates asteroids.
        ...
    }
    ...
    ```

1.  在相应的函数中初始化和更新`MoveableBody`和`InputManager`：

    ```java
    ...
    status DroidBlaster::onActivate() {
        Log::info("Activating DroidBlaster");
        if (mGraphicsManager.start() != STATUS_OK) return STATUS_KO;
        if (mSoundManager.start() != STATUS_OK) return STATUS_KO;
        mInputManager.start();

        mSoundManager.playBGM(mBGM);

        mAsteroids.initialize();
        mShip.initialize();
        mMoveableBody.initialize();

        mTimeManager.reset();
        return STATUS_OK;
    }

    ...

    status DroidBlaster::onStep() {
        mTimeManager.update();
        mPhysicsManager.update();

        mAsteroids.update();
        mMoveableBody.update();

        return mGraphicsManager.update();
    }
    ...
    ```

## *刚才发生了什么？*

我们创建了一个基于触摸事件的输入系统的简单示例。飞船以与触摸距离相关的速度向触摸点飞行。触摸事件坐标是绝对的。它们的原点在屏幕左上角，与 OpenGL 的左下角相对。如果应用程序允许屏幕旋转，那么屏幕原点对于用户来说仍然在左上角，无论设备是纵向还是横向模式。

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645OS_08_07.jpg)

为了实现这个新特性，我们将事件循环连接到了`native_app_glue`模块提供的输入事件队列。这个队列在内部表现为一个 UNIX 管道，类似于活动事件队列。触摸屏事件嵌入在`AInputEvent`结构中，该结构还存储其他类型的输入事件。使用`android/input.h`中声明的`AInputEvent`和`AMotionEvent` API 处理输入事件。`AInputEvent` API 通过`AInputEvent_getType()`和`AInputEvent_getSource()`方法来区分输入事件类型。而`AMotionEvent` API 仅提供处理触摸事件的方法。

触摸 API 相当丰富。许多细节可以按照以下表格所示请求（非详尽无遗）：

| 方法 | 描述 |
| --- | --- |

|

```java
AMotionEvent_getAction()
```

| 用于检测手指是否与屏幕接触、离开或在其表面移动。结果是一个整数值，由事件类型（例如，第 1 个字节上的`AMOTION_EVENT_ACTION_DOWN`）和一个指针索引（在第 2 个字节上，以了解事件指的是哪个手指）组成。 |
| --- |

|

```java
AMotionEvent_getX()
AMotionEvent_getY()
```

| 用于获取屏幕上的触摸坐标，以浮点数（像素）表示（可能存在亚像素值）。 |
| --- |

|

```java
AMotionEvent_getDownTime()
AMotionEvent_getEventTime()
```

| 用于获取手指在屏幕上滑动的时间和事件生成的时间（单位为纳秒）。 |
| --- |

|

```java
AMotionEvent_getPressure()
AMotionEvent_getSize()

```

| 用于检测压力强度和区域。值通常在`0.0`到`1.0`之间（但可能会超出）。大小和压力通常密切相关。行为可能会因硬件而异并产生噪声。 |
| --- |

|

```java
AMotionEvent_getHistorySize()
AMotionEvent_getHistoricalX()
AMotionEvent_getHistoricalY()
```

| 为了提高效率，可以将类型为`AMOTION_EVENT_ACTION_MOVE`的触摸事件分组在一起。这些方法提供了对发生在前一个事件和当前事件之间的这些*历史点*的访问。 |
| --- |

查看完整的`android/input.h`方法列表。

如果你深入查看`AMotionEvent` API，你会注意到一些事件有一个第二个参数`pointer_index`，其范围在`0`到活动指针的数量之间。实际上，当今大多数触摸屏都支持多点触控！屏幕上的两个或更多手指（如果硬件支持）在 Android 中由两个或更多指针表示。要操作它们，请查看以下表格：

| 方法 | 描述 |
| --- | --- |

|

```java
AMotionEvent_getPointerCount()
```

| 用于了解有多少手指触摸屏幕。 |
| --- |

|

```java
AMotionEvent_getPointerId()
```

| 从指针索引获取一个指针的唯一标识符。这是跟踪特定指针（即*手指*）随时间变化唯一的方式，因为当手指触摸或离开屏幕时其索引可能会改变。 |
| --- |

### 提示

如果你关注过（现在已成古董的！）Nexus One 的故事，那么你应该知道它曾因硬件缺陷而出名。指针经常混淆，其中两个会交换它们的坐标。因此，一定要准备好处理硬件的特定行为或表现异常的硬件！

# 检测键盘、D-Pad 和轨迹球事件

在所有的输入设备中，最常见的是键盘。这对于 Android 来说也是如此。Android 的键盘可以是物理的：位于设备正面（如传统的黑莓手机），或者是在滑出式屏幕上的。然而，键盘通常是虚拟的，即在屏幕上模拟，这会占用大量的空间。除了键盘本身，每个 Android 设备都必须包括一些物理或模拟的按钮，如**菜单**、**主页**和**任务**。

一种不太常见的输入设备类型是方向键。方向键是一组物理按钮，用于向上、向下、向左或向右移动以及特定的动作/确认按钮。尽管它们经常从最近的手機和平板电脑上消失，但方向键仍然是在文本或 UI 小部件之间移动的最方便方式之一。方向键通常被轨迹球取代。轨迹球的行为类似于鼠标（带有一个球体的鼠标）并倒置。一些轨迹球是模拟的，但其他（例如，光学的）则表现为方向键（即全有或全无）。

![检测键盘、方向键和轨迹球事件](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645OS_08_02.jpg)

为了了解它们是如何工作的，让我们在`DroidBlaster`中使用这些外设来移动我们的太空船。现在 Android NDK 允许在本地处理所有这些输入外设。那么，让我们试试看！

### 注意

本书提供的结果项目名为`DroidBlaster_Part14`。

# 动手实践——本地处理键盘、方向键和轨迹球事件

让我们扩展我们新的输入系统，加入更多的事件类型：

1.  打开`jni/InputHandler.hpp`并添加键盘和轨迹球事件处理程序：

    ```java
    #ifndef _PACKT_INPUTHANDLER_HPP_
    #define _PACKT_INPUTHANDLER_HPP_

    #include <android/input.h>

    class InputHandler {
    public:
        virtual ~InputHandler() {};

        virtual bool onTouchEvent(AInputEvent* pEvent) = 0;
        virtual bool onKeyboardEvent(AInputEvent* pEvent) = 0;
     virtual bool onTrackballEvent(AInputEvent* pEvent) = 0;
    };
    #endif
    ```

1.  更新现有文件`jni/EventLoop.cpp`中的`processInputEvent()`方法，将键盘和轨迹球事件重定向到`InputHandler`。

    轨迹球和触摸事件被归纳为动作事件，可以根据它们的来源进行区分。相对的，按键事件根据它们的类型进行区分。实际上，存在两个专用的 API，一个用于`MotionEvents`（轨迹球和触摸事件相同），另一个用于`KeyEvents`（键盘、方向键等相同）。

    ```java
    ...
    int32_t EventLoop::processInputEvent(AInputEvent* pEvent) {
        if (!mEnabled) return 0;

        int32_t eventType = AInputEvent_getType(pEvent);
        switch (eventType) {
        case AINPUT_EVENT_TYPE_MOTION:
            switch (AInputEvent_getSource(pEvent)) {
            case AINPUT_SOURCE_TOUCHSCREEN:
                return mInputHandler.onTouchEvent(pEvent);
                break;

            case AINPUT_SOURCE_TRACKBALL:
     return mInputHandler.onTrackballEvent(pEvent);
     break;
            }
            break;

        case AINPUT_EVENT_TYPE_KEY:
     return mInputHandler.onKeyboardEvent(pEvent);
     break;
        }
    return 0;
    }
    ...
    ```

1.  修改`jni/InputManager.hpp`文件，重写这些新方法：

    ```java
    ...
    class InputManager : public InputHandler {
        ...
    protected:
        bool onTouchEvent(AInputEvent* pEvent);
        bool onKeyboardEvent(AInputEvent* pEvent);
     bool onTrackballEvent(AInputEvent* pEvent);

        ...
    };
    #endif
    ```

1.  在`jni/InputManager.cpp`中，使用`onKeyboardEvent()`处理键盘事件：

    +   使用`AKeyEvent_getAction()`获取事件类型（即按下或未按下）。

    +   使用`AKeyEvent_getKeyCode()`获取按钮标识。

    在以下代码中，当按下左、右、上或下按钮时，`InputManager`会计算方向并将其保存到`mDirectionX`和`mDirectionY`中。按钮按下时开始移动，松开时停止。

    当按键被消耗时返回`true`，否则返回`false`。实际上，如果用户按下了例如返回键（`AKEYCODE_BACK`）或音量键（`AKEYCODE_VOLUME_UP`，`AKEYCODE_VOLUME_DOWN`），我们就让系统为我们做出适当的反应：

    ```java
    ...
    bool InputManager::onKeyboardEvent(AInputEvent* pEvent) {
        static const float ORTHOGONAL_MOVE = 1.0f;

        if (AKeyEvent_getAction(pEvent) == AKEY_EVENT_ACTION_DOWN) {
            switch (AKeyEvent_getKeyCode(pEvent)) {
            case AKEYCODE_DPAD_LEFT:
                mDirectionX = -ORTHOGONAL_MOVE;
                return true;
            case AKEYCODE_DPAD_RIGHT:
                mDirectionX = ORTHOGONAL_MOVE;
                return true;
            case AKEYCODE_DPAD_DOWN:
                mDirectionY = -ORTHOGONAL_MOVE;
                return true;
            case AKEYCODE_DPAD_UP:
                mDirectionY = ORTHOGONAL_MOVE;
                return true;
            }
        } else {
            switch (AKeyEvent_getKeyCode(pEvent)) {
            case AKEYCODE_DPAD_LEFT:
            case AKEYCODE_DPAD_RIGHT:
                mDirectionX = 0.0f;
                return true;
            case AKEYCODE_DPAD_DOWN:
            case AKEYCODE_DPAD_UP:
                mDirectionY = 0.0f;
                return true;
            }
        }
        return false;
    }
    ...
    ```

1.  在新方法 `onTrackballEvent()` 中处理轨迹球事件。使用 `AMotionEvent_getX()` 和 `AMotionEvent_getY()` 获取轨迹球的大小。由于一些轨迹球不提供渐变的幅度，因此使用普通常量来量化移动，并通过任意的触发阈值忽略可能出现的噪声：

    ```java
    ...
    bool InputManager::onTrackballEvent(AInputEvent* pEvent) {
        static const float ORTHOGONAL_MOVE = 1.0f;
        static const float DIAGONAL_MOVE   = 0.707f;
        static const float THRESHOLD       = (1/100.0f);

         if (AMotionEvent_getAction(pEvent) == AMOTION_EVENT_ACTION_MOVE) {
            float directionX = AMotionEvent_getX(pEvent, 0);
            float directionY = AMotionEvent_getY(pEvent, 0);
            float horizontal, vertical;

            if (directionX < -THRESHOLD) {
                if (directionY < -THRESHOLD) {
                    horizontal = -DIAGONAL_MOVE;
                    vertical   = DIAGONAL_MOVE;
                } else if (directionY > THRESHOLD) {
                    horizontal = -DIAGONAL_MOVE;
                    vertical   = -DIAGONAL_MOVE;
                } else {
                    horizontal = -ORTHOGONAL_MOVE;
                    vertical   = 0.0f;
                }
            } else if (directionX > THRESHOLD) {
                if (directionY < -THRESHOLD) {
                    horizontal = DIAGONAL_MOVE;
                    vertical   = DIAGONAL_MOVE;
                } else if (directionY > THRESHOLD) {
                    horizontal = DIAGONAL_MOVE;
                    vertical   = -DIAGONAL_MOVE;
                } else {
                    horizontal = ORTHOGONAL_MOVE;
                    vertical   = 0.0f;
                }
            } else if (directionY < -THRESHOLD) {
                horizontal = 0.0f;
                vertical   = ORTHOGONAL_MOVE;
            } else if (directionY > THRESHOLD) {
                horizontal = 0.0f;
                vertical   = -ORTHOGONAL_MOVE;
            }
    ...
    ```

1.  以这种方式使用轨迹球时，飞船会一直移动，直到出现“反方向移动”（例如，在向左移动时请求向右移动）或按下动作按钮（最后的 `else` 部分）：

    ```java
            ...
            // Ends movement if there is a counter movement.
            if ((horizontal < 0.0f) && (mDirectionX > 0.0f)) {
                mDirectionX = 0.0f;
            } else if ((horizontal > 0.0f) && (mDirectionX < 0.0f)) {
                mDirectionX = 0.0f;
            } else {
                mDirectionX = horizontal;
            }

            if ((vertical < 0.0f) && (mDirectionY > 0.0f)) {
                mDirectionY = 0.0f;
            } else if ((vertical > 0.0f) && (mDirectionY < 0.0f)) {
                mDirectionY = 0.0f;
            } else {
                mDirectionY = vertical;
            }
        } else {
            mDirectionX = 0.0f; mDirectionY = 0.0f;
        }
        return true;
    }
    ```

## *刚才发生了什么？*

我们扩展了输入系统以处理键盘、D-Pad 和轨迹球事件。D-Pad 可以被视为键盘的扩展并以相同的方式处理。实际上，D-Pad 和键盘事件使用相同的结构 (`AInputEvent`) 并通过相同的 API（以 `AKeyEvent` 为前缀）处理。

下表列出了主要的键事件方法：

| 方法 | 描述 |
| --- | --- |
| `AKeyEvent_getAction()` | 指示按钮是按下 (`AKEY_EVENT_ACTION_DOWN`) 还是释放 (`AKEY_EVENT_ACTION_UP`)。请注意，可以批量发出多个键动作 (`AKEY_EVENT_ACTION_MULTIPLE`)。 |
| `AKeyEvent_getKeyCode()` | 获取实际被按下的按钮（在 `android/keycodes.h` 中定义），例如，左按钮为 `AKEYCODE_DPAD_LEFT`。 |
| `AKeyEvent_getFlags()` | 键事件可以与一个或多个标志相关联，这些标志提供了关于事件的各种信息，例如 `AKEY_EVENT_LONG_PRESS`、`AKEY_EVENT_FLAG_SOFT_KEYBOARD` 表示事件源自模拟键盘。 |
| `AKeyEvent_getScanCode()` | 类似于键码，但这是一个原始键 ID，依赖于设备且不同设备之间可能不同。 |
| `AKeyEvent_getMetaState()` | 元状态是标志，表示是否同时按下了某些修饰键，如 Alt 或 Shift（例如 `AMETA_SHIFT_ON`、`AMETA_NONE` 等）。 |
| `AKeyEvent_getRepeatCount()` | 指示按钮事件发生了多少次，通常是在你按下按钮不放时。 |
| `AKeyEvent_getDownTime()` | 了解按钮被按下时间。 |

尽管一些轨迹球（尤其是光学的）表现得像 D-Pad，但轨迹球并不使用相同的 API。实际上，轨迹球是通过 `AMotionEvent` API（如触摸事件）来处理的。当然，一些为触摸事件提供的信息在轨迹球上并不总是可用。需要关注的最重要功能如下：

| `AMotionEvent_getAction()` | 了解事件是否表示移动动作（与按下动作相对）。 |
| --- | --- |
| `AMotionEvent_getX()``AMotionEvent_getY()` | 获取轨迹球移动。 |
| `AKeyEvent_getDownTime()` | 了解轨迹球是否被按下（如 D-Pad 动作按钮）。目前，大多数轨迹球使用全或无的压力来指示按下事件。 |

在处理轨迹球时，要记住的一个棘手点是，没有事件生成来指示轨迹球没有移动。此外，轨迹球事件是作为“爆发”生成的，这使得检测运动何时结束变得更加困难。处理这个问题的唯一方法（除了使用手动计时器并定期检查是否有足够长的时间没有事件发生）。

### 提示

不要期望所有手机上的外围设备行为完全相同。轨迹球就是一个很好的例子；它们可以像模拟垫一样指示方向，也可以像 D-Pad 一样指示直线路径（例如，光学轨迹球）。目前还没有办法从可用的 API 中区分设备特性。唯一的解决方案是在运行时校准设备或配置设备，或者保存一种设备数据库。

# 探测设备传感器

处理输入设备对于任何应用来说都很重要，但对于最智能的应用来说，探测传感器才是关键！在 Android 游戏应用中最常见的传感器就是加速度计。

如其名称所示，加速度计测量施加在设备上的线性加速度。当将设备向上、下、左或右移动时，加速度计会被激发，并在 3D 空间中指示一个加速度矢量。该矢量是相对于屏幕默认方向的。坐标系相对于设备的自然方向：

+   X 轴指向右侧

+   Y 轴指向上方

+   Z 轴从后向前指

如果设备旋转，轴会反转（例如，如果设备顺时针旋转 90 度，Y 轴将指向左侧）。

加速度计一个非常有趣的特点是它们经历恒定加速度：地球上的重力，大约是 9.8m/s²。例如，当设备平放在桌子上时，加速度矢量在 Z 轴上指示-9.8。当设备直立时，它在 Y 轴上指示相同的值。因此，假设设备位置固定，可以从重力加速度矢量推导出设备在空间中的两个轴的方向。要获取 3D 空间中设备的完全方向，还需要一个磁力计。

### 提示

请记住，加速度计处理的是线性加速度。它们可以检测设备不旋转时的平移和设备固定时的部分方向。然而，如果没有磁力计和/或陀螺仪，这两种运动是无法结合的。

因此，我们可以使用从加速度计推导出的设备方向来计算一个方向。现在让我们看看如何在 `DroidBlaster` 中应用这个过程。

### 注意

最终项目与本一起提供，名为 `DroidBlaster_Part15`。

# 行动时间——处理加速度计事件

让我们在 `DroidBlaster` 中处理加速度计事件：

1.  打开 `jni/InputHandler.hpp` 文件，并添加一个新的方法 `onAccelerometerEvent()`。包含官方传感器头文件 `android/sensor.h`：

    ```java
    #ifndef _PACKT_INPUTHANDLER_HPP_
    #define _PACKT_INPUTHANDLER_HPP_

    #include <android/input.h>
    #include <android/sensor.h>

    class InputHandler {
    public:
        virtual ~InputHandler() {};

        virtual bool onTouchEvent(AInputEvent* pEvent) = 0;
        virtual bool onKeyboardEvent(AInputEvent* pEvent) = 0;
        virtual bool onTrackballEvent(AInputEvent* pEvent) = 0;
        virtual bool onAccelerometerEvent(ASensorEvent* pEvent) = 0;
    };
    #endif
    ```

1.  在 `jni/EventLoop.hpp` 中创建新方法：

    +   `activateAccelerometer()`和`deactivateAccelerometer()`在活动开始和停止时启用/禁用加速度传感器。

    +   `processSensorEvent()`检索并分派传感器事件。

    +   回调`callback_input()`静态方法绑定到 Looper。

    同时，定义以下成员：

    +   `mSensorManager`，类型为`ASensorManager`，是与传感器交互的主要“对象”。

    +   `mSensorEventQueue`是`ASensorEventQueue`，这是 Sensor API 定义的结构，用于检索发生的事件。

    +   `mSensorPollSource`是 Native Glue 中定义的`android_poll_source`。这个结构描述了如何将原生线程 Looper 绑定到传感器回调。

    +   `mAccelerometer`，声明为`ASensor`结构，表示所使用的传感器：

        ```java
        #ifndef _PACKT_EVENTLOOP_HPP_
        #define _PACKT_EVENTLOOP_HPP_

        #include "ActivityHandler.hpp"
        #include "InputHandler.hpp"

        #include <android_native_app_glue.h>

        class EventLoop {
            ...
        private:
            void activate();
            void deactivate();
            void activateAccelerometer();
         void deactivateAccelerometer();

            void processAppEvent(int32_t pCommand);
            int32_t processInputEvent(AInputEvent* pEvent);
            void processSensorEvent();

            static void callback_appEvent(android_app* pApplication,
                    int32_t pCommand);
            static int32_t callback_input(android_app* pApplication,
                    AInputEvent* pEvent);
            static void callback_sensor(android_app* pApplication,
         android_poll_source* pSource);

            ...
            InputHandler& mInputHandler;

            ASensorManager* mSensorManager;
         ASensorEventQueue* mSensorEventQueue;
         android_poll_source mSensorPollSource;
         const ASensor* mAccelerometer;
        };
        #endif
        ```

1.  更新`jni/EventLoop.cpp`中的构造函数初始化列表：

    ```java
    #include "EventLoop.hpp"
    #include "Log.hpp"

    EventLoop::EventLoop(android_app* pApplication,
        ActivityHandler& pActivityHandler, InputHandler& pInputHandler):
            mApplication(pApplication),
            mActivityHandler(pActivityHandler),
            mEnabled(false), mQuit(false),
            mInputHandler(pInputHandler),
            mSensorPollSource(), mSensorManager(NULL),
            mSensorEventQueue(NULL), mAccelerometer(NULL) {
        mApplication->userData = this;
        mApplication->onAppCmd = callback_appEvent;
        mApplication->onInputEvent = callback_input;
    }
    ...
    ```

1.  创建传感器事件队列，通过它通知所有`sensor`事件。

    将其绑定到`callback_sensor()`。请注意，这里我们使用 Native App Glue 提供的`LOOPER_ID_USER`常量来附加用户定义的队列。

    接着，调用`activateAccelerometer()`来初始化加速度传感器：

    ```java
    ...
    void EventLoop::activate() {
        if ((!mEnabled) && (mApplication->window != NULL)) {
            mSensorPollSource.id = LOOPER_ID_USER;
     mSensorPollSource.app = mApplication;
     mSensorPollSource.process = callback_sensor;
     mSensorManager = ASensorManager_getInstance();
     if (mSensorManager != NULL) {
     mSensorEventQueue = ASensorManager_createEventQueue(
     mSensorManager, mApplication->looper,
     LOOPER_ID_USER, NULL, &mSensorPollSource);
     if (mSensorEventQueue == NULL) goto ERROR;
     }
     activateAccelerometer();

            mQuit = false; mEnabled = true;
            if (mActivityHandler.onActivate() != STATUS_OK) {
                goto ERROR;
            }
        }
        return;

    ERROR:
        mQuit = true;
        deactivate();
        ANativeActivity_finish(mApplication->activity);
    }
    ...
    ```

1.  当活动被禁用或结束时，禁用正在运行的加速度传感器，以免不必要的消耗电池。

    然后，销毁`sensor`事件队列：

    ```java
    ...
    void EventLoop::deactivate() {
        if (mEnabled) {
            deactivateAccelerometer();
     if (mSensorEventQueue != NULL) {
     ASensorManager_destroyEventQueue(mSensorManager,
     mSensorEventQueue);
     mSensorEventQueue = NULL;
     }
     mSensorManager = NULL;

            mActivityHandler.onDeactivate();
            mEnabled = false;
        }
    }
    ...
    ```

1.  当事件循环被轮询时，`callback_sensor()`会被触发。它将事件分派给`EventLoop`实例上的`processSensorEvent()`。我们只关心`ASENSOR_TYPE_ACCELEROMETER`事件：

    ```java
    ...
    void EventLoop::callback_sensor(android_app* pApplication,
        android_poll_source* pSource) {
        EventLoop& eventLoop = *(EventLoop*) pApplication->userData;
        eventLoop.processSensorEvent();
    }

    void EventLoop::processSensorEvent() {
        ASensorEvent event;
        if (!mEnabled) return;

        while (ASensorEventQueue_getEvents(mSensorEventQueue,
                &event, 1) > 0) {
            switch (event.type) {
            case ASENSOR_TYPE_ACCELEROMETER:
                mInputHandler.onAccelerometerEvent(&event);
                break;
            }
        }
    }
    ...
    ```

1.  在`activateAccelerometer()`中通过三个主要步骤激活传感器：

    +   使用`AsensorManager_getDefaultSensor()`获取特定类型的传感器。

    +   然后，使用`ASensorEventQueue_enableSensor()`启用它，以便传感器事件队列填充相关事件。

    +   使用`ASensorEventQueue_setEventRate()`设置所需的事件率。对于游戏，我们通常希望接近实时测量。可以使用`ASensor_getMinDelay()`查询最小延迟（将其设置得较低可能会导致失败）。

    显然，我们应该只在传感器事件队列准备好时执行此设置：

    ```java
    ...
    void EventLoop::activateAccelerometer() {
        mAccelerometer = ASensorManager_getDefaultSensor(
                mSensorManager, ASENSOR_TYPE_ACCELEROMETER);
        if (mAccelerometer != NULL) {
            if (ASensorEventQueue_enableSensor(
                    mSensorEventQueue, mAccelerometer) < 0) {
                Log::error("Could not enable accelerometer");
                return;
            }

            int32_t minDelay = ASensor_getMinDelay(mAccelerometer);
            if (ASensorEventQueue_setEventRate(mSensorEventQueue,
                    mAccelerometer, minDelay) < 0) {
                Log::error("Could not set accelerometer rate");
            }
        } else {
            Log::error("No accelerometer found");
        }
    }
    ...
    ```

1.  传感器停用更容易，只需调用`AsensorEventQueue_disableSensor()`方法即可：

    ```java
    ...
    void EventLoop::deactivateAccelerometer() {
        if (mAccelerometer != NULL) {
            if (ASensorEventQueue_disableSensor(mSensorEventQueue,
                    mAccelerometer) < 0) {
                Log::error("Error while deactivating sensor.");
            }
            mAccelerometer = NULL;
        }
    }
    ```

## *刚才发生了什么？*

我们创建了一个事件队列来监听传感器事件。事件被封装在`ASensorEvent`结构中，该结构在`android/sensor.h`中定义。这个结构提供了以下内容：

+   传感器事件来源，即哪个传感器产生了这个事件。

+   传感器事件发生的时间。

+   传感器输出值。这个值存储在一个联合结构中，即你可以使用其中一个内部结构（这里我们关心的是`acceleration`向量）。

    ```java
    typedef struct ASensorEvent {
        int32_t version;
        int32_t sensor;
        int32_t type;
        int32_t reserved0;
        int64_t timestamp;
        union {
            float           data[16];
            ASensorVector   vector;
            ASensorVector   acceleration;
            ASensorVector   magnetic;
            float           temperature;
            float           distance;
            float           light;
            float           pressure;
        };
        int32_t reserved1[4];
    } ASensorEvent;
    ```

对于任何 Android 传感器，都使用相同的`ASensorEvent`结构。在加速度传感器的情况下，我们获取一个带有三个坐标`x`、`y`、`z`的向量，每个轴一个：

```java
typedef struct ASensorVector {
    union {
        float v[3];
        struct {
            float x;
            float y;
            float z;
        };
        struct {
            float azimuth;
            float pitch;
            float roll;
        };
    };
    int8_t status;
    uint8_t reserved[3];
} ASensorVector;
```

在我们的示例中，加速度计设置为尽可能低的事件率，这可能在不同的设备之间有所变化。需要注意的是，传感器事件率对电池节省有直接影响！因此，使用对应用程序来说足够的事件率。`ASensor` API 提供了一些方法来查询可用的传感器及其功能，如`ASensor_getName()`、`ASensor_getVendor()`、`ASensor_getMinDelay()`等。

现在我们能够获取传感器事件，让我们用它们来计算飞船的方向。

# 行动时间——将 Android 设备转变为游戏手柄

让我们找到设备方向并正确确定方向。

1.  编写一个新文件`jni/Configuration.hpp`，帮助我们获取设备信息，特别是设备旋转（定义为`screen_rot`）。

    声明`findRotation()`，以借助 JNI 发现设备方向：

    ```java
    #ifndef _PACKT_CONFIGURATION_HPP_
    #define _PACKT_CONFIGURATION_HPP_

    #include "Types.hpp"

    #include <android_native_app_glue.h>
    #include <jni.h>

    typedef int32_t screen_rot;

    const screen_rot ROTATION_0   = 0;
    const screen_rot ROTATION_90  = 1;
    const screen_rot ROTATION_180 = 2;
    const screen_rot ROTATION_270 = 3;

    class Configuration {
    public:
        Configuration(android_app* pApplication);

        screen_rot getRotation() { return mRotation; };

    private:
        void findRotation(JNIEnv* pEnv);

        android_app* mApplication;
        screen_rot mRotation;
    };
    #endif
    ```

1.  在`jni/Configuration.cpp`中获取配置详情。

    首先，在构造函数中，使用`AConfiguration` API 转储配置属性，例如当前语言、国家、屏幕大小、屏幕方向。这些信息可能很有趣，但不足以正确分析加速度计事件：

    ```java
    #include "Configuration.hpp"
    #include "Log.hpp"

    #include <stdlib.h>

    Configuration::Configuration(android_app* pApplication) :
        mApplication(pApplication),
        mRotation(0) {
        AConfiguration* configuration = AConfiguration_new();
        if (configuration == NULL) return;

        int32_t result;
        char i18NBuffer[] = "__";
        static const char* orientation[] = {
            "Unknown", "Portrait", "Landscape", "Square"
        };
        static const char* screenSize[] = {
            "Unknown", "Small", "Normal", "Large", "X-Large"
        };
        static const char* screenLong[] = {
            "Unknown", "No", "Yes"
        };

        // Dumps current configuration.
        AConfiguration_fromAssetManager(configuration,
            mApplication->activity->assetManager);
        result = AConfiguration_getSdkVersion(configuration);
        Log::info("SDK Version : %d", result);
        AConfiguration_getLanguage(configuration, i18NBuffer);
        Log::info("Language    : %s", i18NBuffer);
        AConfiguration_getCountry(configuration, i18NBuffer);
        Log::info("Country     : %s", i18NBuffer);
        result = AConfiguration_getOrientation(configuration);
        Log::info("Orientation : %s (%d)", orientation[result], result);
        result = AConfiguration_getDensity(configuration);
        Log::info("Density     : %d dpi", result);
        result = AConfiguration_getScreenSize(configuration);
        Log::info("Screen Size : %s (%d)", screenSize[result], result);
        result = AConfiguration_getScreenLong(configuration);
        Log::info("Long Screen : %s (%d)", screenLong[result], result);
        AConfiguration_delete(configuration);
    ...
    ```

    然后，将当前本地线程附加到 Android VM。

    ### 提示

    如果你仔细阅读了第四章，*从本地代码调用 Java*，你就知道这一步是获取`JNIEnv`对象（特定于线程）的必要步骤。`JavaVM`本身可以从`android_app`结构中获取。

1.  之后，调用`findRotation()`以获取当前设备旋转。

    最后，我们可以将线程从 Dalvik 分离，因为我们不再使用 JNI。请记住，在结束应用程序之前，始终应该分离已附加的线程：

    ```java
    ...
        JavaVM* javaVM = mApplication->activity->vm;
        JavaVMAttachArgs javaVMAttachArgs;
        javaVMAttachArgs.version = JNI_VERSION_1_6;
        javaVMAttachArgs.name = "NativeThread";
        javaVMAttachArgs.group = NULL;
        JNIEnv* env;
        if (javaVM->AttachCurrentThread(&env,
                        &javaVMAttachArgs) != JNI_OK) {
            Log::error("JNI error while attaching the VM");
            return;
        }
        // Finds screen rotation and get-rid of JNI.
        findRotation(env);
        mApplication->activity->vm->DetachCurrentThread();
    }
    ...
    ```

1.  实现`findRotation()`，其基本通过 JNI 执行以下 Java 代码：

    ```java
    WindowManager mgr = (InputMethodManager)
    myActivity.getSystemService(Context.WINDOW_SERVICE);
    int rotation = mgr.getDefaultDisplay().getRotation();
    ```

    显然，这在 JNI 中编写会稍微复杂一些。

    +   首先，获取 JNI 类，然后是方法，最后是字段

    +   然后，执行 JNI 调用

    +   最后，释放分配的 JNI 引用

    以下代码故意简化，以避免额外的检查（即，每个方法调用的`FindClass()`和`GetMethodID()`返回值和异常检查）：

    ```java
    ...
    void Configuration::findRotation(JNIEnv* pEnv) {
        jobject WINDOW_SERVICE, windowManager, display;
        jclass ClassActivity, ClassContext;
        jclass ClassWindowManager, ClassDisplay;
        jmethodID MethodGetSystemService;
        jmethodID MethodGetDefaultDisplay;
        jmethodID MethodGetRotation;
        jfieldID FieldWINDOW_SERVICE;

        jobject activity = mApplication->activity->clazz;

        // Classes.
        ClassActivity = pEnv->GetObjectClass(activity);
        ClassContext = pEnv->FindClass("android/content/Context");
        ClassWindowManager = pEnv->FindClass(
            "android/view/WindowManager");
        ClassDisplay = pEnv->FindClass("android/view/Display");

        // Methods.
        MethodGetSystemService = pEnv->GetMethodID(ClassActivity,
            "getSystemService",
            "(Ljava/lang/String;)Ljava/lang/Object;");
        MethodGetDefaultDisplay = pEnv->GetMethodID(
            ClassWindowManager, "getDefaultDisplay",
            "()Landroid/view/Display;");
        MethodGetRotation = pEnv->GetMethodID(ClassDisplay,
            "getRotation", "()I");

        // Fields.
        FieldWINDOW_SERVICE = pEnv->GetStaticFieldID(
          ClassContext, "WINDOW_SERVICE", "Ljava/lang/String;");

        // Retrieves Context.WINDOW_SERVICE.
        WINDOW_SERVICE = pEnv->GetStaticObjectField(ClassContext,
            FieldWINDOW_SERVICE);
        // Runs getSystemService(WINDOW_SERVICE).
        windowManager = pEnv->CallObjectMethod(activity,
            MethodGetSystemService, WINDOW_SERVICE);
        // Runs getDefaultDisplay().getRotation().
        display = pEnv->CallObjectMethod(windowManager,
            MethodGetDefaultDisplay);
        mRotation = pEnv->CallIntMethod(display, MethodGetRotation);

        pEnv->DeleteLocalRef(ClassActivity);
        pEnv->DeleteLocalRef(ClassContext);
        pEnv->DeleteLocalRef(ClassWindowManager);
        pEnv->DeleteLocalRef(ClassDisplay);
    }
    ```

1.  在`jni/InputManager.hpp`中管理新的加速度计传感器。

    加速度计轴在`toScreenCoord()`中进行转换。

    这种转换意味着我们要跟踪设备旋转：

    ```java
    ...
    #include "Configuration.hpp"
    #include "GraphicsManager.hpp"
    #include "InputHandler.hpp"
    ...
    class InputManager : public InputHandler {
        ...
    protected:
        bool onTouchEvent(AInputEvent* pEvent);
        bool onKeyboardEvent(AInputEvent* pEvent);
        bool onTrackballEvent(AInputEvent* pEvent);
        bool onAccelerometerEvent(ASensorEvent* pEvent);
     void toScreenCoord(screen_rot pRotation,
     ASensorVector* pCanonical, ASensorVector* pScreen);

    private:
        ...
        float mScaleFactor;
        float mDirectionX, mDirectionY;
         // Reference point to evaluate touch distance.
         Location* mRefPoint;
        screen_rot mRotation;
    };
    #endif
    ```

1.  在`jni/InputManager.hpp`中，利用新的`Configuration`类读取当前屏幕旋转设置。由于`DroidBlaster`强制使用竖屏模式，我们可以一次性存储旋转：

    ```java
    ...
     InputManager::InputManager(android_app* pApplication,
             GraphicsManager& pGraphicsManager) :
            mApplication(pApplication), mGraphicsManager(pGraphicsManager),
            mDirectionX(0.0f), mDirectionY(0.0f),
            mRefPoint(NULL) {
        Configuration configuration(pApplication);
     mRotation = configuration.getRotation();
    }
    ...
    ```

1.  让我们从加速度计传感器值计算一个方向。

    首先，将加速度计值从标准坐标转换为屏幕坐标，以处理竖屏和横屏设备。

    接下来，从捕获到的加速度计值中计算一个方向。在以下代码中，`X`和`Z`轴分别表示滚转和俯仰。检查这两个轴，看设备是否处于中性位置（即`CENTER_X`和`CENTER_Z`）或者是在倾斜（`MIN_X`、`MIN_Z`、`MAX_X`和`MAX_Z`）。请注意，我们的需求需要将 Z 值取反：

    ```java
    ...
    bool InputManager::onAccelerometerEvent(ASensorEvent* pEvent) {
        static const float GRAVITY =  ASENSOR_STANDARD_GRAVITY / 2.0f;
        static const float MIN_X = -1.0f; static const float MAX_X = 1.0f;
        static const float MIN_Z =  0.0f; static const float MAX_Z = 2.0f;
        static const float CENTER_X = (MAX_X + MIN_X) / 2.0f;
        static const float CENTER_Z = (MAX_Z + MIN_Z) / 2.0f;

        // Converts from canonical to screen coordinates.
        ASensorVector vector;
        toScreenCoord(mRotation, &pEvent->vector, &vector);

        // Roll tilt.
        float rawHorizontal = pEvent->vector.x / GRAVITY;
        if (rawHorizontal > MAX_X) {
            rawHorizontal = MAX_X;
        } else if (rawHorizontal < MIN_X) {
            rawHorizontal = MIN_X;
        }
        mDirectionX = CENTER_X - rawHorizontal;

        // Pitch tilt. Final value needs to be inverted.
        float rawVertical = pEvent->vector.z / GRAVITY;
        if (rawVertical > MAX_Z) {
            rawVertical = MAX_Z;
        } else if (rawVertical < MIN_Z) {
            rawVertical = MIN_Z;
        }
        mDirectionY = rawVertical - CENTER_Z;
        return true;
    }
    ...
    ```

1.  在`toScreenCoord()`辅助函数中，根据屏幕旋转交换或反转加速度计轴，使得在使用`DroidBlaster`在纵向模式时，无论你使用哪种设备，`X`和`Z`轴都指向同一方向：

    ```java
    ...
    void InputManager::toScreenCoord(screen_rot pRotation,
        ASensorVector* pCanonical, ASensorVector* pScreen) {
        struct AxisSwap {
            int8_t negX; int8_t negY;
            int8_t xSrc; int8_t ySrc;
        };
        static const AxisSwap axisSwaps[] = {
             {  1, -1, 0, 1},  // ROTATION_0
             { -1, -1, 1, 0},  // ROTATION_90
             { -1,  1, 0, 1},  // ROTATION_180
             {  1,  1, 1, 0}}; // ROTATION_270
        const AxisSwap& swap = axisSwaps[pRotation];

        pScreen->v[0] = swap.negX * pCanonical->v[swap.xSrc];
        pScreen->v[1] = swap.negY * pCanonical->v[swap.ySrc];
        pScreen->v[2] = pCanonical->v[2];
    }
    ```

## *刚才发生了什么？*

加速度计现在是一个游戏手柄！Android 设备可以是自然的纵向（主要是智能手机和小型平板电脑）或横向（主要是平板电脑）。这对接收加速度计事件的应用程序有影响。这些类型的设备及其旋转方式不同，轴线的对齐方式也不相同。

实际上，屏幕可以以四种不同的方式定向：`0`、`90`、`180`和`270`度。0 度是设备的自然方向。加速度计 X 轴始终指向右侧，Y 轴指向上方，Z 轴指向前方。在手机上，Y 轴在纵向模式下指向上方，而在大多数平板电脑上，Y 轴在横向模式下指向上方。当设备以 90 度方向定位时，轴的方向显然会改变（X 轴指向上方，等等）。这种情况也可能发生在以纵向模式使用的平板电脑上（其中 0 度对应于横向模式）。

![发生了什么？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645OS_08_03.jpg)

遗憾的是，使用原生 API 无法获取设备相对于屏幕自然方向的旋转。因此，我们需要依赖 JNI 来获取准确的设备旋转信息。然后，我们可以在`onAccelerometerEvent()`中像这样轻松地推导出方向向量。

## 关于传感器的更多内容

每个 Android 传感器都有一个唯一的标识符，在`android/sensor.h`中定义。这些标识符在所有 Android 设备上都是相同的：

+   `ASENSOR_TYPE_ACCELEROMETER`

+   `ASENSOR_TYPE_MAGNETIC_FIELD`

+   `ASENSOR_TYPE_GYRISCOPE`

+   `ASENSOR_TYPE_LIGHT`

+   `ASENSOR_TYPE_PROXIMITY`

可能存在其他额外的传感器并且可用，即使它们在`android/sensor.h`头文件中没有命名。在 Gingerbread 上，我们有与以下情况相同的情况：

+   重力传感器（标识符`9`）

+   线性加速度传感器（标识符`10`）

+   旋转矢量（标识符`11`）。

旋转矢量传感器是现在已弃用的方向矢量的继承者，在`增强现实`应用中至关重要。它提供了设备在 3D 空间中的方向。结合 GPS，它可以通过设备的视角定位任何物体。旋转传感器提供了一个数据矢量，通过`android.hardware.SensorManager`类（请参阅其源代码），可以将其转换为 OpenGL 视图矩阵。这样，你可以直接将设备方向物化为屏幕内容，将真实与虚拟生活联系起来。

# 总结

在本章中，我们介绍了多种从原生代码与 Android 交互的方法。更准确地说，我们学习了如何将输入队列附加到`Native App Glue`事件循环中。然后，我们处理了触摸事件以及来自键盘、D-Pad 的动作事件和轨迹球的运动事件。最后，我们将加速度计转换成了游戏手柄。

由于 Android 的碎片化，预计输入设备的行为会有所不同，需要准备好调整代码。在应用结构、图形、声音、输入和传感器方面，我们已经深入了解了 Android NDK 的能力。然而，重新发明轮子并不是解决方案！

在下一章中，我们将通过将现有的 C/C++库移植到 Android，释放 NDK 的真正力量。
