# 安卓 NDK 秘籍（四）

> 原文：[`zh.annas-archive.org/md5/7FB9DA0CE2811D0AA0DFB1A6AD308582`](https://zh.annas-archive.org/md5/ceefdd89e585c59c7FB9DA0CE2811D0AA0DFB1A6AD30858220db6a7760dc11f1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：其他 Android NDK API

在本章中，我们将涵盖以下内容：

+   使用 Android NDK 中的 jnigraphics 库进行编程

+   使用 Android NDK 中的动态链接库进行编程

+   使用 Android NDK 中的 zlib 压缩库进行编程

+   使用 Android NDK 中的 OpenSL ES 音频库进行音频编程

+   使用 Android NDK 中的 OpenMAX AL 多媒体库进行编程

# 引言

在前三章中，我们已经涵盖了 Android NDK OpenGL ES API（第四章，*Android NDK OpenGL ES API*）、Native Application API（第五章，*Android Native Application API*）和 Multithreading API（第六章，*Android NDK Multithreading*）。这是关于 Android NDK API 说明的最后一章，我们将介绍更多库，包括`jnigraphics`库、动态链接库、`zlib`压缩库、OpenSL ES 音频库和 OpenMAX AL 多媒体库。

我们首先介绍两个小型库，`jnigraphics`和动态链接器，它们的 API 函数较少，易于使用。然后我们描述`zlib`压缩库，该库可用于以`.zlib`和`.gzip`格式压缩和解压数据。OpenSL ES 音频库和 OpenMAX AL 多媒体库是两个相对较新的 API，在 Android 的新版本上可用。这两个库中的 API 函数尚未冻结，仍在发展中。正如 NDK OpenSL ES 和 OpenMAX AL 文档所述，由于 Android 上的库开发并不追求源代码兼容性，因此这两个库的未来版本可能需要我们更新代码。

请注意，OpenSL ES 和 OpenMAX AL 是相当复杂的库，拥有大量的 API 函数。我们只能通过简单示例介绍这两个库的基本用法。感兴趣的读者应查阅库文档以获取更多详细信息。

# 使用 Android NDK 中的 jnigraphics 库进行编程

`jnigraphics`库提供了一个基于 C 的接口，使本地代码能够访问 Java 位图对象的像素缓冲区，该接口在 Android 2.2 系统映像及更高版本上作为一个稳定的本地 API 提供。本节讨论如何使用`jnigraphics`库。

## 准备工作…

读者应该知道如何创建一个 Android NDK 项目。我们可以参考第一章《Hello NDK》中的*编写一个 Hello NDK 程序*一节获取详细说明。

## 如何操作…

以下步骤描述了如何创建一个简单的 Android 应用，该应用演示了`jnigraphics`库的使用方法：

1.  创建一个名为`JNIGraphics`的 Android 应用。将包名设置为`cookbook.chapter7.JNIGraphics`。更多详细说明请参考第二章《Java Native Interface》中的*加载本地库和注册本地方法*一节。

1.  右键点击项目**JNIGraphics**，选择**Android Tools** | **Add Native Support**。

1.  在`cookbook.chapter7.JNIGraphics`包中添加两个名为`MainActivity.java`和`RenderView.java`的 Java 文件。`RenderView.java`加载`JNIGraphics`本地库，调用本地`naDemoJniGraphics`方法处理位图，并最终显示位图。`MainActivity.java`文件创建一个位图，将其传递给`RenderView`类，并将`RenderView`类设置为它的内容视图。

1.  在`jni`文件夹下添加`mylog.h`和`JNIGraphics.cpp`文件。`mylog.h`包含 Android 本地`logcat`实用函数，而`JNIGraphics.cpp`文件包含使用`jnigraphics`库函数处理位图的本地代码。`JNIGraphics.cpp`文件中的部分代码如下所示：

    ```kt
    void naDemoJniGraphics(JNIEnv* pEnv, jclass clazz, jobject pBitmap) {
      int lRet, i, j;
      AndroidBitmapInfo lInfo;
      void* lBitmap;
      //1\. retrieve information about the bitmap
      if ((lRet = AndroidBitmap_getInfo(pEnv, pBitmap, &lInfo)) < 0) {
        return;
      }
      if (lInfo.format != ANDROID_BITMAP_FORMAT_RGBA_8888) {
        return;
      }
      //2\. lock the pixel buffer and retrieve a pointer to it
      if ((lRet = AndroidBitmap_lockPixels(pEnv, pBitmap, &lBitmap)) < 0) {
        LOGE(1, "AndroidBitmap_lockPixels() failed! error = %d", lRet);
      }
      //3\. manipulate the pixel buffer
      unsigned char *pixelBuf = (unsigned char*)lBitmap;
      for (i = 0; i < lInfo.height; ++i) {
        for (j = 0; j < lInfo.width; ++j) {
        unsigned char *pixelP = pixelBuf + i*lInfo.stride + j*4;
        *pixelP = (unsigned char)0x00;	//remove R component
    //    *(pixelP+1) = (unsigned char)0x00;	//remove G component
    //    *(pixelP+2) = (unsigned char)0x00;	//remove B component
    //    LOGI(1, "%d:%d:%d:%d", *pixelP, *(pixelP+1), *(pixelP+2), *(pixelP+3));}
      }
      //4\. unlock the bitmap
      AndroidBitmap_unlockPixels(pEnv, pBitmap);
    }
    ```

1.  在`jni`文件夹中添加一个`Android.mk`文件，内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := JNIGraphics
    LOCAL_SRC_FILES := JNIGraphics.cpp
    LOCAL_LDLIBS := -llog -ljnigraphics
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  构建并运行 Android 项目。我们可以启用代码从位图中移除不同的组件。以下屏幕截图分别显示了原始图片以及移除了红色、绿色和蓝色组件的图片：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_07_01.jpg)

## 它的工作原理...

在我们的示例项目中，我们通过将位图传递给本地`naDemoJniGraphics`函数的一个 RGB 组件设置为 0 来修改位图。

### 注意

`jnigraphics`库仅适用于 Android API 级别 8（Android 2.2，Froyo）及更高版本。

使用`jnigraphics`库应遵循以下步骤：

1.  在使用`jnigraphics`API 的源代码中包含`<android/bitmap.h>`头文件。

1.  在`Android.mk`文件中包含以下行以链接到`jnigraphics`库。

    ```kt
    LOCAL_LDLIBS += -ljnigraphics
    ```

1.  在源代码中，调用`AndroidBitmap_getInfo`函数来获取关于位图对象的信息。`AndroidBitmap_getInfo`函数具有以下原型：

    ```kt
    int AndroidBitmap_getInfo(JNIEnv* env, jobject jbitmap, AndroidBitmapInfo* info);
    ```

    该函数接受指向`JNIEnv`结构的指针、位图对象的引用以及指向`AndroidBitmapInfo`结构的指针。如果调用成功，`info`指向的数据结构将被填充。

    `AndroidBitmapInfo`的定义如下：

    ```kt
    typedef struct {
    uint32_t    width;
    	uint32_t    height;
    uint32_t    stride;
    int32_t     format;
    uint32_t    flags; 
    } AndroidBitmapInfo;
    ```

    `width`和`height`表示位图的像素宽度和高度。`stride`指的是像素缓冲区行之间跳过的字节数。该数字不得小于宽度字节。在大多数情况下，`stride`与`width`相同。然而，有时像素缓冲区包含填充，所以`stride`可能比位图`width`大。

    `format`是颜色格式，可以是`bitmap.h`头文件中定义的`ANDROID_BITMAP_FORMAT_RGBA_8888`、`ANDROID_BITMAP_FORMAT_RGB_565`、`ANDROID_BITMAP_FORMAT_RGBA_4444`、`ANDROID_BITMAP_FORMAT_A_8`或`ANDROID_BITMAP_FORMAT_NONE`。

    在我们的示例中，我们使用`ANDROID_BITMAP_FORMAT_RGBA_8888`作为位图格式。因此，每个像素占用 4 个字节。

1.  通过调用`AndroidBitmap_lockPixels`函数锁定像素地址：

    ```kt
    int AndroidBitmap_lockPixels(JNIEnv* env, jobject jbitmap, void** addrPtr);
    ```

    如果调用成功，`*addrPtr` 指针将指向位图的像素。一旦像素地址被锁定，在像素地址被解锁之前，像素的内存不会移动。

1.  在本地代码中操作像素缓冲区。

1.  通过调用 `AndroidBitmap_unlockPixels` 来解锁像素地址：

    ```kt
    int AndroidBitmap_unlockPixels(JNIEnv* env, jobject jbitmap);
    ```

    请注意，如果 `AndroidBitmap_lockPixels` 函数调用成功，则必须调用此函数。

    ### 注意

    `jnigraphics` 函数在成功时返回 `ANDROID_BITMAP_RESUT_SUCCESS`，其值为 `0`。失败时返回负值。

## 还有更多内容...

回顾我们在第四章，*Android NDK OpenGL ES API* 的*使用 OpenGL ES 1.x API 将纹理映射到 3D 对象*示例中使用了 `jnigraphics` 库来加载纹理。我们可以重新访问该示例，了解我们如何使用 `jnigraphics` 库的另一个例子。

# 在 Android NDK 中使用动态链接库进行编程

动态加载是一种在运行时将库加载到内存中，并执行库中定义的函数或访问变量的技术。它允许应用程序在没有这些库的情况下启动。

在本书的几乎每个示例中，我们都看到了动态加载。当我们调用 `System.loadLibrary` 或 `System.load` 函数来加载本地库时，我们就是在使用动态加载。

自从 Android 1.5 起，Android NDK 就提供了动态链接库以支持 NDK 中的动态加载。本示例讨论动态链接库函数。

## 准备就绪...

期望读者知道如何创建一个 Android NDK 项目。你可以参考第一章的*编写一个 Hello NDK 程序*示例，*Hello NDK* 以获取详细说明。

## 如何操作...

以下步骤描述了如何使用动态链接库创建一个 Android 应用程序，以加载数学库并计算 2 的平方根。

1.  创建一个名为 `DynamicLinker` 的 Android 应用程序。将包名设置为 `cookbook.chapter7.dynamiclinker`。更多详细说明请参考第二章，*Java Native Interface* 的*加载本地库和注册本地方法*示例。

1.  右键点击 `DynamicLinker` 项目，选择 **Android Tools** | **Add Native Support**。

1.  在 `cookbook.chapter7.dynamiclinker` 包下添加一个名为 `MainActivity.java` 的 Java 文件。这个 Java 文件简单加载了本地 `DynamicLinker` 库，并调用了本地 `naDLDemo` 方法。

1.  在 `jni` 文件夹下添加 `mylog.h` 和 `DynamicLinker.cpp` 文件。`OpenSLESDemo.cpp` 文件中的一部分代码在以下代码中显示。

    `naDLDemo` 加载了 `libm.so` 库，获取了 `sqrt` 函数的地址，并以输入参数 `2.0` 调用该函数：

    ```kt
    void naDLDemo(JNIEnv* pEnv, jclass clazz) {
      void *handle;
      double (*sqrt)(double);
      const char *error;
      handle = dlopen("libm.so", RTLD_LAZY);
      if (!handle) {
        LOGI(1, "%s\n", dlerror());
        return;
      }
      dlerror();    /* Clear any existing error */
      *(void **) (&sqrt) = dlsym(handle, "sqrt");
      if ((error = dlerror()) != NULL)  {
        LOGI(1, "%s\n", error);
        return;
      }
      LOGI(1, "%f\n", (*sqrt)(2.0));
    }
    ```

1.  在 `jni` 文件夹下添加一个 `Android.mk` 文件，内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := DynamicLinker
    LOCAL_SRC_FILES := DynamicLinker.cpp
    LOCAL_LDLIBS := -llog -ldl
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  构建并运行 Android 项目，使用以下命令监控 `logcat` 输出：

    ```kt
    $ adb logcat -v time DynamicLinker:I *:S
    ```

    `logcat`输出的屏幕截图如下所示：

    ![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_07_05.jpg)

## 它的工作原理...

为了使用动态加载库`libdl.so`进行构建，我们必须在`Android.mk`文件中添加以下行：

```kt
LOCAL_LDLIBS := -ldl
```

以下函数在`dlfcn.h`头文件中由 Android 动态链接库定义：

```kt
void*        dlopen(const char*  filename, int flag);
int          dlclose(void*  handle);
const char*  dlerror(void);
void*        dlsym(void*  handle, const char*  symbol);
int          dladdr(const void* addr, Dl_info *info);
```

`dlopen`函数动态加载库。第一个参数指示库名称，而第二个参数指的是加载模式，描述了`dlopen`如何解析未定义的符号。当一个对象文件（例如共享库、可执行文件等）被加载时，它可能包含对符号的引用，这些符号的地址在另一个对象文件被加载之前是未知的（这类符号被称为未定义符号）。在使用这些引用访问符号之前，需要解析这些引用。以下两种模式决定了解析何时发生：

+   `RTLD_NOW`：当对象文件被加载时，未定义的符号将被解析。这意味着解析在`dlopen`函数返回之前发生。如果执行了解析但从未访问过引用，这可能是浪费。

+   `RTLD_LAZY`：解析可以在`dlopen`函数返回后执行，即当代码执行时解析未定义的符号。

以下两种模式决定了已加载对象中符号的可见性。它们可以与前面提到的两种模式进行 OR 运算：

+   `RTLD_LOCAL`：符号对另一个对象不可用

+   `RTLD_GLOBAL`：符号将对随后加载的对象可用

`dlopen`函数在成功时返回一个句柄。该句柄应用于后续对`dlsym`和`dlclose`的调用。

`dlclose`函数只是减少了加载库句柄的引用计数。如果引用计数减少到零，将卸载库。

`dlerror`函数返回一个字符串，以描述自上次调用`dlerror`以来在调用`dlopen`、`dlsym`或`dlclose`时发生的最新错误。如果没有发生此类错误，它将返回`NULL`。

`dlsym`函数返回输入参数句柄所引用的已加载动态库中给定符号的内存地址。返回的地址可以用来访问该符号。

`dladdr`函数接收一个地址，并尝试通过`DI_info`类型的`info`参数返回有关该地址和库的更多信息。`DI_info`数据结构定义如下代码片段所示：

```kt
typedef struct {
   const char *dli_fname;  
   void       *dli_fbase;  
   const char *dli_sname;  
   void       *dli_saddr;  
} Dl_info;
```

`dli_fname`表示输入参数`addr`引用的共享对象的路径。`dli_fbase`是共享对象加载的地址。`dli_sname`表示地址低于`addr`的最近符号的名称，而`dli_saddr`是名为`dli_sname`的符号的地址。

在我们的示例中，我们演示了前四个函数的用法。我们通过 `dlopen` 加载数学库，通过 `dlsym` 获取 `sqrt` 函数的地址，通过 `dlerror` 检查错误，并通过 `dlclose` 关闭库。

有关动态加载库的更多详细信息，请参考 [`tldp.org/HOWTO/Program-Library-HOWTO/dl-libraries.html`](http://tldp.org/HOWTO/Program-Library-HOWTO/dl-libraries.html) 和 [`linux.die.net/man/3/dlopen`](http://linux.die.net/man/3/dlopen)。

# 在 Android NDK 中使用 zlib 压缩库进行编程

`zlib` 是一个广泛使用的、无损的数据压缩库，适用于 Android 1.5 系统镜像或更高版本。本食谱讨论了 `zlib` 函数的基本用法。

## 准备中...

期望读者知道如何创建一个 Android NDK 项目。我们可以参考 第一章 的 *编写一个 Hello NDK 程序* 食谱，*Hello NDK* 以获取详细说明。

## 如何操作...

以下步骤描述了如何创建一个简单的 Android 应用程序，该程序演示了 `zlib` 库的用法：

1.  创建一个名为 `ZlibDemo` 的 Android 应用程序。将包名设置为 `cookbook.chapter7.zlibdemo`。有关更详细的说明，请参考 第二章 的 *加载本地库和注册本地方法* 食谱，*Java Native Interface*。

1.  在项目 **ZlibDemo** 上右键点击，选择 **Android Tools** | **添加本地支持**。

1.  在 `cookbook.chapter7.zlibdemo` 包中添加一个名为 `MainActivity.java` 的 Java 文件。`MainActivity.java` 文件加载 `ZlibDemo` 本地库，并调用本地方法。

1.  在 `jni` 文件夹下添加 `mylog.h`、`ZlibDemo.cpp` 和 `GzFileDemo.cpp` 文件。`mylog.h` 头文件包含了 Android 本地的 `logcat` 实用功能函数，而 `ZlibDemo.cpp` 和 `GzFileDemo.cpp` 文件包含了压缩和解压缩的代码。`ZlibDemo.cpp` 和 `GzFileDemo.cpp` 的一部分代码在以下代码中展示。

    `ZlibDemo.cpp` 包含了在内存中压缩和解压缩数据的本地代码。

    `compressUtil` 在内存中压缩和解压缩数据。

    ```kt
    void compressUtil(unsigned long originalDataLen) {
      int rv;
      int compressBufBound = compressBound(originalDataLen);
      compressedBuf = (unsigned char*) malloc(sizeof(unsigned char)*compressBufBound);
      unsigned long compressedDataLen = compressBufBound;
      rv = compress2(compressedBuf, &compressedDataLen, dataBuf, originalDataLen, 6);
      if (Z_OK != rv) {
        LOGE(1, "compression error");
        free(compressedBuf);
        return;
      }
      unsigned long decompressedDataLen = S_BUF_SIZE;
      rv = uncompress(decompressedBuf, &decompressedDataLen, compressedBuf, compressedDataLen);
      if (Z_OK != rv) {
        LOGE(1, "decompression error");
        free(compressedBuf);
        return;
      }
      if (0 == memcmp(dataBuf, decompressedBuf, originalDataLen)) {
        LOGI(1, "decompressed data same as original data");
      }   //free resource
      free(compressedBuf);
    }
    ```

1.  `naCompressAndDecompress` 生成压缩数据并调用 `compressUtil` 函数来压缩和解压缩生成的数据：

    ```kt
    void naCompressAndDecompress(JNIEnv* pEnv, jclass clazz) {
      unsigned long originalDataLen = getOriginalDataLen();
      LOGI(1, "---------data with repeated bytes---------")
      generateOriginalData(originalDataLen);
      compressUtil(originalDataLen);
      LOGI(1, "---------data with random bytes---------")
      generateOriginalDataRandom(originalDataLen);
      compressUtil(originalDataLen);
    }
    ```

    `GzFileDemo.cpp` 包含了本地代码，用于压缩和解压缩文件中的数据。

    `writeToFile` 函数将字符串写入到 `gzip` 文件中。在写入时会应用压缩：

    ```kt
    int writeToFile() {
      gzFile file;
      file = gzopen("/sdcard/test.gz", "w6");
      if (NULL == file) {
        LOGE(1, "cannot open file to write");
        return 0;
      }
      const char* dataStr = "hello, Android NDK!";
      int bytesWritten = gzwrite(file, dataStr, strlen(dataStr));
      gzclose(file);
      return bytesWritten;
    }
    ```

    `readFromFile` 从 `gzip` 文件中读取数据。在读取时会应用解压缩：

    ```kt
    void readFromFile(int pBytesToRead) {
      gzFile file;
      file = gzopen("/sdcard/test.gz", "r6");
      if (NULL == file) {
        LOGE(1, "cannot open file to read");
        return;
      }
      char readStr[100];
      int bytesRead = gzread(file, readStr, pBytesToRead);
      gzclose(file);
      LOGI(1, "%d: %s", bytesRead, readStr);
    }
    ```

1.  在 `jni` 文件夹下添加一个 `Android.mk` 文件，内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := ZlibDemo
    LOCAL_SRC_FILES := ZlibDemo.cpp GzFileDemo.cpp
    LOCAL_LDLIBS := -llog -lz
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  启用 `naCompressAndDecompress` 函数并禁用 `naGzFileDemo` 函数，构建并运行应用程序。我们可以使用以下命令监控 `logcat` 输出：

    ```kt
    $ adb logcat -v time ZlibDemo:I *:S
    ```

    `logcat` 输出的屏幕截图如下所示：

    ![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_07_06.jpg)

    启用 `naGzFileDemo` 函数并禁用 `naCompressAndDecompress` 函数，构建并运行应用程序。`logcat` 输出在以下屏幕截图中显示：

    ![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_07_07.jpg)

## 工作原理...

`zlib` 库为内存数据和文件提供压缩和解压缩功能。我们演示了这两种用例。在 `ZlibDemo.cpp` 文件中，我们创建了两个数据缓冲区，一个包含重复的字节，另一个包含随机的字节。我们按照以下步骤压缩和解压缩数据：

1.  计算压缩后大小的上限。这是通过以下函数完成的：

    ```kt
    uLong compressBound(uLong sourceLen);
    ```

    该函数返回在 `sourceLen` 字节的源数据上调用 `compress` 或 `compress2` 函数后压缩数据的最大大小。

1.  为存储压缩数据分配内存。

1.  压缩数据。这是通过以下函数完成的：

    ```kt
    int compress2(Bytef *dest,   uLongf *destLen, const Bytef *source, uLong sourceLen, int level);
    ```

    这个函数接受五个输入参数。`source` 和 `sourceLen` 指的是源数据缓冲区和源数据长度。`dest` 和 `destLen` 指示用于存储压缩数据的数据缓冲区和这个缓冲区的大小。`destLen` 的值必须在调用函数时至少为 `compressBound` 返回的值。当函数返回时，`destLen` 被设置为压缩数据的实际大小。最后一个输入参数 `level` 可以在 0 到 9 之间取值，其中 1 表示最快的速度，9 表示最佳的压缩率。在我们的示例中，我们将其值设置为 6，以在速度和压缩之间取得平衡。

    ### 注意

    我们还可以使用压缩函数来压缩数据，该函数没有级别输入参数。相反，它假设一个默认级别，相当于 6。

1.  解压缩数据。这是通过使用 `uncompress` 函数完成的：

    ```kt
    int uncompress(Bytef *dest,   uLongf *destLen, const Bytef *source, uLong sourceLen);
    ```

    输入参数与 `compress2` 函数的含义相同。

1.  将解压缩的数据与原始数据比较。这只是简单的检查。

    默认情况下，这些函数使用 `zlib` 格式来处理压缩数据。

    这个库还支持以 `gzip` 格式读写文件。这在 `GzFileDemo.cpp` 中有演示。这些函数的使用类似于 `stdio` 文件读写函数。

我们遵循的步骤将压缩数据写入 `gzip` 文件，然后从中读取未压缩数据，如下所示：

1.  打开一个 `gzip` 文件以供写入。这是通过以下函数完成的：

    ```kt
    gzFile gzopen(const char *path, const char *mode);
    ```

    该函数接受一个文件名和打开模式，并在成功时返回一个 `gzFile` 对象。该模式类似于 `fopen` 函数，但有一个可选的压缩级别。在我们的示例中，我们用 `w6` 调用 `gzopen` 以指定压缩级别为 6。

1.  将数据写入 `gzip` 文件。这是通过以下函数完成的：

    ```kt
    int gzwrite(gzFile file, voidpc buf, unsigned len);
    ```

    此函数将未压缩数据写入压缩文件中。输入参数`file`指的是压缩文件，`buf`指的是未压缩数据缓冲区，而`len`表示要写入的字节数。函数返回实际写入的未压缩数据数量。

1.  关闭`gzip`文件。这是通过以下函数完成的：

    ```kt
    int ZEXPORT    gzclose(gzFile file);
    ```

    调用此函数将刷新所有挂起的输出并关闭压缩文件。

1.  打开文件以供读取。我们向`gzopen`函数传递了`r6`。

1.  从压缩文件中读取数据。这是通过`gzread`函数完成的。

    ```kt
    int gzread(gzFile file, voidp buf, unsigned len);
    ```

    该函数从文件中读取`len`个字节到`buf`中。它返回实际读取的字节数。

    ### 注意

    `zlib`库支持两种压缩格式，`zlib`和`gzip`。`zlib`旨在紧凑且快速，因此最适合在内存和通信通道中使用。另一方面，`gzip`专为文件系统上的单个文件压缩设计，它有一个更大的头部来维护目录信息，并且比`zlib`使用更慢的校验方法。

为了使用`zlib`库，我们必须在源代码中包含`zlib.h`头文件，并在`Android.mk`中添加以下行以链接到`libz.so`库：

```kt
LOCAL_LDLIBS := -lz
```

## 还有更多...

回顾第五章中的*管理 Android NDK 的资产*一节，*Android Native Application API*，我们编译了`libpng`库，它需要`zlib`库。

我们只介绍了`zlib`库提供的一些函数。更多信息，您可以参考`platforms/android-<version>/arch-arm/usr/include/`文件夹中的`zlib.h`和`zconf.h`头文件。`zlib`库的详细文档可以在[`www.zlib.net/manual.html`](http://www.zlib.net/manual.html)找到。

# 使用 Android NDK 中的 OpenSL ES 音频库进行音频编程

OpenSL ES 是一个 C 语言级别的应用程序音频库。Android NDK 原生音频 API 基于 OpenSL ES 1.0.1 标准，并带有 Android 特定的扩展。该 API 适用于 Android 2.3 或更高版本，某些功能仅在 Android 4.0 或更高版本上支持。此库中的 API 函数尚未冻结，仍在发展中。此库的未来版本可能需要我们更新代码。本节在 Android 环境下介绍 OpenSL ES API。

## 准备就绪...

在开始使用 OpenSL ES 编码之前，了解这个库的一些基本知识是至关重要的。OpenSL ES 代表嵌入式系统的**开放声音库**，它是一个跨平台、免版税、使用 C 语言的应用程序级别 API，供开发者访问嵌入式系统的音频功能。该库规范定义了如音频播放和录制、音频效果和控制、2D 和 3D 音频、高级 MIDI 等功能。根据支持的功能，OpenSL ES 定义了三个配置文件，包括电话、音乐和游戏。

然而，Android 原生音频 API 并不符合这三个配置文件中的任何一个，因为它没有实现任何配置文件中的所有功能。此外，Android 实现了一些特定于 Android 的功能，例如 Android 缓冲队列。关于在 Android 上支持的功能的详细描述，我们可以参考随 Android NDK 提供的`docs/opensles/`文件夹下的 OpenSL ES for Android 文档。

尽管 OpenSL ES API 是用 C 语言实现的，但它通过基于对象和接口构建库，采用了面向对象的方法：

+   **对象**：对象是一组资源和它们状态的抽象。每个对象在创建时都会分配一个类型，而类型决定了对象可以执行的任务集合。这类似于 C++中的类概念。

+   **接口**：接口是一组对象可以提供的特性的抽象。这些特性以一组方法和每种接口类型的精确特性集合的形式暴露给我们。在代码中，接口类型通过接口 ID 来识别。

需要注意的是，对象在代码中没有实际的表现形式。我们通过接口改变对象的状态和访问其特性。一个对象可以有一个或多个接口实例。然而，一个单一对象的两个实例不能是同一类型。此外，给定的接口实例只能属于一个对象。这种关系可以如下所示的关系图进行说明：

![准备就绪...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_07_11.jpg)

如图中所示，对象 1 和对象 2 具有不同的类型，因此暴露了不同的接口。对象 1 有三个接口实例，所有实例类型都不同。而对象 2 有另外两个不同类型的接口实例。注意对象 1 的接口 2 和对象 2 的接口 4 具有相同的类型，这意味着对象 1 和对象 2 都支持通过 Interface Type B 的接口暴露的特性。

## 如何操作...

以下步骤描述了如何使用原生音频库创建一个简单的 Android 应用程序以录制和播放音频：

1.  创建一个名为`OpenSLESDemo`的 Android 应用程序。将包名设置为`cookbook.chapter7.opensles`。更多详细说明请参考第二章的*加载本地库和注册本地方法*部分，*Java Native Interface*。

1.  右键点击项目**OpenSLESDemo**，选择**Android Tools** | **Add Native Support**。

1.  在`cookbook.chapter7.opensles`包中添加一个名为`MainActivity.java`的 Java 文件。这个 Java 文件仅加载本地库`OpenSLESDemo`，并调用本地方法来录制和播放音频。

1.  在`jni`文件夹中添加`mylog.h`、`common.h`、`play.c`、`record.c`和`OpenSLESDemo.cpp`文件。`play.c`、`record.c`和`OpenSLESDemo.cpp`文件中的一部分代码在以下代码片段中展示。

    `record.c`包含创建音频录音器对象并录制音频的代码。

    `createAudioRecorder`创建并实现一个音频播放器对象，并获得录音和缓冲队列接口：

    ```kt
    jboolean createAudioRecorder() {
       SLresult result;
       SLDataLocator_IODevice loc_dev = {SL_DATALOCATOR_IODEVICE, SL_IODEVICE_AUDIOINPUT, SL_DEFAULTDEVICEID_AUDIOINPUT, NULL};
       SLDataSource audioSrc = {&loc_dev, NULL};
       SLDataLocator_AndroidSimpleBufferQueue loc_bq = {SL_DATALOCATOR_ANDROIDSIMPLEBUFFERQUEUE, 1};
       SLDataFormat_PCM format_pcm = {SL_DATAFORMAT_PCM, 1, SL_SAMPLINGRATE_16,
           SL_PCMSAMPLEFORMAT_FIXED_16, SL_PCMSAMPLEFORMAT_FIXED_16,
           SL_SPEAKER_FRONT_CENTER, SL_BYTEORDER_LITTLEENDIAN};
       SLDataSink audioSnk = {&loc_bq, &format_pcm};
       const SLInterfaceID id[1] = {SL_IID_ANDROIDSIMPLEBUFFERQUEUE};
       const SLboolean req[1] = {SL_BOOLEAN_TRUE};
       result = (*engineEngine)->CreateAudioRecorder(engineEngine, &recorderObject, &audioSrc,
               &audioSnk, 1, id, req);
         result = (*recorderObject)->Realize(recorderObject, SL_BOOLEAN_FALSE);
       result = (*recorderObject)->GetInterface(recorderObject, SL_IID_RECORD, &recorderRecord);
       result = (*recorderObject)->GetInterface(recorderObject, SL_IID_ANDROIDSIMPLEBUFFERQUEUE, &recorderBufferQueue);
       result = (*recorderBufferQueue)->RegisterCallback(recorderBufferQueue, bqRecorderCallback, NULL);
       return JNI_TRUE;
    }
    ```

    `startRecording`将缓冲区入队以存储录音音频，并将音频对象状态设置为录音状态：

    ```kt
    void startRecording() {
       SLresult result;
       recordF = fopen("/sdcard/test.pcm", "wb");
       result = (*recorderRecord)->SetRecordState(recorderRecord, SL_RECORDSTATE_STOPPED);
       result = (*recorderBufferQueue)->Clear(recorderBufferQueue);
       recordCnt = 0;
       result = (*recorderBufferQueue)->Enqueue(recorderBufferQueue, recorderBuffer,
               RECORDER_FRAMES * sizeof(short));
       result = (*recorderRecord)->SetRecordState(recorderRecord, SL_RECORDSTATE_RECORDING);
    }
    ```

    每当缓冲队列准备好接受新的数据块时，就会调用`bqRecorderCallback`回调方法。这发生在缓冲区填满音频数据时：

    ```kt
    void bqRecorderCallback(SLAndroidSimpleBufferQueueItf bq, void *context) {
       int numOfRecords = fwrite(recorderBuffer, sizeof(short), RECORDER_FRAMES, recordF);
       fflush(recordF);
       recordCnt++;
       SLresult result;
       if (recordCnt*5 < RECORD_TIME) {
        result = (*recorderBufferQueue)->Enqueue(recorderBufferQueue, recorderBuffer,
            RECORDER_FRAMES * sizeof(short));
       } else {
        result = (*recorderRecord)->SetRecordState(recorderRecord, SL_RECORDSTATE_STOPPED);
        if (SL_RESULT_SUCCESS == result) {
          fclose(recordF);
        }
       }
    }
    ```

    `play.c`包含创建音频播放器对象并播放音频的代码。

    `createBufferQueueAudioPlayer`创建并实现一个从缓冲队列播放音频的音频播放器对象：

    ```kt
    void createBufferQueueAudioPlayer() {
       SLresult result;
       SLDataLocator_AndroidSimpleBufferQueue loc_bufq = {SL_DATALOCATOR_ANDROIDSIMPLEBUFFERQUEUE, 1};
       SLDataFormat_PCM format_pcm = {SL_DATAFORMAT_PCM, 1, SL_SAMPLINGRATE_16,
           SL_PCMSAMPLEFORMAT_FIXED_16, SL_PCMSAMPLEFORMAT_FIXED_16,
           SL_SPEAKER_FRONT_CENTER, SL_BYTEORDER_LITTLEENDIAN};
       SLDataSource audioSrc = {&loc_bufq, &format_pcm};
       SLDataLocator_OutputMix loc_outmix = {SL_DATALOCATOR_OUTPUTMIX, outputMixObject};
       SLDataSink audioSnk = {&loc_outmix, NULL};
       const SLInterfaceID ids[3] = {SL_IID_BUFFERQUEUE, SL_IID_EFFECTSEND, SL_IID_VOLUME};
       const SLboolean req[3] = {SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE};
       result = (*engineEngine)->CreateAudioPlayer(engineEngine, &bqPlayerObject, &audioSrc, &audioSnk, 3, ids, req);
       result = (*bqPlayerObject)->Realize(bqPlayerObject, SL_BOOLEAN_FALSE);
       result = (*bqPlayerObject)->GetInterface(bqPlayerObject, SL_IID_PLAY, &bqPlayerPlay);
       result = (*bqPlayerObject)->GetInterface(bqPlayerObject, SL_IID_BUFFERQUEUE,
               &bqPlayerBufferQueue);
       result = (*bqPlayerBufferQueue)->RegisterCallback(bqPlayerBufferQueue, bqPlayerCallback, NULL);
       result = (*bqPlayerObject)->GetInterface(bqPlayerObject, SL_IID_EFFECTSEND,
               &bqPlayerEffectSend);
       result = (*bqPlayerObject)->GetInterface(bqPlayerObject, SL_IID_VOLUME, &bqPlayerVolume);
    }
    ```

    `startPlaying`从`test.cpm`文件填充缓冲区数据并开始播放：

    ```kt
    jboolean startPlaying() {
      SLresult result;
      recordF = fopen("/sdcard/test.pcm", "rb");
      noMoreData = 0;
      int numOfRecords = fread(recorderBuffer, sizeof(short), RECORDER_FRAMES, recordF);
      if (RECORDER_FRAMES != numOfRecords) {
        if (numOfRecords <= 0) {
          return JNI_TRUE;
        }
        noMoreData = 1;
      }   
    result = (*bqPlayerBufferQueue)->Enqueue(bqPlayerBufferQueue, recorderBuffer, RECORDER_FRAMES * sizeof(short));
      result = (*bqPlayerPlay)->SetPlayState(bqPlayerPlay, SL_PLAYSTATE_PLAYING);
      return JNI_TRUE;
    }
    ```

    `bqPlayerCallback`每次缓冲队列准备好接受新的缓冲区时，都会调用这个回调方法。这发生在缓冲区播放完毕时：

    ```kt
    void bqPlayerCallback(SLAndroidSimpleBufferQueueItf bq, void *context) {
       if (!noMoreData) {
            SLresult result;
    int numOfRecords = fread(recorderBuffer, sizeof(short), RECORDER_FRAMES, recordF);
      if (RECORDER_FRAMES != numOfRecords) {
        if (numOfRecords <= 0) {
          noMoreData = 1;
          (*bqPlayerPlay)->SetPlayState(bqPlayerPlay, SL_PLAYSTATE_STOPPED);
          fclose(recordF);
          return;
        }
        noMoreData = 1;
      } 
      result = (*bqPlayerBufferQueue)->Enqueue(bqPlayerBufferQueue, recorderBuffer,  RECORDER_FRAMES * sizeof(short));
       } else {
         (*bqPlayerPlay)->SetPlayState(bqPlayerPlay, SL_PLAYSTATE_STOPPED);
         fclose(recordF);
       }
    }
    ```

    `OpenSLESDemo.cpp`文件包含创建 OpenSL ES 引擎对象、释放对象以及注册本地方法的代码：

    `naCreateEngine`创建引擎对象并输出混合对象。

    ```kt
    void naCreateEngine(JNIEnv* env, jclass clazz) {
       SLresult result;
       result = slCreateEngine(&engineObject, 0, NULL, 0, NULL, NULL);
       result = (*engineObject)->Realize(engineObject, SL_BOOLEAN_FALSE);
       result = (*engineObject)->GetInterface(engineObject, SL_IID_ENGINE, &engineEngine);
       const SLInterfaceID ids[1] = {SL_IID_ENVIRONMENTALREVERB};
       const SLboolean req[1] = {SL_BOOLEAN_FALSE};
       result = (*engineEngine)->CreateOutputMix(engineEngine, &outputMixObject, 1, ids, req);
       result = (*outputMixObject)->Realize(outputMixObject, SL_BOOLEAN_FALSE);
       result = (*outputMixObject)->GetInterface(outputMixObject, SL_IID_ENVIRONMENTALREVERB,
               &outputMixEnvironmentalReverb);
       if (SL_RESULT_SUCCESS == result) {
            result = (*outputMixEnvironmentalReverb)->SetEnvironmentalReverbProperties(
                   outputMixEnvironmentalReverb, &reverbSettings);
       }
    }
    ```

1.  在`AndroidManifest.xml`文件中添加以下权限。

    ```kt
    <uses-permission android:name="android.permission.RECORD_AUDIO"/>
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    <uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS"></uses-permission>
    ```

1.  在`jni`文件夹中添加一个`Android.mk`文件，内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := OpenSLESDemo
    LOCAL_SRC_FILES := OpenSLESDemo.cpp record.c play.c
    LOCAL_LDLIBS := -llog
    LOCAL_LDLIBS    += -lOpenSLES
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  构建并运行 Android 项目，并使用以下命令监控`logcat`输出：

    ```kt
    $ adb logcat -v time OpenSLESDemo:I *:S
    ```

1.  应用的 GUI 如下截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_07_08.jpg)

    +   我们可以通过点击**录音**按钮开始音频录音。录音将持续 15 秒。`logcat`输出将如下截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_07_09.jpg)

    +   录音完成后，将在 Android 设备上创建一个`/sdcard/test.pcm`文件。我们可以点击**播放**按钮来播放音频文件。`logcat`输出将如下截图所示：

    ![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_07_10.jpg)

## 工作原理...

本示例项目展示了如何使用 OpenSL ES 音频库。我们首先解释一些关键概念，然后描述我们是如何使用录音和播放 API 的。

### 对象创建

对象在代码中没有实际的表现形式，对象的创建是通过接口完成的。每个创建对象的方法都返回一个`SLObjectInf`接口，该接口可用于执行对象的基本操作并访问对象的其它接口。对象创建的步骤如下所述：

1.  创建一个引擎对象。引擎对象是 OpenSL ES API 的入口点。创建引擎对象是通过全局函数`slCreateEngine()`完成的，该函数返回一个`SLObjectItf`接口。

1.  实现引擎对象。在对象被实现之前，不能使用该对象。我们将在下一节详细讨论这一点。

1.  通过`SLObjectItf`接口的`GetInterface()`方法获取引擎对象的`SLEngineItf`接口。

1.  调用`SLEngineItf`接口提供的对象创建方法。成功后，将返回新创建对象的`SLObjectItf`接口。

1.  实现新创建的对象。

1.  通过对象的`SLObjectItf`接口操作创建的对象或访问其他接口。

1.  完成对象操作后，调用`SLObjectItf`接口的`Destroy()`方法来释放对象及其资源。

在我们的示例项目中，我们在`OpenSLESDemo.cpp`的`naCreateEngine`函数中创建了并实现了引擎对象，并获得了`SLEngineItf`接口。然后，我们调用了`SLEngineItf`接口暴露的`CreateAudioRecorder()`方法，在`record.c`的`createAudioRecorder`函数中创建了一个音频录音对象。在同一个函数中，我们还实现了录音对象，并通过对象创建时返回的`SLObjectItf`接口访问了对象的其他几个接口。完成录音对象后，我们调用了`Destroy()`方法来释放对象及其资源，如`OpenSLESDemo.cpp`中的`naShutdown`函数所示。

在对象创建时需要注意的另一件事是接口请求。对象创建方法通常接受与接口相关的三个参数，如`SLEngineItf`接口的`CreateAudioPlayer`方法所示，以下代码片段展示了这一点：

```kt
SLresult (*CreateAudioPlayer) (
SLEngineItf self,
SLObjectItf * pPlayer,
SLDataSource *pAudioSrc,
SLDataSink *pAudioSnk,
SLuint32 numInterfaces,
const SLInterfaceID * pInterfaceIds,
const SLboolean * pInterfaceRequired
);
```

最后三个输入参数与接口相关。`numInterfaces`参数表示我们请求访问的接口数量。`pInterfaceIds`是一个包含`numInterfaces`接口 ID 的数组，表示对象应该支持的接口类型。`pInterfaceRequired`是一个`SLboolean`数组，指定请求的接口是可选的还是必需的。在我们的音频播放器示例中，我们调用了`CreateAudioPlayer`方法来请求三种类型的接口（分别由`SL_IID_BUFFERQUEUE`、`SL_IID_EFFECTSEND`和`SL_IID_VOLUME`表示的`SLAndroidSimpleBufferQueueItf`、`SLEffectSendItf`和`SLVolumeItf`）。由于`req`数组中的所有元素都是`true`，因此所有接口都是必需的。如果对象无法提供任何接口，对象创建将失败：

```kt
const SLInterfaceID ids[3] = {SL_IID_BUFFERQUEUE, SL_IID_EFFECTSEND, SL_IID_VOLUME};
const SLboolean req[3] = {SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE,  SL_BOOLEAN_TRUE};
result = (*engineEngine)->CreateAudioPlayer(engineEngine, &bqPlayerObject, &audioSrc, &audioSnk, 3, ids, req);
```

请注意，一个对象可以具有隐式和显式接口。隐式接口对类型的每个对象都是可用的。例如，`SLObjectItf`接口是所有类型所有对象的隐式接口。在对象创建方法中，不需要请求隐式接口。然而，如果我们想要访问一些显式接口，必须在方法中请求它们。

有关接口的更多信息，请参考*OpenSL ES 1.0.1 Specification*文档中的*第 3.1.6 节*，*对象与接口之间的关系*。

### 改变对象的状态

对象创建方法创建一个对象并将其置于未实现状态。在这种状态下，对象的资源尚未分配，因此无法使用。

我们需要调用对象的`SLObjectItf`接口的`Realize()`方法，使对象过渡到实现状态，在该状态下分配资源并且可以访问接口。

一旦我们完成了对象操作，我们调用`Destroy()`方法来释放对象及其资源。这个调用内部将对象转移到未实现阶段，在该阶段释放资源。因此，在释放对象本身之前，首先释放资源。

在这个食谱中，我们使用我们的示例项目展示了录制和播放 API。

### 使用和构建 OpenSL ES 音频库

为了调用 API 函数，我们必须向我们的代码中添加以下行：

```kt
#include <SLES/OpenSLES.h>
```

如果我们也使用安卓特有的功能，我们应该包含另一个头文件：

```kt
#include <SLES/OpenSLES_Android.h>
```

在`Android.mk`文件中，我们必须添加以下行以链接到本地 OpenSL ES 音频库：

```kt
LOCAL_LDLIBS += libOpenSLES
```

### OpenSL ES 音频录制

因为 MIME 数据格式和`SLAudioEncoderItf`接口对安卓上的音频录音机不可用，我们只能以 PCM 格式录制音频。我们的示例展示了如何以 PCM 格式录制音频并将数据保存到文件中。这可以用以下图示说明：

![OpenSL ES 音频录制](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_07_12.jpg)

在`record.c`的`createAudioRecorder`函数中，我们创建并实现了音频录音对象。我们将音频输入设置为数据源，将安卓缓冲队列设置为数据接收端。注意，我们注册了`bqRecorderCallback`函数作为缓冲队列的回调函数。每当缓冲队列准备好新的缓冲区时，将调用`bqRecorderCallback`函数将缓冲区数据保存到`test.cpm`文件中，并将缓冲区重新入队以录制新的音频数据。在`startRecording`函数中，我们开始录音。

### 注意事项

OpenSL ES 中的回调函数是从内部非应用程序线程执行的。这些线程不由 Dalvik VM 管理，因此它们无法访问 JNI。这些线程对 OpenSL ES 实现至关重要，因此回调函数不应该阻塞或执行任何繁重的处理任务。

如果当回调函数被触发时我们需要执行繁重任务，我们应该发布一个事件给另一个线程来处理这些任务。

这同样适用于我们将在下一个食谱中介绍的 OpenMAX AL 库。更详细的信息可以从 NDK OpenSL ES 文档的`docs/opensles/`文件夹中获得。

### OpenSL ES 音频播放

安卓的 OpenSL ES 库为音频播放提供了许多功能。我们可以播放编码的音频文件，包括 mp3、aac 等。我们的示例展示了如何播放 PCM 音频。这可以如下所示图示：

![OpenSL ES 音频播放](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_07_13.jpg)

我们在 `OpenSLESDemo.cpp` 的 `naCreateEngine` 函数中创建了引擎对象和输出混合对象。在 `play.c` 的 `createBufferQueueAudioPlayer` 函数中创建了音频播放器对象，以 Android 缓冲队列作为数据源和输出混合对象作为数据接收器。通过 `SLAndroidSimpleBufferQueueItf` 接口注册了 `bqPlayerCallback` 函数作为回调方法。每当播放器播放完一个缓冲区，缓冲队列就准备好接收新数据，此时会调用回调函数 `bqPlayerCallback`。该方法从 `test.pcm` 文件读取数据到缓冲区并将其入队。

在 `startPlaying` 函数中，我们将初始数据读取到缓冲区，并将播放器状态设置为 `SL_PLAYSTATE_PLAYING`。

## 还有更多...

OpenSL ES 是一个复杂的库，其规范超过 500 页。在开发 OpenSL ES 应用程序时，规范是一个很好的参考，它可以通过 Android NDK 获得。

Android NDK 还附带了一个本地音频示例，演示了更多 OpenSL ES 函数的使用。

# 在 Android NDK 中使用 OpenMAX AL 多媒体库进行编程

OpenMAX AL 是一个用 C 语言编写的应用层多媒体库。Android NDK 多媒体 API 基于 OpenMAX AL 1.0.1 标准，并带有 Android 特定的扩展。该 API 可用于 Android 4.0 或更高版本。需要注意的是，API 正在不断发展，Android NDK 团队提到，未来版本的 OpenMAX AL API 可能会要求开发者更改他们的代码。

## 准备就绪...

在开始使用 OpenMAX AL 库进行编程之前，了解一些关于库的基础知识是很重要的。我们将在以下文本中简要描述该库。

OpenMAX AL 指的是 **Open Media Acceleration**（**OpenMAX**）库的应用层接口。它是一个免版税、跨平台、使用 C 语言的 应用层 API，供开发者创建多媒体应用程序。其主要特性包括媒体记录、媒体播放、媒体控制（例如，亮度控制）和效果。与 OpenSL ES 库相比，OpenMAX AL 提供了视频和音频的功能，但它缺少 OpenSL ES 可以提供的某些音频功能，如 3D 音频和音频效果。某些应用程序可能需要同时使用这两个库。

OpenMAX AL 定义了两个配置文件，分别是媒体播放和媒体播放器/记录器。Android 并没有实现这两个配置文件所需的所有功能，因此 Android 中的 OpenMAX AL 库不符合任何一个配置文件。此外，Android 还实现了一些特定于 Android 的功能。

Android OpenMAX AL 实现提供的主要功能是处理 MPEG-2 传输流的能力。我们可以对流进行解复用，解码视频和音频，并将它们作为音频输出或渲染到手机屏幕。这个库允许我们在将媒体数据传递以供展示之前完全控制它。例如，我们可以在渲染视频数据之前调用 OpenGL ES 函数以应用图形效果。

要了解 Android 支持的内容，我们可以参考随 Android NDK 提供的 OpenMAX AL for Android 文档，位于 `docs/openmaxal/` 文件夹中。

OpenMAX AL 库的设计与 OpenSL ES 库类似。它们都采用面向对象的方法，基本概念包括对象和接口都是相同的。读者应参考之前的食谱以获取这些概念的详细解释。

## 如何操作...

以下步骤描述了如何使用 OpenMAX AL 函数创建一个简单的 Android 视频播放应用程序：

1.  创建一个名为 `OpenMAXSLDemo` 的 Android 应用程序。将包名设置为 `cookbook.chapter7.openmaxsldemo`。有关更详细的说明，请参考 第二章，*Java 本地接口*中的*加载本地库和注册本地方法*食谱。

1.  右键点击项目 **OpenMAXSLDemo**，选择 **Android Tools** | **添加本地支持**。

1.  在包 `cookbook.chapter7.openmaxsldemo` 中添加一个名为 `MainActivity.java` 的 Java 文件。这个 Java 文件加载本地库 `OpenMAXSLDemo`，设置视图，并调用本地方法来播放视频。

1.  在 `jni` 文件夹中添加 `mylog.h` 和 `OpenMAXSLDemo.c` 文件。`OpenMAXSLDemo.c` 的一部分代码在以下代码片段中显示。

    `naCreateEngine` 创建并实现引擎对象和输出混合对象。

    ```kt
    void naCreateEngine(JNIEnv* env, jclass clazz) {
       XAresult res;
       res = xaCreateEngine(&engineObject, 0, NULL, 0, NULL, NULL);
       res = (*engineObject)->Realize(engineObject, XA_BOOLEAN_FALSE);
       res = (*engineObject)->GetInterface(engineObject, XA_IID_ENGINE, &engineEngine);
       res = (*engineEngine)->CreateOutputMix(engineEngine, &outputMixObject, 0, NULL, NULL);
       res = (*outputMixObject)->Realize(outputMixObject, XA_BOOLEAN_FALSE);
    }
    ```

    `naCreateStreamingMediaPlayer` 创建并实现具有数据源和数据接收器的媒体播放器对象。它获取缓冲队列接口，并将 `AndroidBufferQueueCallback` 函数注册为回调函数。回调函数将在处理完缓冲区后被调用：

    ```kt
    jboolean naCreateStreamingMediaPlayer(JNIEnv* env, jclass clazz, jstring filename) {
       XAresult res;
       const char *utf8FileName = (*env)->GetStringUTFChars(env, filename, NULL);
       file = fopen(utf8FileName, "rb");
       XADataLocator_AndroidBufferQueue loc_abq = { XA_DATALOCATOR_ANDROIDBUFFERQUEUE, NB_BUFFERS };
       XADataFormat_MIME format_mime = {XA_DATAFORMAT_MIME, XA_ANDROID_MIME_MP2TS, XA_CONTAINERTYPE_MPEG_TS };
       XADataSource dataSrc = {&loc_abq, &format_mime};
       XADataLocator_OutputMix loc_outmix = { XA_DATALOCATOR_OUTPUTMIX, outputMixObject };
       XADataSink audioSnk = { &loc_outmix, NULL };
       XADataLocator_NativeDisplay loc_nd = {XA_DATALOCATOR_NATIVEDISPLAY,       
               (void*)theNativeWindow, NULL};
       XADataSink imageVideoSink = {&loc_nd, NULL};
       XAboolean required[NB_MAXAL_INTERFACES] = {XA_BOOLEAN_TRUE, XA_BOOLEAN_TRUE};
       XAInterfaceID iidArray[NB_MAXAL_INTERFACES] = {XA_IID_PLAY, XA_IID_ANDROIDBUFFERQUEUESOURCE};
       res = (*engineEngine)->CreateMediaPlayer(engineEngine, &playerObj, &dataSrc, NULL,   &audioSnk, &imageVideoSink, NULL, NULL, NB_MAXAL_INTERFACES, iidArray, required );
       (*env)->ReleaseStringUTFChars(env, filename, utf8FileName);
       res = (*playerObj)->Realize(playerObj, XA_BOOLEAN_FALSE);
       res = (*playerObj)->GetInterface(playerObj, XA_IID_PLAY, &playerPlayItf);
       res = (*playerObj)->GetInterface(playerObj, XA_IID_ANDROIDBUFFERQUEUESOURCE, &playerBQItf);
       res = (*playerBQItf)->SetCallbackEventsMask(playerBQItf, XA_ANDROIDBUFFERQUEUEEVENT_PROCESSED);
       res = (*playerBQItf)->RegisterCallback(playerBQItf, AndroidBufferQueueCallback, NULL);
       if (!enqueueInitialBuffers(JNI_FALSE)) {
           return JNI_FALSE;
       }
       res = (*playerPlayItf)->SetPlayState(playerPlayItf, XA_PLAYSTATE_PAUSED);
       res = (*playerPlayItf)->SetPlayState(playerPlayItf, XA_PLAYSTATE_PLAYING);
       return JNI_TRUE;
    }
    ```

    `AndroidBufferQueueCallback` 是注册的回调函数，用于用媒体数据重新填充缓冲区或处理命令：

    ```kt
    XAresult AndroidBufferQueueCallback(XAAndroidBufferQueueItf caller, void *pCallbackContext, void *pBufferContext,  void *pBufferData, XAuint32 dataSize,  XAuint32 dataUsed, const XAAndroidBufferItem *pItems, XAuint32 itemsLength) {
       XAresult res;
       int ok;
       ok = pthread_mutex_lock(&mutex);
       if (discontinuity) {
           if (!reachedEof) {
               res = (*playerBQItf)->Clear(playerBQItf);
               rewind(file);
                (void) enqueueInitialBuffers(JNI_TRUE);
           }
           discontinuity = JNI_FALSE;
           ok = pthread_cond_signal(&cond);
           goto exit;
       }
       if ((pBufferData == NULL) && (pBufferContext != NULL)) {
           const int processedCommand = *(int *)pBufferContext;
           if (kEosBufferCntxt == processedCommand) {
               goto exit;
           }
       }
       if (reachedEof) {
           goto exit;
       }
       size_t nbRead;
       size_t bytesRead;
       bytesRead = fread(pBufferData, 1, BUFFER_SIZE, file);
       if (bytesRead > 0) {
           if ((bytesRead % MPEG2_TS_PACKET_SIZE) != 0) {
               LOGI(2, "Dropping last packet because it is not whole");
           }
           size_t packetsRead = bytesRead / MPEG2_TS_PACKET_SIZE;
           size_t bufferSize = packetsRead * MPEG2_TS_PACKET_SIZE;
           res = (*caller)->Enqueue(caller, NULL, pBufferData, bufferSize, NULL, 0);
       } else {
           XAAndroidBufferItem msgEos[1];
           msgEos[0].itemKey = XA_ANDROID_ITEMKEY_EOS;
           msgEos[0].itemSize = 0;
           res = (*caller)->Enqueue(caller, (void *)&kEosBufferCntxt, NULL, 0, msgEos, sizeof(XAuint32)*2);
           reachedEof = JNI_TRUE;
       }
    exit:
       ok = pthread_mutex_unlock(&mutex);
       return XA_RESULT_SUCCESS;
    }
    ```

1.  在 `jni` 文件夹中添加一个 `Android.mk` 文件，内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := OpenMAXSLDemo
    LOCAL_SRC_FILES := OpenMAXSLDemo.c
    LOCAL_LDLIBS := -llog
    LOCAL_LDLIBS    += -landroid
    LOCAL_LDLIBS    += -lOpenMAXAL
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  我们可以使用 `samples/native-media/` 目录中可用的 `NativeMedia.ts` 视频文件进行测试。以下命令可以将视频文件放入测试 Android 设备的 `/sdcard/` 目录中：

    ```kt
    $ adb push NativeMedia.ts /sdcard/
    ```

1.  构建并启动 Android 应用程序。我们可以看到如下截图所示的 GUI：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_07_14.jpg)

    我们可以按下 **播放** 开始播放视频。

## 它是如何工作的...

在此食谱中，我们使用了 OpenMAX AL 库来实现一个简单的视频播放器。

### 使用 OpenMAX AL 多媒体库进行构建和使用：

为了调用 API 函数，我们必须在代码中添加以下行：

```kt
#include <OMXAL/OpenMAXAL.h>
```

如果我们也在使用 Android 特定的功能，我们应该包含另一个头文件：

```kt
#include <OMXAL/OpenMAXAL_Android.h>
```

在 `Android.mk` 文件中，我们必须添加以下行以链接到 OpenMAX AL 多媒体库：

```kt
LOCAL_LDLIBS += libOpenMAXAL
```

### OpenMAX AL 视频播放

我们的示例项目是随 Android NDK 一起提供的原生媒体项目的简化版本。下图说明了应用程序的工作原理：

![OpenMAX AL 视频播放](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_07_15.jpg)

在我们的代码中，在 `naCreateEngine` 函数中创建并实现了引擎和输出混合对象。在 `naCreateStreamingMediaPlayerfunction` 函数中，我们创建并实现了媒体播放器对象，将音频数据接收器设置为输出混合，视频数据接收器设置为本地显示，数据源设置为 Android 缓冲队列。

当一个缓冲区被消耗时，会调用回调函数 `AndroidBufferQueueCallback`，我们在其中用 `NativeMedia.ts` 文件中的数据重新填充缓冲区，并将其加入缓冲队列。

## 还有更多……

OpenMAX AL 是一个复杂的库。在开发具有 OpenMAX AL 的应用程序时，规范是一个很好的参考，并且它随 Android NDK 一起提供。Android NDK 还附带了一个原生媒体示例，这个示例很好地展示了如何使用 API。


# 第八章：使用 Android NDK 移植和使用现有库

在本章中，我们将介绍以下食谱：

+   使用 Android NDK 构建系统将库作为共享库模块移植

+   使用 Android NDK 构建系统将库作为静态库模块移植

+   使用 Android NDK 工具链移植使用现有构建系统的库

+   将库作为预构建库使用

+   在多个项目中使用 import-module 引入库

+   移植需要 RTTI、异常和 STL 支持的库

# 引言

对于桌面计算领域有许多 C/C++库。如果我们能在 Android 平台上重用它们，这些库可以为我们节省大量的努力。Android NDK 使这成为可能。在本章中，我们将讨论如何使用 NDK 将现有库移植到 Android。

我们将首先介绍如何使用 Android NDK 构建系统构建库。我们可以将库构建为静态库模块或共享库模块。本章将讨论这两种方式的区别。

我们还可以将 Android NDK 工具链作为独立的交叉编译器使用，这将在下一节介绍。然后，我们将描述如何使用编译后的库作为预构建模块。

我们经常在多个 Android 项目中使用同一个库。我们可以使用 **import-module** 功能将相同的库模块链接到多个项目，同时保持库的单个副本。

许多 C++库需要 STL、C++异常和**运行时类型信息**（**RTTI**）的支持，这些在 Android 默认的 C++运行时库中是不可用的。我们将通过使用流行的 `boost` 库作为示例，说明如何启用这些支持。

# 使用 Android NDK 构建系统将库作为共享库模块移植

本食谱将讨论如何使用 Android NDK 构建系统将现有库作为一个共享库进行移植。我们将以开源的 `libbmp` 库为例。

## 准备工作

建议读者在阅读本节之前先阅读第三章中的*在命令行构建 Android NDK 应用程序*食谱，*构建和调试 NDK 应用程序*。

## 如何操作...

以下步骤描述了如何创建我们的示例 Android 项目，演示如何将 libbmp 库作为共享库进行移植：

1.  创建一个名为 `PortingShared` 的 Android 应用程序，并具有本地支持。将包名设置为 `cookbook.chapter8.portingshared`。如果你需要更详细的说明，请参考第二章中的*加载本地库和注册本地方法*食谱，*Java Native Interface*。

1.  在 `cookbook.chapter8.portingshared` 包下添加一个 Java 文件 `MainActivity.java`。这个 Java 文件简单加载共享库 `.bmp` 和 `PortingShared`，并调用本地方法 `naCreateABmp`。

1.  从[`code.google.com/p/libbmp/downloads/list`](http://code.google.com/p/libbmp/downloads/list)下载`libbmp`库，并解压存档文件。在`jni`文件夹下创建一个名为`libbmp`的文件夹，并将提取的文件夹中的`src/bmpfile.c`和`src/bmpfile.h`文件复制到`libbmp`文件夹。

1.  如果您使用的是 NDK r8 及以下版本，请从`bmpfile.h`中删除以下代码：

    ```kt
    #ifndef uint8_t
    typedef unsigned char uint8_t;
    #endif
    #ifndef uint16_t
    typedef unsigned short uint16_t;
    #endif
    #ifndef uint32_t
    typedef unsigned int uint32_t;
    #endif
    ```

1.  然后，添加以下代码行：

    ```kt
    #include <stdint.h>
    ```

    ### 注意

    对`bmpfile.h`的代码更改仅适用于 Android NDK r8 及以下版本。编译库将返回错误`"error: redefinition of typedef 'uint8_t'"`。这是 NDK 构建系统中的一个错误，因为`uint8_t`的定义被`#ifndef`预处理指令包围。从 NDK r8b 开始，这个问题已被修复，如果我们使用 r8b 及以上版本，则无需更改代码。

1.  在`libbmp`文件夹下创建一个`Android.mk`文件，以将`libbmp`编译为共享库`libbmp.so`。此`Android.mk`文件的内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := libbmp
    LOCAL_SRC_FILES := bmpfile.c
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  在`jni`文件夹下创建另一个名为`libbmptest`的文件夹。在其下添加`mylog.h`和`PortingShared.c`文件。`PortingShared.c`实现了本地方法`naCreateABmp`，该方法使用`libbmp`库中定义的函数来创建位图图像并将其保存到`/sdcard/test_shared.bmp`。如果您的设备上没有`/sdcard`目录，您需要更改目录：

    ```kt
    void naCreateABmp(JNIEnv* env, jclass clazz, jint width, jint height, jint depth) {
      bmpfile_t *bmp;
      int i, j;
      rgb_pixel_t pixel = {128, 64, 0, 0};
      for (i = 10, j = 10; j < height; ++i, ++j) {
        bmp_set_pixel(bmp, i, j, pixel);
        pixel.red++;
        pixel.green++;
        pixel.blue++;
        bmp_set_pixel(bmp, i + 1, j, pixel);
        bmp_set_pixel(bmp, i, j + 1, pixel);
      }
      bmp_save(bmp, "/sdcard/test_shared.bmp");
      bmp_destroy(bmp);
    }
    ```

1.  在`libbmptest`文件夹下创建另一个`Android.mk`文件，以将`PortingShared.c`文件编译为另一个共享库`libPortingShared.so`。此`Android.mk`文件的内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := PortingShared
    LOCAL_C_INCLUDES := $(LOCAL_PATH)/../libbmp/
    LOCAL_SRC_FILES := PortingShared.c
    LOCAL_SHARED_LIBRARIES := libbmp
    LOCAL_LDLIBS := -llog
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  在`jni`文件夹下创建一个`Android.mk`文件，内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(call all-subdir-makefiles)
    ```

1.  向`AndroidManifest.xml`文件添加`WRITE_EXTERNAL_STORAGE`权限，如下所示：

    ```kt
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    ```

1.  构建并运行 Android 项目。在 Android 设备的`sdcard`文件夹中应创建一个位图文件`test_shared.bmp`。我们可以使用以下命令获取该文件：

    ```kt
    $ adb pull /sdcard/test_shared.bmp .
    ```

    以下是`.bmp`文件：

    ![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_08_01.jpg)

## 工作原理...

示例项目演示了如何将`libbmp`代码作为共享库进行移植并在本地代码`PortingShared.c`中使用。

**共享库**：共享库可以被多个可执行文件和库共享。Android 本地代码通常被编译为共享库并由 Java 代码加载。实际上，Android 构建系统只将共享库打包到应用程序的`apk`文件中。因此，我们必须至少提供一个共享库来包含我们的本地代码。

### 注意

我们仍然可以使用静态库来生成共享库，正如我们将在*将库作为静态库模块与 Android NDK 构建系统*的配方中看到的那样。

我们的示例项目构建了两个共享库，分别是`libbmp.so`和`libPortingShared.so`。我们可以在项目的`libs`文件夹下找到这些库。`libPortingShared.so`依赖于`libbmp.so`，因为`PortingShared.c`调用了`libbmp`库中定义的函数。

在我们的 Java 文件中，我们需要在`libPortingShared.so`之前加载`libbmp.so`，如下所示：

```kt
static {
       System.loadLibrary("bmp");
         System.loadLibrary("PortingShared");
}
```

**理解 Android.mk 文件**：Android NDK 提供了一个易于使用的构建系统，使我们免于编写 makefile。然而，我们仍然需要通过`Android.mk`和`Application.mk`向系统提供一些基本输入。本节仅讨论`Android.mk`。

`Android.mk`文件是一个 GNU makefile 片段，它向 Android 构建系统描述源文件。源文件被分组到模块中。每个模块都是一个静态或共享库。Android NDK 提供了一些预定义的变量和宏。这里，我们将简要介绍本节中使用的那些。我们将在后续的菜谱中介绍更多预定义的变量和宏，你也可以参考 Android NDK 的`docs/ANDROID-MK.html`获取更多信息。

+   `CLEAR_VARS`：此变量指向一个脚本，它取消定义几乎所有模块描述变量，除了`LOCAL_PATH`。我们必须在每个新模块之前包含它，如下所示：

    ```kt
    include $(CLEAR_VARS)
    ```

+   `BUILD_SHARED_LIBRARY`：此变量指向一个构建脚本，它根据模块描述确定如何从列出的源构建共享库。包含此变量时，我们必须定义`LOCAL_MODULE`和`LOCAL_SRC_FILES`，如下所示：

    ```kt
    include $(BUILD_SHARED_LIBRARY)
    ```

    包含它将生成共享库`lib$(LOCAL_MODULE).so`。

+   `my-dir`：必须使用`$(call <macro>)`来评估它。`my-dir`宏返回最后一个包含的 makefile 的路径，这通常是包含当前`Android.mk`文件的目录。它通常用于定义`LOCAL_PATH`，如下所示：

    ```kt
    LOCAL_PATH := $(call my-dir)
    ```

+   `all-subdir-makefiles`：此宏返回当前`my-dir`路径下所有子目录中的`Android.mk`文件列表。在我们的示例中，我们在`jni`目录下的`Android.mk`文件中使用了这个宏，如下所示：

    ```kt
    include $(call all-subdir-makefiles)
    ```

    这将包含`libbmp`和`libbmptest`目录下的两个`Android.mk`文件。

+   `LOCAL_PATH`：这是一个模块描述变量，用于定位源文件的路径。它通常与`my-dir`宏一起使用，如下所示：

    ```kt
    LOCAL_PATH := $(call my-dir)
    ```

+   `LOCAL_MODULE`：这是一个模块描述变量，用于定义我们模块的名称。请注意，它必须在所有模块名称中唯一，并且不能包含任何空格。

+   `LOCAL_SRC_FILES`：这是一个模块描述变量，用于列出构建模块时使用的源文件。注意，这些源文件应该是相对于`LOCAL_PATH`的路径。

+   `LOCAL_C_INCLUDES`：这是一个可选的模块描述变量，它提供将附加到编译时包含搜索路径的路径列表。这些路径应该是相对于 NDK 根目录的。在我们的示例项目的`libbmptest`文件夹下的`Android.mk`中，我们使用这个变量如下：

    ```kt
    LOCAL_C_INCLUDES := $(LOCAL_PATH)/../libbmp/
    ```

+   `LOCAL_SHARED_LIBRARIES`：这是一个可选的模块描述变量，提供当前模块依赖的共享库列表。在`libbmptest`文件夹下的`Android.mk`中，我们使用这个变量来包含`libbmp.so`共享库：

    ```kt
    LOCAL_SHARED_LIBRARIES := libbmp
    ```

+   `LOCAL_LDLIBS`：这是一个可选的模块描述变量，提供链接器标志列表。它用于传递带有`-l`前缀的系统库。在我们的示例项目中，我们使用它来链接系统日志库：

    ```kt
    LOCAL_LDLIBS := -llog
    ```

有了前面的描述，现在可以很容易地理解我们示例项目中使用的三个`Android.mk`文件。`jni`下的`Android.mk`简单地包含了另外两个`Android.mk`文件。`libbmp`文件夹下的`Android.mk`将`libbmp`源代码编译为共享库`libbmp.so`，而`libbmptest`文件夹下的`Android.mk`将`PortingShared.c`编译为依赖于`libbmp.so`库的`libPortingShared.so`共享库。

## 另请参阅

可以在本地代码中使用共享库，正如我们在第六章的*使用 Android NDK 动态链接库进行编程*食谱中演示的那样，*其他 Android NDK API*。

# 使用 Android NDK 构建系统将库作为静态库模块移植

前一个食谱讨论了如何将库作为共享库模块移植，以`libbmp`库为例。在本食谱中，我们将展示如何将`libbmp`库作为静态库移植。

## 准备就绪

建议读者在阅读本食谱之前，先阅读第三章的*在命令行构建 Android NDK 应用程序*食谱，*构建和调试 NDK 应用程序*。

## 如何操作...

以下步骤描述了如何创建我们的示例 Android 项目，演示如何将`libbmp`库作为静态库移植：

1.  创建一个名为`PortingStatic`的具有本地支持的 Android 应用程序。将包名设置为`cookbook.chapter8.portingstatic`。如果你需要更详细的说明，请参考第二章的*加载本地库和注册本地方法*食谱，*Java Native Interface*。

1.  在`cookbook.chapter8.portingstatic`包下添加一个 Java 文件`MainActivity.java`。这个 Java 文件简单地加载共享库`PortingStatic`，并调用本地方法`naCreateABmp`。

1.  按照第 3 步的*使用 Android NDK 构建系统将库作为共享库模块移植*食谱下载`libbmp`库并进行修改。

1.  在`libbmp`文件夹下创建一个`Android.mk`文件，以编译`libbmp`为静态库`libbmp.a`。这个`Android.mk`文件的内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := libbmp
    LOCAL_SRC_FILES := bmpfile.c
    include $(BUILD_STATIC_LIBRARY)
    ```

1.  在`jni`文件夹下创建另一个文件夹`libbmptest`。向其中添加`mylog.h`和`PortingStatic.c`文件。注意，它的代码与之前章节中的`naCreateABmp`方法相同，只是`.bmp`文件名从`test_shared.bmp`更改为`test_static.bmp`。

1.  在`libbmptest`文件夹下创建另一个`Android.mk`文件，以编译`PortingStatic.c`文件作为共享库`libPortingStatic.so`。这个`Android.mk`文件的内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir
    include $(CLEAR_VARS)
    LOCAL_MODULE    := PortingStatic
    LOCAL_C_INCLUDES := $(LOCAL_PATH)/../libbmp/
    LOCAL_SRC_FILES := PortingStatic.c
    LOCAL_STATIC_LIBRARIES := libbmp
    LOCAL_LDLIBS := -llog
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  在`jni`文件夹下创建一个`Android.mk`文件，内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(call all-subdir-makefiles)
    ```

1.  向`AndroidManifest.xml`文件添加`WRITE_EXTERNAL_STORAGE`权限，如下所示：

    ```kt
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    ```

1.  构建并运行 Android 项目。应该在 Android 设备的`sdcard`文件夹中创建位图文件`test_static.bmp`。我们可以使用以下命令获取该文件：

    ```kt
    $ adb pull /sdcard/test_static.bmp .
    ```

    这个文件与上一个食谱中使用的`test_static.bmp`文件相同。

## 工作原理...

在示例项目中，我们将`libbmp`构建为静态库`libbmp.a`，可以在`obj/local/armeabi/`文件夹下找到。我们在本地代码`PortingStatic.c`中调用了在`libbmp`中定义的函数。

**静态库**仅仅是从源代码编译的对象文件的归档。在 Android NDK 中，它们被构建为以"`.a`"后缀结尾的文件。静态库在构建时由编译器或链接器复制到目标可执行文件或库中。在 Android NDK 中，静态库仅用于构建共享库，因为只有共享库会被打包到`apk`文件中以便部署。

我们的示例项目构建了一个静态库`libbmp.a`和一个共享库`libPortingStatic.so`。`libPortingStatic.so`共享库位于`libs/armeabi`文件夹下，将被复制到应用程序的`apk`文件中。`libbmp.a`库用于构建`libPortingStatic.so`共享库。如果你使用 Eclipse 项目资源管理器检查`libPortingStatic.so`库的符号，你会发现`libbmp`中定义的函数的符号被包含在内。以下截图展示了这一点：

![工作原理...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_08_02.jpg)

函数`bmp_create`、`bmp_destroy`等在`libbmp`中定义，并包含在共享库`libPortingStatic.so`中。

在我们的 Java 代码中，我们需要使用以下代码加载共享库：

```kt
static {
       System.loadLibrary("PortingStatic");
}
```

**理解 Android.mk 文件**：上一个食谱已经描述了在这三个`Android.mk`文件中使用的预定义变量和宏的大部分内容。因此，我们只涉及那些在上一个食谱中没有看到的内容：

+   `BUILD_STATIC_LIBRARY`：该变量指向一个构建脚本，该脚本将收集模块的信息并确定如何从源代码构建静态库。通常在另一个模块的`LOCAL_STATIC_LIBRARIES`中列出构建的模块。这个变量通常在`Android.mk`中如下包含：

    ```kt
    include $(BUILD_STATIC_LIBRARY)
    ```

    在我们的示例项目中，我们在`jni/libbmp`文件夹下的`Android.mk`文件中包含了这个变量。

+   `LOCAL_STATIC_LIBRARIES`：这是一个模块描述变量，它提供当前模块应链接到的静态库列表。它只在共享库模块中有意义。

    在我们的项目中，我们使用这个变量链接到`libbmp.a`静态库，如`jni/libbmptest/`文件夹下的`Android.mk`文件所示。

    ```kt
    LOCAL_STATIC_LIBRARIES := libbmp
    ```

+   `LOCAL_WHOLE_STATIC_LIBRARIES`：这是`LOCAL_STATIC_LIBRARIES`变量的一个变体。它指示列出的静态库应该作为完整的归档链接。这将强制将静态库中的所有对象文件添加到当前的共享库模块中。

**静态库与共享库**：现在你已经了解了如何将现有库作为静态库或共享库移植，你可能会问哪个更好。答案可能如你所料，取决于我们的需求。

当你移植一个大型库，并且只使用了库提供的一小部分功能时，静态库是一个好的选择。Android NDK 构建系统可以在构建时解决依赖关系，并且只将最终共享库中使用的那部分复制。这意味着库的大小更小，相应的`apk`文件大小也更小。

### 注意事项

有时，我们需要强制将整个静态库构建到最终的共享库中（例如，几个静态库之间存在循环依赖）。我们可以在`Android.mk`中使用`LOCAL_WHOLE_STATIC_LIBRARIES`变量或"`--whole-archive`"链接器标志。

当你需要移植一个将被多个 Android 应用使用的库时，共享库是一个更好的选择。假设你想要构建两个 Android 应用，一个是视频播放器，一个是视频编辑器。这两个应用都需要一个第三方`codec`库，你可以使用 NDK 将其移植到 Android 上。在这种情况下，你可以将库作为一个共享库单独放在一个`apk`文件中（例如，MX Player 将`codecs`库放在单独的`apk`文件中），这样两个应用可以在运行时加载同一个库。这意味着用户只需下载一次库就可以使用这两个应用。

另一个可能需要共享库的情况是，一个库`L`被多个共享库使用。如果`L`是一个静态库，每个共享库将包含其代码的副本，并因代码重复（例如，重复的全局变量）而造成问题。

## 另请参阅

实际上，我们之前使用 Android NDK 构建系统将一个库作为静态库移植过。回想一下我们在第五章的*在 Android NDK 上管理资产*菜谱中，如何将`libpng`作为静态库移植的。

# 使用 Android NDK 工具链移植带有现有构建系统的库

前两个食谱讨论了如何使用 Android NDK 构建系统移植库。然而，许多开源项目都有自己的构建系统，有时在`Android.mk`文件中列出所有源文件会很麻烦。幸运的是，Android NDK 工具链也可以作为一个独立的交叉编译器使用，我们可以将交叉编译器用在开源项目的现有构建系统中。这个食谱将讨论如何使用现有的构建系统移植库。

## 如何操作...

以下步骤描述了如何创建我们的示例项目，该项目展示了如何使用现有的构建系统移植开源`libbmp`库：

1.  创建一个名为 PortingWithBuildSystem 的 Android 应用程序，并支持本地原生代码。将包名设置为`cookbook.chapter8.portingwithbuildsystem`。如果你需要更详细的说明，请参考第二章的*加载本地库和注册本地方法*食谱，*Java Native Interface*。

1.  在`cookbook.chapter8.portingwithbuildsystem`包下添加一个 Java 文件`MainActivity.java`。这个 Java 文件简单地加载共享库`PortingWithBuildSystem`，并调用本地方法`naCreateABmp`。

1.  从[`code.google.com/p/libbmp/downloads/list`](http://code.google.com/p/libbmp/downloads/list)下载`libbmp`库，并将归档文件解压到`jni`文件夹。这将在`jni`文件夹下创建一个`libbmp-0.1.3`文件夹，内容如下：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_08_03.jpg)

1.  按照食谱*将库作为共享库模块与 Android NDK 构建系统一起移植*的第 3 步，更新`src/bmpfile.h`。

1.  在`libbmp-0.1.3`文件夹下添加一个 bash shell 脚本文件`build_android.sh`，内容如下：

    ```kt
    #!/bin/bash
    NDK=<path to Android ndk folder>/android-ndk-r8b
    SYSROOT=$NDK/platforms/android-8/arch-arm/
    CFLAGS="-mthumb"
    LDFLAGS="-Wl,--fix-cortex-a8"
    export CC="$NDK/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86/bin/arm-linux-androideabi-gcc --sysroot=$SYSROOT"
    ./configure \
       --host=arm-linux-androideabi \
       --disable-shared \
       --prefix=$(pwd) \
       --exec-prefix=$(pwd) 
    make clean
    make 
    make install
    ```

1.  使用以下命令为`build_android.sh`文件添加执行权限：

    ```kt
    $ sudo chmod +x build_android.sh
    ```

1.  在命令行终端，转到`libbmp-0.1.3`目录，输入以下命令来构建库：

    ```kt
    $ ./build_android.sh
    ```

    构建将会因为以下错误而失败：

    ![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_08_04.jpg)

    这是因为`libbmp-0.1.3`文件夹下的`config.guess`和`config.sub`脚本过时了（这两个文件的第一行表明时间戳是`2009-08-19`）。我们需要时间戳为`2010-05-20`或之后的脚本副本。可以在[`gcc.gnu.org/svn/gcc/branches/cilkplus/config.guess`](http://gcc.gnu.org/svn/gcc/branches/cilkplus/config.guess)找到`config.guess`脚本，在[`gcc.gnu.org/svn/gcc/branches/cilkplus/config.sub`](http://gcc.gnu.org/svn/gcc/branches/cilkplus/config.sub)找到`config.sub`脚本。

1.  再次尝试执行`build_android.sh`脚本。这次它成功完成了。我们应当在`jni/libbmp-0.1.3/lib`文件夹下找到`libbmp.a`静态库，在`jni/libbmp-0.1.3/include`文件夹下找到`bmpfile.h`。

## 工作原理...

许多现有的开源库可以通过 shell 命令"`./configure; make; make install`"来构建。在我们的示例项目中，我们编写了一个`build_android.sh`脚本来使用 Android NDK 交叉编译器执行这三个步骤。

以下是我们使用 Android NDK 交叉编译器移植库时应该考虑的事项列表：

1.  **选择合适的工具链**：根据我们目标设备（ARM、x86 或 MIPS）的 CPU 架构，你需要选择相应的工具链。以下工具链可在 Android NDK r8d 的`toolchains`文件夹下找到：

    +   **对于基于 ARM 的设备**：`arm-linux-androideabi-4.4.3`，`arm-linux-androideabi-4.6`，`arm-linux-androideabi-4.7`，以及`arm-linux-androideabi-clang3.1`

    +   **对于基于 MIPS 的设备**：`mipsel-linux-android-4.4.3`，`mipsel-linux-android-4.6`，`mipsel-linux-android-4.7`，以及`mipsel-linux-android-clang3.1`

    +   **对于基于 x86 的设备**：`x86-4.4.3`，`x86-4.6`，`x86-4.7`，以及`x86-clang3.1`

1.  **选择 sysroot**：根据我们想要针对的 Android 原生 API 级别和 CPU 架构，你需要选择合适的 sysroot。编译器在编译时会查找`sysroot`目录下的头文件和库。

    `sysroot`的路径遵循以下格式：

    ```kt
    $NDK/platforms/android-<level>/arch-<arch>/
    ```

    `$NDK`指的是 Android NDK 的根目录，`<level>`指的是 Android API 级别，`<arch>`表示 CPU 架构。在你的`build_android.sh`脚本中，`SYSROOT`定义如下： 

    ```kt
    SYSROOT=$NDK/platforms/android-8/arch-arm/
    ```

1.  **指定交叉编译器**：库现有的构建系统通常有一种方法让我们指定交叉编译器。这通常是通过配置选项或环境变量来实现的。

    在`libbmp`中，我们可以输入"`./configure --help`"命令来了解如何设置编译器。`compiler`命令是通过环境变量`CC`指定的，而环境变量`CFLAGS`和`LDFLAGS`用于指定编译器标志和链接器标志。在你的`build_android.sh`脚本中，这三个环境变量如下设置：

    ```kt
    export CFLAGS="-mthumb"
    export LDFLAGS="-Wl,--fix-cortex-a8"
    export CC="$NDK/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86/bin/arm-linux-androideabi-gcc --sysroot=$SYSROOT"
    ```

    ### 注意

    "`-mthumb`"编译器标志表示你将使用 thumb 指令集而不是 ARM 指令集。"`-wl, --fix-cortex-a8`"链接器标志是为了绕过某些 Cortex-A8 实现中的 CPU 错误。

1.  **指定头文件和库二进制文件的输出位置**：你通常希望将库放在`jni/<library folder>/`下。

    在`libbmp`的情况下，库二进制文件安装在`PREFIX/lib`文件夹下，头文件安装在`EPREFIX/include`文件夹下。因此，我们通过向配置脚本传递以下选项，将`PREFIX`和`EPREFIX`设置为`jni/libbmp-0.1.3`：

    ```kt
    --prefix=$(pwd) \
    --exec-prefix=$(pwd)
    ```

1.  **构建并安装库**：你可以简单地执行"`make; make install;`"来构建和安装库。

## 还有更多...

在你的`build_android.sh`脚本中，我们已经禁用了共享库。如果你删除了这行"`--disable-shared \`"，构建将在`jni/libbmp-0.1.3/lib/`文件夹下生成共享库（`libbmp.so`）和静态库（`libbmp.a`）。

在你的示例项目中，我们直接使用了 NDK 工具链。这种方法有一个严重的限制，即你不能使用任何 C++ STL 函数，且 C++异常和 RTTI 不支持。实际上，Android NDK 允许你使用脚本`$NDK/build/tools/make-standalone-toolchain.sh`创建一个自定义的工具链安装。假设你的目标是 Android API 级别 8；你可以使用以下命令在`/tmp/my-android-toolchain`文件夹中安装工具链。

```kt
$ANDROID_NDK/build/tools/make-standalone-toolchain.sh --platform=android-8 --install-dir=/tmp/my-android-toolchain
```

你可以使用以下命令来使用这个工具链：

```kt
export PATH=/tmp/my-android-toolchain/bin:$PATH
export CC=arm-linux-androideabi-gcc
```

请注意，安装的工具链将在`/tmp/my-android-toolchain/arm-linux-androideabi/lib/`文件夹下拥有几个库（`libgnustl_shared.so`、`libstdc++.a`和`libsupc++.a`）。你可以链接这些库以启用异常、RTTI 和 STL 函数支持。我们将在*需要 RTTI 的库移植*配方中进一步讨论异常和 STL 支持。

有关将 Android 工具链作为独立编译器使用的更多信息，请参见 Android NDK 中的`docs/STANDALONE-TOOLCHAIN.html`。

# 将库作为预构建库使用

上一个配方描述了如何使用自己的构建系统构建现有库。我们获得了开源`libbmp`库的编译静态库`libbmp.a`。这个配方将讨论如何使用预构建库。

## 如何操作...

以下步骤构建了一个使用预构建库的 Android NDK 应用程序。请注意，示例项目基于我们之前配方的操作。如果你还没有完成之前的配方，现在应该去做。

1.  打开你在之前配方中创建的`PortingWithBuildSystem`项目。在`cookbook.chapter8.portingwithbuildsystem`包下添加一个 Java 文件`MainActivity.java`。这个 Java 文件只是加载共享库`PortingWithBuildSystem`，并调用本地方法`naCreateABmp`。

1.  在此目录下添加`mylog.h`和`PortingWithBuildSystem.c`文件。`PortingWithBuildSystem.c`实现了本地方法`naCreateABmp`。

1.  在`jni`文件夹下创建一个`Android.mk`文件，以编译`PortingWithBuildSystem.c`作为共享库`libPortingWithBuildSystem.so`。此`Android.mk`文件的内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE := libbmp-prebuilt
    LOCAL_SRC_FILES := libbmp-0.1.3/lib/libbmp.a
    LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/libbmp-0.1.3/include/
    include $(PREBUILT_STATIC_LIBRARY)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := PortingWithBuildSystem
    LOCAL_SRC_FILES := PortingWithBuildSystem.c
    LOCAL_STATIC_LIBRARIES := libbmp-prebuilt
    LOCAL_LDLIBS := -llog
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  在`AndroidManifest.xml`文件中添加`WRITE_EXTERNAL_STORAGE`权限，如下所示：

    ```kt
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    ```

1.  构建并运行 Android 项目。应该在 Android 设备的`sdcard`文件夹中创建位图文件`test_bs_static.bmp`。我们可以使用以下命令来获取该文件：

    ```kt
    $ adb pull /sdcard/test_bs_static.bmp .
    ```

    该文件与本章中*将库作为共享库模块与 Android NDK 构建系统*的配方中显示的`test_static.bmp`文件相同。

## 它的工作原理...

预构建库有两种常见用例：

+   你想使用第三方开发者的库，而只提供了库的二进制文件

+   你已经构建了一个库，并希望在不重新编译的情况下使用该库

你的示例项目属于第二种情况。让我们看看在 Android NDK 中使用预构建库时需要考虑的事项：

1.  **声明一个预构建库模块**：在 Android NDK 中，构建模块可以是静态库或共享库。你已经看到了如何用源代码声明一个模块。当模块基于预构建的库时，声明方式类似。

    i. **声明模块名称**：这是通过`LOCAL_MODULE`模块描述变量完成的。在你的示例项目中，使用以下行定义模块名称：

    ```kt
    	LOCAL_MODULE := libbmp-prebuilt
    ```

    ii. **列出预构建库的源代码**：你需要将预构建库的路径提供给`LOCAL_SRC_FILES`变量。注意，该路径是相对于`LOCAL_PATH`的。在你的示例项目中，以下列方式列出`libbmp.a`静态库的路径：

    ```kt
    	LOCAL_SRC_FILES := libbmp-0.1.3/lib/libbmp.a
    ```

    iii. **导出库头文件**：这是通过`LOCAL_EXPORT_C_INCLUDES`模块描述变量完成的。该变量确保任何依赖预构建库模块的模块都会自动将库头文件的路径追加到`LOCAL_C_INCLUDES`中。注意，这一步是可选的，因为我们可以显式地将库头文件的路径添加到任何依赖预构建库模块的模块中。然而，最好是将头文件导出，而不是将路径添加到每个依赖预构建库模块的模块中。

    在你的示例项目中，通过在`Android.mk`文件中添加以下行来导出库头文件：

    ```kt
    LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/libbmp-0.1.3/include/
    ```

    iv. **导出编译器和/或链接器标志**：这可以通过`LOCAL_EXPORT_CFLAGS`、`LOCAL_EXPORT_CPPFLAGS`和`LOCAL_EXPORT_LDLIBS`来完成。这一步也是可选的，我们在你的示例项目中不会使用它们。你可以参考 Android NDK 中的`docs/ANDROID-MK.html`获取关于这些模块描述变量的更详细信息。

    v. **声明构建类型**：对于共享预构建库，你需要包含`PREBUILT_SHARED_LIBRARY`，对于静态预构建库，需要包含`PREBUILT_STATIC_LIBRARY`。在你的示例项目中，使用以下行来声明你想要构建一个预构建的静态库模块： 

    ```kt
    	include $(PREBUILT_STATIC_LIBRARY) 
    ```

1.  **使用预构建的库模块**：一旦你有了预构建的库模块，你只需在任何依赖该预构建库的模块的`LOCAL_STATIC_LIBRARIES`或`LOCAL_SHARED_LIBRARIES`声明中列出模块名称即可。这在你的示例项目的`Android.mk`文件中有展示：

    ```kt
    LOCAL_STATIC_LIBRARIES := libbmp-prebuilt
    ```

1.  **用于调试的预构建库**：Android NDK 建议你提供包含调试符号的预构建库二进制文件，以便使用`ndk-gdb`进行调试。当你将库打包进`apk`文件时，将使用 Android NDK 创建的剥离版本（位于项目的`libs/<abi>/`文件夹中）。

    ### 提示

    我们不讨论如何生成库的调试版本，因为这取决于库是如何构建的。通常，库的文档将包含如何生成调试构建的说明。如果您直接使用 GCC 构建库，那么您可以参考[`gcc.gnu.org/onlinedocs/gcc/Debugging-Options.html`](http://gcc.gnu.org/onlinedocs/gcc/Debugging-Options.html)了解各种调试选项。

# 使用 import-module 在多个项目中使用库

您可能经常需要在多个项目中使用同一个库。您可以将库放入每个项目的`jni`文件夹中并分别构建它们。然而，维护同一库的多个副本是件麻烦事。例如，当库有新版本发布，您想要更新库时，您将不得不更新每个库副本。

幸运的是，Android NDK 提供了一个功能，允许我们在 NDK 项目的主源代码树之外维护一个库模块，并通过在`Android.mk`文件中使用简单的命令导入该模块。让我们讨论一下如何在此配方中导入一个模块。

## 如何操作...

以下步骤描述了如何在项目的`jni`文件夹之外声明和导入一个模块：

1.  创建一个名为`ImportModule`的具有本地支持的 Android 应用程序。将包名设置为`cookbook.chapter8.importmodule`。请参考第二章，*Java Native Interface*中的*加载本地库和注册本地方法*的配方，以获取更详细的说明。

1.  在`cookbook.chapter8.importmodule`包下添加一个 Java 文件`MainActivity.java`。这个 Java 文件仅加载共享库`ImportModule`，并调用本地方法`naCreateABmp`。

1.  从[`code.google.com/p/libbmp/downloads/list`](http://code.google.com/p/libbmp/downloads/list)下载`libbmp`库并提取归档文件。在项目下创建一个名为`modules`的文件夹，并在`modules`文件夹下创建一个`libbmp-0.1.3`文件夹。将提取的文件夹中的`src/bmpfile.c`和`src/bmpfile.h`文件复制到`libbmp-0.1.3`文件夹。

1.  按照第 3 步*使用 Android NDK 构建系统将库作为共享库模块移植*的配方更新`src/bmpfile.h`。

1.  在`libbmp-0.1.3`文件夹下创建一个`Android.mk`文件，以编译静态库`libbmp.a`的`libbmp`。这个`Android.mk`文件的内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE := libbmp
    LOCAL_SRC_FILES := bmpfile.c
    LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
    include $(BUILD_STATIC_LIBRARY)
    ```

1.  向其添加`mylog.h`和`ImportModule.c`文件。`ImportModule.c`实现了本地方法`naCreateABmp`。

1.  在`jni`文件夹下创建一个`Android.mk`文件，以编译共享库`libImportModule.so`的`ImportModule.c`。这个`Android.mk`文件的内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := ImportModule
    LOCAL_SRC_FILES := ImportModule.c
    LOCAL_LDLIBS := -llog
    LOCAL_STATIC_LIBRARIES := libbmp
    include $(BUILD_SHARED_LIBRARY)
    $(call import-add-path,$(LOCAL_PATH)/../modules)
    $(call import-module,libbmp-0.1.3)
    ```

1.  向`AndroidManifest.xml`文件添加`WRITE_EXTERNAL_STORAGE`权限，如下所示：

    ```kt
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    ```

1.  构建并运行 Android 项目。应该在 Android 设备的`sdcard`文件夹中创建一个位图文件`test_bs_static.bmp`。您可以使用以下命令获取该文件：

    ```kt
    $ adb pull /sdcard/test_im.bmp .
    ```

    该文件与本章中的*使用 Android NDK 构建系统将库作为共享库模块移植*的配方中显示的`test_static.bmp`相同。

## 它的工作原理...

在您的示例项目中，您在项目的`jni`文件夹外部创建了一个模块，然后导入该模块以构建共享库`libImportModule.so`。在声明和导入模块时，应执行以下步骤：

1.  **声明导入模块**：声明导入模块时没有什么特别的。由于导入模块通常被多个 NDK 项目使用，因此在声明导入模块时，导出头文件（使用`LOCAL_EXPORT_C_INCLUDES`）、编译器标志（`LOCAL_EXPORT_CFLAGS`或`LOCAL_EXPORT_CPPFLAGS`）和链接器标志（`LOCAL_EXPORT_LDLIBS`）是一个好习惯。

    在我们的示例项目中，您声明了一个导入的静态库模块`libbmp`。

1.  **决定放置导入模块的位置**：Android NDK 构建系统将在`NDK_MODULE_PATH`中定义的路径中搜索导入模块。默认情况下，Android NDK 目录的`sources`文件夹会添加到`NDK_MODULE_PATH`中。因此，您只需将导入模块文件夹放在`sources`文件夹下，Android NDK 构建系统就能找到它。

    或者，您可以将导入模块文件夹放在任何地方，并将路径追加到`NDK_MODULE_PATH`。在我们的示例项目中，将导入的`libbmp`模块放在`modules`文件夹中。

1.  **追加导入路径**：当将导入模块文件夹放置在 Android NDK 的`sources`目录下时，这不需要。否则，您需要通过向`NDK_MODULE_PATH`追加路径来告诉 Android NDK 构建系统导入模块的位置。`import-add-path`宏由 NDK 提供，以帮助您追加路径。

    在您的示例项目中，您通过在`jni/Android.mk`中的以下这行代码将`modules`文件夹追加到`NDK_MODULE_PATH`：

    ```kt
    $(call import-add-path,$(LOCAL_PATH)/../modules)
    ```

1.  **导入模块**：Android NDK 提供了一个`import-module`宏来导入一个模块。这个宏接受一个相对路径，指向导入模块文件夹，该文件夹中包含导入模块的`Android.mk`文件。Android NDK 构建系统将在`NDK_MODULE_PATH`中定义的所有路径中搜索导入模块。

    在您的示例项目中，您通过在`jni/Android.mk`文件中以下这行代码导入了模块：

    ```kt
    $(call import-module,libbmp-0.1.3)
    ```

    NDK 构建系统将在所有`NDK_MODULE_PATH`目录中搜索导入模块的`libbmp-0.1.3/Android.mk`文件。

1.  **使用该模块**：使用导入模块就像使用其他任何库模块一样。您需要通过在`LOCAL_STATIC_LIBRARIES`中列出静态库导入模块，在`LOCAL_SHARED_LIBRARIES`中列出共享库导入模块来进行链接。

有关如何导入模块的更多信息，您可以参考 Android NDK 中的`docs/IMPORT-MODULE.html`。

# 移植需要 RTTI、异常和 STL 支持的库。

Android 平台在`/system/lib/libstdc++.so`提供了一个 C++运行时库。这个默认的运行时库不提供 C++异常处理和 RTTI，对标准 C++库的支持也有限。幸运的是，Android NDK 提供了对默认 C++运行时库的替代方案，这使得大量需要异常处理、RTTI 和 STL 支持的现有库的移植成为可能。本食谱讨论如何移植一个需要 RTTI、异常处理和 STL 支持的 C++库。你会广泛使用`boost`库作为例子。

## 如何操作...

以下步骤描述了如何为 Android NDK 构建和使用`boost`库：

1.  使用以下命令安装自定义的 Android 工具链：

    ```kt
    $ANDROID_NDK/build/tools/make-standalone-toolchain.sh --platform=android-9 --install-dir=/tmp/my-android-toolchain
    ```

    这应该在`/tmp/my-android-toolchain`文件夹中安装工具链。

1.  创建一个名为`PortingBoost`的具有本地支持的 Android 应用程序。将包名设置为`cookbook.chapter8.portingboost`。更详细的说明，请参考第二章，*Java Native Interface*中的*加载本地库和注册本地方法*食谱。

1.  在`cookbook.chapter8.portingboost`包下添加一个 Java 文件`MainActivity.java`。这个 Java 文件简单地加载共享库`PortingBoost`，并调用本地方法`naExtractSubject`。

1.  从[`sourceforge.net/projects/boost/files/boost/`](http://sourceforge.net/projects/boost/files/boost/)下载 boost 库。在这个食谱中，你将构建`boost`库 1.51.0。将下载的归档文件解压到`jni`文件夹中。这将创建一个名为`boost_1_51_0`的文件夹在`jni`文件夹下，如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_08_05.jpg)

1.  在命令行终端，进入`boost_1_51_0`目录。输入以下命令：

    ```kt
    $ ./bootstrap.sh
    ```

1.  编辑`jni/boost_1_51_0/tools/build/v2`目录下的`user-config.jam`文件。在文件末尾添加以下内容。关于 boost 配置的更多信息，你可以参考[`www.boost.org/boost-build2/doc/html/bbv2/overview/configuration.html`](http://www.boost.org/boost-build2/doc/html/bbv2/overview/configuration.html)：

    ```kt
    NDK_TOOLCHAIN = /tmp/my-android-toolchain ;
    using gcc : android4.6 :
       $(NDK_TOOLCHAIN)/bin/arm-linux-androideabi-g++ :
       <archiver>$(NDK_TOOLCHAIN)/bin/arm-linux-androideabi-ar
       <ranlib>$(NDK_TOOLCHAIN)/bin/arm-linux-androideabi-ranlib
       <compileflags>--sysroot=$(NDK_TOOLCHAIN)/sysroot
       <compileflags>-I$(NDK_TOOLCHAIN)/arm-linux-androideabi/include/c++/4.6
       <compileflags>-I$(NDK_TOOLCHAIN)/arm-linux-androideabi/include/c++/4.6/arm-linux-androideabi
       <compileflags>-DNDEBUG
       <compileflags>-D__GLIBC__
       <compileflags>-DBOOST_FILESYSTEM_VERSION=3
       <compileflags>-lstdc++
       <compileflags>-mthumb
       <compileflags>-fno-strict-aliasing
       <compileflags>-O2
           ;
    ```

1.  尝试使用以下命令构建`boost`库：

    ```kt
    $ ./b2 --without-python --without-mpi  toolset=gcc-android4.6 link=static runtime-link=static target-os=linux --stagedir=android > log.txt &
    ```

    这个命令将在后台执行`boost`构建。你可以使用以下命令监控构建输出：

    ```kt
    $ tail -f log.txt
    ```

    构建完成需要一些时间。有些目标构建可能会失败。我们可以通过`log.txt`文件检查错误。

    第一个错误是找不到`sys/statvfs.h`文件。你可以通过更新`libs/filesystem/src/operations.cpp`文件来修复这个问题。更新的部分如下所示：

    ```kt
    #   include <sys/types.h>
    #   include <sys/stat.h>
    #   if !defined(__APPLE__) && !defined(__OpenBSD__) && !defined(__ANDROID__)
    #     include <sys/statvfs.h>
    #     define BOOST_STATVFS statvfs
    #     define BOOST_STATVFS_F_FRSIZE vfs.f_frsize
    #   else
    #     ifdef __OpenBSD__
    #       include <sys/param.h>
    #     elif defined(__ANDROID__)
    #         include <sys/vfs.h>
    #     endif
    #     include <sys/mount.h>
    #     define BOOST_STATVFS statfs
    #     define BOOST_STATVFS_F_FRSIZE   static_cast<boost::uintmax_t>(vfs.f_bsize)
    #   endif
    ```

    第二个错误是找不到`bzlib.h`文件。这是因为 Android 上可用`bzip`。你可以在`jni/boost_1_51_0/tools/build/v2/user-config.jam`文件顶部添加以下行来禁用`bzip`：

    ```kt
    modules.poke : NO_BZIP2 : 1 ;
    ```

    第三个错误是 `PAGE_SIZE` 在此作用域中没有声明。您可以通过在 `boost_1_51_0/boost/thread/thread.hpp` 和 `boost_1_51_0/boost/thread/pthread/thread_data.hpp` 中添加以下行来修复此问题：

    ```kt
    #define PAGE_SIZE sysconf(_SC_PAGESIZE)
    ```

1.  使用第 5 步的相同命令再次尝试构建库。这次库将成功构建。

1.  在 `jni` 文件夹下添加 `mylog.h` 和 `PortingBoost.cpp` 文件。`PortingBoost.cpp` 文件包含本地方法 `naExtractSubject` 的实现。该函数将使用 `boost` 库的 `regex_match` 方法，将输入字符串 `pInputStr` 的每一行与正则表达式匹配：

    ```kt
    void naExtractSubject(JNIEnv* pEnv, jclass clazz, jstring pInputStr) {
       std::string line;
       boost::regex pat( "^Subject: (Re: |Aw: )*(.*)" );
       const char *str;
       str = pEnv->GetStringUTFChars(pInputStr, NULL);
       std::stringstream stream;  
       stream << str;
       while (1) {
           std::getline(stream, line);
           LOGI(1, "%s", line.c_str());
           if (!stream.good()) {
             break;
           }
           boost::smatch matches;
           if (boost::regex_match(line, matches, pat)) {
               LOGI(1, "matched: %s", matches[0].str().c_str());
           } else {
             LOGI(1, "not matched");
           }
       }
    }
    ```

1.  在 `jni` 文件夹下添加一个 `Android.mk` 文件，内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE := boost_regex
    LOCAL_SRC_FILES := boost_1_51_0/android/lib/libboost_regex.a
    LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/boost_1_51_0
    include $(PREBUILT_STATIC_LIBRARY)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := PortingBoost
    LOCAL_SRC_FILES := PortingBoost.cpp
    LOCAL_LDLIBS := -llog
    LOCAL_STATIC_LIBRARIES := boost_regex
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  在 `jni` 文件夹下添加一个 `Application.mk` 文件，内容如下：

    ```kt
    APP_STL := gnustl_static
    APP_CPPFLAGS := -fexceptions
    ```

1.  构建并运行项目。您可以使用以下命令监控 logcat 输出：

    ```kt
    $ adb logcat -v time PortingBoost:I *:S
    ```

    以下是 logcat 输出的截图：

    ![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_08_06.jpg)

## 它的工作原理...

在您的示例项目中，首先使用 Android 工具链作为独立编译器构建了 boost 库。然后，您将 `boost` 中的 `regex` 库作为预构建模块使用。注意，`boost` 库需要支持 C++ 异常和 STL。让我们讨论如何在 Android NDK 上启用这些特性的支持。

**Android NDK 中的 C++ 运行时**：默认情况下，Android 带有一个最小的 C++ 运行时库位于 `/system/lib/libstdc++.so`。该库不支持大多数 C++ 标准库函数、C++ 异常和 RTTI。幸运的是，Android NDK 提供了额外的 C++ 运行时库供我们使用。以下表格总结了 NDK r8 中不同运行时库提供的特性：

|   | C++ 标准库 | C++ 异常 | C++ RTTI |
| --- | --- | --- | --- |
| **system** | 最小化 | 否 | 否 |
| **gabi++** | 最小化 | 否（NDK r8d 或更高版本为是） | 是 |
| **stlport** | 是 | 否（NDK r8d 或更高版本为是） | 是 |
| **gnustl** | 是 | 是 | 是 |

### 注意

自从 Android NDK r8d 开始，`gabi++` 和 `stlport` 中增加了 C++ 异常支持。

系统库指的是随 Android 系统默认提供的值。这里只支持最小的 C++ 标准库，并且不支持 C++ 异常和 RTTI。支持的 C++ 头文件包括以下内容：

```kt
cassert, cctype, cerrno, cfloat, climits, cmath, csetjmp, csignal, cstddef, cstdint, cstdio, cstdlib, cstring, ctime, cwchar, new, stl_pair.h, typeinfo, utility
```

+   `gabi++` 是一个运行时库，除了支持系统默认提供的 C++ 函数外，还支持 RTTI。

+   `stlport` 提供了一套完整的 C++ 标准库头文件和 RTTI，但不支持 C++ 异常。实际上，Android NDK 的 `stlport` 是基于 `gabi++` 的。

+   `gnustl` 是 GNU 标准的 C++ 库。它附带了一套完整的 C++ 头文件，并支持 C++ 异常和 RTTI。

    ### 提示

    共享库文件 `gnustl` 命名为 `libgnustl_shared.so`，而不是在其他平台上使用的 `libstdc++.so`。这是因为名称 `libstdc++.so` 被系统默认的 C++ 运行时使用。

Android NDK 构建系统允许我们在`Application.mk`文件中指定要链接的 C++ 库运行时。根据库类型（共享或静态）以及要使用的运行时，我们可以如下定义`APP_STL`：

|   | 静态库 | 共享库 |
| --- | --- | --- |
| **gabi++** | `gabi++_static` | `gabi++_shared` |
| **stlport** | `stlport_static` | `stlport_shared` |
| **gnustl** | `gnustl_static` | `gnustl_shared` |

在你的示例项目中，在`Application.mk`中添加以下行，以使用`gnustl`静态库：

```kt
APP_STL := gnustl_static
```

### 提示

你只能将静态 C++ 库链接到一个共享库中。如果一个项目使用多个共享库，并且所有库都链接到静态 C++ 库，每个共享库都会在其二进制文件中包含该库代码的副本。这会导致一些问题，因为 C++ 运行时库使用的一些全局变量会被重复。

这些库的源代码、头文件和二进制文件可以在 Android NDK 的`sources/cxx-stl`文件夹中找到。你也可以参考`docs/CPLUSPLUS-SUPPORT.html`获取更多信息。

**启用 C++ 异常支持**：默认情况下，所有 C++ 源文件都是使用`-fno-exceptions`编译的。为了启用 C++ 异常，你需要选择一个支持异常的 C++ 库（`gnustl_static`或`gnustl_shared`），并执行以下操作之一：

+   在`Android.mk`中，将异常添加到`LOCAL_CPP_FEATURES`中，如下所示：

    ```kt
    LOCAL_CPP_FEATURES += exceptions
    ```

+   在`Android.mk`中，将`-fexceptions`添加到`LOCAL_CPPFLAGS`中，如下所示：

    ```kt
    LOCAL_CPPFLAGS += -fexceptions
    ```

+   在`Application.mk`中，添加以下行：

    ```kt
    APP_CPPFLAGS += -fexceptions
    ```

**启用 C++ RTTI 支持**：默认情况下，C++ 源文件是使用`-fno-rtti`编译的。为了启用 RTTI 支持，你需要使用一个支持 RTTI 的 C++ 库，并执行以下操作之一：

+   在`Android.mk`中，将`rtti`添加到`LOCAL_CPP_FEATURES`中，如下所示：

    ```kt
    LOCAL_CPP_FEATURES += rtti
    ```

+   在`Android.mk`中，将`-frtti`添加到`LOCAL_CPPFLAGS`中，如下所示：

    ```kt
    LOCAL_CPPFLAGS += -frtti
    ```

+   在`Application.mk`中，将`-frtti`添加到`APP_CPPFLAGS`中，如下所示：

    ```kt
    APP_CPPFLAGS += -frtti
    ```


# 第九章：使用 NDK 将现有应用程序移植到 Android

在本章中，我们将涵盖以下内容：

+   使用 NDK 构建系统将命令行可执行文件移植到 Android

+   使用 NDK 独立编译器将命令行可执行文件移植到 Android

+   为移植的 Android 应用程序添加 GUI

+   在移植时使用后台线程

# 简介

上一章涵盖了使用 NDK 将本地库移植到 Android 的各种技术。本章讨论了本地应用程序的移植。

我们将首先介绍如何使用 Android NDK 构建系统和 NDK 提供的独立编译器为 Android 构建本地命令行应用程序。然后，我们为移植的应用程序添加一个图形用户界面（GUI）。最后，我们说明如何使用后台线程进行繁重处理，并将进度更新消息从本地代码发送到 Java UI 线程以进行 GUI 更新。

我们将在本章中使用开源的 Fugenschnitzer 程序。它是一个基于**Seam Carving**算法的内容感知图像调整大小程序。该算法的基本思想是通过搜索并操作原始图像中的接缝（一个**接缝**是从上到下或从左到右连接像素的路径）来改变图像的大小。该算法能够在尝试保留重要信息的同时调整图像大小。对于对程序和算法感兴趣的读者，可以访问[`fugenschnitzer.sourceforge.net/main_en.html`](http://fugenschnitzer.sourceforge.net/main_en.html)了解更多详情。否则，我们可以忽略算法，专注于移植过程。

# 使用 NDK 构建系统将命令行可执行文件移植到 Android

本食谱讨论了如何使用 NDK 构建系统将命令行可执行文件移植到 Android。我们将以开源的 Fugenschnitzer 程序（`fusch`）为例。

## 准备工作

在阅读本章之前，你应该先阅读第八章中的*使用 Android NDK 构建系统将库作为静态库移植*的食谱，*使用 Android NDK 移植和使用现有库*。

## 如何操作...

以下步骤描述了如何使用 NDK 构建系统将`fusch`程序移植到 Android：

1.  创建一个名为**PortingExecutable**的具有本地支持的 Android 应用程序。将包名设置为`cookbook.chapter9.portingexecutable`。如果你需要更详细的说明，请参考第二章中的*加载本地库和注册本地方法*的食谱，*Java 本地接口*。

1.  删除项目`jni`文件夹下的现有内容。

1.  从[`fugenschnitzer.sourceforge.net/main_en.html`](http://fugenschnitzer.sourceforge.net/main_en.html)下载`fusch`库和命令行应用程序的源代码。解压归档文件，并将它们分别放入`jni/fusch`和`jni/fusch_lib`文件夹中。

1.  从[`sourceforge.net/projects/libpng/files/libpng12/1.2.50/`](http://sourceforge.net/projects/libpng/files/libpng12/1.2.50/)下载`libpng 1.2.50`，并将文件解压到`jni/libpng-1.2.50`文件夹中。最新版本的`libpng`无法工作，因为接口不同。

1.  在`jni/libpng-1.2.50`文件夹下添加一个`Android.mk`文件，以将`libpng`构建为一个静态库模块。该文件具有以下内容：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_CFLAGS := 
    LOCAL_MODULE    := libpng
    LOCAL_SRC_FILES :=\
      png.c \
      pngerror.c \
      pngget.c \
      pngmem.c \
      pngpread.c \
      pngread.c \
      pngrio.c \
      pngrtran.c \
      pngrutil.c \
      pngset.c \
      pngtrans.c \
      pngwio.c \
      pngwrite.c \
      pngwtran.c \
      pngwutil.c 
    LOCAL_LDLIBS := -lz
    LOCAL_EXPORT_LDLIBS := -lz
    LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
    include $(BUILD_STATIC_LIBRARY)
    ```

1.  在`jni/fusch_lib`文件夹下添加一个`Android.mk`文件，以将`libseamcarv`构建为一个静态库模块。文件内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := libseamcarv
    LOCAL_SRC_FILES :=\
      sc_core.c  \
      sc_carve.c  \
      sc_color.c  \
      sc_shift.c \
      sc_mgmnt.c \
      seamcarv.c
    LOCAL_CFLAGS := -std=c99 
    LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
    include $(BUILD_STATIC_LIBRARY)
    ```

1.  在`jni/fusch`文件夹下添加第三个`Android.mk`文件，以构建使用`libpng-1.2.50`和`fusch_lib`两个文件夹中构建的两个静态库的`fusch`可执行文件。

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := fusch
    LOCAL_SRC_FILES := fusch.c
    LOCAL_CFLAGS := -std=c99
    LOCAL_STATIC_LIBRARIES := libpng libseamcarv
    include $(BUILD_EXECUTABLE)
    ```

1.  在`jni`文件夹下添加第四个`Android.mk`文件，以包含其子文件夹下的`Android.mk`文件。

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(call all-subdir-makefiles)
    ```

1.  构建应用程序，你会在`libs/armeabi`文件夹下看到一个名为`fusch`的二进制文件。我们可以使用以下命令将此二进制文件放入已越狱的 Android 设备或模拟器中：

    ```kt
    $ adb push fusch /data/data/
    ```

1.  请注意，我们无法在未越狱的 Android 设备上复制并执行二进制文件，因为我们无法获得执行权限。

1.  在控制台上启动第一个命令行。我们可以使用以下命令授予二进制文件执行权限并执行它：

    ```kt
    $ adb shell
    # cd /data/data
    # chmod 755 fusch
    # ./fusch
    ```

    这将输出程序的帮助信息。

1.  启动第二个命令行终端。使用以下命令将测试 PNG 文件`cookbook_ch9_test.png`（位于示例项目源代码的`assets`文件夹中）推送到测试设备或模拟器中：

    ```kt
    $ adb push cookbook_ch9_test.png /data/data/
    ```

1.  回到第一个命令行终端，使用以下命令再次执行`fusch`程序：

    ```kt
    # ./fusch cookbook_ch9_test.png 1.png h-200
    ```

1.  程序将花费一些时间将输入图像从 800 x 600 调整到 600 x 600。一旦完成，我们可以在第二个命令行终端使用以下命令获取处理后的图像：

    ```kt
    $ adb pull /data/data/1.png .
    ```

1.  以下屏幕截图显示了左侧的原始图像和右侧的处理后图像：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_09_12.jpg)

## 工作原理...

示例项目演示了如何将`fusch`程序作为命令行可执行文件移植到 Android。我们在`Android.mk`文件中向 Android NDK 构建系统描述了源代码，NDK 构建系统处理其余部分。

移植命令行可执行文件的操作步骤如下：

1.  确定库依赖关系。在我们的示例程序中，`fusch`依赖于`libseamcarv`（位于`fusch_lib`文件夹中）和`libpng`，而`libpng`随后又依赖于`zlib`。

1.  如果 Android 系统上没有可用的库，将其作为静态库模块移植。这是我们示例应用程序中的`libseamcarv`和`libpng`的情况。但是因为 Android 上有`zlib`，所以我们只需链接到它即可。

1.  将可执行文件作为单独的模块移植，并将其链接到库模块。

### 理解 Android.mk 文件

我们在第八章《使用 Android NDK 移植和使用现有库》中已经介绍了大部分`Android.mk`变量和宏。这里我们将介绍另外两个预定义变量。你也可以查阅 Android NDK 文件`docs/ANDROID-MK.html`获取更多关于宏和变量的信息。

+   `LOCAL_CFLAGS`：一个模块描述变量。它允许我们为构建 C 和 C++源文件指定额外的编译器选项或宏定义。另一个具有类似功能的变量是`LOCAL_CPPFLAGS`，但它仅用于 C++源文件。在我们示例项目中，在构建`libseamcarv`和`fusch`时，我们向编译器传递了`-std=c99`。这要求编译器接受 ISO C99 C 语言标准的语法。如果在构建时未指定该标志，将导致编译错误。

    ### 注意

    也可以使用`LOCAL_CFLAGS += I<包含路径>`来指定包含路径。但是，建议我们使用`LOCAL_C_INCLUDES`，因为`LOCAL_C_INCLUDES`路径也将用于`ndk-gdb`本地调试。

+   `BUILD_EXECUTABLE`：一个 GNU make 变量。它指向一个构建脚本，该脚本收集了我们想要构建的可执行文件的所有信息，并确定如何构建它。它与`BUILD_SHARED_LIBRARY`和`BUILD_STATIC_LIBRARY`类似，不同之处在于它用于构建可执行文件。在我们示例项目中构建`fusch`时使用了它。

    ```kt
    include $(BUILD_EXECUTABLE)
    ```

通过本章的解释以及第八章《使用 Android NDK 移植和使用现有库》的知识，现在理解我们示例应用程序中使用的四个`Android.mk`文件已经相当容易了。我们将`libpng`和`libseamcarv`作为两个静态库模块进行移植。我们导出依赖的库（通过`LOCAL_EXPORT_LDLIBS`）和头文件（通过`LOCAL_EXPORT_C_INCLUDES`），这样在使用模块时它们会被自动包含。在移植`libpng`时，我们还链接了 Android 系统上可用的`zlib`库（通过`LOCAL_LDLIBS`）。最后，我们通过引用这两个库模块（通过`LOCAL_STATIC_LIBRARIES`）来移植`fusch`程序。

# 使用 NDK 独立编译器将命令行可执行文件移植到 Android。

上一个食谱介绍了如何使用 NDK 构建系统将命令行可执行文件移植到 Android。这个食谱描述了如何使用 Android NDK 工具链作为独立编译器来实现这一点。

## 准备工作

在继续之前，建议您阅读第八章中的*使用现有构建系统移植库*一节，*使用 Android NDK 移植和利用现有库*。

## 如何操作...

以下步骤描述了如何使用 NDK 工具链直接将`fusch`程序移植到 Android：

1.  创建一个名为**PortingExecutableBuildSystem**的具有本地支持的 Android 应用。设置包名为`cookbook.chapter9.portingexecutablebuildsystem`。如果您需要更详细的说明，请参考第二章中的*加载本地库和注册本地方法*一节，*Java 本地接口*。

1.  删除项目`jni`文件夹下的现有内容。

1.  从[`fugenschnitzer.sourceforge.net/main_en.html`](http://fugenschnitzer.sourceforge.net/main_en.html)下载`fusch`库和命令行应用的源代码。解压归档文件，并将它们分别放入`jni/fusch`和`jni/fusch_lib`文件夹。

1.  从[`sourceforge.net/projects/libpng/files/libpng12/1.2.50/`](http://sourceforge.net/projects/libpng/files/libpng12/1.2.50/)下载`libpng 1.2.50`，并将文件解压到`jni/libpng-1.2.50`文件夹。最新版本的`libpng`不能工作，因为接口已经改变。将`libpng-1.2.50`下的`config.guess`脚本替换为[`gcc.gnu.org/svn/gcc/branches/cilkplus/config.guess`](http://gcc.gnu.org/svn/gcc/branches/cilkplus/config.guess)的内容，`config.sub`替换为[`gcc.gnu.org/svn/gcc/branches/cilkplus/config.sub`](http://gcc.gnu.org/svn/gcc/branches/cilkplus/config.sub)的脚本。

1.  在`jni/libpng-1.2.50`文件夹下添加一个`build_android.sh`文件来构建`libpng`。文件内容如下：

    ```kt
    #!/bin/bash
    NDK=~/Desktop/android/android-ndk-r8b
    SYSROOT=$NDK/platforms/android-8/arch-arm/
    export CFLAGS="-fpic \
       -ffunction-sections \
       -funwind-tables \
       -D__ARM_ARCH_5__ -D__ARM_ARCH_5T__ \
       -D__ARM_ARCH_5E__ -D__ARM_ARCH_5TE__ \
      -Wno-psabi \
      -march=armv5te \
       -mtune=xscale \
       -msoft-float \
      -mthumb \
       -Os \
      -DANDROID \
       -fomit-frame-pointer \
       -fno-strict-aliasing \
       -finline-limit=64"
    export LDFLAGS="-lz"
    export CC="$NDK/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86/bin/arm-linux-androideabi-gcc --sysroot=$SYSROOT"
    ./configure \
       --host=arm-linux-androideabi \
       --prefix=$(pwd) \
       --exec-prefix=$(pwd) \
      --enable-shared=false \
      --enable-static=true
    make clean
    make 
    make install
    ```

1.  在`jni/fusch_lib`文件夹下添加一个`build_android.sh`文件来构建`libseamcarv`库。文件内容如下：

    ```kt
    #!/bin/bash
    NDK=~/Desktop/android/android-ndk-r8b
    SYSROOT=$NDK/platforms/android-8/arch-arm/
    export CFLAGS="-fpic \
       -ffunction-sections \
       -funwind-tables \
       -D__ARM_ARCH_5__ -D__ARM_ARCH_5T__ \
       -D__ARM_ARCH_5E__ -D__ARM_ARCH_5TE__ \
      -Wno-psabi \
      -march=armv5te \
       -mtune=xscale \
       -msoft-float \
      -mthumb \
       -Os \
       -fomit-frame-pointer \
       -fno-strict-aliasing \
       -finline-limit=64 \
      -std=c99 \
      -DANDROID "
    export CC="$NDK/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86/bin/arm-linux-androideabi-gcc --sysroot=$SYSROOT"
    AR="$NDK/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86/bin/arm-linux-androideabi-ar"
    SRC_FILES="\
      sc_core.c  \
      sc_carve.c  \
      sc_color.c  \
      sc_shift.c \
      sc_mgmnt.c \
      seamcarv.c"
    $CC $SRC_FILES $CFLAGS -c
    $AR cr libseamcarv.a *.o 
    ```

1.  在`jni/fusch`文件夹下添加第三个`build_android.sh`文件，以构建使用在`libpng-1.2.50`和`fusch_lib`两个文件夹下构建的两个静态库的`fusch`可执行文件。

    ```kt
    #!/bin/bash
    NDK=~/Desktop/android/android-ndk-r8b
    SYSROOT=$NDK/platforms/android-8/arch-arm
    CUR_D=$(pwd)
    export CFLAGS="-fpic \
       -ffunction-sections \
       -funwind-tables \
       -D__ARM_ARCH_5__ -D__ARM_ARCH_5T__ \
       -D__ARM_ARCH_5E__ -D__ARM_ARCH_5TE__ \
      -Wno-psabi \
      -march=armv5te \
       -mtune=xscale \
       -msoft-float \
      -mthumb \
       -Os \
       -fomit-frame-pointer \
       -fno-strict-aliasing \
       -finline-limit=64 \
      -std=c99 \
      -DANDROID \
      -I$CUR_D/../fusch_lib \
      -I$CUR_D/../libpng-1.2.50/include"
    export LDFLAGS="-Wl,--no-undefined -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -lz -lc -lm -lpng -lseamcarv -L$CUR_D/../fusch_lib -L$CUR_D/../libpng-1.2.50/lib"
    export CC="$NDK/toolchains/arm-linux-androideabi-4.4.3/prebuilt/linux-x86/bin/arm-linux-androideabi-gcc --sysroot=$SYSROOT"
    SRC_FILES="fusch.c"
    $CC $SRC_FILES $CFLAGS $LDFLAGS -o fusch
    ```

1.  通过在`libpng-1.2.50`、`fusch_lib`和`fusch`三个子文件夹中执行`build_android.sh`脚本来构建`libpng`和`libseamcarv`两个库以及`fusch`可执行文件。我们可以在`libpng-1.2.50/lib`文件夹下找到`libpng.a`，在`fusch_lib`文件夹下找到`libseamcarv.a`，在`fusch`文件夹下找到`fusch`可执行文件。

1.  我们可以使用以下命令将二进制文件`fusch`放到已越狱的 Android 设备或模拟器上：

    ```kt
    $ cd <path to project folder>/PortingExecutableBuildSystem/jni/fusch
    $ adb push fusch /data/data/
    ```

1.  请注意，由于我们无法获得权限，因此不能在未越狱的 Android 设备上复制和执行二进制文件。

1.  启动第一个命令行终端。我们可以给二进制文件执行权限，然后使用以下命令执行它：

    ```kt
    $ adb shell
    # cd /data/data
    # chmod 755 fusch
    # ./fusch
    ```

1.  这将打印出程序的帮助信息。

1.  启动第二个命令行终端。使用以下命令将测试 PNG 文件`cookbook_ch9_test.png`（位于示例项目源代码的`assets`文件夹下）推送到测试设备或模拟器上：

    ```kt
    $ adb push cookbook_ch9_test.png /data/data/
    ```

1.  回到第一个命令行终端，使用以下命令再次执行`fusch`程序：

    ```kt
    # ./fusch cookbook_ch9_test.png 1.png v-200
    ```

1.  程序将花费一些时间将输入图像从 800 x 600 调整到 800 x 400。一旦完成，我们可以在第二个命令行终端使用以下命令获取处理后的图像：

    ```kt
    $ adb pull /data/data/1.png .
    ```

1.  下图显示了左侧的原始图像和右侧的处理后图像：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_09_13.jpg)

## 工作原理...

示例项目展示了如何使用 NDK 工具链作为独立编译器将命令行可执行文件移植到 Android。

移植可执行文件的过程与之前使用 Android NDK 构建系统的食谱类似。关键在于向独立编译器传递适当的选项。

### 移植 libpng

`libpng`附带了它自己的构建脚本。我们可以使用以下命令获取配置构建过程的选项列表：

```kt
$ ./configure –help
```

编译器命令、编译器标志和链接器标志可以通过环境变量`CC`、`CFLAGS`和`LDFLAGS`分别配置。在`libpng-1.2.50`文件夹下的`build_android.sh`脚本中，我们设置这些变量以使用 NDK 编译器为 ARM 架构构建。关于如何移植库的详细说明，我们可以参考*使用 Android NDK 工具链的现有构建系统移植库*的食谱，在第八章，*移植带有其现有构建系统的库*。

我们现在将介绍一些编译选项。由于 Android NDK 工具链基于 GCC，我们可以参考}[`gcc.gnu.org/onlinedocs/gcc/Option-Summary.html`](http://gcc.gnu.org/onlinedocs/gcc/Option-Summary.html)详细了解每个选项。

+   `-fpic`：它生成适用于构建共享库的位置无关代码。

+   `-ffunction-sections`：此选项要求链接器执行优化，以提高代码中的引用局部性。

+   `-funwind-tables`：它生成用于展开调用栈的静态数据。

+   `-D__ARM_ARCH_5__`, `-D__ARM_ARCH_5T`, `-D__ARM_ARCH_5E__`, `-D__ARM_ARCH_5TE`, `-DANDROID`定义了`__ARM_ARCH_5__`, `__ARM_ARCH_5T`, `__ARM_ARCH_5E__`, `__ARM_ARCH_5TE`, 和`ANDROID`作为宏，定义等于`1`。例如，`-DANDROID`等同于`-D ANDROID=1`。

+   `-Wno-psabi`：它抑制了关于`va_list`等的警告信息。

+   `-march=armv5te`：它指定目标 ARM 架构为`ARMv5te`。

+   `-mtune=xscale`：它调整代码的性能，因为代码将在 xscale 处理器上运行。请注意，xscale 是一个处理器名称。

+   `-msoft-float`：它使用软件浮点函数。

+   `-mthumb`：它使用 Thumb 指令集生成代码。

+   `-Os`：提供针对大小的优化。

+   `-fomit-frame-pointer`：如果可能，帮助避免在寄存器中保存帧指针。

+   `-fno-strict-aliasing`：不应用严格的别名规则。这防止编译器进行不想要的优化。

+   `-finline-limit=64`：设置可以作为`64`伪指令内联的函数的大小限制。

+   `-std=c99`：接受`c99`标准语法。

当构建成功执行后，我们可以在`libpng-1.2.50/lib`文件夹下找到`libpng.a`静态库，以及在`libpng-1.2.50/include`文件夹下的头文件。

### 注意

Android NDK 构建系统本质上是为我们确定合适的编译选项并为我们调用交叉编译器。因此，我们可以从 NDK 构建系统的输出中学习传递给编译器的选项。例如，我们可以在前一个食谱中调用命令`ndk-build -B V=1`或`ndk-build -B -n`，以了解 NDK 构建系统如何处理`libpng`、`libseamcarv`和`fusch`的构建，并在本食谱中应用类似的选项。

### 移植 libseamcarv

`libseamcarv`附带一个 Makefile 但没有配置文件。我们可以修改 Makefile 或者从头开始编写构建脚本。由于库只包含几个文件，我们将直接编写构建脚本。需要遵循两个步骤：

1.  将所有源文件编译成对象文件。这是通过在编译时传递`"-c"`选项完成的。

1.  将对象文件归档成静态库。这一步是通过 NDK 工具链中的归档器`arm-linux-androideabi-ar`完成的。

### 提示

正如我们在第八章，*使用 Android NDK 移植和现有库*中所解释的，静态库不过是对象文件的归档，可以通过`archiver`程序创建。

### 移植 fusch

我们需要链接到我们构建的两个库，即`libpng`和`libseamcarv`。这是通过向链接器传递以下选项完成的：

```kt
-lpng -lseamcarv -L$CUR_D/../fusch_lib -L$CUR_D/../libpng-1.2.50/lib
```

这个"`-L`"选项将`fusch_lib`和`libpng-1.2.50/lib`添加到库的搜索路径中，而"`-l`"告诉链接器链接到`libpng`和`libseamcarv`库。构建脚本将在`fusch`文件夹下输出名为`fusch`的二进制文件。

`fusch`程序相当简单。因此，我们可以使用 Android NDK 构建系统或独立的编译器来移植它。如果一个应用程序有更多的依赖，用`Android.mk`文件描述所有内容可能会很困难。因此，能够使用 NDK 工具链作为独立的编译器并利用库的现有构建脚本是非常有帮助的。

# 为移植的 Android 应用添加 GUI

前两个食谱展示了如何将命令行可执行文件移植到 Android。不用说，这种方法最大的缺点是它不能在未越狱的 Android 设备上执行。本食谱讨论了在将应用程序移植到 Android 时，如何通过添加 GUI 来解决这一问题。

## 如何操作...

以下步骤描述了如何向移植的应用添加一个简单的用户界面：

1.  创建一个名为`PortingExecutableAUI`的具有本地支持的 Android 应用。将包名设置为`cookbook.chapter9.portingexecutableaui`。如果你需要更详细的说明，请参考第二章的*加载本地库和注册本地方法*部分，*Java Native Interface*。

1.  按照本章中*使用 NDK 构建系统将命令行可执行文件移植到 Android*的步骤 2 至 8 进行操作。

1.  在`jni/fusch`文件夹下添加一个`mylog.h`文件。在`jni/fusch/fusch.c`文件的开头部分添加以下几行，然后移除原始的主方法签名行。`naMain`方法接受来自 Java 代码的命令，而不是命令行 shell。参数应以空格分隔：

    ```kt
    #ifdef ANDROID_BUILD
    #include <jni.h>
    #include "mylog.h"
    int naMain(JNIEnv* env, jclass clazz, jstring pCmdStr);

    jint JNI_OnLoad(JavaVM* pVm, void* reserved) {
      JNIEnv* env;
      if ((*pVm)->GetEnv(pVm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
      }
      JNINativeMethod nm[1];
      nm[0].name = "naMain";
      nm[0].signature = "(Ljava/lang/String;)I";
      nm[0].fnPtr = (void*)naMain;
      jclass cls = (*env)->FindClass(env, "cookbook/chapter9/portingexecutableaui/MainActivity");
      // Register methods with env->RegisterNatives.
      (*env)->RegisterNatives(env, cls, nm, 1);
      return JNI_VERSION_1_6;
    }

     int naMain(JNIEnv* env, jclass clazz, jstring pCmdStr) {
      int argc = 0;
      char** argv = (char**) malloc (sizeof(char*)*4);
      *argv = "fusch";
      char** targv = argv + 1;
      argc++;
      jboolean isCopy;
       char *cmdstr = (*env)->GetStringUTFChars(env, pCmdStr, &isCopy);
       if (NULL == cmdstr) {
         LOGI(2, "get string failed");
       }
       LOGI(2, "naMain assign parse string %s", cmdstr);
       char* pch;
       pch = strtok(cmdstr, " ");
       while (NULL != pch) {
         *targv = pch;
         argc++;
         targv++;
         pch = strtok(NULL, " ");
       }
       LOGI(1, "No. of arguments: %d", argc);
       LOGI(1, "%s %s %s %s", argv[0], argv[1], argv[2], argv[3]);
    #else
     int main(int argc, char *argv[]) {
    #endif
    ```

1.  在主方法的`return`语句之前添加以下几行以释放本地字符串：

    ```kt
    #ifdef ANDROID_BUILD
       (*env)->ReleaseStringUTFChars(env, pCmdStr, cmdstr);
    #endif
    ```

1.  更新`jni/fusch`下的`Android.mk`文件，如下所示。更新的部分已被高亮显示：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := fusch
    LOCAL_SRC_FILES := fusch.c
    LOCAL_CFLAGS := -std=c99 -DANDROID_BUILD
    LOCAL_STATIC_LIBRARIES := libpng libseamcarv
    LOCAL_LDLIBS := -llog
    include $(BUILD_SHARED_LIBRARY)

    ```

1.  在`cookbook.chapter9.portingexecutableaui`包下添加`MainActivity.java`文件。Java 代码设置图形用户界面，加载共享库`libfusch.so`，并调用本地方法`naMain`。

1.  在`res/layout`文件夹下添加一个`activity_main.xml`文件以描述图形用户界面。

1.  在`AndroidManifest.xml`文件中，在`<application>...</application>`之前添加以下行：

    ```kt
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE"/>
    ```

1.  构建并运行 Android 应用。你应该能看到一个与以下截图类似的图形用户界面：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_09_04.jpg)

1.  我们可以点击**宽度**或**高度**按钮来处理默认图像。或者，我们可以加载另一个`.png`图像并处理它。一旦我们点击**宽度**或**高度**，图形用户界面将不再响应，我们必须等待处理完成。如果出现著名的**应用无响应**（**ANR**）对话框，只需点击**等待**。

1.  处理完成后，将加载处理过的图像并显示其尺寸。左侧的截图显示了点击**宽度**按钮的结果，而右侧的截图则表示**高度**处理的结果。请注意，图像被缩放以适应显示区域：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_09_14.jpg)

## 工作原理...

该示例展示了如何为移植到 Android 的`fusch`程序添加图形用户界面。`fusch`源代码被修改，以便本地代码与图形用户界面接口。

通常，可以按照以下步骤向已移植到 Android 的命令行可执行文件添加图形用户界面。

1.  用本地方法替换主方法。在我们的示例应用中，我们用`naMain`替换了 main。

1.  解析本地方法的输入参数以获取命令选项，而不是从命令行读取。在我们的示例应用程序中，我们解析了第三个输入参数 `pCmdStr` 以获取 `fusch` 命令选项。这使得命令可以在 Java 代码中构建，并轻松地传递给本地代码。

1.  将本地方法注册到 Java 类。

1.  在 Java 代码中，图形用户界面（GUI）可以接收用户指定的各种参数值，构建命令，并将其传递给本地方法进行处理。

请注意，在我们的修改后的本地代码中，我们并没有移除原始代码。我们使用了 C 预处理器宏 `ANDROID_BUILD` 来控制哪些源代码部分应该被包含以构建 Android 共享库。我们在 `Android.mk` 文件（位于 `fusch` 文件夹下）中向编译器传递 `-DANDROID_BUILD`，以启用特定的 Android 代码。这种方法使得我们能够轻松添加对 Android 的支持，而不会破坏其他平台的代码。

本食谱中的示例应用程序有两个严重的限制。首先，主 UI 线程处理繁重的图像处理，这导致应用程序变得无响应。其次，在图像处理过程中没有进度更新。只有在图像处理完成后 GUI 才会更新。我们将在下一个食谱中解决这些问题。

# 在移植中使用后台线程

前一个食谱为移植的 `fusch` 程序添加了 GUI，但留下了两个问题——GUI 的无响应性和处理过程中没有进度更新。这个食谱讨论了如何使用后台线程来处理进程，并将进度报告给主 UI 线程。

## 准备就绪。

本食谱中的示例程序基于我们本章前一个食谱中开发的程序。您应该首先阅读它们。此外，建议读者阅读以下 第二章，*Java Native Interface* 的食谱：

+   *从本地代码调用静态和实例方法*

+   *缓存 `jfieldID`、`jmethodID` 和引用数据以提高性能*

## 如何操作...

以下步骤描述了如何使用后台线程进行繁重的处理，并将进度更新报告给 Java UI 线程：

1.  将我们在前一个食谱中开发的 `PortingExecutableAUI` 项目复制到一个名为 `PortingExecutableAUIAsync` 的文件夹中。在 Eclipse IDE 中打开文件夹中的项目。

1.  向 `MainActivity.java` 添加以下代码：

    `handler`：`handler` 类的实例处理从后台线程发送的消息。它将使用消息内容更新 GUI。

    ```kt
    public static final int MSG_TYPE_PROG = 1;
    public static final int MSG_TYPE_SUCCESS = 2;
    public static final int MSG_TYPE_FAILURE = 3;
    Handler handler = new Handler() {
      @Override
      public void handleMessage(Message msg) {
        switch(msg.what) {
          case MSG_TYPE_PROG:
            String updateMsg = (String)msg.obj;
            if (1 == msg.arg1) {
              String curText = text1.getText().toString();
              String newText = curText.substring(0, curText.lastIndexOf("\n")) + "\n" + updateMsg;
              text1.setText(newText);
            } else if (2 == msg.arg1) {
              text1.append(updateMsg);
            } else {
              text1.append("\n" + updateMsg);
            }
            break;
          case MSG_TYPE_SUCCESS:
            Uri uri = Uri.fromFile(new File(outputImageDir + outputImgFileName));
            img2.setImageURI(uri);
            text1.append("\nprocessing done!");
            text2.setText(getImageDimension(inputImagePath) + ";" + 
            getImageDimension(outputImageDir + outputImgFileName));
            break;
          case MSG_TYPE_FAILURE:
            text1.append("\nerror processing the image");
            break;
        }
      }
    };
    ```

    `ImageProcRunnable`：`MainActivity` 的一个私有类实现了 `Runnable` 接口，它接受命令字符串，调用本地方法 `naMain`，并将结果消息发送给 Java UI 线程的处理器。这个类的实例将从后台线程中调用：

    ```kt
    private class ImageProcRunnable implements Runnable {
      String procCmd;
      public ImageProcRunnable(String cmd) {
        procCmd = cmd;
      }
      @Override
      public void run() {
        int res = naMain(procCmd, MainActivity.this);
        if (0 == res) {
          //success, send message to handler
          Message msg = new Message();
          msg.what = MSG_TYPE_SUCCESS;
          handler.sendMessage(msg);
        } else {
          //failure, send message to handler
          Message msg = new Message();
          msg.what = MSG_TYPE_FAILURE;
          handler.sendMessage(msg);
        }
      }
    }
    ```

    `updateProgress`：这是一个从本地代码通过 JNI 调用的方法。它向 Java UI 线程的处理程序发送一条消息：

    ```kt
    public void updateProgress(String pContent, int pInPlaceUpdate) {
      Message msg = new Message();
      msg.what = MSG_TYPE_PROG;
      msg.arg1 = pInPlaceUpdate;
      msg.obj = pContent;
      handler.sendMessage(msg);
    }
    ```

1.  更新 `fusch.c` 源代码。

1.  在 `naMain` 方法中我们缓存了 `JavaVM` 引用，并为 `MainAcitvity` 对象引用 `pMainActObj` 获取了一个全局引用。`fusch` 程序使用了不止一个后台线程。我们将需要这些引用从那些后台线程调用 Java 方法：

    ```kt
    #ifdef ANDROID_BUILD
    int naMain(JNIEnv* env, jobject pObj, jstring pCmdStr, jobject pMainActObj);
    jint JNI_OnLoad(JavaVM* pVm, void* reserved) {
      JNIEnv* env;
      if ((*pVm)->GetEnv(pVm, (void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        return -1;
      }
      cachedJvm = pVm;
      JNINativeMethod nm[1];
      nm[0].name = "naMain";
      nm[0].signature = "(Ljava/lang/String;Lcookbook/chapter9/portingexecutableaui/MainActivity;)I";
      nm[0].fnPtr = (void*)naMain;
      jclass cls = (*env)->FindClass(env, "cookbook/chapter9/portingexecutableaui/MainActivity");
      (*env)->RegisterNatives(env, cls, nm, 1);
      return JNI_VERSION_1_6;
    }
    int naMain(JNIEnv* env, jobject pObj, jstring pCmdStr, jobject pMainActObj) {
      char progBuf[500];
      jmethodID updateProgMID, toStringMID;
      jstring progStr;
      jclass mainActivityClass = (*env)->GetObjectClass(env, pMainActObj);
      cachedMainActObj = (*env)->NewGlobalRef(env, pMainActObj);
      updateProgMID = (*env)->GetMethodID(env, mainActivityClass, "updateProgress", "(Ljava/lang/String;I)V");
      if (NULL == updateProgMID) {
        LOGE(1, "error finding method updateProgress");
        return EXIT_FAILURE;
      }
      int argc = 0;
      char** argv = (char**) malloc (sizeof(char*)*4);
      *argv = "fusch";
      char** targv = argv + 1;
      argc++;
      jboolean isCopy = JNI_TRUE;
        char *cmdstr = (*env)->GetStringUTFChars(env, pCmdStr, &isCopy);
        if (NULL == cmdstr) {
           LOGI(2, "get string failed");
           return EXIT_FAILURE;
         }
         char* pch;
        pch = strtok(cmdstr, " ");
        while (NULL != pch) {
           *targv = pch;
           argc++;
           targv++;
           pch = strtok(NULL, " ");
       }
        LOGI(1, "No. of arguments: %d", argc);
         LOGI(1, "%s %s %s %s", argv[0], argv[1], argv[2], argv[3]);
    #else
     int main(int argc, char *argv[]) {
    #endif
    ```

1.  在 `main` 方法的 `return` 语句之前添加以下行，以释放本地字符串和缓存的 JavaVM 引用，避免内存泄漏：

    ```kt
    #ifdef ANDROID_BUILD
       (*env)->ReleaseStringUTFChars(env, pCmdStr, cmdstr);
       (*env)->DeleteGlobalRef(env, cachedMainActObj);
       cachedMainActObj = NULL;
    #endif
    ```

1.  为了更新 GUI，我们向 Java 代码发送一条消息。我们需要更新源文件不同部分用于生成输出消息的代码。以下是这方面的一个示例：

    ```kt
    #ifdef ANDROID_BUILD
      progStr = (*env)->NewStringUTF(env, MSG[I_NOTHINGTODO]);
      (*env)->CallVoidMethod(env, pMainActObj, updateProgMID, progStr, 0);
    #else
      puts(MSG[I_NOTHINGTODO]);
    #endif
    ```

1.  `seam_progress` 和 `carve_progress` 函数是由在 `naMain` 启动的本地线程执行的。我们使用了缓存的 `JavaVM` 引用 `cachedJvm` 和 `MainActivity` 对象引用 `cachedMainActObj` 来获取在 `MainActivity.java` 中定义的 `updateProgress` 方法的 `jmethodID`。

    ```kt
    #ifdef ANDROID_BUILD
      char progBuf[500];
      JNIEnv *env;
      jmethodID updateProgMID;
      (*cachedJvm)->AttachCurrentThread(cachedJvm, &env, NULL);
      jstring progStr;
      jclass mainActivityClass = (*env)->GetObjectClass(env, cachedMainActObj);
      updateProgMID = (*env)->GetMethodID(env, mainActivityClass, "updateProgress", "(Ljava/lang/String;I)V");
      if (NULL == updateProgMID) {
        LOGE(1, "error finding method updateProgress at seam_progress");
        (*cachedJvm)->DetachCurrentThread(cachedJvm);
        pthread_exit((void*)NULL);
      }
    #endif
    ```

1.  然后，我们可以从 `seam_progress` 和 `carve_progress` 调用 `updateProgress` 方法。以下是来自 `carve_progress` 函数的代码段，显示了这一点：

    ```kt
    #ifdef ANDROID_BUILD
      sprintf(progBuf, "%6d %6d %3d%%", max, pro, lrintf((float)(pro * 100) / max));
      progStr = (*env)->NewStringUTF(env, progBuf);
      (*env)->CallVoidMethod(env, cachedMainActObj, updateProgMID, progStr, 1);
    #else
      printf("%6d %3d%% ", pro, lrintf((float)(pro * 100) / max));
    #endif
    ```

1.  构建并运行 Android 应用。你应该能看到一个与以下截图相似的图形用户界面：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_09_07.jpg)

1.  我们可以点击**宽度**或**高度**按钮开始处理。左中和右截图分别显示了处理过程和结果：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_09_15.jpg)

## 工作原理...

前面的示例显示了如何使用后台线程处理繁重的处理工作，以便 GUI 能够响应用户输入。当后台线程处理图像时，它还会向 UI 线程发送进度更新。

`fusch` 程序的细节实际上比所描述的核心思想要复杂一些，因为它使用了大量的并发处理。以下图表对此进行了说明：

![工作原理...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505OT_09_11.jpg)

一旦我们在 `MainActivity.java` 中点击了**宽度**或**高度**按钮，将创建一个新的 Java 线程（**后台线程 1**），其实例为 `ImageProcRunnable`。此线程将调用 `naMain` 本地方法。

在 `naMain` 方法中使用 `pthread_create` 函数创建了多个本地线程。其中两个，分别标记为**后台线程 2**和**后台线程 3**，将分别运行 `seam_progress` 和 `carve_progress`。

在所有三个后台线程中，我们向绑定到 UI 线程的处理程序发送 `MSG_TYPE_PROG` 类型的消息。处理程序将处理这些消息并更新图形用户界面。

### 从本地代码发送消息

在 Java 中向处理程序发送消息很简单；我们只需调用 `handler.sendMessage()` 方法。但在本地代码中可能会有些麻烦。

在`MainActivity.java`中，我们定义了一个`updateProgress`方法，该方法接收一个字符串和一个整数，构建一条消息，并将其发送给处理器。本地代码通过 JNI 调用这个 Java 方法以便发送消息。有两种情况：

+   **本地代码在 Java 线程中**：这是前一个图中**后台线程 1**的情况。该线程是在 Java 代码中创建的，并调用了`naMain`本地方法。在`naMain`中，我们获取`updateProgress`的`jmethodID`，并通过 JNI 函数`CallVoidMethod`调用`updateProgress`方法。更多详情，您可以参考第二章，*Java Native Interface*中的*Calling static and instance methods from native code*一节。

+   **本地代码在本地线程中**：这就是**后台线程 2**和**后台线程 3**发生的情况。这些线程是通过`naMain`中的`pthread_create`函数创建的。在进行任何 JNI 调用之前，我们必须调用`AttachCurrentThread`将本地线程附加到 Java 虚拟机。注意，我们使用了缓存的`MainActivity`对象引用`cachedMainActObj`来调用`updateProgress`方法。关于在 JNI 中缓存更多详情，我们可以参考第二章，*Java Native Interface*中的*Caching jfieldID, jmethodID, and reference data to improve performance*一节。

我们创建的 GUI 看起来并不完美，但它足够简单，足以说明如何使用后台线程进行繁重处理以及从本地代码发送 GUI 更新消息。
