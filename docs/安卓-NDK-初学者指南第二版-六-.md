# 安卓 NDK 初学者指南第二版（六）

> 原文：[`zh.annas-archive.org/md5/A3DD702F9D1A87E6BE95B1711A85BCDE`](https://zh.annas-archive.org/md5/A3DD702F9D1A87E6BE95B1711A85BCDE)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十章：使用 RenderScript 进行密集计算

> *如果 NDK 是在 Android 上获得高性能的最佳工具之一。它提供了对机器的低级访问，让你控制内存分配，提供对高级 CPU 指令集的访问，甚至更多。*
> 
> *这种能力是有代价的：要想在一块关键代码上获得最大性能，需要针对世界上许多设备和平台优化代码。有时，使用 CPU SIMD 指令更合适，而其他时候，在 GPU 上进行计算更佳。你最好有丰富的经验、大量的设备和充足的时间！这就是谷歌在 Android 上引入 RenderScript 的原因。*

**RenderScript** 是一种专为 Android 设计的编程语言，它的编写宗旨是：*性能*。明确一点，应用程序不能完全用 RenderScript 编写。但是，那些需要密集计算的关键部分，应该用！RenderScript 可以从 Java 或 C/C++ 中执行。

在本章中，我们将讨论这些基础知识，并将我们的努力集中在它的 NDK 绑定上。我们将创建一个新项目来演示通过过滤图像的 RenderScript 功能。更准确地说，我们将了解如何：

+   执行预定义的**内置函数**

+   创建你自己的自定义**内核**

+   将内置函数和内核结合在一起

到本章结束时，你应该能够创建自己的 RenderScript 程序并将它们绑定到你的原生代码中。

# 什么是 RenderScript？

RenderScript 在 2011 年的 Honeycomb 中被引入，重点是图形处理能力，因此得名。然而，自 Android 4.1 JellyBean 起，RenderScript 的图形引擎部分已被弃用。尽管保留了它的名字，但 RenderScript 已经深刻演变，强调其“计算引擎”。它与 OpenCL 和 CUDA 等技术相似，重点是可移植性和可用性。

更具体地说，RenderScript 试图将硬件的具体性从程序员中抽象出来，并从中提取最大的原始力量。它不是采取最小公倍数，而是根据运行时执行的平台优化代码。最终代码可以在 CPU 或 GPU 上运行，具有由 RenderScript 管理的自动并行化的优势。

RenderScript 框架由几个元素组成：

+   一种基于 C99 的 C 语言，提供变量、函数、结构等。

+   开发者机器上基于**低级虚拟机**（**LLVM**）的编译器，生成中间代码

+   一个 RenderScript 库和运行时，只有在最终程序在设备上运行时才将中间代码转换为机器代码

+   一个 Java 和 NDK 绑定 API，用于执行和链接计算任务

计算任务显然是 RenderScript 的核心。有两种类型的任务：

+   内核，这是用户创建的脚本，使用 RenderScript 语言执行计算任务

+   内置函数（Intrinsics），用于执行一些常见任务，如模糊像素的内置内核（Kernels）。

内核（Kernels）和内置函数（Intrinsics）可以组合在一起，一个程序的输出链接到另一个程序的输入。从复杂的计算任务图中可以快速生成强大程序。

然而，现在让我们看看内置函数（Intrinsics）是什么以及它们是如何工作的。

# 执行一个预定义的内置函数（Intrinsic）。

`RenderScript`提供了一些内置函数，主要用于图像处理，称为内置函数（Intrinsics）。使用这些函数，可以实现像 Photoshop 中那样的图像混合、模糊处理，甚至是从相机中解码原始 YUV 图像（对于更慢的替代方案，请参见第四章，*从本地代码调用 Java*）。这些内置函数简单高效。实际上，内置函数经过高度优化，可以认为是它们领域中最好的实现之一。

为了了解内置函数（Intrinsics）是如何工作的，让我们创建一个新项目，该项目接收一个输入图像并对其应用模糊效果。

### 注意：

本书提供的项目名为`RenderScript_Part1`。

# 动手操作——创建一个 Java UI。

让我们创建一个带有 JNI 模块的新 Java 项目。

1.  按照在第二章，*开始一个本地 Android 项目*中所示，创建一个新的混合 Java/C++项目：

    +   将其命名为`RenderScript`。

    +   主包名为`com.packtpub.renderscript`。

    +   `minSdkVersion`为 9，`targetSdkVersion`为 19。

    +   在`AndroidManifest.xml`文件中定义`android.permission.WRITE_EXTERNAL_STORAGE`权限。

    +   将项目转换为已经了解过的本地项目。

    +   移除由 ADT 创建的本地源文件和头文件。

    +   将主活动命名为`RenderScriptActivity`，其布局命名为`activity_renderscript.xml`。

1.  按如下方式定义`project.properties`文件。这些行激活了`RenderScript`支持库，允许将代码移植到直到 API 8 的旧设备上。

    ```java
    target=android-20
    renderscript.target=20
    renderscript.support.mode=true
    sdk.buildtools=20

    ```

1.  修改`res/activity_renderscript.xml`文件，使其看起来如下所示。我们将需要：

    +   一个`SeekBar`来定义模糊半径。

    +   一个用于应用模糊效果的`Button`。

    +   两个`ImageView`元素用于显示应用效果前后的图像。

        ```java
        <?xml version="1.0" encoding="utf-8"?>
        <LinearLayout

          a:layout_width="fill_parent" a:layout_height="fill_parent"
          a:layout_weight="1" a:orientation="vertical" >
          <LinearLayout 
            a:orientation="horizontal"
            a:layout_width="fill_parent" a:layout_height="wrap_content" >
            <SeekBar a:id="@+id/radiusBar" a:max="250"
              a:layout_gravity="center_vertical"
              a:layout_width="128dp" a:layout_height="wrap_content" />
            <Button a:id="@+id/blurButton" a:text="Blur"
              a:layout_width="wrap_content" a:layout_height="wrap_content"/>
          </LinearLayout>
          <LinearLayout 
            a:baselineAligned="true" a:orientation="horizontal"
            a:layout_width="fill_parent" a:layout_height="fill_parent" >
            <ImageView
              a:id="@+id/srcImageView" a:layout_weight="1"
              a:layout_width="fill_parent" a:layout_height="fill_parent" />
            <ImageView
              a:id="@+id/dstImageView" a:layout_weight="1"
              a:layout_width="fill_parent" a:layout_height="fill_parent" />
          </LinearLayout>
        </LinearLayout>
        ```

1.  按照下面所示实现`RenderScriptActivity`。

    加载`RSSupport`模块，它是`RenderScript`的支持库，以及`renderscript`模块，我们将在一个静态块中创建它。

    然后，在`onCreate()`方法中，从`drawable`资源目录下加载一个 32 位的位图（这里命名为`picture`），并创建一个相同大小的空白位图。将这些位图分配给它们各自的`ImageView`组件。同时，为**模糊**按钮定义`OnClickListener`。

    ```java
    package com.packtpub.renderscript;
    ...
    public class RenderScriptActivity extends Activity
    implements OnClickListener {
        static {

            System.loadLibrary("renderscript");
        }

        private Button mBlurButton;
        private SeekBar mBlurRadiusBar, mThresholdBar;
        private ImageView mSrcImageView, mDstImageView;
        private Bitmap mSrcImage, mDstImage;

        @Override
        protected void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            setContentView(R.layout.activity_renderscript);

            BitmapFactory.Options options = new BitmapFactory.Options();
            options.inPreferredConfig = Bitmap.Config.ARGB_8888;
            mSrcImage = BitmapFactory.decodeResource(getResources(),
                                            R.drawable.picture, options);
            mDstImage = Bitmap.createBitmap(mSrcImage.getWidth(),
                                            mSrcImage.getHeight(),
                                            Bitmap.Config.ARGB_8888);

            mBlurButton = (Button) findViewById(R.id.blurButton);
            mBlurButton.setOnClickListener(this);

            mBlurRadiusBar = (SeekBar) findViewById(R.id.radiusBar);

            mSrcImageView = (ImageView) findViewById(R.id.srcImageView);
            mDstImageView = (ImageView) findViewById(R.id.dstImageView);
            mSrcImageView.setImageBitmap(mSrcImage);
            mDstImageView.setImageBitmap(mDstImage);
        }
    ...
    ```

1.  创建一个本地函数`blur`，它带有以下参数：

    +   `RenderScript`运行时的应用程序缓存目录。

    +   源位图和目标位图。

    +   模糊效果的半径，以确定模糊的强度。

    在`onClick()`处理程序中调用这个方法，使用滑动条值来确定模糊半径。半径必须在`[0, 25]`范围内。

    ```java
    ...
        private native void blur(String pCacheDir, Bitmap pSrcImage,
                                 Bitmap pDstImage, float pRadius);

        @Override
        public void onClick(View pView) {
            float progressRadius = (float) mBlurRadiusBar.getProgress();
            float radius = Math.max(progressRadius * 0.1f, 0.1f);

            switch(pView.getId()) {
            case R.id.blurButton:
                blur(getCacheDir().toString(), mSrcImage, mDstImage,
                     radius);
                break;
            }
            mDstImageView.invalidate();
        }
    }
    ```

# 行动时间——运行 RenderScript 模糊内置（Blur intrinsic）。

让我们创建一个本地模块，用于生成我们的新效果。

1.  创建一个新文件`jni/RenderScript.cpp`。我们需要以下内容：

    +   使用`android/bitmap.h`头文件操作位图。

    +   使用`jni.h`处理 JNI 字符串。

    +   `RenderScript.h`是主要的`RenderScript`头文件。这是你需要唯一的一个。RenderScript 是用 C++编写的，并在`android::RSC`命名空间中定义。

        ```java
        #include <android/bitmap.h>
        #include <jni.h>
        #include <RenderScript.h>

        using namespace android::RSC;
        ...
        ```

1.  写两个实用方法，按照第四章，*从本地代码调用 Java*中所示锁定和解锁 Android 位图：

    ```java
    ...
    void lockBitmap(JNIEnv* pEnv, jobject pImage,
            AndroidBitmapInfo* pInfo, uint32_t** pContent) {
        if (AndroidBitmap_getInfo(pEnv, pImage, pInfo) < 0) abort();
        if (pInfo->format != ANDROID_BITMAP_FORMAT_RGBA_8888) abort();
        if (AndroidBitmap_lockPixels(pEnv, pImage,
                (void**)pContent) < 0) abort();
    }

    void unlockBitmap(JNIEnv* pEnv, jobject pImage) {
        if (AndroidBitmap_unlockPixels(pEnv, pImage) < 0) abort();
    }
    ...
    ```

1.  使用 JNI 约定实现本地方法`blur()`。

    然后，实例化 RS 类。这个类是主要的接口，控制 RenderScript 初始化、资源管理和对象创建。使用 RenderScript 提供的`sp`帮助类包装它，这代表一个智能指针。

    使用提供的缓存目录初始化它，并使用 JNI 适当地转换字符串：

    ```java
    ...
    extern "C" {

    JNIEXPORT void JNICALL
    Java_com_packtpub_renderscript_RenderScriptActivity_blur
    (JNIEnv* pEnv, jobject pClass, jstring pCacheDir, jobject pSrcImage,
            jobject pDstImage, jfloat pRadius) {
        const char * cacheDir = pEnv->GetStringUTFChars(pCacheDir, NULL);
        sp<RS> rs = new RS();
        rs->init(cacheDir);
        pEnv->ReleaseStringUTFChars(pCacheDir, cacheDir);
    ...
    ```

1.  使用我们刚才编写的实用方法锁定我们正在操作的位图：

    ```java
    ...
        AndroidBitmapInfo srcInfo; uint32_t* srcContent;
        AndroidBitmapInfo dstInfo; uint32_t* dstContent;
        lockBitmap(pEnv, pSrcImage, &srcInfo, &srcContent);
        lockBitmap(pEnv, pDstImage, &dstInfo, &dstContent);
    ...
    ```

1.  现在是这部分有趣的内容。从源位图创建一个 RenderScript 的**分配（Allocation）**。这个`ALLOCATION`代表了整个输入内存区域，其维度由`Type`定义。分配（Allocation）由“单个”**元素（Elements）**组成；在我们的案例中，32 位 RGBA 像素定义为`Element::RGBA_8888`。由于位图不作为纹理使用，我们不需要**Mipmaps**（更多信息请参见第六章，*使用 OpenGL ES 渲染图形*）。

    对从输出位图创建的输出`ALLOCATION`重复相同的操作：

    ```java
    ...
        sp<const Type> srcType = Type::create(rs, Element::RGBA_8888(rs),
                srcInfo.width, srcInfo.height, 0);
        sp<Allocation> srcAlloc = Allocation::createTyped(rs, srcType,
                RS_ALLOCATION_MIPMAP_NONE,
                RS_ALLOCATION_USAGE_SHARED | RS_ALLOCATION_USAGE_SCRIPT,
                srcContent);

        sp<const Type> dstType = Type::create(rs, Element::RGBA_8888(rs),
                dstInfo.width, dstInfo.height, 0);
        sp<Allocation> dstAlloc = Allocation::createTyped(rs, dstType,
                RS_ALLOCATION_MIPMAP_NONE,
                RS_ALLOCATION_USAGE_SHARED | RS_ALLOCATION_USAGE_SCRIPT,
                dstContent);
    ...
    ```

1.  创建一个`ScriptIntrinsicBlur`实例以及它处理的数据类型，即 RGBA 像素。内置（Intrinsic）是一个预定义的 RenderScript 函数，实现了一些常见的操作，比如我们案例中的模糊效果。**模糊内置（Blur Intrinsic）**以一个半径作为输入参数。使用`setRadius()`设置它。

    然后，指定模糊内置（Intrinsic）的输入，即使用`setInput()`的源分配（Allocation）。

    使用`forEach()`将内置（Intrinsic）应用于每个元素，并将其保存到输出分配（Allocation）中。

    最后，使用`copy2DRangeTo()`将结果复制到目标位图。

    ```java
    ...
        sp<ScriptIntrinsicBlur> blurIntrinsic =
                ScriptIntrinsicBlur::create(rs, Element::RGBA_8888(rs));
        blurIntrinsic->setRadius(pRadius);

        blurIntrinsic->setInput(srcAlloc);
        blurIntrinsic->forEach(dstAlloc);
        dstAlloc->copy2DRangeTo(0, 0, dstInfo.width, dstInfo.height,
                dstContent);
    ...
    ```

1.  在应用效果后，不要忘记解锁位图！

    ```java
    ...
        unlockBitmap(pEnv, pSrcImage);
        unlockBitmap(pEnv, pDstImage);
    }
    }
    ```

1.  创建一个`jni/Application.mk`文件，针对`ArmEABI V7`和`X86`平台。实际上，RenderScript 目前不支持较旧的`ArmEABI V5`。需要`STLPort`，这也是 RenderScript 本地库要求的。

    ```java
    APP_PLATFORM := android-19
    APP_ABI := armeabi-v7a x86
    APP_STL := stlport_static
    ```

1.  创建一个`jni/Android.mk`文件，定义我们的`renderscript`模块，并列出`RenderScript.cpp`进行编译。

    将 `LOCAL_C_INCLUDES` 指向适当的 RenderScript，包括 NDK 平台目录中的文件目录。同时，将 RenderScript 预编译库目录添加到 `LOCAL_LDFLAG`。

    最后，链接到 `dl`、`log` 和 `RScpp_static`，这些是 RenderScript 必需的：

    ```java
    LOCAL_PATH := $(call my-dir)

    include $(CLEAR_VARS)

    LOCAL_MODULE    := renderscript
    LOCAL_C_INCLUDES += $(TARGET_C_INCLUDES)/rs/cpp \
                        $(TARGET_C_INCLUDES)/rs
    LOCAL_SRC_FILES := RenderScript.cpp
    LOCAL_LDFLAGS += -L$(call host-path,$(TARGET_C_INCLUDES)/../lib/rs)
    LOCAL_LDLIBS    := -ljnigraphics -ldl -llog -lRScpp_static

    include $(BUILD_SHARED_LIBRARY)
    ```

## *发生了什么？*

运行项目，增加 `SeekBar` 的值，点击 **模糊** 按钮。输出 `ImageView` 应显示如下过滤后的图片：

![发生了什么？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_10_01.jpg)

我们在项目中嵌入了 RenderScript 兼容库，使我们能够访问到 API 8 Froyo 的 RenderScript。在旧设备上，RenderScript 是在 CPU 上“模拟”的。

### 提示

如果您决定从 NDK 使用 RenderScript 但不想使用兼容库，则需要手动嵌入 RenderScript 运行时。为此，删除在第 2 步中添加到 `project.properties` 文件的所有内容，并在您的 `Android.mk` 文件的末尾包含以下代码片段：

```java
...
include $(CLEAR_VARS)
LOCAL_MODULE := RSSupport
LOCAL_SRC_FILES := $(SYSROOT_LINK)/usr/lib/rs/lib$(LOCAL_MODULE)$(TARGET_ SONAME_EXTENSION)
include $(PREBUILT_SHARED_LIBRARY)
```

然后，我们执行了第一个 RenderScript 内在（Intrinsic），尽可能高效地应用了模糊效果。内在执行遵循一种简单且重复的模式，您会多次看到：

1.  确保输入和输出内存区域是独占可用的，例如，通过锁定位图。

1.  创建或重用适当的输入和输出分配。

1.  创建并设置内在参数。

1.  设置输入分配（Allocation），并将内在（Intrinsic）应用于输出分配。

1.  将输出分配中的结果复制到目标内存区域。

为了更好地理解这个过程，让我们更深入地了解 RenderScript 的工作方式。RenderScript 遵循一个简单的模型。它获取一些数据作为输入，并处理到输出内存区域：

![发生了什么？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_10_04.jpg)

作为计算解决方案，RenderScript 处理内存中存储的任何类型的数据。这是一个分配（Allocation）。分配由单个元素组成。对于一个指向位图的分配，元素通常是一个像素（本身是一组 4 个 `uchar` 值）。在众多可用的元素中，我们可以列举：

| 可能的分配元素 |
| --- |
| `U8`, `U8_2`, `U8_3`, `U8_4` | `I8`, `I8_2`, `I8_3`, `I8_4` | `RGBA_8888` |
| `U16`, `U16_2`, `U16_3`, `U16_4` | `I16`, `I16_2`, `I16_3`, `I16_4` | `RGB_565` |
| `U32`, `U32_2`, `U32_3`, `U32_4` | `I32`, `I32_2`, `I32_3`, `I32_4` | `RGB_888` |
| `U64`, `U64_2`, `U64_3`, `U64_4` | `I64`, `I64_2`, `I64_3`, `I64_4` | `A_8` |
| `F32`, `F32_2`, `F32_3`, `F32_4` | `F64`, `F64_2`, `F64_3`, `F64_4` | `YUV` |
| `MATRIX_2X2` | `MATRIX_3X3` | `MATRIX_4X4` |

`U` = 无符号整数，`I` = 有符号整数，`F` = 浮点数

`8`, `16`, `32`, `64` = 字节计数。例如 `I8` = 8 位有符号整型（即有符号字符）

`_2`, `_3`, `_4` = 向量中的元素数量（`I8_3` 表示 3 个有符号整数的向量）

`A_8` 表示 Alpha 通道（每个像素表示为一个无符号字符）。

在内部，Element 使用 **DataType**（例如 `UNSIGNED_8` 表示无符号字符）和 **DataKind**（例如 `PIXEL_RGBA` 表示像素）来描述。DataKind 与称为 **Samplers** 的东西一起用于在 GPU 上解释的图形数据（请参阅第六章，*使用 OpenGL ES 渲染图形*，以更好地了解什么是 Sampler）。DataType 和 DataKind 是更高级的用法，大多数时候对您应该是透明的。您可以在 [`developer.android.com/reference/android/renderscript/Element.html`](http://developer.android.com/reference/android/renderscript/Element.html) 查看完整的 Element 列表。 |

仅仅知道输入/输出 Element 的类型是不够的。它们的数量同样重要，因为这决定了整个 Allocation 的大小。这就是 `Type` 的作用，它可以设置为 1 维，2 维（通常用于位图），或 3 维。还支持其他一些信息，例如 YUV 格式（NV21 是 Android 中的默认格式，如第四章，*从本地代码调用 Java* 中所见）。换句话说，`Type` 描述了一个多维数组。

Allocation 有一个特定的标志来控制如何生成 Mipmaps。默认情况下，大多数 Allocation 都不需要 Mipmap (`RS_ALLOCATION_MIPMAP_NONE`)。然而，当作为图形纹理的输入时，Mipmap 要么在脚本内存中创建 (`RS_ALLOCATION_MIPMAP_FULL`)，要么在上传到 GPU 时创建 (`RS_ALLOCATION_MIPMAP_ON_SYNC_TO_TEXTURE`)。

一旦我们根据 Type 和 Element 创建了 Allocation，就可以处理创建和设置 Intrinsics。RenderScript 提供了一些主要关注图像处理的内置函数，虽然数量不多：

| 内置函数 | 描述 |
| --- | --- |

|

```java
ScriptIntrinsicBlend
```

| 用于将两个 Allocation 混合在一起，例如，两个图像（我们将在本章的最后部分看到加性混合）。 |
| --- |

|

```java
ScriptIntrinsicBlur
```

| 用于在 Bitmap 上应用模糊效果。 |
| --- |

|

```java
ScriptIntrinsicColorMatrix
```

| 用于将颜色矩阵应用到 Allocation（例如，调整图像色调，改变颜色等）。 |
| --- |

|

```java
ScriptIntrinsicConvolve3x3
```

| 用于将大小为 3 的卷积矩阵应用到 Allocation（许多图像滤镜可以通过卷积矩阵实现，包括模糊处理）。 |
| --- |

|

```java
ScriptIntrinsicConvolve5x5
```

| 这与 `ScriptIntrinsicConvolve3x3` 相同，但使用的是大小为 5 的矩阵。 |
| --- |

|

```java
ScriptIntrinsicHistogram
```

| 用于应用直方图滤镜（例如，提高图像对比度）。 |
| --- |

|

```java
ScriptIntrinsicLUT
```

| 用于每个通道应用“查找表”（例如，将像素中给定的红色值转换为表中另一个预定义的值）。 |
| --- |

|

```java
ScriptIntrinsicResize
```

| 用于调整 2D Allocation 的大小（例如，缩放图像）。 |
| --- |

|

```java
ScriptIntrinsicYuvToRGB
```

| 例如，要将来自相机的 YUV 图像转换为 RGB 图像（就像我们在第四章，*从本地代码调用 Java*中所做的那样）。在 NDK 中绑定这个内置函数是有问题的，因此在本书编写时无法使用。如果你确实需要它，从 Java 应用它。 |
| --- |

每个内置函数都需要其自己的特定参数（例如，模糊效果的半径）。完整的内置函数文档可以在 [`developer.android.com/reference/android/renderscript/package-summary.html`](http://developer.android.com/reference/android/renderscript/package-summary.html) 找到。

内置函数需要输入和输出分配。从技术上讲，如果应用的函数类型适当，可以使用输入作为输出。例如，`ScriptIntrinsicBlur` 就不适用，因为模糊的像素可能在同时被读取以模糊其他像素时被写入。

设置好分配后，应用内置函数并执行其工作。之后，结果必须使用 `copy***To()` 方法之一（对于具有两个维度的位图使用 `copy2DRangeTo()`，如果目标区域有间隔则使用 `copy2DStridedTo()`）复制到输出内存区域。数据复制是在使用计算结果之前的一个必要步骤。

### 提示

在某些设备上，如果图像分配的大小不是 4 的倍数，已经报告了一些问题。这可能会让你想起 OpenGL 纹理，它们也有相同的要求。因此，尽量使用 4 的倍数的尺寸。

尽管 RenderScript 提供的内置函数确实很有用，但你可能需要更多的灵活性。也许你需要自己的自定义图像滤镜，或者需要超过 25 像素的模糊效果，或者你可能根本不想处理图像。那么，RenderScript 内核可能就是你要找的答案。

# 编写自定义内核

RenderScript 让你有能力开发小的自定义“脚本”，而不是内置函数。这些程序称为内核，用类似 C 的语言编写。它们由基于 RenderScript LLVM 的编译器在构建时编译成中间语言。最后，它们在运行时被翻译成机器码。RenderScript 负责平台相关的优化。

现在，让我们看看如何通过实现一个根据像素亮度过滤的自定义图像效果来创建这样的内核。

### 注意事项

最终的项目随书提供，名为 `RenderScript_Part2`。

# 动手时间 – 编写一个亮度阈值滤波器

让我们在 UI 中添加一个新组件并实现新的图像滤镜。

1.  在 `res/activity_renderscript.xml` 中添加一个新的 **阈值** `SeekBar` 和 `Button`：

    ```java
    <?xml version="1.0" encoding="utf-8"?>
    <LinearLayout

      a:layout_width="fill_parent" a:layout_height="fill_parent"
      a:layout_weight="1" a:orientation="vertical" >
      <LinearLayout 
        a:orientation="horizontal"
        a:layout_width="fill_parent" a:layout_height="wrap_content" >
        ...
        <SeekBar a:id="@+id/thresholdBar" a:max="100"
     a:layout_gravity="center_vertical"
     a:layout_width="128dp" a:layout_height="wrap_content" />
     <Button a:id="@+id/thresholdButton" a:text="Threshold"
     a:layout_width="wrap_content" a:layout_height="wrap_content"/>
      </LinearLayout>
      <LinearLayout 
        a:baselineAligned="true" a:orientation="horizontal"
        a:layout_width="fill_parent" a:layout_height="fill_parent" >
        ...
      </LinearLayout>
    </LinearLayout>
    ```

1.  编辑 `RenderScriptActivity`，并将**阈值** `SeekBar` 和 `Button` 绑定到一个新的本地方法 `threshold()`。这个方法与 `blur()` 类似，不同之处在于它接收一个在范围 [`0`, `100`] 内的浮点阈值参数。

    ```java
    ...
    public class RenderScriptActivity extends Activity
    implements OnClickListener {
        ...

        private Button mBlurButton, mThresholdButton;
        private SeekBar mBlurRadiusBar, mThresholdBar;
        private ImageView mSrcImageView, mDstImageView;
        private Bitmap mSrcImage, mDstImage;

        @Override
        protected void onCreate(Bundle savedInstanceState) {
            ...

            mBlurButton = (Button) findViewById(R.id.blurButton);
            mBlurButton.setOnClickListener(this);
            mThresholdButton = (Button)findViewById(R.id.thresholdButton);
     mThresholdButton.setOnClickListener(this);

            mBlurRadiusBar = (SeekBar) findViewById(R.id.radiusBar);
            mThresholdBar = (SeekBar) findViewById(R.id.thresholdBar);

            ...
        }

        @Override
        public void onClick(View pView) {
            float progressRadius = (float) mBlurRadiusBar.getProgress();
            float radius = Math.max(progressRadius * 0.1f, 0.1f);
            float threshold = ((float) mThresholdBar.getProgress())
                            / 100.0f;

            switch(pView.getId()) {
            ...

            case R.id.thresholdButton:
                threshold(getCacheDir().toString(), mSrcImage, mDstImage,
                          threshold);
                break;
            }
            mDstImageView.invalidate();
        }
        ...

        private native void threshold(String pCacheDir, Bitmap pSrcImage,
                                      Bitmap pDstImage, float pThreshold);
    }
    ```

1.  现在，让我们使用 RenderScript 语言编写自己的 `jni/threshold.rs` 过滤器。首先，使用 pragma 指令声明：

    +   脚本语言版本（目前只有 `1` 是可能的）

    +   脚本关联的 Java 包名

        ```java
        #pragma version(1)
        #pragma rs java_package_name(com.packtpub.renderscript)
        ...
        ```

1.  然后，声明一个类型为 `float` 的输入参数 `thresholdValue`。

    我们还需要两个 3 个浮点数（`float3`）的常量向量。

    +   第一个值表示 `BLACK` 颜色

    +   第二个值是一个预定义的 `LUMINANCE_VECTOR`。

        ```java
        ...
        float thresholdValue;
        static const float3 BLACK = { 0.0, 0.0, 0.0 };
        static const float3 LUMINANCE_VECTOR = { 0.2125, 0.7154, 0.0721 };
        ...
        ```

1.  创建名为 `threshold()` 的脚本根函数。它接收一个 4 个无符号字符的向量，即输入的 RGBA 像素，并输出一个新的像素。使用 `__attribute__((kernel))` 作为前缀，表示这个函数是主要的脚本函数，即“Kernel 的根”。该函数的工作原理如下：

    +   它将输入像素从字符向量转换成浮点值向量，每个颜色分量在范围 [`0`, `255`] 内，转换成每个分量在范围 [`0.0`, `1.0`] 内的向量。这是函数 `rsUnpackColor8888()` 的作用。

    +   现在我们有了浮点向量，可以使用 RenderScript 提供的许多数学函数之一。这里，与 RGBA 颜色空间的预定义亮度向量进行点乘，返回一个像素的相对亮度。

    +   有了这些信息，函数会检查一个像素的亮度是否根据给定的阈值足够。如果不是，像素将被设置为黑色。

    +   最后，它通过 `rsPackColor8888()` 将像素颜色的浮点向量转换为无符号字符向量。这个值随后会被 RenderScript 复制到最终的 Bitmap 中，我们稍后会看到。

        ```java
        ...
        uchar4 __attribute__((kernel)) threshold(uchar4 in) {
            float4 pixel = rsUnpackColor8888(in);
            float luminance = dot(LUMINANCE_VECTOR, pixel.rgb);
            if (luminance < thresholdValue) {
                pixel.rgb = BLACK;
            }
            return rsPackColorTo8888(pixel);
        }
        ```

1.  要编译我们新的 `threshold.rs` 脚本，请在 `Android.mk` 文件中列出它。

    在编译过程中，`ScriptC_threshold.h` 和 `ScriptC_threshold.cpp` 会被生成在 `obj/local/armeabi-v7a/objs-debug/renderscript` 目录下。这些文件包含将我们的代码与由 RenderScript 执行的**阈值 Kernel**绑定的代码。因此，我们还需要将此目录添加到 `LOCAL_C_INCLUDES` 目录中：

    ```java
    LOCAL_PATH := $(call my-dir)

    include $(CLEAR_VARS)

    LOCAL_MODULE    := renderscript
    LOCAL_C_INCLUDES += $(TARGET_C_INCLUDES)/rs/cpp \
                        $(TARGET_C_INCLUDES)/rs \
                        $(TARGET_OBJS)/$(LOCAL_MODULE)
    LOCAL_SRC_FILES := RenderScript.cpp threshold.rs
    LOCAL_LDFLAGS += -L$(call host-path,$(TARGET_C_INCLUDES)/../lib/rs)
    LOCAL_LDLIBS    := -ljnigraphics -ldl -llog -lRScpp_static

    include $(BUILD_SHARED_LIBRARY)
    ```

1.  在 `jni/RenderScript.cpp` 中包含生成的头文件。

    ```java
    #include <android/bitmap.h>
    #include <jni.h>
    #include <RenderScript.h>
    #include "ScriptC_threshold.h"

    using namespace android::RSC;

    ...
    ```

1.  接下来，按照 JNI 命名约定实现新的 `threshold()` 方法。这个方法与 `blur()` 方法类似。

    然而，我们不是实例化一个预定义的 Intrinsic，而是通过 RenderScript 实例化一个名为 `ScriptC_threshold` 的 Kernel，这个名字是根据我们的 RenderScript 文件名来的。

    我们的脚本中定义的输入参数 `thresholdValue` 可以通过 RenderScript 生成的 `set_thresholdValue()` 进行初始化。然后，可以使用生成的 `forEach_threshold()` 方法应用主方法 `threshold()`。

    应用了 Kernel 之后，结果可以像使用 Intrinsics 一样，通过 `copy2DRangeTo()` 复制到目标位图上：

    ```java
    ...
    JNIEXPORT void JNICALL
    Java_com_packtpub_renderscript_RenderScriptActivity_threshold
    (JNIEnv* pEnv, jobject pClass, jstring pCacheDir, jobject pSrcImage,
            jobject pDstImage, jfloat pThreshold) {
        const char * cacheDir = pEnv->GetStringUTFChars(pCacheDir, NULL);
        sp<RS> rs = new RS();
        rs->init(cacheDir);
        pEnv->ReleaseStringUTFChars(pCacheDir, cacheDir);

        AndroidBitmapInfo srcInfo;
        uint32_t* srcContent;
        AndroidBitmapInfo dstInfo;
        uint32_t* dstContent;
        lockBitmap(pEnv, pSrcImage, &srcInfo, &srcContent);
        lockBitmap(pEnv, pDstImage, &dstInfo, &dstContent);

        sp<const Type> srcType = Type::create(rs, Element::RGBA_8888(rs),
                srcInfo.width, srcInfo.height, 0);
        sp<Allocation> srcAlloc = Allocation::createTyped(rs, srcType,
                RS_ALLOCATION_MIPMAP_NONE,
                RS_ALLOCATION_USAGE_SHARED | RS_ALLOCATION_USAGE_SCRIPT,
                srcContent);

        sp<const Type> dstType = Type::create(rs, Element::RGBA_8888(rs),
                dstInfo.width, dstInfo.height, 0);
        sp<Allocation> dstAlloc = Allocation::createTyped(rs, dstType,
                RS_ALLOCATION_MIPMAP_NONE,
                RS_ALLOCATION_USAGE_SHARED | RS_ALLOCATION_USAGE_SCRIPT,
                dstContent);

        sp<ScriptC_threshold> thresholdKernel = new ScriptC_threshold(rs);
     thresholdKernel->set_thresholdValue(pThreshold);

        thresholdKernel->forEach_threshold(srcAlloc, dstAlloc);
        dstAlloc->copy2DRangeTo(0, 0, dstInfo.width, dstInfo.height,
                dstContent);

        unlockBitmap(pEnv, pSrcImage);
        unlockBitmap(pEnv, pDstImage);
    }
    }
    ```

## *刚才发生了什么？*

运行项目，增加新的 `SeekBar`，并点击 **阈值** 按钮。输出的 `ImageView` 应显示只有发光像素的过滤图片，如下所示：

![发生了什么？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_10_02.jpg)

我们编写并编译了第一个 RenderScript Kernel。Kernel 脚本以`.rs`为扩展名，并使用受 C99 启发的语言编写。它们的内容以 pragma 定义开始，这些定义提供了关于它们的额外“元”信息：语言版本（只能是 1）和 Java 包。我们还可以使用 pragma 指令调整浮点计算精度（`#pragma rs_fp_full`, `#pragma rs_fp_relaxed`，或`#pragma rs_fp_imprecise`）。

### 提示

Java 包对于 RenderScript 运行时很重要，它需要在执行期间解析编译后的 Kernels。当使用 RenderScript 兼容库时，使用 NDK 编译的脚本（存储在`jni`文件夹中）可能无法解析。在这种情况下，一个可能的解决方案是在 Java `src`文件夹中适当包内复制`.rs`文件。

Kernels 在某种程度上类似于 Intrinsics。实际上，一旦编译，它们应用的过程是相似的：创建分配、Kernel、设置一切、应用，最后复制结果。当执行时，Kernel 函数对输入的每个 Element 进行操作，并在对应的输出分配 Element 中并行返回。

你可以通过 NDK 绑定 API 和额外的绑定层（更常见的是称为**反射**层）来设置 Kernel，该层在编译时生成。每个编译的脚本都由一个 C++类“反射”，其名称根据脚本文件名前缀`ScriptC_`定义。最终代码在**同名**头文件和`obj`目录中的源文件中生成，每个 ABI 一个。反射类是与脚本文件交互的唯一接口，作为一种包装器。它们对传递给 Kernel 输入或输出的分配类型进行一些运行时检查，以确保其 Element 类型与脚本文件中声明的类型匹配。查看项目中`obj`目录下生成的`ScriptC_threshold.cpp`以获取具体示例。

Kernel 输入参数通过反射层传递给脚本文件，通过全局变量。全局变量对应于所有非`static`和非`const`变量，例如：

```java
float thresholdValue;
```

它们是在函数外部声明的，比如 C 变量。全局变量通过设置器在反射层中可用。在我们的项目中，`thresholdValue`全局变量通过生成的`set_thresholdValue()`方法传递。变量不必是基本类型。它们还可以是指针，在这种情况下，反射方法名称以`bind_`为前缀，并期望一个分配。在生成的类中也提供了获取器。

另一方面，与全局变量在同一作用域内声明的静态变量在 NDK 反射层中不可访问，且无法在脚本外部修改。当标记为`const`时，它们显然被视为常量，就像我们项目中亮度向量一样：

```java
static const float3 LUMINANCE_VECTOR = { 0.2125, 0.7154, 0.0721 };
```

主要的 Kernel 函数，更常见的称呼是**root 函数**，像声明 C 函数一样，只是它们用`__attribute__((kernel))`标记。它们以输入 Allocation 的 Element 类型作为参数，并以输出 Allocation 的 Element 类型作为返回值。输入参数和返回值都是可选的，但至少需要其中一个。在我们的示例中，输入参数和输出返回值都是一个像素 Element（即 4 个无符号字符的向量；每个颜色通道 1 字节）：

```java
uchar4 __attribute__((kernel)) threshold(uchar4 in) {
   ...
}
```

RenderScript 的 root 函数还可以提供额外的索引参数，这些参数表示 Allocation 内的 Element 位置（或“坐标”）。例如，我们可以在`threshold()`中声明两个额外的`uint32_t`参数，以获取像素 Element 的坐标：

```java
uchar4 __attribute__((kernel)) threshold(uchar4 in, uint32_t x, uint32_t y) {
   ...
}
```

在一个脚本中可以声明多个具有不同名称的 root 函数。编译后，它们在生成的类中以`forEach_`前缀的函数形式体现，例如：

```java
void forEach_threshold(android::RSC::sp<const android::RSC::Allocation> ain, android::RSC::sp<const android::RSC::Allocation> aout);
```

在`__attribute__((kernel))`引入之前，RenderScript 文件只能包含一个名为 root 的主函数。这种形式至今仍然被允许。这类函数接收输入、输出 Allocation 的指针作为参数，并且不允许有返回值。因此，将`threshold()`函数重写为传统的 root 方法如下所示：

```java
void root(const uchar4 *in, uchar4 *out) {
    float4 pixel = rsUnpackColor8888(*in);
    float luminance = dot(LUMINANCE_VECTOR, pixel.rgb);
    if (luminance < thresholdValue) {
        pixel.rgb = BLACK;
    }
    *out = rsPackColorTo8888(pixel);
```

除了`root()`函数之外，脚本还可以包含一个无参数和返回值的`init()`函数。这个函数在脚本实例化时只被调用一次。

```java
void init() {
    ...
}
```

显然，RenderScript 语言的功能比传统的 C 语言更有限、更受限制。我们无法：

+   直接分配资源。在运行 Kernel 之前，内存必须由客户端应用程序分配。

+   编写低级汇编代码或进行花哨的 C 语言操作。但是，希望有大量熟悉的 C 语言元素可用，比如`struct`、`typedef`、`enum`等等；甚至指针！

+   使用 C 库或运行时。然而，RenderScript 提供了一个完整的“运行时”库，其中包含大量的数学、转换、原子函数等。更多详细信息，请查看[`developer.android.com/guide/topics/renderscript/reference.html`](http://developer.android.com/guide/topics/renderscript/reference.html)。

    ### 提示

    RenderScript 提供的一个你可能觉得特别有用的方法是`rsDebug()`，它将调试日志打印到 ADB。

即使有这些限制，RenderScript 的限制仍然相当宽松。其结果是，某些脚本可能无法从最大加速中受益，例如在 GPU 上，这相当受限。为了解决这个问题，设计了一个名为 **FilterScript** 的 RenderScript 有限子集，以优化和兼容性。如果你需要最大性能，可以考虑使用它。

有关 RenderScript 语言功能的更多信息，请查看[`developer.android.com/guide/topics/renderscript/advanced.html`](http://developer.android.com/guide/topics/renderscript/advanced.html)。

# 组合脚本

*团结就是力量*对于 RenderScript 来说再真实不过了。内置函数和内核本身是强大的功能。然而，当它们结合在一起时，它们使 RenderScript 框架发挥出全部的力量。

让我们看看如何将**模糊**和**亮度**阈值滤镜与混合内置函数结合在一起，创建一个美观的图像效果。

### 注意

本书提供的项目在名称`RenderScript_Part3`下。

# 动手时间——组合内置函数和脚本

让我们改进项目，应用一个新的组合滤镜。

1.  在`res/activity_renderscript.xml`中添加一个新的**组合**`Button`，如下所示：

    ```java
    <?xml version="1.0" encoding="utf-8"?>
    <LinearLayout

      a:layout_width="fill_parent" a:layout_height="fill_parent"
      a:layout_weight="1" a:orientation="vertical" >
      <LinearLayout 
        a:orientation="horizontal"
        a:layout_width="fill_parent" a:layout_height="wrap_content" >
        ...
        <Button a:"d="@+id/thresholdBut"on" a:te"t="Thresh"ld"
          a:layout_wid"h="wrap_cont"nt" a:layout_heig"t="wrap_cont"nt"/>
        <Button a:"d="@+id/combineBut"on" a:te"t="Comb"ne"
          a:layout_wid"h="wrap_cont"nt" a:layout_heig"t="wrap_cont"nt"/>
      </LinearLayout>
      <LinearLayout 
        a:baselineAlign"d="t"ue" a:orientati"n="horizon"al"
        a:layout_wid"h="fill_par"nt" a:layout_heig"t="fill_par"nt" >
        ...
      </LinearLayout>
    </LinearLayout>
    ```

1.  将**组合**按钮绑定到一个新的本地方法`combine()`，该方法具有`blur()`和`threshold()`的参数：

    ```java
    ...
    public class RenderScriptActivity extends Activity
    implements OnClickListener {
        ...

        private Button mThresholdButton, mBlurButton, mCombineButton;
        private SeekBar mBlurRadiusBar, mThresholdBar;
        private ImageView mSrcImageView, mDstImageView;
        private Bitmap mSrcImage, mDstImage;

        @Override
        protected void onCreate(Bundle savedInstanceState) {
            ...

            mBlurButton = (Button) findViewById(R.id.blurButton);
            mBlurButton.setOnClickListener(this);
            mThresholdButton = (Button) findViewById(R.id.thresholdButton);
            mThresholdButton.setOnClickListener(this);
            mCombineButton = (Button)findViewById(R.id.combineButton);
            mCombineButton.setOnClickListener(this);

            ...
        }

        @Override
        public void onClick(View pView) {
            float progressRadius = (float) mBlurRadiusBar.getProgress();
            float radius = Math.max(progressRadius * 0.1f, 0.1f);
            float threshold = ((float) mThresholdBar.getProgress())
                            / 100.0f;

            switch(pView.getId()) {
            case R.id.blurButton:
                blur(getCacheDir().toString(), mSrcImage, mDstImage,
                     radius);
                break;

            case R.id.thresholdButton:
                threshold(getCacheDir().toString(), mSrcImage, mDstImage,
                          threshold);
                break;

            case R.id.combineButton:
                combine(getCacheDir().toString(), mSrcImage, mDstImage,
                        radius, threshold);
                break;
            }
            mDstImageView.invalidate();
        }
        ...

        private native void combine(String pCacheDir,
                                    Bitmap pSrcImage, Bitmap pDstImage,
                                    float pRadius, float pThreshold);
    }
    ```

1.  编辑`jni/RenderScript.cpp`并按照 JNI 约定添加新的`combine()`方法。该方法与我们之前看到的类似：

    +   初始化 RenderScript 引擎

    +   位图被锁定

    +   为输入和输出位图创建适当的分配

        ```java
        ...
        JNIEXPORT void JNICALL
        Java_com_packtpub_renderscript_RenderScriptActivity_combine
        (JNIEnv* pEnv, jobject pClass, jstring pCacheDir, jobject pSrcImage,
                jobject pDstImage, jfloat pRadius, jfloat pThreshold) {
            const char * cacheDir = pEnv->GetStringUTFChars(pCacheDir, NULL);
            sp<RS> rs = new RS();
            rs->init(cacheDir);
            pEnv->ReleaseStringUTFChars(pCacheDir, cacheDir);

            AndroidBitmapInfo srcInfo; uint32_t* srcContent;
            AndroidBitmapInfo dstInfo; uint32_t* dstContent;
            lockBitmap(pEnv, pSrcImage, &srcInfo, &srcContent);
            lockBitmap(pEnv, pDstImage, &dstInfo, &dstContent);

            sp<const Type> srcType = Type::create(rs, Element::RGBA_8888(rs),
                    srcInfo.width, srcInfo.height, 0);
            sp<Allocation> srcAlloc = Allocation::createTyped(rs, srcType,
                    RS_ALLOCATION_MIPMAP_NONE,
                    RS_ALLOCATION_USAGE_SHARED | RS_ALLOCATION_USAGE_SCRIPT,
                    srcContent);

            sp<const Type> dstType = Type::create(rs, Element::RGBA_8888(rs),
                    dstInfo.width, dstInfo.height, 0);
            sp<Allocation> dstAlloc = Allocation::createTyped(rs, dstType,
                    RS_ALLOCATION_MIPMAP_NONE,
                    RS_ALLOCATION_USAGE_SHARED | RS_ALLOCATION_USAGE_SCRIPT,
                    dstContent);
        ...
        ```

1.  我们还需要一个临时内存区域来存储计算结果。让我们创建一个由内存缓冲区`tmpBuffer`支持的临时分配：

    ```java
    ...
        sp<const Type> tmpType = Type::create(rs, Element::RGBA_8888(rs),
                dstInfo.width, dstInfo.height, 0);tmpType->getX();
        uint8_t* tmpBuffer = new uint8_t[tmpType->getX() *
               tmpType->getY() * Element::RGBA_8888(rs)- >getSizeBytes()];
        sp<Allocation> tmpAlloc = Allocation::createTyped(rs, tmpType,
                RS_ALLOCATION_MIPMAP_NONE,
                RS_ALLOCATION_USAGE_SHARED | RS_ALLOCATION_USAGE_SCRIPT,
                tmpBuffer);
    ...
    ```

1.  初始化组合滤镜所需的内核和内置函数：

    +   `阈值`内核

    +   `模糊`内置函数

    +   一个不需要参数的额外`混合`内置函数

        ```java
        ...
            sp<ScriptC_threshold> thresholdKernel = new ScriptC_threshold(rs);
            sp<ScriptIntrinsicBlur> blurIntrinsic =
                    ScriptIntrinsicBlur::create(rs, Element::RGBA_8888(rs));
            blurIntrinsic->setRadius(pRadius);
            sp<ScriptIntrinsicBlend> blendIntrinsic =
                    ScriptIntrinsicBlend::create(rs, Element::RGBA_8888(rs));
            thresholdKernel->set_thresholdValue(pThreshold);
        ...
        ```

1.  现在，将多个滤镜组合在一起：

    +   首先，应用阈值滤镜并将结果保存到临时分配中。

    +   其次，在临时分配上应用模糊滤镜，并将结果保存到目标位图分配中。

    +   最后，使用加法操作将源位图和过滤后的位图混合在一起，以创建最终图像。由于每个像素只读取和写入一次（与模糊滤镜相反），因此可以“就地”混合，无需额外的分配。

        ```java
        ...
            thresholdKernel->forEach_threshold(srcAlloc, tmpAlloc);
            blurIntrinsic->setInput(tmpAlloc);
            blurIntrinsic->forEach(dstAlloc);
            blendIntrinsic->forEachAdd(srcAlloc, dstAlloc);
        ...
        ```

1.  最后，保存结果并释放资源。所有在`sp<>`（即智能指针）模板中的值，如`tmpAlloc`，都会自动释放：

    ```java
    ...
        dstAlloc->copy2DRangeTo(0, 0, dstInfo.width, dstInfo.height,
                dstContent);

        unlockBitmap(pEnv, pSrcImage);
        unlockBitmap(pEnv, pDstImage);
        delete[] tmpBuffer;

    }
    ...
    ```

## *刚才发生了什么？*

运行项目，调整`SeekBar`组件，并点击**组合**按钮。输出`ImageView`应该显示一个“重制”的图片，其中发光部分被突出显示：

![刚才发生了什么？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-ndk-bgd-2e/img/9645_10_03.jpg)

我们将多个内置函数和内核串联在一起，将**组合**滤镜应用于图像。这样的链很容易建立；我们基本上需要将一个脚本的输出分配连接到下一个脚本的输入分配。在最后才真正需要将数据复制到输出内存区域。

### 提示

令人遗憾的是，脚本分组功能在 Android NDK API 上还不可用，只能在 Java 端使用。通过脚本分组功能，可以定义一个完整的脚本“图”，使 RenderScript 能够进一步优化代码。如果你需要这个功能，那么你可以选择等待或者回到 Java。

幸运的是，如果需要，Allocations 可以在多个脚本中重复使用，以避免分配无用的内存。如果脚本允许“就地”修改，甚至可以将同一个 Allocation 用于输入和输出。例如，**模糊**滤镜就不可以这样，因为它会在读取其他像素进行模糊处理时重写模糊的像素，从而导致奇怪的视觉伪影。

### 提示

说到复用，在执行之间重复使用 RenderSript 对象（即 RS 上下文对象，Intrinsics，Kernels 等）是一种好的实践。如果你反复执行一个计算，比如处理摄像头拍摄的图像，这一点尤为重要。

内存是 RenderScript 性能的一个重要方面。如果使用不当，它可能会降低效率。在我们的项目中，我们提供了一个指向我们创建的 Allocations 的指针。这意味着我们项目中创建的 Allocations 是用本地内存“支持”的，在我们的例子中，就是位图内容：

```java
...
sp<Allocation> srcAlloc = Allocation::createTyped(rs, srcType,
        RS_ALLOCATION_MIPMAP_NONE,
        RS_ALLOCATION_USAGE_SHARED | RS_ALLOCATION_USAGE_SCRIPT,
        srcContent);
...
```

然而，也可以在处理前使用`copy***From()`方法将数据从输入内存区域复制到分配的内存中，这些方法是`copy***To()`方法的对应方法。这对于 Java 绑定来说特别有用，因为 Java 绑定并不总是允许使用“支持分配”。NDK 绑定更加灵活，大多数时候可以避免输入数据的复制。

RenderScript 提供了其他机制来从脚本中传递数据。第一种是`rsSendToClient()`和`rsSendToClientBlocking()`方法。它们允许脚本向调用方传递一个“命令”，可选地带有一些数据。后一种方法在性能方面显然有点危险，应尽量避免使用。

数据也可以通过指针进行传递。指针是动态内存，允许 Kernel 和调用者之间进行双向通信。如前所述，它们在生成的类中以`bind_`前缀的方法反映出来。在编译时，应该在反射层生成适当的获取器和设置器。

但是，NDK RenderScript 框架目前还无法反映在 RenderScript 文件中声明的结构。因此，现在还不能声明指向在脚本文件中定义的`struct`的指针。不过，使用 Allocations，基本类型的指针是可以工作的。因此，在这个问题上，预计 NDK 端会有一些令人讨厌的限制。

在结束内存这一主题之前，如果你在脚本中需要不止一个输入或输出分配（Allocation），有一个解决方案，即`rs_allocation`，它通过 getter 和 setter 反映一个分配（Allocation）。你可以有任意多个。然后，你可以通过`rsAllocationGetDim*()`，`rsGetElementAt*()`，`rsSetElementAt*()`等方法访问尺寸和元素。

例如，`threshold()`方法可以以下列方式重写：

### 注意

注意，由于我们没有在参数中传递输入分配（Allocation），因此像往常一样返回一个。

+   `for`循环不是隐式的，如果传递了参数中的分配（Allocation），它将是隐式的。

+   `threshold()`函数不能作为内核根。但是，完全可以通过与`rs_allocation`结合使用输入分配（Allocation）。

```java
#pragma version(1)
#pragma rs java_package_name(com.packtpub.renderscript)

float thresholdValue;
static const float3 BLACK = { 0.0, 0.0, 0.0 };
static const float3 LUMINANCE_VECTOR = { 0.2125, 0.7154, 0.0721 };

rs_allocation input;
rs_allocation output;

void threshold() {
 uint32_t sizeX = rsAllocationGetDimX(input);
 uint32_t sizeY = rsAllocationGetDimY(output);
 for (uint32_t x = 0; x < sizeX; ++x) {
 for (uint32_t y = 0; y < sizeY; ++y) {
 uchar4 rawPixel = rsGetElementAt_uchar4(input, x, y);

            // The algorithm itself remains the same.
            float4 pixel = rsUnpackColor8888(rawPixel);
            float luminance = dot(LUMINANCE_VECTOR, pixel.rgb);
            if (luminance < thresholdValue) {
                pixel.rgb = BLACK;
            }
            rawPixel = rsPackColorTo8888(pixel);

            rsSetElementAt_uchar4(output, rawPixel, x, y);
        }
    }
}
```

内核将以下列方式被调用。注意，应用效果的方法前缀为`invoked_`（而不是`forEach_`）。这是因为`threshold()`函数不是内核的根函数：

```java
...
thresholdKernel->set_input(srcAlloc);
thresholdKernel->set_output(dstAlloc);
thresholdKernel->invoke_threshold();
dstAlloc->copy2DRangeTo(0, 0, dstInfo.width, dstInfo.height,
        dstContent);
...
```

有关 RenderScript 语言功能的更多信息，请查看[`developer.android.com/guide/topics/renderscript/advanced.html`](http://developer.android.com/guide/topics/renderscript/advanced.html)。

# 总结

本章介绍了 RenderScript，这是一种用于并行化密集计算任务的高级技术。更具体地说，我们了解了如何使用预定义的 RenderScript 内置 Intrinsics，这些 Intrinsics 目前主要用于图像处理。我们还发现如何使用受 C 语言启发的 RenderScript 自定义语言实现我们自己的内核（Kernel）。最后，我们看到了一个 Intrinsics 和 Kernels 结合的例子，以执行更复杂的计算。

RenderScript 可以从 Java 或原生侧使用。但是，让我们明确一点，除了由内存缓冲区支持的分配（Allocation）（这是一个相当重要的性能特性）之外，RenderScript 仍然更多地通过其 Java API 使用。分组不可用，`struct`尚未反映，还有一些其他特性仍然存在问题（例如 YUV Intrinsics）。

实际上，RenderScript 旨在为那些没有时间或知识走原生开发路径的开发者提供巨大的计算能力。因此，NDK 目前并没有得到很好的支持。尽管这可能会在未来改变，但你应该准备好至少将部分 RenderScript 代码保留在 Java 端。


# 第十一章：后记

在整本书中，你已经学习了入门的基本知识，并概览了进一步学习的路径。你现在知道了驾驭这些小而强大的“怪物”的关键元素，并开始充分利用它们的力量。然而，还有很多东西要学，但时间和空间是有限的。无论如何，掌握一项技术的唯一途径就是实践，再实践。希望你能享受这个过程，并为移动挑战做好准备。所以，我现在最好的建议是收集你新鲜的知识和你所有惊人的想法，在脑海中反复打磨它们，并用键盘将它们实现。

# 我们曾经去过的地方

我们已经具体地了解了如何使用 Eclipse 和 NDK 创建本地项目。我们学习了如何通过 JNI 在 Java 应用程序中嵌入 C/C++库，以及如何在不编写 Java 代码的情况下运行本地代码。

我们使用 OpenGL ES 和 OpenSL ES 测试了 Android NDK 的多媒体能力，这些能力在移动领域正逐渐成为标准（当然，是在忽略 Windows Mobile 之后）。我们甚至与手机的输入外设交互，并通过其传感器感知世界。

此外，Android NDK 不仅与性能有关，还与可移植性有关。因此，我们重用了 STL 框架，它最好的伴侣`Boost`，并且几乎无缝地移植了第三方库。

最后，我们了解了如何使用 RenderScript 技术优化密集计算任务。

# 你可以去的地方

C/C++生态系统已经存在了几十年，并且非常丰富。我们移植了一些库，但还有更多库等待被移植。实际上，下面列出许多库，它们无需完全重写代码就可以工作：

+   Bullet ([`bulletphysics.org/`](http://bulletphysics.org/))是一个物理引擎的例子，它可以在几分钟内直接移植。

+   Irrlicht ([`irrlicht.sourceforge.net/`](http://irrlicht.sourceforge.net/))是可以运行在 Android 上的众多 3D 引擎之一。

+   OpenCV ([`opencv.org/`](http://opencv.org/))是一个计算机视觉和机器学习库，它让你的应用程序能够通过摄像头“看到”并理解外部世界。

+   GLM ([`glm.g-truc.net/`](http://glm.g-truc.net/))是一个有用的库，用于 OpenGL ES 2 以完全 C++的方式处理矩阵计算。

+   Intel Threading Building Block 库 ([`www.threadingbuildingblocks.org/`](https://www.threadingbuildingblocks.org/))，通常称为 TBB，对于那些需要在本地代码中进行大规模并行化的开发者来说是一个有趣的库。

一些库是专门为移动设备设计的，例如：

+   Unity ([`unity3d.com/`](http://unity3d.com/))是一个优秀的编辑器和框架，如果你想要编写移动游戏，绝对应该看看。

+   Unreal Engine ([`www.unrealengine.com/`](https://www.unrealengine.com/))是最强大的引擎之一，现在可以免费使用。

+   Cocos2D-X（[`www.cocos2d-x.org/`](http://www.cocos2d-x.org/)），这是一个在许多 2D 游戏中广泛使用的高度流行的游戏引擎。

+   Vuforia（[`www.qualcomm.com/products/vuforia`](https://www.qualcomm.com/products/vuforia)），这是高通公司推出的增强现实 SDK。

对于那些想要深入 Android 内部工作原理的人，我建议你查看一下 Android 平台代码本身，它可以在[`source.android.com/`](http://source.android.com/)找到。下载、编译甚至部署都不是一件容易的事，但这确实是深入了解 Android 内部工作原理的唯一途径，有时也是找出那些讨厌的 bug 来源的唯一方式！

# 寻求帮助的地方：

Android 社区非常活跃，以下是一些寻找有用信息的地方：

+   Android Google 群组（[`groups.google.com/group/android-developers`](http://groups.google.com/group/android-developers）和 Android NDK 群组（[http://groups.google.com/group/android-ndk](http://groups.google.com/group/android-ndk)），你可以在这些地方获得帮助，有时甚至来自 Android 团队成员。

+   Android 开发者博客（[`android-developers.blogspot.com/`](http://android-developers.blogspot.com/)），在这里你可以找到关于 Android 开发的最新官方信息。

+   Google IO（[`www.google.com/events/io`](https://www.google.com/events/io)）上有一些关于 Android 的最佳视频演讲。

+   英特尔开发者网站（[`software.intel.com/en-us/android`](https://software.intel.com/en-us/android)）上有许多关于 x86 上 NDK 的有趣资源。

+   NVidia 开发者中心（[`developer.nvidia.com/category/zone/mobile-development`](http://developer.nvidia.com/category/zone/mobile-development)）提供了关于 Tegra 的开发资源，同时也包含关于 Android 和 NDK 的一般性资源。

+   高通开发者网络（[`developer.qualcomm.com/`](https://developer.qualcomm.com/)）可以找到关于 NVidia 主要竞争对手的信息。特别是高通的增强现实 SDK 非常具有前景。

+   Stack Overflow（[`stackoverflow.com/`](http://stackoverflow.com/)），虽然不是专门针对 Android 的，但你可以提问并获得准确的答案。

+   GitHub（[`github.com/`](http://github.com/)），上面有大量的 NDK 库和示例。

# 这仅仅是一个开始。

创建应用程序只是过程的一部分。发布和销售是另一部分。这当然超出了本书的范围，但处理碎片化和测试与各种目标设备的兼容性确实是一个需要认真对待的难题。

当心！当你开始处理硬件特性（有很多这样的特性）时，问题就会开始出现，正如我们在输入设备中看到的那样。然而，这些问题并不特定于 NDK。如果 Java 应用程序中存在不兼容性，那么原生代码也不会更好。处理各种屏幕尺寸，加载适当大小的资源，以及适应设备功能，这些最终都是你需要处理的事情。然而，这应该是可以管理的。

简而言之，有很多奇妙但也痛苦的惊喜等着被发现。然而，Android 和移动性仍然是一片待开垦的土地，需要被塑造。看看从最早版本到最新版本的 Android 的演变，你就会相信。革命不会每天都发生，所以不要错过它！

祝你好运！

**西尔万·拉塔布伊尔**
