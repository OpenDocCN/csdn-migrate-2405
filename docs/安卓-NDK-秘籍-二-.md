# 安卓 NDK 秘籍（二）

> 原文：[`zh.annas-archive.org/md5/7FB9DA0CE2811D0AA0DFB1A6AD308582`](https://zh.annas-archive.org/md5/ceefdd89e585c59c7FB9DA0CE2811D0AA0DFB1A6AD30858220db6a7760dc11f1)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：构建和调试 NDK 应用程序

在本章中，我们将介绍以下食谱：

+   在命令行构建 Android NDK 应用程序

+   在 Eclipse 中构建 Android NDK 应用程序

+   为不同的 ABI 构建 Android NDK 应用程序

+   为不同的 CPU 特性构建 Android NDK 应用程序

+   使用日志消息调试 Android NDK 应用程序

+   使用 CheckJNI 调试 Android NDK 应用程序

+   使用 NDK GDB 调试 Android NDK 应用程序

+   使用 CGDB 调试 Android NDK 应用程序

+   在 Eclipse 中调试 Android NDK 应用程序

# 引言

我们在第一章 *Hello NDK*中介绍了环境设置，以及第二章 *Java Native Interface*中的 JNI 编程。为了构建 Android NDK 应用程序，我们还需要使用 Android NDK 的**构建**和**调试**工具。

Android NDK 附带了 `ndk-build` 脚本，以方便构建任何 Android NDK 应用程序。这个脚本隐藏了调用交叉编译器、交叉链接器等的复杂性，让开发者无需处理。我们将从介绍 `ndk-build` 命令的用法开始。

**Android Development Tools** (**ADT**) 插件的最近一次发布支持从 Eclipse 构建 Android NDK 应用程序。我们将演示如何使用它。

我们将探讨为不同的**应用程序二进制接口** (**ABIs**) 构建 NDK 应用程序，并利用可选的 CPU 特性。这对于在不同 Android 设备上实现最佳性能至关重要。

除了构建，我们还将介绍各种用于 Android NDK 应用程序的调试工具和技术。从简单但强大的日志技术开始，我们将展示如何从命令行和 Eclipse IDE 中调试 NDK 应用程序。还将介绍 `CheckJNI` 模式，它可以帮助我们捕获 JNI 错误。

# 在命令行构建 Android NDK 应用程序

尽管 Eclipse 是推荐用于 Android 开发的 IDE，但有时我们希望在命令行中构建 Android 应用程序，以便可以轻松地自动化该过程并成为持续集成过程的一部分。本食谱重点介绍如何在命令行中构建 Android NDK 应用程序。

## 准备工作

Apache Ant 主要是一个用于构建 Java 应用程序的工具。它接受一个 XML 文件来描述构建、部署和测试过程，管理这些过程，并自动跟踪依赖关系。

我们将使用 Apache Ant 来构建和部署我们的示例项目。如果你还没有安装它，可以按照以下命令进行安装：

+   如果你使用的是 Ubuntu Linux，请使用以下命令：

    ```kt
    $ sudo apt-get install ant1.8

    ```

+   如果你使用的是 Mac，请使用以下命令：

    ```kt
    $ sudo port install apache-ant

    ```

+   如果你使用的是 Windows，可以从[`code.google.com/p/winant/downloads/list`](http://code.google.com/p/winant/downloads/list)下载 `winant` 安装程序，并进行安装。

读者在阅读本节之前，应该已经设置好了 NDK 开发环境，并阅读了第一章中的*编写 Hello NDK 程序*部分，*Hello NDK*。

## 如何操作…

以下步骤创建并构建一个示例`HelloNDK`应用：

1.  创建项目。启动命令行控制台并输入以下命令：

    ```kt
    $ android create project \
    --target android-15 \
    --name HelloNDK \
    --path ~/Desktop/book-code/chapter3/HelloNDK \
    --activity HelloNDKActivity \
    --package cookbook.chapter3

    ```

    ### 提示

    `android`工具可以在 Android SDK 文件夹的`tools/`目录下找到。如果你按照第一章设置了 SDK 和 NDK 开发环境，并正确配置了`PATH`，那么可以直接从命令行执行`android`命令。否则，你需要输入到`android`程序的相关路径或完整路径。这也适用于本书中使用的其他 SDK 和 NDK 工具。

    以下是命令输出的截图：

    ![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_01.jpg)

1.  转到`HelloNDK`项目文件夹，并使用以下命令创建一个名为`jni`的文件夹：

    ```kt
    $ cd ~/Desktop/book-code/chapter3/HelloNDK
    $ mkdir jni

    ```

1.  在`jni`文件夹下创建一个名为`hello.c`的文件，并添加以下内容：

    ```kt
    #include <string.h>
    #include <jni.h>

    jstring Java_cookbook_chapter3_HelloNDKActivity_naGetHelloNDKStr(JNIEnv* pEnv, jobject pObj)
    {
       return (*pEnv)->NewStringUTF(pEnv, "Hello NDK!");
    }
    ```

1.  在`jni`文件夹下创建一个名为`Android.mk`的文件，内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := hello
    LOCAL_SRC_FILES := hello.c
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  使用以下命令构建本地库：

    ```kt
    $ ndk-build

    ```

1.  修改`HelloNDKActivity.java`文件为以下内容：

    ```kt
    package cookbook.chapter3;
    import android.app.Activity;
    import android.os.Bundle;
    import android.widget.TextView;
    public class HelloNDKActivity extends Activity {
       @Override
       public void onCreate(Bundle savedInstanceState) {
           super.onCreate(savedInstanceState);
           TextView tv = new TextView(this);
           tv.setTextSize(30);
           tv.setText(naGetHelloNDKStr());
           this.setContentView(tv);
       }
       public native String naGetHelloNDKStr();
       static {
           System.loadLibrary("hello");
       }
    }
    ```

1.  更新项目。我们添加了一个本地库，因此需要使用以下命令更新项目。注意，除非我们更改项目设置，否则此命令只需执行一次，而之前的`ndk-build`命令每次更新本地代码都需要执行：

    ```kt
    $ android update project --target android-15 --name HelloNDK \
    --path ~/Desktop/book-code/chapter3/HelloNDK

    ```

    以下是命令输出的截图：

    ![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_02.jpg)

1.  转到项目根文件夹，并使用以下命令以调试模式构建我们的项目：

    ```kt
    $ ant debug

    ```

    在以下截图中，我们展示了输出的最后几行，这表示构建成功的是：

    ![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_03.jpg)

    输出的`apk`文件将生成在`bin/HelloNDK-debug.apk`。

1.  使用以下命令创建一个模拟器：

    ```kt
    $ android --verbose create avd --name android_4_0_3 \
    --target android-15 --sdcard 32M

    ```

    以下是命令输出的截图：

    ![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_04.jpg)

1.  使用以下命令启动模拟器：

    ```kt
    $ emulator -wipe-data -avd android_4_0_3

    ```

    或者，我们可以使用"`android avd`"命令打开**Android 虚拟设备管理器**窗口，然后选择一个模拟器启动，如下所示：

    ![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_05.jpg)

1.  在模拟器上安装应用。我们首先通过以下命令检查设备序列号：

    ```kt
    $ adb devices

    ```

    以下是命令输出的截图：

    ![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_06.jpg)

1.  然后，我们使用以下命令将`debug.apk`文件安装到模拟器上：

    ```kt
    $ adb -s emulator-5554 install bin/HelloNDK-debug.apk

    ```

    ![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_07.jpg)

    ### 提示

    如果只有一个设备连接到电脑，那么无需指定设备序列号。在上述命令中，我们可以移除"-`s emulator-5554`"。

1.  使用以下格式的命令在模拟器上启动`HelloNDK`应用：

    ```kt
    $ adb shell am start -n com.package.name/com.package.name.ActivityName

    ```

    在我们的示例中，我们使用以下命令： 

    ```kt
    $ adb -s emulator-5554 shell am start -n cookbook.chapter3/cookbook.chapter3.HelloNDKActivity

    ```

    ![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_08.jpg)

1.  在设备上运行应用。

    假设设备序列号为 `HT21HTD09025`，那么我们可以使用以下命令在 Android 设备上安装应用。

    ```kt
    $ adb -s HT21HTD09025 install bin/HelloNDK-debug.apk

    ```

    在我们的示例中，我们使用以下命令来启动应用：

    ```kt
    $ adb -s HT21HTD09025 shell am start -n cookbook.chapter3/cookbook.chapter3.HelloNDKActivity

    ```

1.  创建一个发布包。

一旦我们确认应用程序可以成功运行，我们可能想要创建一个发布包以便上传到 Android 市场。你可以执行以下步骤来实现这一点：

1.  创建一个密钥库。Android 应用必须使用密钥库中的密钥进行签名。一个 **密钥库** 是私钥的集合。我们可以使用以下命令创建带有私钥的密钥库：

    ```kt
    $ keytool -genkey -v -keystore release_key.keystore \
    -alias androidkey \
    -keyalg RSA -keysize 2048 -validity 10000 \
    -dname "CN=MyCompany, OU=MyAndroidDev, O=MyOrg, L=Singapore, S=Singapore, C=65" \
    -storepass testkspw -keypass testkpw

    ```

    以下是命令输出的截图：

    ![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_09.jpg)

    如所示，创建了一个带有密码为 `testkwpw` 的密钥库，并在其中添加了一个带有密码为 `testkpw` 的 RSA 密钥对。

1.  输入命令 "`ant release`" 为应用构建一个 `apk`。输出可以在 b`i`n 文件夹中找到，文件名为 `HelloNDK-release-unsigned.apk`。

1.  使用以下命令对 `apk` 进行签名：

    ```kt
    $ jarsigner -verbose -keystore <keystore name> -storepass <store password> -keypass <key password> -signedjar <name of the signed output> <unsigned input file name> <alias>

    ```

    对于我们的示例应用程序，命令和输出如下：

    ![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_10.jpg)

1.  对 `apk` 文件进行 zip 对齐。`zipalign` 工具对 `apk` 文件内的数据进行对齐，以优化性能。以下命令可用于对齐已签名的 `apk`：

    ```kt
    $ zipalign -v 4 <app apk file name>  <aligned apk file name>

    ```

    对于我们的示例应用程序，命令和输出如下：

    ![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_11.jpg)

## 工作原理…

本教程介绍如何从命令行构建 Android NDK 应用程序。

Android NDK 提供了一个具有以下目标的构建系统：

+   **简单性**：它为开发者处理了大部分繁重的工作，我们只需要编写简短的构建文件（`Android.mk` 和 `Application.mk`）来描述需要编译的源代码。

+   **兼容性**：未来的版本可能会向 NDK 添加更多构建工具、平台等，但构建文件不需要更改。

Android NDK 提供了一套交叉工具链，包括交叉编译器、交叉链接器、交叉汇编器等。这些工具可以在 NDK `root` 目录下的 `toolchains` 文件夹中找到。它们可用于在 Linux、Mac OS 或 Windows 上为不同的 Android 平台（ARM、x86 或 MIPS）生成二进制文件。尽管可以直接使用工具链来为 Android 构建本地代码，但除非我们正在移植带有自己的构建脚本的项目，否则不推荐这样做。在这种情况下，我们可能只需要将原始编译器更改为 NDK 交叉编译器，以构建适用于 Android 的版本。

在大多数情况下，我们将在 `Android.mk` 中描述源代码，并在 `Application.mk` 上指定 ABIs。Android NDK 的 `ndk-build` 脚本将在内部调用交叉工具链为我们构建本地代码。以下是一些常用的 `ndk-build` 选项列表：

+   `ndk-build`：它用于构建二进制文件。

+   `ndk-build clean`：它清理生成的二进制文件。

+   `ndk-build V=1`：构建二进制文件并显示构建命令。当我们想要了解构建过程或检查构建错误时，这很方便。

+   `ndk-build -B`：此命令强制重新构建。

+   `ndk-build NDK_DEBUG=1`：生成可调试的构建。

+   `ndk-build NDK_DEBUG=0`：生成发布版本。

## 还有更多内容...

本教程使用了许多 Android SDK 的命令行工具。这允许我们提供如何创建、构建和部署 Android NDK 项目的完整说明。然而，由于本书专注于 Android NDK，因此不会详细介绍这些工具。你可以访问[`developer.android.com/tools/help/index.html`](http://developer.android.com/tools/help/index.html)了解更多关于这些工具的信息。

### 从命令行截取屏幕截图

从命令行截取屏幕截图对于记录自动化测试的显示结果很有帮助。然而，目前 Android 没有提供用于截屏的命令行工具。

可以使用位于 Android 源代码`\development\tools\screenshot\src\com\android\screenshot\`的 Java 程序来截取屏幕截图。该代码使用了与 Eclipse DDMS 插件类似的方法从命令行截取屏幕截图。我们将前面的代码整合到一个名为`screenshot`的 Eclipse Java 项目中，可以从网站下载。

用户可以导入项目并导出一个可执行的 JAR 文件来使用该工具。假设导出的 JAR 文件名为`screenshot.jar`，那么以下示例命令使用它从模拟器中截取屏幕：

![从命令行截取屏幕截图](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_12.jpg)

# 在 Eclipse 中构建 Android NDK 应用程序

上一教程讨论了如何在命令行中构建 Android NDK 应用程序。本教程演示如何在 Eclipse IDE 中完成此操作。

## 准备就绪

添加 NDK 首选项。启动 Eclipse，然后点击**窗口** | **首选项**。在**首选项**窗口中，选择**Android**下的**NDK**。点击**浏览**并选择 NDK 的`根`文件夹。点击**确定**。

![准备就绪](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_13.jpg)

## 如何操作…

以下步骤使用 Eclipse 创建一个 NDK 项目：

1.  创建一个名为`HelloNDKEclipse`的 Android 应用程序。将包名设置为`cookbook.chapter3`。创建一个名为`HelloNDKEclipseActivity`的活动。如果你需要更详细的说明，请参考第二章，*Java Native Interface*中的*加载本地库和注册本地方法*教程。

1.  右键点击项目`HelloNDKEclipse`，选择**Android Tools** | **添加本地支持**。会出现一个类似以下截图的窗口。点击**完成**以关闭它：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_14.jpg)

    这将在内部添加一个包含两个文件（`HelloNDKEclipse.cpp`和`Android.mk`）的`jni`文件夹，并将 Eclipse 切换到 C/C++透视图。

1.  向`HelloNDKEclipse.cpp`中添加以下内容：

    ```kt
    #include <jni.h>

    jstring getString(JNIEnv* env) {
      return env->NewStringUTF("Hello NDK");
    }

    extern "C" {
      JNIEXPORT jstring JNICALL Java_cookbook_chapter3_HelloNDKEclipseActivity_getString(JNIEnv* env, jobject o){
        return getString(env);
      }
    }
    ```

1.  将 HelloNDKEclipseActivity.java 的内容更改为以下内容。

    ```kt
    package cookbook.chapter3;

    import android.os.Bundle;
    import android.app.Activity;
    import android.widget.TextView;

    public class HelloNDKEclipseActivity extends Activity {
      @Override
       public void onCreate(Bundle savedInstanceState) {
           super.onCreate(savedInstanceState);
           TextView tv = new TextView(this);
           tv.setTextSize(30);
           tv.setText(getString());
           this.setContentView(tv);
       }
       public native String getString();
       static {
           System.loadLibrary("HelloNDKEclipse");
       }
    }
    ```

1.  右键点击 `HelloNDKEclipse` 项目，选择 **构建项目**。这将为我们构建本地库。

1.  右键点击项目，选择 **运行方式**，然后选择 **Android 应用程序**。手机屏幕将显示类似于以下截图的内容：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_15.jpg)

## 它是如何工作的...

本食谱讨论在 Eclipse 中构建 Android NDK 应用程序。

在所有之前的食谱中我们一直在使用 C。从本食谱开始，我们将用 C++ 编写代码。

默认情况下，Android 提供了最小的 C++ 支持。没有 **运行时类型信息** (**RTTI**) 和 C++ 异常支持，甚至 C++ 标准库支持也是部分的。以下是 Android NDK 默认支持的 C++ 头文件列表：

```kt
cassert, cctype, cerrno, cfloat, climits, cmath, csetjmp, csignal, cstddef, cstdint, cstdio, cstdlib, cstring, ctime, cwchar, new, stl_pair.h, typeinfo, utility
```

通过使用不同的 C++ 库，有可能增加对 C++ 的支持。NDK 除了系统默认库之外，还提供了 `gabi++`、`stlport` 和 `gnustl` C++ 库。

在我们的示例代码中，我们使用了外部 "C" 来包装 C++ 方法。这样做是为了避免 JNI 函数名被 C++ 糟蹋。C++ 名称糟蹋可能会改变函数名以包含关于参数的类型信息，函数是否为虚函数等。虽然这使得 C++ 能够链接重载函数，但它破坏了 JNI 函数发现机制。

我们还可以使用 第二章 *Java Native Interface* 中 *加载本地库和注册本地方法* 食谱中涵盖的显式函数注册方法来摆脱包装。

# 为不同的 ABI 构建一个 Android NDK 应用程序

本地代码被编译成二进制文件。因此，一组二进制文件只能在一个特定的架构上运行。Android NDK 提供了技术和工具，使开发者能够轻松地为多个架构编译相同的源代码。

## 准备就绪

一个 **应用程序二进制接口** (**ABI**) 定义了 Android 应用程序的机器代码如何在运行时与系统交互，包括 CPU 指令集、字节序、内存对齐等。ABI 基本上定义了一种架构类型。

下表简要总结了 Android 支持的四个 ABI：

| ABI 名称 | 支持 | 不支持 | 可选 |
| --- | --- | --- | --- |
| `armeabi` |

+   ARMv5TE 指令集

+   Thumb（也称为 Thumb-1）指令

| 硬件辅助浮点计算 |   |
| --- | --- |
| `armeabi-v7a` |

+   `armeabi` 支持的所有内容

+   VFP 硬件 FPU 指令

+   Thumb-2 指令集

+   VFPv3-D16 被使用。

|   |
| --- |

+   高级 SIMD（也称为 NEON）

+   VFPv3-D32

+   ThumbEE

|

| `x86` |
| --- |

+   通常称为 "x86" 或 "IA-32" 的指令集。

+   MMX、SSE、SSE2 和 SSE3 指令集扩展

|   |
| --- |

+   MOVBE 指令

+   SSSE3 "补充 SSE3" 扩展

+   任何 "SSE4" 的变体

|

| `mips` |
| --- |

+   MIPS32r1 指令集

+   硬浮点

+   O32

|

+   DSP 应用特定扩展

+   MIPS16

+   micromips

|   |
| --- |

armeabi 和 armeabi-v7a 是 Android 设备最常用的两种 ABI。ABI armeabi-v7a 与 armeabi 兼容，这意味着为 armeabi 编译的应用程序也可以在 armeabi-v7a 上运行。但反之则不成立，因为 armeabi-v7a 包含额外的功能。在以下部分中，我们将简要介绍在 armeabi 和 armeabi-v7a 中经常提到的一些技术术语。

+   **Thumb**：这个指令集由 16 位指令组成，是标准 ARM 32 位指令集的一个子集。某些 32 位指令集中的指令在 Thumb 中不可用，但可以用几个 Thumb 指令来模拟。更窄的 16 位指令集可以提供内存优势。

    Thumb-2 通过添加一些 32 位指令扩展了 Thumb-1，从而形成了一种可变长度指令集。Thumb-2 旨在像 Thumb-1 一样实现代码密度，并在 32 位内存上实现与标准 ARM 指令集相似的性能。

    Android NDK 默认生成 thumb 代码，除非在 `Android.mk` 文件中定义了 `LOCAL_ARM_MODE`。

+   **向量浮点（VFP）**：它是 ARM 处理器的扩展，提供了低成本的浮点计算功能。

+   **VFPv3-D16 和 VFPv3-D32**：VFPv3-D16 指的是 16 个专用的 64 位浮点寄存器。同样，VFPv3-D32 意味着有 32 个 64 位浮点寄存器。这些寄存器加速了浮点计算。

+   **NEON**：NEON 是 ARM **高级单指令多数据（SIMD）** 指令集扩展的昵称。它需要 VFPv3-D32 支持，这意味着将使用 32 个硬件浮点单元 64 位寄存器。它提供了一系列标量/向量指令和寄存器，这些在 x86 世界中与 MMX/SSE/SDNow!相当。并非所有 Android 设备都支持 NEON，但许多新设备已经具备 NEON 支持。NEON 可以通过同时执行多达 16 个操作，显著加速媒体和信号处理应用程序。

有关更详细信息，可以参考 ARM 文档网站 [`infocenter.arm.com/help/index.jsp`](http://infocenter.arm.com/help/index.jsp)。这里我们不讨论 x86 和 mips ABI，因为很少有 Android 设备运行在这些架构上。

在进行这一步之前，请阅读 *在 Eclipse 中构建 Android NDK 应用程序* 的菜谱。

## 如何进行操作...

以下步骤为不同的 ABI 构建 Android 项目：

1.  创建一个名为 `HelloNDKMultipleABI` 的 Android 应用程序。将包名设置为 `cookbook.chapter3`。创建一个名为 `HelloNDKMultipleABIActivity` 的活动。

1.  右键点击 `HelloNDKMultipleABI` 项目，选择 **Android Tools** | **Add Native Support**。出现一个窗口，点击 **Finish** 关闭它。这将添加一个包含两个文件（`HelloNDKMultipleABI.cpp` 和 `Android.mk`）的 `jni` 文件夹，并将 Eclipse 切换到 C/C++视角。

1.  在 `HelloNDKMultipleABI.cpp` 文件中添加以下内容：

    ```kt
    #include <jni.h>

    jstring getString(JNIEnv* env) {
      return env->NewStringUTF("Hello NDK");
    }

    extern "C" {
      JNIEXPORT jstring JNICALL Java_cookbook_chapter3_HelloNDKMultipleABIActivity_getString(JNIEnv* env, jobject o){
        return getString(env);
      }
    }
    ```

1.  将 `HelloNDKMultipleABIActivity.java` 文件更改为以下内容：

    ```kt
    package cookbook.chapter3;

    import android.os.Bundle;
    import android.app.Activity;
    import android.widget.TextView;

    public class HelloNDKMultipleABIActivity extends Activity {

       @Override
       public void onCreate(Bundle savedInstanceState) {
           super.onCreate(savedInstanceState);
           TextView tv = new TextView(this);
           tv.setTextSize(30);
           tv.setText(getString());
           this.setContentView(tv);
       }
       public native String getString();
       static {
           System.loadLibrary("HelloNDKMultipleABI");
       }
    }
    ```

1.  在项目的`jni`文件夹下添加一个名为`Application.mk`的新文件，内容如下：

    ```kt
    APP_ABI := armeabi armeabi-v7a
    ```

1.  右键点击`HelloNDKMultipleABIActivity`项目，选择**构建项目**。这将为我们构建原生库。

1.  创建两个模拟器，分别将 ABI 设置为`armeabi`和`armeabi-v7a`。以下截图展示了如何创建一个 ABI 为`armeabi`的模拟器：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_16.jpg)

1.  在两个模拟器上运行示例 Android 应用程序。在它们上面显示的结果相同：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_17.jpg)

1.  将`Application.mk`的内容更改为以下代码片段，并在两个模拟器上运行示例应用程序。应用程序仍然可以在两个模拟器上运行：

    ```kt
    #APP_ABI := armeabi armeabi-v7a
    APP_ABI := armeabi
    ```

1.  将`Application.mk`的内容更改如下：

    ```kt
    #APP_ABI := armeabi armeabi-v7a
    #APP_ABI := armeabi
    APP_ABI := armeabi-v7a
    ```

1.  在两个模拟器上运行示例应用程序。应用程序在`armeabi-v7a`模拟器上运行，但在`armeabi`模拟器上会崩溃，如下面的截图所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_18.jpg)

## 工作原理…

一个 Android 设备可以定义一个或两个 ABI。对于基于 x86、MIPS、ARMv5 和 ARMv6 的典型设备，只有一个首要 ABI。根据平台，它可以是 x86、mips 或 armeabi。对于基于典型 ARMv7 的设备，首要 ABI 通常是 armeabi-v7a，它还有一个次要 ABI 为 armeabi。这使得编译为 armeabi 或 armeabi-v7a 的二进制文件可以在 ARMv7 设备上运行。在我们的示例中，我们证明了当只针对 armeabi 构建时，应用程序可以在 armeabi 和 armeabi-v7a 模拟器上运行。

在安装时，Android 包管理器会搜索为首要 ABI 构建的原生库，并将其复制到应用程序的数据目录中。如果没有找到，它会搜索为次要 ABI 构建的原生库。这确保只有正确的原生库被安装。

在我们的示例中，当我们只针对 armeabi-v7a 编译二进制文件时，原生库将不会安装在 armeabi 模拟器上，因此无法加载原生库，并且会显示崩溃。

# 为不同的 CPU 特性构建 Android NDK 应用程序

许多项目使用原生代码以提高性能。与 SDK 开发相比，在 NDK 中开发的一个优点是我们可以为不同的 CPU 构建不同的包，这正是本食谱的主题。

## 准备就绪

在继续本食谱之前，请阅读《为不同 ABI 构建 Android NDK 应用程序》的食谱。

## 如何操作…

以下步骤为不同的 CPU 特性构建 Android NDK 应用程序。

1.  在 Eclipse 中，点击**文件** | **新建** | **其他**。在**Android**下选择**现有代码**中的**Android 项目**，如下面的截图所示。然后点击**下一步**：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_19.jpg)

1.  浏览到 Android NDK 文件夹中的`samples/hello-neon`文件夹。然后点击**完成**。

1.  启动终端，然后进入`samples/hello-neon/jni`文件夹。输入命令"`ndk-build`"以构建二进制文件。

1.  在不同的设备和模拟器上运行安卓项目。根据你的设备/模拟器 ABI 和 NEON 特性的可用性，你应该能够看到如下结果：

    +   对于具有 armeabi ABI 的安卓设备，结果如下：![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_20.jpg)

    +   对于具有 armeabi-v7a ABI 和 NEON 的安卓设备，结果如下：

    ![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_21.jpg)

## 工作原理…

安卓设备大致可以通过 ABIs 来划分。然而，具有相同 ABI 的不同设备可能有不同的 CPU 扩展和特性。这些扩展和特性是可选的，因此我们在运行时之前无法知道用户的设备是否具备这些特性。在某些设备上，检测并利用这些特性有时可以显著提高应用性能。

安卓 NDK 包含一个名为`cpufeatures`的库，可以在运行时用来检测 CPU 家族和可选特性。正如示例代码所示，以下步骤指示如何使用这个库：

1.  在`Android.mk`的静态库列表中添加，如下所示：

    ```kt
    LOCAL_STATIC_LIBRARIES := cpufeatures
    ```

1.  在`Android.mk`文件的末尾，导入`cpufeatures`模块：

    ```kt
    $(call import-module,cpufeatures)
    ```

1.  在代码中，包含头文件`<cpu-features.h>`。

1.  调用检测函数；目前`cpufeatures`只提供三个函数：

1.  获取 CPU 家族。函数原型如下：

    ```kt
    AndroidCpuFamily   android_getCpuFamily(); 
    ```

    它返回一个枚举。支持的 CPU 系列在下面的章节中列出。

    ```kt
    ANDROID_CPU_FAMILY_MIPS 
    ANDROID_CPU_FAMILY_MIPS 
    ANDROID_CPU_FAMILY_ARM 
    ```

1.  获取可选的 CPU 特性。每个 CPU 特性由一个位标志表示，如果特性可用，该位设置为`1`。函数原型如下：

    ```kt
    uint64_t   android_getCpuFeatures();
    ```

对于 ARM CPU 家族，支持的 CPU 特性检测如下：

+   `ANDROID_CPU_ARM_FEATURE_ARMv7`：这意味着支持 ARMv7-a 指令。

+   `ANDROID_CPU_ARM_FEATURE_VFPv3`：这意味着支持 VFPv3 硬件 FPU 指令集扩展。请注意，这里指的是 VFPv3-D16，它提供 16 个硬件浮点寄存器。

+   `ANDROID_CPU_ARM_FEATURE_NEON`：这意味着支持 ARM 高级 SIMD（也称为 NEON）向量指令集扩展。请注意，这样的 CPU 也支持 VFPv3-D32，它提供 32 个硬件浮点寄存器。

对于 x86 CPU 家族，支持的 CPU 特性检测如下：

+   `ANDROID_CPU_X86_FEATURE_SSSE3`：这意味着支持`SSSE3`指令扩展集。

+   `ANDROID_CPU_X86_FEATURE_POPCNT`：这意味着支持`POPCNT`指令。

+   `ANDROID_CPU_X86_FEATURE_MOVBE`：这意味着支持`MOVBE`指令。

我们可以进行"`&`"操作来检测一个特性是否可用，如下所示：

```kt
uint64_t features = android_getCpuFeatures();
if ((features & ANDROID_CPU_ARM_FEATURE_NEON) == 0) {
  //NEON is not available
} else {
  //NEON is available
}
```

获取设备上的 CPU 核心数：

```kt
int         android_getCpuCount(void);
```

### 提示

自从 NDK r8c 以来，更多的 CPU 特性检测可用。更多详情请参考`sources/android/cpufeatures/cpu-features.c`。

## 还有更多…

关于安卓上的 CPU 特性还有几个值得注意的点。

### 关于 CPU 特性检测的更多信息

`cpufeatures`库只能检测有限的 CPU 特性集。我们可以实现自己的 CPU 检测机制。通过查看 NDK 源代码在`/sources/android/cpufeatures/`，可以发现`cpufeatures`库本质上查看的是`/proc/cpuinfo`文件。我们可以读取这个文件，并在我们的应用程序中解析内容。以下是文件内容的截图：

![关于 CPU 特性检测的更多信息](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_22.jpg)

请参考本书网站上的 Android 项目`cpuinfo`，了解如何通过编程方式实现这一点。

### 为不同的 CPU 特性构建的不同方法

为不同的 CPU 特性构建本地代码有几种方法：

+   **单一库，构建时不同的二进制文件**：这也在示例项目中演示。`helloneon-intrinsics.c`文件仅针对 armeabi-v7a ABI 编译。

+   **单一库，运行时不同的执行路径**：这也在示例项目中展示。代码在运行时检测 NEON 特性是否可用，并执行不同的代码块。

+   **不同库，运行时加载适当的库**：有时，我们可能希望将源代码编译成不同的库，并通过名称区分它们。例如，我们可能有`libmylib-neon.so`和`libmylib-vfpv3.so`。我们在运行时检测 CPU 特性并加载适当的库。

+   **不同包，运行时加载适当的库**：如果库很大，最好为不同的 CPU 部署不同的二进制文件作为单独的包。这是 Google Play 上许多视频播放器（例如 MX Player）的做法。

# 使用日志消息调试 Android NDK 应用程序

Android 日志系统提供了一种从各种应用程序收集日志到一系列循环缓冲区的方法。使用`logcat`命令查看日志。日志消息是调试程序最简单的方法之一，也是最强大的方法之一。本食谱重点关注 NDK 中的消息日志记录。

## 如何实现…

以下步骤创建我们的示例 Android 项目：

1.  创建一个名为`NDKLoggingDemo`的 Android 应用程序。将包名设置为`cookbook.chapter3`。创建一个名为`NDKLoggingDemoActivity`的活动。如果你需要更详细的说明，请参考第二章，*Java Native Interface*中的*加载本地库和注册本地方法*食谱。

1.  右键点击项目`NDKLoggingDemo`，选择**Android Tools** | **Add Native Support**。出现一个窗口，点击**Finish**关闭它。

1.  在`jni`文件夹下添加一个名为`mylog.h`的新文件，并向其中添加以下内容：

    ```kt
    #ifndef COOKBOOK_LOG_H
    #define COOKBOOK_LOG_H

    #include <android/log.h>

    #define LOG_LEVEL 9
    #define LOG_TAG "NDKLoggingDemo"

    #define LOGU(level, ...) if (level <= LOG_LEVEL) {__android_log_print(ANDROID_LOG_UNKNOWN, LOG_TAG, __VA_ARGS__);}
    #define LOGD(level, ...) if (level <= LOG_LEVEL) {__android_log_print(ANDROID_LOG_DEFAULT, LOG_TAG, __VA_ARGS__);}
    #define LOGV(level, ...) if (level <= LOG_LEVEL) {__android_log_print(ANDROID_LOG_VERBOSE, LOG_TAG, __VA_ARGS__);}
    #define LOGDE(level, ...) if (level <= LOG_LEVEL) {__android_log_print(ANDROID_LOG_DEBUG, LOG_TAG, __VA_ARGS__);}
    #define LOGI(level, ...) if (level <= LOG_LEVEL) {__android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__);}
    #define LOGW(level, ...) if (level <= LOG_LEVEL) {__android_log_print(ANDROID_LOG_WARN, LOG_TAG, __VA_ARGS__);}
    #define LOGE(level, ...) if (level <= LOG_LEVEL) {__android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__);}
    #define LOGF(level, ...) if (level <= LOG_LEVEL) {__android_log_print(ANDROID_LOG_FATAL, LOG_TAG, __VA_ARGS__);}
    #define LOGS(level, ...) if (level <= LOG_LEVEL) {__android_log_print(ANDROID_LOG_SILENT, LOG_TAG, __VA_ARGS__);}

    #endif
    ```

1.  向`NDKLoggingDemo.cpp`添加以下内容：

    ```kt
    #include <jni.h>
    #include "mylog.h"

    void outputLogs() {
      LOGU(9, "unknown log message");
      LOGD(8, "default log message");
      LOGV(7, "verbose log message");
      LOGDE(6, "debug log message");
      LOGI(5, "information log message");
      LOGW(4, "warning log message");
      LOGE(3, "error log message");
      LOGF(2, "fatal error log message");
      LOGS(1, "silent log message");
    }

    extern "C" {
      JNIEXPORT void JNICALL Java_cookbook_chapter3_NDKLoggingDemoActivity_LoggingDemo(JNIEnv* env, jobject o){
        outputLogs();
      }
    }
    ```

1.  更改`NDKLoggingDemoActivity.java`的内容为以下：

    ```kt
    package cookbook.chapter3;

    import android.os.Bundle;
    import android.app.Activity;

    public class NDKLoggingDemoActivity extends Activity {
       @Override
       public void onCreate(Bundle savedInstanceState) {
           super.onCreate(savedInstanceState);
           LoggingDemo();
       }
       public native void LoggingDemo();
       static {
           System.loadLibrary("NDKLoggingDemo");
       }
    }
    ```

1.  更改`Android.mk`文件，如下包含 Android 日志库：

    ```kt
    LOCAL_PATH := $(call my-dir)

    include $(CLEAR_VARS)

    LOCAL_MODULE    := NDKLoggingDemo
    LOCAL_SRC_FILES := NDKLoggingDemo.cpp
    LOCAL_LDLIBS := -llog
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  右键点击`NDKLoggingDemo`项目，并选择**Build Project**。

1.  输入以下命令开始监控`logcat`输出。然后，在 Android 设备上启动示例 Android 应用：

    ```kt
    $ adb logcat -c
    $ adb logcat NDKLoggingDemo:I *:S -v time

    ```

    以下是`logcat`输出的屏幕截图：

    ![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_23.jpg)

1.  启动另一个命令行终端，并在其中输入以下命令：

    ```kt
    $ adb logcat NDKLoggingDemo:V *:S -v time

    ```

    这将导致以下输出：

    ![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_24.jpg)

1.  将`mylog.h`中的行从`#define LOG_LEVEL 9`更改为`#define LOG_LEVEL 4`。重新构建应用程序，然后重新启动应用程序。

1.  我们之前启动的两个终端的输出是相同的。![如何操作…](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_25.jpg)

## 它是如何工作的...

本食谱展示了如何使用 Android 日志消息。Android 中的每个日志消息由以下三部分组成：

+   **优先级**：通常用于过滤日志消息。在我们的项目中，我们可以通过更改以下代码来控制日志：

    ```kt
    #define LOG_LEVEL 4 
    ```

    另外，我们可以使用`logcat`有选择性地显示日志输出。

+   **日志标签**：通常用于标识日志来源。

+   **日志信息**：它提供了详细的日志信息。

### 提示

在 Android 上发送日志消息会消耗 CPU 资源，频繁的日志消息可能会影响应用程序性能。此外，日志存储在一个循环缓冲区中。过多的日志会覆盖一些早期的日志，这可能是我们不希望看到的。由于这些原因，建议我们在发布版本中只记录错误和异常。

`logcat`是查看 Android 日志的命令行工具。它可以根据日志标签和优先级过滤日志，并能够以不同的格式显示日志。

例如，在前面*如何操作…*部分的步骤 8 中，我们使用了以下`logcat`命令。

```kt
adb logcat NDKLoggingDemo:I *:S -v time
```

该命令过滤除了具有`NDKLoggingDemo`标签和优先级`I`（信息）或更高优先级的日志。过滤器以`tag:priority`格式给出。`NDKLoggingDemo:I`表示将显示具有`NDKLoggingDemo`标签和优先级信息或更高的日志。`*:S`将所有其他标签的优先级设置为“静默”。

关于`logcat`过滤和格式的更多详细信息可以在[`developer.android.com/tools/help/logcat.html`](http://developer.android.com/tools/help/logcat.html)和[`developer.android.com/tools/debugging/debugging-log.html#outputFormat`](http://developer.android.com/tools/debugging/debugging-log.html#outputFormat)找到。

# 使用`CheckJNI`调试 Android NDK 应用程序

JNI 为了更好的性能，错误检查很少。因此，错误通常会导致崩溃。Android 提供了一个名为`CheckJNI`的模式。在这个模式下，将调用具有扩展检查的 JNI 函数集，而不是正常的 JNI 函数。本食谱讨论如何启用`CheckJNI`模式以调试 Android NDK 应用程序。

## 如何操作...

以下步骤创建一个示例 Android 项目并启用`CheckJNI`模式：

1.  创建一个名为`CheckJNIDemo`的 Android 应用程序。将包名设置为`cookbook.chapter3`。创建一个名为`CheckJNIDemoActivity`的活动。如果你想获得更详细的说明，请参考第二章中的*加载本地库和注册本地方法*菜谱。

1.  右键点击项目`CheckJNIDemo`，选择**Android Tools** | **添加本地支持**。会出现一个窗口；点击**完成**以关闭它。

1.  向`CheckJNIDemo.cpp`添加以下内容。

1.  将`CheckJNIDemoActivity.java`更改为以下内容：

    ```kt
    package cookbook.chapter3;
    import android.os.Bundle;
    import android.app.Activity;

    public class CheckJNIDemoActivity extends Activity {
       @Override
       public void onCreate(Bundle savedInstanceState) {
           super.onCreate(savedInstanceState);
           setContentView(R.layout.activity_check_jnidemo);
           CheckJNIDemo();
       }
       public native int[] CheckJNIDemo();
       static {
           System.loadLibrary("CheckJNIDemo");
       }
    }
    ```

1.  右键点击`CheckJNIDemo`项目，并选择**构建项目**。

1.  在命令行控制台输入"`adb logcat -v time`"启动 monitor logcat 输出。然后在 Android 设备上启动示例 Android 应用。应用程序将崩溃，logcat 输出将如下显示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_35.jpg)

1.  启用 CheckJNI。

    +   当你使用模拟器时，CheckJNI 默认是开启的。

    +   如果你使用的是已获得 root 权限的设备，可以使用以下命令序列重新启动启用了 CheckJNI 的运行时。这些命令停止正在运行的 Android 实例，更改系统属性以启用 CheckJNI，然后重新启动 Android。

        ```kt
        $ adb shell stop
        $ adb shell setprop dalvik.vm.checkjni true
        $ adb shell start

        ```

    +   如果你有一个常规设备，你可以使用以下命令：

        ```kt
        $ adb shell setprop debug.checkjni 1

        ```

1.  再次运行 Android 应用程序。logcat 输出将如下显示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_26.jpg)

## 工作原理...

CheckJNI 模式使用一组 JNI 函数，这些函数比默认的具有更多的错误检查。这使得查找 JNI 编程错误变得更加容易。目前，CheckJNI 模式检查以下错误：

+   **负尺寸数组**：它尝试分配一个负尺寸的数组。

+   **错误引用**：它向 JNI 函数传递了错误的引用`jarray`/`jclass`/`jobject`/`jstring`。向期望非`NULL`参数的 JNI 函数传递`NULL`。

+   **类名**：它向 JNI 函数传递了无效样式的类名。有效的类名由"`/`"分隔，例如"`java`/`lang`/`String`"。

+   **关键调用**：它在“关键”get 函数及其相应的释放之间调用一个 JNI 函数。

+   **异常**：它在有挂起异常时调用 JNI 函数。

+   **jfieldIDs**：它会无效化`jfieldIDs`或将`jfieldIDs`从一个类型赋值给另一个类型。

+   **jmethodIDs**：它与 jfieldIDs 类似。

+   **引用**：它对错误类型的引用使用`DeleteGlobalRef`/`DeleteLocalRef`。

+   **释放模式**：它向释放调用传递了除了`0`、`JNI_ABORT`和`JNI_COMMIT`之外的释放模式。

+   **类型安全**：它从一个本地方法返回了不兼容的类型。

+   **UTF-8**：它向 JNI 函数传递了无效的修改后的 UTF-8 字符串。

随着 Android 的发展，可能会向 CheckJNI 中添加更多的错误检查。目前，以下检查还不受支持：

+   本地引用的误用

# 使用 NDK GDB 调试 Android NDK 应用程序

Android NDK 引入了一个名为`ndk-gdb`的 shell 脚本，帮助启动一个调试会话来调试本地代码。

## 准备工作

要使用`ndk-gdb`调试项目，项目必须满足以下要求：

+   应用程序是通过`ndk-build`命令构建的。

+   `AndroidManifest.xml`中的`<application>`元素的`android:debuggable`属性设置为`true`。这表示即使应用程序在用户模式下运行在设备上，应用程序也是可调试的。

+   应用程序应该在 Android 2.2 或更高版本上运行。

在进行这一步之前，请阅读*在 Eclipse 中构建 Android NDK 应用程序*的菜谱。

## 如何操作...

以下步骤创建一个示例 Android 项目，并使用 NDK GDB 进行调试。

1.  创建一个名为`HelloNDKGDB`的 Android 应用程序。将包名设置为`cookbook.chapter3`。创建一个名为`HelloNDKGDBActivity`的活动。如果你需要更详细的说明，请参考第二章，*Java Native Interface*中的*加载本地库和注册本地方法*的菜谱。

1.  右键点击项目`HelloNDKGDB`，选择**Android Tools** | **添加本地支持**。会出现一个窗口；点击**完成**关闭它。

1.  向`HelloNDKGDB.cpp`文件中添加以下代码：

    ```kt
    #include <jni.h>
    #include <unistd.h>

    int multiply(int i, int j) {
      int x = i * j;
      return x;
    }

    extern "C" {
      JNIEXPORT jint JNICALL Java_cookbook_chapter3_HelloNDKGDBActivity_multiply(JNIEnv* env, jobject o, jint pi, jint pj){
        int i = 1, j = 0;
        while (i) {
          j=(++j)/100; 

        }
        return multiply(pi, pj);
      }
    }
    ```

1.  将`HelloNDKGDBActivity.java`的内容更改为以下内容：

    ```kt
    package cookbook.chapter3;

    import android.os.Bundle;
    import android.widget.TextView;
    import android.app.Activity;

    public class HelloNDKGDBActivity extends Activity {

       @Overridepublic void onCreate(Bundle savedInstanceState) {
           super.onCreate(savedInstanceState);
           TextView tv = new TextView(this);
           tv.setTextSize(30);
           tv.setText("10 x 20 = " + multiply(10, 20));
           this.setContentView(tv);
       }
       public native int multiply(int a, int b);
       static {
           System.loadLibrary("HelloNDKGDB");
       }
    }
    ```

1.  确保在`AndroidManifest.xml`中的`debuggable`属性设置为`true`。以下代码段是从我们示例项目的`AndroidManifest.xml`中的应用程序元素中提取的一部分：

    ```kt
    <application
           android:icon="@drawable/ic_launcher"
           android:label="@string/app_name"
           android:theme="@style/AppTheme"
           android:debuggable="true"
           >
    ```

1.  使用命令"`ndk-build NDK_DEBUG=1`"构建本地库。或者，我们可以在 Eclipse 中配置项目的**属性**下的**C/C++ Build**中的`build`命令。这在*在 Eclipse 中调试 Android NDK 应用程序*的菜谱中有演示。

1.  在 Android 设备上运行应用程序。然后，启动一个终端并输入以下命令：

    ```kt
    $ ndk-gdb

    ```

1.  一旦调试器连接到远程进程，我们就可以发出 GDB 命令开始调试应用程序。如下所示：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_27.jpg)

## 工作原理...

随 Android NDK 附带的名为`ndk-gdb`的 shell 脚本可以启动本地调试会话与本地代码。为了使用`ndk-gdb`，我们必须以调试模式构建本地代码。这将生成一个`gdbserver`二进制文件和一个`gdb.setup`文件以及本地库。在安装时，`gdbserver`将被安装并在 Android 设备上启动`gdbserver`。

默认情况下，`ndk-gdb`会搜索正在运行的应用程序，并将`gdbserver`附加到它上面。也有选项可以在开始调试之前自动启动应用程序。因为应用程序在`gdbserver`附加之前首先启动，所以在调试之前会执行一些代码。如果我们想调试在应用程序启动时执行的代码，可以插入一个`while(true)`块。调试会话开始后，我们改变标志值以跳出`while(true)`块。这在我们示例项目中得到了演示。

调试会话开始后，我们可以使用`gdb`命令来调试我们的代码。

# 使用 CGDB 调试 Android NDK 应用程序

CGDB 是基于终端的轻量级 GNU 调试器`gdb`的界面。它提供了一个分割屏幕视图，同时显示源代码和调试信息。本教程将讨论如何使用`cgdb`调试 Android 应用程序。

## 准备工作

以下是在不同操作系统上安装`cgdb`的说明：

+   如果您使用的是 Ubuntu，可以使用以下命令安装`cgdb`：

    ```kt
    $ sudo apt-get install cgdb

    ```

    或者，您可以从[`cgdb.github.com/`](http://cgdb.github.com/)下载源代码，并按照以下说明安装`cgdb`：

    ```kt
    $ ./configure --prefix=/usr/local
    $ make
    $ sudo make install

    ```

    注意，`cgdb`需要`libreadline`和`ncurses`开发库。

+   如果您使用的是 Windows 系统，可以在[`cgdb.sourceforge.net/download.php`](http://cgdb.sourceforge.net/download.php)找到 Windows 二进制文件。

+   如果您使用的是 MacOS，可以使用以下 MacPorts 安装命令：

    ```kt
    $ sudo port install cgdb

    ```

在阅读本篇内容之前，请先阅读《使用 NDK GDB 调试 Android NDK 应用程序》的教程。

## 如何操作...

以下步骤为 Android NDK 应用程序调试启用`cgdb`：

1.  在 Android NDK 的`根`目录下复制`ndk-gdb`脚本。这可以通过以下命令完成：

    ```kt
    $ cp $ANDROID_NDK/ndk-gdb $ANDROID_NDK/ndk-cgdb

    ```

    这里，`$ANDROID_NDK`指的是 Android NDK 的`根`目录。

1.  将`ndk-cgdb`脚本中的以下行更改为：

    ```kt
    GDBCLIENT=${TOOLCHAIN_PREFIX}gdb

    ```

    更改为以下内容：

    ```kt
    GDBCLIENT="cgdb -d ${TOOLCHAIN_PREFIX}gdb --"

    ```

1.  我们将使用在《使用 NDK GDB 调试 Android NDK 应用程序》教程中创建的项目。如果您在 Eclipse IDE 中没有打开项目，点击**文件** | **导入**。在**常规**下选择**现有项目到工作空间**，然后点击**下一步**。在导入窗口中，勾选**选择根目录**，并浏览到`HelloNDKGDB`项目。点击**完成**以导入项目：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_33_new.jpg)

1.  在 Android 设备上运行应用程序。然后，启动一个终端，输入以下命令：

    ```kt
    ndk-cgdb

    ```

    下面是`cgdb`界面的截图：

    ![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_28.jpg)

1.  我们可以输入`gdb`命令。注意，窗口上半部分会用箭头标记当前执行行，并用红色标记所有断点。

## 工作原理...

如前一个屏幕截图所示，`cgdb`为在 Android 中调试本地代码提供了一个更直观的界面。我们可以输入`gdb`命令时查看源代码。这个食谱演示了使用`cgdb`调试本地代码的基本设置。有关如何使用`cgdb`的详细信息，请参阅其文档，地址为[`cgdb.github.com/docs/cgdb.html`](http://cgdb.github.com/docs/cgdb.html)。

# 在 Eclipse 中调试 Android NDK 应用程序

对于习惯于图形化开发工具的开发者来说，在终端中使用 GDB 或 CGDB 进行调试是很麻烦的。使用**Android 开发工具**（**ADT**）20.0.0 或更高版本，在 Eclipse 中调试 NDK 应用程序相当简单。

## 准备就绪

确保您已安装 ADT 20.0.0 或更高版本。如果没有，请参考第一章中的食谱，*你好 NDK*，了解如何设置您的环境。

确保您已在 Eclipse 中配置了 NDK 路径。此外，在阅读这个食谱之前，您应该至少构建和运行过一个 Android NDK 应用程序。如果没有，请阅读*在 Eclipse 中构建 Android NDK 应用程序*的食谱。

## 如何操作...

以下步骤将创建一个示例 Android 项目，并使用 Eclipse 进行调试：

1.  我们将使用在*在 Eclipse 中构建 Android NDK 应用程序*的食谱中创建的项目。如果您在 Eclipse IDE 中没有打开项目，请点击**文件** | **导入**。在**常规**下选择**现有项目到工作空间**，然后点击**下一步**。在**导入**窗口中，勾选**选择根目录**，并浏览到`HelloNDKEclipse`项目。点击**完成**以导入项目：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_29.jpg)

1.  在`HelloNDKEclipse`项目上右键点击，选择**属性**。在**属性**窗口中，选择**C/C++ 构建器**。取消勾选**使用默认构建命令**，并将**构建**命令更改为`ndk-build NDK_DEBUG=1`。

1.  点击**确定**关闭窗口：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_30.jpg)

1.  在`HelloNDKEclipseActivity.java`中调用本地方法之前添加以下代码。

    在`HelloNDKEclipse.cpp`中设置两个断点：

    ![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_31.jpg)

1.  在您的项目上右键点击，然后选择**调试为** | **Android 原生应用程序**。我们将看看是否触发了断点。![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_03_32.jpg)

## 它的工作原理...

由于应用程序启动和调试会话启动之间存在几秒钟的延迟，设置断点的源代码可能在调试开始之前就已经执行了。在这种情况下，断点永远不会被触发。在*使用 NDK GDB 调试 Android NDK 应用程序*的食谱中，我们演示了使用`while(true)`循环来解决这个问题。这里我们展示了另一种方法，在应用程序启动时让代码休眠几秒钟。这为调试器提供了足够的时间来启动。一旦开始调试，我们可以使用正常的 Eclipse 调试界面来调试我们的代码。

## 还有更多...

还有其他一些调试器可用于调试 Android NDK 应用程序。

**数据显示调试器**（**DDD**）是 GDB 的图形前端。可以设置 DDD 来调试 Android 应用程序。详细的操作指南可以在[`omappedia.org/wiki/Android_Debugging#Debugging_with_GDB_and_DDD`](http://omappedia.org/wiki/Android_Debugging#Debugging_with_GDB_and_DDD)找到。

**NVIDIA 调试管理器**是一个 Eclipse 插件，用于协助在基于 NVIDIA Tegra 平台的设备上调试 Android NDK 应用程序。关于此工具的更多信息可以在[`developer.nvidia.com/nvidia-debug-manager-android-ndk`](https://developer.nvidia.com/nvidia-debug-manager-android-ndk)找到。


# 第四章．Android NDK OpenGL ES API

在本章中，我们将涵盖以下内容：

+   使用 OpenGL ES 1.x API 绘制 2D 图形并应用变换

+   使用 OpenGL ES 1.x API 绘制 3D 图形并照亮场景

+   使用 OpenGL ES 1.x API 将纹理映射到 3D 对象

+   使用 OpenGL ES 2.0 API 绘制 3D 图形

+   使用 EGL 显示图形

# 引言

**开放图形库**（**OpenGL**）是一个跨平台的工业标准 API，用于生成 2D 和 3D 图形。它定义了一个与语言无关的软件接口，用于图形硬件或软件图形引擎。**OpenGL ES**是针对嵌入式设备的 OpenGL 版本。它由 OpenGL 规范的一个子集和一些特定于 OpenGL ES 的附加扩展组成。

OpenGL ES 不需要专用的图形硬件来工作。不同的设备可以配备具有不同处理能力的图形硬件。OpenGL ES 的调用工作负载在 CPU 和图形硬件之间分配。完全从 CPU 支持 OpenGL ES 是可能的。然而，根据其处理能力，图形硬件可以在不同级别上提高性能。

在深入探讨 Android NDK OpenGL ES 之前，有必要简要介绍一下 OpenGL 上下文中的**图形渲染管线**（**GRP**）。GRP 指的是一系列处理阶段，图形硬件通过这些阶段来生成图形。它以图元（**图元**指的是简单的几何形状，如点、线和三角形）的顶点形式接受对象描述，并为显示上的像素输出颜色值。它可以大致分为以下四个主要阶段：

1.  **顶点处理**：它接受图形模型描述，处理并转换各个顶点以将它们投影到屏幕上，并将它们的信息组合起来进行**图元**的进一步处理。

1.  **光栅化**：它将图元转换为片段。一个**片段**包含生成帧缓冲区中像素数据所必需的数据。请注意，只有受到一个或多个图元影响的像素才会有片段。一个片段包含信息，如光栅位置、深度、插值颜色和纹理坐标。

1.  **片段处理**：它处理每个片段。一系列操作被应用于每个片段，包括 alpha 测试、纹理映射等。

1.  **输出合并**：它将所有片段结合起来，为 2D 显示产生颜色值（包括 alpha）。

在现代计算机图形硬件中，顶点处理和片段处理是可编程的。我们可以编写程序来执行自定义的顶点和片段转换和处理。相比之下，光栅化和输出合并是可配置的，但不可编程。

前述每个阶段可以包含一个或多个步骤。OpenGL ES 1.x 和 OpenGL ES 2.0 提供了不同的 GRP。具体来说，OpenGL ES 1.x 提供了一个固定功能管线，我们输入原始数据和纹理数据，设置光照，剩下的由 OpenGL ES 处理。相比之下，OpenGL ES 2.0 提供了一个可编程管线，允许我们用**OpenGL ES 着色语言**（**GLSL**）编写顶点和片段着色器来处理具体细节。

下图指示了 OpenGL ES 1.x 的固定功能管线：

![介绍](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_04_01.jpg)

下图是另一个说明 OpenGL ES 2.0 可编程管线的图：

![介绍](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_04_02.jpg)

如前图所示，OpenGL ES 1.x 中的固定管线已经被 OpenGL ES 2.0 中的可编程着色器所取代。

通过这篇计算机图形学的介绍，我们现在准备开始学习 Android NDK OpenGL ES 编程的旅程。Android NDK 提供了 OpenGL ES 1.x（版本 1.0 和版本 1.1）和 OpenGL ES 2.0 库，它们之间有显著差异。以下表格概述了在选择 Android 应用程序中使用的 OpenGL ES 版本时需要考虑的因素：

|   | OpenGL 1.x | OpenGL 2.0 |
| --- | --- | --- |
| **性能** | 快速的 2D 和 3D 图形。 | 根据 Android 设备而定，但通常提供更快的 2D 和 3D 图形。 |
| **设备兼容性** | 几乎所有的 Android 设备。 | 大多数 Android 设备，且在增加中。 |
| **编码便利性** | 固定管线，方便的功能。对于简单的 3D 应用来说容易使用。 | 没有内置的基本功能，对于简单的 3-D 应用可能需要更多努力。 |
| **图形控制** | 固定管线。创建某些效果（例如，卡通着色）困难或不可能。 | 可编程管线。更直接地控制图形处理管线以创建特定效果。 |

### 提示

所有 Android 设备都支持 OpenGL ES 1.0，因为 Android 附带了一个 1.0 能力的软件图形引擎，可以在没有相应图形硬件的设备上使用。只有配备相应**图形处理单元**（**GPU**）的设备支持 OpenGL ES 1.1 和 OpenGL ES 2.0。

本章将介绍 Android NDK 中的 OpenGL 1.x 和 OpenGL ES 2.0 API。我们首先展示了如何使用 OpenGL 1.x API 绘制 2D 和 3D 图形。涵盖了变换、光照和纹理映射。然后我们介绍 NDK 中的 OpenGL 2.0 API。最后，我们描述如何使用 EGL 显示图形。本章介绍了一些计算机图形学的基础知识和 OpenGL 的原则。已经熟悉 OpenGL ES 的读者可以跳过这些部分，专注于如何从 Android NDK 调用 OpenGL ES API。

我们将为本章介绍的每个教程提供一个示例 Android 应用程序。由于篇幅限制，书中无法展示所有源代码。强烈建议读者下载代码并在阅读本章时参考。

# 使用 OpenGL ES 1.x API 绘制 2D 图形并应用变换

本教程通过示例介绍了 OpenGL ES 1.x 中的 2D 绘图。为了绘制 2D 对象，我们还将描述通过`GLSurfaceView`的 OpenGL 渲染显示，为它们添加颜色以及变换。

## 准备就绪

推荐读者阅读本章的介绍，这对于理解本教程中的一些内容至关重要。

## 如何操作...

以下步骤将创建我们的示例 Android NDK 项目：

1.  创建一个名为`TwoDG1`的 Android 应用程序。将包名设置为`cookbook.chapter4.gl1x`。如果你需要更详细的说明，请参考第二章中的*加载本地库和注册本地方法*教程，*Java 本地接口*。

1.  在 Eclipse 中右键点击`TwoDG1`项目，选择**Android Tools** | **Add Native Support**。

1.  在`cookbook.chapter4.gl1x`包下添加以下三个 Java 文件：

    +   `MyActivity.java`：它创建了此项目的活动：

        ```kt
        import android.opengl.GLSurfaceView;
        ……
        public class MyActivity extends Activity {
          private GLSurfaceView mGLView;
          @Override
          public void onCreate(Bundle savedInstanceState) {
            super.onCreate(savedInstanceState);
            mGLView = new MySurfaceView(this);
                   setContentView(mGLView);
          }
        }
        ```

    +   `MySurfaceView.java`：它扩展了`GLSurfaceView`，后者提供了一个专用的表面来显示 OpenGL 渲染：

        ```kt
        public class MySurfaceView extends GLSurfaceView {
          private MyRenderer mRenderer;
          public MySurfaceView(Context context) {
            super(context);
            mRenderer = new MyRenderer();
            this.setRenderer(mRenderer);
            this.setRenderMode(GLSurfaceView.RENDERMODE_WHEN_DIRTY);
          }
        }
        ```

    +   `MyRenderer.java`：它实现了`Renderer`并调用本地方法：

        ```kt
        public class MyRenderer implements GLSurfaceView.Renderer{
          @Override
          public void onSurfaceCreated(GL10 gl, EGLConfig config) {
            naInitGL1x();
          }
          @Override
          public void onDrawFrame(GL10 gl) {
            naDrawGraphics();
          }
          @Override
          public void onSurfaceChanged(GL10 gl, int width, int height) {
            naSurfaceChanged(width, height);
          }
          ......
        }
        ```

1.  在`jni`文件夹下添加`TwoDG1.cpp`、`Triangle.cpp`、`Square.cpp`、`Triangle.h`和`Square.h`文件。请参考下载的项目以获取完整的代码内容。这里，我们只列出代码中的一些重要部分：

    `TwoDG1.cpp`：它包含了设置 OpenGL ES 1.x 环境并执行变换的代码：

    ```kt
    void naInitGL1x(JNIEnv* env, jclass clazz) {
      glDisable(GL_DITHER);  
      glHint(GL_PERSPECTIVE_CORRECTION_HINT, GL_FASTEST);
      glClearColor(0.0f, 0.0f, 0.0f, 1.0f);    glShadeModel(GL_SMOOTH);    }

    void naSurfaceChanged(JNIEnv* env, jclass clazz, int width, int height) {
      glViewport(0, 0, width, height);
      float ratio = (float) width / (float)height;
      glMatrixMode(GL_PROJECTION);
      glLoadIdentity();
      glOrthof(-ratio, ratio, -1, 1, 0, 1);  }

    void naDrawGraphics(JNIEnv* env, jclass clazz) {
      glClear(GL_COLOR_BUFFER_BIT);
      glMatrixMode(GL_MODELVIEW);
      glLoadIdentity();
      glTranslatef(0.3f, 0.0f, 0.0f);    //move to the right
      glScalef(0.2f, 0.2f, 0.2f);        // Scale down
      mTriangle.draw();
      glLoadIdentity();
      glTranslatef(-0.3f, 0.0f, 0.0f);    //move to the left
      glScalef(0.2f, 0.2f, 0.2f);      // Scale down
    glRotatef(45.0, 0.0, 0.0, 1.0);  //rotate
      mSquare.draw();
    }
    ```

    `Triangle.cpp`：它绘制一个 2D 三角形：

    ```kt
    void Triangle::draw() {
      glEnableClientState(GL_VERTEX_ARRAY);
      glVertexPointer(3, GL_FLOAT, 0, vertices);
      glColor4f(0.5f, 0.5f, 0.5f, 0.5f);      //set the current color
      glDrawArrays(GL_TRIANGLES, 0, 9/3);
      glDisableClientState(GL_VERTEX_ARRAY);
    }
    ```

    `Square.cpp`：它绘制一个 2D 正方形：

    ```kt
    void Square::draw() {
      glEnableClientState(GL_VERTEX_ARRAY);
      glEnableClientState(GL_COLOR_ARRAY);
      glVertexPointer(3, GL_FLOAT, 0, vertices);
      glColorPointer(4, GL_FLOAT, 0, colors);
      glDrawElements(GL_TRIANGLES, 6, GL_UNSIGNED_BYTE, indices);
      glDisableClientState(GL_VERTEX_ARRAY);
      glDisableClientState(GL_COLOR_ARRAY);
    }
    ```

1.  在`jni`文件夹下添加`Android.mk`文件，内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := TwoDG1
    LOCAL_SRC_FILES := Triangle.cpp Square.cpp TwoDG1.cpp
    LOCAL_LDLIBS := -lGLESv1_CM -llog
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  构建 Android NDK 应用程序并在 Android 设备上运行。以下是显示的截图：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_04_03.jpg)

## 工作原理...

本教程演示了使用 OpenGL ES 的基本 2D 绘图。

### 通过 GLSurfaceView 显示 OpenGL ES 渲染

`GLSurfaceView`和`GLSurfaceView.Renderer`是 Android SDK 提供的两个基础类，用于显示 OpenGL ES 图形。

`GLSurfaceView`接受一个用户定义的`Renderer`对象，该对象实际执行渲染。它通常被扩展以处理触摸事件，这将在下一个教程中说明。它支持按需和连续渲染。在我们的示例代码中，我们只需设置`Renderer`对象并将渲染模式配置为按需。

`GLSurfaceView.Renderer`是渲染器的接口。需要实现它的三个方法：

+   `onSurfaceCreated`：在设置 OpenGL ES 环境时被调用一次。

+   `onSurfaceChanged`：如果视图的几何形状发生变化，它会被调用；最常见的例子是设备屏幕方向的变化。

+   `onDrawFrame`：每次重绘视图时都会调用它。

在我们的示例项目中，`MyRenderer.java`是一个简单的包装器，实际工作是在本地 C++代码中完成的。

### 在 OpenGL ES 中绘制物体

在 OpenGL ES 中绘制物体通常使用两种方法，包括`glDrawArrays`和`glDrawElements`。我们分别在`Triangle.cpp`和`Square.cpp`中演示了这两种方法的用法。请注意，这两种方法都需要启用`GL_VERTEX_ARRAY`。

第一个参数是绘制模式，指明了要使用的图元。在我们的示例代码中，我们使用了`GL_TRIANGLES`，这意味着我们实际上绘制了两个三角形来形成正方形。在 Android NDK OpenGL ES 中还有其他有效值，包括`GL_POINTS`、`GL_LINES`、`GL_LINE_LOOP`、`GL_LINE_STRIP`、`GL_TRIANGLE_STRIP`和`GL_TRIANGLE_FAN`。

### 在 OpenGL ES 中的颜色

我们还展示了两种给物体添加颜色的方法。在`Triangle.cpp`中，我们通过`glColor4f` API 调用设置当前颜色。在`Square.cpp`中，我们启用了`GL_COLOR_ARRAY`，并使用`glColorPointer`定义了一个颜色数组。该颜色数组将由`glDrawElements`（使用`glDrawArrays`也行）API 调用使用。

### OpenGL ES 转换

下图展示了 OpenGL ES 1.0 中的不同转换阶段：

![OpenGL ES 转换](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_04_04.jpg)

如图中所示，顶点数据在光栅化之前进行转换。这些转换类似于用相机拍照：

+   **模型视图转换**：安排场景并放置相机

+   **投影转换**：选择一个相机镜头并调整缩放因子

+   **视点转换**：确定最终照片的大小

**模型视图转换**实际上指的是两种不同的转换，即模型转换和视图转换。**模型转换**是指将所有物体从其对象空间（也称为局部空间或模型空间）转换到世界空间的过程，该空间被所有物体共享。这个转换通过一系列缩放（`glScalef`）、旋转（`glRotatef`）和平移（`glTranslatef`）来完成。

+   `glScalef`：它拉伸、缩小或反射物体。x、y 和 z 轴的值分别乘以相应的 x、y 和 z 缩放因子。在我们的示例代码中，我们调用了`glScalef(0.2f, 0.2f, 0.2f)`，以缩小三角形和正方形，使它们能够适应屏幕。

+   `glRotatef`：它以从原点通过指定点（x, y, z）的方向逆时针旋转物体。旋转角度以度为单位测量。在我们的示例代码中，我们调用了`glRotatef(45.0, 0.0, 0.0, 1.0)`，使正方形绕 z 轴旋转 45 度。

+   `glTranslatef`：该函数根据给定的值沿着每个轴移动对象。在我们的示例代码中，我们调用了`glTranslatef(0.3f, 0.0f, 0.0f)`将三角形向右移动，以及`glTranslatef(-0.3f, 0.0f, 0.0f)`将正方形向左移动，以防止它们重叠。

模型变换在场景中安排对象，而视图变换改变观察相机的位置。为了产生特定的图像，我们可以移动对象或改变相机位置。因此，OpenGL ES 内部使用单一的矩阵——`GL_MODELVIEW`矩阵执行这两种变换。

### 提示

OpenGL ES 定义了相机默认位于眼睛坐标空间的原点（0, 0, 0），并指向负 z 轴。可以通过 Android SDK 中的`GLU.gluLookAt`改变位置。然而，在 Android NDK 中不提供相应的 API。

**投影变换**决定了可以看到什么（类似于选择相机镜头和缩放因子）以及顶点数据如何投影到屏幕上。OpenGL ES 支持两种投影模式，分别是透视投影（`glFrustum`）和正交投影（`glOrtho`）。**透视投影**使得远离的物体显得更小，这与普通相机相匹配。另一方面，**正交投影**类似于望远镜，直接映射物体而不影响其大小。OpenGL ES 通过`GL_PROJECTION`矩阵操纵变换。在投影变换后，位于裁剪体积外的物体将被裁剪掉，在最终场景中不绘制。在我们的示例项目中，我们调用了`glOrthof(-ratio, ratio, -1, 1, 0, 10)`来指定视景体，其中`ratio`指的是屏幕的宽高比。

投影变换后，通过将裁剪坐标除以输入顶点的变换后的`w`值来进行透视除法。x 轴、y 轴和 z 轴的值将被归一化到`-1.0`到`1.0`的范围内。

OpenGL ES 变换管道的最终阶段是视口变换，它将归一化设备坐标映射到窗口坐标（以像素为单位，原点在左上角）。请注意，视点还包括一个 z 分量，这在例如两个重叠的 OpenGL 场景的排序等情况下是需要的，可以通过`glDepthRange` API 调用设置。当显示尺寸发生变化时，应用程序通常需要通过`glViewport` API 调用设置视口。在我们的示例中，我们通过调用`glViewport(0, 0, width, height)`将视口设置为整个屏幕。这个设置与`glOrthof`调用一起，将保持投影变换后的对象比例，如下图所示：

![OpenGL ES 变换](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_04_05.jpg)

如图表所示，裁剪体积设置为（-width/height, width/height, -1, 1, 0, 1）。在透视除法中，顶点被`w`除。在视点变换中，x 和 y 坐标范围都被`w*height/2`放大。因此，对象将如本食谱的*如何操作...*部分所示成比例显示。以下屏幕截图的左侧显示了如果我们通过调用`glOrthof(-1, 1, -1, 1, 0, 1)`设置裁剪体积的输出，右侧表示如果通过调用`glViewport(0, 0, width/2, height/5)`设置视口，图形将呈现什么样子：

![OpenGL ES 变换](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_04_06_new.jpg)

# 使用 OpenGL ES 1.x API 绘制 3D 图形并点亮场景

本食谱涵盖了如何在 OpenGL ES 中绘制 3D 对象、处理触摸事件以及点亮对象。

## 准备就绪

建议读者在阅读本食谱之前，先阅读引言和下面的*使用 OpenGL ES 1.x API 绘制 2D 图形和应用变换*的食谱。

## 如何操作...

以下步骤展示了如何开发我们的示例 Android 项目：

1.  创建一个名为`CubeG1`的 Android 应用程序。将包名设置为`cookbook.chapter4.gl1x`。如果你需要更详细的说明，请参考第二章中的*加载本地库和注册本地方法*食谱，*Java Native Interface*。

1.  右键点击项目 CubeG1，选择**Android Tools** | **添加本地支持**。

1.  在`cookbook.chapter4.gl1x`包下添加三个 Java 文件，分别为`MyActivity.java`，`MySurfaceView`和`MyRenderer.java`。`MyActivity.java`与上一个食谱中使用的一致。

    `MySurfaceView.java`扩展了`GLSurfaceView`，包含处理触摸事件的代码：

    ```kt
    public class MySurfaceView extends GLSurfaceView {
      private MyRenderer mRenderer;
      private float mPreviousX;
       private float mPreviousY;
       private final float TOUCH_SCALE_FACTOR = 180.0f / 320;
      public MySurfaceView(Context context) {
        super(context);
        mRenderer = new MyRenderer();
        this.setRenderer(mRenderer);
        //control whether continuously drawing or on-demand
        this.setRenderMode(GLSurfaceView.RENDERMODE_WHEN_DIRTY);
      }

      public boolean onTouchEvent(final MotionEvent event) {
        float x = event.getX();
           float y = event.getY();
           switch (event.getAction()) {
           case MotionEvent.ACTION_MOVE:
               float dx = x - mPreviousX;
               float dy = y - mPreviousY;
               mRenderer.mAngleX += dx * TOUCH_SCALE_FACTOR;
               mRenderer.mAngleY += dy * TOUCH_SCALE_FACTOR;
               requestRender();
           }
           mPreviousX = x;
           mPreviousY = y;
           return true;
       }
    }
    ```

    `MyRenderer.java`实现了一个渲染器，以调用本地方法渲染图形：

    ```kt
    public class MyRenderer implements GLSurfaceView.Renderer{
       public float mAngleX;
       public float mAngleY;
      @Override
      public void onSurfaceCreated(GL10 gl, EGLConfig config) {
        naInitGL1x();
      }
      @Override
      public void onDrawFrame(GL10 gl) {
        naDrawGraphics(mAngleX, mAngleY);
      }
      @Override
      public void onSurfaceChanged(GL10 gl, int width, int height) {
        naSurfaceChanged(width, height);
      }
    }
    ```

1.  在`jni`文件夹下添加`CubeG1.cpp`、`Cube.cpp`和`Cube.h`文件。请参考下载的项目以获取完整内容。让我们列出`CubeG1.cpp`中的`naInitGL1x`、`naSurfaceChanged`和`naDrawGraphics`本地方法以及`Cube.cpp`中的绘制和光照方法的代码：

    `CubeG1.cpp`设置 OpenGL ES 环境和光照：

    ```kt
    void naInitGL1x(JNIEnv* env, jclass clazz) {
      glDisable(GL_DITHER);
      glHint(GL_PERSPECTIVE_CORRECTION_HINT, GL_NICEST);
      glClearColor(0.0f, 0.0f, 0.0f, 1.0f);    glEnable(GL_CULL_FACE);    
      glClearDepthf(1.0f);  glEnable(GL_DEPTH_TEST);  
      glDepthFunc(GL_LEQUAL);    //type of depth test
      glShadeModel(GL_SMOOTH);    
      glLightModelx(GL_LIGHT_MODEL_TWO_SIDE, 0);
      float globalAmbientLight[4] = {0.5, 0.5, 0.5, 1.0};
      glLightModelfv(GL_LIGHT_MODEL_AMBIENT, globalAmbientLight);
      GLfloat lightOneDiffuseLight[4] = {1.0, 1.0, 1.0, 1.0};
      GLfloat lightOneSpecularLight[4] = {1.0, 1.0, 1.0, 1.0};
      glLightfv(GL_LIGHT0, GL_DIFFUSE, lightOneDiffuseLight);
      glLightfv(GL_LIGHT0, GL_SPECULAR, lightOneSpecularLight);
      glEnable(GL_LIGHTING);
      glEnable(GL_LIGHT0);
    }
    void naSurfaceChanged(JNIEnv* env, jclass clazz, int width, int height) {
      glViewport(0, 0, width, height);
       float ratio = (float) width / height;
       glMatrixMode(GL_PROJECTION);
       glLoadIdentity();
       glOrthof(-ratio, ratio, -1, 1, -10, 10);
    }
    void naDrawGraphics(JNIEnv* env, jclass clazz, float pAngleX, float pAngleY) {
      glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
       glMatrixMode(GL_MODELVIEW);
       glLoadIdentity();
       glRotatef(pAngleX, 0, 1, 0);  //rotate around y-axis
       glRotatef(pAngleY, 1, 0, 0);  //rotate around x-axis
      glScalef(0.3f, 0.3f, 0.3f);      // Scale down
    mCube.lighting();
      mCube.draw();
      float lightOnePosition[4] = {0.0, 0.0, 1.0, 0.0};  
      glLightfv(GL_LIGHT0, GL_POSITION, lightOnePosition);
    }
    ```

    `Cube.cpp`绘制一个 3D 立方体并点亮它：

    ```kt
    void Cube::draw() {
      glEnableClientState(GL_VERTEX_ARRAY);
      glVertexPointer(3, GL_FLOAT, 0, vertices);
      glDrawElements(GL_TRIANGLES, 36, GL_UNSIGNED_BYTE, indices);
      glDisableClientState(GL_VERTEX_ARRAY);
    }
    void Cube::lighting() {
      GLfloat cubeOneAmbientFraction[4] = {0.0, 0.5, 0.5, 1.0};
      GLfloat cubeOneDiffuseFraction[4] = {0.8, 0.0, 0.0, 1.0};
      GLfloat cubeSpecularFraction[4] = {0.0, 0.0, 0.0, 1.0};
      GLfloat cubeEmissionFraction[4] = {0.0, 0.0, 0.0, 1.0};
      glMaterialfv(GL_FRONT_AND_BACK, GL_AMBIENT, cubeOneAmbientFraction);
      glMaterialfv(GL_FRONT_AND_BACK, GL_DIFFUSE, cubeOneDiffuseFraction);
      glMaterialfv(GL_FRONT_AND_BACK, GL_SPECULAR, cubeSpecularFraction);
      glMaterialfv(GL_FRONT_AND_BACK, GL_EMISSION, cubeEmissionFraction);
      glMaterialf(GL_FRONT_AND_BACK, GL_SHININESS, 60.0);
    }
    ```

1.  在`jni`文件夹下添加`Android.mk`文件，内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := CubeG1
    LOCAL_SRC_FILES := Cube.cpp CubeG1.cpp
    LOCAL_LDLIBS := -lGLESv1_CM -llog
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  构建 Android NDK 应用程序并在 Android 设备上运行。应用程序将显示一个立方体，我们可以触摸它使其旋转：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_04_08_new.jpg)

## 工作原理...

本食谱讨论了如何使用 OpenGL ES 1.x API 绘制 3D 图形。注意，我们将在`Andorid.mk`文件中需要加载 OpenGL ES 库`GLESv1_CM`，并在本地源代码中包含头文件`GLES/gl.h`。

+   **在 OpenGL ES 中绘制 3D 对象**：绘制 3D 对象与绘制 2D 对象类似。在`Cube::draw`方法中，我们首先设置顶点缓冲区，然后调用`glDrawElements`来绘制立方体的六个面。我们使用`GL_TRIANGLES`作为图元。因为每个面包含两个三角形，所以有 12 个三角形和 36 个顶点。

+   **触摸事件处理**：在`MySurfaceView.java`中，我们重写`onTouchEvent`方法以检测屏幕上的图形移动，并改变`MyRenderer`的旋转角度属性。我们调用`requestRender`方法，请求渲染器重新绘制图形。

+   **OpenGL ES 中的光照和材质**：光照模型分为两类，即局部光照和全局光照。**局部光照**只考虑直接光照，因此可以对单个对象进行光照计算。与之相对的是，**全局光照**考虑了从其他对象和环境反射的间接光照，因此计算成本更高。OpenGL ES 1.x 使用局部光照，而全局光照可以使用**OpenGL 着色语言**（**GLSL**）在 OpenGL ES 2.0 中进行编程。这里，我们只讨论 OpenGL ES 1.x 中的光照。

当考虑光照时，OpenGL ES 中涉及三个参与者，包括摄像机位置、光源和物体的材质。摄像机位置始终在默认位置`(0, 0, 0)`，并朝向负 z 轴，如前面的食谱所述。光源可以提供独立的环境光、漫反射光和镜面光。材质可以反射不同数量的环境光、漫反射光和镜面光。此外，材质也可能发射光。每种光都由 RGB 分量组成：

+   **环境光**：它近似于场景中无处不在的恒定光照量。

+   **漫反射光**：它近似于来自远距离方向光源的光（例如，阳光）。当反射光照射到表面时，它在所有方向上均匀散射。

+   **镜面光**：它近似于光滑表面反射的光。其强度取决于观察者与从表面反射的射线方向之间的角度。

+   **发射光**：某些材质可以发光。

请注意，光源中的 RGB 值表示颜色分量的强度，而在材质中则指反射这些颜色的比例。为了理解光源和材质如何影响观察者对物体的感知，可以考虑一束白光照射在表面上，如果表面只反射光的蓝色分量，那么观察者看到的表面将是蓝色的。如果光是纯红色的，那么观察者看到的表面将是黑色的。

以下步骤可以在 OpenGL ES 中设置简单的光照：

1.  设置光照模型参数。这是通过`glLightModelfv`完成的。Android NDK OpenGL ES 支持两个参数，包括`GL_LIGHT_MODEL_AMBIENT`和`GL_LIGHT_MODEL_TWO_SIDE`。第一个允许我们指定全局环境光，第二个允许我们指定是否要在表面的背面计算光照。

1.  启用、配置并放置一个或多个光源。这是通过`glLightfv`方法完成的。我们可以分别配置环境光、漫反射光和镜面光。光源位置也通过`glLightfv`与`GL_POSITION`一起配置。在`CubeG1.cpp`中，我们使用了以下代码：

    ```kt
    float lightOnePosition[4] = {0.0, 0.0, 1.0, 0.0};  
    glLightfv(GL_LIGHT0, GL_POSITION, lightOnePosition);
    ```

    位置的第四个值表示光源是位置的还是方向的。当值设置为`0`时，光为方向光，模拟一个远距离的光源（阳光）。光线在撞击表面时是平行的，位置的（x, y, z）值指的是光的传播方向。如果第四个值设置为`1`，光为位置光，类似于灯泡。这里的（x, y, z）值指的是光源的位置，光线从不同的角度撞击表面。请注意，光源向所有方向发射强度相等的光。以下图像说明了这两种光源：

    ![它是如何工作的...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_04_22.jpg)

除了位置光和方向光，还有聚光灯：

1.  我们也将通过调用以下方法来启用光照和光源

    ```kt
    glEnable(GL_LIGHTING);
    ```

    以及

    ```kt
    glEnable(GL_LIGHTx);
    ```

1.  为所有对象的每个顶点定义法向量。这些法向量决定了物体相对于光源的方向。在我们的代码中，我们依赖 OpenGL ES 的默认法向量。

1.  定义材质。这可以通过`glMaterialf`或`glMaterialfv`方法来完成。在我们的示例代码中，我们将漫反射光的红色分量指定为`0.8`，而将绿色和蓝色分量保持为 0。因此，最终的立方体看起来是红色的。

# 使用 OpenGL ES 1.x API 将纹理映射到 3D 对象

**纹理映射**是一种将图像覆盖到物体表面以创建更真实场景的技术。这个菜谱涵盖了如何在 OpenGL ES 1.x 中添加纹理。

## 准备就绪

建议读者在阅读本节内容之前，先阅读《使用 OpenGL ES 1.x API 绘制 3D 图形并照亮场景》的菜谱。

## 如何操作...

以下步骤创建了一个展示如何将纹理映射到 3D 对象的 Android 项目：

1.  创建一个名为`DiceG1`的 Android 应用程序。将包名设置为`cookbook.chapter4.gl1x`。如果你需要更详细的说明，请参考第二章《Java 本地接口》中的《加载本地库和注册本地方法》菜谱。

1.  在项目`CubeG1`上点击右键，选择**Android Tools** | **添加本地支持**。

1.  在`cookbook.chapter4.diceg1`包下添加三个 Java 文件，分别为`MyActivity.java`，`MySurfaceView.java`和`MyRenderer.java`。`MyActivity.java`和`MySurfaceView.java`与之前的配方相似。

1.  `MyRenderer.java`代码如下：

    ```kt
    public class MyRenderer implements GLSurfaceView.Renderer{
       public float mAngleX;
       public float mAngleY;
       private Context mContext;
       public MyRenderer(Context pContext) {
         super();
         mContext = pContext;
       }
      @Override
      public void onSurfaceCreated(GL10 gl, EGLConfig config) {
        //call native methods to load the textures
        LoadTexture(R.drawable.dice41, mContext, 0);
        LoadTexture(R.drawable.dice42, mContext, 1);
        LoadTexture(R.drawable.dice43, mContext, 2);
        LoadTexture(R.drawable.dice44, mContext, 3);
        LoadTexture(R.drawable.dice45, mContext, 4);
        LoadTexture(R.drawable.dice46, mContext, 5);
        naInitGL1x();
      }
    … …
      private void LoadTexture(int resId, Context context, int texIdx) {
        //Get the texture from the Android resource directory
        InputStream is = context.getResources().openRawResource(resId);
        Bitmap bitmap = null;
        try {
          BitmapFactory.Options options = new BitmapFactory.Options();
          options.inPreferredConfig = Bitmap.Config.ARGB_8888;
          bitmap = BitmapFactory.decodeStream(is, null, options);
          naLoadTexture(bitmap, bitmap.getWidth(), bitmap.getHeight(), texIdx);
        } finally {
          try {
            is.close();
            is = null;
          } catch (IOException e) {
          }
        }
        if (null != bitmap) {
          bitmap.recycle();
        }
      }
    }
    ```

1.  在`jni`文件夹下添加`DiceG1.cpp`，`Cube.cpp`，`Cube.h`和`mylog.h`文件。请参考下载的项目以获取完整内容。这里，我们列出`DiceG1.cpp`中的`fornaLoadTexture`和`naInitGL1x`本地方法以及`Cube.cpp`中的`draw`方法的代码：

    ```kt
    void naLoadTexture(JNIEnv* env, jclass clazz, jobject pBitmap, int pWidth, int pHeight, int pId) {
      int lRet;
      AndroidBitmapInfo lInfo;
      void* l_Bitmap;
      GLint format;
      GLenum type;
      if ((lRet = AndroidBitmap_getInfo(env, pBitmap, &lInfo)) < 0) {
        return;
      }
      if (lInfo.format == ANDROID_BITMAP_FORMAT_RGB_565) {
        format = GL_RGB;
        type = GL_UNSIGNED_SHORT_5_6_5;
      } else if (lInfo.format == ANDROID_BITMAP_FORMAT_RGBA_8888) {
        format = GL_RGBA;
        type = GL_UNSIGNED_BYTE;
      } else {
        return;
      }
      if ((lRet = AndroidBitmap_lockPixels(env, pBitmap, &l_Bitmap)) < 0) {
        return;
      }
      glGenTextures(1, &texIds[pId]);
      glBindTexture(GL_TEXTURE_2D, texIds[pId]);
      glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_NEAREST);
      glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_MAG_FILTER, GL_NEAREST);
      glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_S, GL_REPEAT);
      glTexParameteri(GL_TEXTURE_2D, GL_TEXTURE_WRAP_T, GL_REPEAT);
      glTexImage2D(GL_TEXTURE_2D, 0, format, pWidth, pHeight, 0, format, type, l_Bitmap);
      AndroidBitmap_unlockPixels(env, pBitmap);
    }
    void naInitGL1x(JNIEnv* env, jclass clazz) {
      glDisable(GL_DITHER);  
      glHint(GL_PERSPECTIVE_CORRECTION_HINT, GL_NICEST);
      glClearColor(0.0f, 0.0f, 0.0f, 1.0f);  
      glEnable(GL_CULL_FACE);    
      glClearDepthf(1.0f);  
      glEnable(GL_DEPTH_TEST);  
      glDepthFunc(GL_LEQUAL);    
      glShadeModel(GL_SMOOTH);   
      mCube.setTexCoords(texIds);
      glTexEnvx(GL_TEXTURE_ENV, GL_TEXTURE_ENV_MODE, GL_REPLACE);
      glEnable(GL_TEXTURE_2D);
    }
    Cube.cpp: drawing the cube and mapping texture
    void Cube::draw() {
      glEnableClientState(GL_VERTEX_ARRAY);
      glEnableClientState(GL_TEXTURE_COORD_ARRAY);  // Enable texture-coords-array
      glFrontFace(GL_CW);

      glBindTexture(GL_TEXTURE_2D, texIds[0]);
      glTexCoordPointer(2, GL_FLOAT, 0, texCoords);
      glVertexPointer(3, GL_FLOAT, 0, vertices);
      glDrawElements(GL_TRIANGLES, 18, GL_UNSIGNED_BYTE, indices);

    ….
      glDisableClientState(GL_VERTEX_ARRAY);
      glDisableClientState(GL_TEXTURE_COORD_ARRAY);
    }
    ```

1.  在`jni`文件夹下添加`Android.mk`文件，内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := DiceG1
    LOCAL_SRC_FILES := Cube.cpp DiceG1.cpp
    LOCAL_LDLIBS := -lGLESv1_CM -llog -ljnigraphics
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  构建 Android NDK 应用程序并在 Android 设备上运行。该应用将显示一个纹理为骰子的立方体：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_04_10_new.jpg)

## 工作原理...

这个配方给 3D 立方体添加了一个纹理，使其看起来像骰子。

+   **纹理坐标**：纹理通常是 2D 图像。纹理坐标`(s, t)`通常被归一化到`[0.0, 1.0]`，如下图所示。纹理图像在`s`和`t`轴上被映射到`[0, 1]`：![工作原理...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_04_12.jpg)

+   **加载纹理**：在 OpenGL ES 中映射纹理的第一步是加载它们。在我们的示例中，我们使用 Android SDK 从可绘制资源中读取图像文件，并将位图传递给本地代码。本地方法`naLoadTexture`锁定位图图像并执行以下 OpenGL 操作。

    +   **创建 glGenTexture 纹理**：这生成纹理 ID。

    +   绑定纹理：glBindTexture。这告诉 OpenGL 我们要使用的纹理 id。

    +   **设置纹理过滤**：使用`glTexParameter`与`GL_TEXTURE_MIN_FILTER`或`GL_TEXTURE_MAG_FILTER`（这将在后面讨论）。

    +   **设置纹理包装**：使用`glTexParameter`与`GL_TEXTURE_WRAP_S`或`GL_TEXTURE_WRAP_T`（这将在后面讨论）。

    +   **将图像数据加载到 OpenGL 中**：（`glTexImage2D`）我们需要指定图像数据、宽度、高度、颜色格式等。

+   **纹理包装**：纹理在`s`和`t`轴上被映射到`[0, 1]`。但是，我们可以指定超出范围的纹理坐标。一旦发生这种情况，将应用包装。典型的纹理包装设置如下：

    +   `GL_CLAMP`：将纹理坐标限制在`[0.0, 1.0]`。

    +   `GL_REPEAT`：重复纹理。这创建了一个重复的模式。

+   **纹理过滤**：通常纹理图像的分辨率与对象不同。如果纹理较小，则会进行放大处理；如果纹理较大，则会进行缩小处理。通常使用以下两种方法：

    +   `GL_NEAREST`：使用与被纹理化的像素中心最近的纹理元素。

    +   `GL_LINEAR`：对基于与被纹理化的像素最近的四个纹理元素进行插值计算颜色值。

+   **设置纹理环境**：在我们将纹理映射到对象之前，可以调用 `glTexEnvf` 来控制当片段被纹理化时如何解释纹理值。我们可以配置 `GL_TEXTURE_ENV_COLOR` 和 `GL_TEXTURE_ENV_MODE`。在我们的示例项目中，我们使用了 `GL_REPLACE` 作为 `GL_TEXTURE_ENV_MODE`，这简单地将立方体片段替换为纹理值。

+   **映射纹理**：我们绘制 3D 立方体的每个面并通过 `glDrawElement` 映射纹理。必须通过调用 `glEnableClientState` 启用 `GL_TEXTURE_COORD_ARRAY`。在绘制每个接口之前，我们通过调用 `glBindTexture` 绑定到相应的纹理。

## 还有更多...

在我们的本地代码中，我们使用了 Android 本地位图 API 从 Java 代码接收纹理位图对象。这个 API 的更多细节将在第七章，*其他 Android NDK API*中进行介绍。

# 使用 OpenGL ES 2.0 API 绘制 3D 图形

前面的食谱描述了在 Android NDK 上的 OpenGL ES 1.x。这个食谱涵盖了如何在 Android NDK 中使用 OpenGL ES 2.0。

## 准备就绪

建议读者在阅读这个食谱之前先阅读本章的介绍。在以下食谱中涵盖了大量的图形基础；建议我们首先阅读它们：

+   *使用 OpenGL ES 1.x API 绘制 2D 图形和应用变换*

+   *使用 OpenGL ES 1.x API 绘制 3D 图形并照亮场景*

## 如何操作...

以下步骤使用 Android NDK 中的 OpenGL ES 2.0 API 创建一个渲染 3D 立方体的 Android 项目：

1.  创建一个名为 `CubeG2` 的 Android 应用程序。将包名设置为 `cookbook.chapter4.cubeg2`。如果你需要更详细的说明，请参考第二章的*加载本地库和注册本地方法*一节，*Java Native Interface*。

1.  在项目 `CubeG2` 上右键点击，选择 **Android Tools** | **添加本地支持**。

1.  添加三个 Java 文件，分别为 `MyActivity.java`，`MyRenderer.java` 和 `MySurfaceView.java`。我们只列出了部分 `MyRenderer.java` 代码，因为其他两个文件 `MyActivity.java` 和 `MySurfaceView.java` 与前一个食谱中的文件相似：

    ```kt
    @Override
    public void onSurfaceCreated(GL10 gl, EGLConfig config) {
        String vertexShaderStr = LoadShaderStr(mContext, R.raw.vshader);
        String fragmentShaderStr = LoadShaderStr(mContext, R.raw.fshader);
        naInitGL20(vertexShaderStr, fragmentShaderStr);
    }
    @Override
    public void onDrawFrame(GL10 gl) {
      naDrawGraphics(mAngleX, mAngleY);
    }
    @Override
    public void onSurfaceChanged(GL10 gl, int width, int height) {
      naSurfaceChanged(width, height);
    }
    ```

1.  在 `jni` 文件夹下添加 `Cube.cpp`，`matrix.cpp`，`CubeG2.cpp`，`Cube.h`，`matrix.h` 和 `mylog.h` 文件。文件内容总结如下：

    +   **Cube.cpp 和 Cube.h**：它们定义了一个 `Cube` 对象和方法来绘制 3D 立方体。

    +   **matrix.cpp 和 matrix.h**：这些矩阵操作，包括创建平移、缩放和旋转矩阵以及矩阵乘法。

    +   **CubeG2.cpp**：它们创建并加载着色器。它们还创建、链接并使用程序，并对 3D 立方体应用变换。

    +   **mylog.h**：它们定义了用于 Android NDK 日志记录的宏。

    在这里，我们列出了 `Cube.cpp` 和 `CubeG2.cpp` 的部分内容。

    `Cube.cpp`：

    ```kt
    …
    void Cube::draw(GLuint pvPositionHandle) {
      glVertexAttribPointer(pvPositionHandle, 3, GL_FLOAT, GL_FALSE, 0, vertices);
      glEnableVertexAttribArray(pvPositionHandle);
      glDrawArrays(GL_TRIANGLES, 0, 36);
    }
    ...
    ```

    `CubeG2.cpp`：它包含了 `loadShader`，`createProgram`，`naInitGL20` 和 `naDrawGraphics` 方法，下面将进行解释：

    +   `loadShader`：这个方法创建一个着色器，附加源代码，并编译着色器：

        ```kt
        GLuint loadShader(GLenum shaderType, const char* pSource) {
           GLuint shader = glCreateShader(shaderType);
           if (shader) {
               glShaderSource(shader, 1, &pSource, NULL);
               glCompileShader(shader);
               GLint compiled = 0;
               glGetShaderiv(shader, GL_COMPILE_STATUS, &compiled);
               if (!compiled) {
                   GLint infoLen = 0;
                   glGetShaderiv(shader, GL_INFO_LOG_LENGTH, &infoLen);
                   if (infoLen) {
                       char* buf = (char*) malloc(infoLen);
                       if (buf) {
                           glGetShaderInfoLog(shader, infoLen, NULL, buf);
                           free(buf);
                       }
                       glDeleteShader(shader);
                       shader = 0;
                   }
               }
           }
           return shader;
        }
        ```

    +   `createProgram`：这个方法创建一个程序对象，附加着色器，并链接程序：

        ```kt
        GLuint createProgram(const char* pVertexSource, const char* pFragmentSource) {
           GLuint vertexShader = loadShader(GL_VERTEX_SHADER, pVertexSource);
           GLuint pixelShader = loadShader(GL_FRAGMENT_SHADER, pFragmentSource);
           GLuint program = glCreateProgram();
           if (program) {
               glAttachShader(program, vertexShader);
               glAttachShader(program, pixelShader);
               glLinkProgram(program);
           }
           return program;
        }
        ```

    +   `naInitGL20`：这个方法设置 OpenGL ES 2.0 环境，获取着色器源字符串，以及获取着色器属性和统一变量的位置：

        ```kt
        void naInitGL20(JNIEnv* env, jclass clazz, jstring vertexShaderStr, jstring fragmentShaderStr) {
          glDisable(GL_DITHER);  
          glClearColor(0.0f, 0.0f, 0.0f, 1.0f);  
        glClearDepthf(1.0f);  
          glEnable(GL_DEPTH_TEST);  
          glDepthFunc(GL_LEQUAL);    
            const char *vertexStr, *fragmentStr;
          vertexStr = env->GetStringUTFChars(vertexShaderStr, NULL);
          fragmentStr = env->GetStringUTFChars(fragmentShaderStr, NULL);
          setupShaders(vertexStr, fragmentStr);
          env->ReleaseStringUTFChars(vertexShaderStr, vertexStr);
          env->ReleaseStringUTFChars(fragmentShaderStr, fragmentStr);
          gvPositionHandle = glGetAttribLocation(gProgram, "vPosition");
          gmvP = glGetUniformLocation(gProgram, "mvp");

        }
        ```

    +   `naDrawGraphics`：这个方法应用模型变换（旋转、缩放和平移）和投影变换：

        ```kt
        void naDrawGraphics(JNIEnv* env, jclass clazz, float pAngleX, float pAngleY) {
          glClear(GL_COLOR_BUFFER_BIT | GL_DEPTH_BUFFER_BIT);
          glClearColor(0.0, 0.0, 0.0, 1.0f);
          glUseProgram(gProgram);
        //  GL1x: glRotatef(pAngleX, 0, 1, 0);  //rotate around y-axis
        //  GL1x: glRotatef(pAngleY, 1, 0, 0);  //rotate around x-axis
          //rotate
          rotate_matrix(pAngleX, 0.0, 1.0, 0.0, aRotate);
          rotate_matrix(pAngleY, 1.0, 0.0, 0.0, aModelView);
          multiply_matrix(aRotate, aModelView, aModelView);
        //  GL1x: glScalef(0.3f, 0.3f, 0.3f);      // Scale down
          scale_matrix(0.5, 0.5, 0.5, aScale);
          multiply_matrix(aScale, aModelView, aModelView);
        // GL1x: glTranslate(0.0f, 0.0f, -3.5f);
          translate_matrix(0.0f, 0.0f, -3.5f, aTranslate);
          multiply_matrix(aTranslate, aModelView, aModelView);
        //  gluPerspective(45, aspect, 0.1, 100);
          perspective_matrix(45.0, (float)gWidth/(float)gHeight, 0.1, 100.0, aPerspective);
          multiply_matrix(aPerspective, aModelView, aMVP);
          glUniformMatrix4fv(gmvP, 1, GL_FALSE, aMVP);
          mCube.draw(gvPositionHandle);
        }
        ```

1.  在 `res` 文件夹下创建一个名为 `raw` 的文件夹，并向其中添加以下两个文件：

    +   `vshader`：这是顶点着色器的源代码：

        ```kt
        attribute vec4 vPosition;
        uniform mat4 mvp;
        void main() 
        {
           gl_Position = mvp * vPosition;
        }
        ```

    +   `fshader`：这是片段着色器的源代码：

        ```kt
        void main()
        {
           gl_FragColor = vec4(0.0,0.5,0.0,1.0);
        }
        ```

1.  在 `jni` 文件夹下添加 `Android.mk` 文件，如下所示。注意，我们必须通过 `LOCAL_LDLIBS := -lGLESv2` 链接到 OpenGL ES 2.0：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE    := CubeG2
    LOCAL_SRC_FILES := matrix.cpp Cube.cpp CubeG2.cpp
    LOCAL_LDLIBS := -lGLESv2 -llog
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  在 `AndroidManifest.xml` 文件中的 `<application>...</application>` 之前添加以下行，表示安卓应用使用 OpenGL ES 2.0 功能：

    ```kt
    <uses-feature android:glEsVersion="0x00020000" android:required="true" />
    ```

1.  构建安卓 NDK 应用程序并在安卓设备上运行。该应用将显示一个立方体，我们可以触摸以旋转立方体：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_04_13_new.jpg)

## 它是如何工作的...

示例项目使用 OpenGL ES 2.0 渲染了一个 3D 立方体。OpenGL ES 2.0 提供了一个可编程管线，可以提供顶点着色器和片段着色器来控制顶点和片段的处理方式：

+   **顶点着色器**：它对每个顶点执行。通常使用它进行变换、光照、纹理映射等。

+   **片段着色器**：它对光栅化器产生的每个片段执行。一个典型的处理是向每个片段添加颜色。

着色器是使用 OpenGL 着色语言编程的，下面将讨论这一点。

### OpenGL 着色语言（GLSL）

在此，我们简要介绍 GLSL。

+   **数据类型**：它们主要有四种类型，包括 `bool`、`int`、`float` 和 `sampler`。对于前三种类型还有向量类型——`bvec2`、`bvec3`、`bvec4` 分别指 2D、3D 和 4D 布尔向量。`ivec2`、`ivec3` 和 `ivec4` 代表整数向量。`vec2`、`vec3` 和 `vec4` 指浮点向量。**采样器**用于纹理采样，必须是统一变量。

+   **属性、统一变量和着色器间变量**：着色器包括三种输入和输出类型，包括统一变量、属性和着色器间变量。这三种类型都必须是全局的：

    +   **统一变量**：它是只读类型的，在渲染过程中不需要更改。例如，光源位置。

    +   **属性**：它是只读类型的，仅作为顶点着色器的输入。它对每个顶点都不同。例如，顶点位置。

    +   **着色器间变量**：它用于将数据从顶点着色器传递到片段着色器。在顶点着色器中它是可读可写的，但在片段着色器中仅可读。

+   **内置类型**：GLSL 有各种内置的属性、统一变量和着色器间的变量。以下我们突出介绍其中的一些：

    +   `gl_Vertex`：它是一个属性——一个表示顶点位置的 4D 向量。 

    +   `gl_Color`：这是一个属性——表示顶点颜色的 4D 向量。

    +   `gl_ModelViewMatrix`：这是一个统一变量——4x4 的模型视图矩阵。

    +   `gl_ModelViewProjectionMatrix`：这是一个统一变量。4x4 的模型视图投影矩阵。

    +   `gl_Position`：它仅作为顶点着色器输出可用。它是一个 4D 向量，表示最终处理的顶点位置。

    +   `gl_FragColor`：它仅作为片段着色器输出可用。它是一个 4D 向量，表示最终要写入帧缓冲区的颜色。

### 如何使用着色器：

在我们的示例项目中，顶点着色器程序简单地将每个立方体顶点与模型视图投影矩阵相乘，而片段着色器将每个片段设置为绿色。要使用着色器源代码，应遵循以下步骤：

1.  **创建着色器**：调用了以下 OpenGL ES 2.0 方法：

    +   `glCreateShader`：它创建一个`GL_VERTEX_SHADER`或`GL_FRAGMENT_SHADER`着色器。它返回一个非零值，通过这个值可以引用着色器。

    +   `glShaderSource`：它将源代码放入着色器对象中。之前存储的源代码将被完全替换。

    +   `glCompileShader`：它编译着色器对象中的源代码。

1.  **创建程序并附加着色器**：调用了以下方法：

    +   `glCreateProgram`：它创建一个空的程序对象，可以向其附加着色器。程序对象本质上是提供一种机制，将所有需要一起执行的内容链接起来。

    +   `glAttachShader`：它将着色器附加到程序对象上。

    +   `glLinkProgram`：它链接一个程序对象。如果程序对象附加了任何`GL_VERTEX_SHADER`对象，它们将被用来在顶点处理器上创建一个可执行文件。如果附加了任何`GL_FRAGMENT_SHADER`着色器，它们将被用来在片段处理器上创建一个可执行文件。

1.  **使用程序**：我们使用以下调用向着色器传递数据并执行 OpenGL 操作：

    +   `glUseProgram`：将程序对象作为当前渲染状态的一部分安装。

    +   `glGetAttribLocation`：它返回一个属性变量的位置。

    +   `glVertexAttribPointer`：它指定了在渲染时要使用的通用顶点属性数组的存储位置和数据格式。

    +   `glEnableVertexAttribArray`：它启用一个顶点属性数组。

    +   `glGetUniformLocation`：它返回一个统一变量的位置。

    +   `glUniform`：它指定一个统一变量的值。

    +   `glDrawArrays`：它从数组数据中渲染图元。

## 还有更多...

示例项目通过**矩阵操作**执行模型视图变换和投影变换。这些变换的细节很繁琐，不在本书的讨论范围内，因此这里不予介绍。但是，代码中提供了详细的注释。感兴趣的读者也可以轻松地在网上找到这些操作的资源。

# 使用 EGL 显示图形

除了我们在上一个配方中描述的 `GLSurfaceView` 显示机制外，还可以使用 EGL 显示 OpenGL 图形。

## 准备就绪

建议读者在阅读本节之前先阅读 *使用 OpenGL ES 1.x API 绘制 3D 图形和点亮场景* 的配方。

## 如何操作...

以下步骤描述了如何创建一个演示 EGL 用法的 Android 项目：

1.  创建一个名为 `EGLDemo` 的 Android 应用程序。将包名设置为 `cookbook.chapter4.egl`。如果你需要更详细的说明，请参考 第二章 *Java Native Interface* 中的 *加载本地库和注册本地方法* 配方。

1.  在项目 `EGLDemo` 上右键点击，选择 **Android Tools** | **添加本地支持**。

1.  添加两个 Java 文件，分别是 `EGLDemoActivity.java` 和 `MySurfaceView.java`。`EGLDemoActivity.java` 将 `ContentView` 设置为 `MySurfaceView` 的实例，并在 Android 活动回调函数中开始和停止渲染：

    ```kt
    … …
    public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    myView = new MySurfaceView(this);
    this.setContentView(myView);
    }
    protected void onResume() {
    super.onResume();
    myView.startRenderer();
    }
    … …
    protected void onStop() {
    super.onStop();
    myView.destroyRender();
    }
    … …
    ```

1.  `MySurfaceView.java` 执行的角色类似于 `GLSurfaceView`。它与本地渲染器交互来管理显示表面和处理触摸事件：

    ```kt
    public class MySurfaceView extends SurfaceView implements SurfaceHolder.Callback {
    … …
    public MySurfaceView(Context context) {
    super(context);
    this.getHolder().addCallback(this);
    }
    … …
    public boolean onTouchEvent(final MotionEvent event) {
    float x = event.getX();
    float y = event.getY();
    switch (event.getAction()) {
    case MotionEvent.ACTION_MOVE:
        float dx = x - mPreviousX;
        float dy = y - mPreviousY;
        mAngleX += dx * TOUCH_SCALE_FACTOR;
        mAngleY += dy * TOUCH_SCALE_FACTOR;
        naRequestRenderer(mAngleX, mAngleY);
    }
    mPreviousX = x;
    mPreviousY = y;
    return true;
    }
    @Override
    public void surfaceChanged(SurfaceHolder holder, int format, int width,int height) {
    naSurfaceChanged(holder.getSurface());
    }
    @Override
    public void surfaceCreated(SurfaceHolder holder) {}
    @Override
    public void surfaceDestroyed(SurfaceHolder holder) {
    naSurfaceDestroyed();
    }
    }
    ```

1.  以下代码应添加到 `jni` 文件夹中：

    +   **Cube.cpp 和 Cube.h**：使用 OpenGL 1.x API 绘制 3D 立方体。

    +   **OldRenderMethods.cpp 和 OldRenderMethods.h**：初始化 OpenGL 1.x，执行变换，绘制图形等。这类似于 *在 OpenGL 1.x 中绘制 3D 图形* 配方中的相应方法。

    +   **Renderer.cpp 和 Renderer.h**：模拟 `android.opengl.GLSurfaceView.Renderer`。它设置 EGL 上下文，管理显示等。

    +   `renderAFrame`：设置事件类型，然后通知渲染线程处理事件：

        ```kt
        void Renderer::renderAFrame(float pAngleX, float pAngleY) {
        pthread_mutex_lock(&mMutex);
        mAngleX = pAngleX; mAngleY = pAngleY;
        mRendererEvent = RTE_DRAW_FRAME;
        pthread_mutex_unlock(&mMutex);
        pthread_cond_signal(&mCondVar); 
        }
        ```

    +   `renderThreadRun`：在一个单独的线程中运行，处理各种事件，包括表面更改、绘制一帧等：

        ```kt
        void Renderer::renderThreadRun() {
            bool ifRendering = true;
            while (ifRendering) {
                pthread_mutex_lock(&mMutex);
                pthread_cond_wait(&mCondVar, &mMutex);
                switch (mRendererEvent) {
                … …
                    case RTE_DRAW_FRAME:
                        mRendererEvent = RTE_NONE;
                        pthread_mutex_unlock(&mMutex);
                        if (EGL_NO_DISPLAY!=mDisplay) {
                    naDrawGraphics(mAngleX, mAngleY);
                    eglSwapBuffers(mDisplay, mSurface);
                    }
                        }
                        break;
                    ……
                }
        }
        }
        ```

    +   `initDisplay`：设置 EGL 上下文：

        ```kt
        bool Renderer::initDisplay() {
        const EGLint attribs[] = {
            EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
            EGL_BLUE_SIZE, 8,
            EGL_GREEN_SIZE, 8,
            EGL_RED_SIZE, 8,
            EGL_NONE};
        EGLint width, height, format;
        EGLint numConfigs;
        EGLConfig config;
        EGLSurface surface;
        EGLContext context;
        EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
        eglInitialize(display, 0, 0);
        eglChooseConfig(display, attribs, &config, 1, &numConfigs);
        eglGetConfigAttrib(display, config, EGL_NATIVE_VISUAL_ID, &format);
        ANativeWindow_setBuffersGeometry(mWindow, 0, 0, format);
        surface = eglCreateWindowSurface(display, config, mWindow, NULL);
        context = eglCreateContext(display, config, NULL, NULL);
        if (eglMakeCurrent(display, surface, surface, context) == EGL_FALSE) {
            return -1;
        }
        eglQuerySurface(display, surface, EGL_WIDTH, &width);
        eglQuerySurface(display, surface, EGL_HEIGHT, &height);
          … ...
        }
        ```

    +   `EGLDemo.cpp`：注册本地方法并包装本地代码。以下两个方法被使用：

        `naSurfaceChanged`：它获取与 Java `Surface` 对象关联的本地窗口，并初始化 EGL 和 OpenGL：

        ```kt
        void naSurfaceChanged(JNIEnv* env, jclass clazz, jobject pSurface) {
        gWindow = ANativeWindow_fromSurface(env, pSurface);
        gRenderer->initEGLAndOpenGL1x(gWindow);
        }
        ```

        `naRequestRenderer`：渲染一帧，由 `MySurfaceView` 中的 `touch` 事件处理程序调用：

        ```kt
        void naRequestRenderer(JNIEnv* env, jclass clazz, float pAngleX, float pAngleY) {
        gRenderer->renderAFrame(pAngleX, pAngleY);
        }
        ```

1.  在 `jni` 文件夹下添加 `Android.mk` 文件，内容如下：

    ```kt
    LOCAL_PATH := $(call my-dir)
    include $(CLEAR_VARS)
    LOCAL_MODULE := EGLDemo
    LOCAL_SRC_FILES := Cube.cpp OldRenderMethods.cpp Renderer.cpp EGLDemo.cpp
    LOCAL_LDLIBS := -llog -landroid -lEGL -lGLESv1_CM
    include $(BUILD_SHARED_LIBRARY)
    ```

1.  构建 Android NDK 应用程序并在 Android 设备上运行。应用程序将显示一个立方体，我们可以触摸它使其旋转：![如何操作...](https://github.com/OpenDocCN/freelearn-android-pt2-zh/raw/master/docs/andr-ndk-cb/img/1505_04_15_new.jpg)

## 它是如何工作的...

EGL 是 OpenGL ES 与底层本地窗口系统之间的接口。根据 Khronos EGL 网页（[`www.khronos.org/egl`](http://www.khronos.org/egl)）的说明，它处理包括 OpenGL ES 在内的其他 Khronos 2D 和 3D API 的图形上下文管理、表面绑定和渲染同步。

### 提示

**EGL**是一个在嵌入式系统中广泛使用的跨平台 API，包括 Android 和 iPhone（苹果实现的 EGL 称为**EAGL**）。许多桌面平台也支持 EGL。不同的实现可能不是 100%兼容，但通常 EGL 代码的移植工作不会很繁重。

以下步骤描述了如何设置和操作 EGL 及其与 OpenGL 的集成：

1.  **获取并初始化显示连接**：EGL 需要知道内容应该显示在哪里，因此我们将需要获取一个显示连接并初始化它。这是使用以下两个方法完成的：

    +   `eglGetDisplay`：它获取原生显示的 EGL 显示连接。如果输入参数是`EGL_DEFAULT_DISPLAY`，则返回默认显示连接。

    +   `eglInitialize`：它初始化通过`eglGetDisplay`获取的 EGL 显示连接。

1.  **配置 EGL**：这是通过`eglChooseConfig`完成的。

    `eglChooseConfig`返回与`attrib_list`参数指定的要求相匹配的 EGL 帧缓冲区配置列表。属性是一个属性和相应期望值对的数组，以`EGL_NONE`结束。在我们的代码中，我们简单指定`EGL_SURFACE_TYPE`为`EGL_WINDOW_BIT`，颜色组件大小为 8 位。

1.  **创建一个渲染表面，用于放置显示内容**：这是通过`eglCreateWindowSurface`完成的。

    `eglCreateWindowSurface`，给定 EGL 显示连接、EGL 帧缓冲区配置和原生窗口，返回一个新的 EGL 窗口表面。

    在我们的代码中，我们从`SurfaceView`开始，并将其关联的`android.view.Surface`值传递给原生代码。在原生代码中，我们获取其原生窗口，并最终为 OpenGL 绘制创建 EGL 窗口表面。

1.  **创建 EGL 渲染上下文并将其设为当前**：这是通过`eglCreateContext`和`eglMakeCurrent`完成的。

    +   `eglCreateContext`：它创建一个新的 EGL 渲染上下文，用于渲染到 EGL 绘制表面。

    +   `eglMakeCurrent`：它将 EGL 上下文附加到 EGL 绘制和读取表面。在我们的代码中，创建的窗口表面被用作读取和绘制表面。

1.  **OpenGL 绘制**：这在前面的食谱中已经介绍过了。

1.  **交换 EGL 表面内部缓冲区以显示内容**：这是通过`eglSwapBuffers`调用完成的。

    `eglSwapBuffers`将 EGL 表面颜色缓冲区发布到原生窗口。这有效地在屏幕上显示绘制内容。

    EGL 内部维护两个缓冲区。前缓冲区的内容被显示，而绘制可以在后缓冲区进行。当我们决定显示新的绘制内容时，我们交换这两个缓冲区。

1.  当我们想要停止渲染时，释放 EGL 上下文，销毁 EGL 表面，终止 EGL 显示连接：

    +   使用`EGL_NO_SURFACE`和`EGL_NO_CONTEXT`的`eglMakeCurrent`释放当前上下文。

    +   `eglDestroySurface`销毁一个 EGL 表面。

    +   `eglTerminate` 终止了 EGL 显示连接

### 窗口管理

我们的代码使用 Android 原生窗口管理 API 调用来获取原生窗口并配置它。调用了以下方法：

+   `ANativeWindow_fromSurface`：它返回与 Java 表面对象关联的原生窗口。返回的引用应该传递给 `ANativeWindow_release`，以确保没有内存泄漏。

+   `ANativeWindow_setBuffersGeometry`：它设置窗口缓冲区的大小和格式。在我们的代码中，我们将宽度和高度指定为 `0`，在这种情况下，将使用窗口的基本值。

请注意，我们将在 `Android.mk` 文件中链接到 Android 库（`LOCAL_LDLIBS := -landroid`），因为它是 Android 原生应用程序 API 的一部分，我们将在下一章中详细介绍。

## 还有更多...

渲染器在一个单独的线程中运行事件循环。我们使用了**POSIX 线程**（`pthreads`）调用创建原生线程，将其与主线程同步等。我们将在第六章，*Android NDK Multithreading*中详细讲解 `pthread`。
