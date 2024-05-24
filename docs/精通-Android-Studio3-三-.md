# 精通 Android Studio3（三）

> 原文：[`zh.annas-archive.org/md5/9a1caf285755ef105f618b7b4d6fcfa9`](https://zh.annas-archive.org/md5/9a1caf285755ef105f618b7b4d6fcfa9)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：打包和分发

在应用程序开发过程中，编译和构建 APK 文件是我们做的很多次的事情，除了包含各种依赖项之外，我们基本上认为我们的构建自动化系统 Gradle 是理所当然的。尽管如此，读者不会忽视 Gradle 实际上所做的事情是非常复杂和复杂的。

我们可以认为 Gradle 是理所当然的原因之一是它使用一种称为**约定优于配置**的过程来配置每个构建。这确保在几乎所有情况下，Gradle 会为每个项目选择最明智的配置选项。只有当我们覆盖这些设置时，Gradle 才变得有趣和有用。例如，我们可以使用它从同一个 Studio 项目构建应用程序的移动和平板版本。

生成编译后的 APK 文件绝不是我们旅程的最后一步，因为我们仍然可以进行大量的测试和分析。Android Studio 的 APK 分析器极大地帮助了这些过程。

一旦我们的测试完成并且对我们的产品满意，我们将通过生成签名的 APK 文件进入旅程的最后阶段，准备发布。这一步并不是一个复杂的过程，Android Studio 会在每一步中帮助开发人员。

在本章中，您将了解以下内容：

+   了解构建过程

+   创建产品风味

+   从 Eclipse 导入 Gradle 构建

+   分析 APK 文件

+   清理项目

+   生成签名的 APK

+   注册 Google Play 应用签名

+   配置自动签名

# Gradle 构建配置

正如读者所见，Gradle 脚本通常有一个项目（或根）文件和一个或多个模块级别文件：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/ad24eb58-9eea-491f-b91c-c805c56bdaa7.png)

Gradle 脚本

我们被告知不要在根脚本的注释中编辑此文件；除非我们有所有模块通用的配置选项，否则最好保持不变。

模块级别的脚本对我们来说更有趣，以下是典型脚本的分解。

第一行只是声明了使用 Gradle 插件：

```kt
apply plugin: 'com.android.application'
```

接下来，声明了面向 Android 的 API 级别和构建工具版本：

```kt
android { 
    compileSdkVersion 27 
    buildToolsVersion "27.0.0" 
```

默认配置设置定义了 Android 清单文件的元素，并在此处编辑它们将在下一次构建或同步后自动反映在清单中，如下所示：

```kt
defaultConfig { 
     applicationId "com.example.someapp" 
     minSdkVersion 21 
     targetSdkVersion 27 
     versionCode 1 
     versionName "1.0" 
     testInstrumentationRunner 
         "android.support.test.runner.AndroidJUnitRunner" 
} 
```

构建类型部分配置了**ProGuard**，这是一个用于最小化和混淆我们代码的工具。

Proguard 对 APK 大小的影响通常可以忽略不计，但混淆的影响不容小觑，ProGuard 可以使我们的 APK 几乎不可能被反向工程。

`buildTypes`部分包含了在构建应用程序的发布版本时是否以及如何在 APK 文件上运行 ProGuard 的说明：

```kt
buildTypes { 
     release { 
         minifyEnabled false 
         proguardFiles 
             getDefaultProguardFile('proguard-android.txt'), 
             'proguard-rules.pro' 
        } 
    } 
} 

```

可以从`proguard.rules.pro`文件中编辑 ProGuard 规则，该文件覆盖默认规则，可以在`sdk\tools\proguard`中找到。

请注意，默认情况下`minifyEnabled`设置为`false`。这是一组非常有用的函数，可以剥离我们的代码中的冗余部分，通常会导致更小的 APK 文件，通常应该设置为`true`。

另外，添加`shrinkResources true`也是一个好主意，它对我们的资源文件执行类似的操作。

最后，我们将专注于依赖项部分，我们已经非常熟悉。在这里，模块的`lib`目录中的任何`.jar`文件都包括在内：

```kt
dependencies { 
    implementation fileTree(dir: 'libs', include: ['*.jar']) 
    androidTestImplementation('com.android.support 
        .test.espresso:espresso-core:2.2.2', { 
        exclude group: 'com.android.support', 
            module: 'support-annotations' 
    }) 
    implementation 'com.android.support: 
        appcompat-v7:26.0.0-beta2' 
    testImplementation 'junit: 
        junit:4.12' 
    implementation 'com.android.support.constraint: 
        constraint-layout:1.0.2' 
    implementation 'com.android.support: 
        design:26.0.0-beta2' 
} 
```

# 命令行选项

许多从其他 IDE 迁移的读者可能已经从命令行运行 Gradle 脚本，当然，在 Android Studio 中也可以这样做，尽管 Studio 将其很好地整合到工作区中，因此不需要退出 IDE 以这种方式执行命令。

有两个方便的工具窗口可以帮助我们完成这项任务，Gradle 工具窗口和 Gradle 控制台，两者都可以从“查看|工具窗口”菜单中找到。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/f5177500-9e53-4d8c-9dad-cec003e87ea2.png)

Gradle 工具窗口

前面截图中的分解提供了 Gradle 扮演的角色的概览，但要真正掌握它，我们需要通过一个简单的示例来工作，下一节将演示如何配置 Gradle 以从单个项目中生成不同的产品口味。

# 产品口味

一般来说，想要创建自定义版本或口味的应用有两个原因：

+   当我们为不同的形态版本创建版本，比如手机和平板电脑时

+   当我们希望在 Play 商店中有两个不同版本的应用可用时，比如付费版和免费版

这两种情况都可以通过配置我们的构建文件来解决，这可以针对`debug`和`release` APKs 都可以做。新的口味和构建类型都可以使用它们各自的对话框进行配置，这些对话框可以在 Build 菜单下找到：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/a41167aa-8237-4da8-8838-8a7968ea8d07.png)

构建选项

一如既往，最好亲自看看这些过程是如何运作的。在下面的示例中，我们将创建两个产品口味，代表应用的免费版和付费版。要遵循的步骤如下：

1.  在 Android Studio 中启动一个只有一个模块的新项目。

1.  在您的`values`文件夹中创建两个新目录，分别命名为`paid`和`free`。

1.  这些不会在 Android 标签下的资源管理器中可见，但可以通过切换到项目视图来找到。

通过在导航工具栏中选择`values`并从下拉菜单中选择`paid`或`free`，可以快速实现这一快捷方式。这将自动打开项目视图并展开以显示我们的新文件夹。

1.  按照以下方式创建两个合适的`strings.xml`文件：

```kt
<resources> 
    <string name="app_name">Product Flavors Pro</string> 
    <string name="version">Pro</string> 
</resources> 

<resources> 
    <string name="app_name">Product Flavors Free</string> 
    <string name="version">Free</string> 
</resources> 
```

1.  打开`build.gradle`文件，并像这样完成它：

```kt
apply plugin: 'com.android.application' 

android { 

    . . . 

    defaultConfig { 

        . . . 

        flavorSelection 'full', 'paid' 
        flavorSelection 'partial', 'free' 
    } 
    buildTypes { 
        release { 

            . . .  

        } 
    } 

    productFlavors { 
        flavorDimensions "partial", "full" 

        paid { 
            applicationId = "com.example.someapp.paid" 
            versionName = "1.0-paid" 
            dimension "full" 
        } 

        free { 
            applicationId = "com.example.someapp.free" 
            versionName = "1.0-free" 
            dimension "partial" 
        } 
    } 
} 

dependencies { 

    . . .  

} 
```

现在使用 Build Variants 工具窗口来选择随后构建的两种口味中的哪一种。

许多读者可能已经从 Eclipse IDE 迁移到 Android Studio。导入 Eclipse 项目相对简单，但导入 Gradle 构建文件则不那么简单。可以通过以下`build.gradle`根文件实现：

```kt
buildscript { 
    repositories { 
        mavenCentral() 
    } 
    dependencies { 
        classpath 'com.android.tools.build:gradle:3.0.0' 
    } 
} 
apply plugin: 'com.android.application' 

android { 
     lintOptions { 
          abortOnError false 
      } 

    compileSdkVersion 27 
    buildToolsVersion "27.0.0" 

        defaultConfig { 
            targetSdkVersion 27 
        } 

    sourceSets { 
        main { 
            manifest.srcFile 'AndroidManifest.xml' 
            java.srcDirs = ['src'] 
            resources.srcDirs = ['src'] 
            aidl.srcDirs = ['src'] 
            renderscript.srcDirs = ['src'] 
            res.srcDirs = ['res'] 
            assets.srcDirs = ['assets'] 
        } 

        debug.setRoot('build-types/debug') 
        release.setRoot('build-types/release') 
    } 
} 
```

能够创建不同版本的 APK 而无需创建单独的项目是一个很大的时间节省，Gradle 使这变得非常简单。然而，大多数情况下，我们可以让 Gradle 自行处理其工作。

诱人的想法是测试过程将随着 APK 的生成而完成。然而，Android Studio 提供了一个神奇的工具，允许我们分析已完成的 APK。

# APK 分析

APK 分析器是 Android Studio 最方便的功能之一；正如其名称所示，它允许我们分析 APK 文件本身，甚至通过提取资源和 XML 执行一定程度的逆向工程，并允许我们比较不同版本。

APK 分析器也可以在 Build 菜单下的 Analyze APK...中找到。每次在设备或模拟器上运行项目时，都会生成一个调试 APK。这可以在项目目录下找到；`\SomeProject\App\build\outputs\apk\debug`。

分析器显示其输出如下：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/ebd85fd2-29a0-43b2-bbd8-54962bea71ea.png)

APK 分析

分析器的输出包含大量信息，从其大小和压缩的 Play 商店大小开始。可以一目了然地看到哪些资源占用了最多的空间，并在可能的情况下进行修正，例如使用矢量图而不是位图。

`classes.dex`文件允许我们探索我们的类和导入库所消耗的内存。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/5a049f36-fdaf-4a1a-af39-148408a5eca1.png)

APK 类分析。

分析器最有用的功能之一是能够比较两个 APK 并排放在一起，可以使用窗口右上角的按钮实现这一点。

如果 APK 分析器不够用，那么主文件菜单中还有 Profile 或 Debug APK...的选项。这将打开一个新项目并解开 APK，以便完全探索甚至调试。

除了 MakeBuild 和 Analyze 之外，构建菜单还有其他有用的条目，例如，Clean Project 项目可以从构建目录中删除构建工件，如果我们想要与同事和合作者在互联网上共享。要进行更彻底的清理，可以使用本机文件浏览器在项目文件夹中打开命令提示符，或者从文件|工具窗口菜单中选择终端。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/1d4b4bf5-230e-4394-89d6-8db4bebe41c6.png)

以下命令将清理您的项目：

```kt
gradlew clean 
```

这个操作可以节省的空间通常是非常令人印象深刻的。当然，下次构建项目时，它将花费与第一次一样长的时间。

在开发周期的绝大部分时间里，我们只关心 APK 的调试版本，但迟早我们需要制作一个适合发布的 APK。

# 发布应用程序

开发移动应用，即使是相对简单的应用，也是一个漫长的过程，一旦我们测试了所有的代码，消除了任何问题，并完善了我们的用户界面，我们希望能够尽快简单地将我们的产品上架。Android Studio 将所有这些过程都纳入了工作空间。

正如读者所知，向发布迈出的第一步是生成已签名的 APK。

# 生成已签名的 APK

所有 Android 应用程序在安装到用户设备上之前都需要数字证书。这些证书遵循通常的模式，即在每次下载时都包含一个与我们自己的私钥对应的公钥。这个过程保证了用户的真实性，并防止其他人制作其他开发者作品的更新。

在开发过程中，IDE 会自动生成一个调试证书供我们使用，仅在开发过程中使用。这些证书可以在：`\SomeApp\build\outputs\apk\debug`中找到。

有两种方法可以创建这些身份证书：我们可以管理自己的密钥库，或者我们可以使用 Google Play 应用签名。我们现在将看看这两种技术，首先是自我管理。

# 管理密钥库

无论是我们自己管理密钥库还是由 Google 代表我们管理，流程都是一样的，如下面的步骤所示：

1.  单击构建菜单中的 Generate Signed APK...条目。

1.  完成以下对话，使用非常强大的密码。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/48d19670-92ad-4dc8-93ff-2bc41ac1add9.png)

生成已签名的 APK 对话框

1.  如果您正在创建新的密钥库，将会出现新密钥库对话框，必须按照以下方式完成：

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/cfc6f841-3586-4a48-9908-582af45e26d4.png)

新密钥库对话框

1.  最终对话框允许您选择构建类型和 APK 目标文件夹，以及您可能创建的任何版本。确保选择 V2（完整 APK 签名）框。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/a32fca8c-4899-4a10-91c8-93d8da0c3be3.png)

最终 APK 配置

1.  最终的 APK 将存储在`...\app\release\app-release.apk`中。

V2 签名版本的选择是一个重要的包含。在 API 级别 24（Android 7.0）中引入的 Signature Theme v2 提供更快的安装速度，并保护免受黑客逆向工程我们的 APK 的影响。不幸的是，它并不适用于所有版本，但是在适用时非常值得应用。

管理我们自己的密钥库通常是一直以来的做法，只要我们保持密钥的安全，这是一种完全可以接受的管理证书的方式。然而，使用 Google Play 进行应用签名提供了一些明显的优势，是值得考虑的。

# Google Play 应用签名

使用 Google Play 签署我们的应用程序的主要优势是，Google 会维护关键信息，如果不幸丢失，可以检索。关于这个系统非常重要的一点是，一旦采用，就**没有退出选项**。这是因为这本身可能代表着可能的安全漏洞。

要启用 Google Play 应用签名，请按照前面的步骤准备您的签名 APK，然后打开 Google 开发者控制台。从“发布管理”菜单中可以找到 Google Play 应用签名。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/b02ce0eb-3fc3-441f-9693-c1677224d947.png)

Google Play 应用签名

然后将打开服务条款对话框。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/8b567758-f2e9-4433-abc8-2c4d3244b5b3.png)

Google Play 应用签名服务条款

要注册 Google Play 应用签名服务条款，您需要按照这里概述的步骤进行操作：

1.  首先，使用**Play 加密私钥**（PEPK）工具对您的签名密钥进行加密，该工具可以从左侧导航栏中的控制台下载。

1.  创建第二个上传密钥并将其注册到 Google。

1.  使用此密钥对应用进行签名以发布并上传到 Google Play。

1.  然后，Google 使用此密钥对您进行身份验证，然后使用加密密钥对应用进行签名。

有关该过程的更多信息，请单击服务条款对话框上的“了解更多”。

只要我们愿意承诺自己，注册应用签名服务提供了比传统方法更安全的系统。然而，当我们决定签署我们的应用程序时，始终可以通过配置 Gradle 等方式更好地控制该过程。

# 自动签名

每次我们签署应用程序或变体时，都会为我们自动创建签名配置。幸运的是，这些配置可以根据我们的具体目的进行定制。例如，我们可能希望在每次构建时自动签署应用程序。Android Studio 通过“项目结构...”使这成为可能，该选项可以在主文件菜单中找到。

以下练习演示了如何自动签署应用程序的发布版本：

1.  打开项目结构对话框，如前所述，或者通过在项目资源管理器中选择模块的下拉菜单中的“打开模块设置”，或者选择模块并按*F4*。

1.  选择“签名”选项卡，单击“+”图标，并填写相应字段。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/ec8ec989-9da2-4158-a044-bdd17be9fe52.png)

签名配置

1.  接下来，打开“构建类型”选项卡，选择调试或发布类型，输入“签名配置”字段，如下图所示，并进行其他设置，例如启用缩小。

![](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/ms-as3/img/8686cf0b-0bf0-4982-aea9-6c4565c58794.png)

选择构建类型和签名配置

在发布之前还有一些其他准备工作要做。必须对发布 APK 进行更多测试，并收集各种促销资源和材料，但从 Android Studio 的角度来看，签名的发布 APK 几乎就是最终产品了。

# 摘要

签名 APK 的生成是一个漫长的过程的最后一步。每个应用程序从一个想法开始，经历了无数次的设计、开发和测试，最终被放置在 Android Play Store 等商店的货架上。

Android Studio 旨在在这一过程的每一步上帮助开发人员，而 Google 投入如此多的产品的原因之一是，通过投资未来的开发人员并使他们更容易将想法付诸实践，Android 平台只会变得更好。

在这本书中，我们探讨了专门为 Android 开发创建的唯一集成开发环境，并且我们看到了这种专业化的方法为开发者带来了许多好处。布局编辑器的视觉直观特性以及约束布局可以只需点击鼠标一两下就设计完成，这将让大多数开发者对仍在使用其他集成开发环境的人感到遗憾。

在 Android Studio 中，编码也变得不那么繁琐，它具有简单的代码补全和重构功能。再加上 Kotlin 作为官方开发语言的整合，选择 Android Studio 对许多移动开发者来说似乎是唯一的选择。甚至使用 Android Studio 编译和测试应用程序也可以更快更容易，当然，使用该集成开发环境为可穿戴设备和物联网等新颖形态进行开发也变得更加容易。

在整本书中，我们探讨了选择 Android Studio 3 的优势。这个集成开发环境当然还在不断发展，毫无疑问，作为谷歌认真投入的项目，它将在未来多年持续增长和改进。在许多方面，Android Studio 3 只是一个开始，希望这本书能帮助读者掌握这段旅程中的一小步。
