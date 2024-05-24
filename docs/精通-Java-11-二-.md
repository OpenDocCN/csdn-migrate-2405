# 精通 Java 11（二）

> 原文：[Mastering Java 11](https://libgen.rs/book/index.php?md5=550A7DE63D6FA28E9423A226A5BBE759)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 五、将应用迁移到 Java11

在前一章中，我们仔细研究了项目 Jigsaw 指定的 Java 模块的结构，并研究了如何实现项目 Jigsaw 来改进 Java 平台。我们还回顾了 Java 平台的关键内部更改，并特别关注新的模块化系统。我们从一个模块化入门开始，在这里我们了解了 Java 的模块化系统的好处和需求。接下来，我们将探讨 JDK 的模块化，包括如何重新组织源代码。我们还研究了 JDK 的七个主要工具类别，并了解到 Java 模块化扩展到运行时映像，从而提高了可维护性、更好的性能和提高了安全性。引入**链路时间**的概念，作为编译时间与运行时之间的可选阶段。我们在结束这一章时，将介绍 Java 链接器以及 Java 如何封装内部 API。

在本章中，我们将探讨如何将现有的应用迁移到当前的 Java 平台。我们将研究手动和半自动迁移过程。本章旨在为您提供一些见解和过程，使您的非模块化 Java 代码能够在当前的 Java 平台上工作。

我们将在本章讨论的主题如下：

*   Jigsaw 项目快速回顾
*   模块如何适应 Java 环境
*   迁移规划
*   Oracle 的建议
*   部署
*   有用的工具

# 技术要求

本章及后续章节介绍 Java11。Java 平台的**标准版**（**SE**）可从 [Oracle 官方下载网站](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。

一个**集成开发环境**（**IDE**）包就足够了。来自 JetBrains 的 IntelliJ IDEA 用于与本章和后续章节相关的所有编码。IntelliJ IDEA 的社区版可从[网站](https://www.jetbrains.com/idea/features/)下载。

本章的源代码可以在 [GitHub 的 URL](https://github.com/PacktPublishing/Mastering-Java-11-Second-Edition) 上找到。

# Jigsaw 项目快速回顾

Jigsaw 项目是一个 Java 项目，它包含了对 Java 平台的几个更改建议。正如您在前面几章中所读到的，Java9 中对 Java 平台最重要的更改涉及到模块和模块化。转移到 Java 模块的计划是由 Jigsaw 项目推动的。对模块化的需求源于 Java 的两大挑战：

*   类路径
*   JDK 的整体性

接下来，我们将回顾这两个挑战，并了解如何使用当前的 Java 平台解决和克服它们。

# 类路径

在 Java9 之前，类路径是有问题的，也是开发人员痛苦的根源。这一点在众多的开发者论坛上表现得很明显，幸运的是，Oracle 对此给予了关注。下面是类路径可能有问题的几个实例；下面是两个主要的例子：

*   第一种情况涉及在开发计算机上有两个或多个版本的库。Java 系统以前处理这个问题的方式是不一致的。在类加载过程中使用了哪个库并不容易辨别。这导致了不希望的缺乏特异性，而没有足够的关于加载哪个库的细节
*   第二种情况是使用类加载器的最高级功能。通常情况下，这种类型的类加载器的使用会导致最多的错误和 bug。这些错误和 bug 并不总是很容易被发现，并且会给开发人员带来很多额外的工作。

在 Java9 之前，类路径几乎总是非常长的。在最近的一次演示中，Oracle 共享了一个包含 110 个 JAR 文件的类路径。这类笨拙的类路径很难检测到冲突，甚至很难确定是否缺少任何内容，如果缺少，可能缺少什么。将 Java 平台重新设想为一个模块化的系统使得这些类路径问题成为过去。

模块通过提供可靠的配置来解决 Java9 之前的类路径问题。

# JDK 的整体性

自 1995 年以来，Java 以一种令人印象深刻的方式不断发展，随着每一步的发展，JDK 都变得越来越大。与 Java8 一样，JDK 已经变得非常庞大。在 Java9 之前，由于 JDK 的整体性，存在一些问题，包括以下问题：

*   因为 JDK 太大了，它不适合非常小的设备。在一些开发部门，这就足够找到解决软件工程问题的非 Java 解决方案了
*   过大的 JDK 导致了浪费。在设备、网络和云上运行时，它在处理和内存方面是浪费的。这源于这样一个事实：即使只需要 JDK 的一小部分，也会加载整个 JDK
*   虽然 Java 平台在运行时有很好的性能，但是从负载和启动时间来看，启动性能还有很多需要改进的地方
*   大量的内部 API 也是一个难点。因为有太多的内部 API 存在并且被开发人员使用，所以系统很难进化
*   内部 API 的存在使得 JDK 很难实现安全性和可伸缩性。由于存在如此多的内部依赖关系，隔离安全性和可伸缩性问题是非常困难的。

解决 JDK 整体问题的答案是模块。Java9 引入了该模块及其自己的模块化系统。对平台的一个重大更新是只编译所需的模块，而不是编译整个 JDK。这一模块化系统涵盖了整个这本书。

模块通过提供强大的封装解决了 Java9JDK 之前的单片问题。

# 模块如何适应 Java 环境

如下图所示，包由类和接口组成，模块由包组成。模块是包的容器。这是 Java 模块化系统的基本前提，在一个非常高的层次上。重要的是将模块视为模块化系统的一部分，而不是简单地将其视为包之上的新抽象级别，如下图所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/c629e1eb-ffa3-4085-9e74-78d6c0fc1563.jpg)

所以，模块是 Java9 的新成员，正如您所料，它们需要声明才能使用。一个模块的声明包括它具有依赖关系的其他模块的名称。它还为其他依赖于它的模块导出包，模块化声明可以说是开始使用 Java 开发时需要解决的最重要的模块化问题。举个例子：

```java
module com.three19.irisScan {
  // modules that com.three19.irisScan depends upon
  requires com.three19.irisCore;
  requires com.three19.irisData;

  // export packages for other modules that are 
  // dependent upon com.three19.irisScan
  exports com.three19.irisScan.biometric;
}
```

在编程 Java 应用时，模块声明将被放置在`module-info.java`文件中。一旦这个文件完成，您只需运行 Java 编译器 Javac，生成`module-info.class`Java 类文件。您完成此任务的方式与当前将`.java`文件编译为`.class`文件的方式相同

您还可以创建模块化 JAR 文件，将您的`module-info.class`文件放在其根目录下，这代表了极大的灵活性。

接下来，让我们回顾一下有关 Java 模块的三个重要概念：

*   基本模块
*   可靠的配置
*   强封装

# 基本模块

Java 模块概念的核心是理解基本模块。在编程 Java 应用或移植使用旧版本 Java 编程的现有应用时，必须使用基本模块（`java.base`）。每个模块都需要`java.base`模块，因为它定义了关键的或基础的 Java 平台 API

以下是`java.base`模块的内容：

```java
module java.base {
  exports java.io;
  exports java.lang;
  exports java.lang.annotation;
  exports java.lang.invoke;
  exports java.lang.module;
  exports java.lang.ref;
  exports java.lang.reflect;
  exports java.math;
  exports java.net;
  exports java.net.spi;
  exports java.nio;
  exports java.nio.channels;
  exports java.nio.channels.spi;
  exports java.nio.charset;
  exports java.nio.charset.spi;
  exports java.nio.file;
  exports java.nio.file.attribute;
  exports java.nio.file.spi;
  exports java.security;
  exports java.security.aci;
  exports java.security.cert;
  exports java.security.interfaces;
  exports java.security.spec;
  exports java.text;
  exports java.text.spi;
  exports java.time;
  exports java.time.chrono;
  exports java.time.format;
  exports java.time.temporal;
  exports java.time.zone;
  exports java.util;
  exports java.util.concurrent;
  exports java.util.concurrent.atomic;
  exports java.util.concurrent.locks; 
  exports java.util.function;
  exports java.util.jar;
  exports java.util.regex;
  exports java.util.spi;
  exports java.util.stream;
  exports java.util.zip;
  exports java.crypto;
  exports java.crypto.interfaces;
  exports java.crytpo.spec;
  exports java.net;
  exports java.net,ssi;
  exports java.security.auth;
  exports java.security.auth.callbak;
  exports java.security.auth.login;
  exports java.security.auth.spi;
  exports java.security.auth.x500;
  exports java.security.cert;
}
```

如您所见，`java.base`模块不需要任何模块，它导出了许多包。将这些导出的列表放在手边是很有用的，这样当您开始使用 Java 平台创建应用时，就可以知道哪些是可用的。

您会注意到，在上一节中，我们没有在`com.three19.irisScan`模块的声明中包含所需的`java.base`：代码行。更新后的代码如下所示，现在包括所需的`java.base`代码行：

```java
module com.three19.irisScan {
  // modules that com.three19.irisScan depends upon
  requires java.base; // optional inclusion
  requires com.three19.irisCore;
  requires com.three19.irisData;

  // export packages for other modules that are 
  // dependent upon com.three19.irisScan
  exports com.three19.irisScan.biometric;
}
```

如果您没有在模块声明中包含所需的代码行`java.base`，Java 编译器将自动包含它。

# 可靠的配置

正如本章前面提到的，模块为我们的 Java 应用提供了可靠的配置，解决了 Java 平台早期版本中的类路径问题。

Java 读取和解释模块声明，使模块可读。这些可读模块允许 Java 平台确定是否有任何模块丢失，是否声明了重复的库，或者是否存在任何其他冲突。在 Java 版本 9、10 和 11 中，编译器或运行时将生成和输出非常特定的错误消息。以下是编译时错误的示例：

```java
src/com.three19.irisScan/module-info.java: error: module not found:
com.three19.irisScan
requires com.three19.irisCore;
```

下面是一个运行时错误的例子，如果没有找到模块`com.three19.isrisCore`，但是`com.three19.irisScan`应用需要该模块，则会发生该错误：

```java
Error occurred during initialization of VM java.lang.module.ResolutionException: Module com.three19.irisCore not found, required by com.three19.irisScan app
```

# 强封装

在本章前面，您已经了解到 Java 的强封装解决了整体 JDK 问题。

封装是 OOP 的核心概念，它保护对象不受外部代码的影响。**强**封装的特性是指封装的良好编程实现。

在 Java 中，封装是由`module-info.java`文件中的信息驱动的。这个文件中的信息让 Java 知道哪些模块依赖于其他模块，以及每个模块输出什么。这强调了确保我们的`moduleinfo-java`文件正确配置的重要性。在模块化之前，让我们看一个用标准 Java 代码编写的示例：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/d91ffa32-be4b-43c5-b60a-fb1867c325b5.png)

在前面的例子中，`com.three19.irisScan`模块有一个供内部使用的`irisScanner`包和一个`irisScanResult`类。如果`com.three19.access`应用试图导入并使用`irisScanResult`类，Java 编译器将产生以下错误消息：

```java
src/com.three19.access/com/three19/access/Main.java: error: irisScanResult is not accessible because package com.three19.irisScanner.internal is not exported private irisSanResult scan1 = new irisScanResult();
```

如果编译器没有捕捉到此错误（可能性很小），则会发生以下运行时错误：

```java
Exception in thread "main" java.lang.IllegalAccessError: class com.three19.access.Main (in module: com.three19.access) cannot access class com.three19.irisScanner.internal.irisScanResult (in module: com.three19.irisScan), com.three19.irisScanner.internal is not exported to com.three19.access.
```

详细的错误消息将使调试和故障排除更加容易。

# 迁移规划

如果您正在维护使用 Java8 或更早版本构建的 Java 应用，则应该考虑将应用更新到现代 Java 平台。由于 PostJava8 平台与早期版本有很大不同，因此迁移应用时需要有目的的方法。提前计划，考虑最可能遇到的问题是谨慎的。在我们研究这些问题之前，让我们在下一节测试一个简单的 Java 应用。

# 测试一个简单的 Java 应用

下面的代码由一个 Java 类组成，`GeneratePassword`。此类提示用户输入所需的密码长度，然后根据用户请求的长度生成密码。如果用户要求长度小于 8，则将使用默认长度 8。这段代码是用 Java SE 1.7 JRE 系统库编写的：

```java
/*
* This is a simple password generation app
*/

import java.util.Scanner;
public class GeneratePassword {

  public static void main(String[] args) {

  // passwordLength int set up to easily change the schema
  int passwordLength = 8; //default value
  Scanner in = new Scanner(System.in);
  System.out.println("How long would you like your password (min 8)?");

  int desiredLength;
  desiredLength = in.nextInt();

  // Test user input
  if (desiredLength >8) {
    passwordLength = desiredLength;
  }

  // Generate new password
  String newPassword = createNewPassword(passwordLength);

  // Prepare and provide output
  String output = "\nYour new " + passwordLength + "-character password 
  is: ";
  System.out.println(output + newPassword);
  }

  public static String createNewPassword(int lengthOfPassword) {
    // Start with an empty String
    String newPassword = "";
    // Populate password
    for (int i = 0; i < lengthOfPassword; i++) {
      newPassword = newPassword + 
        randomizeFromSet("aAbBcCdDeEfFgGhHiIjJkKlLmMnNoOpPqQrR
        sStTuUvVwWxXyYzZ0123456789+-*/?!@#$%");
    }
    return newPassword;
  }

  public static String randomizeFromSet(String characterSet) {
  int len = characterSet.length();
  int ran = (int)(len * Math.random());
  return characterSet.substring(ran, ran + 1);
  }
}
```

在下面的屏幕截图中，我们在运行 Java8 的 Mac 上测试了`GeneratePassword`应用。如您所见，我们首先查询 Java 以验证当前版本。在这个测试中，使用了 Java`1.8.0_121`。接下来，我们使用`javac`工具编译`GeneratePassword`Java 文件。最后，我们运行应用：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/449e6f07-52e1-4e66-88a4-16153d77be70.png)

从前面的测试中可以看到，`GeneratePassword.java`被成功编译，生成了`GeneratePassword.class`文件。应用是使用`java GeneratePassword`命令运行的。提示用户输入所需的密码长度，并输入了`32`。然后，应用成功地生成了一个 32 个字符的随机密码，并提供了相应的输出

这个测试证明了这个示例应用使用 JDK1.8 可以成功地工作。接下来，让我们使用 JDK10 测试相同的应用：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/101f88cf-d405-49ce-b2e7-02c368a01bf4.png)

如您所见，我们清楚地演示了 Java9 之前的应用有可能在 Java10 上成功运行，而无需进行任何修改。这是一个简单的案例研究，具有一个非常基本的 Java 程序。当然，这是最好的情况，不能假设。您需要测试应用，以确保它们在当前 Java 平台上按预期运行。

在下一节中，我们将回顾在使用新的 Java 平台测试 Java9 之前的应用时可能遇到的一些潜在问题。

# 潜在的迁移问题

本节介绍的潜在迁移问题包括直接访问 JRE、访问内部 API、访问内部 JAR、jarURL 废弃、扩展机制和 JDK 的模块化。让我们看看每一个潜在的迁移问题。

# JRE

创建 Java 的模块化系统使得开发工具和实用工具的数量和位置得到了一些简化。一个这样的例子是 JDK 对 JRE 的使用。在所有 Java9 之前的版本中，Java 平台都将 JDK 和 JRE 作为两个独立的组件包含在内。从 Java9 开始，这些组件已经组合在一起。这是一个重要的变化，开发人员应该非常清楚。如果您有一个专门指向 JRE 目录的应用，则需要进行更改以避免出现问题。JRE 内容如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/3ac2b50a-213b-487d-9196-e9926eda2abd.png)

# 访问内部 API

当前的 Java 平台封装了内部 API，以提高用 Java 编写的平台和应用的安全性。与以前版本的 Java 平台不同，用 Java9、10 或 11 编写的应用将不具有对 JDK 内部 API 的默认访问权限。Oracle 已经确定一些内部 API 是关键的，这些 API 仍然可以通过 JDK 模块访问。

上述关键 API（JDK 内部）如下所示：

*   `sun.misc`
*   `sun.misc.Unsafe`
*   `sun.reflect.Reflection`
*   `sun.reflect.ReflectionFactory.newConstrutorForSerialization`

如果您有实现任何`sun.*`或`com.sun.*`包的 pre-Java9 应用，那么将应用迁移到当前 Java 平台时可能会遇到问题。为了解决这个问题，您应该检查您的类文件以使用`sun.*`和`com.sun.*`包。或者，您可以使用 Java 依赖性分析工具`jdeps`来帮助确定您的 Java 程序是否对 JDK 内部 API 有任何依赖性。

`jdeps`工具是 Java 依赖性分析工具；它可以用来帮助确定 Java 程序是否对 JDK 内部 API 有任何依赖性。

# 访问内部 Jar

从版本 9 开始，Java 不允许访问内部 Jar，如`lib/ant-javax.jar`、`lib/dt.jar`和`lib`目录中列出的其他 Jar，如下所示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/cb3914b7-bbf3-4e0d-b0fb-8332a456c621.png)

这里需要注意的关键是，如果您的 Java 应用依赖于`lib`文件夹中的这些工具之一，那么您需要相应地修改代码。

建议您在开始使用 Java10 和 Java11 之后测试 IDE，以确保 IDE 得到更新并正式支持最新版本的 Java。如果您使用多个 IDE 进行 Java 开发，请测试每一个 IDE 以避免意外。

# JAR URL 废弃

JAR 文件 URL 在 Java9 之前被一些 API 用来标识运行时映像中的特定文件。这些 URL 包含一个带有两条路径的`jar:file:`前缀，一条路径指向`jar`，另一条路径指向`jar`中的特定资源文件。以下是 Java9 JAR 之前的 URL 的语法：

```java
jar:file:<path-to-jar>!<path-to-file-in-jar>
```

随着 Java 模块化系统的出现，容器将容纳资源文件，而不是单独的 JAR。访问资源文件的新语法如下：

```java
jrt:/<module-name>/<path-to-file-in-module>
```

一个新的 URL 模式`jrt`现在已经就位，用于命名运行时映像中的资源。这些资源包括类和模块。新的模式允许在不给运行时映像带来安全风险的情况下识别资源。这种增强的安全性确保运行时映像的形式和结构保持隐藏。新架构如下：

```java
jrt:/[$MODULE[/$PATH]]
```

有趣的是，`jrt`URL 的结构决定了它的含义，这表明该结构可以采用几种形式之一。以下是三个不同的`jrt`URL 结构示例：

*   `jrt:/$MODULE/$PATH`：此结构提供对`$MODULE`参数指定模块内的`$PATH`参数标识的资源文件的访问
*   `jrt:/$MODULE`：该结构可参照`$MODULE`参数指定模块内的所有资源文件
*   `jrt:/`：此结构提供对运行时映像中所有资源文件的引用

如果您已经存在使用 API 返回的 URL 实例的代码，那么您应该不会有任何问题。另一方面，如果您的代码依赖于`jar`URL 结构，则会出现问题。

# 扩展机制

Java 平台以前有一个扩展机制，使开发人员能够为所有应用提供定制 API。如下图所示，扩展是 Java 平台的插件或附加组件。默认情况下，每个扩展中的 API 和类都自动可用：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/58c14de5-53a4-475d-86a4-6c490cc40f7d.png)

如图所示，Java 应用可以访问 Java 平台和扩展，而不需要类路径。此功能在 Java8 中已被弃用，并且在当前版本的 Java 中不再存在。

# JDK 的模块化

到目前为止，您已经对 Java 的模块化有了明确的认识。Java 和另一种面向对象编程语言中的一句老话是*一切都是一个类*。现在，*一切都是一个模块*是一句新的格言。有三种类型的模块，如下所述：

| **模块类型** | **说明** |
| --- | --- |
| 自动 | 当一个 JAR 被放置在一个新的模块路径上时，就会自动创建模块。 |
| 显式/命名 | 这些模块是通过编辑`module-info.java`文件手动定义的。 |
| 未命名 | 当 JAR 被放置在类路径上时，将创建未命名的模块。 |

从 8 或更早版本迁移应用时，应用及其库将成为未命名的模块。因此，您需要确保所有模块都在模块路径中

另一件需要注意的是，运行时映像不会包含整个 JDK，相反，它只包含应用所需的模块。值得回顾一下 JDK 是如何在 Java 中模块化的。下表包含当前 JDK 的 API 规范：

| | | | |
| --- | --- | --- | --- |
| `jdk.accessibility` | `jdk.attach` | `jdk.charsets` | `jdk.compiler` |
| `jdk.crypto.cryptoki` | `jdk.crypto.ec` | `jdk.dynalink` | `jdk.editpad` |
| `jdk.hotspot.agent` | `jdk.httpserver` | `jdk.incubator.httpclient` | `jdk.jartool` |
| `jdk.javadoc` | `jdk.jcmd` | `jdk.jconsole` | `jdk.jdeps` |
| `jdk.jdi` | `jdk.jdwp.agent` | `jdk.jlink` | `jdk.jshell` |
| `jdk.jsobject` | `jdk.jstatd` | `jdk.localedata` | `jdk.management` |
| `jdk.management.agent` | `jdk.naming.dns` | `jdk.naming.rmi` | `jdk.net` |
| `jdk.pack` | `jdk.packager.services` | `jdk.policytool` | `jdk.rmic` |
| `jdk.scripting.nashorn` | `jdk.sctp` | `jdk.security.auth` | `jdk.security.jgss` |
| `jdk.snmp` | `jdk.xml.dom` | `jdk.zipfs` |  |

下表包含 Java SE 的 API 规范：

| | | | |
| --- | --- | --- | --- |
| `java.activation` | `java.base` | `java.compiler` | `java.corba` |
| `java.datatransfer` | `java.desktop` | `java.instrument` | `java.logging` |
| `java.management` | `java.management.rmi` | `java.naming` | `java.prefs` |
| `java.rmi` | `java.scripting` | `java.se` | `java.se.ee` |
| `java.security.jgss` | `java.security.sasl` | `java.sql` | `java.sql.rowset` |
| `java.transaction` | `java.xml` | `java.xml.bind` | `java.xml.crypto` |
| `java.xml.ws` | `java.xml.ws.annotation` |  |  |

记住，默认情况下，所有应用都可以访问模块路径中的`java.base`。

下表包含 Java 中 JavaFX 的 API 规范：

| | | | |
| --- | --- | --- | --- |
| `javafx.base` | `javafx.controls` | `javafx.fxml` | `javafx.graphics` |
| `javafx.media` | `javafx.swing` | `javafx.web` |  |

有两个附加模块：

*   `java.jnlp`定义 **JNLP** 的 API（简称 **Java 网络启动协议**）。
*   `java.smartcardio`定义 Java 智能卡输入/输出的 API。

有关这些模块的详细信息，请访问 Oracle 的 Java® 平台，[Java 标准版开发套件版本 10 API 规范网站](http://docs.oracle.com/javase/10/docs/api/overview-summary.html)。

# Oracle 的建议

Oracle 在不断更新 Java 平台方面做得很好，他们对从旧版本迁移到新 JDK 的见解值得回顾。在本节中，我们将介绍准备步骤、打破封装、对运行时映像的更改、已删除的工具和 API 等组件、对垃圾收集的更改以及部署。

# 准备步骤

Oracle 提供了一个五步流程，帮助开发人员将 Java 应用从 Java9 以前的版本迁移到现代版本 9、10 或 11。以下列出了这些步骤，随后的部分将介绍这些步骤：

1.  获取 JDK 早期访问构建
2.  重新编译前运行程序
3.  更新第三方库和工具
4.  编译应用
5.  在你的代码上运行`jdeps`

# 获取 JDK 早期访问构建

如果您是在 Java11（18.9）正式发布之前阅读本书，[那么您可以从以下链接获得 JDK11 早期访问构建](http://jdk.java.net/11/)。

早期版本可用于 Windows（32 和 64）、MacOS（64）、Linux（32 和 64）以及各种 Linux ARM、Solaris 和 Alpine Linux 版本。

在正式发布 Java11 之前花点时间测试 Java9 应用并迁移它们，这将有助于确保依赖于 Java 应用的服务不会出现任何停机。

您可以从以下链接下载版本 9 和 10：

*   <http://jdk.java.net/9/>
*   <http://jdk.java.net/10/>

# 重新编译前运行程序

如本章前面所述，您现有的 Java 应用有可能在 Java11 平台上运行而不进行修改。因此，在进行任何更改之前，请尝试在 Java9 平台上运行当前的应用。如果您的应用在 Java11 上运行得很好，那就太好了，但是您的工作还没有完成。回顾下面的三个部分：更新第三方库和工具、编译应用以及在代码上运行`jdeps`。

# 更新第三方库和工具

第三方库和工具可以帮助扩展我们的应用并缩短开发时间。对于 Java 兼容性，确保您使用的每个第三方库和工具都与 JDK 的最新版本兼容并支持它是很重要的。在 Java11 上运行应用并不能为您提供所需的洞察力级别，以确保您不会遇到兼容性问题。建议您查看每个库和工具的官方网站，以验证与 JDK18.9 的兼容性和支持。

如果您使用的库或工具的版本确实支持 JDK18.9，请下载并安装它。如果您发现一个还不支持 JDK18.9，请考虑找一个替代品。

在我们的上下文中，工具包括 IDE。NetBeans、Eclipse 和 IntelliJ 都有支持 JDK11 的 IDE 版本。这些网站的链接如下：

*   [**NetBeans**](http://bits.netbeans.org/download/trunk/nightly/latest/)
*   [**Eclipse**](http://www.eclipse.org/downloads/packages/release/oxygen/m2)
*   [**Intelij**](https://www.jetbrains.com/idea/download/#section=windows)

# 编译应用

下一步是使用 JDK 的`javac`编译应用。这一点很重要，即使您的应用可以很好地与最新的 JDK 配合使用。您可能不会收到编译器错误，但也要注意警告。以下是您的应用可能无法使用新 JDK 编译的最常见原因，假设它们在 Java9 之前编译良好。

首先，如本章前面所述，大多数 JDK 的内部 API 在默认情况下是不可访问的。您的指示将是运行时或编译时的`IllegalAccessErrors`错误。您需要更新代码，以便使用可访问的 API

Java9 之前的应用可能无法使用 JDK18.9 编译的第二个原因是，如果将下划线字符用作单个字符标识符。根据 Oracle 的说法，这种做法在 Java8 中生成警告，在 Java9、10 和 11 中生成错误。让我们看一个例子。下面的 Java 类实例化了一个名为`_`的`Object`，并向控制台输出一条单数消息：

```java
public class Underscore {
  public static void main(String[] args) {
    Object _ = new Object();
    System.out.println("This ran successfully.");
  }
}
```

当我们用 Java8 编译这个程序时，我们收到一个警告，在 Java SE 8 之后的版本中可能不支持使用`_`作为标识符：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/5061c9ec-024b-4633-82ab-79506b9257e8.png)

正如您在下面的屏幕截图中看到的，这只是一个警告，应用运行正常：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/341ac55f-8605-4e2e-a83b-c4231bf73ffc.png)

现在让我们尝试使用 JDK9 编译同一个类：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/7a3e7d9b-9d68-4c10-b74c-d54b7693bb63.png)

如您所见，使用下划线作为单个字符标识符仍然只会导致警告而不是错误。应用已成功运行。这个测试是在 JDK9 还处于早期版本时运行的。

在 Java10 和 Java11 中，使用`_`作为标识符是非法的。下面的屏幕截图显示了编译`Underscore.java`应用的尝试：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/cafb30ff-4504-4dcd-9788-03c54a6c6dcc.png)

您的预 Java9 编程应用不使用 JDK9、10 或 11 编译的第三个潜在原因是您使用的是`-source`和`-target`编译器选项。让我们看一下 Java9 之前和 Java10 之后的`-source`和`-target`编译器选项。

# Java9 之前的源和目标选项

`-source`选项指定 Java SE 版本，并具有以下可接受的值：

| **值** | **说明** |
| --- | --- |
| 1.3 | `javac`不支持 JavaSE1.3 之后引入的特性。 |
| 1.4 | `javac`接受具有 JavaSE1.4 中引入的语言特性的代码。 |
| 1.5 或 5 | `javac`接受具有 JavaSE1.5 中引入的语言特性的代码。 |
| 1.6 或 6 | `javac`将编码错误报告为错误而不是警告。值得注意的是，JavaSE1.6 没有引入新的语言特性。 |
| 1.7 或 7 | `javac`接受具有 JavaSE1.7 中引入的语言特性的代码。如果不使用`-source`选项，这是默认值。 |

`-target`选项告诉`javac`目标 JVM 的版本。`-target`选项的可接受值为：`1.1`、`1.2`、`1.3`、`1.4`、`1.5`或`5`、`1.6`或`6`和`1.7`或`7`。如果未使用`-target`选项，则默认 JVM 目标取决于与`-source`选项一起使用的值。以下是`-source`值及其相关`-target`的表格：

| `-source`**值** | **默认**`-target` |
| --- | --- |
| 未指明 | 1.7 |
| 1.2 | 1.4 |
| 1.3 | 1.4 |
| 1.4 | 1.4 |
| 1.5 或 5 | 1.7 |
| 1.6 或 6 | 1.7 |
| 1.7 | 1.7 |

# Java10 和 Java11 的源和目标选项

在 Java9 中，支持的值如下所示：

| **支持值** | **备注** |
| --- | --- |
| 11 | 当 JDK11 发布时，这很可能成为默认值。 |
| 10 | 从 JDK10 开始，这是默认值，不应指定任何值。 |
| 9 | 将支持设置为 1.9。 |
| 8 | 将“支持”设置为 1.8。 |
| 7 | 将支持设置为 1.7。 |
| 6 | 将 support 设置为 1.6，并生成一个警告（不是错误）来指示 JDK6 已废弃。 |

# 在代码上运行`jdeps`

`jdeps`类依赖性分析工具对 Java 来说并不新鲜，但对于开发人员来说，它可能从未像 Java 模块化系统的出现那样重要。将应用迁移到 Java9、10 或 11 的一个重要步骤是运行`jdeps`工具来确定应用及其库的依赖关系。如果您的代码依赖于任何内部 API，`jdeps`工具可以很好地建议替换。

以下屏幕截图显示了使用`jdeps`分析仪时可用的选项：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/81653006-7963-42e0-85e8-3187d1b14bf2.png)

当您使用`jdeps -help`命令时，您还会看到模块相关的分析选项、过滤依赖项的选项和过滤要分析的类的选项。

让我们看一个例子。下面是一个名为`DependencyTest`的简单 Java 类：

```java
import sun.misc.BASE64Encoder; 

public class DependencyTest {
  public static void main(String[] args) throws InstantiationException, 
    IllegalAccessException {
    BASE64Encoder.class.newInstance();
    System.out.println("This Java app ran successfully.");
  }
}
```

现在让我们使用`javac`使用 Java8 编译这个类：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/995554eb-8ba6-47c5-9272-0d38a8a4ea60.png)

如您所见，Java8 成功地编译了类并运行了应用。编译器确实给了我们一个警告。现在让我们看看当我们尝试使用 Java9 编译这个类时会发生什么：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/81066cdf-2703-412c-b6f6-c9e21202eb3e.png)

在本例中，对于 Java9，编译器给了我们两个警告，而不是一个。第一个警告针对`import sun.misc.BASE64Encoder`；语句，第二个警告针对`BASE64Encoder.class.newInstance()`；方法调用。如您所见，这些只是警告而不是错误，因此成功编译了`DependencyTest.java`类文件。

接下来，让我们运行应用：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/b4dc2327-b9f3-46dd-95d1-60d43e2de2be.png)

现在我们可以清楚地看到，Java9 将不允许我们运行应用。接下来，让我们使用`jdeps`分析器工具运行一个依赖性测试。我们将使用以下命令行语法-`jdeps DependencyTest.class`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/0149ecb1-e039-4ade-8d5e-ec3c0d12b93b.png)

如您所见，我们有三个依赖项：`java.io`、`java.lang`和`sun.misc`。在这里，我们建议用`rt.jar`替换我们的`sun.misc`依赖关系。

作为最后的测试，我们将尝试使用 Java10 编译`DependencyTest`：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/3c201148-e7cc-4aa4-a14d-ca23ec4813fc.png)

在这里，我们看到我们根本无法编译应用。JDK10 和 11 都提供了相同的错误。

# 破坏封装

当前的 Java 平台比以前的版本更安全，部分原因是模块化重组导致了封装的增加。也就是说，您可能需要突破模块化系统的封装。

正如您在本章前面所读到的，大多数内部 API 都是强封装的。如前所述，在更新源代码时，您可能会寻找替换 API。当然，这并不总是可行的。您可以在运行时使用`--add-opens`选项、使用`--add-exports`选项和`--permit-illegal-access`命令行选项来采取另外三种方法。让我们看看每一个选项。

# `--add-opens`选项

您可以使用`--add-opens`运行时选项来允许您的代码访问非公共成员。这可以称为**深反射**。进行这种深度反射的库能够访问所有成员，包括私有和公共。要授予这种类型的代码访问权限，可以使用`--add-opens`选项。语法如下：

```java
--add-opens <module>/<package>=<target-module>(,<target-module>)*
```

这允许给定的模块打开指定的包。使用此选项时，编译器不会产生任何错误或警告。

# `--add-exports`选项

您可以使用`--add-exports`来破坏封装，这样您就可以使用默认为不可访问的内部 API。语法如下：

```java
--add-exports <source-module>/<package>=<target-module>(,<target-module>)*
```

这个命令行选项允许`<target-module>`中的代码访问`<source-module>`包中的类型。

另一种破坏封装的方法是使用 JAR 文件的清单。举个例子：

```java
--add-exports:java.management/sun.management
```

只有在认为绝对必要的情况下才应使用`--add-exports`命令行选项。除短期解决方案外，不建议使用此选项。常规使用它的危险在于，对引用的内部 API 的任何更新都可能导致代码无法正常工作。

# `--permit-illegal-access`选项

打破封装的第三个选择是使用`--permit-illegal-access`选项。当然，谨慎的做法是与第三方库创建者核实是否有更新的版本。如果这不是一个选项，那么您可以使用`--permit-illegal-access`非法访问要在类路径上实现的操作。由于这里的操作非常非法，每次发生这些操作时，您都会收到警告。

# 运行时映像更改

在 JDK 和 JRE 方面，当前的 Java 与 Java8 和更早的版本有很大的不同。这些变化大多与模块化有关，并已在其他章节中介绍。还有一些事情你应该考虑。

# Java 版本模式

在 Java9 中，Java 平台版本的显示方式发生了变化。以下是 Java8 版本格式的示例：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/b20c7e9a-8ef1-474c-8998-2ab168283906.png)

现在让我们看看 Java9 是如何报告其版本的：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/f1eacb95-a8b3-4297-81ae-146768f2a64a.png)

如您所见，对于 Java9，版本模式是`$MAJOR.$MINOR.$SECURITY.$PATCH`。这与以前的 Java 版本有明显的不同。只有当您有解析由`java -version`命令和选项返回的字符串的代码时，这才会影响您的应用。

最后，让我们看看 Java10（18.3）如何报告其版本：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/70f59c64-ace3-41e1-9abd-f0098fda0299.png)

对于 Java10、11，在可预见的将来，版本模式是`$YY.$MM`。这是从 Java10 开始的变化。如果您有任何代码来计算由`java -version`命令和选项返回的内容，则可能需要更新代码。

# JDK 和 JRE 的布局

文件在 JDK 和 JRE 中的组织方式在 Java 的新版本中发生了变化。花时间熟悉新的文件系统布局是值得的。下面的屏幕截图显示了 JDK 的`/bin`文件夹的文件结构：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/61e2c6f8-f2ac-4f0f-9fd3-d43b67f37fcc.png)

以下是`\lib`文件夹的布局：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/c3623210-2036-4dae-9642-ff294244f9aa.png)

# 删除了什么？

Java 平台新版本的另一个变化是许多平台组件被删除。以下部分是最重要的组成部分。

值得注意的是，`rt.jar`和`tools.jar`以及`dt.jar`已经被移除。这些 JAR 文件包含类和其他资源文件，并且都位于`/lib`目录中。

已删除认可的标准覆盖机制。在 Java 中，如果检测到这个机制，`javac`和`java`都将退出。该机制用于应用服务器覆盖一些 JDK 组件。在 Java 中，可以使用可升级的模块来实现相同的结果。

如本章前面所述，*扩展机制*也已拆除。

以下列出的 API 以前已被废弃，已被删除，在当前 Java 平台中不可访问。删除这些 API 是 Java 平台模块化的结果：

*   `apple.applescript`
*   `com.apple.concurrent`
*   `com.sun.image.codec.jpeg`
*   `java.awt.dnd.peer`
*   `java.awt.peer`
*   `java.rmi.server.disableHttp`
*   `java.util.logging.LogManager.addPropertyChangeListener`
*   `java.util.logging.LogManager.removePropertyChangeListener`
*   `java.util.jar.Pack200.Packer.addPropertyChangeListener`
*   `java.util.jar.Pack200.Packer.removePropertyChangeListener`
*   `java.util.jar.Pack200.Unpacker.addPropertyChangeListener`
*   `java.util.jar.Pack200.Unpacker.removePropertyChangeListener`
*   `javax.management.remote.rmi.RMIIIOPServerImpl`
*   `sun.misc.BASE64Encoder`
*   `sun.misc.BASE64Decoder`
*   ``sun.rmi.transport.proxy.connectTimeout``
*   `sun.rmi.transport.proxy.eagerHttpFallback`
*   `sun.rmi.transport.proxy.logLevel`
*   `sun.rmi.transport.tcp.proxy`

下列列出的工具已被删除。在每种情况下，该工具以前都被贬低，或其功能被更好的替代品取代：

*   `hprof`
*   `java-rmi.cgi`
*   `java-rmi.exe`
*   `JavaDB`
*   `jhat`
*   `native2ascii`

Java 中删除的另外两个内容如下：

*   AppleScript 引擎。这台发动机被视为无法使用，未经更换就报废了。
*   Windows 32 位客户端虚拟机。JDK9 确实支持 32 位服务器 JVM，但不支持 32 位客户端 VM。这一变化的重点是提高 64 位系统的性能。

# 更新的垃圾收集

垃圾收集一直是 Java 声名鹊起的原因之一。在 Java9 中，**垃圾优先**（**G1**）垃圾收集器现在是 32 位和 64 位服务器上的默认垃圾收集器。在 Java8 中，默认的垃圾收集器是并行垃圾收集器。Oracle 报告说，有三种垃圾收集组合将禁止您的应用在 Java9 中启动。这些组合如下：

*   DefNew + CMS
*   增量 CMS
*   ParNew + SerialOld

我们将在第 7 章“利用默认的 G1 垃圾收集器”中深入了解 Java9 垃圾收集。

# 部署应用

在部署应用时，从 Java8 或更早版本迁移到当前 Java 平台时，有三个问题需要注意。这些问题包括 JRE 版本选择、序列化小程序和 JNLP 更新。

**JNLP** 是 **Java 网络启动协议**的首字母缩写，本章后面的部分将对此进行介绍。

# 选择 JRE 版本

在 Java9、10 和 11 之前，开发人员可以在启动应用时请求 JRE 版本，而不是正在启动的版本。这可以通过命令行选项或正确的 JAR 文件清单配置来实现。由于我们通常部署应用的方式，JDK9 中已经删除了这个特性。以下是三种主要方法：

*   活动安装程序
*   使用 JNLP 的 **Java Web Start** 
*   本机操作系统打包系统

# 序列化 Applet

Java 不再支持将 Applet 作为序列化对象进行部署。过去，Applet 被部署为序列化对象，以补偿压缩速度慢和 JVM 性能问题。在当前的 Java 平台上，压缩技术是先进的，JVM 具有良好的性能。

如果尝试将小程序部署为序列化对象，则在启动小程序时，对象属性和参数标记将被忽略。从 Java9 开始，您可以使用标准部署策略部署小程序。

# JNLP 更新

JNLP 用于使用 Web 服务器上的资源在桌面客户端上启动应用。JNLP 客户端包括 JavaWebStart 和 Java 插件软件，因为它们能够启动远程托管的 Applet。该协议有助于启动 RIA。

**RIAs**（简称**富互联网应用**），当使用 JNLP 启动时，可以访问各种 JNLP API，在用户许可的情况下，可以访问用户的桌面。

JNLP 规范在 Java9 中进行了更新。以下章节详细介绍了四个具体更新。

# 嵌套资源

以前支持将组件扩展与 Java 或 J2SE 元素中的嵌套资源一起使用，但规范中没有对此进行说明。规范现在已经更新以反映这种支持。先前的规范如下：

*不能将 Java 元素指定为资源的一部分。*

更新后的规范内容如下：

组件扩展中的 Java 元素不会控制所使用的 Java 版本，但可以使用包含嵌套资源元素的 Java 版本，并且只有在使用与第 4.6 节中指定的给定版本匹配的 Java 版本时，才可以使用这些资源。

这个特定的更改确保扩展 JLP 文件必须具有 Java 或 J2SE 资源，并且这些资源不会指定使用什么 JRE。使用指定版本时允许嵌套资源。

# FX XML 扩展

在使用 JNLP 时，创建一个 JNLP 文件。下面是一个例子：

```java
<?xml version="1.0" encoding="UTF-8"?>
<jnlp spec="1.0+" codebase="" href="">
  <information>
    <title>Sample/title>
    <vendor>The Sample Vendor</vendor>
    <icon href="sample-icon.jpg"/>
    <offline-allowed/>
  </information>
  <resources>
    <!-- Application Resources -->
    <j2se version="1.6+"
    href="http://java.sun.com/products/autodl/j2se"/>
    <jar href="Sample-Set.jar" main="true" />
  </resources>
  <application-desc
    name="Sample Application"
    main-class="com.vendor.SampleApplication"
    width="800"
    height="500">
    <argument>Arg1</argument>
    <argument>Arg2</argument>
    <argument>Arg3</argument>
  </application-desc>
  <update check="background"/>
</jnlp>
```

对`<application-desc>`元素作了两处修改。首先，可选的`type`属性被添加到可以注解的应用类型中。默认类型是`Java`，因此如果您的程序是 Java 应用，则不需要包含`type`属性

或者，您可以指定`Java`作为您的类型，如下所示：

```java
<application-desc
  name="Another Sample Application"
  type="Java" main-class="com.vendor.SampleApplication2"
  width="800"
  height="500">
  <argument>Arg1</argument>
  <argument>Arg2</argument>
  <argument>Arg3</argument>
</application-desc>
```

我们可以指示其他应用类型包括`JavaFX`，如下所示：

```java
<application-desc
  name="A Great JavaFX Application"
  type="JavaFX" main-class="com.vendor.GreatJavaFXApplication"
  width="800"
  height="500">
  <argument>Arg1</argument>
  <argument>Arg2</argument>
  <argument>Arg3</argument>
</application-desc>
```

如果您指出 JNLP 客户端不支持的应用类型，那么您的应用启动将失败。有关 JNLP 的更多信息，[请参阅官方文档](https://docs.oracle.com/javase/7/docs/technotes/guides/javaws/developersguide/faq.html)。

`<application-desc>`元素的第二个变化是增加了`param`子元素。这允许我们使用`value`属性提供参数的名称及其值。下面是 JNLP 文件的`<application-desc`元素在包含`param`子元素和`value`属性的情况下的外观示例。

此示例显示了三组参数：

```java
<application-desc
  name="My JRuby Application"
  type="JRuby"
  main-class="com.vendor.JRubyApplication"
  width="800"
  height="500">
  <argument>Arg1</argument>
  <argument>Arg2</argument>
  <argument>Arg3</argument>
  <param name="Parameter1" value="Value1"/>
  <param name="Parameter2" value="Value2"/>
  <param name="Parameter3" value="Value3"/>
</application-desc>
```

如果应用`type`是 Java，那么您使用的任何`param`子元素都将被忽略。

# JNLP 文件语法

JNLP 文件语法现在完全符合 XML 规范。在 Java9 之前，您可以使用`&`创建复杂的比较。标准 XML 不支持这一点。您仍然可以在 JNLP 文件中创建复杂的比较。现在您将使用`&amp`；而不是`&`。

# 数字版本比较

JNLP 规范已经更改，以反映数字版本元素与非数字版本元素的比较方式。在更改之前，版本元素是通过 ASCII 值按字典顺序进行比较的。在当前的 Java 平台和 JNLP 规范发生变化的情况下，元素仍然是按 ASCII 值按字典顺序进行比较的。当两个弦的长度不同时，这种变化就很明显了。在新的比较中，较短的字符串将填充前导零以匹配较长字符串的长度。

词典比较使用基于字母顺序的数学模型。

# 有用的工具

本节重点介绍三种工具，它们可以帮助您将应用迁移到当前的 Java 平台。

# Java 环境 - jEnv

如果您在使用 Linux 或 MacOS 的计算机上开发，您可能会考虑使用 **jEnv**，一种开源 Java 环境管理工具。这是一个命令行工具，所以不要期望 GUI。[您可以在以下网址下载该工具](https://github.com/gcuisinier/jenv)。

以下是 Linux 的安装命令：

```java
$ git clone https://github.com/gcuisinier/jenv.git ~/.jenv
```

要使用 MacOS 和自制软件进行下载，请使用以下命令：

```java
$ brew install jenv
```

也可以使用 Bash 在 Linux 或 MacOS 上安装，如下所示：

```java
$ echo 'export PATH="$HOME/.jenv/bin:$PATH"' >> ~/.bash_profile
$ echo 'eval "$(jenv init -)"' >> ~/.bash_profile
```

或者，您可以使用 **Zsh** 在 Linux 或 MacOS 上安装，如下所示：

```java
$ echo 'export PATH="$HOME/.jenv/bin:$PATH"' >> ~/.zshrc
$ echo 'eval "$(jenv init -)"' >> ~/.zshrc
```

安装了 **jEnv** 之后，您需要在您的系统上配置它，如下所示。您需要修改脚本以反映您的实际路径：

```java
$ jenv add /Library/Java/JavaVirtualMachines/JDK17011.jdk/Contents/Home
```

您需要为系统上的每个版本的 JDK 重复`jenv add`命令。通过每个`jenv add`命令，您将收到特定 JDK 版本已添加到 jEnv 的确认，如下所示：

```java
$ jenv add /System/Library/Java/JavaVirtualMachines/1.6.0.jdk/Contents/Home
oracle64-1.6.0.39 added

$ jenv add /Library/Java/JavaVirtualMachines/JDK17011.jdk/Contents/Home
oracle64-1.7.0.11 added
```

您可以通过在命令提示符下使用`$ jenv versions`来检查添加到 jEnv 中的 JDK 版本。这将产生一个输出列表。

下面是三个附加的 jEnv 命令：

*   `jenv global <version>`：设置全局版本
*   `jenv local <version>`：设置本地版本
*   `jenv shell <version>`：设置 Shell 的实例版本

# Maven

Maven 是一个开源工具，可用于构建和管理基于 Java 的项目。它是 **Apache Maven 项目**的一部分。如果您还没有使用 Maven 并且进行了大量 Java 开发，那么您可能会被以下 Maven 目标所吸引：

*   简化构建过程
*   提供统一的构建系统
*   提供优质项目信息
*   提供最佳实践开发指南
*   允许透明地迁移到新功能

[你可以在这个网站上阅读更多关于 Maven 目标的细节](https://maven.apache.org/what-is-maven.html)。要下载 Maven，[请访问以下网站](https://maven.apache.org/download.cgi)。[此处提供了 Windows、MacOS、Linux 和 Solaris 的安装说明](https://maven.apache.org/install.html)。

Maven 可以与 Eclipse（M2Eclipse）、JetBrains IntelliJ IDEA 和 netbeansIDE 集成。例如，M2Eclipse IDE 提供了与 Apache Maven 的丰富集成，并具有以下特性：

*   您可以从 Eclipse 中启动 Maven 构建
*   您可以管理 Eclipse 构建路径的依赖关系
*   您可以很容易地解析 Maven 依赖关系（您可以直接从 Eclipse 执行此操作，而不必安装本地 Maven 存储库）
*   您可以自动下载所需的依赖项（从远程 Maven 存储库）
*   您可以使用软件向导创建新的 Maven 项目，创建`pom.xml`文件，并为普通 Java 项目启用 Maven 支持
*   您可以对 Maven 的远程存储库执行快速的依赖性搜索

# 获取 Eclipse IDE

要获得 M2EclipseIDE，必须首先安装 Eclipse。步骤如下：

1.  Start by opening your current Eclipse IDE. Next, select Preferences | Install/Update | Available Software Sites, as shown in the following screenshot:

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/75648bd7-cdc5-444c-97e3-7b4c981aaf2a.png)

2.  The next task is to add the M2Eclipse repository site to your list of Available Software Sites. To accomplish this, click the Add button and enter values in the Name and Location text input boxes. For Name, enter something to help you remember that M2Eclipse is available at this site. For Location, enter the URL: [http://download.eclipse.org/technology/m2e/releases](http://download.eclipse.org/technology/m2e/releases). Then, click the OK button:

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/b9a68d06-3541-49b4-a1f6-37fdaa548e8d.png)

3.  You should now see the M2Eclipse site listed in your list of Available Software Sites, as shown in the following screenshot. Your final step is to click the OK button:

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/85ad2f79-ca47-4f6f-b625-7a1b453e11ac.png)

4.  Now, when you start a new project, you will see Maven Project as an option:

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/20fe004b-c900-4c0b-ae83-9ce76902c000.png)

# 总结

在本章中，我们探讨了将现有应用迁移到当前 Java 平台时可能涉及的问题。我们研究了手动和半自动迁移过程，本章为您提供了一些见解和过程，使您的 Java8 代码能够在新的 Java 平台上工作。具体来说，我们对项目 Jigsaw 进行了快速回顾，研究了模块如何适应 Java 环境，提供了迁移规划的技巧，共享了 Oracle 关于迁移的建议，以及可以在开始时使用的共享工具。

在下一章中，我们将详细介绍 JavaShell 和 JShellAPI。我们将演示 JShellAPI 和 JShell 工具以交互方式求值 Java 编程语言的声明、语句和表达式的能力。我们将演示此命令行工具的特性和用法。

# 问题

1.  用新的模块化 Java 平台解决的类路径有什么问题？
2.  模块化系统是在哪个版本的 Java 中引入的？
3.  模块化系统解决了什么主要问题？
4.  总是需要哪个模块？
5.  是什么驱动了 Java 中的封装？
6.  哪个模块提供对关键内部 API 的访问？
7.  可以编辑哪个文件来标识显式命名的模块？
8.  什么是 JNLP？
9.  下划线作为单个字符标识符的意义是什么？
10.  哪三个命令行选项可以用来打破封装？

# 进一步阅读

此处列出的参考资料将帮助您深入了解本章中介绍的概念：

*   [《Maven 速成课》](https://www.packtpub.com/application-development/maven-crash-course-video)。

# 六、试用 Java Shell

在上一章中，我们探讨了如何将 Java9 之前的应用迁移到新的 Java 平台。我们研究了在 Java9 上运行时可能导致当前应用出现问题的几个问题。我们首先回顾了 Jigsaw 项目，然后研究了模块如何适应新的 Java 平台。我们为您提供了一些见解和过程，使您的 Java8 代码能够与 Java9、10 或 11 一起工作。具体来说，我们提供了迁移规划的技巧、Oracle 关于迁移的共享建议，以及可以用来帮助您开始使用 Java18.x 的共享工具。

在本章中，我们将首先介绍新的命令行，**读取求值打印循环**（也称为 **REPL** 工具，以及 **Java Shell**（**JShell**）。我们将首先回顾一些关于这个工具的介绍性信息，REPL 概念，然后讨论可以与 JShell 一起使用的命令和命令行选项。我们将采用实践者的方法来回顾 JShell，并包括您可以自己尝试的示例。

本章将讨论以下主题：

*   什么是 JShell？
*   JShell 入门
*   JShell 的实际应用
*   使用脚本

# 技术要求

本章以 Java11 为特色，Java 平台的**标准版**（**SE**）可从 [Oracle 官方下载网站](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。

IDE 包就足够了。来自 JetBrains 的 IntelliJ IDEA 用于与本章和后续章节相关的所有编码。IntelliJ IDEA 的社区版可从[网站](https://www.jetbrains.com/idea/features/)下载。

本章的源代码可以在 [GitHub 的 URL](https://github.com/PacktPublishing/Mastering-Java-11-Second-Edition) 上找到。

# 了解 JShell

**JShell** 是 Java 平台上比较新的一个重要工具。它是在 JDK9 中引入的。它是一个交互式 REPL 工具，用于求值以下 Java 编程语言组件声明、语句和表达式。它有自己的 API，因此可以被外部应用使用。

**读取求值打印循环** 通常称为 **REPL**，取自词组中每个单词的第一个字母。 它也被称为语言外壳或交互式顶层。

JShell 的引入是 **JDK 增强建议**（**JEP**）222 的结果。以下是本 JEP 关于 Java Shell 命令行工具的既定目标：

*   便于快速调查
*   便于快速编码
*   提供编辑历史记录

前面列出的快速调查和编码包括语句和表达式。令人印象深刻的是，这些语句和表达式不需要是方法的一部分。此外，变量和方法不需要是类的一部分，这使得这个工具特别动态。

此外，还包括以下列出的功能，以使 JShell 更易于使用，并使您使用 JShell 的时间尽可能节省时间：

*   制表符补全
*   语句结尾分号的自动补全
*   导入的自动补全
*   定义的自动补全

# JShell 入门

**JShell** 是位于`/bin`文件夹中的命令行工具。此工具的语法如下：

```java
jshell <options> <load files>
```

正如您在下面的屏幕截图中看到的，有几个选项可用于此工具：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/b5d49323-4fde-4871-bc1a-56802226b006.png)

您已经看到了我们使用`jshell -h`执行的`-h`选项。这提供了 JShell 选项的列表。

要登录 JShell，只需使用`jshell`命令即可。您将看到命令窗口中的提示会相应更改：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/97ad13b0-1b4d-4435-9eb5-fae07ba06e81.png)

退出 Shell 就像进入`/exit`一样简单。进入 JShell 后，可以输入以下任何命令：

| **命令** | **功能** |
| --- | --- |
| `/drop` | 使用此命令删除被`name`或`id`引用的源条目。语法如下：`/drop <name or id>` |
| `/edit` | 使用此命令，您可以使用`name`或`id`引用编辑源条目语法如下：`/edit <name or id>` |
| `/env` | 这个强大的命令允许您查看或更改求值上下文语法如下：`/env [-class-path <path>]  [-module-path <path>]  [-add-modules <modules>]` |
| `/exit` | 此命令用于退出 JShell。语法是简单的`/exit`，没有任何可用的选项或参数。 |
| `/history` | `history`命令提供您所键入内容的历史记录。语法是简单的`/history`，没有任何可用的选项或参数。 |
| `/<id>` | 此命令用于通过引用`id`重新运行以前的代码段。语法如下：`/<id>`您也可以使用`/-<n>`引用前`n`个代码段来运行特定的代码段。 |
| `/imports` | 可以使用此命令列出导入的项目。语法为`/imports`，不接受任何选项或参数。 |
| `/list` | 此命令将列出您键入的源代码。语法如下：`/list [<name or id> &#124; -all &#124; -start]` |
| `/methods` | 此命令列出所有声明的方法及其签名。语法如下：`/methods [<name or id> &#124; -all &#124; -start]` |
| `/open` | 使用此命令，可以打开一个文件作为源输入。语法如下：`/open <file>` |
| `/reload` | `reload`命令提供重置和重放相关历史的功能。语法如下：`/reload [-restore] [-quiet] [-class-path <path>] [-module-path <path>]` |
| `/reset` | 此命令重置 JShell。语法如下：`/reset [-class-path <path>] [-module-path <path>] [-add-modules <modules]` |
| `/save` | 此命令将代码段源保存到您指定的文件中。语法如下：`/save [-all &#124; -history &#124; -start] <file>` |
| `/set` | 此命令用于设置 JShell 配置信息。语法如下：`/set editor &#124; start &#124; feedback &#124; mode &#124; prompt &#124; truncation &#124; format` |
| `/types` | 这个命令只列出声明的类型。语法如下：`/types [<name or id> &#124; -all &#124; -start]` |
| `/vars` | 此命令列出所有声明的变量及其值。语法如下：`/vars [<name or id> &#124; -all &#124; -start]` |
| `/!` | 此命令将重新运行最后一个代码段。语法很简单`/!` |

前面列出的几个命令使用术语**片段**。在 Java 和 JShell 的上下文中，代码段如下所示：

*   `ClassDeclaration`
*   `Expression`
*   `FieldDeclaration`
*   `ImportDeclaration`
*   `InterfaceDeclaration`
*   `MethodDeclaration`

在 JShell 中输入`/help`或`/?`命令提供了一个完整的命令列表和可以在 Shell 中使用的语法。该清单如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/00a3354b-8757-4fd3-abed-bc4733f6d427.png)

我们鼓励您尝试使用 JShell 命令。您可以使用前面的屏幕截图来提醒自己正确的语法。

如果您还不熟悉 JShell，`/help`命令会特别有用。在下面的屏幕截图中可以看到，我们只需输入`/help intro`命令，就可以获得 JShell 的简介：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/f0ad218d-880a-4b74-ae2b-960bb9d32bb0.png)

如果您发现自己经常使用 JShell，那么您可能会受益于下面列出的一个或多个快捷方式。可以随时从 JShell 中使用`/help shortcuts`命令列出这些内容：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/7aa11d03-2235-4955-871f-337e9840a532.png)

在 JShell 中，可以使用`/help`命令，然后使用需要额外帮助的命令来获得额外的帮助。例如，输入`/help reload`提供有关`/reload`命令的详细信息。该信息提供如下：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/981313ce-5b1a-479f-9e62-811d1b971829.png)

# JShell 的实际应用

无论您是一个新的或经验丰富的开发人员，还是刚刚接触 Java，您一定会发现 JShell 非常有用。在本节中，我们将介绍 JShell 的一些实际用途。具体来说，我们将介绍以下内容：

*   反馈模式
*   列出你的素材
*   在 JShell 中编辑

# 反馈模式

命令行工具通常提供相对稀疏的反馈，以避免屏幕过于拥挤，否则，可能会对开发人员造成麻烦。除了让开发人员能够创建自己的自定义模式之外，JShell 还有几种反馈模式。

如您所见，在下面的截图中，有四种反馈模式：`concise`、`normal`、`silent`、`verbose`。我们可以输入不带任何参数的`/set feedback`命令来列出反馈模式以及识别当前的反馈模式。输出的第一行（请参见下面的屏幕截图）显示用于设置反馈模式的命令行命令和参数集：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/ad53c5c2-b670-462b-a38f-6bdcd1b9a8e0.png)

我们可以通过在启动 JShell 时包含一个选项来决定第一次进入 JShell 时要进入的模式。以下是命令行选项：

| **命令行命令和选项** | **反馈方式** |
| --- | --- |
| `jshell -q` | `concise` |
| `jshell -n` | `normal` |
| `jshell -s` | `silent` |
| `jshell -v` | `verbose` |

您会注意到我们使用`-q`来表示`concise`模式，而不是`-c`。`-c`选项具有`-c<flag>`语法，用于将`<flag>`传递给编译器。有关这些标志的更多信息，请参阅本章“进一步阅读”部分中列出的参考资料。

回顾反馈模式之间的差异最好的方法是使用示例。从`normal`模式开始，我们将执行命令行命令来完成以下有序反馈演示：

1.  创建一个变量。
2.  更新变量的值。
3.  创建一个方法。
4.  更新方法。
5.  运行方法。

为了开始我们的第一个测试，我们将在`jshell>`提示符处执行`/set feedback normal`命令，这将 JShell 反馈模式设置为`normal`。进入`normal`反馈模式后，我们将输入必要的命令来运行演示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/8831a562-feae-4a1e-9cd7-edddaf9d4e44.png)

进入`normal`反馈模式后，我们进入`int myVar = 3`，收到`myVar ==> 3`作为反馈。在下一个命令中，我们更改了相同变量的值，并用新值接收相同的输出。我们的下一个语句`void quickMath() {System.out.println("Your result is " + (x*30 + 19));}`使用了一个未声明的变量，您将看到由两部分组成的反馈，一部分指示方法已创建，另一部分通知您在声明未声明的变量之前无法调用该方法。接下来，我们改变了我们的方法以包含`myVar`变量，并且反馈报告该方法被修改。我们的最后一步是使用`quickMath();`运行该方法，结果与我们预期的一样

让我们在`concise`模式下尝试同样的反馈演示：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/1029d7ca-3c65-43aa-9d58-bd4a6589fcdf.png)

从前面的截图中可以看到，`concise`反馈模式为我们提供的反馈更少。我们创建和修改了变量，没有收到反馈，当我们用未声明的变量创建方法时，我们收到的反馈与我们在`normal`模式下的反馈相同。我们在没有确认或其他反馈的情况下更新了方法。

我们下次使用反馈演示将在`silent`模式下进行：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/b86dc24b-efda-488f-9fce-771fb84a33bc.png)

当我们进入`silent`反馈模式时，正如您在前面的屏幕截图中看到的，JShell 提示从`jshell>`变为`->`。当我们创建`myVar`变量、修改`myVar`变量或创建`quickMath()`方法时，没有提供反馈。我们故意创建`quickMath()`方法来使用未声明的变量。因为我们处于`silent`反馈模式，所以我们没有被告知该方法有未声明的变量。基于这种缺乏反馈的情况，我们运行了这个方法，没有得到任何输出或反馈。接下来，我们更新了该方法以包含`myVar`声明的变量，然后运行该方法。

`silent`反馈模式似乎没有任何反馈，但这种模式有很大的实用价值。使用`silent`模式可能适合管道输送，或者仅当您想最小化终端输出量时。例如，您可以使用隐式`System.out.println`命令包含特定的条件输出。

我们最后一次使用反馈演示是在`verbose`反馈模式下。这个反馈模式，正如你从它的名字所假设的，提供了最多的反馈。以下是我们的测试结果：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/5f9a8a1c-4586-460d-9344-017a8043293e.png)

在我们的反馈演示中，当使用`verbose`反馈模式时，我们会收到更多的反馈以及更好的反馈格式。

# 创建自定义反馈模式

内部反馈模式（`normal`、`concise`、`silent`、`verbose`不可修改，可自行创建自定义反馈模式。此过程的第一步是复制现有模式。下面的示例演示如何使用`/set mode myCustom verbose -command`命令字符串将`verbose`模式复制到`myCustom`模式：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/a39ed7d6-dc4f-442b-878b-4656fd6a36ea.png)

我们使用了`-command`选项来确保接收到命令反馈。您可以使用`/set`命令和以下屏幕截图中列出的选项之一对反馈模式进行各种更改：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/7e1da0de-02ab-4b9c-8a69-8452b355def4.png)

作为一个例子，让我们浏览一下`truncation`设置，该设置要求在每个输出行上显示多少个字符。使用`/set truncation`命令，如下面的屏幕截图所示，显示当前的截断设置：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/d6c42080-2734-48f5-a805-d520602e9154.png)

如您所见，我们的`myCustom`反馈模式截断了`80`。我们用`/set truncation myCustom 60`命令将其改为`60`，然后用`/set truncation`命令进行验证：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/34a31eb6-17f4-4d18-9333-5811247e30ec.png)

正如您在上一个屏幕截图中看到的，基于我们使用的`/set truncation myCustom 60`JShell 命令，我们的`myCustom`反馈模式的截断成功地从`verbose`模式继承的`80`更改为`60`。

# 列出你的素材

有几个 JShell 命令可以方便地列出您创建的素材。使用上一节的反馈演示，我们执行了`/vars`、`/methods`和`/list`命令，分别提供变量、方法和所有源的列表：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/6fb19153-ec76-4fc1-9d51-69baec531ddb.png)

我们还可以使用`/list -all`命令和选项组合来查看 JShell 导入了哪些包。正如您在下面的屏幕截图中看到的，JShell 导入了几个包，使我们在 Shell 中的工作更加方便，从而节省了我们在方法中导入这些标准包的时间：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/6b657374-17e1-47d9-9b0c-83d79d6dfa27.png)

如果您只想列出启动导入，可以使用`/list -start`命令和选项组合。正如您在下面的屏幕截图中看到的，每个启动导入都有一个`s`前缀，并按数字顺序排列：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/9298628e-8b4a-4085-812c-6a0fd8d218f0.png)

# 在 JShell 中编辑

JShell 不是一个全功能的文本编辑器，但是您可以在 Shell 中做一些事情。本节为您提供编辑技术，分为修改文本、基本导航、历史导航和高级编辑命令。

# 修改文本

默认的文本编辑/输入模式使您键入的文本显示在当前光标位置。当您想删除文本时，有几个选项可供选择。以下是完整的列表：

| **删除动作** | **PC 键盘组合** | **Mac 键盘组合** |
| --- | --- | --- |
| 删除当前光标位置的字符 | `del` | `del` |
| 删除光标左侧的字符 | `backspace` | `del` |
| 删除从光标位置到行尾的文本 | `Ctrl + K` | `Cmd + K` |
| 删除从光标位置到当前单词末尾的文本 | `Alt + D` | `Alt + D` |
| 从光标位置删除到上一个空白处 | `Ctrl + W` | `Cmd + W` |
| 在光标位置粘贴最近删除的文本 | `Ctrl + Y` | `Cmd + Y` |
| 当使用`Ctrl + Y`（或 Macintosh 上的`Cmd + Y`）时，您将能够使用`Alt + Y`键盘组合循环浏览先前删除的文本 | `Alt + Y` | `Alt + Y` |

# 基本导航

虽然 JShell 中的导航控件与大多数命令行编辑器类似，但有一个基本导航控件列表是很有帮助的：

| **键**/**键组合** | **导航动作** |
| --- | --- |
| 向左箭头 | 向后移动一个字符 |
| 向右箭头 | 向前移动一个字符 |
| 向上箭头 | 在历史中向上移动一行 |
| 向下箭头 | 沿着历史向前移动一行 |
| 返回 | 输入（提交）当前行 |
| `Ctrl + A`（`Cmd + A`在 Macintosh 上） | 跳到当前行的开头 |
| `Ctrl + E`（`Cmd + E`在 Macintosh 上） | 跳到当前行的末尾 |
| `Alt + B` | 退一步说 |
| `Alt + F` | 向前跳一个字 |

# 历史导航

JShell 会记住您输入的代码段和命令。它维护此历史记录，以便您可以重用已输入的代码段和命令。要循环浏览代码段和命令，可以按住`Ctrl`键（Macintosh 上的`cmd`，然后使用上下箭头键，直到看到所需的代码段或命令。

# 高级编辑命令

还有几个编辑选项可用，以便您可以包括搜索功能、宏创建和使用等。JShell 的编辑器基于 JLine2，这是一个用于解析控制台输入和编辑的 Java 库。[您可以在这里了解更多关于 JLine2 的信息](https://github.com/jline/jline2/wiki/JLine-2.x-Wiki.)。

# 使用脚本

到目前为止，您已经从键盘将数据直接输入 JShell。现在您可以使用 JShell 脚本了，它是一系列 JShell 命令和代码段。该格式与其他脚本格式相同，每行一条命令。

在本节中，我们将介绍启动脚本，研究如何加载脚本，如何保存脚本，最后介绍使用 JShell 编写高级脚本。

# 启动脚本

每次启动 JShell 时，都会加载启动脚本。每次使用`/reset`、`/reload`和`/env`命令时也会发生这种情况。

默认情况下，`DEFAULT`启动脚本由 JShell 使用。如果你想使用不同的启动脚本，你只需要使用`/set start <script>`命令。举个例子：

```java
/set start MyStartupScript.jsh
```

或者，您可以在命令提示符处使用 JShell`start MyStartupScript.jsh`命令来启动 JShell 并加载`MyStartupScript.jsh`JShell 启动脚本。

当您使用带有`-retain`选项的`/set start <script>`命令时，您告诉 JShell 在下次启动 JShell 时使用新的启动脚本。

# 加载脚本

在 JShell 中加载脚本可以通过以下方法之一完成：

*   您可以使用`/open`命令和脚本名称作为参数。例如，如果我们的脚本名是`MyScript`，我们将使用`/open MyScript`。
*   加载脚本的第二个选项是在命令提示符处使用`jshell MyScript.jsh`命令。这将启动 JShell 并加载`MyScript.jsh`JShell 脚本。

# 保存脚本

除了在外部编辑器中创建 JShell 脚本之外，我们还可以在 JShell 环境中创建它们。采用这种方法时，您需要使用`/save`命令保存脚本。在下面的屏幕截图中可以看到，`/save`命令至少需要一个文件名参数：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/4cb493b3-45ee-432c-8f8e-4849de3e3017.png)

使用`/save`命令有三个可用选项：

*   `-all`选项可用于将所有代码段的源代码保存到指定的文件中。
*   `-history`选项保存自 JShell 启动以来输入的所有命令和代码段的连续历史记录。JShell 执行此操作的能力告诉您，它维护您输入的所有内容的历史记录。
*   `-start`选项将当前启动定义保存到指定的文件中。

# 使用 JShell 编写高级脚本

JShell 的极限是什么？有这么多你可以做这个工具，你几乎只限于你的想象力和编程能力。

让我们看看一个高级代码库，它可以用来从 JShell 脚本编译和运行 Java 程序：

```java
import java.util.concurrent.*
import java.util.concurrent.*
import java.util.stream.*
import java.util.*

void print2Console(String thetext) {
  System.out.println(thetext);
  System.out.println("");
}

void runSomeProcess(String... args) throws Exception {
  String theProcess = 
   Arrays.asList(args).stream().collect(Collectors.joining(" "));
  print2Console("You asked me to run: '"+theProcess+"'");
  print2Console("");
  ProcessBuilder compileBuilder = new ProcessBuilder(args).inheritIO();
   Process compileProc = compileBuilder.start();
   CompletableFuture<Process> compileTask = compileProc.onExit();
   compileTask.get();
}

print2Console("JShell session launched.")
print2Console("Preparing to compile Sample.java. . . ")

// run the Java Compiler to complete Sample.java
runSomeProcess("javac", "Sample.java")
print2Console("Compilation complete.")
print2Console("Preparing to run Sample.class...")

// run the Sample.class file
runSomeProcess("java", "Sample")
print2Console("Run Cycle compete.")

// exit JShell
print2Console("JShell Termination in progress...)
print2Console("Session ended.")

/exit
```

正如您在这个脚本中看到的，我们创建了一个`runSomeProcess()`方法，您可以使用它显式编译和运行外部 Java 文件。我们鼓励你自己尝试一下，这样你就可以熟悉这个过程了。

# 总结

在本章中，我们研究了 Java 的 REPL 命令行工具 JShell，我们从有关该工具的介绍性信息开始，并仔细地研究了 REL 概念。我们花了相当长的时间来查看 JShell 命令和命令行选项。我们的报道包括反馈模式、素材清单和 Shell 中编辑的实用指南。我们还获得了脚本工作经验

在下一章中，我们将介绍 Java 的默认垃圾收集器。具体来说，我们将查看默认的垃圾收集、已废弃的垃圾收集组合，并检查垃圾收集日志记录。

# 问题

1.  什么是 REPL？
2.  什么是 JShell？
3.  您能说出 JShell 的四个最新特性，这些特性使其使用更加高效？
4.  JShell 在您的计算机文件系统中的位置是什么？
5.  你怎么离开 JShell？
6.  您将使用哪个 JShell 命令列出所有声明的变量及其对应的值？
7.  如何获得可以与 JShell 一起使用的命令和语法的完整列表？
8.  如何获得有关特定 JShell 命令的详细帮助？
9.  什么是反馈模式？
10.  什么是默认的反馈模式？

# 进一步阅读

下面这本书是了解 JShell 的好资料：

*   《Java9 和 JShell》在[这个页面](https://www.packtpub.com/application-development/java-9-jshell)上提供。

# 七、利用默认的 G1 垃圾收集器

在上一章中，我们研究了 **Java Shell**（**JShell**）、Java 的 **读取求值打印循环**（**REPL**）命令行工具。我们从介绍该工具的信息开始，仔细研究了 REPL 概念。我们花了大量时间来检查 JShell 命令和命令行选项。我们的报道包括反馈模式的实用指南、素材列表和 Shell 中的编辑。我们还获得了使用脚本的经验。

在本章中，我们将深入了解垃圾收集以及如何在 Java 中处理它。我们将从垃圾收集的概述开始，然后看看 Java9 之前的领域中的细节。有了这些基本信息，我们将研究 Java9 平台中特定的垃圾收集更改。最后，我们将研究一些即使在 Java11 之后仍然存在的垃圾收集问题。

本章包括以下主题：

*   垃圾收集概述
*   Java9 之前的垃圾收集模式
*   用新的 Java 平台收集垃圾
*   长期存在的问题

# 技术要求

本章主要介绍 Java11。Java 平台的标准版（SE）可以从 [Oracle 的官方下载站点](http://www.oracle.com/technetwork/java/javase/downloads/index.html)下载。

IDE 包就足够了。来自 JetBrains 的 IntelliJ IDEA 用于与本章和后续章节相关的所有编码。IntelliJ IDEA 的社区版可从[网站](https://www.jetbrains.com/idea/features/)下载。

[本章源代码可在 GitHub 上获取](https://github.com/PacktPublishing/Mastering-Java-11-Second-Edition)。

# 垃圾收集概述

垃圾收集是 Java 中用来释放未使用内存的机制。本质上，当一个对象被创建时，内存空间被分配并专用于该对象，直到它不再有任何指向它的引用为止。此时，系统将释放内存

Java 为我们自动执行这种垃圾收集，这可能会导致对内存使用的关注不足，以及在内存管理和系统性能方面的糟糕编程实践。Java 的垃圾收集被认为是一种自动内存管理模式，因为程序员不必将对象指定为随时可用取消分配。垃圾收集在低优先级线程上运行，并且，正如您将在本章后面阅读的，具有可变的执行周期。

在垃圾收集概述中，我们将介绍以下概念：

*   对象生命周期
*   垃圾收集算法
*   垃圾收集选项
*   与垃圾收集相关的 Java 方法

我们将在接下来的章节中逐一介绍这些概念。

# 对象生命周期

为了完全理解 Java 的垃圾收集，我们需要了解对象的整个生命周期。因为垃圾收集的核心在 Java 中是自动的，所以将术语**垃圾收集**和**内存管理**视为对象生命周期的假定组件并不少见

我们将从对象创建开始回顾对象生命周期。

# 对象创建

对象被声明和创建。当我们编写一个对象声明或声明一个对象时，我们声明的是一个名称或标识符，这样我们就可以引用一个对象。例如，下面的代码行将`myObjectName`声明为`CapuchinMonkey`类型的对象的名称。此时，没有创建对象，也没有为其分配内存：

```java
CapuchinMonkey myObjectName;
```

我们使用`new`关键字来创建一个对象。下面的示例说明如何调用`new`操作来创建对象。此操作导致：

```java
myObjectName = new CapuchinMonkey();
```

当然，我们可以使用`CapuchinMonkey myObjectName = new CapuchinMonkey();`来组合声明和创建语句，而不是使用`CapuchinMonkey myObjectName;`和`myObjectName = new CapuchinMonkey();`，在前面的示例中，它们是分开的。

当一个对象被创建时，会为存储该对象分配一个特定的内存量，分配的内存量会因架构和 JVM 的不同而不同。

接下来，我们将看一个对象的中期寿命。

# 对象中期

对象被创建，Java 为存储该对象分配系统内存。如果对象未被使用，分配给它的内存将被视为浪费。这是我们要避免的。即使对于小型应用，这种类型的内存浪费也会导致性能低下，甚至出现内存不足的问题

我们的目标是释放或释放内存，即我们不再需要的任何先前分配的内存。幸运的是，对于 Java，有一种机制可以处理这个问题。这就是所谓的垃圾收集

当一个对象（比如我们的`myObjectName`示例）不再有任何指向它的引用时，系统将重新分配相关的内存。

# 对象销毁

Java 让垃圾收集器在代码的暗处运行（通常是一个低优先级线程）并释放当前分配给未引用对象的内存的想法很有吸引力。那么，这是怎么回事？垃圾收集系统监视对象，并在可行的情况下统计每个对象的引用数

如果没有对对象的引用，则无法使用当前运行的代码访问该对象，因此释放相关内存是非常有意义的。

术语**内存泄漏**是指丢失或不正确释放的小内存块。Java 的垃圾收集可以避免这些泄漏。

# 垃圾收集算法

JVM 可以使用几种垃圾收集算法或类型。在本节中，我们将介绍以下垃圾收集算法：

*   标记和扫描
*   **并发标记扫描**（**CMS**）垃圾收集
*   串行垃圾收集
*   并行垃圾收集
*   G1 垃圾收集

# 标记和扫描

Java 的初始垃圾收集算法标记清除使用了一个简单的两步过程：

1.  第一步，标记，是遍历所有具有可访问引用的对象，将这些对象标记为活动对象

2.  第二步，扫描，包括扫描海洋中任何没有标记的对象

正如您可以很容易地确定的那样，标记和扫描算法似乎很有效，但由于这种方法的两步性质，它可能不是很有效。这最终导致了一个 Java 垃圾收集系统，大大提高了效率。

# 并发标记扫描（CMS）垃圾收集

用于垃圾收集的 CMS 算法使用多个线程扫描堆内存。与“标记并扫描”方法类似，它标记要删除的对象，然后进行扫描以实际删除这些对象。这种垃圾收集方法本质上是一种升级的标记和扫描方法。它进行了修改，以利用更快的系统和性能增强。

要为应用手动调用 CMS 垃圾收集算法，请使用以下命令行选项：

```java
-XX:+UseConcMarkSweepGC
```

如果要使用 CMS 垃圾收集算法并指定要使用的线程数，可以使用以下命令行选项。在下面的示例中，我们告诉 Java 平台使用带有八个线程的 CMS 垃圾收集算法：

```java
-XX:ParallelCMSThreads=8
```

# 串行垃圾收集

Java 的串行垃圾收集在一个线程上工作。执行时，它冻结所有其他线程，直到垃圾收集操作结束。由于串行垃圾收集的线程冻结性质，它只适用于非常小的程序

要手动调用应用的串行垃圾收集算法，请使用以下命令行选项：

```java
-XX:+UseSerialGC
```

# 并行垃圾收集

在 Java8 和更早版本中，并行垃圾收集算法是默认的垃圾收集器。它使用多个线程，但冻结应用中的所有非垃圾收集线程，直到垃圾收集函数完成，就像串行垃圾收集算法一样。

# G1 垃圾收集

G1 垃圾收集算法是为处理大内存堆而创建的。这种方法包括将内存堆分割成多个区域。使用 G1 算法的垃圾收集与每个堆区域并行进行

G1 算法的另一部分是当内存被释放时，堆空间被压缩。不幸的是，压实操作是使用*停止世界*方法进行的

G1 垃圾收集算法还根据要收集的垃圾最多的区域来确定区域的优先级。

**G1** 名称指**垃圾优先**。

要为应用手动调用 G1 垃圾收集算法，请使用以下命令行选项：

```java
-XX:+UseG1GC
```

# 垃圾收集选项

以下是 JVM 大小调整选项的列表：

| **大小说明** | **JVM 选项标志** |
| --- | --- |
| 此标志建立初始堆大小（年轻空间和长期空间的组合）。 | `XX:InitialHeapSize=3g` |
| 此标志建立最大堆大小（年轻空间和长期空间的组合）。 | `-XX:MaxHeapSize=3g` |
| 此标志建立初始和最大堆大小（年轻空间和长期空间的组合）。 | `-Xms2048m -Xmx3g` |
| 这个标志建立了年轻空间的初始大小。 | `-XX:NewSize=128m` |
| 此标志确定了年轻空间的最大大小。 | `-XX:MaxNewSize=128m` |
| 此标志确定空间大小。它使用了年轻人和终身监禁者的比例。在右边的示例标志中，`3`表示年轻空间将比终身空间小三倍。 | `-XX:NewRation=3` |
| 此标志将单个幸存者空间的大小确定为伊甸园空间大小的一部分。 | `-XX:SurvivorRatio=15` |
| 此标志确定永久空间的初始大小。 | `-XX:PermSize=512m` |
| 此标志确定永久空间的最大大小。 | `-XX:MaxPermSize=512m` |
| 此标志确定每个线程专用的栈区域的大小（以字节为单位）。 | `-Xss512k` |
| 此标志确定每个线程专用的栈区域的大小（以 KB 为单位）。 | `-XX:ThreadStackSize=512` |
| 此标志确定 JVM 可用的堆外内存的最大大小。 | `-XX:MaxDirectMemorySize=3g` |

以下是新生代垃圾收集选项的列表：

| **新生代垃圾收集调优选项** | **标志** |
| --- | --- |
| 设置保留阈值（从年轻空间升级到保留空间之前集合的阈值） | `-XX:Initial\TenuringThreshold=16` |
| 设置上限寿命阈值。 | `-XX:Max\TenuringThreshold=30` |
| 设置空间中允许的最大对象大小。如果一个对象大于最大大小，它将被分配到终身空间和绕过年轻空间。 | `-XX:Pretenure\SizeThreshold=3m` |
| 用于将年轻集合中幸存的所有年轻对象提升到终身空间。 | `-XX:+AlwaysTenure` |
| 使用此标记，只要幸存者空间有足够的空间，年轻空间中的对象就永远不会升级到终身空间。 | `-XX:+NeverTenure` |
| 我们可以指出我们想要在年轻空间中使用线程本地分配块。这在默认情况下是启用的。 | `-XX:+UseTLAB` |
| 切换此选项以允许 JVM 自适应地调整线程的 **TLAB**（简称**线程本地分配块**）。 | `-XX:+ResizeTLAB` |
| 设置线程的 TLAB 的初始大小。 | `-XX:TLABSize=2m` |
| 设置 TLAB 的最小允许大小。 | `-XX:MinTLABSize=128k` |

以下是 CMS 调整选项列表：

| **CMS 调优选项** | **标志** |
| --- | --- |
| 指示您希望仅使用占用率作为启动 CMS 收集操作的标准。 | `-XX:+UseCMSInitiating\OccupancyOnly` |
| 设置 CMS 生成占用率百分比以开始 CMS 收集周期。如果您指示一个负数，那么您就告诉 JVM 您要使用`CMSTriggerRatio`。 | `-XX:CMSInitiating\OccupancyFraction=70` |
| 设置要启动 CMS 集合以进行引导集合统计的 CMS 生成占用百分比。 | `-XX:CMSBootstrap\Occupancy=10` |
| 这是在 CMS 循环开始之前分配的 CMS 生成中`MinHeapFreeRatio`的百分比。 | `-XX:CMSTriggerRatio=70` |
| 设置在开始 CMS 收集循环之前分配的 CMS 永久生成中`MinHeapFreeRatio`的百分比。 | `-XX:CMSTriggerPermRatio=90` |
| 这是触发 CMS 集合后的等待时间。使用参数指定允许 CMS 等待年轻集合的时间。 | `-XX:CMSWaitDuration=2000` |
| 启用平行备注。 | `-XX:+CMSParallel\RemarkEnabled` |
| 启用幸存者空间的平行备注。 | `-XX:+CMSParallel\SurvivorRemarkEnabled` |
| 您可以使用此命令在备注阶段之前强制年轻的集合。 | `-XX:+CMSScavengeBeforeRemark` |
| 如果使用的 Eden 低于阈值，则使用此选项可防止出现计划注释。 | `-XX:+CMSScheduleRemark\EdenSizeThreshold` |
| 设置您希望 CMS 尝试和安排备注暂停的 Eden 占用百分比。 | `-XX:CMSScheduleRemark\EdenPenetration=20` |
| 至少在新生代的入住率达到您想要安排备注的 1/4（在我们右边的示例中）之前，您就要在这里开始对 Eden 顶部进行采样。 | `-XX:CMSScheduleRemark\SamplingRatio=4` |
| 备注后可选择`variant=1`或`variant=2`验证。 | `-XX:CMSRemarkVerifyVariant=1` |
| 选择使用并行算法进行年轻空间的收集。 | `-XX:+UseParNewGC` |
| 允许对并发阶段使用多个线程。 | `-XX:+CMSConcurrentMTEnabled` |
| 设置用于并发阶段的并行线程数。 | `-XX:ConcGCThreads=2` |
| 设置要用于停止世界阶段的并行线程数。 | `-XX:ParallelGCThreads=2` |
| 您可以启用**增量 CMS**（**iCMS**）模式。 | `-XX:+CMSIncrementalMode` |
| 如果未启用，CMS 将不会清理永久空间。 | `-XX:+CMSClassUnloadingEnabled` |
| 这允许`System.gc()`触发并发收集，而不是整个垃圾收集周期。 | `-XX:+ExplicitGCInvokes\Concurrent` |
| 这允许`System.gc()`触发永久空间的并发收集。 | `‑XX:+ExplicitGCInvokes\ConcurrentAndUnloadsClasses` |

**iCMS** 模式适用于 CPU 数量少的服务器。 不应在现代硬件上使用它。

以下是一些杂项垃圾收集选项：

| **其他垃圾收集选项** | **标志** |
| --- | --- |
| 这将导致 JVM 忽略应用的任何`System.gc()`方法调用。 | `-XX:+DisableExplicitGC` |
| 这是堆中每 MB 可用空间的生存时间（软引用），以毫秒为单位。 | `-XX:SoftRefLRU\PolicyMSPerMB=2000` |
| 这是用于在抛出`OutOfMemory`错误之前限制垃圾收集所用时间的使用策略。 | `-XX:+UseGCOverheadLimit` |
| 这限制了抛出`OutOfMemory`错误之前在垃圾收集中花费的时间比例。与`GCHeapFreeLimit`一起使用。 | `-XX:GCTimeLimit=95` |
| 这将设置在抛出`OutOfMemory`错误之前，完全垃圾收集之后的最小可用空间百分比。与`GCTimeLimit`一起使用。 | `-XX:GCHeapFreeLimit=5` |

最后，这里有一些特定于 G1 的选项。请注意，从 jvm6u26 开始，所有这些都受支持：

| **G1 垃圾收集选项** | **标志** |
| --- | --- |
| 堆区域的大小。默认值是 2048，可接受的范围是 1 MiB 到 32 MiB。 | `-XX:G1HeapRegionSize=16m` |
| 这是置信系数暂停预测启发式算法。 | `-XX:G1ConfidencePercent=75` |
| 这决定了堆中的最小保留空间。 | `-XX:G1ReservePercent=5` |
| 这是每个 MMU 的垃圾收集时间——时间片（毫秒）。 | `-XX:MaxGCPauseMillis=100` |
| 这是每个 MMU 的暂停间隔时间片（毫秒）。 | `-XX:GCPauseIntervalMillis=200` |

**MiB** 代表 **Mebibyte**，它是数字信息的字节倍数。

# 与垃圾收集相关的 Java 方法

让我们看看与垃圾收集相关联的两种特定方法。

# `System.gc()`方法

虽然垃圾收集在 Java 中是自动的，但是您可以显式调用`java.lang.System.gc()`方法来帮助调试过程。此方法不接受任何参数，也不返回任何值。它是一个显式调用，运行 Java 的垃圾收集器。下面是一个示例实现：

```java
System.gc();
System.out.println("Garbage collected and unused memory has been deallocated.");
```

让我们看一个更深入的例子。在下面的代码中，我们首先创建一个实例`Runtime`，使用返回单例的`Runtime myRuntime = Runtime.getRuntime();`。这使我们能够访问 JVM。在打印一些头信息和初始内存统计信息之后，我们创建了大小为`300000`的`ArrayList`。然后，我们创建一个循环来生成`100000`数组列表对象。最后，我们在三个过程中提供输出，要求 JVM 调用垃圾收集器，中间有`1`秒的暂停。以下是源代码：

```java
package MyGarbageCollectionSuite;

import java.util.ArrayList;
import java.util.concurrent.TimeUnit;

public class GCVerificationTest {
  public static void main(String[] args) throws InterruptedException { 
    // Obtain a Runtime instance (to communicate with the JVM)
    Runtime myRuntime = Runtime.getRuntime();

    // Set header information and output initial memory stats
    System.out.println("Garbage Collection Verification Test");
    System.out.println("-----------------------------------------------
    -----------");
    System.out.println("Initial JVM Memory: " + myRuntime.totalMemory() 
    +
      "\tFree Memory: " + myRuntime.freeMemory());

    // Use a bunch of memory
    ArrayList<Integer> AccountNumbers = new ArrayList<>(300000);
    for (int i = 0; i < 100000; i++) {
      AccountNumbers = new ArrayList<>(3000);
      AccountNumbers = null;
    }

    // Provide update with with three passes
    for (int i = 0; i < 3; i++) {
      System.out.println("--------------------------------------");
      System.out.println("Free Memory before collection number " +
        (i+1) + ": " + myRuntime.freeMemory());
      System.gc();
      System.out.println("Free Memory after collection number " +
        (i+1) + ": " + myRuntime.freeMemory());
      TimeUnit.SECONDS.sleep(1); // delay thread 5 second
    }
  }
}
```

从以下输出中可以看到，垃圾收集器在第一次甚至第二次传递期间没有重新分配所有垃圾：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/de97440f-5537-4c83-bb8b-7f99c8a692b1.png)

垃圾收集验证测试

除了使用`System.gc()`方法调用垃圾收集器之外，还有一种替代方法。在我们的例子中，我们可以使用`myRuntime.gc()`，我们早期的单例例子。

# `finalize()`方法

你可以把 Java 的垃圾收集器想象成死亡贩子。当它从记忆中删除某些东西时，它就消失了。这个所谓的死亡贩子并非没有同情心，因为它为每个方法提供了他们最后的遗言。对象通过`finalize()`方法给出他们的最后一句话。如果一个对象有一个`finalize()`方法，垃圾收集器会在移除该对象和释放相关内存之前调用它。该方法不带参数，返回类型为`void`。

`finalize()`方法只调用一次，在运行时可能会有变化，当然，方法是在被删除之前调用的，但是垃圾收集器运行时依赖于系统。例如，如果您有一个运行内存丰富系统的相对较小的应用，则垃圾收集器可能根本不会运行。那么，为什么要包含一个`finalize()`方法呢？覆盖`finalize()`方法被认为是糟糕的编程实践。也就是说，如果需要的话，你可以使用这个方法。实际上，您可以在那里添加代码来添加对对象的引用，以确保垃圾收集器不会删除该对象。同样，这是不可取的。

因为 Java 中的所有对象，甚至是您自己创建的对象，都是`java.lang.Object`的子类，所以 Java 中的每个对象都有一个`finalize()`方法

垃圾收集器虽然复杂，但可能无法按您希望的方式关闭数据库、文件或网络连接。如果您的应用在收集其对象时需要特定的注意事项，您可以覆盖对象的`finalize()`方法

下面是一个示例实现，它演示了当您可能希望覆盖对象的`finalize()`方法时的一个用例：

```java
public class Animal { 
  private static String animalName;
  private static String animalBreed;
  private static int objectTally = 0;

  // constructor
  public Animal(String name, String type) {
    animalName = name;
    animalBreed = type;

    // increment count of object
    ++objectTally;
  }

  protected void finalize() {
    // decrement object count each time this method
    // is called by the garbage collector
    --objectTally;

    //Provide output to user
    System.out.println(animalName + " has been removed from memory.");

    // condition for 1 animal (use singular form)
    if (objectTally == 1) {
      System.out.println("You have " + objectTally + " animal 
      remaining.");
    }

    // condition for 0 or greater than 1 animals (use plural form)
    else {
      System.out.println("You have " + objectTally + " animals 
      remaining.");
    }
  }
}
```

正如您在前面的代码中所看到的，`objectTally`计数在每次创建类型为`Animal`的对象时递增，而在垃圾收集器删除类型为`Animal`的对象时递减。

通常不鼓励覆盖对象的`finalize()`方法。`finalize()`方法通常应声明为`protected`。

# Java9 之前的垃圾收集模式

Java 的垃圾收集对于 Java9 来说并不新鲜，它从 Java 的初始版本就已经存在了，Java 早就有了一个复杂的垃圾收集系统，它是自动的并且在后台运行。通过在后台运行，我们指的是在空闲时间运行的垃圾收集进程。

空闲时间是指输入/输出之间的时间，例如键盘输入、鼠标单击和输出生成之间的时间。

这种自动垃圾收集是开发人员选择 Java 作为编程解决方案的关键因素之一。其他编程语言，如 C#和 Objective-C，在 Java 平台成功之后已经实现了垃圾收集。

在查看当前 Java 平台中对垃圾收集的更改之前，下面让我们先看看下面列出的概念：

*   可视化垃圾收集
*   Java8 中的垃圾收集升级
*   用 Java 编写的案例游戏

# 可视化垃圾收集

将垃圾收集的工作原理以及（也许更重要的是）对它的需求形象化是很有帮助的。考虑以下逐步创建字符串`Garbage`的代码段：

```java
001 String var = new String("G");
002 var += "a";
003 var += "r";
004 var += "b";
005 var += "a";
006 var += "g";
007 var += "e";
008 System.out.println("Your completed String is: " + var + ".");
```

显然，前面的代码生成的输出如下所示：

```java
Your completed String is Garbage.
```

可能不清楚的是，示例代码产生了五个未引用的字符串对象，这在一定程度上是由于字符串是不可变的。如下表所示，对于每一行连续的代码，被引用的对象都会被更新，而另一个对象将变为未被引用：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/ed2d5917-235f-4391-b6b6-6b056b1932d7.jpg)

未引用对象累积

前面列出的未引用对象肯定不会破坏内存库，但它表示大量未引用对象的累积速度有多快。

# Java8 中的垃圾收集升级

从 Java8 开始，默认的垃圾收集算法是并行垃圾收集器。这些改进之一是能够使用以下命令行选项通过删除重复的字符串值来优化堆内存：

```java
-XX:+UseStringDeduplication
```

G1 垃圾收集器在看到字符串时可以查看字符数组。然后，它获取值并将其与新的、弱的字符数组引用一起存储。如果 G1 垃圾收集器发现一个具有相同哈希码的字符串，它将用一个字符一个字符的检查来比较这两个字符串。如果找到匹配项，两个字符串最终都指向同一个字符数组。具体来说，第一个字符串将指向第二个字符串的字符数组。

这种方法可能需要大量的处理开销，只有在认为有益或绝对必要时才应使用。

# 案例研究-用 Java 编写的游戏

多人游戏需要广泛的管理技术，无论是服务器还是客户端系统。JVM 在低优先级线程中运行垃圾收集线程，并定期运行。服务器管理员以前使用了一个增量垃圾收集模式，使用现在已废弃的`-Xincgc`命令行选项，以避免服务器过载时发生服务器暂停。目标是让垃圾收集运行得更频繁，每次执行周期要短得多。

在考虑内存使用和垃圾收集时，在目标系统上使用尽可能少的内存并在可行的范围内限制垃圾收集的暂停是很重要的。这些技巧对于游戏、模拟和其他需要实时性能的应用尤其重要。

JVM 管理存储 Java 内存的堆。默认情况下，JVM 从一个小堆开始，随着其他对象的创建而增长。堆有两个分区：年轻分区和终身分区。最初创建对象时，它们在年轻分区中创建。持久对象被移动到保留分区。对象的创建通常非常快速，只需增加指针即可。年轻分区的处理速度比长期分区快得多。这是很重要的，因为它适用于整个应用，或者在我们的情况下，一个游戏的效率。

对我们来说，监控游戏的内存使用情况以及垃圾收集发生的时间变得非常重要。为了监控垃圾收集，我们可以在启动游戏时添加`verbose`标志（`-verbose:gc`），例如下面的例子：

```java
java -verbose:gc MyJavaGameClass
```

然后 JVM 将为每个垃圾收集提供一行格式化输出。以下是`verbose`GC 输出的格式：

```java
[<TYPE> <MEMORY USED BEFORE> -> MEMORY USED AFTER (TOTAL HEAP SIZE), <TIME>]
```

让我们看两个例子。在第一个例子中，我们看到类型的`GC`，它指的是我们之前讨论过的年轻分区：

```java
[GC 31924K -> 29732K(42234K), 0.0019319 secs]
```

在第二个示例中，`Full GC`表示对内存堆的永久分区执行了垃圾收集操作：

```java
[Full GC 29732K -> 10911K(42234K), 0.0319319 secs]
```

您可以使用`-XX:+PrintGCDetails`选项从垃圾收集器获取更详细的信息，如下所示：

```java
java -verbose:gc -XX:+PrintGCDetails MyJavaGameClass
```

# 新的 Java 平台的垃圾收集

Java 以自动垃圾收集的方式脱颖而出，成为许多程序员的首选开发平台。在其他编程语言中，想要避免手动内存管理是司空见惯的。我们深入研究了垃圾收集系统，包括 JVM 使用的各种方法或算法。Java，从 Release9 开始一直到 Release11，其中包括对垃圾收集系统的一些相关更改。让我们回顾一下最重要的变化：

*   默认垃圾收集
*   废弃的垃圾收集组合
*   统一垃圾收集日志
*   垃圾收集接口
*   G1 的并行完全垃圾收集
*   Epsilon：一个任意低开销的**垃圾收集**（**GC**）

我们将在下面的小节中回顾每一个垃圾收集概念问题。

# 默认垃圾收集

我们之前详细介绍了 Java9 之前的 JVM 使用的以下垃圾收集方法。这些仍然是合理的垃圾收集算法：

*   CMS 垃圾收集
*   串行垃圾收集
*   并行垃圾收集
*   G1 垃圾收集

让我们简要回顾一下这些方法：

*   **CMS 垃圾收集**：CMS 垃圾收集算法使用多线程扫描堆内存。使用这种方法，JVM 标记要删除的对象，然后进行扫描以实际删除它们。
*   **串行垃圾收集**：这种方法在单个线程上使用线程冻结模式。当垃圾收集正在进行时，它会冻结所有其他线程，直到垃圾收集操作结束。由于串行垃圾收集的线程冻结特性，它只适用于非常小的程序。
*   **并行垃圾收集**：这种方法使用多个线程，但冻结应用中所有非垃圾收集线程，直到垃圾收集函数完成，就像串行垃圾收集算法一样
*   **G1 垃圾收集**：这是垃圾收集算法，具有以下特点：
*   与大内存堆一起使用
*   包括将内存堆分割为多个区域
*   与每个堆区域并行进行
*   释放内存时压缩堆空间
*   使用*停止世界*方法进行压实操作
*   根据要收集的垃圾最多的区域来确定区域的优先级

在 Java9 之前，并行垃圾收集算法是默认的垃圾收集器，在 Java9 中，G1 垃圾收集器是 Java 内存管理系统的新默认实现。32 位和 64 位服务器配置都是如此

Oracle 评估 G1 垃圾收集器，主要是由于它的低暂停特性，是一种比并行方法性能更好的垃圾收集方法。这一变化基于以下概念：

*   限制延迟是很重要的
*   最大化吞吐量不如限制延迟重要
*   G1 垃圾收集算法是稳定的

使 G1 垃圾收集方法成为并行方法的默认方法涉及两个假设：

*   使 G1 成为默认的垃圾收集方法将显著增加其使用量。这种增加的使用可能会暴露出在 Java9 之前没有意识到的性能或稳定性问题
*   G1 方法比并行方法更需要处理器。在某些用例中，这可能有点问题。

从表面上看，这一变化对于 Java9 来说似乎是一个伟大的进步，很可能就是这样。但是，当盲目接受这种新的默认收集方法时，应该谨慎使用。如果切换到 G1，建议对系统进行测试，以确保应用不会因使用 G1 而出现性能下降或意外问题。如前所述，G1 并没有从并行方法的广泛测试中获益。

关于缺乏广泛测试的最后一点意义重大。使用 Java9 将 G1 作为默认的自动内存管理（垃圾收集）系统等同于将开发人员变成毫无戒备的测试人员。虽然预计不会出现大的问题，但了解到在使用 G1 和 Java9 时可能会出现性能和稳定性问题，将更加强调测试 Java9 应用。

# 废弃的垃圾收集组合

Oracle 在将特性、API 和库从 Java 平台的新版本中删除之前，一直非常重视这些特性、API 和库。有了这个模式，在 Java8 中被贬低的语言组件就可以在 Java9 中被删除。在 Java8 中，有一些垃圾收集组合被认为很少使用和被贬低

下面列出的这些组合已在 Java9 中删除：

*   DefNew + CMS
*   ParNew + SerialOld
*   增量 CMS

这些组合除了很少使用之外，还为垃圾收集系统带来了不必要的复杂性。这导致了系统资源的额外消耗，而没有为用户或开发人员提供相应的好处

以下列出的垃圾收集配置受 Java8 平台中上述废弃的影响：

| **垃圾收集配置** | **标志** |
| --- | --- |
| DefNew + CMS | `-XX:+UseParNewGC` |
| | `-XX:UseConcMarkSweepGC` |
| ParNew + SerialOld | `-XX:+UseParNewGC` |
| ParNew + iCMS | `-Xincgc` |
| ParNew + iCMS | `-XX:+CMSIncrementalMode` |
| | `-XX:+UseConcMarkSweepGC` |
| Defnew + iCMS | `-XX:+CMSIncrementalMode` |
| | `-XX:+UseConcMarkSweepGC` |
| | `-XX:-UseParNewGC` |

随着 Java9 的发布，JDK8 中的垃圾收集组合被删除，这些组合与控制这些组合的标志一起列出。此外，启用 CMS 前台集合的标志已被删除，并且在 JDK9 中不存在。这些标志如下所示：

| **垃圾收集组合** | **标志** |
| --- | --- |
| CMS 前景 | `-XX:+UseCMSCompactAtFullCollection` |
| CMS 前景 | `-XX+CMSFullGCsBeforeCompaction` |
| CMS 前景 | `-XX+UseCMSCollectionPassing` |

删除已废弃的垃圾收集组合的唯一缺点是，使用带有本节中列出的任何标志的 JVM 启动文件的应用将需要修改其 JVM 启动文件以删除或替换旧标志。

# 统一垃圾收集日志记录

统一 GC 日志记录是 JDK9 增强的一部分，旨在使用统一 JVM 日志记录框架重新实现垃圾收集日志记录。因此，让我们首先回顾一下统一 JVM 日志记录计划。

# 统一 JVM 日志记录

为 JVM 创建统一的日志模式包括以下目标的高级列表：

*   为所有日志操作创建一组 JVM 范围的命令行选项。
*   使用分类标签进行日志记录。
*   提供六个级别的日志记录，如下所示：
*   错误
*   警告
*   信息
*   调试
*   跟踪
*   开发

这不是一个详尽的目标清单。我们将在第 14 章“命令行标志”中更详细地讨论 Java 的统一日志模式。

在日志记录上下文中，对 JVM 的更改可以分为：

*   标签
*   水平
*   装饰
*   输出
*   命令行选项

让我们简单地看一下这些类别。

# 标签

日志标记在 JVM 中标识，如果需要，可以在源代码中更改。标签应该是自识别的，例如用于垃圾收集的`gc`。

# 级别

每个日志消息都有一个关联的级别。如前所列，级别包括错误、警告、信息、调试、跟踪和开发。下图显示了级别的详细程度如何随着记录的信息量的增加而增加：

![](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/ms-java11/img/342051ac-be35-43f1-89fa-175d5ff0ddd8.jpg)

冗长程度

# 装饰

在 Java 日志框架的上下文中，装饰是关于日志消息的元数据。以下是按字母顺序排列的可用装饰品列表：

*   `level`
*   `pid`
*   `tags`
*   `tid`
*   `time`
*   `timemillis`
*   `timenanos`
*   `uptime`
*   `uptimemillis`
*   `uptimenanos`

有关这些装饰的说明，请参阅第 14 章、“命令行标志”。

# 输出

Java9 日志框架支持三种类型的输出：

*   `stderr`：向`stderr`提供输出
*   `stdout`：向`stdout`提供输出
*   文本文件：将输出写入文本文件

# 命令行选项

通过命令行控制 JVM 的日志操作。`-Xlog`命令行选项有大量的参数和可能性。下面是一个例子：

```java
-Xlog:gc+rt*=debug
```

在本例中，我们告诉 JVM 执行以下操作：

*   记录至少带有`gc`和`rt`标记的所有消息
*   使用`debug`水平
*   向`stdout`提供输出

# 统一 GC 日志记录

现在我们已经对 Java 的日志框架的变化有了大致的了解，让我们看看引入了哪些变化。在本节中，我们将了解以下方面：

*   垃圾收集日志记录选项
*   `gc`标签
*   宏
*   其他注意事项

# 垃圾收集日志记录选项

下面是我们在引入 Java 日志框架之前可以使用的垃圾收集日志选项和标志的列表：

| **垃圾收集日志记录选项** | **JVM 选项标志** |
| --- | --- |
| 这将打印基本的垃圾收集信息。 | `-verbose:gc`或`-XX:+PrintGC` |
| 这将打印更详细的垃圾收集信息。 | `-XX:+PrintGCDetails` |
| 您可以打印每个垃圾收集事件的时间戳。秒是连续的，从 JVM 开始时间开始。 | `-XX:+PrintGCTimeStamps` |
| 您可以为每个垃圾收集事件打印日期戳。样本格式：`2017-07-26T03:19:00.319+400:[GC .  .  . ]` | `-XX:+PrintGCDateStamps` |
| 您可以使用此标志打印单个垃圾收集工作线程任务的时间戳。 | `-XX:+PrintGC\TaskTimeStamps` |
| 使用此选项，可以将垃圾收集输出重定向到文件而不是控制台。 | `-Xloggc:` |
| 您可以在每个收集周期之后打印有关年轻空间的详细信息。 | `-XX:+Print\TenuringDistribution` |
| 可以使用此标志打印 TLAB 分配统计信息。 | `-XX:+PrintTLAB` |
| 使用此标志，您可以打印`Stop the World`暂停期间的参考处理时间（即弱、软等）。 | `-XX:+PrintReferenceGC` |
| 此报告垃圾收集是否正在等待本机代码取消固定内存中的对象。 | `-XX:+PrintJNIGCStalls` |
| 每次*停止*暂停后，打印暂停摘要。 | `-XX:+PrintGC\ApplicationStoppedTime` |
| 此标志将打印垃圾收集的每个并发阶段的时间。 | `-XX:+PrintGC\ApplicationConcurrentTime` |
| 使用此标志将在完全垃圾收集后打印类直方图。 | `-XX:+Print\ClassHistogramAfterFullGC` |
| 使用此标志将在完全垃圾收集之前打印类直方图。 | `-XX:+Print\ClassHistogramBeforeFullGC` |
| 这将在完全垃圾收集之后创建一个堆转储文件。 | `-XX:+HeapDump\AfterFullGC` |
| 这将在完全垃圾收集之前创建一个堆转储文件。 | `-XX:+HeapDump\BeforeFullGC` |
| 这将在内存不足的情况下创建堆转储文件。 | `-XX:+HeapDump\OnOutOfMemoryError` |
| 您可以使用此标志指定要在系统上保存堆转储的路径。 | `-XX:HeapDumpPath=<path>` |
| 如果`n >= 1`，您可以使用它来打印 CMS 统计信息。仅适用于 CMS。 | `-XX:PrintCMSStatistics=2` |
| 这将打印 CMS 初始化详细信息。仅适用于 CMS。 | `-XX:+Print\CMSInitiationStatistics` |
| 您可以使用此标志打印有关可用列表的其他信息。仅适用于 CMS。 | `-XX:PrintFLSStatistics=2` |
| 您可以使用此标志打印有关可用列表的其他信息。仅适用于 CMS。 | `-XX:PrintFLSCensus=2` |
| 您可以使用此标志在升级（从年轻到终身）失败后打印详细的诊断信息。仅适用于 CMS。 | `-XX:+PrintPromotionFailure` |
| 当升级（从年轻到终身）失败时，此标志允许您转储有关 CMS 旧代状态的有用信息。仅适用于 CMS。 | `-XX:+CMSDumpAt\PromotionFailure` |
| 当使用`-XX:+CMSDumpAt\PromotionFailure`标志时，您可以使用`-XX:+CMSPrint\ChunksInDump`来包含关于空闲块的附加细节。仅适用于 CMS。 | `-XX:+CMSPrint\ChunksInDump` |
| 当使用`-XX:+CMSPrint\ChunksInDump`标志时，您可以使用`-XX:+CMSPrint\ObjectsInDump`标志包含有关已分配对象的附加信息。仅适用于 CMS。 | `-XX:+CMSPrint\ObjectsInDump` |

# `gc`标签

我们可以使用带有`-Xlog`选项的`gc`标记来通知 JVM 在`info`级别只记录`gc`标记的项。您还记得，这类似于使用`-XX:+PrintGC`。使用这两个选项，JVM 将为每个垃圾收集操作记录一行。

值得注意的是，`gc`标签并非单独使用，而是建议与其他标签一起使用。

# 宏

我们可以创建宏，以向垃圾收集日志记录添加逻辑。以下是`log`宏的一般语法：

```java
log_<level>(Tag1[,...])(fmtstr, ...)
```

以下是一个`log`宏的例子：

```java
log_debug(gc, classloading)("Number of objects loaded: %d.", object_count)
```

下面的示例框架`log`宏显示了如何使用新的 Java 日志框架来创建脚本，以提高日志记录的逼真度：

```java
LogHandle(gc, rt, classunloading) log;

if (log.is_error()) {
  // do something specific regarding the 'error' level
}

if (log.is_warning()) {
  // do something specific regarding the 'warning' level
}

if (log.is_info()) {
  // do something specific regarding the 'info' level
}

if (log.is_debug()) {
  // do something specific regarding the 'debug' level
}

if (log.is_trace()) {
  // do something specific regarding the 'trace' level
}
```

# 其他注意事项

以下是关于垃圾收集日志记录需要考虑的一些附加项目：

*   使用新的`-Xlog:gc`应该会产生与`-XX:+PrintGCDetails`命令行选项和标志配对类似的结果
*   新的`trace`级别提供了以前使用`verbose`标志提供的详细级别

# 垃圾收集接口

对 Java 垃圾收集的改进并没有随着 Java8 和 Java9 中的主要变化而停止。在 Java10 中，引入了一个干净的垃圾收集器接口。新接口的目标是增加特定于 HotSpot JVM 的内部垃圾收集代码的模块化。增加的模块化将使新接口更容易更新，而不会对核心代码库产生负面影响。另一个好处是相对容易地从 JDK 构建中排除垃圾收集。

在 Java10 之前，垃圾收集实现在 JVM 的整个文件结构中都是源代码。清理这些代码以使代码模块化是优化 Java 代码库和使垃圾收集现代化的一个自然步骤，这样可以更容易地更新和使用。

在 Java 中，垃圾收集器实现了`CollectedHeap`类，该类管理 JVM 和垃圾收集操作之间的交互

新的垃圾收集接口值得注意，但最适用于垃圾收集和 JVM 开发人员

# G1 的并行完全垃圾收集

正如本章前面提到的，G1 垃圾收集器自 Java9 以来一直是默认的垃圾收集器。G1 垃圾收集器的效率之一是它使用并发垃圾收集而不是完全收集。有时会实现完全垃圾收集，通常是并发垃圾收集速度不够快。注意，在 Java9 之前，并行收集器是默认的垃圾收集器，是一个并行的完全垃圾收集器。

对于 Java10，G1Full 垃圾收集器被转换为并行，以减轻对使用完全垃圾收集的开发人员的任何负面影响。将用于 G1 完全垃圾收集的 mark-week 压缩算法并行化。

# Epsilon–任意低开销 GC

Java 的最新版本 11 附带了一个负责内存分配的被动 GC。这个 GC 的被动性质（称为 EpsilonGC）表明它不执行垃圾收集；相反，它继续分配内存，直到堆上没有剩余空间为止。这时，JVM 关闭。

为了启用 Epsilon GC，我们使用以下任一方法：

*   `-XX:+UseEpsilonGC`
*   `-XX:+UseNoGC`

EpsilonGC 的使用主要出现在测试中，由于缺乏垃圾收集，它的开销很低，提高了测试效率

# 长期存在的问题

即使有了 Java9、10 和 11 的现代版本，Java 的垃圾收集系统也有缺点，因为它是一个自动过程，所以我们不能完全控制收集器的运行时间。作为开发人员，我们不能控制垃圾收集，JVM 是。JVM 决定何时运行垃圾收集。正如您在本章前面所看到的，我们可以要求 JVM 使用`System.gc()`方法运行垃圾收集。尽管我们使用了这种方法，但我们不能保证我们的请求会得到满足，也不能保证我们的请求会及时得到满足

在本章前面，我们回顾了垃圾收集的几种方法和算法。我们讨论了作为开发人员如何控制流程。这假设我们有能力控制垃圾收集。即使我们指定了一种特定的垃圾收集技术（例如，将`-XX:+UseConcMarkSweepGC`用于 CMS 垃圾收集），我们也不能保证 JVM 将使用该实现。因此，我们可以尽最大努力控制垃圾收集器的工作方式，但是应该记住，JVM 对于如何、何时以及是否发生垃圾收集具有最终的权限

我们缺乏对垃圾收集的完全控制，这突出了在编写高效代码时考虑内存管理的重要性。在下一节中，我们将研究如何编写代码来显式地使对象符合 JVM 垃圾收集的条件。

# 使对象符合垃圾收集的条件

使对象可用于垃圾收集的一种简单方法是将`null`赋给引用该对象的引用变量。让我们回顾一下这个例子：

```java
package MyGarbageCollectionSuite;

public class GarbageCollectionExperimentOne {
  public static void main(String[] args) {
    // Declare and create new object.
    String junk = new String("Pile of Junk");

    // Output to demonstrate that the object has an active
    // reference and is not eligible for garbage collection.
    System.out.println(junk);

    // Set the reference variable to null. 
    junk = null;

    // The String object junk is now eligible for garbage collection.
  }
}
```

如在代码注释中所示，一旦字符串对象引用变量设置为`null`，在本例中使用`junk = null;`语句，对象就可以进行垃圾收集。

在我们的下一个示例中，我们将通过将对象的引用变量设置为指向另一个对象来放弃该对象。正如您在以下代码中看到的，这导致第一个对象可用于垃圾收集：

```java
package MyGarbageCollectionSuite; 

public class GarbageCollectionExperimentTwo {
  public static void main(String[] args) {
    // Declare and create the first object.
    String junk1 = new String("The first pile of Junk");

    // Declare and create the second object.
    String junk2 = new String("The second pile of Junk");

    // Output to demonstrate that both objects have active references
    // and are not eligible for garbage collection.
    System.out.println(junk1);
    System.out.println(junk2);

    // Set the first object's reference to the second object.
    junk1 = junk2;

    // The String "The first pile of Junk" is now eligible for garbage 
    //collection.
  }
}
```

让我们回顾一下使对象可用于垃圾收集的最后一种方法。在本例中，我们有一个实例变量（`objectNbr`，它是`GarbageCollectionExperimentThree`类实例的引用变量。这个类除了为`GarbageCollectionExperimentThree`类的实例创建额外的引用变量之外，没有做任何有趣的事情。在我们的示例中，我们将`objectNbr2`、`objectNbr3`、`objectNbr4`和`objectNbr5`引用设置为`null`。尽管这些对象有实例变量并且可以相互引用，但是通过将它们的引用设置为`null`，它们在类之外的可访问性已经终止。这使得它们（`objectNbr2`、`objectNbr3`、`objectNbr4`和`objectNbr5`有资格进行垃圾收集：

```java
package MyGarbageCollectionSuite;

public class GarbageCollectionExperimentThree 
 {
  // instance variable
  GarbageCollectionExperimentThree objectNbr;

  public static void main(String[] args) {
    GarbageCollectionExperimentThree objectNbr2 = new 
    GarbageCollectionExperimentThree();
    GarbageCollectionExperimentThree objectNbr3 = new 
    GarbageCollectionExperimentThree();
    GarbageCollectionExperimentThree objectNbr4 = new 
    GarbageCollectionExperimentThree();
    GarbageCollectionExperimentThree objectNbr5 = new 
    GarbageCollectionExperimentThree();
    GarbageCollectionExperimentThree objectNbr6 = new 
    GarbageCollectionExperimentThree();
    GarbageCollectionExperimentThree objectNbr7 = new 
    GarbageCollectionExperimentThree();

    // set objectNbr2 to refer to objectNbr3
    objectNbr2.objectNbr = objectNbr3;

    // set objectNbr3 to refer to objectNbr4
    objectNbr3.objectNbr = objectNbr4;

    // set objectNbr4 to refer to objectNbr5
    objectNbr4.objectNbr = objectNbr5;

    // set objectNbr5 to refer to objectNbr2
    objectNbr5.objectNbr = objectNbr2;

    // set selected references to null
    objectNbr2 = null;
    objectNbr3 = null;
    objectNbr4 = null;
    objectNbr5 = null;
  }
}
```

# 总结

在本章中，我们深入回顾了垃圾收集作为一个关键的 Java 平台组件。我们的综述包括对象生命周期、垃圾收集算法、垃圾收集选项以及与垃圾收集相关的方法。我们研究了 Java8、9、10 和 11 中对垃圾收集的升级，并研究了一个案例来帮助我们理解现代垃圾收集。

然后，我们将重点转向新的 Java9 平台对垃圾收集的更改。我们在 Java 中对垃圾收集的探索包括默认垃圾收集、废弃的垃圾收集组合和统一的垃圾收集日志记录。我们通过查看一些即使在最新版本的 Java 中仍然存在的垃圾收集问题来结束对垃圾收集的探索。

在下一章中，我们将研究如何使用 **Java 微基准线束**（**JMH**）编写性能测试，这是一个用于编写 JVM 基准测试的 Java 线束库。

# 问题

1.  列举五种垃圾收集算法。
2.  什么是 G1？
3.  iCMS 的用途是什么？
4.  什么是 MiB？
5.  如何显式调用垃圾收集？
6.  如何将`finalize()`方法添加到自定义对象？
7.  以下垃圾收集组合有什么共同点？
    1.  DefNew + CMS
    2.  ParNew + Serial
    3.  旧的增量 CMS
8.  在 Java 中，由垃圾收集器实现的哪个类管理 JVM 和垃圾收集操作之间的交互？
9.  Java10 中对 g1fullgc 做了哪些更改？
10.  Java11 中引入的被动 GC 的名称是什么？

# 进一步阅读

以下参考资料将帮助您深入了解本章中介绍的概念：

*   《Java EE 8 高性能》【视频】在[这个页面](https://www.packtpub.com/application-development/java-ee-8-high-performance-video)提供。