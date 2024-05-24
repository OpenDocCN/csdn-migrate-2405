# 谷歌 Web 工具包：GWT（一）

> 原文：[`zh.annas-archive.org/md5/4648A16837179E5128074558BBE7AB6A`](https://zh.annas-archive.org/md5/4648A16837179E5128074558BBE7AB6A)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

客户端-服务器架构在短时间内发生了巨大变化。以前，每个应用程序都有不同的客户端软件，软件充当 UI。这些软件必须单独安装在每个客户端上，并且每次我们对应用程序进行更改时都需要进行更新。我们从那里转移到了网络时代，并在互联网上部署应用程序，然后互联网使我们能够使用无处不在的 Web 浏览器从任何地方访问我们的应用程序。这是一个巨大的变化，但我们仍然存在性能问题，应用程序没有与桌面应用程序相同的感觉或响应。然后出现了 AJAX，现在我们可以构建可以与桌面应用程序一样具有响应性和漂亮外观的网页。AJAX 支撑着当前称为 Web 2.0 的互联网应用程序开发的趋势。为了构建 Ajax 化的应用程序，您至少需要了解 HTML、XML 和 JavaScript。

Google Web Toolkit（GWT）使使用 Java 编程语言设计 AJAX 应用程序变得更加容易。它是一个开源的 Java 开发框架，最好的特点是我们不必太担心不同的网络浏览器和平台之间的不兼容性。在 GWT 中，我们用 Java 编写代码，然后 GWT 将其转换为符合浏览器的 JavaScript 和 HTML。这非常有帮助，因为我们不必再担心模块化编程。它提供了一个类似于使用 Swing、AWT 或 SWT 等 GUI 工具包构建 Java 应用程序的开发人员所使用的编程框架。GWT 提供了所有常见的用户界面小部件，监听器以对小部件中发生的事件做出反应，并将它们组合成更复杂的小部件以执行 GWT 团队可能从未设想过的操作！此外，它使得重用程序块变得容易。这大大减少了您需要掌握的不同技术的数量。如果您了解 Java，那么您可以使用您喜欢的 IDE（本书中使用 Eclipse）来使用 Java 编写和调试 AJAX GWT 应用程序。是的，这意味着您实际上可以在代码中设置断点，并且可以从客户端无缝地调试到服务器端。您可以在任何 servlet 容器中部署应用程序，创建和运行单元测试，并基本上像任何 Java 应用程序一样开发 GWT 应用程序。因此，请开始阅读本书，启动 Eclipse，并进入令人惊叹的 AJAX 和 GWT 编程世界！

在本书中，我们将从下载和安装 GWT 开始，然后逐步介绍创建、测试、调试和部署 GWT 应用程序。我们将创建许多高度交互和有趣的用户界面。我们还将自定义小部件，并使用 JSNI 将 GWT 与其他库（如 Rico 和 Moo.fx）集成。我们还将学习创建自定义小部件，并创建一个日历和一个天气小部件。我们将探索 GWT 中的 I18N 和 XML 支持，创建单元测试，并最终学习如何将 GWT 应用程序部署到诸如 Tomcat 之类的 servlet 容器中。本书采用了典型的基于任务的模式，首先展示如何实现任务，然后解释其工作原理。

# 本书内容

第一章介绍了 GWT，下载和安装 GWT 以及运行其示例应用程序。

第二章介绍了从头开始创建一个新的 GWT 应用程序，使用 Eclipse IDE 与 GWT 项目，创建一个新的 AJAX 随机引用应用程序，并运行新应用程序。

第三章介绍了 GWT 异步服务的概述和介绍，以及创建素数服务和地理编码服务。

第四章涉及使用 GWT 构建简单的交互式用户界面。本章包括的示例有实时搜索、自动填充表单、可排序的表格、动态列表和类似 flickr 的可编辑标签。

第五章介绍了 GWT 的一些更高级的功能，用于构建更复杂的用户界面。本章包括的示例有可分页的表格、可编辑的树节点、简单的日志监视器、便利贴和拼图游戏。

第六章包括对 JavaScript 本地接口（JSNI）的介绍，以及使用它来包装第三方 JavaScript 库，如`Moo.fx`和`Rico`。它还包括使用 gwt-widgets 项目及其对`Script.aculo.us`效果的支持。

第七章涉及创建自定义的 GWT 小部件。本章包括的示例有一个日历小部件和一个天气小部件。

第八章涉及为 GWT 服务和应用程序创建和运行单元测试。

第九章介绍了我们在 GWT 中使用国际化（I18N）和客户端 XML 支持。

第十章包括使用 Ant 和 Eclipse 部署 GWT 应用程序。

# 您需要为本书做好准备

*GWT 需要安装 Java SDK*。它可以从以下网站下载：[`java.sun.com/javase/downloads/`](http://java.sun.com/javase/downloads/)。与 GWT 兼容的最安全版本是 Java 1.4.2。不同版本的 GWT 适用于不同的操作系统，因此您可以使用您喜欢的操作系统而不会遇到任何麻烦。

# 约定

在本书中，您会发现一些文本样式，用于区分不同类型的信息。以下是一些这些样式的示例，以及它们的含义解释。

代码有三种样式。文本中的代码单词显示如下：“`GWT_HOME`目录包含一个带有七个应用程序的`samples`文件夹。”

代码块将设置如下：

```java
public interface PrimesService extends RemoteService
{
public boolean isPrimeNumber(int numberToVerify);
}

```

当我们希望引起您对代码块的特定部分的注意时，相关的行或项目将被加粗：

```java
calendarPanel.add(calendarGrid);
calendarPanel.add(todayButton);

```

任何命令行输入和输出都将按照以下方式编写：

```java
applicationCreator.cmd -out <directory location>\GWTBook\HelloGWT com.packtpub.gwtbook.HelloGWT.client.HelloGWT 

```

**新术语**和**重要单词**以粗体字体引入。例如，屏幕上看到的单词，如菜单或对话框中的单词，会在我们的文本中出现，如：“单击**点击我**按钮，您将获得带有您消息的窗口。”

### 注意

警告或重要提示会以这样的方式出现在一个框中。

### 注意

提示和技巧会以这种方式出现。


# 第一章：入门

**Google Web Toolkit**（**GWT**）是一种革命性的构建**异步 JavaScript 和 XML**（**AJAX**）应用程序的方式，其响应速度和外观与桌面应用程序相媲美。

在本章中，我们将看到：

+   GWT 简介

+   下载 GWT

+   探索 GWT 示例

+   GWT 许可证

# GWT 简介

**AJAX**应用程序非常适合创建高度交互且提供出色用户体验的 Web 应用程序，同时在功能上与桌面应用程序相媲美，而无需下载或安装任何内容。

AJAX 应用程序将 XML 数据交换与 HTML 和 CSS 相结合，用于为界面设置样式，`XMLHttpRequest`对象用于与服务器应用程序进行异步通信，JavaScript 用于与提供的数据进行动态交互。这使得我们能够构建 Web 2.0 革命的一部分-与桌面应用程序相媲美的应用程序。我们可以使用 AJAX 构建与服务器在后台通信的 Web 页面，而无需重新加载页面。我们甚至可以在不刷新页面的情况下替换显示的网页的不同部分。最后，AJAX 使我们能够将传统的面向桌面的应用程序（如文字处理器、电子表格和绘图程序）通过 Web 提供给用户。

GWT 提供了一个基于 Java 的开发环境，使您能够使用 Java 语言构建 AJAX 应用程序。它封装了`XMLHttpRequest`对象 API，并最小化了跨浏览器问题。因此，您可以快速高效地构建 AJAX 应用程序，而无需过多担心调整代码以在各种浏览器中运行。它允许您利用**标准小部件工具包**（**SWT**）或 Swing 样式编程，通过提供一个使您能够将小部件组合成用户界面的框架来提高生产力并缩短开发时间。这是一种通过利用您对 Java 编程语言的了解和对基于事件的接口开发框架的熟悉来提高生产力并缩短开发时间的好方法。

GWT 提供了一组可立即使用的用户界面小部件，您可以立即利用它们来创建新的应用程序。它还提供了一种通过组合现有小部件来创建创新小部件的简单方法。您可以使用 Eclipse IDE 来创建、调试和单元测试您的 AJAX 应用程序。您可以构建 RPC 服务，以提供可以从您的 Web 应用程序异步访问的某些功能，使用 GWT RPC 框架非常容易。GWT 使您能够轻松地与其他语言编写的服务器集成，因此您可以通过利用 AJAX 框架快速增强您的应用程序，从而提供更好的用户体验。

到本书结束时，您将：

+   了解 GWT 的工作原理

+   快速创建有效的 AJAX 应用程序

+   为您的应用程序创建自定义可重用小部件

+   创建易于从 AJAX 应用程序中使用的后端 RPC 服务

# 基本下载

我们将下载 GWT 及其先决条件，将它们安装到硬盘上，然后运行 GWT 分发的一个示例应用程序，以确保它能正常工作。

## 行动时间-下载 GWT

为了使用 GWT，您需要安装 Java SDK。如果您还没有安装 Java SDK，可以从[`java.sun.com/javase/downloads/`](http://java.sun.com/javase/downloads/)下载最新版本。按照下载提供的说明在您的平台上安装 SDK。

### 注意

Java 1.4.2 是与 GWT 一起使用的最安全的 Java 版本，因为它与该版本完全兼容，您可以确保您的应用程序代码将正确编译。GWT 还适用于 Java 平台的两个较新版本-1.5 和 1.6；但是，您将无法在 GWT 应用程序代码中使用这些版本中引入的任何新功能。

现在，您已经准备好下载 GWT：

1.  GWT 可从 GWT 下载页面（[`code.google.com/webtoolkit/download.html`](http://code.google.com/webtoolkit/download.html)）下载，适用于 Windows XP/2000、Linux 和 Mac OS X 平台。此下载包括 GWT 编译器、托管 Web 浏览器、GWT 类库和几个示例应用程序。

请在下载之前阅读使用条款和条件。最新版本是 1.3 RC 1，发布于 2006 年 12 月 12 日。选择适合您平台的文件。以下是显示 GWT 可用版本的示例窗口：

![下载 GWT 的时间到了](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_01_01.jpg)

1.  将下载的 GWT 分发文件解压到硬盘上。它将在 Windows 上创建一个名为`gwt-windows-xxx`的目录，在 Linux 上创建一个名为`gwt-linux-xxx`的目录，其中`xxx`是下载分发的版本号。我们将把包含解压分发的目录称为`GWT_HOME`。`GWT_HOME`目录包含一个包含七个应用程序的`samples`文件夹。

1.  为了确保 GWT 已正确安装，请通过执行平台的启动脚本（Windows 的可执行脚本扩展名为`.cmd`，Linux 的为`.sh`）来运行平台的`Hello`示例应用程序。

为您的平台执行`Hello-shell`脚本。以下是托管 GWT 浏览器中成功运行`Hello`应用程序的屏幕截图：

![下载 GWT 的时间到了](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_01_02.jpg)

单击**点击我**按钮，您将会得到一个对话框，如下所示：

![下载 GWT 的时间到了](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_01_03.jpg)

### 刚刚发生了什么？

`GWT_HOME`目录包含 GWT 开发所需的所有脚本、文件和库，如下所示：

+   `doc：`该目录包含各种 GWT 类的 API 文档。API 文档以两种格式提供——Google 自定义格式和熟悉的`javadoc`格式。

+   `samples：`包含示例应用程序的目录。

+   `gwt-*.jar：`这些是包含 GWT 类的 Java 库。

+   `index.html：`该文件用作 GWT 的自述文件。它还提供了 GWT 文档的起点，以及指向其他信息来源的指针。

+   `gwt-ll.dll`和`swt-win32-3235.dll：`这些是 Windows 的共享库（仅限 Windows）。

+   `libgwt-11.so, libswt-gtk-3235.so, libswt-mozilla17-profile-gcc3-gtk-3235.so, libswt-mozilla17-profile-gtk-3235.so, libswt-mozilla-gcc3-gtk-3235.so, libswt-mozilla-gtk-3235.so`和`libswt-pi-gtk-3235.so：`这些是 Linux 共享库（仅限 Linux）。

+   `applicationCreator：`这是一个用于创建新应用程序的脚本文件。

+   `junitCreator：`这是一个用于创建新的 JUnit 测试的脚本文件。

+   `projectCreator：`这是一个用于创建新项目的脚本文件。

+   `i18nCreator：`这是一个用于创建国际化脚本的脚本文件。

当您执行`Hello-shell.cmd`时，您启动了 GWT 开发 shell，并将`Hello.html`文件作为其参数提供。开发 shell 然后启动了一个特殊的托管 Web 浏览器，并在其中显示了`Hello.html`文件。托管 Web 浏览器是一个嵌入式 SWT Web 浏览器，它与 Java 虚拟机（JVM）有关联。这使得可以使用 Java 开发环境（如 Eclipse）来调试应用程序的 Java 代码。

这是启动的开发 shell 的屏幕截图：

![刚刚发生了什么？](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_01_04.jpg)

### 还有更多！

您可以在启动时自定义 GWT 开发 shell 提供的几个选项。从命令提示符中在`GWT_HOME`目录下运行开发 shell，以查看各种可用选项：

```java
@java -cp "gwt-user.jar;gwt-dev-windows.jar" com.google.gwt.dev. GWTShell help 

```

您将看到类似于这样的屏幕：

![还有更多！](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_01_05.jpg)

如果您想尝试不同的设置，比如不同的端口号，您可以修改`Hello-shell.cmd`文件以使用这些选项。

GWT 的 Linux 版本包含了用于托管 Web 浏览器的 32 位 SWT 库绑定。为了在 AMD64 等 64 位平台上运行示例或使用 GWT 托管的浏览器，您需要执行以下操作：

+   使用启用了 32 位二进制兼容性的 32 位 JDK。

+   在启动 GWT shell 之前，将环境变量 `LD_LIBRARY_PATH` 设置为您的 GWT 发行版中的 Mozilla 目录。

# 探索 GWT 示例

Google 提供了一组示例应用程序，演示了 GWT 的几个功能。本任务将解释如何运行这些示例之一——`KitchenSink` 应用程序。

## 行动时间——进入 KitchenSink

GWT 发行版提供了七个示例应用程序——`Hello, DynaTable, I18N, JSON, KitchenSink, SimpleXML` 和 `Mail`，每个应用程序都演示了一组 GWT 功能。在这个任务中，我们将探索 `KitchenSink` 示例应用程序，因为它演示了 GWT 提供的所有用户界面小部件。所以，让我们进入 `KitchenSink`：

1.  通过在 `GWT_HOME/samples/KitchenSink` 目录中执行 `KitchenSink-shell` 脚本来为您的平台运行 `KitchenSink` 应用程序。这是 `KitchenSink` 应用程序：![Time for Action—Getting into KitchenSink](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_01_06.jpg)

1.  点击**编译/浏览**按钮。`KitchenSink` 应用程序将自动编译，并且系统浏览器将启动并显示 `KitchenSink` 应用程序。

1.  通过单击左侧导航树中的每个小部件名称来探索应用程序。右侧的框架将显示所选小部件及其变体。我们将在以后的任务中使用大多数这些小部件来构建 AJAX 应用程序。

1.  您可以将 `KitchenSink` 示例作为 Eclipse 项目添加到您的工作区，并浏览最终由 GWT 编译成 HTML 和 JavaScript 的 Java 源代码。我们可以使用 GWT 提供的 `projectCreator` 文件辅助脚本来生成 `KitchenSink` 应用程序的 Eclipse 项目文件。

1.  导航到您的 `GWT_HOME` 目录，并在命令提示符中运行以下命令。

```java
projectCreator.cmd -eclipse -ignore -out samples\KitchenSink 

```

这将创建 Eclipse 平台项目文件，可以导入到您的 Eclipse 工作区中。在下一章中，当我们从头开始创建一个新应用程序时，我们将更多地了解这个脚本。

1.  将 `samples/KitchenSink/.project` 文件导入到您的 Eclipse 工作区中。您可以按照上述步骤为每个示例项目生成其 Eclipse 项目文件，然后将其导入到您的工作区。这是一个显示 `KitchenSink.java` 文件的 Eclipse 工作区：![Time for Action—Getting into KitchenSink](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_01_07.jpg)

如果您知道如何使用 Java 编程，您可以使用 GWT 构建 AJAX 应用程序，而不需要了解 `XMLHttpRequest` 对象 API 的复杂性，也不需要了解 `XMLHttpRequest` 对象 API 在各种浏览器中的差异。

### 刚刚发生了什么？

GWT 开发 shell 启动，并在其中运行托管 Web 浏览器，其中运行着 `KitchenSink` 应用程序。该 shell 包含一个嵌入式版本的 Tomcat servlet 容器，监听在端口 8888 上。当您在 Web 模式下运行时，应用程序将从 Java 编译为 HTML 和 JavaScript。编译后的应用程序存储在 `KitchenSink/www` 目录中，并且该目录本身被注册为 Tomcat 的 Web 应用程序。这就是 Tomcat 能够为请求的 Web 浏览器提供应用程序的原因。

只要开发 shell 在运行，您甚至可以使用其他外部 Web 浏览器通过 URL `http://localhost:8888/com.google.gwt.sample.kitchensink.KitchenSink/KitchenSink.html` 连接到 `KitchenSink` 应用程序。

然而，当我们使用外部浏览器连接到开发 shell 时，我们无法使用断点，因此失去了在使用托管浏览器运行应用程序时提供的调试功能。为了从另一台计算机访问应用程序，请确保您使用可解析 DNS 的机器名称或机器的 IP 地址，而不是 localhost。

GWT 由四个主要组件组成，这些组件层叠在一起，为使用工具包编写 AJAX 应用程序提供了框架：

+   **GWT Java-to-JavaScript 编译器：**您可以使用 GWT 编译器将 GWT 应用程序编译为 JavaScript。然后可以将应用程序部署到 Web 容器。这被称为在 Web 模式下运行。当您单击**编译/浏览**按钮时，`KitchenSink`项目的 Java 代码将被 Java-to-JavaScript 编译器编译为纯 HTML 和 JavaScript。生成的构件会自动复制到`KitchenSink/www`文件夹中。

+   **GWT 托管 Web 浏览器：**这使您可以在 Java 虚拟机（JVM）中运行和执行 GWT 应用程序，而无需首先编译为 JavaScript。这被称为在托管模式下运行。GWT 通过嵌入一个特殊的 SWT 浏览器控件来实现这一点，该控件包含对 JVM 的钩子。这个特殊的浏览器在 Windows 上使用 Internet Explorer 控件，在 Linux 上使用 Mozilla 控件。当您运行`KitchenSink`示例时，嵌入的 SWT 浏览器就是您看到显示应用程序的内容。

+   **JRE 仿真库：**这包含了`java.lang`和`java.util`包中大多数常用类的 JavaScript 实现，来自 Java 标准类库。这两个包中的一些常用类得到了支持。JDK 中的其他 Java 包目前不包括在此仿真库中。这些是您可以在 AJAX 应用程序的客户端使用的唯一类。当然，您可以自由地在服务器端实现中使用整个 Java 类库。`KitchenSink`项目中的 Java 代码使用此仿真库编译为 JavaScript。

+   **GWT Web UI 类库：**这提供了一组自定义接口和类，使您能够创建各种小部件，如按钮、文本框、图像和文本。GWT 附带了大多数在 Web 应用程序中常用的小部件。这是提供了`KitchenSink`应用程序中使用的 Java 小部件的类库。

# GWT 许可证

检查 GWT 许可证是否适合您。这些是您需要牢记的主要功能：

+   GWT 是开源的，并在 Apache 开源许可证 2.0 下提供- [`www.apache.org/licenses/`](http://www.apache.org/licenses/)。

+   与 GWT 分发捆绑在一起的第三方库和产品是根据此页面上详细说明的许可证提供的- [`code.google.com/webtoolkit/terms.html#licenses`](http://code.google.com/webtoolkit/terms.html#licenses)。

+   您可以使用 GWT 构建任何类型的应用程序（商业或非商业）。

+   应用程序和应用程序的代码属于应用程序的开发人员，Google 对此没有任何权利。

您可以使用 GWT 构建任何应用程序，并在任何许可下分发该应用程序。您还可以分发由 GWT 生成的 Java、HTML、JavaScript 和任何其他内容，以及用于生成该内容的 GWT 工具，只要您遵循 Apache 许可证的条款。

# 摘要

在本章中，我们了解了 GWT 的基本组件。我们看到了如何下载和安装 GWT，并探索了 GWT 示例应用程序。最后，我们讨论了 GWT 的许可条款。

在下一章中，我们将学习如何从头开始创建一个新的 GWT 应用程序。


# 第二章：创建一个新的 GWT 应用程序

在本章中，我们将使用 GWT 工具生成一个骨架项目结构和文件，有时还会使用 Eclipse 支持。然后，我们将通过修改生成的应用程序来添加功能，最终在托管模式和 Web 模式下运行应用程序。

我们将要处理的任务是：

+   生成一个新应用程序

+   使用 Eclipse 支持生成一个新应用程序

+   创建一个随机引用 AJAX 应用程序

+   在托管模式下运行应用程序

+   在 Web 模式下运行应用程序

# 生成一个新应用程序

我们将使用 GWT 脚本之一生成一个新的 GWT 应用程序。GWT 提供的这些辅助脚本创建了一个带有基本文件夹结构和初始项目文件的 GWT 项目的骨架，以便我们可以尽快开始创建我们的新应用程序。

## 行动时间-使用 ApplicationCreator

GWT 分发包含一个名为`applicationCreator`的命令行脚本，可用于创建一个带有所有必要脚手架的骨架 GWT 项目。要创建一个新应用程序，请按照以下步骤进行：

1.  创建一个名为`GWTBook`的新目录。我们将把这个目录位置称为`GWT_EXAMPLES_DIR`。这个文件夹将包含在本书中执行各种任务时创建的所有项目。

1.  现在创建一个子目录并将其命名为`HelloGWT`。这个目录将包含我们将在本章中创建的新项目的代码和文件。

1.  在命令提示符中提供以下参数运行`GWT_HOME\applicationCreator`：

```java
applicationCreator.cmd -out <directory location>\GWTBook\HelloGWT com.packtpub.gwtbook.HelloGWT.client.HelloGWT 

```

`-out`参数指定所有工件生成在名为`HelloGWT`的目录中。作为最后一个参数提供的完全限定的类名被用作`applicationCreator`脚本生成的类的名称，并标记为此应用程序的`EntryPoint`类（我们将在下一节中介绍`EntryPoint`类）。

上述步骤将在`GWT_EXAMPLES_DIR\HelloGWT`目录中创建文件夹结构并生成多个文件，如下面的屏幕截图所示：

![行动时间-使用 ApplicationCreator](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_02_01.jpg)

### 刚刚发生了什么？

`applicationCreator`脚本调用`gwt‑dev‑xxx.jar`中的`ApplicationCreator`类，后者又创建了文件夹结构并生成了应用程序文件。这使得在新项目上开始变得非常容易，因为整个项目的结构都会自动为您创建。您所需要做的就是开始用您的代码填写应用程序，以提供所需的功能。统一的项目创建方式还确保遵守标准的目录结构，这在您处理不同的 GWT 项目时会更加方便。

当我们运行`applicationCreator`命令时，在`GWT_EXAMPLES_DIR\HelloGWT`目录下自动创建的所有文件和文件夹如下：

+   `src`

+   `HelloGWT-compile.cmd`

+   `HelloGWT-shell.cmd`

**src:** 这个文件夹包含了所有为应用程序生成的源代码和配置文件，以熟悉的 Java 包结构进行组织，根包为`com.packtpub.gwtbook.hellogwt`。这个包名是由`applicationCreator`根据我们提供的完全限定的类名推断出来的。在这个目录下生成的文件有：

+   `com\packtpub\gwtbook\hellogwt\HelloGWT.gwt.xml:` 这是项目模块——一个 XML 文件，包含了 GWT 项目所需的全部配置。`inherits`标签指定了该模块继承的模块。在这个简单的例子中，我们只继承了 GWT 内置的`User`模块提供的功能。在更复杂的项目中，模块继承提供了一种很好的重用功能的方式。`EntryPoint`指的是当模块加载时 GWT 框架将实例化的类。这是在创建项目时提供给`applicationCreator`命令的类名。以下代码可以在这个文件中找到：

```java
<module>
<!-- Inherit the core Web Toolkit stuff.-->
<inherits name="com.google.gwt.user.User"/>
<!-- Specify the app entry point class. -->
<entry-point class=
"com.packtpub.gwtbook.hellogwt.client.HelloGWT"/>
</module>

```

+   `com\packtpub\gwtbook\hellogwt\client\HelloGWT.java:` 这是我们应用程序的入口点。它扩展了`EntryPoint`类，当 GWT 框架加载`HelloGWT`模块时，这个类被实例化，并且它的`onModuleLoad()`方法会被自动调用。在这个生成的类中，`onModuleLoad()`方法创建了一个按钮和一个标签，然后将它们添加到页面上。它还为按钮添加了一个点击监听器。我们将在本章后面修改`HellowGWT.java`中的代码来创建一个新的应用程序。这个文件中的当前代码如下：

```java
package com.packtpub.gwtbook.hellogwt.client;
import com.google.gwt.core.client.EntryPoint;
import com.google.gwt.user.client.ui.Button;
import com.google.gwt.user.client.ui.ClickListener;
import com.google.gwt.user.client.ui.Label;
import com.google.gwt.user.client.ui.RootPanel;
import com.google.gwt.user.client.ui.Widget;
/** Entry point classes define <code>onModuleLoad()</code>. */
public class HelloGWT implements EntryPoint
{
/** This is the entry point method. */
public void onModuleLoad()
{
final Button button = new Button("Click me");
final Label label = new Label();
button.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
if (label.getText().equals(""))
label.setText("Hello World!");
else
label.setText("");
}
}
//Assume that the host HTML has elements defined whose
//IDs are "slot1", "slot2". In a real app, you probably
//would not want to hard-code IDs. Instead, you could,
//for example, search for all elements with a
//particular CSS class and replace them with widgets.
RootPanel.get("slot1").add(button);
RootPanel.get("slot2").add(label);
}

```

+   `com\packtpub\gwtbook\hellogwt\public\HelloGWT.html:` 这是一个生成的 HTML 页面，加载了`HelloGWT`应用程序，并被称为**主机页面**，因为这是托管`HelloGWT`应用程序的网页。尽管这个 HTML 文件看起来非常简单，但有一些需要注意的地方：

+   首先，它包含一个指向`HelloGWT`模块目录的元标记。这个标记是 HTML 页面和`HelloGWT`应用程序之间的连接。以下代码表示了这个连接：

```java
<meta name='gwt:module'
content='com.packtpub.gwtbook.hellogwt.HelloGWT'>

```

+   其次，`script`标签导入了来自`gwt.js`文件的代码。这个文件包含了引导 GWT 框架所需的代码（如下所示）。它使用`HelloGWT.gwt.xml`文件中的配置，然后动态加载通过编译`HelloGWT.java`文件生成的 JavaScript 来呈现应用程序。当我们生成骨架项目时，`gwt.js`文件并不存在。它是在我们在托管模式下运行应用程序或者编译应用程序时由 GWT 框架生成的。

```java
<script language="JavaScript" src="img/gwt.js"></script>

```

+   `HelloGWT-compile.cmd:` 这个文件包含了一个用于将应用程序编译成 HTML 和 JavaScript 的命令脚本。

+   `HelloGWT-shell.cmd:` 这个文件包含了一个用于在托管模式下运行应用程序的命令脚本。

这些生成的文件之间有着明确定义的关系。`HelloGWT.html`文件是加载`gwt.js`文件的主机页面。

### 还有更多！

`applicationCreator`提供了控制新应用程序的几个参数的选项。您可以通过从以下命令行执行它来查看这些选项：

```java
applicationCreator.cmd -help 

```

![There's More!GWTgenerating application, ApplicationCreator used](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_02_02.jpg)

`className`是`applicationCreator`的唯一必需参数。所有其他参数都是可选的。以下是运行`applicationCreator`的一些不同方式：

+   不使用 Eclipse 调试支持创建一个新的应用程序：

```java
applicationCreator.cmd -out C:\GWTBook\Test1 com.packtpub.gwtbook.Test1.client.Test1 

```

+   使用 Eclipse 调试支持创建一个新的应用程序：

```java
applicationCreator.cmd -eclipse -out C:\GWTBook\Test1 com.packtpub.gwtbook.Test1.client.Test1 

```

+   使用 Eclipse 调试支持创建一个新的应用程序，覆盖任何先前生成的同名类：

```java
applicationCreator.cmd -eclipse -overwrite -out C:\GWTBook\Test1 com.packtpub.gwtbook.Test1.client.Test1 

```

Google 建议为 GWT 应用程序的源代码使用以下包命名约定。这将根据其功能将项目代码分离。

+   `client:` 这个包含了所有与客户端相关的应用程序代码。这些代码只能使用 GWT 的`JRE Emulation`库提供的`java.util`和`java.lang`包中的 Java 类。

+   `public：`这包含应用程序所需的所有静态 web 资源，如 HTML 文件、样式表和图像文件。此目录包括主机页面，即包含 AJAX 应用程序的 HTML 文件（在上面的情况下为`HelloGWT.html`）。

+   `server：`这包含服务器端代码。这些类可以使用任何 Java 类和任何 Java 库来提供功能。

应用程序的模块，如`HelloGWT.gwt.xml`必须放在根包目录中，作为客户端、公共和服务器包的同级目录。

# 使用 Eclipse 支持生成新应用程序

GWT 默认支持在 Eclipse IDE 中调试 GWT 应用程序。这是一个非常有用和节省时间的功能。在本节中，我们将学习如何使用 Eclipse IDE 支持创建新应用程序。

## 行动时间-修改 HelloGWT

我们在上一个任务中创建的`HelloGWT`应用程序运行良好，我们可以对其进行修改，并且很容易地运行它。但是，我们没有充分利用 GWT 的最大优势之一-增强整个开发体验的 Eclipse IDE 支持。现在，我们将重新创建相同的`HelloGWT`应用程序，这次作为一个 Eclipse 项目。如果我们可以将上一个任务中创建的项目添加 Eclipse 支持就好了。但是，目前 GWT 不支持这样做。要做到这一点，请按照下一页上给出的步骤进行操作：

1.  GWT 提供了一个`projectCreator`脚本，用于创建 Eclipse 项目文件。使用参数运行脚本，您将看到如下所示的屏幕：

```java
projectCreator.cmd -out E:\GWTBook\HelloGWT -eclipse HelloGWT 

```

![行动时间-修改 HelloGWT](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_02_03.jpg)

1.  现在，使用下面给出的参数再次运行`applicationCreator`，以将 HelloGWT 项目创建为 Eclipse 项目：

```java
applicationCreator.cmd -out E:\GWTBook\HelloGWT -eclipse HelloGWT -overwrite com.packtpub.gwtbook.hellogwt.client.HelloGWT 

```

`-overwrite`参数将覆盖`HelloGWT`目录中的文件和文件夹。因此，如果您进行了任何想要保留的更改，请确保将其复制到其他目录。您将看到如下所示的屏幕：

![行动时间-修改 HelloGWT](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_02_04.jpg)

1.  将新创建的`HelloGWT`项目导入 Eclipse。通过 Eclipse 的**文件|导入**菜单导航到**现有项目到工作区**屏幕。选择**HelloGWT**目录作为根目录，并单击**完成**按钮将项目导入到您的 Eclipse 工作区。现在，您可以在 Eclipse IDE 中编辑、调试和运行应用程序！

1.  完成此任务后创建的所有文件夹和文件如下：![行动时间-修改 HelloGWT](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_02_05.jpg)

### 刚刚发生了什么？

`projectCreator`脚本调用`gwt‑dev‑xxx.jar`中的`ProjectCreator`类，该类又创建 Eclipse 项目文件。然后，`applicationCreator`修改这些文件，添加项目名称和项目的类路径信息。

通过运行`projectCreator`命令创建的特定于 Eclipse 的文件如下：

+   `.classpath：`Eclipse 文件，用于设置项目类路径信息

+   `.project：`Eclipse 项目文件，带有项目名称和构建器信息

+   `HelloGWT.launch：`Eclipse 配置，用于从**运行**和**调试** Eclipse 菜单启动项目

### 还有更多！

以下是从命令行运行`projectCreator`时显示的各种选项的屏幕截图，带有`-help`选项：

```java
projectCreator.cmd -help 

```

![还有更多！GWT 应用程序的 Eclipse IDE](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_02_06.jpg)

# 创建一个随机引用的 AJAX 应用程序

在本节中，我们将创建我们的第一个 AJAX 应用程序，在网页上显示一个随机引用。这个示例应用程序将使我们熟悉 GWT 应用程序中的各种部件和模块，并为本书的其余部分奠定基础。

## 行动时间-修改自动生成的应用程序

我们将通过修改上一个任务中自动生成的应用程序来创建上述应用程序。自动生成的项目结构为我们提供了一个快速入门，并演示了我们可以多快地使用 GWT 框架和工具提高生产力。

随机引用是从服务器上存储的引用列表中选择的。我们的应用程序每秒钟将检索服务器提供的随机引用，并以真正的 AJAX 样式在网页上显示它——无需刷新页面。

1.  在`com.packtpub.gwtbook.hellogwt.client`包中创建一个名为`RandomQuoteService.java`的新的 Java 文件。定义一个`RandomQuoteService`接口，其中包含一个检索引用的方法：

```java
public interface RandomQuoteService extends RemoteService
{
public String getQuote();
}

```

1.  在`com.packtpub.gwtbook.hellogwt.client`包中创建一个名为`RandomQuoteServiceAsync.java`的新的 Java 文件。定义一个`RandomQuoteServiceAsync`接口：

```java
public interface RandomQuoteServiceAsync
{
public void getQuote(AsyncCallback callback);
}

```

1.  在`com.packtpub.gwtbook.hellogwt.server`包中创建一个名为`RandomQuoteServiceImpl.java`的新的 Java 文件。定义一个`RandomQuoteServiceImpl`类，它继承`RemoteService`并实现先前创建的`RandomQuoteService`接口。为这个类添加功能，以便在客户端调用`getQuote()`方法时返回一个随机引用。

```java
public class RandomQuoteServiceImpl extends RemoteServiceServlet implements RandomQuoteService
{
private Random randomizer = new Random();
private static final long serialVersionUID=
-1502084255979334403L;
private static List quotes = new ArrayList();
static
{
quotes.add("No great thing is created suddenly — Epictetus");
quotes.add("Well done is better than well said
— Ben Franklin");
quotes.add("No wind favors he who has no destined port
—Montaigne");
quotes.add("Sometimes even to live is an act of courage
— Seneca");
quotes.add("Know thyself — Socrates");
}
public String getQuote()
return (String) quotes.get(randomizer.nextInt(4));
}

```

这就是我们在服务器上实现功能所要做的全部。现在，我们将修改客户端以访问我们添加到服务器的功能。

1.  修改`HelloGWT.java`以删除现有的标签和按钮，并添加一个用于显示检索到的引用的标签。在`onModuleload()`中添加功能，创建一个定时器，每秒触发一次，并调用`RandomQuoteService`来检索引用，并在上一步中创建的标签中显示它。

```java
public void onModuleLoad()
{
final Label quoteText = new Label();
//create the service
final RandomQuoteServiceAsync quoteService =
(RandomQuoteServiceAsync)GWT.create (RandomQuoteService.class);
//Specify the URL at which our service implementation is //running.
ServiceDefTarget endpoint = (ServiceDefTarget)quoteService; endpoint.setServiceEntryPoint("/");
Timer timer = new Timer()
{
public void run()
{
//create an async callback to handle the result.
AsyncCallback callback = new AsyncCallback()
{
public void onSuccess(Object result)
{
//display the retrieved quote in the label
quoteText.setText((String) result);
}
public void onFailure(Throwable caught)
{
//display the error text if we cant get quote
quoteText.setText("Failed to get a quote.");
}
};
//Make the call.
quoteService.getQuote(callback);
}
};
//Schedule the timer to run once every second
timer.scheduleRepeating(1000);
RootPanel.get().add(quoteText);
}

```

我们现在有客户端应用程序访问服务器来检索引用。

1.  修改`HelloGWT.html`以添加描述我们的 AJAX 应用程序的段落。

```java
<p>
This is an AJAX application that retrieves a random quote from the Random Quote service every second. The data is retrieved and the quote updated without refreshing the page !
application, GWTgenerating, AJAX used</p>

```

1.  通过为标签添加 CSS 使标签看起来更漂亮。在`com.packtpub.gwtbook.hellogwt.public`包中创建一个名为`HelloGWT.css`的新文件，并向其中添加以下样式类声明：

```java
quoteLabel
{
color: white;
display: block;
width: 450px;
padding: 2px 4px;
text-decoration: none;
text-align: center;
font-family: Arial, Helvetica, sans-serif;
font-weight: bold;
border: 1px solid;
border-color: black;
background-color: #704968;
text-decoration: none;
}

```

1.  在`HelloGWT.java`文件中修改标签以使用这种样式：

```java
quoteText.setStyleName("quoteLabel");

```

1.  在`HelloGWT.html`中添加对这个样式表的引用，以便页面可以找到样式表中定义的样式。

```java
<link rel="stylesheet" href="HelloGWT.css">

```

1.  我们要做的最后一件事是在`HelloGWT`模块中注册我们的`RandomQuoteServiceImpl` servlet 类，以便客户端可以找到它。在`HelloGWT.gwt.xml`中添加以下行：

```java
<servlet path="/" class="com.packtpub.gwtbook.hellogwt.server. RandomQuoteServiceImpl"/>

```

这个 servlet 引用将由 GWT 框架在嵌入式 Tomcat servlet 容器中注册，因此当您在托管模式下运行它时，上下文路径`/`被映射，以便所有对它的请求都由`RandomQuoteServiceImpl` servlet 提供。

在完成所有上述修改后，`HelloGWT`项目中的文件夹和文件如下：

![Time for Action—Modifying Auto-Generated Applications](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_02_07.jpg)

我们的第一个 AJAX 应用程序现在已经准备就绪，我们能够完全使用 Java 创建它，而不需要编写任何 HTML 代码！

### 刚刚发生了什么？

我们创建的`RandomQuoteService`接口是我们服务的客户端定义。我们还定义了`RandomQuoteServiceAsync`，它是我们服务的异步版本的客户端定义。它提供了一个回调对象，使服务器和客户端之间可以进行异步通信。`RandomQuoteServiceImpl`是一个实现了这个接口并提供通过 RPC 检索随机引用功能的 servlet。我们将在第三章中详细讨论创建服务。

`HelloGWT.java`创建用户界面——在这种情况下只是一个标签——实例化`RandomQuote`服务，并启动一个计时器，计划每秒触发一次。每次计时器触发时，我们都会异步与`RandomQuoteService`通信以检索引言，并使用引言更新标签。`RootPanel`是 HTML 页面主体的 GWT 包装器。我们将标签附加到它上面，以便显示。

我们通过使用级联样式表修改了标签的外观和感觉，并在`HelloGWT.java`中为标签分配了样式的名称。我们将在第六章中学习如何使用样式表和样式来美化 GWT。

该应用程序中的用户界面非常简单。因此，我们直接将标签添加到`RootPanel`。然而，在几乎任何非平凡的用户界面中，我们都需要更准确地定位小部件并布局它们。我们可以通过利用 GWT UI 框架中的各种布局和面板类轻松实现这一点。我们将在第四章和第五章学习如何使用这些类。

# 在托管模式下运行应用程序

GWT 提供了一种很好的方法来测试应用程序，而无需部署它，而是在托管模式下运行应用程序。在本节中，我们将学习如何在托管模式下运行`HelloGWT`应用程序。

## 执行 HelloGWT-Shell 脚本的操作时间

您可以通过执行`HelloGWT-shell`脚本在托管模式下运行`HelloGWT`应用程序。您可以通过以下三种不同的方式来执行此操作：

+   从 shell 中执行命令脚本：

打开命令提示符并导航到`HelloGWT`目录。运行`HelloGWT-shell.cmd`以在托管模式下启动`HelloGWT`应用程序。

+   从 Eclipse 内部执行命令脚本：

在 Eclipse 的**Package Explorer**或**navigator**视图中双击`HelloGWT-shell.cmd`文件。这将执行该文件并启动托管模式下的`HelloGWT`应用程序。

+   从 Eclipse 中运行`HelloGWT.launcher`：

在 Eclipse 中，通过单击**Run | Run**链接导航到**Run**屏幕。展开**Java Application**节点。选择`HelloGWT`目录。单击**Run**链接以在托管模式下启动`HelloGWT`应用程序。

如果应用程序正常运行，您将看到以下屏幕：

![执行 HelloGWT-Shell 脚本的操作时间](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_02_08.jpg)

### 刚刚发生了什么？

命令脚本通过提供应用程序类名作为参数来执行 GWT 开发 shell。Eclipse 启动器通过创建一个启动配置来模仿命令脚本，该启动配置从 Eclipse 环境中执行 GWT 开发 shell。启动的 GWT 开发 shell 在嵌入式浏览器窗口中加载指定的应用程序，显示应用程序。在托管模式下，项目中的 Java 代码不会被编译为 JavaScript。应用程序代码作为已编译的字节码在 Java 虚拟机中运行。

# 在 Web 模式下运行应用程序

在上一节中，我们学习了如何在托管模式下运行 GWT 应用程序而无需部署它们。这是测试和调试应用程序的好方法。然而，当您的应用程序在生产环境中运行时，它将部署到诸如 Tomcat 之类的 Servlet 容器中。本任务解释了如何编译`HelloGWT`应用程序，以便随后可以部署到任何 Servlet 容器中。在 GWT 术语中，这称为在 Web 模式下运行。

## 执行编译应用程序的操作时间

为了在 Web 模式下运行`HelloGWT`应用程序，我们需要执行以下操作：

1.  首先通过运行`HelloGWT‑compile`脚本编译`HelloGWT`应用程序。

```java
HelloGWT-compile.cmd 

```

1.  上述步骤将在`HelloGWT`目录中创建一个`www`文件夹。导航到`www/com.packtpub.gwt.HelloGWT.HelloGWT`目录。

1.  在 Web 浏览器中打开`HelloGWT.html`文件。

运行`HelloGWT`客户端应用程序所需的一切都包含在`www`文件夹中。您可以将文件夹的内容部署到任何 Servlet 容器，并提供`HelloGWT`应用程序。完成上述步骤后，以下是文件夹的内容：

![操作时间-编译应用程序](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_02_09.jpg)

### 刚刚发生了什么？

`HelloGWT-compile`脚本调用 GWT 编译器，并将`com.packtpub.gwt.hellogwt.client`包中的所有 Java 源代码编译成 HTML 和 JavaScript，并将其复制到`www\com.packtpub.gwt.hellogwt.HelloGWT`目录中。这个目录名是由 GWT 自动创建的，之前提供给`applicationCreator`的完全限定类名中去掉`client`部分。这个文件夹包含了`HelloGWT`客户端应用程序的一个准备部署的版本。它包括：

+   `HelloGWT.html：`作为`HelloGWT`应用程序的主 HTML 页面的主机页面。

+   `gwt.js：`包含用于加载和初始化 GWT 框架的引导代码的生成的 JavaScript 文件。

+   `History.html：`提供历史管理支持的 HTML 文件。

+   `xxx-cache.html`和`xxx-cache.xml：`每个受支持的浏览器生成一个 HTML 和 XML 文件。这些文件包含通过编译`com.packtpub.gwtbook.hellogwt.client`和`com.packtpub.gwtbook.hellogwt.server`包中的源 Java 文件生成的 JavaScript 代码。例如，在这种情况下，在 Windows 上，编译产生了这些文件：

```java
0B0ADCCCE2B7E0273AD2CA032DE172D1.cache.html
0B0ADCCCE2B7E0273AD2CA032DE172D1.cache.xml
224EDC91CDCFD8793FCA1F211B325349.cache.html
224EDC91CDCFD8793FCA1F211B325349.cache.xml
546B5855190E25A30111DE5E5E2005C5.cache.html
546B5855190E25A30111DE5E5E2005C5.cache.xml
D802D3CBDE35D3663D973E88022BC653.cache.html
D802D3CBDE35D3663D973E88022BC653.cache.xml

```

每组 HTML 和 XML 文件代表一个受支持的浏览器：

```java
0B0ADCCCE2B7E0273AD2CA032DE172D1 - Safari
224EDC91CDCFD8793FCA1F211B325349 Mozilla or Firefox
546B5855190E25A30111DE5E5E2005C5 Internet Explorer
D802D3CBDE35D3663D973E88022BC653 - Opera

```

文件名是通过生成**全局唯一标识符**（**GUIDs**）并将 GUID 作为名称的一部分来创建的。这些文件名在不同的计算机上会有所不同，并且每次在您的计算机上进行干净的重新编译时也会有所不同。还有一个生成的主 HTML 文件（`com.packtpub.gwtbook.hellogwt.HelloGWT.nocache.html`），它从上面的文件中选择正确的 HTML 文件并加载它，具体取决于运行应用程序的浏览器。

`www`文件夹不包含`com.packtpub.gwtbook.hellogwt.server`包中的代码。这个服务器代码需要被编译并部署到一个 Servlet 容器中，以便客户端应用程序可以与随机引用服务进行通信。我们将在第十章中学习如何部署到外部 Servlet 容器。在正常的开发模式下，我们将使用托管模式进行测试，该模式在 GWT 开发外壳中的嵌入式 Tomcat Servlet 容器中运行服务器代码。这使得从同一个 Eclipse 环境中运行和调试服务器代码变得非常容易，就像客户端应用程序代码一样。这是 GWT 的另一个特性，使其成为开发 AJAX 应用程序的极其高效的环境。

在 Web 模式下，我们的客户端 Java 代码已经编译成 JavaScript，不同于托管模式。此外，您会注意到`HelloGWT.gwt.xml`不在这个目录中。此模块的配置细节包含在上面生成的 HTML 和 XML 文件中。

在 Web 模式下，我们的客户端 Java 代码已经编译成 JavaScript，不同于托管模式。此外，您会注意到`HelloGWT.gwt.xml`不在这个目录中。此模块的配置细节包含在上面生成的 HTML 和 XML 文件中。

值得庆幸的是，当我们运行`HelloGWT-compile`脚本时，所有这些工作都会被 GWT 框架自动完成。我们可以专注于我们的 AJAX 应用程序提供的功能，并将与浏览器无关的代码生成和较低级别的 XmlHttpRequest API 留给 GWT。

我们将在第十章中学习如何将 GWT 应用程序部署到 Web 服务器和 Servlet 容器。

### 还有更多！

您还可以在托管模式下从 GWT 开发 shell 中编译`HelloGWT`应用程序。运行`HelloGWT-shell`命令脚本以在托管模式下运行应用程序。单击 GWT 开发 shell 窗口中的**编译/浏览**按钮。这将编译应用程序并在单独的 Web 浏览器窗口中启动应用程序。

所有这些动态的 JavaScript 魔法意味着当您尝试从 Web 浏览器查看应用程序的源代码时，您总是会看到来自主机页面的 HTML。当您试图调试问题时，这可能令人不安。但是 GWT 中的出色 Eclipse 支持意味着您可以通过设置断点并逐行浏览整个应用程序来从图形调试器的舒适环境中调试问题！我们将在第八章中了解更多关于 GWT 应用程序的调试。

# 摘要

在本章中，我们使用提供的辅助脚本如`applicationCreator`生成了一个新的 GWT 应用程序。然后为项目生成了 Eclipse 支持文件。我们还创建了一个新的随机引用 AJAX 应用程序。我们看到如何在托管模式和 Web 模式下运行这个新应用程序。

在下一章中，我们将学习如何创建 GWT 服务，这将使我们能够提供可以通过 GWT 应用程序网页通过 AJAX 访问的异步功能。


# 第三章：创建服务

在本章中，我们将学习如何创建服务，这是 GWT 术语用于提供服务器端功能的术语。在 GWT 上下文中使用的术语**服务**与 Web 服务没有任何关系。它指的是客户端在服务器端调用的代码，以便访问服务器提供的功能。我们开发的大多数应用程序都需要访问服务器以检索一些数据或信息，然后使用 AJAX 以直观和非侵入性的方式将其显示给用户。在 GWT 应用程序中实现这一点的最佳方式是通过服务。

在本章中，我们将介绍创建服务所需的必要步骤。我们将首先创建创建一个简单的`素数`服务所需的各种工件，该服务验证提供的数字是否为素数。该应用程序很简单，但是其中的概念适用于您将创建的任何 GWT 服务。我们还将创建一个简单的客户端，用于消费`素数`服务。

我们将要解决的任务是：

+   创建服务定义接口

+   创建异步服务定义接口

+   创建服务实现

+   消费服务

前三个任务需要为您创建的每个 GWT 服务完成。

# 创建服务定义接口

服务定义接口充当客户端和服务器之间的合同。这个接口将由我们稍后在本章中构建的实际服务来实现。它定义了服务应提供的功能，并为希望消费此服务提供的功能的客户端制定了基本规则。

## 行动时间-创建素数服务

我们将为我们的素数服务创建定义。我们还将创建一个名为`Samples`的新项目，以包含本章和本书中创建的代码。

1.  使用`projectCreator`和`applicationCreator`创建一个名为`Samples`的新 Eclipse GWT 项目。将应用程序类的名称指定为`com.packtpub.gwtbook.samples.client.Samples`。

1.  将新创建的项目导入 Eclipse IDE。

1.  在`com.packtpub.gwtbook.samples.client`包中创建一个名为`PrimesService.java`的新 Java 文件。定义一个`PrimesService`接口，其中包含一个验证数字是否为素数的方法。它以整数作为参数，并在验证后返回一个布尔值：

```java
public interface PrimesService extends RemoteService
{
public boolean isPrimeNumber(int numberToVerify);
}

```

### 刚刚发生了什么？

`PrimesService`是一个服务定义接口。它指定了支持的方法以及应该传递给它的参数，以便服务返回响应。在 GWT 上下文中，RPC 这个术语指的是一种通过 HTTP 协议在客户端和服务器之间轻松传递 Java 对象的机制。只要我们的方法参数和返回值使用了支持的类型，GWT 框架就会自动为我们执行此操作。目前，GWT 支持以下 Java 类型和对象：

+   原始类型-字符、字节、短整型、整型、长整型、布尔型、浮点型和双精度型

+   原始类型包装类-字符、字节、短整型、整型、长整型、布尔型、浮点型和双精度型

+   字符串

+   日期

+   任何这些`可序列化`类型的数组

+   实现实现`isSerializable`接口的自定义类，其非瞬态字段是上述支持的类型之一

您还可以使用支持的对象类型的集合作为方法参数和返回类型。但是，为了使用它们，您需要通过使用特殊的`Javadoc`注释`@gwt.typeArgs`明确提到它们预期包含的对象类型。例如，这是我们如何定义一个服务方法，它以整数列表作为输入参数，并返回一个字符串列表：

```java
public interface MyRPCService extends RemoteService
{
/*
* @gwt.typeArgs numbers <java.lang.Integer>
* @gwt.typeArgs <java.lang.String>
*/
List myServiceMethod(List numbers);
}

```

第一个注解表示这个方法只接受一个整数对象列表作为参数，第二个注解表示这个方法的返回参数是一个字符串对象列表。

# 创建一个异步服务定义接口

在上一个任务中创建的接口是同步的。为了利用 GWT 中的 AJAX 支持，我们需要创建这个接口的异步版本，用于在后台向服务器进行远程调用。

## 行动时间-利用 AJAX 支持

在本节中，我们将创建服务定义接口的异步版本。

在`com.packtpub.gwtbook.samples.client`包中创建一个名为`PrimesServiceAsync.java`的新的 Java 文件。定义一个`PrimesServiceAsync`接口：

```java
public interface PrimesServiceAsync
{
public void isPrimeNumber(inr numberToVerify, AsyncCallbackcallback);
}

```

### 刚刚发生了什么？

我们的服务定义接口的异步版本必须具有与同步接口相同的方法，除了所有方法都必须将`AsyncCallback`对象作为参数，并且方法可能不返回任何内容。回调对象充当客户端和服务器之间的绑定。一旦客户端发起异步调用，当服务器端完成处理时，通过此回调对象进行通知。基本上，这就是 AJAX 的魔法发生的地方！你不必为所有这些魔法做任何特殊的事情，只需确保为服务定义提供这个异步接口即可。GWT 框架将自动处理客户端和服务器之间的所有通信。使用此服务的客户端应用程序将通过此方法调用服务，传递一个回调对象，并将自动通过回调到客户端应用程序中的`onSuccess()`方法或`onFailure()`方法来通知成功或失败。当前版本的 GWT 只支持异步回调到服务器。即使服务定义接口是同步的，也不能使用它来对服务器进行同步调用。因此，目前只能通过 AJAX 异步访问使用 GWT 构建的任何服务。

# 创建服务实现

到目前为止，我们已经创建了定义质数服务功能的接口。在本节中，我们将开始实现和填充服务类，并创建质数服务的实际实现。

## 行动时间-实现我们的服务

我们将创建质数服务的实现。它通过确保提供的数字只能被 1 和它自己整除来检查提供的数字是否是质数。验证结果以布尔值返回。

在`com.packtpub.gwtbook.samples.server`包中创建一个名为`PrimesServiceImpl.java`的新的 Java 文件。定义一个`PrimesServiceImpl`类，它扩展`RemoteServiceServlet`并实现先前创建的`PrimesService`接口。为这个类添加功能，以验证提供的数字是否是质数。

```java
public class PrimesServiceImpl extends RemoteServiceServlet
implements PrimesService
{
private static final long serialVersionUID = -8620968747002510678L;
public boolean isPrimeNumber(int numberToVerify)
{
boolean isPrime = true;
int limit = (int) Math.sqrt ( numberToVerify );
for ( int i = 2; i <= limit; i++ )
{
if(numberToVerify % i == 0 )
{
isPrime = false;
break;
}
}
return isPrime;
}
}

```

### 刚刚发生了什么？

由于这是素数服务的实现，这个类需要实现服务定义接口，并为实现的方法添加功能。这个任务和之前的任务勾画出了创建 GWT 服务时总是需要的步骤。创建和使用 RPC 服务是解锁 GWT 强大功能并有效使用它的关键步骤。GWT 应用的基本架构包括在 Web 浏览器中呈现的客户端用户界面，并与作为 RPC 服务实现的服务器端功能进行交互，以异步地检索数据和信息而不刷新页面。在 GWT 应用中，服务包装了应用的服务器端模型，因此通常映射到 MVC 架构中的模型角色。

![发生了什么？](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_03_01.jpg)

让我们来看看我们为一个服务创建的各种类和接口之间的关系。每次我们创建一个 RPC 服务，我们都会利用一些 GWT 框架类，并创建一些新的类和接口。完成上述任务后创建的类和接口如下：

+   `PrimesService：` 我们的服务定义接口。它定义了我们服务中的方法，并扩展了`RemoteService`标记接口，表示这是一个 GWT RPC 服务。这是同步定义，服务器端实现必须实现这个接口。

+   `PrimesServiceAsync：` 我们接口的异步定义。它必须具有与同步接口相同的方法，除了所有方法都必须以`AsyncCallback`对象作为参数，并且方法可能不返回任何内容。建议为这个接口使用的命名约定是在我们的同步接口名称后缀加上`Async`这个词。

+   `PrimesServiceImpl：` 这是我们服务的服务器端实现。它必须扩展`RemoteServiceServlet`并实现我们的同步接口——`PrimesService`。

我们使用的 GWT 框架类来创建`PrimesService：`

+   `RemoteService：` 所有 RPC 服务都应该实现的标记接口。

+   `RemoteServiceServlet：` `PrimesServiceImpl`服务实现类扩展了这个类并添加了所需的功能。这个类支持序列化和反序列化请求，并确保请求调用`PrimesServiceImpl`类中的正确方法。

这里有一个图表，描述了在创建素数服务时涉及的各种类和接口之间的关系。

![发生了什么？](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_03_02.jpg)

我们的服务实现扩展了`RemoteServiceServlet`，它继承自`HttpServlet`类。`RemoteServiceServlet`负责自动反序列化传入的请求和序列化传出的响应。GWT 可能选择使用基于 servlet 的方法，因为它简单，并且在 Java 社区中被广泛认可和使用。它还使得我们的服务实现在任何 servlet 容器之间移动变得容易，并为 GWT 与其他框架之间的各种集成可能性打开了大门。GWT 社区的几位成员已经使用它来实现 GWT 与其他框架（如 Struts 和 Spring）之间的集成。GWT 使用的 RPC wire 格式基本上是基于 JavaScript 对象表示法（JSON）的。这个协议是 GWT 专有的，目前没有文档记录。然而，`RemoteServiceServlet`提供了两个方法——`onAfterResponseSerialized()`和`onBeforeRequestDeserialized()`，你可以重写这些方法来检查和打印序列化的请求和响应。

创建任何 GWT 服务的基本模式和架构总是相同的，包括以下基本步骤：

1.  创建服务定义接口。

1.  创建服务定义接口的异步版本。

1.  创建服务实现类。在服务实现类中，我们访问外部服务提供的功能，并将结果转换为符合我们要求的结果。

在下一节中，我们将创建一个简单的客户端来消费这个新服务。我们将学习如何将此服务部署到外部 servlet 容器，如 Tomcat，在第十章。这个例子中的概念适用于我们创建的每个 GWT 服务。我们将至少为我们创建的每个服务创建这两个接口和一个实现类。这将帮助我们提供可以通过 GWT 客户端以异步方式访问的服务器功能。我们上面创建的服务独立于 GWT 客户端应用程序，并且可以被多个应用程序使用。我们只需要确保在 servlet 容器中正确注册服务，以便我们的客户端应用程序可以访问它。

# 消费服务

我们已经完成了 Prime Number 服务的实现。现在我们将创建一个简单的客户端，可以消费`PrimesService`。这将帮助我们测试服务的功能，以确保它能够完成它应该完成的任务。

## 行动时间-创建客户端

我们将创建一个简单的客户端，连接到 Prime Number 服务，并检查给定的数字是否是质数。我们将添加一个文本框用于输入要检查的数字，以及一个按钮，当点击时将调用服务。它将在警报对话框中显示调用的结果。

1.  在`com.packtpub.gwtbook.samples.client`包中创建一个名为`PrimesClient.java`的新文件，该文件扩展了`EntryPoint`类。

```java
public class PrimesClient implements EntryPoint
{
}

```

1.  在这个新类中添加一个`onModuleLoad()`方法，并创建一个文本框。

```java
public void onModuleLoad()
{
final TextBox primeNumber = new TextBox();
}

```

1.  在`onModuleLoad()`方法中实例化`PrimesService`并将其存储在变量中。

```java
final PrimesServiceAsync primesService =
(PrimesServiceAsync) GWT
GWT.create(PrimesService.class);
ServiceDefTarget endpoint = (ServiceDefTarget) primesService;
endpoint.setServiceEntryPoint(GWT.getModuleBaseURL()+"primes");

```

1.  创建一个新按钮，并添加一个事件处理程序来监听按钮的点击。在处理程序中，使用文本框中输入的文本作为服务的输入参数来调用`PrimesService`。在警报对话框中显示结果。

```java
final Button checkPrime=new Button("Is this a prime number?",
new ClickListener())
{
public void onClick(Widget sender)
{
AsyncCallback callback = new AsyncCallback()
{
public void onSuccess(Object result)
{
if(((Boolean) result).booleanValue())
{
Window.alert("Yes, "+ primeNumber.getText()
+ "' is a prime number.");
}
else
{
Window.alert("No, "+ primeNumber.getText()
+ "' is not a prime number.");
}
}
public void onFailure(Throwable caught)
{
Window.alert("Error while calling the Primes
Service.");
}
};
primesService.isPrimeNumber(Integer
parseInt(primeNumber.getText()), callback);
}
});

```

1.  在应用程序的`module.xml`文件中添加以下条目，以便客户端找到此服务。

```java
<servlet path="/primes" class=
"com.packtpub.gwtbook.samples.server.PrimesServiceImpl"/>

```

这是客户端。输入一个数字，然后点击按钮检查这个数字是否是质数。

![行动时间-创建客户端](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_03_03.jpg)

响应如下显示在警报对话框中：

![行动时间-创建客户端](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_03_04.jpg)

### 刚刚发生了什么？

`Prime Number`服务客户端通过向`PrimesService`传递所需的参数来调用服务。我们在`module.xml`文件中为服务做了一个条目，以便 GWT 框架可以正确初始化并且客户端可以找到服务。我们遵循了创建简单客户端消费 GWT 服务的常见模式：

1.  创建一个实现`EntryPoint`类的类。

1.  重写`onModuleLoad()`方法以添加所需的用户界面小部件。

1.  向用户界面小部件之一添加事件处理程序，以在触发处理程序时调用服务。

1.  在事件处理程序中，处理对服务方法调用的成功和失败的`callbacks`，并对调用结果采取一些操作。

1.  在 GWT 应用程序`module.xml`中添加一个条目以便消费服务。

我们将在本书中创建示例应用程序时使用这种常见模式以及一些变化。

# 总结

在本章中，我们看了一下创建新的 Prime Number GWT 服务所需的各种类和接口。我们还创建了一个可以使用质数服务的客户端。

在下一章中，我们将使用 GWT 创建交互式网络用户界面。


# 第四章：交互式表单

在本章中，我们将学习创建交互式表单的不同方式，这些方式利用 GWT 和 AJAX 在使用基于 Web 的用户界面时提供更加流畅的用户体验。本章以及接下来的两章将为我们探索 GWT 提供基础。

我们将要解决的任务包括：

1.  实时搜索

1.  密码强度检查器

1.  自动填充表单

1.  可排序的表格

1.  动态列表

1.  类似 Flickr 的可编辑标签

# 示例应用程序

我们将把本书中创建的所有示例应用程序都整合到上一章中创建的 Samples GWT 应用程序中。我们将以与我们在第一章中探讨的`KitchenSink`应用程序类似的方式进行。为了做到这一点，我们将按照以下步骤进行：

+   应用程序的用户界面将在一个类中创建，该类扩展了`com.packtpub.gwtbook.samples.client`包中的`SamplePanel`类。

+   然后，该类将被初始化并添加到`com.packtpub.gwtbook.samples.client`包中的`Samples`类的应用程序列表中。由于`Samples`类被设置为入口点类，当 GWT 启动时，它将加载这个类并显示所有示例应用程序，就像`KitchenSink`一样。

所有示例的源代码都可以从本书的下载站点获取。请参阅附录以获取有关下载和运行示例的说明。

# 实时搜索

“实时搜索”是一种用户界面，它会根据用户输入的搜索条件实时提供与之匹配的选择。这是一种非常流行的 AJAX 模式，用于在用户细化搜索查询时持续显示所有有效结果。由于用户的查询不断与显示的结果同步，为用户创造了非常流畅的搜索体验。它还使用户能够以高度互动的方式快速轻松地尝试不同的搜索查询。搜索结果是异步从服务器检索的，无需任何页面刷新或重新提交搜索条件。Google 搜索页面（[`google.com/`](http://google.com/)）就是一个很好的例子。它甚至在您输入时告诉您与您的查询匹配的搜索结果数量！

“实时搜索”AJAX 模式提供的即时反馈也可以用于预先从服务器获取结果并用于预测用户的操作。这种即时响应可以使应用程序的用户体验更加流畅，并显著提高应用程序的延迟。Google 地图（[`maps.google.com/`](http://maps.google.com/)）是使用这种模式预先获取地图数据的很好的例子。

## 行动时间-搜索即时输入！

在这个“实时搜索”示例中，我们将创建一个应用程序，该应用程序检索以您在搜索文本中输入的字母开头的水果名称列表。您可以通过减少或增加输入的字母数量来细化查询条件，用户界面将实时显示匹配的结果集。

1.  在`com.packtpub.gwtbook.samples.client`包中创建一个名为`LiveSearchService.java`的新的 Java 文件。定义一个`LiveSearchService`接口，其中包含一个方法，用于检索与提供的字符串匹配的搜索结果。

```java
public interface LiveSearchService extends RemoteService
{
public List getCompletionItems(String itemToMatch);
}

```

1.  在`com.packtpub.gwtbook.samples.client`包中的一个新的 Java 文件中创建此服务定义接口的异步版本，命名为`LiveSearchServiceAsync.java`：

```java
public interface LiveSearchServiceAsync
{
public void getCompletionItems
(String itemToMatch, AsyncCallback callback);
}

```

1.  在`com.packtpub.gwtbook.samples.server`包中创建一个名为`LiveSearchServiceImpl.java`的新的 Java 文件，实现我们的实时搜索服务。我们将创建一个字符串数组，其中包含水果列表，当调用服务方法时，我们将返回该数组中以参数提供的字符串开头的水果的子列表。

```java
public class LiveSearchServiceImpl extends RemoteServiceServlet
implements LiveSearchService
{
private String[] items = new String[]
{"apple", "peach", "orange", "banana", "plum", "avocado",
"strawberry", "pear", "watermelon", "pineapple", "grape",
"blueberry", "cantaloupe"
};
public List getCompletionItems(String itemToMatch)
{
ArrayList completionList = new ArrayList();
for (int i = 0; i < items.length; i++)
{
if (items[i].startsWith(itemToMatch.toLowerCase()))
{
completionList.add(items[i]);
}
}
return completionList;
}
}

```

1.  我们的服务器端实现已经完成。现在我们将创建用户界面，与实时搜索服务进行交互。在`com.packtpub.gwtbook.samples.client.panels`包中创建一个名为`LiveSearchPanel.java`的新的 Java 文件，该文件扩展了`com.packtpub.gwtbook.samples.client.panels.SamplePanel`类。正如本章开头所提到的，本书中创建的每个用户界面都将被添加到一个示例应用程序中，该应用程序类似于 GWT 下载中作为示例项目之一的`KitchenSink`应用程序。这就是为什么我们将每个用户界面创建为扩展`SamplePanel`类的面板，并将创建的面板添加到示例应用程序中的示例面板列表中。添加一个文本框用于输入搜索字符串，以及一个`FlexTable`，用于显示从服务中检索到的匹配项。最后，创建一个我们将要调用的`LiveSearchService`的实例。

```java
public FlexTable liveResultsPanel = new FlexTable();
public TextBox searchText = new TextBox();
final LiveSearchServiceAsync
liveSearchService=(LiveSearchServiceAsync)
GWT.create(LiveSearchService.class);

```

1.  在`LiveSearchPanel`的构造函数中，创建服务目标并设置其入口点。还创建一个新的`VerticalPanel`，我们将使用它作为添加到用户界面的小部件的容器。设置搜索文本框的 CSS 样式。此样式在`Samples.css`文件中定义，并且是本书的源代码分发包的一部分。有关如何下载源代码包的详细信息，请参见附录。

```java
ServiceDefTarget endpoint=(ServiceDefTarget) liveSearchService;
endpoint.setServiceEntryPoint("/Samples/livesearch");
VerticalPanel workPanel = new VerticalPanel();
searchText.setStyleName("liveSearch-TextBox");

```

1.  在同一个构造函数中，为文本框添加一个监听器，该监听器将在用户在文本框中输入时异步调用`LiveSearchService`，并持续更新弹出面板，显示与文本框中当前字符串匹配的最新结果。这是通过调用服务获取完成项列表的方法。

```java
searchText.addKeyboardListener(new KeyboardListener()
{
public void onKeyPress
(Widget sender, char keyCode, int modifiers)
{
// not implemented
}
public void onKeyDown
(Widget sender, char keyCode, int modifiers)
{
for (int i = 0; i < liveResultsPanel.getRowCount(); i++)
{
liveResultsPanel.removeRow(i);
}
}
public void onKeyUp
(Widget sender, char keyCode, int modifiers)
{
for (int i = 0; i < liveResultsPanel.getRowCount(); i++)
{
liveResultsPanel.removeRow(i);
}
if (searchText.getText().length() > 0)
{
AsyncCallback callback = new AsyncCallback()
{
public void onSuccess(Object result)
{
ArrayList resultItems = (ArrayList) result;
int row = 0;
for(Iterator iter=resultItems.iterator();
iter.hasNext();)
{
liveResultsPanel.setText
(row++, 0, (String) iter.next());
}
}
public void onFailure(Throwable caught)
{
Window.alert("Live search failed because "
+ caught.getMessage());
}
};
liveSearchService.getCompletionItems
(searchText.getText(),callback);
}
}
});

```

1.  最后，在构造函数中，将搜索文本框和搜索结果面板添加到工作面板。创建一个小的信息面板，显示关于此应用程序的描述性文本，以便在我们的`Samples`应用程序中选择此示例时显示此文本。将信息面板和工作面板添加到一个停靠面板，并初始化小部件。

```java
liveResultsPanel.setStyleName("liveSearch-Results");
HorizontalPanel infoPanel = new HorizontalPanel();
infoPanel.add(new HTML
("<div class='infoProse'>Type the first few letters
of the name of a fruit in the text box below. A
list of fruits with names starting with the typed
letters will be displayed. The list is retrieved
from the server asynchronously. This is nice AJAX
pattern for providing user-friendly search
functionality in an application.</div>"));
workPanel.add(searchText);
workPanel.add(liveResultsPanel);
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

1.  将服务添加到`Samples`应用程序的模块文件`Samples.gwt.xml`中，该文件位于`com.packtpub.gwtbook.samples`包中。通过将此路径添加到模块文件中，让我们可以使用此路径创建并设置此服务的端点信息。

```java
<servlet path="/livesearch" class=
"com.packtpub.gwtbook.samples.server.LiveSearchServiceImpl"/>

```

这是应用程序的用户界面：

![行动时间-搜索时输入！](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_04_01.jpg)

一旦开始输入水果名称的前几个字母，以该字符串开头的水果名称将被检索并显示在文本框下方的面板中。

![行动时间-搜索时输入！](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_04_02.jpg)

### 刚刚发生了什么？

应用程序的用户界面在浏览器中加载时显示一个文本框。当您在框中输入一个字母时，文本框上将触发`onKeyUp()`事件，并在此事件处理程序中，我们异步调用`LiveSearchService`中的`getCompletionItems()`，并传入当前在文本框中的文本。我们服务中此方法的实现返回一个包含所有匹配名称的列表。在这个例子中，匹配的名称是从服务本身包含的映射中检索出来的，但根据您的应用程序需求，它也可以很容易地从数据库、另一个应用程序或 Web 服务中检索出来。我们将列表中存在的项目添加到`FlexTable`部件中，该部件就在文本框的下方。`FlexTable`允许我们创建可以动态扩展的表格。如果文本框为空，或者我们删除了框中的所有文本，那么我们就清空表中的列表。我们使用一个面板作为此应用程序中所有部件的容器。

面板是 GWT 框架中部件的容器，用于对它们进行布局。您可以将任何部件甚至其他面板添加到面板中。这使我们能够通过将它们添加到面板中来组合部件，从而构建复杂的用户界面。GWT 框架中常用的面板有：

+   停靠面板：一个通过将其停靠或定位在边缘上的子部件进行布局，并允许最后添加的部件占据剩余空间的面板。

+   单元格面板：一个将其部件布局在表格的单元格中的面板。

+   选项卡面板：一个在选项卡页集中布局子部件的面板，每个选项卡页都有一个部件。

+   水平面板：一个将其所有子部件按从左到右的单个水平列布局的面板。

+   垂直面板：一个将其所有子部件按从上到下的单个垂直列布局的面板。

+   流动面板：一个将其部件从左到右布局的面板，就像文本在一行上流动一样。

+   弹出面板：一个通过弹出或覆盖在页面上的其他部件上显示其子部件的面板。

+   堆叠面板：一个通过垂直堆叠其子部件来布局其子部件的面板。所使用的隐喻与 Microsoft Outlook 的用户界面相同。

在本章和本书的其余部分，我们将使用大多数这些面板来布局我们的用户界面。这个任务的概念可以扩展并应用于几乎任何类型的搜索，您可以为您的应用程序提供。您甚至可以增强和扩展此应用程序，以向用户提供更多的信息，例如匹配结果的数量。GWT 提供的管道和工具使得提供此功能变得非常容易。实时搜索 AJAX 模式及其使用的最佳示例之一是 Google 建议服务。当您在文本字段中键入搜索查询字符串时，它会连续检索并显示匹配结果列表。您可以在[`www.google.com/webhp?complete=1&hl=en`](http://www.google.com/webhp?complete=1&hl=en)上看到它的运行情况。

# 密码强度检查器

视觉线索是通知用户应用程序中事物状态的好方法。消息框和警报经常被用于此目的，但它们通常会让用户感到烦躁。通过微妙地向用户指示应用程序使用状态，可以提供更流畅和愉快的用户体验。在本节中，我们将创建一个应用程序，通过使用颜色和复选框来向用户指示输入密码的强度。我们将以与它们正常用法非常不同的方式使用复选框。这是使用 GWT 部件的新颖和不同方式的示例，并混合和匹配它们以提供出色的用户体验。

## 行动时间-创建检查器

在当今时代，几乎所有事情都需要密码，选择安全密码非常重要。有许多标准建议创建一个免受大多数常见密码破解攻击的安全密码。这些标准从创建包含一定数量的小写字母和数字的 15 个字母密码到使用随机密码生成器创建密码。在我们的示例应用程序中，我们将创建一个非常简单的密码强度检查器，只检查密码中的字母数量。包含少于五个字母的密码字符串将被视为弱密码，而包含五到七个字母的密码将被视为中等强度。任何包含超过七个字母的密码将被视为强密码。标准故意保持简单，以便我们可以专注于创建应用程序，而不会陷入实际密码强度标准中。这将帮助我们理解概念，然后您可以扩展它以使用您的应用程序需要的任何密码强度标准。此示例使用服务来获取密码强度，但这也可以在客户端上完成，而无需使用服务器。

1.  在`com.packtpub.gwtbook.samples.client`包中创建一个名为`PasswordStrengthService.java`的新的 Java 文件。定义一个`PasswordStrengthService`接口，其中包含一个方法，用于检索作为方法参数提供的密码字符串的强度：

```java
public interface PasswordStrengthService extends RemoteService
{
public int checkStrength(String password);
}

```

1.  在`com.packtpub.gwtbook.samples.client`包中的一个新的 Java 文件中创建这个服务定义接口的异步版本，命名为`PasswordStrengthServiceAsync.java`：

```java
public interface PasswordStrengthServiceAsync
{
public void checkStrength
(String password, AsyncCallback callback);
}

```

1.  在`com.packtpub.gwtbook.samples.server`包中创建一个名为`PasswordStrengthServiceImpl.java`的新 Java 文件，实现我们的密码强度服务。

```java
public class PasswordStrengthServiceImpl extends
RemoteServiceServlet implements PasswordStrengthService
{
private int STRONG = 9;
private int MEDIUM = 6;
private int WEAK = 3;
public int checkStrength(String password)
{
if (password.length() <= 4)
{
return WEAK;
}
else if (password.length() < 8)
{
return MEDIUM;
}else
{
return STRONG;
}
}
}

```

1.  现在让我们为这个应用程序创建用户界面。在`com.packtpub.gwtbook.samples.client.panels`包中创建一个名为`PasswordStrengthPanel.java`的新的 Java 文件，它扩展了`com.packtpub.gwtbook.samples.client.panels.SamplePanel`类。创建一个用于输入密码字符串的文本框，一个名为`strengthPanel`的`ArrayList`，用于保存我们将用于显示密码强度的复选框。还创建`PasswordStrengthService`对象。

```java
public TextBox passwordText = new TextBox();
final PasswordStrengthServiceAsync pwStrengthService =
(PasswordStrengthServiceAsync) GWT.create(PasswordStrengthService.class);
public ArrayList strength = new ArrayList();

```

1.  通过将它们的样式设置为默认样式来添加一个私有方法来清除所有复选框。

```java
private void clearStrengthPanel()
{
for (Iterator iter = strength.iterator(); iter.hasNext();)
{
((CheckBox) iter.next()).
setStyleName(getPasswordStrengthStyle(0));
}
}

```

1.  添加一个私有方法，根据密码强度返回 CSS 名称。这是一个很好的方法，可以根据强度动态设置复选框的样式。

```java
private String getPasswordStrengthStyle(int passwordStrength)
{
if (passwordStrength == 3)
{
return "pwStrength-Weak";
}
else if (passwordStrength == 6)
{
return "pwStrength-Medium";
}
else if (passwordStrength == 9)
{
return "pwStrength-Strong";
}
else
{
return "";
}
}

```

1.  在`PasswordStrengthPanel`类的构造函数中，创建一个名为`strengthPanel`的`HorizontalPanel`，向其中添加九个复选框，并设置其样式。如前所述，我们在本书的示例应用程序中使用的样式可在文件`Samples.css`中找到，该文件是本书源代码分发的一部分。我们还将这些相同的复选框添加到`strength`对象中，以便稍后可以检索它们以设置它们的状态。这些复选框将用于直观显示密码强度。创建一个新的`VerticalPanel`，我们将用作向用户界面添加的小部件的容器。最后，创建服务目标并设置其入口点。

```java
HorizontalPanel strengthPanel = new HorizontalPanel();
strengthPanel.setStyleName("pwStrength-Panel");
for (int i = 0; i < 9; i++)
{
CheckBox singleBox = new CheckBox();
strengthPanel.add(singleBox);
strength.add(singleBox);
}
VerticalPanel workPanel = new VerticalPanel();
ServiceDefTarget endpoint=(ServiceDefTarget) pwStrengthService;
endpoint.setServiceEntryPoint(GWT.getModuleBaseURL() +
"pwstrength");

```

1.  在同一个构造函数中，设置密码文本框的样式，并添加一个事件处理程序来监听密码框的更改。

```java
passwordText.setStyleName("pwStrength-Textbox");
passwordText.addKeyboardListener(new KeyboardListener()
{
public void onKeyDown
(Widget sender, char keyCode, int modifiers)
{
}
public void onKeyPress
(Widget sender, char keyCode, int modifiers)
{
}
public void onKeyUp(Widget sender, char keyCode, int modifiers)
{
if (passwordText.getText().length() > 0)
{
AsyncCallback callback = new AsyncCallback()
{
public void onSuccess(Object result)
{
clearStrengthPanel();
int checkedStrength = ((Integer) result).intValue();
for (int i = 0; i < checkedStrength; i++)
{
((CheckBox) strength.get(i)).setStyleName
(getPasswordStrengthStyle(checkedStrength));
}
}
public void onFailure(Throwable caught)
{
Window.alert("Error calling the password strength service." + caught.getMessage());
}
};
pwStrengthService.checkStrength
(passwordText.getText(), callback);
}
else
{
clearStrengthPanel();
}
}
});

```

1.  最后，在构造函数中，将密码文本框和强度面板添加到工作面板。创建一个小的信息面板，显示关于此应用程序的描述性文本，以便在我们的`Samples`应用程序的可用示例列表中选择此示例时可以显示此文本。将信息面板和工作面板添加到一个停靠面板，并初始化小部件。

```java
HorizontalPanel infoPanel = new HorizontalPanel();
infoPanel.add(new HTML(
"<div class='infoProse'>Start typing a password
string. The strength of the password will be
checked and displayed below. Red indicates that the
password is Weak, Orange indicates a Medium
strength password and Green indicates a Strong
password. The algorithm for checking the strength
is very basic and checks the length of the password
string.</div>"));
workPanel.add(passwordText);
workPanel.add(infoPanel);
workPanel.add(strengthPanel);
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

1.  将服务添加到`Samples`应用程序的模块文件中——`com.packtpub.gwtbook.samples`包中的`Samples.gwt.xml`。

```java
<servlet path="/pwstrength" class=
"com.packtpub.gwtbook.samples.server.
PasswordStrengthServiceImpl"/>

```

这是密码强度检查应用程序的用户界面：

![操作时间—创建检查器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_04_03.jpg)

现在开始输入密码字符串以检查其强度。当您输入少于五个字符的密码字符串时，密码强度如下：

![操作时间—创建检查器](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_04_04.jpg)

### 刚刚发生了什么？

密码强度服务检查提供的字符串的大小，并根据其弱、中、强返回一个整数值，分别为三、六或九。它通过使用以下标准来做出这一决定：如果密码字符串长度小于五个字符，则为弱密码；如果超过五个字符但不超过七个字符，则被视为中等强度密码。超过七个字符的任何密码都被视为强密码。

用户界面由一个文本框和一个包含九个复选框的面板组成，用于以密码形式输入密码字符串，并以密码的形式显示其强度。事件处理程序被注册用于监听由密码文本框生成的键盘事件。每当密码文本发生变化时，无论是在字段中输入或更改字符，我们都会异步与密码强度服务通信，并检索给定字符串作为密码的强度。返回的强度以颜色的形式显示给用户，以象征三种不同的密码强度。

密码强度显示在一个由九个复选框添加到`HorizontalPanel`创建的复合小部件中。根据密码字符串的强度，复选框的颜色会使用 CSS 进行更改。将 GWT 提供的基本小部件组合成更复杂的小部件以构建用户界面的过程是构建 GWT 应用程序中的常见模式。通过利用 GWT 框架的强大功能，可以以这种方式构建相当复杂的用户界面。随着我们在本章后面继续探索各种 GWT 应用程序以及整本书中的其他部分，我们将看到更多的例子。

# 自动表单填充

Web 上的表单是无处不在的，广泛用于从客户资料显示到在线填写申请等各种用途。我们不喜欢每次都要通过所有这些字段并在每次都要输入信息，尤其是如果我们之前在该网站上已经这样做过。加快这个过程的一个很好的方法是在填写关键表单字段时预填充以前收集的信息。这不仅节省了客户的一些输入，还是一个极大的可用性增强，提高了整个客户体验。在本节中，我们将构建一个表单，当我们在客户 ID 字段中输入一个已识别的值时，将自动填写各种字段。

## 操作时间—创建动态表单

我们将创建一个应用程序，使得在某个字段中提供特定值时，填写表单的各种字段变得容易。这在大多数基于 Web 的业务应用程序中是非常常见的情况，例如，需要提供用户信息以注册服务。对于新用户，这些信息需要由用户填写，但对于系统的先前用户，这些信息已经可用，并且可以在用户输入唯一标识符（识别他或她的 ID）时访问和用于填写所有字段。在这个应用程序中，当用户输入我们已知的`CustomerID`时，我们将自动填写表单的各种字段。

1.  在`com.packtpub.gwtbook.samples.client`包中创建名为`AutoFormFillService.java`的新 Java 文件。定义一个`AutoFormFillService`接口，其中包含一个方法，用于在提供键时检索表单信息：

```java
public interface AutoFormFillService extends RemoteService
{
public HashMap getFormInfo(String formKey);
}

```

1.  在`com.packtpub.gwtbook.samples.client`包中创建名为`AutoFormFillServiceAsync.java`的新 Java 文件。定义一个`AutoFormFillAsync`接口：

```java
public interface AutoFormFillServiceAsync
{
public void getFormInfo
(String formKey, AsyncCallback callback);
}

```

1.  在`com.packtpub.gwtbook.samples.server`包中创建名为`AutoFormFillServiceImpl.java`的新 Java 文件。定义一个`AutoFormFillServiceImpl`类，该类扩展`RemoteServiceServlet`并实现先前创建的`AutoFormFillService`接口。首先，我们将使用一个简单的`HashMap`来存储客户信息，并添加一个方法来填充映射。在您的应用程序中，您可以从任何外部数据源（如数据库）检索此客户信息。

```java
private HashMap formInfo = new HashMap();
private void loadCustomerData()
{
HashMap customer1 = new HashMap();
customer1.put("first name", "Joe");
customer1.put("last name", "Customer");
customer1.put("address", "123 peachtree street");
customer1.put("city", "Atlanta");
customer1.put("state", "GA");
customer1.put("zip", "30339");
customer1.put("phone", "770-123-4567");
formInfo.put("1111", customer1);
HashMap customer2 = new HashMap();
customer2.put("first name", "Jane");
customer2.put("last name", "Customer");
customer2.put("address", "456 elm street");
customer2.put("city", "Miami");
customer2.put("state", "FL");
customer2.put("zip", "24156");
customer2.put("phone", "817-123-4567");
formInfo.put("2222", customer2);
HashMap customer3 = new HashMap();
customer3.put("first name", "Jeff");
customer3.put("last name", "Customer");
customer3.put("address", "789 sunset blvd");
customer3.put("city", "Los Angeles");
customer3.put("state", "CA");
customer3.put("zip", "90211");
customer3.put("phone", "714-478-9802");
formInfo.put("3333", customer3);
}

```

1.  在`getFormInfo()`中添加逻辑，以返回提供的表单键的表单信息。我们获取用户在表单中输入的提供的键，并使用它来查找用户信息，并将其异步返回给客户端应用程序。

```java
public HashMap getFormInfo(String formKey)
{
if (formInfo.containsKey(formKey))
{
return (HashMap) formInfo.get(formKey);
}
else
{
return new HashMap();
}
}

```

1.  在`com.packtpub.gwtbook.samples.client.panels`包中的新 Java 文件`AutoFormFillPanel.java`中创建此应用程序的用户界面。为每个信息字段创建一个文本框和一个标签。

```java
private TextBox custID = new TextBox();
private TextBox firstName = new TextBox();
private TextBox lastName = new TextBox();
private TextBox address = new TextBox();
private TextBox zip = new TextBox();
private TextBox phone = new TextBox();
private TextBox city = new TextBox();
private TextBox state = new TextBox();
private Label custIDLbl = new Label("Customer ID : ");
private Label firstNameLbl = new Label("First Name : ");
private Label lastNameLbl = new Label("Last Name : ");
private Label addressLbl = new Label("Address : ");
private Label zipLbl = new Label("Zip Code : ");
private Label phoneLbl = new Label("Phone Number : ");
private Label cityLbl = new Label("City : ");
private Label stateLbl = new Label("State : ");
HorizontalPanel itemPanel = new HorizontalPanel();

```

1.  创建我们要调用的服务类。

```java
final AutoFormFillServiceAsync autoFormFillService =
(AutoFormFillServiceAsync) GWT.create (AutoFormFillService.class);

```

1.  创建用于设置和清除表单字段值的私有方法。我们将从构造函数中设置的事件处理程序中使用这些方法。

```java
private void setValues(HashMap values)
{
if (values.size() > 0)
{
firstName.setText((String) values.get("first name"));
lastName.setText((String) values.get("last name"));
address.setText((String) values.get("address"));
city.setText((String) values.get("city"));
state.setText((String) values.get("state"));
zip.setText((String) values.get("zip"));
phone.setText((String) values.get("phone"));
}
else
{
clearValues();
}
}
private void clearValues()
{
firstName.setText(" ");
lastName.setText(" ");
address.setText(" ");
city.setText(" ");
state.setText(" ");
zip.setText(" ");
phone.setText(" ");
}

```

1.  创建用于检索不同标签的访问器方法。当我们从服务中检索信息时，我们将使用这些方法来获取标签并设置其值。

```java
public Label getAddressLbl()
{
return addressLbl;
}
public Label getCityLbl()
{
return cityLbl;
}
public Label getCustIDLbl()
{
return custIDLbl;
}
public Label getFirstNameLbl()
{
return firstNameLbl;
}
public Label getLastNameLbl()
{
return lastNameLbl;
}
public Label getPhoneLbl()
{
return phoneLbl;
}
public Label getStateLbl()
{
return stateLbl;
}
public Label getZipLbl()
{
return zipLbl;
}

```

1.  为检索不同的文本框创建访问器方法。当我们从服务中检索信息时，我们将使用这些方法来获取文本框并设置其值。

```java
public TextBox getAddress()
{
return address;
}
public TextBox getCity()
{
return city;
}
public TextBox getCustID()
{
return custID;
}
public TextBox getFirstName()
{
return firstName;
}
public TextBox getLastName()
{
return lastName;
}
public TextBox getPhone()
{
return phone;
}
public TextBox getState()
{
return state;
}
public TextBox getZip()
{
return zip;
}

```

1.  在`AutoFormFillPanel`的构造函数中，创建一个新的`VerticalPanel`，我们将使用它作为添加到用户界面的小部件的容器。还要创建服务目标并设置其入口点。

```java
ServiceDefTarget endpoint = (ServiceDefTarget)
autoFormFillService;
endpoint.setServiceEntryPoint("/Samples/autoformfill");

```

1.  同样在构造函数中，创建一个名为`itemPanel`的`HorizontalPanel`，并将每个表单字段的小部件添加到其中。例如，这是我们如何将`customerID`字段添加到`itemPanel`，设置其样式，并将此`itemPanel`添加到`workPanel`，这是我们之前创建的用于容纳用户界面小部件的主容器。对于每个表单字段，您将创建一个新的`HorizontalPanel`并将其添加到`workPanel`。对于我们拥有的每个表单字段，重复此操作。

```java
HorizontalPanel itemPanel = new HorizontalPanel();
itemPanel.setStyleName("autoFormItem-Panel");
custIDLbl.setStyleName("autoFormItem-Label");
itemPanel.add(custIDLbl);
custID.setStyleName("autoFormItem-Textbox");
itemPanel.add(custID);
workPanel.add(itemPanel);

```

1.  在相同的构造函数中，向`custID`文本框添加键盘监听器，并在事件处理程序中调用服务以检索键入客户 ID 的客户信息。从服务调用的返回值设置表单字段的值。

```java
custID.addKeyboardListener(new KeyboardListener()
{
public void onKeyDown(Widget sender,
char keyCode, int modifiers)
{
}
public void onKeyPress(Widget sender,
char keyCode, int modifiers)
{
}
public void onKeyUp(Widget sender, char
keyCode, int modifiers)
{
if (custID.getText().length() > 0)
{
AsyncCallback callback = new
AsyncCallback()
{
public void onSuccess
(Object result)
{
setValues((HashMap) result);
}
};
autoFormFillService.getFormInfo
(custID.getText(), callback);
}
else
{
clearValues();
}
}
public void onFailure(Throwable caught)
{
Window.alert("Error while calling the
Auto Form Fill service."
+ caught.getMessage());
}
});

```

1.  最后，在构造函数中，创建一个小的信息面板，显示关于此应用程序的描述性文本，以便在我们的`Samples`应用程序的可用示例列表中选择此示例时显示此文本。将信息面板和工作面板添加到一个停靠面板中，并初始化小部件。

```java
HorizontalPanel infoPanel = new HorizontalPanel();
infoPanel.add(new HTML(
"<div class='infoProse'>This example
demonstrates how to automatically fill a
form by retrieving the data from the server
asynchronously. Start typing a customer ID
in the provided field, and corresponding
values for that customer are retrieved
asynchronously from the server and the form
filled for you.</div>"));
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

1.  将服务添加到`Samples`应用程序的模块文件`Samples.gwt.xml`中，该文件位于`com.packtpub.gwtbook.samples`包中。

```java
<servlet path="/autoformfill" class=
"com.packtpub.gwtbook.samples.server. AutoFormFillServiceImpl"/>

```

当用户在我们的应用程序中输入已知的`CustomerID`（在本例中为 1111）时，应用程序的外观如下：

![操作时间-创建动态表单](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_04_05.jpg)

### 刚刚发生了什么？

我们创建一个包含存储在`HashMap`数据结构中的客户数据的服务。在一个真实的应用程序中，这些数据通常来自外部数据源，比如数据库。对于每个客户，我们创建一个包含客户信息字段存储为键值对的 map。然后，将这个客户 map 添加到一个主`HashMap`中，使用`customerID`作为键。这样，当我们提供键时，也就是`customerID`时，我们更容易检索到正确的客户信息。

```java
HashMap customer2 = new HashMap();
customer2.put("first name", "Jane");
customer2.put("last name", "Customer");
customer2.put("address", "456 elm street");
customer2.put("city", "Miami");
customer2.put("state", "FL");
customer2.put("zip", "24156");
customer2.put("phone", "817-123-4567");
formInfo.put("2222", customer2);

```

当用户界面在浏览器中加载时，用户将看到一个包含与客户相关的字段的页面。用户需要在提供的文本框中输入一个唯一的客户 ID。在这个示例应用程序中只有三个已知的客户 ID——1111、2222 和 3333。我们在这里使用客户 ID 作为客户信息的键，但根据应用程序的要求，您也可以使用社会安全号码或任何其他唯一 ID。当用户在文本框中输入客户 ID，例如 1111，事件处理程序`onKeyUp()`被触发。在事件处理程序中，我们调用`AutoFormFillService`中的`getFormInfo()`方法，并将输入的文本作为参数传递。`getFormInfo()`方法搜索给定客户 ID 的客户信息，并将信息作为`HashMap`返回。如果由于未知 ID 而找不到信息，我们将返回一个空的 map。从这个 map 中检索值，并通过调用`setValues()`填充相应的字段。

```java
firstName.setText((String) values.get("first name"));
lastName.setText((String) values.get("last name"));
address.setText((String) values.get("address"));
city.setText((String) values.get("city"));
state.setText((String) values.get("state"));
zip.setText((String) values.get("zip"));
phone.setText((String) values.get("phone"));

```

这是为用户与我们的系统交互提供良好体验的一种简单但非常强大和有效的方式。

# 可排序表格

表格可能是在应用程序中显示业务数据最常见的方式。它们为所有用户所熟知，并提供了一种通用的查看数据的方式。在网页上传统上很难实现这一点。GWT 为我们提供了在应用程序中轻松快速地提供这种功能的能力。我们将创建一个包含表格的应用程序，其中的行可以通过点击列标题以升序或降序排序。这为用户提供了更好的用户体验，因为用户可以修改显示的数据顺序以满足他们的需求。GWT 提供的表格小部件没有内置的方法来提供这种功能，但是 GWT 为我们提供了足够的工具来轻松地为表格添加支持。请记住，这只是使用 GWT 创建可排序的表格的一种方式。

## 行动时间——排序表格行

我们不需要为这个应用程序创建一个服务，因为数据的排序是在客户端上进行的。我们将创建一个包含表格种子数据的应用程序，然后添加支持通过点击列标题对数据进行排序。

1.  在`com.packtpub.gwtbook.samples.client.panels`包中创建一个名为`SortableTablesPanel.java`的新的 Java 文件。我们将为这个类添加支持，使包含的表格可以通过点击列标题进行排序。首先创建一个`CustomerData`类，它将代表表格中的一行，并为每个字段创建访问器。

```java
private class CustomerData
{
private String firstName;
private String lastName;
private String country;
private String city;
public CustomerData(String firstName, String lastName,
String city, String country)
{
this.firstName = firstName;
this.lastName = lastName;
this.country = country;
this.city = city;
}
public String getCountry()
{
return country;
}
public String getCity()
{
return city;
}
public String getFirstName()
{
return firstName;
}
public String getLastName()
{
return lastName;
}
}

```

1.  创建一个名为`customerData`的`ArrayList`来存储客户数据。创建变量来存储排序方向、表格中列的标题、用于排序的临时数据结构，以及用于显示客户数据的`FlexTable`。

```java
private int sortDirection = 0;
private FlexTable sortableTable = new FlexTable();
private String[] columnHeaders = new String[]
{ "First Name", "Last Name", "City", "Country" };
private ArrayList customerData = new ArrayList();
private HashMap dataBucket = new HashMap();
private ArrayList sortColumnValues = new ArrayList();

```

1.  在`SortableTablesPanel`的构造函数中，创建一个新的`VerticalPanel`，我们将使用它作为添加到用户界面的小部件的容器。设置表格的样式，并设置表格的列标题。

```java
VerticalPanel workPanel = new VerticalPanel();
sortableTable.setWidth(500 + "px");
sortableTable.setStyleName("sortableTable");
sortableTable.setBorderWidth(1);
sortableTable.setCellPadding(4);
sortableTable.setCellSpacing(1);
sortableTable.setHTML(0, 0, columnHeaders[0]
+ "&nbsp;<img border='0' src='images/blank.gif'/>");
sortableTable.setHTML(0, 1, columnHeaders[1]
+ "&nbsp;<img border='0' src='images/blank.gif'/>");
sortableTable.setHTML(0, 2, columnHeaders[2]
+ "&nbsp;<img border='0' src='images/blank.gif'/>");
sortableTable.setHTML(0, 3, columnHeaders[3]
+ "&nbsp;<img border='0' src='images/blank.gif'/>");

```

1.  同样在构造函数中，向`customerData`列表添加五个客户。将此列表中的数据添加到表格中，并在表格上设置一个监听器，以在点击第一列时对行进行排序。我们将在表格中显示这些客户的列表，然后在点击列标题时对表格进行排序。

```java
customerData.add(new CustomerData("Rahul","Dravid","Bangalore",
"India"));
customerData.add(new CustomerData("Nat", "Flintoff", "London",
"England"));
customerData.add(new CustomerData("Inzamamul", "Haq", "Lahore",
"Pakistan"));
customerData.add(new CustomerData("Graeme", "Smith", "Durban",
"SouthAfrica"));
customerData.add(new CustomerData("Ricky", "Ponting", "Sydney",
"Australia"));
int row = 1;
for (Iterator iter = customerData.iterator(); iter.hasNext();)
{
CustomerData element = (CustomerData) iter.next();
sortableTable.setText(row, 0, element.getFirstName());
sortableTable.setText(row, 1, element.getLastName());
sortableTable.setText(row, 2, element.getCity());
sortableTable.setText(row, 3, element.getCountry());
row++;
}
RowFormatter rowFormatter = sortableTable.getRowFormatter();
rowFormatter.setStyleName(0, "tableHeader");
sortableTable.addTableListener(new TableListener()
{
public void onCellClicked(SourcesTableEvents sender, int row,
int cell)
{
if (row == 0)
{
sortTable(row, cell);
}
}
});

```

1.  最后，在构造函数中，将表格添加到工作面板。创建一个小的信息面板，显示关于此应用程序的描述性文本，以便在`Samples`应用程序的可用样本列表中选择此样本时，我们可以显示此文本。将信息面板和工作面板添加到一个停靠面板，并初始化小部件。

```java
HorizontalPanel infoPanel = new HorizontalPanel();
infoPanel.add(new HTML(
"<div class='infoProse'>This example shows
how to create tables whose rows can be
sorted by clicking on the column
header.</div>"));
workPanel.setStyleName("sortableTables-Panel");
workPanel.add(sortableTable);
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
sortTable(0, 0);
initWidget(workPane);

```

1.  为表格的标题重新绘制一个私有方法。这是一个很好的方法，可以重新绘制表格列标题，以便我们可以更改标题中显示的图像，以匹配当前的排序方向。

```java
private void redrawColumnHeaders(int column)
{
if (sortDirection == 0)
{
sortableTable.setHTML(0, column, columnHeaders[column]
+ "&nbsp;<img border='0' src='images/desc.gif'/>");
}
else if (sortDirection == 1)
{
sortableTable.setHTML(0, column, columnHeaders[column]
+ "&nbsp;<img border='0' src='images/asc.gif'/>");
}
else
{
sortableTable.setHTML(0, column, columnHeaders[column]
+ "&nbsp;<img border='0' src='images/blank.gif'/>");
}
for (int i = 0; i < 4; i++)
{
if (i != column)
{
sortableTable.setHTML(0, i, columnHeaders[i]
+ "&nbsp;<img border='0' src='images/blank.gif'/>");
}
}
}

```

1.  添加一个私有方法，在更改排序顺序时重新绘制整个表格。

```java
private void redrawTable()
{
int row = 1;
for (Iterator iter = sortColumnValues.iterator();
iter.hasNext();)
{
String key = (String) iter.next();
CustomerData custData = (CustomerData) dataBucket.get(key);
sortableTable.setText(row, 0, custData.getFirstName());
sortableTable.setText(row, 1, custData.getLastName());
sortableTable.setText(row, 2, custData.getCity());
sortableTable.setText(row, 3, custData.getCountry());
row++;
}
}

```

1.  添加一个私有方法，可以按升序或降序对数据进行排序，并重新绘制带有排序行的表格。我们正在使用`Collections`类提供的 sort 方法对数据进行排序，但也可以修改为使用`Comparator`类来比较两个数据，并将其用于排序。

```java
public void sortTable(int row, int cell)
{
dataBucket.clear();
sortColumnValues.clear();
for (int i = 1; i < customerData.size() + 1; i++)
{
dataBucket.put(sortableTable.getText(i, cell), new
CustomerData(
sortableTable.getText(i, 0), sortableTable.getText(i, 1),
sortableTable.getText(i, 2), sortableTable.getText
(i, 3)));
sortColumnValues.add(sortableTable.getText(i, cell));
}
if (sortDirection == 0)
{
sortDirection = 1;
Collections.sort(sortColumnValues);
}
else
{
sortDirection = 0;
Collections.reverse(sortColumnValues);
}
redrawColumnHeader(cell);
resetColumnHeaders(cell);
redrawTable();
}

```

这是应用程序的屏幕截图。您可以点击任何列标题来对数据进行排序。

![操作时间-排序表行](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_04_06.jpg)

### 刚刚发生了什么？

我们创建了一个`CustomerData`类来表示`FlexTable`中的每一行。然后我们创建一些客户数据，并将其存储在`ArrayList`中。

```java
customerData.add(new CustomerData("Rahul", "Dravid", "Bangalore",
"India"));

```

将此列表中的数据添加到表格中。我们需要指定行号和列号，以便将元素添加到表格中。

```java
CustomerData element = (CustomerData) iter.next();
sortableTable.setText(row, 0, element.getFirstName());
sortableTable.setText(row, 1, element.getLastName());
sortableTable.setText(row, 2, element.getCity());
sortableTable.setText(row, 3, element.getCountry());

```

列标题包含在零行中，表格数据从第 1 行开始。我们通过设置该特定单元格的 HTML 来添加列标题，如下所示：

```java
sortableTable.setHTML(0, 0, columnHeaders[0] + "&nbsp; <img border='0' src='images/blank.gif'/>");

```

这使我们能够向单元格添加一小段 HTML，而不仅仅是设置纯文本。我们添加列标题的文本以及一个带有空白图像文件的`img`标签。列标题旁边没有图像的列标题在视觉上向用户指示，该特定列没有指定排序顺序。当我们点击列标题时，我们将修改此图像以使用升序或降序图标。注册了一个事件处理程序来监听表格上的点击。GWT 不包含在某人点击特定单元格时注册处理程序的机制，因此我们使用通用表格点击监听器，并检查点击是否在零行，即包含列标题的行。如果用户确实点击了列标题，我们将继续对表格进行排序。

真正的魔法发生在`sortTable()`方法中。创建一个临时的名为`dataBucket`的`HashMap`来存储来自表格的行，每行都以被点击的列中的值为键，以及一个临时的名为`sortColumnValues`的`ArrayList`，它存储被点击的列中的列值。这意味着`sortColumnValues`列表包含作为`dataBucket`映射中键的值。

```java
for (int i = 1; i < customerData.size() + 1; i++)
{
dataBucket.put(sortableTable.getText(i, cell), new CustomerData(
sortableTable.getText(i, 0), sortableTable.getText(i, 1),
sortableTable.getText(i, 2), sortableTable.getText(i, 3)));
sortColumnValues.add(sortableTable.getText(i, cell));
}

```

我们检查`sortDirection`变量的值，并根据该值对`sortColumnValues`列表进行升序或降序排序，以包含正确顺序的列值。使用`Collections`类的内置`sort()`和`reverseSort()`方法来提供排序机制。

```java
if (sortDirection == 0)
{
sortDirection = 1;
Collections.sort(sortColumnValues);
}
else
{
sortDirection = 0;
Collections.reverse(sortColumnValues);
}

```

然后重新绘制表格列标题，以便被点击的列将具有正确的排序顺序的图标，而所有其他列标题只有纯文本和空白图像。最后，我们通过遍历`sortColumnValues`列表并从`dataBucket`中检索关联的`CustomerData`对象，将其作为表格中的一行添加，重新绘制表格。

这个应用程序展示了 GWT 框架提供的巨大能力，使您能够操纵表格以扩展其功能。GWT 提供了不同类型的表格来构建用户界面：

+   **FlexTable:** 一个按需创建单元格的表格。甚至可以有包含不同数量单元格的行。当您向其添加行和列时，此表格会根据需要扩展。

+   **Grid:** 一个可以包含文本、HTML 或子小部件的表格。但是，它必须明确地创建，指定所需的行数和列数。

我们将在本章和本书的其余部分中广泛使用这两个表小部件。

# 动态列表

我们将创建一个应用程序，使用动态列表向用户呈现一种过滤搜索条件的方式。在本节中，我们将创建动态表格，这将使我们能够在选择主表中的项目时填充子表格。我们将通过使用 GWT 的 AJAX 支持来实现这一点，并且只显示与主表中选择相关的子表中的项目。这个应用程序将使得轻松浏览和过滤搜索条件成为可能。在这个示例应用程序中，我们将使用户能够选择汽车制造商，这将自动填充第二个列表，其中包含该制造商生产的所有汽车品牌。当客户进一步在这些品牌列表中选择项目时，第三个列表将自动填充所选品牌的汽车型号。通过这种方式，用户可以交互式地选择和浏览搜索条件，以用户友好和直观的方式，而无需提交数据和刷新页面来呈现这些信息的一部分。

## 行动时间-过滤搜索条件

作为这个应用程序的一部分，我们还将创建一个服务，它将提供有关制造商、品牌和型号的信息，并创建一个用户界面，异步地从服务中检索这些信息，以显示给用户。

1.  在`com.packtpub.gwtbook.samples.client`包中创建一个名为`DynamicListsService.java`的新的 Java 文件。定义一个`DynamicListsService`接口，其中包含检索有关制造商、品牌和型号信息的方法：

```java
public interface DynamicListsService extends RemoteService
{
public List getManufacturers();
public List getBrands(String manufacturer);
public List getModels(String manufacturer, String brand);
}

```

1.  在`com.packtpub.gwtbook.samples.client`包中创建一个名为`DynamicListsServiceAsync.java`的新的 Java 文件。定义一个`DynamicListsServiceAsync`接口：

```java
public interface DynamicListsServiceAsync
{
public void getManufacturers(AsyncCallback callback);
public void getBrands(String manufacturer,
AsyncCallback callback);
public void getModels(String manufacturer, String brand,
AsyncCallback callback);
}

```

1.  在`com.packtpub.gwtbook.samples.server`包中创建一个名为`DynamicListsServiceImpl.java`的新的 Java 文件。定义一个扩展`RemoteServiceServlet`并实现先前创建的`DynamicListsService`接口的`DynamicListsServiceImpl`类。这个类将返回有关制造商、品牌和型号的信息。创建一个名为`Manufacturer`的类，封装有关每个制造商的信息，包括它们提供的汽车品牌和型号。

```java
private class Manufacturer
{
private HashMap brands = new HashMap();
public Manufacturer(HashMap brands)
{
this.brands = brands;
}
public HashMap getBrands()
{
return brands;
}
}

```

1.  创建一个私有方法，将制造商信息加载到`HashMap`中。制造商的数据将稍后加载到第一个表中。当用户界面启动时，制造商表是唯一具有数据的表，为使用应用程序提供了起点。

```java
private void loadData()
{
ArrayList brandModels = new ArrayList();
brandModels.add("EX");
brandModels.add("DX Hatchback");
brandModels.add("DX 4-Door");
HashMap manufacturerBrands = new HashMap();
manufacturerBrands.put("Civic", brandModels);
brandModels = new ArrayList();
brandModels.add("SX");
brandModels.add("Sedan");
manufacturerBrands.put("Accord", brandModels);
brandModels = new ArrayList();
brandModels.add("LX");
brandModels.add("Deluxe");
manufacturerBrands.put("Odyssey", brandModels);
Manufacturer manufacturer = new
Manufacturer(manufacturerBrands);
data.put("Honda", manufacturer);
brandModels = new ArrayList();
brandModels.add("LXE");
brandModels.add("LX");
manufacturerBrands = new HashMap();
manufacturerBrands.put("Altima", brandModels);
brandModels = new ArrayList();
brandModels.add("NX");
brandModels.add("EXE");
manufacturerBrands.put("Sentra", brandModels);
manufacturer = new Manufacturer(manufacturerBrands);
data.put("Nissan", manufacturer);
brandModels = new ArrayList();
brandModels.add("E300");
brandModels.add("E500");
manufacturerBrands = new HashMap();
manufacturerBrands.put("E-Class", brandModels);
brandModels = new ArrayList();
brandModels.add("C250");
brandModels.add("C300");
manufacturerBrands.put("C-Class", brandModels);
manufacturer = new Manufacturer(manufacturerBrands);
data.put("Mercedes", manufacturer);
}

```

1.  实现用于检索制造商列表的服务方法。

```java
public ArrayList getManufacturers()
{
ArrayList manufacturersList = new ArrayList();
for (Iterator iter=data.keySet().iterator(); iter.hasNext();)
{
manufacturersList.add((String) iter.next());
}
return manufacturersList;
}

```

1.  实现用于检索制造商提供的品牌列表的服务方法。

```java
public ArrayList getBrands(String manufacturer)
{
ArrayList brandsList = new ArrayList();
for (Iterator iter = ((Manufacturer)data.get(manufacturer))
.getBrands().keySet().iterator(); iter.hasNext();)
{
brandsList.add((String) iter.next());
}
return brandsList;
}

```

1.  实现用于检索特定品牌制造商提供的型号的服务方法。

```java
public ArrayList getModels(String manufacturer, String brand)
{
ArrayList modelsList = new ArrayList();
Manufacturer mfr = (Manufacturer) data.get(manufacturer);
HashMap mfrBrands = (HashMap) mfr.getBrands();
for (Iterator iter = ((ArrayList)
mfrBrands.get(brand)).iterator(); iter.hasNext();)
{
modelsList.add((String) iter.next());
}
return modelsList;
}

```

1.  在`com.packtpub.gwtbook.samples.client.panels`包中创建一个名为`DynamicListsPanel.java`的新的 Java 文件，为这个应用程序创建用户界面。创建三个 Grid 小部件来保存制造商、品牌和型号信息，并将它们添加到主面板中。创建我们将要调用的服务类。

```java
Grid manufacturers = new Grid(5, 1);
Grid brands = new Grid(5, 1);
Grid models = new Grid(5, 1);
final DynamicListsServiceAsync dynamicListsService =
(DynamicListsServiceAsync) GWT.create (DynamicListsService.class);

```

1.  添加一个用于清除面板的私有方法。

```java
public void clearSelections(Grid grid, boolean clearData)
{
for (int i = 0; i < grid.getRowCount(); i++)
{
if (clearData)
{
grid.setText(i, 0, " ");
}
}
}

```

1.  在`DynamicListsPanel`的构造函数中，创建一个新的`HorizontalPanel`，我们将用它作为添加到用户界面的小部件的容器。同时，创建服务目标并设置其入口点。

```java
HorizontalPanel workPanel = new HorizontalPanel();
ServiceDefTarget endpoint = (ServiceDefTarget)
dynamicListsService;
endpoint.setServiceEntryPoint("/Samples/dynamiclists");

```

1.  在同一个构造函数中，添加一个事件处理程序来监听对“选择制造商”表格的点击。

```java
manufacturers.addTableListener(new TableListener()
{
public void onCellClicked
(SourcesTableEvents sender,
int row, int cell)
{
clearSelections(manufacturers,
false);
clearSelections(brands, true);
clearSelections(models, true);
selectedManufacturer = row;
AsyncCallback callback = new
AsyncCallback()
{
public void onSuccess(Object
result)
{
brands.clear();
int row = 0;
for (Iterator iter =
((ArrayList) result).
iterator();
iter.hasNext();)
{
brands.setText(row++, 0,
(String) iter.next());
}
}
public void onFailure(Throwable
caught)
{
Window.alert("Error calling
the Dynamic Lists service to
get the brands." +
caught.getMessage());
}
};
dynamicListsService.getBrands
(manufacturers.getText(row,
cell),callback);
}
});

```

1.  在同一个构造函数中，添加一个事件处理程序来监听对“选择品牌”表格的点击。

```java
brands.addTableListener
(new TableListener()
{
public void onCellClicked
(SourcesTableEvents sender, int row, int cell)
{
clearSelections(brands, false);
clearSelections(models, true);
AsyncCallback callback = new
AsyncCallback()
{
public void onSuccess(Object result)
{
models.clear();
int row = 0;
for (Iterator iter = ((ArrayList)
result).iterator(); iter.hasNext();)
{
models.setText(row++, 0, (String)
iter.next());
}
}
public void onFailure(Throwable caught)
{
Window.alert("Error calling the Dynamic
Lists service to get the models." +
caught.getMessage());
}
};
dynamicListsService.getModels
(manufacturers.getText
(selectedManufacturer, cell),
brands.getText(row, cell), callback);
}
});

```

1.  在构造函数中，还要添加一个监听器，以便在选择车型时清除选择。在应用程序启动时，加载“选择制造商”表格的数据。

```java
models.addTableListener(new TableListener()
{
public void onCellClicked
(SourcesTableEvents sender, int row,
int cell)
{
clearSelections(models, false);
models.getCellFormatter()
.setStyleName(row, cell,
"dynamicLists-Selected");
}
});
AsyncCallback callback = new AsyncCallback()
{
public void onSuccess(Object result)
{
int row = 0;
for (Iterator iter = ((ArrayList) result).iterator(); iter.hasNext();)
{
manufacturers.setText(row++, 0, (String) iter.next());
}
}
public void onFailure(Throwable caught)
{
Window.alert("Error calling the Dynamic Lists service to
get the manufacturers." + caught.getMessage());
}
};
dynamicListsService.getManufacturers(callback);

```

1.  在构造函数中，创建一个名为`itemPanel`的`VerticalPanel`，并将每个表格及其相关的标签添加到其中。为三个表格创建一个`itemPanel`，设置样式，并将它们添加到`workPanel`中。

```java
VerticalPanel itemPanel = new VerticalPanel();
Label itemLabel = new Label("Select Manufacturer");
itemLabel.setStyleName("dynamicLists-Label");
itemPanel.add(itemLabel);
itemPanel.add(manufacturers);
workPanel.add(itemPanel);
itemPanel = new VerticalPanel();
itemLabel = new Label("Select Brand");
itemLabel.setStyleName("dynamicLists-Label");
itemPanel.add(itemLabel);
itemPanel.add(brands);
workPanel.add(itemPanel);
itemPanel = new VerticalPanel();
itemLabel = new Label("Models");
itemLabel.setStyleName("dynamicLists-Label");
itemPanel.add(itemLabel);
itemPanel.add(models);
workPanel.add(itemPanel);
manufacturers.setStyleName("dynamicLists-List");
brands.setStyleName("dynamicLists-List");
models.setStyleName("dynamicLists-List");
workPanel.setStyleName("dynamicLists-Panel");

```

1.  最后，在构造函数中，创建一个小的信息面板，显示关于这个应用程序的描述性文本，这样当我们在`Samples`应用程序的可用示例列表中选择此样本时，我们可以显示这个文本。将信息面板和工作面板添加到一个停靠面板中，并设置小部件。

```java
HorizontalPanel infoPanel = new HorizontalPanel();
infoPanel.add(new HTML(
"<div class='infoProse'>This example
demonstrates the creation of dynamic
lists. You select an item from the first
list and corresponding items are retrieved
asynchronously from the server to display
in the second list. You can then select an
item in the second list to get another
selection of items. In this particular
example, we retrieve car brand by
manufacturer, and then get and display the
specific models for the selected
brand.</div>"));
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

1.  将服务添加到`Samples`应用程序的模块文件中——`com.packtpub.gwtbook.samples`包中的`Samples.gwt.xml`。

```java
<servlet path="/dynamiclists" class=
"com.packtpub.gwtbook.samples.server.DynamicListsServiceImpl"/>

```

这是一个应用程序的截图，当我们选择了其中一个制造商——奔驰，和它的一个品牌——E 级时：

![操作时间—过滤搜索条件](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_04_07.jpg)

### 刚刚发生了什么？

我们创建了一个制造商对象的列表，每个制造商一个。每个制造商对象都包含一个名为品牌的`HashMap`，其中包含该特定品牌的车型的`ArrayList`。我们刚刚创建的这个数据结构包含了关于制造商提供的品牌和车型的所有信息。在实际应用中，这些数据通常会从企业数据源中检索出来。例如，这是我们如何构建奔驰制造商的数据：

```java
brandModels = new ArrayList();
brandModels.add("E300");
brandModels.add("E500");
manufacturerBrands = new HashMap();
manufacturerBrands.put("E-Class", brandModels);
brandModels = new ArrayList();
brandModels.add("C250");
brandModels.add("C300");
manufacturerBrands.put("C-Class", brandModels);
manufacturer = new Manufacturer(manufacturerBrands);
data.put("Mercedes", manufacturer);

```

然后，我们实现了接口中的三个服务方法，以返回制造商列表、给定制造商的品牌列表，最后是给定制造商和品牌的车型列表。这些方法中的每一个都导航到制造商对象，并检索并返回包含必要信息的列表。当我们请求给定品牌和制造商的车型列表时，服务方法的实现通过导航制造商列表返回列表，如下所示：

```java
Manufacturer mfr = (Manufacturer) data.get(manufacturer);
HashMap mfrBrands = (HashMap) mfr.getBrands();
for (Iterator iter = ((ArrayList) mfrBrands.get(brand)).iterator();
iter.hasNext();)
{
modelsList.add((String) iter.next());
}
return modelsList;

```

用户界面由三个网格小部件组成。网格是另一种可以在其单元格中包含文本、HTML 或子小部件的表格小部件。当应用程序初始化时，首先从`DynamicListsService`中检索制造商列表，然后用数据填充制造商网格。注册了一个事件处理程序来监听网格中的点击。当制造商网格中的项目被点击时，我们首先清除品牌网格，然后调用服务的`getBrands()`方法，并用检索到的信息加载品牌网格。当用户通过点击在品牌网格中选择一个项目时，我们首先清除车型网格，然后调用服务的`getModels()`方法，并用检索到的信息加载车型网格。每当我们在任何网格中进行选择时，我们都能够使用 GWT 检索到所有这些信息，而无需进行任何页面刷新或提交！

# Flickr 风格的可编辑标签

Flickr（[`flickr.com/`](http://flickr.com/)）是互联网上最具创新性的 Web 2.0 网站之一。其使用 AJAX 使得这个网站非常愉快。一个典型的例子是在您添加到 flickr 帐户的任何图像下方显示的标签小部件。它看起来像一个简单的标签，但当您将光标悬停在其上时，它会改变颜色，表明它不仅仅是一个标签。当您单击它时，它会转换为一个文本框，您可以在其中编辑标签中的文本！您甚至可以获得按钮来使您的更改持久化或取消以放弃更改。保存或取消后，它会再次转换为标签。试一试。这真的很棒！这是将多个 HTML 控件-标签、文本框和按钮-组合成一个复合控件的绝佳方式，可以节省网页上的宝贵空间，同时以非常用户友好的方式提供必要的功能。在本节中，我们将使用 GWT 中可用的小部件重新创建 flickr 风格的标签。

## 行动时间-自定义可编辑标签

我们将创建一个标签，当您单击它时会动态转换为可编辑的文本框。它还将为您提供保存更改或丢弃更改的能力。如果您修改文本并保存更改，则标签文本将更改，否则原始文本将保留，并且文本框将转换回标签。这是一个非常创新的用户界面，您真的需要使用它来欣赏它！

1.  在`com.packtpub.gwtbook.samples.client.panels`包中创建一个名为`FlickrEditableLabelPanel.java`的新 Java 文件。为用户界面创建一个图像、一个标签、一个文本框和两个按钮。

```java
private Label originalName;
private String originalText;
private Button saveButton;
private Button cancelButton;
private Image image = new Image("images/sample.jpg");
private Label orLabel = new Label("or");

```

1.  创建一个私有方法来显示文本框以及按钮，同时隐藏标签。这将基本上将标签转换为带有按钮的文本框！

```java
private void ShowText()
{
originalText = originalName.getText();
originalName.setVisible(false);
saveButton.setVisible(true);
orLabel.setVisible(true);
cancelButton.setVisible(true);
newName.setText(originalText);
newName.setVisible(true);
newName.setFocus(true);
newName.setStyleName("flickrPanel-textBox-edit");
}

```

1.  在`FlickrEditableLabelPanel`的构造函数中，创建一个事件处理程序，以侦听标签的单击，并调用上述方法。

```java
originalName.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
ShowText();
}
});

```

1.  此外，在构造函数中，创建一个事件处理程序，以侦听鼠标悬停并修改标签样式，为用户提供视觉提示，以便单击标签。

```java
originalName.addMouseListener(new MouseListener()
{
public void onMouseDown
(Widget sender, int x, int y)
{
}
public void onMouseEnter
(Widget sender)
{
originalName.setStyleName
"flickrPanel-label-hover");
}
public void onMouseLeave
(Widget sender)
{
originalName.setStyleName
("flickrPanel-label");
}
public void onMouseMove
(Widget sender, int x, int y)
{
}
public void onMouseUp
(Widget sender, int x, int y)
{
}
});

```

1.  在构造函数中为输入新名称创建一个文本框，并创建一个事件处理程序，以侦听文本框中的焦点的回车键和 ESC 键，并保存更改或取消更改。

```java
newName.addKeyboardListener(new KeyboardListenerAdapter()
{
public void onKeyPress(Widget sender, char keyCode, int
modifiers)
{
switch (keyCode)
{
case KeyboardListenerAdapter. KEY_ENTER:saveChange();
break;
case KeyboardListenerAdapter. KEY_ESCAPE:cancelChange();
break;
}
}
});

```

1.  在构造函数中创建一个事件处理程序，以侦听保存按钮的单击并保存更改。

```java
saveButton.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
saveChange();
}
});

```

1.  在构造函数中创建一个事件处理程序，以侦听取消按钮的单击并丢弃所做的任何更改。

```java
cancelButton.addClickListener(new ClickListener()
{
public void onClick(Widget sender)
{
cancelChange();
}
});

```

1.  在构造函数中，设置应用程序首次加载时小部件的可见性。当首次显示用户界面时，我们希望显示标签，而隐藏其他所有内容。

```java
originalName.setVisible(true);
newName.setVisible(false);
saveButton.setVisible(false);
orLabel.setVisible(false);
cancelButton.setVisible(false);

```

1.  最后，在构造函数中，创建一个名为`buttonPanel`的`HorizontalPanel`，并将我们创建的小部件添加到其中。创建一个名为`workPanel`的`VerticalPanel`，并将`buttonPanel`添加到其中。创建一个小信息面板，显示有关此应用程序的描述性文本，以便在我们的`Samples`应用程序的可用样本列表中选择此样本时显示此文本。将信息面板和工作面板添加到一个停靠面板，并初始化小部件。

```java
HorizontalPanel buttonPanel = new HorizontalPanel();
buttonPanel.setStyleName("flickrPanel-buttonPanel");
buttonPanel.add(saveButton);
buttonPanel.add(orLabel);
buttonPanel.add(cancelButton);
DockPanel workPane = new DockPanel();
workPane.add(infoPanel, DockPanel.NORTH);
VerticalPanel workPanel = new VerticalPanel();
workPanel.setStyleName("flickrPanel");
workPanel.add(image);
workPanel.add(originalName);
workPanel.add(newName);
workPanel.add(buttonPanel);
workPane.add(workPanel, DockPanel.CENTER);
workPane.setCellHeight(workPanel, "100%");
workPane.setCellWidth(workPanel, "100%");
initWidget(workPane);

```

1.  创建一个私有方法来显示标签并隐藏文本。现在我们正在隐藏标签，并显示我们漂亮的文本编辑界面，其中包括文本框和用于保存或放弃所做更改的按钮。

```java
private void showLabel()
{
originalName.setVisible(true);
saveButton.setVisible(false);
orLabel.setVisible(false);
cancelButton.setVisible(false);
newName.setVisible(false);
}

```

1.  创建一个私有方法来保存更改。

```java
private void saveChange()
{
originalName.setText(newName.getText());
showLabel();
// This is where you can call an RPC service to update
// a db or call some other service to propagate
// the change. In this example we just change the
// text of the label.
}

```

1.  创建一个丢弃更改的方法。

```java
public void cancelChange()
{
originalName.setText(originalText);
showLabel();
}

```

当您访问页面时，应用程序的外观如下：

![行动时间-自定义可编辑标签](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_04_08.jpg)

如果单击图像下方的标签，它将转换为带有保存和取消按钮的文本框。您可以修改文本并保存更改，或单击取消以将其更改回标签。

![Time for Action—A Custom Editable Label](https://github.com/OpenDocCN/freelearn-javaweb-zh/raw/master/docs/ggl-web-tk-gwt/img/1007_04_09.jpg)

### 刚刚发生了什么？

我们创建了一个用户界面，其中包括一个带有标签的图像，一个文本框，一个保存按钮，一个标签和一个取消按钮。事件处理程序被注册用来监听标签的点击。当用户点击标签时，事件处理程序被触发，我们隐藏标签，并设置文本框和按钮可见。

```java
originalText = originalName.getText();
originalName.setVisible(false);
saveButton.setVisible(true);
orLabel.setVisible(true);
cancelButton.setVisible(true);
newName.setText(originalText);
newName.setVisible(true);
newName.setFocus(true);
newName.setStyleName("flickrPanel-textBox-edit");

```

如果我们修改文本并点击保存，监听保存按钮点击的事件处理程序将保存文本作为标签的值，并再次显示标签并隐藏所有其他小部件。

```java
originalName.setText(newName.getText());
originalName.setVisible(true);
saveButton.setVisible(false);
orLabel.setVisible(false);
cancelButton.setVisible(false);
newName.setVisible(false);

```

如果我们通过点击取消按钮放弃更改，监听取消按钮点击的事件处理程序将显示标签并隐藏所有其他小部件。

```java
originalName.setText(originalText);
originalName.setVisible(true);
saveButton.setVisible(false);
orLabel.setVisible(false);
cancelButton.setVisible(false);
newName.setVisible(false);

```

在这个应用程序中，我们没有调用任何服务来传播更改到服务器端的过程，但我们可以很容易地通过添加代码来调用服务，以保存对文本所做的更改。

# 摘要

在本章中，我们看了创建一个实时搜索应用程序。然后我们看了创建一个密码强度检查器。此外，我们创建了可以从服务器自动填充信息的表单。我们还创建了对表进行排序的应用程序。然后在创建类似 flickr 风格的可编辑标签之前，我们创建了根据用户选择动态填充列表的应用程序。

在下一章中，我们将学习创建响应式复杂界面，使用 GWT 的一些更高级的功能。
