# 安卓 SQLite 基础知识（一）

> 原文：[`zh.annas-archive.org/md5/C362B2CF2341EAB7AC3F3FDAF20E2012`](https://zh.annas-archive.org/md5/C362B2CF2341EAB7AC3F3FDAF20E2012)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Android 可能是本十年的热词。在短短的时间内，它已经占据了大部分手机市场。Android 计划在今年秋天通过 Android L 版本接管可穿戴设备、我们的电视房间以及我们的汽车。随着 Android 的快速增长，开发人员也需要提升自己的技能。面向数据库的应用程序开发是每个开发人员都应该具备的关键技能之一。应用程序中的 SQLite 数据库是数据中心产品的核心，也是构建优秀产品的关键。理解 SQLite 并实现 Android 数据库对一些人来说可能是一个陡峭的学习曲线。诸如内容提供程序和加载程序之类的概念更加复杂，需要更多的理解和实现。*Android SQLite Essentials*以简单的方式为开发人员提供了构建基于数据库的 Android 应用程序的工具。它是根据当前行业的需求和最佳实践编写的。让我们开始我们的旅程。

# 本书涵盖内容

第一章, *进入 SQLite*，提供了对 SQLite 架构、SQLite 基础知识及其与 Android 的连接的深入了解。

第二章, *连接点*，介绍了如何将数据库连接到 Android 视图。它还涵盖了构建以数据库为中心/启用的应用程序应遵循的一些最佳实践。

第三章, *分享就是关怀*，将反映如何通过内容提供程序访问和共享 Android 中的数据，以及如何构建内容提供程序。

第四章, *小心处理线程*，将指导您如何使用加载程序并确保数据库和数据的安全。它还将为您提供探索在 Android 应用程序中构建和使用数据库的替代方法的提示。

# 本书所需内容

为了有效地使用本书，您需要一个预装有 Windows、Ubuntu 或 Mac OS 的工作系统。下载并设置 Java 环境；我们需要这个环境来运行我们选择的 IDE Eclipse。从 Android 开发者网站下载 Android SDK 和 Eclipse 的 Android ADT 插件。或者，您可以下载包含 Eclipse SDK 和 ADT 插件的 Eclipse ADT 捆绑包。您也可以尝试 Android Studio；这个 IDE 刚刚转入 beta 版，也可以在开发者网站上找到。确保您的操作系统、JDK 和 IDE 都是 32 位或 64 位中的一种。

# 本书适合对象

*Android SQLite Essentials*是一本面向 Android 程序员的指南，他们想要探索基于 SQLite 数据库的 Android 应用程序。读者应该具有一些 Android 基本构建块的实际经验，以及 IDE 和 Android 工具的知识。

# 约定

在本书中，您将找到一些文本样式，用于区分不同类型的信息。以下是这些样式的一些示例以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“要关闭`Cursor`对象，将使用`close()`方法调用。”

代码块设置如下：

```kt
ContentValues cv = new ContentValues();
cv.put(COL_NAME, "john doe");
cv.put(COL_NUMBER, "12345000");
dataBase.insert(TABLE_CONTACTS, null, cv);
```

任何命令行输入或输出都以以下形式书写：

```kt
adb shell SQLite3 --version
SQLite 3.7.11: API 16 - 19
SQLite 3.7.4: API 11 - 15
SQLite 3.6.22: API 8 - 10
SQLite 3.5.9: API 3 - 7

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词、菜单或对话框中的单词等，都会以这种方式出现在文本中：“从**Windows**菜单中转到**Android 虚拟设备管理器**以启动模拟器。”

### 注意

警告或重要提示以以下方式显示在一个框中。

### 提示

提示和技巧以这种方式出现。


# 第一章：进入 SQLite

SQLite 的架构师和主要作者 Richard Hipp 博士在他 2007 年 6 月接受《卫报》采访时解释了一切是如何开始的：

> “我是在 2000 年 5 月 29 日开始的。现在已经七年多了，”他说。他当时正在做一个项目，使用了一个数据库服务器，但数据库不时会离线。“然后我的程序会出错，说数据库不工作了，我就因此受到指责。所以我说，这个数据库对我的应用来说并不是一个很苛刻的要求，为什么我不直接和磁盘对话，然后以这种方式构建一个 SQL 数据库引擎呢？就是这样开始的。”

在我们开始探索 Android 环境中的 SQLite 之旅之前，我们想要告诉您一些先决条件。以下是非常基本的要求，您需要付出很少的努力：

+   您需要确保 Android 应用程序构建的环境已经就位。当我们说“环境”时，我们指的是 JDK 和 Eclipse 的组合，我们的 IDE 选择，ADT 插件和 Android SDK 工具。如果这些还没有就位，ADT 捆绑包中包含了 IDE、ADT 插件、Android SDK 工具和平台工具，可以从[`developer.android.com/sdk/index.html`](http://developer.android.com/sdk/index.html)下载。链接中提到的步骤非常易懂。对于 JDK，您可以访问 Oracle 的网站下载最新版本并在[`www.oracle.com/technetwork/java/javase/downloads/index.html`](http://www.oracle.com/technetwork/java/javase/downloads/index.html)设置它。

+   您需要对 Android 组件有基本的了解，并且在 Android 模拟器上运行过不止“Hello World”程序。如果没有，Android 开发者网站上有一个非常合适的指南来设置模拟器。我们建议您熟悉基本的 Android 组件：Intent、Service、Content Providers 和 Broadcast Receiver。Android 开发者网站上有很好的示例库和文档。其中一些如下：

+   模拟器：[`developer.android.com/tools/devices/index.html`](http://developer.android.com/tools/devices/index.html)

+   Android 基础：[`developer.android.com/training/basics/firstapp/index.html`](http://developer.android.com/training/basics/firstapp/index.html)

有了这些准备，我们现在可以开始探索 SQLite 了。

在这一章中，我们将涵盖以下内容：

+   为什么选择 SQLite？

+   SQLite 的架构

+   数据库基础知识快速回顾

+   Android 中的 SQLite

# 为什么选择 SQLite？

SQLite 是一个嵌入式 SQL 数据库引擎。它被广泛应用于诸如 Adobe 集成运行时（AIR）中的 Adobe、空中客车公司的飞行软件、Python 等知名公司。在移动领域，由于其轻量级的特性，SQLite 是各种平台上非常受欢迎的选择。苹果在 iPhone 中使用它，谷歌在 Android 操作系统中使用它。

它被用作应用程序文件格式，电子设备的数据库，网站的数据库，以及企业关系数据库管理系统。是什么让 SQLite 成为这些以及许多其他公司的如此有趣的选择呢？让我们更仔细地看看 SQLite 的特点，看看它为什么如此受欢迎：

+   零配置：SQLite 被设计成不需要配置文件。它不需要安装步骤或初始设置；它没有运行服务器进程，即使它崩溃也不需要恢复步骤。它没有服务器，直接嵌入在我们的应用程序中。此外，不需要管理员来创建或维护数据库实例，或者为用户设置权限。简而言之，这是一个真正无需 DBA 的数据库。

+   无版权：SQLite 不是以许可证而是以祝福的形式提供。SQLite 的源代码是公有领域的；您可以自由修改、分发，甚至出售代码。甚至贡献者也被要求签署一份声明，以保护免受未来可能发生的任何版权纠纷的影响。

+   **跨平台**: 一个系统的数据库文件可以轻松地移动到运行不同架构的系统上。这是可能的，因为数据库文件格式是二进制的，所有的机器都使用相同的格式。在接下来的章节中，我们将从 Android 模拟器中提取数据库到 Windows。

+   **紧凑**: 一个 SQLite 数据库是一个普通的磁盘文件；它没有服务器，被设计成轻量级和简单。这些特性导致了一个非常轻量级的数据库引擎。与其他 SQL 数据库引擎相比，SQLite Version 3.7.8 的占用空间小于 350 KiB（kibibyte）。

+   **防错**: 代码库有很好的注释，易于理解，而且是模块化的。SQLite 中的测试用例和测试脚本的代码量大约是 SQLite 库源代码的 1084 倍，他们声称测试覆盖了 100%的分支。这种级别的测试重新确立了开发者对 SQLite 的信心。

### 注意

有兴趣的读者可以在维基百科上阅读更多关于分支测试覆盖的信息，网址为[`en.wikipedia.org/wiki/Code_coverage`](http://en.wikipedia.org/wiki/Code_coverage)。

# SQLite 架构

核心、SQL 编译器、后端和数据库构成了 SQLite 的架构：

![SQLite 架构](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951_01_01.jpg)

## SQLite 接口

根据文档，在 SQLite 库堆栈的顶部，大部分公共接口是由`wen.c`，`legacy.c`和`vdbeapi.c`源文件实现的。这是其他程序和脚本的通信点。

## SQL 编译器

分词器将从接口传递的 SQL 字符串分解为标记，并逐个将标记传递给解析器。分词器是用 C 手工编码的。SQLite 的解析器是由 Lemon 解析器生成器生成的。它比 YACC 和 Bison 更快，同时是线程安全的，并防止内存泄漏。解析器从分词器传递的标记构建解析树，并将树传递给代码生成器。生成器从输入生成虚拟机代码，并将其作为可执行文件传递给虚拟机。有关 Lemon 解析器生成器的更多信息，请访问[`en.wikipedia.org/wiki/Lemon_Parser_Generator`](http://en.wikipedia.org/wiki/Lemon_Parser_Generator)。

## 虚拟机

虚拟机，也被称为**虚拟数据库引擎**（**VDBE**），是 SQLite 的核心。它负责从数据库中获取和更改值。它执行代码生成器生成的程序来操作数据库文件。每个 SQL 语句首先被转换为 VDBE 的虚拟机语言。VDBE 的每个指令都包含一个操作码和最多三个附加操作数。

## SQLite 后端

B 树，连同 Pager 和 OS 接口，形成了 SQLite 架构的后端。B 树用于组织数据。Pager 则通过缓存、修改和回滚数据来辅助 B 树。当需要时，B 树会从缓存中请求特定的页面；这个请求由 Pager 以高效可靠的方式处理。OS 接口提供了一个抽象层，可以移植到不同的操作系统。它隐藏了与不同操作系统通信的不必要细节，由 SQLite 调用代表 SQLite 处理。

这些是 SQLite 的内部，Android 应用程序开发者不需要担心 Android 的内部，因为 SQLite Android 库有效地使用了抽象的概念，所有的复杂性都被隐藏起来。只需要掌握提供的 API，就可以满足在 Android 应用程序中使用 SQLite 的所有可能的用例。

# 数据库基础知识的快速回顾

数据库，简单来说，是一种有序的持续存储数据的方式。数据保存在表中。表由不同数据类型的列组成。表中的每一行对应一个数据记录。您可以将表想象成 Excel 电子表格。从面向对象编程的角度来看，数据库中的每个表通常描述一个对象（由类表示）。每个表列举了一个类属性。表中的每条记录表示该对象的特定实例。

让我们看一个快速的例子。假设您有一个名为`Shop`的数据库，其中有一个名为`Inventory`的表。这个表可以用来存储商店中所有产品的信息。`Inventory`表可能包含这些列：`产品名称`（字符串）、`产品 ID`（数字）、`成本`（数字）、`库存`（0/1）和`可用数量`（数字）。然后，您可以向数据库中添加一个名为`鞋子`的产品记录：

| ID | 产品名称 | 产品 ID | 成本 | 库存 | 可用数量 |
| --- | --- | --- | --- | --- | --- |
| 1 | 地毯 | 340023 | 2310 | 1 | 4 |
| 2 | 鞋子 | 231257 | 235 | 1 | 2 |

数据库中的数据应该经过检查和影响。表中的数据可以如下所示：

+   使用`INSERT`命令添加

+   使用`UPDATE`命令修改

+   使用`DELETE`命令删除

您可以通过使用所谓的**查询**在数据库中搜索特定数据。查询（使用`SELECT`命令）可以涉及一个表，或多个表。要生成查询，必须使用 SQL 命令确定感兴趣的表、数据列和数据值。每个 SQL 命令都以分号（`;`）结尾。

## 什么是 SQLite 语句？

SQLite 语句是用 SQL 编写的，用于从数据库中检索数据或创建、插入、更新或删除数据库中的数据。

所有 SQLite 语句都以关键字之一开头：`SELECT`、`INSERT`、`UPDATE`、`DELETE`、`ALTER`、`DROP`等，所有语句都以分号（`;`）结尾。例如：

```kt
CREATE TABLE table_name (column_name INTEGER);
```

`CREATE TABLE`命令用于在 SQLite 数据库中创建新表。`CREATE TABLE`命令描述了正在创建的新表的以下属性：

+   新表的名称。

+   创建新表的数据库。表可以在主数据库、临时数据库或任何已连接的数据库中生成。

+   表中每列的名称。

+   表中每列的声明类型。

+   表中每列的默认值或表达式。

+   每列使用的默认关系序列。

+   最好为表设置一个`PRIMARY KEY`。这将支持单列和复合（多列）主键。

+   每个表的一组 SQL 约束。支持`UNIQUE`、`NOT NULL`、`CHECK`和`FOREIGN KEY`等约束。

+   在某些情况下，表将是`WITHOUT ROWID`表。

以下是一个创建表的简单 SQLite 语句：

```kt
String databaseTable =   "CREATE TABLE " 
   + TABLE_CONTACTS +"(" 
   + KEY_ID  
   + " INTEGER PRIMARY KEY,"
   + KEY_NAME + " TEXT,"
   + KEY_NUMBER + " INTEGER"
   + ")";
```

在这里，`CREATE TABLE`是创建一个名为`TABLE_CONTACTS`的表的命令。`KEY_ID`、`KEY_NAME`和`KEY_NUMBER`是列 ID。SQLite 要求为每个列提供唯一 ID。`INTEGER`和`TEXT`是与相应列关联的数据类型。SQLite 要求在创建表时定义要存储在列中的数据类型。`PRIMARY KEY`是数据列的**约束**（对表中的数据列强制执行的规则）。

SQLite 支持更多的属性，可用于创建表，例如，让我们创建一个`create table`语句，为空列输入默认值。请注意，对于`KEY_NAME`，我们提供了一个默认值`xyz`，对于`KEY_NUMBER`列，我们提供了一个默认值`100`：

```kt
String databaseTable = 
   "CREATE TABLE " 
   + TABLE_CONTACTS  + "(" 
   + KEY_ID    + " INTEGER PRIMARY KEY,"

   + KEY_NAME + " TEXT DEFAULT  xyz,"

   + KEY_NUMBER + " INTEGER DEFAULT 100" + ")";
```

在这里，当在数据库中插入一行时，这些列将以`CREATE` SQL 语句中定义的默认值进行预初始化。

还有更多的关键字，但我们不想让你因为一个庞大的列表而感到无聊。我们将在后续章节中介绍其他关键字。

## SQLite 语法

SQLite 遵循一组称为**语法**的独特规则和指南。

需要注意的一点是，SQLite 是**不区分大小写**的，但有一些命令是区分大小写的，例如，在 SQLite 中，`GLOB`和`glob`具有不同的含义。让我们以 SQLite `DELETE`语句的语法为例。尽管我们使用了大写字母，但用小写字母替换它们也可以正常工作：

```kt
DELETE FROM table WHERE {condition};
```

## SQLite 中的数据类型

SQLite 使用动态和弱类型的 SQL 语法，而大多数 SQL 数据库使用静态、严格的类型。如果我们看其他语言，Java 是一种静态类型语言，Python 是一种动态类型语言。那么当我们说动态或静态时，我们是什么意思呢？让我们看一个例子：

```kt
a=5
a="android"
```

在静态类型的语言中，这将引发异常，而在动态类型的语言中，它将起作用。在 SQLite 中，值的数据类型与其容器无关，而与值本身相关。当处理静态类型系统时，这不是一个问题，其中值由容器确定。这是因为 SQLite 向后兼容更常见的静态类型系统。因此，我们用于静态系统的 SQL 语句可以在这里无缝使用。

### 存储类

在 SQLite 中，我们有比数据类型更一般的**存储**类。在内部，SQLite 以五种存储类存储数据，也可以称为**原始数据类型**：

+   `NULL`：这代表数据库中的缺失值。

+   `INTEGER`：这支持带符号整数的范围，从 1、2、3、4、6 或 8 个字节，取决于值的大小。SQLite 会根据值的大小自动处理这一点。在内存中处理时，它们会被转换为最一般的 8 字节带符号整数形式。

+   `REAL`：这是一个浮点值，SQLite 使用它作为 8 字节 IEEE 浮点数来存储这些值。

+   `TEXT`：SQLite 支持各种字符编码，如 UTF-8、UTF-16BE 或 UTF-16LE。这个值是一个文本字符串。

+   `BLOB`：这种类型存储了一个大的二进制数据数组，就像输入时提供的那样。

SQLite 本身不验证写入列的类型是否实际上是定义的类型，例如，您可以将整数写入字符串列，反之亦然。我们甚至可以有一个单独的列具有不同的存储类：

```kt
 id                   col_t
------               ------
1                       23
2                     NULL
3                     test
```

### 布尔数据类型

SQLite 没有单独的布尔存储类，而是使用`Integer`类来实现这一目的。整数`0`表示假状态，而`1`表示真状态。这意味着 SQLite 间接支持布尔类型，我们只能创建布尔类型的列。问题是，它不包含熟悉的`TRUE`/`FALSE`值。

### 日期和时间数据类型

就像我们在布尔数据类型中看到的那样，在 SQLite 中没有日期和时间数据类型的存储类。SQLite 有五个内置的日期和时间函数来帮助我们处理它；我们可以将日期和时间用作整数、文本或实数值。此外，这些值是可互换的，取决于应用程序的需要。例如，要计算当前日期，请使用以下代码：

```kt
SELECT date('now');
```

# Android 中的 SQLite

Android 软件堆栈由核心 Linux 内核、Android 运行时、支持 Android 框架的 Android 库以及最终运行在所有这些之上的 Android 应用程序组成。Android 运行时使用**Dalvik 虚拟机**（**DVM**）来执行 dex 代码。在较新的 Android 版本中，即从 KitKat（4.4）开始，Android 启用了一个名为**ART**的实验性功能，它最终将取代 DVM。它基于**Ahead of Time**（**AOT**），而 DVM 基于**Just in Time**（**JIT**）。在下图中，我们可以看到 SQLite 提供了本地数据库支持，并且是支持应用程序框架的库的一部分，还有诸如 SSL、OpenGL ES、WebKit 等库。这些用 C/C++编写的库在 Linux 内核上运行，并与 Android 运行时一起构成了应用程序框架的支撑，如下图所示：

![Android 中的 SQLite](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951_01_02.jpg)

在我们开始探索 Android 中的 SQLite 之前，让我们先看看 Android 中的其他持久存储替代方案：

+   **共享偏好**：数据以键值对的形式存储在共享偏好中。文件本身是一个包含键值对的 XML 文件。该文件位于应用程序的内部存储中，可以根据需要进行公共或私有访问。Android 提供了 API 来写入和读取共享偏好。建议在需要保存少量此类数据时使用此功能。一个常见的例子是保存 PDF 中的最后阅读位置，或者保存用户的偏好以显示评分框。

+   **内部/外部存储**：这个术语可能有点误导；Android 定义了两个存储空间来保存文件。在一些设备上，你可能会有一个外部存储设备，比如 SD 卡，而在其他设备上，你会发现系统将其内存分成两部分，分别标记为内部和外部。可以使用 Android API 获取外部和内部存储的路径。默认情况下，内部存储是有限的，只能被应用程序访问，而外部存储可能可用，也可能不可用，具体取决于是否已挂载。

### 提示

`android:installLocation`可以在清单中使用，指定应用程序的内部/外部安装位置。

## SQLite 版本

从 API 级别 1 开始，Android 就内置了 SQLite。在撰写本书时，当前版本的 SQLite 是 3.8.4.1。根据文档，SQLite 的版本是 3.4.0，但已知不同的 Android 版本会内置不同版本的 SQLite。我们可以通过 Android SDK 安装文件夹内的`platform-tools`文件夹中的名为**SQLite3**的工具以及 Android 模拟器轻松验证这一点。

```kt
adb shell SQLite3 --version
SQLite 3.7.11: API 16 - 19
SQLite 3.7.4: API 11 - 15
SQLite 3.6.22: API 8 - 10
SQLite 3.5.9: API 3 - 7

```

我们不需要担心 SQLite 的不同版本，应该坚持使用 3.5.9 以确保兼容性，或者我们可以按照 API 14 是新的`minSdkVersion`的说法，并将其切换为 3.7.4。除非你有特定于某个版本的需求，否则这几乎不重要。

### 注意

一些额外方便的 SQLite3 命令如下：

+   `.dump`：打印表的内容

+   `.schema`：打印现有表的`SQL CREATE`语句

+   `.help`：获取指令

## 数据库包

`android.database`包含了所有与数据库操作相关的必要类。`android.database.SQLite`包含了特定于 SQLite 的类。

### API

Android 提供了各种 API 来创建、访问、修改和删除数据库。完整的列表可能会让人感到不知所措；为了简洁起见，我们将介绍最重要和最常用的 API。

### SQLiteOpenHelper 类

`SQLiteOpenHelper`类是 Android 中用于处理 SQLite 数据库的第一个和最重要的类；它位于`android.database.SQLite`命名空间中。`SQLiteOpenHelper`是一个辅助类，旨在进行扩展，并在创建、打开和使用数据库时实现您认为重要的任务和操作。这个辅助类由 Android 框架提供，用于处理 SQLite 数据库，并帮助管理数据库的创建和版本管理。操作方式是扩展该类，并根据我们的应用程序的要求实现任务和操作。`SQLiteOpenHelper`有以下定义的构造函数：

```kt
SQLiteOpenHelper(Context context, String name, SQLiteDatabase.CursorFactory factory, int version)

SQLiteOpenHelper(Context context, String name, SQLiteDatabase.CursorFactory factory, int version, DatabaseErrorHandler errorHandler)
```

应用程序上下文允许访问应用程序的所有共享资源和资产。`name`参数包括 Android 存储中的数据库文件名。`SQLiteDatabase.CursorFactory`是一个工厂类，用于创建光标对象，充当针对 Android 下 SQLite 应用的所有查询的输出集。数据库的应用程序特定版本号将是版本参数（或更确切地说，它的模式）。

`SQLiteOpenHelper`的构造函数用于创建一个帮助对象来创建、打开或管理数据库。**context**是允许访问所有共享资源和资产的应用程序上下文。`name`参数要么包含数据库的名称，要么为内存中的数据库为 null。`SQLiteDatabase.CursorFactory`工厂创建一个光标对象，充当所有查询的结果集。`version`参数定义了数据库的版本号，并用于升级/降级数据库。第二个构造函数中的`errorHandler`参数在 SQLite 报告数据库损坏时使用。

如果我们的数据库版本号不是默认的`1`，`SQLiteOpenHelper`将触发其`onUpgrade()`方法。`SQLiteOpenHelper`类的重要方法如下：

+   `synchronized void close()`

+   `synchronized SQLiteDatabase getReadableDatabase()`

+   `synchronized SQLiteDatabase getWritableDatabase()`

+   `abstract void onCreate(SQLiteDatabase db)`

+   `void onOpen(SQLiteDatabase db)`

+   `abstract void onUpgrade(SQLiteDatabase db, int oldVersion, int newVersion)`

同步的`close()`方法关闭任何打开的数据库对象。`synchronized`关键字可以防止线程和内存一致性错误。

接下来的两个方法`getReadableDatabase()`和`getWriteableDatabase()`是实际创建或打开数据库的方法。两者都返回相同的`SQLiteDatabase`对象；不同之处在于`getReadableDatabase()`在无法返回可写数据库时将返回可读数据库，而`getWriteableDatabase()`返回可写数据库对象。如果无法打开数据库进行写操作，`getWriteableDatabase()`方法将抛出`SQLiteException`。对于`getReadableDatabase()`，如果无法打开数据库，它将抛出相同的异常。

我们可以使用`SQLiteDatabase`类的`isReadOnly()`方法来了解数据库的状态。对于只读数据库，它返回`true`。

调用这两个方法中的任何一个将在数据库尚不存在时调用`onCreate()`方法。否则，它将调用`onOpen()`或`onUpgrade()`方法，具体取决于版本号。`onOpen()`方法应在更新数据库之前检查`isReadOnly()`方法。一旦打开，数据库将被缓存以提高性能。最后，我们需要调用`close()`方法来关闭数据库对象。

`onCreate()`、`onOpen()`和`onUpgrade()`方法是为了子类实现预期行为。当数据库第一次创建时，将调用`onCreate()`方法。这是我们使用 SQLite 语句创建表的地方，这些语句在前面的示例中已经看到了。当数据库已经配置并且数据库模式已经根据需要创建、升级或降级时，将触发`onOpen()`方法。在这里应该使用`isReadOnly()`方法检查读/写状态。

当数据库需要根据提供的版本号进行升级时，将调用`onUpgrade()`方法。默认情况下，数据库版本是`1`，随着我们增加数据库版本号并发布新版本，将执行升级。

本章的代码包中包含了一个演示 SQLiteOpenHelper 类的简单示例；我们将用它进行解释：

```kt
class SQLiteHelperClass
    {
    ...
    ...
    public static final int VERSION_NUMBER = 1;

    sqlHelper =
       new SQLiteOpenHelper(context, "ContactDatabase", null,
      VERSION_NUMBER)
    {

      @Override
      public void onUpgrade(SQLiteDatabase db,   
            int oldVersion, int newVersion) 
      {

        //drop table on upgrade
        db.execSQL("DROP TABLE IF EXISTS " 
                + TABLE_CONTACTS);
        // Create tables again
        onCreate(db);

      }

   @Override
   public void onCreate(SQLiteDatabase db)
   {
      // creating table during onCreate
      String createContactsTable = 
 "CREATE TABLE "
 + TABLE_CONTACTS + "(" 
 + KEY_ID + " INTEGER PRIMARY KEY," 
 + KEY_NAME + " TEXT,"
 + KEY_NUMBER + " INTEGER" + ")";

        try {
       db.execSQL(createContactsTable);
        } catch(SQLException e) {
          e.printStackTrace();
        }
   }

   @Override
   public synchronized void close()
   {
      super.close();
      Log.d("TAG", "Database closed");
   }

   @Override
   public void onOpen(SQLiteDatabase db)
   {
         super.onOpen(db);
         Log.d("TAG", "Database opened");
   }

};

...
... 

//open the database in read-only mode
SQLiteDatabase db = SQLiteOpenHelper.getWritableDatabase();

...
...

//open the database in read/write mode
SQLiteDatabase db = SQLiteOpenHelper.getWritableDatabase();
```

### 提示

**下载示例代码**

您可以从您在[`www.packtpub.com`](http://www.packtpub.com)的帐户中购买的所有 Packt 图书的示例代码文件。如果您在其他地方购买了本书，您可以访问[`www.packtpub.com/support`](http://www.packtpub.com/support)并注册，直接将文件发送到您的电子邮件。

### SQLiteDatabase 类

现在您已经熟悉了在 Android 中启动 SQLite 数据库使用的辅助类，是时候看看核心的`SQLiteDatabase`类了。`SQLiteDatabase`是在 Android 中使用 SQLite 数据库所需的基类，并提供了打开、查询、更新和关闭数据库的方法。

`SQLiteDatabase`类提供了 50 多种方法，每种方法都有其自己的细微差别和用例。我们将覆盖最重要的方法子集，而不是详尽的列表，并允许您在闲暇时探索一些重载方法。您可以随时参考[`developer.android.com/reference/android/database/sqlite/SQLiteDatabase.html`](http://developer.android.com/reference/android/database/sqlite/SQLiteDatabase.html)上的完整在线 Android 文档了解`SQLiteDatabase`类。

以下是`SQLiteDatabase`类的一些方法：

+   `public long insert (String table, String nullColumnHack, ContentValues values)`

+   `public Cursor query (String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy)`

+   `public Cursor rawQuery(String sql, String[] selectionArgs)`

+   `public int delete (String table, String whereClause, String[] whereArgs)`

+   `public int update (String table, ContentValues values, String whereClause, String[] whereArgs)`

让我们通过一个示例来看看这些`SQLiteDatabase`类的实际应用。我们将在表中插入一个名称和数字。然后，我们将使用原始查询从表中获取数据。之后，我们将介绍`delete()`和`update()`方法，这两种方法都将以`id`作为参数，以确定我们打算删除或更新数据库表中的哪一行数据：

```kt
public void insertToSimpleDataBase() 
{
   SQLiteDatabase db = sqlHelper.getWritableDatabase();

   ContentValues cv = new ContentValues();
   cv.put(KEY_NAME, "John");
   cv.put(KEY_NUMBER, "0000000000");
   // Inserting values in different columns of the table using
   // Content Values
   db.insert(TABLE_CONTACTS, null, cv);

   cv = new ContentValues();
   cv.put(KEY_NAME, "Tom");
   cv.put(KEY_NUMBER, "5555555");
   // Inserting values in different columns of the table using
   // Content Values
   db.insert(TABLE_CONTACTS, null, cv);
}
...
...

public void getDataFromDatabase()
{  
   int count;
   db = sqlHelper.getReadableDatabase();
   // Use of normal query to fetch data
   Cursor cr = db. query(TABLE_CONTACTS, null, null, 
                           null, null, null, null);

   if(cr != null) {
      count = cr.getCount();
      Log.d("DATABASE", "count is : " + count);
   }

   // Use of raw query to fetch data
   cr = db.rawQuery("select * from " + TABLE_CONTACTS, null);
   if(cr != null) {
      count = cr.getCount();
      Log.d("DATABASE", "count is : " + count);
   }

}
...
...

public void delete(String name)
 {
     String whereClause = KEY_NAME + "=?";
     String[] whereArgs = new String[]{name};
     db = sqlHelper.getWritableDatabase();
     int rowsDeleted = db.delete(TABLE_CONTACTS, whereClause, whereArgs);
 }
...
...

public void update(String name)
 {
     String whereClause = KEY_NAME + "=?";
     String[] whereArgs = new String[]{name};
     ContentValues cv = new ContentValues();
     cv.put(KEY_NAME, "Betty");
     cv.put(KEY_NUMBER, "999000");
     db = sqlHelper.getWritableDatabase();
     int rowsUpdated = db.update(TABLE_CONTACTS, cv, whereClause, whereArgs);
 }
```

### ContentValues

`ContentValues`本质上是一组键值对，其中键表示表的列，值是要插入该列的值。因此，在`values.put("COL_1", 1);`的情况下，列是`COL_1`，要插入该列的值是`1`。

以下是一个示例：

```kt
ContentValues cv = new ContentValues();
cv.put(COL_NAME, "john doe");
cv.put(COL_NUMBER, "12345000");
dataBase.insert(TABLE_CONTACTS, null, cv);
```

### 游标

查询会返回一个`Cursor`对象。`Cursor`对象描述了查询的结果，基本上指向查询结果的一行。通过这种方法，Android 可以以一种高效的方式缓冲查询结果；因为它不需要将所有数据加载到内存中。

您可以使用`getCount()`方法获取查询结果的元素。

要在各个数据行之间导航，可以利用`moveToFirst()`和`moveToNext()`方法。`isAfterLast()`方法允许您分析输出是否已经结束。

`Cursor`对象提供了带类型的`get*()`方法，例如`getLong(columnIndex)`和`getString(columnIndex)`方法，以便访问结果的当前位置的列数据。`columnIndex`是您将要访问的列的编号。

`Cursor`对象还提供了`getColumnIndexOrThrow(String)`方法，允许您获取表的列名的列索引。

要关闭`Cursor`对象，将使用`close()`方法调用。

数据库查询返回一个游标。这个接口提供了对结果集的随机读写访问。它指向查询结果的一行，使得 Android 能够有效地缓冲结果，因为现在不需要将所有数据加载到内存中。

返回的游标指针指向第 0 个位置，也就是游标的第一个位置。我们需要在`Cursor`对象上调用`moveToFirst()`方法；它将游标指针移动到第一个位置。现在我们可以访问第一条记录中的数据。

如果来自多个线程的游标实现，应在使用游标时执行自己的同步。通过调用`close()`方法关闭游标以释放对象持有的资源。

我们将遇到一些其他支持方法，如下所示：

+   `getCount()`方法：返回查询结果中元素的数量。

+   `get*()`方法：用于访问结果的当前位置的列数据，例如，`getLong(columnIndex)`和`getString(columnIndex)`。

+   `moveToNext()`方法：将游标移动到下一行。如果游标已经超过了结果集中的最后一个条目，它将返回`false`。

# 总结

在本章中，我们介绍了 SQLite 的特性和内部架构。我们从讨论 SQLite 的显著特点开始，然后介绍了 SQLite 的基本架构，如语法和数据类型，最后转向了 Android 中的 SQLite。我们探索了在 Android 中使用 SQLite 的 Android API。

在下一章中，我们将专注于将本章学到的知识应用到构建 Android 应用程序中。我们将专注于 UI 元素和将 UI 连接到数据库组件。


# 第二章：连接点

|   | *"除非你以多种方式学习，否则你不会理解任何东西。"* |   |
| --- | --- | --- |
|   | --*-Marvin Minsky* |

在上一章中，我们学习了两个重要的 Android 类及其相应的方法，以便与 SQLite 数据库一起工作：

+   `SQLiteOpenHelper`类

+   `SQLiteDatabase`类

我们还看到了解释它们实现的代码片段。现在，我们准备在 Android 应用程序中使用所有这些概念。我们将利用上一章中学到的知识来制作一个功能性的应用程序。我们还将进一步研究插入、查询和删除数据库中的数据的 SQL 语句。

在本章中，我们将在 Android 模拟器上构建和运行 Android 应用程序。我们还将构建我们自己的完整的`contacts`数据库。在本章的过程中，我们将遇到 Android UI 组件，如`Buttons`和`ListView`。如果需要重新访问 Android 中的 UI 组件，请访问链接[`developer.android.com/design/building-blocks/index.html`](http://developer.android.com/design/building-blocks/index.html)。

在我们开始之前，本章的代码旨在解释与 Android 中的 SQLite 数据库相关的概念，并不适用于生产；在许多地方，您会发现缺乏适当的异常处理或适当的空值检查以及类似的实践，以减少代码的冗长。您可以从 Packt 的网站下载当前和以下章节的完整代码。为了获得最佳结果，我们建议在阅读本章的过程中下载代码并参考它。

在本章中，我们将涵盖：

+   构建模块

+   数据库处理程序和查询

+   连接 UI 和数据库

# 构建模块

Android 以在不同硬件和软件规格的各种设备上运行而闻名。在撰写本书时，激活标记已经突破了 10 亿。运行 Android 的设备数量惊人，为用户提供了不同形态和不同硬件基础的丰富选择。当在不同设备上测试应用程序时，这增加了障碍，因为人类不可能获得所有这些设备，更不用说需要投入其中的时间和资本。模拟器本身是一个很好的工具；它使我们能够通过模拟不同的硬件特性（如 CPU 架构、RAM 和相机）和从早期的 Cupcake 到 KitKat 的不同软件版本，来规避这个问题。我们还将尝试利用这一优势来运行我们的应用程序。使用模拟器的另一个好处是，我们将运行一个已 root 的设备，这将允许我们执行一些操作。在普通设备上，我们将无法执行这些操作。

让我们从在 Eclipse 中设置模拟器开始：

1.  转到**窗口**菜单中的**Android 虚拟设备管理器**以启动模拟器。

我们可以设置不同的硬件属性，如 CPU 类型、前/后摄像头、RAM（最好在 Windows 机器上少于 768MB）、内部和外部存储大小。

1.  启动应用程序时，启用**保存快照**；这将减少下次从快照启动模拟器实例时的启动时间：![Building blocks](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951_02_01.jpg)

### 注意

有兴趣的读者可以尝试在[`www.genymotion.co`](http://www.genymotion.co)上尝试更快的模拟器 Genymotion。

现在让我们开始构建我们的 Android 应用程序。

1.  我们将从创建一个名为`PersonalContactManager`的新项目开始。转到**文件** | **新建** | **项目**。现在，导航到**Android**，然后选择**Android 应用程序项目**。这一步将为我们提供一个活动文件和一个相应的 XML 文件。

在我们放置所有需要的块之后，我们将回到这些组件。对于我们的应用程序，我们将创建一个名为`contact`的数据库，其中将包含一个名为`ContactsTable`的表。在上一章中，我们讨论了如何使用 SQL 语句创建数据库；让我们为我们的项目构建一个数据库架构。这是一个非常重要的步骤，它基于我们应用程序的要求；例如，在我们的情况下，我们正在构建一个个人联系人管理器，并且将需要诸如姓名、号码、电子邮件和显示图片等字段。

`ContactsTable`的数据库架构概述如下：

| 列 | 数据类型 |
| --- | --- |
| `Contact_ID` | 整数/主键/自动递增 |
| `姓名` | 文本 |
| `号码` | 文本 |
| `电子邮件` | 文本 |
| `照片` | Blob |

### 注意

一个 Android 应用可以有多个数据库，每个数据库可以有多个表。每个表以 2D（行和列）格式存储数据。

第一列是`Contact_ID`。它的数据类型是整数，其**列约束**是主键。此外，当在该行中插入数据时，该列是自动递增的，这意味着对于每一行，它将递增一次。

主键唯一标识每一行，不能为 null。数据库中的每个表最多可以有一个主键。一个表的主键可以作为另一个表的外键。外键作为两个相关表之间的连接；例如，我们当前的`ContactsTable`架构是：

```kt
ContactsTable (Contact_ID,Name, Number, Email, Photo)
```

假设我们有另一个具有以下架构的表`ColleagueTable`：

```kt
ColleagueTable (Colleague_ID, Contact_ID, Position, Fax)
```

在这里，`ContactTable`的主键，即`Contact_ID`可以称为`ColleagueTable`的外键。它用于在关系数据库中连接两个表，因此允许我们对`ColleagueTable`执行操作。我们将在接下来的章节和示例中详细探讨这个概念。

### 注意

**列约束**

约束是对表中数据列强制执行的规则。这确保了数据库中数据的准确性和可靠性。

与大多数 SQL 数据库不同，SQLite 不会根据声明的列类型限制可以插入列的数据类型。相反，SQLite 使用**动态类型**。列的声明类型仅用于确定列的**亲和性**。当将一种类型的变量存储在另一种类型中时，也会进行类型转换（自动）。

约束可以是列级或表级。列级约束仅应用于一列，而表级约束应用于整个表。

以下是 SQLite 中常用的约束和关键字：

+   `NOT NULL`约束：这确保列没有`NULL`值。

+   `DEFAULT`约束：当未指定列的默认值时，这为列提供了默认值。

+   `UNIQUE`约束：这确保列中的所有值都不同。

+   主键：这个唯一标识数据库表中所有行/记录的键。

+   `CHECK`约束：`CHECK`约束确保列中的所有值满足某些条件。

+   `AUTO INCREMENT`关键字：`AUTOINCREMENT`是一个用于自动递增表中字段值的关键字。我们可以使用`AUTOINCREMENT`关键字来自动递增一个字段值，当创建一个具有特定列名的表时，使用`AUTOINCREMENT`关键字。关键字`AUTOINCREMENT`只能与`INTEGER`字段一起使用。

下一步是准备我们的数据模型；我们将使用我们的模式来构建数据模型类。`ContactModel`类将具有`Contact_ID`、`Name`、`Number`、`Email`和`Photo`作为字段，它们分别表示为`id`、`name`、`contactNo`、`email`和`byteArray`。该类将包括一个 getter/setter 方法，根据需要设置和获取属性值。数据模型的使用将有助于活动与数据库处理程序之间的通信，我们将在本章后面定义。我们将在其中创建一个新的包和一个新的类，称为`ContactModel`类。请注意，创建一个新的包不是必要的步骤；它用于以逻辑和易于访问的方式组织我们的类。这个类可以描述如下：

```kt
public class ContactModel {
  private int id;
  private String name, contactNo, email;
  private byte[] byteArray;

  public byte[] getPhoto() {
    return byteArray;
  }
  public void setPhoto(byte[] array) {
    byteArray = array;
  }
  public int getId() {
    return id;
  }
  public void setId(int id) {
    this.id = id;
  }
  ……………
}
```

### 提示

Eclipse 提供了很多有用的快捷方式，但不包括生成 getter 和 setter 方法。我们可以将生成 getter 和 setter 方法绑定到任何我们喜欢的键绑定上。在 Eclipse 中，转到**窗口** | **首选项** | **常规** | **键**，搜索 getter，并添加你的绑定。我们使用*Alt* + *Shift* + *G*；你可以自由设置任何其他键组合。

# 数据库处理程序和查询

我们将构建一个支持类，该类将根据我们的数据库需求包含读取、更新和删除数据的方法。这个类将使我们能够创建和更新数据库，并充当我们的数据管理中心。我们将使用这个类来运行 SQLite 查询，并将数据发送到 UI；在我们的情况下，是一个 listview 来显示结果：

```kt
public class DatabaseManager {

  private SQLiteDatabase db; 
  private static final String DB_NAME = "contact";

  private static final int DB_VERSION = 1;
  private static final String TABLE_NAME = "contact_table";
  private static final String TABLE_ROW_ID = "_id";
  private static final String TABLE_ROW_NAME = "contact_name";
  private static final String TABLE_ROW_PHONENUM = "contact_number";
  private static final String TABLE_ROW_EMAIL = "contact_email";
  private static final String TABLE_ROW_PHOTOID = "photo_id";
  .........
}
```

我们将创建一个`SQLiteDatabase`类的对象，稍后我们将用`getWritableDatabase()`或`getReadableDatabase()`来初始化它。我们将定义整个类中将要使用的常量。

### 注意

按照惯例，常量以大写字母定义，但在定义常量时使用`static final`比惯例更多一些。要了解更多，请参考[`goo.gl/t0PoQj`](http://goo.gl/t0PoQj)。

我们将把数据库的名称定义为`contact`，并将版本定义为 1。如果我们回顾前一章，我们会记得这个值的重要性。对这个值的快速回顾使我们能够将数据库从当前版本升级到新版本。通过这个例子，用例将变得清晰。假设将来有一个新的需求，即我们需要在我们的联系人详细信息中添加传真号码。我们将修改我们当前的模式以包含这个变化，我们的联系人数据库将相应地改变。如果我们在新设备上安装应用程序，就不会有问题；但在已经运行应用程序的设备上，我们将面临问题。在这种情况下，`DB_VERSION`将派上用场，并帮助我们用当前版本替换旧版本的数据库。另一种方法是卸载应用程序并重新安装，但这是不鼓励的。

现在将定义表名和重要字段，如表列。`TABLE_ROW_ID`是一个非常重要的列。这将作为表的主键；它还将自动递增，不能为 null。`NOT NULL`再次是一个列约束，它只能附加到列定义，并且不能作为表约束指定。毫不奇怪，`NOT NULL`约束规定相关列不能包含`NULL`值。在插入新行或更新现有行时，如果尝试将列值设置为`NULL`，将导致约束违规。这将用于在表中查找特定值。ID 的唯一性保证了我们在表中没有与表中数据冲突，因为每一行都是由这个键唯一标识的。表的其余列都相当容易理解。`DatabaseManager`类的构造函数如下：

```kt
public DatabaseManager(Context context) {
   this.context = context;
   CustomSQLiteOpenHelper helper = new CustomSQLiteOpenHelper(context);
   this.db = helper.getWritableDatabase();
  }
```

注意我们使用了一个名为`CustomSQLiteOpenHelper`的类。我们稍后会回到这个问题。我们将使用该类对象来获取我们的`SQLitedatabase`实例。

## 构建创建查询

为了创建一个具有所需列的表，我们将构建一个查询语句并执行它。该语句将包含表名、不同的表列和相应的数据类型。我们现在将看一下创建新数据库以及根据应用程序的需求升级现有数据库的方法：

```kt
private class CustomSQLiteOpenHelper extends SQLiteOpenHelper {
  public CustomSQLiteOpenHelper(Context context) {
    super(context, DB_NAME, null, DB_VERSION);
  }
  @Override
  public void onCreate(SQLiteDatabase db) {
String newTableQueryString = "create table "
+ TABLE_NAME + " ("
+ TABLE_ROW_ID 
+ " integer primary key autoincrement not null,"
+ TABLE_ROW_NAME
+ " text not null," 
+ TABLE_ROW_PHONENUM 
+ " text not null,"
+ TABLE_ROW_EMAIL
+ " text not null,"
+ TABLE_ROW_PHOTOID 
+ " BLOB" + ");";
    db.execSQL(newTableQueryString);
  }

  @Override
  public void onUpgrade(SQLiteDatabase db, int oldVersion, 
int newVersion) {

    String DROP_TABLE = "DROP TABLE IF EXISTS " + 
TABLE_NAME;
    db.execSQL(DROP_TABLE);
    onCreate(db);
  }
}
```

`CustomSQLiteOpenHelper`扩展了`SQLiteOpenHelper`，并为我们提供了关键方法`onCreate()`和`onUpgrade()`。我们已将此类定义为`DatabaseManager`类的内部类。这使我们能够从一个地方管理所有与数据库相关的功能，即 CRUD（创建、读取、更新和删除）。

在我们的`CustomSQLiteOpenHelper`构造函数中，负责创建我们类的实例，我们将传递一个上下文，然后将其传递给超级构造函数，参数如下：

+   `Context context`：这是我们传递给构造函数的上下文

+   `String name`：这是我们数据库的名称

+   `CursorFactory factory`：这是游标工厂对象，可以传递为`null`

+   `int version`：这是数据库的版本

下一个重要的方法是`onCreate()`。我们将构建我们的 SQLite 查询字符串，用于创建我们的数据库表：

```kt
"create table " + TABLE_NAME + " ("
+ TABLE_ROW_ID
+ " integer primary key autoincrement not null,"
….....
+ TABLE_ROW_PHOTOID + " BLOB" + ");";
```

前面的语句基于以下语法图：

![构建创建查询](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951OS_02_02.jpg)

在这里，关键字`create table`用于创建表。接着是表名、列的声明和它们的数据类型。准备好我们的 SQL 语句后，我们将使用 SQLite 数据库的`execSQL()`方法来执行它。如果我们之前构建的查询语句有问题，我们将遇到异常`android.database.sqlite.SQLiteException`。默认情况下，数据库形成在应用程序分配的内部存储空间中。该文件夹可以在`/data/data/<yourpackage>/databases/`找到。

我们可以在模拟器或已获取 root 权限的手机上运行这段代码时轻松验证我们的数据库是否已创建。在 Eclipse 中，转到 DDMS 透视图，然后转到文件管理器。如果我们有足够的权限，即已获取 root 权限的设备，我们可以轻松导航到给定的文件夹。我们还可以借助文件资源管理器拉取我们的数据库，并借助独立的 SQLite 管理工具查看我们的数据库，并对其执行 CRUD 操作。是什么使得 Android 应用程序的数据库可以通过其他工具读取？还记得我们在上一章中讨论过 SQLite 特性中的跨平台吗？在下面的截图中，注意表名、用于构建它的 SQL 语句以及列名及其数据类型：

![构建创建查询](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951_02_03.jpg)

### 注意

SQLite 管理工具可以在 Chrome 或 Firefox 浏览器中下载。以下是 Firefox 扩展的链接：[`goo.gl/NLu8JT`](http://goo.gl/NLu8JT)。

另一个方便的方法是使用`adb pull`命令来拉取我们的数据库或任何其他文件：

```kt
adb pull /data/data/your package name/databases  /file location

```

另一个有趣的要点是`TABLE_ROW_PHOTOID`的数据类型是`BLOB`。BLOB 代表二进制大对象。它与其他数据类型（如文本和整数）不同，因为它可以存储二进制数据。二进制数据可以是图像、音频或任何其他类型的多媒体对象。

不建议在数据库中存储大型图像；我们可以存储文件名或位置，但存储图像有点过度。想象一种情况，我们存储联系人图像。为了放大这种情况，让它不是几百个联系人，而是几千个联系人。数据库的大小将变得很大，访问时间也会增加。我们想通过存储联系人图像来演示 BLOB 的使用。

当数据库升级时，将调用`onUpgrade()`方法。通过更改数据库的版本号来升级数据库。在这里，实现取决于应用的需求。在某些情况下，可能需要删除整个表并创建一个新表，在某些应用程序中，可能只需要进行轻微修改。如何从一个版本迁移到另一个版本在第四章中有所涵盖，*小心操作*。

## 构建插入查询

要在数据库表中插入新的数据行，我们需要使用`insert()`方法或者制作一个插入查询语句并使用`execute()`方法：

```kt
public void addRow(ContactModel contactObj) {
  ContentValues values = prepareData(contactObj);
  try {
    db.insert(TABLE_NAME, null, values);
  } catch (Exception e) {
    Log.e("DB ERROR", e.toString()); 
    e.printStackTrace();
  }
}
```

如果我们的表名错误，SQLite 将给出一个日志`no such table`消息和异常`android.database.sqlite.SQLiteException`。`addRow()`方法用于在数据库行中插入联系人详细信息；请注意，该方法的参数是`ContactModel`的对象。我们创建了一个额外的方法`prepareData()`，从`ContactModel`对象的 getter 方法构造一个`ContentValues`对象。

```kt
.......................
values.put(TABLE_ROW_NAME, contactObj.getName());
values.put(TABLE_ROW_PHONENUM, contactObj.getContactNo());
....................
```

在准备好`ContentValues`对象之后，我们将使用`SQLiteDatabase`类的`insert()`方法：

```kt
public long insert (String table, String nullColumnHack, ContentValues values)
```

`insert()`方法的参数如下：

+   `table`：要将行插入的数据库表。

+   `values`：这个键值映射包含表行的初始列值。列名充当键。值作为列值。

+   `nullColumnHack`：这与其名称一样有趣。以下是来自 Android 文档网站的一句引用：

> “可选；可能为空。SQL 不允许插入完全空的行，而不命名至少一个列名。如果您提供的值为空，那么不知道任何列名，也无法插入空行。如果未设置为 null，则 nullColumnHack 参数提供可为空列名的名称，以明确在值为空的情况下插入 NULL。”

简而言之，在我们试图传递一个空的`ContentValues`以进行插入的情况下，SQLite 需要一些安全的列来分配`NULL`。

或者，我们可以准备 SQL 语句并执行它，如下所示：

```kt
public void addRowAlternative(ContactModel contactObj) {

  String insertStatment = "INSERT INTO " + TABLE_NAME 
      + " ("
      + TABLE_ROW_NAME + ","
      + TABLE_ROW_PHONENUM + ","
      + TABLE_ROW_EMAIL + ","
      + TABLE_ROW_PHOTOID
      + ") "
      + " VALUES "
      + "(?,?,?,?)";

  SQLiteStatement s = db.compileStatement(insertStatment);
  s.bindString(1, contactObj.getName());
  s.bindString(2, contactObj.getContactNo());
  s.bindString(3, contactObj.getEmail());
if (contactObj.getPhoto() != null)
   {s.bindBlob(4, contactObj.getPhoto());}
  s.execute();
}
```

我们将涵盖这里提到的许多方法的替代方案。其目的是使您熟悉构建和执行查询的其他可能方式。替代部分的解释留作练习给您。`getRowAsObject()`方法将以`ContactModel`对象的形式返回从数据库中获取的行，如下面的代码所示。它将需要`rowID`作为参数，以唯一标识我们想要访问的表中的哪一行：

```kt
public ContactModel getRowAsObject(int rowID) { 
  ContactModel rowContactObj = new ContactModel();
  Cursor cursor;
  try {
    cursor = db.query(TABLE_NAME, new String[] {
TABLE_ROW_ID, TABLE_ROW_NAME, TABLE_ROW_PHONENUM, TABLE_ROW_EMAIL, TABLE_ROW_PHOTOID },
    TABLE_ROW_ID + "=" + rowID, null,
    null, null, null, null);
    cursor.moveToFirst();
    if (!cursor.isAfterLast()) {
      prepareSendObject(rowContactObj, cursor);    }
  } catch (SQLException e) {
      Log.e("DB ERROR", e.toString());
    e.printStackTrace();
  }
  return rowContactObj;
}
```

这个方法将以`ContactModel`对象的形式返回从数据库中获取的行。我们正在使用`SQLiteDatabase()`查询方法从我们的联系人表中根据提供的`rowID`参数获取行。该方法返回结果集上的游标：

```kt
public Cursor query (String table, String[] columns, String selection, String[] selectionArgs, String groupBy, String having, String orderBy, String limit)
```

以下是上述代码的参数：

+   `table`：这表示将对其运行查询的数据库表。

+   `columns`：这是返回的列的列表；如果我们传递`null`，它将返回所有列。

+   `selection`：这是我们定义要返回哪些行的地方，并作为 SQL `WHERE` 子句。传递`null`将返回所有行。

+   `selectionArgs`：我们可以为这个参数传递`null`，或者我们可以在选择中包含问号，这些问号将被`selectionArgs`中的值替换。

+   `groupBy`：这是一个作为 SQL `GROUP BY` 子句的过滤器，声明如何对行进行分组。传递`null`将导致行不被分组。

+   `Having`：这是一个过滤器，告诉哪些行组应该成为游标的一部分，作为 SQL `HAVING` 子句。传递`null`将导致所有行组被包括。

+   `OrderBy`：这告诉查询如何对行进行排序，作为 SQL `ORDER BY`子句。传递`null`将使用默认排序顺序。

+   `limit`：这将限制查询返回的行数，作为`LIMIT`子句。传递`null`表示没有`LIMIT`子句。

这里另一个重要的概念是移动游标以访问数据。注意以下方法：`cursor.moveToFirst()`、`cursor.isAfterLast()`和`cursor.moveToNext()`。

当我们尝试检索数据构建 SQL 查询语句时，数据库将首先创建游标对象的对象并返回其引用。返回的引用指针指向第 0 个位置，也称为游标的“第一个位置”之前。当我们想要检索数据时，我们必须首先移动到第一条记录；因此，使用`cursor.moveToFirst()`。谈到其他两种方法，`cursor.isAfterLast()`返回游标是否指向最后一行之后的位置，`cursor.moveToNext()`将游标移动到下一行。

### 提示

建议读者查看 Android 开发者网站上更多的游标方法：[`goo.gl/fR75t8`](http://goo.gl/fR75t8)。

或者，我们可以使用以下方法：

```kt
public ContactModel getRowAsObjectAlternative(int rowID) {

  ContactModel rowContactObj = new ContactModel();
  Cursor cursor;

  try {
    String queryStatement = "SELECT * FROM " 
       + TABLE_NAME  + " WHERE " + TABLE_ROW_ID + "=?";
    cursor = db.rawQuery(queryStatement,
      new String[]{String.valueOf(rowID)});
    cursor.moveToFirst();

    rowContactObj = new ContactModel();
    rowContactObj.setId(cursor.getInt(0));
    prepareSendObject(rowContactObj, cursor);

  } catch (SQLException e) {
    Log.e("DB ERROR", e.toString());
    e.printStackTrace();
  }

  return rowContactObj;
}
```

`update`语句基于以下语法图：

![构建插入查询](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951OS_02_04.jpg)

在我们转到`datamanager`类中的其他方法之前，让我们看一下在`prepareSendObject()`方法中从游标对象中获取数据：

```kt
rowObj.setContactNo(cursor.getString(cursor.getColumnIndexOrThrow(TABLE_ROW_PHONENUM)));
rowObj.setEmail(cursor.getString(cursor.getColumnIndexOrThrow(TABLE_ROW_EMAIL)));
```

这里`cursor.getstring()`以列索引作为参数，并返回请求列的值，而`cursor.getColumnIndexOrThrow()`以列名作为参数，并返回给定列名的基于零的索引。除了这种链接方法，我们可以直接使用`cursor.getstring()`。如果我们知道要从中提取数据的所需列的列号，我们可以使用以下表示法：

```kt
cursor.getstring(2);
```

## 构建删除查询

从我们的数据库表中删除特定的数据行，我们需要提供主键来唯一标识要删除的数据集：

```kt
public void deleteRow(int rowID) {
  try {
    db.delete(TABLE_NAME, TABLE_ROW_ID 
    + "=" + rowID, null);
  } catch (Exception e) {
    Log.e("DB ERROR", e.toString());
    e.printStackTrace();
  }
}
```

此方法使用 SQLiteDatabase 的`delete()`方法来删除表中给定 ID 的行：

```kt
public int delete (String table, String whereClause, String[] whereArgs)
```

以下是上述代码片段的参数：

+   `table`：这是要针对其运行查询的数据库表。

+   `whereClause`：这是在删除行时要应用的子句；在此子句中传递`null`将删除所有行

+   `whereArgs`：我们可以在`where`子句中包含问号，这些问号将被绑定为字符串的值

或者，我们可以使用以下方法：

```kt
public void deleteRowAlternative(int rowId) {

  String deleteStatement = "DELETE FROM " 
    + TABLE_NAME + " WHERE " 
    + TABLE_ROW_ID + "=?";
  SQLiteStatement s = db.compileStatement(deleteStatement);
  s.bindLong(1, rowId);
  s.executeUpdateDelete();
}
```

`delete`语句基于以下语法图：

![构建删除查询](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951OS_02_05.jpg)

## 构建更新查询

要更新现有值，我们需要使用`update()`方法和所需的参数：

```kt
public void updateRow(int rowId, ContactModel contactObj) {

  ContentValues values = prepareData(contactObj);

  String whereClause = TABLE_ROW_ID + "=?";
  String whereArgs[] = new String[] {String.valueOf(rowId)};

  db.update(TABLE_NAME, values, whereClause, whereArgs);

}
```

通常情况下，我们需要主键，即`rowId`参数，来标识要修改的行。使用 SQLiteDatabase 的`update()`方法来修改数据库表中零行或多行的现有数据：

```kt
public int update (String table, ContentValues values, String whereClause, String[] whereArgs) 
```

以下是上述代码片段的参数：

+   `table`：这是要更新的合格数据库表名称。

+   `values`：这是从列名称到新列值的映射。

+   `whereClause`：这是在更新值/行时要应用的可选`WHERE`子句。如果`UPDATE`语句没有`WHERE`子句，则将修改表中的所有行。

+   `whereArgs`：我们可以在`where`子句中包含问号，这些问号将被绑定为字符串的值替换。

或者，您可以使用以下代码：

```kt
public void updateRowAlternative(int rowId, ContactModel contactObj) {
  String updateStatement = "UPDATE " + TABLE_NAME + " SET "
      + TABLE_ROW_NAME     + "=?,"
      + TABLE_ROW_PHONENUM + "=?,"
      + TABLE_ROW_EMAIL    + "=?,"
      + TABLE_ROW_PHOTOID  + "=?"
      + " WHERE " + TABLE_ROW_ID + "=?";

  SQLiteStatement s = db.compileStatement(updateStatement);
  s.bindString(1, contactObj.getName());
  s.bindString(2, contactObj.getContactNo());
  s.bindString(3, contactObj.getEmail());
  if (contactObj.getPhoto() != null)
   {s.bindBlob(4, contactObj.getPhoto());}
  s.bindLong(5, rowId);

  s.executeUpdateDelete();
}
```

`update`语句基于以下语法图：

![构建更新查询](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951OS_02_06.jpg)

# 连接 UI 和数据库

既然我们已经在数据库中设置了钩子，让我们将我们的 UI 与数据连接起来：

1.  第一步是从用户那里获取数据。我们可以通过内容提供程序使用 Android 联系人应用程序中的现有联系人数据。

我们将在下一章中介绍这种方法。现在，我们将要求用户添加一个新联系人，我们将把它插入到数据库中：

![连接 UI 和数据库](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951_02_07.jpg)

1.  我们正在使用标准的 Android UI 小部件，如`EditText`、`TextView`和`Buttons`来收集用户提供的数据：

```kt
private void prepareSendData() {
  if (TextUtils.isEmpty(contactName.getText().toString())
      || TextUtils.isEmpty(
      contactPhone.getText().toString())) {

  .............

   } else {
    ContactModel contact = new ContactModel();
    contact.setName(contactName.getText().toString());
    ............

    DatabaseManager dm = new DatabaseManager(this);
    if(reqType == ContactsMainActivity
.CONTACT_UPDATE_REQ_CODE) {
      dm.updateRowAlternative(rowId, contact);
    } else {
      dm.addRowAlternative(contact);
    }

    setResult(RESULT_OK);
    finish();
  }
}
```

`prepareSendData()`是负责将数据打包到我们的对象模型中，然后将其插入到我们的数据库中的方法。请注意，我们使用`TextUtils.isEmpty()`而不是对`contactName`进行空值检查和长度检查，这是一个非常方便的方法。如果字符串为 null 或长度为零，则返回`true`。

1.  我们从用户填写表单接收的数据准备我们的`ContactModel`对象。我们创建我们的`DatabaseManager`类的一个实例，并访问我们的`addRow()`方法，将我们的联系对象传递给数据库中插入，正如我们之前讨论的那样。

另一个重要的方法是`getBlob()`，它用于以 BLOB 格式获取图像数据：

```kt
private byte[] getBlob() {

  ByteArrayOutputStream blob = new ByteArrayOutputStream();
  imageBitmap.compress(Bitmap.CompressFormat.JPEG, 100, blob);
  byte[] byteArray = blob.toByteArray();

  return byteArray;
}
```

1.  我们创建一个新的`ByteArrayOutputStream`对象`blob`。位图的`compress()`方法将用于将位图的压缩版本写入我们的`outputstream`对象：

```kt
public boolean compress (Bitmap.CompressFormat format, int quality, OutputStream stream)
```

以下是上述代码的参数：

+   `format`：这是压缩图像的格式，在我们的情况下是 JPEG。

+   `quality`：这是对压缩器的提示，范围从`0`到`100`。值`0`表示压缩到较小的尺寸和低质量，而`100`是最高质量。

+   `stream`：这是用于写入压缩数据的输出流。

1.  然后，我们创建我们的`byte[]`对象，它将从`ByteArrayOutputStream toByteArray()`方法构造。

### 注意

您会注意到我们并没有涵盖所有的方法；只有与数据操作相关的方法以及可能引起混淆的一些方法或调用。还有一些用于调用相机或画廊以选择要用作联系人图像的照片的方法。建议您探索随书提供的代码中的方法。

让我们继续到演示部分，在那里我们使用自定义 listview 以一种可呈现和可读的方式显示我们的联系人信息。我们将跳过与演示相关的大部分代码，集中在我们获取和提供数据给我们的 listview 的部分。我们还将实现上下文菜单，以便为用户提供删除特定联系人的功能。我们将涉及数据库管理器方法，如`getAllData()`来获取所有添加的联系人。我们将使用`deleteRow()`来从我们的联系人数据库中删除任何不需要的联系人。最终结果将类似于以下截图：

![连接 UI 和数据库](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951_02_08.jpg)

1.  为了创建一个类似于前面截图中显示的自定义 listview，我们创建`CustomListAdapter`扩展`BaseAdapter`并使用自定义布局来设置 listview 行。请注意，在以下构造函数中，我们已经初始化了一个新的数组列表，并将使用我们的数据库管理器通过使用`getAllData()`方法来获取所有数据库条目的值：

```kt
public CustomListAdapter(Context context) {

   contactModelList = new ArrayList<ContactModel>();
   _context = context;
   inflater = (LayoutInflater)context.getSystemService( 
Context.LAYOUT_INFLATER_SERVICE);
      dm = new DatabaseManager(_context);
   contactModelList = dm.getAllData();
}
```

另一个非常重要的方法是`getView()`方法。这是我们在视图中填充自定义布局的地方：

```kt
convertView = inflater.inflate(R.layout.contact_list_row, null);
```

我们将使用视图持有者模式来提高 listview 的滚动流畅性：

```kt
vHolder = (ViewHolder) convertView.getTag();
```

1.  最后，将数据设置到相应的视图中：

```kt
vHolder.contact_email.setText(contactObj.getEmail());
```

### 注意

在视图持有者中持有视图对象可以通过减少对`findViewById()`的调用来提高性能。您可以在[`developer.android.com/training/improving-layouts/smooth-scrolling.html`](http://developer.android.com/training/improving-layouts/smooth-scrolling.html)上阅读更多关于此的信息以及如何使 listview 滚动流畅。

1.  我们还将实现一种删除 listview 条目的方法。我们将使用上下文菜单来实现这一目的。我们将首先在应用程序结构的`res`文件夹下的`menu`文件夹中创建一个菜单项：

```kt
<?xml version="1.0" encoding="utf-8"?>
<menu  >

    <item
        android:id="@+id/delete_item"
        android:title="Delete"/>
<item
        android:id="@+id/update_item"
     android:title="Update"/>
</menu>
```

1.  现在，在我们将显示 listview 的主要活动中，我们将使用以下调用来注册我们的 listview 到上下文菜单。为了启动上下文菜单，我们需要在 listview 项上执行长按操作：

```kt
registerForContextMenu(listReminder) 
```

1.  还有一些方法我们需要实现以实现删除功能：

```kt
@Override
  public void onCreateContextMenu(ContextMenu menu, View v,
      ContextMenuInfo menuInfo) {
    super.onCreateContextMenu(menu, v, menuInfo);
    MenuInflater m = getMenuInflater();
    m.inflate(R.menu.del_menu, menu);
  }
```

这种方法用于用我们之前在 XML 中定义的菜单填充上下文菜单。`MenuInfater`类从菜单 XML 文件生成菜单对象。菜单膨胀在很大程度上依赖于在构建时对 XML 文件的预处理；这是为了提高性能而做的。

1.  现在，我们将实现一种捕获上下文菜单点击的方法：

```kt
  @Override
  public boolean onContextItemSelected(MenuItem item) {
..............
    case R.id.delete_item:

      cAdapter.delRow(info.position);
      cAdapter.notifyDataSetChanged();
      return true;
    case R.id.update_item:

      Intent intent = new Intent( 
ContactsMainActivity.this, AddNewContactActivity.class);
      ......................
  }
```

1.  在这里，我们将找到点击的 listview 项的位置 ID，并调用 CustomListAdapter 的`delRow（）`方法，最后，我们将通知适配器数据集已更改：

```kt
public void delRow(int delPosition) {
                  dm.deleteRowAlternative(contactModelList.get(delPosition).getId());
       contactModelList.remove(delPosition);
```

`delRow（）`方法负责将我们数据库的`deleteRowAlternative（）`方法连接到我们上下文菜单的`delete（）`方法。在这里，我们获取设置在特定 listview 项上的对象的 ID，并将其传递给`databaseManager`的`deleteRowAlternative（）`方法，以从数据库中删除数据。在从数据库中删除数据后，我们将指示我们的 listview 从我们的联系人列表中删除相应的条目。

在`onContextItemSelected（）`方法中，我们还可以看到`update_item`，以防用户点击了`update`按钮。我们将启动添加新联系人的活动，并在用户想要编辑某些字段时添加我们已经拥有的数据。关键是要知道调用是从哪里发起的。是要添加新条目还是更新现有条目？我们借助以下代码告诉活动，此操作用于更新而不是添加新条目：

```kt
intent.putExtra(REQ_TYPE, CONTACT_UPDATE_REQ_CODE);
```

# 摘要

在本章中，我们涵盖了构建基于数据库的应用程序的步骤，从头开始，然后从模式到对象模型，然后从对象模型到构建实际数据库。我们经历了构建数据库管理器的过程，最终实现了 UI 数据库连接，实现了一个完全功能的应用程序。涵盖的主题包括模型类的构建块，数据库模式到数据库处理程序和 CRUD 方法。我们还涵盖了将数据库连接到 Android 视图的重要概念，并在适当的位置设置钩子以获取用户数据，将数据添加到数据库，并在从数据库中获取数据后显示相关信息。

在下一章中，我们将专注于在这里所做的基础上构建。我们将探索`ContentProviders`。我们还将学习如何从`ContentProviders`获取数据，如何制作我们自己的内容提供程序，以及在构建它们时涉及的最佳实践等等。


# 第三章：分享就是关怀

|   | *"数据真的驱动着我们所做的一切。"* |   |
| --- | --- | --- |
|   | --*– Jeff Weiner, LinkedIn* |

在上一章中，我们开始编写我们自己的联系人管理器。我们遇到了数据库中心应用程序的各种构建模块；我们涵盖了数据库处理程序和构建查询，以便从我们的数据库中获取有意义的数据。我们还探讨了如何在我们的 UI 和数据库之间建立连接，并以一种可消费的方式呈现给最终用户。

在这一章中，我们将学习如何通过内容提供程序访问其他应用程序的数据。我们还将学习如何构建自己的内容提供程序，以便与其他应用程序共享我们的数据。我们将研究 Android 的提供者，如**contactprovider**。最后，我们将构建一个测试应用程序来使用我们新构建的内容提供程序。

在本章中，我们将涵盖以下主题：

+   什么是内容提供程序？

+   创建内容提供程序

+   实现核心方法

+   使用内容提供程序

# 什么是内容提供程序？

内容提供程序是 Android 应用程序的第四个组件。它用于管理对结构化数据集的访问。内容提供程序封装数据，并提供抽象和定义数据安全性的机制。然而，内容提供程序主要用于被其他应用程序使用，这些应用程序使用提供程序的客户端对象访问提供程序。提供程序和提供程序客户端一起为数据提供了一致的标准接口，还处理了进程间通信和安全数据访问。

内容提供程序允许一个应用程序与其他应用程序共享数据。按设计，由应用程序创建的 Android SQLite 数据库对应用程序是私有的；从安全的角度来看，这是很好的，但当你想要在不同的应用程序之间共享数据时会很麻烦。这就是内容提供程序发挥作用的地方；通过构建自己的内容提供程序，您可以轻松地共享数据。重要的是要注意，尽管我们的讨论将集中在数据库上，但内容提供程序并不局限于此。它也可以用来提供通常存储在文件中的文件数据，如照片、音频或视频：

![什么是内容提供程序？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951OS_03_01.jpg)

在上图中，注意应用程序 A 和 B 之间交换数据的交互方式。在这里，我们有一个**应用程序 A**，其活动需要访问**应用程序 B**的数据库。正如我们已经看到的，**应用程序 B**的数据库存储在内部存储器中，无法直接被**应用程序 A**访问。这就是**内容提供程序**出现的地方；它允许我们共享数据并修改对其他应用程序的访问。内容提供程序实现了查询、插入、更新和删除数据库中的数据的方法。**应用程序 A**现在请求内容提供程序代表它执行一些所需的操作。我们将探索这个问题的两面，但我们将首先使用**内容提供程序**从手机的联系人数据库中获取联系人，然后我们将构建我们自己的内容提供程序，供其他人从我们的数据库中获取数据。

## 使用现有内容提供程序

Android 列出了许多标准内容提供程序，我们可以使用。其中一些是`Browser`、`CalendarContract`、`CallLog`、`Contacts`、`ContactsContract`、`MediaStore`、`userDictionary`等。

在我们当前的联系人管理应用程序中，我们将添加一个新功能。在`AddNewContactActivity`类的 UI 中，我们将添加一个小按钮，以帮助系统的现有`ContentProvider`和`ContentResolver`提供程序从手机的联系人列表中获取联系人。我们将使用`ContactsContract`提供程序来实现这个目的。

### 什么是内容解析器？

应用程序上下文中的`ContentResolver`对象用于作为客户端与提供程序进行通信。`ContentResolver`对象与提供程序对象通信——提供程序对象是实现`ContentProvider`的类的实例。提供程序对象接收来自客户端的数据请求，执行请求的操作，并返回结果。

`ContentResolver`是我们应用程序中的一个单一的全局实例，它提供了对其他应用程序的内容提供程序的访问；我们不需要担心处理进程间通信。`ContentResolver`方法提供了持久存储的基本 CRUD（创建、检索、更新和删除）功能；它有调用提供程序对象中同名方法的方法，但不知道实现。随着我们在本章中的进展，我们将更详细地介绍`ContentResolver`。

![什么是内容解析器？](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951_03_02.jpg)

在前面的屏幕截图中，注意右侧的新图标，可以直接从手机联系人中添加联系人；我们修改了现有的 XML 以添加这个图标。相应的类`AddNewContactActivity`也将被修改：

```kt
public void pickContact() {
   try {
       Intent cIntent = new Intent(Intent.ACTION_PICK,
            ContactsContract.Contacts.CONTENT_URI);
      startActivityForResult(cIntent, PICK_CONTACT);
    } catch (Exception e) {
      e.printStackTrace();
      Log.i(TAG, "Exception while picking contact");
    }
   }
```

我们添加了一个新的方法`pickContact()`来准备一个意图以选择联系人。`Intent.ACTION_PICK`允许我们从数据源中选择一个项目；此外，我们只需要知道提供程序的**统一资源标识符**（**URI**），在我们的情况下是`ContactsContract.Contacts.CONTENT_URI`。这个功能也由消息、画廊和联系人提供。如果您查看第二章的代码，*连接点*，您会发现我们已经使用了相同的代码从画廊中选择图像。联系人屏幕将弹出，允许我们浏览或搜索我们需要迁移到我们的新应用程序的联系人。注意`onActivityResult`，也就是说，我们的下一站我们将修改这个方法来处理我们对联系人的相应请求。让我们看看我们需要添加的代码，以从 Android 的联系人提供程序中选择联系人：

```kt
{
.
.
.

else if (requestCode == PICK_CONTACT) {
      if (resultCode == Activity.RESULT_OK)

       {
          Uri contactData = data.getData();
          Cursor c = getContentResolver().query(contactData, null, null, null, null);
         if (c.moveToFirst()) {
             String id = c
                   .getString(c
                         .getColumnIndexOrThrow(ContactsContract.Contacts._ID));

             String hasPhone = c
                   .getString(c
                         .getColumnIndex(ContactsContract.Contacts.HAS_PHONE_NUMBER));

            if (hasPhone.equalsIgnoreCase("1")) {
                Cursor phones = getContentResolver()
                      .query(ContactsContract.CommonDataKinds.Phone.CONTENT_URI,
                           null,
                           ContactsContract.CommonDataKinds.Phone.CONTACT_ID
                                  + " = " + id, null, null);
               phones.moveToFirst();
               contactPhone.setText(phones.getString(phones
                      .getColumnIndex("data1")));

               contactName
                      .setText(phones.getString(phones
                            .getColumnIndex(ContactsContract.Contacts.DISPLAY_NAME)));

 }
…..
```

### 提示

为了为您的应用程序增添一些特色，可以从 Android 开发者网站[`goo.gl/4Msuct`](http://goo.gl/4Msuct)下载整套模板、源代码、操作栏图标包、颜色样本和 Roboto 字体系列。设计一个功能性应用程序是不完整的，如果没有遵循 Android 指南的一致 UI。

我们首先检查请求代码是否与我们的匹配。然后，我们交叉检查`resultcode`。我们通过在`Context`对象上调用`getcontentresolver`来获取`ContentResolver`对象；这是`android.content.Context`类的一个方法。由于我们在一个继承自`Context`的活动中，我们不需要显式地调用它。服务也是一样。现在我们将验证我们选择的联系人是否有电话号码。在验证必要的细节之后，我们提取我们需要的数据，比如联系人姓名和电话号码，并将它们设置在相关字段中。

# 创建内容提供程序

内容提供程序以两种方式提供数据访问：一种是以数据库的形式进行结构化数据，就像我们目前正在处理的例子一样，或者以文件数据的形式，也就是说，以图片、音频、视频等形式存储在应用程序的私有空间中。在我们开始深入研究如何创建内容提供程序之前，我们还应该回顾一下我们是否需要一个。如果我们想要向其他应用程序提供数据，允许用户从我们的应用程序复制数据到另一个应用程序，或者在我们的应用程序中使用搜索框架，那么答案就是肯定的。

就像其他 Android 组件（`Activity`、`Service`或`BroadcastReceiver`）一样，内容提供程序是通过扩展`ContentProvider`类来创建的。由于`ContentProvider`是一个抽象类，我们必须实现这六个抽象方法。这些方法如下：

| 方法 | 用法 |
| --- | --- |
| `void onCreate()` | 初始化提供程序 |
| `String getType(Uri)` | 返回内容提供程序中数据的 MIME 类型 |
| `int delete(Uri uri, String selection, String[] selectionArgs)` | 从内容提供程序中删除数据 |
| `Uri insert(Uri uri, ContentValues values)` | 将新数据插入内容提供程序 |
| `Cursor query(Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder)` | 返回数据给调用者 |
| `int update(Uri uri, ContentValues values, String selection, String[] selectionArgs)` | 更新内容提供程序中的现有数据 |

随着我们在本章中的进展和应用程序的构建，这些方法将在以后更详细地讨论。

## 理解内容 URI

`ContentProvider`的每个数据访问方法都有一个内容 URI 作为参数，允许它确定要访问的表、行或文件。它通常遵循以下结构：

```kt
content://authority/Path/Id
```

让我们分析`content://` URI 组件的分解。内容提供程序的方案始终是`content`。冒号和双斜杠(`://`)充当与权限部分的分隔符。然后，我们有`authority`部分。根据规则，每个内容提供程序的权限都必须是唯一的。Android 文档推荐使用的命名约定是内容提供程序子类的完全限定类名。通常，它是一个包名称加上我们发布的每个内容提供程序的限定符。

剩下的部分是可选的，也称为**path**，用于区分内容提供程序可以提供的不同类型的数据。一个很好的例子是`MediaStore`提供程序，它需要区分音频、视频和图像文件。

另一个可选部分是`id`，它指向特定记录；根据`id`是否存在，URI 分别成为基于 ID 或基于目录。另一种理解方式是，基于 ID 的 URI 使我们能够在行级别单独与数据交互，而基于目录的 URI 使我们能够与数据库的多行交互。

例如，考虑`content://com.personalcontactmanager.provider/contacts`；随着我们继续本章的进展，我们很快就会遇到这个。

### 注意

顺便说一句，应用程序的包名称应始终是唯一的；这是因为 Play 商店上的所有应用程序都是通过其包名称进行识别的。Play 商店上的应用程序的所有更新都需要具有相同的包名称，并且必须使用最初使用的相同密钥库进行签名。例如，以下是 Gmail 应用程序的 Play 商店链接；请注意，在 URL 的末尾，我们将找到应用程序的包名称：

[play.google.com/store/apps/details?id=com.google.android.gm](http://play.google.com/store/apps/details?id=com.google.android.gm)

## 声明我们的合同类

声明合同是构建内容提供程序的非常重要的部分。这个类，正如其名称所示，将充当我们的内容提供程序和将要访问我们的内容提供程序的应用程序之间的合同。它是一个`public final`类，其中包含 URI、列名和其他元数据的常量定义。它也可以包含 Javadoc，但最大的优势是使用它的开发人员不需要担心表的名称、列和常量的名称，从而减少了容易出错的代码。

合同类为我们提供了必要的抽象；我们可以根据需要更改底层操作，也可以更改影响其他依赖应用程序的相应数据操作。需要注意的一点是，我们在未来更改合同时需要小心；如果我们不小心，可能会破坏使用我们合同类的其他应用程序。

我们的合同类看起来像下面这样：

```kt
public final class PersonalContactContract {

   /**
    * The authority of the PersonalContactProvider
    */
   public static final String AUTHORITY = "com.personalcontactmanager.provider";

   public static final String BASE_PATH = "contacts";

   /**
    * The Uri for the top-level PersonalContactProvider
    * authority
    */
   public static final Uri CONTENT_URI = Uri.parse("content://" + AUTHORITY 
         + "/" + BASE_PATH);

   /**
    * The mime type of a directory of items.
    */
   public static final String CONTENT_TYPE =                  
ContentResolver.CURSOR_DIR_BASE_TYPE + 
                  "/vnd.com.personalcontactmanager.provider.table";
   /**
    * The mime type of a single item.
    */
   public static final String CONTENT_ITEM_TYPE = 
ContentResolver.CURSOR_ITEM_BASE_TYPE + 
                 "/vnd.com.personalcontactmanager.provider.table_item";

   /**
    * A projection of all columns 
    * in the items table.
    */
   public static final String[] PROJECTION_ALL = { "_id", 
      "contact_name", "contact_number", 
      "contact_email", "photo_id" };

   /**
    * The default sort order for 
    * queries containing NAME fields.
    */
   //public static final String SORT_ORDER_DEFAULT = NAME + " ASC";

   public static final class Columns {
      public static String TABLE_ROW_ID = "_id";
      public static String TABLE_ROW_NAME  = "contact_name";
      public static String TABLE_ROW_PHONENUM = "contact_number";
      public static String TABLE_ROW_EMAIL = "contact_email";
      public static String TABLE_ROW_PHOTOID = "photo_id";
   }
}
```

`AUTHORITY`是在 Android 系统中注册的许多其他提供程序中标识提供程序的符号名称。`BASE_PATH`是表的路径。`CONTENT_URI`是提供程序封装的表的 URI。`CONTENT_TYPE`是包含零个或多个项目的游标的内容 URI 的 Android 平台的基本 MIME 类型。`CONTENT_ITEM_TYPE`是包含单个项目的游标的内容 URI 的 Android 平台的基本 MIME 类型。`PROJECTION_ALL`和`Columns`包含表的列 ID。

没有这些信息，其他开发人员将无法访问您的提供程序，即使它是开放访问的。

### 注意

提供程序内部可能有许多表，每个表都应该有一个唯一的路径；路径不是真正的物理路径，而是一个标识符。

## 创建 UriMatcher 定义

`UriMatcher`是一个实用类，它帮助匹配内容提供程序中的 URI。`addURI()`方法接受提供程序应该识别的内容 URI 模式。我们添加一个要匹配的 URI，以及在匹配此 URI 时返回的代码：

```kt
addURI(String authority, String path, int code)
```

我们将`authority`、`path`模式和整数值传递给`UriMatcher`的`addURI()`方法；当我们尝试匹配模式时，它返回我们定义的常量作为`int`值。

我们的`UriMatcher`看起来像下面这样：

```kt
private static final int CONTACTS_TABLE = 1;
private static final int CONTACTS_TABLE_ITEM = 2;

private static final UriMatcher mmURIMatcher = new UriMatcher(UriMatcher.NO_MATCH);
   static {
      mmURIMatcher.addURI(PersonalContactContract.AUTHORITY, 
            PersonalContactContract.BASE_PATH, CONTACTS_TABLE);
      mmURIMatcher.addURI(PersonalContactContract.AUTHORITY, 
            PersonalContactContract.BASE_PATH+  "/#",  
                       CONTACTS_TABLE_ITEM);
   }
```

请注意，它还支持使用通配符；我们在前面的代码片段中使用了井号（`#`），我们也可以使用通配符，比如`*`。在我们的情况下，使用井号，`"content://com.personalcontactmanager.provider/contacts/2"`这个表达式匹配，但使用`* "content://com.personalcontactmanager.provider/contacts`就不匹配了。

# 实现核心方法

为了构建我们的内容提供程序，下一步将是准备我们的核心数据库访问和数据修改方法，也就是 CRUD 方法。这是我们希望根据接收到的插入、查询或删除调用与数据交互的核心逻辑所在。我们还将实现 Android 架构的生命周期方法，比如`onCreate()`。

## 通过 onCreate()方法初始化提供程序

我们在`onCreate()`中创建我们的数据库管理器类的对象。`oncreate()`中应该有最少的操作，因为它在主 UI 线程上运行，可能会导致某些用户的延迟。最好避免在`oncreate()`中进行长时间运行的任务，因为这会增加提供程序的启动时间。甚至建议将数据库创建和数据加载推迟到我们的提供程序实际收到对数据的请求时，也就是将持续时间长的操作移到 CRUD 方法中：

```kt
@Override
Public Boolean onCreate() {
   dbm = new DatabaseManager(getContext());
   return false;
}   
```

## 通过 query()方法查询记录

`query()`方法将返回结果集上的游标。将 URI 传递给我们的`UriMatcher`，以查看它是否与我们之前定义的任何模式匹配。在我们的 switch case 语句中，如果是与表项相关的情况，我们检查`selection`语句是否为空；如果是，我们将选择语句构建到`lastpathsegment`，否则我们将选择附加到`lastpathsegment`语句。我们使用`DatabaseManager`对象在数据库上运行查询，并得到一个游标作为结果。`query()`方法预期会抛出`IllegalArgumentException`来通知未知的 URI；在查询过程中遇到内部错误时，抛出`nullPointerException`也是一个良好的做法：

```kt
@Override
public Cursor query(Uri uri, String[] projection, String selection,
      String[] selectionArgs, String sortOrder) {

   int uriType = mmURIMatcher.match(uri);
   switch(uriType) {

   case CONTACTS_TABLE:
      break;
   case CONTACTS_TABLE_ITEM:
      if (TextUtils.isEmpty(selection)) {
         selection = PersonalContactContract.Columns.TABLE_ROW_ID 
                  + "=" + uri.getLastPathSegment();
      } else {
         selection = PersonalContactContract.Columns.TABLE_ROW_ID 
                  + "=" + uri.getLastPathSegment() + 
               " and " + selection;
      }
      break;
   default:
      throw new IllegalArgumentException("Unknown URI: " + uri);
   }

   Cursor cr = dbm.getRowAsCursor(projection, selection, 
               selectionArgs, sortOrder);

   return cr;
}
```

### 注意

请记住，Android 系统必须能够跨进程边界通信异常。Android 可以为以下异常执行此操作，这些异常在处理查询错误时可能有用：

+   `IllegalArgumentException`：如果您的提供程序收到无效的内容 URI，您可以选择抛出此异常

+   `NullPointerException`：当对象为空且我们尝试访问其字段或方法时抛出

## 通过 insert()方法添加记录

正如其名称所示，`insert()`方法用于在我们的数据库中插入一个值。它返回插入行的 URI，并且在检查 URI 时，我们需要记住插入可以发生在表级别，因此方法中的操作在与表匹配的 URI 上进行处理。匹配后，我们使用标准的`DatabaseManager`对象将新值插入到数据库中。新行的内容 URI 是通过将新行的`_ID`值附加到表的内容 URI 构造的：

```kt
@Override
public Uri insert(Uri uri, ContentValues values) {

   int uriType = mmURIMatcher.match(uri);
   long id;

   switch(uriType) {
   case CONTACTS_TABLE:
      id = dbm.addRow(values);
      break;
   default:
      throw new IllegalArgumentException("Unknown URI: " + uri);
   }

   Uri ur = ContentUris.withAppendedId(uri, id);
   return ur;
}
```

## 通过 update()方法更新记录

`update()`方法更新适当表中的现有行，使用`ContentValues`参数中的值。首先，我们确定 URI，无论是基于目录还是基于 ID，然后我们构建选择语句，就像我们在`query()`方法中所做的那样。现在，我们将执行我们在第二章中构建此应用程序时定义的标准`DatabaseManager`的`updateRow()`方法，该方法返回受影响的行数。

`update()`方法返回更新的行数。根据选择条件，可以更新一行或多行：

```kt
@Override
public int update(Uri uri, ContentValues values, String selection,
      String[] selectionArgs) {
   int uriType = mmURIMatcher.match(uri);

   switch(uriType) {
   case CONTACTS_TABLE:
      break;
   case CONTACTS_TABLE_ITEM:
      if (TextUtils.isEmpty(selection)) {
         selection = PersonalContactContract.Columns.TABLE_ROW_ID
 + "=" + uri.getLastPathSegment();
      } else {
         selection = PersonalContactContract.Columns.TABLE_ROW_ID 
+ "=" + uri.getLastPathSegment() 
+ " and " + selection;
      }
      break;
   default:
      throw new IllegalArgumentException("Unknown URI: " + uri);
   }

   int count = dbm.updateRow(values, selection, selectionArgs);

   return count;
}
```

## 通过 delete()方法删除记录

`delete()`方法与`update()`方法非常相似，使用它的过程类似；在这里，调用是用来删除一行而不是更新它。`delete()`方法返回删除的行数。根据选择条件，可以删除一行或多行：

```kt
@Override
public int delete(Uri uri, String selection, String[] selectionArgs) {

   int uriType = mmURIMatcher.match(uri);

   switch(uriType) {
   case CONTACTS_TABLE:
      break;
   case CONTACTS_TABLE_ITEM:
      if (TextUtils.isEmpty(selection)) {
         selection = PersonalContactContract.Columns.TABLE_ROW_ID
 + "=" + uri.getLastPathSegment();
      } else {
         selection = PersonalContactContract.Columns.TABLE_ROW_ID 
 + "=" + uri.getLastPathSegment() 
 + " and " + selection;
      }
      break;
   default:
      throw new IllegalArgumentException("Unknown URI: " + uri);
   }

   int count = dbm.deleteRow(selection, selectionArgs);

   return count;
}
```

## 通过 getType()方法获取数据的返回类型

这个简单方法的签名接受一个 URI 并返回一个字符串值；每个内容提供者必须为其支持的 URI 返回内容类型。一个非常有趣的事实是，应用程序访问这些信息时不需要任何权限；如果我们的内容提供者需要权限，或者没有被导出，所有的应用程序仍然可以调用这个方法，而不管它们对检索 MIME 类型的访问权限如何。

所有这些 MIME 类型都应在合同类中声明：

```kt
@Override
public String getType(Uri uri) {

   int uriType = mmURIMatcher.match(uri);
   switch(uriType) {
   case CONTACTS_TABLE:
      return PersonalContactContract.CONTENT_TYPE;
   case CONTACTS_TABLE_ITEM:
      return PersonalContactContract.CONTENT_ITEM_TYPE;
   default:
      throw new IllegalArgumentException("Unknown URI: " + uri);   
   }

}
```

## 将提供者添加到清单中

另一个重要的步骤是将我们的内容提供者添加到清单中，就像我们对其他 Android 组件所做的那样。我们可以在这里注册多个提供者。这里的重要部分，除了`android:authorities`之外，还有`android:exported`；它定义了内容提供者是否可供其他应用程序使用。如果为`true`，则提供者可供其他应用程序使用；如果为`false`，则提供者不可供其他应用程序使用。如果应用程序具有与提供者相同的用户 ID（UID），它们将可以访问它：

```kt
<provider
   android:name="com.personalcontactmanager.provider.PersonalContactProvider"
   android:authorities="com.personalcontactmanager.provider"
   android:exported="true"
   android:grantUriPermissions="true" >
   </provider>
```

另一个重要的概念是**权限**。我们可以通过添加读取和写入权限来增加额外的安全性，其他应用程序必须在其清单 XML 文件中添加这些权限，并自动通知用户他们将要使用特定应用程序的内容提供者来读取、写入或两者兼而有之。我们可以通过以下方式添加权限：

```kt
android:readPermission="com.personalcontactmanager.provider.READ"
```

# 使用内容提供者

我们构建内容提供者的主要原因是允许其他应用程序访问我们数据库中的复杂数据存储并执行 CRUD 操作。现在我们将构建另一个应用程序来测试我们新构建的内容提供者。测试应用程序非常简单，只包括一个活动类和一个布局文件。它有标准按钮来执行操作。没有花哨的东西，只是用来测试我们刚刚实现的功能的工具。现在我们将深入研究`TestMainActivity`类并查看其实现：

```kt
public class TestMainActivity extends Activity {

public final String AUTHORITY = "com.personalcontactmanager.provider";
public final String BASE_PATH = "contacts";
private TextViewqueryT, insertT;

public class Columns {
   public final static String TABLE_ROW_ID = "_id";
   public final static String TABLE_ROW_NAME = "contact_name";
   public final static String TABLE_ROW_PHONENUM =

"contact_number";
   public final static String TABLE_ROW_EMAIL = "contact_email";
   public final static String TABLE_ROW_PHOTOID = "photo_id";
   }
```

要访问内容提供程序，我们需要诸如`AUTHORITY`和`BASE_PATH`的详细信息，以及数据库表的列名称；我们需要访问公共类`Columns`。为此目的。我们有更多的表，我们将看到更多这些类。通常，所有这些必要的信息将从内容提供程序的已发布合同类中获取。一些内容提供程序还需要在清单中实现读取或写入权限：

```kt
<uses-permissionandroid:name="AUTHORITY.permission.WRITE_TASKS"/>
```

在某些情况下，我们需要访问的内容提供程序可能会要求我们在清单中添加权限。当用户安装应用程序时，他们将在其权限列表中看到一个添加的权限：

```kt
@Override
protected void onCreate(Bundle savedInstanceState) {
   super.onCreate(savedInstanceState);
   setContentView(R.layout.activity_test_main);
   queryT = (TextView) findViewById(R.id.textQuery);
   insertT = (TextView) findViewById(R.id.textInsert);
   }
```

### 注意

要尝试其他应用程序的内容提供程序，请参阅[`goo.gl/NEX2hN`](http://goo.gl/NEX2hN)。

它列出了如何使用 Any.do 的内容提供程序-一个非常著名的任务应用程序。

我们将在活动的`onCreate()`中设置我们的布局并初始化我们需要的视图。要查询，我们首先需要准备与表匹配的 URI 对象。

现在内容解析器开始发挥作用；它充当我们准备的内容 URI 的解析器。在这种情况下，我们的`getContentResolver.query()`方法将获取所有列和行。现在，我们将游标移动到第一个位置，以便读取结果。出于测试目的，它被读取为一个字符串：

```kt
public void query(View v) {
  Uri contentUri = Uri.parse("content://" + AUTHORITY 
               + "/" + BASE_PATH);

  Cursor cr = getContentResolver().query(contentUri, null, 
            null, null, null);     

  if (cr != null) {
      if (cr.getCount() > 0) {
         cr.moveToFirst();
         String name = cr.getString(cr.getColumnIndexOrThrow( 
Columns.TABLE_ROW_NAME));
         queryT.setText(name);
      }
  }

  ....
  ....
}
```

现在，我们构建一个 URI 来读取特定行，而不是完整的表。我们已经提到，为了使 URI 基于 ID，我们需要将 ID 部分添加到我们现有的`contenturi`中。现在，我们构建我们的投影字符串数组，以作为我们`query()`方法中的参数传递：

```kt
public void query(View v) {

 ...
 ...

  Uri rowUri = contentUri = ContentUris.withAppendedId
            (contentUri, getFirstRowId());

  String[] projection = new String[] {
      Columns.TABLE_ROW_NAME, Columns.TABLE_ROW_PHONENUM,
      Columns.TABLE_ROW_EMAIL, Columns.TABLE_ROW_PHOTOID };

  cr = getContentResolver().query(contentUri, projection,
      null, null, null);

  if (cr != null) {
      if (cr.getCount() > 0) {
         cr.moveToFirst();
         String name = cr.getString(cr.getColumnIndexOrThrow(
                  Columns.TABLE_ROW_NAME));

         queryT.setText(name);

      }
  }

}   
```

`getFirstRowId()`方法获取表中第一行的 ID。这是因为第一行的 ID 并不总是`1`。当行被删除时，它会发生变化。如果具有行 ID`1`的表中的第一项被删除，那么具有行 ID`1`的第二项将成为第一项：

```kt
private int getFirstRowId() {

  int id = 1;
  Uri contentUri = Uri.parse("content://" + AUTHORITY + "/"
               + "contacts");
  Cursor cr = getContentResolver().query(contentUri, null,
            null, null, null);
  if (cr != null) {
      if (cr.getCount() > 0) {
         cr.moveToFirst();
         id = cr.getInt(cr.getColumnIndexOrThrow(
            Columns.TABLE_ROW_ID));
      }
  }
return id;

}
```

让我们更仔细地看一下`query()`方法：

```kt
public final Cursor query (Uri uri, String[] projection, String selection, String[] selectionArgs, String sortOrder)
```

在 API 级别 1 中，`query()`方法根据我们提供的参数返回结果集上的游标。以下是前面代码的参数：

+   `uri`：这是我们的情况下的`contentURI`，使用`content://`方案来检索内容。它可以基于 ID 或基于目录。

+   `projection`：这是要返回的列的列表，我们已经使用列名准备好了。传递`null`将返回所有列。

+   `selection`：格式化为 SQL `WHERE`子句，不包括`WHERE`本身，这充当一个过滤器，声明要返回哪些行。

+   `selectionArgs`：我们可以在`selection`中包含`?`参数标记。Android SQL 查询构建器将使用从`selectionArgs`绑定为字符串的值替换`?`参数标记，按照它们在`selection`中出现的顺序。

+   `sortOrder`：这告诉我们如何对行进行排序，格式化为 SQL `ORDER BY`子句。`null`值将使用默认排序顺序。

### 注意

根据官方文档，我们应该遵循一些指导方针以获得最佳性能：

+   提供明确的投影，以防止从存储中读取不会使用的数据。

+   在选择参数中使用问号参数标记，例如`phone=?`，而不是显式值，以便仅由这些值不同的查询将被识别为相同以进行缓存。

我们之前使用的相同过程用于检查`null`值和空游标，并最终从游标中提取所需的值。

现在，让我们看一下我们测试应用程序的`insert`方法。

我们首先构建我们的内容值对象和相关的键值对，例如，在相关的`Columns.TABLE_ROW_PHONENUM`字段中放入电话号码。请注意，因为诸如列名之类的细节以类的形式与我们共享，所以我们不需要担心实际的列名等细节。我们只需要通过`Columns`类的方式访问它。这确保我们只需要更新相关的值。如果将来内容提供程序发生某些更改并更改表名，其余功能和实现仍然保持不变。我们像之前在查询内容提供程序数据的情况下一样，构建我们所需的列名的投影字符串数组。

我们还构建我们的内容 URI；请注意，它与表匹配，而不是单独的行。`insert()`方法也返回一个 URI，不像`query()`方法返回结果集上的游标：

```kt
public void insert(View v) {

  String name = getRandomName();
  String number = getRandomNumber();

  ContentValues values = new ContentValues();
  values.put(Columns.TABLE_ROW_NAME, name);
  values.put(Columns.TABLE_ROW_PHONENUM, number);
  values.put(Columns.TABLE_ROW_EMAIL, name + "@gmail.com");
  values.put(Columns.TABLE_ROW_PHOTOID, "abc");

  String[] projection = new String[] {
      Columns.TABLE_ROW_NAME, Columns.TABLE_ROW_PHONENUM,
      Columns.TABLE_ROW_EMAIL, Columns.TABLE_ROW_PHOTOID };

  Uri contentUri = Uri.parse("content://" + AUTHORITY + "/"
            + BASE_PATH);

  Uri insertedRowUri = getContentResolver().insert(
            contentUri, values);

  //checking the added row
  Cursor cr = getContentResolver().query(insertedRowUri,
         projection, null, null, null);

  if (cr != null) {
      if (cr.getCount() > 0) {
           cr.moveToFirst();
           name = cr.getString(cr.getColumnIndexOrThrow(
               Columns.TABLE_ROW_NAME));
           insertT.setText(name);
      }
  }

}
```

`getRandomName()`和`getRandomNumber()`方法生成要插入表中的随机名称和数字：

```kt
private String getRandomName() {

      Random rand = new Random();
      String name = "" + (char) (122-rand.nextInt(26))
         + (char) (122-rand.nextInt(26))
         + (char) (122-rand.nextInt(26))
         + (char) (122-rand.nextInt(26))
         + (char) (122-rand.nextInt(26))
         + (char) (122-rand.nextInt(26))
         + (char) (122-rand.nextInt(26))
         + (char) (122-rand.nextInt(26)) ;

      return name;
}

public String getRandomNumber() {
  Random rand = new Random();
  String number = rand.nextInt(98989)*rand.nextInt(59595)+"";

  return number;
}
```

让我们更仔细地看看`insert()`方法：

```kt
public final Uri insert (Uri url, ContentValues values)
```

以下是上一行代码的参数：

+   `url`：要插入数据的表的 URL

+   `values`：以`ContentValues`对象的形式为新插入的行的值，键是字段的列名

请注意，在插入后，我们再次运行了`query()`方法，使用了`insert()`方法返回的 URI。我们运行这个查询是为了看到我们打算插入的值是否已经插入；这个查询将根据附加了 ID 的行的投影返回列。

到目前为止，我们已经涵盖了`query()`和`insert()`方法；现在，我们将涵盖`update()`方法。

我们在`insert()`方法中通过准备`ContentValues`对象来进行了进展。类似地，我们将准备一个对象，我们将在`ContentResolver`的`update()`方法中使用来更新现有行。在这种情况下，我们将构建我们的 URI 直到 ID，因为这个操作是基于 ID 的。更新由`rowUri`对象指向的行，它将返回更新的行数，这将与 URI 相同；在这种情况下，它是指向单个行的`rowUri`。另一种方法可能是使用指向表的`contentUri`和`selection`/`selectionArgs`的组合。在这种情况下，根据`selection`子句，更新的行可能多于一个：

```kt
public void update(View v) {

  String name = getRandomName();
  String number = getRandomNumber();

  ContentValues values = new ContentValues();
  values.put(Columns.TABLE_ROW_NAME, name);
  values.put(Columns.TABLE_ROW_PHONENUM, number);
  values.put(Columns.TABLE_ROW_EMAIL, name + "@gmail.com");
  values.put(Columns.TABLE_ROW_PHOTOID, " ");

  Uri contentUri = Uri.parse("content://" + AUTHORITY
                    + "/" + BASE_PATH);
  Uri rowUri = ContentUris.withAppendedId(
                    contentUri, getFirstRowId());
  int count = getContentResolver().update(rowUri, values, null, null);

}
```

让我们更仔细地看看`update()`方法：

```kt
public final int update (Uri uri, ContentValues values, String where, String[] selectionArgs)
```

以下是上一行代码的参数：

+   `uri`：这是我们希望修改的内容 URI

+   `values`：这类似于我们之前在其他方法中使用的值；传递`null`值将删除现有字段值

+   `where`：作为过滤器对行进行更新之前的 SQL `WHERE`子句

我们可以再次运行`query()`方法来查看更改是否反映出来；这个活动留给你作为练习。

最后一个方法是`delete()`，我们需要它来完成我们的 CRUD 方法。`delete()`方法的开始方式与其他方法类似；首先，准备我们的内容 URI 在目录级别，然后在 ID 级别构建它，也就是在单个行级别。之后，我们将其传递给`ContentResolver`的`delete()`方法。与`query()`和`insert()`方法返回整数值不同，`delete()`方法删除由我们基于 ID 的内容 URI 对象`rowUri`指向的行，并返回删除的行数。在我们的情况下，这将是`1`，因为我们的 URI 只指向一行。另一种方法可能是使用指向表的`contentUri`和`selection`/`selectionArgs`的组合。在这种情况下，根据`selection`子句，删除的行可能多于 1：

```kt
public void delete(View v) {

      Uri contentUri = Uri.parse("content://" + AUTHORITY
                              + "/" + BASE_PATH);
      Uri rowUri = contentUri = ContentUris.withAppendedId(
                              contentUri, getFirstRowId());
      int count = getContentResolver().delete(rowUri, null,
               null);
}
```

UI 和输出如下：

![使用内容提供程序](https://github.com/OpenDocCN/freelearn-android-zh/raw/master/docs/andr-sqlite-ess/img/2951_03_03.jpg)

### 注意

如果你想更深入地了解 Android 内容提供程序是如何在各个表之间管理各种写入和读取调用的（提示：它使用`CountDownLatch`），你可以查看 Coursera 上 Douglas C. Schmidt 博士的视频以获取更多信息。视频可以在[`class.coursera.org/posa-002/lecture/49`](https://class.coursera.org/posa-002/lecture/49)找到。

# 总结

在本章中，我们介绍了内容提供程序的基础知识。我们学习了如何访问系统提供的内容提供程序，甚至我们自己的内容提供程序版本。我们从创建一个基本的联系人管理器，逐渐发展成为 Android 生态系统中的一个完整的成员，通过实现`ContentProvider`来在其他应用程序之间共享数据。

在接下来的章节中，我们将介绍`Loaders`、`CursorAdapters`、巧妙的技巧和提示，以及一些开源库，以使我们在使用 SQLite 数据库时更轻松。
