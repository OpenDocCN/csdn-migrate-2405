# Java7 新特性秘籍（二）

> 原文：[`zh.annas-archive.org/md5/5FB42CDAFBC18FB5D8DD681ECE2B0206`](https://zh.annas-archive.org/md5/5FB42CDAFBC18FB5D8DD681ECE2B0206)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：获取文件和目录信息

在本章中，我们将涵盖以下内容：

+   确定文件内容类型

+   使用 getAttribute 方法逐个获取单个属性

+   获取文件属性的映射

+   获取文件和目录信息

+   确定操作系统对属性视图的支持

+   使用 BasicFileAttributeView 维护基本文件属性

+   使用 PosixFileAttributeView 维护 POSIX 文件属性

+   使用 DosFileAttributeView 维护 FAT 表属性

+   使用 FileOwnerAttributeView 维护文件所有权属性

+   使用 AclFileAttributeView 维护文件的 ACL

+   使用 UserDefinedFileAttributeView 维护用户定义的文件属性

# 介绍

许多应用程序需要访问文件和目录信息。这些信息包括文件是否可以执行，文件的大小，文件的所有者，甚至其内容类型等属性。在本章中，我们将研究获取有关文件或目录信息的各种技术。我们根据所需的访问类型组织了配方。

使用`java.nio.file.Files`类获取文件和目录信息的五种一般方法如下：

+   使用`Files`类的特定方法，如`isDirectory`方法，逐个获取单个属性。这在*获取文件和目录信息*配方中有详细说明。

+   使用`Files`类的`getAttribute`方法逐个获取单个属性。这在*使用 getAttribute 方法逐个获取单个属性*配方中有详细说明。

+   使用`readAttributes`方法返回使用`String`指定要返回的属性的映射。这在*获取文件属性的映射*配方中有解释。

+   使用`readAttributes`方法与`BasicFileAttributes`派生类返回该属性集的属性类。这在*使用 BasicFileAttributeView 维护基本文件属性*配方中有详细说明。

+   使用`getFileAttributes`方法返回提供对特定属性集的访问的视图。这也在*使用 BasicFileAttributeView 方法维护基本文件属性*配方中有详细说明。它在配方的*还有更多..*部分中找到。

通过几种方法支持对属性的动态访问，并允许开发人员使用`String`指定属性。`Files`类的`getAttribute`方法代表了这种方法。

Java 7 引入了一些基于文件视图的接口。视图只是关于文件或目录的信息的一种组织方式。例如，`AclFileAttributeView`提供了与文件的**访问控制列表**（**ACL**）相关的方法。`FileAttributeView`接口是提供特定类型文件信息的其他接口的基接口。`java.nio.file.attribute`包中的子接口包括以下内容：

+   `AclFileAttributeView：`用于维护文件的 ACL 和所有权属性

+   `BasicFileAttributeView：`用于访问有关文件的基本信息并设置与时间相关的属性

+   `DosFileAttributeView：`设计用于与传统**磁盘操作系统**（**DOS**）文件属性一起使用

+   `FileOwnerAttributeView：`用于维护文件的所有权

+   `PosixFileAttributeView：`支持**便携式操作系统接口**（**POSIX**）属性

+   `UserDefinedFileAttributeView：`支持文件的用户定义属性

视图之间的关系如下所示：

### 注意

低级接口继承自它们上面的接口。

![介绍](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_03_01.jpg)

`readAttributes` 方法的第二个参数指定要返回的属性类型。支持三个属性接口，它们的关系如下图所示。这些接口提供了访问它们对应的视图接口的方法：

![Introduction](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_03_02.jpg)

每个视图都有一个专门的配方。这里不讨论 `FileStoreAttributeView`，但在 第四章 的 *管理文件和目录* 中有相关内容。

本章中示例使用的文件和目录结构在 第二章 的介绍中有描述，*使用路径定位文件和目录*。

# 确定文件内容类型

文件的类型通常可以从其扩展名推断出来。但这可能会误导，具有相同扩展名的文件可能包含不同类型的数据。`Files` 类的 `probeContentType` 方法用于确定文件的内容类型（如果可能）。当应用程序需要一些指示文件内容以便处理时，这是很有用的。

## 准备工作

为了确定内容类型，需要完成以下步骤：

1.  获取代表文件的 `Path` 对象。

1.  使用 `Path` 对象作为 `probeContentType` 方法的参数。

1.  使用结果处理文件。

## 操作步骤...

1.  创建一个新的控制台应用程序。将三种不同类型的文件添加到 `/home/docs` 目录中。使用以下内容作为 `main` 方法。虽然你可以使用任何你选择的文件，但本示例使用了一个文本文件，一个 Word 文档和一个可执行文件：

```java
public static void main(String[] args) throws Exception {
displayContentType("/home/docs/users.txt");
displayContentType("/home/docs/Chapter 2.doc");
displayContentType("/home/docs/java.exe");
}
static void displayContentType(String pathText) throws Exception {
Path path = Paths.get(pathText);
String type = Files.probeContentType(path);
System.out.println(type);
}

```

1.  执行应用程序。你的输出应该如下所示。返回的类型取决于你使用的实际文件：

**text/plain**

**application/msword**

**application/x-msdownload**

## 工作原理...

创建了一个 `java.nio.file.Path` 变量，并分配给了三个不同的文件。对每个文件执行了 `Files` 类的 `probeContentPath` 方法。返回的结果是一个 `String`，用于说明目的。`probeContentType` 方法会抛出一个 `java.io.IOException`，我们通过让 `displayConentType` 方法和 `main` 方法抛出一个基类异常来处理这个异常。`probeContentPath` 方法也可能会抛出一个 `java.lang.SecurityException`，但你不需要处理它。

在本示例中使用的文件中，第一个文件是一个文本文件。返回的类型是 **text/plain**。另外两个是一个 Word 文档和可执行文件 `java.exe`。返回的类型分别是 **application/msword** 和 **application/x-msdownload**。

## 还有更多...

该方法的结果是一个 `String`，由 **多用途互联网邮件扩展** (**MIME**)：**RFC 2045：多用途互联网邮件扩展（MIME）第一部分：互联网消息正文的格式** 定义。这允许使用 RFC 2045 语法规范解析 `String`。如果无法识别内容类型，则返回 null。

MIME 类型由类型和子类型以及一个或多个可选参数组成。类型和子类型之间使用斜杠分隔。在前面的输出中，文本文档的类型是 text，子类型是 plain。另外两种类型都是 application 类型，但子类型不同。以 x- 开头的子类型是非标准的。

`probeContentType`方法的实现取决于系统。该方法将使用`java.nio.file.spi.FileTypeDetector`实现来确定内容类型。它可能检查文件名或可能访问文件属性以确定文件内容类型。大多数操作系统将维护文件探测器列表。从此列表中加载并用于确定文件类型。`FileTypeDetector`类没有扩展，并且目前无法确定哪些文件探测器可用。

# 使用`getAttribute`方法一次获取一个属性

如果您有兴趣获取单个文件属性，并且知道属性的名称，则`Files`类的`getAttribute`方法简单且易于使用。它将返回基于表示属性的`String`的文件信息。本食谱的第一部分说明了`getAttribute`方法的简单用法。其他可用的属性列在本食谱的*更多内容*部分中。

## 准备就绪

获取单个文件属性值：

1.  创建一个表示感兴趣的文件的`Path`对象。

1.  将此对象用作`getAttribute`方法的第一个参数。

1.  使用包含属性名称的`String`作为方法的第二个参数。

## 如何做...

1.  创建一个新的控制台应用程序并使用以下`main`方法。在此方法中，我们确定文件的大小如下：

```java
public static void main(String[] args) {
try {
Path path = FileSystems.getDefault().getPath("/home/docs/users.txt");
System.out.println(Files.getAttribute(path, "size"));
}
catch (IOException ex) {
System.out.println("IOException");
}
}

```

1.  输出将如下所示，并将取决于所使用文件的实际大小：

**30**

## 它是如何工作的...

创建了一个表示`users.txt`文件的`Path`。然后将此路径用作`Files`类的`getAttribute`方法的第一个参数。执行代码时，将显示文件的大小。

## 更多内容...

`Files`类的`getAttribute`方法具有以下三个参数：

+   一个表示文件的`Path`对象

+   包含属性名称的`String`

+   在处理符号文件时使用的可选`LinkOption`

以下表格列出了可以与此方法一起使用的有效属性名称：

| 属性名称 | 数据类型 |
| --- | --- |
| `lastModifiedTime` | FileTime |
| `lastAccessTime` | FileTime |
| `creationTime` | FileTime |
| `size` | 长整型 |
| `isRegularFile` | 布尔值 |
| `isDirectory` | 布尔值 |
| `isSymbolicLink` | 布尔值 |
| `isOther` | 布尔值 |
| `fileKey` | 对象 |

如果使用无效的名称，则会发生运行时错误。这是这种方法的主要弱点。例如，如果名称拼写错误，我们将收到运行时错误。此方法如下所示，指定的属性在属性`String`末尾有一个额外的*s*：

```java
System.out.println(Files.getAttribute(path, "sizes"));

```

当应用程序执行时，您应该获得类似以下的结果：

**线程"main"中的异常 java.lang.IllegalArgumentException：未识别'sizes'**

**在 sun.nio.fs.AbstractBasicFileAttributeView$AttributesBuilder.<init>(AbstractBasicFile AttributeView.java:102)**

**在 sun.nio.fs.AbstractBasicFileAttributeView$AttributesBuilder.create(AbstractBasicFileAttributeView.java:112)**

**在 sun.nio.fs.AbstractBasicFileAttributeView.readAttributes(AbstractBasicFileAttributeView.java:166)**

**在 sun.nio.fs.AbstractFileSystemProvider.readAttributes(AbstractFileSystemProvider.java:92)**

**在 java.nio.file.Files.readAttributes(Files.java:1896)**

**在 java.nio.file.Files.getAttribute(Files.java:1801)**

**在 packt.SingleAttributeExample.main(SingleAttributeExample.java:15)**

**Java 结果：1**

可以按照*获取文件属性映射*食谱中的描述获取文件属性列表。这可以用来避免使用无效名称。

# 获取文件属性映射

访问文件属性的另一种方法是使用`Files`类的`readAttributes`方法。该方法有两个重载版本，在第二个参数和返回的数据类型上有所不同。在本示例中，我们将探讨返回`java.util.Map`对象的版本，因为它允许在返回的属性上更灵活。该方法的第二个版本在一系列食谱中讨论，每个食谱都专门讨论一类属性。

## 准备就绪

要获取`Map`对象形式的属性列表，需要执行以下步骤：

1.  创建一个表示文件的`Path`对象。

1.  对`Files`类应用静态的`readAttributes`方法。

1.  指定其参数的值：

+   表示感兴趣文件的`Path`对象

+   表示要返回的属性的`String`参数

+   可选的第三个参数，指定是否应该跟踪符号链接

## 如何做...

1.  创建一个新的控制台应用程序。使用以下`main`方法：

```java
public static void main(String[] args) throws Exception {
Path path = Paths.getPath("/home/docs/users.txt");
try {
Map<String, Object> attrsMap = Files.readAttributes(path, "*");
Set<String> keys = attrsMap.keySet();
for(String attribute : keys) {
out.println(attribute + ": "
+ Files.getAttribute(path, attribute));
}
}
}

```

1.  执行应用程序。您的输出应该类似于以下内容：

**lastModifiedTime: 2011-09-06T01:26:56.501665Z**

**fileKey: null**

**isDirectory: false**

**lastAccessTime: 2011-09-06T21:14:11.214057Z**

**isOther: false**

**isSymbolicLink: false**

**isRegularFile: true**

**creationTime: 2011-09-06T21:14:11.214057Z**

**大小：30**

## 它是如何工作的...

示例中使用了`docs`目录中的`users.txt`文件。声明了一个键类型为`String`，值类型为`Object`的`Map`对象，然后为其赋予了`readAttributes`方法的值。使用`Map`接口的`keySet`方法创建了一个`java.util.Set`对象。这使我们可以访问`Map`的键和值。在 for each 循环中，将集合的每个成员用作`getAttribute`方法的参数。文件的相应属性和其值将被显示。`getAttribute`方法在*使用 getAttribute 方法逐个获取属性*食谱中有解释。

在这个例子中，我们使用字符串字面值`"*"`作为第二个参数。这个值指示方法返回文件的所有可用属性。正如我们很快将看到的，其他字符串值可以用来获得不同的结果。

`readAttributes`方法是一个原子文件系统操作。默认情况下，会跟踪符号链接。要指示该方法不要跟踪符号链接，使用`java.nio.file`包的`LinkOption.NOFOLLOW_LINKS`枚举常量，如下所示：

```java
Map<String, Object> attrsMap = Files.readAttributes(path, "*", LinkOption.NOFOLLOW_LINKS);

```

## 还有更多...

该方法的有趣之处在于它的第二个参数。`String`参数的语法包括一个可选的`viewName`，后面跟着一个冒号，然后是属性列表。`viewName`通常是以下之一：

+   acl

+   基本

+   所有者

+   用户

+   dos

+   posix

每个`viewNames`对应于一个视图接口的名称。

属性列表是一个逗号分隔的属性列表。属性列表可以包含零个或多个元素。如果使用无效的元素名称，则会被忽略。使用星号将返回与该`viewName`关联的所有属性。如果不包括`viewName`，则会返回所有基本文件属性，就像前面所示的那样。

以基本视图为例，以下表格说明了我们如何选择要返回的属性：

| String | 返回的属性 |
| --- | --- |
| `"*"` | 所有基本文件属性 |
| `"basic:*"` | 所有基本文件属性 |
| `"basic:isDirectory,lastAccessTime`" | 仅`isDirectory`和`lastAccessTime`属性 |
| `"isDirectory,lastAccessTime`" | 仅`isDirectory`和`lastAccessTime`属性 |
| `""` | 无 - 会生成`java.lang.IllegalArgumentException` |

`String`属性在除基本视图以外的视图中使用方式相同。

### 提示

属性`String`中不能有嵌入的空格。例如，`String, "basic:isDirectory, lastAccessTime"`，逗号后面有一个空格会导致`IllegalArgumentException`。

# 获取文件和目录信息

经常需要检索有关文件或目录的基本信息。本教程将介绍`java.nio.file.Files`类如何提供直接支持。这些方法仅提供对文件和目录信息的部分访问，并以`isRegularFile`等方法为代表。此类方法的列表可在本教程的*更多信息*部分找到。

## 准备就绪

要使用`Files`类的方法显示信息很容易，因为这些方法大多数（如果不是全部）都是静态的。这意味着这些方法可以轻松地针对`Files`类名称执行。要使用这种技术：

1.  创建一个表示文件或目录的`Path`对象。

1.  将`Path`对象用作适当的`Files`类方法的参数。

## 如何做...

1.  为了演示如何获取文件属性，我们将开发一个方法来显示文件的属性。创建一个包含以下`main`方法的新控制台应用程序。在该方法中，我们创建一个文件的引用，然后调用`displayFileAttribute`方法。它使用几种方法来显示有关路径的信息，如下所示：

```java
public static void main(String[] args) throws Exception {
Path path = FileSystems.getDefault().getPath("/home/docs/users.txt");
displayFileAttributes(path);
}
private static void displayFileAttributes(Path path) throws Exception {
String format =
"Exists: %s %n"
+ "notExists: %s %n"
+ "Directory: %s %n"
+ "Regular: %s %n"
+ "Executable: %s %n"
+ "Readable: %s %n"
+ "Writable: %s %n"
+ "Hidden: %s %n"
+ "Symbolic: %s %n"
+ "Last Modified Date: %s %n"
+ "Size: %s %n";
System.out.printf(format,
Files.exists(path, LinkOption.NOFOLLOW_LINKS),
Files.notExists(path, LinkOption.NOFOLLOW_LINKS),
Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS),
Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS),
Files.isExecutable(path),
Files.isReadable(path),
Files.isWritable(path),
Files.isHidden(path),
Files.isSymbolicLink(path),
Files.getLastModifiedTime(path, LinkOption.NOFOLLOW_LINKS),
Files.size(path));
}

```

1.  执行程序。您的输出应如下所示：

**存在：true**

**不存在：false**

**目录：false**

**常规：true**

**可执行：true**

**可读：true**

**可写：true**

**隐藏：false**

**符号链接：false**

**上次修改日期：2011-10-20T03:18:20.338139Z**

**大小：29**

## 它是如何工作的...

创建了指向`users.txt`文件的`Path`。然后将此`Path`对象传递给`displayFileAttribute`方法，该方法显示了文件的许多属性。返回这些属性的方法在以下表格中进行了总结：

| 方法 | 描述 |
| --- | --- |
| `exists` | 如果文件存在则返回`true` |
| `notExists` | 如果文件不存在则返回`true` |
| `isDirectory` | 如果路径表示目录则返回`true` |
| `isRegularFile` | 如果路径表示常规文件则返回`true` |
| `isExecutable` | 如果文件可执行则返回`true` |
| `isReadable` | 如果文件可读则返回`true` |
| `isWritable` | 如果文件可写则返回`true` |
| `isHidden` | 如果文件是隐藏的且对非特权用户不可见则返回`true` |
| `isSymbolicLink` | 如果文件是符号链接则返回`true` |
| `getLastModifiedTime` | 返回文件上次修改的时间 |
| `size` | 返回文件的大小 |

其中几种方法具有第二个参数，指定如何处理符号链接。当存在`LinkOption.NOFOLLOW_LINKS`时，符号链接不会被跟踪。第二个参数是可选的。如果省略，则不会跟踪符号链接。符号链接在第二章的*使用路径定位文件和目录*中的*管理符号链接*教程中进行了讨论。

## 更多信息...

以下表格总结了抛出的异常以及方法是否为非原子操作。如果调用线程无权读取文件，则可能会抛出`SecurityException`。 

### 注意

当一个方法被称为**非原子**时，这意味着其他文件系统操作可能会与该方法同时执行。非原子操作可能导致不一致的结果。也就是说，在这些方法执行时，可能会导致对方法目标的并发操作可能修改文件的状态。在使用这些方法时应考虑到这一点。

这些方法标记为过时的结果在返回时不一定有效。也就是说，不能保证任何后续访问都会成功，因为文件可能已被删除或以其他方式修改。

被指定为**无法确定**的方法表示，如果无法确定结果，则可能返回 `false`。例如，如果 `exists` 方法无法确定文件是否存在，则会返回 `false`。它可能存在，但该方法无法确定它是否存在：

| 方法 | SecurityException | IOException | 非原子 | 过时 | 无法确定 |
| --- | --- | --- | --- | --- | --- |
| `exists` | 是 |   |   | 是 | 是 |
| `notExists` | 是 |   |   | 是 | 是 |
| `isDirectory` | 是 |   |   |   | 是 |
| `isRegularFile` | 是 |   |   |   | 是 |
| `isExecutable` | 是 |   | 是 | 是 | 是 |
| `isReadable` | 是 |   | 是 | 是 | 是 |
| `isWritable` | 是 |   | 是 | 是 | 是 |
| `isHidden` | 是 | 是 |   |   |   |
| `isSymbolicLink` | 是 |   |   |   | 是 |
| `getLastModifiedTime` | 是 | 是 |   |   |   |
| `size` | 是 | 是 |   |   |   |

请注意，`notExists` 方法不是 `exists` 方法的反义词。使用任一方法，可能无法确定文件是否存在。在这种情况下，两种方法都将返回 `false`。

`isRegularFile` 确定文件是否为常规文件。如果 `isDirectory, isSymbolicLink` 和 `isRegularFile` 方法返回 `false`，则可能是因为：

+   它不是这些类型之一

+   如果文件不存在或

+   如果无法确定它是文件还是目录

对于这些方法，它们在 `BasicFileAttributes` 接口中对应的方法可能会提供更好的结果。这些方法在 *使用 BasicFileAttributeView 维护基本文件属性* 部分中有介绍。

`isExecutable` 方法检查文件是否存在，以及 JVM 是否有执行文件的访问权限。如果文件是一个目录，则该方法确定 JVM 是否有足够的权限来搜索该目录。如果：

+   文件不存在

+   文件不可执行

+   如果无法确定是否可执行

隐藏的含义取决于系统。在 UNIX 系统上，如果文件名以句点开头，则文件是隐藏的。在 Windows 上，如果设置了 DOS 隐藏属性，则文件是隐藏的。

# 确定操作系统对属性视图的支持

操作系统可能不支持 Java 中的所有属性视图。有三种基本技术可以确定支持哪些视图。知道支持哪些视图可以让开发人员避免在尝试使用不受支持的视图时可能发生的异常。

## 准备工作

这三种技术包括使用：

+   使用 `java.nio.file.FileSystem` 类的 `supportedFileAttributeViews` 方法返回一个包含所有支持的视图的集合。

+   使用 `java.nio.file.FileStore` 类的 `supportsFileAttributeView` 方法和一个类参数。如果该类受支持，则该方法将返回 `true`。

+   使用 `FileStore` 类的 `supportsFileAttributeView` 方法和一个 `String` 参数。如果该 `String` 表示的类受支持，则该方法将返回 `true`。

第一种方法是最简单的，将首先进行说明。

## 如何做...

1.  创建一个新的控制台应用程序，其中包含以下 `main` 方法。在这个方法中，我们将显示当前系统支持的所有视图，如下所示：

```java
public static void main(String[] args)
Path path = Paths.get("C:/home/docs/users.txt");
FileSystem fileSystem = path.getFileSystem();
Set<String> supportedViews = fileSystem.supportedFileAttributeViews();
for(String view : supportedViews) {
System.out.println(view);
}
}

```

1.  当应用在 Windows 7 系统上执行时，应该会得到以下输出：

**acl**

**basic**

**owner**

**user**

**dos**

1.  当应用在 Ubuntu 10.10 版本下执行时，应该会得到以下输出：

**basic**

**owner**

**user**

**unix**

**dos**

**posix**

请注意，**acl**视图不受支持，而**unix**和**posix**视图受支持。在 Java 7 发布版中没有`UnixFileAttributeView`。但是，该接口可以作为 JSR203-backport 项目的一部分找到。

## 它是如何工作的...

为`users.txt`文件创建了一个`Path`对象。接下来使用`getFileSystem`方法获取了该`Path`的文件系统。`FileSystem`类具有`supportedFileAttributeViews`方法，该方法返回一个表示支持的视图的字符串集合。然后使用 for each 循环显示每个字符串值。

## 还有更多...

还有另外两种方法可以用来确定支持哪些视图：

+   使用带有类参数的`supportsFileAttributeView`方法

+   使用带有`String`参数的`supportsFileAttributeView`方法

这两种技术非常相似。它们都允许您测试特定的视图。

### 使用带有类参数的 supportsFileAttributeView 方法

重载的`supportsFileAttributeView`方法接受表示所讨论的视图的类对象。将以下代码添加到上一个示例的`main`方法中。在这段代码中，我们确定支持哪些视图：

```java
try {
FileStore fileStore = Files.getFileStore(path);
System.out.println("FileAttributeView supported: " + fileStore.supportsFileAttributeView(
FileAttributeView.class));
System.out.println("BasicFileAttributeView supported: " + fileStore.supportsFileAttributeView(
BasicFileAttributeView.class));
System.out.println("FileOwnerAttributeView supported: " + fileStore.supportsFileAttributeView(
FileOwnerAttributeView.class));
System.out.println("AclFileAttributeView supported: " + fileStore.supportsFileAttributeView(
AclFileAttributeView.class));
System.out.println("PosixFileAttributeView supported: " + fileStore.supportsFileAttributeView(
PosixFileAttributeView.class));
System.out.println("UserDefinedFileAttributeView supported: " + fileStore.supportsFileAttributeView(
UserDefinedFileAttributeView.class));
System.out.println("DosFileAttributeView supported: " + fileStore.supportsFileAttributeView(
DosFileAttributeView.class));
}
catch (IOException ex) {
System.out.println("Attribute view not supported");
}

```

在 Windows 7 机器上执行时，您应该获得以下输出：

**FileAttributeView supported: false**

**BasicFileAttributeView supported: true**

**FileOwnerAttributeView supported: true**

**AclFileAttributeView supported: true**

**PosixFileAttributeView supported: false**

**UserDefinedFileAttributeView supported: true**

**DosFileAttributeView supported: true**

### 使用带有`String`参数的`supportsFileAttributeView`方法

重载的`supportsFileAttributeView`方法接受一个`String`对象的工作方式类似。将以下代码添加到`main`方法的 try 块中：

```java
System.out.println("FileAttributeView supported: " + fileStore.supportsFileAttributeView(
"file"));
System.out.println("BasicFileAttributeView supported: " + fileStore.supportsFileAttributeView(
"basic"));
System.out.println("FileOwnerAttributeView supported: " + fileStore.supportsFileAttributeView(
"owner"));
System.out.println("AclFileAttributeView supported: " + fileStore.supportsFileAttributeView(
"acl"));
System.out.println("PosixFileAttributeView supported: " + fileStore.supportsFileAttributeView(
"posix"));
System.out.println("UserDefinedFileAttributeView supported: " + fileStore.supportsFileAttributeView(
"user"));
System.out.println("DosFileAttributeView supported: " + fileStore.supportsFileAttributeView(
"dos"));

```

在 Windows 7 平台上执行时，您应该获得以下输出：

**FileAttributeView supported: false**

**BasicFileAttributeView supported: true**

**FileOwnerAttributeView supported: true**

**AclFileAttributeView supported: true**

**PosixFileAttributeView supported: false**

**UserDefinedFileAttributeView supported: true**

**DosFileAttributeView supported: true**

# 使用 BasicFileAttributeView 维护基本文件属性

`java.nio.file.attribute.BasicFileAttributeView`提供了一系列方法，用于获取有关文件的基本信息，例如其创建时间和大小。该视图具有一个`readAttributes`方法，该方法返回一个`BasicFileAttributes`对象。`BasicFileAttributes`接口具有几种用于访问文件属性的方法。该视图提供了一种获取文件信息的替代方法，而不是由`Files`类支持的方法。该方法的结果有时可能比`Files`类的结果更可靠。

## 准备工作

有两种方法可以获取`BasicFileAttributes`对象。第一种方法是使用`readAttributes`方法，该方法使用`BasicFileAttributes.class`作为第二个参数。第二种方法使用`getFileAttributeView`方法，并在本章的*更多内容..*部分中进行了探讨。

`Files`类的`readAttributes`方法最容易使用：

1.  将表示感兴趣的文件的`Path`对象用作第一个参数。

1.  将`BasicFileAttributes.class`用作第二个参数。

1.  使用返回的`BasicFileAttributes`对象方法来访问文件属性。

这种基本方法用于本章中所示的其他视图。只有属性视图类不同。

## 操作步骤...

1.  创建一个新的控制台应用程序。使用以下`main`方法。在该方法中，我们创建了一个`BasicFileAttributes`对象，并使用其方法来显示有关文件的信息：

```java
public static void main(String[] args) {
Path path
= FileSystems.getDefault().getPath("/home/docs/users.txt");
try {
BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class);
System.out.println("Creation Time: " + attributes.creationTime());
System.out.println("Last Accessed Time: " + attributes.lastAccessTime());
System.out.println("Last Modified Time: " + attributes.lastModifiedTime());
System.out.println("File Key: " + attributes.fileKey());
System.out.println("Directory: " + attributes.isDirectory());
System.out.println("Other Type of File: " + attributes.isOther());
System.out.println("Regular File: " + attributes.isRegularFile());
System.out.println("Symbolic File: " + attributes.isSymbolicLink());
System.out.println("Size: " + attributes.size());
}
catch (IOException ex) {
System.out.println("Attribute error");
}
}

```

1.  执行应用程序。您的输出应该类似于以下内容：

**Creation Time: 2011-09-06T21:14:11.214057Z**

**Last Accessed Time: 2011-09-06T21:14:11.214057Z**

**Last Modified Time: 2011-09-06T01:26:56.501665Z**

**文件键：null**

**目录：false**

**其他类型的文件：false**

**常规文件：true**

**符号文件：false**

**大小：30**

## 它是如何工作的...

首先，我们创建了一个代表`users.txt`文件的`Path`对象。接下来，我们使用`Files`类的`readAttributes`方法获取了一个`BasicFileAttributes`对象。该方法的第一个参数是一个`Path`对象。第二个参数指定了我们想要返回的对象类型。在这种情况下，它是一个`BasicFileAttributes.class`对象。

然后是一系列打印语句，显示有关文件的特定属性信息。`readAttributes`方法检索文件的所有基本属性。由于它可能会抛出`IOException`，代码序列被包含在 try 块中。

大多数`BasicFileAttributes`接口方法很容易理解，但有一些需要进一步解释。首先，如果`isOther`方法返回`true`，这意味着文件不是常规文件、目录或符号链接。此外，尽管文件大小以字节为单位，但由于文件压缩和稀疏文件的实现等问题，实际大小可能会有所不同。如果文件不是常规文件，则返回值的含义取决于系统。

`fileKey`方法返回一个唯一标识该文件的对象。在 UNIX 中，设备 ID 或 inode 用于此目的。如果文件系统及其文件发生更改，文件键不一定是唯一的。它们可以使用`equals`方法进行比较，并且可以用于集合。再次强调的是，假设文件系统没有以影响文件键的方式发生更改。两个文件的比较在第二章的*确定两个路径是否等效*中有所涉及，*使用路径定位文件和目录*。

## 还有更多...

获取对象的另一种方法是使用`Files`类的`getFileAttributeView`方法。它根据第二个参数返回一个基于`AttributeView`的派生对象。要获取`BasicFileAttributeView`对象的实例：

1.  使用代表感兴趣的文件的`Path`对象作为第一个参数。

1.  使用`BasicFileAttributeView`作为第二个参数。

不要使用以下语句：

```java
BasicFileAttributes attributes = Files.readAttributes(path, BasicFileAttributes.class);

```

我们可以用以下代码序列替换它：

```java
BasicFileAttributeView view = Files.getFileAttributeView(path, BasicFileAttributeView.class);
BasicFileAttributes attributes = view.readAttributes();

```

使用`getFileAttributeView`方法返回`BasicFileAttributeView`对象。然后`readAttributes`方法返回`BasicFileAttributes`对象。这种方法更长，但现在我们可以访问另外三种方法，如下所示：

+   `name：`这返回属性视图的名称

+   `readAttributes：`这返回一个`BasicFileAttributes`对象

+   `setTimes：`这用于设置文件的时间属性

1.  然后我们使用如下所示的`name`方法：

```java
System.out.println("Name: " + view.name());

```

这导致了以下输出：

**名称：basic**

然而，这并没有为我们提供太多有用的信息。`setTimes`方法在第四章的*设置文件或目录的时间相关属性*中有所说明，*管理文件和目录*。

# 使用 PosixFileAttributeView 维护 POSIX 文件属性

许多操作系统支持**可移植操作系统接口**（**POSIX**）标准。这提供了一种更便携的方式来编写可以在不同操作系统之间移植的应用程序。Java 7 支持使用`java.nio.file.attribute.PosixFileAttributeView`接口访问文件属性。 

并非所有操作系统都支持 POSIX 标准。*确定操作系统是否支持属性视图*的示例说明了如何确定特定操作系统是否支持 POSIX。

## 准备工作

为了获取文件或目录的 POSIX 属性，我们需要执行以下操作：

1.  创建一个代表感兴趣的文件或目录的`Path`对象。

1.  使用`getFileAttributeView`方法获取`PosixFileAttributeView`接口的实例。

1.  使用`readAttributes`方法获取一组属性。

## 如何做...

1.  创建一个新的控制台应用程序。使用以下`main`方法。在此方法中，我们获取`users.txt`文件的属性如下：

```java
public static void main(String[] args) throws Exception {
Path path = Paths.get("home/docs/users.txt");
FileSystem fileSystem = path.getFileSystem();
PosixFileAttributeView view = Files.getFileAttributeView(path, PosixFileAttributeView.class);
PosixFileAttributes attributes = view.readAttributes();
System.out.println("Group: " + attributes.group());
System.out.println("Owner: " + attributes.owner().getName());
Set<PosixFilePermission> permissions = attributes.permissions();
for(PosixFilePermission permission : permissions) {
System.out.print(permission.name() + " ");
}
}

```

1.  执行应用程序。您的输出应如下所示。所有者名称可能会有所不同。在这种情况下，它是**richard：**

**组：richard**

**所有者：richard**

**OWNER_READ OWNER_WRITE OTHERS_READ GROUP_READ**

## 它是如何工作的...

为`users.txt`文件创建了一个`Path`对象。这被用作`Files`类的`getFileAttributeView`方法的第一个参数。第二个参数是`PosixFileAttributeView.class`。返回了一个`PosixFileAttributeView`对象。

接下来，使用`readAttributes`方法获取了`PosixFileAttributes`接口的实例。使用`group`和`getName`方法显示了文件的组和所有者。权限方法返回了一组`PosixFilePermission`枚举。这些枚举表示分配给文件的权限。

## 还有更多...

`PosixFileAttributes`接口扩展了`java.nio.file.attribute.BasicFileAttributes`接口，因此可以访问其所有方法。`PosixFileAttributeView`接口扩展了`java.nio.file.attribute.FileOwnerAttributeView`和`BasicFileAttributeView`接口，并继承了它们的方法。

`PosixFileAttributeView`接口具有`setGroup`方法，可用于配置文件的组所有者。可以使用`setPermissions`方法维护文件的权限。在第四章*管理文件和目录*中讨论了维护文件权限的*管理 POSIX 属性*配方。

## 另请参阅

*Maintaining basic file attributes using the BasicFileAttributeView*配方详细介绍了通过此视图可用的属性。*使用 FileOwnerAttributeView 维护文件所有权属性*配方讨论了所有权问题。要确定操作系统是否支持 POSIX，请查看*确定属性视图的操作系统支持*配方。

# 使用`DosFileAttributeView`维护 FAT 表属性

`java.nio.file.attribute.DosFileAttributeView`涉及较旧的**磁盘操作系统**（**DOS**）文件。在今天的大多数计算机上，它的价值有限。但是，这是唯一可以用来确定文件是否标记为归档文件或系统文件的接口。

## 准备就绪

要使用`DosFileAttributeView`接口：

1.  使用`Files`类的`getFileAttributeView`方法获取`DosFileAttributeView`的实例。

1.  使用视图的`readAttributes`方法返回`DosFileAttributes`的实例。

1.  使用`DosFileAttributes`类的方法获取文件信息。

此视图支持以下四种方法：

+   `isArchive：`关注文件是否需要备份

+   `isHidden：`如果文件对用户不可见，则返回`true`

+   `isReadOnly：`如果文件只能读取，则返回`true`

+   `isSystem：`如果文件是操作系统的一部分，则返回`true`

## 如何做...

1.  创建一个新的控制台应用程序，并添加以下`main`方法。在此方法中，我们创建`DosFileAttributes`的一个实例，然后使用其方法显示有关文件的信息：

```java
public static void main(String[] args) {
Path path = FileSystems.getDefault().getPath("/home/docs/users.txt");
try {
DosFileAttributeView view = Files.getFileAttributeView(path, DosFileAttributeView.class);
DosFileAttributes attributes = view.readAttributes();
System.out.println("isArchive: " + attributes.isArchive());
System.out.println("isHidden: " + attributes.isHidden());
System.out.println("isReadOnly: " + attributes.isReadOnly());
System.out.println("isSystem: " + attributes.isSystem());
}
catch (IOException ex) {
ex.printStackTrace();
}
}

```

1.  执行程序。您的输出应如下所示：

**isArchive：true**

**isHidden：false**

**isReadOnly：false**

**isSystem：false**

## 它是如何工作的...

创建了一个代表`users.txt`文件的`Path`对象。将此对象用作`Files`类的`getFileAttributeView`方法的参数，以及`DosFileAttributeView.class`。返回了`DosFileAttributeView`接口的一个实例。这被用于创建`DosFileAttributes`接口的一个实例，该实例与接口的四个方法一起使用。

`DosFileAttributeView`扩展了`BasicFileAttributes`接口，并因此继承了其所有属性，如*使用 BasicFileAttributeView 维护基本文件属性*配方中所述。

## 另请参阅

有关其方法的更多信息，请参阅*使用 BasicFileAttributeView 维护基本文件属性*配方。

# 使用 FileOwnerAttributeView 来维护文件所有权属性

如果我们只对访问文件或目录的所有者的信息感兴趣，那么`java.nio.file.attribute.FileOwnerAttributeView`接口提供了检索和设置此类信息的方法。文件所有权的设置在第四章的*设置文件和目录所有者*配方中有所涵盖，*管理文件和目录*。

## 准备就绪

检索文件的所有者：

1.  获取`FileOwnerAttributeView`接口的实例。

1.  使用其`getOwner`方法返回代表所有者的`UserPrincipal`对象。

## 如何做...

1.  创建一个新的控制台应用程序。将以下`main`方法添加到其中。在此方法中，我们将确定`users.txt`文件的所有者如下：

```java
public static void main(String[] args) {
Path path = Paths.get("C:/home/docs/users.txt");
try {
FileOwnerAttributeView view = Files.getFileAttributeView(path, FileOwnerAttributeView.class);
UserPrincipal userPrincipal = view.getOwner();
System.out.println(userPrincipal.getName());
}
catch (IOException e) {
e.printStackTrace();
}
}

```

1.  执行应用程序。您的输出应该类似于以下内容，除了 PC 和用户名应该不同。

**Richard-PC\Richard**

## 它是如何工作的...

为`users.txt`文件创建了一个`Path`对象。接下来，使用`Path`对象作为第一个参数调用了`Files`类的`getFileAttributeView`方法。第二个参数是`FileOwnerAttributeView.class`，这导致返回文件的`FileOwnerAttributeView`对象。

然后调用视图的`getOwner`方法返回一个`UserPrincipal`对象。它的`getName`方法返回用户的名称，然后显示出来。

## 另请参阅

有关其方法的更多信息，请参阅*使用 BasicFileAttributeView 维护基本文件属性*配方。

# 使用 AclFileAttributeView 维护文件的 ACL

`java.nio.file.attribute.AclFileAttributeView`接口提供了对文件或目录的 ACL 属性的访问。这些属性包括用户主体、属性类型以及文件的标志和权限。使用此接口的能力允许用户确定可用的权限并修改这些属性。

## 准备就绪

确定文件或目录的属性：

1.  创建代表该文件或目录的`Path`对象。

1.  使用此`Path`对象作为`Files`类的`getFileAttributeView`方法的第一个参数。

1.  使用`AclFileAttributeView.class`作为其第二个参数。

1.  使用返回的`AclFileAttributeView`对象访问该文件或目录的 ACL 条目列表。

## 如何做...

1.  创建一个新的控制台应用程序。在`main`方法中，我们将检查`users.txt`文件的 ACL 属性。使用`getFileAttributeView`方法获取视图并访问 ACL 条目列表。使用两个辅助方法来支持此示例：`displayPermissions`和`displayEntryFlags`。使用以下`main`方法：

```java
public static void main(String[] args) {
Path path = Paths.get("C:/home/docs/users.txt");
try {
AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class);
List<AclEntry> aclEntryList = view.getAcl();
for (AclEntry entry : aclEntryList) {
System.out.println("User Principal Name: " + entry.principal().getName());
System.out.println("ACL Entry Type: " + entry.type());
displayEntryFlags(entry.flags());
displayPermissions(entry.permissions());
System.out.println();
}
}
catch (IOException e) {
e.printStackTrace();
}
}

```

1.  创建`displayPermissions`方法以显示文件的权限列表如下：

```java
private static void displayPermissions(Set<AclEntryPermission> permissionSet) {
if (permissionSet.isEmpty()) {
System.out.println("No Permissions present");
}
else {
System.out.println("Permissions");
for (AclEntryPermission permission : permissionSet) {
System.out.print(permission.name() + " " );
}
System.out.println();
}
}

```

1.  创建`displayEntryFlags`方法以显示文件的 ACL 标志列表如下：

```java
private static void displayEntryFlags(Set<AclEntryFlag> flagSet) {
if (flagSet.isEmpty()) {
System.out.println("No ACL Entry Flags present");
}
else {
System.out.println("ACL Entry Flags");
for (AclEntryFlag flag : flagSet) {
System.out.print(flag.name() + " ");
}
System.out.println();
}
}

```

1.  执行应用程序。您应该得到类似以下的输出：

**用户主体名称：BUILTIN\Administrators**

**ACL 条目类型：允许**

**没有 ACL 条目标志**

**权限**

WRITE_ATTRIBUTES EXECUTE DELETE READ_ATTRIBUTES WRITE_DATA READ_ACL READ_DATA WRITE_OWNER READ_NAMED_ATTRS WRITE_ACL APPEND_DATA SYNCHRONIZE DELETE_CHILD WRITE_NAMED_ATTRS

用户主体名称：NT AUTHORITY\SYSTEM

ACL 条目类型：允许

未出现 ACL 条目标志

权限

WRITE_ATTRIBUTES EXECUTE DELETE READ_ATTRIBUTES WRITE_DATA READ_ACL READ_DATA WRITE_OWNER READ_NAMED_ATTRS WRITE_ACL APPEND_DATA SYNCHRONIZE DELETE_CHILD WRITE_NAMED_ATTRS

用户主体名称：BUILTIN\Users

ACL 条目类型：允许

未出现 ACL 条目标志

权限

READ_DATA READ_NAMED_ATTRS EXECUTE SYNCHRONIZE READ_ATTRIBUTES READ_ACL

用户主体名称：NT AUTHORITY\Authenticated Users

ACL 条目类型：允许

未出现 ACL 条目标志

权限

READ_DATA READ_NAMED_ATTRS WRITE_ATTRIBUTES EXECUTE DELETE APPEND_DATA SYNCHRONIZE READ_ATTRIBUTES WRITE_NAMED_ATTRS WRITE_DATA READ_ACL

## 它是如何工作的...

创建了到`users.txt`文件的`Path`。然后将其与`AclFileAttributeView.class`参数一起用作`getFileAttributeView`方法的参数。这将返回`AclFileAttributeView`的一个实例。

`AclFileAttributeView`接口有三种方法：`name, getAcl`和`setAcl`。在本例中，只使用了`getAcl`方法，它返回了一个`AclEntry`元素列表。每个条目代表文件的特定 ACL。

使用 for each 循环来遍历列表。显示了用户主体的名称和条目类型。接下来调用了`displayEntryFlags`和`displayPermissions`方法来显示有关条目的更多信息。

这两种方法在构造上相似。进行了检查以确定集合中是否有任何元素，并显示了适当的消息。接下来，将集合的每个元素显示在单独的一行上，以节省输出的垂直空间。

## 还有更多...

`AclFileAttributeView`源自`java.nio.file.attribute.FileOwnerAttributeView`接口。这提供了对`getOwner`和`setOwner`方法的访问。这些方法分别为文件或目录返回或设置`UserPrincipal`对象。

有三种`AclFileAttributeView`方法：

+   `getAcl`方法，返回 ACL 条目列表，如前所示

+   `setAcl`方法，允许我们向文件添加新属性

+   `name`方法，简单地返回`acl`

`getAcl`方法将返回一个`AclEntrys`列表。条目的一个元素是一个`java.nio.file.attribute.UserPrincipal`对象。正如我们在前面的示例中看到的，这代表了可以访问文件的用户。访问用户的另一种技术是使用`java.nio.file.attribute.UserPrincipalLookupService`类。可以使用`FileSystem`类的`getUserPrincipalLookupService`方法获取此类的实例，如下所示：

```java
try {
UserPrincipalLookupService lookupService = FileSystems.getDefault().getUserPrincipalLookupService();
GroupPrincipal groupPrincipal = lookupService.lookupPrincipalByGroupName("Administrators");
UserPrincipal userPrincipal = lookupService.lookupPrincipalByName("Richard");
System.out.println(groupPrincipal.getName());
System.out.println(userPrincipal.getName());
}
catch (IOException e) {
e.printStackTrace();
}

```

服务可用的两种方法可以按用户名或组名查找用户。在前面的代码中，我们使用了`Administrators`组和用户`Richard`。

将此代码添加到上一个示例中，并更改名称以反映系统中的组和用户。当代码执行时，您应该收到类似以下的输出：

BUILTIN\Administrators

Richard-PC\Richard

然而，请注意，`UserPrincipal`和`java.nio.file.attribute.GroupPrincipal`对象的方法提供的信息比用户的名称更少。用户或组名称可能是大小写敏感的，这取决于操作系统。如果使用无效的名称，将抛出`java.nio.file.attribute.UserPrincipalNotFoundException`。

## 另请参阅

在第四章中讨论了管理文件所有权和权限的内容，*管理文件和目录*中的*设置文件和目录所有者*配方。第四章还涵盖了在*管理 ACL 文件权限*配方中说明的 ACL 属性的设置。

# 使用 UserDefinedFileAttributeView 维护用户定义的文件属性

`java.nio.file.attribute.UserDefinedFileAttributeView`接口允许将非标准属性附加到文件或目录。这些类型的属性有时被称为**扩展**属性。通常，用户定义的属性存储有关文件的元数据。这些数据不一定被文件系统理解或使用。

这些属性存储为名称/值对。名称是一个`String`，值存储为`ByteBuffer`对象。该缓冲区的大小不应超过`Integer.MAX_VALUE`。

## 准备就绪

用户定义的属性必须首先附加到文件上。这可以通过以下方式实现：

1.  获取`UserDefinedFileAttributeView`对象的实例

1.  创建一个以`String`名称和`ByteBuffer`值形式的属性

1.  使用`write`方法将属性附加到文件

读取用户定义属性的过程在本配方的*更多内容*部分进行了说明。

## 如何做...

1.  创建一个新的控制台应用程序。在`main`方法中，我们将创建一个名为`publishable`的用户定义属性，并将其附加到`users.txt`文件。使用以下`main`方法：

```java
public static void main(String[] args) {
Path path = Paths.get("C:/home/docs/users.txt");
try {
UserDefinedFileAttributeView view = Files.getFileAttributeView(path, UserDefinedFileAttributeView.class);
view.write("publishable", Charset.defaultCharset().encode("true"));
System.out.println("Publishable set");
}
catch (IOException e) {
e.printStackTrace();
}
}

```

1.  执行应用程序。您的输出应如下所示：

**设置为可发布**

## 它是如何工作的...

首先，创建一个代表`users.txt`文件的`Path`对象。然后使用`Files`类的`getFileAttributeView`方法，使用`Path`对象和`UserDefinedFileAttributeView.class`作为第二个参数。这将返回文件的`UserDefinedFileAttributeView`的实例。

使用这个对象，我们对其执行`write`方法，使用属性`publishable`，创建了一个包含属性值`true`的`java.nio.ByteBuffer`对象。`java.nio.Charset`类的`defaultCharset`方法返回一个使用底层操作系统的区域设置和字符集的`Charset`对象。`encode`方法接受`String`并返回属性值的`ByteBuffer`。然后我们显示了一个简单的消息，指示进程成功完成。

## 还有更多...

`read`方法用于读取属性。要获取与文件关联的用户定义属性，需要按照以下步骤进行：

1.  获取`UserDefinedFileAttributeView`对象的实例。

1.  为属性名称创建一个`String`。

1.  分配一个`ByteBuffer`来保存值。

1.  使用`read`方法获取属性值。

以下代码序列完成了先前附加的`publishable`属性的任务：

```java
String name = "publishable";
ByteBuffer buffer = ByteBuffer.allocate(view.size(name));
view.read(name, buffer);
buffer.flip();
String value = Charset.defaultCharset().decode(buffer).toString();
System.out.println(value);

```

首先创建属性名称的`String`。接下来，创建一个`ByteBuffer`来保存要检索的属性值。`allocate`方法根据`UserDefinedFileAttributeView`接口的`size`方法指定的空间分配空间。此方法确定附加属性的大小并返回大小。

然后对`view`对象执行`read`方法。缓冲区填充了属性值。`flip`方法重置了缓冲区。使用`decode`方法将缓冲区转换为`String`对象，该方法使用操作系统的默认字符集。

在`main`方法中，用这个`read`序列替换用户定义的属性`write`序列。当应用程序执行时，您应该得到类似以下的输出：

**true**

还有一个`delete`方法，用于从文件或目录中删除用户定义的属性。另外，需要注意使用`UserDefinedFileAttributeView`对象需要运行时权限`accessUserDefinedAttributes`。


# 第四章：管理文件和目录

在这一章中，我们将涵盖以下内容：

+   创建文件和目录

+   控制文件复制方式

+   管理临时文件和目录

+   设置文件或目录的时间相关属性

+   管理文件所有权

+   管理 ACL 文件权限

+   管理 POSIX 属性

+   移动文件或目录

+   删除文件和目录

+   管理符号链接

# 介绍

通常需要执行文件操作，如创建文件，操作它们的属性和内容，或从文件系统中删除它们。Java 7 中`java.lang.object.Files`类的添加简化了这个过程。这个类在很大程度上依赖于新的`java.nio.file.Path`接口的使用，这在第二章中深入讨论，*使用路径定位文件和目录*。该类的方法在本质上都是静态的，并且通常将实际的文件操作分配给底层文件系统。

本章描述的许多操作在本质上是原子的，例如用于创建和删除文件或目录的操作。原子操作要么成功执行完成，要么失败并导致操作的有效取消。在执行过程中，它们不会从文件系统的角度受到干扰。其他并发文件操作不会影响该操作。

### 注意

要执行本章中的许多示例，应用程序需要以管理员身份运行。在 Windows 下以管理员身份运行应用程序，右键单击**命令提示符**菜单，选择**以管理员身份运行**。然后导航到适当的目录并使用`java.exe`命令执行。在 UNIX 系统上以管理员身份运行，使用终端窗口中的`sudo`命令，然后是`java`命令。

本章涵盖了基本的文件管理。创建文件和目录所需的方法在*创建文件和目录*教程中介绍。该教程侧重于普通文件。临时文件和目录的创建在*管理临时文件和目录*教程中介绍，链接文件的创建在*管理符号链接*教程中介绍。

复制文件和目录的可用选项在*控制文件复制方式*教程中找到。那里展示的技术提供了处理文件复制的强大方式。移动和删除文件和目录分别在*移动文件或目录*和*删除文件或目录*教程中介绍。

*设置文件或目录的时间相关属性*教程说明了如何为文件分配时间属性。与此相关的还有其他属性，如文件所有权和权限。文件所有权在*管理文件所有权*教程中讨论。文件权限在两个教程中讨论：*管理 ACL 文件权限*和*管理 POSIX 文件权限*。

# 创建文件和目录

在 Java 7 中，创建新文件和目录的过程大大简化。`Files`类实现的方法相对直观，易于整合到您的代码中。在本教程中，我们将介绍如何使用`createFile`和`createDirectory`方法创建新文件和目录。

## 准备工作

在我们的示例中，我们将使用几种不同的方法来创建代表文件或目录的`Path`对象。我们将执行以下操作：

1.  创建`Path`对象。

1.  使用`Files`类的`createDirectory`方法创建目录。

1.  使用`Files`类的`createFile`方法创建文件。

`FileSystem`类的`getPath`方法可用于创建`Path`对象，`Paths`类的`get`方法也可以。`Paths`类的静态`get`方法基于字符串序列或`URI`对象返回`Path`的实例。`FileSystem`类的`getPath`方法也返回`Path`对象，但只使用字符串序列来标识文件。

## 如何做...

1.  创建一个带有`main`方法的控制台应用程序。在`main`方法中，添加以下代码，为`C`目录中的`/home/test`目录创建一个`Path`对象。在 try 块内，使用您的`Path`对象作为参数调用`createDirectory`方法。如果路径无效，此方法将抛出`IOException`。接下来，使用此`Path`对象上的`createFile`方法创建文件`newFile.txt`，再次捕获`IOException`如下：

```java
try {
Path testDirectoryPath = Paths.get("C:/home/test");
Path testDirectory = Files.createDirectory(testDirectoryPath);
System.out.println("Directory created successfully!");
Path newFilePath = FileSystems.getDefault().getPath("C:/home/test/newFile.txt");
Path testFile = Files.createFile(newFilePath);
System.out.println("File created successfully!");
}
catch (IOException ex) {
ex.printStackTrace();
}

```

1.  执行程序。您的输出应如下所示：

**目录创建成功！**

**文件创建成功！**

1.  验证新文件和目录是否存在于您的文件系统中。接下来，在两个方法之后添加一个`IOException`之前的 catch 块，并捕获`FileAlreadyExistsException`：

```java
}
catch (FileAlreadyExistsException a) {
System.out.println("File or directory already exists!");
}
catch (IOException ex) {
ex.printStackTrace();
}

```

1.  当您再次执行程序时，您的输出应如下所示：

**文件或目录已存在！**

## 工作原理...

第一个`Path`对象被创建，然后被`createDirectory`方法用于创建一个新目录。创建第二个`Path`对象后，使用`createFile`方法在刚刚创建的目录中创建了一个文件。重要的是要注意，在创建目录之前无法实例化用于文件创建的`Path`对象，因为它将引用无效的路径。这将导致`IOException`。

当调用`createDirectory`方法时，系统首先检查目录是否存在，如果不存在，则创建。`createFile`方法的工作方式类似。如果文件已经存在，该方法将失败。当我们捕获`FileAlreadyExistsException`时，我们看到了这一点。如果我们没有捕获该异常，将抛出`IOException`。无论哪种方式，现有文件都不会被覆盖。

## 还有更多...

`createFile`和`createDirectory`方法在本质上是原子的。`createDirectories`方法可用于创建目录，如下所述。这三种方法都提供了传递文件属性参数以进行更具体文件创建的选项。

### 使用`createDirectories`方法创建目录层次结构

`createDirectories`方法用于创建目录和可能的其他中间目录。在此示例中，我们通过向`test`目录添加`subtest`和`subsubtest`目录来构建先前的目录结构。注释掉之前创建目录和文件的代码，并添加以下代码序列：

```java
Path directoriesPath = Paths.get("C:/home/test/subtest/subsubtest");
Path testDirectory = Files.createDirectories(directoriesPath);

```

通过检查生成的目录结构来验证操作是否成功。

## 另请参阅

创建临时文件和目录在*管理临时文件和目录*中有所涉及。符号文件的创建在*管理符号链接*中有所说明。

# 控制文件复制的方式

在 Java 7 中，文件复制的过程也变得更加简化，并允许控制复制的方式。`Files`类的`copy`方法支持此操作，并提供了三种不同的复制技术。

## 准备就绪

在我们的示例中，我们将创建一个新文件，然后将其复制到另一个目标文件。这个过程涉及：

1.  使用`createFile`方法创建一个新文件。

1.  为目标文件创建一个路径。

1.  使用`copy`方法复制文件。

## 如何做...

1.  创建一个带有`main`方法的控制台应用程序。在`main`方法中，添加以下代码序列来创建一个新文件。指定两个`Path`对象，一个用于您的初始文件，另一个用于将其复制的位置。然后添加`copy`方法将该文件复制到目标位置，如下所示：

```java
Path newFile = FileSystems.getDefault().getPath("C:/home/docs/newFile.txt");
Path copiedFile = FileSystems.getDefault().getPath("C:/home/docs/copiedFile.txt");
try {
Files.createFile(newFile);
System.out.println("File created successfully!");
Files.copy(newFile, copiedFile);
System.out.println("File copied successfully!");
}
catch (IOException e) {
System.out.println("IO Exception.");
}

```

1.  执行程序。您的输出应如下所示：

**文件创建成功！**

**文件复制成功！**

## 它是如何工作的...

`createFile`方法创建了您的初始文件，`copy`方法将该文件复制到`copiedFile`变量指定的位置。如果您尝试连续两次运行该代码序列，您将遇到`IOException`，因为`copy`方法默认情况下不会替换现有文件。`copy`方法是重载的。使用带有`java.lang.enum.StandardCopyOption`枚举值`REPLACE_EXISTING`的`copy`方法，允许替换文件，如下所示。

`StandardCopyOption`的三个枚举值列在下表中：

| 值 | 含义 |
| --- | --- |
| `ATOMIC_MOVE` | 原子性地执行复制操作 |
| `COPY_ATTRIBUTES` | 将源文件属性复制到目标文件 |
| `REPLACE_EXISTING` | 如果已存在，则替换现有文件 |

用以下代码序列执行前面的示例中的`copy`方法调用替换：

```java
Files.copy(newFile, copiedFile, StandardCopyOption.REPLACE_EXISTING);

```

当代码执行时，文件应该被替换。在*还有更多..*部分的*移动文件和目录*配方中还有另一个使用复制选项的示例。

## 还有更多...

如果源文件和目标文件相同，则该方法会完成，但实际上不会发生复制。`copy`方法不是原子的。

还有另外两个重载的`copy`方法。一个是将`java.io.InputStream`复制到文件，另一个是将文件复制到`java.io.OutputStream`。在本节中，我们将更深入地研究以下过程：

+   复制符号链接文件

+   复制目录

+   将输入流复制到文件

+   将文件复制到输出流

### 复制符号链接文件

当复制符号链接文件时，会复制符号链接的目标。为了说明这一点，在`music`目录中创建一个名为`users.txt`的符号链接文件，指向`docs`目录中的`users.txt`文件。可以通过使用第二章中描述的*管理符号链接*配方中的过程，即*使用路径定位文件和目录*，或者使用本章中所示的*管理符号链接*配方中的方法来完成。

使用以下代码序列执行复制操作：

```java
Path originalLinkedFile = FileSystems.getDefault().getPath("C:/home/music/users.txt");
Path newLinkedFile = FileSystems.getDefault().getPath("C:/home/music/users2.txt");
try {
Files.copy(originalLinkedFile, newLinkedFile);
System.out.println("Symbolic link file copied successfully!");
}
catch (IOException e) {
System.out.println("IO Exception.");
}

```

执行代码。您应该得到以下输出：

**符号链接文件复制成功！**

检查生成的`music`目录结构。`user2.txt`文件已添加，并且与链接文件或原始目标文件没有连接。修改`user2.txt`不会影响其他两个文件的内容。

### 复制目录

当复制目录时，会创建一个空目录。原始目录中的文件不会被复制。以下代码序列说明了这个过程：

```java
Path originalDirectory = FileSystems.getDefault().getPath("C:/home/docs");
Path newDirectory = FileSystems.getDefault().getPath("C:/home/tmp");
try {
Files.copy(originalDirectory, newDirectory);
System.out.println("Directory copied successfully!");
}
catch (IOException e) {
e.printStackTrace();
}

```

执行此序列时，您应该得到以下输出：

**目录复制成功！**

检查`tmp`目录。它应该是空的，因为源目录中的任何文件都没有被复制。

### 将输入流复制到文件

`copy`方法有一个方便的重载版本，允许基于`InputStream`的输入创建新文件。该方法的第一个参数与原始`copy`方法不同，因为它是`InputStream`的实例。

以下示例使用此方法将`jdk7.java.net`网站复制到文件中：

```java
Path newFile = FileSystems.getDefault().getPath("C:/home/docs/java7WebSite.html");
URI url = URI.create("http://jdk7.java.net/");
try (InputStream inputStream = url.toURL().openStream())
Files.copy(inputStream, newFile);
System.out.println("Site copied successfully!");
}
catch (MalformedURLException ex) {
ex.printStackTrace();
}
catch (IOException ex) {
ex.printStackTrace();
}

```

当代码执行时，您应该得到以下输出：

**站点复制成功！**

创建一个`java.lang.Object.URI`对象来表示网站。使用`URI`对象而不是`java.lang.Object.URL`对象立即避免了创建一个单独的 try-catch 块来处理`MalformedURLException`异常。

`URL`类的`openStream`方法返回一个`InputStream`，该流作为`copy`方法的第一个参数使用。请注意使用 try-with-resource 块。这个 try 块是 Java 7 中的新功能，并在第一章的*使用 try-with-resource 块改进异常处理代码*中有详细说明，*Java 语言改进*。

然后执行了`copy`方法。现在可以使用浏览器打开新文件，或者根据需要进行处理。请注意，该方法返回一个表示写入的字节数的长整型值。

### 将文件复制到输出流

`copy`方法的第三个重载版本将打开一个文件并将其内容写入`OutputStream`。当需要将文件的内容复制到非文件对象（如`PipedOutputStream`）时，这可能很有用。当与其他线程通信或写入字节数组时，这也可能很有用，如本例所示。在这个例子中，`users.txt`文件的内容被复制到一个`ByteArrayOutputStream`的实例中。然后使用它的`toByteArray`方法来填充一个数组，如下所示：

```java
Path sourceFile = FileSystems.getDefault().getPath("C:/home/docs/users.txt");
try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
Files.copy(sourceFile, outputStream);
byte arr[] = outputStream.toByteArray();
System.out.println("The contents of " + sourceFile.getFileName());
for(byte data : arr) {
System.out.print((char)data);
}
System.out.println();
}
catch (IOException ex) {
ex.printStackTrace();
}

```

执行这个序列。输出将取决于您的文件内容，但应该类似于以下内容：

**users.txt 的内容**

**Bob**

**Jennifer**

**Sally**

**Tom**

**Ted**

注意使用 try-with-resources 块来处理文件的打开和关闭。在复制操作完成或发生异常时关闭`OutputStream`总是一个好主意。try-with-resources 块很好地处理了这个问题。在某些情况下，该方法可能会阻塞，直到操作完成。它的行为大部分是特定于实现的。此外，输出流可能需要刷新，因为它实现了`Flushable`接口。请注意，该方法返回一个表示写入的字节数的长整型值。

## 另请参阅

有关使用符号链接的更多详细信息，请参阅*管理符号链接*食谱。

# 管理临时文件和目录

创建临时文件和目录的过程可能是许多应用程序的重要部分。临时文件可以用于中间数据或作为稍后清理的临时存储。通过`Files`类可以简单地完成管理临时文件和目录的过程。在本食谱中，我们将介绍如何使用`createTempDirectory`和`createTempFile`方法创建临时文件和目录。

## 准备就绪

在我们的示例中，我们将创建一个临时目录，然后在目录中创建一个临时文件，如下所示：

1.  创建代表临时文件和目录的`Path`对象。

1.  使用`createTempDirectory`方法创建一个临时目录。

1.  使用`createTempFile`方法创建一个临时文件。

## 如何做...

1.  创建一个带有`main`方法的控制台应用程序。在`main`方法中，使用`getPath`方法创建一个`Path`对象`rootDirectory`。使用`rootDirectory`作为第一个参数，空字符串作为第二个参数调用`createTempDirectory`方法。然后使用`toString`方法将返回的`Path`对象`dirPath`转换为`String`并打印到屏幕上。接下来，使用`dirPath`作为第一个参数，空字符串作为第二和第三个参数添加`createTempFile`方法。再次使用`toString`方法打印出这个结果路径，如下所示：

```java
try {
Path rootDirectory = FileSystems.getDefault().getPath("C:/home/docs");
Path tempDirectory = Files.createTempDirectory(rootDirectory, "");
System.out.println("Temporary directory created successfully!");
String dirPath = tempDirectory.toString();
System.out.println(dirPath);
Path tempFile = Files.createTempFile(tempDirectory,"", "");
System.out.println("Temporary file created successfully!");
String filePath = tempFile.toString();
System.out.println(filePath);
}
catch (IOException e) {
System.out.println("IO Exception.");
}

```

1.  这段代码序列将产生类似于以下内容的输出：

**临时目录创建成功！**

**C:\home\docs\7087436262102989339**

**临时文件创建成功！**

**C:\home\docs\7087436262102989339\3473887367961760381**

## 工作原理...

`createTempDirectory`方法创建一个空目录并返回代表这个新目录位置的`Path`对象。同样，`createTempFile`方法创建一个空文件并返回代表这个新文件的`Path`对象。在我们之前的例子中，我们使用`toString`方法来查看我们的目录和文件创建的路径。之前的数字目录和文件名由系统分配，并且是特定于平台的。

这个`createTempDirectory`方法至少需要两个参数，即指向新目录位置的`Path`对象和指定目录前缀的`String`变量。在我们之前的例子中，我们留空了前缀。但是，如果我们想要指定文本以在系统分配的文件名之前出现，第二个变量可以用这个前缀字符串填充。

`createTempFile`方法的工作方式与`createTempDirectory`方法类似，如果我们想要为临时文件分配一个前缀，我们可以使用第二个参数来指定字符串。此方法的第三个参数也可以用来指定文件的后缀或类型，例如`.txt`。

重要的是要注意，尽管在我们的例子中我们指定了我们想要创建目录和文件的`Path`，但每种方法还有另一个版本，其中初始参数，`Path`对象，可以被省略，目录和/或文件将被创建在系统的默认临时目录中。此外，这些方法在创建文件或目录之前不会检查文件或目录的存在，并且会覆盖具有相同临时、系统分配名称的任何现有文件或目录。

## 更多内容...

文件属性名称也可以传递给重载的`createTempDirectory`或`createTempFile`方法。这些属性是可选的，但可以用来指定临时文件的处理方式，例如文件是否应在关闭时被删除。文件属性的创建在*更多内容*的*管理 POSIX 文件权限*配方的部分中描述。

`createTempDirectory`和`createTempFile`方法的存在是有限的。如果希望自动删除这些文件或目录，可以使用关闭挂钩或`java.io.File`类的`deleteOnExit`方法。这两种技术将导致在应用程序或 JVM 终止时删除元素。

# 设置文件或目录的与时间相关的属性

文件的时间戳对于某些应用程序可能至关重要。例如，操作执行的顺序可能取决于文件的最后更新时间。`BasicFileAttributeView`支持三种日期：

+   最后修改时间

+   最后访问时间

+   创建时间

它们可以使用`BasicFileAttributeView`接口的`setTimes`方法进行设置。正如我们将在*更多内容*部分看到的，`Files`类可以用来设置或仅获取最后修改时间。

## 准备工作

为了使用`setTimes`方法设置时间，我们需要做以下操作：

1.  获取代表感兴趣文件的`Path`对象。

1.  获取`BasicFileAttributeView`对象。

1.  为所需的时间创建`FileTime`对象。

1.  使用这些`FileTime`对象作为`setTimes`方法的参数。

## 如何做...

1.  使用以下`main`方法创建一个新的控制台应用程序。我们将更新我们最喜欢的文件`users.txt`的最后修改时间为当前时间：

```java
public static void main(String[] args) throws Exception {
Path path = Paths.get("C:/home/docs/users.txt");
BasicFileAttributeView view = Files.getFileAttributeView(path, BasicFileAttributeView.class);
FileTime lastModifedTime;
FileTime lastAccessTime;
FileTime createTime;
BasicFileAttributes attributes = view.readAttributes();
lastModifedTime = attributes.lastModifiedTime();
createTime = attributes.creationTime();
long currentTime = Calendar.getInstance().getTimeInMillis();
lastAccessTime = FileTime.fromMillis(currentTime);
view.setTimes(lastModifedTime, lastAccessTime, createTime);
System.out.println(attributes.lastAccessTime());
}

```

1.  执行应用程序。除非您有时间机器的访问权限，或者以其他方式操纵了系统的时钟，否则您的输出应该反映出比以下显示的时间更晚的时间：

**2011-09-24T21:34:55.012Z**

## 工作原理...

首先为 `users.txt` 文件创建了一个 `Path`。接下来，使用 `getFileAttributeView` 方法获得了 `BasicFileAttributeView` 接口的一个实例。使用 try 块来捕获 `readAttributes` 或 `setTimes` 方法可能抛出的任何 `IOExceptions`。

在 try 块中，为三种类型的时间创建了 `FileTime` 对象。文件的 `lastModifedTime` 和 `createTime` 时间没有改变。这些是使用 `BasicFileAttributes` 类的相应方法获得的，该类是使用 `view` 方法获得的。

`currentTime` 长变量被赋予以毫秒表示的当前时间。它的值是使用 `Calendar` 类的实例执行 `getTimeInMillis` 方法获得的。然后，三个 `FileTime` 对象被用作 `setTimes` 方法的参数，有效地设置了这些时间值。

## 还有更多...

`FileTime` 类的使用还不止以上所述。此外，`Files` 类提供了维护时间的替代方法。在这里，我们将进一步探讨以下内容： 

+   了解 `FileTime` 类

+   使用 `Files` 类的 `setLastModifiedTime` 来维护最后修改时间

+   使用 `Files` 类的 `setAttribute` 方法来设置单个属性

### 了解 `FileTime` 类

`java.nio.file.attribute.FileTime` 类表示用于 `java.nio` 包方法的时间。要创建一个 `FileTime` 对象，我们需要使用以下两个静态 `FileTime` 方法之一：

+   `from` 方法，接受一个表示持续时间的长数字和一个表示时间测量单位的 `TimeUnit` 对象

+   `fromMillis` 方法，接受一个基于纪元的毫秒数的长参数

`TimeUnit` 是 `java.util.concurrent` 包中的一个枚举。它表示如下表中定义的时间持续时间。它与另一个参数结合使用，其组合表示时间持续时间：

| 枚举值 | 含义 |
| --- | --- |
| 纳秒 | 千分之一微秒 |
| 微秒 | 千分之一毫秒 |
| 毫秒 | 千分之一秒 |
| 秒 | 一秒 |
| 分钟 | 六十秒 |
| 小时 | 六十分钟 |
| 天 | 二十四小时 |

`from` 方法返回一个 `TimeUnit` 对象。它的值是通过将第一个长参数（其度量单位由第二个 `TimeUnit` 参数指定）加到纪元得到的。

### 注意

纪元是 1970-01-01T00:00:00Z，这是大多数计算机上用于指定时间的基本时间。这个基本时间代表 1970 年 1 月 1 日的**协调世界时**午夜。

例如，`from` 方法可以用来表示一个时间点，即从纪元开始的 1000 天，使用以下代码序列：

```java
FileTime fileTime = FileTime.from(1000, TimeUnit.DAYS);
System.out.println(fileTime);

```

执行时应该得到以下输出：

**1972-09-27T00:00:00Z**

`fromMillis` 方法用于创建一个 `FileTime` 对象，其时间是通过将其参数加到纪元得到的，其中参数是以毫秒表示的长数字。如果我们使用以下 `fromMillis` 方法而不是如下所示的 `from` 方法：

```java
FileTime fileTime = FileTime.fromMillis(1000L*60*60*24*1000);

```

我们将得到相同的结果。注意，第一个参数是一个长整型字面量，这迫使表达式的结果为长整数。如果我们没有将结果提升为长整数值，我们将得到一个整数值，这将导致溢出和错误的日期。任何方法的第一个参数都可以是负数。

### 注意

有关在 Java 中使用时间的更多细节，请参阅[`www3.ntu.edu.sg/home/ehchua/programming/java/DateTimeCalendar.html`](http://www3.ntu.edu.sg/home/ehchua/programming/java/DateTimeCalendar.html)。

### 使用 `Files` 类的 `setLastModifiedTime` 来维护最后修改时间

`Files`类的`getLastModifiedTime`和`setLastModifiedTime`方法提供了设置文件最后修改属性的另一种方法。在下面的代码序列中，`setLastModifiedTime`方法使用`lastModifedTime`对象来设置时间，如下所示：

```java
Files.setLastModifiedTime(path, lastModifedTime);

```

`Files`类的`getLastModifiedTime`返回一个`FileTime`对象。我们可以使用这个方法将一个值赋给`lastModifedTime`变量，如下所示：

```java
lastModifedTime = Files.getLastModifiedTime(path);

```

该方法有一个可选的`LinkOption`参数，指示是否应该跟随符号链接。

### 使用 Files 类的 setAttribute 方法来设置单个属性

`setAttribute`方法提供了一种灵活和动态的方法来设置某些文件属性。要设置最后修改时间，我们可以使用以下代码序列：

```java
Files.setAttribute(path, "basic:lastAccessTime", lastAccessTime);

```

第三章中的*使用 getAttribute 方法逐个获取属性*配方详细介绍了可以设置的其他属性。

## 另请参阅

*管理符号链接*配方讨论了符号链接的使用。

# 管理文件所有权

文件或目录的所有者可以在文件创建后进行修改。这是通过使用`java.nio.file.attribute.FileOwnerAttributeView`接口的`setOwner`方法来实现的，当所有权发生变化并需要以编程方式进行控制时，这将非常有用。

使用`java.nio.file.attribute.UserPrincipal`对象表示一个用户。使用`Path`对象表示一个文件或目录。将这两个对象与`Files`类的`setOwner`方法一起使用，可以维护文件的所有权。

## 准备工作

为了更改文件或目录的所有者：

1.  获取一个代表文件或目录的`Path`对象。

1.  使用`Path`作为`getFileAttributeView`方法的参数。

1.  创建一个代表新所有者的`UserPrincipal`对象。

1.  使用`FileOwnerAttributeView`接口的`setOwner`方法来更改文件的所有者。

## 如何做...

1.  在这个例子中，我们将假设`users.txt`文件的当前所有者是`richard`。我们将把所有者更改为一个名为`jennifer`的用户。为此，在系统上创建一个名为`jennifer`的新用户。创建一个包含以下`main`方法的新控制台应用程序。在该方法中，我们将使用`FileOwnerAttributeView`和`UserPrincipal`对象来更改所有者，如下所示：

```java
public static void main(String[] args) throws Exception {
Path path = Paths.get("C:/home/docs/users.txt");
FileOwnerAttributeView view = Files.getFileAttributeView(path, FileOwnerAttributeView.class);
UserPrincipalLookupService lookupService = FileSystems.getDefault().getUserPrincipalLookupService();
UserPrincipal userPrincipal = lookupService.lookupPrincipalByName("jennifer");
view.setOwner(userPrincipal);
System.out.println("Owner: " + view.getOwner().getName());
}

```

1.  为了修改文件的所有权，我们必须拥有适当的权限。本章的介绍解释了如何获取管理员权限。当应用程序在 Windows 7 上执行时，输出应该反映出 PC 名称和文件所有者，如下所示。PC 名称与所有者之间用反斜杠分隔：

**所有者：Richard-PC\Richard**

**所有者：Richard-PC\Jennifer**

## 工作原理...

首先为`users.txt`文件创建了一个`Path`。接下来，使用`getFileAttributeView`方法获取了`FileOwnerAttributeView`接口的一个实例。在 try 块内，使用默认的`FileSystem`类的`getUserPrincipalLookupService`方法创建了一个`UserPrincipalLookupService`对象。`lookupPrincipalByName`方法传递了字符串`jennifer`，返回了代表该用户的`UserPrincipal`对象。

最后一步是将`UserPrincipal`对象传递给`setOwner`方法。然后使用`getOwner`方法检索当前所有者以验证更改。

## 还有更多...

从`FileOwnerAttributeView`派生的任何接口都可以使用`getOwner`或`setOwner`方法。这些包括`AclFileAttributeView`和`PosixFileAttributeView`接口。此外，`Files`类的`setOwner`方法也可以用于更改文件的所有权。

### 使用 Files 类的 setOwner 方法

`Files`类的`setOwner`方法与`FileOwnerAttributeView`接口的`setOwner`方法相同。不同之处在于它有两个参数，一个表示文件的`Path`对象和一个`UserPrincipal`对象。以下序列说明了将`users.txt`文件的所有者设置为`jennifer`的过程：

```java
Path path = Paths.get("C:/home/docs/users.txt");
try {
UserPrincipalLookupService lookupService = FileSystems.getDefault().getUserPrincipalLookupService();
UserPrincipal userPrincipal = lookupService.lookupPrincipalByName("jennifer");
Files.setOwner(path, userPrincipal);
System.out.println("Owner: " + view.getOwner().getName());
}
catch (IOException ex) {
ex.printStackTrace();
}

```

# 管理 ACL 文件权限

在本教程中，我们将研究如何设置 ACL 权限。设置这些权限的能力对许多应用程序很重要。例如，当我们需要控制谁可以修改或执行文件时，我们可以通过编程方式影响这种变化。我们可以改变的内容由稍后列出的`AclEntryPermission`枚举值表示。

## 准备工作

为文件设置新的 ACL 权限：

1.  为要更改其属性的文件创建`Path`对象。

1.  获取该文件的`AclFileAttributeView`。

1.  为用户获取一个`UserPrincipal`对象。

1.  获取当前分配给文件的 ACL 条目列表。

1.  创建一个持有我们要添加的权限的新`AclEntry.Builder`对象。

1.  将权限添加到 ACL 列表中。

1.  使用`setAcl`方法用新的 ACL 列表替换当前的 ACL 列表。

## 操作步骤...

1.  使用以下`main`方法创建一个新的控制台应用程序。在这个方法中，我们将首先简单地显示文件`users.txt`的当前 ACL 列表，如下所示：

```java
public static void main(String[] args) throws Exception {
Path path = Paths.get("C:/home/docs/users.txt");
AclFileAttributeView view = Files.getFileAttributeView(path, AclFileAttributeView.class);
List<AclEntry> aclEntryList = view.getAcl();
displayAclEntries(aclEntryList);
}

```

1.  为了说明添加和删除 ACL 属性的过程，我们将使用一系列辅助方法：

+   `displayAclEntries:` 显示主体和条目类型，然后调用其他两个辅助方法

+   `displayEntryFlags:` 如果存在，显示条目标志

+   `displayPermissions:` 如果有的话，显示条目权限

1.  按照以下代码向应用程序添加方法：

```java
private static void displayAclEntries(List<AclEntry> aclEntryList) {
System.out.println("ACL Entry List size: " + aclEntryList.size());
for (AclEntry entry : aclEntryList) {
System.out.println("User Principal Name: " + entry.principal().getName());
System.out.println("ACL Entry Type: " + entry.type());
displayEntryFlags(entry.flags());
displayPermissions(entry.permissions());
System.out.println();
}
}
private static void displayPermissions(Set<AclEntryPermission> permissionSet) {
if (permissionSet.isEmpty()) {
System.out.println("No Permissions present");
}
else {
System.out.println("Permissions");
for (AclEntryPermission permission : permissionSet) {
System.out.print(permission.name() + " ");
}
System.out.println();
}
}
private static void displayEntryFlags(Set<AclEntryFlag> flagSet) {
if (flagSet.isEmpty()) {
System.out.println("No ACL Entry Flags present");
}
else {
System.out.println("ACL Entry Flags");
for (AclEntryFlag flag : flagSet) {
System.out.print(flag.name() + " ");
}
System.out.println();
}
}

```

1.  ACL 列表包含文件的 ACL 条目。当执行`displayAclEntries`方法时，它将方便地显示条目数量，然后每个条目将用空行分隔。以下是`users.txt`文件可能的列表：

所有者：Richard-PC\Richard

ACL 条目列表大小：4

用户主体名称：BUILTIN\Administrators

ACL 条目类型：允许

没有 ACL 条目标志

权限

读取数据 删除 读取命名属性 读取属性 写入所有者 删除子项 写入数据 追加数据 同步 执行 写入属性 写入 ACL 写入命名属性 读取 ACL

用户主体名称：NT AUTHORITY\SYSTEM

ACL 条目类型：允许

没有 ACL 条目标志

权限

读取数据 删除 读取命名属性 读取属性 写入所有者 删除子项 写入数据 追加数据 同步 执行 写入属性 写入 ACL 写入命名属性 读取 ACL

用户主体名称：BUILTIN\用户

ACL 条目类型：允许

没有 ACL 条目标志

权限

读取数据 同步 执行 读取命名属性 读取属性 读取 ACL

用户主体名称：NT AUTHORITY\已验证用户

ACL 条目类型：允许

没有 ACL 条目标志

权限

追加数据 读取数据 删除 同步 执行 读取命名属性 读取属性 写入属性 写入命名属性 读取 ACL 写入数据

1.  接下来，使用`UserPrincipalLookupService`类的`lookupService`方法返回`UserPrincipalLookupService`类的实例。使用它的`lookupPrincipalByName`方法根据用户名称返回一个`UserPrincipal`对象。在调用`displayAclEntries`方法之后添加以下代码：

```java
UserPrincipalLookupService lookupService = FileSystems.getDefault().getUserPrincipalLookupService();
UserPrincipal userPrincipal = lookupService.lookupPrincipalByName("users");

```

1.  接下来，添加以下代码来创建和设置一个`AclEntry.Builder`对象。这将用于为用户添加`WRITE_ACL 和 DELETE`权限。将条目添加到 ACL 列表，并使用`setAcl`方法将其附加到当前文件，如下所示：

```java
AclEntry.Builder builder = AclEntry.newBuilder();
builder.setType(AclEntryType.ALLOW);
builder.setPrincipal(userPrincipal);
builder.setPermissions(
AclEntryPermission.WRITE_ACL,
AclEntryPermission.DELETE);
AclEntry entry = builder.build();
aclEntryList.add(0, entry);
view.setAcl(aclEntryList);

```

1.  执行应用程序。为了修改文件的一些 ACL 属性，我们必须具有适当的权限。本章的介绍详细介绍了如何以管理员身份运行应用程序的细节。接下来，注释掉添加 ACL 条目的代码，并验证是否已添加 ACL 条目。您应该看到以下条目添加到列表中：

**ACL 条目列表大小：5**

**用户主体名称：BUILTIN\Users**

**ACL 条目类型：允许**

**没有 ACL 条目标志存在**

**权限**

**WRITE_ACL DELETE**

## 它是如何工作的...

在`main`方法中，我们创建了`Path`对象，然后使用它来获取`java.nio.file.attribute.AclFileAttributeView`接口的实例。`Path`对象表示的文件是`users.txt`文件。`AclFileAttributeView`对象可以用于多种目的。在这里，我们只对使用其`getAcl`方法返回与文件关联的 ACL 属性列表感兴趣。

我们只显示当前 ACL 的列表，以查看它们是什么，并最终验证文件的属性是否已更改。ACL 属性与用户关联。在这个例子中，我们创建了一个代表用户的`UserPrincipal`对象。

可以使用`java.nio.file.attribute.AclEntry.Builder`类的`build`方法创建新的 ACL 条目。静态的`newBuilder`方法创建了`AclEntry.Builder`类的一个实例。执行`setPrincipal`方法将用户设置为属性的主体。`setPermissions`方法接受一组`AclEntryPermission`对象或可变数量的`AclEntryPermission`对象。在这个例子中，我们使用了一个由逗号分隔的两个权限组成的列表：`AclEntryPermission.WRITE_ACL`和`AclEntryPermission.DELETE`。

然后将`AclEntry.Builder`对象添加到文件的现有 ACL 中。条目被添加到列表的开头。最后一步是使用`setAcl`方法用新的 ACL 列表替换旧的 ACL 列表。

## 还有更多...

要删除 ACL 属性，我们需要获取当前列表，然后确定要删除的属性的位置。我们可以使用`java.util.List`接口的`remove`方法来删除该项。然后可以使用`setAcl`方法用新列表替换旧列表。

ACL 属性在**RFC 3530: Network File System (NFS) version 4 Protocol**中有更详细的解释。以下表格提供了有关可用 ACL 权限的附加信息和见解。枚举`AclEntryType`具有以下值：

| 值 | 含义 |
| --- | --- |
| `ALARM` | 在尝试访问指定属性时，以系统特定的方式生成警报 |
| `ALLOW` | 授予权限 |
| `AUDIT` | 在尝试访问指定属性时，以系统相关的方式记录所请求的访问 |
| `DENY` | 拒绝访问 |

`AclEntryPermission`枚举值总结如下表所示：

| 值 | 含义 |
| --- | --- |
| `APPEND_DATA` | 能够向文件追加数据 |
| `DELETE` | 能够删除文件 |
| `DELETE_CHILD` | 能够删除目录中的文件或目录 |
| `EXECUTE` | 能够执行文件 |
| `READ_ACL` | 能够读取 ACL 属性 |
| `READ_ATTRIBUTES` | 能够读取（非 ACL）文件属性 |
| `READ_DATA` | 能够读取文件的数据 |
| `READ_NAMED_ATTRS` | 能够读取文件的命名属性 |
| `SYNCHRONIZE` | 能够在服务器上本地访问文件，进行同步读写 |
| `WRITE_ACL` | 能够写入 ACL 属性 |
| `WRITE_ATTRIBUTES` | 能够写入（非 ACL）文件属性 |
| `WRITE_DATA` | 能够修改文件的数据 |
| `WRITE_NAMED_ATTRS` | 能够写入文件的命名属性 |
| `WRITE_OWNER` | 能够更改所有者 |

`AclEntryFlag`枚举适用于目录条目。总结为四个值如下：

| 值 | 含义 |
| --- | --- |
| `DIRECTORY_INHERIT` | ACL 条目应添加到每个新创建的目录 |
| `FILE_INHERIT` | ACL 条目应添加到每个新创建的非目录文件 |
| `INHERIT_ONLY` | ACL 条目应添加到每个新创建的文件或目录 |
| `NO_PROPAGATE_INHERIT` | ACL 条目不应放置在新创建的目录上，该目录可被创建目录的子目录继承 |

目前，`AclEntryType.AUDIT`或`AclEntryType.ALARM`没有与之关联的标志。

# 管理 POSIX 属性

可用的 POSIX 属性包括组所有者、用户所有者和一组权限。在本示例中，我们将研究如何维护这些属性。管理这些属性使得开发应用程序在多个操作系统上执行更加容易。虽然属性的数量有限，但对于许多应用程序来说可能已经足够了。

有三种方法可以用来管理 POSIX 属性：

+   `java.nio.file.attribute.PosixFileAttributeView`接口

+   `Files`类的设置/获取 POSIX 文件权限方法

+   `Files`类的`setAttribute`方法

使用`PosixFileAttributeView`接口获取`PosixFileAttributes`对象的方法在第三章的*使用 PosixFileAttributeView 维护 POSIX 文件属性*中有详细说明。在这里，我们将首先说明如何使用`PosixFileAttributeView`接口方法，并在本示例的*还有更多..*部分演示最后两种方法。

## 准备工作

要维护文件的 POSIX 权限属性，我们需要：

1.  创建一个表示感兴趣的文件或目录的`Path`对象。

1.  获取该文件的`PosixFileAttributes`对象。

1.  使用`permissions`方法获取该文件的一组权限。

1.  修改权限集。

1.  使用`setPermissions`方法替换权限。

## 如何做...

1.  我们将创建一个应用程序，获取`PosixFileAttributes`对象并使用它来显示`users.txt`文件的当前权限集，然后向文件添加`PosixFilePermission.OTHERS_WRITE`权限。创建一个新的控制台应用程序，并添加以下`main`方法：

```java
public static void main(String[] args) throws Exception {
Path path = Paths.get("home/docs/users.txt");
FileSystem fileSystem = path.getFileSystem();
PosixFileAttributeView view = Files.getFileAttributeView(path, PosixFileAttributeView.class);
PosixFileAttributes attributes = view.readAttributes();
Set<PosixFilePermission> permissions = attributes.permissions();
listPermissions(permissions);
permissions.add(PosixFilePermission.OTHERS_WRITE);
view.setPermissions(permissions);
System.out.println();
listPermissions(permissions);
}
private static void listPermissions(Set<PosixFilePermission> permissions) {
System.out.print("Permissions: ");
for (PosixFilePermission permission : permissions) {
System.out.print(permission.name() + " ");
}
System.out.println();
}

```

1.  在支持 POSIX 的系统上执行应用程序。在**Ubuntu 11.04**下执行时，应该会得到类似以下的结果：

**权限：GROUP_READ OWNER_WRITE OTHERS_READ OWNER_READ**

**权限：GROUP_READ OWNER_WRITE OTHERS_WRITE OTHERS_READ OWNER_READ**

## 它是如何工作的...

在`main`方法中，我们获取了`users.txt`文件的`Path`，然后使用`getFileAttributeView`方法获取了`PosixFileAttributeView`的实例。然后使用`readAttributes`方法获取了表示文件 POSIX 属性的`PosixFileAttributes`对象的实例。

使用`listPermissions`方法列出文件的权限。在添加新权限到文件之前和之后各执行一次此方法。我们这样做只是为了显示权限的变化。

使用`add`方法将`PosixFilePermission.OTHERS_WRITE`权限添加到权限集中。以下表列出了`PosixFilePermission`枚举值：

| 值 | 级别 | 授予权限 |
| --- | --- | --- |
| `GROUP_EXECUTE` | 组 | 执行和搜索 |
| `GROUP_READ` |   | 读取 |
| `GROUP_WRITE` |   | 写入 |
| `OTHERS_EXECUTE` | 其他人 | 执行和搜索 |
| `OTHERS_READ` |   | 读取 |
| `OTHERS_WRITE` |   | 写入 |
| `OWNER_EXECUTE` | 拥有者 | 执行和搜索 |
| `OWNER_READ` |   | 读取 |
| `OWNER_WRITE` |   | 写入 |

在这个例子中，我们添加了一个`PosixFilePermission.OTHERS_WRITE`权限。在下一节中，我们将说明如何删除权限。

## 还有更多...

还有其他几个感兴趣的操作，包括：

+   删除文件权限

+   修改文件的 POSIX 所有权

+   使用`Files`类的`set/get` POSIX 文件权限方法

+   使用`Files`类的`setAttribute`方法

+   使用`PosixFilePermissions`类创建`PosixFilePermissions`

### 删除文件权限

删除权限只是一个简单的事情：

+   获取文件的一组权限

+   使用`Set`接口的`remove`方法来删除权限

+   将集合重新分配给文件

这在以下代码序列中有所体现，其中删除了`PosixFilePermission.OTHERS_WRITE`权限：

```java
Set<PosixFilePermission> permissions = attributes.permissions();
Permissions.remove(PosixFilePermission.OTHERS_WRITE);
view.setPermissions(permissions);

```

### 修改文件的 POSIX 所有权

POSIX 所有者在组和用户级别指定。`PosixFileAttributes`方法的组和所有者将返回表示文件的组和用户所有者的对象。`setGroup`和`setOwner`方法将设置相应的成员资格。

在接下来的示例中，将显示`users.txt`文件的所有者，然后进行更改。创建`UserPrincipal`对象以支持`set`方法：

```java
Path path = Paths.get("home/docs/users.txt");
try {
FileSystem fileSystem = path.getFileSystem();
PosixFileAttributeView view = Files.getFileAttributeView(path, PosixFileAttributeView.class);
PosixFileAttributes attributes = view.readAttributes();
Set<PosixFilePermission> permissions = attributes.permissions();
System.out.println("Old Group: " + attributes.group().getName());
System.out.println("Old Owner: " + attributes.owner().getName());
System.out.println();
UserPrincipalLookupService lookupService = FileSystems.getDefault().getUserPrincipalLookupService();
UserPrincipal userPrincipal = lookupService.lookupPrincipalByName("jennifer");
GroupPrincipal groupPrincipal = lookupService.lookupPrincipalByGroupName(("jennifer");
view.setGroup(groupPrincipal);
view.setOwner(userPrincipal);
attributes = view.readAttributes();
System.out.println("New Group: " + attributes.group().getName());
System.out.println("New Owner: " + attributes.owner().getName());
System.out.println();
POSIX attributesfile permission, removing}
catch (IOException ex) {
ex.printStackTrace();
}

```

执行时，输出应如下所示：

**为 users.txt 设置所有者**

**旧组：richard**

**旧所有者：richard**

**新组：jennifer**

**新所有者：jennifer**

您可能需要以管理员身份执行代码，详细信息请参见介绍。

### 使用 Files 类的 set/get POSIX 文件权限方法

此方法使用`Files`类的`setPosixFilePermissions`和`getPosixFilePermissions`方法。`getPosixFilePermissions`方法返回指定其第一个参数的文件的`PosixFilePermissions`集合。它的第二个参数是`LinkOption`，用于确定如何处理符号链接文件。通常不会跟随链接，除非使用`LinkOption.NOFOLLOW_LINKS`。我们可以使用以下代码序列列出与文件关联的权限：

```java
Path path = Paths.get("home/docs/users.txt");
try {
Set<PosixFilePermission> permissions = Files.getPosixFilePermissions(path);
System.out.print("Permissions: ");
for (PosixFilePermission permission : permissions) {
System.out.print(permission.name() + " ");
}
System.out.println();
}
catch (IOException ex) {
ex.printStackTrace();
}

```

`setPermissions`方法接受表示文件的`Path`对象和一组`PosixFilePermission`。而不是使用以前的方法：

```java
view.setPermissions(path, permissions);

```

我们可以使用`Files`类的`setPosixFilePermissions`方法：

```java
Files.setPosixFilePermissions(path, permissions);

```

使用`Files`类简化了该过程，避免了创建`PosixFileAttributes`对象。

### 使用 Files 类的 setAttribute 方法

`Files`类的`getAttribute`方法在第三章中详细介绍了*使用 getAttribute 方法逐个获取属性*配方。`setAttribute`方法将设置一个属性，并具有以下四个参数：

+   表示文件的`Path`对象

+   包含要设置的属性的`String`

+   表示属性值的对象

+   指定符号链接的可选`LinkOption`值

以下说明了向`users.txt`文件添加`PosixFilePermission.OTHERS_WRITE`权限：

```java
Path path = Paths.get("home/docs/users.txt");
try {
Files.setAttribute(path, "posix:permission, PosixFilePermission.OTHERS_WRITE);
}
catch (IOException ex) {
ex.printStackTrace();
}

```

在此示例中未使用`LinkOption`值。

### 使用 PosixFilePermissions 类创建 PosixFilePermissions

`PosixFilePermissions`类拥有三种方法：

+   `asFileAttribute`，返回一个包含一组`PosixFilePermissions`的`FileAttribute`对象

+   `fromString`，也返回一个基于`String`参数的`PosixFilePermissions`集合

+   `toString`，执行`fromString`方法的逆操作

所有三种方法都是静态的。第一种方法返回一个`FileAttribute`对象，可以与*创建文件和目录*配方中讨论的`createFile`或`createDirectory`方法一起使用。

在 Unix 系统上，文件权限经常表示为一个九个字符的字符串。这个字符串分为三个字符组。第一组表示用户的权限，第二组表示组的权限，最后一组表示其他所有人的权限。这三个字符组中的每一个表示为该组授予的读、写或执行权限。在第一个位置的`r`表示读权限，第二个位置的`w`表示写权限，最后一个位置的`x`表示执行权限。在任何这些位置上的`-`表示权限未设置。

为了说明这些方法，执行以下代码序列：

```java
Path path = Paths.get("home/docs/users.txt");
try {
FileSystem fileSystem = path.getFileSystem();
PosixFileAttributeView view = Files.getFileAttributeView(path, PosixFileAttributeView.class);
PosixFileAttributes attributes = view.readAttributes();
Set<PosixFilePermission> permissions = attributes.permissions();
for(PosixFilePermission permission : permissions) {
System.out.print(permission.toString() + ' ');
}
System.out.println();
FileAttribute<Set<PosixFilePermission>> fileAttributes = PosixFilePermissions.asFileAttribute(permissions);
Set<PosixFilePermission> fileAttributeSet = fileAttributes.value();
for (PosixFilePermission posixFilePermission : fileAttributeSet) {
System.out.print(posixFilePermission.toString() + ' ');
}
System.out.println();
System.out.println(PosixFilePermissions.toString(permissions));
permissions = PosixFilePermissions.fromString("rw-rw-r--");
for(PosixFilePermission permission : permissions) {
System.out.print(permission.toString() + ' ');
}
System.out.println();
}
catch (IOException ex) {
}

```

你的输出应该类似于以下内容：

**OTHERS_READ OWNER_READ GROUP_READ OWNER_WRITE**

**OTHERS_READ OWNER_READ OWNER_WRITE GROUP_READ**

**rw-r--r--**

**OWNER_READ OWNER_WRITE GROUP_READ GROUP_WRITE OTHERS_READ**

代码的第一部分获取了`users.txt`文件的权限集，就像在本食谱中早些时候详细介绍的那样。然后显示了权限。接下来，执行了`asFileAttribute`方法，返回了文件的`FileAttribute`。使用`value`方法获取了一组属性，然后显示了这些属性。两组权限被显示，但顺序不同。

接下来，使用`toString`方法将这组权限显示为字符串。注意每个字符反映了对`users.txt`文件授予的权限。

最后的代码段使用`fromString`方法创建了一个新的权限集。然后显示这些权限以验证转换。

# 移动文件和目录

移动文件或目录在重新组织用户空间结构时非常有用。这个操作由`Files`类的`move`方法支持。在移动文件或目录时，有几个因素需要考虑。这些包括符号链接文件是否存在，`move`是否应该替换现有文件，以及移动是否应该是原子的。

如果移动发生在相同的文件存储上，移动可能会导致资源的重命名。使用这个方法有时会使用`Path`接口的`resolveSibling`方法。这个方法将用它的参数替换路径的最后一部分。这在重命名文件时很有用。`resolveSibling`方法在第二章的*使用路径解析合并路径*食谱的*还有更多..*部分中有详细介绍。

## 做好准备

为了移动文件或目录：

1.  获取一个`Path`对象，表示要移动的文件或目录。

1.  获取一个`Path`对象，表示移动的目的地。

1.  确定复制选项以控制移动。

1.  执行`move`方法。

## 操作步骤...

1.  使用以下`main`方法创建一个新的控制台应用程序。我们将把`users.txt`文件移动到`music`目录：

```java
public static void main(String[] args) throws Exception {
Path sourceFile = Paths.get("C:/home/docs/users.txt");
Path destinationFile = Paths.get ("C:/home/music/users.txt");
Files.move(sourceFile, destinationFile);
}

```

1.  执行应用程序。检查`docs`和`music`目录的内容。`users.txt`文件应该不在`docs`目录中，但在`music`目录中。

## 工作原理...

`move`方法使用这两个`Path`对象，并且没有使用第三个可选参数。这个参数用于确定复制操作的工作方式。当它没有被使用时，文件复制操作默认为简单复制。

`StandardCopyOption`枚举实现了`CopyOption`接口，并定义了支持的复制操作类型。`CopyOption`接口与`Files`类的`copy`和`move`方法一起使用。下表列出了这些选项。这些选项在*还有更多..*部分中有更详细的解释：

| 值 | 含义 |
| --- | --- |
| `ATOMIC_MOVE` | 移动操作是原子的 |
| `COPY_ATTRIBUTES` | 源文件属性被复制到新文件 |
| `REPLACE_EXISTING` | 如果目标文件存在，则替换目标文件 |

如果目标文件已经存在，则会抛出`FileAlreadyExistsException`异常。但是，如果`CopyOption.REPLACE_EXISTING`作为`move`方法的第三个参数使用，则不会抛出异常。当源是符号链接时，将复制链接而不是链接的目标。

## 还有更多...

有几个需要涵盖的变化和问题。这些包括：

+   移动方法的琐碎用法

+   标准复制选项枚举值的含义

+   使用`resolveSibling`方法与`move`方法影响重命名操作

+   移动目录

### 移动方法的琐碎用法

如果源文件和目标文件相同，则该方法不会产生任何效果。以下代码序列将不会产生任何效果：

```java
Path sourceFile = ...;
Files.move(sourceFile, sourceFile);

```

不会抛出异常，文件也不会被移动。

### 标准复制选项枚举值的含义

标准复制选项枚举值需要更多的解释。`StandardCopyOption.REPLACE_EXISTING`的值将替换已存在的文件。如果文件是符号链接，则只替换符号链接文件，而不是其目标。

`StandardCopyOption.COPY_ATTRIBUTES`的值将复制文件的所有属性。`StandardCopyOption.ATOMIC_MOVE`的值指定移动操作要以原子方式执行。所有其他枚举值都将被忽略。但是，如果目标文件已经存在，则要么替换文件，要么抛出`IOException`。结果取决于实现。如果无法以原子方式执行移动操作，则会抛出`AtomicMoveNotSupportedException`。原子移动可能由于源文件和目标文件的文件存储器的差异而失败。

如果在 Windows 7 上执行以下代码序列：

```java
Path sourceFile = Paths.get("C:/home/docs/users.txt");
Path destinationFile = Paths.get("C:/home/music/users. txt");
Files.move(sourceFile, destinationFile, StandardCopyOption.ATOMIC_MOVE);

```

如果目标文件已经存在，则会抛出`AccessDeniedException`异常。如果文件不存在，其执行将导致以下错误消息：

**java.nio.file.AtomicMoveNotSupportedException: C:\home\docs\users.txt -> E:\home\music\users.txt: 系统无法将文件移动到不同的磁盘驱动器**

### 使用`resolveSibling`方法与`move`方法影响重命名操作

`resolveSibling`方法将用不同的字符串替换路径的最后一部分。这可以用于在使用`move`方法时影响重命名操作。在以下序列中，`users.txt`文件被有效地重命名：

```java
Path sourceFile = Paths.get("C:/home/docs/users.txt");
Files.move(sourceFile, sourceFile.resolveSibling(sourceFile.getFileName()+".bak"));

```

文件已重命名为`users.txt.bak`。请注意，源文件路径被使用了两次。要重命名文件并替换其扩展名，可以使用显式名称，如下所示：

```java
Files.move(sourceFile, sourceFile.resolveSibling("users.bak"));

```

更复杂的方法可能使用以下序列：

```java
Path sourceFile = Paths.get("C:/home/docs/users.txt");
String newFileName = sourceFile.getFileName().toString();
newFileName = newFileName.substring(0, newFileName.indexOf('.')) + ".bak";
Files.move(sourceFile, sourceFile.resolveSibling(newFileName));

```

`substring`方法返回一个以第一个字符开头，以紧接着句号之前的字符结尾的新文件名。

### 移动目录

当在同一文件存储器上移动目录时，目录和子目录也会被移动。以下将把`docs`目录、其文件和子目录移动到`music`目录中：

```java
Path sourceFile = Paths.get("C:/home/docs");
Path destinationFile = Paths.get("C:/home/music/docs");
Files.move(sourceFile, destinationFile);

```

然而，执行此代码序列，其中`docs`目录将被移动到`E`驱动器上类似的文件结构，将导致`DirectoryNotEmptyException`异常：

```java
Path sourceFile = Paths.get("C:/home/docs");
Path destinationFile = Paths.get("E:/home/music/docs");
Files.move(sourceFile, destinationFile);

```

在不同文件存储器之间移动目录将导致异常，如果目录不为空。如果在前面的例子中`docs`目录是空的，`move`方法将成功执行。如果需要在不同文件存储器之间移动非空目录，通常需要进行复制操作，然后进行删除操作。

# 删除文件或目录

删除文件或目录当它们不再需要时是一个常见的操作。它将节省系统空间并导致更干净的文件系统。`Files`类有两种方法可以用来删除文件或目录：`delete`和`deleteIfExists`。它们都以`Path`对象作为参数，并可能抛出`IOException`。

## 准备工作

要删除文件或目录，需要执行以下操作：

1.  获取一个代表文件或目录的`Path`对象。

1.  使用`delete`或`deleteIfExists`方法来删除元素。

## 如何做...

1.  创建一个新的控制台应用程序，并使用以下`main`方法：

```java
public static void main(String[] args) throws Exception {
Path sourceFile = Paths.get("C:/home/docs/users.txt");
Files.delete(sourceFile);
}

```

1.  执行应用程序。如果`users.txt`文件在程序运行时存在于目录中，那么在程序执行后它就不应该存在。如果文件不存在，那么你的程序输出应该类似于以下内容：

**java.nio.file.NoSuchFileException: C:\home\docs\users.txt**

## 它是如何工作的...

这种方法很简单。我们创建了一个代表`users.txt`方法的`Path`对象。然后我们将它作为`delete`方法的参数。由于`delete`方法可能会抛出`IOException`，所以代码被包含在 try-catch 块中。

为了避免如果文件不存在会抛出异常，我们可以使用`deleteIfExists`方法。用以下内容替换`delete`方法的调用：

```java
Files.deleteIfExists(sourceFile);

```

确保文件不存在，然后执行此代码。程序应该正常终止，不会抛出任何异常。

## 还有更多...

如果我们尝试删除一个目录，那么该目录必须首先为空。如果目录不为空，则会抛出`DirectoryNotEmptyException`异常。执行以下代码序列来代替前面的示例：

```java
Path sourceFile = Paths.get("C:/home/docs");
Files.delete(sourceFile);

```

假设`docs`目录不为空，应用程序应该抛出`DirectoryNotEmptyException`异常。

空目录的定义取决于文件系统的实现。在一些系统中，如果目录只包含特殊文件或符号链接，该目录可能被认为是空的。

如果一个目录不为空并且需要被删除，那么需要首先使用`walkFileTree`方法删除它的条目，就像在第五章的*使用 SimpleFileVisitor 类遍历文件系统*中所示的那样，*管理文件系统*。

### 注意

如果要删除的文件是一个符号链接，只有链接被删除，而不是链接的目标。此外，如果文件被其他应用程序打开或正在使用中，可能无法删除文件。

# 管理符号链接

符号链接是文件，它们不是真正的文件，而是指向真正文件的链接，通常称为目标文件。当希望一个文件出现在多个目录中而不必实际复制文件时，这些链接是有用的。这样可以节省空间，并且所有更新都被隔离到一个单独的文件中。

`Files`类具有以下三种方法来处理符号链接：

+   `createSymbolicLink`方法，用于创建到可能不存在的目标文件的符号链接

+   `createLink`方法创建一个到现有文件的硬链接

+   `readSymbolicLink`检索到目标文件的`Path`

链接通常对文件的用户是透明的。对符号链接的任何访问都会被重定向到引用的文件。硬链接类似于符号链接，但有更多的限制。这些类型的链接在本食谱的*还有更多..*部分中有更详细的讨论。

## 准备工作

为了创建一个符号链接到一个文件：

1.  获取一个代表链接的`Path`对象。

1.  获取一个代表目标文件的`Path`对象。

1.  将这些路径作为`createSymbolicLink`方法的参数。

## 如何做...

1.  创建一个新的控制台应用程序。将以下`main`方法添加到应用程序中。在这个应用程序中，我们将在`music`目录中创建一个符号链接，指向`docs`目录中的实际`users.txt`文件。

```java
public static void main(String[] args) throws Exception {
Path targetFile = Paths.get("C:/home/docs/users.txt");
Path linkFile = Paths.get("C:/home/music/users.txt");
Files.createSymbolicLink(linkFile, targetFile);
}

```

1.  执行应用程序。如果应用程序没有足够的权限，那么将抛出异常。在 Windows 7 上执行时的示例如下：

**java.nio.file.FileSystemException: C:\home\music\users.txt: A required privilege is not held by the client.**

1.  验证`music`目录中是否存在一个名为`users.txt`的新文件。检查文件的属性，以验证它是否是一个符号链接。在 Windows 7 上，右键单击文件名，然后选择**属性**。接下来，选择**快捷方式**选项卡。它应该显示如下截图所示：

![操作步骤...](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/java7-new-feat-cb/img/5627_04_01.jpg)

注意指定的目标是`docs`目录中的`users.txt`文件。

## 它是如何工作的...

我们创建了两个`Path`对象。第一个代表`docs`目录中的目标文件。第二个代表要在`music`目录中创建的链接文件。接下来，我们使用`createSymbolicLink`方法来实际创建符号链接。整个代码序列被包含在 try 块中，以捕获可能抛出的任何`IOExceptions`。

`createSymbolicLink`方法的第三个参数可以是一个或多个`FileAttribute`值。这些值用于在创建链接文件时设置其属性。然而，目前它还没有得到完全支持。未来的 Java 版本将增强这一功能。`FileAttribute`可以按照*还有更多..*部分中*管理 POSIX 文件权限*配方中的详细说明来创建。

## 还有更多...

在这里，我们将更仔细地研究以下问题：

+   创建硬链接

+   创建对目录的符号链接

+   确定链接文件的目标

### 创建硬链接

与符号链接相比，硬链接有更多的限制。这些限制包括以下内容：

+   目标必须存在。如果不存在，就会抛出异常。

+   不能对目录创建硬链接。

+   硬链接只能在单个文件系统内建立。

硬链接的行为就像普通文件。文件没有明显的属性表明它是一个链接文件，而不是一个具有快捷方式选项卡的符号链接文件。硬链接的所有属性与目标文件的属性相同。

硬链接不像软链接那样经常使用。`Path`类的方法可以处理硬链接，不需要任何特殊考虑。使用`createLink`方法创建硬链接。它接受两个参数：链接文件的`Path`对象和目标文件的`Path`对象。在下面的示例中，我们在`music`目录中创建了一个硬链接，而不是一个符号链接：

```java
try {
Path targetFile = Paths.get("C:/home/docs/users.txt");
Path linkFile = Paths.get("C:/home/music/users.txt");
Files.createLink(linkFile, targetFile);
}
catch (IOException ex) {
ex.printStackTrace();
}

```

执行应用程序。如果您检查链接文件的属性，您会发现它不显示为符号链接。但是，修改任一文件的内容将导致另一个文件也被修改。它们实际上是一样的。

### 创建对目录的符号链接

创建对目录的符号链接使用与文件相同的方法。在下面的示例中，创建了一个新目录`tmp`，它是`docs`目录的符号链接：

```java
try {
Path targetFile = Paths.get("C:/home/docs");
Path linkFile = Paths.get("C:/home/tmp");
Files.createSymbolicLink(linkFile, targetFile);
}
catch (IOException ex) {
ex.printStackTrace();
}

```

`tmp`目录中的所有文件实际上都是指向`docs`目录中相应文件的符号链接。

### 确定链接文件的目标

`isSymbolicLink`方法，如第二章 *使用路径定位文件和目录*中*管理符号链接*配方中所讨论的，用于确定文件是否是符号链接。`readSymbolicLink`方法接受一个代表链接文件的`Path`对象，并返回一个代表链接目标的`Path`对象。

以下代码序列说明了这一点，在`music`目录中的`users.txt`文件是一个符号链接：

```java
try {
Path targetFile = Paths.get("C:/home/docs/users.txt");
Path linkFile = Paths.get("C:/home/music/users.txt");
System.out.println("Target file is: " + Files.readSymbolicLink(linkFile));
}
catch (IOException ex) {
ex.printStackTrace();
}

```

然而，如果`users.txt`链接文件是一个硬链接，就像使用`createLink`方法创建的那样，当执行代码时会得到以下异常：

**java.nio.file.NotLinkException: 文件或目录不是一个重解析点**。

### 注意

重解析点是一个**NTFS**文件系统对象，它将特定数据与文件或目录关联起来。文件系统过滤器可以与重解析点类型关联。当文件系统打开文件时，它将传递这些信息给文件系统过滤器进行处理。这种方法是扩展文件系统功能的一种方式。
