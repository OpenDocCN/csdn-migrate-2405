# Java7 新特性秘籍（三）

> 原文：[`zh.annas-archive.org/md5/5FB42CDAFBC18FB5D8DD681ECE2B0206`](https://zh.annas-archive.org/md5/5FB42CDAFBC18FB5D8DD681ECE2B0206)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第五章：管理文件系统

在本章中，我们将涵盖以下内容：

+   获取 FileStore 信息

+   获取 FileSystem 信息

+   使用 SimpleFileVisitor 类遍历文件系统

+   使用 SimpleFileVisitor 类删除目录

+   使用 SimpleFileVisitor 类复制目录

+   使用 DirectoryStream 接口处理目录的内容，如*使用 globbing 过滤目录*教程中所述

+   编写自己的目录过滤器

+   使用 WatchEvents 监视文件事件

+   理解 ZIP 文件系统提供程序

# 介绍

**文件系统**是一个或多个顶级根目录，包含文件层次结构。文件系统由文件存储支持，该文件存储是文件存储的提供者。本章涉及获取有关这些实体和典型文件系统任务的信息，例如确定目录的内容或监视文件系统事件。

文件存储表示存储单元。例如，它可能表示设备，比如`C`驱动器，驱动器的分区或卷。`java.nio.file.FileStore`类支持文件存储，并提供了几种方法。*获取 FileStore 信息*教程介绍了如何获取有关特定文件存储的基本信息。

文件系统支持访问目录和文件的层次结构。它在 Java 7 中用`java.nio.file.FileSystem`类表示。获取有关文件系统的一般信息在*获取 FileSystem 信息*教程中介绍。这包括如何获取文件系统的根目录列表和底层文件存储。

遍历目录层次结构对许多应用程序很有用。*使用 SimpleFileVisitor 类遍历文件系统*教程详细介绍了基本方法。这种方法在*使用 SimpleFileVisitor 类删除目录*和*使用 SimpleFileVisitor 类复制目录*教程中使用。

当操作限制在单个目录时，`java.nio.file.DirectoryStream`接口提供了一种方便的技术，用于将目录中的每个元素作为`java.nio.file.Path`对象进行检查。使用 for each 循环处理这些路径非常容易。这种方法在*使用 DirectoryStream 接口处理目录的内容*教程中探讨。

有时我们不需要整个目录的内容，而是需要其元素的子集。Java 7 提供了几种过滤目录内容的方法，如*使用 globbing 过滤目录*和*编写自己的目录过滤器*教程中所述。**Globbing**是一种类似于正则表达式但更容易使用的模式匹配技术。

在*使用 WatchEvents 监视文件事件*教程中，我们了解到 Java 7 支持通过外部进程检测目录中文件的创建、修改和删除。当需要知道对目录进行更改时，这可能非常有用。

使用 Java 7，现在可以将 ZIP 文件的内容视为文件系统。这使得更容易管理 ZIP 文件的内容并操作 ZIP 文件中包含的文件。这种技术在*理解 zip 文件系统提供程序*教程中进行了演示。

# 获取 FileStore 信息

每个文件系统都支持文件存储机制。这可能是一个设备，比如`C`驱动器，一个驱动器的分区，一个卷，或者其他组织文件系统空间的方式。`java.nio.file.FileStore`类代表其中一个存储分区。本教程详细介绍了获取有关文件存储的信息的方法。

## 准备工作

要获取并使用`FileStore`对象：

1.  获取正在使用的`java.nio.file.FileSystem`的实例。

1.  使用`FileSystem`类的`getFileStores`方法返回可用的文件存储。

## 如何做…

1.  创建一个新的控制台应用程序。在`main`方法中，我们将使用`FileStore`类的几种方法来演示该类提供的支持。让我们从添加`main`方法的第一部分开始，其中我们显示初始标题并获取一个`FileSystem`对象。还定义一个名为`kiloByte`的`long`变量：

```java
static final long kiloByte = 1024;
public static void main(String[] args) throws IOException {
String format = "%-16s %-20s %-8s %-8s %12s %12s %12s\n";
System.out.printf(format,"Name", "Filesystem", "Type",
"Readonly", "Size(KB)", "Used(KB)",
"Available(KB)");
FileSystem fileSystem = FileSystems.getDefault();
}

```

1.  接下来，我们需要使用`getFileStores`方法检索可用的文件存储，并显示它们。在代码块的第一部分中，我们使用了几个`FileStore`方法来获取相关信息。在最后一部分，我们按以下方式显示信息：

```java
for (FileStore fileStore : fileSystem.getFileStores()) {
try {
long totalSpace = fileStore.getTotalSpace() / kiloByte;
long usedSpace = (fileStore.getTotalSpace() -
fileStore.getUnallocatedSpace()) / kiloByte;
long usableSpace = fileStore.getUsableSpace() / kiloByte;
String name = fileStore.name();
String type = fileStore.type();
boolean readOnly = fileStore.isReadOnly();
NumberFormat numberFormat = NumberFormat.getInstance();
System.out.printf(format,
name, fileStore, type, readOnly,
numberFormat.format(totalSpace),
numberFormat.format(usedSpace),
numberFormat.format(usableSpace));
}
catch (IOException ex) {
ex.printStackTrace();
}
}

```

1.  执行应用程序。您的输出将与以下内容不同，但应反映系统上的驱动器：

**名称 文件系统类型 只读 大小（KB）已用（KB）可用（KB）**

**HP HP (C:) NTFS false 301,531,984 163,041,420 138,490,564**

**FACTORY_IMAGE FACTORY_IMAGE (D:) NTFS false 11,036,652 9,488,108 1,548,544**

**HP_PAVILION HP_PAVILION (E:) NTFS false 312,568,640 66,489,184 246,079,456**

**TOSHIBA TOSHIBA (H:) FAT32 false 15,618,080 3,160,768 12,457,312**

## 工作原理...

创建了一个格式化字符串，以简化文件存储信息的显示。此字符串在两个`printf`方法中都使用。两次使用相同的字符串可以确保输出的一致间距。使用此字符串显示了一个简单的标题。

使用`FileSystems`类的`getDefault`方法获取了一个`FileSystem`对象。对该对象执行`getFileStores`方法以获取`FileStore`对象的列表。

在循环中，使用 try 块捕获可能抛出的异常。按照下表详细说明的方式调用了几个方法。创建了`NumberFormat`类的实例以格式化文件存储大小信息。最后的`printf`方法显示了每个文件存储的文件存储信息：

| 方法 | 含义 |
| --- | --- |
| `getTotalSpace` | 文件存储中可用的总空间（以字节为单位） |
| `getUnallocatedSpace` | 未分配的字节数 |
| `getUsableSpace` | JVM 可用的可用字节数 |
| `name` | 表示文件存储名称的特定于实现的字符串 |
| `type` | 表示文件存储类型的特定于实现的字符串 |
| `isReadOnly` | 如果方法返回`true`，则尝试创建文件或打开文件进行写入将导致抛出`IOException` |

`getUnallocatedSpace`或`getUsableSpace`方法返回的值可能会在外部操作使用或释放文件存储空间时发生变化。

## 另请参阅

使用两种`supportsFileAttributeView`方法之一来确定`FileStore`支持的属性视图。这些方法在第三章的*确定操作系统对属性视图的支持*食谱的*还有更多..*部分中进行了说明，*获取文件和目录信息*。

# 获取文件系统信息

文件系统由一系列目录和文件组成。通常有一些关于文件系统的有限信息是有用的。例如，我们可能想知道文件系统是否为只读，或者提供者是谁。在本示例中，我们将研究用于检索文件系统属性的可用方法。

## 准备就绪

要访问文件系统的方法，我们需要：

1.  获取对`java.nio.file.FileSystem`对象的引用。

1.  使用此对象的方法来访问文件系统信息。

## 如何做...

1.  创建一个新的控制台应用程序。将以下代码添加到应用程序的`main`方法中。此序列显示了几个`fileSystem`属性，包括文件系统提供程序、文件打开状态、文件是否可读写、根目录和文件存储的名称：

```java
FileSystem fileSystem = FileSystems.getDefault();
FileSystemProvider provider = fileSystem.provider();
System.out.println("Provider: " + provider.toString());
System.out.println("Open: " + fileSystem.isOpen());
System.out.println("Read Only: " + fileSystem.isReadOnly());
Iterable<Path> rootDirectories = fileSystem.getRootDirectories();
System.out.println();
System.out.println("Root Directories");
for (Path path : rootDirectories) {
System.out.println(path);
}
Iterable<FileStore> fileStores = fileSystem.getFileStores();
System.out.println();
System.out.println("File Stores");
for (FileStore fileStore : fileStores) {
System.out.println(fileStore.name());
}

```

1.  执行应用程序。您的输出将取决于系统的配置。但是，它应该与以下输出类似：

**提供程序：sun.nio.fs.WindowsFileSystemProvider@7b60e796**

**打开：true**

**只读：false**

**根目录**

**C:\**

**D:\**

**E:\**

**F:\**

**G:\**

**H:\**

**I:\**

**J:\**

**K:\**

**L:\**

**文件存储**

**HP**

**FACTORY_IMAGE**

**HP_PAVILION**

**TOSHIBA**

## 工作原理...

`getDefault`方法返回 JVM 使用的默认文件系统。接下来，针对此对象执行了几种方法：

+   `provider`方法返回提供程序，即文件系统的实现者。在这种情况下，它是与 JVM 捆绑在一起的 Windows 文件系统提供程序。

+   `isOpen`方法指示文件系统已打开并准备就绪。

+   `isReadOnly`方法返回`false`，这意味着我们可以读写系统。

+   我们使用`getRootDirectories`方法创建了一个`Iterable`对象，允许我们列出每个根目录。

+   `getFileStores`方法返回另一个`Iterable`对象，用于显示文件存储的名称。

## 还有...

虽然我们通常不需要关闭文件系统，但是`close`方法可以用于关闭文件系统。对文件系统执行的任何后续方法都将导致抛出`ClosedFileSystemException`。与文件系统关联的任何打开通道、目录流和监视服务也将被关闭。请注意，默认文件系统无法关闭。

`FileSystems`类的`getFileSystem`方法可用于访问特定的文件系统。此外，重载的`newFileSystem`方法将创建新的文件系统。`close`方法可以用于这些实例。

文件系统是线程安全的。但是，如果一个线程尝试关闭文件系统，而另一个线程正在访问`filesystem`对象，关闭操作可能会被阻塞。

直到访问完成。

# 使用`SimpleFileVisitor`类来遍历文件系统

在处理目录系统时，常见的需求是遍历文件系统，检查文件层次结构中的每个子目录。使用`java.nio.file.SimpleFileVisitor`类可以轻松完成这项任务。该类实现了在访问目录之前和之后执行的方法。此外，对于在目录中访问每个文件实例以及发生异常的情况，还会调用回调方法。

`SimpleFileVisitor`类或派生类与`java.nio.file.Files`类的`walkFileTree`方法一起使用。它执行深度优先遍历，从特定的根目录开始。

## 准备就绪

要遍历目录，我们需要：

1.  创建一个代表根目录的`Path`对象。

1.  创建一个派生自`SimpleFileVisitor`的类的实例。

1.  将这些对象用作`Files`类的`walkFileTree`方法的参数。

## 如何做...

1.  创建一个新的控制台应用程序，并使用以下`main`方法。在这里，我们将遍历`home`目录，并列出其每个元素如下：

```java
public static void main(String[] args) {
try {
Path path = Paths.get("/home");
ListFiles listFiles = new ListFiles();
Files.walkFileTree(path, listFiles);
}
catch (IOException ex) {
ex.printStackTrace();
}
}

```

1.  将以下`ListFiles`类添加到您的项目中。它说明了每个`SimpleFileVisitor`方法的用法：

```java
class ListFiles extends SimpleFileVisitor<Path> {
private final int indentionAmount = 3;
private int indentionLevel;
public ListFiles() {
indentionLevel = 0;
}
private void indent() {
for(int i=0 ; i<indentionLevel; i++) { {
System.out.print(' ');
}
}
@Override
public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) {
indent();
System.out.println("Visiting file:" + file.getFileName());
return FileVisitResult.CONTINUE;
}
@Override
public FileVisitResult postVisitDirectory(Path directory, IOException e) throws IOException {
indentionLevel -= indentionAmount;
indent();
System.out.println("Finished with the directory: " + directory.getFileName());
return FileVisitResult.CONTINUE;
}
@Override
public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes) throws IOException {
indent();
System.out.println("About to traverse the directory: " + directory.getFileName());
indentionLevel += indentionAmount;
return FileVisitResult.CONTINUE;
}
SimpleFileVisitor classusing, for filesystem traverse@Override
public FileVisitResult visitFileFailed(Path file, IOException exc) throws IOException {
System.out.println("A file traversal error ocurred");
return super.visitFileFailed(file, exc);
}
}

```

1.  执行应用程序。根据您的`home`目录的结构，您可能会得到与以下不同的结果：

即将遍历目录：home

**即将遍历目录：docs**

**访问文件：users.bak**

**访问文件：users.txt**

**完成目录：docs**

**即将遍历目录：music**

**访问文件：Future Setting A.mp3**

**访问文件：Robot Brain A.mp3**

**访问文件：Space Machine A.mp3**

**完成目录：music**

**完成目录：home**

检查`backup`目录，以验证它是否成功创建。

## 工作原理...

在`main`方法中，我们为`home`目录创建了一个`Path`对象。接下来，创建了`ListFiles`类的一个实例。这些对象被用作`walkFileTree`方法的参数。该方法影响了`home`目录的遍历，并根据需要调用了`ListFiles`类的方法。

`walkFileTree`方法从根目录开始，并对目录层次结构进行深度优先遍历。在遍历目录之前，将调用`preVisitDirectory`方法。接下来，处理目录的每个元素。如果是文件，则调用`visitFile`方法。一旦处理了目录的所有元素，将调用`postVisitDirectory`方法。如果发生异常，则将调用`visitFileFailed`方法。

添加了私有辅助方法，使输出更易读。`indentionAmount`变量控制了每个缩进的深度。`indentionLevel`变量在访问每个子目录时递增和递减。`indent`方法执行实际的缩进。

## 还有更多...

有两个重载的`walkFileTree`方法。一个接受`Path`和`FileVisitor`对象，之前已经说明过。它不会跟踪链接，并将访问目录的所有级别。第二个方法接受两个额外的参数：一个指定要访问的目录级别的数量，另一个用于配置遍历。目前，唯一可用的配置选项是`FileVisitOption.FOLLOW_LINKS`，它指示方法跟随符号链接。

默认情况下不会跟随符号链接。如果在`walkFileTree`方法的参数中指定了跟随它们，则会注意检测循环链接。如果检测到循环链接，则将其视为错误条件。

要访问的目录级别的数量由整数参数控制。值为 0 将导致只访问顶级目录。值为`Integer.MAX_VALUE`表示将访问所有级别。值为 2 表示只遍历前两个目录级别。

遍历将在以下条件之一发生时终止：

+   所有文件都已被遍历

+   `visit`方法返回`FileVisitResult.TERMINATE`

+   `visit`方法以`IOException`或其他异常终止时，将被传播回来

任何不成功的操作通常会导致调用`visitFileFailed`方法并抛出`IOException`。

当遇到文件时，如果它不是目录，则尝试读取其`BasicFileAttributes`。如果成功，将属性传递给`visitFile`方法。如果不成功，则调用`visitFileFailed`方法，并且除非处理，否则会抛出`IOException`。

如果文件是目录并且目录可以打开，则调用`preVisitDirectory`，并访问目录及其后代的元素。

如果文件是目录且无法打开该目录，则将调用`visitFileFailed`方法，并将抛出`IOException`。但是，深度优先搜索将继续进行下一个兄弟节点。

以下表总结了遍历过程。

| 遇到的元素 | 可以打开 | 无法打开 |
| --- | --- | --- |
| 文件 | 调用`visitFile` | 调用`visitFileFailed` |
| 目录 | 调用`preVisitDirectory`目录元素被处理调用`postVisitDirectory` | 调用`visitFileFailed` |

为方便起见，列出了枚举`FileVisitResult`的枚举常量如下：

| 值 | 含义 |
| --- | --- |
| `CONTINUE` | 继续遍历 |
| `SKIP_SIBLINGS` | 继续而不访问此文件或目录的兄弟节点 |
| `SKIP_SUBTREE` | 继续而不访问此目录中的条目 |
| `TERMINATE` | 终止 |

## 另请参阅

*使用 SimpleFileVisitor 类删除目录*和*使用 SimpleFileVisitor 类复制目录*的方法利用了本方法中描述的方法来分别删除和复制目录。

# 使用 SimpleFileVisitor 类删除目录

删除目录是一些应用程序的要求。这可以通过使用`walkFileTree`方法和一个`java.nio.file.SimpleFileVisitor`派生类来实现。这个示例建立在*使用 SimpleFileVisitor 类遍历文件系统*示例提供的基础上。

## 准备工作

要删除一个目录，我们需要：

1.  创建一个代表根目录的`Path`对象。

1.  创建一个从`SimpleFileVisitor`派生的类的实例如下：

+   重写`visitFile`方法来删除文件

+   重写`postVisitDirectory`方法来删除目录

1.  将这些对象作为参数传递给`Files`类的`walkFileTree`方法。

## 如何做...

1.  创建一个新的控制台应用程序。在这里，我们将删除`home`目录及其所有元素。将以下代码添加到`main`方法中：

```java
try {
Files.walkFileTree(Paths.get("/home"), new DeleteDirectory());
}
catch (IOException ex) {
ex.printStackTrace();
}

```

1.  `DeleteDirectory`类如下所示。在删除每个文件和目录时，都会显示相应的消息：

```java
public class DeleteDirectory extends SimpleFileVisitor<Path> {
@Override
public FileVisitResult visitFile(Path file, BasicFileAttributes attributes)
throws IOException {
System.out.println("Deleting " + file.getFileName());
Files.delete(file);
return FileVisitResult.CONTINUE;
}
@Override
public FileVisitResult postVisitDirectory(Path directory, IOException exception)
throws IOException {
if (exception == null) {
System.out.println("Deleting " + directory.getFileName());
Files.delete(directory);
return FileVisitResult.CONTINUE;
}
else {
throw exception;
}
}
}

```

1.  备份`home`目录，然后执行应用程序。根据实际的目录结构，你应该会得到以下输出：

**删除 users.bak**

**删除 users.txt**

**删除 docs**

**删除 Future Setting A.mp3**

**删除 Robot Brain A.mp3**

**删除 Space Machine A.mp3**

**删除音乐**

**删除 home**

验证目录是否已被删除。

## 它是如何工作的...

在`main`方法中，我们创建了一个代表`home`目录的`Path`对象。接下来，我们创建了`DeleteDirectory`类的一个实例。这两个对象被用作`walkFileTree`方法的参数，该方法启动了遍历过程。

当遇到一个文件时，`visitFile`方法被执行。在这个方法中，我们显示了一个指示文件正在被删除的消息，然后使用`Files`类的`delete`方法来删除文件。当遇到一个目录时，`postVisitDirectory`方法被调用。进行了一个测试以确保没有发生错误，然后显示了一个指示目录正在被删除的消息，随后调用了该目录的`delete`方法。这两个方法都返回了`FileVisitResult.CONTINUE`，这将继续删除过程。

## 另请参阅

*使用 SimpleFileVisitor 类遍历文件系统*示例提供了关于使用`walkFileTree`方法和`SimpleFileVisitor`类的更多细节。*使用 SimpleFileVisitor 类复制目录*示例也提供了这种方法的变体。

# 使用 SimpleFileVisitor 类复制目录

复制目录是一些应用程序的要求。这可以通过使用`walkFileTree`方法和一个`java.nio.file.SimpleFileVisitor`派生类来实现。这个示例建立在*使用 SimpleFileVisitor 类遍历文件系统*示例提供的基础上。

## 准备工作

要删除一个目录，我们需要：

1.  创建一个代表根目录的`Path`对象。

1.  创建一个从`SimpleFileVisitor`派生的类的实例如下：

+   重写`visitFile`方法来复制文件

+   重写`preVisitDirectory`方法来复制目录

1.  将这些对象作为参数传递给`Files`类的`walkFileTree`方法。

## 如何做...

1.  创建一个新的控制台应用程序。在这里，我们将把`home`目录及其所有元素复制到一个`backup`目录中。将以下代码添加到`main`方法中：

```java
try {
Path source = Paths.get("/home");
Path target = Paths.get("/backup");
Files.walkFileTree(source,
EnumSet.of(FileVisitOption.FOLLOW_LINKS),
Integer.MAX_VALUE,
new CopyDirectory(source, target));
}
catch (IOException ex) {
ex.printStackTrace();
}

```

1.  `CopyDirectory`类如下所示。在删除每个文件和目录时，都会显示相应的消息：

```java
public class CopyDirectory extends SimpleFileVisitor<Path> {
private Path source;
private Path target;
public CopyDirectory(Path source, Path target) {
this.source = source;
this.target = target;
}
@Override
public FileVisitResult visitFile(Path file, BasicFileAttributes attributes) throws IOException {
SimpleFileVisitor classusing, for directory copySystem.out.println("Copying " + source.relativize(file));
Files.copy(file, target.resolve(source.relativize(file)));
return FileVisitResult.CONTINUE;
}
@Override
public FileVisitResult preVisitDirectory(Path directory, BasicFileAttributes attributes) throws IOException {
Path targetDirectory = target.resolve(source.relativize(directory));
try {
System.out.println("Copying " + source.relativize(directory));
Files.copy(directory, targetDirectory);
}
catch (FileAlreadyExistsException e) {
if (!Files.isDirectory(targetDirectory)) {
throw e;
}
}
return FileVisitResult.CONTINUE;
}
}

```

1.  执行应用程序。确切的输出取决于你使用的源文件结构，但应该类似于以下内容：

**复制**

**复制 docs**

**复制 docs\users.bak**

**复制 docs\users.txt**

**复制音乐**

**复制 music\Future Setting A.mp3**

**复制 music\Robot Brain A.mp3**

**复制 music\Space Machine A.mp3**

## 它是如何工作的...

在`main`方法中，我们为`home`和`backup`目录创建了`Path`对象。我们使用这些对象创建了一个`CopyDirectory`对象。我们使用了一个两参数的`CopyDirectory`构造函数，这样它的方法就可以直接访问这两个路径。

使用源`Path`调用了`walkFileTree`方法。它还作为第二个参数传递，一个`EnumSet`，指定不要跟随符号链接。这个参数需要一组选项。`EnumSet`类的静态方法创建了这个集合。

`walkFileTree`方法的第三个参数是一个值，表示要跟随多少级。我们传递了一个`Integer.MAX_VALUE`的值，这将导致复制`home`目录的所有级别。最后一个参数是`CopyDirectory`对象的一个实例。

在遍历过程中遇到文件时，将调用`CopyDirectory`类的`visitFile`方法。显示一个消息指示正在复制文件，然后使用`copy`方法将源文件复制到目标目录。使用`relativize`方法获取到源文件的相对路径，然后用作`resolve`方法的参数。结果是一个代表目标目录和源文件名的`Path`对象。这些方法在第二章的*使用路径解析组合路径*和*在两个位置之间创建路径*示例中进行了讨论，*使用路径定位文件和目录*。

当在遍历过程中遇到一个目录时，将调用`preVisitDirectory`方法。它的工作方式与`visitFile`方法相同，只是我们复制的是一个目录而不是一个文件。这两种方法都返回`FileVisitResult.CONTINUE`，这将继续复制过程。仍然需要复制目录的各个文件，因为`copy`方法只能复制单个文件。

请注意，`CopyDirectory`类扩展了`SimpleFileVisitor`类，使用`Path`作为通用值。`walkFileTree`方法需要一个实现`Path`接口的对象。因此，我们必须使用`Path`或扩展`Path`的接口。

## 另请参阅

*使用 SimpleFileVisitor 类遍历文件系统*示例提供了更多关于`walkFileTree`方法和`SimpleFileVisitor`类的使用细节。*使用 SimpleFileVisitor 类删除目录*示例也提供了这种方法的变体。

# 使用`DirectoryStream`接口处理目录的内容

确定目录的内容是一个相当常见的需求。有几种方法可以做到这一点。在这个示例中，我们将研究使用`java.nio.file.DirectoryStream`接口来支持这个任务。

目录将包含文件或子目录。这些文件可能是常规文件，也可能是链接或隐藏文件。`DirectoryStream`接口将返回所有这些元素类型。我们将使用`java.nio.file.Files`类的`newDirectoryStream`方法来获取`DirectoryStream`对象。这个方法有三个重载版本。首先演示了这个方法的最简单用法。用于过滤目录内容的版本在*使用 globbing 过滤目录*示例和*编写自己的目录过滤器*示例中展示。

## 准备工作

为了使用`DirectoryStream`，我们需要：

1.  获取`DirectoryStream`对象的实例。

1.  通过`DirectoryStream`迭代处理其元素。

## 如何做...

1.  创建一个新的控制台应用程序，并添加以下`main`方法。我们创建了一个新的`DirectoryStream`对象，然后使用 for each 循环来迭代目录元素，如下所示：

```java
public static void main(String[] args) {
Path directory = Paths.get("/home");
try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(directory)) {
for (Path file : directoryStream) {
System.out.println(file.getFileName());
}
}
catch (IOException | DirectoryIteratorException ex) {
ex.printStackTrace();
}
}

```

1.  执行应用程序。您的输出应该反映出您的`home`目录的内容，并且应该类似于以下内容：

**文档**

**音乐**

## 它是如何工作的...

为`home`目录创建了一个`Path`对象。这个对象与`newDirectoryStream`方法一起使用，该方法返回了一个目录的`DirectoryStream`对象。`DirectoryStream`接口扩展了`Iterable`接口。这允许`DirectoryStream`对象与 for each 语句一起使用，它简单地打印了`home`目录的每个元素的名称。在这种情况下，只有两个子目录：`docs`和`music`。

注意使用 try-with-resource 块。这是 Java 7 中的新功能，并在第一章中的*使用 try-with-resource 块改进异常处理代码*中进行了讨论，*Java 语言改进*。这保证了目录流将被关闭。如果没有使用这种 try 块，则在不再需要流之后关闭流是很重要的。

使用的`Iterable`对象不是通用的`iterator`。它在几个重要方面有所不同，如下所示：

+   它只支持单个`Iterator`

+   `hasNext`方法执行至少一个元素的预读

+   它不支持`remove`方法

`DirectoryStream`接口有一个方法`iterator`，它返回一个`Iterator`类型的对象。第一次调用该方法时，将返回一个`Iterator`对象。对该方法的后续调用将抛出`IllegalStateException`。

`hasNext`方法将至少提前读取一个元素。如果该方法返回`true`，则对其 next 方法的下一次调用将保证返回一个元素。返回的元素的顺序没有指定。此外，许多操作系统在许多 shell 中以`"."`或`"..`"表示对自身和/或其父级的链接。这些条目不会被返回。

`iterator`有时被称为**弱一致**。这意味着虽然`iterator`是线程安全的，但在`iterator`返回后对目录的任何更新都不会导致`iterator`的更改。

## 还有更多...

有两个重载的`newDirectoryStream`方法，允许该方法的结果通过通配符模式或`DirectoryStream.Filter`对象进行过滤。**通配符模式**是一个包含一系列字符的字符串，用于定义模式。该模式用于确定要返回哪些目录元素。`DirectoryStream.Filter`接口有一个方法`accept`，它返回一个布尔值，指示是否应返回目录元素。

## 另请参阅

*使用通配符过滤目录*示例说明了通配符模式的使用。*编写自己的目录过滤器*示例展示了如何创建和使用`DirectoryStream.Filter`对象来过滤目录的内容。

# 使用通配符过滤目录

通配符模式类似于正则表达式，但更简单。与正则表达式一样，它可以用于匹配特定的字符序列。我们可以将通配符与`newDirectoryStream`方法结合使用，以过滤目录的内容。该方法的使用在*使用 DirectoryStream 接口处理目录的内容*示例中进行了演示。

## 准备工作

要使用这种技术，我们需要：

1.  创建一个符合我们过滤要求的 globbing 字符串。

1.  为感兴趣的目录创建一个`java.nio.file.Path`对象。

1.  将这两个对象用作`newDirectoryStream`方法的参数。

## 如何做...

1.  创建一个新的控制台应用程序，并使用以下`main`方法。在这个例子中，我们将只列出那些以`java`开头并以`.exe`结尾的目录元素。我们将使用 Java 7 的`bin`目录。`globbing`字符串使用特殊字符`*`来表示零个或多个字符，如下所示：

```java
Path directory = Paths.get("C:/Program Files/Java/jdk1.7.0/bin");
try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(directory,"java*.exe")) {
for (Path file : directoryStream) {
System.out.println(file.getFileName());
}
}
catch (IOException | DirectoryIteratorException ex) {
ex.printStackTrace();
}

```

1.  执行应用程序。输出应该类似于以下内容：

**java-rmi.exe**

**java.exe**

**javac.exe**

**javadoc.exe**

**javah.exe**

**javap.exe**

**javaw.exe**

**javaws.exe**

## 它是如何工作的...

首先，创建了一个代表`bin`目录的`Path`对象。然后将其用作`newDirectoryStream`方法的第一个参数。第二个参数是`globbing`字符串。在这种情况下，它匹配以`java`开头并以`.exe`结尾的目录元素。允许任意数量的中间字符。然后使用 for each 循环显示过滤后的文件。

## 还有更多...

Globbing 字符串基于模式，使用特殊字符来匹配字符串序列。这些特殊字符在`Files`类的`getPathMatcher`方法的文档中定义。在这里，我们将更深入地研究这些字符串。以下表格总结了几个特殊字符：

| 特殊符号 | 意义 |
| --- | --- |
| * | 匹配不跨越目录边界的名称组件的零个或多个字符 |
| ** | 匹配跨越目录边界的零个或多个字符 |
| ? | 匹配名称组件的一个字符 |
| \ | 用于匹配特殊符号的转义字符 |
| [ ] | 匹配括号内找到的单个字符。A - 匹配一个范围。!表示否定。*、?和\字符匹配它们自己，-如果是括号内的第一个字符或!后的第一个字符，则匹配它自己。 |
| { } | 可以同时指定多个子模式。这些模式使用花括号分组在一起，但在花括号内部用逗号分隔。 |

匹配通常以实现相关的方式执行。这包括匹配是否区分大小写。`**`符号在这里不适用，因为`newDirectoryStream`方法返回单独的元素。在这里没有机会匹配跨越目录边界的序列。其他方法将使用这种能力。

以下表格列出了几个可能有用的 glob 模式示例：

| Globbing 字符串 | 将匹配 |
| --- | --- |
| `*.java` | 以`.java`结尾的任何文件名 |
| `*.{java,class,jar}` | 以`.java, .class`或`.jar`结尾的任何文件 |
| `java*[ph].exe` | 仅匹配以 java 开头并以`p.exe`或`h.exe`结尾的文件 |
| `j*r.exe` | 以`j`开头并以`r.exe`结尾的文件 |

现在，让我们讨论`PathMatcher`接口的使用。

### 使用 PathMatcher 接口来过滤目录

`java.nio.file.PathMatcher`接口提供了使用**glob**匹配文件名的方法。它有一个名为`matches`的方法，接受一个`Path`参数。如果文件与 glob 模式匹配，则返回`true`。否则返回`false`。

在以下代码序列中，我们通过使用 glob 模式`glob:java?.exe`创建了一个`PathMatcher`对象。在 for 循环中，我们使用`matches`方法进一步过滤以`java`开头，后跟一个字符，然后以`.exe`结尾的文件的子集：

```java
Path directory = Paths.get("C:/Program Files/Java/jdk1.7.0/bin");
PathMatcher pathMatcher = FileSystems.getDefault().getPathMatcher("glob:java?.exe");
try (DirectoryStream<Path> directoryStream =
Files.newDirectoryStream(directory,"java*.exe")) {
for (Path file : directoryStream) {
if(pathMatcher.matches(file.getFileName())) {
System.out.println(file.getFileName());
}
}
}
catch (IOException | DirectoryIteratorException ex) {
ex.printStackTrace();
}

```

当您执行此序列时，您应该得到以下输出：

**javac.exe**

**javah.exe**

**javap.exe**

**javaw.exe**

注意`matches`方法中使用的**glob:**前缀。这种方法需要使用这个前缀，但`newDirectoryStream`方法不需要。此外，`matches`方法接受一个`Path`参数。但是，请注意我们使用了从`Path`类的`getFileName`方法返回的`String`。仅使用`Path`对象或使用`String`文字均不起作用。

与使用 glob:前缀不同，我们可以改用正则表达式。为此，请使用**reg:**前缀，后跟正则表达式。

通常，对于简单的目录过滤，我们会在`newDirectoryStream`方法中使用更严格的 glob 模式。我们在这里使用它是为了举例说明。然而，如果我们想要在循环的一部分执行多个过滤操作，那么使用模式作为`newDirectoryStream`方法的一部分，然后使用一个或多个`matches`方法调用是一种可行的策略。

## 另请参阅

*编写自己的目录过滤器*配方探讨了如何创建更强大的过滤器，以匹配基于文件名以外的属性的文件名。

# 编写自己的目录过滤器

在使用`java.nio.file.Files`类的`newDirectoryStream`方法时，目录过滤器用于控制返回哪些目录元素。当我们需要限制流的输出时，这是很有用的。例如，我们可能只对超过一定大小或在某个日期后修改的文件感兴趣。正如本配方中描述的`java.nio.file.DirectoryStream.Filter`接口，它将限制流的输出。它比使用 globbing 更强大，因为决策可以基于文件名以外的因素。

## 准备工作

要使用这种技术，我们需要：

1.  创建一个满足我们过滤要求的`DirectoryStream.Filter`对象。

1.  为感兴趣的目录创建一个`Path`对象。

1.  使用这两个对象作为`newDirectoryStream`方法的参数。

## 如何做...

1.  创建一个新的控制台应用程序，并将以下序列添加到`main`方法中。在这个例子中，我们将只过滤出那些隐藏的目录元素。我们将使用 Windows 系统目录。然而，任何其他适当的目录都可以工作：

```java
DirectoryStream.Filter<Path> filter = new DirectoryStream.Filter<Path>() {
public boolean accept(Path file) throws IOException {
return (Files.isHidden(file));
}
};
Path directory = Paths.get("C:/Windows");
try (DirectoryStream<Path> directoryStream = Files.newDirectoryStream(directory,filter)){
own directory filterwritingfor (Path file : directoryStream) {
System.out.println(file.getFileName());
}
}
catch (IOException | DirectoryIteratorException ex) {
ex.printStackTrace();
}

```

1.  执行时，您的输出应该只列出那些隐藏的文件。以下是一个可能的输出：

**SwSys1.bmp**

**SwSys2.bmp**

**WindowsShell.Manifest**

## 工作原理...

首先，我们创建了一个匿名内部类来定义一个实现`DirectoryStream.Filter`接口的对象。在`accept`方法中，使用`isHidden`方法来确定元素文件是否隐藏。`DirectoryStream.Filter`接口使用其`accept`方法来确定是否应该返回目录元素。该方法返回`true`或`false`，指示`newDirectoryStream`方法是否应该返回该元素。因此，它过滤掉了不需要的元素，这种情况下是非隐藏元素。使用 for each 循环来显示隐藏元素。当声明`filter`变量时，它是使用`Path`作为其泛型值声明的。扩展`Path`接口的接口也可以使用。

## 另请参阅

这种技术过滤单个目录。如果需要过滤多个目录，则可以根据*使用 SimpleFileVisitor 类遍历文件系统*配方中使用的示例来适应多个目录。

# 使用 WatchEvents 监视文件事件

当应用程序需要了解目录中的更改时，监视服务可以监听这些更改，然后通知应用程序这些更改。服务将根据感兴趣的事件类型注册要监视的目录。事件发生时，将排队一个监视事件，随后可以根据应用程序的需求进行处理。

## 准备工作

要监视目录的事件，我们需要执行以下操作：

1.  创建一个代表目录的`java.nio.file.Path`对象。

1.  使用`java.nio.file.FileSystem`类的`newWatchService`方法创建一个新的监视服务。

1.  确定我们感兴趣监视的事件。

1.  使用监视服务注册目录和事件。

1.  处理事件发生时的事件。

## 如何做...

1.  创建一个新的控制台应用程序。我们将在`main`方法中添加代码来创建一个观察服务，确定我们想要观察的事件，将`docs`目录注册到服务中，然后处理事件。让我们从创建观察服务和目录的`Path`对象开始。将以下代码添加到`main`方法中：

```java
try {
FileSystem fileSystem = FileSystems.getDefault();
WatchService watchService = fileSystem.newWatchService();
Path directory = Paths.get("/home/docs");

```

1.  接下来，创建一个监视文件创建、删除和修改的事件数组，如下所示：

```java
WatchEvent.Kind<?>[] events = {
StandardWatchEventKinds.ENTRY_CREATE,
StandardWatchEventKinds.ENTRY_DELETE,
StandardWatchEventKinds.ENTRY_MODIFY};
directory.register(watchService, events);

```

1.  添加以下 while 循环以监视和处理任何目录事件：

```java
while (true) {
System.out.println("Waiting for a watch event");
WatchKey watchKey = watchService.take();
System.out.println("Path being watched: " + watchKey.watchable());
System.out.println();
if (watchKey.isValid()) {
for (WatchEvent<?> event : watchKey.pollEvents()) {
System.out.println("Kind: " + event.kind());
System.out.println("Context: " + event.context());
System.out.println("Count: " + event.count());
System.out.println();
}
boolean valid = watchKey.reset();
if (!valid) {
// The watchKey is not longer registered
}
}
}
}
catch (IOException ex) {
ex.printStackTrace();
}
catch (InterruptedException ex) {
ex.printStackTrace();
}

```

1.  执行应用程序。您应该得到以下输出：

等待观察事件

1.  使用文本编辑器，在`docs`目录中创建一个名为`temp.txt`的新文件并保存。然后应用程序应该显示类似以下的输出。如果这是您第一次在目录中创建文件，则您的输出可能会有所不同。这些条目表示文件已被创建，其内容随后被保存：

正在观察的路径：\home\docs

类型：ENTRY_CREATE

上下文：temp.txt

计数：1

等待观察事件

正在观察的路径：\home\docs

类型：ENTRY_MODIFY

上下文：temp.txt

计数：2

等待观察事件

1.  接下来，再次保存文件。现在您应该得到以下输出：

正在观察的路径：\home\docs

类型：ENTRY_MODIFY

上下文：temp.txt

计数：1

等待观察事件

1.  从文件管理器中删除文件。您的输出应该反映出它的删除：

类型：ENTRY_DELETE

上下文：temp1.txt

计数：1

等待观察事件

## 它是如何工作的...

我们需要的第一件事是一个`WatchService`对象。这是通过获取默认文件系统，然后对其应用`newWatchService`方法来获得的。接下来，我们创建了一个代表`docs`目录的`Path`对象和一个涵盖创建、删除和修改类型事件的事件数组。

然后进入了一个无限循环，以监视和处理`docs`目录中发生的文件事件。循环开始时显示一个消息，指示它正在等待事件。执行了`WatchService`类的`take`方法。此方法将阻塞，直到发生事件。

当事件发生时，它返回一个`WatchKey`对象，其中包含有关事件的信息。它的`watchable`方法返回被观察的对象，然后为了信息目的而显示。

使用`isValid`方法验证了观察键的有效性，并且它的`pollEvents`方法被用作 for each 循环的一部分。`pollEvents`方法返回所有待处理事件的列表。显示了与事件相关的类型、上下文和计数值。

我们监视的事件的上下文是目标目录和引起事件的条目之间的相对路径。计数值取决于事件，并在下一节中讨论。

最后的活动重置了观察键。这是为了将键重新置于就绪状态，直到再次需要它。如果方法返回`false`，则键不再有效。

## 还有更多...

`WatchService`接口具有获取观察键和关闭服务的方法。`poll`和`take`方法检索下一个观察键，就像我们之前看到的那样。如果没有观察键存在，`poll`方法将返回`null`。但是，`take`方法将阻塞，直到观察键可用。有一个重载的`poll`方法，它接受额外的参数来指定在返回之前等待事件的时间。这些参数包括超时值和`TimeUnit`值。`TimeUnit`枚举的使用在第四章的*理解 FileTime 类部分*中讨论，*管理文件和目录*。

`Path`类的`register`方法将注册由其执行的`Path`对象指定的文件。该方法接受参数：

+   指定监视服务

+   要监视的事件类型

+   确定`Path`对象注册方式的修饰符

`WatchEvent.Modifier`接口指定了如何使用监视服务注册`Path`对象。在此版本的 Java 中，没有定义修饰符。

`java.nio.file.StandardWatchEventKinds`类定义了标准事件类型。此接口的字段总结在以下表中：

| 类型 | 含义 | 计数 |
| --- | --- | --- |
| `ENTRY_CREATE` | 创建目录条目 | 总是 1 |
| `ENTRY_DELETE` | 删除目录条目 | 总是 1 |
| `ENTRY_MODIFY` | 修改目录条目 | 大于 1 |
| `OVERFLOW` | 表示事件可能已丢失或被丢弃的特殊事件 | 大于 1 |

当事件发生时，监视服务将返回一个代表事件的`WatchKey`对象。此键用于同一类型事件的多次发生。当发生该类型的事件时，与事件关联的计数将增加。如果在处理事件之前发生了该类型的多个事件，则每次增加的计数值取决于事件类型。

在前面的示例中使用`reset`方法将重新排队监视键并将计数重置为零。对于重复事件，上下文是相同的。每个目录条目将为该事件类型拥有自己的监视键。

可以使用`WatchKey`接口的`cancel`方法取消事件。这将取消事件在监视服务中的注册。队列中的任何待处理事件将保留在队列中，直到被移除。如果监视服务关闭，监视事件也将被取消。

监视服务是线程安全的。这意味着如果多个线程正在访问事件，那么在使用`reset`方法时应该小心。在所有使用该事件的线程完成处理事件之前，不应该使用该方法。

可以使用`close`方法关闭监视服务。如果多个线程正在使用此服务，那么后续尝试检索监视键将导致`ClosedWatchServiceException`。

文件系统可能能够比监视服务更快地报告事件。一些监视服务的实现可能会对排队的事件数量施加限制。当有意忽略事件时，将使用`OVERFLOW`类型的事件来报告此问题。溢出事件会自动为目标注册。溢出事件的上下文取决于实现。

监视服务的许多方面都依赖于实现，包括：

+   是否使用本机事件通知服务或模拟

+   事件被排队的及时性

+   处理事件的顺序

+   是否报告短暂事件

# 了解 ZIP 文件系统提供程序

处理 ZIP 文件比 Java 7 之前要简单得多。在这个版本中引入的 ZIP 文件系统提供程序处理 ZIP 和 JAR 文件，就好像它们是文件系统一样，因此您可以轻松访问文件的内容。您可以像处理普通文件一样操作文件，包括复制、删除、移动和重命名文件。您还可以修改文件的某些属性。本教程将向您展示如何创建 ZIP 文件系统的实例并向系统添加目录。

## 准备就绪

我们必须首先创建一个`java.net.URI`对象的实例来表示我们的 ZIP 文件，然后创建新的`java.nio.file.FileSystem`，然后才能对 ZIP 文件的内容进行任何操作。在这个例子中，我们还将使用`java.util.HashMap`来设置`FileSystem`的可选属性如下：。

1.  创建一个`URI`对象来表示 ZIP 文件。

1.  创建一个`HashMap`对象来指定`create`属性为`true`。

1.  使用`newFileSystem`方法创建`FileSystem`对象。

## 如何做...

1.  创建一个带有`main`方法的控制台应用程序。在`main`方法中，添加以下代码序列。我们将在 ZIP 文件中创建一个新的文件系统，然后将一个目录添加到其中，如下所示：

```java
Map<String, String> attributes = new HashMap<>();
attributes.put("create", "true");
try {
URI zipFile = URI.create("jar:file:/home.zip");
try (FileSystem zipFileSys = FileSystems.newFileSystem(zipFile, attributes);) {
Path path = zipFileSys.getPath("docs");
Files.createDirectory(path);
try (DirectoryStream<Path> directoryStream =
Files.newDirectoryStream(zipFileSys.getPath("/"));) {
for (Path file : directoryStream) {
System.out.println(file.getFileName());
}
}
}
}
catch (IOException e) {
e.printStackTrace();
}

```

1.  执行程序。您的输出应如下所示：

**docs/**

## 它是如何工作的...

`URI`对象通过使用`HashMap`对象指定了 ZIP 文件的位置，我们指定如果 ZIP 文件不存在，它应该被创建。`FileSystem`对象`zipFileSys`是在 try-with-resources 块中创建的，因此资源将自动关闭，但如果您不希望使用嵌套的 try-with-resources 块，您必须使用`FileSystem`类的`close`方法手动关闭资源。try-with-resources 块在第一章中有详细介绍，*Java 语言改进*，配方：*使用 try-with-resources 块改进异常处理代码*。

为了演示如何将 ZIP 文件作为`FileSystem`对象进行操作，我们调用了`createDirectory`方法在我们的 ZIP 文件中添加了一个文件夹。在这一点上，我们还有选择执行其他`FileSystem`操作的选项，比如复制文件、重命名文件和删除文件。我们使用了一个`java.nio.file.DirectoryStream`来浏览我们的 ZIP 文件结构并打印出我们的`docs`目录，但您也可以在计算机上导航到 ZIP 文件的位置来验证其创建。

## 另请参阅

有关`DirectoryStream`类的更多信息，请参阅*使用 DirectoryStream 接口处理目录的内容*配方。


# 第六章：Java 7 中的流 IO

在本章中，我们将涵盖：

+   管理简单文件

+   使用缓冲 IO 处理文件

+   使用`SeekableByteChannel`进行随机访问 IO

+   使用`AsynchronousServerSocketChannel`类管理异步通信

+   使用`AsynchronousFileChannel`类写入文件

+   使用`AsynchronousFileChannel`类从文件中读取

+   使用`SecureDirectoryStream`类

# 介绍

在 Java 7 中，我们发现它的 IO 功能有许多改进。其中大部分都在`java.nio`包中，被称为**NIO2**。在本章中，我们将专注于对流和基于通道的 IO 的新支持。**流**是一系列连续的数据。**流 IO**一次处理一个字符，而**通道 IO**对每个操作使用一个缓冲区。

我们从用于处理简单文件的新技术开始。这些技术由`Files`类支持，并在*管理简单文件*配方中有讨论。**缓冲 IO**通常更有效，并在*使用缓冲 IO 处理文件*配方中有解释。

`java.nio.channels`包的`ByteChannel`接口是一个可以读写字节的通道。`SeekableByteChannel`接口扩展了`ByteChannel`接口以在通道内保持位置。位置可以使用寻找类型的随机 IO 操作进行更改。这个功能在*使用 SeekableByteChannel 进行随机访问 IO*配方中有讨论。

Java 7 增加了对异步通道功能的支持。这些操作的异步性在于它们不会阻塞。异步应用可以继续执行而不需要等待 IO 操作完成。当 IO 完成时，应用的一个方法会被调用。有四个新的`java.nio.channels`包异步通道类：

+   `AsynchronousSocketChannel`

+   `AsynchronousServerSocketChannel`

+   `AsynchronousFileChannel`

+   `AsynchronousChannelGroup`

前两者在服务器/客户端环境中一起使用，并在*使用 AsynchronousServerSocketChannel 类管理异步通信*配方中有详细说明。

`AsynchronousFileChannel`类用于需要以异步方式执行的文件操作。支持写和读操作的方法分别在*使用 AsynchronousFileChannel 类写入文件*和*使用 AsynchronousFileChannel 类从文件中读取*配方中有说明。

`AsynchronousChannelGroup`类提供了一种将异步通道组合在一起以共享资源的方法。这个类的使用在*更多内容*部分的*使用 AsynchronousFileChannel 类从文件中读取*配方中有展示。

`java.nio.file`包的`SecureDirectoryStream`类提供了对目录的更安全访问的支持。这个类的使用在*使用 SecureDirectoryStream*配方中有解释。然而，底层操作系统必须为这个类提供本地支持。

`users.txt`文件在本章中的几个示例中使用。假定`users.txt`文件的内容最初包含以下内容：

+   Bob

+   Mary

+   Sally

+   Tom

+   Ted

如果您的文件内容不同，那么示例的输出将相应地有所不同。

本章中的一些配方打开了一个文件。其中一些打开方法将使用一个枚举参数来指定文件应该如何打开。`java.nio.file`包的`OpenOption`接口指定了文件的打开方式，`StandardOpenOption`枚举实现了这个接口。枚举的值总结在下表中：

| 枚举 | 含义 |
| --- | --- |
| `APPEND` | 字节被写入文件的末尾 |
| `CREATE` | 如果文件不存在则创建一个新文件 |
| `CREATE_NEW` | 仅在文件不存在时创建新文件 |
| `DELETE_ON_CLOSE` | 关闭文件时删除文件 |
| `DSYNC` | 对文件的每次更新都是同步写入的 |
| `READ` | 以读取访问权限打开 |
| `SPARSE` | 稀疏文件 |
| `SYNC` | 对文件或元数据的每次更新都是同步写入的 |
| `TRUNCATE_EXISTING` | 打开文件时将文件长度截断为 0 |
| `WRITE` | 以写入访问权限打开文件 |

虽然这里没有讨论，但是`java.nio.channels`包的`NetworkChannel`接口是在 Java 7 中引入的。这代表了一个到网络套接字的通道。包括`AsynchronousServerSocketChannel`和`AsynchronousSocketChannel`在内的几个类在本章中实现了它。它有一个`bind`方法，用于将套接字绑定到本地地址，允许检索和设置各种查询套接字选项。它允许使用操作系统特定的选项，这可以用于高性能服务器。

`java.nio.channels`包的`MulticastChannel`也是 Java 7 中的新功能。它用于支持组的多播操作。它由`DatagramChannel`类实现。该接口的方法支持从组中加入和离开成员。

**Sockets Direct Protocol**（**SDP**）是一种网络协议，支持使用**InfiniBand**（**IB**）进行流连接。IB 技术支持高速外围设备之间的点对点双向串行链接，例如磁盘。IB 的一个重要部分是它能够将数据从一台计算机的内存直接移动到另一台计算机的内存。

SDP 在 Solaris 和 Linux 操作系统上的 Java 7 中得到支持。`java.net`和`java.nio.channels`包中的几个类支持它的透明使用。但是，在使用之前必须启用 SDP。有关如何启用 IB，然后创建 SDP 配置文件的详细信息，请参阅[`download.oracle.com/javase/tutorial/sdp/sockets/index.html`](http://download.oracle.com/javase/tutorial/sdp/sockets/index.html)。

# 管理简单文件

一些文件很小，包含简单的数据。这通常适用于文本文件。当可以一次性读取或写入文件的全部内容时，有一些`Files`类的方法可以很好地工作。

在本教程中，我们将研究处理简单文件的技术。首先，我们将研究如何读取这些类型文件的内容。在*还有更多*部分，我们将演示如何向它们写入。

## 准备工作

一次性读取文件的全部内容：

1.  创建一个代表文件的`java.nio.file.Path`对象。

1.  使用`java.nio.file.Files`类的`readAllBytes`方法。

## 如何做...

1.  创建一个新的控制台应用程序。我们将读取并显示在 docs 目录中找到的`users.txt`文件的内容。将以下主要方法添加到应用程序中：

```java
public static void main(String[] args) throws IOException {
Path path = Paths.get("/home/docs/users.txt");
byte[] contents = Files.readAllBytes(path);
for (byte b : contents) {
System.out.print((char)b);
}
}

```

1.  执行应用程序。您的输出应该反映文件的内容。以下是一个可能的输出：

鲍勃

玛丽

莎莉

汤姆

泰德

## 它是如何工作的...

我们首先创建了一个代表`users.txt`文件的`Path`对象。使用`Files`类的`readAllBytes`方法，使用`path`对象作为其参数执行了该方法。该方法返回一个字节数组。

接下来，使用 for 语句来遍历数组。每个`byte`都被转换为`char`，然后显示出来。

## 还有更多...

一旦所有字节都被读取或发生异常，该方法将自动关闭文件。除了可能发生的`IOException`之外，还可能抛出`OutOfMemoryError`，如果不可能创建足够大的数组来容纳文件的内容。如果发生这种情况，则应使用另一种方法。

我们还关注：

+   写入简单文件

+   将文件的所有行作为列表返回

### 写入简单文件

在下面的例子中，我们将获取`users.txt`文件的内容，并向列表中添加一个新的名字。使用前面的代码，在打印出内容值的 for 循环之后加上注释。然后，在`Path`对象上调用`readAllBytes`方法后，创建一个指向一个新的不存在的文本文件的新`path`对象。然后声明一个名为`name`的`String`变量，并在字符串上调用`getBytes`方法返回一个新的`byte`数组。

```java
Path newPath = Paths.get("/home/docs/newUsers.txt");
byte[] newContents = "Christopher".getBytes();

```

接下来，我们将使用`Files`类的写入方法创建一个与我们的`users.txt`文件内容相同的新文件，然后将我们的`String`名字追加到这个列表中。在第一次调用`write`方法时，我们使用`newPath`指定文件应该创建在哪里，使用内容字节数组指定应该使用什么信息，使用`StandardOpenOption.CREATE`参数指定如果文件不存在则应该创建文件。在第二次调用`write`方法时，我们再次使用`newPath`，然后使用字节数组`newContents`和`StandardOpenOption.APPEND`指定应该将名字追加到现有文件中。

```java
Files.write(newPath, contents, StandardOpenOption.CREATE);
Files.write(newPath, newContents, StandardOpenOption.APPEND);

```

如果你打开`newUsers.txt`文件，你会看到从你的`users.txt`文件中获取的名单，以及使用`newContents`字节数组指定的名字。

还有一个重载的`write`方法，它使用相同的`Path`对象作为第一个参数，并使用`Iterable`接口作为第二个参数来迭代`CharSequence`。该方法的第三个参数定义了要使用的`Charset`。`StandardOpenOptions`作为可选参数可用，如前一个版本所示。在本章的介绍中列出了打开选项。

### 将文件的所有行作为列表返回

在你希望从一个简单的文件中读取时，使用`readAllLines`方法可能是有效的。该方法接受两个参数，即`Path`对象和`Charset`。该方法可能会抛出`IOException`。在下面的例子中，我们使用我们的`users.txt`文件的路径和`Charset`类的`defaultCharset`方法来执行`readAllLines`方法。该方法返回一个字符串列表，我们在 for 循环中打印出来。

```java
try {
Path path = Paths.get("/home/docs/users.txt");
List<String> contents = Files.readAllLines(path, Charset.defaultCharset());
for (String b : contents) {
System.out.println(b);
}
} catch (IOException e) {
e.printStackTrace();
}

```

你的输出应该类似于这样：

```java
Bob
Mary
Sally
Tom
Ted

```

注意，`readAllLines`方法返回的字符串不包括行结束符。

`readAllLines`方法识别以下行终止符：

+   `\u000D`后跟`\u000A` (CR/LF)

+   `\u000A`，(LF)

+   `\u000D`，(CR)

## 另请参阅

在本章中：

+   *使用缓冲 IO 处理文件：*这个示例说明了在 Java 7 中如何处理缓冲 IO

+   *使用 AsynchronousFileChannel 类写入文件：*这个示例说明了如何以异步方式对文件进行 IO 操作

+   *使用 AsynchronousFileChannel 类从文件中读取：*这个示例说明了如何以异步方式对文件进行 IO 操作

# 使用缓冲 IO 处理文件

缓冲 IO 提供了一种更有效的访问文件的技术。`java.nio.file`包的`Files`类的两种方法返回`java.io`包的`BufferedReader`或`BufferedWriter`对象。这些类提供了一种易于使用和高效的处理文本文件的技术。

我们将首先说明读取操作。在*还有更多*部分，我们将演示如何写入文件。

## 准备工作

使用`BufferedReader`对象从文件中读取：

1.  创建一个代表感兴趣的文件的`Path`对象

1.  使用`newBufferedReader`方法创建一个新的`BufferedReader`对象

1.  使用适当的`read`方法从文件中读取

## 操作步骤…

1.  使用以下`main`方法创建一个新的控制台应用程序。在这个方法中，我们将读取`users.txt`文件的内容，然后显示它的内容。

```java
public static void main(String[] args) throws IOException {
Path path = Paths.get("/home/docs/users.txt");
Charset charset = Charset.forName("ISO-8859-1");
try (BufferedReader reader = Files.newBufferedReader(path, charset)) {
String line = null;
while ((line = reader.readLine()) != null) {
System.out.println(line);
}
}

```

1.  执行应用程序。你的输出应该反映出`users.txt`文件的内容，应该类似于以下内容：

```java
Bob
Mary
Sally
Tom
Ted

```

### 工作原理...

创建代表`users.txt`文件的`Path`对象，然后创建`Charset`。在此示例中使用 ISO Latin Alphabet No. 1。可以根据所使用的平台使用其他字符集。

使用 try-with-resource 块创建了`BufferedReader`对象。这种类型的`try`块是 Java 7 中的新功能，并在第一章的*使用 try-with-resource 块改进异常处理代码*中有详细说明，*Java 语言改进*。这将导致`BufferedReader`对象在块完成时自动关闭。

while 循环读取文件的每一行，然后将每一行显示到控制台。任何`IOExceptions`都将根据需要抛出。

### 还有更多...

当字节存储在文件中时，其含义可能取决于预期的编码方案。`java.nio.charset`包的`Charset`类提供了字节序列和 16 位 Unicode 代码单元之间的映射。`newBufferedReader`方法的第二个参数指定要使用的编码。JVM 支持一组标准字符集，详细信息请参阅`Charset`类的 Java 文档。

我们还需要考虑：

+   使用`BufferedWriter`类写入文件

+   `Files`类中的非缓冲 IO 支持

#### 使用 BufferedWriter 类写入文件

`newBufferedWriter`方法打开或创建一个文件进行写入，并返回一个`BufferedWriter`对象。该方法需要两个参数，一个是`Path`对象，一个是指定的`Charset`，还可以使用可选的第三个参数。第三个参数指定一个`OpenOption`，如*Introduction*中的表中所述。如果未指定选项，该方法将表现为`CREATE, TRUNCATE_EXISTING`和`WRITE`选项被指定，将创建一个新文件或截断现有文件。

在以下示例中，我们指定一个包含要添加到我们的`users.txt`文件中的名称的新`String`对象。声明了我们的`Path`对象后，我们使用 try-with-resource 块打开了一个新的`BufferedWriter`。在此示例中，我们使用默认系统字符集和`StandardOpenOption.APPEND`来指定我们要将名称追加到我们的`users.txt`文件的末尾。在 try 块内，我们首先针对我们的`BufferedWriter`对象调用`newline`方法，以确保我们的名称放在新行上。然后我们针对我们的`BufferedWriter`对象调用`write`方法，使用我们的`String`作为第一个参数，零来表示字符串的开始字符，以及我们的`String`的长度来表示整个`String`应该被写入。

```java
String newName = "Vivian";
Path file = Paths.get("/home/docs/users.txt");
try (BufferedWriter writer = Files.newBufferedWriter(file, Charset.defaultCharset(), StandardOpenOption.APPEND)) {
writer.newLine();
writer.write(newName, 0, newName.length());
}

```

如果您检查`users.txt`文件的内容，新名称应该附加到文件中的其他名称的末尾。

#### `Files`类中的非缓冲 IO 支持

虽然非缓冲 IO 不如缓冲 IO 高效，但有时仍然很有用。`Files`类通过其`newInputStream`和`newOutputStream`方法为`InputStream`和`OutputStream`类提供支持。这些方法在需要访问非常小的文件或方法或构造函数需要`InputStream`或`OutputStream`作为参数时非常有用。

在以下示例中，我们将执行一个简单的复制操作，将`users.txt`文件的内容复制到`newUsers.txt`文件中。我们首先声明两个`Path`对象，一个引用源文件`users.txt`，一个指定我们的目标文件`newUsers.txt`。然后，在 try-with-resource 块内，我们打开了一个`InputStream`和一个`OutputStream`，使用`newInputStream`和`newOutputStream`方法。在块内，我们从源文件中读取数据并将其写入目标文件。

```java
Path file = Paths.get("/home/docs/users.txt");
Path newFile = Paths.get("/home/docs/newUsers.txt");
try (InputStream in = Files.newInputStream(file);
OutputStream out = Files.newOutputStream( newFile,StandardOpenOption.CREATE, StandardOpenOption.APPEND)) {
int data = in.read();
while (data != -1){
out.write(data);
data = in.read();
fileunbuffered IO}
}

```

检查`newUsers.txt`文件后，您应该看到内容与`users.txt`文件相匹配。

### 另请参阅

在本章中：

+   *管理简单文件：*此示例显示了如何在 Java 7 中处理非缓冲 IO

+   *使用 AsynchronousFileChannel 类向文件写入：*此示例说明了如何以异步方式对文件进行 IO 操作

+   *使用 AsynchronousFileChannel 类从文件中读取：*此示例说明了如何以异步方式对文件进行 IO 操作

## 使用 SeekableByteChannel 进行随机访问 IO

对文件的随机访问对于更复杂的文件很有用。它允许以非顺序方式访问文件中的特定位置。`java.nio.channels`包的`SeekableByteChannel`接口提供了这种支持，基于通道 IO。通道提供了用于大容量数据传输的低级方法。在此示例中，我们将使用`SeekableByteChannel`来访问文件。

### 准备工作

要获取`SeekableByteChannel`对象：

1.  创建一个表示文件的`Path`对象。

1.  使用`Files`类的静态`newByteChannel`方法获取`SeekableByteChannel`对象。

### 操作步骤...

1.  使用以下`main`方法创建一个新的控制台应用程序。我们将定义一个`bufferSize`变量来控制通道使用的缓冲区的大小。我们将创建一个`SeekableByteChannel`对象，并使用它来显示`users.txt`文件中的前两个名称。

```java
public static void main(String[] args) throws IOException {
int bufferSize = 8;
Path path = Paths.get("/home/docs/users.txt");
try (SeekableByteChannel sbc = Files.newByteChannel(path)) {
ByteBuffer buffer = ByteBuffer.allocate(bufferSize);
sbc.position(4);
sbc.read(buffer);
for(int i=0; i<5; i++) {
System.out.print((char)buffer.get(i));
}
System.out.println();
buffer.clear();
sbc.position(0);
sbc.read(buffer);
for(int i=0; i<4; i++) {
System.out.print((char)buffer.get(i));
}
System.out.println();
}
}

```

确保`users.txt`文件包含以下内容：

```java
Bob
Mary
Sally
Tom
Ted

```

1.  执行应用程序。输出应显示前两个名称的相反顺序：

```java
Mary
Bob

```

#### 工作原理...

我们创建了一个`bufferSize`变量来控制通道使用的缓冲区的大小。接下来，为`users.txt`文件创建了一个`Path`对象。该路径被用作`newByteChannel`方法的参数，该方法返回了一个`SeekableByteChannel`对象。

我们将文件中的读取位置移动到第四个位置。这将我们放置在文件中第二个名称的开头。然后使用`read`方法，将大约八个字节读入缓冲区。然后显示缓冲区的前五个字节。

我们重复了这个序列，但将位置移动到零，即文件的开头。然后再次执行了一个`read`操作，然后显示了前四个字符，这是文件中的第一个名称。

此示例使用了对文件中名称大小的明确了解。通常，除非通过其他技术获得，否则不会获得这种了解。我们在这里使用这些知识只是为了演示`SeekableByteChannel`接口的性质。

#### 还有更多...

`read`方法将从文件中的当前位置开始读取。它将读取直到缓冲区填满或达到文件末尾。该方法返回一个整数，指示读取了多少字节。当达到流的末尾时，返回`-1`。

读取和写入操作可能会访问由多个线程使用的相同的`SeekableByteChannel`对象。因此，当另一个线程关闭通道或以其他方式中断当前线程时，可能会抛出`AsynchronousCloseException`或`ClosedByInterruptException`异常。

有一个返回流大小的`size`方法。还有一个可用的`truncate`方法，它会丢弃文件中特定位置之后的所有字节。该位置作为长参数传递给该方法。

`Files`类的静态`newByteChannel`方法可以接受第二个参数，该参数指定打开文件时使用的选项。这些选项在*还有更多*部分的*使用 Buffered IO for files*示例的*使用 BufferedWriter 类向文件写入*中有详细说明。

此外，我们需要考虑：

+   处理整个文件的内容

+   使用`SeekableByteChannel`接口向文件写入

+   查询位置

##### 处理整个文件的内容

将以下代码添加到应用程序中。其目的是演示如何以顺序方式处理整个文件，并了解各种`SeekableByteChannel`接口方法。

```java
// Read the entire file
System.out.println("Contents of File");
sbc.position(0);
buffer = ByteBuffer.allocate(bufferSize);
String encoding = System.getProperty("file.encoding");
int numberOfBytesRead = sbc.read(buffer);
System.out.println("Number of bytes read: " + numberOfBytesRead);
while (numberOfBytesRead > 0) {
buffer.rewind();
System.out.print("[" + Charset.forName(encoding). decode(buffer) + "]");
buffer.flip();
numberOfBytesRead = sbc.read(buffer);
System.out.println("\nNumber of bytes read: " + numberOfBytesRead);
}

```

执行应用程序。您的输出应该类似于以下内容：

```java
Contents of File
Number of bytes read: 8
[Bob
Mar]
Number of bytes read: 8
[y
Sally]
Number of bytes read: 8
[
Tom
T]
Number of bytes read: 2
[edTom
T]
Number of bytes read: -1

```

我们首先通过使用`position`方法将`read`重新定位到文件的开头。通过访问`system`属性：`file.encoding`来确定系统的编码字符串。我们跟踪了每次读取操作读取了多少字节，并显示了这个计数。

在 while 循环中，我们通过将其括在一对括号中显示了缓冲区的内容。这样更容易看到读取的内容。`rewind`方法将缓冲区内的位置设置为`0`。这不应与文件内的位置混淆。

要显示实际的缓冲区，我们需要应用`forName`方法来获取`Charset`对象，然后使用`decode`方法将缓冲区中的字节转换为 Unicode 字符。然后是`flip`方法，它将缓冲区的限制设置为当前位置，然后将缓冲区的位置设置为`0`。这为后续读取设置了缓冲区。

您可能希望调整`bufferSize`值，以查看应用程序在不同值下的行为。

##### 使用 SeekableByteChannel 接口向文件写入

`write`方法接受`java.nio`包的`ByteBuffer`对象，并将其写入通道。操作从文件中的当前位置开始。例如，如果文件以追加选项打开，则第一次写入将在文件末尾进行。该方法返回写入的字节数。

在下一个示例中，我们将向`users.txt`文件的末尾追加三个名称。我们使用`StandardOpenOption.APPEND`作为`newByteChannel`方法的打开选项。这将把光标移动到文件的末尾，并从该位置开始写入。创建了一个`ByteBuffer`，其中包含三个名称，由系统行分隔符属性分隔。使用此属性使代码更具可移植性。然后执行`write`方法。

```java
final String newLine = System.getProperty("line.separator");
try (SeekableByteChannel sbc = Files.newByteChannel(path, StandardOpenOption.APPEND)) {
String output = newLine + "Paul" + newLine + "Carol" + newLine + "Fred";
ByteBuffer buffer = ByteBuffer.wrap(output.getBytes());
sbc.write(buffer);
}

```

`users.txt`文件的初始内容应该是：

```java
Bob
Mary
Sally
Tom
Ted

```

将代码序列添加到应用程序并执行该程序。检查`users.txt`文件的内容。现在应该如下所示：

```java
Bob
Mary
Sally
Tom
Ted
Paul
Carol
Fred 

```

##### 查询位置

重载的`position`方法返回一个长值，指示文件内的位置。这由一个接受长参数的`position`方法补充，并将位置设置为该值。如果该值超过流的大小，则位置将设置为流的末尾。`size`方法将返回通道使用的文件的大小。

为了演示这些方法的使用，我们将复制上一节中的示例。这意味着我们将把文件光标定位到`users.txt`文件的末尾，然后在单独的行上写入三个不同的名称。

在下面的代码序列中，我们使用`size`方法来确定文件的大小，然后将此值作为`position`方法的参数。这将把光标移动到文件的末尾。

接下来，创建了三次`ByteBuffer`，并且每次使用不同的名称写入文件。位置是为了信息目的而显示的。

```java
Path path = Paths.get("/home/docs/users.txt");
final String newLine = System.getProperty("line.separator");
try (SeekableByteChannel sbc = Files.newByteChannel(path, StandardOpenOption.WRITE)) {
ByteBuffer buffer;
long position = sbc.size();
sbc.position(position);
System.out.println("Position: " + sbc.position());
buffer = ByteBuffer.wrap((newLine + "Paul").getBytes());
sbc.write(buffer);
System.out.println("Position: " + sbc.position());
buffer = ByteBuffer.wrap((newLine + "Carol").getBytes());
sbc.write(buffer);
System.out.println("Position: " + sbc.position());
buffer = ByteBuffer.wrap((newLine + "Fred").getBytes());
sbc.write(buffer);
System.out.println("Position: " + sbc.position());
}

```

`users.txt`文件的内容应该最初包含：

```java
Bob
Mary
Sally
Tom
Ted

```

将此序列添加到应用程序并执行该程序。检查`users.txt`文件的内容。现在应该如下所示：

**Bob**

**Mary**

**Sally**

**Tom**

**Ted**

**Paul**

**Carol**

**Fred**

#### 另请参阅

在本章中

+   *随后*的*使用 SeekableByteChannel 进行随机访问 IO*配方：此配方简要介绍了用于打开文件的选项

+   *使用 BufferedWriter 类向文件写入*的*使用缓冲 IO 进行文件*配方。

### 使用 AsynchronousServerSocketChannel 类管理异步通信

Java 7 支持服务器和客户端之间的异步通信。`java.nio.channels`包的`AsynchronousServerSocketChannel`类支持以线程安全的方式进行流 IO 的服务器操作。通信是使用充当客户端的`AsynchronousSocketChannel`对象进行的。我们可以一起使用这些类来构建一个以异步方式通信的服务器/客户端应用程序。

#### 准备就绪

需要创建服务器和客户端。要创建服务器：

1.  使用静态的`AsynchronousServerSocketChannel`类的`open`方法来获取`AsynchronousServerSocketChannel`对象的实例

1.  将通道绑定到本地地址和端口号

1.  使用`accept`方法来接受来自客户端的连接请求

1.  在接收到消息时处理消息

要创建客户端：

1.  使用静态的`open`方法创建一个`AsynchronousSocketChannel`对象

1.  为服务器创建一个`InetSocketAddress`对象的实例

1.  连接到服务器

1.  根据需要发送消息

#### 如何做...

我们将创建两个应用程序：一个在服务器上，一个在客户端上。它们将一起支持一个简单的服务器/客户端应用程序，这将解释如何使用`AsynchronousSocketChannel`执行异步通信。 

1.  创建一个新的控制台应用程序，将作为服务器，并添加以下`main`方法。服务器将简单地显示发送到它的任何消息。它打开一个服务器套接字并将其绑定到一个地址。然后，它将使用`accept`方法和`CompletionHandler`来处理来自客户端的任何请求。

```java
public static void main(String[] args) {throws Exception final AsynchronousServerSocketChannel listener = AsynchronousServerSocketChannel.open();
InetSocketAddress address = new InetSocketAddress("localhost", 5000);
listener.bind(address);
listener.accept(null, new CompletionHandler<AsynchronousSocketChannel, Void>() {
public void completed(AsynchronousSocketChannel channel, Void attribute) {
AsynchronousServerSocketChannel classasynchronous communication, managingtry {
System.out.println("Server: completed method executing");
while(true) {
ByteBuffer buffer = ByteBuffer.allocate(32);
Future<Integer> readFuture = channel.read(buffer);
Integer number = readFuture.get();
System.out.println("Server: Message received: " + new String(buffer.array()));
}
} catch (InterruptedException | ExecutionException ex) {
ex.printStackTrace();
}
}
public void failed(Throwable ex, Void atttribute) {
System.out.println("Server: CompletionHandler exception");
ex.printStackTrace();
}
});
while(true) {
// wait — Prevents the program from
// terminating before the client can connect
}
} catch (IOException ex) {
ex.printStackTrace();
}
}

```

1.  接下来，创建一个作为客户端的第二个控制台应用程序。它将使用`open`方法来创建一个`AsynchronousSocketChannel`对象，然后连接到服务器。使用`java.util.concurrent`包的`Future`对象的`get`方法来阻塞，直到连接完成，然后向服务器发送消息。

```java
public static void main(String[] args) {throws Exception try {
AsynchronousSocketChannel client = AsynchronousSocketChannel.open();
InetSocketAddress address = new InetSocketAddress("localhost", 5000);
Future<Void> future = client.connect(address);
System.out.println("Client: Waiting for the connection to complete");
future.get();
AsynchronousServerSocketChannel classasynchronous communication, managingString message;
do {
System.out.print("Enter a message: ");
Scanner scanner = new Scanner(System.in);
message = scanner.nextLine();
System.out.println("Client: Sending ...");
ByteBuffer buffer = ByteBuffer.wrap(message.getBytes());
System.out.println("Client: Message sent: " + new String(buffer.array()));
client.write(buffer);
} while(!"quit".equals(message)) {
}
}

```

您需要执行这两个应用程序。根据您的环境，您可能需要在命令窗口中执行一个应用程序，然后在 IDE 中执行第二个应用程序。如果您一次只能运行一个 IDE 实例，就会出现这种情况。

首先执行服务器应用程序。然后执行客户端应用程序。它应提示您输入消息，然后将消息发送到服务器，在那里将显示。您的输出应该具有以下一般输出。客户端和服务器的输出显示在以下表格中的不同列中：

| 客户端 | 服务器 |
| --- | --- |
| 客户端：等待连接完成输入消息：第一条消息客户端：发送...客户端：消息已发送：第一条消息 |   |
|   | 服务器：完成方法执行中服务器：收到消息：第一条消息 |
| 输入消息：`最优秀的消息`客户端：发送...客户端：消息已发送：最优秀的消息 |  |
|   | 服务器：收到消息：最优秀的消息 |
| 输入消息：`退出`客户端：发送...客户端：消息已发送：退出 |  |
|   | 服务器：收到消息：退出 java.util.concurrent.ExecutionException: java.io.IOException:指定的网络名称不再可用... |

+   请注意，当客户端应用程序终止时，服务器中发生了`ExecutionException`。通常，我们会在生产应用程序中更优雅地处理此异常。

#### 它是如何工作的...

让我们首先检查服务器应用程序。使用`open`方法创建了一个`AsynchronousServerSocketChannel`对象。然后使用`bind`方法将套接字与由系统确定的套接字地址和端口号`5000`关联起来。

接下来，调用`accept`方法来接受一个连接。第一个参数指定了一个`null`值，用于附件。稍后，我们将看到如何使用附件。第二个参数是一个`CompletionHandler`对象。这个对象被创建为一个匿名内部类，当客户端发出通信请求时，它的方法将被调用。

在`completed`方法中，我们显示了一个消息，指示该方法正在执行。然后我们进入了一个无限循环，在循环中我们为一个缓冲区分配了 32 个字节，然后尝试从客户端读取。`read`方法返回了一个`Future`对象，随后我们使用`get`方法。这有效地阻塞了执行，直到客户端发送了一条消息。然后显示了这条消息。

注意`get`方法返回了一个泛型`Future 对象`，类型为`Integer`。我们可以使用这个来确定实际读取了多少字节。这里只是用来阻塞，直到 IO 完成。如果通道通信发生异常，将调用`failed`方法。

在 try 块的末尾进入了一个无限循环，防止服务器终止。这在这里是可以接受的，为了简单起见，但通常我们会以更优雅的方式处理这个问题。

在客户端应用程序中，我们使用`open`方法创建了一个`AsynchronousSocketChannel`对象。创建了一个与服务器对应的网络地址，然后与`connect`方法一起使用以连接到服务器。这个方法返回了一个`Future`对象。我们使用这个对象与`get`方法来阻塞，直到与服务器建立连接。

注意`connect`方法返回了一个`Void`类型的`Future`对象。`Void`类位于`java.lang`包中，是`void`的包装类。这里使用它是因为`connect`方法实际上没有返回任何东西。

进入了一个 while 循环，当用户输入`quit`时终止。用户被提示输入一条消息，然后使用该消息创建了一个`ByteBuffer`对象。然后将缓冲区写入服务器。

注意在两个应用程序的 catch 块中使用了多个异常。这是 Java 7 的新语言改进，可以在第一章的*Catching multiple exception types to improve type checking*中找到。

#### 还有更多...

`bind`方法是重载的。两个版本的第一个参数都是一个`SocketAddress`对象，对应一个本地地址。可以使用`null`值，这将自动分配一个套接字地址。第二个`bind`方法接受一个整数值作为第二个参数。这样可以以实现相关的方式配置允许的最大挂起连接数。小于或等于零的值将使用特定于实现的默认值。

有两个方面的通信技术我们应该注意：

+   在服务器中使用`Future`对象

+   理解`AsynchronousServerSocketChannel`类的选项

##### 在服务器中使用 Future 对象

`AsynchronousServerSocketChannel`类的`accept`方法是重载的。有一个不带参数的方法接受一个连接并返回通道的`Future`对象。`Future`对象的`get`方法将返回一个连接的`AsynchronousSocketChannel`对象。这种方法的优势是返回一个`AsynchronousSocketChannel`对象，可以在其他上下文中使用。

与使用`CompletionHandler`的`accept`方法不同，我们可以使用以下顺序来做同样的事情。注释掉之前的`accept`方法，添加以下代码：

```java
try {
Future<AsynchronousSocketChannel> future = listener.accept();
AsynchronousSocketChannel worker = future.get();
while (true) {
// Wait
stem.out.println("Server: Receiving ...");
ByteBuffer buffer = ByteBuffer.allocate(32);
Future<Integer> readFuture = worker.read(buffer);
Integer number = readFuture.get();
ystem.out.println("Server: Message received: " + new String(buffer.array()));
}
} catch (IOException | InterruptedException | ExecutionException ex) {
ex.printStackTrace();
}

```

再次执行应用程序。你应该得到与之前相同的输出。

##### 理解 AsynchronousServerSocketChannel 类的选项

`supportedOptions`方法返回`AsynchronousServerSocketChannel`类使用的一组选项。`getOption`方法将返回选项的值。在上一个示例中的`bind`方法之后添加以下代码：

```java
Set<SocketOption<?>> options = listener.supportedOptions();
for (SocketOption<?> socketOption : options) {
System.out.println(socketOption.toString() + ": " + listener.getOption(socketOption));
}

```

执行代码。将显示默认值，并且应该类似于以下内容：

```java
SO_RCVBUF: 8192
SO_REUSEADDR: false

```

可以使用`setOption`方法设置选项。此方法接受选项的名称和值。以下说明了如何将接收缓冲区大小设置为 16,384 字节：

```java
listener.setOption(StandardSocketOptions.SO_RCVBUF, 16384);

```

`StandardSocketOptions`类定义了套接字选项。仅支持`AsynchronousServerSocketChannel`通道的`SO_REUSEADDR`和`SO_RCVBUF`选项。

#### 另请参见

+   在本章中：*使用`AsynchronousFileChannel`类从文件中读取*部分的*还有更多*部分：本示例解释了完成处理程序的附件使用以及`AsynchronousChannelGroup`类的使用

### 使用`AsynchronousFileChannel`类写入文件

`java.nio.channels`包的`AsynchronousFileChannel`类允许以异步方式执行文件 IO 操作。当调用 IO 方法时，它将立即返回。实际操作可能会在其他时间发生（可能使用不同的线程）。在本示例中，我们将探讨`AsynchronousFileChannel`类如何执行异步**写**操作。**读**操作将在*使用`AsynchronousFileChannel`类从文件中读取*示例中进行演示。

#### 准备工作

执行写操作：

1.  创建一个代表要从中读取的文件的`Path`对象。

1.  使用此路径和`open`方法打开文件通道。

1.  使用`write`方法向文件写入数据，可以选择使用完成处理程序。

#### 如何做...

在这个例子中，我们将对文件执行一系列写操作。有两个重载的`write`方法。它们的初始参数都是`java.nio`包的`ByteBuffer`，包含要写入的数据，以及指定要写入文件的位置的第二个参数。

两个参数的`write`方法返回一个`java.util.concurrent`包的`Future<Integer>`对象，也可以用于向文件写入，如*还有更多*部分所示。第二个`write`方法有第三个参数，一个附件，和第四个参数，一个`CompletionHandler`对象。当写操作完成时，执行完成处理程序。

1.  创建一个新的控制台应用程序。使用以下`main`方法。我们打开一个名为`asynchronous.txt`的文件进行写入。创建并使用了一个完成处理程序与`write`方法。执行了两次写操作。显示线程信息以解释操作的异步性质以及完成处理程序的工作原理。

```java
public static void main(String[] args) {throws Exception try (AsynchronousFileChannel fileChannel = AsynchronousFileChannel.open(Paths.get( "/home/docs/asynchronous.txt"),
READ, WRITE,
StandardOpenOption.CREATE)) {
CompletionHandler<Integer, Object> handler = new CompletionHandler<Integer, Object>() {
@Override
public void completed(Integer result, Object attachment) {
System.out.println("Attachment: " + attachment + " " + result + " bytes written");
System.out.println("CompletionHandler Thread ID: " + Thread.currentThread().getId());
}
@Override
public void failed(Throwable e, Object attachment) {
System.err.println("Attachment: " + attachment + " failed with:");
e.printStackTrace();
}
};
AsynchronousFileChannel classfile, writing toSystem.out.println("Main Thread ID: " + Thread.currentThread().getId());
fileChannel.write(ByteBuffer.wrap("Sample".getBytes()), 0, "First Write", handler);
fileChannel.write(ByteBuffer.wrap("Box".getBytes()), 0, "Second Write", handler);
}
}

```

1.  执行应用程序。您的应用程序可能不会按您的预期行为。由于操作的异步性质，各个元素的执行顺序可能会因执行而异。以下是一个可能的输出：

```java
Main Thread ID: 1
Attachment: Second Write 3 bytes written
Attachment: First Write 6 bytes written
CompletionHandler Thread ID: 13
CompletionHandler Thread ID: 12

```

重新执行应用程序可能会给出不同的执行顺序。这种行为在下一节中有解释。

#### 它是如何工作的...

我们首先使用`docs`目录中的`asynchronous.txt`文件的`Path`对象创建了一个`AsynchronousFileChannel`对象。该文件被打开以进行读写操作，并且如果文件不存在，则应该被创建。创建了一个`CompletionHandler`对象。在本例中，它用于确认写操作的执行。

`write`方法被执行了两次。第一次将字符串`Sample`从文件的位置`0`开始写入。第二次写操作将字符串`Box`写入文件，也从位置`0`开始。这导致覆盖，文件的内容包含字符串`Boxple`。这是有意的，并且说明了`write`方法的`position`参数的使用。

当前线程的 ID 在代码的各个地方都有显示。它显示了一个线程用于`main`方法，另外两个线程用于内容处理程序。当执行`write`方法时，它是以异步方式执行的。`write`方法执行并立即返回。实际的写操作可能会在稍后发生。写操作完成后，成功完成会导致内容处理程序的`completed`方法执行。这会显示其线程的 ID，并显示一个消息，显示附件和写入的字节数。如果发生异常，将执行`failed`方法。

从输出中可以看到，一个单独的线程被用来执行完成处理程序。完成处理程序被定义为返回一个`Integer`值。这个值代表写入的字节数。附件可以是任何需要的对象。在这种情况下，我们用它来显示哪个`write`方法已经完成。写操作的异步性导致内容处理程序的执行顺序不可预测。然而，`write`方法确实按预期的顺序执行了。

注意使用 try-with-resource 块。这是 Java 7 的一个特性，在第一章的*使用 try-with-resource 块改进异常处理代码*示例中进行了探讨，*Java 语言改进*。

#### 还有更多...

两个参数的`write`方法返回一个`Future<Integer>`对象。稍后在程序中，我们可以使用它的`get`方法，它会阻塞，直到写操作完成。注释掉前面示例的写操作，并用以下代码序列替换它们：

```java
Future<Integer> writeFuture1 = fileChannel.write(ByteBuffer.wrap("Sample".getBytes()), 0);
Future<Integer> writeFuture2 = fileChannel.write(ByteBuffer.wrap("Box".getBytes()), 0);
int result = writeFuture1.get();
System.out.println("Sample write completed with " + result + " bytes written");
result = writeFuture2.get();
System.out.println("Box write completed with " + result + " bytes written");

```

执行应用程序。输出应该类似于以下内容：

```java
Main Thread ID: 1
Sample write completed with 6 bytes written
Box write completed with 3 bytes written 

```

`write`方法返回了一个`Future`对象。`get`方法被阻塞，直到写操作完成。我们用结果来显示一个消息，指示哪个写操作执行了，以及写入了多少字节。

还有许多关于异步文件通道 IO 的方面可以讨论。可能感兴趣的其他方面包括：

+   强制将对通道的更新写入

+   锁定文件的部分或全部以独占方式访问

+   使用`AsynchronousChannelGroup`来管理相关的异步操作

#### 另请参阅

+   在本章*使用 AsynchronousFileChannel 类从文件中读取:* 这个示例演示了如何执行异步读取，并使用`AsynchronousChannelGroup`类。

### 使用 AsynchronousFileChannel 类从文件中读取

也可以使用两个重载的`read`方法来进行异步读取操作。我们将演示如何使用`java.nio.channels`包的`AsynchronousChannelGroup`对象来实现这一点。这将为我们提供一种观察这些方法的方式，并提供一个`AsynchronousChannelGroup`的示例。

#### 准备工作

执行写操作：

1.  创建一个代表要从中读取的文件的`Path`对象。

1.  使用这个路径和`open`方法来打开一个文件通道。

1.  使用`read`方法从文件中读取数据。

#### 如何做...

1.  创建一个新的控制台应用程序。在`main`方法中，创建一个大小为三的`java.util.concurrent`包的`ScheduledThreadPoolExecutor`对象的实例。我们将主要使用`ScheduledThreadPoolExecutor`类，因为它很容易创建。大小为三将有助于说明线程是如何管理的。

```java
ExecutorService pool = new ScheduledThreadPoolExecutor(3);

```

1.  接下来，添加一个 try-with-resource 块，并为文件`items.txt`创建一个`AsynchronousFileChannel`对象。使用`StandardOpenOption.READ`的`open`选项，以及之前创建的 pool 对象。

```java
try (AsynchronousFileChannel fileChannel = AsynchronousFileChannel.open( Paths.get("/home/docs/items.txt"), EnumSet.of(StandardOpenOption.READ), pool)) {

```

1.  接下来，显示主线程 ID，然后创建一个`CompletionHandler`对象，我们将用它来显示异步读操作的结果。

```java
System.out.println("Main Thread ID: " + Thread.currentThread().getId());
CompletionHandler<Integer, ByteBuffer> handler = new CompletionHandler<Integer, ByteBuffer>() {
@Override
public synchronized void completed(Integer result, ByteBuffer attachment) {
for (int i = 0; i < attachment.limit(); i++) {
System.out.print((char) attachment.get(i));
}
System.out.println("");
System.out.println("CompletionHandler Thread ID: " + Thread.currentThread().getId());
System.out.println("");
}
@Override
public void failed(Throwable e, ByteBuffer attachment) {
System.out.println("Failed");
}
};

```

1.  接下来，添加代码来创建一个`ByteBuffer`对象数组。为每个缓冲区分配`10`字节，然后使用一个缓冲区作为`read`方法的第一个参数和附件。将其用作附件，允许我们在完成处理程序中访问读操作的结果。第二个参数指定了起始读取位置，并设置为读取文件的每个 10 字节段。

```java
final int bufferCount = 5;
ByteBuffer buffers[] = new ByteBuffer[bufferCount];
for (int i = 0; i < bufferCount; i++) {
buffers[i] = ByteBuffer.allocate(10);
fileChannel.read(buffers[i], i * 10, buffers[i], handler);
}

```

1.  添加一个调用`awaitTermination`方法，以允许读取操作完成。然后再次显示缓冲区。

```java
pool.awaitTermination(1, TimeUnit.SECONDS);
System.out.println("Byte Buffers");
for (ByteBuffer byteBuffer : buffers) {
for (int i = 0; i < byteBuffer.limit(); i++) {
System.out.print((char) byteBuffer.get(i));
}
System.out.println();
}

```

1.  使用以下内容作为`items.txt`文件的内容，其中每个条目都是一个包含商品和数量的 10 字节序列：

```java
Nail 34Bolt 12Drill 22Hammer 24Auger 24

```

1.  执行应用程序。您的输出应该类似于以下内容：

```java
Main Thread ID: 1
Nail 34
CompletionHandler Thread ID: 10
Drill 22
CompletionHandler Thread ID: 12
Bolt 12
CompletionHandler Thread ID: 11
Auger 24
CompletionHandler Thread ID: 12
Hammer 24
CompletionHandler Thread ID: 10
Byte Buffers
Nail 34
Bolt 12
Drill 22
Hammer 24
Auger 24 

```

注意完成处理程序线程的三个 ID 的使用。这些对应于作为线程池的一部分创建的三个线程。

#### 它的工作原理...

使用大小为三的线程池创建了一个`java.util.concurrent`包的`ExecutorService`，以演示线程组的使用并强制重用线程。`items.txt`文件包含了相等长度的数据。这简化了示例。

在内容处理程序中，成功完成后，将执行`completed`方法。附件包含了缓冲区`read`，然后与内容处理程序的线程 ID 一起显示。请注意`completed`方法中`synchronized`关键字的使用。虽然不是每个方法都需要，但在这里使用了，以使输出更易读。删除关键字将导致缓冲区输出交错，使其无法阅读。

注意完成处理程序线程的非确定性行为。它们并没有按照相应的`read`方法执行的顺序执行。重复执行应用程序应该产生不同的输出。

知道输入文件只包含五个项目，我们创建了五个大小为`10`的`ByteBuffer`对象。`read`方法使用不同的缓冲区执行了五次。

执行了`awaitTermination`方法，有效地暂停了应用程序一秒钟。这允许完成处理程序的线程完成。然后再次显示缓冲区以验证操作。

#### 还有更多...

每当创建一个异步通道时，它都被分配到一个通道组。通过定义自己的组，可以更好地控制组中使用的线程。使用`open`方法创建通道时，它属于全局通道组。

异步通道组提供了完成绑定到组的异步 IO 操作所需的技术。每个组都有一个线程池。这些线程用于 IO 操作和`CompletionHandler`对象。

在上一个例子中，我们使用`open`方法将线程池与异步操作关联起来。也可以使用以下静态`AsynchronousChannelGroup`方法之一来创建异步通道组：

+   `withFixedThreadPool:` 使用`ThreadFactory`创建新线程的固定大小池。池的大小由其第一个参数指定。

+   `withCachedThreadPool:` 这个池使用`ExecutorService`来创建新线程。第二个参数指定了池的建议初始线程数。

+   `withThreadPool:` 这也使用`ExecutorService`，但没有指定初始大小。

异步通道组提供了对组进行有序关闭的能力。一旦关闭被启动：

+   它尝试创建一个新通道的结果是`ShutdownChannelGroupException`

+   运行完成处理程序的线程不会被中断

当组终止时：

+   所有通道都已关闭

+   所有完成处理程序都已经完成

+   所有组资源都已被释放

其他感兴趣的方法包括：

+   `isShutdown`方法，用于确定组是否已关闭。

+   `isTerminated`方法，用于确定组是否已终止。

+   `shutdownNow`方法，用于强制关闭组。所有通道都将关闭，但内容处理程序不会被中断。

#### 另请参阅

在本章中：

+   *使用 AsynchronousFileChannel 类写入文件：*此示例演示了如何执行异步写入

### 使用 SecureDirectoryStream 类

`java.nio.file`包的`SecureDirectoryStream`类设计用于与依赖于比其他 IO 类提供的更严格安全性的应用程序一起使用。它支持在目录上进行无竞争（顺序一致）操作，其中操作与其他应用程序同时进行。

该类需要操作系统的支持。通过将`Files`类的`newDirectoryStream`方法的返回值转换为`SecureDirectoryStream`对象来获取类的实例。如果转换失败，则底层操作系统不支持此类型的流。

#### 准备就绪

获取并使用`SecureDirectoryStream`对象：

1.  创建表示感兴趣目录的`Path`对象。

1.  使用`Files`类的`newDirectoryStream`方法，并将结果转换为`SecureDirectoryStream`。

1.  使用此对象来影响`SecureDirectoryStream`操作。

#### 如何做...

1.  创建一个新的控制台应用程序。在`main`方法中，添加以下代码。我们将为`docs`目录创建一个`Path`对象，然后获取一个`SecureDirectoryStream`对象。这将用于查看目录的 POSIX 权限。

```java
public static void main(String args[]) throws IOException {
Path path = Paths.get("home/docs");
SecureDirectoryStream<Path> sds = (SecureDirectoryStream) Files.newDirectoryStream(path);
PosixFileAttributeView view = sds.getFileAttributeView(PosixFileAttributeView.class);
PosixFileAttributes attributes = view.readAttributes();
Set<PosixFilePermission> permissions = attributes.permissions();
for (PosixFilePermission permission : permissions) {
System.out.print(permission.toString() + ' ');
}
System.out.println();
}

```

1.  在支持`SecureDirectoryStream`类的系统上执行应用程序。在 Ubuntu 系统上运行应用程序后获得以下输出：

```java
GROUP_EXECUTE OWNER_WRITE OWNER_READ OTHERS_EXECUTE GROUP_READ OWNER_EXECUTE OTHERS_READ 

```

##### 工作原理...

获取`docs`目录的`Path`对象，然后将其用作`Files`类的`newDirectoryStream`方法的参数。该方法的结果被转换为`SecureDirectoryStream`类。然后执行`getFileAttributeView`方法以获取一个视图，该视图用于显示目录的 POSIX 文件权限。`PosixFileAttributeView`类的使用在*使用 PosixFileAttributeView 维护 POSIX 文件属性*中有所讨论，在第三章 *获取文件和目录信息*。

##### 还有更多...

SecureDirectoryStream 类支持的其他方法包括删除文件或目录的能力，将文件移动到不同目录的移动方法，以及创建`SeekableByteChannel`以访问文件。
