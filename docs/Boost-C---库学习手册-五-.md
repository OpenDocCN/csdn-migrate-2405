# Boost C++ 库学习手册（五）

> 原文：[`zh.annas-archive.org/md5/9ADEA77D24CFF2D20B546F835360FD23`](https://zh.annas-archive.org/md5/9ADEA77D24CFF2D20B546F835360FD23)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第九章：文件、目录和 IOStreams

为了与操作系统的各种子系统进行交互以利用它们的服务，编写真实世界系统的程序需要。从本章开始，我们将看看各种 Boost 库，这些库提供对操作系统子系统的编程访问。

在本章中，我们将介绍用于执行输入和输出以及与文件系统交互的 Boost 库。我们将在本章的以下部分中介绍这些库：

+   使用 Boost 文件系统管理文件和目录

+   使用 Boost IOStreams 进行可扩展 I/O

使用本章涵盖的库和技术，您将能够编写可移植的 C++程序，与文件系统交互，并使用标准接口执行各种 I/O 操作。本章不涵盖网络 I/O，而是专门讨论第十章*使用 Boost 进行并发*。

# 使用 Boost 文件系统管理文件和目录

使用 Boost 库编写的软件可以在多个操作系统上运行，包括 Linux、Microsoft Windows、Mac OS 和各种其他 BSD 变体。这些操作系统访问文件和目录的路径的方式可能在多种方面有所不同；例如，MS Windows 使用反斜杠作为目录分隔符，而所有 Unix 变体，包括 Linux、BSD 和 Mac，使用正斜杠。非英语操作系统可能使用其他字符作为目录分隔符，有时还支持多个目录分隔符。Boost 文件系统库隐藏了这些特定于平台的特性，并允许您编写更具可移植性的代码。使用 Boost 文件系统库中的函数和类型，您可以编写与操作系统无关的代码，执行应用程序运行所需的文件系统上的常见操作，如复制、重命名和删除文件，遍历目录，创建目录和链接等。

## 操作路径

文件系统路径使用`boost::filesystem::path`类型的对象表示。给定`boost::filesystem::path`类型的对象，我们可以从中获取有用的信息，并从中派生其他`path`对象。`path`对象允许我们对真实的文件系统路径进行建模并从中获取信息，但它不一定代表系统中真正存在的路径。

### 打印路径

让我们看看使用 Boost 文件系统打印进程的当前工作目录的第一个示例：

**清单 9.1：使用 Boost 文件系统的第一个示例**

```cpp
 1 #include <boost/filesystem.hpp>
 2 #include <iostream>
 3
 4 namespace fs = boost::filesystem;
 5
 6 int main() {
 7   // Get the current working directory
 8   fs::path cwd = fs::current_path();
 9
10   // Print the path to stdout
11   std::cout << "generic: " << cwd.generic_string() << '\n';
12   std::cout << "native: " << cwd.string() << '\n';
13   std::cout << "quoted: " << cwd << '\n';
14 
15   std::cout << "Components: \n";
16   for (const auto& dir : cwd) {
17     std::cout <<'[' <<dir.string() << ']'; // each part
18   }
19   std::cout << '\n';
20 }
```

在此示例中，程序通过调用`current_path`（第 8 行）确定其当前工作目录，这是`boost::filesystem`命名空间中的一个命名空间级函数。它返回一个表示当前工作目录的`boost::filesystem::path`类型的对象。`boost::filesystem`中的大多数函数都是在`boost::filesystem::path`对象上而不是字符串上工作。

我们通过调用`path`的`generic_string`成员函数（第 11 行），通过调用`string`成员函数（第 12 行），以及通过将`cwd`，路径对象，流式传输到输出流（第 13 行）来打印路径。`generic_string`成员以**通用格式**返回路径，该格式由 Boost 文件系统支持，使用正斜杠作为分隔符。`string`成员函数以**本机格式**返回路径，这是一个依赖于操作系统的实现定义格式。在 Windows 上，本机格式使用反斜杠作为路径分隔符，而在 UNIX 上，通用格式和本机格式之间没有区别。Boost 文件系统在 Windows 上识别正斜杠和反斜杠作为路径分隔符。

流式传输`path`对象也会以本机格式写入路径，但还会在路径周围加上双引号。在路径中有嵌入空格的情况下，加上双引号可以方便将结果用作命令的参数。如果路径中有嵌入的双引号字符（`"`），则会用和号（`&`）对其进行转义。

在 Windows 上，完整路径以宽字符（`wchar_t`）字符串存储，因此`generic_string`或`string`在执行转换*后*将路径作为`std::string`返回。根据路径中特定的 Unicode 字符，可能无法将路径有意义地转换为单字节字符字符串。在这种系统上，只能安全地调用`generic_wstring`或`wstring`成员函数，它们以通用或本机格式返回路径作为`std::wstring`。

我们使用 C++11 中的范围 for 循环迭代路径中的每个目录组件（第 15 行）。如果范围 for 循环不可用，我们应该使用`path`中的`begin`和`end`成员函数来迭代路径元素。在我的 Windows 系统上，该程序打印以下内容：

```cpp
generic: E:/DATA/Packt/Boost/Draft/Book/Chapter07/examples
native:E:\DATA\Packt\Boost\Draft\Book\Chapter07\examples
quoted: "E:\DATA\Packt\Boost\Draft\Book\Chapter07\examples"
Components:
[E:][/][DATA][Packt] [Boost][Draft][Book][Chapter07][examples]
```

在我的 Ubuntu 系统上，这是我得到的输出：

```cpp
generic: /home/amukher1/devel/c++/book/ch07
native: /home/amukher1/devel/c++/book/ch07
quoted: "/home/amukher1/devel/c++/book/ch07"
Components:
[/][home][amukher1] [devel][c++][book][ch07]
```

该程序以通用格式和本机格式打印其当前工作目录。您可以看到在 Ubuntu 上（以及通常在任何 Unix 系统上）两者之间没有区别。

在 Windows 上，路径的第一个组件是驱动器号，通常称为**根名称**。然后是/（根文件夹）和路径中的每个子目录。在 Unix 上，没有根名称（通常情况下），因此清单以/（根目录）开头，然后是路径中的每个子目录。

类型为`path`的`cwd`对象是可流式传输的（第 19 行），将其打印到标准输出会以本机格式带引号打印出来。

### 注意

**使用 Boost Filesystem 编译和链接示例**

Boost Filesystem 不是一个仅包含头文件的库。Boost Filesystem 共享库作为 Boost 操作系统包的一部分安装，或者根据第一章中描述的方式从源代码构建，*介绍 Boost*。

**在 Linux 上**

如果您使用本机包管理器安装 Boost 库，则可以使用以下命令构建您的程序。请注意，库名称采用系统布局。

```cpp
$ g++ <source>.c -o <executable> -lboost_filesystem -lboost_system

```

如果您按照第一章中所示的方式从源代码构建 Boost，并将其安装在`/opt/boost`下，您可以使用以下命令来编译和链接您的源代码：

```cpp
$ g++ <source>.cpp -c -I/opt/boost/include
$ g++ <source>.o -o <executable> -L/opt/boost/lib -lboost_filesystem-mt -lboost_system-mt -Wl,-rpath,/opt/boost/lib

```

由于我们使用标记布局构建了库，因此我们链接到适当命名的 Boost Filesystem 和 Boost System 版本。`-Wl,-rpath,/opt/boost/lib`部分将 Boost 共享库的路径嵌入生成的可执行文件中，以便运行时链接器知道从哪里获取可执行文件运行所需的共享库。

**在 Windows 上**

在 Windows 上，使用 Visual Studio 2012 或更高版本，您可以启用自动链接，无需显式指定要链接的库。为此，您需要在**项目属性**对话框中编辑**配置属性**设置（在 IDE 中使用*Alt* + *F7*打开）：

1\. 在**VC++目录**下，将`<boost-install-path>\include`追加到**包含目录**属性。

2\. 在**VC++目录**下，将`<boost-install-path>\lib`追加到**库目录**属性。

3\. 在**调试**下，将**环境**属性设置为`PATH=%PATH%;<boost-install-path>\lib`。

4\. 在**C/C++ > 预处理器**下，定义以下预处理器符号：

`BOOST_ALL_DYN_LINK`

`BOOST_AUTO_LINK_TAGGED`（仅在使用标记布局构建时）

5\. 通过从 Visual Studio IDE 中按下*F7*来构建，并通过从 IDE 中按下*Ctrl* + *F5*来运行程序。

### 构建路径

您可以使用`path`构造函数之一或以某种方式组合现有路径来构造`boost::filesystem::path`的实例。字符串和字符串字面值可以隐式转换为`path`对象。您可以构造相对路径和绝对路径，将相对路径转换为绝对路径，从路径中添加或删除元素，并“规范化”路径，如清单 9.2 所示：

**清单 9.2a：构造空路径对象**

```cpp
 1 #define BOOST_FILESYSTEM_NO_DEPRECATED
 2 #include <boost/filesystem.hpp>
 3 #include <iostream>
 4 #include <cassert>
 5 namespace fs = boost::filesystem;
 6 
 7 int main() {
 8   fs::path p1; // empty path
 9   assert(p1.empty());  // does not fire
10   p1 = "/opt/boost";   // assign an absolute path
11   assert(!p1.empty());
12   p1.clear();
13   assert(p1.empty());
14 }
```

一个默认构造的路径对象表示一个空路径，就像前面的例子所示。你可以将一个路径字符串赋给一个空的`path`对象（第 10 行），它就不再是空的了（第 11 行）。在路径上调用`clear`成员函数（第 12 行）后，它再次变为空（第 13 行）。多年来，Boost 文件系统库的一些部分已经被弃用，并被更好的替代品所取代。我们定义宏`BOOST_FILESYSTEM_NO_DEPRECATED`（第 1 行）以确保这些弃用的成员函数和类型不可访问。

**清单 9.2b：构造相对路径**

```cpp
15 void make_relative_paths() {
16   fs::path p2(".."); // relative path
17   p2 /= "..";
18   std::cout << "Relative path: " << p2.string() << '\n';
19
20   std::cout << "Absolute path: "
21      << fs::absolute(p2, "E:\\DATA\\photos").string() << '\n';
22   std::cout << "Absolute path wrt CWD: "
23             << fs::absolute(p2).string() << '\n';
24
25   std::cout << fs::canonical(p2).string() << '\n';
26 }
27
```

我们使用`..`（双点）构造了一个相对路径，这是一种在大多数文件系统上引用父目录的常见方式（第 16 行）。然后我们使用`operator/=`来将额外的`..`路径元素附加到相对路径（第 17 行）。然后我们以其原生格式打印相对路径（第 18 行），并使用这个相对路径创建绝对路径。

`boost::filesystem::absolute`函数根据相对路径构造绝对路径。你可以将一个绝对路径传递给它，以便将相对路径附加到构造一个新的绝对路径（第 21 行）。请注意，我们传递了一个 Windows 绝对路径，并确保转义了反斜杠。如果省略`absolute`的第二个参数，它将使用进程的当前工作目录作为基本路径从相对路径构造绝对路径（第 23 行）。

例如，文件路径`/opt/boost/lib/../include`可以被*规范化*为等效形式`/opt/boost/include`。函数`boost::filesystem::canonical`从给定路径生成一个**规范化的绝对路径**（第 25 行），但要求路径存在。否则，它会抛出一个需要处理的异常。它还会读取并遵循路径中的任何符号链接。前面的代码在我的 Windows 系统上打印了以下输出：

```cpp
Relative path: ..\..
Absolute path: E:\DATA\photos\..\..
Absolute path wrt CWD: E:\DATA\Packt\Boost\Draft\Book\Chapter07\examples\..\..
Canonical: E:/DATA\Packt\Boost\Draft\Book
```

请注意，规范路径的输出中双点已经被折叠。

**清单 9.2c：处理错误**

```cpp
28 void handle_canonical_errors() {
29   fs::path p3 = "E:\\DATA"; // absolute path
30   auto p4 = p3 / "boost" / "boost_1_56";  // append elements
31   std::cout << p4.string() << '\n';
32   std::cout.put('\n');
33
34   boost::system::error_code ec;
35   auto p5 = p4 / ".." / "boost_1_100";  // append elements
36   auto p6 = canonical(p5, ec);
37
38   if (ec.value() == 0) {
39     std::cout << "Normalized: " << p6.string() << '\n';
40   } else {
41     std::cout << "Error (file=" << p5.string()
42           << ") (code=" << ec.value() << "): "
43           << ec.message() << '\n';
44   }
45 }
```

这个例子说明了当`canonical`被传递一个不存在的路径时会出错。我们创建了一个路径对象`p3`，表示 Windows 上的绝对路径`E:\DATA`（第 29 行）。然后我们通过使用`operator/`为`path`对象（第 30 行）连续添加路径元素（`boost`和`boost_1_56`）来创建第二个路径对象`p4`。这构造了一个等同于`E:\DATA\boost\boost_1_56`的路径。

接下来，我们将相对路径`../boost_1_100`附加到`p4`（第 35 行），这构造了一个等同于`E:\DATA\boost\boost_1_56\..\boost_1_100`的路径。这个路径在我的系统上不存在，所以当我在这个路径上调用`canonical`时，它会出错。请注意，我们将`boost::system::error_code`类型的对象作为`canonical`的第二个参数传递，以捕获任何错误。我们使用`error_code`的`value`成员函数（第 38 行）来检查返回的非零错误代码。如果发生错误，我们还可以使用`message`成员函数（第 43 行）检索系统定义的描述性错误消息。或者，我们可以调用`canonical`的另一个重载，它不接受`error_code`引用作为参数，而是在路径不存在时抛出异常。抛出异常和不抛出异常的重载是在文件系统库和其他来自 Boost 的系统编程库中常见的模式。

### 将路径分解为组件

在前一节中，我们看到了如何通过调用`parent_path`成员函数来获取路径的父目录。实际上，在`boost::filesystem::path`中有一整套成员函数可以提取路径中的组件。让我们首先看一下路径及其组件。

我们将首先了解 Boost 文件系统术语中关于路径组件的概念，使用来自 UNIX 系统的以下路径：

`/opt/boost/include/boost/filesystem/path.hpp`

前导`/`称为**根目录**。最后一个组件`path.hpp`称为**文件名**，即使路径表示的是目录而不是常规文件。剥离了文件名的路径（`/opt/boost/include/boost/filesystem`）称为**父路径**。在前导斜杠之后的部分（`opt/boost/include/boost/filesystem/path.hpp`）称为**相对路径**。

在前面的示例中，`.hpp`是**扩展名**（包括句点或点），`path`是文件名的**主干**。对于具有多个嵌入点的文件名（例如，`libboost_filesystem-mt.so.1.56.0`），扩展名被认为从最后（最右边）的点开始。

现在考虑以下 Windows 路径：

`E:\DATA\boost\include\boost\filesystem\path.hpp`

组件`E:`称为**根名称**。在`E:`后面的前导反斜杠称为**根目录**。根名称与根目录（`E:\`）的连接称为**根路径**。以下是一个打印路径的不同组件的简短函数，使用`boost::filesystem::path`的成员函数：

**清单 9.3：将路径拆分为组件**

```cpp
 1 #include <boost/filesystem.hpp>
 2 #include <iostream>
 3 #include <cassert>
 4 namespace fs = boost::filesystem;
 5
 6 void printPathParts(const fs::path& p1)
 7 {
 8 std::cout << "For path: " << p1.string() << '\n';
 9
10   if (p1.is_relative()) {
11     std::cout << "\tPath is relative\n";
12   } else {
13     assert(p1.is_absolute());
14     std::cout << "\tPath is absolute\n";
15   }
16
17   if (p1.has_root_name())
18     std::cout << "Root name: "
19               << p1.root_name().string() << '\n';
20
21   if (p1.has_root_directory())
22     std::cout << "Root directory: "
23               << p1.root_directory().string() << '\n';
24
25   if (p1.has_root_path())
26     std::cout << "Root path: "
27               << p1.root_path().string() << '\n';
28
29   if (p1.has_parent_path())
30     std::cout << "Parent path: "
31               << p1.parent_path().string() << '\n';
32
33   if (p1.has_relative_path())
34     std::cout << "Relative path: "
35               << p1.relative_path().string() << '\n';
36
37   if (p1.has_filename())
38     std::cout << "File name: "
39               << p1.filename().string() << '\n';
40
41   if (p1.has_extension())
42     std::cout << "Extension: "
43               << p1.extension().string() << '\n';
44
45   if (p1.has_stem())
46     std::cout << "Stem: " << p1.stem().string() << '\n';
47
48   std::cout << '\n';
49 }
50
51 int main()
52 {
53   printPathParts ("");                    // no components
54   printPathParts ("E:\\DATA\\books.txt"); // all components
55   printPathParts ("/root/favs.txt");      // no root name
56   printPathParts ("\\DATA\\books.txt");   // Windows, relative
57   printPathParts ("boost");              // no rootdir, no extn
58   printPathParts (".boost");              // no stem, only extn
59   printPathParts ("..");                  // no extension
60   printPathParts (".");                   // no extension
61   printPathParts ("/opt/boost/");         // file name == .
62 }
```

在前面的示例中，函数`printPathParts`（第 6 行）打印路径的尽可能多的组件。要访问路径组件，它使用`path`的相应成员函数。要检查组件是否可用，它使用`path`的`has_`成员函数之一。它还使用`path`的`is_relative`和`is_absolute`成员函数（第 10 行，第 13 行）检查路径是相对路径还是绝对路径。

我们使用不同的相对路径和绝对路径调用`printPathParts`。结果可能因操作系统而异。例如，在 Windows 上，对`has_root_name`（第 17 行）的调用对除了 Windows 路径`E:\DATA\books.txt`（第 54 行）之外的所有路径返回`false`，这被认为是绝对路径。对此路径调用`root_name`返回`E:`。然而，在 UNIX 上，反斜杠不被识别为分隔符，被认为是路径组件的一部分，因此`E:\DATA\books.txt`将被解释为具有文件名`E:\DATA\books.txt`的相对路径，主干`E:\DATA\books`和扩展名`.txt`。这，再加上在 Windows 上正斜杠被识别为路径分隔符的事实，是绝对不要像我们在这里所做的那样在路径文字中使用反斜杠的一个很好的理由。

### 注意

为了最大的可移植性，在路径文字中始终使用正斜杠，或者使用重载的`operator/`和`operator/=`生成路径。

我们还可以比较两个路径，看它们是否**相等**和**等效**。可以使用重载的`operator==`来比较两个路径是否相等，只有当两个路径可以分解为相同的组件时才返回`true`。请注意，这意味着路径`/opt`和`/opt/`不相等；在前者中，文件名组件是`opt`，而在后者中，它是`.`（点）。如果两个路径不相等，但仍然可以等效，如果它们表示相同的底层文件系统条目。例如，`/opt/boost`和`/opt/cmake/../boost/`虽然不是相等路径，但它们是等效的。要计算等效性，我们可以使用`boost::filesystem::equivalent`函数，如果两个路径引用文件系统中的相同条目，则返回`true`：

```cpp
boost::filesystem::path p1("/opt/boost"), p2("/opt/cmake");
if (boost::filesystem::equivalent(p1, p2 / ".." / "boost") {
  std::cout << "The two paths are equivalent\n";
}
```

与`boost::filesystem::canonical`一样，`equivalent`函数实际上也检查路径的存在，并且如果任一路径不存在则抛出异常。还有一个不会抛出异常而是设置`boost::system::error_code`输出参数的重载。

`path`对象可以被视为路径元素的序列容器，这些元素可以通过`path`公开的迭代器接口进行迭代。这允许将几个标准算法轻松应用于`path`对象。要遍历每个路径元素，我们可以使用以下代码片段：

```cpp
boost::filesystem::path p1("/opt/boost/include/boost/thread.hpp");
for (const auto& pathElem: p1) {
  std::cout <<pathElem.string() <<"  ";
}
```

这将打印由一对空格分隔的组件：

`/ optboost include boost thread.hpp`

`boost::filesystem::path`的`begin`和`end`成员函数返回类型为`boost::filesystem::path::iterator`的随机访问迭代器，您可以以有趣的方式与标准库算法一起使用。例如，要找到路径中的组件数，您可以使用：

```cpp
size_t count = std::distance(p1.begin(), p1.end());

```

现在，考虑两个路径：`/opt/boost/include/boost/filesystem/path.hpp`和`/opt/boost/include/boost/thread/detail/thread.hpp`。我们现在将编写一个函数，计算这两个路径所在的公共子目录：

第 9.4 节：查找公共前缀路径

```cpp
 1 #include <boost/filesystem.hpp>
 2 #include <iostream>
 3 namespace fs = boost::filesystem;
 4
 5 fs::path commonPrefix(const fs::path& first,
 6                       const fs::path& second) {
 7   auto prefix =
 8     [](const fs::path& p1, const fs::path& p2) {
 9       auto result =
10         std::mismatch(p1.begin(), p1.end(), p2.begin());
11       fs::path ret;
12       std::for_each(p2.begin(), result.second,
13               &ret {
14               ret /= p;
15               });
16       return ret;
17     };
18
19   size_t n1 = std::distance(first.begin(), first.end());
20   size_t n2 = std::distance(second.begin(), second.end());
21 
22   return (n1 < n2) ? prefix(first, second)
23                    : prefix(second, first);
24 }
```

在这两个路径上调用`commonPrefix`函数会正确返回`/opt/boost/include/boost`。为了使该函数正确工作，我们应该传递不包含`.`或`..`组件的路径，一个更完整的实现可以处理这个问题。为了计算前缀，我们首先使用 lambda 表达式定义了一个名为`prefix`的嵌套函数（第 7-17 行），它执行实际的计算。我们计算了两个路径的元素计数（第 19、20 行），并将较短的路径作为第一个参数，较长的路径作为第二个参数传递给`prefix`函数（第 22-23 行）。在`prefix`函数中，我们使用`std::mismatch`算法在两个路径上计算它们不匹配的第一个组件（第 10 行）。然后我们构造公共前缀作为直到第一个不匹配的路径，并返回它（第 12-15 行）。

## 遍历目录

Boost Filesystem 提供了两个迭代器类，`directory_iterator`和`recursive_directory_iterator`，使得遍历目录变得相当简单。两者都符合**输入迭代器**概念，并提供了用于向前遍历的`operator++`。在这里的第一个例子中，我们看到了`directory_iterator`的使用：

第 9.5 节：迭代目录

```cpp
 1 #include <boost/filesystem.hpp>
 2 #include <iostream>
 3 #include <algorithm>
 4 namespace fs = boost::filesystem;
 5
 6 void traverse(const fs::path& dirpath) {
 7   if (!exists(dirpath) || !is_directory(dirpath)) {
 8     return;
 9   }
10
11   fs::directory_iterator dirit(dirpath), end;
12
13   std::for_each(dirit, end, [](const fs::directory_entry& entry) {
14           std::cout <<entry.path().string() << '\n';
15         });
16 }
17
18 int main(int argc, char *argv[1]) {
19   if (argc > 1) {
20     traverse(argv[1]);
21   }
22 }
```

`traverse`函数接受一个类型为`boost::filesystem::path`的参数`dirpath`，表示要遍历的目录。使用命名空间级别的函数`exists`和`is_directory`（第 7 行），函数检查`dirpath`是否实际存在并且是一个目录，然后再继续。

为了执行迭代，我们为路径创建了一个`boost::filesystem::directory_iterator`的实例`dirit`，并创建了一个名为`end`的第二个默认构造的`directory_iterator`实例（第 11 行）。默认构造的`directory_iterator`充当了序列结束标记。对类型为`directory_iterator`的有效迭代器进行解引用会返回一个类型为`boost::filesystem::directory_entry`的对象。由迭代器范围`dirit`，`end`)表示的序列是目录中的条目列表。为了遍历它们，我们使用熟悉的`std::for_each`标准算法。我们使用 lambda 来定义对每个条目执行的操作，即简单地将其打印到标准输出（第 13-14 行）。

虽然我们可以围绕`boost::directory_iterator`编写递归逻辑来递归地遍历目录树，但`boost::recursive_directory_iterator`提供了一个更简单的替代方法。我们可以在第 9.5 节中用`boost::recursive_directory_iterator`替换`boost::directory_iterator`，它仍然可以工作，对目录树进行深度优先遍历。但是`recursive_directory_iterator`接口提供了额外的功能，比如跳过特定目录的下降和跟踪下降的深度。手写循环更好地利用了这些功能，如下例所示：

第 9.6 节：递归迭代目录

```cpp
 1 void traverseRecursive(const fs::path& path)
 2 {
 3   if (!exists(path) || !is_directory(path)) {
 4     return;
 5   }
 6
 7   try {
 8     fs::recursive_directory_iterator it(path), end;
 9
10     while (it != end) {
11       printFileProperties(*it, it.level());
12
13       if (!is_symlink(it->path())
14           && is_directory(it->path())
15           && it->path().filename() == "foo") {
16           it.no_push();
17       }
18       boost::system::error_code ec;
19       it.increment(ec);
21       if (ec) {
22         std::cerr << "Skipping entry: "
23                   << ec.message() << '\n';
24       }
25     }
26   } catch (std::exception& e) {
27     std::cout << "Exception caught: " << e.what() << '\n';
28   }
29 }
```

我们创建了一个`recursive_directory_iterator`并用一个路径初始化它（第 8 行），就像我们在第 9.5 节中为`directory_iterator`做的那样。如果路径不存在或程序无法读取，`recursive_directory_iterator`构造函数可能会抛出异常。为了捕获这种异常，我们将代码放在`try-catch`块中。

我们使用 while 循环来遍历条目（第 10 行），并通过调用`increment`成员函数（第 19 行）来推进迭代器。当`increment`成员函数遇到目录时，它会尝试按深度优先顺序进入该目录。这有时可能会由于系统问题而失败，比如当程序没有足够的权限查看目录时。在这种情况下，我们希望继续到下一个可用的条目，而不是中止迭代。因此，我们不在迭代器上使用`operator++`，因为当它遇到错误时会抛出异常，处理这种情况会使代码变得更加复杂。`increment`函数接受一个`boost::system::error_code`参数，在出现错误时设置`error_code`并推进迭代器到下一个条目。在这种情况下，我们可以使用`error_code`的`message`成员函数获取与错误相关的系统定义的错误消息。

### 注意

**boost::filesystem::recursive_directory_iterator 的行为**

在 Boost 版本 1.56 之前，当`operator++`和`increment`成员函数遇到错误时，它们只会抛出异常或设置`error_code`，而不会推进迭代器。这使得编写一个正确的循环以跳过错误变得更加复杂。从 Boost 1.56 开始，这些函数还会将迭代器推进到下一个条目，使循环代码变得简单得多。

我们通过调用一个虚构的函数`printFileProperties`（第 11 行）来处理每个条目，该函数接受两个参数——解引用`recursive_directory_iterator`实例的结果，以及通过调用迭代器的`level`成员函数获得的遍历深度。`level`函数对于一级目录返回零，并且对于每个额外的下降级别，其返回值递增 1。`printFileProperties`函数可以利用这一点来缩进子目录中的条目，例如。我们将在下一节中实现`printFileProperties`函数。

为了给这个例子增加维度，我们决定不进入名为`foo`的目录。为此，我们检查名为`foo`的目录（第 13-15 行），并在`recursive_directory_iterator`上调用`no_push`成员函数以防止进入该目录（第 16 行）。同样，我们可以随时调用迭代器的`pop`成员函数来在目录树中上升一级，而不一定要在当前级别完成迭代。

在支持符号链接的系统上，如果`recursive_directory_iterator`遇到指向目录的符号链接，它不会跟随链接进入目录。如果我们想要覆盖这种行为，我们应该向`recursive_directory_iterator`构造函数传递`boost::filesystem::symlink_option`枚举类型的第二个参数。`symlink_option`枚举提供了`none`（或`no_recurse`）（默认值）和`recurse`两个值，表示应该跟随符号链接进入目录。

## 查询文件系统条目

Boost Filesystem 提供了一组函数来对文件和目录执行有用的操作。其中大多数是`boost::filesystem`命名空间中的函数。使用这些函数，我们可以检查文件是否存在、其大小（以字节为单位）、最后修改时间、文件类型、是否为空等等。我们使用这些函数来编写我们在前一节中使用的`printFileProperties`函数：

**清单 9.7：查询文件系统条目**

```cpp
 1 #include <boost/filesystem.hpp>
 2 #include <iostream>
 3 #include <boost/date_time.hpp>
 4 namespace fs = boost::filesystem;
 5 namespace pxtm = boost::posix_time;
 6
 7 void printFileProperties(const fs::directory_entry& entry,
 8                          int indent = 0) {
 9   const fs::path& path= entry.path();
10   fs::file_status stat = entry.symlink_status();
11   std::cout << std::string(2*indent, '');
12
13   try {
14     if (is_symlink(path)) {
15       auto origin = read_symlink(path);
16       std::cout <<" L " << " -  - "
17                 << path.filename().string() << " -> "
18                 << origin.string();
19     } else if (is_regular_file(path)) {
20       std::cout << " F " << " "
21          << file_size(path) << " " << " "
22          << pxtm::from_time_t(last_write_time(path))
23          << " " << path.filename().string();
24     } else if (is_directory(path)) {
25       std::cout << " D " << " – " << " "
26 << pxtm::from_time_t(last_write_time(path))
27 << " " << path.filename().string();
28     } else {
29       switch (stat.type()) {
30       case fs::character_file:
31         std::cout << " C ";
32         break;
33       case fs::block_file:
34         std::cout << " B ";
35         break;
36       case fs::fifo_file:
37         std::cout << " P ";
38         break;
39       case fs::socket_file:
40         std::cout << " S ";
41         break;
42       default:
43         std::cout << " - ";
44         break;
45       }
46       std::cout << pxtm::from_time_t(last_write_time(path))
47                 << " ";
48       std::cout << path.filename().string();
49     }
50     std::cout << '\n';
51   } catch (std::exception& e) {
52     std::cerr << "Exception caught: " <<e.what() << '\n';
53   }
54 }
```

`printFileProperties`用于打印给定文件的简短摘要，包括类型、大小、最后修改时间、名称，以及对于符号链接，目标文件。这个函数的第一个参数是`directory_entry`类型，是对`directory_iterator`或`recursive_directory_iterator`的解引用的结果。我们通过调用`directory_entry`的`path`成员函数（第 9 行）获取到`directory_entry`对象引用的文件的路径。我们通过调用`directory_entry`的`symlink_status`成员函数（第 10 行）获取到`file_status`对象的引用。`file_status`对象包含有关文件系统条目的其他详细信息，我们在示例中使用它来打印特殊文件的状态。`symlink_status`函数作用于所有类型的文件，而不仅仅是符号链接，但它返回的是符号链接本身的状态，而不是跟随它到目标的状态。如果你需要每次查询符号链接时都需要目标的状态，使用`status`成员函数而不是`symlink_status`。`status`和`symlink_status`成员函数比同名的全局函数更快，因为它们会缓存文件状态，而不是在每次调用时查询文件系统。

在打印适合类型的信息之前，我们确定每个条目的类型。为此，我们使用方便的函数`is_symlink`、`is_regular_file`和`is_directory`（第 14、19、24 行）。在像 Linux 这样的 POSIX 系统上，还有其他类型的文件，如块和字符设备、管道和 Unix 域套接字。为了识别这些文件，我们使用之前获得的`file_status`对象（第 10 行）。我们调用`file_status`对象的`type`成员函数来确定特殊文件的确切类型（第 29 行）。请注意，我们首先检查文件是否是符号链接，然后进行其他测试。这是因为`is_regular_file`或`is_directory`对于目标文件的类型也可能返回 true，基于目标文件的类型。

这个函数以以下格式打印每个条目：

```cpp
file_type  sizetime  name -> target
```

文件类型由单个字母表示（`D`：目录，`F`：普通文件，`L`：符号链接，`C`：字符设备，`B`：块设备，`P`：管道，`S`：Unix 域套接字）。大小以字节为单位打印，最后修改时间以长整数形式打印，文件名打印时不包含完整路径。只有对于符号链接，名称后面会附加一个指向目标路径的箭头。当文件大小或最后写入时间不可用时，缺少字段会显示为连字符（`-`）。对于每个下降级别，条目都会缩进两个额外的空格（第 11 行）。

这是在我的 Linux 系统上运行此函数的示例输出：

![查询文件系统条目](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-boost-cpp-lib/img/1217OT_09_04.jpg)

你也可以在 Linux 的`/dev`目录上运行这个程序，看看设备文件是如何列出的。

调用`read_symlink`函数（第 15 行）来获取符号链接指向的目标文件。调用`file_size`函数（第 21 行）获取文件的大小（以字节为单位），调用`last_write_time`函数（第 22、26 和 46 行）获取文件的最后修改时间。`last_write_time`函数返回文件最后修改的**Unix 时间**。

我们通过调用`boost::posix_time::from_time_t`函数将这个数字时间戳转换为可打印的日期时间字符串来打印这个时间戳的有意义的表示（参见第七章，“高阶和编译时编程”）。为了构建这个程序，你还必须链接 Boost DateTime 库，如下所示：

```cpp
$ g++ listing8_7.cpp -o listing8_7 -std=c++11 -lboost_filesystem -lboost_date_time
```

文件系统中有几个这样的函数，用于查询文件系统中对象的不同类型的信息，例如查找文件的硬链接数。我们可以查询`file_status`对象（第 10 行）以获取文件权限。请注意，我们不需要在命名空间级别函数中加上命名空间；它们会根据参数的类型正确解析，使用基于参数类型的参数相关查找（Argument Dependent Lookup）。

## 对文件执行操作

除了查询文件系统条目的信息之外，我们还可以使用 Boost 文件系统库对文件执行操作，如创建目录和链接，复制文件和移动文件等。

### 创建目录

使用函数`boost::filesystem::create_directory`很容易创建目录。传递一个路径给它，如果该路径上不存在目录，则会在该路径上创建一个目录；如果目录已经存在，则不会执行任何操作。如果路径存在但不是一个目录，`create_directory`会抛出一个异常。还有一个非抛出版本，它接受一个`boost::system::error_code`引用，在错误时设置错误代码。这些函数如果创建了目录则返回`true`，如果没有则返回`false`：

**清单 9.8：创建目录**

```cpp 
 1 #include <boost/filesystem.hpp> 
 2 #include <iostream> 
 3 #include <cassert>	 
 4 namespace fs = boost::filesystem; 
 5 
 6 int main() { 
 7   fs::path p1 = "notpresent/dirtest"; 
 8   boost::system::error_code ec; 
 9   if (!is_directory(p1.parent_path()) || exists(p1)) {
10     assert( !create_directory(p1, ec) );
11
12     if (is_directory(p1)) assert(!ec.value());
13     else assert(ec.value());
14   }
15
16   try {
17     if (create_directories(p1)) {
18       assert( !create_directory(p1) );
19     }
20   } catch (std::exception& e) {
21     std::cout << "Exception caught: " << e.what() << '\n';
22   }
23 }
```

在这个例子中，相对于当前目录在路径`notpresent/dirtest`上调用`create_directory`失败（第 10 行），如果当前目录中没有名为`notpresent`的目录，或者`notpresent/dirtest`已经存在。这是因为`create_directory`期望传递的路径的父目录存在，并且不会创建已经存在的路径。如果我们没有传递错误代码参数，这次对`create_directory`的调用将会抛出一个需要处理的异常。如果`notpresent/dirtest`已经存在并且是一个目录，那么`create_directory`会失败，但不会设置错误代码（第 12 行）。

函数`boost::filesystem::create_directories`创建所需的所有路径组件，类似于 Unix 系统上的`mkdir -p`。对它的调用（第 17 行）除非存在权限问题或路径已经存在，否则会成功。它创建目录，包括沿路径缺失的任何目录。对`create_directory`和`create_directories`的调用是幂等的；如果目标目录存在，不会返回错误或抛出异常，但函数会返回`false`，因为没有创建新目录。

### 创建符号链接

符号链接，有时被称为软链接，是文件系统中的条目，类似于其他文件的别名。它们可以引用文件以及目录，并经常用于为文件和目录提供替代的简化名称和路径。符号链接在UNIX系统上已经存在了相当长的时间，并且自Windows 2000以来在Windows上以某种形式可用。我们可以使用函数`boost::filesystem::create_symlink`来创建符号链接。对于创建指向目录的符号链接，建议使用函数`boost::filesystem::create_directory_symlink`以获得更好的可移植性。

**清单9.9：创建符号链接**

```cpp
 1 #include <boost/filesystem.hpp>
 2 namespace fs = boost::filesystem; 
 3 
 4 void makeSymLink(const fs::path& target, const fs::path& link) { 
 5   boost::system::error_code ec; 
 6  
 7   if (is_directory(target)) { 
 8     create_directory_symlink(target, link); 
 9   } else {
10     create_symlink(target, link);
11   }
12 }
```
这显示了一个名为`makeSymLink`的函数，它创建指向给定路径的符号链接。函数的第一个参数是链接必须别名的目标路径，第二个参数是链接本身的路径。这种参数顺序让人联想到UNIX的`ln`命令。如果目标是目录，此函数调用`create_directory_symlink`（第8行），而对于所有其他情况，它调用`create_symlink`（第10行）。请注意，目标路径在创建符号链接时不需要存在，在这种情况下将创建悬空的符号链接。调用这些函数的效果与在POSIX系统上运行`ln -s target link`命令相同。在Windows上，当`target`是目录时，通过运行`mklink /D link target`命令可以获得相同的效果，当`target`不是目录时，通过运行`mklink link target`命令可以获得相同的效果。如果`create_directory_symlink`或`create_symlink`抛出异常，函数`makeSymLink`将抛出异常。

### 复制文件

复制文件是Boost文件系统中的另一个常见任务。`boost::filesystem::copy_file`函数将常规文件从源复制到目标，并且如果目标处已存在该文件，则会失败。使用适当的覆盖，可以使其覆盖目标处的文件。`boost::filesystem::copy_symlink`接受源符号链接并在目标处创建第二个符号链接，它别名与源相同的文件。您不能将目录传递给任何一个函数作为目标。还有一个`boost::copy_directory`函数，似乎并不做其名称所示的事情。它创建目录并将源目录的属性复制到目标目录。因此，我们将推出我们自己的递归目录复制实用程序函数：

第9.10节：递归复制目录

```cpp 
 1 void copyDirectory(const fs::path& src, const fs::path& target) { 
 2   if (!is_directory(src) 
 3     || (exists(target) && !is_directory(target)) 
 4     || !is_directory(absolute(target).parent_path()) 
 5     || commonPrefix(src, target) == src) { 
 6     throw std::runtime_error("Preconditions not satisfied"); 
 7   } 
 8 
 9   boost::system::error_code ec;
10   fs::path effectiveTarget = target;
11   if (exists(target)) {
12     effectiveTarget /= src.filename();
13   }
14   create_directory(effectiveTarget);
15
16   fs::directory_iterator iter(src), end;
17   while (iter != end) {
18     auto status = iter->symlink_status();
19     auto currentTarget = effectiveTarget/
20                               iter->path().filename();
21
22     if (status.type() == fs::regular_file) {
23       copy_file(*iter, currentTarget,
24                     fs::copy_option::overwrite_if_exists);
25     } else if (status.type() == fs::symlink_file) {
26       copy_symlink(*iter, currentTarget);
27     } else if (status.type() == fs::directory_file) {
28       copyDirectory(*iter, effectiveTarget);
29     } // else do nothing
30     ++iter;
31   }
32 }
```
第9.10节定义了`copyDirectory`函数，该函数递归地将源目录复制到目标目录。它执行基本验证，并在不满足必要的初始条件时抛出异常（第6行）。如果以下任何条件为真，则违反了必要的前提条件：

1.  源路径不是目录（第2行）

1.  目标路径存在，但不是目录（第3行）

1.  目标路径的父目录不是目录（第4行）

1.  目标路径是源路径的子目录（第5行）

为了检测违反4，我们重用了第9.4节中定义的`commonPrefix`函数。如果目标路径已经存在，则在其下创建与源目录同名的子目录以容纳复制的内容（第11-12行，14行）。否则，将创建目标目录并将内容复制到其中。

除此之外，我们使用`directory_iterator`而不是`recursive_directory_iterator`（第17行）来递归迭代源目录。我们使用`copy_file`来复制常规文件，传递`copy_option::overwrite_if_exists`选项以确保已存在的目标文件被覆盖（第23-24行）。我们使用`copy_symlink`来复制符号链接（第26行）。每次遇到子目录时，我们递归调用`copyDirectory`（第28行）。如果从`copyDirectory`调用的Boost文件系统函数抛出异常，它将终止复制。

### 移动和删除文件

您可以使用`boost::filesystem::rename`函数移动或重命名文件和目录，该函数以旧路径和新路径作为参数。两个参数的重载如果失败会抛出异常，而三个参数的重载则设置错误代码：

```cpp
void rename(const path& old_path, const path& new_path);
void rename(const path& old_path, const path& new_path,
            error_code& ec);
```

如果`new_path`不存在，且其父目录存在，则会创建它；否则，重命名调用失败。如果`old_path`不是目录，则`new_path`如果存在，也不能是目录。如果`old_path`是目录，则`new_path`如果存在，必须是一个空目录，否则函数失败。当一个目录被移动到另一个空目录时，源目录的内容被复制到目标空目录内，然后源目录被删除。重命名符号链接会影响链接本身，而不是它们所指向的文件。

您可以通过调用`boost::filesystem::remove`并传递文件系统条目的路径来删除文件和空目录。要递归删除一个非空目录，必须调用`boost::filesystem::remove_all`。

```cpp
bool remove(const path& p);
bool remove(const path& p, error_code& ec);
uintmax_t remove_all(const path& p);
uintmax_t remove_all(const path& p, error_code& ec);
```

如果路径指定的文件不存在，`remove`函数返回false。这会删除符号链接而不影响它们所指向的文件。`remove_all`函数返回它删除的条目总数。在错误情况下，`remove`和`remove_all`的单参数重载会抛出异常，而双参数重载会设置传递给它的错误代码引用，而不会抛出异常。

### 路径感知的fstreams

此外，头文件`boost/filesystem/fstream.hpp`提供了与`boost::filesystem::path`对象一起工作的标准文件流类的版本。当您编写使用`boost::filesystem`并且需要读取和写入文件的代码时，这些非常方便。

### 注意

最近，基于Boost文件系统库的C++技术规范已被ISO批准。这为其包含在未来的C++标准库修订版中铺平了道路。

# 使用Boost IOStreams进行可扩展I/O

标准库IOStreams设施旨在为各种设备上的各种操作提供一个框架，但它并没有被证明是最容易扩展的框架。Boost IOStreams库通过一个更简单的接口来补充这个框架，以便将I/O功能扩展到新设备，并提供一些非常有用的类来满足在读取和写入数据时的常见需求。

## Boost IOStreams的架构

标准库IOStreams框架提供了两个基本抽象，**流**和**流缓冲区**。流为应用程序提供了一个统一的接口，用于在底层设备上读取或写入一系列字符。流缓冲区为实际设备提供了一个更低级别的抽象，这些设备被流所利用和进一步抽象。

Boost IOStreams框架提供了`boost::iostreams::stream`和`boost::iostreams::stream_buffer`模板，这些是流和流缓冲区抽象的通用实现。这两个模板根据一组进一步的概念实现其功能，这些概念描述如下：

+   **源**是一个抽象，用于从中读取一系列字符的对象。

+   **汇**是一个抽象，用于向其写入一系列字符。

+   **设备**是源、汇，或两者兼有。

+   **输入过滤器**修改从源读取的一系列字符，而**输出过滤器**修改写入到汇之前的一系列字符。

+   **过滤器**是输入过滤器或输出过滤器。可以编写一个既可以用作输入过滤器又可以用作输出过滤器的过滤器；这被称为**双用过滤器**。

要在设备上执行I/O，我们将零个或多个过滤器序列与设备关联到`boost::iostreams::stream`的实例或`boost::iostreams::stream_buffer`的实例。一系列过滤器称为**链**，一系列过滤器以设备结尾称为**完整链**。

以下图表是输入和输出操作的统一视图，说明了流对象和底层设备之间的I/O路径：

![Boost IOStreams的架构](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-boost-cpp-lib/img/1217OT_09_01.jpg)

Boost IOStreams 架构

输入从设备中读取，并通过一个可选的过滤器堆栈传递到流缓冲区，从那里可以通过流访问。输出从流通过流缓冲区写入，并通过一堆过滤器传递到设备。如果有的话，过滤器会对从设备读取的数据进行操作，以向流的读取者呈现一个转换后的序列。它们还会对要写入设备的数据进行操作，并在写入之前进行转换。上面的图表用于可视化这些交互，但略有不准确；在代码中，过滤器不能同时作为输入过滤器和输出过滤器。

Boost IOStreams 库配备了几个内置的设备和过滤器类，并且也很容易创建我们自己的设备和过滤器。在接下来的章节中，我们将通过代码示例来说明 Boost IOStreams 库的不同组件的使用。

## 使用设备

设备提供了一个接口，用于向底层介质读写字符。它抽象了像磁盘、内存或网络连接这样的真实介质。在本书中，我们将专注于使用作为 Boost IOStreams 库一部分提供的许多现成的设备。编写我们自己的设备类的方法超出了本书的范围，但一旦您熟悉了本章内容，您应该很容易从在线文档中学习它们。

### 文件 I/O 的设备

Boost 定义了许多用于在文件上执行 I/O 的设备，我们首先看的是一个抽象平台特定文件描述符的设备。每个平台都使用一些本机句柄来打开文件，与标准 C++使用`fstream`表示打开文件的方式不同。例如，这些可以是 POSIX 系统上的整数文件描述符和 Windows 上的 HANDLE。Boost IOStreams 库提供了`boost::iostreams::file_descriptor_source`、`boost::iostreams::file_descriptor_sink`和`boost::iostreams::file_descriptor`设备，它们将 POSIX 文件描述符和 Windows 文件句柄转换为输入和输出的设备。在下面的示例中，我们使用`file_descriptor_source`对象使用流接口从 POSIX 系统上的文件中读取连续的行。如果您想要使用流接口来处理使用文件描述符进行文件打开的 I/O，这将非常有用。

**清单 9.11：使用 file_descriptor 设备**

```cpp
 1 #include <boost/iostreams/stream.hpp>
 2 #include <boost/iostreams/device/file_descriptor.hpp>
 3 #include <iostream>
 4 #include <string>
 5 #include <cassert>
 6 #include <sys/types.h>
 7 #include <fcntl.h>
 8 namespace io = boost::iostreams;
 9
10 int main(int argc, char *argv[]) {
11   if (argc < 2) {
12     return 0;
13   }
14
15   int fdr = open(argv[1], O_RDONLY);
16   if (fdr >= 0) {
17     io::file_descriptor_source fdDevice(fdr,
18                    io::file_descriptor_flags::close_handle);
19     io::stream<io::file_descriptor_source> in(fdDevice);
20     assert(fdDevice.is_open());
21
22     std::string line;
23     while (std::getline(in, line))
24     std::cout << line << '\n';
25   }
26 }
```

使用这个程序，我们打开命令行中命名的第一个文件，并从中读取连续的行。我们首先使用 Unix 系统调用`open`（第 15 行）打开文件，为此我们包括 Unix 头文件`sys/types.h`和`fcntl.h`（第 6-7 行）。如果文件成功打开（由`open`返回的文件描述符的正值表示），那么我们创建一个`file_descriptor_source`的实例，将打开的文件描述符和一个`close_handle`标志传递给它，以指示在设备被销毁时应适当关闭描述符（第 17-18 行）。

如果我们不希望设备管理描述符的生命周期，那么我们必须传递`never_close_handle`标志。然后我们创建一个`boost::iostreams::stream<file_descriptor_source>`的实例（第 19 行），将设备对象传递给它，并使用`std::getline`函数从中读取连续的行，就像我们使用任何`std::istream`实例一样（第 23 行）。请注意，我们使用`is_open`成员函数断言设备已经打开以供读取（第 19 行）。这段代码旨在在 Unix 和类 Unix 系统上编译。在 Windows 上，Visual Studio C 运行时库提供了兼容的接口，因此您也可以通过包括一个额外的头文件`io.h`来在 Windows 上编译和运行它。

### 注意

Boost IOStreams 库中的类型和函数分为一组相当独立的头文件，并没有一个单一的头文件包含所有符号。设备头文件位于`boost/iostreams/device`目录下，过滤器头文件位于`boost/iostreams/filter`目录下。其余接口位于`boost/iostreams`目录下。

要构建此程序，我们必须将其与`libboost_iostreams`库链接。我在我的 Ubuntu 系统上使用以下命令行，使用本机包管理器在默认路径下安装的 Boost 库来构建程序：

```cpp
$ g++ listing8_11.cpp -o listing8_11 -std=c++11 -lboost_iostreams

```

我们可能还希望构建我们的程序，以使用我们在第一章中从源代码构建的 Boost 库，*介绍 Boost*。为此，我在我的 Ubuntu 系统上使用以下命令行来构建此程序，指定包含路径和库路径，以及要链接的`libboost_iostreams-mt`库：

```cpp
$ g++listing8_11.cpp -o listing8_11-I /opt/boost/include -std=c++11 -L /opt/boost/lib -lboost_iostreams-mt -Wl,-rpath,/opt/boost/lib

```

要通过文件描述符写入文件，我们需要使用`file_descriptor_sink`对象。我们还可以使用`file_descriptor`对象来同时读取和写入同一设备。还有其他允许写入文件的设备——`file_source`，`file_sink`和`file`设备允许您读取和写入命名文件。`mapped_file_source`，`mapped_file_sink`和`mapped_file`设备允许您通过内存映射读取和写入文件。

### 用于读写内存的设备

标准库`std::stringstream`类系列通常用于将格式化数据读写到内存。如果要从任何给定的连续内存区域（如数组或字节缓冲区）中读取和写入，Boost IOStreams 库中的`array`设备系列（`array_source`，`array_sink`和`array`）非常方便：

**清单 9.12：使用数组设备**

```cpp
 1 #include <boost/iostreams/device/array.hpp>
 2 #include <boost/iostreams/stream.hpp>
 3 #include <boost/iostreams/copy.hpp>
 4 #include <iostream>
 5 #include <vector>
 6 namespace io = boost::iostreams;
 7
 8 int main() {
 9   char out_array[256];
10   io::array_sink sink(out_array, out_array + sizeof(out_array));
11   io::stream<io::array_sink> out(sink);
12   out << "Size of out_array is " << sizeof(out_array)
13       << '\n' << std::ends << std::flush;
14
15   std::vector<char> vchars(out_array,
16                           out_array + strlen(out_array));
17   io::array_source src(vchars.data(),vchars.size());
18   io::stream<io::array_source> in(src);
19
20   io::copy(in, std::cout);
21 }
```

此示例遵循与清单 9.11 相同的模式，但我们使用了两个设备，一个汇和一个源，而不是一个。在每种情况下，我们都执行以下操作：

+   我们创建一个适当初始化的设备

+   我们创建一个流对象并将设备与其关联

+   在流上执行输入或输出

首先，我们定义了一个`array_sink`设备，用于写入连续的内存区域。内存区域作为一对指针传递给设备构造函数，指向一个`char`数组的第一个元素和最后一个元素的下一个位置（第 10 行）。我们将这个设备与流对象`out`关联（第 11 行），然后使用插入操作符(`<<`)向流中写入一些内容。请注意，这些内容可以是任何可流化的类型，不仅仅是文本。使用操纵器`std::ends`（第 13 行），我们确保数组在文本之后有一个终止空字符。使用`std::flush`操纵器，我们确保这些内容不会保留在设备缓冲区中，而是在调用`out_array`（第 16 行）上的`strlen`之前找到它们的方式到汇流设备的后备数组`out_array`中。

接下来，我们创建一个名为`vchars`的`char`向量，用`out_array`的内容进行初始化（第 15-16 行）。然后，我们定义一个由这个`vector`支持的`array_source`设备，向构造函数传递一个指向`vchars`第一个元素的迭代器和`vchars`中的字符数（第 17 行）。最后，我们构造一个与该设备关联的输入流（第 18 行），然后使用`boost::iostreams::copy`函数模板将字符从输入流复制到标准输出（第 20 行）。运行上述代码将通过`array_sink`设备向`out_array`写入以下行：

```cpp
The size of out_array is 256
```

然后它读取短语中的每个单词，并将其打印到新行的标准输出中。

除了`array`设备，`back_insert_device`设备还可以用于适配几个标准容器作为 sink。`back_insert_device`和`array_sink`之间的区别在于，`array_sink`需要一个固定的内存缓冲区来操作，而`back_insert_device`可以使用任何具有`insert`成员函数的标准容器作为其后备存储器。这允许`back_insert_device`的底层内存区域根据输入的大小而增长。我们使用`back_insert_device`替换`array_sink`重写列表 9.12：

**列表 9.13：使用 back_insert_device**

```cpp
 1 #include <boost/iostreams/device/array.hpp>
 2 #include <boost/iostreams/device/back_inserter.hpp>
 3 #include <boost/iostreams/stream.hpp>
 4 #include <boost/iostreams/copy.hpp>
 5 #include <iostream>
 6 #include <vector>
 7 namespace io = boost::iostreams;
 8
 9 int main() {
10   typedef std::vector<char> charvec;
11   charvec output;
12   io::back_insert_device<charvec> sink(output);
13   io::stream<io::back_insert_device<charvec>> out(sink);
14   out << "Size of outputis "<< output.size() << std::flush;
15
16   std::vector<char> vchars(output.begin(),
17                            output.begin() + output.size());
18   io::array_source src(vchars.data(),vchars.size());
19   io::stream<io::array_source> in(src);
20
21   io::copy(in, std::cout);
22 }
```

在这里，我们写入`out_vec`，它是一个`vector<char>`（第 11 行），并且使用`back_insert_device` sink（第 12 行）进行写入。我们将`out_vec`的大小写入流中，但这可能不会打印在那时已经写入设备的字符总数，因为设备可能会在将输出刷新到向量之前对其进行缓冲。由于我们打算将这些数据复制到另一个向量以供读取（第 16-17 行），我们使用`std::flush`操纵器确保所有数据都写入`out_vec`（第 14 行）。

还有其他有趣的设备，比如`tee_device`适配器，允许将字符序列写入两个不同的设备，类似于 Unix 的`tee`命令。现在我们将看一下如何编写自己的设备。

## 使用过滤器

过滤器作用于写入到汇或从源读取的字符流，可以在写入和读取之前对其进行转换，或者仅仅观察流的一些属性。转换可以做各种事情，比如标记关键字，翻译文本，执行正则表达式替换，以及执行压缩或解压缩。观察者过滤器可以计算行数和单词数，或者计算消息摘要等。

常规流和流缓冲区不支持过滤器，我们需要使用**过滤流**和**过滤流缓冲区**来使用过滤器。过滤流和流缓冲区维护一个过滤器堆栈，源或汇在顶部，最外层的过滤器在底部，称为**链**的数据结构。

现在我们将看一下 Boost IOStreams 库作为一部分提供的几个实用过滤器。编写自己的过滤器超出了本书的范围，但优秀的在线文档详细介绍了这个主题。

### 基本过滤器

在使用过滤器的第一个示例中，我们使用`boost::iostreams::counter`过滤器来计算从文件中读取的文本的字符和行数：

**列表 9.14：使用计数器过滤器**

```cpp
 1 #include <boost/iostreams/device/file.hpp>
 2 #include <boost/iostreams/filtering_stream.hpp>
 3 #include <boost/iostreams/filter/counter.hpp>
 4 #include <boost/iostreams/copy.hpp>
 5 #include <iostream>
 6 #include <vector>
 7 namespace io = boost::iostreams;
 8
 9 int main(int argc, char *argv[]) {
10   if (argc <= 1) {
11     return 0;
12   }
13
14   io::file_source infile(argv[1]);
15   io::counter counter;
16   io::filtering_istream fis;
17   fis.push(counter);
18   assert(!fis.is_complete());
19   fis.push(infile);
20   assert(fis.is_complete());
21
22   io::copy(fis, std::cout);
23
24   io::counter *ctr = fis.component<io::counter>(0);
25   std::cout << "Chars: " << ctr->characters() << '\n'
26             << "Lines: " << ctr->lines() << '\n';
27 }
```

我们创建一个`boost::iostream::file_source`设备来读取命令行中指定的文件的内容（第 14 行）。我们创建一个`counter`过滤器来计算读取的行数和字符数（第 15 行）。我们创建一个`filtering_istream`对象（第 16 行），并推送过滤器（第 17 行），然后是设备（第 19 行）。在设备被推送之前，我们可以断言过滤流是不完整的（第 18 行），一旦设备被推送，它就是完整的（第 20 行）。我们将从过滤输入流中读取的内容复制到标准输出（第 22 行），然后访问字符和行数。

要访问计数，我们需要引用过滤流内部的链中的`counter`过滤器对象。为了做到这一点，我们调用`filtering_istream`的`component`成员模板函数，传入我们想要的过滤器的索引和过滤器的类型。这将返回一个指向`counter`过滤器对象的指针（第 24 行），我们通过调用适当的成员函数（第 25-26 行）检索读取的字符和行数。

在下一个示例中，我们使用`boost::iostreams::grep_filter`来过滤掉空行。与不修改输入流的计数器过滤器不同，这个过滤器通过删除空行来转换输出流。

**列表 9.15：使用 grep_filter**

```cpp
 1 #include <boost/iostreams/device/file.hpp>
 2 #include <boost/iostreams/filtering_stream.hpp>
 3 #include <boost/iostreams/filter/grep.hpp>
 4 #include <boost/iostreams/copy.hpp>
 5 #include <boost/regex.hpp>
 6 #include <iostream>
 7 namespace io = boost::iostreams;
 8
 9 int main(int argc, char *argv[]) {
10   if (argc <= 1) {
11     return 0;
12   }
13
14   io::file_source infile(argv[1]);
15   io::filtering_istream fis;
16   io::grep_filter grep(boost::regex("^\\s*$"),
17       boost::regex_constants::match_default, io::grep::invert);
18   fis.push(grep);
19   fis.push(infile);
20
21   io::copy(fis, std::cout);
22 }
```

这个例子与列表 9.14 相同，只是我们使用了不同的过滤器`boost::iostreams::grep_filter`来过滤空行。我们创建了`grep_filter`对象的一个实例，并向其构造函数传递了三个参数。第一个参数是匹配空行的正则表达式`^\s*$`（第 16 行）。请注意，反斜杠在代码中被转义了。第二个参数是常量`match_default`，表示我们使用 Perl 正则表达式语法（第 17 行）。第三个参数`boost::iostreams::grep::invert`告诉过滤器只允许匹配正则表达式的行被过滤掉（第 17 行）。默认行为是只过滤掉不匹配正则表达式的行。

要在 Unix 上构建此程序，您还必须链接到 Boost Regex 库：

```cpp
$ g++ listing8_15.cpp -o listing8_15 -std=c++11 -lboost_iostreams-lboost_regex

```

在没有 Boost 本机包并且 Boost 安装在自定义位置的系统上，使用以下更详细的命令行：

```cpp
$ g++ listing8_15.cpp -o listing8_15-I /opt/boost/include -std=c++11 -L /opt/boost/lib -lboost_iostreams-mt-lboost_regex-mt -Wl,-rpath,/opt/boost/lib

```

在 Windows 上，使用 Visual Studio 并启用自动链接到 DLL，您不需要显式指定 Regex 或 IOStream DLL。

### 压缩和解压过滤器

Boost IOStreams 库配备了三种不同的数据压缩和解压过滤器，分别用于 gzip、zlib 和 bzip2 格式。gzip 和 zlib 格式实现了不同变种的 DEFLATE 算法进行压缩，而 bzip2 格式则使用更节省空间的 Burrows-Wheeler 算法。由于这些是外部库，如果我们使用这些压缩格式，它们必须被构建和链接到我们的可执行文件中。如果您已经按照第一章中概述的详细步骤构建了支持 zlib 和 bzip2 的 Boost 库，那么 zlib 和 bzip2 共享库应该已经与 Boost Iostreams 共享库一起构建了。

在下面的例子中，我们压缩了一个命令行中命名的文件，并将其写入磁盘。然后我们读取它，解压它，并将其写入标准输出。

**列表 9.16：使用 gzip 压缩器和解压器**

```cpp
 1 #include <boost/iostreams/device/file.hpp>
 2 #include <boost/iostreams/filtering_stream.hpp>
 3 #include <boost/iostreams/stream.hpp>
 4 #include <boost/iostreams/filter/gzip.hpp>
 5 #include <boost/iostreams/copy.hpp>
 6 #include <iostream>
 7 namespace io = boost::iostreams;
 8
 9 int main(int argc, char *argv[]) {
10   if (argc <= 1) {
11     return 0;
12   }
13   // compress
14   io::file_source infile(argv[1]);
15   io::filtering_istream fis;
16   io::gzip_compressor gzip;
17   fis.push(gzip);
18   fis.push(infile);
19
20   io::file_sink outfile(argv[1] + std::string(".gz"));
21   io::stream<io::file_sink> os(outfile);
22   io::copy(fis, os);
23
24   // decompress
25   io::file_source infile2(argv[1] + std::string(".gz"));
26   fis.reset();
27   io::gzip_decompressor gunzip;
28   fis.push(gunzip);
29   fis.push(infile2);
30   io::copy(fis, std::cout);
31 }
```

前面的代码首先使用`boost::iostreams::gzip_compressor`过滤器（第 16 行）在读取文件时解压文件（第 17 行）。然后使用`boost::iostreams::copy`将这个内容写入一个带有`.gz`扩展名的文件中，该扩展名附加到原始文件名上（第 20-22 行）。对`boost::iostreams::copy`的调用还会刷新和关闭传递给它的输出和输入流。因此，在`copy`返回后立即从文件中读取是安全的。为了读取这个压缩文件，我们使用一个带有`boost::iostreams::gzip_decompressor`的`boost::iostreams::file_source`设备（第 27-28 行），并将解压后的输出写入标准输出（第 30 行）。我们重用`filtering_istream`对象来读取原始文件，然后再次用于读取压缩文件。在过滤流上调用`reset`成员函数会关闭并删除与流相关的过滤器链和设备（第 26 行），因此我们可以关联一个新的过滤器链和设备（第 27-28 行）。

通过向压缩器或解压器过滤器的构造函数提供额外的参数，可以覆盖几个默认值，但基本结构不会改变。通过将头文件从`gzip.hpp`更改为`bzip2.hpp`（第 4 行），并在前面的代码中用`bzip2_compressor`和`bzip2_decompressor`替换`gzip_compressor`和`gzip_decompressor`，我们可以测试 bzip2 格式的代码；同样适用于 zlib 格式。理想情况下，扩展名应该适当更改（.bz2 用于 bzip2，.zlib 用于 zlib）。在大多数 Unix 系统上，值得测试生成的压缩文件，通过使用 gzip 和 bzip2 工具单独解压缩它们。对于 zlib 存档的命令行工具似乎很少，且标准化程度较低。在我的 Ubuntu 系统上，`qpdf`程序带有一个名为`zlib-flate`的原始 zlib 压缩/解压缩实用程序，可以压缩到 zlib 格式并从 zlib 格式解压缩。

构建此程序的步骤与构建清单 9.15 时的步骤相同。即使使用`zlib_compressor`或`bzip2_compressor`过滤器，只要在链接期间使用选项`-Wl,-rpath,/opt/boost/lib`，链接器（以及稍后的运行时链接器在执行期间）将自动选择必要的共享库，路径`/opt/boost/lib`包含 zlib 和 bzip2 的共享库。

### 组合过滤器

过滤流可以在管道中对字符序列应用多个过滤器。通过在过滤流上使用`push`方法，我们可以形成以最外层过滤器开始的管道，按所需顺序插入过滤器，并以设备结束。

这意味着对于过滤输出流，您首先推送首先应用的过滤器，然后向前推送每个连续的过滤器，最后是接收器。例如，为了过滤掉一些行并在写入接收器之前进行压缩，推送的顺序将如下所示：

```cpp
filtering_ostream fos;
fos.push(grep);
fos.push(gzip);
fos.push(sink);
```

对于过滤输入流，您需要推送过滤器，从最后应用的过滤器开始，然后逆向工作，推送每个前置过滤器，最后是源。例如，为了读取文件，解压缩它，然后执行行计数，推送的顺序将如下所示：

```cpp
filtering_istream fis;
fis.push(counter);
fis.push(gunzip);
fis.push(source);
```

#### 管道

原来一点点的操作符重载可以使这个过程更加具有表现力。我们可以使用管道操作符（`operator|`）以以下替代符号来编写前面的链：

```cpp
filtering_ostream fos;
fos.push(grep | gzip | sink);

filtering_istream fis;
fis.push(counter | gunzip | source);
```

前面的片段显然更具表现力，代码行数更少。从左到右，过滤器按照您将它们推入流中的顺序串联在一起，最后是设备。并非所有过滤器都可以以这种方式组合，但来自 Boost IOStreams 库的许多现成的过滤器可以；更明确地说，过滤器必须符合**可管道化概念**才能以这种方式组合。以下是一个完整的示例程序，该程序读取文件中的文本，删除空行，然后使用 bzip2 进行压缩：

**清单 9.17：使用管道过滤器**

```cpp
 1 #include <boost/iostreams/device/file.hpp>
 2 #include <boost/iostreams/filtering_stream.hpp>
 3 #include <boost/iostreams/stream.hpp>
 4 #include <boost/iostreams/filter/bzip2.hpp>
 5 #include <boost/iostreams/filter/grep.hpp>
 6 #include <boost/iostreams/copy.hpp>
 7 #include <boost/regex.hpp>
 8 #include <iostream>
 9 namespace io = boost::iostreams;
10
11 int main(int argc, char *argv[]) {
12   if (argc <= 1) { return 0; }
13
14   io::file_source infile(argv[1]);
15   io::bzip2_compressor bzip2;
16   io::grep_filter grep(boost::regex("^\\s*$"),
17         boost::regex_constants::match_default,
18         io::grep::invert);
19   io::filtering_istream fis;
20   fis.push(bzip2 | grep | infile);
21   io::file_sink outfile(argv[1] + std::string(".bz2"));
22   io::stream<io::file_sink> os(outfile);
23
24   io::copy(fis, os);
25 }
```

前面的示例将一个用于过滤空行的 grep 过滤器（第 16-18 行）和一个 bzip2 压缩器（第 15 行）与使用管道的文件源设备串联在一起（第 20 行）。代码的其余部分应该与清单 9.15 和 9.16 相似。

#### 使用 tee 分支数据流

在使用具有多个过滤器的过滤器链时，有时捕获两个过滤器之间流动的数据是有用的，特别是用于调试。`boost::iostreams::tee_filter`是一个输出过滤器，类似于 Unix 的`tee`命令，它位于两个过滤器之间，并提取两个过滤器之间流动的数据流的副本。基本上，当您想要在处理的不同中间阶段捕获数据时，可以使用`tee_filter`：

![使用 tee 分支数据流](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-boost-cpp-lib/img/1217OT_09_03.jpg)

您还可以复用两个接收设备来创建一个**tee 设备**，这样将一些内容写入 tee 设备会将其写入底层设备。`boost::iostream::tee_device`类模板结合了两个接收器以创建这样的 tee 设备。通过嵌套 tee 设备或管道化 tee 过滤器，我们可以生成几个可以以不同方式处理的并行流。`boost::iostreams::tee`函数模板可以生成 tee 过滤器和 tee 流。它有两个重载——一个单参数重载，接收一个接收器并生成一个`tee_filter`，另一个双参数重载，接收两个接收器并返回一个`tee_device`。以下示例显示了如何使用非常少的代码将文件压缩为三种不同的压缩格式（gzip、zlib 和 bzip2）：

**清单 9.18：使用 tee 分支输出流**

```cpp
 1 #include <boost/iostreams/device/file.hpp>
 2 #include <boost/iostreams/filtering_stream.hpp>
 3 #include <boost/iostreams/stream.hpp>
 4 #include <boost/iostreams/filter/gzip.hpp>
 5 #include <boost/iostreams/filter/bzip2.hpp>
 6 #include <boost/iostreams/filter/zlib.hpp>
 7 #include <boost/iostreams/copy.hpp>
 8 #include <boost/iostreams/tee.hpp>
 9 namespace io = boost::iostreams;
10
11 int main(int argc, char *argv[]) {
12   if (argc <= 1) { return 0; }
13
14   io::file_source infile(argv[1]);  // input
15   io::stream<io::file_source> ins(infile);
16
17   io::gzip_compressor gzip;
18   io::file_sink gzfile(argv[1] + std::string(".gz"));
19   io::filtering_ostream gzout;     // gz output
20   gzout.push(gzip | gzfile);
21   auto gztee = tee(gzout);
22
23   io::bzip2_compressor bzip2;
24   io::file_sink bz2file(argv[1] + std::string(".bz2"));
25   io::filtering_ostream bz2out;     // bz2 output
26   bz2out.push(bzip2 | bz2file);
27   auto bz2tee = tee(bz2out);
28
29   io::zlib_compressor zlib;
30   io::file_sink zlibfile(argv[1] + std::string(".zlib"));
31
32   io::filtering_ostream zlibout;
33   zlibout.push(gztee | bz2tee | zlib | zlibfile);
34
35   io::copy(ins, zlibout);
36 }
```

我们为 gzip、bzip2 和 zlib 设置了三个压缩过滤器（第 17、23 和 29 行）。我们需要为每个输出文件创建一个`filtering_ostream`。我们为 gzip 压缩输出创建了`gzout`流（第 20 行），为 bzip2 压缩输出创建了`bz2out`流（第 26 行）。我们在这两个流周围创建了 tee 过滤器（第 21 和 27 行）。最后，我们将 gztee、bz2tee 和 zlib 连接到 zlibfile 接收器前面，并将此链推入 zlibout 的`filtering_ostream`中，用于 zlib 文件（第 33 行）。从输入流`ins`复制到输出流`zlibout`会生成管道中的三个压缩输出文件，如下图所示：

![使用 tee 分支数据流](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-boost-cpp-lib/img/1217OT_09_02.jpg)

请注意，对 tee 的调用没有命名空间限定，但由于参数相关查找（见第二章，“使用 Boost 实用工具的第一次尝试”），它们得到了正确的解析。

Boost IOStreams 库提供了一个非常丰富的框架，用于编写和使用设备和过滤器。本章仅介绍了此库的基本用法，还有许多过滤器、设备和适配器可以组合成有用的 I/O 模式。

# 自测问题

对于多项选择题，选择所有适用的选项：

1.  对于操作路径的`canonical`和`equivalent`函数有什么独特之处？

a. 参数不能命名真实路径。

b. 两者都是命名空间级别的函数。

c. 参数必须命名真实路径。

1.  以下代码片段的问题是什么，假设路径的类型是`boost::filesystem::path`？

```cpp
if (is_regular_file(path)) { /* … */ }
else if (is_directory(path)) { /* … */ }
else if (is_symlink(path)) { /* … */ }
```

a. 它必须有静态的`value`字段。

b. 它必须有一个名为`type`的嵌入类型。

c. 它必须有静态的`type`字段。

d. 它必须有一个名为`result`的嵌入类型。

1.  考虑到这段代码：

```cpp
boost::filesystem::path p1("/opt/boost/include/boost/thread.hpp");
size_t n = std::distance(p1.begin(), p1.end());
```

n 的值是多少？

a. 5，路径中组件的总数。

b. 6，路径中组件的总数。

c. 10，斜杠和组件数量的总和。

d. 4，目录组件的总数。

1.  您想要读取一个文本文件，使用`grep_filter`删除所有空行，使用`regex_filter`替换特定关键词，并计算结果中的字符和行数。您将使用以下哪个管道？

a. `file_source | grep_filter| regex_filter | counter`

b. `grep_filter | regex_filter | counter | file_source`

c. `counter | regex_filter | grep_filter |file_source`

d. `file_source | counter | grep_filter | regex_filter`

1.  真或假：tee 过滤器不能与输入流一起使用。

a. 真。

b. 错误。

# 总结

在本章中，我们介绍了 Boost Filesystem 库，用于读取文件元数据和文件和目录状态，并对它们执行操作。我们还介绍了高级 Boost IOStreams 框架，用于执行具有丰富语义的类型安全 I/O。

处理文件和执行 I/O 操作是基本的系统编程任务，几乎任何有用的软件都需要执行这些任务，而我们在本章中介绍的 Boost 库通过一组可移植的接口简化了这些任务。在下一章中，我们将把注意力转向另一个系统编程主题——并发和多线程。


# 第十章：使用 Boost 进行并发

**线程**代表进程内的并发执行流。它们是**并发**的低级抽象，并由操作系统的系统编程库或系统调用接口公开，例如，POSIX 线程、Win32 线程。在多处理器或多核系统上，操作系统可以调度同一进程的两个线程在两个不同的核上并行运行，从而实现真正的**并行**。

线程是一种流行的机制，用于抽象可能与其他类似任务并行运行的并发任务。如果做得好，线程可以简化程序结构并提高性能。然而，并发和并行性引入了在单线程程序中看不到的复杂性和非确定性行为，做到正确通常是涉及线程时最大的挑战。不同操作系统上本地多线程库或接口的广泛差异使得使用线程编写可移植的并发软件的任务变得更加困难。Boost Thread 库通过提供一个可移植的接口来创建线程和更高级别的抽象来缓解这个问题。Boost Coroutine 库提供了一种创建协作*协程*或可以退出和恢复的函数的机制，在这些调用之间保留自动对象的状态。协程可以以更简单的方式表达事件驱动逻辑，并在某些情况下避免线程的开销。

本章是对使用 Boost Thread 库的实际介绍，还包括对 Boost Coroutine 库的简要介绍。它分为以下几个部分：

+   使用 Boost Thread 创建并发任务

+   并发、信号和同步

+   Boost 协程

即使您从未编写过多线程程序或并发软件，这也是一个很好的起点。我们还将涉及基于 Boost Thread 库的 C++11 标准库中的线程库，并引入额外的改进。

# 使用 Boost Thread 创建并发任务

考虑一个以不同语言打印问候语的程序。有一个用盎撒克逊语言，如英语、德语、荷兰语、丹麦语等的问候语列表。还有一个用罗曼语言，如意大利语、西班牙语、法语、葡萄牙语等的问候语列表。需要打印来自两种语言组的问候语，我们不希望因为其中一组的问候语而延迟打印另一组的问候语，也就是说，我们希望同时打印来自两个组的问候语。以下是同时打印两组问候语的一种方法：

**清单 10.1：交错任务**

```cpp
 1 #include <iostream>
 2 #include <string>
 3 #include <vector>
 4
 5 int main()
 6 {
 7   typedef std::vector<std::string> strvec;
 8
 9   strvec angloSaxon{"Guten Morgen!", "Godmorgen!", 
10                    "Good morning!", "goedemorgen"};
11
12   strvec romance{"Buenos dias!", "Bonjour!", 
13                  "Bom dia!", "Buongiorno!"};
14
15   size_t max1 = angloSaxon.size(), max2 = romance.size();
16   size_t i = 0, j = 0;
17
18   while (i < max1 || j < max2) {
19     if (i < max1)
20       std::cout << angloSaxon[i++] << '\n';
21
22     if (j < max2)
23       std::cout << romance[j++] << '\n';
24   }
25 }
```

在前面的示例中，我们有两个问候语的向量，并且在每个向量中打印问候语是一个独立的任务。我们通过从每个数组中打印一个问候语来交错这两个任务，因此这两个任务同时进行。从代码中，我们可以看出拉丁语和盎格鲁-撒克逊语的问候语将交替打印，顺序如下所示：

```cpp
Buenos dias!
Guten Morgen!
Bonjour!
Godmorgen!
Bom dia!
Good morning!
Buongiorno!
goedemorgen
```

虽然这两个任务是交替运行的，并且在某种意义上是同时进行的，但它们在代码中的区别完全混乱，以至于它们被编码在一个单一的函数中。通过将它们分开成单独的函数并在单独的线程中运行，这些任务可以完全解耦，但可以同时运行。此外，线程可以允许它们并行执行。

## 使用 Boost Threads

每个运行的进程至少有一个执行线程。传统的“hello world”程序具有一个`main`函数，也有一个单一线程，通常称为**主线程**。这样的程序称为**单线程**。使用 Boost Threads，我们可以创建具有多个执行线程的程序，这些线程并发运行任务。我们可以使用 Boost Threads 重写列表 10.1，以便将单个任务的代码清晰地分解出来，并且在有并行硬件可用时，任务可能并行运行。我们可以这样做：

**列表 10.2：作为线程的并发任务**

```cpp
 1 #include <boost/thread.hpp>
 2 #include <string>
 3 #include <vector>
 4 #include <iostream>
 5
 6 typedef std::vector<std::string> strvec;
 7 
 8 void printGreets(const strvec& greets)
 9 {
10   for (const auto& greet : greets) {
11     std::cout << greet << '\n';
12   }
13 }
14
15 int main()
16 {
17   strvec angloSaxon{"Guten Morgen!", "Godmorgen!", 
18                    "Good morning!", "goedemorgen"};
19
20   strvec romance{"Buenos dias!", "Bonjour!", 
21                  "Bom dia!", "Buongiorno!"};
15
16   boost::thread t1(printGreets, romance);
17   printGreets(angloSaxon);
18   t1.join();
19 }
```

我们定义了一个函数`printGreets`，它接受一个问候语的向量并打印向量中的所有问候语（第 8-13 行）。这是任务的代码，简化并分解出来。这个函数在两个问候语向量上分别被调用一次。它从`main`函数中调用一次，该函数在主线程中执行（第 17 行），并且从我们通过实例化`boost::thread`对象来生成的第二个执行线程中调用一次，传递给它要调用的函数和它的参数（第 16 行）。头文件`boost/thread.hpp`提供了使用 Boost Threads 所需的类型和函数（第 1 行）。

类型为`boost::thread`的对象`t1`包装了一个本地线程，例如`pthread_t`，Win32 线程`HANDLE`等。为了简洁起见，我们简单地指“线程`t1`”来表示底层线程以及包装它的`boost::thread`对象，除非有必要区分两者。通过传递函数对象（线 16）和传递给函数对象的所有参数来构造对象`t1`。在构造时，底层本地线程立即通过调用传递的函数和提供的参数开始运行。当此函数返回时，线程终止。这与从`main`函数调用的`printGreets`函数（第 17 行）同时发生。

这个程序的一个可能的输出是：

```cpp
Guten Morgen!
Buenos dias!
Godmorgen!
Bonjour!
Bom dia!
Good morning!
Buongiorno!
goedemorgen
```

拉丁语问候语按照它们在`romance`向量中出现的顺序打印，盎格鲁-撒克逊语问候语按照它们在`angloSaxon`向量中出现的顺序打印。但它们交错的顺序是不可预测的。这种缺乏确定性是并发编程的一个关键特征，也是一些困难的来源。可能更令人不安的是，甚至以下输出也是可能的：

```cpp
Guten Morgen!
Buenos dGodmorgeias!
n!
Bonjour!
Bom dia! Good morning!
Buongiorno!
goedemorgen
```

请注意，两个问候语`Buenos dias!`（西班牙语）和`Godmorgen!`（荷兰语）是交错的，而`Good morning!`在`Bom dia!`后的换行之前被打印出来。

我们在`t1`上调用`join`成员函数来等待底层线程终止（第 18 行）。由于主线程和线程`t1`并发运行，任何一个都可以在另一个之前终止。如果`main`函数先终止，它将终止程序，并且在线程`t1`中运行的`printGreets`函数在执行完之前将被终止。通过调用`join`，主函数确保在`t1`仍在运行时不会退出。

### 注意

链接到 Boost 线程库

Boost Thread 不是一个仅包含头文件的库，而是必须从源代码构建的。第一章，*介绍 Boost*，描述了从源代码构建 Boost 库的细节，它们的**名称布局变体**和命名约定。

要从列表 10.2 构建一个运行的程序，您需要将编译后的对象与这些库链接起来。要构建前面的示例，您必须链接 Boost 线程和 Boost 系统库。在 Linux 上，您还必须链接`libpthread`，其中包含 Pthreads 库的实现。

假设源文件是`Listing9_2.cpp`，以下是在 Linux 上编译和链接源代码以构建二进制文件的 g++命令行：

```cpp
$ g++ Listing9_2.cpp -o Listing9_2 -lboost_thread -lboost_system –lboost_chrono –pthread 
```

只有在使用 Boost Chrono 库时才需要链接到`libboost_chrono`。选项`-pthread`设置了必要的预处理器和链接器标志，以启用编译多线程应用程序并将其链接到`libpthread`。如果您没有使用本机包管理器在 Linux 上安装 Boost，或者正在尝试在其他平台上构建，比如 Windows，则请参考第一章中的详细构建说明，*介绍 Boost*。

如果您使用的是 C++11，可以使用标准库线程而不是 Boost Threads。为此，您必须包含标准库头文件`thread`，并使用`std::thread`代替`boost::thread`。Boost Thread 和`std::thread`不能直接替换彼此，因此可能需要进行一些更改。

### 移动线程和等待线程

`std::thread`对象与进程中的一个线程关联并管理。考虑以下代码片段：

```cpp
 1 void threadFunc() { ... }
 2
 3 boost::thread makeThread(void (*thrFunc)()) {
 4   assert(thrFunc);
 5   boost::thread thr(thrFunc);
 6   // do some work
 7   return thr;
 8 }
 9
10 int main() {
11   auto thr1 = makeThread(threadFunc);
12   // ...
13   thr1.join();
14 }
```

当创建`boost::thread`对象`thr`（第 4 行）时，它与一个新的本机线程（`pthread_t`，Windows 线程句柄等）相关联，该线程执行`thrFunc`指向的函数。现在`boost::thread`是可移动但不可复制的类型。当`makeThread`函数通过值返回`thr`（第 7 行）时，底层本机线程句柄的所有权从`makeThread`中的对象`thr`移动到`main`函数中的`thr1`（第 11 行）。因此，您可以在一个函数中创建一个线程，并将其返回给调用函数，在此过程中*转移所有权*。

最终，我们在`main`函数内等待线程完成执行，通过调用`join`（第 13 行）。这确保了在线程`thr1`终止之前，`main`函数不会退出。现在完全有可能，在`makeThread`返回`thr`时，底层线程已经完成了执行。在这种情况下，`thr1.join()`（第 13 行）会立即返回。另一方面，当主线程上的控制转移到`main`函数时，底层线程可能会继续执行，即使在`thr1`（第 13 行）上调用了`join`。在这种情况下，`thr1.join()`将会阻塞，等待线程退出。

有时，我们可能希望一个线程运行完毕并退出，之后就不再关心它了。此外，线程是否终止可能并不重要。想象一下，一个个人财务桌面应用程序具有一个巧妙的股票行情线程，它在窗口的一个角落不断显示一组可配置公司的股票价格。它由主应用程序启动，并继续执行其获取最新股票价格并显示的工作，直到应用程序退出。主线程在退出之前等待此线程没有多大意义。应用程序终止时，股票行情线程也会终止并在其退出时进行清理。我们可以通过在`boost::thread`对象上调用`detach`来显式请求线程的此行为，如下面的代码片段所示：

```cpp
 1 int main() {
 2   boost::thread thr(thrFunc, arg1, ...);
 3   thr.detach();
 4   // ...
 5 }
```

当我们在`boost::thread`对象上调用`detach`时，底层本机线程的所有权被传递给 C++运行时，它将继续执行线程，直到线程终止或程序终止并杀死线程。在调用`detach`之后，`boost::thread`对象不再引用有效线程，程序不再能够检查线程的状态或以任何方式与其交互。

只有在`boost::thread`对象上既没有调用`detach`也没有调用`join`时，线程才被认为是可连接的。`boost::thread`的`joinable`方法仅在线程可连接时返回`true`。如果您在不可连接的`boost::thread`对象上调用`detach`或`join`，则调用将立即返回，没有其他效果。如果我们没有在`boost::thread`对象上调用`join`，则在线程超出范围时将调用`detach`。

### 注意

`boost::thread`和`std::thread`之间的区别

必须在`std::thread`对象上调用`join`或`detach`；否则，`std::thread`的析构函数将调用`std::terminate`并中止程序。此外，在不可连接的`std::thread`上调用`join`或`detach`将导致抛出`std::system_error`异常。因此，您在`std::thread`上调用`join`和`detach`中的任何一个，并且只调用一次。这与我们刚刚描述的`boost::thread`的行为相反。

我们可以通过定义以下预处理器宏使`boost::thread`模拟`std::thread`的行为，而且在您编写的任何新代码中模拟`std::thread`的行为是一个好主意：

```cpp
BOOST_THREAD_TRHOW_IF_PRECONDITION_NOT_SATISFIED BOOST_THREAD_PROVIDES_THREAD_DESTRUCTOR_CALLS_TERMINATE_IF_JOINABLE
```

### 线程 ID

在任何时候，进程中的每个运行线程都有一个唯一的标识符。此标识符由类型`boost::thread::id`表示，并且可以通过调用`get_id`方法从`boost::thread`对象中获取。要获取当前线程的 ID，我们必须使用`boost::this_thread::get_id()`。可以使用重载的插入运算符（`operator<<`）将 ID 的字符串表示打印到`ostream`对象中。

线程 ID 可以使用`operator<`进行排序，因此它们可以轻松地存储在有序的关联容器（`std::set` / `std::map`）中。线程 ID 可以使用`operator==`进行比较，并且可以存储在无序的关联容器中（`std::unordered_set` / `std::unordered_map`）。将线程存储在由其 ID 索引的关联容器中是支持线程查找的有效手段：

**清单 10.3：使用线程 ID**

```cpp
 1 #include <boost/thread.hpp>
 2 #include <boost/chrono/duration.hpp>
 3 #include <vector>
 4 #include <map>
 5 #include <iostream>
 6 #include <sstream>
 7 #include <boost/move/move.hpp>
 8
 9 void doStuff(const std::string& name) {
10   std::stringstream sout;
11   sout << "[name=" << name << "]"
12     << "[id=" << boost::this_thread::get_id() << "]"
13     << " doing work\n";
14   std::cout << sout.str();
15   boost::this_thread::sleep_for(boost::chrono::seconds(2));
16 }
17
18 int main() {
19   typedef std::map<boost::thread::id, boost::thread> threadmap;
20   threadmap tmap;
21
22   std::vector<std::string> tnames{ "thread1", "thread2",
23                             "thread3", "thread4", "thread5" };
24   for (auto name : tnames) {
25     boost::thread thr(doStuff, name);
26     tmap[thr.get_id()] = boost::move(thr);
27   }
28
29   for (auto& thrdEntry : tmap) {
30     thrdEntry.second.join();
31     std::cout << thrdEntry.first << " returned\n";
32   }
33 }
```

在前面的例子中，我们创建了五个线程，每个线程都运行函数`doStuff`。函数`doStuff`被分配了一个线程运行的名称；我们将线程命名为`thread1`到`thread5`，并将它们放在一个由它们的 ID 索引的`std::map`中（第 26 行）。因为`boost::thread`是可移动但不可复制的，我们将线程对象移动到地图中。`doStuff`函数简单地使用`boost::this_thread::get_id`方法（第 12 行）打印当前线程的 ID 作为一些诊断消息的一部分，然后使用`boost::this_thread::sleep_for`休眠 2 秒，该方法接受`boost::chrono::duration`类型的持续时间（参见第八章，“日期和时间库”）。我们还可以使用 Boost Date Time 提供的持续时间类型，即`boost::posix_time::time_duration`及其子类型，而不是`boost::chrono`，但是为此我们需要使用`boost::this_thread::sleep`函数而不是`sleep_for`。

### 核心和线程

许多现代计算机在单个芯片上有多个 CPU 核心，并且处理器包中可能有多个芯片。要获取计算机上的物理核心数，可以使用静态函数`boost::thread::physical_concurrency`。

现代英特尔 CPU 支持英特尔的超线程技术，该技术通过使用两组寄存器最大限度地利用单个核心，允许在任何给定时间点上在核心上复用两个线程，并降低上下文切换的成本。在支持超线程的具有八个核心的英特尔系统上，可以并行调度的最大线程数为 8x2 = 16。静态函数`boost::thread::hardware_concurrency`为本地机器返回此数字。

这些数字对于决定程序中的最佳线程数是有用的。但是，如果这些数字在底层系统中不可用，这些函数可能会返回 0。您应该在计划使用它们的每个平台上彻底测试这些函数。

# 管理共享数据

进程中的所有线程都可以访问相同的全局内存，因此在一个线程中执行的计算结果相对容易与其他线程共享。对共享内存的并发只读操作不需要任何协调，但对共享内存的任何写入都需要与任何读取或写入同步。共享*可变数据*和其他资源的线程需要机制来*仲裁对共享数据的访问*并向彼此发出关于事件和状态更改的信号。在本节中，我们探讨了多个线程之间的协调机制。

## 创建和协调并发任务

考虑一个生成两个文本文件之间差异的程序，类似于 Unix 的 `diff` 实用程序。您需要读取两个文件，然后应用算法来识别相同部分和已更改部分。对于大多数文本文件，读取两个文件，然后应用适当的算法（基于最长公共子序列问题）都能很好地工作。算法本身超出了本书的范围，与当前讨论无关。

考虑我们需要执行的任务：

+   R1: 读取第一个文件的完整内容

+   R2: 读取第二个文件的完整内容

+   D: 对两个文件的内容应用差异算法

任务 R1 和 R2 可能产生包含文件内容的两个字符数组。任务 D 消耗了 R1 和 R2 产生的内容，并将差异作为另一个字符数组产生。R1 和 R2 之间不需要顺序，我们可以在单独的线程中同时读取两个文件。为简单起见，D 仅在 R1 和 R2 完成后才开始，也就是说，R1 和 R2 必须在 D 之前发生。让我们从编写读取文件的代码开始：

**清单 10.4a: 读取文件内容**

```cpp
 1 #include <vector>
 2 #include <string>
 3 #include <fstream>
 4 #include <boost/filesystem.hpp>
 5
 6 std::vector<char> readFromFile(const std::string& filepath)
 7 {
 8   std::ifstream ifs(filepath);
 9   size_t length = boost::filesystem::file_size(filepath);
10   std::vector<char> content(length);
11   ifs.read(content.data(), length);
12
13   return content;
14 }
15
16 std::vector<char> diffContent(const std::vector<char>& c1,
17                               const std::vector<char>& c2) {
18   // stub - returns an empty vector
19   return std::vector<char>();
20 }
```

给定文件名，函数 `readFromFile` 读取整个文件的内容并将其返回为 `vector<char>`。我们将文件内容读入 `vector` 的基础数组中，为了获取它，我们调用了 C++11 中引入的 `data` 成员函数（第 11 行）。我们打开文件进行读取（第 8 行），并使用 `boost::filesystem::size` 函数获取文件的大小（第 9 行）。我们还定义了一个计算两个文件内容差异的方法 `diffContent` 的存根。

我们如何使用 `readFromFile` 函数在单独的线程中读取文件并将包含文件内容的向量返回给调用线程？调用线程需要一种等待读取完成的方式，并且然后获取所读取的内容。换句话说，调用线程需要等待异步操作的未来结果。`boost::future` 模板提供了一种简单的方式来强制执行任务之间的这种顺序。

### boost::future 和 boost::promise

`boost::future<>` 模板用于表示可能在将来发生的计算结果。类型为 `boost::future<T>` 的对象代表将来可能产生的类型为 `T` 的对象的代理。粗略地说，`boost::future` 使调用代码能够等待或阻塞事件的发生——产生某种类型的值的事件。这种机制可以用于信号事件并从一个线程传递值到另一个线程。

值的生产者或事件的来源需要一种与调用线程中的 future 对象通信的方法。为此，使用与调用线程中的 future 对象关联的`boost::promise<T>`类型的对象来发出事件并发送值。因此，`boost::future`和`boost::promise`对象成对工作，以在线程之间传递事件和值。现在我们将看到如何使用 Boost futures 和 promises 来保证两个文件读取操作在两个线程中先于 diff 操作：

**列表 10.4b：使用 futures 和 promises 从线程返回值**

```cpp
 1 #define BOOST_THREAD_PROVIDES_FUTURE
 2 #include <boost/thread.hpp>
 3 #include <boost/thread/future.hpp>
 4 // other includes
 5
 6 std::vector<char> diffFiles(const std::string& file1, 
 7                             const std::string& file2) {
 8   // set up the promise-future pair
 9   boost::promise<std::vector<char>> promised_value;
10   boost::future<std::vector<char>> future_result
11                                = promised_value.get_future();
12   // spawn a reader thread for file2
13   boost::thread reader(
14                     [&promised_value, &file2]() {
15                       std::cout << "Reading " << file2 << '\n';
16                       auto content = readFromFile(file2);
17                       promised_value.set_value(content);
18                       std::cout << "Read of " << file2
19                                 << " completed.\n";
20                     });
21
22   std::cout << "Reading " << file1 << '\n';
23   auto content1 = readFromFile(file1);
24   std::cout << "Read of " << file1 << " completed.\n";
25
26   auto content2 = future_result.get(); // this blocks
27   auto diff = diffContent(content1, content2);
28   reader.join();
29   return diff; 
30 }
```

为了能够使用`boost::future`和`boost::promise`，我们需要包括`boost/thread/future.hpp`（第 3 行）。如果我们没有定义预处理符号`BOOST_THREAD_PROVIDES_FUTURE`（第 1 行），那么我们需要使用`boost::unique_future`而不是`boost::future`。如果我们用`boost::unique_future`替换`boost::future`，这个例子将不变，但一般来说，这两种设施的能力有所不同，我们在本书中坚持使用`boost::future`。

`diffFiles`函数（第 6 和 7 行）接受两个文件名并返回它们的差异。它同步读取第一个文件（第 23 行），使用列表 10.4a 中的`readFromFile`函数，并创建一个名为`reader`的线程并发读取第二个文件（第 13 行）。为了在`reader`线程完成读取并获取读取的内容时得到通知，我们需要设置一个 future-promise 对。由于我们想要从`reader`线程返回`std::vector<char>`类型的值，我们定义了一个名为`promised_value`的`boost::promise<std::vector<char>>`类型的 promise（第 9 行）。promise 对象的`get_future`成员返回关联的 future 对象，并用于移动构造`future_result`（第 10-11 行）。这将`promised_value`和`future_result`设置为我们要处理的 promise-future 对。

为了读取`file2`的内容，我们创建了`reader`线程，传递了一个 lambda（第 14-20 行）。lambda 捕获了`promised_value`和要读取的文件的名称（第 14 行）。它读取文件的内容并在 promise 对象上调用`set_value`，传递读取的内容（第 17 行）。然后打印诊断消息并返回。与此同时，调用线程也将另一个文件`file1`读入缓冲区`content1`，然后在`future_result`上调用`get`（第 26 行）。此调用会阻塞，直到通过调用`set_value`（第 17 行）设置了关联的 promise。它返回在 promise 中设置的`vector<char>`，并用于移动构造`content2`。如果在调用`get`时 promise 已经设置，它会返回值而不会阻塞调用线程。

现在我们有了计算差异所需的数据，并且通过将缓冲区`content1`和`content2`传递给`diffContent`函数（第 27 行）来进行计算。请注意，在返回`diff`之前，我们在`reader`线程上调用`join`（第 28 行）。只有在我们希望确保`reader`线程在函数返回之前退出时才需要这样做。我们也可以调用`detach`而不是`join`来不等待读取线程退出。

### 等待 future

`boost::future<>`的`get`成员函数会阻塞调用线程，直到关联的 promise 被设置。它返回 promise 中设置的值。有时，您可能希望阻塞一小段时间，如果 promise 没有设置，则继续进行。为此，您必须使用`wait_for`成员函数，并使用`boost::chrono::duration`指定等待的持续时间（参见第八章，“日期和时间库”）。

**列表 10.5：等待和超时 future**

```cpp
 1 #define BOOST_THREAD_PROVIDES_FUTURE
 2 #include <boost/thread.hpp>
 3 #include <boost/thread/future.hpp>
 4 #include <boost/chrono.hpp>
 5 #include <ctime>
 6 #include <cassert>
 7 #include <cstdlib>
 8 #include <iostream>
 9 
10 int main() {
11   boost::promise<void> promise;
12   boost::future<void> future = promise.get_future();
13
14   std::cout << "Main thread id=" 
15                       << boost::this_thread::get_id() << '\n';
16   boost::thread thr([&promise]() {
17          srand(time(0));
18          int secs = 10 + rand() % 10;
19          std::cout << "Thread " << boost::this_thread::get_id()
20                   << " sleeping for "
21                   << secs << " seconds\n";
22          boost::this_thread::sleep_for(
23               boost::chrono::seconds(secs));
24          promise.set_value();
25        });
26
27   size_t timeout_count = 0;
28   size_t secs = 2;
29
30   while (future.wait_for(boost::chrono::seconds(secs)) 
31           == boost::future_status::timeout) {
32     std::cout << "Main thread timed out\n";
33     ++timeout_count;
34   }
35   assert(future.is_ready());
36   assert(future.get_state() == boost::future_state::ready);
37
38   std::cout << "Timed out for " << timeout_count * secs 
39             << " seconds \n";
40   thr.join();
41 }
```

这个例子演示了我们如何在 future 对象上等待固定的持续时间。我们创建了一个 promise-future 对（第 11-12 行），但是`boost::future<>`和`boost::promise<>`的模板参数是 void。这意味着我们可以纯粹用于信号/等待，但不能在线程之间传输任何数据。

我们创建了一个线程`thr`（第 16 行），传递一个 lambda，它捕获了 promise 对象。这个线程简单地睡眠在 10 到 19 秒之间的随机持续时间，通过将随机持续时间传递给`boost::this_thread::sleep_for`（第 22 行），然后退出。持续时间是使用`boost::chrono::seconds`函数构造的（第 23 行），并传递了使用`rand`函数计算的随机间隔`secs`（第 18 行）。我们使用`rand`是为了简洁起见，尽管 Boost 和 C++11 中提供了更可靠和健壮的设施。要使用`rand`，我们需要调用`srand`来种子随机数生成器。在 Windows 上，我们必须在每个调用`rand`的线程中调用`srand`，就像我们在这里展示的（第 17 行），而在 POSIX 上，我们应该在每个进程中调用`srand`，这可以在`main`的开始处。

在特定持续时间后，线程`thr`调用 promise 的`set_value`并返回（第 24 行）。由于 promise 的类型是`boost::promise<void>`，`set_value`不带任何参数。

在主线程中，我们运行一个循环，每次调用与`promise`相关联的 future 的`wait_for`，传递 2 秒的持续时间（第 30 行）。`wait_for`函数返回枚举类型`boost::future_state`的值。每次`wait_for`超时，它返回`boost::future_state::timeout`。一旦 promise 被设置（第 24 行），`wait_for`调用返回`boost::future_state::ready`并且循环中断。`boost::future`的`is_ready`成员函数返回`true`（第 35 行），并且`get_state`成员函数返回的 future 状态是`boost::future_state::ready`（第 36 行）。

### 在线程之间抛出异常

如果传递给`boost::thread`构造函数的初始函数允许任何异常传播，那么程序将立即通过调用`std::terminate`中止。如果我们需要从一个线程向另一个线程抛出异常来指示问题，或者传播我们在一个线程中捕获的异常到另一个线程，那么 promise/future 机制也很方便。考虑一下，在清单 10.4a 和 10.4b 中，当文件不存在或不可读时，你将如何处理：

**清单 10.6：在线程之间传递异常**

```cpp
 1 #define BOOST_THREAD_PROVIDES_FUTURE
 2 #include <boost/thread.hpp>
 3 #include <boost/thread/future.hpp>
 4 // other includes
 5
 6 std::vector<char> readFromFile(const std::string& filepath)
 7 {
 8   std::ifstream ifs(filepath, std::ios::ate);
 9   if (!ifs) {
10     throw std::runtime_error(filepath + " unreadable");
11   }
12   ... // rest of the code – check Listing 10.4a
13 }
14
15 std::vector<char> diffFiles(const std::string& file1,
16                             const std::string& file2) {
17   // set up the promise-future pair
18   boost::promise<std::vector<char> > promised_value;
19   boost::future<std::vector<char> > future_result
20                                = promised_value.get_future();
21   // spawn a reader thread for file2
22   boost::thread reader(
23                        [&promised_value, &file2]() {
24                          try {
25                            auto content = readFromFile(file2);
26                            promised_value.set_value(content);
27                          } catch (std::exception& e) {
28                            promised_value.set_exception(
29                               boost::copy_exception(e));
30                          }
31                        });
32   ...
33   std::vector<char> diff;
34   try {
35     auto content2 = future_result.get(); // this blocks
36     diff = diffContent(content1, content2);
37   } catch (std::exception& e) {
38     std::cerr << "Exception caught: " << e.what() << '\n';
39   }
40   reader.join();
41   return diff; 
42 }
```

如果`file2`是一个不存在或不可读的文件的名称（第 25 行），那么`readFromFile`函数会抛出一个异常（第 10 行），被`reader`线程捕获（第 27 行）。`reader`线程使用`set_exception`成员函数在 promise 对象中设置异常（第 28-29 行）。请注意，我们使用`boost::copy_exception`创建异常对象的副本并将其设置在 promise 对象中（第 29 行）。一旦 promise 中设置了异常，对 future 对象的`get`调用（第 35 行）会抛出该异常，需要捕获和处理（第 38 行）。

### shared_future

`boost::future`对象只能由一个线程等待。它不可复制，但可移动；因此，它的所有权可以从一个线程转移到另一个线程，从一个函数转移到另一个函数，但不能共享。如果我们希望多个线程使用 future 机制等待相同的条件，我们需要使用`boost::shared_future`。在下面的示例中，我们创建一个发布者线程，在设置带有其线程 ID 的 promise 之前等待固定的持续时间。我们还创建了三个订阅者线程，它们以不同的周期性轮询与 promise 对象关联的`boost::shared_future`对象，直到它准备就绪，然后从`shared_future`中检索发布者对象的线程 ID：

**清单 10.7：使用 shared_future**

```cpp
 1 #include <string>
 2 #include <vector>
 3 #include <iostream>
 4 #define BOOST_THREAD_PROVIDES_FUTURE
 5 #include <boost/lexical_cast.hpp>
 6 #include <boost/thread.hpp>
 7 #include <boost/thread/future.hpp>
 8 #include <boost/chrono.hpp>
 9
10 int main() {
11   boost::promise<std::string> prom;
12   boost::future<std::string> fut(prom.get_future());
13   boost::shared_future<std::string> shfut(std::move(fut));
14   boost::thread publisher([&prom]() {
15               std::string id =
16                 boost::lexical_cast<std::string>(
17                                boost::this_thread::get_id());
18               std::cout << "Publisher thread " << id 
19                         << " starting.\n";
20               boost::this_thread::sleep_for(
21                                   boost::chrono::seconds(15));
22               prom.set_value(id);
23            });
24   auto thrFunc = [](boost::shared_future<std::string> sf, 
25                     int waitFor) {
26     while (sf.wait_for(boost::chrono::seconds(waitFor))
27         == boost::future_status::timeout) {
28       std::cout << "Subscriber thread " 
29                 << boost::this_thread::get_id()
30                 << " waiting ...\n";
31     }
32
33     std::cout << "\nSubscriber thread " 
34               << boost::this_thread::get_id()
35               << " got " << sf.get() << ".\n";
36   };
37
38   boost::thread subscriber1(thrFunc, shfut, 2);
39   boost::thread subscriber2(thrFunc, shfut, 4);
40   boost::thread subscriber3(thrFunc, shfut, 6);
41
42   publisher.join();
43   subscriber1.join();
44   subscriber2.join();
45   subscriber3.join();
46 }
```

按照熟悉的模式，我们创建一个 promise（第 11 行）和一个`boost::future`（第 12 行）。使用 future 对象，我们 move-initialize 一个`shared_future`对象`shfut`（第 13 行）。`publisher`线程捕获 promise（第 14 行），并在设置其 ID 字符串到 promise 之前睡眠 15 秒（第 21 行）。

对于订阅者线程，我们将 lambda 表达式生成的函数对象存储在名为`thrFunc`的变量中（第 24 行），以便可以多次重用。订阅者线程的初始函数通过值传递一个`shared_future`参数，并且还有一个`waitFor`参数，该参数指定以秒为单位轮询`shared_future`的频率。订阅者在一个循环中调用`shared_future`上的`wait_for`，在`waitFor`秒后超时。一旦 promise 被设置（第 22 行），它就会退出循环，并通过在`shared_future`上调用`get`（第 35 行）来检索 promise 中设置的值（发布者线程的 ID）。

三个订阅者线程被创建（第 38-40 行）。请注意，它们初始函数的参数，`shared_future`对象和以秒为单位的等待时间作为额外参数传递给`boost::thread`对象的可变构造函数模板。请注意，`shared_future`是可复制的，同一个`shared_future`对象`shfut`被复制到三个订阅者线程中。

### std::future 和 std::promise

C++11 标准库提供了`std::future<>`、`std::shared_future<>`和`std::promise<>`模板，它们的行为几乎与它们的 Boost 库对应物相同。Boost 版本的额外成员函数是实验性的，但是除此之外，它们与标准库对应物相同。例如，我们可以通过在程序文本中替换以下符号来重写 10.5 和 10.7 清单：

+   将`boost::thread`替换为`std::thread`

+   将`boost::future`替换为`std::future`

+   将`boost::promise`替换为`std::promise`

+   将`boost::shared_promise`替换为`std::shared_promise`

+   将`boost::chrono`替换为`std::chrono`

此外，我们需要用标准库头文件`thread`、`future`和`chrono`分别替换包含的头文件`boost/thread.hpp`、`boost/thread/future.hpp`和`boost/chrono.hpp`。

在 10.6 清单中，我们使用`boost::promise`的`set_exception`成员函数来实现在线程边界传递异常。这需要一些更改才能与`std::promise`一起工作。C++11 引入了`std::exception_ptr`，这是一种具有共享所有权语义的特殊智能指针类型，必须包装异常对象，以便它们可以在函数和线程之间传递（见附录，*C++11 语言特性模拟*）。`std::promise`的`set_exception`成员函数接受一个`std::exception_ptr`类型的参数，而不是`std::exception`。以下代码片段显示了如何更改 10.6 清单以使用标准库：

```cpp
 1 // include other headers
 2 #include <exception>
... // other code
22   boost::thread reader(
23                        [&promised_value, &file2]() {
24                          try {
25                            auto content = readFromFile(file2);
26                            promised_value.set_value(content);
27                          } catch (std::exception& e) {
28                            promised_value.set_exception(
29                                     std::current_exception());
30                          }
31                        });
```

在这里，我们调用`std::current_exception`（第 29 行），它返回一个包装在 catch 块中当前活动异常的`std::exception_ptr`对象。这个`exception_ptr`被传递给`std::promise`的`set_exception`成员函数（第 28 行）。这些类型和函数声明可以从标准库头文件`exception`（第 2 行）中获得。

我们还可以使用`std::make_exception_ptr`从异常对象创建一个`std::exception_ptr`对象，如下面的代码片段所示（第 29 行）：

```cpp
22   boost::thread reader(
23                        [&promised_value, &file2]() {
24                          try {
25                            auto content = readFromFile(file2);
26                            promised_value.set_value(content);
27                          } catch (std::exception& e) {
28                            promised_value.set_exception(
29                                  std::make_exception_ptr(e));
30                          }
31                        });
The exception stored in a std::exception_ptr can be thrown using std::rethrow_exception, as shown here:
01 void throwAgain(std::exception_ptr eptr) {
02   // do stuff
03   std::rethrow_exception(eptr);
04 }
```

### std::packaged_task 和 std::async

虽然线程是强大的构造，但它们提供的完整的通用性和控制是以简单性为代价的。在许多情况下，最好以比创建显式线程运行任务更高的抽象级别进行操作。标准库提供了`std::async`函数模板和`std::packaged_task`类模板，为创建并发任务提供了不同的抽象级别，从而使程序员免于在此过程中编写大量样板代码。它们在 Boost 库中有对应物（`boost::async`和`boost::packaged_task`），但在撰写本文时（Boost 版本 1.57），它们的实现不完整，且在早期 C++11 环境中使用起来不太方便。

#### std::packaged_task

`std::packaged_task<>`类模板用于创建异步任务。您需要显式创建一个运行任务的线程，或者使用`packaged_task`中重载的`operator()`手动调用任务。但您不需要手动设置 promise-future 对，也不需要以任何方式处理 promise。这里是使用`std::packaged_task`重写的列表 10.6：

**列表 10.8：使用 std::packaged_task**

```cpp
 1 #include <future>
 2 #include <thread>
 3 #include <vector>
 4 // other includes
 5
 6 std::vector<char> readFromFile(const std::string& filepath)
 7 {
 8   std::ifstream ifs(filepath, std::ios::ate);
 9   if (!ifs) {
10     throw std::runtime_error(filepath + " unreadable");
11   }
12   ... // rest of the code – check Listing 10.4a
13 }
14
15 std::vector<char> diffFiles(const std::string& file1,
16                             const std::string file2)
17 {
18   typedef std::vector<char> buffer_t;
19   std::packaged_task<buffer_t(const std::string&)>
20             readerTask(readFromFile);
21   auto future = readerTask.get_future();
22
23   try {
24     std::thread thread2(std::move(readerTask), file2);
25     auto content1 = readFromFile(file1);
26     std::cout << "Read from file " << file1 << " completed.\n";
27
28     auto content2 = future.get();
29     thread2.detach();
30     return diffContent(content1, content2);
31   } catch (std::exception& e) {
32     std::cout << "Exception caught: " << e.what() << '\n';
33   }
34
35   return std::vector<char>(); 
36 }
```

在这个例子中，我们读取两个文件并计算它们的差异。为了读取文件，我们使用`readFromFile`函数，它返回一个`vector<char>`中的文件内容，或者如果文件不可读则抛出异常。我们通过阻塞调用`readFromFile`（第 25 行）读取其中一个文件，并在单独的线程中读取另一个文件。

为了与第一个文件同时读取第二个文件，我们将`readFromFile`函数包装在名为`readerTask`的`std::packaged_task`中（第 19-20 行），并在单独的线程中运行它。`readerTask`的具体类型是`std::packaged_task<buffer_t(const std::string&)>`。`packaged_task`的模板参数是包装的函数类型。在将此任务在单独的线程上启动之前，我们必须首先获取与之关联的 future 对象的引用。我们通过调用`packaged_task`的`get_future`成员函数（第 21 行）来获取与 future 对象的引用。接下来，我们创建一个线程并将打包的任务移动到这个线程（第 24 行）。这是必要的，因为`packaged_task`是可移动的但不可复制的，这就是为什么必须在将`packaged_task`对象移动之前调用`get_future`方法的原因。

线程`thread2`通过调用传递给它的`readFromFile`函数来读取`file2`。通过调用与`readerTask`关联的 future 对象的`get`成员函数（第 28 行），可以获取`readFromFile`返回的`vector<char>`。`get`调用将抛出`readFromFile`最初抛出的任何异常，比如当命名文件不存在时。

#### std::async

`std::async`函数模板从一个函数对象创建一个任务，这个任务可以在一个单独的线程中并发运行。它返回一个`std::future`对象，可以用来阻塞任务或等待它。它通过标准库头文件`future`提供。使用`std::async`，我们不再需要显式创建线程。相反，我们将要执行的函数、要传递的参数以及可选的启动策略传递给`std::async`。`std::async`根据指定的启动策略，要么在不同的线程中异步运行函数，要么在调用线程中同步运行函数。这里是使用`std::async`简单重写列表 10.5 的示例：

**列表 10.9：使用 std::async 创建并发任务**

```cpp
 1 #include <iostream>
 2 #include <thread>
 3 #include <future>
 4 #include <chrono>
 5 #include <ctime>
 6 #include <cstdlib>
 7
 8 int main()
 9 {
10   int duration = 10 + rand() % 10;
11   srand(time(0));
12   std::cout << "Main thread id="
13             << std::this_thread::get_id() << '\n';
14 
15   std::future<int> future =
16     std::async(std::launch::async,
17        [](int secs) -> int {               
18            std::cout << "Thread " << std::this_thread::get_id()
19                     << " sleeping for "
20                     << secs << " seconds\n";
21            std::this_thread::sleep_for(
22                     std::chrono::seconds(secs));
23            return secs;
24        }, duration);
25   
26   size_t timeout_count = 0, secs = 2;
27 
28   while (future.wait_for(std::chrono::seconds(secs))
29           == std::future_status::timeout) {
30     std::cout << "Main thread timed out\n";
31     ++timeout_count;
32   }
33   std::cout << "Launched task slept for " 
34             << future.get() << '\n';
35   std::cout << "Timed out for " << timeout_count * secs 
36             << " seconds \n";
37 }
```

虽然`packaged_task`抽象了 promise，`std::async`抽象了线程本身，我们不再处理`std::thread`的对象。相反，我们调用`std::async`，传递一个启动策略`std::launch::async`（第 16 行），一个函数对象（第 17 行），以及函数对象所需的任意数量的参数。它返回一个 future 对象，并异步运行传递给它的函数。

与`thread`的构造函数一样，`std::async`是一个可变参数函数，并传递需要转发给函数对象的所有参数。函数对象使用 lambda 表达式创建，并且除了按参数传递的持续时间休眠外，几乎不做任何事情。`duration`是 10 到 19 秒之间的随机值，并作为函数对象的唯一参数传递给`async`调用（第 24 行）。函数对象返回休眠的持续时间（第 23 行）。我们调用 future 对象的`wait_for`成员函数，以等待短时间直到 future 设置（第 28 行）。我们通过调用其`get`成员函数从 future 对象中检索任务的返回值（第 34 行）。

##### 启动策略

我们使用启动策略`std::launch::async`来指示我们希望任务在单独的线程上运行。这将立即在单独的线程中启动任务。使用另一个标准启动策略`std::launch::deferred`，我们可以在首次调用与关联 future 对象的`get`或`wait`（非定时等待函数）时懒惰地启动任务。任务将在调用`get`或`wait`的线程中同步运行。这也意味着，如果使用`deferred`策略并且没有调用`get`或`wait`，任务将永远不会启动。

我们无法在列表 10.10 中使用`std::launch::deferred`。这是因为我们在同一线程中等待 future 准备好（第 28 行）之前调用`get`（第 34 行）。任务在我们调用`get`之前永远不会启动，但是除非任务启动并返回一个值，future 永远不会准备好；所以我们会在`while`循环中永远旋转。

在使用`std::async`创建任务时，我们也可以省略启动策略：

```cpp
auto future = std::async([]() {...}, arg1, arg2);
```

在这种情况下，行为等同于以下调用：

```cpp
auto future = std::async(std::launch::async|std::launch::deferred,
                          []() {...}, arg1, arg2);
```

实现可以选择符合`std::launch::async`或`std::launch::deferred`的行为。此外，只有在运行时库需要支持多线程的情况下，实现才会创建一个新线程并链接到程序。使用默认策略时，当启用多线程时，`std::async`要么在新线程中启动新任务，要么将它们发布到内部线程池。如果线程池中没有空闲线程或空闲核心，任务将被同步启动。

## 基于锁的线程同步方法

到目前为止，我们已经看到了如何使用`boost::thread`和`std::thread`委托函数在单独的线程上运行。我们看到了使用`boost::future`和`boost::promise`在线程之间通信结果和异常，并通过阻塞调用在任务之间施加顺序。有时，您可以将程序分解为可以并发运行的独立任务，产生一个值、一个副作用或两者，然后由程序的另一部分消耗。启动这样的任务并使用 futures 等待它们是一种有效的策略。一旦任务返回，您可以开始下一个消耗第一阶段结果的计算阶段。

然而，通常需要多个线程同时访问和修改相同的数据结构。这些访问需要可靠地排序并且相互隔离，以防止由于不协调的并发访问导致底层数据结构中出现不一致。在本节中，我们将看一下帮助我们解决这些问题的 Boost 库。

### 数据竞争和原子操作

考虑以下代码片段。我们创建两个线程，每个线程在循环中递增一个共享的整数变量固定次数：

```cpp
int main() {
  int x = 0;
  const int max = 1000000;

  auto thrFunc = [&x]() {
                          for (int i = 0; i < max; ++i) {
                            ++x;
                          }
                        };

  boost::thread t1(thrFunc);
  boost::thread t2(thrFunc);
  t1.join();
  t2.join();

  std::cout << "Value of x: " << x << '\n';
}
```

程序结束时`x`的值是多少？由于每个线程对`x`递增了一百万次，而且有两个线程，人们可能期望它是`2000000`。你可以自行验证，递增运算符在`x`上被调用的次数不少于`N*max`次，其中`N=2`是线程数，`max`是一百万。然而，我看到`2000000`被打印出来不止一次；每次都是一个较小的数字。这种行为可能会因操作系统和硬件而有所不同，但它是相当常见的。显然，一些递增操作没有生效。

当你意识到操作`++x`涉及读取`x`的值，将一个添加到该值，然后将结果写回`x`时，原因就变得清楚了。假设`x`的值是`V`，两个线程对`V`执行操作`++x`。两个线程中的每一个都可以将 V 读取为`x`的值，执行递增操作，然后将 V+1 写回。因此，两个线程分别对`x`进行一次递增操作后，`x`的值仍然可能是如果只递增了一次。根据机器架构的不同，对于某些“原始”数据类型，更新变量的值可能需要两个 CPU 指令。并发执行两个这样的操作可能会由于*部分写入*而将值设置为两者都不想要的值。

像这样交错的操作代表了**数据竞争**—执行它们的线程被认为在执行操作步骤及其确切顺序上相互竞争，因此结果是不可预测的。

让我们使用符号[r=v1，w=v2]来表示一个线程从变量`x`中*读取*值 v1 并*写回*值 v2。请注意，在线程读取变量`x`的值和写回值之间可能有任意长的持续时间。因此，符号[r=v1，…用于表示已经读取了值 v1，但尚未进行写回，符号…w=v2]表示待定的写回已经发生。现在考虑两个线程分别对`x`进行一百万次递增操作，如下所示：

![数据竞争和原子操作](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-boost-cpp-lib/img/1217OT_10_01.jpg)

为简单起见，假设部分写入是不可能发生的。在时间**t1**，线程 1 和线程 2 都将变量`x`的值读取为 0。线程 2 递增这个值，并将值写回为 1。线程 2 继续读取和递增`x`的值 999998 次，直到在时间**t999999**写回值 999999。之后，线程 1 递增了它在**t1**读取的值 0，并将值写回为 1。接下来，线程 1 和线程 2 都读取了值 1，线程 1 写回 2，但线程 2 挂起。线程 1 继续进行 999998 次迭代，读取和递增`x`的值。它在时间**t1999999**将值 1000000 写入`x`并退出。线程 2 现在递增了它在**t1000001**读取的值 1 并写回。对于两百万次递增，`x`的最终值可能是 2。你可以将迭代次数更改为大于或等于 2 的任意数字，将线程数更改为大于或等于 2 的任意数字，这个结果仍然成立——这是并发的不确定性和非直观方面的一种度量。当我们看到操作`++x`时，我们直观地认为它是一个不可分割的或*原子操作*，但实际上并非如此。

原子操作在没有任何可观察的中间状态的情况下运行。这些操作不能交错。原子操作创建的中间状态对其他线程不可见。机器架构提供了执行原子读取-修改-写入操作的特殊指令，操作系统通常提供了使用这些原语的原子类型和操作的库接口。

增量操作`++x`显然是不可重入的。变量`x`是一个共享资源，在一个线程的读取、增量和随后的写入`x`之间，其他线程可以进行任意数量的读取-修改-写入操作——这些操作可以交错进行。对于这样的不可重入操作，我们必须找到使它们**线程安全**的方法，即通过防止多个线程之间的操作交错，比如`++x`。

### 互斥排斥和临界区

使`++x`操作线程安全的一种方法是在**临界区**中执行它。临界区是一段代码，不能同时被两个不同的线程执行。因此，来自不同线程的两次对`x`的增量可以交错进行。线程必须遵守这个协议，并且可以使用**互斥对象**来实现。互斥对象是用于同步并发访问共享资源的原语，比如变量`x`。我们在这个示例中使用`boost::mutex`类来实现这一目的，如下例所示：

**清单 10.10：使用互斥对象**

```cpp
 1 #include <boost/thread/thread.hpp>
 2 #include <boost/thread/mutex.hpp>
 3 #include <iostream>
 4
 5 int main()
 6 {
 7   int x = 0;
 8   static const int max = 1000000;
 9   boost::mutex mtx;
10
11   auto thrFunc = [&x, &mtx]() {
12     for (int i = 0; i < max; ++i) {
13       mtx.lock();
14       ++x;
15       mtx.unlock();
16     }
17   };
18
19   boost::thread t1(thrFunc);
20   boost::thread t2(thrFunc);
21
22   t1.join();
23   t2.join();
24
25   std::cout << "Value of x: " << x << '\n';
26 }
```

我们声明了一个`boost::mutex`类型的互斥对象（第 9 行），在生成线程的初始函数的 lambda 中捕获它（第 11 行），然后在执行增量操作之前通过锁定互斥对象来保护变量`x`（第 13 行），并在之后解锁它（第 15 行）。对`x`的增量操作（第 14 行）是临界区。这段代码每次都会打印以下内容：

```cpp
2000000
```

这是如何工作的？互斥对象有两种状态：**锁定**和**未锁定**。第一个调用未锁定互斥对象的`lock`成员函数的线程会锁定它，并且`lock`的调用会返回。其他调用已锁定互斥对象的`lock`的线程会**阻塞**，这意味着操作系统调度程序不会安排这些线程运行，除非发生某些事件（比如所讨论的互斥对象解锁）。然后持有锁的线程增加`x`并调用互斥对象的`unlock`成员函数来释放它持有的锁。此时，阻塞在`lock`调用中的一个线程会被唤醒，该线程的`lock`调用返回，并且该线程被安排运行。等待唤醒的线程取决于底层的本地实现。这一过程会一直持续，直到所有线程（在我们的示例中，只有两个）都运行完成。锁确保在任何时刻，只有一个线程独占持有锁，并且可以自由地增加`x`。

我们选择用互斥对象保护的部分是关键的。我们也可以选择保护整个 for 循环，就像下面的代码片段所示：

```cpp
12     mtx.lock();
13     for (int i = 0; i < max; ++i) {
14       ++x;
15     }
16     mtx.unlock();
```

`x`的最终值仍然与 10.10 清单中一样（`2000000`），但临界区会更大（第 13-15 行）。一个线程会在另一个线程甚至只能增加`x`一次之前运行完整个循环。通过限制临界区的范围和线程持有锁的时间，多个线程可以取得更加公平的进展。

一个线程也可以选择探测并查看是否可以获取互斥对象的锁，但如果不能则不阻塞。为此，线程必须调用`try_lock`成员函数而不是`lock`成员函数。调用`try_lock`会在互斥对象被锁定时返回`true`，否则返回`false`，并且如果互斥对象未被锁定则不会阻塞：

```cpp
boost::mutex mtx;
if (mtx.try_lock()) {
  std::cout << "Acquired lock\n";
} else {
  std::cout << "Failed to acquire lock\n";
}
```

一个线程也可以选择在等待获取锁时阻塞指定的持续时间，使用`try_lock_for`成员函数。如果成功获取锁并且一旦获取锁，`try_lock_for`的调用会返回`true`。否则，它会在指定持续时间内阻塞，并且一旦超时而未获取锁则返回 false：

```cpp
boost::mutex mtx;
if (mtx.try_lock_for(boost::chrono::seconds(5))) { 
  std::cout << "Acquired lock\n";
} else {
  std::cout << "Failed to acquire lock\n";
}
```

### 注意

互斥对象应该在尽可能短的时间内持有，覆盖尽可能小的代码段。由于互斥对象串行化了临界区的执行，持有互斥对象的时间越长，等待锁定互斥对象的其他线程的进展就会延迟。

#### boost::lock_guard

在互斥锁上获取锁并未能释放它是灾难性的，因为任何其他等待互斥锁的线程都将无法取得任何进展。在互斥锁上的裸`lock` / `try_lock`和`unlock`调用并不是一个好主意，我们需要一些在异常安全方式下锁定和解锁互斥锁的方法。`boost::lock_guard<>`模板使用**资源获取即初始化**（**RAII**）范式在其构造函数和析构函数中锁定和解锁互斥锁：

**列表 10.11：使用 boost::lock_guard**

```cpp
 1 #include <boost/thread/thread.hpp>
 2 #include <boost/thread/mutex.hpp>
 3 #include <iostream>
 4
 5 int main()
 6 {
 7   int x = 0;
 8   static const int max = 1000000;
 9   boost::mutex mtx;
10
11   auto thrFunc = [&x, &mtx]() {
12     for (int i = 0; i < max; ++i) {
13       boost::lock_guard<boost::mutex> lg(mtx);
14       ++x;
16     }
17   };
18
19   boost::thread t1(thrFunc);
20   boost::thread t2(thrFunc);
21
22   t1.join();
23   t2.join();
24
25   std::cout << "Value of x: " << x << '\n';
26 }
```

使用`boost::lock_guard`对象（第 13 行），我们锁定在锁保护实例化后的代码部分，直到作用域结束。`lock_guard`在构造函数中获取锁，并在析构函数中释放锁。这确保即使在关键部分出现异常，一旦作用域退出，互斥锁总是被解锁。您将锁的类型作为模板参数传递给`lock_guard`。`boost::lock_guard`不仅可以与`boost::mutex`一起使用，还可以与符合**BasicLockable**概念的任何类型一起使用，即具有可访问的`lock`和`unlock`成员函数。

我们还可以使用`boost::lock_guard`来封装已经锁定的互斥锁。为此，我们需要向`lock_guard`构造函数传递第二个参数，指示它应该假定拥有互斥锁而不尝试锁定它：

```cpp
 1 boost::mutex mtx;
 2 ...
 3 mtx.lock();  // mutex locked
 4 ...
 5 {
 6   boost::lock_guard<boost::mutex> lk(mtx, boost::adopt_lock);
 7   ...
 8 } // end of scope
```

`boost::lock_guard`在其构造函数中锁定底层互斥锁，或者采用已经锁定的互斥锁。释放互斥锁的唯一方法是让`lock_guard`超出作用域。`lock_guard`既不可复制也不可移动，因此您不能将它们从一个函数传递到另一个函数，也不能将它们存储在容器中。您不能使用`lock_guard`等待特定持续时间的互斥锁。

#### boost::unique_lock

`boost::unique_lock<>`模板是一种更灵活的替代方案，它仍然使用 RAII 来管理类似互斥锁，但提供了手动锁定和解锁的接口。为了获得这种额外的灵活性，`unique_lock`必须维护一个额外的数据成员，以跟踪互斥锁是否被线程拥有。我们可以使用`unique_lock`来管理符合**Lockable**概念的任何类。如果一个类符合 Lockable 概念，那么它符合 BasicLockable，并且另外定义了一个可访问的`try_lock`成员函数，就像`boost::mutex`一样。

我们可以将`boost::unique_lock`用作`boost::lock_guard`的替代品，但是如果`lock_guard`足够用于某个目的，则不应使用`unique_lock`。当我们想要将手动锁定与异常安全的锁管理混合使用时，`unique_lock`通常很有用。例如，我们可以重写列表 10.11 以使用`unique_lock`，如下面的代码片段所示：

```cpp
 7   int x = 0;
 8   static const int max = 1000000;
 9   boost::mutex mtx;
10
11   auto thrFunc = [&x, &mtx]() {
12     boost::unique_lock<boost::mutex> ul(mtx, boost::defer_lock);
13     assert(!ul.owns_lock());
14
15     for (int i = 0; i < max; ++i) {
16       ul.lock();
17       ++x;
18       assert(ul.owns_lock());
19       assert(ul.mutex() == &mtx);
20
21       ul.unlock();
22     }
23   };
```

与列表 10.11 不同，我们不会在每次循环迭代中创建一个新的`lock_guard`对象。相反，我们在循环开始之前创建一个封装互斥锁的单个`unique_lock`对象（第 12 行）。传递给`unique_lock`构造函数的`boost::defer_lock`参数告诉构造函数不要立即锁定互斥锁。在调用`unique_lock`的`lock`成员函数（第 16 行）增加共享变量之前，互斥锁被锁定，并且在操作之后通过调用`unique_lock`的`unlock`成员函数（第 21 行）解锁。在发生异常时，如果互斥锁被锁定，`unique_lock`析构函数将解锁互斥锁。

`unique_lock`的`owns_lock`成员函数在`unique_lock`拥有互斥锁时返回`true`，否则返回`false`（第 13 行和第 18 行）。`unique_lock`的`mutex`成员函数返回存储的互斥锁的指针（第 19 行），如果`unique_lock`没有包装有效的互斥锁，则返回`nullptr`。

#### 死锁

互斥锁提供了对共享资源的独占所有权，而许多现实世界的问题涉及多个共享资源。以多人第一人称射击游戏为例。它实时维护和更新两个列表。一个是 A 组射手，他们是带有某种弹药的玩家，另一个是 U 组玩家，他们是手无寸铁的。当玩家用尽弹药时，她会从 A 组移动到 U 组。当她的弹药补充时，她会从 U 组移回 A 组。线程 1 负责将元素从 A 组移动到 U 组，线程 2 负责将元素从 U 组移动到 A 组。

当一个新玩家加入游戏时，她会被添加到 U 组或 A 组，具体取决于她是否有弹药。当玩家在游戏中被杀死时，她会从 U 组或 A 组中被移除。但当弹药用尽或补充时，玩家会在 U 组和 A 组之间移动；因此 U 组和 A 组都需要被编辑。考虑以下代码，其中一个线程负责在弹药用尽时将玩家从 A 组移动到 U 组，另一个线程负责在弹药补充时将玩家从 U 组移回 A 组：

**清单 10.12：死锁示例**

```cpp
 1 #include <iostream>
 2 #include <cstdlib>
 3 #include <ctime>
 4 #include <set>
 5 #include <boost/thread.hpp>
 6
 7 struct player {
 8   int id;
 9   // other fields
10   bool operator < (const player& that) const {
11     return id < that.id;
12   }
13 };
14
15 std::set<player> armed, unarmed; // A, U
16 boost::mutex amtx, umtx;
17
18 auto a2u = & {
19         boost::lock_guard<boost::mutex> lka(amtx);
20         auto it = armed.find(player{playerId}); 
21         if (it != armed.end()) {
22           auto plyr = *it;
23           boost::unique_lock<boost::mutex> lku(umtx);
24           unarmed.insert(plyr);
25           lku.unlock();
26           armed.erase(it);
27         }
28       };
29
30 auto u2a = & {
31         boost::lock_guard<boost::mutex> lku(umtx);
32         auto it = unarmed.find(player{playerId});
33         if (it != unarmed.end()) {
34           auto plyr = *it;
35           boost::unique_lock<boost::mutex> lka(amtx);
36           armed.insert(plyr);
37           lka.unlock();
38           unarmed.erase(it);
39         }
40       };
41
42 void onAmmoExhausted(int playerId) { // event callback
43   boost::thread exhausted(a2u, playerId);
44   exhausted.detach();
45 }
46
47 void onAmmoReplenished(int playerId) { // event callback
48   boost::thread replenished(a2u, playerId);
49   replenished.detach();
50 }
```

每当玩家的弹药用尽时，都会调用`onAmmoExhausted`（第 42 行）函数，并传递玩家的 ID。这个函数创建一个线程来运行`a2u`函数（第 18 行），将这个玩家从 A 组（武装）移动到 U 组（非武装）。同样，当玩家的弹药补充时，会调用`onAmmoReplenished`（第 47 行）函数，然后在一个单独的线程中运行`u2a`函数，将玩家从 U 组（非武装）移动到 A 组（武装）。

互斥锁`amtx`和`umtx`控制着对`armed`和`unarmed`组的访问。要将玩家从 A 组移动到 U 组，函数`a2u`首先获取`amtx`的锁（第 19 行），然后在`armed`中查找玩家（第 20 行）。如果找到了玩家，线程会在`umtx`上获取锁（第 23 行），将玩家放入`unarmed`（第 23 行），释放`umtx`上的锁（第 24 行），并从`armed`中移除玩家（第 25 行）。

函数`u2a`本质上具有相同的逻辑，但首先获取`umtx`的锁，然后是`amtx`，这导致了一个致命的缺陷。如果一个玩家在大约相同的时间内用尽弹药，另一个玩家补充弹药，两个线程可能会同时运行`a2u`和`u2a`。也许很少见，但可能发生的是，`exhausted`线程锁定了`amtx`（第 19 行），但在它可以锁定`umtx`（第 23 行）之前，`replenished`线程锁定了`umtx`（第 31 行）。现在，`exhausted`线程等待`umtx`，而`umtx`被`replenished`线程持有，而`replenished`线程等待`amtx`，而`amtx`被`exhausted`线程持有。这两个线程没有任何可能的方式可以从这种状态中继续，它们陷入了死锁。

**死锁**是指两个或更多个线程竞争共享资源时被阻塞，它们在等待某些资源的同时持有其他资源，以至于任何一个线程都*不可能*从这种状态中前进。

在我们的例子中，只涉及了两个线程，相对容易调试和修复问题。修复死锁的黄金标准是确保**固定的锁获取顺序**——任何线程以相同的顺序获取两个给定的锁。通过重写`u2a`，如下面的代码片段所示，我们可以确保不会发生死锁：

```cpp
30 auto u2a = & {
31     boost::unique_lock<boost::mutex> 
32       lka(amtx, boost::defer_lock),
33       lku(umtx, boost::defer_lock);
34                                              
35     boost::lock(lka, lku);  // ordered locking
36     auto it = unarmed.find(player{playerId});
37     if (it != unarmed.end()) {
38       auto plyr = *it;
39       armed.insert(plyr);
40       lka.unlock();
41       unarmed.erase(it);
42     }
43   };
```

在前面的代码中，我们确保`u2a`在锁定`umtx`之前先锁定`amtx`，就像`a2u`一样。我们本可以手动按照这个顺序获取锁，但相反，我们演示了使用`boost::lock`来实现这一点。我们创建了`unique_lock`对象`lka`和`lku`，并使用`defer_lock`标志来指示我们暂时不想获取锁。然后我们调用`boost::lock`，按照我们想要获取它们的顺序传递`unique_lock`，`boost::lock`确保了这个顺序被遵守。

在这个例子中，使用`boost::unique_lock`而不是`boost::lock_guard`有两个原因。首先，我们可以创建`unique_lock`而不立即锁定互斥锁。其次，我们可以调用`unlock`提前释放`unique_lock`（第 40 行），增加锁的粒度，促进并发。

除了固定的锁获取顺序，避免死锁的另一种方法是让线程探测锁（使用`try_lock`），如果未能获取特定锁，则回溯。这通常会使代码更复杂，但有时可能是必要的。

有许多现实世界的代码示例出现死锁，就像我们例子中的代码一样，可能多年来一直正常工作，但其中潜藏着死锁。有时，在一个系统上运行时命中死锁的概率可能非常低，但当你在另一个系统上运行相同的代码时，可能会立即遇到死锁，这纯粹是因为两个系统上的线程调度差异。

### 在条件上进行同步

互斥锁通过创建临界区来串行访问共享数据。临界区就像一个带有锁和外部等待区的房间。一个线程获取锁并占据房间，而其他线程在外面等待，等待占有者离开房间，然后按照某种定义好的顺序取代它的位置。有时，线程需要等待条件变为真，比如一些共享数据改变状态。让我们看看生产者-消费者问题，看看线程等待条件的例子。

#### 条件变量和生产者-消费者问题

Unix 命令行实用程序**grep**使用正则表达式在文件中搜索文本模式。它可以搜索整个文件列表。要在文件中搜索模式，必须读取完整内容并搜索模式。根据要搜索的文件数量，可以使用一个或多个线程并发地将文件内容读入缓冲区。缓冲区可以存储在某种数据结构中，通过文件和偏移量对其进行索引。然后多个线程可以处理这些缓冲区并搜索其中的模式。

我们刚刚描述的是生产者-消费者问题的一个例子，其中一组线程生成一些内容并将其放入数据结构中，第二组线程从数据结构中读取内容，并对其进行计算。如果数据结构为空，消费者必须等待，直到生产者添加一些内容。如果数据填满了数据结构，那么生产者必须等待消费者处理一些数据，并在尝试添加更多内容之前在数据结构中腾出空间。换句话说，消费者等待某些条件得到满足，这些条件是由生产者的行为导致的，反之亦然。

模拟这种条件、等待它们并发出信号的一种方法是使用`boost::condition_variable`对象。**条件变量**与程序中可测试的运行时条件或谓词相关联。线程测试条件，如果条件不成立，则线程使用`condition_variable`对象等待条件成立。导致条件成立的另一个线程发出条件变量的信号，这会唤醒一个或多个等待的线程。条件变量与共享数据固有相关，并表示共享数据的某个条件被满足。为了让等待的线程首先测试共享数据的条件，它必须获取互斥锁。为了让发出信号的线程改变共享数据的状态，它也需要互斥锁。为了让等待的线程醒来并验证变化的结果，它再次需要互斥锁。因此，我们需要使用`boost::mutex`与`boost::condition_variable`结合使用。

现在，我们将使用条件变量解决固定大小队列的生产者-消费者问题。队列的大小是固定的，这意味着队列中的元素数量是有限的。一个或多个线程生产内容并将其入队（追加到队列）。一个或多个线程出队内容（从队列头部移除内容）并对内容进行计算。我们使用在固定大小的`boost::array`上实现的循环队列，而不是任何 STL 数据结构，如`std::list`或`std::deque`。

**清单 10.13：使用条件变量实现线程安全的固定大小队列**

```cpp
 1 #include <boost/thread/thread.hpp>
 2 #include <boost/thread/mutex.hpp>
 3 #include <boost/thread/condition_variable.hpp>
 4 #include <boost/array.hpp>
 5
 6 template <typename T, size_t maxsize>
 7 struct CircularQueue
 8 {
 9   CircularQueue () : head_(0), tail_(0) {}
10
11   void pop() {
12     boost::unique_lock<boost::mutex> lock(qlock);
13     if (size() == 0) {
14       canRead.wait(lock, [this] { return size() > 0; });
15     }
16     ++head_;
17     lock.unlock();
18     canWrite.notify_one();
19   }
20
21   T top() {
22     boost::unique_lock<boost::mutex> lock(qlock);
23    if (size() == 0) {
24       canRead.wait(lock, [this] { return size() > 0; });
25     }
26     T ret = data[head_ % maxsize];
27     lock.unlock();
28
29     return ret;
30   }
31
32   void push(T&& obj) {
33     boost::unique_lock<boost::mutex> lock(qlock);
34     if (size() == capacity()) {
35       canWrite.wait(lock, [this] 
36                         { return size() < capacity(); });
37     }
38     data[tail_++ % maxsize] = std::move(obj);
39     lock.unlock();
40     canRead.notify_one();
41   }
42
43   size_t head() const { return head_; }
44   size_t tail() const { return tail_; }
45
46   size_t count() const {
47     boost::unique_lock<boost::mutex> lock(qlock);
48     return (tail_ - head_); 
49   }
50
51 private:
52   boost::array<T, maxsize> data;
53   size_t head_, tail_;
54 
55   size_t capacity() const { return maxsize; }
56   size_t size() const { return (tail_ - head_); };
57
58   mutable boost::mutex qlock;
59   mutable boost::condition_variable canRead;
60   mutable boost::condition_variable canWrite;
61 };
62
63 int main()
64 {
65   CircularQueue<int, 200> ds;
66
67   boost::thread producer([&ds] {
68             for (int i = 0; i < 10000; ++i) {
69               ds.push(std::move(i));
70               std::cout << i << "-->"
71                   << " [" << ds.count() << "]\n";
72             }
73          });
74
75   auto func = [&ds] {
76     for (int i = 0; i < 2500; ++i) {
77       std::cout << "\t\t<--" << ds.top() << "\n";
78       ds.pop();
79     }
80   };
81
82   boost::thread_group consumers;
83   for (int i = 0; i < 4; ++i) {
84     consumers.create_thread(func);
85   }
86 
87   producer.join();
88   consumers.join_all();
89 }
```

在这个清单中，我们定义了`CircularQueue<>`模板及其成员函数，包括特别感兴趣的`pop`（第 11 行）和`push`（第 32 行）成员函数。调用`push`会阻塞，直到队列中有空间添加新元素。调用`pop`会阻塞，直到能够从队列顶部读取并移除一个元素。实用函数`top`（第 21 行）会阻塞，直到能够从队列顶部读取一个元素，并返回其副本。

为了实现必要的同步，我们定义了互斥锁`qlock`（第 58 行）和两个条件变量，`canRead`（第 59 行）和`canWrite`（第 60 行）。`canRead`条件变量与一个检查队列中是否有可读元素的谓词相关联。`canWrite`条件变量与一个检查队列中是否还有空间可以添加新元素的谓词相关联。编辑队列和以任何方式检查队列状态都需要锁定`qlock`互斥锁。

`pop`方法首先在`qlock`（第 12 行）上获取锁，然后检查队列是否为空（第 13 行）。如果队列为空，调用必须阻塞，直到有可读取的项目为止。为此，`pop`调用`canRead`条件变量上的`wait`方法，传递锁`lock`和一个 lambda 谓词进行测试（第 14 行）。调用`wait`会解锁`lock`中的互斥锁并阻塞。如果另一个线程的`push`方法调用成功并且数据可用，`push`方法会解锁互斥锁（第 39 行）并通过调用`notify_one`方法（第 40 行）通知`canRead`条件变量。这会唤醒在`pop`方法调用内部的`wait`调用中阻塞的一个线程。`wait`调用会原子性地锁定互斥锁，检查谓词（`size() > 0`）是否为真，如果是，则返回（第 14 行）。如果谓词不为真，则再次解锁互斥锁并返回等待。

`pop`方法要么从等待中唤醒，并在重新获取互斥锁后验证是否有要读取的元素，要么根本不需要等待，因为已经有要读取的元素。因此，`pop`继续移除列表头部的元素（第 16 行）。在移除元素后，它会解锁互斥锁（第 17 行）并在`canWrite`条件上调用`notify_one`（第 18 行）。如果它从一个满队列中弹出一个元素，并且有线程在`push`中阻塞，等待队列中的空间，那么调用`notify_one`会唤醒在`push`内部的`canWrite.wait(...)`中阻塞的一个线程（第 35 行），并给它添加一个项目到队列的机会。

`push`的实现实际上是对称的，并使用了我们描述的`pop`相同的概念。我们将互斥锁传递给条件变量上的`wait`方法，用`unique_lock`包装而不是`lock_guard`，因为`wait`方法需要手动访问底层互斥锁进行解锁。通过调用`unique_lock`的`mutex`成员函数从`unique_lock`中检索底层互斥锁；`lock_guard`不提供这样的机制。

为了测试我们的实现，我们创建了一个包含 200 个`int`类型元素的`CircularQueue`（第 65 行），一个将 10,000 个元素推入队列的生产者线程（第 67 行），以及四个每个弹出 2,500 个元素的消费者线程（第 82-85 行）。

消费者线程不是单独创建的，而是作为**线程组**的一部分创建的。线程组是`boost::thread_group`类型的对象，它提供了一种管理多个线程的简单方法。由于我们想要使用相同的初始函数创建四个消费者线程并将它们全部加入，因此很容易创建一个`thread_group`对象（第 82 行），使用其`create_thread`成员函数在循环中创建四个线程（第 84 行），并通过调用`join_all`方法等待组中的所有线程（第 88 行）。

##### 条件变量细微差别

我们调用`notify_one`来通知`canRead`条件变量并唤醒等待读取的一个线程（第 39 行）。相反，我们可以调用`notify_all`来*广播*事件并唤醒所有等待的线程，它仍然可以工作。但是，我们每次调用`push`时只向队列中放入一个新元素，因此被唤醒的线程中只有一个会从队列中读取新元素。其他线程会检查队列中的元素数量，发现它为空，然后回到等待状态，导致不必要的上下文切换。

但是，如果我们向队列中添加了大量元素，调用`notify_all`可能比`notify_one`更好。调用`notify_one`只会唤醒一个等待的线程，它会在循环中逐个处理元素（第 63-65 行）。调用`notify_all`会唤醒所有线程，它们会并发地更快地处理元素。

一个常见的难题是在持有互斥锁时是否调用`notify_one`/`notify_all`，就像我们之前的例子中所做的那样，还是在释放锁之后。这两种选择都同样有效，但在性能上可能会有一些差异。如果在持有互斥锁时发出条件变量信号，被唤醒的线程会立即阻塞，等待释放锁。因此，每个线程会有两次额外的上下文切换，这可能会影响性能。因此，如果在发出条件变量信号之前先解锁互斥锁，可能会带来一些性能优势。因此，通常更倾向于在解锁之后发出信号。

### 读者-写者问题

以图书馆的在线目录为例。图书馆维护一张书籍查找表。为简单起见，让我们假设书籍只能通过标题查找，并且标题是唯一的。代表各种客户端的多个线程同时在图书馆进行查找。图书管理员不时地向目录中添加新书，很少从目录中取走一本书。只有在没有相同标题的书籍或者存在旧版标题时，才能添加新书。

在下面的代码片段中，我们定义了一个表示书目条目的类型，以及代表图书馆目录的`LibraryCatalog`类的公共接口：

**清单 10.14a：图书馆目录类型和接口**

```cpp
 1 struct book_t
 2 {
 3   std::string title;
 4   std::string author;
 5   int edition;
 6 };
 7
 8 class LibraryCatalog
 9 {
10 public:
11   typedef boost::unordered_map<std::string, book_t> map_type;
12   typedef std::vector<book_t> booklist_t;
13
14   boost::optional<book_t> find_book(const std::string& title) 
15                                                       const;
16   booklist_t find_books(const std::vector<std::string>& 
17                                            titles) const;
18   bool add_book(const book_t& book);
19   bool remove_book(const std::string& title);
20 };
```

成员函数`find_book`用于查找单个标题，并将其作为`book_t`对象包装在`boost::optional`中返回。使用`boost::optional`，如果找不到标题，我们可以返回一个空值（见第二章，“与 Boost 实用工具的初次接触”）。成员函数`find_books`查找作为`vector`传递给它的标题列表，并返回`book_t`对象的向量。成员函数`add_book`向目录中添加标题，`remove_book`从目录中删除标题。

我们希望实现该类以允许多个线程同时查找标题。我们还希望允许图书管理员在读取时并发地添加和删除标题，而不会影响正确性或一致性。

只要目录中的数据不发生变化，多个线程可以同时查找标题，而无需任何同步；因为只读操作不会引入不一致性。但由于目录允许图书管理员添加和删除标题，我们必须确保这些操作不会与读操作交错。在这样制定我们的要求时，我们刚刚陈述了众所周知的并发问题，即读者-写者问题。读者-写者问题规定了以下约束：

+   任何写线程必须对数据结构进行排他访问

+   在没有写入线程的情况下，任何读取线程都可以与其他读取线程共享对数据结构的访问。

在上述语句中，*读取线程*指的是只执行只读操作的线程，比如查找标题，*写入线程*指的是以某种方式修改数据结构内容的线程，比如添加和删除标题。这有时被称为**多读者单写者**（**MRSW**）模型，因为它允许多个并发读者或单个独占写者。

虽然`boost::mutex`允许单个线程获取排他锁，但它不允许多个线程共享锁。我们需要使用`boost::shared_mutex`来实现这一目的。`boost::shared_mutex`符合*SharedLockable*概念，它包含 Lockable 概念，并且另外定义了`lock_shared`和`unlock_shared`成员函数，应该由读取线程调用。因为`shared_mutex`也符合 Lockable，所以可以使用`boost::lock_guard`或`boost::unique_lock`来对其进行排他访问。现在让我们来看一下`LibraryCatalog`的实现：

**清单 10.14b：图书馆目录实现**

```cpp
 1 #include <vector>
 2 #include <string>
 3 #include <boost/thread.hpp>
 4 #include <boost/optional.hpp>
 5 #include <boost/unordered/unordered_map.hpp>
 6
 7 struct book_t { /* definitions */ };
 8
 9
10 class LibraryCatalog {
11 public:
12   typedef boost::unordered_map<std::string, book_t> map_type;
13   typedef std::vector<book_t> booklist_t;
14
15   boost::optional<book_t> find_book(const std::string& title)
16                                                       const {
17     boost::shared_lock<boost::shared_mutex> rdlock(mtx);
18     auto it = catalog.find(title);
19
20     if (it != catalog.end()) {
21       return it->second;
22     }
23     rdlock.unlock();
24
25     return boost::none;
26   }
27
28   booklist_t find_books(const std::vector<std::string>& titles)
29                                                         const {
30     booklist_t result;
31     for (auto title : titles) {
32       auto book = find_book(title);
33
34       if (book) {
35         result.push_back(book.get());
36       }
37     }
38
39     return result;
40   }
41
42   bool add_book(const book_t& book) {
43     boost::unique_lock<boost::shared_mutex> wrlock(mtx);
44     auto it = catalog.find(book.title);
45
46     if (it == catalog.end()) {
47       catalog[book.title] = book;
48       return true;
49     }
50     else if (it->second.edition < book.edition) {
51       it->second = book;
52       return true;
53     }
54
55     return false;
56   }
57
58   bool remove_book(const std::string& title) {
59     boost::unique_lock<boost::shared_mutex> wrlock(mtx);
60     return catalog.erase(title);
61   }
62
63 private:
64   map_type catalog;
65   mutable boost::shared_mutex mtx;
66 };
```

方法`find_book`对目录执行只读操作，因此使用`boost::shared_lock`模板（第 17 行）获取共享锁。在检索到匹配的书籍后释放锁（第 23 行）。方法`find_books`是根据`find_book`实现的，它在传递给它的列表中的每个标题上调用循环中的`find_book`。这允许更好地在读取线程之间实现整体并发性，但会因为重复锁定和解锁`shared_mutex`而导致轻微的性能损失。

`add_book`和`remove_book`都是可能改变目录中元素数量的变异函数。为了修改目录，这两种方法都需要对目录进行排他性或写入锁定。因此，我们使用`unique_lock`实例来获取`shared_mutex`（第 43 行和第 59 行）上的排他锁。

#### 可升级的锁

在清单 10.14b 中`add_book`和`remove_book`方法的实现中存在一个明显的问题。这两种方法都是有条件地修改目录，根据首先运行的查找的结果。然而，在这两个操作的开始处无条件地获取了排他锁。可以想象，可能会在循环中调用`remove_book`，并严重阻碍系统的并发性，因为标题不存在，或者使用已经在目录中的书的版本调用`add_book`。

如果我们获取了共享锁来执行查找，那么在获取排他锁修改目录之前，我们必须释放它。在这种情况下，查找的结果将不再可靠，因为在释放共享锁和获取排他锁之间，其他线程可能已经修改了目录。

这个问题可以通过使用`boost::upgrade_lock`和一组相关的原语来解决。这在以下`add_book`的重写中显示：

```cpp
 1 bool LibraryCatalog::add_book(const book_t& book) {
 2   boost::upgrade_lock<boost::shared_mutex> upglock(mtx);
 3   auto it = catalog.find(book.title);
 4
 5   if (it == catalog.end()) {
 6     boost::upgrade_to_unique_lock<boost::shared_mutex> 
 7                                             ulock(upglock);
 8     catalog[book.title] = book;
 9     return true;
10   } else if (it->second.edition > book.edition) {
11     boost::upgrade_to_unique_lock<boost::shared_mutex> 
12                                             ulock(upglock);
13     it->second = book;
14     return true;
15   }
16
17   return false;
18 }
```

我们不是从一开始就获取独占锁，而是在执行查找之前获取*升级锁*（第 2 行），然后只有在需要修改目录时才将其*升级*为唯一锁（第 6-7 行和第 11-12 行）。要获取升级锁，我们将共享互斥量包装在`upgrade_lock<boost::shared_mutex>`实例中（第 2 行）。如果互斥量上有独占锁或另一个升级锁在生效，则会阻塞，但否则即使有共享锁也会继续。因此，在任何时间点，互斥量上可以有任意数量的共享锁，最多只能有一个升级锁。因此，获取升级锁不会影响读并发性。一旦执行查找，并确定需要执行写操作，升级锁就会通过将其包装在`upgrade_to_unique_lock<boost::shared_mutex>`实例中（第 6-7 行和第 11-12 行）来升级为唯一锁。这会阻塞，直到没有剩余的共享锁，然后*原子地*释放升级所有权并在`shared_mutex`上获取独占所有权。

### 注意

获取升级锁表示有可能将其升级为独占锁并执行写入或修改。

#### 共享互斥量的性能

`boost::shared_mutex`比`boost::mutex`慢，但在已经被读锁定的互斥量上获取额外的读锁要快得多。它非常适合频繁的并发读取，很少需要独占写访问。每当需要频繁写入时，只需使用`boost::mutex`来提供独占写访问。

大多数 MRSW 问题的解决方案要么偏向读取者，要么偏向写入者。在**偏向读取的解决方案**中，当共享锁生效时，新的读取线程可以获取共享锁，即使有一个等待获取独占锁的写入者。这导致写入者饥饿，因为写入者只有在没有读取者时才能获取独占锁。在**偏向写入的解决方案**中，如果有一个写入者线程在等待独占锁，那么即使现有的读取者持有共享锁，新的读取者也会排队。这会影响读取的并发性。Boost 1.57（当前版本）提供了一个完全公平的共享/独占锁实现，既不偏向读取者也不偏向写入者。

### 标准库原语

C++11 标准库引入了`std::mutex`和一整套用于锁的 RAII 包装器，包括`std::lock_guard`、`std::unique_lock`和`std::lock`，都在头文件`mutex`中可用。C++11 标准库还引入了`std::condition_variable`，可在头文件`condition_variable`中使用。C++14 标准库引入了`std::shared_timed_mutex`，对应于`boost::shared_mutex`和`std::shared_lock`，都在头文件`mutex`中可用。它们对应于它们的同名 Boost 对应物，并且具有非常相似的接口。截至 C++14，标准库中没有升级锁设施，也没有方便的`boost::thread_group`的等效物。

# Boost 协程

协程是可以*yield*或放弃控制权给另一个协程的函数，然后再次获得控制权，从之前放弃控制权的地方继续执行。自动变量的状态在 yield 和恢复之间保持不变。协程可用于复杂的控制流模式，代码既简单又清晰。Boost 协程库提供了两种类型的协程：

+   非对称协程：非对称协程区分调用者和被调用者协程。使用非对称协程时，被调用者只能向调用者产生输出。它们通常用于从被调用者到调用者的单向数据传输，或者反之亦然。

+   对称协程：这种协程可以*yield*给其他协程，不管调用者是谁。它们可以用于生成复杂的协作协程链。

当协程放弃控制时，它被挂起，即它的寄存器被保存，并且它放弃控制给另一个函数。在恢复时，寄存器被恢复，执行继续到挂起点之后。Boost Coroutine 库利用 Boost Context 库来实现这一目的。

*堆栈协程*与*无堆栈协程*之间有区别。堆栈协程可以从由协程调用的函数中挂起，也就是说，从嵌套的堆栈帧中挂起。对于无堆栈协程，只有顶层例程可以挂起自己。在本章中，我们只关注不对称的堆栈协程。

## 不对称协程

用于定义不对称协程的核心模板称为`boost::coroutines::asymmetric_coroutine<>`。它接受一个表示从一个协程传输到另一个协程的值类型参数。如果不需要传输值，可以是`void`。

调用其他协程或向它们产出数据的协程必须有一种方式来引用其他协程。嵌套类型`asymmetric_coroutine<T>::push_type`表示提供类型为`T`的数据的协程，而嵌套类型`asymmetric_coroutine<T>::pull_type`表示消耗类型为`T`的数据的协程。这两种类型都是可调用类型，具有重载的`operator()`。使用这些类型，我们现在将编写一个程序，使用协程从元素的向量中读取数据：

**清单 10.15：使用不对称协程**

```cpp
 1 #include <iostream>
 2 #include <boost/coroutine/all.hpp>
 3 #include <boost/bind.hpp>
 4 #include <vector>
 5 #include <string>
 6
 7 template <typename T>
 8 using pull_type = typename
 9   boost::coroutines::asymmetric_coroutine<T>::pull_type;
10
11 template <typename T>
12 using push_type = typename
13   boost::coroutines::asymmetric_coroutine<T>::push_type;
14
15 template <typename T>
16 void getNextElem(push_type<T>& sink, 
17                  const std::vector<T>& vec)
18 {
19   for (const auto& elem: vec) {
20     sink(elem);
21   }
22 }
23
24 int main()
25 {
26   std::vector<std::string> vec{"hello", "hi", "hola", 
27                                "servus"};
28   pull_type<std::string> greet_func(
29       boost::bind(getNextElem<std::string>, ::_1, 
30       boost::cref(vec)));
31
32   while (greet_func) {
33     std::cout << greet_func.get() << '\n';
34     greet_func();
35   }
36 }
```

首先，我们定义了两个别名模板，称为`pull_type`和`push_type`，分别指向类型参数 T 的`asymmetric_coroutine<T>::pull_type`和`asymmetric_coroutine<T>::push_type`（第 7-9 行和 11-13 行）。

函数`getNextElem`（第 16 行）旨在用作协程，每次调用时将下一个元素从向量传递给调用者。`main`函数填充了这个向量（第 26-27 行），然后重复调用`getNextElem`以获取每个元素。因此，数据从`getNextElem`传输到`main`，`main`是调用者例程，`getNextElem`是被调用者例程。

根据协程是向调用者推送数据还是从中拉取数据，它应该具有以下两种签名之一：

+   `void (push_type&)`：协程向调用者推送数据

+   `void(pull_type&)`：协程从调用者拉取数据

传递给协程的`pull_type`或`push_type`引用表示调用上下文，并代表通过它向调用者推送数据或从调用者拉取数据的通道。

调用者例程必须使用`pull_type`或`push_type`包装函数，具体取决于它是打算从中拉取数据还是向其中推送数据。在我们的情况下，`main`函数必须在`pull_type`的实例中包装`getNextElem`。然而，`getNextElem`的签名是：

```cpp
void (push_type&, const std::vector<T>&)
```

因此，我们必须使用某种机制（如 lambda 或`bind`）将其调整为符合签名。我们使用`boost::bind`将`getNextElem`的第二个参数绑定到向量（第 29-30 行），并将结果的一元函数对象包装在名为`greet_func`的`pull_type`实例中。创建`pull_type`实例会首次调用`getNextElem`协程。

我们可以在布尔上下文中使用`greet_func`来检查是否从被调用者那里获得了值，并且我们使用这一点在循环中旋转（第 32 行）。在循环的每次迭代中，我们调用`pull_type`实例上的`get`成员函数，以获取`getNextElem`提供的下一个值（第 33 行）。然后，我们调用`pull_type`的重载`operator()`，将控制权交给`getNextElem`协程（第 34 行）。

另一方面，`getNextElem`协程不使用传统的返回值将数据发送回调用者。它通过向量进行迭代，并在调用上下文中使用重载的`operator()`来返回每个元素（第 20 行）。如果调用者必须将数据推送到被调用者，那么调用者将在`push_type`中包装被调用者，被调用者将传递给调用者的引用包装在`pull_type`中。在下一章中，我们将看到 Boost Asio 如何使用协程来简化异步事件驱动逻辑。

# 自测问题

对于多项选择题，选择所有适用的选项：

1.  如果在`boost::thread`对象和`std::thread`对象上不调用`join`或`detach`会发生什么？

a. 在`boost::thread`的基础线程上调用`join`。

b. 对于`std::thread`，将调用`std::terminate`，终止程序。

c. 在`boost::thread`的基础线程上调用`detach`。

d. 在`std::thread`的基础线程上调用`detach`。

1.  如果允许异常传播到创建`boost::thread`对象的初始函数之外会发生什么？

a. 程序将通过`std::terminate`终止。

b. 这是未定义的行为。

c. 在调用线程上`future`对象的`get`调用会抛出异常。

d. 线程终止，但异常不会传播。

1.  在不持有相关互斥量的情况下，您应该在`condition_variable`对象上调用`notify_one`或`notify_all`吗？

a. 不会，调用会阻塞。

b. 是的，但在某些情况下可能会导致优先级反转。

c. 不会，一些等待的线程可能会错过信号。

d. 是的，甚至可能更快。

1.  使用`boost::unique_lock`而不是`boost::lock_guard`的优势是什么？

a. `boost::unique_lock`更有效率和轻量级。

b. `boost::unique_lock`可以或者采用已经获取的锁。

c. `boost::lock_guard`不能在中间范围内解锁和重新锁定。

d. `boost::unique_lock`可以推迟获取锁。

1.  以下哪些关于`boost::shared_mutex`是正确的？

a. `shared_mutex`比`boost::mutex`更轻量级和更快。

b. Boost 对`shared_mutex`的实现没有读者或写者偏向。

c. `shared_mutex`可以用作可升级的锁。

d. `shared_mutex`非常适合高写入争用的系统。

# 摘要

在本章中，我们学习了如何使用 Boost Thread 库和 C++11 标准库来编写线程和任务的并发逻辑。我们学习了如何使用期望和承诺范式来定义并发任务之间的操作顺序，以及标准库中围绕期望和承诺的一些抽象。我们还研究了各种基于锁的线程同步原语，并将它们应用于一些常见的多线程问题。

多线程是一个困难而复杂的主题，本章仅介绍了 Boost 中可用的便携式 API 来编写并发程序。Boost Thread 库和 C++标准库中的并发编程接口是一个不断发展的集合，我们没有涵盖几个功能：C++内存模型和原子操作，Boost Lockfree，线程取消，使用`boost::future`进行实验性延续等等。设计并发系统和并发数据结构的架构问题是其他相关主题，超出了本书的范围。希望本章介绍的概念和方法能帮助您在这些方向上进一步探索。

# 参考

+   *C++ Concurrency in Action*, *Anthony Williams*, *Manning Publications*

+   无锁数据结构：[`www.boost.org/libs/lockfree`](http://www.boost.org/libs/lockfree)

+   *向 C++标准库添加协程的提案（修订版 1）*，*Oliver Kowalke* 和 *Nat Goodspeed*: [`www.open-std.org/jtc1/sc22/wg21/docs/papers/2014/n3985.pdf`](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2014/n3985.pdf)

+   无锁编程，Herb Sutter: [`youtu.be/c1gO9aB9nbs`](https://youtu.be/c1gO9aB9nbs)

+   atomic<> Weapons（视频），Herb Sutter:

+   [`channel9.msdn.com/Shows/Going+Deep/Cpp-and-Beyond-2012-Herb-Sutter-atomic-Weapons-1-of-2`](https://channel9.msdn.com/Shows/Going+Deep/Cpp-and-Beyond-2012-Herb-Sutter-atomic-Weapons-1-of-2)

+   [`channel9.msdn.com/Shows/Going+Deep/Cpp-and-Beyond-2012-Herb-Sutter-atomic-Weapons-2-of-2`](https://channel9.msdn.com/Shows/Going+Deep/Cpp-and-Beyond-2012-Herb-Sutter-atomic-Weapons-2-of-2)
