# Boost C++ 库学习手册（二）

> 原文：[`zh.annas-archive.org/md5/9ADEA77D24CFF2D20B546F835360FD23`](https://zh.annas-archive.org/md5/9ADEA77D24CFF2D20B546F835360FD23)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：内存管理和异常安全

C++与 C 编程语言有很高的兼容性。C++保留了指针来表示和访问特定的内存地址，并通过`new`和`delete`运算符提供了手动内存管理原语。您还可以无缝地从 C++访问 C 标准库函数和大多数主要操作系统的 C 系统调用或平台 API。自然地，C++代码经常处理对各种 OS 资源的*句柄*，如堆内存、打开的文件、套接字、线程和共享内存。获取这些资源并未能释放它们可能会对您的程序产生不良后果，表现为隐匿的错误，包括内存泄漏和死锁。

在本章中，我们将探讨使用**智能指针**封装动态分配对象的指针的方法，以确保在不再需要时它们会自动释放。然后我们将这些技术扩展到非内存资源。在这个过程中，我们将理解什么是异常安全的代码，并使用智能指针来编写这样的代码。

这些主题分为以下几个部分：

+   动态内存分配和异常安全

+   智能指针

+   唯一所有权语义

+   共享所有权语义

在本章的某些部分，您将需要使用支持 C++11 的编译器。这将在各个部分中附加说明。

# 动态内存分配和异常安全

想象一下，您需要编写一个程序来旋转图像。您的程序接受文件名和旋转角度作为输入，读取文件的内容，执行处理，并返回输出。以下是一些示例代码。

```cpp
 1 #include <istream>
 2 #include <fstream>
 3 typedef unsigned char byte;
 4 
 5 byte *rotateImage(std::string imgFile, double angle, 
 6                   size_t& sz) {
 7   // open the file for reading
 8   std::ifstream imgStrm(imgFile.c_str(), std::ios::binary);
 9 
10   if (imgStrm) {
11     // determine file size
12     imgStrm.seekg(0, std::ios::end);
13     sz = imgStrm.tellg();
14     imsStrm.seekg(0);        // seek back to start of stream
15
16     byte *img = new byte[sz]; // allocate buffer and read
17     // read the image contents
18     imgStrm.read(reinterpret_cast<char*>(img), sz);
19     // process it
20     byte *rotated = img_rotate(img, sz, angle);
21     // deallocate buffer
22     delete [] img;
23 
24     return rotated;
25   }
26 
27   sz = 0;
28   return 0;
29 }
```

旋转图像的实际工作是由一个名为`img_rotate`的虚构的 C++ API 完成的（第 20 行）。`img_rotate`函数接受三个参数：图像内容作为字节数组，数组的大小以非 const 引用的形式，以及旋转角度。它返回旋转后图像的内容作为动态分配的字节数组。通过作为第三个参数传递的引用返回该数组的大小。这是一个不完美的代码，更像是 C 语言。这样的代码在“野外”中非常常见，这就是为什么了解它的缺陷很重要。因此，让我们来剖析一下问题。

为了读取图像文件的内容，我们首先确定文件的大小（第 12-13 行），然后分配一个足够大的字节数组`img`来容纳文件中的所有数据（第 16 行）。我们读取图像内容（第 18 行），并在通过调用`img_rotate`进行图像旋转后，删除包含原始图像的缓冲区`img`（第 22 行）。最后，我们返回旋转后的图像的字节数组（第 24 行）。为简单起见，我们没有检查读取错误（第 18 行）。

在前面的代码中有两个明显的问题。如果图像旋转失败（第 19 行）并且`img_rotate`抛出异常，那么`rotateImage`函数将在不释放字节缓冲区`img`的情况下返回，这样就会*泄漏*。这是一个明显的例子，说明在面对异常时代码的行为不佳，也就是说，它不是*异常安全*的。此外，即使一切顺利，该函数也会返回旋转后的缓冲区（第 24 行），这本身是动态分配的。因此，我们完全将其释放的责任留给调用者，没有任何保证。我们应该做得更好。

还有一个不太明显的问题。 `img_rotate`函数应该已经记录了它如何分配内存，以便我们知道如何释放它——通过调用数组删除（`delete []`）运算符（第 22 行）。但是，如果开发`img_rotate`找到了更有效的自定义内存管理方案，并希望在下一个版本中使用呢？他们会避免这样做；否则，所有客户端代码都会中断，因为`delete []`运算符可能不再是正确的释放内存的方式。理想情况下，`img_rotate` API 的客户端不应该为此烦恼。

## 异常安全和 RAII

在前面的例子中，我们非正式地看了一下异常安全的概念。我们看到`img_rotate` API 可能抛出的潜在异常可能会在`rotateImage`函数中泄漏资源。事实证明，您可以根据一组标准称为**The Abrahams Exception Safety Guarantees**来推断代码在面对异常时的行为。它们以 Dave Abrahams 的名字命名，他是 Boost 的联合创始人和杰出的 C++标准委员会成员，他在 1996 年正式化了这些保证。此后，它们已经被其他人进一步完善，包括特别是 Herb Sutter，并列在下面：

+   **基本保证**：中途终止的操作保留不变，并且不会泄漏资源

+   **强保证**：中途终止的操作不会产生任何影响，即操作是原子的

+   **无异常保证**：无法失败的操作

不满足这些标准的操作被称为“不安全的异常”或更通俗地说，不安全的异常。操作的适当异常安全级别是程序员的特权，但不安全的异常代码很少被接受。

用于使代码具有异常安全性的最基本和有效的 C++技术是名为**Resource Acquisition is Initialization**（**RAII**）的奇特名称。 RAII 习惯提出了封装需要手动管理的资源的以下模型：

1.  在包装对象的构造函数中封装资源获取。

1.  在包装对象的析构函数中封装资源释放。

1.  此外，为包装对象定义一致的复制和移动语义，或者禁用它们。

如果包装对象是在堆栈上创建的，则其析构函数也会在正常范围退出以及由于异常退出时调用。否则，包装对象本身应该由 RAII 习惯管理。粗略地说，您可以在堆栈上创建对象，也可以使用 RAII 来管理它们。在这一点上，我们需要一些例子，然后我们可以直接回到图像旋转示例并使用 RAII 进行修复：

```cpp
 1 struct ScopeGuard
 2 {
 3   ScopeGuard(byte *buffer) : data_(buffer) {}
 4   ~ScopeGuard() { delete [] data_; }
 5
 6   byte *get() { return data_; }
 7 private:
 8   byte *data_;
 9 };
10 
11 byte *rotateImage(std::string imgFile, double angle, size_t& sz)
12 {
13   // open the file for reading
14   std::ifstream imgStrm(imgFile.c_str(), std::ios::binary);
15 
16   if (imgStrm) {
17     // determine file size
18     imgStrm.seekg(0, std::ios::end);
19     sz = imgStrm.tellg();
20     imgStrm.seekg(0);
21
22     // allocate buffer and read
23     ScopeGuard img(new byte[sz]);
24     // read the image contents
25     imgStrm.read(reinterpret_cast<char*>(img.get()), sz);
26     // process it
27     return img_rotate(img.get(), sz, angle);
28   } // ScopeGuard destructor
29 
30   sz = 0;
31   return 0;
32 }
```

前面的代码是一个谦虚的尝试，使`rotateImage`函数在`img_rotate`函数本身是异常安全的情况下是异常安全的。首先，我们定义了一个名为`ScopeGuard`（第 1-9 行）的`struct`，用于封装由数组`new operator`分配的字符数组。它以分配的数组指针作为其构造函数参数，并将数据成员`data_`设置为该指针（第 3 行）。它的析构函数使用数组`delete`运算符（第 4 行）释放其`data_`成员指向的数组。`get`成员函数（第 6 行）提供了一种从`ScopeGuard`对象获取底层指针的方法。

在`rotateImage`函数内部，我们实例化了一个名为`img`的`ScopeGuard`对象，它包装了使用数组`new`运算符分配的字节数组（第 23 行）。我们调用打开文件流的`read`方法，并将`img`的`get`方法获取的原始字节数组传递给它（第 25 行）。我们假设读取总是成功的，但在生产代码中，我们应该始终进行适当的错误检查。最后，我们调用`img_rotate` API 并返回它返回的旋转图像（第 27 行）。当我们退出作用域时，`ScopeGuard`析构函数被调用，并自动释放封装的字节数组（第 28 行）。即使`img_rotate`抛出异常，`ScopeGuard`析构函数仍将在堆栈展开的过程中被调用。通过使用`ScopeGuard`类的 RAII，我们能够声明`rotateImage`函数永远不会泄漏包含图像数据的缓冲区。

另一方面，由`rotateImage`返回的旋转图像的缓冲区*可能*会泄漏，除非调用者注意将其分配给指针，然后以异常安全的方式释放它。`ScopeGuard`类在其当前形式下并不适用。事实证明，Boost 提供了不同类型的智能指针模板来解决这些问题，值得理解这些智能指针以及它们帮助解决的资源获取模式和异常安全问题。

# 智能指针

智能指针，明确地说，是一个封装指针访问并经常管理与指针相关的内存的类。如果你注意到了，你会注意到智能指针与菠萝的相似之处——智能指针是类，而不是指针，就像菠萝并不是真正的苹果一样。摆脱水果类比，不同类型的智能指针通常具有额外的功能，如边界检查、空指针检查和访问控制等。在 C++中，智能指针通常重载解引用运算符（`operator->`），这允许使用`operator->`在智能指针上调用的任何方法调用都绑定到底层指针上。

Boost 包括四种不同语义的智能指针。此外，由于 C++经常使用指针来标识和操作对象数组，Boost 提供了两种不同的智能数组模板，它们通过指针封装了数组访问。在接下来的章节中，我们将研究 Boost 中不同类别的智能指针及其语义。我们还将看看`std::unique_ptr`，这是一个 C++11 智能指针类，它取代了 Boost 的一个智能指针，并支持 Boost 中不容易获得的语义。

## 独占所有权语义

考虑以下代码片段来实例化一个对象并调用其方法：

```cpp
 1 class Widget;
 2 
 3 // …
 4 
 5 void useWidget()
 6 {
 7   Widget *wgt = new Widget;
 8   wgt->setTitle(...);
 9   wgt->setSize(...);
10   wgt->display(...);
11   delete wgt;
12 }
```

正如我们在前一节中看到的，前面的代码并不具有异常安全性。在动态内存上构造`Widget`对象（第 7 行）之后和销毁`Widget`对象（第 11 行）之前抛出的异常可能导致为`Widget`对象动态分配的内存泄漏。为了解决这个问题，我们需要类似于我们在前一节中编写的`ScopeGuard`类，而 Boost 则提供了`boost::scoped_ptr`模板。

### boost::scoped_ptr

以下是使用`scoped_ptr`修复的前面的示例。`scoped_ptr`模板可以从头文件`boost/scoped_ptr.hpp`中获得。它是一个仅包含头文件的库，你不需要将你的程序链接到任何其他库：

**清单 3.1：使用 scoped_ptr**

```cpp
 1 #include <boost/scoped_ptr.hpp>
 2 #include "Widget.h"  // contains the definition of Widget
 3 
 4 // …
 5 
 6 void useWidget()
 7 {
 8   boost::scoped_ptr<Widget> wgt(new Widget);
 9   wgt->setTitle(...);
10   wgt->setSize(...);
11   wgt->display(...);
12 }
```

在前面的代码中，`wgt`是`scoped_ptr<Widget>`类型的对象，它是`Widget*`指针的替代品。我们用动态分配的`Widget`对象对其进行初始化（第 8 行），并且省略了`delete`的调用。这是使这段代码具有异常安全性所需的唯一两个更改。

像`scoped_ptr`和 Boost 中的其他智能指针一样，在它们的析构函数中调用`delete`来释放封装的指针。当`useWidget`完成或者如果异常中止它，`scoped_ptr`实例`wgt`的析构函数将被调用，并且将销毁`Widget`对象并释放其内存。`scoped_ptr`中的重载解引用运算符（`operator->`）允许通过`wgt`智能指针访问`Widget`成员（第 9-11 行）。

`boost::scoped_ptr`模板的析构函数使用`boost::checked_delete`来释放封装指针指向的动态分配内存。因此，在`boost::scoped_ptr`实例超出范围时，封装指针指向的对象的类型必须在完全定义；否则，代码将无法编译。

`boost::scoped_ptr`是 Boost 智能指针中最简单的一个。它接管传递的动态分配指针，并在自己的析构函数中调用`delete`。这将使底层对象的生命周期绑定到封装`scoped_ptr`操作的范围，因此称为`scoped_ptr`。本质上，它在封装的指针上实现了 RAII。此外，`scoped_ptr`不能被复制。这意味着动态分配的对象在任何给定时间点只能被一个`scoped_ptr`实例包装。因此，`scoped_ptr`被认为具有*唯一所有权语义*。请注意，`scoped_ptr`实例不能存储在标准库容器中，因为它们在 C++11 意义上既不能被复制也不能被移动。

在下面的例子中，我们探索了`scoped_ptr`的一些更多特性：

**清单 3.2：详细介绍 scoped_ptr**

```cpp
 1 #include <boost/scoped_ptr.hpp>
 2 #include <cassert>
 3 #include "Widget.h" // Widget definition
 4 // …
 5 
 6 void useTwoWidgets()
 7 {
 8   // default constructed scoped_ptr 
 9   boost::scoped_ptr<Widget> wgt;
10   assert(!wgt);          // null test - Boolean context
11 
12   wgt.reset(new Widget); // create first widget
13   assert(wgt);          // non-null test – Boolean context
14   wgt->display();        // display first widget
15   wgt.reset(new Widget); // destroy first, create second widget
16   wgt->display();        // display second widget
17   
18   Widget *w1 = wgt.get();  // get the raw pointer
19   Widget& rw1 = *wgt;      // 'dereference' the smart pointer
20   assert(w1 == &rw1);      // same object, so same address
21
22   boost::scoped_ptr<Widget> wgt2(new Widget);
23   Widget *w2 = wgt2.get();
24   wgt.swap(wgt2);
25   assert(wgt.get() == w2);  // effect of swap
26   assert(wgt2.get() == w1); // effect of swap
27 }
```

在这个例子中，我们首先使用默认构造函数（第 9 行）构造了一个`scoped_ptr<Widget>`类型的对象。这创建了一个包含空指针的`scoped_ptr`。任何尝试对这样一个智能指针进行解引用的行为都会导致未定义的行为，通常会导致崩溃。`scoped_ptr`支持隐式转换为布尔值；因此我们可以在布尔上下文中像`wgt`这样使用`scoped_ptr`对象来检查封装的指针是否为空。在这种情况下，我们知道它应该为空，因为它是默认构造的；因此，我们断言`wgt`为空（第 10 行）。

有两种方法可以改变`scoped_ptr`中包含的指针，其中一种是使用`scoped_ptr`的`reset`成员方法。当我们在`scoped_ptr`上调用`reset`时，封装的指针被释放，并且`scoped_ptr`接管新传递的指针。因此，我们可以使用`reset`来改变`scoped_ptr`实例所拥有的指针（第 12 行）。随后，`scoped_ptr`包含一个非空指针，并且我们使用隐式转换`scoped_ptr`为布尔值的能力进行断言（第 13 行）。接下来，我们再次调用`reset`来在`wgt`中存储一个新的指针（第 15 行）。在这种情况下，先前存储的指针被释放，并且在存储新指针之前底层对象被销毁。

我们可以通过调用`scoped_ptr`的`get`成员函数（第 18 行）来获取底层指针。我们还可以通过对智能指针进行解引用（第 19 行）来获取指向的对象的引用。我们断言这个引用和`get`返回的指针都指向同一个对象（第 20 行）。

当然，改变`scoped_ptr`中包含的指针的第二种方法是交换两个`scoped_ptr`对象，它们的封装指针被交换（第 24-26 行）。这是改变动态分配对象的拥有`scoped_ptr`的唯一方法。

总之，我们可以说一旦你用`scoped_ptr`包装了一个对象，它就永远不能从`scoped_ptr`中分离出来。`scoped_ptr`可以销毁对象并接管一个新对象（使用`reset`成员函数），或者它可以与另一个`scoped_ptr`中的指针交换。在这个意义上，`scoped_ptr`表现出独特的、可转移的所有权语义。

#### scoped_ptr 的用途

`scoped_ptr`是一个轻量级且多功能的智能指针，它不仅可以作为作用域保护器，还可以用于其他用途。下面是它在代码中的使用方式。

##### 创建异常安全的作用域

`scoped_ptr`在创建异常安全的作用域时非常有用，当对象在某个作用域中动态分配。C++允许对象在堆栈上创建，通常这是你会采取的创建对象的方式，而不是动态分配它们。但是，在某些情况下，你需要通过调用返回指向动态分配对象的指针的工厂函数来实例化对象。这可能来自某个旧库，`scoped_ptr`可以成为这些指针的方便包装器。在下面的例子中，`makeWidget`就是一个这样的工厂函数，它返回一个动态分配的`Widget`：

```cpp
 1 class Widget { ... };
 2
 3 Widget *makeWidget() // Legacy function
 4 {
 5   return new Widget;
 6 }
 7 
 8 void useWidget()
 9 {
10   boost::scoped_ptr<Widget> wgt(makeWidget());
11   wgt->display();              // widget displayed
12 }   // Widget destroyed on scope exit
```

一般来说，前面形式中的`useWidget`将是异常安全的，只要从`useWidget`中调用的`makeWidget`函数也是异常安全的。

##### 在函数之间转移对象所有权

作为不可复制的对象，`scoped_ptr`对象不能从函数中以值传递或返回。可以将`scoped_ptr`的非 const 引用作为参数传递给函数，这将重置其内容并将新指针放入`scoped_ptr`对象中。

**清单 3.3：使用 scoped_ptr 进行所有权转移**

```cpp
 1 class Widget { ... };
 2
 3 void makeNewWidget(boost::scoped_ptr<Widget>& result)
 4 {
 5   result.reset(new Widget);
 6   result->setProperties(...);
 7 }
 8 
 9 void makeAndUseWidget()
10 {
11   boost::scoped_ptr<Widget> wgt; // null wgt
12   makeNewWidget(wgt);         // wgt set to some Widget object.
13   wgt->display();              // widget #1 displayed
14 
15   makeNewWidget(wgt);        // wgt reset to some other Widget.
16                              // Older wgt released.
17   wgt->display();            // widget #2 displayed
18 }
```

`makeNewWidget`函数使用传递给它的`scoped_ptr<Widget>`引用作为输出参数，用它来返回动态分配的对象（第 5 行）。每次调用`makeNewWidget`（第 12、15 行）都用新的动态分配的`Widget`对象替换其先前的内容，并删除先前的对象。这是一种将在函数内动态分配的对象所有权转移到函数外作用域的方法。这种方法并不经常使用，在 C++11 中使用`std::unique_ptr`有更多成语化的方法来实现相同的效果，这将在下一节中讨论。

##### 作为类成员

在 Boost 的智能指针中，`scoped_ptr`通常只被用作函数中的本地作用域保护，但实际上，它也可以作为类成员来确保异常安全，是一个有用的工具。

考虑以下代码，其中类`DatabaseHandler`为了记录到文件和连接到数据库创建了两个虚构类型`FileLogger`和`DBConnection`的动态分配对象。`FileLogger`和`DBConnection`以及它们的构造函数参数都是用于说明目的的虚构类。

```cpp
// DatabaseHandler.h
 1 #ifndef DATABASEHANDLER_H
 2 #define DATABASEHANDLER_H
 3
 4 class FileLogger;
 5 class DBConnection;
 6
 7 class DatabaseHandler
 8 {
 9 public:
10   DatabaseHandler();
11   ~DatabaseHandler();
12   // other methods here
13
14 private:
15   FileLogger *logger_;
16   DBConnection *dbconn_;
17 };
18
19 #endif /* DATABASEHANDLER_H */
```

前面的代码是`DatabaseHandler`类在头文件`DatabaseHandler.h`中的定义清单。`FileLogger`和`DBConnection`是不完整的类型，只被前向声明过。我们只声明了指向它们的指针，由于指针的大小不依赖于底层类型的大小，编译器不需要知道`FileHandler`和`DBConnection`的定义来确定`DatabaseHandler`类的总大小，而是以其指针成员的总大小来确定。

设计类的这种方式有一个优势。`DatabaseHandler`的客户端包括前面列出的`DatabaseHandler.h`文件，但不依赖于`FileLogger`或`DBConnection`的实际定义。如果它们的定义发生变化，客户端保持不受影响，无需重新编译。这本质上就是 Herb Sutter 所推广的**Pimpl Idiom**。类的实际实现被抽象在一个单独的源文件中：

```cpp
// DatabaseHandler.cpp
 1 #include "DatabaseHandler.h"
 2 
 3 // Dummy concrete implementations
 4 class FileLogger
 5 {
 6 public:
 7   FileLogger(const std::string& logfile) {...}
 8 private:
 9   ...
10 };
11
12 class DBConnection
13 {
14 public:
15   DBConnection(const std::string& dbhost,
16                const std::string& username,
17                const std::string& passwd) {...}
18 private:
19   ...
20 };
21
22 // class methods implementation
23 DatabaseHandler::DatabaseHandler(const std::string& logFile,
24           const std::string& dbHost,
25           const std::string& user, const std::string& passwd)
26         : logger_(new FileLogger(logFile)), 
27           dbconn_(new DBConnection(dbHost, user, passwd))
28 {}
29
30 ~DatabaseHandler()
31 {
32   delete logger_;
33   delete dbconn_;
34 }
35 
36 // Other methods
```

在这个源文件中，我们可以访问`FileLogger`和`DBConnection`的具体定义。即使这些定义和我们的实现的其他部分发生了变化，只要`DatabaseHandler`的公共方法和类布局没有发生变化，`DatabaseHandler`的客户端就不需要改变或重新编译。

但这段代码非常脆弱，可能会泄漏内存和其他资源。考虑一下如果`FileLogger`构造函数抛出异常会发生什么（第 26 行）。为`logger_`指针分配的内存会自动释放，不会造成进一步的损害。异常从`DatabaseHandler`构造函数传播到调用上下文，`DatabaseHandler`的对象不会被实例化；目前为止一切都很好。

现在考虑如果`FileLogger`对象成功构造，然后`DBConnection`构造函数抛出异常（第 27 行）。在这种情况下，异常发生时为`dbconn_`指针分配的内存会自动释放，但为`logger_`指针分配的内存不会被释放。当异常发生时，任何非 POD 类型的完全构造成员的析构函数都会被调用。但`logger_`是一个原始指针，它是一个 POD 类型，因此它没有析构函数。因此，`logger_`指向的内存泄漏了。

一般来说，如果你的类有多个指向动态分配对象的指针，确保异常安全性就变得很具挑战性，大多数围绕使用 try/catch 块的过程性解决方案都不太好扩展。智能指针是解决这类问题的完美工具，只需很少的代码就可以解决。我们在下面使用`scoped_ptr`来修复前面的例子。这是头文件：

**清单 3.4：将 scoped_ptr 用作类成员**

```cpp
// DatabaseHandler.h
 1 #ifndef DATABASEHANDLER_H
 2 #define DATABASEHANDLER_H
 3
 4 #include <boost/scoped_ptr.hpp>
 5
 6 class FileLogger;
 7 class DBConnection;
 8
 9 class DatabaseHandler
10 {
11 public:
12   DatabaseHandler(const std::string& logFile,
13        const std::string& dbHost, const std::string& user,
14        const std::string& passwd);
15   ~DatabaseHandler();
16   // other methods here
17
18 private:
19   boost::scoped_ptr<FileLogger> logger_;
20   boost::scoped_ptr<DBConnection> dbconn_;
21 
22   DatabaseHandler(const DatabaseHandler&);
23   DatabaseHandler& operator=(const DatabaseHandler&);
24 };
25 #endif /* DATABASEHANDLER_H */
```

`logger_`和`dbconn_`现在是`scoped_ptr`实例，而不是原始指针（第 19 行和第 20 行）。另一方面，由于`scoped_ptr`是不可复制的，编译器无法生成默认的复制构造函数和复制赋值运算符。我们可以像这里做的那样禁用它们（第 22 行和第 23 行），或者自己定义它们。一般来说，为`scoped_ptr`定义复制语义只有在封装类型可复制时才有意义。另一方面，使用`scoped_ptr`的`swap`成员函数可能更容易定义移动语义。现在让我们看看源文件的变化：

```cpp
// DatabaseHandler.cpp
 1 #include "DatabaseHandler.h"
 2 
 3 // Dummy concrete implementations
 4 class FileLogger
 5 {
 6 public:
 7   FileLogger(const std::string& logfile) {...}
 8 private:
 9   ...
10 };
11
12 class DBConnection
13 {
14 public:
15   DBConnection(const std::string& dbhost,
16                const std::string& username,
17                const std::string& passwd) {...}
18 private:
19   ...
20 };
21
22 // class methods implementation
23 DatabaseHandler::DatabaseHandler(const std::string& logFile,
24             const std::string& dbHost, const std::string& user,
25             const std::string& passwd)
26         : logger_(new FileLogger(logFileName)),
27           dbconn_(new DBConnection(dbsys, user, passwd))
28 {}
29
30 ~DatabaseHandler()
31 {}
32 
33 // Other methods
```

我们在构造函数初始化列表中初始化了两个`scoped_ptr`实例（第 26 行和第 27 行）。如果`DBConnection`构造函数抛出异常（第 27 行），则会调用`logger_`的析构函数，它会清理动态分配的`FileLogger`对象。

`DatabaseHandler`析构函数为空（第 31 行），因为没有 POD 类型的成员，而`scoped_ptr`成员的析构函数会自动调用。但我们仍然必须定义析构函数。你能猜到为什么吗？如果让编译器生成定义，它会在头文件中的类定义范围内生成析构函数定义。在那个范围内，`FileLogger`和`DBConnection`没有完全定义，`scoped_ptr`的析构函数将无法编译通过，因为它们使用`boost::checked_delete`（第二章，“与 Boost 实用工具的初次接触”）

### boost::scoped_array

`scoped_ptr` 类模板非常适用于单个动态分配的对象。现在，如果您还记得我们的激励示例，即编写图像旋转实用程序，我们需要在我们自定义的 `ScopeGuard` 类中包装一个动态数组，以使 `rotateImage` 函数具有异常安全性。Boost 提供了 `boost::scoped_array` 模板作为 `boost::scoped_ptr` 的数组类似物。`boost::scoped_array` 的语义与 `boost::scoped_ptr` 完全相同，只是它有一个重载的下标运算符 (`operator[]`) 用于访问封装数组的单个元素，并且不提供其他形式的间接操作符的重载 (`operator*` 和 `operator->`)。在这一点上，使用 `scoped_array` 重写 `rotateImage` 函数将是有益的。

**清单 3.5：使用 scoped_array**

```cpp
 1 #include <boost/scoped_array.hpp>
 2
 3 typedef unsigned char byte;
 4
 5 byte *rotateImage(const std::string &imgFile, double angle, 
 6                   size_t& sz) {
 7   // open the file for reading
 8   std::ifstream imgStrm(imgFile, std::ios::binary);
 9 
10   if (imgStrm) {
11     imgStrm.seekg(0, std::ios::end);
12     sz = imgStrm.tellg();            // determine file size
13     imgStrm.seekg(0);
14 
15     // allocate buffer and read
16     boost::scoped_array<byte> img(new byte[sz]);
17     // read the image contents
18     imgStrm.read(reinterpret_cast<char*>(img.get()), sz);
19 
20     byte first = img[0];  // indexed access
21     return img_rotate(img.get(), sz, angle);
22   }
23 
24   sz = 0;
25   return 0;
26 }
```

我们现在使用 `boost::scoped_array` 模板来代替我们的 `ScopeGuard` 类，以包装动态分配的数组（第 16 行）。在作用域退出时，由于正常执行或异常，`scoped_array` 的析构函数将调用包含动态数组的数组删除运算符 (`delete[]`) 并以异常安全的方式释放它。为了突出从 `scoped_array` 接口访问数组元素的能力，我们使用 `scoped_array` 的重载 `operator[]` 来访问第一个字节（第 20 行）。

`scoped_array` 模板主要用于处理大量动态数组的遗留代码。由于重载下标运算符，`scoped_array` 可以直接替换动态分配的数组。因此，将动态数组封装在 `scoped_array` 中是实现异常安全的快速途径。C++ 倡导使用 `std::vector` 而不是动态数组，这可能是你最终的目标。然而，作为几乎没有与向量相比的空间开销的包装器，`scoped_array` 可以帮助更快地过渡到异常安全的代码。

### std::unique_ptr

C++ 11 引入了 `std::unique_ptr` 智能指针模板，它取代了已弃用的 `std::auto_ptr`，支持 `boost::scoped_ptr` 和 `boost::scoped_array` 的功能，并且可以存储在标准库容器中。它在标准头文件 `memory` 中定义，与 C++11 中引入的其他智能指针一起。

`std::unique_ptr` 的成员函数很容易映射到 `boost::scoped_ptr` 的成员函数：

+   默认构造的 `unique_ptr` 包含一个空指针（`nullptr`），就像默认构造的 `scoped_ptr` 一样。

+   您可以调用 `get` 成员函数来访问包含的指针。

+   `reset` 成员函数释放旧指针并接管新指针的所有权（可以是空指针）。

+   `swap` 成员函数交换两个 `unique_ptr` 实例的内容，并且始终成功。

+   您可以使用 `operator*` 对非空的 `unique_ptr` 实例进行解引用，并使用 `operator->` 访问成员。

+   您可以在布尔上下文中使用 `unique_ptr` 实例来检查是否为空，就像 `scoped_ptr` 实例一样。

+   然而，在某些方面，`std::unique_ptr` 比 `boost::scoped_ptr` 更灵活。

+   `unique_ptr` 是可移动的，不像 `scoped_ptr`。因此，它可以存储在 C++11 标准库容器中，并且可以从函数中返回。

+   如果必须，您可以分离 `std::unique_ptr` 拥有的指针并手动管理它。

+   有一个用于动态分配数组的 `unique_ptr` 部分特化。`scoped_ptr` 不支持数组，您必须使用 `boost::scoped_array` 模板来实现这一目的。

#### 使用 unique_ptr 进行所有权转移

`std::unique_ptr` 智能指针可以像 `boost::scoped_ptr` 一样用作作用域保护。与 `boost::scoped_ptr` 不同，`unique_ptr 实例` 不需要绑定到单个作用域，可以从一个作用域移动到另一个作用域。

`std::unique_ptr`智能指针模板不能被复制，但支持移动语义。支持移动语义使得可以将`std::unique_ptr`用作函数返回值，从而在函数之间传递动态分配的对象的所有权。以下是一个这样的例子：

**列表 3.6a：使用 unique_ptr**

```cpp
// Logger.h
 1 #include <memory>
 2
 3 class Logger
 4 {
 5 public:
 6   Logger(const std::string& filename) { ... }
 7   ~Logger() {...}
 8   void log(const std::string& message, ...) { ... }
 9   // other methods
10 };
11
12 std::unique_ptr<Logger> make_logger(
13                       const std::string& filename) {
14   std::unique_ptr<Logger> logger(new Logger(filename));
15   return logger;
16 }
```

`make_logger`函数是一个工厂函数，返回一个包装在`unique_ptr`中的`Logger`的新实例（第 14 行）。一个函数可以这样使用`make_logger`：

**列表 3.6b：使用 unique_ptr**

```cpp
 1 #include "Logger.h"
 2 
 3 void doLogging(const std::string& msg, ...)
 4 {
 5   std::string logfile = "/var/MyApp/log/app.log";
 6   std::unique_ptr<Logger> logger = make_logger(logfile);
 7   logger->log(msg, ...);
 8 }
```

在函数`doLogging`中，局部变量`logger`通过从`make_logger`返回的`unique_ptr`进行移动初始化（第 6 行）。因此，`make_logger`内部创建的`unique_ptr`实例的内容被移动到变量`logger`中。当`logger`超出范围时，即`doLogging`返回时（第 8 行），它的析构函数将销毁底层的`Logger`实例并释放其内存。

#### 在`unique_ptr`中包装数组

为了说明使用`unique_ptr`包装动态数组的用法，我们将再次重写图像旋转示例（列表 3.5），将`scoped_ptr`替换为`unique_ptr`： 

**列表 3.7：使用 unique_ptr 包装数组**

```cpp
 1 #include <memory>
 2
 3 typedef unsigned char byte;
 4
 5 byte *rotateImage(std::string imgFile, double angle, size_t& sz)
 6 {
 7   // open the file for reading
 8   std::ifstream imgStrm(imgFile, std::ios::binary);
 9 
10   if (imgStrm) {
11     imgStrm.seekg(0, std::ios::end);
12     sz = imgStrm.tellg();      // determine file size
13     imgStrm.seekg(0);
14     
15     // allocate buffer and read
16     std::unique_ptr<byte[]> img(new byte[sz]);
17     // read the image contents
18     imgStrm.read(reinterpret_cast<char*>(img.get()),sz);
19     // process it
20     byte first = img[0];  // access first byte
21     return img_rotate(img.get(), sz, angle);
22   }
23 
24   sz = 0;
25   return 0;
26 }
```

除了包含不同的头文件（`memory`代替`boost/scoped_ptr.hpp`）之外，只需要编辑一行代码。在`boost::scoped_array<byte>`的位置，`img`的声明类型更改为`std::unique_ptr<byte[]>`（第 16 行）- 一个明确的替换。重载的`operator[]`仅适用于`unique_ptr`的数组特化，并用于引用数组的元素。

#### 在 C++14 中使用 make_unique

C++14 标准库包含一个函数模板`std::make_unique`，它是一个用于在动态内存上创建对象实例并将其包装在`std::unique_ptr`中的工厂函数。以下示例是对列表 3.6b 的重写，用于说明`make_unique`的用法：

**列表 3.8：使用 make unique**

```cpp
 1 #include "Logger.h"  // Listing 3.6a
 2 
 3 void doLogging(const std::string& msg, ...)
 4 {
 5   std::string filename = "/var/MyApp/log/app.log";
 6   std::unique_ptr<Logger> logger = 
 7                 std::make_unique<Logger>(filename);
 8   logger->log(msg, ...);
 9 }
```

`std::make_unique`函数模板将要构造的基础对象的类型作为模板参数，并将对象的构造函数的参数作为函数参数。我们直接将文件名参数传递给`make_unique`，它将其转发给`Logger`的构造函数（第 7 行）。`make_unique`是一个可变模板；它接受与实例化类型的构造函数参数匹配的变量数量和类型。如果`Logger`有一个两个参数的构造函数，比如一个接受文件名和默认日志级别的构造函数，我们将向`make_unique`传递两个参数：

```cpp
// two argument constructor
Logger::Logger(const std::string& filename, loglevel_t level) {
  ...
}

std::unique_ptr<Logger> logger =
 std::make_unique<Logger>(filename, DEBUG);

```

假设`loglevel_t`描述用于表示日志级别的类型，`DEBUG`描述该类型的一个有效值，前面的片段说明了使用`make_unique`与多个构造函数参数的用法。

如果您已将代码库迁移到 C++11，应优先使用`std::unique_ptr`而不是`boost::scoped_ptr`。

## 共享所有权语义

具有转移所有权能力的独特所有权语义对于大多数您使用智能指针的目的来说已经足够好了。但在一些现实世界的应用中，您需要在多个上下文中共享资源，而这些上下文中没有一个是明确的所有者。这样的资源只有在持有对共享资源的引用的所有上下文释放它们时才能释放。这种释放的时间和地点无法提前确定。

让我们通过一个具体的例子来理解这一点。在单个进程中，两个线程从内存中的同一动态分配区的不同部分读取数据。每个线程对数据进行一些处理，然后再读取更多数据。我们需要确保当最后一个线程终止时，动态分配的内存区域能够被清理释放。任何一个线程都可能在另一个线程之前终止；那么谁来释放缓冲区呢？

通过将缓冲区封装在一个智能包装器中，该包装器可以保持对其的引用计数，并且仅当计数变为零时才释放缓冲区，我们可以完全封装释放逻辑。缓冲区的用户应该切换到使用智能包装器，他们可以自由复制，并且当所有副本超出范围时，引用计数变为零并且缓冲区被释放。

### boost::shared_ptr 和 std::shared_ptr

`boost::shared_ptr`智能指针模板提供了引用计数的共享所有权语义。它使用共享引用计数来跟踪对它的引用次数，该引用计数与包装的动态分配对象一起维护。与我们迄今为止看到的其他智能指针模板一样，它实现了 RAII 习语，负责在其析构函数中销毁和释放包装的对象，但只有当所有对它的引用都被销毁时才这样做，也就是说，引用计数变为零。它是一个仅包含头文件的库，通过包括`boost/shared_ptr.hpp`可用。

`shared_ptr`于 2007 年被包含在 C++标准委员会技术报告（俗称 TR1）中，这是 C++11 标准的前身，并作为`std::tr1::shared_ptr`提供。它现在是 C++11 标准库的一部分，作为`std::shared_ptr`通过标准 C++头文件`memory`提供。如果您将代码库迁移到 C++11，应该使用`std::shared_ptr`。本节中的大部分讨论都适用于两个版本；如果有任何区别，都会被指出。

您创建`shared_ptr`实例来拥有动态分配的对象。与`boost::scoped_ptr`和`std::unique_ptr`不同，您可以复制`shared_ptr`实例。`std::shared_ptr`还支持移动语义。它存储动态分配的指针和共享引用计数对象。每次通过复制构造函数复制`shared_ptr`时，指针和引用计数对象都会被浅复制。复制`shared_ptr`实例会导致引用计数增加。`shared_ptr`实例超出范围会导致引用计数减少。`use_count`成员函数可用于获取当前引用计数。以下是一个展示`shared_ptr`的示例：

**清单 3.9：`shared_ptr`的示例**

```cpp
 1 #include <boost/shared_ptr.hpp>
 2 #include <iostream>
 3 #include <cassert>
 4 
 5 class Foo {
 6 public:
 7   Foo() {}
 8   ~Foo() { std::cout << "~Foo() destructor invoked." << '\n';}
 9 };
10 
11 typedef boost::shared_ptr<Foo> SPFoo;
12   
13 int main()
14 {
15   SPFoo f1(new Foo);
16   // SPFoo f1 = new Foo; // Won't work, explicit ctor
17   assert(f1.use_count() == 1);
18
19   // copy construction
20   SPFoo f2(f1);
21   assert(f1.use_count() == f2.use_count() && 
22          f1.get() == f2.get() && f1.use_count() == 2);
23   std::cout << "f1 use_count: " << f1.use_count() << '\n';
24          
25   SPFoo f3(new Foo);
26   SPFoo f4(f3);
27   assert(f3.use_count() == 2 && f3.get() == f4.get());
28   std::cout << "f3 use_count: " << f3.use_count() << '\n';
29  
30   // copy assignment
31   f4 = f1;
32   assert(f4.use_count() == f1.use_count() && 
33         f1.use_count() == 3 && f1.get() == f4.get());
34   assert(f3.use_count() == 1);
35   std::cout << "f1 use_count: " << f1.use_count() << '\n';
36   std::cout << "f3 use_count: " << f3.use_count() << '\n';
37 }
```

在上述代码中，我们定义了一个带有默认构造函数和打印一些消息的析构函数的`Foo`类（第 5-9 行）。我们包括了`boost/shared_ptr.hpp`（第 1 行），它提供了`boost::shared_ptr`模板。

在主函数中，我们定义了两个`shared_ptr<Foo>`实例`f1`（第 15 行）和`f3`（第 25 行），初始化为`Foo`类的两个不同动态分配的实例。请注意，`shared_ptr`构造函数是显式的，因此您不能使用赋值表达式使用隐式转换来复制初始化`shared_ptr`（第 16 行）。每个`shared_ptr<Foo>`实例在构造后的引用计数为 1（第 17 行和第 25 行）。接下来，我们创建`f2`作为`f1`的副本（第 20 行），并创建`f4`作为`f3`的副本（第 26 行）。复制会导致引用计数增加。`shared_ptr`的`get`成员函数返回封装的指针，`use_count`成员函数返回当前引用计数。使用`use_count`，我们断言`f1`和`f2`具有相同的引用计数，并使用`get`，我们断言它们包含相同的指针（第 21-22 行）。对于`f3`和`f4`也是如此（第 27 行）。

接下来，我们将`f1`复制分配给`f4`（第 31 行）。结果，`f4`现在包含与`f1`和`f2`相同的指针，并且不再与`f3`共享指针。现在，`f1`，`f2`和`f4`是指向相同指针的三个`shared_ptr<Foo>`实例，它们的共享引用计数变为 3（第 32-33 行）。`f3`不再与另一个实例共享其指针，因此其引用计数变为 1（第 34 行）。

运行上述代码，您可以期望以下输出：

```cpp
f1 use_count: 2
f3 use_count: 2
f1 use_count: 3
f3 use_count: 1
~Foo() destructor invoked.
~Foo() destructor invoked.
```

引用计数在`main`函数结束时确实变为零，并且`shared_ptr`析构函数销毁了动态创建的`Foo`实例。

#### `shared_ptr`的用途

在 C++11 之前的代码中，由于其灵活性和易用性，`boost::shared_ptr`或`std::tr1::shared_ptr`往往是智能指针的默认选择，而不是`boost::scoped_ptr`。它用于超出纯共享所有权语义的目的，这使其成为最知名的智能指针模板。在 C++11 中，应该遏制这种普遍使用，而应该优先使用`std::unique_ptr`，`shared_ptr`应该仅用于模拟真正的共享所有权语义。

##### 作为类成员

考虑一个场景，应用程序的多个组件可以共享单个数据库连接以获得更好的性能。只要有一些组件在使用它，就可以在首次请求时创建这样的连接并将其缓存。当所有组件都使用完毕后，连接应该被关闭。这是共享所有权语义的定义，`shared_ptr`在这种情况下非常有用。让我们看看应用程序组件如何使用`shared_ptr`来封装共享数据库连接：

**清单 3.10：将 shared_ptr 用作类成员**

```cpp
 1 class AppComponent
 2 {
 3 public:
 4  AppComponent() : spconn_(new DatabaseConnection(...))
 5  {}
 6 
 7  AppComponent( 
 8         const boost::shared_ptr<DatabaseConnection>& spc)
 9      : spconn_(spc) {}
11 
12  // Other public member
13  ...
14
15  boost::shared_ptr<DatabaseConnection> getConnection() {
16    return spconn_;
17  }
18 
19 private:
20  boost::shared_ptr<DatabaseConnection> spconn_;
21  // other data members
22 };
```

`AppComponent`是应用程序的一个组件，它使用包装在`shared_ptr`（第 20 行）中的数据库连接。默认构造的`AppComponent`创建一个新的数据库连接（第 4 行），但您始终可以通过传递包装在`shared_ptr`（第 7-9 行）中的现有数据库连接来创建`AppComponent`实例。`getConnection`成员函数检索包装在 shared_ptr 中的`DatabaseConnection`对象（第 16 行）。以下是一个例子：

```cpp
 1 AppComponent c1;
 2 AppComponent c2(a.getConnection());
```

在此示例中，我们创建了两个`AppComponent`实例`c1`和`c2`，它们共享相同的数据库连接。第二个实例是使用第一个实例缓存的`shared_ptr`包装的数据库连接通过`getConnection`方法获得的。无论`c1`和`c2`的销毁顺序如何，只有当两者中的最后一个被销毁时，共享连接才会被销毁。

##### 在标准库容器中存储动态分配的对象

标准库容器存储的对象被复制或移动到容器中，并随容器一起销毁。对象也通过复制或移动来检索。在 C++11 之前，没有支持移动语义，复制是在容器中存储对象的唯一机制。标准库容器不支持引用语义。您可以将动态分配对象的指针存储在容器中，但在其生命周期结束时，容器不会尝试通过指针销毁和释放这些对象。

您可以将动态分配的对象包装在`shared_ptr`或`unique_ptr`中并将它们存储在容器中。假设您可以使用 C++11，如果将它们存储在单个容器中就足够了，那么`std::unique_ptr`就足够好了。但是，如果需要在多个容器中存储相同的动态分配对象，`shared_ptr`是包装器的最佳选择。当容器被销毁时，将调用每个`shared_ptr`实例的析构函数，并将该`shared_ptr`的引用计数减少。如果任何`shared_ptr`的引用计数为零，则其中存储的底层动态对象将被释放。以下示例说明了如何将`shared_ptr`中包装的对象存储在多个 STL 容器中：

**清单 3.11：在容器中存储 shared_ptr**

```cpp
 1 class Person;
 2 typedef boost::shared_ptr<Person> PersonPtr;
 3 std::vector<PersonPtr> personList;
 4 std::multimap<std::string, PersonPtr> personNameMap;
 5 ...
 6 
 7 for (auto it = personList.begin(); 
 8      it != personList.end(); ++it) {
 9   personNameMap.insert(std::make_pair((*it)->name(), *it));
10 }
```

在前面的例子中，让我们假设有一个名为`Person`的类（第 1 行）。现在，给定一个类型为`Person`的对象列表，我们想要创建一个将名称映射到`Person`对象的映射。假设`Person`对象不能被复制，因此它们需要以指针的形式存储在容器中。我们为`shared_ptr<Person>`定义了一个类型别名称为`PersonPtr`（第 2 行）。我们还定义了用于存储`Person`对象列表的数据结构（`std::vector<PersonPtr>`（第 3 行））和将`Person`名称映射到`Person`对象的映射（`std::multimap<std::string, PersonPtr>`（第 4 行））。最后，我们从列表构造映射（第 7-9 行）。

`personNameMap`容器中的每个条目都被创建为一个人的名称和`PersonPtr`对象的`std::pair`（使用`std::make_pair`）。每个这样的条目都使用其`insert`成员函数插入到`multimap`中（第 9 行）。我们假设`Person`中有一个名为`name`的成员函数。`PersonPtr`对象作为`shared_ptr`在`vector`和`multimap`容器之间共享。当两个容器中的最后一个被销毁时，`Person`对象也将被销毁。

除了`shared_ptr`，Boost 的指针容器提供了一种在容器中存储动态分配对象的替代方法。我们将在第五章中介绍指针容器，*超越 STL 的有效数据结构*。在第九章中，*文件、目录和 IOStreams*，处理 Boost 线程，我们将看到`shared_ptr`实例如何在线程之间共享。

#### 非拥有别名 - boost::weak_ptr 和 std::weak_ptr

在上一节中，我们看到的一个例子是多个应用程序组件共享的数据库连接。这种使用方式有一定的缺点。在实例化旨在重用打开的数据库连接的应用程序组件时，您需要引用另一个使用连接的现有组件，并将该连接传递给新对象的构造函数。更可扩展的方法是解耦连接创建和应用程序组件创建，以便应用程序组件甚至不知道它们是否获得了新连接或现有可重用连接。但要求仍然是连接必须在所有客户端之间共享，并且在最后一个引用它消失时必须关闭连接。

构建这样一种机制的一种方法是使用数据库连接工厂，它根据调用者传递的连接参数创建到特定数据库实例的连接。然后将连接包装在`shared_ptr`中返回给调用者，并将其存储在可以查找的映射中。当新的客户端请求连接到相同数据库用户的相同实例时，工厂可以简单地从映射中查找现有连接并将其包装在`shared_ptr`中返回。以下是说明此逻辑的代码。它假设连接到数据库实例所需的所有信息都封装在`DBCredentials`对象中：

```cpp
 1 typedef boost::shared_ptr<DatabaseConnection> DBConnectionPtr;
 2
 3 struct DBConnectionFactory
 4 {
 5   typedef std::map<DBCredentials, DBConnectionPtr> 
 6                                             ConnectionMap;
 7
 8   static DBConnectionPtr connect(const DBCredentials& creds)
 9   {
10     auto iter = conn_map_.find(creds);
11
12     if (iter != conn_map_.end()) {
13       return iter->second;
14     } else {
15       DBConnectionPtr dbconn(new DatabaseConnection(creds));
16       conn_map_[creds] = dbconn;
17       return dbconn;
18     }
19   }
20 
21   static ConnectionMap conn_map_;
22 };
23 
24 DBConnectionFactory::ConnectionMap 
25                                DBConnectionFactory::conn_map_;
26 int main()
27 {
28   DBCredentials creds(...);
29   DBConnectionPtr dbconn = DBConnectionFactory::connect(creds);
30   DBConnectionPtr dbconn2 =DBConnectionFactory::connect(creds);
31   assert(dbconn.get() == dbconn2.get() 
32          && dbconn.use_count() == 3);
33 }
```

在前面的代码中，`DBConnectionFactory`提供了一个名为`connect`的静态方法，它接受一个`DBCredentials`对象并返回一个`shared_ptr`包装的`DatabaseConnection`（`DBConnectionPtr`）（第 8-19 行）。我们调用`DBConnectionFactory::connect`两次，传递相同的凭据。第一次调用（第 28 行）应该导致创建一个新的连接（第 15 行），而第二次调用应该只是查找并返回相同的连接（第 10-13 行）。

这段代码存在一个主要问题：`DBConnectionFactory`将连接存储在静态的`std::map` `conn_map_`（第 21 行）中的`shared_ptr`中。结果是，只有在程序结束时`conn_map_`被销毁时，引用计数才会变为 0。否则，即使没有上下文使用连接，引用计数仍保持为 1。我们要求，当所有使用共享连接的上下文退出或过期时，连接应该被销毁。显然这个要求没有得到满足。

在地图中存储原始指针（`DatabaseConnection*`）而不是`shared_ptr`（`DBConnectionPtr`）是不好的，因为我们需要为连接创建更多的`shared_ptr`实例时，能够使用我们分发的第一个`shared_ptr`实例。即使有方法可以解决这个问题（正如我们将在`enable_shared_from_this`中看到的），通过在连接映射中查找原始指针，我们也无法知道它是否仍在使用或已经被释放。

`boost::weak_ptr`模板，也可以在 C++11 中作为`std::weak_ptr`使用，是解决这个问题的正确工具。您可以使用一个或多个`weak_ptr`实例引用`shared_ptr`实例，而不会增加决定其生命周期的引用计数。使用`weak_ptr`实例，您可以安全地确定它所引用的`shared_ptr`是否仍然活动或已过期。如果没有过期，您可以使用`weak_ptr`实例来创建另一个引用相同对象的`shared_ptr`实例。现在我们将使用`weak_ptr`重写前面的示例：

**清单 3.12：使用 weak_ptr**

```cpp
 1 typedef boost::shared_ptr<DatabaseConnection> DBConnectionPtr;
 2 typedef boost::weak_ptr<DatabaseConnection> DBConnectionWkPtr;
 3
 4 struct DBConnectionFactory
 5 {
 6   typedef std::map<DBCredentials, DBConnectionWkPtr> 
 7                                             ConnectionMap;
 8
 9   static DBConnectionPtr connect(const DBCredentials& creds) {
10      ConnectionIter it = conn_map_.find(creds);
11      DBConnectionPtr connptr;
12
13     if (it != conn_map_.end() &&
14         (connptr = it->second.lock())) {
15       return connptr;
16     } else {
17       DBConnectionPtr dbconn(new DatabaseConnection(creds));
18       conn_map_[creds] = dbconn;  // weak_ptr = shared_ptr;
19       return dbconn;
20     }
21   }
22 
23   static ConnectionMap conn_map_;
24 };
25 
26 DBConnectionFactory::ConnectionMap 
27                                DBConnectionFactory::conn_map_;
28 int main()
29 {
30   DBCredentials creds(...);
31   DBConnectionPtr dbconn = DBConnectionFactory::connect(creds);
32   DBConnectionPtr dbconn2 =DBConnectionFactory::connect(creds);
33   assert(dbconn.get() == dbconn2.get() 
34          && dbconn.use_count() == 2);
35 }
```

在这个例子中，我们修改了`ConnectionMap`的定义，将`shared_ptr<DatabaseConnection>`存储为`weak_ptr<DatabaseConnection>`（第 6-7 行）。当调用`DBConnectionFactory::connect`函数时，代码查找条目（第 10 行），失败时，创建一个新的数据库连接，将其包装在`shared_ptr`中（第 17 行），并将其存储为地图中的`weak_ptr`（第 18 行）。请注意，我们使用复制赋值运算符将`shared_ptr`分配给`weak_ptr`。新构造的`shared_ptr`被返回（第 19 行）。如果查找成功，它会尝试从中检索的`weak_ptr`上调用`lock`方法来构造一个`shared_ptr`（第 12 行）。如果由`it->second`表示的检索的`weak_ptr`引用一个有效的`shared_ptr`，`lock`调用将自动返回另一个引用相同对象的`shared_ptr`，并将其分配给`connptr`变量并返回（第 15 行）。否则，`lock`调用将返回一个空的`shared_ptr`，我们将在`else`块中创建一个新的连接，就像之前描述的那样。

如果您只想检查`weak_ptr`实例是否引用有效的`shared_ptr`，而不创建一个新的`shared_ptr`引用对象，只需在`weak_ptr`上调用`expired`方法。只有当至少有一个`shared_ptr`实例仍然存在时，它才会返回`false`。

`weak_ptr`是如何实现这一点的？实际上，`shared_ptr`和`weak_ptr`是设计为相互配合使用的。每个`shared_ptr`实例都有两块内存：它封装的动态分配的对象和一个名为共享计数器的内存块，其中包含两个原子引用计数而不是一个。这两块内存都在所有相关的`shared_ptr`实例之间共享。共享计数器块也与引用这些`shared_ptr`实例的所有`weak_ptr`实例共享。

共享计数器中的第一个引用计数，*使用计数*，保持对`shared_ptr`的引用数量的计数。当此计数变为零时，封装的动态分配对象将被删除，`shared_ptr`将过期。第二个引用计数，*弱引用计数*，是`weak_ptr`引用的数量，加上 1（仅当有`shared_ptr`实例存在时）。只有当弱引用计数变为零时，也就是当所有`shared_ptr`和`weak_ptr`实例都过期时，共享计数块才会被删除。因此，任何剩余的`weak_ptr`实例都可以通过检查使用计数来判断`shared_ptr`是否已过期，并查看它是否为 0。`weak_ptr`的`lock`方法会原子地检查使用计数，并仅在它不为零时递增它，返回一个包装封装指针的有效`shared_ptr`。如果使用计数已经为零，`lock`将返回一个空的`shared_ptr`。

#### 一个 shared_ptr 的批评 - make_shared 和 enable_shared_from_this

`shared_ptr`已被广泛使用，超出了适当使用共享所有权语义的用例。这在一定程度上是由于它作为 C++ **技术报告 1**（**TR1**）发布的一部分而可用，而其他可行的选项，如 Boost 的指针容器（参见第五章，*超出 STL 的有效数据结构*）并不是 TR1 的一部分。但是`shared_ptr`需要额外的分配来存储共享计数，因此构造和销毁比`unique_ptr`和`scoped_ptr`慢。共享计数本身是一个包含两个原子整数的对象。如果您从不需要共享所有权语义但使用`shared_ptr`，则需要为共享计数支付额外的分配，并且需要为原子计数的递增和递减操作付费，这使得复制`shared_ptr`变慢。如果您需要共享所有权语义但不关心`weak_ptr`观察者，那么您需要为弱引用计数占用的额外空间付费，而这是您不需要的。

缓解这个问题的一种方法是以某种方式将两个分配（一个用于对象，一个用于共享计数）合并为一个。`boost::make_shared`函数模板（C++11 中也有`std::make_shared`）是一个可变函数模板，正是这样做的。以下是您将如何使用它的方式：

**清单 3.13：使用 make_shared**

```cpp
 1 #include <boost/make_shared.hpp>
 2
 3 struct Foo {
 4   Foo(const std::string& name, int num);
 5   ...
 6 };
 7
 8 boost::shared_ptr<Foo> spfoo = 
 9             boost::make_shared<Foo>("Foo", 10);
10
```

`boost::make_shared`函数模板将对象的类型作为模板参数，并将对象的构造函数的参数作为函数参数。我们调用`make_shared<Foo>`，将要用来构造`Foo`对象的参数传递给它（第 8-9 行）。然后函数会在内存中分配一个单一的内存块，其中放置对象，并一次性附加两个原子计数。请注意，您需要包含头文件`boost/make_shared.hpp`才能使用`make_shared`。这并不像看起来那么完美，但可能是一个足够好的折衷方案。这并不完美，因为现在它是一个单一的内存块而不是两个，并且在所有`shared_ptr`和`weak_ptr`引用之间共享。

即使所有`shared_ptr`引用都消失并且对象被销毁，只有当最后一个`weak_ptr`消失时，其内存才会被回收。同样，只有在使用持久的`weak_ptr`实例并且对象大小足够大以至于成为一个问题时，这才是一个问题。

我们之前简要讨论过`shared_ptr`的另一个问题。如果我们从同一个原始指针创建两个独立的`shared_ptr`实例，那么它们将有独立的引用计数，并且两者都会尝试在适当的时候删除封装的对象。第一个会成功，但第二个实例的析构函数很可能会崩溃，试图删除一个已经删除的实体。此外，在第一个实例超出范围后，通过第二个`shared_ptr`尝试解引用对象的任何尝试都将同样灾难性。解决这个问题的一般方法是根本不使用`shared_ptr`，而是使用`boost::intrusive_ptr`——这是我们在下一节中探讨的内容。解决这个问题的另一种方法是为包装类的实例方法提供返回`shared_ptr`的能力，使用`this`指针。为此，你的类必须从`boost::enable_shared_from_this`类模板派生。下面是一个例子：

**清单 3.14：使用 enable_shared_from_this**

```cpp
 1 #include <boost/smart_ptr.hpp>
 2 #include <boost/current_function.hpp>
 3 #include <iostream>
 4 #include <cassert>
 5
 6 class CanBeShared
 7        : public boost::enable_shared_from_this<CanBeShared> {
 8 public:
 9   ~CanBeShared() {
10     std::cout << BOOST_CURRENT_FUNCTION << '\n';
11   }
12   
13   boost::shared_ptr<CanBeShared> share()
14   {
15     return shared_from_this();
16   }
17 };
18 
19 typedef boost::shared_ptr<CanBeShared> CanBeSharedPtr;
20 
21 void doWork(CanBeShared& obj)
22 {
23   CanBeSharedPtr sp = obj.share();
24   std::cout << "Usage count in doWork "<<sp.use_count() <<'\n';
25   assert(sp.use_count() == 2);
26   assert(&obj == sp.get());
27 }
28 
29 int main()
30 {
31   CanBeSharedPtr cbs = boost::make_shared<CanBeShared>();
32   doWork(*cbs.get());
33   std::cout << cbs.use_count() << '\n';
34   assert(cbs.use_count() == 1);
35 }
```

在前面的代码中，类`CanBeShared`派生自`boost::enable_shared_from_this<CanBeShared>`（第 7 行）。如果你想知道为什么`CanBeShared`继承自一个类模板实例，该实例以`CanBeShared`本身作为模板参数，那么我建议你查阅一下奇异递归模板模式，这是一个 C++习惯用法，你可以在网上了解更多。现在，`CanBeShared`定义了一个名为`share`的成员函数，它返回包装在`shared_ptr`中的`this`指针（第 13 行）。它使用了它从基类继承的成员函数`shared_from_this`（第 15 行）来实现这一点。

在`main`函数中，我们从类型为`CanBeShared`的动态分配对象（第 31 行）创建了`CanBeSharedPtr`的实例`cbs`（它是`boost::shared_ptr<CanBeShared>`的`typedef`）。接下来，我们调用`doWork`函数，将`cbs`中的原始指针传递给它（第 32 行）。`doWork`函数被传递了一个对`CanBeShared`的引用（`obj`），并调用了它的`share`方法来获取相同对象的`shared_ptr`包装（第 23 行）。这个`shared_ptr`的引用计数现在变成了 2（第 25 行），它包含的指针指向`obj`（第 26 行）。一旦`doWork`返回，`cbs`上的使用计数就会回到 1（第 34 行）。

从对`shared_from_this`的调用返回的`shared_ptr`实例是从`enable_shared_from_this<>`基类中的`weak_ptr`成员实例构造的，并且仅在包装对象的构造函数结束时构造。因此，如果你在类的构造函数中调用`shared_from_this`，你将遇到运行时错误。你还应该避免在尚未包装在`shared_ptr`对象中的原始指针上调用它，或者在开始时就不是动态构造的对象上调用它。C++11 标准将这一功能标准化为`std::enable_shared_from_this`，可以通过标准头文件`memory`使用。我们在编写异步 TCP 服务器时广泛使用`enable_shared_from_this`，详见第十一章 *网络编程使用 Boost Asio*。

如果你有雄辩的眼力，你会注意到我们只包含了一个头文件`boost/smart_ptr.hpp`。这是一个方便的头文件，将所有可用的智能指针功能集成到一个头文件中，这样你就不必记得包含多个头文件。

### 提示

如果你可以使用 C++11，那么在大多数情况下应该使用`std::unique_ptr`，只有在需要共享所有权时才使用`shared_ptr`。如果出于某种原因仍在使用 C++03，你应该尽可能利用`boost::scoped_ptr`，或者使用`boost::shared_ptr`和`boost::make_shared`以获得更好的性能。

### 侵入式智能指针 - boost::intrusive_ptr

考虑一下当你将同一个指针包装在两个不是彼此副本的`shared_ptr`实例中会发生什么。

```cpp
 1 #include <boost/shared_ptr.hpp>
 2 
 3 int main()
 4 {
 5   boost::shared_ptr<Foo> f1 = boost::make_shared<Foo>();
 6   boost::shared_ptr<Foo> f2(f1.get());  // don't try this
 7
 8   assert(f1.use_count() == 1 && f2.use_count() == 1);
 9   assert(f1.get() == f2.get());
10 } // boom!
```

在前面的代码中，我们创建了一个`shared_ptr<Foo>`实例（第 5 行）和第二个独立的`shared_ptr<Foo>`实例，使用与第一个相同的指针（第 6 行）。其结果是两个`shared_ptr<Foo>`实例都具有引用计数为 1（第 8 行的断言），并且都包含相同的指针（第 9 行的断言）。在作用域结束时，`f1`和`f2`的引用计数都变为零，并且都尝试在相同的指针上调用`delete`（第 10 行）。由于双重删除的结果，代码几乎肯定会崩溃。从编译的角度来看，代码是完全合法的，但行为却不好。您需要防范对`shared_ptr<Foo>`的这种使用，但这也指出了`shared_ptr`的一个局限性。这个局限性是由于仅凭借原始指针，无法判断它是否已被某个智能指针引用。共享引用计数在`Foo`对象之外，不是其一部分。`shared_ptr`被称为非侵入式。

另一种方法是将引用计数作为对象本身的一部分进行维护。在某些情况下可能不可行，但在其他情况下将是完全可接受的。甚至可能存在实际维护这种引用计数的现有对象。如果您曾经使用过 Microsoft 的组件对象模型，您就使用过这样的对象。`boost::intrusive_ptr`模板是`shared_ptr`的一种侵入式替代品，它将维护引用计数的责任放在用户身上，并使用用户提供的钩子来增加和减少引用计数。如果用户愿意，引用计数可以成为类布局的一部分。这有两个优点。对象和引用计数在内存中相邻，因此具有更好的缓存性能。其次，所有`boost::intrusive_ptr`实例使用相同的引用计数来管理对象的生命周期。因此，独立的`boost::intrusive_ptr`实例不会造成双重删除的问题。实际上，您可以潜在地同时为同一个对象使用多个不同的智能指针包装器，只要它们使用相同的侵入式引用计数。

#### 使用 intrusive_ptr

要管理类型为`X`的动态分配实例，您创建`boost::intrusive_ptr<X>`实例，就像创建其他智能指针实例一样。您只需要确保有两个全局函数`intrusive_ptr_add_ref(X*)`和`intrusive_ptr_release(X*)`可用，负责增加和减少引用计数，并在引用计数变为零时调用`delete`删除动态分配的对象。如果`X`是命名空间的一部分，那么这两个全局函数最好也应该在相同的命名空间中定义，以便进行参数相关查找。因此，用户控制引用计数和删除机制，并且`boost::intrusive_ptr`提供了一个 RAII 框架，它们被连接到其中。请注意，如何维护引用计数是用户的权利，不正确的实现可能会导致泄漏、崩溃，或者至少是低效的代码。最后，这里是一些使用`boost::intrusive_ptr`的示例代码：

**清单 3.15：使用 intrusive_ptr**

```cpp
 1 #include <boost/intrusive_ptr.hpp>
 2 #include <iostream>
 3 
 4 namespace NS {
 5 class Bar {
 6 public:
 7   Bar() : refcount_(0) {}
 8  ~Bar() { std::cout << "~Bar invoked" << '\n'; }
 9 
10   friend void intrusive_ptr_add_ref(Bar*);
11   friend void intrusive_ptr_release(Bar*);
12 
13 private:
14   unsigned long refcount_;
15 };
16 
17 void intrusive_ptr_add_ref(Bar* b) {
18   b->refcount_++;
19 }
20 
21 void intrusive_ptr_release(Bar* b) {
22   if (--b->refcount_ == 0) {
23     delete b;
24   }
25 }    
26 } // end NS
27 
28 
29 int main()
30 {
31   boost::intrusive_ptr<NS::Bar> pi(new NS::Bar, true);
32   boost::intrusive_ptr<NS::Bar> pi2(pi);
33   assert(pi.get() == pi2.get());
34   std::cout << "pi: " << pi.get() << '\n'
35             << "pi2: " << pi2.get() << '\n';
36 }
```

我们使用`boost::intrusive_ptr`来包装类`Bar`的动态分配对象（第 31 行）。我们还可以将一个`intrusive_ptr<NS::Bar>`实例复制到另一个实例中（第 32 行）。类`Bar`在成员变量`refcount_`中维护其引用计数，类型为`unsigned long`（第 14 行）。`intrusive_ptr_add_ref`和`intrusive_ptr_release`函数被声明为类`Bar`的友元（第 10 和 11 行），并且在与`Bar`相同的命名空间`NS`中（第 3-26 行）。`intrusive_ptr_add_ref`每次调用时都会增加`refcount_`。`intrusive_ptr_release`会减少`refcount_`并在`refcount_`变为零时对其参数指针调用`delete`。

类`Bar`将变量`refcount_`初始化为零。我们将布尔值的第二个参数传递给`intrusive_ptr`构造函数，以便构造函数通过调用`intrusive_ptr_add_ref(NS::Bar*)`来增加`Bar`的`refcount_`（第 31 行）。这是默认行为，`intrusive_ptr`构造函数的布尔值第二个参数默认为`true`，因此我们实际上不需要显式传递它。另一方面，如果我们处理的是一个在初始化时将其引用计数设置为 1 而不是 0 的类，那么我们不希望构造函数再次增加引用计数。在这种情况下，我们应该将第二个参数传递给`intrusive_ptr`构造函数为`false`。复制构造函数总是通过调用`intrusive_ptr_add_ref`增加引用计数。每个`intrusive_ptr`实例的析构函数调用`intrusive_ptr_release`，并将封装的指针传递给它。

虽然前面的示例说明了如何使用`boost::intrusive_ptr`模板，但如果你要管理动态分配的对象，Boost 提供了一些便利。`boost::intrusive_ref_counter`包装了一些通用的样板代码，这样你就不必自己编写那么多了。以下示例说明了这种用法：

**清单 3.16：使用 intrusive_ptr 减少代码**

```cpp
 1 #include <boost/intrusive_ptr.hpp>
 2 #include <boost/smart_ptr/intrusive_ref_counter.hpp>
 3 #include <iostream>
 4 #include <cassert>
 5
 6 namespace NS {
 7 class Bar : public boost::intrusive_ref_counter<Bar> {
 8 public:
 9   Bar() {}
10   ~Bar() { std::cout << "~Bar invoked" << '\n'; }
11 };
12 } // end NS
13
14 int main() {
15   boost::intrusive_ptr<NS::Bar> pi(new NS::Bar);
16   boost::intrusive_ptr<NS::Bar> pi2(pi);
17   assert(pi.get() == pi2.get());
18   std::cout << "pi: " << pi.get() << '\n'
19             << "pi2: " << pi2.get() << '\n';
20   
21   assert(pi->use_count() == pi2->use_count()
22          && pi2->use_count() == 2);
23   std::cout << "pi->use_count() : " << pi->use_count() << '\n'
24          << "pi2->use_count() : " << pi2->use_count() << '\n';
25 }
```

我们不再维护引用计数，并为`intrusive_ptr_add_ref`和`intrusive_ptr_release`提供命名空间级别的重载，而是直接从`boost::intrusive_ref_counter<Bar>`公开继承类`Bar`。这就是我们需要做的全部。这也使得可以轻松地在任何时候获取引用计数，使用从`intrusive_ref_counter<>`继承到`Bar`的`use_count()`公共成员。请注意，`use_count()`不是`intrusive_ptr`本身的成员函数，因此我们必须使用解引用运算符(`operator->`)来调用它（第 21-24 行）。

前面示例中使用的引用计数器不是线程安全的。如果要确保引用计数的线程安全性，请编辑示例，使用`boost::thread_safe_counter`策略类作为`boost::intrusive_ref_counter`的第二个类型参数：

```cpp
 7 class Bar : public boost::intrusive_ref_counter<Bar, 
 8                               boost::thread_safe_counter>
```

有趣的是，`Bar`继承自`boost::intrusive_ref_counter`模板的一个实例化，该模板将`Bar`本身作为模板参数。这再次展示了奇特的递归模板模式的工作原理。

### shared_array

就像`boost::scoped_ptr`有一个专门用于管理动态分配数组的模板一样，有一个名为`boost::shared_array`的模板，可以用来包装动态分配的数组，并使用共享所有权语义来管理它们。与`scoped_array`一样，`boost::shared_array`有一个重载的下标运算符(`operator[]`)。与`boost::shared_ptr`一样，它使用共享引用计数来管理封装数组的生命周期。与`boost::shared_ptr`不同的是，`shared_array`没有`weak_array`。这是一个方便的抽象，可以用作引用计数的向量。我留给你进一步探索。

## 使用智能指针管理非内存资源

到目前为止，我们所见过的所有智能指针类都假设它们的资源是使用 C++的`new`运算符动态分配的，并且需要使用`delete`运算符进行删除。`scoped_array`和`shared_array`类以及`unique_ptr`的数组部分特化都假设它们的资源是动态分配的数组，并使用数组`delete`运算符(`delete[]`)来释放它们。动态内存不是程序需要以异常安全方式管理的唯一资源，智能指针忽视了这种情况。

`shared_ptr`和`std::unique_ptr`模板可以使用替代的用户指定的删除策略。这使它们适用于管理不仅是动态内存，而且几乎任何具有显式创建和删除 API 的资源，例如使用`malloc`和`free`进行 C 风格堆内存分配和释放，打开文件流，Unix 打开文件描述符和套接字，特定于平台的同步原语，Win32 API 句柄到各种资源，甚至用户定义的抽象。以下是一个简短的例子来结束本章：

```cpp
 1 #include <boost/shared_ptr.hpp>
 2 #include <stdio.h>
 3 #include <time.h>
 4 
 5 struct FILEDeleter
 6 {
 7   void operator () (FILE *fp) const {
 8     fprintf(stderr, "Deleter invoked\n");
 9     if (fp) {
10       ::fclose(fp);
11     }
12   }
13 };
14 
15 int main()
16 {
18   boost::shared_ptr<FILE> spfile(::fopen("tmp.txt", "a+"), 
19                                  FILEDeleter());
20   time_t t;
21   time(&t);
22 
23   if (spfile) {
24     fprintf(spfile.get(), "tstamp: %s\n", ctime(&t));
25   }
26 }
```

我们将`fopen`返回的`FILE`指针包装在`shared_ptr<FILE>`对象中（第 18 行）。但是，`shared_ptr`模板对`FILE`指针一无所知，因此我们还必须指定删除策略。为此，我们定义了一个名为`FILEDeleter`的函数对象（第 5 行），它的重载函数调用运算符（`operator()`，第 7 行）接受`FILE`类型的参数，并在其上调用`fclose`（如果不为空）（第 10 行）。临时的`FILEDeleter`实例作为第二个删除器参数（第 19 行）传递给`shared_ptr<FILE>`的构造函数。`shared_ptr<FILE>`的析构函数调用传递的删除器对象上的重载函数调用运算符，将存储的`FILE`指针作为参数传递。在这种情况下，重载的`operator->`几乎没有用处，因此通过使用`get`成员函数访问原始指针执行包装指针的所有操作（第 24 行）。我们还可以在`FILEDeleter`函数对象的位置使用 lambda 表达式。我们在第七章中介绍 Lambda 表达式，*高阶和编译时编程*。

如果您可以访问 C++11，最好始终使用`std::unique_ptr`来实现这些目的。使用`std::unique_ptr`，您必须为删除器的类型指定第二个模板参数。前面的例子将使用一个`std::unique_ptr`，只需进行以下编辑：

```cpp
 1 #include <memory>
...
18   std::unique_ptr<FILE, FILEDeleter> spfile(::fopen("tmp.txt", 
19                                             "a+"), FILEDeleter());
```

我们包括 C++标准头文件`memory`，而不是`boost/shared_ptr.hpp`（第 1 行），并将`fopen`调用返回的`FILE`指针包装在`unique_ptr`实例中（第 18 行），传递给它一个临时的`FILEDeleter`实例（第 19 行）。唯一的额外细节是`unique_ptr`模板的第二个类型参数，指定删除器的类型。我们还可以在 FILEDeleter 函数对象的位置使用 C++ 11 Lambda 表达式。在介绍 Lambda 表达式之后的章节中，我们将看到这种用法。

# 自测问题

对于多项选择题，选择所有适用的选项：

1.  亚伯拉罕的异常安全性保证是什么？

a. 基本的，弱的，和强的

b. 基本的，强的，不抛出异常

c. 弱的，强的，不抛出异常

d. 无，基本的，和强的

1.  `boost::scoped_ptr`和`std::unique_ptr`之间的主要区别是什么？

a. `boost::scoped_ptr`不支持移动语义

b. `std::scoped_ptr`没有数组的部分特化

c. `std::unique_ptr`可以存储在 STL 容器中

d. `std::unique_ptr`支持自定义删除器

1.  为什么`boost::shared_ptr`比其他智能指针更重？

a. 它使用共享引用计数

b. 它支持复制和移动语义

c. 它使用每个封装对象的两个分配

d. 它不比其他智能指针更重

1.  使用`boost::make_shared`创建`shared_ptr`的缺点是什么？

a. 它比直接实例化`boost::shared_ptr`慢

b. 它不是线程安全的

c. 它直到所有`weak_ptr`引用过期才释放对象内存

d. 它在 C++11 标准中不可用

1.  `boost::shared_ptr`和`std::unique_ptr`之间的主要区别是什么？

a. `std::unique_ptr`不支持复制语义

b. `std::unique_ptr`不支持移动语义

c. `boost::shared_ptr`不支持自定义删除器

d. `boost::shared_ptr`不能用于数组

1.  如果您想从类`X`的成员函数中返回包装`this`指针的`shared_ptr<X>`，以下哪个会起作用？

a. `return boost::shared_ptr<X>(this)`

b. `boost::enable_shared_from_this`

c. `boost::make_shared`

d. `boost::enable_shared_from_raw`

# 总结

本章明确了代码异常安全性的要求，然后定义了使用智能指针以异常安全的方式管理动态分配对象的各种方法。我们研究了来自 Boost 和新的 C++11 标准引入的智能指针模板，并理解了不同的所有权语义以及侵入式和非侵入式引用计数。我们还有机会看看如何调整一些智能指针模板来管理非内存资源。

希望您已经理解了各种所有权语义，并能够明智地将本章中的技术应用于这些场景。在智能指针库中有一些我们没有详细介绍的功能，比如`boost::shared_array`和`boost::enable_shared_from_raw`。您应该自行进一步探索它们，重点关注它们的适用性和缺陷。在下一章中，我们将学习使用 Boost 的字符串算法处理文本数据的一些巧妙而有用的技术。

# 参考资料

+   零规则：[`en.cppreference.com/w/cpp/language/rule_of_three`](http://en.cppreference.com/w/cpp/language/rule_of_three)

+   *设计 C++接口-异常安全性*，*Mark Radford*：[`accu.org/index.php/journals/444`](http://accu.org/index.php/journals/444)

+   *异常安全性分析*，*Andrei Alexandrescu 和 David B. Held*：[`erdani.com/publications/cuj-2003-12.pdf`](http://erdani.com/publications/cuj-2003-12.pdf)


# 第四章：处理字符串

文本数据是现代应用程序处理的最重要和普遍的数据形式。通过直观的抽象有效地处理文本数据的能力是处理文本数据有效性的关键标志。Boost 有许多专门用于有效文本处理的库，增强和扩展了 C++标准库提供的功能。

在本章中，我们将介绍三个用于处理文本数据的关键 Boost 库。我们将从 Boost String Algorithms 库开始，这是一个通用文本数据算法库，提供了大量易于使用的文本操作，通常在标准库中被忽略。然后我们将介绍 Boost Tokenizer 库，这是一个基于各种标准对字符串数据进行标记的可扩展框架。之后，我们将研究一个用于搜索和解析字符串的正则表达式库 Boost.Regex，它也已经包含在 C++11 标准中。以下主题将出现在以下各节中：

+   使用 Boost String Algorithms 库进行文本处理

+   使用 Boost Tokenizer 库拆分文本

+   使用 Boost.Regex 进行正则表达式

本章应该帮助您充分掌握 Boost 库中可用的文本处理技术。本书不涉及国际化问题，但本章讨论的大部分概念将适用于基于非拉丁字符集的书写系统的语言中的文本。

# 使用 Boost String Algorithms 库进行文本处理

文本数据通常表示为内存中连续布置的字符序列或*字符串*，并以特殊标记（空终止符）终止。虽然用于表示字符的实际数据类型可能因情况而异，但 C++标准库在类模板`std::basic_string`中抽象了字符串概念，该模板将字符数据类型作为参数。`std::basic_string`模板有三个类型参数：

+   字符类型

+   封装在特征类中的字符类型的一些固有属性和行为

+   用于为`std::basic_string`分配内部数据结构的分配器类型

特征和分配器参数被默认设置，如下面的片段所示：

```cpp
template <typename charT,
          typename Traits = std::char_traits<chart>,
          typename Allocator = std::allocator<chart>>
std::basic_string;
```

C++03 标准库还提供了`std::basic_string`的两个特化：

+   `std::string` 用于窄字符（8 位 `char`）

+   `std::wstring` 用于宽字符（16 位或 32 位 `wchar_t`）

在 C++11 中，我们还有两个：

+   `std::u16string`（用于`u16char_t`）

+   `std::u32string`（用于`u32char_t`）

除了这些类，纯旧的 C 风格字符串，即由空字符终止的`char`或`wchar_t`数组，也是相当常用的，特别是在传统的 C++代码中。

标准库中存在两个主要缺陷，使得处理文本数据类型有时过于繁琐。首先，只有一组有限的可用算法可以应用于`string`和`wstring`。此外，大多数这些算法都是`std::basic_string`的成员函数，不适用于其他字符串表示形式，如字符数组。即使作为非成员函数模板可用的算法也处理迭代器而不是容器，使得代码繁琐且不够灵活。

考虑一下如何使用 C++标准库将字符串转换为大写：

**清单 4.1：使用 std::transform 将字符串更改为大写**

```cpp
 1 #include <string>
 2 #include <algorithm>
 3 #include <cassert>
 4 #include <cctype>
 5 
 6 int main() {
 7   std::string song = "Green-tinted sixties mind";
 8   std::transform(song.begin(), song.end(), song.begin(),
 9                  ::toupper);
10 
11   assert(song == "GREEN-TINTED SIXTIES MIND");
12 }
```

我们使用`std::transform`算法将一系列字符转换为它们的大写形式，使用标准库中的`toupper`函数应用于每个字符（第 8-9 行）。要转换的字符序列由一对迭代器指定，指向字符串`song`的第一个字符（`song.begin()`）和最后一个字符的下一个位置（`song.end()`）——作为`std::transform`的前两个参数传递。转换后的序列被就地写回，从`song.begin()`开始，这是`std::transform`的第三个参数。如果您已经在 C++中编程了一段时间，可能不会看到太多问题，但是`transform`函数的普遍性有些掩盖了意图的表达。这就是 Boost String Algorithms 库的作用，它通过提供一系列有用的字符串算法函数模板来帮助，这些函数模板具有直观的命名并且有效地工作，有时甚至可以在不同的字符串抽象上使用。考虑以下替代前面代码的方法：

清单 4.2：使用 boost::to_upper 将字符串转换为大写

```cpp
 1 #include <string>
 2 #include <boost/algorithm/string.hpp>
 3 #include <cassert>
 4
 5 int main()
 6 {
 7   std::string song = "Green-tinted sixties mind";
 8   boost::to_upper(song);
 9   assert(song == "GREEN-TINTED SIXTIES MIND");
10 }
```

要将字符串`song`转换为大写，可以调用`boost::to_upper(song)`（第 8 行）。我们包含头文件`boost/algorithm/string.hpp`（第 2 行）来访问`boost::to_upper`，它是来自 Boost String Algorithms 库的算法函数模板。它被命名为`to_upper`，而不是`transform`，只需要一个参数而不是四个，也没有迭代器——有什么不喜欢的呢？此外，您可以在裸数组上运行相同的代码：

清单 4.3：使用 boost::to_upper 将字符数组转换为大写

```cpp
 1 #include <string>
 2 #include <boost/algorithm/string.hpp>
 3 #include <cassert>
 4
 5 int main()
 6 {
 7   char song[17] = "Book of Taliesyn";
 8   boost::to_upper(song);
 9   assert(std::string(song) == "BOOK OF TALIESYN");
10 }
```

但是迭代器让您选择要转换为大写的范围，而在这里，我们似乎只能将任何东西应用于整个字符串。实际上，这也不是问题，我们将会看到。

### 注意

**Boost.Range**

Boost String Algorithms 库中的算法实际上是在称为范围的抽象上工作，而不是在容器或迭代器上工作。一个**范围**只是一系列元素，可以以某种顺序完全遍历。粗略地说，像`std::string`这样的容器是一系列连续的单字节字符，而像`std::list<Foo>`这样的容器是类型为`Foo`的元素序列。因此，它们都符合有效的范围。

一个简单的范围可以由一对迭代器表示——一个指向范围中的第一个元素，另一个指向范围中最后一个元素的下一个元素。一个范围可以表示容器中所有元素的序列。进一步概括，范围可以被描述为容器的子序列，即容器中元素的子集，它们的相对顺序被保留。例如，容器中奇数索引的元素子序列是一个有效的范围。单个迭代器对可能不足以表示这样的范围；我们需要更多的构造来表示它们。

Boost.Range 库提供了生成和处理各种范围所需的必要抽象和函数。类模板`boost::iterator_range`用于使用一对迭代器表示不同类型的范围。Boost String Algorithms 中的算法接受范围作为参数，并返回范围，从而实现调用的链接，这是大多数 STL 算法无法实现的。在本章中，我们不会深入讨论 Boost.Range 的细节，但会发展对使用 String Algorithms 库的范围所需的直观理解。

如果我们只想转换字符串的一部分大小写，我们需要构造表示该部分的范围。我们可以使用`boost::iterator_range`类模板生成任意范围。下面是我们如何做到的：

清单 4.4：使用 to_upper 将字符串的一部分转换为大写

```cpp
 1 #include <string>
 2 #include <boost/algorithm/string.hpp>
 3 #include <cassert>
 4
 5 int main()
 6 {
 7   std::string song = "Green-tinted sixties mind";
 8   typedef boost::iterator_range<std::string::iterator>
 9                                                RangeType; 
10   RangeType range = boost::make_iterator_range(
11                        song.begin() + 13, song.begin() + 20);
12   boost::to_upper(range);
13   assert(song == "Green-tinted SIXTIES mind");
14 }
```

具体来说，我们希望使用两个迭代器来构造字符串的范围。因此，范围的类型将是`boost::iterator_range<std::string::iterator>`。我们为这个相当长的类型名称创建了一个 typedef（第 8-9 行）。我们希望将字符串`"Green-tinted sixties mind"`中的单词`"sixties"`更改为大写。这个单词从字符串`song`的索引 13 开始，长度为 7 个字符。因此，定义包含`"sixties"`的范围的迭代器是`song.begin() + 13`和`song.begin() + 13 + 7`，即`song.begin() + 20`。通过将这两个迭代器传递给函数模板`boost::make_iterator_range`（第 10-11 行）来构造实际范围（`range`）。我们将这个范围传递给`boost::to_upper`算法，它更改了子字符串`"sixties"`的大小写（第 12 行），并且我们断言预期的更改（第 13 行）。

这可能看起来是很多代码，但请记住，当您将算法应用于整个字符串或容器时，您不必构造显式范围。此外，如果您使用 C++11，`auto`关键字可以帮助减少冗长；因此，您可以像这样替换突出显示的行（8-11 行）：

```cpp
 8 auto range = boost::make_iterator_range(song.begin() + 13,
 9                                       song.begin() + 20);

```

您可以在附录中了解有关`auto`关键字的更多信息，*C++11 语言特性模拟*。

从数组构造迭代器范围也并不完全不同：

**清单 4.5：使用 to_upper 将 char 数组的一部分更改为大写**

```cpp
 1 #include <string>
 2 #include <boost/algorithm/string.hpp>
 3 #include <cassert>
 4
 5 int main()
 6 {
 7   char song[17] = "Book of Taliesyn";
 8 
 9   typedef boost::iterator_range<char*> RangeType; 
10   RangeType rng = boost::make_iterator_range(song + 8,
11                                              song + 16);
12   boost::to_upper(rng);
13   assert(std::string(song) == "Book of TALIESYN");
14 }
```

范围被定义为`boost::iterator_range<char*>`类型，数组的迭代器类型为`char*`（第 9 行）。再次，如果我们使用 C++11，我们可以使用`auto`来消除所有的语法痛苦。我们使用适当的偏移量（8 和 16）创建迭代器范围，限定单词`"Taliesyn"`（第 10-11 行），并使用`boost::to_upper`转换范围（第 12 行）。

## 使用 Boost 字符串算法

在本节中，我们将探讨可用的各种字符串算法，并了解它们可以应用的条件。不过，在我们查看具体算法之前，我们将首先尝试了解事情的一般方案。

考虑算法`boost::contains`。它检查作为第二个参数传递的字符串是否是作为第一个参数传递的字符串的子字符串：

**清单 4.6：使用 boost::contains**

```cpp
 1 #include <boost/algorithm/string.hpp>
 2 #include <string>
 3 #include <cassert>
 4 
 5 int main() {
 6   std::string input = "linearize";
 7   std::string test = "near";
 8   assert(boost::contains(input, test));
 9 }
```

算法`boost::contains`应该返回 true，因为`"linearize"`包含子字符串`"near"`（第 8 行）。虽然调用`boost::contains`返回 true，但如果我们将`test`设置为`"Near"`而不是`"near"`，它将返回 false。如果我们想要检查子字符串而不关心大小写，我们必须使用`boost::icontains`作为`boost::contains`的替代品。与`boost::contains`一样，来自 Boost 字符串算法的大多数算法都有一个不区分大小写的版本，带有`i-`前缀。

与`boost::contains`不同，一些字符串算法根据传递给它的字符串生成修改后的字符串内容。例如，`boost::to_lower`将传递给它的字符串内容转换为小写。它通过就地更改字符串来实现这一点，从而修改其参数。算法的非变异版本称为`boost::to_lower_copy`，它复制传递的字符串，转换复制的字符串的大小写，并返回它，而不修改原始字符串。这样的非变异变体在其名称中具有`_copy`后缀。这里是一个简短的例子：

**清单 4.7：使用 _boost 字符串算法的 _copy 版本**

```cpp
 1 #include <boost/algorithm/string.hpp>
 2 #include <string>
 3 #include <cassert>
 4 
 5 int main() {
 6   std::string str1 = "Find the Cost of Freedom";
 7   std::string str2 = boost::to_lower_copy(str1);
 8   assert(str1 != str2);
 9   boost::to_lower(str1);
10   assert(str1 == str2);
11   assert(str1 == "find the cost of freedom");
12 }
```

字符串`str1`首先被复制并转换为小写，使用非变异变体`boost::to_lower_copy`，结果被赋给`str2`（第 7 行）。此时，`str1`保持不变。接下来，`str1`被就地转换为小写，使用`boost::to_lower`（第 9 行）。此时，`str1`和`str2`都具有相同的内容（第 10 行）。在接下来的大部分内容中，我们将使用区分大小写的变体和适用的变异变体，理解到算法的不区分大小写和非变异（复制）版本也存在。我们现在开始查看特定的算法。

### 查找算法

从 Boost String Algorithms 库中有几种*find 算法*的变体可用，所有这些算法都在另一个输入字符串中搜索字符串或模式。每个算法都将输入字符串和搜索字符串作为参数，将它们转换为范围，然后执行搜索。每个 find 变体都返回与搜索字符串或模式匹配的输入中的连续子序列作为范围。如果没有找到匹配项，则返回一个空范围。

#### find_first

我们首先看一下`boost::find_first`，它在另一个字符串中查找一个字符串：

**清单 4.8：使用 boost::find_first**

```cpp
 1 #include <boost/algorithm/string.hpp>
 2 #include <string>
 3 #include <iostream>
 4 
 5 int main()
 6 {
 7   const char *haystack = "Mary had a little lamb";
 8   const char *needles[] = {"little", "Little", 0};
 9 
10   for (int i = 0; needles[i] != 0; ++i) {
11     auto ret = boost::find_first(haystack, needles[i]);
12   
13     if (ret.begin() == ret.end()) {
14       std::cout << "String [" << needles[i] << "] not found in"
15                 << " string [" << haystack << "\n";
16     } else {
17       std::cout << "String [" << needles[i] << "] found at " 
18                 << "offset " << ret.begin() - haystack
19                 << " in string [" << haystack << "\n";
20     }
21 
22     std::cout << "'" << ret << "'" << '\n';
23   }
24 }
```

我们有一个我们想要搜索的字符串数组，称为`needles`（第 8 行）。我们还有一个名为`haystack`的 C 风格字符串，在其中我们想要查找包含我们想要搜索的文本的搜索字符串（第 7 行）。我们循环遍历`needles`中的每个字符串，并调用`boost::find_first`算法在`haystack`中查找它（第 11 行）。我们检查搜索是否未能找到匹配项（第 13 行）。如果找到了匹配项，那么我们计算在`haystack`中找到匹配项的偏移量（第 18 行）。范围`ret`定义了输入字符串`haystack`的范围；因此，我们总是可以执行偏移计算，比如`ret.begin() - haystack`。

第一次迭代将能够找到`"little"`，而第二次迭代将无法找到`"Little"`，因为`boost::find_first`是区分大小写的。如果我们使用`boost::ifind_first`执行不区分大小写的搜索，那么两者都会匹配。

我们使用 C++11 的`auto`关键字来避免编写一个笨拙的`ret`类型（第 11 行），但如果我们不得不写，它将是`boost::iterator_range<char*>`。请注意，我们实际上可以将从算法返回的范围`ret`流式传输到输出流（第 22 行）。

这个例子说明了在 C 风格字符数组上的技术，但将其应用到`std::string`将需要惊人地少的更改。如果`haystack`是一个`std::string`实例，那么唯一的变化将在我们计算偏移量的方式上（第 18 行）：

```cpp
               << "offset " << ret.begin() – haystack.begin()
```

由于`haystack`不是字符数组而是一个`std::string`，所以通过调用其`begin()`成员函数来获得其开始的迭代器。

如果我们想要找到`haystack`中搜索字符串的最后一个实例，而不是第一个实例，我们可以用`boost::find_last`替换`boost::find_first`。如果可能有多个匹配的标记，我们可以通过索引要求特定的匹配。为此，我们需要调用`boost::find_nth`，传递第三个参数，这将是匹配的基于零的索引。我们可以传递负索引来要求从末尾匹配。因此，传递`-1`会给我们最后一个匹配，`-2`会给我们倒数第二个匹配，依此类推。

#### find_all

要在输入字符串中找到所有匹配的子字符串，我们必须使用`boost::find_all`并将其传递给一个序列容器，以便将所有匹配的子字符串放入其中。以下是如何做的一个简短示例：

**清单 4.9：使用 boost::find_all 查找所有匹配的子字符串**

```cpp
 1 #include <boost/algorithm/string.hpp>
 2 #include <string>
 3 #include <iostream>
 4 #include <vector>
 5
 6 int main()
 7 {
 8   typedef boost::iterator_range<std::string::const_iterator>
 9                                                 string_range;
10   std::vector<string_range> matches;
11   std::string str = "He deserted the unit while they trudged "
12                     "through the desert one night.";
13 
14   boost::find_all(matches, str, "desert");
15   for (auto match : matches) {
16     std::cout << "Found [" << "desert" << "] at offset "
17           << match.begin() - str.begin() << ".\n";
18   }
19 }
```

首先我们为适当的范围类型创建一个 typedef `string_range`（第 8-9 行）。`boost::find_all`算法将所有匹配的范围复制到范围的向量`matches`中（第 14 行）。我们使用 C++11 的新**基于范围的 for 循环**语法（第 15 行）遍历向量`matches`，并打印每个匹配被找到的偏移量（第 17 行）。巧妙的基于范围的 for 循环声明了一个循环变量`match`，用于迭代容器`matches`中的连续元素。使用`auto`关键字，`match`的类型会根据`matches`中包含的值的类型自动推断。使用范围的向量而不是字符串的向量，我们能够计算出匹配发生在`str`中的确切偏移量。

#### find_token

另一个有趣的查找算法是`boost::find_token`算法。使用这个算法，我们可以找到满足我们指定的某些谓词的字符的子字符串。我们可以使用一组预定义的谓词或定义自己的谓词，尽管后一种方法需要相当多的工作，我们在本书中不会尝试这种方法。在下一个示例中，我们在字符串中搜索具有四个或更多位数的十六进制数字。这也将说明如何使用函数执行重复搜索。

为此，我们使用`boost::is_xdigit`谓词，如果传递给它的特定字符是有效的十六进制字符，则返回 true。以下是示例代码：

**清单 4.10：使用 boost::find_token 和谓词查找子字符串**

```cpp
 1 #include <boost/algorithm/string.hpp>
 2 #include <string>
 3 #include <iostream>
 4 
 5 int main()
 6 {
 7   std::string str = "The application tried to read from an "
 8                     "invalid address at 0xbeeffed";
 9 
10   auto token = boost::find_token(str, boost::is_xdigit(), 
11                                boost::token_compress_on);
12   while (token.begin() != token.end()) {
13     if (boost::size(token) > 3) {
14       std::cout << token << '\n';
15     }
16 
17     auto remnant = boost::make_iterator_range(token.end(), 
18                                             str.end());
19     token = boost::find_token(remnant, boost::is_xdigit(),
20                             boost::token_compress_on);
21   }
22 }
```

字符串`str`包含一个有趣的十六进制标记（`0xbeeffed`）。我们将`str`与谓词`boost::is_xdigit`的实例一起传递给`boost::find_token`，该谓词标识有效的十六进制数字（第 10 行）。我们使用`boost::token_compress_on`指示应该连接连续匹配的字符（第 11 行）；默认情况下，此选项是关闭的。返回的范围`token`表示当前匹配的子字符串。只要返回的范围`token`不为空，即`token.begin() != token.end()`（第 12 行），我们就循环并在其长度大于 3 时打印其内容（第 13 行）。请注意在`token`上使用`boost::size`函数。这是可以用于计算范围属性的几个函数之一，比如它的开始和结束迭代器、大小等等。另外，请注意我们可以直接将像标记这样的范围对象流式传输到`ostream`对象，比如`std::cout`，以打印范围中的所有字符（第 14 行）。

在每次迭代中，我们使用`find_token`搜索匹配后的剩余字符串。剩余字符串被构造为一个名为`remnant`的范围（第 17-18 行）。`remnant`的开始是`token.end()`，即最后一个匹配标记之后的第一个位置。剩余部分的结束只是字符串`str.end()`的结束。

#### iter_find

遍历字符串并找到所有满足某些条件的子字符串是一个常见的用例，Boost 提供了一个更简单的方法来实现这一点。通过使用`boost::iter_find`算法，将输入字符串、查找器函数对象和一个序列容器传递给它以保存匹配的范围，我们可以在传递的容器中获取匹配的子字符串。以下是使用`boost::iter_find`重写的上面的示例：

**清单 4.11：使用 boost::iter_find 和 boost::token_finder**

```cpp
 1 #include <boost/algorithm/string.hpp>
 2 #include <string>
 3 #include <iostream>
 4 #include <vector>
 5 #include <iterator>
 6 #include <algorithm>
 7
 8 struct MinLen
 9 {
10   bool operator()(const std::string& s) const 
11   { return s.size() > 3; }
12 };
13 
14 int main() {
15   std::string str = "The application tried to read from an "
16                     "invalid address at 0xbeeffed";
17 
18   std::vector<std::string> v;
19   auto ret = boost::iter_find(v, str, 
20                      boost::token_finder(boost::is_xdigit(), 
21                                   boost::token_compress_on));
22 
23   std::ostream_iterator<std::string> osit(std::cout, ", ");
24   std::copy_if(v.begin(), v.end(), osit, MinLen());
25 }
```

`boost::find_regex`算法可以搜索字符串中与正则表达式模式匹配的子字符串。我们将在本章后面处理使用 Boost.Regex 处理正则表达式时涵盖这个算法。

#### find

有一个通用的`boost::find`算法，大多数其他查找算法都是基于它实现的。使用可用的查找器-函数对象模板，作为字符串算法库的一部分，或编写我们自己的模板，我们可以让通用的`boost::find`字符串算法为我们执行各种搜索任务。以下是使用`boost::last_finder`函数对象与`boost::find`算法来查找最后一个匹配子字符串的示例——这正是`boost::ifind_last`所做的。`boost::last_finder`函数对象和类似它的其他函数对象接受一个可选的谓词，并且可以用于影响字符比较的方式。为了模拟`ifind_last`所做的不区分大小写的比较，我们需要传递一个以不区分大小写方式比较两个字符的谓词。为此，我们使用`boost::is_iequal`谓词：

```cpp
  1 std::string haystack = "How little is too little";
  2 std::string needle = "Little";
  3 
 4 auto ret = boost::find(haystack,
 5                       boost::last_finder(needle,
 6                                   boost::is_iequal()));

```

我们在`haystack`上调用`boost::find`，传递`boost::last_finder`函数对象。由于我们希望`last_finder`执行不区分大小写的比较，因此我们传递了`boost::is_iequal`谓词的实例。这类似于`boost::ifind_last`，实际上就是它的实现方式。您甚至可以传递自己的字符比较谓词。假设您收到了一个编码消息，其中每个字符都向后移动了 4 个位置，并且环绕，因此`a`是`e`，`z`是`d`。您可以使用以下代码中的`equalsShift`函数对象来检查编码文本中是否存在特定的真实单词：

**清单 4.12：使用 Boost 子字符串查找器的自定义谓词**

```cpp
 1 struct EqualsShift {
 2   EqualsShift(unsigned int n) : shift(n) {}
 3 
 4   bool operator()(char input, char search) const
 5   {
 6     int disp = tolower(input) - 'a' - shift;
 7     return tolower(search) == (disp >= 0)?'a':'z' + disp;
 8   }
 9 
10 private:
11   unsigned long shift;
12 };
13
14 // encoded ... How little is too little
15 std::string encoded = "Lsa pmxxpi mw xss pmxxpi";
16 std::string realWord = "little";
17 auto ret = boost::find(encoded,
18                        boost::first_finder(realWord,
19                                           EqualsShift(4)));

```

在不解码变量`encoded`中包含的整个字符串的情况下，我们希望找到一个`encoded`的子字符串，解码后与变量`realWord`中包含的字符串匹配。为了做到这一点，我们调用`boost::find`，传递两个参数，编码输入字符串称为`encoded`，以及一个谓词，只有在找到匹配的子字符串时才返回`true`（第 17-19 行）。

对于谓词，我们构造了一个临时类，类型为`boost::first_finder`，将两个参数传递给它的构造函数：要查找的单词是`realWord`，二进制谓词`EqualShift(4)`。`EqualsShift`函数对象执行两个字符的不区分大小写比较：一个来自编码输入，一个来自要查找的单词。如果第一个字符是根据固定整数 N 进行的编码的第二个字符，则返回 true，如前面描述的（在我们的例子中 N=4）。

#### find_head 和 find_tail

还有一些*find*算法，比如`boost::find_head`和`boost::find_tail`，它们本来可以被命名为`prefix`和`suffix`，因为它们确实是这样做的——从字符串中切出指定长度的前缀或后缀：

```cpp
1 std::string run = "Run Forrest run";
2 assert( boost::find_head(run, 3) == "Run");
3 assert( boost::find_head(run, -3) == "Run Forrest ");
4 assert( boost::find_tail(run, 3) == "run");
5 assert( boost::find_ tail(run, -3) == " Forrest run");

```

您使用输入字符串和偏移量调用`find_head`。如果偏移量是正数`N`，`find_head`返回输入字符串的前`N`个字符，如果`N`大于字符串的大小，则返回整个字符串。如果偏移量是负数`-N`，`find_head`返回前`size - N`个字符，其中`size`表示字符串`run`中的字符总数。

您使用字符串和整数调用`find_tail`。当传递正整数`N`时，`find_tail`返回输入字符串的最后`N`个字符，如果`N`大于字符串的大小，则返回整个字符串。当传递负整数`-N`时，`find_tail`返回字符串中的最后`size - N`个字符，其中`size`表示字符串中的字符总数，如果`N > size`，则返回空字符串。

#### 用于测试字符串属性的其他算法

存在一些方便的函数，使得某些常见操作非常容易编码。像`boost::starts_with`和`boost::ends_with`（以及它们的不区分大小写的变体）这样的算法，测试特定字符串是否是另一个字符串的前缀或后缀。要确定两个字符串的字典顺序，可以使用`boost::lexicographical_compare`。您可以使用`boost::equals`检查相等性，并使用`boost::contains`检查一个字符串是否是另一个字符串的子字符串。每个函数都有相应的不区分大小写的变体，而区分大小写的变体则采用一个可选的谓词来比较字符。Boost 在线文档提供了这些函数及其行为的充分详细的列表。

### 大小写转换和修剪算法

更改字符串或其部分的大小写，并修剪前导或尾随的额外空格是非常常见的任务，但仅使用标准库需要一些努力。我们已经看到了`boost::to_upper`、`boost::to_lower`以及它们的复制版本来执行大小写更改的操作。在本节中，我们将把这些算法应用于更有趣的范围，并且还将看看修剪算法。

#### 大小写转换算法

如何将字符串中的交替字符转换为大写，而其余部分保持不变？由于`boost::to_upper`函数接受一个范围，我们需要以某种方式生成包含字符串中交替元素的范围。这样做的方法是使用**范围适配器**。Boost Range 库提供了许多适配器，允许从现有范围生成新的范围模式。我们正在寻找的适配器是`strided`适配器，它允许通过在每一步跳过固定数量的元素来遍历范围。我们只需要每步跳过一个元素：

**清单 4.13：使用 Boost.Range 适配器生成非连续范围**

```cpp
 1 #include <boost/range.hpp>
 2 #include <boost/range/adaptors.hpp>
 3 #include <string>
 4 #include <iostream>
 5 #include <boost/algorithm/string.hpp>
 6 #include <cassert>
 7
 8 int main()
 9 {
10   std::string str = "funny text";
11   auto range = str | boost::adaptors::strided(2);
12   boost::to_upper(range);
13   assert(str == "FuNnY TeXt");
14 }
```

为了将`boost::to_upper`算法应用于偶数索引的字符，我们首先生成正确的范围。管道运算符(`operator |`)被重载以创建一个直观的链接语法，用于适配器，比如`strided`。使用表达式`str | strided(2)`，我们实质上是将`strided`适配器应用于字符串`str`，并使用参数`2`来获得包含`str`的偶数索引元素的范围（第 11 行）。注意，`strided`适配器总是从输入的第一个字符开始。

可以通过编写以下内容来实现相同的效果：

```cpp
auto range = boost::adaptors::stride(str, 2);
```

我更喜欢使用管道符号，因为它似乎更具表现力，特别是当需要链接更多的适配器时。在生成这个`range`之后，我们将`to_upper`应用于它（第 12 行），预期地，`str`的偶数索引字符被转换为大写（第 13 行）。

如果我们想对所有奇数索引执行相同的操作，那么我们需要解决一个问题。`strided`适配器以跳过两个元素之间的数字作为参数，但总是从输入的第一个字符开始。为了从索引 1 处开始而不是从 0 开始，我们必须从容器的元素（在这种情况下是索引 1）开始取一个片段，然后应用参数为`2`的`strided`。

首先取片段，我们使用另一个适配器，称为`boost::adaptors::sliced`。它以起始位置和结束位置的索引作为参数。在这种情况下，我们想从索引 1 开始并切片容器的其余部分。因此，我们可以像这样写整个表达式：

```cpp
auto range = str | boost::adaptors::sliced(1, str.size() – 1)| boost::adaptors::strided(2);
```

以这种方式链接适配器是一种强大的方式，可以使用非常可读的语法即时生成范围。相同的技术也适用于 C 风格的字符数组。

#### 修剪算法

对于修剪字符串，有三种主要的算法：`boost::trim_left`用于修剪字符串中的前导空白，`boost::trim_right`用于修剪字符串中的尾随空白，`boost::trim`用于修剪两者。修剪算法可能会改变输出的长度。每个算法都有一个带有谓词的`_if`变体，该谓词用于识别要修剪的字符。例如，如果您只想从从控制台读取的字符串中删除尾随换行符（经常需要这样做），您可以编写一个适当的谓词来仅识别换行符。最后，所有这些算法都有复制变体。如果我们列出可用算法的扩展列表，将会有十二种算法；`trim_left`有四种：`trim_left`、`trim_left_copy`、`trim_left_if`和`trim_left_if_copy`；`trim_right`和`trim`各有四种。以下是在字符串上执行修剪的示例：

**清单 4.14：使用 boost::trim 及其变体**

```cpp
 1 #include <boost/algorithm/string.hpp>
 2 #include <string>
 3 #include <iostream>
 4 #include <cassert>
 5 
 6 bool isNewline(char c) {
 7   return c == '\n';
 8 }
 9 
10 int main()
11 {
12   std::string input = "  Hello  ";
13   std::string input2 = "Hello   \n";
14   
15   boost::trim(input);
16   boost::trim_right_if(input2, isNewline);
17 
18   assert(*(input.end() - 1) != ' ');
19   assert(*(input2.end() - 1) != '\n' && 
20          *(input2.end() - 1) == ' ');
21 }
```

在清单 4.14 中，我们有两个字符串：`input`具有前导和尾随空格（第 12 行），`input2`具有尾随空格和末尾的换行符（第 13 行）。通过在`input`上应用`boost::trim`，前导和尾随空格被修剪（第 15 行）。如果我们在`input2`上应用`boost::trim_right`，它将删除所有尾随空格，包括空格和换行符。我们只想删除换行符，而不是空格；因此，我们编写了一个谓词`isNewline`来帮助选择需要修剪的内容。这种技术也可以用于非空白字符。

这些函数不适用于 C 风格数组，非复制版本期望一个名为`erase`的成员函数。它们适用于标准库中的`basic_string`特化，以及提供具有类似接口和语义的`erase`成员函数的其他类。

### 替换和删除算法

替换和删除算法是在字符串上执行搜索和替换操作的便捷函数。基本思想是查找一个或多个与搜索字符串匹配的内容，并用不同的字符串替换匹配项。擦除是替换的一种特殊情况，当我们用空字符串替换匹配项时。

这些操作可能会在原地执行时改变输入的长度，因为匹配的内容及其替换可能具有不同的长度。库中的核心算法是`boost::find_format`，所有其他算法都是基于它实现的。算法`boost::replace_first`、`boost::replace_last`、`boost::replace_nth`和`boost::replace_all`分别用替换字符串替换输入中搜索字符串的第一个、最后一个、第 n 个或所有匹配的出现。相应的擦除算法简单地擦除匹配的部分。这些算法不适用于 C 风格数组：

**清单 4.15：使用 boost::replace 和 boost::erase 变体**

```cpp
 1 #include <boost/algorithm/string.hpp>
 2 #include <string>
 3 #include <iostream>
 4 #include <cassert>
 5 
 6 int main()
 7 {
 8   std::string input = "Hello, World! Hello folks!";
 9   boost::replace_first(input, "Hello", "Hola");
10   assert(input == "Hola, World! Hello folks!");
11   boost::erase_first(input, "Hello");
12   assert(input == "Hola, World!  folks!");
13 }
```

在清单 4.15 中，我们首先使用`boost::replace_first`算法来将字符串`"Hello"`的第一个实例替换为`"Hola"`（第 9 行）。如果我们使用`boost::replace_all`，则会替换两个实例的`"Hello"`，并且我们将得到`"Hola, World! Hola folks!"`。然后我们调用`boost::erase_first`来删除字符串中剩余的`"Hello"`（第 11 行）。这些算法中的每一个都有一个不区分大小写的变体，以不区分大小写的方式进行匹配。可以预见地，它们以`i-`前缀命名：`ireplace_first`、`ierase_first`等等。

每个算法都有一个返回新字符串的`_copy`变体，而不是原地更改。以下是一个简短的示例：

```cpp
std::string input = "Hello, World! Hello folks!";
auto output = boost::ireplace_last_copy(input, "hello", "Hola");
assert(input == "Hello, World! Hello folks!"); // input unchanged
assert(output == "Hello, World! Hola folks!"); // copy changed
```

请注意`boost::ireplace_last_copy`变体是如何工作的，以不区分大小写的方式匹配`"hello"`，并在输入的副本中执行替换。

您可以使用`boost::replace_head`或`boost::replace_tail`（以及它们的擦除变体）来替换或擦除字符串的前缀或后缀。`boost::replace_regex`和`boost::replace_regex_all`算法使用正则表达式来查找匹配项，并用替换字符串替换它们。替换字符串可能包含特殊语法来引用匹配字符串的部分，有关详细信息，我们将在本章后面的 Boost.Regex 部分中详细介绍。

### 拆分和连接算法

Boost 提供了一个名为`boost::split`的算法，它基本上用于根据一些分隔符将输入字符串分割成标记。该算法接受输入字符串、用于识别分隔符的谓词和用于存储解析标记的序列容器。以下是一个示例：

**清单 4.16：使用 boost::split 在简单标记上拆分字符串**

```cpp
 1 #include <boost/algorithm/string.hpp>
 2 #include <string>
 3 #include <iostream>
 4 #include <vector>
 5 #include <cassert>
 6
 7 int main()
 8 {
 9   std::string dogtypes = "mongrel, puppy, whelp, hound";
10   std::vector<std::string> dogs;
11   boost::split(dogs, dogtypes, boost::is_any_of(" ,"),
12                boost::token_compress_on);
13   
14   assert(dogs.size() == 4);
15   assert(dogs[0] == "mongrel" && dogs[1] == "puppy" &&
16          dogs[2] == "whelp" && dogs[3] == "hound");
17 }
```

清单 4.16 将列出出现在字符串`dogtypes`中的四种狗的类型，用逗号和空格分隔（第 9 行）。它使用`boost::split`算法来实现。`dogtypes`字符串使用谓词`boost::is_any_of(" ,")`进行标记化，该谓词将任何空格或逗号识别为分隔符（第 11 行）。`boost::token_compress_on`选项确保`boost::split`算法不会对每个相邻的分隔符字符返回空字符串，而是将它们组合在一起，将其视为单个分隔符（第 12 行）。如果我们想要在任何标点符号处拆分字符串，我们将使用`boost::is_punct()`而不是`boost::is_any_of(…)`。但是，这是一种相对不太灵活的标记化方案，只能使用有限的谓词集。

如果您只想使用另一个字符串作为分隔符拆分字符串，可以使用`boost::iter_split`：

**清单 4.17：使用 boost::iter_split 标记化字符串**

```cpp
 1 #include <boost/algorithm/string.hpp>
 2 #include <string>
 3 #include <iostream>
 4 #include <vector>
 5
 6 int main()
 7 {
 8   std::string dogtypes = 
 9                "mongrel and puppy and whelp and hound";
10   std::vector<std::string> dogs;
11   boost::iter_split(dogs, dogtypes, 
12                     boost::first_finder(" and "));
13   assert(dogs.size() == 4);
14   assert(dogs[0] == "mongrel" && dogs[1] == "puppy" &&
15          dogs[2] == "whelp" && dogs[3] == "hound");
16 }
```

`boost::split`和`boost::iter_split`之间的主要区别在于，在后者中，您使用查找器来识别分隔符，因此可以是特定的字符串。`boost::iter_split`和`boost::iter_find`都使用相同类型的参数，并使用查找器来搜索匹配的子字符串，但`boost::iter_split`返回位于两个匹配子字符串之间的标记，而它的补充`boost::iter_find`返回匹配的子字符串。

最后，当您尝试使用一些分隔符将一系列值串在一起时，`boost::join`和`boost::join_if`算法非常有用。`boost::join`连接序列中的所有值，而`boost::join_if`只连接满足传递的谓词的序列中的值。以下是`boost::join`的示例，它接受一个字符串向量和一个分隔符，并返回连接的字符串：

```cpp
std::vector<std::string> vec{"mongrel", "puppy", "whelp", "hound"};
std::string joined = boost::join(vec, ", ");
assert(joined == "mongrel, puppy, whelp, hound");
```

在前面的示例中，我们看到另一个有用的 C++11 特性：统一初始化。我们使用大括号括起来并用逗号分隔的四个字符串序列来初始化向量`vec`。这种初始化语法适用于所有 STL 容器，并且可以用于具有特定类型构造函数的常规类。现在，如果我们想要挑选哪些字符串被连接，哪些不被连接，我们将使用`boost::join_if`，如下所示：

```cpp
bool fiveOrLessChars(const std::string& s) { return s.size() <= 5; }

std::vector<std::string> vec{"mongrel", "puppy", "whelp", "hound"};
std::string joined = boost::join_if(vec, ", ", fiveOrLessChars);
assert(joined == "puppy, whelp, hound");
```

`fiveOrLessChars`谓词检查传递给它的字符串是否长度为五或更少。因此，字符串`"mongrel"`由于长度超过五而不出现在连接的字符串中。

# 使用 Boost Tokenizer 库拆分文本

我们在上一节中看到的`boost::split`算法使用谓词拆分字符串，并将标记放入序列容器中。它需要额外的存储空间来存储所有标记，并且用户对使用的标记化标准选择有限。根据各种标准将字符串拆分为一系列标记是一个常见的编程需求，Boost.Tokenizer 库提供了一个可扩展的框架来实现这一点。此外，这不需要额外的存储空间来存储标记。它提供了一个通用接口来从字符串中检索连续的标记。将字符串拆分为连续标记的标准作为参数传递。Tokenizer 库本身提供了一些可重用的常用标记策略进行拆分，但更重要的是，它定义了一个接口，使用该接口可以编写我们自己的拆分策略。它将输入字符串视为一系列标记的容器，可以从中解析出连续的标记。

## 基于分隔符的标记

首先，让我们看看如何将字符串拆分为其组成单词：

**清单 4.19：使用 Boost Tokenizer 将字符串标记为单词**

```cpp
 1 #include <iostream>
 2 #include <boost/tokenizer.hpp>
 3 #include <string>
 4 
 5 int main()
 6 {
 7   std::string input = 
 8         "God knows, I've never been a spiritual man!";
 9 
10   boost::tokenizer<> tokenizer(input);
11
12   for (boost::tokenizer<>::iterator token = tokenizer.begin();
13         token != tokenizer.end(); ++token) {
14     std::cout << *token << '\n';
15   }
16 }
```

`boost::tokenizer`类模板抽象了标记化过程。我们创建`boost::tokenizer`的默认特化的实例，将输入字符串`input`传递给它（第 10 行）。接下来，使用`boost::tokenizer`的迭代器接口，我们将`input`拆分为连续的标记（第 12-14 行）。通常，您可以通过传递适当的标记策略来自定义字符串的拆分方式。由于我们没有显式地将其传递给`boost::tokenizer`模板，因此默认的标记策略将使用空格和标点符号作为标记的分隔符。上述代码将将以下输出打印到标准输出：

```cpp
God
knows
I
ve
never
been
a
spiritual
man
```

因此，它不仅在空格上分割，还在逗号和撇号上分割；由于撇号，`"I've"`被分割成`"I"`和`"ve"`。

如果我们想要根据空格和标点符号拆分输入，但不要在撇号上拆分，我们需要做更多工作。Boost 提供了一些可重用的模板，用于常用的拆分策略。`boost::char_delimiter`模板使用指定的字符作为分隔符拆分字符串。以下是代码：

**清单 4.20：使用 boost::char_separator 的 Boost Tokenizer**

```cpp
 1 #include <boost/tokenizer.hpp>
 2 #include <string>
 3 #include <iostream>
 4
 5 int main()
 6 {
 7   std::string input = 
 8                "God knows, I've never been a spiritual man!";
 9
10   boost::char_separator<char> sep(" \t,.!?;./\"(){}[]<>");
11   typedef boost::tokenizer<boost::char_separator<char> > 
12                                                  tokenizer;
13   tokenizer mytokenizer(input, sep);
14   for (auto& token: mytokenizer) 
16   {
17     std::cout << token << '\n';
18   }
19 }
```

在这种情况下，我们首先使用`boost::char_separator`模板（第 10 行）构造拆分策略`sep`。由于我们正在拆分`std::string`类型的文本，其字符类型为`char`，因此必须将`char`作为参数传递给`boost::char_separator`，以指定分隔符的类型为`char`。我们还可以写`boost::char_separator<std::string::value_type>`，而不是`boost::char_separator<char>`，以更好地表达关系。我们构造要用作分隔符的标点符号和空白字符列表，并将其作为`sep`的构造函数参数传递。最后，我们构造分词器，将输入字符串`input`和拆分策略`sep`传递给它。我们使用基于范围的 for 循环迭代连续的标记，这比使用标记迭代器时的代码更简洁。

## 使用包含元字符的字段标记记录

`boost::char_delimiter`策略并不是唯一可用的拆分策略。考虑一个以逗号分隔的数据格式，如下所示：

```cpp
Joe Reed,45,Bristol UK
Ophir Leibovitch,28,Netanya Israel
Raghav Moorthy,31,Mysore India
```

每行一个记录，每个记录有三个字段：一个人的姓名、年龄和居住城市。我们可以使用`boost::char_separator`策略解析这样的记录，将逗号作为分隔符传递给它。现在，如果我们想要使格式更丰富一些，我们可以包括人们的完整地址而不是他们目前的城市。但是地址是更长的字段，有时带有嵌入的逗号，这样的地址会破坏基于逗号作为分隔符的解析。因此，我们决定引用可能带有嵌入逗号的字符串：

```cpp
Joe Reed,45,"33 Victoria St., Bristol UK"
Ophir Leibovitch,28,"19 Smilanski Street, Netanya, Israel"
Raghav Moorthy,31,"156A Railway Gate Road, Mysore India"
```

引用本身可能不够。有些地址可能有引号字符串，我们希望保留这些。为了解决这个问题，我们决定使用反斜杠（\）作为转义字符。以下是一个地址中带有引号字符串的第四条记录：

```cpp
Amit Gupta,70,"\"Nandanvan\", Ghole Road, Pune, India"
```

现在的问题是，不再可能使用`boost::char_separator`策略来解析前述记录。对于这样的记录，我们应该使用`boost::escaped_list_char`。`boost::escaped_list_char`策略是专门为这种用途量身定制的。默认情况下，它使用逗号（，）作为字段分隔符，双引号（"）作为引号字符，反斜杠（\）作为转义字符。要在字段中包含逗号，请引用字段。要在字段中包含引号，请转义嵌入的引号。现在我们可以尝试解析前面讨论过的四个人中最复杂的记录：

**清单 4.21：使用 boost::tokenizer 和 boost::escaped_list_separator**

```cpp
 1 #include <iostream>
 2 #include <boost/tokenizer.hpp>
 3 #include <string>
 4
 5 int main()
 6 {
 7   std::string input = "Amit Gupta,70,\"\\\"Nandanvan\\\", "
 8                       "Ghole Road, Pune, India\"";
 9
10   typedef boost::tokenizer<boost::escaped_list_separator<char> > 
11                                           tokenizer;
12   tokenizer mytokenizer(input);
13  
14   for (auto& tok: mytokenizer) 
15   {
16     std::cout << tok << '\n';
17   }
18 }
```

在第 12 行创建了`boost::tokenizer<boost::escaped_list_separator<char>>`的一个实例，使用了 typedef（第 10-11 行）。这实际上是唯一需要处理的操作变化，以适应这种新格式。变量`input`中硬编码的记录需要一些额外级别的转义，以使其成为有效的 C++字符串文字（第 7-8 行）。

如果记录具有不同的元字符集合，例如连字符（-）作为字段分隔符，斜杠（/）作为引号，波浪号（~）作为转义字符，我们需要明确指定这些选项，因为`boost::escaped_list_separator<<char>>`的默认选项将不再起作用。考虑一个名为 Alon Ben-Ari 的人，年龄为 35 岁，住在特拉维夫 Zamenhoff St. 11/5 号。使用指定的引号、字段分隔符和转义字符，这可以表示为：

```cpp
/Alon Ben-Ari/-35-11~/5 Zamenhoff St., Tel Aviv
```

姓氏字段中的 Ben-Ari 有一个连字符。由于连字符也是字段分隔符，因此名字字段必须使用斜杠引起来。地址字段有一个斜杠，由于斜杠是引号字符，所以地址字段必须用转义字符（~）转义。现在轮到我们对其进行标记化了：

**清单 4.22：使用 boost::escaped_list_separator 和奇特的分隔符**

```cpp
 1 #include <iostream>
 2 #include <boost/tokenizer.hpp>
 3 #include <string>
 4
 5 int main()
 6 {
 7   std::string input = 
 8        "/Alon Ben-Ari/-35-11~/5 Zamenhoff St., Tel Aviv";
 9
10   typedef boost::tokenizer<boost::escaped_list_separator<char> > 
11                                               tokenizer;
12   boost::escaped_list_separator<char> sep('~', '-', '/');
13   tokenizer mytokenizer(input, sep);
14  
15   for (auto& tok: mytokenizer) {
16     std::cout << tok << '\n';
17   }
18 }
```

这是输出：

```cpp
Alon Ben-Ari
35
11/5 Zamenhoff Str., Tel Aviv
```

## 使用固定长度字段标记化记录

在金融交易和其他几个领域经常出现的一类数据格式是固定偏移量的记录。考虑以下代表支付指令的记录格式：

```cpp
201408091403290000001881303614419ABNANL2AWSSDEUTDEMM720000000412000EUR…
```

在这里，记录几乎不可读，只能由程序使用。它具有固定偏移量的字段，解析程序必须知道其含义。这里描述了各个字段：

```cpp
Offset 0, length 8: date of record in YYYYMMDD format.
Offset 8, length 9: time of record in HHMMSSmmm format where mmm represents milliseconds.
Offset 17, length 16: the transaction identifier for the transaction, numeric format.
Offset 33, length 11: the Swift Bank Identifier Code for the bank from which money is transferred.
Offset 44, length 11: the Swift Bank Identifier Code for the bank to which money is transferred.
Offset 55, length 12: the transaction amount.
Offset 67, length 3: the ISO code for the currency of transaction.
```

为了解析这样的记录，我们使用`boost::offset_separator`分割策略。这个类（注意它不是一个模板）以一对迭代器的形式接受连续标记的长度，用于解析。

解析前述支付指令的代码示例应该有助于说明这个想法：

**清单 4.23：使用固定长度字段标记化记录**

```cpp
 1 #include <boost/tokenizer.hpp>
 2 #include <string>
 3 #include <iostream>
 4 
 5 int main()
 6 {
 7   std::string input =  
 8      "201408091403290000001881303614419ABNANL2AWSSDEUTDEMM72"
 9      "0000000412000EUR";
10   int lengths[] = {8, 9, 16, 11, 11, 12, 13};
11 
12   boost::offset_separator ofs(lengths, lengths + 7);
13   typedef boost::tokenizer<boost::offset_separator> tokenizer;
14   tokenizer mytokenizer(input, ofs);
15   
16   for (auto& token: mytokenizer) {
17     std::cout << token << '\n';
18   }
19 }
```

首先定义一个包含连续字段长度的数组（第 10 行），并使用它来初始化类型为`boost::offset_separator`的对象`ofs`（第 12 行）。我们也可以使用向量而不是数组，并将其`begin()`和`end()`迭代器传递给`offset_separator`构造函数。然后创建一个标记化器，它根据`ofs`中指定的偏移量对字符串进行标记化（第 13-14 行），并使用基于范围的 for 循环打印连续的标记（第 16-18 行）。

该程序产生以下输出：

```cpp
20140809
140329000
0001881303614419
ABNANL2AWSS
DEUTDEMM720
000000412000
EUR
```

我们看到连续的行上列出了日期、时间、ID、发送者 SWIFT 银行代码（发送者银行的标识符）、接收者 SWIFT 银行代码、金额和交易货币的值。

现在，如果所有字段都已解析并且仍有一些输入剩下会发生什么？默认行为是重新开始解析剩余的文本，并从开头应用长度偏移。这对某些格式可能有意义，对某些格式可能没有意义。如果要关闭此行为，以便在使用所有长度偏移后停止解析，应将第三个参数传递给`boost::offset_separator`的构造函数，并且其值应为`false`，如下所示：

```cpp
boost::offset_separator ofs(lengths, lengths + nfields, 
 false);

```

在这里，`lengths`是长度偏移的数组，`nfields`是我们希望解析的字段数。

相反，如果输入短于长度之和会发生什么？默认行为是返回最后部分解析的字段并停止。假设您有一个格式，其中付款人的评论附加到每个交易记录中。评论是可选的，不一定存在。如果存在，可能有最大大小限制，也可能没有。第一种行为可以通过指定最大大小来解析最后一个评论字段，或者指定一个您不希望评论达到的任意大的大小，从而利用最后记录的部分解析。同样，如果要关闭此行为，以便遇到第一个部分字段时停止解析，应将第四个参数传递给`boost::offset_separator`构造函数，并且其值应为`false`：

```cpp
boost::offset_separator ofs(lengths, lengths + nfields, restart,
 false);

```

## 编写自己的标记函数

有许多情况下，您需要根据一些在 Boost 中不可重用的标准来解析字符串。虽然您可以使用`boost::split`等替代库，但是您可以通过插入自定义**标记生成器**来使用`boost::tokenizer`工具。标记生成器类封装了标记策略，并作为模板参数传递给`boost::tokenizer`。

标记生成器可以定义为符合以下要求的函数对象：

+   可复制分配。

+   可复制构造。

+   具有重载的公共函数调用运算符（`operator()`）具有以下签名：

```cpp
template <typename InputIterator, typename StringType>bool operator()(InputIterator& next,InputIterator end,StringType& token)
```

此运算符传递两个迭代器，定义了它在其中查找下一个标记的字符串部分。仅当找到新标记时，它才返回 true。在这种情况下，它将其第三个参数设置为标记，并将其第一个参数设置为字符串中标记结束后的第一个位置，从那里可以继续解析。如果未找到标记，则返回 false。我们必须在此函数中编写逻辑以识别连续的标记。

+   具有公共成员函数`void reset()`。这可以用于清除用于保持字符串解析状态的任何成员变量。然后，可以使用对象的相同实例来解析多个输入。

这些函数由`boost::tokenizer`实现调用，而不是直接由程序员调用。

现在，我们编写一个标记生成器类，以从一些文本中选择带引号或括号的字符串。例如，给定字符串`"我要从法兰克福（am Main）乘火车去法兰克福（an der Oder）"`, 我们想要提取出标记`"am Main"`和`"an der Oder"`。为了简化我们的实现，给定具有嵌套括号或引号的字符串，只需要检索最内部引号的内容。因此，给定字符串`"tokenizer<char_separator<char>>"`, 它应该返回`"char"`, 最内部的括号实体。以下是这样一个名为`qstring_token_generator`的类的代码：

**清单 4.24a：qstring_token_generator 接口**

```cpp
 1 class qstring_token_generator
 2 {
 3 public:
 4   typedef std::string::const_iterator iterator;
 5
 6   qstring_token_generator(char open_q = '"',
 7              char close_q = '"', char esc_c = '\\',
 8              bool skip_empty = true);
 9 
10   bool operator() (iterator& next, iterator end,
11                    std::string& token);
12 
13   void reset();
14
15 private:
16   // helper functions to be defined
17
18   char start_marker;
19   char end_marker;
20   char escape_char;
21   bool skip_empty_tokens;
22   bool in_token;
23   bool in_escape;
24 };
```

`qstring_token_generator`类具有一个接受必要输入的构造函数：

+   开始和结束标记字符，默认都是双引号（"）

+   转义字符，默认为反斜杠（\）

+   一个布尔值，指示是否跳过空令牌，默认为 true（第 6-8 行）

用于存储这些值的相应私有变量被定义（第 18-21 行）。该类使用两个额外的状态变量来跟踪解析状态：`in_token`变量（第 22 行），在解析引号内的内容时为 true，否则为 false，以及`in_escape`变量（第 23 行），如果当前字符是转义序列的一部分则为 true，否则为 false。这是构造函数的实现：

**清单 4.24b：qstring_token_generator 构造函数**

```cpp
 1   qstring_token_generator::qstring_token_generator
 2             (char open_q, char close_q, char esc_c,
 3              bool skip_empty) : 
 4      start_marker(open_q), end_marker(close_q), 
 5      escape_char(esc_c), skip_empty_tokens(skip_empty),
 6      in_token(false), in_escape(false)
 7   {}
```

请注意，`in_token`和`in_escape`被初始化为 false。每次我们使用标记生成器接口迭代输入的连续标记时，标记生成器实现都会调用标记生成器重新解析输入。为了重新开始解析，必须重置任何内部解析状态。`reset`函数封装了这些操作，并在创建新的标记迭代器时由标记生成器调用。

这是重置函数的实现：

**清单 4.24c：qstring_token_generator 重置函数**

```cpp
 1   void qstring_token_generator::reset()
 2   {
 3     in_token = false;
 4     in_escape = false;
 5   }
```

重置函数确保用于维护解析状态的内部变量被适当地重置以重新开始解析。

最后，解析算法是在重载的函数调用操作员成员（`operator()`）中实现的。为了解析字符串，我们寻找开始和结束标记来识别标记的开始和结束，并将转义的开始和结束标记计为标记的一部分，并处理开始和结束标记是相同字符的情况。我们还处理引号标记嵌套的情况。我们将用`qstring_token_generator`类中的一些辅助私有函数来编写算法。

**清单 4.24d：解析算法辅助函数**

```cpp
 1 iterator qstring_token_generator::start_token(iterator& next)
 2 {
 3   in_token = true;
 4   return ++next;
 5 }
 6
 7 std::string qstring_token_generator::end_token(iterator& next,
 8                                         iterator token_start) 
 9 {
10   in_token = false;
11   auto token_end = next++;
12   return std::string(token_start, token_end);
13 }
```

`start_token`函数的意思是每次我们识别出一个新标记的开始时调用它（第 1 行）。它将`in_token`标志设置为 true，增加迭代器`next`，并返回它的值。

`end_token`函数的意思是每次我们识别出一个标记的结束时调用它（第 7 行）。它将`in_token`标志设置为 false，增加迭代器`next`，并将完整的标记作为字符串返回。

现在我们需要编写逻辑来识别标记的开始和结束，并适当地调用前面的函数。我们直接在重载的`operator()`中执行这个操作：

**清单 4.24e：解析算法**

```cpp
 1 bool operator() (iterator& next, iterator end,
 2                  std::string& token)
 3 {
 4   iterator token_start;
 5
 6   while (next != end) {
 7     if (in_escape) {
 8       // unset in_escape after reading the next char
 9       in_escape = false;
10     } else if (*next == start_marker) { // found start marker
11       if (!in_token) { // potential new token
12         token_start = start_token(next);
13         continue;
14       } else { // already in a quoted string
15         if (start_marker == end_marker) {
16           // Found end_marker, is equal to start_marker
17           token = end_token(next, token_start);
18           if (!token.empty() || !skip_empty_tokens) {
19             return true;
20           }
21         } else {
22           // Multiple start markers without end marker.
23           // Discard previous start markers, consider
24           //  inner-most token only.
25           token_start = start_token(next);
26           continue;
27         }
28       }
29     } else if (*next == end_marker) {
30       // Found end_marker, is not equal to start_marker
31       if (in_token) {
32         token = end_token(next, token_start);
33         if (!token.empty() || !skip_empty_tokens) {
34           return true;
35         }
36       }
37     } else if (*next == escape_char) {
38       in_escape = !in_escape;  // toggle
39     }
40     ++next;
41   }
42
43   return false;
44 }
```

我们使用 while 循环遍历输入的连续字符（第 6 行）。对于每个字符，我们检查它是否是转义字符（第 7 行），或者它是否是开始标记（第 10 行），结束标记（第 29 行）或转义字符（第 37 行）的前导字符。

如果找到未转义的开始标记，并且我们还没有在解析标记中（第 11 行），那么它可能代表一个新标记的开始。因此，我们调用`start_token`，记录标记的起始位置，并继续到下一个迭代（第 12-13 行）。但是，如果我们已经在解析标记中，并且找到了开始标记，那么有两种可能性。如果开始和结束标记恰好相同，那么这表示标记的结束（第 15 行）。在这种情况下，我们调用`end_token`来获取完整的标记并返回它，除非它为空并且设置了`skip_empty_tokens`（第 16-20 行）。如果开始和结束标记不相同，那么第二个开始标记表示嵌套标记。由于我们只想提取最嵌套的标记，我们丢弃先前的标记并调用`start_token`来指示我们有一个新标记的开始（第 25-26 行）。

如果结束标记与开始标记不同，并且我们找到它（第 29 行），那么我们调用`end_token`生成并返回找到的完整标记，除非它为空并且设置了`skip_empty_tokens`。最后，如果我们找到转义字符，我们设置`in_escape`标志（第 37-38 行）。

我们使用`qstring_token_generator`类来对我们的输入字符串进行标记化：

**清单 4.25：使用自定义标记生成器提取括号字符串**

```cpp
 1  std::string input = "I'm taking a train from Frankfurt "
 2                    "(am Main) to Frankfurt (an der Oder)";
 3  bool skipEmpty = true;
 4  qstring_token_generator qsep('(', ')', '\\', skipEmpty);
 5  typedef boost::tokenizer<qstring_token_generator> qtokenizer;
 6  qtokenizer tokenizer(input, qsep);
 7
 8  unsigned int n = 0;
 9  for (auto& token: tokenizer) {
10    std::cout << ++n << ':' << token << '\n';
11 }
```

前面突出显示的代码显示了我们代码中的关键更改。我们定义了一个`qstring_token_generator`对象，它接受左引号和右引号字符（在本例中是左括号和右括号），并跳过空标记（第 4 行）。然后我们为`boost::tokenizer<qstring_token_generator>`（第 4 行）创建了一个 typedef，创建了一个该类型的标记生成器来解析输入（第 6 行），并打印连续的标记（第 10 行）。

# 使用 Boost.Regex 的正则表达式

当我们编写像`boost::find_first("Where have all the flowers gone?", "flowers")`这样的代码行时，我们是在要求在较大的字符串`"Where have all the flowers gone?"`（称为**大海草堆**）中找到字符串`"flowers"`（称为**针）的存在。针是模式；一个特定顺序中的七个特定字符，其存在必须在大海草堆中查找。然而，有时我们并不知道我们要找的确切字符串；我们只有一个抽象的想法或一个模式。正则表达式是一种表达这种抽象模式的强大语言。

## 正则表达式语法

正则表达式是一种字符串，它使用常规字符和一些具有特殊解释的字符的混合来编码文本的模式，这些字符统称为*元字符*。 Boost.Regex 库提供了消耗正则表达式字符串并生成搜索和验证符合特定模式的文本的逻辑的函数。例如，要定义模式“a 后面跟零个或多个 b”，我们使用正则表达式`ab*`。这个模式将匹配文本`a`，`ab`，`abb`，`abbb`等。

### 原子

在非常基本的层面上，正则表达式由称为**原子**的一个或多个字符组成，每个原子都有一个关联的**量词**，跟在原子后面，还可以选择地有**锚点**，定义了如何相对于周围文本定位一些文本。量词可能是隐式的。原子可以是单个字符（或转义的元字符）、**字符类**、字符串或**通配符**。如果是字符串，必须将其括在括号中以指示它是一个原子。通配符匹配任何字符（除了换行符），并使用句点（.）元字符编写。

### 量词

没有尾随量词的单个原子只匹配自身的单个出现。当存在时，尾随量词确定了前面原子的最小和最大允许出现次数。一般的量词看起来像`{m, M}`，其中`m`表示最小出现次数，`M`表示最大出现频率。省略最大值，如`{m,}`表示原子可以出现的最大次数是无限的。也可以使用一个数字作为`{n}`来匹配固定数量的实例。更常见的是，我们使用以下快捷量词：

+   `*`：等同于`{0,}`，称为**Kleene 星**。表示可能不会发生的原子，或者可能发生任意次数。

+   `+`：等同于`{1,}`。表示必须至少出现一次的原子。

+   `?`：等同于`{0,1}`。表示可选原子。

使用上述语法规则，我们在下表中构造摘要示例：

| 正则表达式 | 原子 | 量词 | 等效量词 | 匹配文本 |
| --- | --- | --- | --- | --- |
| W | w | None（隐式） | `{1}` | w |
| a* | a | * | `{0,}` | （空白），a，aa，aaa，aaaa，… |
| (abba)+ | abba | + | `{1,}` | abba, abbaabba, abbaabbaabba, … |
| a?b | a，b | ? | `{0,1}` | b，ab |
| (ab){2,4} | (ab) | {2,4} | `{2,4}` | abab, ababab, abababab |
| .*x | . 和 x | * 和 None | `{0,}` 和 `{1}` | x 和以 x 结尾的任何字符串 |

默认情况下，量词是*贪婪*的，会匹配尽可能多的字符。因此，对于字符串`"abracadabra"`，正则表达式`"a.*a"`将匹配整个字符串，而不是更小的子字符串`"abra"`、`"abraca"`或`"abracada"`，它们也都以`'a'`开头和结尾。如果我们只想匹配最小的匹配子字符串，我们需要覆盖贪婪的语义。为此，我们在量词`"a.*?a"`后面加上问号（?）元字符。

### 字符类

字符也可以与字符类匹配，字符类是一组功能相关字符的简写表示。以下是 Boost 库中预定义的字符类的部分列表：

| 字符类 | 简写形式 | 含义 | 补集 |
| --- | --- | --- | --- |
| [[:digit:]] | `\d` | 任何十进制数字（0-9） | \D |
| [[:space:]] | `\s` | 任何空白字符 | \S |
| [[:word:]] | `\w` | 任何单词字符：字母、数字和下划线 | \W |
| [[:lower:]] | `\l` | 任何小写字符 |   |
| [[:upper:]] | `\u` | 任何大写字符 |   |
| [[:punct:]] | 无 | 任何标点字符 |   |

例如，`\d`是一个字符类，匹配一个十进制数字。它的补集\`D`匹配任何单个字符，除了十进制数字。`\s`匹配空白字符，`\S`匹配非空白字符。可以用方括号创建临时字符类；`[aeiouAEIOU]`匹配任何英语元音字母，`[1-5]`匹配 1 到 5 之间的数字（包括 1 和 5）。表达式`[²-4]`匹配除了 2、3 和 4 之外的任何字符，并且方括号内的前导插入符号具有否定其后字符的作用。我们可以组合多个字符类，比如—[[:digit:][:lower:]]—来表示小写字母和十进制数字的集合。

### 锚点

某些元字符，称为**锚点**，不匹配字符，但可以用于匹配文本中的特定位置。例如，正则表达式中的插入符（`^`）匹配行的开头（换行符后面）。美元符（`$`）匹配行的结尾（换行符前面）。此外，`\b`表示单词边界，而`\B`匹配除了单词边界之外的任何位置。

### 子表达式

一般来说，字符中的每个字符都被解释为一个独立的原子。为了将一串字符视为一个单独的原子，我们必须将其括在括号中。正则表达式中括号内的子字符串称为**子表达式**。跟在子表达式后面的量词适用于整个子表达式：

```cpp
([1-9][0-9]*)(\s+\w+)*
```

前面的表达式表示一个数字（`[1-9][0-9]*`）后面跟着零个或多个单词（`\w+`），它们之间和彼此之间由一个或多个空白字符（`\s+`）分隔。第二个 Kleene 星号由于括号的存在应用于整个子表达式`\s+\w+`。

正则表达式库，包括 Boost.Regex，跟踪字符串的子字符串，这些子字符串与括号内的子表达式匹配。匹配的子表达式可以在正则表达式内部使用反向引用，如`\1`、`\2`、`\3`等。例如，在前面的正则表达式中，术语`\1`匹配前导数字，而`\2`匹配带有前导空格的最后匹配的单词。如果没有尾随单词，则不匹配任何内容。子表达式可以嵌套，并且按照它们在字符串中从左到右出现的左括号的顺序从 1 开始递增编号。

如果您想使用子表达式来能够对字符组应用量词和锚定，但不需要捕获它们以供以后引用，您可以使用形式为`(?:expr)`的**非捕获子表达式**，其中括号内的前导元字符序列`?:`表示它是一个非捕获子表达式，`expr`是一些有效的正则表达式。这将把 expr 视为一个原子，但不会捕获它。括号内没有前导`?:`的子表达式因此被称为**捕获组**或**捕获子表达式**。

### 分离

您可以创建一个正则表达式，它是一个或多个正则表达式的逻辑或。为此，您可以使用|**分离运算符**。例如，要匹配包含小写和大写字符混合的单词，您可以使用表达式`(\l|\u)+`。

您可以使用分离运算符来组合正则表达式并形成更复杂的表达式。例如，要匹配包含大写或小写字符的单词，或正整数，我们可以使用表达式`(\l|\u)+|\d+`。

## 使用 Boost.Regex 来解析正则表达式

正则表达式是一个丰富的主题，在前面的段落中我们只是浅尝辄止。但这种基本的熟悉已经足够让我们开始使用 Boost.Regex 库。Boost.Regex 库是 C++ 11 标准中被接受的库之一，现在是 C++ 11 标准库的一部分，减去了处理 Unicode 字符的能力。

Boost 正则表达式库*不是*仅包含头文件，需要链接到 Boost.Regex 共享或静态库。它可以从头文件`boost/regex.hpp`中获得。在我使用本机包管理器安装 Boost 库的 Linux 桌面上，我使用以下命令行来构建正则表达式程序：

```cpp
$ g++ source.cpp -o progname -lboost_regex

```

在从源代码安装 Boost 的 Linux 系统上，头文件可能位于非标准位置，如`/opt/boost/include`，库位于`/opt/boost/lib`下。在这样的系统上，我必须使用以下命令行来构建我的程序：

```cpp
$ g++ source.cpp -o progname -I/opt/boost/include -L/opt/boost/lib -lboost_regex-mt -Wl,-rpath,/opt/boost/lib

```

`-Wl`，`-rpath`，`/opt/boost/lib`指令告诉链接器硬编码路径，从中加载共享库，如`libboost_regex-mt`，并帮助我们的程序在没有额外设置的情况下运行。在使用 Visual Studio 的 Windows 上，链接是自动的。

它使用`boost::basic_regex`模板来建模正则表达式，并为`char`类型提供其特化`boost::regex`和`wchar_t`类型的`boost::wregex`作为 typedef。使用这个库，我们可以检查一个字符串是否符合某种模式或包含符合某种模式的子字符串，提取符合某种模式的字符串的所有子字符串，用另一个格式化的字符串替换与模式匹配的子字符串，并根据匹配表达式拆分字符串，这是最常用的几种操作。

### 匹配文本

考虑字符串`"Alaska area"`。我们想要将其与正则表达式`a.*a`匹配，以查看字符串是否符合模式。为此，我们需要调用`boost::regex_match`函数，该函数返回一个布尔值 true，表示成功匹配，否则返回 false。以下是代码：

**清单 4.26：使用正则表达式匹配字符串**

```cpp
1 #include <boost/regex.hpp>
2 #include <string>
3 #include <cassert>
4 int main()
5 {
6   std::string str1 = "Alaska area";
7   boost::regex r1("a.*a");
8   assert(!boost::regex_match(str1, r1));
9 }
```

正则表达式`"a.*a"`封装在`boost::regex`的实例中。当我们将字符串与此表达式匹配时，匹配失败（第 8 行），因为字符串以大写`'A'`开头，而正则表达式期望在开头是小写`'a'`。我们可以通过构造并将`boost::regex::icase`作为标志传递给`boost::regex`构造函数来要求不区分大小写的正则表达式：

```cpp
7   boost::regex r1("a.*a", boost::regex::icase);
8   assert(boost::regex_match(str1.begin(), str1.end(), r1));
```

请注意，我们调用了`boost::regex_match`的不同重载，它接受两个`std::string`的迭代器（第 8 行），只是为了说明另一种签名。您也可以像在清单 4.25 中那样使用`const char*`或`std::string`调用`boost::regex_match`。函数的结果不依赖于变体。

### 搜索文本

如果我们想要搜索与特定正则表达式匹配的字符串的子字符串，我们应该使用`boost::regex_search`函数，而不是`boost::regex_match`。考虑字符串`"An array of papers from the academia on Alaska area's fauna"`。我们想要找到这个短语中属于同一个单词并以`'a'`开头和结尾的所有子字符串。要使用的正则表达式将是`a\w*a`。让我们看看如何使用`boost::regex_search`来做到这一点：

**清单 4.27：搜索匹配正则表达式的子字符串**

```cpp
 1 #include <boost/regex.hpp>
 2 #include <string>
 3 #include <iostream>
 4 
 5 int main() {
 6   std::string str2 = "An array of papers from the academia "
 7                      "on Alaska area's fauna";
 8   boost::regex r2("a\\w*a");
 9   boost::smatch matches;
10   std::string::const_iterator start = str2.begin(),
11                               end = str2.end();
12
13   while (boost::regex_search(start, end, matches, r2)) { 
14     std::cout << "Matched substring " << matches.str()
15            << " at offset " << matches[0].first - str2.begin()
16            << " of length " << matches[0].length() << '\n';
17     start = matches[0].second;
18   }
19 }
```

这打印了以下行，每行都有一个以`'a'`开头和结尾的单词或单词的一部分：

```cpp
Matched substring arra at offset 3 of length 4.
Matched substring academia at offset 28 of length 8.
Matched substring aska at offset 42 of length 4.
Matched substring area at offset 47 of length 4.
Matched substring auna at offset 58 of length 4.
```

在代码示例中，我们构造了字符串（第 6 行），正则表达式（第 8 行），以及`boost::smatch`的实例（第 9 行），它是`boost::match_results`模板的特化，用于输入类型为`std::string`时使用。我们在循环中搜索连续匹配的子字符串，调用`boost::regex_search`。我们将两个迭代器传递给`boost::regex_search`，`smatch`实例称为`matches`，以及正则表达式`r2`（第 13 行）。您必须向`boost::regex_search`传递`const`迭代器（第 10、11 行），否则编译将无法解析函数调用，并显示大量不必要的消息。

类型为`boost::smatch`的对象`matches`在调用`regex_search`后存储有关与正则表达式匹配的子字符串的信息。它的`str`成员返回由正则表达式匹配的子字符串。`boost::smatch`是`boost::ssub_match`对象的序列集合。当正则表达式匹配子字符串时，迭代器对的一部分存储在类型为`boost::ssub_match`的对象中。这存储在`matches`的索引 0 处，并作为`matches[0]`访问。`ssub_match`的`first`和`second`成员是匹配的开始（第 15 行）和匹配结束的迭代器。成员函数`length()`返回匹配的长度（第 16 行）。在每次迭代结束时，我们将`start`迭代器设置为上一个匹配结束位置之后的第一个位置（第 17 行），以开始寻找下一个匹配。`boost::ssub_match`是模板`boost::sub_match`的特化，用于当输入字符串的类型为`std::string`时使用。

假设对于每个匹配，我们想要提取两个`a`之间的内容。为此，我们可以使用捕获子表达式。正则表达式会稍微修改为`a(\\w*)a`。要访问与括号子表达式匹配的内容，我们再次使用`boost::smatch`对象。对于正则表达式中的每个这样的子表达式，都会构造一个额外的`boost::ssub_match`对象，并将其添加到传递的`boost::smatch`对象的连续索引中。如果子表达式在字符串中匹配了任何内容，那么匹配该子表达式的子字符串的开始和结束将存储在`ssub_match`对象中。

这是我们如何使用修改后的正则表达式：

**清单 4.28：解析匹配的子字符串和子表达式**

```cpp
 1 #include <boost/regex.hpp>
 2 #include <string>
 3 #include <iostream>
 4 int main()
 5 {
 6   std::string str2 = "An array of papers from the academia "
 7                      "on Alaska area's fauna";
 8  boost::regex r2("a(\\w*)a");
 9  boost::smatch matches;
10   std::string::const_iterator start = str2.begin(),
11                               end = str2.end();
12
13   while (boost::regex_search(start, end, matches, r2)) {
14     std::cout << "Matched substring '" << matches.str()
15          << "' following '" << matches.prefix().str()
16          << " preceding '" << matches.suffix().str() << "'\n";
17     start = matches[0].second;
18     for (size_t s = 1; s < matches.size(); ++s) {
19       if (matches[s].matched) {
20         std::cout << "Matched substring " << matches[s].str()
21            << " at offset " << matches[s].first – str2.begin()
22            << " of length " << matches[s].length() << '\n';
23       }
24     }
25   }
26 }
```

在内部循环（第 18 行）中，我们遍历所有子表达式，对于匹配任何子字符串的子表达式（第 19 行），我们使用`boost::ssub_match`的`str`成员函数（第 20 行）打印匹配的子字符串，以及子字符串的偏移量（第 21 行）和长度（第 22 行）。`matches`对象的`prefix`和`suffix`方法分别返回匹配的子字符串之前和之后的部分，作为`boost::ssub_match`对象（第 15、16 行）。

`boost::match_results`和`boost::sub_match`模板有不同的可用特化，适用于不同类型的输入，比如窄字符或宽字符数组，或者`std::basic_string`（`std::string`或`std::wstring`）的特化。

以下表总结了这些特化：

| 输入类型 | std::match_results 特化 | std::sub_match 特化 |
| --- | --- | --- |
| `std::string` | `std::smatch` | `std::ssub_match` |
| `std::wstring` | `std::wmatch` | `std::wsub_match` |
| `const char*` | `std::cmatch` | `std::csub_match` |
| `const wchar_t*` | `std::wcmatch` | `std::wcsub_match` |

### 使用正则表达式对文本进行标记化

使用正则表达式解析输入是很多工作，应该有更好的抽象可用于应用程序员。事实上，您可以使用`boost::regex_iterator`和`boost::regex_token_iterator`来简化这种工作。假设我们想要挑选出字符串中以`'a'`开头和结尾的所有单词。以下是一个相对轻松的方法：

**清单 4.29：使用 boost::regex_iterator 解析字符串**

```cpp
 1 #include <boost/regex.hpp>
 2 #include <string>
 3 #include <iostream>
 4
 5 int main()
 6 {
 7   std::string str2 = "An array of papers from the academia "
 8                      "on Alaska area's fauna";
 9   boost::regex r1("\\ba\\w*a\\b", boost::regex::icase);
10   boost::sregex_iterator rit(str2.begin(), str2.end(), r1), rend;
11 
12   while (rit != rend) {
13     std::cout << *rit++ << '\n';
14   }
15 }
```

该程序将以下文本打印到输出，由以`'a'`开头和结尾的三个单词组成：

```cpp
academia
Alaska
area
```

`boost::sregex_iterator`是模板`boost::regex_iterator`的特化，用于当输入字符串的类型为`std::string`时使用。它的实例`rit`使用字符串迭代器初始化，定义了用于查找连续标记的输入字符串和正则表达式（第 10 行）。然后，它用于像任何其他迭代器一样迭代连续的标记（第 12 行）。

在前面的示例中，我们没有处理子表达式。因此，让我们看一个带有子表达式的示例。考虑一个字符串`"animal=Llama lives_in=Llama and is related_to=vicuna"`。它由一些由等号分隔的键值对组成，还有其他内容。如果我们想要提取所有这样的键值对，我们可以使用正则表达式`\w+=\w+`。我们假设键和值是不带嵌入标点或空格的单词。如果我们还想要分别挑选出键和值，我们可以使用捕获组，如`(\w+)=(\w+)`用于子表达式匹配。

通过使用`boost::sregex_token_iterator`，我们实际上可以相对容易地挑选出与单个子表达式匹配的子字符串。`boost::sregex_token_iterator`是模板`boost::regex_token_iterator`的特化，用于处理类型为`std::string`的输入字符串。它接受输入字符串、正则表达式和可选参数的迭代器，指定要迭代的子表达式。以下是引导代码：

**清单 4.30：使用 boost::regex_token_iterator 解析输入字符串**

```cpp
 1 #include <boost/regex.hpp>
 2 #include <string>
 3 #include <iostream>
 4
 5 int main()
 6 {
 7   std::string str3 = "animal=Llama lives_in=Chile "
 8                      "and is related_to=vicuna";
 9   boost::regex r3("(\\w+)=(\\w+)");
10   int subindx[] = {2, 1};
11   boost::sregex_token_iterator tokit(str3.begin(), str3.end(),
12                                      r3, subindx), tokend;
13   while (tokit != tokend) {
14     std::cout << *tokit++ << '\n';
15   }
16   std::cout << '\n';
17 }
```

此代码打印以下输出：

```cpp
Llama
animal
Chile
lives_in
vicuna
related_to
```

您可能已经注意到，我们打印的值后面跟着键。我们使用定义输入字符串的迭代器、正则表达式和数组`subindx`来初始化`boost::sregex_token_iterator`，该数组指定我们感兴趣的子表达式（第 11 行）。由于`subindx`的值为`{2, 1}`（第 10 行），第二个字段在第一个字段之前打印。除了数组，我们还可以传递标识子表达式索引的整数向量，或者标识我们感兴趣的唯一子表达式的单个整数。如果省略此参数，`boost::regex_token_iterator`的行为与`boost::regex_iterator`相同。数组的大小不需要传递，并且通过模板参数推导自动推断。

Boost String Algorithms 库中的一些算法提供了对 Boost.Regex 功能的便捷包装。`boost::find_all_regex` 算法接受一个序列容器、一个输入字符串和一个正则表达式，并通过单个函数调用将匹配正则表达式的输入字符串的所有子字符串放入序列容器中。`boost::split_regex` 容器将一个字符串分割成由匹配某个正则表达式的文本分隔的标记，并将这些标记放入序列容器中。以下是两者的示例；`find_all_regex` 将一个句子分割成单词，而 `split_regex` 将使用管道字符分隔的记录分割成字段：

**清单 4.31：使用 find_all_regex 和 split_regex**

```cpp
 1 #include <boost/algorithm/string_regex.hpp>
 2 #include <boost/regex.hpp>
 3 #include <string>
 4 #include <iostream>
 5 #include <vector>
 6
 7 int main()
 8 {
 9   std::string line = "All that you touch";
10   std::vector<std::string> words;
11   boost::find_all_regex(words, line, boost::regex("\\w+"));
12
13   std::string record = "Pigs on the Wing|Dogs| Pigs| Sheep";
14   std::vector<std::string> fields;
15   boost::split_regex(fields, record, boost::regex("[\\|]"));
16
17   for (auto word: words) { std::cout << word << ","; }
18   std::cout << '\n';
19   for (auto field: fields) { std::cout << field << ","; }
20 }
```

这打印出以下输出：

```cpp
All,ll,l,that,hat,at,t,you,ou,u,touch,ouch,ch,h,
Pigs on the Wing,Dogs, Pigs, Sheep,
```

请注意，第一行打印出了与正则表达式 `\w+` 匹配的所有可能子字符串（第 11 行），而不仅仅是最大的不相交匹配子字符串。这是因为 `find_all_regex` 在输入中找到了每个匹配的子字符串。

### 替换文本

正则表达式的一个常见用途是搜索文本，并用其他文本替换匹配的文本。例如，我们可能想要扫描特定段落以寻找所有所有格短语（英国的女王，印度的文化，人们的选择等），并将它们转换为另一种形式（英国的女王，印度的文化，人们的选择等）。`boost::regex_replace` 函数模板可以很方便地实现这一目的。

首先，我们定义正则表达式 `\w+'s\s+\w+`。由于我们必须重新排列短语，我们必须使用子表达式来捕获匹配的部分。我们使用正则表达式 `(\w+)'s\s+(\w+)` 进行匹配。我们可以在替换字符串中使用编号的反向引用来引用子匹配，因此替换字符串是 `"\2 of \1"`。我们将这些与输入字符串一起传递给 `boost::regex_replace`，它将返回一个字符串，其中匹配的部分已适当替换。以下是代码：

**清单 4.32：使用正则表达式查找/替换字符串**

```cpp
 1 #include <boost/regex.hpp>
 2 #include <cassert>
 3
 4 int main()
 5 {
 6   std::string str4 = "England's Queen, India's President, "
 7                      "people's choice";
 8   boost::regex r4("(\\w+)'s\\s+(\\w+)");
10   std::string rep = boost::regex_replace(str4, r4, "\\2 of \\1");
11   
12   assert(rep == "Queen of England, President of India, "
13                   "choice of people");
14 }
```

默认情况下，`regex_replace` 会替换所有匹配的子字符串。如果我们只想替换第一个匹配的子字符串，那么我们需要将 `boost::regex_constants::format_first_only` 作为第四个参数传递给 `regex_replace`。

# 自测问题

对于多项选择题，选择所有适用的选项：

1.  Boost Range 如何帮助 Boost Algorithms 提供更好的接口？

a. 任何以单个参数表示的字符范围，而不是迭代器对

b. 它比迭代器对更快

c. 它支持 C 风格数组，并可扩展到其他抽象

d. 它提供更好的异常安全性

1.  哪个算法生成了搜索所有匹配搜索字符串或模式的子字符串的最短代码？

a. `boost::find_all`

b. `boost::find_all_regex`

c. `boost::find_first`

d. `boost::regex_iterator`

1.  Boost Tokenizer 库提供了哪些标记化函数？

a. `boost::char_separator`

b. `boost::split`

c. `boost::escaped_list_separator`

d. `boost::tokenizer`

1.  正则表达式 `"\ba.*a"` 匹配字符串 `"two giant anacondas creeping around"` 的哪一部分？

a. `"ant anacondas creeping a"`

b. `"anacondas creeping a"`

c. `"ant anaconda"`

d. `"anaconda"`

1.  以下关于 `boost::smatch` 的哪个说法是正确的？

a. 它是 `boost::match_results` 的一个特化

b. 它仅存储匹配的子表达式

c. 它为每个子表达式存储一个 `boost::ssub_match` 对象

d. 其 `str` 成员返回匹配的子字符串

# 总结

在本章中，我们学习了使用 Boost String Algorithms 库中的各种杂项函数来执行对字符串数据类型的各种操作。然后我们看了一下通用的 Boost String Tokenizer 框架，它提供了一种高效和可扩展的方式来根据用户定义的条件对字符串进行标记化。最后，我们看了一下正则表达式，以及 Boost.Regex 库，它提供了匹配字符数据与正则表达式、搜索模式、标记化和使用正则表达式替换模式的能力。

本章应该为您提供了从 Boost 库中提供的基本文本处理工具的广泛视角。在这个过程中，我们还从 Boost Range 抽象中学到了一些有用的技巧。在下一章中，我们将转向 Boost 库中提供的各种数据结构。
