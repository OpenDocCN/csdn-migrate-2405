# C++ 游戏开发秘籍（一）

> 原文：[`zh.annas-archive.org/md5/260E2BE0C3FA0FF74505C2A10CA40511`](https://zh.annas-archive.org/md5/260E2BE0C3FA0FF74505C2A10CA40511)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

这本书详细介绍了 C++的一些方面，这些方面可以用于游戏开发。

# 本书涵盖的内容

第一章，“游戏开发基础”，解释了 C++编程的基础知识，编写小型程序用于游戏，并且如何在游戏中处理内存。

第二章，“面向对象的方法和游戏设计”，解释了在游戏中使用面向对象的概念，您将制作一个小型的原型文本游戏。

第三章，“游戏开发中的数据结构”，介绍了 C++中所有简单和复杂的数据结构，并展示了如何在游戏中有效地使用它们。

第四章，“游戏开发的算法”，解释了可以在游戏中使用的各种算法。它还涵盖了衡量算法效率的方法。

第五章，“事件驱动编程-制作您的第一个 2D 游戏”，介绍了 Windows 编程，创建精灵和动画。

第六章，“游戏开发的设计模式”，解释了如何在游戏开发中使用众所周知的设计模式以及何时不要使用它们。

第七章，“组织和备份”，解释了备份数据的重要性以及在团队中共享数据的重要性。

第八章，“游戏开发中的人工智能”，解释了如何在游戏中编写人工智能。

第九章，“游戏开发中的物理学”，解释了如何使物体碰撞以及如何使用第三方物理库，如 Box2D，来制作游戏。

第十章，“游戏开发中的多线程”，解释了如何使用 C++11 的线程架构来制作游戏。

第十一章，“游戏开发中的网络”，解释了编写多人游戏的基础知识。

第十二章，“游戏开发中的音频”，解释了如何向游戏添加声音和音乐效果，并在播放声音时避免内存泄漏。

第十三章，“技巧和窍门”，介绍了使用 C++制作游戏的一些巧妙技巧。

# 您需要为这本书做什么

对于这本书，您需要一台 Windows 机器和一个可用的 Visual Studio 2015 Community Edition 的副本。

# 这本书是为谁准备的

这本书主要适用于想要进入游戏行业的大学生，或者想要早早动手并了解游戏编程基础的热情学生。这本书还有一些非常技术性的章节，对于行业专业人士来说，这些章节将非常有用，可以作为参考或在解决复杂问题时随身携带。

# 部分

在这本书中，您会发现一些经常出现的标题（准备工作，如何做，它是如何工作的，还有更多，另请参阅）。

为了清晰地说明如何完成一个食谱，我们使用以下部分：

## 准备工作

这一部分告诉您食谱中可以期待什么，并描述了为食谱设置任何所需的软件或任何初步设置的方法。

## 如何做...

这一部分包含了遵循食谱所需的步骤。

## 它是如何工作的...

这一部分通常包括对前一部分发生的事情的详细解释。

## 还有更多...

这一部分包含有关食谱的其他信息，以使读者对食谱更加了解。

## 另请参阅

本节提供了有用的链接，可获取其他有用信息。

# 约定

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些示例以及它们的含义解释。

文本中的代码单词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“如果您有一个名为`main.cpp`的文件，它将生成一个名为`main.o`的目标代码。”

代码块设置如下：

```cpp
#include <iostream>
#include <conio.h>

using namespace std;

int countTotalBullets(int iGun1Ammo, int iGun2Ammo)
{
    return iGun1Ammo + iGun2Ammo;
}
```

**新术语**和**重要单词**以粗体显示。您在屏幕上看到的单词，例如菜单或对话框中的单词，会以这种方式出现在文本中：“点击**下载 Visual Studio Community**。”

### 注意

警告或重要提示会以这样的方式显示在框中。

### 提示

提示和技巧显示如下。


# 第一章：游戏开发基础

在本章中，将涵盖以下食谱：

+   在 Windows 上安装一个 IDE

+   选择合适的源代码控制工具

+   使用调用堆栈进行内存存储

+   谨慎使用递归

+   使用指针存储内存地址

+   在各种数据类型之间进行转换

+   使用动态分配更有效地管理内存

+   使用位操作进行高级检查和优化

# 介绍

在本章中，我们将介绍你在游戏开发中需要了解的基本概念。

在一个人开始编码之前的第一步是安装一个**集成开发环境**（**IDE**）。现在有一些在线 IDE 可用，但我们将使用离线独立的 IDE，**Visual Studio**。许多程序员在早期阶段没有开始使用的下一个最重要的事情是**修订控制软件**。

修订控制软件有助于将代码备份到一个中心位置；它有对所做更改的历史概述，您可以访问并在需要时恢复，它还有助于解决不同程序员同时对同一文件进行的工作之间的冲突。

在我看来，C++最有用的特性是**内存处理**。它让开发人员对内存分配方式有很大的控制，这取决于程序的当前使用和需求。因此，我们可以在需要时分配内存，并相应地释放它。

如果我们不释放内存，我们可能很快就会用完内存，特别是如果我们使用递归。有时需要将一种数据类型转换为另一种，以防止数据丢失，在函数中传递正确的数据类型等。C++提供了一些方法，我们可以通过这些方法进行转换。

本章的食谱主要关注这些主题，并处理实现它们的实际方法。

# 在 Windows 上安装一个 IDE

在这个步骤中，我们将发现在 Windows 机器上安装 Visual Studio 有多么容易。

## 准备工作

要完成这个步骤，你需要一台运行 Windows 的机器。不需要其他先决条件。

## 操作步骤

Visual Studio 是一个强大的 IDE，大多数专业软件都是用它编写的。它有很多功能和插件，帮助我们写出更好的代码：

1.  转到[`www.visualstudio.com`](https://www.visualstudio.com)。

1.  点击**下载 Visual Studio Community**。![操作步骤…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_01_01.jpg)

下载 Visual Studio Community

1.  这应该下载一个`.exe`文件。

1.  下载完成后，双击安装文件开始安装。

1.  确保你的 Windows 机器上有必要的所有更新。

1.  你也可以下载任何版本的 Visual Studio 或 Visual C++ Express。

1.  如果应用程序要求开始环境设置，请从可用选项中选择**C++**。

### 注意

以下是需要注意的几点：

+   你需要一个 Microsoft 账户来安装它。

+   还有其他免费的 C++ IDE，比如**NetBeans**、**Eclipse**和**Code::Blocks**。

+   虽然 Visual Studio 只适用于 Windows，但 Code::Blocks 和其他跨平台的 IDE 也可以在 Mac 和 Linux 上运行。

在本章的其余部分，所有的代码示例和片段都将使用 Visual Studio 提供。

## 工作原理

IDE 是一个编程环境。IDE 包括各种功能，这些功能在一个 IDE 到另一个 IDE 可能会有所不同。然而，在所有 IDE 中都存在的最基本的功能是代码编辑器、编译器、调试器、链接器和 GUI 构建器。

代码编辑器，或者另一种称呼为源代码编辑器，对程序员编写的代码进行编辑非常有用。它们提供诸如自动校正、语法高亮、括号补全和缩进等功能。下面是 Visual Studio 代码编辑器的示例快照：

![工作原理…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_01_02.jpg)

**编译器**是一个将您的 C++代码转换为目标代码的计算机程序。这是为了创建可执行文件所必需的。如果您有一个名为`main.cpp`的文件，它将生成一个名为`main.o`的目标代码。

**链接器**是一个将编译器生成的目标代码转换为可执行文件或库文件的计算机程序：

![工作原理...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_01_03.jpg)

编译器和链接器

**调试器**是一个帮助测试和调试计算机程序的计算机程序。

**GUI 构建器**帮助设计师和程序员轻松创建 GUI 内容或小部件。它使用拖放**所见即所得**工具编辑器。

# 选择正确的源代码控制工具

在这个步骤中，我们将看到使用正确的版本控制来备份我们的代码是多么容易。将备份到中央服务器的优势是您永远不会丢失工作，可以在任何计算机上下载代码，还可以回到过去的任何更改。想象一下，就像我们在游戏中有一个检查点，如果遇到问题，可以回到那个检查点。

## 准备工作

要完成这个步骤，您需要一台运行 Windows 的计算机。不需要其他先决条件。

## 如何做…

选择正确的版本控制工具非常重要，因为它将节省大量时间来组织数据。有几种版本控制工具可用，因此非常重要的是我们应该了解所有这些工具，这样我们就可以根据自己的需求选择正确的工具。

首先分析一下你可以选择的选项。选择主要包括**Concurrent Versions System**（**CVS**），**Apache** **Subversion**（**SVN**），**Mercurial**和**GIT**。

## 工作原理...

CVS 已经存在很长时间了，因此有大量的文档和帮助可用。然而，缺乏原子操作经常导致源代码损坏，不太适合长期分支操作。

SVN 是作为对 CVS 的改进而制作的，它解决了许多与原子操作和源代码损坏有关的问题。它是免费和开源的。它有许多不同 IDE 的插件。然而，这个工具的一个主要缺点是它在操作中相对非常慢。

GIT 主要是为 Linux 开发的，但它大大提高了操作速度。它也适用于 UNIX 系统。它具有廉价的分支操作，但与 Linux 相比，它对单个开发人员的支持有限。然而，GIT 非常受欢迎，许多人更喜欢 GIT 而不是 SVN 或 CVS。

Mercurial 在 GIT 之后不久出现。它具有基于节点的操作，但不允许合并两个父分支。

因此，总之，如果您想要一个其他人可以推送和拉取的中央存储库，请使用 SVN。尽管它有局限性，但很容易学习。如果您想要一个分布式模型，请使用 Mercurial 或 GIT。在这种情况下，每台计算机上都有一个存储库，并且通常有一个被视为*官方*的存储库。如果团队规模相对较小，通常更喜欢 Mercurial，并且比 GIT 更容易学习。

我们将在另一章节中更详细地研究这些内容。

### 提示

有关下载代码包的详细步骤在本书的前言中有提及。请查看。

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/C++Game-Development-Cookbook`](https://github.com/PacktPublishing/C++Game-Development-Cookbook)。我们还有来自丰富书籍和视频目录的其他代码包，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 使用调用堆栈进行内存存储

C++仍然是大多数游戏开发者首选的语言的主要原因是你可以自己处理内存并且在很大程度上控制内存的分配和释放。因此，我们需要了解为我们提供的不同内存空间。当数据被“推”到堆栈上时，堆栈增长。当数据被“弹”出堆栈时，堆栈缩小。不可能在不先弹出放在其上面的所有数据的情况下弹出堆栈上的特定数据。把这想象成一系列从上到下排列的隔间。堆栈的顶部是堆栈指针指向的任何隔间（这是一个寄存器）。

每个隔间都有一个顺序地址。其中一个地址被保存在堆栈指针中。在那个神奇的地址下面的所有东西，被称为堆栈的顶部，被认为是在堆栈上。在堆栈顶部以上的所有东西被认为是堆栈之外的。当数据被推送到堆栈上时，它被放入堆栈指针上面的一个隔间中，然后堆栈指针被移动到新的数据上。当数据从堆栈上弹出时，堆栈指针的地址通过向下移动来改变。

## 准备工作

你需要在你的 Windows 机器上安装一个可用的 Visual Studio 副本。

## 如何做…

C++可能是目前最好的编程语言之一，而其中一个主要原因是它也是一种低级语言，因为我们可以操纵内存。要理解内存处理，了解内存堆栈的工作方式非常重要：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加一个名为`main.cpp`的源文件，或者任何你想要命名的源文件。

1.  添加以下代码行：

```cpp
#include <iostream>
#include <conio.h>

using namespace std;

int countTotalBullets(int iGun1Ammo, int iGun2Ammo)
{
    return iGun1Ammo + iGun2Ammo;
}

int main()
{
    int iGun1Ammo = 3;
    int iGun2Ammo = 2;
    int iTotalAmmo = CountTotalBullets(iGun1Ammo, iGun2Ammo);

    cout << "Total ammunition currently with you is"<<iTotalAmmo;

    _getch();
}
```

## 它是如何工作的…

当你调用函数`CountTotalBullets`时，代码会分支到被调用的函数。参数被传递进来，函数体被执行。当函数完成时，一个值被返回，控制返回到调用函数。

但从编译器的角度来看，它是如何真正工作的呢？当你开始你的程序时，编译器创建一个堆栈。**堆栈**是为了在你的程序中保存每个函数的数据而分配的内存的一个特殊区域。堆栈是一个**后进先出**（**LIFO**）的数据结构。想象一副牌；放在牌堆上的最后一张牌将是最先拿出的。

当你的程序调用`CountTotalBullets`时，一个堆栈帧被建立。**堆栈帧**是堆栈中专门留出来管理该函数的区域。这在不同的平台上非常复杂和不同，但这些是基本步骤：

1.  `CountTotalBullets`的返回地址被放在堆栈上。当函数返回时，它将在这个地址继续执行。

1.  为你声明的返回类型在堆栈上留出空间。

1.  所有函数参数都被放在堆栈上。

1.  程序分支到你的函数。

1.  局部变量在定义时被推送到堆栈上。

# 谨慎使用递归

递归是一种编程设计形式，函数多次调用自身以通过将大型解决方案集拆分为多个小解决方案集来解决问题。代码大小肯定会缩短。然而，如果不正确使用，递归可能会非常快地填满调用堆栈，导致内存耗尽。

## 准备工作

要开始使用这个方法，你应该对调用堆栈和函数调用期间内存分配有一些先验知识。你需要一台装有 Visual Studio 的 Windows 机器。

## 如何做…

在这个方法中，你将看到使用递归是多么容易。递归编程非常聪明，但也可能导致一些严重的问题：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加一个名为`main.cpp`的源文件，或者任何你想要命名的源文件。

1.  添加以下代码行：

```cpp
#include <iostream>
#include <conio.h>

using namespace std;
int RecursiveFactorial(int number);
int Factorial(int number);
int main()
{
    long iNumber;
    cout << "Enter the number whose factorial you want to find";
    cin >> iNumber;

    cout << RecursiveFactorial(iNumber) << endl;
    cout << Factorial(iNumber);

    _getch();
    return 0;
}

int Factorial(int number)
{
    int iCounter = 1;
    if (number < 2)
    {
        return 1;
    }
    else
    {
        while (number>0)
        {
            iCounter = iCounter*number;
            number -= 1;
        }

    }
    return iCounter;
}

int RecursiveFactorial(int number)
{
    if (number < 2)
    {
        return 1;
    }
    else
    {
        while (number>0)
    {
            return number*Factorial(number - 1);
        }
    }

}
```

## 工作原理...

从前面的代码中可以看出，这两个函数都可以找到一个数字的阶乘。然而，使用递归时，每次函数调用时堆栈大小都会急剧增长；堆栈指针必须在每次调用时更新，并且数据被推送到堆栈上。使用递归时，由于函数调用自身，每次从内部调用函数时，堆栈大小都会不断增加，直到内存耗尽并创建死锁或崩溃。

想象一下找到 1000 的阶乘。该函数将在自身内部被调用很多次。这是一种导致灾难的方法，我们应该尽量避免这种编码实践。

## 还有更多...

如果要找到大于 15 的数字的阶乘，可以使用比 int 更大的数据类型，因为得到的阶乘将太大而无法存储在 int 中。

# 使用指针存储内存地址

在前两个示例中，我们已经看到内存不足可能会成为我们的问题。然而，直到现在，我们对分配多少内存以及分配给每个内存地址的内容没有任何控制。使用指针，我们可以解决这个问题。在我看来，指针是 C++中最重要的主题。如果你对 C++的概念必须清晰，并且如果你要成为一个优秀的 C++开发人员，你必须擅长使用指针。指针一开始可能看起来很可怕，但一旦你掌握了它，指针就很容易使用。

## 准备就绪

对于这个示例，你需要一台装有 Visual Studio 的 Windows 机器。

## 如何做...

在这个示例中，我们将看到使用指针有多么容易。一旦你熟悉使用指针，我们就可以很容易地操纵内存并在内存中存储引用：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加一个名为`main.cpp`的源文件，或者任何你想要命名源文件。

1.  添加以下代码行：

```cpp
#include <iostream>
#include <conio.h>

using namespace std;

int main()
{
    float fCurrentHealth = 10.0f;

    cout << "Address where the float value is stored: " << &fCurrentHealth << endl;
    cout << "Value at that address: " << *(&fCurrentHealth) << endl;

    float* pfLocalCurrentHealth = &fCurrentHealth;
    cout << "Value at Local pointer variable: "<<pfLocalCurrentHealth << endl;
    cout << "Address of the Local pointer variable: "<<&pfLocalCurrentHealth << endl;
    cout << "Value at the address of the Local pointer variable: "<<*pfLocalCurrentHealth << endl;

    _getch();
    return 0;
}
```

## 工作原理...

C++程序员最强大的工具之一是直接操作计算机内存。**指针**是一个保存内存地址的变量。C++程序中使用的每个变量和对象都存储在内存的特定位置。每个内存位置都有一个唯一的地址。内存地址将根据所使用的操作系统而变化。所占用的字节数取决于变量类型：*float = 4 字节*，*short = 2 字节*：

![工作原理...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_01_04.jpg)

指针和内存存储

内存中的每个位置都是 1 字节。指针`pfLocalCurrentHealth`保存了存储`fCurrentHealth`的内存位置的地址。因此，当我们显示指针的内容时，我们得到的是与包含`fCurrentHealth`变量的地址相同的地址。我们使用`&`运算符来获取`pfLocalCurrentHealth`变量的地址。当我们使用`*`运算符引用指针时，我们得到存储在该地址的值。由于存储的地址与存储`fCurrentHealth`的地址相同，我们得到值`10`。

## 还有更多...

让我们考虑以下声明：

+   `const float* pfNumber1`

+   `float* const pfNumber2`

+   `const float* const pfNumber3`

所有这些声明都是有效的。但是它们的含义是什么？第一个声明说明`pfNumber1`是一个指向常量浮点数的指针。第二个声明说明`pfNumber2`是一个指向浮点数的常量指针。第三个声明说明`pfNumber3`是一个指向常量整数的常量指针。引用和这三种 const 指针之间的关键区别如下：

+   `const`指针可以是 NULL

+   引用没有自己的地址，而指针有

引用的地址是实际对象的地址

+   指针有自己的地址，并且它的值是它指向的值的地址

### 注意

有关指针和引用的更多信息，请访问以下链接：

[`stackoverflow.com/questions/57483/what-are-the-differences-between-a-pointer-variable-and-a-reference-variable-in/57492#57492`](http://stackoverflow.com/questions/57483/what-are-the-differences-between-a-pointer-variable-and-a-reference-variable-in/57492#57492)

# 在不同数据类型之间进行转换

转换是一种将一些数据转换为不同类型数据的转换过程。我们可以在内置类型或我们自己的数据类型之间进行转换。一些转换是由编译器自动完成的，程序员不必干预。这种转换称为**隐式转换**。其他转换必须由程序员直接指定，称为显式转换。有时我们可能会收到关于*数据丢失*的警告。我们应该注意这些警告，并考虑这可能会对我们的代码产生不利影响。当接口期望特定类型的数据，但我们想要提供不同类型的数据时，通常会使用转换。在 C 中，我们可以将任何东西转换为任何东西。然而，C++为我们提供了更精细的控制。

## 准备工作

对于这个教程，你需要一台装有 Visual Studio 的 Windows 机器。

## 如何做…

在这个教程中，我们将看到如何在各种数据类型之间轻松转换或转换。通常，程序员即使在 C++中也使用 C 风格的转换，但这是不推荐的。C++为不同情况提供了自己的转换风格，我们应该使用它：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加一个名为`main.cpp`的源文件，或者任何你想要命名的源文件。

1.  添加以下代码行：

```cpp
#include <iostream>
#include <conio.h>

using namespace std;

int main()
{
    int iNumber = 5;
    int iOurNumber;
    float fNumber;

    //No casting. C++ implicitly converts the result into an int and saves 
    //into a float
    fNumber = iNumber/2;
    cout << "Number is " << fNumber<<endl;

    //C-style casting. Not recommended as this is not type safe
    fNumber = (float)iNumber / 2;
    cout << "Number is " << fNumber<<endl;

    //C++ style casting. This has valid constructors to make the casting a safe one
    iOurNumber = static_cast<int>(fNumber);
    cout << "Number is " << iOurNumber << endl;

    _getch();
    return 0;
}
```

## 它是如何工作的…

在 C++中有四种类型的转换操作符，取决于我们要转换的内容：`static_cast`、`const_cast`、`reinterpret_cast`和`dynamic_cast`。现在，我们将看看`static_cast`。在讨论动态内存和类之后，我们将看看剩下的三种转换技术。从较小的数据类型转换为较大的类型称为提升，保证不会丢失数据。然而，从较大的数据类型转换为较小的数据类型称为降级，可能会导致数据丢失。当发生这种情况时，编译器通常会给出警告，你应该注意这一点。

让我们看看之前的例子。我们已经用值`5`初始化了一个整数。接下来，我们初始化了一个浮点变量，并存储了`5`除以`2`的结果，即`2.5`。然而，当我们显示变量`fNumber`时，我们看到显示的值是`2`。原因是 C++编译器隐式地将`5/2`的结果转换为整数并存储它。因此，它类似于计算 int(`5/2`)，即 int(`2.5`)，计算结果为`2`。因此，为了实现我们想要的结果，我们有两个选项。第一种方法是 C 风格的显式转换，这是不推荐的，因为它没有类型安全检查。C 风格转换的格式是(`resultant_data_type`) (`expression`)，在这种情况下类似于 float (`5/2`)。我们明确告诉编译器将表达式的结果存储为浮点数。第二种方法，更符合 C++风格的转换方法，是使用`static_cast`操作。这种方法有适当的构造函数来指示转换是类型安全的。`static_cast`操作的格式是`static_cast<resultant_data_type> (expression)`。编译器会检查转换是否安全，然后执行类型转换操作。

# 更有效地管理内存，使用动态分配

程序员通常处理内存的五个领域：全局命名空间，寄存器，代码空间，堆栈和自由存储区。当数组被初始化时，必须定义元素的数量。这导致了许多内存问题。大多数情况下，我们分配的元素并没有全部被使用，有时我们需要更多的元素。为了帮助解决这个问题，C++通过使用自由存储区在`.exe`文件运行时进行内存分配。

自由存储区是一个可以用来存储数据的大内存区域，有时被称为*堆*。我们可以请求一些自由存储区的空间，它会给我们一个地址，我们可以用来存储数据。我们需要将该地址保存在一个指针中。自由存储区直到程序结束才会被清理。程序员有责任释放程序使用的任何自由存储区内存。

自由存储区的优势在于不需要预先分配所有变量。我们可以在运行时决定何时需要更多内存。内存被保留并保持可用，直到显式释放为止。如果在函数中保留内存，当控制从该函数返回时，仍然可用。这比全局变量编码要好得多。只有可以访问指针的函数才能访问存储在内存中的数据，并且它为该数据提供了一个严格控制的接口。

## 准备工作

对于这个配方，你需要一台装有 Visual Studio 的 Windows 机器。

## 如何做...

在这个配方中，我们将看到动态分配是多么容易。在游戏中，大部分内存都是在运行时动态分配的，因为我们从来不确定应该分配多少内存。分配任意数量的内存可能导致内存不足或内存浪费：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  添加一个名为`main.cpp`的源文件，或者任何你想要命名的源文件。

1.  添加以下代码行：

```cpp
#include <iostream>
#include <conio.h>
#include <string>

using namespace std;

int main()
{

  int iNumberofGuns, iCounter;
  string * sNameOfGuns;
  cout << "How many guns would you like to purchase? ";
  cin >> iNumberofGuns;
  sNameOfGuns = new string[iNumberofGuns];
  if (sNameOfGuns == nullptr)
    cout << "Error: memory could not be allocated";
  else
  {
    for (iCounter = 0; iCounter<iNumberofGuns; iCounter++)
    {
      cout << "Enter name of the gun: ";
      cin >> sNameOfGuns[iCounter];
    }
    cout << "You have purchased: ";
    for (iCounter = 0; iCounter<iNumberofGuns; iCounter++)
      cout << sNameOfGuns[iCounter] << ", ";
    delete[] sNameOfGuns;
  }

  _getch();
  return 0;
}
```

## 它是如何工作的...

您可以使用`new`关键字将内存分配给自由存储区；`new`后面跟着您想要分配的变量的类型。这允许编译器知道需要分配多少内存。在我们的示例中，我们使用了 string。`new`关键字返回一个内存地址。这个内存地址被分配给一个指针`sNameOfGuns`。我们必须将地址分配给一个指针，否则地址将丢失。使用`new`运算符的格式是`datatype * pointer = new datatype`。所以在我们的示例中，我们使用了`sNameOfGuns = new string[iNumberofGuns]`。如果新的分配失败，它将返回一个空指针。我们应该始终检查指针分配是否成功；否则我们将尝试访问未分配的内存的一部分，并且可能会收到编译器的错误，如下面的屏幕截图所示，您的应用程序将崩溃：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_01_05.jpg)

当你完成内存的使用后，必须在指针上调用 delete。Delete 将内存返回给自由存储区。请记住，指针是一个局部变量。指针声明所在的函数作用域结束时，自由存储区上的内存不会自动释放。静态内存和动态内存的主要区别在于，静态内存的创建/删除是自动处理的，而动态内存必须由程序员创建和销毁。

`delete[]`运算符向编译器发出需要释放数组的信号。如果你不加括号，只有数组中的第一个元素会被删除。这将导致内存泄漏。内存泄漏真的很糟糕，因为这意味着有未被释放的内存空间。请记住，内存是有限的空间，所以最终你会遇到麻烦。

当我们使用`delete[]`时，编译器如何知道它必须从内存中释放*n*个字符串？运行时系统将项目数存储在某个位置，只有当你知道指针`sNameOfGuns`时才能检索到。有两种流行的技术可以做到这一点。这两种技术都被商业编译器使用，都有权衡，都不是完美的：

+   技术 1：

过度分配数组，并将项目数放在第一个元素的左侧。这是两种技术中较快的一种，但对于程序员错误地使用`delete sNameOfGuns`而不是`delete[] sNameOfGuns`更敏感。

+   技术 2：

使用关联数组，以指针作为键，项目数作为值。这是两种技术中较慢的一种，但对于程序员错误地使用`delete sNameOfGuns`而不是`delete[] sNameOfGuns`不太敏感。

## 更多内容...

我们还可以使用一个名为**VLD**的工具来检查内存泄漏。

### 注意

从[`vld.codeplex.com/`](https://vld.codeplex.com/)下载 VLD。

设置完成后，安装 VLD 到你的系统上。这可能会或可能不会正确设置 VC++目录。如果没有，可以通过右键单击项目页面并将 VLD 目录添加到名为**包含目录**的字段中手动设置，如下图所示：

![更多内容...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_01_06.jpg)

设置目录后，在源文件中添加头文件`<vld.h>`。执行应用程序并退出后，输出窗口将显示应用程序中是否存在任何内存泄漏。

### 理解错误消息

在调试构建时，你可能会在调试期间在内存中看到以下值：

+   `0xCCCCCCCC`：这指的是在堆栈上分配的值，但尚未初始化。

+   `0xCDCDCDCD`：这意味着内存已经在堆中分配，但尚未初始化（干净内存）。

+   `0xDDDDDDDD`：这意味着内存已经从堆中释放（死内存）。

+   `0xFEEEFEEE`：这指的是值被从自由存储中释放。

+   `0xFDFDFDFD`："无人之地"栅栏，它们被放置在调试模式下堆内存的边界上。它们不应该被覆盖，如果被覆盖了，这可能意味着程序正在尝试访问数组最大大小之外的索引处的内存。

# 使用位操作进行高级检查和优化

在大多数情况下，程序员不需要过多地担心位，除非有必要编写一些压缩算法，当我们制作游戏时，我们永远不知道是否会出现这样的情况。为了以这种方式压缩和解压文件，你需要实际上在位级别提取数据。最后，你可以使用位操作来加速你的程序或执行巧妙的技巧。但这并不总是推荐的。

## 准备就绪

对于这个示例，你需要一台装有 Visual Studio 的 Windows 机器。

## 如何做...

在这个示例中，我们将看到使用位操作通过操作内存执行操作是多么容易。位操作也是通过直接与内存交互来优化代码的好方法：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  添加一个名为`main.cpp`的源文件，或者任何你想要命名的源文件。

1.  添加以下代码行：

```cpp
#include <iostream>
#include <conio.h>

using namespace std;

void Multi_By_Power_2(int iNumber, int iPower);
void BitwiseAnd(int iNumber, int iNumber2);
void BitwiseOr(int iNumber, int iNumber2);
void Complement(int iNumber4);
void BitwiseXOR(int iNumber,int iNumber2);

int main()
{
  int iNumber = 4, iNumber2 = 3;
  int iPower = 2;
  unsigned int iNumber4 = 8;

  Multi_By_Power_2(iNumber, iPower);
  BitwiseAnd(iNumber,iNumber2);
  BitwiseOr(iNumber, iNumber2);
  BitwiseXOR(iNumber,iNumber2);
  Complement(iNumber4);

  _getch();
  return 0;
}

void Multi_By_Power_2(int iNumber, int iPower)
{
  cout << "Result is :" << (iNumber << iPower)<<endl;
}
void BitwiseAnd(int iNumber, int iNumber2)
{
  cout << "Result is :" << (iNumber & iNumber2) << endl;
}
void BitwiseOr(int iNumber, int iNumber2)
{
  cout << "Result is :" << (iNumber | iNumber2) << endl;
}
void Complement(int iNumber4)
{
  cout << "Result is :" << ~iNumber4 << endl;
}
void BitwiseXOR(int iNumber,int iNumber2)
{
  cout << "Result is :" << (iNumber^iNumber2) << endl;
}
```

## 工作原理...

左移操作符相当于将数字的所有位向左移动指定的位数。在我们的例子中，我们发送给函数`Multi_By_Power_2`的数字是`4`和`3`。数字`4`的二进制表示是`100`，所以如果我们将最高有效位（1）向左移动三位，我们得到`10000`，这是`16`的二进制。因此，左移等同于整数除以`2^shift_arg`，即`4*2³`，这又是`16`。类似地，右移操作等同于整数除以`2^shift_arg`。

现在让我们考虑我们想要打包数据，以便压缩数据。考虑以下示例：

```cpp
int totalammo,type,rounds;
```

我们正在存储枪支的总子弹数；枪支的类型，但只能是步枪或手枪；以及它可以发射的每轮总子弹数。目前我们使用三个整数值来存储数据。然而，我们可以将所有前述数据压缩成一个单一整数，从而压缩数据：

```cpp
int packaged_data;
packaged_data = (totalammo << 8) | (type << 7) | rounds;
```

如果我们假设以下符号：

+   总弹药数：`A`

+   类型：`T`

+   轮数：`R`

数据的最终表示将类似于这样：

```cpp
AAAAAAATRRRRRRR
```


# 第二章：游戏中的面向对象方法和设计

在本章中，我们将介绍以下教程：

+   使用类进行数据封装和抽象

+   使用多态性来重用代码

+   使用复制构造函数

+   使用运算符重载来重用运算符

+   使用函数重载来重用函数

+   使用文件进行输入和输出

+   创建您的第一个简单的基于文本的游戏

+   模板 - 何时使用它们

# 介绍

以下图表显示了**OOP**（**面向对象编程**）的主要概念。让我们假设我们需要制作一款赛车游戏。因此，汽车由发动机、车轮、底盘等组成。所有这些部分都可以被视为单独的组件，也可以用于其他汽车。同样，每辆汽车的发动机都可以是不同的，因此我们可以为每个单独的组件添加不同的功能、状态和属性。

所有这些都可以通过面向对象编程实现：

![介绍](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/B04929_02_01.jpg)

我们需要在任何包含状态和行为的设计中使用面向对象的系统。让我们考虑一个像*Space Invaders*的游戏。游戏由两个主要角色组成，玩家飞船和敌人。还有一个 boss，但那只是敌人的高级版本。玩家飞船可以有不同的状态，如存活、空闲、移动、攻击和死亡。它还有一些行为，比如左/右移动，单发/连发/导弹。同样，敌人也有状态和行为。这是使用面向对象设计的理想条件。boss 只是敌人的高级形式，因此我们可以使用多态性和继承的概念来实现结果。

# 使用类进行数据封装和抽象

类用于将信息组织成有意义的状态和行为。在游戏中，我们处理许多不同类型的武器、玩家、敌人和地形，每种都有自己的状态和行为类型，因此必须使用具有类的面向对象设计。

## 准备就绪

要完成本教程，您需要一台运行 Windows 的计算机。您需要在 Windows 计算机上安装 Visual Studio 的工作副本。不需要其他先决条件。

## 如何做…

在本教程中，我们将看到使用 C++中的面向对象编程轻松创建游戏框架有多容易：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加名为`Source.cpp`、`CEnemy.h`和`CEnemy.cpp`的源文件。

1.  将以下代码添加到`Souce.cpp`：

```cpp
#include "CEnemy.h"
#include <iostream>
#include <string>
#include <conio.h>
#include "vld.h"

using namespace std;

int main()
{
  CEnemy* pEnemy = new CEnemy(10,100,"DrEvil","GOLD");

  int iAge;
  int iHealth;
  string sName;
  string sArmour;

  iAge = pEnemy->GetAge();
  iHealth = pEnemy->TotalHealth();
  sArmour = pEnemy->GetArmourName();
  sName = pEnemy->GetName();

  cout << "Name of the enemy is :" << sName << endl;
  cout << "Name of " << sName << "'s armour is :" << sArmour << endl;
  cout << "Health of " << sName << " is :" << iHealth << endl;
  cout << sName << "'s age is :" << iAge;

delete pEnemy;
  _getch();
}
```

1.  将以下代码添加到`CEnemy.h`：

```cpp
#ifndef _CENEMY_H
#define _CENEMY_H

#include <string>
using namespace std;

class CEnemy
{
public:
  string GetName()const;
  int GetAge()const;
  string GetArmourName()const;
  int TotalHealth()const;

  //ctors
  CEnemy(int,int,string,string);
//dtors
  ~CEnemy();
private:
  int m_iAge;
  int m_iHealth;
  string m_sName;
  string m_sArmour;
};

#endif
```

1.  将以下代码添加到`CEnemy.cpp`：

```cpp
#include <iostream>
#include <string>
#include "CEnemy.h"

using namespace std;

CEnemy::CEnemy(int Age,int Health,int Armour,int Name)
{
  m_iAge = Age;
  m_iHealth = Health;
  m_sArmour = Armour;
  m_sName = Name;
}

int CEnemy::GetAge()const
{
  return m_iAge;
}

int CEnemy::TotalHealth()const
{
  return m_iHealth;
}

string CEnemy::GetArmourName()const
{
  return m_sArmour;
}

string CEnemy::GetName()const
{
  return m_sName;
}
```

## 它是如何工作的…

创建一个面向对象的程序，我们需要创建类和对象。虽然我们可以在同一个文件中编写类的定义和声明，但建议将定义和声明分开为两个单独的文件。声明类文件称为头文件，而定义类文件称为源文件。

在`CEnemy`头文件中，我们定义了我们需要的成员变量和函数。在一个类中，我们可以选择将变量分为公共、受保护或私有。公共状态表示它们可以从类外部访问，受保护状态表示只有从当前基类继承的子类可以访问它，而私有状态表示它们可以被类的任何实例访问。在 C++类中，默认情况下，一切都是私有的。因此，我们将所有成员函数都创建为公共的，以便我们可以从驱动程序中访问它们，例如本例中的`Source.cpp`。头文件中的成员变量都是私有的，因为它们不应该直接从类外部访问。这就是我们所说的抽象。我们为名称和护甲定义了一个字符串类型的变量，为健康和年龄定义了一个整数类型的变量。即使我们目前没有为它们创建任何功能，也建议创建构造函数和析构函数。最好还使用一个复制构造函数。稍后在本章中会解释这个原因。

在`CEnemy`源文件中，我们对成员变量进行了初始化，并声明了函数。我们在每个函数的末尾使用了`const`关键字，因为我们不希望函数改变成员变量的内容。我们只希望它们返回已经分配的值。作为一个经验法则，除非有必要不使用它，我们应该总是使用它。这使得代码更安全、有组织和可读。我们在构造函数中初始化了变量；我们也可以创建参数化构造函数，并从驱动程序中分配值给它们。或者，我们也可以创建设置函数来分配值。

从驱动程序中，我们创建一个`CEnemy`类型的指针对象。当对象被初始化时，它调用适当的构造函数并将值分配给它们。然后我们通过使用`->`运算符对指针进行解引用来调用函数。因此，当我们调用`p->`函数时，它与(`*p`).function 相同。由于我们是动态分配内存，我们还应该删除对象，否则会出现内存泄漏。我们已经使用`vld`来检查内存泄漏。这个程序没有任何内存泄漏，因为我们使用了`delete`关键字。只需注释掉`delete pEnemy;`这一行，你会注意到程序在退出时有一些内存泄漏。

# 使用多态来重用代码

多态意味着具有多种形式。通常，当类的层次结构存在某种关联时，我们使用多态。我们通常通过使用继承来实现这种关联。

## 准备工作

你需要在 Windows 机器上安装 Visual Studio 的工作副本。

## 如何做…

在这个示例中，我们将看到如何使用相同的函数并根据需要覆盖它们的不同功能。此外，我们还将看到如何在基类和派生类之间共享值：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加一个名为 Source.cpp 的源文件和三个名为`Enemy.h`、`Dragon.h`和`Soldier.h`的头文件。

1.  将以下代码行添加到`Enemy.h`中：

```cpp
#ifndef _ENEMY_H
#define _ENEMY_H

#include <iostream>

using namespace std;

class CEnemy {
protected:
  int m_ihealth,m_iarmourValue;
public:
  CEnemy(int ihealth, int iarmourValue) : m_ihealth(ihealth), m_iarmourValue(iarmourValue) {}
  virtual int TotalHP(void) = 0;
  void PrintHealth()
  {
    cout << "Total health is " << this->TotalHP() << '\n';
  }
};

   #endif
```

1.  将以下代码行添加到`Dragon.h`中：

```cpp
#ifndef _DRAGON_H
#define _DRAGON_H

#include "Enemy.h"
#include <iostream>

using namespace std;

class CDragon : public CEnemy {
public:
  CDragon(int m_ihealth, int m_iarmourValue) : CEnemy(m_ihealth, m_iarmourValue)
  {
  }
  int TotalHP()
  {
    cout << "Dragon's ";
    return m_ihealth*2+3*m_iarmourValue;
  }
};

  #endif
```

1.  将以下代码行添加到`Soldier.h`中：

```cpp
#ifndef _SOLDIER_H
#define _SOLDIER_H

#include "Enemy.h"
#include <iostream>

using namespace std;

class CSoldier : public CEnemy {
public:
  CSoldier(int m_ihealth, int m_iarmourValue) : CEnemy(m_ihealth, m_iarmourValue) {}
  int TotalHP()
  {
    cout << "Soldier's ";
    return m_ihealth+m_iarmourValue;
  }
};

#endif
```

1.  将以下代码行添加到`Source.cpp`中：

```cpp
// dynamic allocation and polymorphism
#include <iostream>
#include <conio.h>
#include "vld.h"
#include "Enemy.h"
#include "Dragon.h"
#include "Soldier.h"

int main()
 {
  CEnemy* penemy1 = new CDragon(100, 50);
  CEnemy* penemy2 = new CSoldier(100, 100);

  penemy1->PrintHealth();
  penemy2->PrintHealth();

  delete penemy1;
  delete penemy2;

  _getch();
  return 0;

}
```

## 它是如何工作的…

多态是具有不同形式的能力。因此，在这个例子中，我们有一个`Enemy`接口，它没有任何用于计算总体健康的功能。然而，我们知道所有类型的敌人都应该有一个计算总体健康的功能。因此，我们通过将基类中的函数设置为纯虚函数（通过将其分配为`0`）来实现这个功能。

这使得所有子类都必须有自己的实现来计算总健康值。因此，`CSoldier`类和`CDragon`类都有自己的`TotalHP`实现。这种结构的优势在于，我们可以从基类创建子类的指针对象，并且在解析时，它调用子类的正确函数。

如果我们不创建虚函数，那么子类中的函数将隐藏基类的函数。然而，使用纯虚函数，这是不正确的，因为这将创建一个编译器错误。编译器在运行时解析函数的方式是通过一种称为动态分派的技术。大多数语言使用动态分派。C++使用单一转发动态分派。它借助虚拟表来实现。当`CEnemy`类定义虚函数`TotalHP`时，编译器向类添加一个隐藏的成员变量，该成员变量指向一个名为虚方法表（VMT）或 Vtable 的函数指针数组。在运行时，这些指针将被设置为指向正确的函数，因为在编译时还不知道是调用基函数还是由`CDragon`和`CSoldier`实现的派生函数。

基类中的成员变量是受保护的。这意味着派生类也可以访问成员变量。从驱动程序中，因为我们动态分配了内存，我们也应该删除，否则我们将会有内存泄漏。当析构函数标记为虚函数时，我们确保调用正确的析构函数。

# 使用复制构造函数

复制构造函数用于将一个对象复制到另一个对象。C++为我们提供了一个默认的复制构造函数，但不建议使用。我们应该为更好的编码和组织实践编写自己的复制构造函数。它还可以最小化使用 C++提供的默认复制构造函数可能引起的崩溃和错误。

## 准备工作

您需要在 Windows 机器上安装 Visual Studio 的工作副本。

## 如何做...

在这个示例中，我们将看到编写复制构造函数有多么容易：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加名为`Source.cpp`和`Terrain.h`的源文件。

1.  在`Terrain.h`中添加以下代码行：

```cpp
#pragma once
#include <iostream>

using namespace std;
class CTerrain
{
public:
  CTerrainCTerrain();
  ~CTerrain();

  CTerrain(const CTerrain &T)
  {
    cout << "\n Copy Constructor";
  }
  CTerrain& operator =(const CTerrain &T)
  {
    cout << "\n Assignment Operator";
    return *this;
  }
};
```

1.  在`Source.cpp`中添加以下代码行：

```cpp
#include <conio.h>
#include "Terrain.h"

using namespace std;

int main()
{
  CTerrain Terrain1,Terrain2;

  Terrain1 = Terrain2;

  CTerrain Terrain3 = Terrain1;

  _getch();
  return 0;
}
```

## 它是如何工作的...

在这个例子中，我们创建了自己的复制构造函数和赋值运算符。当我们给已经初始化的两个对象赋值时，赋值运算符被调用。当我们初始化一个对象并将其设置为另一个对象时，复制构造函数被调用。如果我们不创建自己的复制构造函数，新创建的对象只是持有被赋值对象的浅层引用。如果对象被销毁，那么浅层对象也会丢失，因为内存也会丢失。如果我们创建自己的复制构造函数，就会创建一个深层复制，即使第一个对象被删除，第二个对象仍然在不同的内存位置中保存信息。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_02_02.jpg)

因此，浅层复制（或成员逐一复制）将一个对象的成员变量的确切值复制到另一个对象中。两个对象中的指针最终指向相同的内存。深层复制将在自由存储器上分配的值复制到新分配的内存中。因此，在浅层删除中，浅层复制中的对象是灾难性的：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_02_03.jpg)

然而，深层复制为我们解决了这个问题：

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/4929_02_04.jpg)

# 使用运算符重载来重用运算符

C++为我们提供了许多运算符。但是，有时我们需要重载这些运算符，以便我们可以在自己创建的数据结构上使用它们。当然，我们也可以重载运算符以改变其含义。例如，我们可以将+（加号）改为行为像-（减号），但这并不推荐，因为这通常没有任何意义或帮助我们。此外，这可能会让使用相同代码库的其他程序员感到困惑。

## 准备工作

您需要在 Windows 机器上安装 Visual Studio 的工作副本。

## 如何做…

在这个示例中，我们将看到如何重载运算符以及在 C++中允许重载哪些运算符。

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加名为`Source.cpp`、`vector3.h`和`vector3.cpp`的源文件。

1.  将以下代码添加到`Source.cpp`：

```cpp
#include "vector3.h"
#include <conio.h>
#include "vld.h"

int main()
{
  // Vector tests:

  // Create two vectors.
  CVector3 a(1.0f, 2.0f, 3.0f);
  CVector3 b(1.0f, 2.0f, 3.0f);

  CVector3 c;

  // Zero Vector.
  c.Zero();

  // Addition.
  CVector3 d = a + b;

  // Subtraction.
  CVector3 e = a - b;

  //Scalar Multiplication.
  CVector3 f1 = a * 10;

  //Scalar Multiplication.
  CVector3 f2 = 10 * a;

  //Scalar Division.
  CVector3 g = a / 10;

  // Unary minus.
  CVector3 h = -a;

  // Relational Operators.
  bool bAEqualsB = (a == b);
  bool bANotEqualsB = (a != b);

  // Combined operations +=.
  c = a;
  c += a;

  // Combined operations -=.
  c = a;
  c -= a;

  // Combined operations /=.
  c = a;
  c /= 10;

  // Combined operations *=.
  c = a;
  c *= 10;

  // Normalization.
  c.Normalize();

  // Dot Product.
  float fADotB = a * b;

  // Magnitude.
  float fMag1 = CVector3::Magnitude(a);
  float fMag2 = CVector3::Magnitude(c);

  // Cross product.
  CVector3 crossProduct = CVector3::CrossProduct(a, c);

  // Distance.
  float distance = CVector3::Distance(a, c);

  _getch();
  return (0);

}
```

1.  将以下代码添加到`vector3.h`：

```cpp
#ifndef __VECTOR3_H__
#define __VECTOR3_H__

#include <cmath>

class CVector3
{
public:
  // Public representation: Not many options here.
  float x;
  float y;
  float z;

  CVector3();
  CVector3(const CVector3& _kr);
  CVector3(float _fx, float _fy, float _fz);

  // Assignment operator.
  CVector3& operator =(const CVector3& _kr);

  // Relational operators.
  bool operator ==(const CVector3& _kr) const;
  bool operator !=(const CVector3& _kr) const;

  // Vector operations
  void Zero();

  CVector3 operator -() const;
  CVector3 operator +(const CVector3& _kr) const;
  CVector3 operator -(const CVector3& _kr) const;

  // Multiplication and division by scalar.
  CVector3 operator *(float _f) const;
  CVector3 operator /(float _f) const;

  // Combined assignment operators to conform to C notation convention.
  CVector3& operator +=(const CVector3& _kr);
  CVector3& operator -=(const CVector3& _kr);
  CVector3& operator *=(float _f);
  CVector3& operator /=(float _f);

  // Normalize the vector
  void Normalize();
  // Vector dot product.
  // We overload the standard multiplication symbol to do this.
  float operator *(const CVector3& _kr) const;

  // Static member functions.

  // Compute the magnitude of a vector.
  static inline float Magnitude(const CVector3& _kr)
  {
    return (sqrt(_kr.x * _kr.x + _kr.y * _kr.y + _kr.z * _kr.z));
  }

  // Compute the cross product of two vectors.
  static inline CVector3 CrossProduct(const CVector3& _krA,
    const CVector3& _krB)
  {
    return
      (
      CVector3(_krA.y * _krB.z - _krA.z * _krB.y,
      _krA.z * _krB.x - _krA.x * _krB.z,
      _krA.x * _krB.y - _krA.y * _krB.x)
      );
  }

  // Compute the distance between two points.
  static inline float Distance(const CVector3& _krA, const CVector3& _krB)
  {
    float fdx = _krA.x - _krB.x;
    float fdy = _krA.y - _krB.y;
    float fdz = _krA.z - _krB.z;

    return sqrt(fdx * fdx + fdy * fdy + fdz * fdz);
  }
};

// Scalar on the left multiplication, for symmetry.
inline CVector3 operator *(float _f, const CVector3& _kr)
{
  return (CVector3(_f * _kr.x, _f * _kr.y, _f * _kr.z));
}

#endif // __VECTOR3_H__
```

1.  将以下代码添加到`vector3.cpp`：

```cpp
#include "vector3.h"

// Default constructor leaves vector in an indeterminate state.
CVector3::CVector3()
{

}

// Copy constructor.
CVector3::CVector3(const CVector3& _kr)
: x(_kr.x)
, y(_kr.y)
, z(_kr.z)
{

}

// Construct given three values.
CVector3::CVector3(float _fx, float _fy, float _fz)
: x(_fx)
, y(_fy)
, z(_fz)
{

}

// Assignment operator, we adhere to C convention and return reference to the lvalue.
CVector3&
CVector3::operator =(const CVector3& _kr)
{
  x = _kr.x;
  y = _kr.y;
  z = _kr.z;

  return (*this);
}

// Equality operator.
bool
CVector3::operator ==(const CVector3&_kr) const
{
  return (x == _kr.x && y == _kr.y && z == _kr.z);
}

// Inequality operator.
bool
CVector3::operator !=(const CVector3& _kr) const
{
  return (x != _kr.x || y != _kr.y || z != _kr.z);
}

// Set the vector to zero.
void
CVector3::Zero()
{
  x = 0.0f;
  y = 0.0f;
  z = 0.0f;
}

// Unary minus returns the negative of the vector.
CVector3
CVector3::operator -() const
{
  return (CVector3(-x, -y, -z));
}

// Binary +, add vectors.
CVector3
CVector3::operator +(const CVector3& _kr) const
{
  return (CVector3(x + _kr.x, y + _kr.y, z + _kr.z));
}

// Binary –, subtract vectors.
CVector3
CVector3::operator -(const CVector3& _kr) const
{
  return (CVector3(x - _kr.x, y - _kr.y, z - _kr.z));
}

// Multiplication by scalar.
CVector3
CVector3::operator *(float _f) const
{
  return (CVector3(x * _f, y * _f, z * _f));
}

// Division by scalar.
// Precondition: _f must not be zero.
CVector3
CVector3::operator /(float _f) const
{
  // Warning: no check for divide by zero here.
  ASSERT(float fOneOverA = 1.0f / _f);

  return (CVector3(x * fOneOverA, y * fOneOverA, z * fOneOverA));
}

CVector3&
CVector3::operator +=(const CVector3& _kr)
{
  x += _kr.x;
  y += _kr.y;
  z += _kr.z;

  return (*this);
}

CVector3&
CVector3::operator -=(const CVector3& _kr)
{
  x -= _kr.x;
  y -= _kr.y;
  z -= _kr.z;

  return (*this);
}

CVector3&
CVector3::operator *=(float _f)
{
  x *= _f;
  y *= _f;
  z *= _f;

  return (*this);
}

CVector3&
CVector3::operator /=(float _f)
{
  float fOneOverA = ASSERT(1.0f / _f);

  x *= fOneOverA;
  y *= fOneOverA;
  z *= fOneOverA;

  return (*this);
}

void
CVector3::Normalize()
{
  float fMagSq = x * x + y * y + z * z;

  if (fMagSq > 0.0f)
  {
    // Check for divide-by-zero.
    float fOneOverMag = 1.0f / sqrt(fMagSq);

    x *= fOneOverMag;
    y *= fOneOverMag;
    z *= fOneOverMag;
  }
}

// Vector dot product.
//    We overload the standard multiplication symbol to do this.
float
CVector3::operator *(const CVector3& _kr) const
{
  return (x * _kr.x + y * _kr.y + z * _kr.z);
}
```

## 工作原理…

C++具有内置类型：int、char 和 float。每种类型都有许多内置运算符，如加法（+）和乘法（*）。C++还允许您将这些运算符添加到自己的类中。内置类型（int、float）上的运算符不能被重载。优先级顺序不能被改变。在重载运算符时要谨慎的原因有很多。目标是增加可用性和理解。在我们的示例中，我们已经重载了基本的乘法运算符，以便我们可以对我们创建的`vector3`对象进行加法、减法等操作。这非常方便，因为如果我们知道两个对象的位置向量，我们就可以在游戏中找到对象的距离。我们尽可能使用 const 函数。编译器将强制执行不修改对象的承诺。这可以是确保您的代码没有意外副作用的好方法。

所有接受向量的函数都接受向量的常量引用。我们必须记住，将参数按值传递给函数会调用构造函数。继承对于向量类并不是非常有用，因为我们知道`CVector3`是速度关键的。虚函数表会使类大小增加 25%，因此不建议使用。

此外，数据隐藏并没有太多意义，因为我们需要向量类的值。在 C++中可以重载一些运算符。C++不允许我们重载的运算符是：

```cpp
(Member Access or Dot operator),?: (Ternary or Conditional Operator),:: (Scope Resolution Operator),.* (Pointer-to-member Operator),sizeof (Object size Operator) and typeid (Object type Operator)
```

# 使用函数重载来重用函数

函数重载是 C++中的一个重要概念。有时，我们希望使用相同的函数名称，但有不同的函数来处理不同的数据类型或不同数量的类型。这是有用的，因为客户端可以根据自己的需求选择正确的函数。C++允许我们通过函数重载来实现这一点。

## 准备工作

对于这个示例，您需要一台安装有 Visual Studio 工作副本的 Windows 机器。

## 如何做…

在这个示例中，我们将学习如何重载函数：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加名为`main.cpp`、`Cspeed.h`和`Cspeed.cpp`的源文件。

1.  将以下代码添加到`main.cpp`：

```cpp
#include <iostream>
#include <conio.h>
#include "CSpeed.h"

using namespace std;

//This is not overloading as the function differs only
//in return type
/*int Add(float x, float y)
{
  return x + y;
}*/

int main()
{
  CSpeed speed;

  cout<<speed.AddSpeed(2.4f, 7.9f)<<endl;
  cout << speed.AddSpeed(4, 5)<<endl;
  cout << speed.AddSpeed(4, 9, 12)<<endl;

  _getch();
  return 0;
}
```

1.  将以下代码添加到`CSpeed.cpp`：

```cpp
#include "CSpeed.h"

CSpeed::CSpeed()
{

}

CSpeed::~CSpeed()
{

}
int CSpeed::AddSpeed(int x, int y, int z)
{
  return x + y + z;
}
int CSpeed::AddSpeed(int x, int y)
{
  return x + y;
}
float CSpeed::AddSpeed(float x, float y)
{
  return x + y;
}
```

1.  将以下代码添加到`CSpeed.h`：

```cpp
#ifndef _VELOCITY_H
#define _VELOCITY_H

class CSpeed
{
public:
  int AddSpeed(int x, int y, int z);
  int AddSpeed(int x, int y);
  float AddSpeed(float x, float y);

  CSpeed();
  ~CSpeed();
private:

};

#endif
```

## 工作原理…

函数重载是一种函数多态的类型。函数只能通过参数列表中的参数数量和参数类型进行重载。函数不能仅通过返回类型进行重载。

我们已经创建了一个类来计算速度的总和。我们可以使用该函数来添加两个速度、三个速度或不同数据类型的速度。编译器将根据签名解析要调用的函数。有人可能会认为我们可以创建不同速度的不同对象，然后使用运算符重载来添加它们，或者使用模板编写一个模板函数。然而，我们必须记住，在简单的模板中，实现将保持不变，但在函数重载中，我们也可以更改每个函数的实现。

# 使用文件进行输入和输出

文件对于保存本地数据非常有用，这样我们可以在程序下次运行时检索数据，或者在程序退出后分析数据。对于我们在代码中创建并填充值的所有数据结构，除非我们将它们保存在本地或服务器/云端，否则这些值在应用程序退出后将丢失。文件用于包含保存的数据。我们可以创建文本文件、二进制文件，甚至具有我们自己加密的文件。当我们想要记录错误或生成崩溃报告时，文件非常方便。

## 准备就绪

对于这个食谱，您需要一台装有 Visual Studio 的 Windows 机器。

## 如何做...

在这个食谱中，我们将了解如何在 C++中使用文件处理操作来读取或写入文本文件。我们甚至可以使用 C++操作来创建二进制文件。

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加名为`Source.cpp`、`File.h`和`File.cpp`的源文件。

1.  将以下代码添加到`Source.cpp`中：

```cpp
#include <conio.h>
#include "File.h"

int main() {

  CFile file;

  file.WriteNewFile("Example.txt");
  file.WriteNewFile("Example.txt", "Logging text1");
  file.AppendFile("Example.txt", "Logging text2");
  file.ReadFile("Example.txt");

  _getch();
  return 0;
}
```

1.  将以下代码添加到`File.cpp`中：

```cpp
#include "File.h"
#include <string>
#include <fstream>
#include <iostream>

using namespace std;

CFile::CFile()
{
  Text = "This is the initial data";
}
CFile::~CFile()
{

}
void CFile::WriteNewFile(string Filename)const
{
  ofstream myfile(Filename);
  if (myfile.is_open())
  {
    myfile << Text;

    myfile.close();
  }
  else cout << "Unable to open file";
}
void CFile::WriteNewFile(string Filename,string Text)const
{
  ofstream myfile(Filename);
  if (myfile.is_open())
  {
    myfile << Text;

    myfile.close();
  }
  else cout << "Unable to open file";
}

void CFile::AppendFile(string Filename, string Text)const
{
  ofstream outfile;

  outfile.open(Filename, ios_base::app);
  outfile << Text;
       outfile.close();

}
void CFile::ReadFile(string Filename)const
{
  string line;
  ifstream myfile(Filename);
  if (myfile.is_open())
  {
    while (getline(myfile, line))
    {
      cout << line << '\n';
    }
    myfile.close();
  }

  else cout << "Unable to open file";
}
```

1.  将以下代码添加到`File.h`中：

```cpp
#ifndef _FILE_H
#define _FILE_H

#include <iostream>
#include <string.h>
using namespace std;

class CFile
{
public:
  CFile();
  ~CFile();

  void WriteNewFile(string Filename)const;
  void WriteNewFile(string Filename, string Text)const;
  void AppendFile(string Filename, string Text)const;
  void ReadFile(string Filename)const;
private:

  string Text;
};
#endif
```

## 它是如何工作的...

我们使用文件处理有各种原因。其中一些最重要的原因是在游戏运行时记录数据、从文本文件中加载数据以在游戏中使用，或者加密保存数据或加载游戏数据。

我们已经创建了一个名为`CFile`的类。这个类帮助我们向新文件写入数据，向文件追加数据，并从文件中读取数据。我们使用`fstream`头文件来加载所有文件处理操作。

文件中的所有内容都是以流的形式写入和读取的。在进行 C++编程时，我们必须使用流插入运算符(`<<`)从程序中向文件写入信息，就像我们使用该运算符向屏幕输出信息一样。唯一的区别是，您使用`ofstream`或`fstream`对象，而不是`cout`对象。

我们已经创建了一个构造函数，用于在没有任何数据的情况下创建文件时包含初始数据。如果我们只是创建或写入文件，每次都会创建一个新文件，并带有新数据。如果我们只想写入最近更新或最新的数据，这有时是有用的。但是，如果我们想向现有文件添加数据，我们可以使用`append`函数。追加函数从最后的文件位置指针位置开始向现有文件写入。

读取函数开始从文件中读取数据，直到达到最后一行写入的数据。我们可以将结果显示到屏幕上，或者如果需要，然后将内容写入另一个文件。我们还必须记住在每次操作后关闭文件，否则可能会导致代码的歧义。我们还可以使用`seekp`和`seekg`函数来重新定位文件位置指针。

# 创建你的第一个简单游戏

创建一个简单的基于文本的游戏非常容易。我们所需要做的就是创建一些规则和逻辑，我们就会有一个游戏。当然，随着游戏变得更加复杂，我们需要添加更多的函数。当游戏达到一个点，其中有多个对象和敌人的行为和状态时，我们应该使用类和继承来实现所需的结果。

## 准备就绪

要完成这个示例，您需要一台运行 Windows 的机器。您还需要在 Windows 机器上安装一个可用的 Visual Studio 副本。不需要其他先决条件。

## 如何做...

在这个示例中，我们将学习如何创建一个简单的基于运气的抽奖游戏：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加一个`Source.cpp`文件。

1.  将以下代码添加到其中：

```cpp
#include <iostream>
#include <cstdlib>
#include <ctime>

int main(void) {
  srand(time(NULL)); // To not have the same numbers over and over again.

  while (true) { // Main loop.
    // Initialize and allocate.
    int inumber = rand() % 100 + 1 // System number is stored in here.
    int iguess; // User guess is stored in here.
    int itries = 0; // Number of tries is stored here.
    char canswer; // User answer to question is stored here.

    while (true) { // Get user number loop.
      // Get number.
      std::cout << "Enter a number between 1 and 100 (" << 20 - itries << " tries left): ";
      std::cin >> iguess;
      std::cin.ignore();

      // Check is tries are taken up.
      if (itries >= 20) {
        break;
      }

      // Check number.
      if (iguess > inumber) {
        std::cout << "Too high! Try again.\n";
      }
      else if (iguess < inumber) {
        std::cout << "Too low! Try again.\n";
      }
      else {
        break;
      }

      // If not number, increment tries.
      itries++;
    }

    // Check for tries.
    if (itries >= 20) {
      std::cout << "You ran out of tries!\n\n";
    }
    else {
      // Or, user won.
      std::cout << "Congratulations!! " << std::endl;
      std::cout << "You got the right number in " << itries << " tries!\n";
    }

    while (true) { // Loop to ask user is he/she would like to play again.
      // Get user response.
      std::cout << "Would you like to play again (Y/N)? ";
      std::cin >> canswer;
      std::cin.ignore();

      // Check if proper response.
      if (canswer == 'n' || canswer == 'N' || canswer == 'y' || canswer == 'Y') {
        break;
      }
      else {
        std::cout << "Please enter \'Y\' or \'N\'...\n";
      }
    }

    // Check user's input and run again or exit;
    if (canswer == 'n' || canswer == 'N') {
      std::cout << "Thank you for playing!";
      break;
    }
    else {
      std::cout << "\n\n\n";
    }
  }

  // Safely exit.
  std::cout << "\n\nEnter anything to exit. . . ";
  std::cin.ignore();
  return 0;
}
```

## 它是如何工作的...

游戏的工作原理是创建一个从 1 到 100 的随机数，并要求用户猜测该数字。会提供提示，告诉用户猜测的数字是高于还是低于实际数字。用户只有 20 次机会来猜测数字。我们首先需要一个伪随机数生成器，基于它我们将生成一个随机数。在这种情况下，伪随机数生成器是`srand`。我们选择了时间作为生成随机范围的值。

我们需要在一个无限循环中执行程序，这样程序只有在所有尝试用完或用户正确猜出数字时才会中断。我们可以为尝试设置一个变量，并为用户每次猜测增加一个。随机数由 rand 函数生成。我们使用`rand%100+1`，这样随机数就在 1 到 100 的范围内。我们要求用户输入猜测的数字，然后我们检查该数字是小于、大于还是等于随机生成的数字。然后显示正确的消息。如果用户猜对了，或者所有尝试都已经用完，程序应该跳出主循环。在这一点上，我们询问用户是否想再玩一次游戏。

然后，根据答案，我们重新进入主循环，并开始选择一个随机数的过程。

# 模板-何时使用它们

模板是 C++编程的一种方式，为编写泛型程序奠定基础。使用模板，我们可以以独立于任何特定数据类型的方式编写代码。我们可以使用函数模板或类模板。

## 准备工作

对于这个示例，您需要一台安装有 Visual Studio 的 Windows 机器。

## 如何做...

在这个示例中，我们将了解模板的重要性，如何使用它们以及使用它们提供给我们的优势。

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  添加名为`Source.cpp`和`Stack.h`的源文件。

1.  将以下代码添加到`Source.cpp`中：

```cpp
#include <iostream>
#include <conio.h>
#include <string>
#include "Stack.h"

using namespace std;

template<class T>
void Print(T array[], int array_size)
{
  for (int nIndex = 0; nIndex < array_size; ++nIndex)
  {  
    cout << array[nIndex] << "\t";
  }
  cout << endl;
}

int main()
{
  int iArray[5] = { 4, 5, 6, 6, 7 };
  char cArray[3] = { 's', 's', 'b' };
  string sArray[3] = { "Kratos", "Dr.Evil", "Mario" };

  //Printing any type of elements
  Print(iArray, sizeof(iArray) / sizeof(*iArray));
  Print(cArray, sizeof(cArray) / sizeof(*cArray));
  Print(sArray, sizeof(sArray) / sizeof(*sArray));

  Stack<int> iStack;

  //Pushes an element to the bottom of the stack
  iStack.push(7);

  cout << iStack.top() << endl;

  for (int i = 0; i < 10; i++)
  {
    iStack.push(i);
  }

  //Removes an element from the top of the stack
  iStack.pop();

  //Prints the top of stack
  cout << iStack.top() << endl;

  _getch();
}
```

1.  将以下代码添加到`Stack.h`中：

```cpp
#include <vector>

using namespace std;

template <class T>
class Stack {
private:
  vector<T> elements;     // elements

public:
  void push(T const&);  // push element
  void pop();               // pop element
  T top() const;            // return top element
  bool empty() const{       // return true if empty.
    return elements.empty();
  }
};

template <class T>
void Stack<T>::push(T const& elem)
{
  // append copy of passed element
  elements.push_back(elem);
}

template <class T>
void Stack<T>::pop()
{
  if (elements.empty()) {
    throw out_of_range("Stack<>::pop(): empty stack");
  }
  // remove last element
  elements.pop_back();
}

template <class T>
T Stack<T>::top() const
{
  if (elements.empty()) {
    throw out_of_range("Stack<>::top(): empty stack");
  }
  // return copy of last element
  return elements.back();
}
```

## 它是如何工作的...

模板是 C++中泛型编程的基础。如果函数或类的实现相同，但我们需要它们操作不同的数据类型，建议使用模板而不是编写新的类或函数。有人可能会说我们可以重载一个函数来实现相同的功能，但请记住，当重载一个函数时，我们可以根据数据类型改变实现，而且我们仍然在编写一个新的函数。使用模板，实现必须对所有数据类型都相同。这就是模板的优势：编写一个函数就足够了。使用高级模板和 C++11 特性，我们甚至可以改变实现，但我们将把这个讨论留到以后。

在这个示例中，我们使用了函数模板和类模板。函数模板是在`Source.cpp`中定义的。在`print`函数的顶部，我们添加了模板`<class T>`。`关键字`类也可以被`typename`替换。两个关键字的原因是历史性的，我们不需要在这里讨论。函数定义的其余部分是正常的，只是我们使用了`T`代替了特定的数据类型。所以当我们从主函数调用函数时，`T`会被正确的数据类型替换。通过这种方式，只需使用一个函数，我们就可以打印所有数据类型。我们甚至可以创建自己的数据类型并将其传递给函数。

`Stack.h` 是一个类模板的示例，因为类使用的数据类型是通用的。我们选择了堆栈，因为它是游戏编程中非常流行的数据结构。它是一个**LIFO**（**后进先出**）结构，因此我们可以根据我们的需求显示堆栈中的最新内容。push 函数将一个元素推入堆栈，而 pop 函数将一个元素从堆栈中移除。top 函数显示堆栈中的顶部元素，empty 函数清空堆栈。通过使用这个通用的堆栈类，我们可以存储和显示我们选择的数据类型。

在使用模板时需要记住的一件事是，编译器必须在编译时知道模板的正确实现，因此通常模板的定义和声明都在头文件中完成。然而，如果你想将两者分开，可以使用两种流行的方法。一种方法是使用另一个头文件，并在其末尾列出实现。另一种方法是创建一个`.ipp`或`.tpp`文件扩展名，并在这些文件中进行实现。


# 第三章：游戏开发中的数据结构

在本章中，将涵盖以下示例：

+   使用更高级的数据结构

+   使用链表存储数据

+   使用栈存储数据

+   使用队列存储数据

+   使用树存储数据

+   使用图形存储数据

+   使用 STL 列表存储数据

+   使用 STL 映射存储数据

+   使用 STL 哈希表存储数据

# 介绍

数据结构在视频游戏行业中用于将代码组织得更加清晰和易于管理。一个普通的视频游戏至少会有大约 2 万行代码。如果我们不使用有效的存储系统和结构来管理这些代码，调试将变得非常困难。此外，我们可能会多次编写相同的代码。

如果我们有一个大型数据集，数据结构对于搜索元素也非常有用。假设我们正在制作一个大型多人在线游戏。从成千上万在线玩游戏的玩家中，我们需要找出在某一天得分最高的玩家。如果我们没有将用户数据组织成有意义的数据结构，这可能需要很长时间。另一方面，使用合适的数据结构可以帮助我们在几秒钟内实现这一目标。

# 使用更高级的数据结构

在这个示例中，我们将看到如何使用更高级的数据结构。程序员的主要任务是根据需要选择正确的数据结构，以便最大限度地减少存储和解析数据所需的时间。有时，选择正确的数据结构比选择适当的算法更重要。

## 准备工作

要完成这个示例，您需要一台运行 Windows 的计算机。您还需要在 Windows 计算机上安装一个可用的 Visual Studio 副本。不需要其他先决条件。

## 操作步骤...

在这个示例中，我们将看到使用高级数据结构是多么容易，以及为什么我们应该使用它们。如果我们将数据组织成合适的结构，访问数据会更快，也更容易对其应用复杂的算法。

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加名为`Source.cpp`、`LinkedList.h`/`LinkedList.cpp`和`HashTables.h`/`HashTables.cpp`的源文件。

1.  将以下代码添加到`Source.cpp`中：

```cpp
#include "HashTable.h"
#include <conio.h>

int main()
{
  // Create 26 Items to store in the Hash Table.
  Item * A = new Item{ "Enemy1", NULL };
  Item * B = new Item{ "Enemy2", NULL };
  Item * C = new Item{ "Enemy3", NULL };
  Item * D = new Item{ "Enemy4", NULL };
  Item * E = new Item{ "Enemy5", NULL };
  Item * F = new Item{ "Enemy6", NULL };
  Item * G = new Item{ "Enemy7", NULL };
  Item * H = new Item{ "Enemy8", NULL };
  Item * I = new Item{ "Enemy9", NULL };
  Item * J = new Item{ "Enemy10", NULL };
  Item * K = new Item{ "Enemy11", NULL };
  Item * L = new Item{ "Enemy12", NULL };
  Item * M = new Item{ "Enemy13", NULL };
  Item * N = new Item{ "Enemy14", NULL };
  Item * O = new Item{ "Enemy15", NULL };
  Item * P = new Item{ "Enemy16", NULL };
  Item * Q = new Item{ "Enemy17", NULL };
  Item * R = new Item{ "Enemy18", NULL };
  Item * S = new Item{ "Enemy19", NULL };
  Item * T = new Item{ "Enemy20", NULL };
  Item * U = new Item{ "Enemy21", NULL };
  Item * V = new Item{ "Enemy22", NULL };
  Item * W = new Item{ "Enemy23", NULL };
  Item * X = new Item{ "Enemy24", NULL };
  Item * Y = new Item{ "Enemy25", NULL };
  Item * Z = new Item{ "Enemy26", NULL };

  // Create a Hash Table of 13 Linked List elements.
  HashTable table;

  // Add 3 Items to Hash Table.
  table.insertItem(A);
  table.insertItem(B);
  table.insertItem(C);
  table.printTable();

  // Remove one item from Hash Table.
  table.removeItem("Enemy3");
  table.printTable();

  // Add 23 items to Hash Table.
  table.insertItem(D);
  table.insertItem(E);
  table.insertItem(F);
  table.insertItem(G);
  table.insertItem(H);
  table.insertItem(I);
  table.insertItem(J);
  table.insertItem(K);
  table.insertItem(L);
  table.insertItem(M);
  table.insertItem(N);
  table.insertItem(O);
  table.insertItem(P);
  table.insertItem(Q);
  table.insertItem(R);
  table.insertItem(S);
  table.insertItem(T);
  table.insertItem(U);
  table.insertItem(V);
  table.insertItem(W);
  table.insertItem(X);
  table.insertItem(Y);
  table.insertItem(Z);
  table.printTable();

  // Look up an item in the hash table
  Item * result = table.getItemByKey("Enemy4");
  if (result!=nullptr)
  cout << endl<<"The next key is "<<result->next->key << endl;

  _getch();
  return 0;
}
```

1.  将以下代码添加到`LinkedList.h`中：

```cpp
#ifndef LinkedList_h
#define LinkedList_h

#include <iostream>
#include <string>
using namespace std;

//*****************************************************************
// List items are keys with pointers to the next item.
//*****************************************************************
struct Item
{
  string key;
  Item * next;
};

//*****************************************************************
// Linked lists store a variable number of items.
//*****************************************************************
class LinkedList
{
private:
  // Head is a reference to a list of data nodes.
  Item * head;

  // Length is the number of data nodes.
  int length;

public:
  // Constructs the empty linked list object.
  // Creates the head node and sets length to zero.
  LinkedList();

  // Inserts an item at the end of the list.
  void insertItem(Item * newItem);

  // Removes an item from the list by item key.
  // Returns true if the operation is successful.
  bool removeItem(string itemKey);

  // Searches for an item by its key.
  // Returns a reference to first match.
  // Returns a NULL pointer if no match is found.
  Item * getItem(string itemKey);

  // Displays list contents to the console window.
  void printList();

  // Returns the length of the list.
  int getLength();

  // De-allocates list memory when the program terminates.
  ~LinkedList();
};

#endif
```

1.  将以下代码添加到`LinkedList.cpp`中：

```cpp
#include "LinkedList.h"

// Constructs the empty linked list object.
// Creates the head node and sets length to zero.
LinkedList::LinkedList()
{
  head = new Item;
  head->next = NULL;
  length = 0;
}

// Inserts an item at the end of the list.
void LinkedList::insertItem(Item * newItem)
{
  if (!head->next)
  {
    head->next = newItem;
newItem->next=NULL;
    length++;
    return;
  }
//Can be reduced to fewer lines of codes.
//Using 2 variables p and q to make it more clear
  Item * p = head->next;
  Item * q = p->next;
  while (q)
  {
    p = q;
    q = p->next;
  }
  p->next = newItem;
  newItem->next = NULL;
  length++;
}

// Removes an item from the list by item key.
// Returns true if the operation is successful.
bool LinkedList::removeItem(string itemKey)
{
  if (!head->next) return false;
  Item * p = head;
  Item * q = head->next;
  while (q)
  {
    if (q->key == itemKey)
    {
      p->next = q->next;
      delete q;
      length--;
      return true;
    }
    p = q;
    q = p->next;
  }
  return false;
}

// Searches for an item by its key.
// Returns a reference to first match.
// Returns a NULL pointer if no match is found.
Item * LinkedList::getItem(string itemKey)
{
  Item * p = head;
  Item * q = p->next;
  while (q)
  {

if (q->key == itemKey))
  {  
return p;
  }
p = q;  
q = p->next;
  }
  return NULL;
}

// Displays list contents to the console window.
void LinkedList::printList()
{
  if (length == 0)
  {
    cout << "\n{ }\n";
    return;
  }
  Item * p = head;
  Item * q = p->next;
  cout << "\n{ ";
  while (q)
  {
    p = q;
    if (p != head)
    {
      cout << p->key;
      if (q->next) cout << ", ";
      else cout << " ";
    }
    q = p->next;
  }
  cout << "}\n";
}

// Returns the length of the list.
int LinkedList::getLength()
{
  return length;
}

// De-allocates list memory when the program terminates.
LinkedList::~LinkedList()
{
  Item * p = head;
  Item * q = head;
  while (q)
  {
    p = q;
    q = p->next;
    if (q) 
  }
delete p;
}
```

1.  将以下代码添加到`HashTable.cpp`中：

```cpp
#include "HashTable.h"

// Constructs the empty Hash Table object.
// Array length is set to 13 by default.
HashTable::HashTable(int tableLength)
{
  if (tableLength <= 0) tableLength = 13;
  array = new LinkedList[tableLength];
  length = tableLength;
}

// Returns an array location for a given item key.
int HashTable::hash(string itemKey)
{
  int value = 0;
  for (int i = 0; i < itemKey.length(); i++)
    value += itemKey[i];
  return (value * itemKey.length()) % length;
}

// Adds an item to the Hash Table.
void HashTable::insertItem(Item * newItem)
{
If(newItem)
{
  int index = hash(newItem->key);
  array[index].insertItem(newItem);
}
}

// Deletes an Item by key from the Hash Table.
// Returns true if the operation is successful.
bool HashTable::removeItem(string itemKey)
{
  int index = hash(itemKey);
  return array[index].removeItem(itemKey);
}

// Returns an item from the Hash Table by key.
// If the item isn't found, a null pointer is returned.
Item * HashTable::getItemByKey(string itemKey)
{
  int index = hash(itemKey);
  return array[index].getItem(itemKey);
}

// Display the contents of the Hash Table to console window.
void HashTable::printTable()
{
  cout << "\n\nHash Table:\n";
  for (int i = 0; i < length; i++)
  {
    cout << "Bucket " << i + 1 << ": ";
    array[i].printList();
  }
}

// Returns the number of locations in the Hash Table.
int HashTable::getLength()
{
  return length;
}

// Returns the number of Items in the Hash Table.
int HashTable::getNumberOfItems()
{
  int itemCount = 0;
  for (int i = 0; i < length; i++)
  {
    itemCount += array[i].getLength();
  }
  return itemCount;
}

// De-allocates all memory used for the Hash Table.
HashTable::~HashTable()
{
  delete[] array;
}
```

1.  将以下代码添加到`HashTables.h`中：

```cpp
#ifndef HashTable_h
#define HashTable_h

#include "LinkedList.h"

//*****************************************************************
// Hash Table objects store a fixed number of Linked Lists.
//*****************************************************************
class HashTable
{
private:

  // Array is a reference to an array of Linked Lists.
  LinkedList * array;

  // Length is the size of the Hash Table array.
  int length;

  // Returns an array location for a given item key.
  int hash(string itemKey);

public:

  // Constructs the empty Hash Table object.
  // Array length is set to 13 by default.
  HashTable(int tableLength = 13);

  // Adds an item to the Hash Table.
  void insertItem(Item * newItem);

  // Deletes an Item by key from the Hash Table.
  // Returns true if the operation is successful.
  bool removeItem(string itemKey);

  // Returns an item from the Hash Table by key.
  // If the item isn't found, a null pointer is returned.
  Item * getItemByKey(string itemKey);

  // Display the contents of the Hash Table to console window.
  void printTable();

  // Returns the number of locations in the Hash Table.
  int getLength();

  // Returns the number of Items in the Hash Table.
  int getNumberOfItems();

  // De-allocates all memory used for the Hash Table.
  ~HashTable();
};

#endif
```

## 它是如何工作的...

我们创建了这个类来使用哈希表存储不同的敌人，然后使用键从哈希表中搜索特定的敌人。而哈希表则是使用链表创建的。

在`LINKEDLIST`文件中，我们定义了一个结构来存储哈希表中的键和指向下一个值的指针。主类包含了一个名为`ITEM`的结构的指针引用。除此之外，该类还包含了数据的长度和用于插入项、删除项、查找元素、显示整个列表以及查找列表长度的成员函数。

在`HASHTABLE`文件中，使用链表创建了一个哈希表。创建了一个链表的引用，以及哈希表数组的长度和一个返回哈希表数组中特定项的数组位置的私有函数。除此之外，哈希表具有与链表类似的功能，如插入项、删除项和显示哈希表。

从驱动程序中，创建一个结构的对象来初始化要推送到哈希表中的项。然后创建一个哈希表的对象，并将项推送到表中并显示。还可以从表中删除一个项。最后，搜索一个名为`Enemy4`的特定项并显示下一个键。

# 使用链表存储数据

在这个示例中，我们将看到如何使用链表来存储和组织数据。链表在游戏行业的主要优势是它是一种动态数据结构。然而，它不适合搜索和插入元素，因为您需要找到信息。搜索是*O(n)*。这意味着我们可以在运行时为这种数据结构分配内存。在游戏中，大多数东西都是在运行时创建、销毁和更新的，因此使用链表非常合适。链表还可以用于创建堆栈和队列等线性数据结构，在游戏编程中同样重要。

## 准备工作

您需要在 Windows 机器上安装一个可用的 Visual Studio 副本。

## 如何做到...

在这个示例中，我们将看到使用链表是多么容易。链表是存储数据的好方法，并且被用作其他数据结构的基本机制：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加一个名为`Source.cpp`的源文件。

1.  将以下代码添加到其中：

```cpp
#include <iostream>
#include <conio.h>

using namespace std;

typedef struct LinkedList {
  int LevelNumber;
  LinkedList * next;
} LinkedList;

int main() {
  LinkedList * head = NULL;
  int i;
  for (i = 1; i <= 10; i++) {
    LinkedList * currentNode = new LinkedList;
    currentNode->LevelNumber = i;
    currentNode->next = head;
    head = currentNode;
  }
  while (head) {
    cout << head->LevelNumber << " ";
    head = head->next;
  }
delete head;
  _getch();
  return 0;
}
```

## 它是如何工作的...

链表用于创建存储数据和包含下一个节点地址的字段的数据结构。链表由节点组成。

![它是如何工作的...](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/B04929_03_01.jpg)

在我们的例子中，我们使用结构创建了一个链表，并使用迭代来填充链表。如前所述，链表的主要概念是它包含某种数据，并包含下一个节点的地址信息。在我们的例子中，我们创建了一个链表来存储当前级别的编号和下一个要加载的级别的地址。这种结构对于存储我们想要加载的级别非常重要。通过遍历链表，我们可以按正确的顺序加载级别。甚至游戏中的检查点也可以以类似的方式编程。

# 使用堆栈存储数据

堆栈是 C++中线性数据结构的一个例子。在这种类型的数据结构中，数据输入的顺序非常重要。最后输入的数据是要删除的第一条数据。这就是为什么有时也称为**后进先出**（**LIFO**）数据结构。将数据输入堆栈的过程称为**push**，删除数据的过程称为**pop**。有时我们只想打印堆栈顶部的值，而不删除或弹出。堆栈在游戏行业的各个领域都有用，尤其是在为游戏创建 UI 系统时。

## 准备工作

您需要在 Windows 机器上安装一个可用的 Visual Studio 副本。

## 如何做到...

在这个示例中，我们将发现使用堆栈数据结构是多么容易。堆栈是最容易实现的数据结构之一，并且在多个领域中使用：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加一个名为`Source.cpp`的源文件。

1.  将以下代码添加到其中：

```cpp
#include <iostream>
#include <conio.h>
#include <string>

using namespace std;

class Stack
{
private:
  string UI_Elements[10];
  int top;
public:
  Stack()
  {
    top = -1;
  }

  void Push(string element)
  {
    if (top >= 10)
    {
      cout << "Some error occurred";
    }
    UI_Elements[++top] = element;
  }

  string Pop()
  {
    if (top == -1)
    {
      cout << "Some error occurred";
    }
    return UI_Elements[top--];
  }

  string Top()
  {
    return UI_Elements[top];
  }

  int Size()
  {
    return top + 1;
  }

  bool isEmpty()
  {
    return (top == -1) ? true : false;
  }
};

int main()
{
    Stack _stack;

    if (_stack.isEmpty())
    {
      cout << "Stack is empty" << endl;
    }
    // Push elements    
    _stack.Push("UI_Element1");
    _stack.Push("UI_Element2");
    // Size of stack
    cout << "Size of stack = " << _stack.Size() << endl;
    // Top element    
    cout << _stack.Top() << endl;
    // Pop element    
    cout << _stack.Pop() << endl;
    // Top element    
    cout << _stack.Top() << endl;

    _getch();
    return 0;
  }
```

## 它是如何工作的...

在这个例子中，我们使用`STACK`数据结构将各种 UI 元素推入堆栈。`STACK`本身是通过数组创建的。在推入元素时，我们需要检查堆栈是否为空或已经存在一些元素。在弹出元素时，我们需要删除堆栈顶部的元素，并相应地更改指针地址。在打印堆栈的 UI 元素时，我们遍历整个堆栈，并从顶部显示它们。让我们考虑一个具有以下级别的游戏：主菜单、章节选择、级别选择和游戏开始。当我们想退出游戏时，我们希望用户以相反的顺序选择级别。因此，第一个级别应该是游戏开始（暂停状态），然后是级别选择、章节选择，最后是主菜单。这可以很容易地通过堆栈来实现，就像前面的例子中所解释的那样。

# 使用队列存储数据

队列是动态数据结构的一个例子。这意味着队列的大小可以在运行时改变。这在编程游戏时是一个巨大的优势。队列从数据结构的后面进行入队/插入操作，从数据结构的前面进行出队/删除/推出操作。这使它成为一个**先进先出**（**FIFO**）的数据结构。想象一下，在游戏中，我们有一个库存，但我们希望玩家使用他拿起的第一个物品，除非他手动切换到另一个物品。这可以很容易地通过队列实现。如果我们想设计成当前物品切换到库存中最强大的物品，我们可以使用优先队列来实现这个目的。

## 准备工作

对于这个教程，你需要一台装有 Visual Studio 的 Windows 机器。

## 如何做…

在这个教程中，我们将使用链表来实现队列数据结构。实现队列非常容易，它是一个非常健壮的数据结构：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加一个名为`Source.cpp`的源文件。

1.  向其中添加以下代码行：

```cpp
#include <iostream>
#include <queue>
#include <string>
#include <conio.h>

using namespace std;

int main()
{
  queue <string> gunInventory;
  gunInventory.push("AK-47");
  gunInventory.push("BullPup");
  gunInventory.push("Carbine");

  cout << "This is your weapons inventory" << endl << endl;
  cout << "The first gun that you are using is "
    << gunInventory.front() << endl << endl;
  gunInventory.pop();
  cout << "There are currently " << gunInventory.size()
    << " more guns in your inventory. " << endl << endl
    << "The next gun in the inventory is "
    << gunInventory.front() << "." << endl << endl

    << gunInventory.back() << " is the last gun in the inventory."
    << endl;

  _getch();
  return 0;

}
```

## 它是如何工作的…

我们使用 STL 队列来创建队列结构，或者说使用队列结构。队列结构，正如我们所知，是在需要使用 FIFO 数据结构时非常重要的。就像在第一人称射击游戏中，我们可能希望用户使用他拿起的第一把枪，剩下的枪放在库存中。这是队列的一个理想案例，就像例子中解释的那样。队列结构的前端保存了拿起的第一把枪，或者当前的枪，剩下的枪按照拿起的顺序存储在库存中。有时候，在游戏中，我们希望如果拿起的枪比正在使用的更强大，它应该自动切换到那个枪。在这种情况下，我们可以使用一个更专门的队列形式，称为优先队列，我们只需要指定队列按照什么参数进行排序。

# 使用树来存储数据

树是非线性数据结构的一个例子，不像数组和链表是线性的。树经常用在需要层次结构的游戏中。想象一辆汽车有很多部件，所有部件都是功能的，可升级的，并且可以互动。在这种情况下，我们将使用树数据结构为汽车创建整个类。树使用父子关系在所有节点之间进行遍历。

## 准备工作

对于这个教程，你需要一台装有 Visual Studio 的 Windows 机器。

## 如何做…

在这个教程中，我们将实现一个二叉树。二叉树有很多变种。我们将创建最基本的二叉树。很容易向二叉树添加新的逻辑来实现平衡二叉树，AVL 树等等：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加一个名为`CTree.cpp`的源文件。

1.  向其中添加以下代码行：

```cpp
// Initialize the node with a value and pointers
// to left child
// and right child
struct node
{
  string data_value;
  node *left;
  node *right;
};

class Binary_Tree
{
public:
  Binary_Tree();
  ~Binary_Tree();

  void insert(string key);
  node *search(string key);
  void destroy_tree();

private:
  void destroy_tree(node *leaf);
  void insert(string key, node *leaf);
  node *search(string key, node *leaf);

  node *root;
};

Binary_Tree::Binary_Tree()
{
  root = NULL;
}

Binary_Tree::~Binary_Tree()
{
  destroy_tree();
}

void Binary_Tree::destroy_tree(node *leaf)
{
  if (leaf != NULL)
  {
    destroy_tree(leaf->left);
    destroy_tree(leaf->right);
    delete leaf;
  }
}

void Binary_Tree::insert(string key, node *leaf)
{
  if (key< leaf->key_value)
  {
    if (leaf->left != NULL)
      insert(key, leaf->left);
    else
    {
      leaf->left = new node;
      leaf->left->key_value = key;
      leaf->left->left = NULL;  
      leaf->left->right = NULL;  
    }
  }
  else if (key >= leaf->key_value)
  {
    if (leaf->right != NULL)
      insert(key, leaf->right);
    else
    {
      leaf->right = new node;
      leaf->right->key_value = key;
      leaf->right->left = NULL;
      leaf->right->right = NULL;
    }
  }
}

node *Binary_Tree::search(string key, node *leaf)
{
  if (leaf != NULL)
  {
    if (key == leaf->key_value)
      return leaf;
    if (key<leaf->key_value)
      return search(key, leaf->left);
    else
      return search(key, leaf->right);
  }
  else return NULL;
}

void Binary_Tree::insert(string key)
{
  if (root != NULL)
    insert(key, root);
  else
  {
    root = new node;
    root->key_value = key;
    root->left = NULL;
    root->right = NULL;
  }
}
node *Binary_Tree::search(string key)
{
  return search(key, root);
}

void Binary_Tree::destroy_tree()
{
  destroy_tree(root);
}
```

## 它是如何工作的…

我们使用一个结构来存储值和左孩子和右孩子的指针。没有特定的规则来决定哪些元素应该是左孩子，哪些元素应该是右孩子。如果我们愿意，我们可以决定所有低于根元素的元素都在左边，所有高于根元素的元素都在右边。

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/B04929_03_02.jpg)

树数据结构中的插入和删除都是以递归方式完成的。要插入元素，我们遍历树并检查它是否为空。如果为空，我们创建一个新节点，并通过递归方式添加所有相应的节点，通过检查新节点的值是大于还是小于根节点。搜索元素的方式也类似。如果要搜索的元素的值小于根节点，则我们可以忽略树的整个右侧部分，正如我们在`search`函数中所看到的，并继续递归搜索。这大大减少了搜索空间并优化了我们的算法。这意味着在运行时搜索项目将更快。假设我们正在创建一个需要实现程序化地形的游戏。在场景加载后，我们可以使用二叉树根据它们出现在左侧还是右侧来将整个级别划分为部分。如果这些信息在树中正确存储，那么游戏摄像机可以使用这些信息来决定哪个部分被渲染，哪个部分不被渲染。这也创建了一个很好的剔除优化级别。如果父级没有被渲染，我们可以忽略检查树的其余部分进行渲染。

# 使用图来存储数据

在这个教程中，我们将看到使用图数据结构存储数据是多么容易。如果我们必须创建一个像 Facebook 一样的系统来与朋友和朋友的朋友分享我们的游戏，图数据结构非常有用。图可以以几种方式实现。最常用的方法是使用边和节点。

## 准备工作

要完成这个教程，您需要一台运行 Windows 的机器。您还需要在 Windows 机器上安装一个可用的 Visual Studio 副本。不需要其他先决条件。

## 如何做…

在这个教程中，我们将看到如何实现图。图是一个非常好的数据结构，用于将各种状态和数据与边缘条件相互连接。任何社交网络算法都以某种方式使用图数据结构：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  选择**Win32 控制台应用程序**。

1.  添加`CGraph.h`/`CGraph.cpp`文件。

1.  将以下代码添加到`CGraph.h`：

```cpp
#include <iostream>
#include <vector>
#include <map>
#include <string>

using namespace std;

struct vertex
{
  typedef pair<int, vertex*> ve;
  vector<ve> adj; //cost of edge, destination vertex
  string name;
  vertex(string s)
  {
    name = s;
  }
};

class graph
{
public:
  typedef map<string, vertex *> vmap;
  vmap work;
  void addvertex(const string&);
  void addedge(const string& from, const string& to, double cost);
};
```

1.  将以下代码添加到`CGraph.cpp`：

```cpp
void graph::addvertex(const string &name)
{
  vmap::iterator itr = work.begin();
  itr = work.find(name);
  if (itr == work.end())
  {
    vertex *v;
    v = new vertex(name);
    work[name] = v;
    return;
  }
  cout << "\nVertex already exists!";
}

void graph::addedge(const string& from, const string& to, double cost)
{
  vertex *f = (work.find(from)->second);
  vertex *t = (work.find(to)->second);
  pair<int, vertex *> edge = make_pair(cost, t);
  f->adj.push_back(edge);
}
```

## 它是如何工作的…

图由边和节点组成。因此，在实现图数据结构时，首先要做的是创建一个结构来存储节点和顶点信息。下图有六个节点和七条边。要实现一个图，我们需要了解从一个节点到另一个节点的每条边的成本。这些被称为邻接成本。要插入一个节点，我们创建一个节点。要向节点添加边，我们需要提供有关需要连接的两个节点和边的成本的信息。

获取信息后，我们使用边的成本和其中一个节点创建一对，并将该边的信息推送到另一个节点：

![它是如何工作的…](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/cpp-gm-dev-cb/img/B04929_03_03.jpg)

# 使用 STL 列表来存储数据

STL 是一个标准模板库，其中包含许多基本数据结构的实现，这意味着我们可以直接用它们来实现我们的目的。列表在内部实现为双向链表，这意味着插入和删除可以在两端进行。

## 准备工作

对于这个教程，您需要一台安装有 Visual Studio 的 Windows 机器。

## 如何做…

在这个教程中，我们将看到如何使用 C++为我们提供的内置模板库来轻松创建复杂的数据结构。创建复杂的数据结构后，我们可以轻松地使用它来存储数据和访问数据：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  添加一个名为`Source.cpp`的源文件。

1.  将以下代码添加到其中：

```cpp
#include <iostream>
#include <list>
#include <conio.h>

using namespace std;

int main()
{
  list<int> possible_paths;
  possible_paths.push_back(1);
  possible_paths.push_back(1);
  possible_paths.push_back(8);
  possible_paths.push_back(9);
  possible_paths.push_back(7);
  possible_paths.push_back(8);
  possible_paths.push_back(2);
  possible_paths.push_back(3);
  possible_paths.push_back(3);

  possible_paths.sort();
  possible_paths.unique();

  for (list<int>::iterator list_iter = possible_paths.begin();
    list_iter != possible_paths.end(); list_iter++)
  {
    cout << *list_iter << endl;
  }

  _getch();
  return 0;

}
```

## 它是如何工作的…

我们已经使用列表将可能的路径成本值推送到某个 AI 玩家到达目的地的值中。我们使用了 STL 列表，它带有一些内置的函数，我们可以在容器上应用这些函数。我们使用`sort`函数按升序对列表进行排序。我们还有`unique`函数来删除列表中的所有重复值。在对列表进行排序后，我们得到了最小的路径成本，因此我们可以将该路径应用于 AI 玩家。尽管代码大小大大减小，编写起来更容易，但我们应该谨慎使用 STL，因为我们从来不确定内置函数背后的算法。例如，`sort`函数很可能使用快速排序，但我们不知道。

# 使用 STL 地图来存储数据

地图是 STL 的关联容器之一，它存储由键值和映射值组成的元素，遵循特定的顺序。地图是 C++为我们提供的 STL 的一部分。

## 准备就绪

对于这个示例，您需要一台安装有 Visual Studio 的 Windows 机器。

## 如何做…

在这个示例中，我们将看到如何使用 C++提供的内置模板库来创建复杂的数据结构。创建复杂的数据结构后，我们可以轻松地使用它来存储数据和访问数据：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  添加名为`Source.cpp`的源文件。

1.  将以下代码行添加到其中：

```cpp
#include <iostream>
#include <map>
#include <conio.h>

using namespace std;

int main()
{
  map <string, int> score_list;

  score_list["John"] = 242;
  score_list["Tim"] = 768;
  score_list["Sam"] = 34;

  if (score_list.find("Samuel") == score_list.end())
  {
    cout << "Samuel is not in the map!" << endl;
  }

  cout << score_list.begin()->second << endl;

  _getch();
  return 0;

}
```

## 它是如何工作的…

我们已经使用 STL 地图创建了一个键/值对，用于存储玩我们游戏的玩家的姓名和他们的高分。我们可以在地图中使用任何数据类型。在我们的示例中，我们使用了一个字符串和一个整数。创建数据结构后，非常容易找到玩家是否存在于数据库中，我们还可以对地图进行排序并显示与玩家关联的分数。第二个字段给出了值，而第一个字段给出了键。

# 使用 STL 哈希表来存储数据

地图和哈希表之间最大的区别在于，地图数据结构是有序的，而哈希表是无序的。两者都使用键/值对的相同原则。无序地图的最坏情况搜索复杂度为*O(N)*，因为它不像地图那样有序，地图的复杂度为*O(log N)*。

## 准备就绪

对于这个示例，您需要一台安装有 Visual Studio 的 Windows 机器。

## 如何做…

在这个示例中，我们将看到如何使用 C++为我们提供的内置模板库来创建复杂的数据结构。创建复杂的数据结构后，我们可以轻松地使用它来存储数据和访问数据：

1.  打开 Visual Studio。

1.  创建一个新的 C++项目。

1.  添加名为`Source.cpp`的源文件。

1.  将以下代码行添加到其中：

```cpp
#include <unordered_map>
#include <string>
#include <iostream>
#include <conio.h>

using namespace std;

int main()
{
  unordered_map<string, string> hashtable;
  hashtable.emplace("Alexander", "23ms");
  hashtable.emplace("Christopher", "21ms");
  hashtable.emplace("Steve", "55ms");
  hashtable.emplace("Amy", "17ms");
  hashtable.emplace("Declan", "999ms");

  cout << "Ping time in milliseconds: " << hashtable["Amy"] << endl<<endl;
  cout << "----------------------------------" << endl << endl;

  hashtable.insert(make_pair("Fawad", "67ms"));

  cout << endl<<"Ping time of all player is the server" << endl;
  cout << "------------------------------------" << endl << endl;
  for (auto &itr : hashtable)
  {
    cout << itr.first << ": " << itr.second << endl;
  }

  _getch();
  return 0;
}
```

## 它是如何工作的…

该程序计算当前在服务器上玩我们游戏的所有玩家的 ping 时间。我们创建一个哈希表，并使用`emplace`关键字存储所有玩家的姓名和 ping 时间。我们还可以使用`make_pair`关键字稍后插入新玩家及其 ping 时间。创建哈希表后，我们可以轻松地显示特定玩家的 ping 时间，或者服务器上所有玩家的 ping 时间。我们使用迭代器来遍历哈希表。第一个参数给出了键，第二个参数给出了值。
