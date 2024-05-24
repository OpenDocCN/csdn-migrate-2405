# C++ 专家编程（二）

> 原文：[`annas-archive.org/md5/57ea316395e58ce0beb229274ec493fc`](https://annas-archive.org/md5/57ea316395e58ce0beb229274ec493fc)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：智能指针

在上一章中，您了解了模板编程和通用编程的好处。在本章中，您将学习以下智能指针主题：

+   内存管理

+   原始指针的问题

+   循环依赖

+   智能指针：

+   `auto_ptr`

+   `unique_ptr`

+   `shared_ptr`

+   `weak_ptr`

让我们探索 C++提供的内存管理设施。

# 内存管理

在 C++中，内存管理通常是软件开发人员的责任。这是因为 C++标准不强制在 C++编译器中支持垃圾回收；因此，这取决于编译器供应商的选择。特别地，Sun C++编译器附带了一个名为`libgc`的垃圾回收库。

C++语言具有许多强大的功能。其中，指针无疑是最强大和最有用的功能之一。指针虽然非常有用，但它们也有自己的奇怪问题，因此必须负责任地使用。当内存管理没有得到认真对待或者没有做得很好时，会导致许多问题，包括应用程序崩溃、核心转储、分段错误、间歇性的调试困难、性能问题等等。悬空指针或流氓指针有时会干扰其他无关的应用程序，而罪魁祸首应用程序却悄无声息地执行；事实上，受害应用程序可能会被多次指责。内存泄漏最糟糕的部分是，在某些时候它变得非常棘手，即使有经验的开发人员也会花费数小时来调试受害代码，而罪魁祸首代码却毫发未动。有效的内存管理有助于避免内存泄漏，并让您开发出内存高效的高性能应用程序。

由于每个操作系统的内存模型都不同，每个操作系统在同一内存泄漏问题的不同时间点可能会有不同的行为。内存管理是一个大课题，C++提供了许多有效的方法。我们将在以下部分讨论一些有用的技术。

# 原始指针的问题

大多数 C++开发人员有一个共同点：我们都喜欢编写复杂的东西。你问一个开发人员，“嘿，伙计，你想重用已经存在并且有效的代码，还是想自己开发一个？”虽然大多数开发人员会委婉地说在可能的情况下重用已有的代码，但他们的内心会说，“我希望我能自己设计和开发它。”复杂的数据结构和算法往往需要指针。原始指针在遇到麻烦之前确实很酷。

原始指针在使用前必须分配内存，并且在完成后需要释放内存；就是这么简单。然而，在一个产品中，指针分配可能发生在一个地方，而释放可能发生在另一个地方，事情就会变得复杂起来。如果内存管理决策没有做出正确的选择，人们可能会认为释放内存是调用者或被调用者的责任，有时内存可能在任何地方都没有被释放。另一种可能性是，同一个指针可能会在不同的地方被多次删除，这可能导致应用程序崩溃。如果这种情况发生在 Windows 设备驱动程序中，很可能会导致蓝屏死机。

想象一下，如果应用程序出现异常，并且抛出异常的函数在异常发生之前分配了一堆内存的指针，那会怎么样？任何人都可以猜到：会有内存泄漏。

让我们看一个使用原始指针的简单例子：

```cpp
#include <iostream>
using namespace std;

class MyClass {
      public:
           void someMethod() {

                int *ptr = new int();
                *ptr = 100;
                int result = *ptr / 0;  //division by zero error expected
                delete ptr;

           }
};

int main ( ) {

    MyClass objMyClass;
    objMyClass.someMethod();

    return 0;

}
```

现在运行以下命令：

```cpp
g++ main.cpp -g -std=c++17
```

查看此程序的输出：

```cpp
main.cpp: In member function ‘void MyClass::someMethod()’:
main.cpp:12:21: warning: division by zero [-Wdiv-by-zero]
 int result = *ptr / 0;
```

现在运行以下命令：

```cpp
./a.out
[1] 31674 floating point exception (core dumped) ./a.out
```

C++编译器真的很酷。看看警告消息，它指出了问题。我喜欢 Linux 操作系统。Linux 非常聪明，能够找到行为不端的恶意应用程序，并及时将其关闭，以免对其他应用程序或操作系统造成任何损害。核心转储实际上是好事，尽管它被诅咒，而不是庆祝 Linux 的方法。猜猜，微软的 Windows 操作系统同样聪明。当发现某些应用程序进行可疑的内存访问时，它们会进行错误检查，而且 Windows 操作系统也支持迷你转储和完整转储，这相当于 Linux 操作系统中的核心转储。

让我们来看一下 Valgrind 工具的输出，检查内存泄漏问题：

```cpp
valgrind --leak-check=full --show-leak-kinds=all ./a.out

==32857== Memcheck, a memory error detector
==32857== Copyright (C) 2002-2015, and GNU GPL'd, by Julian Seward et al.
==32857== Using Valgrind-3.12.0 and LibVEX; rerun with -h for copyright info
==32857== Command: ./a.out
==32857== 
==32857== 
==32857== Process terminating with default action of signal 8 (SIGFPE)
==32857== Integer divide by zero at address 0x802D82B86
==32857== at 0x10896A: MyClass::someMethod() (main.cpp:12)
==32857== by 0x1088C2: main (main.cpp:24)
==32857== 
==32857== HEAP SUMMARY:
==32857== in use at exit: 4 bytes in 1 blocks
==32857== total heap usage: 2 allocs, 1 frees, 72,708 bytes allocated
==32857== 
==32857== 4 bytes in 1 blocks are still reachable in loss record 1 of 1
==32857== at 0x4C2E19F: operator new(unsigned long) (in /usr/lib/valgrind/vgpreload_memcheck-amd64-linux.so)
==32857== by 0x108951: MyClass::someMethod() (main.cpp:8)
==32857== by 0x1088C2: main (main.cpp:24)
==32857== 
==32857== LEAK SUMMARY:
==32857== definitely lost: 0 bytes in 0 blocks
==32857== indirectly lost: 0 bytes in 0 blocks
==32857== possibly lost: 0 bytes in 0 blocks
==32857== still reachable: 4 bytes in 1 blocks
==32857== suppressed: 0 bytes in 0 blocks
==32857== 
==32857== For counts of detected and suppressed errors, rerun with: -v
==32857== ERROR SUMMARY: 0 errors from 0 contexts (suppressed: 0 from 0)
[1] 32857 floating point exception (core dumped) valgrind --leak-check=full --show-leak-kinds=all ./a.out
```

在这个输出中，如果你注意**粗体**部分的文本，你会注意到 Valgrind 工具指出了导致核心转储的源代码行号。`main.cpp`文件的第 12 行如下：

```cpp
 int result = *ptr / 0; //division by zero error expected 
```

一旦在`main.cpp`文件的第 12 行发生异常，出现在异常下方的代码将永远不会被执行。在`main.cpp`文件的第 13 行，出现了一个`delete`语句，由于异常而永远不会被执行：

```cpp
 delete ptr;
```

由于指针指向的内存在堆栈展开过程中没有被释放，因此分配给前述原始指针的内存没有被释放。每当函数抛出异常并且异常没有被同一函数处理时，堆栈展开是有保证的。然而，在堆栈展开过程中只有自动本地变量会被清理，而不是指针指向的内存。这导致内存泄漏。

这是使用原始指针引发的奇怪问题之一；还有许多类似的情况。希望你现在已经相信，使用原始指针的乐趣确实是要付出代价的。但所付出的代价并不值得，因为在 C++中有很好的替代方案来解决这个问题。你是对的，使用智能指针是解决方案，它提供了使用指针的好处，而不需要付出原始指针所附带的代价。

因此，智能指针是在 C++中安全使用指针的方法。

# 智能指针

在 C++中，智能指针让你专注于手头的问题，摆脱了处理自定义垃圾回收技术的烦恼。智能指针让你安全地使用原始指针。它们负责清理原始指针使用的内存。

C++支持许多类型的智能指针，可以在不同的场景中使用：

+   `auto_ptr`

+   `unique_ptr`

+   `shared_ptr`

+   `weak_ptr`

`auto_ptr`智能指针是在 C++11 中引入的。`auto_ptr`智能指针在其作用域结束时自动释放堆内存。然而，由于`auto_ptr`从一个`auto_ptr`实例转移所有权的方式，它已被弃用，并且`unique_ptr`被引入作为其替代品。`shared_ptr`智能指针帮助多个共享智能指针引用同一个对象，并负责内存管理负担。`weak_ptr`智能指针帮助解决由于应用程序设计中存在循环依赖问题而导致的`shared_ptr`使用时的内存泄漏问题。

还有其他类型的智能指针和相关内容，它们并不常用，并列在下面的项目列表中。然而，我强烈建议你自己探索它们，因为你永远不知道什么时候会发现它们有用：

+   `owner_less`

+   `enable_shared_from_this`

+   `bad_weak_ptr`

+   `default_delete`

`owner_less`智能指针帮助比较两个或多个智能指针是否共享相同的原始指向对象。`enable_shared_from_this`智能指针帮助获取`this`指针的智能指针。`bad_weak_ptr`智能指针是一个异常类，意味着使用无效智能指针创建了`shared_ptr`。`default_delete`智能指针是`unique_ptr`使用的默认销毁策略，它调用`delete`语句，同时也支持用于数组类型的部分特化，使用`delete[]`。

在本章中，我们将逐一探讨`auto_ptr`、`shared_ptr`、`weak_ptr`和`unique-ptr`。

# auto_ptr

`auto_ptr`智能指针接受一个原始指针，包装它，并确保在`auto_ptr`对象超出范围时释放原始指针指向的内存。任何时候，只有一个`auto_ptr`智能指针可以指向一个对象。因此，当一个`auto_ptr`指针被赋值给另一个`auto_ptr`指针时，所有权被转移到接收赋值的`auto_ptr`实例；当复制`auto_ptr`智能指针时也是如此。

通过一个简单的例子观察这些功能将会很有趣，如下所示：

```cpp
#include <iostream>
#include <string>
#include <memory>
#include <sstream>
using namespace std;

class MyClass {
      private:
           static int count;
           string name;
      public:
           MyClass() {
                 ostringstream stringStream(ostringstream::ate);
                 stringStream << "Object";
                 stringStream << ++count;
                 name = stringStream.str();
                 cout << "nMyClass Default constructor - " << name << endl;
           }
           ~MyClass() {
                 cout << "nMyClass destructor - " << name << endl;
           }

           MyClass ( const MyClass &objectBeingCopied ) {
                 cout << "nMyClass copy constructor" << endl;
           }

           MyClass& operator = ( const MyClass &objectBeingAssigned ) {
                 cout << "nMyClass assignment operator" << endl;
           }

           void sayHello( ) {
                cout << "Hello from MyClass " << name << endl;
           }
};

int MyClass::count = 0;

int main ( ) {

   auto_ptr<MyClass> ptr1( new MyClass() );
   auto_ptr<MyClass> ptr2( new MyClass() );

   return 0;

}
```

前面程序的编译输出如下：

```cpp
g++ main.cpp -std=c++17

main.cpp: In function ‘int main()’:
main.cpp:40:2: warning: ‘template<class> class std::auto_ptr’ is deprecated [-Wdeprecated-declarations]
 auto_ptr<MyClass> ptr1( new MyClass() );

In file included from /usr/include/c++/6/memory:81:0,
 from main.cpp:3:
/usr/include/c++/6/bits/unique_ptr.h:49:28: note: declared here
 template<typename> class auto_ptr;

main.cpp:41:2: warning: ‘template<class> class std::auto_ptr’ is deprecated [-Wdeprecated-declarations]
 auto_ptr<MyClass> ptr2( new MyClass() );

In file included from /usr/include/c++/6/memory:81:0,
 from main.cpp:3:
/usr/include/c++/6/bits/unique_ptr.h:49:28: note: declared here
 template<typename> class auto_ptr;
```

正如你所看到的，C++编译器警告我们使用`auto_ptr`已经被弃用。因此，我不建议再使用`auto_ptr`智能指针；它已被`unique_ptr`取代。

目前，我们可以忽略警告并继续，如下所示：

```cpp
g++ main.cpp -Wno-deprecated

./a.out

MyClass Default constructor - Object1

MyClass Default constructor - Object2

MyClass destructor - Object2

MyClass destructor - Object1 
```

正如你在前面程序输出中看到的，分配在堆中的`Object1`和`Object2`都被自动删除了。这要归功于`auto_ptr`智能指针。

# 代码演示 - 第 1 部分

从`MyClass`的定义中你可能已经了解到，它定义了默认`构造函数`、`复制`构造函数和析构函数，一个`赋值`运算符和`sayHello()`方法，如下所示：

```cpp
//Definitions removed here to keep it simple 
class MyClass {
public:
      MyClass() { }  //Default constructor
      ~MyClass() { } //Destructor 
      MyClass ( const MyClass &objectBeingCopied ) {} //Copy Constructor 
      MyClass& operator = ( const MyClass &objectBeingAssigned ) { } //Assignment operator
      void sayHello();
}; 
```

`MyClass`的方法只是打印声明表明方法已被调用；它们纯粹是为了演示目的而设计的。

`main()`函数创建了两个指向堆中两个不同`MyClass`对象的`auto_ptr`智能指针，如下所示：

```cpp
int main ( ) {

   auto_ptr<MyClass> ptr1( new MyClass() );
   auto_ptr<MyClass> ptr2( new MyClass() );

   return 0;

}
```

正如你所理解的，`auto_ptr`是一个包装原始指针而不是指针的本地对象。当控制流达到`return`语句时，堆栈展开过程开始，作为这一过程的一部分，堆栈对象`ptr1`和`ptr2`被销毁。这反过来调用了`auto_ptr`的析构函数，最终删除了由堆栈对象`ptr1`和`ptr2`指向的`MyClass`对象。

我们还没有完成。让我们探索`auto_ptr`的更多有用功能，如下所示的`main`函数：

```cpp
int main ( ) {

    auto_ptr<MyClass> ptr1( new MyClass() );
    auto_ptr<MyClass> ptr2( new MyClass() );

    ptr1->sayHello();
    ptr2->sayHello();

    //At this point the below stuffs happen
    //1\. ptr2 smart pointer has given up ownership of MyClass Object 2
    //2\. MyClass Object 2 will be destructed as ptr2 has given up its 
    //   ownership on Object 2
    //3\. Ownership of Object 1 will be transferred to ptr2
    ptr2 = ptr1;

    //The line below if uncommented will result in core dump as ptr1 
    //has given up its ownership on Object 1 and the ownership of 
    //Object 1 is transferred to ptr2.
    // ptr1->sayHello();

    ptr2->sayHello();

    return 0;

}
```

# 代码演示 - 第 2 部分

我们刚刚看到的`main()`函数代码演示了许多有用的技术和一些`auto_ptr`智能指针的争议行为。以下代码创建了两个`auto_ptr`实例，即`ptr1`和`ptr2`，它们包装了堆中创建的两个`MyClass`对象：

```cpp
 auto_ptr<MyClass> ptr1( new MyClass() );
 auto_ptr<MyClass> ptr2( new MyClass() );
```

接下来，以下代码演示了如何使用`auto_ptr`调用`MyClass`支持的方法：

```cpp
 ptr1->sayHello();
 ptr2->sayHello();
```

希望你注意到了`ptr1->sayHello()`语句。它会让你相信`auto_ptr` `ptr1`对象是一个指针，但实际上，`ptr1`和`ptr2`只是作为本地变量在堆栈中创建的`auto_ptr`对象。由于`auto_ptr`类已经重载了`->`指针运算符和`*`解引用运算符，它看起来像一个指针。事实上，`MyClass`暴露的所有方法只能使用`->`指针运算符访问，而所有`auto_ptr`方法可以像访问堆栈对象一样访问。

以下代码演示了`auto_ptr`智能指针的内部行为，所以请密切关注；这将会非常有趣：

```cpp
ptr2 = ptr1;
```

看起来前面的代码只是一个简单的`赋值`语句，但它会触发`auto_ptr`中的许多活动。由于前面的`赋值`语句，发生了以下活动：

+   `ptr2`智能指针将放弃对`MyClass`对象 2 的所有权。

+   `MyClass`对象 2 将被销毁，因为`ptr2`已经放弃了对`object 2`的所有权。

+   `object 1`的所有权将被转移给`ptr2`。

+   此时，`ptr1`既不指向`object 1`，也不负责管理`object 1`使用的内存。

以下注释行有一些事实要告诉你：

```cpp
// ptr1->sayHello();
```

由于`ptr1`智能指针已经释放了对`object 1`的所有权，因此尝试访问`sayHello()`方法是非法的。这是因为`ptr1`实际上不再指向`object 1`，而`object 1`由`ptr2`拥有。当`ptr2`超出范围时，释放`object 1`使用的内存是`ptr2`智能指针的责任。如果取消注释前面的代码，将导致核心转储。

最后，以下代码让我们使用`ptr2`智能指针在`object 1`上调用`sayHello()`方法：

```cpp
ptr2->sayHello();
return 0;
```

我们刚刚看到的`return`语句将在`main()`函数中启动堆栈展开过程。这将最终调用`ptr2`的析构函数，从而释放`object 1`使用的内存。美妙的是，所有这些都是自动发生的。`auto_ptr`智能指针在我们专注于手头的问题时在幕后为我们努力工作。

然而，由于以下原因，从`C++11`开始`auto_ptr`被弃用：

+   `auto_ptr`对象不能存储在 STL 容器中

+   `auto_ptr`的复制构造函数将从原始来源，也就是`auto_ptr`中移除所有权。

+   `auto_ptr`复制`赋值`运算符将从原始来源，也就是`auto_ptr`中移除所有权。

+   `auto_ptr`的复制构造函数和`赋值`运算符违反了原始意图，因为`auto_ptr`的复制构造函数和`赋值`运算符将从右侧对象中移除源对象的所有权，并将所有权分配给左侧对象

# unique_ptr

`unique_ptr`智能指针的工作方式与`auto_ptr`完全相同，只是`unique_ptr`解决了`auto_ptr`引入的问题。因此，`unique_ptr`是从`C++11`开始取代`auto_ptr`的。`unique_ptr`智能指针只允许一个智能指针独占一个堆分配的对象。从一个`unique_ptr`实例到另一个实例的所有权转移只能通过`std::move()`函数来完成。

因此，让我们重构我们之前的示例，使用`unique_ptr`来替代`auto_ptr`。

重构后的代码示例如下：

```cpp
#include <iostream>
#include <string>
#include <memory>
#include <sstream>
using namespace std;

class MyClass {
      private:
          static int count;
          string name;

      public:
          MyClass() {
                ostringstream stringStream(ostringstream::ate);
                stringStream << "Object";
                stringStream << ++count;
                name = stringStream.str();
                cout << "nMyClass Default constructor - " << name << endl;
          }

          ~MyClass() {
                cout << "nMyClass destructor - " << name << endl;
          }

          MyClass ( const MyClass &objectBeingCopied ) {
                cout << "nMyClass copy constructor" << endl;
          }

          MyClass& operator = ( const MyClass &objectBeingAssigned ) {
                cout << "nMyClass assignment operator" << endl;
          }

          void sayHello( ) {
                cout << "nHello from MyClass" << endl;
          }

};

int MyClass::count = 0;

int main ( ) {

 unique_ptr<MyClass> ptr1( new MyClass() );
 unique_ptr<MyClass> ptr2( new MyClass() );

 ptr1->sayHello();
 ptr2->sayHello();

 //At this point the below stuffs happen
 //1\. ptr2 smart pointer has given up ownership of MyClass Object 2
 //2\. MyClass Object 2 will be destructed as ptr2 has given up its 
 // ownership on Object 2
 //3\. Ownership of Object 1 will be transferred to ptr2
 ptr2 = move( ptr1 );

 //The line below if uncommented will result in core dump as ptr1 
 //has given up its ownership on Object 1 and the ownership of 
 //Object 1 is transferred to ptr2.
 // ptr1->sayHello();

 ptr2->sayHello();

 return 0;
}
```

前面程序的输出如下：

```cpp
g++ main.cpp -std=c++17

./a.out

MyClass Default constructor - Object1

MyClass Default constructor - Object2

MyClass destructor - Object2

MyClass destructor - Object1 
```

在前面的输出中，您可以注意到编译器没有报告任何警告，并且程序的输出与`auto_ptr`的输出相同。

# 代码演示

重要的是要注意`main()`函数中`auto_ptr`和`unique_ptr`之间的区别。让我们来看看以下代码中`main()`函数。该代码在堆中创建了两个`MyClass`对象的实例，分别是`ptr1`和`ptr2`的两个实例：

```cpp
 unique_ptr<MyClass> ptr1( new MyClass() );
 unique_ptr<MyClass> ptr2( new MyClass() );
```

接下来的代码演示了如何使用`unique_ptr`调用`MyClass`支持的方法：

```cpp
 ptr1->sayHello();
 ptr2->sayHello();
```

就像`auto_ptr`一样，`unique_ptr`智能指针`ptr1`对象已经重载了`->`指针运算符和`*`解引用运算符；因此，它看起来像一个指针。

以下代码演示了`unique_ptr`不支持将一个`unique_ptr`实例分配给另一个实例，所有权转移只能通过`std::move()`函数实现：

```cpp
ptr2 = std::move(ptr1);
```

`move`函数触发了以下活动：

+   `ptr2`智能指针放弃了对`MyClass`对象 2 的所有权

+   `MyClass`对象 2 将被销毁，因为`ptr2`放弃了对`object 2`的所有权。

+   `object 1`的所有权已转移到`ptr2`

+   此时，`ptr1`既不指向`object 1`，也不负责管理`object 1`使用的内存

如果取消注释以下代码，将导致核心转储：

```cpp
// ptr1->sayHello();
```

最后，以下代码让我们使用`ptr2`智能指针调用`object 1`的`sayHello()`方法：

```cpp
ptr2->sayHello();
return 0;
```

我们刚刚看到的`return`语句将在`main()`函数中启动堆栈展开过程。这将最终调用`ptr2`的析构函数，从而释放`object 1`使用的内存。请注意，与`auto_ptr`对象不同，`unique_ptr`对象可以存储在 STL 容器中。

# shared_ptr

当一组`shared_ptr`对象共享对堆分配对象的所有权时，使用`shared_ptr`智能指针。当所有`shared_ptr`实例完成对共享对象的使用时，`shared_ptr`指针释放共享对象。`shared_ptr`指针使用引用计数机制来检查对共享对象的总引用；每当引用计数变为零时，最后一个`shared_ptr`实例将删除共享对象。

让我们通过一个示例来检查`shared_ptr`的使用，如下所示：

```cpp
#include <iostream>
#include <string>
#include <memory>
#include <sstream>
using namespace std;

class MyClass {
  private:
    static int count;
    string name;
  public:
    MyClass() {
      ostringstream stringStream(ostringstream::ate);
      stringStream << "Object";
      stringStream << ++count;

      name = stringStream.str();

      cout << "nMyClass Default constructor - " << name << endl;
    }

    ~MyClass() {
      cout << "nMyClass destructor - " << name << endl;
    }

    MyClass ( const MyClass &objectBeingCopied ) {
      cout << "nMyClass copy constructor" << endl;
    }

    MyClass& operator = ( const MyClass &objectBeingAssigned ) {
      cout << "nMyClass assignment operator" << endl;
    }

    void sayHello() {
      cout << "Hello from MyClass " << name << endl;
    }

};

int MyClass::count = 0;

int main ( ) {

  shared_ptr<MyClass> ptr1( new MyClass() );
  ptr1->sayHello();
  cout << "nUse count is " << ptr1.use_count() << endl;

  {
      shared_ptr<MyClass> ptr2( ptr1 );
      ptr2->sayHello();
      cout << "nUse count is " << ptr2.use_count() << endl;
  }

  shared_ptr<MyClass> ptr3 = ptr1;
  ptr3->sayHello();
  cout << "nUse count is " << ptr3.use_count() << endl;

  return 0;
}
```

前面程序的输出如下：

```cpp
MyClass Default constructor - Object1
Hello from MyClass Object1
Use count is 1

Hello from MyClass Object1
Use count is 2

Number of smart pointers referring to MyClass object after ptr2 is destroyed is 1

Hello from MyClass Object1
Use count is 2

MyClass destructor - Object1
```

# 代码演示

以下代码创建了一个指向`MyClass`堆分配对象的`shared_ptr`对象实例。就像其他智能指针一样，`shared_ptr`也有重载的`->`和`*`运算符。因此，可以调用所有`MyClass`对象方法，就像使用原始指针一样。`use_count()`方法告诉指向共享对象的智能指针数量：

```cpp
 shared_ptr<MyClass> ptr1( new MyClass() );
 ptr1->sayHello();
 cout << "nNumber of smart pointers referring to MyClass object is "
      << ptr1->use_count() << endl;
```

在以下代码中，智能指针`ptr2`的作用域被花括号包围的块内部。因此，`ptr2`将在以下代码块的末尾被销毁。代码块内预期的`use_count`函数为 2：

```cpp
 { 
      shared_ptr<MyClass> ptr2( ptr1 );
      ptr2->sayHello();
      cout << "nNumber of smart pointers referring to MyClass object is "
           << ptr2->use_count() << endl;
 }
```

在以下代码中，预期的`use_count`值为 1，因为`ptr2`已被删除，这将减少引用计数 1：

```cpp
 cout << "nNumber of smart pointers referring to MyClass object after ptr2 is destroyed is "
 << ptr1->use_count() << endl; 
```

以下代码将打印一个 Hello 消息，然后`use_count`为 2。这是因为`ptr1`和`ptr3`现在引用堆中的`MyClass`共享对象：

```cpp
shared_ptr<MyClass> ptr3 = ptr2;
ptr3->sayHello();
cout << "nNumber of smart pointers referring to MyClass object is "
     << ptr2->use_count() << endl;
```

在`main`函数末尾的`return 0;`语句将销毁`ptr1`和`ptr3`，将引用计数减少到零。因此，我们可以观察到`MyClass`析构函数在输出末尾打印语句。

# weak_ptr

到目前为止，我们已经讨论了`shared_ptr`的正面作用，并举例说明。然而，当应用程序设计中存在循环依赖时，`shared_ptr`无法清理内存。要么必须重构应用程序设计以避免循环依赖，要么可以使用`weak_ptr`来解决循环依赖问题。

您可以查看我的 YouTube 频道，了解`shared_ptr`问题以及如何使用`weak_ptr`解决：[`www.youtube.com/watch?v=SVTLTK5gbDc`](https://www.youtube.com/watch?v=SVTLTK5gbDc)。

假设有三个类：A、B 和 C。类 A 和 B 有一个 C 的实例，而 C 有 A 和 B 的实例。这里存在一个设计问题。A 依赖于 C，C 也依赖于 A。同样，B 依赖于 C，C 也依赖于 B。

考虑以下代码：

```cpp
#include <iostream>
#include <string>
#include <memory>
#include <sstream>
using namespace std;

class C;

class A {
      private:
           shared_ptr<C> ptr;
      public:
           A() {
                 cout << "nA constructor" << endl;
           }

           ~A() {
                 cout << "nA destructor" << endl;
           }

           void setObject ( shared_ptr<C> ptr ) {
                this->ptr = ptr;
           }
};

class B {
      private:
           shared_ptr<C> ptr;
      public:
           B() {
                 cout << "nB constructor" << endl;
           }

           ~B() {
                 cout << "nB destructor" << endl;
           }

           void setObject ( shared_ptr<C> ptr ) {
                this->ptr = ptr;
           }
};

class C {
      private:
           shared_ptr<A> ptr1;
           shared_ptr<B> ptr2;
      public:
           C(shared_ptr<A> ptr1, shared_ptr<B> ptr2) {
                   cout << "nC constructor" << endl;
                   this->ptr1 = ptr1;
                   this->ptr2 = ptr2;
           }

           ~C() {
                   cout << "nC destructor" << endl;
           }
};

int main ( ) {
                shared_ptr<A> a( new A() );
                shared_ptr<B> b( new B() );
                shared_ptr<C> c( new C( a, b ) );

                a->setObject ( shared_ptr<C>( c ) );
                b->setObject ( shared_ptr<C>( c ) );

                return 0;
}
```

前面程序的输出如下：

```cpp
g++ problem.cpp -std=c++17

./a.out

A constructor

B constructor

C constructor
```

在前面的输出中，您可以观察到，即使我们使用了`shared_ptr`，对象 A、B 和 C 使用的内存也从未被释放。这是因为我们没有看到各自类的析构函数被调用。原因是`shared_ptr`在内部使用引用计数算法来决定是否共享对象必须被销毁。然而，在这里它失败了，因为除非对象 C 被删除，否则无法删除对象 A。除非删除对象 A，否则无法删除对象 C。同样，除非删除对象 A 和 B，否则无法删除对象 C。同样，除非删除对象 C，否则无法删除对象 A，除非删除对象 C，否则无法删除对象 B。

底线是这是一个循环依赖设计问题。为了解决这个问题，从 C++11 开始，C++引入了`weak_ptr`。`weak_ptr`智能指针不是强引用。因此，所引用的对象可以在任何时候被删除，不像`shared_ptr`。

# 循环依赖

循环依赖是一个问题，如果对象 A 依赖于 B，而对象 B 又依赖于 A。现在让我们看看如何通过`shared_ptr`和`weak_ptr`的组合来解决这个问题，最终打破循环依赖，如下所示：

```cpp
#include <iostream>
#include <string>
#include <memory>
#include <sstream>
using namespace std;

class C;

class A {
      private:
 weak_ptr<C> ptr;
      public:
           A() {
                  cout << "nA constructor" << endl;
           }

           ~A() {
                  cout << "nA destructor" << endl;
           }

           void setObject ( weak_ptr<C> ptr ) {
                  this->ptr = ptr;
           }
};

class B {
      private:
 weak_ptr<C> ptr;
      public:
           B() {
               cout << "nB constructor" << endl;
           }

           ~B() {
               cout << "nB destructor" << endl;
           }

           void setObject ( weak_ptr<C> ptr ) {
                this->ptr = ptr;
           }
};

class C {
      private:
           shared_ptr<A> ptr1;
           shared_ptr<B> ptr2;
      public:
           C(shared_ptr<A> ptr1, shared_ptr<B> ptr2) {
                   cout << "nC constructor" << endl;
                   this->ptr1 = ptr1;
                   this->ptr2 = ptr2;
           }

           ~C() {
                   cout << "nC destructor" << endl;
           }
};

int main ( ) {
         shared_ptr<A> a( new A() );
         shared_ptr<B> b( new B() );
         shared_ptr<C> c( new C( a, b ) );

         a->setObject ( weak_ptr<C>( c ) );
         b->setObject ( weak_ptr<C>( c ) );

         return 0;
}
```

前面重构代码的输出如下：

```cpp
g++ solution.cpp -std=c++17

./a.out

A constructor

B constructor

C constructor

C destructor

B destructor

A destructor
```

# 总结

在本章中，您学习了

+   由于原始指针而引起的内存泄漏问题

+   关于`auto_ptr`在赋值和复制构造函数方面的问题

+   `unique_ptr`及其优势

+   `shared_ptr`在内存管理中的作用及其与循环依赖相关的限制。

+   您还将使用`weak_ptr`解决循环依赖问题

在下一章中，您将学习如何在 C++中开发 GUI 应用程序。


# 第五章：在 C++中开发 GUI 应用程序

在本章中，您将学习以下主题：

+   Qt 的简要概述

+   Qt 框架

+   在 Ubuntu 上安装 Qt

+   开发 Qt 核心应用程序

+   开发 Qt GUI 应用程序

+   在 Qt GUI 应用程序中使用布局

+   理解事件处理的信号和槽

+   在 Qt 应用程序中使用多个布局

Qt 是一个用 C++开发的跨平台应用程序框架。它支持包括 Windows、Linux、Mac OS、Android、iOS、嵌入式 Linux、QNX、VxWorks、Windows CE/RT、Integrity、Wayland、X11、嵌入式设备等在内的各种平台。它主要用作人机界面（HMI）或图形用户界面（GUI）框架；然而，它也用于开发命令行界面（CLI）应用程序。Qt 的正确发音方式是可爱。Qt 应用程序框架有两种版本：开源版本和商业许可版本。

Qt 是 Haavard Nord 和 Eirik Chambe-Eng 的原始开发人员，他们于 1991 年开发了 Qt。

由于 C++语言本身不支持 GUI，你可能已经猜到了，C++语言本身没有原生的事件管理支持。因此，Qt 需要支持自己的事件处理机制，这导致了信号和槽技术的出现。在底层，信号和槽使用了观察者设计模式，允许 Qt 对象相互通信。这听起来太难理解了吗？别担心！信号只是事件，比如按钮点击或窗口关闭，而槽是事件处理程序，可以以你希望的方式对这些事件做出响应。

为了使我们在 Qt 应用程序开发方面的生活更加轻松，Qt 支持各种宏和特定于 Qt 的关键字。由于这些关键字不会被 C++理解，Qt 必须将它们和宏转换为纯粹的 C++代码，以便 C++编译器可以像往常一样完成其工作。为了使这一切更加顺利，Qt 支持一种称为元对象编译器（Meta-Object Compiler）的东西，也被称为 moc。

对于 C++项目来说，Qt 是一个自然的选择，因为它是纯粹的 C++代码；因此，作为 C++开发人员，在应用程序中使用 Qt 时会感到非常自在。一个典型的应用程序将同时具有复杂的逻辑和令人印象深刻的 UI。在小型产品团队中，通常一个开发人员会做多种工作，这既有利也有弊。

通常，专业开发人员具有良好的问题解决能力。问题解决能力对于以最佳方式解决复杂问题并选择良好的数据结构和算法至关重要。

开发令人印象深刻的 UI 需要创造性的设计技能。虽然有一定数量的开发人员擅长解决问题或创造性的 UI 设计，但并非所有开发人员都擅长这两者。这就是 Qt 脱颖而出的地方。

假设一家初创公司想要为其内部目的开发一个应用程序。为此，一个简单的 GUI 应用程序就足够了，一个看起来不错的 HMI/GUI 可能适用于团队，因为该应用程序仅用于内部目的。在这种情况下，整个应用程序可以使用 C++和 Qt 小部件框架进行开发。唯一的前提是开发团队必须精通 C++。

然而，在需要开发移动应用的情况下，出色的 HMI 变得必不可少。同样，移动应用可以使用 C++和 Qt 小部件进行开发。但是，这个选择有两个方面。好的一面是移动应用团队只需要擅长 C++。这个选择的坏处是，并不是所有擅长设计移动应用的 HMI/GUI 的 C++开发人员都能保证做得好。

假设团队有一两个专门的 Photoshop 专业人员，擅长创建引人注目的图像，可以在 GUI 中使用，并且有一两个 UI 设计师，可以使用 Photoshop 专家创建的图像制作出令人印象深刻的 HMI/GUI。通常，UI 设计师擅长前端技术，如 JavaScript、HTML 和 CSS。强大的 Qt 框架可以开发复杂的业务逻辑，而 HMI/GUI 可以在 QML 中开发。

QML 是与 Qt 应用程序框架一起提供的一种声明性脚本语言。它接近 JavaScript，并具有 Qt 特定的扩展。它非常适合快速应用程序开发，并允许 UI 设计师专注于 HMI/GUI，而 C++开发人员专注于可以在 Qt 框架中开发的复杂业务逻辑。

由于 C++ Qt 框架和 QML 都是同一 Qt 应用程序框架的一部分，它们可以无缝地搭配使用。

Qt 是一个庞大而强大的框架；因此，本章将重点介绍 Qt 的基本要点，以帮助您开始使用 Qt。如果您想了解更多信息，您可能想要查看我正在撰写的另一本即将推出的书，即*精通 Qt 和 QML 编程*。

# Qt

Qt 框架是用 C++开发的，因此可以保证对任何优秀的 C++开发人员来说都是易如反掌。它支持 CLI 和基于 GUI 的应用程序开发。在撰写本章时，Qt 应用程序框架的最新版本是 Qt 5.7.0。当您阅读本书时，可能会有不同版本的 Qt 可供您下载。您可以从[`www.qt.io`](https://www.qt.io)下载最新版本。

# 在 Ubuntu 16.04 中安装 Qt 5.7.0

在本章中，我将使用 Ubuntu 16.04 操作系统；但是，本章中列出的程序应该适用于支持 Qt 的任何平台。

有关详细的安装说明，请参考[`wiki.qt.io/install_Qt_5_on_Ubuntu`](https://wiki.qt.io/install_Qt_5_on_Ubuntu)。

此时，您的系统应该已经安装了 C++编译器。如果不是这样，请首先确保安装 C++编译器，如下所示：

```cpp
sudo apt-get install build-essential
```

从 Ubuntu 终端，您应该能够下载 Qt 5.7.0，如下命令所示：

```cpp
w**get** **http://download.qt.io/official_releases/qt/5.7/5.7.0/qt-
opensource-linux-x64-5.7.0.run** 
```

为下载的安装程序提供执行权限，如下命令所示：

```cpp
chmod +x qt-opensource-linux-x64-5.7.0.run 
```

我强烈建议您安装 Qt 及其源代码。如果您喜欢用极客的方式查找 Qt 帮助，您可以直接从源代码获取帮助。

按照以下命令启动安装程序：

```cpp
./qt-opensource-linux-x64-5.7.0.run
```

由于 Qt 使用 OpenGL，请确保在开始编写 Qt 中的第一个程序之前安装以下内容。要安装`libfontconfig1`，运行以下命令：

```cpp
 sudo apt-get install libfontconfig1
```

要安装`mesa-common-dev`，请运行以下命令：

```cpp
sudo apt-get install mesa-common-dev  
```

此时，您应该已经有一个可用的 Qt 设置。您可以通过在 Linux 终端中发出以下命令来验证安装：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/0b2f4ba7-cd86-4d65-b782-d184577597a1.png)

图 5.1

如果`qmake`命令未被识别，请确保导出 Qt 安装文件夹的`bin`路径，如前面的屏幕截图所示。此外，创建一个软链接也可能很有用。此命令如下：

```cpp
 sudo ln -s /home/jegan/Qt5.7.0/5.7/gcc_64/bin/qmake /usr/bin/qmake  
```

Qt 在您系统上安装的路径可能与我的不同，因此请相应地替换 Qt 路径。

# Qt Core

Qt Core 是 Qt 支持的模块之一。该模块具有许多有用的类，如`QObject`、`QCoreApplication`、`QDebug`等。几乎每个 Qt 应用程序都需要这个模块，因此它们被 Qt 框架隐式链接。每个 Qt 类都继承自`QObject`，而`QObject`类为 Qt 应用程序提供事件处理支持。`QObject`是支持事件处理机制的关键部分；有趣的是，即使是基于控制台的应用程序也可以在 Qt 中支持事件处理。

# 编写我们的第一个 Qt 控制台应用程序

如果你得到类似于*图 5.1*所示的输出，那么你已经准备好动手了。让我们写我们的第一个 Qt 应用程序，如下面的屏幕截图所示：

**![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/17772c64-4752-40a0-afd1-fea5113595c4.png)**

图 5.2

在第一行中，我们从**QtCore**模块中包含了`QDebug`头文件。如果你仔细观察，`qDebug()`函数类似于 C++的`cout ostream`运算符。在调试代码时，`qDebug()`函数将成为 Qt 世界中的好朋友。`QDebug`类已经重载了 C++的`ostream`运算符，以支持 C++编译器不支持的 Qt 数据类型。

以老派的方式，我有点痴迷于终端，几乎在编码时实现任何功能，而不是使用一些花哨的**集成开发环境**（**IDE**）。你可能会喜欢或讨厌这种方法，这是很自然的。好处是在你和 Qt/C++之间没有任何障碍，因为你将使用简单而强大的文本编辑器，如 Vim、Emacs、Sublime Text、Atom、Brackets 或 Neovim，因此你将学会几乎所有关于 Qt 项目和 qmake 的基本知识；IDE 会让你的生活变得轻松，但它们隐藏了许多每个严肃的开发人员都必须了解的基本知识。所以这是一个权衡。我把决定权交给你，决定是使用你喜欢的纯文本编辑器还是 Qt Creator IDE 或其他花哨的 IDE。我将坚持使用重构后的 Vim 编辑器 Neovim，它看起来真的很酷。*图 5.2*将给你一个关于 Neovim 编辑器外观和感觉的想法。

让我们回到正题。让我们看看如何以极客的方式在命令行中编译这段代码。在此之前，你可能想了解一下`qmake`工具。它是 Qt 的专有`make`实用程序。`qmake`实用程序不过是一个 make 工具，但它了解 Qt 特定的东西，因此它知道 moc、signals、slots 等等，而典型的`make`实用程序则不知道。

以下命令应该帮助你创建一个`.pro`文件。`.pro`文件的名称将由`qmake`实用程序根据项目文件夹名称决定。`.pro`文件是 Qt Creator IDE 将相关文件组合为单个项目的方式。由于我们不打算使用 Qt Creator，我们将使用`.pro`文件来创建`Makefile`，以便编译我们的 Qt 项目，就像编译普通的 C++项目一样。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/9fcbc0ba-f1d9-437e-a94d-e1741ace3f10.png)

图 5.3

当你发出`qmake -project`命令时，qmake 将扫描当前文件夹和当前文件夹下的所有子文件夹，并在`Ex1.pro`中包含头文件和源文件。顺便说一句，`.pro`文件是一个纯文本文件，可以使用任何文本编辑器打开，如*图 5.4*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/27b49cc7-7480-4e85-8544-2b986d05d07c.png)

图 5.4

现在是时候创建`Makefile`，以`Ex1.pro`作为输入文件。由于`Ex1.pro`文件存在于当前目录中，我们不必明确提供`Ex1.pro`作为输入文件来自动生成`Makefile`。这个想法是，一旦我们有了一个`.pro`文件，我们只需要从`.pro`文件发出命令：`qmake`来生成`Makefile`。这将完成创建一个完整的`Makefile`的魔术，你可以使用`make`实用程序来构建你的项目，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/b90c5b0d-ed70-4da8-b9f1-072a57b6710b.png)

图 5.5

这就是我们一直在等待的时刻，对吧？是的，让我们执行我们的第一个 Qt Hello World 程序，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/1b64726c-933d-4a3a-a527-f691d3feaa60.png)

图 5.6

恭喜！你已经完成了你的第一个 Qt 应用程序。在这个练习中，你学会了如何在 Ubuntu 中设置和配置 Qt，以及如何编写一个简单的 Qt 控制台应用程序，然后构建和运行它。最好的部分是你学会了所有这些都是通过命令行完成的。

# Qt 小部件

Qt Widgets 是一个有趣的模块，支持许多小部件，如按钮、标签、编辑、组合、列表、对话框等。`QWidget`是所有小部件的基类，而`QObject`是几乎每个 Qt 类的基类。虽然许多编程语言称之为 UI 控件，Qt 将它们称为小部件。尽管 Qt 可以在许多平台上运行，但它的主要平台仍然是 Linux；小部件在 Linux 世界中很常见。

# 编写我们的第一个 Qt GUI 应用程序

我们的第一个控制台应用程序真的很酷，不是吗？让我们继续深入探索。这一次，让我们编写一个简单的基于 GUI 的 Hello World 程序。程序的步骤几乎相同，只是`main.cpp`中有一些小的改变。请参考以下完整的代码：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/07a381bd-7684-4715-b758-d9378575f02f.png)

图 5.7

等一下。让我解释一下第 23 行和第 29 行需要`QApplication`的原因。每个 Qt GUI 应用程序必须有一个`QApplication`实例。`QApplication`为我们的应用程序提供了对命令行开关的支持，因此需要提供**参数计数**（**argc**）和**参数值**（**argv**）。基于 GUI 的应用程序是事件驱动的，因此它们必须响应 Qt 世界中的事件或者更准确地说是信号。在第 29 行，`exec`函数启动了`事件`循环，这确保应用程序等待用户交互，直到用户关闭窗口。其思想是所有用户事件将被`QApplication`实例接收并存储在事件队列中，然后通知给它的`Child`小部件。事件队列确保队列中存储的所有事件按照它们发生的顺序进行处理，即**先进先出**（**FIFO**）。

如果你好奇地想要检查一下，如果你注释掉第 29 行会发生什么，应用程序仍然会编译和运行，但你可能看不到任何窗口。原因是`main`线程或`main`函数在第 25 行创建了一个`QWidget`的实例，这就是我们启动应用程序时看到的窗口。

在第 27 行，窗口实例被显示出来，但在没有第 29 行的情况下，`main`函数将立即终止应用程序，而不给你检查你的第一个 Qt GUI 应用程序的机会。值得一试，所以继续看看有没有第 29 行会发生什么。

让我们生成`Makefile`，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/bf08a1bd-9471-45b3-968e-bbed8c9f8978.png)

图 5.8

现在让我们尝试使用`make`工具编译我们的项目，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/0d446036-e622-4d5e-8c30-f8f2344e52e0.png)

图 5.9

有趣，对吧？我们全新的 Qt GUI 程序无法编译。你注意到致命错误了吗？没关系，让我们了解一下为什么会发生这种情况。原因是我们还没有链接 Qt Widgets 模块，因为`QApplication`类是 Qt Widgets 模块的一部分。在这种情况下，你可能会想知道为什么我们的第一个 Hello World 程序编译时没有任何问题。在我们的第一个程序中，`QDebug`类是**QtCore**模块的一部分，它隐式地被链接，而其他模块必须显式地被链接。让我们看看如何解决这个问题：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/31f35928-8459-43d6-8dc6-a686bd6a22ec.png)

图 5.10

我们需要在`Ex2.pro`文件中添加`QT += widgets`，这样`qmake`工具就会理解需要在创建最终可执行文件时链接 Qt Widgets 的**共享对象**（在 Linux 中是`.so`文件），在 Windows 中也称为**动态链接库**（`.dll`文件）。一旦这个问题得到解决，我们必须运行`qmake`，这样`Makefile`就能反映我们`Ex2.pro`文件中的新更改，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/9fc484e6-678d-4f37-bfc0-dd8861b9e6e9.png)

图 5.11

很好。现在让我们检查一下我们的第一个基于 GUI 的 Qt 应用程序。在我的系统中，应用程序输出如*图 5.12*所示；如果一切顺利，你也应该得到类似的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/9b9a237a-4c8d-43c2-809b-827f2e0558ff.png)

图 5.12

如果我们将窗口的标题设置为`Hello Qt`，那就太好了，对吧？让我们马上做这个：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/8b0e0f02-dc79-4f13-9f03-835d7126d6a5.png)

图 5.13

在第 26 行添加所示代码，以确保在测试新更改之前使用`make`实用程序构建项目：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/60c83655-7c91-4928-a48b-d833d29478d8.png)

图 5.14

# 布局

Qt 是跨平台应用程序框架，因此支持布局等概念，用于开发在所有平台上看起来一致的应用程序，而不管不同的屏幕分辨率如何。当我们开发基于 GUI/HMI 的 Qt 应用程序时，在一个系统中开发的应用程序不应该在另一个具有不同屏幕大小和分辨率的系统上看起来不同。这是通过布局在 Qt 框架中实现的。布局有不同的风格。这有助于开发人员通过在窗口或对话框中组织各种小部件来设计一个专业的 HMI/GUI。布局在安排其子小部件的方式上有所不同。当窗口或对话框被调整大小时，布局会调整其子小部件，以便它们不会被截断或失焦。

# 使用水平布局编写 GUI 应用程序

让我们编写一个 Qt 应用程序，在对话框中放置一些按钮。Qt 支持各种有用的布局管理器，它们充当一个无形的画布，在那里可以将许多`QWidgets`排列好，然后再将它们附加到窗口或对话框上。每个对话框或窗口只能有一个布局。每个小部件只能添加到一个布局中；然而，可以组合多个布局来设计专业的用户界面。

现在让我们开始编写代码。在这个项目中，我们将以模块化的方式编写代码，因此我们将创建三个文件，分别命名为`MyDlg.h`、`MyDlg.cpp`和`main.cpp`。

我们的计划如下：

1.  创建`QApplication`的单个实例。

1.  通过继承`QDialog`来创建一个自定义对话框。

1.  创建三个按钮。

1.  创建一个水平框布局。

1.  将这三个按钮添加到不可见的水平框布局中。

1.  将水平框布局的实例设置为我们对话框的布局。

1.  显示对话框。

1.  在`QApplication`上启动事件循环。

重要的是，我们要遵循清晰的代码规范，以便我们的代码易于理解，并且可以被任何人维护。由于我们将遵循行业最佳实践，让我们在一个名为`MyDlg.h`的头文件中声明对话框，在一个名为`MyDlg.cpp`的源文件中定义对话框，并在具有`main`函数的`main.cpp`中使用`MyDlg.cpp`。每当`MyDlg.cpp`需要一个头文件时，让我们养成一个习惯，只在`MyDlg.h`中包含所有的头文件；这样，我们在`MyDlg.cpp`中看到的唯一头文件将是`MyDlg.h`。

顺便说一句，我有没有告诉过你 Qt 遵循驼峰命名约定？是的，我刚刚提到了。到目前为止，你可能已经注意到所有的 Qt 类都以字母*Q*开头，因为 Qt 的发明者喜欢 Emacs 中的字母“Q”，他们对这种字体类型如此着迷，以至于决定在 Qt 中到处使用字母 Q。

最后一个建议。如果文件名和类名相似，其他人是否会更容易找到对话框类？我听到你说是。一切准备就绪！让我们开始编写我们的 Qt 应用程序。首先，参考以下截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/01449c0c-d8cc-49ab-88f5-c93ee98feea1.png)

图 5.15

在上面的截图中，我们声明了一个名为`MyDlg`的类。它有一个布局、三个按钮和一个构造函数。现在参考这个截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/388777d7-05fd-4a99-b1c9-52737aa5a452.png)

图 5.16

在上面的屏幕截图中，我们定义了`MyDlg`构造函数并实例化了布局和三个按钮。在第 27 到 29 行，我们将三个按钮添加到布局中。在第 31 行，我们将布局与对话框关联起来。就是这样。在下面的屏幕截图中，我们定义了我们的`main`函数，它创建了一个`QApplication`的实例：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/edcd8936-3b7f-4d0f-bad0-39ecf9eee797.png)

图 5.17

我们随后创建了我们的自定义对话框实例并显示了对话框。最后，在第 27 行，我们启动了`event`循环，以便`MyDlg`可以响应用户交互。请参考下面的屏幕截图：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/8584c26a-43b1-4414-9e26-8460a5c0c24f.png)

图 5.18

上面的屏幕截图展示了构建和执行过程，这就是我们可爱的应用程序。实际上，您可以尝试使用对话框来更好地理解水平布局。首先，水平拉伸对话框，注意所有按钮的宽度都会增加；然后，尝试减小对话框的宽度，以便注意所有按钮的宽度都会减小。这是任何布局管理器的工作。布局管理器安排小部件并检索窗口的大小，并将高度和宽度平均分配给其所有子小部件。布局管理器不断通知其所有子小部件有关任何调整大小的事件。但是，由于各个子小部件是否要调整大小或忽略布局调整信号是由各个子小部件自行决定的。

要检查此行为，请尝试垂直拉伸对话框。随着对话框高度的增加，对话框的高度应该增加，但按钮不会增加其高度。这是因为每个 Qt 小部件都有自己的首选大小策略；根据其大小策略，它们可能会响应或忽略某些布局调整信号。

如果您希望按钮在垂直方向上也能拉伸，`QPushButton`提供了一种实现这一点的方法。实际上，`QPushButton`与任何其他小部件一样都是从`QWidget`继承而来。`setSizePolicy()`方法是从其基类`QWidget`继承到`QPushButton`的：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ccfeabfa-d590-4456-9b8b-f6f6f3258623.png)

图 5.19

您注意到了第 37 行吗？是的，我在`MyDlg`的构造函数中设置了窗口标题，以使我们的`main`函数简洁干净。

在启动应用程序之前，请确保使用`make`工具构建了您的项目：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/89368655-a31e-4011-a774-cb04fd88e28b.png)

图 5.20

在突出显示的部分，我们已经覆盖了所有按钮的默认大小策略。在第 27 行，第一个参数`QSizePolicy::Expanding`是指水平策略，第二个参数是指垂直策略。要查找`QSizePolicy`的其他可能值，请参考 Qt API 参考中随时可用的助手，如下面的屏幕截图所示：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/7cb0d5de-7fbf-4099-b8da-a548569f6208.png)

图 5.21

# 使用垂直布局编写 GUI 应用程序

在上一节中，您学习了如何使用水平框布局。在本节中，您将看到如何在应用程序中使用垂直框布局。

事实上，水平和垂直框布局只是在安排小部件方面有所不同。例如，水平框布局将以从左到右的水平方式排列其子小部件，而垂直框布局将以从上到下的垂直方式排列其子小部件。

您可以从上一节中复制源代码，因为更改的性质是次要的。复制代码后，您的项目目录应如下所示：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/c79ef261-34b6-44bc-b475-a8cf4b911e2d.png)

图 5.22

让我从`MyDlg.h`头文件开始演示更改，如下所示：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/314e2d11-bb5a-49e1-8e07-e22b7882adc9.png)

图 5.23

我已经用`QVBoxLayout`替换了`QHBoxLayout`；就是这样。是的，让我们继续进行与`MyDlg.cpp`相关的文件更改：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/bf52c7e3-ddaa-4000-824a-20c60dde8836.png)

图 5.24

`main.cpp`中没有要做的更改；但是，我已经为您的参考展示了`main.cpp`，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/2819fa5e-adc9-47af-a302-7025f39bcbbb.png)

图 5.25

现在我们需要做的就是自动生成`Makefile`，然后按照以下步骤进行编译和运行程序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/24383093-c366-4be3-a4d2-ee8c3645aadb.png)

图 5.26

让我们执行我们全新的程序并检查输出。以下输出演示了`QVBoxLayout`以垂直从上到下的方式安排小部件。当窗口被拉伸时，所有按钮的宽度将根据窗口是拉伸还是收缩而增加/减少：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ad04f0f0-a3ba-4de1-b4fc-eed6927d8360.png)

图 5.27

# 使用框布局编写 GUI 应用程序

在前面的部分中，你学会了如何使用`QHBoxLayout`和`QVBoxLayout`。实际上，这两个类都是`QBoxLayout`的便利类。在`QHBoxLayout`的情况下，`QHBoxLayout`类已经将`QBoxLayout`作为子类，并将`QBoxLayout::Direction`配置为`QBoxLayout::LeftToRight`，而`QVBoxLayout`类已经将`QBoxLayout`作为子类，并将`QBoxLayout::Direction`配置为`QBoxLayout::TopToBottom`。

除了这些值，`QBoxLayout::Direction`还支持其他各种值，如下所示：

+   `QBoxLayout::LeftToRight`：这将从左到右排列小部件

+   `QBoxLayout::RightToLeft`：这将从右到左排列小部件

+   `QBoxLayout::TopToBottom`：这将从上到下排列小部件

+   `QBoxLayout::BottomToTop`：这将从下到上排列小部件

让我们使用`QBoxLayout`编写一个简单的程序，其中包含五个按钮。

让我们从`MyDlg.h`头文件开始。我在`MyDlg`类中声明了五个按钮指针和一个`QBoxLayout`指针：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/2edce8e9-ff7e-472a-80b3-12bf0af60d34.png)

图 5.28

让我们来看看我们的`MyDlg.cpp`源文件。如果你注意到下面截图中的第 21 行，`QBoxLayout`构造函数需要两个参数。第一个参数是您希望安排小部件的方向，第二个参数是一个可选参数，期望布局实例的父地址。

正如你可能已经猜到的那样，`this`指针指的是`MyDlg`实例指针，它恰好是布局的父级。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/4aa8c13b-aefc-4cff-883c-be180daac1e9.png)

图 5.29

再次，正如你可能已经猜到的那样，`main.cpp`文件不会改变，就像我们过去的练习一样，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/e999e104-0a48-435e-a458-f18c473c668b.png)

图 5.30

让我们编译并运行我们的程序，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/742ca3a6-8db9-470b-b9d9-5e95f7b1d9a8.png)

图 5.31

如果你注意到输出，它看起来像是水平框布局的输出，对吧？确实，因为我们已经将方向设置为`QBoxLayout::LeftToRight`。如果你将方向修改为，比如`QBoxLayout::RightToLeft`，那么按钮 1 将出现在右侧，按钮 2 将出现在按钮 1 的左侧，依此类推。因此，输出将如下截图所示：

+   如果方向设置为`QBoxLayout::RightToLeft`，你会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/e7d530e9-3822-4e9e-a26c-f9e335475df6.png)

图 5.32

+   如果方向设置为`QBoxLayout::TopToBottom`，你会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/01f3d529-5758-4182-a6f7-d9f4c497ee36.png)

图 5.33

+   如果方向设置为`QBoxLayout::BottomToTop`，你会看到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/2b8fd5b6-2899-4fb3-81ba-c85dfbb3c7c9.png)

图 5.34

在所有前述的情况中，按钮都是按照相同的顺序添加到布局中，从按钮 1 到按钮 5。然而，根据`QBoxLayout`构造函数中选择的方向，框布局将安排按钮，因此输出会有所不同。

# 使用网格布局编写 GUI 应用程序

网格布局允许我们以表格方式排列小部件。这很容易，就像盒式布局一样。我们所需要做的就是指示每个小部件必须添加到布局的行和列。由于行和列索引从零开始，因此行 0 的值表示第一行，列 0 的值表示第一列。理论够了；让我们开始写一些代码。

让我们声明 10 个按钮，并将它们添加到两行和五列中。除了特定的`QGridLayout`差异，其余的东西将与之前的练习保持一致，所以如果你已经理解了到目前为止讨论的概念，就继续创建`MyDlg.h`，`MyDl.cpp`和`main.cpp`。

让我在以下截图中呈现`MyDlg.h`源代码：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/863326d6-1360-4ce2-b3b8-a1bf5b3725b3.png)

图 5.35

以下是`MyDlg.cpp`的代码片段：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/0e8dfc86-ee70-4c4f-a55f-1ea4fa1cedd9.png)

图 5.36

`main.cpp`源文件内容将与我们之前的练习保持一致；因此，我已经跳过了`main.cpp`的代码片段。由于你已经熟悉了构建过程，我也跳过了它。如果你忘记了这一点，只需查看之前的部分以了解构建过程。

如果你已经正确输入了代码，你应该会得到以下输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/b0fe0162-c162-4aa2-aeca-f548532f7789.png)

图 5.37

实际上，网格布局还有更多的功能。让我们探索如何使按钮跨越多个单元格。我保证你将要看到的内容更有趣。

我将修改`MyDlg.h`和`MyDlg.cpp`，并保持`main.cpp`与之前的练习相同：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/41efa017-2b43-49b6-b2fd-bb0afcf8c63e.png)

图 5.38

这是我们的`MyDlg.cpp`： 

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ef957ac5-1cbe-4a32-87ff-6c183038f0f7.png)

图 5.39

注意 35 到 38 行。现在让我们详细讨论`addWidget()`函数。

35 行中，`pLayout->addWidget ( pBttn1, 0, 0, 1, 1 )`代码执行以下操作：

+   前三个参数将 Button 1 添加到网格布局的第一行和第一列

+   第四个参数`1`指示 Button 1 将只占据一行

+   第五个参数`1`指示 Button 1 将只占据一列

+   因此，很明显`pBttn1`应该呈现在单元格(0, 0)上，并且它应该只占据一个网格单元

36 行中，`pLayout->addWidget ( pBttn2, 0, 1, 1, 2 )`代码执行以下操作：

+   前三个参数将`Button 2`添加到网格布局的第一行和第二列

+   第四个参数指示`Button 2`将占据一行

+   第五个参数指示`Button 2`将占据两列（即第一行的第二列和第三列）

+   在底部，Button 2 将呈现在单元格(0,1)上，并且它应该占据一行和两列

37 行中，`pLayout->addWidget ( pBttn3, 0, 3, 2, 1 )`代码执行以下操作：

+   前三个参数将 Button 3 添加到网格布局的第一行和第四列

+   第四个参数指示 Button 3 将占据两行（即第一行和第四列以及第二行和第四列）

+   第五个参数指示 Button 3 将占据一列

38 行中，`pLayout->addWidget ( pBttn4, 1, 0, 1, 3 )`代码执行以下操作：

+   前三个参数将 Button 4 添加到网格布局的第二行和第一列

+   第四个参数指示 Button 4 将占据一行

+   第五个参数指示 Button 4 将占据三列（即第二行第一列，然后第二列和第三列）

查看程序的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/bf9c1280-349d-42fd-958d-6ee93db547b9.png)

图 5.40

# 信号和槽

信号和槽是 Qt 框架的一个组成部分。到目前为止，我们已经编写了一些简单但有趣的 Qt 应用程序，但我们还没有处理事件。现在是时候了解如何在我们的应用程序中支持事件。

让我们编写一个简单的应用程序，只有一个按钮。当按钮被点击时，检查是否可以在控制台上打印一些内容。

`MyDlg.h`头文件展示了如何声明`MyDlg`类：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/6d340f6a-76c4-4889-8adf-8670c32149a3.png)

图 5.41

下面的屏幕截图演示了如何定义`MyDlg`构造函数以向对话框窗口添加一个按钮：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/e476f68c-0cd6-4fc5-b722-e5f5178465cf.png)

图 5.42

`main.cpp`如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/46510322-00a5-434a-ae4a-3b47fdbc6a36.png)

图 5.43

让我们构建并运行我们的程序，然后稍后添加对信号和槽的支持。如果您正确地遵循了说明，您的输出应该类似于以下屏幕截图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/92f395d6-c157-4c55-92bf-c2faccdb77d0.png)

图 5.44

如果您点击按钮，您会注意到什么都没有发生，因为我们还没有在我们的应用程序中添加对信号和槽的支持。好的，现在是时候揭示一个秘密指令，它将帮助您使按钮响应按钮点击信号。等一下，现在是时候获取更多信息了。别担心，这与 Qt 有关。 

Qt 信号只是事件，而槽函数是事件处理程序函数。有趣的是，信号和槽都是普通的 C++函数；只有当它们被标记为信号或槽时，Qt 框架才能理解它们的目的并提供必要的样板代码。

Qt 中的每个小部件都支持一个或多个信号，并且还可以选择性地支持一个或多个槽。因此，在我们编写任何进一步的代码之前，让我们探索`QPushButton`支持哪些信号。

让我们使用 Qt 助手进行 API 参考：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ce2e7532-cc6b-48e1-8d08-6d0e7e04c7fe.png)

图 5.45

如果您观察前面的屏幕截图，它有一个目录部分，似乎涵盖了公共插槽，但我们没有看到任何信号列在那里。这是很多信息。如果目录部分没有列出信号，`QPushButton`就不会直接支持信号。然而，也许它的基类，也就是`QAbstractButton`，会支持一些信号。`QPushButton`类部分提供了大量有用的信息，比如头文件名，必须链接到应用程序的 Qt 模块，也就是必须添加到`.pro`文件的 qmake 条目等等。它还提到了`QPushButton`的基类。如果您继续向下滚动，您的 Qt 助手窗口应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/fe870f4e-5b3c-43ad-93ad-664b4a496456.png)

图 5.46

如果您观察下面的`Additional Inherited Members`部分，显然 Qt 助手暗示`QPushButton`从`QAbstractButton`继承了四个信号。因此，我们需要探索`QAbstractButton`支持的信号，以支持`QPushButton`中的信号。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ad8ebd1d-7061-4c54-8b6b-1c27cf8d5b17.png)

图 5.47

通过 Qt 助手的帮助，如前面的屏幕截图所示，很明显`QAbstractButton`类支持四个信号，这些信号也适用于`QPushButton`，因为`QPushButton`是`QAbstractButton`的子类。因此，让我们在这个练习中使用`clicked()`信号。

我们需要在`MyDlg.h`和`MyDlg.cpp`中进行一些微小的更改，以便使用`clicked()`信号。因此，我已经在以下屏幕截图中展示了这两个文件的更改部分：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/f915e03d-bbc3-4d57-90b6-37bd752bec05.png)

图 5.48

正如你所知，`QDebug`类用于调试目的。它为 Qt 应用程序提供了类似于`cout`的功能，但实际上并不需要用于信号和槽。我们在这里使用它们只是为了调试目的。在*图 5.48*中，第 34 行，`void MyDlg::onButtonClicked()`是我们打算用作事件处理程序函数的槽函数，必须在按钮点击时调用。

以下截图应该让你了解你需要在`MyDlg.cpp`中进行哪些更改以支持信号和槽：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/89b96bab-3c35-42b4-a1f4-2734ea8a7228.png)

图 5.49

如果你观察前面截图中的第 40 到 42 行，`MyDlg::onButtonClicked()`方法是一个槽函数，必须在按钮被点击时调用。但是除非按钮的`clicked()`信号映射到`MyDlg::onButtonClicked()`槽，否则 Qt 框架不会知道它必须在按钮被点击时调用`MyDlg::onButtonClicked()`。因此，在 32 到 37 行，我们将按钮信号`clicked()`与`MyDlg`实例的`onButtonClicked()`槽函数连接起来。connect 函数是从`QDialog`继承而来的。而`QDialog`又是从其最终基类`QObject`继承而来。

这个口头禅是，每个想要参与信号和槽通信的类必须是`QObject`或其子类。 `QObject`提供了相当多的信号和槽支持，`QObject`是`QtCore`模块的一部分。令人惊奇的是，Qt 框架甚至将信号和槽功能提供给了命令行应用程序。这就是为什么信号和槽支持内置到了最终基类`QObject`中，它是**QtCore**模块的一部分。

好的，让我们构建并运行我们的程序，看看信号在我们的应用程序中是否起作用：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/88c3c117-2e98-44c0-96b8-c94ccc793062.png)

图 5.50

有趣的是，我们并没有得到编译错误，但当我们点击按钮时，突出显示的警告消息会自动出现。这是 Qt 框架的一个提示，表明我们错过了一个必要的程序，这是使信号和槽工作的必要程序。

让我们回顾一下我们在头文件和源文件中自动生成`Makefile`的过程：

1.  `qmake -project`命令确保当前文件夹中的所有头文件和源文件都包含在`.pro`文件中。

1.  `qmake`命令会读取当前文件夹中的`.pro`文件，并为我们的项目生成`Makefile`。

1.  `make`命令将调用`make`实用程序。然后在当前目录中执行`Makefile`，根据`Makefile`中定义的制作规则构建我们的项目。

在步骤 1 中，`qmake`实用程序扫描我们所有的自定义头文件，并检查它们是否需要信号和槽支持。任何具有`Q_OBJECT`宏的头文件都会提示`qmake`实用程序需要信号和槽支持。因此，我们必须在我们的`MyDlg.h`头文件中使用`Q_OBJECT`宏：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/c609e242-3a7c-47a3-bf36-102d9a114c53.png)

图 5.51

一旦在头文件中完成了推荐的更改，我们需要确保发出`qmake`命令。现在`qmake`实用程序将打开`Ex8.pro`文件，获取我们的项目头文件和源文件。当`qmake`解析`MyDlg.h`并找到`Q_OBJECT`宏时，它将了解到我们的`MyDlg.h`需要信号和槽，然后它将确保在`MyDlg.h`上调用 moc 编译器，以便在一个名为`moc_MyDlg.cpp`的文件中自动生成样板代码。然后，它将继续在`Makefile`中添加必要的规则，以便自动生成的`moc_MyDlg.cpp`文件与其他源文件一起构建。

现在你知道了 Qt 信号和槽的秘密，继续尝试这个过程，并检查你的按钮点击是否打印了“Button clicked ...”消息。我已经根据建议进行了项目构建。在下面的截图中，我已经突出显示了幕后发生的有趣的事情；这些是在命令行中工作与使用花哨的 IDE 相比的一些优势：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/cc70f3aa-1d19-46b0-8387-b536c9a354ae.png)

图 5.52

现在是时候测试我们支持信号和槽的酷而简单的应用程序的输出了。输出如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/603ec985-f698-49bf-9ee8-63f7550d9bae.png)

图 5.53

恭喜！你可以为自己鼓掌。你已经学会了在 Qt 中做一些很酷的东西。

# 在 Qt 应用程序中使用堆叠布局

由于你已经了解了信号和槽，在这一部分，让我们探讨如何在具有多个窗口的应用程序中使用堆叠布局；每个窗口可以是**QWidget**或**QDialog**。每个页面可能有自己的子窗口部件。我们即将开发的应用程序将演示堆叠布局的使用以及如何在堆叠布局中从一个窗口导航到另一个窗口。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/935df883-b771-4cf5-96bd-b4cbd5d7165c.png)

图 5.54

这个应用程序将需要相当数量的代码，因此很重要的是要确保我们的代码结构良好，以满足结构和功能质量，尽量避免代码异味。

让我们创建四个可以堆叠在堆叠布局中的小部件/窗口，其中每个页面可以作为一个单独的类分割成两个文件：`HBoxDlg.h`和`HBoxDlg.cpp`等等。

让我们从`HBoxDlg.h`开始。由于你熟悉布局，在这个练习中，我们将创建每个对话框与一个布局，这样在导航子窗口之间时，你可以区分页面。否则，堆叠布局和其他布局之间将没有任何连接。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/2aea2186-e099-4660-bc7e-111cfc2fd449.png)

图 5.55

以下代码片段来自`HBoxDlg.cpp`文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/aeb95ddf-262e-4055-8cbc-1e1294272f7d.png)

图 5.56

同样，让我们按照以下方式编写`VBoxDlg.h`：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/dba374ca-cccd-4d62-a17c-e0443e24f94e.png)

图 5.57

让我们按照以下方式创建第三个对话框`BoxDlg.h`，使用框布局：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/6aa043a4-7eee-4cdf-a456-13a2ccadf497.png)

图 5.58

相应的`BoxDlg.cpp`源文件如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/c299d866-fdd1-4e52-9b7d-2ee0b5fb5d9a.png)

图 5.59

我们想要堆叠的第四个对话框是`GridDlg`，所以让我们看看`GridDlg.h`应该如何编写，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/75120737-fe0e-402a-b218-18eb21906a61.png)

图 5.60

相应的`GridDlg.cpp`将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/d73646f0-1461-4759-ac87-4b4c3c6dde92.png)

图 5.61

很好，我们已经创建了四个可以堆叠在`MainDlg`中的小部件。`MainDlg`将使用`QStackedLayout`，所以这个练习的关键是理解堆叠布局的工作原理。

让我们看看`MainDlg.h`应该如何编写：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/29eecb61-f873-4be2-8df3-6df5d52f26a6.png)

图 5.62

在`MainDlg`中，我们声明了三个槽函数，每个按钮一个，以支持四个窗口之间的导航逻辑。堆叠布局类似于选项卡小部件，不同之处在于选项卡小部件将提供自己的视觉方式来在选项卡之间切换，而在堆叠布局的情况下，切换逻辑由我们提供。

`MainDlg.cpp`将如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/2faacb2d-ee1a-4fb8-950a-a28a9eb4d3e0.png)图 5.63

你可以选择一个框布局来容纳这三个按钮，因为我们希望按钮对齐到右侧。但是，为了确保额外的空间被一些不可见的粘合剂占用，我们在第 44 行添加了一个伸展项。

在 30 至 33 行之间，我们将所有四个子窗口添加到堆叠布局中，以便一次只能显示一个窗口。`HBox`对话框添加在索引 0 处，`VBox`对话框添加在索引 1 处，依此类推。

第 53 至 58 行演示了如何将上一个按钮的点击信号与其对应的`MainDlg::onPrevPage()`槽函数连接起来。类似的连接必须为下一个和退出按钮进行配置：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/61a0e9cf-28b8-450b-9c2a-be944501b388.png)

图 5.64

第 78 行的`if`条件确保只有在我们处于第二个或更后面的子窗口时才发生切换逻辑。由于水平对话框位于索引 0，所以在当前窗口是水平对话框的情况下，我们无法导航到上一个窗口。类似的验证也适用于在第 85 行切换到下一个子窗口。

堆叠布局支持`setCurrentIndex()`方法以切换到特定的索引位置；或者，如果在您的情况下更有效，也可以尝试`setCurrentWidget()`方法。

`main.cpp`看起来简短而简单，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/7b477938-f928-40d0-8dae-73b39d05d476.png)

图 5.65

我们`main`函数的最好之处在于，无论应用逻辑的复杂性如何，`main`函数都没有任何业务逻辑。这使得我们的代码清晰易懂，易于维护。

# 代码覆盖率指标是好还是坏？

代码覆盖工具帮助开发者识别其自动化测试用例中的空白。毫无疑问，很多时候它会提供有关缺失测试场景的线索，这最终会进一步加强自动化测试用例。但是，当组织开始将代码覆盖率作为检查测试覆盖率有效性的衡量标准时，有时会导致开发者走向错误的方向。根据我的实际咨询经验，我所学到的是，许多开发者开始为构造函数、私有和受保护函数编写测试用例，以展示更高的代码覆盖率。在这个过程中，开发者开始追求数字，失去了 TDD 的最终目标。

在一个具有 20 个方法的类的特定源中，可能只有 10 个方法适合单元测试，而其他方法是复杂的功能。在这种情况下，代码覆盖工具将只显示 50%的代码覆盖率，这完全符合 TDD 哲学。然而，如果组织政策强制要求最低 75%的代码覆盖率，那么开发者除了为了展示良好的代码覆盖率而对构造函数、析构函数、私有、受保护和复杂函数进行测试外别无选择。

测试私有和受保护方法的麻烦在于它们往往会更改，因为它们被标记为实现细节。当私有和受保护方法发生严重更改时，就需要修改测试用例，这使得开发者在维护测试用例方面更加困难。

因此，代码覆盖工具是非常好的开发者工具，可以找到测试场景的空白，但是是否编写测试用例或忽略某些方法的测试用例取决于方法的复杂性，应该由开发者自行决定。然而，如果代码覆盖率被用作项目指标，往往会导致开发者采取错误的方式来展示更好的覆盖率，导致糟糕的测试用例实践。

# 编写一个结合多个布局的简单数学应用

在本节中，让我们探讨如何编写一个简单的数学应用。作为这个练习的一部分，我们将使用`QLineEdit`和`QLabel`小部件以及`QFormLayout`。我们需要设计一个 UI，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/4100769e-5138-49d9-a251-44d61f3dec11.png)

图 5.66

`QLabel`是一个通常用于静态文本的小部件，而`QLineEdit`允许用户提供单行输入。如前面的屏幕截图所示，我们将使用`QVBoxLayout`作为主要布局，以便以垂直方式排列`QFormLayout`和`QBoxLayout`。当您需要创建一个表单，左侧将有标题，右侧将有一些小部件时，`QFormLayout`非常方便。`QGridLayout`也可能能够胜任，但在这种情况下，`QFormLayout`易于使用。

在这个练习中，我们将创建三个文件，分别是`MyDlg.h`，`MyDlg.cpp`和`main.cpp`。让我们从`MyDlg.h`源代码开始，然后转移到其他文件：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/96ddfeef-c109-419e-b4d9-de12497f3db1.png)

图 5.67

在上图中，声明了三种布局。垂直框布局用作主要布局，而框布局用于以右对齐的方式排列按钮。表单布局用于添加标签，即行编辑小部件。这个练习还将帮助您了解如何组合多个布局来设计专业的 HMI。

Qt 没有关于可以在单个窗口中组合的布局数量的记录限制。然而，如果可能的话，考虑使用最少数量的布局设计 HMI 是一个好主意，如果您正在努力开发一个占用内存较小的应用程序。否则，在您的应用程序中使用多个布局当然没有坏处。

在下面的屏幕截图中，您将了解`MyDlg.cpp`源文件应该如何实现。在`MyDlg`构造函数中，所有按钮都被实例化并在框布局中进行右对齐。表单布局用于以网格方式容纳`QLineEdit`小部件及其对应的`QLabel`小部件。`QLineEdit`小部件通常用于提供单行输入；在这个特定的练习中，它们帮助我们提供必须根据用户的选择进行加法、减法等操作的数字输入。

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/1bd457e2-cdac-4911-81d9-d95b62776cfc.png)

图 5.68

我们的`main.cpp`源文件的最好部分是，它基本上保持不变，无论我们的应用程序的复杂性如何。在这个练习中，我想告诉你一个关于`MyDlg`的秘密。你有没有注意到`MyDlg`构造函数是在堆栈中实例化而不是在堆中？这样做的想法是，当`main()`函数退出时，`main`函数使用的堆栈会被解开，最终释放堆栈中存在的所有堆栈变量。当`MyDlg`被释放时，会导致调用`MyDlg`析构函数。在 Qt 框架中，每个小部件构造函数都接受一个可选的父小部件指针，顶层窗口析构函数使用它来释放其子小部件。有趣的是，Qt 维护一个类似树的数据结构来管理所有子小部件的内存。因此，如果一切顺利，Qt 框架将自动处理释放所有子小部件的内存位置。

这有助于 Qt 开发人员专注于应用程序方面，而 Qt 框架将负责内存管理。

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/5a6cf1b9-cb5f-4713-a512-8663c1b63ae6.png)

图 5.69

您是不是很兴奋地想要检查我们新应用程序的输出？如果您构建并执行应用程序，那么您应该会得到类似以下屏幕截图的输出。当然，我们还没有添加信号和槽支持，但设计 GUI 以满足我们的要求，然后将焦点转移到事件处理是一个好主意：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/077b1f99-c166-4c60-832f-0930639075ab.png)

图 5.70

如果你仔细观察，尽管按钮是按从右到左的顺序布局在`QBoxLayout`上，但按钮并没有对齐到右侧。这种行为的原因是当窗口被拉伸时，框布局似乎已经将额外的水平空间分配给了所有的按钮。因此，让我们在框布局的最左侧位置添加一个伸展项，这样伸展项将占据所有额外的空间，使按钮没有空间可以扩展。这样就可以得到右对齐的效果。在添加了伸展项之后，代码将如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/5a935fb3-e5d6-4f0d-be92-494731b793a2.png)

图 5.71

继续检查你的输出是否与下面的屏幕截图一样。有时作为开发人员，我们会兴奋地匆忙看到输出，忘记编译我们的更改，所以确保项目再次构建。如果你在输出中没有看到任何变化，别担心；尝试水平拉伸窗口，你应该会看到右对齐的效果，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/735e0a2a-dc8e-4854-a628-7624502e50a9.png)

图 5.72

现在我们有了一个看起来不错的应用程序，让我们为按钮点击添加信号和槽支持。让我们不要急于包括添加和减去功能。我们将使用一些`qDebug()`打印语句来检查信号和槽是否连接正确，然后逐渐用实际功能替换它们。

如果你还记得之前的信号和槽练习，任何有兴趣支持信号和槽的 Qt 窗口都必须是`QObject`，并且应该在`MyDlg.h`头文件中包含`Q_OBJECT`宏，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/9836047f-2b2b-4b2f-95cd-d3fc669ab05e.png)

图 5.73

从第 41 行到 45 行，私有部分声明了四个槽方法。槽函数是常规的 C++函数，可以像其他 C++函数一样直接调用。然而，在这种情况下，槽函数只打算与`MyDlg`一起调用。因此它们被声明为私有函数，但如果你认为其他人可能会发现连接到你的公共槽有用，它们也可以被声明为公共函数。

很好，如果你已经走到这一步，那说明你已经理解了到目前为止讨论的内容。好的，让我们继续在`MyDlg.cpp`中实现槽函数的定义，然后将`clicked()`按钮的信号连接到相应的槽函数：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/9ee7de87-238a-4583-9434-4a81be20275b.png)

图 5.74

现在是时候将信号连接到它们各自的槽上了。正如你可能已经猜到的那样，我们需要在`MyDlg`构造函数中使用`connect`函数，如下面的屏幕截图所示，以将按钮点击传递到相应的槽中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/12f256c1-54b9-41ea-bc82-cac4025cc12c.png)

图 5.75

我们已经准备好了。是的，现在是展示时间。由于我们已经处理了大部分的事情，让我们编译并检查一下我们小小的 Qt 应用程序的输出：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/08f502c2-1d47-4b80-bd4c-6b2ef28bbaa9.png)

图 5.76

糟糕！我们遇到了一些链接错误。这个问题的根本原因是我们在启用应用程序的信号和槽支持后忘记调用`qmake`。别担心，让我们调用`qmake`和`make`来运行我们的应用程序：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/0736093f-595d-4648-b932-3a7a4cfa7b37.png)

图 5.77

很好，我们已经解决了问题。这次 make 工具似乎没有发出任何声音，我们能够启动应用程序。让我们检查信号和槽是否按预期工作。为此，点击“添加”按钮，看看会发生什么：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/d937f0b1-ee83-4f5c-8f13-1c1cad9a8043.png)

图 5.78

哇！当我们点击“添加”按钮时，`qDebug()`控制台消息确认了`MyDlg::onAddButtonClicked()`槽被调用。如果你好奇检查其他按钮的槽，请继续尝试点击其他按钮。

我们的应用程序将不完整没有业务逻辑。因此，让我们在`MyDlg::onAddButtonClicked()`槽函数中添加业务逻辑，执行加法并显示结果。一旦你学会了如何集成添加的业务逻辑，你可以遵循相同的方法并实现其余的槽函数：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/3b2dccec-e47a-48a1-970d-a5f1ec9ee1d1.png)

图 5.79

在`MyDlg::onAddButtonClicked()`函数中，集成了业务逻辑。在第 82 和 83 行，我们试图提取用户在`QLineEdit`小部件中输入的值。`QLineEdit`中的`text()`函数返回`QString`**。** `QString`对象提供了`toInt()`函数，非常方便地提取了由`QString`表示的整数值。一旦值被添加并存储在结果变量中，我们需要将结果整数值转换回`QString`，如第 86 行所示，以便结果可以被输入到`QLineEdit`中，如第 88 行所示。

同样，你可以继续集成其他数学运算的业务逻辑。一旦你彻底测试了应用程序，你可以删除`qDebug()`控制台的输出。我们添加了`qDebug()`消息用于调试目的，因此现在可以清理它们。

# 摘要

在本章中，你学会了使用 Qt 应用程序框架开发 C++ GUI 应用程序。以下是关键要点。

+   你学会了在 Linux 中安装 Qt 和所需的工具。

+   你学会了使用 Qt Framework 编写简单的基于控制台的应用程序。

+   你学会了使用 Qt Framework 编写简单的基于 GUI 的应用程序。

+   你学会了使用 Qt 信号和槽机制处理事件，并且了解了元对象编译器如何帮助我们生成信号和槽所需的关键样板代码。

+   你学会了在应用程序开发中使用各种 Qt 布局，以开发在许多 Qt 支持的平台上看起来很棒的吸引人的 HMI。

+   你学会了将多个布局组合在一个 HMI 中，以开发专业的 HMI。

+   你学会了许多 Qt 小部件以及它们如何帮助你开发令人印象深刻的 HMI。

+   总的来说，你学会了使用 Qt 应用程序框架开发跨平台 GUI 应用程序。

在下一章中，你将学习 C++中的多线程编程和 IPC。


# 第六章：测试驱动开发

本章将涵盖以下主题：

+   测试驱动开发的简要概述

+   关于 TDD 的常见神话和问题

+   开发人员是否需要更多的工作来编写单元测试

+   代码覆盖率指标是好是坏

+   TDD 是否适用于复杂的遗留项目？

+   TDD 是否适用于嵌入式产品或涉及硬件的产品

+   C++的单元测试框架

+   Google 测试框架

+   在 Ubuntu 上安装 Google 测试框架

+   将 Google 测试和模拟一起构建为一个单一的静态库的过程，而无需安装它们

+   使用 Google 测试框架编写我们的第一个测试用例

+   在 Visual Studio IDE 中使用 Google 测试框架

+   TDD 的实践

+   测试具有依赖关系的遗留代码

让我们深入探讨这些 TDD 主题。

# TDD

**测试驱动开发**（**TDD**）是一种极限编程实践。在 TDD 中，我们从一个测试用例开始，逐步编写所需的生产代码，以使测试用例成功。这个想法是应该一次专注于一个测试用例或场景，一旦测试用例通过，就可以转移到下一个场景。在这个过程中，如果新的测试用例通过，我们不应该修改生产代码。换句话说，在开发新功能或修复错误的过程中，我们只能出于两个原因修改生产代码：要么确保测试用例通过，要么重构代码。TDD 的主要重点是单元测试；然而，它可以在一定程度上扩展到集成和交互测试。 

以下图表直观地展示了 TDD 的过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/e5f04dbe-4d3b-4f54-844f-4fe142c52e71.png)

当 TDD 被严格遵循时，可以实现代码的功能和结构质量。非常重要的是，在编写生产代码之前先编写测试用例，而不是在开发阶段末尾编写测试用例。这会产生很大的差异。例如，当开发人员在开发结束时编写单元测试用例时，测试用例很可能不会发现代码中的任何缺陷。原因是当测试用例在开发结束时编写时，开发人员会下意识地倾向于证明他们的代码是正确的。而当开发人员提前编写测试用例时，由于尚未编写代码，他们会从最终用户的角度出发思考，这将鼓励他们从需求规范的角度提出许多场景。

换句话说，针对已经编写的代码编写的测试用例通常不会发现任何错误，因为它倾向于证明编写的代码是正确的，而不是根据要求进行测试。开发人员在编写代码之前考虑了各种情况，这有助于他们逐步编写更好的代码，确保代码确实考虑到这些情况。然而，当代码存在漏洞时，测试用例将帮助他们发现问题，因为如果测试用例不符合要求，测试用例将失败。

TDD 不仅仅是使用一些单元测试框架。在开发或修复代码时，它需要文化和心态的改变。开发人员的重点应该是使代码在功能上正确。一旦以这种方式开发了代码，强烈建议开发人员还应专注于通过重构代码来消除任何代码异味；这将确保代码的结构质量也很好。从长远来看，代码的结构质量将使团队更快地交付功能。

# 关于 TDD 的常见神话和问题

TDD 的许多神话和常见疑问在每个人开始 TDD 之旅时都会出现在脑海中。让我澄清我遇到的大部分问题，因为我咨询了全球许多产品巨头。

# 开发人员是否需要更多的工作来编写单元测试？

大多数开发人员心中常常产生的疑问之一是，“当我们采用 TDD 时，我应该如何估计我的努力？”由于开发人员应该在 TDD 的一部分写单元和集成测试用例，你担心如何与客户或管理层协商额外的努力，以编写测试用例而不仅仅是编写代码。别担心，你并不孤单；作为一名自由软件顾问，许多开发人员向我提出了这个问题。

作为开发人员，你手动测试你的代码；现在改为编写自动化测试用例。好消息是，这是一次性的努力，保证能在长远帮助你。虽然开发人员需要重复手动测试他们的代码，每次他们改变代码时，已经存在的自动化测试用例将帮助开发人员在集成新的代码时立即给予他们反馈。

底线是，这需要额外的努力，但从长远来看，它有助于减少所需的努力。

# TDD 对复杂的遗留项目有效吗？

当然！TDD 适用于任何类型的软件项目或产品。TDD 不仅适用于新产品或项目；它也被证明在复杂的遗留项目或产品中更加有效。在维护项目中，绝大部分时间都要修复缺陷，很少需要支持新功能。即使在这样的遗留代码中，修复缺陷时也可以遵循 TDD。

作为开发人员，你会很容易同意，一旦你能够重现问题，从开发人员的角度来看，问题几乎已经解决了一半。因此，你可以从能够重现问题的测试用例开始，然后调试和修复问题。当你修复问题时，测试用例将开始通过；现在是时候考虑可能会重现相同缺陷的另一个测试用例，并重复这个过程。

# TDD 是否适用于嵌入式或涉及硬件的产品？

就像应用软件可以从 TDD 中受益一样，嵌入式项目或涉及硬件交互的项目也可以从 TDD 方法中受益。有趣的是，嵌入式项目或涉及硬件的产品更多地受益于 TDD，因为他们可以通过隔离硬件依赖性来测试大部分代码而无需硬件。TDD 有助于减少上市时间，因为团队可以在不等待硬件的情况下测试大部分软件。由于大部分代码已经在没有硬件的情况下进行了彻底测试，这有助于避免在板卡启动发生时出现最后一分钟的意外或应急情况。这是因为大部分情况已经得到了彻底测试。

根据软件工程的最佳实践，一个良好的设计是松散耦合和高内聚的。虽然我们都努力编写松散耦合的代码，但并不总是可能编写绝对独立的代码。大多数情况下，代码都有某种依赖。在应用软件的情况下，依赖可能是数据库或 Web 服务器；在嵌入式产品的情况下，依赖可能是一块硬件。但是使用依赖反转，可以将**被测试的代码**（**CUT**）与其依赖隔离开来，使我们能够在没有依赖的情况下测试代码，这是一种强大的技术。只要我们愿意重构代码使其更模块化和原子化，任何类型的代码和项目或产品都将受益于 TDD 方法。

# C++的单元测试框架

作为 C++开发人员，在选择单元测试框架时，你有很多选择。虽然还有许多其他框架，但这些是一些流行的框架：CppUnit、CppUnitLite、Boost、MSTest、Visual Studio 单元测试和 Google 测试框架。

尽管是较旧的文章，我建议您查看[`gamesfromwithin.com/exploring-the-c-unit-testing-framework-jungle`](http://gamesfromwithin.com/exploring-the-c-unit-testing-framework-jungle)和[`accu.org/index.php/journals/`](https://accu.org/index.php/journals/)。它们可能会给您一些关于这个主题的见解。

毫无疑问，Google 测试框架是 C++最受欢迎的测试框架之一，因为它支持多种平台，得到积极开发，并且最重要的是由 Google 支持。

在本章中，我们将使用 Google 测试和 Google 模拟框架。然而，本章讨论的概念适用于所有单元测试框架。我们将深入研究 Google 测试框架及其安装过程。

# Google 测试框架

Google 测试框架是一个开源的测试框架，适用于许多平台。TDD 只关注单元测试和在一定程度上的集成测试，但 Google 测试框架可以用于各种测试。它将测试用例分类为小型、中型、大型、忠诚度、韧性、精度和其他类型的测试用例。单元测试用例属于小型，集成测试用例属于中型，复杂功能和验收测试用例属于大型。

它还将 Google 模拟框架捆绑在一起。由于它们在技术上来自同一个团队，它们可以无缝地相互配合。然而，Google 模拟框架可以与其他测试框架一起使用，如 CppUnit。

# 在 Ubuntu 上安装 Google 测试框架

您可以从[`github.com/google/googletest`](https://github.com/google/googletest)下载 Google 测试框架的源代码。然而，最佳的下载方式是通过终端命令行中的 Git 克隆：

```cpp
git clone https://github.com/google/googletest.git
```

Git 是一个开源的分布式版本控制系统（DVCS）。如果您还没有在系统上安装它，您可以在[`git-scm.com/`](https://git-scm.com/)上找到更多关于为什么应该安装它的信息。然而，在 Ubuntu 中，可以使用`sudo apt-get install git`命令轻松安装它。

一旦代码像*图 7.1*所示下载，您就可以在`googletest`文件夹中找到 Google 测试框架的源代码：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/9b32c917-be3d-4b38-b5f6-a948915bba56.png)

图 7.1

`googletest`文件夹中有`googletest`和`googlemock`框架分别在不同的文件夹中。现在我们可以调用`cmake`实用程序来配置我们的构建并自动生成`Makefile`，如下所示：

```cpp
cmake CMakeLists.txt
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/b0792f8f-c9c0-4ac1-a1e3-a407b3beeb45.png)

图 7.2

当调用`cmake`实用程序时，它会检测构建 Google 测试框架所需的 C/C++头文件及其路径。此外，它还会尝试定位构建源代码所需的工具。一旦找到所有必要的头文件和工具，它将自动生成`Makefile`。一旦有了`Makefile`，您就可以使用它来编译和安装 Google 测试和 Google 模拟到您的系统上：

```cpp
sudo make install
```

以下截图演示了如何在系统上安装 Google 测试：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/fa68c8ee-430c-459c-9f0c-a6236c487505.png)

图 7.3

在上图中，`make install`命令已经编译并安装了`libgmock.a`和`libgtest.a`静态库文件到`/usr/local/lib`文件夹中。由于`/usr/local/lib`文件夹路径通常在系统的 PATH 环境变量中，因此可以从系统中的任何项目中访问它。

# 如何将 Google 测试和模拟一起构建为一个单一的静态库而不安装？

如果您不喜欢在常用系统文件夹上安装`libgmock.a`和`libgtest.a`静态库文件以及相应的头文件，那么还有另一种构建 Google 测试框架的方式。

以下命令将创建三个对象文件，如*图 7.4*所示：

```cpp
g++ -c googletest/googletest/src/gtest-all.cc googletest/googlemock/src/gmock-all.cc googletest/googlemock/src/gmock_main.cc -I googletest/googletest/ -I googletest/googletest/include -I googletest/googlemock -I googletest/googlemock/include -lpthread -
```

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/bd4a03db-5477-4a53-b46a-11eac3a604d5.png)

图 7.4

下一步是使用以下命令将所有对象文件合并到一个单独的静态库中：

```cpp
ar crf libgtest.a gmock-all.o gmock_main.o gtest-all.o
```

如果一切顺利，您的文件夹应该有全新的`libgtest.a`静态库，如*图 7.5*所示。让我们了解以下命令说明：

```cpp
g++ -c googletest/googletest/src/gtest-all.cc    googletest/googlemock/src/gmock-all.cc googletest/googlemock/src/gmock_main.cc -I googletest/googletest/ -I googletest/googletest/include 
-I googletest/googlemock  -I googletest/googlemock/include -lpthread -std=c++14
```

上述命令将帮助我们创建三个对象文件：**gtest-all.o**，**gmock-all.o**和**gmock_main.o**。`googletest`框架使用了一些 C++11 特性，我故意使用了 c++14 以确保安全。`gmock_main.cc`源文件有一个 main 函数，将初始化 Google 模拟框架，然后内部初始化 Google 测试框架。这种方法的最大优点是我们不必为我们的单元测试应用程序提供 main 函数。请注意编译命令包括以下`include`路径，以帮助 g++编译器定位 Google 测试和 Google 模拟框架中必要的头文件：

```cpp
-I googletest/googletest
-I googletest/googletest/include
-I googletest/googlemock
-I googletest/googlemock/include
```

现在下一步是创建我们的`libgtest.a`静态库，将 gtest 和 gmock 框架捆绑到一个单独的静态库中。由于 Google 测试框架使用了多个线程，因此必须将`pthread`库链接到我们的静态库中：

```cpp
ar crv libgtest.a gtest-all.o gmock_main.o gmock-all.o
```

`ar`存档命令有助于将所有对象文件合并到一个单独的静态库中。

以下图片在终端上实际演示了讨论的过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/24a914fe-482c-49d9-affa-a963e310e2ba.png)

图 7.5

# 使用 Google 测试框架编写我们的第一个测试用例

学习 Google 测试框架非常容易。让我们创建两个文件夹：一个用于生产代码，另一个用于测试代码。这样做的目的是将生产代码与测试代码分开。创建了这两个文件夹后，从`Math.h`头文件开始，如*图 7.6*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/806d97a0-e7f7-4453-960e-5a56c85cfac1.png)

图 7.6

`Math`类只有一个函数，用于演示单元测试框架的用法。首先，我们的`Math`类有一个简单的 add 函数，足以理解 Google 测试框架的基本用法。

在 Google 测试框架的位置，您也可以使用 CppUnit，并集成模拟框架，如 Google 模拟框架、mockpp 或 opmock。

让我们在以下`Math.cpp`源文件中实现我们简单的`Math`类：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/08ebccb7-7a22-413b-855e-aa8f697b6ade.png)

图 7.7

前面的两个文件应该在`src`文件夹中，如*图 7.8*所示。所有的生产代码都放在`src`文件夹中，`src`文件夹可以包含任意数量的文件。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/646383e1-8841-4cea-8f06-a9229e5b42c1.png)

图 7.8

由于我们已经编写了一些生产代码，让我们看看如何为前面的生产代码编写一些基本的测试用例。作为一般的最佳实践，建议将测试用例文件命名为`MobileTest`或`TestMobile`，以便任何人都能轻松预测文件的目的。在 C++或 Google 测试框架中，不强制将文件名和类名保持一致，但通常被认为是最佳实践，因为它可以帮助任何人通过查看文件名来定位特定的类。

Google 测试框架和 Google 模拟框架是同一个团队的产品，因此这种组合在大多数平台上，包括嵌入式平台，都能很好地工作。

由于我们已经将 Google 测试框架编译为静态库，让我们直接从`MathTest.cpp`源文件开始：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/766ad4f5-c24a-4536-abd7-b58f87946592.png)

图 7.9

在*图 7.9*中，第 18 行，我们包含了来自 Google 测试框架的 gtest 头文件。在 Google 测试框架中，测试用例使用`TEST`宏编写，该宏接受两个参数。第一个参数，即`MathTest`，表示测试模块名称，第二个参数是测试用例的名称。测试模块帮助我们将一组相关的测试用例分组到一个模块下。因此，为了提高测试报告的可读性，为测试模块和测试用例命名非常重要。

正如您所知，`Math`是我们打算测试的类；我们在*第 22 行*实例化了`Math`对象。在*第 25 行*，我们调用了 math 对象上的 add 函数，这个函数应该返回实际结果。最后，在*第 27 行*，我们检查了预期结果是否与实际结果匹配。Google 测试宏`EXPECT_EQ`将在预期和实际结果匹配时标记测试用例为通过；否则，框架将标记测试用例的结果为失败。

好了，我们现在已经准备好了。让我们看看如何编译和运行我们的测试用例。以下命令应该帮助您编译测试用例：

```cpp
g++ -o tester.exe src/Math.cpp test/MathTest.cpp -I googletest/googletest 
-I googletest/googletest/include -I googletest/googlemock     
-I googletest/googlemock/include -I src libgtest.a -lpthread

```

请注意，编译命令包括以下包含路径：

```cpp
-I googletest/googletest
-I googletest/googletest/include
-I googletest/googlemock
-I googletest/googlemock/include
-I src
```

另外，需要注意的是，我们还链接了我们的 Google 测试静态库`libgtest.a`和 POSIX pthreads 库，因为 Google 测试框架使用了多个。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ace1d532-0d14-4853-9a53-a00201640fc8.png)**图 7.10**

恭喜！我们成功编译并执行了我们的第一个测试用例。

# 在 Visual Studio IDE 中使用 Google 测试框架

首先，我们需要从[`github.com/google/googletest/archive/master.zip`](https://github.com/google/googletest/archive/master.zip)下载 Google 测试框架的`.zip`文件。下一步是在某个目录中解压`.zip`文件。在我的情况下，我已将其解压到`googletest`文件夹，并将`googletest googletest-mastergoogletest-master`的所有内容复制到`googletest`文件夹中，如*图 7.11*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/c00daec6-8797-4f22-bed7-b9bff08a2eb8.png)

图 7.11

现在是在 Visual Studio 中创建一个简单项目的时候了。我使用的是 Microsoft Visual Studio Community 2015。但是，这里遵循的步骤对于其他版本的 Visual Studio 来说基本上是一样的，只是选项可能在不同的菜单中可用。

您需要通过转到新项目| Visual Studio | Windows | Win32 | Win32 控制台应用程序来创建一个名为`MathApp`的新项目，如*图 7.12*所示。该项目将成为要测试的生产代码。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/5110e15b-45e8-40bc-9d8a-9c82679ea631.png)

图 7.12

让我们将`MyMath`类添加到`MathApp`项目中。`MyMath`类是将在`MyMath.h`中声明并在`MyMath.cpp`中定义的生产代码。

让我们来看一下*图 7.13*中显示的`MyMath.h`头文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/0dd5bc3a-c7c9-4543-bc80-b1c199347f6e.png)

图 7.13

`MyMath`类的定义如*图 7.14*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/2cb5e1f9-a9b1-4c7c-819b-b04e4ff475a2.png)

图 7.14

由于这是一个控制台应用程序，必须提供主函数，如*图 7.15*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/d09021c7-205c-4807-9938-a2738721ded1.png)

图 7.15

接下来，我们将向`MathApp`项目解决方案中添加一个名为`GoogleTestLib`的静态库项目，如*图 7.16*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/7123a677-1300-47f9-8877-ee7d7d6e1423.png)

图 7.16

接下来，我们需要将 Google 测试框架的以下源文件添加到我们的静态库项目中：

```cpp
C:Usersjegangoogletestgoogletestsrcgtest-all.cc
C:Usersjegangoogletestgooglemocksrcgmock-all.cc
C:Usersjegangoogletestgooglemocksrcgmock_main.cc
```

为了编译静态库，我们需要在`GoogleTestLib/Properties/VC++ Directories/Include`目录中包含以下头文件路径：

```cpp
C:Usersjegangoogletestgoogletest
C:Usersjegangoogletestgoogletestinclude
C:Usersjegangoogletestgooglemock
C:Usersjegangoogletestgooglemockinclude
```

您可能需要根据在系统中复制/安装 Google 测试框架的位置来自定义路径。

现在是时候将`MathTestApp` Win32 控制台应用程序添加到`MathApp`解决方案中了。我们需要将`MathTestApp`设置为`StartUp`项目，以便可以直接执行此应用程序。在我们向`MathTestApp`项目添加名为`MathTest.cpp`的新源文件之前，让我们确保`MathTestApp`项目中没有源文件。

我们需要配置与我们添加到`GoogleTestLib`静态库的相同一组 Google 测试框架包含路径。除此之外，我们还必须将`MathApp`项目目录添加为测试项目将引用`MathApp`项目中的头文件，如下所示。但是，请根据您在系统中为此项目遵循的目录结构自定义路径：

```cpp
C:Usersjegangoogletestgoogletest
C:Usersjegangoogletestgoogletestinclude
C:Usersjegangoogletestgooglemock
C:Usersjegangoogletestgooglemockinclude
C:ProjectsMasteringC++ProgrammingMathAppMathApp
```

在`MathAppTest`项目中，确保您已经添加了对`MathApp`和`GoogleTestLib`的引用，以便在它们发生更改时，`MathAppTest`项目将编译其他两个项目。

太好了！我们几乎完成了。现在让我们实现`MathTest.cpp`，如*图 7.17*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/e95073ff-6873-4b90-b8f2-74bbb21d27a8.png)

图 7.17

现在一切准备就绪；让我们运行测试用例并检查结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/2bb7e110-1c85-479b-b752-c94fb2fc454d.png)

图 7.18

# TDD 实践

让我们看看如何开发一个遵循 TDD 方法的**逆波兰表达式**（**RPN**）计算器应用程序。RPN 也被称为后缀表示法。RPN 计算器应用程序的期望是接受后缀数学表达式作为输入，并将计算结果作为输出返回。

逐步地，我想演示在开发应用程序时如何遵循 TDD 方法。作为第一步，我想解释项目目录结构，然后我们将继续。让我们创建一个名为`Ex2`的文件夹，具有以下结构：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/b8f79361-8f56-4bb9-92e3-7aa286bb9afb.png)

图 7.19

`googletest`文件夹是具有必要的`gtest`和`gmock`头文件的 gtest 测试库。现在`libgtest.a`是我们在上一个练习中创建的 Google 测试静态库。我们将使用`make`实用程序来构建我们的项目，因此我已经将`Makefile`放在项目`home`目录中。`src`目录将保存生产代码，而测试目录将保存我们将要编写的所有测试用例。 

在我们开始编写测试用例之前，让我们拿一个后缀数学表达式“2 5 * 4 + 3 3 * 1 + /”并了解我们将应用于评估 RPN 数学表达式的标准后缀算法。根据后缀算法，我们将逐个标记地解析 RPN 数学表达式。每当我们遇到一个操作数（数字）时，我们将把它推入堆栈。每当我们遇到一个运算符时，我们将从堆栈中弹出两个值，应用数学运算，将中间结果推回堆栈，并重复该过程，直到 RPN 表达式中的所有标记都被评估。最后，当输入字符串中没有更多的标记时，我们将弹出该值并将其打印为结果。该过程在以下图中逐步演示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/451d51b6-eb60-4485-a956-9a907bfcd8eb.png)

图 7.20

首先，让我们拿一个简单的后缀数学表达式，并将情景转化为一个测试用例：

```cpp
Test Case : Test a simple addition
Input: "10 15 +"
Expected Output: 25.0
```

让我们将前述测试用例翻译为测试文件夹中的 Google 测试，如下所示：

```cpp
test/RPNCalculatorTest.cpp

TEST ( RPNCalculatorTest, testSimpleAddition ) { 
         RPNCalculator rpnCalculator; 
         double actualResult = rpnCalculator.evaluate ( "10 15 +" ); 
         double expectedResult = 25.0; 
         EXPECT_EQ ( expectedResult, actualResult ); 
}
```

为了编译前述测试用例，让我们在`src`文件夹中编写所需的最小生产代码：

```cpp
src/RPNCalculator.h

#include <iostream>
#include <string>
using namespace std;

class RPNCalculator {
  public:
      double evaluate ( string );
};
```

由于 RPN 数学表达式将作为以空格分隔的字符串提供，因此评估方法将接受一个字符串输入参数：

```cpp
src/RPNCalculator.cpp

#include "RPNCalculator.h"

double RPNCalculator::evaluate ( string rpnMathExpression ) {
    return 0.0;
}
```

以下的`Makefile`类帮助我们在编译生产代码时每次运行测试用例：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/2f819f7b-c23d-4cbb-9239-bce7db1f192b.png)

图 7.21

现在让我们构建并运行测试用例，并检查测试用例的结果：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ec54c683-c310-4fc3-8577-b8b71d1f349d.png)

图 7.22

在 TDD 中，我们总是从一个失败的测试用例开始。失败的根本原因是预期结果是 25，而实际结果是 0。原因是我们还没有实现 evaluate 方法，因此我们已经硬编码返回 0，而不管任何输入。因此，让我们实现 evaluate 方法，以使测试用例通过。

我们需要修改`src/RPNCalculator.h`和`src/RPNCalculator.cpp`如下：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/b82b6739-0e1f-446b-8268-3e4278b9a435.png)

图 7.23

在 RPNCalculator.h 头文件中，观察包含的新头文件，用于处理字符串标记化和字符串双精度转换，并将 RPN 标记复制到向量中：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/60edb91d-fb13-4c15-abe3-28d51fb04033.png)

图 7.24

根据标准的后缀算法，我们使用一个栈来保存在 RPN 表达式中找到的所有数字。每当我们遇到`+`数学运算符时，我们从栈中弹出两个值并将它们相加，然后将结果推回栈中。如果标记不是`+`运算符，我们可以安全地假定它是一个数字，所以我们只需将值推到栈中。

有了前面的实现，让我们尝试测试用例并检查测试用例是否通过：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/f1818c63-eed8-48d8-8c34-f46b389d0983.png)

图 7.25

很好，我们的第一个测试用例如预期地通过了。现在是时候考虑另一个测试用例了。这次，让我们为减法添加一个测试用例：

```cpp
Test Case : Test a simple subtraction
Input: "25 10 -"
Expected Output: 15.0
```

让我们将前面的测试用例翻译成测试文件中的 Google 测试，如下所示：

```cpp
test/RPNCalculatorTest.cpp

TEST ( RPNCalculatorTest, testSimpleSubtraction ) { 
         RPNCalculator rpnCalculator; 
         double actualResult = rpnCalculator.evaluate ( "25 10 -" ); 
         double expectedResult = 15.0; 
         EXPECT_EQ ( expectedResult, actualResult ); 
}
```

通过将前面的测试用例添加到`test/RPNCalculatorTest`，现在应该是这样的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/cc5b0b61-89a8-4f0e-b3a4-dbd6c211184f.png)

图 7.26

让我们执行测试用例并检查我们的新测试用例是否通过：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/693817e5-8ceb-41f4-bf67-3aee2b1f4cdf.png)

图 7.27

如预期的那样，新的测试用例失败了，因为我们还没有在应用程序中添加对减法的支持。这是非常明显的，基于 C++异常，因为代码试图将减法`-`运算符转换为数字。让我们在 evaluate 方法中添加对减法逻辑的支持：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/50e8ab37-d576-49f8-88ef-ae73292bf0e1.png)

图 7.28

是时候测试了。让我们执行测试用例并检查事情是否正常：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/a717a076-d04f-4e5b-ad99-c0cc64dccf11.png)

图 7.29

酷！你有没有注意到我们的测试用例在这种情况下失败了？等一下。如果测试用例失败了，为什么我们会兴奋呢？我们应该高兴的原因是，我们的测试用例发现了一个 bug；毕竟，这是 TDD 的主要目的，不是吗？

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/9040e38a-2afb-4da2-9e59-aba4a997ad03.png)

图 7.30

失败的根本原因是栈是基于**后进先出**（**LIFO**）操作，而我们的代码假设是先进先出。你有没有注意到我们的代码假设它会先弹出第一个数字，而实际上它应该先弹出第二个数字？有趣的是，这个 bug 在加法操作中也存在；然而，由于加法是可结合的，这个 bug 被抑制了，但减法测试用例检测到了它。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/3c2c58af-23b1-4385-b8e9-1dd1fa0de62b.png)

图 7.31

让我们按照上面的截图修复 bug，并检查测试用例是否通过：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/ecfdb074-47b3-458c-9f97-b0b8492e1c70.png)

图 7.32

太棒了！我们修复了 bug，我们的测试用例似乎证实了它们已经修复。让我们添加更多的测试用例。这次，让我们添加一个用于验证乘法的测试用例：

```cpp
Test Case : Test a simple multiplication
Input: "25 10 *"
Expected Output: 250.0
```

让我们将前面的测试用例翻译成测试文件中的谷歌测试，如下所示：

```cpp
test/RPNCalculatorTest.cpp

TEST ( RPNCalculatorTest, testSimpleMultiplication ) { 
         RPNCalculator rpnCalculator; 
         double actualResult = rpnCalculator.evaluate ( "25 10 *" ); 
         double expectedResult = 250.0; 
         EXPECT_EQ ( expectedResult, actualResult ); 
}
```

我们知道这次测试用例肯定会失败，所以让我们快进，看看除法测试用例：

```cpp
Test Case : Test a simple division
Input: "250 10 /"
Expected Output: 25.0
```

让我们将前面的测试用例翻译成测试文件中的谷歌测试，如下所示：

```cpp
test/RPNCalculatorTest.cpp

TEST ( RPNCalculatorTest, testSimpleDivision ) { 
         RPNCalculator rpnCalculator; 
         double actualResult = rpnCalculator.evaluate ( "250 10 /" ); 
         double expectedResult = 25.0; 
         EXPECT_EQ ( expectedResult, actualResult );
}
```

让我们跳过测试结果，继续进行最终的复杂表达式测试，涉及许多操作：

```cpp
Test Case : Test a complex rpn expression
Input: "2  5  *  4  + 7  2 -  1  +  /"
Expected Output: 25.0
```

让我们将前面的测试用例翻译成测试文件中的谷歌测试，如下所示：

```cpp
test/RPNCalculatorTest.cpp

TEST ( RPNCalculatorTest, testSimpleDivision ) { 
         RPNCalculator rpnCalculator; 
         double actualResult = rpnCalculator.evaluate ( "250 10 /" ); 
         double expectedResult = 25.0; 
         EXPECT_EQ ( expectedResult, actualResult );
}
```

让我们检查一下我们的 RPNCalculator 应用程序是否能够评估一个复杂的 RPN 表达式，其中包括加法、减法、乘法和除法在一个表达式中，使用以下测试用例：

```cpp
test/RPNCalculatorTest.cpp

TEST ( RPNCalculatorTest, testComplexExpression ) { 
         RPNCalculator rpnCalculator; 
         double actualResult = rpnCalculator.evaluate ( "2  5  *  4  +  7  2 - 1 +  /" ); 
         double expectedResult = 2.33333; 
         ASSERT_NEAR ( expectedResult, actualResult, 4 );
}
```

在前面的测试用例中，我们正在检查预期结果是否与实际结果匹配，精确到小数点后四位。如果超出这个近似值，那么测试用例应该失败。

现在让我们检查一下测试用例的输出：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/f7ee9b6e-a7c4-4724-ba76-248586d1042b.png)

图 7.33

太棒了！所有的测试用例都通过了。

现在让我们看一下我们的生产代码，并检查是否有改进的空间：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/59968599-0045-46c6-a21d-c23758b35e5b.png)

图 7.34

代码在功能上很好，但有很多代码异味。这是一个长方法，有嵌套的`if-else`条件和重复的代码。TDD 不仅仅是关于测试自动化；它也是关于编写没有代码异味的好代码。因此，我们必须重构代码，使其更模块化，减少代码复杂度。

我们可以在这里应用多态性或策略设计模式，而不是嵌套的`if-else`条件。此外，我们可以使用工厂方法设计模式来创建各种子类型。还可以使用空对象设计模式。

最好的部分是，在重构过程中我们不必担心破坏我们的代码，因为我们有足够数量的测试用例来在我们破坏代码时给我们反馈。

首先，让我们了解一下如何重构*图 7.35*中所示的 RPNCalculator 设计：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/1f4554af-6399-4958-bf1f-c652d1a40ba2.png)

图 7.35

根据前面的设计重构方法，我们可以将 RPNCalculator 重构如*图 7.36*所示：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/0365aef4-8679-4a68-9fa3-b1412e710b8c.png)

图 7.36

如果你比较重构前后的`RPNCalculator`代码，你会发现重构后代码复杂度有所降低。

`MathFactory`类可以按照*图 7.37*中所示实现：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/50ef6be4-5685-42f2-ae2a-4017ce0eb786.png)

图 7.37

尽可能地，我们必须努力避免`if-else`条件，或者一般地说，我们必须尽量避免代码分支。因此，STL map 用于避免`if-else`条件。这也促进了相同的 Math 对象的重复使用，无论 RPN 表达式的复杂程度如何。

如果你参考*图 7.38*，你将了解到`MathOperator Add`类是如何实现的：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/88aa74aa-72cb-4d7d-a8c3-5f129418d4bb.png)

图 7.38

`Add`类的定义如*图 7.39*所示：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/29aaf860-3fbd-4a28-adac-7baaa25fb372.png)

图 7.39

减法、乘法和除法类可以像`Add`类一样实现。重点是，在重构后，我们可以将单个`RPNCalculator`类重构为更小、可维护的类，可以单独进行测试。

让我们看一下重构后的`Makefile`类在*图 7.40*中是如何实现的，并在重构过程完成后测试我们的代码：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/24b2be6c-d0af-43c6-ab20-f863918d589c.png)

图 7.40

如果一切顺利，重构后我们应该看到所有测试用例通过，如果没有功能出现问题，就像*图 7.41*中所示的那样：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/3938e73e-79d5-4970-92b0-429e8e7a5f8d.png)

图 7.41

太棒了！所有的测试用例都通过了，因此我们保证在重构过程中没有破坏功能。TDD 的主要目的是编写可测试的代码，既在功能上又在结构上是清晰的。

# 测试具有依赖关系的旧代码

在上一节中，CUT 是独立的，没有依赖，因此它测试代码的方式很直接。然而，让我们讨论一下如何对具有依赖关系的 CUT 进行单元测试。为此，请参考以下图片：

！[](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/64a56413-6eb2-45e0-bf2f-05337e3ebf83.png)

图 7.42

在*图 7.42*中，很明显**Mobile**依赖于**Camera**，而**Mobile**和**Camera**之间的关联是*组合*。让我们看看遗留应用程序中`Camera.h`头文件是如何实现的：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/561d5d0d-9c73-4d5b-835c-9a9453cdaf72.png)

图 7.43

为了演示目的，让我们来看一下这个简单的`Camera`类，它具有`ON()`和`OFF()`功能。假设 ON/OFF 功能将在内部与相机硬件交互。查看*图 7.44*中的`Camera.cpp`源文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/bc953aab-781d-496f-b297-3a65c20ab28e.png)

图 7.44

为了调试目的，我添加了一些打印语句，这些语句在我们测试`powerOn()`和`powerOff()`功能时会派上用场。现在让我们检查*图 7.45*中的`Mobile`类头文件：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/1bc9c336-d9b7-4baa-9117-26691c11a1fa.png)

图 7.45

我们继续移动实现，如*图 7.46*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/c9db6f57-11e5-4bcd-8730-adaa968f482d.png)

图 7.46

从`Mobile`构造函数的实现中，很明显手机有一个相机，或者更确切地说是组合关系。换句话说，`Mobile`类是构造`Camera`对象的类，如*图 7.46*，*第 21 行*所示，在构造函数中。让我们尝试看看测试`Mobile`的`powerOn()`功能所涉及的复杂性；依赖关系与`Mobile`的 CUT 具有组合关系。

假设相机已成功打开，让我们编写`powerOn()`测试用例，如下所示：

```cpp
TEST ( MobileTest, testPowerOnWhenCameraONSucceeds ) {

     Mobile mobile;
     ASSERT_TRUE ( mobile.powerOn() );

}
```

现在让我们尝试运行`Mobile`测试用例并检查测试结果，如*图 7.47*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/d7c57ec6-dfaa-4f1c-84bd-53985d314075.png)

图 7.47

从*图 7.47*，我们可以理解`Mobile`的`powerOn()`测试用例已经通过。然而，我们也了解到`Camera`类的真正`ON()`方法也被调用了。这反过来将与相机硬件交互。归根结底，这不是一个单元测试，因为测试结果并不完全取决于 CUT。如果测试用例失败，我们将无法确定失败是由于`Mobile`的`powerOn()`逻辑中的代码还是由于相机的`ON()`逻辑中的代码，这将违背我们测试用例的目的。理想的单元测试应该使用依赖注入将 CUT 与其依赖项隔离，并测试代码。这种方法将帮助我们识别 CUT 在正常或异常情况下的行为。理想情况下，当单元测试用例失败时，我们应该能够猜测失败的根本原因，而无需调试代码；只有当我们设法隔离 CUT 的依赖项时才有可能做到这一点。

这种方法的关键好处是，CUT 可以在依赖项实现之前进行测试，这有助于在没有依赖项的情况下测试 60~70%的代码。这自然减少了将软件产品上市的时间。

这就是 Google mock 或 gmock 派上用场的地方。让我们看看如何重构我们的代码以实现依赖注入。虽然听起来很复杂，但重构代码所需的工作并不复杂。实际上，重构生产代码所需的工作可能更复杂，但这是值得的。让我们看看*图 7.48*中显示的重构后的`Mobile`类：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/4127e4d3-a4ba-40d4-92b6-45c55c8395b8.png)

图 7.48

在`Mobile`类中，我添加了一个以相机为参数的重载构造函数。这种技术称为**构造函数依赖注入**。让我们看看这种简单而强大的技术如何在测试`Mobile`的`powerOn()`功能时帮助我们隔离相机依赖关系。

此外，我们必须重构`Camera.h`头文件，并声明`ON()`和`OFF()`方法为虚拟方法，以便 gmock 框架帮助我们存根这些方法，如*图 7.49*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/23fba3ac-3c81-4c0f-8832-d491579481fe.png)

图 7.49

现在让我们根据*图 7.50*对我们的测试用例进行重构：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/90b5acab-6142-4f68-aa83-5f99e2763a3b.png)

图 7.50

我们已经准备好构建和执行测试用例。测试结果如*图 7.51*所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp-prog/img/4b7bc63c-5423-404d-bc44-0df96ad748be.png)

图 7.51

太棒了！我们的测试用例不仅通过了，而且我们还隔离了我们的 CUT 与其相机依赖，这很明显，因为我们没有看到相机的`ON()`方法的打印语句。最重要的是，您现在已经学会了如何通过隔离其依赖来对代码进行单元测试。

愉快的 TDD！

# 摘要

在本章中，您对 TDD 有了相当多的了解，以下是关键要点的摘要：

+   TDD 是一种极限编程（XP）实践

+   TDD 是一种自下而上的方法，鼓励我们从一个测试用例开始，因此通常被称为小写测试优先开发

+   您学会了如何在 Linux 和 Windows 中使用 Google Test 和 Google Mock 框架编写测试用例

+   您还学会了如何在 Linux 和 Windows 平台上的 Visual Studio 中编写遵循 TDD 的应用程序

+   您学会了依赖反转技术以及如何使用 Google Mock 框架隔离其依赖来对代码进行单元测试

+   Google Test 框架支持单元测试、集成测试、回归测试、性能测试、功能测试等。

+   TDD 主要坚持单元测试、集成测试和交互测试，而复杂的功能测试必须通过行为驱动开发来完成

+   您学会了如何将代码异味重构为干净的代码，同时您编写的单元测试用例会给出持续的反馈

您已经学会了 TDD 以及如何自下而上地自动化单元测试用例、集成测试用例和交互测试用例。有了 BDD，您将学习自上而下的开发方法，编写端到端的功能和测试用例以及我们在讨论 TDD 时没有涵盖的其他复杂测试场景。

在下一章中，您将学习有关行为驱动开发的知识。
