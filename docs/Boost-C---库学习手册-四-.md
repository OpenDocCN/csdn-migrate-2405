# Boost C++ 库学习手册（四）

> 原文：[`zh.annas-archive.org/md5/9ADEA77D24CFF2D20B546F835360FD23`](https://zh.annas-archive.org/md5/9ADEA77D24CFF2D20B546F835360FD23)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：高阶和编译时编程

许多标准库算法接受可调用实体，称为**函数对象**（函数指针、函数符等）作为参数。它们调用这些函数对象来计算容器中的各个元素的某个值或执行某些操作。因此，算法的一部分运行时逻辑被封装在一个函数或函数符中，并作为算法的参数提供。函数也可以返回函数对象而不是数据值。返回的函数对象可以应用于一组参数，并可能反过来返回一个值或另一个函数对象。这就产生了高阶变换。这种涉及传递和返回函数的编程风格称为**高阶编程**。

C++模板使我们能够编写类型通用的代码。使用模板，可以在编译时执行分支和递归逻辑，并根据简单的构建块条件地包含、排除和生成代码。这种编程风格称为**编译时编程**或**模板元编程**。

在本章的第一部分，我们将学习使用 Boost Phoenix 库和 C++11 的绑定和 lambda 等设施在 C++中应用高阶编程的应用。在本章的下一部分，我们将学习 C++模板元编程技术，这些技术在编译时执行，帮助生成更高效和更具表现力的代码。在本章的最后一部分，我们将通过将高阶编程技术与元编程相结合，在 C++中创建领域特定语言。本章的主题分为以下几个部分：

+   使用 Boost 进行高阶编程

+   使用 Boost 进行编译时编程

+   领域特定嵌入式语言

在这一章中，我们将探讨一种与面向对象和过程式编程不同的编程范式，它大量借鉴了函数式编程。我们还将开发通用编程技术，最终帮助我们实现更高效的模板库。

# 使用 Boost 进行高阶编程

考虑一个类型`Book`，它有三个字符串字段：ISBN、标题和作者（对于我们的目的，假设只有一个作者）。以下是我们可以选择定义这种类型的方式：

```cpp
 1 struct Book
 2 {
 3   Book(const std::string& id,
 4        const std::string& name,
 5        const std::string& auth)
 6         : isbn(id), title(name), author(auth)
 7   {}
 8
 9   std::string isbn;
10   std::string title;
11   std::string author;
12 };
13
14 bool operator< (const Book& lhs, const Book& rhs)
12 {  return lhs.isbn < rhs.isbn;  }
```

它是一个带有三个字段和一个构造函数的`struct`，用于初始化这三个字段。`isbn`字段唯一标识书籍，因此用于定义`Book`对象的排序，使用重载的`operator<`（第 14 行）。

现在假设我们有一个`std::vector`中的这些`Book`对象的列表，并且我们想对这些书籍进行排序。由于重载的`operator<`，我们可以轻松地使用标准库的`sort`算法对它们进行排序：

```cpp
 1 #include <vector>
 2 #include <string>
 3 #include <algorithm>
 4 #include <iostream>
 5
 6 // include the definition of struct Book
 7 
 8 int main()
 9 {
10   std::vector<Book> books;
11   books.emplace_back("908..511..123", "Little Prince",
12                      "Antoine St. Exupery");
13   books.emplace_back("392..301..109", "Nineteen Eighty Four",
14                      "George Orwell");
15   books.emplace_back("872..610..176", "To Kill a Mocking Bird",
16                      "Harper Lee");
17   books.emplace_back("392..301..109", "Animal Farm",
18                      "George Orwell");
19
20   std::sort(books.begin(), books.end());
21 }
```

在前面的代码中，我们将四个`Book`对象放入向量`books`中。我们通过调用`emplace_back`方法（第 11-18 行）而不是`push_back`来实现这一点。`emplace_back`方法（在 C++11 中引入）接受存储类型（`Book`）的构造函数参数，并在向量的布局中构造一个对象，而不是复制或移动预先构造的对象。然后我们使用`std::sort`对向量进行排序，最终使用`Book`对象的`operator<`。如果没有这个重载的运算符，`std::sort`将无法编译。

这一切都很好，但如果您想按 ISBN 的降序对书籍进行排序怎么办？或者您可能想按作者对书籍进行排序。此外，对于两本具有相同作者的书，您可能希望进一步按标题对它们进行排序。我们将在下一节中看到一种按这种方式对它们进行排序的方法。

## 函数对象

`std::sort`算法有一个三参数重载，第三个参数是一个用于比较两个元素的函数对象。这个函数对象应该在最终排序中如果第一个参数出现在第二个参数之前则返回 true，否则返回 false。因此，即使没有重载`operator<`，你也可以告诉`std::sort`如何比较两个元素并对向量进行排序。以下是使用排序函数进行排序的方法：

**清单 7.1：将函数传递给算法**

```cpp
 1 bool byDescendingISBN(const Book& lhs, const Book& rhs)
 2 {  return lhs.isbn > rhs.isbn; }
 3 
 4 ...
 5 std::vector<Book> books;
 6 ...
 7 std::sort(books.begin(), books.end(), byDescendingISBN);
```

函数`byDescendingISBN`接受两本书的 const 引用，并在第一本书的 ISBN（`lhs`）在字典顺序上大于第二本书（`rhs`）的 ISBN 时返回 true，否则返回 false。该函数的签名与`std::sort`算法期望的函数对象兼容。为了按降序对`books`向量进行排序，我们将指向这个函数的指针传递给`std::sort`（第 7 行）。

函数指针绝不是你可以传递的唯一可调用实体。*函数对象*是一种重载了函数调用运算符成员（`operator()`）的类型。通过在一组参数上应用或调用函数对象的实例，你调用了重载的`operator()`成员。在下面的例子中，我们定义了一个函数对象来按作者名对书籍进行排序，如果作者名相同，则按标题排序：

**清单 7.2：定义和传递函数对象给算法**

```cpp
 1 ...
 2 struct CompareBooks
 3 {
 4   bool operator()(const Book& b1, const Book& b2) const {
 5     return (b1.author < b2.author)
 6            || (b1.author == b2.author 
 7                && b1.title < b2.title);
 8   }
 9 };
10
11 ...
12 std::vector<Book> books;
13 ...
14 std::sort(books.begin(), books.end(), CompareBooks());
```

我们定义了一个名为`CompareBooks`的函数对象，它重载了`operator()`，接受两个要比较的`Book`对象（第 4 行）。如果第一本书的作者名在字典顺序上小于第二本书的作者名，则返回 true。如果两本书的作者相同，则如果第一本书的标题在字典顺序上小于第二本书的标题，则返回 true。为了将这个函数对象作为排序标准使用，我们将`CompareBooks`的临时实例作为`std::sort`算法的第三个参数传递（第 14 行）。像`CompareBooks`这样将一个或多个参数映射到布尔真值的函数对象被称为**谓词**。

### 提示

**术语说明**

我们使用术语**函数对象**来指代所有可调用的实体，可以在应用程序中传递和存储以供以后使用。这些包括函数指针和函数对象，以及其他类型的可调用实体，如未命名函数或**lambda**，我们将在本章中探讨。

**函数对象**简单地是定义了重载的函数调用运算符的类或结构。

一个接受一个或多个参数并将它们映射到布尔真值的函数对象通常被称为**谓词**。

函数对象的**arity**是它所接受的参数数量。没有参数的函数具有 0-arity 或者是**nullary**，一个参数的函数具有 1-arity 或者是**unary**，两个参数的函数具有 2-arity 或者是**binary**，依此类推。

**纯函数**是一个其返回值仅取决于传递给它的参数值，并且没有副作用的函数。修改不属于函数的本地状态，执行 I/O，或者以其他方式修改执行环境都属于副作用。

当你希望函数对象在调用之间保留一些状态时，函数对象特别有用。例如，想象一下你有一个未排序的名字列表，你只想制作一个以特定字母开头的所有名字的逗号分隔列表。以下是一种方法：

**清单 7.3：带状态的函数对象**

```cpp
 1 #include <vector>
 2 #include <string>
 3 #include <iostream>
 4 #include <algorithm>
 5
 6 struct ConcatIfStartsWith {
 7   ConcatIfStartsWith(char c) : startCh(c) {}
 8
 9   void operator()(const std::string& name) {
10     if (name.size() > 0 && name.at(0) == startCh) {
11       csNames += name + ", ";
12     }
13   }
14
15   std::string getConcat() const {
16     return csNames;
17   }
18
19   void reset() { csNames = ""; }
20
21 private:
22   char startCh;
23   std::string csNames;
24 };
25
26 int main() {
27   std::vector<std::string> names{"Meredith", "Guinnevere", 
28       "Mabel", "Myrtle", "Germaine", "Gwynneth", "Mirabelle"};
29
30   const auto& fe = std::for_each(names.begin(), names.end(), 
31                            ConcatIfStartsWith('G'));
32   std::cout << fe.getConcat() << '\n';
33 }
```

我们定义了一个名为`ConcatIfStartsWith`的函数对象（第 6 行），它存储一些状态，即要匹配的起始字符（`startCh`）和包含逗号分隔的名称列表的字符串（`csNames`）。当在名称上调用函数对象时，它会检查名称是否以指定字符开头，如果是，则将其连接到`csNames`（第 10-11 行）。我们使用`std::for_each`算法将`ConcatIfStartsWith`函数对象应用于名称向量中的每个名称（第 30-31 行），寻找以字母 G 开头的名称。我们传递的函数对象是一个临时的（第 31 行），但我们需要一个引用来访问其中存储的连接字符串。`std::for_each`算法实际上返回对传递的函数对象的引用，然后我们使用它来获取连接的字符串。这是输出，列出以 G 开头的名称：

```cpp
Guinnevere, Germaine, Gwynneth, 
```

这说明了关于函数对象的一个重要观点；当您希望在连续调用函数之间保持状态时，它们特别有用。如果您需要在代码中的多个地方使用它们，它们也非常有用。通过直观地命名它们，可以在使用的地方清楚地表明它们的目的：

```cpp
   const auto& fe = std::for_each(names.begin(), names.end(), 
                                  ConcatIfStartsWith('G'));
```

但有时，一个函数对象需要做的事情是微不足道的（例如，检查一个数字是偶数还是奇数）。通常，我们不需要在调用之间维护任何状态。我们甚至可能不需要在多个地方使用它。有时，我们正在寻找的功能可能已经以某种形式存在，也许作为对象的成员函数。在这种情况下，编写一个新的函数对象似乎有些过度。C++11 引入了 lambda 或未命名函数，以精确解决这种情况。

### Lambda - 未命名函数文字

字符串`"hello"`是一个有效的 C++表达式。它有一个明确定义的类型（`const char[6]`），可以赋值给类型为`const char*`的变量，并传递给接受`const char*`类型参数的函数。同样，还有像`3.1415`或`64000U`这样的数字文字，像`true`和`false`这样的布尔文字，等等。C++11 引入了**lambda 表达式**，用于在调用它们的地方定义匿名函数。通常简称为**lambda**（来自 Alonzo Church 的λ演算），它们由一个未绑定到函数名称的函数体组成，并用于在程序的词法范围内的任何点生成函数定义，您期望传递一个函数对象。让我们首先通过一个例子来了解如何做到这一点。

我们有一个整数列表，并希望使用`std::find_if`算法在列表中找到第一个奇数。传递给`std::find_if`的谓词是使用 lambda 定义的。

**清单 7.4：使用 lambda**

```cpp
 1 #include <vector>
 2 #include <algorithm>
 3 #include <cassert>
 4 
 5 int main() {
 6   std::vector<int> vec{2, 4, 6, 8, 9, 1};
 7 
 8   auto it = std::find_if(vec.begin(), vec.end(),
 9                         [](const int& num) -> bool 
10                         {  return num % 2 != 0; }
11                         );
12 
13   assert(it != vec.end() && *it == 9);
14 }
```

计算一个数字是奇数还是偶数的 lambda 是作为第三个参数传递给`std::find_if`的代码块（第 9-10 行）。让我们单独看一下 lambda 以了解语法。首先，考虑这个函数做什么；给定一个整数，如果它是奇数则返回 true，否则返回 false。因此，我们有一个未命名函数，将`int`映射到`bool`。在 lambda-land 中编写这个的方式如下：

```cpp
[](const int& num) -> bool
```

我们使用一对空方括号引入未命名函数，并通过编写类似于常规函数的参数列表，后跟一个箭头和返回类型来描述映射。在此之后，我们编写函数体，就像为正常函数编写一样：

```cpp
{  return num % 2 != 0;  }
```

方括号对，通常称为**lambda 引入者**，不一定为空，我们很快就会看到。这种语法还有其他几种变体，但您可以仅使用这一小部分语法来定义 lambda。在简单情况下，lambda 的返回类型规范是可选的，编译器可以轻松从函数体中推断出返回类型。因此，我们可以重新编写前面示例中的 lambda，而不需要返回类型，因为函数体实际上非常简单：

```cpp
[](const int& num) { return num % 2 != 0; }
```

#### Lambda 捕获

我们在前面的示例中定义的 lambda 是一个没有任何状态的纯函数。实际上，lambda 如何可能存储在调用之间持续存在的状态？实际上，lambda 可以访问来自周围范围的局部变量（以及全局变量）。为了启用这样的访问，我们可以在 lambda 引入器中指定**捕获子句**，列出了来自周围范围的哪些变量可以访问 lambda 以及*如何*。考虑以下示例，其中我们从名称向量中过滤出长度超过用户指定长度的名称，并返回仅包含较短名称的向量：

**清单 7.5：带捕获的 lambda**

```cpp
 1 #include <vector>
 2 #include <string>
 3 #include <algorithm>
 4 #include <iterator>
 5 typedef std::vector<std::string> NameVec;
 6
 7 NameVec getNamesShorterThan(const NameVec& names,
 8                             size_t maxSize) {
 9   NameVec shortNames;
10   std::copy_if(names.begin(), names.end(),
11                std::back_inserter(shortNames),
12                maxSize {
13                   return name.size() <= maxSize;
14                }
15                );
16   return shortNames;
17 }
```

`getNamesShorterThan`函数接受两个参数：一个名为`names`的向量和一个名为`maxSize`的变量，该变量限制要过滤的字符串的大小。它将`names`向量中短于`maxSize`的名称复制到第二个名为`shortNames`的向量中，使用标准库中的`std::copy_if`算法。我们使用 lambda 表达式（第 12-14 行）生成`std::copy_if`的谓词。您可以看到我们在方括号中命名了来自周围词法范围的`maxSize`变量（第 12 行），并在 lambda 主体中访问它以比较传递的字符串的大小（第 13 行）。这使得 lambda 内部对`maxSize`变量的只读访问成为可能。如果我们想要潜在地访问周围范围中的任何变量而不是特定的变量，我们可以在方括号中使用等号来编写 lambda；这将*隐式捕获*来自周围范围的任何使用的变量：

```cpp
= {
   return name.size() <= maxSize;
}
```

您可能希望修改来自周围范围的局部变量的副本，而不影响周围范围中的值。为了使您的 lambda 能够执行此操作，必须将其声明为 mutable：

```cpp
= mutable -> bool {
 maxSize *= 2;
   return name.size() <= maxSize;
}
```

`mutable`关键字跟在参数列表后面，但如果指定了返回类型，则出现在返回类型之前。这不会影响周围范围中`maxSize`的值。

您还可以在 lambda 内部修改来自周围范围的变量。为此，必须通过在方括号中的变量名称前加上一个和符号来引用捕获变量。

这是使用 lambda 重写的 6.3 清单：

**清单 7.6：lambda 中的引用捕获**

```cpp
 1 #include <vector>
 2 #include <string>
 3 #include <algorithm>
 4 #include <iostream>
 5
 6 int main() {
 7   std::string concat;
 8   char startCh = 'M';
 9   std::vector<std::string> names{"Meredith", "Guinnevere", "Mabel"
10                  , "Myrtle", "Germaine", "Gwynneth", "Mirabelle"};
11 
12   std::for_each(names.begin(), names.end(), 
13                &concat, startCh {
14                  if (name.size() > 0 && name[0] == startCh) {
15                    concat += name + ", ";
16                  }
17                });
18   std::cout << concat << '\n';
19 }
```

在前面的示例中，我们将来自向量`names`的所有以特定字符开头的名称连接起来。起始字符取自变量`startCh`。连接的字符串存储在变量`concat`中。我们对向量的元素调用`std::for_each`，并传递一个 lambda，该 lambda 显式地将`concat`作为引用捕获（带有前导和符号），并将`startCh`作为来自周围范围的只读值传递（第 13 行）。因此，它能够附加到`concat`（第 15 行）。此代码打印以下输出：

```cpp
Meredith, Mabel, Myrtle, Mirabelle
```

在最新的 C++标准中，被称为 C++14，lambda 变得更加巧妙。您可以编写一个*通用 lambda*，其参数类型是根据上下文推断的。例如，在 C++14 中，您可以按照前面示例中的调用`std::for_each`，编写如下：

```cpp
  std::for_each(names.begin(), names.end(), 
               &concat, startCh {
                 if (name.size() > 0 && name[0] == startCh) {
                   concat += name + ", ";
                 }
               });
```

lambda 的参数类型写为`const auto&`，编译器根据迭代序列中元素的类型推断为`const std::string&`。

### 委托和闭包

假设您正在编写一个用于读取消息队列上传入消息的高级 C++ API。您的 API 的客户端必须注册其感兴趣的消息类型，并传递一个回调函数对象，当您感兴趣的消息到达时将调用该对象。您的 API 可以是`Queue`类的成员。以下是一个可能的 API 签名：

```cpp
class Queue
{
public:
  ...
 template <typename CallbackType>
 int listen(MsgType msgtype, CallbackType cb);
  ...
};
```

`listen`成员模板接受两个参数：消息类型`msgtype`，用于标识感兴趣的消息，以及回调函数对象`cb`，当新消息到达时将调用它。由于我们希望客户端能够传递函数指针、成员函数指针、仿函数以及 lambda 作为回调，因此我们将`listen`作为一个成员模板参数化为回调类型。当然，回调应该具有特定的签名。假设它应该与以下函数的签名兼容：

```cpp
void msgRead(Message msg);
```

在这里，`Message`是从队列中读取的消息的类型。`listen`成员模板有点过于宽松，因为它可以实例化为不符合前面签名的函数对象。对于不符合签名的回调，编译错误会发生在调用`listen`内部的回调处，而不是传递不符合签名的回调的地方。这可能会使调试编译器错误变得更加困难。

Boost.Function 库及其 C++11 版本`std::function`提供了专门设计用于解决此类问题的函数对象包装器。我们可以将函数`msgRead`的类型写为`void (Message)`。具有 N 个参数的函数类型的一般语法如下：

```cpp
return-type(param1-type, param2-type, ..., paramN-type)
```

与之前的**函数类型**对应的更熟悉的**函数指针类型**将是：

```cpp
return-type (*)(param1-type, param2-type, ..., paramN-type)
```

因此，函数`int foo(double, const char*)`的类型将是：

```cpp
int(double, const char*);
```

指针将是以下类型：

```cpp
int (*)(double, const char*);
```

使用具有适当函数类型的`std::function`，我们可以声明`listen`，以便它只接受符合正确签名的函数对象：

```cpp
#include <boost/function.hpp>

class Queue
{
public:
  ...
 int listen(MsgType msgtype, boost::function<void(Message)> cb);
  ...
};
```

回调现在被声明为`boost::function<void(Message)>`类型。现在可以使用指向全局函数、仿函数或甚至 lambda 调用`listen`，只有当函数对象具有符合签名时才会编译。如果使用的是 C++11 编译器，我们可以使用`std::function`代替`boost::function`。在 C++11 之前的编译器上，`boost::function`支持最多十个参数的签名，而`std::function`没有任何这样的限制，因为它使用了 C++11 的*可变模板*。有关`boost::function`的更多特性及其与`std::function`的区别（这些区别很小），您可以参考在线文档。

将非静态成员函数作为回调需要更多的工作，因为非静态成员必须在其类的实例上调用。考虑以下类`MessageHandler`，它有一个成员`handleMessage`：

```cpp
class MessageHandler
{
public:
  ...
  void handleMessage(Message msg);
};
```

`handleMessage`成员函数会隐式地传递一个指向其所调用的`MessageHandler`对象的指针作为其第一个参数；因此它的有效签名是：

```cpp
void(MessageHandler*, Message);
```

当我们想要将其作为回调传递给`Queue::listen`时，我们可能已经知道要调用`handleMessage`的对象，如果我们可以在调用 listen 时以某种方式附加该对象实例，那将是很好的。有几种方法可以做到这一点。

第一种方法涉及将对`handleMessage`的调用包装在 lambda 中，并将其传递给`listen`。以下代码片段说明了这一点：

**清单 7.7：使用闭包的成员函数回调**

```cpp
 1 MessageHandler *handler = new MessageHandler(...);
 2 Queue q(...);
 3 ...
 4 q.listen(msgType, handler
 5                   {  handler->handleMessage(msg);  }
 6                   );
```

在这里，`listen`的第二个参数是使用 lambda 表达式生成的，它还捕获了来自周围范围的`handler`对象的指针。在这个例子中，`handler`是调用范围内的一个局部变量，但是 lambda 捕获了它并将其绑定到它生成的函数对象中。这个函数对象不会立即被调用，而是延迟到队列上接收到感兴趣的消息时，它会将调用转发到`handler`对象指针上的`handleMessage`方法。

`handler`指针是在调用范围内创建的，但通过 lambda 捕获变得间接可访问到另一个范围。这被称为**动态作用域**，在创建它们的词法作用域中绑定到变量的这种函数被称为**闭包**。当然，在调用`handleMessage`时，`handler`指针仍然必须指向一个有效的`MessageHandler`对象，而不仅仅是在 lambda 创建时。

很多时候，这样的 lambda 表达式会从类的成员函数内部生成，比如`MessageHandler`类的成员函数，并且会捕获`this`指针，从而简化语法：

**清单 7.8：在 lambda 中捕获 this 指针**

```cpp
 1 class MessageHandler
 2 {
 3 public:
 4   ...
 5   void listenOnQueue(Queue& q, MessageType msgType) {
 6     q.listen(msgType, this 
 7                       { handleMsg(msg); } );
 8   }
 9 
10   void handleMsg(Message msg) { ... }
11 };
```

在前面的例子中，我们使用 lambda 表达式创建了一个闭包，它捕获了`this`指针（第 6 行）。在 lambda 内部调用`handleMsg`会自动绑定到`this`指针，就像在成员函数中一样。回调函数，特别是绑定到特定对象的回调函数，如前所述，有时被称为**委托**。

`boost::function` / `std::function`包装器提供了一种有效的、经过类型检查的方式来传递和返回函数对象作为回调或委托。它们有时被称为多态函数包装器，因为它们完全将底层可调用实体（函数指针、函数对象等）的类型从调用者中抽象出来。大多数实现都会动态分配内存，因此您应该认真评估它们对运行时性能的影响。

### 部分函数应用

给定标准库函数`pow`：

```cpp
double pow(double base, double power);
```

考虑一下代码行`x = pow(2, 3)`的效果。当遇到这行代码时，函数`pow`立即被调用，带有两个参数，值为 2 和 3。函数`pow`计算 2 的 3 次方，并返回值 8.0，然后赋给`x`。

现在，假设你有一个数字列表，你想把它们的立方放入另一个列表中。标准库算法`std::transform`非常适合这个任务。我们只需要找到正确的函数对象来将数字提升到它们的立方幂。以下函数对象接受一个数字参数，并使用`pow`函数将其提升到特定的幂：

```cpp
#include <cmath>

struct RaiseTo {
  RaiseTo(double power) : power_(power) {}

  double operator()(double base) const {
    return pow(base, power_);
  }

  double power_;
};
```

我们也可以使用 lambda 表达式来生成函数对象，就像上一节的清单 7.7 和 7.8 中所示。使用`RaiseTo`和`std::transform`算法，以下代码完成了任务：

```cpp
std::vector<double> nums, raisedToThree;
...
std::transform(nums.begin(), nums.end(), 
               std::back_inserter(raisedToThree),
               RaiseTo(3));
```

`RaiseTo`中的核心计算是由`pow`函数完成的。`RaiseTo`函数对象通过构造函数参数和与`std::transform`期望的调用签名兼容的方式来固定幂。

想象一下，如果在 C++中可以不使用函数对象或 lambda 来做到这一点。如果使用以下*虚构的*语法，你可以做同样的事情吗？

```cpp
std::transform(nums.begin(), nums.end(), 
               std::back_inserter(raisedToThree),
               pow(_, 3));
```

就好像你正在传递`pow`函数，其中有两个参数中的一个被固定为 3，并要求`transform`算法填写空白；提供要提升的数字。表达式`pow(_, 3)`将会评估为一个函数对象，接受一个参数而不是 2 个。我们基本上使用`RaiseTo`函数对象实现了这一点，但 Boost Bind 库及其 C++11 版本的`std::bind`帮助我们以更少的语法来实现这一点。正式地说，我们刚刚做的被称为**部分函数应用**。

使用`bind`创建一个部分应用的`pow`函数对象，你需要写：

```cpp
boost::bind(pow, _1, 3)
```

前面的表达式生成了一个无名的函数对象，它接受一个参数并返回它的值的 3 次方，使用标准库函数`pow`。与我们的虚构语法的相似之处应该是显而易见的。要立方的值作为生成的函数对象的唯一参数传递，并映射到特殊的占位符`_1`。

**清单 7.9：使用 Boost Bind**

```cpp
 1 #include <boost/bind.hpp>
 2 
 3 std::vector<double> nums, raisedToThree;
 4 std::transform(nums.begin(), nums.end(),
 5                std::back_inserter(raisedToThree),
 6                boost::bind(pow, _1, 3));
```

如果生成的函数对象接受更多的参数，则可以根据它们在参数列表中的位置将它们映射到占位符`_2`、`_3`等。一般来说，第 n 个参数映射到占位符`_n`。Boost Bind 默认支持最多九个位置占位符（`_1`到`_9`）；`std::bind`可能支持更多（根据编译器的不同），但您需要从`std::placeholders`命名空间中访问它们，使用以下指令之一：

```cpp
using std::placeholders::_1;
using std::placeholders::_2;
// etc. OR
using namespace std::placeholders;
```

您可以通过重新排序它们的参数而不改变函数 arity 来调整函数以实现新的功能。例如，给定返回`true`的函数`std::less`，如果它的第一个参数小于它的第二个参数，我们可以生成一个函数对象，如果它的第一个参数大于它的第二个参数，则返回`true`。以下表达式生成了这个：

```cpp
boost::bind(std::less<int>(), _2, _1)
```

在这里，`std::less<int>`接受两个参数，我们生成了一个包装函数对象，它也接受两个参数，但在将它们传递给`std::less`之前交换它们的位置。我们可以直接在原地调用生成的函数对象，就像这样：

```cpp
boost::bind(std::less<int>(), _2, _1)(1, 10)
```

我们可以安全地断言 1 不大于 10，但实际上是小于：

```cpp
assert( std::less<int>()(1, 10) );
assert( !boost::bind(std::less<int>(), _2, _1)(1, 10) );
```

Boost Bind 还可用于生成委托，清单 7.7 和 7.8 中还演示了生成委托的其他方法。以下是使用`boost::bind`重写的清单 7.8：

清单 7.10：使用 Boost Bind 生成委托

```cpp
 1 class MessageHandler
 2 {
 3 public:
 4   ...
 5   void listenOnQueue(Queue& q, MessageType msgType) {
 6     q.listen(msgType, boost::bind(&MessageHandler::handleMsg,
 7                                   this, _1));
 8   }
 9 
10   void handleMsg(Message msg) { ... }
11 };
```

我们必须将一个成员函数绑定到一个对象实例。我们通过将`this`绑定到`MessageHandler::handleMsg`的第一个参数（第 6-7 行）来实现这一点。这种技术通常用于在集合中的每个对象上调用成员函数。此外，`boost::bind` / `std::bind`智能地处理对象、指针、智能指针等，因此您无需根据对象的复制、指针或智能指针来编写不同的绑定器。在下面的示例中，我们获取了一个`std::string`的向量，使用`size`成员函数计算它们的长度，并将它们放入一个长度向量中：

清单 7.11：使用 Boost Bind 生成委托

```cpp
 1 #include <functional>
 2 ...
 3 std::vector<std::string> names{"Groucho", "Chico", "Harpo"};
 4 std::vector<std::string::size_type> lengths;
 5 using namespace std::placeholders;
 67 std::transform(names.begin(), names.end(), 
 8                std::back_inserter(lengths),
 9                std::bind(&std::string::size, _1));
```

长度是通过在每个`std::string`对象上调用`size`成员函数来计算的。表达式`std::bind(&std::string::size, _1)`生成了一个未命名的函数对象，它调用传递给它的`string`对象的`size`成员。

即使`names`是指向`std::string`对象的指针或智能指针的向量，绑定表达式（第 9 行）也不需要改变。`bind`函数按值传递其参数。因此，在前面的示例中，每个字符串都被复制到生成的函数对象中，这可能导致性能问题。

另一个名为`boost::mem_fn`的函数模板及其标准库对应物`std::mem_fn`使得在对象上调用成员函数和生成委托变得更加容易。`mem_fn`函数模板创建了一个指向类成员的包装器。对于类`X`中的 arity`N`的成员函数`f`，`mem_fn(&X::f)`生成一个 arity`N+1`的函数对象，其第一个参数必须是对对象的引用、指针或智能指针，该对象上调用成员函数。

我们可以编写清单 7.11 来使用`mem_fn`：

```cpp
 1 #include <boost/mem_fn.hpp> // <functional> for std
 2
...
 7 std::transform(names.begin(), names.end(), 
 8                std::back_inserter(lengths),
 9                boost::mem_fn(&std::string::size));
```

因为`std::string::size`是 nullary 的，`boost::mem_fn`生成的函数对象是一元的，并且可以直接与`transform`一起使用，无需额外的绑定。节省了不必写`_1`占位符，因此语法上更简洁。

当我们使用`bind`生成函数对象时，它不会立即检查参数类型和数量是否与绑定到的函数的签名匹配。只有在调用生成的函数对象时，编译器才会检测到参数类型和 arity 不匹配：

```cpp
1 std::string str;
2 auto f = boost::bind(&std::string::size, 5); // binds to literal 5
3 auto g = boost::bind(&std::string::size, _1, 20); // binds two args
```

例如，即使你不能在数字文字 5 上调用 `std::string` 的 `size` 成员函数（第 2 行），前面的代码也会编译。`size` 成员函数也不接受额外的数字参数（第 3 行）。但是一旦你尝试调用这些生成的函数对象，你将因为类型和参数数量不匹配而得到错误：

```cpp
4 f(); // error: operand has type int, expected std::string
5 g(str); // error: std::string::size does not take two arguments
```

绑定重载的成员函数需要更多的语法工作。使用 `bind` 生成甚至是中等复杂度的函数是一个嵌套绑定的练习，这往往会产生难以维护的代码。一般来说，有了 C++11 lambda 的可用性以及在 C++14 中的进一步完善，应该优先使用 lambda 而不是 bind 作为生成匿名函数对象的机制。只有在使用 `bind` 使你的代码比 lambda 更具表现力时才使用它。

# 使用 Boost 进行编译时编程

模板允许我们编写独立于操作数特定类型的 C++ 代码，因此可以在大量类型的情况下不变地工作。我们可以创建**函数模板**和**类模板**（或结构模板），它们接受类型参数、非类型参数（如常量整数）以及模板参数。当类模板的*特化*被实例化时，从未直接或间接调用的成员函数将不会被实例化。

C++ 模板的威力不仅仅在于能够编写通用代码。C++ 模板是一个强大的计算子系统，我们可以利用它来审视 C++ 类型，获取它们的属性，并编写复杂的递归和分支逻辑，这些逻辑在编译时执行。利用这些能力，我们可以定义对每种操作类型高度优化的通用接口。

## 使用模板进行基本的编译时控制流

在本节中，我们简要地看一下使用模板生成的分支和递归逻辑。

### 分支

考虑函数模板 `boost::lexical_cast`，它在第二章中介绍过，*Boost 实用工具的初次尝试*。要将 `string` 转换为 `double`，我们可以编写如下代码：

```cpp
std::string strPi = "3.141595259";
double pi = boost::lexical_cast<double>(strPi);
```

`lexical_cast` 的主模板是这样声明的：

```cpp
template <typename Target, typename Source>Target lexical_cast(const Source&);
```

`lexical_cast` 的默认实现（称为**主模板**）通过类似 `ostringstream` 的接口将源对象写入内存缓冲区，然后通过类似 `istringstream` 的另一个接口从中读取。这种转换可能会产生一些性能开销，但具有表现力的语法。现在假设对于一个特别性能密集型的应用程序，你想要提高这些字符串到双精度浮点数的转换性能，但又不想用其他函数调用替换 `lexical_cast`。你会怎么做？我们可以创建 `lexical_cast` 函数模板的**显式特化**，以便根据转换中涉及的类型在编译时执行分支。由于我们想要覆盖默认实现的 `string` 到 `double` 转换，这就是我们会写特化的方式：

**清单 7.12：函数模板的显式特化**

```cpp
 1 namespace boost {
 2 template <>
 3 double lexical_cast<double, std::string>(
 4                          const std::string& str)
 5 {
 6   const char *numstr = str.c_str();
 7   char *end = nullptr;
 8   double ret = strtod(numstr, &end);
 9   
10   if (end && *end != '\0') {
11     throw boost::bad_lexical_cast();
12   }
13
14   return ret;
15 }
16 } // boost
```

`template` 关键字与空参数列表 (`template<>`) 表示这是特定类型参数的特化（第 2 行）。**模板标识符** `lexical_cast <double, std::string>` 列出了特化生效的特定类型（第 3 行）。有了这个特化，编译器在看到这样的代码时会调用它：

```cpp
std::string strPi = "3.14159259";
double pi = boost::lexical_cast<double>(strPi);
```

请注意，*重载函数模板*（而不仅仅是函数）是可能的。例如：

```cpp
template<typename T> void foo(T);     // 1
template<typename T> void foo(T*);    // 2
template<typename T> T foo(T, T);     // 3
void foo(int);                        // 4
template<> void foo<double>(double);  // 5

int x;
foo(&x);   // calls 2
foo(4, 5); // calls 3
foo(10);   // calls 4
foo(10.0); // calls 5
```

在前面的例子中，`foo`是一个函数模板（1），它被重载（2 和 3）。函数`foo`本身也被重载（4）。函数模板`foo`（1）也被专门化（5）。当编译器遇到对`foo`的调用时，它首先寻找匹配的非模板重载，如果找不到，则寻找最专门化的模板重载。在没有匹配的专门化重载的情况下，这将简单地解析为主模板。因此，对`foo(&x)`的调用解析为`template<typename T> void foo(T*)`。如果不存在这样的重载，它将解析为`template<typename T> void foo(T)`。

对于类模板也可以创建专门化。除了显式专门化之外，还可以创建类模板的**部分专门化**，为一类类型专门化一个类模板。

```cpp
template <typename T, typename U>
class Bar { /* default implementation */ };

template <typename T>
class Bar<T*, T> { /* implementation for pointers */ };
```

在前面的例子中，主模板`Bar`接受两个类型参数。我们为`Bar`创建了一个部分特化，对于这些情况，其中这两个参数中的第一个是指针类型，第二个参数是第一个参数的指针类型。因此，实例化`Bar<int, float>`或`Bar<double, double*>`将实例化主模板，但`Bar<float*, float>`，`Bar<Foo*, Foo>`等将实例化部分特化模板。请注意，函数不能被部分指定。

### 递归

使用模板进行递归最好通过一个在编译时计算阶乘的例子来说明。类模板（以及函数模板）可以接受整数参数，只要这些值在编译时是已知的。

**清单 7.13：使用模板进行编译时递归**

```cpp
 1 #include <iostream>
 2
 3 template <unsigned int N>
 4 struct Factorial
 5 {
 6   enum {value = N * Factorial<N-1>::value};
 7 };
 8
 9 template <>
10 struct Factorial<0>
11 {
12   enum {value = 1};  // 0! == 1
13 };
14
15 int main()
16 {
17   std::cout << Factorial<8>::value << '\n';  // prints 40320
18 }
```

用于计算阶乘的主模板定义了一个编译时常量枚举`value`。`Factorial<N>`中的`value`枚举包含`N`的阶乘值。这是通过递归计算的，通过实例化`Factorial`模板为`N-1`并将其嵌套的`value`枚举与`N`相乘来实现的。停止条件由专门化的`Factorial`为 0 提供。这些计算发生在编译时，因为`Factorial`模板被用逐渐变小的参数实例化，直到`Factorial<0>`停止进一步的实例化。因此，值`40320`完全在编译时计算，并嵌入到构建的二进制文件中。例如，我们可以编写以下内容，它将编译并在堆栈上生成一个包含 40320 个整数的数组：

```cpp
int arr[Factorial<8>::value];  // an array of 40320 ints
```

## Boost 类型特征

Boost 类型特征库提供了一组模板，用于在编译时查询类型的属性并生成派生类型。它们在通用代码中很有用，即使用参数化类型的代码，用于根据类型参数的属性选择最佳实现。

考虑以下模板：

```cpp
 1 #include <iostream>
 2
 3 template <typename T>
 4 struct IsPointer {
 5   enum { value = 0 };
 6 };
 7
 8 template <typename T>
 9 struct IsPointer <T*> {
10   enum { value = 1 };
11 };
12
13 int main() {
14   std::cout << IsPointer<int>::value << '\n';
15   std::cout << IsPointer<int*>::value << '\n';
16 }
```

`IsPointer`模板有一个名为`value`的嵌套枚举。这在主模板中设置为 0。我们还为指针类型的参数定义了`IsPointer`的部分特化，并将嵌套的`value`设置为 1。这个类模板有什么用呢？对于任何类型`T`，只有当`T`是指针类型时，`IsPointer<T>::value`才为 1，否则为 0。`IsPointer`模板将其类型参数映射到一个编译时常量值 0 或 1，这可以用于进一步的编译时分支决策。

Boost 类型特征库中充满了这样的模板（包括`boost::is_pointer`），它们可以获取有关类型的信息，并且还可以在编译时生成新类型。它们可以用于选择或生成针对手头类型的最佳代码。Boost 类型特征在 2007 年被接受为 C++ TR1 版本，并且在 C++11 中，标准库中有一个类型特征库。

每个类型特征都在自己的头文件中定义，这样您就可以只包含您需要的那些类型特征。例如，`boost::is_pointer`将在`boost/type_traits/is_pointer.hpp`中定义。相应的`std::is_pointer`（在 C++11 中引入）定义在标准头文件`type_traits`中，没有单独的标准头文件。每个类型特征都有一个嵌入类型称为`type`，此外，它可能有一个名为`value`的 bool 类型成员。以下是使用一些类型特征的示例。

**清单 7.14：使用类型特征**

```cpp
 1 #include <boost/type_traits/is_pointer.hpp>
 2 #include <boost/type_traits/is_array.hpp>
 3 #include <boost/type_traits/rank.hpp>
 4 #include <boost/type_traits/extent.hpp>
 5 #include <boost/type_traits/is_pod.hpp>
 6 #include <string>
 7 #include <iostream>
 8 #include <cassert>
 8
 9 struct MyStruct {
10   int n;
11   float f;
12   const char *s;
13 };
14
15 int main()
16 {
17 // check pointers
18   typedef int* intptr;
19   std::cout << "intptr is "
20             << (boost::is_pointer<intptr>::value ?"" :"not ") 
21             << "pointer type\n";
22 // introspect arrays
23   int arr[10], arr2[10][15];
24   if (boost::is_array<decltype(arr)>::value) {
25     assert(boost::rank<decltype(arr)>::value == 1);
26     assert(boost::rank<decltype(arr2)>::value == 2);
27     assert(boost::extent<decltype(arr)>::value == 10);
28     assert(boost::extent<decltype(arr2)>::value == 10);
29     assert((boost::extent<decltype(arr2), 1>::value) == 15);
30     std::cout << "arr is an array\n";
31   }
32
33 // POD vs non-POD types
34   std::cout << "MyStruct is " 
35             << (boost::is_pod<MyStruct>::value ?"" : "not ")
36             << "pod type." << '\n';
37   std::cout << "std::string is " 
38             << (boost::is_pod<std::string>::value ?"" : "not ")
40             << "pod type." << '\n';
41 }
```

在这个例子中，我们使用了许多类型特征来查询有关类型的信息。我们将类型`intptr`定义为整数指针（第 18 行）。将`boost::is_pointer`应用于`intptr`将返回 true（第 20 行）。

此处使用的`decltype`说明符是在 C++ 11 中引入的。它生成应用于表达式或实体的类型。因此，`decltype(arr)`（第 24 行）返回 arr 的声明类型，包括任何`const`或`volatile`限定符。这是计算表达式类型的有用手段。我们将`boost::is_array`特征应用于数组类型，显然返回 true（第 24 行）。要找到数组的维数或秩，我们使用特征`boost::rank`（第 25 和 26 行）。`arr[10]`的秩为 1（第 25 行），但`arr2[10][15]`的秩为 2（第 26 行）。`boost::extent`特征用于查找数组秩的范围。它必须传递数组的类型和秩。如果未传递秩，则默认为 0，并返回一维数组的范围（第 27 行）或多维数组的零维（第 28 行）。否则，应明确指定秩（第 29 行）。

`boost::is_pod`特征返回一个类型是否是 POD 类型。它对于一个没有任何构造函数或析构函数的简单结构，如`MyStruct`，返回 true（第 34 行），对于显然不是 POD 类型的`std::string`，返回 false（第 38 行）。

如前所述，这些特征中还有一个嵌入类型称为`type`。这被定义为`boost::true_type`或`boost::false_type`，具体取决于特征返回 true 还是 false。现在假设我们正在编写一个通用算法，将任意对象的数组复制到堆上的数组中。对于 POD 类型，整个数组的浅复制或`memcpy`就足够了，而对于非 POD 类型，我们需要逐个元素复制。

**清单 7.15：利用类型特征**

```cpp
 1 #include <boost/type_traits/is_pod.hpp>
 2 #include <cstring>
 3 #include <iostream>
 4 #include <string>
 5 
 6 struct MyStruct {
 7   int n; float f;
 8   const char *s;
 9 };
10
11 template <typename T, size_t N>
12 T* fastCopy(T(&arr)[N], boost::true_type podType)
13 {
14   std::cerr << "fastCopy for POD\n";
15   T *cpyarr = new T[N];
16   memcpy(cpyarr, arr, N*sizeof(T));
17
18   return cpyarr;
19 }
20
21 template <typename T, size_t N>
22 T* fastCopy(T(&arr)[N], boost::false_type nonPodType)
23 {
24   std::cerr << "fastCopy for non-POD\n";
25   T *cpyarr = new T[N];
26   std::copy(&arr[0], &arr[N], &cpyarr[0]);
27
28   return cpyarr;
29 }
30
31 template <typename T, size_t N>
32 T* fastCopy(T(&arr)[N])
33 {
34   return fastCopy(arr, typename boost::is_pod<T>::type());
35 }
36
37 int main()
38 {
39   MyStruct podarr[10] = {};
40   std::string strarr[10];
41
42   auto* cpyarr = fastCopy(podarr);
43   auto* cpyarr2 = fastCopy(strarr);
44   delete []cpyarr;
45   delete []cpyarr2;
46 }
```

`fastCopy`函数模板在堆上创建数组的副本（第 31-35 行）。我们创建了两个重载：一个用于复制 POD 类型（第 11-12 行），另一个用于复制非 POD 类型（第 21-22 行），在第一种情况下添加`boost::true_type`类型的第二个参数，在第二种情况下添加`boost::false_type`类型的第二个参数。我们创建了两个数组：一个是 POD 类型`MyStruct`，另一个是非 POD 类型`std::string`（第 42-43 行）。我们在两者上调用`fastCopy`，这将解析为单参数重载（第 32 行）。这将调用`fastCopy`的两个参数重载，传递`boost::is_pod<T>::type`的实例作为第二个参数（第 34 行）。这将根据存储的类型`T`是 POD 类型还是非 POD 类型自动路由调用到正确的重载。

本书的范围内有许多类型特征，远远超出我们可以涵盖的范围。您可以使用类型特征来检查一个类型是否是另一个类型的基类（`boost::is_base`），一个类型是否可以被复制构造（`boost::is_copy_constructible`），是否具有特定的操作符（例如，`boost::has_pre_increment`），是否与另一个类型相同（`boost::is_same`）等等。在线文档是挖掘特征并找到适合当前工作的特征的好地方。

### SFINAE 和 enable_if / disable_if

每次编译器遇到与函数模板同名的函数调用时，它会创建一个匹配模板和非模板重载的重载解析集。编译器根据需要推断模板参数，以确定哪些函数模板重载（及其特化）符合条件，并在此过程中实例化符合条件的模板重载。如果在模板的参数列表或函数参数列表中替换推断出的类型参数导致错误，这不会导致编译中止。相反，编译器会从重载解析集中移除该候选项。这被称为**替换失败不是错误**或**SFINAE**。只有在过程结束时，重载解析集为空（没有候选项）或有多个同样好的候选项（歧义）时，编译器才会标记错误。

利用一些巧妙的技巧，涉及编译时类型计算，可以利用 SFINAE 有条件地包含模板或从重载解析集中排除它们。最简洁的语法是由`boost::enable_if` / `boost::disable_if`模板提供的，它们是 Boost.Utility 库的一部分。

让我们编写一个函数模板，将一个元素数组复制到另一个数组中。主模板的签名如下：

```cpp
template <typename T, size_t N>
void copy(T (&lhs)[N], T (&rhs)[N]);
```

因此，您传递两个存储相同类型元素的相同大小的数组，第二个参数的元素按正确顺序复制到第一个数组中。我们还假设数组永远不会重叠；这保持了实现的简单性。不用说，这不是这样的赋值可以发生的最一般情况，但我们稍后会放宽一些这些限制。这是此模板的通用实现：

```cpp
 1 template <typename T, size_t N>
 2 void copy(T (&lhs)[N], T (&rhs)[N])
 3 {
 4   for (size_t i = 0; i < N; ++i) {
 5     lhs[i] = rhs[i];
 6   }
 7 }
```

这里的第一个优化机会是当 T 是 POD 类型且位拷贝足够好且可能更快时。我们将为 POD 类型创建一个特殊的实现，并使用 SFINAE 仅在处理 POD 类型数组时选择此实现。我们的技术应该在处理非 POD 类型数组时将此重载排除在重载集之外。这是 POD 类型的特殊实现：

```cpp
 1 // optimized for POD-type
 2 template <typename T, size_t N>
 3 void copy(T (&lhs)[N], T (&rhs)[N])
 4 {
 5   memcpy(lhs, rhs, N*sizeof(T));
 6 }
```

如果您注意到，这两个实现具有相同的签名，显然不能共存。这就是`boost::enable_if`模板发挥作用的地方。`boost::enable_if`模板接受两个参数：一个类型`T`和第二个类型`E`，默认为`void`。`enable_if`定义了一个名为`type`的嵌入类型，当`T`有一个名为`type`的嵌入类型且`T::type`是`boost::true_type`时，它被 typedef 为`E`。否则，不定义嵌入类型。使用`enable_if`，我们修改了优化实现。

**清单 7.16：使用 enable_if**

```cpp
#include <boost/utility/enable_if.hpp>
#include <boost/type_traits/is_pod.hpp>

// optimized for POD-type
template <typename T, size_t N>
typename boost::enable_if<boost::is_pod<T>>::type
copy(T (&lhs)[N], T (&rhs)[N])
{
  memcpy(lhs, rhs, N*sizeof(T));
}
```

`typename`关键字是必需的，因为否则编译器无法知道表达式`boost::enable_if<boost::is_pod<T>>::type`是一个类型还是一个成员。

如果我们现在实例化一个非 POD 类型的数组，它将解析为默认实现：

```cpp
std::string s[10], s1[10];
copy(s1, s);  // invokes the generic template
```

对`copy`的调用会导致编译器实例化两个模板，但`boost::is_pod<std::string>::type`是`boost::false_type`。现在`enable_if<false_type>`没有嵌套类型，这是`copy`版本的返回类型规范所要求的。因此，存在替换失败，这个重载被从重载解析集中移除，并调用第一个或通用实现。现在考虑以下情况，我们尝试复制 POD 类型（`double`）的数组：

```cpp
double d[10], d1[10];
copy(d1, d);
```

在当前情况下，POD 优化版本将不再遇到替换失败，但默认实现也将与此调用兼容。因此，会出现歧义，这将导致编译器错误。为了解决这个问题，我们必须确保通用实现这次从重载集中豁免自己。这是通过在通用实现的返回类型中使用 `boost::disable_if`（实际上是 `boost::enable_if` 的否定形式）来实现的。

**清单 7.17：使用 disable_if**

```cpp
 1 template <typename T, size_t N>
 2 typename boost::disable_if<boost::is_pod<T>>::type
 3 copy(T (&lhs)[N], T (&rhs)[N])
 4 {
 5   for (size_t i = 0; i < N; ++i) {
 6     lhs[i] = rhs[i];
 7   }
 8 }
```

当 `T` 是 POD 类型时，`is_pod<T>::type` 是 `boost::true_type`。`boost::disable_if<true_type>` 没有嵌套的 `type`，因此在通用实现中会发生替换失败。这样，我们构建了两个互斥的实现，在编译时正确解析。

我们还可以使用 `boost::enable_if_c<>` 模板，它接受一个布尔参数而不是类型。`boost::enable_if_c<true>` 有一个嵌入的 `type`，而 `boost::enable_if_c<false>` 没有。在清单 7.17 中，返回类型将如下所示：

```cpp
typename boost::disable_if_c<boost::is_pod<T>::value>::type
```

标准库在 C++11 中只有 `std::enable_if`，它的行为类似于 `boost::enable_if_c`，接受一个布尔参数而不是类型。它可以从标准头文件 `type_traits` 中获得。

## Boost 元编程库（MPL）

**Boost 元编程库**，简称 **MPL**，是一个用于模板元编程的通用库。它在 Boost 代码库中无处不在，大多数库都使用了 MPL 的一些元编程功能。一些库，如 Phoenix、BiMap、MultiIndex 和 Variant，使用得非常频繁。它被广泛用于类型操作和通过条件选择特定模板实现进行优化。本节是关于 MPL 涉及的一些概念和技术的简要概述。

### 元函数

MPL 库的核心是**元函数**。形式上，元函数要么是只有类型参数的类模板，要么是一个类，它公开一个名为 `type` 的嵌入类型。实际上，如果有的话，类型参数类似于函数的参数，而根据参数在编译时计算得到的嵌入 `type` 类似于函数的返回值。

Boost Type Traits 库提供的类型特征是一流的元函数。考虑 `boost::add_pointer` 类型特征：

```cpp
template <typename T>
struct add_pointer;
```

`add_pointer<int>::type` 类型是 `int*`。`add_pointer` 模板是一个一元元函数，有一个类型参数和一个名为 `type` 的嵌入类型。

有时，类型计算的有效结果是数值型的 - 例如 `boost::is_pointer<T>`（布尔真值）或 `boost::rank<T>`（正整数）。在这种情况下，嵌入的 `type` 将具有一个名为 `value` 的静态成员，其中包含此结果，并且还可以直接从元函数中作为非类型成员的 `value` 访问。因此，`boost::is_pointer<T>::type::value` 和 `boost::is_pointer<T>::value` 都是有效的，后者更加简洁。

### 使用 MPL 元函数

MPL 与 Boost Type Traits 协同工作，使得许多元编程工作变得简单。为此，MPL 提供了许多将现有元函数组合在一起的元函数。

与类型特征一样，MPL 设施被分成独立的、高度细粒度的头文件。所有元函数都在 `boost::mpl` 命名空间中。我们可以使用 MPL 库将未命名的元函数组合成复合元函数。这与运行时的 lambda 和 bind 类似。以下代码片段使用 `boost::mpl::or_` 元函数来检查一个类型是否是数组或指针：

**清单 7.18：使用 MPL 元函数**

```cpp
 1 #include <boost/mpl/or.hpp>
 2 #include <boost/type_traits.hpp>
 34 if (boost::mpl::or_<
 5                     boost::is_pointer<int*>,
 6                     boost::is_array<int*>
 7                    >::value) {
 8   std::cout << "int* is a pointer or array type\n";
 9 }
10
11 if (boost::mpl::or_<
12                     boost::is_pointer<int[]>,
13                     boost::is_array<int[]>
14                    >::value) {
15   std::cout << "int* is a pointer or array type\n";
16 }
```

`boost::mpl::or_` 元函数检查其参数元函数中是否有任何一个评估为 true。我们可以使用一种称为**元函数转发**的技术，创建自己的可重用元函数，将前述逻辑打包起来。

**清单 7.19：创建自己的元函数**

```cpp
 1 #include <boost/mpl/or.hpp>
 2 #include <boost/type_traits.hpp>
 3
 4 template <typename T>
 5 struct is_pointer_or_array
 6       : boost::mpl::or_<boost::is_pointer<T>, 
 7                         boost::is_array<T>>
 8 {};
```

我们使用 `boost::mpl::or_` 来组合现有的类型特性元函数，并从组合实体继承，如前述清单所示（第 6 行）。现在我们可以像使用任何类型特性一样使用 `is_pointer_or_array`。

有时，我们需要将明显是非类型的数值参数传递给元函数。例如，为了比较类型 T 的大小是否小于另一类型 U 的大小，我们最终需要比较两个数值大小。让我们编写以下特性来比较两种类型的大小：

```cpp
template <typename T, typename U> struct is_smaller;
```

`is_smaller<T, U>::value` 如果且仅如果 `sizeof(T)` 小于 `sizeof(U)`，则为 true，否则为 false。

**清单 7.20：使用整数包装器和其他元函数**

```cpp
 1 #include <boost/mpl/and.hpp>
 2 #include <boost/mpl/int.hpp>
 3 #include <boost/mpl/integral_c.hpp>
 4 #include <boost/mpl/less.hpp>
 5 #include <iostream>
 6 namespace mpl = boost::mpl;
 7
 8 template <typename L, typename R>
 9 struct is_smaller : mpl::less<
10                     mpl::integral_c<size_t, sizeof(L)>
11                    , mpl::integral_c<size_t, sizeof(R)>>
12 {};
13
14 int main()
15 {
16   if (is_smaller<short, int>::value) {
17     std::cout << "short is smaller than int\n";
18   } else { ... }
19 }
```

MPL 提供了一个元函数 `boost::mpl::integral_c` 来包装指定类型（`size_t`、`short` 等）的整数值。我们使用它来包装两种类型的大小。`boost::mpl::less` 元函数比较这两个大小，如果第一个参数在数值上小于第二个参数，则其嵌套的 `value` 只会设置为真。我们可以像使用其他特性一样使用它。

现在我们将尝试写一些稍微不那么琐碎的东西。我们想要编写一个函数来赋值数组。以下是函数模板的签名：

```cpp
template <typename T, size_t M,
          typename S, size_t N>
void arrayAssign(T(&lhs)[M], S(&rhs)[N]);
```

类型 `T(&)[M]` 是指向 `M` 个类型为 `T` 的元素的数组的引用；`S (&)[N]` 也是如此。我们希望将第二个参数 `rhs` 赋给第一个参数 `lhs`。

您可以将类型为 `S[]` 的数组赋给类型为 `T[]` 的数组，只要 `S` 和 `T` 是相同类型，或者从 `S` 到 `T` 的转换是允许的且不会导致信息丢失。此外，`M` 不能小于 `N`。我们将定义一个特性 `is_array_assignable` 来捕捉这些约束。因此，只有在满足前述约束时，`is_array_assignable<T(&)[M], S(&)[N]>::value` 才为真。

首先，我们需要定义三个辅助元函数：`is_floating_assignable`，`is_integer_assignable` 和 `is_non_pod_assignable`。`is_floating_assignable<T, S>` 元函数检查是否可以将类型为 `S` 的数值赋给浮点类型 `T`。`is_integer_assignable<T, S>` 元函数检查 `T` 和 `S` 是否都是整数，并且 `T` 和 `S` 的赋值不会导致潜在的损失或缩小。因此，有符号整数不能赋给无符号整数，无符号整数只能赋给更大的有符号整数类型，依此类推。`is_non_pod_assignable<T, S>` 特性检查 `S` 和 `T` 中至少有一个是非 POD 类型，并且是否存在从 `S` 到 `T` 的赋值运算符。

然后，我们将使用这些和其他元函数来定义 `is_array_assignable`。

**清单 7.21：使用 MPL 定义有用的类型特性**

```cpp
 1 #include <boost/type_traits.hpp>
 2 #include <type_traits>
 3 #include <boost/mpl/and.hpp>
 4 #include <boost/mpl/or.hpp>
 5 #include <boost/mpl/not.hpp>
 6 #include <boost/mpl/greater.hpp>
 7 #include <boost/mpl/greater_equal.hpp>
 8 #include <boost/mpl/equal.hpp>
 9 #include <boost/mpl/if.hpp>
10 #include <boost/mpl/integral_c.hpp>
11 #include <boost/utility/enable_if.hpp>
12 #include <iostream>
13
14 namespace mpl = boost::mpl;
15
16 template <typename T, typename S>
17 struct is_larger
18    : mpl::greater<mpl::integral_c<size_t, sizeof(T)>
19                 , mpl::integral_c<size_t, sizeof(S)>>
20 {};
21 template <typename T, typename S>
22 struct is_smaller_equal
23   : mpl::not_<is_larger<T, S>>
24 {};
25
26 template <typename T, typename S>
27 struct is_floating_assignable
28    : mpl::and_<
29        boost::is_floating_point<T>
30      , boost::is_arithmetic<S>
31      , is_smaller_equal<S, T>
32      >
33 {};
34
35 template <typename T, typename S>
36 struct is_integer_assignable
37    : mpl::and_<
38        boost::is_integral<T>
39      , boost::is_integral<S>
40      , is_smaller_equal<S, T>
41      , mpl::if_<boost::is_signed<S>
42               , boost::is_signed<T>
43               , mpl::or_<boost::is_unsigned<T>
44                        , mpl::and_<boost::is_signed<T>
45                                  , is_larger<T, S>>
46                         >
47               >
48      >
49 {};
50
51 template <typename T, typename S>
52 struct is_non_pod_assignable
53    : mpl::and_<
54                mpl::not_<mpl::and_<boost::is_pod<T>
55                                  , boost::is_pod<S>>
56                         >
57              , std::is_assignable<T, S>
58               >
59 {};
60
61 template <typename T, typename U>
62 struct is_array_assignable
63    : boost::false_type
64 {};
65
66 template <typename T, size_t M, typename S, size_t N>
67 struct is_array_assignable<T (&)[M], S (&)[N]>
68    : mpl::and_<
69           mpl::or_<
70               boost::is_same<T, S>
71             , is_floating_assignable<T, S>
72             , is_integer_assignable<T, S>
73             , is_non_pod_assignable<T, S>
74              >
75         , mpl::greater_equal<mpl::integral_c<size_t, M>
76                            , mpl::integral_c<size_t, N>>
77         >
78 {};
79
80
81 template <typename T, size_t M, typename S, size_t N>
82 typename boost::enable_if<is_array_assignable<T(&)[M], 
83                                               S(&)[N]>>::type
84 assignArray(T (&target)[M], S (&source)[N])
85 { /* actual copying implementation */ }
```

`is_array_assignable` 元函数的主模板始终返回 false（第 61-64 行）。`is_array_assignable` 的部分特化（第 66-78 行）是实现的核心。它使用 `mpl::or_` 元函数来检查是否满足以下任何一个条件：

+   源类型和目标类型相同（第 70 行）

+   目标类型是浮点数，源类型是数值，并且可以进行赋值而不会缩小（第 71 行）

+   目标类型是整数（有符号或无符号），源类型是整数，并且可以进行赋值而不会缩小（第 72 行）

+   源和目标类型中至少有一个是非 POD 类型，并且从源类型到目标类型的转换是可能的（第 73 行）

`mpl::or_` 元函数类似于 C++ 的逻辑或运算符，如果传递的条件中有任何一个为真，则其静态成员 `value` 就设置为真。除了这个复合条件为真之外，还必须满足以下条件：

目标数组中的元素数量至少应与源数组中的元素数量一样多。

我们使用`mpl::greater_equal`元函数来比较这两个值`M`和`N`。由于元函数需要获取类型参数，我们使用`boost::mpl::integral_c`包装器生成与`M`和`N`对应的类型参数（第 75-76 行）。我们使用`mpl::and_`元函数计算条件 1-4 的逻辑或及其与条件 5 的逻辑与（第 61 行）。

我们使用`boost::enable_if`，它利用 SFINAE 在`is_array_assignable`返回 false 时禁用`assignArray`。

现在让我们看一下`is_integer_assignable`的实现。它检查目标和源类型是否都是整数（第 38-39 行），并且源类型不大于目标类型（第 40 行）。此外，我们使用`boost::mpl::if_`元函数，它需要三个元函数；如果第一个元函数评估为`true`，则返回第二个元函数，否则返回第三个元函数。使用`mpl::if_`，我们表达了源类型和目标类型的约束（第 41-47 行）。如果源类型是有符号整数（第 41 行），那么目标类型也必须是有符号整数（第 42 行）。但是如果源类型是无符号整数，那么目标类型必须是无符号整数（第 43 行）或大于源类型的有符号整数（第 44-45 行）。其余的特性也是使用 Boost MPL 库设施类似地定义的。

元编程不仅是选择最佳实现或在编译时捕获违规的工具。它实际上有助于创建像`boost::tuple`或`boost::variant`这样的表达性库，涉及重要的类型操作。我们只介绍了 Boost MPL 库中的一些基本抽象，以帮助您轻松进入模板元编程。如果您已经在本章中的示例中工作过，那么您应该没有问题自己进一步探索 MPL。

# 领域特定嵌入式语言

在本章的最后三分之一，我们主要看了高阶和编译时编程在领域特定嵌入式语言中的应用。

## 惰性评估

在 C++中，当我们看到以下代码时：

```cpp
z = x + y();
```

我们知道当控制到达语句`z = x + y()`之后，`z`的值会立即计算。事实上，计算总和涉及对`x`和`y()`表达式本身的评估。在这里，`y`可能是一个函数或一个函数符实例，因此对`y()`的调用将依次触发更多的评估。无论`z`是否以后被用于任何事情，它的值仍然会被计算。这是许多编程语言遵循的**急切评估**模型。实际情况稍微复杂一些，因为编译器可以重新排序和优化计算，但程序员对这个过程几乎没有控制。

如果我们能够推迟对这些表达式及其任何子表达式的评估，直到我们必须使用结果，会怎么样？这是许多函数式编程语言中看到的**惰性评估**模型，比如 Haskell。如果我们能够构造惰性评估的任意语言表达式，那么这些表达式就可以像函数符一样传递，并在必要时进行评估。想象一个名为`integrate`的函数，它评估任意函数的定积分，给定边界值：

```cpp
double integrate(std::function<double(double)> func,
                 double low, double high);
```

想象一下通过调用以下代码来评估积分![惰性评估](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-boost-cpp-lib/img/1217OT_07_02.jpg)：

```cpp
double result = integrate(x + 1/x, 1, 10);
```

关键是不急切评估表达式`x + 1/x`，而是将其作为惰性表达式传递给`integrate`函数。现在 C++没有任何内置机制来使用常规变量创建这样的惰性表达式。但是我们可以很容易地编写一个 lambda 来完成我们的工作：

```cpp
result = integrate([](double) { return x + 1/x; }, 1, 10);
```

这样做虽然有一些语法噪音，但在许多应用中，lambda 和 bind 并不适用于复杂性。在本节中，我们简要研究**表达式模板**，更一般地说，**领域特定嵌入式语言**（**DSELs**），这是在 C++中构建惰性评估函数对象的手段，可以在不牺牲表达语法的情况下完成工作。

## 表达式模板

那么，如何在领域语言中表达一个函数*f(x)=x+1/x*，而不是通过 C++的语法妥协来实现呢？为了创建一个通用解决方案，我们必须能够支持各种代数表达式。让我们从最基本的函数开始 - 一个常数函数，比如*f(x)=5*。无论*x*的值如何，这个函数应该始终返回 5。

以下函数对象可用于此目的：

**清单 7.22a：表达式模板迷你库 - 惰性文字**

```cpp
 1 #include <iostream>2
 3 struct Constant {
 4   Constant(double val = 0.0) : val_(val) {}
 5   double operator()(double) const { return val_; }
 67   const double val_;
 8 };
 9
10 Constant c5(5);
11 std::cout << c5(1.0) << '\n';  // prints 5
```

`operator()`返回存储的`val_`并忽略它的参数，该参数是无名的。现在让我们看看如何使用类似的函数对象来表示*f(x)=x*这样的函数：

**清单 7.22b：表达式模板迷你库 - 惰性变量**

```cpp
 1 struct Variable {
 2   double operator()(double x) { return x; }
 3 };
 4
 5 Variable x;
 6 std::cout << x(8) << '\n';  // prints 8
 7 std::cout << x(10) << '\n'; // prints 10
```

现在我们有一个产生传递给它的任何值的函数对象；正是*f(x)=x*所做的。但是如何表达一个类似*x + 1/x*的表达式呢？表示单变量任意函数的函数对象的一般形式应该如下：

```cpp
struct Expr {
  ...
  double operator()(double x) {
    return (value computed using x);
  }
};
```

`Constant`和`Variable`都符合这个形式。但是考虑一个更复杂的表达式，比如*f(x)=x+1/x*。我们可以将它分解为两个子表达式*x*和*1/x*，由二元操作+作用。表达式*1/x*可以进一步分解为两个子表达式*1*和*x*，由二元操作/作用。

这可以用**抽象语法树**（**AST**）来表示，如下所示：

![表达式模板](https://github.com/OpenDocCN/freelearn-c-cpp-pt2-zh/raw/master/docs/lrn-boost-cpp-lib/img/1217OT_07_01.jpg)

树中的非叶节点表示操作。二元操作节点有两个子节点：左操作数是左子节点，右操作数是右子节点。AST 在根部有一个操作（*+*），并且有两个子表达式作为两个子节点。左子表达式是*x*，而右子表达式是*1/x*。*1/x*进一步在一个子树中被分解，根部是操作（*/*），*1*是左子节点，*x*是右子节点。注意像*1*和*x*这样的值只出现在叶级别，并且对应于我们定义的`Constant`和`Variable`类。所有非叶节点表示操作符。

我们可以将复杂表达式建模为由两个带有运算符的子表达式组成的表达式：

**清单 7.22c：表达式模板迷你库 - 复杂表达式**

```cpp
 1 template <typename E1, typename E2, typename OpType>
 2 struct ComplexExpression {
 3   ComplexExpression(E1 left, E2 right) : left_(left), 
 4             right_(right) 
 5   {}
 6
 7   double operator()(double x) { 
 8     return OpType()(left_(x), right_(x));
 9   }
10
11   E1 left_; E2 right_;
12 };
```

当调用`ComplexExpression`函数对象时，也就是当它评估其左右子表达式然后对它们应用运算符（第 7 行），这将触发左右子表达式的评估。如果它们本身是`ComplexExpression`，那么它们将触发进一步的评估，深度优先遍历树。这是明确的**延迟评估**。

现在，为了轻松生成复杂表达式函数对象，我们需要重载算术运算符，以组合`Constant`、`Variable`、`ComplexExpression<>`或原始算术类型的子表达式。为了更好地做到这一点，我们为所有类型的表达式创建一个名为`Expr`的抽象。我们还修改了`ComplexExpression`的定义以使用`Expr`。

**清单 7.22d：表达式模板迷你库 - 通用表达式**

```cpp
 1 template <typename E, typename Enable = void>
 2 struct Expr {
 3   Expr(E e) : expr_(e) {}
 4  
 5   double operator()(double x) { return expr_(x); }
 6 
 7 private: 
 8   E expr_;
 9 };
10
11 template <typename E1, typename E2, typename Op>
12 struct ComplexExpression
13 {
14   ComplexExpression(Expr<E1> left, Expr<E2> right) : 
15                    left_(left), right_(right) {}
16
17   double operator()(double d) {
18     return Op()(left_(d), right_(d));
19   }
20
21 private:
22   Expr<E1> left_;
23   Expr<E2> right_;
24 };
```

我们将传递包装在`Expr`中的各种表达式，例如`Expr<Constant>`、`Expr<ComplexExpression>`等。如果您不确定为什么我们需要第二个模板参数`Enable`，那么稍等片刻就会得到答案。在此之前，我们将定义任何两个`Expr`之间的算术运算符，从`operator+`开始：

**清单 7.22e：表达式模板迷你库 - 重载运算符**

```cpp
 1 #include <functional>
 2 
 3 template <typename E1, typename E2>
 4 Expr<ComplexExpression<E1, E2, std::plus<double>>> 
 5           operator+ (E1 left, E2 right)
 6 {
 7   typedef ComplexExpression <E1, E2,
 8                                 std::plus<double>> ExprType;
 9   return ExprType(Expr<E1>(left), Expr<E2>(right));
10 }
```

任何二元操作都将产生一个 `ComplexExpression`。由于我们将一切抽象为 `Expr`，所以我们从算术运算符中返回 `Expr<ComplexExpression<…>>`。在相同的行上很容易编写 `operator-`、`operator*` 或 `operator/`。我们可以在前面的实现中用 `std::plus` 替换为 `std::minus`、`std::multiples` 或 `std::divides`。

只有一个细节需要注意。有了前面的代码，我们可以写出以下形式的表达式：

```cpp
Variable x;
Constant c1(1);
integrate(x + c1/x, 1, 10);
```

但我们无法使用数字文字来写 *x + 1/x*。为了做到这一点，我们必须自动将数字文字转换为 `Constant`。为此，我们将创建 `Expr` 的部分特化，并使用 `boost::enable_if` 为数字类型启用它。这就是 `Expr` 模板的 `Enable` 参数派上用场的地方。对于主模板，默认为 `void`，但它帮助我们编写包装算术类型文字的部分特化。

**列表 7.22f：一个表达式模板迷你库 – 一个小技巧**

```cpp
 1 #include <boost/utility/enable_if.hpp>
 2 #include <boost/type_traits/is_arithmetic.hpp>
 34 template <typename E>
 5 struct Expr<E, typename boost::enable_if< 
 6                               boost::is_arithmetic<E>>::type> 
 7 {
 8   Expr(E& e) : expr_(Constant(e)) {}
 9
10   double operator()(double x) { return expr_(x); }
11
12   Constant expr_;
13 };
```

只有当 `E` 是算术类型（`int`、`double`、`long`等）时，才会调用这个部分特化（partial specialization）。这将算术值存储为 `Constant`。有了这个改变，我们可以在我们的表达式中使用数字文字，只要表达式中有一个单一的 `Variable`，这些文字就会通过列表 7.22f 中的部分特化被包装为 `Constant`。现在我们可以仅使用自然的代数表达式生成一个函数器：

**列表 7.22g：一个表达式模板迷你库 – 使用表达式**

```cpp
Variable x;
std::cout << (x + 1/x)(10) << '\n'; 
std::cout << ((x*x - x + 4)/(2*x))(10) << '\n';
```

我们可以对这个非常基本的 *表达式模板* 库进行许多更多的改进，即使代码不到一百行。但它已经允许我们使用非常简单的语法生成单变量的任意代数函数。这是一个*特定领域语言*的例子。而且，特别是因为我们使用有效的 C++ 语法来做所有这些，而不是定义一个新的语法，它被称为**特定领域嵌入语言**（**DSEL**）或有时称为**嵌入式特定领域语言**（**EDSL**）。现在我们将看一下 Boost Phoenix，一个复杂的惰性表达式库。

## Boost Phoenix

Boost Phoenix 3 是一个在 C++ 中启用函数式编程构造的库。它定义了一个复杂而易读的 DSEL，其中包含大量的函数器和运算符，可以用来生成相当复杂的 lambda。它提供了一个全面的库，用于构造惰性表达式，并展示了表达式模板可以实现的优秀示例。本节简要介绍了如何使用 Phoenix 表达式作为 lambda，并将看到一些使用 Boost Spirit Parser Framework 的 Phoenix 示例。这是一个非常庞大的库，甚至在一个章节中都无法覆盖，更不用说它的一个子部分，但这个介绍应该足够提供足够的支持来掌握 Phoenix，同时还可以获得优秀的在线文档的好处。

Phoenix 表达式由**演员**组成，演员是惰性函数的抽象。演员用于生成未命名函数或 lambda。它们通过将一些参数绑定到值并保持其他参数未指定来支持部分函数应用。它们可以组合以生成更复杂的函数器。在这个意义上，Phoenix 是一个 lambda 语言库。

演员根据功能进行分类，并通过一组头文件公开。最基本的演员是 `val`，它表示惰性不可变值（与我们表达式模板示例中的 `Constant` 函数器类似）。`ref` 演员用于创建惰性可变变量引用，`cref` 演员生成惰性不可变引用。还有一整套定义惰性运算符的演员，包括算术运算符（`+`、`-`）、比较运算符（`<`、`==`、`>`）、逻辑运算符（`&&`、`||`）、位运算符（`|`、`^`、`&`）和其他类型的运算符。仅使用这些，我们就可以构造代数表达式，就像我们在下面的示例中所做的那样：

**清单 7.23：使用 Phoenix 的惰性代数表达式**

```cpp
 1 #include <boost/phoenix/core.hpp>
 2 #include <boost/phoenix/operator.hpp>
 3 #include <iostream>
 4
 5 int main() {
 6   namespace phx = boost::phoenix;
 7   double eX;
 8   auto x = phx::ref(eX);
 9
10   eX = 10.0;
11   std::cout << (x + 1/x)() << '\n';              // prints 10.1
12   std::cout << ((x*x -x + 4) / (2*x))() << '\n'; // prints 4.7
13 }
```

使用`boost::phoenix::ref`，我们生成了一个用于惰性评估变量`eX`（**e**代表**eager**）的 actor，并将其缓存在变量`x`中。表达式`x + 1/x`和`x*x – x + 4`生成了匿名函数，就像清单 7.22 中的表达式模板一样，只是`x`已经绑定到变量`eX`。actor `x`的存在通过其影响了表达式中的数字文字；这些文字被包装在`boost::phoenix::val`中。表达式中使用的`+`、`-`、`*`和`/`操作符是来自 Phoenix 的惰性操作符（就像我们在清单 7.22e 中为我们的表达式模板定义的操作符一样），并生成了匿名函数。

使用 Phoenix 有时可以非常简洁地编写简单的 lambda。看看我们如何使用`std::for_each`和 Phoenix 的惰性`operator<<`来打印向量中的每个元素：

**清单 7.24：使用 Phoenix 的简单 lambda**

```cpp
 1 #include <boost/phoenix/core.hpp>
 2 #include <boost/phoenix/operator.hpp>
 3 #include <vector>
 4 #include <string>
 5 #include <iostream>
 6 #include <algorithm>
 7
 8 int main() {
 9   using boost::phoenix::arg_names::arg1;
10   std::vector<std::string> vec{"Lambda", "Iota", 
11                                "Sigma", "Alpha"};
12   std::for_each(vec.begin(), vec.end(), 
13                 std::cout << arg1 << '\n');
14 }
```

表达式`std::cout << arg1`实际上是生成一个函数对象的 lambda。actor `arg1`（`boost::phoenix::arg_names::arg1`）代表函数对象的第一个参数，并且是惰性评估的。表达式`std::cout << arg1`中的`arg1`的存在调用了惰性`operator<<`并感染整个表达式，生成一个未命名函数，将其参数打印到标准输出。通常情况下，您可以使用`arg1`到`argN`来引用使用 Phoenix 生成的 N 元函数的惰性参数。默认情况下，支持最多十个参数 actors（`arg1`到`arg10`）。这类似于`boost::bind`的`_1`、`_2`等。您还可以使用`boost::phoenix::placeholders::_1`、`_2`等。

Phoenix actors 不仅限于涉及运算符的表达式。我们可以生成惰性评估包含分支和循环结构的整个代码块的 actors。假设我们有一个乐队阵容中人员姓名的向量，并且我们想要打印一个人是歌手还是乐器演奏者：

**清单 7.25：使用 Phoenix 的惰性控制结构**

```cpp
 1 #include <boost/phoenix/core.hpp>
 2 #include <boost/phoenix/statement/if.hpp>
 3 #include <boost/phoenix/operator.hpp>
 4 #include <algorithm>
 5 #include <vector>
 6 #include <iostream>
 7 
 8 int main() {
 9   namespace phx = boost::phoenix;
10   using namespace phx;
11   using phx::arg_names::arg1;
12
13   std::vector<std::string> names{"Daltrey", "Townshend", 
14                                  "Entwistle", "Moon"};
15   std::for_each(names.begin(), names.end(),   
16             if_(arg1 == "Daltrey") [
17               std::cout << arg1 << ", vocalist" << '\n'
18             ].else_[
19               std::cout << arg1 << ", instrumentalist" << '\n'
20             ]
21             );
22 }
```

我们想要遍历*The Who*四位传奇成员的姓氏向量，并列出他们的角色。对于（罗杰）达特里，角色将是一个歌手，而对于其他人来说，是乐器演奏者。我们使用`std::for_each`来迭代名单。我们通过使用 Phoenix 的语句 actors 生成的一元函数来传递给它一个 unary functor，具体来说是`boost::phoenix::if_`。

语法足够直观，可以理解正在发生的事情。`if_`和`else_`块中的实际语句被放在方括号中，而不是大括号（不能被重载），并且被惰性评估。如果有多个语句，它们需要用逗号分隔。注意`else_`是在前面的表达式上调用的成员调用，用点调用（第 18 行）。`arg1`的存在被称为*感染*语句，即它调用了惰性`operator<<`并导致文字字符串自动包装在`boost::phoenix::val`中（第 16、17、19 行）。运行此代码将打印以下内容：

```cpp
Daltrey, vocalist
Townshend, instrumentalist
Entwistle, instrumentalist
Moon, instrumentalist
```

Phoenix 的强大之处已经显而易见。它使用标准 C++运算符重载和函数对象定义了一个表达力强的子语言，可以轻松生成所需的未命名函数或 lambda，并开始模仿宿主语言本身。Phoenix 库还有更多内容。它充斥着用于惰性评估 STL 容器成员函数和 STL 算法的 actors。让我们看一个例子来更好地理解这一点：

**清单 7.26：用于 STL 算法和容器成员函数的 actors**

```cpp
 1 #include <vector>
 2 #include <string>
 3 #include <iostream>
 4 #include <boost/phoenix/core.hpp>
 5 #include <boost/phoenix/stl/algorithm.hpp>
 6 #include <boost/phoenix/stl/container.hpp>
 7 #include <cassert>
 8
 9 int main() {
10   namespace phx = boost::phoenix;
11   using phx::arg_names::arg1;
12   std::vector<std::string> greets{ "Hello", "Hola", "Hujambo", 
13                                    "Hallo" };
14   auto finder = phx::find(greets, arg1);
15   auto it = finder("Hujambo");
16
17   assert (phx::end(greets)() != it);
18   std::cout << *it << '\n';
19   assert (++it != greets.end());
20   std::cout << *it << '\n';
21 }
```

我们有一个包含不同语言的问候语（英语、西班牙语、斯瓦希里语和德语）的向量`greets`，我们想要搜索特定的问候语。我们想要使用 Phoenix 进行延迟搜索。Phoenix 提供了用于生成大多数 STL 算法的延迟版本的 actors。我们使用`boost/phoenix/stl/algorithm.hpp`头文件中可用的`std::find`算法的延迟形式（第 5 行），并调用`boost::phoenix::find` actor 来生成一个名为`finder`的一元函数对象（第 14 行）。`finder`函数对象以`greets`中要查找的字符串作为唯一参数。调用`boost::phoenix::find(greets, arg1)`需要两个参数并生成一个一元函数对象。第一个参数是对向量`greets`的引用，它会自动包装在`cref` actor 中并存储以供以后延迟评估。`find`的第二个参数是 Phoenix 占位符`arg1`。

当`finder`以要查找的字符串作为唯一参数调用时，它评估`arg1` actor 以获取此字符串参数。它还评估它之前存储的`cref` actor 以获取对`greets`的引用。然后在`greets`向量上调用`std::find`，查找传递的字符串，返回一个迭代器。我们查找向量中存在的字符串`Hujambo`（第 15 行）。

为了检查返回的迭代器是否有效，我们需要将其与`greets.end()`进行比较。只是为了表明可以做到这一点，我们使用从头文件`boost/phoenix/stl/algorithm.hpp`中可用的`boost::phoenix::end` actor 生成`end`成员函数调用的延迟版本。调用`boost::phoenix::end(greets)`生成一个函数对象，我们通过在后面加括号来直接调用它。我们将结果与`finder`返回的迭代器进行比较（第 17 行）。我们打印`find`返回的迭代器指向的问候语以及其后的元素（第 18-20 行）：

```cpp
Hujambo
Hallo
```

Phoenix 的 actors 是多态的。您可以在任何支持通过`std::find`进行搜索的容器上应用`boost::phoenix::find`，并且可以查找底层容器可以存储的任何类型的对象。

在 Phoenix 的最后一个例子中，我们将看看如何定义自己的 actor，这些 actor 可以与 Phoenix 的其余部分相匹配。我们有一个名称向量，我们从中打印每个条目的第一个名称，使用`std::for_each`和使用 Phoenix 生成的函数对象。我们通过查找字符串中的第一个空格字符并提取直到该点的前缀来从名称字符串中提取名字。我们可以使用`find` actor 来定位空格，但是要提取前缀，我们需要一种延迟调用`std::string`的`substr`成员的方法。目前在 Phoenix 中没有`substr` actor 可用，因此我们需要自己编写：

**清单 7.27：用户定义的 actors 和 STL actors**

```cpp
 1 #include <vector>
 2 #include <string>
 3 #include <iostream>
 4 #include <algorithm>
 5 #include <boost/phoenix/core.hpp>
 6 #include <boost/phoenix/function.hpp>
 7 #include <boost/phoenix/operator.hpp>
 8 #include <boost/phoenix/stl/container.hpp>
 9 #include <boost/phoenix/stl/algorithm.hpp>
10
11 struct substr_impl {
12   template<typename C, typename F1, typename F2>
13   struct result  {
14     typedef C type;
15   };
16
17   template<typename C, typename F1, typename F2>
18   C operator()(const C& c, const F1& offset, 
19               const F2& length) const
20   {  return c.substr(offset, length); }
21 };
22
23 int main() {
24   namespace phx = boost::phoenix;
25   using phx::arg_names::arg1;
26
27   std::vector<std::string> names{"Pete Townshend", 
28             "Roger Daltrey", "Keith Moon", "John Entwistle"};
29   phx::function<substr_impl> const substr = substr_impl();
30
31   std::for_each(names.begin(), names.end(), std::cout <<
32                substr(arg1, 0, phx::find(arg1, ' ')
33                                - phx::begin(arg1))
34                 << '\n');
35 }
```

我们编写了`substr_impl`函数对象，它有一个成员模板`operator()`（第 17 行）和一个名为`result`的元函数（第 12 行）。`operator()`是一个模板，用于使`substr_impl`多态化。任何具有名为`substr`的成员函数的类型`C`，它接受类型为`F1`和`F2`的两个参数（可能是不同类型）都可以由这个单一实现覆盖（第 17-20 行）。`result`元函数中的`type`是包装函数（`substr`）的返回类型。实际的`substr`操作者是`boost::phoenix::function<substr_impl>`类型的实例（第 29 行）。我们使用刚刚定义的`substr`操作者来生成一个一元函数对象，然后将其传递给`std::for_each`算法（第 32-33 行）。由于我们想要从`names`向量中的每个字符串中提取第一个名字，所以第一个参数是`arg1`（传递给函数对象的名字），第二个偏移参数是 0，而第三个长度参数是字符串中第一个空格字符的偏移量。第三个参数被懒惰地计算为表达式`boost::phoenix::find(arg1, ' ') – boost::phoenix::begin(arg1)`。`find(arg1, ' ')`是一个操作者，它使用我们在列表 7.26 中也使用的 Phoenix 的通用查找操作者来查找字符串中的第一个空格。`begin(arg1)`是一个操作者，它返回其参数（在本例中是字符串）的起始迭代器。它们之间的差异返回第一个名字的长度。

## 提升 Spirit 解析器框架

Boost Spirit 是一个非常流行的用于生成词法分析器和解析器的领域特定语言，它使用 Boost Phoenix。编写自定义词法分析器和解析器过去严重依赖于专门的工具，如 lex/flex、yacc/bison 和 ANTLR，这些工具从**扩展巴科斯-瑙尔范式**（EBNF）的语言中立规范生成 C 或 C++代码。Spirit 消除了在语言之外创建这样的规范的需要，也消除了从这样的规范翻译的工具的需要。它在 C++中定义了一个具有直观语法的声明式领域特定语言，并且只使用 C++编译器来生成解析器。Spirit 大量使用模板元编程，导致编译时间较慢，但生成的解析器在运行时非常高效。

Spirit 是一个包含 Spirit Lex（词法分析器）、Spirit Qi（解析器）和 Spirit Karma（生成器）的丰富框架。您可以单独使用它们，或者协作使用它们来构建强大的数据转换引擎。

本书中我们只关注 Spirit Qi。它主要用于根据一些指定的*语法*来解析*文本数据*，数据应该遵守以下目标：

+   验证输入是否符合语法

+   将符合语法的输入分解为有意义的语义组件

例如，我们可以解析一些输入文本，以验证它是否是有效的时间戳，如果是，提取时间戳的组件，如年、月、日、小时、分钟等。为此，我们需要为时间戳定义一个语法，并且需要定义在解析数据时要采取的操作，以其语义组成部分的形式。让我们看一个具体的例子。

### 使用 Spirit Qi

Spirit 提供了**预定义解析器**，可以使用 Spirit 定义的**解析器操作者**组合起来，为我们的需求定义解析器。一旦定义好，我们可以将解析器或其组件存储为可以与其他规则组合的**规则**。或者我们可以直接将其传递给 Qi 的**解析 API**，如`parse`或`phrase_parse`，以及要解析的输入。

#### 预定义解析器

Qi 提供了许多预定义的解析器，可以用来解析基本的数据片段。这些解析器可以在命名空间`boost::spirit::qi`下使用或别名。以下是这些解析器及其目的的列表：

| 输入类 | 解析器 | 目的 |
| --- | --- | --- |
| 整数 | `int_`, `uint_`, `short_`, `ushort_`, `long_`, `ulong_`, `long_long`, `ulong_long` | 解析有符号和无符号整数 |
| 实数 | `float_`, `double_`, `long_double` | 解析带有小数点的实数 |
| 布尔 | `bool_`, `true_`, `false_` | 解析字符串`true`和`false`中的一个或两个 |
| 字符 | `char_`, `alpha`, `lower`, `upper`,`digit`, `xdigit`, `alnum`,`space`, `blank`,`punct`, `cntrl`, `graph`, `print` | 解析不同类别的字符，如字母、数字、十六进制数字、标点等。 |
| 字符串 | `String` | 解析特定字符串 |

在上表中列出的解析器是预定义对象，而不是类型。每个解析器都有对应的通用解析器模板。例如，模板`boost::spirit::qi::int_parser`可用于定义有符号整数的自定义解析器。还有许多其他模板，包括`boost::spirit::qi::uint_parser`、`boost::spirit::qi::bool_parser`等等。

#### 解析 API

Qi 提供了两个函数模板，`parse`和`phrase_parse`，用于解析文本输入。每个函数都接受定义输入范围和解析器表达式的迭代器对。此外，`phrase_parse`接受第二个解析器表达式，用于匹配和跳过空白。以下简短的示例向您展示了使用 Spirit 的精髓：

**清单 7.28：一个简单的 Spirit 示例**

```cpp
 1 #include <boost/spirit/include/qi.hpp>
 2 #include <cassert>
 3 namespace qi = boost::spirit::qi;
 4
 5 int main()
 6 {
 7   std::string str = "Hello, world!";
 8
 9   auto iter = str.begin();
10   bool success = qi::parse(iter, str.end(), qi::alpha);
11                            
12   assert(!success);
13   assert(iter - str.begin() == 1);
14 }
```

我们包含头文件`boost/spirit/include/qi.hpp`以便访问 Spirit Qi 函数、类型和对象。我们的输入是字符串`Hello, world!`，并且使用预定义解析器`alpha`，我们希望强制第一个字符是拉丁字母表中的字母，而不是数字或标点符号。为此，我们使用`parse`函数，将其传递给定义输入和`alpha`解析器的迭代器对（第 10 行）。`parse`函数如果成功解析输入则返回`true`，否则返回`false`。范围开始的迭代器被递增以指向输入中第一个未解析的字符。由于`Hello, world!`的第一个字符是 H，`alpha`解析器成功解析它，将`iter`递增 1（第 13 行），`parse`返回`true`（第 12 行）。请注意，第一个迭代器作为非 const 引用传递给`parse`，并且由`parse`递增；我们传递`str.begin()`的副本的原因。

#### 解析器运算符和表达式

Spirit 定义了一些名为**解析器运算符**的重载运算符，可以用来将简单解析器组合成复杂的解析器表达式，包括预定义的解析器。以下表总结了其中一些运算符：

| 运算符 | 类型 | 目的 | 示例 |
| --- | --- | --- | --- |
| >> (序列运算符) | 二进制，中缀 | 两个解析器依次解析两个标记 | `string("Hello") >> string("world")`匹配`Helloworld`。 |
| &#124; (分歧运算符) | 二进制，中缀 | 两个解析器中的任何一个都能解析标记，但不能同时解析 | `string("Hello") &#124; string("world")`匹配`Hello`或`world`但不匹配`Helloworld`。 |
| * (Kleene 运算符) | 一元，前缀 | 解析空字符串或一个或多个匹配的标记 | `*string("Hello")`匹配空字符串、`Hello`、`HelloHello`等。 |
| + (加号运算符) | 一元，前缀 | 解析一个或多个匹配的标记 | `+string("Hello")`匹配`Hello`、`HelloHello`等，但不匹配空字符串。 |
| ~ (否定运算符) | 一元，前缀 | 解析不匹配解析器的标记 | `~xdigit`将解析任何不是十六进制数字的字符。 |
| - (可选运算符) | 一元，前缀 | 解析空字符串或单个匹配的标记 | `-string("Hello")`匹配`Hello`或空字符串。 |
| - (差分运算符) | 二进制，中缀 | *P1 - P2* 解析 P1 可以解析而 P2 不能解析的任何标记 | `uint_ - ushort_`匹配任何不是`unsigned short`的`unsigned int`。在一个有 2 字节`short`的系统上，匹配 65540 但不匹配 65530。 |
| %（列表运算符） | 二进制，中缀 | *P1 % D*将输入在匹配 D 的分隔符处拆分为与 P1 匹配的标记 | `+alnum % +(space | punct)`使用空格和标点作为分隔符将输入文本字符串拆分为字母数字字符串。 |
| | | （顺序或运算符） | 二进制，中缀 | *P1 | | P2*等同于*P1 | (P1 >> P2)* | `string("Hello") | | string("world")`匹配`Hello`或`Helloworld`但不匹配`world`。 |

请注意，有一个一元`operator-`，即可选运算符，和一个二元`operator-`，即差运算符。

`boost::spirit::qi::parse`函数模板在解析时不会跳过任何空白字符。有时，在解析时忽略标记之间的空格是很方便的，`boost::spirit::qi::phrase_parse`就是这样做的。例如，解析器`string("Hello") >> string("world")`在使用`boost::spirit::qi::parse`时会解析`Helloworld`，但不会解析`Hello, world!`。但是，如果我们使用`phrase_parse`并忽略空格和标点，那么它也会解析`Hello, world!`。

**清单 7.29：使用 phrase_parse**

```cpp
 1 #include <boost/spirit/include/qi.hpp>
 2 #include <cassert>
 3 namespace qi = boost::spirit::qi;
 4
 5 int main()
 6 {
 7   std::string str = "Hello, world!";
 8
 9   auto iter = str.begin();
10   bool success = qi::parse(iter, str.end(),
11                   qi::string("Hello") >> qi::string("world"));
12
13   assert(!success);
14
15   iter = str.begin();
16   success = qi::phrase_parse(iter, str.end(),
17                   qi::string("Hello") >> qi::string("world"),
18                   +(qi::space|qi::punct));
19
20   assert(success);
21   assert(iter - str.begin() == str.size());
22 }
```

请注意，我们将`+(space|punct)`作为第四个参数传递给`phrase_parse`，告诉它要忽略哪些字符；空格和标点。

#### 解析指令

解析指令是可以用来以某种方式改变解析器行为的修饰符。例如，我们可以使用`no_case`指令执行不区分大小写的解析，如下面的代码片段所示：

```cpp
1   std::string str = "Hello, WORLD!";
2   iter = str.begin();
3   success = qi::phrase_parse(iter, str.end(),
4                   qi::string("Hello") >> 
5                     qi::no_case[qi::string("world")],
6                   +(qi::space|qi::punct));
7   assert(success);
```

`skip`指令可用于跳过输入的某个部分上的空白：

```cpp
 1   std::string str = "Hello world";
 2   auto iter = str.begin();
 3   bool success = qi::parse(iter, str.end(),
 4                   qi::skip(qi::space)[qi::string("Hello") >> 
 5                                        qi::string("world")]);
 6   assert( success); 
```

指令`qi::skip(qi::space)[parser]`即使我们调用的是`parse`而不是`phrase_parse`也会忽略空格。它可以有选择地应用于解析器子表达式。

#### 语义动作

在使用 Spirit 时，我们通常不仅仅是要验证一段文本是否符合某种语法；我们希望提取标记，并可能在某种计算中使用它们或将它们存储起来。我们可以将某个动作与解析器实例关联起来，以便在成功解析文本时运行，这个动作可以使用解析的结果进行必要的计算。这样的动作是使用方括号括起来的函数对象定义的，跟在它关联的解析器后面。

**清单 7.30：定义与解析器关联的动作**

```cpp
 1 #include <boost/spirit/include/qi.hpp>
 2 #include <iostream>
 3 namespace qi = boost::spirit::qi;
 4
 5 void print(unsigned int n) {
 6   std::cout << n << '\n';
 7 }
 8
 9 int main() {
10   std::string str = "10 20 30 40 50 60";
11
12   auto iter = str.begin();
13   bool success = qi::phrase_parse(iter, str.end(),
14                                   +qi::uint_[print],
15                                   qi::space);
16   assert(success);
17   assert(iter == str.end());
18 }
```

在上面的示例中，我们使用`uint_`解析器（第 10 行）解析由空格分隔的无符号整数列表。我们定义一个`print`函数（第 5 行）来打印无符号整数，并将其作为一个动作与`uint_`解析器（第 14 行）关联起来。对于每个解析的无符号整数，前面的代码通过调用指定的动作在新行上打印它。动作也可以使用函数对象指定，包括由 Boost Bind 和 Boost Phoenix 生成的函数对象。

从原始到最复杂的每个解析器都有一个关联的*属性*，它设置为成功解析的结果，即当它应用于转换为适当类型的某些输入时匹配的文本。对于像`uint_`这样的简单解析器，该属性将是`unsigned int`类型。对于复杂的解析器，这可能是其组成解析器的属性的有序元组。当与解析器关联的动作被调用时，它会传递解析器属性的值。

表达式`+qi::uint_[print]`将`print`函数与`uint_`解析器关联起来。如果我们想要将动作与复合解析器`+qi::uint_`关联起来，那么我们需要使用不同签名的函数，即带有类型为`std::vector<unsigned int>`的参数的函数，它将包含所有解析的数字。

```cpp
 1 #include <vector>
 2
 3 void printv(std::vector<unsigned int> vn) 
 4 {
 5   for (const int& n: vn) {
 6     std::cout << n << '\n';
 7   }
 8 }
 9
10 int main() {
11   std::string str = "10 20 30 40 50 60";
12
13   auto iter = str.begin();
14   bool success = qi::phrase_parse(iter, str.end(),
15                                  (+qi::uint_)[printv],
16                                  qi::space);
17 }
```

我们还可以使用 Boost Bind 表达式和 Phoenix 操作来生成动作。因此，我们可以编写`+qi::uint_[boost::bind(print, ::_1)]`来在每个解析的数字上调用`print`。占位符`::_1`到`::_9`由 Boost Bind 库在全局命名空间中定义。Spirit 提供了可以用于各种操作的 Phoenix 操作。以下代码片段展示了将解析的数字添加到向量中的方法：

```cpp
 1 #include <boost/spirit/include/qi.hpp>
 2 #include <boost/spirit/include/phoenix_core.hpp>
 3 #include <boost/spirit/include/phoenix_operator.hpp>
 4 #include <boost/spirit/include/phoenix_stl.hpp> 
 5 
 6 int main() {
 7   using boost::phoenix::push_back;
 8 
 9   std::string str = "10 20 30 40 50 60";
10   std::vector<unsigned int> vec;
11   auto iter = str.begin();
12   bool status = qi::phrase_parse(iter, str.end(),
13                 +qi::uint_[push_back(boost::phoenix::ref(vec), 
14                                         qi::_1)],
15                  qi::space);
16 }
```

使用`boost::phoenix::push_back`操作表达式`push_back(boost::phoenix::ref(vec), qi::_1)`将每个解析的数字（由占位符`qi::_1`表示）附加到向量`vec`。

有`parse`和`phrase_parse`函数模板的重载，它们接受一个属性参数，您可以直接将解析器解析的数据存储在其中。因此，我们可以将`unsigned int`的`vector`作为属性参数传递，同时解析无符号整数的列表：

```cpp
std::vector<unsigned int> result;
bool success = qi::phrase_parse(iter, str.end(),
 +qi::uint_, result,
                                qi::space);
for (int n: result) {std::cout << n << '\n';
}
```

#### 规则

到目前为止，我们使用内联表达式生成了解析器。当处理更复杂的解析器时，缓存组件并重用它们是很有用的。为此，我们使用`boost::spirit::qi::rule`模板。规则模板最多接受四个参数，其中第一个即输入的迭代器类型是必需的。因此，我们可以缓存解析`std::string`对象中的空格的解析器，如下所示：

```cpp
qi::rule<std::string::iterator> space_rule = qi::space; 
```

请注意，如上所定义的`space_rule`是一个遵循与`qi::space`相同语法的解析器。

往往我们对解析器解析的值感兴趣。要定义包含这样的解析器的规则，我们需要指定一个方法的签名，该方法将用于获取解析的值。例如，`boost::spirit::qi::double_`解析器的属性类型为`double`。因此，我们认为一个不带参数并返回`double`的函数是适当的签名`double()`。此签名作为规则的第二个模板参数传递：

```cpp
qi::rule<std::string::iterator, double()> double_rule = 
                                                  qi::double_;
```

如果规则用于跳过空格，我们将用于识别要跳过的字符的解析器的类型指定为`rule`的第三个模板参数。因此，要定义一个由空格分隔的`double`列表的解析器，我们可以使用以下规则和`qi::space_type`，指定空格解析器的类型：

```cpp
qi::rule<std::string::iterator, std::vector<double>(), 
                qi::space_type> doubles_p = +qi::double_;
```

当规则以一组解析器的组合形式定义时，规则解析的值是从各个组件解析器解析的值合成而来的。这称为规则的**合成属性**。规则模板的签名参数应与合成属性的类型兼容。例如，解析器`+qi::double_`返回一系列双精度浮点数，因此合成属性的类型是`std::vector<std::double>`：

```cpp
qi::rule<std::string::iterator, std::vector<double>(), 
                                 qi::space_type> doubles_p;
doubles_p %= +qi::double_;
```

请注意，我们将解析器分配给规则的操作在单独的一行上，使用`operator %=`。如果我们不使用`%=`操作符，而是使用普通的赋值操作符，那么使用`+qi::double_`成功解析的结果将不会传播到`doubles_p`的合成属性。由于`%=`操作符，我们可以将语义动作与`doubles_p`关联起来，以访问其合成值作为`std::vector<double>`，如下例所示：

```cpp
std::string nums = "0.207879576 0.577215 2.7182818 3.14159259";
std::vector<double> result;
qi::phrase_parse(iter1, iter2,
 doubles_p[boost::phoenix::ref(result) == qi::_1],
                qi::space);
```

#### 解析时间戳

考虑形式为 YYYY-mm-DD HH:MM:SS.ff 的时间戳，其中日期部分是必需的，时间部分是可选的。此外，时间的秒和小数秒部分也是可选的。我们需要定义一个合适的解析器表达式。

我们首先需要一种方法来定义固定长度无符号整数的解析器。`boost::spirit::qi::int_parser`模板非常适用于此目的。使用`int_parser`的模板参数，我们指定要使用的基本整数类型、数字系统的基数或基数，以及允许的最小和最大数字位数。因此，对于 4 位数的年份，我们可以使用解析器类型`int_parser<unsigned short, 10, 4, 4>`，最小宽度和最大宽度都为 4，因为我们需要固定长度的整数。以下是使用`int_parser`构造的规则：

```cpp
#include <boost/spirit/include/qi.hpp>

namespace qi = boost::spirit::qi;

qi::int_parser<unsigned short, 10, 4, 4> year_p;
qi::int_parser<unsigned short, 10, 2, 2> month_p, day_p, hour_p, 
                                          min_p, sec_p;
qi::rule<std::string::iterator> date_p = 
   year_p >> qi::char_('-') >> month_p >> qi::char_('-') >> day_p;

qi::rule<std::string::iterator> seconds_p = 
            sec_p >> -(qi::char_('.') >> qi::ushort_);

qi::rule<std::string::iterator> time_p = 
   hour_p >> qi::char_(':') >> min_p 
             >> -(qi::char_(':') >> seconds_p);

qi::rule<std::string::iterator> timestamp_p = date_p >> -
                                        (qi::space >> time_p);
```

当然，我们需要定义操作来捕获时间戳的组件。为了简单起见，我们将操作与组件解析器相关联。我们将定义一个类型来表示时间戳，并将操作与解析器相关联，以设置此类型的实例的属性。

**清单 7.31：简单的日期和时间解析器**

```cpp
1 #include <boost/spirit/include/qi.hpp>
 2 #include <boost/bind.hpp>
 3 #include <cassert>
 4 namespace qi = boost::spirit::qi;
 5
 6 struct timestamp_t
 7 {
 8   void setYear(short val) { year = val; }
 9   unsigned short getYear() { return year; }
10   // Other getters / setters
11
12 private:
13   unsigned short year, month, day,
14            hours, minutes, seconds, fractions;
15 };
16
17 timestamp_t parseTimeStamp(std::string input)
18 {
19   timestamp_t ts;
20
21   qi::int_parser<unsigned short, 10, 4, 4> year_p;
22   qi::int_parser<unsigned short, 10, 2, 2> month_p, day_p, 
23                                       hour_p, min_p, sec_p;
24   qi::rule<std::string::iterator> date_p =
25    year_p [boost::bind(&timestamp_t::setYear, &ts, ::_1)]
26    >> qi::char_('-')
27    >> month_p [boost::bind(&timestamp_t::setMonth, &ts, ::_1)]
28    >> qi::char_('-')
29    >> day_p [boost::bind(&timestamp_t::setDay, &ts, ::_1)];
30
31   qi::rule<std::string::iterator> seconds_p =
32       sec_p [boost::bind(&timestamp_t::setSeconds, &ts, ::_1)]
33         >> -(qi::char_('.')
34         >> qi::ushort_
35         [boost::bind(&timestamp_t::setFractions, &ts, ::_1)]);
36
37   qi::rule<std::string::iterator> time_p =
38    hour_p  [boost::bind(&timestamp_t::setHours, &ts, ::_1)]
39    >> qi::char_(':')
40    >> min_p [boost::bind(&timestamp_t::setMinutes, &ts, ::_1)]
41     >> -(qi::char_(':') >> seconds_p);
42
43   qi::rule<std::string::iterator> timestamp_p = date_p >> -
44                                        (qi::space >> time_p);
45   auto iterator = input.begin();
46   bool success = qi::phrase_parse(iterator, input.end(),
47                                   timestamp_p, qi::space);
48   assert(success);
49
50   return ts;
51 }
```

`timestamp_t`类型（第 6 行）表示时间戳，具有每个字段的获取器和设置器。为了简洁起见，我们省略了大多数获取器和设置器。我们定义了与时间戳的各个字段的解析器相关联的操作，使用`boost::bind`（第 25、27、29、32、35、38、40 行）设置`timestamp_t`实例的适当属性。

# 自测问题

对于多项选择题，选择所有适用的选项：

1.  以下重载/特化中的哪一个会解析到调用`foo(1.0, std::string("Hello"))`？

a. `template <typename T, typename U> foo(T, U);`

b. `foo(double, std::string&);`

c. `template <> foo<double, std::string>`

d. 存在歧义

1.  元函数必须满足的接口是什么？

a. 必须有一个静态的`value`字段

b. 它必须有一个名为`type`的嵌入类型

c. 它必须有一个静态的`type`字段

d. 它必须有一个名为`result`的嵌入类型

1.  以下语句`boost::mpl::or_<boost::is_floating_point<T>, boost::is_signed<T>>`是做什么的？

a. 检查类型 T 是有符号和浮点类型

b. 生成一个检查（a）的元函数

c. 检查类型 T 是有符号还是浮点类型

d. 生成一个检查（b）的元函数

1.  我们有一个声明为：`template <typename T, typename Enable = void> class Bar`的模板，并且以任何方式都不使用`Enable`参数。如何声明 Bar 的部分特化，只有在 T 是非 POD 类型时才实例化？

a. `template <T> class Bar<T, boost::is_non_pod<T>>`

b. `template <T> class Bar<T, boost::enable_if<is_non_pod<T>>::type>`

c. `template <T> class Bar<T, boost::mpl::not<boost::is_pod<T>>>`

d. `template <T> class Bar<T, boost::disable_if<is_pod<T>>::type>`

1.  以下关于 C++ lambda 表达式和 Boost Phoenix actors 的哪一个是正确的？

a. Lambda 表达式是无名的，Phoenix actors 不是

b. Phoenix actors 是多态的，而多态 lambda 表达式仅在 C++14 中可用

c. Phoenix actors 可以部分应用，而 lambda 表达式不能

d. Lambda 表达式可以用作闭包，而 Phoenix actors 不能

# 总结

本章是我们探索 Boost 库的插曲。有两个关键的主题：更具表现力的代码和更快的代码。我们看到高阶编程如何帮助我们使用函数对象和运算符重载实现更具表现力的语法。我们看到模板元编程技术如何使我们能够编写在编译时执行的代码，并为手头的任务选择最优实现。

我们在一个章节中涵盖了大量的材料，并介绍了一种编程范式，这可能对你们中的一些人来说是新的。我们用不同的功能模式解决了一些问题，并看到了 C++函数对象、模板和运算符重载的强大力量。如果你正在阅读大多数 Boost 库的实现，或者试图编写一个高效、表达力强、可扩展的通用库，那么理解本章的主题将立即有所帮助。

在本章中我们没有涵盖的内容还有很多，也没有在本书中涵盖，包括许多但不限于 Boost Spirit 的基本细节，一个 DSEL 构建工具包，Boost Proto；基于表达式模板的快速正则表达式库，Boost Xpressive；以及更先进的元组库，Boost Fusion。希望本章能够给你足够的起点来进一步探索它们。从下一章开始，我们将转向重点介绍 Boost 中用于日期和时间计算的库，重点关注 Boost 中的系统编程库。

# 参考资料

+   《C++常识》，《Stephen C. Dewhurst》，《Addison Wesley Professional》

+   《现代 C++设计》，《Andrei Alexandrescu》，《Addison Wesley Professional》

+   《C++模板元编程》，《David Abrahams 和 Aleksey Gurtovoy》，《Addison Wesley Professional》

+   Proto: [`web.archive.org/web/20120906070131/http://cpp-next.com/archive/2011/01/expressive-c-expression-optimization/`](http://web.archive.org/20120906070131/http://cpp-next.com/archive/2011/01/expressive-c-expression-optimization/)

+   Boost Xpressive FTW: [`ericniebler.com/2010/09/27/boost-xpressive-ftw/`](http://ericniebler.com/2010/09/27/boost-xpressive-ftw/)

+   Fusion: [www.boost.org/libs/fusion](http://www.boost.org/libs/fusion)


# 第八章：日期和时间库

这是一个简短的章节，向您展示如何使用不同的 Boost 库执行基本的日期和时间计算。大多数实际软件都以某种形式使用日期和时间测量。应用程序计算当前日期和时间，以生成应用程序活动的时间日志。专门的程序根据复杂的调度策略计算作业的时间表，并等待特定的时间点或时间间隔过去。有时，应用程序甚至会监视自己的性能和执行速度，并在需要时采取补救措施或发出通知。

在本章中，我们将介绍使用 Boost 库进行日期和时间计算以及测量代码性能。这些主题分为以下几个部分：

+   使用 Boost `Date Time`进行日期和时间计算

+   使用 Boost Chrono 测量时间

+   使用 Boost Timer 测量程序性能

# 使用 Boost Date Time 进行日期和时间计算

日期和时间计算在许多软件应用程序中都很重要，但是 C++03 对于操作日期和执行计算的支持有限。Boost `Date Time`库提供了一组直观的接口，用于表示日期、时间戳、持续时间和时间间隔。通过允许涉及日期、时间戳、持续时间的简单算术运算，并补充一组有用的日期/时间算法，它可以使用很少的代码进行相当复杂的时间和日历计算。

## 公历中的日期

公历，也称为基督教历，由教皇格里高利十三世于 1582 年 2 月引入，并在接下来的几个世纪内取代了儒略历在绝大多数西方世界的使用。`Date_Time`库提供了一组用于表示日期和相关数量的类型：

+   `boost::gregorian::date`：我们使用这种类型来表示公历中的日期。

+   `boost::gregorian::date_duration`：除了日期，我们还需要表示日期间的持续时间——以天为单位的两个给定日期之间的时间长度。为此，我们使用`boost::gregorian::date_duration`类型。它指的是与`boost::gregorian::days`相同的类型。

+   `boost::date_period`：使用`boost::date_period`类型表示日历中从给定日期开始并延续一段特定持续时间的固定日期周期。

### 创建日期对象

我们可以使用日期的组成部分，即年份、月份和日期，创建`boost::gregorian::date`类型的对象。此外，还有许多工厂函数可以解析不同格式的日期字符串，以创建`date`对象。在下面的示例中，我们演示了创建`date`对象的不同方法：

**清单 8.1：使用 boost::gregorian::date**

```cpp
 1 #include <boost/date_time.hpp>
 2 #include <iostream>
 3 #include <cassert>
 4 namespace greg = boost::gregorian;
 5
 6 int main() {
 7   greg::date d0;  // default constructed, is not a date
 8   assert(d0.is_not_a_date());
 9   // Construct dates from parts
10   greg::date d1(1948, greg::Jan, 30);
11   greg::date d2(1968, greg::Apr, 4);
12
13   // Construct dates from string representations
14   greg::date dw1 = greg::from_uk_string("15/10/1948");
15   greg::date dw2 = greg::from_simple_string("1956-10-29");
16   greg::date dw3 = greg::from_undelimited_string("19670605");
17   greg::date dw4 = greg::from_us_string("10-06-1973");
18
19   // Current date
20   greg::date today = greg::day_clock::local_day();
21   greg::date londonToday = greg::day_clock::universal_day();
22
23   // Take dates apart
24   std::cout << today.day_of_week() << " " << today.day() << ", "
25             << today.month() << ", " << today.year() << '\n';
26 }
```

默认构造的日期表示无效日期（第 7 行）；`is_not_a_date`成员谓词对于这样的日期返回 true（第 8 行）。我们可以从其组成部分构造日期：年、月和日。月份可以使用名为`Jan`、`Feb`、`Mar`、`Apr`、`May`、`Jun`、`Jul`、`Aug`、`Sep`、`Oct`、`Nov`和`Dec`的`enum`值来表示，这些是年份的英文缩写。使用特殊的工厂函数，可以从其他标准表示中构造日期。我们使用`boost::gregorian::from_uk_string`函数从 DD/MM/YYYY 格式的字符串中构造一个`date`对象，这是英国的标准格式（第 14 行）。`boost::gregorian::from_us_string`函数用于从美国使用的 MM/DD/YYYY 格式的字符串中构造一个`date`（第 17 行）。`boost::gregorian::from_simple_string`函数用于从 ISO 8601 YYYY-MM-DD 格式的字符串中构造一个`date`（第 15 行），并且其无分隔形式 YYYYMMDD 可以使用`boost::gregorian::from_undelimited_string`函数转换为`date`对象（第 16 行）。

**时钟**提供了一种在系统上检索当前日期和时间的方法。Boost 为此提供了几个时钟。`day_clock`类型提供了`local_day`（第 20 行）和`universal_day`（第 21 行）函数，它们返回本地和 UTC 时区的当前日期，这两者可能相同，也可能相差一天，这取决于时区和时间。

使用方便的访问器成员函数，如`day`，`month`，`year`和`day_of_week`，我们可以获取`date`的部分（第 24-25 行）。

### 注意

`Date_Time`库不是一个仅包含头文件的库，为了在本节中运行示例，它们必须链接到`libboost_date_time`库。在 Unix 上，使用 g++，您可以使用以下命令行来编译和链接涉及 Boost Date Time 的示例：

```cpp
$ g++ example.cpp -o example -lboost_date_time
```

有关更多详细信息，请参见第一章*介绍 Boost*。

### 处理日期持续时间

两个日期之间的时间持续时间由`boost::gregorian::date_duration`表示。在下面的示例中，我们计算日期之间的时间持续时间，并将持续时间添加到日期或从日期中减去以得到新的日期。

**清单 8.2：基本日期算术**

```cpp
 1 #include <boost/date_time.hpp>
 2 #include <iostream>
 3 namespace greg = boost::gregorian;
 4
 5 int main() {
 6   greg::date d1(1948, greg::Jan, 30);
 7   greg::date d2(1968, greg::Apr, 4);
 8
 9   greg::date_duration day_diff = d2 - d1;
10   std::cout << day_diff.days() 
11             << " days between the two dates\n";
12
13   greg::date six_weeks_post_d1 = d1 + greg::weeks(6);
14   std::cout << six_weeks_post_d1 << '\n';
15
16   greg::date day_before_d2 = d2 - greg::days(1);
17   std::cout << day_before_d2 << '\n';
18 }
```

我们计算持续时间（可以是负数）作为两个日期的差异（第 9 行），并以天为单位打印出来（第 10 行）。`date_duration`对象在内部以天为单位表示持续时间。我们还可以使用类型`boost::gregorian::weeks`，`boost::gregorian::months`和`boost::gregorian::years`来构造以周、月或年为单位的`date_duration`对象。请注意，`boost::gregorian::days`和`boost::gregorian::date_duration`指的是相同的类型。我们通过将持续时间添加到日期或从日期中减去它们（第 13、16 行）来获得新的日期。

### 日期周期

以固定日期开始的周期由类型`boost::gregorian::date_period`表示。在下面的示例中，我们构造了两个日期周期，一个是日历年，一个是美国财政年。我们计算它们的重叠期，然后确定重叠期内每个月的最后一个星期五的日期。

**清单 8.3：日期周期和日历计算**

```cpp
 1 #include <boost/date_time.hpp>
 2 #include <iostream>
 3 namespace greg = boost::gregorian;
 4 namespace dt = boost::date_time;
 5
 6 int main() {
 7   greg::date startCal(2015, greg::Jan, 1);
 8   greg::date endCal(2015, greg::Dec, 31);
 9
10   greg::date startFiscal(2014, greg::Oct, 1);
11   greg::date endFiscal(2015, greg::Sep, 30);
12
13   greg::date_period cal(startCal, endCal);
14   greg::date_period fisc(startFiscal, endFiscal);
15
16   std::cout << "Fiscal year begins " << fisc.begin()
17     << " and ends " << fisc.end() << '\n';
18
19   if (cal.intersects(fisc)) {
20     auto overlap = cal.intersection(fisc);
21     greg::month_iterator miter(overlap.begin());
22
23     while (*miter < overlap.end()) {
24       greg::last_day_of_the_week_in_month 
25                    last_weekday(greg::Friday, miter->month());
26       std::cout << last_weekday.get_date(miter->year())
27                 << '\n';
28       ++miter;
29     }
30   }
31 }
```

我们根据开始日期和结束日期定义日期周期（第 13、14 行）。我们可以使用`date_period`的`intersects`成员函数（第 19 行）检查两个周期是否重叠，并使用`intersection`成员函数（第 20 行）获取重叠期。我们通过在开始日期处创建一个`month_iterator`（第 21 行），并使用预增量运算符（第 28 行）迭代到结束日期（第 23 行）来遍历一个周期。有不同类型的迭代器，具有不同的迭代周期。我们使用`boost::gregorian::month_iterator`来迭代周期内连续的月份。`month_iterator`每次递增时都会将日期提前一个月。您还可以使用其他迭代器，如`year_iterator`，`week_iterator`和`day_iterator`，它们分别以年、周或天为单位递增迭代器。

对于周期中的每个月，我们想要找到该月的最后一个星期五的日期。`Date Time`库具有一些有趣的算法类，用于此类日历计算。我们使用`boost::gregorian::last_day_of_the_week_in_month`算法来执行这样的计算，以确定月份的最后一个星期五的日期。我们构造了一个`last_day_of_the_week_in_month`对象，构造函数参数是星期几（星期五）和月份（第 24、25 行）。然后我们调用它的`get_date`成员函数，将特定年份传递给它（第 26 行）。

## Posix 时间

`Date_Time`库还提供了一组类型，用于表示时间点、持续时间和周期。

+   `boost::posix_time::ptime`：特定的时间点，或者**时间点**，由类型`boost::posix_time::ptime`表示。

+   `boost::posix_time::time_duration`：与日期持续时间一样，两个时间点之间的时间长度称为**时间持续时间**，并由类型`boost::posix_time::time_duration`表示。

+   `boost::posix_time::time_period`：从特定时间点开始的固定间隔，到另一个时间点结束，称为**时间段**，由类型`boost::posix_time::time_period`表示。

这些类型及其上的操作一起定义了一个**时间系统**。Posix Time 使用`boost::gregorian::date`来表示时间点的日期部分。

### 构造时间点和持续时间

我们可以从其组成部分，即日期、小时、分钟、秒等创建`boost::posix_time::ptime`的实例，或者使用解析时间戳字符串的工厂函数。在以下示例中，我们展示了创建`ptime`对象的不同方式：

清单 8.4：使用 boost::posix_time

```cpp
 1 #include <boost/date_time.hpp>
 2 #include <iostream>
 3 #include <cassert>
 4 #include <ctime>
 5 namespace greg = boost::gregorian;
 6 namespace pt = boost::posix_time;
 7
 8 int main() {
 9   pt::ptime pt; // default constructed, is not a time
10   assert(pt.is_not_a_date_time());
11
12   // Get current time
13   pt::ptime now1 = pt::second_clock::universal_time();
14   pt::ptime now2 = pt::from_time_t(std::time(0));
15
16   // Construct from strings
17   // Create time points using durations
18   pt::ptime pt1(greg::day_clock::universal_day(),
19           pt::hours(10) + pt::minutes(42)
20           + pt::seconds(20) + pt::microseconds(30));
21   std::cout << pt1 << '\n';
22
23   // Compute durations
24   pt::time_duration dur = now1 - pt1;
25   std::cout << dur << '\n';
26   std::cout << dur.total_microseconds() << '\n';
27
28   pt::ptime pt2(greg::day_clock::universal_day()),
29        pt3 = pt::time_from_string("2015-01-28 10:00:31.83"),
30        pt4 = pt::from_iso_string("20150128T151200");
31
32   std::cout << pt2 << '\n' << to_iso_string(pt3) << '\n'
33             << to_simple_string(pt4) << '\n';
34 }
```

就像日期对象一样，默认构造的`ptime`对象（第 9 行）不是一个有效的时间点（第 10 行）。有时钟可以用来推导一天中的当前时间，例如，`second_clock`和`microsec_clock`，它们分别以秒或微秒单位给出时间。在这些时钟上调用`local_time`和`universal_time`函数（第 13 行）将返回本地和 UTC 时区中的当前日期和时间。

`from_time_t`工厂函数传递 Unix 时间，即自 Unix 纪元（1970 年 1 月 1 日 00:00:00 UTC）以来经过的秒数，并构造一个表示该时间点的`ptime`对象（第 14 行）。当传递 0 时，C 库函数`time`返回 UTC 时区中的当前 Unix 时间。

两个时间点之间的持续时间，可以是负数，是通过计算两个时间点之间的差值来计算的（第 24 行）。它可以被流式传输到输出流中，以默认方式打印持续时间，以小时、分钟、秒和小数秒为单位。使用访问器函数`hours`、`minutes`、`seconds`和`fractional_seconds`，我们可以获取持续时间的相关部分。或者我们可以使用访问器`total_seconds`、`total_milliseconds`、`total_microseconds`和`total_nanoseconds`将整个持续时间转换为秒或亚秒单位（第 26 行）。

我们可以从一个公历日期和一个类型为`boost::posix_time::time_duration`的持续时间对象创建一个`ptime`对象（第 18-20 行）。我们可以在`boost::posix_time`命名空间中使用 shim 类型`hours`、`minutes`、`seconds`、`microseconds`等来生成适当单位的`boost::posix_time::time_duration`类型的持续时间，并使用`operator+`将它们组合起来。

我们可以仅从一个`boost::gregorian::date`对象构造一个`ptime`对象（第 28 行）。这代表了给定日期的午夜时间。我们可以使用工厂函数从不同的字符串表示中创建`ptime`对象（第 29-30 行）。函数`time_from_string`用于从“YYYY-MM-DD hh:mm:ss.xxx…”格式的时间戳字符串构造一个`ptime`实例，在该格式中，日期和时间部分由空格分隔（第 29 行）。函数`from_iso_string`用于从“YYYYMMDDThhmmss.xxx…”格式的无分隔字符串构造一个`ptime`实例，其中大写 T 分隔日期和时间部分（第 30 行）。在这两种情况下，分钟、秒和小数秒是可选的，如果未指定，则被视为零。小数秒可以跟在秒后，用小数点分隔。这些格式是与地区相关的。例如，在几个欧洲地区，使用逗号代替小数点。

我们可以将`ptime`对象流式输出到输出流，比如`std::cout`（第 32 行）。我们还可以使用转换函数，比如`to_simple_string`和`to_iso_string`（第 32-33 行），将`ptime`实例转换为`string`。在英文环境中，`to_simple_string`函数将其转换为"YYYY-MM-DD hh:mm:ss.xxx…"格式。请注意，这是`time_from_string`预期的相同格式，也是在流式输出`ptime`时使用的格式。`to_iso_string`函数将其转换为"YYYYMMDDThhmmss.xxx…"格式，与`from_iso_string`预期的格式相同。

### 分辨率

时间系统可以表示的最小持续时间称为其分辨率。时间在特定系统上表示的精度，因此，有效的小数秒数取决于时间系统的分辨率。Posix 时间使用的默认分辨率是微秒（10^(-6)秒），也就是说，它不能表示比微秒更短的持续时间，因此不能区分相隔不到一微秒的两个时间点。以下示例演示了如何获取和解释时间系统的分辨率：

**清单 8.5：时间刻度和分辨率**

```cpp
 1 #include <boost/date_time.hpp>
 2 #include <iostream>
 3 namespace pt = boost::posix_time;
 4 namespace dt = boost::date_time;
 5 
 6 int main() {
 7   switch (pt::time_duration::resolution()) {
 8   case dt::time_resolutions::sec:
 9     std::cout << " second\n";
10     break;
11   case dt::time_resolutions::tenth:
12     std::cout << " tenth\n";
13     break;
14   case dt::time_resolutions::hundredth:
15     std::cout << " hundredth\n";
16     break;
17   case dt::time_resolutions::milli:
18     std::cout << " milli\n";
19     break;
20   case dt::time_resolutions::ten_thousandth:
21     std::cout << " ten_thousandth\n";
22     break;
23   case dt::time_resolutions::micro:
24     std::cout << " micro\n";
25     break;
26   case dt::time_resolutions::nano:
27     std::cout << " nano\n";
28     break;
29   default:
30     std::cout << " unknown\n";
31     break;
32   }
33   std::cout << pt::time_duration::num_fractional_digits()
34             << '\n';
35   std::cout << pt::time_duration::ticks_per_second() 
36             << '\n';
37 }
```

`time_duration`类的`resolution`静态函数返回一个枚举常量作为分辨率（第 7 行）；我们解释这个`enum`并打印一个字符串来指示分辨率（第 7-32 行）。

`num_fractional_digits`静态函数返回小数秒的有效数字位数（第 33 行）；在具有微秒分辨率的系统上，这将是 6，在具有纳秒分辨率的系统上，这将是 9。`ticks_per_second`静态函数将 1 秒转换为系统上最小可表示的时间单位（第 35 行）；在具有微秒分辨率的系统上，这将是 10⁶，在具有纳秒分辨率的系统上，这将是 10⁹。

### 时间段

与日期一样，我们可以使用`boost::posix_time::time_period`表示固定的时间段。以下是一个简短的示例，演示了如何创建时间段并比较不同的时间段：

**清单 8.6：使用时间段**

```cpp
 1 #include <boost/date_time.hpp>
 2 #include <iostream>
 3 #include <cassert>
 4 namespace greg = boost::gregorian;
 5 namespace pt = boost::posix_time;
 6
 7 int main()
 8 {
 9   // Get current time
10   pt::ptime now1 = pt::second_clock::local_time();
11   pt::time_period starts_now(now1, pt::hours(2));
12
13   assert(starts_now.length() == pt::hours(2));
14
15   auto later1 = now1 + pt::hours(1);
16   pt::time_period starts_in_1(later1, pt::hours(3));
17
18   assert(starts_in_1.length() == pt::hours(3));
19
20   auto later2 = now1 + pt::hours(3);
21   pt::time_period starts_in_3(later2, pt::hours(1));
22
23   assert(starts_in_3.length() == pt::hours(1));
24
26   std::cout << "starts_in_1 starts at " << starts_in_1.begin()
27             << " and ends at " << starts_in_1.last() << '\n';
28
29   // comparing time periods
30   // non-overlapping
31   assert(starts_now < starts_in_3);
32   assert(!starts_now.intersects(starts_in_3));
33
34   // overlapping
35   assert(starts_now.intersects(starts_in_1));
36
37   assert(starts_in_1.contains(starts_in_3));
38 }
```

我们创建了一个名为`starts_now`的时间段，它从当前时刻开始，持续 2 小时。为此，我们使用了`time_period`的两个参数构造函数，传递了当前时间戳和 2 小时的持续时间（第 11 行）。使用`time_period`的`length`成员函数，我们验证了该时间段的长度确实为 2 小时（第 13 行）。

我们创建了另外两个时间段：`starts_in_1`从 1 小时后开始，持续 3 小时（第 16 行），`starts_in_3`从 3 小时后开始，持续 1 小时（第 20 行）。`time_period`的`begin`和`last`成员函数返回时间段中的第一个和最后一个时间点（第 26-27 行）。

我们使用关系运算符和称为`intersects`和`contains`的两个成员函数来表示三个时间段`starts_now`，`starts_in_1`和`starts_in_3`之间的关系。显然，`starts_in_1`的第一个小时与`starts_now`的最后一个小时重叠，因此我们断言`starts_now`和`starts_in_1`相交（第 35 行）。`starts_in_1`的最后一个小时与整个时间段`starts_in_3`重合，因此我们断言`starts_in_1`包含`starts_in_3`（第 37 行）。但是`starts_now`和`starts_in_3`不重叠；因此，我们断言`starts_now`和`starts_in_3`不相交（第 32 行）。

关系运算符`operator<`被定义为对于两个时间段`tp1`和`tp2`，条件`tp1 < tp2`成立当且仅当`tp1.last() < tp2.begin()`。同样，`operator>`被定义为条件`tp1 > tp2`成立当且仅当`tp1.begin() > tp2.last()`。这些定义意味着`tp1`和`tp2`是不相交的。因此，对于不相交的`time_period` `starts_now`和`starts_in_3`，关系`starts_now < starts_in_3`成立（第 31 行）。这些关系对于重叠的时间段是没有意义的。

### 时间迭代器

我们可以使用`boost::posix_time::time_iterator`来遍历一个时间段，类似于我们使用`boost::gregorian::date_iterator`的方式。下面的例子展示了这一点：

**清单 8.7：遍历一个时间段**

```cpp
 1 #include <boost/date_time.hpp>
 2 #include <iostream>
 3
 4 namespace greg = boost::gregorian;
 5 namespace pt = boost::posix_time;
 6
 7 int main()
 8 {
 9   pt::ptime now = pt::second_clock::local_time();
10   pt::ptime start_of_day(greg::day_clock::local_day());
11
12   for (pt::time_iterator iter(start_of_day, 
13          pt::hours(1)); iter < now; ++iter)
14   {
15     std::cout << *iter << '\n';
16   }
17 }
```

前面的例子打印了当天每个完成的小时的时间戳。我们实例化了一个`time_iterator`（第 12 行），将开始迭代的时间点(`start_of_day`)和迭代器每次增加的持续时间（1 小时）传递给它。我们迭代直到当前时间，通过解引用迭代器获得时间戳（第 15 行）并增加迭代器（第 13 行）。请注意，在表达式`iter < now`中，我们将迭代器与时间点进行比较，以决定何时停止迭代——这是`posix_time::time_iterator`的一个特殊属性，与其他迭代器不同。

# 使用 Chrono 来测量时间

Boost Chrono 是一个用于时间计算的库，与`Date Time`库的 Posix Time 部分有一些重叠的功能。与 Posix Time 一样，Chrono 也使用时间点和持续时间的概念。Chrono 不处理日期。它比`Date Time`库更新，实现了 C++标准委员会工作组(WG21)的一份提案中提出的设施。该提案的部分内容成为了 C++11 标准库的一部分，即`Chrono`库，Boost Chrono 上的许多讨论也适用于 Chrono 标准库(`std::chrono`)。

## 持续时间

持续时间表示一段时间间隔。持续时间具有数值大小，并且必须用时间单位表示。`boost::chrono::duration`模板用于表示任何这样的持续时间，并声明如下：

```cpp
template <typename Representation, typename Period>
class duration;
```

`Representation`类型参数标识用于持续时间大小的基础算术类型。`Period`类型参数标识滴答周期，即用于测量持续时间的一个时间单位的大小。该周期通常表示为 1 秒的比例或分数，使用一个名为`boost::ratio`的模板。

因此，如果我们想要以百分之一秒（centiseconds）表示持续时间，我们可以使用`int64_t`作为基础类型，并且可以使用比例(1/100)来表示滴答周期，因为滴答周期是一百分之一秒。使用`boost::ratio`，我们可以特化`duration`来表示百分之一秒的间隔，如下所示：

```cpp
typedef boost::chrono::duration<int64_t, boost::ratio<1, 100>> 
                                                    centiseconds;
centiseconds cs(1000);  // represents 10 seconds
```

我们创建了一个名为`centiseconds`的`typedef`，并将`1000`作为构造函数参数传递进去，这是持续时间中的百分之一秒的数量。`1000`百分之一秒相当于(1/100)*1000 秒，也就是 10 秒。

`boost::ratio`模板用于构造表示有理数的类型，即两个整数的比例。我们通过将我们的有理数的分子和分母作为两个非类型模板参数来特化`ratio`，按照这个顺序。第二个参数默认为 1；因此，要表示一个整数，比如 100，我们可以简单地写成`boost::ratio<100>`，而不是`boost::ratio<100, 1>`。表达式`boost::ratio<100>`并不代表值 100，而是封装了有理数 100 的类型。

`Chrono`库已经提供了一组预定义的`duration`的特化，用于构造以常用时间单位表示的持续时间。这些包括：

+   `boost::chrono::hours`（滴答周期=`boost::ratio<3600>`）

+   `boost::chrono::minutes`（滴答周期=`boost::ratio<60>`）

+   `boost::chrono::seconds`（滴答周期 = `boost::ratio<1>`）

+   `boost::chrono::milliseconds`（滴答周期 = `boost::ratio<1, 1000>`）

+   `boost::chrono::microseconds`（滴答周期 = `boost::ratio<1, 1000000>`）

+   `boost::chrono::nanoseconds`（滴答周期 = `boost::ratio<1, 1000000000>`）

### 持续时间算术

持续时间可以相加和相减，并且不同单位的持续时间可以组合成其他持续时间。较大单位的持续时间可以隐式转换为较小单位的持续时间。如果使用浮点表示，从较小单位到较大单位的隐式转换是可能的；对于整数表示，这样的转换会导致精度损失。为了处理这个问题，我们必须使用类似于强制转换运算符的函数，进行从较小单位到较大单位的显式转换：

**清单 8.8：使用 chrono 持续时间**

```cpp
 1 #include <boost/chrono/chrono.hpp>
 2 #include <boost/chrono/chrono_io.hpp>
 3 #include <iostream>
 4 #include <cstdint>
 5 namespace chrono = boost::chrono;
 6
 7 int main()
 8 {
 9   chrono::duration<int64_t, boost::ratio<1, 100>> csec(10);
10   std::cout << csec.count() << '\n';
11   std::cout << csec << '\n';
12
13   chrono::seconds sec(10);
14   chrono::milliseconds sum = sec + chrono::milliseconds(20);
15   // chrono::seconds sum1 = sec + chrono::milliseconds(20);
16
17   chrono::milliseconds msec = sec;
18
19   // chrono::seconds sec2 = sum;
20   chrono::seconds sec2 = 
21                  chrono::duration_cast<chrono::seconds>(sum);
22 }
```

这个例子说明了您可以执行的不同操作与持续时间。`boost/chrono/chrono.hpp`头文件包括了我们需要的大部分 Boost Chrono 设施（第 1 行）。我们首先创建一个 10 厘秒的`duration`（第 9 行）。`count`成员函数返回持续时间的滴答计数，即持续时间中所选单位的时间单位数，厘秒（第 10 行）。我们可以直接将持续时间流式传输到输出流（第 11 行），但需要包含额外的头文件`boost/chrono/chrono_io.hpp`来访问这些操作符（第 2 行）。流式传输`csec`打印如下：

```cpp
10 centiseconds
```

Boost Ratio 根据持续时间使用的时间单位提供适当的 SI 单位前缀，并用于智能打印适当的 SI 前缀。这在 C++11 标准库 Chrono 实现中不可用。

我们使用适当的持续时间特化创建秒和毫秒持续时间，并使用重载的`operator+`计算它们的和（第 13、14 行）。秒和毫秒持续时间的和是毫秒持续时间。毫秒持续时间隐式转换为秒单位的持续时间会导致精度损失，因为较大类型的表示是整数类型。因此，不支持这种隐式转换（第 15 行）。例如，10 秒+20 毫秒将计算为 10020 毫秒。`boost:::chrono::seconds` `typedef`使用带符号整数类型表示，要将 10020 毫秒表示为秒，20 毫秒需要被隐式四舍五入。

我们使用`duration_cast`函数模板，类似于 C++转换运算符，执行这种转换（第 20-21 行），使意图明确。`duration_cast`将进行四舍五入。另一方面，秒单位的持续时间总是可以隐式转换为毫秒单位的持续时间，因为没有精度损失（第 17 行）。

### 注意

`Chrono`库是一个单独构建的库，也依赖于 Boost System 库。因此，我们必须将本节中的示例链接到`libboost_system`。在 Unix 上使用 g++，您可以使用以下命令行来编译和链接涉及 Boost Chrono 的示例：

```cpp
$ g++ example.cpp -o example -lboost_system -lboost_chrono
```

对于非标准位置安装的 Boost 库，请参阅第一章*介绍 Boost*。

如果我们将持续时间专门化为使用`double`表示秒，而不是带符号整数，那么情况将会有所不同。以下代码将编译，因为`double`表示将能够容纳小数部分：

```cpp
boost::chrono::milliseconds millies(20);
boost::chrono::duration<double> sec(10);

boost::chrono::duration<double> sec2 = sec + millies;
std::cout << sec2 << '\n';
```

### 注意

我们在本书中没有详细介绍 Boost Ratio，但本章介绍了处理 Boost Chrono 所需的足够细节。此外，您可以访问比率的部分，并将比率打印为有理数或 SI 前缀，如果有意义的话。以下代码说明了这一点：

```cpp
#include <boost/ratio.hpp>
typedef boost::ratio<1000> kilo;
typedef boost::ratio<1, 1000> milli;
typedef boost::ratio<22, 7> not_quite_pi;
std::cout << not_quite_pi::num << "/" 
          << not_quite_pi::den << '\n';
std::cout << boost::ratio_string<kilo, char>::prefix() 
          << '\n';
std::cout << boost::ratio_string<milli, char>::prefix() 
          << '\n';
```

注意我们如何使用`ratio_string`模板及其前缀成员函数来打印 SI 前缀。代码打印如下：

```cpp
22/7
kilo
milli
```

C++11 标准库中的`std::ratio`模板对应于 Boost Ratio，并被`std::chrono`使用。标准库中没有`ratio_string`，因此缺少 SI 前缀打印。

## 时钟和时间点

时间点是时间的固定点，而不是持续时间。给定一个时间点，我们可以从中添加或减去一个持续时间，以得到另一个时间点。时代是某个时间系统中的参考时间点，可以与持续时间结合，以定义其他时间点。最著名的时代是 Unix 或 POSIX 时代，即 1970 年 1 月 1 日 00:00:00 UTC。

Boost Chrono 提供了几种时钟，用于在不同的上下文中测量时间。时钟具有以下关联成员：

+   一个名为`duration`的 typedef，表示使用该时钟可以表示的最小持续时间

+   一个名为`time_point`的 typedef，用于表示该时钟的时间点

+   一个静态成员函数`now`，返回当前时间点

Boost Chrono 定义了几种时钟，其中一些可能在您的系统上可用，也可能不可用：

+   `system_clock`类型表示壁钟或系统时间。

+   `steady_clock`类型表示一个单调时间系统，这意味着如果连续调用`now`函数，第二次调用将始终返回比第一次调用返回的时间点晚的时间点。这对于`system_clock`不能保证。只有在定义了`BOOST_CHRONO_HAS_STEADY_CLOCK`预处理宏时，才可用`steady_clock`类型。

+   如果可用，`high_resolution_clock`类型被定义为`steady_clock`，否则被定义为`system_clock`。

前面的时钟也可以作为`std::chrono`的一部分使用。它们使用一个实现定义的时代，并提供了在`time_point`和 Unix 时间(`std::time_t`)之间转换的函数。以下示例说明了时钟和时间点的使用方式：

**清单 8.9：使用 chrono system_clock**

```cpp
 1 #include <iostream>
 2 #include <boost/chrono.hpp>
 3
 4 namespace chrono = boost::chrono;
 5
 6 int main()
 7 {
 8   typedef chrono::system_clock::period tick_period;
 9   std::cout
10      << boost::ratio_string<tick_period, char>::prefix() 
11      << " seconds\n";
12   chrono::system_clock::time_point epoch;
13   chrono::system_clock::time_point now = 
14                             chrono::system_clock::now();
15
16   std::cout << epoch << '\n';
17   std::cout << chrono::time_point_cast<chrono::hours>(now) 
18             << '\n';
19 }
```

在这个例子中，我们首先打印与`system_clock`关联的持续时间的滴答周期。`system_clock::period`是`system_clock::duration::period`的一个 typedef，表示与`system_clock`关联的持续时间的滴答周期（第 8 行）。我们将其传递给`boost::ratio_string`，并使用`prefix`成员函数打印正确的 SI 前缀（第 9-10 行）。

它构造了两个时间点：一个用于`system_clock`的默认构造时间点，表示时钟的时代（第 12 行），以及由`system_clock`提供的`now`函数返回的当前时间（第 13-14 行）。然后我们打印时代（第 16 行），然后是当前时间（第 17 行）。时间点被打印为自时代以来的时间单位数。请注意，我们使用`time_point_cast`函数将当前时间转换为自时代以来的小时数。前面的代码在我的系统上打印如下：

```cpp
nanoseconds
0 nanoseconds since Jan 1, 1970
395219 hours since Jan 1, 1970
```

Boost Chrono 还提供了以下时钟，这些时钟都不作为 C++标准库 Chrono 的一部分：

+   `process_real_cpu_clock`类型用于测量程序启动以来的总时间。

+   `process_user_cpu_clock`类型用于测量程序在用户空间运行的时间。

+   `process_system_cpu`类型用于测量内核代表程序运行某些代码的时间。

+   `thread_clock`类型用于测量特定线程调度的总时间。只有在定义了`BOOST_CHRONO_HAS_THREAD_CLOCK`预处理宏时才可用此时钟。

只有在定义了`BOOST_CHRONO_HAS_PROCESS_CLOCKS`预处理宏时，才可用处理时钟。这些时钟可以类似于系统时钟使用，但它们的时代是 CPU 时钟的程序启动时，或者线程时钟的线程启动时。

# 使用 Boost Timer 测量程序性能

作为程序员，我们经常需要测量代码段的性能。虽然有几种出色的性能分析工具可用于此目的，但有时，能够对我们自己的代码进行仪器化既简单又更精确。Boost Timer 库提供了一个易于使用的、可移植的接口，用于通过仪器化代码来测量执行时间并报告它们。它是一个单独编译的库，不是仅头文件，并且在内部使用 Boost Chrono。

## cpu_timer

`boost::timer::cpu_timer`类用于测量代码段的执行时间。在下面的示例中，我们编写一个函数，该函数读取文件的内容并将其包装在`unique_ptr`中返回（参见第三章*内存管理和异常安全*）。它还使用`cpu_timer`计算并打印读取文件所用的时间。

**清单 8.10：使用 cpu_timer**

```cpp
 1 #include <fstream>
 2 #include <memory>
 3 #include <boost/timer/timer.hpp>
 4 #include <string>
 5 #include <boost/filesystem.hpp>
 6 using std::ios;
 7
 8 std::unique_ptr<char[]> readFile(const std::string& file_name,
 9                                  std::streampos& size)
10 {
11   std::unique_ptr<char[]> buffer;
12   std::ifstream file(file_name, ios::binary);
13
14   if (file) {
15     size = boost::filesystem::file_size(file_name);
16
17     if (size > 0) {
18       buffer.reset(new char[size]);
19
20       boost::timer::cpu_timer timer;
21       file.read(buffer.get(), size);
22       timer.stop();
23
24       std::cerr << "file size = " << size
25                 << ": time = " << timer.format();
26     }
27   }
28
29   return buffer;
30 }
```

我们在代码段的开始处创建一个`cpu_timer`实例（第 20 行），它启动计时器。在代码段结束时，我们在`cpu_timer`对象上调用`stop`成员函数（第 22 行），它停止计时器。我们调用`format`成员函数以获得可读的经过时间表示，并将其打印到标准错误（第 25 行）。使用文件名调用此函数，将以下内容打印到标准输入：

```cpp
file size = 1697199:  0.111945s wall, 0.000000s user + 0.060000s system = 0.060000s CPU (53.6%)
```

这表明对`fstream`的`read`成员函数的调用（第 21 行）被阻塞了 0.111945 秒。这是挂钟时间，即计时器测量的总经过时间。CPU 在用户模式下花费了 0.000000 秒，在内核模式下花费了 0.060000 秒（即在系统调用中）。请注意，读取完全在内核模式下进行，这是预期的，因为它涉及调用系统调用（例如在 Unix 上的读取）来从磁盘中读取文件的内容。CPU 在执行此代码时花费的经过时间的百分比为 53.6。它是作为在用户模式和内核模式中花费的持续时间之和除以总经过时间计算的，即（0.0 + 0.06）/ 0.111945，约为 0.536。

### 注意

使用 Boost Timer 的代码必须链接`libboost_timer`和`libboost_system`。要在 POSIX 系统上使用 g++构建涉及 Boost Timer 的示例，使用以下命令行：

```cpp
$ g++ source.cpp -o executable -std=c++11 -lboost_system -lboost_timer
```

对于安装在非标准位置的 Boost 库，请参阅第一章*介绍 Boost*。

如果我们想要测量打开文件、从文件中读取并关闭文件所花费的累积时间，那么我们可以使用单个计时器来测量多个部分的执行时间，根据需要停止和恢复计时器。

以下代码片段说明了这一点：

```cpp
12   boost::timer::cpu_timer timer;
13   file.open(file_name, ios::in|ios::binary|ios::ate);
14
15   if (file) {
16     size = file.tellg();
17
18     if (size > 0) {
19       timer.stop();
20       buffer.reset(new char[size]);
21
22       timer.resume();
23       file.seekg(0, ios::beg);
24       file.read(buffer.get(), size);
25     }
26
27     file.close();
28   }
29
30   timer.stop();
31 
```

在停止的计时器上调用`resume`成员函数会重新启动计时器，并添加到任何先前的测量中。在前面的代码片段中，我们在分配堆内存之前停止计时器（第 19 行），然后立即恢复计时器（第 22 行）。

还有一个`start`成员函数，它在`cpu_timer`构造函数内部调用以开始测量。在停止的计时器上调用`start`而不是`resume`会清除任何先前的测量，并有效地重置计时器。您还可以使用`is_stopped`成员函数检查计时器是否已停止，如果计时器已停止，则返回`true`，否则返回`false`。

我们可以通过调用`cpu_timer`的`elapsed`成员函数获取经过的时间（挂钟时间）、在用户模式下花费的 CPU 时间和在内核模式下花费的 CPU 时间（以纳秒为单位）：

```cpp
20       file.seekg(0, ios::beg);
21       boost::timer::cpu_timer timer;
22       file.read(buffer.get(), size);
23       timer.stop();
24
25       boost::timer::cpu_times times = timer.elapsed();
26       std::cout << std::fixed << std::setprecision(8)
27                 << times.wall / 1.0e9 << "s wall, "
28                 << times.user / 1.0e9 << "s user + "
29                 << times.system / 1.0e9 << "s system. "
30                 << (double)100*(timer.user + timer.system) 
31                       / timer.wall << "% CPU\n";
```

`elapsed`成员函数返回一个`cpu_times`类型的对象（第 25 行），其中包含三个字段，分别称为`wall`、`user`和`system`，它们以纳秒（10^(-9)秒）为单位包含适当的持续时间。

## 自动 CPU 计时器

`boost::timer::auto_cpu_timer`是`cpu_timer`的子类，它会在其封闭作用域结束时自动停止计数器，并将测量的执行时间写入标准输出或用户提供的另一个输出流。您无法停止和恢复它。当您需要测量代码段的执行时间直到作用域结束时，您可以使用`auto_cpu_timer`，只需使用一行代码，如下面从列表 8.10 调整的片段所示：

```cpp
17     if (size > 0) {
18       buffer.reset(new char[size]);
19
20       file.seekg(0, ios::beg);
21
22       boost::timer::auto_cpu_timer timer;
23       file.read(buffer.get(), size);
24     }
```

这将以熟悉的格式将测量的执行时间打印到标准输出：

```cpp
0.102563s wall, 0.000000s user + 0.040000s system = 0.040000s CPU (39.0%)
```

要将其打印到不同的输出流，我们需要将流作为构造函数参数传递给`timer`。

要测量读取文件所需的时间，我们只需在调用`read`之前声明`auto_cpu_timer`实例（第 22 行）。如果调用 read 不是作用域中的最后一条语句，并且我们不想测量后续内容的执行时间，那么这将不起作用。然后，我们可以使用`cpu_timer`而不是`auto_cpu_timer`，或者只将我们感兴趣的语句放在一个嵌套作用域中，并在开始时创建一个`auto_cpu_timer`实例：

```cpp
17     if (size > 0) {
18       buffer.reset(new char[size]);
19
20       file.seekg(0, ios::beg);
21
22       {
23         boost::timer::auto_cpu_timer timer(std::cerr);
24         file.read(buffer.get(), size);
25       }
26       // remaining statements in scope
27     }
```

在上面的例子中，我们创建了一个新的作用域（第 22-25 行），使用`auto_cpu_timer`来隔离要测量的代码部分。

# 自测问题

对于多项选择题，选择所有适用的选项：

1.  以下代码行哪个/哪些是不正确的？假设符号来自`boost::chrono`命名空间。

a. `milliseconds ms = milliseconds(5) + microseconds(10);`

b. `nanoseconds ns = milliseconds(5) + microseconds(10);`

c. `microseconds us = milliseconds(5) + microseconds(10);`

d. `seconds s = minutes(5) + microseconds(10);`

1.  `boost::chrono::duration<std::intmax_t, boost::ratio<1, 1000000>>`代表什么类型？

a. 以整数表示的毫秒持续时间

b. 以整数表示的微秒持续时间

c. 以浮点表示的毫秒持续时间

d. 以整数表示的纳秒持续时间

1.  `boost::timer::cpu_timer`和`boost::timer::auto_cpu_timer`之间有什么区别？

a. `auto_cpu_timer`在构造函数中调用`start`，`cpu_timer`不会

b. `auto_cpu_timer` 无法停止和恢复

c. `auto_cpu_timer`在作用域结束时写入输出流，`cpu_timer`不会

d. 你可以从`cpu_timer`中提取墙壁时间、用户时间和系统时间，但不能从`auto_cpu_timer`中提取

# 总结

本章介绍了用于测量时间和计算日期的库。本章让您快速了解了日期和时间计算的基础知识，而不涉及复杂的日历计算、时区意识和自定义和特定区域设置的格式。Boost 在线文档是这些细节的绝佳来源。

# 参考

+   《C++标准库：教程和参考指南（第二版）》，《Nicolai M. Josuttis》，《Addison Wesley Professional》

+   *睡眠的基础*：*Howard E. Hinnant*，*Walter E. Brown*，*Jeff Garland*和*Marc Paterno*（[`www.open-std.org/jtc1/sc22/wg21/docs/papers/2008/n2661.htm`](http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2008/n2661.htm)）
