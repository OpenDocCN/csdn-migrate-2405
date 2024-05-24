# C++ 专家编程：成为熟练的程序员（三）

> 原文：[`annas-archive.org/md5/f9404739e16292672f830e964de1c2e4`](https://annas-archive.org/md5/f9404739e16292672f830e964de1c2e4)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第二部分：设计健壮高效的应用程序

本节将集中讨论使用数据结构、算法和并发工具进行数据处理的效率。我们还将介绍基本的设计模式和最佳实践。

本节包括以下章节：

+   第六章，*深入 STL 中的数据结构和算法*

+   第七章，*函数式编程*

+   第八章，*并发和多线程*

+   第九章，*设计并发数据结构*

+   第十章，*设计面向世界的应用程序*

+   第十一章，*使用设计模式设计策略游戏*

+   第十二章，*网络和安全*

+   第十三章，*调试和测试*

+   第十四章，*使用 Qt 进行图形用户界面设计*


# 第六章：深入 STL 中的数据结构和算法

掌握数据结构对程序员至关重要。大多数情况下，数据存储方式定义了应用程序的整体效率。例如，考虑一个电子邮件客户端。您可以设计一个显示最新 10 封电子邮件的电子邮件客户端，并且它可能具有最佳的用户界面；在几乎任何设备上都可以顺畅地显示最近的 10 封电子邮件。您的电子邮件应用程序的用户在使用您的应用程序两年后可能会收到数十万封电子邮件。当用户需要搜索电子邮件时，您的数据结构知识将发挥重要作用。您存储数十万封电子邮件的方式以及您用于排序和搜索它们的方法（算法）将是您的程序与其他所有程序的区别所在。

程序员在项目中努力寻找每日问题的最佳解决方案。使用经过验证的数据结构和算法可以极大地改善程序员的工作。一个好程序最重要的特性之一是速度，通过设计新的算法或使用现有算法来获得速度。

最后，C++20 引入了用于定义**元类型**的**概念**，即描述其他类型的类型。语言的这一强大特性使数据架构完整。

C++的**标准模板库**（**STL**）涵盖了大量的数据结构和算法。我们将探索使用 STL 容器来高效组织数据的方法。然后我们将深入研究 STL 提供的算法实现。理解并使用 STL 容器中的概念至关重要，因为 C++20 通过引入迭代器概念来大幅改进迭代器。

本章将涵盖以下主题：

+   数据结构

+   STL 容器

+   概念和迭代器

+   掌握算法

+   探索树和图

# 技术要求

本章中使用带有选项`-std=c++2a`的 g++编译器来编译示例。您可以在本书的 GitHub 存储库中找到本章中使用的源文件[`github.com/PacktPublishing/Expert-CPP`](https://github.com/PacktPublishing/Expert-CPP)。

# 数据结构

作为程序员，您可能熟悉使用数组来存储和排序数据集。程序员在项目中除了数组之外还会大量使用其他数据结构。了解并应用适当的数据结构可能在程序性能中发挥重要作用。要选择正确的数据结构，您需要更好地了解它们。一个明显的问题可能会出现，即我们是否需要研究数据结构的动物园——向量、链表、哈希表、图、树等等。为了回答这个问题，让我们假设一个想要更好的数据结构的必要性自然而然地显现出来的想象场景。

在介绍内容中，我们提到了设计一个电子邮件客户端。让我们对其设计和实现过程中的基本任务有一个一般的了解。

电子邮件客户端是一个列出来自各个发件人的电子邮件的应用程序。我们可以将其安装在台式电脑或智能手机上，或者使用浏览器版本。电子邮件客户端应用程序的主要任务包括发送和接收电子邮件。现在假设我们正在设计一个足够简单的电子邮件客户端。就像在编程书籍中经常发生的那样，假设我们使用了一些封装了发送和接收电子邮件工作的库。我们更愿意集中精力设计专门用于存储和检索电子邮件的机制。电子邮件客户端用户应该能够查看**收件箱**部分中的电子邮件列表。我们还应该考虑用户可能想要对电子邮件执行的操作。他们可以逐个删除电子邮件，也可以一次删除多封。他们可以选择任意选定的电子邮件并回复给发件人或将电子邮件转发给其他人。

我们在第十章中讨论了软件设计过程和最佳实践，*设计真实世界应用程序*。现在，让我们草拟一个描述电子邮件对象的简单结构，如下所示：

```cpp
struct Email
{
  std::string subject;
  std::string body;
  std::string from;
  std::chrono::time_point datetime;
};
```

我们应该关心的第一件事是将电子邮件集合存储在一个易于访问的结构中。数组听起来可能不错。假设我们将所有收到的电子邮件存储在一个数组中，如下面的代码块所示：

```cpp
// let's suppose a million emails is the max for anyone
const int MAX_EMAILS = 1'000'000; 
Email inbox[MAX_EMAILS];
```

我们可以以任何形式存储 10 封电子邮件-这不会影响应用程序的性能。然而，显而易见的是，随着时间的推移，电子邮件的数量将增加。对于每封新收到的电子邮件，我们将`Email`对象与相应的字段推送到`inbox`数组中。数组的最后一个元素表示最近收到的电子邮件。因此，要显示最近的十封电子邮件列表，我们需要读取并返回数组的最后十个元素。

当我们尝试操作存储在`inbox`数组中的成千上万封电子邮件时，问题就出现了。如果我们想在所有电子邮件中搜索单词`friend`，我们必须扫描数组中的所有电子邮件，并将包含单词`friend`的电子邮件收集到一个单独的数组中。看看下面的伪代码：

```cpp
std::vector<Email> search(const std::string& word) {
  std::vector<Email> search_results;  
  for (all-million-emails) {
    if (inbox[i].subject.contains(word)) {
      search_results.push_back(inbox[i]);
    }
  }
  return search_results;
}
```

使用数组存储所有数据对于小集合来说已经足够了。在处理更大的数据集的真实世界应用程序中，情况会发生巨大变化。使用特定的数据结构的目的是使应用程序运行更加流畅。前面的例子展示了一个简单的问题：在电子邮件列表中搜索匹配特定值。在一封电子邮件中找到该值需要合理的时间。

如果我们假设电子邮件的主题字段可能包含多达十个单词，那么在电子邮件主题中搜索特定单词需要将该单词与主题中的所有单词进行比较。在*最坏的情况*下，没有匹配。我们强调最坏的情况，因为只有在查找需要检查主题中的每个单词时才会出现这种情况。对成千上万甚至数十万封电子邮件做同样的操作将使用户等待时间过长。

选择适合特定问题的数据结构对于应用程序的效率至关重要。例如，假设我们使用哈希表将单词映射到电子邮件对象。每个单词将被映射到包含该单词的电子邮件对象列表。这种方法将提高搜索操作的效率，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/f7318cbc-fefa-41f1-a377-9bf8ebd60b26.png)

`search()`函数将返回哈希表键引用的列表：

```cpp
std::vector<Email> search(const std::string& word) {
  return table[word];
}
```

这种方法只需要处理每封接收到的电子邮件，将其拆分为单词并更新哈希表。

为了简单起见，我们使用`Email`对象作为值而不是引用。请注意，最好将指针存储在向量中指向`Email`。

现在让我们来看看不同的数据结构及其应用。

# 顺序数据结构

开发人员最常用的数据结构之一是动态增长的一维数组，通常称为向量。STL 提供了一个同名的容器：`std::vector`。向量背后的关键思想是它包含相同类型的项目按顺序放置在内存中。例如，由 4 字节整数组成的向量将具有以下内存布局。向量的索引位于以下图表的右侧：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/8f1961c0-dcd6-481f-8ae8-3ba43902ba49.png)

向量的物理结构允许实时访问其任何元素。

我们应该根据容器的操作来区分它们，以便在特定问题中正确应用它们。为此，我们通常定义容器中的操作与容器中元素数量的运行时间复杂度的关系。例如，向量的元素访问被定义为常数时间操作，这意味着获取向量项需要相同数量的指令，无论向量长度如何。

访问向量的第一个元素和访问向量的第 100 个元素需要相同的工作量，因此我们称之为常数时间操作，也称为***O(1)操作***。

虽然向量中的元素访问速度很快，但添加新元素有些棘手。每当我们在向量的末尾插入新项时，我们还应该考虑向量的容量。当没有为向量分配更多空间时，它应该动态增长。看一下下面的`Vector`类及其`push_back()`函数：

```cpp
template <typename T>
class Vector
{
public:
  Vector() : buffer_{nullptr}, capacity_{2}, size_{0}
  {
    buffer_ = new T[capacity_]; // initializing an empty array
  }
  ~Vector() { delete [] buffer_; }
  // code omitted for brevity

public:
  void push_back(const T& item)
 {
 if (size_ == capacity_) {
 // resize
 }
 buffer_[size_++] = item;
 }
  // code omitted for brevity
};
```

在深入实现`push_back()`函数之前，让我们看一下下面的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/11cb3eec-b2a8-4166-8fdf-a58cf516bf90.png)

我们应该分配一个全新的数组，将旧数组的所有元素复制到新数组中，然后将新插入的元素添加到新数组末尾的下一个空闲槽中。这在下面的代码片段中显示：

```cpp
template <typename T>
class Vector
{
public:
  // code omitted for brevity
  void push_back(const T& item)
  {
    if (size_ == capacity_) {
 capacity_ *= 2; // increase the capacity of the vector twice
 T* temp_buffer = new T[capacity_];
      // copy elements of the old into the new
 for (int ix = 0; ix < size_; ++ix) {
 temp_buffer[ix] = buffer_[ix];
 }
 delete [] buffer_; // free the old array
 buffer_ = temp_buffer; // point the buffer_ to the new array
 }
    buffer_[size_++] = item;
  }
  // code omitted for brevity
};
```

调整因子可以选择不同 - 我们将其设置为`2`，这样每当向量满时，向量的大小就会增长两倍。因此，我们可以坚持认为，大多数情况下，在向量的末尾插入新项需要常数时间。它只是在空闲槽中添加项目并增加其`private size_`变量。不时地，添加新元素将需要分配一个新的、更大的向量，并将旧的向量复制到新的向量中。对于这样的情况，该操作被称为**摊销**常数时间完成。

当我们在向量的前面添加元素时，情况就不一样了。问题在于，所有其他元素都应该向右移动一个位置，以便为新元素腾出一个位置，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/0f4021af-1ec3-4d9d-85ca-891a7e16e42a.png)

这是我们在`Vector`类中如何实现它的方式：

```cpp
// code omitted for brevity
void push_front(const T& item)
{
  if (size_ == capacity_) {
    // resizing code omitted for brevity
  }
  // shifting all the elements to the right
 for (int ix = size_ - 1; ix > 0; --ix) {
 buffer_[ix] = buffer[ix - 1];
 }
  // adding item at the front buffer_[0] = item;
  size_++;
}
```

在需要仅在容器的前面插入新元素的情况下，选择向量并不是一个好的选择。这是其他容器应该被考虑的例子之一。

# 基于节点的数据结构

基于节点的数据结构不占用连续的内存块。基于节点的数据结构为其元素分配节点，没有任何顺序 - 它们可能随机分布在内存中。我们将每个项目表示为链接到其他节点的节点。

最流行和最基础的基于节点的数据结构是链表。下图显示了双向链表的可视结构：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/de263cb6-41ed-4f47-a59e-1a9e01261f64.png)

链表与向量非常不同。它的一些操作速度更快，尽管它缺乏向量的紧凑性。

为了简洁起见，让我们在列表的前面实现元素插入。我们将每个节点都保留为一个结构：

```cpp
template <typename T>
struct node 
{
  node(const T& it) : item{it}, next{nullptr}, prev{nullptr} {}
  T item;
  node<T>* next;
  node<T>* prev;
};
```

注意`next`成员 - 它指向相同的结构，这样可以允许节点链接在一起，如前面的插图所示。

要实现一个链表，我们只需要保留指向其第一个节点的指针，通常称为链表的头。在列表的前面插入元素很简单：

```cpp
template <typename T>
class LinkedList 
{
  // code omitted for brevity
public:
  void push_front(const T& item) 
 {
 node<T>* new_node = new node<T>{item};
 if (head_ != nullptr) {
 new_node->next = head_->next;
 if (head_->next != nullptr) {
 head_->next->prev = new_node;
 }
 }
 new_node->next = head_;
 head_ = new_node;
 }
private:
  node<T>* head_; 
};
```

在向列表中插入元素时，我们应该考虑三种情况：

+   如前所述，在列表前面插入元素需要以下步骤：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/06be3736-adbe-4388-9396-677b0a094a7f.png)

+   在列表末尾插入元素如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/6f88bf92-0a38-448d-a32c-8a92883f53ab.png)

+   最后，在列表中间插入元素的操作如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/75876dd0-13a8-4b23-a1be-68ac50c50dd0.png)

在前面的图中，向向量插入元素显然与向列表插入元素不同。您将如何在向量和列表之间进行选择？您应该专注于操作及其速度。例如，从向量中读取任何元素都需要恒定的时间。我们可以在向量中存储一百万封电子邮件，并在不需要任何额外工作的情况下检索位置为 834,000 的电子邮件。对于链表，操作是线性的。因此，如果您需要存储的数据集大部分是读取而不是写入，那么显然使用向量是一个合理的选择。

在列表中的任何位置插入元素都是一个常量时间的操作，而向量会努力在随机位置插入元素。因此，当您需要一个可以频繁添加/删除数据的对象集合时，更好的选择将是链表。

我们还应该考虑缓存内存。向量具有良好的数据局部性。读取向量的第一个元素涉及将前*N*个元素复制到缓存中。进一步读取向量元素将更快。我们不能说链表也是如此。要找出原因，让我们继续比较向量和链表的内存布局。

# 内存中的容器

正如您从前几章已经知道的那样，对象占用内存空间在进程提供的内存段之一上。大多数情况下，我们对堆栈或堆内存感兴趣。自动对象占用堆栈上的空间。以下两个声明都驻留在堆栈上：

```cpp
struct Email 
{
  // code omitted for brevity
};

int main() {
  Email obj;
  Email* ptr;
}
```

尽管`ptr`表示指向`Email`对象的指针，但它占用堆栈上的空间。它可以指向在堆上分配的内存位置，但指针本身（存储内存位置地址的变量）驻留在堆栈上。在继续使用向量和列表之前，这一点是至关重要的。

正如我们在本章前面看到的，实现向量涉及封装指向表示指定类型的元素数组的内部缓冲区的指针。当我们声明一个`Vector`对象时，它需要足够的堆栈内存来存储其成员数据。`Vector`类有以下三个成员：

```cpp
template <typename T>
class Vector
{
public:
  // code omitted for brevity

private:
  int capacity_;
  int size_;
  T* buffer_;
};
```

假设整数占用 4 个字节，指针占用 8 个字节，那么以下`Vector`对象声明将至少占用 16 个字节的堆栈内存：

```cpp
int main()
{
  Vector<int> v;
}
```

这是我们对前面代码的内存布局的想象：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/5b07753c-2089-4701-a865-3e98d597197f.png)

插入元素后，堆栈上的向量大小将保持不变。堆出现了。`buffer_`数组指向使用`new[]`运算符分配的内存位置。例如，看看以下代码：

```cpp
// we continue the code from previous listing
v.push_back(17);
v.push_back(21);
v.push_back(74);
```

我们推送到向量的每个新元素都将占用堆上的空间，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/ffb6f27e-00ca-4b30-86b7-4cdfd6c1530e.png)

每个新插入的元素都驻留在`buffer_`数组的最后一个元素之后。这就是为什么我们可以说向量是一个友好的缓存容器。

声明链表对象也会为其数据成员占用堆栈上的内存空间。如果我们讨论的是仅存储`head_`指针的简单实现，那么以下链表对象声明将至少占用 8 个字节的内存（仅用于`head_`指针）：

```cpp
int main()
{
  LinkedList<int> list;
}
```

以下插图描述了前面代码的内存布局：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/62daaf10-d88c-4439-a8e8-4bb85feb15e4.png)

插入新元素会在堆上创建一个`node`类型的对象。看看以下行：

```cpp
list.push_back(19);
```

在插入新元素后，内存插图将如下所示改变：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/62c34472-4720-43f8-80c1-71ac1b5ab204.png)

要注意的是，节点及其所有数据成员都驻留在堆上。该项存储我们插入的值。当我们插入另一个元素时，将再次创建一个新节点。这次，第一个节点的下一个指针将指向新插入的元素。而新插入的节点的 prev 指针将指向列表的前一个节点。下图描述了在插入第二个元素后链表的内存布局：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/080ab163-ffd0-4b7b-8ff8-2ba3e9dfed60.png)

当我们在向列表中插入元素之间在堆上分配一些随机对象时，会发生有趣的事情。例如，以下代码将一个节点插入列表，然后为一个整数（与列表无关）分配空间。最后，再次向列表中插入一个元素：

```cpp
int main()
{
  LinkedList<int> list;
  list.push_back(19);
  int* random = new int(129);
  list.push_back(22);
}
```

这个中间的随机对象声明破坏了列表元素的顺序，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/bff12ecb-958e-4b6b-95b1-d731f5a627a6.png)

前面的图表提示我们，列表不是一个友好的缓存容器，因为它的结构和其元素的分配。

注意通过将每个新节点合并到代码中所创建的内存开销。我们为一个元素额外支付 16 个字节（考虑到指针占用 8 个字节的内存）。因此，列表在最佳内存使用方面输给了向量。

我们可以尝试通过在列表中引入预分配的缓冲区来解决这个问题。然后每个新节点的创建将通过**placement new**操作符进行。然而，更明智的选择是选择更适合感兴趣问题的数据结构。

在实际应用程序开发中，程序员很少实现自己的向量或链表。他们通常使用经过测试和稳定的库版本。C++为向量和链表提供了标准容器。此外，它为单链表和双链表提供了两个单独的容器。

# STL 容器

STL 是一个强大的算法和容器集合。虽然理解和实现数据结构是程序员的一项重要技能，但你不必每次在项目中需要时都要实现它们。库提供者负责为我们实现稳定和经过测试的数据结构和算法。通过理解数据结构和算法的内部细节，我们在解决问题时能够更好地选择 STL 容器和算法。

先前讨论的向量和链表在 STL 中分别实现为`std::vector<T>`和`std::list<T>`，其中`T`是集合中每个元素的类型。除了类型，容器还以分配器作为第二个默认`template`参数。例如，`std::vector`声明如下：

```cpp
template <typename T, typename Allocator = std::allocator<T> >
class vector;
```

在上一章中介绍过，分配器处理容器元素的高效分配/释放。`std::allocator` 是 STL 中所有标准容器的默认分配器。一个更复杂的分配器，根据内存资源的不同而表现不同，是`std::pmr::polymorphic_allocator`。STL 提供了`std::pmr::vector`作为使用多态分配器的别名模板，定义如下：

```cpp
namespace pmr {
  template <typename T>
  using vector = std::vector<T, std::pmr::polymorphic_allocator<T>>;
}
```

现在让我们更仔细地看看`std::vector`和`std::list`。

# 使用 std::vector 和 std::list

`std::vector`在`<vector>`头文件中定义。以下是最简单的使用示例：

```cpp
#include <vector>

int main()
{
  std::vector<int> vec;
  vec.push_back(4);
  vec.push_back(2);
  for (const auto& elem : vec) {
    std::cout << elem;
  }
}
```

`std::vector`是动态增长的。我们应该考虑增长因子。在声明一个向量时，它有一些默认容量，然后在插入元素时会增长。每当元素的数量超过向量的容量时，它会以给定的因子增加其容量（通常情况下，它会将其容量加倍）。如果我们知道我们将需要的向量中元素的大致数量，我们可以通过使用`reserve()`方法来为向量最初分配该容量来优化其使用。例如，以下代码保留了一个包含 10,000 个元素的容量：

```cpp
std::vector<int> vec;
vec.reserve(10000);
```

它强制向量为 10,000 个元素分配空间，从而避免在插入元素时进行调整大小（除非达到 10,000 个元素的阈值）。

另一方面，如果我们遇到容量远大于向量中实际元素数量的情况，我们可以缩小向量以释放未使用的内存。我们需要调用`shrink_to_fit()`函数，如下例所示：

```cpp
vec.shrink_to_fit();
```

这减少了容量以适应向量的大小。

访问向量元素的方式与访问常规数组的方式相同，使用`operator[]`。然而，`std::vector`提供了两种访问其元素的选项。其中一种被认为是安全的方法，通过`at()`函数进行，如下所示：

```cpp
std::cout << vec.at(2);
// is the same as
std::cout << vec[2];
// which is the same as
std::cout << vec.data()[2];
```

`at()`和`operator[]`之间的区别在于，`at()`通过边界检查访问指定的元素；也就是说，以下行会抛出`std::out_of_range`异常：

```cpp
try {
  vec.at(999999);
} catch (std::out_of_range& e) { }
```

我们几乎以相同的方式使用`std::list`。这些列表大多有相似的公共接口。在本章后面，我们将讨论迭代器，允许从特定容器中抽象出来，这样我们可以用一个向量替换一个列表而几乎没有任何惩罚。在此之前，让我们看看列表和向量的公共接口之间的区别。

除了两个容器都支持的标准函数集，如`size()`、`resize()`、`empty()`、`clear()`、`erase()`等，列表还有`push_front()`函数，它在列表的前面插入一个元素。这样做是有效的，因为`std::list`表示一个双向链表。如下所示，`std::list`也支持`push_back()`：

```cpp
std::list<double> lst;
lst.push_back(4.2);
lst.push_front(3.14);
// the list contains: "3.14 -> 4.2"
```

列表支持许多在许多情况下非常有用的附加操作。例如，要合并两个排序列表，我们使用`merge()`方法。它接受另一个列表作为参数，并将其所有元素移动到当前列表。传递给`merge()`方法的列表在操作后变为空。

STL 还提供了一个单向链表，由`std::forward_list`表示。要使用它，应该包含`<forward_list>`头文件。由于单向链表节点只有一个指针，所以在内存方面比双向链表更便宜。

`splice()`方法与`merge()`有些相似，不同之处在于它移动作为参数提供的列表的一部分。所谓移动，是指重新指向内部指针以指向正确的列表节点。这对于`merge()`和`splice()`都是成立的。

当我们使用容器存储和操作复杂对象时，复制元素的代价在程序性能中起着重要作用。考虑以下表示三维点的结构体：

```cpp
struct Point
{
  float x;
  float y;
  float z;

  Point(float px, float py, float pz)
    : x(px), y(py), z(pz)
  {}

  Point(Point&& p)
    : x(p.x), y(p.y), z(p.z)
  {}
};
```

现在，看看以下代码，它将一个`Point`对象插入到一个向量中：

```cpp
std::vector<Point> points;
points.push_back(Point(1.1, 2.2, 3.3));
```

首先构造一个临时对象，然后将其移动到向量的相应插槽中。我们可以用以下方式进行可视化表示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/d94643e3-cbfa-4816-8059-4ac126c1bbcb.png)

显然，向量事先占用更多空间，以尽可能延迟调整大小操作。当我们插入一个新元素时，向量将其复制到下一个可用插槽（如果已满，则重新分配更多空间）。我们可以利用该未初始化空间来创建一个新元素。向量提供了`emplace_back()`函数来实现这一目的。以下是我们如何使用它：

```cpp
points.emplace_back(1.1, 2.2, 3.3);
```

注意我们直接传递给函数的参数。以下插图描述了`emplace_back()`的使用：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/47e01350-abf8-4a83-8eba-70afe1301af7.png)

`emplace_back()`通过`std::allocator_traits::construct()`构造元素。后者通常使用新操作符的放置来在已分配但未初始化的空间中构造元素。

`std::list`还提供了一个`emplace_front()`方法。这两个函数都返回插入的元素的引用。唯一的要求是元素的类型必须是`EmplaceConstructible`。对于向量，类型还应该是`MoveInsertable`。

# 使用容器适配器

你可能已经遇到了关于堆栈和队列的描述，它们被称为数据结构（或者在 C++术语中称为*容器*）。从技术上讲，它们不是数据结构，而是数据结构适配器。在 STL 中，`std::stack`和`std::queue`通过提供特殊的接口来访问容器来适配容器。术语*堆栈*几乎无处不在。到目前为止，我们已经用它来描述具有自动存储期限的对象的内存段。该段采用*堆栈*的名称，因为它的分配/释放策略。

我们说每次声明对象时，对象都会被推送到堆栈上，并在销毁时弹出。对象以它们被推送的相反顺序弹出。这就是称内存段为堆栈的原因。相同的**后进先出**（**LIFO**）方法适用于堆栈适配器。`std::stack`提供的关键函数如下：

```cpp
void push(const value_type& value);
void push(value_type&& value);
```

`push()`函数有效地调用基础容器的`push_back()`。通常，堆栈是使用向量实现的。我们已经在第三章中讨论过这样的情况，*面向对象编程的细节*，当我们介绍了受保护的继承。`std::stack`有两个模板参数；其中一个是容器。你选择什么并不重要，但它必须有一个`push_back()`成员函数。`std::stack`和`std::queue`的默认容器是`std::deque`。

`std::deque`允许在其开头和结尾快速插入。它是一个类似于`std::vector`的索引顺序容器。deque 的名称代表*双端队列*。

让我们看看堆栈的运行情况：

```cpp
#include <stack>

int main()
{
  std::stack<int> st;
  st.push(1); // stack contains: 1
  st.push(2); // stack contains: 2 1
  st.push(3); // stack contains: 3 2 1
}
```

`push()`函数的一个更好的替代方法是`emplace()`。它调用基础容器的`emplace_back()`，因此在原地构造元素。

要取出元素，我们调用`pop()`函数。它不接受任何参数，也不返回任何内容，只是从堆栈中移除顶部元素。要访问堆栈的顶部元素，我们调用`top()`函数。让我们修改前面的示例，在弹出元素之前打印所有堆栈元素：

```cpp
#include <stack>

int main()
{
  std::stack<int> st;
  st.push(1);
  st.push(2);
  st.push(3);
  std::cout << st.top(); // prints 3
  st.pop();
  std::cout << st.top(); // prints 2
  st.pop();
  std::cout << st.top(); // prints 1
  st.pop();
  std::cout << st.top(); // crashes application
}
```

`top()`函数返回对顶部元素的引用。它调用基础容器的`back()`函数。在空堆栈上调用`top()`函数时要注意。我们建议在对空堆栈调用`top()`之前检查堆栈的大小使用`size()`。

`queue`是另一个适配器，其行为与堆栈略有不同。队列背后的逻辑是它首先返回插入的第一个元素：它遵循**先进先出**（**FIFO**）原则。看下面的图表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/04d19255-e43e-485b-af2f-6269d220bd0e.png)

队列中插入和检索操作的正式名称是**enqeue**和**dequeue**。`std::queue`保持一致的方法，并提供`push()`和`pop()`函数。要访问队列的第一个和最后一个元素，应该使用`front()`和`back()`。两者都返回元素的引用。这里是一个简单的使用示例：

```cpp
#include <queue>

int main()
{
 std::queue<char> q;
  q.push('a');
  q.push('b');
  q.push('c');
  std::cout << q.front(); // prints 'a'
  std::cout << q.back(); // prints 'c'
  q.pop();
  std::cout << q.front(); // prints 'b'
}
```

当你正确应用它们时，了解各种容器和适配器是有用的。在选择所有类型问题的正确容器时，并没有银弹。许多编译器使用堆栈来解析代码表达式。例如，使用堆栈很容易验证以下表达式中的括号：

```cpp
int r = (a + b) + (((x * y) - (a / b)) / 4);
```

尝试练习一下。编写一个小程序，使用堆栈验证前面的表达式。

队列的应用更加广泛。我们将在第十一章中看到其中之一，*使用设计模式设计策略游戏*，在那里我们设计了一个策略游戏。

另一个容器适配器是`std::priority_queue`。优先队列通常适配平衡的、基于节点的数据结构，例如最大堆或最小堆。我们将在本章末尾讨论树和图，并看看优先队列在内部是如何工作的。

# 迭代容器

一个不可迭代的容器的概念就像一辆无法驾驶的汽车一样。毕竟，容器是物品的集合。迭代容器元素的常见方法之一是使用普通的`for`循环：

```cpp
std::vector<int> vec{1, 2, 3, 4, 5};
for (int ix = 0; ix < vec.size(); ++ix) {
  std::cout << vec[ix];
}
```

容器提供了一组不同的元素访问操作。例如，向量提供了`operator[]`，而列表则没有。`std::list`有`front()`和`back()`方法，分别返回第一个和最后一个元素。另外，正如前面讨论的，`std::vector`还提供了`at()`和`operator[]`。

这意味着我们不能使用前面的循环来迭代列表元素。但我们可以使用基于范围的`for`循环来遍历列表（和向量），如下所示：

```cpp
std::list<double> lst{1.1, 2.2, 3.3, 4.2};
for (auto& elem : lst) {
  std::cout << elem;
} 
```

这可能看起来令人困惑，但诀窍隐藏在基于范围的`for`实现中。它使用`std::begin()`函数检索指向容器第一个元素的迭代器。

**迭代器**是指向容器元素的对象，并且可以根据容器的物理结构前进到下一个元素。以下代码声明了一个`vector`迭代器，并用指向`vector`开头的迭代器进行初始化：

```cpp
std::vector<int> vec{1, 2, 3, 4};
std::vector<int>::iterator it{vec.begin()};
```

容器提供两个成员函数`begin()`和`end()`，分别返回指向容器开头和结尾的迭代器。以下图表显示了我们如何处理容器的开头和结尾：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/4a058f5f-c5de-47fb-94e4-a5e25dbf0440.png)

使用基于范围的`for`迭代列表元素的先前代码可以被视为以下内容：

```cpp
auto it_begin = std::begin(lst);
auto it_end = std::end(lst);
for ( ; it_begin != it_end; ++it_begin) {
  std::cout << *it_begin;
}
```

注意我们在先前代码中使用的`*`运算符，通过迭代器访问底层元素。我们认为迭代器是对容器元素的*巧妙*指针。

`std::begin()`和`std::end()`函数通常调用容器的`begin()`和`end()`方法，但它们也适用于常规数组。

容器迭代器确切地知道如何处理容器元素。例如，向前推进向量迭代器会将其移动到数组的下一个槽位，而向前推进列表迭代器会使用相应的指针将其移动到下一个节点，如下面的代码所示：

```cpp
std::vector<int> vec;
vec.push_back(4);
vec.push_back(2);
std::vector<int>::iterator it = vec.begin();
std::cout << *it; // 4
it++;
std::cout << *it; // 2

std::list<int> lst;
lst.push_back(4);
lst.push_back(2);
std::list<int>::iterator lit = lst.begin();
std::cout << *lit; // 4
lit++;
std::cout << *lit; // 2
```

每个容器都有自己的迭代器实现；这就是为什么列表和向量迭代器有相同的接口但行为不同。迭代器的行为由其*类别*定义。例如，向量的迭代器是随机访问迭代器，这意味着我们可以使用迭代器随机访问任何元素。以下代码通过向量的迭代器访问第四个元素，方法是将`3`添加到迭代器上：

```cpp
auto it = vec.begin();
std::cout << *(it + 3);
```

STL 中有六种迭代器类别：

+   输入

+   输出（与输入相同，但支持写访问）

+   前向

+   双向

+   随机访问

+   连续

**输入迭代器**提供读取访问（通过调用`*`运算符）并使用前缀和后缀递增运算符向前推进迭代器位置。输入迭代器不支持多次遍历，也就是说，我们只能使用迭代器对容器进行一次遍历。另一方面，**前向迭代器**支持多次遍历。多次遍历支持意味着我们可以通过迭代器多次读取元素的值。

**输出迭代器**不提供对元素的访问，但它允许为其分配新值。具有多次遍历特性的输入迭代器和输出迭代器的组合构成了前向迭代器。然而，前向迭代器仅支持递增操作，而**双向迭代器**支持将迭代器移动到任何位置。它们支持递减操作。例如，`std::list`支持双向迭代器。

最后，**随机访问迭代器**允许通过向迭代器添加/减去一个数字来*跳跃*元素。迭代器将跳转到由算术操作指定的位置。`std::vector`提供了随机访问迭代器。

每个类别都定义了可以应用于迭代器的操作集。例如，输入迭代器可用于读取元素的值并通过递增迭代器前进到下一个元素。另一方面，随机访问迭代器允许以任意值递增和递减迭代器，读取和写入元素的值等。

到目前为止在本节中描述的所有特性的组合都属于**连续迭代器**类别，它也期望容器是一个连续的。这意味着容器元素保证紧邻在一起。`std::array`就是一个连续的容器的例子。

诸如`distance()`的函数使用迭代器的信息来实现最快的执行结果。例如，两个双向迭代器之间的`distance()`函数需要线性执行时间，而随机访问迭代器的相同函数在常数时间内运行。

以下伪代码演示了一个示例实现：

```cpp
template <typename Iter>
std::size_type distance(Iter first, Iter second) {
  if (Iter is a random_access_iterator) {
    return second - first; 
  }
  std::size_type count = 0;
  for ( ; first != last; ++count, first++) {}
  return count;
}
```

尽管前面示例中显示的伪代码运行良好，但我们应该考虑在运行时检查迭代器的类别不是一个选项。它是在编译时定义的，因此我们需要使用模板特化来生成随机访问迭代器的`distance()`函数。更好的解决方案是使用`<type_traits>`中定义的`std::is_same`类型特征：

```cpp
#include <iterator>
#include <type_traits>

template <typename Iter>
typename std::iterator_traits<Iter>::difference_type distance(Iter first, Iter last)
{
  using category = std::iterator_traits<Iter>::iterator_category;
  if constexpr (std::is_same_v<category, std::random_access_iterator_tag>) {
    return last - first;
  }
  typename std::iterator_traits<Iter>::difference_type count;
  for (; first != last; ++count, first++) {}
  return count;
}
```

`std::is_same_v`是`std::is_same`的辅助模板，定义如下：

```cpp
template <class T, class U>
inline constexpr bool is_same_v = is_same<T, U>::value;
```

迭代器最重要的特性是提供了容器和算法之间的松耦合：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/2d7a6c25-7b1f-4a4d-a3c1-80259c833393.png)

STL 基于这三个概念：容器、算法和迭代器。虽然向量、列表或任何其他容器都不同，它们都有相同的目的：存储数据。

另一方面，算法是处理数据的函数；它们大部分时间都与数据集合一起工作。算法定义通常代表了指定应采取哪些步骤来处理容器元素的通用方式。例如，排序算法按升序或降序对容器元素进行排序。

向量是连续的容器，而列表是基于节点的容器。对它们进行排序将需要更深入地了解特定容器的物理结构。为了正确地对向量进行排序，应该为它实现一个单独的排序函数。相同的逻辑也适用于列表。

迭代器将这种多样性的实现提升到了一个通用级别。它们为库设计者提供了实现只需处理迭代器的排序函数的能力，抽象出容器类型。在 STL 中，`sort()`算法（在`<algorithm>`中定义）处理迭代器，我们可以使用相同的函数对向量和列表进行排序：

```cpp
#include <algorithm>
#include <vector>
#include <list>
...
std::vector<int> vec;
// insert elements into the vector
std::list<int> lst;
// insert elements into the list

std::sort(vec.begin(), vec.end());
std::sort(lst.begin(), lst.end());
```

本节中描述的迭代器现在被认为是遗留特性。C++20 引入了基于**概念**的新迭代器系统。

# 概念和迭代器

C++20 将**概念**作为其主要特性之一引入。除了概念，C++20 还有基于概念的新迭代器。尽管本章讨论的迭代器现在被认为是遗留特性，但已经有大量的代码使用它们。这就是为什么我们在继续介绍新的迭代器概念之前首先介绍它们的原因。现在，让我们了解一下概念是什么，以及如何使用它们。

# 理解概念

抽象在计算机编程中是至关重要的。我们在第三章中引入了类，*面向对象编程的细节*，作为一种将数据和操作表示为抽象实体的方式。之后，在第四章中，*理解和设计模板*，我们深入研究了模板，并看到如何通过重用它们来使类变得更加灵活，以适用于各种聚合类型。模板不仅提供了对特定类型的抽象，还实现了实体和聚合类型之间的松耦合。例如，`std::vector`。它提供了一个通用接口来存储和操作对象的集合。我们可以轻松地声明三个包含三种不同类型对象的不同向量，如下所示：

```cpp
std::vector<int> ivec;
std::vector<Person> persons;
std::vector<std::vector<double>> float_matrix;
```

如果没有模板，我们将不得不对前面的代码做如下处理：

```cpp
std::int_vector ivec;
std::custom_vector persons; // supposing the custom_vector stores void* 
std::double_vector_vector float_matrix;
```

尽管前面的代码是不可接受的，但我们应该同意模板是泛型编程的基础。概念为泛型编程引入了更多的灵活性。现在可以对模板参数设置限制，检查约束，并在编译时发现不一致的行为。模板类声明的形式如下：

```cpp
template <typename T>
class Wallet
{
  // the body of the class using the T type
};
```

请注意前面代码块中的`typename`关键字。概念甚至更进一步：它们允许用描述模板参数的类型描述来替换它。假设我们希望`Wallet`能够处理可以相加的类型，也就是说，它们应该是*可加的*。以下是如何使用概念来帮助我们在代码中实现这一点：

```cpp
template <addable T>
class Wallet
{
  // the body of the class using addable T's
};
```

因此，现在我们可以通过提供可相加的类型来创建`Wallet`实例。每当类型不满足约束时，编译器将抛出错误。这看起来有点超自然。以下代码片段声明了两个`Wallet`对象：

```cpp
class Book 
{
  // doesn't have an operator+
  // the body is omitted for brevity
};

constexpr bool operator+(const Money& a, const Money& b) { 
  return Money{a.value_ + b.value_}; 
}

class Money
{
  friend constexpr bool operator+(const Money&, const Money&);
  // code omitted for brevity
private:
  double value_;
};

Wallet<Money> w; // works fine
Wallet<Book> g; // compile error
```

`Book`类没有`+`运算符，因此由于`template`参数类型限制，`g`的构造将失败。

使用`concept`关键字来声明概念，形式如下：

```cpp
template <*parameter-list*>
concept *name-of-the-concept* = *constraint-expression*;
```

正如你所看到的，概念也是使用模板来声明的。我们可以将它们称为描述其他类型的类型。概念在**约束**上有很大的依赖。约束是指定模板参数要求的一种方式，因此概念是一组约束。以下是我们如何实现前面的可加概念：

```cpp
template <typename T>
concept addable = requires (T obj) { obj + obj; }
```

标准概念在`<concepts>`头文件中定义。

我们还可以通过要求新概念支持其他概念来将几个概念合并为一个。为了实现这一点，我们使用`&&`运算符。让我们看看迭代器如何利用概念，并举例说明一个将其他概念结合在一起的`incrementable`迭代器概念。

# 在 C++20 中使用迭代器

在介绍概念之后，显而易见的是迭代器是首先充分利用它们的。迭代器及其类别现在被认为是遗留的，因为从 C++20 开始，我们使用迭代器概念，如**`readable`**（指定类型可通过应用`*`运算符进行读取）和`writable`（指定可以向迭代器引用的对象写入值）。正如承诺的那样，让我们看看`incrementable`在`<iterator>`头文件中是如何定义的：

```cpp
template <typename T>
concept incrementable = std::regular<T> && std::weakly_incrementable<T>
            && requires (T t) { {t++} -> std::same_as<T>; };
```

因此，可递增的概念要求类型为 std::regular。这意味着它应该可以通过默认方式构造，并且具有复制构造函数和 operator==()。除此之外，可递增的概念要求类型为 weakly_incrementable，这意味着该类型支持前置和后置递增运算符，除了不需要该类型是可比较相等的。这就是为什么可递增加入 std::regular 要求类型是可比较相等的。最后，附加的 requires 约束指出类型在递增后不应更改，也就是说，它应该与之前的类型相同。尽管 std::same_as 被表示为一个概念（在<concepts>中定义），在以前的版本中我们使用的是在<type_traits>中定义的 std::is_same。它们基本上做同样的事情，但是 C++17 版本的 std::is_same_v 很啰嗦，带有额外的后缀。

因此，现在我们不再提到迭代器类别，而是提到迭代器概念。除了我们之前介绍的概念，还应该考虑以下概念：

+   输入迭代器指定该类型允许读取其引用值，并且可以进行前置和后置递增。

+   输出迭代器指定该类型的值可以被写入，并且该类型可以进行前置和后置递增。

+   输入或输出迭代器，除了名称过长之外，指定该类型是可递增的，并且可以被解引用。

+   前向迭代器指定该类型是一个输入迭代器，此外还支持相等比较和多遍历。

+   双向迭代器指定该类型支持前向迭代器，并且还支持向后移动。

+   随机访问迭代器指定该类型为双向迭代器，支持常数时间的前进和下标访问。

+   连续迭代器指定该类型是一个随机访问迭代器，指的是内存中连续的元素。

它们几乎重复了我们之前讨论的传统迭代器，但现在它们可以在声明模板参数时使用，这样编译器将处理其余部分。

# 掌握算法

正如前面提到的，算法是接受一些输入，处理它，并返回输出的函数。通常，在 STL 的上下文中，算法意味着处理数据集合的函数。数据集合以容器的形式呈现，例如 std::vector、std::list 等。

选择高效的算法是程序员日常工作中的常见任务。例如，使用二分搜索算法搜索排序后的向量将比使用顺序搜索更有效。为了比较算法的效率，进行所谓的渐近分析，考虑算法速度与输入数据大小的关系。这意味着我们实际上不应该将两个算法应用于一个包含十个或一百个元素的容器进行比较。

算法的实际差异在应用于足够大的容器时才会显现，比如有一百万甚至十亿条记录的容器。衡量算法的效率也被称为验证其复杂性。您可能遇到过 O(n)算法或 O(log N)算法。O()函数（读作 big-oh）定义了算法的复杂性。

让我们来看看搜索算法，并比较它们的复杂性。

# 搜索

在容器中搜索元素是一个常见的任务。让我们实现在向量中进行顺序搜索元素。

```cpp
template <typename T>
int search(const std::vector<T>& vec, const T& item)
{
  for (int ix = 0; ix < vec.size(); ++ix) {
    if (vec[ix] == item) {
      return ix;
    }
  }
  return -1; // not found
}
```

这是一个简单的算法，它遍历向量并返回元素等于作为搜索键传递的值的索引。我们称之为顺序搜索，因为它按顺序扫描向量元素。它的复杂性是线性的：*O(n)*。为了衡量它，我们应该以某种方式定义算法找到结果所需的操作数。假设向量包含 *n* 个元素，下面的代码在搜索函数的每一行都有关于其操作的注释：

```cpp
template <typename T>
int search(const std::vector<T>& vec, const T& item)
{
  for (int ix = 0;           // 1 copy
       ix < vec.size;        // n + 1 comparisons 
       ++ix)                 // n + 1 increments
  {  
    if (vec[ix] == item) {   // n comparisons
      return ix;             // 1 copy
    }
  }
  return -1;                 // 1 copy
}
```

我们有三种复制操作，*n + 1* 和 *n*（也就是 *2n + 1*）次比较，以及 *n + 1* 次增量操作。如果所需元素在向量的第一个位置怎么办？那么，我们只需要扫描向量的第一个元素并从函数中返回。

然而，这并不意味着我们的算法非常高效，只需要一步就能完成任务。为了衡量算法的复杂性，我们应该考虑最坏情况：所需元素要么不存在于向量中，要么位于向量的最后位置。下图显示了我们即将找到的元素的三种情况：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/89c34b2d-9597-4ea4-ac1a-a32ef5031eb7.png)

我们只需要考虑最坏情况，因为它也涵盖了所有其他情况。如果我们为最坏情况定义算法的复杂性，我们可以确保它永远不会比那更慢。

为了找出算法的复杂性，我们应该找到操作次数和输入大小之间的关系。在这种情况下，输入的大小是容器的长度。让我们将复制记为 A，比较记为 C，增量操作记为 I，这样我们就有 3A + (2n + 1)C + (n + 1)I 次操作。算法的复杂性将定义如下：

*O(3A + (2n + 1)C + (n + 1)I)*

这可以以以下方式简化：

+   *O(3A + (2n + 1)C + (n + 1)I) =*

+   *O(3A + 2nC + C + nI + I) = *

+   *O(n(2C + I) + (3A + C + I)) = *

+   *O(n(2C + I))*

最后，*O()*的属性使我们可以摆脱常数系数和较小的成员，因为实际算法的复杂性只与输入的大小有关，即 *n*，我们得到最终复杂性等于 *O(n)*。换句话说，顺序搜索算法具有线性时间复杂性。

正如前面提到的，STL 的本质是通过迭代器连接容器和算法。这就是为什么顺序搜索实现不被认为是 STL 兼容的：因为它对输入参数有严格的限制。为了使其通用，我们应该考虑仅使用迭代器来实现它。为了涵盖各种容器类型，使用前向迭代器。下面的代码使用了`Iter`类型的操作符，假设它是一个前向迭代器：

```cpp
template <typename Iter, typename T>
int search(Iter first, Iter last, const T& elem)
{
  for (std::size_t count = 0; first != last; first++, ++count) {
    if (*first == elem) return count;
  }
  return -1;
}
...
std::vector<int> vec{4, 5, 6, 7, 8};
std::list<double> lst{1.1, 2.2, 3.3, 4.4};

std::cout << search(vec.begin(), vec.end(), 5);
std::cout << search(lst.begin(), lst.end(), 5.5);
```

实际上，任何类型的迭代器都可以传递给`search()`函数。我们通过对迭代器本身应用操作来确保使用前向迭代器。我们只使用增量（向前移动）、读取（`*`运算符）和严格比较（`==`和`!=`），这些操作都受前向迭代器支持。

# 二分搜索

另一方面是二分搜索算法，这个算法很容易解释。首先，它查找向量的中间元素并将搜索键与之进行比较，如果相等，算法就结束了：它返回索引。否则，如果搜索键小于中间元素，算法继续向向量的左侧进行。如果搜索键大于中间元素，算法继续向右侧子向量进行。

为了使二分搜索在向量中正确工作，它应该是排序的。二分搜索的核心是将搜索键与向量元素进行比较，并继续到左侧或右侧子向量，每个子向量都包含与向量中间元素相比较的较小或较大的元素。看一下下面的图表，它描述了二分搜索算法的执行过程：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/c478e0fd-ae7e-4b99-8bec-7c288cd13272.png)

二分搜索算法有一个优雅的递归实现（尽管最好使用迭代实现）-在下面的代码中看一下：

```cpp
template <typename T>
std::size_t binsearch(const std::vector<T>& vec, const T& item, int start, int end)
{
  if (start > end) return -1;
  int mid = start + (end - start) / 2;
  if (vec[mid] == item) {
    return mid; // found
  }
  if (vec[mid] > item) {
    return binsearch(vec, item, start, mid - 1);
  }
  return binsearch(vec, item, mid + 1, end);
}
```

注意中间元素的计算。我们使用了`start + (end - start) / 2;`技术，而不是`(start + end) / 2;`，只是为了避免二分搜索实现中的著名错误（假设我们没有留下其他错误）。关键是对于 start 和 end 的大值，它们的和（*start + end*）会产生整数溢出，这将导致程序在某个时刻崩溃。

现在让我们找到二分搜索的复杂度。很明显，在执行的每一步中，源数组都会减半，这意味着我们在下一步中处理它的较小或较大的一半。这意味着最坏情况是将向量分割到只剩下一个或没有元素的情况。为了找到算法的步数，我们应该根据向量的大小找到分割的次数。如果向量有 10 个元素，那么我们将它分成一个包含五个元素的子向量；再次分割，我们得到一个包含两个元素的子向量，最后，再次分割将带我们到一个单一元素。因此，对于包含 10 个元素的向量，分割的次数是 3。对于包含*n*个元素的向量，分割的次数是*log(n)*，因为在每一步中，*n*变为*n/2*，然后变为*n/4*，依此类推。二分搜索的复杂度是*O(logn)*（即对数）。

STL 算法定义在`<algorithm>`头文件中；二分搜索的实现也在其中。STL 实现如果元素存在于容器中则返回 true。看一下它的原型：

```cpp
template <typename Iter, typename T>
bool binary_search(Iter start, Iter end, const T& elem);
```

STL 算法不直接与容器一起工作，而是与迭代器一起工作。这使我们能够抽象出特定的容器，并使用`binary_search()`来支持前向迭代器的所有容器。下面的示例调用了`binary_search()`函数，用于向量和列表：

```cpp
#include <vector>
#include <list>
#include <algorithm>
...
std::vector<int> vec{1, 2, 3, 4, 5};
std::list<int> lst{1, 2, 3, 4};
binary_search(vec.begin(), vec.end(), 8);
binary_search(lst.begin(), lst.end(), 3);
```

`binary_search()`检查迭代器的类别，在随机访问迭代器的情况下，它使用二分搜索算法的全部功能（否则，它将退回到顺序搜索）。

# 排序

二分搜索算法仅适用于排序的容器。对于计算机程序员来说，排序是一个众所周知的古老任务，现在他们很少编写自己的排序算法实现。你可能多次使用了`std::sort()`而不关心它的实现。基本上，排序算法接受一个集合作为输入，并返回一个新的排序集合（按照算法用户定义的顺序）。

在众多的排序算法中，最流行的（甚至是最快的）是**快速排序**。任何排序算法的基本思想都是找到较小（或较大）的元素，并将它们与较大（或较小）的元素交换，直到整个集合排序。例如，选择排序逻辑上将集合分为两部分，已排序和未排序，其中已排序的子数组最初为空，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/303865f2-ae26-44a9-bce2-0f8cefb9cc6f.png)

算法开始在未排序的子数组中寻找最小的元素，并通过与未排序的子数组的第一个元素交换将其放入已排序的子数组中。每一步之后，已排序子数组的长度增加了一个，而未排序子数组的长度减少了，如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/995dc143-d05a-4a3d-b808-de3d058583c5.png)

该过程持续进行，直到未排序的子数组变为空。

STL 提供了`std::sort()`函数，接受两个随机访问迭代器：

```cpp
#include <vector>
#include <algorithm>
...
std::vector<int> vec{4, 7, -1, 2, 0, 5};
std::sort(vec.begin(), vec.end());
// -1, 0, 2, 4, 5, 7
```

`sort`函数不能应用于`std::list`，因为它不支持随机访问迭代器。相反，应该调用列表的`sort()`成员函数。尽管这与 STL 具有通用函数的想法相矛盾，但出于效率考虑而这样做。

`sort()`函数有一个第三个参数：一个比较函数，用于比较容器元素。假设我们在向量中存储`Product`对象：

```cpp
struct Product
{
  int price;
  bool available;
  std::string title;
};

std::vector<Product> products;
products.push_back({5, false, "Product 1"});
products.push_back({12, true, "Product 2"});
```

为了正确排序容器，其元素必须支持小于运算符，或`<`。我们应该为我们的自定义类型定义相应的运算符。但是，如果我们为我们的自定义类型创建一个单独的比较函数，就可以省略运算符定义，如下面的代码块所示：

```cpp
class ProductComparator
{
public:
 bool operator()(const Product& a, const Product& b) {
 return a.price > b.price;
 }
};
```

将`ProductComparator`传递给`std::sort()`函数允许它比较向量元素，而无需深入了解其元素的类型，如下所示：

```cpp
std::sort(products.begin(), products.end(), ProductComparator{});
```

虽然这是一个不错的技术，但更优雅的做法是使用 lambda 函数，它们是匿名函数，非常适合前面提到的场景。以下是我们如何覆盖它的方法：

```cpp
std::sort(products.begin(), products.end(), 
  [](const Product& a, const Product& b) { return a.price > b.price; })
```

上述代码允许省略`ProductComparator`的声明。

# 探索树和图

二叉搜索算法和排序算法结合在一起，引出了默认按排序方式保持项目的容器的想法。其中一个这样的容器是基于平衡树的`std::set`。在讨论平衡树本身之前，让我们先看看二叉搜索树，这是一个快速查找的完美候选者。

二叉搜索树的思想是，节点的左子树的值小于节点的值。相比之下，节点的右子树的值大于节点的值。以下是一个二叉搜索树的示例：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/9c361b58-ff03-4ab1-bffc-dd29595f2378.png)

如前面的图表所示，值为 15 的元素位于左子树中，因为它小于 30（根元素）。另一方面，值为 60 的元素位于右子树中，因为它大于根元素。相同的逻辑适用于树的其余元素。

二叉树节点表示为一个包含项目和指向每个子节点的两个指针的结构。以下是树节点的示例代码表示：

```cpp
template <typename T>
struct tree_node
{
  T item;
  tree_node<T>* left;
  tree_node<T>* right;
};
```

在完全平衡的二叉搜索树中，搜索、插入或删除元素需要*O(logn)*的时间。STL 没有为树提供单独的容器，但它有基于树实现的类似容器。例如，`std::set`容器是基于平衡树的，可以按排序顺序唯一存储元素：

```cpp
#include <set>
...
std::set<int> s{1, 5, 2, 4, 4, 4, 3};
// s has {1, 2, 3, 4, 5}
```

`std::map`也是基于平衡树，但它提供了一个将键映射到某个值的容器，例如：

```cpp
#include <map>
...
std::map<int, std::string> numbers;
numbers[3] = "three";
numbers[4] = "four";
...
```

如前面的代码所示，`map` `numbers`函数将整数映射到字符串。因此，当我们告诉地图将`3`的值存储为键，`three`的字符串作为值时，它会向其内部树添加一个新节点，其键等于`3`，值等于`three`。

`set`和`map`操作是对数的，这使得它在大多数情况下成为非常高效的数据结构。然而，更高效的数据结构接下来就要出现。

# 哈希表

哈希表是最快的数据结构。它基于一个简单的向量索引的想法。想象一个包含指向列表的指针的大向量：

```cpp
std::vector<std::list<T> > hash_table;
```

访问向量元素需要常数时间。这是向量的主要优势。哈希表允许我们使用任何类型作为容器的键。哈希表的基本思想是使用精心策划的哈希函数，为输入键生成唯一的索引。例如，当我们使用字符串作为哈希表键时，哈希表使用哈希函数将哈希作为底层向量的索引值：

```cpp
template <typename T>
int hash(const T& key)
{
  // generate and return and efficient
  // hash value from key based on the key's type
}

template <typename T, typename U>
void insert_into_hashtable(const T& key, const U& value)
{
  int index = hash(key);
  hash_table[index].push_back(value); // insert into the list
}
```

以下是我们如何说明哈希表：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/5623724b-8217-4b70-8fac-b52b713d8435.png)

访问哈希表需要常数时间，因为它是基于向量操作的。虽然可能会有不同的键导致相同的哈希值，但这些冲突通过使用值列表作为向量元素来解决（如前图所示）。

STL 支持名为`std::unordered_map`的哈希表：

```cpp
#include <unordered_map>
...
std::unordered_map<std::string, std::string> hashtable;
hashtable["key1"] = "value 1";
hashtable["key2"] = "value 2";
...
```

为了为提供的键生成哈希值，函数`std::unordered_map`使用`<functional>`头文件中定义的`std::hash()`函数。您可以为哈希函数指定自定义实现。`std::unordered_map`的第三个`template`参数是哈希函数，默认为`std::hash`。

# 图

二叉搜索树的平衡性是基于许多搜索索引实现的。例如，数据库系统使用称为 B 树的平衡树进行表索引。B 树不是*二叉*树，但它遵循相同的平衡逻辑，如下图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/92b32da1-8667-447b-b087-481c79ac0dc4.png)

另一方面，图表示没有适当顺序的连接节点：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/84949559-6f1a-41a6-8b34-746c60392218.png)

假设我们正在构建一个最终将击败 Facebook 的社交网络。社交网络中的用户可以互相关注，这可以表示为图。例如，如果 A 关注 B，B 关注 C，C 既关注 B 又同时关注 A，那么我们可以将关系表示为以下图：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/afd3b4ab-05ed-448a-8612-d596cce84d88.png)

在图中，一个节点被称为**顶点**。两个节点之间的链接被称为**边**。实际上并没有固定的图表示，所以我们应该从几种选择中进行选择。让我们想想我们的社交网络 - 我们如何表示用户 A 关注用户 B 的信息？

这里最好的选择之一是使用哈希表。我们可以将每个用户映射到他们关注的所有用户：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/ff9a742f-9d83-4b1d-b655-77d3f57fe938.png)

图的实现变成了混合容器：

```cpp
#include <list>
#include <unordered_map>

template <typename T>
class Graph
{
public: 
  Graph();
  ~Graph();
  // copy, move constructors and assignment operators omitted for brevity

public:
  void insert_edge(const T& source, const T& target);
  void remove_edge(const T& source, const T& target);

  bool connected(const T& source, const T& target);

private:
  std::unordered_map<T, std::list<T> > hashtable_;
};
```

为了使其成为 STL 兼容的容器，让我们为图添加一个迭代器。虽然迭代图不是一个好主意，但添加迭代器并不是一个坏主意。

# 字符串

字符串类似于向量：它们存储字符，公开迭代器，并且它们是容器。但是，它们有些不同，因为它们专门表示一种数据：字符串。下图描述了字符串**hello, C++**作为以特殊**\0**字符结尾的字符数组：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/c99154de-7f04-4bfe-8ae5-b8ba7ed23ecb.png)

特殊的**\0**字符（也称为空字符）用作字符串终止符。编译器会依次读取字符，直到遇到空字符为止。

字符串的实现方式与我们在本章开头实现向量的方式相同：

```cpp
class my_string
{
public:
 my_string();
 // code omitted for brevity

public:
 void insert(char ch);
 // code omitted for brevity

private:
 char* buffer_;
 int size_;
 int capacity_;
};
```

C++有其强大的`std::string`类，提供了一堆用于处理的函数。除了`std::string`成员函数外，`<algorithm>`中定义的算法也适用于字符串。

# 摘要

数据结构和算法在开发高效软件方面至关重要。通过理解和利用本章讨论的数据结构，您将充分利用 C++20 的功能，使程序运行更快。程序员具有强大的问题解决能力在市场上更受欢迎，这并不是秘密。首先要通过深入理解基本算法和数据结构来获得问题解决能力。正如您在本章中已经看到的，使用二分搜索算法在搜索任务中使代码运行速度比顺序搜索快得多。高效的软件节省时间并提供更好的用户体验，最终使您的软件成为现有软件的杰出替代品。

在本章中，我们讨论了基本数据结构及其区别。我们学会了根据问题分析来使用它们。例如，在需要随机查找的问题中应用链表被认为是耗时的，因为链表元素访问操作的复杂性。在这种情况下，使用动态增长的向量更合适，因为它具有常数时间的元素访问。相反，在需要在容器的前面快速插入的问题中使用向量比如列表更昂贵。

本章还介绍了算法以及衡量它们效率的方法。我们比较了几个问题，以应用更好的算法更有效地解决它们。

在下一章中，我们将讨论 C++中的函数式编程。在学习了 STL 的基本知识后，我们现在将在容器上应用函数式编程技术。

# 问题

1.  描述将元素插入动态增长的向量。

1.  在链表的前面插入元素和在向量的前面插入元素有什么区别？

1.  实现一个混合数据结构，它将元素存储在向量和列表中。对于每个操作，选择具有最快实现该操作的基础数据结构。

1.  如果我们按顺序插入 100 个元素，二叉搜索树会是什么样子呢？

1.  选择排序和插入排序算法有什么区别？

1.  实现本章描述的排序算法，即计数排序。

# 进一步阅读

有关更多信息，请参考以下资源：

+   *Jon Bentley 著的* *Programming Pearls* ，可从[`www.amazon.com/Programming-Pearls-2nd-Jon-Bentley/dp/0201657880/`](https://www.amazon.com/Programming-Pearls-2nd-Jon-Bentley/dp/0201657880/)获取。

+   *Data Abstraction and Problem Solving Using C++: Walls and Mirrors* by Frank Carrano 和 Timothy Henry，可从[`www.amazon.com/Data-Abstraction-Problem-Solving-Mirrors/dp/0134463978/`](https://www.amazon.com/Data-Abstraction-Problem-Solving-Mirrors/dp/0134463978/)获取。

+   *Cormen, Leiserson, Rivest, and Stein 著的* *Introduction to Algorithms* ，可从[`www.amazon.com/Introduction-Algorithms-3rd-MIT-Press/dp/0262033844/`](https://www.amazon.com/Introduction-Algorithms-3rd-MIT-Press/dp/0262033844/)获取。

+   *Wisnu Anggoro 著的* *C++ Data Structures and Algorithms* ，可从[`www.packtpub.com/application-development/c-data-structures-and-algorithms`](https://www.packtpub.com/application-development/c-data-structures-and-algorithms)获取。


# 第七章：函数式编程

**面向对象编程**（**OOP**）为我们提供了一种思考对象的方式，从而以类和它们的关系来表达现实世界。函数式编程是一种完全不同的编程范式，因为它允许我们专注于*功能*结构而不是代码的*物理*结构。学习和使用函数式编程有两种用途。首先，它是一种迫使你以非常不同的方式思考的新范式。解决问题需要灵活的思维。附着于单一范式的人往往对任何问题提供类似的解决方案，而大多数优雅的解决方案需要更广泛的方法。掌握函数式编程为开发人员提供了一种新的技能，帮助他们提供更好的解决方案。其次，使用函数式编程可以减少软件中的错误数量。其中最大的原因之一是函数式编程的独特方法：它将程序分解为函数，每个函数都不修改数据的状态。

在本章中，我们将讨论函数式编程的基本模块，以及范围。在 C++20 中引入的范围为我们提供了一种很好的方式，以便将算法组合起来，使它们能够处理数据集合。将算法组合起来，以便我们可以将它们顺序应用于这些数据集合，这是函数式编程的核心。这就是为什么我们在本章中还将讨论范围。

本章将涵盖以下主题：

+   函数式编程介绍

+   介绍范围库

+   纯函数

+   高阶函数

+   深入递归

+   函数式 C++中的元编程

# 技术要求

在本章的示例中，将使用 g++编译器以及`-std=c++2a`选项。

您可以在[`github.com/PacktPublishing/Expert-CPP`](https://github.com/PacktPublishing/Expert-CPP)找到本章的源文件。

# 揭示函数式编程

正如我们之前提到的，函数式编程是一种编程范式。您可以将范式视为构建程序时的一种思维方式。C++是一种多范式语言。我们可以使用它以过程范式开发程序，即通过依次执行语句来执行。在第三章《面向对象编程的细节》中，我们讨论了面向对象的方法，它涉及将复杂系统分解为相互通信的对象。另一方面，函数式编程鼓励我们将系统分解为函数而不是对象。它使用表达式而不是语句。基本上，您将某些东西作为输入，并将其传递给生成输出的函数。然后可以将其用作另一个函数的输入。这乍看起来可能很简单，但函数式编程包含了一些一开始感觉难以掌握的规则和实践。然而，当您掌握了这一点，您的大脑将解锁一种新的思维方式——函数式方式。

为了使这一点更清晰，让我们从一个示例开始，它将演示函数式编程的本质。假设我们已经获得了一个整数列表，并且需要计算其中偶数的数量。唯一的问题是有几个这样的向量。我们应该分别计算所有向量中的偶数，并将结果作为一个新向量产生，其中包含对每个输入向量的计算结果。

输入以矩阵形式提供，即向量的向量。在 C++中表达这一点的最简单方式是使用以下类型：

```cpp
std::vector<std::vector<int>>
```

我们可以通过使用类型别名来进一步简化前面的代码，如下所示：

```cpp
using IntMatrix = std::vector<std::vector<int>>;
```

以下是这个问题的一个例子。我们有一堆包含整数的向量，结果应该是一个包含偶数的计数的向量：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/6afeff6f-80a2-4fdc-a80e-d758cdcac856.png)

看一下以下函数。它以整数向量的向量（也称为矩阵）作为其参数。该函数计算偶数的数量：

```cpp
std::vector<int> count_all_evens(const IntMatrix& numbers)
{
  std::vector<int> even_numbers_count;
  for (const auto& number_line: numbers) {
    int even{0};
 for (const auto& number: number_line) {
 if (number % 2 == 0) {
 ++even;
 }
 }
 even_numbers_count.push_back(even);
  }
  return even_numbers_count;
}
```

前面的函数保留了一个单独的向量，用于存储每个向量中偶数的计数。输入以向量的形式提供，这就是为什么函数循环遍历第一个向量以检索内部向量。对于每个检索到的向量，它循环遍历并在向量中每次遇到偶数时递增计数器。在完成每个向量的循环后，最终结果被推送到包含数字列表的向量中。虽然您可能希望回到前面的示例并改进代码，但我们现在将继续并将其分解为更小的函数。首先，我们将负责计算偶数数量的代码部分移入一个单独的函数中。

让我们将其命名为`count_evens`，如下所示：

```cpp
int count_evens(const std::vector<int>& number_line) {
  return std::count_if(number_line.begin(), 
       number_line.end(), [](int num){return num % 2 == 0;});
}
```

注意我们如何应用`count_if()`算法。它接受两个迭代器，并将它们分别放在容器的开头和结尾。它还接受第三个参数，一个*一元谓词*，它对集合的每个元素进行调用。我们传递了一个 lambda 作为一元谓词。您也可以使用任何其他可调用实体，例如函数指针、`std::`函数等。

现在我们有了一个单独的计数函数，我们可以在原始的`count_all_evens()`函数中调用它。以下是 C++中函数式编程的实现：

```cpp
std::vector<int> count_all_evens(const std::vector<std::vector<int>>& numbers) {
  return numbers | std::ranges::views::transform(count_evens);
}
```

在深入研究前面的代码之前，让我们先就引起我们注意的第一件事达成一致——不是`|`运算符的奇怪用法，而是代码的简洁性。将其与我们在本节开头介绍的代码版本进行比较。它们都完成了同样的工作，但第二个——函数式的代码——更加简洁。还要注意的是，该函数不保留或更改任何状态。它没有副作用。这在函数式编程中至关重要，因为函数必须是*纯*函数。它接受一个参数，然后在不修改它的情况下对其进行处理，并返回一个新值（通常基于输入）。函数式编程的第一个挑战是将任务分解为更小的独立函数，然后轻松地将它们组合在一起。

尽管我们是从命令式的解决方案转向函数式的解决方案，但这并不是在利用函数式编程范式时的正确方式。与其首先编写命令式代码，然后修改它以获得函数式版本，不如改变您的思维方式和解决问题的方式。您应该驯服思考函数式的过程。计算所有偶数的问题导致我们解决了一个向量的问题。如果我们能找到一种方法来解决单个向量的问题，我们就能解决所有向量的问题。`count_evens()`函数接受一个向量并产生一个单个值，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/f23fba4f-7441-4785-94ef-d67480148d5e.png)

解决了一个向量的问题后，我们应该继续将解决方案应用于所有向量的原始问题。`std::transform()`函数基本上做了我们需要的事情：它接受一个可以应用于单个值的函数，并将其转换为处理集合的方式。以下图片说明了我们如何使用它来实现一个函数(`count_all_evens`)，该函数可以处理来自只处理一个项目的函数(`count_evens`)的函数的项目集合：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/9fa67593-d788-4281-a47a-f8e9a968a285.png)

将更大的问题分解为更小的、独立的任务是函数式编程的核心。每个函数都专门用于执行一个足够简单的任务，而不会意识到原始问题。然后将函数组合在一起，以从原始输入生成一系列转换后的项目。

现在，`count_all_evens()`函数的最终版本利用了范围。让我们找出它们是什么以及如何使用它们，因为我们将在后续示例中需要它们。

# 使用范围

范围与视图相关联。我们将在本节中同时研究它们。我们在第六章中讨论了 STL 容器和算法，*深入研究 STL 中的数据结构和算法*。它们为我们提供了一种通用的方法来组合和处理对象集合。正如您已经知道的那样，我们经常使用迭代器来循环遍历容器并处理它们的元素。迭代器是一种工具，允许我们在算法和容器之间实现松耦合。

例如，之前，我们对向量应用了`count_if()`，但`count_if()`不知道它被应用到了什么容器。看一下`count_if()`的以下声明：

```cpp
template <typename InputIterator, typename UnaryPredicate>
constexpr typename iterator_traits<InputIterator>::difference_type
  count_if(InputIterator first, InputIterator last, UnaryPredicate p);
```

正如您所看到的，除了其特定于 C++的冗长声明之外，`count_if()`不接受容器作为参数。相反，它使用迭代器 - 具体来说，输入迭代器。

输入迭代器支持使用`++`运算符向前迭代，并使用`*`运算符访问每个元素。我们还可以使用`==`和`!=`关系比较输入迭代器。

算法在不知道容器的确切类型的情况下迭代容器。我们可以在任何具有开始和结束的实体上使用`count_if()`，如下所示：

```cpp
#include <array>
#include <iostream>
#include <algorithm>

int main()
{
  std::array<int, 4> arr{1, 2, 3, 4};
 auto res = std::count_if(arr.cbegin(), arr.cend(), 
 [](int x){ return x == 3; });
  std::cout << "There are " << res << " number of elements equal to 3";
}
```

除了它们的通用性，算法不太容易组合。通常，我们将算法应用于一个集合，并将算法的结果存储为另一个集合，以便在以后的某个日期应用更多的算法。我们使用`std::transform()`将结果放入另一个容器中。例如，以下代码定义了一个产品的向量：

```cpp
// consider the Product is already declared and has a "name", "price", and "weight"
// also consider the get_products() is defined 
// and returns a vector of Product instances

using ProductList = std::vector<std::shared_ptr<Product>>;
ProductList vec{get_products()};
```

假设项目是由不同的程序员团队开发的，并且他们选择将产品的名称保留为任何数字；例如，1 代表苹果，2 代表桃子，依此类推。这意味着`vec`将包含`Product`实例，每个实例的`name`字段中将有一个数字字符（而名称的类型是`std::string` - 这就是为什么我们将数字保留为字符而不是其整数值）。现在，我们的任务是将产品的名称从数字转换为完整的字符串（`apple`，`peach`等）。我们可以使用`std::transform`来实现：

```cpp
ProductList full_named_products; // type alias has been defined above
using ProductPtr = std::shared_ptr<Product>;
std::transform(vec.cbegin(), vec.cend(), 
  std::back_inserter(full_named_products), 
  [](ProductPtr p){ /* modify the name and return */ });
```

执行上述代码后，`full_named_products`向量将包含具有完整产品名称的产品。现在，要过滤出所有的苹果并将它们复制到一个苹果向量中，我们需要使用`std::copy_if`：

```cpp
ProductList apples;
std::copy_if(full_named_products.cbegin(), full_named_products.cend(),
  std::back_inserter(apples), 
  [](ProductPtr p){ return p->name() == "apple"; });
```

前面代码示例的最大缺点之一是缺乏良好的组合，直到引入范围。范围为我们提供了一种优雅的方式来处理容器元素和组合算法。

简而言之，范围是一个可遍历的实体；也就是说，一个范围有一个`begin()`和一个`end()`，就像我们迄今为止使用的容器一样。在这些术语中，每个 STL 容器都可以被视为一个范围。STL 算法被重新定义为直接接受范围作为参数。通过这样做，它们允许我们将一个算法的结果直接传递给另一个算法，而不是将中间结果存储在本地变量中。例如，`std::transform`，我们之前使用`begin()`和`end()`，如果应用于一个范围，将具有以下形式（以下代码是伪代码）。通过使用范围，我们可以以以下方式重写前面的示例：

```cpp
ProductList apples = filter(
  transform(vec, [](ProductPtr p){/* normalize the name */}),
  [](ProductPtr p){return p->name() == "apple";}
);
```

不要忘记导入`<ranges>`头文件。transform 函数将返回一个包含已标准化名称的`Product`指针的范围；也就是说，数值将被替换为字符串值。filter 函数将接受结果并返回具有`apple`作为名称的产品范围。

请注意，我们通过省略 `std::ranges::views` 在 `filter` 和 `transform` 函数前面的部分来简化了这些代码示例。分别使用 `std::ranges::views::filter` 和 `std::ranges::views::transform`。

最后，我们在本章开头的示例中使用的重载运算符 `**|**` 允许我们将范围串联在一起。这样，我们可以组合算法以产生最终结果，如下所示：

```cpp
ProductList apples = vec | transform([](ProductPtr p){/* normalize the name */})
                         | filter([](ProductPtr p){return p->name() == "apple";});
```

我们使用管道而不是嵌套函数调用。这可能一开始会让人困惑，因为我们习惯将 `|` 运算符用作按位或。每当你看到它应用于集合时，它指的是管道范围。

`|` 运算符受 Unix shell 管道运算符的启发。在 Unix 中，我们可以将多个进程的结果串联在一起；例如，`ls -l | grep cpp | less` 将在 `ls` 命令的结果中查找 `cpp`，并使用 `less` 程序逐屏显示最终结果。

正如我们已经提到的，范围是对集合的抽象。这并不意味着它是一个集合。这就是为什么前面的示例没有带来任何额外开销 - 它只是从一个函数传递到另一个函数的范围，其中范围只提供了集合的开始和结束。它还允许我们访问底层集合元素。以下图解释了这个想法：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/exp-cpp/img/fa625af2-3795-4fd4-b089-5a72113aa071.png)

函数（无论是 **transform** 还是 **filter**）返回的是一个范围结构而不是一个集合。范围的 `begin()` 迭代器将指向满足谓词的源集合中的元素。范围的迭代器是一个代理对象：它与常规迭代器不同，因为它指向满足给定谓词的元素。我们有时将它们称为 **智能迭代器**，因为每次我们推进它（例如通过增量），它都会找到满足谓词的集合中的下一个元素。更有趣的是，迭代器的“智能性”取决于我们应用于集合的函数类型。例如，`filter()` 函数返回一个具有智能迭代器的范围，用于它们的增量运算符。这主要是因为过滤的结果可能包含比原始集合更少的元素。另一方面，transform 不会返回具有减少元素数量的结果 - 它只是转换元素。这意味着由 transform 返回的范围对于增量/减量操作具有相同的功能，但元素访问将不同。对于每次访问，范围的智能迭代器将从原始集合中返回转换的元素。换句话说，它只是为迭代器实现了 `*()` 运算符，类似于下面的代码片段中所示：

```cpp
auto operator*()
{
  return predicate(*current_position);
}
```

通过这种方式，我们创建了集合的新 *视图* 而不是转换元素的新集合。`filter` 和其他函数也是如此。更有趣的是，范围视图利用了 *惰性评估*。对于我们之前的示例，即使我们有两个范围转换，结果也是通过在单次遍历中评估它们来产生的。

在使用 `transform` 和 `filter` 的示例中，每个函数都定义了一个视图，但它们不会修改或评估任何内容。当我们将结果分配给结果集合时，向量是从视图中访问每个元素来构造的。这就是评估发生的地方。

就是这么简单 - 范围为我们提供了惰性评估的函数组合。我们之前简要介绍了函数式编程中使用的工具集。现在，让我们了解一下这种范式的好处。

# 为什么使用函数式编程？

首先，函数式编程引入了简洁性。与命令式对应物相比，代码要短得多。它提供了简单但高度表达的工具。当代码更少时，错误就会更少出现。

函数不会改变任何东西，这使得并行化变得更加容易。这是并发程序中的主要问题之一，因为并发任务需要在它们之间共享可变数据。大多数情况下，您必须使用诸如互斥锁之类的原语来显式同步线程。函数式编程使我们摆脱了显式同步，我们可以在多个线程上运行代码而无需进行调整。在第八章，*深入数据结构*中，我们将详细讨论数据竞争。

函数式范式将所有函数视为*纯*函数；也就是说，不会改变程序状态的函数。它们只是接受输入，以用户定义的方式进行转换，并提供输出。对于相同的输入，纯函数生成相同的结果，不受调用次数的影响。每当我们谈论函数式编程时，我们应该默认考虑所有纯函数。

以下函数以`double`作为输入，并返回其平方：

```cpp
double square(double num) { return num * num; }
```

仅编写纯函数可能会让程序运行变慢。

一些编译器，如 GCC，提供了帮助编译器优化代码的属性。例如，`[[gnu::pure]]`属性告诉编译器该函数可以被视为纯函数。这将让编译器放心，函数不会访问任何全局变量，函数的结果仅取决于其输入。

有许多情况下，*常规*函数可能会带来更快的解决方案。然而，为了适应这种范式，您应该强迫自己以函数式思维。例如，以下程序声明了一个向量，并计算了其元素的平方根：

```cpp
void calc_square_roots(std::vector<double>& vec) 
{
  for (auto& elem : vec) {
    elem = std::sqrt(elem);
  }
}

int main()
{
  std::vector<double> vec{1.1, 2.2, 4.3, 5.6, 2.4};
 calc_square_roots(vec);
}
```

在这里，我们通过引用传递向量。这意味着，如果我们在函数中对它进行更改，就会改变原始集合。显然，这不是一个纯函数，因为它改变了输入向量。函数式的替代方法是在一个新的向量中返回转换后的元素，保持输入不变：

```cpp
std::vector<double> pure_calc_square_roots(const std::vector<double>& vec)
{
 std::vector<double> new_vector;
  for (const auto& elem : vec) {
    new_vector.push_back(std::sqrt(elem));
  }
 return new_vector;
}
```

函数式思维的一个更好的例子是解决一个较小的问题，并将其应用到集合中。在这种情况下，较小的问题是计算单个数字的平方根，这已经实现为`std::sqrt`。将其应用到集合中是通过`std::ranges::views::transform`完成的，如下所示：

```cpp
#include <ranges>
#include <vector>

int main()
{
 std::vector<double> vec{1.1, 2.2, 4.3, 5.6, 2.4};
 auto result = vec | std::ranges::views::transform(std::sqrt);
}
```

正如我们已经知道的，通过使用范围，我们可以避免存储中间对象。在前面的例子中，我们直接将`transform`应用于向量。`transform`返回一个视图，而不是由源向量的转换元素组成的完整集合。当我们构造`result`向量时，实际的转换副本才会产生。另外，请注意`std::sqrt`被认为是一个纯函数。

本章开始时我们解决的例子为我们提供了函数式编程所需的视角。为了更好地掌握这种范式，我们应该熟悉它的原则。在下一节中，我们将深入探讨函数式编程的原则，以便您更好地了解何时以及如何使用这种范式。

# 函数式编程原则

尽管函数式范式很古老（诞生于 20 世纪 50 年代），但它并没有在编程世界中掀起风暴。如我们在本书和其他许多书中多次声明的那样，C++是一种**多范式语言**。这就是学习 C++的美妙之处；我们可以调整它以适应几乎每个环境。掌握这种范式并不是一件容易的事。您必须感受它并应用它，直到最终开始以这种范式思考。之后，您将能够在几秒钟内找到常规任务的解决方案。

如果您还记得第一次学习面向对象编程时，您可能会记得在能够发挥面向对象编程的真正潜力之前，您可能会有些挣扎。函数式编程也是如此。在本节中，我们将讨论函数式编程的基本概念，这将成为进一步发展的基础。您可以应用（或已经这样做）其中一些概念，而实际上并没有使用函数式范例。然而，请努力理解和应用以下每个原则。

# 纯函数

正如我们之前提到的，*如果函数不改变状态，则函数是纯的*。与非纯函数相比，纯函数可能被视为性能较差；然而，它们非常好，因为它们避免了由于状态修改而导致的代码中可能出现的大多数错误。这些错误与程序状态有关。显然，程序处理数据，因此它们组成修改状态的功能，从而为最终用户产生一些预期的结果。

在面向对象编程中，我们将程序分解为对象，每个对象都有一系列特殊功能。面向对象编程中对象的一个基本特征是其*状态*。通过向对象发送消息（换句话说，调用其方法）来修改对象的状态在面向对象编程中至关重要。通常，成员函数调用会导致对象状态的修改。在函数式编程中，我们将代码组织成一组纯函数，每个函数都有自己的目的，并且独立于其他函数。

让我们来看一个简单的例子，只是为了让这个概念清晰起来。假设我们在程序中处理用户对象，每个用户对象都包含与用户相关的年龄。`User`类型在以下代码块中被描述为`struct`：

```cpp
struct User
{
  int age;
  string name;
  string phone_number;
  string email;
};
```

有必要每年更新用户的年龄。假设我们有一个函数，每年为每个`User`对象调用一次。以下函数接受一个`User`对象作为输入，并将其`age`增加`1`：

```cpp
void update_age(User& u)
{
  u.age = u.age + 1;
}
```

`update_age()`函数通过引用接受输入并更新原始对象。这在函数式编程中并不适用。这个纯函数不是通过引用获取原始对象并改变其值，而是返回一个完全不同的`user`对象，具有相同的属性，除了更新的`age`属性：

```cpp
User pure_update_age(const User& u) // cannot modify the input argument
{
 User tmp{u};
  tmp.age = tmp.age + 1;
  return tmp;
}
```

尽管与`update_age()`相比似乎效率低下，但这种方法的优点之一是它使操作变得非常清晰（在调试代码时非常有用）。现在，可以保证`pure_update_age()`不会修改原始对象。我们可以修改前面的代码，使其按值传递对象。这样，我们将跳过创建`tmp`对象，因为参数本身就代表了一个副本：

```cpp
User pure_update_age(User u) // u is the copy of the passed object
{
  u.age = u.age + 1;
  return u;
}
```

如果一个纯函数使用相同的参数多次调用，它必须每次返回相同的结果。以下代码演示了我们的`pure_update_age()`函数在给定相同输入时返回相同的值：

```cpp
User john{.age{21}, .name{"John"}};

auto updated{pure_update_age(john)};
std::cout << updated.age; // prints 22

updated = pure_update_age(john);
std::cout << updated.age; // prints 22
```

对于一个函数来说，每次针对相同的输入数据调用时都表现相同是一个很大的好处。这意味着我们可以通过将应用程序的逻辑分解为更小的函数来设计它，每个函数都有一个确切而清晰的目的。然而，纯函数在额外临时对象方面存在开销。常规设计涉及具有包含程序状态的集中存储，该状态通过纯函数间接更新。在每次纯函数调用之后，函数将修改后的对象作为可能需要存储的新对象返回。您可以将其视为调整代码以省略传递整个对象。

# 高阶函数

在函数式编程中，函数被视为*一等*对象（你可能也会遇到一等公民）。这意味着我们应该将它们视为对象，而不是一组指令。这对我们有什么区别？嗯，在这一点上，函数被视为对象的唯一重要之处是能够将其传递给其他函数。接受其他函数作为参数的函数被称为**高阶函数**。

C++程序员将一个函数传递到另一个函数是很常见的。以下是以老式方式实现的方法：

```cpp
typedef  void (*PF)(int);
void foo(int arg) 
{
  // do something with arg
}

int bar(int arg, PF f)
{
 f(arg);
  return arg;
}

bar(42, foo);
```

在前面的代码中，我们声明了一个指向函数的指针。`PF`代表函数的类型定义，接受一个整数参数，并且不返回任何值。前面的例子是将指针函数传递给其他函数作为参数的一种常见方式。我们将函数视为对象。然而，这取决于我们对*对象*的理解。

在前面的章节中，我们将对象定义为具有状态的东西。这意味着，如果我们将函数视为对象，我们也应该能够在需要时以某种方式改变它的状态。对于函数指针来说，情况并非如此。以下是将函数传递给另一个函数的更好方法：

```cpp
class Function
{
public:
  void modify_state(int a) {
    state_ = a;
  }

  int get_state() {
    return state_;
  }

  void operator()() {
 // do something that a function would do
 }
private:
  int state_;
};

void foo(Function f)
{
 f();
  // some other useful code
}
```

看一下前面的代码。它声明了一个具有重载`operator()`的类。每当我们重载一个类的运算符时，我们使它变得*可调用*。尽管听起来很明显，但任何可调用的东西都被视为函数。因此，具有重载`operator()`的类的对象可以被视为函数（有时被称为*函数对象*）。这在某种程度上有点像一个技巧，因为我们不是将函数变成对象，而是使对象可调用。然而，这使我们能够实现我们想要的东西：具有状态的函数。以下客户端代码演示了`Function`对象具有状态：

```cpp
void foo(Function f)
{
  f();
  f.modify_state(11);
 cout << f.get_state(); // get the state
  f(); // call the "function"
}
```

通过这样做，我们可以跟踪函数被调用的次数。以下是一个跟踪调用次数的简单示例：

```cpp
class Function
{
public:
 void operator()() {    // some useful stuff ++called_; 
  }

private:
  int called_ = 0;
};
```

最后，`std::function`，它在以下代码中的`<functional>`头文件中定义，展示了另一种定义高阶函数的方法：

```cpp
#include <functional>

void print_it(int a) {
  cout << a;
}

std::function<void(int)> function_object = print_it;
```

当调用`function_object`（使用`operator()`）时，它将调用`print_it`函数。`std::function`封装了任何函数，并允许将其作为对象使用（以及将其传递给其他函数）。

在前面的例子中，接受其他函数作为参数的函数都是高阶函数的例子。返回函数的函数也被称为高阶函数。总之，高阶函数是接受或返回另一个函数或多个函数的函数。看一下以下例子：

```cpp
#include <functional>
#include <iostream>

std::function<int (int, int)> get_multiplier()
{
 return [](int a, int b) { return a * b; };
}

int main()
{
 auto multiply = get_multiplier();
  std::cout << multiply(3, 5) << std::endl; // outputs 15
}
```

`get_multiplier()`返回一个包装在`std::function`中的 lambda。然后，我们调用结果，就像调用普通函数一样。`get_multiplier()`函数是一个高阶函数。我们可以使用高阶函数来实现**柯里化**，类似于我们在前面的例子中所做的。在函数式编程中，柯里化是指我们将一个函数的多个参数转换为多个函数，每个函数只接受一个参数；例如，将`multiply(3, 5)`转换为`multiply(3)(5)`。以下是我们如何实现这一点：

```cpp
std::function<int(int)> multiply(int a)
{
 return a { return a * b; };
}

int main()
{
  std::cout << multiply(3)(5) << std::endl;
}
```

`multiply()`接受一个参数，并返回一个也接受单个参数的函数。注意 lambda 捕获：它捕获了`a`的值，以便在其主体中将其乘以`b`。

柯里化是对逻辑学家 Haskell Curry 的致敬。Haskell、Brook 和 Curry 编程语言也以他的名字命名。

柯里化最有用的特性之一是拥有我们可以组合在一起的抽象函数。我们可以创建`multiply()`的专门版本，并将它们传递给其他函数，或者在适用的地方使用它们。这可以在以下代码中看到：

```cpp
auto multiplyBy22 = multiply(22);
auto fiveTimes = multiply(5);

std::cout << multiplyBy22(10); // outputs 220
std::cout << fiveTimes(4); // outputs 20
```

在使用 STL 时，您一定会使用高阶函数。许多 STL 算法使用谓词来过滤或处理对象集合。例如，`std::find_if`函数找到满足传递的谓词对象的元素，如下例所示：

```cpp
std::vector<int> elems{1, 2, 3, 4, 5, 6};
std::find_if(elems.begin(), elems.end(), [](int el) {return el % 3 == 0;});
```

`std::find_if`以 lambda 作为其谓词，并对向量中的所有元素调用它。满足条件的任何元素都将作为请求的元素返回。

另一个高阶函数的例子是`std::transform`，我们在本章开头介绍过（不要与`ranges::view::transform`混淆）。让我们使用它将字符串转换为大写字母：

```cpp
std::string str = "lowercase";
std::transform(str.begin(), str.end(), str.begin(), 
  [](unsigned char c) { return std::toupper(c); });
std::cout << str; // "LOWERCASE"
```

第三个参数是容器的开始，是`std::transform`函数插入其当前结果的位置。

# 折叠

折叠（或减少）是将一组值组合在一起以生成减少数量的结果的过程。大多数情况下，我们说的是单个结果。折叠抽象了迭代具有递归性质的结构的过程。例如，链表或向量在元素访问方面具有递归性质。虽然向量的递归性质是有争议的，但我们将考虑它是递归的，因为它允许我们通过重复增加索引来访问其元素。为了处理这样的结构，我们通常在每一步中跟踪结果，并处理稍后要与先前结果组合的下一个项目。根据我们处理集合元素的方向，折叠称为*左*或*右*折叠。

例如，`std::accumulate`函数（另一个高阶函数的例子）是折叠功能的完美例子，因为它结合了集合中的值。看一个简单的例子：

```cpp
std::vector<double> elems{1.1, 2.2, 3.3, 4.4, 5.5};
auto sum = std::accumulate(elems.begin(), elems.end(), 0);
```

函数的最后一个参数是累加器。这是应该用作集合的第一个元素的先前值的初始值。前面的代码计算了向量元素的和。这是`std::accumulate`函数的默认行为。正如我们之前提到的，它是一个高阶函数，这意味着可以将一个函数作为其参数传递。然后将为每个元素调用该函数以产生所需的结果。例如，让我们找到先前声明的`elems`向量的乘积：

```cpp
auto product = std::accumulate(elems.begin(), elems.end(), 1, 
  [](int prev, int cur) { return prev * cur; });
```

它采用二进制操作；也就是说，具有两个参数的函数。操作的第一个参数是到目前为止已经计算的先前值，而第二个参数是当前值。二进制操作的结果将是下一步的先前值。可以使用 STL 中的现有操作之一简洁地重写前面的代码：

```cpp
auto product = std::accumulate(elems.begin(), elems.end(), 1, 
 std::multiplies<int>());
```

`std::accumulate`函数的更好替代品是`std::reduce`函数。`reduce()`类似于`accumulate()`，只是它不保留操作的顺序；也就是说，它不一定按顺序处理集合元素。您可以向`std::reduce`函数传递执行策略并更改其行为，例如并行处理元素。以下是如何使用并行执行策略将 reduce 函数应用于先前示例中的`elems`向量：

```cpp
std::reduce(std::execution::par, elems.begin(), elems.end(), 
  1, std::multiplies<int>());
```

尽管`std::reduce`与`std::accumulate`相比似乎更快，但在使用非交换二进制操作时，您应该小心。

折叠和递归是相辅相成的。递归函数也通过将问题分解为较小的任务并逐个解决它们来解决问题。

# 深入递归

我们已经在第二章 *使用 C++进行低级编程*中讨论了递归函数的主要特点。让我们来看一个简单的递归计算阶乘的例子：

```cpp
int factorial(int n)
{
  if (n <= 1) return 1;
  return n * factorial(n - 1);
}
```

递归函数相对于它们的迭代对应物提供了优雅的解决方案。然而，你应该谨慎地考虑使用递归的决定。递归函数最常见的问题之一是堆栈溢出。

# 头递归

头递归是我们已经熟悉的常规递归。在前面的例子中，阶乘函数表现为头递归函数，意味着在处理当前步骤的结果之前进行递归调用。看一下阶乘函数中的以下一行：

```cpp
...
return n * factorial(n - 1);
...
```

为了找到并返回乘积的结果，函数阶乘以减小的参数（即`(n - 1)`）被调用。这意味着乘积（`*`运算符）有点像*暂停*，正在等待它的第二个参数由`factorial(n - 1)`返回。堆栈随着对函数的递归调用次数的增加而增长。让我们尝试将递归阶乘实现与以下迭代方法进行比较：

```cpp
int factorial(int n) 
{
  int result = 1;
  for (int ix = n; ix > 1; --ix) {
    result *= ix;
  }
  return result;
}
```

这里的一个主要区别是我们在相同的变量（名为`result`）中存储了每一步的乘积的结果。有了这个想法，让我们试着分解阶乘函数的递归实现。

很明显，每个函数调用在堆栈上占据了指定的空间。每一步的结果都应该存储在堆栈的某个地方。尽管我们知道应该，甚至必须是相同的变量，但递归函数并不在乎；它为它的变量分配空间。常规递归函数的反直觉性促使我们寻找一个解决方案，以某种方式知道每次递归调用的结果应该存储在同一个地方。

# 尾递归

尾递归是解决递归函数中存在多个不必要变量的问题的方法。尾递归函数的基本思想是在递归调用之前进行实际处理。以下是我们如何将阶乘函数转换为尾递归函数：

```cpp
int tail_factorial(int n, int result)
{
  if (n <= 1) return result;
  return tail_factorial(n - 1, n * result);
}
```

注意函数的新参数。仔细阅读前面的代码给了我们尾递归正在发生的基本概念：在递归调用之前进行处理。在`tail_factorial`再次在其主体中被调用之前，当前结果被计算（`n * result`）并传递给它。

虽然这个想法可能看起来并不吸引人，但如果编译器支持**尾调用优化（TCO）**，它确实非常高效。TCO 基本上涉及知道阶乘函数的第二个参数（尾部）可以在每次递归调用时存储在相同的位置。这允许堆栈保持相同的大小，独立于递归调用的次数。

说到编译器优化，我们不能忽略模板元编程。我们将它与编译器优化一起提到，因为我们可以将元编程视为可以对程序进行的最大优化。在编译时进行计算总是比在运行时更好。

# 函数式 C++中的元编程

元编程可以被视为另一种编程范式。这是一种完全不同的编码方法，因为我们不再处理常规的编程过程。通过常规过程，我们指的是程序在其生命周期中经历的三个阶段：编码、编译和运行。显然，当程序被执行时，它会按照预期的方式执行。通过编译和链接，编译器生成可执行文件。另一方面，元编程是代码在编译代码期间被*执行*的地方。如果你第一次接触这个，这可能听起来有点神奇。如果程序甚至还不存在，我们怎么能执行代码呢？回想一下我们在第四章中学到的关于模板的知识，*理解和设计模板*，我们知道编译器会对模板进行多次处理。在第一次通过中，编译器定义了模板类或函数中使用的必要类型和参数。在下一次通过中，编译器开始以我们熟悉的方式编译它们；也就是说，它生成一些代码，这些代码将由链接器链接以生成最终的可执行文件。

由于元编程是在代码编译期间发生的事情，我们应该已经对所使用的语言的概念和结构有所了解。任何可以在编译时计算的东西都可以用作元编程构造，比如模板。

以下是 C++中经典的令人惊叹的元编程示例：

```cpp
template <int N>
struct MetaFactorial
{
  enum {
    value = N * MetaFactorial<N - 1>::value
  };
};

template <>
struct MetaFactorial<0>
{
  enum {
    value = 1
  };
};

int main() {
  std::cout << MetaFactorial<5>::value; // outputs 120
  std::cout << MetaFactorial<6>::value; // outputs 720
}
```

为什么我们要写这么多代码来计算阶乘，而在上一节中我们只用不到五行的代码就写出了？原因在于它的效率。虽然编译代码需要花费一点时间，但与普通的阶乘函数（递归或迭代实现）相比，它的效率非常高。这种效率的原因在于阶乘的实际计算是在编译时发生的。也就是说，当可执行文件运行时，结果已经准备好了。我们只是在运行程序时使用了计算出的值；运行时不会发生计算。如果你是第一次看到这段代码，下面的解释会让你爱上元编程。

让我们详细分解和分析前面的代码。首先，`MetaFactorial` 模板声明为带有单个 `value` 属性的 `enum`。之所以选择这个 `enum`，仅仅是因为它的属性是在编译时计算的。因此，每当我们访问 `MetaFactorial` 的 value 属性时，它已经在编译时被计算（评估）了。看一下枚举的实际值。它从相同的 `MetaFactorial` 类中进行了递归依赖：

```cpp
template <int N>
struct MetaFactorial
{
  enum {
 value = N * MetaFactorial<N - 1>::value
 };
};
```

你们中的一些人可能已经注意到了这里的技巧。`MetaFactorial<N - 1>` 不是与 `MetaFactorial<N>` 相同的结构。尽管它们有相同的名称，但每个具有不同类型或值的模板都会生成一个单独的新类型。因此，假设我们调用类似以下的内容：

```cpp
std::cout << MetaFactorial<3>::value;
```

在这里，勤奋的编译器为每个值生成了三个不同的结构（以下是一些伪代码，表示我们应该如何想象编译器的工作）：

```cpp
struct MetaFactorial<3>
{
  enum {
    value = 3 * MetaFactorial<2>::value
  };
};

struct MetaFactorial<2>
{
  enum {
    value = 2 * MetaFactorial<1>::value;
  };
};

struct MetaFactorial<1>
{
  enum {
    value = 1 * MetaFactorial<0>::value;
  };
};
```

在下一次通过中，编译器将用其相应的数值替换生成的结构的每个值，如下伪代码所示：

```cpp
struct MetaFactorial<3>
{
  enum {
   value = 3 * 2
  };
};

struct MetaFactorial<2>
{
  enum {
    value = 2 * 1
  };
};

struct MetaFactorial<1>
{
  enum {
    value = 1 * 1
  };
};

```

然后，编译器删除未使用的生成的结构，只留下 `MetaFactorial<3>`，再次只用作 `MetaFactorial<3>::value`。这也可以进行优化。通过这样做，我们得到以下结果：

```cpp
std::cout << 6;
```

将此与我们之前的一行进行比较：

```cpp
std::cout << MetaFactorial<3>::value;
```

这就是元编程的美妙之处——它是在编译时完成的，不留痕迹，就像忍者一样。编译时间会更长，但程序的执行速度是可能的情况下最快的，与常规解决方案相比。我们建议您尝试实现其他成本昂贵的计算的元版本，比如计算第 n 个斐波那契数。这并不像为*运行时*而不是*编译时*编写代码那么容易，但您已经感受到了它的力量。

# 总结

在这一章中，我们对使用 C++有了新的视角。作为一种多范式语言，它可以被用作函数式编程语言。

我们学习了函数式编程的主要原则，比如纯函数、高阶函数和折叠。纯函数是不会改变状态的函数。纯函数的优点之一是它们留下的错误较少，否则会因为状态的改变而引入错误。

高阶函数是接受或返回其他函数的函数。除了在函数式编程中，C++程序员在处理 STL 时也使用高阶函数。

纯函数以及高阶函数使我们能够将整个应用程序分解为一系列函数的*装配线*。这个装配线中的每个函数负责接收数据并返回原始数据的新修改版本（而不是改变原始状态）。当结合在一起时，这些函数提供了一个良好协调的任务线。

在下一章中，我们将深入探讨多线程编程，并讨论在 C++中引入的线程支持库组件。

# 问题

1.  列出范围的优势。

1.  哪些函数被认为是纯函数？

1.  在函数式编程方面，纯虚函数和纯函数之间有什么区别？

1.  什么是折叠？

1.  尾递归相对于头递归的优势是什么？

# 进一步阅读

有关本章涵盖内容的更多信息，请查看以下链接：

+   *学习 C++函数式编程* 作者 Wisnu Anggoro：[`www.packtpub.com/application-development/learning-c-functional-programming`](https://www.packtpub.com/application-development/learning-c-functional-programming)

+   *在 C++中的函数式编程：如何利用函数式技术改进您的 C++程序* 作者伊万·库奇克（Ivan Cukic）：[`www.amazon.com/Functional-Programming-programs-functional-techniques/dp/1617293814/`](https://www.amazon.com/Functional-Programming-programs-functional-techniques/dp/1617293814/)
