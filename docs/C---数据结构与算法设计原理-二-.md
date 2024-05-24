# C++ 数据结构与算法设计原理（二）

> 原文：[`annas-archive.org/md5/89b76b51877d088e41b92eef0985a12b`](https://annas-archive.org/md5/89b76b51877d088e41b92eef0985a12b)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第三章：哈希表和布隆过滤器

## 学习目标

在本章结束时，您将能够：

+   在任何大型应用程序中轻松识别与查找相关的问题

+   评估问题是否适合确定性或非确定性查找解决方案

+   基于场景实现高效的查找解决方案

+   在大型应用程序中实现 C++ STL 提供的通用解决方案

在本章中，我们将研究快速查找的问题。我们将了解解决此问题的各种方法，并了解哪种方法可以用于特定情况。

## 介绍

查找只是检查元素是否存在于容器中或在容器中查找键的相应值。在我们在前几章中提到的学生数据库系统和医院管理系统示例中，一个常见的操作是从系统中存储的大量数据中获取特定记录。在从字典中获取单词的含义，根据一组记录（访问控制）检查某人是否被允许进入某个设施等许多应用程序中也会出现类似的问题。

对于大多数情况，线性遍历所有元素并匹配值将非常耗时，特别是考虑到存储的大量记录。让我们以在字典中查找单词为例。英语词典中大约有 17 万个单词。最简单的方法之一是线性遍历字典，并将给定的单词与字典中的所有单词进行比较，直到找到单词或者到达字典的末尾。但这太慢了，它的时间复杂度为*O(n)*，其中 n 是字典中的单词数，这不仅庞大而且每天都在增加。

因此，我们需要更高效的算法来实现更快的查找。在本章中，我们将看一些高效的结构，即哈希表和布隆过滤器。我们将实现它们并比较它们的优缺点。

## 哈希表

让我们来看看在字典中搜索的基本问题。牛津英语词典中大约有 17 万个单词。正如我们在介绍中提到的，线性搜索将花费*O(n)*的时间，其中*n*是单词的数量。存储数据的更好方法是将其存储在具有类似 BST 属性的高度平衡树中。这使得它比线性搜索快得多，因为它的时间复杂度仅为*O(log n)*。但对于需要大量此类查询的应用程序来说，这仍然不是足够好的改进。想想在包含数百万甚至数十亿条记录的数据中查找所需的时间，比如神经科学数据或遗传数据。在这些情况下，我们需要更快的东西，比如**哈希表**。

哈希表的一个重要部分是**哈希**。其背后的想法是用可能唯一的键表示每个值，然后稍后使用相同的键来检查键的存在或检索相应的值，具体取决于使用情况。从给定数据派生唯一键的函数称为哈希函数。让我们看看如何通过一些示例存储和检索数据，并让我们了解为什么我们需要这样的函数。

### 哈希

在跳入哈希之前，让我们举一个简单的例子。假设我们有一个存储整数的容器，并且我们想尽快知道特定整数是否是容器的一部分。最简单的方法是使用一个布尔数组，其中每个位表示与其索引相同的值。当我们想要插入一个元素时，我们将设置与该元素对应的布尔值为*0*。要插入*x*，我们只需设置*data[x] = true*。检查特定整数*x*是否在容器内同样简单——我们只需检查*data[x]*是否为*true*。因此，我们的插入、删除和搜索函数变为*O(1)*。存储从*0*到*9*编号的整数的简单哈希表如下所示：

![图 3.1：一个简单的哈希表](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_01.jpg)

###### 图 3.1：一个简单的哈希表

然而，这种方法存在一些问题：

+   如果数据是浮点数呢？

+   如果数据不仅仅是一个数字呢？

+   如果数据的范围太高怎么办？也就是说，如果我们有十亿个数字，那么我们需要一个大小为十亿的布尔数组，这并不总是可行的。

为了解决这个问题，我们可以实现一个函数，将任何数据类型的任何值映射到所需范围内的整数。我们可以选择范围，使其布尔数组的大小可行。这个函数被称为**哈希函数**，正如我们在前一节中提到的。它将一个数据元素作为输入，并在提供的范围内提供相应的输出整数。

对于大范围内的整数，最简单的哈希函数是模函数（用*%*表示），它将元素除以指定的整数（*n*）并返回余数。因此，我们将简单地有一个大小为*n*的数组。

如果我们想要插入一个给定的值*x*，我们可以对其应用模函数（*x % n*），并且我们将始终得到一个在*0*和（*n – 1*）之间的值，两者都包括在内。现在，*x*可以插入到位置*（x % n）*。这里，通过应用哈希函数获得的数字称为**哈希值**。

我们可能会遇到的一个主要问题是，两个元素可能具有相同的模函数输出。一个例子是（*9 % 7*）和（*16 % 7*），它们都得到哈希值*2*。因此，如果对应于*2*的槽位为*TRUE*（或布尔值为*1*），我们将不知道我们的容器中存在*2*、*9*、*16*或任何返回*x % 7 = 2*的其他整数。这个问题被称为冲突，因为多个键具有相同的值而不是唯一值，而不是应用哈希函数后的唯一值。

如果我们在哈希表中存储实际值而不是布尔整数，我们将知道我们有哪个值，但我们仍然无法存储具有相同哈希值的多个值。我们将在下一节中看看如何处理这个问题。但首先，让我们看看在下一个练习中为一堆整数实现基本字典的实现。

### 练习 13：整数的基本字典

在这个练习中，我们将实现一个无符号整数的基本版本的哈希映射。让我们开始吧：

1.  首先，让我们包括所需的头文件：

```cpp
#include <iostream>
#include <vector>
```

1.  现在，让我们添加`hash_map`类。我们将别名`unsigned int`以避免编写一个很长的名称：

```cpp
using uint = unsigned int;
class hash_map
{
    std::vector<int> data;
```

1.  现在，让我们为此添加一个构造函数，它将接受数据或哈希映射的大小：

```cpp
public:
hash_map(size_t n)
{
    data = std::vector<int>(n, -1);
}
```

如图所示，我们使用“-1”来表示元素的缺失。这是我们作为数据使用的唯一负值。

1.  让我们添加`insert`函数：

```cpp
void insert(uint value)
{
    int n = data.size();
    data[value % n] = value;
    std::cout << "Inserted " << value << std::endl;
}
```

正如我们所看到的，我们并没有真正检查是否已经存在具有相同哈希值的值。我们只是覆盖了已经存在的任何值。因此，对于给定的哈希值，只有最新插入的值将被存储。

1.  让我们编写一个查找函数，看看元素是否存在于映射中：

```cpp
bool find(uint value)
{
    int n = data.size();
    return (data[value % n] == value);
}
```

我们将简单地检查值是否存在于根据哈希值计算的索引处。

1.  让我们实现一个`remove`函数：

```cpp
void erase(uint value)
{
    int n = data.size();
    if(data[value % n] == value)
    {
data[value % n] = -1;
        std::cout << "Removed " << value << std::endl;
}
}
};
```

1.  让我们在`main`中编写一个小的 lambda 函数来打印查找的状态：

```cpp
int main()
{
    hash_map map(7);
    auto print = &
        {
            if(map.find(value))
                std::cout << value << " found in the hash map";
            else
                std::cout << value << " NOT found in the hash map";
            std::cout << std::endl;
        };
```

1.  让我们在地图上使用`insert`和`erase`函数：

```cpp
    map.insert(2);
    map.insert(25);
    map.insert(290);
    print(25);
    print(100);
    map.insert(100);
    print(100);
    map.erase(25);
}
```

1.  这是程序的输出：

```cpp
Inserted 2
Inserted 25
Inserted 290
25 found in the hash map
100 NOT found in the hash map
Inserted 100
100 found in the hash map
Removed 25
```

正如我们所看到的，我们能够找到我们之前插入的大多数值，如预期的那样，除了最后一种情况，其中`100`被`0`覆盖，因为它们具有相同的哈希值。这被称为碰撞，正如我们之前所描述的。在接下来的章节中，我们将看到如何避免这种问题，使我们的结果更准确。

以下图示说明了上一个练习中的不同函数，这应该更清楚：

![图 3.2：哈希表中的基本操作](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_02.jpg)

###### 图 3.2：哈希表中的基本操作

![图 3.3：哈希表中的基本操作（续）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_03.jpg)

###### 图 3.3：哈希表中的基本操作（续）

正如前面的图所示，我们无法插入具有相同哈希值的两个元素；我们必须放弃其中一个。

现在，正如我们之前提到的，哈希表的一个主要用途是找到与键对应的值，而不仅仅是检查键是否存在。这可以通过存储键值对而不仅仅是数据中的键来简单实现。因此，我们的插入、删除和查找函数仍将根据我们的键计算哈希值，但一旦我们在数组中找到位置，我们的值将作为对的第二个参数。

## 哈希表中的碰撞

在前面的章节中，我们看到了哈希表如何帮助我们以一种便于查找任何所需键的方式存储大量键。然而，我们也遇到了一个问题，即多个键具有相同的哈希值，也称为**碰撞**。在*练习 13*中，*整数的基本字典*，我们通过简单地重写键并保留与给定哈希值对应的最新键来处理了这个问题。然而，这并不允许我们存储所有的键。在接下来的子主题中，我们将看一下几种方法，这些方法可以帮助我们克服这个问题，并允许我们在哈希表中保留所有的键值。

### 闭合寻址 - 链接

到目前为止，我们只为任何哈希值存储了一个单一元素。如果我们已经有一个特定哈希值的元素，我们除了丢弃新值或旧值之外别无选择。`push_back`方法（用于新元素）是为了能够快速从任何位置删除元素。让我们在下一个练习中实现这一点。

### 练习 14：使用链表的哈希表

在这个练习中，我们将实现一个哈希表，并使用链接来处理碰撞。让我们开始吧：

1.  首先，让我们包括所需的头文件：

```cpp
#include <iostream>
#include <vector>
#include <list>
#include <algorithm>
```

1.  现在，让我们添加`hash_map`类。我们将别名`unsigned int`以避免编写一个很长的名称：

```cpp
using uint = unsigned int;
class hash_map
{
    std::vector<std::list<int>> data;
```

1.  现在，让我们为`hash_map`添加一个构造函数，该构造函数将接受数据或哈希映射的大小：

```cpp
public:
hash_map(size_t n)
{
    data.resize(n);
}
```

1.  让我们添加一个`insert`函数：

```cpp
void insert(uint value)
{
    int n = data.size();
    data[value % n].push_back(value);
    std::cout << "Inserted " << value << std::endl;
}
```

正如我们所看到的，我们总是在数据中插入值。一个替代方法是搜索该值，并仅在该值不存在时插入。

1.  让我们编写查找函数，以查看地图中是否存在元素：

```cpp
bool find(uint value)
{
    int n = data.size();
    auto& entries = data[value % n];
    return std::find(entries.begin(), entries.end(), value) != entries.end();
}
```

正如我们所看到的，我们的查找似乎比传统方法更快，但不像之前那样快。这是因为现在它也依赖于数据，以及`n`的值。在这个练习之后，我们将再次回到这一点。

1.  让我们实现一个函数来删除元素：

```cpp
void erase(uint value)
{
    int n = data.size();
    auto& entries = data[value % n];
    auto iter = std::find(entries.begin(), entries.end(), value);

    if(iter != entries.end())
    {
entries.erase(iter);
        std::cout << "Removed " << value << std::endl;
}
}
};
```

1.  让我们编写与上一个练习中相同的`main`函数，并查看其中的区别：

```cpp
int main()
{
    hash_map map(7);
    auto print = &
        {
            if(map.find(value))
                std::cout << value << " found in the hash map";
            else
                std::cout << value << " NOT found in the hash map";
            std::cout << std::endl;
        };
```

1.  让我们在`map`上使用`insert`和`erase`函数：

```cpp
    map.insert(2);
    map.insert(25);
    map.insert(290);
    map.insert(100);
    map.insert(55);
    print(100);
    map.erase(2);
}
```

这是我们程序的输出：

```cpp
Inserted 2
Inserted 25
Inserted 290
Inserted 100
Inserted 55
100 found in the hash map
Removed 2
```

正如我们所看到的，值没有被覆盖，因为我们可以在列表中存储任意数量的值。因此，我们的输出是完全准确和可靠的。

以下图片说明了如何在数据集上执行不同的操作：

![图 3.4：哈希表上的基本操作（链接）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_04.jpg)

###### 图 3.4：使用链接的哈希表的基本操作

![图 3.5：使用链接的哈希表的基本操作（续）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_05.jpg)

###### 图 3.5：使用链接的哈希表的基本操作（续）

正如我们所看到的，我们将具有相同哈希值的元素附加到节点中的列表中，而不是单个元素。

现在，让我们考虑这些操作的时间复杂度。正如我们所看到的，插入函数仍然是*O(1)*。虽然`push_back`可能比仅设置一个值慢一些，但并不显著慢。考虑到这种方法解决的问题，这是一个小代价。但查找和删除可能会显著慢一些，这取决于我们的哈希表大小和数据集。例如，如果所有的键都具有相同的哈希值，搜索所需的时间将是 O(n)，因为它将简单地成为链表中的线性搜索。

如果哈希表与要存储的键的数量相比非常小，将会有很多碰撞，并且平均而言列表会更长。另一方面，如果我们保留一个非常大的哈希表，可能会最终产生非常稀疏的数据，并最终浪费内存。因此，哈希表的大小应该根据应用程序的上下文和情景进行优化。我们也可以在数学上定义这些事情。

**负载因子**表示哈希表中每个列表中存在的平均键的数量。它可以使用以下公式计算：

![图 3.6：负载因子](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_06.jpg)

###### 图 3.6：负载因子

如果键的数量等于我们的哈希表大小，负载因子将是*1*。这是一个理想的情况；我们将接近*O(1)*的所有操作，并且所有的空间将被充分利用。

如果值小于*1*，这意味着我们甚至没有在每个列表中存储一个键（假设我们希望在每个索引处都有一个列表），实际上浪费了一些空间。

如果值大于*1*，这意味着我们的列表的平均长度大于 1，因此我们的查找和删除函数在平均情况下会慢一些。

负载因子的值可以在任何时候以*O(1)*的时间计算。一些高级的哈希表实现利用这个值来修改哈希函数（也称为重新散列），如果该值跨过 1 的某些阈值。哈希函数被修改，以使负载因子更接近 1。然后，哈希表的大小可以根据我们的负载因子进行更新，并根据更新后的哈希函数重新分配值。重新散列是一个昂贵的操作，因此不应该太频繁地执行。但是，如果应用了适当的策略，我们可以在平均时间复杂度方面取得非常好的结果。

然而，负载因子并不是决定这种技术性能的唯一因素。考虑以下情景：我们有一个大小为*7*的哈希表，它有七个元素。然而，它们全部具有相同的哈希值，因此全部存在于一个单独的桶中。因此，搜索将始终需要*O(n)*的时间，而不是*O(1)*的时间。然而，负载因子将是 1，这是一个绝对理想的值。在这里，实际的问题是哈希函数。哈希函数应该被设计成以尽可能均匀地分布不同的键到所有可能的索引中。基本上，最小桶大小和最大桶大小之间的差异不应该太大（在这种情况下是七）。如果哈希函数被设计成所有七个元素都获得不同的哈希值，那么所有的搜索函数调用将导致*O(1)*的复杂度和即时结果。这是因为最小和最大桶大小之间的差异将为*0*。然而，这通常不是哈希表实现中所做的。它应该由哈希函数本身来处理，因为哈希表不依赖于哈希函数的实现。

### 开放寻址

解决碰撞的另一种方法是**开放寻址**。在这种方法中，我们将所有元素存储在哈希表中，而不是将元素链接到哈希表。因此，为了容纳所有元素，哈希表的大小必须大于元素的数量。其思想是探测特定哈希值对应的单元格是否已被占用。我们可以通过多种方式来探测值，我们将在以下子主题中看到。

**线性探测**

这是一种简单的探测技术。如果在特定哈希值处发生碰撞，我们可以简单地查看后续的哈希值，找到一个空单元并在找到空间后插入我们的元素。如果*hash(x)*处的单元格已满，则需要检查*hash(x + 1)*处的单元格是否为空。如果它也已满，再看*hash(x + 2)*，依此类推。

以下图示了线性探测的工作原理：

![图 3.7：使用线性探测的哈希表上的基本操作](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_07.jpg)

###### 图 3.7：使用线性探测的哈希表上的基本操作

![图 3.8：哈希表填满后无法插入元素](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_08.jpg)

###### 图 3.8：哈希表填满后无法插入元素

正如我们所看到的，如果与其哈希值对应的位置已被占用，我们会将元素插入到下一个可用的插槽中。在插入了前三个元素后，我们可以看到它们聚集在一起。如果在相同范围内插入更多元素，它们都将连续地放在聚集的末尾，从而使聚集增长。现在，当我们尝试搜索一个不在哈希函数计算的位置上，但在一个大聚集的末尾的值时，我们必须线性搜索整个聚集中的所有键。因此，搜索变得极其缓慢。

因此，如果数据密集聚集，我们会遇到一个主要问题。我们可以说数据密集聚集，如果数据分布方式是某些组围绕着非常高频率的值。例如，假设在大小为 100 的哈希表中有很多哈希值为 3 到 7 的键。所有键将在此范围内连续探测到一些值，这将极大地减慢我们的搜索速度。

**二次探测**

正如我们所看到的，线性探测的主要问题是聚集。其原因是在碰撞的情况下我们是线性探测的。这个问题可以通过使用二次方程而不是线性方程来解决。这就是二次探测提供的。

首先，我们尝试将值*x*插入到位置*hash(x)*。如果该位置已被占用，我们继续到位置*hash(x + 1**2**)*，然后*hash(x + 2**2**)*，依此类推。因此，我们以二次方式增加偏移量，从而降低了创建小数据集的概率。

这两种探测技术还有一个优势 - 元素的位置可能会受到没有相同哈希值的其他元素的影响。因此，即使只有一个具有特定哈希值的键，也可能会因为该位置存在其他元素而发生碰撞，而这在链接中是不会发生的。例如，在线性探测中，如果我们有两个哈希值为 4 的键，其中一个将被插入到位置 4，另一个将被插入到位置 5。接下来，如果我们需要插入一个哈希值为 5 的键，它将需要插入到 6。即使它与任何其他键的哈希值不同，这个键也受到了影响。

### 完美哈希 - 布谷鸟哈希

正如标题所示，**布谷鸟哈希**是完美哈希技术之一。我们之前提到的方法在最坏情况下不能保证*O(1)*的时间复杂度，但是如果正确实现，布谷鸟哈希可以实现这一点。

在布谷鸟哈希中，我们保持两个相同大小的哈希表，每个哈希表都有自己独特的哈希函数。任何元素都可以存在于任一哈希表中，并且其位置基于相应的哈希函数。

布谷鸟哈希与我们以前的哈希技术有两种主要不同之处：

+   任何元素都可以存在于两个哈希表中的任何一个。

+   任何元素都可以在将来移动到另一个位置，即使在插入后。

以前的哈希技术在插入后不允许元素移动，除非我们进行完全的重新哈希，但布谷鸟哈希不是这样，因为任何元素都可以有两个可能的位置。我们仍然可以通过增加任何元素的可能位置的数量来增加程度，以便获得更好的结果并减少频繁的重新哈希。然而，在本章中，我们只会看两个可能位置（哈希表）的版本，因为这样更容易理解。

对于查找，我们只需要查看两个位置来确定元素是否存在。因此，查找总是需要 *O(1)* 的时间。

然而，插入函数可能需要更长的时间。在这种情况下，插入函数首先检查是否可能将新元素（比如 *A*）插入第一个哈希表中。如果可以，它就在那里插入元素，然后完成。但是，如果该位置被现有元素（比如 *B*）占据，我们仍然继续插入 *A* 并将 *B* 移动到第二个哈希表中。如果第二个哈希表中的新位置也被占据（比如元素 *C*），我们再次在那里插入 *B* 并将 *C* 移动到第一个表中。我们可以递归地进行这个过程，直到我们能够为所有元素找到空槽。这个过程在下图中有所说明：

![图 3.9：布谷鸟哈希](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_09.jpg)

###### 图 3.9：布谷鸟哈希

一个主要问题是我们可能会陷入循环，递归可能导致无限循环。对于前面段落中的例子，考虑我们希望插入 *C* 的元素 *D*，但如果我们尝试移动 *D*，它会到达 *A* 的位置。因此，我们陷入了无限循环。下图应该帮助您可视化这一点：

![图 3.10：布谷鸟哈希中形成的循环](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_10.jpg)

###### 图 3.10：布谷鸟哈希中形成的循环

为了解决这个问题，一旦我们确定了循环，我们需要使用新的哈希函数重新对所有内容进行哈希。使用新哈希函数创建的哈希表可能仍然存在相同的问题，因此我们可能需要重新哈希并尝试不同的哈希函数。然而，通过聪明的策略和明智选择的哈希函数，我们可以以高概率实现摊销 *O(1)* 的性能。

就像开放寻址一样，我们不能存储比哈希表的总大小更多的元素。为了确保良好的性能，我们应该确保负载因子小于 50%，也就是说，元素的数量应该小于可用容量的一半。

我们将在下一个练习中看一下布谷鸟哈希的实现。

### 练习 15：布谷鸟哈希

在这个练习中，我们将实现布谷鸟哈希来创建一个哈希表，并在其中插入各种元素。我们还将获得操作进行的跟踪，这将允许我们查看插入是如何工作的。让我们开始吧：

1.  让我们像往常一样包括所需的头文件：

```cpp
#include <iostream>
#include <vector>
```

1.  让我们为哈希映射添加一个类。这次我们也将单独存储大小：

```cpp
class hash_map
{
    std::vector<int> data1;
    std::vector<int> data2;
    int size;
```

正如我们所看到的，我们使用了两个表。

1.  现在，让我们添加相应的哈希函数：

```cpp
int hash1(int key) const
{
    return key % size;
}
int hash2(int key) const
{
    return (key / size) % size;
}
```

在这里，我们将两个函数都保持得非常简单，但这些函数可以根据需求进行调整。

1.  现在，让我们添加一个构造函数，用于设置我们的数据进行初始化：

```cpp
public:
hash_map(int n) : size(n)
{
    data1 = std::vector<int>(size, -1);
    data2 = std::vector<int>(size, -1);
}
```

正如我们所看到的，我们只是将两个数据表都初始化为空（用 `–1` 表示）。

1.  让我们首先编写一个 `lookup` 函数：

```cpp
std::vector<int>::iterator lookup(int key)
{
    auto hash_value1 = hash1(key);
    if(data1[hash_value1] == key)
    {
        std::cout << "Found " << key << " in first table" << std::endl;
        return data1.begin() + hash_value1;
    }
    auto hash_value2 = hash2(key);
    if(data2[hash_value2] == key)
    {
        std::cout << "Found " << key << " in second table" << std::endl;
        return data2.begin() + hash_value2;
    }
    return data2.end();
}
```

我们试图在两个表中找到键，并在找到时返回相关的迭代器。我们并不总是需要迭代器，但我们将在删除函数中使用它以简化事情。如果未找到元素，我们将返回`data2`表的末尾。正如我们所看到的，查找将具有*O(1)*的时间复杂度，并且将被执行得非常快速。

1.  让我们实现一个删除函数：

```cpp
void erase(int key)
{
    auto position = lookup(key);
    if(position != data2.end())
    {
        *position = -1;
        std::cout << "Removed the element " << key << std::endl;
    }
    else
    {
        std::cout << "Key " << key << " not found." << std::endl;
    }
}
```

正如我们所看到的，大部分工作是通过调用`lookup`函数完成的。我们只需要验证结果并重置值以将其从表中移除。

1.  对于插入，我们将在不同的函数中实现实际逻辑，因为它将是递归的。我们还想要避免循环。然而，保留所有访问过的值的记录可能代价高昂。为了避免这种情况，我们将简单地在函数被调用超过 n 次时停止函数。由于递归深度 n 的阈值取决于我们的内存（或哈希表大小），这样可以获得良好的性能：

```cpp
void insert(int key)
{
    insert_impl(key, 0, 1);
}
void insert_impl(int key, int cnt, int table)
{
    if(cnt >= size)
    {
        std::cout << "Cycle detected, while inserting " << key << ". Rehashing required." << std::endl;
        return;
    }
    if(table == 1)
    {
int hash = hash1(key);
        if(data1[hash] == -1)
        {
            std::cout << "Inserted key " << key << " in table " << table << std::endl;
            data1[hash] = key;
        }
        else
        {
            int old = data1[hash];
            data1[hash] = key;
            std::cout << "Inserted key " << key << " in table " << table << " by replacing " << old << std::endl;
            insert_impl(old, cnt + 1, 2);
        }
    }
    else
    {
int hash = hash2(key);
        if(data2[hash] == -1)
        {
            std::cout << "Inserted key " << key << " in table " << table << std::endl;
            data2[hash] = key;
        }
        else
        {
            int old = data2[hash];
            data2[hash] = key;
            std::cout << "Inserted key " << key << " in table " << table << " by replacing " << old << std::endl;
            insert_impl(old, cnt + 1, 2);
        }
    }
}
```

正如我们所看到的，实现需要三个参数-键、我们要插入键的表以及递归调用堆栈的计数，以跟踪我们已经改变位置的元素数量。

1.  现在，让我们编写一个实用函数来打印哈希表中的数据。虽然这并不是真正必要的，也不应该暴露，但我们将这样做，以便更好地了解我们的插入函数如何在内部管理数据：

```cpp
void print()
{
    std::cout << "Index: ";
    for(int i = 0; i < size; i++)
        std::cout << i << '\t';
    std::cout << std::endl;
    std::cout << "Data1: ";
    for(auto i: data1)
        std::cout << i << '\t';
    std::cout << std::endl;
    std::cout << "Data2: ";
    for(auto i: data2)
        std::cout << i << '\t';
    std::cout << std::endl;
}
};
```

1.  现在，让我们编写`main`函数，以便我们可以使用这个哈希映射：

```cpp
int main()
{
    hash_map map(7);
    map.print();
    map.insert(10);
    map.insert(20);
    map.insert(30);
    std::cout << std::endl;
    map.insert(104);
    map.insert(2);
    map.insert(70);
    map.insert(9);
    map.insert(90);
    map.insert(2);
    map.insert(7);
    std::cout << std::endl;
    map.print();
    std::cout << std::endl;
    map.insert(14);  // This will cause cycle.
}
```

1.  您应该看到以下输出：

```cpp
Index: 0    1    2    3    4    5    6    
Data1: -1    -1    -1    -1    -1    -1    -1    
Data2: -1    -1    -1    -1    -1    -1    -1    
Inserted key 10 in table 1
Inserted key 20 in table 1
Inserted key 30 in table 1
Inserted key 104 in table 1 by replacing 20
Inserted key 20 in table 2
Inserted key 2 in table 1 by replacing 30
Inserted key 30 in table 2
Inserted key 70 in table 1
Inserted key 9 in table 1 by replacing 2
Inserted key 2 in table 2
Inserted key 90 in table 1 by replacing 104
Inserted key 104 in table 2 by replacing 2
Inserted key 2 in table 1 by replacing 9
Inserted key 9 in table 2
Inserted key 2 in table 1 by replacing 2
Inserted key 2 in table 2 by replacing 104
Inserted key 104 in table 1 by replacing 90
Inserted key 90 in table 2
Inserted key 7 in table 1 by replacing 70
Inserted key 70 in table 2
Index: 0    1    2    3    4    5     6
Data1: 7   -1    2    10  -1   -1     104
Data2: 2    9    20   70   30   90   -1
Inserted key 14 in table 1 by replacing 7
Inserted key 7 in table 2 by replacing 9
Inserted key 9 in table 1 by replacing 2
Inserted key 2 in table 2 by replacing 2
Inserted key 2 in table 1 by replacing 9
Inserted key 9 in table 2 by replacing 7
Inserted key 7 in table 1 by replacing 14
Cycle detected, while inserting 14\. Rehashing required.
```

正如我们所看到的，输出显示了内部维护两个表的完整跟踪。我们打印了内部步骤，因为一些值正在移动。我们可以从跟踪中看到，`14`的最后插入导致了一个循环。插入的深度已经超过了`7`。同时，我们还可以看到两个表几乎已经满了。我们已经填充了`14`中的`11`个元素，因此在每一步替换值的机会都在增加。我们还在循环之前打印了表。

此外，这里删除元素的时间复杂度为*O(1)*，因为它只是使用`lookup`函数并删除元素（如果找到）。因此，唯一昂贵的函数是插入。因此，如果在任何应用程序中插入的数量要比查找的数量少得多，这是一个理想的实现。

让我们使用以下视觉辅助工具，以便更好地理解这一点：

![图 3.11：在使用布谷鸟哈希的哈希表中插入元素](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_11.jpg)

###### 图 3.11：在使用布谷鸟哈希的哈希表中插入元素

![图 3.12：使用布谷鸟哈希处理哈希表中的碰撞](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_12.jpg)

###### 图 3.12：使用布谷鸟哈希处理哈希表中的碰撞

![图 3.13：使用布谷鸟哈希处理哈希表中的碰撞（续）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_13.jpg)

###### 图 3.13：使用布谷鸟哈希处理哈希表中的碰撞（续）

![图 3.14：在使用布谷鸟哈希的哈希表中查找值](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_14.jpg)

###### 图 3.14：在使用布谷鸟哈希的哈希表中查找值

![图 3.15：在使用布谷鸟哈希的哈希表中删除值](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_15.jpg)

###### 图 3.15：在使用布谷鸟哈希的哈希表中删除值

正如我们从前面一系列的图中所看到的，首先，我们尝试在第一个表中插入元素。如果已经有另一个元素，我们将覆盖它并将现有元素插入到另一个表中。我们重复这个过程，直到安全地插入最后一个元素。

## C++哈希表

正如我们之前提到的，查找操作在大多数应用程序中是非常频繁的。然而，我们可能并不总是遇到正整数，这些很容易进行哈希。大部分时间你可能会遇到字符串。考虑我们之前考虑过的英语词典的例子。我们可以使用单词作为键，单词定义作为值来存储词典数据。另一个例子是我们在*第一章*，*列表、栈和队列*中考虑过的医院记录数据库，患者的姓名可能被用作键，其他相关信息可以作为值存储。

我们之前使用的简单取模函数来计算整数的哈希值对于字符串不起作用。一个简单的选择是计算所有字符的 ASCII 值的总和的模。然而，字符串中字符的所有排列可能非常庞大，这将导致很多碰撞。

C++提供了一个名为`std::hash<std::string>(std::string)`的函数，我们可以用它来生成字符串的哈希值。它有一个内置算法来处理哈希函数。同样，C++为所有基本数据类型提供了这样的函数。

现在，看看我们在*练习 14*中实现的哈希表，*链式哈希表*，很明显我们可以根据数据类型简单地将其模板化，并提供一个通用解决方案来为任何给定类型的数据提供哈希函数。STL 为此提供了几种解决方案：`std::unordered_set<Key>`和`std::unordered_map<Key, Value>`。无序集合只能存储一组键，而无序映射可以存储键和它们的值。因此，容器中的每个唯一键都将有一个相应的值。

这两个容器都是以相同的方式实现的 - 使用链式哈希表。哈希表中的每一行都是一个存储键（和映射的值）的向量。这些行被称为**桶**。因此，在计算密钥的哈希值后，它将被放置到其中一个桶中。每个桶也是一个列表，以支持链式处理。

默认情况下，这些容器的最大负载因子为*1*。一旦元素数量超过哈希表的大小，哈希函数将被更改，哈希值将被重新计算（重新散列），并且将重新构建一个更大的哈希表以降低负载因子。我们也可以使用`rehash`函数手动执行此操作。使用`max_load_factor(float)`函数可以更改负载因子的默认最大限制为*1*。一旦负载因子超过定义的最大限制，值将被重新散列。

这些容器提供了常用的函数，如`find`，`insert`和`erase`。它们还提供迭代器来遍历所有元素，以及使用其他容器（如向量和数组）创建无序集合和映射的构造函数。无序映射还提供`operator[]`，以便它可以返回已知键的值。

我们将在下一个练习中看一下无序集合和映射的实现。

### 练习 16：STL 提供的哈希表

在这个练习中，我们将实现无序集合和映射，并对这些容器进行插入、删除和查找等操作。让我们开始吧：

1.  包括所需的头文件：

```cpp
#include <iostream>
#include <unordered_map>
#include <unordered_set>
```

1.  现在，让我们编写一些简单的`print`函数，以使我们的`main`函数更易读：

```cpp
void print(const std::unordered_set<int>& container)
{
    for(const auto& element: container)
        std::cout << element << " ";
    std::cout << std::endl;
}
void print(const std::unordered_map<int, int>& container)
{
    for(const auto& element: container)
        std::cout << element.first << ": " << element.second << ", ";
    std::cout << std::endl;
}
```

1.  同样，添加对`find`函数的包装器，以保持代码整洁：

```cpp
void find(const std::unordered_set<int>& container, const auto& element)
{
    if(container.find(element) == container.end())
        std::cout << element << " not found" << std::endl;
    else
        std::cout << element << " found" << std::endl;
}
void find(const std::unordered_map<int, int>& container, const auto& element)
{
    auto it = container.find(element);
    if(it == container.end())
        std::cout << element << " not found" << std::endl;
    else
        std::cout << element << " found with value=" << it->second << std::endl;
}
```

1.  现在，编写`main`函数，以便我们可以使用`unordered_set`和`unordered_map`，然后对其执行各种操作。我们将查找、插入和删除元素：

```cpp
int main()
{
    std::cout << "Set example: " << std::endl;
    std::unordered_set<int> set1 = {1, 2, 3, 4, 5};
    std::cout << "Initial set1: ";
    print(set1);
    set1.insert(2);
    std::cout << "After inserting 2: ";
    print(set1);
    set1.insert(10);
    set1.insert(351);
    std::cout << "After inserting 10 and 351: ";
    print(set1);
    find(set1, 4);
    find(set1, 100);
    set1.erase(2);
    std::cout << "Erased 2 from set1" << std::endl;
    find(set1, 2);
    std::cout << "Map example: " << std::endl;
    std::unordered_map<int, int> squareMap;
    squareMap.insert({2, 4});
    squareMap[3] = 9;
    std::cout << "After inserting squares of 2 and 3: ";
    print(squareMap);
    squareMap[30] = 900;
    squareMap[20] = 400;
    std::cout << "After inserting squares of 20 and 30: ";
    print(squareMap);
    find(squareMap, 10);
    find(squareMap, 20);
    std::cout << "Value of map[3]=" << squareMap[3] << std::endl;
    std::cout << "Value of map[100]=" << squareMap[100] << std::endl;
}
```

1.  这个程序的可能输出之一如下。集合和映射中元素的顺序可能不同，因此被称为*无序*集合/映射：

```cpp
Set example: 
Initial set1: 5 4 3 2 1 
After inserting 2: 5 4 3 2 1 
After inserting 10 and 351: 351 10 1 2 3 4 5 
4 found
100 not found
Erased 2 from set1
2 not found
Map example: 
After inserting squares of 2 and 3: 3: 9, 2: 4, 
After inserting squares of 20 and 30: 20: 400, 30: 900, 2: 4, 3: 9, 
10 not found
20 found with value=400
Value of map[3]=9
Value of map[100]=0
```

正如我们所看到的，我们可以向这两个容器插入、查找和删除元素。这些操作都按预期工作。如果我们将这些操作与其他容器（如 vector、list、array、deque 等）进行基准测试，性能会更快。

我们可以存储键值对，并使用`operator[]`访问任何给定键的值，就像本练习中所示的那样。它返回一个引用，因此还允许我们设置值，而不仅仅是检索它。

#### 注意

由于`operator[]`返回一个引用，如果找不到键，它将向条目添加默认值。

在最后一行，我们得到了`map[100] = 0`，即使`100`从未被插入到映射中。这是因为`operator[]`返回了默认值。

如果我们想要跟踪基于重新散列而更改的桶的数量，我们可以使用`bucket_count()`函数来实现。还有其他函数可以获取有关其他内部参数的详细信息，比如`load_factor`、`max_bucket_count`等等。我们还可以使用`rehash`函数手动重新散列。

由于这些容器是使用链接实现的，它们实际上将键/值对存储在不同的桶中。因此，在任何桶中搜索键时，我们需要比较它们是否相等。因此，我们需要为键类型定义相等运算符。或者，我们可以将其作为另一个模板参数传递。

在这个练习中，我们可以看到，无序集合和映射不允许重复的键。如果我们需要存储重复的值，我们可以使用`unordered_multiset`或`unordered_multimap`。为了支持多个值，插入函数不会检查键是否已经存在于容器中。此外，它支持一些额外的函数来检索具有特定键的所有项。我们不会再深入研究这些容器的细节，因为这超出了本书的范围。

STL 为 C++支持的所有基本数据类型提供了哈希函数。因此，如果我们想要将自定义类或结构作为前述容器中的键类型，我们需要在`std`命名空间内实现一个哈希函数。或者，我们可以将其作为模板参数传递。然而，每次都自己编写哈希函数并不是一个好主意，因为性能在很大程度上取决于它。设计哈希函数需要进行相当多的研究和对手头问题的理解，以及数学技能。因此，我们将其排除在本书的范围之外。对于我们的目的，我们可以简单地使用`boost`库中提供的`hash_combine`函数，就像下面的例子中所示的那样。

```cpp
#include <boost/functional/hash.hpp>
struct Car
{
    std::string model;
    std::string brand;
    int buildYear;
};
struct CarHasher
{
    std::size_t operator()(const Car& car) const
    {
        std::size_t seed = 0;
        boost::hash_combine(seed, car.model);
        boost::hash_combine(seed, car.brand);
        return seed;
    }
};
struct CarComparator
{
    bool operator()(const Car& car1, const Car& car2) const
    {
    return (car1.model == car2.model) && (car1.brand == car2.brand);
    }
};
// We can use the hasher as follows:
std::unordered_set<Car, CarHasher, CarComparator> carSet;
std::unordered_map<Car, std::string, CarHasher, CarComparator> carDescriptionMap;
```

正如我们所看到的，我们已经定义了一个具有`operator()`的哈希结构，它将被无序容器使用。我们还定义了一个具有`operator()`的比较器结构，以支持相关函数。我们将这些结构作为模板参数传递。这也允许我们为不同的对象使用不同类型的比较器和哈希器。

除了简单的哈希函数，如取模，还有一些复杂的哈希函数，称为加密哈希函数，如 MD5、SHA-1 和 SHA-256。这些算法非常复杂，它们可以接受任何类型的数据——甚至是文件——作为输入值。加密函数的一个重要特征是，很难从给定的哈希值确定实际数据（也称为逆哈希），因此它们被用于一些最安全的系统中。例如，比特币区块链使用 SHA-256 算法来存储交易记录的重要真实性证明。区块链中的每个*块*都包含其前一个链接块的 SHA-256 哈希值，并且当前块的哈希值包含在后续块中。非法修改任何块将使整个区块链从该块开始无效，因为现在修改后的块的哈希值将与下一个块中存储的值不匹配。即使使用世界上一些最快的超级计算机，也需要数百年才能打破这一点，并创建伪造的交易记录。

### 活动 6：将长 URL 映射到短 URL

在这个活动中，我们将创建一个程序来实现类似于[`tinyurl.com/`](https://tinyurl.com/)的服务。它可以将一个非常长的 URL 映射到一个易于分享的小 URL。每当我们输入短 URL 时，它应该检索原始 URL。

我们想要以下功能：

+   高效地存储用户提供的原始 URL 和相应的较小 URL

+   如果找到，基于给定的较小 URL 检索原始 URL；否则，返回错误

这些高层次的步骤应该帮助你解决这个活动：

1.  创建一个包含`unordered_map`作为主要数据成员的类。

1.  添加一个插入值的函数。这个函数应该接受两个参数：原始 URL 和它的较小版本。

1.  添加一个函数来查找基于给定小 URL 的实际 URL（如果存在）。

#### 注意

这个活动的解决方案可以在第 498 页找到。

## 布隆过滤器

与哈希表相比，布隆过滤器在空间上非常高效，但代价是确定性答案；也就是说，我们得到的答案是不确定的。它只保证不会有假阴性，但可能会有假阳性。换句话说，如果我们得到一个正面的命中，元素可能存在，也可能不存在；但如果我们得到一个负面的命中，那么元素肯定不存在。

就像布谷鸟哈希一样，我们将在这里使用多个哈希函数。然而，我们将保留三个函数，因为两个函数无法达到合理的准确性。基本思想是，我们不存储实际值，而是存储一个布尔数组，指示值是否（可能）存在。

要插入一个元素，我们计算所有哈希函数的值，并将数组中所有三个哈希值对应的位设置为*1*。对于查找，我们计算所有哈希函数的值，并检查所有相应的位是否都设置为*1*。如果是，我们返回*true*；否则，我们返回*false*（元素不存在）。

显而易见的问题是——为什么查找是不确定的？原因是任何位都可以被多个元素设置。因此，有相当大的概率，所有特定值（称为*x*）的相关位都设置为*1*，因为之前插入了一些其他元素，尽管*x*根本没有被插入。在这种情况下，查找函数仍然会返回*true*。因此，我们可以期望一些误报。我们插入的元素越多，误报的机会就越大。然而，如果*x*的某个位没有设置，那么我们可以确定地说元素不存在。因此，假阴性不可能发生。

数组中的所有位都设置为*1*时，数组将饱和。因此，查找函数将始终返回*true*，并且插入函数根本不会产生任何影响，因为所有位已经设置为*1*。

以下图表使这一点更清晰：

![图 3.16：在 Bloom 过滤器中插入元素](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_16.jpg)

###### 图 3.16：在 Bloom 过滤器中插入元素

![图 3.17：在 Bloom 过滤器中查找元素](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_17.jpg)

###### 图 3.17：在 Bloom 过滤器中查找元素

![图 3.18：在 Bloom 过滤器中查找元素（续）](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_03_18.jpg)

###### 图 3.18：在 Bloom 过滤器中查找元素（续）

如前面的图表所示，我们根据哈希函数设置相关位，并且对于插入，我们对元素进行位`AND`查找，就像我们之前解释的那样。

我们将在接下来的练习中用 C++实现一个 Bloom 过滤器。

### 练习 17：创建 Bloom 过滤器

在这个练习中，我们将创建一个 Bloom 过滤器并尝试一些基本操作。我们还将测试查找中的误报。让我们开始吧：

1.  让我们包括所需的头文件：

```cpp
#include <iostream>
#include <vector>
```

1.  现在，让我们为我们的 Bloom 过滤器创建一个类，并添加所需的数据成员：

```cpp
class bloom_filter
{
    std::vector<bool> data;
    int nBits;
```

1.  现在，让我们添加所需的哈希函数。同样，我们将使用非常基本的哈希函数：

```cpp
int hash(int num, int key)
{
    switch(num)
    {
    case 0:
        return key % nBits;
    case 1:
        return (key / 7) % nBits;
    case 2:
        return (key / 11) % nBits;
    }
    return 0;
}
```

如您所见，我们使用单个函数，参数称为`num`，确定哈希函数，以避免其他函数中不必要的`if`-`else`块。这也很容易扩展；我们只需要为每个哈希函数添加一个情况。

1.  让我们为 Bloom 过滤器添加一个构造函数：

```cpp
public:
bloom_filter(int n) : nBits(n)
{
    data = std::vector<bool>(nBits, false);
}
```

1.  现在，让我们添加一个`lookup`函数：

```cpp
void lookup(int key)
{
    bool result = data[hash(0, key)] & data[hash(1, key)] & data[hash(2, key)];
    if(result)
    {
        std::cout << key << " may be present." << std::endl;
    }
    else
    {
        std::cout << key << " is not present." << std::endl;
    }
}
```

如预期的那样，`lookup`函数非常简单。它检查所有必需的位是否都设置为`1`。如果有可变数量的哈希函数，我们总是可以循环遍历所有这些函数，以检查所有相应的位是否都设置为`1`。为了使我们的话更准确，我们还说由于误报的可能性，一个键*可能存在*。另一方面，如果`lookup`返回负数，我们完全确定一个键不存在。

1.  甚至插入函数同样简单：

```cpp
void insert(int key)
{
    data[hash(0, key)] = true;
    data[hash(1, key)] = true;
    data[hash(2, key)] = true;
    std::cout << key << " inserted." << std::endl;
}
};
```

1.  现在，让我们添加`main`函数，以便我们可以使用这个类：

```cpp
int main()
{
bloom_filter bf(11);
bf.insert(100);
bf.insert(54);
bf.insert(82);
bf.lookup(5);
bf.lookup(50);
bf.lookup(2);
bf.lookup(100);
bf.lookup(8);
bf.lookup(65);
}
```

1.  您应该看到以下输出：

```cpp
100 inserted.
54 inserted.
82 inserted.
5 may be present.
50 is not present.
2 is not present.
100 may be present.
8 is not present.
65 may be present.
```

正如我们所看到的，有一些误报，但没有错误的否定。

与以前的技术不同，这种结构只需要 11 位来存储这些信息，正如我们从 Bloom 过滤器的构造函数中所看到的。因此，我们可以轻松地增加过滤器的大小，并相应地更新哈希函数，以获得更好的结果。例如，我们可以将数组的大小增加到 1,000（1,023 经常被使用，因为它是一个质数），我们仍然将使用少于 130 字节，这比大多数其他技术要少得多。随着哈希表大小的增加，我们的哈希函数也将变为*%1023*或类似的，并且将提供更好的结果和更好的数字分布。

这里需要注意的一个重要点是，由于我们没有在容器中存储实际数据，我们可以将其用作异构结构；也就是说，只要我们的哈希函数足够好，我们可以同时在同一个 Bloom 过滤器中插入不同类型的数据，比如整数、字符串和双精度浮点数。

在现实生活中有一些非常好的用例，特别是当数据量太大，即使使用哈希表也无法搜索，一些误报也是可以接受的。例如，在创建像 Gmail 或 Outlook 这样的电子邮件提供商的新电子邮件地址时，会检查电子邮件地址是否已经存在。数据库中存在数十亿个电子邮件地址，对于这样一个基本且频繁的查询，进行准确的检查将非常昂贵。幸运的是，即使电子邮件地址尚未被占用，有时说它已被占用也没关系，因为这不会造成任何伤害。用户只需选择其他内容。在这种情况下，使用 Bloom 过滤器是一个可行的选择。我们将在*Activity 7*，*电子邮件地址验证器*中看到它的运作。

另一个例子是用于显示新广告的推荐算法，这些广告被 Facebook 等服务使用。每次查看动态时，它都会向您显示一个新广告。它可以简单地将您观看的广告的 ID 存储在 Bloom 过滤器中。然后，在显示广告之前，可以针对特定广告的 ID 进行检查。如果检查返回您观看了特定广告，即使您没有（误报），它也不会显示该广告。然而，这没关系，因为您根本不知道，毕竟您也没有看到那个广告。这样，您可以每次都以非常快的查找获得新广告。

### 活动 7：电子邮件地址验证器

在这个活动中，我们将创建一个类似于我们在许多电子邮件服务提供商（如 Gmail 和 Outlook）的注册过程中找到的电子邮件验证器。我们将使用 Bloom 过滤器来检查电子邮件地址是否已被他人占用。

这些高级步骤应该帮助您完成此活动：

1.  创建一个`BloomFilter`类，可以接受一定数量的哈希函数和 Bloom 的大小。

1.  对于哈希，使用 OpenSSL 库中的 MD5 算法生成给定电子邮件的哈希值。MD5 是一种 128 位的哈希算法。对于多个哈希函数，我们可以使用每个字节作为单独的哈希值。

1.  要在 Bloom 过滤器中添加电子邮件，我们需要将在*步骤 2*中计算的哈希值的每个字节的所有位设置为*true*。

1.  要查找任何电子邮件，我们需要检查基于*步骤 2*中计算的哈希值的所有相关位是否为*true*。

#### 注

此活动的解决方案可在第 503 页找到。

## 总结

正如我们在介绍中提到的，查找问题在大多数应用程序中以一种或另一种方式遇到。根据我们的需求，我们可以使用确定性和概率性解决方案。在本章中，我们实现并看到了如何使用它们。最后，我们还看了 C++中用于哈希的内置容器的示例。这些容器在编写应用程序时非常有用，因为我们不需要每次为每种类型都实现它们。一个简单的经验法则是：如果我们可以看到对容器的`find`函数的大量调用，我们应该选择基于查找的解决方案。

到目前为止，我们已经看到了如何将数据存储在各种数据结构中并执行一些基本操作。在接下来的章节中，我们将研究各种类型的算法设计技术，以便优化这些操作，从分而治之开始。


# 第四章：分治

## 学习目标

在本章结束时，您将能够:

+   描述分治设计范式

+   实现标准的分治算法，如归并排序、快速排序和线性时间选择

+   使用 MapReduce 编程模型解决问题

+   学习如何使用多线程的 C++ MapReduce 实现

在本章中，我们将学习分治算法设计范式，并学习如何使用它来解决计算问题。

## 介绍

在上一章中，我们学习了一些常用的数据结构。数据结构是以不同形式组织数据的方式，数据结构使得控制和访问存储在其中的数据的成本成为可能。然而，使软件有用的不仅仅是存储和检索各种格式的数据的能力，而是能够对数据进行转换以解决计算问题的能力。对于给定的问题，对数据的精确定义和转换顺序由一系列称为**算法**的指令确定。

算法接受一组定义问题实例的输入，应用一系列变换，并输出一组结果。如果这些结果是手头计算问题的正确解决方案，我们称算法是*正确*的。算法的*好坏*由其效率决定，或者说算法需要执行多少指令才能产生正确的结果：

![图 4.1：算法所需步骤随输入大小的扩展](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_01.jpg)

###### 图 4.1：算法所需步骤随输入大小的扩展

上图显示了算法所需步骤随输入大小的增长情况。复杂度更高的算法随着输入大小的增加而增长更快，对于足够大的输入，它们甚至在现代计算机系统上也可能无法运行。例如，假设我们有一台每秒可以执行一百万次操作的计算机。对于大小为 50 的输入，需要*N log(N)*步的算法将花费 283 微秒完成；需要*N**2*步的算法将花费 2.5 毫秒；需要*N!*（*N*的阶乘）步的算法将需要大约 9,637,644,561,599,544,267,027,654,516,581,964,749,586,575,812,734.82 **世纪**来运行！

*如果对于输入大小 N，算法以 N 的多项式步骤解决问题，则称算法是高效的。*

将**多项式时间算法**表达为解决方案的问题也被称为属于计算复杂性的类*P*（多项式）。问题可以分为几种其他计算复杂性，以下是一些示例：

+   **NP**（非确定性多项式时间）问题的解决方案可以在多项式时间内验证，但没有已知的多项式时间解决方案。

+   **EXPTIME**（指数时间）问题的解决方案运行时间与输入大小呈指数关系。

+   **PSPACE**（多项式空间）问题需要多项式数量的空间。

找出*P*中的问题集是否与*NP*中的问题集完全相同是著名的*P = NP*问题，经过数十年的努力仍未解决，甚至为任何能解决它的人提供了 100 万美元的奖金。我们将在*第九章* *动态规划 II*中再次研究*P*和*NP*类型的问题。

计算机科学家们几十年来一直将算法作为数学对象进行研究，并确定了一组通用的方法（或**范式**）来设计高效的算法，这些方法可以用来解决各种各样的问题。其中最广泛适用的算法设计范式之一被称为*分治*，将是我们在本章的研究对象。

**分而治之**类型的算法将给定的问题分解成较小的部分，尝试为每个部分解决问题，最后将每个部分的解决方案合并为整个问题的解决方案。几种广泛使用的算法属于这一类，例如二分搜索、快速排序、归并排序、矩阵乘法、快速傅里叶变换和天际线算法。这些算法几乎出现在今天使用的所有主要应用程序中，包括数据库、Web 浏览器，甚至语言运行时，如 Java 虚拟机和 V8 JavaScript 引擎。

在本章中，我们将向您展示使用分而治之的方法解决问题的含义，以及如何确定您的问题是否适合这样的解决方案。接下来，我们将练习递归思维，并向您展示现代 C++标准库提供的工具，以便您可以使用分而治之来解决问题。最后，我们将通过查看 MapReduce 来结束本章，包括讨论为什么以及如何扩展，以及如何使用相同的范例来扩展您的程序，包括 CPU 级别和机器级别的并行化。

让我们深入研究一种使用分而治之方法的基本算法-二分搜索。

## 二分搜索

让我们从标准搜索问题开始：假设我们有一个排序的正整数序列，并且需要找出一个数字*N*是否存在于序列中。搜索问题自然地出现在几个地方；例如，接待员在一组按客户 ID 排序的文件中寻找客户的文件，或者老师在学生注册表中寻找学生的成绩。他们实际上都在解决搜索问题。

现在，我们可以以两种不同的方式解决问题。在第一种方法中，我们遍历整个序列，检查每个元素是否等于*N*。这称为**线性搜索**，并在以下代码中显示：

```cpp
bool linear_search(int N, std::vector<int>& sequence)
{
    for (auto i : sequence)
    {
        if (i == N)
            return true;      // Element found!
    }

    return false;
}
```

这种方法的一个好处是它适用于所有数组，无论是排序还是未排序。但是，它效率低下，并且没有考虑到给定数组是排序的。在算法复杂度方面，它是一个*O(N)*算法。

利用序列已排序的事实的另一种解决方案如下：

1.  从`range`中开始整个序列。

1.  将当前`range`的中间元素与*N*进行比较。让这个中间元素为*M*。

1.  如果*M = N*，我们在序列中找到了*N*，因此搜索停止。

1.  否则，我们根据两条规则修改`range`：

- 如果*N < M*，这意味着如果*N*存在于`range`中，它将在*M*的左侧，因此我们可以安全地从`range`中删除*M*右侧的所有元素。

- 如果*N > M*，算法从`range`中删除所有左侧的*M*元素。

1.  如果`range`中仍有多于 1 个元素，则转到*步骤 2*。

1.  否则，*N*不存在于序列中，搜索停止。

为了说明这个算法，我们将展示二分搜索是如何工作的，其中*S*是从*1*到*9*的整数排序序列，*N = 2*：

1.  算法从将*S*的所有元素放入范围开始。在这一步中，中间元素被发现是*5*。我们比较*N*和*5*：

###### 图 4.2：二分搜索算法-步骤 1

1.  由于*N < 5*，如果*N*存在于序列中，它必须在*5*的左边。因此，我们可以安全地丢弃序列中位于*5*右侧的所有元素。现在我们的范围只有*1*到*5*之间的元素，中间元素现在是*3*。我们现在可以比较*N*和*3*：

###### 图 4.3：二分搜索算法-步骤 2

1.  我们发现当前的中间元素*3*仍然大于*N*，并且范围可以进一步修剪为仅包含*1*和*3*之间的元素。新的中间元素现在是*2*，它等于*N*，搜索终止：

![图 4.4：二分搜索算法-步骤 3](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_04.jpg)

###### 图 4.4：二分搜索算法-步骤 3

在下一个练习中，我们将看一下二分搜索算法的实现。

### 练习 18：二分搜索基准

在这个练习中，我们将编写并基准测试二分搜索实现。按照以下步骤完成这个练习：

1.  首先添加以下头文件：

```cpp
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <algorithm>
#include <numeric>
```

1.  添加线性搜索代码如下：

```cpp
bool linear_search(int N, std::vector<int>& S)
{
        for (auto i : S)
        {
            if (i == N)
                return true;       // Element found!
        }

        return false;
}
```

1.  添加此处显示的二分搜索代码：

```cpp
bool binary_search(int N, std::vector<int>& S)
{
    auto first = S.begin();
    auto last = S.end();
    while (true)
    {
        // Get the middle element of current range
        auto range_length = std::distance(first, last);
        auto mid_element_index = first + std::floor(range_length / 2);
        auto mid_element = *(first + mid_element_index);
        // Compare the middle element of current range with N
        if (mid_element == N)
            return true;
        else if (mid_element > N)
            std::advance(last, -mid_element_index);
        if (mid_element < N)
            std::advance(first, mid_element_index);
        // If only one element left in the current range
        if (range_length == 1)
            return false;
    }
}
```

1.  为了评估二分搜索的性能，我们将实现两个函数。首先，编写小测试：

```cpp
void run_small_search_test()
{
    auto N = 2;
    std::vector<int> S{ 1, 3, 2, 4, 5, 7, 9, 8, 6 };
    std::sort(S.begin(), S.end());
    if (linear_search(N, S))
        std::cout << "Element found in set by linear search!" << std::endl;
    else
        std::cout << "Element not found." << std::endl;
    if (binary_search(N, S))
        std::cout << "Element found in set by binary search!" << std::endl;
    else
        std::cout << "Element not found." << std::endl;
}
```

1.  现在，添加大型测试函数，如下所示：

```cpp
void run_large_search_test(int size, int N)
{
    std::vector<int> S;
    std::random_device rd;
    std::mt19937 rand(rd());
      // distribution in range [1, size]
    std::uniform_int_distribution<std::mt19937::result_type> uniform_dist(1, size); 
    // Insert random elements
    for (auto i=0;i<size;i++)
        S.push_back(uniform_dist(rand));
    std::sort(S.begin(), S.end());
    // To measure the time taken, start the clock
    std::chrono::steady_clock::time_point begin = std::chrono::steady_clock::now();

    bool search_result = binary_search(111, S);
    // Stop the clock
    std::chrono::steady_clock::time_point end = std::chrono::steady_clock::now();

    std::cout << "Time taken by binary search = " << 
std::chrono::duration_cast<std::chrono::microseconds>
(end - begin).count() << std::endl;

    if (search_result)
        std::cout << "Element found in set!" << std::endl;
    else
        std::cout << "Element not found." << std::endl;
}
```

1.  最后，添加以下驱动程序代码，用于在不同大小的随机生成向量中搜索数字`36543`：

```cpp
int main()
{
    run_small_search_test();
    run_large_search_test(100000, 36543);
    run_large_search_test(1000000, 36543);
    run_large_search_test(10000000, 36543);
    return 0;
}
```

1.  以 x64-Debug 模式编译程序并运行。输出应如下所示：

![图 4.5：启用调试的二分搜索](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_05.jpg)

###### 图 4.5：启用调试的二分搜索

请注意，三个输入数组的大小都比前一个数组大 10 倍，因此第三个数组比第一个数组大 100 倍，它本身包含十万个元素。然而，使用二分搜索在数组中搜索所花费的时间仅增加了 10 微秒。

在上一个测试中，我们没有允许任何编译器优化，并且在运行时附加了调试器。现在，让我们看看当我们的编译器允许优化 C++代码而没有附加调试器时会发生什么。尝试以 x64-Release 模式编译*练习 18*中的*二分搜索基准*代码，并运行。输出应如下所示：

![图 4.6：打开编译器优化的二分搜索](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_06.jpg)

###### 图 4.6：打开编译器优化的二分搜索

无论向量大小如何，二分搜索在这三种情况下大致需要相同的时间！

请注意，我们的二分搜索实现使用迭代器和 C++标准库函数，如`std::distance()`和`std::advance()`。这在现代 C++中被认为是良好的实践，因为它有助于使我们的代码不依赖于基础数据类型，并且可以避免索引越界错误。

现在，假设我们想在一个浮点数向量上执行搜索。我们如何修改上一个练习中的函数？答案非常简单。我们可以修改函数签名如下：

```cpp
bool linear_search(float N, std::vector<float>& S)
bool binary_search(float N, std::vector<float>& S)
```

搜索函数内部的其余代码仍然可以保持完全相同，因为它完全独立于基础数据类型，仅取决于容器数据类型的行为。**在现代 C++中，将核心算法逻辑与算法操作的基础数据类型分离开来，是编写可重用代码的基石。**我们将在本书的过程中看到几个这样的分离示例，并深入研究标准库提供的更多函数，这些函数可以帮助我们编写可重用和健壮的代码。

### 活动 8：疫苗接种

想象一下，现在是流感季节，卫生部门官员计划访问一所学校，以确保所有入学的孩子都接种了流感疫苗。然而，出现了一个问题：一些孩子已经接种了流感疫苗，但不记得他们是否已经接种了卫生官员计划为所有学生接种的特定类别的流感疫苗。官方记录被寻找出来，部门能够找到已经接种疫苗的学生名单。这里显示了名单的一个小节：

![图 4.7：疫苗接种记录摘录](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_07.jpg)

###### 图 4.7：疫苗接种记录摘录

假设所有名称都是正整数，并且给定列表已排序。您的任务是编写一个程序，可以查找列表中给定学生的接种状况，并向官员输出学生是否需要接种疫苗。学生需要接种疫苗，如果满足以下两个条件：

+   如果它们不在列表中

+   如果他们在名单上但尚未接种流感疫苗。

由于列表中可能有大量学生，您的程序应尽可能快速和高效。程序的最终输出应如下所示：

![图 4.8：活动 8 的示例输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_08.jpg)

###### 图 4.8：活动 8 的示例输出

**高级步骤**

此活动的解决方案使用了稍微修改过的二分搜索算法。让我们开始吧：

1.  将每个学生表示为`Student`类的对象，可以定义如下：

```cpp
 class Student
{
    std::pair<int, int> name;
    bool vaccinated;
}
```

1.  重载`Student`类的必要运算符，以便可以使用标准库的`std::sort()`函数对学生向量进行排序。

1.  使用二分搜索查看学生是否在名单上。

1.  如果学生不在列表中，则您的函数应返回*true*，因为学生需要接种疫苗。

1.  否则，如果学生在名单上但尚未接种疫苗，则返回*true*。

1.  否则，返回*false*。

#### 注意

此活动的解决方案可在第 506 页找到。

## 理解分而治之方法

在分而治之方法的核心是一个简单直观的想法：如果您不知道如何解决问题的大实例，请找到一个小部分的问题，您可以解决，然后解决它。然后，迭代更多这样的部分，一旦解决了所有部分，将结果合并成原始问题的大一致解决方案。使用分而治之方法解决问题有三个步骤：

1.  **划分**：将原始问题划分为部分，以便为每个部分解决相同的问题。

1.  征服：解决每个部分的问题。

1.  **合并**：将不同部分的解决方案合并成原始问题的解决方案。

在前一节中，我们看了一个使用分而治之来在序列中搜索的示例。在每一步中，二分搜索尝试仅在标记为`range`的序列的一部分中搜索。当找到元素或不再能将`range`进一步分割为更小的部分时，搜索终止。然而，搜索问题与大多数分而治之算法有所不同：在搜索问题中，如果元素可以在序列的较小`range`中找到，则它也一定存在于完整序列中。换句话说，在序列的较小部分中的问题的解决方案给出了整个问题的解决方案。因此，解决方案不需要实现一般分而治之方法的组合步骤。遗憾的是，这种特性并不适用于绝大多数可以使用分而治之方法解决的计算问题。在接下来的部分中，我们将深入探讨并查看更多使用分而治之方法解决问题的示例。

## 使用分而治之进行排序

现在我们将探讨如何在解决另一个标准问题——排序时实现分治方法。拥有高效的排序算法的重要性不言而喻。在计算机发展的早期，即 20 世纪 60 年代，计算机制造商估计他们机器中 25%的 CPU 周期都用于对数组元素进行排序。尽管多年来计算机领域发生了重大变化，但排序仍然是当今广泛研究的内容，并且仍然是几个应用中的基本操作。例如，它是数据库索引背后的关键思想，然后允许使用对数时间搜索快速访问存储的数据，这类似于二分搜索。

排序算法的一般要求如下：

+   实现应该能够处理任何数据类型。它应该能够对整数、浮点小数甚至 C++结构或类进行排序，其中不同元素之间可以定义顺序。

+   排序算法应该能够处理大量数据，也就是说，相同的算法应该能够处理甚至大于计算机主存储器的数据大小。

+   排序算法应该在理论上和实践中都很快。

虽然所有三个列出的目标都是可取的，但在实践中，很难同时实现第二和第三个目标。第二个目标需要外部排序，即对不驻留在计算机主存储器上的数据进行排序。外部排序算法可以在执行期间仅持有整个数据的一个小子集时工作。

在本节中，我们将介绍两种排序算法：归并排序和快速排序。归并排序是一种外部排序算法，因此实现了我们的第二个目标，而快速排序，顾名思义，是实践中已知的最快的排序算法之一，并且作为 C++标准库的`std::sort()`函数的一部分出现。

### 归并排序

**归并排序**是已知的最古老的排序算法之一，出现在 20 世纪 40 年代末的报告中。当时的计算机只有几百字节的主存储器，通常用于复杂的数学分析。因此，对于排序算法来说，即使不能将所有要操作的数据都保存在主存储器中，也是至关重要的。归并排序通过利用一个简单的思想解决了这个问题——对一组大量元素进行排序与对一小部分元素进行排序，然后合并排序的子集，以保持元素的递增或递减顺序是相同的：

![图 4.9：归并排序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_09.jpg)

###### 图 4.9：归并排序

上图显示了使用归并排序对整数数组进行排序的示例。首先，算法将原始数组分成子数组，直到每个子数组只包含一个元素（*步骤 1*至*4*）。在随后的所有步骤中，算法将元素合并到更大的数组中，保持每个子数组中的元素按递增顺序排列。

### 练习 19：归并排序

在本练习中，我们将实现归并排序算法。步骤如下：

1.  导入以下头文件：

```cpp
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <algorithm>
#include <numeric>
```

1.  对两个向量进行合并操作的 C++代码如下。编写`merge()`函数如下：

```cpp
template <typename T>
std::vector<T> merge(std::vector<T>& arr1, std::vector<T>& arr2)
{
    std::vector<T> merged;
    auto iter1 = arr1.begin();
    auto iter2 = arr2.begin();
    while (iter1 != arr1.end() && iter2 != arr2.end())
    {
        if (*iter1 < *iter2)
        {
            merged.emplace_back(*iter1);
            iter1++;
        }
        else
        {
            merged.emplace_back(*iter2);
            iter2++;
        }
    }
    if (iter1 != arr1.end())
    {
        for (; iter1 != arr1.end(); iter1++)
            merged.emplace_back(*iter1);
    }
    else
    {
        for (; iter2 != arr2.end(); iter2++)
            merged.emplace_back(*iter2);
    }
    return merged;
}
```

模板化的`merge()`函数接受类型为`T`的两个向量的引用，并返回一个包含输入数组中元素的新向量，但按递增顺序排序。

1.  现在我们可以使用合并操作来编写递归的归并排序实现，如下所示：

```cpp
template <typename T>
std::vector<T> merge_sort(std::vector<T> arr)
{
    if (arr.size() > 1)
    {
        auto mid = size_t(arr.size() / 2);
        auto left_half = merge_sort<T>(std::vector<T>(arr.begin(), arr.begin() + mid));
        auto right_half = merge_sort<T>(std::vector<T>(arr.begin() + mid, arr.end()));
        return merge<T>(left_half, right_half);
    }

    return arr;
}
```

1.  添加以下函数以打印向量：

```cpp
template <typename T>
void print_vector(std::vector<T> arr)
{
    for (auto i : arr)
        std::cout << i << " ";

    std::cout << std::endl;
}
```

1.  以下函数允许我们测试归并排序算法的实现：

```cpp
void run_merge_sort_test()
{
    std::vector<int>    S1{ 45, 1, 3, 1, 2, 3, 45, 5, 1, 2, 44, 5, 7 };
    std::vector<float>  S2{ 45.6f, 1.0f, 3.8f, 1.01f, 2.2f, 3.9f, 45.3f, 5.5f, 1.0f, 2.0f, 44.0f, 5.0f, 7.0f };
    std::vector<double> S3{ 45.6, 1.0, 3.8, 1.01, 2.2, 3.9, 45.3, 5.5, 1.0, 2.0,  44.0, 5.0, 7.0 };
    std::vector<char>   C{ 'b','z','a','e','f','t','q','u','y' };
    std::cout << "Unsorted arrays:" << std::endl;
    print_vector<int>(S1);
    print_vector<float>(S2);
    print_vector<double>(S3);
    print_vector<char>(C);
    std::cout << std::endl;
    auto sorted_S1 = merge_sort<int>(S1);
    auto sorted_S2 = merge_sort<float>(S2);
    auto sorted_S3 = merge_sort<double>(S3);
    auto sorted_C = merge_sort<char>(C);
    std::cout << "Arrays sorted using merge sort:" 
                << std::endl;
    print_vector<int>(sorted_S1);
    print_vector<float>(sorted_S2);
    print_vector<double>(sorted_S3);
    print_vector<char>(sorted_C);
    std::cout << std::endl;
}
int main()
{
    run_merge_sort_test();
    return 0;
}
```

1.  编译并运行程序。输出应该如下所示：

![图 4.10：归并排序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_10.jpg)

###### 图 4.10：归并排序

本练习中对归并排序的实现延续了我们不将算法实现与底层数据类型绑定并且仅依赖于容器公开的函数的主题。

### 快速排序

在归并排序的情况下，目标是对大量数据进行排序，而快速排序试图减少平均情况下的运行时间。快速排序中的基本思想与归并排序相同-将原始输入数组分成较小的子数组，对子数组进行排序，然后合并结果以获得排序后的数组。但是，快速排序使用的基本操作是**分区**而不是合并。

**分区操作的工作原理**

给定一个数组和数组中的**枢轴元素** *P*，**分区操作**执行两件事：

1.  它将原始数组分成两个子数组*L*和*R*，其中*L*包含给定数组中小于或等于*P*的所有元素，*R*包含给定数组中大于*P*的所有元素。

1.  它重新组织数组中的元素顺序*L*，*P*，*R*。

以下图表显示了对未排序数组应用的分区的结果，其中选择了第一个元素作为枢轴：

![图 4.11：选择一个枢轴并围绕它对向量进行分区](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_11.jpg)

###### 图 4.11：选择一个枢轴并围绕它对向量进行分区

分区操作的一个有用属性是，在应用分区操作后，向量中枢轴*P*的新位置成为向量排序时*P*将具有的位置。例如，元素*5*在应用分区操作后出现在数组的第 5 个位置，这是元素*5*在数组按递增顺序排序时将出现的位置。

前面的属性也是快速排序算法的核心思想，其工作原理如下：

1.  如果输入数组*A*中有超过 1 个元素，则在*A*上应用分区操作。它将产生子数组*L*和*R*。

1.  使用*L*作为*步骤 1*的输入。

1.  使用*R*作为*步骤 1*的输入。

*步骤 2*和*3*是对由分区操作生成的数组进行递归调用，然后应用于原始输入数组。分区操作的简单递归应用导致元素按递增顺序排序。由于快速排序递归树可能会迅速变得很深，因此以下图表显示了在一个包含六个元素的小数组*{5, 6, 7, 3, 1, 9}*上应用快速排序的示例：

![图 4.12：快速排序算法的可视化](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_12.jpg)

###### 图 4.12：快速排序算法的可视化

算法的每次迭代都显示了对先前步骤中使用突出显示的枢轴应用的分区操作的结果。应该注意，我们将数组的第一个元素作为枢轴的选择是任意的。数组的任何元素都可以被选择为枢轴，而不会影响快速排序算法的正确性。

### 练习 20：快速排序

在本练习中，我们将实现并测试快速排序的实现。让我们开始吧：

1.  导入以下标头：

```cpp
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <algorithm>
#include <numeric>
```

1.  分区操作的 C++代码如下。按照以下所示编写`partition()`函数：

```cpp
template <typename T>
auto partition(typename std::vector<T>::iterator begin,
            typename std::vector<T>::iterator last)
{
      // Create 3 iterators, 
      // one pointing to the pivot, one to the first element and 
      // one to the last element of the vector.
    auto pivot_val = *begin;
    auto left_iter = begin+1;
    auto right_iter = last;
    while (true)
    {
        // Starting from the first element of vector, find an element that is greater than pivot.
        while (*left_iter <= pivot_val && 
                   std::distance(left_iter, right_iter) > 0)
            left_iter++;
        // Starting from the end of vector moving to the beginning, find an element that is lesser than the pivot.
        while (*right_iter > pivot_val && 
                   std::distance(left_iter, right_iter) > 0)
            right_iter--;
        // If left and right iterators meet, there are no elements left to swap. Else, swap the elements pointed to by the left and right iterators
        if (left_iter == right_iter)
            break;
        else
            std::iter_swap(left_iter, right_iter);
    }
    if (pivot_val > *right_iter)
        std::iter_swap(begin, right_iter);

    return right_iter;
}
```

此处显示的实现仅接受底层容器对象上的迭代器，并返回指向数组中分区索引的另一个迭代器。这意味着向量的所有元素都大于右分区中的枢轴，而小于或等于枢轴的所有元素都在左分区中。

1.  快速排序算法递归使用分区操作，如下所示：

```cpp
template <typename T>
void quick_sort(typename std::vector<T>::iterator begin, 
        typename std::vector<T>::iterator last)
{
    // If there are more than 1 elements in the vector
    if (std::distance(begin, last) >= 1)
    {
        // Apply the partition operation
        auto partition_iter = partition<T>(begin, last);

        // Recursively sort the vectors created by the partition operation
        quick_sort<T>(begin, partition_iter-1);
        quick_sort<T>(partition_iter, last);
    }
}
```

1.  `print_vector()`用于将向量打印到控制台，并实现如下：

```cpp
template <typename T>
void print_vector(std::vector<T> arr)
{
    for (auto i : arr)
        std::cout << i << " ";

    std::cout << std::endl;
}
```

1.  根据*练习 19*，*归并排序*中的驱动程序代码进行调整：

```cpp
void run_quick_sort_test()
{
    std::vector<int> S1{ 45, 1, 3, 1, 2, 3, 45, 5, 1, 2, 44, 5, 7 };
    std::vector<float>  S2{ 45.6f, 1.0f, 3.8f, 1.01f, 2.2f, 3.9f, 45.3f, 5.5f, 1.0f, 2.0f, 44.0f, 5.0f, 7.0f };
    std::vector<double> S3{ 45.6, 1.0, 3.8, 1.01, 2.2, 3.9, 45.3, 5.5, 1.0, 2.0,  44.0, 5.0, 7.0 };
    std::vector<char> C{ 'b','z','a','e','f','t','q','u','y'};
    std::cout << "Unsorted arrays:" << std::endl;
    print_vector<int>(S1);
    print_vector<float>(S2);
    print_vector<double>(S3);
    print_vector<char>(C);
    std::cout << std::endl;
    quick_sort<int>(S1.begin(), S1.end() - 1);
    quick_sort<float>(S2.begin(), S2.end() - 1);
    quick_sort<double>(S3.begin(), S3.end() - 1);
    quick_sort<char>(C.begin(), C.end() - 1);
    std::cout << "Arrays sorted using quick sort:" << std::endl;
    print_vector<int>(S1);
    print_vector<float>(S2);
    print_vector<double>(S3);
    print_vector<char>(C);
    std::cout << std::endl;
}
```

1.  编写一个`main()`函数，调用`run_quick_sort_test()`：

```cpp
int main()
{
    run_quick_sort_test();
    return 0;
}
```

1.  您的最终输出应如下所示：

![图 4.13：快速排序排序](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_13.jpg)

###### 图 4.13：快速排序排序

然而，快速排序的运行时间取决于我们选择的枢轴有多“好”。快速排序的最佳情况是在任何步骤中，枢轴都是当前数组的中位数元素；在这种情况下，快速排序能够将元素分成每一步相等大小的向量，因此，递归树的深度恰好是*log(n)*。如果不选择中位数作为枢轴，会导致分区大小不平衡，因此递归树更深，运行时间更长。

快速排序和归并排序的渐近复杂度如下所示：

![图 4.14：快速排序和归并排序的渐近复杂度](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_14.jpg)

###### 图 4.14：快速排序和归并排序的渐近复杂度

### 活动 9：部分排序

在最后两个练习中，我们实现了**总排序**算法，它按照递增（或递减）顺序对向量的所有元素进行排序。然而，在一些问题实例中，这可能是过度的。例如，想象一下，您得到一个包含地球上所有人的年龄的向量，并被要求找到人口最老的 10%的人的中位数年龄。

对这个问题的一个天真的解决方案是对年龄向量进行排序，从向量中提取最老的 10%人的年龄，然后找到提取向量的中位数。然而，这种解决方案是浪费的，因为它做的远远超出了计算解决方案所需的，也就是说，它对整个数组进行排序，最终只使用排序数组的 10%来计算所需的解决方案。

对这类问题的更好解决方案可以通过将归并排序和快速排序等总排序算法专门化为**部分排序算法**来得到。部分排序算法只对给定向量中的指定数量的元素进行排序，而将向量的其余部分保持未排序状态。

部分快速排序的描述如下：

1.  假设我们有一个向量*V*，我们需要创建一个有序的*k*元素的子向量。

1.  在*V*上应用分区操作，假设*V*的第一个元素作为枢轴（同样，这个选择完全是任意的）。分区操作的结果是两个向量，*L*和*R*，其中*L*包含所有小于枢轴的*V*的元素，*R*包含所有大于枢轴的元素。此外，枢轴的新位置是排序数组中枢轴的“正确”位置。

1.  使用*L*作为*步骤 1*的输入。

1.  如果*步骤 2*中枢轴的新位置小于*k*，则使用*R*作为*步骤 1*的输入。

您在本活动中的任务是实现部分快速排序算法，该算法使用随机生成的数组来测试算法的输出。大小为*100*且*k = 100*的向量的最终输出应如下所示：

![图 4.15：活动 9 的示例输出](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_15.jpg)

###### 图 4.15：活动 9 的示例输出

#### 注意

本活动的解决方案可在第 510 页找到。

### 线性时间选择

在前一节中，我们看了使用分治范式的简单算法示例，并介绍了分区和合并操作。到目前为止，我们对分治算法的看法局限于那些将每个中间步骤递归地分成两个子部分的算法。然而，有些问题在将每一步分成更多子部分时可以产生实质性的好处。在接下来的部分，我们将研究这样一个问题——线性时间选择。

想象一下，你负责为你的学校组织一场游行队伍。为了确保所有乐队成员看起来一致，学生的身高是相同的很重要。此外，要求所有年级的学生都参加。为了解决这些问题，你提出了以下解决方案——你将选择每个年级第 15 矮的学生参加游行。问题可以形式化如下：给定一个随机排序的元素集*S*，要求你找到*S*中第*i*小的元素。一个简单的解决方案可能是对输入进行排序，然后选择第*i*个元素。然而，这种解决方案的算法复杂度是*O(n log n)*。在本节中，我们将通过分治法解决这个问题，其复杂度为*O(n)*。

我们的解决方案依赖于正确使用分区操作。我们在上一小节介绍的分区操作接受一个向量和一个枢轴，然后将向量分成两部分，一部分包含所有小于枢轴的元素，另一部分包含所有大于枢轴的元素。最终算法的工作如下：

1.  假设我们有一个输入向量*V*，我们需要找到第*i*小的元素。

1.  将输入向量*V*分成向量*V**1*、*V**2*、*V**3*、*…*、*V**n/5*，每个向量包含五个元素（如果需要，最后一个向量可以少于五个元素）。

1.  接下来，我们对每个*V**i*进行排序。

1.  对于每个*V**i*，找到中位数*m**i*，并将所有中位数收集到一个集合*M*中，如下所示：![图 4.16：找到每个子向量的中位数](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_16.jpg)

###### 图 4.16：找到每个子向量的中位数

1.  找到*M*的中位数元素*q*：![图 4.17：找到一组中位数的中位数](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_17.jpg)

###### 图 4.17：找到一组中位数的中位数

1.  使用分区操作在*V*上使用*q*作为枢轴得到两个向量*L*和*R*：![图 4.18：对整个向量进行分区](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_18.jpg)

###### 图 4.18：对整个向量进行分区

1.  根据分区操作的定义，*L*包含所有小于*q*的元素，*R*包含所有大于*q*的元素。假设*L*有*(k-1)*个元素：

- 如果*i = k*，那么*q*就是*V*中的第*i*个元素。

- 如果*i < k*，则设置*V = L*并转到*步骤 1*。

- 如果*i > k*，则设置*V = R*并*i = i - k*，并转到*步骤 1*。

以下练习演示了在 C++中实现此算法。

### 练习 21：线性时间选择

在这个练习中，我们将实现线性时间选择算法。让我们开始吧：

1.  导入以下头文件：

```cpp
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <algorithm>
#include <numeric>
```

1.  编写如下所示的辅助函数：

```cpp
template<typename T>
auto find_median(typename std::vector<T>::iterator begin, typename std::vector<T>::iterator last)
{
    // Sort the array
    quick_sort<T>(begin, last);

    // Return the middle element, i.e. median
    return begin + (std::distance(begin, last)/2); 
}
```

1.  在*练习 20*中，*快速排序*，我们的分区函数假设给定向量中的第一个元素始终是要使用的枢轴。现在我们需要一个更一般的分区操作形式，可以与任何枢轴元素一起使用：

```cpp
template <typename T>
auto partition_using_given_pivot(
typename std::vector<T>::iterator begin, 
typename std::vector<T>::iterator end, 
typename std::vector<T>::iterator pivot)
{
        // Since the pivot is already given,
        // Create two iterators pointing to the first and last element of the vector respectively
    auto left_iter = begin;
    auto right_iter = end;
    while (true)
    {
        // Starting from the first element of vector, find an element that is greater than pivot.
        while (*left_iter < *pivot && left_iter != right_iter)
            left_iter++;
        // Starting from the end of vector moving to the beginning, find an element that is lesser than the pivot.
        while (*right_iter >= *pivot && 
                  left_iter != right_iter)
            right_iter--;
        // If left and right iterators meet, there are no elements left to swap. Else, swap the elements pointed to by the left and right iterators.
        if (left_iter == right_iter)
            break;
        else
            std::iter_swap(left_iter, right_iter);
    }
    if (*pivot > *right_iter)
        std::iter_swap(pivot, right_iter);
    return right_iter;
}
```

1.  使用以下代码来实现我们的线性时间搜索算法：

```cpp
// Finds ith smallest element in vector V
template<typename T>
typename std::vector<T>::iterator linear_time_select(
typename std::vector<T>::iterator begin,
typename std::vector<T>::iterator last, size_t i)
{
    auto size = std::distance(begin, last);
    if (size > 0 && i < size) {
        // Get the number of V_i groups of 5 elements each
        auto num_Vi = (size+4) / 5; 
        size_t j = 0;
        // For each V_i, find the median and store in vector M
        std::vector<T> M;
        for (; j < size/5; j++)
        {
            auto b = begin + (j * 5);
            auto l = begin + (j * 5) + 5;
            M.push_back(*find_median<T>(b, l));
        }
        if (j * 5 < size)
        {
            auto b = begin + (j * 5);
            auto l = begin + (j * 5) + (size % 5);
            M.push_back(*find_median<T>(b, l));
        }
        // Find the middle element ('q' as discussed)
           auto median_of_medians = (M.size() == 1)? M.begin():
      linear_time_select<T>(M.begin(), 
                            M.end()-1, M.size() / 2);

         // Apply the partition operation and find correct position 'k' of pivot 'q'.
        auto partition_iter = partition_using_given_pivot<T>(begin, last, median_of_medians);
        auto k = std::distance(begin, partition_iter)+1;
        if (i == k)
            return partition_iter;
        else if (i < k)
            return linear_time_select<T>(begin, partition_iter - 1, i);
        else if (i > k)
            return linear_time_select<T>(partition_iter + 1, last, i-k);
    }
    else {
        return begin;
    }
}
```

1.  添加合并排序实现，如下所示的代码。我们将使用排序算法来证明我们实现的正确性：

```cpp
template <typename T>
std::vector<T> merge(std::vector<T>& arr1, std::vector<T>& arr2)
{
    std::vector<T> merged;
    auto iter1 = arr1.begin();
    auto iter2 = arr2.begin();
    while (iter1 != arr1.end() && iter2 != arr2.end())
    {
        if (*iter1 < *iter2)
        {
            merged.emplace_back(*iter1);
            iter1++;
        }
        else
        {
            merged.emplace_back(*iter2);
            iter2++;
        }
    }
    if (iter1 != arr1.end())
    {
        for (; iter1 != arr1.end(); iter1++)
            merged.emplace_back(*iter1);
    }
    else
    {
        for (; iter2 != arr2.end(); iter2++)
            merged.emplace_back(*iter2);
    }
    return merged;
}
template <typename T>
std::vector<T> merge_sort(std::vector<T> arr)
{
    if (arr.size() > 1)
    {
        auto mid = size_t(arr.size() / 2);
        auto left_half = merge_sort(std::vector<T>(arr.begin(),
            arr.begin() + mid));
        auto right_half = merge_sort(std::vector<T>(arr.begin() + mid,
            arr.end()));
        return merge<T>(left_half, right_half);
    }
    return arr;
}
```

1.  最后，添加以下驱动程序和测试函数：

```cpp
void run_linear_select_test()
{
    std::vector<int> S1{ 45, 1, 3, 1, 2, 3, 45, 5, 1, 2, 44, 5, 7 };
    std::cout << "Original vector:" << std::endl;
    print_vector<int> (S1);
    std::cout << "Sorted vector:" << std::endl;
    print_vector<int>(merge_sort<int>(S1));
    std::cout << "3rd element: " 
                 << *linear_time_select<int>(S1.begin(), S1.end() - 1, 3) << std::endl;
    std::cout << "5th element: " 
                 << *linear_time_select<int>(S1.begin(), S1.end() - 1, 5) << std::endl;
    std::cout << "11th element: " 
                 << *linear_time_select<int>(S1.begin(), S1.end() - 1, 11) << std::endl;
}
int main()
{
    run_linear_select_test();
    return 0;
}
```

1.  编译并运行代码。你的最终输出应该如下所示：

![图 4.19：使用线性时间选择找到第 3、第 5 和第 11 个元素](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_19.jpg)

###### 图 4.19：使用线性时间选择找到第 3、第 5 和第 11 个元素

虽然对给定算法的详细理论分析超出了本章的范围，但算法的运行时间值得讨论。前面算法为什么有效的基本思想是，每次调用`linear_time_select()`时，都会应用分区操作，然后函数在其中一个分区上递归调用自身。在每个递归步骤中，问题的大小至少减少 30%。由于找到五个元素的中位数是一个常数时间操作，因此通过对前面算法得到的递归方程进行归纳，可以看到运行时间确实是*O(n)*。

#### 注意

线性时间选择算法的一个有趣特性是，当*V*被分成每个五个元素的子向量时，它的已知渐近复杂度（线性）被实现。找到导致更好渐近复杂度的子向量的恒定大小仍然是一个未解决的问题。

## C++标准库工具用于分治

在上一节中，我们手动实现了分治算法所需的函数。然而，C++标准库捆绑了一大批预定义函数，可以在编程时节省大量工作。以下表格提供了一个常用函数的便捷列表，这些函数在实现使用分治范例的算法时使用。我们简要描述了这些函数以供参考，但出于简洁起见，详细实现超出了本章的范围。请随意探索更多关于这些函数的信息；基于本章涵盖的概念，您应该能够理解它们。

![图 4.20：一些用于算法的有用 STL 函数](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_20_1.jpg)![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_20_2.jpg)

###### 图 4.20：一些用于算法的有用 STL 函数

## 在更高抽象级别上的分治-MapReduce

到目前为止，在本章中，我们已经将分治作为一种算法设计技术，并使用它来使用预定义的分治合并步骤集来解决我们的问题。在本节中，我们将稍微偏离一下，看看当我们需要将问题分解为较小部分并分别解决每个部分时，相同的分治原则如何在需要将软件扩展到单台计算机的计算能力之外并使用计算机集群来解决问题时特别有帮助。

原始**MapReduce**论文的开头如下：

“MapReduce 是一个用于处理和生成大型数据集的编程模型及其相关实现。用户指定一个映射函数，该函数处理键值对以生成一组中间键/值对，以及一个减少函数，该函数合并与相同中间键关联的所有中间值。”

#### 注意

您可以参考 Jeffrey Dean 和 Sanjay Ghemawat 于 2004 年发表的有关 MapReduce 模型的原始研究论文，链接在这里：[`static.googleusercontent.com/media/research.google.com/en/us/archive/mapreduce-osdi04.pdf`](https://static.googleusercontent.com/media/research.google.com/en/us/archive/mapreduce-osdi04.pdf)。

自从原始论文首次出现以来，MapReduce 编程模型的几个开源实现已经出现，其中最引人注目的是 Hadoop。Hadoop 为用户提供了一个编程工具包，用户可以编写映射和减少函数，这些函数可以应用于存储在名为 Hadoop 分布式文件系统（HDFS）中的数据。由于 HDFS 可以轻松扩展到通过网络连接的数千台机器的集群，因此 MapReduce 程序能够随着集群的规模而扩展。

然而，在这一部分，我们对 Hadoop 不感兴趣，而是对 MapReduce 作为一种编程范式以及它与手头的主题，即分治技术的关联感兴趣。我们将坚持使用一个使用多线程来模拟任务并行化的开源单机 MapReduce 实现，而不是 Hadoop。

### 映射和减少抽象

*map*和*reduce*这两个术语起源于诸如 Lisp 之类的函数式编程语言。

**映射**是一个操作，它接受一个容器*C*，并对*C*的每个元素应用给定的函数*f(x)*。下图显示了使用*f(x) = x**2*的示例：

![图 4.21：映射容器的值](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_21.jpg)

###### 图 4.21：映射容器的值

**减少**是一个操作，它通过将给定函数*f(acc, x)*应用于容器*C*的每个元素*x*来聚合值，并返回单个值。下图显示了这一点：

![图 4.22：减少容器的值](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_22.jpg)

###### 图 4.22：减少容器的值

C++标准库包含映射和减少操作，即`std::transform()`和`std::accumulate()`，分别（`std::reduce()`也在 C++ 17 中可用）。

#### 注意

`std::accumulate()`是一种只使用加法函数的限制形式的减少操作。更新的编译器还提供了`std::reduce()`，它更通用并且可以并行化。

以下练习演示了使用 C++标准库实现 MapReduce。

### 练习 22：在 C++标准库中进行映射和减少

在这个练习中，我们将看到如何使用这些函数来进一步理解映射和减少操作。让我们开始吧：

1.  导入以下头文件：

```cpp
#include <iostream>
#include <vector>
#include <chrono>
#include <random>
#include <algorithm>
#include <numeric>
```

1.  首先创建一个具有随机元素的数组：

```cpp
void transform_test(size_t size)
{
    std::vector<int> S, Tr;
    std::random_device rd;
    std::mt19937 rand(rd());
    std::uniform_int_distribution<std::mt19937::result_type> uniform_dist(1, size);
    // Insert random elements
    for (auto i = 0; i < size; i++)
        S.push_back(uniform_dist(rand));
    std::cout << "Original array, S: ";
    for (auto i : S)
        std::cout << i << " ";
    std::cout << std::endl;
    std::transform(S.begin(), S.end(), std::back_inserter(Tr), 
                      [](int x) {return std::pow(x, 2.0); });
    std::cout << "Transformed array, Tr: ";
    for (auto i : Tr)
        std::cout << i << " ";
    std::cout << std::endl;
    // For_each
    std::for_each(S.begin(), S.end(), [](int &x) {x = std::pow(x, 2.0); });
    std::cout << "After applying for_each to S: ";
    for (auto i : S)
            std::cout << i << " ";
    std::cout << std::endl;
}
```

1.  `transform_test()`函数随机生成给定大小的向量，并将变换*f(x) = x**2*应用于向量。

#### 注意

```cpp
void reduce_test(size_t size)
{
    std::vector<int> S;
    std::random_device rd;
    std::mt19937 rand(rd());
    std::uniform_int_distribution<std::mt19937::result_type> uniform_dist(1, size);
    // Insert random elements
    for (auto i = 0; i < size; i++)
        S.push_back(uniform_dist(rand));
    std::cout << std::endl << "Reduce test== " << std::endl << "Original array, S: ";
    for (auto i : S)
        std::cout << i << " ";
    std::cout << std::endl;
    // Accumulate
    std::cout<<"std::accumulate() = " << std::accumulate(S.begin(), S.end(), 0, [](int acc, int x) {return acc+x; });
    std::cout << std::endl;
}
```

1.  添加以下驱动程序代码：

```cpp
int main() 
{
    transform_test(10);
    reduce_test(10);
    return 0;
}
```

1.  编译并运行代码。您的输出应该如下所示：

![图 4.23：映射和减少数组](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_23.jpg)

###### 图 4.23：映射和减少数组

### 整合部分-使用 MapReduce 框架

要使用 MapReduce 模型编写程序，我们必须能够将我们期望的计算表达为两个阶段的系列：**映射**（也称为**分区**），在这个阶段程序读取输入并创建一组中间*<key,value>*对，以及**减少**，在这个阶段中间*<key,value>*对以所需的方式组合以生成最终结果。以下图表说明了这个想法：

![图 4.24：通用 MapReduce 框架](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_24.jpg)

###### 图 4.24：通用 MapReduce 框架

像 Hadoop 这样的框架为 MapReduce 编程模型增加的主要价值在于，它们使映射和减少操作分布式和高度可扩展，从而使计算在一组机器上运行，并且总共所需的时间减少了。

我们将使用 MapReduce 框架来执行以下练习中的示例任务。

#### 注意

以下的练习和活动需要在您的系统上安装 Boost C++库。请按照以下链接获取 Boost 库：

Windows：[`www.boost.org/doc/libs/1_71_0/more/getting_started/windows.html`](https://www.boost.org/doc/libs/1_71_0/more/getting_started/windows.html)

Linux/macOS：[`www.boost.org/doc/libs/1_71_0/more/getting_started/unix-variants.html`](https://www.boost.org/doc/libs/1_71_0/more/getting_started/unix-variants.html)

### 练习 23：使用 MapReduce 检查质数

给定一个正整数*N*，我们希望找出*1*和*N*之间的质数。在这个练习中，我们将看到如何使用 MapReduce 编程模型来实现这一点，并使用多个线程解决这个问题。让我们开始吧：

1.  让我们首先包括所需的库，并定义一个使用质因数分解检查给定数字是否为质数的函数：

```cpp
#include <iostream>
#include "mapreduce.hpp"
namespace prime_calculator {
    bool const is_prime(long const number)
    {
        if (number > 2)
        {
            if (number % 2 == 0)
                return false;
            long const n = std::abs(number);
            long const sqrt_number = static_cast<long>(std::sqrt(
static_cast<double>(n)));
            for (long i = 3; i <= sqrt_number; i += 2)
            {
                if (n % i == 0)
                    return false;
            }
        }
        else if (number == 0 || number == 1)
            return false;
        return true;
    }
```

1.  以下类用于生成具有给定差值的一系列数字（也称为**步长**）：

```cpp
    template<typename MapTask>
    class number_source : mapreduce::detail::noncopyable
    {
    public:
        number_source(long first, long last, long step)
            : sequence_(0), first_(first), last_(last), step_(step)
        {
        }
        bool const setup_key(typename MapTask::key_type& key)
        {
            key = sequence_++;
            return (key * step_ <= last_);
        }
        bool const get_data(typename MapTask::key_type const& key, typename MapTask::value_type& value)
        {
            typename MapTask::value_type val;
            val.first = first_ + (key * step_);
            val.second = std::min(val.first + step_ - 1, last_);
            std::swap(val, value);
            return true;
        }
    private:
        long sequence_;
        long const step_;
        long const last_;
        long const first_;
    };
```

1.  以下函数定义了映射阶段要执行的步骤：

```cpp
    struct map_task : public mapreduce::map_task<long, std::pair<long, long> >
    {
        template<typename Runtime>
        void operator()(Runtime& runtime, key_type const& key, 
value_type const& value) const
        {
            for (key_type loop = value.first; 
                loop <= value.second; loop++)
            runtime.emit_intermediate(is_prime(loop), loop);
        }
    };
```

1.  现在，让我们实现减少阶段：

```cpp
    struct reduce_task : public mapreduce::reduce_task<bool, long>
    {
        template<typename Runtime, typename It>
        void operator()(Runtime& runtime, key_type const& key, It it, It ite) const
        {
            if (key)
                std::for_each(it, ite, std::bind(&Runtime::emit, 
&runtime, true, std::placeholders::_1));
        }
    };
    typedef
        mapreduce::job<
            prime_calculator::map_task,
            prime_calculator::reduce_task,
            mapreduce::null_combiner,
            prime_calculator::number_source<prime_calculator::map_task>> job;
} // namespace prime_calculator
```

前面的命名空间有三个函数：首先，它定义了一个检查给定数字是否为质数的函数；其次，它定义了一个在给定范围内生成一系列数字的函数；第三，它定义了映射和减少任务。如前所述，映射函数发出*< k, v >*对，其中*k*和*v*都是`long`类型，其中*k*如果*v*是质数，则为*1*，如果*v*不是质数，则为*0*。然后，减少函数充当过滤器，仅在*k = 1*时输出*< k, v >*对。

1.  接下来的驱动代码设置了相关参数并启动了 MapReduce 计算：

```cpp
int main()
{
    mapreduce::specification spec;
    int prime_limit = 1000;
    // Set number of threads to be used
    spec.map_tasks = std::max(1U, std::thread::hardware_concurrency());
    spec.reduce_tasks = std::max(1U, std::thread::hardware_concurrency());
    // Set the source of numbers in given range
    prime_calculator::job::datasource_type datasource(0, prime_limit, prime_limit / spec.reduce_tasks);
    std::cout << "\nCalculating Prime Numbers in the range 0 .. " << prime_limit << " ..." << std::endl;

std::cout << std::endl << "Using "
        << std::max(1U, std::thread::hardware_concurrency()) << " CPU cores";
    // Run mapreduce
    prime_calculator::job job(datasource, spec);
    mapreduce::results result;
    job.run<mapreduce::schedule_policy::cpu_parallel<prime_calculator::job> >(result);

    std::cout << "\nMapReduce finished in " 
<< result.job_runtime.count() << " with " 
<< std::distance(job.begin_results(), job.end_results()) 
<< " results" << std::endl;

// Print results
    for (auto it = job.begin_results(); it != job.end_results(); ++it)
        std::cout << it->second << " ";
    return 0;
}
```

驱动代码设置了 MapReduce 框架所需的参数，运行计算，从减少函数收集结果，最后输出结果。

1.  编译并运行上述代码。您的输出应如下所示：

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_25.jpg)

###### 图 4.25：使用 MapReduce 框架计算质数

使用 MapReduce 模型编程的主要好处是它产生了具有极大可扩展性的软件。我们在本练习中使用的 MapReduce 框架只在单台机器上使用多线程来实现并行化。但是，如果它能够支持分布式系统，我们在这里编写的相同代码可以在大型服务器集群上运行，使计算规模扩展到巨大。将前面的代码移植到 Hadoop 等系统是 Java 中的一个微不足道的练习，但超出了本书的范围。

### 活动 10：在 MapReduce 中实现 WordCount

在本章中，我们已经看到了分治技术背后的强大思想作为一种非常有用的算法设计技术，以及在处理大型和复杂计算时提供有用工具的能力。在这个活动中，我们将练习将一个大问题分解成小部分，解决小部分，并使用前一节中介绍的 MapReduce 模型合并后续结果。

我们的问题定义来自原始的 MapReduce 论文，如下所示：给定一组包含文本的文件，找到文件中出现的每个单词的频率。例如，假设您有两个文件，内容如下：

文件 1：

```cpp
The quick brown fox jumps over a rabbit
```

文件 2：

```cpp
The quick marathon runner won the race
```

考虑输入文件，我们的程序应该输出以下结果：

```cpp
The         2
quick       2
a           1
brown       1
fox         1
jumps       1
marathon    1
over        1
rabbit      1
race        1
runner      1
the         1
won         1
```

这类问题经常出现在索引工作负载中，也就是说，当您获得大量文本并需要对内容进行索引以便后续对文本的搜索可以更快地进行时。谷歌和必应等搜索引擎大量使用这样的索引。

在这个活动中，您需要实现单词计数问题的映射和减少阶段。由于这涉及到我们库特定的大部分代码，因此在`mapreduce_wordcount_skeleton.cpp`中为您提供了样板代码。

**活动指南：**

1.  阅读并理解`mapreduce_wordcount_skeleton.cpp`中给定的代码。您会注意到我们需要在头文件中导入 Boost 库。另一个需要注意的是，给定代码中的映射阶段创建了*< k, v >*对，其中*k*是一个字符串，*v*设置为*1*。例如，假设您的输入文件集包含一组随机组合的单词，*w**1*，*w**2*，*w**3*，…，*w**n*。如果是这样，映射阶段应该输出*k, 1*对，其中*k = {w**1**, w**2**, w**3**, …, w**n**}*，如下图所示：![图 4.26：映射阶段](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_26.jpg)

###### 图 4.26：映射阶段

1.  地图阶段的骨架代码如下：

```cpp
struct map_task : public mapreduce::map_task<
    std::string,                            // MapKey (filename)
    std::pair<char const*, std::uintmax_t>> // MapValue (memory mapped file               
                                               // contents)
{
template<typename Runtime>
    void operator()(Runtime& runtime, key_type const& key, 
                                         value_type& value) const
    {
        // Write your code here.
        // Use runtime.emit_intermediate() to emit <k,v> pairs
    }
};
```

1.  由于问题的地图阶段生成了*< k, 1 >*对，我们的程序的减少任务现在应该组合具有匹配*k*值的对，如下所示：![图 4.27：减少阶段](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_27.jpg)

###### 图 4.27：减少阶段

1.  在给定的代码中，减少任务接受两个迭代器，这些迭代器可用于迭代具有相同键的元素，即，`it`和`ite`之间的所有元素都保证具有相同的键。然后，您的减少阶段应创建一个新的*< k, v >*对，其中*k*设置为输入对的键，*v*等于输入对的数量：

```cpp
template<typename KeyType>
struct reduce_task : public mapreduce::reduce_task<KeyType, unsigned>
{
    using typename mapreduce::reduce_task<KeyType, unsigned>::key_type;
    template<typename Runtime, typename It>
    void operator()(Runtime& runtime, key_type const& key, It it, It const ite) const
    {
        // Write your code here.
        // Use runtime.emit() to emit the resulting <k,v> pairs
    }
};
```

1.  您将在`testdata/`中获得一组测试数据。编译并运行您的代码。输出应如下所示：

![图 4.28：获取给定输入文件中单词的频率](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/cpp-dsal-dsn-prin/img/C14498_04_28.jpg)

###### 图 4.28：获取给定输入文件中单词的频率

#### 注

此活动的解决方案可在第 514 页找到。

## 摘要

在本章中，我们以两种不同的方式讨论了分而治之：首先作为算法设计范式，然后在设计其他帮助我们扩展软件的工具中使用它。我们涵盖了一些标准的分而治之算法（归并排序和快速排序）。我们还看到了简单操作，如**分区**是不同问题的解决方案的基础，例如部分排序和线性时间选择。

在实践中实施这些算法时要牢记的一个重要思想是将保存数据的数据结构与算法本身的实现分开。使用 C++模板通常是实现这种分离的好方法。我们看到，C++标准库配备了一大套原语，可用于实现分而治之算法。

分而治之背后的基本思想的简单性使其成为解决问题的非常有用的工具，并允许创建诸如 MapReduce 之类的并行化框架。我们还看到了使用 MapReduce 编程模型在给定范围内找到质数的示例。

在下一章中，我们将介绍贪婪算法设计范式，这将导致诸如 Dijkstra 算法在图中找到最短路径的解决方案。
