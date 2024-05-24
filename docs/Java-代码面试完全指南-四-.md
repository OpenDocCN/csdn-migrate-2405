# Java 代码面试完全指南（四）

> 原文：[`zh.annas-archive.org/md5/2AD78A4D85DC7F13AC021B920EE60C36`](https://zh.annas-archive.org/md5/2AD78A4D85DC7F13AC021B920EE60C36)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十一章：链表和映射

本章涵盖了在编码面试中遇到的涉及映射和链表的最受欢迎的编码挑战。由于在技术面试中更喜欢使用单向链表，本章中的大多数问题将利用它们。但是，您可以挑战自己，尝试在双向链表的情况下解决每个问题。通常，对于双向链表来说，问题变得更容易解决，因为双向链表为每个节点维护两个指针，并允许我们在列表内前后导航。

通过本章结束时，您将了解涉及链表和映射的所有热门问题，并且将具有足够的知识和理解各种技术，以帮助您解决此类问题。我们的议程非常简单；我们将涵盖以下主题：

+   链表简介

+   映射简介

+   编码挑战

# 技术要求

本章中的所有代码文件都可以在 GitHub 上找到，网址为[`github.com/PacktPublishing/The-Complete-Coding-Interview-Guide-in-Java/tree/master/Chapter11`](https://github.com/PacktPublishing/The-Complete-Coding-Interview-Guide-in-Java/tree/master/Chapter11)。

但在进行编码挑战之前，让我们先了解一下链表和映射。

# 链表简介

链表是表示节点序列的线性数据结构。第一个节点通常被称为**头部**，而最后一个节点通常被称为**尾部**。当每个节点指向下一个节点时，我们有一个*单向链表*，如下图所示：

![11.1：单向链表](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.1_B15403.jpg)

图 11.1 – 单向链表

当每个节点指向下一个节点和前一个节点时，我们有一个*双向链表*，如下图所示：

![11.2：双向链表](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.2_B15403.jpg)

图 11.2 – 双向链表

让我们考虑一个单向链表。如果尾部指向头部，那么我们有一个*循环单向链表*。或者，让我们考虑一个双向链表。如果尾部指向头部，头部指向尾部，那么我们有一个*循环双向链表*。

在单向链表中，一个节点保存数据（例如，整数或对象）和指向下一个节点的指针。以下代码表示单向链表的节点：

```java
private final class Node {
  private int data;
  private Node next;
}
```

双向链表还需要指向前一个节点的指针：

```java
private final class Node {
  private int data;
  private Node next;
  private Node prev;
}
```

与数组不同，链表不提供访问第 n 个元素的常数时间。我们必须迭代 n-1 个元素才能获得第 n 个元素。我们可以在常数时间内从链表（单向和双向）的开头插入，删除和更新节点。如果我们的实现管理双向链表的尾部（称为双头双向链表），那么我们也可以在常数时间内从链表的末尾插入，删除和更新节点；否则，我们需要迭代链表直到最后一个节点。如果我们的实现管理单向链表的尾部（称为双头单向链表），那么我们可以在常数时间内在链表的末尾插入节点；否则，我们需要迭代链表直到最后一个节点。

本书的代码包包括以下应用程序（每个应用程序都公开`insertFirst()`、`insertLast()`、`insertAt()`、`delete()`、`deleteByIndex()`和`print()`方法）：

+   *SinglyLinkedList*：双头单向链表的实现

+   *SinglyLinkedListOneHead*：单头单向链表的实现

+   *DoublyLinkedList*：双头双向链表的实现

+   *DoublyLinkedListOneHead*：单头双向链表的实现

强烈建议您自己彻底分析这些应用程序。每个应用程序都有大量注释，以帮助您理解每个步骤。以下编码挑战依赖于这些链表实现。

# 简而言之，地图

想象一下，您正在字典中查找一个单词。这个单词本身是唯一的，可以被视为*键*。这个单词的意思可以被视为*值*。因此，这个单词及其意思形成了一个*键值对*。同样，在计算中，键值对容纳了一段数据，可以通过键来查找值。换句话说，我们知道键，我们可以用它来找到值。

地图是一个**抽象数据类型**（**ADT**），通过数组管理键值对（称为条目）。地图的特征包括以下内容：

+   键是唯一的（即，不允许重复键）。

+   我们可以查看键的列表，值的列表，或两者。

+   处理地图的最常见方法是`get()`，`put()`和`remove()`。

现在我们已经简要概述了链表和地图的概念，让我们开始我们的编码挑战。

# 编码挑战

在接下来的 17 个编码挑战中，我们将涵盖涉及地图和链表的许多问题。由于链表是技术面试中更受欢迎的话题，我们将为它们分配更多的问题。然而，为了掌握地图数据结构的概念，特别是内置的 Java 地图实现，我强烈建议您购买 Packt Publishing 出版的书籍*Java 编码问题*（[`www.packtpub.com/programming/java-coding-problems`](https://www.packtpub.com/programming/java-coding-problems)）。除了是本书的绝佳伴侣外，*Java 编码问题*还包含以下地图问题（请注意，这不是完整的列表）：

+   创建不可修改/不可变集合

+   映射默认值

+   计算`Map`中值的存在/不存在

+   从`Map`中删除

+   替换`Map`中的条目

+   比较两个地图

+   对`Map`进行排序

+   复制`HashMap`

+   合并两个地图

+   删除与谓词匹配的集合的所有元素

现在我们对链表和地图有了基本的了解，让我们来看看与地图和链表相关的面试中最常见的问题。

## 编码挑战 1 - Map put，get 和 remove

`put(K k, V v)`，一个名为`get(K k)`的方法，和一个名为`remove(K k)`的方法。

**解决方案**：正如您所知，地图是一个键值对数据结构。每个键值对都是地图的一个条目。因此，我们无法实现地图的功能，直到我们实现一个条目。由于一个条目包含两个信息，我们需要定义一个类来以通用的方式包装键和值。

代码非常简单：

```java
private final class MyEntry<K, V> {
  private final K key;
  private V value;
  public MyEntry(K key, V value) {
    this.key = key;
    this.value = value;
  }
  // getters and setters omitted for brevity
}
```

现在我们有了一个条目，我们可以声明一个地图。地图通过具有默认大小的条目数组来管理，这个默认大小称为地图容量。具有 16 个元素的初始容量的地图声明如下：

```java
private static final int DEFAULT_CAPACITY = 16;
private MyEntry<K, V>[] entries 
        = new MyEntry[DEFAULT_CAPACITY];
```

接下来，我们可以专注于使用这个数组作为客户端的地图。只有在条目的键在地图中是唯一的情况下，才能将条目放入地图中。如果给定的键存在，则只需更新其值。除此之外，只要我们没有超出地图的容量，就可以添加一个条目。在这种情况下的典型方法是将地图的大小加倍。基于这些语句的代码如下：

```java
private int size;
public void put(K key, V value) {
  boolean success = true;
  for (int i = 0; i < size; i++) {
    if (entries[i].getKey().equals(key)) {
      entries[i].setValue(value);
      success = false;
    }
  }
  if (success) {
    checkCapacity();
    entries[size++] = new MyEntry<>(key, value);
  }
}
```

以下辅助方法用于将地图的容量加倍。由于 Java 数组无法调整大小，我们需要通过创建初始数组的副本，但大小加倍来解决这个问题：

```java
private void checkCapacity() {
  if (size == entries.length) {
    int newSize = entries.length * 2;
    entries = Arrays.copyOf(entries, newSize);
  }
}
```

使用键来获取值。如果找不到给定的键，则返回`null`。获取值不会从地图中删除条目。让我们看一下代码：

```java
public V get(K key) {
  for (int i = 0; i < size; i++) {
    if (entries[i] != null) {
      if (entries[i].getKey().equals(key)) {
        return entries[i].getValue();
      }
    }
  }
  return null;
}
```

最后，我们需要使用键来删除一个条目。从数组中删除一个元素涉及将剩余的元素向前移动一个位置。元素移动后，倒数第二个和最后一个元素相等。通过将数组的最后一个元素置空，可以避免内存泄漏。忘记这一步是一个常见的错误：

```java
public void remove(K key) {
  for (int i = 0; i < size; i++) {
    if (entries[i].getKey().equals(key)) {
      entries[i] = null;
      size--;
      condenseArray(i);
    }
  }
}
private void condenseArray(int start) {
  int i;
  for (i = start; i < size; i++) {
    entries[i] = entries[i + 1];
  }
  entries[i] = null; // don't forget this line
}
```

地图的生产实现比这里展示的要复杂得多（例如，地图使用桶）。然而，很可能在面试中你不需要了解比这个实现更多的内容。尽管如此，向面试官提到这一点是个好主意。这样，你可以向他们展示你理解问题的复杂性，并且你意识到了这一点。

完成！完整的应用程序名为*Map*。

## 编码挑战 2 - 映射键集和值

`keySet()`）和一个返回值集合的方法（`values()`）。

`Set`。以下代码不言自明：

```java
public Set<K> keySet() {
  Set<K> set = new HashSet<>();
  for (int i = 0; i < size; i++) {
    set.add(entries[i].getKey());
  }
  return set;
}
```

为了返回一个值的集合，我们循环遍历映射并将值逐个添加到`List`中。我们使用`List`，因为值可能包含重复项：

```java
public Collection<V> values() {
  List<V> list = new ArrayList<>();
  for (int i = 0; i < size; i++) {
    list.add(entries[i].getValue());
  }
  return list;
}
```

完成！这很简单；生产中实现的地图比这里展示的要复杂得多。例如，值被缓存而不是每次都被提取。向面试官提到这一点，让他/她看到你知道生产地图是如何工作的。花点时间检查 Java 内置的`Map`和`HashMap`源代码。

完整的应用程序名为*Map*。

## 编码挑战 3 - 螺母和螺栓

**谷歌**，**Adobe**

**问题**：给定*n*个螺母和*n*个螺栓，考虑它们之间的一一对应关系。编写一小段代码，找出螺母和螺栓之间的所有匹配项，使迭代次数最少。

**解决方案**：让我们假设螺母和螺栓分别由以下两个数组表示：

```java
char[] nuts = {'$', '%', '&', 'x', '@'};
char[] bolts = {'%', '@', 'x', '$', '&'};
```

最直观的解决方案依赖于蛮力方法。我们可以选择一个螺母，并迭代螺栓以找到它的配偶。例如，如果我们选择`nuts[0]`，我们可以用`bolts[3]`找到它的配偶。此外，我们可以取`nuts[1]`，并用`bolts[0]`找到它的配偶。这个算法非常简单，可以通过两个`for`语句来实现，并且具有 O(n2)的时间复杂度。

或者，我们可以考虑对螺母和螺栓进行排序。这样，螺母和螺栓之间的匹配将自动对齐。这也可以工作，但不会包括最少的迭代次数。

为了获得最少的迭代次数，我们可以使用哈希映射。在这个哈希映射中，首先，我们将每个螺母作为一个键，将其在给定螺母数组中的位置作为一个值。接下来，我们迭代螺栓，并检查哈希映射是否包含每个螺栓作为一个键。如果哈希映射包含当前螺栓的键，那么我们找到了一个匹配（一对）；否则，这个螺栓没有匹配。让我们看一下代码：

```java
public static void match(char[] nuts, char[] bolts) {
  // in this map, each nut is a key and 
  // its position is as value
  Map<Character, Integer> map = new HashMap<>();
  for (int i = 0; i < nuts.length; i++) {
    map.put(nuts[i], i);
  }
  //for each bolt, search a nut
  for (int i = 0; i < bolts.length; i++) {
    char bolt = bolts[i];
    if (map.containsKey(bolt)) {
      nuts[i] = bolts[i];
    } else {
      System.out.println("Bolt " + bolt + " has no nut");
    }
  }
  System.out.println("Matches between nuts and bolts: ");
  System.out.println("Nuts: " + Arrays.toString(nuts));
  System.out.println("Bolts: " +Arrays.toString(bolts));
}
```

这段代码的运行时间是 O(n)。完整的代码名为*NutsAndBolts*。

## 编码挑战 4 - 删除重复项

**亚马逊**，**谷歌**，**Adobe**，**微软**

**问题**：考虑一个未排序的整数单向链表。编写一小段代码来删除重复项。

`Set<Integer>`。然而，在将当前节点的数据添加到`Set`之前，我们检查数据是否与`Set`的当前内容相匹配。如果`Set`已经包含该数据，我们就从链表中删除节点；否则，我们只是将其数据添加到`Set`中。从单向链表中删除节点可以通过将前一个节点链接到当前节点的下一个节点来完成。

以下图示说明了这个陈述：

![11.3: 从单向链表中删除节点](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.3_B15403.jpg)

图 11.3 - 从单向链表中删除节点

由于单链表只保存指向下一个节点的指针，我们无法知道当前节点之前的节点。技巧是跟踪两个连续的节点，从当前节点作为链表头部和前一个节点作为`null`开始。当当前节点前进到下一个节点时，前一个节点前进到当前节点。让我们看一下将这些语句组合在一起的代码：

```java
// 'size' is the linked list size
public void removeDuplicates() {
  Set<Integer> dataSet = new HashSet<>();
  Node currentNode = head;
  Node prevNode = null;
  while (currentNode != null) {
    if (dataSet.contains(currentNode.data)) {
      prevNode.next = currentNode.next;
      if (currentNode == tail) {
        tail = prevNode;
      }
      size--;
    } else {
      dataSet.add(currentNode.data);
      prevNode = currentNode;
    }
    currentNode = currentNode.next;
  }
}
```

这个解决方案的时间和空间复杂度为 O(n)，其中*n*是链表中的节点数。我们可以尝试另一种方法，将空间复杂度降低到 O(1)。首先，让我们将以下图表作为下一步的指南：

![11.4：从单链表中移除节点](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.4_B15403.jpg)

图 11.4 - 从单链表中移除节点

这种方法使用两个指针：

1.  当前节点从链表的头部开始遍历链表，直到到达尾部（例如，在前面的图表中，当前节点是第二个节点）。

1.  奔跑者节点，从与当前节点相同的位置开始，即链表的头部。

此外，奔跑者节点遍历链表，并检查每个节点的数据是否等于当前节点的数据。当奔跑者节点遍历链表时，当前节点的位置保持不变。

如果奔跑者节点检测到重复，那么它会将其从链表中移除。当奔跑者节点到达链表的尾部时，当前节点前进到下一个节点，奔跑者节点再次从当前节点开始遍历链表。因此，这是一个 O(n2)时间复杂度的算法，但空间复杂度为 O(1)。让我们看一下代码：

```java
public void removeDuplicates() {
  Node currentNode = head;
  while (currentNode != null) {
    Node runnerNode = currentNode;
    while (runnerNode.next != null) {
      if (runnerNode.next.data == currentNode.data) {
        if (runnerNode.next == tail) {
          tail = runnerNode;
        }
        runnerNode.next = runnerNode.next.next;
        size--;
      } else {
        runnerNode = runnerNode.next;
      }
    }
    currentNode = currentNode.next;
  }
}
```

完整的代码名为*LinkedListRemoveDuplicates*。

## 编码挑战 5 - 重新排列链表

**Adobe**，**Flipkart**，**Amazon**

**问题**：考虑一个未排序的整数单链表和一个给定的整数*n*。编写一小段代码，围绕*n*重新排列节点。换句话说，最后，链表将包含所有小于*n*的值，后面跟着所有大于*n*的节点。节点的顺序可以改变，*n*本身可以位于大于*n*的值之间的任何位置。

**解决方案**：假设给定的链表是 1→5→4→3→2→7→null，*n*=3。所以，3 是我们的枢轴。其余的节点应该围绕这个枢轴重新排列，符合问题的要求。解决这个问题的一个方法是逐个遍历链表节点，并将小于枢轴的每个节点放在头部，而大于枢轴的每个节点放在尾部。以下图表帮助我们可视化这个解决方案：

![11.5：链表重新排列](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.5_B15403.jpg)

图 11.5 - 链表重新排列

因此，值为 5、4 和 3 的节点被移动到尾部，而值为 2 的节点被移动到头部。最后，所有小于 3 的值都在虚线的左侧，而所有大于 3 的值都在虚线的右侧。我们可以将此算法编写成以下代码：

```java
public void rearrange(int n) {
  Node currentNode = head;
  head = currentNode;
  tail = currentNode;
  while (currentNode != null) {
    Node nextNode = currentNode.next;
    if (currentNode.data < n) {
      // insert node at the head
      currentNode.next = head;
      head = currentNode;
    } else {
      // insert node at the tail
      tail.next = currentNode;
      tail = currentNode;
    }
    currentNode = nextNode;
  }
  tail.next = null;
}
```

完整的应用程序名为*LinkedListRearranging*。

## 编码挑战 6 - 倒数第 n 个节点

**Adobe**，**Flipkart**，**Amazon**，**Google**，**Microsoft**

**问题**：考虑一个整数单链表和一个给定的整数*n*。编写一小段代码，返回倒数第 n 个节点的值。

**解决方案**：我们有一堆节点，我们必须找到满足给定约束的第*n*个节点。根据我们从*第八章*的经验，*递归和动态规划*，我们可以直觉地认为这个问题有一个涉及递归的解决方案。但我们也可以通过迭代解决它。由于迭代解决方案更有趣，我将在这里介绍它，而递归解决方案在捆绑代码中可用。

让我们使用以下图表来呈现算法（按照从上到下的顺序遵循图表）：

![11.6: The nth to last node](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.6_B15403.jpg)

图 11.6 - 最后第 n 个节点

因此，我们有一个链表，2 → 1 → 5 → 9 → 8 → 3 → 7 → null，并且我们想要找到第五个到最后一个节点值，即 5（您可以在前面的图表顶部看到）。迭代解决方案使用两个指针；让我们将它们表示为*runner1*和*runner2*。最初，它们都指向链表的头部。在步骤 1（前面图表的中间），我们将*runner1*从头移动到第 5 个到头（或*n*到头）节点。这在`for`循环中从 0 到 5（或*n*）中很容易实现。在步骤 2（前面图表的底部），我们同时移动*runner1*和*runner2*，直到*runner1*为`null`。当*runner1*为`null`时，*runner2*将指向距离头部第五个到最后一个节点（或*n*到最后一个）节点。在代码行中，我们可以这样做：

```java
public int nthToLastIterative(int n) {
  // both runners are set to the start
  Node firstRunner = head;
  Node secondRunner = head;
  // runner1 goes in the nth position
  for (int i = 0; i < n; i++) {
    if (firstRunner == null) {
      throw new IllegalArgumentException(
             "The given n index is out of bounds");
    }
    firstRunner = firstRunner.next;
  }
  // runner2 run as long as runner1 is not null
  // basically, when runner1 cannot run further (is null), 
  // runner2 will be placed on the nth to last node
  while (firstRunner != null) {
    firstRunner = firstRunner.next;
    secondRunner = secondRunner.next;
  }
  return secondRunner.data;
}
```

完整的应用程序名为*LinkedListNthToLastNode*。

## 编码挑战 7 - 循环开始检测

**Adobe**，**Flipkart**，**Amazon**，**Google**，**Microsoft**

**问题**：考虑一个包含循环的整数单链表。换句话说，链表的尾部指向之前的一个节点，定义了一个循环或循环。编写一小段代码来检测循环的第一个节点（即循环开始的节点）。

`tail.next`. 如果我们不管理尾部，那么我们可以搜索具有两个指向它的节点的节点。这也很容易实现。如果我们知道链表的大小，那么我们可以从 0 到大小进行迭代，最后一个`node.next`指向标记循环开始的节点。

### 快跑者/慢跑者方法

然而，让我们尝试另一种需要更多想象力的算法。这种方法称为快跑者/慢跑者方法。它很重要，因为它可以用于涉及链表的某些问题。

主要的快跑者/慢跑者方法涉及使用两个指针，它们从链表的头部开始，并同时遍历列表，直到满足某些条件。一个指针被命名为**慢跑者**（**SR**），因为它逐个节点地遍历列表。另一个指针被命名为**快跑者**（**FR**），因为它在每次移动时跳过下一个节点来遍历列表。以下图表是四个移动的示例：

![11.7: Fast Runner/Slow Runner example](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.7_B15403.jpg)

图 11.7 - 快跑者/慢跑者示例

因此，在第一步移动时，*FR*和*SR*指向*head*。在第二步移动时，*SR*指向值为 1 的*head.next*节点，而*FR*指向值为 4 的*head.next.next*节点。移动继续遵循这种模式。当*FR*到达链表的尾部时，*SR*指向中间节点。

正如您将在下一个编码挑战中看到的，快跑者/慢跑者方法可以用于检测链表是否是回文。但是，现在让我们恢复我们的问题。那么，我们可以使用这种方法来检测链表是否有循环，并找到此循环的起始节点吗？这个问题引发了另一个问题。如果我们将快跑者/慢跑者方法应用于具有循环的链表，*FR*和*SR*指针会相撞或相遇吗？答案是肯定的，它们会相撞。

解释一下，假设在开始循环之前，我们有*q*个先行节点（这些节点在循环外）。对于*SR*遍历的每个*q*个节点，*FR*已经遍历了 2**q*个节点（这是显而易见的，因为*FR*在每次移动时都会跳过一个节点）。因此，当*SR*进入循环（到达循环起始节点）时，*FR*已经遍历了 2**q*个节点。换句话说，*FR*在循环部分的 2**q-q*节点处；因此，它在循环部分的*q*个节点处。让我们通过以下测试案例来形象化这一点：

![11.8: 带有循环的链表](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.8_B15403.jpg)

图 11.8 - 带有循环的链表

因此，当*SR*进入循环（到达第四个节点）时，*FR*也到达了循环的第四个节点。当然，我们需要考虑到*q*（先行非循环节点的数量）可能比循环长度要大得多；因此，我们应该将 2**q-q*表示为*Q=modulo(q, LOOP_SIZE)*。

例如，考虑*Q = modulo*(3, 8) =3，其中我们有三个非循环节点（*q*=3），循环大小为八（*LOOP_SIZE*=8）。在这种情况下，我们也可以应用 2**q-q*，因为 2*3-3=3。因此，我们可以得出*SR*距离列表开头三个节点，*FR*距离循环开头三个节点。然而，如果链表前面有 25 个节点，后面有 7 个节点的循环，那么*Q = modulo* (25, 7) = 4 个节点，而 2*25-25=25，这是错误的。

除此之外，*FR*和*SR*在循环内移动。由于它们在一个圆圈内移动，这意味着当*FR*远离*SR*时，它也在向*SR*靠近，反之亦然。下图将循环隔离出来，并展示了它们如何继续移动*FR*和*SR*直到它们相撞：

![11.9: FR and SR collision](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.9_B15403.png)

图 11.9 - FR 和 SR 碰撞

花时间追踪*SR*和*FR*直到它们到达相遇点。我们知道*FR*比*FR*落后*LOOP_SIZE - Q*个节点，*SR*比*FR*落后*Q*个节点。在我们的测试案例中，*FR*比*SR*落后 8-3=5 个节点，*SR*比*FR*落后 3 个节点。继续移动*SR*和*FR*，我们可以看到*FR*以每次移动 1 步的速度追上了。

那么，它们在哪里相遇呢？如果*FR*以每次移动 1 步的速度追上，*FR*比*SR*落后*LOOP_SIZE - Q*个节点，那么它们将在离循环头部*Q*步的地方相遇。在我们的测试案例中，它们将在距离循环头部 3 步的地方相遇，节点值为 8。

如果相遇点距离循环头部的节点数为*Q*，我们可以继续回想相遇点距离循环头部的节点数也为*q*，因为*Q=modulo(q, LOOP_SIZE)*。这意味着我们可以制定以下四步算法：

1.  从链表的头部开始*FR*和*SR*。

1.  将*SR*以 1 个节点的速度移动，*FR*以 2 个节点的速度移动。

1.  当它们相撞（在相遇点），将*SR*移动到链表的头部，保持*FR*在原地。

1.  将*SR*和*FR*以 1 个节点的速度移动，直到它们相撞（这是代表循环头部的节点）。

让我们把这写成代码：

```java
public void findLoopStartNode() {
  Node slowRunner = head;
  Node fastRunner = head;
  // fastRunner meets slowRunner
  while (fastRunner != null && fastRunner.next != null) {
    slowRunner = slowRunner.next;
    fastRunner = fastRunner.next.next;
    if (slowRunner == fastRunner) { // they met
      System.out.println("\nThe meet point is at 
        the node with value: " + slowRunner);
      break;
    }
  }
  // if no meeting point was found then there is no loop
  if (fastRunner == null || fastRunner.next == null) {
    return;
  }
  // the slowRunner moves to the head of the linked list
  // the fastRunner remains at the meeting point
  // they move simultaneously node-by-node and 
  // they should meet at the loop start
  slowRunner = head;
  while (slowRunner != fastRunner) {
    slowRunner = slowRunner.next;
    fastRunner = fastRunner.next;
  }
  // both pointers points to the start of the loop
  System.out.println("\nLoop start detected at 
      the node with value: " + fastRunner);
}
```

作为一个快速的提示，不要期望*FR*能够跳过*SR*，所以它们不会相遇。这种情况是不可能的。想象一下，*FR*已经跳过了*SR*，它在节点*a*，那么*SR*必须在节点*a*-1。这意味着，在上一步中，*FR*在节点*a*-2，*SR*在节点(*a*-1)-1=*a*-2；因此，它们已经相撞了。

完整的应用程序名为*LinkedListLoopDetection*。在这段代码中，你会找到一个名为`generateLoop()`的方法。调用这个方法可以生成带有循环的随机链表。

## 编码挑战 8 - 回文

Adobe，Flipkart，Amazon，Google，Microsoft

如果链表是回文的，则返回`true`。解决方案应该涉及快速运行者/慢速运行者方法（这种方法在先前的编码挑战中有详细介绍）。

**解决方案**：只是一个快速提醒，回文（无论是字符串、数字还是链表）在翻转时看起来没有变化。这意味着处理（读取）回文可以从两个方向进行，得到的结果是相同的（例如，数字 12321 是一个回文，而数字 12322 不是）。

我们可以通过思考，当*FR*到达链表的末尾时，*SR*正好在链表的中间，来直观地得出使用快慢指针方法的解决方案。

如果链表的前半部分是后半部分的倒序，那么链表就是一个回文。因此，如果我们在栈中存储*FR*到达链表末尾之前*SR*遍历的所有节点，那么结果栈将包含链表前半部分的倒序。让我们通过以下图表来可视化这一点：

![11.10：使用快慢指针方法的链表回文](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.10_B15403.jpg)

图 11.10 - 使用快慢指针方法的链表回文

因此，当*FR*到达链表的末尾，*SR*到达第四个节点（链表的中间）时，栈包含值 2、1 和 4。接下来，我们可以继续以 1 个节点的速度移动*SR*，直到链表的末尾。在每次移动时，我们从栈中弹出一个值，并将其与当前节点的值进行比较。如果我们发现不匹配，那么链表就不是回文。在代码中，我们有以下内容：

```java
public boolean isPalindrome() {
  Node fastRunner = head;
  Node slowRunner = head;
  Stack<Integer> firstHalf = new Stack<>();
  // the first half of the linked list is added into the stack
  while (fastRunner != null && fastRunner.next != null) {
    firstHalf.push(slowRunner.data);
    slowRunner = slowRunner.next;
    fastRunner = fastRunner.next.next;
  }
  // for odd number of elements we to skip the middle node
  if (fastRunner != null) {
    slowRunner = slowRunner.next;
  }
  // pop from the stack and compare with the node by node of 
  // the second half of the linked list
  while (slowRunner != null) {
    int top = firstHalf.pop();
    // a mismatch means that the list is not a palindrome
    if (top != slowRunner.data) {
      return false;
    }
    slowRunner = slowRunner.next;
  }
  return true;
}
```

完整的应用程序名为*LinkedListPalindrome*。

## 编码挑战 9 - 两个链表相加

**Adobe**，**Flipkart**，**Microsoft**

**问题**：考虑两个正整数和两个单链表。第一个整数按位存储在第一个链表中（第一个数字是第一个链表的头）。第二个整数按位存储在第二个链表中（第一个数字是第二个链表的头）。编写一小段代码，将这两个数字相加，并将和作为一个链表返回，每个节点一个数字。

**解决方案**：让我们从一个测试案例的可视化开始：

![11.11：将两个数字作为链表相加](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.11_B15403.jpg)

图 11.11 - 将两个数字作为链表相加

如果我们逐步计算前面图表的总和，我们得到以下结果：

我们添加 7 + 7 = 14，所以我们写下 4 并携带 1：

结果链表是 4 →？

我们添加 3 + 9 + 1 = 13，所以我们写下 3 并携带 1：

结果链表是 4 → 3 →？

我们添加 8 + 8 + 1 = 17，所以我们写下 7 并携带 1：

结果链表是 4 → 3 → 7 →？

我们添加 9 + 4 + 1 = 14，所以我们写下 4 并携带 1

结果链表是 4 → 3 → 7 → 4 →？

我们添加 4 + 1 = 5，所以我们写下 5 并携带无：

结果链表是 4 → 3 → 7 → 4 → 5 →？

我们添加 1 + 0 = 1，所以我们写下 1 并携带无：

结果链表是 4 → 3 → 7 → 4 → 5 → 1 →？

我们添加 2 + 0 = 2，所以我们写下 2 并携带无：

结果链表是 4 → 3 → 7 → 4 → 5 → 1 → 2

如果我们将结果链表写成一个数字，我们得到 4374512；因此，我们需要将其反转为 2154734。虽然反转结果链表的方法（可以被视为一个编码挑战）可以在捆绑代码中找到，但以下方法以递归的方式应用了前面的步骤（如果你不擅长递归问题，请不要忘记阅读*第八章*，*递归和动态规划*）。基本上，以下递归通过逐个节点添加数据，将任何多余的数据传递到下一个节点：

```java
private Node sum(Node node1, Node node2, int carry) {
  if (node1 == null && node2 == null && carry == 0) {
    return null;
  }
  Node resultNode = new Node();
  int value = carry;
  if (node1 != null) {
    value += node1.data;
  }
  if (node2 != null) {
    value += node2.data;
  }
  resultNode.data = value % 10;
  if (node1 != null || node2 != null) {
    Node more = sum(node1 == null
        ? null : node1.next, node2 == null
        ? null : node2.next, value >= 10 ? 1 : 0);
    resultNode.next = more;
  }
  return resultNode;
}
```

完整的应用程序名为*LinkedListSum*。

## 编码挑战 10 - 链表交集

**Adobe**，**Flipkart**，**Google**，**Microsoft**

**问题**：考虑两个单链表。编写一小段代码，检查这两个列表是否相交。交集是基于引用的，而不是基于值的，但是你应该返回交集节点的值。因此，通过引用检查交集并返回值。

**解决方案**：如果你不确定*两个链表的交集*是什么意思，那么我们建议你勾画一个测试用例，并与面试官讨论细节。下面的图表展示了这样一个情况：

![11.12: 两个列表的交集](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.12_B15403.jpg)

图 11.12 – 两个列表的交集

在这个图表中，我们有两个相交的列表，它们在值为 8 的节点处相交。因为我们谈论的是引用交集，这意味着值为 9 和值为 4 的节点指向值为 8 的节点的内存地址。

主要问题是列表的大小不同。如果它们的大小相等，我们可以从头到尾遍历它们，逐个节点，直到它们相撞（直到*node_list_1.next= node_list_2.next*）。如果我们能跳过值为 2 和 1 的节点，我们的列表将是相同大小的（参考下一个图表；因为第一个列表比第二个列表长，我们应该从标记为*虚拟头*的节点开始迭代）：

![11.13: Removing the first two nodes of the top list](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.13_B15403.jpg)

图 11.13 – 移除顶部列表的前两个节点

记住这个陈述，我们可以推导出以下算法：

1.  确定列表的大小。

1.  如果第一个列表（我们将其表示为*l1*）比第二个列表（我们将其表示为*l2*）长，那么将第一个列表的指针移动到（*l1-l2*）。

1.  如果第一个列表比第二个列表短，那么将第二个列表的指针移动到（*l2-l1*）。

1.  逐个移动两个指针，直到达到末尾或者它们相撞为止。

将这些步骤转化为代码是直接的：

```java
public int intersection() {
  // this is the head of first list
  Node currentNode1 = {head_of_first_list};
  // this is the head of the second list
  Node currentNode2 = {head_of_second_list};
  // compute the size of both linked lists
  // linkedListSize() is just a helper method
  int s1 = linkedListSize(currentNode1);
  int s2 = linkedListSize(currentNode2);
  // the first linked list is longer than the second one
  if (s1 > s2) {
    for (int i = 0; i < (s1 - s2); i++) {
      currentNode1 = currentNode1.next;
    }
  } else {
    // the second linked list is longer than the first one
    for (int i = 0; i < (s2 - s1); i++) {
      currentNode2 = currentNode2.next;
    }
  }
  // iterate both lists until the end or the intersection node
  while (currentNode1 != null && currentNode2 != null) {
    // we compare references not values!
    if (currentNode1 == currentNode2) {
      return currentNode1.data;
    }
    currentNode1 = currentNode1.next;
    currentNode2 = currentNode2.next;
  }
  return -1;
}
```

完整的应用程序名为*LinkedListsIntersection*。在代码中，你会看到一个名为`generateTwoLinkedListWithInterection()`的辅助方法。这用于生成具有交集点的随机列表。

## 编码挑战 11 – 交换相邻节点

**亚马逊**，**谷歌**

**问题**：考虑一个单链表。编写一小段代码，交换相邻的节点，使得一个列表，比如 1 → 2 → 3 → 4 → null，变成 2 → 1 → 4 → 3 → null。考虑交换相邻的节点，而不是它们的值！

**解决方案**：我们可以将交换两个相邻节点*n1*和*n2*的问题简化为找到解决方案。交换两个值（例如，两个整数*v1*和*v2*）的一个众所周知的技巧依赖于一个辅助变量，并且可以写成如下形式：

*aux = v1; v1 = v2; v2 = aux;*

然而，我们不能对节点应用这种简单的方法，因为我们必须处理它们的链接。仅仅写下面这样是不够的：

*aux = n1; n1 = n2; n2 = aux;*

如果我们依赖这种简单的方法来交换*n1*和*n2*，那么我们将得到类似于以下图表的东西（注意，在交换*n1*和*n2*之后，我们有*n1.next* = *n3*和*n2.next* = *n1*，这是完全错误的）：

![11.14: Plain swapping with broken links (1)](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.14_B15403.jpg)

图 11.14 – 交换破损链接（1）

但是我们可以修复链接，对吧？嗯，我们可以明确地设置*n1.next*指向*n2*，并设置*n2.next*指向*n3*：

*n1.next = n2*

*n2.next = n3*

现在应该没问题了！我们可以交换两个相邻的节点。然而，当我们交换一对节点时，我们也会破坏两对相邻节点之间的链接。下面的图表说明了这个问题（我们交换并修复了*n1-n2*对和*n3-n4*对的链接）：

![11.15: Plain swapping with broken links (2)](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.15_B15403.jpg)

图 11.15 – 交换破损链接（2）

注意，在交换这两对之后，*n2.next*指向了* n4*，这是错误的。因此，我们必须修复这个链接。为此，我们可以存储*n2*，在交换*n3-n4*之后，我们可以通过设置*n2.next=n3*来修复链接。现在，一切看起来都很好，我们可以将其放入代码中：

```java
public void swap() {
  if (head == null || head.next == null) {
    return;
  }
  Node currentNode = head;
  Node prevPair = null;
  // consider two nodes at a time and swap their links
  while (currentNode != null && currentNode.next != null) {
    Node node1 = currentNode;           // first node
    Node node2 = currentNode.next;      // second node                    
    Node node3 = currentNode.next.next; // third node            
    // swap node1 node2
    Node auxNode = node1;
    node1 = node2;
    node2 = auxNode;
    // repair the links broken by swapping
    node1.next = node2;
    node2.next = node3;
    // if we are at the first swap we set the head
    if (prevPair == null) {
      head = node1;
    } else {
      // we link the previous pair to this pair
      prevPair.next = node1;
    }
    // there are no more nodes, therefore set the tail
    if (currentNode.next == null) {
      tail = currentNode;
    }
    // prepare the prevNode of the current pair
    prevPair = node2;
    // advance to the next pair
    currentNode = node3;
  }
}
```

完整的应用程序名为*LinkedListPairwiseSwap*。考虑挑战自己交换*n*个节点的序列。

## 编码挑战 12 - 合并两个排序的链表

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

**问题**：考虑两个排序的单链表。编写一小段代码，将这两个列表合并而不使用额外空间。

**解决方案**：所以，我们有两个排序的列表，*list1*：4 → 7 → 8 → 10 → null 和*list2*：5 → 9 → 11 → null，我们希望得到结果，4 → 5 → 7 → 8 → 9 → 10 → 11 → null。此外，我们希望在不分配新节点的情况下获得这个结果。

由于我们不能分配新节点，我们必须选择其中一个列表成为最终结果或合并的链表。换句话说，我们可以从*list1*开始作为合并的链表，并在*list1*的适当位置添加*list2*的节点。在处理每次比较后，我们将指针（*list1*）移动到合并列表的最后一个节点。

例如，我们首先比较这两个列表的头部。如果*list1*的头部小于*list2*的头部，我们选择*list1*的头部作为合并列表的头部。否则，如果*list1*的头部大于*list2*的头部，我们交换头部。以下图表说明了这一步骤：

![图 11.16 - 合并两个排序的链表（步骤 1）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.16_B15403.jpg)

图 11.16 - 合并两个排序的链表（步骤 1）

由于*list1*的头部小于*list2*的头部（4 < 5），它成为了合并列表的头部。我们说*list1*将指向合并列表的最后一个节点；因此，下一个要比较的节点应该是*list1.next*（值为 7 的节点）和*list2*（值为 5 的节点）。以下图表显示了这个比较的结果：

![图 11.17 - 合并两个排序的链表（步骤 2）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.17_B15403.jpg)

图 11.17 - 合并两个排序的链表（步骤 2）

因为*list1*跟随合并后的列表（最终结果），我们必须将*list1.next*移动到值为 5 的节点，但我们不能直接这样做。如果我们说*list1.next=list2*，那么我们就会失去*list1*的其余部分。因此，我们必须执行一次交换，如下所示：

```java
Node auxNode = list1.next; // auxNode = node with value 7
list1.next = list2;        // list1.next = node with value 5
list2 = auxNode;           // list2 = node with value 7
```

接下来，我们将*list1*移动到*list1.next*，也就是值为 9 的节点。我们将*list.next*与*list2*进行比较；因此，我们将 9 与 7 进行比较。以下图表显示了这个比较的结果：

![图 11.18 - 合并两个排序的链表（步骤 3）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.18_B15403.jpg)

图 11.18 - 合并两个排序的链表（步骤 3）

因为*list1*跟随合并后的列表（最终结果），我们必须将*list1.next*移动到值为 7 的节点（因为 7 < 9），我们使用之前讨论过的交换来完成。接下来，我们将*list1*移动到*list1.next*，也就是值为 8 的节点。我们将*list.next*与*list2*进行比较；因此，我们将 8 与 9 进行比较。以下图表显示了这个比较的结果：

![图 11.19 - 合并两个排序的链表（步骤 4）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.19_B15403.jpg)

图 11.19 - 合并两个排序的链表（步骤 4）

由于 8 < 9，不需要交换。我们将*list1.next*移动到下一个节点（值为 10 的节点）并将 10 与 9 进行比较。下一个图表显示了这个比较的结果：

![图 11.20 - 合并两个排序的链表（步骤 5）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.20_B15403.jpg)

图 11.20 - 合并两个排序的链表（步骤 5）

作为*list1*跟随合并后的列表（最终结果），我们必须将*list1.next*移动到值为 9 的节点（因为 9 < 10），我们使用之前讨论过的交换来完成。接下来，我们将*list1*移动到*list1.next*，这是值为 11 的节点。我们将*list.next*与*list2*进行比较；因此，我们将 11 与 10 进行比较。下一个图表显示了这个比较的结果：

![11.21：合并两个排序的链表（第 6 步）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.21_B15403.jpg)

图 11.21 - 合并两个排序的链表（第 6 步）

因为*list1*跟随合并后的列表（最终结果），我们必须将*list1.next*移动到值为 10 的节点（因为 10 < 11），我们使用之前讨论过的交换来完成。接下来，我们将*list1*移动到*list1.next*，这是`null`；因此，我们从*list2*中复制剩余部分。下一个图表显示了这个比较的结果：

![11.22：合并两个排序的链表（最后一步）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.22_B15403.jpg)

图 11.22 - 合并两个排序的链表（最后一步）

此时，合并后的链表已经完成。现在是时候揭示代码了（这个方法被添加到了著名的`SinglyLinkedList`中）：

```java
public void merge(SinglyLinkedList sll) {
  // these are the two lists
  Node list1 = head;      // the merged linked list 
  Node list2 = sll.head;  // from this list we add nodes at 
                          // appropriate place in list1
  // compare heads and swap them if it is necessary
  if (list1.data < list2.data) {
    head = list1;
  } else {
    head = list2;
    list2 = list1;
    list1 = head;
  }
  // compare the nodes from list1 with the nodes from list2
  while (list1.next != null) {
    if (list1.next.data > list2.data) {
      Node auxNode = list1.next;
      list1.next = list2;
      list2 = auxNode;
    }
    // advance to the last node in the merged linked list              
    list1 = list1.next;
  }
  // add the remaining list2
  if (list1.next == null) {
    list1.next = list2;
  }
}
```

完整的应用程序名为*LinkedListMergeTwoSorted*。类似的问题可能要求您通过递归合并两个排序的链表。虽然您可以找到名为*LinkedListMergeTwoSortedRecursion*的应用程序，但我建议您挑战自己尝试一种实现。此外，基于这种递归实现，挑战自己合并*n*个链表。完整的应用程序名为*LinkedListMergeNSortedRecursion*。

## 编码挑战 13 - 去除多余路径

**问题**：考虑一个存储矩阵中路径的单链表。节点的数据类型为(*行，列*)或简写为(*r，c*)。路径只能是水平（按*列*）或垂直（按*行*）。完整路径由所有水平和垂直路径的终点给出；因此，中间点（或中间的点）是多余的。编写一小段代码，删除多余的路径。

**解决方案**：让我们考虑一个包含以下路径的链表：(0, 0) → (0, 1) → (0, 2) → (1, 2) → (2, 2) → (3, 2) → (3, 3) → (3, 4) → null。多余的路径包括以下节点：(0, 1)，(1, 2)，(2, 2)和(3, 3)。因此，在移除多余路径后，我们应该保留一个包含四个节点的列表：(0, 0) → (0, 2) → (3, 2) → (3, 4) → null。下一个图表表示了多余的路径：

![11.23：多余的路径](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.23_B15403.jpg)

图 11.23 - 多余的路径

去除多余路径后，我们得到以下图表：

![11.24：去除冗余后的剩余路径](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.24_B15403.jpg)

图 11.24 - 去除冗余后的剩余路径

前面的图表应该提供了这个问题的解决方案。请注意，定义垂直路径的节点具有相同的列，因为我们只在行上下移动，而定义水平路径的节点具有相同的行，因为我们只在列左右移动。这意味着，如果我们考虑具有相同列或行的值的三个连续节点，那么我们可以移除中间节点。对相邻三元组重复此过程将移除所有多余节点。代码应该非常简单易懂：

```java
public void removeRedundantPath() {
  Node currentNode = head;
  while (currentNode.next != null 
          && currentNode.next.next != null) {
    Node middleNode = currentNode.next.next;
    // check for a vertical triplet (triplet with same column)
    if (currentNode.c == currentNode.next.c
            && currentNode.c == middleNode.c) {
      // delete the middle node
      currentNode.next = middleNode;
    } // check for a horizontal triplet 
    else if (currentNode.r == currentNode.next.r
            && currentNode.r == middleNode.r) {
      // delete the middle node
      currentNode.next = middleNode;
    } else {
      currentNode = currentNode.next;
    }
  }
}
```

完整的应用程序名为*LinkedListRemoveRedundantPath*。

## 编码挑战 14 - 将最后一个节点移到最前面

**问题**：考虑一个单链表。编写一小段代码，通过两种方法将最后一个节点移到最前面。因此，链表的最后一个节点变为头节点。

**解决方案**：这是一个听起来简单并且确实简单的问题。第一种方法将遵循以下步骤：

1.  将指针移动到倒数第二个节点（我们将其表示为*currentNode*）。

1.  存储*currentNode.next*（我们将其表示为*nextNode* - 这是最后一个节点）。

1.  将`cu`*rrentNode.next*设置为`null`（因此，最后一个节点变为尾部）。

1.  将新的头部设置为存储的节点（因此，头部变为*nextNode*）。

在代码行中，我们有以下内容：

```java
public void moveLastToFront() {      
  Node currentNode = head;
  // step 1
  while (currentNode.next.next != null) {
    currentNode = currentNode.next;
  }
  // step 2
  Node nextNode = currentNode.next;
  // step 3
  currentNode.next = null;
  // step 4
  nextNode.next = head;
  head = nextNode;
}
```

第二种方法可以通过以下步骤执行：

1.  将指针移动到倒数第二个节点（我们将其表示为*currentNode*）。

1.  将链表转换为循环列表（将*currentNode.next.next*链接到头部）。

1.  将新的头部设置为*currentNode.next*。

1.  通过将*currentNode.next*设置为`null`来打破循环性。

在代码行中，我们有以下内容：

```java
public void moveLastToFront() {
  Node currentNode = head;
  // step 1
  while (currentNode.next.next != null) {
    currentNode = currentNode.next;
  }
  // step 2
  currentNode.next.next = head;
  // step 3
  head = currentNode.next;
  // step 4
 currentNode.next = null;
}
```

完整的应用程序名为*LinkedListMoveLastToFront*。

## 编码挑战 15 - 以 k 组反转单链表

**Amazon**，**Google**，**Adobe**，**Microsoft**

**问题**：考虑一个单链表和一个整数*k*。编写一小段代码，以*k*组反转链表的节点。

**解决方案**：假设给定的链表是 7 → 4 → 3 → 1 → 8 → 2 → 9 → 0 → null，*k*=3。结果应为 3 → 4 → 7 → 2 → 8 → 1 → 0 → 9 → null。

让我们考虑给定的*k*等于链表的大小。在这种情况下，我们将问题简化为反转给定的链表。例如，如果给定的列表是 7 → 4 → 3 → null，*k*=3，则结果应为 3 → 4 → 7 → null。那么，我们如何获得这个结果呢？

为了反转节点，我们需要当前节点（*current*）、当前节点旁边的节点（*next*）和当前节点之前的节点（*previous*），并且我们应用以下代表节点重新排列的算法：

1.  从 0 开始计数。

1.  作为*当前*节点（最初是头节点）不是`null`，并且我们还没有达到给定的*k*，发生以下情况：

a. *next*节点（最初为`null`）变为*current*节点旁边的节点（最初是头节点）。

b. *current*节点（最初是头节点）旁边的节点变为*previous*节点（最初为`null`）。

c. *previous*节点变为*current*节点（最初是头节点）。

d. *current*节点变为*next*节点（*步骤 2a*的节点）。

e. 增加计数器。

因此，如果我们应用此算法，我们可以反转整个列表。但是我们需要按组反转它；因此，我们必须解决我们所做的*k*个子问题。如果这对你来说听起来像递归，那么你是对的。在前述算法的末尾，设置为*步骤 2a*（*next*）的节点指向计数器所指向的节点。我们可以说我们已经反转了前*k*个节点。接下来，我们通过递归从*next*节点开始继续下一组*k*节点。以下图表说明了这个想法：

![11.25：以 k 组（k=3）反转列表](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.25_B15403.jpg)

图 11.25 - 以 k 组（k=3）反转列表

以下代码实现了这个想法：

```java
public void reverseInKGroups(int k) {
  if (head != null) {
    head = reverseInKGroups(head, k);
  }
}
private Node reverseInKGroups(Node head, int k) {
  Node current = head;
  Node next = null;
  Node prev = null;
  int counter = 0;
  // reverse first 'k' nodes of linked list
  while (current != null && counter < k) {
    next = current.next;                        
    current.next = prev;            
    prev = current;
    current = next;
    counter++;
  }
  // 'next' points to (k+1)th node            
  if (next != null) {
    head.next = reverseInKGroups(next, k);
  }
  // 'prev' is now the head of the input list 
  return prev;
}
```

这段代码运行时间为 O(n)，其中*n*是给定列表中的节点数。完整的应用程序名为*ReverseLinkedListInGroups*。

## 编码挑战 16 - 反转双向链表

**Microsoft**，**Flipkart**

**问题**：考虑一个双向链表。编写一小段代码来反转它的节点。

**解决方案**：反转双向链表可以利用双向链表维护到前一个节点的链接的事实。这意味着我们可以简单地交换每个节点的前指针和后指针，如下面的代码所示：

```java
public void reverse() {
  Node currentNode = head;
  Node prevNode = null;
  while (currentNode != null) {
    // swap next and prev pointers of the current node
    Node prev = currentNode.prev;
    currentNode.prev = currentNode.next;
    currentNode.next = prev;
    // update the previous node before moving to the next node
    prevNode = currentNode;
    // move to the next node in the doubly linked list            
    currentNode = currentNode.prev;
  }
  // update the head to point to the last node
  if (prevNode != null) {
    head = prevNode;
  }
}
```

完整的应用程序名为*DoublyLinkedListReverse*。要对单链表和双链表进行排序，请参考*第十四章*，*排序和搜索*。

## 编码挑战 17 - LRU 缓存

**Amazon**，**Google**，**Adobe**，**Microsoft**，**Flipkart**

**问题**：编写一小段代码来实现固定大小的 LRU 缓存。LRU 缓存代表最近最少使用的缓存。这意味着，当缓存已满时，添加新条目将指示缓存自动驱逐最近最少使用的条目。

**解决方案**：任何缓存实现必须提供一种快速有效的检索数据的方式。这意味着我们的实现必须遵守以下约束：

+   **固定大小**：缓存必须使用有限的内存。因此，它需要一些限制（例如，固定大小）。

+   **快速访问数据**：插入和搜索操作应该快速；最好是 O(1)复杂度时间。

+   **快速驱逐数据**：当缓存已满（达到其分配的限制）时，缓存应该提供一个有效的算法来驱逐条目。

在最后一个要点的背景下，从 LRU 缓存中驱逐意味着驱逐最近最少使用的数据。为了实现这一点，我们必须跟踪最近使用的条目和长时间未使用的条目。此外，我们必须确保插入和搜索操作的 O(1)复杂度时间。在 Java 中没有内置的数据结构可以直接给我们提供这样的缓存。

但是我们可以从`HashMap`数据结构开始。在 Java 中，`HashMap`允许我们在 O(1)时间内按键插入和搜索（查找）数据。因此，使用`HashMap`解决了问题的一半。另一半，即跟踪最近使用的条目和长时间未使用的条目，无法通过`HashMap`完成。

然而，如果我们想象一个提供快速插入、更新和删除的数据结构，那么我们必须考虑双向链表。基本上，如果我们知道双向链表中节点的地址，那么插入、更新和删除可以在 O(1)时间内完成。

这意味着我们可以提供一个实现，它依赖于`HashMap`和双向链表之间的共生关系。基本上，对于 LRU 缓存中的每个条目（键值对），我们可以在`HashMap`中存储条目的键和关联链表节点的地址，而这个节点将存储条目的值。以下图表是对这一陈述的可视化表示：

![11.26：使用 HashMap 和双向链表的 LRU 缓存](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_11.26_B15403.jpg)

图 11.26 - 使用 HashMap 和双向链表的 LRU 缓存

但是双向链表如何帮助我们跟踪最近使用的条目呢？秘密在于以下几点：

+   在缓存中插入新条目将导致将相应的节点添加到双向链表的头部（因此，双向链表的头部保存了最近使用的值）。

+   当访问一个条目时，我们将其对应的节点移动到双向链表的头部。

+   当我们需要驱逐一个条目时，我们驱逐双向链表的尾部（因此，双向链表的尾部保存了最近最少使用的值）。

基于这些陈述，我们可以提供以下直接的实现：

```java
public final class LRUCache {
  private final class Node {
    private int key;
    private int value;
    private Node next;
    private Node prev;
  }
  private final Map<Integer, Node> hashmap;
  private Node head;
  private Node tail;
  // 5 is the maximum size of the cache
  private static final int LRU_SIZE = 5;
  public LRUCache() {
    hashmap = new HashMap<>();
  }
  public int getEntry(int key) {
    Node node = hashmap.get(key);
    // if the key already exist then update its usage in cache
    if (node != null) {
      removeNode(node);
      addNode(node);
      return node.value;
    }
    // by convention, data not found is marked as -1
    return -1;
  }
  public void putEntry(int key, int value) {
    Node node = hashmap.get(key);
    // if the key already exist then update 
    // the value and move it to top of the cache                 
    if (node != null) { 
      node.value = value;
      removeNode(node);
      addNode(node);
    } else {
      // this is new key
      Node newNode = new Node();
      newNode.prev = null;
      newNode.next = null;
      newNode.value = value;
      newNode.key = key;
      // if we reached the maximum size of the cache then 
      // we have to remove the  Least Recently Used
      if (hashmap.size() >= LRU_SIZE) { 
        hashmap.remove(tail.key);
        removeNode(tail);
        addNode(newNode);
      } else {
        addNode(newNode);
      }
      hashmap.put(key, newNode);
    }
  }
  // helper method to add a node to the top of the cache
  private void addNode(Node node) {
    node.next = head;
    node.prev = null;
    if (head != null) {
      head.prev = node;
    }
    head = node;
    if (tail == null) {
      tail = head;
    }
  }
  // helper method to remove a node from the cache
  private void removeNode(Node node) {
    if (node.prev != null) {
      node.prev.next = node.next;
    } else {
      head = node.next;
    }
    if (node.next != null) {
      node.next.prev = node.prev;
    } else {
      tail = node.prev;
    }
  }   
}
```

完整的应用程序名为*LRUCache*。

好了，这是本章的最后一个编码挑战。是时候总结本章了！

# 摘要

本章引起了您对涉及链表和映射的最常见问题的注意。在这些问题中，首选涉及单向链表的问题；因此，本章主要关注了这一类编码挑战。

在下一章中，我们将解决与堆栈和队列相关的编码挑战。


# 第十二章：栈和队列

本章涵盖了涉及栈和队列的最受欢迎的面试编码挑战。主要是，您将学习如何从头开始提供栈/队列实现，以及如何通过 Java 的内置实现来解决编码挑战，例如`Stack`类和`Queue`接口实现，特别是`ArrayDeque`。通常，此类别的编码挑战将要求您构建栈/队列，或者要求您使用 Java 的内置实现解决特定问题。根据问题的不同，它可能明确禁止您调用某些内置方法，这将导致您找到一个简单的解决方案。

通过本章结束时，您将深入了解栈和队列，能够利用它们的功能，并且能够识别和编写依赖于栈和队列的解决方案。

在本章中，您将学习以下主题：

+   概述栈

+   概述队列

+   编码挑战

让我们首先简要介绍栈的数据结构。

# 技术要求

本章中提供的所有代码文件都可以在 GitHub 上找到，网址为[`github.com/PacktPublishing/The-Complete-Coding-Interview-Guide-in-Java/tree/master/Chapter12`](https://github.com/PacktPublishing/The-Complete-Coding-Interview-Guide-in-Java/tree/master/Chapter12)。

# 概述栈

栈是一种使用**后进先出**（**LIFO**）原则的线性数据结构。想象一堆需要清洗的盘子。您从顶部取出第一个盘子（最后添加的盘子），然后清洗它。然后，您从顶部取出下一个盘子，依此类推。这正是现实生活中的栈（例如，一堆盘子，一堆书，一堆 CD 等）。

因此，从技术上讲，在栈中，元素只能从一端添加（称为**push**操作）和移除（称为**pop**操作）（称为**top**）。

在栈中执行的最常见操作如下：

+   `push(E e)`: 将元素添加到栈的顶部

+   `E pop()`: 移除栈顶的元素

+   `E peek()`: 返回（但不移除）栈顶的元素

+   `boolean isEmpty()`: 如果栈为空则返回`true`

+   `int size()`: 返回栈的大小

+   `boolean isFull()`: 如果栈已满则返回`true`

与数组不同，栈不以常数时间提供对第 n 个元素的访问。但是，它确实提供了添加和移除元素的常数时间。栈可以基于数组甚至基于链表实现。这里使用的实现是基于数组的，并命名为`MyStack`。该实现的存根如下所示：

```java
public final class MyStack<E> {
  private static final int DEFAULT_CAPACITY = 10;
  private int top;
  private E[] stack;
  MyStack() {
    stack = (E[]) Array.newInstance(
             Object[].class.getComponentType(), 
             DEFAULT_CAPACITY);
    top = 0; // the initial size is 0
  }
  public void push(E e) {}
  public E pop() {}
  public E peek() {}
  public int size() {}
  public boolean isEmpty() {}
  public boolean isFull() {}
  private void ensureCapacity() {}
}
```

将元素推入栈意味着将该元素添加到基础数组的末尾。在推入元素之前，我们必须确保栈不是满的。如果满了，我们可以通过消息/异常来表示这一点，或者我们可以增加其容量，如下所示：

```java
// add an element 'e' in the stack
public void push(E e) {
  // if the stack is full, we double its capacity
  if (isFull()) {
    ensureCapacity();
  }
  // adding the element at the top of the stack
  stack[top++] = e;
}
// used internally for doubling the stack capacity
private void ensureCapacity() {
  int newSize = stack.length * 2;
  stack = Arrays.copyOf(stack, newSize);
}
```

如您所见，每当我们达到栈的容量时，我们都会将其大小加倍。从栈中弹出一个元素意味着我们返回最后添加到基础数组中的元素。通过将最后一个索引置空来从基础数组中移除该元素，如下所示：

```java
// pop top element from the stack
public E pop() {
  // if the stack is empty then just throw an exception
  if (isEmpty()) {
    throw new EmptyStackException();
  }
  // extract the top element from the stack                
  E e = stack[--top];
  // avoid memory leaks
  stack[top] = null;
  return e;
}
```

从栈中查看元素意味着返回最后添加到基础数组中的元素，但不从该数组中移除它：

```java
// return but not remove the top element in the stack
public E peek() {
  // if the stack is empty then just throw an exception
  if (isEmpty()) {
    throw new EmptyStackException();
  }
  return stack[top - 1];
}
```

由于此实现可能代表您在面试中可能遇到的编码挑战，建议您花时间分析其代码。完整的应用程序称为*MyStack*。

# 概述队列

队列是一种使用**先进先出**（**FIFO**）原则的线性数据结构。想象排队购物的人。您还可以想象成蚂蚁在队列中行走。

因此，从技术上讲，元素的移除顺序与它们添加的顺序相同。在队列中，添加到一端的元素称为后端（这个操作称为入队操作），从另一端移除的元素称为前端（这个操作称为出队或轮询操作）。

队列中的常见操作如下：

+   `enqueue(E e)`: 将元素添加到队列的末尾

+   `E dequeue()`: 删除并返回队列前面的元素

+   `E peek()`: 返回（但不删除）队列前面的元素

+   `boolean isEmpty()`: 如果队列为空则返回`true`

+   `int size()`: 返回队列的大小

+   `boolean isFull()`：如果队列已满则返回`true`

与数组不同，队列不提供以常量时间访问第 n 个元素的功能。但是，它确实提供了添加和删除元素的常量时间。队列可以基于数组实现，甚至可以基于链表或堆栈（堆栈是基于数组或链表构建的）实现。这里使用的实现是基于数组的，并且命名为`MyQueue`。这个实现的存根在这里列出：

```java
public final class MyQueue<E> {
  private static final int DEFAULT_CAPACITY = 10;
  private int front;
  private int rear;
  private int count;
  private int capacity;
  private E[] queue;
  MyQueue() {
    queue = (E[]) Array.newInstance(
                Object[].class.getComponentType(), 
                DEFAULT_CAPACITY);
  count = 0; // the initial size is 0
  front = 0;
  rear = -1;
  capacity = DEFAULT_CAPACITY;
  }
  public void enqueue(E e) {}
  public E dequeue() {}
  public E peek() {}
  public int size() {}
  public boolean isEmpty() {}
  public boolean isFull() {}
  private void ensureCapacity() {}
} 
```

将元素加入队列意味着将该元素添加到底层数组的末尾。在将元素加入队列之前，我们必须确保队列不是满的。如果满了，我们可以通过消息/异常来表示，或者我们可以增加其容量，如下所示：

```java
// add an element 'e' in the queue
public void enqueue(E e) {
  // if the queue is full, we double its capacity
  if (isFull()) {
    ensureCapacity();
  }
  // adding the element in the rear of the queue
  rear = (rear + 1) % capacity;
  queue[rear] = e;
  // update the size of the queue
  count++;
}
// used internally for doubling the queue capacity
private void ensureCapacity() {       
  int newSize = queue.length * 2;
  queue = Arrays.copyOf(queue, newSize);
  // setting the new capacity
  capacity = newSize;
}
```

从队列中出列一个元素意味着从底层数组的开头返回下一个元素。该元素从数组中删除：

```java
// remove and return the front element from the queue
public E dequeue() {
  // if the queue is empty we just throw an exception
  if (isEmpty()) {
    throw new EmptyStackException();
  }
  // extract the element from the front
  E e = queue[front];
  queue[front] = null;
  // set the new front
  front = (front + 1) % capacity;
  // decrease the size of the queue
  count--;
  return e;
}
```

从队列中窥视一个元素意味着从底层数组的开头返回下一个元素，而不将其从数组中删除：

```java
// return but not remove the front element in the queue
public E peek() {
  // if the queue is empty we just throw an exception
  if (isEmpty()) {
    throw new EmptyStackException();
  }
  return queue[front];
}
```

由于这个实现可以代表你在面试中可能遇到的编码挑战，建议你花时间来分析它的代码。完整的应用程序称为*MyQueue*。

# 编码挑战

在接下来的 11 个编码挑战中，我们将涵盖在过去几年中出现在面试中的涉及栈和队列的最流行问题，这些问题涉及到各种雇佣 Java 开发人员的公司。其中最常见的问题之一，*使用一个数组实现三个栈*，在*第十章**，数组和字符串*中有所涉及。

以下编码挑战的解决方案依赖于 Java 内置的`Stack`和`ArrayDeque`API。所以，让我们开始吧！

## 编码挑战 1 - 反转字符串

**问题**：假设你有一个字符串。使用堆栈将其反转。

**解决方案**：使用堆栈反转字符串可以按以下方式完成：

1.  从左到右循环字符串，并将每个字符推入堆栈。

1.  循环堆栈并逐个弹出字符。每个弹出的字符都放回字符串中。

基于这两个步骤的代码如下：

```java
public static String reverse(String str) {
  Stack<Character> stack = new Stack();
  // push characters of the string into the stack
  char[] chars = str.toCharArray();
  for (char c : chars) {
    stack.push(c);
  }
  // pop all characters from the stack and
  // put them back to the input string
  for (int i = 0; i < str.length(); i++) {
    chars[i] = stack.pop();
  }
  // return the string
  return new String(chars);
}
```

完整的应用程序称为*StackReverseString*。

## 编码挑战 2 - 大括号堆栈

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

包含大括号的字符串。编写一小段代码，如果有匹配的大括号对，则返回`true`。如果我们可以找到适当顺序的闭合大括号来匹配开放的大括号，那么我们可以说有一个匹配的对。例如，包含匹配对的字符串如下：{{{}}}{}{{}}。

`false`。其次，如果它们的数量相等，则它们必须按适当的顺序；否则，我们返回`false`。按适当的顺序，我们理解最后打开的大括号是第一个关闭的，倒数第二个是第二个关闭的，依此类推。如果我们依赖于堆栈，那么我们可以详细说明以下算法：

1.  对于给定字符串的每个字符，做出以下决定之一：

a. 如果字符是一个开放的大括号，{，那么将其放入堆栈。

b. 如果字符是闭合大括号，}，则执行以下操作：

i. 检查堆栈顶部，如果是{，则弹出并将其移动到下一个字符。

ii. 如果不是{，则返回`false`。

1.  如果堆栈为空，则返回`true`（我们找到了所有配对）；否则返回`false`（堆栈包含不匹配的大括号）。

将这些步骤转化为代码，结果如下：

```java
public static boolean bracesMatching(String bracesStr) {
  Stack<Character> stackBraces = new Stack<>();
  int len = bracesStr.length();
  for (int i = 0; i < len; i++) {
    switch (bracesStr.charAt(i)) {
      case '{':
        stackBraces.push(bracesStr.charAt(i));
        break;
      case '}':
        if (stackBraces.isEmpty()) { // we found a mismatch
          return false;
        }
        // for every match we pop the corresponding '{'
        stackBraces.pop(); 
        break;
      default:
        return false;
    }
  }
  return stackBraces.empty();
}
```

完整的应用程序称为*StackBraces*。通过实现类似的问题，但是对于多种类型的括号（例如，在相同的给定字符串中允许(){}[]），来挑战自己。

## 编程挑战 3 - 堆叠盘

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

`push()`和`pop()`方法将像单个堆栈一样工作。另外，编写一个`popAt(int stackIndex)`方法，它会从堆栈中弹出一个值，如`stackIndex`所示。

**解决方案**：我们知道如何处理单个堆栈，但是如何将多个堆栈链接在一起呢？嗯，既然我们需要*链接*，那么链表怎么样？如果链表中每个节点都包含一个堆栈，那么节点的下一个指针将指向下一个堆栈。以下图表可视化了这个解决方案：

![图 12.1 - 堆栈的链表](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_12.1_B15403.jpg)

图 12.1 - 堆栈的链表

每当当前堆栈容量超过时，我们就创建一个新节点并将其附加到链表中。Java 的内置链表（`LinkedList`）通过`getLast()`方法使我们可以访问最后一个节点。换句话说，通过`LinkedList#getLast()`，我们可以轻松操作当前堆栈（例如，我们可以推送或弹出一个元素）。通过`LinkedList#add()`方法很容易添加一个新的堆栈。基于这些语句，我们可以实现`push()`方法，如下所示：

```java
private static final int STACK_SIZE = 3;
private final LinkedList<Stack<Integer>> stacks 
  = new LinkedList<>();
public void push(int value) {
  // if there is no stack or the last stack is full
  if (stacks.isEmpty() || stacks.getLast().size()
      >= STACK_SIZE) {
    // create a new stack and push the value into it
    Stack<Integer> stack = new Stack<>();
    stack.push(value);
    // add the new stack into the list of stacks
    stacks.add(stack);
  } else {
    // add the value in the last stack
    stacks.getLast().push(value);
  }
}
```

如果我们想要弹出一个元素，那么我们必须从最后一个堆栈中这样做，所以`LinkedList#getLast()`在这里非常方便。这里的特殊情况是当我们从最后一个堆栈中弹出最后一个元素时。当这种情况发生时，我们必须删除最后一个堆栈，在这种情况下，倒数第二个（如果有的话）将成为最后一个。以下代码说明了这一点：

```java
public Integer pop() {
  // find the last stack
  Stack<Integer> lastStack = stacks.getLast();
  // pop the value from the last stack
  int value = lastStack.pop();
  // if last stack is empty, remove it from the list of stacks
  removeStackIfEmpty();
  return value;
}
private void removeStackIfEmpty() {
  if (stacks.getLast().isEmpty()) {
      stacks.removeLast();
  }
}
```

最后，让我们专注于实现`popAt(int stackIndex)`方法。我们可以通过简单调用`stacks.get(stackIndex).pop()`从`stackIndex`堆栈中弹出。一旦我们弹出一个元素，我们必须移动剩余的元素。下一个堆栈的底部元素将成为由`stackIndex`指向的堆栈的顶部元素，依此类推。如果最后一个堆栈包含单个元素，则移动其他元素将消除最后一个堆栈，并且其前面的堆栈将成为最后一个堆栈。让我们通过代码来看一下：

```java
public Integer popAt(int stackIndex) {
  // get the value from the correspondind stack
  int value = stacks.get(stackIndex).pop();
  // pop an element -> must shift the remaining elements        
  shift(stackIndex);
  // if last stack is empty, remove it from the list of stacks
  removeStackIfEmpty();
  return value;
}
private void shift(int index) {
  for (int i = index; i<stacks.size() - 1; ++i) {
    Stack<Integer> currentStack = stacks.get(i);
    Stack<Integer> nextStack = stacks.get(i + 1);
    currentStack.push(nextStack.remove(0));
  }
}
```

完整的应用程序称为*StackOfPlates*。

## 编程挑战 4 - 股票跨度

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

**问题**：假设你已经获得了一个单一股票连续多天的价格数组。股票跨度由前几天（今天）的股票价格小于或等于当前天（今天）的股票价格的天数表示。例如，考虑股票价格覆盖 10 天的情况；即{55, 34, 22, 23, 27, 88, 70, 42, 51, 100}。结果的股票跨度是{1, 1, 1, 2, 3, 6, 1, 1, 2, 10}。注意，对于第一天，股票跨度始终为 1。编写一小段代码，计算给定价格列表的股票跨度。

**解决方案**：我们可以从给定的示例开始，尝试将其可视化，如下所示：

![图 12.2 - 10 天的股票跨度](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_12.2_B15403.jpg)

图 12.2 - 10 天的股票跨度

从前面的图表中，我们可以观察到以下内容：

+   对于第一天，跨度始终为 1。

+   对于第 2 天，价格为 34。由于 34 小于前一天（55）的价格，第 2 天的股票跨度也是 1。

+   对于第 3 天，价格为 22。由于 22 小于前一天（34）的价格，第 3 天的股票跨度也是 1。第 7 天和第 8 天也属于同样的情况。

+   对于第 4 天，价格是 23。由于 23 大于前一天的价格（22），但小于第 2 天的价格，所以股票跨度为 2。第 9 天与第 4 天类似。

+   对于第 5 天，价格是 27。由于这个价格大于第 3 天和第 4 天的价格，但小于第 2 天的价格，所以股票跨度为 3。

+   对于第 6 天，价格是 88。这是迄今为止最高的价格，所以股票跨度是 6。

+   对于第 10 天，价格是 100。这是迄今为止最高的价格，所以股票跨度是 10。

注意，我们计算当前天的股票跨度，是当前天的索引与对应于最后一个最大股价的那一天的索引之间的差。在追踪这种情况之后，我们可能会有这样的第一个想法：对于每一天，扫描它之前的所有天，直到股价大于当前天。换句话说，我们使用了蛮力方法。正如我在本书中早些时候提到的，蛮力方法应该在面试中作为最后的手段使用，因为它的性能较差，面试官不会感到印象深刻。在这种情况下，蛮力方法的时间复杂度为 O(n2)。

然而，让我们换个角度来思考。对于每一天，我们想找到一个之前的一天，它的价格比当前天的价格高。换句话说，我们要找到最后一个价格比当前天的价格高的那一天。

在这里，我们应该选择一个后进先出的数据结构，它允许我们按降序推入价格并弹出最后推入的价格。一旦我们做到这一点，我们可以遍历每一天，并将栈顶的价格与当前天的价格进行比较。直到栈顶的价格小于当前天的价格，我们可以从栈中弹出。但是如果栈顶的价格大于当前天的价格，那么我们计算当前天的股票跨度，就是当前天和栈顶价格对应的那一天之间的天数差。如果我们按降序将价格推入栈中，这将起作用 - 最大的价格在栈顶。然而，由于我们可以将股票跨度计算为当前天的索引与对应于最后一个最大股价的那一天的索引之间的差（我们用`i`表示），我们可以简单地将`i`索引存储在栈中；`stackPrices[i]`（我们将价格数组表示为`stackPrices`）将返回第*i*天的股票价格。

这可以通过以下算法实现：

1.  第一天的股票跨度为 1，索引为 0 - 我们将这个索引推入栈中（我们将其表示为`dayStack`；因此，`dayStack.push(0)`）。

1.  我们循环剩余的天数（第 2 天的索引为 1，第 3 天的索引为 2，依此类推）并执行以下操作：

a. 当`stockPrices[i] > stockPrices[dayStack.peek()]`并且`!dayStack.empty()`时，我们从栈中弹出（`dayStack.pop()`）。

1.  如果`dayStack.empty()`，那么`i+1`的股票跨度。

1.  如果`stockPrices[i] <= stockPrices[dayStack.peek()]`，那么股票跨度就是`i - dayStack.peek()`。

1.  将当前天的索引`i`推入栈中（`dayStack`）。

让我们看看这个算法如何适用于我们的测试案例：

1.  第一天的股票跨度为 1，索引为 0 - 我们将这个索引推入栈中，`dayStack.push(0)`。

1.  对于第 2 天，`stockPrices[1]=34`，`stockPrices[0]=55`。由于 34 < 55，第 2 天的股票跨度为`i - dayStack.peek()` = 1 - 0 = 1。我们将 1 推入栈中，`dayStack.push(1)`。

1.  对于第三天，`stockPrices[2]`=22，`stockPrices[1]`=34。由于 22 < 34，第 3 天的股票跨度为 2 - 1 = 1。我们将 1 推入栈中，`dayStack.push(2)`。

1.  对于第 4 天，`stockPrices[3]`=23，`stockPrices[2]`=22。由于 23 > 22 并且栈不为空，我们弹出栈顶，所以我们弹出值 2。由于 23 < 34（`stockPrices[1]`），第 4 天的股票跨度为 3 - 1 = 2。我们将 3 推入栈中，`dayStack.push(3)`。

1.  对于第五天，`stockPrices[4]`=27 和 `stockPrices[3]`=23。由于 27 > 23 并且栈不为空，我们弹出栈顶，所以我们弹出值 3。接下来，27 < 34（记住我们在上一步弹出了值 2，所以下一个栈顶的值为 1），第 5 天的股票跨度为 4 - 1 = 3。我们在栈中推入 4，`dayStack.push(4)`。

1.  对于第六天，`stockPrices[5]`=88 和 `stockPrices[4]`=27。由于 88 > 27 并且栈不为空，我们弹出栈顶，所以我们弹出值 4。接下来，88 > 34 并且栈不为空，所以我们弹出值 1。接下来，88 > 55 并且栈不为空，所以我们弹出值 0。接下来，栈为空，第 6 天的股票跨度为 5 + 1 = 6。

好了，我想你已经明白了，现在，挑战自己，继续到第 10 天。目前，我们有足够的信息将这个算法转化为代码：

```java
public static int[] stockSpan(int[] stockPrices) {
  Stack<Integer> dayStack = new Stack();
  int[] spanResult = new int[stockPrices.length];
  spanResult[0] = 1; // first day has span 1
  dayStack.push(0);
  for (int i = 1; i < stockPrices.length; i++) {
    // pop until we find a price on stack which is 
    // greater than the current day's price or there 
    // are no more days left
    while (!dayStack.empty() 
      && stockPrices[i] > stockPrices[dayStack.peek()]) {
      dayStack.pop();
    }
    // if there is no price greater than the current 
    // day's price then the stock span is the numbers of days
    if (dayStack.empty()) {
        spanResult[i] = i + 1;
    } else {
      // if there is a price greater than the current 
      // day's price then the stock span is the 
      // difference between the current day and that day
        spanResult[i] = i - dayStack.peek();
    }
    // push current day onto top of stack
     dayStack.push(i);
  }
  return spanResult;
}
```

完整的应用程序称为 *StockSpan*。

## 编码挑战 5 – 栈最小值

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

`push()`、`pop()` 和 `min()` 方法应在 O(1) 时间内运行。

`push()` 和 `pop()` 在 O(1) 时间内运行。

符合问题约束的解决方案需要一个额外的栈来跟踪最小值。主要是，当推送的值小于当前最小值时，我们将这个值添加到辅助栈（我们将其表示为 `stackOfMin`）和原始栈中。如果从原始栈中弹出的值是 `stackOfMin` 的栈顶，则我们也从 `stackOfMin` 中弹出它。在代码方面，我们有以下内容：

```java
public class MyStack extends Stack<Integer> {
  Stack<Integer> stackOfMin;
  public MyStack() {
    stackOfMin = new Stack<>();
  }
  public Integer push(int value) {
    if (value <= min()) {
       stackOfMin.push(value);
    }
    return super.push(value);
  }
  @Override
  public Integer pop() {
    int value = super.pop();
    if (value == min()) {
       stackOfMin.pop();
    }
    return value;
  }
  public int min() {
   if (stackOfMin.isEmpty()) {
      return Integer.MAX_VALUE;
    } else {
      return stackOfMin.peek();
    }
  }
}
```

完成！我们的解决方案以 O(1) 复杂度时间运行。完整的应用程序称为 *MinStackConstantTime*。与此相关的一个问题要求您在常数时间和空间内实现相同的功能。这个问题的解决方案施加了几个限制，如下：

+   `pop()` 方法返回 `void`，以避免返回不正确的值。

+   给定值乘以 2 不应超出 `int` 数据类型的范围。

简而言之，这些限制是由解决方案本身造成的。我们不能使用额外的空间；因此，我们将使用初始值栈来存储最小值。此外，我们需要将给定值乘以 2，因此我们应确保不超出 `int` 范围。为什么我们需要将给定值乘以 2？

让我们来解释一下这个问题！假设我们需要将一个值推入一个具有特定最小值的栈中。如果这个值大于或等于当前最小值，那么我们可以简单地将它推入栈中。但是如果它小于最小值，那么我们推入 2**值-最小值*，这应该小于值本身。然后，我们将当前最小值更新为值。

当我们弹出一个值时，我们必须考虑两个方面。如果弹出的值大于或等于最小值，那么这是之前推送的真实值。否则，弹出的值不是推送的值。真正推送的值存储在最小值中。在我们弹出栈顶（最小值）之后，我们必须恢复先前的最小值。先前的最小值可以通过 2**最小值 - 栈顶* 获得。换句话说，由于当前栈顶是 2**值 - 先前的最小值*，而值是当前最小值，先前的最小值是 2**当前最小值 - 栈顶*。以下代码说明了这个算法：

```java
public class MyStack {
  private int min;
  private final Stack<Integer> stack = new Stack<>();
  public void push(int value) {
    // we don't allow values that overflow int/2 range
    int r = Math.addExact(value, value);
    if (stack.empty()) {
      stack.push(value);
      min = value;
    } else if (value > min) {
      stack.push(value);
    } else {
      stack.push(r - min);
      min = value;
    }
  }
  // pop() doesn't return the value since this may be a wrong   
  // value (a value that was not pushed by the client)!
  public void pop() {
    if (stack.empty()) {
      throw new EmptyStackException();
    }
    int top = stack.peek();
    if (top < min) {
      min = 2 * min - top;
    }
    stack.pop();
  }
  public int min() {
    return min;
  }
}
```

完整的应用程序称为 *MinStackConstantTimeAndSpace*。

## 编码挑战 6 – 通过栈实现队列

**谷歌**，**Adobe**，**微软**，**Flipkart**

**问题**：通过两个栈设计一个队列。

**解决方案**：为了找到这个问题的合适解决方案，我们必须从队列和栈之间的主要区别开始。我们知道队列按照先进先出的原则工作，而栈按照后进先出的原则工作。接下来，我们必须考虑主要的操作（推入、弹出和查看）并确定它们之间的区别。

它们都以相同的方式推送新元素。当我们将一个元素推入队列时，我们是从一端（队列的后端）推入的。当我们将一个元素推入栈时，我们是从栈的新顶部推入的，这可以被视为与队列的后端相同。

当我们从栈中弹出或查看一个值时，我们是从顶部这样做的。然而，当我们在队列上执行相同的操作时，我们是从前面这样做的。这意味着，当弹出或查看一个元素时，一个反转的栈将充当队列。以下图表说明了这一点：

![图 12.3 - 通过两个栈实现队列](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_12.3_B15403.jpg)

图 12.3 - 通过两个栈实现队列

因此，每个新元素都被推入*enqueue stack*作为新的顶部。当我们需要弹出或查看一个值时，我们使用*dequeue*栈，这是*enqueue stack*的反转版本。请注意，我们不必在每次弹出/查看操作时都反转*enqueue stack*。我们可以让元素停留在*dequeue stack*中，直到我们绝对必须反转元素。换句话说，对于每个弹出/查看操作，我们可以检查*dequeue stack*是否为空。只要*dequeue stack*不为空，我们就不需要反转*enqueue stack*，因为我们至少有一个元素可以弹出/查看。

让我们用代码来看一下：

```java
public class MyQueueViaStack<E> {
  private final Stack<E> stackEnqueue;
  private final Stack<E> stackDequeue;
  public MyQueueViaStack() {
    stackEnqueue = new Stack<>();
    stackDequeue = new Stack<>();
  }
  public void enqueue(E e) {
    stackEnqueue.push(e);
  }
  public E dequeue() {
    reverseStackEnqueue();
    return stackDequeue.pop();
  }
  public E peek() {
    reverseStackEnqueue();
    return stackDequeue.peek();
  }
  public int size() {
    return stackEnqueue.size() + stackDequeue.size();
  }
  private void reverseStackEnqueue() {
    if (stackDequeue.isEmpty()) {
      while (!stackEnqueue.isEmpty()) {
        stackDequeue.push(stackEnqueue.pop());
      }
    }
  }
}
```

完整的应用程序称为*QueueViaStack*。

## 编码挑战 7 - 通过队列实现栈

**Google**，**Adobe**，**Microsoft**

**问题**：设计一个通过两个队列实现的栈。

**解决方案**：为了找到这个问题的合适解决方案，我们必须从栈和队列之间的主要区别开始。我们知道栈是后进先出，而队列是先进先出。接下来，我们必须考虑主要操作（推入、弹出和查看）并确定它们之间的区别。

它们都以相同的方式推送新元素。当我们将一个元素推入栈时，我们是从栈的新顶部推入的。当我们将一个元素推入队列时，我们是从一端（队列的后端）推入的。队列的后端就像栈的顶部。

当我们从队列中弹出或查看一个值时，我们是从前面这样做的。然而，当我们在栈上执行相同的操作时，我们是从顶部这样做的。这意味着，当我们从充当栈的队列中弹出或查看一个元素时，我们需要轮询除最后一个元素之外的所有元素。最后一个元素就是我们弹出/查看的元素。以下图表说明了这一点：

![图 12.4 - 通过两个队列实现栈](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_12.4_B15403.jpg)

图 12.4 - 通过两个队列实现栈

正如前面的图表左侧所显示的，将一个元素推入栈和队列是一个简单的操作。前面图表的右侧显示了当我们想要从充当栈的队列中弹出/查看一个元素时会出现问题。主要是，在弹出/查看元素之前，我们必须将队列（在前面的图表中标记为*queue1*）中的元素（*rear*-1 和*front*之间）移动到另一个队列（在前面的图表中标记为*queue2*）。在前面的图表中，右侧，我们从*queue1*中轮询元素 2、5、3 和 1，并将它们添加到*queue2*中。接下来，我们从*queue1*中弹出/查看最后一个元素。如果我们弹出元素 6，那么*queue1*就会保持为空。如果我们查看元素 6，那么*queue1*就会保留这个元素。

现在，剩下的元素都在*queue2*中，所以为了执行另一个操作（推入、查看或弹出），我们有两个选项：

+   将*queue2*中剩余的元素移回*queue1*，恢复*queue1*。

+   使用*queue2*就像它是*queue1*一样，这意味着交替使用*queue1*和*queue2*。

在第二个选项中，我们避免了将*queue2*中的元素移回*queue1*的开销，目的是在*queue1*上执行下一个操作。虽然你可以挑战自己来实现第一个选项，但让我们更多地关注第二个选项。

如果我们考虑到我们应该使用的下一个操作的队列是不空的，那么可以交替使用*queue1*和*queue2*。由于我们在这两个队列之间移动元素，其中一个始终为空。因此，当我们查看一个元素时，会出现问题，因为查看操作不会移除元素，因此其中一个队列仍然保留该元素。由于没有一个队列是空的，我们不知道下一个操作应该使用哪个队列。解决方案非常简单：我们弹出最后一个元素，即使是对于查看操作，我们也将其存储为实例变量。随后的查看操作将返回此实例变量。推送操作将在推送给定值之前将此实例变量推回队列，并将此实例变量设置为`null`。弹出操作将检查此实例变量是否为`null`。如果不是`null`，那么这就是要弹出的元素。

让我们看看代码：

```java
public class MyStackViaQueue<E> {
  private final Queue<E> queue1;
  private final Queue<E> queue2;
  private E peek;
  private int size;
  public MyStackViaQueue() {
    queue1 = new ArrayDeque<>();
    queue2 = new ArrayDeque<>();
  }
  public void push(E e) {
    if (!queue1.isEmpty()) {
      if (peek != null) {
        queue1.add(peek);
      }
      queue1.add(e);
    } else {
      if (peek != null) {
        queue2.add(peek);
      }
      queue2.add(e);
    }
    size++;
    peek = null;
  }
  public E pop() {
    if (size() == 0) {
      throw new EmptyStackException();
    }
    if (peek != null) {
      E e = peek;
      peek = null;
      size--;
      return e;
    }
    E e;
    if (!queue1.isEmpty()) {
      e = switchQueue(queue1, queue2);
    } else {
      e = switchQueue(queue2, queue1);
    }
    size--;
    return e;
  }
  public E peek() {
    if (size() == 0) {
      throw new EmptyStackException();
    }
    if (peek == null) {
      if (!queue1.isEmpty()) {
        peek = switchQueue(queue1, queue2);
      } else {
        peek = switchQueue(queue2, queue1);
      }
    }
    return peek;
  }
  public int size() {
    return size;
  }
  private E switchQueue(Queue from, Queue to) {
    while (from.size() > 1) {
      to.add(from.poll());
    }
    return (E) from.poll();
  }
}
```

完整的应用程序称为*StackViaQueue*。

## 编码挑战 8 - 最大直方图面积

**亚马逊**，**谷歌**，**Adobe**，**微软**，**Flipkart**

**问题**：假设你已经得到了下图中显示的直方图：

![图 12.5 - 直方图，类间隔等于 1](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_12.5_B15403.jpg)

图 12.5 - 直方图，类间隔等于 1

我们将直方图定义为一个矩形条的图表，其中面积与某个变量的频率成比例。条的宽度称为直方图类间隔。例如，前面图像中的直方图的类间隔等于 1。有六个宽度均为 1，高度分别为 4、2、8、6、5 和 3 的条。

假设你已经得到了这些高度作为整数数组（这是问题的输入）。编写一小段代码，使用栈来计算直方图中最大的矩形区域。为了更好地理解这一点，下图突出显示了几个（不是全部）可以形成的矩形：

![图 12.6 - 直方图的矩形](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_12.6_B15403.jpg)

图 12.6 - 直方图的矩形

在前面的图像中，最大的矩形区域（即最大的矩形）是中间的一个，3 x 5 = 15。

**解决方案**：这个问题比起初看起来要困难得多。首先，我们需要分析给定的图像并制定几个声明。例如，非常重要的是要注意，只有当某个条的高度小于或等于该区域的高度时，该条才能成为矩形区域的一部分。此外，对于每个条，我们可以说，所有左侧高于当前条的条都可以与当前条形成一个矩形区域。同样，所有右侧高于当前条的条都可以与当前条形成一个矩形区域。

这意味着每个矩形区域由*左*和*右*边界限定，而(*右 - 左*) ** current_bar*给出了这个区域的值。我们应该计算所有可能的区域，并选择最高的区域作为我们实现的输出。以下图像突出显示了 3 x 5 矩形的左右边界：

![图 12.7 - 左右边界](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_12.7_B15403.jpg)

图 12.7 - 左右边界

请记住，我们必须使用栈来解决这个问题。现在我们有了一些可以引导我们解决问题的声明，是时候把栈引入讨论了。主要是，我们可以使用栈来计算左右边界。

我们从第一个条开始，将其索引（索引 0）推入栈中。我们继续处理剩下的条，并执行以下操作：

1.  重复*步骤 1a*、*1b*和*1c*，直到当前条小于栈顶部并且栈不为空：

a.我们弹出栈顶部。

b.我们计算左边界。

c. 我们计算可以在计算的左边界条和当前条之间形成的矩形区域的宽度。

d. 我们计算面积为计算的宽度乘以我们在*步骤 1a*中弹出的条的高度。

e. 如果这个区域比以前的大，那么我们存储这个区域。

1.  将当前条的索引推入栈中。

1.  重复从*步骤 1*直到每个条都被处理。

让我们看看代码方面的情况：

```java
public static int maxAreaUsingStack(int[] histogram) {
  Stack<Integer> stack = new Stack<>();
  int maxArea = 0;
  for (int bar = 0; bar <= histogram.length; bar++) {
    int barHeight;
    if (bar == histogram.length) {
      barHeight = 0; // take into account last bar
    } else {
      barHeight = histogram[bar];
    }
    while (!stack.empty() 
          && barHeight < histogram[stack.peek()]) {
      // we found a bar smaller than the one from the stack                
      int top = stack.pop();
      // find left boundary
      int left = stack.isEmpty() ? -1 : stack.peek();
      // find the width of the rectangular area 
      int areaRectWidth = bar - left - 1;
      // compute area of the current rectangle
      int area = areaRectWidth * histogram[top];
      maxArea = Integer.max(area, maxArea);
    }
    // add current bar (index) into the stack
    stack.push(bar);
  }        
  return maxArea;
}
```

这段代码的时间复杂度是 O(n)。此外，额外的空间复杂度是 O(n)。完整的应用程序称为*StackHistogramArea*。

## 编码挑战 9 - 最小数字

**问题**：考虑到你已经得到一个表示*n*位数的字符串。编写一小段代码，删除给定的*k*位数后打印出最小可能的数字。

**解决方案**：让我们假设给定的数字是*n*=4514327 和*k*=4。在这种情况下，删除四位数字后的最小数字是 127。如果*n*=2222222，那么最小数字是 222。

解决方案可以通过`Stack`和以下算法轻松实现：

1.  从左到右迭代给定的数字，逐位数字。

a. 只要给定的*k*大于 0，栈不为空，并且栈中的顶部元素大于当前遍历的数字：

i. 从栈中弹出顶部元素。

ii. 将*k*减 1。

b. 将当前数字推入栈中。

1.  当给定的*k*大于 0 时，执行以下操作（处理特殊情况，如 222222）：

a. 从栈中弹出元素。

b. 将*k*减 1。

在代码方面，我们有以下内容：

```java
public static void smallestAfterRemove(String nr, int k) {
  int i = 0;
  Stack<Character> stack = new Stack<>();
  while (i < nr.length()) {
    // if the current digit is less than the previous 
    // digit then discard the previous one
    while (k > 0 && !stack.isEmpty()
          && stack.peek() > nr.charAt(i)) {
      stack.pop();
      k--;
    }
    stack.push(nr.charAt(i));
    i++;
  }
  // cover corner cases such as '2222'
  while (k > 0) {
    stack.pop();
    k--;
  }
  System.out.println("The number is (as a printed stack; "
      + "ignore leading 0s (if any)): " + stack);
  }
}
```

完整的应用程序称为*SmallestNumber*。

## 编码挑战 10 - 岛屿

**亚马逊**，**Adobe**

**问题**：考虑到你已经得到一个包含只有 0 和 1 的*m*x*n*矩阵。按照惯例，1 表示陆地，0 表示水。编写一小段代码来计算岛屿的数量。岛屿被定义为由 0 包围的 1 组成的区域。

**解决方案**：让我们想象一个测试案例。以下是一个包含 6 个岛屿的 10x10 矩阵，分别标记为 1、2、3、4、5 和 6：

![图 12.8 - 10x10 矩阵中的岛屿](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_12.8_B15403.jpg)

图 12.8 - 10x10 矩阵中的岛屿

为了找到岛屿，我们必须遍历矩阵。换句话说，我们必须遍历矩阵的每个单元格。由于一个单元格由行（我们将其表示为*r*）和列（我们将其表示为*c*）来表示，我们观察到，从一个单元格(*r, c*)，我们可以朝八个方向移动：(*r-*1*, c-*1), (*r-*1*, c*), (*r-*1*, c+*1), (*r, c-*1), (*r, c+*1), (*r+*1*, c-*1), (*r+*1*, c*), 和 (*r+*1*, c+*1)。这意味着从当前单元格(*r, c*)，我们可以移动到(*r+ROW*[*k*]*, c+COL*[*k*])，只要`ROW`和`COL`是下面的数组，且 0 ≤ *k* ≤ 7：

```java
// top, right, bottom, left and 4 diagonal moves
private static final int[] ROW = {-1, -1, -1, 0, 1, 0, 1, 1};
private static final int[] COL = {-1, 1, 0, -1, -1, 1, 0, 1};
```

只要我们做到以下几点，移动到一个单元格就是有效的：

+   不要从网格上掉下来。

+   踩在代表陆地的单元格上（一个 1 的单元格）。

+   没有在该单元格之前。

为了确保我们不多次访问同一个单元格，我们使用一个布尔矩阵表示为`flagged[][]`。最初，这个矩阵只包含`false`的值，每次我们访问一个单元格(`r`, `c`)时，我们将相应的`flagged[r][c]`翻转为`true`。

以下是代码形式中的前三个要点：

```java
private static booleanisValid(int[][] matrix, 
      int r, int c, boolean[][] flagged) {
  return (r >= 0) && (r < flagged.length)
    && (c >= 0) && (c < flagged[0].length)
    && (matrix[r][c] == 1 && !flagged[r][c]);
}
```

到目前为止，我们知道如何决定从当前单元格移动到另一个单元格（从八个可能的移动中）。此外，我们必须定义一个算法来确定移动模式。我们知道从一个单元格(*r, c*)，我们可以在相邻单元格中的八个方向移动。因此，最方便的算法是尝试从当前单元格移动到所有有效的邻居，如下所示：

1.  从一个空队列开始。

1.  移动到一个有效的单元格(*r, c*)，将其入队，并标记为已访问 - 起始点应该是单元格(0, 0)。

1.  出队当前单元并解决其周围的八个相邻单元 - 解决单元意味着如果有效则将其入队并标记为已访问。

1.  重复*步骤 3*直到队列为空。当队列为空时，这意味着我们找到了一个岛屿。

1.  重复从*步骤 2*直到没有更多有效单元格。

在代码方面，我们有以下内容：

```java
private static class Cell {
  int r, c;
  public Cell(int r, int c) {
    this.r = r;
    this.c = c;
  }
}
// there are 8 possible movements from a cell    
private static final int POSSIBLE_MOVEMENTS = 8;
// top, right, bottom, left and 4 diagonal moves
private static final int[] ROW = {-1, -1, -1, 0, 1, 0, 1, 1};
private static final int[] COL = {-1, 1, 0, -1, -1, 1, 0, 1};
public static int islands(int[][] matrix) {
  int m = matrix.length;
  int n = matrix[0].length;
  // stores if a cell is flagged or not
  boolean[][] flagged = new boolean[m][n];
  int island = 0;
  for (int i = 0; i < m; i++) {
    for (int j = 0; j < n; j++) {
      if (matrix[i][j] == 1 && !flagged[i][j]) {
        resolve(matrix, flagged, i, j);
        island++;
      }
    }
  }
  return island;
}
private static void resolve(int[][] matrix, 
        boolean[][] flagged, int i, int j) {
  Queue<Cell> queue = new ArrayDeque<>();
  queue.add(new Cell(i, j));
  // flag source node
  flagged[i][j] = true;
  while (!queue.isEmpty()) {
    int r = queue.peek().r;
    int c = queue.peek().c;
    queue.poll();
    // check for all 8 possible movements from current 
    // cell and enqueue each valid movement
    for (int k = 0; k < POSSIBLE_MOVEMENTS; k++) {
      // skip this cell if the location is invalid
      if (isValid(matrix, r + ROW[k], c + COL[k], flagged)) {
        flagged[r + ROW[k]][c + COL[k]] = true;
        queue.add(new Cell(r + ROW[k], c + COL[k]));
      }
    }
  }
}
```

完整的应用程序称为*QueueIslands*。

## 编码挑战 11-最短路径

**亚马逊**，**谷歌**，**Adobe**

**问题**：假设给定一个只包含 0 和 1 的矩阵*m* x *n*。按照惯例，1 表示安全土地，而 0 表示不安全的土地。更准确地说，0 表示不应该被激活的传感器。此外，所有八个相邻的单元格都可以激活传感器。编写一小段代码，计算从第一列的任何单元格到最后一列的任何单元格的最短路径。您只能一次移动一步；向左、向右、向上或向下。结果路径（如果存在）应只包含值为 1 的单元格。

**解决方案**：让我们想象一个测试案例。以下是一个 10 x 10 的矩阵。

在下图的左侧，您可以看到给定的矩阵。请注意，值为 0 表示不应该被激活的传感器。在右侧，您可以看到应用程序使用的矩阵和可能的解决方案。这个矩阵是通过扩展传感器的覆盖区域从给定的矩阵中获得的。请记住，传感器的八个相邻单元格也可以激活传感器。解决方案从第一列（单元格（4,0））开始，以最后一列（单元格（9,9））结束，并包含 15 个步骤（从 0 到 14）。您可以在下图中看到这些步骤：

![图 12.9 - 给定矩阵（左侧）和解析矩阵（右侧）](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_12.9_B15403.jpg)

图 12.9 - 给定矩阵（左侧）和解析矩阵（右侧）

从坐标（*r，c*）的安全单元格，我们可以朝四个安全方向移动：（*r*-1*，c*），（*r，c*-1），（*r*+1*，c*）和（*r，c*+1）。如果我们将可能的移动视为方向（边）并将单元格视为顶点，则可以在图的上下文中可视化这个问题。边是可能的移动，而顶点是我们可以到达的可能单元格。每次移动都保持从当前单元格到起始单元格的距离（起始单元格是第一列的单元格）。对于每次移动，距离增加 1。因此，在图的上下文中，问题可以简化为在图中找到最短路径。因此，我们可以使用**广度优先搜索（BFS）**方法来解决这个问题。在*第十三章**，树和图*中，您已经了解了 BFS 算法的描述，并且另一个问题也是以与此处解决的问题相同的方式解决的- *国际象棋骑士*问题。

现在，根据前面问题提供的经验，我们可以详细说明这个算法：

1.  从一个空队列开始。

1.  将第一列的所有安全单元格入队，并将它们的距离设置为 0（这里，0 表示每个单元格到自身的距离）。此外，这些单元格被标记为已访问或标记。

1.  只要队列不为空，执行以下操作：

a. 弹出表示队列顶部的单元格。

b. 如果弹出的单元格是目的地单元格（即在最后一列），则简单地返回其距离（从目的地单元格到第一列源单元格的距离）。

c. 如果弹出的单元格不是目的地，则对该单元格的四个相邻单元格中的每一个，将每个有效单元格（安全且未访问）入队到队列中，并标记为已访问。

d. 如果我们处理了队列中的所有单元格但没有到达目的地，则没有解决方案。返回-1。

由于我们依赖 BFS 算法，我们知道所有最短路径为 1 的单元格首先被访问。接下来，被访问的单元格是具有最短路径为 1+1=2 等的相邻单元格。因此，具有最短路径的单元格等于其父级的最短路径+1。这意味着当我们第一次遍历目标单元格时，它给出了我们的最终结果。这就是最短路径。让我们看看代码中最相关的部分：

```java
private static int findShortestPath(int[][] board) {
  // stores if cell is visited or not
  boolean[][] visited = new boolean[M][N];
  Queue<Cell> queue = new ArrayDeque<>();
  // process every cell of first column
  for (int r1 = 0; r1 < M; r1++) {
    // if the cell is safe, mark it as visited and
    // enqueue it by assigning it distance as 0 from itself
    if (board[r1][0] == 1) {
      queue.add(new Cell(r1, 0, 0));
      visited[r1][0] = true;
    }
  }
  while (!queue.isEmpty()) {
    // pop the front node from queue and process it
    int rIdx = queue.peek().r;
    int cIdx = queue.peek().c;
    int dist = queue.peek().distance;
    queue.poll();
    // if destination is found then return minimum distance
    if (cIdx == N - 1) {
      return (dist + 1);
    }
    // check for all 4 possible movements from 
    // current cell and enqueue each valid movement
    for (int k = 0; k < 4; k++) {
      if (isValid(rIdx + ROW_4[k], cIdx + COL_4[k])
            && isSafe(board, visited, rIdx + ROW_4[k], 
                cIdx + COL_4[k])) {
        // mark it as visited and push it into 
        // queue with (+1) distance
        visited[rIdx + ROW_4[k]][cIdx + COL_4[k]] = true;
        queue.add(new Cell(rIdx + ROW_4[k], 
          cIdx + COL_4[k], dist + 1));
      }
    }
  }
  return -1;
}
```

完整的应用程序称为*ShortestSafeRoute*。

# 中缀、后缀和前缀表达式

前缀、后缀和中缀表达式在当今并不是一个非常常见的面试话题，但它可以被认为是任何开发人员至少应该涵盖一次的一个话题。以下是一个快速概述：

+   **前缀表达式**：这是一种表示法（代数表达式），用于编写算术表达式，其中操作数在其运算符之后列出。

+   **后缀表达式**：这是一种表示法（代数表达式），用于编写算术表达式，其中操作数在其运算符之前列出。

+   **中缀表达式**：这是一种表示法（代数表达式），通常用于算术公式或语句中，其中运算符写在其操作数之间。

如果我们有三个运算符 a、b 和 c，我们可以写出下图中显示的表达式：

![图 12.10 - 中缀、后缀和前缀](https://github.com/OpenDocCN/freelearn-java-zh/raw/master/docs/cpl-code-itw-gd-java/img/Figure_12.10_B15403.jpg)

图 12.10 - 中缀、后缀和前缀

最常见的问题涉及评估前缀和后缀表达式以及在前缀、中缀和后缀表达式之间进行转换。所有这些问题都有依赖于堆栈（或二叉树）的解决方案，并且在任何专门致力于基本算法的严肃书籍中都有涵盖。花些时间，收集一些关于这个主题的资源，以便熟悉它。由于这个主题在专门的书籍中得到了广泛的涵盖，并且在面试中并不常见，我们将不在这里进行涵盖。

# 摘要

本章涵盖了任何准备进行 Java 开发人员技术面试的候选人必须了解的堆栈和队列问题。堆栈和队列出现在许多实际应用中，因此掌握它们是面试官将测试您的顶级技能之一。

在下一章《树、Trie 和图形》中，您将看到堆栈和队列经常用于解决涉及树和图形的问题，这意味着它们也值得您的关注。
