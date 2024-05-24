# Go 高性能实用指南（二）

> 原文：[`zh.annas-archive.org/md5/CBDFC5686A090A4C898F957320E40302`](https://zh.annas-archive.org/md5/CBDFC5686A090A4C898F957320E40302)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：Go 中的 STL 算法等价物

许多来自其他高性能编程语言，特别是 C++的程序员，了解**标准模板库**（**STL**）的概念。该库提供了常见的编程数据结构和函数访问通用库，以便快速迭代和编写大规模的高性能代码。Go 没有内置的 STL。本章将重点介绍如何在 Go 中利用一些最常见的 STL 实践。STL 有四个常见的组件：

+   算法

+   容器

+   函数对象

+   迭代器

熟悉这些主题将帮助您更快、更有效地编写 Go 代码，利用常见的实现和优化模式。在本章中，我们将学习以下内容：

+   如何在 Go 中使用 STL 实践

+   如何在 Go 中利用标准编程算法

+   容器如何存储数据

+   Go 中函数的工作原理

+   如何正确使用迭代器

记住，所有这些部分仍然是我们性能拼图的一部分。知道何时使用正确的算法、容器或函数对象将帮助您编写性能更好的代码。

# 了解 STL 中的算法

STL 中的算法执行排序、搜索、操作和计数等功能。这些功能由 C++中的`<algorithm>`头文件调用，并用于元素范围。被修改的对象组不会影响它们所关联的容器的结构。这里每个小标题中概述的模式使用 Go 的语言结构来实现这些算法。本章的这一部分将解释以下类型的算法：

+   排序

+   逆转

+   最小和最大元素

+   二分搜索

能够理解所有这些算法的工作原理将帮助您在需要使用这些技术来操作数据结构时编写性能良好的代码。

# 排序

**sort**算法将数组按升序排序。排序不需要创建、销毁或复制新的容器——排序算法对容器中的所有元素进行排序。我们可以使用 Go 的标准库 sort 来实现这一点。Go 的标准库 sort 对不同的数据类型（`IntsAreSorted`、`Float64sAreSorted`和`StringsAreSorted`）有辅助函数来对它们进行排序。我们可以按照以下代码中所示的方式实现排序算法：

```go
package main
import (
    "fmt"
    "sort"
)
func main() {
    intData := []int{3, 1, 2, 5, 6, 4}
    stringData := []string{"foo", "bar", "baz"}
    floatData := []float64{1.5, 3.6, 2.5, 10.6}
```

这段代码使用值实例化简单的数据结构。之后，我们使用内置的`sort`函数对每个数据结构进行排序，如下所示：

```go

    sort.Ints(intData)
    sort.Strings(stringData)
    sort.Float64s(floatData)
    fmt.Println("Sorted Integers: ", intData, "\nSorted Strings:
      ", stringData, "\nSorted Floats: ", floatData)
}
```

当我们执行这个代码时，我们可以看到所有的切片都按顺序排序，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/f300c9de-491f-4a81-91f3-de0892136d22.png)

整数按从低到高排序，字符串按字母顺序排序，浮点数按从低到高排序。这些是`sort`包中的默认排序方法。

# 反转

**reverse**算法接受一个数据集并反转集合的值。Go 标准的`sort`包没有内置的反转切片的方法。我们可以编写一个简单的`reverse`函数来反转我们数据集的顺序，如下所示：

```go
package main

import (
  "fmt"
)

func reverse(s []string) []string {
  for x, y := 0, len(s)-1; x < y; x, y = x+1, y-1 {
    s[x], s[y] = s[y], s[x]
  }
  return s
}
func main() {
  s := []string{"foo", "bar", "baz", "go", "stop"}
  reversedS := reverse(s)
  fmt.Println(reversedS)
}
```

这个函数通过切片进行迭代，增加和减少`x`和`y`直到它们收敛，并交换切片中的元素，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/fecb8769-eec6-4e8f-b2a1-cb458c9f6ea3.png)

我们可以看到，我们的切片使用`reverse()`函数被反转。使用标准库可以使一个难以手动编写的函数变得简单、简洁和可重用。

# 最小元素和最大元素

我们可以使用`min_element`和`max_element`算法在数据集中找到最小和最大值。我们可以使用简单的迭代器在 Go 中实现`min_element`和`max_element`：

1.  首先，我们将编写一个函数来找到切片中最小的整数：

```go
package main

import "fmt"

func findMinInt(a []int) int {
  var minInt int = a[0]
  for _, i := range a {
    if minInt > i {
      minInt = i
    }
  }
  return minInt

}
```

1.  接下来，我们将按照相同的过程，尝试在切片中找到最大的整数：

```go
func findMaxInt(b []int) int {
  var max int = b[0]
  for _, i := range b {
    if max < i {
      max = i
    }
  }
  return max
}
```

1.  最后，我们将使用这些函数打印出最终的最小值和最大值：

```go
func main() {
  intData := []int{3, 1, 2, 5, 6, 4}
  minResult := findMinInt(intData)
  maxResult := findMaxInt(intData)
  fmt.Println("Minimum value in array: ", minResult)
  fmt.Println("Maximum value in array: ", maxResult)
}
```

这些函数遍历整数切片，并在切片中找到最小值和最大值，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/7ef9856d-ff05-4ca0-aaf3-d8aa36112563.png)

从我们的执行结果可以看出，找到了最小值和最大值。

在 Go 的`math`包中，我们还有`math.Min`和`math.Max`。这些仅用于比较`float64`数据类型。浮点数比较并不是一件容易的事情，因此 Go 的设计者决定将默认的`Min`和`Max`签名；在`math`库中，应该使用浮点数。如果 Go 有泛型，我们上面编写的主要函数可能适用于不同类型。这是 Go 语言设计的一部分——保持事情简单和集中。

# 二分查找

**二分查找**是一种用于在排序数组中查找特定元素位置的算法。它从数组中间元素开始。如果没有匹配，算法接下来取可能包含该项的数组的一半，并使用中间值来找到目标。正如我们在第二章中学到的，*数据结构和算法*，二分查找是一个高效的*O*(log *n*)算法。Go 标准库的`sort`包有一个内置的二分查找函数。我们可以这样使用它：

```go
package main

import (
  "fmt"
  "sort"
)

func main() {
  data := []int{1, 2, 3, 4, 5, 6}
  findInt := 2
  out := sort.Search(len(data), func(i int) bool { return data[i]
     >= findInt })
  fmt.Printf("Integer %d was found in %d at position %d\n",
     findInt, data, out)
}
```

二分查找算法正确地找到了我们正在搜索的整数值`2`，并且在预期位置（在零索引切片中的位置`1`）上。我们可以在以下屏幕截图中看到二分查找的执行：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/deb1ce15-a3ba-4e03-957f-7c347ea83fa7.png)

总之，STL 中的算法都很好地转换到了 Go 中。Go 的默认函数和迭代器使得组合简单、可重用的算法变得容易。在下一节中，我们将学习关于容器的知识。

# 理解容器

STL 中的容器分为三个独立的类别：

+   序列容器

+   序列容器适配器

+   关联容器

接下来，我们将在以下小节中介绍这三种类型的容器。

# 序列容器

序列容器存储特定类型的数据元素。目前有五种序列容器的实现：`array`、`vector`、`deque`、`list`和`forward_list`。这些序列容器使得以顺序方式引用数据变得容易。能够利用这些序列容器是编写有效代码和重用标准库中模块化部分的一个很好的捷径。我们将在以下小节中探讨这些内容。

# 数组

在 Go 中，**数组**类似于 C++中的数组。Go 的数组结构在编译时静态定义，不可调整大小。数组在 Go 中的实现方式如下：

```go
arrayExample := [5]string{"foo", "bar", "baz", "go", "rules"}
```

这个数组保存了在`arrayExample`变量中定义的字符串的值，该变量被定义为一个数组。

# 向量

Go 最初有一个**向量**的实现，但这在语言开发的早期就被移除了（2011 年 10 月 11 日）。人们认为切片更好（正如拉取请求的标题所说），切片成为了 Go 中的事实上的向量实现。我们可以这样实现一个切片：

```go
sliceExample := []string{"slices", "are", "cool", "in", "go"}
```

切片很有益，因为它们像 STL 中的向量一样，可以根据添加或删除而增长或缩小。在我们的示例中，我们创建一个切片，向切片附加一个值，并从切片中移除一个值，如下面的代码所示：

```go
package main

import "fmt"

// Remove i indexed item in slice
func remove(s []string, i int) []string {
  copy(s[i:], s[i+1:])
  return s[:len(s)-1]
}

func main() {
  slice := []string{"foo", "bar", "baz"} // create a slice
  slice = append(slice, "tri") // append a slice
  fmt.Println("Appended Slice: ", slice) // print slice [foo, bar baz, tri]
  slice = remove(slice, 2) // remove slice item #2 (baz)
  fmt.Println("After Removed Item: ", slice) // print slice [foo, bar, tri]
}
```

当我们执行我们的向量示例时，我们可以看到我们的附加和移除操作，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/e76ae808-21bd-4a85-ace9-d0627b4d30ae.png)

我们可以看到`tri`元素被附加到了我们的切片末尾，并且我们还可以看到基于我们的`remove()`函数调用，`baz`元素（切片中的第 3 个元素）被移除了。

# 双端队列

**双端队列**是一个可以扩展的容器。这些扩展可以发生在容器的前端或后端。当需要频繁引用队列的顶部或后部时，通常会使用双端队列。以下代码块是双端队列的简单实现：

```go
package main

import (
    "fmt"

    "gopkg.in/karalabe/cookiejar.v1/collections/deque"
)

func main() {
    d := deque.New()
    elements := []string{"foo", "bar", "baz"}
    for i := range elements {
        d.PushLeft(elements[i])
    }
    fmt.Println(d.PopLeft())  // queue => ["foo", "bar"]
    fmt.Println(d.PopRight()) // queue => ["bar"]
    fmt.Println(d.PopLeft())  // queue => empty
}
```

`deque`包接受一个元素的切片，并使用`PushLeft`函数将它们推送到队列上。接下来，我们可以从双端队列的左侧和右侧弹出元素，直到我们的队列为空。我们可以在以下截图中看到我们双端队列逻辑的执行：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/8f7cf55a-1bfc-4ddd-8621-72fdbb477ef1.png)

我们的结果显示了对双端队列的操作输出以及我们如何可以从队列的任一端取出东西。能够从队列的任一端取出东西在数据操作中是有优势的，这就是为什么双端队列是一种流行的数据结构选择。

# 列表

**列表**是 Go 语言中双向链表的实现。这是内置在标准库的 container/list 包中的。我们可以使用通用双向链表的实现执行许多操作，如下面的代码所示：

```go
package main

import (
    "container/list"
    "fmt"
)

func main() {
    ll := list.New()
    three := ll.PushBack(3)           // stack representation -> [3]
    four := ll.InsertBefore(4, three) // stack representation -> [4 3]
    ll.InsertBefore(2, three)         // stack representation ->
                                      //  [4 2 3]
    ll.MoveToBack(four)               // stack representation ->
                                      // [2 3 4]
    ll.PushFront(1)                   // stack representation ->
                                      //  [1 2 3 4]
    listLength := ll.Len()
    fmt.Printf("ll type: %T\n", ll)
    fmt.Println("ll length: :", listLength)
    for e := ll.Front(); e != nil; e = e.Next() {
        fmt.Println(e.Value)
    }
}
```

双向链表类似于双端队列容器，但如果需要，它允许在堆栈的中间进行插入和移除。双向链表在实践中使用得更多。我们可以在以下截图中看到我们双向链表代码的执行。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/a9cac75c-cea0-4d60-a222-dede65b5634b.png)

我们可以看到所有元素在程序输出中按照它们在堆栈上协调的顺序。链表是编程的基本要素，因为它们是当今计算机科学建立在其上的基本算法。

# 前向列表

**前向列表**是单向链表的实现。单向链表通常比双向链表具有更小的内存占用；然而，通过单向链表进行迭代不太好，特别是在反向方向上。让我们看看如何实现前向列表：

1.  首先，我们初始化我们的程序并定义我们的结构：

```go
package main

import "fmt"

type SinglyLinkedList struct {
    head *LinkedListNode
}

type LinkedListNode struct {
    data string
    next *LinkedListNode
}
```

1.  然后我们创建我们的`Append`函数并在我们的`main`函数中应用它：

```go

func (ll *SinglyLinkedList) Append(node *LinkedListNode) {
    if ll.head == nil {
        ll.head = node
        return
    }

    currentNode := ll.head
    for currentNode.next != nil {
        currentNode = currentNode.next
    }
    currentNode.next = node
}

func main() {
    ll := &SinglyLinkedList{}
    ll.Append(&LinkedListNode{data: "hello"})
    ll.Append(&LinkedListNode{data: "high"})
    ll.Append(&LinkedListNode{data: "performance"})
    ll.Append(&LinkedListNode{data: "go"})

    for e := ll.head; e != nil; e = e.next {
        fmt.Println(e.data)
    }
}
```

从以下截图的输出结果中可以看到，我们附加到我们的单链表的所有数据都是可访问的：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/eb95afd0-8331-4c4a-a236-2988b3672f40.png)

这个数据结构的初始元素按照它们在代码块中添加的顺序放入列表中。这是预期的，因为单向链表通常用于保持数据结构中的数据顺序。

# 容器适配器

**容器适配器**接受一个顺序容器并调整它的使用方式，以便原始顺序容器能够按照预期的方式运行。在研究这些容器适配器时，我们将学习它们是如何创建的，以及它们如何从实际的角度使用。

# 队列

**队列**是遵循**FIFO**队列方法或**先进先出**的容器。这意味着我们可以将东西添加到容器中，并从容器的另一端取出它们。我们可以通过向切片附加和出列来制作最简单形式的队列，如下面的代码所示：

```go
package main

import "fmt"

func main() {

    var simpleQueue []string
    simpleQueue = append(simpleQueue, "Performance ")
    simpleQueue = append(simpleQueue, "Go")

    for len(simpleQueue) > 0 {
        fmt.Println(simpleQueue[0])   // First element
        simpleQueue = simpleQueue[1:] // Dequeue
    }
    fmt.Println(simpleQueue) //All items are dequeued so result should be []
}
```

在我们的示例中，我们将字符串附加到我们的`simpleQueue`，然后通过移除切片的第一个元素来出列它们：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/4019bac0-03c1-48b9-b70d-8bc356bece3f.png)

在我们的输出中，我们可以看到我们正确地向队列添加了元素并将它们移除。

# 优先队列

**优先队列**是使用堆来保持容器中元素的优先列表的容器。优先队列很有帮助，因为可以按优先级对结果集进行排序。优先队列通常用于许多实际应用，从负载平衡 Web 请求到数据压缩，再到 Dijkstra 算法。

在我们的优先级队列示例中，我们创建了一个新的优先级队列，并插入了几种具有给定优先级的不同编程语言。我们从 Java 开始，它是第一个优先级，然后 Go 成为第一个优先级。添加了 PHP，Java 的优先级被推到 3。以下代码是优先级队列的一个示例。在这里，我们实例化了必要的要求，创建了一个新的优先级队列，向其中插入元素，改变了这些项的优先级，并从堆栈中弹出项：

```go
package main

import (
    "fmt"

    pq "github.com/jupp0r/go-priority-queue"
)

func main() {
    priorityQueue := pq.New()
    priorityQueue.Insert("java", 1)
    priorityQueue.Insert("golang", 1)
    priorityQueue.Insert("php", 2)
    priorityQueue.UpdatePriority("java", 3)
    for priorityQueue.Len() > 0 {
        val, err := priorityQueue.Pop()
        if err != nil {
            panic(err)
        }
        fmt.Println(val)
    }
}
```

在我们执行这个示例代码之后，我们可以看到基于我们设置的优先级队列值的语言的正确排序，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/fee330b8-41fd-4f84-bf6a-897163106ca2.png)

优先级队列是一种常用的重要数据结构。它们用于首先处理数据结构中最重要的元素，并且能够使用 STL 等效实现这一点有助于我们节省时间和精力，同时能够优先处理传入的请求。

# 堆栈

**堆栈**使用`push`和`pop`来添加和删除容器中的元素，用于对数据进行分组。堆栈通常具有**LIFO**（**后进先出**）的操作顺序，`Peek`操作通常允许您查看堆栈顶部的内容而不将其从堆栈中移除。堆栈非常适用于具有有限内存集的事物，因为它们可以有效地利用分配的内存。以下代码是堆栈的简单实现：

```go
package main

import (
    "fmt"

    stack "github.com/golang-collections/collections/stack"
)

func main() {
    // Create a new stack
    fmt.Println("Creating New Stack")
    exstack := stack.New()
    fmt.Println("Pushing 1 to stack")
    exstack.Push(1) // push 1 to stack
    fmt.Println("Top of Stack is : ", exstack.Peek())
    fmt.Println("Popping 1 from stack")
    exstack.Pop() // remove 1 from stack
    fmt.Println("Stack length is : ", exstack.Len())
}
```

我们可以从我们的程序输出中看到以下内容：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/b5668bbc-af83-441e-9686-3cba9578e963.png)

我们可以看到我们的堆栈操作按预期执行。能够使用堆栈操作在计算机科学中非常重要，因为这是许多低级编程技术执行的方式。

# 关联容器

**关联容器**是实现关联数组的容器。这些数组是有序的，只是在算法对它们的每个元素施加的约束上有所不同。STL 引用关联容器，即 set、map、multiset 和 multimap。我们将在以下部分探讨这些内容。

# 集合

**集合**用于仅存储键。Go 没有集合类型，因此经常使用`map`类型到布尔值的映射来构建集合。以下代码块是 STL 等效集合的实现：

```go
package main

import "fmt"

func main() {
    s := make(map[int]bool)

    for i := 0; i < 5; i++ {
        s[i] = true
    }

    delete(s, 4)

    if s[2] {
        fmt.Println("s[2] is set")
    }
    if !s[4] {
        fmt.Println("s[4] was deleted")
    }
}
```

结果输出显示我们能够设置和删除相应的值：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/7addd1b1-797a-4329-b59f-542ae2b6fb62.png)

从我们的输出中可以看出，我们的代码可以正确地操作集合，这对于常见的键-值对非常重要。

# 多重集

**多重集**是带有与每个元素关联的计数的无序集合。多重集可以进行许多方便的操作，例如取差集、缩放集合或检查集合的基数。

在我们的示例中，我们构建了一个多重集`x`，将其缩放为多重集`y`，验证`x`是否是`y`的子集，并检查`x`的基数。我们可以在以下代码中看到多重集的一个示例实现：

```go
package main

import (
    "fmt"

    "github.com/soniakeys/multiset"
)

func main() {
    x := multiset.Multiset{"foo": 1, "bar": 2, "baz": 3}
    fmt.Println("x: ", x)
    // Create a scaled version of x
    y := multiset.Scale(x, 2)
    fmt.Println("y: ", y)
    fmt.Print("x is a subset of y: ")
    fmt.Println(multiset.Subset(x, y))

    fmt.Print("Cardinality of x: ")
    fmt.Println(x.Cardinality())
}
```

当我们执行此代码时，我们可以看到`x`，`x`的缩放版本`y`的验证，以及`x`的基数计算。以下是我们多重集代码片段执行的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/1e1f8c99-6d59-49b1-a0e6-46cec4e2d93a.png)

多重集对于集合操作非常有用，并且非常方便，因为每个元素可以有多个实例。多重集的一个很好的实际例子是购物车——您可以向购物车中添加许多物品，并且您可以在购物车中拥有同一物品的多个计数。

# 映射

**映射**是一种用于存储键-值对的容器。Go 的内置`map`类型使用哈希表来存储键和它们关联的值。

在 Go 中，实例化映射很简单，如下所示：

```go
package main

import "fmt"

func main() {
    m := make(map[int]string)
    m[1] = "car"
    m[2] = "train"
    m[3] = "plane"
    fmt.Println("Full Map:\t ", m)
    fmt.Println("m[3] value:\t ", m[3])
    fmt.Println("Length of map:\t ", len(m))
}
```

现在让我们来看一下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/4851a8a9-75ea-4ead-9a1a-5c545d7e85eb.png)

在前面的执行结果中，我们可以看到我们可以创建一个映射，通过使用它的键引用映射中的值，并使用`Len()`内置类型找到我们映射中的元素数量。

# 多重映射

**多重映射**是一个可以返回一个或多个值的映射。多重映射的一个实际应用是 Web 查询字符串。查询字符串可以将多个值分配给相同的键，就像我们在下面的示例 URL 中看到的那样：`https://www.example.com/?foo=bar&foo=baz&a=b`。

在我们的例子中，我们将创建一个汽车的多重映射。我们的`car`结构体每辆车都有一个年份和一个风格。我们将能够聚合这些不同类型。以下代码片段是一个多重映射的实现：

```go
package main

import (
    "fmt"

    "github.com/jwangsadinata/go-multimap/slicemultimap"
)

type cars []struct {
    year  int
    style string
}

func main() {

    newCars := cars{{2019, "convertible"}, {1966, "fastback"}, {2019, "SUV"}, {1920, "truck"}}
    multimap := slicemultimap.New()

    for _, car := range newCars {
        multimap.Put(car.year, car.style)
    }

    for _, style := range multimap.KeySet() {
        color, _ := multimap.Get(style)
        fmt.Printf("%v: %v\n", style, color)
    }
}
```

我们有多个版本的汽车，有一个`2019`年的车型（敞篷车和 SUV）。在我们的输出结果中，我们可以看到这些值被聚合在一起：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/c9e210b0-fd35-4fc8-b8f8-9e5d3d55f297.png)

当你想要在映射中捕获一对多的关联时，多重映射是非常有用的。在下一节中，我们将看看函数对象。

# 理解函数对象

**函数对象**，也称为**函子**，用于生成、测试和操作数据。如果将一个对象声明为函子，你可以像使用函数调用一样使用该对象。通常情况下，STL 中的算法需要一个参数来执行它们指定的任务。函子往往是一种有用的方式来帮助执行这些任务。在本节中，我们将学习以下内容：

+   函子

+   内部和外部迭代器

+   生成器

+   隐式迭代器

# 函子

**函子**是一种函数式编程范式，它在保持结构的同时对结构执行转换。

在我们的例子中，我们取一个整数切片`intSlice`，并将该切片提升为一个函子。`IntSliceFunctor`是一个包括以下内容的接口：

+   `fmt.Stringer`，它定义了值的字符串格式及其表示。

+   `Map(fn func(int int) IntSliceFunctor` – 这个映射将`fn`应用到我们切片中的每个元素。

+   一个方便的函数，`Ints() []int`，它允许你获取函子持有的`int`切片。

在我们有了我们的提升切片之后，我们可以对我们新创建的函子执行操作。在我们的例子中，我们执行了一个平方操作和一个模三操作。以下是一个函子的示例实现：

```go
package main                                                                                                                                

import (
    "fmt"

    "github.com/go-functional/core/functor"
)

func main() {
    intSlice := []int{1, 3, 5, 7}
    fmt.Println("Int Slice:\t", intSlice)
    intFunctor := functor.LiftIntSlice(intSlice)
    fmt.Println("Lifted Slice:\t", intFunctor)

    // Apply a square to our given functor
    squareFunc := func(i int) int {
        return i * i 
    }   

    // Apply a mod 3 to our given functor
    modThreeFunc := func(i int) int {
        return i % 3 
    }   

    squared := intFunctor.Map(squareFunc)
    fmt.Println("Squared: \t", squared)

    modded := squared.Map(modThreeFunc)
    fmt.Println("Modded: \t", modded)
}
```

在执行这段代码时，我们可以看到我们的函子对函数操作的处理符合预期。我们取出了我们的初始`intSlice`，将它提升为一个函子，用`squareFunc`对每个值应用了平方，并用`modThreeFunc`对每个值应用了`%3`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/894922cf-f5cd-4fdb-bdc0-3d3673dc0c35.png)

函子是一种非常强大的语言构造。函子以一种易于修改的方式抽象了一个容器。它还允许关注点的分离——例如，你可以将迭代逻辑与计算逻辑分开，函子可以更简单地进行参数化，函子也可以是有状态的。

# 迭代器

我们在第三章中讨论了迭代器，*理解并发*。迭代器是允许遍历列表和其他容器的对象。迭代器通常作为容器接口的一部分实现，这对程序员来说是一个重要的方法。它们通常被分为以下类别：

+   内部迭代器

+   外部迭代器

+   生成器

+   隐式迭代器

我们将在接下来的章节中更详细地讨论这些类别是什么。

# 内部迭代器

**内部迭代器**表示为高阶函数（通常使用匿名函数，正如我们在第三章中所见，*理解并发*）。高阶函数将函数作为参数并返回函数作为输出。匿名函数是不绑定标识符的函数。

内部迭代器通常映射到将函数应用于容器中的每个元素。这可以由变量标识符表示，也可以匿名表示。语言的作者曾提到在 Go 语言中可以使用 apply/reduce，但不应该使用（这是因为在 Go 语言中通常更喜欢使用`for`循环）。这种模式符合 Go 语言的座右铭*简单胜于巧妙*。

# 外部迭代器

外部迭代器用于访问对象中的元素并指向对象中的下一个元素（分别称为元素访问和遍历）。Go 语言大量使用`for`循环迭代器。`for`循环是 Go 语言唯一的自然循环结构，并极大简化了程序构建。`for`循环就像下面这样简单：

```go
package main

import "fmt"

func main() {
    for i := 0; i < 5; i++ {
        fmt.Println("Hi Gophers!")
    }
}
```

我们可以看到我们的输出如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/12e62017-4ec8-4562-9e54-15c3dac96969.png)

我们的`for`循环迭代器很简单，但证明了一个重要观点——有时，简单对于复杂的问题集也能起到预期的作用。

# 生成器

**生成器**在调用函数时返回序列中的下一个值。如下面的代码块所示，匿名函数可以用于在 Go 语言中实现生成器迭代器模式：

```go
package main

import "fmt"

func incrementCounter() func() int {
    initializedNumber := 0
    return func() int {
        initializedNumber++
        return initializedNumber
    }   
}

func main() {
    n1 := incrementCounter()
    fmt.Println("n1 increment counter #1: ", n1())
    fmt.Println("n1 increment counter #2: ", n1())
    n2 := incrementCounter()
    fmt.Println("n2 increment counter #1: ", n2())
    fmt.Println("n1 increment counter #3: ", n1())
}
```

当调用`incrementCounter()`时，函数中表示的整数会递增。能够以这种方式并发使用匿名函数对许多从其他语言转到 Go 语言的程序员来说是一个很大的吸引点。它为利用语言的并发提供了简洁的方法。

# 隐式迭代器

**隐式迭代器**为程序员提供了一种简单的方法来迭代容器中存储的元素。这通常是使用 Go 语言中的内置 range 创建的。内置的 range 允许您遍历容器。以下是实现隐式迭代器的代码片段：

```go
package main

import "fmt"

func main() {
    stringExample := []string{"foo", "bar", "baz"}
    for i, out := range stringExample {
        fmt.Println(i, out)
    }
}
```

我们可以看到以下结果输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/d46622c2-5514-4696-a784-1fa92aed1b26.png)

此输出显示了我们对`stringExample`变量范围的迭代。`range`函数是一种非常强大的构造，简洁易读。

# 总结

在本章中，我们学习了如何在 Go 语言中使用 STL 实践。我们还学习了如何利用标准编程算法来处理 Go 语言，学习了容器如何存储数据，学习了函数在 Go 语言中的工作原理，并了解了如何正确使用迭代器。在我们继续 Go 性能之旅时，我们应始终将这些算法、容器、函数和迭代器放在编写代码选择的首要位置。这样做将帮助我们快速而简洁地编写符合惯例的 Go 代码。选择这些 STL 习语的正确组合将帮助我们更快、更有效地操作手头的数据。在下一章中，我们将学习如何在 Go 语言中计算向量和矩阵。


# 第五章：在 Go 中的矩阵和向量计算

矩阵和向量计算在计算机科学中很重要。向量可以在动态数组中保存一组对象。它们使用连续的存储，并且可以被操作以适应增长。矩阵建立在向量的基础上，创建了一个二维向量集。在本章中，我们将讨论矩阵和向量以及这两种数据结构如何实际使用，以执行今天计算机科学中发生的大部分数据操作。向量和矩阵是线性代数的基本组成部分，在今天的计算机科学中非常重要。诸如图像处理、计算机视觉和网络搜索等过程都利用线性代数来执行它们各自的操作。

在本章中，你将学习以下主题：

+   **基本线性代数子程序**（**BLAS**）

+   向量

+   矩阵

+   向量和矩阵操作

一旦我们能够将所有这些东西联系在一起，你将学会如何利用矩阵和向量计算的不同方面来推动大量数据的有效操作。

# 介绍 Gonum 和 Sparse 库

Go 中最受欢迎的科学算法库之一是 Gonum 包。Gonum 包（[`github.com/gonum`](https://github.com/gonum)）提供了一些工具，帮助我们使用 Go 编写有效的数值算法。这个包专注于创建高性能算法，可以在许多不同的应用程序中使用，向量和矩阵是这个包的核心要点。这个库是以性能为目标创建的 - 创建者们在 C 中看到了向量化的问题，所以他们建立了这个库，以便更容易地在 Go 中操作向量和矩阵。Sparse 库（[`github.com/james-bowman/sparse`](https://github.com/james-bowman/sparse)）是建立在 Gonum 库之上的，用于处理在机器学习和科学计算的其他部分中发生的一些正常的稀疏矩阵操作。在 Go 中使用这些库是一种高性能的方式来管理向量和矩阵。

在下一节中，我们将看看 BLAS 是什么。

# 介绍 BLAS

BLAS 是一个常用的规范，用于执行线性代数运算。这个库最初是在 1979 年作为 FORTRAN 库创建的，并且自那时以来一直得到维护。BLAS 对矩阵的高性能操作进行了许多优化。由于这个规范的深度和广度，许多语言选择在其领域内的线性代数库中使用这个规范的一部分。Go Sparse 库使用了 BLAS 实现进行线性代数操作。BLAS 规范由三个单独的例程组成：

+   级别 1：向量操作

+   级别 2：矩阵-向量操作

+   级别 3：矩阵-矩阵操作

有了这些分级的例程，有助于实现和测试这个规范。BLAS 已经在许多实现中使用过，从 Accelerate（macOS 和 iOS 框架）到英特尔**数学核心库**（**MKL**），并且已经成为应用计算机科学中线性代数的一个重要部分。

现在，是时候学习关于向量的知识了。

# 介绍向量

向量是一种常用于存储数据的一维数组。Go 最初有一个容器/向量实现，但在 2011 年 10 月 18 日被移除，因为切片被认为更适合在 Go 中使用向量。内置切片提供的功能可以提供大量的向量操作帮助。切片将是一个行向量，或者 1×m 矩阵的实现。一个简单的行向量如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/00b322c7-b978-45a4-a681-2f4397aa7199.png)

正如你所看到的，我们有一个 1×m 矩阵。要在 Go 中实现一个简单的行向量，我们可以使用切片表示，如下所示：

```go
v := []int{0, 1, 2, 3}
```

这是一种使用 Go 内置功能来描绘简单行向量的简单方法。

# 向量计算

列向量是一个 m x 1 矩阵，也被称为行向量的转置。矩阵转置是指矩阵沿对角线翻转，通常用上标 T 表示。我们可以在下面的图片中看到一个列向量的例子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/a47f76c2-b883-4fba-adc9-1eb32396c694.png)

如果我们想在 Go 中实现一个列向量，我们可以使用 Gonum 向量包来初始化这个向量，就像下面的代码块中所示的那样：

```go
package main

import (
   "fmt"
   "gonum.org/v1/gonum/mat"
)
func main() {
   v := mat.NewVecDense(4, []float64{0, 1, 2, 3})
   matPrint(v)
}

func matrixPrint(m mat.Matrix) {
   formattedMatrix := mat.Formatted(m, mat.Prefix(""), mat.Squeeze())
   fmt.Printf("%v\n", formattedMatrix)
}
```

这将打印出一个列向量，就像前面图片中所示的那样。

我们还可以使用 Gonum 包对向量进行一些整洁的操作。例如，在下面的代码块中，我们可以看到如何简单地将向量中的值加倍。我们可以使用`AddVec`函数将两个向量相加，从而创建一个加倍的向量。我们还有`prettyPrintMatrix`便利函数，使我们的矩阵更容易阅读：

```go
package main

import (
   "fmt"
   "gonum.org/v1/gonum/mat"
)

func main() {
   v := mat.NewVecDense(5, []float64{1, 2, 3, 4, 5})
   d := mat.NewVecDense(5, nil)
   d.AddVec(v, v)
   fmt.Println(d)
}

func prettyPrintMatrix(m mat.Matrix) { 
    formattedM := mat.Formatted(m, mat.Prefix(""), mat.Squeeze())
    fmt.Printf("%v\n", formattedM)
}

```

这个函数的结果，也就是加倍的向量，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/1b020747-a770-4fb4-ad41-98648242a382.png)

`gonum/mat`包还为向量提供了许多其他整洁的辅助函数，包括以下内容：

+   `Cap()` 给出了向量的容量

+   `Len()` 给出了向量中的列数

+   `IsZero()` 验证向量是否为零大小

+   `MulVec()`将向量*a*和*b*相乘并返回结果

+   `AtVec()`返回向量中给定位置的值

`gonum/mat`包中的向量操作函数帮助我们轻松地将向量操作成我们需要的数据集。

现在我们已经完成了向量，让我们来看看矩阵。

# 介绍矩阵

矩阵是二维数组，按行和列分类。它们在图形处理和人工智能中很重要；即图像识别。矩阵通常用于图形处理，因为矩阵中的行和列可以对应于屏幕上像素的行和列排列，以及因为我们可以让矩阵的值对应于特定的颜色。矩阵也经常用于数字音频处理，因为数字音频信号使用傅里叶变换进行滤波和压缩，矩阵有助于执行这些操作。

矩阵通常用*M × N*的命名方案表示，其中*M*是矩阵中的行数，*N*是矩阵中的列数，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/d388ff6d-3fc2-431f-9a5a-f3afa4dd282c.png)

例如，前面的图片是一个 3 x 3 的矩阵。*M x N*矩阵是线性代数的核心要素之一，因此在这里看到它的关系是很重要的。

现在，让我们看看矩阵是如何操作的。

# 矩阵操作

矩阵是以高效的方式存储大量信息的好方法，但是矩阵的操作是矩阵真正价值的所在。最常用的矩阵操作技术如下：

+   矩阵加法

+   矩阵标量乘法

+   矩阵转置

+   矩阵乘法

能够在矩阵上执行这些操作是很重要的，因为它们可以帮助处理规模化的真实世界数据操作。我们将在接下来的部分中看一些这些操作，以及它们的实际应用。

# 矩阵加法

矩阵加法是将两个矩阵相加的方法。也许我们想要找到两个 2D 集合的求和结果值。如果我们有两个相同大小的矩阵，我们可以将它们相加，就像这样：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/8bccb841-8f4e-4dab-8dce-228ef662ba58.png)

我们也可以用 Go 代码表示这一点，就像下面的代码块中所示的那样：

```go
package main

import (
   "fmt"
   "gonum.org/v1/gonum/mat"
)

func main() {
   a := mat.NewDense(3, 3, []float64{1, 2, 3, 4, 5, 6, 7, 8, 9})
   a.Add(a, a) // add a and a together
   matrixPrint(a)
}

func matrixPrint(m mat.Matrix) {
   formattedMatrix := mat.Formatted(m, mat.Prefix(""), mat.Squeeze())
   fmt.Printf("%v\n", formattedMatrix)
}
```

执行这个函数的结果如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/71bc0301-19cd-4cf0-90da-68a61be2c948.png)

结果是我们代码块中矩阵求和的描述。

在下一节中，我们将讨论矩阵操作的一个实际例子。为了演示这个例子，我们将使用矩阵减法。

# 一个实际的例子（矩阵减法）

假设您拥有两家餐厅，一家位于**纽约，纽约**，另一家位于**亚特兰大，乔治亚**。您想要弄清楚每个月在您的餐厅中哪些物品销售最好，以确保您在接下来的几个月中备货正确的原料。我们可以利用矩阵减法找到每家餐厅的单位销售净总数。我们需要每家餐厅的单位销售原始数据，如下表所示：

五月销量：

|  | **纽约，纽约** | **亚特兰大，乔治亚** |
| --- | --- | --- |
| 龙虾浓汤 | 1,345 | 823 |
| 鲜蔬沙拉 | 346 | 234 |
| 肋眼牛排 | 843 | 945 |
| 冰淇淋圣代 | 442 | 692 |

六月销量：

|  | **纽约，纽约** | **亚特兰大，乔治亚** |
| --- | --- | --- |
| 龙虾浓汤 | 920 | 776 |
| 鲜蔬沙拉 | 498 | 439 |
| 肋眼牛排 | 902 | 1,023 |
| 冰淇淋圣代 | 663 | 843 |

现在，我们可以使用以下矩阵减法找到这两个月之间的单位销售差异：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/43b44258-6545-45bf-af7b-ec30fd67ef97.png)

我们可以在 Go 中执行相同的操作，如下所示的代码块：

```go
package main

import (
  "fmt"

  "gonum.org/v1/gonum/mat"
)

func main() {
  a := mat.NewDense(4, 2, []float64{1345, 823, 346, 234, 843, 945, 442, 692})
  b := mat.NewDense(4, 2, []float64{920, 776, 498, 439, 902, 1023, 663, 843})
  var c mat.Dense
  c.Sub(b, a)
  result := mat.Formatted(&c, mat.Prefix(""), mat.Squeeze())
 fmt.Println(result)
}
```

我们的结果输出给出了五月和六月之间两家餐厅的销售差异，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/10425e6d-5f23-4933-a4e6-74d78620f88f.png)

在上述屏幕截图中的结果显示为*N × M*矩阵，描述了销售差异。

随着我们拥有更多的餐厅并在餐厅菜单中添加更多项目，利用矩阵减法将有助于我们记下我们需要保持库存的物品。

# 标量乘法

在操作矩阵时，我们可能希望将矩阵中的所有值乘以一个标量值。

我们可以用以下代码在 Go 中表示这一点：

```go
package main

import (
  "fmt"

  "gonum.org/v1/gonum/mat"
)

func main() {
  a := mat.NewDense(3, 3, []float64{1, 2, 3, 4, 5, 6, 7, 8, 9})
  a.Scale(4, a) // Scale matrix by 4
  matrixPrint(a)
}

func matrixPrint(m mat.Matrix) {
  formattedMatrix := mat.Formatted(m, mat.Prefix(""), mat.Squeeze())
  fmt.Printf("%v\n", formattedMatrix)
}
```

这段代码产生了以下结果：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/c155d917-5fbb-42d8-b001-5a2b9f4a6270.png)

在这里，我们可以看到矩阵中的每个元素都被缩放了 4 倍，从而提供了矩阵缩放的执行示例。

# 标量乘法实际示例

假设我们拥有一个五金店，我们有一个产品目录，其中的产品与**美元**（**USD**）值相关联。我们公司决定开始在加拿大和美国销售我们的产品。在撰写本书时，1 美元等于 1.34 加拿大元（**CAD**）。我们可以查看我们的螺丝、螺母和螺栓价格矩阵，根据数量计数，如下表所示：

|  | **单个 USD** | **100 个 USD** | **1000 个 USD** |
| --- | --- | --- | --- |
| 螺丝 | $0.10 | $0.05 | $0.03 |
| 螺母 | $0.06 | $0.04 | $0.02 |
| 螺栓 | $0.03 | $0.02 | $0.01 |

如果我们使用矩阵标量乘法来找到 CAD 中的结果成本，我们将得到以下矩阵计算：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/7cb9da0e-246b-40c8-98c0-4e74ab792012.png)

我们可以使用 Go 标量乘法功能验证这一点，如下所示的代码片段：

```go
package main

import (
    "fmt"

    "gonum.org/v1/gonum/mat"
) 

func main() {
    usd := mat.NewDense(3, 3, []float64{0.1, 0.05, 0.03, 0.06, 0.04, 0.02, 0.03, 0.02, 0.01})
    var cad mat.Dense
    cad.Scale(1.34, usd)
    result := mat.Formatted(&cad, mat.Prefix(""), mat.Squeeze()) 
    fmt.Println(result)
} 
```

我们收到一个包含我们每个物品的 CAD 值的结果矩阵：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/ccdb70b9-3875-4224-b005-cab7c4b6a435.png)

输出显示了我们缩放后的结果矩阵。

随着我们获得越来越多的产品，并有更多不同的货币需要考虑，我们的标量矩阵操作将非常方便，因为它将减少我们需要操作这些大量数据集的工作量。

# 矩阵乘法

我们可能还想将两个矩阵相乘。将两个矩阵相乘会得到两个矩阵的乘积。当我们想要同时以并发方式将许多数字相乘时，这将非常有帮助。我们可以取矩阵*A*，一个*N × M*矩阵，以及*B*，一个*M × P*矩阵。结果集称为*AB*，是一个*N × P*矩阵，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/e82ea761-1246-45b0-938f-effceac4c7eb.png)

我们可以用以下代码在 Go 中表示这一点：

```go
package main

import (
    "fmt"
    "gonum.org/v1/gonum/mat"
)

func main() {
    a := mat.NewDense(2, 2, []float64{1, 2, 3, 4})
    b := mat.NewDense(2, 3, []float64{1, 2, 3, 4, 5, 6})
    var c mat.Dense
    c.Mul(a, b)
    result := mat.Formatted(&c, mat.Prefix(""), mat.Squeeze())
    fmt.Println(result)
}
```

执行后，我们得到以下结果：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/47d0d3dc-cea7-458b-a975-fc1ca5e3bbdc.png)

这是我们可以使用`gonum/mat`包将矩阵相乘的方式。矩阵乘法是一个常见的矩阵函数，了解如何执行这个操作将帮助您有效地操作矩阵。

# 矩阵乘法实际示例

让我们来谈谈矩阵乘法的一个实际例子，这样我们就可以将我们的理论工作与一个可行的例子联系起来。两家不同的电子供应商正在竞相为您的公司制造小部件。供应商 A 和供应商 B 都为该小部件设计并为您提供了所需的零件清单。供应商 A 和供应商 B 都使用相同的组件供应商。在这个例子中，我们可以使用矩阵乘法来找出哪个供应商创建了一个更便宜的小部件。每个供应商给您的零件清单如下：

+   **供应商 A**：电阻：5

晶体管：10

电容器：2

+   **供应商 B**：

电阻：8

晶体管：6

电容器：3

您从组件供应商目录中得知，每个组件的定价如下：

+   电阻成本：$0.10

+   晶体管成本：$0.42

+   电容器成本：$0.37

我们可以用之前学到的方法，用矩阵来表示每个输入。这样做如下：

1.  我们创建了一个由组件成本组成的矩阵，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/54558420-1ed7-4e3d-ac0f-06e756954ced.png)

我们创建了一个由每个供应商的组件数量组成的矩阵：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/3bb4f614-13ca-4049-bbeb-12821e878eb2.png)

1.  然后，我们使用矩阵乘法来找到一些有趣的结果：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/6a727ef6-8d10-449b-ae9c-030ba4aeb3f6.png)

这个结果告诉我们，供应商 A 的解决方案零件成本为 5.44 美元，而供应商 B 的解决方案零件成本为 4.43 美元。从原材料的角度来看，供应商 B 的解决方案更便宜。

这可以在 Go 中用以下代码计算：

```go
package main

import (
    "fmt"
    "gonum.org/v1/gonum/mat"
)

func main() {
    a := mat.NewDense(1, 3, []float64{0.10, 0.42, 0.37})
    b := mat.NewDense(3, 2, []float64{5, 8, 10, 6, 2, 3})
    var c mat.Dense
    c.Mul(a, b)
    result := mat.Formatted(&c, mat.Prefix("    "), mat.Squeeze())
    fmt.Println(result)
}
```

得到的输出确认了我们在前面程序中所做的计算：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/ebec003c-cb2b-4b1f-96d8-a1e8545ebefa.png)

正如我们从结果中看到的，我们格式化的矩阵与我们之前执行的数学相吻合。在巩固我们对理论概念的理解方面，具有一个实际的例子可能会非常有帮助。

# 矩阵转置

矩阵转置是指将矩阵对角线翻转，交换行和列索引。以下图片显示了矩阵的一个转置示例：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/1475bd2c-8592-40f8-bc57-e676face4d1c.png)

我们可以用以下代码在 Go 中表示矩阵转置：

```go
package main

import (
    "fmt"
    "gonum.org/v1/gonum/mat"
)

func main() {
    a := mat.NewDense(3, 3, []float64{5, 3, 10, 1, 6, 4, 8, 7, 2})
    matrixPrint(a)
    matrixPrint(a.T())
}

func matrixPrint(m mat.Matrix) {
    formattedMatrix := mat.Formatted(m, mat.Prefix(""), mat.Squeeze())
    fmt.Printf("%v\n", formattedMatrix)
}
```

这个矩阵转置的结果可以在下图中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/2fa63e4c-f0e4-49ff-9bac-afcb485a38e7.png)

在前面的输出中，我们可以看到常规矩阵和转置版本。矩阵转置经常用于计算机科学中，比如通过在内存中转置矩阵来改善内存局部性。

# 矩阵转置实际示例

转置矩阵很有趣，但对您来说，可能有一个矩阵转置可能会被使用的实际示例会很有帮助。假设我们有三个工程师：**鲍勃**，**汤姆**和**爱丽丝**。这三个工程师每天都推送 Git 提交。我们希望以一种有意义的方式跟踪这些 Git 提交，以便我们可以确保工程师们有他们需要继续编写代码的所有资源。让我们统计一下我们工程师连续 3 天的代码提交：

| **用户** | **天** | **提交** |
| --- | --- | --- |
| 鲍勃 | 1 | 5 |
| 鲍勃 | 2 | 3 |
| 鲍勃 | 3 | 10 |
| 汤姆 | 1 | 1 |
| 汤姆 | 2 | 6 |
| 汤姆 | 3 | 4 |
| 爱丽丝 | 1 | 8 |
| 爱丽丝 | 2 | 7 |
| 爱丽丝 | 3 | 2 |

当我们有了我们的数据点后，我们可以用一个二维数组来表示它们：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/76486750-5d15-428b-a297-aaccfe1dffce.png)

现在我们有了这个数组，我们可以对数组进行转置：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/a3acc159-f37d-42de-869e-ac94f779af6d.png)

现在我们已经进行了这个转置，我们可以看到转置数组的行对应于提交的天数，而不是个体最终用户的提交。让我们看看第一行：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/f3574069-e3d2-42ad-bb87-f5e164f9cd82.png)

现在代表**BD1**、**TD1**和**AD1**——每个开发者的第 1 天提交。

现在我们完成了操作部分，是时候看看矩阵结构了。

# 理解矩阵结构

矩阵通常被分类为两种不同的结构：密集矩阵和稀疏矩阵。密集矩阵由大部分非零元素组成。稀疏矩阵是一个大部分由值为 0 的元素组成的矩阵。矩阵的稀疏度被计算为具有零值的元素数除以总元素数。

如果这个方程的结果大于 0.5，那么矩阵是稀疏的。这种区别很重要，因为它帮助我们确定矩阵操作的最佳方法。如果矩阵是稀疏的，我们可能能够使用一些优化来使矩阵操作更有效。相反，如果我们有一个密集矩阵，我们知道我们很可能会对整个矩阵执行操作。

重要的是要记住，矩阵的操作很可能会受到当今计算机硬件的内存限制。矩阵的大小是一个重要的记住的事情。当你在计算何时使用稀疏矩阵或密集矩阵时，密集矩阵将具有一个 int64 的值，根据 Go 中数字类型的大小和对齐，这是 8 个字节。稀疏矩阵将具有该值，加上一个条目的列索引的 int。在选择要用于数据的数据结构时，请记住这些大小。

# 密集矩阵

当你创建一个密集矩阵时，矩阵的所有值都被存储。有时这是不可避免的——当我们关心与表相关的所有值并且表大部分是满的时。对于密集矩阵存储，使用 2D 切片或数组通常是最好的选择，但如果你想操作矩阵，使用 Gonum 包可以以有效的方式进行数据操作。实际上，大多数矩阵不属于密集矩阵类别。

# 稀疏矩阵

稀疏矩阵在现实世界的数据集中经常出现。无论某人是否观看了电影目录中的视频，听了播放列表上的歌曲数量，或者完成了待办事项列表中的项目，都是可以使用稀疏矩阵的好例子。这些表中的许多值都是零，因此将这些矩阵存储为密集矩阵是没有意义的。这将占用大量内存空间，并且操作起来会很昂贵。

我们可以使用 Go 稀疏库来创建和操作稀疏矩阵。稀疏库使用来自 BLAS 例程的习语来执行许多常见的矩阵操作。Go 稀疏库与 Gonum 矩阵包完全兼容，因此可以与该包互换使用。在这个例子中，我们将创建一个新的稀疏**键字典**（**DOK**）。创建后，我们将为数组中的集合设置特定的*M x N*值。最后，我们将使用`gonum/mat`包来打印我们创建的稀疏矩阵。

在以下代码中，我们使用 Sparse 包创建了一个稀疏矩阵。`ToCSR()`和`ToCSC()`矩阵函数分别创建 CSR 和 CSC 矩阵：

```go
package main

import (
    "fmt"
    "github.com/james-bowman/sparse"
    "gonum.org/v1/gonum/mat"
)

func main() {
    sparseMatrix := sparse.NewDOK(3, 3)
    sparseMatrix.Set(0, 0, 5)
    sparseMatrix.Set(1, 1, 1)
    sparseMatrix.Set(2, 1, -3)
    fmt.Println(mat.Formatted(sparseMatrix))
    csrMatrix := sparseMatrix.ToCSR()
    fmt.Println(mat.Formatted(csrMatrix))
    cscMatrix := sparseMatrix.ToCSC()
    fmt.Println(mat.Formatted(cscMatrix))
}
```

执行完这段代码后，我们可以看到稀疏矩阵已经返回：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/70599b5b-53e2-4949-80bf-92cba0e216a2.png)

这个输出向我们展示了生成的稀疏矩阵。

稀疏矩阵可以分为三种不同的格式：

+   用于有效创建和修改矩阵的格式

+   用于有效访问和矩阵操作的格式

+   专用格式

用于有效创建和修改矩阵的格式如下：

+   **键字典**（**DOK**）

+   **列表的列表**（**LIL**）

+   **坐标列表**（**COO**）

这些格式将在以下部分中定义。

# DOK 矩阵

DOK 矩阵是 Go 中的一个映射。这个映射将行和列对链接到它们的相关值。如果没有为矩阵中的特定坐标定义值，则假定为零。通常，哈希映射被用作底层数据结构，这为随机访问提供了 O(1)，但遍历元素的速度会变得稍慢一些。DOK 对于矩阵的构建或更新是有用的，但不适合进行算术运算。一旦创建了 DOK 矩阵，它也可以简单地转换为 COO 矩阵。

# LIL 矩阵

LIL 矩阵存储了每行的列表，其中包含列索引和值，通常按列排序，因为这样可以减少查找时间。LIL 矩阵对于逐步组合稀疏矩阵是有用的。当我们不知道传入数据集的稀疏模式时，它们也是有用的。

# COO 矩阵

A COO 矩阵（也经常被称为三元组格式矩阵）存储了按行和列索引排序的元组列表，其中包含行、列和值。COO 矩阵可以简单地通过 O(1) 的时间进行追加。从 COO 矩阵中进行随机读取相对较慢（O(n)）。COO 矩阵是矩阵初始化和转换为 CSR 的良好选择。COO 矩阵不适合进行算术运算。通过对矩阵内的向量进行排序，可以提高对 COO 矩阵的顺序迭代的性能。

用于高效访问和矩阵操作的格式如下：

+   **压缩稀疏行**（**CSR**）

+   **压缩稀疏列**（**CSC**）

这些格式将在以下部分中定义。

# CSR 矩阵

CSR 矩阵使用三个一维数组来表示矩阵。CSR 格式使用这三个数组：

+   A：数组中存在的值。

+   IA：这些值的索引。这些值定义如下：

+   IA 在索引 0 处的值，IA[0] = 0

+   IA 在索引 i 处的值，IA[i] = IA[i − 1] +（原始矩阵中第 i-1 行上的非零元素数）

+   JA：存储元素的列索引。

下图显示了一个 4 x 4 矩阵的示例。这是我们将在下面的代码示例中使用的矩阵：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/5ab5424b-13fd-4162-aaa5-5e4e016ed4a2.png)

我们可以按以下方式计算这些值：

+   A = [ 1 2 3 4]

+   IA = [0 1 2 3 4]

+   JA = [2 0 3 1]

我们可以使用 `sparse` 包进行验证，如下面的代码片段所示：

```go
package main

import (
    "fmt"
    "github.com/james-bowman/sparse"
    "gonum.org/v1/gonum/mat"
)

func main() {
    sparseMatrix := sparse.NewDOK(4, 4)
    sparseMatrix.Set(0, 2, 1)
    sparseMatrix.Set(1, 0, 2)
    sparseMatrix.Set(2, 3, 3)
    sparseMatrix.Set(3, 1, 4)
    fmt.Print("DOK Matrix:\n", mat.Formatted(sparseMatrix), "\n\n") // Dictionary of Keys
    fmt.Print("CSR Matrix:\n", sparseMatrix.ToCSR(), "\n\n")        // Print CSR version of the matrix
}
```

结果显示了我们创建的矩阵的 DOK 表示的重新转换值，以及其对应的 CSR 矩阵：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/f59aabb2-8043-4d8b-a7fb-fab0ddef139a.png)

这段代码的输出显示了一个打印 IA、JA 和 A 值的 CSR 矩阵。随着矩阵的增长，能够计算 CSR 矩阵使得矩阵操作变得更加高效。计算机科学通常会处理数百万行和列的矩阵，因此能够以高效的方式进行操作会使您的代码更加高效。

# CSC 矩阵

CSC 矩阵与 CSR 矩阵具有相同的格式，但有一个小的不同之处。列索引切片是被压缩的元素，而不是行索引切片，就像我们在 CSR 矩阵中看到的那样。这意味着 CSC 矩阵以列为主序存储其值，而不是以行为主序。这也可以看作是对 CSR 矩阵的自然转置。我们可以通过对前一节中使用的示例进行操作，来看一下如何创建 CSC 矩阵，如下面的代码块所示：

```go
package main

import (
    "fmt"

    "github.com/james-bowman/sparse"
    "gonum.org/v1/gonum/mat"
)

func main() {
    sparseMatrix := sparse.NewDOK(4, 4)
    sparseMatrix.Set(0, 2, 1)
    sparseMatrix.Set(1, 0, 2)
    sparseMatrix.Set(2, 3, 3)
    sparseMatrix.Set(3, 1, 4)
    fmt.Print("DOK Matrix:\n", mat.Formatted(sparseMatrix), "\n\n") // Dictionary of Keys
    fmt.Print("CSC Matrix:\n", sparseMatrix.ToCSC(), "\n\n")        // Print CSC version
}
```

结果显示了我们创建的矩阵的 DOK 表示的重新转换值，以及其对应的 CSC 矩阵：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/6ac314fa-998d-4d1a-80e1-5e86d0161180.png)

前面代码块的输出向我们展示了 DOK 矩阵和 CSC 矩阵。了解如何表示 CSR 和 CSC 矩阵对于矩阵操作过程至关重要。这两种不同类型的矩阵具有不同的特征。例如，DOK 矩阵具有 O(1)的访问模式，而 CSC 矩阵使用面向列的操作以提高效率。

# 摘要

在本章中，我们讨论了矩阵和向量，以及这两种数据结构如何在计算机科学中实际使用来执行大部分数据操作。此外，我们还了解了 BLAS、向量、矩阵和向量/矩阵操作。向量和矩阵是线性代数中常用的基本组件，我们看到了它们在哪些情况下会发挥作用。

本章讨论的示例将在涉及真实世界数据处理的情况下对我们有很大帮助。在第六章中，《编写可读的 Go 代码》，我们将讨论如何编写可读的 Go 代码。能够编写可读的 Go 代码将有助于保持主题和想法清晰简洁，便于代码贡献者之间的轻松协作。


# 第二部分：在 Go 中应用性能概念

在本节中，您将了解为什么性能概念在 Go 中很重要。它们使您能够有效地处理并发请求。Go 是以性能为重点编写的，了解与编写 Go 代码相关的性能习语将帮助您编写在许多情况下都有帮助的代码。

本节包括以下章节：

+   第六章，*编写可读的 Go 代码*

+   第七章，*Go 中的模板编程*

+   第八章，*Go 中的内存管理*

+   第九章，*Go 中的 GPU 并行化*

+   第十章，*Go 中的编译时评估*


# 第六章：编写可读的 Go 代码

学习如何编写可读的 Go 代码是语言的一个重要部分。语言开发人员在编写其他语言时使用了他们的先前经验来创建一种他们认为清晰简洁的语言。在描述使用这种语言编写的正确方式时，经常使用的短语是*惯用 Go*。这个短语用来描述在 Go 中编程的*正确*方式。风格往往是主观的，但 Go 团队为了以一种有见地的方式编写语言并促进开发者的速度、可读性和协作而努力工作。在本章中，我们将讨论如何保持语言的一些核心原则：

+   简单

+   可读性

+   打包

+   命名

+   格式化

+   接口

+   方法

+   继承

+   反射

了解这些模式和惯用法将帮助您编写更易读和可操作的 Go 代码。能够编写惯用的 Go 将有助于提高代码质量水平，并帮助项目保持速度。

# 保持 Go 中的简单性

Go 默认不遵循其他编程语言使用的特定模式。作者选择了不同的惯用法来保持语言简单和清晰。保持语言的简单性对语言开发人员来说是一项艰巨的任务。拥有工具、库、快速执行和快速编译，同时保持简单性，一直是语言开发的重中之重。Go 的语言开发人员一直坚持这些决定，采用共识设计模式——对向语言添加新功能的共识确保了这些功能的重要性。

语言维护者在 GitHub 的问题页面上活跃，并且非常乐意审查拉取请求。从其他使用该语言的人那里获得反馈，使语言维护者能够就向语言添加新功能和功能做出明智的决定，同时保持可读性和简单性。

接下来的部分将向我们展示 Go 语言的下一个基本方面：可读性。

# 保持 Go 语言中的可读性

可读性是 Go 的另一个核心原则。能够快速理解新代码库并理解其中一些微妙之处是任何编程语言的重要部分。随着分布式系统的不断增长，供应商库和 API 变得更加普遍，能够轻松阅读包含的代码并理解其中的意义对于推动前进是有帮助的。这也使得破损的代码更容易修复。

拥有具体的数据类型、接口、包、并发、函数和方法有助于 Go 继续前进。可读性是能够在较长时间内维护大型代码库的最重要参数之一，这是 Go 与竞争对手之间最重要的区别之一。该语言是以可读性作为一等公民构建的。

Go 语言有许多复杂的底层内部部分，但这些实际上并不复杂。诸如简单定义的常量、接口、包、垃圾回收和易于实现的并发等都是复杂的内部部分，但对最终用户来说是透明的。拥有这些构造有助于使 Go 语言蓬勃发展。

让我们在下一节看看 Go 语言中的打包意味着什么。

# 探索 Go 中的打包

打包是 Go 语言的一个基本部分。每个 Go 程序都需要在程序的第一行定义一个包。这有助于可读性、可维护性、引用和组织。

Go 程序中的`main`包使用主声明。这个主声明调用程序的`main`函数。这之后，我们在`main`函数中有其他导入，可以用来导入程序中的其他包。我们应该尽量保持主包的小型化，以便将我们程序中的所有依赖项模块化。接下来我们将讨论包命名。

# 包命名

在命名包时，开发人员应遵循以下规则：

+   包不应该有下划线、连字符或混合大小写

+   包不应该以通用的命名方案命名，比如 common、util、base 或 helper

+   包命名应该与包执行的功能相关

+   包应该保持一个相当大的范围；包中的所有元素应该具有相似的目标和目标

+   在新包与公共 API 对齐之前，利用内部包可以帮助您审查新包

# 包装布局

当我们讨论 Go 程序的布局时，我们应该遵循一些不同的流程。一个常见的约定是将主程序放在名为`cmd`的文件夹中。您构建的其他要从`main`函数执行的包应该放在`pkg`目录中。这种分离有助于鼓励包的重用。在下面的例子中，如果我们想要在 CLI 和 Web 主程序中都重用通知包，我们可以轻松地通过一个导入来实现。以下是一个屏幕截图显示了这种分离：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/2cc26180-33c9-43f4-9e5b-cfd15626cdc3.png)

Go 的一个反模式是为包映射创建一对一的文件。我们应该以在特定目录结构内驱动常见用例的方式来编写 Go。例如，我们可以创建一个文件的单个目录并进行如下测试：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/7259ab0e-d9fa-475c-b009-2f29fc0ca1d2.png)

然而，我们应该按照以下方式创建我们的包：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/c59b9d7d-6f00-4d7a-bcd5-cf018c48e5b5.png)

所有这些不同的通知策略都共享一个共同的做法。我们应该尝试将类似的功能耦合在同一个包中。这将帮助其他人理解通知包具有类似功能的任何上下文。

# 内部包装

许多 Go 程序使用内部包的概念来表示尚未准备好供外部使用的 API。内部包的概念首次在 Go 1.4 中引入，以在程序内部添加组件边界。这些内部包不能从存储它们的子树之外导入。如果您想要维护内部包并不将它们暴露给程序的其余部分，这是很有用的。一旦您以您认为合适的方式审查了内部包，您可以更改文件夹名称并公开先前的内部包。

让我们看一个例子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/de065a1d-6412-4b9d-95de-bb151434405f.png)

在前面的例子中，我们可以看到我们有一个内部目录。这只能从这个项目内部访问。然而，`pkg`和`cmd`目录将可以从其他项目访问。这对于我们继续开发新产品和功能是很重要的，这些产品和功能在其他项目中还不应该可以导入。

# 供应商目录

供应商目录的概念起源于 Go 1.5 的发布。 `vendor`文件夹是一个存储外部和内部源代码的编译组合的地方，存放在项目的一个目录中。这意味着代码组合器不再需要将依赖包复制到源代码树中。当`GOPATH`寻找依赖项时，将在`vendor`文件夹中进行搜索。这有很多好处：

+   我们可以在我们的项目中保留外部依赖项的本地副本。如果我们想要在具有有限或没有外部网络连接的网络上执行我们的程序，这可能会有所帮助。

+   这样可以加快我们 Go 程序的编译速度。将所有这些依赖项存储在本地意味着我们不需要在构建时拉取依赖项。

+   如果您想使用第三方代码，但已经为您的特定用例进行了调整，您可以将该代码存储并更改为内部发布。

# Go 模块

Go 模块是在 Go 1.11 中引入的。它们可以跟踪 Go 代码库中的版本化依赖项。它们是一组作为一个统一单元存储在项目目录中的`go.mod`文件的 Go 包。

我们将执行以下步骤来初始化一个新模块：

1.  首先执行`go mod init repository`：

```go
go mod init github.com/bobstrecansky/HighPerformanceWithGo
go: creating new go.mod: module github.com/bobstrecansky/HighPerformanceWithGo
```

1.  初始化新模块后，您可以构建 Go 包并像往常一样执行它。您将在项目目录中的`go.mod`文件中保存来自项目内导入的模块。

例如，如果我们想要使用 Gin 框架[[`github.com/gin-gonic/gin`](https://github.com/gin-gonic/gin)]创建一个简单的 Web 服务器，我们可以在项目结构中创建一个目录，如下所示：`/home/bob/git/HighPerformanceWithGo/6-composing-readable-go-code/goModulesExample`。

1.  接下来创建一个简单的 Web 服务器，以对`/foo`请求返回`bar`：

```go
package main
import "github.com/gin-gonic/gin"
func main() {
  server := gin.Default()
  server.GET("/foo", func(c *gin.Context) {
    c.JSON(200, gin.H{
      "response": "bar",
    })
  })
  server.Run()
}
```

1.  之后，我们可以在新创建的目录中创建一个新的 Go 模块：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/0a10594a-9569-461b-aca2-1c5d84a65580.png)

1.  接下来，我们可以执行我们的 Go 程序；必要时将引入适当的依赖项：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/840e0cfe-d102-4b92-b4b9-95bb3ca725d7.png)

现在我们可以看到我们的简单 Web 服务器的依赖项存储在我们目录中的`go.sum`文件中（我使用了`head`命令将列表截断为前 10 个条目）：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/c420a06b-62d2-4fed-a04e-91e34413a63e.png)

Go 模块有助于保持 Go 存储库中的依赖项清洁和一致。如果需要，我们还可以使用存储库来保持所有依赖项与项目本地相关。

关于在存储库中存储依赖项的意见往往差异很大。一些人喜欢使用存储库，因为它可以减少构建时间并限制无法从外部存储库中拉取包的风险。其他人认为存储可能会妨碍包更新和安全补丁。您是否选择在程序中使用存储目录取决于您，但 Go 模块包含这种功能是很方便的。以下输出说明了这一点：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/23e64c8a-290f-46fb-8f24-aa4aaaa29eff.png)

能够使用内置编译工具来存储目录使得设置和配置变得容易。

在下一节中，我们将讨论在 Go 中命名事物。

# 了解 Go 中的命名

有很多一致的行为，Go 程序员喜欢保留以保持可读性和可维护性的代码。Go 命名方案往往是一致的、准确的和简短的。我们希望在创建名称时记住以下习语：

+   迭代器的局部变量应该简短而简单：

+   `i` 代表迭代器；如果有二维迭代器，则使用`i`和`j`

+   `r` 代表读取器

+   `w` 代表写入器

+   `ch` 代表通道

+   全局变量名称应该简短且描述性强：

+   `RateLimit`

+   `Log`

+   `Pool`

+   首字母缩略语应遵循使用全大写的约定：

+   `FooJSON`

+   `FooHTTP`

+   避免使用模块名称时的口吃：

+   `log.Error()` 而不是 `log.LogError()`

+   具有一个方法的接口应遵循方法名称加上`-er`后缀：

+   `Stringer`

+   `Reader`

+   `Writer`

+   `Logger`

+   Go 中的名称应遵循 Pascal 或 mixedCaps 命名法：

+   `var ThingOne`

+   `var thingTwo`

重要的是要记住，如果名称的首字母大写，它是公开的，并且可以在其他函数中使用。在为事物想出自己的命名方案时，请记住这一点。

遵循这些命名约定可以使您拥有可读性强、易消化、可重用的代码。另一个良好的实践是使用一致的命名风格。如果您正在实例化相同类型的参数，请确保它遵循一致的命名约定。这样可以使新的使用者更容易跟随您编写的代码。

在下一节中，我们将讨论 Go 代码的格式化。

# 了解 Go 中的格式化

正如在第一章中所述，*Go 性能简介*，`gofmt`是 Go 代码的一种主观格式化工具。它会缩进和对齐您的代码，以便按照语言维护者的意图进行阅读。今天许多最受欢迎的代码编辑器在保存文件时都可以执行`gofmt`。这样做，以及拥有您的持续集成软件验证，可以使您无需关注您正在编写的代码的格式，因为语言将会在输出中规定格式。使用这个工具将使 Go 代码更容易阅读、编写和维护，同时有多个贡献者。它还消除了语言内的许多争议，因为空格、制表符和大括号会自动定位。

我们还可以向我们的 Git 存储库（在`.git/hooks/pre-commit`中）添加一个预提交挂钩，以确保提交到存储库的所有代码都按预期格式化。以下代码块说明了这一点：

```go
#!/bin/bash
FILES=$(/usr/bin/git diff --cached --name-only --diff-filter=dr | grep '\.go$')
[ -z "$FILES" ] && exit 0
FORMAT=$(gofmt -l $FILES)
[ -z "$FORMAT" ] && exit 0

echo >&2 "gofmt should be used on your source code. Please execute:"
  for gofile in $FORMAT; do
      echo >&2 " gofmt -w $PWD/$gofile"
  done
  exit 1
```

在添加了这个预提交挂钩之后，我们可以通过向存储库中的文件添加一些错误的空格来确认一切是否按预期工作。这样做后，当我们`git commit`我们的代码时，我们将看到以下警告消息：

```go
git commit -m "test"
//gofmt should be used on your source code. Please execute:
gofmt -w /home/bob/go/example/badformat.go
```

`gofmt`还有一个鲜为人知但非常有用的简化方法，它将在可能的情况下执行源代码转换。这将对一些复合、切片和范围复合文字进行缩短。简化格式化命令将采用以下代码：

```go
package main
import "fmt"
func main() {
    var tmp = []int{1, 2, 3}
    b := tmp[1:len(tmp)]
    fmt.Println(b)
    for i, _ := range tmp {
       fmt.Println(tmp[i])
    }
}
```

这将简化为以下代码：`gofmt -s gofmtSimplify.go`。

这个`gofmt`代码片段的输出如下：

```go
package main
import "fmt"
func main() {
    var tmp = []int{1, 2, 3}
    b := tmp[1:]
    fmt.Println(b)
    for i := range tmp {
       fmt.Println(tmp[i]) 
    }
}
```

请注意，前面代码片段中的变量`b`有一个简单的定义，并且范围定义中的空变量已被`gofmt`工具移除。这个工具可以帮助您在存储库中定义更清晰的代码。它还可以用作一种编写代码的机制，使编写者可以思考问题，但`gofmt`生成的结果代码可以以紧密的方式存储在共享存储库中。

在下一节中，我们将讨论 Go 中的接口。

# Go 接口简介

Go 的接口系统与其他语言的接口系统不同。它们是方法的命名集合。接口在组合可读的 Go 代码方面非常重要，因为它们使代码具有可伸缩性和灵活性。接口还赋予我们在 Go 中具有多态性（为具有不同类型的项目提供单一接口）的能力。接口的另一个积极方面是它们是隐式实现的——编译器检查特定类型是否实现了特定接口。

我们可以定义一个接口如下：

```go
type example interface {
foo() int
bar() float64
}
```

如果我们想要实现一个接口，我们只需要实现接口中引用的方法。编译器会验证您的接口方法，因此您无需执行此操作。

我们还可以定义一个空接口，即一个没有方法的接口，表示为`interface{}`。在 Go 中，空接口是有价值和实用的，因为我们可以向它们传递任意值，如下面的代码块所示：

```go
package main
import "fmt"
func main() {
    var x interface{}
    x = "hello Go"
    fmt.Printf("(%v, %T)\n", x, x)
    x = 123
    fmt.Printf("(%v, %T)\n", x, x)
    x = true
    fmt.Printf("(%v, %T)\n", x, x)
}
```

当我们执行我们的空接口示例时，我们可以看到 x 接口的类型和值随着我们改变（最初）空接口的定义而改变：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/c77209dc-7c5a-47e0-ad53-ab7a6d084287.png)

空的、可变的接口很方便，因为它们给了我们灵活性，以一种对代码编写者有意义的方式来操作我们的数据。

在下一节中，我们将讨论 Go 中的方法理解。

# 理解 Go 中的方法

Go 中的方法是具有特殊类型的函数，称为`接收器`，它位于`function`关键字和与关键字相关联的方法名称之间。Go 没有类与其他编程语言相同的方式。结构体通常与方法一起使用，以便以与其他语言中构造类似的方式捆绑数据及其相应的方法。当我们实例化一个新方法时，我们可以添加结构值以丰富函数调用。

我们可以实例化一个结构和一个方法如下：

```go
package main
import "fmt"
type User struct {
    uid int
    name string
    email string
    phone string
}

func (u User) displayEmail() {
    fmt.Printf("User %d Email: %s\n", u.uid, u.email)
}
```

完成后，我们可以使用此结构和方法来显示有关用户的信息，如下所示：

```go
func main() {
    userExample := User{
       uid: 1,
       name: "bob",
       email: "bob@example.com",
       phone: "123-456-7890",
    }

    userExample.displayEmail()
}
```

这将返回`userExample.displayEmail()`的结果，它会在方法调用中打印结构的相关部分，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/cc7465c3-67c7-48fa-9461-d20edab04dad.png)

随着我们拥有更大的数据结构，我们有能力轻松有效地引用存储在这些结构中的数据。如果我们决定要编写一个方法来查找最终用户的电话号码，那么使用我们现有的数据类型并编写类似于`displayEmail`方法的方法来返回最终用户的电话号码将是很简单的。

到目前为止，我们所看到的方法只有值接收器。方法也可以有指针接收器。指针接收器在您希望在原地更新数据并使结果可用于调用函数时很有帮助。

考虑我们之前的例子，做一些修改。我们将有两种方法，允许我们更新用户的电子邮件地址和电话号码。电子邮件地址更新将使用值接收器，而电话更新将使用指针接收器。

我们在以下代码块中创建这些函数，以便能够轻松更新最终用户的信息：

```go
package main 
import "fmt"

type User struct {
    uid int
    name string
    email string
    phone string
} 

func (u User) updateEmail(newEmail string) {
    u.email = newEmail
} 

func (u *User) updatePhone(newPhone string) {
    u.phone = newPhone
} 
```

接下来在`main`中创建我们的示例最终用户，如下代码块所示：

```go
func main() {
      userExample := User{ 
        uid: 1, 
        name: "bob",
        email: "bob@example.com",
        phone: "123-456-7890",
    } 
```

然后我们在以下代码块中更新我们最终用户的电子邮件和电话号码：

```go
userExample.updateEmail("bob.strecansky@example.com") 
    (userExample).updatePhone("000-000-0000")
    fmt.Println("Updated User Email: ", userExample.email)
    fmt.Println("Updated User Phone: ", userExample.phone)
}     
```

在我们的输出结果中，我们可以看到从接收器的角度来看，用户的电子邮件地址没有被更新，但用户的电话号码已经被更新了：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/a399ec7d-6ede-4114-b0a5-79f20cc686d6.png)

在尝试从方法调用中改变状态时，记住这一点是很重要的。方法在操作 Go 程序中的数据方面非常有帮助。

现在是时候看看 Go 中的继承是怎么回事了。

# 理解 Go 中的继承

Go 没有继承。组合用于将项目（主要是结构）嵌入在一起。当您有一个用于许多不同功能的基线结构时，这是方便的，其他结构在初始结构的基础上构建。

我们可以描述一些我厨房里的物品，以展示继承是如何工作的。

我们可以初始化我们的程序，如下代码块所示。在这个代码块中，我们创建了两个结构：

`器具`：我厨房抽屉里的器具

`电器`：我厨房里的电器

```go
package main
import "fmt" 

func main() {
    type Utensils struct {
        fork string
        spoon string
        knife string
    } 

    type Appliances struct {
        stove string
        dishwasher string
        oven string
    } 
```

接下来，我可以使用 Go 的嵌套结构来创建一个包含所有器具和电器的`厨房`结构，如下所示：

```go
    type Kitchen struct {
        Utensils
        Appliances
    } 
```

然后我可以用我拥有的器具和电器填满我的厨房：

```go
    bobKitchen := new(Kitchen)
    bobKitchen.Utensils.fork = "3 prong"
    bobKitchen.Utensils.knife = "dull"
    bobKitchen.Utensils.spoon = "deep"
    bobKitchen.Appliances.stove = "6 burner"
    bobKitchen.Appliances.dishwasher = "3 rack"
    bobKitchen.Appliances.oven = "self cleaning"
    fmt.Printf("%+v\n", bobKitchen) 
}                 
```

所有这些东西都在之后，我们可以看到结果输出，我的厨房物品（`器具`和`电器`）被组织在我的`厨房`结构中。我的`厨房`结构稍后可以轻松地在其他方法中引用。

拥有嵌套结构对于未来的扩展非常实用。如果我决定想要向这个结构中添加其他元素，我可以创建一个`House`结构，并将我的`Kitchen`结构嵌套在`House`结构中。我还可以为房子中的其他房间组合结构，并将它们添加到房子结构中。

在下一节中，我们将探讨 Go 中的反射。

# 探索 Go 中的反射

Go 中的反射是一种元编程形式。在 Go 中使用反射让程序理解自己的结构。有时候，当程序被组合时，我们想要在运行时使用一个变量，而这个变量在程序被组合时并不存在。我们使用反射来检查存储在接口变量中的键值对。反射通常不太清晰，因此在使用时要谨慎——它应该在必要时才使用。它只有运行时检查（而不是编译时检查），因此我们需要理性地使用反射。

重要的是要记住，Go 的变量是静态类型的。我们可以在 Go 中使用许多不同的变量类型——`rune`、`int`、`string`等。我们可以声明特定类型如下：

```go
Type foo int
var x int
var y foo
```

变量`x`和`y`都将是 int 类型的变量。

有三个重要的反射部分用于获取信息：

+   类型

+   种类

+   值

这三个不同的部分共同工作，以推断与接口相关的信息。让我们分别看看每个部分，看看它们如何配合。

# 类型

能够确定变量的类型在 Go 中是很重要的。在我们的例子中，我们可以验证字符串类型是否确实是字符串，如下面的代码块所示：

```go
package main

import (
    "fmt"
    "reflect"
)

func main() {
    var foo string = "Hi Go!"
    fooType := reflect.TypeOf(foo)
    fmt.Println("Foo type: ", fooType)
}
```

我们程序的输出将向我们展示反射类型将准确推导出`foo string`类型：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/f130eaff-5d87-4cb7-87d2-445a2c22918b.png)

尽管这个例子很简单，但重要的是要理解其中的基本原则：如果我们不是验证字符串，而是查看传入的网络调用或外部库调用的返回，或者尝试构建一个可以处理不同类型的程序，反射库的`TypeOf`定义可以帮助我们正确地识别这些类型。

# 种类

种类被用作占位符，用于定义特定类型表示的类型。它用于表示类型由什么组成。这在确定定义了什么样的结构时非常有用。让我们看一个例子：

```go
package main
import (
    "fmt"
    "reflect"
)

func main() {
    i := []string{"foo", "bar", "baz"}
    ti := reflect.TypeOf(i)
    fmt.Println(ti.Kind())
}
```

在我们的例子中，我们可以看到我们创建了一个字符串切片——`foo`、`bar`和`baz`。然后，我们可以使用反射来找到`i`的类型，并且我们可以使用`Kind()`函数来确定类型是由什么组成的——在我们的例子中，是一个切片，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/97e57f40-2a7e-409a-b097-8cc345e9c95c.png)

如果我们想要推断特定接口的类型，这可能会很有用。

# 值

反射中的值有助于读取、设置和存储特定变量的结果。在下面的例子中，我们可以看到我们设置了一个示例变量`foo`，并且使用反射包，我们可以推断出我们示例变量的值如下所示：

```go
package main
import (
    "fmt"
    "reflect"
)

func main() {
    example := "foo"
    exampleVal := reflect.ValueOf(example)
    fmt.Println(exampleVal)
}
```

在我们的输出中，我们可以看到示例变量`foo`的值被返回：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-hiperf-go/img/a3cfa0b8-90ae-4ce5-9e59-ceb21c646150.png)

反射系统中的这三个不同的函数帮助我们推断我们可以在代码库中使用的类型。

# 总结

在本章中，我们学习了如何使用语言的一些核心原则来编写可读的 Go 代码。我们学习了简单性和可读性的重要性，以及打包、命名和格式化对于编写可读的 Go 代码是至关重要的。此外，我们还学习了接口、方法、继承和反射如何都可以用来编写其他人能够理解的代码。能够有效地使用这些核心 Go 概念将帮助您产生更高效的代码。

在下一章中，我们将学习 Go 语言中的内存管理，以及如何针对手头的内存资源进行优化。
