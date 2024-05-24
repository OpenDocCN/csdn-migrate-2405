# Go 系统编程（二）

> 原文：[`zh.annas-archive.org/md5/2DB8F67A356AEFD794B578E9C4995B3C`](https://zh.annas-archive.org/md5/2DB8F67A356AEFD794B578E9C4995B3C)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：Go 包、算法和数据结构

本章的主要主题将是 Go 包、算法和数据结构。如果您将所有这些结合起来，您将得到一个完整的程序，因为 Go 程序以包的形式提供，其中包含处理数据的算法。这些包包括 Go 自带的包和您自己创建的包，以便操作您的数据。

因此，在本章中，您将学习以下内容：

+   大 O 符号

+   两种排序算法

+   `sort.Slice()`函数

+   链表

+   树

+   在 Go 中创建自己的哈希表数据结构

+   Go 包

+   Go 中的垃圾回收（GC）

# 关于算法

了解算法及其工作方式肯定会在您需要处理大量数据时帮助您。此外，如果您选择对于特定工作使用错误的算法，可能会减慢整个过程并使您的软件无法使用。

传统的 Unix 命令行实用程序，如`awk(1)`、`sed(1)`、`vi(1)`、`tar(1)`和`cp(1)`，是好算法如何帮助的很好的例子，这些实用程序可以处理比机器内存大得多的文件。这在早期的 Unix 时代非常重要，因为当时 Unix 机器上的总 RAM 量大约为 64K 甚至更少！

# 大 O 符号

**大 O 符号**用于描述算法的复杂性，这与其性能直接相关。算法的效率是通过其计算复杂性来判断的，这主要与算法需要访问其输入数据的次数有关。通常，您会想了解最坏情况和平均情况。

因此，O(n)算法（其中 n 是输入的大小）被认为比 O(n²)算法更好，后者又比 O(n³)算法更好。然而，最糟糕的算法是具有 O(n!)运行时间的算法，因为这使得它们几乎无法用于超过 300 个元素的输入。请注意，大 O 符号更多地是关于估计而不是给出精确值。因此，它主要用作比较值而不是绝对值。

此外，大多数内置类型的 Go 查找操作，比如查找地图键的值或访问数组元素，都具有常数时间，用 O(1)表示。这意味着内置类型通常比自定义类型更快，通常应该优先选择它们，除非你想完全控制后台发生的事情。另外，并非所有数据结构都是平等的。一般来说，数组操作比地图操作更快，而地图比数组更灵活！

# 排序算法

最常见的算法类别涉及对数据进行排序，即将其放置在给定顺序中。最著名的两种排序算法如下：

+   **快速排序**：这被认为是最快的排序算法之一。快速排序对其数据进行排序所需的平均时间为 O(n log n)，但在最坏情况下可能增长到 O(n²)，这主要与数据呈现方式有关。

+   **冒泡排序**：这个算法非常容易实现，平均复杂度为 O(n²)。如果您想开始学习排序，可以先从冒泡排序开始，然后再研究更难开发的算法。

尽管每种算法都有其缺点，但如果您没有大量数据，那么只要它能完成工作，算法就不是真正重要的。

您应该记住的是，Go 内部实现排序的方式无法由开发人员控制，并且将来可能会发生变化；因此，如果您想完全控制排序，应该编写自己的实现。

# sort.Slice()函数

本节将说明首次出现在 Go 版本 1.8 中的`sort.Slice()`函数的用法。该函数的用法将在`sortSlice.go`中进行说明，该文件将分为三部分呈现。

第一部分是程序的预期序言和新结构类型的定义，如下所示：

```go
package main 

import ( 
   "fmt" 
   "sort" 
) 

type aStructure struct { 
   person string 
   height int 
   weight int 
} 
```

正如您所期望的，您必须导入`sort`包才能使用其`Slice()`函数。

第二部分包含了切片的定义，其中包含四个元素：

```go
func main() { 

   mySlice := make([]aStructure, 0) 
   a := aStructure{"Mihalis", 180, 90}

   mySlice = append(mySlice, a) 
   a = aStructure{"Dimitris", 180, 95} 
   mySlice = append(mySlice, a) 
   a = aStructure{"Marietta", 155, 45} 
   mySlice = append(mySlice, a) 
   a = aStructure{"Bill", 134, 40} 
   mySlice = append(mySlice, a)
```

因此，在第一部分中，您声明了一个结构的切片，该切片将在程序的其余部分中以两种方式进行排序，其中包含以下代码：

```go
   fmt.Println("0:", mySlice) 
   sort.Slice(mySlice, func(i, j int) bool { 
         return mySlice[i].weight <mySlice[j].weight 
   }) 
   fmt.Println("<:", mySlice) 
   sort.Slice(mySlice, func(i, j int) bool { 
         return mySlice[i].weight >mySlice[j].weight 
   }) 
   fmt.Println(">:", mySlice) 
} 
```

这段代码包含了所有的魔法：您只需定义您想要对`slice`进行`sort`的方式，Go 就会完成其余工作。`sort.Slice()`函数将匿名排序函数作为其参数之一；另一个参数是您想要`sort`的`slice`变量的名称。请注意，排序后的切片保存在`slice`变量中。

执行`sortSlice.go`将生成以下输出：

```go
$ go run sortSlice.go
0: [{Mihalis 180 90} {Dimitris 180 95} {Marietta 155 45} {Bill 134 40}]
<: [{Bill 134 40} {Marietta 155 45} {Mihalis 180 90} {Dimitris 180 95}]
>: [{Dimitris 180 95} {Mihalis 180 90} {Marietta 155 45} {Bill 134 40}]
```

如您所见，您可以通过在 Go 代码中更改一个字符来轻松地按升序或降序进行`sort`！

此外，如果您的 Go 版本不支持`sort.Slice()`，您将收到类似以下的错误消息：

```go
$ go version
go version go1.3.3 linux/amd64
$ go run sortSlice.go
# command-line-arguments
./sortSlice.go:27: undefined: sort.Slice
./sortSlice.go:31: undefined: sort.Slice
```

# Go 中的链表

**链表**是具有有限元素集的结构，其中每个元素使用至少两个内存位置：一个用于存储数据，另一个用于将当前元素链接到构成链表的元素序列中的下一个元素的指针。链表的最大优势是易于理解和实现，并且足够通用，可用于许多不同情况并模拟许多不同类型的数据。

链表的第一个元素称为**头部**，而列表的最后一个元素通常称为**尾部**。定义链表时，首先要做的是将列表的头部保留在单独的变量中，因为头部是您需要访问整个链表的唯一内容。

请注意，如果丢失单链表的第一个节点的指针，将无法再次找到它。

以下图显示了链表和双向链表的图形表示。双向链表更灵活，但需要更多的维护：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/834e20cc-7099-4649-b740-da9fa61fbd3d.png)

链表和双向链表的图形表示

因此，在本节中，我们将介绍在`linkedList.go`中保存的 Go 中链表的简单实现。

当创建自己的数据结构时，最重要的元素是节点的定义，通常使用结构来实现。

`linkedList.go`的代码将分为四部分呈现。

第一部分如下：

```go
package main 

import ( 
   "fmt" 
) 
```

第二部分包含以下 Go 代码：

```go
type Node struct { 
   Value int 
   Next  *Node 
} 

func addNode(t *Node, v int) int { 
   if root == nil { 
         t = &Node{v, nil} 
         root = t 
         return 0 
   } 

   if v == t.Value { 
         fmt.Println("Node already exists:", v) 
         return -1 
   } 

   if t.Next == nil { 
         t.Next = &Node{v, nil} 
         return -2 
   } 

   return addNode(t.Next, v)

} 
```

在这里，您定义了将保存列表中每个元素的结构以及允许您向列表添加新节点的函数。为了避免重复条目，您应该检查值是否已经存在于列表中。请注意，`addNode()`是一个递归函数，因为它调用自身，这种方法可能比迭代稍慢，需要更多的内存。

代码的第三部分是`traverse()`函数：

```go
func traverse(t *Node) { 
   if t == nil { 
         fmt.Println("-> Empty list!") 
         return 
   } 

   for t != nil {

         fmt.Printf("%d -> ", t.Value) 
         t = t.Next 
   } 
   fmt.Println() 
} 
```

`for`循环实现了访问链表中所有节点的迭代方法。

最后一部分如下：

```go
var root = new(Node)
func main() { 
   fmt.Println(root) 
   root = nil 
   traverse(root) 
   addNode(root, 1) 
   addNode(root, 1) 
   traverse(root) 
   addNode(root, 10) 
   addNode(root, 5) 
   addNode(root, 0) 
   addNode(root, 0) 
   traverse(root) 
   addNode(root, 100) 
   traverse(root) 
}
```

在本书中首次看到不是常量的全局变量的使用。全局变量可以从程序的任何地方访问和更改，这使得它们的使用既实用又危险。使用名为`root`的全局变量来保存链表的`root`是为了显示链表是否为空。这是因为在 Go 中，整数值被初始化为`0`；因此`new(Node)`实际上是`{0 <nil>}`，这使得在不传递额外变量给每个操作链表的函数的情况下，无法判断列表的头部是否为空。

执行`linkedList.go`将生成以下输出：

```go
$ go run linkedList.go
&{0 <nil>}
-> Empty list!
Node already exists: 1
1 ->
Node already exists: 0
1 -> 10 -> 5 -> 0 ->
1 -> 10 -> 5 -> 0 -> 100 ->
```

# Go 中的树

**图**是一个有限且非空的顶点和边的集合。**有向图**是一个边带有方向的图。**有向无环图**是一个没有循环的有向图。**树**是一个满足三个原则的有向无环图：首先，它有一个根节点：树的入口点；其次，除了根之外，每个顶点只有一个入口点；第三，存在一条连接根和每个顶点的路径，并且属于树。

因此，根是树的第一个节点。每个节点可以连接到一个或多个节点，具体取决于树的类型。如果每个节点只指向一个其他节点，那么树就是一个链表！

最常用的树类型是二叉树，因为每个节点最多可以有两个子节点。下图显示了二叉树数据结构的图形表示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/4f4a000e-6fe7-4025-81f3-ff52adfbd59f.png)

二叉树

所呈现的代码只会向您展示如何创建二叉树以及如何遍历它以打印出所有元素，以证明 Go 可以用于创建树数据结构。因此，它不会实现二叉树的完整功能，其中还包括删除树节点和平衡树。

`tree.go`的代码将分为三部分呈现。

第一部分是预期的序言以及节点的定义，如下所示：

```go
package main 

import ( 
   "fmt" 
   "math/rand" 
   "time" 
) 
type Tree struct { 
   Left  *Tree 
   Value int 
   Right *Tree 
} 
```

第二部分包含允许您遍历树以打印所有元素、使用随机生成的数字创建树以及将节点插入其中的函数：

```go
func traverse(t *Tree) { 
   if t == nil { 
         return 
   } 
   traverse(t.Left) 
   fmt.Print(t.Value, " ") 
   traverse(t.Right) 
} 

func create(n int) *Tree { 
   var t *Tree 
   rand.Seed(time.Now().Unix()) 
   for i := 0; i< 2*n; i++ { 
         temp := rand.Intn(n) 
         t = insert(t, temp) 
   } 
   return t 
} 

func insert(t *Tree, v int) *Tree { 
   if t == nil { 
         return&Tree{nil, v, nil} 
   } 
   if v == t.Value { 
         return t 
   } 
   if v <t.Value { 
         t.Left = insert(t.Left, v) 
         return t 
   } 
   t.Right = insert(t.Right, v) 
   return t 
} 
```

`insert()`的第二个`if`语句检查树中是否已经存在值，以免重复添加。第三个`if`语句标识新元素将位于当前节点的左侧还是右侧。

最后一部分是`main()`函数的实现：

```go
func main() { 
   tree := create(30) 
   traverse(tree) 
   fmt.Println() 
   fmt.Println("The value of the root of the tree is", tree.Value) 
} 
```

执行`tree.go`将生成以下输出：

```go
$ go run tree.go
0 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 21 22 23 24 25 26 27 28 29
The value of the root of the tree is 16
```

请注意，由于树的节点的值是随机生成的，程序的输出每次运行时都会不同。如果您希望始终获得相同的元素，则在`create()`函数中使用种子值的常量。

# 在 Go 中开发哈希表

严格来说，**哈希表**是一种数据结构，它存储一个或多个键值对，并使用键的`hashFunction`计算出数组中的桶或槽的索引，从中可以检索到正确的值。理想情况下，`hashFunction`应该将每个键分配到一个唯一的桶中，前提是您有所需数量的桶。

一个良好的`hashFunction`必须能够产生均匀分布的哈希值，因为拥有未使用的桶或桶的基数差异很大是低效的。此外，`hashFunction`应该能够一致地工作，并为相同的键输出相同的哈希值，否则将无法找到所需的信息！如果你认为哈希表并不那么有用、方便或聪明，你应该考虑以下：当哈希表有*n*个键和*k*个桶时，其搜索速度从线性搜索的 O(n)变为 O(n/k)!虽然改进看起来很小，但你应该意识到，对于只有 20 个插槽的哈希数组，搜索时间将减少 20 倍！这使得哈希表非常适用于诸如字典或任何其他类似的应用程序，其中需要搜索大量数据。尽管使用大量桶会增加程序的复杂性和内存使用量，但有时这是值得的。

下图显示了一个具有 10 个桶的简单哈希表的图形表示。很容易理解`hashFunction`是取模运算符：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/30731fad-6b66-43d1-8e49-25ae564255a1.png)

一个简单的哈希表

尽管所呈现的哈希表版本使用数字，因为它们更容易实现和理解，但只要你能找到合适的`hashFunction`来处理输入，你可以使用任何数据类型。`hash.go`的源代码将分为三部分呈现。

第一个是以下内容：

```go
package main 

import ( 
   "fmt" 
) 

type Node struct { 
   Value int 
   Next  *Node 
} 

type HashTablestruct { 
   Table map[int]*Node

   Size  int 
} 
```

`Node struct`的定义取自您之前看到的链表的实现。使用`map`变量的`Table`而不是切片的原因是，切片的索引只能是自然数，而`map`的键可以是任何东西。

第二部分包含以下 Go 代码：

```go
func hashFunction(i, size int) int { 
   return (i % size) 
} 

func insert(hash *HashTable, value int) int { 
   index := hashFunction(value, hash.Size) 
   element := Node{Value: value, Next: hash.Table[index]} 
   hash.Table[index] = &element 
   return index 
} 

func traverse(hash *HashTable) { 
   for k := range hash.Table { 
         if hash.Table[k] != nil { 
               t := hash.Table[k] 
               for t != nil { 
                     fmt.Printf("%d -> ", t.Value) 
                     t = t.Next 
               } 
               fmt.Println() 
         } 
   } 
}
```

请注意，`traverse()`函数使用`linkedList.go`中的 Go 代码来遍历哈希表中每个桶的元素。另外，请注意，`insert`函数不会检查值是否已经存在于哈希表中，以节省空间，但通常情况下并非如此。另外，出于速度和简单性的考虑，新元素被插入到每个列表的开头。

最后一部分包含了`main()`函数的实现：

```go
func main() { 
   table := make(map[int]*Node, 10) 
   hash := &HashTable{Table: table, Size: 10} 
   fmt.Println("Number of spaces:", hash.Size) 
   for i := 0; i< 95; i++ { 
         insert(hash, i) 
   } 
   traverse(hash) 
} 
```

执行`hash.go`将生成以下输出，证明哈希表按预期工作：

```go
$ go run hash.go
Number of spaces: 10 89 -> 79 -> 69 -> 59 -> 49 -> 39 -> 29 -> 19 -> 9 ->
86 -> 76 -> 66 -> 56 -> 46 -> 36 -> 26 -> 16 -> 6 ->
92 -> 82 -> 72 -> 62 -> 52 -> 42 -> 32 -> 22 -> 12 -> 2 ->
94 -> 84 -> 74 -> 64 -> 54 -> 44 -> 34 -> 24 -> 14 -> 4 ->
85 -> 75 -> 65 -> 55 -> 45 -> 35 -> 25 -> 15 -> 5 ->
87 -> 77 -> 67 -> 57 -> 47 -> 37 -> 27 -> 17 -> 7 ->
88 -> 78 -> 68 -> 58 -> 48 -> 38 -> 28 -> 18 -> 8 ->
90 -> 80 -> 70 -> 60 -> 50 -> 40 -> 30 -> 20 -> 10 -> 0 ->
91 -> 81 -> 71 -> 61 -> 51 -> 41 -> 31 -> 21 -> 11 -> 1 ->
93 -> 83 -> 73 -> 63 -> 53 -> 43 -> 33 -> 23 -> 13 -> 3 ->
```

如果你多次执行`hash.go`，你会发现打印行的顺序会变化。这是因为`traverse()`函数中`range hash.Table`的输出是无法预测的，这是因为 Go 对哈希的返回顺序没有指定。

# 关于 Go 包

包用于将相关函数和常量分组，以便您可以轻松地传输它们并在自己的 Go 程序中使用。因此，除了主包之外，包不是独立的程序。

每个 Go 发行版都附带许多有用的 Go 包，包括以下内容：

+   `net`包：这支持可移植的 TCP 和 UDP 连接

+   `http`包：这是 net 包的一部分，提供了 HTTP 服务器和客户端的实现

+   `math`包：这提供了数学函数和常量

+   `io`包：这处理原始的输入和输出操作

+   `os`包：这为您提供了一个便携式的操作系统功能接口

+   `time`包：这允许您处理时间和日期

有关标准 Go 包的完整列表，请参阅[`golang.org/pkg/`](https://golang.org/pkg/)。我强烈建议您在开始开发自己的函数和包之前，先了解 Go 提供的所有包，因为你要寻找的功能很可能已经包含在标准 Go 包中。

# 使用标准 Go 包

您可能已经知道如何使用标准的 Go 包。但是，您可能不知道的是，一些包有一个结构。例如，`net`包有几个子目录，命名为`http`、`mail`、`rpc`、`smtp`、`textproto`和`url`，应该分别导入为`net/http`、`net/mail`、`net/rpc`、`net/smtp`、`net/textproto`和`net/url`。Go 在这些情况下对包进行分组，但是如果它们是为了分发而不是功能而分组，这些包也可以是独立的包。

您可以使用`godoc`实用程序查找有关 Go 标准包的信息。因此，如果您正在寻找有关`net`包的信息，您应该执行`godoc net`。

# 创建您自己的包

包使得大型软件系统的设计、实现和维护更加简单和容易。此外，它们允许多个程序员在同一个项目上工作而不会发生重叠。因此，如果您发现自己一直在使用相同的函数，您应该认真考虑将它们包含在您自己的 Go 包中。

Go 包的源代码，可以包含多个文件，可以在一个目录中找到，该目录以包的名称命名，除了主包，主包可以有任何名称。

在本节中将开发的`aSimplePackage.go`文件的 Go 代码将分为两部分呈现。

第一部分是以下内容：

```go
package aSimplePackage 

import ( 
   "fmt" 
) 
```

这里没有什么特别的；您只需定义包的名称并包含必要的导入语句，因为一个包可以依赖于其他包。

第二部分包含以下 Go 代码：

```go
const Pi = "3.14159" 

func Add(x, y int) int { 
   return x + y 
} 

func Println(x int) { 
   fmt.Println(x) 
} 
```

因此，`aSimplePackage`包提供了两个函数和一个常量。

完成`aSimplePackage.go`的代码编写后，您应该执行以下命令，以便能够在其他 Go 程序或包中使用该包：

```go
$ mkdir ~/go
$ mkdir ~/go/src
$ mkdir ~/go/src/aSimplePackage
$ export GOPATH=~/go
$ vi ~/go/src/aSimplePackage/aSimplePackage.go
$ go install aSimplePackage 
```

除了前两个`mkdir`命令，您应该为您创建的每个 Go 包执行所有这些操作，这两个命令只需要执行一次。

如您所见，每个包都需要在`~/go/src`目录下有自己的文件夹。在执行上述命令后，`go tool`将自动生成一个 Go 包的`ar(1)`存档文件，该文件刚刚在`pkg`目录中编译完成：

```go
$ ls -lR ~/go
total 0
drwxr-xr-x  3 mtsouk  staff  102 Apr  4 22:35 pkg
drwxr-xr-x  3 mtsouk  staff  102 Apr  4 22:35 src

/Users/mtsouk/go/pkg:
total 0
drwxr-xr-x  3 mtsouk  staff  102 Apr  4 22:35 darwin_amd64

/Users/mtsouk/go/pkg/darwin_amd64:
total 8
-rw-r--r--  1 mtsouk  staff  2918 Apr  4 22:35 aSimplePackage.a

/Users/mtsouk/go/src:
total 0
drwxr-xr-x  3 mtsouk  staff  102 Apr  4 22:35 aSimplePackage

/Users/mtsouk/go/src/aSimplePackage:
total 8
-rw-r--r--  1 mtsouk  staff  148 Apr  4 22:30 aSimplePackage.go
```

尽管您现在已经准备好使用`aSimplePackage`包，但是没有一个独立的程序，您无法看到包的功能。

# 私有变量和函数

私有变量和函数与公共变量和函数不同，它们只能在包内部使用和调用。控制哪些函数和变量是公共的或不公共的也被称为封装。

Go 遵循一个简单的规则，即以大写字母开头的函数、变量、类型等都是公共的，而以小写字母开头的函数、变量、类型等都是私有的。但是，这个规则不影响包名。

现在您应该明白为什么`fmt.Printf()`函数的命名是这样的，而不是`fmt.printf()`。

为了说明这一点，我们将对`aSimplePackage.go`模块进行一些更改，并添加一个私有变量和一个私有函数。新的独立包的名称将是`anotherPackage.go`。您可以使用`diff(1)`命令行实用程序查看对其所做的更改：

```go
$ diff aSimplePackage.go anotherPackage.go
1c1
<packageaSimplePackage
---
>packageanotherPackage
7a8
>const version = "1.1"
15a17,20
>
>func Version() {
>     fmt.Println("The version of the package is", version)
> }
```

# init()函数

每个 Go 包都可以有一个名为`init()`的函数，在执行开始时自动执行。因此，让我们在`anotherPackage.go`包的代码中添加以下`init()`函数：

```go
func init() { 
   fmt.Println("The init function of anotherPackage") 
} 
```

`init()`函数的当前实现是简单的，没有特殊操作。但是，有时您希望在开始使用包之前执行重要的初始化操作，例如打开数据库和网络连接：在这些相对罕见的情况下，`init()`函数是非常宝贵的。

# 使用您自己的 Go 包

本小节将向你展示如何在你自己的 Go 程序中使用`aSimplePackage`和`anotherPackage`包，通过展示两个名为`usePackage.go`和`privateFail.go`的小型 Go 程序。

为了使用`GOPATH`目录下的`aSimplePackage`包，你需要在另一个 Go 程序中编写以下 Go 代码：

```go
package main 

import ( 
   "aSimplePackage" 
   "fmt" 
) 

func main() { 
   temp := aSimplePackage.Add(5, 10) 
   fmt.Println(temp)

   fmt.Println(aSimplePackage.Pi) 
} 
```

首先，如果`aSimplePackage`尚未编译并位于预期位置，编译过程将失败，并显示类似以下的错误消息：

```go
$ go run usePackage.go
usePackage.go:4:2: cannot find package "aSimplePackage" in any of:
      /usr/local/Cellar/go/1.8/libexec/src/aSimplePackage (from $GOROOT)
      /Users/mtsouk/go/src/aSimplePackage (from $GOPATH)
```

然而，如果`aSimplePackage`可用，`usePackage.go`将会被成功执行：

```go
$ go run usePackage.go
15
3.14159
```

现在，让我们看看另一个使用`anotherPackage`的小程序的 Go 代码：

```go
package main 

import ( 
   "anotherPackage" 
   "fmt" 
) 

func main() { 
   anotherPackage.Version() 
   fmt.Println(anotherPackage.version) 
   fmt.Println(anotherPackage.Pi) 
} 
```

如果你尝试从`anotherPackage`调用私有函数或使用私有变量，你的 Go 程序`privateFail.go`将无法运行，并显示以下错误消息：

```go
$ go run privateFail.go
# command-line-arguments
./privateFail.go:10: cannot refer to unexported name anotherPackage.version
./privateFail.go:10: undefined: anotherPackage.version
```

我真的很喜欢显示错误消息，因为大多数书籍都试图隐藏它们，好像它们不存在一样。当我学习 Go 时，我花了大约 3 个小时的调试，直到我发现一个我无法解释的错误消息的原因是一个变量的名字！

然而，如果你从`privateFail.go`中删除对私有变量的调用，程序将在没有错误的情况下执行。此外，你会看到`init()`函数实际上会自动执行：

```go
$ go run privateFail.go
The init function of anotherPackage
The version of the package is 1.1
3.14159
```

# 使用外部 Go 包

有时候，包可以在互联网上找到，并且你希望通过指定它们的互联网地址来使用它们。一个这样的例子是 Go 的`MySQL`驱动程序，可以在`github.com/go-sql-driver/mysql`找到。

看看以下的 Go 代码，保存为`useMySQL.go`：

```go
package main 

import ( 
   "fmt" 
   _ "github.com/go-sql-driver/mysql"
) 

func main() { 
   fmt.Println("Using the MySQL Go driver!") 
} 
```

使用`_`作为包标识符将使编译器忽略包未被使用的事实：绕过编译器的唯一合理理由是当你的未使用包中有一个你想要执行的`init`函数时。另一个合理的理由是为了说明一个 Go 概念！

如果你尝试执行`useMySQL.go`，编译过程将失败：

```go
$ go run useMySQL.go
useMySQL.go:5:2: cannot find package "github.com/go-sql-driver/mysql" in any of:
      /usr/local/Cellar/go/1.8/libexec/src/github.com/go-sql-driver/mysql (from $GOROOT)
      /Users/mtsouk/go/src/github.com/go-sql-driver/mysql (from $GOPATH)
```

为了编译`useMySQL.go`，你应该首先执行以下步骤：

```go
$ go get github.com/go-sql-driver/mysql
$ go run useMySQL.go
Using the MySQL Go driver!
```

成功下载所需的包后，`~/go`目录的内容将验证所需的 Go 包已被下载：

```go
$ ls -lR ~/go
total 0
drwxr-xr-x  3 mtsouk  staff  102 Apr  4 22:35 pkg
drwxr-xr-x  5 mtsouk  staff  170 Apr  6 21:32 src

/Users/mtsouk/go/pkg:
total 0
drwxr-xr-x  5 mtsouk  staff  170 Apr  6 21:32 darwin_amd64

/Users/mtsouk/go/pkg/darwin_amd64:
total 24
-rw-r--r--  1 mtsouk  staff  2918 Apr  4 23:07 aSimplePackage.a
-rw-r--r--  1 mtsouk  staff  6102 Apr  4 22:50 anotherPackage.a
drwxr-xr-x  3 mtsouk  staff   102 Apr  6 21:32 github.com

/Users/mtsouk/go/pkg/darwin_amd64/github.com:
total 0
drwxr-xr-x  3 mtsouk  staff  102 Apr  6 21:32 go-sql-driver

/Users/mtsouk/go/pkg/darwin_amd64/github.com/go-sql-driver:
total 728
-rw-r--r--  1 mtsouk  staff  372694 Apr  6 21:32 mysql.a

/Users/mtsouk/go/src:
total 0
drwxr-xr-x  3 mtsouk  staff  102 Apr  4 22:35 aSimplePackage
drwxr-xr-x  3 mtsouk  staff  102 Apr  4 22:50 anotherPackage
drwxr-xr-x  3 mtsouk  staff  102 Apr  6 21:32 github.com

/Users/mtsouk/go/src/aSimplePackage:
total 8
-rw-r--r--  1 mtsouk  staff  148 Apr  4 22:30 aSimplePackage.go

/Users/mtsouk/go/src/anotherPackage:
total 8
-rw-r--r--@ 1 mtsouk  staff  313 Apr  4 22:50 anotherPackage.go

/Users/mtsouk/go/src/github.com:
total 0
drwxr-xr-x  3 mtsouk  staff  102 Apr  6 21:32 go-sql-driver

/Users/mtsouk/go/src/github.com/go-sql-driver:
total 0
drwxr-xr-x  35 mtsouk  staff  1190 Apr  6 21:32 mysql

/Users/mtsouk/go/src/github.com/go-sql-driver/mysql:
total 584
-rw-r--r--  1 mtsouk  staff   2066 Apr  6 21:32 AUTHORS
-rw-r--r--  1 mtsouk  staff   5581 Apr  6 21:32 CHANGELOG.md
-rw-r--r--  1 mtsouk  staff   1091 Apr  6 21:32 CONTRIBUTING.md
-rw-r--r--  1 mtsouk  staff  16726 Apr  6 21:32 LICENSE
-rw-r--r--  1 mtsouk  staff  18610 Apr  6 21:32 README.md
-rw-r--r--  1 mtsouk  staff    470 Apr  6 21:32 appengine.go
-rw-r--r--  1 mtsouk  staff   4965 Apr  6 21:32 benchmark_test.go
-rw-r--r--  1 mtsouk  staff   3339 Apr  6 21:32 buffer.go
-rw-r--r--  1 mtsouk  staff   8405 Apr  6 21:32 collations.go
-rw-r--r--  1 mtsouk  staff   8525 Apr  6 21:32 connection.go
-rw-r--r--  1 mtsouk  staff   1831 Apr  6 21:32 connection_test.go
-rw-r--r--  1 mtsouk  staff   3111 Apr  6 21:32 const.go
-rw-r--r--  1 mtsouk  staff   5036 Apr  6 21:32 driver.go
-rw-r--r--  1 mtsouk  staff   4246 Apr  6 21:32 driver_go18_test.go
-rw-r--r--  1 mtsouk  staff  47090 Apr  6 21:32 driver_test.go
-rw-r--r--  1 mtsouk  staff  13046 Apr  6 21:32 dsn.go
-rw-r--r--  1 mtsouk  staff   7872 Apr  6 21:32 dsn_test.go
-rw-r--r--  1 mtsouk  staff   3798 Apr  6 21:32 errors.go
-rw-r--r--  1 mtsouk  staff    989 Apr  6 21:32 errors_test.go
-rw-r--r--  1 mtsouk  staff   4571 Apr  6 21:32 infile.go
-rw-r--r--  1 mtsouk  staff  31362 Apr  6 21:32 packets.go
-rw-r--r--  1 mtsouk  staff   6453 Apr  6 21:32 packets_test.go
-rw-r--r--  1 mtsouk  staff    600 Apr  6 21:32 result.go
-rw-r--r--  1 mtsouk  staff   3698 Apr  6 21:32 rows.go
-rw-r--r--  1 mtsouk  staff   3609 Apr  6 21:32 statement.go
-rw-r--r--  1 mtsouk  staff    729 Apr  6 21:32 transaction.go
-rw-r--r--  1 mtsouk  staff  17924 Apr  6 21:32 utils.go
-rw-r--r--  1 mtsouk  staff   5784 Apr  6 21:32 utils_test.go
```

# go clean 命令

有时候，你正在开发一个使用大量非标准 Go 包的大型 Go 程序，并且希望从头开始编译过程。Go 允许你清理一个包的文件，以便稍后重新创建它。以下命令清理一个包，而不影响包的代码：

```go
$ go clean -x -i aSimplePackage
cd /Users/mtsouk/go/src/aSimplePackage
rm -f aSimplePackage.test aSimplePackage.test.exe
rm -f /Users/mtsouk/go/pkg/darwin_amd64/aSimplePackage.a
```

同样，你也可以清理从互联网下载的包，这也需要使用其完整路径：

```go
$ go clean -x -i github.com/go-sql-driver/mysql
cd /Users/mtsouk/go/src/github.com/go-sql-driver/mysql
rm -f mysql.test mysql.test.exe appengine appengine.exe
rm -f /Users/mtsouk/go/pkg/darwin_amd64/github.com/go-sql-driver/mysql.a
```

请注意，当你想将项目转移到另一台机器上而不包括不必要的文件时，`go clean`命令也特别有用。

# 垃圾收集

在本节中，我们将简要讨论 Go 如何处理 GC，它试图高效地释放未使用的内存。`garbageCol.go`的 Go 代码可以分为两部分。

第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "runtime" 
   "time" 
) 

func printStats(mem runtime.MemStats) { 
   runtime.ReadMemStats(&mem) 
   fmt.Println("mem.Alloc:", mem.Alloc) 
   fmt.Println("mem.TotalAlloc:", mem.TotalAlloc) 
   fmt.Println("mem.HeapAlloc:", mem.HeapAlloc) 
   fmt.Println("mem.NumGC:", mem.NumGC) 
   fmt.Println("-----") 
} 
```

每当你想要读取最新的内存统计信息时，你应该调用`runtime.ReadMemStats()`函数。

第二部分包含了`main()`函数的实现，其中包含以下 Go 代码：

```go
func main() { 
   var memruntime.MemStats 
   printStats(mem) 

   for i := 0; i< 10; i++ { 
         s := make([]byte, 100000000) 
         if s == nil { 
               fmt.Println("Operation failed!") 
         } 
   } 
   printStats(mem) 

   for i := 0; i< 10; i++ { 
         s := make([]byte, 100000000) 
         if s == nil { 
               fmt.Println("Operation failed!") 
         } 
         time.Sleep(5 * time.Second) 
   } 
   printStats(mem)

} 
```

在这里，你尝试获取大量内存，以触发垃圾收集器的使用。

执行`garbageCol.go`会生成以下输出：

```go
$ go run garbageCol.go
mem.Alloc: 53944
mem.TotalAlloc: 53944
mem.HeapAlloc: 53944
mem.NumGC: 0
-----
mem.Alloc: 100071680
mem.TotalAlloc: 1000146400
mem.HeapAlloc: 100071680
mem.NumGC: 10
-----
mem.Alloc: 66152
mem.TotalAlloc: 2000230496
mem.HeapAlloc: 66152
mem.NumGC: 20
-----
```

因此，输出呈现了与`garbageCol.go`程序使用的内存相关的属性信息。如果你想获得更详细的输出，可以执行`garbageCol.go`，如下所示：

```go
$ GODEBUG=gctrace=1 go run garbageCol.go
```

这个命令的版本将以以下格式给出信息：

```go
gc 11 @0.101s 0%: 0.003+0.083+0.020 ms clock, 0.030+0.059/0.033/0.006+0.16 mscpu, 95->95->0 MB, 96 MB goal, 8 P
```

`95->95->0 MB` 部分包含有关各种堆大小的信息，还显示了垃圾收集器的表现如何。第一个值是 GC 开始时的堆大小，而中间值显示了 GC 结束时的堆大小。第三个值是活动堆的大小。

# 您的环境

在本节中，我们将展示如何使用 `runtime` 包查找有关您的环境的信息：当您必须根据操作系统和您使用的 Go 版本采取某些操作时，这可能很有用。

使用 `runtime` 包查找有关您的环境的信息是直接的，并在 `runTime.go` 中有所说明：

```go
package main 

import ( 
   "fmt" 
   "runtime" 
) 

func main() { 
   fmt.Print("You are using ", runtime.Compiler, " ") 
   fmt.Println("on a", runtime.GOARCH, "machine") 
   fmt.Println("with Go version", runtime.Version()) 
   fmt.Println("Number of Goroutines:", runtime.NumGoroutine())
} 
```

只要您知道要从 runtime 包中调用什么，就可以获取所需的信息。这里的最后一个 `fmt.Println()` 命令显示有关 **goroutines** 的信息：您将在第九章*,* *Goroutines - Basic Features* 中了解更多关于 goroutines 的信息。

在 macOS 机器上执行 `runTime.go` 会生成以下输出：

```go
$ go run runTime.go
You are using gc on a amd64 machine
with Go version go1.8
Number of Goroutines: 1  
```

在使用旧版 Go 的 Linux 机器上执行 `runTime.go` 会得到以下结果：

```go
$ go run runTime.go
You are using gc on a amd64 machine
with Go version go1.3.3
Number of Goroutines: 4
```

# Go 经常更新！

在写完本章的最后，Go 进行了一点更新。因此，我决定在本书中包含这些信息，以便更好地了解 Go 的更新频率：

```go
$ date
Sat Apr  8 09:16:46 EEST 2017
$ go version
go version go1.8.1 darwin/amd64
```

# 练习

1.  访问 runtime 包的文档。

1.  创建您自己的结构，创建一个切片，并使用 `sort.Slice()` 对您创建的切片的元素进行排序。

1.  在 Go 中实现快速排序算法，并对一些随机生成的数字数据进行排序。

1.  实现一个双向链表。

1.  `tree.go` 的实现远未完成！尝试实现一个检查树中是否可以找到值的函数，以及一个允许您删除树节点的函数。

1.  同样，`linkedList.go` 文件的实现也是不完整的。尝试实现一个用于删除节点的函数，以及另一个用于在链表中某个位置插入节点的函数。

1.  再次，`hash.go` 的哈希表实现是不完整的，因为它允许重复条目。因此，在插入之前，实现一个在哈希表中搜索键的函数。

# 总结

在本章中，您学到了许多与算法和数据结构相关的知识。您还学会了如何使用现有的 Go 包以及如何开发自己的 Go 包。本章还讨论了 Go 中的垃圾收集以及如何查找有关您的环境的信息。

在下一章中，我们将开始讨论系统编程，并呈现更多的 Go 代码。更确切地说，第五章，*文件和目录*，将讨论如何在 Go 中处理文件和目录，如何轻松地遍历目录结构，以及如何使用 `flag` 包处理命令行参数。但更重要的是，我们将开始开发各种 Unix 命令行实用程序的 Go 版本。


# 第五章：文件和目录

在上一章中，我们谈到了许多重要的主题，包括开发和使用 Go 包，Go 数据结构，算法和 GC。然而，直到现在，我们还没有开发任何实际的系统实用程序。这很快就会改变，因为从这一非常重要的章节开始，我们将开始学习如何使用 Go 来开发真正的系统实用程序，以便处理文件系统的各种类型的文件和目录。

您应该始终记住，Unix 将一切都视为文件，包括符号链接、目录、网络设备、网络套接字、整个硬盘驱动器、打印机和纯文本文件。本章的目的是说明 Go 标准库如何允许我们了解路径是否存在，以及如何搜索目录结构以检测我们想要的文件类型。此外，本章将通过 Go 代码作为证据证明，许多传统的 Unix 命令行实用程序在处理文件和目录时并不难实现。

在本章中，您将学习以下主题：

+   将帮助您操作目录和文件的 Go 包

+   使用`flag`包轻松处理命令行参数和选项

+   在 Go 中开发`which(1)`命令行实用程序的版本

+   在 Go 中开发`pwd(1)`命令行实用程序的版本

+   删除和重命名文件和目录

+   轻松遍历目录树

+   编写`find(1)`实用程序的版本

+   在另一个地方复制目录结构

# 有用的 Go 包

允许您将文件和目录视为实体的最重要的包是`os`包，在本章中我们将广泛使用它。如果您将文件视为带有内容的盒子，`os`包允许您移动它们，将它们放入废纸篓，更改它们的名称，访问它们，并决定您想要使用哪些文件，而`io`包，将在下一章中介绍，允许您操作盒子的内容，而不必太担心盒子本身！

`flag`包，您将很快看到，让您定义和处理自己的标志，并操作 Go 程序的命令行参数。

`filepath`包非常方便，因为它包括`filepath.Walk()`函数，允许您以简单的方式遍历整个目录结构。

# 重新审视命令行参数！

正如我们在第二章中所看到的，*使用 Go 编写程序*，使用`if`语句无法高效处理多个命令行参数和选项。解决这个问题的方法是使用`flag`包，这将在这里解释。

记住`flag`包是一个标准的 Go 包，您不必在其他地方搜索标志的功能非常重要。

# flag 包

`flag`包为我们解析命令行参数和选项做了脏活，因此无需编写复杂和令人困惑的 Go 代码。此外，它支持各种类型的参数，包括字符串、整数和布尔值，这样可以节省时间，因为您不必执行任何数据类型转换。

`usingFlag.go`程序演示了`flag`Go 包的使用，并将分为三个部分呈现。第一部分包含以下 Go 代码：

```go
package main 

import ( 
   "flag" 
   "fmt" 
) 
```

程序的最重要的 Go 代码在第二部分中，如下所示：

```go
func main() { 
   minusO := flag.Bool("o", false, "o") 
   minusC := flag.Bool("c", false, "c") 
   minusK := flag.Int("k", 0, "an int") 

   flag.Parse() 
```

在这部分，您可以看到如何定义您感兴趣的标志。在这里，您定义了`-o`、`-c`和`-k`。虽然前两个是布尔标志，但`-k`标志需要一个整数值，可以写成`-k=123`。

最后一部分包含以下 Go 代码：

```go
   fmt.Println("-o:", *minusO) 
   fmt.Println("-c:", *minusC) 
   fmt.Println("-K:", *minusK) 

   for index, val := range flag.Args() { 
         fmt.Println(index, ":", val) 
   } 
} 
```

在这部分中，您可以看到如何读取选项的值，这也允许您判断选项是否已设置。另外，`flag.Args()`允许您访问程序未使用的命令行参数。

`usingFlag.go`的使用和输出在以下输出中展示：

```go
$ go run usingFlag.go
-o: false
-c: false
-K: 0
$ go run usingFlag.go -o a b
-o: true
-c: false
-K: 0
0 : a
1 : b
```

但是，如果您忘记输入命令行选项（`-k`）的值，或者提供的值类型错误，您将收到以下消息，并且程序将终止：

```go
$ ./usingFlag -k
flag needs an argument: -k
Usage of ./usingFlag:
  -c  c
  -k int
      an int
  -o  o $ ./usingFlag -k=abc invalid value "abc" for flag -k: strconv.ParseInt: parsing "abc": invalid syntax
Usage of ./usingFlag:
  -c  c
  -k int
      an int
  -o  o
```

如果您不希望程序在出现解析错误时退出，可以使用`flag`包提供的`ErrorHandling`类型，它允许您通过`NewFlagSet()`函数更改`flag.Parse()`在错误时的行为。但是，在系统编程中，通常希望在一个或多个命令行选项出现错误时退出实用程序。

# 处理目录

目录允许您创建一个结构，并以便于您组织和搜索文件的方式存储文件。实际上，目录是文件系统上包含其他文件和目录列表的条目。这是通过**inode**的帮助发生的，inode 是保存有关文件和目录的信息的数据结构。

如下图所示，目录被实现为分配给 inode 的名称列表。因此，目录包含对自身、其父目录和其每个子目录的条目，其中其他内容可以是常规文件或其他目录：

您应该记住的是，inode 保存有关文件的元数据，而不是文件的实际数据。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/e74853d3-8d25-49c3-a968-dc7713c53a72.png)

inode 的图形表示

# 关于符号链接

**符号链接**是指向文件或目录的指针，在访问时解析。符号链接，也称为**软链接**，不等同于它们所指向的文件或目录，并且允许指向无处，这有时可能会使事情复杂化。

保存在`symbLink.go`中并分为两部分的以下 Go 代码允许您检查路径或文件是否是符号链接。第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "path/filepath" 
) 

func main() { 
   arguments := os.Args 
   if len(arguments) == 1 { 
         fmt.Println("Please provide an argument!") 
         os.Exit(1) 
   } 
   filename := arguments[1] 
```

这里没有发生什么特别的事情：您只需要确保获得一个命令行参数，以便有东西可以测试。第二部分是以下 Go 代码：

```go
   fileinfo, err := os.Lstat(fil /etcename) 
   if err != nil { 
         fmt.Println(err) 
         os.Exit(1) 
   } 

   if fileinfo.Mode()&os.ModeSymlink != 0 { 
         fmt.Println(filename, "is a symbolic link") 
         realpath, err := filepath.EvalSymlinks(filename) 
         if err == nil { 
               fmt.Println("Path:", realpath) 
         } 
   } 

}
```

`SymbLink.go`的前述代码比通常更加神秘，因为它使用了更低级的函数。确定路径是否为真实路径的技术涉及使用`os.Lstat()`函数，该函数提供有关文件或目录的信息，并在`os.Lstat()`调用的返回值上使用`Mode()`函数，以将结果与`os.ModeSymlink`常量进行比较，该常量是符号链接位。

此外，还存在`filepath.EvalSymlinks()`函数，允许您评估任何存在的符号链接并返回文件或目录的真实路径，这也在`symbLink.go`中使用。这可能会让您认为我们在为这样一个简单的任务使用大量的 Go 代码，这在一定程度上是正确的，但是当您开发系统软件时，您必须考虑所有可能性并保持谨慎。

执行`symbLink.go`，它只需要一个命令行参数，会生成以下输出：

```go
$ go run symbLink.go /etc
/etc is a symbolic link
Path: /private/etc
```

在本章的其余部分，您还将看到一些前面提到的 Go 代码作为更大程序的一部分。

# 实现 pwd(1)命令

当我开始考虑如何实现一个程序时，我的脑海中涌现了很多想法，有时决定要做什么变得太困难了！关键在于做一些事情，而不是等待，因为当您编写代码时，您将能够判断您所采取的方法是好还是不好，以及您是否应该尝试另一种方法。

`pwd(1)`命令行实用程序非常简单，但工作得很好。如果您编写大量 shell 脚本，您应该已经知道`pwd(1)`，因为当您想要获取与正在执行的脚本位于同一目录中的文件或目录的完整路径时，它非常方便。

`pwd.go`的 Go 代码将分为两部分，并且只支持`-P`命令行选项，该选项解析所有符号链接并打印物理当前工作目录。`pwd.go`的第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "path/filepath" 
) 

func main() { 
   arguments := os.Args 

   pwd, err := os.Getwd() 
   if err == nil { 
         fmt.Println(pwd) 
   } else { 
         fmt.Println("Error:", err) 
   } 
```

第二部分如下：

```go
   if len(arguments) == 1 { 
         return 
   } 

   if arguments[1] != "-P" { 
         return 
   } 

   fileinfo, err := os.Lstat(pwd) 
   if fileinfo.Mode()&os.ModeSymlink != 0 { 
         realpath, err := filepath.EvalSymlinks(pwd) 
         if err == nil { 
               fmt.Println(realpath) 
         } 
   } 
} 
```

请注意，如果当前目录可以由多个路径描述，这可能发生在使用符号链接时，`os.Getwd()`可以返回其中任何一个。此外，如果给出了`-P`选项并且正在处理一个目录是符号链接，您需要重用`symbolLink.go`中找到的一些 Go 代码来发现物理当前工作目录。此外，不在`pwd.go`中使用`flag`包的原因是我发现代码现在的方式更简单。

执行`pwd.go`将生成以下输出：

```go
$ go run pwd.go
/Users/mtsouk/Desktop/goBook/ch/ch5/code
```

在 macOS 机器上，`/tmp`目录是一个符号链接，这可以帮助我们验证`pwd.go`是否按预期工作：

```go
$ go run pwd.go
/tmp
$ go run pwd.go -P
/tmp
/private/tmp
```

# 使用 Go 开发`which(1)`实用程序

`which(1)`实用程序搜索`PATH`环境变量的值，以找出可执行文件是否存在于`PATH`变量的一个目录中。以下输出显示了`which(1)`实用程序的工作方式：

```go
$ echo $PATH
/home/mtsouk/bin:/usr/local/bin:/usr/bin:/bin:/usr/local/games:/usr/games
$ which ls
/home/mtsouk/bin/ls
code$ which -a ls
/home/mtsouk/bin/ls
/bin/ls
```

我们的 Unix 实用程序的实现将支持 macOS 版本的`which(1)`支持的两个命令行选项`-a`和`-s`，并借助`flag`包：Linux 版本的`which(1)`不支持`-s`选项。`-a`选项列出可执行文件的所有实例，而不仅仅是第一个，而`-s`返回`0`如果找到了可执行文件，否则返回`1`：这与使用`fmt`包打印`0`或`1`不同。

为了检查 Unix 命令行实用程序在 shell 中的返回值，您应该执行以下操作：

```go
$ which -s ls $ echo $?
0
```

请注意，`go run`会打印出非零的退出代码。

`which(1)`的 Go 代码将保存在`which.go`中，并将分为四个部分呈现。`which.go`的第一部分包含以下 Go 代码：

```go
package main 

import ( 
   "flag" 
   "fmt" 
   "os" 
   "strings" 
) 
```

需要`strings`包来分割读取`PATH`变量的内容。`which.go`的第二部分处理了`flag`包的使用：

```go
func main() { 
   minusA := flag.Bool("a", false, "a") 
   minusS := flag.Bool("s", false, "s") 

   flag.Parse() 
   flags := flag.Args() 
   if len(flags) == 0 { 
         fmt.Println("Please provide an argument!") 
         os.Exit(1) 
   } 
   file := flags[0] 
   fountIt := false 
```

`which.go`的一个非常重要的部分是读取`PATH` shell 环境变量以分割并使用它的部分，这在这里的第三部分中呈现：

```go
   path := os.Getenv("PATH") 
   pathSlice := strings.Split(path, ":") 
   for _, directory := range pathSlice { 
         fullPath := directory + "/" + file 
```

这里的最后一条语句构造了我们正在搜索的文件的完整路径，就好像它存在于`PATH`变量的每个单独目录中，因为如果你有文件的完整路径，你就不必再去搜索它了！

`which.go`的最后一部分如下：

```go
         fileInfo, err := os.Stat(fullPath) 
         if err == nil { 
               mode := fileInfo.Mode() 
               if mode.IsRegular() { 
                     if mode&0111 != 0 { 
                           fountIt = true 
                           if *minusS == true { 
                                 os.Exit(0) 
                           } 
                           if *minusA == true {

                                 fmt.Println(fullPath) 
                           } else { 
                                 fmt.Println(fullPath) 
                                 os.Exit(0) 
                           } 
                     } 
               } 
         } 
   } 
   if fountIt == false { 
         os.Exit(1) 
   } 
} 
```

在这里，对`os.Stat()`的调用告诉我们正在寻找的文件是否实际存在。在成功的情况下，`mode.IsRegular()`函数检查文件是否是常规文件，因为我们不寻找目录或符号链接。但是，我们还没有完成！`which.go`程序执行了一个测试，以找出找到的文件是否确实是可执行文件：如果不是可执行文件，它将不会被打印。因此，`if mode&0111 != 0`语句使用二进制操作验证文件实际上是可执行文件。

接下来，如果`-s`标志设置为`*minusS == true`，那么`-a`标志就不太重要了，因为一旦找到匹配项，程序就会终止。

正如您所看到的，在`which.go`中涉及许多测试，这对于系统软件来说并不罕见。尽管如此，您应该始终检查所有可能性，以避免以后出现意外。好消息是，这些测试中的大多数将在`find(1)`实用程序的 Go 实现中稍后使用：通过编写小程序来测试一些功能，然后将它们全部组合成更大的程序，这是一个很好的实践，因为这样做可以更好地学习技术，并且可以更容易地检测愚蠢的错误。

执行`which.go`将产生以下输出：

```go
$ go run which.go ls
/home/mtsouk/bin/ls
$ go run which.go -s ls
$ echo $?
0
$ go run which.go -s ls123123
exit status 1
$ echo $?
1
$ go run which.go -a ls
/home/mtsouk/bin/ls
/bin/ls
```

# 打印文件或目录的权限位

借助`ls(1)`命令，您可以找出文件的权限：

```go
$ ls -l /bin/ls
-rwxr-xr-x  1 root  wheel  38624 Mar 23 01:57 /bin/ls
```

在本小节中，我们将展示如何使用 Go 打印文件或目录的权限：Go 代码将保存在`permissions.go`中，并将分为两部分呈现。第一部分如下：

```go
package main 

import ( 
   "fmt" 
   "os" 
) 

func main() { 
   arguments := os.Args 
   if len(arguments) == 1 { 
         fmt.Println("Please provide an argument!") 
         os.Exit(1) 
   } 

   file := arguments[1] 
```

第二部分包含重要的 Go 代码：

```go
   info, err := os.Stat(file) 
   if err != nil { 
         fmt.Println("Error:", err) 
         os.Exit(1) 
   } 
   mode := info.Mode() 
   fmt.Print(file, ": ", mode, "\n") 
} 
```

再次强调，大部分的 Go 代码用于处理命令行参数并确保您有一个！实际工作的 Go 代码主要是调用`os.Stat()`函数，该函数返回一个描述`os.Stat()`检查的文件或目录的`FileInfo`结构。通过`FileInfo`结构，您可以调用`Mode()`函数来发现文件的权限。

执行`permissions.go`会产生以下输出：

```go
$ go run permissions.go /bin/ls
/bin/ls: -rwxr-xr-x
$ go run permissions.go /usr
/usr: drwxr-xr-x
$ go run permissions.go /us
Error: stat /us: no such file or directory
exit status 1
```

# 在 Go 中处理文件

操作系统的一个极其重要的任务是处理文件，因为所有数据都存储在文件中。在本节中，我们将向您展示如何删除和重命名文件，在下一节*在 Go 中开发 find(1)*中，我们将教您如何搜索目录结构以找到所需的文件。

# 删除文件

在本节中，我们将说明如何使用`os.Remove()` Go 函数删除文件和目录。

在测试删除文件和目录的程序时，请格外小心并且要有常识！

`rm.go`文件是`rm(1)`工具的 Go 实现，说明了您如何在 Go 中删除文件。尽管`rm(1)`的核心功能已经存在，但缺少`rm(1)`的选项：尝试实现其中一些选项将是一个很好的练习。在实现`-f`和`-R`选项时要特别注意。

`rm.go`的 Go 代码如下：

```go
package main 
import ( 
   "fmt" 
   "os" 
) 

func main() { 
   arguments := os.Args 
   if len(arguments) == 1 { 
         fmt.Println("Please provide an argument!") 
         os.Exit(1) 
   } 

   file := arguments[1] 
   err := os.Remove(file) 
   if err != nil { 
         fmt.Println(err) 
         return 
   } 
} 
```

如果`rm.go`在没有任何问题的情况下执行，将不会产生任何输出，这符合 Unix 哲学。因此，有趣的是观察当您尝试删除的文件不存在时可以获得的错误消息：当您没有必要的权限删除它时以及当目录不为空时：

```go
$ go run rm.go 123
remove 123: no such file or directory
$ ls -l /tmp/AlTest1.err
-rw-r--r--  1 root  wheel  1278 Apr 17 20:13 /tmp/AlTest1.err
$ go run rm.go /tmp/AlTest1.err
remove /tmp/AlTest1.err: permission denied
$ go run rm.go test
remove test: directory not empty
```

# 重命名和移动文件

在本小节中，我们将向您展示如何使用 Go 代码重命名和移动文件：Go 代码将保存为`rename.go`。尽管相同的代码可以用于重命名或移动目录，但`rename.go`只允许处理文件。

在执行一些无法轻易撤消的操作时，例如覆盖文件时，您应该格外小心，也许通知用户目标文件已经存在，以避免不愉快的意外。尽管传统的`mv(1)`实用程序的默认操作会自动覆盖目标文件（如果存在），但我认为这并不是很安全。因此，默认情况下，`rename.go`不会覆盖目标文件。

在开发系统软件时，您必须处理所有细节，否则这些细节将在最不经意的时候显露为错误！广泛的测试将使您能够找到您错过的细节并加以纠正。

`rename.go`的代码将分为四部分呈现。第一部分包括预期的序言以及处理`flag`包设置的 Go 代码：

```go
package main 

import ( 
   "flag" 
   "fmt" 
   "os" 
   "path/filepath" 
) 

func main() { 
   minusOverwrite := flag.Bool("overwrite", false, "overwrite") 

   flag.Parse() 
   flags := flag.Args() 

   if len(flags) < 2 { 
         fmt.Println("Please provide two arguments!") 
         os.Exit(1) 
   } 
```

第二部分包含以下 Go 代码：

```go
   source := flags[0] 
   destination := flags[1] 
   fileInfo, err := os.Stat(source) 
   if err == nil { 
         mode := fileInfo.Mode() 
         if mode.IsRegular() == false { 
               fmt.Println("Sorry, we only support regular files as source!") 
               os.Exit(1) 
         } 
   } else { 
         fmt.Println("Error reading:", source) 
         os.Exit(1) 
   } 
```

这部分确保源文件存在，是一个普通文件，并且不是一个目录或者其他类似网络套接字或管道的东西。再次，你在`which.go`中看到的`os.Stat()`的技巧在这里被使用了。

`rename.go`的第三部分如下：

```go
   newDestination := destination 
   destInfo, err := os.Stat(destination) 
   if err == nil { 
         mode := destInfo.Mode() 
         if mode.IsDir() { 
               justTheName := filepath.Base(source) 
               newDestination = destination + "/" + justTheName 
         } 
   } 
```

这里还有另一个棘手的地方；你需要考虑源文件是普通文件而目标是目录的情况，这是通过`newDestination`变量的帮助实现的。

另一个你应该考虑的特殊情况是，当源文件以包含绝对或相对路径的格式给出时，比如`./aDir/aFile`。在这种情况下，当目标是一个目录时，你应该获取路径的基本名称，即跟在最后一个`/`字符后面的内容，在这种情况下是`aFile`，并将其添加到目标目录中，以正确构造`newDestination`变量。这是通过`filepath.Base()`函数的帮助实现的，它返回路径的最后一个元素。

最后，`rename.go`的最后部分包含以下 Go 代码：

```go
   destination = newDestination 
   destInfo, err = os.Stat(destination) 
   if err == nil { 
         if *minusOverwrite == false { 
               fmt.Println("Destination file already exists!") 
               os.Exit(1) 
         } 
   } 

   err = os.Rename(source, destination) 
   if err != nil { 
         fmt.Println(err) 
         os.Exit(1) 
   } 
} 
```

`rename.go`最重要的 Go 代码与识别目标文件是否存在有关。再次，这是通过`os.Stat()`函数的支持实现的。如果`os.Stat()`返回一个错误消息，这意味着目标文件不存在；因此，你可以调用`os.Rename()`。如果`os.Stat()`返回`nil`，这意味着`os.Stat()`调用成功，并且目标文件存在。在这种情况下，你应该检查`overwrite`标志的值，以查看是否允许覆盖目标文件。

当一切正常时，你可以自由地调用`os.Rename()`并执行所需的任务！

如果`rename.go`被正确执行，它将不会产生任何输出。然而，如果有问题，`rename.go`将生成一些输出：

```go
$ touch newFILE
$ ./rename newFILE regExpFind.go
Destination file already exists!
$ ./rename -overwrite newFILE regExpFind.go
$
```

# 在 Go 中开发 find(1)

这一部分将教你开发一个简化版本的`find(1)`命令行实用程序所需的必要知识。开发的版本将不支持`find(1)`支持的所有命令行选项，但它将有足够的选项来真正有用。

在接下来的子章节中，你将看到整个过程分为小步骤。因此，第一个子章节将向你展示访问给定目录树中的所有文件和目录的 Go 方式。

# 遍历目录树

`find(1)`最重要的任务是能够访问从给定目录开始的所有文件和子目录。因此，这一部分将在 Go 中实现这个任务。`traverse.go`的 Go 代码将分为三部分呈现。第一部分是预期的序言：

```go
package main 

import ( 
   "fmt" 
   "os" 
   "path/filepath" 
) 
```

第二部分是关于实现一个名为`walkFunction()`的函数，该函数将用作 Go 函数`filepath.Walk()`的参数：

```go
func walkFunction(path string, info os.FileInfo, err error) error { 
   _, err = os.Stat(path) 
   if err != nil { 
         return err 
   } 

   fmt.Println(path) 
   return nil 
} 
```

再次，`os.Stat()`函数被使用是因为成功的`os.Stat()`函数调用意味着我们正在处理实际存在的东西（文件、目录、管道等）！

不要忘记，在调用`filepath.Walk()`和调用执行`walkFunction()`之间，活跃和繁忙的文件系统中可能会发生许多事情，这是调用`os.Stat()`的主要原因。

代码的最后部分如下：

```go
func main() { 
   arguments := os.Args 
   if len(arguments) == 1 { 
         fmt.Println("Not enough arguments!") 
         os.Exit(1) 
   } 

   Path := arguments[1] 
   err := filepath.Walk(Path, walkFunction) 
   if err != nil { 
         fmt.Println(err) 
         os.Exit(1) 
   } 
} 
```

所有这些繁琐的工作都是由`filepath.Walk()`函数自动完成的，借助于之前定义的`walkFunction()`函数。`filepath.Walk()`函数接受两个参数：一个目录的路径和它将使用的遍历函数。

执行`traverse.go`将生成以下类型的输出：

```go
$ go run traverse.go ~/code/C/cUNL
/home/mtsouk/code/C/cUNL
/home/mtsouk/code/C/cUNL/gpp
/home/mtsouk/code/C/cUNL/gpp.c
/home/mtsouk/code/C/cUNL/sizeofint
/home/mtsouk/code/C/cUNL/sizeofint.c
/home/mtsouk/code/C/cUNL/speed
/home/mtsouk/code/C/cUNL/speed.c
/home/mtsouk/code/C/cUNL/swap
/home/mtsouk/code/C/cUNL/swap.c
```

正如你所看到的，`traverse.go`的代码相当天真，因为它除其他事情外，无法区分目录、文件和符号链接。然而，它完成了访问给定目录树下的每个文件和目录的繁琐工作，这是`find(1)`实用程序的基本功能。

# 仅访问目录！

虽然能够访问所有内容是很好的，但有时您只想访问目录而不是文件。因此，在本小节中，我们将修改`traverse.go`以仍然访问所有内容，但只打印目录名称。新程序的名称将是`traverseDir.go`。需要更改的是`traverse.go`的唯一部分是`walkFunction()`的定义：

```go
func walkFunction(path string, info os.FileInfo, err error) error { 
   fileInfo, err := os.Stat(path) 
   if err != nil { 
         return err 
   } 

   mode := fileInfo.Mode() 
   if mode.IsDir() { 
         fmt.Println(path) 
   } 
   return nil 
} 
```

如您所见，您需要使用`os.Stat()`函数调用返回的信息来检查您是否正在处理目录。如果您有一个目录，那么打印其路径，您就完成了。

执行`traverseDir.go`将生成以下输出：

```go
$ go run traverseDir.go ~/code
/home/mtsouk/code
/home/mtsouk/code/C
/home/mtsouk/code/C/cUNL
/home/mtsouk/code/C/example
/home/mtsouk/code/C/sysProg
/home/mtsouk/code/C/system
/home/mtsouk/code/Haskell
/home/mtsouk/code/aLink
/home/mtsouk/code/perl
/home/mtsouk/code/python  
```

# find(1)的第一个版本

本节中的 Go 代码保存为`find.go`，将分为三部分呈现。正如您将看到的，`find.go`使用了在`traverse.go`中找到的大量代码，这是您逐步开发程序时获得的主要好处。

`find.go`的第一部分是预期的序言：

```go
package main 

import ( 
   "flag" 
   "fmt" 
   "os" 
   "path/filepath" 
) 
```

由于我们已经知道将来会改进`find.go`，因此即使这是`find.go`的第一个版本并且没有任何标志，这里也使用了`flag`包！

Go 代码的第二部分包含了`walkFunction()`的实现：

```go
func walkFunction(path string, info os.FileInfo, err error) error { 

   fileInfo, err := os.Stat(path) 
   if err != nil { 
         return err 
   } 

   mode := fileInfo.Mode() 
   if mode.IsDir() || mode.IsRegular() { 
         fmt.Println(path) 
   } 
   return nil 
} 
```

从`walkFunction()`的实现中，您可以轻松理解`find.go`只打印常规文件和目录，没有其他内容。这是一个问题吗？不是，如果这是您想要的。一般来说，这不是好的。尽管如此，尽管存在一些限制，但拥有一个能够工作的东西的第一个版本是一个很好的起点！下一个版本将被命名为`improvedFind.go`，将通过向其添加各种命令行选项来改进`find.go`。

`find.go`的最后一部分包含实现`main()`函数的代码：

```go
func main() { 
   flag.Parse() 
   flags := flag.Args() 

   if len(flags) == 0 { 
         fmt.Println("Not enough arguments!") 
         os.Exit(1) 
   } 

   Path := flags[0]

   err := filepath.Walk(Path, walkFunction) 
   if err != nil { 
         fmt.Println(err) 
         os.Exit(1) 
   } 
} 
```

执行`find.go`将创建以下输出：

```go
$ go run find.go ~/code/C/cUNL
/home/mtsouk/code/C/cUNL
/home/mtsouk/code/C/cUNL/gpp
/home/mtsouk/code/C/cUNL/gpp.c
/home/mtsouk/code/C/cUNL/sizeofint
/home/mtsouk/code/C/cUNL/sizeofint.c
/home/mtsouk/code/C/cUNL/speed
/home/mtsouk/code/C/cUNL/speed.c
/home/mtsouk/code/C/cUNL/swap
/home/mtsouk/code/C/cUNL/swap.c
```

# 添加一些命令行选项

本小节将尝试改进您之前创建的`find(1)`的 Go 版本。请记住，这是开发真实程序使用的过程，因为您不会在程序的第一个版本中实现每个可能的命令行选项。

新版本的 Go 代码将保存为`improvedFind.go`。新版本将能够忽略符号链接：只有在使用适当的命令行选项运行`improvedFind.go`时，才会打印符号链接。为此，我们将使用`symbolLink.go`的一些 Go 代码。

`improvedFind.go`程序是一个真正的系统工具，您可以在自己的 Unix 机器上使用。

支持的标志将是以下内容：

+   -s：这是用于打印套接字文件的

+   -p：这是用于打印管道的

+   -sl：这是用于打印符号链接的

+   -d：这是用于打印目录的

+   -f：这是用于打印文件的

正如您将看到的，大部分新的 Go 代码是为了支持添加到程序中的标志。此外，默认情况下，`improvedFind.go`打印每种类型的文件或目录，并且您可以组合任何前述标志以打印您想要的文件类型。

除了在实现`main()`函数中进行各种更改以支持所有这些标志之外，大部分其余更改将发生在`walkFunction()`函数的代码中。此外，`walkFunction()`函数将在`main()`函数内部定义，这是为了避免使用全局变量。

`improvedFind.go`的第一部分如下：

```go
package main 

import ( 
   "flag" 
   "fmt" 
   "os" 
   "path/filepath" 
) 

func main() { 

   minusS := flag.Bool("s", false, "Sockets") 
   minusP := flag.Bool("p", false, "Pipes") 
   minusSL := flag.Bool("sl", false, "Symbolic Links") 
   minusD := flag.Bool("d", false, "Directories") 
   minusF := flag.Bool("f", false, "Files") 

   flag.Parse() 
   flags := flag.Args() 

   printAll := false 
   if *minusS && *minusP && *minusSL && *minusD && *minusF { 
         printAll = true 
   } 

   if !(*minusS || *minusP || *minusSL || *minusD || *minusF) { 
         printAll = true 
   } 

   if len(flags) == 0 { 
         fmt.Println("Not enough arguments!") 
         os.Exit(1) 
   } 

   Path := flags[0] 
```

因此，如果所有标志都未设置，程序将打印所有内容，这由第一个`if`语句处理。同样，如果所有标志都设置了，程序也将打印所有内容。因此，需要一个名为`printAll`的新布尔变量。

`improvedFind.go`的第二部分包含以下 Go 代码，主要是`walkFunction`变量的定义，实际上是一个函数：

```go
   walkFunction := func(path string, info os.FileInfo, err error) error { 
         fileInfo, err := os.Stat(path) 
         if err != nil { 
               return err 
         } 

         if printAll { 
               fmt.Println(path) 
               return nil 
         } 

         mode := fileInfo.Mode() 
         if mode.IsRegular() && *minusF { 
               fmt.Println(path) 
               return nil 
         } 

         if mode.IsDir() && *minusD { 
               fmt.Println(path) 
               return nil 
         } 

         fileInfo, _ = os.Lstat(path)

         if fileInfo.Mode()&os.ModeSymlink != 0 { 
               if *minusSL { 
                     fmt.Println(path) 
                     return nil 
               } 
         } 

         if fileInfo.Mode()&os.ModeNamedPipe != 0 { 
               if *minusP { 
                     fmt.Println(path) 
                     return nil 
               } 
         } 

         if fileInfo.Mode()&os.ModeSocket != 0 { 
               if *minusS { 
                     fmt.Println(path) 
                     return nil 
               } 
         } 

         return nil 
   } 
```

在这里，好处是一旦找到匹配并打印文件，你就不必访问`if`语句的其余部分，这是将`minusF`检查放在第一位，`minusD`检查放在第二位的主要原因。调用`os.Lstat()`用于找出我们是否正在处理符号链接。这是因为`os.Stat()`会跟随符号链接并返回有关链接引用的文件的信息，而`os.Lstat()`不会这样做：`stat(2)`和`lstat(2)`也是如此。

你应该对`improvedFind.go`的最后部分非常熟悉：

```go
   err := filepath.Walk(Path, walkFunction) 
   if err != nil { 
         fmt.Println(err) 
         os.Exit(1) 
   } 
} 
```

执行`improvedFind.go`生成以下输出，这是`find.go`输出的增强版本：

```go
$ go run improvedFind.go -d ~/code/C
/home/mtsouk/code/C
/home/mtsouk/code/C/cUNL
/home/mtsouk/code/C/example
/home/mtsouk/code/C/sysProg
/home/mtsouk/code/C/system
$ go run improvedFind.go -sl ~/code
/home/mtsouk/code/aLink
```

# 从查找输出中排除文件名

有时你不需要显示`find(1)`的输出中的所有内容。因此，在这一小节中，你将学习一种技术，允许你根据文件名手动排除`improvedFind.go`的输出中的文件。

请注意，该程序的这个版本不支持正则表达式，只会排除文件名的精确匹配。

因此，`improvedFind.go`的改进版本将被命名为`excludeFind.go`。`diff(1)`实用程序的输出可以揭示`improvedFind.go`和`excludeFind.go`之间的代码差异：

```go
$ diff excludeFind.go improvedFind.go
10,19d9
< func excludeNames(name string, exclude string) bool {`
<     if exclude == "" {
<           return false
<     }
<     if filepath.Base(name) == exclude {
<           return true
<     }
<     return false
< }
<
27d16
<     minusX := flag.String("x", "", "Files")
54,57d42
<           if excludeNames(path, *minusX) {
<                 return nil
<           }
<
```

最重要的变化是引入了一个名为`excludeNames()`的新的 Go 函数，处理文件名的排除以及`-x`标志的添加，用于设置要从输出中排除的文件名。所有的工作都由文件路径完成。`Base()`函数找到路径的最后一部分，即使路径不是文件而是目录，也会将其与`-x`标志的值进行比较。

请注意，`excludeNames()`函数的更合适的名称可能是`isExcluded()`或类似的，因为`-x`选项接受单个值。

使用`excludeFind.go`执行并不带`-x`标志的命令将证明新的 Go 代码实际上是有效的。

```go
$ go run excludeFind.go -x=dT.py ~/code/python
/home/mtsouk/code/python
/home/mtsouk/code/python/dataFile.txt
/home/mtsouk/code/python/python
$ go run excludeFind.go ~/code/python
/home/mtsouk/code/python
/home/mtsouk/code/python/dT.py
/home/mtsouk/code/python/dataFile.txt
/home/mtsouk/code/python/python
```

# 从查找输出中排除文件扩展名

文件扩展名是最后一个点（`.`）字符之后的文件名的一部分。因此，`image.png`文件的文件扩展名是 png，这适用于文件和目录。

再次，为了实现这个功能，你需要一个单独的命令行选项，后面跟着你想要排除的文件扩展名：新的标志将被命名为`-ext`。这个`find(1)`实用程序的版本将基于`excludeFind.go`的代码，并将被命名为`finalFind.go`。你们中的一些人可能会说，这个选项更合适的名称应该是`-xext`，你们是对的！

再次，`diff(1)`实用程序将帮助我们发现`excludeFind.go`和`finalFind.go`之间的代码差异：新功能是在名为`excludeExtensions()`的 Go 函数中实现的，这使得理解更加容易。

```go
$ diff finalFind.go excludeFind.go
8d7
<     "strings"
21,34d19
< func excludeExtensions(name string, extension string) bool {
<     if extension == "" {
<           return false
<     }
<     basename := filepath.Base(name)
<     s := strings.Split(basename, ".")
<     length := len(s)
<     basenameExtension := s[length-1]
<     if basenameExtension == extension {
<           return true
<     }
<     return false
< }
<
43d27
<     minusEXT := flag.String("ext", "", "Extensions")
74,77d57
<           if excludeExtensions(path, *minusEXT) {
<                 return nil
<           }
< 
```

由于我们正在寻找路径中最后一个点后的字符串，我们使用`strings.Split()`根据路径中包含的点字符来分割路径。然后，我们取`strings.Split()`的返回值的最后一部分，并将其与使用`-ext`标志给定的扩展名进行比较。因此，这里没有什么特别的，只是一些字符串操作代码。再次强调，`excludeExtensions()`更合适的名称应该是`isExcludedExtension()`。

执行`finalFind.go`将生成以下输出：

```go
$ go run finalFind.go -ext=py ~/code/python
/home/mtsouk/code/python
/home/mtsouk/code/python/dataFile.txt
/home/mtsouk/code/python/python
$ go run finalFind.go ~/code/python
/home/mtsouk/code/python
/home/mtsouk/code/python/dT.py
/home/mtsouk/code/python/dataFile.txt
/home/mtsouk/code/python/python
```

# 使用正则表达式

这一部分将说明如何在`finalFind.go`中添加对正则表达式的支持：工具的最新版本的名称将是`regExpFind.go`。新的标志将被称为`-re`，它将需要一个字符串值：与此字符串值匹配的任何内容都将包含在输出中，除非它被另一个命令行选项排除。此外，由于标志提供的灵活性，我们不需要删除任何以前的选项来添加另一个选项！

再次，`diff(1)`命令将告诉我们`regExpFind.go`和`finalFind.go`之间的代码差异：

```go
$ diff regExpFind.go finalFind.go
8d7
<     "regexp"
36,44d34
< func regularExpression(path, regExp string) bool {
<     if regExp == "" {
<           return true
<     }
<     r, _ := regexp.Compile(regExp)
<     matched := r.MatchString(path)
<     return matched
< }
<
54d43
<     minusRE := flag.String("re", "", "Regular Expression")
71a61
>
75,78d64
<           if regularExpression(path, *minusRE) == false {
<                 return nil
<           }
< 
```

在第七章*,* *处理系统文件*中，我们将更多地讨论 Go 中的模式匹配和正则表达式：现在，理解`regexp.Compile()`创建正则表达式，`MatchString()`尝试在`regularExpression()`函数中进行匹配就足够了。

执行`regExpFind.go`将生成以下输出：

```go
$ go run regExpFind.go -re=anotherPackage /Users/mtsouk/go
/Users/mtsouk/go/pkg/darwin_amd64/anotherPackage.a
/Users/mtsouk/go/src/anotherPackage
/Users/mtsouk/go/src/anotherPackage/anotherPackage.go
$ go run regExpFind.go -ext=go -re=anotherPackage /Users/mtsouk/go
/Users/mtsouk/go/pkg/darwin_amd64/anotherPackage.a
/Users/mtsouk/go/src/anotherPackage 
```

可以使用以下命令验证先前的输出：

```go
$ go run regExpFind.go /Users/mtsouk/go | grep anotherPackage
/Users/mtsouk/go/pkg/darwin_amd64/anotherPackage.a
/Users/mtsouk/go/src/anotherPackage
/Users/mtsouk/go/src/anotherPackage/anotherPackage.go
```

# 创建目录结构的副本

凭借您在前几节中获得的知识，我们现在将开发一个 Go 程序，该程序在另一个目录中创建目录结构的副本：这意味着输入目录中的任何文件都不会复制到目标目录，只会复制目录。当您想要将有用的文件从一个目录结构保存到其他位置并保持相同的目录结构时，或者当您想要手动备份文件系统时，这可能会很方便。

由于您只对目录感兴趣，因此`cpStructure.go`的代码基于本章前面看到的`traverseDir.go`的代码：再次，为了学习目的而开发的小程序帮助您实现更大的程序！此外，`test`选项将显示程序的操作，而不会实际创建任何目录。

`cpStructure.go`的代码将分为四部分呈现。第一部分如下：

```go
package main 

import ( 
   "flag" 
   "fmt" 
   "os" 
   "path/filepath" 
   "strings" 
) 
```

这里没有什么特别的，只是预期的序言。第二部分如下：

```go
func main() { 
   minusTEST := flag.Bool("test", false, "Test run!") 

   flag.Parse() 
   flags := flag.Args() 

   if len(flags) == 0 || len(flags) == 1 { 
         fmt.Println("Not enough arguments!") 
         os.Exit(1) 
   } 

   Path := flags[0] 
   NewPath := flags[1] 

   permissions := os.ModePerm 
   _, err := os.Stat(NewPath) 
   if os.IsNotExist(err) { 
         os.MkdirAll(NewPath, permissions) 
   } else { 
         fmt.Println(NewPath, "already exists - quitting...") 
         os.Exit(1) 
   } 
```

`cpStructure.go`程序要求预先不存在目标目录，以避免后续不必要的意外和错误。

第三部分包含`walkFunction`变量的代码：

```go
   walkFunction := func(currentPath string, info os.FileInfo, err error) error { 
         fileInfo, _ := os.Lstat(currentPath) 
         if fileInfo.Mode()&os.ModeSymlink != 0 { 
               fmt.Println("Skipping", currentPath) 
               return nil 
         } 

         fileInfo, err = os.Stat(currentPath) 
         if err != nil { 
               fmt.Println("*", err) 
               return err 
         } 

         mode := fileInfo.Mode() 
         if mode.IsDir() { 
               tempPath := strings.Replace(currentPath, Path, "", 1) 
               pathToCreate := NewPath + "/" + filepath.Base(Path) + tempPath 

               if *minusTEST { 
                     fmt.Println(":", pathToCreate) 
                     return nil 
               } 

               _, err := os.Stat(pathToCreate) 
               if os.IsNotExist(err) { 
                     os.MkdirAll(pathToCreate, permissions) 
               } else { 
                     fmt.Println("Did not create", pathToCreate, ":", err) 
               } 
         } 
         return nil 
   } 
```

在这里，第一个`if`语句确保我们将处理符号链接，因为符号链接可能很危险并且会造成问题：始终尝试处理特殊情况以避免问题和令人讨厌的错误。

`os.IsNotExist()`函数允许您确保您要创建的目录尚不存在。因此，如果目录不存在，您可以使用`os.MkdirAll()`创建它。`os.MkdirAll()`函数创建包括所有必要父目录的目录路径，这对开发人员来说更简单。

然而，`walkFunction`变量的代码必须处理的最棘手的部分是删除源路径的不必要部分并正确构造新路径。程序中使用的`strings.Replace()`函数用其第二个参数(`Path`)替换其第一个参数(`currentPath`)中可以找到的出现，用其第三个参数(`""`)替换其最后一个参数(`1`)的次数。如果最后一个参数是负数，这里不是这种情况，那么将没有限制地进行替换。在这种情况下，它会从`currentPath`变量（正在检查的目录）中删除`Path`变量的值，这是源目录。

程序的最后部分如下：

```go
   err = filepath.Walk(Path, walkFunction) 
   if err != nil { 
         fmt.Println(err) 
         os.Exit(1) 
   } 
} 
```

执行`cpStructure.go`将生成以下输出：

```go
$ go run cpStructure.go ~/code /tmp/newCode
Skipping /home/mtsouk/code/aLink
$ ls -l /home/mtsouk/code/aLink
lrwxrwxrwx 1 mtsouk mtsouk 14 Apr 21 18:10 /home/mtsouk/code/aLink -> /usr/local/bin 
```

以下图显示了前述示例中使用的源目录和目标目录结构的图形表示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-sys-prog/img/ecf2e299-f496-48f4-9622-d1225bd52ad4.png)

两个目录结构及其文件的图形表示

# 练习

1.  阅读[`golang.org/pkg/os/`](https://golang.org/pkg/os/)上的`os`包的文档页面。

1.  访问[`golang.org/pkg/path/filepath/`](https://golang.org/pkg/path/filepath/)了解更多关于`filepath.Walk()`函数的信息。

1.  更改`rm.go`的代码以支持多个命令行参数，然后尝试实现`rm(1)`实用程序的`-v`命令行选项。

1.  对`which.go`的 Go 代码进行必要的更改，以支持多个命令行参数。

1.  开始在 Go 中实现`ls(1)`实用程序的版本。不要一次性尝试支持每个`ls(1)`选项。

1.  修改`traverseDir.go`的代码，以便只打印常规文件。

1.  查看`find(1)`的手册页面，并尝试在`regExpFind.go`中添加对其某些选项的支持。

# 摘要

在本章中，我们讨论了许多内容，包括使用`flag`标准包，允许您使用目录和文件以及遍历目录结构的 Go 函数，并且我们开发了各种 Unix 命令行实用程序的 Go 版本，包括`pwd(1)`、`which(1)`、`rm(1)`和`find(1)`。

在下一章中，我们将继续讨论文件操作，但这次您将学习如何在 Go 中读取文件和写入文件：正如您将看到的，有许多方法可以做到这一点。虽然这给了您灵活性，但它也要求您能够选择尽可能高效地完成工作的正确技术！因此，您将首先学习更多关于`io`包以及`bufio`包，到本章结束时，您将拥有`wc(1)`和`dd(1)`实用程序的 Go 版本！
