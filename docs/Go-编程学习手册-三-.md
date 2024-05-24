# Go 编程学习手册（三）

> 原文：[`zh.annas-archive.org/md5/5FC2C8948F5CEA11C4D0D293DBBCA039`](https://zh.annas-archive.org/md5/5FC2C8948F5CEA11C4D0D293DBBCA039)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第七章：复合类型

在之前的章节中，您可能已经在一些示例代码中看到了复合类型（如数组、切片、映射和结构体）的使用。尽管对这些类型的早期接触可能让您感到好奇，但请放心，在本章中，您将有机会了解所有这些复合类型。本章继续了第四章*数据类型*中开始的内容，讨论了以下主题：

+   数组类型

+   切片类型

+   映射类型

+   结构类型

# 数组类型

正如您在其他语言中所看到的那样，Go 数组是用于存储相同类型的序列化值的容器，这些值是按数字索引的。以下代码片段显示了分配了数组类型的变量的示例：

```go
var val [100]int 
var days [7]string 
var truth [256]bool 
var histogram [5]map[string]int 

```

golang.fyi/ch07/arrtypes.go

请注意，前面示例中分配给每个变量的类型是使用以下类型格式指定的：

*[<长度>]<元素类型>*

数组的类型定义由其长度组成，用括号括起来，后跟其存储元素的类型。例如，`days`变量被分配了类型`[7]string`。这是一个重要的区别，因为 Go 的类型系统认为存储相同类型元素但长度不同的两个数组是不同类型。以下代码说明了这种情况：

```go
var days [7]string 
var weekdays [5]string 

```

尽管这两个变量都是具有`string`类型元素的数组，但类型系统将`days`和`weekdays`变量视为不同类型。

### 注意

在本章的后面，您将看到如何使用切片类型而不是数组来缓解这种类型限制。

数组类型可以定义为多维的。这是通过将一维数组类型的定义组合和嵌套来实现的，如下面的代码片段所示：

```go
var board [4][2]int
var matrix [2][2][2][2] byte
```

golang.fyi/ch07/arrtypes.go

Go 没有单独的多维数组类型。具有多个维度的数组由相互嵌套的一维数组组成。下一节将介绍如何初始化单维和多维数组。

## 数组初始化

当数组变量没有明确初始化时，所有元素将被分配为元素声明类型的零值。数组可以使用复合文字值进行初始化，其一般格式如下：

*<数组类型>{<逗号分隔的元素值列表>}*

数组的文字值由数组类型定义（在前一节中讨论）组成，后跟一组逗号分隔的值，用大括号括起来，如下面的代码片段所示，其中显示了声明和初始化了几个数组：

```go
var val [100]int = [100]int{44,72,12,55,64,1,4,90,13,54}
var days [7]string = [7]string{
  "Monday",
  "Tuesday",
  "Wednesday",
  "Thursday",
  "Friday",
  "Saturday",
  "Sunday",
}
var truth = [256]bool{true}
var histogram = [5]map[string]int {
  map[string]int{"A":12,"B":1, "D":15},
  map[string]int{"man":1344,"women":844, "children":577,...},
}
```

golang.fyi/ch07/arrinit.go

文字值中的元素数量必须小于或等于数组类型中声明的大小。如果定义的数组是多维的，可以通过将每个维度嵌套在另一个括号的括号中，使用文字值进行初始化，如下面的示例代码片段所示：

```go
var board = [4][2]int{ 
   {33, 23}, 
   {62, 2}, 
   {23, 4}, 
   {51, 88}, 
} 
var matrix = [2][2][2][2]byte{ 
   {{{4, 4}, {3, 5}}, {{55, 12}, {22, 4}}}, 
   {{{2, 2}, {7, 9}}, {{43, 0}, {88, 7}}}, 
} 

```

golang.fyi/ch07/arrinit.go

以下代码片段显示了指定数组文字的另外两种方式。在初始化期间，数组的长度可以被省略并用省略号替换。以下将类型`[5]string`分配给变量`weekdays`：

```go
var weekdays = [...]string{ 
   "Monday", 
   "Tuesday", 
   "Wednesday", 
   "Thursday", 
   "Friday",    
}  

```

数组的文字值也可以被索引。如果您只想初始化某些数组元素，同时允许其他元素以它们的自然零值进行初始化，这将非常有用。以下指定了位置 0、`2`、`4`、`6`、`8`的元素的初始值。其余元素将被分配为空字符串：

```go
var msg = [12]rune{0: 'H', 2: 'E', 4: 'L', 6: 'O', 8: '!'} 

```

## 声明命名数组类型

数组的类型可能会变得难以重用。对于每个声明，需要重复声明，这可能会出错。处理这种习惯用法的方法是使用类型声明别名数组类型。为了说明这是如何工作的，以下代码片段声明了一个新的命名类型`matrix`，使用多维数组作为其基础类型：

```go
type matrix [2][2][2][2]byte 

func main() { 
   var mat1 matrix 
   mat1 = initMat() 
   fmt.Println(mat1) 
} 

func initMat() matrix { 
   return matrix{ 
         {{{4, 4}, {3, 5}}, {{55, 12}, {22, 4}}}, 
         {{{2, 2}, {7, 9}}, {{43, 0}, {88, 7}}}, 
   } 
} 

```

golang.fyi/ch07/arrtype_dec.go

声明的命名类型`matrix`可以在使用其基础数组类型的所有上下文中使用。这允许使用简化的语法，促进复杂数组类型的重用。

## 使用数组

数组是静态实体，一旦使用指定的长度声明，就无法增长或缩小。当程序需要分配预定义大小的连续内存块时，数组是一个很好的选择。当声明数组类型的变量时，它已经准备好在没有任何进一步分配语义的情况下使用。

因此，`image`变量的以下声明将分配一个由 256 个相邻的`int`值组成的内存块，并用零初始化，如下图所示：

```go
var image [256]byte
```

![使用数组](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/image_07_001.jpg)

与 C 和 Java 类似，Go 使用方括号索引表达式来访问存储在数组变量中的值。这是通过指定变量标识符，后跟方括号括起来的元素的索引来完成的，如下面的代码示例所示：

```go
p := [5]int{122,6,23,44,6} 
p[4] = 82 
fmt.Println(p[0]) 

```

前面的代码更新了数组中的第五个元素，并打印了数组中的第一个元素。

## 数组长度和容量

内置的`len`函数返回数组类型的声明长度。内置的`cap`函数可以用于返回数组的容量。例如，在以下源代码片段中，类型为`[7]string`的数组`seven`将返回`7`作为其长度和容量：

```go
func main() { 
   seven := [7]string{"grumpy", "sleepy", "bashful"} 
   fmt.Println(len(seven), cap(seven)) 
} 

```

对于数组，`cap()`函数始终返回与`len()`相同的值。这是因为数组值的最大容量是其声明的长度。容量函数更适合与切片类型一起使用（稍后在本章中讨论）。

## 数组遍历

数组遍历可以使用传统的`for`语句或更符合习惯的`for…range`语句。以下代码片段显示了使用`for`语句进行数组遍历，以在`init()`中使用随机数初始化数组，并使用`for`范围语句实现`max()`函数：

```go
const size = 1000 
var nums [size]int 

func init() { 
   rand.Seed(time.Now().UnixNano()) 
   for i := 0; i < size; i++ { 
         nums[i] = rand.Intn(10000) 
   } 
} 

func max(nums [size]int) int { 
   temp := nums[0] 
   for _, val := range nums { 
         if val > temp { 
               temp = val 
         } 
   } 
   return temp 
} 

```

golang.fyi/ch07/arrmax_iter.go

在传统的`for`语句中，循环的索引变量`i`用于使用索引表达式`num[i]`访问数组的值。在`for…range`语句中，在`max`函数中，迭代的值存储在`val`变量中，每次循环都会忽略索引（分配给空白标识符）。如果您不了解*for*语句的工作原理，请参阅第三章，*Go 控制流*，详细解释 Go 中循环的机制。

## 数组作为参数

数组值被视为单个单元。数组变量不是指向内存中的位置的指针，而是表示包含数组元素的整个内存块。当重新分配数组变量或将其作为函数参数传递时，这意味着创建数组值的新副本。

这可能会对程序的内存消耗产生不良的副作用。一个解决方法是使用指针类型来引用数组值。在以下示例中，声明了一个命名类型`numbers`，表示数组类型`[1024 * 1024]]int`。函数`initialize()`和`max()`不直接接受数组值作为参数，而是接受`*numbers`类型的指针，如下面的源代码片段所示：

```go
type numbers [1024 * 1024]int 
func initialize(nums *numbers) { 
   rand.Seed(time.Now().UnixNano()) 
   for i := 0; i < size; i++ { 
         nums[i] = rand.Intn(10000) 
   } 
} 
func max(nums *numbers) int { 
   temp := nums[0] 
   for _, val := range nums { 
         if val > temp { 
               temp = val 
         } 
   } 
   return temp 
} 
func main() { 
   var nums *numbers = new(numbers) 
   initialize(nums) 
} 

```

golang.fyi/ch07/arrptr.go

前面的代码使用内置函数`new(numbers)`来初始化数组元素为它们的零值，并在`main()`中获取指向该数组的指针。因此，当调用`initialize`和`max`函数时，它们将接收到数组的地址（其副本），而不是整个大小为 100K 的数组。

在改变主题之前，应该注意到复合文字数组值可以使用地址运算符`&`初始化并返回数组的指针，如下例所示。在代码片段中，复合文字`&galaxies{...}`返回指针`*galaxies`，并用指定的元素值初始化：

```go
type galaxies [14]string 
func main() { 
   namedGalaxies = &galaxies{ 
         "Andromeda", 
         "Black Eye", 
         "Bode's", 
          ...   
   } 
   printGalaxies(namedGalaxies) 
} 

```

golang.fyi/ch07/arraddr.go

数组类型是 Go 中的低级存储构造。例如，数组通常用作存储原语的基础，其中有严格的内存分配要求以最小化空间消耗。然而，在更常见的情况下，切片，下一节中介绍的，通常被用作处理序列化索引集合的更成语化的方式。

# 切片类型

切片类型通常用作 Go 中索引数据的成语构造。切片比数组更灵活，具有许多更有趣的特性。切片本身是一种具有类似数组语义的复合类型。实际上，切片使用数组作为其底层数据存储机制。切片类型的一般形式如下所示：

*[ ]<element_type>*

切片和数组类型之间一个明显的区别是在类型声明中省略了大小，如下面的例子所示：

```go
var ( 
    image []byte      
    ids []string 
    vector []float64 
    months []string 
    q1 []string 
    histogram []map[string]int // slice of map (see map later) 
) 

```

golang.fyi/ch07/slicetypes.go

切片类型中缺少的大小属性表示以下内容：

+   与数组不同，切片的大小是不固定的

+   切片类型表示指定元素类型的所有集合

这意味着切片在理论上可以无限增长（尽管在实践中这并不是真的，因为切片由底层有界数组支持）。给定元素类型的切片被认为是相同类型，而不管其底层大小如何。这消除了数组中大小决定类型的限制。

例如，以下变量`months`和`q1`具有相同的`[]string`类型，并且将编译没有问题：

```go
var ( 
    months []string 
    q1 []string 
) 
func print(strs []string){ ... } 
func main() { 
   print(months) 
   print(q1) 
} 

```

golang.fyi/ch07/slicetypes.go

与数组类似，切片类型可以嵌套以创建多维切片，如下面的代码片段所示。每个维度可以独立地具有自己的大小，并且必须单独初始化：

```go
var( 
    board [][]int 
    graph [][][][]int 
) 

```

## 切片初始化

切片在类型系统中表示为一个值（下一节将探讨切片的内部表示）。然而，与数组类型不同，未初始化的切片具有*nil*的零值，这意味着任何尝试访问未初始化切片的元素都会导致程序恐慌。

初始化切片的最简单方法之一是使用以下格式的复合文字值（类似于数组）：

*<slice_type>{<comma-separated list of element values>}*

切片的文字值由切片类型和一组逗号分隔的值组成，这些值被分配给切片的元素，并用大括号括起来。以下代码片段说明了用复合文字值初始化的几个切片变量：

```go
var ( 
    ids []string = []string{"fe225", "ac144", "3b12c"} 
    vector = []float64{12.4, 44, 126, 2, 11.5}  
    months = []string { 
         "Jan", "Feb", "Mar", "Apr", 
         "May", "Jun", "Jul", "Aug", 
         "Sep", "Oct", "Nov", "Dec", 
    } 
    // slice of map type (maps are covered later) 
    tables = []map[string][]int { 
         { 
               "age":{53, 13, 5, 55, 45, 62, 34, 7}, 
               "pay":{124, 66, 777, 531, 933, 231}, 
         }, 
    } 
    graph  = [][][][]int{ 
         {{{44}, {3, 5}}, {{55, 12, 3}, {22, 4}}}, 
         {{{22, 12, 9, 19}, {7, 9}}, {{43, 0, 44, 12}, {7}}},     
    } 
) 

```

golang.fyi/ch07/sliceinit.go

如前所述，切片的复合文字值使用与数组类似的形式表示。但是，文字中提供的元素数量不受固定大小的限制。这意味着文字可以根据需要很大。尽管如此，Go 在幕后创建和管理一个适当大小的数组来存储文字中表达的值。

## 切片表示

之前提到切片值使用基础数组来存储数据。实际上，*切片*这个名称是指数组中的数据段的引用。在内部，切片由以下三个属性表示：

| **属性** | **描述** |
| --- | --- |
| a *指针* | 指针是存储在基础数组中的切片的第一个元素的地址。当切片值未初始化时，其指针值为 nil，表示它尚未指向数组。Go 使用指针作为切片本身的零值。未初始化的切片将返回 nil 作为其零值。但是，切片值在类型系统中不被视为引用值。这意味着某些函数可以应用于 nil 切片，而其他函数将导致恐慌。一旦创建了切片，指针就不会改变。要指向不同的起始点，必须创建一个新的切片。 |
| a *长度* | 长度表示可以从第一个元素开始访问的连续元素的数量。它是一个动态值，可以增长到切片的容量（见下文）。切片的长度始终小于或等于其容量。尝试访问超出切片长度的元素，而不进行调整大小，将导致恐慌。即使容量大于长度，这也是真的。 |
| a *容量* | 切片的容量是可以从其第一个元素开始存储的最大元素数量。切片的容量受基础数组的长度限制。 |

因此，当初始化以下变量`halfyr`时如下所示：

```go
halfyr := []string{"Jan","Feb","Mar","Apr","May","Jun"}
```

它将存储在类型为`[6]string`的数组中，具有指向第一个元素的指针，长度和容量为`6`，如下图形式地表示：

![切片表示](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/B036376_07_02.jpg)

## 切片

另一种创建切片值的方法是通过对现有数组或另一个切片值（或指向这些值的指针）进行切片。Go 提供了一种索引格式，使得表达切片操作变得容易，如下所示：

*<切片或数组值>[<低索引>:<高索引>]*

切片表达式使用[`:`]运算符来指定切片段的低和高边界索引，用冒号分隔。

+   *低*值是切片段开始的从零开始的索引

+   *高*值是段停止的第*n*个元素偏移量

下表显示了通过重新切片以下值的切片表达式的示例：`halfyr := []string{"Jan","Feb","Mar","Apr","May","Jun"}`。

| **表达式** | **描述** |
| --- | --- |
| `all := halfyr[:]` | 省略表达式中的低和高索引相当于以下操作：`all := halfyr[0 : 6]`这将产生一个新的切片段，与原始切片相等，从索引位置 0 开始，停在偏移位置`6`：`["Jan","Feb","Mar","Apr","May","Jun"]` |
| `q1 := halfyr[:3]` | 这里的切片表达式省略了低索引值，并指定了长度为`3`的切片段。它返回新的切片，`["Jan","Feb","Mar"]`。 |
| `q2 := halfyr[3:]` | 这将通过指定起始索引位置为`3`并省略高边界索引值（默认为`6`）创建一个新的切片段，其中包含最后三个元素。 |
| `mapr := halfyr[2:4]` | 为了消除对切片表达式的任何困惑，这个例子展示了如何创建一个包含月份`"Mar"`和`"Apr"`的新切片。这将返回一个值为`["Mar","Apr"]`的切片。 |

## 切片切片

对现有切片或数组值进行切片操作不会创建新的基础数组。新的切片会创建指向基础数组的新指针位置。例如，以下代码显示了将切片值`halfyr`切片成两个额外切片的操作：

```go
var ( 
    halfyr = []string{ 
         "Jan", "Feb", "Mar", 
         "Apr", "May", "Jun", 
    } 

    q1 = halfyr[:3] 
    q2 = halfyr[3:] 
) 

```

golang.fyi/ch07/slice_reslice.go

支持数组可能有许多投影其数据的切片。以下图示说明了在前面的代码中切片可能如何在视觉上表示：

![切片切片](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/image_07_003.jpg)

请注意，切片`q1`和`q2`都指向同一基础数组中的不同元素。切片`q1`的初始长度为`3`，容量为`6`。这意味着`q1`可以调整大小，最多达到`6`个元素。然而，切片`q2`的大小为`3`，容量为`3`，不能超出其初始大小（切片调整大小将在后面介绍）。

## 切片数组

如前所述，数组也可以直接进行切片。在这种情况下，提供的数组值将成为基础数组。使用提供的数组将计算切片的容量和长度。以下源代码片段显示了对名为 months 的现有数组值进行切片：

```go
var ( 
    months [12]string = [12]string{ 
         "Jan", "Feb", "Mar", "Apr", "May", "Jun", 
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", 
    } 

    halfyr = months[:6] 
    q1 = halfyr[:3] 
    q2 = halfyr[3:6] 
    q3 = months[6:9] 
    q4 = months[9:] 
) 

```

golang.fyi/ch07/slice_reslice_arr.go

## 具有容量的切片表达式

最后，Go 的切片表达式支持更长的形式，其中包括切片的最大容量，如下所示：

*<slice_or_array_value>[<low_index>:<high_index>:max]*

*max*属性指定要用作新切片的最大容量的索引值。该值可以小于或等于基础数组的实际容量。以下示例对包含最大值的数组进行切片：

```go
var ( 
    months [12]string = [12]string{ 
         "Jan", "Feb", "Mar", "Apr", "May", "Jun", 
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", 
    } 
    summer1 = months[6:9:9] 
) 

```

golang.fyi/ch07/slice_reslice_arr.go

前面的代码片段创建了一个新的切片值`summer1`，大小为`3`（从索引位置`6`到`9`）。最大索引设置为位置`9`，这意味着切片的容量为`3`。如果未指定最大值，则最大容量将自动设置为基础数组的最后一个位置，与以前一样。

## 创建切片

切片可以在运行时使用内置函数`make`进行初始化。此函数创建一个新的切片值，并使用元素类型的零值初始化其元素。未初始化的切片具有零值 nil，表示它不指向基础数组。如果没有显式初始化，使用复合文字值或使用`make()`函数，尝试访问切片的元素将导致恐慌。以下代码片段重新使用`make()`函数初始化切片的示例：

```go
func main() { 
   months := make([]string, 6) 
   ... 
} 

```

golang.fyi/ch07/slicemake.go

`make()`函数以切片的类型作为参数进行初始化，并为切片设置初始大小。然后返回一个切片值。在前面的代码片段中，`make()`执行以下操作：

+   创建类型为`[6]string`的基础数组

+   创建长度和容量为`6`的切片值

+   返回切片值（而不是指针）

使用`make()`函数初始化后，访问合法的索引位置将返回切片元素的零值，而不会导致程序恐慌。`make()`函数可以接受一个可选的第三个参数，指定切片的最大容量，如下例所示：

```go
func main() { 
   months := make([]string, 6, 12)  
   ... 
} 

```

golang.fyi/ch07/slicemake2.go

前面的代码片段将使用初始长度为`6`和最大容量为`12`的切片值初始化`months`变量。

## 使用切片

切片值最简单的操作是访问其元素。正如前面提到的，切片使用索引表示法来访问其元素，类似于数组。以下示例访问索引位置 0 的元素并更新为`15`：

```go
func main () { 
   h := []float64{12.5, 18.4, 7.0} 
   h[0] = 15 
   fmt.Println(h[0]) 
   ... 
} 

```

golang.fyi/ch07/slice_use.go

程序运行时，使用索引表达式`h[0]`打印更新后的值。请注意，仅使用索引号的切片表达式，例如`h[0]`，将返回该位置的项目的值。然而，如果表达式包括冒号，比如`h[2:]`或`h[:6]`，该表达式将返回一个新的切片。

切片遍历可以使用传统的`for`语句，也可以使用更符合惯例的`for…range`语句，如下面的代码片段所示：

```go
func scale(factor float64, vector []float64) []float64 { 
   for i := range vector { 
         vector[i] *= factor 
   } 
   return vector 
} 

func contains(val float64, numbers []float64) bool { 
   for _, num := range numbers { 
         if num == val { 
               return true 
         } 
   } 
   return false 
} 

```

golang.fyi/ch07/slice_loop.go

在上面的代码片段中，函数`scale`使用索引变量`i`直接更新切片`factor`中的值，而函数`contains`使用存储在`num`中的迭代产生的值来访问切片元素。如果您需要关于`for…range`语句的更多细节，请参阅第三章*Go 控制流*。

## 切片作为参数

当函数接收切片作为其参数时，该切片的内部指针将指向切片的基础数组。因此，在函数内部对切片的所有更新都将被函数的调用者看到。例如，在下面的代码片段中，对`vector`参数的所有更改都将被`scale`函数的调用者看到：

```go
func scale(factor float64, vector []float64) { 
   for i := range vector { 
         vector[i] *= factor 
   } 
} 

```

golang.fyi/ch07/slice_loop.go

## 长度和容量

Go 提供了两个内置函数来查询切片的长度和容量属性。给定一个切片，可以使用`len`和`cap`函数分别查询其长度和最大容量，如下例所示：

```go
func main() { 
    var vector []float64 
    fmt.Println(len(vector)) // prints 0, no panic 
    h := make([]float64, 4, 10) 
    fmt.Println(len(h), ",", cap(h)) 
} 

```

请记住，切片是一个值（而不是指针），其零值为 nil。因此，代码能够查询未初始化切片的长度（和容量），而不会在运行时引发恐慌。

## 向切片添加元素

切片类型的一个不可或缺的特性是它们的动态增长能力。默认情况下，切片具有静态长度和容量。任何尝试访问超出该限制的索引都将引发恐慌。Go 提供了内置的可变参数函数`append`，用于动态向指定的切片添加新值，根据需要增加其长度和容量。以下代码片段显示了如何实现这一点：

```go
func main() { 
   months := make([]string, 3, 3) 
   months = append(months, "Jan", "Feb", "March",  
    "Apr", "May", "June") 
   months = append(months, []string{"Jul", "Aug", "Sep"}...) 
   months = append(months, "Oct", "Nov", "Dec") 
   fmt.Println(len(months), cap(months), months) 
} 

```

golang.fyi/ch07/slice_append.go

上面的代码片段以大小和容量为`3`的切片开始。`append`函数用于动态向切片添加新值，超出其初始大小和容量。在内部，`append`将尝试将附加的值适应目标切片。如果切片尚未初始化或容量不足，`append`将分配一个新的基础数组，以存储更新后的切片的值。

## 复制切片

请记住，分配或切片现有切片值只是创建一个指向相同基础数组结构的新切片值。Go 提供了`copy`函数，它返回切片的深层副本以及一个新的基础数组。以下代码片段显示了一个`clone()`函数，它创建一个数字切片的新副本：

```go
func clone(v []float64) (result []float64) { 
   result = make([]float64, len(v), cap(v)) 
   copy(result, v) 
   return 
} 

```

golang.fyi/ch07/slice_use.go

在上面的代码片段中，`copy`函数将`v`切片的内容复制到`result`中。源切片和目标切片必须具有相同的大小和相同的类型，否则复制操作将失败。

## 字符串作为切片

在内部，字符串类型是使用指向 rune 的基础数组的复合值实现的切片。这使得字符串类型能够像切片一样进行惯用处理。例如，以下代码片段使用索引表达式从给定的字符串值中提取字符串切片：

```go
func main() { 
   msg := "Bobsayshelloworld!" 
   fmt.Println( 
         msg[:3], msg[3:7], msg[7:12],  
         msg[12:17], msg[len(msg)-1:], 
   ) 
} 

```

golang.fyi/ch07/slice_string.go

对字符串的切片表达式将返回一个指向其基础 rune 数组的新字符串值。可以将字符串值转换为字节切片（或 rune 切片），如下面的函数片段所示，该函数对给定字符串的字符进行排序：

```go
func sort(str string) string { 
   bytes := []byte(str) 
   var temp byte 
   for i := range bytes { 
         for j := i + 1; j < len(bytes); j++ { 
               if bytes[j] < bytes[i] { 
                     temp = bytes[i] 
                     bytes[i], bytes[j] = bytes[j], temp 
               } 
         } 
   } 
   return string(bytes) 
} 

```

golang.fyi/ch07/slice_string.go

上面的代码显示了将字节切片显式转换为字符串值。请注意，可以使用索引表达式访问每个字符。

# 映射类型

Go 映射是一种复合类型，用作存储相同类型的无序元素的容器，由任意键值索引。以下代码片段显示了使用各种键类型声明的各种映射变量：

```go
var ( 
    legends map[int]string 
    histogram map[string]int 
    calibration map[float64]bool 
    matrix map[[2][2]int]bool    // map with array key type 
    table map[string][]string    // map of string slices 

   // map (with struct key) of map of string 
   log map[struct{name string}]map[string]string 
) 

```

golang.fyi/ch07/maptypes.go

上面的代码片段显示了几个变量声明为不同类型的映射，具有各种键类型。一般来说，映射类型的指定如下：

*map[<键类型>]<元素类型>*

*键*指定了将用于索引映射存储元素的值的类型。与数组和切片不同，映射键可以是任何类型，而不仅仅是`int`。然而，映射键必须是可比较的类型，包括数字、字符串、布尔、指针、数组、结构和接口类型（参见第四章*，数据类型*，讨论可比较类型）。

## 映射初始化

与切片类似，映射管理一个底层数据结构，对其用户来说是不透明的，用于存储其值。未初始化的映射也具有零值为 nil。尝试向未初始化的映射中插入值将导致程序恐慌。然而，与切片不同的是，可以从 nil 映射中访问元素，这将返回元素的零值。

与其他复合类型一样，映射可以使用以下形式的复合文字值进行初始化：

*<map 类型>{<逗号分隔的键:值对列表>}*

以下代码片段显示了使用映射复合文字进行变量初始化：

```go
var ( 
   histogram map[string]int = map[string]int{ 
         "Jan":100, "Feb":445, "Mar":514, "Apr":233, 
         "May":321, "Jun":644, "Jul":113, "Aug":734, 
         "Sep":553, "Oct":344, "Nov":831, "Dec":312,  
   } 

   table = map[string][]int { 
         "Men":[]int{32, 55, 12, 55, 42, 53}, 
         "Women":[]int{44, 42, 23, 41, 65, 44}, 
   } 
) 

```

golang.fyi/ch07/mapinit.go

如前面的例子所示，使用以冒号分隔的键值对指定了文本映射的值。每个键和值对的类型必须与映射中声明的元素的类型匹配。

## 创建映射

与切片类似，映射值也可以使用*make*函数进行初始化。使用 make 函数初始化底层存储，允许数据被插入到映射中，如下简短的代码片段所示：

```go
func main() { 
   hist := make(map[int]string) 
   hist["Jan"] = 100 
   hist["Feb"] = 445 
   hist["Mar"] = 514 
... 
} 

```

golang.fyi/ch07/maptypes.go

`make`函数以映射的类型作为参数，并返回一个初始化的映射。在前面的例子中，`make`函数将初始化一个类型为`map[int]string`的映射。`make`函数还可以选择接受第二个参数来指定映射的容量。然而，映射将根据需要继续增长，忽略指定的初始容量。

## 使用映射

与切片和数组一样，索引表达式用于访问和更新映射中存储的元素。要设置或更新`map`元素，请使用索引表达式，在赋值的左侧，指定要更新的元素的键。以下代码片段显示了使用值`100`更新具有`"Jan"`键的元素：

```go
hist := make(map[int]string) 
hist["Jan"] = 100 

```

使用索引表达式访问具有给定键的元素，该表达式放置在赋值的右侧，如下例所示，在这个例子中，使用`"Mar"`键索引的值被赋给了`val`变量：

```go
val := hist["Mar"] 

```

之前提到访问不存在的键将返回该元素的零值。例如，如果映射中不存在具有键`"Mar"`的元素，则前面的代码将返回 0。可以想象，这可能是一个问题。你怎么知道你得到的是实际值还是零值？幸运的是，Go 提供了一种明确测试元素缺失的方法，通过在索引表达式的结果中返回一个可选的布尔值，如下代码片段所示：

```go
func save(store map[string]int, key string, value int) { 
   val, ok := store[key] 
   if !ok { 
         store[key] = value 
   }else{ 
         panic(fmt.Sprintf("Slot %d taken", val)) 
   } 
} 

```

golang.fyi/ch07/map_use.go

在前面的代码片段中，函数在更新值之前测试键的存在。称为*逗号-ok*习语，存储在`ok`变量中的布尔值在实际未找到值时设置为 false。这允许代码区分键的缺失和元素的零值。

## 映射遍历

`for…range`循环语句可以用来遍历映射值的内容。`range`表达式在每次迭代中发出键和元素值。以下代码片段显示了对映射`hist`的遍历：

```go
for key, val := range hist { 
   adjVal := int(float64(val) * 0.100) 
   fmt.Printf("%s (%d):", key, val) 
   for i := 0; i < adjVal; i++ { 
         fmt.Print(".") 
   } 
   fmt.Println() 
} 

```

golang.fyi/ch07/map_use.go

每次迭代都会返回一个键及其关联的元素值。然而，迭代顺序并不保证。内部映射迭代器可能会在程序的每次运行中以不同的顺序遍历映射。为了保持可预测的遍历顺序，保留（或生成）键的副本在一个单独的结构中，比如一个切片。在遍历过程中，使用键的切片以可预测的方式进行遍历。

### 注意

您应该知道，在迭代期间对发出的值进行的更新将会丢失。而是使用索引表达式，比如`hist[key]`来在迭代期间更新元素。有关`for…range`循环的详细信息，请参阅第三章*Go 控制流*，对 Go`for`循环进行彻底的解释。

## 映射函数

除了之前讨论的`make`函数，映射类型还支持以下表中讨论的两个附加函数：

| **函数** | **描述** |
| --- | --- |

| len(map) | 与其他复合类型一样，内置的`len()`函数返回映射中条目的数量。例如，以下内容将打印**3**：

```go
h := map[int]bool{3:true, 7:false, 9:false}   
fmt.Println(len(h))   

```

对于未初始化的映射，`len`函数将返回零。|

| delete(map, key) | 内置的`delete`函数从给定的映射中删除与提供的键关联的元素。以下代码片段将打印**2**：

```go
h := map[int]bool{3:true, 7:false, 9:false}   
delete(h,7)   
fmt.Println(len(h))   

```

|

### 作为参数的映射

因为映射维护了一个指向其后备存储结构的内部指针，所以在调用函数内对映射参数的所有更新将在函数返回后被调用者看到。下面的示例显示了调用`remove`函数来改变映射内容。传递的变量`hist`将在`remove`函数返回后反映出这一变化：

```go
func main() { 
   hist := make(map[string]int) 
   hist["Jun"] = 644 
   hist["Jul"] = 113 
   remove(hit, "Jun") 
   len(hist) // returns 1 
} 
func remove(store map[string]int, key string) error { 
   _, ok := store[key] 
   if !ok { 
         return fmt.Errorf("Key not found") 
   } 
   delete(store, key) 
   return nil 
} 

```

golang.fyi/ch07/map_use.go

# 结构体类型

本章讨论的最后一种类型是 Go 的`struct`。它是一种复合类型，用作其他命名类型（称为字段）的容器。以下代码片段显示了几个声明为结构体的变量：

```go
var( 
   empty struct{} 
   car struct{make, model string} 
   currency struct{name, country string; code int} 
   node struct{ 
         edges []string 
         weight int 
   } 
   person struct{ 
         name string 
         address struct{ 
               street string 
               city, state string 
               postal string 
         } 
   } 
) 

```

golang.fyi/ch07/structtypes.go

请注意，结构体类型具有以下一般格式：

*struct{<field declaration set>}*

`struct`类型是通过指定关键字`struct`后跟在花括号内的一组字段声明来构造的。在其最常见的形式中，字段是一个具有分配类型的唯一标识符，遵循 Go 的变量声明约定，如前面的代码片段所示（`struct`也支持匿名字段，稍后讨论）。

重要的是要理解`struct`的类型定义包括其声明的所有字段。例如，person 变量的类型（见前面的代码片段）是声明`struct { name string; address struct { street string; city string; state string; postal string }}`中的所有字段。因此，任何需要该类型的变量或表达式都必须重复这个长声明。我们将在后面看到，通过使用`struct`的命名类型来减轻这个问题。

## 访问结构字段

结构体使用*选择器表达式*（或点表示法）来访问字段中存储的值。例如，以下内容将打印出先前代码片段中的 person 结构变量的`name`字段的值：

```go
fmt.Pritnln(person.name)
```

选择器可以链接以访问嵌套在结构体内部的字段。以下代码片段将打印出`person`变量的嵌套地址值的街道和城市：

```go
fmt.Pritnln(person.address.street)
fmt.Pritnln(person.address.city)
```

## 结构初始化

与数组类似，结构体是纯值，没有额外的底层存储结构。未初始化的结构体的字段被分配它们各自的零值。这意味着未初始化的结构体不需要进一步分配，可以直接使用。

尽管如此，结构体变量可以使用以下形式的复合字面量进行显式初始化：

*<struct_type>{<positional or named field values>}*

结构的复合文字值可以通过它们各自位置指定的一组字段值进行初始化。使用这种方法，必须提供所有字段值，以匹配它们各自声明的类型，如下面的片段所示：

```go
var( 
   currency = struct{ 
         name, country string 
         code int 
   }{ 
         "USD", "United States",  
         840, 
   } 
... 
) 

```

golang.fyi/ch07/structinit.go

在以前的结构文字中，提供了`struct`的所有字段值，与其声明的字段类型匹配。或者，可以使用字段索引及其关联值指定`struct`的复合文字值。与以前一样，索引（字段名称）及其值由冒号分隔，如下面的片段所示：

```go
var( 
   car = struct{make, model string}{make:"Ford", model:"F150"} 
   node = struct{ 
         edges []string 
         weight int 
   }{ 
         edges: []string{"north", "south", "west"}, 
   } 
... 
) 

```

golang.fyi/ch07/structinit.go

正如您所看到的，当提供索引及其值时，结构文字的字段值可以被选择性地指定。例如，在初始化`node`变量时，`edge`字段被初始化，而`weight`被省略。

## 声明命名结构类型

尝试重用结构类型可能会变得难以控制。例如，每次需要时都必须编写`struct { name string; address struct { street string; city string; state string; postal string }}`来表示结构类型，这样做不会扩展，容易出错，并且会让 Go 开发人员感到不快。幸运的是，修复这个问题的正确习惯是使用命名类型，如下面的源代码片段所示：

```go
type person struct { 
   name    string 
   address address 
} 

type address struct { 
   street      string 
   city, state string 
   postal      string 
} 

func makePerson() person { 
   addr := address{ 
         city: "Goville", 
         state: "Go", 
         postal: "12345", 
   } 
   return person{ 
         name: "vladimir vivien", 
         address: addr, 
   } 
} 

```

golang.fyi/ch07/structtype_dec.go

前面的示例将结构类型定义绑定到标识符`person`和`address`。这允许在不需要携带类型定义的长形式的情况下，在不同的上下文中重用结构类型。您可以参考第四章，*数据类型*，了解更多有关命名类型的信息。

## 匿名字段

以前的结构类型定义涉及使用命名字段。但是，还可以定义仅具有其类型的字段，省略标识符。这称为匿名字段。它的效果是将类型直接嵌入结构中。

这个概念在下面的代码片段中得到了演示。`diameter`和`name`两种类型都作为`planet`类型的`anonymous`字段嵌入：

```go
type diameter int 

type name struct { 
   long   string 
   short  string 
   symbol rune 
} 

type planet struct { 
   diameter 
   name 
   desc string 
} 

func main() { 
   earth := planet{ 
         diameter: 7926, 
         name: name{ 
               long:   "Earth", 
               short:  "E", 
               symbol: '\u2641', 
         }, 
         desc: "Third rock from the Sun", 
   } 
   ... 
} 

```

golang.fyi/ch07/struct_embed.go

前面片段中的`main`函数展示了如何访问和更新匿名字段，就像在`planet`结构中所做的那样。请注意，嵌入类型的名称成为结构的复合文字值中的字段标识符。

为了简化字段名称解析，Go 在使用匿名字段时遵循以下规则：

+   类型的名称成为字段的名称

+   匿名字段的名称可能与其他字段名称冲突

+   仅使用导入类型的未限定（省略包）类型名称

在直接使用选择器表达式访问嵌入结构的字段时，这些规则也适用，就像下面的代码片段中所示的那样。请注意，嵌入类型的名称被解析为字段名称：

```go
func main(){ 
   jupiter := planet{} 
   jupiter.diameter = 88846 
   jupiter.name.long = "Jupiter" 
   jupiter.name.short = "J" 
   jupiter.name.symbol = '\u2643' 
   jupiter.desc = "A ball of gas" 
   ... 
} 

```

golang.fyi/ch07/struct_embed.go

### 提升的字段

嵌入结构的字段可以*提升*到其封闭类型。提升的字段出现在选择器表达式中，而不带有它们类型的限定名称，如下面的示例所示：

```go
func main() {
...
saturn := planet{}
saturn.diameter = 120536
saturn.long = "Saturn"
saturn.short = "S"
saturn.symbol = '\u2644'
saturn.desc = "Slow mover"
...
}
```

golang.fyi/ch07/struct_embed.go

在前面的片段中，通过省略选择器表达式中的`name`，突出显示的字段是从嵌入类型`name`中提升的。字段`long`，`short`和`symbol`的值来自嵌入类型`name`。同样，只有在提升不会导致任何标识符冲突时才会起作用。在有歧义的情况下，可以使用完全限定的选择器表达式。

## 结构作为参数

请记住，结构变量存储实际值。这意味着每当重新分配或作为函数参数传递`struct`变量时，都会创建结构值的新副本。例如，在调用`updateName()`之后，以下内容将不会更新名称的值：

```go
type person struct { 
   name    string 
   title string       
} 
func updateName(p person, name string) { 
   p.name = name 
}  

func main() { 
   p := person{} 
   p.name = "uknown" 
   ... 
   updateName(p, "Vladimir Vivien") 
} 

```

golang.fyi/ch07/struct_ptr.go

这可以通过将指针传递给 person 类型的 struct 值来解决，如下面的代码片段所示：

```go
type person struct { 
   name    string 
   title string 
} 

func updateName(p *person, name string) { 
   p.name = name 
} 

func main() { 
   p := new(person) 
   p.name = "uknown" 
   ... 
   updateName(p, "Vladimir Vivien") 
} 

```

golang.fyi/ch07/struct_ptr2.go

在这个版本中，变量`p`声明为`*person`，并使用内置的`new()`函数进行初始化。在`updateName()`返回后，其更改将被调用函数看到。

## 字段标签

关于结构的最后一个主题与字段标签有关。在定义`struct`类型时，可以在每个字段声明中添加可选的`string`值。字符串的值是任意的，它可以作为提示，供使用反射消费标签的工具或其他 API 使用。

以下显示了 Person 和 Address 结构的定义，它们带有 JSON 注释，可以被 Go 的 JSON 编码器和解码器解释（在标准库中找到）：

```go
type Person struct { 
   Name    string `json:"person_name"` 
   Title   string `json:"person_title"` 
   Address `json:"person_address_obj"` 
} 

type Address struct { 
   Street string `json:"person_addr_street"` 
   City   string `json:"person_city"` 
   State  string `json:"person_state"` 
   Postal string `json:"person_postal_code"` 
} 
func main() { 
   p := Person{ 
         Name: "Vladimir Vivien", 
         Title : "Author", 
         ... 
   } 
   ... 
   b, _ := json.Marshal(p) 
   fmt.Println(string(b)) 
} 

```

golang.fyi/ch07/struct_ptr2.go

请注意，标签被表示为原始字符串值（包裹在一对``中）。标签在正常的代码执行中被忽略。但是，它们可以使用 Go 的反射 API 收集，就像 JSON 库所做的那样。当本书讨论输入和输出流时，您将在第十章中遇到更多关于这个主题的内容，*Go 中的数据 IO*。

# 摘要

本章涵盖了 Go 中找到的每种复合类型，以提供对它们特性的深入覆盖。本章以数组类型的覆盖开篇，读者学习了如何声明、初始化和使用数组值。接下来，读者学习了关于切片类型的所有内容，特别是声明、初始化和使用切片索引表达式来创建新的或重新切片现有切片的实际示例。本章涵盖了映射类型，其中包括有关映射初始化、访问、更新和遍历的信息。最后，本章提供了有关结构类型的定义、初始化和使用的信息。

不用说，这可能是本书中最长的章节之一。然而，这里涵盖的信息将在书中继续探讨新主题时被证明是非常宝贵的。下一章将介绍使用 Go 支持对象式习语的想法，使用方法和接口。


# 第八章：方法、接口和对象

使用您目前的技能，您可以编写一个使用到目前为止涵盖的基本概念的有效的 Go 程序。正如您将在本章中看到的，Go 类型系统可以支持超出简单函数的习语。虽然 Go 的设计者并不打算创建一个具有深层类层次结构的面向对象的语言，但该语言完全能够支持类型组合，具有高级特性来表达复杂对象结构的创建，如下面的主题所涵盖的那样：

+   Go 方法

+   Go 中的对象

+   接口类型

+   类型断言

# Go 方法

可以将 Go 函数定义为仅限于特定类型的范围。当函数范围限定为类型或附加到类型时，它被称为*方法*。方法的定义与任何其他 Go 函数一样。但是，它的定义包括*方法接收器*，它是放置在方法名称之前的额外参数，用于指定方法附加到的主机类型。

为了更好地说明这个概念，以下图示了定义方法涉及的不同部分。它显示了`quart`方法附加到“类型加仑”基于接收器参数“g 加仑”的接收器：

![Go 方法](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/image_08_001.jpg)

如前所述，方法具有类型的范围。因此，它只能通过已声明的值（具体或指针）使用*点表示法*来访问。以下程序显示了如何使用此表示法访问已声明的方法`quart`：

```go
package main 
import "fmt" 

type gallon float64 

func (g gallon) quart() float64 { 
   return float64(g * 4) 
} 
func main(){ 
    gal := gallon(5) 
    fmt.Println(gal.quart()) 
} 

```

golang.fyi/ch08/method_basic.go

在前面的示例中，`gal`变量被初始化为`gallon`类型。因此，可以使用`gal.quart()`访问`quart`方法。

在运行时，接收器参数提供对方法的基本类型分配的值的访问。在示例中，`quart`方法接收`g`参数，该参数传递了声明类型的值的副本。因此，当`gal`变量初始化为值`5`时，调用`gal.quart()`会将接收器参数`g`设置为`5`。因此，接下来将打印出值`20`：

```go
func main(){ 
    gal := gallon(5) 
    fmt.Println(gal.quart()) 
} 

```

重要的是要注意，方法接收器的基本类型不能是指针（也不能是接口）。例如，以下内容将无法编译：

```go
type gallon *float64    
func (g gallon) quart() float64 {
  return float64(g * 4)
}

```

以下显示了实现更通用的液体体积转换程序的源代码的较长版本。每种容积类型都接收其各自的方法，以公开与该类型相关的行为：

```go
package main 
import "fmt" 

type ounce float64 
func (o ounce) cup() cup { 
   return cup(o * 0.1250) 
} 

type cup float64 
func (c cup) quart() quart { 
   return quart(c * 0.25) 
} 
func (c cup) ounce() ounce { 
   return ounce(c * 8.0) 
} 

type quart float64 
func (q quart) gallon() gallon { 
   return gallon(q * 0.25) 
} 
func (q quart) cup() cup { 
   return cup(q * 4.0) 
} 

type gallon float64 
func (g gallon) quart() quart { 
   return quart(g * 4) 
} 

func main() { 
    gal := gallon(5) 
    fmt.Printf("%.2f gallons = %.2f quarts\n", gal, gal.quart()) 
    ozs := gal.quart().cup().ounce() 
    fmt.Printf("%.2f gallons = %.2f ounces\n", gal, ozs) 
} 

```

github.com/vladimirvivien/learning-go/ch08/methods.go

例如，将`5`加仑转换为盎司可以通过在给定值上调用适当的转换方法来完成，如下所示：

```go
gal := gallon(5) 
ozs := gal.quart().cup().ounce() 

```

整个实现使用了一个简单但有效的典型结构来表示数据类型和行为。阅读代码，它清晰地表达了其预期含义，而不依赖于繁重的类结构。

### 注意

**方法集**

通过接收器参数附加到类型的方法数量被称为类型的*方法集*。这包括具体和指针值接收器。方法集的概念在确定类型相等性、接口实现和*空接口*的空方法集的支持方面非常重要（本章中都有讨论）。

## 值和指针接收器

到目前为止，逃脱讨论的方法的一个方面是接收器是普通函数参数。因此，它们遵循 Go 函数的传值机制。这意味着调用的方法会得到从声明类型中的原始值的副本。

接收器参数可以作为基本类型的值或指针传递。例如，以下程序显示了两种方法，`half`和`double`；两者都直接更新其各自的方法接收器参数`g`的值：

```go
package main
import "fmt" 
type gallon float64 
func (g gallon) quart() float64 { 
  return float64(g * 4) 
} 
func (g gallon) half() { 
  g = gallon(g * 0.5) 
} 
func (g *gallon) double() { 
  *g = gallon(*g * 2) 
} 
func main() { 
  var gal gallon = 5 
  gal.half() 
  fmt.Println(gal) 
  gal.double() 
  fmt.Println(gal) 
} 

```

golang.fyi/ch08/receiver_ptr.go

在`half`方法中，代码使用`g = gallon(g * 0.5)`更新接收器参数。正如您所期望的那样，这不会更新原始声明的值，而是存储在`g`参数中的副本。因此，当在`main`中调用`gal.half()`时，原始值保持不变，以下内容将打印`5`：

```go
func main() { 
   var gal gallon = 5 
   gal.half() 
   fmt.Println(gal) 
} 

```

与常规函数参数类似，使用指针作为接收器参数来引用其基础值的参数允许代码对原始值进行解引用以更新它。这在以下代码片段中的`double`方法中得到了突出显示。它使用了`*gallon`类型的方法接收器，该接收器使用`*g = gallon(*g * 2)`进行更新。因此，当在`main`中调用以下内容时，它将打印出**10**的值：

```go
func main() { 
   var gal gallon = 5 
   gal.double() 
   fmt.Println(gal) 
} 

```

指针接收器参数在 Go 中被广泛使用。这是因为它们可以表达类似对象的原语，可以携带状态和行为。正如下一节所示，指针接收器以及其他类型特性是在 Go 中创建对象的基础。

# Go 中的对象

前几节的冗长介绍材料是为了引出讨论 Go 中的对象。已经提到 Go 并不是设计成传统的面向对象语言。Go 中没有定义对象或类关键字。那么，为什么我们要讨论 Go 中的对象呢？事实证明，Go 完全支持对象习语和面向对象编程实践，而不需要其他面向对象语言中复杂的继承结构。

让我们在下表中回顾一些通常归因于面向对象语言的原始特性。

| **对象特性** | **Go** | **评论** |
| --- | --- | --- |
| 对象：存储状态并公开行为的数据类型 | 是 | 在 Go 中，所有类型都可以实现这一点。没有称为类或对象的特殊类型来做到这一点。任何类型都可以接收一组方法来定义其行为，尽管`struct`类型最接近其他语言中通常称为对象的内容。 |
| 组合 | 是 | 使用诸如`struct`或`interface`（稍后讨论）的类型，可以通过组合创建对象并表达它们的多态关系。 |
| 通过接口进行子类型化 | 是 | 定义一组其他类型可以实现的行为（方法）的类型。稍后您将看到它是如何用于实现对象子类型化的。 |
| 模块化和封装 | 是 | Go 在其核心支持物理和逻辑模块化，包括包和可扩展的类型系统，以及代码元素的可见性。 |
| 类型继承 | 否 | Go 不支持通过继承实现多态性。新声明的命名类型不会继承其基础类型的所有属性，并且在类型系统中会被不同对待。因此，通过类型谱系实现继承在其他语言中很难实现。 |
| 类 | 无 | Go 中没有作为对象基础的类类型概念。Go 中的任何数据类型都可以用作对象。 |

正如前面的表所示，Go 支持通常归因于面向对象编程的大多数概念。本章的其余部分涵盖了如何将 Go 用作面向对象编程语言的主题和示例。

## 结构体作为对象

几乎所有的 Go 类型都可以通过存储状态和公开能够访问和修改这些状态的方法来扮演对象的角色。然而，`struct`类型提供了传统上归因于其他语言中对象的所有特性，例如：

+   能够承载方法

+   能够通过组合进行扩展

+   能够被子类型化（借助 Go 的`interface`类型）

本章的其余部分将基于使用`struct`类型来讨论对象。

## 对象组合

让我们从以下简单的示例开始，演示`struct`类型如何作为一个可以实现多态组合的对象。以下源代码片段实现了一个典型的结构，模拟了包括`fuel, engine`, `vehicle`, `truck`和`plane`在内的机动交通组件：

```go
type fuel int 
const ( 
    GASOLINE fuel = iota 
    BIO 
    ELECTRIC 
    JET 
) 
type vehicle struct { 
    make string 
    model string 
} 

type engine struct { 
   fuel fuel 
   thrust int 
} 
func (e *engine) start() { 
   fmt.Println ("Engine started.") 
} 

type truck struct { 
   vehicle 
   engine 
   axels int 
   wheels int 
   class int 
} 
func (t *truck) drive() { 
   fmt.Printf("Truck %s %s, on the go!\n", t.make, t.model)           
} 

type plane struct { 
   vehicle 
   engine 
   engineCount int 
   fixedWings bool 
   maxAltitude int 
} 
func (p *plane) fly() { 
   fmt.Printf( 
          "Aircraft %s %s clear for takeoff!\n", 
          p.make, p.model, 
       ) 
} 

```

golang.fyi/ch08/structobj.go

在前面的代码片段中声明的组件及其关系在下图中进行了说明，以可视化类型映射及其组成：

![对象组合](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/image_08_002.jpg)

Go 使用*组合优于继承*原则，通过`struct`类型支持的类型嵌入机制实现多态性。在 Go 中，没有通过类型继承支持多态性。请记住，每种类型都是独立的，被认为与所有其他类型都不同。实际上，上面的模型中的语义略有问题。类型`truck`和`plane`被显示为由`vehicle`类型组成（或拥有），这听起来不正确。相反，正确的，或者至少更正确的表示应该是显示类型`truck`和`plane`*是*通过子类型关系`vehicle`。在本章的后面，我们将看到如何使用`interface`类型来实现这一点。

## 字段和方法提升

现在在前面的部分中已经建立了对象，让我们花一些时间讨论结构体内部字段、方法和嵌入类型的可见性。以下源代码片段显示了前面示例的延续。它声明并初始化了一个类型为`truck`的变量`t`和一个类型为`plane`的变量`p`。前者使用结构字面量进行初始化，后者使用点符号进行更新：

```go
func main() { 
   t := &truck { 
         vehicle:vehicle{"Ford", "F750"}, 
         engine:engine{GASOLINE+BIO,700}, 
         axels:2, 
         wheels:6, 
         class:3,     
   } 
   t.start() 
   t.drive() 

   p := &plane{} 
   p.make = "HondaJet" 
   p.model = "HA-420" 
   p.fuel = JET 
   p.thrust = 2050 
   p.engineCount = 2 
   p.fixedWings = true 
   p.maxAltitude = 43000 
   p.start() 
   p.fly() 

} 

```

golang.fyi/ch08/structobj.go

在前面的代码片段中，一个更有趣的细节是`struct`类型嵌入机制如何在使用点符号访问时提升字段和方法。例如，以下字段（`make`, `mode`, `fuel`, 和 `thrust`）都声明在`plane`类型内部嵌入的类型中：

```go
p.make = "HondaJet" 
p.model = "HA-420" 
p.fuel = JET 
p.thrust = 2050 

```

前面的字段是从它们的嵌入类型中提升出来的。当访问它们时，就好像它们是`plane`类型的成员一样，但实际上它们分别来自`vehicle`和`engine`类型。为了避免歧义，字段的名称可以被限定，如下所示：

```go
p.vehicle.make = "HondaJet" 
p.vehicle.model = "HA-420" 
p.engine.fuel = JET 
p.engine.thrust = 2050 

```

方法也可以以类似的方式提升。例如，在前面的代码中，我们看到了方法`t.start()`和`p.start()`被调用。然而，类型`truck`和`plane`都不是名为`start()`的方法的接收者。就像之前的程序中所示的那样，`start()`方法是为`engine`类型定义的。由于`engine`类型被嵌入到`truck`和`plane`类型中，`start()`方法在范围上被提升到这些封闭类型中，因此可以访问。

## 构造函数

由于 Go 不支持类，因此没有构造函数的概念。然而，在 Go 中你会遇到的一个常规习语是使用工厂函数来创建和初始化类型的值。以下代码片段显示了前面示例的一部分，已更新为使用构造函数来创建`plane`和`truck`类型的新值：

```go
type truck struct { 
   vehicle 
   engine 
   axels int 
   wheels int 
   class int 
} 
func newTruck(mk, mdl string) *truck { 
   return &truck {vehicle:vehicle{mk, mdl}} 
} 

type plane struct { 
   vehicle 
   engine 
   engineCount int 
   fixedWings bool 
   maxAltitude int 
}   
func newPlane(mk, mdl string) *plane { 
   p := &plane{} 
   p.make = mk 
   p.model = mdl 
   return p 
} 

```

golang.fyi/ch08/structobj2.go

尽管不是必需的，但提供一个函数来帮助初始化复合值，比如一个结构体，会增加代码的可用性。它提供了一个地方来封装可重复的初始化逻辑，可以强制执行验证要求。在前面的例子中，构造函数`newTruck`和`newPlane`都传递了制造和型号信息来创建和初始化它们各自的值。

# 接口类型

当您与已经使用 Go 一段时间的人交谈时，他们几乎总是将接口列为他们最喜欢的语言特性之一。Go 中的接口概念，类似于 Java 等其他语言，是一组方法，用作描述行为的模板。然而，Go 接口是由`interface{}`文字指定的类型，用于列出满足接口的一组方法。以下示例显示了将`shape`变量声明为接口：

```go
var shape interface { 
    area() float64 
    perim() float64 
} 

```

在先前的代码片段中，`shape`变量被声明并分配了一个未命名类型，`interface{area()float64; perim()float64}`。使用未命名的`interface`文字类型声明变量并不是很实用。使用惯用的 Go 方式，几乎总是将`interface`类型声明为命名的`type`。可以重写先前的代码片段以使用命名的接口类型，如以下示例所示：

```go
type shape interface { 
   area() float64 
   perim() float64 
} 
var s shape 

```

## 实现接口

Go 中接口的有趣之处在于它们是如何实现和最终使用的。实现 Go 接口是隐式完成的。不需要单独的元素或关键字来指示实现的意图。任何定义了`interface`类型的方法集的类型都会自动满足其实现。

以下源代码显示了`rect`类型作为`shape`接口类型的实现。`rect`类型被定义为具有接收器方法`area`和`perim`的`struct`。这一事实自动使`rect`成为`shape`的实现：

```go
type shape interface { 
   area() float64 
   perim() float64 
} 

type rect struct { 
   name string 
   length, height float64 
} 

func (r *rect) area() float64 { 
   return r.length * r.height 
} 

func (r *rect) perim() float64 { 
   return 2*r.length + 2*r.height 
} 

```

golang.fyi/ch08/interface_impl.go

## 使用 Go 接口进行子类型化

在讨论对象时，曾提到 Go 在构建对象时更青睐组合（*具有*）关系。虽然如此，Go 也可以使用接口通过子类型化来表达对象之间的“是一个”关系。在我们先前的示例中，可以认为`rect`类型（以及实现`area`和`perim`方法的任何其他类型）可以被视为`shape`的子类型，如下图所示：

![使用 Go 接口进行子类型化](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/image_08_003.jpg)

正如您可能期望的那样，`shape`的任何子类型都可以参与表达式或作为函数（或方法）参数传递，其中期望`shape`类型。在以下代码片段中，先前定义的`rect`和`triangle`类型都能够传递给`shapeInfo(shape)`函数，以返回包含形状计算的`string`值：

```go
type triangle struct { 
   name string 
   a, b, c float64 
} 

func (t *triangle) area() float64 { 
   return 0.5*(t.a * t.b) 
} 

func (t *triangle) perim() float64 { 
   return t.a + t.b + math.Sqrt((t.a*t.a) + (t.b*t.b)) 
} 

func (t *triangle) String() string { 
   return fmt.Sprintf( 
         "%s[sides: a=%.2f b=%.2f c=%.2f]", 
         t.name, t.a, t.b, t.c, 
   ) 
} 
func shapeInfo(s shape) string { 
   return fmt.Sprintf( 
         "Area = %.2f, Perim = %.2f", 
         s.area(), s.perim(), 
   ) 
} 

func main() { 
   r := &      rect{"Square", 4.0, 4.0} 
   fmt.Println(r, "=>", shapeInfo(r)) 

   t := &      triangle{"Right Triangle", 1,2,3} 
   fmt.Println(t, "=>", shapeInfo(t)) 
} 

```

golang.fyi/ch08/interface_impl.go

## 实现多个接口

接口的隐式机制允许任何命名类型同时满足多个接口类型。这只需让给定类型的方法集与要实现的每个`interface`类型的方法相交即可实现。让我们重新实现先前的代码以展示如何实现这一点。引入了两个新接口，`polygon`和`curved`，以更好地捕获和分类形状的信息和行为，如以下代码片段所示：

```go
type shape interface { 
   area() float64 
} 

type polygon interface { 
   perim() 
} 

type curved interface { 
   circonf() 
} 
type rect struct {...} 
func (r *rect) area() float64 { 
   return r.length * r.height 
} 
func (r *rect) perim() float64 { 
   return 2*r.length + 2*r.height 
} 

type triangle struct {...} 
func (t *triangle) area() float64 { 
   return 0.5*(t.a * t.b) 
} 
func (t *triangle) perim() float64 { 
   return t.a + t.b + math.Sqrt((t.a*t.a) + (t.b*t.b)) 
} 

type circle struct { ... } 
func (c *circle) area() float64 { 
   return math.Pi * (c.rad*c.rad) 
} 
func (c *circle) circonf() float64 { 
   return 2 * math.Pi * c.rad 
} 

```

golang.fyi/ch08/interface_impl2.go

先前的源代码片段显示了类型如何通过简单声明满足接口的方法集来自动满足多个接口。如下图所示：

![实现多个接口](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/image_08_004.jpg)

## 接口嵌入

`interface`类型的另一个有趣方面是它支持类型嵌入（类似于`struct`类型）。这使您可以以最大程度地重用类型的方式来构造您的类型。继续使用形状示例，以下代码片段通过将形状嵌入到其他两种类型中，重新组织并将先前的接口数量从三个减少到两个：

```go
type shape interface { 
   area() float64 
} 

type polygon interface { 
   shape 
   perim() 
} 

type curved interface { 
   shape 
   circonf() 
} 

```

golang.fyi/ch08/interface_impl3.go

以下插图显示了如何组合接口类型，以便*是一个*关系仍然满足代码组件之间的关系：

![接口嵌入](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/image_08_005.jpg)

在嵌入接口类型时，封闭类型将继承嵌入类型的方法集。如果嵌入类型导致方法签名冲突，编译器将发出警告。嵌入成为一个至关重要的特性，特别是当代码应用类型检查时。它允许类型汇总类型信息，从而减少不必要的断言步骤（类型断言稍后讨论）。

## 空接口类型

`interface{}` 类型，或空 `interface` 类型，是具有空方法集的 `interface` 类型的文字表示。根据我们迄今为止的讨论，可以推断出 *所有类型都实现了空接口*，因为所有类型都可以具有零个或多个成员的方法集。

当一个变量被赋予 `interface{}` 类型时，编译器会放松其构建时的类型检查。然而，该变量仍然携带可以在运行时查询的类型信息。下面的代码说明了这是如何工作的：

```go
func main() { 
   var anyType interface{} 
   anyType = 77.0 
   anyType = "I am a string now" 
   fmt.Println(anyType) 

   printAnyType("The car is slow") 
   m := map[string] string{"ID":"12345", "name":"Kerry"} 
   printAnyType(m) 
   printAnyType(1253443455) 
} 

func printAnyType(val interface{}) { 
   fmt.Println(val) 
} 

```

golang.fyi/ch08/interface_empty.go

在前面的代码中，`anyType` 变量被声明为 `interface{}` 类型。它能够被赋予不同类型的值，而不会受到编译器的投诉：

```go
anyType = 77.0 
anyType = "I am a string now" 

```

`printAnyType()` 函数以 `interface{}` 类型的参数。这意味着该函数可以传递任何有效类型的值，如下所示：

```go
printAnyType("The car is slow") 
m := map[string] string{"ID":"12345", "name":"Kerry"} 
printAnyType(m) 
printAnyType(1253443455) 

```

空接口对于 Go 语言的习惯用法至关重要。将类型检查延迟到运行时使得语言更具动态性，而不完全牺牲强类型。Go 语言提供了诸如类型断言（下文介绍）的机制，以在运行时查询接口所携带的类型信息。

# 类型断言

当将接口（空或其他）分配给变量时，它携带可以在运行时查询的类型信息。类型断言是 Go 语言中可用的一种机制，用于将变量（`interface` 类型）习惯上缩小到存储在变量中的具体类型和值。下面的示例使用类型断言在 `eat` 函数中选择要在 `eat` 函数中选择的 `food` 类型：

```go
type food interface { 
   eat() 
} 

type veggie string 
func (v veggie) eat() { 
   fmt.Println("Eating", v) 
} 

type meat string 
func (m meat) eat() { 
   fmt.Println("Eating tasty", m) 
} 

func eat(f food) { 
   veg, ok := f.(veggie) 
   if ok { 
         if veg == "okra" { 
               fmt.Println("Yuk! not eating ", veg) 
         }else{ 
               veg.eat() 
         } 

         return 
   } 

   mt, ok := f.(meat) 
   if ok { 
         if mt == "beef" { 
               fmt.Println("Yuk! not eating ", mt) 
         }else{ 
               mt.eat() 
         } 
         return 
   } 

   fmt.Println("Not eating whatever that is: ", f) 
} 

```

golang.fyi/interface_assert.go

`eat` 函数以 `food` 接口类型作为参数。代码展示了如何使用习惯用法的 Go 语言来使用断言提取存储在 `f` 接口参数中的静态类型和值。类型断言表达式的一般形式如下所示：

*<interface_variable>.(具体类型名称)*

表达式以接口类型的变量开头。然后跟着一个点和括号括起来的具体断言的类型。类型断言表达式可以返回两个值：一个是具体值（从接口中提取），第二个是一个布尔值，指示断言的成功，如下所示：

*value, boolean := <interface_variable>.(具体类型名称)*

这是在下面的代码片段中显示的断言形式（从之前的示例中提取），用于将 `f` 参数缩小到特定类型的 `food`。如果断言的类型是 `meat`，则代码将继续测试 `mt` 变量的值：

```go
mt, ok := f.(meat) 
if ok { 
   if mt == "beef" { 
         fmt.Println("Yuk! not eating ", mt) 
   }else{ 
         mt.eat() 
   } 
   return 
} 

```

类型断言表达式也可以只返回值，如下所示：

*value := <interface_variable>**.**(具体类型名称)*

这种形式的断言是有风险的，因为如果接口变量中存储的值不是所断言的类型，运行时将导致程序崩溃。只有在有其他保障可以防止或优雅地处理崩溃时才使用这种形式。

最后，当您的代码需要多个断言来在运行时测试多种类型时，更好的断言习惯是使用类型 `switch` 语句。它使用 `switch` 语句语义来使用 case 子句从接口值中查询静态类型信息。前面与食品相关的示例中的 `eat` 函数可以更新为使用类型 `switch` 而不是 `if` 语句，如下面的代码片段所示：

```go
func eat(f food) { 
   swtich morsel := f.(type){ 
   case veggie: 
         if morsel == "okra" { 
               fmt.Println("Yuk! not eating ", mosel) 
         }else{ 
               mosel.eat() 
         } 
   case meat: 
         if morsel == "beef" { 
               fmt.Println("Yuk! not eating ", mosel) 
         }else{ 
               mosel.eat() 
         }            
   default: 
         fmt.Println("Not eating whatever that is: ", f) 
   } 
} 

```

golang.fyi/interface_assert2.go

请注意，代码的可读性大大提高。它可以支持任意数量的情况，并且清晰地布局，具有视觉线索，使人们能够轻松推理。`switch`类型还通过简单指定一个默认情况来消除了恐慌问题，该默认情况可以处理在情况子句中没有明确处理的任何类型。

# 总结

本章试图以广泛且在某种程度上全面的视角来介绍几个重要主题，包括在 Go 中的方法、接口和对象。本章首先介绍了如何使用接收器参数将方法附加到类型。接下来介绍了对象以及如何在 Go 中创建符合惯例的基于对象的编程。最后，本章全面概述了接口类型以及它在支持 Go 中对象语义方面的应用。下一章将引导读者了解 Go 中最基本的概念之一，这也是 Go 在开发者中引起轰动的原因：并发！


# 第九章：并发性

并发被认为是 Go 最吸引人的特性之一。语言的采用者沉迷于使用其原语来表达正确的并发实现的简单性，而不会出现通常伴随此类努力的陷阱。本章涵盖了理解和创建并发 Go 程序的必要主题，包括以下内容：

+   Goroutines

+   通道

+   编写并发程序

+   sync 包

+   检测竞争条件

+   Go 中的并行性

# Goroutines

如果您在其他语言中工作过，比如 Java 或 C/C++，您可能熟悉并发的概念。这是程序能够独立运行两个或多个执行路径的能力。通常通过直接向程序员公开线程原语来创建和管理并发来实现这一点。

Go 有自己的并发原语，称为*goroutine*，它允许程序启动一个函数（例程）以独立于其调用函数执行。Goroutines 是轻量级的执行上下文，它们在少量 OS 支持的线程中进行多路复用，并由 Go 的运行时调度程序进行调度。这使它们可以在不需要真正的内核线程的开销要求的情况下轻松创建。因此，Go 程序可以启动数千（甚至数十万）个 goroutine，对性能和资源降级的影响很小。

## go 语句

使用`go`语句启动 goroutines 如下所示：

*go <function or expression>*

使用`go`关键字后跟要安排执行的函数创建 goroutine。指定的函数可以是现有函数、匿名函数或调用函数的表达式。以下代码片段显示了 goroutines 的使用示例：

```go
func main() { 
   go count(10, 50, 10) 
   go count(60, 100, 10) 
   go count(110, 200, 20) 
} 
func count(start, stop, delta int) { 
   for i := start; i <= stop; i += delta { 
         fmt.Println(i) 
   } 
} 

```

golang.fyi/ch09/goroutine0.go

在前面的代码示例中，当在`main`函数中遇到`go count()`语句时，它会在独立的执行上下文中启动`count`函数。`main`和`count`函数将同时执行。作为副作用，`main`将在任何`count`函数有机会向控制台打印任何内容之前完成。

在本章的后面，我们将看到如何在 goroutines 之间以惯用方式处理同步。现在，让我们使用`fmt.Scanln()`来阻塞并等待键盘输入，如下示例所示。在这个版本中，同时运行的函数有机会在等待键盘输入时完成：

```go
func main() { 
   go count(10, 30, 10) 
   go count(40, 60, 10) 
   go count(70, 120, 20) 
   fmt.Scanln() // blocks for kb input 
} 

```

golang.fyi/ch09/goroutine1.go

Goroutines 也可以直接在`go`语句中定义为函数文字，如下面代码片段中所示的示例的更新版本：

```go
func main() { 
   go count(10, 30, 10) 
   go func() { 
         count(40, 60, 10) 
   }() 
   ... 
}  

```

golang.fyi/ch09/goroutine2.go

函数文字提供了一个方便的习语，允许程序员直接在`go`语句的位置组装逻辑。当使用带有函数文字的`go`语句时，它被视为具有对非局部变量的词法访问权限的常规闭包，如下例所示：

```go
func main() { 
   start := 0 
   stop := 50 
   step := 5 
   go func() { 
         count(start, stop, step) 
   }() 
} 

```

golang.fyi/ch09/goroutine3.go

在前面的代码中，goroutine 能够访问和使用变量`start`、`stop`和`step`。只要在闭包中捕获的变量在 goroutine 启动后不会发生更改，这是安全的。如果这些值在闭包之外更新，可能会导致竞争条件，从而导致 goroutine 在计划运行时读取意外值。

以下片段显示了一个示例，其中 goroutine 闭包捕获了循环中的变量`j`：

```go
func main() { 
   starts := []int{10,40,70,100} 
   for _, j := range starts{ 
         go func() { 
               count(j, j+20, 10) 
         }() 
   } 
} 

```

golang.fyi/ch09/goroutine4.go

由于`j`在每次迭代中都会更新，所以不可能确定闭包将读取什么值。在大多数情况下，goroutine 闭包将在执行时看到`j`的最后更新值。可以通过在 goroutine 的函数文字中将变量作为参数传递来轻松解决这个问题，如下所示：

```go
func main() { 
   starts := []int{10,40,70,100} 
   for _, j := range starts{ 
         go func(s int) { 
               count(s, s+20, 10) 
         }(j) 
   } 
} 

```

golang.fyi/ch09/goroutine5.go

每次循环迭代时调用的 goroutine 闭包通过函数参数接收`j`变量的副本。这将创建`j`值的本地副本，并在调度运行 goroutine 时使用正确的值。

## Goroutine 调度

总的来说，所有的 goroutine 都是独立运行的，如下图所示。创建 goroutine 的函数不会等待它返回，除非有阻塞条件，它会继续执行自己的执行流。本章后面将介绍协调 goroutine 的同步习语：

![Goroutine 调度](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/image_09_001.jpg)

Go 的运行时调度程序使用一种协作调度形式来调度 goroutine。默认情况下，调度程序将允许运行的 goroutine 执行完成。但是，如果发生以下事件之一，调度程序将自动让出执行权给另一个 goroutine：

+   在执行 goroutine 中遇到`go`语句

+   遇到通道操作（通道稍后会介绍）

+   遇到阻塞的系统调用（例如文件或网络 IO）

+   在垃圾回收周期完成后

调度程序将调度排队的 goroutine，准备在运行的 goroutine 中遇到前面的事件之一时进入执行。重要的是要指出，调度程序不保证 goroutine 的执行顺序。例如，当执行以下代码片段时，输出将以任意顺序打印每次运行：

```go
func main() { 
   go count(10, 30, 10) 
   go count(40, 60, 10) 
   go count(70, 120, 20) 
   fmt.Scanln() // blocks for kb input 
} 
func count(start, stop, delta int) { 
   for i := start; i <= stop; i += delta { 
         fmt.Println(i) 
   } 
} 

```

golang.fyi/ch09/goroutine1.go

以下显示了前一个程序的可能输出：

```go
10
70
90
110
40
50
60
20
30

```

# 通道

谈论并发时，一个自然的关注点是数据的安全性和并发执行代码之间的同步。如果您在诸如 Java 或 C/C++等语言中进行并发编程，您可能熟悉确保运行线程可以安全访问共享内存值以实现线程之间通信和同步所需的有时脆弱的协调。

这是 Go 与其 C 血统不同的地方之一。Go 不是通过使用共享内存位置让并发代码进行通信，而是使用通道作为运行的 goroutine 之间通信和共享数据的通道。博客文章*Effective Go*（[`golang.org/doc/effective_go.html`](https://golang.org/doc/effective_go.html)）将这个概念简化为以下口号：

*不要通过共享内存进行通信；相反，通过通信共享内存。*

### 注意

通道的概念源于著名计算机科学家 C.A. Hoare 的**通信顺序进程**（**CSP**）工作，用于使用通信原语对并发进行建模。正如本节将讨论的那样，通道提供了在运行的 goroutine 之间同步和安全地通信数据的手段。

本节讨论了 Go 通道类型，并深入了解了其特性。稍后，您将学习如何使用通道来创建并发程序。

## 通道类型

通道类型声明了一个通道，其中只能通过通道发送或接收给定元素类型的值。`chan`关键字用于指定通道类型，如以下声明格式所示：

*chan <element type>*

以下代码片段声明了一个双向通道类型`chan int`，分配给变量`ch`，用于通信整数值：

```go
func main() { 
   var ch chan int 
   ... 
} 

```

在本章后面，我们将学习如何使用通道在运行程序的并发部分之间发送数据。

### 发送和接收操作

Go 使用`<-`（箭头）运算符来指示通道内的数据移动。以下表总结了如何从通道发送或接收数据：

| **示例** | **操作** | **描述** |
| --- | --- | --- |
| `intCh <- 12` | 发送 | 当箭头放置在值、变量或表达式的左侧时，表示向指向的通道进行发送操作。在这个例子中，`12`被发送到`intCh`通道中。 |
| `value := <- intCh` | 接收 | 当`<-`操作符放置在通道的左侧时，表示从通道接收操作。`value`变量被赋予从`intCh`通道接收到的值。 |

未初始化的通道具有*nil*零值，并且必须使用内置的*make*函数进行初始化。正如将在接下来的章节中讨论的那样，通道可以根据指定的容量初始化为无缓冲或带缓冲。每种类型的通道都有不同的特性，在不同的并发构造中得到利用。

## 无缓冲通道

当`make`函数在没有容量参数的情况下被调用时，它会返回一个双向*无缓冲*通道。以下代码片段展示了创建类型为`chan int`的无缓冲通道：

```go
func main() { 
   ch := make(chan int) // unbuffered channel 
   ... 
} 

```

无缓冲通道的特性如下图所示：

![无缓冲通道](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/image_09_002.jpg)

在前面的图中（从左到右），显示了无缓冲通道的工作原理：

+   如果通道为空，接收方会阻塞，直到有数据

+   发送方只能向空通道发送数据，并且会阻塞，直到下一个接收操作

+   当通道有数据时，接收方可以继续接收数据。

向无缓冲通道发送数据，如果操作没有包装在 goroutine 中，很容易导致*死锁*。以下代码在向通道发送`12`后将会阻塞：

```go
func main() { 
   ch := make(chan int) 
   ch <- 12 // blocks   
   fmt.Println(<-ch) 
} 

```

golang.fyi/ch09/chan-unbuff0.go

当运行前面的程序时，将得到以下结果：

```go
$> go run chan-unbuff0.go
fatal error: all goroutines are asleep - deadlock!

```

请记住，向无缓冲通道发送数据时，发送方会立即阻塞。这意味着任何后续的语句，例如接收通道的操作，都将无法到达，导致死锁。以下代码展示了向无缓冲通道发送数据的正确方式：

```go
func main() { 
   ch := make(chan int) 
   go func() { ch <- 12 }() 
   fmt.Println(<-ch) 
} 

```

golang.fyi/ch09/chan-unbuff1.go

请注意，发送操作被包装在一个匿名函数中，作为一个单独的 goroutine 调用。这允许`main`函数在不阻塞的情况下进行接收操作。正如您将在后面看到的，无缓冲通道的这种阻塞特性被广泛用作 goroutine 之间的同步和协调习语。

## 带缓冲通道

当`make`函数使用容量参数时，它会返回一个双向*带缓冲*通道，如下面的代码片段所示：

```go
func main 
   ch := make(chan int, 3) // buffered channel  
} 

```

前面的代码将创建一个容量为`3`的带缓冲通道。带缓冲通道作为先进先出的阻塞队列进行操作，如下图所示：

![带缓冲通道](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/image_09_003.jpg)

在前面的图中所示的带缓冲通道具有以下特性：

+   当通道为空时，接收方会阻塞，直到至少有一个元素

+   只要通道未达到容量，发送方就会成功

+   当通道达到容量时，发送方会阻塞，直到至少接收到一个元素

使用带缓冲的通道，可以在同一个 goroutine 中发送和接收值而不会导致死锁。以下是使用容量为`4`的带缓冲通道进行发送和接收的示例：

```go
func main() { 
   ch := make(chan int, 4) 
   ch <- 2 
   ch <- 4 
   ch <- 6 
   ch <- 8 

   fmt.Println(<-ch) 
   fmt.Println(<-ch) 
   fmt.Println(<-ch) 
   fmt.Println(<-ch) 

} 

```

golang.fyi/ch09/chan0.go

在前面的示例中，该代码能够将值`2`、`4`、`6`和`8`发送到`ch`通道，而不会出现阻塞的风险。四个`fmt.Println(<-ch)`语句用于依次接收通道中的值。然而，如果在第一个接收操作之前添加第五个发送操作，代码将会出现死锁，如下面的代码片段所示：

```go
func main() { 
   ch := make(chan int, 4) 
   ch <- 2 
   ch <- 4 
   ch <- 6 
   ch <- 8 
   ch <- 10  
   fmt.Println(<-ch) 
   ... 
} 

```

在本章的后面，您将会了解更多关于使用通道进行通信的惯用且安全的方法。

## 单向通道

在声明时，通道类型还可以包括单向操作符（再次使用 `<-` 箭头）来指示通道是只发送还是只接收的，如下表所示：

| **声明** | **操作** |
| --- | --- |

| `<-` *chan <element type>* | 声明一个只接收的通道，如后面所示。

```go
var inCh chan<- int
```

|

| *chan* `<-`*<element type>* | 声明一个只发送的通道，如后面所示。

```go
var outCh <-chan int
```

|

下面的代码片段显示了函数 `makeEvenNums`，它具有一个类型为 `chan <- int` 的只发送通道参数：

```go
func main() { 
   ch := make(chan int, 10) 
   makeEvenNums(4, ch) 

   fmt.Println(<-ch) 
   fmt.Println(<-ch) 
   fmt.Println(<-ch) 
   fmt.Println(<-ch) 
} 

func makeEvenNums(count int, in chan<- int) { 
   for i := 0; i < count; i++ { 
         in <- 2 * i 
   } 
} 

```

golang.fyi/ch09/chan1.go

由于通道的方向性已经在类型中确定，访问违规将在编译时被检测到。因此，在上一个示例中，`in` 通道只能用于接收操作。

双向通道可以显式或自动地转换为单向通道。例如，当从 `main()` 调用 `makeEvenNums()` 时，它接收双向通道 `ch` 作为参数。编译器会自动将通道转换为适当的类型。

## 通道长度和容量

`len` 和 `cap` 函数可以分别用于返回通道的长度和容量。`len` 函数返回接收者读取通道之前通道中排队的元素的当前数量。例如，以下代码片段将打印 **2**：

```go
func main() { 
   ch := make(chan int, 4) 
   ch <- 2 
   ch <- 2 
   fmt.Println(len(ch)) 
} 

```

`cap` 函数返回通道类型的声明容量，与长度不同，容量在通道的整个生命周期中保持不变。

### 注意

非缓冲通道的长度和容量均为零。

## 关闭通道

一旦通道初始化，它就准备好进行发送和接收操作。通道将保持在打开状态，直到使用内置的 *close* 函数强制关闭，如下例所示：

```go
func main() { 
   ch := make(chan int, 4) 
   ch <- 2 
   ch <- 4 
   close(ch) 
   // ch <- 6 // panic, send on closed channel 

   fmt.Println(<-ch) 
   fmt.Println(<-ch) 
   fmt.Println(<-ch) // closed, returns zero value for element 

} 

```

golang.fyi/ch09/chan2.go

一旦通道关闭，它具有以下属性：

+   后续的发送操作将导致程序恐慌

+   接收操作永远不会阻塞（无论是缓冲还是非缓冲）

+   所有接收操作都返回通道元素类型的零值

在上面的片段中，`ch` 通道在两次发送操作后关闭。如注释中所示，第三次发送操作将导致恐慌，因为通道已关闭。在接收端，代码在通道关闭之前获取了两个元素。第三次接收操作返回 `0`，即通道元素的零值。

Go 提供了接收操作的长形式，它返回从通道读取的值，后面跟着一个布尔值，指示通道的关闭状态。这可以用于正确处理从关闭通道中的零值，如下例所示：

```go
func main() { 
   ch := make(chan int, 4) 
   ch <- 2 
   ch <- 4 
   close(ch) 

   for i := 0; i < 4; i++ { 
         if val, opened := <-ch; opened { 
               fmt.Println(val) 
         } else { 
               fmt.Println("Channel closed!") 
         } 
   } 
} 

```

golang.fyi/ch09/chan3.go

# 编写并发程序

到目前为止，关于 goroutines 和通道的讨论一直故意分开，以确保每个主题都得到适当的覆盖。然而，当它们结合起来创建并发程序时，通道和 goroutines 的真正力量才得以实现，正如本节所介绍的。

## 同步

通道的主要用途之一是在运行的 goroutines 之间进行同步。为了说明这个用例，让我们来看一下下面的代码，它实现了一个单词直方图。该程序从 `data` 切片中读取单词，然后在一个单独的 goroutine 中收集每个单词的出现次数：

```go
func main() { 
   data := []string{ 
         "The yellow fish swims slowly in the water", 
         "The brown dog barks loudly after a drink ...", 
         "The dark bird bird of prey lands on a small ...", 
   } 

   histogram := make(map[string]int) 
   done := make(chan bool) 

   // splits and count words 
   go func() { 
         for _, line := range data { 
               words := strings.Split(line, " ") 
               for _, word := range words { 
                     word = strings.ToLower(word) 
                     histogram[word]++ 
               } 
         } 
         done <- true 
   }() 

   if <-done { 
         for k, v := range histogram { 
               fmt.Printf("%s\t(%d)\n", k, v) 
         } 
   } 
} 

```

golang.fyi/ch09/pattern0.go

在上一个示例中的代码中，使用 `done := make(chan bool)` 创建了一个通道，该通道将用于同步程序中运行的两个 goroutines。`main` 函数启动了一个次要的 goroutine，它执行单词计数，然后继续执行，直到在 `<-done` 表达式处阻塞，导致它等待。

与此同时，次要的 goroutine 运行直到完成其循环。然后，它向 `done` 通道发送一个值，使用 `done <- true`，导致被阻塞的 `main` 例程变得不再阻塞，并继续执行。

### 注意

前面的代码存在一个可能导致竞争条件的错误。在本章后面将介绍修正方法。

在前一个示例中，代码分配并实际发送了一个布尔值，用于同步。经过进一步检查，可以清楚地看到通道中的值是无关紧要的，我们只是希望它发出信号。因此，我们可以将同步习语进一步简化为一个俗语形式，如下面的代码片段所示：

```go
func main() { 
... 
   histogram := make(map[string]int) 
   done := make(chan struct{}) 

   // splits and count 
   go func() { 
         defer close(done) // closes channel upon fn return 
         for _, line := range data { 
               words := strings.Split(line, " ") 
               for _, word := range words { 
                     word = strings.ToLower(word) 
                     histogram[word]++ 
               } 
         } 
   }() 

   <-done // blocks until closed 

   for k, v := range histogram { 
         fmt.Printf("%s\t(%d)\n", k, v) 
   } 
} 

```

golang.fyi/ch09/pattern1.go

这个代码版本通过以下方式实现了 goroutine 同步：

+   done 通道，声明为类型`chan struct{}`

+   主 goroutine 在接收表达式`<-done`处阻塞

+   当 done 通道关闭时，所有接收方都能成功接收，而不会阻塞。

尽管信令是使用不同的结构完成的，但这个代码版本等同于第一个版本（`pattern0.go`）。空的`struct{}`类型不存储任何值，严格用于信令。这个代码版本关闭了`done`通道（而不是发送一个值）。这样做的效果是允许主 goroutine 解除阻塞并继续执行。

## 数据流

通道的一个自然用途是从一个 goroutine 流式传输数据到另一个。这种模式在 Go 代码中非常常见，为了使其工作，必须完成以下工作：

+   不断在通道上发送数据

+   不断接收来自该通道的传入数据

+   发出流的结束信号，以便接收方可以停止

正如你将看到的，所有这些都可以使用一个单一的通道完成。以下代码片段是前一个示例的重写。它展示了如何使用单一通道从一个 goroutine 流式传输数据到另一个。同一个通道也被用作信令设备来指示流的结束：

```go
func main(){ 
... 
   histogram := make(map[string]int) 
   wordsCh := make(chan string) 

   // splits lines and sends words to channel 
   go func() { 
         defer close(wordsCh) // close channel when done 
         for _, line := range data { 
               words := strings.Split(line, " ") 
               for _, word := range words { 
                     word = strings.ToLower(word) 
                     wordsCh <- word 
               } 
         } 
   }() 

   // process word stream and count words 
   // loop until wordsCh is closed 
   for { 
         word, opened := <-wordsCh 
         if !opened { 
               break 
         } 
         histogram[word]++ 
   } 

   for k, v := range histogram { 
         fmt.Printf("%s\t(%d)\n", k, v) 
   } 
} 

```

golang.fyi/ch09/pattern2.go

这个代码版本与以前一样生成了单词直方图，但引入了不同的方法。这是通过下表中显示的代码部分实现的：

| **代码** | **描述** |
| --- | --- |

|

```go
wordsCh := make(chan string)   

```

| 数据流使用的通道。 |
| --- |

|

```go
wordsCh <- word   

```

| 发送 goroutine 循环遍历文本行并逐个发送单词。然后它会阻塞，直到单词被接收（主）goroutine 接收到。 |
| --- |

|

```go
defer close(wordsCh)   

```

| 当单词不断被接收（见后文）时，发送 goroutine 在完成时关闭通道。这将是接收方应该停止的信号。 |
| --- |

|

```go
for {   
  word, opened := <-wordsCh   
  if !opened {   
    break   
  }   
  histogram[word]++   
}   

```

| 这是接收方的代码。它被放在一个循环中，因为它不知道要预期多少数据。在每次循环迭代中，代码执行以下操作：

+   从通道中拉取数据

+   检查通道的开放状态

+   如果关闭了，就跳出循环

+   否则记录直方图

|

## 使用`for…range`接收数据

前一个模式在 Go 中非常常见，这种习语已经内置到语言中，以`for…range`语句的形式存在：

*for <elemem> := range <channel>{...}*

在每次迭代中，这个`for…range`语句将阻塞，直到它从指定的通道接收到传入的数据，就像下面的代码片段所示：

```go
func main(){                           
... 
   go func() { 
         defer close(wordsCh) 
         for _, line := range data { 
               words := strings.Split(line, " ") 
               for _, word := range words { 
                     word = strings.ToLower(word) 
                     wordsCh <- word 
               } 
         } 
   }() 

   for word := range wordsCh { 
         histogram[word]++ 
   } 
... 
} 

```

golang.fyi/ch09/pattern3.go

前面的代码展示了使用`for-range`语句的更新版本，`for word := range wordsCh`。它会连续地从`wordsCh`通道接收到值。当通道被关闭（来自 goroutine），循环会自动中断。

### 注意

始终记得关闭通道，以便接收方得到适当的信号。否则，程序可能会陷入死锁，导致恐慌。

## 生成器函数

通道和 goroutine 提供了一种自然的基础，用于使用生成器函数实现一种生产者/生产者模式。在这种方法中，一个 goroutine 被包装在一个函数中，该函数生成通过函数返回的通道发送的值。消费者 goroutine 接收这些值，因为它们被生成。

单词直方图已经更新为使用这种模式，如下面的代码片段所示：

```go
func main() { 
   data := []string{"The yellow fish swims...", ...} 
   histogram := make(map[string]int) 

   words := words(data) // returns handle to data channel 
   for word := range words { 
         histogram[word]++ 
   } 
... 
} 

// generator function that produces data 
func words(data []string) <-chan string { 
   out := make(chan string) 
   go func() { 
         defer close(out) // closes channel upon fn return 
         for _, line := range data { 
               words := strings.Split(line, " ") 
               for _, word := range words { 
                     word = strings.ToLower(word) 
                     out <- word 
               } 
         } 
   }() 
   return out 
} 

```

golang.fyi/ch09/pattern4.go

在这个例子中，生成器函数声明为`func words(data []string) <-chan string`，返回一个只接收字符串元素的通道。消费者函数，在这种情况下是`main()`，接收生成器函数发出的数据，并使用`for…range`循环进行处理。

## 从多个通道选择

有时，并发程序需要同时处理多个通道的发送和接收操作。为了方便这样的努力，Go 语言支持`select`语句，它可以在多个发送和接收操作之间进行选择：

*select {*

*case <send_ or_receive_expression>:*

*default:*

*}*

`case`语句类似于`switch`语句，具有`case`子句。但是，`select`语句会选择成功的发送或接收情况之一。如果两个或更多通信情况恰好在同一时间准备就绪，将随机选择一个。当没有其他情况成功时，默认情况总是被选择。

以下代码片段更新了直方图代码，以说明`select`语句的使用。生成器函数`words`在两个通道`out`之间进行选择，以前发送数据的通道，以及作为参数传递的新通道`stopCh`，用于检测停止发送数据的中断信号：

```go
func main() { 
... 
   histogram := make(map[string]int) 
   stopCh := make(chan struct{}) // used to signal stop 

   words := words(stopCh, data) // returns handle to channel 
   for word := range words { 
         if histogram["the"] == 3 { 
               close(stopCh) 
         } 
         histogram[word]++ 
   } 
... 
} 

func words(stopCh chan struct{}, data []string) <-chan string { 
   out := make(chan string) 
   go func() { 
         defer close(out) // closes channel upon fn return 
         for _, line := range data { 
               words := strings.Split(line, " ") 
               for _, word := range words { 
                     word = strings.ToLower(word) 
                     select { 
                     case out <- word: 
                     case <-stopCh: // succeeds first when close 
                         return 
                     } 
               } 
         } 
   }() 
   return out 
} 

```

golang.fyi/ch09/pattern5.go

在前面的代码片段中，`words`生成器函数将选择成功的第一个通信操作：`out <- word`或`<-stopCh`。只要`main()`中的消费者代码继续从`out`通道接收数据，发送操作就会首先成功。但是请注意，当`main()`中的代码遇到第三个`"the"`实例时，它会关闭`stopCh`通道。当这种情况发生时，它将导致选择语句中的接收情况首先进行，从而导致 goroutine 返回。

## 通道超时

Go 并发中常见的一种习语是使用之前介绍的`select`语句来实现超时。这通过使用`select`语句在给定的时间段内等待通道操作成功来实现，使用`time`包的 API（[`golang.org/pkg/time/`](https://golang.org/pkg/time/)）。

以下代码片段显示了一个单词直方图示例的版本，如果程序计算和打印单词的时间超过 200 微秒，则会超时：

```go
func main() { 
   data := []string{...} 
   histogram := make(map[string]int) 
   done := make(chan struct{}) 

   go func() { 
         defer close(done) 
         words := words(data) // returns handle to channel 
         for word := range words { 
               histogram[word]++ 
         } 
         for k, v := range histogram { 
               fmt.Printf("%s\t(%d)\n", k, v) 
         } 
   }() 

   select { 
   case <-done: 
         fmt.Println("Done counting words!!!!") 
   case <-time.After(200 * time.Microsecond): 
         fmt.Println("Sorry, took too long to count.") 
   } 
} 
func words(data []string) <-chan string {...} 

```

golang.fyi/ch09/pattern6.go

这个直方图示例的版本引入了`done`通道，用于在处理完成时发出信号。在`select`语句中，接收操作`case``<-done:`会阻塞，直到 goroutine 关闭`done`通道。同样在`select`语句中，`time.After()`函数返回一个通道，该通道将在指定的持续时间后关闭。如果在`done`关闭之前经过了 200 微秒，那么来自`time.After()`的通道将首先关闭，导致超时情况首先成功。

# sync 包

有时，使用传统方法访问共享值比使用通道更简单和更合适。*sync*包（[`golang.org/pkg/sync/`](https://golang.org/pkg/sync/)）提供了几种同步原语，包括互斥锁和同步屏障，用于安全访问共享值，如本节所讨论的。

## 使用互斥锁进行同步

互斥锁允许通过导致 goroutine 阻塞和等待直到锁被释放来串行访问共享资源。以下示例说明了具有`Service`类型的典型代码场景，必须在准备好使用之前启动。服务启动后，代码会更新内部布尔变量`started`，以存储其当前状态：

```go
type Service struct { 
   started bool 
   stpCh   chan struct{} 
   mutex   sync.Mutex 
} 
func (s *Service) Start() { 
   s.stpCh = make(chan struct{}) 
   go func() { 
         s.mutex.Lock() 
         s.started = true 
         s.mutex.Unlock() 
         <-s.stpCh // wait to be closed. 
   }() 
} 
func (s *Service) Stop() { 
   s.mutex.Lock() 
   defer s.mutex.Unlock() 
   if s.started { 
         s.started = false 
         close(s.stpCh) 
   } 
} 
func main() { 
   s := &Service{} 
   s.Start() 
   time.Sleep(time.Second) // do some work 
   s.Stop() 
} 

```

golang.fyi/ch09/sync2.go

前面的代码片段使用了类型为`sync.Mutex`的变量`mutex`来同步访问共享变量`started`。为了使其有效工作，所有争议的区域，在这些区域中`started`变量被更新，必须使用相同的锁，连续调用`mutex.Lock()`和`mutex.Unlock()`，如代码所示。

你经常会遇到的一种习惯用法是直接在结构体中嵌入`sync.Mutex`类型，如下面的代码片段所示。这样做的效果是将`Lock()`和`Unlock()`方法作为结构体本身的一部分：

```go
type Service struct { 
   ... 
   sync.Mutex 
} 

func (s *Service) Start() { 
   s.stpCh = make(chan struct{}) 
   go func() { 
         s.Lock() 
         s.started = true 
         s.Unlock() 
         <-s.stpCh // wait to be closed. 
   }() 
} 

func (s *Service) Stop() { 
   s.Lock() 
   defer s.Unlock() 
   ... 
} 

```

golang.fyi/ch09/sync3.go

`sync`包还提供了 RWMutex（读写互斥锁），可以在有一个写入者更新共享资源的情况下使用，同时可能有多个读取者。写入者会像以前一样使用完全锁定来更新资源。然而，读取者在读取共享资源时使用`RLock()`/`RUnlock()`方法对其进行只读锁定。RWMutex 类型在下一节*同步访问复合值*中使用。

## 同步访问复合值

前面的章节讨论了在共享对简单值的访问时的并发安全性。在共享对复合类型值的访问时，必须应用相同程度的小心，比如映射和切片，因为 Go 语言没有提供这些类型的并发安全版本，如下面的例子所示：

```go
type Service struct { 
   started bool 
   stpCh   chan struct{} 
   mutex   sync.RWMutex 
   cache   map[int]string 
} 

func (s *Service) Start() { 
   ... 
   go func() { 
         s.mutex.Lock() 
         s.started = true 
         s.cache[1] = "Hello World" 
         ... 
         s.mutex.Unlock() 
         <-s.stpCh // wait to be closed. 
   }() 
} 
... 
func (s *Service) Serve(id int) { 
   s.mutex.RLock() 
   msg := s.cache[id] 
   s.mutex.RUnlock() 
   if msg != "" { 
         fmt.Println(msg) 
   } else { 
         fmt.Println("Hello, goodbye!") 
   } 
} 

```

golang.fyi/ch09/sync4.go

前面的代码使用了`sync.RWMutex`变量（参见前面的章节，*使用 Mutex Locks 进行同步*）来管理访问`cache`映射变量时的锁。代码将对`cache`变量的更新操作包装在一对方法调用`mutex.Lock()`和`mutex.Unlock()`中。然而，当从`cache`变量中读取值时，使用`mutex.RLock()`和`mutex.RUnlock()`方法来提供并发安全性。

## 使用 sync.WaitGroup 进行并发障碍

有时在使用 goroutine 时，您可能需要创建一个同步障碍，希望在继续之前等待所有正在运行的 goroutine 完成。`sync.WaitGroup`类型就是为这种情况设计的，允许多个 goroutine 在代码中的特定点会合。使用 WaitGroup 需要三件事：

+   通过 Add 方法设置组中的参与者数量

+   每个 goroutine 调用 Done 方法来表示完成

+   使用 Wait 方法阻塞，直到所有 goroutine 完成

WaitGroup 经常被用来实现工作分配模式。下面的代码片段演示了工作分配，计算`3`和`5`的倍数的和，直到`MAX`。代码使用`WaitGroup`变量`wg`创建并发障碍，等待两个 goroutine 计算数字的部分和，然后在所有 goroutine 完成后收集结果：

```go
const MAX = 1000 

func main() { 
   values := make(chan int, MAX) 
   result := make(chan int, 2) 
   var wg sync.WaitGroup 
   wg.Add(2) 
   go func() { // gen multiple of 3 & 5 values 
         for i := 1; i < MAX; i++ { 
               if (i%3) == 0 || (i%5) == 0 { 
                     values <- i // push downstream 
               } 
         } 
         close(values) 
   }() 

   work := func() { // work unit, calc partial result 
         defer wg.Done() 
         r := 0 
         for i := range values { 
               r += i 
         } 
         result <- r 
   } 

   // distribute work to two goroutines 
   go work() 
   go work() 

   wg.Wait()                    // wait for both groutines 
   total := <-result + <-result // gather partial results 
   fmt.Println("Total:", total) 
} 

```

golang.fyi/ch09/sync5.go

在前面的代码中，方法调用`wg.Add(2)`配置了`WaitGroup`变量`wg`，因为工作在两个 goroutine 之间分配。`work`函数调用`defer wg.Done()`在每次完成时将 WaitGroup 计数器减一。

最后，`wg.Wait()`方法调用会阻塞，直到其内部计数器达到零。如前所述，当两个 goroutine 的`work`运行函数都成功完成时，这将发生。当发生这种情况时，程序将解除阻塞并收集部分结果。重要的是要记住，如果内部计数器永远不达到零，`wg.Wait()`将无限期地阻塞。

# 检测竞争条件

使用带有竞争条件的并发代码进行调试可能是耗时且令人沮丧的。当竞争条件发生时，通常是不一致的，并且显示很少或没有可辨认的模式。幸运的是，自从 1.1 版本以来，Go 已经将竞争检测器作为其命令行工具链的一部分。在构建、测试、安装或运行 Go 源代码时，只需添加`-race`命令标志即可启用代码的竞争检测器。

例如，当使用`-race`标志执行源文件`golang.fyi/ch09/sync1.go`（一个带有竞争条件的代码）时，编译器的输出显示了导致竞争条件的冒犯性 goroutine 位置，如下面的输出所示：

```go
$> go run -race sync1.go 
================== 
WARNING: DATA RACE 
Read by main goroutine: 
  main.main() 
/github.com/vladimirvivien/learning-go/ch09/sync1.go:28 +0x8c 

Previous write by goroutine 5: 
  main.(*Service).Start.func1() 
/github.com/vladimirvivien/learning-go/ch09/sync1.go:13 +0x2e 

Goroutine 5 (running) created at: 
  main.(*Service).Start() 
/github.com/vladimirvivien/learning-go/ch09/sync1.go:15 +0x99 
  main.main() 
/github.com/vladimirvivien/learning-go/ch09/sync1.go:26 +0x6c 
================== 
Found 1 data race(s) 
exit status 66 

```

竞争检测器列出了共享值的并发访问的行号。它列出了*读取*操作，然后是可能同时发生*写入*操作的位置。即使在经过充分测试的代码中，代码中的竞争条件也可能被忽略，直到它随机地显现出来。如果您正在编写并发代码，强烈建议您将竞争检测器作为测试套件的一部分集成进去。

# Go 中的并行性

到目前为止，本章的讨论重点是同步并发程序。正如本章前面提到的，Go 运行时调度器会自动在可用的 OS 管理线程上多路复用和调度 goroutine。这意味着可以并行化的并发程序可以利用底层处理器核心，几乎不需要配置。例如，以下代码通过启动`workers`数量的 goroutine 来清晰地分隔其工作单元（计算 3 和 5 的倍数的和）：

```go
const MAX = 1000 
const workers = 2 

func main() { 
   values := make(chan int) 
   result := make(chan int, workers) 
   var wg sync.WaitGroup 

   go func() { // gen multiple of 3 & 5 values 
         for i := 1; i < MAX; i++ { 
               if (i%3) == 0 || (i%5) == 0 { 
                     values <- i // push downstream 
               } 
         } 
         close(values) 
   }() 

   work := func() { // work unit, calc partial result 
         defer wg.Done() 
         r := 0 
         for i := range values { 
               r += i 
         } 
         result <- r 
   } 

   //launch workers 
   wg.Add(workers) 
   for i := 0; i < workers; i++ { 
         go work() 
   } 

   wg.Wait() // wait for all groutines 
   close(result) 
   total := 0 
   // gather partial results 
   for pr := range result { 
         total += pr 
   } 
   fmt.Println("Total:", total) 
} 

```

golang.fyi/ch09/sync6.go

在多核机器上执行时，上述代码将自动并行启动每个 goroutine，使用`go work()`。默认情况下，Go 运行时调度器将为调度创建一定数量的 OS 支持的线程，该数量等于 CPU 核心数。这个数量由运行时值*GOMAXPROCS*确定。

GOMAXPROCS 值可以被显式更改以影响可用于调度的线程数。该值可以使用相同名称的命令行环境变量进行更改。GOMAXPROCS 也可以在*runtime*包的`GOMAXPROCS()`函数中进行更新（[`golang.org/pkg/runtime`](https://golang.org/pkg/runtime)）。任何一种方法都允许程序员微调将参与调度 goroutine 的线程数。

# 总结

并发在任何语言中都可能是一个复杂的话题。本章介绍了主要内容，以指导读者如何在 Go 语言中使用并发原语。本章的第一部分概述了 goroutine 的关键属性，包括*go*语句的创建和使用。接下来，本章介绍了 Go 运行时调度器的机制，以及用于在运行的 goroutine 之间进行通信的通道的概念。最后，用户被介绍了几种使用 goroutine、通道和 sync 包中的同步原语创建并发程序的并发模式。

接下来，您将介绍在 Go 中进行数据输入和输出的标准 API。
