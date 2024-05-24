# Go 编程学习手册（二）

> 原文：[`zh.annas-archive.org/md5/5FC2C8948F5CEA11C4D0D293DBBCA039`](https://zh.annas-archive.org/md5/5FC2C8948F5CEA11C4D0D293DBBCA039)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：- 第四章：数据类型

- Go 是一种强类型语言，这意味着存储（或产生）值的任何语言元素都与其关联一个类型。在本章中，读者将了解类型系统的特性，因为他们将探索语言支持的常见数据类型，如下所述：

+   - Go 类型

+   - 数值类型

+   - 布尔类型

+   - 指针

+   - 类型声明

+   - 类型转换

# - Go 类型

- 为了帮助启动关于类型的讨论，让我们来看看可用的类型。Go 实现了一个简单的类型系统，为程序员提供了直接控制内存分配和布局的能力。当程序声明一个变量时，必须发生两件事：

+   - 变量必须接收一个类型

+   - 变量也将绑定到一个值（即使没有分配任何值）

- 这使得类型系统能够分配存储已声明值所需的字节数。已声明变量的内存布局直接映射到它们声明的类型。没有类型装箱或自动类型转换发生。分配的空间实际上就是在内存中保留的空间。

- 为了证明这一事实，以下程序使用一个名为 `unsafe` 的特殊包来规避类型系统，并提取已声明变量的内存大小信息。重要的是要注意，这纯粹是为了说明，因为大多数程序通常不常使用 `unsafe` 包。

```go
package main 
import ( 
   "fmt" 
   "unsafe" 
) 

var ( 
   a uint8   = 72 
   b int32   = 240 
   c uint64  = 1234564321 
   d float32 = 12432345.232 
   e int64   = -1233453443434 
   f float64 = -1.43555622362467 
   g int16   = 32000 
   h [5]rune = [5]rune{'O', 'n', 'T', 'o', 'p'} 
) 

func main() { 
   fmt.Printf("a = %v [%T, %d bits]\n", a, a, unsafe.Sizeof(a)*8) 
   fmt.Printf("b = %v [%T, %d bits]\n", b, b, unsafe.Sizeof(b)*8) 
   fmt.Printf("c = %v [%T, %d bits]\n", c, c, unsafe.Sizeof(c)*8) 
   fmt.Printf("d = %v [%T, %d bits]\n", d, d, unsafe.Sizeof(d)*8) 
   fmt.Printf("e = %v [%T, %d bits]\n", e, e, unsafe.Sizeof(e)*8) 
   fmt.Printf("f = %v [%T, %d bits]\n", f, f, unsafe.Sizeof(f)*8) 
   fmt.Printf("g = %v [%T, %d bits]\n", g, g, unsafe.Sizeof(g)*8) 
   fmt.Printf("h = %v [%T, %d bits]\n", h, h, unsafe.Sizeof(h)*8) 
} 

```

- golang.fyi/ch04/alloc.go

- 当程序执行时，它会打印出每个已声明变量消耗的内存量（以位为单位）：

```go
$>go run alloc.go
a = 72 [uint8, 8 bits]
b = 240 [int32, 32 bits]
c = 1234564321 [uint64, 64 bits]
d = 1.2432345e+07 [float32, 32 bits]
e = -1233453443434 [int64, 64 bits]
f = -1.43555622362467 [float64, 64 bits]
g = 32000 [int16, 16 bits]
h = [79 110 84 111 112] [[5]int32, 160 bits]

```

- 从前面的输出中，我们可以看到变量 `a`（类型为 `uint8`）将使用 8 位（或 1 字节）存储，变量 `b` 将使用 32 位（或 4 字节）存储，依此类推。通过影响内存消耗的能力以及 Go 对指针类型的支持，程序员能够强力控制内存在其程序中的分配和消耗。

- 本章将介绍下表中列出的类型。它们包括基本类型，如数值、布尔和字符串：

| - **类型** | **描述** |
| --- | --- |
| - `string` | 用于存储文本值的类型。 |
| - `rune` | 用于表示字符的整数类型（int32）。 |
| - `byte`, `int`, `int8`, `int16`, `int32`, `int64`, `rune`, `uint`, `uint8`, `uint16`, `uint32`, `uint64`, `uintptr` | 用于存储整数值的类型。 |
| - `float32`, `float64` | 用于存储浮点十进制值的类型。 |
| - `complex64`, `complex128` | 可以表示具有实部和虚部的复数的类型。 |
| - `bool` | 用于布尔值的类型。 |
| - `*T`，指向类型 T 的指针 | 代表存储类型为 T 的值的内存地址的类型。 |

- Go 支持的其余类型，如下表中列出的类型，包括复合类型、接口、函数和通道。它们将在专门讨论它们的章节中进行介绍。

| - **类型** | **描述** |
| --- | --- |
| - 数组 `[n]T` | 由类型 `T` 的元素组成的具有固定大小 `n` 的有序集合。 |
| - 切片`[]T` | 由类型 `T` 的元素组成的未指定大小的有序集合。 |
| - `struct{}` | 结构是由称为字段的元素组成的复合类型（类似于对象）。 |
| - `map[K]T` | 由任意类型 `K` 的键索引的类型为 `T` 的元素的无序序列。 |
| - `interface{}` | 一组命名的函数声明，定义了其他类型可以实现的一组操作。 |
| - `func (T) R` | 代表具有给定参数类型 `T` 和返回类型 `R` 的所有函数的类型。 |
| - `chan T` | 用于内部通信通道的类型，用于发送或接收类型为 `T` 的值。 |

# - 数值类型

Go 的数字类型包括对从 8 位到 64 位的各种大小的整数和小数值的支持。 每种数字类型在内存中都有自己的布局，并且被类型系统视为独特的。 为了强制执行这一点，并且避免在不同平台上移植 Go 时出现任何混淆，数字类型的名称反映了其大小要求。 例如，类型`*int16*`表示使用 16 位进行内部存储的整数类型。 这意味着在赋值、表达式和操作中跨类型边界时，必须明确地转换数值。

以下程序并不是非常实用，因为所有值都被分配给了空白标识符。 但是，它展示了 Go 中支持的所有数字数据类型。

```go
package main 
import ( 
   "math" 
   "unsafe" 
) 

var _ int8 = 12 
var _ int16 = -400 
var _ int32 = 12022 
var _ int64 = 1 << 33 
var _ int = 3 + 1415 

var _ uint8 = 18 
var _ uint16 = 44 
var _ uint32 = 133121 
var i uint64 = 23113233 
var _ uint = 7542 
var _ byte = 255 
var _ uintptr = unsafe.Sizeof(i) 

var _ float32 = 0.5772156649 
var _ float64 = math.Pi 

var _ complex64 = 3.5 + 2i 
var _ complex128 = -5.0i 

func main() { 
   fmt.Println("all types declared!") 
} 

```

golang.fyi/ch04/nums.go

## 无符号整数类型

以下表格列出了 Go 中可以表示无符号整数及其存储要求的所有可用类型：

| **类型** | **大小** | **描述** |
| --- | --- | --- |
| `uint8` | 无符号 8 位 | 范围 0-255 |
| `uint16` | 无符号 16 位 | 范围 0-65535 |
| `uint32` | 无符号 32 位 | 范围 0-4294967295 |
| `uint64` | 无符号 64 位 | 范围 0-18446744073709551615 |
| `uint` | 实现特定 | 预先声明的类型，旨在表示 32 位或 64 位整数。 截至 Go 的 1.x 版本，`uint`表示 32 位无符号整数。 |
| `byte` | 无符号 8 位 | `unit8`类型的别名。 |
| `uintptr` | 无符号 | 一种设计用于存储底层机器体系结构的指针（内存地址）的无符号整数类型。 |

## 有符号整数类型

以下表格列出了 Go 中可以表示有符号整数及其存储要求的所有可用类型：

| **类型** | **大小** | **描述** |
| --- | --- | --- |
| `int8` | 有符号 8 位 | 范围-128 - 127 |
| `int16` | 有符号 16 位 | 范围-32768 - 32767 |
| `int32` | 有符号 32 位 | 范围-2147483648 - 2147483647 |
| `int64` | 有符号 64 位 | 范围-9223372036854775808 - 9223372036854775807 |
| `int` | 实现特定 | 预先声明的类型，旨在表示 32 位或 64 位整数。 截至 Go 的 1.x 版本，`int`表示 32 位有符号整数。 |

## 浮点类型

Go 支持以下类型来表示使用 IEEE 标准的十进制值：

| **类型** | **大小** | **描述** |
| --- | --- | --- |
| `float32` | 有符号 32 位 | 单精度浮点值的 IEEE-754 标准表示。 |
| `float64` | 有符号 64 位 | 双精度浮点值的 IEEE-754 标准表示。 |

## 复数类型

Go 还支持表示具有虚部和实部的复数，如下表所示：

| **类型** | **大小** | **描述** |
| --- | --- | --- |
| `complex64` | float32 | 以`float32`值存储的实部和虚部表示复数。 |
| `complex128` | float64 | 以`float64`值存储的实部和虚部表示复数。 |

## 数字文字

Go 支持使用数字序列和符号以及小数点的组合来自然表示整数值（如前面的例子所示）。 可选地，Go 整数文字也可以表示十六进制和八进制数字，如下面的程序所示：

```go
package main 
import "fmt" 

func main() { 
   vals := []int{ 
       1024, 
       0x0FF1CE, 
       0x8BADF00D, 
       0xBEEF, 
       0777, 
   } 
   for _, i := range vals { 
         if i == 0xBEEF { 
               fmt.Printf("Got %d\n", i) 
               break 
         } 
   } 
} 

```

golang.fyi/ch04/intslit.go

十六进制值以`0x`或（`0X`）前缀开头，而八进制值以前面示例中显示的数字 0 开头。 浮点值可以使用十进制和指数表示法表示，如下面的示例所示：

```go
package main 

import "fmt" 

func main() { 
   p := 3.1415926535 
   e := .5772156649 
   x := 7.2E-5 
   y := 1.616199e-35 
   z := .416833e32 

   fmt.Println(p, e, x, y, z) 
} 

```

golang.fyi/ch04/floats.go

前面的程序展示了 Go 中浮点文字的几种表示。 数字可以包括一个可选的指数部分，该部分由数字末尾的`e`（或`E`）表示。 例如，代码中的`1.616199e-35`表示数值 1.616199 x 10^(-35)。 最后，Go 支持用于表示复数的文字，如下面的示例所示：

```go
package main 
import "fmt" 

func main() { 
   a := -3.5 + 2i 
   fmt.Printf("%v\n", a) 
   fmt.Printf("%+g, %+g\n", real(a), imag(a)) 
} 

```

golang.fyi/ch04/complex.go

在上一个示例中，变量`a`被分配了一个具有实部和虚部的复数。虚部文字是一个浮点数，后面跟着字母`i`。请注意，Go 还提供了两个内置函数，`real()`和`imag()`，分别用于将复数分解为其实部和虚部。

# 布尔类型

在 Go 中，布尔二进制值使用`bool`类型存储。虽然`bool`类型的变量存储为 1 字节值，但它并不是数值的别名。Go 提供了两个预声明的文字，`true`和`false`，用于表示布尔值，如下例所示：

```go
package main 
import "fmt" 

func main() { 
   var readyToGo bool = false 
   if !readyToGo { 
       fmt.Println("Come on") 
   } else { 
       fmt.Println("Let's go!") 
   } 
} 

```

golang.fyi/ch04/bool.go

# 符文和字符串类型

为了开始我们关于`rune`和`string`类型的讨论，需要一些背景知识。Go 可以将其源代码中的字符和字符串文字常量视为 Unicode。这是一个全球标准，其目标是通过为每个字符分配一个数值（称为代码点）来记录已知书写系统的符号。

默认情况下，Go 本身支持 UTF-8，这是一种有效的编码和存储 Unicode 数值的方式。这就是继续这个主题所需的所有背景。不会讨论更多细节，因为这超出了本书的范围。 

## 符文

那么，`rune`类型与 Unicode 有什么关系呢？`rune`是`int32`类型的别名。它专门用于存储以 UTF-8 编码的 Unicode 整数值。让我们在下面的程序中看一些`rune`文字：

！符文

golang.fyi/ch04/rune.go

上一个程序中的每个变量都存储一个 Unicode 字符作为`rune`值。在 Go 中，`rune`可以被指定为由单引号括起来的字符串文字常量。文字可以是以下之一：

+   可打印字符（如变量`char1`、`char2`和`char3`所示）

+   用反斜杠转义的单个字符，用于不可打印的控制值，如制表符、换行符、换行符等

+   `\u`后直接跟 Unicode 值（`\u0369`）

+   `\x`后跟两个十六进制数字

+   反斜杠后跟三个八进制数字（`\045`）

无论单引号内的`rune`文字值如何，编译器都会编译并分配一个整数值，如上一个变量的打印输出所示：

```go
$>go run runes.go
8
9
10
632
2438
35486
873
250
37 

```

## 字符串

在 Go 中，字符串被实现为不可变字节值的切片。一旦将字符串值分配给变量，该字符串的值就不会改变。通常，字符串值被表示为双引号括起来的常量文字，如下例所示：

！字符串

golang.fyi/ch04/string.go

上一个片段显示了变量`txt`被分配了一个包含七个字符的字符串文字，其中包括两个嵌入的中文字符。正如前面提到的，Go 编译器会自动将字符串文字值解释为 Unicode 字符，并使用 UTF-8 对其进行编码。这意味着在底层，每个文字字符都被存储为`rune`，并且可能需要多于一个字节的存储空间来存储每个可见字符。事实上，当程序执行时，它打印出`txt`的长度为`11`，而不是预期的字符串的七个字符，这考虑到了用于中文符号的额外字节。

## 解释和原始字符串文字

以下片段（来自上一个示例）包括分配给变量`txt2`和`txt3`的两个字符串文字。正如你所看到的，这两个文字具有完全相同的内容，然而，编译器会对它们进行不同的处理：

```go
var ( 
   txt2 = "\u6C34\x20brings\x20\x6c\x69\x66\x65." 
   txt3 = ` 
   \u6C34\x20 
   brings\x20 
   \x6c\x69\x66\x65\. 
   ` 
) 

```

golang.fyi/ch04/string.go

变量`txt2`分配的文字值用双引号括起来。这被称为解释字符串。解释字符串可以包含普通的可打印字符，也可以包含反斜杠转义值，这些值被解析并解释为`rune`文字。因此，当打印`txt2`时，转义值被翻译为以下字符串：

![解释和原始字符串文字](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/B03676-04-bingslife-snippet.jpg)

在解释字符串中，每个符号对应一个转义值或可打印符号，如下表所总结的：

| ![解释和原始字符串文字](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/B03676-water-chinese.jpg) | **<space>** | **带来** | **<space>** | **生命** | . |
| --- | --- | --- | --- | --- | --- |
| \u6C34 | \x20 | 带来 | \x20 | \x6c\x69\x66\x65 | . |

另一方面，变量`txt3`分配的文字值被反引号字符`` ` ``包围。这在Go中创建了所谓的原始字符串。原始字符串值未被解释，其中转义序列被忽略，所有有效字符都按照它们在文本中出现的方式进行编码。

打印`txt3`变量时，将产生以下输出：

```go

\u6C34\x20 brings\x20\x6c\x69\x66\x65。

```

注意，打印的字符串包含所有反斜杠转义值，就像它们出现在原始字符串文本中一样。未解释的字符串文本是在不破坏语法的情况下将大型多行文本内容嵌入源代码主体中的一种有效方式。

# 指针

在 Go 中，当一段数据存储在内存中时，可以直接访问该数据的值，也可以使用指针来引用存储数据位置的内存地址。与其他 C 家族语言一样，Go 中的指针提供了一种间接的方式，让程序员可以更高效地处理数据，而不必每次需要时都复制实际数据值。

然而，与 C 不同，Go 运行时在运行时管理指针的控制。程序员不能将任意整数值添加到指针中生成新的指针地址（一种称为指针算术的做法）。一旦一个指针引用了内存区域，该区域中的数据将保持可访问状态，直到不再有任何指针变量引用。在那时，未引用的值将变得可供垃圾收集。

## 指针类型

类似于 C/C++，Go 使用`*`运算符指定类型为指针。以下代码片段显示了几个具有不同底层类型的指针：

```go

package main
import "fmt"
var valPtr *float32
var countPtr *int
var person *struct {
   name string
   age  int
}
var matrix *[1024]int
var row []*int64
func main() {
   fmt.Println(valPtr, countPtr, person, matrix, row)
}

```

[golang.fyi/ch04/pointers.go](https://golang.fyi/ch04/pointers.go)

给定类型`T`的变量，Go 使用表达式`*T`作为其指针类型。类型系统将`T`和`*T`视为不同且不可互换。指针的零值，当它不指向任何内容时，是地址 0，表示为*常数* nil。

## 地址运算符

指针值只能分配给它们声明类型的地址。在 Go 中，一种方法是使用地址运算符`&`（和号）获取变量的地址值，如下例所示：

```go

package main
import "fmt"
func main() {
   var a int = 1024
   var aptr *int = &a
   fmt.Printf("a=%v\n", a)
   fmt.Printf("aptr=%v\n", aptr)
}

```

[golang.fyi/ch04/pointers.go](https://golang.fyi/ch04/pointers.go)

变量`aptr`，指针类型为`*int`，使用表达式`&a`进行初始化，并将变量`a`的地址值分配给它，如下所示：

```go

var a int = 1024
var aptr *int = &a

```

虽然变量`a`存储实际值，我们说`aptr`指向`a`。以下显示了程序输出，其中变量`a`的值和其内存位置被分配给`aptr`：

```go

a=1024
aptr=0xc208000150

```

分配的地址值将始终相同（始终指向`a`），无论在代码中何处访问`aptr`。值得注意的是，Go 不允许在数字、字符串和布尔类型的文本常量中使用地址运算符。因此，以下代码不会编译：

```go

var aptr *int = &1024
fmt.Printf("a ptr1 = %v\n", aptr)

```

然而，有一个语法例外情况，当用文本常量初始化结构体和数组等复合类型时。以下程序说明了这样的情况：

```go

package main
import "fmt"
func main() {
   structPtr := &struct{ x, y int }{44, 55}
   pairPtr := &[2]string{"A", "B"}
   fmt.Printf("struct=%#v, type=%T\n", structPtr, structPtr)
   fmt.Printf("pairPtr=%#v, type=%T\n", pairPtr, pairPtr)
}

```

[golang.fyi/ch04/address2.go](https://golang.fyi/ch04/address2.go)

在前面的代码片段中，地址运算符直接与复合字面量`&struct{ x, y int }{44, 55}`和`&[2]string{"A", "B"}`一起使用，返回指针类型`*struct { x int; y int }`和`*[2]string`。这是一种语法糖，消除了将值分配给变量，然后检索其分配地址的中间步骤。

## new()函数

使用内置函数*new(<type>)*也可以用来初始化指针值。它首先为指定类型的零值分配适当的内存。然后函数返回新创建值的地址。下面的程序使用`new()`函数初始化变量`intptr`和`p`：

```go

package main

import "fmt"
func main() {
   intptr := new(int)
   *intptr = 44
   p := new(struct{ first, last string })
   p.first = "Samuel"
   p.last = "Pierre"
   fmt.Printf("Value %d, type %T\n", *intptr, intptr)
   fmt.Printf("Person %+v\n", p)
}

```

golang.fyi/ch04/newptr.go

变量`intptr`初始化为`*int`，`p`初始化为`*struct{first, last string}`。一旦初始化，两个值在代码中稍后会相应更新。当实际值在初始化时不可用时，您可以使用`new()`函数以零值初始化指针变量。

## 指针间接引用 - 访问引用的值

如果你只有地址，你可以通过将`*`运算符应用到指针值本身（或解引用）来访问它指向的值。以下程序在函数`double()`和`cap()`中演示了这一理念：

```go

package main
import (
   "fmt"
   "strings"
)
func main() {
   a := 3
   double(&a)
   fmt.Println(a)
   p := &struct{ first, last string }{"Max", "Planck"}
   cap(p)
   fmt.Println(p)
}
func double(x *int) {
   *x = *x * 2
}
func cap(p *struct{ first, last string }) {
   p.first = strings.ToUpper(p.first)
   p.last = strings.ToUpper(p.last)
}

```

golang.fyi/ch04/derefptr.go

在前面的代码中，在函数`double()`中，表达式`*x = *x * 2`可以分解如下以了解其工作原理：

| **表达式** | **步骤** |
| --- | --- |

```go

*x * 2

```

| `x`是`*int`类型的原始表达式。 |
| --- |

```go

*(*x) * 2

```

| 通过对地址值应用`*`进行指针解引用。 |
| --- |

```go

3 * 2 = 6

```

| `*(*x) = 3`的解引用值。 |
| --- |

```go

*(*x) = 6

```

| 此表达式的右侧解引用了`x`的值。它被更新为结果 6。 |
| --- |

在函数`cap()`中，使用类似的方法来访问和更新类型为`struct{first, last string}`的复合变量`p`中的字段。然而，处理复合类型时，这种习惯用法更加宽容。不需要写`*p.first`来访问指针的字段值。我们可以去掉`*`，直接使用`p.first = strings.ToUpper(p.first)`。

# 类型声明

在 Go 语言中，可以将类型绑定到标识符以创建一个新的命名类型，可以在需要该类型的任何地方引用和使用它。声明类型的通用格式如下：

*type <名称标识符> <基础类型名称>*

类型声明以关键字`type`开始，后跟*名称标识符*和现有*基础类型*的名称。基础类型可以是内置命名类型，如数字类型之一，布尔值，或字符串类型，如下面的类型声明片段所示：

```go

type truth bool
type quart float64
type gallon float64
type node string

```

### 注意

类型声明也可以使用复合*类型字面值*作为其基础类型。复合类型包括数组、切片、映射和结构体。本节侧重于非复合类型。有关复合类型的更多详细信息，请参阅第七章*复合类型*。

以下示例说明了命名类型在其最基本形式中的工作方式。示例中的代码将温度值转换。每个温度单位都由一个声明类型表示，包括`fahrenheit`、`celsius`和`kelvin`。

```go

package main
import "fmt"
type fahrenheit float64
type celsius float64
type kelvin float64
func fharToCel(f fahrenheit) celsius {
   return celsius((f - 32) * 5 / 9)
}
func fharToKel(f fahrenheit) celsius {
   return celsius((f-32)*5/9 + 273.15)
}
func celToFahr(c celsius) fahrenheit {
   return fahrenheit(c*5/9 + 32)
}
func celToKel(c celsius) kelvin {
   return kelvin(c + 273.15)
}
func main() {
   var c celsius = 32.0
   f := fahrenheit(122)
   fmt.Printf("%.2f \u00b0C = %.2f \u00b0K\n", c, celToKel(c))
   fmt.Printf("%.2f \u00b0F = %.2f \u00b0C\n", f, fharToCel(f))
}

```

golang.fyi/ch04/typedef.go

在上述代码片段中，新声明的类型都基于基础的内置数值类型`float64`。一旦新类型已声明，它可以被赋值给变量，并像其基础类型一样参与表达式。新声明的类型将具有相同的零值，并且可以与其基础类型进行相互转换。

# 类型转换

通常情况下，Go 认为每种类型都是不同的。这意味着在正常情况下，不同类型的值在赋值、函数参数和表达式上下文中不可互换。这对于内置类型和声明的类型都适用。例如，以下代码会因类型不匹配而导致构建错误：

```go

package main
import "fmt"
type signal int
func main() {
   var count int32
   var actual int
   var test int64 = actual + count
   var sig signal
   var event int = sig
   fmt.Println(test)
   fmt.Println(event)
}

```

golang.fyi/ch04/type_conv.go

表达式`actual + count`会导致构建时错误，因为两个变量的类型不同。即使变量`actual`和`count`都是数值类型，并且`int32`和`int`具有相同的内存表示，编译器仍然会拒绝这个表达式。

声明的命名类型及其基础类型也是如此。编译器将拒绝赋值`var event int = sig`，因为类型`signal`被视为与类型`int`不同。即使`signal`使用`int`作为其基础类型，这也是正确的。

要跨越类型边界，Go 支持一种类型转换表达式，用于将一个类型的值转换为另一个类型。类型转换使用以下格式进行：

*<目标类型>(<值或表达式>)*

以下代码片段通过将变量转换为适当的类型来修复先前的示例：

```go

type signal int
func main() {
   var count int32
   var actual int
   var test int32 = int32(actual) + count
   var sig signal
   var event int = int(sig)
}

```

golang.fyi/ch04/type_conv2.go

请注意，在上述代码中，赋值表达式`var test int32 = int32(actual) + count`将变量`actual`转换为相应的类型，以匹配表达式的其余部分。类似地，表达式`var event int = int(sig)`将变量`sig`转换为匹配赋值中的目标类型`int`。

转换表达式通过显式更改封闭值的类型来满足赋值。显然，并非所有类型都可以互相转换。以下表总结了类型转换适合和允许的常见情况： 

| **描述** | **代码** |
| --- | --- |
| 目标类型和转换值都是简单的数值类型。 |

```go

var i int
var i2 int32 = int32(i)
var re float64 = float64(i +   int(i2))

```

| 目标类型和转换值都是复数数值类型。 |
| --- |

```go

var cn64 complex64
var cn128 complex128 =   complex128(cn64)

```

| 目标类型和转换值具有相同的基础类型。 |
| --- |

```go

type signal int
var sig signal
var event int = int(sig)

```

| 目标类型是字符串，转换值是有效的整数类型。 |
| --- |

```go

a := string(72)
b := string(int32(101))
c := string(rune(108))

```

| 目标类型是字符串，转换值是字节片、int32 或符文。 |
| --- |

```go

msg0 := string([]byte{'H','i'})
msg1 := string([]rune{'Y','o','u','!'})

```

| 目标类型是字节、int32 或符文值的片，转换值是一个字符串。 |
| --- |


```go

data0 := []byte("Hello")
data0 := []int32("World!")

```

此外，当目标类型和转换值是引用相同类型的指针时，转换规则也适用。除了上表中的这些情况外，Go 类型不能被显式转换。任何尝试这样做都将导致编译错误。

# 总结

本章向读者介绍了 Go 类型系统。本章以类型概述开篇，深入全面地探讨了基本内置类型，如数字、布尔、字符串和指针类型。讨论继续暴露读者对其他重要主题，如命名类型定义。本章以类型转换的机制结束。在接下来的章节中，您将有机会了解其他类型，如复合类型、函数类型和接口类型。


# 第五章：Go 中的函数

Go 的语法*绝活*之一是通过支持高阶函数，就像在 Python 或 Ruby 等动态语言中一样。正如我们将在本章中看到的，函数也是一个具有值的类型实体，可以赋值给变量。在本章中，我们将探讨 Go 中的函数，涵盖以下主题：

+   Go 函数

+   传递参数值

+   匿名函数和闭包

+   高阶函数

+   错误信号处理

+   延迟函数调用

+   函数恐慌和恢复

# Go 函数

在 Go 中，函数是第一类的、有类型的编程元素。声明的函数文字始终具有类型和值（定义的函数本身），并且可以选择地绑定到命名标识符。因为函数可以被用作数据，它们可以被分配给变量或作为其他函数的参数传递。

## 函数声明

在 Go 中声明函数的一般形式如下图所示。这种规范形式用于声明命名和匿名函数。

![函数声明](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/B03676_05_01.jpg)

在 Go 中，最常见的函数定义形式包括函数文字中的函数分配标识符。为了说明这一点，下表显示了几个程序的源代码，其中定义了具有不同参数和返回类型组合的命名函数。

| **代码** | **描述** |
| --- | --- |

|

```go
package main import (
  "fmt"
  "math"
)func printPi() {
  fmt.Printf("printPi()
    %v\n", math.Pi)
} func main() {
  printPi() }               ("fmt" "math" ) func
printPi() {
  fmt.Printf("printPi()
    %v\n", math.Pi)
}
func main() { printPi() }
```

golang.fyi/ch05/func0.go | 一个名为`printPi`的函数。它不接受参数，也不返回任何值。请注意，当没有要返回的内容时，`return`语句是可选的。|

|

```go
package main   
import "fmt"   

func avogadro() float64 {   
   return 6.02214129e23   
}   

func main() {   
   fmt.Printf("avogadro()
   = %e 1/mol\n",   
   avogadro())   
}   

```

golang.fyi/ch05/func1.go | 一个名为`avogadro`的函数。它不接受参数，但返回一个`float64`类型的值。请注意，当返回值在函数签名中声明时，`return`语句是必需的。|

|

```go
package main   
import "fmt"    
func fib(n int) {   
  fmt.Printf("fib(%d):
    [", n)
  var p0, p1 uint64 = 0,
    1   
  fmt.Printf("%d %d ",
    p0, p1)   
  for i := 2; i <= n; i++
  {   
    p0, p1 = p1, p0+p1
    fmt.Printf("%d ",p1)
  }   
  fmt.Println("]")   
}   
func main() {   
  fib(41)   
}
```

golang.fyi/ch05/func2.go | 这定义了`fib`函数。它接受类型为`int`的参数`n`，并打印出最多`n`的斐波那契数列。同样，没有要返回的内容，因此省略了`return`语句。|

|

```go
package main   
import (   
  "fmt"   
  "math"   
)    
func isPrime(n int) bool {   
  lim :=
  int(math.Sqrt
  (float64(n)))
  for p := 2; p <= lim;
  p++ {
    if (n % p) == 0 {   
      return false   
    }  }   
  return true   
}   
func main() {   
  prime := 37
  fmt.Printf
  ("isPrime(%d)  =
  %v\n", prime,
  isPrime(prime))
}
```

golang.fyi/ch05/func3.go | 最后一个示例定义了`isPrime`函数。它接受一个`int`类型的参数，并返回一个`bool`类型的值。由于函数声明要返回一个`bool`类型的值，因此执行流程中的最后一个逻辑语句必须是一个`return`语句，返回声明类型的值。|

### 注意

**函数签名**

指定的参数类型、结果类型和这些类型声明的顺序被称为函数的签名。这是另一个帮助识别函数的独特特征。两个函数可能具有相同数量的参数和结果值；然而，如果这些元素的顺序不同，那么这些函数就具有不同的签名。

## 函数类型

通常，函数文字中声明的名称标识符用于使用调用表达式调用函数，其中函数标识符后面跟着参数列表。这是我们迄今为止在整本书中看到的，并且在下面的示例中调用`fib`函数中有所说明：

```go
func main() { 
   fib(41) 
} 

```

然而，当函数的标识符出现时，没有括号，它被视为一个具有类型和值的常规变量，如下面的程序所示：

```go
package main 
import "fmt" 

func add(op0 int, op1 int) int { 
   return op0 + op1 
} 

func sub(op0, op1 int) int { 
   return op0 - op1 
} 

func main() { 
   var opAdd func(int, int) int = add 
   opSub := sub 
   fmt.Printf("op0(12,44)=%d\n", opAdd(12, 44)) 
   fmt.Printf("sub(99,13)=%d\n", opSub(99, 13)) 
}  

```

golang.fyi/ch05/functype.go

函数的类型由其签名确定。当具有相同数量的参数、相同类型和相同顺序的参数时，函数被认为是相同类型的。在前面的示例中，`opAdd`变量被声明为`func (int, int) int`类型。这与声明的`add`和`sub`函数相同。因此，`opAdd`变量被赋予`add`函数变量。这允许像调用`add`函数一样调用`opAdd`。

对于`opAdd`变量也是同样的操作。它被赋予了由函数标识符`add`和类型`func(int, int)`表示的值。因此，`opAdd(3,5)`调用了第一个函数，返回了加法的结果。

## 可变参数

函数的最后一个参数可以通过在参数类型之前添加省略号(`…`)来声明为**可变参数**（**可变长度参数**）。这表示在调用函数时可以传递零个或多个该类型的值。

以下示例实现了两个接受可变参数的函数。第一个函数计算传入值的平均值，第二个函数对传入的数字进行求和：

```go
package main 
import "fmt" 

func avg(nums ...float64) float64 { 
   n := len(nums) 
   t := 0.0 
   for _, v := range nums { 
         t += v 
   } 
   return t / float64(n) 
} 

func sum(nums ...float64) float64 { 
   var sum float64 
   for _, v := range nums { 
         sum += v 
   } 
   return sum 
} 

func main() { 
   fmt.Printf("avg([1, 2.5, 3.75]) =%.2f\n", avg(1, 2.5, 3.75)) 
   points := []float64{9, 4, 3.7, 7.1, 7.9, 9.2, 10} 
   fmt.Printf("sum(%v) = %.2f\n", points, sum(points...)) 
} 

```

golang.fyi/ch05/funcvariadic.go

编译器在前述两个函数中将可变参数解析为`[]float64`类型的切片。然后可以使用切片表达式来访问参数值，就像前面的例子中所示。要调用具有可变参数的函数，只需提供一个逗号分隔的值列表，与指定类型匹配，如下面的代码片段所示：

```go
fmt.Printf("avg([1, 2.5, 3.75]) =%.2f\n", avg(1, 2.5, 3.75)))  

```

当没有提供参数时，函数接收到一个空切片。敏锐的读者可能会想，“是否可以将现有值的切片作为可变参数传递进去？”幸运的是，Go 提供了一个简单的习语来处理这种情况。让我们来看下面代码片段中对`sum`函数的调用：

```go
points := []float64{9, 4, 3.7, 7.1, 7.9, 9.2, 10} 
fmt.Printf("sum(%v) = %f\n", points, sum(points...))  

```

声明了一个浮点数值的切片，并将其存储在变量`points`中。通过在`sum(points...)`函数调用中的参数中添加省略号，可以将切片作为可变参数传递。

## 函数结果参数

Go 函数可以定义返回一个或多个结果值。到目前为止，在本书中，我们遇到的大多数函数都被定义为返回单个结果值。一般来说，一个函数能够返回一个由逗号分隔的不同类型的结果值列表（参见前一节，*函数声明*）。

为了说明这个概念，让我们来看下面的简单程序，它定义了一个实现欧几里得除法算法的函数（参见[`en.wikipedia.org/wiki/Division_algorithm`](http://en.wikipedia.org/wiki/Division_algorithm)）。`div`函数返回商和余数作为其结果：

```go
package main 
import "fmt" 

func div(op0, op1 int) (int, int) { 
   r := op0 
   q := 0 
   for r >= op1 { 
         q++ 
         r = r - op1 
   } 
   return q, r 
} 

func main() { 
   q, r := div(71, 5) 
   fmt.Printf("div(71,5) -> q = %d, r = %d\n", q, r) 
} 

```

golang.fyi/ch05/funcret0.go

`**return**`关键字后面跟着与函数签名中声明的结果匹配的结果值的数量。在前面的例子中，`div`函数的签名指定了两个`int`值作为结果值返回。在内部，函数定义了`int`变量`p`和`r`，它们在函数完成时作为结果值返回。这些返回的值必须与函数签名中定义的类型匹配，否则会出现编译错误。

具有多个结果值的函数必须在适当的上下文中调用：

+   它们必须分别分配给相同类型的标识符列表

+   它们只能包含在期望相同数量的返回值的表达式中

这在下面的源代码片段中有所说明：

```go
q, r := div(71, 5) 
fmt.Printf("div(71,5) -> q = %d, r = %d\n", q, r) 

```

### 命名结果参数

一般来说，函数签名的结果列表可以使用变量标识符及其类型来指定。使用命名标识符时，它们被传递给函数作为常规声明的变量，并且可以根据需要访问和修改。在遇到`return`语句时，将返回最后分配的结果值。这在下面的源代码片段中有所说明，它是对前一个程序的重写：

```go
func div(dvdn, dvsr int) (q, r int) { 
   r = dvdn 
   for r >= dvsr { 
         q++ 
         r = r - dvsr 
   } 
   return 
} 

```

golang.fyi/ch05/funcret1.go

请注意`return`语句是裸的；它省略了所有标识符。如前所述，`q`和`r`中分配的值将返回给调用者。为了可读性、一致性或风格，您可以选择不使用裸`return`语句。可以像以前一样将标识符的名称与`return`语句（例如`return q, r`）结合使用是完全合法的。

# 传递参数值

在 Go 中，所有传递给函数的参数都是按值传递的。这意味着在被调用的函数内部创建了传递值的本地副本。没有固有的按引用传递参数值的概念。以下代码通过修改`dbl`函数内的传递参数`val`的值来说明这种机制：

```go
package main 
import ( 
   "fmt" 
   "math" 
) 

func dbl(val float64) { 
   val = 2 * val // update param 
   fmt.Printf("dbl()=%.5f\n", val) 
} 

func main() { 
   p := math.Pi 
   fmt.Printf("before dbl() p = %.5f\n", p) 
   dbl(p) 
   fmt.Printf("after dbl() p = %.5f\n", p) 
} 

```

golang.fyi/ch05/funcpassbyval.go

当程序运行时，它产生以下输出，记录了传递给`dbl`函数之前`p`变量的状态。更新是在`dbl`函数内部对传递参数变量进行本地更新的，最后是在调用`dbl`函数之后的`p`变量的值：

```go
$> go run funcpassbyval.go
before dbl() p = 3.14159
dbl()=6.28319
after dbl() p = 3.14159

```

前面的输出显示，分配给变量`p`的原始值保持不变，即使它被传递给一个似乎在内部更新其值的函数。这是因为`dbl`函数中的`val`参数接收传递参数的本地副本。

## 实现按引用传递

虽然按值传递在许多情况下是合适的，但重要的是要注意，Go 可以使用指针参数值实现按引用传递的语义。这允许被调用的函数超出其词法范围并更改指针参数引用的位置存储的值，就像在以下示例中的`half`函数中所做的那样：

```go
package main 
import "fmt" 

func half(val *float64) { 
   fmt.Printf("call half(%f)\n", *val) 
   *val = *val / 2 
} 

func main() { 
   num := 2.807770 
   fmt.Printf("num=%f\n", num) 
   half(&num) 
   fmt.Printf("half(num)=%f\n", num) 
} 

```

golang.fyi/ch05/funcpassbyref.go

在前面的例子中，在`main()`中对`half(&num)`函数的调用会直接更新其`num`参数引用的原始值。因此，当代码执行时，它显示了`num`的原始值以及调用`half`函数后的值：

```go
$> go run funcpassbyref.go
num=2.807770
call half(2.807770)
half(num)=1.403885

```

正如前面所述，Go 函数参数是按值传递的。即使函数以指针值作为参数，这也是正确的。Go 仍然创建并传递指针值的本地副本。在前面的例子中，`half`函数接收通过`val`参数传递的指针值的副本。代码使用指针操作符（`*`）来取消引用和就地操作`val`引用的值。当`half`函数退出并超出范围时，通过调用`main`函数可以访问其更改。

## 匿名函数和闭包

函数可以被写成没有命名标识符的文字。这些被称为匿名函数，可以被分配给一个变量，以便稍后调用，就像下面的例子所示：

```go
package main 
import "fmt" 

var ( 
   mul = func(op0, op1 int) int { 
         return op0 * op1 
   } 

   sqr = func(val int) int { 
         return mul(val, val) 
   } 
) 

func main() { 
   fmt.Printf("mul(25,7) = %d\n", mul(25, 7)) 
   fmt.Printf("sqr(13) = %d\n", sqr(13)) 
}  

```

golang.fyi/ch05/funcs.go

前面的程序显示了两个匿名函数声明并绑定到`mul`和`sqr`变量。在这两种情况下，函数都接受参数并返回一个值。稍后在`main()`中，变量被用来调用与它们绑定的函数代码。

## 调用匿名函数文字

值得注意的是，匿名函数不一定要绑定到标识符。函数文字可以在现场评估为返回函数结果的表达式。通过在括号中结束函数文字的方式，传递参数值的列表，如下面的程序所示：

```go
package main 
import "fmt" 

func main() { 
   fmt.Printf( 
         "94 (°F) = %.2f (°C)\n", 
         func(f float64) float64 { 
               return (f - 32.0) * (5.0 / 9.0) 
         }(94), 
   ) 
} 

```

golang.fyi/ch05/funcs.go

文字格式不仅定义了匿名函数，还调用了它。例如，在以下片段（来自前面的程序）中，匿名函数文字被嵌套为`fmt.Printf()`的参数。函数本身被定义为接受一个参数并返回`float64`类型的值。

```go
fmt.Printf( 
   "94 (°F) = %.2f (°C)\n", 
   func(f float64) float64 { 
         return (f - 32.0) * (5.0 / 9.0) 
   }(94), 
) 

```

由于函数文字以括号括起的参数列表结束，因此该函数被调用为表达式。

## 闭包

Go 函数文字是闭包。这意味着它们在封闭的代码块之外声明的非局部变量具有词法可见性。以下示例说明了这一事实：

```go
package main 
import ( 
   "fmt" 
   "math" 
) 

func main() { 
   for i := 0.0; i < 360.0; i += 45.0 { 
         rad := func() float64 { 
               return i * math.Pi / 180 
         }() 
         fmt.Printf("%.2f Deg = %.2f Rad\n", i, rad) 
   } 
} 

```

github.com/vladimirvivien/learning-go/ch05/funcs.go

在上一个程序中，函数文字代码块`func() float64 {return deg * math.Pi / 180}()`被定义为将度数转换为弧度的表达式。在每次循环迭代时，闭包在封闭的函数文字和外部非局部变量`i`之间形成。这提供了一种更简单的习语，其中函数自然地访问非局部值，而不需要诸如指针之类的其他手段。

### 注意

在 Go 中，词法闭包的值可以在创建闭包的外部函数已经超出范围之后仍然保持与它们的闭包绑定。垃圾收集器将在这些闭合值变得无限制时处理清理工作。

# 高阶函数

我们已经确定 Go 函数是绑定到类型的值。因此，Go 函数可以接受另一个函数作为参数，并且还可以返回一个函数作为结果值，这应该不足为奇。这描述了一个被称为高阶函数的概念，这是从数学中采用的概念。虽然诸如`struct`之类的类型让程序员抽象数据，但高阶函数提供了一种机制，用于封装和抽象可以组合在一起形成更复杂行为的行为。

为了使这个概念更清晰，让我们来看一下下面的程序，它使用了一个高阶函数`apply`来做三件事。它接受一个整数切片和一个函数作为参数。它将指定的函数应用于切片中的每个元素。最后，`apply`函数还返回一个函数作为其结果：

```go
package main 
import "fmt" 

func apply(nums []int, f func(int) int) func() { 
   for i, v := range nums { 
         nums[i] = f(v) 
   } 
   return func() { 
         fmt.Println(nums) 
   } 
} 

func main() { 
   nums := []int{4, 32, 11, 77, 556, 3, 19, 88, 422} 
   result := apply(nums, func(i int) int { 
         return i / 2 
   }) 
   result() 
} 

```

golang.fyi/ch05/funchighorder.go

在程序中，`apply`函数被调用，并使用匿名函数对切片中的每个元素进行减半，如下面的代码段所示：

```go
nums := []int{4, 32, 11, 77, 556, 3, 19, 88, 422} 
result := apply(nums, func(i int) int { 
   return i / 2 
}) 
result() 

```

作为高阶函数，`apply`抽象了可以由任何类型为`func(i int) int`的函数提供的转换逻辑，如下所示。由于`apply`函数返回一个函数，因此变量`result`可以像前面的代码段中所示那样被调用。

当您探索本书和 Go 语言时，您将继续遇到高阶函数的使用。这是一种在标准库中广泛使用的习语。您还将发现高阶函数在一些并发模式中被用于分发工作负载（参见第九章，“并发性”）。

# 错误信号和处理

在这一点上，让我们来看看如何在进行函数调用时惯用地发出和处理错误。如果您曾经使用过 Python、Java 或 C#等语言，您可能熟悉在不良状态出现时通过抛出异常来中断执行代码流的做法。

正如我们将在本节中探讨的，Go 对错误信号和错误处理采用了简化的方法，这使得程序员需要在调用函数返回后立即处理可能的错误。Go 不鼓励通过在执行程序中不加区别地中断执行来短路执行程序，并希望异常能够在调用堆栈的更高位置得到适当处理的概念。在 Go 中，信号错误的传统方式是在函数执行过程中出现问题时返回`error`类型的值。因此，让我们更仔细地看看这是如何完成的。

## 错误信号

为了更好地理解前面段落中所描述的内容，让我们从一个例子开始。以下源代码实现了一个变位词程序，如 Jon Bentley 的流行书籍《编程珠玑》（第二版）中的第 2 列所述。该代码读取一个字典文件（`dict.txt`），并将所有具有相同变位词的单词分组。如果代码不太容易理解，请参阅[golang.fyi/ch05/anagram1.go](http://learning.golang.fyi/ch05/anagram1.go)以获取程序各部分如何工作的注释解释。

```go
package main 

import ( 
   "bufio" 
   "bytes" 
   "fmt" 
   "os" 
   "errors" 
) 

// sorts letters in a word (i.e. "morning" -> "gimnnor") 
func sortRunes(str string) string { 
   runes := bytes.Runes([]byte(str)) 
   var temp rune 
   for i := 0; i < len(runes); i++ { 
         for j := i + 1; j < len(runes); j++ { 
               if runes[j] < runes[i] { 
                     temp = runes[i] 
                     runes[i], runes[j] = runes[j], temp 
               } 

         } 
   } 
   return string(runes) 
} 

// load loads content of file fname into memory as []string 
func load(fname string) ([]string, error) { 
   if fname == "" { 
         return nil, errors.New( 
               "Dictionary file name cannot be empty.")  
   } 

   file, err := os.Open(fname) 
   if err != nil { 
         return nil, err 
   } 
   defer file.Close() 

   var lines []string 
   scanner := bufio.NewScanner(file) 
   scanner.Split(bufio.ScanLines) 
   for scanner.Scan() { 
         lines = append(lines, scanner.Text()) 
   } 
   return lines, scanner.Err() 
} 

func main() { 
   words, err := load("dict.txt")       
   if err != nil { 
         fmt.Println("Unable to load file:", err) 
         os.Exit(1) 
   } 

      anagrams := make(map[string][]string) 
   for _, word := range words { 
         wordSig := sortRunes(word) 
         anagrams[wordSig] = append(anagrams[wordSig], word) 
   } 

   for k, v := range anagrams { 
         fmt.Println(k, "->", v) 
   } 
} 

```

golang.fyiy/ch05/anagram1.go

同样，如果您想要更详细的解释前面的程序，请查看之前提供的链接。这里的重点是前面程序中使用的错误信号。作为惯例，Go 代码使用内置类型`error`来表示在函数执行过程中发生错误。因此，函数必须返回一个`error`类型的值，以指示给其调用者发生了错误。这在前面示例中的`load`函数的以下片段中有所说明：

```go
func load(fname string) ([]string, error) { 
   if fname == "" { 
       return nil, errors.New( 
         "Dictionary file name cannot be empty.")  
   } 

   file, err := os.Open(fname) 
   if err != nil { 
         return nil, err 
   } 
   ... 
} 

```

请注意，`load`函数返回多个结果参数。一个是预期值，本例中为`[]string`，另一个是错误值。惯用的 Go 规定程序员应该返回一个非 nil 值作为`error`类型的结果，以指示在函数执行过程中发生了异常情况。在前面的片段中，`load`函数在两种可能的情况下向其调用者发出错误发生的信号：

+   当预期的文件名（`fname`）为空时

+   当调用`os.Open()`失败时（例如，权限错误，或其他情况）

在第一种情况下，当未提供文件名时，代码使用`errors.New()`返回一个`error`类型的值来退出函数。在第二种情况下，`os.Open`函数返回一个代表文件的指针，并将错误分配给`file`和`err`变量。如果`err`不是`nil`（表示生成了错误），则`load`函数的执行会过早终止，并将`err`的值返回给调用函数处理调用堆栈中更高的位置。

### 注意

当为具有多个结果参数的函数返回错误时，习惯上会返回其他（非错误类型）参数的零值。在这个例子中，对于类型为`[]string`的结果，返回了`nil`值。虽然这并非必需，但它简化了错误处理，并避免了对函数调用者造成任何困惑。

## 错误处理

如前所述，在函数执行过程中，只需返回一个非 nil 值，类型为`error`，即可简单地表示错误状态的发生。调用者可以选择处理`error`或将其`return`以供调用堆栈上进一步评估，就像在`load`函数中所做的那样。这种习惯强制错误向上传播，直到某个地方处理它们。下一个片段展示了`load`函数生成的错误在`main`函数中是如何处理的：

```go
func main() { 
   words, err := load("dict.txt") 
   if err != nil { 
         fmt.Println("Unable to load file:", err) 
         os.Exit(1) 
   } 
   ... 
} 

```

由于`main`函数是调用堆栈中最顶层的调用者，它通过终止整个程序来处理错误。

这就是 Go 中错误处理的机制。语言强制程序员始终测试每个返回`error`类型值的函数调用是否处于错误状态。`if…not…nil error`处理习惯可能对一些人来说过于冗长，特别是如果你来自一个具有正式异常机制的语言。然而，这里的好处在于程序可以构建一个健壮的执行流程，程序员总是知道错误可能来自哪里，并适当地处理它们。

## 错误类型

`error`类型是一个内置接口，因此必须在使用之前实现。幸运的是，Go 标准库提供了准备好的实现。我们已经使用了来自`errors`包的一个实现：

```go
errors.New("Dictionary file name cannot be empty.")  

```

您还可以使用`fmt.Errorf`函数创建参数化的错误值，如下面的代码片段所示：

```go
func load(fname string) ([]string, error) { 
   if fname == "" { 
         return nil, errors.New( 
             "Dictionary file name cannot be emtpy.") 
   } 

   file, err := os.Open(fname) 
   if err != nil { 
         return nil, fmt.Errorf( 
             "Unable to open file %s: %s", fname, err) 
   } 
   ... 
} 

```

golang.fyi/ch05/anagram2.go

将错误值分配给高级变量，以便根据需要在整个程序中重复使用，也是惯用的做法。以下摘录自[`golang.org/src/os/error.go`](http://golang.org/src/os/error.go)显示了与 OS 文件操作相关的可重用错误的声明：

```go
var ( 
   ErrInvalid    = errors.New("invalid argument") 
   ErrPermission = errors.New("permission denied") 
   ErrExist      = errors.New("file already exists") 
   ErrNotExist   = errors.New("file does not exist") 
) 

```

[`golang.org/src/os/error.go`](http://golang.org/src/os/error.go)

您还可以创建自己的`error`接口实现来创建自定义错误。这个主题在第七章中重新讨论，*方法，接口和对象*，在这本书中讨论了扩展类型的概念。

# 推迟函数调用

Go 支持推迟函数调用的概念。在函数调用之前放置关键字`defer`会有一个有趣的效果，将函数推入内部堆栈，延迟其执行直到封闭函数返回之前。为了更好地解释这一点，让我们从以下简单的程序开始，它演示了`defer`的用法：

```go
package main 
import "fmt" 

func do(steps ...string) { 
   defer fmt.Println("All done!") 
   for _, s := range steps { 
         defer fmt.Println(s) 
   } 

   fmt.Println("Starting") 
} 

func main() { 
   do( 
         "Find key", 
         "Aplly break", 
         "Put key in ignition", 
         "Start car", 
   ) 
} 

```

golang.fyi/ch05/defer1.go

前面的示例定义了`do`函数，该函数接受可变参数`steps`。该函数使用`defer fmt.Println("All done!")`推迟语句。接下来，函数循环遍历切片`steps`，并推迟每个元素的输出，使用`defer fmt.Println(s)`。函数`do`中的最后一个语句是一个非延迟调用`fmt.Println("Starting")`。当程序执行时，请注意打印的字符串值的顺序，如下面的输出所示：

```go
$> go run defer1.go
Starting
Start car
Put key in ignition
Aplly break
Find key
All done!

```

有几个事实可以解释打印顺序的反向顺序。首先，回想一下，延迟函数在其封闭函数返回之前执行。因此，第一个打印的值是由最后一个非延迟方法调用生成的。接下来，如前所述，延迟语句被推入堆栈。因此，延迟调用使用后进先出的顺序执行。这就是为什么输出中的最后一个字符串值是`"All done!"`。

## 使用 defer

`defer`关键字通过延迟函数调用修改程序的执行流程。这一特性的惯用用法之一是进行资源清理。由于 defer 总是在封闭函数返回时执行，因此它是一个很好的地方来附加清理代码，比如：

+   关闭打开的文件

+   释放网络资源

+   关闭 Go 通道

+   提交数据库事务

+   等等

为了说明，让我们回到之前的变位词示例。下面的代码片段显示了在加载文件后使用 defer 关闭文件的代码版本。`load`函数在返回之前调用`file.Close()`：

```go
func load(fname string) ([]string, error) { 
... 
   file, err := os.Open(fname) 
   if err != nil { 
         return nil, err 
   } 
   defer file.Close() 
... 
} 

```

golang.fyi/ch05/anagram2.go

打开-推迟-关闭资源的模式在 Go 中被广泛使用。在打开或创建资源后立即放置延迟意图的做法使得代码读起来更自然，并减少了资源泄漏的可能性。

# 函数 panic 和恢复

在本章的前面提到，Go 没有其他语言提供的传统异常机制。尽管如此，在 Go 中，有一种称为函数 panic 的突然退出执行函数的方法。相反，当程序处于 panic 状态时，Go 提供了一种恢复并重新控制执行流程的方法。

## 函数 panic

在执行过程中，函数可能因为以下任何一个原因而 panic：

+   显式调用**panic**内置函数

+   使用由于异常状态而引发 panic 的源代码包

+   访问 nil 值或超出数组范围的元素

+   并发死锁

当函数 panic 时，它会中止并执行其延迟调用。然后它的调用者 panic，导致如下图所示的连锁反应：

![函数 panic](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/B03676_05_02.jpg)

panic 序列一直沿着调用堆栈一直到达`main`函数并且程序退出（崩溃）。以下源代码片段显示了一个版本的 anagram 程序，如果尝试创建一个输出 anagram 文件时已经存在，则会导致显式 panic。这是为了导致`write`函数在出现文件错误时引发 panic：

```go
package main 
... 
func write(fname string, anagrams map[string][]string) { 
   file, err := os.OpenFile( 
         fname,  
         os.O_WRONLY+os.O_CREATE+os.O_EXCL,  
         0644, 
   ) 
   if err != nil { 
         msg := fmt.Sprintf( 
               "Unable to create output file: %v", err, 
         ) 
         panic(msg) 
   } 
   ... 
} 

func main() { 
   words, err := load("dict.txt") 
   if err != nil { 
         fmt.Println("Unable to load file:", err) 
         os.Exit(1) 
   } 
   anagrams := mapWords(words) 
   write("out.txt", anagrams) 
} 

```

golang.fyi/ch05/anagram2.go

在上面的片段中，如果`os.OpenFile()`方法出错，`write`函数调用`panic`函数。当程序调用`main`函数时，如果工作目录中已经存在输出文件，程序将会引发 panic 并像下面的堆栈跟踪所示一样崩溃，指示导致崩溃的调用序列：

```go
> go run anagram2.go 
panic: Unable to create output file: open out.txt: file exists
goroutine 1 [running]:
main.write(0x4e7b30, 0x7, 0xc2080382a0)
/Go/src/github.com/vladimirvivien/learning-go/ch05/anagram2.go:72 +0x1a3 
main.main()
Go/src/github.com/vladimirvivien/learning-go/ch05/anagram2.go:103 +0x1e9
exit status 2

```

## 函数 panic 恢复

当一个函数引发 panic 时，正如前面所解释的，它可能会导致整个程序崩溃。根据您的需求，这可能是期望的结果。然而，可以在 panic 序列开始后重新获得控制。为此，Go 提供了名为`recover`的内置函数。

recover 与 panic 协同工作。对 recover 函数的调用会返回作为参数传递给 panic 的值。以下代码展示了如何从前面的示例中引入的 panic 调用中恢复。在这个版本中，write 函数被移动到`makeAnagram()`中以提高清晰度。当从`makeAnagram()`调用`write`函数并且无法打开文件时，它会引发 panic。然而，现在添加了额外的代码来进行恢复：

```go
package main 
... 
func write(fname string, anagrams map[string][]string) { 
   file, err := os.OpenFile( 
         fname,  
         os.O_WRONLY+os.O_CREATE+os.O_EXCL,  
         0644, 
   ) 
   if err != nil { 
         msg := fmt.Sprintf( 
               "Unable to create output file: %v", err, 
         ) 
         panic(msg) 
   } 
   ... 
} 

func makeAnagrams(words []string, fname string) { 
   defer func() { 
         if r := recover(); r != nil { 
               fmt.Println("Failed to make anagram:", r) 
         } 
   }() 

   anagrams := mapWords(words) 
   write(fname, anagrams) 
} 
func main() { 
   words, err := load("") 
   if err != nil { 
         fmt.Println("Unable to load file:", err) 
         os.Exit(1) 
   } 
   makeAnagrams(words, "") 
} 

```

golang.fyi/ch05/anagram3.go

为了能够从一个展开的 panic 序列中恢复，代码必须对 recover 函数进行延迟调用。在前面的代码中，这是在`makeAnagrams`函数中通过将`recover()`包装在一个匿名函数文字中完成的，如下面的片段所示：

```go
defer func() { 
   if r := recover(); r != nil { 
         fmt.Println("Failed to make anagram:", r) 
   } 
}() 

```

当执行延迟的`recover`函数时，程序有机会重新获得控制并阻止 panic 导致程序崩溃。如果`recover()`返回`nil`，这意味着当前没有 panic 在调用堆栈上展开，或者 panic 已经在下游处理过了。

因此，现在当程序执行时，不会崩溃并显示堆栈跟踪，而是会恢复并优雅地显示问题，如下面的输出所示：

```go
> go run anagram3.go
Failed to make anagram: Unable to open output file for creation: open out.txt: file exists

```

### 注意

您可能想知道为什么我们在测试`recover`函数返回的值时使用`nil`，而在调用`panic`时传递了一个字符串。这是因为 panic 和 recover 都采用了空接口类型。正如您将了解的那样，空接口类型是一个通用类型，具有表示 Go 类型系统中的任何类型的能力。在第七章*方法、接口和对象*中关于接口的讨论中，我们将更多地了解空接口。

# 总结

本章向读者介绍了 Go 函数的探索。它从命名函数声明的概述开始，然后讨论了函数参数。本章深入讨论了函数类型和函数值。本章的最后部分讨论了错误处理、panic 和恢复的语义。下一章将继续讨论函数；然而，它是在 Go 包的上下文中进行的。它解释了包作为 Go 函数（和其他代码元素）的逻辑分组形成可共享和可调用的代码模块的角色。


# 第六章：Go 包和程序

第五章, *Go 中的函数*涵盖了函数，这是代码组织的基本抽象级别，使代码可寻址和可重用。本章将继续讨论围绕 Go 包展开的抽象层次。正如将在这里详细介绍的那样，包是存储在源代码文件中的语言元素的逻辑分组，可以共享和重用，如下面的主题所涵盖的：

+   Go 包

+   创建包

+   构建包

+   包可见性

+   导入包

+   包初始化

+   创建程序

+   远程包

# Go 包

与其他语言类似，Go 源代码文件被分组为可编译和可共享的单元，称为包。但是，所有 Go 源文件必须属于一个包（没有默认包的概念）。这种严格的方法使得 Go 可以通过偏爱惯例而不是配置来保持其编译规则和包解析规则简单。让我们深入了解包的基础知识，它们的创建、使用和推荐做法。

## 理解 Go 包

在我们深入讨论包的创建和使用之前，至关重要的是从高层次上理解包的概念，以帮助引导后续的讨论。Go 包既是代码组织的物理单元，也是逻辑单元，用于封装可以重用的相关概念。按照惯例，存储在同一目录中的一组源文件被认为是同一个包的一部分。以下是一个简单的目录树示例，其中每个目录代表一个包，包含一些源代码：

```go
 foo
 ├── blat.go
 └── bazz
 ├── quux.go
 └── qux.go 

```

golang.fyi/ch06-foo

虽然不是必需的，但是建议按照惯例，在每个源文件中设置包的名称与文件所在目录的名称相匹配。例如，源文件`blat.go`被声明为`foo`包的一部分，因为它存储在名为`foo`的目录中，如下面的代码所示：

```go
package foo 

import ( 
   "fmt" 
   "foo/bar/bazz" 
) 

func fooIt() { 
   fmt.Println("Foo!") 
   bazz.Qux() 
} 

```

golang.fyi/ch06-foo/foo/blat.go

文件`quux.go`和`qux.go`都是`bazz`包的一部分，因为它们位于具有该名称的目录中，如下面的代码片段所示：

|

```go
package bazz
import "fmt"
func Qux() {
  fmt.Println("bazz.Qux")
}
```

golang.fyi/ch06-foo/foo/bazz/quux.go |

```go
package bazz
import "fmt"
func Quux() {
  Qux()fmt.Println("gazz.Quux")
}
```

golang.fyi/ch06-foo/foo/bazz/qux.go |

## 工作区

在讨论包时理解的另一个重要概念是*Go 工作区*。工作区只是一个任意的目录，用作在某些任务（如编译）期间解析包的命名空间。按照惯例，Go 工具期望工作区目录中有三个特定命名的子目录：`src`、`pkg`和`bin`。这些子目录分别存储 Go 源文件以及所有构建的包构件。

建立一个静态目录位置，将 Go 包放在一起具有以下优势：

+   简单设置，几乎没有配置

+   通过将代码搜索减少到已知位置来实现快速编译

+   工具可以轻松创建代码和包构件的源图

+   从源代码自动推断和解析传递依赖关系

+   项目设置可以是可移植的，并且易于分发

以下是我笔记本电脑上 Go 工作区的部分（和简化的）树状布局，其中突出显示了三个子目录`bin`、`pkg`和`src`：

|

```go
/home/vladimir/Go/   
├── bin   
│  ├── circ   
│  ├── golint   
│  ...   
├── pkg   
│  └── linux_amd64    
│    ├── github.com   
│    │  ├── golang   
│    │  │  └── lint.a   
│    │  └── vladimirvivien   
│    │    └── learning-go   
│    │      └── ch06   
│    │        ├── current.a   
│    ...       ...    
└── src   
  ├── github.com   
  │  ├── golang   
  │  │  └── lint   
  │  │    ├── golint   
  │  │    │  ├── golint.go   
  │  ...   ... ...   
  │  └── vladimirvivien   
  │    └── learning-go   
  │      ├── ch01   
  │      ...   
  │      ├── ch06   
  │      │  ├── current   
  │      │  │  ├── doc.go   
  │      │  │  └── lib.go   
  ...     ...      

```

|

示例工作区目录

+   `bin`：这是一个自动生成的目录，用于存储编译的 Go 可执行文件（也称为程序或命令）。当 Go 工具编译和安装可执行包时，它们被放置在此目录中。前面的示例工作区显示了两个列出的二进制文件`circ`和`golint`。建议将此目录添加到操作系统的`PATH`环境变量中，以使您的命令在本地可用。

+   `pkg`：这个目录也是自动生成的，用于存储构建的包构件。当 Go 工具构建和安装非可执行包时，它们被存储为对象文件（带有`.a`后缀）在子目录中，子目录的名称模式基于目标操作系统和架构。在示例工作区中，对象文件被放置在`linux_amd64`子目录下，这表明该目录中的对象文件是为运行在 64 位架构上的 Linux 操作系统编译的。

+   `src`：这是一个用户创建的目录，用于存储 Go 源代码文件。`src`下的每个子目录都映射到一个包。*src*是解析所有导入路径的根目录。Go 工具搜索该目录以解析代码中引用的包，这些引用在编译或其他依赖源路径的活动中。上图中的示例工作区显示了两个包：`github.com/golang/lint/golint/`和`github.com/vladimirvivien/learning-go/ch06/current`。

### 注意

您可能会对工作区示例中显示的包路径中的`github.com`前缀感到疑惑。值得注意的是，包目录没有命名要求（请参阅*命名包*部分）。包可以有任意的名称。但是，Go 建议遵循一些约定，这有助于全局命名空间解析和包组织。

## 创建工作区

创建工作区就像设置一个名为`GOPATH`的操作系统环境一样简单，并将其分配给工作区目录的根路径。例如，在 Linux 机器上，工作区的根目录为`/home/username/Go`，工作区将被设置为：

```go
$> export GOPATH=/home/username/Go 

```

在设置`GOPATH`环境变量时，可以指定存储包的多个位置。每个目录由操作系统相关的路径分隔符分隔（换句话说，Linux/Unix 使用冒号，Windows 使用分号），如下所示：

```go
$> export GOPATH=/home/myaccount/Go;/home/myaccount/poc/Go

```

当解析包名称时，Go 工具将搜索`GOPATH`中列出的所有位置。然而，Go 编译器只会将编译后的文件，如对象和二进制文件，存储在分配给`GOPATH`的第一个目录位置中。

### 注意

通过简单设置操作系统环境变量来配置工作区具有巨大的优势。它使开发人员能够在编译时动态设置工作区，以满足某些工作流程要求。例如，开发人员可能希望在合并代码之前测试未经验证的代码分支。他或她可能希望设置一个临时工作区来构建该代码，方法如下（Linux）：`$> GOPATH=/temporary/go/workspace/path go build`

## 导入路径

在继续设置和使用包的详细信息之前，最后一个重要概念要涵盖的是*导入路径*的概念。每个包的相对路径，位于工作区路径`$GOPATH/src`下，构成了一个全局标识符，称为包的`导入路径`。这意味着在给定的工作区中，没有两个包可以具有相同的导入路径值。

让我们回到之前的简化目录树。例如，如果我们将工作区设置为某个任意路径值，如`GOPATH=/home/username/Go`：

```go
/home/username/Go
└── foo
 ├── ablt.go
 └── bazz
 ├── quux.go
 └── qux.go 

```

从上面示例的工作区中，包的目录路径映射到它们各自的导入路径，如下表所示：

| **目录路径** | **导入路径** |
| --- | --- |
| `/home/username/Go/foo` |

```go
"foo"   

```

|

| `/home/username/Go/foo/bar` |
| --- |

```go
"foo/bar"   

```

|

| `/home/username/Go/foo/bar/bazz` |
| --- |

```go
"foo/bar/bazz"   

```

|

# 创建包

到目前为止，本章已经涵盖了 Go 包的基本概念；现在是时候深入了解并查看包含在包中的 Go 代码的创建。Go 包的主要目的之一是将常见逻辑抽象出来并聚合到可共享的代码单元中。在本章的前面提到，一个目录中的一组 Go 源文件被认为是一个包。虽然这在技术上是正确的，但是关于 Go 包的概念还不仅仅是将一堆文件放在一个目录中。

为了帮助说明我们的第一个包的创建，我们将利用在[github.com/vladimirvivien/learning-go/ch06](https://github.com/vladimirvivien/learning-go/ch06)中找到的示例源代码。该目录中的代码定义了一组函数，用于使用*欧姆定律*计算电气值。以下显示了组成示例包的目录布局（假设它们保存在某个工作区目录`$GOPATH/src`中）：

|

```go
github.com/vladimirvivien/learning-go/ch06   
├── current   
│  ├── curr.go   
│  └── doc.go   
├── power   
│  ├── doc.go   
│  ├── ir   
│  │  └── power.go   
│  ├── powlib.go   
│  └── vr   
│    └── power.go   
├── resistor   
│  ├── doc.go   
│  ├── lib.go   
│  ├── res_equivalence.go   
│  ├── res.go   
│  └── res_power.go   
└── volt   
  ├── doc.go   
  └── volt.go   

```

|

Ohm's Law 示例的包布局

在上述目录中，每个目录都包含一个或多个 Go 源代码文件，用于定义和实现函数以及其他源代码元素，这些元素将被组织成包并可重复使用。以下表格总结了从前面的工作区布局中提取的导入路径和包信息：

| **导入路径** | **包** |
| --- | --- |
| "github.com/vladimirvivien/learning-go/ch06/**current**" | `current` |
| "github.com/vladimirvivien/learning-go/ch06/**power**" | `power` |
| "github.com/vladimirvivien/learning-go/ch06/**power/ir**" | `ir` |
| "github.com/vladimirvivien/learning-go/ch06/**power/vr**" | `vr` |
| "github.com/vladimirvivien/learning-go/ch06/**resistor**" | `resistor` |
| "github.com/vladimirvivien/learning-go/ch06/**volt**" | `volt` |

虽然没有命名要求，但是将包目录命名为反映其各自目的的名称是明智的。从前面的表格中，每个示例中的包都被命名为代表电气概念的名称，例如 current、power、resistor 和 volt。*包命名*部分将详细介绍包命名约定。

## 声明包

Go 源文件必须声明自己属于一个包。这是使用`package`子句完成的，作为 Go 源文件中的第一个合法语句。声明的包由`package`关键字后跟一个名称标识符组成。以下显示了`volt`包中的源文件`volt.go`：

```go
package volt 

func V(i, r float64) float64 { 
   return i * r 
} 

func Vser(volts ...float64) (Vtotal float64) { 
   for _, v := range volts { 
         Vtotal = Vtotal + v 
   } 
   return 
} 

func Vpi(p, i float64) float64 { 
   return p / i 
} 

```

golang.fyi/ch06/volt/volt.go

源文件中的包标识符可以设置为任意值。与 Java 不同，包的名称不反映源文件所在的目录结构。虽然对于包名称没有要求，但是将包标识符命名为与文件所在目录相同的约定是被接受的。在我们之前的源代码清单中，包被声明为标识符`volt`，因为该文件存储在*volt*目录中。

## 多文件包

一个包的逻辑内容（源代码元素，如类型、函数、变量和常量）可以在多个 Go 源文件中物理扩展。一个包目录可以包含一个或多个 Go 源文件。例如，在下面的示例中，包`resistor`被不必要地分割成几个 Go 源文件，以说明这一点：

|

```go
package resistor   

func recip(val float64) float64 {   
   return 1 / val   
}   

```

golang.fyi/ch06/resistor/lib.go |

|

```go
  package resistor   

func Rser(resists ...float64) (Rtotal float64) {   
   for _, r := range resists {   
         Rtotal = Rtotal + r   
   }   
   return   
}   

func Rpara(resists ...float64) (Rtotal float64) {   
   for _, r := range resists {   
         Rtotal = Rtotal + recip(r)   
   }   
   return   
}   

```

golang.fyi/ch06/resistor/res_equivalance.go |

|

```go
package resistor   

func R(v, i float64) float64 {   
   return v / i   
}   

```

golang.fyi/ch06/resistor/res.go |

|

```go
package resistor   

func Rvp(v, p float64) float64 {   
   return (v * v) / p   
}   

```

golang.fyi/ch06/resistor/res_power.go |

包中的每个文件必须具有相同的名称标识符的包声明（在本例中为`resistor`）。Go 编译器将从所有源文件中的所有元素中拼接出一个逻辑单元，形成一个可以被其他包使用的单一范围内的逻辑单元。

需要指出的是，如果给定目录中所有源文件的包声明不相同，编译将失败。这是可以理解的，因为编译器期望目录中的所有文件都属于同一个包。

## 命名包

如前所述，Go 期望工作区中的每个包都有一个唯一的完全限定的导入路径。您的程序可以拥有任意多的包，您的包结构可以在工作区中深入到您喜欢的程度。然而，惯用的 Go 规定了一些关于包的命名和组织的**规则**，以使创建和使用包变得简单。

### 使用全局唯一的命名空间

首先，在全局上下文中，完全限定您的包的导入路径是一个好主意，特别是如果您计划与他人共享您的代码。考虑以唯一标识您或您的组织的命名空间方案开始您的导入路径的名称。例如，公司*Acme, Inc.*可能选择以`acme.com/apps`开头命名他们所有的 Go 包名称。因此，一个包的完全限定导入路径将是`"acme.com/apps/foo/bar"`。

### 注意

在本章的后面，我们将看到如何在集成 Go 与 GitHub 等源代码存储库服务时使用包导入路径。

### 为路径添加上下文

接下来，当您为您的包设计一个命名方案时，使用包的路径为您的包名称添加上下文。名称中的上下文应该从左到右开始通用，然后变得更具体。例如，让我们参考电源包的导入路径（来自之前的示例）。电源值的计算分为三个子包，如下所示：

+   `github.com/vladimirvivien/learning-go/ch06/**power**`

+   `github.com/vladimirvivien/learning-go/ch06/**power/ir**`

+   `github.com/vladimirvivien/learning-go/ch06/**power/vr**`

父路径`power`包含具有更广泛上下文的包成员。子包`ir`和`vr`包含更具体的成员，具有更窄的上下文。这种命名模式在 Go 中被广泛使用，包括内置包，如以下所示：

+   `crypto/md5`

+   `net/http`

+   `net/http/httputil`

+   `reflect`

请注意，一个包深度为一是一个完全合法的包名称（参见`reflect`），只要它能捕捉上下文和它所做的本质。同样，保持简单。避免在您的命名空间内将您的包嵌套超过三层的诱惑。如果您是一个习惯于长嵌套包名称的 Java 开发人员，这种诱惑将特别强烈。

### 使用简短的名称

当审查内置的 Go 包名称时，您会注意到一个事实，即与其他语言相比，名称的简洁性。在 Go 中，包被认为是实现一组紧密相关功能的代码集合。因此，您的包的导入路径应该简洁，并反映出它们的功能，而不会过长。我们的示例源代码通过使用诸如 volt、power、resistance、current 等简短名称来命名包目录，充分体现了这一点。在各自的上下文中，每个目录名称都准确说明了包的功能。

在 Go 的内置包中严格遵守了简短名称规则。例如，以下是 Go 内置包中的几个包名称：`log`、`http`、`xml`和`zip`。每个名称都能够清楚地识别包的目的。

### 注意

短包名称有助于减少在较大代码库中的击键次数。然而，拥有短而通用的包名称也有一个缺点，即容易发生导入路径冲突，即在大型项目中的开发人员（或开源库的开发人员）可能最终在他们的代码中使用相同的流行名称（换句话说，`log`、`util`、`db`等）。正如我们将在本章后面看到的那样，这可以通过使用`命名`导入路径来处理。

# 构建包

通过应用某些约定和合理的默认值，Go 工具减少了编译代码的复杂性。虽然完整讨论 Go 的构建工具超出了本节（或本章）的范围，但了解`build`和`install`工具的目的和用法是有用的。一般来说，使用构建和安装工具的方式如下：

*$> go build [<package import path>]*

`import path`可以明确提供或完全省略。`build`工具接受`import path`，可以表示为完全限定或相对路径。在正确设置的工作区中，以下是从前面的示例中编译包`volt`的等效方式：

```go
$> cd $GOPATH/src/github.com/vladimirvivien/learning-go
$> go build ./ch06/volt 
$> cd $GOPATH/src/github.com/vladimirvivien/learning-go/ch06
$> go build ./volt 
$> cd $GOPATH/src/github.com/vladimirvivien/learning-go/ch06/volt
$> go build . 
$> cd $GOPATH/src/ 
$> go build github.com/vladimirvivien/learning-go/ch06/current /volt

```

上面的`go build`命令将编译在目录`volt`中找到的所有 Go 源文件及其依赖项。此外，还可以使用通配符参数构建给定目录中的所有包和子包，如下所示：

```go
$> cd $GOPATH/src/github.com/vladimirvivien/learning-go/ch06
$> go build ./...

```

前面的内容将构建在目录`$GOPATH/src/github.com/vladimirvivien/learning-go/ch06`中找到的所有包和子包。

## 安装一个包

默认情况下，构建命令将其结果输出到一个工具生成的临时目录中，在构建过程完成后会丢失。要实际生成可用的构件，必须使用`install`工具来保留已编译的对象文件的副本。

`install`工具与构建工具具有完全相同的语义：

```go
$> cd $GOPATH/src/github.com/vladimirvivien/learning-go/ch06
$> go install ./volt

```

除了编译代码，它还将结果保存并输出到工作区位置`$GOPATH/pkg`，如下所示：

```go
$GOPATH/pkg/linux_amd64/github.com/vladimirvivien/learning-go/
└── ch06
 └── volt.a

```

生成的对象文件（带有`.a`扩展名）允许包在工作区中被重用和链接到其他包中。在本章的后面，我们将讨论如何编译可执行程序。

# 包可见性

无论声明为包的一部分的源文件数量如何，所有在包级别声明的源代码元素（类型、变量、常量和函数）都共享一个公共作用域。因此，编译器不允许在整个包中重新声明元素标识符超过一次。让我们使用以下代码片段来说明这一点，假设两个源文件都是同一个包`$GOPATH/src/foo`的一部分：

|

```go
package foo   

var (   
  bar int = 12   
)   

func qux () {   
  bar += bar   
}   

```

foo/file1.go |

```go
package foo   

var bar struct{   
  x, y int   
}   

func quux() {   
  bar = bar * bar   
}   

```

foo/file2.go |

非法的变量标识符重新声明

尽管它们在两个不同的文件中，但在 Go 中使用标识符`bar`声明变量是非法的。由于这些文件是同一个包的一部分，两个标识符具有相同的作用域，因此会发生冲突。

函数标识符也是如此。Go 不支持在相同作用域内重载函数名称。因此，无论函数的签名如何，使用函数标识符超过一次都是非法的。如果我们假设以下代码出现在同一包内的两个不同源文件中，则以下代码片段将是非法的：

|

```go
package foo   

var (   
  bar int = 12   
)   

func qux () {   
  bar += bar   
}   

```

foo/file1.go |

```go
package foo   

var (   
  fooVal int = 12   
)   

func qux (inc int) int {   
  return fooVal += inc   
}   

```

foo/file1.go |

非法的函数标识符重新声明

在前面的代码片段中，函数名标识符`qux`被使用了两次。即使这两个函数具有不同的签名，编译器也会失败。唯一的解决方法是更改名称。

## 包成员可见性

包的有用性在于其能够将其源元素暴露给其他包。控制包元素的可见性很简单，遵循这个规则：*大写标识符会自动导出*。这意味着任何具有大写标识符的类型、变量、常量或函数都会自动从声明它的包之外可见。

参考之前描述的欧姆定律示例，以下说明了来自包`resistor`（位于[github.com/vladimirvivien/learning-go/ch06/resistor](https://github.com/vladimirvivien/learning-go/ch06/resistor)）的功能：

| **代码** | **描述** |
| --- | --- |

|

```go
package resistor   

func R(v, i float64) float64 {   
   return v / i   
}   

```

| 函数`R`自动导出，并且可以从其他包中访问：`resistor.R()` |
| --- |

|

```go
package resistor   

func recip(val float64) float64 {   
   return 1 / val   
}   

```

| 函数标识符`recip`全部小写，因此未导出。虽然在其自己的范围内可访问，但该函数将无法从其他包中可见。 |
| --- |

值得重申的是，同一个包内的成员始终对彼此可见。在 Go 中，没有复杂的可见性结构，比如私有、友元、默认等，这使得开发人员可以专注于正在实现的解决方案，而不是对可见性层次进行建模。

# 导入包

到目前为止，您应该对包是什么，它的作用以及如何创建包有了很好的理解。现在，让我们看看如何使用包来导入和重用其成员。正如您在其他几种语言中所发现的那样，关键字`import`用于从外部包中导入源代码元素。它允许导入源访问导入包中的导出元素（请参阅本章前面的*包范围和可见性*部分）。导入子句的一般格式如下：

*import [包名称标识符] "<导入路径>"*

请注意，导入路径必须用双引号括起来。`import`语句还支持可选的包标识符，可用于显式命名导入的包（稍后讨论）。导入语句也可以写成导入块的形式，如下所示。这在列出两个或更多导入包的情况下很有用：

*import (*

*[包名称标识符] "<导入路径>"*

*)*

以下源代码片段显示了先前介绍的欧姆定律示例中的导入声明块：

```go
import ( 
   "flag" 
   "fmt" 
   "os" 

   "github.com/vladimirvivien/learning-go/ch06/current" 
   "github.com/vladimirvivien/learning-go/ch06/power" 
   "github.com/vladimirvivien/learning-go/ch06/power/ir" 
   "github.com/vladimirvivien/learning-go/ch06/power/vr" 
      "github.com/vladimirvivien/learning-go/ch06/volt" 
) 

```

golang.fyi/ch06/main.go

通常省略导入包的名称标识符，如上所示。然后，Go 将导入路径的最后一个目录的名称作为导入包的名称标识符，如下表所示，对于某些包：

| **导入路径** | **包名称** |
| --- | --- |
| `flag` | `flag` |
| `github.com/vladimirvivien/learning-go/ch06/current` | `current` |
| `github.com/vladimirvivien/learning-go/ch06/power/ir` | `ir` |
| `github.com/vladimirvivien/learning-go/ch06/volt` | `volt` |

点符号用于访问导入包的导出成员。例如，在下面的源代码片段中，从导入包`"github.com/vladimirvivien/learning-go/ch06/volt"`调用了方法`volt.V()`：

```go
... 
import "github.com/vladimirvivien/learning-go/ch06/volt" 
func main() { 
   ... 
   switch op { 
   case "V", "v": 
         val := volt.V(i, r) 
  ... 
} 

```

golang.fyi/ch06/main.go

## 指定包标识符

如前所述，`import`声明可以显式为导入声明一个名称标识符，如下面的导入片段所示：

```go
import res "github.com/vladimirvivien/learning-go/ch06/resistor"
```

按照前面描述的格式，名称标识符放在导入路径之前，如前面的片段所示。命名包可以用作缩短或自定义包名称的一种方式。例如，在一个大型源文件中，有大量使用某个包的情况下，这可以是一个很好的功能，可以减少按键次数。

给包分配一个名称也是避免给定源文件中的包标识符冲突的一种方式。可以想象导入两个或更多的包，具有不同的导入路径，解析为相同的包名称。例如，您可能需要使用来自不同库的两个不同日志系统记录信息，如下面的代码片段所示：

```go
package foo 
import ( 
   flog "github.com/woom/bat/logger" 
   hlog "foo/bar/util/logger" 
) 

func main() { 
   flog.Info("Programm started") 
   err := doSomething() 
   if err != nil { 
     hlog.SubmitError("Error - unable to do something") 
   } 
} 

```

如前面的片段所示，两个日志包默认都将解析为名称标识符`"logger"`。为了解决这个问题，至少其中一个导入的包必须分配一个名称标识符来解决名称冲突。在上面的例子中，两个导入路径都被命名为有意义的名称，以帮助代码理解。

## 点标识符

一个包可以选择将点（句号）分配为它的标识符。当一个`import`语句使用点标识符（`.`）作为导入路径时，它会导致导入包的成员与导入包的作用域合并。因此，导入的成员可以在不添加额外限定符的情况下被引用。因此，如果在以下源代码片段中使用点标识符导入了包`logger`，那么在访问 logger 包的导出成员函数`SubmitError`时，包名被省略了：

```go
package foo 

import ( 
   . "foo/bar/util/logger" 
) 

func main() { 
   err := doSomething() 
   if err != nil { 
     SubmitError("Error - unable to do something") 
   } 
} 

```

虽然这个特性可以帮助减少重复的按键，但这并不是一种鼓励的做法。通过合并包的作用域，更有可能遇到标识符冲突。

## 空白标识符

当导入一个包时，要求在导入的代码中至少引用其成员之一。如果未能这样做，将导致编译错误。虽然这个特性有助于简化包依赖关系的解析，但在开发代码的早期阶段，这可能会很麻烦。

使用空白标识符（类似于变量声明）会导致编译器绕过此要求。例如，以下代码片段导入了内置包`fmt`；但是，在随后的源代码中从未使用过它：

```go
package foo 
import ( 
   _ "fmt" 
   "foo/bar/util/logger" 
) 

func main() { 
   err := doSomething() 
   if err != nil { 
     logger.Submit("Error - unable to do something") 
   } 
} 

```

空白标识符的一个常见用法是为了加载包的副作用。这依赖于包在导入时的初始化顺序（请参阅下面的*包初始化*部分）。使用空白标识符将导致导入的包在没有引用其成员的情况下被初始化。这在需要在不引起注意的情况下运行某些初始化序列的代码中使用。

# 包初始化

当导入一个包时，它会在其成员准备好被使用之前经历一系列的初始化序列。包级变量的初始化是使用依赖分析来进行的，依赖于词法作用域解析，这意味着变量是基于它们的声明顺序和它们相互引用的解析来初始化的。例如，在以下代码片段中，包`foo`中的解析变量声明顺序将是`a`、`y`、`b`和`x`：

```go
package foo 
var x = a + b(a) 
var a = 2 
var b = func(i int) int {return y * i} 
var y = 3 

```

Go 还使用了一个名为`init`的特殊函数，它不接受任何参数，也不返回任何结果值。它用于封装在导入包时调用的自定义初始化逻辑。例如，以下源代码显示了在`resistor`包中使用的`init`函数来初始化函数变量`Rpi`：

```go
package resistor 

var Rpi func(float64, float64) float64 

func init() { 
   Rpi = func(p, i float64) float64 { 
         return p / (i * i) 
   } 
} 

func Rvp(v, p float64) float64 { 
   return (v * v) / p 
} 

```

golang.fyi/ch06/resistor/res_power.go

在前面的代码中，`init`函数在包级变量初始化之后被调用。因此，`init`函数中的代码可以安全地依赖于声明的变量值处于稳定状态。`init`函数在以下方面是特殊的：

+   一个包可以定义多个`init`函数

+   您不能直接在运行时访问声明的`init`函数

+   它们按照它们在每个源文件中出现的词法顺序执行

+   `init`函数是将逻辑注入到在任何其他函数或方法之前执行的包中的一种很好的方法。

# 创建程序

到目前为止，在本书中，您已经学会了如何创建和捆绑 Go 代码作为可重用的包。但是，包本身不能作为独立的程序执行。要创建一个程序（也称为命令），您需要取一个包，并定义一个执行入口，如下所示：

+   声明（至少一个）源文件作为名为`main`的特殊包的一部分

+   声明一个名为`main()`的函数作为程序的入口点

函数`main`不接受任何参数，也不返回任何值。以下是`main`包的缩写源代码，用于之前的 Ohm 定律示例中。它使用了 Go 标准库中的`flag`包来解析格式为`flag`的程序参数：

```go
package main 
import ( 
   "flag" 
   "fmt" 
   "os" 

   "github.com/vladimirvivien/learning-go/ch06/current" 
   "github.com/vladimirvivien/learning-go/ch06/power" 
   "github.com/vladimirvivien/learning-go/ch06/power/ir" 
   "github.com/vladimirvivien/learning-go/ch06/power/vr" 
   res "github.com/vladimirvivien/learning-go/ch06/resistor" 
   "github.com/vladimirvivien/learning-go/ch06/volt" 
) 

var ( 
   op string 
   v float64 
   r float64 
   i float64 
   p float64 

   usage = "Usage: ./circ <command> [arguments]\n" + 
     "Valid command { V | Vpi | R | Rvp | I | Ivp |"+  
    "P | Pir | Pvr }" 
) 

func init() { 
   flag.Float64Var(&v, "v", 0.0, "Voltage value (volt)") 
   flag.Float64Var(&r, "r", 0.0, "Resistance value (ohms)") 
   flag.Float64Var(&i, "i", 0.0, "Current value (amp)") 
   flag.Float64Var(&p, "p", 0.0, "Electrical power (watt)") 
   flag.StringVar(&op, "op", "V", "Command - one of { V | Vpi |"+   
    " R | Rvp | I | Ivp | P | Pir | Pvr }") 
} 

func main() { 
   flag.Parse() 
   // execute operation 
   switch op { 
   case "V", "v": 
    val := volt.V(i, r) 
    fmt.Printf("V = %0.2f * %0.2f = %0.2f volts\n", i, r, val) 
   case "Vpi", "vpi": 
   val := volt.Vpi(p, i) 
    fmt.Printf("Vpi = %0.2f / %0.2f = %0.2f volts\n", p, i, val) 
   case "R", "r": 
   val := res.R(v, i)) 
    fmt.Printf("R = %0.2f / %0.2f = %0.2f Ohms\n", v, i, val) 
   case "I", "i": 
   val := current.I(v, r)) 
    fmt.Printf("I = %0.2f / %0.2f = %0.2f amps\n", v, r, val) 
   ... 
   default: 
         fmt.Println(usage) 
         os.Exit(1) 
   } 
} 

```

golang.fyi/ch06/main.go

前面的清单显示了`main`包的源代码以及`main`函数的实现，当程序运行时将执行该函数。Ohm's Law 程序接受指定要执行的电气操作的命令行参数（请参阅下面的*访问程序参数*部分）。`init`函数用于初始化程序标志值的解析。`main`函数设置为一个大的开关语句块，以根据所选的标志选择要执行的适当操作。

## 访问程序参数

当程序被执行时，Go 运行时将所有命令行参数作为一个切片通过包变量`os.Args`提供。例如，当执行以下程序时，它会打印传递给程序的所有命令行参数：

```go
package main 
import ( 
   "fmt" 
   "os" 
) 

func main() { 
   for _, arg := range os.Args { 
         fmt.Println(arg) 
   } 
} 

```

golang.fyi/ch06-args/hello.go

当使用显示的参数调用程序时，以下是程序的输出：

```go
$> go run hello.go hello world how are you?
/var/folders/.../exe/hello
hello
world
how
are
you?

```

请注意，程序名称后面放置的命令行参数`"hello world how are you?"`被拆分为一个以空格分隔的字符串。切片`os.Args`中的位置 0 保存了程序二进制路径的完全限定名称。切片的其余部分分别存储了字符串中的每个项目。

Go 标准库中的`flag`包在内部使用此机制来提供已知为标志的结构化命令行参数的处理。在前面列出的 Ohm's Law 示例中，`flag`包用于解析几个标志，如以下源代码片段中所示（从前面的完整清单中提取）：

```go
var ( 
   op string 
   v float64 
   r float64 
   i float64 
   p float64 
) 

func init() { 
   flag.Float64Var(&v, "v", 0.0, "Voltage value (volt)") 
   flag.Float64Var(&r, "r", 0.0, "Resistance value (ohms)") 
   flag.Float64Var(&i, "i", 0.0, "Current value (amp)") 
   flag.Float64Var(&p, "p", 0.0, "Electrical power (watt)") 
   flag.StringVar(&op, "op", "V", "Command - one of { V | Vpi |"+   
    " R | Rvp | I | Ivp | P | Pir | Pvr }") 
} 
func main(){ 
  flag.Parse() 
  ... 
} 

```

代码片段显示了`init`函数用于解析和初始化预期的标志`"v"`、`"i"`、`"p"`和`"op"`（在运行时，每个标志都以减号开头）。`flag`包中的初始化函数设置了预期的类型、默认值、标志描述以及用于存储标志解析值的位置。`flag`包还支持特殊标志"help"，用于提供有关每个标志的有用提示。

`flag.Parse()`在`main`函数中用于开始解析作为命令行提供的任何标志的过程。例如，要计算具有 12 伏特和 300 欧姆的电路的电流，程序需要三个标志，并产生如下输出：

```go
$> go run main.go -op I -v 12 -r 300
I = 12.00 / 300.00 = 0.04 amps

```

## 构建和安装程序

构建和安装 Go 程序遵循与构建常规包相同的程序（如在*构建和安装包*部分中讨论的）。当您构建可执行的 Go 程序的源文件时，编译器将通过传递链接`main`包中声明的所有依赖项来生成可执行的二进制文件。构建工具将默认使用与包含 Go 程序源文件的目录相同的名称命名输出二进制文件。

例如，在 Ohm's Law 示例中，位于目录`github.com/vladimirvivien/learning-go/ch06`中的文件`main.go`被声明为`main`包的一部分。程序可以按以下方式构建：

```go
$> cd $GOPATH/src/github.com/vladimirvivien/learning-go/ch06
$> go build .

```

当构建`main.go`源文件时，构建工具将生成一个名为`ch06`的二进制文件，因为程序的源代码位于具有该名称的目录中。您可以使用输出标志`-o`来控制二进制文件的名称。在以下示例中，构建工具将创建一个名为`ohms`的二进制文件。

```go
$> cd $GOPATH/src/github.com/vladimirvivien/learning-go/ch06
$> go build -o ohms

```

最后，安装 Go 程序的方法与使用 Go `install`命令安装常规包的方法完全相同：

```go
$> cd $GOPATH/src/github.com/vladimirvivien/learning-go/ch06
$> go install .

```

使用 Go install 命令安装程序时，如果需要，将构建该程序，并将生成的二进制文件保存在`$GOPAHT/bin`目录中。将工作区`bin`目录添加到您的操作系统的`$PATH`环境变量中，将使您的 Go 程序可供执行。

### 注意

Go 生成的程序是静态链接的二进制文件。它们不需要满足任何额外的依赖关系就可以运行。但是，Go 编译的二进制文件包括 Go 运行时。这是一组处理功能的操作，如垃圾回收、类型信息、反射、goroutines 调度和 panic 管理。虽然可比的 C 程序会小上几个数量级，但 Go 的运行时带有使 Go 变得愉快的工具。

# 远程软件包

Go 附带的工具之一允许程序员直接从远程源代码存储库检索软件包。默认情况下，Go 可以轻松支持与以下版本控制系统的集成：

+   Git（`git`，[`git-scm.com/`](http://git-scm.com/)）

+   Mercurial（`hg`，[`www.mercurial-scm.org/`](https://www.mercurial-scm.org/)）

+   Subversion（`svn`，[`subversion.apache.org/`](http://subversion.apache.org/)）

+   Bazaar（`bzr`，[`bazaar.canonical.com/`](http://bazaar.canonical.com/)）

### 注意

为了让 Go 从远程存储库中拉取软件包源代码，您必须在操作系统的执行路径上安装该版本控制系统的客户端作为命令。在幕后，Go 启动客户端与源代码存储库服务器进行交互。

`get`命令行工具允许程序员使用完全合格的项目路径作为软件包的导入路径来检索远程软件包。一旦软件包被下载，就可以在本地源文件中导入以供使用。例如，如果您想要包含前面片段中 Ohm's Law 示例中的一个软件包，您可以从命令行发出以下命令：

```go
$> go get github.com/vladimirvivien/learning-go/ch06/volt

```

`go get`工具将下载指定的导入路径以及所有引用的依赖项。然后，该工具将在`$GOPATH/pkg`中构建和安装软件包工件。如果`import`路径恰好是一个程序，go get 还将在`$GOPATH/bin`中生成二进制文件，以及在`$GOPATH/pkg`中引用的任何软件包。

# 总结

本章详细介绍了源代码组织和软件包的概念。读者了解了 Go 工作区和导入路径。读者还了解了如何创建软件包以及如何导入软件包以实现代码的可重用性。本章介绍了诸如导入成员的可见性和软件包初始化之类的机制。本章的最后部分讨论了从打包代码创建可执行 Go 程序所需的步骤。

这是一个冗长的章节，理所当然地对 Go 中软件包创建和管理这样一个广泛的主题进行了公正的处理。下一章将详细讨论复合类型，如数组、切片、结构和映射，回到 Go 类型讨论。
