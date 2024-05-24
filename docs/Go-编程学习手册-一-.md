# Go 编程学习手册（一）

> 原文：[`zh.annas-archive.org/md5/5FC2C8948F5CEA11C4D0D293DBBCA039`](https://zh.annas-archive.org/md5/5FC2C8948F5CEA11C4D0D293DBBCA039)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

Go 是一种开源编程语言，让程序员可以轻松构建可靠且可扩展的程序。它通过提供简单的语法来实现这一点，使得使用并发习语和强大的标准库编写正确且可预测的代码变得有趣。

Go 拥有庞大而活跃的在线社区，全球每年都会举办几次 Go 大会。从[`golang.org/`](https://golang.org/)开始，你会发现网络上有许多提供文档、博客、视频和幻灯片的地方，涵盖了各种与 Go 相关的主题。在 GitHub 上也是如此；一些最知名的项目，例如驱动云计算未来的项目，都是用 Go 编写的，并且项目列表还在不断增长。

正如你所期望的那样，开始使用 Go 简单、快速且有很好的文档支持。然而，“深入”Go 可能更具挑战性，特别是对于来自其他语言的新手。我的第一次尝试 Go 失败了。即使阅读了规定的文档并完成了教程，由于我自己以前的编程经验所带来的偏见，理解上还是有差距。几个月后，我重新开始学习 Go 并且深入其中。这一次我阅读了语言规范，阅读了博客，观看了视频，并在网络上搜索任何提供设计动机和语言深入解释的讨论。

学习 Go 是一本旨在帮助新手和经验丰富的程序员学习 Go 编程语言的书。通过这本书，我试图写出我在开始学习 Go 时希望能够阅读的书。它将语言规范、文档、博客、视频、幻灯片以及我自己编写 Go 的经验融合在一起，提供了恰到好处的深度和见解，帮助你理解这门语言及其设计。

希望你喜欢它。

# 本书涵盖内容

第一章*，Go 的第一步*，读者将以高层次介绍 Go，并参观使该语言成为受欢迎的特点。

第二章*，Go 语言基础*，本章从更深入地探索 Go 的语法和其他语言元素开始，如源文件、变量和运算符。

第三章*，Go 控制流*，检查了 Go 程序的控制流元素，包括 if、循环和 switch 语句。

第四章*，数据类型*，向读者介绍了 Go 的类型系统，包括内置类型、类型声明和转换的详细信息。

第五章*，Go 中的函数*，讨论了 Go 函数类型的特点，包括定义、赋值、可变参数和闭包。

第六章*，Go 包和程序结构*，向读者介绍了将函数组织为逻辑分组（称为包和程序）的方式。

第七章*，复合类型*，本章继续讨论 Go 类型，向读者介绍了 Go 的复合类型，如数组、切片、映射和结构体。

第八章*，方法、接口和对象*，向读者介绍了可以用于创建和组合对象结构的 Go 习语和特性。

第九章*，并发*，介绍了使用诸如 goroutines 和 channels 等语言构造在 Go 中编写并发程序的主题。

第十章*，Go 中的数据 IO*，介绍了用于实现数据流输入、输出和编码的内置接口和 API。

第十一章*，编写网络服务*，探讨了 Go 标准库用于创建连接应用程序的功能，涵盖了从低级 TCP 协议到 HTTP 和 RPC 的主题。

第十二章*，代码测试*，在这里读者将介绍 Go 对代码测试和基准测试的固有支持和工具。

# 本书所需内容

要按照本书中的示例，您需要 Go 版本 1.6 或更高版本。 Go 支持包括 AMD64、x386 和 ARM 在内的多种架构，以及以下操作系统：

+   Windows XP（或更高版本）

+   Mac OSX 10.7（或更高版本）

+   Linux 2.6（或更高版本）

+   FreeBSD 8（或更高版本）

# 本书的读者

如果您之前有编程经验，并且有兴趣学习 Go，那么这本书就是为您设计的。虽然它假设您熟悉变量、数据类型、数组、方法和函数等概念，但本书旨在让您可以按章节顺序阅读，或者跳到您想学习的主题。

# 惯例

在本书中，您将找到许多文本样式，用于区分不同类型的信息。以下是一些这些样式的示例及其含义的解释。

文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“将源代码保存在名为`helloworld.go`的文件中，放在 GOPATH 的任何位置。”

代码块设置如下：

```go
package main
import "fmt"
func main() {
  fmt.Println("Hello, World!")
}
```

任何命令行输入或输出都是这样写的：

```go
$> go version
go version go1.6.1 linux/amd64

```

**新术语**和**重要单词**以粗体显示。例如，屏幕上看到的单词，比如菜单或对话框中的单词，会在文本中显示为：“如果一切顺利，您应该在屏幕上看到**Hello, World!**的输出。”

### 注意

警告或重要提示会以这样的方式显示在框中。

### 提示

提示和技巧看起来像这样。


# 第一章：Go 的第一步

在本书的第一章中，您将介绍 Go 并了解使该语言成为受欢迎的特点。本章的开头部分介绍了 Go 编程语言背后的动机。然而，如果您感到不耐烦，可以跳到其他主题并学习如何编写您的第一个 Go 程序。最后，“Go 简介”部分提供了对该语言特性的高级摘要。

本章涵盖以下主题：

+   Go 编程语言

+   使用 Go

+   安装 Go

+   您的第一个 Go 程序

+   Go 简介

# Go 编程语言

自从贝尔实验室的*Dennis Ritchie*在 1970 年代初发明了 C 语言以来，计算机行业已经产生了许多流行的语言，它们直接基于（或借鉴了）C 语言的语法。通常被称为 C 语言家族的语言，它们可以分为两个广泛的演变分支。在一个分支中，派生语言如 C++、C#和 Java 已经发展出采用了强类型系统、面向对象和使用编译二进制的特点。然而，这些语言往往具有较慢的构建部署周期，程序员被迫采用复杂的面向对象类型系统来获得运行时安全性和执行速度：

![Go 编程语言](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/image_01_001.jpg)

在另一个演变的语言分支中，有诸如 Perl、Python 和 JavaScript 等语言，它们被描述为动态语言，因为它们缺乏类型安全形式，使用轻量级脚本语法，并且代码解释而非编译。动态语言已成为 Web 和云规模开发的首选工具，速度和部署便利性被重视胜过运行时安全性。然而，动态语言的解释性质意味着它们通常运行速度比编译语言慢。此外，运行时缺乏类型安全意味着系统的正确性随着应用程序的增长而变得不稳定。

Go 是由*Robert Griesemer*、*Rob Pike*和*Ken Thomson*于 2007 年在 Google 创建的系统语言，用于处理应用程序开发的需求。Go 的设计者们希望在创建一种新语言的同时，减轻前述语言的问题，使其简单、安全、一致和可预测。正如 Rob Pike 所说：

> *“Go 试图将静态类型语言的安全性和性能与动态类型解释语言的表现力和便利性相结合。”*

Go 从之前的不同语言中借鉴了一些想法，包括：

+   简化但简洁的语法，有趣且易于使用

+   一种更像动态语言的系统类型

+   支持面向对象编程

+   静态类型用于编译和运行时安全

+   编译为本机二进制以实现快速运行时执行

+   几乎零编译时间，更像解释型语言

+   一种简单的并发习语，以利用多核、多芯片机器

+   用于安全和自动内存管理的垃圾收集器

本章的其余部分将带您走过一系列入门步骤，让您预览该语言并开始构建和运行您的第一个 Go 程序。这是本书其余章节中详细讨论的主题的前奏。如果您已经对 Go 有基本的了解，可以跳到其他章节。欢迎您跳到其他章节。

# 使用 Go

在我们首先安装和运行 Go 工具之前，让我们先来看看**Go Playground**。语言的创建者提供了一种简单的方式来熟悉语言，而无需安装任何工具。Go Playground 是一个基于 Web 的工具，可从[`play.golang.org/`](https://play.golang.org/)访问，它使用编辑器的比喻，让开发人员可以直接在 Web 浏览器窗口中编写代码来测试他们的 Go 技能。Playground 让用户能够在 Google 的远程服务器上编译和运行他们的代码，并立即获得结果，如下面的截图所示：

![Playing with Go](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/image_01_002.jpg)

编辑器很基础，因为它旨在作为学习工具和与他人分享代码的方式。Playground 包括实用功能，如行号和格式化，以确保您的代码在超过几行时仍然可读。由于这是一个消耗实际计算资源的免费服务，Google 可以理解地对 Playground 可以做什么施加一些限制：

+   你的代码将消耗的内存量受到限制

+   长时间运行的程序将被终止

+   文件访问是通过内存文件系统模拟的。

+   网络访问仅模拟对回环接口的访问

## 无需 IDE

除了 Go Playground，有什么其他方法可以编写 Go 代码呢？编写 Go 并不需要一个花哨的**集成开发环境**（**IDE**）。事实上，您可以使用捆绑在您的操作系统中的喜爱的纯文本编辑器开始编写简单的 Go 程序。但是，大多数主要文本编辑器（和完整的 IDE）都有针对 Go 的插件，如 Atom、Vim、Emacs、Microsoft Code、IntelliJ 等。可以在[`github.com/golang/go/wiki/IDEsAndTextEditorPlugins`](https://github.com/golang/go/wiki/IDEsAndTextEditorPlugins)找到完整的编辑器和 IDE 插件列表。

## 安装 Go

要在本地计算机上开始使用 Go 进行编程，您需要在计算机上安装**Go 工具链**。目前，Go 已准备好在以下主要操作系统平台上安装：

+   Linux

+   FreeBSD Unix

+   Mac OSX

+   Windows

官方安装包都适用于 32 位和 64 位的基于英特尔的架构。还有官方的二进制发布版本适用于 ARM 架构。随着 Go 的流行，未来肯定会提供更多的二进制发行选择。

让我们跳过详细的安装说明，因为当您阅读此文时，这些说明肯定会发生变化。相反，您可以访问[`golang.org/doc/install`](http://golang.org/doc/install)并按照针对您特定平台的说明进行操作。完成后，请确保在继续使用以下命令之前测试您的安装是否正常：

```go
$> go version
go version go1.6.1 linux/amd64

```

前面的命令应该打印出版本号、目标操作系统以及安装了 Go 及其工具的机器架构。如果您没有得到类似于前面命令的输出，请确保将 Go 二进制文件的路径添加到您的操作系统的执行`PATH`环境变量中。

在开始编写自己的代码之前，请确保已正确设置了`GOPATH`。这是一个本地目录，您在使用 Go 工具链时保存 Go 源文件和编译后的构件的地方。请按照[`golang.org/doc/install#testing`](https://golang.org/doc/install#testing)中的说明设置您的 GOPATH。

## 源代码示例

本书中提供的编程示例都可以在 GitHub 源代码存储库上找到。在那里，你将找到所有按章节分组的源文件，存储在存储库中的[`github.com/vladimirvivien/learning-go/`](https://github.com/vladimirvivien/learning-go/)。为了节省读者一些按键次数，示例使用了一个缩短的 URL，以`golang.fyi`开头，直接指向 GitHub 中的相应文件。

或者，你可以通过下载和解压（或克隆）本地存储库来跟随。在你的`GOPATH`中创建一个目录结构，使得源文件的根目录位于`$GOPATH/src/github.com/vladimirvivien/learning-go/`。

# 你的第一个 Go 程序

在你的本地机器上成功安装了 Go 工具之后，你现在可以准备编写和执行你的第一个 Go 程序了。为此，只需打开你喜欢的文本编辑器，输入下面代码中显示的简单的 Hello World 程序：

```go
package main
import "fmt"
func main() { 
  fmt.Println("Hello, World!")
} 

```

golang.fyi/ch01/helloworld.go

将源代码保存在名为`helloworld.go`的文件中，放在你的 GOPATH 的任何位置。然后使用以下 Go 命令来编译和运行程序：

```go
$> go run helloworld.go 
Hello, World!

```

如果一切顺利，你应该在屏幕上看到消息**Hello, World!**的输出。恭喜，你刚刚编写并执行了你的第一个 Go 程序。现在，让我们以高层次来探索 Go 语言的属性和特性。

# Go 简介

按设计，Go 具有简单的语法。它的设计者希望创建一种清晰、简洁、一致的语言，减少语法上的惊喜。阅读 Go 代码时，要记住这句口号：*你看到的就是它的样子*。Go 避免了巧妙而简洁的编码风格，而更倾向于清晰易读的代码，正如下面的程序所示：

```go
// This program prints molecular information for known metalloids 
// including atomic number, mass, and atom count found 
// in 100 grams of each element using the mole unit. 
// See http://en.wikipedia.org/wiki/Mole_(unit) 
package main 

import "fmt" 

const avogadro float64 = 6.0221413e+23 
const grams = 100.0 

type amu float64 

func (mass amu) float() float64 { 
  return float64(mass) 
} 

type metalloid struct { 
  name   string 
  number int32 
  weight amu 
} 

var metalloids = []metalloid{ 
  metalloid{"Boron", 5, 10.81}, 
  metalloid{"Silicon", 14, 28.085}, 
  metalloid{"Germanium", 32, 74.63}, 
  metalloid{"Arsenic", 33, 74.921}, 
  metalloid{"Antimony", 51, 121.760}, 
  metalloid{"Tellerium", 52, 127.60}, 
  metalloid{"Polonium", 84, 209.0}, 
} 

// finds # of moles 
func moles(mass amu) float64 { 
  return float64(mass) / grams 
} 

// returns # of atoms moles 
func atoms(moles float64) float64 { 
  return moles * avogadro 
} 

// return column headers 
func headers() string { 
  return fmt.Sprintf( 
    "%-10s %-10s %-10s Atoms in %.2f Grams\n", 
    "Element", "Number", "AMU", grams, 
  ) 
} 

func main() { 
  fmt.Print(headers()) 

    for _, m := range metalloids { 
      fmt.Printf( 
    "%-10s %-10d %-10.3f %e\n", 
      m.name, m.number, m.weight.float(), atoms(moles(m.weight)), 
      ) 
    } 
}

```

golang.fyi/ch01/metalloids.go

当代码被执行时，它将给出以下输出：

```go
$> go run metalloids.go 
Element    Number     AMU        Atoms in 100.00 Grams 
Boron      5          10.810     6.509935e+22 
Silicon    14         28.085     1.691318e+23 
Germanium  32         74.630     4.494324e+23 
Arsenic    33         74.921     4.511848e+23 
Antimony   51         121.760    7.332559e+23 
Tellerium  52         127.600    7.684252e+23 
Polonium   84         209.000    1.258628e+24

```

如果你以前从未见过 Go，你可能不理解前一个程序中使用的语法和习惯用法的一些细节。然而，当你阅读代码时，你很有可能能够跟上逻辑并形成程序流的心智模型。这就是 Go 简单之美的所在，也是为什么有这么多程序员使用它的原因。如果你完全迷失了，不用担心，后续章节将涵盖语言的所有方面，让你上手。

## 函数

Go 程序由函数组成，函数是语言中最小的可调用代码单元。在 Go 中，函数是有类型的实体，可以是命名的（如前面的示例所示），也可以被赋值给一个变量作为值：

```go
// a simple Go function 
func moles(mass amu) float64 { 
    return float64(mass) / grams 
} 

```

关于 Go 函数的另一个有趣特性是它们能够返回多个值作为调用的结果。例如，前面的函数可以重写为返回`error`类型的值，以及计算出的`float64`值：

```go
func moles(mass amu) (float64, error) { 
    if mass < 0 { 
        return 0, error.New("invalid mass") 
    } 
    return (float64(mass) / grams), nil 
}
```

前面的代码使用了 Go 函数的多返回能力来返回质量和错误值。你将在整本书中遇到这种习惯用法，作为向函数的调用者正确地传递错误的一种方式。在第五章 *Go 中的函数*中将进一步讨论多返回值函数。

## 包

包含 Go 函数的源文件可以进一步组织成称为包的目录结构。包是逻辑模块，用于在 Go 中共享代码作为库。你可以创建自己的本地包，或者使用 Go 提供的工具自动从源代码存储库中拉取和使用远程包。你将在第六章 *Go 包和程序*中学到更多关于 Go 包的知识。

## 工作空间

Go 遵循简单的代码布局约定，可靠地组织源代码包并管理其依赖关系。您的本地 Go 源代码存储在工作区中，这是一个包含源代码和运行时工件的目录约定。这使得 Go 工具可以自动找到、构建和安装已编译的二进制文件。此外，Go 工具依赖于`workspace`设置来从远程存储库（如 Git、Mercurial 和 Subversion）中拉取源代码包，并满足其依赖关系。

## 强类型

Go 中的所有值都是静态类型的。但是，该语言提供了一个简单但富有表现力的类型系统，可以具有动态语言的感觉。例如，类型可以像下面的代码片段中那样被安全地推断出来：

```go
const grams = 100.0 

```

正如您所期望的，常量克会被 Go 类型系统分配一个数值类型，准确地说是`float64`。这不仅适用于常量，而且任何变量都可以使用声明和赋值的简写形式，就像下面的示例中所示的那样：

```go
package main  
import "fmt"  
func main() { 
  var name = "Metalloids" 
  var triple = [3]int{5,14,84} 
  elements := []string{"Boron","Silicon", "Polonium"} 
  isMetal := false 
  fmt.Println(name, triple, elements, isMetal) 

} 

```

请注意，在前面的代码片段中，变量没有明确分配类型。相反，类型系统根据赋值中的文字值为每个变量分配类型。第二章*Go 语言基础*和第四章*数据类型*更详细地介绍了 Go 类型。

## 复合类型

除了简单值的类型之外，Go 还支持复合类型，如`array`、`slice`和`map`。这些类型旨在存储指定类型的索引元素的值。例如，前面显示的`metalloid`示例使用了一个`slice`，它是一个可变大小的数组。变量`metalloid`被声明为一个`slice`，用于存储类型为`metalloid`的集合。该代码使用文字语法来组合声明和赋值一个`slice`类型的`metalloid`：

```go
var metalloids = []metalloid{ 
    metalloid{"Boron", 5, 10.81}, 
    metalloid{"Silicon", 14, 28.085}, 
    metalloid{"Germanium", 32, 74.63}, 
    metalloid{"Arsenic", 33, 74.921}, 
    metalloid{"Antimony", 51, 121.760}, 
    metalloid{"Tellerium", 52, 127.60}, 
    metalloid{"Polonium", 84, 209.0}, 
} 

```

Go 还支持`struct`类型，它是一个存储名为字段的命名元素的复合类型，如下面的代码所示：

```go
func main() { 
  planet := struct { 
      name string 
      diameter int  
  }{"earth", 12742} 
} 

```

前面的示例使用文字语法声明了`struct{name string; diameter int}`，其值为`{"earth", 12742}`。您可以在第七章*复合类型*中了解有关复合类型的所有信息。

## 命名类型

正如讨论的那样，Go 提供了一组健全的内置类型，包括简单类型和复合类型。Go 程序员还可以根据现有基础类型定义新的命名类型，就像在前面的示例中从`metalloid`中提取的代码片段所示的那样：

```go
type amu float64 

type metalloid struct { 
  name string 
  number int32 
  weight amu 
} 

```

前面的代码片段显示了两个命名类型的定义，一个称为`amu`，它使用`float64`类型作为其基础类型。另一方面，类型`metalloid`使用`struct`复合类型作为其基础类型，允许它在索引数据结构中存储值。您可以在第四章*数据类型*中了解更多关于声明新命名类型的信息。

## 方法和对象

Go 并不是传统意义上的面向对象语言。Go 类型不使用类层次结构来模拟世界，这与其他面向对象的语言不同。但是，Go 可以支持基于对象的开发习惯，允许数据接收行为。这是通过将函数（称为方法）附加到命名类型来实现的。

从 metalloid 示例中提取的以下代码片段显示了类型`amu`接收了一个名为`float()`的方法，该方法返回`float64`值作为质量：

```go
type amu float64 

func (mass amu) float() float64 { 
    return float64(mass) 
} 

```

这个概念的强大之处在第八章*方法、接口和对象*中得到了详细探讨。

## 接口

Go 支持程序接口的概念。但是，正如您将在第八章，“方法、接口和对象”中看到的，Go 接口本身是一种类型，它聚合了一组可以将能力投射到其他类型值上的方法。忠实于其简单的本质，实现 Go 接口不需要使用关键字显式声明接口。相反，类型系统通过附加到类型的方法隐式解析实现的接口。

例如，Go 包括名为`Stringer`的内置接口，定义如下：

```go
type Stringer interface { 
    String() string 
} 

```

任何具有附加`String()`方法的类型都会自动实现`Stringer`接口。因此，修改前一个程序中类型`metalloid`的定义，以附加`String()`方法将自动实现`Stringer`接口：

```go
type metalloid struct { 
    name string 
    number int32 
    weight amu 
} 
func (m metalloid) String() string { 
  return fmt.Sprintf( 
    "%-10s %-10d %-10.3f %e", 
    m.name, m.number, m.weight.float(), atoms(moles(m.weight)), 
  ) 
}  

```

golang.fyi/ch01/metalloids2.go

`String()`方法返回表示`metalloid`值的预格式化字符串。标准库包`fmt`中的`Print()`函数将自动调用方法`String()`，如果其参数实现了`stringer`。因此，我们可以利用这一点将`metalloid`值打印如下：

```go
func main() { 
  fmt.Print(headers()) 
  for _, m := range metalloids { 
    fmt.Print(m, "\n") 
  } 
} 

```

再次参考第八章，“方法、接口和对象”，对接口主题进行深入讨论。

## 并发和通道

将 Go 推向当前采用水平的主要特性之一是其固有支持简单并发习语。该语言使用一种称为`goroutine`的并发单元，它允许程序员使用独立和高度并发的代码结构化程序。

正如您将在以下示例中看到的，Go 还依赖于一种称为通道的构造，用于独立运行的`goroutine`之间的通信和协调。这种方法避免了通过共享内存进行线程通信的危险和（有时脆弱的）传统方法。相反，Go 通过使用通道促进了通过通信共享的方法。下面的示例说明了使用`goroutine`和通道作为处理和通信原语：

```go
// Calculates sum of all multiple of 3 and 5 less than MAX value. 
// See https://projecteuler.net/problem=1 
package main 

import ( 
  "fmt" 
) 

const MAX = 1000 

func main() { 
  work := make(chan int, MAX) 
  result := make(chan int) 

  // 1\. Create channel of multiples of 3 and 5 
  // concurrently using goroutine 
  go func(){ 
    for i := 1; i < MAX; i++ { 
      if (i % 3) == 0 || (i % 5) == 0 { 
        work <- i // push for work 
      } 
    } 
    close(work)  
  }() 

  // 2\. Concurrently sum up work and put result 
  //    in channel result  
  go func(){ 
    r := 0 
    for i := range work { 
      r = r + i 
    } 
    result <- r 
  }() 

  // 3\. Wait for result, then print 
  fmt.Println("Total:", <- result) 
} 

```

golang.fyi/ch01/euler1.go

前面示例中的代码将要做的工作分成了两个并发运行的`goroutine`（使用`go`关键字声明），如代码注释所示。每个`goroutine`都独立运行，并使用 Go 通道`work`和`result`来通信和协调计算最终结果。再次强调，如果这段代码一点也不清楚，放心，整个第九章，“并发”都专门讨论了并发。

## 内存管理和安全性

与其他编译和静态类型语言（如 C 和 C++）类似，Go 允许开发人员直接影响内存分配和布局。例如，当开发人员创建字节的`slice`（类似`array`）时，这些字节在机器的底层物理内存中有直接的表示。此外，Go 借用指针的概念来表示存储值的内存地址，使得 Go 程序可以支持通过值和引用传递函数参数。

Go 在内存管理周围设定了高度主观的安全屏障，几乎没有可配置的参数。Go 使用运行时垃圾收集器自动处理内存分配和释放的繁琐工作。指针算术在运行时不被允许；因此，开发人员不能通过增加或减少基本内存地址来遍历内存块。

## 快速编译

Go 的另一个吸引力是对中等规模项目的毫秒级构建时间。这得益于诸如简单的语法、无冲突的语法和严格的标识符解析等功能，这些功能禁止未使用的声明资源，如导入的包或变量。此外，构建系统使用依赖树中最近的源节点中存储的传递性信息来解析包。这再次使得代码-编译-运行周期更像是动态语言而不是编译语言。

## 测试和代码覆盖

虽然其他语言通常依赖于第三方工具进行测试，但 Go 包括专门用于自动化测试、基准测试和代码覆盖的内置 API 和工具。与 Go 中的其他功能类似，测试工具使用简单的约定自动检查和检测代码中找到的测试函数。

以下函数是欧几里德除法算法的简单实现，返回正整数的商和余数值（作为变量`q`和`r`）：

```go
func DivMod(dvdn, dvsr int) (q, r int) { 
  r = dvdn 
  for r >= dvsr { 
    q += 1 
    r = r - dvsr 
  } 
  return 
} 

```

golang.fyi/ch01/testexample/divide.go

在单独的源文件中，我们可以编写一个测试函数，通过使用 Go 测试 API 检查被测试函数返回的余数值来验证算法，如下面的代码所示：

```go
package testexample 
import "testing" 
func TestDivide(t *testing.T) { 
  dvnd := 40 
    for dvsor := 1; dvsor < dvnd; dvsor++ { 
      q, r := DivMod(dvnd, dvsor) 
  if (dvnd % dvsor) != r { 
    t.Fatalf("%d/%d q=%d, r=%d, bad remainder.", dvnd, dvsor, q, r) 
    } 
  } 
}  

```

golang.fyi/ch01/testexample/divide_test.go

要运行测试源代码，只需按照以下示例运行 Go 的测试工具：

```go
$> go test . 
ok   github.com/vladimirvivien/learning-go/ch01/testexample  0.003s

```

测试工具报告测试结果的摘要，指示已测试的包及其通过/失败的结果。Go 工具链配备了许多其他功能，旨在帮助程序员创建可测试的代码，包括：

+   在测试期间自动检测代码以收集覆盖统计信息

+   生成覆盖代码和测试路径的 HTML 报告

+   一个基准 API，允许开发人员从测试中收集性能指标

+   具有有价值的指标的基准报告，用于检测性能问题

您可以在第十二章*代码测试*中了解有关测试及其相关工具的所有信息。

## 文档

文档在 Go 中是一流的组件。可以说，该语言的流行部分原因是其广泛的文档（参见[`golang.org/pkg`](http://golang.org/pkg)）。Go 配备了 Godoc 工具，可以轻松地从源代码中直接嵌入的注释文本中提取文档。例如，要为上一节中的函数编写文档，我们只需在`DivMod`函数上方直接添加注释行，如下例所示：

```go
// DivMod performs a Eucledan division producing a quotient and remainder. 
// This version only works if dividend and divisor > 0\. 
func DivMod(dvdn, dvsr int) (q, r int) { 
... 
}
```

Go 文档工具可以自动提取和创建 HTML 格式的页面。例如，以下命令将在`localhost 端口 6000`上启动 Godoc 工具作为服务器：

```go
$> godoc -http=":6001"

```

然后，您可以直接从 Web 浏览器访问代码的文档。例如，以下图显示了位于`http://localhost:6001/pkg/github.com/vladimirvivien/learning-go/ch01/testexample/`的先前函数的生成文档片段：

![文档](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/image_01_003.jpg)

## 一个广泛的库

在其短暂的存在中，Go 迅速发展了一套高质量的 API 集合，作为其标准库的一部分，这些 API 与其他流行和更成熟的语言相媲美。以下列出了一些核心 API 的列表，当然这并不是详尽无遗的：

+   完全支持具有搜索和替换功能的正则表达式

+   用于读写字节的强大 IO 原语

+   完全支持网络编程，包括套接字、TCP/UDP、IPv4 和 IPv6

+   用于编写生产就绪的 HTTP 服务和客户端的 API

+   支持传统的同步原语（互斥锁、原子等）

+   具有 HTML 支持的通用模板框架

+   支持 JSON/XML 序列化

+   具有多种传输格式的 RPC

+   存档和压缩算法的 API：`tar`，`zip`/`gzip`，`zlib`等

+   大多数主要算法和哈希函数的加密支持

+   访问操作系统级别的进程、环境信息、信号等等

## Go 工具链

在我们结束本章之前，应该强调 Go 的一个方面，那就是它的工具集。虽然本章的前几节已经提到了一些工具，但其他工具在这里列出以供您了解：

+   `fmt`：重新格式化源代码以符合标准

+   `vet`：报告源代码构造的不当使用

+   `lint`：另一个源代码工具，报告 flagrant 风格违规

+   `goimports`：分析和修复源代码中的包导入引用

+   `godoc`：生成和组织源代码文档

+   `generate`：从存储在源代码中的指令生成 Go 源代码

+   `get`：远程检索和安装包及其依赖项

+   `build`：编译指定包及其依赖项中的代码

+   `run`：提供编译和运行您的 Go 程序的便利

+   `test`：执行单元测试，并支持基准和覆盖率报告

+   `oracle` 静态分析工具：查询源代码结构和元素

+   `cgo`：生成用于 Go 和 C 之间互操作性的源代码

# 总结

在其相对较短的存在期内，Go 已经赢得了许多重视简单性的采用者的心。正如您从本章的前几节中所看到的，很容易开始编写您的第一个 Go 程序。

本章还向读者介绍了 Go 最重要特性的高级摘要，包括其简化的语法、对并发性的强调以及使 Go 成为软件工程师首选的工具，为数据中心计算时代创建系统。正如您所想象的那样，这只是即将到来的一小部分。

在接下来的章节中，本书将继续详细探讨使 Go 成为一个很棒的学习语言的语法元素和语言概念。让我们开始吧！


# 第二章：Go 语言基础

在前一章中，我们确定了使 Go 成为一个用于创建现代系统程序的优秀语言的基本特征。在本章中，我们将深入探讨语言的语法，以探索其组件和特性。

我们将涵盖以下主题：

+   Go 源文件

+   标识符

+   变量

+   常量

+   运算符

# Go 源文件

我们在第一章中看到了一些 Go 程序的例子。在本节中，我们将研究 Go 源文件。让我们考虑以下源代码文件（它以不同的语言打印了`"Hello World"`问候）：

![Go 源文件](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/B03676_02_Helloworld2-source.jpg)

golang.fyi/ch02/helloworld2.go

一个典型的 Go 源文件，比如前面列出的那个，可以分为三个主要部分，如下所示：

+   **包声明**：

```go
      //1 Package Clause 
      package main 

```

+   **导入声明**：

```go
      //2 Import Declaration 
      import "fmt" 
      import "math/rand" 
      import "time" 

```

+   **源代码主体**：

```go
      //3 Source Body 
      var greetings = [][]string{ 
        {"Hello, World!","English"}, 
        ... 
      } 

      func greeting() [] string { 
        ... 
      } 

      func main() { 
        ... 
      } 

```

**包**声明指示了这个源文件所属的包的名称（参见第六章，Go *包和程序*中对包组织的详细讨论）。**导入**声明列出了源代码希望使用的任何外部包。Go 编译器严格执行包声明的使用。在你的源文件中包含一个未使用的包被认为是一个错误（编译）。源文件的最后部分被认为是源文件的主体。在这里你声明变量、常量、类型和函数。

所有的 Go 源文件都必须以`.go`后缀结尾。一般来说，你可以随意命名一个 Go 源文件。与 Java 不同，例如，Go 文件名和其内容中声明的类型之间没有直接关联。然而，将文件命名为与其内容相关的名称被认为是一个良好的做法。

在我们更详细地探讨 Go 的语法之前，了解语言的一些基本结构元素是很重要的。虽然其中一些元素在语法上被固定在语言中，但其他一些只是简单的习惯和约定，你应该了解这些以使你对 Go 的介绍简单而愉快。

## 可选的分号

你可能已经注意到，Go 不需要分号作为语句分隔符。这是从其他更轻量级和解释性语言中借鉴来的特点。以下两个程序在功能上是等价的。第一个程序使用了典型的 Go，并省略了分号：

![可选的分号](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/B03736_02_Helloworld-snippet1.jpg)

程序的第二个版本，如下所示，使用了多余的分号来显式终止其语句。虽然编译器可能会感谢你的帮助，但这在 Go 中并不是惯用法：

![可选的分号](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/B03676_02_Helloworld-snippet2-1.jpg)

尽管 Go 中的分号是可选的，但 Go 的正式语法仍要求它们作为语句终止符。因此，Go 编译器会在以下以以下结尾的源代码行末尾插入分号：

+   一个标识符

+   字符串、布尔、数字或复数的文字值

+   控制流指令，比如 break、continue 或 return

+   一个闭括号，比如`)`、`}`或`]`

+   增量`++`或减量`--`运算符

由于这些规则，编译器强制执行严格的语法形式，这严重影响了 Go 中源代码的风格。例如，所有的代码块必须以与其前一个语句相同行的开放大括号`{`开始。否则，编译器可能会在破坏代码的位置插入分号，如下面的`if`语句所示：

```go
func main() { 
    if "a" == "a" 
    { 
      fmt.Println("Hello, World!") 
    } 
} 

```

将大括号移到下一行会导致编译器过早地插入分号，这将导致以下语法错误：

```go
$> ... missing condition in if statement ... 

```

这是因为编译器在 `if` 语句之后插入了分号（`if "a"=="a";`），使用了本节讨论的分号插入规则。您可以通过在 `if` 条件语句之后手动插入分号来验证这一点；您将得到相同的错误。这是一个很好的过渡到下一节的地方，讨论代码块中的尾随逗号。

## 多行

将表达式分解为多行必须遵循前一节讨论的分号规则。主要是，在多行表达式中，每一行必须以一个标记结尾，以防止过早插入分号，如下表所示。应该注意的是，表中具有无效表达式的行将无法编译：

| **表达式** | **有效** |
| --- | --- |

|

```go
lonStr := "Hello World! " +
"How are you?"

```

| 是的，`+` 运算符阻止了过早插入分号。 |
| --- |

|

```go
lonStr := "Hello World! "
+ "How are you?"

```

| 不，第一行后会插入一个分号，语义上会断开这一行。 |
| --- |

|

```go
fmt.Printf("[%s] %d %d %v",
str,
num1,
num2,
nameMap)

```

| 是的，逗号正确地断开了表达式。 |
| --- |

|

```go
fmt.Printf("[%s] %d %d %v",
str,
num1,
num2,
nameMap)

```

| 是的，编译器只在最后一行后插入了一个分号。 |
| --- |

|

```go
weekDays := []string{
"Mon", "Tue",
"Wed", "Thr",
"Fri"
}

```

| 不，`Fri` 行导致了过早插入分号。 |
| --- |

|

```go
weekDays2 := []string{
"Mon", "Tue",
"Wed", "Thr",
"Fri",
}

```

| 是的，`Fri` 行包含了一个尾随逗号，这导致编译器在下一行插入了一个分号。 |
| --- |
| `weekDays1 := []string{``"Mon", "Tue",``"Wed", "Thr",``"Fri"}` | 是的，在闭括号后的那一行会插入分号。 |

您可能会想为什么 Go 编译器要求开发人员提供换行提示来指示语句的结束。当然，Go 的设计者本可以设计一个复杂的算法来自动解决这个问题。是的，他们可以。然而，通过保持语法简单和可预测，编译器能够快速解析和编译 Go 源代码。

### 注意

Go 工具链包括 gofmt 工具，可以用于一致地应用正确的格式规则到您的源代码。还有 `govet` 工具，它通过分析代码元素的结构问题，可以更深入地分析您的代码。

# Go 标识符

Go 标识符用于命名程序元素，包括包、变量、函数和类型。以下总结了 Go 中标识符的一些属性：

+   标识符支持 Unicode 字符集

+   标识符的第一个位置必须是字母或下划线

+   惯用的 Go 喜欢混合大小写（驼峰命名）

+   包级别的标识符必须在给定包中是唯一的

+   标识符必须在代码块（函数、控制语句）内是唯一的

## 空白标识符

Go 编译器对于变量或包的声明标识符的使用特别严格。基本规则是：*你声明了它，你必须使用它*。如果您尝试编译带有未使用的标识符（如变量或命名包）的代码，编译器将不会满意并且编译失败。

Go 允许您使用空白标识符（表示为 `_`（下划线）字符）关闭此行为。使用空白标识符的任何声明或赋值都不绑定到任何值，并且在编译时会被忽略。空白标识符通常用于以下两个上下文中，如下一小节中所列出的。

## 消除包导入

当包声明之前有一个下划线时，编译器允许声明该包而不需要进一步引用：

```go
import "fmt" 
import "path/filepath" 
import _ "log" 

```

在前面的代码片段中，包 `log` 将在代码中没有进一步引用的情况下被消除。这在开发新代码时可能是一个方便的功能，开发人员可能希望尝试新的想法，而不必不断地注释或删除声明。尽管具有空白标识符的包不绑定到任何引用，但 Go 运行时仍会初始化它。第六章，*Go 包和程序*，讨论了包初始化的生命周期。

## 消除不需要的函数结果

当 Go 函数调用返回多个值时，返回列表中的每个值都必须分配给一个变量标识符。然而，在某些情况下，可能希望消除返回列表中不需要的结果，同时保留其他结果，如下所示：

```go
_, execFile := filepath.Split("/opt/data/bigdata.txt")
```

先前对函数`filepath.Split("/opt/data/bigdata.txt")`的调用接受一个路径并返回两个值：第一个是父路径（`/opt/data`），第二个是文件名（`bigdata.txt`）。第一个值被分配给空白标识符，因此未绑定到命名标识符，这导致编译器忽略它。在未来的讨论中，我们将探讨这种习惯用法在其他上下文中的其他用途，比如错误处理和`for`循环。

## 内置标识符

Go 带有许多内置标识符。它们属于不同的类别，包括类型、值和内置函数。

### 类型

以下标识符用于 Go 的内置类型：

| **类别** | **标识符** |
| --- | --- |
| 数字 | `byte`，`int`，`int8`，`int16`，`int32`，`int64`，`rune`，`uint`，`uint8`，`uint16`，`uint32`，`uint64`，`float32`，`float64`，`complex64`，`complex128`，`uintptr` |
| 字符串 | `string` |
| 布尔 | `bool` |
| 错误 | `error` |

### 值

这些标识符具有预分配的值：

| **类别** | **标识符** |
| --- | --- |
| 布尔常量 | `true`，`false` |
| 常量计数器 | `iota` |
| 未初始化值 | `nil` |

### 函数

以下函数作为 Go 的内置预声明标识符的一部分可用：

| **类别** | **标识符** |
| --- | --- |
| 初始化 | `make()`，`new()` |
| 集合 | `append()`，`cap()`，`copy()`，`delete()` |
| 复数 | `complex()`，`imag()`，`real()` |
| 错误处理 | `panic()`，`recover()` |

# Go 变量

Go 是一种严格类型的语言，这意味着所有变量都是绑定到值和类型的命名元素。正如你将看到的，它的语法的简单性和灵活性使得在 Go 中声明和初始化变量更像是一种动态类型的语言。

## 变量声明

在 Go 中使用变量之前，必须使用命名标识符声明它以便在代码中将来引用。在 Go 中变量声明的长格式遵循以下格式：

```go
*var <identifier list> <type>*

```

`var`关键字用于声明一个或多个变量标识符，后面跟着变量的类型。以下源代码片段显示了一个缩写程序，其中声明了几个变量，这些变量在`main()`函数之外声明：

```go
package main 

import "fmt" 

var name, desc string 
var radius int32 
var mass float64 
var active bool 
var satellites []string 

func main() { 
  name = "Sun" 
  desc = "Star" 
  radius = 685800 
  mass = 1.989E+30 
  active = true 
  satellites = []string{ 
    "Mercury", 
    "Venus", 
    "Earth", 
    "Mars", 
    "Jupiter", 
    "Saturn", 
    "Uranus", 
    "Neptune", 
  } 
  fmt.Println(name) 
  fmt.Println(desc) 
  fmt.Println("Radius (km)", radius) 
  fmt.Println("Mass (kg)", mass) 
  fmt.Println("Satellites", satellites) 
} 

```

golang.fyi/ch02/vardec1.go

## 零值

先前的源代码显示了使用各种类型声明变量的几个示例。然后在`main()`函数内为变量赋值。乍一看，这些声明的变量在声明时似乎没有被赋值。这将与我们先前的断言相矛盾，即所有 Go 变量都绑定到类型和值。

我们如何声明一个变量而不将值绑定到它？在变量声明期间，如果没有提供值，Go 将自动将默认值（或零值）绑定到变量以进行适当的内存初始化（我们稍后将看到如何在一个表达式中进行声明和初始化）。

以下表格显示了 Go 类型及其默认零值：

| **类型** | **零值** |
| --- | --- |
| `string` | `""`（空字符串） |
| 数字 - 整数：`byte`，`int`，`int8`，`int16`，`int32`，`int64`，`rune`，`uint`，`uint8`，`uint16`，`uint32`，`uint64`，`uintptr` | 0 |
| 数字 - 浮点数：`float32`，`float64` | 0.0 |
| `bool` | false |
| `Array` | 每个索引位置都有一个与数组元素类型相对应的零值。 |
| `Struct` | 一个空的`struct`，每个成员都具有其相应的零值。 |
| 其他类型：接口、函数、通道、切片、映射和指针 | nil |

## 初始化声明

如前所述，Go 还支持使用以下格式将变量声明和初始化组合为一个表达式：

*var <标识符列表> <类型> = <值列表或初始化表达式>*

这种声明格式具有以下特性：

+   等号左侧提供的标识符列表（后跟类型）

+   右侧有匹配的逗号分隔值列表

+   赋值按标识符和值的相应顺序进行

+   初始化表达式必须产生匹配的值列表

以下是声明和初始化组合的简化示例：

```go
var name, desc string = "Earth", "Planet" 
var radius int32 = 6378 
var mass float64 = 5.972E+24 
var active bool = true 
var satellites = []string{ 
  "Moon", 
} 

```

golang.fyi/ch02/vardec2.go

## 省略变量类型

到目前为止，我们已经讨论了 Go 的变量声明和初始化的长格式。为了使语言更接近其动态类型的表亲，可以省略类型规范，如下所示：

*var <标识符列表> = <值列表或初始化表达式>*

在编译期间，编译器根据等号右侧的赋值或初始化表达式推断变量的类型，如下例所示。

```go
var name, desc = "Mars", "Planet" 
var radius = 6755 
var mass = 641693000000000.0 
var active = true 
var satellites = []string{ 
  "Phobos", 
  "Deimos", 
} 

```

golang.fyi/ch02/vardec3.go

如前所述，当变量被赋值时，必须同时接收一个类型和该值。当省略变量的类型时，类型信息是从分配的值或表达式的返回值中推断出来的。以下表格显示了给定文字值时推断出的类型：

| **文字值** | **推断类型** |
| --- | --- |
| 双引号或单引号（原始）文本：`"火星行星"``"所有行星都围绕太阳运转。"` | `string` |
| 整数：`-76`0`1244``1840` | `int` |
| 小数：`-0.25``4.0``3.1e4``7e-12` | `float64` |
| 复数：`-5.0i``3i``(0+4i)` | `complex128` |
| 布尔值：`true``false` | `bool` |
| 数组值：`[2]int{-76, 8080}` | 在文字值中定义的`数组`类型。在这种情况下是：`[2]int` |
| 映射值：`map[string]int{``  "Sun": 685800,``  "Earth": 6378,``  "Mars": 3396,``}` | 在文字值中定义的映射类型。在这种情况下是：`map[string]int` |
| 切片值：`[]int{-76, 0, 1244, 1840}` | 在文字值中定义的`切片`类型：`[]int` |
| 结构值：`struct{``  name string``  diameter int}``{``  "Mars", 3396,``}` | 在文字值中定义的`结构`类型。在这种情况下，类型是：`struct{name string; diameter int}` |
| 函数值：`var sqr = func (v int)   int {``  return v * v``}` | 在函数定义文字中定义的函数类型。在这种情况下，变量`sqr`的类型将是：`func (v int) int` |

## 短变量声明

Go 可以进一步减少变量声明语法，使用*短变量声明*格式。在这种格式中，声明不再使用 var 关键字和类型规范，而是使用赋值运算符`:=`（冒号等于），如下所示：

*<标识符列表> := <值列表或初始化表达式>*

这是一个简单而清晰的习惯用语，在 Go 中声明变量时通常使用。以下代码示例显示了短变量声明的用法：

```go
func main() { 
    name := "Neptune" 
    desc := "Planet" 
    radius := 24764 
    mass := 1.024e26 
    active := true 
    satellites := []string{ 
         "Naiad", "Thalassa", "Despina", "Galatea", "Larissa", 
     "S/2004 N 1", "Proteus", "Triton", "Nereid", "Halimede", 
         "Sao", "Laomedeia", "Neso", "Psamathe", 
    } 
... 
} 

```

golang.fyi/ch02/vardec4.go

请注意，关键字`var`和变量类型在声明中被省略。短变量声明使用了先前讨论的相同机制来推断变量的类型。

## 短变量声明的限制

为了方便起见，变量声明的简短形式确实带有一些限制，您应该注意以避免混淆：

+   首先，它只能在函数块内使用

+   赋值运算符`:=`，声明变量并赋值

+   `:=`不能用于更新先前声明的变量

+   变量的更新必须使用等号

尽管这些限制可能有其根源于 Go 语法的简单性的理由，但它们通常被视为对语言新手的一个困惑来源。例如，冒号等号运算符不能与包级别的变量赋值一起使用。学习 Go 的开发人员可能会发现使用赋值运算符来更新变量是一种诱人的方式，但这将导致编译错误。

## 变量作用域和可见性

Go 使用基于代码块的词法作用域来确定包内变量的可见性。根据变量声明的位置在源文本中，将确定其作用域。一般规则是，变量只能在声明它的块内访问，并对所有嵌套的子块可见。

以下截图说明了在源文本中声明的几个变量的作用域（`package`，`function`，`for`循环和`if...else`块）：

![变量作用域和可见性](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/B036376_02_01.jpg)

golang.fyi/ch02/makenums.go

如前所述，变量的可见性是自上而下的。包范围的变量，如`mapFile`和`numbersFile`，对包中的所有其他元素都是全局可见的。向下移动作用域梯级，函数块变量，如`data`和`err`，对函数中的所有元素以及包括子块在内的所有元素都是可见的。内部`for`循环块中的变量`i`和`b`只在该块内可见。一旦循环结束，`i`和`b`就会超出作用域。

### 注意

对于 Go 的新手来说，包范围变量的可见性是一个令人困惑的问题。当一个变量在包级别（在函数或方法块之外）声明时，它对整个包都是全局可见的，而不仅仅是变量声明的源文件。这意味着包范围的变量标识符只能在组成包的文件组中声明一次，这一点对于刚开始使用 Go 的开发人员可能并不明显。有关包组织的详细信息，请参阅第六章，“Go 包和程序”。

## 变量声明块

Go 的语法允许将顶级变量的声明组合到块中，以提高可读性和代码组织性。以下示例展示了使用变量声明块重写先前示例的方式：

```go
var ( 
  name string = "Earth" 
  desc string = "Planet" 
  radius int32 = 6378 
  mass float64 = 5.972E+24 
  active bool = true 
  satellites []string   
) 

```

golang.fyi/ch02/vardec5.go

# Go 常量

在 Go 中，常量是具有文字表示的值，例如文本字符串，布尔值或数字。常量的值是静态的，不能在初始赋值后更改。尽管它们所代表的概念很简单，但常量具有一些有趣的属性，使它们在处理数值时特别有用。

## 常量文字

常量是可以用语言中的文本文字表示的值。常量最有趣的一个属性是它们的文字表示可以被视为有类型或无类型的值。与变量不同，常量可以以无类型值的形式存储在内存空间中。没有类型约束，例如，数值常量值可以以极高的精度存储。

以下是可以在 Go 中表示的有效常量文字值的示例：

```go
"Mastering Go" 
'G' 
false 
111009 
2.71828 
94314483457513374347558557572455574926671352 1e+500 
5.0i 

```

## 有类型的常量

Go 常量值可以使用常量声明绑定到命名标识符。与变量声明类似，Go 使用`const`关键字来指示常量的声明。但是，与变量不同，声明必须包括要绑定到标识符的文字值，如下所示：

*const <标识符列表> 类型 = <值列表或初始化表达式>*

常量不能有任何需要运行时解析的依赖关系。编译器必须能够在编译时解析常量的值。这意味着所有常量必须声明并用值文字（或导致常量值的表达式）初始化。

以下代码片段显示了一些已声明的有类型常量：

```go
const a1, a2 string = "Mastering", "Go" 
const b rune = 'G' 
const c bool = false 
const d int32 = 111009 
const e float32 = 2.71828 
const f float64 = math.Pi * 2.0e+3 
const g complex64 = 5.0i 
const h time.Duration = 4 * time.Second 

```

golang.fyi/ch02/const.go

请注意在前面的源代码片段中，每个声明的常量标识符都明确给出了一个类型。正如您所期望的那样，这意味着常量标识符只能在与其类型兼容的上下文中使用。然而，下一节将解释当常量声明中省略类型时，这是如何工作的。

## 无类型常量

当无类型常量时，常量声明如下：

*const <标识符列表> = <值列表或初始化表达式>*

与以前一样，关键字`const`用于声明一系列标识符作为常量以及它们的相应的边界值。然而，在这种格式中，类型规范在声明中被省略。作为一个无类型实体，常量只是内存中的一块字节，没有任何类型精度限制。以下显示了一些无类型常量的示例声明：

```go
const i = "G is" + " for Go " 
const j = 'V' 
const k1, k2 = true, !k1 
const l = 111*100000 + 9 
const m1 = math.Pi / 3.141592 
const m2 = 1.414213562373095048801688724209698078569671875376... 
const m3 = m2 * m2 
const m4 = m3 * 1.0e+400 
const n = -5.0i * 3 
const o = time.Millisecond * 5 

```

golang.fyi/ch02/const.go

从前面的代码片段中，无类型常量`m2`被分配了一个长的十进制值（截断以适应打印页面，因为它还有另外 17 位数字）。常量`m4`被分配了一个更大的数字`m3 x 1.0e+400`。生成常量的整个值存储在内存中，没有任何精度损失。这对于对精度要求很高的计算感兴趣的开发人员来说可能是一个非常有用的工具。

## 分配无类型常量

无类型常量值在分配给变量、用作函数参数或作为分配给变量的表达式的一部分之前是有限的。在像 Go 这样的强类型语言中，这意味着可能需要进行一些类型调整，以确保存储在常量中的值可以正确地分配给目标变量。使用无类型常量的一个优点是，类型系统放宽了对类型检查的严格应用。无类型常量可以被分配给不同但兼容的不同精度的类型，而不会引起编译器的任何投诉，如下例所示：

```go
const m2 = 1.414213562373095048801688724209698078569671875376... 
var u1 float32 = m2 
var u2 float64 = m2 
u3 := m2 

```

前面的代码片段显示了无类型常量`m2`被分配给两个不同浮点精度的变量`u1`和`u2`，以及一个无类型变量`u3`。这是可能的，因为常量`m2`被存储为一个原始的无类型值，因此可以分配给与其表示兼容的任何变量（一个浮点数）。

虽然类型系统将容纳`m2`分配给不同精度的变量，但所得到的分配将被调整以适应变量类型，如下所示：

```go
u1 = 1.4142135      //float32 
u2 = 1.4142135623730951   //float64 

```

那么变量`u3`呢，它本身是一个无类型变量？由于`u3`没有指定类型，它将依赖于常量值的类型推断来接收类型分配。回想一下之前在*省略变量类型*部分的讨论，常量文字根据它们的文本表示映射到基本的 Go 类型。由于常量`m2`表示一个十进制值，编译器将推断其默认为`float64`，这将自动分配给变量`u3`，如下所示：

```go
U3 = 1.4142135623730951  //float64 

```

正如您所看到的，Go 对无类型原始常量文字的处理通过自动应用一些简单但有效的类型推断规则，增加了语言的可用性，而不会牺牲类型安全性。与其他语言不同，开发人员不必在值文字中明确指定类型或执行某种类型转换来使其工作。

## 常量声明块

正如您可能已经猜到的那样，常量声明可以组织为代码块以增加可读性。前面的示例可以重写如下：

```go
const ( 
  a1, a2 string        = "Mastering", "Go" 
  b      rune          = 'G' 
  c      bool          = false 
  d      int32         = 111009 
  e      float32       = 2.71828 
  f      float64       = math.Pi * 2.0e+3 
  g      complex64     = 5.0i 
  h      time.Duration = 4 * time.Second 
... 
) 

```

golang.fyi/ch02/const2.go

## 常量枚举

常量的一个有趣用法是创建枚举值。使用声明块格式（在前面的部分中显示），您可以轻松地创建数字递增的枚举整数值。只需将预先声明的常量值`iota`分配给声明块中的常量标识符，如下面的代码示例所示：

```go
const ( 
  StarHyperGiant = iota 
  StarSuperGiant 
  StarBrightGiant 
  StarGiant 
  StarSubGiant 
  StarDwarf 
  StarSubDwarf 
  StarWhiteDwarf 
  StarRedDwarf 
  StarBrownDwarf 
) 

```

golang.fyi/ch02/enum0.go

然后编译器会自动执行以下操作：

+   将块中的每个成员声明为无类型整数常量值

+   用值 0 初始化`iota`

+   将`iota`或零分配给第一个常量成员（`StarHyperGiant`）

+   每个后续常量都被分配一个增加了一的`int`值

因此，以前的常量列表将被分配一个从零到九的值序列。每当`const`出现为声明块时，它将计数器重置为零。在下面的代码片段中，每组常量都分别从零到四进行枚举：

```go
const ( 
  StarHyperGiant = iota 
  StarSuperGiant 
  StarBrightGiant 
  StarGiant 
  StarSubGiant 
) 
const ( 
  StarDwarf = iota 
  StarSubDwarf 
  StarWhiteDwarf 
  StarRedDwarf 
  StarBrownDwarf 
) 

```

golang.fyi/ch02/enum1.go

## 覆盖默认枚举类型

默认情况下，枚举常量被声明为无类型整数值。但是，您可以通过为枚举常量提供显式数字类型来覆盖枚举值的默认类型，如下面的代码示例所示：

```go
const ( 
  StarDwarf byte = iota 
  StarSubDwarf 
  StarWhiteDwarf 
  StarRedDwarf 
  StarBrownDwarf 
) 

```

您可以指定可以表示整数或浮点值的任何数字类型。例如，在前面的代码示例中，每个常量将被声明为类型`byte`。

## 在表达式中使用 iota

当`iota`出现在表达式中时，相同的机制会按预期工作。编译器将对每个递增的`iota`值应用表达式。以下示例将偶数分配给常量声明块的枚举成员：

```go
const ( 
  StarHyperGiant = 2.0*iota 
  StarSuperGiant 
  StarBrightGiant 
  StarGiant 
  StarSubGiant 
) 

```

golang.fyi/ch02/enum2.go

正如您所期望的那样，前面的示例为每个枚举常量分配了一个偶数值，从 0 开始，如下面的输出所示：

```go
 StarHyperGiant = 0    [float64]
    StarSuperGiant = 2    [float64]
    StarBrightGiant = 4   [float64]
    StarGiant = 6         [float64]
    StarSubGiant = 8      [float64] 

```

## 跳过枚举值

在使用枚举常量时，您可能希望丢弃不应成为枚举一部分的某些值。这可以通过将 iota 分配给枚举中所需位置的空白标识符来实现。例如，以下内容跳过了值 0 和`64`：

```go
_              = iota    // value 0 
StarHyperGiant = 1 << iota 
StarSuperGiant 
StarBrightGiant 
StarGiant 
StarSubGiant 
_          // value 64 
StarDwarf 
StarSubDwarf 
StarWhiteDwarf 
StarRedDwarf 
StarBrownDwarf 

```

golang.fyi/ch02/enum3.go

由于我们跳过了`iota`位置`0`，第一个分配的常量值位于位置`1`。这导致表达式`1 << iota`解析为`1 << 1 = 2`。在第六个位置也是同样的情况，表达式`1 << iota`返回`64`。该值将被跳过，不会被分配给任何常量，如下面的输出所示：

```go
 StarHyperGiant = 2
    StarSuperGiant = 4
    StarBrightGiant = 8
    StarGiant = 16
    StarSubGiant = 32
    StarDwarf = 128
    StarSubDwarf = 256
    StarWhiteDwarf = 512
    StarRedDwarf = 1024
    StarBrownDwarf = 2048 

```

# Go 运算符

忠实于其简单的本质，Go 中的运算符确切地执行您所期望的操作，主要是允许操作数组合成表达式。与 C++或 Scala 中发现的运算符重载不同，Go 运算符没有隐藏的意外行为。这是设计者故意做出的决定，以保持语言的语义简单和可预测。

本节探讨了您在开始使用 Go 时会遇到的最常见的运算符。其他运算符将在本书的其他章节中介绍。

## 算术运算符

以下表总结了 Go 中支持的算术运算符。

| **运算符** | **操作** | **兼容类型** |
| --- | --- | --- |
| `*`，`/`，`-` | 乘法，除法和减法 | 整数，浮点数和复数 |
| `%` | 余数 | 整数 |
| 加法 | 整数，浮点数，复数和字符串（连接） |

请注意，加法运算符`+`可以应用于字符串，例如表达式`var i = "G is" + " for Go"`。这两个字符串操作数被连接以创建一个新的字符串，该字符串被分配给变量`i`。

## 增量和减量运算符

与其他类似 C 的语言一样，Go 支持`++`（增量）和`--`（减量）运算符。当应用时，这些运算符分别增加或减少操作数的值。以下是一个使用减量运算符以相反顺序遍历字符串 s 中的字母的函数示例：

```go
func reverse(s string) { 
  for i := len(s) - 1; i >= 0; { 
    fmt.Print(string(s[i])) 
    i-- 
  } 
} 

```

重要的是要注意，增量和减量运算符是语句，而不是表达式，如下面的示例所示：

```go
nextChar := i++       // syntax error 
fmt.Println("Current char", i--)   // syntax error 
nextChar++        // OK 

```

在前面的示例中，值得注意的是增量和减量语句只支持后缀表示法。以下代码段不会编译，因为有语句-`i`：

```go
for i := len(s) - 1; i >= 0; { 
  fmt.Print(string(s[i])) 
  --i   //syntax error 
} 

```

## Go 赋值运算符

| **运算符** | **描述** |
| --- | --- |
| `=` | 简单赋值按预期工作。它使用右侧的值更新左侧的操作数。 |
| `:=` | 冒号等号运算符声明一个新变量，左侧操作数，并将其赋值为右侧操作数的值（和类型）。 |
| `+=`, `-=`, `*=`, `/=`, `%=` | 使用左操作数和右操作数应用指定的操作，并将结果存储在左操作数中。例如，`a *= 8`意味着`a = a * 8`。 |

## 位运算符

Go 包括对操作值的最基本形式的完全支持。以下总结了 Go 支持的位运算符：

| **运算符** | **描述** |
| --- | --- |
| `&` | 位与 |
| `&#124;` | 位或 |
| `a ^ b` | 位异或 |
| `&^` | 位清空 |
| `^a` | 一元位补码 |
| `<<` | 左移 |
| 右移 |

在移位操作中，右操作数必须是无符号整数或能够转换为无符号值。当左操作数是无类型常量值时，编译器必须能够从其值中推导出有符号整数类型，否则将无法通过编译。

Go 中的移位运算符也支持算术和逻辑移位。如果左操作数是无符号的，Go 会自动应用逻辑移位，而如果它是有符号的，Go 将应用算术移位。

## 逻辑运算符

以下是关于布尔值的 Go 逻辑操作的列表：

| **运算符** | **操作** |
| --- | --- |
| `&&` | 逻辑与 |
| `&#124;&#124;` | 逻辑或 |
| `!` | 逻辑非 |

## 比较运算符

所有 Go 类型都可以进行相等性测试，包括基本类型和复合类型。然而，只有字符串、整数和浮点值可以使用排序运算符进行比较，如下表所总结的：

| **运算符** | **操作** | **支持的类型** |
| --- | --- | --- |
| `==` | 相等 | 字符串、数字、布尔、接口、指针和结构类型 |
| `!=` | 不等 | 字符串、数字、布尔、接口、指针和结构类型 |
| `<`, `<=`, `>`, `>=` | 排序运算符 | 字符串、整数和浮点数 |

## 运算符优先级

由于 Go 的运算符比 C 或 Java 等语言中的运算符要少，因此其运算符优先级规则要简单得多。以下表格列出了 Go 的运算符优先级，从最高开始：

| **操作** | **优先级** |
| --- | --- |
| 乘法 | `*`, `/`, `%`, `<<`, `>>`, `&`, `&^` |
| 加法 | `+`, `-`, `&#124;`, `^` |
| 比较 | `==`, `!=`, `<`, `<=`, `>`, `>=` |
| 逻辑与 | `&&` |
| 逻辑或 | `&#124;&#124;` |

# 总结

本章涵盖了 Go 语言的基本构造的许多内容。它从 Go 源代码文本文件的结构开始，并逐步介绍了变量标识符、声明和初始化。本章还广泛介绍了 Go 常量、常量声明和运算符。

此时，您可能会对语言及其语法的如此多的基本信息感到有些不知所措。好消息是，您不必了解所有这些细节才能有效地使用该语言。在接下来的章节中，我们将继续探讨关于 Go 的一些更有趣的部分，包括数据类型、函数和包。


# 第三章：Go 控制流

Go 从 C 语言家族中借用了几种控制流语法。它支持所有预期的控制结构，包括 if...else、switch、for 循环，甚至 goto。然而，明显缺少的是 while 或 do...while 语句。本章中的以下主题将讨论 Go 的控制流元素，其中一些您可能已经熟悉，而其他一些则带来了其他语言中没有的一组新功能：

+   if 语句

+   switch 语句

+   类型 Switch

+   for 语句

# if 语句

在 Go 中，if 语句从其他类似 C 的语言中借用了其基本结构形式。当跟随 if 关键字的布尔表达式求值为 true 时，该语句有条件地执行代码块，如下面简化的程序所示，该程序显示有关世界货币的信息：

```go
import "fmt" 

type Currency struct { 
  Name    string 
  Country string 
  Number  int 
} 

var CAD = Currency{ 
    Name: "Canadian Dollar",  
    Country: "Canada",  
    Number: 124} 

var FJD = Currency{ 
    Name: "Fiji Dollar",  
    Country: "Fiji",  
    Number: 242} 

var JMD = Currency{ 
    Name: "Jamaican Dollar",  
    Country: "Jamaica",  
    Number: 388} 

var USD = Currency{ 
    Name: "US Dollar",  
    Country: "USA",  
    Number: 840} 

func main() { 
  num0 := 242 
  if num0 > 100 || num0 < 900 { 
    fmt.Println("Currency: ", num0) 
    printCurr(num0) 
  } else { 
    fmt.Println("Currency unknown") 
  } 

  if num1 := 388; num1 > 100 || num1 < 900 { 
    fmt.Println("Currency:", num1) 
    printCurr(num1) 
  } 
} 

func printCurr(number int) { 
  if CAD.Number == number { 
    fmt.Printf("Found: %+v\n", CAD) 
  } else if FJD.Number == number { 
    fmt.Printf("Found: %+v\n", FJD) 
  } else if JMD.Number == number { 
    fmt.Printf("Found: %+v\n", JMD) 
  } else if USD.Number == number { 
    fmt.Printf("Found: %+v\n", USD) 
  } else { 
    fmt.Println("No currency found with number", number) 
  } 
} 

```

golang.fyi/ch03/ifstmt.go

Go 中的 if 语句看起来与其他语言相似。但是，它摒弃了一些语法规则，同时强制执行了一些新规则：

+   在测试表达式周围的括号是不必要的。虽然以下 if 语句将编译，但这不是惯用法：

```go
      if (num0 > 100 || num0 < 900) { 
        fmt.Println("Currency: ", num0) 
        printCurr(num0) 
      } 

```

+   使用以下代替：

```go
      if num0 > 100 || num0 < 900 { 
        fmt.Println("Currency: ", num0) 
        printCurr(num0) 
      } 

```

+   代码块的大括号始终是必需的。以下代码片段将无法编译：

```go
      if num0 > 100 || num0 < 900 printCurr(num0) 

```

+   然而，这将编译通过：

```go
      if num0 > 100 || num0 < 900 {printCurr(num0)} 

```

+   然而，惯用的、更清晰的编写 if 语句的方式是使用多行（无论语句块有多简单）。以下代码片段将无问题地编译通过：

```go
      if num0 > 100 || num0 < 900 {printCurr(num0)} 

```

+   然而，语句的首选惯用布局是使用多行，如下所示：

```go
      if num0 > 100 || num0 < 900 { 
        printCurr(num0) 
      }
```

+   if 语句可以包括一个可选的 else 块，当 if 块中的表达式求值为 false 时执行。else 块中的代码必须使用多行用大括号括起来，如下面的代码片段所示：

```go
      if num0 > 100 || num0 < 900 { 
        fmt.Println("Currency: ", num0) 
        printCurr(num0) 
      } else { 
        fmt.Println("Currency unknown") 
      } 

```

+   else 关键字后面可以紧接着另一个 if 语句，形成 if...else...if 链，就像前面列出的源代码中的 printCurr()函数中使用的那样：

```go
      if CAD.Number == number { 
        fmt.Printf("Found: %+v\n", CAD) 
      } else if FJD.Number == number { 
        fmt.Printf("Found: %+v\n", FJD) 
      } 

```

if...else...if 语句链可以根据需要增加，并且可以通过可选的 else 语句来终止，以表达所有其他未经测试的条件。同样，这是在 printCurr()函数中完成的，该函数使用 if...else...if 块测试四个条件。最后，它包括一个 else 语句块来捕获任何其他未经测试的条件：

```go
func printCurr(number int) { 
  if CAD.Number == number { 
    fmt.Printf("Found: %+v\n", CAD) 
  } else if FJD.Number == number { 
    fmt.Printf("Found: %+v\n", FJD) 
  } else if JMD.Number == number { 
    fmt.Printf("Found: %+v\n", JMD) 
  } else if USD.Number == number { 
    fmt.Printf("Found: %+v\n", USD) 
  } else { 
    fmt.Println("No currency found with number", number) 
  } 
}
```

然而，在 Go 中，编写这样深层 if...else...if 代码块的惯用且更清晰的方式是使用无表达式的 switch 语句。这将在*Switch 语句*部分中介绍。

## if 语句初始化

if 语句支持复合语法，其中被测试的表达式前面有一个初始化语句。在运行时，初始化在评估测试表达式之前执行，如前面列出的程序中所示：

```go
if num1 := 388; num1 > 100 || num1 < 900 { 
  fmt.Println("Currency:", num1) 
  printCurr(num1) 
}  

```

初始化语句遵循正常的变量声明和初始化规则。初始化变量的作用域绑定到 if 语句块，超出该范围后就无法访问。这是 Go 中常用的习惯用法，并且在本章中涵盖的其他流程控制结构中也得到支持。

# Switch 语句

Go 还支持类似于 C 或 Java 等其他语言中的 switch 语句。Go 中的 switch 语句通过评估 case 子句中的值或表达式来实现多路分支，如下面简化的源代码所示：

```go
import "fmt" 

type Curr struct { 
  Currency string 
  Name     string 
  Country  string 
  Number   int 
} 

var currencies = []Curr{ 
  Curr{"DZD", "Algerian Dinar", "Algeria", 12}, 
  Curr{"AUD", "Australian Dollar", "Australia", 36}, 
  Curr{"EUR", "Euro", "Belgium", 978}, 
  Curr{"CLP", "Chilean Peso", "Chile", 152}, 
  Curr{"EUR", "Euro", "Greece", 978}, 
  Curr{"HTG", "Gourde", "Haiti", 332}, 
  ... 
} 

func isDollar(curr Curr) bool { 
  var bool result 
  switch curr { 
  default: 
    result = false 
  case Curr{"AUD", "Australian Dollar", "Australia", 36}: 
    result = true 
  case Curr{"HKD", "Hong Kong Dollar", "Hong Koong", 344}: 
    result = true 
  case Curr{"USD", "US Dollar", "United States", 840}: 
    result = true 
  } 
  return result 
} 
func isDollar2(curr Curr) bool { 
  dollars := []Curr{currencies[2], currencies[6], currencies[9]} 
  switch curr { 
  default: 
    return false 
  case dollars[0]: 
    fallthrough 
  case dollars[1]: 
    fallthrough 
  case dollars[2]: 
    return true 
  } 
  return false 
} 

func isEuro(curr Curr) bool { 
  switch curr { 
  case currencies[2], currencies[4], currencies[10]: 
    return true 
  default: 
    return false 
  } 
} 

func main() { 
  curr := Curr{"EUR", "Euro", "Italy", 978} 
  if isDollar(curr) { 
    fmt.Printf("%+v is Dollar currency\n", curr) 
  } else if isEuro(curr) { 
    fmt.Printf("%+v is Euro currency\n", curr) 
  } else { 
    fmt.Println("Currency is not Dollar or Euro") 
  } 
  dol := Curr{"HKD", "Hong Kong Dollar", "Hong Koong", 344} 
  if isDollar2(dol) { 
    fmt.Println("Dollar currency found:", dol) 
  } 
} 

```

golang.fyi/ch03/switchstmt.go

Go 中的 switch 语句具有一些有趣的属性和规则，使其易于使用和理解：

+   从语义上讲，Go 的 switch 语句可以在两个上下文中使用：

+   表达式 switch 语句

+   类型 switch 语句

+   break 语句可以用于提前跳出 switch 代码块。

+   当没有其他 case 表达式评估为匹配时，`switch`语句可以包括一个默认 case。只能有一个默认 case，并且可以放置在 switch 块的任何位置。

## 使用表达式开关

表达式开关是灵活的，可以在程序控制流需要遵循多个路径的许多上下文中使用。表达式开关支持许多属性，如下面的要点所述：

+   表达式开关可以测试任何类型的值。例如，以下代码片段（来自前面的程序清单）测试了类型为`struct`的变量`Curr`：

```go
      func isDollar(curr Curr) bool { 
        var bool result 
        switch curr { 
          default: 
          result = false 
          case Curr{"AUD", "Australian Dollar", "Australia", 36}: 
          result = true 
          case Curr{"HKD", "Hong Kong Dollar", "Hong Koong", 344}: 
          result = true 
          case Curr{"USD", "US Dollar", "United States", 840}: 
          result = true 
        } 
        return result 
      } 
```

+   `case`子句中的表达式从左到右、从上到下进行评估，直到找到与`switch`表达式相等的值（或表达式）为止。

+   遇到与`switch`表达式匹配的第一个 case 时，程序将执行`case`块的语句，然后立即退出`switch`块。与其他语言不同，Go 的`case`语句不需要使用`break`来避免下一个 case 的穿透（参见*Fallthrough cases*部分）。例如，调用`isDollar(Curr{"HKD", "Hong Kong Dollar", "Hong Kong", 344})`将匹配前面函数中的第二个`case`语句。代码将将结果设置为`true`并立即退出`switch`代码块。

+   `Case`子句可以有多个值（或表达式），用逗号分隔，它们之间隐含着逻辑`OR`运算符。例如，在以下片段中，`switch`表达式`curr`被测试与值`currencies[2]`、`currencies[4]`或`currencies[10]`，使用一个 case 子句，直到找到匹配：

```go
      func isEuro(curr Curr) bool { 
        switch curr { 
          case currencies[2], currencies[4], currencies[10]: 
          return true 
          default: 
          return false 
        } 
      } 

```

+   `switch`语句是在 Go 中编写复杂条件语句的更清晰和首选的惯用方法。当前面的片段与使用`if`语句进行相同比较时，这一点是明显的：

```go
      func isEuro(curr Curr) bool { 
        if curr == currencies[2] || curr == currencies[4],  
        curr == currencies[10]{ 
        return true 
      }else{ 
        return false 
      } 
    } 

```

## 穿透案例

在 Go 的`case`子句中没有自动的*穿透*，就像 C 或 Java 的`switch`语句中一样。回想一下，一个`switch`块在执行完第一个匹配的 case 后会退出。代码必须明确地将`fallthrough`关键字放在`case`块的最后一个语句，以强制执行流程穿透到连续的`case`块。以下代码片段显示了一个`switch`语句，其中每个 case 块都有一个`fallthrough`：

```go
func isDollar2(curr Curr) bool { 
  switch curr { 
  case Curr{"AUD", "Australian Dollar", "Australia", 36}: 
    fallthrough 
  case Curr{"HKD", "Hong Kong Dollar", "Hong Kong", 344}: 
    fallthrough 
  case Curr{"USD", "US Dollar", "United States", 840}: 
    return true 
  default: 
    return false 
  } 
} 

```

golang.fyi/ch03/switchstmt.go

当匹配到一个 case 时，`fallthrough`语句会级联到连续`case`块的第一个语句。因此，如果`curr = Curr{"AUD", "Australian Dollar", "Australia", 36}`，第一个 case 将被匹配。然后流程级联到第二个 case 块的第一个语句，这也是一个`fallthrough`语句。这导致第三个 case 块的第一个语句执行返回`true`。这在功能上等同于以下片段：

```go
switch curr {  
case Curr{"AUD", "Australian Dollar", "Australia", 36},  
     Curr{"HKD", "Hong Kong Dollar", "Hong Kong", 344},  
     Curr{"USD", "US Dollar", "United States", 840}:  
  return true 
default: 
   return false 
}  

```

## 无表达式的开关

Go 支持一种不指定表达式的`switch`语句形式。在这种格式中，每个`case`表达式必须评估为布尔值`true`。以下简化的源代码示例说明了无表达式`switch`语句的用法，如`find()`函数中所列。该函数循环遍历`Curr`值的切片，以根据传入的`struct`函数中的字段值搜索匹配项：

```go
import ( 
  "fmt" 
  "strings" 
) 
type Curr struct { 
  Currency string 
  Name     string 
  Country  string 
  Number   int 
} 

var currencies = []Curr{ 
  Curr{"DZD", "Algerian Dinar", "Algeria", 12}, 
  Curr{"AUD", "Australian Dollar", "Australia", 36}, 
  Curr{"EUR", "Euro", "Belgium", 978}, 
  Curr{"CLP", "Chilean Peso", "Chile", 152}, 
  ... 
} 

func find(name string) { 
  for i := 0; i < 10; i++ { 
    c := currencies[i] 
    switch { 
    case strings.Contains(c.Currency, name), 
      strings.Contains(c.Name, name), 
      strings.Contains(c.Country, name): 
      fmt.Println("Found", c) 
    } 
  } 
} 

```

golang.fyi/ch03/switchstmt2.go

请注意，在前面的示例中，函数`find()`中的`switch`语句不包括表达式。每个`case`表达式用逗号分隔，并且必须被评估为布尔值，每个之间隐含着`OR`运算符。前面的`switch`语句等同于以下使用`if`语句实现相同逻辑：

```go
func find(name string) { 
  for I := 0; i < 10; i++ { 
    c := currencies[i] 
    if strings.Contains(c.Currency, name) || 
      strings.Contains(c.Name, name) || 
      strings.Contains(c.Country, name){ 
      fmt.Println""Foun"", c) 
    } 
  } 
} 

```

## 开关初始化器

`switch`关键字后面可以紧跟一个简单的初始化语句，在其中可以声明和初始化`switch`代码块中的局部变量。这种方便的语法使用分号在初始化语句和`switch`表达式之间声明变量，这些变量可以出现在`switch`代码块的任何位置。以下代码示例显示了如何通过初始化两个变量`name`和`curr`来完成这个操作：

```go
func assertEuro(c Curr) bool {  
  switch name, curr := "Euro", "EUR"; {  
  case c.Name == name:  
    return true  
  case c.Currency == curr:  
    return true 
  }  
  return false  
} 

```

golang.fyi/ch03/switchstmt2.go

前面的代码片段使用了一个没有表达式的`switch`语句和一个初始化程序。注意分号表示初始化语句和`switch`表达式区域之间的分隔。然而，在这个例子中，`switch`表达式是空的。

## 类型开关

考虑到 Go 对强类型的支持，也许不足为奇的是，该语言支持查询类型信息的能力。类型`switch`是一种语句，它使用 Go 接口类型来比较值（或表达式）的底层类型信息。关于接口类型和类型断言的详细讨论超出了本节的范围。你可以在第八章*方法、接口和对象*中找到更多关于这个主题的细节。

尽管如此，为了完整起见，这里提供了关于类型开关的简短讨论。目前，你只需要知道的是，Go 提供了类型`interface{}`或空接口作为一个超类型，它由类型系统中的所有其他类型实现。当一个值被赋予类型`interface{}`时，可以使用类型`switch`来查询关于其底层类型的信息，如下面的代码片段中的函数`findAny()`所示：

```go
func find(name string) { 
  for i := 0; i < 10; i++ { 
    c := currencies[i] 
    switch { 
    case strings.Contains(c.Currency, name), 
      strings.Contains(c.Name, name), 
      strings.Contains(c.Country, name): 
      fmt.Println("Found", c) 
    } 
  } 
}  

func findNumber(num int) { 
  for _, curr := range currencies { 
    if curr.Number == num { 
      fmt.Println("Found", curr) 
    } 
  } 
}  

func findAny(val interface{}) {  
  switch i := val.(type) {  
  case int:  
    findNumber(i)  
  case string:  
    find(i)  
  default:  
    fmt.Printf("Unable to search with type %T\n", val)  
  }  
} 

func main() { 
findAny("Peso") 
  findAny(404) 
  findAny(978) 
  findAny(false) 
} 

```

golang.fyi/ch03/switchstmt2.go

函数`findAny()`以`interface{}`作为其参数。类型`switch`用于使用类型断言表达式确定变量`val`的底层类型和值：

```go
switch i := val.(type) 

```

请注意在前面的类型断言表达式中使用了关键字`type`。每个 case 子句将根据从`val.(type)`查询到的类型信息进行测试。变量`i`将被赋予底层类型的实际值，并用于调用具有相应值的函数。默认块被调用来防范对参数`val`分配的任何意外类型。然后，函数`findAny`可以使用不同类型的值进行调用，如下面的代码片段所示：

```go
findAny("Peso")  
findAny(404)  
findAny(978)  
findAny(false)  

```

# for 语句

作为与 C 家族相关的语言，Go 也支持`for`循环风格的控制结构。然而，正如你现在可能已经预料到的那样，Go 的`for`语句工作方式有趣地不同而简单。Go 中的`for`语句支持四种不同的习语，如下表所总结的：

| **For 语句** | **用法** |
| --- | --- |

条件为|用于语义上替代`while`和`do...while`循环：

```go
for x < 10 { 
... 
}

```

|

| 无限循环 | 可以省略条件表达式创建无限循环：

```go
for {
...
}
```

|

| 传统的 | 这是 C 家族`for`循环的传统形式，包括初始化、测试和更新子句：

```go
for x:=0; x < 10; x++ {
...
}
```

|

| For 范围 | 用于遍历表示存储在数组、字符串（rune 数组）、切片、映射和通道中的项目集合的表达式：

```go
for i, val := range values {
...
}
```

|

请注意，与 Go 中的所有其他控制语句一样，`for`语句不使用括号括住它们的表达式。循环代码块的所有语句必须用大括号括起来，否则编译器会产生错误。

## 对于条件

`for`条件使用了一个在其他语言中等价于`while`循环的构造。它使用关键字`for`，后面跟着一个布尔表达式，允许循环在评估为 true 时继续进行。以下是这种形式的`for`循环的缩写源代码清单示例：

```go
type Curr struct {  
  Currency string  
  Name     string  
  Country  string  
  Number   int  
}  
var currencies = []Curr{  
  Curr{"KES", "Kenyan Shilling", "Kenya", 404},  
  Curr{"AUD", "Australian Dollar", "Australia", 36},  
... 
} 

func listCurrs(howlong int) {  
  i := 0  
  for i < len(currencies) {  
    fmt.Println(currencies[i])  
    i++  
  }  
} 

```

golang.fyi/ch03/forstmt.go

在函数`listCurrs()`中，`for`语句循环迭代，只要条件表达式`i < len(currencencies)`返回`true`。必须小心确保`i`的值在每次迭代中都得到更新，以避免创建意外的无限循环。

## 无限循环

当`for`语句中省略布尔表达式时，循环将无限运行，如下例所示：

```go
for { 
  // statements here 
} 

```

这相当于在其他语言（如 C 或 Java）中找到的`for(;;)`或`while(true)`。

## 传统的 for 语句

Go 还支持传统形式的`for`语句，其中包括初始化语句、条件表达式和更新语句，所有这些都由分号分隔。这是传统上在其他类 C 语言中找到的语句形式。以下源代码片段说明了在函数`sortByNumber`中使用传统的 for 语句：

```go
type Curr struct {  
  Currency string  
  Name     string  
  Country  string  
  Number   int  
}  

var currencies = []Curr{  
  Curr{"KES", "Kenyan Shilling", "Kenya", 404},  
  Curr{"AUD", "Australian Dollar", "Australia", 36},  
... 
} 

func sortByNumber() {  
  N := len(currencies)  
  for i := 0; i < N-1; i++ {  
     currMin := i  
     for k := i + 1; k < N; k++ {  
    if currencies[k].Number < currencies[currMin].Number {  
         currMin = k  
    }  
     }  
     // swap  
     if currMin != i {  
        temp := currencies[i]  
    currencies[i] = currencies[currMin]  
    currencies[currMin] = temp  
     } 
  }  
} 

```

golang.fyi/ch03/forstmt.go

前面的例子实现了一个选择排序，它通过比较每个`struct`值的`Number`字段来对`slice` currencies 进行排序。`for`语句的不同部分使用以下代码片段进行了突出显示（来自前面的函数）：

![传统的 for 语句](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-go-prog/img/B03676_For-Loop.jpg)

事实证明，传统的`for`语句是迄今为止讨论的循环形式的超集，如下表所总结的那样：

| **For 语句** | **描述** |
| --- | --- |

|

```go
k:=initialize()
for ; k < 10; 
++{
...
}
```

| 初始化语句被省略。变量`k`在`for`语句之外被初始化。然而，惯用的方式是用`for`语句初始化你的变量。 |
| --- |

|

```go
for k:=0; k < 10;{
...
}
```

| 这里省略了`update`语句（在最后的分号之后）。开发人员必须在其他地方提供更新逻辑，否则会产生无限循环。 |
| --- |

|

```go
for ; k < 10;{
...
}
```

| 这相当于`for`条件形式（前面讨论过的）`for k < 10 { ... }`。再次强调，变量`k`预期在循环之前声明。必须小心更新`k`，否则会产生无限循环。 |
| --- |

|

```go
for k:=0; ;k++{
...
}
```

| 这里省略了条件表达式。与之前一样，如果在循环中没有引入适当的终止逻辑，这将评估为`true`，将产生无限循环。 |
| --- |

|

```go
for ; ;{ ... }
```

| 这相当于形式`for{ ... }`，会产生无限循环。 |
| --- |

在`for`循环中的初始化和`update`语句是常规的 Go 语句。因此，它们可以用于初始化和更新多个变量，这是 Go 支持的。为了说明这一点，下一个例子在语句子句中同时初始化和更新两个变量`w1`和`w2`：

```go
import ( 
  "fmt" 
  "math/rand" 
) 

var list1 = []string{ 
"break", "lake", "go",  
"right", "strong",  
"kite", "hello"}  

var list2 = []string{ 
"fix", "river", "stop",  
"left", "weak", "flight",  
"bye"}  

func main() {  
  rand.Seed(31)  
  for w1, w2:= nextPair();  
  w1 != "go" && w2 != "stop";  
  w1, w2 = nextPair() {  

    fmt.Printf("Word Pair -> [%s, %s]\n", w1, w2)  
  }  
}  

func nextPair() (w1, w2 string) {  
  pos := rand.Intn(len(list1))  
  return list1[pos], list2[pos]  
} 

```

golang.fyi/ch03/forstmt2.go

初始化语句通过调用函数`nextPair()`初始化变量`w1`和`w2`。条件使用一个复合逻辑表达式，只要它被评估为 true，循环就会继续运行。最后，变量`w1`和`w2`通过调用`nextPair()`在每次循环迭代中都会被更新。

## for range

最后，`for`语句支持使用关键字`range`的另一种形式，用于迭代求值为数组、切片、映射、字符串或通道的表达式。for-range 循环具有以下通用形式：

*for [<identifier-list> :=] range <expression> { ... }*

根据`range`表达式产生的类型，每次迭代可能会产生多达两个变量，如下表所总结的那样：

| **Range 表达式** | **Range 变量** |
| --- | --- |

| 循环遍历数组或切片：

```go
for i, v := range []V{1,2,3} {
...
}
```

| range 产生两个值，其中`i`是循环索引，`v`是集合中的值`v[i]`。有关数组和切片的进一步讨论在第七章中有所涵盖，*复合类型*。 |
| --- |

| 循环遍历字符串值：

```go
for i, v := range "Hello" {
...
}
```

| `range`产生两个值，其中`i`是字符串中字节的索引，`v`是在`v[i]`处返回的 UTF-8 编码字节的值作为 rune。有关字符串类型的进一步讨论在第四章中有所涵盖，*数据类型*。 |
| --- |

| 循环地图：

```go
for k, v := range map[K]V {
...
}
```

| `range`产生两个值，其中`k`被赋予类型为`K`的地图键的值，`v`被存储在类型为`V`的`map[k]`中。有关地图的进一步讨论在第七章中有所涵盖，*复合类型*。 |
| --- |

| 循环通道值：

```go
var ch chan T
for c := range ch {
...
}
```

| 有关通道的充分讨论在第九章中有所涵盖，*并发*。通道是一个能够接收和发出值的双向导管。`for...range`语句将从通道接收到的每个值分配给变量`c`，每次迭代。 |
| --- |

您应该知道，每次迭代发出的值都是源中存储的原始项目的副本。例如，在以下程序中，循环完成后，切片中的值不会被更新：

```go
import "fmt" 

func main() { 
  vals := []int{4, 2, 6} 
  for _, v := range vals { 
    v-- 
  } 
  fmt.Println(vals) 
} 

```

要使用`for...range`循环更新原始值，使用索引表达式访问原始值，如下所示。

```go
func main() { 
  vals := []int{4, 2, 6} 
  for i, v := range vals { 
    vals[i] = v - 1 
  } 
  fmt.Println(vals) 
} 

```

在前面的示例中，值`i`用于切片索引表达式`vals[i]`来更新存储在切片中的原始值。如果您只需要访问数组、切片或字符串（或地图的键）的索引值，则可以省略迭代值（赋值中的第二个变量）。例如，在以下示例中，`for...range`语句只在每次迭代中发出当前索引值：

```go
func printCurrencies() { 
  for i := range currencies { 
    fmt.Printf("%d: %v\n", i, currencies[i]) 
  } 
} 

```

golang.fyi/ch03/for-range-stmt.go

最后，有些情况下，您可能对迭代生成的任何值都不感兴趣，而是对迭代机制本身感兴趣。引入了 for 语句的下一形式（截至 Go 的 1.4 版本）来表达不带任何变量声明的 for 范围，如下面的代码片段所示：

```go
func main() { 
  for range []int{1,1,1,1} { 
    fmt.Println("Looping") 
  } 
}  

```

前面的代码将在标准输出上打印四次`"Looping"`。当范围表达式在通道上时，这种形式的`for...range`循环有时会被使用。它用于简单地通知通道中存在值。

# `break`，`continue`和`goto`语句

Go 支持一组专门设计用于突然退出运行中的代码块的语句，例如`switch`和`for`语句，并将控制转移到代码的不同部分。所有三个语句都可以接受一个标签标识符，该标识符指定了代码中要转移控制的目标位置。

## 标签标识符

在深入本节的核心之前，值得看一下这些语句使用的标签。在 Go 中声明标签需要一个标识符，后面跟着一个冒号，如下面的代码片段所示：

```go
DoSearch: 

```

给标签命名是一种风格问题。但是，应该遵循前一章中介绍的标识符命名指南。标签必须包含在函数内。与变量类似，如果声明了标签，则必须在代码中引用它，否则 Go 编译器将不允许未使用的标签在代码中悬挂。

## `break`语句

与其他类似 C 的语言一样，Go 的`break`语句终止并退出最内层的包围`switch`或`for`语句代码块，并将控制转移到运行程序的其他部分。`break`语句可以接受一个可选的标签标识符，指定在包围函数中程序流将恢复的标记位置。以下是要记住`break`语句标签的一些属性：

+   标签必须在与`break`语句所在的运行函数内声明

+   声明的标签必须紧随着包围控制语句（`for`循环或`switch`语句）的位置，其中`break`被嵌套

如果`break`语句后面跟着一个标签，控制将被转移到标签所在的位置，而不是紧接着标记块后面的语句。如果没有提供标签，`break`语句会突然退出并将控制转移到其封闭的`for`语句（或`switch`语句）块后面的下一个语句。

以下代码是一个过度夸张的线性搜索，用于说明`break`语句的工作原理。它进行单词搜索，并在找到单词的第一个实例后退出切片：

```go
import ( 
  "fmt" 
) 

var words = [][]string{  
  {"break", "lake", "go", "right", "strong", "kite", "hello"},  
  {"fix", "river", "stop", "left", "weak", "flight", "bye"},  
  {"fix", "lake", "slow", "middle", "sturdy", "high", "hello"},  
}  

func search(w string) {  
DoSearch:  
  for i := 0; i < len(words); i++ {  
    for k := 0; k < len(words[i]); k++ {  
      if words[i][k] == w {  
        fmt.Println("Found", w)  
        break DoSearch  
      }  
    }  
  }  
}  

```

golang.fyi/ch03/breakstmt.go

在前面的代码片段中，`break DoSearch`语句实质上将退出最内层的`for`循环，并导致执行流在最外层的带标签的`for`语句之后继续，这个例子中，将简单地结束程序。

## 继续语句

`continue`语句导致控制流立即终止封闭的`for`循环的当前迭代，并跳转到下一次迭代。`continue`语句也可以带有可选的标签。标签具有与`break`语句类似的属性：

+   标签必须在`continue`语句所在的运行函数内声明

+   声明的标签必须紧随着一个封闭的`for`循环语句，在其中`continue`语句被嵌套

当`continue`语句在`for`语句块内部到达时，`for`循环将被突然终止，并且控制将被转移到最外层的带标签的`for`循环块以进行继续。如果未指定标签，`continue`语句将简单地将控制转移到其封闭的`for`循环块的开始，以进行下一次迭代的继续。

为了说明，让我们重新访问单词搜索的先前示例。这个版本使用了`continue`语句，导致搜索在切片中找到搜索词的多个实例：

```go
func search(w string) {  
DoSearch:  
  for i := 0; i < len(words); i++ {  
    for k := 0; k < len(words[i]); k++ {  
      if words[i][k] == w {  
        fmt.Println("Found", w)  
        continue DoSearch  
      }  
    }  
  }  
} 

```

golang.fyi/ch03/breakstmt2.go

`continue DoSearch`语句导致最内层循环的当前迭代停止，并将控制转移到带标签的外部循环，导致它继续下一次迭代。

## goto 语句

`goto`语句更灵活，因为它允许将流控制转移到函数内定义目标标签的任意位置。`goto`语句会突然转移控制到`goto`语句引用的标签。以下是 Go 中`goto`语句在一个简单但功能性示例中的示例：

```go
import "fmt" 

func main() {  
  var a string 
Start:  
  for {  
    switch {  
    case a < "aaa":  
      goto A  
    case a >= "aaa" && a < "aaabbb":  
      goto B  
    case a == "aaabbb":  
      break Start  
    }  
  A:  
    a += "a"  
    continue Start  
  B:  
    a += "b"  
    continue Start  
  }  
fmt.Println(a) 
} 

```

golang.fyi/ch03/gotostmt.go

该代码使用`goto`语句跳转到`main()`函数的不同部分。请注意，`goto`语句可以定位到代码中任何地方定义的标签。在这种情况下，代码中留下了多余使用`Start:`标签的部分，这在这种情况下是不必要的（因为没有标签的`continue`会产生相同的效果）。以下是在使用`goto`语句时提供一些指导的内容：

+   除非实现的逻辑只能使用`goto`分支，否则应避免使用`goto`语句。这是因为过度使用`goto`语句会使代码更难以理解和调试。

+   尽可能将`goto`语句及其目标标签放在同一个封闭的代码块中。

+   避免在`goto`语句将流程跳过新变量声明或导致它们被重新声明的地方放置标签。

+   Go 允许您从内部跳转到外部封闭的代码块。

+   如果尝试跳转到对等或封闭的代码块，这将是一个编译错误。

# 摘要

本章介绍了 Go 语言中控制流的机制，包括`if`、`switch`和`for`语句。虽然 Go 的流程控制结构看起来简单易用，但它们功能强大，实现了现代语言所期望的所有分支原语。读者通过丰富的细节和示例介绍了每个概念，以确保主题的清晰度。下一章将继续介绍 Go 基础知识，向读者介绍 Go 类型系统。
