# Go 函数式编程学习手册（一）

> 原文：[`zh.annas-archive.org/md5/5FC2C8948F5CEA11C4D0D293DBBCA039`](https://zh.annas-archive.org/md5/5FC2C8948F5CEA11C4D0D293DBBCA039)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

直到最近，信息一直是*Go 和函数式编程——不要这样做*。

函数式编程（FP）非常适合多核、并行处理。Go 是一个并发球员（具有 Goroutines、通道等），并且已经在每个可用的 CPU 核心上运行。FP 减少了复杂性；简单性是 Go 最大的优势之一。

那么，FP 能为 Go 带来什么，实际上会改进我们的软件应用程序？它提供了什么：

+   **构成**：FP 向我们展示了如何分解我们的应用程序，并通过重用小的构建模块来重建它们。

+   **单子**：使用单子，我们能够将我们的工作流安全地排序为数据转换的管道。

+   **错误处理**：我们可以利用单子错误处理，同时保持与成熟的 Go 代码的兼容性。

+   **性能**：引用透明性是我们可以评估我们的函数一次，然后随后引用其预先计算的值的地方。

+   **表达性代码**：FP 允许我们在代码中简洁地表达业务意图。我们声明我们的函数做什么，而不必在每个函数调用后进行错误检查的混乱，也不必遵循状态变化（纯 FP 意味着不可变变量）。

+   **更简单的代码**：没有共享数据意味着不必处理信号量、锁、竞争条件或死锁。

大多数人都很难掌握 FP。

我也是如此。当我懂了，我写了这本书。和我一起踏上这段旅程。我们将看到数百幅插图，阅读易于理解的解释，并在途中实现 Go 代码中的 FP。

我喜欢指导足球。我用来确定我是否成功作为教练的试金石是这个简单问题的答案：*他们是否都注册了下个赛季并请求我成为他们的教练？* 就像计划练习一样，我计划了每一章，从简单的概念开始，然后逐渐添加。阅读这本书，然后你也能说，*我懂了*。

如果你想提高你的 FP 技能，这本书适合你。

## 本书涵盖了什么

第一章，*Go 中的纯函数式编程*，介绍了声明式编程风格，并演示了使用斐波那契序列的递归、记忆化和 Go 的并发构造。我们将学习如何对递归代码进行基准/性能测试，我们将得到一些坏消息。

第二章，*操作集合*，向我们展示了如何使用中间（Map、Filter 和 Sort）和终端（Reduce、GroupBy 和 Join）函数执行数据转换。我们使用类似 Mocha 的 BDD Go 框架来测试谓词函数。Itertools 帮助我们掌握 FP 集合操作函数的广度，我们还看了一个分布式 MapReduce 解决方案：Gleam = Go + LuaJIT + Unix Pipes。

第三章，*使用高阶函数*，涵盖了 27 个 FP 特征的列表：匿名函数、闭包、柯里化、Either 数据类型、一级函数、函数、函数组合、Hindley-Milner 类型系统、幂等性、不可变状态、不可变变量、Lambda 表达式、列表单子、Maybe 数据类型、Maybe 单子、单子错误处理、无副作用、运算符重载、选项类型、参数多态性、部分函数应用、递归、引用透明性、和类型的总和或联合类型、尾调用优化、类型类和单元类型。它还涵盖了泛型的示例，并说明了它对 FP 程序员的价值。我们实现了 Map、Filter 和 Reduce 函数，以及使用 Goroutines 和 Go 通道进行惰性评估。

第四章，“Go 中的 SOLID 设计”，讨论了 Gophers 为什么憎恨 Java，良好软件设计原则的应用，如何应用单一职责原则、函数组合、开闭原则、FP 合同和鸭子类型。它还涵盖了如何使用接口建模行为，使用接口隔离原则和嵌入接口来组合软件。我们将学习使用紫色 Monoid 链的结合律，并揭示 Monads 链的延续。

第五章，“使用装饰添加功能”，演示了使用 Go 的互补 Reader 和 Writer 接口进行接口组合。接下来，我们将学习过程式设计与函数式控制反转的比较。我们将实现以下装饰器：授权、日志记录和负载平衡。此外，我们将向我们的应用程序添加 easy-metrics，以查看我们的装饰器模式的实际效果。

第六章，“在架构层面应用函数式编程”，使用分层架构构建应用程序框架，解决循环依赖错误。我们将学习如何应用好莱坞原则，以及观察者模式和依赖注入之间的区别。我们将使用控制反转（IoC）来控制逻辑流，并构建一个分层应用程序。此外，我们将构建一个有效的表驱动框架来测试我们应用程序的 API。

第七章，“函数参数”，让我们明白了为什么我们从 Java 和面向对象编程中学到的很多东西并不适用于 Go，教会我们使用函数选项更好地重构长参数列表，并帮助我们理解柯里化和部分应用之间的区别。我们将学习如何应用部分应用来创建另一个具有较小 arity 的函数。我们将使用上下文来优雅地关闭服务器，并了解如何使用上下文取消和回滚长时间运行的数据库事务。

第八章，“使用流水线提高性能”，涵盖了数据流类型（读取、拆分、转换、合并和写入），并教会我们何时以及如何构建数据转换流水线。我们使用缓冲区来增加吞吐量，使用 goroutines 和通道来更快地处理数据，使用接口来改善 API 的可读性，并实现一些有用的过滤器。我们还实现并比较了用于处理信用卡交易的命令式和函数式流水线设计。

第九章，“函子、幺半群和泛型”，让我们对 Go 中缺乏对泛型的支持有了更深入的了解。我们将看到如何使用代码生成工具来解决重复样板代码的问题。我们将深入研究函数组合，实现一些函子，并学习如何在不同世界之间进行映射。我们还将学习如何编写一个 Reduce 函数来实现发票处理幺半群。

第十章，“Monad、类型类和泛型”，向我们展示了 Monad 的工作原理，并教会我们如何使用 Bind 操作组合函数。它向我们展示了 Monad 如何处理错误并处理输入/输出（I/O）。本章通过 Go 中的 monadic 工作流程实现。我们将介绍 Lambda 演算是什么，以及它与 Monad 有什么关系，看看 Lambda 演算如何实现递归，并学习 Y-组合器在 Go 中的工作原理。接下来，我们将使用 Y-组合器来控制工作流程，并学习如何在管道的末尾处理所有错误。我们将学习类型类的工作原理，并在 Go 中实现一些类型类。最后，我们将回顾 Go 中泛型的优缺点。

第十一章，*适用的范畴论*，让我们对范畴论有了一个实际的理解。我们将学会欣赏范畴论、逻辑和类型理论之间的深刻联系。我们将通过 FP 历史之旅增进我们的理解。本章使用一个维恩图来帮助解释各种编程语言的范畴。我们将理解在 lambda 表达式的上下文中绑定、柯里化和应用的含义。本章向我们展示了 Lambda 演算就像巧克力牛奶。本章涵盖了 FP 的类型系统含义，向我们展示了不同类别的同态和何时使用它们，并使用数学和足球的飞行来增进我们对态射的理解。我们将用线性和二次函数来进行函数组合，并学习接口驱动开发。我们将探索知识驱动系统的价值，并学会如何应用我们对范畴论的理解来构建更好的应用。

附录，*杂项信息和操作指南*，向我们展示了作者建议我们如何构建和运行本书中的 Go 项目。它向我们展示了如何提出对 Go 的更改，介绍了词法工作流解决方案：一种处理错误的 Go 兼容方式，提供了一个提供反馈的地方和一个 FP 资源页面，讨论了 Minggatu-Catalan 数，并提供了世界和平的解决方案。

## 你需要为这本书做好什么准备

如果你想运行每章讨论的 Go 项目，你需要安装 Go。接下来，你需要启动你的 Go 开发环境并开始编写代码。

阅读*附录*中*如何构建和运行 Go 项目*部分的*TL;DR*子部分。转到第一章，*Go 中的纯函数式编程*，开始阅读*获取源代码*部分。继续阅读如何设置和运行你的第一个项目。

其他 Go 资源包括：

+   Go 之旅 ([`tour.golang.org/welcome/1`](https://tour.golang.org/welcome/1))

+   Go by Example ([`gobyexample.com/`](https://gobyexample.com/))

+   学习 Go 书籍 ([`www.miek.nl/go/`](https://www.miek.nl/go/))

+   Go 语言规范 ([`golang.org/ref/spec`](https://golang.org/ref/spec))

当我想到其他要添加的东西时，我会把信息放在这里：[`lexsheehan.blogspot.com/2017/11/what-you-need-for-this-book.html`](https://lexsheehan.blogspot.com/2017/11/what-you-need-for-this-book.html)。

## 这本书适合谁

这本书中的很多信息只需要高中学历。

对于本书中的编程部分，你应该至少有一年的编程经验。精通 Go 或 Haskell 是理想的，但有其他语言（如 C/C++、Python、Javascript、Java、Scala 或 Ruby）的经验也足够了。你应该对使用命令行有一定的了解。

这本书应该吸引两个群体：

1.  非程序员（阅读第十一章，*适用的范畴论*）如果你是其中之一：

+   K-12 数学教师，想知道你所教的内容为什么重要

+   数学教师，想知道你所教的内容与数学的其他分支有何关联

+   法学院的学生，想了解在为客户辩护时你将要做什么

+   足球爱好者，喜欢数学

+   对范畴论感兴趣的人

+   Lambda 演算的爱好者，想看到用图表、图片和 Go 代码来说明它

+   软件项目经理，想看到需求收集、实施和测试之间有更好的对应关系

+   高管，想了解是什么激励和激发了你的 IT 员工

1.  程序员：如果你是其中之一：

+   软件爱好者，想学习函数式编程

+   软件测试人员，想看到需求收集、实施和测试之间有更好的对应关系

+   软件架构师，想要了解如何使用 FP

+   Go 开发人员，喜欢足球

+   Go 开发人员，并希望使用更具表现力的代码实现您的业务用例编程任务

+   Go 开发人员，并希望了解泛型

+   Java 开发人员，并希望了解为什么我们说*少即是多*

+   *您的语言*开发人员，了解 FP 并希望将您的技能转移到 Go

+   Go 开发人员寻找更好的方法来构建数据转换管道

+   Go 开发人员，并希望看到编写更少代码的可行方法，即更少的*err != nil*块

+   有经验的 Go 开发人员，并希望学习 FP 或为工具箱添加一些工具

+   参与软件开发并希望了解以下任何术语的人。

如果您是一名 Go 开发人员，正在寻找以下任何工作代码，并且需要逐行解释，那么这本书适合您：

+   基准测试

+   并发（Goroutines/Channels）

+   柯里化

+   数据转换管道

+   装饰者模式

+   依赖注入

+   鸭子类型

+   嵌入接口

+   错误处理程序

+   函数组合

+   函数参数

+   函子

+   通过代码生成实现泛型

+   好莱坞原则

+   接口驱动开发

+   I18N（语言翻译）

+   IoC

+   Go 中的 Lambda 表达式

+   分层应用框架

+   日志处理程序

+   单子

+   单子

+   观察者模式

+   部分应用

+   处理信用卡支付的管道

+   递归

+   减少函数以求和发票总额

+   解决循环依赖错误

+   基于表的 http API 测试框架

+   类型类

+   将文件上传/下载到/从 Google Cloud Buckets

+   Y-组合子

如果我决定更改格式或更新此信息，我会在这里放置它：[`lexsheehan .blogspot.com/2017/11/who-this-book-is-for.html`](http://lexsheehan%C2%A0.blogspot.com/2017/11/who-this-book-is-for.html)。

## 约定

在本书中，您将找到一些文本样式，用以区分不同类型的信息。以下是一些样式的示例及其含义的解释。文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄显示如下：“我们更新代码，运行`glide-update`和`go-run`命令，并重复直到完成。”代码块设置如下：

```go
func newSlice(s []string) *Collection {
  return &Collection{INVALID_INT_VAL, s}
}
```

当我们希望引起您对代码块的特定部分的注意时，相关行或项目将以粗体显示：

```go
[default] 
exten => s,1,Dial(Zap/1|30) 
exten => s,2,Voicemail(u100) 
exten => s,102,Voicemail(b100) 
exten => i,1,Voicemail(s0) 
```

任何命令行输入或输出都按如下方式编写：

```go
go get --help
```

**新术语**和**重要单词**以粗体显示。屏幕上看到的单词，例如菜单或对话框中的单词，以这种方式出现在文本中：“为了下载新模块，我们将转到文件 | 设置 | 项目名称 | 项目解释器。”

警告或重要说明如下。

技巧以这种方式出现。


# 第一章：在 Go 中进行纯函数式编程

Go 是一种尝试将静态类型语言的安全性和性能与动态类型解释语言的便利性和乐趣相结合的语言。

- Rob Pike

您喜欢 Go 吗？如果是，为什么？它可以更好吗？您今天能写出更好的代码吗？

是的！因为 Go 简单而强大；Go 不让我等待；它的编译器快速且跨平台；Go 使并发编程变得容易；Go 还提供了有用的工具，并且拥有一个伟大的开发社区。也许。是的，这本书就是关于这个的：使用**函数式编程**（**FP**）编码风格。

在本章中，我将通过处理斐波那契数列代码示例，分享纯 FP 的好处以及在 Go 中的性能影响。从简单的命令式实现开始，您将探索函数式实现，并学习一些测试驱动开发和基准测试技术。

本章的目标是：

+   扎根于 FP 的理论

+   学习如何实现函数式解决方案

+   确定哪种 FP 最适合您的业务需求

## 使用 FP 的动机

函数式编程风格可以帮助您以更简洁和表达力更强的方式编写更少的代码，减少错误。这是怎么可能的呢？嗯，函数式编程将计算视为数学函数的评估。函数式编程利用这种计算模型（以及一些杰出的数学家和逻辑学家的工作）来实现优化和性能增益，这是使用传统的命令式编码技术根本不可能的。

开发软件并不容易。您必须首先处理众多的**非功能性需求**（**NFRs**），例如：

+   复杂性

+   可扩展性

+   可维护性

+   可靠性

+   并发

+   可扩展性

软件变得越来越复杂。您的典型应用程序中平均有多少第三方依赖项？5 年前是什么样子？我们的应用程序通常必须与我们自己公司内部的其他服务以及与我们的合作伙伴以及外部客户集成。我们如何管理这种不断增长的复杂性？

应用程序过去通常在被赋予宠物名字的服务器上运行，例如 Apollo、Gemini 等。似乎每个客户都有不同的命名方案。如今，大多数应用程序都部署在云环境中，例如 AWS 或 Google Cloud Platform。您是否有很多软件应用程序在许多服务器上运行？如果是的话，您应该更多地像对待牲畜一样对待您的服务器；它们太多了。此外，由于您已经实现了自动扩展，重要的不是单个服务器，而是整个群体。只要您的集群中始终至少有一台服务器为会计部门运行，那就是真正重要的。

随着数字的增加，复杂性也随之增加。您能否将应用程序组合在一起，像乐高积木一样，编写运行速度非常快的有用测试？或者，您是否经常觉得自己的代码中有太多的脚手架/`for`循环？您是否喜欢频繁处理`err != nil`的条件？您是否希望看到更简单、更清晰的方法来做同样的事情？您的应用程序有全局变量吗？您是否有代码来始终正确管理其状态并防止所有可能的副作用？曾经出现过竞争条件问题吗？

您是否了解应用程序中所有可能的错误条件，并且是否有代码来处理它们？您是否可以查看代码中任何函数的函数签名，并立即对其功能有直观的理解？

您是否有兴趣了解更好的方法来实现您的 NFR，并且比现在更享受开发 Go 软件？在寻找银弹吗？如果是的话，请继续阅读。（请注意，本书的其余部分将以第一人称复数形式撰写，因为我们将一起学习。）

## 获取源代码

这本书的源代码的 GitHub 存储库是[`github.com/l3x/fp-go`](https://github.com/l3x/fp-go)。

如果您将 Go 项目存储在`~/myprojects`目录中，那么运行`cd ~/myprojects; git clone https://github.com/l3x/fp-go.git`。

接下来，运行`cd`命令进入第一个项目目录：`cd ~/myprojects/fp-go/1-functional-fundamentals/ch01-pure-fp/01_oop`。

### 源文件的目录结构

目录对应于书的单元和章节：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/40477779-288a-46bb-81b0-e384bd08f0aa.png)

每一章都分成按顺序编号的目录，按照它们在书中出现的顺序。

### 如何运行我们的第一个 Go 应用程序

首先，让我们确保我们已经安装了 Go，我们的`GOPATH`已经正确设置，并且我们可以运行一个 Go 应用程序。

如果您使用的是 macOS，那么请查看附录中如何使用`brew`命令安装 Go 的说明；否则，要安装 Go，请访问：[`golang.org/doc/install`](http://golang.org/doc/install)。要设置您的`GOPATH`，请访问：[`github.com/golang/go/wiki/Setting-GOPATH`](https://github.com/golang/go/wiki/Setting-GOPATH)。

许多人使用全局`GOPATH`来存储所有 Go 应用程序的源代码，或者经常手动重置他们的`GOPATH`。我发现这种做法在处理多个客户的多个 Go 项目时很麻烦，每个项目都有不同的 Go 版本和第三方依赖关系。

本章中我们将使用的示例 Go 应用程序没有依赖关系；也就是说，我们不需要导入任何第三方包。因此，我们要做的就是运行我们的第一个`app--cars.go--`，验证 Go 是否已安装，设置我们的`GOPATH`，然后输入`go run cars.go`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/8ff6f041-0caa-4dbd-8aa7-1cb35e033a80.png)

对于本章中的示例这样非常简单的项目来说，使用全局`GOPATH`是很容易的。

在第二章 *操作集合*中，我们的 Go 应用程序将变得更加复杂，我们将介绍一种简单、更一致的方式来管理我们的 Go 开发环境。

## 命令式与声明式编程

让我们看看为什么函数式编程风格比命令式编程风格更有助于我们提高生产力。

“我们不是历史的创造者。我们是历史的产物。”

- 马丁·路德·金

几乎所有的计算机硬件都是设计用来执行机器代码的，这是计算机本地的，以命令式风格编写的。程序状态由内存内容定义，语句是机器语言中的指令，其中每个语句都推进计算状态向前，朝着最终结果。命令式程序随着时间逐步改变它们的状态。高级命令式语言，如 C 和 Go，使用变量和更复杂的语句，但它们仍然遵循相同的范式。由于命令式编程中的基本思想在概念上与直接在计算机硬件上操作的低级代码非常相似，大多数计算机语言--如 Go，也被称为 21 世纪的 C--在很大程度上是命令式的。

**命令式编程**是一种使用改变程序状态的语句的编程范式。它侧重于程序操作的逐步机制。

这个术语通常与**声明式编程**相对使用。在声明式编程中，我们声明我们想要的结果。我们描述我们想要的，而不是如何得到它的详细说明。

这是一个典型的命令式查找`Blazer`在汽车切片中的方法：

```go
var found bool 
carToLookFor := "Blazer" 
cars := []string{"Accord", "IS250", "Blazer" }
for _, car := range cars {
   if car == carToLookFor {
      found = true; // set flag
   }
}
fmt.Printf("Found? %v", found)
```

这是完成相同任务的函数式方法：

```go
cars := []string{"Accord", "IS250", "Blazer" }
fmt.Printf("Found? %v", cars.contains("Blazer"))
```

这是九行命令式代码，而在**函数式编程**（**FP**）风格中只有两行。

在这种情况下，函数式构造通常比 for 循环更清晰地表达我们的意图，并且在我们想要过滤、转换或聚合数据集中的元素时特别有用。

在命令式示例中，我们必须编写*如何*。我们必须：

+   声明一个布尔标志

+   声明并设置变量值

+   创建一个循环结构

+   比较每个迭代值

+   设置标志

在函数式示例中，我们声明了我们想要做什么。我们能够专注于我们想要实现的目标，而不是用循环结构、设置变量值等来膨胀我们的代码。

在 FP 中，迭代是通过库函数`contains()`来实现的。利用库函数意味着我们编写的代码更少，并且允许库开发人员专注于高效的实现，这些实现通常经过经验丰富的专业人员的审查和性能增强。我们不必为重复的逻辑编写、调试或测试这样高质量的代码。

现在，让我们看看如何使用面向对象编程范式查找`Blazer`：

```go
type Car struct {
   Model string
}
accord := &Car{"Accord"}; is250 := &Car{"IS250"}; blazer := &Car{"Blazer"}
cars := []*Car{is250, accord, blazer}
var found bool
carToLookFor := is250
for _, car := range cars {
   if car == carToLookFor {
     found = true;
   }
}
fmt.Printf("Found? %v", found)
```

首先，我们声明我们的对象类型：

```go
type Car struct {
   Model string
}
type Cars []Car
```

接下来，我们添加我们的方法：

```go
func (cars *Cars) Add(car Car) {
   myCars = append(myCars, car)
}

func (cars *Cars) Find(model string) (*Car, error) {
   for _, car := range *cars {
      if car.Model == model {
         return &car, nil
      }
   }
   return nil, errors.New("car not found")
}
```

在这里，我们声明了一个全局变量，即`myCars`，我们将在其中保持状态，即我们将构建的汽车列表：

```go
var myCars Cars
```

向列表中添加三辆车。`Car`对象封装了每个对象的数据，而`cars`对象封装了我们的汽车列表：

```go
func main() {
   myCars.Add(Car{"IS250"})
   myCars.Add(Car{"Blazer"})
   myCars.Add(Car{"Highlander"})
```

查找`Highlander`并打印结果：

```go
    car, err := myCars.Find("Highlander")
   if err != nil {
      fmt.Printf("ERROR: %v", car)
   } else {
      fmt.Printf("Found %v", car)
   }
}
```

我们使用`car`对象，但实质上我们正在执行与简单的命令式代码示例中相同的操作。我们有状态的对象，可以向其添加方法，但底层机制是相同的。我们给对象属性分配状态，通过进行方法调用修改内部状态，并推进执行状态直到达到期望的结果。这就是命令式编程。

## 纯函数

“疯狂就是一遍又一遍地做同样的事情，却期待不同的结果。”

- 阿尔伯特·爱因斯坦

我们可以利用这种纯函数的原则来获益。

在命令式函数的执行过程中给变量赋值可能会导致在其运行的环境中修改变量。如果我们再次运行相同的命令式函数，使用相同的输入，结果可能会有所不同。

对于命令式函数的结果，给定相同的输入，每次运行时可能返回不同的结果。这不是疯狂吗？

**纯函数**：

+   将函数视为一等公民

+   在给定相同的输入时，始终返回相同的结果

+   在其运行的环境中没有副作用

+   不允许外部状态影响它们的结果

+   不允许变量值随时间改变

纯函数的两个特征包括引用透明性和幂等性：

+   **引用透明性**：这是指函数调用可以替换为其相应的值，而不会改变程序的行为

+   **幂等性**：这是指函数调用可以重复调用并每次产生相同的结果

引用透明的程序更容易优化。让我们看看是否可以使用缓存技术和 Go 的并发特性进行优化。

## 斐波那契数列 - 一个简单的递归和两个性能改进

斐波那契数列是一个数列，其中每个数字等于前两个数字相加。这是一个例子：

```go
 1  1  2  3  5  8  13  21  34
```

所以，1 加 1 等于 2，2 加 3 等于 5，5 加 8 等于 13，依此类推。

让我们使用斐波那契数列来帮助说明一些概念。

**递归函数**是指调用自身以将复杂输入分解为更简单的输入的函数。每次递归调用时，输入问题必须以一种简化的方式简化，以便最终达到基本情况。

斐波那契数列可以很容易地实现为一个递归函数：

```go
func Fibonacci(x int) int {
    if x == 0 {
        return 0
 } else if x <= 2 {
        return 1
 } else {
        return Fibonacci(x-2) + Fibonacci(x-1)
    }
}
```

在前面的递归函数（`Fibonacci`）中，如果输入是简单情况的`0`，则返回**0**。同样，如果输入是`1`或`2`，则返回**1**。

0、1 或 2 的输入被称为**基本情况**或**停止条件**；否则，`fib`将调用自身两次，将序列中的前一个值加到前一个值上：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/0e2ebf78-c7d6-4b9c-98cf-f30eb82b76c0.png)

Fibonacci(5)计算图

在上图*Fibonacci(5)计算图*中，我们可以直观地看到如何计算斐波那契数列中的第五个元素。我们看到**f(3)**被计算了两次，**f(2)**被计算了三次。只有**1**的最终叶节点被加在一起来计算**8**的总和：

```go
func main() {
   fib := Fibonacci
   fmt.Printf("%vn", fib(5))
}
```

运行该代码，你会得到`8`。递归函数一遍又一遍地执行相同的计算；**f(3)**被计算了两次，**f(2)**被计算了三次。图形越深，冗余计算就越多。这是非常低效的。你自己试试吧。将一个大于 50 的值传递给`fib`，看看你要等多久才能得到最终结果。

Go 提供了许多提高性能的方法。我们将看两个选项：备忘录和并发。

备忘录是一种优化技术，通过存储昂贵的函数调用的结果并在再次出现相同输入时返回缓存的结果来提高性能。

备忘录的工作效果很好，因为纯函数具有以下两个属性：

+   它们在给定相同的输入时总是返回相同的结果

+   它们在其运行的环境中没有副作用

### 备忘录

让我们利用备忘录技术来加速我们的斐波那契计算。

首先，让我们创建一个名为`Memoized()`的函数类型，并将我们的斐波那契变量定义为该类型：

```go
type Memoized func(int) int
var fibMem Memoized
```

接下来，让我们实现`Memoize()`函数。在这里要意识到的关键是，当我们的应用程序启动时，甚至在我们的`main()`函数执行之前，我们的`fibMem`变量就已经被*连接*起来了。如果我们逐步执行我们的代码，我们会看到我们的`Memoize`函数被调用。缓存变量被赋值，并且我们的匿名函数被返回并赋值给我们的`fibMem`函数文字变量。

```go
func Memoize(mf Memoized) Memoized {
       cache := make(map[int]int)
       return func(key int) int {
 if val, found := cache[key]; found {
 return val
 }
 temp := mf(key)
 cache[key] = temp
 return temp
 }
}
```

备忘录接受一个`Memoized()`函数类型作为输入，并返回一个`Memoized()`函数。

在 Memoize 的第一行，我们创建了一个`map`类型的变量，作为我们的缓存，以保存计算的斐波那契数。

接下来，我们创建一个闭包，它是由`Memoized()`类型*返回*的`Memoize()`函数。请注意，**闭包**是一个内部函数，它关闭或者访问其外部作用域中的变量。

在闭包内，如果我们找到了传递整数的计算，我们就从缓存中返回它的值；否则，我们调用递归的斐波那契函数`mf`，参数为整数（`key`），其返回值将存储在`cache[key]`中。下次请求相同的键时，它的值将直接从缓存中返回。

匿名函数是没有名称定义的函数。当匿名函数包含可以访问其作用域中定义的变量的逻辑，例如`cache`，并且如果该匿名函数可以作为参数传递或作为函数调用的返回值返回，这在这种情况下是正确的，那么我们可以将这个匿名函数称为 lambda 表达式。

我们将在名为`fib`的函数中实现斐波那契数列的逻辑：

```go
func fib(x int) int {
   if x == 0 {
      return 0
 } else if x <= 2 {
      return 1
 } else {
      return fib(x-2) + fib(x-1)
   }
}
```

在我们的`memoize.go`文件中，我们要做的最后一件事是创建以下函数：

```go
func FibMemoized(n int) int {
   return fibMem(n)
}
```

现在，是时候看看我们的连线是否正常工作了。在我们的`main()`函数中，当我们执行`println`语句时，我们得到了正确的输出。

```go
println(fibonacci.FibMemoized(5))
```

以下是输出：

```go
5
```

我们可以通过回顾本章前面显示的`Fibonacci(5)`*计算图*来验证 5 是否是正确答案。

如果我们使用调试器逐步执行我们的代码，我们会看到`fibonacci.FibMemoized(5)`调用了以下内容

```go
func FibMemoized(n int) int {
   return fibMem(n)
}
```

`n`变量的值为 5。由于`fibMem`已经预先连接，我们从`return`语句开始执行（并且我们可以访问已经初始化的`cache`变量）。因此，我们从以下代码中的`return`语句开始执行（从`Memoize`函数）：

```go
return func(key int) int {
   if val, found := cache[key]; found {
      return val
   }
   temp := mf(key)
   cache[key] = temp
   return temp
}
```

由于这是第一次执行，缓存中没有条目，我们跳过 if 块的主体并运行`temp := mf(key)`

调用`fib`函数：

```go
func fib(x int) int {
   if x == 0 {
      return 0
 } else if x <= 2 {
      return 1
 } else {
      return fib(x-2) + fib(x-1)
   }
}
```

由于`x`大于 2，我们运行最后的 else 语句，递归调用`fib`两次。对`fib`的递归调用会一直持续，直到达到基本条件，然后计算并返回最终结果。

## 匿名函数和闭包之间的区别

让我们看一些简单的代码示例，以了解匿名函数和闭包之间的区别。

这是一个典型的命名函数：

```go
func namedGreeting(name string) {
   fmt.Printf("Hey %s!n", name)
}
```

以下是匿名函数的示例：

```go
func anonymousGreeting() func(string) {
     return func(name string) {
            fmt.Printf("Hey %s!n", name)
     }
}
```

现在，让我们同时调用它们，并调用一个匿名内联函数对 Cindy 说“嘿”：

```go
func main() {
   namedGreeting("Alice")

   greet := anonymousGreeting()
   greet("Bob")

   func(name string) {
      fmt.Printf("Hello %s!n", name)
   }("Cindy")
}
```

输出如下：

```go
Hello Alice!
Hello Bob!
Hello Cindy!
```

现在，让我们看一个名为`greeting`的闭包，并看看它与`anonymousGreeting()`函数的区别。

由于闭包函数在与`msg`变量相同的作用域中声明，所以闭包可以访问它。`msg`变量被称为与闭包在同一环境中；稍后，我们将看到闭包的环境变量和数据可以在程序执行期间传递和引用：

```go
func greeting(name string) {
     msg := name + fmt.Sprintf(" (at %v)", time.Now().String())

     closure := func() {
            fmt.Printf("Hey %s!n", msg)
     }
     closure()
}

func main() {
     greeting("alice")
}
```

输出如下：

```go
Hey alice (at 2017-01-29 12:29:30.164830641 -0500 EST)!
```

在下一个示例中，我们将闭包返回而不是在`greeting()`函数中执行它，并将其返回值分配给`main`函数中的`hey`变量：

```go
func greeting(name string) func() {
     msg := name + fmt.Sprintf(" (at %v)", time.Now().String())
     closure := func() {
            fmt.Printf("Hey %s!n", msg)
     }
     return closure
}

func main() {
     fmt.Println(time.Now())
     hey := greeting("bob")
     time.Sleep(time.Second * 10)
     hey()
}
```

输出如下：

```go
2017-01-29 12:42:09.767187225 -0500 EST
Hey bob (at 2017-01-29 12:42:09.767323847 -0500 EST)!
```

请注意，时间戳是在初始化`msg`变量时计算的，在将`greeting("bob")`的值分配给`hey`变量时。

所以，10 秒后，当调用`greeting`并执行闭包时，它将引用 10 秒前创建的消息。

这个例子展示了闭包如何保留状态。闭包允许创建、传递和随后引用状态，而不是在外部环境中操作状态。

使用函数式编程，你仍然有一个状态，但它只是通过每个函数传递，并且即使外部作用域已经退出，它仍然是可访问的。

在本书的后面，我们将看到一个更现实的例子，说明闭包如何被利用来维护 API 所需的应用程序资源的上下文。

加速我们的递归斐波那契函数的另一种方法是使用 Go 的并发构造。

### 使用 Go 的并发构造的 FP

给定表达式`result := function1() + function2()`，并行化意味着我们可以在不同的 CPU 核心上运行每个函数，并且总时间将大约等于最昂贵函数返回其结果所需的时间。考虑以下关于并行化和并发性的解释：

+   **并行化**：同时执行多个函数（在不同的 CPU 核心上）

+   **并发**：将程序分解成可以独立执行的部分

我建议你观看 Rob Pike 的视频*并发不等于并行*，网址为[`player.vimeo.com/video/49718712`](https://player.vimeo.com/video/49718712)。在视频中，他解释了并发是将复杂问题分解为更小的组件，这些组件可以同时运行，从而提高性能，前提是它们之间的通信得到管理。

Go 通过使用通道增强了 Goroutines 的并发执行，使用`Select`语句提供了多路并发控制。

以下语言构造为 Go 提供了一个易于理解、使用和推理的并发软件构建模型：

+   **Goroutine**：由 Go 运行时管理的轻量级线程。

+   **Go 语句**：`go`指令启动函数调用的执行，作为独立的并发控制线程，或 Goroutine，在与调用代码相同的地址空间中。

+   **通道**：一种类型的导管，通过它可以使用通道操作符`<-`发送和接收值。

在下面的代码中，`data`在第一行发送到`channel`。在第二行，`data`被赋予从`channel`接收到的值：

```go
channel <- data
data := <-channel
```

由于 Go 通道的行为类似于 FIFO 队列，先进先出，而斐波那契序列中下一个数的计算是一个小组件，因此我们的斐波那契序列函数计算似乎是并发实现的一个很好的候选。

让我们试一试。首先，让我们定义一个使用通道执行斐波那契计算的`Channel`函数：

```go
func Channel(ch chan int, counter int) {
       n1, n2 := 0, 1
 for i := 0; i < counter; i++ {
              ch <- n1
              n1, n2 = n2, n1 + n2
       }
       close(ch)
}
```

首先，我们声明变量`n1`和`n2`来保存我们的初始序列值`0`和`1`。

然后，我们创建一个循环，循环次数为给定的总次数。在每个循环中，我们将下一个顺序数发送到通道，并计算序列中的下一个数，直到达到我们的计数器值，即序列中的最后一个顺序数。

`FibChanneled`函数创建一个通道，即`ch`，使用`make()`函数并将其定义为包含整数的通道：

```go
func FibChanneled(n int) int {
       n += 2
 ch := make(chan int)
       go Channel(ch, n)
       i := 0; var result int
       for num := range ch {
              result = num
              i++
       }
       return result
}
```

我们将我们的`Channel`（斐波那契）函数作为 Goroutine 运行，并传递给它`ch`通道和`8`数字，告诉`Channel`生成斐波那契序列的前八个数字。

接下来，我们遍历通道并打印通道产生的任何值，只要通道尚未关闭。

现在，让我们休息一下，检查一下我们在斐波那契序列示例中取得的成就。

## 使用测试驱动开发测试 FP

让我们编写一些测试来验证每种技术（简单递归，记忆化和通道）是否正常工作。我们将使用 TDD 来帮助我们设计和编写更好的代码。

TDD 是一种软件开发方法，开发人员从需求开始，首先编写一个简单的测试，然后编写足够的代码使其通过。它重复这种单元测试模式，直到没有更多合理的测试来验证代码是否满足要求。这个概念是*立即让它工作，然后稍后完善*。每次测试后，都会执行重构以实现更多的功能需求。

相同或类似的测试将再次执行，同时引入新的测试代码来测试功能的下一部分。该过程将根据需要重复多次，直到每个单元根据所需的规格进行操作。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/79c13566-2ba5-4090-8d9e-dd1619702ed7.png)

TDD 工作流程图

我们可以开始使用输入值和相应结果值的表格来验证被测试的函数是否正常工作：

```go
// File: chapter1/_01_fib/ex1_test.go
package fib

import "testing"

var fibTests = []struct {
   a int
   expected int
}{
   {1, 1},
   {2, 2},
   {3, 3},
   {4, 5},
   {20, 10946},
   {42, 433494437},
}

func TestSimple(t *testing.T) {
   for _, ft := range fibTests {
      if v := FibSimple(ft.a); v != ft.expected {
        t.Errorf("FibSimple(%d) returned %d, expected %d", ft.a, v, ft.expected)
      }
   }
}
```

回想一下，斐波那契序列看起来是这样的：`1  1  2  3  5  8  13  21  34`。这里，第一个元素是`1 {1, 1}`，第二个元素是`2 {2, 2}`，依此类推。

我们使用 range 语句逐行遍历表格，并检查每个计算结果（`v := FibSimple(ft.a)`）与该行的预期值（`ft.expected`）是否一致。

只有在出现不匹配时，我们才报告错误。

稍后在`ex1_test.go`文件中，我们发现基准测试设施正在运行，这使我们能够检查我们的 Go 代码的性能：

```go
func BenchmarkFibSimple(b *testing.B) {
     fn := FibSimple
     for i := 0; i < b.N; i++ {
            _ = fn(8)
     }
}
```

让我们打开一个终端窗口，并写入`cd`命令到第一组 Go 代码，即我们书籍的源代码存储库。对我来说，该目录是`~/clients/packt/dev/fp-go/1-functional-fundamentals/ch01-pure-fp/01_fib`。

### 关于路径的说明

在第一个示例中，我使用了`~/myprojects/fp-go`路径。我实际用于创建本书中代码的路径是`~/clients/packt/dev/fp-go`。所以，请不要被这些路径所困扰。它们是同一个东西。

此外，在本书的后面，当我们开始使用 KISS-Glide 时，屏幕截图可能会引用`~/dev`目录。这来自初始化脚本，即`MY_DEV_DIR=~/dev`。

在该目录中有一些链接：

```go
01_duck@ -> /Users/lex/clients/packt/dev/fp-go/2-design-patterns/ch04-solid/01_duck
01_hof@ -> /Users/lex/clients/packt/dev/fp-go/1-functional-fundamentals/ch03-hof/01_hof
04_onion@ -> /Users/lex/clients/packt/dev/fp-go/2-design-patterns/ch07-onion-arch/04_onion
```

有关 KISS-Glide 的更多信息，请参阅附录。

### 如何运行我们的测试

在第一个基准测试中，我们检查了计算斐波那契数列中第八个数字的性能。请注意，我们传入了`-bench=.`参数，这意味着运行所有基准测试。`./...`参数表示运行此目录及所有子目录中的所有测试：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/33f7376d-15ce-4343-87fb-d5118f43194d.png)

当我们请求数列中的第八个数字时，简单的递归实现比记忆化和通道化（优化）版本运行得更快，分别为`213 ns/op`，`1302 ns/op`和`2224 ns/op`。

实际上，当简单版本执行一次时，只需要`3.94 ns/op`。

Go 基准测试设施的一个非常酷的特性是，它足够聪明，可以找出要执行被测试函数的次数。`b.N`的值将每次增加，直到基准测试运行器对基准测试的稳定性感到满意。函数在测试下运行得越快，基准测试设施就会运行得越多。基准测试设施运行函数的次数越多，性能指标就越准确，例如`3.94 ns/op`。

以`FibSimple`测试为例。当传入`1`时，意味着只需要执行一次。由于每次执行只需要`3.94 ns/op`，我们看到它被执行了 10,000,000 次。然而，当`FibSimple`传入`40`时，我们发现完成一次操作需要 2,509,110,502 ns，并且基准测试设施足够智能，只运行一次。这样，我们可以确保运行基准测试尽可能准确，并且在合理的时间内运行。多好啊？

由于`FibSimple`实现是递归的，并且没有被优化，我们可以测试我们的假设，即计算数列中每个后续数字所需的时间将呈指数增长。我们可以通过调用私有函数`benchmarkFibSimple`来使用一种常见的测试技术来做到这一点，该函数避免直接调用测试驱动程序：

```go
func benchmarkFibSimple(i int, b *testing.B) {
     for n := 0; n < b.N; n++ {
            FibSimple(i)
     }
}

func BenchmarkFibSimple1(b *testing.B)  { benchmarkFibSimple(1, b) }
func BenchmarkFibSimple2(b *testing.B)  { benchmarkFibSimple(2, b) }
func BenchmarkFibSimple3(b *testing.B)  { benchmarkFibSimple(3, b) }
func BenchmarkFibSimple10(b *testing.B) { benchmarkFibSimple(4, b) }
func BenchmarkFibSimple20(b *testing.B) { benchmarkFibSimple(20, b) }
func BenchmarkFibSimple40(b *testing.B) { benchmarkFibSimple(42, b) }
```

我们测试了数列中的前四个数字，`20`和`42`。由于我的计算机计算数列中的第 42 个数字大约需要 3 秒，我决定不再继续。当我们可以轻松看到指数增长模式时，就没有必要等待更长的时间来获取结果了。

我们的基准测试已经证明，我们对斐波那契数列的简单递归实现表现如预期。这种行为等同于性能不佳。

让我们看看一些提高性能的方法。

我们观察到我们的`FibSimple`实现总是返回相同的结果，给定相同的输入，并且在其运行环境中没有副作用。例如，如果我们传入`FibSimple`一个`8`值，我们知道每次结果都将是`13`。我们利用了这一事实来利用一种称为记忆化的缓存技术来创建`FibMemoized`函数。

现在，让我们编写一些测试，看看`MemoizeFcn`有多有效。

由于我们的`fibTests`结构已在包中的另一个测试中定义，即`chapter1/_01_fib/ex1_test.go`，我们不需要重新定义它。这样，我们只需定义一次测试表，就能够在后续的斐波那契函数实现中重复使用它，以获得合理的苹果对苹果的比较。

这是`FibMemoized`函数的基本单元测试：

```go
func TestMemoized(t *testing.T) {
   for _, ft := range fibTests {
      if v := FibMemoized(ft.a); v != ft.expected {
         t.Errorf("FibMemoized(%d) returned %d, expected %d", ft.a, v, ft.expected)
      }
   }
}
```

除非我们的代码中有错误，否则它不会返回错误。

这就是运行单元测试的好处之一。除非出现问题，否则您不会听到它们。

我们应该编写单元测试以便：

+   确保您实现的内容符合您的功能要求

+   利用测试来帮助您考虑如何最好地实施您的解决方案

+   生成可以在您的持续集成过程中使用的高质量测试

+   验证您的实现是否符合应用程序其他部分的接口要求

+   使开发集成测试更容易

+   保护您的工作免受其他开发人员的影响，他们可能会实现一个可能在生产中破坏您代码的组件

以下是基准测试的结果：

```go
func BenchmarkFibMemoized(b *testing.B) {
     fn := FibMemoized
     for i := 0; i < b.N; i++ {
            _ = fn(8)
     }
}
```

与以前一样，在`FibSimple`示例中，我们检查了计算斐波那契数列中第八个数字的性能：

```go
func BenchmarkFibMemoized(b *testing.B) {
     fn := FibMemoized
     for i := 0; i < b.N; i++ {
            _ = fn(8)
     }
}

func benchmarkFibMemoized(i int, b *testing.B) {
     for n := 0; n < b.N; n++ {
            FibMemoized(i)
     }
}

func BenchmarkFibMemoized1(b *testing.B)  { 
    benchmarkFibMemoized(1, b) }
func BenchmarkFibMemoized2(b *testing.B)  { 
    benchmarkFibMemoized(2, b) }
func BenchmarkFibMemoized3(b *testing.B)  { 
    benchmarkFibMemoized(3, b) }
func BenchmarkFibMemoized10(b *testing.B) { 
    benchmarkFibMemoized(4, b) }
func BenchmarkFibMemoized20(b *testing.B) { 
    benchmarkFibMemoized(20, b) }
func BenchmarkFibMemoized40(b *testing.B) { 
    benchmarkFibMemoized(42, b) }
```

与以前一样，我们进行了一项测试，使用`1`、`2`、`3`、`4`、`20`和`42`作为输入调用`FibMemoized`。

以下是`FibChanelled`函数的完整列表：

```go
package fib

import "testing"

func TestChanneled(t *testing.T) {
     for _, ft := range fibTests {
            if v := FibChanneled(ft.a); v != ft.expected {
                   t.Errorf("FibChanneled(%d) returned %d, expected %d", ft.a, v, ft.expected)
            }
     }
}

func BenchmarkFibChanneled(b *testing.B) {
     fn := FibChanneled
     for i := 0; i < b.N; i++ {
            _ = fn(8)
     }
}

func benchmarkFibChanneled(i int, b *testing.B) {
     for n := 0; n < b.N; n++ {
            FibChanneled(i)
     }
}

func BenchmarkFibChanneled1(b *testing.B)  { 
    benchmarkFibChanneled(1, b) }
func BenchmarkFibChanneled2(b *testing.B)  { 
    benchmarkFibChanneled(2, b) }
func BenchmarkFibChanneled3(b *testing.B)  { 
    benchmarkFibChanneled(3, b) }
func BenchmarkFibChanneled10(b *testing.B) { 
    benchmarkFibChanneled(4, b) }
func BenchmarkFibChanneled20(b *testing.B) { 
    benchmarkFibChanneled(20, b) }
func BenchmarkFibChanneled40(b *testing.B) { 
    benchmarkFibChanneled(42, b) }
```

我们对原始斐波那契数列逻辑进行了两次优化，使用了缓存技术和 Go 的并发特性。我们编写了这两种优化实现。还有更多的优化可能。在某些情况下，可以将优化技术结合起来产生更快的代码。

如果我们只需要编写一个简单的递归版本，然后在编译 Go 代码时，Go 编译器会自动生成带有性能优化的目标代码，那该有多好？

**惰性求值**：一种延迟对表达式进行求值直到需要其值的求值策略，通过避免不必要的计算来提高性能。

## 从命令式编程到纯 FP 和启示的旅程

让我们从命令式编程`sum`函数转向纯函数式编程的旅程。首先，让我们看看命令式的`sum`函数：

```go
func SumLoop(nums []int) int {
       sum := 0
 for _, num := range nums {
              sum += num
       }
       return sum
}
```

整数变量`sum`会随时间改变或变异；`sum`是不可变的。在纯 FP 中没有 for 循环或变异变量。

那么，我们如何使用纯 FP 来迭代一系列元素呢？我们可以使用递归来实现这一点。

**不可变变量**：在运行时分配值并且不能被修改的变量。

请注意，Go 确实有常量，但它们与不可变变量不同，常量的值是在编译时分配的，而不是在运行时分配的：

```go
func SumRecursive(nums []int) int {
       if len(nums) == 0 {
              return 0
 }
       return nums[0] + SumRecursive(nums[1:])
}
```

请注意前面的`SumRecursive`函数的最后一行调用了自身：`SumRecursive(nums[1:])`。这就是递归。

### SumLoop 函数的基准测试

我们听说 Go 中的递归可能很慢。因此，让我们编写一些基准测试来检查一下。首先，让我们测试基本命令式函数`SumLoop`的性能：

```go
func benchmarkSumLoop(s []int, b *testing.B) {
       for n := 0; n < b.N; n++ {
              SumLoop(s)
       }
}

func BenchmarkSumLoop40(b *testing.B) { benchmarkSumLoop([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40}, b) }
```

**结果**：每次操作耗时`46.1 ns`。

### SumRecursive 函数的基准测试

现在我们知道了命令式函数`SumLoop`需要多长时间，让我们编写一个基准测试来看看我们的递归版本，即`SumRecursive`需要多长时间：

```go
func benchmarkSumRecursive(s []int, b *testing.B) {
       for n := 0; n < b.N; n++ {
              SumRecursive(s)
       }
}

func BenchmarkSumRecursive40(b *testing.B) { benchmarkSumRecursive([]int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40}, b) }
```

**结果**：每次操作耗时`178 ns`。

在 Prolog、Scheme、Lua 和 Elixir 等语言中，尾调用递归速度更快，而符合 ECMAScript 6.0 标准的 JavaScript 引擎采用了纯函数式编程风格。因此，让我们试一试：

```go
func SumTailCall(vs []int) int {
       if len(vs) == 0 {
              return 0
 }
       return vs[0] + SumTailCall(vs[1:])
}
```

**基准测试结果**：每次操作耗时`192 ns`。

**TCO**：尾调用是指函数的最后一条语句是一个函数调用。优化的尾调用已经被有效地替换为`GoTo`语句，它消除了在函数调用之前设置调用堆栈和在函数调用之后恢复调用堆栈所需的工作。

我们甚至可以使用`GoTo`语句来进一步加速尾递归，但它仍然比命令式版本慢三倍。

为什么？这是因为 Go 不支持纯 FP。例如，Go 不执行 TCO，也不提供不可变变量。

### 一次清算

为什么我们想在 Go 中使用纯 FP？如果编写表达力强、易于维护和富有洞察力的代码比性能更重要，那或许可以考虑。

我们有哪些替代方案？稍后，我们将看一些纯 FP 库，它们已经为我们做了大量工作，并且在更高性能方面取得了进展。

在 Go 中的函数式编程就是这些吗？不，远远不止这些。我们在 Go 中可以做的 FP 目前受到 Go 编译器目前不支持 TCO 的限制；然而，这可能很快会改变。有关详细信息，请参阅附录中的*如何提出 Go 更改*部分。

函数式编程的另一个方面是 Go 完全支持的：函数文字。事实证明，这是支持 FP 所必须具有的最重要特征。

**函数文字**：这些函数被视为语言的一等公民，例如，任何变量类型，如 int 和 string。在 Go 中，函数可以声明为一种类型，分配给变量和结构的字段，作为参数传递给其他函数，并从其他函数中作为值返回。函数文字是闭包，使它们可以访问其声明的范围。当函数文字在运行时分配给变量时，例如，`val := func(x int) int { return x + 2}(5)`，我们可以称该**匿名函数**为**函数表达式**。函数文字用于 lambda 表达式以及柯里化。 （有关 lambda 表达式的详细信息，请参见第十章，*函子、幺半群和泛型*。）

#### 函数文字的一个快速示例

请注意，`{ret = n + 2}`是我们的匿名函数/函数文字/闭包/lambda 表达式。

我们的函数文字：

+   像函数声明一样编写，但在`func`关键字后没有函数名称

+   是一个表达式

+   可以访问其词法范围中的所有变量（在我们的例子中为`n`）

```go
package main

func curryAddTwo(n int) (ret int) {
   defer func(){ret = n + 2}()
   return n
}

func main()  {
   println(curryAddTwo(1))
}
```

输出如下：

```go
3
```

请注意，我们使用`defer`语句延迟执行我们的函数文字，直到其周围的函数（`curryAddTwo`）返回。由于我们的匿名函数可以访问其范围内的所有变量（`n`），它可以修改`n`。修改后的值就是打印出来的值。

## 总结

在测试纯函数时，我们只需传递输入参数并验证结果。无需设置环境或上下文。不需要存根或模拟。没有副作用。测试再也不容易了。

纯函数可以在水平扩展的多 CPU 环境中并行化以获得性能增益。然而，鉴于 Go 尚未经过优化以支持纯函数式编程，Go 中的纯 FP 实现可能无法满足我们的性能要求。我们不会让这妨碍我们利用 Go 的许多有效的非纯函数式编程技术。我们已经看到了通过添加缓存逻辑和利用 Go 的并发功能来提高性能。有许多我们可以使用的功能模式，我们很快就会看到。我们还将看到我们如何利用它们来满足严格的性能要求。

在下一章中，您将学习高阶函数，因为我们探索使用 FP 编程技术来操作集合的不同方式。


# 第二章：操作集合

处理项目列表在生活中以及编程语言中是常见的。当一个列表有相关的函数帮助我们操作列表中的项目时，我们通常称该对象为集合。

在这一章中，我们将看到如何使用高阶函数来极大地简化操作集合的任务。我们将看到如何使用函数式编程技术和开源的函数式包来创建优雅的解决方案，这些解决方案不仅富有洞察力，而且在当今的分布式处理环境中也具有高性能。

本章的目标是：

+   遍历集合

+   了解中间和终端函子

+   使用谓词来过滤集合中的项目

+   使用类似 Mocha 的 BDD 库进行测试

+   专注于 Map 函数

+   掌握 Itertools 中操作集合的函数的广度

+   利用例程和通道来遍历集合

+   看看我们如何使用 Go 处理大数据集合

## 遍历集合

为了实现一个集合，我们必须提供一种访问集合中每个元素的方式，可以使用下面代码中显示的 int 索引值来实现。我们将实现一个**先进先出**（**FIFO**）顺序队列。我们将提供一种使用切片数据结构来存储元素的方法。最后，我们将实现一个`Next()`方法来提供一种遍历集合中元素的方式。

在下面的代码中，我们为`Iterator`对象定义了一个接口。它有一个`Next()`方法，它将返回集合中的下一个元素和一个布尔标志，指示是否可以继续迭代：

```go
type CarIterator interface {
     Next() (value string, ok bool)
}
const INVALID_INT_VAL = -1
const INVALID_STRING_VAL = ""
```

接下来，我们定义一个具有两个属性的集合对象：用于访问当前元素的`int`索引和一个字符串切片，即集合中的实际数据：

```go
type Collection struct {
       index int
       List  []string
}
```

现在，我们实现集合的`Next()`方法，以满足`IntIterator`接口的规范：

```go
func (collection *Collection) Next() (value string, ok bool) {
       collection.index++
       if collection.index >= len(collection.List) {
              return INVALID_STRING_VAL, false
       }
       return collection.List[collection.index], true
}
```

`newSlice`函数是可迭代集合`intCollection`的构造函数：

```go
func newSlice(s []string) *Collection {
        return &Collection{INVALID_INT_VAL, s}
}
```

最后，我们实现`main()`函数来测试我们的`Collection`。

让我们打开一个终端窗口，并使用`.init`工具集来运行我们简单的 Go 应用程序：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/a83d65f5-90c5-4260-b7dc-78042af5eb3b.png)

`.init`（"Dot Init"）工具集确保我们已经安装了 Go，并且我们的`GOPATH`和`GOBIN`目录已经正确配置。首先，我们通过输入`.init`来源化初始化脚本。由于我们没有导入语句，因此无需运行 glide-update。要运行我们的应用程序，我们输入`go-run`。有关`Dot Init`的更多详细信息，请参见[附录](https://cdp.packtpub.com/learning_functional_programming_in_go/wp-admin/post.php?post=99&action=edit#post_7)，*其他信息和操作方法*。

这种实现的问题在于我们混合了我们想要做的事情和我们如何做的事情。我们实现了一个显式的`for`循环来执行迭代的机制。我们定义并改变了索引值的值，以便遍历元素。我们可以立即看到这是一种命令式的实现。

在函数式编程中，我们声明要做什么，而不是命令式地实现每个操作的每个细节。我们还避免了`for`循环的顺序性质，这些循环很难适应并发编程模型。

Go 不是一种函数式编程语言，但它具有许多函数式特性，我们可以利用这些特性来编写简洁、表达力强、并且希望是无错误的代码。

纯函数式语言不维护状态。函数调用经常被链接在一起，其中输入从一个函数传递到另一个函数。每个函数调用以某种方式转换其输入。这些函数不需要关心外部状态，也不会产生副作用。每个函数调用在其所做的事情上都可以非常高效。这种编程风格适合进行高效的测试。

接下来，我们将看到函数链式调用非常类似于通过 Bash 命令传递输出。

## Bash 命令传递

执行函数的组合或链非常类似于执行一系列 Bash 命令，其中一个命令的输出被传送到下一个命令。例如，我们可能在`awk`命令中输入一个包含时间戳和 IP 地址列表的文件。`awk`命令删除除第七列之外的所有内容。接下来，我们按降序对列表进行排序，最后，我们按唯一的 IP 地址对数据进行分组。

考虑以下 Bash 命令：

```go
$ cat ips.log | awk '{print $7}' | sort | uniq -c
```

让我们给这个命令以下输入：

```go
Sun Feb 12 20:27:32 EST 2017 74.125.196.101
Sun Feb 12 20:27:33 EST 2017 98.139.183.24
Sun Feb 12 20:27:34 EST 2017 151.101.0.73
Sun Feb 12 20:27:35 EST 2017 98.139.183.24
Sun Feb 12 20:27:36 EST 2017 151.101.0.73
>Sun Feb 12 20:27:37 EST 2017 74.125.196.101
Sun Feb 12 20:27:38 EST 2017 98.139.183.24
Sun Feb 12 20:27:39 EST 2017 151.101.0.73
Sun Feb 12 20:27:40 EST 2017 98.139.183.24
Sun Feb 12 20:27:41 EST 2017 151.101.0.73
Sun Feb 12 20:27:42 EST 2017 151.101.0.73
Sun Feb 12 20:27:43 EST 2017 151.101.0.73
```

我们将得到以下输出：

```go
6 151.101.0.73
2 74.125.196.101
4 98.139.183.24
```

这是函数式编程中非常常见的模式。我们经常将数据集输入到函数或一系列函数调用中，并获得以某种方式转换的结果。

集合经常被使用。当我们以简洁的方式实现它们时，通过链式函数调用明确声明我们想要实现的目标，我们大大减少了代码的繁文缛节。结果是，我们的代码更具表现力、简洁，并且更易于阅读。

## 函子

Go 有三种预声明/原始数据类型：`bool`、`string`、数值（`float`、`int64`等）。Go 中的其他数据类型需要类型声明，也就是说，它们需要我们使用`type`关键字。函数属于后一类数据类型，与数组、结构、指针、接口、切片、映射和通道类型一起。在 Go 中，函数是头等数据类型，这意味着它们可以作为参数传递并作为值返回。可以接受函数作为参数并返回函数的函数称为高阶函数。

我们可以编写函数工厂--返回函数的函数--甚至函数工厂工厂。我们还可以编写修改函数或为特定目的创建函数的函数。

**函子**：函子是一个包含`X`变量的集合，可以将函数`f`应用于自身，以创建一个`Y`的集合，即`f(X) → Y`。（要了解我们在这里谈论的是什么，请快速查看第九章中的*Fingers times 10 functor*示例，*函子、幺半群和泛型*）

请注意，Prolog 软件语言将函子定义为简单的函数。前面的定义来自于函数式编程对*范畴论*的影响。（有关更多详细信息，请参见第十一章，*适用的范畴论*。）

### 修改函数的函数

在我们探索中间和终端函数之前，让我们通过一些例子澄清短语*修改函数的函数*。

#### 函数修改函数的编码示例

以下是我们可能编写的代码片段，用于构建一个页面部分，其中包含两个下拉列表，一个用于汽车制造商，另一个用于汽车型号：

```go
// http.Get :: String -> JSON
var renderPage = curry(func(makes, models) { /* render page */ })
// return two divs: one with makes and the other with models HTML/ULs
Task.Of(renderPage).Ap(http.Get("/makes")).Ap(http.Get("/models"))
```

请注意，每个 http.Get 都是一个单独的 API 调用。每个 API 调用都是部分应用。为了使 renderPage 等待每个调用完成，我们必须对我们的 API 调用进行柯里化。

以下是生成的 HTML 可能看起来像：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/108dc35b-5d2a-48a3-a59f-1dbe93e674d5.png)

#### 函数修改函数的视觉示例

在上一个例子中，我们组成了 HTML 网页的一部分。在这个例子中，让我们沉浸在一个铁路世界中，使用函数组合铺设一些火车轨道。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/0f10db22-6848-4ac4-b2cc-7b6edc8ff6e5.png)

沉浸式铁路世界

以下是我们的可重用组件工具箱。我们通过从工具箱中添加项目来修改我们的世界。因此，我们沉浸式铁路*世界*函数通过添加和连接一堆较小的*组件*函数来修改。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/e9f7d447-6994-47df-8b0d-290b01cdc9a9.png)

这是 Christian 铺设铁路开关的一个例子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/b1bf5814-eaad-48aa-a4bb-d26eb1397e7b.png)

##### Mindcraft 中的组合

我们可以在[`github.com/cam72cam/ImmersiveRailroading`](https://github.com/cam72cam/ImmersiveRailroading)找到这个 Immersive Railroad 应用的源代码。

Minecraft 可以选择通过柯里化部分应用来专门使用 FP 技术实现其世界构建 UI，但当我们仔细观察时，我们发现更多的是命令式实现。尽管使用了泛型：

```go
// cam72cam.immersiverailroading.render.TileSteamHammerRender
public class TileSteamHammerRender extends TileEntitySpecialRenderer<TileSteamHammer> {   
   private List<String> hammer;
   private List<String> rest;
```

### Tacit 编程

Tacit 编程是一种编程风格，其中函数定义组合其他函数，组合器操作参数。组合器是一个高阶函数，它仅使用函数应用程序和预定义的组合器来定义其参数的结果。有关更多详细信息，请参见第十一章中的 Moses Schonfinkel 部分，*适用的范畴论*。

#### 使用 Unix 管道的 Tacit 编程

管道中的以下组合器是函数，例如`head`，`awk`，`grep`等。每个组合器都是一个将输出发送到标准输出并从标准输入读取输入的函数。请注意，命令中没有提到参数。

```go
$ cat access10k.log | head -n 1 | awk '{print $7}' | grep "\.json" | uniq -c | sort -nr 
```

#### 使用 Unix 管道编程 CMOS

Unix 管道也可以用来模拟 CMOS 设备的 NAND 门的流程控制。

假设 nil 代表电子，那么`/dev/zero`（又名 VSS）提供了无限的电子供应，`/dev/null`（又名 VDD）将消耗发送到它的每个电子。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/7c08dd33-3219-4653-983f-451d32b33aae.png)

CMOS NAND 门

在我们的模型中，UNIX 管道就像一根导线。当管道连接到 Vss 时，其缓冲区填满了空字节，管道就像一个带负电荷的金属板。当它连接到 Vdd 时，管道的缓冲区被排空，管道就像一个带正电荷的金属板。Unix 管道用于模拟我们的 NAND 逻辑门中的流程控制。

有关更多详细信息，请参见[`www.linusakesson.net/programming/pipelogic/index.php`](http://www.linusakesson.net/programming/pipelogic/index.php)。

#### 使用 FP 的 Tacit 编程

我们将使用 Haskell 来演示一个对整数列表求和的程序。两者都是递归的，第二个受益于**尾调用优化**（**TCO**）。我们可以使用 Go，但目前 Go 不支持 TCO。

我们循环遍历数字列表以累积总和。在命令式编程中，我们将使用循环索引来存储累积和值。在函数式编程中，我们使用递归来实现循环，其中累积和作为参数传递给下一个递归调用。在命令式语言中作为循环索引变量/累加器变量的东西在尾递归版本中成为*参数*。

##### 非 TCO 递归示例

首先，我们来看看命令式的例子：

```go
rSum :: [Integer] -> Integer
rSum (x:xs) = x + (rSum xs)
rSum [] = 0

```

请注意，x:xs 表示我们将列表的头存储在 x 中，列表的其余部分存储在 xs 中。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/b5312a5a-329b-447d-a3f9-04a86b194eca.png)

每次调用`rSum`都需要获取递归调用的返回值，并将其添加到其 x 参数中，然后才能返回。这意味着每个函数必须比其调用的任何函数的帧在堆栈上停留更长的时间。我们必须创建四个堆栈帧来对三个数字求和。想象一下，当我们处理具有大量值的列表时，这种实现将需要多少 RAM 存储空间。没有 TCO，我们的实现将需要**O**(n)的 RAM 存储空间，根据列表中的项目数。（请参阅第十章中的大 O 符号表示法，*单子，类型类和泛型*）

##### TCO 递归示例

在我们的尾递归函数中，我们的堆栈帧不需要被保留。

```go
tSum :: [Integer] -> Integer
tSum lst = tSum lst 0 where
 tSum (x:xs) i = tSum xs (i+x)
    tSum [] i = i
```

以下图表说明了与先前的例子（`rSum`）不同，`tSum`在进行递归调用后不需要在帧的上下文中执行任何操作。`rSum`为列表的每个成员创建了一个堆栈帧。`tSum`只需要创建一个堆栈帧，然后重用它。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/17c37ebf-a4a8-44a3-9a9e-38acf240fe79.png)

TCO 在递归的最后调用是函数本身时避免创建新的堆栈帧。Go 目前不支持 TCO。这意味着什么？没有 TCO，我们应该避免使用递归来处理具有大量元素的列表，也就是说，超过几千个；否则，我们的程序很可能会耗尽内存并崩溃。为什么不用实现命令式循环的函数替换递归函数？换句话说，递归在函数式编程中的重要性是什么？

### 递归的重要性

首先，让我们确保我们理解递归是什么。让我们想想如何拆开俄罗斯娃娃。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/f685a5c3-86ee-4fdf-8ae6-6e6afe872654.png)

递归的工作原理就像寻找最小的娃娃的过程。我们重复相同的过程，即，拆开娃娃，直到找到一个实心的娃娃。虽然我们的问题变得更小，但问题解决的过程与之前相同，因为嵌套娃娃的结构是相同的。每个娃娃都比前一个小。最终，我们找到了一个太小而无法再放置娃娃的娃娃，我们完成了。这就是递归背后的基本思想。

我们还需要了解如何编写尾递归函数，因为这是 TCO 的候选递归类型。当我们的递归函数在最后一个动作调用自身时，我们可以重用该函数的堆栈帧。上一节中的 tSum 函数就是尾递归的一个例子。

理解递归标志着我们从程序员转变为计算机科学家。递归需要一些数学知识来理解，但一旦我们掌握了它，我们会发现它为解决重要问题打开了大量的方式。

一个足球教练不会让他的球员练习将球踢下山到目标处；这种情况在比赛中永远不会发生。同样，我们也不会花费大量时间追求在 Go 中的递归实现。

尾递归函数是循环的函数形式，通过 TCO 执行效率与循环一样高。没有递归，我们必须使用命令式编程技术来实现大多数循环。因此，在 Go 中具有 TCO 实际上对 FP 比泛型更有益。我们将在第九章 *函子、幺半群和泛型*和第十章 *单子、类型类和泛型*中了解更多关于泛型的知识。请参阅附录中的*如何提出对 Go 的更改*部分，或直接跳转到有关在 Go 中添加 TCO 的讨论[`github.com/golang/go/issues/22624`](https://github.com/golang/go/issues/22624)。

### 各种中间和终端函数

看看以下函子图中的各种中间和终端函数。它们都是函子。例如，当函数`Map`提供一组值作为输入时，它将对元素应用转换，并产生一个不同的值集作为输出。

在函数式编程中，对于相同的输入，给定函数将始终返回相同的结果集。

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/699a2988-487c-40d7-98ba-e99bc371c96a.png)

在前面的函子的第一行中，`Map`和`Sort`，接受一个集合，以某种方式对其进行转换，并返回一个相同大小的集合。

在函子图的第二行中，`Filter`和`GroupBy`，接受一个集合，并将其转换为另一个较小的集合。

在第三行中，`Reduce`接受一个集合，对其元素执行计算，并返回单个结果值。

### 减少的例子

以下是使用`alediaferia/go-collections`包来减少集合以找到最大值的实现：

```go
numbers := []interface{}{
 1,
 5,
 3,
 2,
}

coll := collections.NewFromSlice(numbers)
min := collections.Reduce(0, func(a, b interface{}) interface{} {
 if a > b { return a } else { return b }
})
```

`Join`函数接受两个不同的集合，并将它们合并成一个更大的集合。

函数式编程中有两种基本类型的函子：中间函数和终端函数。它们一起工作，将传入的集合转换为另一个集合或单个值。任意数量的中间函数可以链接在一起，然后是终端函数。

### 中间函数

中间函数在终端函数被处理之前不会被评估。

**惰性评估**是一种延迟处理中间函数的评估策略，直到需要其值为止。它可以与**记忆化**结合使用，其中首先对评估进行缓存，以便对该值的后续请求立即返回缓存的值，而无需重新评估最初创建它的表达式。

一些更流行的中间函数包括`map`、`filter`和`sort`。

我们可以创建许多其他高阶函数来处理传入的流，通常是一个集合。我们很快将看到提供这些基本函数类型各种变体的函数式编程库。

#### 常见的中间函数

这是一个描述一些常见的中间函数的表格：

| **函数** | **Gleam** | **保留类型** | **保留计数** | **保留顺序** | **描述** |
| --- | --- | --- | --- | --- | --- |
| `map` | 是 | 否 | 是 | 是 | 这将列表中的每个元素转换为结果列表中大小相同的另一个元素。 |
| `filter` | 是 | 是 | 否 | 是 | 这调用一个谓词函数。如果为真，则当前项目将被跳过，不会出现在结果列表中。 |
| `sort` | 是 | 是 | 是 | 是 | 这按照标准对结果集进行排序。 |

##### 映射示例

这是使用`alediaferia/go-collections`包对集合进行映射的示例：

```go
names := []interface{}{
 "Alice",
 "Bob",
 "Cindy",
}
collection := collections.NewFromSlice(planets)
collection = collection.Map(func(v interface{}) interface{} {
 return strings.Join([]string{ "Hey ", v.(string) })
})
println(collection)
```

输出如下：

```go
Hey Alice
Hey Bob
Hey Cindy
```

### 终端函数

终端函数会被急切地执行。它们立即执行，一旦执行，它们会执行调用链中的所有先前的中间、惰性函数。终端函数要么返回单个值，要么产生副作用。前面我们看到的 reduce 示例返回一个单个值：`1`。`ForEach`函数不返回值，但可以产生副作用，比如打印出每个项目。`Collect`、`Join`和`GroupBy`函数将集合中的项目分组。

#### 常见的终端函数

这是一个描述一些更流行的终端函数的表格：

| **函数** | **Gleam** | **分组项目** | **创建副作用** | **收集结果** | **描述** |
| --- | --- | --- | --- | --- | --- |
| `Collect`、`Join`和`GroupBy` | 是 | 是 |  |  | 产生另一个集合 |
| `ForEach` | 是 |  | 是 |  | 用于处理单个项目 |
| `Reduce` | 是 |  |  | 是 | 强制要求延迟表达式触发并产生结果 |

##### Join 示例

以下代码显示了`Join()`函数的示例：

```go
 // left collection:
 0001, "alice", "bob"
 0001, "cindy", "dan"
 0002, "evelyn", "frank"
 // right collection:
 0001, "greg", "izzy"
 0002, "jenny", "alice"

left.Join(right)
```

输出如下：

```go
 0001, "alice", "bob", "greg", "izzy"
 0001, "cindy", "dan", "greg", "izzy"
 0002, "evelyn", "frank", "jenny", "alice"
```

##### GroupBy 示例

以下代码显示了`GroupBy()`函数的示例：

```go
// input collection:
 0001, "alice", 0002
 0001, "bob", 0002
 0003, "cindy", 0002

 GroupBy(1,3)
```

输出如下：

```go
 0001, 0002, ["alice", "bob"]
 0003, 0002, ["cindy"]
```

##### Reduce 示例

这是使用`alediaferia/go-collections`包来减少集合以找到最大值的实现：

```go
numbers := []interface{}{
 1,
 5,
 3,
 2,
}
collection := collections.NewFromSlice(numbers)
min := collection.Reduce(0, func(a, b interface{}) interface{} {
 if a > b { return a } else { return b }
})
```

## 谓词

我们可以使用谓词对输入数据执行操作。谓词可用于实现我们应用于集合以将输入数据转换为结果集合或值的许多函数。

`predicate`函数是一个接受一个项目作为输入并根据项目是否满足某些条件返回 true 或 false 的函数。它们通常被条件地使用，以确定是否在执行链中应用某些操作。

让我们创建一些谓词函数，以便我们可以用来操作一组汽车。

`All()`函数仅在集合中的所有值都满足`predicate`条件时返回`true`：

```go
package predicate

func All(vals []string, predicate func(string) bool) bool {
       for _, val := range vals {
              if !predicate(val) {
                     return false
              }
       }
       return true
}
```

`Any()`函数只要集合中的任何一个值满足`predicate`条件就返回`true`：

```go
func Any(vs []string, predicate func(string) bool) bool {
       for _, val := range vs {
              if predicate(val) {
                     return true
              }
       }
       return false
}
```

`Filter()` 函数返回一个新的、更小的或大小相等的集合，其中包含满足 `predicate` 条件的集合中的所有字符串：

```go
func Filter(vals []string, predicate func(string) bool) []string {
       filteredVals := make([]string, 0)
       for _, v := range vals {
              if predicate(v) {
                     filteredVals = append(filteredVals, v)
              }
       }
       return filteredVals
}
```

`Count()` 函数是一个辅助函数：

```go
func Count(vals []string) int {
       return len(vals)
}
```

现在，让我们使用一个名为 `goblin` 的类似 Mocha 的 BDD Go 测试框架来测试我们的谓词。

声明包并定义基本导入。我们只需要定义一个函数。让我们称之为 `TestPredicateSucceed`：

```go
package predicate

import (
       "testing"
 "strings"
 . "github.com/franela/goblin"
)

func TestPredicateSucceed(t *testing.T) {
       fakeTest := testing.T{}
       g := Goblin(&fakeTest)
```

让我们用一个名为 `Predicate Tests` 的 `Describe` 块包装所有我们的单元测试，其中我们定义 `cars` 变量来保存我们的汽车型号列表：

```go
     g.Describe("Predicate Tests", func() {
          cars := []string{"CRV", "IS250", "Highlander"}
```

这是我们的第一个测试。它以一个 `Describe` 块开始，并包含一个 `It` 块。在我们的 `It` 块内，我们将我们的一等函数 `bs` 赋值为调用 `Any()` 函数的返回值。我们的谓词函数是调用 `strings.HasPrefix()` 函数的函数文本。我们的单元测试的最后一行断言 `bs` 是 `true`：

```go
g.Describe("Starts High", func() {
       g.It("Should be true", func() {
              bs := Any(cars, func(v string) bool {
                     return strings.HasPrefix(v, "High")
              })
              g.Assert(bs).Equal(true)
       })
})
```

我们的下一个单元测试说 `Highlander should be High` 并断言它应该为真。我们将 `strings.Contains()` 函数作为我们的谓词传递给 `Filter()` 函数，以仅返回列表中包含 `High` 子字符串的项目：

```go
g.Describe("Highlander should be High", func() {
       high := Filter(cars, func(v string) bool {
              return strings.Contains(v, "High")
       })
       highlander := []string{"Highlander"}
       g.It("Should be true", func() {
              g.Assert(high).Equal(highlander)
       })
})
```

这个测试计算包含 `High` 子字符串的汽车数量，并断言计数应该为 1：

```go
g.Describe("One is High", func() {
       high := Count(Filter(cars, func(v string) bool {
              return strings.Contains(v, "High")
       }))
       g.It("Should be true", func() {
              g.Assert(high).Equal(1)
       })
})
```

我们的最后一个测试断言并非所有汽车都包含 `High` 子字符串：

```go
g.Describe("All are High", func() {
       high := All(cars, func(v string) bool {
              return strings.Contains(v, "High")
       })
       g.It("Should be false", func() {
              g.Assert(high).Equal(false)
       })
})
```

让我们花点时间来反思这个实现。

### 反射

我们的谓词实现是高效的但是有限制的。以 `Any()` 函数签名为例：

```go
func Any(vs []string, predicate func(string) bool) bool
```

`Any` 函数仅适用于 `string` 切片。如果我们想要迭代树或映射结构怎么办？我们将不得不为每个写单独的函数。这是请求 Go 支持泛型的一个有效论点。如果 Go 支持泛型，我们的实现可能需要的代码量会少得多。

另一种替代实现可以使用空接口。这将解决我们需要为要处理的每种数据类型实现单独的函数的问题，因为空接口可以接受任何类型的值。要使用 `interface{}` 类型的值，必须使用反射或类型断言或类型开关来确定值的类型，并且任何这些方法都会导致性能损失。

另一种替代实现可以使用 Goroutines 和通道。Itertools 使用空接口、Goroutines 和通道。

`github.com/ahl5esoft/golang-underscore` 是一个使用大量反射和空接口来提供类似下划线的高阶函数实现的包。

### 组合器模式

由于 Go 支持将函数作为值传递，我们可以创建谓词组合器，从更简单的谓词构建更复杂的谓词。

**组合器模式**：通过将更原始的函数组合成更复杂的函数来创建系统。

我们将在本书的后面更深入地探讨组合和组合器模式。现在，让我们更仔细地看一下 `map` 和 `filter` 函数。

## 映射和过滤

下一个代码示例演示了几个标准中间函数的使用：`map` 和 `filter`。

这个例子中的代码可以复制/粘贴到 Go playground 中，这是一个服务，它接受您的 Go 程序，编译，链接，并在沙箱中使用最新版本的 Go 运行您的程序，然后将输出返回到屏幕上。您可以在 [`play.golang.org/`](https://play.golang.org/) 找到它。

可执行命令必须始终使用 `package main`。我们可以将每个导入语句分开放在单独的行上以提高可读性。

可以使用其远程 GitHub 存储库路径引用外部包。我们可以用更短的别名前缀长包名。`go_utils` 包现在可以用 `u` 字母引用。请注意，如果我们用 `_` 给包名取别名，它的导出函数可以直接在我们的 Go 代码中引用，而不需要指示它来自哪个包：

```go
package main
import (
   "fmt"
   "log"
   "strings"
   "errors"
   u "github.com/go-goodies/go_utils"
)
```

`iota`：Go 中用于`const`声明的标识符，表示连续的无类型整数常量。每当保留字`const`出现时，它都会重置为 0：

`const (`

`   SMALL = iota // 0`

`   MEDIUM // 1`

`   LARGE // 2`

`)`

我们可以对`iota`应用表达式来设置大于`1`的增量值。我们将在下一节中讨论这个问题。

让我们定义一个名为`WordSize`的 int 类型，并使用`iota`表达式从我们的常量中创建一个枚举。前`iota`元素被分配的值从 0 开始，然后递增 1。由于我们将`iota`元素乘以`6`，所以序列看起来像`0`，`6`，`12`，`18`等。我们明确将值`50`分配给枚举中的最后一个元素：

```go
type WordSize int
const (
     ZERO WordSize = 6 * iota
     SMALL
     MEDIUM
     LARGE
     XLARGE
     XXLARGE  WordSize = 50
     SEPARATOR = ", "
)
```

`ChainLink`类型允许我们链接函数/方法调用。它还将数据保持在`ChainLink`内部，避免了数据变异的副作用：

```go
type ChainLink struct {
     Data []string
}
```

`Value()`方法将返回链中引用元素或链接的值：

```go
func (v *ChainLink) Value() []string {
     return v.Data
}
```

让我们将`stringFunc`定义为一个函数类型。这个一级方法在以下代码中作为`Map`函数的参数使用：

```go
type stringFunc func(s string) (result string)
```

`Map`函数使用`stringFunc`来转换（大写）切片中的每个字符串：

```go
func (v *ChainLink)Map(fn stringFunc) *ChainLink {
     var mapped []string
     orig := *v
     for _, s := range orig.Data {
            mapped = append(mapped, fn(s))
     }
     v.Data = mapped
     return v
}
```

这一行值得重复：

```go
mapped = append(mapped, fn(s))
```

我们对切片中的每个元素执行`fn()`函数参数

`Filter`函数使用嵌入逻辑来过滤字符串切片。我们本可以选择使用一级函数，但这个实现更快：

```go
func (v *ChainLink)Filter(max WordSize) *ChainLink {
     filtered := []string{}
     orig := *v
     for _, s := range orig.Data {
            if len(s) <= int(max) {             // embedded logic
                   filtered = append(filtered, s)
            }
     }
     v.Data = filtered
     return v
}
```

从纯函数式的角度来看，前面代码中的过滤函数有什么问题？

+   我们正在使用命令式循环

+   我们将过滤后的结果保存到`ChainLink`结构中的`Data`字段

为什么不使用递归？我们之前讨论过这个问题。简短的版本是，直到 Go 获得 TCO，如果我们正在处理的元素列表可能超过几千个元素，我们需要避免递归。

为什么我们要存储过滤后的数据而不是返回它呢？好问题。这个过滤函数的实现作为一个学习课程。它向我们展示了如何以非纯函数式的方式链接函数。我们将在下一章中看到一个改进的过滤实现。这里是一个预览：

```go
func (cars Collection) Filter(fn FilterFunc) Collection {
   filteredCars := make(Collection, 0)
   for _, car := range cars {
      if fn(car) {
         filteredCars = append(filteredCars, car)
      }
   }
   return filteredCars
}
```

让我们使用插值的方式显示我们的常量。请注意，`fmt.Printf`语句的第一个参数是我们的插值文档`constants`，其余参数被插入到`constants`中。

```go
func main() {
   constants := `
** Constants ***
ZERO: %v
SMALL: %d
MEDIUM: %d
LARGE: %d
XLARGE: %d
XXLARGE: %d
`
 fmt.Printf(constants, ZERO, SMALL, MEDIUM, LARGE, XLARGE, XXLARGE)
```

输出将如下所示：

```go
** Constants ***
ZERO: 0
SMALL: 6
MEDIUM: 12
LARGE: 18
XLARGE: 24
XXLARGE: 50
```

让我们用我们的单词切片初始化`ChainLink`：

```go
words := []string{
   "tiny",
   "marathon",
   "philanthropinist",
   "supercalifragilisticexpialidocious"}

data := ChainLink{words};
fmt.Printf("unfiltered: %#v\n", data.Value())
```

输出将如下所示：

```go
unfiltered: []string{"tiny", "marathon", "philanthropinist", "supercalifragilisticexpialidocious"}
```

现在，让我们过滤我们的单词列表：

```go
  filtered := data.Filter(SMALL)
  fmt.Printf("filtered: %#vn", filtered)
```

输出将如下所示：

```go
filtered: &main.ChainLink{Data:[]string{"tiny"}}
```

接下来，让我们将`ToUpper`映射应用到我们的小型单词上：

```go
     fmt.Printf("filtered and mapped (<= SMALL sized words): %#vn",
          filtered.Map(strings.ToUpper).Value())
```

输出将如下所示：

```go
filtered and mapped (<= SMALL sized words): []string{"TINY"}
```

让我们应用一个`MEDIUM`过滤器和`ToUpper`过滤器：

```go
     data = ChainLink{words}
     fmt.Printf("filtered and mapped (<= MEDIUM and smaller sized words): %#vn",
          data.Filter(MEDIUM).Map(strings.ToUpper).Value())
```

输出将如下所示：

```go
filtered and mapped (<= MEDIUM and smaller sized words): []string{"TINY", "MARATHON"}
```

接下来，让我们应用我们的`XLARGE`过滤器并映射然后`ToUpper`：

```go
     data = ChainLink{words}
     fmt.Printf("filtered twice and mapped (<= LARGE and smaller sized words): 
     %#vn",
          data.Filter(XLARGE).Map(strings.ToUpper).Filter(LARGE).Value())
```

输出将如下所示：

```go
filtered twice and mapped (<= LARGE and smaller sized words): []string{"TINY", "MARATHON", "PHILANTHROPINIST"}
```

现在，让我们应用我们的`XXLARGE`过滤器并映射`ToUpper`：

```go
     data = ChainLink{words}
     val := data.Map(strings.ToUpper).Filter(XXLARGE).Value()
     fmt.Printf("mapped and filtered (<= XXLARGE and smaller sized words): %#vn", 
     val)
```

输出将如下所示：

```go
mapped and filtered (<= XXLARGE and smaller sized words): []string{"TINY", "MARATHON", "PHILANTHROPINIST", "SUPERCALIFRAGILISTICEXPIALIDOCIOUS"}
```

输出将如下所示：

```go
** Constants ***
ZERO: 0
SMALL: 6
MEDIUM: 12
LARGE: 18
XLARGE: 24
XXLARGE: 50
```

在这里，我们使用`Join()`函数来连接列表中的项目，以帮助格式化我们的输出：

```go
     fmt.Printf("norig_data : %vn", u.Join(orig_data, SEPARATOR))
     fmt.Printf("data: %vnn", u.Join(data.Value(), SEPARATOR))
```

输出将如下所示：

```go
 orig_data : tiny, marathon, philanthropinist, supercalifragilisticexpialidocious
 data: TINY, MARATHON, PHILANTHROPINIST, SUPERCALIFRAGILISTICEXPIALIDOCIOUS
```

现在，让我们比较我们原始的单词集合与我们通过函数链传递的值，看看是否有副作用：

这是你的终端控制台应该看起来的样子：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/aed12031-9b10-4174-9691-0b8f3cc23347.png)

## 包含

让我们考虑另一个常见的集合操作：`contains`。

在 Go 中，事物的列表通常存储在切片中。如果 Go 提供了一个`contains`方法来告诉我们我们正在寻找的项目是否包含在切片中，那不是很好吗？由于 Go 中没有用于处理项目列表的通用`contains`方法，让我们实现一个来迭代一组汽车对象。

### 迭代一组汽车

首先，让我们创建一个`Car`结构，用来定义`Cars`集合作为`Car`切片。稍后，我们将创建一个`Contains()`方法来尝试在我们的集合上使用：

```go
package main
type Car struct {
     Make string
     Model string
}
type Cars []*Car
```

这是我们的`Contains()`实现。`Contains()`是`Cars`的一个方法。它接受一个`modelName`字符串，例如`Highlander`，如果在`Cars`的切片中找到了它，就返回`true`：

```go
func (cars Cars) Contains(modelName string) bool {
     for _, a := range cars {
            if a.Model == modelName {
                   return true
            }
     }
     return false
}
```

这似乎很容易实现，但是当我们得到一个要迭代的船只或箱子列表时会发生什么？没错，我们将不得不为每一个重新实现`Contains()`方法。这太丑陋了！

这又是一个情况，如果有泛型将会很好。

#### 空接口

另一种选择是这样使用空接口：

```go
type Object interface{}
type Collection []Object
func (list Collection) Contains(e string) bool {
     for _, t := range list { if t == e { return true } }
     return false
}
```

然而，这将需要反射或类型转换，这将再次对性能产生不利影响。

#### Contains()方法

现在，让我们来使用我们的`Contains()`方法：

```go
func main() {
     crv := &Car{"Honda", "CRV"}
     is250 := &Car{"Lexus", "IS250"}
     highlander := &Car{"Toyota", "Highlander"}
     cars := Cars{crv, is250, highlander}
     if cars.Contains("Highlander") {
            println("Found Highlander")
     }
     if !cars.Contains("Hummer") {
            println("Did NOT find a Hummer")
     }
}
```

输出将如下所示：

```go
Found Highlander
Did NOT find a Hummer
```

为了理解如何从命令式编程转向函数式编程，让我们看看纯函数式编程语言以及如何实现`Map()`这样的高阶函数来操作集合。

使用纯函数类型，你有一个函数`f`，它接受一个立方体并返回一个心形，如下图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/lrn-fp-go/img/ee48a5f5-1cf3-4611-9741-d2fcdee1e086.png)

如果你给`f`传递一个立方体列表，你可以使用`f`来返回一个心形列表。

为了在 Go 语言中实现这一点，我们可以用一个字符串替换立方体，用一个`bool`值替换心形：

```go
func Map(f func(v string) bool, vs [] string) []bool {
     if len(vs) == 0 {
            return nil
     }
     return append(
            []bool{f(vs[0])},
            Map(f, vs[1:])...)
}
```

首先，我们定义了一个元音字母的映射，然后测试一个不检索值的键，使用下划线代替第一个值：

```go
func main() {
     vowels := map[string]bool{
            "a": true,
            "e": true,
            "i": true,
            "o": true,
            "u": true,
     }
     isVowel := func(v string) bool { _, ok := vowels[v]; return ok }
     letters := []string{"a", "b", "c", "d", "e"}
     fmt.Println(Map(isVowel, letters))
}
```

我们定义`isVowel`为一个取一个字符串并返回一个`bool`结果的文字函数。我们定义 letters 为一个字符串切片（`a`、`b`、... `e`），然后调用我们的`Map`函数，传递我们的`isVowel`函数和要检查的字符串列表。

这很有效，但问题是我们必须为每种数据类型重新编写我们的逻辑。如果我们想要检查一个特定的符文字符是否存在于符文列表中，我们将不得不编写一个新的`Map`函数。我们将不得不关心这样的事情：`len()`是否像它在字符串中那样与符文一起工作？如果不是，我们将不得不替换这个逻辑。这将包括大量的工作和代码，执行类似的操作，这不是一个好的风格。

这是另一个例子，说明了在 Go 语言中拥有泛型将是一种乐趣。

## 如果 Go 语言有泛型

如果 Go 语言有泛型，我们可以编写一个函数签名，用以下内容替换字符串中的符文，而不必重写内部逻辑：

```go
func Map(f func(v <string>) <bool>, vs [] <string>) []<bool> 
```

然而，Go 语言没有泛型，所以我们可以使用空接口和反射来实现相同的结果。

### Map 函数

让我们创建一个`Map`函数来转换集合的内容。

首先，让我们定义`Object`为空接口类型，并创建一个`Collection`类型作为对象的切片：

```go
package main
import "fmt"
type Object interface{}
type Collection []Object
func NewCollection(size int) Collection {
     return make(Collection, size)
}
```

`NewCollection`函数创建一个给定大小的集合的新实例：

```go
type Callback func(current, currentKey, src Object) Object
```

`Callback`类型是一个一流函数类型，返回计算结果：

```go
func Map(c Collection, cb Callback) Collection {
     if c == nil {
          return Collection{}
     } else if cb == nil {
          return c
     }
     result := NewCollection(len(c))
     for index, val := range c {
          result[index] = cb(val, index, c)
     }
     return result
}
```

`Map`函数返回一个新的集合，其中每个元素都是调用`Callback`函数的结果。

### 测试我们基于空接口的`Map`函数

我们将通过定义一个变换函数来测试我们的新的基于空接口的`Map`函数。这个函数将把集合中的每个项目乘以 10：

```go
func main() {
     transformation10 := func(curVal, _, _ Object) Object {
     return curVal.(int) * 10 }
     result := Map(Collection{1, 2, 3, 4}, transformation10)
     fmt.Printf("result: %vn", result)
```

我们传递了数字`1`、`2`、`3`和`4`的集合以及变换函数。

输出将如下所示：

```go
result: [10 20 30 40]
```

现在，让我们把我们的`Map`函数传递给一个字符串集合：

```go
     transformationUpper := func(curVal, _, _ Object) Object { return strings.ToUpper(curVal.(string)) }
     result = Map(Collection{"alice", "bob", "cindy"}, transformationUpper)
     fmt.Printf("result: %vn", result)
}
```

这次我们传递了一个字符串集合，并通过调用`ToUpper`来转换每个字符串。

输出如下：

```go
result: [ALICE BOB CINDY]
```

注意在每种情况下，我们都必须转换每个`curVal`？使用`transformation10`，我们可以将集合中的每个项目转换为一个`int`变量；使用`transformationUpper`，我们可以将每个项目转换为一个`string`变量。我们可以选择使用反射来避免显式转换，但这对性能来说甚至更糟。

与我们之前的例子一样，我们可以将集合传递给一系列转换函数，以得到结果，结果可以是另一个集合或单个终端值。

不要每次都重新发明轮子，我们需要另一个高阶函数；让我们使用 Go 中可用的许多包中的任何一个，这些包可以轻松地实现 Go 中的函数式编程风格。

## Itertools

Itertools 是一个 Go 包，它提供了与 Python 标准库中相同的许多高阶函数。

接下来，我们看到 Itertools 提供的不同类型的高阶函数。高阶函数为声明性编码风格提供了词汇。

无限迭代器创建者：

+   `Count(i)`: 从`i`开始的无限计数

+   `Cycle(iter)`: 对`iter`进行无限循环（需要内存）

+   `Repeat(element [, n])`: 重复元素`n`次（或无限次）

迭代器销毁者：

+   `Reduce(iter, reducer, memo)`: 在迭代器上进行减少（或 Foldl）

+   `List(iter)`: 从迭代器创建一个列表

迭代器修改器：

+   `Chain(iters...)`: 将多个迭代器链接在一起。

+   `DropWhile(predicate, iter)`: 删除元素，直到 predicate(el) == false。

+   `TakeWhile(predicate, iter)`: 当 predicate(el) == false 时取元素。

+   `Filter(predicate, iter)`: 当 predicate(el) == false 时过滤掉元素。

+   `FilterFalse(predicate, iter)`: 当 predicate(el) == true 时过滤掉元素。

+   `Slice(iter, start[, stop[, step]])`: 删除元素，直到开始（从零开始的索引）。停止在停止时（独占），除非没有给出。步长为 1，除非给出。

更多的迭代器修改器：

+   `Map(mapper func(interface{}) interface{}, iter)`: 将每个元素映射到 mapper(el)。

+   `MultiMap(multiMapper func(interface{}...)interface{}, iters...)`: 将所有迭代器作为可变参数映射到`multiMaper(elements...)`；在最短的迭代器处停止。

+   `MultiMapLongest(multiMapper func(interface{}...)interface{}, iters...)`: 与`MultiMap`相同，只是这里需要在最长的迭代器处停止。较短的迭代器在耗尽后填充为 nil。

+   `Starmap(multiMapper func(interface{}...)interface{}, iter)`: 如果`iter`是`[]interface{}`的迭代器，则将其扩展为`multiMapper`。

+   `Zip(iters...)`: 将多个迭代器一起压缩。

+   `ZipLongest(iters...)`: 将多个迭代器一起压缩。取最长的；较短的追加为 nil。

+   `Tee(iter, n)`: 将迭代器分成 n 个相等的版本。

+   `Tee2(iter)`: 将迭代器分成两个相等的版本。

### New 函数使用的 Go 通道

在`itertools.go`文件中，我们看到迭代器使用 Go 通道来遍历集合中的每个元素：

```go
type Iter chan interface{}
func New(els ... interface{}) Iter {
     c := make(Iter)
     go func () {
            for _, el := range els {
                   c <- el
            }
            close(c)
     }()
     return c
}
```

`New`函数可以按以下方式使用，将值列表转换为新的可迭代集合：

```go
New(3,5,6)
```

### 测试 itertool 的 Map 函数

让我们通过传递各种长度的单词集合和一个操作每个单词返回其长度的文字函数来测试 itertool 的`Map`函数：

```go
package itertools
import (
     "testing"
     "reflect"
     . "github.com/yanatan16/itertools"
)
```

不要忘记运行`go get -u github.com/yanatan16/itertools`来下载`itertools`包以及它的依赖项。

### 测试迭代器的元素相等性

首先，让我们创建`testIterEq`函数来测试两个集合是否等价：

```go
func testIterEq(t *testing.T, it1, it2 Iter) {
     t.Log("Start")
     for el1 := range it1 {
            if el2, ok := <- it2; !ok {
                   t.Error("it2 shorter than it1!", el1)
                   return
            } else if !reflect.DeepEqual(el1, el2) {
                   t.Error("Elements are not equal", el1, el2)
            } else {
                   t.Log(el1, el2)
            }
     }
     if el2, ok := <- it2; ok {
            t.Error("it1 shorter than it2!", el2)
     }
     t.Log("Stop")
}
```

在我们的测试函数`TestMap`中，我们定义了一个`mapper`函数文字，它被传递给我们的`Map`函数来执行转换。`mapper`函数返回传递给它的每个字符串的长度：

```go
func TestMap(t *testing.T) {
     mapper := func (i interface{}) interface{} {
            return len(i.(string))
     }
     testIterEq(t, New(3,5,10), Map(mapper, New("CRV", "IS250", "Highlander")))
}
```

让我们转到具有此测试文件的目录，并运行以下内容，以验证`Map`函数是否按我们的期望工作。这是我的控制台输出的样子：

```go
~/clients/packt/dev/go/src/bitbucket.org/lsheehan/fp-in-go-work/chapter2/itertools $ go test
PASS
ok bitbucket.org/lsheehan/fp-in-go-work/chapter2/itertools 0.008s
```

## 功能包

还有许多其他 Go 包提供了我们在编写用于操作集合的声明代码时所期望的高阶函数（HOF）。它们通常使用空接口和反射，这对性能有负面影响。一个众所周知的 HOF 实现是 Rob Pike 的`Reduce`包（参见[`github.com/robpike/filter`](https://github.com/robpike/filter)），他在那里表明了他对使用 for 循环的偏好，并明确表示，*不要使用这个*。

## 另一次反思

我们是否感到沮丧了？我们学会了如何以简洁、声明式的函数式编程风格编码，却发现它可能运行得太慢，无法在生产中使用。我们尝试了各种技术来加快速度，但迄今为止，我们所做的一切纯函数式编程都无法与老式的命令式编程的性能相匹敌。

我们的目标是找到一种在 Go 中使用声明式函数式编程风格的编程方式，并且性能指标达到或超过预期。

### Go 很棒

Go 是我们喜欢的语言，原因有很多，包括：

+   性能

+   快速且易于部署

+   跨平台支持

+   受保护的源代码

+   并发处理

### Go 很棒，但是

由于 Go 并不是为了成为纯函数式语言而设计的，并且缺乏泛型，我们必须承受性能损失，以将 Go 强制转换为函数式编程风格，对吗？（保持信念！希望就在拐角处。）

我们已经涵盖了实现和使用集合的核心原则。您学到了在函数式编程中，单个函数可以接受输入并返回结果，并且在函数内部发生的对集合的转换。您学到了我们可以通过将它们链接在一起来组合函数。

如果 Go 具有泛型，那将简化我们的实现任务，但更重要的是，如果 Go 被设计为执行**尾递归优化**（**TCO**）和其他提高性能的优化，那么选择在 Go 中以函数式风格编程将是一个容易的决定。

Go 最好的特性之一是其性能，如果我们正在开发一个在单个服务器上运行且性能比简洁、直观和声明式代码更重要的解决方案，那么很可能我们不会以函数式风格编程 Go。

## 解决方法

然而，如果我们想要使用 Go 来实现分布式计算解决方案，那么我们很幸运。

让我们快速看一下一个新的 Go 包的特性，用于在规模上进行数据处理的分布式**MapReduce**。

### Gleam - 用于 Golang 的分布式 MapReduce

“首先，我们需要泛型。当然，我们可以使用反射。但明显要慢得多，以至于我不想展示性能数字。其次，如果我们想要在运行时动态调整执行计划，还需要动态远程代码执行。我们可以预先构建所有执行 DAG，然后在运行时选择其中一个。但这非常有限。和这里的每个人一样，我享受 Go 的美。如何使其适用于大数据？”

- Chris Lu

这就是正确的问题。

Chris 使用了一个名为 LuaJIT 的脚本语言来解决反射和泛型缺失的性能问题。与其在运行时构建整个**有向无环图**（**DAG**），然后选择一个分支，不如使用 LuaJIT 的脚本性质允许动态远程代码执行，允许我们在运行时动态调整执行计划。

#### LuaJIT 的 FFI 库

LuaJIT 的 FFI 库通过解析 C 声明，使调用 C 函数和 C 数据结构变得容易：

```go
local ffi = require("ffi")
Load LuaJIT's FF library
ffi.cdef[[
int printf(const char *fmt, ...);
]]
Add a C declaration for the function.
ffi.C.printf("Hello %s!", "world")
```

调用命名的 C 函数。简单！

#### Unix 管道工具

Gleam 还利用了 Unix 管道工具。

Gleam = Go + LuaJIT + Unix 管道

让我们看看如何使用 Gleam 处理集合。

### 处理 Gleam 集合

让我们看看 Gleam 如何处理集合。我们将使用的输入是`/etc/paths`文件中包含单词的行集合：

```go
$ cat /etc/paths
/usr/local/bin
/usr/bin
/bin
/usr/sbin
/sbin
```

Gleam 将文件内容作为行读取，并将每一行输入到流中。从这里，它创建了一个流，通过这个流调用`Map`和`Reduce`函数来计算每个单词的出现次数：

```go
package main
import (
     "os"
     "github.com/chrislusf/gleam/flow"
)
func main() {
     flow.New().TextFile("/etc/paths").Partition(2).FlatMap(`
            function(line)
                   return line:gmatch("%w+")
            end
     `).Map(`
            function(word)
                   return word, 1
            end
     `).ReduceBy(`
            function(x, y)
                   return x + y
            end
     `).Fprintf(os.Stdout, "%s,%dn").Run()
}
```

这是输出结果：

```go
bin,3
local,1
sbin,2
usr,3
```

失望了吗？你是不是希望在纯 Go 中有纯函数式编程的实际用途？（在这里，实际意味着使用递归的性能不是问题，你可以以声明式风格编写业务逻辑和控制流逻辑，摆脱空接口、向下转型/拆箱和那些繁琐的 if err != nil 代码块？）继续阅读本书，你会在最后一个单元中找到一个解决方案。

## 总结

我们在代码中不断地操作集合。我们经常从一系列项目开始，需要将我们的初始列表转换为另一个不同项目的列表。有时，我们希望将我们的列表映射到另一个相同大小的列表。有时，我们希望对我们的列表进行分组和排序。其他时候，我们需要得到一个单一的结果值。

在本章中，我们探讨了不同类型（中间和终端）的集合函子。我们深入研究了集合操作的几个关键领域，包括迭代器、`map`函数、`contains`方法和函数的链接。

我们看了一些 Go 包，它们提供了一系列高阶函数，可以在我们的新函数式编程风格中使用。

我们对 Unix 管道有了更深的了解，并发现一个名为 Gleam 的新的分布式处理 Go 包，利用管道提供了一个基于 Go 的轻量级函数式解决方案。

在下一章中，我们将深入探讨流水线技术，看看它如何提高性能。
