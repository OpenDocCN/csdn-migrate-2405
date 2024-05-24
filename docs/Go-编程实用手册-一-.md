# Go 编程实用手册（一）

> 原文：[`zh.annas-archive.org/md5/62FC08F1461495F0676A88A03EA0ECBA`](https://zh.annas-archive.org/md5/62FC08F1461495F0676A88A03EA0ECBA)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

本书将通过解决开发人员常见的问题来帮助您学习 Go 编程语言。您将首先安装 Go 二进制文件，并熟悉开发应用程序所需的工具。然后，您将操作字符串，并将它们用于内置结构和内置函数构造，以从两个浮点值创建复杂值。之后，您将学习如何对日期和时间执行算术运算，以及如何从字符串值中解析它们。

无论您是专业程序员还是新手，您都将学习如何在 Go 中编程各种解决方案，这将使您在掌握 Go 方面更上一层楼。这些示例涵盖了 Go 中的并发，执行各种 Web 编程任务，进行系统编程，读写文件以及许多基本的 Go 编程技能，如正确的错误处理和日志记录。

# 这本书适合谁

本书适合对学习 Go 语言感兴趣的软件开发人员，以及希望通过实际的代码示例进一步学习的程序员。

# 本书涵盖了什么

第一章《Go 入门》解决了新的 Go 开发人员以及使用其他语言的人在日常编程中面临的最常见问题。

第二章《操作字符串值》包含一些操作字符串值的示例，例如修剪字符串开头和结尾的空格，提取子字符串，替换字符串的部分，转义字符串值和大写字符串值。

第三章《类型转换》通过一些实际示例带您了解如何轻松地将一种类型转换为另一种类型。

第四章《日期和时间》解释了如何在 Go 编程语言中处理日期和时间。

第五章《映射和数组》介绍了如何在 Go 中使用映射和数组。

第六章《错误和日志》讨论了如何处理错误，并在需要时返回错误。

第七章《文件和目录》提供了在 Go 中处理文件和目录的示例。

第八章《并发》解释了如何在 Go 语言中使用并发构造。

第九章《系统编程》涵盖了如何使用 Go 处理命令行参数。

第十章《Web 编程》包含有效的示例，涉及与互联网的交互，如下载网页，创建自己的示例 Web 服务器和处理 HTTP 请求。

第十一章《关系数据库》解释了如何使用 Go 在关系数据库上读取、更新、删除和创建数据。

# 充分利用本书

为了更轻松地跟随本书，建议读者应该对软件开发有扎实的知识。读者应该具备基本的编程语言知识，以及对 Go 语言的概述。您将了解更多关于本书中使用的 GoLand IDE。

# 下载示例代码文件

您可以从[www.packtpub.com](http://www.packtpub.com)的帐户中下载本书的示例代码文件。如果您在其他地方购买了本书，您可以访问[www.packtpub.com/support](http://www.packtpub.com/support)并注册，以便直接将文件发送到您的邮箱。

您可以按照以下步骤下载代码文件：

1.  在[www.packtpub.com](http://www.packtpub.com/support)上登录或注册。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明操作。

下载文件后，请确保使用最新版本的以下软件解压或提取文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[`github.com/PacktPublishing/Hands-On-Go-Programming`](https://github.com/PacktPublishing/Hands-On-Go-Programming)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 用户名。例如：“我将使用`touch`命令来创建`main.go`文件。”

代码块设置如下：

```go
package main
import "fmt"
func main(){
 fmt.Println(a:"Hello World")
}
```

任何命令行输入或输出都以以下方式书写：

```go
$go run main.go
```

**粗体**：表示新术语、重要词汇或屏幕上看到的词语。例如，菜单或对话框中的词语会在文本中以这种方式出现。例如：“您可以运行它，然后不断点击“继续”，直到安装完成。”

警告或重要提示会以这种方式出现。

技巧和窍门会以这种方式出现。


# 第一章：开始使用 Go

本书将帮助您在 Go 编程之旅中，特别是在您开始积极开发 Go 应用程序时。本章节解决了新的 Go 开发人员以及与其他语言一起工作的人在日常编程中面临的最常见问题。希望您喜欢这本书并且觉得它有用。

我们将涵盖以下主题：

+   安装 Go 二进制文件

+   快速了解 Go 语言

# 安装 Go 二进制文件

让我们开始使用 Go。在本节中，我们将学习如何安装 Go 二进制文件，并简要了解 Go 语言。

要安装 Go 二进制文件，首先要做的是转到以下链接：[`golang.org/doc/install`](https://golang.org/doc/install)；您也可以直接在 Google 中搜索并访问它。您将找到一个逐步指南，介绍如何在不同平台和操作系统上安装 Go。如果您点击“下载 Go”，它将带您到下载页面，在那里您可以找到各种二进制格式。

您将在以下截图中找到 Windows、Linux 和 macOS 的 MSI：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/cc1f0180-dd8d-4c29-88bf-3e936a68fed2.png)

我将使用 macOS，但您也会发现其他平台的步骤类似。让我们继续进行下载。

安装程序基本上是一个逐步向导；您只需运行它并不断点击“继续”，直到安装完成。安装完成后，您可能还需要做一件事，那就是设置您的环境变量。此外，您还需要设置您的工作区。您将有三个文件夹，`bin`、`pkg`和`src`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/ad693586-b8d7-4898-b568-296ea7bd9c88.png)

`src`文件夹是您放置源文件的地方，`pkg`文件夹是 Go 存储对象文件的地方，`bin`文件夹是存储二进制文件（实际可执行文件）的地方。接下来，我将使用我的 shell，并且您需要使用`export`来设置一些环境变量。您还可以使用配置文件来设置您的环境变量。如果您查看下面的截图，您可以看到路径`$PATH:/usr/local/go/bin`，这就是我的 Go 二进制文件所在的位置：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/a05dd85f-116b-482c-83c9-2b17140c83d1.png)

因此，当我运行`Go`命令时，它将自动找到 Go 程序的位置。

接下来，我们设置`GOPATH`。`GOPATH`基本上是您的 Go 工作区所在的位置。如果您记得的话，工作区包含三个文件夹，`pkg`、`src`和`bin`。`GoProject`是该结构的父文件夹。最后是`$GOPATH/bin`，当您希望终端找到已安装的 Go 二进制文件时使用。只需确保在重新启动终端之前添加这三个内容并保存此文件。然后，您就可以开始使用 Go 了！

您还可以通过点击链接找出如何设置 Go 路径的环境变量，如下截图所示，该链接位于同一页面上：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/ece31944-4fa2-4491-8969-1db2b04813f2.png)

您将找到不同操作系统的说明。例如，对于基于 Unix 的系统，您可以使用`~/.bash_profile`，或者根据您使用的 shell 不同，您可以使用各种配置文件。在我的系统中，我使用的是如下截图中所见的配置文件：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/2ec25741-dc7c-4fb6-b138-7fcda340d3f4.png)

对于 Windows，在安装完成后，一旦您有了 Go 工作区，按照给定的说明进行操作，您就可以开始使用 Go 了。说明将如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/1ee9027a-dde7-4abd-88ee-598e7c11adc4.png)

测试您是否已安装 Go 的最快方法就是输入`go`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/ae4661b5-6535-46c1-8ed7-1e5ca5c58cf2.png)

它将带出帮助教程，您可以通过使用 Go 版本查看可用命令和您拥有的代码版本。

这就是您如何轻松设置 Go 环境。在下一节中，我们将快速了解 Go 语言本身。

# 快速了解 Go 语言

在本节中，我们将快速了解 Go 编程语言。 Go 是一种表达力强，简洁，干净的语言；它具有并发机制，这有助于程序员编写能充分利用多核和网络机器的程序。它还可以快速编译为机器代码，并具有垃圾回收的便利性和运行时反射的强大性。它是一种静态类型的编译语言，但对大多数人来说，它感觉像是一种动态类型和解释语言。好了！让我们通过导航到[`tour.golang.org/welcome/1`](https://tour.golang.org/welcome/1)来查看 Go 的语法；这对于想要学习 Go 语法的人来说是一个很好的起点：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/0531d92f-0fa8-49d2-b0a5-5fe4de42171d.png)

好的，所以如果您看一下截图中的语法，如果您来自诸如 Java 和 C#，或 C 和 C++之类的语言，您可能会发现语法有点不同。例如，如果您看一下返回类型，您实际上是在函数的末尾定义返回类型，而不是定义类型。我们还有一个主函数，这是我们应用程序的入口点，类似于许多其他编程语言，如果您看一下下面截图中显示的上下文，您会发现我们有包、变量和函数，以及流程控制语句：`for`、`if...else`，以及`struct`、`slices`和`maps`等类型：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/2aff032d-e205-49a6-a873-da00529d102e.png)

如果您想创建一个类，比如结构，您可以使用结构类型并将其与指针结合。此外，它具有方法和接口以及并发性，但它没有泛型。

说到这一点，我还将谈论我将在整本书中使用的工具。**GoLand**中有几个可用的工具。 GoLand 是 JetBrains 推出的一个相对较新的 IDE。我们将在整本书中使用 GoLand。您可以轻松创建新项目并为其命名，并选择 SDK，即 Go 1.9。您还可以添加新文件或新包等。

您可以通过输入您的入口文件来定义您的配置并构建您的 Go，如下截图所示。然后，您可以运行`main.go`并单击 OK：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/ef4f11d9-cb81-44f4-a70b-f72f7bcf9fdf.png)

最后，按下*Ctrl* + *r*将构建您的项目，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/c3e1bc05-93d5-4ec2-95ae-1da7786c8ce7.png)

在我结束本章之前，让我快速向您展示一个仅使用终端的示例。我将使用`touch`命令创建`main.go`文件并添加以下代码：

```go
package main
import "fmt"
func main(){
 fmt.Println(a:"Hello World")
}
```

您可以使用`go run main.go`命令运行它，然后您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/ed40c885-8935-47d5-8781-bf553c172e2f.png)

您可以保存它，然后运行它。因此，这就是您如何使用终端快速编写 Go 代码并运行它。

# 摘要

在本章中，我们学习了如何安装 Go 二进制文件，并简要了解了 Go 语言。我们学会了如何编写 Go 代码并仅使用终端运行它。我们还看了将在所有章节中使用的工具以及可以用来开发 Go 应用程序的其他工具。我们现在准备继续下一章，在那里我们将看到一些操作字符串值的示例。


# 第二章：操作字符串值

现在我们已经了解了这本书将带领我们完成的内容概述。我们知道如何安装 Go 二进制文件，编写 Go 代码并使用终端运行它。在本章中，我们将学习一些操作字符串值的技巧，比如从字符串的开头和结尾修剪空格，提取子字符串，替换字符串的部分，转义字符串值中的字符，以及将字符串值大写。

# 从字符串的开头和结尾修剪空格

让我们从字符串的开头和结尾修剪空格开始。有许多原因你可能想要从字符串的开头和结尾删除空格；例如，如果你接受一些值，比如名字，你通常不需要在字符串值的末尾或开头有任何空格。

所以，让我们继续进行我们的项目，并看看我们如何在 Go 语言中进行这个过程。所以，你必须为修剪空格添加一个新项目，并有一个我们将放置我们的代码的`main.go`文件，然后我们只需要运行它；你的屏幕应该看起来像这样：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/d928383e-79c9-4b4c-9ae3-36e489d22922.png)

首先，让我们想象一下，我们有一个字符串变量，其中有一些空格：

```go
package main
import (
  "fmt"
  "strings"
)
func main(){
  greetings := "\t Hello, World "
  fmt.Printf("%d %s\n", len(greetings), greetings)
}
```

在上面的代码片段中，`/t`代表制表符，后面有一些空格。有*hello World*和一些空格。我已经将这个字符串值与它的长度属性一起放到控制台上。`len`函数将给我们字符串的长度，表示字符串中的字符数。让我们运行一下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/5cf1f06e-2e5f-4398-abbc-932f34a332f8.png)

从屏幕截图中可以看出，它有 15 个字符，包括制表符、空格和字符串的其余部分。

现在，让我们继续修剪变量中的空格。我们有`strings.TrimSpace`，它返回另一个字符串，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/d5b7429f-3f3d-4967-bd9f-ac7e9f16f587.png)

然后我们可以将字符串捕获到一个变量中。检查以下代码：

```go
package main
import (
 "fmt"
 "strings"
)
func main(){
 greetings := "\t Hello, World "
 fmt.Printf("%d %s\n", len(greetings), greetings)
trimmed := strings.TrimSpace(greetings)
 fmt.Printf("%d %s\n", len(trimmed), trimmed)
}
```

上面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/61ab38f8-1c83-447e-ae87-23c8c64c4d78.png)

看！正如你所看到的，我们的开头和结尾的空格，包括制表符，都消失了，现在我们这里有 12 个字符。这就是你在 Go 中修剪空格的方法。在下一节中，我们将看到如何从字符串值中提取子字符串。

# 从字符串值中提取子字符串

在这一部分，你将学习如何从字符串值中提取子字符串。Go 语言中的字符串实际上是一个只读的字节切片，这意味着你也可以对字符串执行任何切片操作。让我们去编辑器看看我们如何进行操作。

在编辑器中，添加一个新文件并将其命名为`main.go`。你必须将包更改为`main`，并添加一个名为`main`的新函数。这个`main`函数将是我们示例的入口点。所以，让我们假设我们有一个字符串值如下：

```go
package main
import "fmt"
func main(){
 greetings := "Hello, World and Mars"
```

我想从字符串中删除*Mars*和*and*这两个词，只提取其中的*Hello, World*部分。可以这样做：

```go
package main
import "fmt"
func main(){
 greetings := "Hello, World and Mars"
 helloWorld := greetings[0:12]
 fmt.Println(helloWorld)
}
```

索引从 0 开始，因为它是切片。上面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/4112dafd-57f4-4f89-85fe-baf862ef351d.png)

如你所见，我们只提取了整个短语中的*Hello, World*部分。如果索引中没有 0，它仍然可以工作。如果我们只想要这个字符串的*World*和*Mars*部分，索引可以是[6:]。

这就是你从字符串值中提取子字符串的方法。在我们的下一个视频中，我们将看到如何用另一个字符串替换字符串的一部分。

# 替换字符串的部分

在本节中，我们将看到如何快速将字符串的一部分替换为另一个值。在 Go 语言中进行字符串操作时，您会发现在字符串包下有许多实用方法。在这里，我们将使用相同的包来将字符串的一部分替换为另一个值。让我们回到我们的编辑器，看看我们如何开始这个过程。

因此，我将有一个`helloWorld`变量，并且我们将用*Mars*替换*World*。检查以下代码：

```go
package main
import (
 "strings"
 "fmt"
)
func main(){
 helloWorld := "Hello, World"
 helloMars := strings.Replace(helloWorld, "World", "Mars", 1)
 fmt.Println(helloMars)
}
```

下面的屏幕截图将解释我们刚刚看到的代码：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/5814b177-4e26-4d61-a5d1-8fd981a31820.png)

如屏幕截图所示，我们将使用`strings`包，它有一个`replace`函数，它接受我们要搜索的变量作为第一个参数，即*Hello, World*。旧字符串将是我们要替换的字符串中的内容，即*World*。新字符串将是*Mars*，我们要应用于此替换的重复次数将是'1'。

如果您看一下，此方法的签名返回另一个字符串，并且我们将其分配给另一个变量，在这种情况下是`helloMars`。因此，您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/5dbd4c75-dc8b-4889-a38b-a6eaf0bfd9fb.png)

如您所见，我们已经用*Mars*替换了*World*。

现在，假设我们在句子中有多个*World*实例，并且您使用以下代码：

```go
package main
import (
 "strings"
 "fmt"
)
```

```go
func main(){
 helloWorld := "Hello, World. How are you World, I am good, thanks World."
 helloMars := strings.Replace(helloWorld, "World", "Mars", 1)
 fmt.Println(helloMars)
}
```

因此，如果您有这样的字符串值，使用 1 将无济于事。它只会用*Mars*替换第一个*World*出现，但其余部分仍将保留为*World*，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/25508dbe-50fe-4367-b3de-a25ecc622bd8.png)

因此，您可以通过更改重复次数来替换尽可能多的*World*实例。例如，如果您想要用*Mars*替换前两个*World*实例，重复次数将为 2，依此类推。如果您想要用*Mars*替换所有*World*实例，一个快速简单的方法是使用减一，这有效地告诉 Go 用单词*Mars*替换您可以找到的字符串中的任何*World*实例。让我们运行以下代码：

```go
package main
import (
 "strings"
 "fmt"
)
```

```go
func main(){
 helloWorld := "Hello, World. How are you World, I am good, thanks World."
 helloMars := strings.Replace(helloWorld, "World", "Mars", -1)
 fmt.Println(helloMars)
}
```

上述代码将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/16d3d73a-73e5-425a-8429-6c109e3165a5.png)

现在，所有*world*实例都已被单词*Mars*替换。Go 字符串包提供了许多其他选项，正如您所见，替换字符串真的很容易。在下一节中，我们将看到如何在字符串中转义字符。

# 在字符串中转义字符

在本节中，我们将看到如何转义字符串值中的特殊字符。与今天市场上许多其他语言类似，Go 以特殊方式处理某些字符。例如，如果 Go 在字符串值中看到\t 字符，它将将其视为制表符字符。此外，如果不进行转义，您无法在双引号内包含双引号，现在我们将看到如何转义它们以正确显示这些字符到我们的输出中。

像往常一样，我们将有我们的`main.go`文件和`main`函数。因此，让我们检查一个与之前类似的示例。

```go
package main
import "fmt"
func main(){
  helloWorld := "Hello World, this is Tarik."
}
```

因此，如果我想在术语 Tarik 周围包含双引号，我可以这样做，但是，正如您所看到的，它会给我一个编译时错误，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/ba60f272-bc4b-4602-a2a7-32053c00cb32.png)

所以，让我们来修复这个问题。我所需要做的就是使用`\`。因此，每当您想要转义特殊字符时，都要用`\`进行转义。让我们继续并将其添加到我们的控制台：

```go
package main
import "fmt" 
func main(){
 helloWorld := "Hello World, this is \"Tarik.\""
fmt.Println(helloWorld)
}
```

上述代码的输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/08b1ad84-c990-4a17-aed7-62879f0a4566.png)

好了！正如您所看到的，它说 Hello World, this is "Tarik."，但 Tarik 被包含在两个双引号中，这是我们想要的。

现在还有其他问题。假设我想以某种原因输出`\t`而不带双引号：

```go
package main
import "fmt"
func main(){
 helloWorld := "Hello World, this is \"Tarik.\" \t"
fmt.Println(helloWorld)
}
```

看起来可以运行，既然我们没有看到任何编译时错误，我们可以继续运行。得到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/13045bfc-e96b-4df1-895d-1ffc2ea35d43.png)

如您所见，\t 不会出现在控制台中；实际上，我看到了一个大制表符，因为这是一个特殊字符；\t 表示制表符。还有其他类似的特殊字符，例如\n，表示换行。因此，让我们尝试运行以下代码：

```go
package main
import "fmt"
func main(){
 helloWorld := "Hello World, this is \"Tarik.\" \t\nHello again."
 fmt.Println(helloWorld)
}
```

前面的代码将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/6efe8ca7-17d6-4ca7-93b5-a8bdaec6d69f.png)

如您所见，`Hello again`不再在同一行上，而是放在了新的一行上。如果我删除/n 并再次运行代码，hello again 将回到同一行，我们还会因为特殊字符\t 而有一个大的空格：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/4257ff60-42f1-4acc-ace5-4714afc05243.png)

那么，我们如何转义\t？让我们看看如果包含另一个\会发生什么，并运行以下代码：

```go
package main
import "fmt"
func main(){
 helloWorld := "Hello World, this is \"Tarik.\" \\tHello again."
 fmt.Println(helloWorld)
}
```

如您在以下屏幕截图中所见，我们现在在字符串值中有了\t，Go 不再将其视为特殊字符：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/dc5f9031-2a97-42f3-b989-105a8b825d3d.png)

这就是在 Go 中使用转义字符的方法。在我们的下一节中，我们将看到如何轻松地将字符串值大写。

# 大写字符串值

在本节中，我们将看到如何在 Go 中大写单词。有多种方式可以大写句子中的单词；例如，您可能希望大写句子中的所有字母，或者只是所有单词的首字母，我们将看到如何做到这一点。

让我们回到我们的编辑器。前几个步骤与从字符串的开头和结尾修剪空格时一样。然而，在这里，我们有一个变量，其值为"hello world, how are you today"，我们希望只大写这个句子中所有单词的首字母。因此，我们之前在上一节中看到的 strings 包中有一个名为`title`的函数，该方法的签名也返回另一个字符串，我们可以将其赋给另一个变量，即`HelloWorldtitle`。为了继续，我们将不得不运行刚刚描述的代码：

```go
package main
import (
 "strings"
 "fmt"
)
func main(){
 helloWorld := "hello world, how are you today!"
 helloWorldtitle := strings.Title(helloWorld)
 fmt.Println(helloWorldtitle)
}
```

前面的代码将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/2c064635-37d6-4fc4-bb17-d4adf025420b.png)

如您所见，该代码导致了句子中所有首字母的大写。现在，如果我们想要大写这个句子中的所有字母，我们将不得不使用新的`ToUpper`函数运行以下代码：

```go
package main
import (
 "strings"
 "fmt"
)
func main(){
 helloWorld := "hello world, how are you today!"
 helloWorldtitle := strings.Title(helloWorld)
 fmt.Println(helloWorldtitle)
helloWorldUpper := strings.ToUpper(helloWorld)
 fmt.Println(helloWorldUpper)
}
```

如果您打印`Ln`，它实际上会在新的一行中打印该字符串，而如果您不打印，它就不会这样做。我们刚刚看到的代码将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/c2e4a283-6ac9-40e3-8556-d4c302a7f66d.png)

这就是关于大写字符串值的全部内容！

# 总结

在本章中，我们学习了如何从字符串的开头和结尾修剪空格，如何从字符串值中提取子字符串，如何替换字符串的部分内容，如何在字符串中转义字符，以及如何将字符串值大写。有了这些，我们已经完成了关于字符串操作的学习。下一章将描述如何在各种类型之间进行类型转换，我们将从将 pool 转换为字符串值开始。


# 第三章：类型转换

在日常编程活动中，从一种类型转换为另一种类型是非常常见的操作，因此知道如何做到这一点非常重要。在本章中，我们将通过一些实际示例来学习如何轻松地将一种类型转换为另一种类型。

在本章中，我们将涵盖以下主题：

+   从字符串的开头和结尾修剪空格

+   从字符串值中提取子字符串

+   替换字符串的部分

+   在字符串中转义字符

+   大写字符串值

# 将布尔值转换为字符串

我们将从学习如何将`Boolean`值转换为`String`值开始：

1.  在我们的编辑器中，创建一个名为`main.go`的新文件和`main`函数后，让我们考虑一个名为`isNew`的变量，它是一个布尔值。因此值将是`true`。

1.  所以，假设我们想要将其打印到控制台并附上消息。请查看以下截图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/2a36f4ec-b575-4739-9391-88b78d5af789.png)

正如您所看到的，我们遇到了一个编译时错误。因此，您不能使用`+`运算符，我们需要将`isNew`布尔值转换为其字符串表示形式。

1.  让我们使用`stringconvert`包，其中有各种字符串转换函数，其中，我们将使用`FormatBool`。

1.  获取`Boolean`值返回其每个字符串表示形式，此时是`isNew`。如果您查看签名，您会看到它根据传递的布尔值的值返回 true 或 false：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/4f96132a-3597-4cc1-babf-3aaab03d088c.png)

1.  所以，让我们添加`isNewStr`，运行它并检查输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/31306e10-e0bd-45eb-9e23-3bc257ac874e.png)

还有另一种将这些值打印到控制台的方法，称为`Printf`。它实际上可以将各种类型格式化到控制台。例如，我们可以使用之前介绍过的特殊字符。

请注意，我们不会为`Printf`使用`isNewStr`，因为现在我们可以使用任何类型，它将找到一个默认的字符串表示。

1.  此外，Go 不接受未使用的变量和未使用的包，因此，我们将注释掉`isNewStr := strconv.FormatBool(isNew)`并删除`isNewStr`。现在，我们可以运行以下代码：

```go
package main
import (
  "fmt"
)
func main(){
  isNew := true
  // isNewStr := strconv.FormatBool(isNew)
  message := "Purchased item is "
  fmt.Printf("%s %v", message, isNew)
}
```

1.  得到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/0c29abd4-91fa-4719-b8da-074263400aec.png)

1.  现在，我们得到与之前相同的消息，这就是您如何轻松地将`Boolean`类型转换为`String`类型。

在下一节中，我们将看到如何将整数和浮点值转换为字符串。

# 将整数和浮点值转换为字符串

在本节中，我们将学习如何将整数和浮点值转换为字符串值。起初，这可能看起来有点复杂，但在本节之后，您将感到足够舒适以处理这些转换。所以让我们回到我们的编辑器，看看我们如何做到这一点。

# 将整数值转换为字符串值

让我们从将整数值转换为字符串值开始：

1.  在字符串转换包`strconv`下，我们有一堆可以用于这些转换的函数；其中一个函数是`FormatInt`。

1.  所以让我们继续使用十进制。您可以有不同的基数，比如 16、10 和 24。

1.  如果您查看签名，您会看到它返回一个字符串。

1.  现在，代码将不会完全按照我们想要的方式工作，但我们将看到原因并加以修复。当您运行先前描述的代码时，将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/9d422335-6dc0-4b37-bb25-fbb001f9bf1c.png)

1.  现在，我们知道它接受 64 位整数类型；让我们修改代码并再次运行以获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/6070c681-1066-4311-a206-99eb0050f9e8.png)

1.  我们得到`100`作为字符串值返回到我们的控制台。您可能不想一直这样做，因此这是您可以运行的代码：

```go
package main
import (
  "strconv"
  "fmt"
)
func main(){
  number := 100
  numberStr := strconv.Itoa(number)
  fmt.Println(numberStr)
}
```

1.  我们使用了一个不同的函数，它会自动将整数转换为 ASCII。运行代码后，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/6257ebe3-8da2-41da-96e5-1a5d0fc65b4b.png)

# 将浮点值转换为字符串值

让我们继续进行第二次转换，即将浮点值转换为字符串值：

1.  在这里，我们将为`numberFloat`有另一个数字，例如`23445221.1223`，并且我们将学习将其转换为缩小值。

1.  我们将考虑另一个函数，即`FormatFloat`。

1.  因此，让我们继续看一下签名：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/10f21884-0e44-4085-9269-2327420941ea.png)

1.  首先，它希望我们传递一个浮点数`64`（我们也有浮点数`32`）；它们是`bitSizes`，表示浮点数的大小。我们有格式（`fmt`），可以使用各种字母，如*E*、*F*或*G*；例如，*G*用于大指数，*F*用于无指数。我们有精度，基本上告诉我们想要使用小数点后的数字有多远，位大小是浮点数`32`或浮点数`64`。我们可以根据情况添加所有这些实体。因此，您可以运行以下代码：

```go
package main
import (
 "strconv"
 "fmt"
)
func main(){
 number := 100
 numberStr := strconv.Itoa(number)
 fmt.Println(numberStr)
 numberFloat := 23445221.1223356
 numberFloatStr := strconv.FormatFloat(numberFloat, 'f', 5, 64 )
 fmt.Println(numberFloatStr)
}
```

1.  上述代码的输出将如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/fe413dfc-1525-4d59-b22c-6982f974ae04.png)

1.  让我们再玩一下精度；如果我们将其更改为`3`，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/2708bbac-f0b8-405c-80b9-b3efb9d4a79b.png)

1.  输出只显示小数点后的三个字符或三个数字。如果您不知道小数点后需要多少位数，可以将精度设置为`-1`，输出将显示小数点后的所有数字；例如，检查以下代码：

```go
package main
import (
  "strconv"
  "fmt"
)
func main(){
  number := 100
  numberStr := strconv.Itoa(number)
  fmt.Println(numberStr)
  numberFloat := 23445221.1223356
  numberFloatStr := strconv.FormatFloat(numberFloat, 'f',-1,64 )
  fmt.Println(numberFloatStr)
}
```

1.  上述代码将给我们以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/02dec563-88af-4cdb-af5d-5d004f37e6da.png)

1.  因此，当您想显示所有内容但不知道小数点后的确切数字时，您可能希望使用精度为`-1`。

这就是您可以在 Go 中执行整数和浮点值转换为字符串值的方法。在下一节中，我们将看到如何将字符串值解析为布尔值。

# 将字符串值解析为布尔值

在本节中，我们将看到如何将字符串值转换为布尔值：

1.  因此，在我们的编辑器中，我们将有一个名为`isNew`的变量，这将是一个字符串值，是一个真值。我们将使用一个名为`strconv`的包，其中有`ParseBool`。它返回两件事：一个是布尔值，另一个是错误。因此，让我们检查以下代码：

```go
package main
import (
  "strconv"
  "fmt"
)
```

```go
func main(){
  isNew := "true"
  isNewBool, err := strconv.ParseBool(isNew)
  if(err != nil){
    fmt.Println("failed")
  }else{
    if(isNewBool){
      fmt.Print("IsNew")
    }else{
      fmt.Println("Not new")
    }
  }
}
```

1.  您应该检查错误是否不为 nil。这将意味着发生了错误，我们将不得不处理它。例如，我们只会输出一些失败消息，即`failed`。

1.  如果在其他语言中它不是 nil，但在这里它是 nil，那么我们将不得不检查`isNew`布尔值。如果看起来没问题，我们将`IsNew`写入输出，或者`Not new`。

1.  运行代码后，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/5c0f7e46-e726-41dc-99ee-1d0285df5de1.png)

1.  如您所见，它通过了并且没有抛出异常。如果`true`更改为`false`，我们将获得`Not new`的输出。当然，`ParseBool`方法足够灵活，可以接受各种字符串值。

1.  如果您查看以下截图中的签名，您将看到`T`、`TRUE`、`true`等：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/345064b0-4eec-4638-9a0e-4e585f023edf.png)

1.  如果我们输入`1`而不是`true`，输出仍将是`IsNew`；如果我们输入`0`、`F`或`f`，它将转换为`false`，并输出`Not new`。

1.  让我们看看如果我们传入`J`会发生什么：

```go
package main
import (
  "strconv"
  "fmt"
)
func main(){
  isNew := "j"
  isNewBool, err := strconv.ParseBool(isNew)
  if(err != nil){
    fmt.Println("failed")
  }else{
    if(isNewBool){
      fmt.Print("IsNew")
    }else{
      fmt.Println("Not new")
    }
  }
}
```

1.  代码将输出以下内容：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/f9d95a80-0719-46aa-9a36-b0b8cecec456.png)

1.  如您所见，输出将是`failed`。

在下一节中，我们将向您展示如何将字符串值解析为整数和浮点类型。

# 将字符串值解析为整数和浮点类型

在本节中，我们将看到如何将字符串值解析为整数和浮点类型。

# 将字符串值解析为整数类型

假设我们有一个名为`number`的变量，它的字符串值为`2`。我们将使用`strconv.ParseInt`，它返回两个变量：第一个是我们期望的实际整数，另一个是在转换过程中发生错误时出现的返回变量。

如果你看一下签名，你会看到它返回整数`64`和一个错误：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/1e2ad662-0146-481c-b80f-3a604a7ebedf.png)

因此，我们可以首先检查在转换过程中是否发生了任何错误；如果不是 nil，我们就可以理解发生了某些事情，然后打印`Error happened`。

在 Go 中没有`try...catch`，所以如果要编写弹性代码，就必须始终进行错误检查。

现在，对于`if`检查，如果数字是`2`，我们可以输出`Success`。现在，让我们运行如下描述的代码：

```go
package main
import (
  "strconv"
  "fmt"
)
func main(){

  number := "2"
  valueInt, err := strconv.ParseInt(number, 10, 32)
  if err != nil {
    fmt.Print("Error happened.")
  } else {
    if valueInt == 2{
      fmt.Println("Success")
    }
  }
}
```

代码的输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/4e0ecf78-6533-42a9-af26-04c200d74fc7.png)

转换成功了。你也可以尝试 64 位，结果是一样的。好了！这是从字符串转换为整数。

# 将字符串值解析为浮点数

现在，让我们来检查将字符串值解析为浮点数。首先，我们将使用与将字符串值解析为浮点数相同的代码，只进行了轻微的修改。修改后的代码如下：

```go
package main
import (
  "strconv"
  "fmt"
)
func main(){

  numberFloat := "2.2"
  valueFloat, errFloat := strconv.ParseFloat(numberFloat, 64)
  if errFloat != nil {
    fmt.Print("Error happened.")
  } else {
    if valueFloat == 2.2 {
      fmt.Println("Success")
    }
  }
}
```

运行代码后，返回一个`Success`消息。这意味着我们的转换成功了，我们成功地从`ParseFloat`方法中得到了`2.2`。

在下一节中，我们将学习如何将字节数组转换为字符串。

# 将字节数组转换为字符串

在本节中，我们将学习如何将字节数组转换为字符串：

关于本教程，你需要知道的最重要的事情是，在 Go 中，字符串变量只是字节切片。因此，将字节数组转换为字符串值和将字符串值转换为字节数组非常容易。

1.  让我们看看如何开始。假设你有一个`helloWorldByte`数组；目前，它是一个字节数组，但你可以从任何流中获取它，比如网络或文件。

```go
package main

import "fmt"

func main(){
  helloWorldByte := []byte{72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100}
  fmt.Println(string(helloWorldByte))
}
```

1.  我们还有字符串构造，它使将字节数组转换为其字符串表示变得非常容易。我们将使用`fmt.Println`来打印`helloWorldByte`的字符串表示，并运行代码。

1.  因此，让我们运行代码并检查输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/3c225bfd-6b53-484e-a845-38d678d1bda5.png)

1.  正如你所看到的，我们非常简单地将整个字节数组转换为了字符串表示。如果你想将字符串转换为字节数组，也可以使用一个字节来做同样的事情。让我们快速地做一下。检查以下代码：

```go
package main
import "fmt"
func main(){
  helloWorld := "Hello, World"
  fmt.Println([]byte(helloWorld))
}
```

1.  运行代码后，我们得到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/7e6ed7ac-7149-469a-a900-6d6c172fa19e.png)

将字节数组转换为字符串结束了第三章，*类型转换*。

# 总结

在本章中，我们涵盖了从字符串开头和结尾修剪空格、从字符串值中提取子字符串、替换字符串的部分、在字符串中转义字符以及将字符串值大写。在第四章中，*日期和时间*，我们将学习日期和时间的用法，并首先学习如何找到今天的日期和时间。


# 第四章：日期和时间

在本章中，我们将学习如何在 Go 编程语言中处理日期和时间。你将学习如何对`DateTime`值进行基本操作，比如找到两个日期之间的差异、获取今天的日期、对`DateTime`值进行简单的算术运算以及从字符串值中解析日期。本章将涵盖以下主题：

+   找到今天的日期和时间

+   从日期中添加和减去

+   找到两个日期之间的差异

+   从字符串中解析日期和时间

# 找到今天的日期和时间

在本节中，我们将学习如何找到今天的日期和时间。我们可以使用`time.Now`来获取今天的日期，它导入了一个`time`包，`time`返回一个`time`类型，因此我们将其分配给另一个变量并使用`String`函数。以下代码将帮助你更好地理解：

```go
package main

import (
  "time"
  "fmt"
)

func main(){
  current := time.Now()
  fmt.Println(current.String())
}
```

前面代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/eb811292-5437-4c8a-9ece-790933beab03.png)

如你所见，我们得到了一个包含所有内容的大字符串，当然，我们可以根据需要进行格式化。例如，我可以添加`current.Format`函数和一个预定义的布局，如下面的截图所示：

```go
package main

import (
 "time"
 "fmt"
)

func main(){
 current := time.Now()
 fmt.Println(current.String())

 fmt.Println("MM-DD-YYYY :", current.Format("01-02-2006"))
}
```

在前面截图中显示的代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/0db48887-4277-48e0-a361-5e40c9af55bb.png)

在前面的截图中，你会看到今天的日期。你也可以通过绕过布局`snf`，提及你想要的输出格式(`YYYY-MM-DD hh:mm:ss`)，来同时获得时间和日期，如下面的代码所示：

```go
package main

import (
  "time"
  "fmt"
)

func main(){
  current := time.Now()
  fmt.Println(current.String())

  fmt.Println("MM-DD-YYYY :", current.Format("01-02-2006"))

  fmt.Println("YYYY-MM-DD hh:mm:ss", current.Format("2006-01-02 15:04:05"))
}
```

在运行前面截图中提到的代码时，我们得到了以下输出，其中包括年、月、日和时间信息。可以在以下截图中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/ec22743f-6643-4cdc-8eae-03e05f815e6f.png)

因此，这就是你如何简单地获取今天的日期，并以各种方式在 Go 语言中进行格式化。在下一节中，我们将学习如何对日期值进行添加或减去。

# 从日期中添加和减去

在本节中，我们将学习如何对日期值进行添加和减去操作。

# 添加日期

让我们继续学习如何向当前日期添加一个月。但在这之前，我们需要知道当前日期。你可以按照我们在上一节中学到的步骤来做到这一点。假设我得到了 8 月 8 日(`2018-08-08 09:35:16.2687997 +0530 IST m=+0.003951601`)作为输出，我们需要在这个值上再添加一个月。通过在`time`类型上使用`AddDate`函数，我们可以添加任意多的年、月和日，因为它接受三个参数。整个代码将如下所示：

```go
package main

import (
  "time"
  "fmt"
)

func main(){
  current := time.Now()
  septDate := current.AddDate(0,1,0)

  fmt.Println(current.String())
  fmt.Println(septDate.String())
}
```

因此，从输出的下面截图中，你会注意到我们通过将值`1`传递给第二个参数，成功地向八月添加了一个额外的月份：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/3a6073c4-66a5-42d8-ba0f-fb758ab84dbe.png)

我们可以执行相同的步骤来添加年份。你可以将`years:`参数更改为`1`，并将输出中的`2018`更改为`2019`。这可以在下面的截图中看到：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/5b6c8f00-2155-4c1a-96bb-9a670bebc1e8.png)

这就是你如何添加日期值。

# 从日期中减去

我们要学习的第二件事是如何从当前日期中减去日期。如你在下面的代码行中所见，我们使用了`Sub`方法，因为它接受另一个`time`类型：

```go
septDate.Sub(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))
```

相反，我们将使用`AddDate`并向参数传递一个负值。因此，让我们将其分配给另一个变量并运行以下代码：

```go
package main

import (
  "time"
  "fmt"
)

func main(){
  current := time.Now()
  septDate := current.AddDate(1,1,0)

  fmt.Println(current.String())
  fmt.Println(septDate.String())

  //septDate.Sub(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))

  oneLessYears := septDate.AddDate(-1,0,0)
  fmt.Println(oneLessYears.String())
}
```

以下代码的输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/d3c6bec3-33f8-4673-ac4b-5de57621287d.png)

如你所见，我们通过从`2019`中减去`1`获得了`2018`。

# 添加时间

现在，假设你需要添加时间而不是月份或年份。为了继续，我们必须使用`Add`，它有`duration`，即你想要添加的时间量。

例如，让我们假设我们想要添加 10 分钟。检查以下代码：

```go
package main

import (
  "time"
  "fmt"
)

func main(){
  current := time.Now()
  septDate := current.AddDate(1,1,0)

  fmt.Println(current.String())
  fmt.Println(septDate.String())

  //septDate.Sub(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))

  oneLessYears := septDate.AddDate(-1,0,0)
  fmt.Println(oneLessYears.String())

  tenMoreMinutes := septDate.Add(10 * time.Minute)
  fmt.Println(tenMoreMinutes)
}
```

该代码返回另一种类型或值，即`time`类型，如果您查看输出，将会看到我们在 9 月的日期上添加了 10 分钟：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/88deb3f1-dc61-49e1-9cee-11d9c9c745f2.png)

现在，如果我看一下输出，我们可以看到我们添加了`10`分钟，所以`10:10:24`变成了`10:20:24`。如果我将`Minute`改为`Hour`，然后运行代码，我们将看到我们从 9 月的日期中添加了`10`小时，可以在以下代码块中看到：

```go
package main

import (
  "time"
  "fmt"
)

func main(){
  current := time.Now()
  septDate := current.AddDate(1,1,0)

  fmt.Println(current.String())
  fmt.Println(septDate.String())

  oneLessYears := septDate.AddDate(-1,0,0)
  fmt.Println(oneLessYears.String())

  tenMoreMinutes := septDate.Add(10 * time.Hour)
  fmt.Println(tenMoreMinutes)
}
```

我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/f1dbdcea-0904-4ee5-9f49-e16905899147.png)

所以，这基本上就是您进行时间添加的方法。在我们的下一节中，我们将看到如何找到两个日期值之间的差异。

# 查找两个日期之间的差异

在本节中，我们将学习如何找到两个日期之间的差异。假设我们有两个日期，如下面的代码块所示，您将看到此方法的签名是不言自明的。因此，我们只需使用以下代码来减去第一个日期：

```go
package main

import (
  "time"
  "fmt"
)

func main(){
  first := time.Date(2017, 1,1,0,0,0,0,time.UTC)
  second := time.Date(2018, 1,1,0,0,0,0,time.UTC)

  difference := second.Sub(first)
  fmt.Printf("Difference %v", difference)
}
```

现在，在我们运行代码并获得输出之前，如果您检查签名，您将看到该方法返回`Duration`而不是日期之间的`Time`类型：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/80ae7ed8-0d3e-454b-86a8-9718e3375118.png)

回到运行我们的代码，您将看到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/324aafb5-1f42-491c-bb2d-fc30f89e9b59.png)

这就是您简单地找到两个日期之间的差异。在我们的下一节中，我们将学习如何从给定的字符串中解析日期和时间。

# 解析字符串中的日期和时间

在本节中，我们将学习如何从字符串中解析日期和时间。本节将结束我们的章节。当您从字符串中解析日期和时间时，您需要两样东西：第一是布局，第二样是您想要解析的实际字符串。所以，让我们假设我们有一个变量，其中包含`str := "2018-08-08T11:45:26.371Z"`的字符串值。

为了让 Go 理解这一点，您需要提供一个`layout`属性。`layout`属性基本上描述了您的字符串`DateTime`的外观；它以年份开头，然后是月份，日期，然后是时间。与往常一样，`time`包为我们提供了各种实用函数，我们可以用来操作日期和时间。`Parse`方法返回两样东西，一个是解析日期，另一个是错误。如果在解析过程中发生任何错误，将会抛出一个错误，我们可以检查错误并查看出了什么问题，否则我们将只输出当前时间和我们解析的时间的字符串表示。所以，让我们运行以下代码：

```go
package main

import (
  "time"
  "fmt"
)

func main(){
  str := "2018-08-08T11:45:26.371Z"
  layout := "2006-01-02T15:04:05.000Z"
  t,err := time.Parse(layout, str)
  if err != nil{
    fmt.Println(err)
  }
  fmt.Println(t.String())
}
```

我们运行的代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/3a1c2d95-5493-4519-8444-610368de885d.png)

正如您所看到的，我们准确地捕获了我们试图解析的日期。这就是您在 Go 中进行解析的方法。

# 总结

在本章中，我们学习了如何找到当前日期和时间，如何在日期上添加和减去，如何找到两个日期之间的差异，以及如何从字符串中解析日期和时间。在下一章中，您将学习如何在 Go 语言中使用映射和数组。您将看到操作和迭代数组的实际示例，合并数组和映射，以及测试映射中是否存在键。


# 第五章：映射和数组

在本章中，您将学习如何在 Go 中使用映射和数组。您将看到操作和迭代数组、合并数组和映射以及测试映射中是否存在键的实际示例。在本章中，我们将介绍以下配方：

+   从列表中提取唯一的元素

+   从数组中查找元素

+   反转数组

+   迭代数组

+   将映射转换为键和值的数组

+   合并数组

+   合并映射

+   测试映射中是否存在键

# 从数组中提取唯一的元素

首先，我们将学习如何从列表中提取唯一的元素。首先，让我们想象我们有一个包含重复元素的切片。

现在，假设我们想提取唯一的元素。由于 Go 中没有内置的构造，我们将制作自己的函数来进行提取。因此，我们有`uniqueIntSlice`函数，它接受`intSlice`或`intarray`。我们的唯一函数将接受`intSlice`，并返回另一个切片。

因此，这个函数的想法是在一个单独的列表中跟踪重复的元素，如果一个元素在我们给定的列表中再次出现，那么我们就不会将该元素添加到我们的新列表中。现在，看看以下代码：

```go
package main
import "fmt"
func main(){
  intSlice := []int{1,5,5,5,5,7,8,6,6, 6}
  fmt.Println(intSlice)
  uniqueIntSlice := unique(intSlice)
  fmt.Println(uniqueIntSlice)
}
func unique(intSlice []int) []int{
  keys := make(map[int]bool)
  uniqueElements := []int{}
  for _,entry := range intSlice {
    if _, value := keys[entry]; !value{
      keys[entry] =true
      uniqueElements = append(uniqueElements, entry)
    }
  }
  return uniqueElements
}
```

所以，我们将有`keys`，它基本上是一个映射，在其他语言中称为字典。我们将有另一个切片来保存我们的`uniqueElements`，我们将使用`for each`循环来迭代每个元素，并将其添加到我们的新列表中，如果它不是重复的。我们通过传递一个`entry`来基本上获取我们的值；如果值是`false`，那么我们将该条目添加到我们的键或映射中，并将其值设置为`true`，以便我们可以看到这个元素是否已经出现在我们的列表中。我们还有一个内置的`append`函数，它接受一个切片，并将条目附加到我们的切片末尾，返回另一个切片。运行代码后，您应该获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/2c9e9a14-96fe-4b83-8ff2-7c2f67227f16.png)

如果您看一下第一个数组，会发现有重复的元素：多个`6`和`5`的实例。在我们的新数组或切片中，我们没有任何重复项，这就是我们从列表中提取唯一元素的方法。

在下一节中，我们将学习如何在 Go 中从数组中查找元素。

# 从数组中查找元素

在本节中，我们将学习如何从数组或切片中查找元素。有许多方法可以做到这一点，但在本章中，我们将介绍其中的两种方法。假设我们有一个变量，其中包含一系列字符串。在这个切片中搜索特定字符串的第一种方法将使用`for`循环：

```go
package main
import (
 "fmt"
 "sort"
)
func main() {
 str := []string{"Sandy","Provo","St. George","Salt Lake City","Draper","South Jordan","Murray"}
 for i,v := range str{
 if v == "Sandy" {
 fmt.Println(i)
 }
 }
}
```

运行上述代码后，我们发现单词`Sandy`在索引`0`处：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/04364147-9fe6-462e-8079-69aa08775fe6.png)

另一种方法是使用排序，我们可以先对切片进行排序，然后再搜索特定的项目。为了做到这一点，Go 提供了一个`sort`包。为了能够对切片进行排序，切片需要实现`sort`包需要的各种方法。`sort`包提供了一个名为`sort.stringslice`的类型，我们可以将我们的`stringslice`转换为`sort`提供的`StringSlice`类型。在这里，`sortedList`没有排序，所以我们必须显式对其进行排序。现在，看看以下代码：

```go
package main
import (
  "fmt"
  "sort"
)
func main() {
  str := []string{"Sandy","Provo","St. George","Salt Lake City","Draper","South Jordan","Murray"}
  for i,v := range str{
    if v == "Sandy" {
      fmt.Println(i)
    }
  }
  sortedList := sort.StringSlice(str)
  sortedList.Sort()
  fmt.Println(sortedList)
}
```

该代码将给出以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/484a6d9d-267e-4450-ae74-4d1e856e821a.png)

你可以看到`Draper`先出现，然后是`Murray`，基本上是按升序排序的。现在，要在这里搜索特定的项目，例如`Sandy`，只需在`main`函数中添加以下代码行：

```go
index := sortedList.Search("Sandy")
fmt.Println(index)
```

运行整个代码后，获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/5f078198-f4e9-4361-a7e8-db94193a14d3.png)

它输出`4`，这是单词`Sandy`的位置。这就是如何在数组中找到一个元素。同样的方法也适用于数字；例如，如果您查看`sort`包，您会发现`IntSlice`。使用整数切片确实简化了所有数字的排序和搜索操作。在我们的下一节中，我们将看到如何对数组进行反转。

# 反转一个数组

在本节中，我们将学习如何对数组进行反向排序。我们将有一个变量，它保存了一组数字的切片。由于您现在熟悉了 Go 中的`sort`包，您会知道`sort`包提供了许多功能，我们可以用来对数组和切片进行排序。如果您查看`sort`包，您会看到许多类型和函数。

现在，我们需要`sort`函数，它接受一个接口，这个接口在`sort`包中定义；因此，我们可以称之为`Sort`接口。我们将把我们的数字切片转换成一个接口。看看以下代码：

```go
package main
import (
  "sort"
  "fmt"
)
func main() {
  numbers := []int{1, 5, 3, 6, 2, 10, 8}
  tobeSorted := sort.IntSlice(numbers)
  sort.Sort(tobeSorted)
  fmt.Println(tobeSorted)
}
```

这段代码将给出以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/5408e565-0603-4b8d-b016-f488a25c5eae.png)

如果您查看输出，您会发现我们已经按升序对数字进行了排序。如果我们想按降序对它们进行排序呢？为了能够做到这一点，我们有另一种类型叫做`Reverse`，它实现了不同的函数来按降序对事物进行排序。看看以下代码：

```go
package main
import (
  "sort"
  "fmt"
)
func main() {
  numbers := []int{1, 5, 3, 6, 2, 10, 8}
  tobeSorted := sort.IntSlice(numbers)
  sort.Sort(sort.Reverse(tobeSorted))
  fmt.Println(tobeSorted)
}
```

运行代码后，我们得到以下输出，您会看到数字按降序排列：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/a92c26d9-a869-495f-b7f1-404564a40df3.png)

在下一节中，我们将看到如何遍历一个数组。

# 遍历一个数组

在本节中，我们将学习如何遍历一个数组。遍历一个数组是 Go 编程中最基本和常见的操作之一。让我们去我们的编辑器，看看我们如何轻松地做到这一点：

```go
package main

import "fmt"

func main(){
  numbers := []int{1, 5, 3, 6, 2, 10, 8}

  for index,value := range numbers{
     fmt.Printf("Index: %v and Value: %v\n", index, value)
  }
}
```

我们从上述代码中获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/3ee49dac-df50-42af-bf76-1874d827de22.png)

这就是您如何轻松地遍历各种类型的切片，包括字符串切片、字节切片或字节数组。

有时，您不需要`index`。在这种情况下，您可以使用下划线(`_`)来忽略它。这意味着您只对值感兴趣。为了执行这个操作，您可以输入以下代码：

```go
package main

import "fmt"

func main(){
  numbers := []int{1, 5, 3, 6, 2, 10, 8}
  for _,value := range numbers{
    // fmt.Printf("Index: %v and Value: %v\n", index, value)
    fmt.Println(value)
  }
}
```

这段代码的输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/b70f4a9a-ee1f-4338-8d5f-37f7a7b02984.png)

这就是您如何轻松地遍历各种类型的切片。在下一节中，我们将看到如何将一个 map 转换成一个键和值的数组。

# 将一个 map 转换成一个键和值的数组

在本节中，我们将看到如何将一个 map 转换成一个键和值的数组。让我们想象一个名为`nameAges`的变量，它有一个`map`，如下面的代码块所示，我们将字符串值映射到整数值。还有名字和年龄。

我们需要添加一个名为`NameAge`的新结构，它将有`Name`作为字符串和`Age`作为整数。我们现在将遍历我们的`nameAges`映射。我们将使用一个`for`循环，当您在映射类型上使用范围运算符时，它会返回两个东西，一个键和一个值。因此，让我们编写这段代码：

```go
package main
import "fmt"
type NameAge struct{
  Name string
  Age int
}
func main(){
  var nameAgeSlice []NameAge
  nameAges := map[string]int{
    "Michael": 30,
    "John": 25,
    "Jessica": 26,
    "Ali": 18,
  }
  for key, value := range nameAges{
    nameAgeSlice = append(nameAgeSlice, NameAge {key, value})
  }

  fmt.Println(nameAgeSlice)

}
```

运行上述代码后，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/25a71f49-0975-4bdc-8a4f-d0b45c58ccd2.png)

这就是如何将一个 map 轻松转换成一个数组。在下一节中，我们将学习如何在 Go 中合并数组。

# 合并数组

在本节中，我们将看到如何在 Go 中轻松合并两个数组。假设我们有两个数组，我们将把它们合并。如果您之前使用过`append`，您会知道它可以接受任意数量的参数。让我们看看以下代码：

```go
package main
import "fmt"
func main(){
  items1 := []int{3,4}
  items2 := []int{1,2}
  result := append(items1, items2...)
  fmt.Println(result)
}
```

运行以下代码后，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/f122f01d-3833-498a-b4de-ed35626bda0b.png)

现在，我们在输出中看到了`[3 4 1 2]`。你可以向数组中添加更多的值，仍然可以合并它们。这就是我们如何在 Go 中轻松合并两个数组。在下一节中，我们将看到如何这次合并地图。

# 合并地图

在本节中，我们将学习如何合并地图。查看以下截图中的两张地图：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/3c48d9be-6bf9-4d6a-b7b5-feac3fd561c4.png)

正如你所看到的，有四个项目，这些地图基本上是将一个字符串映射到一个整数。

如果你不使用逗号，就像在上述截图中`22`后面所示的那样，你将得到一个编译时异常。这是因为在 Go 中自动添加了一个分号，这在这段代码中是不合适的。

好的，让我们继续合并这两张地图。不幸的是，没有内置的方法可以做到这一点，所以我们只需要迭代这两张地图，然后将它们合并在一起。查看以下代码：

```go
package main
import "fmt"
func main(){
  map1 := map[string]int {
   "Michael":10,
   "Jessica":20,
   "Tarik":33,
   "Jon": 22,
  }
  fmt.Println(map1)

  map2 := map[string]int {
    "Lord":11,
    "Of":22,
    "The":36,
    "Rings": 23,
  }
  for key, value := range map2{
    map1[key] = value
  }
  fmt.Println(map1)
}
```

上述代码的输出如下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/b5759f76-ccad-406c-892b-7567588ef0c4.png)

好的，第一行，你可以看到，只有我们使用的初始元素，第二行包含基本上所有的东西，也就是来自`map2`的所有项目。这就是你可以快速将两张地图合并成一张地图的方法。在下一节中，我们将学习如何测试地图中键的存在。

# 测试地图中键的存在

在本节中，我们将看到如何检查给定地图中键是否存在。因此，我们有一个地图`nameAges`，它基本上将名字映射到年龄。查看以下代码：

```go
package main
import "fmt"
func main() {
  nameAges := map[string]int{
    "Tarik": 32,
    "Michael": 30,
    "Jon": 25,
  }

  fmt.Println(nameAges["Tarik"])
}
```

如你从以下截图中所见，我们基本上从`Tarik`键中获取了值。因此，它只返回了一个值，即`32`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/233df873-945f-418d-809e-98e38d7d60ab.png)

然而，还有另一种使用这个地图的方法，它返回两个东西：第一个是值，第二个是键是否存在。例如，查看以下代码：

```go
package main
import "fmt"
func main() {
  nameAges := map[string]int{
    "Tarik": 32,
    "Michael": 30,
    "Jon": 25,
  }

  value, exists := nameAges["Tarik"]
  fmt.Println(value)
  fmt.Println(exists)
}
```

输出将如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/4b64a2b0-285c-4827-b8a1-6dd206e0055c.png)

正如你所看到的，代码返回`true`，因为地图中存在`Tarik`，存在于`nameAges`中。现在，如果我们在地图中输入一个不存在的名字会怎么样呢？如果我们在`nameAges`中用`Jessica`替换`Tarik`，代码将返回`0`和`false`，而不是之前得到的`32`和`true`。

此外，你可以使用 Go 的`if`条件，这是一个条件检查。查看以下代码：

```go
package main
import "fmt"
func main() {
  nameAges := map[string]int{
    "Tarik": 32,
    "Michael": 30,
    "Jon": 25,
  }
  if _, exists := nameAges["Jessica"]; exists{
    fmt.Println("Jessica has found")
  }else {
    fmt.Println("Jessica cannot be found")
  }
}
```

如果你查看以下输出，你会看到我们得到了`Jessica 找不到`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/f215982e-5966-4997-a611-85304fcfe2b8.png)

这意味着它不存在。现在，如果我将`Jessica`添加到地图中并运行以下代码会怎么样：

```go
package main
import "fmt"
func main() {
  nameAges := map[string]int{
    "Tarik": 32,
    "Michael": 30,
    "Jon": 25,
    "Jessica" : 20,
  }
  if _, exists := nameAges["Jessica"]; exists{
    fmt.Println("Jessica can be found")
  }else {
    fmt.Println("Jessica cannot be found")
  }
}
```

如你从上述代码的输出中所见，代码返回`Jessica 可以找到`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/fd232325-4901-4e23-8243-0bdfbce0fe38.png)

实际上，我们甚至可以在`if`后面添加一个`value`，就像我们之前看到的那样，并用以下代码打印出`value`：

```go
package main
import "fmt"
func main() {
  nameAges := map[string]int{
    "Tarik": 32,
    "Michael": 30,
    "Jon": 25,
    "Jessica" : 20,
  }
  if value, exists := nameAges["Jessica"]; exists{
    fmt.Println(value)
  }else {
    fmt.Println("Jessica cannot be found")
  }
}
```

我们将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/97d71283-452a-45f9-a97b-3d48e436ebcc.png)

这就是你可以简单地查看给定地图中键是否存在的方法。

# 总结

本章带你了解了许多主题，比如从列表中提取唯一元素，从数组中找到一个元素，反转一个数组，将地图转换为键和值的数组，合并数组，合并地图，以及测试地图中键的存在。在第六章中，*错误和日志*，我们将看到有关错误和日志的用法，我们将从在 Go 中创建自定义错误类型开始。


# 第六章：错误和日志记录

在本章中，我们将学习如何处理错误并在需要时返回错误。Go 的错误机制与一些其他流行语言的不同，本节将教你如何按照 Go 的方式处理错误。我们还将学习如何在应用程序中执行简单的日志记录操作，以便更好地调试你的运行应用程序。在本章中，我们将涵盖以下主题：

+   创建自定义错误类型

+   在 Go 中的 try...catch 等价物

+   在你的应用程序中进行简单的日志记录

+   优雅地处理 panic

# 创建自定义错误类型

让我们从创建自定义错误类型开始。如果你来自 C#和 Java 等语言，你可能会发现 Go 中的错误机制有些不同。此外，创建自定义错误的方式非常简单，因为 Go 是一种鸭子类型的语言，这意味着只要你的结构满足一个接口，你就可以使用。让我们继续使用一个新类型创建我们自己的自定义错误。所以，我将有两个字段，`ShortMessage`和`DetailedMessage`，类型为字符串。你可以有尽可能多的字段，以捕获有关错误的更多信息。此外，为了满足`error`接口，我将实现一个新方法，`*MyError`，它将返回一个`string`值，我们可以将这个错误输出到控制台或某个日志文件中。

然后，我要做的是返回错误消息。所以，你可以很简单地从你的方法中返回这个错误类型。假设我们有一个`doSomething`方法返回一个错误。假设我们在该方法中做了一些代码，并且由于某种原因返回了一个错误，比如一个`ShortMessage`实例为`"Wohoo something happened!"`。当然，你可能需要在这里使用更有意义的消息，并且不要忘记使用`&`运算符。它将获取你的`*MyError`对象的地址，因为我们在这里使用的是指针。如果你不这样做，你会看到有一个类型错误，修复这个错误的一种方法是删除那个`*`指针，错误就会被修复。但你可能不想有多个相同对象的副本，所以不要按照我刚刚描述的做法，你可以很容易地这样做：发送一个引用回去，这样你就有更好的内存管理。现在让我们看一下整个代码：

```go
package main

import "fmt"

type MyError struct{
  ShortMessage string
  DetailedMessage string
  //Name string
  //Age int
}

func (e *MyError) Error() string {
  return e.ShortMessage + "\n" +e.DetailedMessage

}
  func main(){
    err:= doSomething()
    fmt.Print(err)
}
func doSomething() error {
  //Doing something here...
  return &MyError{ShortMessage:"Wohoo something happened!", DetailedMessage:"File cannot found!"}
}
```

所以，让我们运行一下，当然它会返回一些错误；我们只需要在这里添加`err`，然后运行到控制台。现在，我们可以看到我们的消息或错误消息被写入到控制台中，如下面的截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/b6df9a90-ea0c-4398-817c-d7addf448f5d.png)

这就是你可以简单地创建自己的错误消息类型。在我们的下一节中，我们将学习 Go 中的`try...catch`等价物。

# 在 Go 中的 try...catch 等价物

与其他语言不同，Go 中没有`try...catch`块。在本节中，我们将看到 Go 如何处理基本错误。所以，我们首先要看的是如何处理 API 调用返回的错误。我们可以使用`time.Parse()`方法，因为它接受一个布局和一个值字符串。它返回两个东西，一个是`parsedDate`，另一个是一个错误。Go 大多数时候不是返回异常，而是返回一个错误作为它的第二个参数。

现在，你可以处理这个错误，检查`parsedDate`是否为 nil。如果在 Go 中不是 nil，那么我们知道发生了错误，我们需要处理它。如果什么都没发生，我们可以安全地继续下一行，即将`parsedDate`的内容写入输出。所以，检查下面的代码示例：

```go
package main

import (
  "time"
  "fmt"
)

func main(){
  parsedDate, err:= time.Parse("2006", "2018")
  if err != nil {
    fmt.Println("An error occured", err.Error())
  }else{
    fmt.Println(parsedDate)
  }
}
```

上述代码将给出以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/150d4ada-4907-439b-b23e-bcb639aa084a.png)

你可以看到它运行正常。如果我们在`2018`后面添加一些`string`值会发生什么？让我们添加`abc`，然后运行代码。如果你看到以下截图，你会看到在解析时间时发生了错误；它还添加了错误消息`An error occured parsing time "2018 abc": extra text: abc`，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/9f6e2e3d-0e2b-4cef-99b2-2e1070ab3f0c.png)

现在，本节的第二部分是当你自己返回一个错误时。假设我们有一个`doSomething`函数，它返回一个`err`类型。检查以下代码：

```go
package main
import (
  "fmt"
  "errors"
)
func main(){
  _, err := doSomething()
  if err != nil {
    fmt.Println(err)
  }
}
func doSomething() (string,error) {
  return "", errors.New("Something happened.")
}
```

上述代码将产生以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/9fdffdf3-e102-4817-b4a6-6db1eb04ef37.png)

这就是你可以在 Go 中做一个简单的`try...catch`的等价物。在下一节中，我们将看到如何在你的应用程序中进行简单的日志记录。

# 在你的应用程序中进行简单的日志记录

在本节中，我们将学习如何在应用程序中进行简单的日志记录。当然，你可以用各种方法来做这个，也有第三方包可以让你这样做，但我们将使用 Go 提供的`log`包。所以，我们首先要做的是使用`os`包创建一个新文件，如果在创建`log`文件时出现错误，我们将把它写入控制台。我们还将使用`defer`函数。在`main`方法退出之前，这个`defer`函数将被调用，下一步是设置输出：

```go
package main
import (
  "os"
  "fmt"
  "log"
)
func main(){
  log_file, err := os.Create("log_file")
  if err != nil{
    fmt.Println("An error occured...")
  }
  defer log_file.Close()
  log.SetOutput(log_file)

  log.Println("Doing some logging here...")
  log.Fatalln("Fatal: Application crashed!")
}
```

当我们运行上述代码时，将创建一个名为`log_file`的新文件，其中包含以下内容：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/e907f02e-c236-4823-a6a7-946bd6ab4355.png)

你可能想知道致命错误和普通信息错误之间的区别。让我们重新排列这两行，看看新的顺序的行为。因此，我们将首先运行`Fatalln`，然后运行`Println`如下：

```go
package main
import (
  "os"
  "fmt"
  "log"
)
func main(){
  log_file, err := os.Create("log_file")
  if err != nil{
    fmt.Println("An error occured...")
  }
  defer log_file.Close()
  log.SetOutput(log_file)
  log.Fatalln("Fatal: Application crashed!")
  log.Println("Doing some logging here...")
}
```

如果你现在运行上述代码并检查`log_file`的内容，你会发现第二个`Println`没有被写入：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/a37bdce9-51b4-4c7c-9ead-f353274673bc.png)

区别在于`Fatalln`类似于`Println`，但后面只有一个对`os.Exit`的调用。因此，它基本上写入一个日志并退出应用程序，这就是两者之间的简单区别。这就是你可以在你的应用程序中简单地进行日志记录。当然，如果你不想一直设置输出，你可以将`main`函数封装到你的包中，就像我们在这里做的那样。在下一节中，我们将看到如何优雅地处理恐慌。

# 优雅地处理恐慌

在本节中，我们将看到如何优雅地处理恐慌。与错误不同，如果你不从恐慌中恢复，它将停止程序的执行。因此，处理它们是重要的，如果你希望你的程序继续执行。首先，让我们看看如何在 Go 程序中抛出恐慌。你可以简单地使用一个叫做`panic`的关键字，这是一个内置函数，类型为 panic，运行它以获得输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/c8bfa192-2f73-42ac-886d-0b6f49bb6bd6.png)

还有另一种方法。让我们在这里使用另一个函数并写一些东西。假设我们正在做某事，由于某种原因它突然恐慌了。这可能是一个第三方方法，这意味着它位于第三方包中，所以我们可能无法完全控制该包。因此，如果你运行上述代码，这是我们将在应用程序窗口中看到的内容，以及我们想要写入控制台的消息，如下所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/a142bb04-f555-4a89-a8f0-c9a7eec7fa69.png)

我们还在这里看到了我们的`panic`的堆栈跟踪。首先，它触发了主要消息，后来又触发了`writeSomething()`方法。那么我们如何处理这个`panic`呢？我们有这个`defer`关键字，你必须使用这个`defer`。`defer`的意思是；嗯，就在你的方法退出之前，你想运行另一段代码，所以你只需传递一个函数，然后说“我想运行这个`defer`函数”。当然，它需要像这样：`defer func(){}()`，或者你可以在这里直接说`defer writeSomething()`。没关系，但是因为我要运行一些代码，所以我在这里将它们封装在函数中。我们还有另一个关键字叫做`recover`，它在`main`函数退出之前运行`defer`函数。此外，在这个函数中，我们尝试`recover`。

如果发生了 panic，这个`recover`会返回一些东西，如果没有 panic，那就意味着它不会返回任何东西。因此，`r`的值将是`nil`，这意味着我们不会向控制台写任何东西，因为我们不需要。但是，如果发生了 panic，那么我们就会进入`if`条件，然后写下来自`recover`构建方法的任何内容，然后继续运行以下代码，我们将得到相应的输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/e79fd976-228d-41d9-be1e-1c15e47e6d58.png)

所以，现在你可以看到我们基本上说`Recovered in f`，消息就是 panic 抛出的内容，这是我们在这里写的。如果你想看到这个过程的继续，我们可以从`main`函数中复制`defer func()`函数。接下来，我们将创建另一个名为`sayHello()`的方法，并将`defer func()`粘贴到其中。我想向你展示的是，我们已经从 panic 中恢复了，所以执行也会到达这一行。所以，我们可以继续运行以下代码：

```go
package main

import "fmt"

func main(){
  sayHello()
  fmt.Println("After the panic was recovered!")
}

func sayHello(){
  defer func(){
    if r := recover(); r != nil {
      fmt.Println("Recovered in f", r)
    }
  }()
  writeSomething()
}

func writeSomething(){
  /// Doing something here..
  panic("Write operation error")
}
```

在执行`main`函数之后，现在我们看到消息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/f04575d2-ccdd-4269-94d3-ee71ba297f3b.png)

如果我们没有`defer`函数，让我们看看它会如何表现。现在你看到它没有触发`main`函数，我们有 panic 和所有的堆栈跟踪，这就是你如何在应用程序中优雅地处理 panic。

# 摘要

本章是关于错误和日志记录的介绍。在下一章中，我们将学习如何在操作系统中处理文件和目录。我们还将学习解析和使用各种格式，如 XML、YAML 和 JSON。


# 第七章：文件和目录

在上一章中，您学会了如何处理错误和日志记录。在本章中，我们将看到如何在 Go 语言中处理文件和目录的相关操作。您还将了解解析和使用各种格式，如 XML、YAML 和 JSON。本章将涵盖以下主题：

+   检查文件是否存在

+   读取文本文件的全部内容

+   写入文件

+   创建临时文件

+   计算文件中的行数

+   在文件中读取特定行

+   比较两个文件的内容

+   删除文件

+   复制或移动文件

+   重命名文件

+   删除目录及其内容

+   列出目录下的所有文件

# 检查文件是否存在

我们将从检查文件是否存在开始。因此，首先让我们通过单击 New | File 并将其命名为`log.txt`来创建一个文件。

要开始检查文件是否存在，我们将使用`os.Stat`包。它返回两个值：第一个是文件信息，第二个是错误。我们不需要文件信息，只需要错误本身，因为我们将检查错误以查看文件是否存在。如果错误是`nil`（没有错误发生），那么文件存在。请查看以下代码：

```go
package main
import (
  "os"
  "fmt"
)
func main(){
  if _, err := os.Stat("log.txt"); err == nil{
    fmt.Println("Log.txt file exists")
  }
}
```

运行上述代码时，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/1b6a4608-dc38-45fd-81c2-2a7fcde62f49.png)

要以相反的方式检查文件是否存在，我们只需输入`os.IsNotExist()`并传递我们捕获的`err`并将其打印到控制台。请查看以下代码：

```go
package main
import (
  "os"
  "fmt"
)
func main(){
  if _, err := os.Stat("log.txt"); os.IsNotExist(err){
    fmt.Println("Log.txt file does not exist")
  }else{
    fmt.Println("Log.txt file exists")
  }
}
```

运行上述代码时，我们将得到相同的输出，显示`Log.txt 文件存在`。现在，让我们尝试运行相同的代码，但这次删除`log.txt`文件。您将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/3f4015dc-873e-4739-878f-bcc035a86f58.png)

您可以看到现在输出显示`Log.txt 文件不存在`，这样您就可以轻松地检查文件是否存在。在下一节中，我们将看到如何读取文件的全部内容。

# 读取文本文件的全部内容

在本节中，我们将看到如何读取文件的全部内容。我们将创建一个名为`names`的新文件，我有一堆名字，例如`Tarik`，`Guney`，`Michael`，`John`和`Montana`。我们将读取这个文件。我们将使用提供读取文件功能的`io`实用程序包，并接受文件的路径，即`names.txt`。它返回两个东西：文件的实际内容和错误。如果没有错误发生，我们将首先将`contentBytes`转换为`string`表示。现在让我们使用以下代码将内容写入控制台：

```go
package main
import (
  "io/ioutil"
  "fmt"
)
func main(){
  contentBytes, err := ioutil.ReadFile("names.txt")
  if err == nil{
    var contentStr string = string(contentBytes)
    fmt.Println(contentStr)
  }
}
```

通过在终端中使用`go run main.go`命令运行代码，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/0c58474b-7b23-4b89-9a69-29121a73758b.png)

因此，您可以看到我们已经从文件中读取了所有的名字。这就是您如何轻松地将文件的全部内容读入内存中。

在下一节中，我们将看到如何写入文件。

# 写入文件

在这一部分，我们将看到如何写入文件。与读取文件类似，我们将使用`ioutil`包。我们将使用`ioutil.WriteFile`函数，它接受三个参数。第一个参数是我们要写入的文件名，第二个是我们要写入的数据，最后一个是文件权限。这里的优势是，如果文件不存在，`WriteFile`将使用`perm`参数给出的权限创建文件，如果文件已经存在，则在写入之前将截断文件。我们将继续往我们的文件中写入一些内容，因为我们的文件还不存在，它会为我们创建一个新文件。我们将写入`Hello, World`，这是一个`string`参数，我们将把它转换为`byte`数组，然后才能传递给`WriteFile`。文件名将是`hello_world`，第二个参数将是`hello`变量的字节表示。这将返回一个错误。如果它不是`nil`，意味着发生了某些事情。让我们检查一下代码：

```go
package main
import (
  "io/ioutil"
  "fmt"
)
```

```go
func main() {
  hello := "Hello, World"
  err := ioutil.WriteFile("hello_world", []byte(hello), 0644)
  if err != nil{
    fmt.Println(err)
  }
}
```

运行代码时，你会看到没有错误发生，我们的`hello_world`文件存在。如果你打开文件，你会看到`Hello, World`已经被写入了：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/e95a2f11-50ae-4abe-964a-7769cdef2f44.png)

如果我们再次用不同的`string`和`Hello, World Again`运行代码，你会看到之前的内容被清除并替换为新内容，如下截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/fca14fb8-c3bb-44ec-a633-e81e0859989c.png)

这基本上就是如何写入文件。在我们的下一部分中，我们将看到如何创建临时文件。

# 创建临时文件

在这一部分，我们将看到如何创建临时文件。我们还将有一个包含字符串的变量，叫做`helloWorld := "Hello, World"`。我们将使用`ioutil`包，它提供了`TempFile()`方法。第一个参数是目录；如果你不给它传递任何东西，它将使用默认的临时目录，这在这种情况下我们将使用，第二个是给你的临时文件一个前缀，将是`hello_world_temp`。它返回两个东西：第一个是创建的临时文件，第二个是错误（`err`）。现在，如果发生任何错误，我们将会抛出错误作为消息。

当你完成临时文件后，建议删除文件，我们可以使用`defer`函数，其中有一个`os.Remove()`方法。你只需要提供文件名，它就会找到并删除它。现在我们要把`helloWorld`写入我们的文件。现在让我们检查一下代码：

```go
package main
import (
 "io/ioutil"
 "fmt"
)
func main(){
 helloWorld := "Hello, World"
 file, err := ioutil.TempFile("", "hello_world_temp")
 if err != nil{
 panic(err)
 }
 defer os.Remove(file.Name())
 if _, err := file.Write([]byte(helloWorld)); err != nil {
 panic(err)
 }
 fmt.Println(file.Name())
}
```

运行上述代码，你将得到以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/8a87c71d-62b3-4fca-b709-b271a2b0377f.png)

路径是我们的文件所在的位置，选择的部分是我们文件的名称，这是一个临时文件，当然，这个文件会被删除。如果没有被删除，我们会在那个位置看到它。现在，我们不会删除文件，只需注释掉前面代码块中的`deferos.Remove(file.Name())`一行并运行它。

此外，我们将打开文件，并使用终端，我们将显示该文件的内容，使用`less`命令（在 Linux 中）和`more <`命令（在 Windows 中），如截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/350448fe-4fe4-4618-8ed6-f1f6c76d2676.png)

如果你看前面的截图，你会看到`Hello, World`在那里。

这就是你如何在 Go 中创建临时文件。

在我们的下一部分中，我们将看到如何计算文件的行数。

# 在文件中计算行数

在本节中，我们将看到如何计算文件的行数。假设我们有一个文件，每行都有一堆名字，我们必须计算文件中有多少行。首先，我们将使用`os.Open`包打开我们的文件，文件名将是`names.txt`。它返回一个错误，但是对于这个例子，我们不会关心错误，因为我们知道文件是存在的。因此，我将使用文件扫描程序来扫描文件。我们有`bufio.NewScanner`包，其中有新的扫描程序，它接受一个读取器，因此我们可以传递文件。行数将从`0`开始，我们将对`fileScanner.scan`进行此操作。因此，只要它扫描，它将增加行数。最后，我们将将行号写入控制台。当一切都完成时，我们将使用`defer file.Close()`函数。让我们检查代码：

```go
package main
import (
  "os"
  "bufio"
  "fmt"
)
func main() {
  file, _ := os.Open("names.txt")
  fileScanner := bufio.NewScanner(file)
  lineCount := 0;
  for fileScanner.Scan(){
    lineCount++
  }
  defer file.Close()
  fmt.Println(lineCount)
}
```

运行上述代码时，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/745e2305-90c6-48b5-9b06-24c3d98ca5f7.png)

输出打印出`5`，您也可以通过查看文件并手动计数来确认。

在我们的下一节中，我们将看到如何读取文件中的特定行。

# 读取文件中的特定行

在本节中，我们将看到如何读取文件中的特定行。我们有一个名为`names.txt`的文件，每行都有一堆名字：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/95227ee6-4354-4493-bb79-bd20b3e0b606.png)

我们只想从文件中读取第三行。查看以下代码：

```go
package main
import (
  "os"
  "bufio"
  "fmt"
)
func main(){
  fmt.Println(ReadLine(3))
}
func ReadLine(lineNumber int) string{
  file, _ := os.Open("names.txt")
  fileScanner := bufio.NewScanner(file)
  lineCount := 0
  for fileScanner.Scan(){
    if lineCount == lineNumber{
      return fileScanner.Text()
    }
    lineCount++
  }
  defer file.Close()
  return ""
}
```

首先，我们将有一个`ReadLine()`函数，它接受行号并返回一个字符串。首先，我们将使用`os.Open()`函数打开文件，然后我们将使用`fileScanner`。然后我们将传递文件，我们将使用的行数将从`0`开始。如果行数等于给定给我们的行号，那么我们将返回文件`scanner.txt`；否则，我们将递增计数器。最后，我们将使用`defer file.Close()`函数。运行上述代码时，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/4fa59ff5-ddd9-4385-960f-94f8e33941dc.png)

因此，它返回`john`，这是第三行，从`0`开始计数。如果您希望与人们在文件中计算行数时的预期更加一致，可以更改索引并从`1`开始。这样您就可以轻松地从文件中获取特定行。

在我们的下一节中，我们将看到如何比较两个文件的内容。

# 比较两个文件的内容

在本节中，我们将看到如何比较两个文件的内容。首先，我们将创建两个文本文件，内容相同，以便比较，`one.txt`和`two.txt`。我们将使用`ioutil`包将文件读入内存；与往常一样，我们将确保在导入第一个文件时没有错误，如果有错误，我们将简单地发生 panic。我们还将导入第二个文件。有一种非常简单的方法来检查这两个文件是否具有相同的内容（相等），即使用`byte`包下定义的`Equal`函数。查看以下代码：

```go
package main
import (
  "io/ioutil"
  "bytes"
  "fmt"
)
func main(){
  one, err := ioutil.ReadFile("one.txt")
  if err != nil{
    panic(err)
  }
  two, err2 := ioutil.ReadFile("two.txt")
  if err2 != nil{
    panic(err2)
  }
  same := bytes.Equal(one, two)
  fmt.Println(same)
}
```

运行上述代码时，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/af24c517-9553-4d45-bbbf-fb54e3e25a01.png)

输出为`true`，这意味着文件的内容相等。如果更改一个文件中的内容并再次运行相同的代码，则输出为`false`。这就是您检查两个不同文件中的内容是否相同的方法。

在下一节中，我们将学习如何使用 Go 语言删除文件。

# 删除文件

在这一部分，我们将看到如何在 Go 中删除文件。删除文件是 Go 中最简单的操作之一，因为`os`包提供了一个名为`Remove()`的函数，允许您删除任何文件。因此，首先，我们将创建一个新文件并命名为`new.txt`。下面的屏幕截图将显示在创建`new.txt`后的文件夹结构：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/85fe0208-841b-4aff-90e9-3ee20c9afb3e.png)

我们将看到如何删除`new.txt`文件。`Remove()`函数接受您文件的路径。如果发生错误，它会返回一个错误，我们将“捕获”该错误，如果它不是`nil`，则会触发。查看以下代码：

```go
package main
import "os"
func main() {
  err := os.Remove("new.txt")
  if err != nil{
    panic(err)
  }
}
```

让我们运行代码并检查输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/0a6265c5-edb4-4ed5-b9d4-50f5c0c35887.png)

您可以看到`new.txt`文件已经消失，我们已成功删除了该文件。因此，我要继续运行这个，正如您所看到的，`new.txt`文件消失了。让我们再次运行这个并看看当您尝试删除一开始不存在的文件时，我们将得到什么类型的恐慌和错误消息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/3f26b6bf-03fe-4ca6-a365-28dc4e283b6d.png)

好了，这就是您如何在 Go 中轻松删除文件。在下一节中，我们将看到如何复制或移动文件。

# 复制或移动文件

在这一部分，我们将看到如何复制或移动文件。您可以以各种方式执行此操作，其中一些取决于您将要使用的操作系统。但是，我们将看到在不过多依赖操作系统的情况下复制或移动文件的最简单方法。首先，我们将添加一个要复制的文件并命名为`original.txt`，并添加一些包含`Hello, World`的内容。然后，我们将使用`os.Open()`打开文件，它将返回两个东西，原始文件和一个错误。如果没有错误，我们将继续执行`defer`，然后关闭文件。此外，我们将使用`os.Create()`创建一个新文件在相同的位置，它也会返回一个错误。现在最简单的方法是使用`io.Copy()`。因此，代码将看起来像这样：

```go
package main
import (
  "os"
  "io"
)
func main(){
  original, err := os.Open("original.txt")
  if err != nil{
    panic(err)
  }
  defer original.close()
  original_copy, err2 := os.Create("copy.txt")
  if err2 != nil{
    panic(err2)
  }
  defer original_copy.Close()
  _, err3 := io.Copy(original_copy, original)
  if err3 != nil{
    panic(err3)
  }
}
```

运行代码后，我们看到`copy.txt`出现，并且打开它时，我们可以看到其中包含从`original.txt`文件复制的`Hello, World`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/54b81394-f01b-4afb-ba56-8b01b8257960.png)

现在，让我们来看如何移动文件。首先，我们将创建一个名为`target`的新文件夹，并将`original.txt`复制到`target`中，并删除放置在`target`文件夹外部的`original.txt`文件。为此，`original_copy, err2 := os.Create("copy.txt")`将更改为`original_copy, err2 := os.Create("target/original.txt")`。如果您看到以下屏幕截图，您将注意到`original.txt`文件已被复制到`target`文件夹下：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/adc1d602-be2b-4525-8097-0be21234491b.png)

我们现在可以删除外部的`original.txt`文件。在上述代码的`main`函数末尾添加以下两行代码：

```go
original.Close()
os.Remove("original.txt")
```

运行上述代码后，您将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/a7d9ea9e-8779-4bd6-b9a1-467be9e39726.png)

正如您所看到的，该代码有效地通过移动和删除文件来移动`original.txt`文件。这就是您如何简单地在 Go 中复制和移动文件。

在下一节中，我们将看到如何在 Go 中轻松重命名文件。

# 重命名文件

在这一部分，我们将看到如何在 Go 中重命名文件。首先，我们将创建一个新文件并命名为`old.txt`，文件夹结构将如下屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/60b9bac7-c0df-439b-8862-7e32ab5867bf.png)

我们将更改此文件的名称为`new.txt`。要做到这一点，最简单的方法是使用`os`包提供的`Rename()`函数。该函数接受旧路径`old.txt`和新路径`new.txt`。让我们来看看代码：

```go
package main
import "os"
func main() {
  os.Rename("old.txt", "new.txt")
}
```

在运行代码时，您可以看到在以下屏幕截图中，名称`old.txt`已更改为`new.txt`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/1b7e6add-0928-4b42-91c5-51bd0843ad74.png)

因此，这基本上是我们如何在 Go 中重命名文件的方法。

在下一节中，我们将看到如何删除目录及其所有内容。

# 删除目录及其内容

在本节中，我们将看到如何删除目录及其内容。我们将使用`os`包，它提供了两个函数，`Remove（）`和`RemoveAll（）`。我们将检查这两个函数。首先，我们将创建一个名为`hello`的新目录，并保持为空，如下面的屏幕截图所示：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/06f763ca-9e82-4c16-9470-64388339dd92.png)

如前所述，我们将使用`os`包，它接受文件或目录。我们将传递一个目录，如果发生任何事情，它总是返回一个错误。我们必须检查这个错误是否不是`nil`。请查看以下代码：

```go
package main
import (
  "os"
  "fmt"
)
func main(){
  err := os.Remove("hello")
  if err != nil{
    fmt.Println(err)
  }
}
```

如果您运行代码，将获得以下文件夹结构作为输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/b9cd3c16-0a56-4800-8e83-e986b2723d47.png)

如果您比较两个输出屏幕截图，您会发现我们已成功删除了`hello`目录。但是，如果目录中有文件（比如`world.txt`），也就是说，目录不是空的，并且您运行相同的代码，那么目录将不会被删除，并且如果`hello`目录中有文件，则会显示以下消息：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/137c35c3-58be-4eea-928e-467a30bde069.png)

现在，有一个选项可以删除文件以及目录。我们可以使用我们在本节开头提到的`RemoveAll（）`函数。要做到这一点，只需将上述代码中的`err：= os.Remove（“hello”）`更改为`err：= os.RemoveAll（“hello”）`。

在运行上述代码时，您会发现您已成功删除了文件和目录，并且您将再次查看以下文件夹结构：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/d2ffbd3c-0af5-4b86-af53-c543117243f7.png)

在下一节中，我们将看到如何列出目录下的所有文件。

# 列出目录下的所有文件

在本节中，我们将看到如何列出目录下的所有文件。我们将创建一个名为`hello`的新目录，其中包括三个文件，即`jupiter.txt`，`mars.txt`和`world.txt`：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/0e8b0a22-d83b-425f-9296-8c09a188fccc.png)

我们要做的是读取所有文件并将它们的名称输出到控制台。我们将使用`ioutil.ReadDir`包并传入`hello`，这是我们目录的名称。这将返回两种类型的东西：两个文件和一个错误。我们将检查错误是否不是`nil`，并使用 panic 打印出内容。我们还将使用`for`循环来遍历文件。请查看以下代码：

```go
package main
import (
  "io/ioutil"
  "fmt"
)
func main() {
  files, err := ioutil.ReadDir("hello")
  if err != nil{
    panic(nil)
  }
  for _,f := range files{
    fmt.Println(f.Name())
  }
}
```

如果您运行上述代码，将获得以下输出：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-go-prog/img/d2ee0c53-9b60-48ec-8b1d-c7e90ab11019.png)

这就是您如何简单列出目录下的所有文件。

# 摘要

在本章中，您学习了如何在操作系统中处理文件和目录。您还学习了解析和使用各种格式，如 XML，YAML 和 JSON。在下一章中，我们将学习有关并发的技巧，并且我们将从同时运行多个函数开始。
