# Go 编程蓝图（二）

> 原文：[`zh.annas-archive.org/md5/AC9839247134C458206EE3BE6D404A66`](https://zh.annas-archive.org/md5/AC9839247134C458206EE3BE6D404A66)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：用于查找域名的命令行工具

我们在前几章中构建的聊天应用程序已经准备好在互联网上大放异彩，但在邀请朋友加入对话之前，我们需要为其在互联网上找一个家。在邀请朋友加入对话之前，我们需要选择一个有效、引人注目且可用的域名，以便将其指向运行我们 Go 代码的服务器。我们将开发一些命令行工具，而不是在我们喜爱的域名提供商前面花费数小时尝试不同的名称，这些工具将帮助我们找到合适的域名。在这个过程中，我们将看到 Go 标准库如何允许我们与终端和其他正在执行的应用程序进行交互，以及探索一些构建命令行程序的模式和实践。

在本章中，您将学到：

+   如何使用尽可能少的代码文件构建完整的命令行应用程序

+   如何确保我们构建的工具可以使用标准流与其他工具组合

+   如何与简单的第三方 JSON RESTful API 进行交互

+   如何在 Go 代码中利用标准输入和输出管道

+   如何从流式源中逐行读取

+   如何构建 WHOIS 客户端来查找域信息

+   如何存储和使用敏感或部署特定信息的环境变量

# 命令行工具的管道设计

我们将构建一系列命令行工具，这些工具使用标准流（`stdin`和`stdout`）与用户和其他工具进行通信。每个工具将通过标准输入管道逐行接收输入，以某种方式处理它，然后通过标准输出管道逐行打印输出，以供下一个工具或用户使用。

默认情况下，标准输入连接到用户的键盘，标准输出打印到运行命令的终端；但是，可以使用重定向元字符进行重定向。可以通过将输出重定向到 Windows 上的`NUL`或 Unix 机器上的`/dev/null`来丢弃输出，也可以将其重定向到文件，这将导致输出保存到磁盘。或者，您可以使用`|`管道字符将一个程序的输出管道到另一个程序的输入；我们将利用这个特性来连接我们的各种工具。例如，您可以通过以下代码将一个程序的输出管道到终端中的另一个程序的输入：

```go
one | two
```

我们的工具将使用字符串行的形式进行操作，其中每行（由换行符分隔）代表一个字符串。当没有任何管道重定向时，我们将能够直接与程序进行交互，使用默认的输入和输出，这在测试和调试代码时将非常有用。

# 五个简单的程序

在本章中，我们将构建五个小程序，最后将它们组合在一起。程序的主要特点如下：

+   **Sprinkle**：该程序将添加一些适合网络的词语，以增加找到可用域名的机会

+   **Domainify**：该程序将确保单词适合作为域名，方法是删除不可接受的字符，用连字符替换空格，并在末尾添加适当的顶级域（如`.com`和`.net`）

+   **Coolify**：该程序将通过调整元音字母将无聊的普通单词变成 Web 2.0

+   **Synonyms**：该程序将使用第三方 API 查找同义词

+   **可用**：该程序将使用适当的 WHOIS 服务器检查域名是否可用

五个程序在一个章节中可能看起来很多，但不要忘记在 Go 中整个程序可以有多小。

## Sprinkle

我们的第一个程序通过添加一些糖词来增加找到可用名称的几率。许多公司使用这种方法来保持核心消息一致，同时又能够负担得起`.com`域名。例如，如果我们传入单词`chat`，它可能输出`chatapp`；或者，如果我们传入`talk`，我们可能得到`talk time`。

Go 的`math/rand`包允许我们摆脱计算机的可预测性，为我们的程序过程提供机会或机会，并使我们的解决方案感觉比实际更智能一些。

为了使我们的 Sprinkle 程序工作，我们将：

+   使用特殊常量定义转换数组，以指示原始单词将出现在哪里

+   使用`bufio`包从`stdin`扫描输入，并使用`fmt.Println`将输出写入`stdout`

+   使用`math/rand`包来随机选择要应用于单词的转换，比如在单词后添加"app"或在术语前添加"get"

### 提示

我们所有的程序都将驻留在`$GOPATH/src`目录中。例如，如果您的`GOPATH`是`~/Work/projects/go`，您将在`~/Work/projects/go/src`文件夹中创建您的程序文件夹。

在`$GOPATH/src`目录中，创建一个名为`sprinkle`的新文件夹，并添加一个包含以下代码的`main.go`文件：

```go
package main
import (
  "bufio"
  "fmt"
  "math/rand"
  "os"
  "strings"
  "time"
)
const otherWord = "*"
var transforms = []string{
  otherWord,
  otherWord,
  otherWord,
  otherWord,
  otherWord + "app",
  otherWord + "site",
  otherWord + "time",
  "get" + otherWord,
  "go" + otherWord,
  "lets " + otherWord,
}
func main() {
  rand.Seed(time.Now().UTC().UnixNano())
  s := bufio.NewScanner(os.Stdin)
  for s.Scan() {
    t := transforms[rand.Intn(len(transforms))]
    fmt.Println(strings.Replace(t, otherWord, s.Text(), -1))
  }
}
```

从现在开始，假定您将自行解决适当的`import`语句。如果需要帮助，请参考附录中提供的提示，*稳定的 Go 环境的良好实践*。

前面的代码代表了我们完整的 Sprinkle 程序。它定义了三件事：一个常量，一个变量，以及作为 Sprinkle 入口点的必需的`main`函数。`otherWord`常量字符串是一个有用的标记，允许我们指定原始单词应出现在我们可能的每个转换中的位置。它让我们编写诸如`otherWord+"extra"`的代码，这清楚地表明，在这种特殊情况下，我们想在原始单词的末尾添加单词 extra。

可能的转换存储在我们声明为字符串切片的`transforms`变量中。在前面的代码中，我们定义了一些不同的转换，比如在单词末尾添加`app`或在单词前添加`lets`。随意添加一些更多的转换；越有创意，越好。

在`main`函数中，我们首先使用当前时间作为随机种子。计算机实际上无法生成随机数，但更改随机算法的种子数字会产生它可以的幻觉。我们使用纳秒级的当前时间，因为每次运行程序时它都是不同的（前提是系统时钟在每次运行之前没有被重置）。

然后，我们创建一个`bufio.Scanner`对象（称为`bufio.NewScanner`），并告诉它从`os.Stdin`读取输入，表示标准输入流。由于我们总是要从标准输入读取并写入标准输出，这将是我们五个程序中的常见模式。

### 提示

`bufio.Scanner`对象实际上将`io.Reader`作为其输入源，因此我们可以在这里使用各种类型。如果您为此代码编写单元测试，可以为扫描器指定自己的`io.Reader`，从中读取，而无需担心模拟标准输入流的需要。

作为默认情况，扫描器允许我们逐个读取由定义的分隔符分隔的字节块，例如回车和换行符。我们可以为扫描器指定自己的分割函数，或者使用标准库中内置的选项之一。例如，有`bufio.ScanWords`可以通过在空格上断开而不是换行符上断开来扫描单个单词。由于我们的设计规定每行必须包含一个单词（或短语），默认的逐行设置是理想的。

对`Scan`方法的调用告诉扫描器读取输入的下一块字节（下一行），并返回一个`bool`值，指示它是否找到了任何内容。这就是我们能够将其用作`for`循环的条件的方式。只要有内容可以处理，`Scan`就会返回`true`，并执行`for`循环的主体，当`Scan`到达输入的末尾时，它返回`false`，循环就会被打破。已选择的字节存储在扫描器的`Bytes`方法中，我们使用的方便的`Text`方法将`[]byte`切片转换为字符串。

在`for`循环内（对于每行输入），我们使用`rand.Intn`从`transforms`切片中选择一个随机项，并使用`strings.Replace`将原始单词插入到`otherWord`字符串出现的位置。最后，我们使用`fmt.Println`将输出打印到默认标准输出流。

让我们构建我们的程序并玩耍一下：

```go

go build –o sprinkle

./sprinkle

```

一旦程序运行，由于我们没有输入任何内容，或者指定了一个来源来读取内容，我们将使用默认行为，从终端读取用户输入。输入`chat`并按回车。我们代码中的扫描器注意到单词末尾的换行符，并运行转换代码，输出结果。例如，如果您多次输入`chat`，您可能会看到类似的输出：

```go

chat

go chat

chat

lets chat

chat

chat app

```

Sprinkle 永远不会退出（意味着`Scan`方法永远不会返回`false`来中断循环），因为终端仍在运行；在正常执行中，输入管道将被生成输入的任何程序关闭。要停止程序，请按*Ctrl* + *C*。

在我们继续之前，让我们尝试运行 Sprinkle，指定一个不同的输入源，我们将使用`echo`命令生成一些内容，并使用管道字符将其输入到我们的 Sprinkle 程序中：

```go

echo "chat" | ./sprinkle

```

程序将随机转换单词，打印出来，然后退出，因为`echo`命令在终止和关闭管道之前只生成一行输入。

我们已经成功完成了我们的第一个程序，它有一个非常简单但有用的功能，我们将会看到。

### 练习-可配置的转换

作为额外的任务，不要像我们所做的那样将`transformations`数组硬编码，看看是否可以将其外部化到文本文件或数据库中。

## Domainify

从 Sprinkle 输出的一些单词包含空格和其他在域名中不允许的字符，因此我们将编写一个名为 Domainify 的程序，将一行文本转换为可接受的域段，并在末尾添加适当的**顶级域**（**TLD**）。在`sprinkle`文件夹旁边，创建一个名为`domainify`的新文件夹，并添加一个带有以下代码的`main.go`文件：

```go
package main
var tlds = []string{"com", "net"}
const allowedChars = "abcdefghijklmnopqrstuvwxyz0123456789_-"
func main() {
  rand.Seed(time.Now().UTC().UnixNano())
  s := bufio.NewScanner(os.Stdin)
  for s.Scan() {
    text := strings.ToLower(s.Text())
    var newText []rune
    for _, r := range text {
      if unicode.IsSpace(r) {
        r = '-'
      }
      if !strings.ContainsRune(allowedChars, r) {
        continue
      }
      newText = append(newText, r)
    }
    fmt.Println(string(newText) + "." +        
                tlds[rand.Intn(len(tlds))])
  }
}
```

您会注意到 Domainify 和 Sprinkle 程序之间的一些相似之处：我们使用`rand.Seed`设置随机种子，使用`NewScanner`方法包装`os.Stdin`读取器，并扫描每一行，直到没有更多的输入。

然后我们将文本转换为小写，并构建一个名为`newText`的`rune`类型的新切片。`rune`类型仅包含出现在`allowedChars`字符串中的字符，`strings.ContainsRune`让我们知道。如果`rune`是一个空格，我们通过调用`unicode.IsSpace`来确定，我们将其替换为连字符，这在域名中是可以接受的做法。

### 注意

在字符串上进行范围循环会返回每个字符的索引和`rune`类型，这是一个表示字符本身的数值（具体是`int32`）。有关符文、字符和字符串的更多信息，请参阅[`blog.golang.org/strings`](http://blog.golang.org/strings)。

最后，我们将`newText`从`[]rune`切片转换为字符串，并在打印之前在末尾添加`.com`或`.net`。

构建并运行 Domainify：

```go

go build –o domainify

./domainify

```

输入一些选项，看看`domainify`的反应如何：

+   `Monkey`

+   `Hello Domainify`

+   `"What's up?"`

+   `One (two) three!`

例如，`One (two) three!`可能产生`one-two-three.com`。

现在我们将组合 Sprinkle 和 Domainify 以使它们一起工作。在您的终端中，导航到`sprinkle`和`domainify`的父文件夹（可能是`$GOPATH/src`），并运行以下命令：

```go

./sprinkle/sprinkle | ./domainify/domainify

```

在这里，我们运行了 Sprinkle 程序并将输出导入 Domainify 程序。默认情况下，`sprinkle`使用终端作为输入，`domanify`输出到终端。再次尝试多次输入`chat`，注意输出与之前 Sprinkle 输出的类似，只是现在这些单词适合作为域名。正是这种程序之间的管道传输使我们能够组合命令行工具。

### 练习-使顶级域名可配置

仅支持`.com`和`.net`顶级域名相当受限。作为额外的任务，看看是否可以通过命令行标志接受 TLD 列表。

## Coolify

通常，像`chat`这样的常见单词的域名已经被占用，一个常见的解决方案是对单词中的元音进行处理。例如，我们可能删除`a`得到`cht`（实际上更不太可能可用），或者添加一个`a`得到`chaat`。虽然这显然对酷度没有实际影响，但它已经成为一种流行的，尽管略显过时的方式来获得仍然听起来像原始单词的域名。

我们的第三个程序 Coolify 将允许我们处理通过输入的单词的元音，并将修改后的版本写入输出。

在`sprinkle`和`domainify`旁边创建一个名为`coolify`的新文件夹，并创建带有以下代码的`main.go`代码文件：

```go
package main
const (
  duplicateVowel bool   = true
  removeVowel    bool   = false
) 
func randBool() bool {
  return rand.Intn(2) == 0
}
func main() {
  rand.Seed(time.Now().UTC().UnixNano())
  s := bufio.NewScanner(os.Stdin)
  for s.Scan() {
    word := []byte(s.Text())
    if randBool() {
      var vI int = -1
      for i, char := range word {
        switch char {
        case 'a', 'e', 'i', 'o', 'u', 'A', 'E', 'I', 'O', 'U':
          if randBool() {
            vI = i
          }
        }
      }
      if vI >= 0 {
        switch randBool() {
        case duplicateVowel:
          word = append(word[:vI+1], word[vI:]...)
        case removeVowel:
          word = append(word[:vI], word[vI+1:]...)
        }
      }
    }
    fmt.Println(string(word))
  }
}
```

虽然前面的 Coolify 代码看起来与 Sprinkle 和 Domainify 的代码非常相似，但它稍微复杂一些。在代码的顶部，我们声明了两个常量，`duplicateVowel`和`removeVowel`，这有助于使 Coolify 代码更易读。`switch`语句决定我们是复制还是删除元音。此外，使用这些常量，我们能够非常清楚地表达我们的意图，而不仅仅使用`true`或`false`。

然后我们定义`randBool`辅助函数，它只是通过要求`rand`包生成一个随机数，然后检查该数字是否为零来随机返回`true`或`false`。它将是`0`或`1`，因此它有 50/50 的机会成为`true`。

Coolify 的`main`函数的开始方式与 Sprinkle 和 Domainify 的`main`函数相同——通过设置`rand.Seed`方法并在执行循环体之前创建标准输入流的扫描器来执行每行输入的循环体。我们首先调用`randBool`来决定是否要改变一个单词，因此 Coolify 只会影响通过其中的一半单词。

然后我们遍历字符串中的每个符文，并寻找元音。如果我们的`randBool`方法返回`true`，我们将元音字符的索引保留在`vI`变量中。如果不是，我们将继续在字符串中寻找另一个元音，这样我们就可以随机选择单词中的元音，而不总是修改相同的元音。

一旦我们选择了一个元音，我们再次使用`randBool`来随机决定要采取什么行动。

### 注意

这就是有用的常量发挥作用的地方；考虑以下备用的 switch 语句：

```go
switch randBool() {
case true:
  word = append(word[:vI+1], word[vI:]...)
case false:
  word = append(word[:vI], word[vI+1:]...)
}
```

在上述代码片段中，很难判断发生了什么，因为`true`和`false`没有表达任何上下文。另一方面，使用`duplicateVowel`和`removeVowel`告诉任何阅读代码的人我们通过`randBool`的结果的意图。

切片后面的三个点使每个项目作为单独的参数传递给`append`函数。这是一种将一个切片附加到另一个切片的成语方式。在`switch`情况下，我们对切片进行一些操作，以便复制元音或完全删除它。我们重新切片我们的`[]byte`切片，并使用`append`函数构建一个由原始单词的部分组成的新单词。以下图表显示了我们在代码中访问字符串的哪些部分：

![Coolify](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-prog-bp/img/Image00010.jpg)

如果我们以`blueprints`作为示例单词的值，并假设我们的代码选择第一个`e`字符作为元音（所以`vI`是`3`），我们可以看到单词的每个新切片在这个表中代表什么：

| 代码 | 值 | 描述 |
| --- | --- | --- |
| `word[:vI+1]` | `blue` | 描述了从单词切片的开头到所选元音的切片。`+1`是必需的，因为冒号后面的值不包括指定的索引；它切片直到该值。 |
| `word[vI:]` | `eprints` | 描述了从所选元音开始并包括切片到切片的末尾。 |
| `word[:vI]` | `blu` | 描述了从单词切片的开头到所选元音之前的切片。 |
| `word[vI+1:]` | `prints` | 描述了从所选元音后的项目到切片的末尾。 |

修改单词后，我们使用`fmt.Println`将其打印出来。

让我们构建 Coolify 并玩一下，看看它能做什么：

```go

go build –o coolify

./coolify

```

当 Coolify 运行时，尝试输入`blueprints`，看看它会做出什么样的修改：

```go

blueprnts

bleprints

bluepriints

blueprnts

blueprints

bluprints

```

让我们看看 Coolify 如何与 Sprinkle 和 Domainify 一起玩，通过将它们的名称添加到我们的管道链中。在终端中，使用`cd`命令返回到父文件夹，并运行以下命令：

```go

./coolify/coolify | ./sprinkle/sprinkle | ./domainify/domainify

```

首先，我们将用额外的部分来调整一个单词，通过调整元音字母使其更酷，最后将其转换为有效的域名。尝试输入一些单词，看看我们的代码会做出什么建议。

## 同义词

到目前为止，我们的程序只修改了单词，但要真正使我们的解决方案生动起来，我们需要能够集成一个提供单词同义词的第三方 API。这使我们能够在保留原始含义的同时建议不同的域名。与 Sprinkle 和 Domainify 不同，同义词将为每个给定的单词写出多个响应。我们将这三个程序连接在一起的架构意味着这不是问题；事实上，我们甚至不必担心，因为这三个程序都能够从输入源中读取多行。

[bighughlabs.com](http://bighughlabs.com)的 Big Hugh Thesaurus 有一个非常干净简单的 API，允许我们进行一次 HTTP `GET`请求来查找同义词。

### 提示

如果将来我们使用的 API 发生变化或消失（毕竟，这是互联网！），您可以在[`github.com/matryer/goblueprints`](https://github.com/matryer/goblueprints)找到一些选项。

在使用 Big Hugh Thesaurus 之前，您需要一个 API 密钥，您可以通过在[`words.bighugelabs.com/`](http://words.bighugelabs.com/)注册该服务来获取。

### 使用环境变量进行配置

您的 API 密钥是一项敏感的配置信息，您不希望与他人分享。我们可以将其存储为代码中的`const`，但这不仅意味着我们不能在不分享密钥的情况下分享我们的代码（尤其是如果您喜欢开源项目），而且，也许更重要的是，如果密钥过期或者您想使用其他密钥，您将不得不重新编译您的项目。

更好的解决方案是使用环境变量来存储密钥，因为这样可以让您在需要时轻松更改它。您还可以为不同的部署设置不同的密钥；也许您在开发或测试中有一个密钥，而在生产中有另一个密钥。这样，您可以为代码的特定执行设置一个特定的密钥，这样您可以轻松地在不必更改系统级设置的情况下切换密钥。无论如何，不同的操作系统以类似的方式处理环境变量，因此如果您正在编写跨平台代码，它们是一个完美的选择。

创建一个名为`BHT_APIKEY`的新环境变量，并将您的 API 密钥设置为其值。

### 注意

对于运行 bash shell 的计算机，您可以修改您的`~/.bashrc`文件或类似文件，包括`export`命令，例如：

```go
export BHT_APIKEY=abc123def456ghi789jkl
```

在 Windows 计算机上，您可以转到计算机的属性并在**高级**部分中查找**环境变量**。

### 消费 web API

在 Web 浏览器中请求[`words.bighugelabs.com/apisample.php?v=2&format=json`](http://words.bighugelabs.com/apisample.php?v=2&format=json)会显示我们在查找单词 love 的同义词时 JSON 响应数据的结构。

```go
{
  "noun":{
    "syn":[
      "passion",
      "beloved",
      "dear"
    ]
  },
  "verb":{
    "syn":[
      "love",
      "roll in the hay",
      "make out"
    ],
    "ant":[
      "hate"
    ]
  }
}
```

真正的 API 返回的实际单词比这里打印的要多得多，但结构才是重要的。它表示一个对象，其中键描述了单词类型（动词、名词等），值是包含在`syn`或`ant`（分别表示同义词和反义词）上的字符串数组的对象；这就是我们感兴趣的同义词。

要将这个 JSON 字符串数据转换成我们在代码中可以使用的东西，我们必须使用`encoding/json`包中的功能将其解码为我们自己的结构。因为我们正在编写的东西可能在我们项目的范围之外有用，所以我们将在一个可重用的包中消费 API，而不是直接在我们的程序代码中。在`$GOPATH/src`中的其他程序文件夹旁边创建一个名为`thesaurus`的新文件夹，并将以下代码插入到一个新的`bighugh.go`文件中：

```go
package thesaurus
import (
  "encoding/json"
  "errors"
  "net/http"
)
type BigHugh struct {
  APIKey string
}
type synonyms struct {
  Noun *words `json:"noun"`
  Verb *words `json:"verb"`
}
type words struct {
  Syn []string `json:"syn"`
}
func (b *BigHugh) Synonyms(term string) ([]string, error) {
  var syns []string
  response, err := http.Get("http://words.bighugelabs.com/api/2/" + b.APIKey + "/" + term + "/json")
  if err != nil {
    return syns, errors.New("bighugh: Failed when looking for synonyms for \"" + term + "\"" + err.Error())
  }
  var data synonyms
  defer response.Body.Close()
  if err := json.NewDecoder(response.Body).Decode(&data); err != nil {
    return syns, err
  }
  syns = append(syns, data.Noun.Syn...)
  syns = append(syns, data.Verb.Syn...)
  return syns, nil
}
```

在上述代码中，我们定义的`BigHugh`类型包含必要的 API 密钥，并提供了`Synonyms`方法，该方法将负责访问端点、解析响应并返回结果。这段代码最有趣的部分是`synonyms`和`words`结构。它们用 Go 术语描述了 JSON 响应格式，即包含名词和动词对象的对象，这些对象又包含一个名为`Syn`的字符串切片。标签（在每个字段定义后面的反引号中的字符串）告诉`encoding/json`包将哪些字段映射到哪些变量；这是必需的，因为我们给它们赋予了不同的名称。

### 提示

通常，JSON 键具有小写名称，但我们必须在我们的结构中使用大写名称，以便`encoding/json`包知道这些字段存在。如果我们不这样做，包将简单地忽略这些字段。但是，类型本身（`synonyms`和`words`）不需要被导出。

`Synonyms`方法接受一个`term`参数，并使用`http.Get`向 API 端点发出 web 请求，其中 URL 不仅包含 API 密钥值，还包含`term`值本身。如果由于某种原因 web 请求失败，我们将调用`log.Fatalln`，它会将错误写入标准错误流并以非零退出代码（实际上是`1`的退出代码）退出程序，表示发生了错误。

如果 web 请求成功，我们将响应主体（另一个`io.Reader`）传递给`json.NewDecoder`方法，并要求它将字节解码为我们的`synonyms`类型的`data`变量。我们推迟关闭响应主体，以便在使用 Go 的内置`append`函数将`noun`和`verb`的同义词连接到我们然后返回的`syns`切片之前保持内存清洁。

虽然我们已经实现了`BigHugh`词库，但这并不是唯一的选择，我们可以通过为我们的包添加`Thesaurus`接口来表达这一点。在`thesaurus`文件夹中，创建一个名为`thesaurus.go`的新文件，并将以下接口定义添加到文件中：

```go
package thesaurus
type Thesaurus interface {
  Synonyms(term string) ([]string, error)
}
```

这个简单的接口只是描述了一个接受`term`字符串并返回包含同义词的字符串切片或错误（如果出现问题）的方法。我们的`BigHugh`结构已经实现了这个接口，但现在其他用户可以为其他服务添加可互换的实现，比如[Dictionary.com](http://Dictionary.com)或 Merriam-Webster 在线服务。

接下来我们将在一个程序中使用这个新的包。通过在终端中返回到`$GOPATH/src`，创建一个名为`synonyms`的新文件夹，并将以下代码插入到一个新的`main.go`文件中，然后将该文件放入该文件夹中：

```go
func main() {
  apiKey := os.Getenv("BHT_APIKEY")
  thesaurus := &thesaurus.BigHugh{APIKey: apiKey}
  s := bufio.NewScanner(os.Stdin)
  for s.Scan() {
    word := s.Text()
    syns, err := thesaurus.Synonyms(word)
    if err != nil {
      log.Fatalln("Failed when looking for synonyms for \""+word+"\"", err)
    }
    if len(syns) == 0 {
      log.Fatalln("Couldn't find any synonyms for \"" + word + "\"")
    }
    for _, syn := range syns {
      fmt.Println(syn)
    }
  }
}
```

当你再次管理你的导入时，你将编写一个完整的程序，能够通过集成 Big Huge Thesaurus API 来查找单词的同义词。

在前面的代码中，我们的`main`函数首先要做的事情是通过`os.Getenv`调用获取`BHT_APIKEY`环境变量的值。为了使你的代码更加健壮，你可能需要再次检查以确保这个值被正确设置，并在没有设置时报告错误。现在，我们将假设一切都配置正确。

接下来，前面的代码开始看起来有点熟悉，因为它再次从`os.Stdin`扫描每一行输入，并调用`Synonyms`方法来获取替换词列表。

让我们构建一个程序，看看当我们输入单词`chat`时，API 返回了什么样的同义词：

```go

go build –o synonyms

./synonyms

chat

confab

confabulation

schmooze

New World chat

Old World chat

conversation

thrush

wood warbler

chew the fat

shoot the breeze

chitchat

chatter

```

你得到的结果很可能与我们在这里列出的结果不同，因为我们正在使用实时 API，但这里重要的一点是，当我们将一个词或术语作为程序的输入时，它会返回一个同义词列表作为输出，每行一个。

### 提示

尝试以不同的顺序将你的程序链接在一起，看看你得到什么结果。无论如何，我们将在本章后面一起做这件事。

### 获取域名建议

通过组合我们在本章中迄今为止构建的四个程序，我们已经有了一个有用的工具来建议域名。现在我们所要做的就是运行这些程序，同时以适当的方式将输出导入输入。在终端中，导航到父文件夹并运行以下单行命令：

```go

./synonyms/synonyms | ./sprinkle/sprinkle | ./coolify/coolify | ./domainify/domainify

```

因为`synonyms`程序在我们的列表中排在第一位，它将接收来自终端的输入（无论用户决定输入什么）。同样，因为`domainify`是链中的最后一个，它将把输出打印到终端供用户查看。在每一步，单词行将通过其他程序进行传输，使它们有机会发挥魔力。

输入一些单词来看一些域名建议，例如，如果你输入`chat`并回车，你可能会看到：

```go

getcnfab.com

confabulationtim.com

getschmoozee.net

schmosee.com

neew-world-chatsite.net

oold-world-chatsite.com

conversatin.net

new-world-warblersit.com

gothrush.net

lets-wood-wrbler.com

chw-the-fat.com

```

你得到的建议数量实际上取决于同义词的数量，因为它是唯一一个生成比我们给它的输出更多行的程序。

我们仍然没有解决我们最大的问题——我们不知道建议的域名是否真的可用，所以我们仍然需要坐下来，把它们每一个输入到一个网站中。在下一节中，我们将解决这个问题。

## 可用

我们的最终程序 Available 将连接到 WHOIS 服务器，询问传入的域名的详细信息——当然，如果没有返回任何详细信息，我们可以安全地假设该域名可以购买。不幸的是，WHOIS 规范（参见[`tools.ietf.org/html/rfc3912`](http://tools.ietf.org/html/rfc3912)）非常简单，没有提供关于当你询问域名的详细信息时，WHOIS 服务器应该如何回复的信息。这意味着以编程方式解析响应变得非常混乱。为了暂时解决这个问题，我们将只集成一个我们可以确定在响应中有“无匹配”（No match）的单个 WHOIS 服务器，当它没有该域名的记录时。

### 注意

一个更健壮的解决方案可能是使用具有明确定义结构的 WHOIS 接口来获取详细信息，也许在域名不存在的情况下提供错误消息，针对不同的 WHOIS 服务器有不同的实现。正如你所能想象的，这是一个相当大的项目；非常适合开源项目。

在`$GOPATH/src`目录旁边创建一个名为`available`的新文件夹，并在其中添加一个名为`main.go`的文件，其中包含以下函数代码：

```go
func exists(domain string) (bool, error) {
  const whoisServer string = "com.whois-servers.net"
  conn, err := net.Dial("tcp", whoisServer+":43")
  if err != nil {
    return false, err
  }
  defer conn.Close()
  conn.Write([]byte(domain + "\r\n"))
  scanner := bufio.NewScanner(conn)
  for scanner.Scan() {
    if strings.Contains(strings.ToLower(scanner.Text()), "no match") {
      return false, nil
    }
  }
  return true, nil
}
```

`exists`函数通过打开到指定`whoisServer`实例的端口`43`的连接来实现 WHOIS 规范中的一点内容，使用`net.Dial`进行调用。然后我们推迟关闭连接，这意味着无论函数如何退出（成功或出现错误，甚至是恐慌），都将在连接`conn`上调用`Close()`。连接打开后，我们只需写入域名，然后跟着`\r\n`（回车和换行字符）。这就是规范告诉我们的全部内容，所以从现在开始我们就要自己动手了。

基本上，我们正在寻找响应中是否提到了“无匹配”的内容，这就是我们决定域名是否存在的方式（在这种情况下，`exists`实际上只是询问 WHOIS 服务器是否有我们指定的域名的记录）。我们使用我们喜欢的`bufio.Scanner`方法来帮助我们迭代响应中的行。将连接传递给`NewScanner`是可行的，因为`net.Conn`实际上也是一个`io.Reader`。我们使用`strings.ToLower`，这样我们就不必担心大小写敏感性，使用`strings.Contains`来查看任何行是否包含“无匹配”文本。如果是，我们返回`false`（因为域名不存在），否则我们返回`true`。

`com.whois-servers.net` WHOIS 服务支持`.com`和`.net`的域名，这就是为什么 Domainify 程序只添加这些类型的域名。如果你使用的服务器对更广泛的域名提供了 WHOIS 信息，你可以添加对其他顶级域的支持。

让我们添加一个`main`函数，使用我们的`exists`函数来检查传入的域名是否可用。以下代码中的勾号和叉号符号是可选的——如果你的终端不支持它们，你可以自由地用简单的`Yes`和`No`字符串替换它们。

将以下代码添加到`main.go`中：

```go
var marks = map[bool]string{true: "✔", false: "×"}
func main() {
  s := bufio.NewScanner(os.Stdin)
  for s.Scan() {
    domain := s.Text()
    fmt.Print(domain, " ")
    exist, err := exists(domain)
    if err != nil {
      log.Fatalln(err)
    }
    fmt.Println(marks[!exist])
    time.Sleep(1 * time.Second)
  }
}
```

在`main`函数的前面代码中，我们只是迭代通过`os.Stdin`传入的每一行，用`fmt.Print`打印出域名（但不是`fmt.Println`，因为我们不想要换行），调用我们的`exists`函数来查看域名是否存在，然后用`fmt.Println`打印出结果（因为我们*确实*希望在最后有一个换行）。

最后，我们使用`time.Sleep`告诉进程在 1 秒内什么都不做，以确保我们对 WHOIS 服务器轻松一些。

### 提示

大多数 WHOIS 服务器都会以各种方式限制，以防止你占用过多资源。因此，减慢速度是确保我们不会惹恼远程服务器的明智方式。

考虑一下这对单元测试意味着什么。如果一个单元测试实际上是在向远程 WHOIS 服务器发出真实请求，每次测试运行时，您都会在您的 IP 地址上累积统计数据。一个更好的方法是对 WHOIS 服务器进行存根，以模拟真实的响应。

在前面代码的顶部的`marks`映射是将`exists`的布尔响应映射到人类可读的文本的一种好方法，这样我们只需使用`fmt.Println(marks[!exist])`在一行中打印响应。我们说不存在是因为我们的程序正在检查域名是否可用（逻辑上与是否存在于 WHOIS 服务器中相反）。

### 注意

我们可以在我们的代码中愉快地使用检查和叉字符，因为所有的 Go 代码文件都符合 UTF-8 标准——实际上获得这些字符的最好方法是在网上搜索它们，然后使用复制和粘贴将它们带入代码；否则，还有一些依赖于平台的方法来获得这样的特殊字符。

修复`main.go`文件的`import`语句后，我们可以尝试运行 Available，看看域名是否可用：

```go

go build –o available

./available

```

一旦 Available 正在运行，输入一些域名：

```go

packtpub.com

packtpub.com 

×

google.com

google.com 

×

madeupdomain1897238746234.net

madeupdomain1897238746234.net 

✔
```

正如你所看到的，对于显然不可用的域名，我们得到了一个小叉号，但是当我们使用随机数字编造一个域名时，我们发现它确实是可用的。

# 读累了记得休息一会哦~

**公众号：古德猫宁李**

+   电子书搜索下载

+   书单分享

+   书友学习交流

**网站：**[沉金书屋 https://www.chenjin5.com](https://www.chenjin5.com)

+   电子书搜索下载

+   电子书打包资源分享

+   学习资源分享

# 组合所有五个程序

现在我们已经完成了我们的所有五个程序，是时候把它们全部放在一起，这样我们就可以使用我们的工具为我们的聊天应用程序找到一个可用的域名。这样做的最简单方法是使用我们在本章中一直在使用的技术：在终端中使用管道连接输出和输入。

在终端中，导航到这五个程序的父文件夹，并运行以下单行代码：

```go

./synonyms/synonyms | ./sprinkle/sprinkle | ./coolify/coolify | ./domainify/domainify | ./available/available

```

程序运行后，输入一个起始词，看它如何生成建议，然后再检查它们的可用性。

例如，输入`chat`可能会导致程序执行以下操作：

1.  单词`chat`进入`synonyms`，然后出来一系列的同义词：

+   `confab`

+   `confabulation`

+   `schmooze`

1.  同义词流入`sprinkle`，在那里它们会被增加上网友好的前缀和后缀，比如：

+   `confabapp`

+   `goconfabulation`

+   `schmooze time`

1.  这些新词汇流入`coolify`，其中元音可能会被调整：

+   `confabaapp`

+   `goconfabulatioon`

+   `schmoooze time`

1.  修改后的词汇流入`domainify`，在那里它们被转换成有效的域名：

+   `confabaapp.com`

+   `goconfabulatioon.net`

+   `schmooze-time.com`

1.  最后，域名流入`available`，在那里它们被检查是否已经被某人注册了：

+   `confabaapp.com` ×

+   `goconfabulatioon.net` ✔

+   `schmooze-time.com` ✔

## 一款程序统治所有

通过将程序连接在一起来运行我们的解决方案是一种优雅的架构，但它并没有一个非常优雅的界面。具体来说，每当我们想要运行我们的解决方案时，我们都必须输入一个长长的混乱的行，其中每个程序都被列在一起，用管道字符分隔。在本节中，我们将编写一个 Go 程序，使用`os/exec`包来运行每个子程序，同时按照我们的设计将一个程序的输出传递到下一个程序的输入。

在其他五个程序旁边创建一个名为`domainfinder`的新文件夹，并在其中创建另一个名为`lib`的新文件夹。`lib`文件夹是我们将保存子程序构建的地方，但我们不想每次进行更改时都复制和粘贴它们。相反，我们将编写一个脚本，用于构建子程序并将二进制文件复制到`lib`文件夹中。

在 Unix 机器上创建一个名为`build.sh`的新文件，或者在 Windows 上创建一个名为`build.bat`的文件，并插入以下代码：

```go
#!/bin/bash
echo Building domainfinder...
go build -o domainfinder
echo Building synonyms...
cd ../synonyms
go build -o ../domainfinder/lib/synonyms
echo Building available...
cd ../available
go build -o ../domainfinder/lib/available
cd ../build
echo Building sprinkle...
cd ../sprinkle
go build -o ../domainfinder/lib/sprinkle
cd ../build
echo Building coolify...
cd ../coolify
go build -o ../domainfinder/lib/coolify
cd ../build
echo Building domainify...
cd ../domainify
go build -o ../domainfinder/lib/domainify
cd ../build
echo Done.
```

前面的脚本只是构建了我们所有的子程序（包括我们尚未编写的`domainfinder`），告诉`go build`将它们放在我们的`lib`文件夹中。确保通过执行`chmod +x build.sh`或类似的操作赋予新脚本执行权限。从终端运行此脚本，并查看`lib`文件夹，确保它确实将我们的子程序的二进制文件放在那里。

### 提示

现在不要担心`no buildable Go source files`错误，这只是 Go 告诉我们`domainfinder`程序没有任何`.go`文件可供构建。

在`domainfinder`内创建一个名为`main.go`的新文件，并在文件中插入以下代码：

```go
package main
var cmdChain = []*exec.Cmd{
  exec.Command("lib/synonyms"),
  exec.Command("lib/sprinkle"),
  exec.Command("lib/coolify"),
  exec.Command("lib/domainify"),
  exec.Command("lib/available"),
}
func main() {

  cmdChain[0].Stdin = os.Stdin
  cmdChain[len(cmdChain)-1].Stdout = os.Stdout

  for i := 0; i < len(cmdChain)-1; i++ {
    thisCmd := cmdChain[i]
    nextCmd := cmdChain[i+1]
    stdout, err := thisCmd.StdoutPipe()
    if err != nil {
      log.Fatalln(err)
    }
    nextCmd.Stdin = stdout
  }

  for _, cmd := range cmdChain {
    if err := cmd.Start(); err != nil {
      log.Fatalln(err)
    } else {
      defer cmd.Process.Kill()
    }
  }

  for _, cmd := range cmdChain {
    if err := cmd.Wait(); err != nil {
      log.Fatalln(err)
    }
  }

}
```

`os/exec`包为我们提供了一切我们需要从 Go 程序内部运行外部程序或命令的东西。首先，我们的`cmdChain`切片按照我们想要将它们连接在一起的顺序包含了`*exec.Cmd`命令。

在`main`函数的顶部，我们将第一个程序的`Stdin`（标准输入流）绑定到此程序的`os.Stdin`流，将最后一个程序的`Stdout`（标准输出流）绑定到此程序的`os.Stdout`流。这意味着，就像以前一样，我们将通过标准输入流接收输入，并将输出写入标准输出流。

我们的下一个代码块是通过迭代每个项目并将其`Stdin`设置为其前一个程序的`Stdout`来将子程序连接在一起的地方。

以下表格显示了每个程序，以及它从哪里获取输入，以及它的输出去哪里：

| 程序 | 输入（Stdin） | 输出（Stdout） |
| --- | --- | --- |
| `synonyms` | 与`domainfinder`相同的`Stdin` | `sprinkle` |
| `sprinkle` | `synonyms` | `coolify` |
| `coolify` | `sprinkle` | `domainify` |
| `domainify` | `coolify` | `available` |
| `available` | `domainify` | 与`domainfinder`相同的`Stdout` |

然后我们迭代每个命令调用`Start`方法，该方法在后台运行程序（与`Run`方法相反，后者将阻塞我们的代码，直到子程序退出——这当然是不好的，因为我们必须同时运行五个程序）。如果出现任何问题，我们将使用`log.Fatalln`退出，但如果程序成功启动，我们将推迟调用杀死进程。这有助于确保子程序在我们的`main`函数退出时退出，这将是`domainfinder`程序结束时。

一旦所有程序都在运行，我们就会再次迭代每个命令，并等待其完成。这是为了确保`domainfinder`不会提前退出并过早终止所有子程序。

再次运行`build.sh`或`build.bat`脚本，并注意`domainfinder`程序具有与我们之前看到的相同行为，但界面更加优雅。

# 总结

在这一章中，我们学习了五个小的命令行程序如何在组合在一起时产生强大的结果，同时保持模块化。我们避免了紧密耦合我们的程序，因此它们仍然可以单独使用。例如，我们可以使用我们的可用程序来检查手动输入的域名是否可用，或者我们可以将我们的`synonyms`程序仅用作命令行同义词词典。

我们学习了如何使用标准流来构建这些类型的程序的不同流，以及如何重定向标准输入和标准输出让我们非常容易地玩弄不同的流。

我们学习了在 Go 中消耗 JSON RESTful API web 服务是多么简单，当我们需要从 Big Hugh Thesaurus 获取同义词时。一开始我们保持简单，通过内联编码来编写代码，后来重构代码将`Thesaurus`类型抽象成自己的包，可以共享。当我们打开到 WHOIS 服务器的连接并通过原始 TCP 写入数据时，我们还使用了非 HTTP API。

我们看到了`math/rand`包如何通过允许我们在代码中使用伪随机数和决策，为我们带来了一些变化和不可预测性，这意味着每次运行程序时，我们都会得到不同的结果。

最后，我们构建了我们的`domainfinder`超级程序，将所有子程序组合在一起，为我们的解决方案提供了简单、干净和优雅的界面。


# 第五章：构建分布式系统并使用灵活数据

在本章中，我们将探讨可转移的技能，使我们能够使用无模式数据和分布式技术来解决大数据问题。本章中我们将构建的系统将为我们准备一个未来，在那里民主选举都将在线进行——当然是在 Twitter 上。我们的解决方案将通过查询 Twitter 的流 API 来收集和计算投票特定标签的提及，并且每个组件都能够水平扩展以满足需求。我们的用例是有趣而有趣的，但我们将学习的核心概念和我们将做出的具体技术选择是本章的真正重点。这里讨论的思想直接适用于任何需要真正规模能力的系统。

### 注意

水平扩展是指向系统添加节点，如物理机器，以改善其可用性、性能和/或容量。谷歌等大数据公司可以通过添加廉价且易获得的硬件（通常称为商品硬件）来扩展，因为他们编写软件和设计解决方案的方式。垂直扩展意味着增加单个节点的可用资源，例如向盒子添加额外的 RAM，或者具有更多内核的处理器。

在本章中，您将：

+   了解分布式 NoSQL 数据存储；特别是如何与 MongoDB 交互

+   了解分布式消息队列；特别是 Bit.ly 的 NSQ 以及如何使用`go-nsq`包轻松发布和订阅事件

+   通过 Twitter 的流 API 流式传输实时推文数据并管理长时间运行的网络连接

+   学习如何正确停止具有许多内部 goroutine 的程序

+   学习如何使用低内存通道进行信令

# 系统设计

有一个基本的设计草图通常是有用的，特别是在分布式系统中，许多组件将以不同的方式相互通信。我们不希望在这个阶段花费太长时间，因为我们的设计可能会随着我们深入细节而发展，但我们将看一下高层次的概述，以便我们可以讨论组成部分以及它们如何相互配合。

![系统设计](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-prog-bp/img/Image00011.jpg)

前面的图片显示了我们将要构建的系统的基本概述：

+   Twitter 是我们都熟悉和喜爱的社交媒体网络。

+   Twitter 的流 API 允许长时间运行的连接，其中推文数据尽可能快地流式传输。

+   `twittervotes`是我们将编写的一个程序，它读取推文并将投票推送到消息队列中。`twittervotes`获取相关的推文数据，找出正在投票的内容（或者说，提到了哪些选项），并将投票推送到 NSQ 中。

+   NSQ 是一个开源的、实时的分布式消息平台，旨在大规模运行，由 Bit.ly 构建和维护。NSQ 在其实例之间传递消息，使其对任何对选举数据表示兴趣的人都可用。

+   `counter`是我们将编写的一个程序，它监听消息队列上的投票，并定期将结果保存在 MongoDB 数据库中。`counter`从 NSQ 接收投票消息，并在内存中定期计算结果，定期推送更新以持久化数据。

+   MongoDB 是一个设计用于大规模运行的开源文档数据库。

+   `web`是一个 Web 服务器程序，将在下一章中公开我们将编写的实时结果。

可以说，可以编写一个单个的 Go 程序来读取推文，计算投票并将它们推送到用户界面，但是这样的解决方案，虽然是一个很好的概念验证，但在规模上非常有限。在我们的设计中，任何一个组件都可以在特定能力的需求增加时进行水平扩展。如果我们有相对较少的投票，但有很多人查看数据，我们可以保持`twittervotes`和`counter`实例不变，并添加更多的`web`和 MongoDB 节点，或者反之亦然。

我们设计的另一个关键优势是冗余；因为我们可以同时拥有许多组件的实例在工作，如果其中一个箱子消失了（例如由于系统崩溃或断电），其他箱子可以接管工作。现代架构通常会将这样的系统分布在地理范围内，以防止本地自然灾害。如果我们以这种方式构建我们的解决方案，所有这些选项都是可用的。

我们选择本章中的特定技术，是因为它们与 Go 的关联（例如，NSQ 完全使用 Go 编写），以及有经过充分测试的驱动程序和软件包可用。然而，从概念上讲，您可以根据需要选择各种替代方案。

## 数据库设计

我们将称我们的 MongoDB 数据库为`ballots`。它将包含一个名为`polls`的单个集合，这是我们将存储投票详细信息的地方，例如标题、选项和结果（在一个 JSON 文档中）。投票的代码将如下所示：

```go
{
  "_id": "???",
  "title": "Poll title",
  "options": ["one", "two", "three"],
  "results": {
    "one": 100,
    "two": 200,
    "three": 300
  }
}
```

`_id`字段是由 MongoDB 自动生成的，将是我们标识每个投票的方式。`options`字段包含一个字符串选项数组；这些是我们将在 Twitter 上寻找的标签。`results`字段是一个映射，其中键表示选项，值表示每个项目的总投票数。

# 安装环境

我们在本章中编写的代码具有真正的外部依赖关系，我们需要在开始构建系统之前设置这些依赖关系。

### 提示

如果您在安装任何依赖项时遇到困难，请务必查看[`github.com/matryer/goblueprints`](https://github.com/matryer/goblueprints)上的章节注释。

在大多数情况下，诸如`mongod`和`nsqd`之类的服务在我们运行程序之前必须启动。由于我们正在编写分布式系统的组件，我们将不得不同时运行每个程序，这就像打开许多终端窗口一样简单。

## NSQ

NSQ 是一个消息队列，允许一个程序向另一个程序发送消息或事件，或者向通过网络连接的不同节点上运行的许多其他程序发送消息。NSQ 保证消息的传递，这意味着它会将未传递的消息缓存，直到所有感兴趣的方收到它们。这意味着，即使我们停止`counter`程序，我们也不会错过任何投票。您可以将此功能与“发送并忘记”消息队列进行对比，其中信息被视为过时，因此如果在规定时间内未传递，则被遗忘，并且发送消息的人不关心消费者是否收到它们。

消息队列抽象允许您在不同的位置运行系统的不同组件，只要它们与队列有网络连接。您的程序与其他程序解耦；相反，您的设计开始关心专门的微服务的细节，而不是数据通过单片程序的流动。

NSQ 传输原始字节，这意味着我们可以自行决定如何将数据编码为这些字节。例如，根据我们的需求，我们可以将数据编码为 JSON 或二进制格式。在我们的情况下，我们将投票选项作为字符串发送，而不需要任何额外的编码，因为我们只共享一个数据字段。

在浏览器中打开[`nsq.io/deployment/installing.html`](http://nsq.io/deployment/installing.html)（或搜索`install nsq`）并按照您的环境的说明进行操作。您可以下载预编译的二进制文件，也可以从源代码构建自己的。如果您已经安装了 homebrew，安装 NSQ 就像输入以下命令一样简单：

```go

brew install nsq

```

安装 NSQ 后，您需要将`bin`文件夹添加到您的`PATH`环境变量中，以便在终端中使用这些工具。

为了验证 NSQ 是否正确安装，打开一个终端并运行`nsqlookupd`；如果程序成功启动，您应该会看到类似以下的一些输出：

```go

nsqlookupd v0.2.27 (built w/go1.3)

TCP: listening on [::]:4160

HTTP: listening on [::]:4161

```

我们将使用默认端口与 NSQ 进行交互，所以请注意输出中列出的 TCP 和 HTTP 端口，因为我们将在我们的代码中引用它们。

按下*Ctrl* + *C*暂停进程；稍后我们会正确启动它们。

我们将使用 NSQ 安装中的关键工具`nsqlookupd`和`nsqd`。`nsqlookupd`程序是一个管理分布式 NSQ 环境的拓扑信息的守护进程；它跟踪特定主题的所有`nsqd`生产者，并为客户端提供查询此类信息的接口。`nsqd`程序是一个守护进程，负责 NSQ 的重要工作，如接收、排队和传递来自和到感兴趣的各方的消息。有关 NSQ 的更多信息和背景，请访问[`nsq.io/`](http://nsq.io/)。

### Go 的 NSQ 驱动程序

NSQ 工具本身是用 Go 编写的，因此 Bit.ly 团队已经有一个使与 NSQ 交互非常容易的 Go 包。我们需要使用它，所以在终端中使用`go get`获取它：

```go

go get github.com/bitly/go-nsq

```

## MongoDB

MongoDB 是一个文档数据库，基本上允许您存储和查询 JSON 文档及其中的数据。每个文档都进入一个集合，可以用来将文档组合在一起，而不对其中的数据强制执行任何模式。与传统的 Oracle、Microsoft SQL Server 或 MySQL 中的行不同，文档可以具有不同的结构是完全可以接受的。例如，一个`people`集合可以同时包含以下三个 JSON 文档：

```go
{"name":"Mat","lang":"en","points":57}
{"name":"Laurie","position":"Scrum Master"}
{"position":"Traditional Manager","exists":false}
```

这种灵活性使得具有不同结构的数据可以共存，而不会影响性能或浪费空间。如果您期望软件随着时间的推移而发展，这也非常有用，因为我们确实应该这样做。

MongoDB 被设计为可以扩展，同时在单机安装上也非常易于操作，比如我们的开发机。当我们将应用程序托管到生产环境时，我们可能会安装一个更复杂的多分片、复制系统，分布在许多节点和位置，但现在，只需运行`mongod`即可。

前往[`www.mongodb.org/downloads`](http://www.mongodb.org/downloads)下载最新版本的 MongoDB 并安装它，确保像往常一样将`bin`文件夹注册到您的`PATH`环境变量中。

为了验证 MongoDB 是否成功安装，运行`mongod`命令，然后按下*Ctrl* + *C*暂停它。

### Go 的 MongoDB 驱动程序

Gustavo Niemeyer 通过他在[`labix.org/mgo`](http://labix.org/mgo)托管的`mgo`（发音为"mango"）包，大大简化了与 MongoDB 的交互，这个包是可以通过以下命令*go gettable*的：

```go

go get gopkg.in/mgo.v2

```

## 启动环境

现在我们已经安装了所有需要的部件，我们需要启动我们的环境。在本节中，我们将：

+   启动`nsqlookupd`以便我们的`nsqd`实例可以被发现

+   启动`nsqd`并告诉它要使用哪个`nsqlookupd`

+   启动`mongod`进行数据服务

这些守护进程中的每一个都应该在自己的终端窗口中运行，这样我们就可以通过按下*Ctrl* + *C*来轻松停止它们。

### 提示

记住这一节的页码，因为在您阅读本章时，您可能会多次回顾它。

在一个终端窗口中运行：

```go

nsqlookupd

```

注意 TCP 端口，默认为`4160`，然后在另一个终端窗口中运行：

```go

nsqd --lookupd-tcp-address=localhost:4160

```

确保`--lookupd-tcp-address`标志中的端口号与`nsqlookupd`实例的 TCP 端口匹配。一旦启动`nsqd`，您将注意到一些输出会从`nsqlookupd`和`nsqd`的终端打印出来；这表明这两个进程正在互相通信。

在另一个窗口或选项卡中，通过运行启动 MongoDB：

```go

mongod --dbpath ./db

```

`dbpath`标志告诉 MongoDB 在哪里存储我们数据库的数据文件。您可以选择任何位置，但在`mongod`运行之前，您必须确保文件夹存在。

### 提示

通过随时删除`dbpath`文件夹，您可以有效地擦除所有数据并重新开始。这在开发过程中特别有用。

现在我们的环境已经运行，我们准备开始构建我们的组件。

# 来自 Twitter 的投票

在`$GOPATH/src`文件夹中，与其他项目一起，为本章创建一个名为`socialpoll`的新文件夹。该文件夹本身不是 Go 包或程序，但将包含我们的三个组件程序。在`socialpoll`中，创建一个名为`twittervotes`的新文件夹，并添加必需的`main.go`模板（这很重要，因为没有`main`函数的`main`包将无法编译）：

```go
package main
func main(){}
```

我们的`twittervotes`程序将：

+   使用`mgo`从 MongoDB 数据库加载所有投票，并从每个文档的`options`数组中收集所有选项。

+   打开并保持与 Twitter 的流 API 的连接，寻找任何提及选项的内容。

+   对于与筛选器匹配的每条推文，找出提到的选项，并将该选项推送到 NSQ。

+   如果与 Twitter 的连接中断（这在长时间运行的连接中很常见，因为它实际上是 Twitter 的流 API 规范的一部分），则在短暂延迟后（以便我们不会用连接请求轰炸 Twitter），重新连接并继续。

+   定期重新查询 MongoDB 以获取最新的投票，并刷新与 Twitter 的连接，以确保我们始终关注正确的选项。

+   当用户通过按*Ctrl* + *C*终止程序时，它将自动停止。

## 与 Twitter 进行授权。

为了使用流 API，我们将需要从 Twitter 的应用程序管理控制台获取身份验证凭据，就像我们在第三章中为我们的 Gomniauth 服务提供者所做的那样，*实现个人资料图片的三种方法*。转到[`apps.twitter.com`](https://apps.twitter.com)并创建一个名为`SocialPoll`的新应用程序（名称必须是唯一的，因此您可以在这里玩得很开心；名称的选择不会影响代码）。创建应用程序后，访问**API 密钥**选项卡，并找到**您的访问令牌**部分，在那里您需要创建一个新的访问令牌。短暂延迟后，刷新页面并注意到您实际上有两组密钥和秘钥；一个 API 密钥和秘钥，以及一个访问令牌和相应的秘密。遵循良好的编码实践，我们将这些值设置为环境变量，以便我们的程序可以访问它们，而无需在源文件中硬编码它们。

本章中我们将使用的密钥是：

+   `SP_TWITTER_KEY`

+   `SP_TWITTER_SECRET`

+   `SP_TWITTER_ACCESSTOKEN`

+   `SP_TWITTER_ACCESSSECRET`

您可以根据需要设置环境变量，但由于应用程序依赖于它们才能工作，因此创建一个名为`setup.sh`（对于 bash shell）或`setup.bat`（在 Windows 上）的新文件是一个好主意，因为您可以将这些文件检入到源代码存储库中。通过从 Twitter 应用程序页面复制相应的值将以下代码插入`setup.sh`或`setup.bat`中：

```go
#!/bin/bash
export SP_TWITTER_KEY=yCwwKKnuBnUBrelyTN...
export SP_TWITTER_SECRET=6on0YRYniT1sI3f...
export SP_TWITTER_ACCESSTOKEN=2427-13677...
export SP_TWITTER_ACCESSSECRET=SpnZf336u...
```

运行文件并使用源或调用命令来适当设置值，或将它们添加到您的`.bashrc`或`C:\cmdauto.cmd`文件中，以节省每次打开新终端窗口时运行它们的时间。

### 提取连接

Twitter 流 API 支持保持长时间打开的 HTTP 连接，并且考虑到我们解决方案的设计，我们需要从请求发生的 goroutine 之外访问`net.Conn`对象以关闭它。我们可以通过为我们将创建的`http.Transport`对象提供自己的`dial`方法来实现这一点。

在`twittervotes`（所有与 Twitter 相关的内容都将驻留在此处）中创建一个名为`twitter.go`的新文件，并插入以下代码：

```go
var conn net.Conn
func dial(netw, addr string) (net.Conn, error) {
  if conn != nil {
    conn.Close()
    conn = nil
  }
  netc, err := net.DialTimeout(netw, addr, 5*time.Second)
  if err != nil {
    return nil, err
  }
  conn = netc
  return netc, nil
}
```

我们定制的`dial`函数首先确保关闭`conn`，然后打开一个新连接，保持`conn`变量更新为当前连接。如果连接中断（Twitter 的 API 偶尔会这样做）或被我们关闭，我们可以重新拨号，而不必担心僵尸连接。

我们将定期关闭连接并启动新连接，因为我们希望定期从数据库重新加载选项。为此，我们需要一个关闭连接的函数，并且还需要关闭我们将用于读取响应主体的`io.ReadCloser`。将以下代码添加到`twitter.go`中：

```go
var reader io.ReadCloser
func closeConn() {
  if conn != nil {
    conn.Close()
  }
  if reader != nil {
    reader.Close()
  }
}
```

现在我们可以随时调用`closeConn`来中断与 Twitter 的持续连接并整理事情。在大多数情况下，我们的代码将再次从数据库加载选项并立即打开新连接，但如果我们正在关闭程序（响应*Ctrl* + *C*按键），那么我们可以在退出之前调用`closeConn`。

### 读取环境变量

接下来，我们将编写一个函数，该函数将读取环境变量并设置我们需要验证请求的`OAuth`对象。在`twitter.go`文件中添加以下代码：

```go
var (
  authClient *oauth.Client
  creds *oauth.Credentials
)
func setupTwitterAuth() {
  var ts struct {
    ConsumerKey    string `env:"SP_TWITTER_KEY,required"`
    ConsumerSecret string `env:"SP_TWITTER_SECRET,required"`
    AccessToken    string `env:"SP_TWITTER_ACCESSTOKEN,required"`
    AccessSecret   string `env:"SP_TWITTER_ACCESSSECRET,required"`
  }
  if err := envdecode.Decode(&ts); err != nil {
    log.Fatalln(err)
  }
  creds = &oauth.Credentials{
    Token:  ts.AccessToken,
    Secret: ts.AccessSecret,
  }
  authClient = &oauth.Client{
    Credentials: oauth.Credentials{
      Token:  ts.ConsumerKey,
      Secret: ts.ConsumerSecret,
    },
  }
}
```

在这里，我们定义了一个`struct`类型来存储我们需要用来验证 Twitter 的环境变量。由于我们不需要在其他地方使用这种类型，我们内联定义它，并创建一个名为`ts`的变量，它是这种匿名类型（这就是为什么我们有了有些不寻常的`var ts struct…`代码）。然后我们使用 Joe Shaw 优雅的`envdecode`包来为我们拉取这些环境变量。您需要运行`go get github.com/joeshaw/envdecode`，并且还要导入`log`包。我们的程序将尝试为所有标记为`required`的字段加载适当的值，并在失败时返回错误，提醒人们如果没有 Twitter 凭据，程序将无法工作。

在`struct`中每个字段旁边的反引号内的字符串称为标签，并且可以通过反射接口获得，这就是`envdecode`知道要查找哪些变量的方式。Tyler Bunnell 和我为这个包添加了 required 参数，这表明如果缺少（或为空）任何环境变量都是错误的。

一旦我们获得了密钥，我们将使用它们来创建`oauth.Credentials`和`oauth.Client`对象，这些对象来自 Gary Burd 的`go-oauth`包，它将允许我们使用 Twitter 进行授权请求。

现在我们有了控制底层连接和授权请求的能力，我们准备编写实际构建授权请求并返回响应的代码。在`twitter.go`中，添加以下代码：

```go
var (
  authSetupOnce sync.Once
  httpClient    *http.Client
)
func makeRequest(req *http.Request, params url.Values) (*http.Response, error) {
  authSetupOnce.Do(func() {
    setupTwitterAuth()
    httpClient = &http.Client{
      Transport: &http.Transport{
        Dial: dial,
      },
    }
  })
  formEnc := params.Encode()
  req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
  req.Header.Set("Content-Length", strconv.Itoa(len(formEnc)))
  req.Header.Set("Authorization", authClient.AuthorizationHeader(creds, "POST", req.URL, params))
  return httpClient.Do(req)
}
```

我们使用`sync.Once`来确保我们的初始化代码只运行一次，尽管我们调用`makeRequest`的次数有多少。在调用`setupTwitterAuth`方法之后，我们使用`http.Transport`创建一个新的`http.Client`，该`http.Transport`使用我们自定义的`dial`方法。然后，我们通过对包含我们要查询的选项的指定`params`对象进行编码，设置与 Twitter 授权所需的适当标头。

## 从 MongoDB 读取

为了加载投票，并因此搜索 Twitter 的选项，我们需要连接并查询 MongoDB。在`main.go`中，添加两个函数`dialdb`和`closedb`：

```go
var db *mgo.Session
func dialdb() error {
  var err error
  log.Println("dialing mongodb: localhost")
  db, err = mgo.Dial("localhost")
  return err
}
func closedb() {
  db.Close()
  log.Println("closed database connection")
}
```

这两个函数将使用`mgo`包连接到本地运行的 MongoDB 实例，并将`mgo.Session`（数据库连接对象）存储在名为`db`的全局变量中，并从中断开连接。

### 提示

作为额外的任务，看看是否可以找到一种优雅的方式来使 MongoDB 实例的位置可配置，以便您不需要在本地运行它。

假设 MongoDB 正在运行并且我们的代码能够连接，我们需要加载投票对象并从文档中提取所有选项，然后我们将使用这些选项来搜索 Twitter。将以下`Options`函数添加到`main.go`中：

```go
type poll struct {
  Options []string
}
func loadOptions() ([]string, error) {
  var options []string
  iter := db.DB("ballots").C("polls").Find(nil).Iter()
  var p poll
  for iter.Next(&p) {
    options = append(options, p.Options...)
  }
  iter.Close()
  return options, iter.Err()
}
```

我们的投票文档包含的不仅仅是`Options`，但我们的程序不关心其他任何内容，因此我们不需要膨胀我们的`poll`结构。我们使用`db`变量访问`ballots`数据库中的`polls`集合，并调用`mgo`包的流畅`Find`方法，传递`nil`（表示没有过滤）。

### 注意

流畅接口（由 Eric Evans 和 Martin Fowler 首次创造）是指旨在通过允许您链接方法调用来使代码更可读的 API 设计。这是通过每个方法返回上下文对象本身来实现的，以便可以直接调用另一个方法。例如，`mgo`允许您编写诸如此类的查询：

```go
query := col.Find(q).Sort("field").Limit(10).Skip(10)
```

然后我们通过调用`Iter`方法获得迭代器，这允许我们逐个访问每个投票。这是一种非常节省内存的读取投票数据的方式，因为它只使用一个`poll`对象。如果我们使用`All`方法，我们将使用的内存量取决于我们在数据库中拥有的投票数量，这将超出我们的控制。

当我们有一个投票时，我们使用`append`方法来构建选项切片。当然，随着数据库中有数百万个投票，这个切片也会变得庞大而难以控制。对于这种规模，我们可能会运行多个`twittervotes`程序，每个程序专门用于一部分投票数据。一个简单的方法是根据标题的首字母将投票分成组，例如 A-N 组和 O-Z 组。一个更复杂的方法是向`poll`文档添加一个字段，以更受控制的方式对其进行分组，也许是基于其他组的统计数据，以便我们能够在许多`twittervotes`实例之间平衡负载。

### 提示

`append`内置函数实际上是一个`variadic`函数，这意味着您可以为其附加多个元素。如果您有正确类型的切片，可以在末尾添加`...`，这模拟了将切片的每个项目作为不同参数传递。

最后，我们关闭迭代器并清理任何使用的内存，然后返回选项和在迭代过程中发生的任何错误（通过在`mgo.Iter`对象上调用`Err`方法）。

## 从 Twitter 阅读

现在我们能够加载选项并向 Twitter API 发出授权请求。因此，我们准备编写启动连接的代码，并持续从流中读取，直到我们调用我们的`closeConn`方法，或者 Twitter 因某种原因关闭连接。流中包含的结构是一个复杂的结构，包含有关推文的各种信息-谁发表了它以及何时，甚至在正文中出现了哪些链接或用户提及（有关更多详细信息，请参阅 Twitter 的 API 文档）。但是，我们只对推文文本本身感兴趣，因此您无需担心所有其他噪音；将以下结构添加到`twitter.go`中：

```go
type tweet struct {
  Text string
}
```

### 提示

这可能感觉不完整，但请考虑它如何清晰地表达了我们对其他程序员可能看到我们的代码的意图：推文有一些文本，这就是我们关心的全部。

使用这种新结构，在`twitter.go`中添加以下`readFromTwitter`函数，该函数接收一个名为`votes`的只发送通道；这是该函数通知程序的其余部分它已经在 Twitter 上注意到了一次投票的方式：

```go
func readFromTwitter(votes chan<- string) {
  options, err := loadOptions()
  if err != nil {
    log.Println("failed to load options:", err)
    return
  }
  u, err := url.Parse("https://stream.twitter.com/1.1/statuses/filter.json")
  if err != nil {
    log.Println("creating filter request failed:", err)
    return
  }
  query := make(url.Values)
  query.Set("track", strings.Join(options, ","))
  req, err := http.NewRequest("POST", u.String(), strings.NewReader(query.Encode()))
  if err != nil {
    log.Println("creating filter request failed:", err)
    return
  }
  resp, err := makeRequest(req, query)
  if err != nil {
    log.Println("making request failed:", err)
    return
  }
  reader := resp.Body
  decoder := json.NewDecoder(reader)
  for {
    var tweet tweet
    if err := decoder.Decode(&tweet); err != nil {
      break
    }
    for _, option := range options {
      if strings.Contains(
        strings.ToLower(tweet.Text),
        strings.ToLower(option),
      ) {
        log.Println("vote:", option)
        votes <- option
      }
    }
  }
}
```

在上述代码中，加载所有投票数据的选项（通过调用`loadOptions`函数）后，我们使用`url.Parse`创建一个描述 Twitter 上适当端点的`url.URL`对象。我们构建一个名为`query`的`url.Values`对象，并将选项设置为逗号分隔的列表。根据 API，我们使用编码后的`url.Values`对象作为主体发出新的`POST`请求，并将其与查询对象一起传递给`makeRequest`。如果一切顺利，我们将从请求的主体中创建一个新的`json.Decoder`，并通过调用`Decode`方法在无限的`for`循环中不断读取。如果出现错误（可能是由于连接关闭），我们简单地中断循环并退出函数。如果有要读取的推文，它将被解码为`tweet`变量，这将使我们可以访问`Text`属性（推文本身的 140 个字符）。然后，我们遍历所有可能的选项，如果推文提到了它，我们就在`votes`通道上发送它。这种技术还允许一个推文同时包含许多投票，这取决于选举规则，您可能会决定是否更改。

### 注意

`votes`通道是**只发送**的（这意味着我们不能在其上接收），因为它的类型是`chan<- string`。想象一下小箭头告诉我们消息流向的方式：要么进入通道，要么离开通道。这是一种表达意图的好方法——很明显，我们从不打算使用`readFromTwitter`函数来读取投票；相反，我们只会在该通道上发送它们。

每当`Decode`返回错误时终止程序并不提供一个非常健壮的解决方案。这是因为 Twitter API 文档规定连接会不时中断，客户端在消费服务时应考虑到这一点。而且请记住，我们也会定期终止连接，所以我们需要考虑一种在连接中断后重新连接的方法。

### 信号通道

在 Go 中使用通道的一个很好的用途是在不同 goroutine 中运行的代码之间发出信号事件。当我们编写下一个函数时，我们将看到一个真实世界的例子。

该函数的目的是启动一个 goroutine，不断调用`readFromTwitter`函数（使用指定的`votes`通道接收投票），直到我们发出停止信号。一旦它停止，我们希望通过另一个信号通道得到通知。函数的返回值将是一个`struct{}`类型的通道；一个信号通道。

信号通道具有一些有趣的特性值得仔细研究。首先，通过通道发送的类型是一个空的`struct{}`，实际上不占用任何字节，因为它没有字段。因此，`struct{}{}`是一个用于信号事件的内存高效选项。有些人使用`bool`类型，这也可以，尽管`true`和`false`都占用一个字节的内存。

### 注意

前往[`play.golang.org`](http://play.golang.org)并自己尝试一下。

布尔类型的大小为 1：

```go
fmt.Println(reflect.TypeOf(true).Size())
= 1
```

结构体`struct{}{}`的大小为`0`：

```go
fmt.Println(reflect.TypeOf(struct{}{}).Size())
= 0
```

信号通道还具有缓冲区大小为 1，这意味着执行不会阻塞，直到有东西从通道中读取信号。

我们将在我们的代码中使用两个信号通道，一个是我们传递给函数的，告诉我们的 goroutine 它应该停止，另一个是函数提供的，一旦停止完成就发出信号。

在`twitter.go`中添加以下函数：

```go
func startTwitterStream(stopchan <-chan struct{}, votes chan<- string) <-chan struct{} {
  stoppedchan := make(chan struct{}, 1)
  go func() {
    defer func() {
      stoppedchan <- struct{}{}
    }()
    for {
      select {
      case <-stopchan:
        log.Println("stopping Twitter...")
        return
      default:
        log.Println("Querying Twitter...")
        readFromTwitter(votes)
        log.Println("  (waiting)")
        time.Sleep(10 * time.Second) // wait before reconnecting
      }
    }
  }()
  return stoppedchan
}
```

在上述代码中，第一个参数`stopchan`是一个类型为`<-chan struct{}`的通道，一个**只接收**的信号通道。在代码外部，将在此通道上发出信号，这将告诉我们的 goroutine 停止。请记住，在此函数内部它是只接收的，实际通道本身将能够发送。第二个参数是`votes`通道，用于发送投票。我们函数的返回类型也是一个类型为`<-chan struct{}`的信号通道；一个只接收的通道，我们将用它来指示我们已经停止。

这些通道是必要的，因为我们的函数会触发自己的 goroutine，并立即返回，所以没有这些，调用代码将不知道生成的代码是否仍在运行。

在`startTwitterStream`函数中，我们首先创建了`stoppedchan`，并延迟发送`struct{}{}`以指示我们的函数退出时已经完成。请注意，`stoppedchan`是一个普通通道，因此即使它作为只接收返回，我们也可以在此函数内部发送它。

然后我们开始一个无限的`for`循环，在其中我们从两个通道中选择一个。第一个是`stopchan`（第一个参数），这将表明是时候停止并返回（从而触发`stoppedchan`上的延迟信号）。如果还没有发生这种情况，我们将调用`readFromTwitter`（传入`votes`通道），它将从数据库中加载选项并打开到 Twitter 的连接。

当 Twitter 连接断开时，我们的代码将返回到这里，在这里我们使用`time.Sleep`函数睡眠十秒。这是为了让 Twitter API 休息一下，以防它由于过度使用而关闭连接。一旦休息过后，我们重新进入循环，并再次检查`stopchan`通道，看看调用代码是否希望我们停止。

为了使这个流程清晰，我们记录了一些关键语句，这些语句不仅有助于我们调试代码，还让我们窥视这个有些复杂的机制的内部工作。

## 发布到 NSQ

一旦我们的代码成功地注意到 Twitter 上的投票并将它们发送到`votes`通道中，我们需要一种方法将它们发布到 NSQ 主题；毕竟，这是`twittervotes`程序的目的。

我们将编写一个名为`publishVotes`的函数，它将接收类型为`<-chan string`（只接收通道）的`votes`通道，并发布从中接收到的每个字符串。

### 注意

在我们之前的函数中，`votes`通道的类型是`chan<- string`，但这次它的类型是`<-chan string`。您可能会认为这是一个错误，甚至认为这意味着我们不能同时使用同一个通道，但您是错误的。我们稍后创建的通道将使用`make(chan string)`，既不是接收也不是发送，可以在两种情况下都起作用。在参数中使用`<-`运算符的原因是为了明确通道的使用意图；或者在它是返回类型的情况下，防止用户意外地在预期用于接收或发送的通道上发送。如果用户错误地使用这样的通道，编译器实际上会产生错误。

一旦`votes`通道关闭（这是外部代码告诉我们的函数停止工作的方式），我们将停止发布并向返回的停止信号通道发送信号。

将`publishVotes`函数添加到`main.go`：

```go
func publishVotes(votes <-chan string) <-chan struct{} {
  stopchan := make(chan struct{}, 1)
  pub, _ := nsq.NewProducer("localhost:4150", nsq.NewConfig())
  go func() {
    for vote := range votes {
      pub.Publish("votes", []byte(vote)) // publish vote
    }
    log.Println("Publisher: Stopping")
    pub.Stop()
    log.Println("Publisher: Stopped")
    stopchan <- struct{}{}
  }()
  return stopchan
}
```

我们做的第一件事是创建`stopchan`，然后将其返回，这次不是延迟发送信号，而是通过向`stopchan`发送`struct{}{}`来内联执行。

### 注意

不同之处在于显示备选选项：在一个代码库中，您应该选择自己喜欢的风格并坚持下去，直到社区内出现一个标准；在这种情况下，我们都应该遵循这个标准。

然后我们通过调用`NewProducer`创建一个 NSQ 生产者，并连接到`localhost`上的默认 NSQ 端口，使用默认配置。我们启动一个 goroutine，它使用 Go 语言的另一个很棒的内置功能，让我们可以通过在通道上执行正常的`for…range`操作来不断地从通道中拉取值（在我们的情况下是`votes`通道）。每当通道没有值时，执行将被阻塞，直到有值传送过来。如果`votes`通道被关闭，`for`循环将退出。

### 提示

要了解 Go 语言中通道的强大之处，强烈建议您查找 John Graham-Cumming 的博客文章和视频，特别是他在 2014 年 Gophercon 上介绍的*通道概览*，其中包含了通道的简要历史，包括它们的起源。（有趣的是，John 还成功地请求英国政府正式为对待 Alan Turing 的方式道歉。）

当循环退出（在`votes`通道关闭后），发布者将停止，随后发送`stopchan`信号。

## 优雅地启动和停止

当我们的程序被终止时，我们希望在实际退出之前做一些事情；即关闭与 Twitter 的连接并停止 NSQ 发布者（实际上是取消其对队列的兴趣）。为了实现这一点，我们必须覆盖默认的*Ctrl + C*行为。

### 提示

即将到来的代码块都在`main`函数内部；它们被分开，以便我们在继续之前讨论每个部分。

在`main`函数内添加以下代码：

```go
var stoplock sync.Mutex
stop := false
stopChan := make(chan struct{}, 1)
signalChan := make(chan os.Signal, 1)
go func() { 
  <-signalChan
  stoplock.Lock()
  stop = true
  stoplock.Unlock()
  log.Println("Stopping...")
  stopChan <- struct{}{}
  closeConn()
}()
signal.Notify(signalChan, syscall.SIGINT, syscall.SIGTERM)
```

在这里，我们创建了一个带有关联`sync.Mutex`的停止`bool`，以便我们可以同时从许多 goroutine 中访问它。然后我们创建了另外两个信号通道，`stopChan`和`signalChan`，并使用`signal.Notify`要求 Go 在有人尝试终止程序时将信号发送到`signalChan`（无论是使用`SIGINT`中断还是`SIGTERM`终止 POSIX 信号）。`stopChan`是我们指示要终止进程的方式，我们将其作为参数传递给`startTwitterStream`。

然后我们运行一个 goroutine，通过尝试从`signalChan`读取来阻塞等待信号；这就是这种情况下`<-`操作符的作用（它正在尝试从通道中读取）。由于我们不关心信号的类型，因此我们不需要捕获通道上返回的对象。一旦收到信号，我们将`stop`设置为`true`，并关闭连接。只有在发送了指定的信号之一后，才会运行剩余的 goroutine 代码，这就是我们能够在退出程序之前执行拆卸代码的方式。

在`main`函数内添加以下代码片段，以打开并延迟关闭数据库连接：

```go
if err := dialdb(); err != nil {
  log.Fatalln("failed to dial MongoDB:", err)
}
defer closedb()
```

由于`readFromTwitter`方法每次都会从数据库重新加载选项，并且我们希望在无需重新启动程序的情况下保持程序更新，因此我们将引入最后一个 goroutine。这个 goroutine 将每分钟调用`closeConn`，导致连接断开，并导致`readFromTwitter`再次被调用。在`main`函数的底部插入以下代码，以启动所有这些进程，然后等待它们优雅地停止：

```go
// start things
votes := make(chan string) // chan for votes
publisherStoppedChan := publishVotes(votes)
twitterStoppedChan := startTwitterStream(stopChan, votes)
go func() {
  for {
    time.Sleep(1 * time.Minute)
    closeConn()
    stoplock.Lock()
    if stop {
      stoplock.Unlock()
      break
    }
    stoplock.Unlock()
  }
}()
<-twitterStoppedChan
close(votes)
<-publisherStoppedChan
```

首先，我们创建了我们在本节中一直在谈论的`votes`通道，它是一个简单的字符串通道。请注意，它既不是发送（`chan<-`）也不是接收（`<-chan`）通道；实际上，创建这样的通道没有多大意义。然后我们调用`publishVotes`，将`votes`通道传递给它进行接收，并将返回的停止信号通道捕获为`publisherStoppedChan`。类似地，我们调用`startTwitterStream`，传入我们在`main`函数开头的`stopChan`，以及`votes`通道进行发送，并捕获生成的停止信号通道为`twitterStoppedChan`。

然后我们启动刷新 goroutine，它立即进入无限的`for`循环，然后睡眠一分钟并通过调用`closeConn`关闭连接。如果停止`bool`已经设置为 true（在之前的 goroutine 中），我们将`break`循环并退出，否则我们将继续循环并等待另一分钟再次关闭连接。使用`stoplock`是重要的，因为我们有两个 goroutine 可能同时尝试访问停止变量，但我们希望避免冲突。

一旦 goroutine 启动，我们就会在`twitterStoppedChan`上阻塞，尝试从中读取。当成功时（这意味着在`stopChan`上发送了信号），我们关闭`votes`通道，这将导致发布者的`for…range`循环退出，并且发布者本身停止，之后会在`publisherStoppedChan`上发送信号，我们等待后退出。

## 测试

为了确保我们的程序正常工作，我们需要做两件事：首先，我们需要在数据库中创建一个投票，其次，我们需要查看消息队列，看看消息是否确实由`twittervotes`生成。

在终端中，运行`mongo`命令打开一个数据库 shell，允许我们与 MongoDB 交互。然后输入以下命令添加一个测试投票：

```go

> use ballots

switched to db ballots

> db.polls.insert({"title":"Test poll","options":["happy","sad","fail","win"]})

```

前面的命令向`ballots`数据库的`polls`集合中添加了一个新项目。我们使用一些常见的选项词，这些选项可能会被 Twitter 上的人提到，以便我们可以观察到真实的推文被翻译成消息。您可能会注意到我们的投票对象缺少`results`字段；这没关系，因为我们处理的是非结构化数据，文档不必遵循严格的模式。我们将在下一节中编写的`counter`程序稍后为我们添加和维护`results`数据。

按下*Ctrl + C*退出 MongoDB shell，并输入以下命令：

```go

nsq_tail --topic="votes" --lookupd-http-address=localhost:4161

```

`nsq_tail`工具连接到指定的消息队列主题，并输出它注意到的任何消息。这是我们验证我们的`twittervotes`程序是否正在发送消息的地方。

在一个单独的终端窗口中，让我们构建并运行`twittervotes`程序：

```go

go build –o twittervotes

./twittervotes

```

现在切换回运行`nsq_tail`的窗口，并注意确实会生成消息以响应实时 Twitter 活动。

### 提示

如果您没有看到太多活动，请尝试在 Twitter 上查找热门标签，并添加另一个包含这些选项的投票。

# 计票

我们将要实现的第二个程序是`counter`工具，它将负责监视 NSQ 中的投票，对其进行计数，并将 MongoDB 与最新数字保持同步。

在`twittervotes`旁边创建一个名为`counter`的新文件夹，并将以下代码添加到一个新的`main.go`文件中：

```go
package main
import (
  "flag"
  "fmt"
  "os"
)
var fatalErr error
func fatal(e error) {
  fmt.Println(e)
  flag.PrintDefaults()
  fatalErr = e
}
func main() {
  defer func() {
    if fatalErr != nil {
      os.Exit(1)
    }
  }()
}
```

通常，当我们在代码中遇到错误时，我们使用`log.Fatal`或`os.Exit`这样的调用，它会立即终止程序。以非零退出代码退出程序很重要，因为这是我们告诉操作系统出现问题，我们没有成功完成任务的方式。常规方法的问题在于我们安排的任何延迟函数（因此我们需要运行的任何拆卸代码）都不会有机会执行。

在前面的代码片段中使用的模式允许我们调用`fatal`函数来记录发生错误。请注意，只有当我们的主函数退出时，推迟的函数才会运行，然后调用`os.Exit(1)`以退出带有退出代码`1`的程序。因为推迟的语句按 LIFO（后进先出）顺序运行，我们推迟的第一个函数将是最后执行的函数，这就是为什么我们在`main`函数中首先推迟退出代码。这使我们确信我们推迟的其他函数将在程序退出*之前*被调用。我们将使用此功能来确保无论发生任何错误，我们的数据库连接都会关闭。

## 连接到数据库

在成功获取资源后，立即考虑清理资源（例如数据库连接）是最佳时机；Go 的`defer`关键字使这变得容易。在主函数的底部，添加以下代码：

```go
log.Println("Connecting to database...")
db, err := mgo.Dial("localhost")
if err != nil {
  fatal(err)
  return
}
defer func() {
  log.Println("Closing database connection...")
  db.Close()
}()
pollData := db.DB("ballots").C("polls")
```

此代码使用熟悉的`mgo.Dial`方法打开到本地运行的 MongoDB 实例的会话，并立即推迟一个关闭会话的函数。我们可以确信这段代码将在先前推迟的包含退出代码的语句之前运行（因为推迟的函数按照它们被调用的相反顺序运行）。因此，无论我们的程序发生什么，我们都知道数据库会话一定会正确关闭。

### 提示

日志语句是可选的，但将帮助我们在运行和退出程序时查看发生了什么。

在片段的末尾，我们使用`mgo`流畅的 API 将`ballots.polls`数据集的引用保存在`pollData`变量中，稍后我们将使用它来进行查询。

## 在 NSQ 中消费消息

为了计算选票，我们需要消耗 NSQ 中`votes`主题上的消息，并且我们需要一个地方来存储它们。将以下变量添加到`main`函数中：

```go
var counts map[string]int
var countsLock sync.Mutex
```

在 Go 中，地图和锁（`sync.Mutex`）是常见的组合，因为我们将有多个 goroutine 尝试访问相同的地图，并且我们需要避免在同时尝试修改或读取它时破坏它。

将以下代码添加到`main`函数中：

```go
log.Println("Connecting to nsq...")
q, err := nsq.NewConsumer("votes", "counter", nsq.NewConfig())
if err != nil {
  fatal(err)
  return
}
```

`NewConsumer`函数允许我们设置一个对象，该对象将侦听`votes` NSQ 主题，因此当`twittervotes`在该主题上发布选票时，我们可以在此程序中处理它。如果`NewConsumer`返回错误，我们将使用我们的`fatal`函数来记录并返回。

接下来，我们将添加处理来自 NSQ 的消息（选票）的代码：

```go
q.AddHandler(nsq.HandlerFunc(func(m *nsq.Message) error {
  countsLock.Lock()
  defer countsLock.Unlock()
  if counts == nil {
    counts = make(map[string]int)
  }
  vote := string(m.Body)
  counts[vote]++
  return nil
}))
```

我们在`nsq.Consumer`上调用`AddHandler`方法，并将一个函数传递给它，该函数将在接收到`votes`主题上的每条消息时调用。

当选票到来时，我们首先锁定`countsLock`互斥体。接下来，我们推迟了互斥体的解锁，以便在函数退出时解锁。这使我们确信，在`NewConsumer`运行时，我们是唯一被允许修改地图的人；其他人必须等到我们的函数退出后才能使用它。对`Lock`方法的调用在放置锁时阻止执行，只有在通过调用`Unlock`释放锁时才继续执行。这就是为什么每个`Lock`调用都必须有一个`Unlock`对应项的原因，否则我们将使程序死锁。

每次收到一张选票时，我们都会检查`counts`是否为`nil`，如果是，则创建一个新地图，因为一旦数据库已更新为最新结果，我们希望重置一切并从零开始。最后，我们增加给定键的`int`值一次，并返回`nil`表示没有错误。

尽管我们已经创建了 NSQ 消费者，并添加了处理程序函数，但我们仍然需要连接到 NSQ 服务，我们将通过添加以下代码来实现：

```go
if err := q.ConnectToNSQLookupd("localhost:4161"); err != nil {
  fatal(err)
  return
}
```

重要的是要注意，我们实际上是连接到`nsqlookupd`实例的 HTTP 端口，而不是 NSQ 实例；这种抽象意味着我们的程序不需要知道消息来自何处才能消费它们。如果我们无法连接到服务器（例如，如果我们忘记启动它），我们将收到错误，我们会在立即返回之前将其报告给我们的致命函数。

## 保持数据库更新

我们的代码将监听投票，并在内存中保留结果的映射，但是这些信息目前被困在我们的程序中。接下来，我们需要添加定期将结果推送到数据库的代码：

```go
log.Println("Waiting for votes on nsq...")
var updater *time.Timer
updater = time.AfterFunc(updateDuration, func() {
  countsLock.Lock()
  defer countsLock.Unlock()
  if len(counts) == 0 {
    log.Println("No new votes, skipping database update")
  } else {
    log.Println("Updating database...")
    log.Println(counts)
    ok := true
    for option, count := range counts {
      sel := bson.M{"options": bson.M{"$in": []string{option}}}
      up := bson.M{"$inc": bson.M{"results." + option: count}}
      if _, err := pollData.UpdateAll(sel, up); err != nil {
        log.Println("failed to update:", err)
        ok = false
      }
    }
    if ok {
      log.Println("Finished updating database...")
      counts = nil // reset counts
    }
  }
  updater.Reset(updateDuration)
})
```

`time.AfterFunc`函数在指定的持续时间后调用函数的 goroutine。最后我们调用`Reset`，重新开始这个过程；这允许我们定期安排我们的更新代码定期运行。

当我们的更新函数运行时，我们首先锁定`countsLock`，并推迟其解锁。然后我们检查计数映射中是否有任何值。如果没有，我们只是记录我们正在跳过更新，并等待下一次。

如果有一些投票，我们会遍历`counts`映射，提取选项和投票数（自上次更新以来），并使用一些 MongoDB 魔法来更新结果。

### 注意

MongoDB 在内部存储 BSON（二进制 JSON）文档，这比普通 JSON 文档更容易遍历，这就是为什么`mgo`包带有`mgo/bson`编码包。在使用`mgo`时，我们经常使用`bson`类型，例如`bson.M`映射来描述 MongoDB 的概念。

我们首先使用`bson.M`快捷类型创建我们的更新操作的选择器，这类似于创建`map[string]interface{}`类型。我们创建的选择器将大致如下：

```go
{
  "options": {
    "$in": ["happy"]
  }
}
```

在 MongoDB 中，前面的 BSON 指定我们要选择`options`数组中包含`"happy"`的选项的投票。

接下来，我们使用相同的技术生成更新操作，大致如下：

```go
{
  "$inc": {
    "results.happy": 3
  }
}
```

在 MongoDB 中，前面的 BSON 指定我们要将`results.happy`字段增加 3。如果投票中没有`results`映射，将创建一个，如果`results`中没有`happy`键，则假定为`0`。

然后我们调用`pollsData`查询上的`UpdateAll`方法来向数据库发出命令，这将依次更新与选择器匹配的每个投票（与`Update`方法相反，它只会更新一个）。如果出现问题，我们会报告并将`ok`布尔值设置为 false。如果一切顺利，我们将`counts`映射设置为 nil，因为我们想重置计数器。

我们将在文件顶部将`updateDuration`指定为常量，这将使我们在测试程序时更容易进行更改。在`main`函数上面添加以下代码：

```go
const updateDuration = 1 * time.Second
```

## 响应 Ctrl + C

在我们的程序准备就绪之前要做的最后一件事是确保我们的`main`函数在退出之前等待操作完成，就像我们在`twittervotes`程序中所做的那样。在`main`函数的末尾添加以下代码：

```go
termChan := make(chan os.Signal, 1)
signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
for {
  select {
  case <-termChan:
    updater.Stop()
    q.Stop()
  case <-q.StopChan:
    // finished
    return
  }
}
```

这里我们采用了与以前略有不同的策略。我们捕获终止事件，这将导致在我们按下*Ctrl + C*时通过`termChan`发送信号。接下来，我们启动一个无限循环，在循环内部，我们使用 Go 的`select`结构，使我们能够在`termChan`或消费者的`StopChan`上接收到东西时运行代码。

实际上，我们只会在按下`Ctrl+C`时首先收到`termChan`信号，此时我们会停止`updater`计时器，并要求消费者停止监听投票。然后执行重新进入循环，并阻塞直到消费者通过在其`StopChan`上发出信号来报告已经停止。当这发生时，我们完成并退出，此时我们的延迟语句运行，如果您记得的话，它会整理数据库会话。

# 运行我们的解决方案

是时候看到我们的代码在运行了。确保在单独的终端窗口中运行`nsqlookupd`，`nsqd`和`mongod`：

```go

nsqlookupd

nsqd --lookupd-tcp-address=127.0.0.1:4160

mongod --dbpath ./db

```

如果你还没有这样做，请确保`twittervotes`程序也在运行。然后在`counter`文件夹中，构建并运行我们的计数程序：

```go

go build -o counter

./counter

```

你应该会看到定期的输出，描述`counter`正在做的工作，比如：

```go

No new votes, skipping database update

Updating database...

map[win:2 happy:2 fail:1]

Finished updating database...

No new votes, skipping database update

Updating database...

map[win:3]

Finished updating database...

```

### 提示

输出当然会有所不同，因为我们实际上是在回应 Twitter 上的实时活动。

我们可以看到我们的程序正在从 NSQ 接收投票数据，并报告正在更新数据库的结果。我们可以通过打开 MongoDB shell 并查询投票数据来确认这一点，看看`results` map 是否正在更新。在另一个终端窗口中，打开 MongoDB shell：

```go

mongo

```

要求它使用选票数据库：

```go

> use ballots

switched to db ballots

```

使用无参数的 find 方法获取所有投票（在末尾添加`pretty`方法以获得格式良好的 JSON）：

```go

> db.polls.find().pretty()

{

 "_id" : ObjectId("53e2a3afffbff195c2e09a02"),

 "options" : [

 "happy","sad","fail","win"

 ],

 "results" : {

 "fail" : 159, "win" : 711,

 "happy" : 233, "sad" : 166,

 },

 "title" : "Test poll"

}

```

`results` map 确实在更新，并且随时包含每个选项的总票数。

# 摘要

在本章中，我们涵盖了很多内容。我们学习了使用信号通道优雅地关闭程序的不同技术，这在我们的代码在退出之前需要做一些工作时尤其重要。我们看到，在程序开始时推迟报告致命错误可以让我们的其他推迟函数有机会在进程结束之前执行。

我们还发现使用`mgo`包与 MongoDB 进行交互是多么容易，并且在描述数据库概念时如何使用 BSON 类型。`bson.M`替代了`map[string]interface{}`，帮助我们保持代码更简洁，同时仍然提供了我们在处理非结构化或无模式数据时所需的所有灵活性。

我们了解了消息队列以及它们如何允许我们将系统的组件分解为独立和专业化的微服务。我们首先运行查找守护程序`nsqlookupd`，然后运行单个`nsqd`实例，并通过 TCP 接口将它们连接在一起。然后我们能够在`twittervotes`中将投票发布到队列中，并连接到查找守护程序，在我们的`counter`程序中为每个发送的投票运行处理函数。

虽然我们的解决方案实际上执行的是一个非常简单的任务，但是我们在本章中构建的架构能够做一些非常了不起的事情。

+   我们消除了`twittervotes`和`counter`程序需要在同一台机器上运行的需求——只要它们都能连接到适当的 NSQ，无论它们在哪里运行，它们都会按预期运行。

+   我们可以将我们的 MongoDB 和 NSQ 节点分布在许多物理机器上，这意味着我们的系统能够实现巨大的规模——每当资源开始不足时，我们可以添加新的盒子来满足需求。

+   当我们添加其他需要查询和读取投票结果的应用程序时，我们可以确保我们的数据库服务是高度可用的，并且能够提供服务。

+   我们可以将我们的数据库分布在地理范围内，复制数据以备份，这样当灾难发生时我们不会丢失任何东西。

+   我们可以构建一个多节点、容错的 NSQ 环境，这意味着当我们的`twittervotes`程序了解到有趣的推文时，总会有地方发送数据。

+   我们可以编写更多的程序，从不同的来源生成投票；唯一的要求是它们知道如何将消息放入 NSQ。

+   在下一章中，我们将构建自己的 RESTful 数据服务，通过它我们将公开我们社交投票应用程序的功能。我们还将构建一个 Web 界面，让用户创建自己的投票，并可视化结果。


# 第六章：通过 RESTful 数据 Web 服务 API 公开数据和功能

在上一章中，我们构建了一个从 Twitter 读取推文，计算标签投票并将结果存储在 MongoDB 数据库中的服务。我们还使用了 MongoDB shell 来添加投票并查看投票结果。如果我们是唯一使用我们的解决方案的人，那么这种方法是可以的，但是如果我们发布我们的项目并期望用户直接连接到我们的 MongoDB 实例以使用我们构建的服务，那将是疯狂的。

因此，在本章中，我们将构建一个 RESTful 数据服务，通过该服务将数据和功能公开。我们还将组建一个简单的网站来消费新的 API。用户可以使用我们的网站创建和监视投票，或者在我们发布的 Web 服务之上构建自己的应用程序。

### 提示

本章中的代码依赖于第五章中的代码，*构建分布式系统并使用灵活数据*，因此建议您首先完成该章节，特别是因为它涵盖了设置本章代码运行的环境。

具体来说，您将学到：

+   如何包装`http.HandlerFunc`类型可以为我们的 HTTP 请求提供一个简单但强大的执行管道

+   如何在 HTTP 处理程序之间安全共享数据

+   编写负责公开数据的处理程序的最佳实践

+   小的抽象可以让我们现在编写尽可能简单的实现，但留下改进它们的空间，而不改变接口

+   如何向我们的项目添加简单的辅助函数和类型将防止我们（或至少推迟）对外部包添加依赖

# RESTful API 设计

要使 API 被视为 RESTful，它必须遵循一些原则，这些原则忠实于 Web 背后的原始概念，并且大多数开发人员已经了解。这种方法可以确保我们没有在 API 中构建任何奇怪或不寻常的东西，同时也让我们的用户提前消费它，因为他们已经熟悉其概念。

一些最重要的 RESTful 设计概念是：

+   HTTP 方法描述要采取的操作类型，例如，`GET`方法只会*读取*数据，而`POST`请求将*创建*某些东西

+   数据表示为资源集合

+   操作被表达为对数据的更改

+   URL 用于引用特定数据

+   HTTP 头用于描述进入和离开服务器的表示形式

### 注意

要深入了解 RESTful 设计的这些和其他细节，请参阅维基百科文章[`en.wikipedia.org/wiki/Representational_state_transfer`](http://en.wikipedia.org/wiki/Representational_state_transfer)。

以下表格显示了我们的 API 中支持的 HTTP 方法和 URL，以及我们打算如何使用调用的简要描述和示例用例：

| 请求 | 描述 | 用例 |
| --- | --- | --- |
| `GET /polls/` | 读取所有投票 | 向用户显示投票列表 |
| `GET /polls/{id}` | 读取投票 | 显示特定投票的详细信息或结果 |
| `POST /polls/` | 创建投票 | 创建新的投票 |
| `DELETE /polls/{id}` | 删除投票 | 删除特定投票 |

`{id}`占位符表示路径中唯一的投票 ID 的位置。

# 在处理程序之间共享数据

如果我们希望保持处理程序与 Go 标准库中的`http.Handler`接口一样纯净，同时将常见功能提取到我们自己的方法中，我们需要一种在处理程序之间共享数据的方法。以下的`HandlerFunc`签名告诉我们，我们只允许传入一个`http.ResponseWriter`对象和一个`http.Request`对象，什么都不能传入：

```go
type HandlerFunc func(http.ResponseWriter, *http.Request)
```

这意味着我们不能在一个地方创建和管理数据库会话对象，然后将它们传递给我们的处理程序，这理想情况下是我们想要做的。

相反，我们将实现一个按请求数据的内存映射，并为处理程序提供一种轻松访问它的方式。在`twittervotes`和`counter`文件夹旁边，创建一个名为`api`的新文件夹，并在其中创建一个名为`vars.go`的新文件。将以下代码添加到文件中：

```go
package main
import (
  "net/http"
  "sync"
)
var vars map[*http.Request]map[string]interface{}
var varsLock sync.RWMutex
```

在这里，我们声明了一个`vars`映射，它的键是指向`http.Request`类型的指针，值是另一个映射。我们将存储与请求实例相关联的变量映射。`varsLock`互斥锁很重要，因为我们的处理程序将同时尝试访问和更改`vars`映射，同时处理许多并发的 HTTP 请求，我们需要确保它们可以安全地执行这些操作。

接下来，我们将添加`OpenVars`函数，允许我们准备`vars`映射以保存特定请求的变量：

```go
func OpenVars(r *http.Request) {
  varsLock.Lock()
  if vars == nil {
    vars = map[*http.Request]map[string]interface{}{}
  }
  vars[r] = map[string]interface{}{}
  varsLock.Unlock()
}
```

这个函数首先锁定互斥锁，以便我们可以安全地修改映射，然后确保`vars`包含一个非 nil 映射，否则当我们尝试访问其数据时会导致恐慌。最后，它使用指定的`http.Request`指针作为键，分配一个新的空`map`值，然后解锁互斥锁，从而释放其他处理程序与之交互。

一旦我们完成了处理请求，我们需要一种方法来清理我们在这里使用的内存；否则，我们的代码的内存占用将不断增加（也称为内存泄漏）。我们通过添加`CloseVars`函数来实现这一点：

```go
func CloseVars(r *http.Request) {
  varsLock.Lock()
  delete(vars, r)
  varsLock.Unlock()
}
```

这个函数安全地删除了请求的`vars`映射中的条目。只要我们在尝试与变量交互之前调用`OpenVars`，并在完成后调用`CloseVars`，我们就可以自由地安全地存储和检索每个请求的数据。但是，我们不希望我们的处理程序代码在需要获取或设置一些数据时担心锁定和解锁映射，因此让我们添加两个辅助函数，`GetVar`和`SetVar`：

```go
func GetVar(r *http.Request, key string) interface{} {
  varsLock.RLock()
  value := vars[r][key]
  varsLock.RUnlock()
  return value
}
func SetVar(r *http.Request, key string, value interface{}) {
  varsLock.Lock()
  vars[r][key] = value
  varsLock.Unlock()
}
```

`GetVar`函数将使我们能够轻松地从映射中获取指定请求的变量，`SetVar`允许我们设置一个。请注意，`GetVar`函数调用`RLock`和`RUnlock`而不是`Lock`和`Unlock`；这是因为我们使用了`sync.RWMutex`，这意味着可以安全地同时进行许多读取，只要没有写入发生。这对于可以同时读取的项目的性能是有利的。对于普通的互斥锁，`Lock`会阻塞执行，等待锁定它的东西解锁它，而`RLock`则不会。

# 包装处理程序函数

在构建 Go 中的 Web 服务和网站时，学习的最有价值的模式之一是我们在第二章中已经使用过的*添加身份验证*，在那里我们通过用其他`http.Handler`类型包装它们来装饰`http.Handler`类型。对于我们的 RESTful API，我们将应用相同的技术到`http.HandlerFunc`函数上，以提供一种非常强大的模块化代码的方式，而不会破坏标准的`func(w http.ResponseWriter, r *http.Request)`接口。

## API 密钥

大多数 Web API 要求客户端为其应用程序注册一个 API 密钥，并要求他们在每个请求中发送该密钥。这些密钥有许多用途，从简单地识别请求来自哪个应用程序到解决授权问题，例如一些应用程序只能根据用户允许的内容做有限的事情。虽然我们实际上不需要为我们的应用程序实现 API 密钥，但我们将要求客户端提供一个，这将允许我们在保持接口不变的同时稍后添加实现。

在您的`api`文件夹中添加必要的`main.go`文件：

```go
package main
func main(){}
```

接下来，我们将在`main.go`的底部添加我们的第一个`HandlerFunc`包装器函数，名为`withAPIKey`：

```go
func withAPIKey(fn http.HandlerFunc) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    if !isValidAPIKey(r.URL.Query().Get("key")) {
      respondErr(w, r, http.StatusUnauthorized, "invalid API key")
      return
    }
    fn(w, r)
  }
}
```

正如你所看到的，我们的`withAPIKey`函数既接受一个`http.HandlerFunc`类型作为参数，又返回一个；这就是我们在这个上下文中所说的包装。`withAPIKey`函数依赖于许多其他我们尚未编写的函数，但你可以清楚地看到发生了什么。我们的函数立即返回一个新的`http.HandlerFunc`类型，通过调用`isValidAPIKey`来检查查询参数`key`。如果密钥被认为是无效的（通过返回`false`），我们将回应一个`无效的 API 密钥`错误。要使用这个包装器，我们只需将一个`http.HandlerFunc`类型传递给这个函数，以启用`key`参数检查。由于它也返回一个`http.HandlerFunc`类型，因此结果可以被传递到其他包装器中，或者直接传递给`http.HandleFunc`函数，以实际将其注册为特定路径模式的处理程序。

让我们接下来添加我们的`isValidAPIKey`函数：

```go
func isValidAPIKey(key string) bool {
  return key == "abc123"
}
```

目前，我们只是将 API 密钥硬编码为`abc123`；其他任何内容都将返回`false`，因此被视为无效。稍后，我们可以修改这个函数，以查阅配置文件或数据库来检查密钥的真实性，而不影响我们如何使用`isValidAPIKey`方法，或者`withAPIKey`包装器。

## 数据库会话

现在我们可以确保请求有一个有效的 API 密钥，我们必须考虑处理程序将如何连接到数据库。一种选择是让每个处理程序拨号自己的连接，但这并不是很**DRY**（**不要重复自己**），并且留下了潜在错误的空间，比如忘记在完成后关闭数据库会话的代码。相反，我们将创建另一个管理数据库会话的`HandlerFunc`包装器。在`main.go`中，添加以下函数：

```go
func withData(d *mgo.Session, f http.HandlerFunc) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    thisDb := d.Copy()
    defer thisDb.Close()
    SetVar(r, "db", thisDb.DB("ballots"))
    f(w, r)
  }
}
```

`withData`函数使用`mgo`包来接受一个 MongoDB 会话表示，以及另一个处理程序，符合该模式。返回的`http.HandlerFunc`类型将复制数据库会话，延迟关闭该副本，并使用我们的`SetVar`助手将`ballots`数据库的引用设置为`db`变量，最后调用下一个`HandlerFunc`。这意味着在此之后执行的任何处理程序都将通过`GetVar`函数访问受管数据库会话。一旦处理程序执行完毕，延迟关闭会话将发生，这将清理请求使用的任何内存，而无需个别处理程序担心它。

## 每个请求的变量

我们的模式允许我们非常轻松地代表我们的实际处理程序执行常见任务。请注意，其中一个处理程序正在调用`OpenVars`和`CloseVars`，以便`GetVar`和`SetVar`可以在不必关心设置和拆卸的情况下使用。该函数将返回一个首先调用`OpenVars`进行请求的`http.HandlerFunc`，延迟调用`CloseVars`，并调用指定的处理程序函数。任何使用`withVars`包装的处理程序都可以使用`GetVar`和`SetVar`。

将以下代码添加到`main.go`：

```go
func withVars(fn http.HandlerFunc) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    OpenVars(r)
    defer CloseVars(r)
    fn(w, r)
  }
}
```

使用这种模式可以解决许多其他问题；每当你发现自己在处理程序内部重复常见任务时，都值得考虑是否处理程序包装函数可以帮助简化代码。

## 跨浏览器资源共享

同源安全策略要求 Web 浏览器中的 AJAX 请求只允许服务于同一域上托管的服务，这将使我们的 API 相当受限，因为我们不一定会托管使用我们 Web 服务的所有网站。CORS 技术绕过了同源策略，允许我们构建一个能够为其他域上托管的网站提供服务的服务。为此，我们只需在响应中设置`Access-Control-Allow-Origin`头为`*`。顺便说一句，因为我们在创建投票调用中使用了`Location`头，我们也将允许客户端访问该头，这可以通过在`Access-Control-Expose-Headers`头中列出来实现。在`main.go`中添加以下代码：

```go
func withCORS(fn http.HandlerFunc) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Access-Control-Allow-Origin", "*")
    w.Header().Set("Access-Control-Expose-Headers", "Location")
    fn(w, r)
  }
}
```

这是最简单的包装函数，它只是在`ResponseWriter`类型上设置适当的头，并调用指定的`http.HandlerFunc`类型。

### 提示

在这一章中，我们明确处理 CORS，以便我们可以准确了解发生了什么；对于真正的生产代码，您应该考虑使用开源解决方案，比如[`github.com/fasterness/cors`](https://github.com/fasterness/cors)。

# 读累了记得休息一会哦~

**公众号：古德猫宁李**

+   电子书搜索下载

+   书单分享

+   书友学习交流

网站：[沉金书屋 https://www.chenjin5.com](https://www.chenjin5.com)

+   电子书搜索下载

+   电子书打包资源分享

+   学习资源分享

# 响应

任何 API 的重要部分是以状态码、数据、错误和有时头部的组合来响应请求，`net/http`包使得所有这些都非常容易实现。我们有一个选项，对于小型项目或者大项目的早期阶段来说，仍然是最好的选项，那就是直接在处理程序中构建响应代码。然而，随着处理程序数量的增加，我们将不得不重复大量的代码，并在整个项目中散布表示决策。一个更可扩展的方法是将响应代码抽象成助手函数。

对于我们 API 的第一个版本，我们将只使用 JSON，但如果需要，我们希望灵活地添加其他表示。

创建一个名为`respond.go`的新文件，并添加以下代码：

```go
func decodeBody(r *http.Request, v interface{}) error {
  defer r.Body.Close()
  return json.NewDecoder(r.Body).Decode(v)
}
func encodeBody(w http.ResponseWriter, r *http.Request, v interface{}) error {
  return json.NewEncoder(w).Encode(v)
}
```

这两个函数分别抽象了从`Request`和`ResponseWriter`对象解码和编码数据。解码器还关闭了请求体，这是推荐的。虽然我们在这里没有添加太多功能，但这意味着我们不需要在代码的其他地方提到 JSON，如果我们决定添加对其他表示的支持或者切换到二进制协议，我们只需要修改这两个函数。

接下来，我们将添加一些更多的助手，使得响应变得更加容易。在`respond.go`中，添加以下代码：

```go
func respond(w http.ResponseWriter, r *http.Request,
  status int, data interface{},
) {
  w.WriteHeader(status)
  if data != nil {
    encodeBody(w, r, data)
  }
}
```

这个函数使得使用我们的`encodeBody`助手，可以轻松地将状态码和一些数据写入`ResponseWriter`对象。

处理错误是另一个值得抽象的重要方面。添加以下`respondErr`助手：

```go
func respondErr(w http.ResponseWriter, r *http.Request,
  status int, args ...interface{},
) {
  respond(w, r, status, map[string]interface{}{
    "error": map[string]interface{}{
      "message": fmt.Sprint(args...),
    },
  })
}
```

这个方法给我们提供了一个类似于`respond`函数的接口，但写入的数据将被包装在一个`error`对象中，以明确表示出现了问题。最后，我们可以添加一个特定于 HTTP 错误的助手，通过使用 Go 标准库中的`http.StatusText`函数为我们生成正确的消息：

```go
func respondHTTPErr(w http.ResponseWriter, r *http.Request,
  status int,
) {
  respondErr(w, r, status, http.StatusText(status))
}
```

请注意，这些函数都是 dogfooding，这意味着它们彼此使用（就像吃自己的狗粮一样），这很重要，因为我们希望实际的响应只发生在一个地方，以便在需要进行更改时（或更可能的是，何时需要进行更改）。

# 理解请求

`http.Request`对象为我们提供了关于底层 HTTP 请求的所有信息，因此值得浏览`net/http`文档，真正感受其强大之处。例如，但不限于：

+   URL、路径和查询字符串

+   HTTP 方法

+   Cookies

+   文件

+   表单值

+   请求者的引荐者和用户代理

+   基本身份验证详细信息

+   请求体

+   头信息

有一些问题它没有解决，我们需要自己解决或寻求外部包的帮助。URL 路径解析就是一个例子——虽然我们可以通过`http.Request`类型的`URL.Path`字段访问路径（例如`/people/1/books/2`），但没有简单的方法来提取路径中编码的数据，比如`1`的 people ID 或`2`的 books ID。

### 注意

一些项目很好地解决了这个问题，比如 Goweb 或 Gorillz 的`mux`包。它们允许您映射包含占位符值的路径模式，然后从原始字符串中提取这些值并使其可用于您的代码。例如，您可以映射`/users/{userID}/comments/{commentID}`的模式，这将映射路径，如`/users/1/comments/2`。在处理程序代码中，您可以通过放在花括号内的名称获取值，而不必自己解析路径。

由于我们的需求很简单，我们将编写一个简单的路径解析工具；如果必要，我们随时可以使用不同的包，但这意味着向我们的项目添加依赖。

创建一个名为`path.go`的新文件，并插入以下代码：

```go
package main
import (
  "strings"
)
const PathSeparator = "/"
type Path struct {
  Path string
  ID   string
}
func NewPath(p string) *Path {
  var id string
  p = strings.Trim(p, PathSeparator)
  s := strings.Split(p, PathSeparator)
  if len(s) > 1 {
    id = s[len(s)-1]
    p = strings.Join(s[:len(s)-1], PathSeparator)
  }
  return &Path{Path: p, ID: id}
}
func (p *Path) HasID() bool {
  return len(p.ID) > 0
}
```

这个简单的解析器提供了一个`NewPath`函数，它解析指定的路径字符串并返回`Path`类型的新实例。前导和尾随斜杠被修剪（使用`strings.Trim`），剩下的路径被`PathSeparator`常量（即斜杠）分割（使用`strings.Split`）。如果有多个段（`len(s) > 1`），最后一个被认为是 ID。我们重新切片字符串切片以使用`len(s)-1`选择最后一个项目作为 ID，并使用`s[:len(s)-1]`选择路径的其余部分。在同样的行上，我们还使用`PathSeparator`常量重新连接路径段，以形成一个包含路径但不包含 ID 的单个字符串。

这支持任何`collection/id`对，这正是我们 API 所需要的。以下表格显示了给定原始路径字符串的`Path`类型的状态：

| 原始路径字符串 | 路径 | ID | 是否有 ID |
| --- | --- | --- | --- |
| `/` | `/` | `nil` | `false` |
| `/people/` | `people` | `nil` | `false` |
| `/people/1/` | `people` | `1` | `true` |

# 用于提供我们的 API 的简单 main 函数

Web 服务只不过是绑定到特定 HTTP 地址和端口并提供请求的简单 Go 程序，因此我们可以使用所有我们的命令行工具编写知识和技术。

### 提示

我们还希望确保我们的`main`函数尽可能简单和适度，这始终是编码的目标，特别是在 Go 中。

在编写我们的`main`函数之前，让我们看一下我们的 API 程序的一些设计目标：

+   我们应该能够指定 API 监听的 HTTP 地址和端口以及 MongoDB 实例的地址，而无需重新编译程序（通过命令行标志）

+   我们希望程序在我们终止它时能够优雅地关闭，允许正在处理的请求（在发送终止信号给我们的程序时仍在处理的请求）完成。

+   我们希望程序能够记录状态更新并正确报告错误

在`main.go`文件的顶部，用以下代码替换`main`函数占位符：

```go
func main() {
  var (
    addr  = flag.String("addr", ":8080", "endpoint address")
    mongo = flag.String("mongo", "localhost", "mongodb address")
  )
  flag.Parse()
  log.Println("Dialing mongo", *mongo)
  db, err := mgo.Dial(*mongo)
  if err != nil {
    log.Fatalln("failed to connect to mongo:", err)
  }
  defer db.Close()
  mux := http.NewServeMux()
  mux.HandleFunc("/polls/", withCORS(withVars(withData(db, withAPIKey(handlePolls)))))
  log.Println("Starting web server on", *addr)
  graceful.Run(*addr, 1*time.Second, mux)
  log.Println("Stopping...")
}
```

这个函数就是我们的 API `main`函数的全部内容，即使我们的 API 增长，我们只需要添加一点点冗余。

我们要做的第一件事是指定两个命令行标志`addr`和`mongo`，并使用一些合理的默认值，并要求`flag`包解析它们。然后我们尝试拨号指定地址的 MongoDB 数据库。如果我们失败了，我们会通过调用`log.Fatalln`中止。假设数据库正在运行并且我们能够连接，我们会在延迟关闭连接之前将引用存储在`db`变量中。这确保我们的程序在结束时正确断开连接并整理自己。

然后，我们创建一个新的`http.ServeMux`对象，这是 Go 标准库提供的请求多路复用器，并为所有以路径`/polls/`开头的请求注册一个处理程序。

最后，我们使用 Tyler Bunnell 的优秀的`Graceful`包，可以在[`github.com/stretchr/graceful`](https://github.com/stretchr/graceful)找到，来启动服务器。该包允许我们在运行任何`http.Handler`（例如我们的`ServeMux`处理程序）时指定`time.Duration`，这将允许任何正在进行的请求在函数退出之前有一些时间完成。`Run`函数将阻塞，直到程序终止（例如，当有人按下*Ctrl* + *C*）。

## 使用处理程序函数包装器

在`ServeMux`处理程序上调用`HandleFunc`时，我们使用了我们的处理程序函数包装器，代码如下：

```go
withCORS(withVars(withData(db, withAPIKey(handlePolls)))))
```

由于每个函数都将`http.HandlerFunc`类型作为参数，并返回一个，我们可以通过嵌套函数调用来链接执行，就像我们之前做的那样。因此，当请求带有路径前缀`/polls/`时，程序将采取以下执行路径：

1.  调用`withCORS`，设置适当的标头。

1.  调用`withVars`，调用`OpenVars`并为请求延迟`CloseVars`。

1.  然后调用`withData`，它会复制提供的数据库会话作为第一个参数，并延迟关闭该会话。

1.  接下来调用`withAPIKey`，检查请求是否有 API 密钥，如果无效则中止，否则调用下一个处理程序函数。

1.  然后调用`handlePolls`，它可以访问变量和数据库会话，并且可以使用`respond.go`中的辅助函数向客户端编写响应。

1.  执行返回到`withAPIKey`，然后退出。

1.  执行返回到`withData`，然后退出，因此调用延迟的会话`Close`函数并清理数据库会话。

1.  执行返回到`withVars`，然后退出，因此调用`CloseVars`并清理。

1.  最后，执行返回到`withCORS`，然后退出。

### 注意

我们嵌套包装函数的顺序很重要，因为`withData`使用`SetVar`将每个请求的数据库会话放入该请求的变量映射中。因此，`withVars`必须在`withData`之外。如果不遵守这一点，代码很可能会出现 panic，并且您可能希望添加一个检查，以便 panic 对其他开发人员更有意义。

# 处理端点

拼图的最后一块是`handlePolls`函数，它将使用辅助函数来理解传入的请求并访问数据库，并生成一个有意义的响应，将发送回客户端。我们还需要对上一章中使用的投票数据进行建模。

创建一个名为`polls.go`的新文件，并添加以下代码：

```go
package main
import "gopkg.in/mgo.v2/bson"
type poll struct {
  ID      bson.ObjectId  `bson:"_id" json:"id"`
  Title   string         `json":"title""`
  Options []string       `json:"options"`
  Results map[string]int `json:"results,omitempty"`
}
```

在这里，我们定义了一个名为`poll`的结构，它有三个字段，依次描述了我们在上一章中编写的代码创建和维护的投票。每个字段还有一个标签（在`ID`情况下有两个），这使我们能够提供一些额外的元数据。

## 使用标签向结构体添加元数据

标签是跟随`struct`类型中字段定义的字符串，位于同一行代码中。我们使用反引号字符来表示字面字符串，这意味着我们可以在标签字符串本身中使用双引号。`reflect`包允许我们提取与任何键关联的值；在我们的情况下，`bson`和`json`都是键的示例，它们都是由空格字符分隔的键/值对。`encoding/json`和`gopkg.in/mgo.v2/bson`包允许您使用标签来指定将用于编码和解码的字段名称（以及一些其他属性），而不是从字段名称本身推断值。我们使用 BSON 与 MongoDB 数据库通信，使用 JSON 与客户端通信，因此我们实际上可以指定相同`struct`类型的不同视图。例如，考虑 ID 字段：

```go
ID bson.ObjectId `bson:"_id" json:"id"`
```

在 Go 中的字段名是`ID`，JSON 字段是`id`，BSON 字段是`_id`，这是 MongoDB 中使用的特殊标识符字段。

## 单个处理程序的多个操作

因为我们简单的路径解析解决方案只关心路径，所以当查看客户端正在进行的 RESTful 操作类型时，我们需要做一些额外的工作。具体来说，我们需要考虑 HTTP 方法，以便知道如何处理请求。例如，对我们的`/polls/`路径进行`GET`调用应该读取投票，而`POST`调用将创建一个新的投票。一些框架为您解决了这个问题，允许您基于更多内容而不仅仅是路径来映射处理程序，比如 HTTP 方法或请求中特定标头的存在。由于我们的情况非常简单，我们将使用一个简单的`switch`情况。在`polls.go`中，添加`handlePolls`函数：

```go
func handlePolls(w http.ResponseWriter, r *http.Request) {
  switch r.Method {
  case "GET":
    handlePollsGet(w, r)
    return
  case "POST":
    handlePollsPost(w, r)
    return
  case "DELETE":
    handlePollsDelete(w, r)
    return
  }
  // not found
  respondHTTPErr(w, r, http.StatusNotFound)
}
```

我们根据 HTTP 方法进行分支，并根据是`GET`、`POST`还是`DELETE`来分支我们的代码。如果 HTTP 方法是其他的，我们只是用`404 http.StatusNotFound`错误进行响应。为了使这段代码编译，您可以在`handlePolls`处理程序下面添加以下函数存根：

```go
func handlePollsGet(w http.ResponseWriter, r *http.Request) {
  respondErr(w, r, http.StatusInternalServerError, errors.New("not implemented"))
}
func handlePollsPost(w http.ResponseWriter, r *http.Request) {
  respondErr(w, r, http.StatusInternalServerError, errors.New("not implemented"))
}
func handlePollsDelete(w http.ResponseWriter, r *http.Request) {
  respondErr(w, r, http.StatusInternalServerError, errors.New("not implemented"))
}
```

### 提示

在这一部分，我们学习了如何手动解析请求的元素（HTTP 方法）并在代码中做出决策。这对于简单的情况来说很好，但值得看看像 Goweb 或 Gorilla 的`mux`包这样的包，以便以更强大的方式解决这些问题。然而，将外部依赖保持在最低限度是编写良好且包含的 Go 代码的核心理念。

### 阅读投票

现在是时候实现我们的 Web 服务的功能了。在`GET`情况下，添加以下代码：

```go
func handlePollsGet(w http.ResponseWriter, r *http.Request) {
  db := GetVar(r, "db").(*mgo.Database)
  c := db.C("polls")
  var q *mgo.Query
  p := NewPath(r.URL.Path)
  if p.HasID() {
    // get specific poll
    q = c.FindId(bson.ObjectIdHex(p.ID))
  } else {
    // get all polls
    q = c.Find(nil)
  }
  var result []*poll
  if err := q.All(&result); err != nil {
    respondErr(w, r, http.StatusInternalServerError, err)
    return
  }
  respond(w, r, http.StatusOK, &result)
}
```

我们在每个子处理程序函数中的第一件事是使用`GetVar`获取`mgo.Database`对象，这将允许我们与 MongoDB 进行交互。由于此处理程序嵌套在`withVars`和`withData`中，我们知道数据库将在执行到达我们的处理程序时可用。然后，我们使用`mgo`创建一个对象，引用数据库中的`polls`集合——如果您记得，这就是我们的投票所在的地方。

然后，我们通过解析路径构建一个`mgo.Query`对象。如果存在 ID，我们使用`polls`集合上的`FindId`方法，否则我们将`nil`传递给`Find`方法，这表示我们要选择所有的投票。我们使用`ObjectIdHex`方法将 ID 从字符串转换为`bson.ObjectId`类型，以便我们可以使用它们的数字（十六进制）标识符引用投票。

由于`All`方法期望生成一组投票对象，我们将结果定义为`[]*poll`，或者指向投票类型的指针切片。在查询上调用`All`方法将导致`mgo`使用其与 MongoDB 的连接来读取所有投票并填充`result`对象。

### 注意

对于小规模项目，比如少量投票，这种方法是可以的，但随着投票数量的增加，我们需要考虑对结果进行分页或者使用查询中的`Iter`方法进行迭代，以便不要将太多数据加载到内存中。

现在我们已经添加了一些功能，让我们第一次尝试我们的 API。如果您使用的是我们在上一章中设置的相同的 MongoDB 实例，那么您应该已经在`polls`集合中有一些数据；为了确保我们的 API 正常工作，您应该确保数据库中至少有两个投票。

### 提示

如果您需要向数据库添加其他投票，在终端中运行`mongo`命令以打开一个允许您与 MongoDB 交互的数据库 shell。然后输入以下命令以添加一些测试投票：

```go
> use ballots
switched to db ballots
> db.polls.insert({"title":"Test poll","options":["one","two","three"]})
> db.polls.insert({"title":"Test poll two","options":["four","five","six"]})
```

在终端中，导航到您的`api`文件夹，并构建和运行项目：

```go

go build –o api

./api

```

现在，通过在浏览器中导航到`http://localhost:8080/polls/?key=abc123`，向`/polls/`端点发出`GET`请求；记得包括尾随斜杠。结果将以 JSON 格式返回一组投票。

复制并粘贴投票列表中的一个 ID，并将其插入到浏览器中`?`字符之前，以访问特定投票的数据；例如，`http://localhost:8080/polls/5415b060a02cd4adb487c3ae?key=abc123`。请注意，它只返回一个投票，而不是所有投票。

### 提示

通过删除或更改密钥参数来测试 API 密钥功能，看看错误是什么样子。

您可能还注意到，尽管我们只返回了一个投票，但这个投票值仍然嵌套在一个数组中。这是一个有意为之的设计决定，有两个原因：第一个和最重要的原因是，嵌套使得 API 的用户更容易编写代码来消费数据。如果用户总是期望一个 JSON 数组，他们可以编写描述这种期望的强类型，而不是为单个投票和投票集合编写另一种类型。作为 API 设计者，这是您的决定。我们将对象嵌套在数组中的第二个原因是，它使 API 代码更简单，允许我们只改变`mgo.Query`对象并保持其余代码不变。

### 创建投票

客户端应该能够向`/polls/`发出`POST`请求来创建一个投票。让我们在`POST`情况下添加以下代码：

```go
func handlePollsPost(w http.ResponseWriter, r *http.Request) {
  db := GetVar(r, "db").(*mgo.Database)
  c := db.C("polls")
  var p poll
  if err := decodeBody(r, &p); err != nil {
    respondErr(w, r, http.StatusBadRequest, "failed to read poll from request", err)
    return
  }
  p.ID = bson.NewObjectId()
  if err := c.Insert(p); err != nil {
    respondErr(w, r, http.StatusInternalServerError, "failed to insert poll", err)
    return
  }
  w.Header().Set("Location", "polls/"+p.ID.Hex())
  respond(w, r, http.StatusCreated, nil)
}
```

在这里，我们首先尝试解码请求的主体，根据 RESTful 原则，请求的主体应包含客户端想要创建的投票对象的表示。如果发生错误，我们使用`respondErr`助手将错误写入用户，并立即返回该函数。然后，我们为投票生成一个新的唯一 ID，并使用`mgo`包的`Insert`方法将其发送到数据库。根据 HTTP 标准，我们设置响应的`Location`标头，并以`201 http.StatusCreated`消息做出响应，指向新创建的投票的 URL。

### 删除投票

我们要在 API 中包含的最后一个功能是能够删除投票。通过使用`DELETE` HTTP 方法向投票的 URL（例如`/polls/5415b060a02cd4adb487c3ae`）发出请求，我们希望能够从数据库中删除投票并返回`200 Success`响应：

```go
func handlePollsDelete(w http.ResponseWriter, r *http.Request) {
  db := GetVar(r, "db").(*mgo.Database)
  c := db.C("polls")
  p := NewPath(r.URL.Path)
  if !p.HasID() {
    respondErr(w, r, http.StatusMethodNotAllowed, "Cannot delete all polls.")
    return
  }
  if err := c.RemoveId(bson.ObjectIdHex(p.ID)); err != nil {
    respondErr(w, r, http.StatusInternalServerError, "failed to delete poll", err)
    return
  }
  respond(w, r, http.StatusOK, nil) // ok
}
```

与`GET`情况类似，我们解析路径，但这次如果路径不包含 ID，我们会响应错误。目前，我们不希望人们能够通过一个请求删除所有投票，因此使用适当的`StatusMethodNotAllowed`代码。然后，使用我们在之前情况下使用的相同集合，我们调用`RemoveId`，传入路径中的 ID 并将其转换为`bson.ObjectId`类型。假设一切顺利，我们会以`http.StatusOK`消息做出响应，没有正文。

### CORS 支持

为了使我们的`DELETE`功能在 CORS 上工作，我们必须做一些额外的工作，以支持 CORS 浏览器处理一些 HTTP 方法（如`DELETE`）的方式。CORS 浏览器实际上会发送一个预检请求（HTTP 方法为`OPTIONS`），请求权限进行`DELETE`请求（列在`Access-Control-Request-Method`请求标头中），API 必须做出适当的响应才能使请求工作。在`switch`语句中添加另一个`OPTIONS`的情况：

```go
case "OPTIONS":
  w.Header().Add("Access-Control-Allow-Methods", "DELETE")
  respond(w, r, http.StatusOK, nil)
  return
```

如果浏览器要求发送`DELETE`请求的权限，API 将通过将`Access-Control-Allow-Methods`标头设置为`DELETE`来响应，从而覆盖我们在`withCORS`包装处理程序中设置的默认`*`值。在现实世界中，`Access-Control-Allow-Methods`标头的值将根据所做的请求而改变，但由于我们只支持`DELETE`，因此现在可以硬编码它。

### 注意

CORS 的细节不在本书的范围之内，但建议您在打算构建真正可访问的 Web 服务和 API 时，如果打算构建真正可访问的 Web 服务和 API，建议您在网上研究相关内容。请访问[`enable-cors.org/`](http://enable-cors.org/)开始。

## 使用 curl 测试我们的 API

`curl`是一个命令行工具，允许我们向我们的服务发出 HTTP 请求，以便我们可以像真正的应用程序或客户端一样访问它。

### 注意

Windows 用户默认没有`curl`，需要寻找替代方法。请查看[`curl.haxx.se/dlwiz/?type=bin`](http://curl.haxx.se/dlwiz/?type=bin)或在网络上搜索“Windows`curl`替代方法”。

在终端中，让我们通过我们的 API 读取数据库中的所有投票。转到您的`api`文件夹，构建和运行项目，并确保 MongoDB 正在运行：

```go

go build –o api

./api

```

然后我们执行以下步骤：

1.  输入以下`curl`命令，使用`-X`标志表示我们要对指定的 URL 进行`GET`请求：

```go

curl -X GET http://localhost:8080/polls/?key=abc123

```

1.  在按下*Enter*键后，输出将被打印：

```go

[{"id":"541727b08ea48e5e5d5bb189","title":"Best Beatle?","options":["john","paul","george","ringo"]},{"id":"541728728ea48e5e5d5bb18a","title":"Favorite language?","options":["go","java","javascript","ruby"]}]

```

1.  虽然不够美观，但您可以看到 API 从数据库返回了投票。发出以下命令来创建一个新的投票：

```go

curl --data '{"title":"test","options":["one","two","three"]}' -X POST http://localhost:8080/polls/?key=abc123

```

1.  再次获取列表，以查看新的投票包括在内：

```go

curl -X GET http://localhost:8080/polls/?key=abc123

```

1.  复制并粘贴其中一个 ID，并调整 URL 以特指该投票：

```go

curl -X GET http://localhost:8080/polls/541727b08ea48e5e5d5bb189?key=abc123

[{"id":"541727b08ea48e5e5d5bb189",","title":"Best Beatle?","options":["john","paul","george","ringo"]}]

```

1.  现在我们只看到了选定的投票`Best Beatle`。让我们发出`DELETE`请求来删除该投票：

```go

curl -X DELETE http://localhost:8080/polls/541727b08ea48e5e5d5bb189?key=abc123

```

1.  现在当我们再次获取所有投票时，我们会看到`Best Beatle`投票已经消失了：

```go

curl -X GET http://localhost:8080/polls/?key=abc123

[{"id":"541728728ea48e5e5d5bb18a","title":"Favorite language?","options":["go","java","javascript","ruby"]}]

```

现在我们知道我们的 API 正在按预期工作，是时候构建一个正确消耗 API 的东西了。

# 消耗 API 的 Web 客户端

我们将组建一个超级简单的 Web 客户端，通过我们的 API 公开的功能和数据，允许用户与我们在上一章和本章早些时候构建的投票系统进行交互。我们的客户端将由三个网页组成：

+   显示所有投票的`index.html`页面

+   显示特定投票结果的`view.html`页面

+   一个`new.html`页面，允许用户创建新的投票

在`api`文件夹旁边创建一个名为`web`的新文件夹，并将以下内容添加到`main.go`文件中：

```go
package main
import (
  "flag"
  "log"
  "net/http"
)
func main() {
  var addr = flag.String("addr", ":8081", "website address")
  flag.Parse()
  mux := http.NewServeMux()
  mux.Handle("/", http.StripPrefix("/", 
    http.FileServer(http.Dir("public"))))
  log.Println("Serving website at:", *addr)
  http.ListenAndServe(*addr, mux)
}
```

这几行 Go 代码真正突出了这种语言和 Go 标准库的美。它们代表了一个完整的、高度可扩展的、静态网站托管程序。该程序接受一个`addr`标志，并使用熟悉的`http.ServeMux`类型从名为`public`的文件夹中提供静态文件。

### 提示

在构建下面的几个页面时，我们将编写大量的 HTML 和 JavaScript 代码。由于这不是 Go 代码，如果您不想全部输入，可以随时转到本书的 GitHub 存储库，从[`github.com/matryer/goblueprints`](https://github.com/matryer/goblueprints)复制并粘贴。

## 显示投票列表的索引页面

在`web`文件夹内创建`public`文件夹，并在其中添加`index.html`文件，然后写入以下 HTML 代码：

```go
<!DOCTYPE html>
<html>
<head>
  <title>Polls</title>
  <link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css">
</head>
<body>
</body>
</html>
```

我们将再次使用 Bootstrap 来使我们的简单 UI 看起来漂亮，但是我们需要在 HTML 页面的`body`标签中添加两个额外的部分。首先，添加将显示投票列表的 DOM 元素：

```go
<div class="container">
  <div class="col-md-4"></div>
  <div class="col-md-4">
    <h1>Polls</h1>
    <ul id="polls"></ul>
    <a href="new.html" class="btn btn-primary">Create new poll</a>
  </div>
  <div class="col-md-4"></div>
</div>
```

在这里，我们使用 Bootstrap 的网格系统来居中对齐我们的内容，内容由一系列投票列表和一个指向`new.html`的链接组成，用户可以在那里创建新的投票。

接下来，在上述代码下面添加以下`script`标签和 JavaScript：

```go
<script src="img/jquery.min.js"></script>
<script src="img/bootstrap.min.js"></script>
<script>
  $(function(){
    var update = function(){
      $.get("http://localhost:8080/polls/?key=abc123", null, null, "json")
        .done(function(polls){
          $("#polls").empty();
          for (var p in polls) {
            var poll = polls[p];
            $("#polls").append(
              $("<li>").append(
                $("<a>")
                  .attr("href", "view.html?poll=polls/" + poll.id)
                  .text(poll.title)
              )
            )
          }
        }
      );
      window.setTimeout(update, 10000);
    }
    update();
  });
</script>
```

我们使用 jQuery 的`$.get`函数向我们的 Web 服务发出 AJAX 请求。我们还将 API URL 硬编码。在实践中，您可能会决定反对这样做，但至少应该使用域名来进行抽象。一旦投票加载完成，我们使用 jQuery 构建一个包含指向`view.html`页面的超链接的列表，并将投票的 ID 作为查询参数传递。

## 创建新投票的页面

为了允许用户创建新的投票，创建一个名为`new.html`的文件放在`public`文件夹中，并将以下 HTML 代码添加到文件中：

```go
<!DOCTYPE html>
<html>
<head>
  <title>Create Poll</title>
  <link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css">
</head>
<body>
  <script src="img/jquery.min.js"></script>
  <script src="img/bootstrap.min.js"></script>
</body>
</html>
```

我们将为 HTML 表单添加元素，以捕获创建新投票时所需的信息，即投票的标题和选项。在`body`标签内添加以下代码：

```go
<div class="container">
  <div class="col-md-4"></div>
  <form id="poll" role="form" class="col-md-4">
    <h2>Create Poll</h2>
    <div class="form-group">
      <label for="title">Title</label>
      <input type="text" class="form-control" id="title" placeholder="Title">
    </div>
    <div class="form-group">
      <label for="options">Options</label>
      <input type="text" class="form-control" id="options" placeholder="Options">
      <p class="help-block">Comma separated</p>
    </div>
    <button type="submit" class="btn btn-primary">Create Poll</button> or <a href="/">cancel</a>
  </form>
  <div class="col-md-4"></div>
</div>
```

由于我们的 API 使用 JSON，我们需要做一些工作，将 HTML 表单转换为 JSON 编码的字符串，并将逗号分隔的选项字符串拆分为选项数组。添加以下`script`标签：

```go
<script>
  $(function(){
    var form = $("form#poll");
    form.submit(function(e){
      e.preventDefault();
      var title = form.find("input[id='title']").val();
      var options = form.find("input[id='options']").val();
      options = options.split(",");
      for (var opt in options) {
        options[opt] = options[opt].trim();
      }
      $.post("http://localhost:8080/polls/?key=abc123",
        JSON.stringify({
          title: title, options: options
        })
      ).done(function(d, s, r){
        location.href = "view.html?poll=" + r.getResponseHeader("Location");
      });
    });
  });
</script>
```

在这里，我们添加一个监听器来监听表单的`submit`事件，并使用 jQuery 的`val`方法来收集输入值。我们用逗号分隔选项，并在使用`$.post`方法发出`POST`请求到适当的 API 端点之前去除空格。`JSON.stringify`允许我们将数据对象转换为 JSON 字符串，并将该字符串用作请求的主体，正如 API 所期望的那样。成功后，我们提取`Location`头并将用户重定向到`view.html`页面，将新创建的投票作为参数传递。

## 显示投票详细信息的页面

我们需要完成应用程序的最终页面是`view.html`页面，用户可以在该页面上查看投票的详细信息和实时结果。在`public`文件夹中创建一个名为`view.html`的新文件，并将以下 HTML 代码添加到其中：

```go
<!DOCTYPE html>
<html>
<head>
  <title>View Poll</title>
  <link rel="stylesheet" href="//maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css">
</head>
<body>
  <div class="container">
    <div class="col-md-4"></div>
    <div class="col-md-4">
      <h1 data-field="title">...</h1>
      <ul id="options"></ul>
      <div id="chart"></div>
      <div>
        <button class="btn btn-sm" id="delete">Delete this poll</button>
      </div>
    </div>
    <div class="col-md-4"></div>
  </div>
</body>
</html>
```

这个页面与其他页面大部分相似；它包含用于呈现投票标题、选项和饼图的元素。我们将使用谷歌的可视化 API 与我们的 API 结合，呈现结果。在`view.html`的最后一个`div`标签下（并在闭合的`body`标签上方），添加以下`script`标签：

```go
<script src="img/"></script>
<script src="img/jquery.min.js"></script>
<script src="img/bootstrap.min.js"></script>
<script>
google.load('visualization', '1.0', {'packages':['corechart']});
google.setOnLoadCallback(function(){
  $(function(){
    var chart;
    var poll = location.href.split("poll=")[1];
    var update = function(){
      $.get("http://localhost:8080/"+poll+"?key=abc123", null, null, "json")
        .done(function(polls){
          var poll = polls[0];
          $('[data-field="title"]').text(poll.title);
          $("#options").empty();
          for (var o in poll.results) {
            $("#options").append(
              $("<li>").append(
                $("<small>").addClass("label label-default").text(poll.results[o]),
                " ", o
              )
            )
          }
          if (poll.results) {
            var data = new google.visualization.DataTable();
            data.addColumn("string","Option");
            data.addColumn("number","Votes");
            for (var o in poll.results) {
              data.addRow([o, poll.results[o]])
            }
            if (!chart) {
              chart = new google.visualization.PieChart(document.getElementById('chart'));
            }
            chart.draw(data, {is3D: true});
          }
        }
      );
      window.setTimeout(update, 1000);
    };
    update();
    $("#delete").click(function(){
      if (confirm("Sure?")) {
        $.ajax({
          url:"http://localhost:8080/"+poll+"?key=abc123",
          type:"DELETE"
        })
        .done(function(){
          location.href = "/";
        })
      }
    });
  });
});
</script>
```

我们包括我们将需要为页面提供动力的依赖项，jQuery 和 Bootstrap，以及 Google JavaScript API。该代码从谷歌加载适当的可视化库，并在提取 URL 上的投票 ID 时等待 DOM 元素加载，通过在`poll=`上拆分它。然后，我们创建一个名为`update`的变量，表示负责生成页面视图的函数。采用这种方法是为了使我们能够使用`window.setTimeout`轻松地发出对视图的定期调用。在`update`函数内部，我们使用`$.get`向我们的`/polls/{id}`端点发出`GET`请求，将`{id}`替换为我们之前从 URL 中提取的实际 ID。一旦投票加载完成，我们更新页面上的标题，并遍历选项以将它们添加到列表中。如果有结果（请记住在上一章中，`results`映射仅在开始计票时才添加到数据中），我们创建一个新的`google.visualization.PieChart`对象，并构建一个包含结果的`google.visualization.DataTable`对象。调用图表上的`draw`会导致它呈现数据，从而使用最新的数字更新图表。然后，我们使用`setTimeout`告诉我们的代码在另一个秒内再次调用`update`。

最后，我们绑定到我们页面上添加的`delete`按钮的`click`事件，并在询问用户是否确定后，向投票 URL 发出`DELETE`请求，然后将其重定向回主页。这个请求实际上会导致首先进行`OPTIONS`请求，请求权限，这就是为什么我们在之前的`handlePolls`函数中添加了显式支持的原因。

# 运行解决方案

在过去的两章中，我们构建了许多组件，现在是时候看到它们一起工作了。本节包含了您需要使所有项目运行的所有内容，假设您已经按照上一章开头描述的那样正确设置了环境。本节假设您有一个包含四个子文件夹的单个文件夹：`api`，`counter`，`twittervotes`和`web`。

假设没有任何运行中的内容，按照以下步骤进行（每个步骤在自己的终端窗口中）：

1.  在顶层文件夹中，启动`nsqlookupd`守护进程：

```go

nsqlookupd

```

1.  在相同的目录中，启动`nsqd`守护进程：

```go

nsqd --lookupd-tcp-address=localhost:4160

```

1.  启动 MongoDB 守护进程：

```go

mongod

```

1.  导航到`counter`文件夹并构建并运行它：

```go

cd counter

go build –o counter

./counter

```

1.  导航到`twittervotes`文件夹并构建并运行它。确保你设置了适当的环境变量，否则当你运行程序时会看到错误：

```go

cd ../twittervotes

go build –o twittervotes

./twittervotes

```

1.  导航到`api`文件夹并构建并运行它：

```go

cd ../api

go build –o api

./api

```

1.  导航到`web`文件夹并构建并运行它：

```go

cd ../web

go build –o web

./web

```

现在一切都在运行，打开浏览器，转到`http://localhost:8081/`。使用用户界面，创建一个名为`Moods`的投票，并输入选项`happy,sad,fail,and success`。这些是足够常见的词，我们很可能会在 Twitter 上看到一些相关的活动。

创建了投票后，您将被带到查看页面，在那里您将开始看到结果的出现。等待几秒钟，享受您的辛勤工作的成果，因为 UI 会实时更新，显示实时结果。

![运行解决方案](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/go-prog-bp/img/Image00012.jpg)

# 总结

在本章中，我们通过一个高度可扩展的 RESTful API 公开了我们社交投票解决方案的数据，并构建了一个简单的网站，该网站使用 API 来提供用户与之交互的直观方式。该网站仅包含静态内容，没有服务器端处理（因为 API 为我们处理了繁重的工作）。这使我们能够在静态托管网站（如[bitballoon.com](http://bitballoon.com)）上以非常低的成本托管网站，或者将文件分发到内容交付网络。

在我们的 API 服务中，我们学会了如何在不破坏或混淆标准库中的处理程序模式的情况下在处理程序之间共享数据。我们还看到编写包装处理程序函数如何使我们能够以一种非常简单和直观的方式构建功能管道。

我们编写了一些基本的编码和解码函数，目前只是简单地包装了`encoding/json`包中的对应函数，以后可以改进以支持一系列不同的数据表示，而不改变我们代码的内部接口。我们编写了一些简单的辅助函数，使得响应数据请求变得容易，同时提供了相同类型的抽象，使我们能够以后发展我们的 API。

我们看到，对于简单的情况，切换到 HTTP 方法是支持单个端点的许多功能的一种优雅方式。我们还看到，通过添加几行额外的代码，我们能够构建支持 CORS 的功能，允许在不同域上运行的应用程序与我们的服务交互，而无需像 JSONP 那样的黑客。

本章的代码与我们在上一章中所做的工作结合起来，提供了一个实际的、可投入生产的解决方案，实现了以下流程：

1.  用户在网站上点击**创建投票**按钮，并输入投票的标题和选项。

1.  在浏览器中运行的 JavaScript 将数据编码为 JSON 字符串，并将其发送到我们的 API 的`POST`请求的主体中。

1.  API 收到请求后，验证 API 密钥，设置数据库会话，并将其存储在我们的变量映射中，调用 `handlePolls` 函数处理请求，并将新的投票存储在 MongoDB 数据库中。

1.  API 将用户重定向到新创建的投票的 `view.html` 页面。

1.  与此同时，`twittervotes` 程序从数据库中加载所有投票，包括新的投票，并打开到 Twitter 的连接，过滤代表投票选项的标签。

1.  当选票进来时，`twittervotes` 将它们推送到 NSQ。

1.  `counter` 程序正在监听适当的频道，并注意到投票的到来，计算每一个，并定期更新数据库。

1.  用户在 `view.html` 页面上看到结果显示（并刷新），因为网站不断地向所选投票的 API 端点发出 `GET` 请求。

在下一章中，我们将发展我们的 API 和 web 技能，构建一个全新的创业应用程序 Meander。我们将看到如何在几行 Go 代码中编写一个完整的静态 web 服务器，并探索一种在官方不支持的语言中表示枚举器的有趣方式！
