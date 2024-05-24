# Go 依赖注入实用指南（一）

> 原文：[`zh.annas-archive.org/md5/87633C3DBA89BFAAFD7E5238CC73EA73`](https://zh.annas-archive.org/md5/87633C3DBA89BFAAFD7E5238CC73EA73)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 前言

你好！这本书旨在介绍如何在 Go 语言中进行依赖注入。也许你会惊讶地发现，在 Go 语言中有许多不同的方法可以应用依赖注入，在本书中，我们将讨论六种不同的方法，有时它们还可以相互补充。

依赖注入，像许多软件工程概念一样，很容易被误解，因此本文试图解决这个问题。它深入探讨了相关概念，如 SOLID 原则、代码异味和测试诱导的破坏，以便提供更广泛和更实用的视角。

《Go 语言依赖注入实战》的目标不仅是教会你如何应用依赖注入，还有何时、何地以及何时不应该应用。每种方法都有明确定义；我们讨论它的优缺点，以及何时最适合应用该方法。此外，每种方法都会使用重要的示例逐步应用。

尽管我非常喜欢依赖注入，但它并不总是适合所有情况。这本书还将帮助你发现应用依赖注入可能不是最佳选择的情况。

在介绍每种依赖注入方法时，我会请你停下来，退后一步，考虑以下问题。这种技术试图解决什么问题？在你应用这种方法后，你的代码会是什么样子？如果这些问题的答案不会很快出现，不要担心；到本书结束时，它们会出现的。

愉快的编码！

# 这本书适合谁

这本书适用于希望他们的代码易于阅读、测试和维护的开发人员。它适用于来自面向对象背景的开发人员，他们希望更多地了解 Go，以及相信高质量代码不仅仅是交付一个特定功能的开发人员。

毕竟，编写代码很容易。同样，让单个测试用例通过也很简单。创建代码，使得测试在添加额外功能的几个月或几年后仍然通过，这几乎是不可能的。

为了能够持续地以这个水平交付代码，我们需要很多巧妙的技巧。这本书希望不仅能够装备你这些技巧，还能够给你应用它们的智慧。

# 为了充分利用这本书

尽管依赖注入和本书中讨论的许多其他编程概念并不简单或直观，但本书在假定很少的知识的情况下介绍它们。

也就是说，我们假设以下内容：

+   你具有构建和测试 Go 代码的基本经验。

+   由于之前使用 Go 或面向对象的语言（如 Java 或 Scala）的经验，你对对象/类的概念感到舒适。

此外，至少对构建和使用基于 HTTP 的 REST API 有一定的了解会很有益。在第四章中，《ACME 注册服务简介》，我们将介绍一个示例 REST 服务，它将成为本书许多示例的基础。为了能够运行这个示例服务，你需要在开发环境中安装和配置 MySQL 数据库服务，并能够自定义提供的配置以匹配你的本地环境。本书提供的所有命令都是在 OSX 下开发和测试的，并且应该可以在任何基于 Linux 或 Unix 的系统上无需修改地工作。使用基于 Windows 的开发环境的开发人员需要在运行这些命令之前进行调整。

# 下载示例代码文件

你可以从[www.packt.com](http://www.packt.com)的账户中下载本书的示例代码文件。如果你在其他地方购买了这本书，你可以访问[www.packt.com/support](http://www.packt.com/support)并注册，以便直接通过电子邮件接收文件。

你可以通过以下步骤下载代码文件：

1.  登录或注册[www.packt.com](http://www.packt.com)。

1.  选择“支持”选项卡。

1.  单击“代码下载和勘误”。

1.  在搜索框中输入书名，然后按照屏幕上的说明进行操作。

下载文件后，请确保使用最新版本的解压缩软件解压缩文件夹：

+   WinRAR/7-Zip for Windows

+   Zipeg/iZip/UnRarX for Mac

+   7-Zip/PeaZip for Linux

该书的代码包也托管在 GitHub 上，网址为[**https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go**](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go)。如果代码有更新，将在现有的 GitHub 存储库上进行更新。

我们还有其他代码包，来自我们丰富的图书和视频目录，可在[`github.com/PacktPublishing/`](https://github.com/PacktPublishing/)上找到。去看看吧！

# 下载彩色图像

我们还提供了一个 PDF 文件，其中包含本书中使用的屏幕截图/图表的彩色图像。您可以在这里下载：[`www.packtpub.com/sites/default/files/downloads/Bookname_ColorImages.pdf`](http://www.packtpub.com/sites/default/files/downloads/Bookname_ColorImages.pdf)。

# 使用的约定

本书中使用了许多文本约定。

`CodeInText`：表示文本中的代码词、数据库表名、文件夹名、文件名、文件扩展名、路径名、虚拟 URL、用户输入和 Twitter 句柄。例如："将下载的`WebStorm-10*.dmg`磁盘映像文件挂载为系统中的另一个磁盘。"

代码块设置如下：

```go
html, body, #map {
 height: 100%; 
 margin: 0;
 padding: 0
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

任何命令行输入或输出都以以下方式编写：

```go
$ mkdir css
$ cd css
```

**粗体**：表示新术语、重要单词或屏幕上看到的单词。例如，菜单或对话框中的单词会以这种方式出现在文本中。例如："从管理面板中选择系统信息。"

警告或重要提示会以这种方式出现。

提示和技巧会以这种方式出现。


# 第一章：永远不要停止追求更好

你想要更容易维护的代码吗？更容易测试吗？更容易扩展吗？**依赖注入**（**DI**）可能正是你需要的工具。

在本章中，我们将以一种有点非典型的方式定义 DI，并探讨可能表明你需要 DI 的代码异味。我们还将简要讨论 Go 以及我希望你如何对待本书中提出的想法。

你准备好和我一起踏上更好的 Go 代码之旅了吗？

我们将涵盖以下主题：

+   DI 为什么重要？

+   什么是 DI？

+   何时应用 DI？

+   我如何作为 Go 程序员改进？

# 技术要求

希望你已经安装了 Go。它可以从[`golang.org/`](https://golang.org/) 或你喜欢的软件包管理器下载。

本章中的所有代码都可以在[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch01`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch01)找到。

# DI 为什么重要？

作为专业人士，我们永远不应该停止学习。学习是确保我们保持需求并继续为客户提供价值的唯一真正途径。医生、律师和科学家都是备受尊敬的专业人士，他们都专注于不断学习。为什么程序员应该有所不同呢？

在本书中，我们将开始一段旅程，从一些*完成工作*的代码开始，然后通过有选择地应用 Go 中可用的各种 DI 方法，我们将把它转变成更容易维护、测试和扩展的东西。

本书中并非所有内容都是*传统*的，甚至可能不是*惯用*的，但我希望你在否定之前*尝试一下*。如果你喜欢，太棒了。如果不喜欢，至少你学到了你不想做什么。

# 那么，我如何定义 DI？

DI 是*以这样的方式编码，使得我们依赖的资源（即函数或结构）是抽象的*。因为这些依赖是抽象的，对它们的更改不需要更改我们的代码。这个花哨的词是**解耦**。

这里使用的抽象一词可能有点误导。我不是指像 Java 中那样的抽象类；Go 没有那个。不过，Go 确实有接口和函数文字（也称为**闭包**）。

考虑以下接口的例子和使用它的`SavePerson()`函数：

```go
// Saver persists the supplied bytes
type Saver interface {
  Save(data []byte) error
}

// SavePerson will validate and persist the supplied person
func SavePerson(person *Person, saver Saver) error {
  // validate the inputs
  err := person.validate()
  if err != nil {
    return err
  }

  // encode person to bytes
  bytes, err := person.encode()
  if err != nil {
    return err
  }

  // save the person and return the result
  return saver.Save(bytes)
}

// Person data object
type Person struct {
   Name  string
   Phone string
}

// validate the person object
func (p *Person) validate() error {
   if p.Name == "" {
      return errors.New("name missing")
   }

   if p.Phone == "" {
      return errors.New("phone missing")
   }

   return nil
}

// convert the person into bytes
func (p *Person) encode() ([]byte, error) {
   return json.Marshal(p)
}
```

在前面的例子中，`Saver`是做什么的？它在某个地方保存一些`bytes`。它是如何做到的？我们不知道，在编写`SavePerson`函数时，我们也不关心。

让我们看另一个使用函数文字的例子**：**

```go
// LoadPerson will load the requested person by ID.
// Errors include: invalid ID, missing person and failure to load 
// or decode.
func LoadPerson(ID int, decodePerson func(data []byte) *Person) (*Person, error) {
  // validate the input
  if ID <= 0 {
    return nil, fmt.Errorf("invalid ID '%d' supplied", ID)
  }

  // load from storage
  bytes, err := loadPerson(ID)
  if err != nil {
    return nil, err
  }

  // decode bytes and return
  return decodePerson(bytes), nil
}
```

`decodePerson`是做什么的？它将`bytes`转换为一个人。怎么做？我们现在不需要知道。

这是我要向你强调的 DI 的第一个优点：

**DI 通过以抽象或通用的方式表达依赖关系，减少了在处理一段代码时所需的知识**

现在，假设前面的代码来自一个将数据存储在**网络文件共享**（**NFS**）中的系统。我们如何为此编写单元测试？始终访问 NFS 将是一种痛苦。由于完全不相关的问题，例如网络连接问题，任何此类测试也会比应该更频繁地失败。

另一方面，通过依赖于抽象，我们可以用虚假代码替换保存到 NFS 的代码。这样，我们只测试我们的代码与 NFS 隔离的情况，如下面的代码所示：

```go
func TestSavePerson_happyPath(t *testing.T) {
   // input
   in := &Person{
      Name:  "Sophia",
      Phone: "0123456789",
   }

   // mock the NFS
   mockNFS := &mockSaver{}
   mockNFS.On("Save", mock.Anything).Return(nil).Once()

   // Call Save
   resultErr := SavePerson(in, mockNFS)

   // validate result
   assert.NoError(t, resultErr)
   assert.True(t, mockNFS.AssertExpectations(t))
}
```

不要担心前面的代码看起来陌生；我们将在本书的后面深入研究所有部分。

这带我们来到 DI 的第二个优点：

**DI 使我们能够在不依赖于我们的依赖关系的情况下测试我们的代码**

考虑前面的例子，我们如何测试我们的错误处理代码？我们可以通过一些外部脚本关闭 NFS，每次运行测试时，但这可能会很慢，肯定会惹恼依赖它的其他人。

另一方面，我们可以快速制作一个总是失败的假`Saver`，如下所示：

```go
func TestSavePerson_nfsAlwaysFails(t *testing.T) {
   // input
   in := &Person{
      Name:  "Sophia",
      Phone: "0123456789",
   }

   // mock the NFS
   mockNFS := &mockSaver{}
   mockNFS.On("Save", mock.Anything).Return(errors.New("save failed")).Once()

   // Call Save
   resultErr := SavePerson(in, mockNFS)

   // validate result
   assert.Error(t, resultErr)
   assert.True(t, mockNFS.AssertExpectations(t))
}
```

上面的测试快速、可预测、可靠。这是我们测试中想要的一切！

这给了我们 DI 的第三个优势：

**DI 使我们能够快速、可靠地测试其他情况**

不要忘记 DI 的传统销售点。如果明天我们决定将保存到 NoSQL 数据库而不是我们的 NFS，我们的`SavePerson`代码将如何改变？一点也不。我们只需要编写一个新的`Saver`实现，这给了我们 DI 的第四个优势：

**DI 减少了扩展或更改的影响**

归根结底，DI 是一个工具——一个方便的工具，但不是魔法子弹。它是一个可以使代码更容易理解、测试、扩展和重用的工具，也可以帮助减少常常困扰新 Go 开发人员的循环依赖问题。

# 表明您可能需要 DI 的代码气味

俗话说“对于只有一把锤子的人来说，每个问题都像一颗钉子”，这句话虽然古老，但在编程中却从未比现在更真实。作为专业人士，我们应该不断努力获取更多的工具，以便更好地应对工作中遇到的任何问题。DI 虽然是一个非常有用的工具，但只对特定的问题有效。在我们的情况下，这些问题是**代码气味**。代码气味是代码中潜在更深层问题的指示。

有许多不同类型的代码气味；在本节中，我们将仅讨论那些可以通过 DI 缓解的气味。在后面的章节中，我们将在试图从我们的代码中消除它们时引用这些气味。

代码气味通常可以分为四个不同的类别：

+   代码膨胀

+   对变化的抵抗

+   徒劳的努力

+   紧耦合

# 代码膨胀

代码膨胀的气味是指已经添加到结构体或函数中的笨重代码块，使得它们变得难以理解、维护和测试。在旧代码中经常发现，它们往往是逐渐恶化和缺乏维护的结果，而不是有意的选择。

它们可以通过对源代码进行视觉扫描或使用循环复杂度检查器（指示代码复杂性的软件度量标准）来发现，例如 gocyclo（[`github.com/fzipp/gocyclo`](https://github.com/fzipp/gocyclo)）。

这些气味包括以下内容：

+   **长方法**：虽然代码是在计算机上运行的，但是它是为人类编写的。任何超过 30 行的方法都应该分成更小的块。虽然对计算机没有影响，但对我们人类来说更容易理解。

+   **长结构体**：与长方法类似，结构体越长，就越难理解，因此也更难维护。长结构体通常也表明结构体做得太多。将一个结构体分成几个较小的结构体也是增加代码可重用性潜力的好方法。

+   **长参数列表**：长参数列表也表明该方法可能做了太多的事情。在添加新功能时，很容易向现有函数添加新参数，以适应新的用例。这是一个很危险的斜坡。这个新参数要么对现有用例是可选的/不必要的，要么表明方法的复杂性显著增加。

+   **长条件块**：Switch 语句很棒。问题在于它们很容易被滥用，而且往往像谚语中的兔子一样繁殖。然而，最重要的问题可能是它们对代码的可读性的影响。长条件块占用大量空间，打断了函数的可读性。考虑以下代码：

```go
func AppendValue(buffer []byte, in interface{}) []byte{
   var value []byte

   // convert input to []byte
   switch concrete := in.(type) {
   case []byte:
      value = concrete

   case string:
      value = []byte(concrete)

   case int64:
      value = []byte(strconv.FormatInt(concrete, 10))

   case bool:
      value = []byte(strconv.FormatBool(concrete))

   case float64:
      value = []byte(strconv.FormatFloat(concrete, 'e', 3, 64))
   }

   buffer = append(buffer, value...)
   return buffer
}
```

通过将`interface{}`作为输入，我们几乎被迫使用类似这样的开关。我们最好改为从`interface{}`改为接口，然后向接口添加必要的操作。这种方法在标准库中的`json.Marshaller`和`driver.Valuer`接口中得到了很好的说明。

将 DI 应用于这些问题通常会通过将其分解为更小的、独立的部分来减少代码的复杂性，从而使其更易于理解、维护和测试。

# 对变化的抵抗

这些情况下很难和/或缓慢地添加新功能。同样，测试通常更难编写，特别是对于失败条件的测试。与代码膨胀类似，这些问题可能是逐渐恶化和缺乏维护的结果，但也可能是由于缺乏前期规划或糟糕的 API 设计引起的。

它们可以通过检查拉取请求日志或提交历史来找到，特别是确定新功能是否需要在代码的不同部分进行许多小的更改。

如果您的团队跟踪功能速度，并且您注意到它在下降，这也可能是一个原因。

这些问题包括以下内容：

+   **散弹手术**：这是指对一个结构体进行的小改动需要改变其他结构体。这些变化意味着使用的组织或抽象是不正确的。通常，所有这些更改应该在一个类中。

在下面的例子中，您可以看到向人员数据添加电子邮件字段将导致更改所有三个结构体（`Presenter`、`Validator`和`Saver`）：

```go
// Renderer will render a person to the supplied writer
type Renderer struct{}

func (r Renderer) render(name, phone string, output io.Writer) {
  // output the person
}

// Validator will validate the supplied person has all the 
// required fields
type Validator struct{}

func (v Validator) validate(name, phone string) error {
  // validate the person
  return nil
}

// Saver will save the supplied person to the DB
type Saver struct{}

func (s *Saver) Save(db *sql.DB, name, phone string) {
  // save the person to db
}
```

+   **泄漏实现细节**：Go 社区中更受欢迎的习语之一是*接受接口，返回结构体*。这是一个引人注目的短语，但它的简单性掩盖了它的巧妙之处。当一个函数接受一个结构体时，它将用户与特定的实现联系在一起，这种严格的关系使得未来的更改或附加使用变得困难。此外，如果实现细节发生变化，API 也会发生变化，并迫使用户进行更改。

将 DI 应用于这些问题通常是对未来的良好投资。虽然不修复它们不会致命，但代码将逐渐恶化，直到你处理谚语中的*大泥球*。你知道这种类型——一个没有人理解、没有人信任的包，只有勇敢或愚蠢的人愿意进行更改。DI 使您能够脱离实现选择，从而更容易地重构、测试和维护代码的小块。

# 浪费的努力

这些问题是代码维护成本高于必要成本的情况。它们通常是由懒惰或缺乏经验引起的。复制/粘贴代码总是比仔细重构代码更容易。问题是，像这样编码就像吃不健康的零食。在当时感觉很棒，但长期后果很糟糕。

它们可以通过对源代码进行批判性审视并问自己*我真的需要这段代码吗？*或者*我能让这更容易理解吗？*来找到。

使用诸如 dupl ([`github.com/mibk/dupl`](https://github.com/mibk/dupl))或 PMD ([`pmd.github.io/`](https://pmd.github.io/))之类的工具也将帮助您识别需要调查的代码区域。

这些问题包括以下内容：

+   **过多的重复代码**：首先，请不要对此变得过分狂热。虽然在大多数情况下，重复的代码是一件坏事，但有时复制代码可以导致一个更容易维护和发展的系统。我们将在第八章中处理这种问题的常见来源，*通过配置进行依赖注入*。

+   **过多的注释**：为后来的人留下一条便签，即使只有 6 个月后的自己，也是一件友好和专业的事情。但当这个注释变成一篇文章时，就是重构的时候了。

```go
// Excessive comments
func outputOrderedPeopleA(in []*Person) {
  // This code orders people by name.
  // In cases where the name is the same, it will order by 
  // phone number.
  // The sort algorithm used is a bubble sort
  // WARNING: this sort will change the items of the input array
  for _, p := range in {
    // ... sort code removed ...
  }

  outputPeople(in)
}

// Comments replaced with descriptive names
func outputOrderedPeopleB(in []*Person) {
  sortPeople(in)
  outputPeople(in)
}
```

+   **过于复杂的代码**：代码越难让其他人理解，它就越糟糕。通常，这是某人试图过于花哨或者没有花足够的精力在结构或命名上的结果。从更自私的角度来看，如果只有你一个人能理解一段代码，那么只有你能够处理它。也就是说，你注定要永远维护它。以下代码是做什么的：

```go
for a := float64(0); a < 360; a++ {
   ra := math.Pi * 2 * a / 360
   x := r*math.Sin(ra) + v
   y := r*math.Cos(ra) + v
   i.Set(int(x), int(y), c)
}
```

+   **DRY/WET 代码**：**不要重复自己**（DRY）原则旨在通过将责任分组并提供清晰的抽象来减少重复的工作。相比之下，在 WET 代码中，有时也被称为**浪费每个人的时间**代码，你会发现同样的责任出现在许多地方。这种气味通常出现在格式化或转换代码中。这种代码应该存在于系统边界，也就是说，转换用户输入或格式化输出。

虽然许多这些气味可以在没有依赖注入的情况下修复，但依赖注入提供了一种更容易的方式来将重复的工作转移到一个抽象中，然后可以用来减少重复和提高代码的可读性和可维护性。

# 紧耦合

对于人来说，紧耦合可能是一件好事。但对于 Go 代码来说，真的不是。耦合是衡量对象之间关系或依赖程度的指标。当存在紧耦合时，这种相互依赖会迫使对象或包一起发展，增加了复杂性和维护成本。

耦合相关的气味可能是最隐匿和顽固的，但处理起来也是最有回报的。它们通常是由于缺乏面向对象设计或接口使用不足造成的。

遗憾的是，我没有一个方便的工具来帮助你找到这些气味，但我相信，在本书结束时，你将毫无困难地发现并处理它们。

经常情况下，我发现先以紧密耦合的形式实现一个功能，然后逐步解耦并彻底单元测试我的代码，然后再提交，这对我来说是特别有帮助的，尤其是在正确的抽象不明显的情况下。

这些气味包括以下内容：

+   **依赖于上帝对象**：这些是*知道太多*或*做太多*的大对象。虽然这是一种普遍的代码气味，应该像瘟疫一样避免，但从依赖注入的角度来看，问题在于太多的代码依赖于这个对象。当它们存在并且我们不小心时，很快 Go 就会因为循环依赖而拒绝编译。有趣的是，Go 认为依赖和导入不是在对象级别，而是在包级别。因此，我们也必须避免上帝包。我们将在第八章中解决一个非常常见的上帝对象问题，*通过配置进行依赖注入*。

+   **循环依赖**：这是指包 A 依赖于包 B，包 B 又依赖于包 A。这是一个容易犯的错误，有时很难摆脱。

在下面的例子中，虽然配置可以说是一个`上帝`对象，因此是一种代码气味，但我很难找到更好的方法来从一个单独的 JSON 文件中导入配置。相反，我会认为需要解决的问题是`orders`包对`config`包的使用。一个典型的上帝配置对象如下：

```go
package config

import ...

// Config defines the JSON format of the config file
type Config struct {
   // Address is the host and port to bind to.  
   // Default 0.0.0.0:8080
   Address string

   // DefaultCurrency is the default currency of the system
   DefaultCurrency payment.Currency
}

// Load will load the JSON config from the file supplied
func Load(filename string) (*Config, error) {
   // TODO: load currency from file
   return nil, errors.New("not implemented yet")
}
```

在对`config`包的尝试使用中，你可以看到`Currency`类型属于`Package`包，因此在`config`中包含它，如前面的例子所示，会导致循环依赖：

```go
package payment

import ...

// Currency is custom type for currency
type Currency string

// Processor processes payments
type Processor struct {
   Config *config.Config
}

// Pay makes a payment in the default currency
func (p *Processor) Pay(amount float64) error {
   // TODO: implement me
   return errors.New("not implemented yet")
}
```

+   **对象混乱**：当一个对象对另一个对象的内部知识和/或访问过多时，或者换句话说，*对象之间的封装不足*。因为这些对象*紧密耦合*，它们经常需要一起发展，增加了理解代码和维护代码的成本。考虑以下代码：

```go
type PageLoader struct {
}

func (o *PageLoader) LoadPage(url string) ([]byte, error) {
   b := newFetcher()

   // check cache
   payload, err := b.cache.Get(url)
   if err == nil {
      // found in cache
      return payload, nil
   }

   // call upstream
   resp, err := b.httpClient.Get(url)
   if err != nil {
      return nil, err
   }
   defer resp.Body.Close()

   // extract data from HTTP response
   payload, err = ioutil.ReadAll(resp.Body)
   if err != nil {
      return nil, err
   }

   // save to cache asynchronously
   go func(key string, value []byte) {
      b.cache.Set(key, value)
   }(url, payload)

   // return
   return payload, nil
}

type Fetcher struct {
   httpClient http.Client
   cache      *Cache
}

```

在这个例子中，`PageLoader`重复调用`Fetcher`的成员变量。以至于，如果`Fetcher`的实现发生了变化，`PageLoader`很可能会受到影响。在这种情况下，这两个对象应该合并在一起，因为`PageLoader`没有额外的功能。

+   **Yo-yo problem**：这种情况的标准定义是*当继承图如此漫长和复杂以至于程序员不得不不断地翻阅代码才能理解它*。鉴于 Go 没有继承，你可能会认为我们不会遇到这个问题。然而，如果你努力尝试，通过过度的组合是可能的。为了解决这个问题，最好保持关系尽可能浅和抽象。这样，我们在进行更改时可以集中在一个更小的范围内，并将许多小对象组合成一个更大的系统。

+   **Feature envy**：当一个函数广泛使用另一个对象时，它就是嫉妒它。通常，这表明该函数应该从它所嫉妒的对象中移开。DI 可能不是解决这个问题的方法，但这种情况表明高耦合，因此是考虑应用 DI 技术的指标：

```go
func doSearchWithEnvy(request searchRequest) ([]searchResults, error) {
   // validate request
   if request.query == "" {
      return nil, errors.New("search term is missing")
   }
   if request.start.IsZero() || request.start.After(time.Now()) {
      return nil, errors.New("start time is missing or invalid")
   }
   if request.end.IsZero() || request.end.Before(request.start) {
      return nil, errors.New("end time is missing or invalid")
   }

   return performSearch(request)
}

func doSearchWithoutEnvy(request searchRequest) ([]searchResults, error) {
   err := request.validate()
   if err != nil {
      return nil, err
   }

   return performSearch(request)
}
```

当你的代码变得不那么耦合时，你会发现各个部分（包、接口和结构）会变得更加专注。这被称为**高内聚**。低耦合和高内聚都是可取的，因为它们使代码更容易理解和处理。

# 健康的怀疑。

当我们阅读本书时，你将看到一些很棒的编码技巧，也会看到一些不太好的。我希望你花一些时间思考哪些是好的，哪些是不好的。持续学习应该与健康的怀疑相结合。对于每种技术，我会列出其利弊，但我希望你能深入思考。问问自己以下问题：

+   这种技术试图实现什么？

+   我应用这种技术后，我的代码会是什么样子？

+   我真的需要它吗？

+   使用这种方法有什么不利之处吗？

即使你内心的怀疑者否定了这种技术，你至少学会了识别自己不喜欢并且不想使用的东西，而学习总是一种胜利。

# 关于符合 Go 的惯例的简短说明

我个人尽量避免使用术语**符合 Go 的惯例**，但是一本 Go 书在某种程度上没有涉及它是不完整的。我避免使用它，因为我经常看到它被用来打击人。基本上，*这不是符合惯例的，因此是错误的*，并且由此推论，*我是符合惯例的，因此比你更好*。我相信编程是一门手艺，虽然手艺在应用中应该有一定的一致性，但是，就像所有手艺一样，它应该是灵活的。毕竟，创新通常是通过弯曲或打破规则来实现的。

那么对我来说，符合 Go 的惯例意味着什么？

我会尽量宽泛地定义它：

+   **使用`gofmt`格式化你的代码**：对我们程序员来说，真的少了一件要争论的事情。这是官方的风格，由官方工具支持。让我们找一些更实质性的事情来争论。

+   阅读，应用，并定期回顾《Effective Go》（[`golang.org/doc/effective_go.html`](https://golang.org/doc/effective_go.html)）和《Code Review Comments》（[`github.com/golang/go/wiki/CodeReviewComments`](https://github.com/golang/go/wiki/CodeReviewComments)）中的想法：这些页面中包含了大量的智慧，以至于可能不可能仅通过一次阅读就能全部领会。

+   **积极应用*Unix 哲学***：它规定我们应该*设计代码只做一件事，但要做得很好，并且与其他代码很好地协同工作**。*

虽然对我来说，这三件事是最低限度的，但还有一些其他的想法也很有共鸣：

+   **接受接口并返回结构体**：虽然接受接口会导致代码解耦，但返回结构体可能会让你感到矛盾。我知道一开始我也是这样认为的。虽然输出接口可能会让你感觉它更松散耦合，但实际上并不是。输出只能是一种东西——无论你编码成什么样。如果需要，返回接口是可以的，但强迫自己这样做最终只会让你写更多的代码。

+   **合理的默认值**：自从转向 Go 以来，我发现许多情况下我想要为用户提供配置模块的能力，但这样的配置通常不被使用。在其他语言中，这可能会导致多个构造函数或很少使用的参数，但通过应用这种模式，我们最终得到了一个更清晰的 API 和更少的代码来维护。

# 把你的包袱留在门口

如果你问我*新手 Go 程序员最常犯的错误是什么*？我会毫不犹豫地告诉你，那就是将其他语言的模式带入 Go 中。我知道这是我最初的最大错误。我的第一个 Go 服务看起来像是用 Go 编写的 Java 应用程序。结果不仅是次等的，而且相当痛苦，特别是当我试图实现诸如继承之类的东西时。我在使用`Node.js`中以函数式风格编程 Go 时也有类似的经历。

简而言之，请不要这样做。重新阅读*Effective Go*和 Go 博客，直到您发现自己使用小接口、毫不犹豫地启动 Go 例程、喜欢通道，并想知道为什么您需要的不仅仅是组合来实现良好的多态性。

# 总结

在本章中，我们开始了一段旅程——这段旅程将导致更容易维护、扩展和测试的代码。

我们首先定义了 DI，并检查了它可以给我们带来的一些好处。通过一些例子的帮助，我们看到了这在 Go 中可能是什么样子。

之后，我们开始识别需要注意的代码异味，并通过应用 DI 来解决或减轻这些问题。

最后，我们研究了我认为 Go 代码是什么样子的，并向您提出质疑，对本书中提出的技术持怀疑态度。

# 问题

1.  什么是 DI？

1.  DI 的四个突出优势是什么？

1.  它解决了哪些问题？

1.  为什么持怀疑态度很重要？

1.  对你来说，惯用的 Go 是什么意思？

# 进一步阅读

Packt 还有许多其他关于 DI 和 Go 的学习资源。

+   [`www.packtpub.com/application-development/java-9-dependency-injection`](https://www.packtpub.com/application-development/java-9-dependency-injection)

+   [`www.packtpub.com/application-development/dependency-injection-net-core-20`](https://www.packtpub.com/application-development/dependency-injection-net-core-20)

+   [`www.packtpub.com/networking-and-servers/mastering-go`](https://www.packtpub.com/networking-and-servers/mastering-go)


# 第二章：Go 的 SOLID 设计原则

2002 年，*Robert "Uncle Bob" Martin*出版了《敏捷软件开发，原则，模式和实践》一书，其中他定义了可重用程序的五个原则，他称之为 SOLID 原则。虽然在一个 10 年后发明的编程语言的书中包含这些原则似乎有些奇怪，但这些原则今天仍然是相关的。

在本章中，我们将简要讨论这些原则，它们与**依赖注入**（DI）的关系以及对 Go 意味着什么。SOLID 是五个流行的面向对象软件设计原则的首字母缩写：

+   单一责任原则

+   开闭原则

+   Liskov 替换原则

+   接口隔离原则

+   依赖反转原则

# 技术要求

本章的唯一要求是对对象和接口有基本的了解，并持开放的态度。

本章中的所有代码都可以在[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch02`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch02)找到。

您将在本章结束时的*进一步阅读*部分中找到本章中提到的其他信息和参考链接。

# 单一责任原则（SRP）

“一个类应该有一个，且仅有一个，变化的原因。”

–Robert C. Martin

Go 没有类，但如果我们稍微闭上眼睛，将*类*替换为*对象*（结构，函数，接口或包），那么这个概念仍然适用。

我们为什么希望我们的对象只做一件事？让我们看看一些只做一件事的对象：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/e11113bc-3419-40f2-a79b-fe55cdf8a914.png)

这些对象简单易用，用途广泛。

设计对象，使它们只做一件事，在抽象层面上听起来还不错。但你可能会认为为整个系统这样做会增加更多的代码。是的，会增加。但它不会增加复杂性；事实上，它会显著减少复杂性。每段代码会更小，更容易理解，因此更容易测试。这一事实给我们带来了 SRP 的第一个优势：

**SRP 通过将代码分解为更小，更简洁的部分来减少复杂性**

以单一责任原则这样的名字，可以安全地假设它完全是关于责任的，但到目前为止，我们谈论的都是变化。为什么？让我们看一个例子：

```go
// Calculator calculates the test coverage for a directory 
// and it's sub-directories
type Calculator struct {
  // coverage data populated by `Calculate()` method
  data map[string]float64
}

// Calculate will calculate the coverage
func (c *Calculator) Calculate(path string) error {
  // run `go test -cover ./[path]/...` and store the results
  return nil
}

// Output will print the coverage data to the supplied writer
func (c *Calculator) Output(writer io.Writer) {
  for path, result := range c.data {
    fmt.Fprintf(writer, "%s -> %.1f\n", path, result)
  }
}
```

代码看起来合理——一个成员变量和两个方法。但它并不符合 SRP。假设应用程序很成功，我们决定还需要将结果输出到 CSV。我们可以添加一个方法来做到这一点，如下面的代码所示：

```go
// Calculator calculates the test coverage for a directory 
// and it's sub-directories
type Calculator struct {
  // coverage data populated by `Calculate()` method
  data map[string]float64
}

// Calculate will calculate the coverage
func (c *Calculator) Calculate(path string) error {
  // run `go test -cover ./[path]/...` and store the results
  return nil
}

// Output will print the coverage data to the supplied writer
func (c Calculator) Output(writer io.Writer) {
  for path, result := range c.data {
    fmt.Fprintf(writer, "%s -> %.1f\n", path, result)
  }
}

// OutputCSV will print the coverage data to the supplied writer
func (c Calculator) OutputCSV(writer io.Writer) {
  for path, result := range c.data {
    fmt.Fprintf(writer, "%s,%.1f\n", path, result)
  }
}
```

我们已经改变了结构并添加了另一个`Output()`方法。我们为结构添加了更多的责任，在这样做的过程中，我们增加了复杂性。在这个简单的例子中，我们的更改局限于一个方法，因此没有风险破坏以前的代码。然而，随着结构变得越来越大和更加复杂，我们的更改不太可能如此干净。

相反，如果我们将责任分解为`Calculate`和`Output`，那么添加更多的输出只是定义新的结构。此外，如果我们决定不喜欢默认的输出格式，我们可以单独更改它。

让我们尝试不同的实现：

```go
// Calculator calculates the test coverage for a directory 
// and it's sub-directories
type Calculator struct {
  // coverage data populated by `Calculate()` method
  data map[string]float64
}

// Calculate will calculate the coverage
func (c *Calculator) Calculate(path string) error {
  // run `go test -cover ./[path]/...` and store the results
  return nil
}

func (c *Calculator) getData() map[string]float64 {
  // copy and return the map
  return nil
}

type Printer interface {
  Output(data map[string]float64)
}

type DefaultPrinter struct {
  Writer io.Writer
}

// Output implements Printer
func (d *DefaultPrinter) Output(data map[string]float64) {
  for path, result := range data {
    fmt.Fprintf(d.Writer, "%s -> %.1f\n", path, result)
  }
}

type CSVPrinter struct {
  Writer io.Writer
}

// Output implements Printer
func (d *CSVPrinter) Output(data map[string]float64) {
```

```go
for path, result := range data {
    fmt.Fprintf(d.Writer, "%s,%.1f\n", path, result)
  }
}
```

你有没有注意到打印机有什么显著的地方？它们与计算完全没有任何连接。它们可以用于相同格式的任何数据。这导致了 SRP 的第二个优势：

**SRP 增加了代码的潜在可重用性**。

在我们的覆盖率计算器的第一个实现中，要测试`Output()`方法，我们首先要调用`Calculate()`方法。这种方法通过将计算与输出耦合，增加了我们测试的复杂性。考虑以下情景：

+   我们如何测试没有结果？

+   我们如何测试边缘条件，比如 0%或 100%的覆盖率？

在解耦这些职责之后，我们应该鼓励自己以更少的相互依赖方式考虑每个部分的输入和输出，从而使得测试更容易编写和维护。这导致了 SRP 的第三个优势：

**SRP 使测试更简单，更易于维护**。

SRP 也是提高代码可读性的绝佳方式。看下面的例子：

```go
func loadUserHandler(resp http.ResponseWriter, req *http.Request) {
  err := req.ParseForm()
  if err != nil {
    resp.WriteHeader(http.StatusInternalServerError)
    return
  }
  userID, err := strconv.ParseInt(req.Form.Get("UserID"), 10, 64)
  if err != nil {
    resp.WriteHeader(http.StatusPreconditionFailed)
    return
  }

  row := DB.QueryRow("SELECT * FROM Users WHERE ID = ?", userID)

  person := &Person{}
  err = row.Scan(&person.ID, &person.Name, &person.Phone)
  if err != nil {
    resp.WriteHeader(http.StatusInternalServerError)
    return
  }

  encoder := json.NewEncoder(resp)
  encoder.Encode(person)
}
```

我敢打赌你花了超过五秒钟才理解。那么这段代码呢？

```go
func loadUserHandler(resp http.ResponseWriter, req *http.Request) {
  userID, err := extractIDFromRequest(req)
  if err != nil {
    resp.WriteHeader(http.StatusPreconditionFailed)
    return
  }

  person, err := loadPersonByID(userID)
  if err != nil {
    resp.WriteHeader(http.StatusInternalServerError)
    return
  }

  outputPerson(resp, person)
}
```

通过在函数级别应用 SRP，我们减少了函数的膨胀并增加了其可读性。函数的单一责任现在是协调对其他函数的调用。

# 这与 DI 有什么关系？

在对我们的代码应用 DI 时，我们不奇怪地注入我们的依赖，通常以函数参数的形式。如果你看到一个函数有很多注入的依赖，这很可能是该方法做了太多事情的迹象。

此外，应用 SRP 将指导我们的对象设计。因此，这有助于我们确定何时以及在哪里使用 DI。

# 这对 Go 意味着什么？

在第一章中，*永远不要停止追求更好*，我们提到了 Go 与 Unix 哲学的关系，即我们应该*设计代码只做一件事，但要做得很好，并且与其他代码很好地协同工作*。应用 SRP 后，我们的对象将完全符合这一原则。

# Go 接口、结构和函数

在接口和结构级别应用 SRP 会产生许多小接口。符合 SRP 的函数输入少，代码相当短（即不到一屏的代码）。这两个特点本质上解决了我们在第一章中提到的代码膨胀问题。

通过解决代码膨胀问题，我们发现 SRP 的一个不太被宣传的优势是它使代码更容易理解。简而言之，当一段代码只做一件事时，它的目的更加清晰。

在对现有代码应用 SRP 时，通常会将代码分解为更小的部分。由于你可能觉得自己可能需要编写更多的测试，因此你可能会自然而然地对此产生厌恶。在将结构或接口拆分为多个部分的情况下，这可能是真的。然而，如果你正在重构的代码具有高单元测试覆盖率，那么你可能已经拥有许多你需要的测试。它们只需要稍微移动一下。

另一方面，当将 SRP 应用于函数以减少膨胀时，不需要新的测试；原始函数的测试是完全可以接受的。让我们看一个对我们的`loadUserHandler()`的测试的例子，这在前面的例子中已经展示过了：

```go
func TestLoadUserHandler(t *testing.T) {
   // build request
   req := &http.Request{
      Form: url.Values{},
   }
   req.Form.Add("UserID", "1234")

   // call function under test
   resp := httptest.NewRecorder()
   loadUserHandler(resp, req)

   // validate result
   assert.Equal(t, http.StatusOK, resp.Code)

   expectedBody := `{"ID":1,"Name":"Bob","Phone":"0123456789"}` + "\n"
   assert.Equal(t, expectedBody, resp.Body.String())
}
```

这个测试可以应用于我们函数的任何形式，并且会达到相同的效果。在这种情况下，我们正在重构以提高可读性，我们不希望有任何事情阻止我们这样做。此外，从 API（公共方法或其他函数调用的函数）进行测试更加稳定，因为 API 合同不太可能改变，而内部实现可能会改变。

# Go 包

在包级别应用 SRP 可能更难。系统通常是分层设计的。例如，通常会看到一个按以下方式排列层的 HTTP REST 服务：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/528ec62c-ccb2-464d-bc13-926017793262.png)

这些抽象很好而且清晰；然而，当我们的服务有多个端点时，问题开始出现。我们很快就会得到充满完全无关逻辑的庞大包。另一方面，良好的包应该是小巧、简洁且目的明确的。

找到正确的抽象可能很困难。通常，当我需要灵感时，我会求助于专家，并检查标准的 Go 库。例如，让我们来看看`encoding`包：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/2b144d17-587f-4b9d-9245-dae8f9d9d965.png)

正如您所看到的，每种不同类型都整齐地组织在自己的包中，但所有的包仍然按父目录逻辑分组。我们的 REST 服务将按照下图所示进行拆分：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/29ac7f3f-93ef-48ec-a808-627f86f2abb6.png)

我们最初的抽象是正确的，只是从太高的层次开始。

`encoding`包的另一个不明显的方面是共享代码位于父包中。在开发功能时，程序员通常会想到*我需要我之前写的那段代码*，并且会被诱惑将代码提取到`commons`或`utils`包中。请抵制这种诱惑——重用代码是绝对正确的，但您应该抵制通用包名称的诱惑。这样的包本质上违反了 SRP，因为它们没有明确的目的。

另一个常见的诱惑是将新代码添加到现有代码旁边。让我们想象一下，我们正在编写先前提到的`encoding`包，我们制作的第一个编码器是 JSON 编码器。接下来，我们添加了 GobEncoder，一切都进行得很顺利。再添加几个编码器，突然间我们有了一个大量代码和大量导出 API 的实质性包。在某个时候，我们的`encoding`包的文档变得如此之长，以至于用户很难跟踪。同样地，我们的包中有如此多的代码，以至于我们的扩展和调试工作变慢，因为很难找到东西。

SRP 帮助我们确定更改的原因；多个更改原因表示多个责任。解耦这些责任使我们能够开发更好的抽象。

如果您有时间或意愿从一开始就做正确，那太棒了。然而，从一开始应用 SRP 并找到正确的抽象是困难的。您可以通过首先打破规则，然后使用后续更改来发现软件希望如何发展，以此作为重构的基础。

# 开闭原则（OCP）

"软件实体（类、模块、函数等）应该对扩展开放，对修改关闭。"

- Bertrand Meyer

术语*开放*和*封闭*在讨论软件工程时并不是我经常听到的，所以也许需要做一些解释。

开放意味着我们应该能够通过添加新的行为和功能来扩展或调整代码。封闭意味着我们应该避免对现有代码进行更改，这些更改可能导致错误或其他类型的退化。

这两个特征可能看起来矛盾，但缺失的是范围。当谈论开放时，我们指的是软件的设计或结构。从这个角度来看，开放意味着很容易添加新的包、新的接口或现有接口的新实现。

当我们谈论封闭时，我们指的是现有的代码，以及最小化我们对其进行的更改，特别是被他人使用的 API。这带我们来到 OCP 的第一个优势：

**OCP 有助于减少增加和扩展的风险**

您可以将 OCP 视为一种风险缓解策略。修改现有代码总是存在一定的风险，尤其是对他人使用的代码进行更改。虽然我们可以通过单元测试来保护自己免受这种风险，但这些测试仅限于我们打算的场景和我们可以想象到的误用；它们不会涵盖我们的用户可能想出的一切。

以下代码不遵循 OCP：

```go
func BuildOutput(response http.ResponseWriter, format string, person Person) {
  var err error

  switch format {
  case "csv":
    err = outputCSV(response, person)

  case "json":
    err = outputJSON(response, person)
  }

  if err != nil {
    // output a server error and quit
    response.WriteHeader(http.StatusInternalServerError)
    return
  }

  response.WriteHeader(http.StatusOK)
}
```

第一个提示出现在`switch`语句中。很容易想象情况会发生变化，我们可能需要添加或甚至删除输出格式。

如果我们需要添加另一个格式，需要改变多少？请看下面：

+   **我们需要在`switch`中添加另一个 case 条件**：这个方法已经有 18 行长了；在我们无法在一个屏幕上看到所有内容之前，我们需要添加多少个格式？这个`switch`语句还存在于多少其他地方？它们也需要更新吗？

+   **我们需要编写另一个格式化函数**：这是三个不可避免的变化之一

+   **方法的调用者必须更新以使用新格式**：这是另一个不可避免的变化

+   **我们需要添加另一组测试场景以匹配新的格式**：这也是不可避免的；然而，这里的测试可能会比仅测试独立格式化要长

开始作为*一个小而简单的改变*，现在开始感觉比我们预期的更艰难和风险。

让我们用一个抽象替换格式输入参数和`switch`语句，如下所示：

```go
func BuildOutput(response http.ResponseWriter, formatter PersonFormatter, person Person) {
  err := formatter.Format(response, person)
  if err != nil {
    // output a server error and quit
    response.WriteHeader(http.StatusInternalServerError)
    return
  }

  response.WriteHeader(http.StatusOK)
}
```

这次有多少变化？让我们看看：

+   我们需要定义`PersonFormatter`接口的另一个实现

+   方法的调用者必须更新以使用新格式

+   我们必须为新的`PersonFormatter`编写测试场景

这好多了：我们只剩下三个不可避免的变化，*而主要函数根本没有改变*。这向我们展示了 OCP 的第二个优势：

**OCP 可以帮助减少添加或删除功能所需的更改数量**。

此外，如果在添加新格式化程序后，新结构中出现了错误，那么错误只会出现在一个地方——新代码中。这是 OCP 的第三个优势：

**OCP 将错误的局部性缩小到仅限于新代码及其使用**。

让我们看另一个例子，我们不会应用 DI：

```go
func GetUserHandlerV1(resp http.ResponseWriter, req *http.Request) {
  // validate inputs
  err := req.ParseForm()
  if err != nil {
    resp.WriteHeader(http.StatusInternalServerError)
    return
  }
  userID, err := strconv.ParseInt(req.Form.Get("UserID"), 10, 64)
  if err != nil {
    resp.WriteHeader(http.StatusPreconditionFailed)
    return
  }

  user := loadUser(userID)
  outputUser(resp, user)
}

func DeleteUserHandlerV1(resp http.ResponseWriter, req *http.Request) {
  // validate inputs
  err := req.ParseForm()
  if err != nil {
    resp.WriteHeader(http.StatusInternalServerError)
    return
  }
  userID, err := strconv.ParseInt(req.Form.Get("UserID"), 10, 64)
  if err != nil {
    resp.WriteHeader(http.StatusPreconditionFailed)
    return
  }

  deleteUser(userID)
}
```

正如您所看到的，我们的 HTTP 处理程序都是从表单中提取数据，然后将其转换为数字。有一天，我们决定加强输入验证，并确保数字是正数。可能的结果？一些相当恶劣的霰弹手术。然而，在这种情况下，没有其他办法。我们搞砸了；现在我们需要清理。修复方法显而易见——将重复的逻辑提取到一个地方，然后在那里添加新的验证，如下面的代码所示：

```go
func GetUserHandlerV2(resp http.ResponseWriter, req *http.Request) {
  // validate inputs
  err := req.ParseForm()
  if err != nil {
    resp.WriteHeader(http.StatusInternalServerError)
    return
  }
  userID, err := extractUserID(req.Form)
  if err != nil {
    resp.WriteHeader(http.StatusPreconditionFailed)
    return
  }

  user := loadUser(userID)
  outputUser(resp, user)
}

func DeleteUserHandlerV2(resp http.ResponseWriter, req *http.Request) {
  // validate inputs
  err := req.ParseForm()
  if err != nil {
    resp.WriteHeader(http.StatusInternalServerError)
    return
  }
  userID, err := extractUserID(req.Form)
  if err != nil {
    resp.WriteHeader(http.StatusPreconditionFailed)
    return
  }

  deleteUser(userID)
}
```

遗憾的是，原始代码并没有减少，但肯定更容易阅读。除此之外，我们已经未来证明了对`UserID`字段验证的任何进一步更改。

对于我们的两个例子，满足 OCP 的关键是找到正确的抽象。

# 这与 DI 有什么关系？

在第一章中，*永远不要停止追求更好*，我们将 DI 定义为*以依赖于抽象的方式编码*。通过使用 OCP，我们可以发现更清晰和更持久的抽象。

# 这对 Go 意味着什么？

通常，在讨论 OCP 时，示例中充斥着抽象类、继承、虚函数和 Go 没有的各种东西。还是有吗？

抽象类到底是什么？它实际上试图实现什么？

它试图提供一个用于多个实现之间共享代码的地方。我们可以在 Go 中做到这一点——这就是**组合**。您可以在下面的代码中看到它的工作：

```go
type rowConverter struct {
}

// populate the supplied Person from *sql.Row or *sql.Rows object
func (d *rowConverter) populate(in *Person, scan func(dest ...interface{}) error) error {
  return scan(in.Name, in.Email)
}

type LoadPerson struct {
  // compose the row converter into this loader
  rowConverter
}

func (loader *LoadPerson) ByID(id int) (Person, error) {
  row := loader.loadFromDB(id)

  person := Person{}
  // call the composed "abstract class"
  err := loader.populate(&person, row.Scan)

  return person, err
}

type LoadAll struct {
  // compose the row converter into this loader
  rowConverter
}

func (loader *LoadPerson) All() ([]Person, error) {
  rows := loader.loadAllFromDB()
  defer rows.Close()

  output := []Person{}
  for rows.Next() {
    person := Person{}

    // call the composed "abstract class"
    err := loader.populate(&person, rows.Scan)
    if err != nil {
      return nil, err
    }
  }

  return output, nil
}
```

在前面的例子中，我们将一些共享逻辑提取到`rowConverter`结构中。然后，通过将该结构嵌入其他结构中，我们可以在不进行任何更改的情况下使用它。我们已经实现了抽象类和 OCP 的目标。我们的代码是开放的；我们可以随意嵌入，但是封闭的。嵌入的类不知道自己被嵌入，也不需要进行任何更改就可以使用。

早些时候，我们将*封闭*定义为保持不变，但范围仅限于 API 的部分被导出或被他人使用。我们不能期望内部实现细节，包括私有成员变量，永远不会改变。实现这一点的最佳方法是隐藏这些实现细节。这就是**封装**。

在包级别上，封装很简单：我们将其设为私有。在这里的一个很好的经验法则是，将所有东西都设为私有，只有在真正需要时才将其设为公共。再次，我的理由是风险和工作的避免。一旦你导出了某些东西，就意味着有人可能依赖它。一旦他们依赖它，它就应该变成封闭的；你必须维护它，任何更改都有更高的风险会破坏某些东西。通过适当的封装，包内的更改应该对现有用户是不可见的。

在对象级别上，私有并不意味着在其他语言中的意思，所以我们必须学会自律。访问私有成员变量会使对象紧密耦合，这个决定将会给我们带来麻烦。

我最喜欢 Go 类型系统的一个特性是能够将方法附加到几乎任何东西上。比如说，你正在为健康检查编写一个 HTTP 处理程序。它只是返回状态`204`（无内容）。我们需要满足的接口如下：

```go
type Handler interface {
   ServeHTTP(ResponseWriter, *Request)
}
```

一个简单的实现可能如下所示的代码：

```go
// a HTTP health check handler in long form
type healthCheck struct {
}

func (h *healthCheck) ServeHTTP(resp http.ResponseWriter, _ *http.Request) {
   resp.WriteHeader(http.StatusNoContent)
}

func healthCheckUsage() {
   http.Handle("/health", &healthCheckLong{})
}
```

我们可以创建一个新的结构来实现一个接口，但这至少需要五行。我们可以将其减少到三行，如下所示的代码：

```go
// a HTTP health check handler in short form
func healthCheck(resp http.ResponseWriter, _ *http.Request) {
  resp.WriteHeader(http.StatusNoContent)
}

func healthCheckUsage() {
  http.Handle("/health", http.HandlerFunc(healthCheck))
}
```

在这种情况下，秘密酱汁隐藏在标准库中。我们将我们的函数转换为`http.HandlerFunc`类型，它附加了一个`ServeHTTP`方法。这个巧妙的小技巧使我们很容易满足`http.Handler`接口。正如我们在本章中已经看到的，朝着接口的方向前进会使我们的代码更少耦合，更容易维护和扩展。

# 里斯科夫替换原则（LSP）

“如果对于类型为 S 的每个对象 o1，都有类型为 T 的对象 o2，使得对于所有以 T 定义的程序 P，当 o1 替换 o2 时，P 的行为不变，则 S 是 T 的子类型。”

-芭芭拉·里斯科夫

读了三遍之后，我仍然不确定我是否理解正确。幸运的是，罗伯特 C.马丁为我们总结了如下：

“子类型必须可以替换其基类型。”

-罗伯特 C.马丁

我能理解这一点。然而，他是不是又在谈论抽象类了？可能是。正如我们在 OCP 部分看到的，虽然 Go 没有抽象类或继承，但它确实有组合和接口实现。

让我们退后一步，看看这个原则的动机。LSP 要求*子类型可以相互替换*。我们可以使用 Go 接口，这将始终成立。

但是等等，这段代码怎么样：

```go
func Go(vehicle actions) {
  if sled, ok := vehicle.(*Sled); ok {
    sled.pushStart()
  } else {
    vehicle.startEngine()
  }

  vehicle.drive()
}

type actions interface {
  drive()
  startEngine()
}

type Vehicle struct {
}

func (v Vehicle) drive() {
  // TODO: implement
}

func (v Vehicle) startEngine() {
  // TODO: implement
}

func (v Vehicle) stopEngine() {
  // TODO: implement
}

type Car struct {
  Vehicle
}

type Sled struct {
  Vehicle
}

func (s Sled) startEngine() {
  // override so that is does nothing
}

func (s Sled) stopEngine() {
  // override so that is does nothing
}

func (s Sled) pushStart() {
  // TODO: implement
}
```

它使用了一个接口，但显然违反了 LSP。我们可以通过添加更多接口来修复这个问题，如下所示的代码：

```go
func Go(vehicle actions) {
   switch concrete := vehicle.(type) {
   case poweredActions:
      concrete.startEngine()

   case unpoweredActions:
      concrete.pushStart()
   }

   vehicle.drive()
}

type actions interface {
   drive()
}

type poweredActions interface {
   actions
   startEngine()
   stopEngine()
}

type unpoweredActions interface {
   actions
   pushStart()
}

type Vehicle struct {
}

func (v Vehicle) drive() {
   // TODO: implement
}

type PoweredVehicle struct {
   Vehicle
}

func (v PoweredVehicle) startEngine() {
   // common engine start code
}

type Car struct {
   PoweredVehicle
}

type Buggy struct {
   Vehicle
}

func (b Buggy) pushStart() {
   // do nothing
}
```

然而，这并不是更好的。这段代码仍然有异味，这表明我们可能使用了错误的抽象或错误的组合。让我们再试一次重构：

```go
func Go(vehicle actions) {
  vehicle.start()
  vehicle.drive()
}

type actions interface {
  start()
  drive()
}

type Car struct {
  poweredVehicle
}

func (c Car) start() {
  c.poweredVehicle.startEngine()
}

func (c Car) drive() {
  // TODO: implement
}

type poweredVehicle struct {
}

func (p poweredVehicle) startEngine() {
  // common engine start code
}

type Buggy struct {
}

func (b Buggy) start() {
  // push start
}

func (b Buggy) drive() {
  // TODO: implement
}
```

这样好多了。`Buggy`短语不再被迫实现毫无意义的方法，也不包含任何它不需要的逻辑，两种车辆类型的使用都很干净。这展示了 LSP 的一个关键点：

**LSP 指的是行为而不是实现**。

一个对象可以实现任何它喜欢的接口，但这并不意味着它在行为上与同一接口的其他实现是一致的。看看下面的代码：

```go
type Collection interface {
   Add(item interface{})
   Get(index int) interface{}
}

type CollectionImpl struct {
   items []interface{}
}

func (c *CollectionImpl) Add(item interface{}) {
   c.items = append(c.items, item)
}

func (c *CollectionImpl) Get(index int) interface{} {
   return c.items[index]
}

type ReadOnlyCollection struct {
   CollectionImpl
}

func (ro *ReadOnlyCollection) Add(item interface{}) {
   // intentionally does nothing
}
```

在前面的例子中，我们通过实现所有方法来满足 API 合同，但我们将不需要的方法转换为 NO-OP。通过让我们的`ReadOnlyCollection`实现`Add()`方法，它满足了接口，但引入了混乱的可能性。当你有一个接受`Collection`的函数时会发生什么？当你调用`Add()`时，你会期望发生什么？

在这种情况下，修复方法可能会让你感到惊讶。我们可以将关系反转，而不是将`MutableCollection`转换为`ImmutableCollection`，如下面的代码所示：

```go
type ImmutableCollection interface {
   Get(index int) interface{}
}

type MutableCollection interface {
   ImmutableCollection
   Add(item interface{})
}

type ReadOnlyCollectionV2 struct {
   items []interface{}
}

func (ro *ReadOnlyCollectionV2) Get(index int) interface{} {
   return ro.items[index]
}

type CollectionImplV2 struct {
   ReadOnlyCollectionV2
}

func (c *CollectionImplV2) Add(item interface{}) {
   c.items = append(c.items, item)
}
```

这种新结构的一个好处是，我们现在可以让编译器确保我们不会在需要`MutableCollection`的地方使用`ImmutableCollection`。

# 这与 DI 有什么关系？

通过遵循 LSP，我们的代码在注入的依赖关系不同的情况下表现一致。另一方面，违反 LSP 会导致我们违反 OCP。这些违规行为使我们的代码对实现有太多的了解，从而打破了注入依赖的抽象。

# 这对 Go 有什么意义？

在使用组合，特别是未命名变量形式来满足接口时，LSP 的应用方式与面向对象语言中的应用方式一样。

在实现接口时，我们可以利用 LSP 对*一致的*行为的关注，作为检测与不正确的抽象相关的代码异味的一种方式。

# 接口隔离原则（ISP）

“客户端不应被强迫依赖他们不使用的方法。”

–Robert C. Martin

就我个人而言，我更喜欢一个更直接的定义——*接口应该被减少到可能的最小尺寸*。

让我们首先讨论为什么臃肿的接口可能是一件坏事。臃肿的接口有更多的方法，因此可能更难理解。它们也需要更多的工作来使用，无论是通过实现、模拟还是存根。

臃肿的接口表明更多的责任，正如我们在 SRP 中看到的，一个对象承担的责任越多，它就越有可能想要改变。如果接口发生变化，它会通过所有的用户产生连锁反应，违反 OCP 并引起大量的散弹手术。这是 ISP 的第一个优势：

**ISP 要求我们定义薄接口**

对于许多程序员来说，他们的自然倾向是向现有接口添加内容，而不是定义一个新的接口，从而创建一个臃肿的接口。这导致了一种情况，即有时候，实现变得与接口的用户紧密耦合。这种耦合使得接口、它们的实现和用户更加抵制变化。考虑以下例子：

```go
type FatDbInterface interface {
   BatchGetItem(IDs ...int) ([]Item, error)
   BatchGetItemWithContext(ctx context.Context, IDs ...int) ([]Item, error)

   BatchPutItem(items ...Item) error
   BatchPutItemWithContext(ctx context.Context, items ...Item) error

   DeleteItem(ID int) error
   DeleteItemWithContext(ctx context.Context, item Item) error

   GetItem(ID int) (Item, error)
   GetItemWithContext(ctx context.Context, ID int) (Item, error)

   PutItem(item Item) error
   PutItemWithContext(ctx context.Context, item Item) error

   Query(query string, args ...interface{}) ([]Item, error)
   QueryWithContext(ctx context.Context, query string, args ...interface{}) ([]Item, error)

   UpdateItem(item Item) error
   UpdateItemWithContext(ctx context.Context, item Item) error
}

type Cache struct {
   db FatDbInterface
}

func (c *Cache) Get(key string) interface{} {
   // code removed

   // load from DB
   _, _ = c.db.GetItem(42)

   // code removed
   return nil
}

func (c *Cache) Set(key string, value interface{}) {
   // code removed

   // save to DB
   _ = c.db.PutItem(Item{})

   // code removed
}
```

很容易想象所有这些方法都属于一个结构。例如`GetItem()`和`GetItemWithContext()`这样的方法对很可能共享大部分，如果不是全部相同的代码。另一方面，使用`GetItem()`的用户不太可能也会使用`GetItemWithContext()`。对于这种特定的用例，一个更合适的接口应该是以下这样的：

```go
type myDB interface {
   GetItem(ID int) (Item, error)
   PutItem(item Item) error
}

type CacheV2 struct {
   db myDB
}

func (c *CacheV2) Get(key string) interface{} {
   // code removed

   // load from DB
   _, _ = c.db.GetItem(42)

   // code removed
   return nil
}

func (c *CacheV2) Set(key string, value interface{}) {
   // code removed

   // save from DB
   _ = c.db.PutItem(Item{})

   // code removed
}
```

利用这个新的薄接口，使函数签名更加明确和灵活。这带来了 ISP 的第二个优势：

**ISP 导致明确的输入**。

薄接口也更容易更完全地实现，使我们远离与 LSP 相关的潜在问题。

在使用接口作为输入并且接口需要臃肿的情况下，这是方法违反 SRP 的一个有力指示。考虑以下代码：

```go
func Encrypt(ctx context.Context, data []byte) ([]byte, error) {
   // As this operation make take too long, we need to be able to kill it
   stop := ctx.Done()
   result := make(chan []byte, 1)

   go func() {
      defer close(result)

      // pull the encryption key from context
      keyRaw := ctx.Value("encryption-key")
      if keyRaw == nil {
         panic("encryption key not found in context")
      }
      key := keyRaw.([]byte)

      // perform encryption
      ciperText := performEncryption(key, data)

      // signal complete by sending the result
      result <- ciperText
   }()

   select {
   case ciperText := <-result:
      // happy path
      return ciperText, nil

   case <-stop:
      // cancelled
      return nil, errors.New("operation cancelled")
   }
}
```

你看到问题了吗？我们正在使用`context`接口，这是很棒并且强烈推荐的，但我们正在违反 ISP。作为务实的程序员，我们可以争辩说这个接口被广泛使用和理解，定义我们自己的接口来将其减少到我们需要的两种方法是不必要的。在大多数情况下，我会同意，但在这种特殊情况下，我们应该重新考虑。我们在这里使用`context`接口有两个完全不同的目的。第一个是控制通道，允许我们提前停止或超时任务，第二个是提供一个值。实际上，我们在这里使用`context`违反了 SRP，并且因此存在潜在的混淆风险，并且导致更大的变更阻力。

如果我们决定不在请求级别上使用停止通道模式，而是在应用级别上使用，会发生什么？如果键值不在`context`中，而是来自其他来源会发生什么？通过应用 ISP，我们可以将关注点分离为两个接口，如下面的代码所示：

```go
type Value interface {
   Value(key interface{}) interface{}
}

type Monitor interface {
   Done() <-chan struct{}
}

func EncryptV2(keyValue Value, monitor Monitor, data []byte) ([]byte, error) {
   // As this operation make take too long, we need to be able to kill it
   stop := monitor.Done()
   result := make(chan []byte, 1)

   go func() {
      defer close(result)

      // pull the encryption key from Value
      keyRaw := keyValue.Value("encryption-key")
      if keyRaw == nil {
         panic("encryption key not found in context")
      }
      key := keyRaw.([]byte)

      // perform encryption
      ciperText := performEncryption(key, data)

      // signal complete by sending the result
      result <- ciperText
   }()

   select {
   case ciperText := <-result:
      // happy path
      return ciperText, nil

   case <-stop:
      // cancelled
      return nil, errors.New("operation cancelled")
   }
}
```

我们的函数现在符合 ISP，并且两个输入可以分别自由演化。但是这个函数的用户会发生什么？他们必须停止使用`context`吗？绝对不是。该方法可以如下所示调用：

```go
// create a context
ctx, cancel := context.WithCancel(context.Background())
defer cancel()

// store the key
ctx = context.WithValue(ctx, "encryption-key", "-secret-")

// call the function
_, _ = EncryptV2(ctx, ctx, []byte("my data"))
```

重复使用`context`作为参数可能会感觉有点奇怪，但正如你所看到的，这是有充分理由的。这将我们带到了 ISP 的最后一个优势：

**ISP 有助于将输入与其具体实现解耦，使它们能够分别演化**。

# 这与 DI 有什么关系？

正如我们所看到的，ISP 帮助我们将接口分解为逻辑上的独立部分，每个部分提供特定的功能——有时被称为角色接口的概念。通过在我们的 DI 中利用这些角色接口，我们的代码与输入的具体实现解耦。

这种解耦不仅允许代码的各个部分分别演化，而且往往更容易识别测试向量。在前面的例子中，逐个扫描输入并考虑它们可能的值和状态更容易。这个过程可能会导致一个类似下面的向量列表：

** *value* 输入的测试向量包括**：

+   **正常路径**：返回一个有效值

+   **错误路径**：返回一个空值

** *monitor* 输入的测试向量包括**：

+   **正常路径**：不返回完成信号

+   **错误路径**：立即返回完成信号

# 这对 Go 意味着什么？

在第一章中，我们提到了由*Jack Lindamood*创造的流行 Go 成语——*接受接口，返回结构体*。将这个想法与 ISP 结合起来，事情就开始起飞了。由此产生的函数对其需求非常简洁，同时对其输出也非常明确。在其他语言中，我们可能需要以抽象的形式定义输出，或者创建适配器类来完全解耦我们的函数和用户。然而，由于 Go 支持隐式接口，这是不需要的。

隐式接口是一种语言特性，实现者（即结构体）不需要定义它实现的接口，而只需要定义适当的方法来满足接口，如下面的代码所示：

```go
type Talker interface {
   SayHello() string
}

type Dog struct{}

// The method implicitly implements the Talker interface
func (d Dog) SayHello() string {
   return "Woof!"
}

func Speak() {
   var talker Talker
   talker = Dog{}

   fmt.Print(talker.SayHello())
}
```

这可能看起来像一个简洁的技巧，而且确实是。但这并不是使用它的唯一原因。当使用显式接口时，实现对象与其依赖对象之间存在一定的耦合，因为它们之间有一个相当明确的链接。然而，也许最重要的原因是简单性。让我们来看一下 Go 中最流行的接口之一，你可能从未听说过的：

```go
// Stringer is implemented by any value that has a String method, which 
// defines the “native” format for that value. The String method is used 
// to print values passed as an operand to any format that accepts a 
// string or to an unformatted printer such as Print.
type Stringer interface {
    String() string
}
```

这个接口可能看起来并不令人印象深刻，但`fmt`包支持这个接口的事实使你能够做到以下几点：

```go
func main() {
  kitty := Cat{}

  fmt.Printf("Kitty %s", kitty)
}

type Cat struct{}

// Implicitly implement the fmt.Stringer interface
func (c Cat) String() string {
  return "Meow!"
}
```

如果我们有显式接口，想象一下我们将不得不声明我们实现`Stringer`多少次。也许在 Go 中，隐式接口给我们带来的最大优势是当它们与 ISP 和 DI 结合使用时。这三者的结合允许我们定义输入接口，这些接口很薄，特定于特定用例，并且与其他所有内容解耦，就像我们在`Stringer`接口中看到的那样。

此外，在使用的包中定义接口会缩小对工作在一段代码上所需的知识范围，从而使理解和测试变得更加容易。

# 依赖反转原则（DIP）

“高级模块不应依赖于低级模块。两者都应依赖于抽象。抽象不应依赖于细节。细节应依赖于抽象”

-罗伯特 C.马丁

你有没有发现自己站在鞋店里犹豫是买棕色还是黑色的鞋子，然后回家后后悔自己的选择？不幸的是，一旦你买了它们，它们就是你的了。针对具体实现进行编程也是一样的：一旦你选择了，你就被困住了，退款和重构都不管用。但为什么要选择，当你不必选择？看看下图中显示的关系：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/d884c295-071e-4718-94e8-a3147c61a713.png)

不太灵活，是吧？让我们将关系转换为抽象：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/51c1018c-2c1f-4f10-a286-eff0cf163de8.png)

好多了。一切都只依赖于干净的抽象，满足 LSP 和 ISP。这些包简洁明了，愉快地满足 SRP。代码甚至*似乎*满足*Robert C*. *Martin*对 DIP 的描述，但遗憾的是，它并没有。中间那个讨厌的词，反转。

在我们的例子中，`Shoes`包拥有`Shoe`接口，这是完全合理的。然而，当需求发生变化时就会出现问题。对`Shoes`包的更改可能会导致`Shoe`接口发生变化。这将进而要求`Person`对象发生变化。我们添加到`Shoe`接口的任何新功能可能不需要或与`Person`对象无关。因此，`Person`对象仍然与`Shoe`包耦合。

为了完全打破这种耦合，我们需要将关系从**Person**使用 Shoe 更改为**Person**需要**Footwear**，就像这样：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/fbac05cb-978c-49ef-b58d-d2dead2306d0.png)

这里有两个关键点。首先，DIP 迫使我们专注于抽象的所有权。在我们的例子中，这意味着将接口移动到使用它的包中，并将关系从*uses*更改为*requires*；这是一个微妙的区别，但很重要。

其次，DIP 鼓励我们将使用要求与实现解耦。在我们的例子中，我们的`Brown Shoes`对象实现了`Footwear`，但很容易想象有更多的实现，有些甚至可能不是鞋子。

# 这与 DI 有什么关系？

依赖反转很容易被误解为依赖注入，包括我在内的许多人长期以来都认为它们是等价的。但正如我们所见，依赖反转关注的是依赖项的抽象定义的所有权，而 DI 则专注于使用这些抽象。

通过将 DIP 与 DI 结合应用，我们最终得到了非常良好解耦的包，这些包非常容易理解、易于扩展和简单测试。

# 这对 Go 意味着什么？

我们之前已经讨论过 Go 对隐式接口的支持，以及我们如何利用它在同一个包中将我们的依赖项定义为接口，而不是从另一个包导入接口。这种方法就是 DIP。

也许你内心的怀疑者正在疯狂地大喊，“但这意味着我到处都要定义接口！”是的，这可能是真的。这甚至可能导致一些重复。然而，你会发现，没有依赖倒置的情况下你定义的接口会更加臃肿和难以控制，这个事实将会在未来给你带来更多的工作成本。

应用 DIP 后，你不太可能遇到任何循环依赖的问题。事实上，你几乎肯定会发现你的代码中导入的数量显著减少，你的依赖图变得相当扁平。事实上，许多包只会被`main`包导入。

# 总结

在这个对 SOLID 设计原则的简要介绍中，我们了解到它们不仅适用于 DI，还适用于 Go。在本书第二部分对各种 DI 方法的讨论中，我们将经常引用这些原则。

在下一章中，我们将继续研究应该在你学习和尝试新技术时放在首要位置的编码方面。我还会向你介绍一些方便的工具，让你的编码生活变得更加轻松。

# 问题

1.  单一职责原则如何改进 Go 代码？

1.  开闭原则如何改进 Go 代码？

1.  里斯科夫替换原则如何改进 Go 代码？

1.  接口隔离原则如何改进 Go 代码？

1.  依赖倒置原则如何改进 Go 代码？

1.  依赖倒置与依赖注入有何不同？

# 进一步阅读

Packt 还有许多其他关于学习 SOLID 原则的优秀资源：

+   [`www.packtpub.com/mapt/book/application_development/9781787121300/1`](https://www.packtpub.com/mapt/book/application_development/9781787121300/1)

+   [`www.packtpub.com/mapt/book/application_development/9781785884375/10/ch10lvl1sec50/the-solid-principles`](https://www.packtpub.com/mapt/book/application_development/9781785884375/10/ch10lvl1sec50/the-solid-principles)

+   [`www.packtpub.com/mapt/book/application_development/9781785280832/8`](https://www.packtpub.com/mapt/book/application_development/9781785280832/8)


# 第三章：为用户体验编码

在本章中，我们将研究编程中经常被忽视但有价值的几个方面，主要是测试、用户体验和依赖图。虽然这些主题可能看起来与**依赖注入**（DI）没有任何关系，但它们被包含在内是为了给你一个坚实但务实的基础，以便你可以评估本书第二部分的技术。

本章将涵盖以下主题：

+   为人类进行优化

+   一个名为*单元测试*的安全保障。

+   测试诱发的损害

+   使用 Godepgraph 可视化您的包依赖关系

# 发现良好的用户体验

良好的用户体验不需要被推测。它也不需要从一些有经验的大师那里传授。事实上，经验的问题在于，今天对你来说容易、简单和明显的东西与上个月、去年或你刚开始时大不相同。

通过逻辑、坚持和实践可以发现良好的 UX。要找出对于你的用户来说良好的 UX 是什么样的，你可以应用我的 UX 发现调查。

问问自己以下四个问题：

+   谁是用户？

+   你的用户有什么能力？

+   用户为什么想要使用你的代码？

+   你的用户希望如何使用它？

# 技术要求

对于本章，你需要对 Go 有基本的了解。

本章中的所有代码都可以在[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch03`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch03)找到。

# 为人类进行优化

近年来，我们看到了 UX 这个术语的兴起，它代表用户体验。在其核心，UX 是关于可用性的——理解用户并设计交互和界面，使其对他们更直观或更自然。

UX 通常指的是客户，这是有道理的，毕竟那里有钱。然而，我们程序员错过了一些相当重要的东西。让我问你，你写的代码的用户是谁？不是使用软件本身的客户。代码的用户是你的同事和未来的你。你想让他们的生活更轻松吗？换句话说，你宁愿花时间去弄清楚一段代码的目的，还是扩展系统？那里才有钱。作为程序员，我们得到的报酬是交付功能，而不是美丽的代码，而具有良好 UX 的代码可以更快地交付功能，并且风险更小。

# 对于 Go 代码，用户体验意味着什么？

对于 Go 代码，UX 意味着什么？简而言之，*我们应该编写代码，任何有能力的程序员在第一次阅读后就能理解其一般意图*。

这听起来有点像挥手吗？是的，可能是挥手。这是解决任何创造性努力中的问题的标准问题；当你看到它时，你知道它，当它不存在时，你会感觉到它。也许定义*能力*的问题主要是因为团队成员和环境的定义差异很大。同样，很难实现的原因也在于代码本身对作者来说比其他人更容易理解。

但首先，让我们看一些简单的原则，以便朝着正确的方向开始。

# 从简单开始——只有在必要时才变得复杂

作为程序员，我们应该始终努力保持简单，并在没有其他办法时才求助于复杂。让我们看看这个原则是如何实施的。试着在三秒钟内确定下一个示例的作用：

```go
func NotSoSimple(ID int64, name string, age int, registered bool) string {
  out := &bytes.Buffer{}
  out.WriteString(strconv.FormatInt(ID, 10))
  out.WriteString("-")
  out.WriteString(strings.Replace(name, " ", "_", -1))
  out.WriteString("-")
  out.WriteString(strconv.Itoa(age))
  out.WriteString("-")
  out.WriteString(strconv.FormatBool(registered))
  return out.String()
}
```

这个怎么样：

```go
func Simpler(ID int64, name string, age int, registered bool) string {
  nameWithNoSpaces := strings.Replace(name, " ", "_", -1)
  return fmt.Sprintf("%d-%s-%d-%t", ID, nameWithNoSpaces, age, registered)
}
```

将第一个代码中体现的方法应用到整个系统几乎肯定会使其运行更快，但不仅编码可能需要更长时间，而且阅读起来也更困难，因此维护和扩展也更困难。

有时你需要从代码中提取极端的性能，但最好等到无法避免时再增加额外的复杂性。

# 只应用足够的抽象

过度的抽象会导致过度的心理负担和过度的打字。虽然有人可能会认为任何可以在以后交换或扩展的代码片段都应该有一个抽象，但我会主张更加务实的方法。实现足够的内容以交付我们所负责的业务价值，然后根据需要进行重构。看看以下代码：

```go
type myGetter interface {
  Get(url string) (*http.Response, error)
}

func TooAbstract(getter myGetter, url string) ([]byte, error) {
  resp, err := getter.Get(url)
  if err != nil {
    return nil, err
  }
  defer resp.Body.Close()

  return ioutil.ReadAll(resp.Body)
}
```

将上述代码与以下常见概念的使用进行比较：

```go
func CommonConcept(url string) ([]byte, error) {
  resp, err := http.Get(url)
  if err != nil {
    return nil, err
  }
  defer resp.Body.Close()

  return ioutil.ReadAll(resp.Body)
}
```

# 遵循行业、团队和语言约定

当概念、变量和函数名称遵循约定时，它们都*很容易理解*。问问自己，如果你在一个关于汽车的系统上工作，你会期望一个名为`flower`的变量是什么？

编码风格可以说是 Go 做对的事情。多年来，我一直参与*括号放置*和*制表符与空格*之争，但转到 Go 后，一切都改变了。有一个固定的、有文档的、易于重现的风格——运行`gofmt`，问题解决了。仍然有一些地方你可能会伤害到自己。从一个没有检查异常的语言转过来，你可能会想要使用 Go 的`panic()`短语；虽然可能，但这是官方代码审查评论维基明确不鼓励的约定之一（[`github.com/golang/go/wiki/CodeReviewComments`](https://github.com/golang/go/wiki/CodeReviewComments)）。

团队约定有点难以定义，有时也难以遵循。`channel`类型的变量应该叫做`result`、`resultCh`还是`resultChan`？我见过，也可能写过，这三种情况都有。

错误日志记录呢？有些团队喜欢在触发错误的地方记录错误，而其他人更喜欢在调用堆栈的顶部这样做。我有自己的偏好，我相信你也有，但我还没有看到一个非常有说服力的论点支持其中任何一种。

# 只导出必要的内容

当你对你的导出 API 小心谨慎时，会发生很多好事。主要的是，它变得更容易让其他人理解；当一个方法有更少的参数时，它自然更容易理解。看看以下代码：

```go
NewPet("Fido", true)
```

`true`是什么意思？不打开函数或文档很难说。但是，如果我们这样做呢：

```go
NewDog("Fido")
```

在这种情况下，目的是明确的，错误不太可能发生，而且封装性得到了改善。

同样，具有较少方法和对象的接口和结构以及包更容易理解，更有明确的目的。让我们看另一个例子：

```go
type WideFormatter interface {
  ToCSV(pets []Pet) ([]byte, error)
  ToGOB(pets []Pet) ([]byte, error)
  ToJSON(pets []Pet) ([]byte, error)
}
```

将前面的代码与以下进行比较：

```go
type ThinFormatter interface {
  Format(pets []Pet) ([]byte, error)
}

type CSVFormatter struct {}

func (f CSVFormatter) Format(pets []Pet) ([]byte, error) {
  // convert slice of pets to CSV
}
```

是的，在这两种情况下，结果都是更多的代码。更直接的代码，但无论如何都更多的代码。为用户提供更好的用户体验通常会带来一些额外的成本，但用户的生产力收益是成倍增加的。考虑到，在许多情况下，你编写的代码的用户之一是未来的你，你可以说现在多做一点额外的工作会为你节省大量的未来工作。

继续关注*未来的我*，这种方法提供的第二个优势是更容易改变主意。一旦一个函数或类型被导出，它就可以被使用；一旦被使用，就必须被维护，并且更改需要付出更多的努力。这种方法使这些更改变得更容易。

# 积极应用单一职责原则

正如我们在第二章中看到的，*Go 的 SOLID 设计原则*，应用**单一职责原则**（**SRP**）鼓励对象更简洁、更连贯，因此更容易理解。

# 谁是用户？

大部分时间，答案将是“未来的我”和我的同事。你的“未来的我”将会是一个更好、更聪明、更英俊的版本。另一方面，你的同事则更难预测。如果有帮助的话，我们可以避免考虑那些聪明、了不起的人；希望无论我们做什么，他们都能理解。然而，实习生则更难预测。如果我们的代码能让他们理解，那么对其他人来说也就没问题了。

如果你有机会为公司范围或一般用途编写软件库，那么这个问题就会变得更加困难。一般来说，你希望目标低，只有在没有其他选择时才离开标准和简单的格式。

# 你的用户有什么能力？

既然我们清楚了用户是谁，我们就可以更好地理解他们的世界观。你和你的用户之间，甚至你和未来的你之间的技能、经验和领域知识可能存在巨大的差异。这就是大多数技术工具和软件库失败的地方。回想一下你刚开始使用 Go 的时候。你的代码是什么样子的？在 Go 中有没有一些语言特性是你还没有使用过的？就我个人而言，我来自 Java 背景，因此我带着一些先入为主的观念进入这个领域：

+   我以为线程很昂贵（而 goroutine 就是线程）

+   我以为一切都必须在一个结构体中

+   习惯于显式接口意味着我对使用**接口隔离原则**（**ISP**）或**依赖反转原则**（**DSP**）的热情不如现在

+   我不理解通道的威力

+   传递 lambda 让我大开眼界

随着时间的推移，我看到这些事情一次又一次地出现，特别是在代码审查的评论中。回答问题“你的用户有什么能力？”有一种非常有效的方法：写一个例子，然后问你的同事以下问题：

+   这是做什么的？

+   你会怎么做？

+   你期望这个函数做什么？

如果你没有任何可以询问的用户，另一个选择是问自己，“还有什么类似的东西存在？”我并不是建议你跟随别人的错误。基本理论是，如果其他类似的东西存在，而你的用户对它感到舒适，那么如果你的东西类似的话，他们就不必学习如何使用。这在我使用 lambda 时给我留下了深刻的印象。来自函数式背景的同事对此很满意，但来自面向对象背景的同事则觉得有些困惑或者不直观。

# 用户为什么想要使用你的代码？

回答为什么你的用户想要使用你的代码的问题可能是长而多样的。如果是这样，你可能需要回去重新阅读*SRP*部分。除了能够将代码分割成更小、更简洁的块之外，我们还需要列出一个清单。我们将这个清单应用到 80/20 法则上。通常，80%的使用来自 20%的用例。让我用一个例子来解释一下。

考虑一个**自动取款机**（**ATM**）。它的用例列表可能如下所示：

+   取款

+   存款

+   查询余额

+   更改 PIN 码

+   转账

+   存款支票

我估计一个人使用自动取款机的至少 80%的目的是取钱。那么我们可以怎么利用这个信息呢？我们可以优化界面，使最常见的用例尽可能方便。对于自动取款机来说，可能只需要在第一个屏幕的顶部放置取款功能，这样用户就不必搜索了。既然我们了解了用户想要实现什么，我们可以在此基础上继续思考他们期望如何使用它。

# 他们期望如何使用它？

虽然 ATM 的例子很清楚，但它是一个系统，所以你可能会想知道它如何可能适用于诸如函数之类的低级概念。让我们看一个例子：

```go
// PetFetcher searches the data store for pets whose name matches
// the search string.
// Limit is optional (default is 100). Offset is optional (default 0).
// sortBy is optional (default name). sortAscending is optional
func PetFetcher(search string, limit int, offset int, sortBy string, sortAscending bool) []Pet {
  return []Pet{}
}
```

这看起来可能还不错，对吧？问题是大多数使用看起来像下面这样：

```go
results := PetFetcher("Fido", 0, 0, "", true)
```

正如你所看到的，大多数情况下我们并不需要所有这些返回值，而且许多输入都被忽略了。

解决这种情况的第一步是查看代码中未被充分利用的部分，并问自己，我们真的需要它们吗？如果它们只存在于测试中，那么它们就是“测试诱导的破坏”，我们将在本章后面讨论。

如果它们存在于一些不经常使用但引人注目的用例中，那么我们可以用另一种方式来解决。第一种选择是将函数分成多个部分；这将允许用户只采用他们需要的复杂性。第二个选择是将配置合并到一个对象中，允许用户忽略他们不使用的部分。

在这两种方法中，我们提供“合理的默认值”，通过允许用户只关注他们需要的内容来减少函数的心理负担。

# 何时妥协

拥有出色的用户体验是一个值得追求的目标，但并非必需。总会有一些情况下需要牺牲用户体验。第一个，也许是最常见的情况是团队的发展。

随着团队的发展和对 Go 的经验增加，他们将不可避免地发现一些早期的软件模式不再那么有效。这些可能包括全局变量的使用、panic、从环境变量加载配置，甚至何时使用函数而不是对象。随着团队的发展，他们对良好软件的定义以及标准或直观的定义也在发生变化。

第二个，而且在许多情况下，是对糟糕用户体验的过度使用的借口，是性能。正如我们在本章的早期例子中看到的，通常可以编写更快的代码，但更快的代码通常更难理解。这里的最佳选择是首先为人类优化，然后，只有当系统被证明不够快时，才为速度进行优化。即使在这种情况下，这些优化也应该有选择地应用于系统中那些经过测量证明值得重构和长期成本低于理想用户体验的部分。

最后一种情况是可见性；有时，你就是看不到一个好的用户体验可能是什么。在这些情况下，更有效的选择是实施，然后根据使用和出现的任何不便逐步进行重构。

# 关于为用户体验编码的最后思考

程序员的时间，你的时间，是昂贵的；你应该节约它以优先考虑 CPU 时间。开发人员的用户体验是具有挑战性的，因为我们天生就有解决问题和交付有用软件的需求。然而，节约程序员的时间是可能的。试着记住以下几点：

+   使某物更具配置性并不会使其更易用，而是使其更令人困惑

+   为所有用例设计会使代码对每个人都不方便

+   用户的能力和期望在你的代码被感知以及被采用方面起着重要作用

也许最重要的是，改变用户体验以适应用户总是更好、更容易，而不是相反。

# 一个名为单元测试的安全保障。

许多人会告诉你，“你必须为你的代码编写单元测试；它们可以确保你没有错误”。它们实际上根本不这样做。我写单元测试不是因为有人告诉我必须这样做，而是因为它们对我有用。单元测试是有力的。它们实际上减少了我需要做的工作量。也许这些不是你以前听过的理由。让我们更详细地探讨一下。

单元测试给您重构的自由和信心：我喜欢重构，也许有点过分，但这是另一个话题。重构让我可以尝试不同风格的代码、实现和 UX。通过进行单元测试，我可以大胆尝试，并且有信心不会无意中破坏任何东西。它们还可以让您有勇气尝试新技术、库或编码技术。

现有的单元测试使添加新功能变得更容易：正如我们之前提到的，添加新功能确实会带来一些风险——我们可能会破坏某些东西。有了测试，就提供了一个安全网，让我们不那么在意已经存在的东西，更专注于添加新功能。这可能看起来有些反直觉，但单元测试实际上让您更快地前进。随着系统的扩展，有了单元测试的安全保障，您可以自信地继续前进，而不必担心可能会破坏的东西。

单元测试可以防止重复的回归：无论如何，回归都很糟糕。它会让你看起来很糟糕，还会让你额外工作，但它是会发生的。我们最希望的是不要反复修复同一个错误。虽然测试确实可以防止一些回归，但它们无法完全阻止。通过编写一个由于错误而失败的测试，然后修复错误，我们实现了两件事。首先，我们知道错误何时被修复，因为测试通过了。其次，错误不会再次发生。

单元测试记录了您的意图：虽然我并不是在暗示测试可以取代文档，但它们是您编写代码时所期望的明确、可执行的表达。这在团队中工作时是一个非常可取的品质。它允许您在系统的任何部分工作，而不必担心破坏他人编写的代码，甚至可能完全理解它。

单元测试记录了您对依赖项的需求：在本书的第二部分中，我们将通过一些示例来应用 DI 到现有的代码库中。这个过程的一个重要部分将包括将功能分组并提取到抽象中。这些抽象自然成为*工作单元*。然后分别对每个单元进行测试并隔离。因此，这些测试更加专注，更容易编写和维护。

此外，对使用 DI 的代码进行测试通常会关注该函数如何使用和对依赖项做出反应。这些测试有效地定义了依赖项的需求合同，并有助于防止回归。让我们看一个例子：

```go
type Loader interface {
  Load(ID int) (*Pet, error)
}

func TestLoadAndPrint_happyPath(t *testing.T) {
  result := &bytes.Buffer{}
  LoadAndPrint(&happyPathLoader{}, 1, result)
  assert.Contains(t, result.String(), "Pet named")
}

func TestLoadAndPrint_notFound(t *testing.T) {
  result := &bytes.Buffer{}
  LoadAndPrint(&missingLoader{}, 1, result)
  assert.Contains(t, result.String(), "no such pet")
}

func TestLoadAndPrint_error(t *testing.T) {
  result := &bytes.Buffer{}
  LoadAndPrint(&errorLoader{}, 1, result)
  assert.Contains(t, result.String(), "failed to load")
}

func LoadAndPrint(loader Loader, ID int, dest io.Writer) {
  loadedPet, err := loader.Load(ID)
  if err != nil {
    fmt.Fprintf(dest, "failed to load pet with ID %d. err: %s", ID, err)
    return
  }

  if loadedPet == nil {
    fmt.Fprintf(dest, "no such pet found")
    return
  }

  fmt.Fprintf(dest, "Pet named %s loaded", loadedPet.Name)
}
```

正如您所看到的，这段代码期望依赖项以某种方式运行。虽然测试不会强制执行依赖项的行为，但它们确实有助于定义代码的需求。

单元测试可以帮助恢复信心并增加理解：您的系统中是否有您不敢更改的代码，因为如果更改，会有东西会出错？您是否有一些代码，您真的不确定它是做什么的？单元测试对这两种情况都非常棒。针对这些代码编写测试是一种不显眼的方式，既可以了解它的功能，又可以验证它是否符合您的预期。这些测试的额外好处是它们还可以用作未来任何更改的回归预防，并且可以教给其他人这段代码的功能。

# 那么我为什么要写单元测试？

对我来说，写单元测试最具说服力的原因是它让我感觉良好。在一天或一周结束时，知道一切都按预期工作，并且测试正在确保这一点，感觉真好。

这并不是说没有错误，但肯定会更少。一旦修复，错误就不会再次出现，这让我免于尴尬，也节省了时间。也许最重要的是，修复错误意味着晚上和周末的支持电话更少，因为某些东西出了问题。

# 我应该测试什么？

我希望能给你一个清晰、可量化的度量标准，告诉你应该测试什么，不应该测试什么，但事情并不那么清楚。第一个规则肯定如下：

*不要测试太简单的代码。*

这包括语言特性，比如以下代码中显示的那些：

```go
func NewPet(name string) *Pet {
   return &Pet{
      Name: name,
   }
}

func TestLanguageFeatures(t *testing.T) {
   petFish := NewPet("Goldie")
   assert.IsType(t, &Pet{}, petFish)
}
```

这也包括简单的函数，就像以下代码中显示的那样：

```go
func concat(a, b string) string {
   return a + b
}

func TestTooSimple(t *testing.T) {
   a := "Hello "
   b := "World"
   expected := "Hello World"

   assert.Equal(t, expected, concat(a, b))
}
```

之后，要实事求是。我们得到报酬是为了编写能够工作的代码；测试只是确保它确实如此并持续如此的工具。测试过多是完全可能的。过多的测试不仅会导致大量额外的工作，还会导致测试变得脆弱，并在重构或扩展过程中经常出现故障。

因此，我建议从稍高且更*黑盒*的层次进行测试。看一下这个例子中的结构：

```go
type PetSaver struct{}

// save the supplied pet and return the ID
func (p PetSaver) Save(pet Pet) (int, error) {
   err := p.validate(pet)
   if err != nil {
      return 0, err
   }

   result, err := p.save(pet)
   if err != nil {
      return 0, err
   }

   return p.extractID(result)
}

// ensure the pet record is complete
func (p PetSaver) validate(pet Pet) (error) {
   return nil
}

// save to the datastore
func (p PetSaver) save(pet Pet) (sql.Result, error) {
   return nil, nil
}

// extract the ID from the result
func (p PetSaver) extractID(result sql.Result) (int, error) {
   return 0, nil
}
```

如果我们为这个结构的每个方法编写测试，那么我们将被阻止重构这些方法，甚至从`Save()`中提取它们，因为我们还需要重构相应的测试。然而，如果我们只测试`Save()`方法，这是其他方法使用的唯一方法，那么我们可以更轻松地重构其余部分。

测试的类型也很重要。通常，我们应该测试以下内容：

+   **快乐路径**：这是一切都如预期那样进行时。这些测试也倾向于记录如何使用代码。

+   **输入错误**：不正确和意外的输入通常会导致代码以奇怪的方式运行。这些测试确保我们的代码以可预测的方式处理这些问题。

+   **依赖问题**：另一个常见的失败原因是依赖项未能按我们需要的方式执行，要么是通过编码错误（如回归），要么是通过环境问题（如丢失文件或对数据库的调用失败）。

希望到现在为止，你已经对单元测试感到满意，并对它们能为你做些什么感到兴奋。测试经常被忽视的另一个方面是它们的质量。我说的不是用例覆盖率或代码覆盖率百分比，而是原始代码质量。遗憾的是，通常会以一种我们不允许自己用于生产代码的方式编写测试。

重复、可读性差和缺乏结构都是常见的错误。幸运的是，这些问题可以很容易地解决。第一步只是注意到这个问题，并且应用与生产代码一样的努力和技能。第二步需要使用一些特定于测试的技术；有很多，但在本章中，我只会介绍三种。它们如下：

+   表驱动测试

+   存根

+   模拟

# 表驱动测试

通常，在编写测试时，你会发现对同一个方法的多个测试会导致大量的重复。看这个例子：

```go
func TestRound_down(t *testing.T) {
   in := float64(1.1)
   expected := 1

   result := Round(in)
   assert.Equal(t, expected, result)
}

func TestRound_up(t *testing.T) {
   in := float64(3.7)
   expected := 4

   result := Round(in)
   assert.Equal(t, expected, result)
}

func TestRound_noChange(t *testing.T) {
   in := float64(6.0)
   expected := 6

   result := Round(in)
   assert.Equal(t, expected, result)
}
```

这里没有什么令人惊讶的，也没有什么错误的意图。表驱动测试承认了重复的需要，并将变化提取到一个*表*中。正是这个表驱动了原本需要重复的代码的单个副本。让我们将我们的测试转换成表驱动测试：

```go
func TestRound(t *testing.T) {
   scenarios := []struct {
      desc     string
      in       float64
      expected int
   }{
      {
         desc:     "round down",
         in:       1.1,
         expected: 1,
      },
      {
         desc:     "round up",
         in:       3.7,
         expected: 4,
      },
      {
         desc:     "unchanged",
         in:       6.0,
         expected: 6,
      },
   }

   for _, scenario := range scenarios {
      in := float64(scenario.in)

      result := Round(in)
      assert.Equal(t, scenario.expected, result)
   }
}
```

现在我们的测试保证在这个方法的所有场景中都是一致的，这反过来使它们更有效。如果我们必须更改函数签名或调用模式，我们只需要在一个地方进行，从而减少维护成本。最后，将输入和输出减少到一个表格中，可以廉价地添加新的测试场景，并通过鼓励我们专注于输入来帮助识别测试场景。

# 存根

有时被称为*测试替身*，存根是依赖项（即接口）的虚假实现，它提供可预测的、通常是固定的结果。存根也用于帮助执行代码路径，比如错误，否则可能会非常困难或不可能触发。

让我们看一个接口的例子：

```go
type PersonLoader interface {
   Load(ID int) (*Person, error)
}
```

假设获取器接口的生产实现实际上调用上游 REST 服务。使用我们之前的*测试类型*列表，我们想测试以下场景：

+   正常路径：获取器返回数据

+   输入错误：获取器未能找到我们请求的“人员”

+   系统错误：上游服务宕机

我们可以实现更多可能的测试，但这已经足够满足我们的目的了。

让我们想一想如果不使用存根，我们将如何进行测试：

+   正常路径：上游服务必须正常运行，并且我们必须确保我们随时都有一个有效的 ID 来请求。

+   输入错误：上游服务必须正常运行，但在这种情况下，我们必须有一个保证无效的 ID；否则，这个测试将是不稳定的。

+   系统错误：服务必须宕机？如果我们假设上游服务属于另一个团队或者有其他用户，我认为他们不会欣赏我们每次需要测试时都关闭服务。我们可以为服务配置一个不正确的 URL，但那么我们将为不同的测试场景运行不同的配置。

前面的场景存在很多非编程问题。让我们看看一点代码是否可以解决问题：

```go
// Stubbed implementation of PersonLoader
type PersonLoaderStub struct {
   Person *Person
   Error error
}

func (p *PersonLoaderStub) Load(ID int) (*Person, error) {
   return p.Person, p.Error
}
```

通过前面的存根实现，我们现在可以使用表驱动测试为每个场景创建一个存根实例，如下面的代码所示：

```go
func TestLoadPersonName(t *testing.T) {
   // this value does not matter as the stub ignores it
   fakeID := 1

   scenarios := []struct {
      desc         string
      loaderStub   *PersonLoaderStub
      expectedName string
      expectErr    bool
   }{
      {
         desc: "happy path",
         loaderStub: &PersonLoaderStub{
            Person: &Person{Name: "Sophia"},
         },
         expectedName: "Sophia",
         expectErr:    false,
      },
      {
         desc: "input error",
         loaderStub: &PersonLoaderStub{
            Error: ErrNotFound,
         },
         expectedName: "",
         expectErr:    true,
      },
      {
         desc: "system error path",
         loaderStub: &PersonLoaderStub{
            Error: errors.New("something failed"),
         },
         expectedName: "",
         expectErr:    true,
      },
   }

   for _, scenario := range scenarios {
      result, resultErr := LoadPersonName(scenario.loaderStub, fakeID)

      assert.Equal(t, scenario.expectedName, result, scenario.desc)
      assert.Equal(t, scenario.expectErr, resultErr != nil, scenario.desc)
   }
}
```

正如你所看到的，我们的测试现在不会因为依赖而失败；它们不再需要项目本身之外的任何东西，而且它们可能运行得更快。如果你觉得编写存根很繁琐，我建议两件事。首先，查看之前的第二章，*Go 的 SOLID 设计原则*，看看你是否可以将接口分解成更小的部分。其次，查看 Go 社区中的众多优秀工具之一；你肯定会找到一个适合你需求的工具。

# 过度的测试覆盖

另一个可能出现的问题是过度的测试覆盖。是的，你没看错。写太多的测试是可能的。作为技术思维的程序员，我们喜欢度量。单元测试覆盖率就是这样一种度量。虽然可能实现 100%的测试覆盖率，但实现这个目标是一个巨大的时间浪费，而且结果可能相当糟糕。考虑以下代码：

```go
func WriteAndClose(destination io.WriteCloser, contents string) error {
   defer destination.Close()

   _, err := destination.Write([]byte(contents))
   if err != nil {
      return err
   }

   return nil 
}
```

要实现 100%的覆盖率，我们需要编写一个测试，其中“destination.Close（）”调用失败。我们完全可以做到这一点，但这会实现什么？我们将测试什么？这将给我们另一个需要编写和维护的测试。如果这行代码不起作用，你会注意到吗？比如这个例子：

```go
func PrintAsJSON(destination io.Writer, plant Plant) error {
   bytes, err := json.Marshal(plant)
   if err != nil {
      return err
   }

   destination.Write(bytes)
   return nil
}

type Plant struct {
   Name string
}
```

同样，我们完全可以测试这一点。但我们真的在测试什么？在这种情况下，我们将测试 Go 标准库中的 JSON 包是否按预期工作。外部 SDK 和包应该有它们自己的测试，这样我们就可以相信它们会按照它们声称的那样工作。如果情况不是这样，我们可以随时为它们编写测试并将它们发送回项目。这样整个社区都会受益。

# 模拟

模拟非常像存根，但它们有一个根本的区别。模拟有期望。当我们使用存根时，我们的测试对我们对依赖的使用没有任何验证；而使用模拟，它们会有。你使用哪种取决于测试的类型和依赖本身。例如，你可能想为日志依赖使用存根，除非你正在编写一个确保代码在特定情况下记录日志的测试。然而，你通常需要为数据库依赖使用模拟。让我们将之前的测试从存根更改为模拟，以确保我们进行这些调用：

```go
func TestLoadPersonName(t *testing.T) {
   // this value does not matter as the stub ignores it
   fakeID := 1

   scenarios := []struct {
      desc          string
      configureMock func(stub *PersonLoaderMock)
      expectedName  string
      expectErr     bool
   }{
      {
         desc: "happy path",
         configureMock: func(loaderMock *PersonLoaderMock) {
            loaderMock.On("Load", mock.Anything).
               Return(&Person{Name: "Sophia"}, nil).
               Once()
         },
         expectedName: "Sophia",
         expectErr:    false,
      },
      {
         desc: "input error",
         configureMock: func(loaderMock *PersonLoaderMock) {
            loaderMock.On("Load", mock.Anything).
               Return(nil, ErrNotFound).
               Once()
         },
         expectedName: "",
         expectErr:    true,
      },
      {
         desc: "system error path",
         configureMock: func(loaderMock *PersonLoaderMock) {
            loaderMock.On("Load", mock.Anything).
               Return(nil, errors.New("something failed")).
               Once()
         },
         expectedName: "",
         expectErr:    true,
      },
   }

   for _, scenario := range scenarios {
      mockLoader := &PersonLoaderMock{}
      scenario.configureMock(mockLoader)

      result, resultErr := LoadPersonName(mockLoader, fakeID)

      assert.Equal(t, scenario.expectedName, result, scenario.desc)
      assert.Equal(t, scenario.expectErr, resultErr != nil, scenario.desc)
      assert.True(t, mockLoader.AssertExpectations(t), scenario.desc)
   }
}
```

在上面的示例中，我们正在验证是否进行了适当的调用，并且输入是否符合我们的预期。鉴于基于模拟的测试更加明确，它们通常比基于存根的测试更脆弱和冗长。我可以给你的最好建议是选择最适合你要编写的测试的选项，如果设置量似乎过多，请考虑这对你正在测试的代码意味着什么。您可能会遇到特性嫉妒或低效的抽象。重构以符合 DIP 或 SRP 可能会有所帮助。

与存根一样，社区中有许多用于生成模拟的优秀工具。我个人使用过 Vektra 的 mockery ([`github.com/vektra/mockery`](https://github.com/vektra/mockery))。

您可以使用以下命令安装 mockery：

```go
$ go get github.com/vektra/mockery/.../
```

安装后，我们可以使用命令行中的 mockery 为我们的测试接口生成模拟，或者通过在源代码中添加注释来使用 Go SDK 提供的`go generate`工具，如下面的代码所示：

```go
//go:generate mockery -name PersonLoader -testonly -inpkg -case=underscore
type PersonLoader interface {
   Load(ID int) (*Person, error)
}
```

安装完成后，我们运行以下命令：

```go
$ go generate ./…
```

然后生成的模拟可以像前面的示例中那样使用。在本书的第二部分中，我们将大量使用 mockery 和它生成的模拟。如果您希望下载 mockery，您将在本章末尾找到指向他们 GitHub 项目的链接。

# 测试引起的损害

在 2014 年的一篇博客文章中，*David Heinemeier Hansson*表示，为了使测试更容易或更快而对系统进行更改会导致测试引起的损害。虽然我同意 David 的意图，但我不确定我们在细节上是否一致。他创造了这个术语，以回应他认为过度应用 DI 和**测试驱动开发**（**TDD**）。

就个人而言，我对两者都采取务实的态度。它们只是工具。请尝试它们。如果它们对你有用，那太棒了。如果不行，也没关系。我从来没有能够像其他方法那样高效地使用 TDD。通常，我会先编写我的函数，至少是正常路径，然后应用我的测试。然后我进行重构和清理。

# 测试引起的损害的警告信号

尽管测试可能会对软件设计造成许多损害，但以下是一些更常见的损害类型。

# 仅因测试而存在的参数、配置选项或输出

虽然单个实例可能并不会产生巨大影响，但成本最终会累积起来。请记住，每个参数、选项和输出都是用户必须理解的内容。同样，每个参数、选项和输出都必须经过测试、记录和其他维护。

# 导致或由不完全抽象引起的参数

通常会看到数据库连接字符串或 URL 被传递到业务逻辑层，唯一目的是将其传递到数据层（数据库或 HTTP 客户端）。通常的动机是通过层传递配置，以便我们可以将实际配置替换为更友好的测试。这听起来不错，但它破坏了数据层的封装。也许更令人担忧的是，如果我们将数据层实现更改为其他内容，我们可能会有大量的重构工作。这里的实际问题不是测试，而是我们选择如何*替换数据层。使用 DIP，我们可以在业务逻辑层中将我们的需求定义为接口，然后进行模拟或存根。这将完全将业务逻辑层与数据层解耦，并消除了传递测试配置的需要。

# 在生产代码中发布模拟

模拟和存根是测试工具；因此，它们应该只存在于测试代码中。在 Go 中，这意味着一个`_test.go`文件。我见过许多好心的人在生产代码中发布接口及其模拟。这样做的第一个问题是，它引入了一个可能性，无论多么微小，这段代码最终会进入生产环境。根据此错误在系统中的位置，结果可能是灾难性的。

第二个问题有点微妙。在发布接口和模拟时，意图是减少重复，这是很棒的。然而，这也增加了依赖性和抵抗变化。一旦这段代码被发布并被其他人采用，修改它将需要改变它的所有用法。

# 使用 Godepgraph 可视化您的软件包依赖关系

在一本关于 DI 的书中，您可以期待我们花费大量时间讨论依赖关系。在最低级别的依赖关系，函数、结构和接口很容易可视化；我们可以只需阅读代码，或者如果我们想要一个漂亮的图片，我们可以制作一个类图，就像下面的例子一样：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/782bf8ac-65ed-4f92-b38d-9cc09cc1c450.png)

如果我们放大到软件包级别并尝试映射软件包之间的依赖关系，那么生活就会变得更加困难。这就是我们再次依赖开源社区丰富的开源工具的地方。这一次，我们将需要两个名为**godepgraph**和**Graphviz**（[`www.graphviz.org/`](http://www.graphviz.org/)）的工具。Godepgraph 是一个用于生成 Go 软件包依赖关系图的程序，而 Graphviz 是一个源图可视化软件。

# 安装工具

简单的`go get`将安装`godepgraph`，如下面的代码所示：

```go
 $ go get github.com/kisielk/godepgraph
```

如何安装 Graphviz 取决于您的操作系统。您可以使用 Windows 二进制文件，Linux 软件包，以及 MacPorts 和 HomeBrew 用于 OSX。

# 生成依赖图

一旦一切都安装好了，使用以下命令：

```go
$ godepgraph github.com/kisielk/godepgraph | dot -Tpng -o godepgraph.png
```

将为您生成以下漂亮的图片：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/7dd06d05-ed7a-4466-8d2b-72813417f6ff.png)

正如您所看到的，`godepgraph`的依赖图很好而且平坦，只依赖于标准库的软件包（绿色圆圈）。

让我们尝试一些更复杂的东西：让我们为我们将在本书第二部分中使用的代码生成依赖图：

```go
$ godepgraph github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/ch04/acme/ | dot -Tpng -o acme-graph-v1.png
```

这给我们一个非常复杂的图表，永远不会适合在页面上。如果您想看看它有多复杂，请查看`ch03/04_visualizing_dependencies/acme-graph-v1.png`。不要太担心试图弄清楚细节；它现在不是一个非常有用的形式。

我们可以做的第一件事是删除标准库导入（使用`-s`标志），如下面的代码所示。我们可以假设使用标准库是可以接受的，并且不是我们需要转换为抽象或使用 DI 的东西：

```go
$ godepgraph -s github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/ch04/acme/ | dot -Tpng -o acme-graph-v2.png
```

我们可以使用这个图，但对我来说还是太复杂了。假设我们不会鲁莽地采用外部依赖项，我们可以像标准库一样对待它们，并将它们从图表中隐藏（使用`-o`标志），如下面的代码所示：

```go
$ godepgraph -s -o github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/ch04/acme/ github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/ch04/acme/ | dot -Tpng -o acme-graph-v3.png
```

这给我们以下内容：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/fb1d7fc1-69ba-4873-a931-80a20e0ae5a4.png)

删除所有外部软件包后，我们可以看到我们的软件包之间的关系和依赖关系。

如果您使用 OSX 或 Linux，我在本章的源代码中包含了一个名为`depgraph.sh`的 Bash 脚本，我用它来生成这些图表。

# 解释依赖图

就像编程世界中的许多事物一样，依赖图所表达的意思在很大程度上是开放的。我使用图表来发现我可以在代码中搜索的潜在问题。

那么，*完美*的图表会是什么样子？如果有一个，它将非常平坦，几乎所有的东西都悬挂在主包下。在这样的系统中，所有的包都将完全解耦，并且除了它们的外部依赖和标准库之外，不会有任何依赖。

这实际上是不可行的。正如您将在本书的第二部分中看到的各种 DI 方法，目标通常是解耦层，以便依赖关系只能单向流动-从上到下。

从抽象的角度来看，这看起来有点像下面这样：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/e0d5132d-0e6a-431d-a581-2ffccc2079ee.png)

考虑到这一点，我们在图表中看到了哪些潜在问题？

查看任何包时要考虑的第一件事是有多少箭头指向它或指向外部。这是耦合的基本度量。指向包的每个箭头表示该包的用户。因此，每个指向内部的箭头意味着如果我们对当前包进行更改，该包可能必须更改。反之亦然-当前包依赖的包越多，它可能因它们的更改而需要更改。

考虑到 DIP，虽然从另一个包采用接口是快速简便的方法，但定义我们自己的接口允许我们依赖于自己，并减少更改的可能性。

接下来引人注目的是 config 包。几乎每个包都依赖于它。正如我们所见，承担这么多责任，对该包进行更改可能会有些棘手。在棘手程度方面，日志包也不甘落后。也许最令人担忧的是 config 包依赖于日志包。这意味着我们离循环依赖问题只差一个糟糕的导入。这些都是我们需要在后面的章节中利用 DI 来处理的问题。

否则，图表看起来很好；它从主包像金字塔一样流出，几乎所有的依赖关系都是单向的。下次您寻找改进代码库的方法或遇到循环依赖问题时，为什么不启动`godepgraph`并查看它对您的系统的说法。依赖图不会准确告诉您问题所在或问题所在，但它会给您一些提示从哪里开始查找。

# 摘要

恭喜！我们已经到达了第一部分的结尾！希望在这一点上，您已经发现了一些新东西，或者可能已经想起了一些您已经忘记的软件设计概念。

编程，就像任何专业努力一样，都需要不断讨论、学习和健康的怀疑态度。

在第二部分，您将找到几种非常不同的 DI 技术，有些您可能会喜欢，有些您可能不会。有了我们迄今为止所检查的一切，您将毫无困难地确定每种技术何时以及如何适合您。

# 问题

1.  为什么代码的可用性很重要？

1.  谁最能从具有良好用户体验的代码中受益？

1.  如何构建良好的用户体验？

1.  单元测试对您有什么作用？

1.  您应该考虑哪些测试场景？

1.  表驱动测试如何帮助？

1.  测试如何损害您的软件设计？
