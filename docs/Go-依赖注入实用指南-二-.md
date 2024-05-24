# Go 依赖注入实用指南（二）

> 原文：[`zh.annas-archive.org/md5/87633C3DBA89BFAAFD7E5238CC73EA73`](https://zh.annas-archive.org/md5/87633C3DBA89BFAAFD7E5238CC73EA73)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第四章：ACME 注册服务简介

在本章中，我们将介绍一个名为***ACME 注册服务***的小型但虚假的服务。这个服务的代码将成为本书其余大部分示例的基础。我们将研究这个服务所在的商业环境，讨论服务和代码的目标，最后，我们将看一些我们可以通过应用**依赖注入**（**DI**）来解决的问题的例子。

通过本章结束时，您应该有足够的知识来加入团队，一起完成我们将在接下来的章节中进行的改进。

本章将涵盖以下主题：

+   我们系统的目标

+   我们系统的介绍

+   已知问题

# 技术要求

由于我们正在了解本书中将要使用的系统，我强烈建议下载源代码并在您喜欢的 IDE 中运行它。

本章中的所有代码都可以在[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch04`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch04)找到。

有关如何获取代码和配置示例服务的说明，请参阅 README 文件，网址为[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/)。

您可以在`ch04/acme`文件中找到服务的代码。

# 我们系统的目标

您有没有尝试过从种子开始种植自己的蔬菜？这是一个漫长、缓慢但令人满意的经历。构建优秀的代码也是一样的。在园艺中，跳过第一步直接从苗圃购买植物作为幼苗可能更常见，编程也是如此。大多数情况下，当我们加入一个项目时，代码已经存在；有时它很健康，但通常它是生病和垂死的。

在这种情况下，我们正在采用一个系统。它有效，但有一些问题——好吧，也许不止一些。通过一些精心的关怀，我们将把这个系统变成健康和蓬勃发展的东西。

那么，我们如何定义一个健康的系统？我们现有的系统有效；它做了业务需要它做的事情。这就足够了，对吧？

绝对不！我们可能明确地被支付一定数量的功能，但我们隐含地被支付以提供可维护和可扩展的代码。除了考虑我们为什么被支付，让我们以更自私的角度来看：您希望明天的工作比今天更容易还是更难？

一个健康的代码库具有以下关键特征：

+   高可读性

+   高可测试性

+   低耦合

我们在第一部分中已经谈到或暗示了所有这些要求，但它们的重要性意味着我们将再次重点介绍它们。

# 高可读性

简而言之，高可读性意味着能够阅读代码并理解它。不可读的代码会减慢您的速度，并可能导致错误，您可能会假设它做一件事，但实际上它做了另一件事。

让我们看一个示例，如下所示的代码：

```go
type House struct {
   a string
   b int
   t int
   p float64
}
```

在这个例子中，代码的命名存在问题。短变量名似乎是一个胜利；少打字意味着少工作，对吗？短期内是的，但从长远来看，它们很难理解。您被迫阅读代码以确定变量的含义，然后在该上下文中重新阅读代码，而一个好的名称本来可以省去我们的第一步。这并不意味着超长的名称是正确的；它们也增加了心理负担并浪费了屏幕空间。一个好的变量通常是一个单词，具有常见的含义或目的。

有两种情况下不应遵循上述原则。第一种是方法。也许是因为我使用 C++和 Java 的时间以及 Go 中缺少`this`运算符，但我发现短方法接收器很有用，可能是因为它们在整个结构中是一致的，只有短变量使它们与其他所有变量有所不同。

第二种情况是我们在处理测试名称时。测试本质上是小故事；在这种情况下，长名称通常是完全合适的。注释也可以起作用，但效果较差，因为测试运行器在失败时输出测试的名称而不是注释。

让我们在考虑这些想法的基础上更新前面的示例，看看它是否更好，如下所示：

```go
type House struct {
   address string
   bedrooms int
   toilets int
   price float64
}
```

有关可读性的更多信息，请翻回到第三章中的*Optimizing for humans*部分。

# 高可测试性

编写自动化测试可能会感觉像是*额外的工作*，会占用我们编写功能的真正目的的时间。事实上，自动化测试的主要目标是确保代码的执行符合预期，并且尽管我们对代码库作出任何更改或添加，它仍然如此。但自动化测试确实有成本：您必须编写和维护它们。因此，如果我们的代码易于测试，我们就不太可能在测试上吝啬，并匆忙进行下一个令人兴奋的功能。

让我们看一个示例，如下所示：

```go
func longMethod(resp http.ResponseWriter, req *http.Request) {
   err := req.ParseForm()
   if err != nil {
      resp.WriteHeader(http.StatusPreconditionFailed)
      return
   }
   userID, err := strconv.ParseInt(req.Form.Get("UserID"), 10, 64)
   if err != nil {
      resp.WriteHeader(http.StatusPreconditionFailed)
      return
   }

   row := DB.QueryRow("SELECT * FROM Users WHERE userID = ?", userID)

   person := &Person{}
   err = row.Scan(person.ID, person.Name, person.Phone)
   if err != nil {
      resp.WriteHeader(http.StatusInternalServerError)
      return
   }

   encoder := json.NewEncoder(resp)
   err = encoder.Encode(person)
   if err != nil {
      resp.WriteHeader(http.StatusInternalServerError)
      return
   }
}
```

所以这个例子有什么问题？最简单的答案是它知道得太多，或者更自私地说，它让我知道得太多。

它包含边界层（HTTP 和数据库）逻辑，也包含业务逻辑。它相当长，意味着我必须在脑海中保留更多的上下文。它基本上违反了**单一职责原则**（**SRP**）。有很多原因它可能会改变。输入格式可能会改变。数据库格式可能会改变。业务规则可能会改变。任何这样的改变都意味着这段代码的每个测试很可能也需要改变。让我们看看前面代码的测试可能是什么样子，如下所示：

```go
func TestLongMethod_happyPath(t *testing.T) {
   // build request
   request := &http.Request{}
   request.PostForm = url.Values{}
   request.PostForm.Add("UserID", "123")

   // mock the database
   var mockDB sqlmock.Sqlmock
   var err error

   DB, mockDB, err = sqlmock.New()
   require.NoError(t, err)
     mockDB.ExpectQuery("SELECT .* FROM people WHERE ID = ?").
    WithArgs(123).
    WillReturnRows(
      sqlmock.NewRows(
        []string{"ID", "Name", "Phone"}).
        AddRow(123, "May", "0123456789"))

   // build response
   response := httptest.NewRecorder()

   // call method
   longMethod(response, request)

   // validate response
   require.Equal(t, http.StatusOK, response.Code)

   // validate the JSON
   responseBytes, err := ioutil.ReadAll(response.Body)
   require.NoError(t, err)

   expectedJSON := `{"ID":123,"Name":"May","Phone":"0123456789"}` + "\n"
   assert.Equal(t, expectedJSON, string(responseBytes))
}
```

正如您所看到的，这个测试冗长且笨重。最糟糕的是，对于这个方法的任何其他测试都将涉及复制这个测试并进行微小的更改。这听起来很有效，但有两个问题。这些样板代码中可能很难发现小的差异，而我们测试的功能发生任何更改都需要对所有这些测试进行更改。

虽然有许多方法可以修复我们示例的可测试性，但也许最简单的选择是分离不同的关注点，然后逐个方法进行大部分测试，如下所示：

```go
func shortMethods(resp http.ResponseWriter, req *http.Request) {
   userID, err := extractUserID(req)
   if err != nil {
      resp.WriteHeader(http.StatusInternalServerError)
      return
   }

   person, err := loadPerson(userID)
   if err != nil {
      resp.WriteHeader(http.StatusInternalServerError)
      return
   }

   outputPerson(resp, person)
}

func extractUserID(req *http.Request) (int64, error) {
   err := req.ParseForm()
   if err != nil {
      return 0, err
   }

   return strconv.ParseInt(req.Form.Get("UserID"), 10, 64)
}

func loadPerson(userID int64) (*Person, error) {
   row := DB.QueryRow("SELECT * FROM people WHERE ID = ?", userID)

   person := &Person{}
   err := row.Scan(&person.ID, &person.Name, &person.Phone)
   if err != nil {
      return nil, err
   }
   return person, nil
}

func outputPerson(resp http.ResponseWriter, person *Person) {
   encoder := json.NewEncoder(resp)
   err := encoder.Encode(person)
   if err != nil {
      resp.WriteHeader(http.StatusInternalServerError)
      return
   }
}
```

有关单元测试对您的作用，可以翻回到第三章中的*A security blanket named unit tests*部分。

# 低耦合度

耦合是一个对象或包与其他对象的关系程度的度量。如果对一个对象的更改可能导致其他对象的更改，或者反之亦然，则认为该对象的耦合度高。相反，当一个对象的耦合度低时，它独立于其他对象或包。在 Go 中，低耦合度最好通过隐式接口和稳定且最小化的公开 API 来实现。

低耦合度是可取的，因为它导致代码的更改局部化。在下面的示例中，通过使用隐式接口来定义我们的要求，我们能够使自己免受对依赖项的更改的影响：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/a89adf8d-2d89-403c-85e4-14f073fe2245.png)

正如您从前面的例子中所看到的，我们不再依赖 FileManager Package，这在其他方面也对我们有所帮助。这种缺乏依赖也意味着在阅读代码时我们需要记住的上下文更少，在编写测试时依赖更少。

要了解如何实现低耦合性，请翻回到第二章中涵盖的*SOLID Design Principles for Go*。

# 关于目标的最终想法

到现在为止，您可能已经看到了一个模式。所有这些目标将导致易于阅读、理解、测试和扩展的代码，也就是说，可维护的代码。虽然这些目标可能看起来是自私或完美主义的，但我认为这对于企业长远来说是必不可少的。在短期内，向用户提供价值，通常以功能的形式，是至关重要的。但是，当这样做得不好时，可以添加功能的速度、添加功能所需的程序员数量以及因更改引入的错误数量都会增加，并且会给企业带来的成本将超过开发良好代码的成本。

现在我们已经定义了我们对服务的目标，让我们来看看它的当前状态。

# 我们系统的介绍

欢迎加入项目！那么，加入团队需要了解什么呢？与任何项目一样，您首先想要了解它的功能，用户以及部署环境。

我们正在处理的系统是基于 HTTP 的事件注册服务。它旨在被我们的 Web 应用程序或原生移动应用程序调用。以下图表显示了它如何适应我们的网络：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/f6f650d4-a5f0-4ddf-8df7-9eb76718354a.png)

目前有三个端点，列举如下：

+   **注册**：这将创建一个新的注册记录

+   **获取**：这将返回现有注册记录的全部详细信息

+   **列表**：这将返回所有注册的列表

所有请求和响应负载都是 JSON 格式。数据存储在 MySQL 数据库中。

我们还有一个上游货币转换服务——我们在注册时调用它，将 100 欧元的注册价格转换为用户请求的货币。

如果您希望在本地运行服务或测试，请参考`ch04/README.md`文件中的说明。

# 软件架构

从概念上讲，我们的代码有三层，如下图所示：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/b9bd6944-d7c7-40ee-b32d-b3ad0dfe40ce.png)

这些层如下：

+   REST：这个包接受 HTTP 请求并将它们转换为业务逻辑中的函数调用。然后将业务逻辑响应转换回 HTTP。

+   业务逻辑：这就是魔法发生的地方。这一层使用外部服务和数据层来执行业务功能。

+   外部服务和数据：这一层包括访问数据库和提供货币汇率的上游服务的代码。

我在本节的开头使用了“概念上”的词，因为我们的导入图显示了一个略有不同的故事：

！[](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/2c796c74-08f7-49c5-acce-06f2aca8863b.png)

正如您所看到的，我们有一个准第四层，其中包括配置和日志包，更糟糕的是，一切似乎都依赖于它们。这很可能会在某个时候给我们带来问题。

这里显示了一个不太明显的问题。看到 REST 和数据包之间的链接了吗？这表明我们的 HTTP 层依赖于数据层。这是有风险的，因为它们有不同的生命周期和不同的变更原因。我们将在下一节中看到这一点以及其他一些令人不快的惊喜。

# 已知问题

每个系统都有它的骨架，我们不以之为傲的代码部分。有时，它们是我们本可以做得更好的代码部分，如果我们有更多的时间的话。这个项目也不例外。让我们来看看我们目前知道的问题。

# 可测试性

尽管是一个小型且工作正常的服务，但我们有相当多的问题，其中最严重的是难以测试。现在，我们不想开始引入测试导致的破坏，但我们确实希望有一个我们有信心的系统。为了实现这一点，我们需要减少测试的复杂性和冗长。看看下面的测试：

```go
func TestGetHandler_ServeHTTP(t *testing.T) {
   // ensure the test always fails by giving it a timeout
   ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
   defer cancel()

     // Create and start a server
  // With out current implementation, we cannot test this handler 
  // without a full server as we need the mux.
  address, err := startServer(ctx)
  require.NoError(t, err)

   // build inputs
   response, err := http.Get("http://" + address + "/person/1/")

   // validate outputs
   require.NoError(t, err)
   require.Equal(t, http.StatusOK, response.StatusCode)

   expectedPayload := []byte(`{"id":1,"name":"John","phone":"0123456780","currency":"USD","price":100}` + "\n")
   payload, _ := ioutil.ReadAll(response.Body)
   defer response.Body.Close()

   assert.Equal(t, expectedPayload, payload)
}
```

这个测试是针对我们最简单的端点`Get`的。问问自己，这个测试可能会以什么方式失败？什么样的技术或业务相关的变化会导致这个测试需要更新？系统的哪些部分必须正常工作才能通过这个测试？

对这些问题的一些潜在答案包括以下：

+   如果 URL 路径发生变化，这个测试就会失败

+   如果输出格式发生变化，这个测试就会失败

+   如果`config`文件没有正确配置，这个测试就会失败

+   如果数据库不工作，这个测试就会失败

+   如果数据库中缺少记录 ID 1，这个测试就会失败

+   如果业务逻辑层出现错误，这个测试就会失败

+   如果数据库层出现错误，这个测试就会失败

这个简单端点的测试列表相当恶劣。这个测试可以以这么多种方式失败意味着它是一个脆弱的测试。脆弱的测试令人筋疲力尽，而且通常编写起来也很费力。

# 工作的重复

让我们来看看业务层中`Get`端点的测试，如下所示：

```go
func TestGetter_Do(t *testing.T) {
   // inputs
   ID := 1
   name := "John"

   // call method
   getter := &Getter{}
   person, err := getter.Do(ID)

   // validate expectations
   require.NoError(t, err)
   assert.Equal(t, ID, person.ID)
   assert.Equal(t, name, person.FullName)
}
```

这个测试几乎与前一节的测试相同。也许这是合理的，因为它是相同的端点。但让我们以自私的角度来看，这个测试除了更好的单元测试覆盖率之外，还给了我们什么？

没有。因为之前的测试实际上是一个集成测试，它测试了整个堆栈。这个测试也是一个集成测试，但是更深一层。因为它测试了之前示例中测试过的代码，我们做了双倍的工作，有双倍数量的测试需要维护，但没有任何收获。

# 测试中的隔离不足

在我们之前的代码中显示的缺乏隔离是层之间高耦合的症状。在接下来的部分，我们将应用 DI 和**依赖反转原则**（**DIP**）来解决这个问题。

# 数据和 REST 包之间的高耦合

我们的`REST`包使用了`data`包中定义的`Person`结构。从表面上看，这是有道理的。更少的代码意味着写和维护更少的工作；然而，这意味着输出格式和数据格式是相互关联的。考虑一下，如果我们开始存储与客户相关的私人信息，比如密码或 IP 地址会发生什么。这些信息可能对某些功能是必要的，但很少需要通过`Get`或`List`端点发布。

还有另一个考虑我们应该记住。随着存储的数据量或使用量的增长，可能需要更改数据的格式。对这个结构的任何更改都会破坏 API 合同，因此也会破坏我们的用户。

也许这里最大的风险就是人为错误；如果你在`data`包上工作，你可能不记得`REST`包如何使用那个结构。假设我们添加了用户登录系统的功能。最简单的实现方式是在数据库中添加一个密码字段。如果我们的`Get`端点构建其输出如下所示的代码会发生什么？

```go
// output the supplied person as JSON
func (h *GetHandler) writeJSON(writer io.Writer, person *data.Person) error {
   return json.NewEncoder(writer).Encode(person)
}
```

我们的`Get`端点负载现在将包括密码。哎呀！

这个问题是 SRP 违规，解决这个问题的方法是确保这两个用例是解耦的，并允许它们分别发展。

# 与配置包的高耦合

正如我们在依赖图中看到的那样，几乎所有东西都依赖于`config`包。这主要原因是代码直接引用公共全局变量来配置自身。这带来的第一个问题是它对测试的影响。现在几乎所有的测试都确保在运行之前已经正确初始化了配置全局变量。因为所有的测试都使用同一个全局变量，我们被迫在不改变配置的情况下进行选择，这影响了我们的测试能力，或者按顺序运行测试，这浪费了我们的时间。

让我们来看一个例子，如下面的代码所示：

```go
// bind stop channel to context
ctx := context.Background()

// start REST server
server := rest.New(config.App.Address)
server.Listen(ctx.Done())
```

在这段代码中，我们正在启动我们的 REST 服务器，并将地址（主机和端口）传递给它以绑定。如果我们决定要启动多个服务器以便隔离测试不同的事物，那么我们将不得不更改存储在`config.App.Address`中的值。然而，通过在一个测试中这样做，我们可能会意外地影响到另一个测试。

第二个问题并不经常出现，但这种耦合也意味着这段代码不能轻松地被其他项目、包或用例所使用，超出了最初的意图。

最后一个问题可能是最烦人的：由于循环依赖问题，您无法在配置中使用自定义数据类型，这些类型在`Config`包之外定义。

考虑以下代码：

```go
// Currency is a custom type; used for convenience and code readability
type Currency string

// UnmarshalJSON implements json.Unmarshaler
func (c *Currency) UnmarshalJSON(in []byte) error {
   var s string
   err := json.Unmarshal(in, &s)
   if err != nil {
      return err
   }

   currency, valid := validCurrencies[s]
   if !valid {
      return fmt.Errorf("'%s' is not a valid currency", s)
   }

   *c = currency

   return nil
}
```

假设您的配置包括以下内容：

```go
type Config struct {
   DefaultCurrency currency.Currency `json:"default_currency"`
}
```

在这种情况下，任何尝试在与我们的`Currency`类型相同的包中使用配置包都将被阻止。

# 下游货币服务

交换包对外部服务进行 HTTP 调用以获取汇率。目前，当运行测试时，它将调用该服务。这意味着我们的测试具有以下特点：

+   它们需要互联网连接

+   它们依赖于下游服务可访问和正常工作

+   它们需要来自下游服务的适当凭据和配额

所有这些因素要么超出我们的控制，要么与我们的服务完全无关。如果我们从测试的可靠性是我们工作质量的衡量标准的角度来看，那么我们的质量现在取决于我们无法控制的事情。这远非理想。

我们可以创建一个虚假的货币服务，并更改我们的配置指向该服务，在测试交换包时，我可能会这样做。但在其他地方这样做是令人讨厌的，并且容易出错。

# 总结

在本章中，我们介绍了一个状况相当糟糕的小型服务。我们将通过一系列重构来改进这个服务，同时探索许多 DI 技术。在接下来的章节中，我们将通过应用 Go 中可用的不同 DI 技术来解决本章中概述的问题。

对于每种不同的技术，要记住代码异味，SOLID 原则，代码 UX 以及我们在第一部分讨论的所有其他想法。还要记得带上你内心的怀疑者。

始终要问自己，这种技术实现了什么？这种技术如何使代码变得更好/更糟？你如何应用这种技术来改进属于你的其他代码？

# 问题

1.  对于我们的服务定义的目标，哪一个对你个人来说最重要？

1.  概述中列出的问题中哪一个似乎是最紧迫或最重要的？


# 第五章：使用猴子补丁进行依赖注入

您的代码是否依赖于全局变量？您的代码是否依赖于文件系统？您是否曾经尝试过测试数据库错误处理代码？

在本章中，我们将研究猴子补丁作为一种在测试期间*替换*依赖项的方法，并以一种其他情况下不可能的方式进行测试。无论这些依赖项是对象还是函数，我们都将应用猴子补丁到我们的示例服务中，以便我们可以将测试与数据库解耦；将不同层解耦，并且所有这些都不需要进行重大重构。

在继续我们务实、怀疑的方法时，我们还将讨论猴子补丁的优缺点。

本章将涵盖以下主题：

+   猴子魔术——猴子补丁简介

+   猴子补丁的优点

+   应用猴子补丁

+   猴子补丁的缺点

# 技术要求

熟悉我们在第四章中介绍的服务的代码将是有益的，*ACME 注册服务简介*。您可能还会发现阅读和运行本章的完整代码版本对您有所帮助，这些代码可在[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch05`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch05)中找到。

获取代码并配置示例服务的说明可在此处的 README 中找到[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/)。

您可以在`ch05/acme`中找到我们服务的代码，并已应用本章的更改。

# 猴子魔术！

猴子补丁是在运行时改变程序，通常是通过替换函数或变量来实现的。

虽然这不是传统的**依赖注入**（**DI**）形式，但它可以在 Go 中用于进行测试。事实上，猴子补丁可以用于以其他方式不可能的方式进行测试。

首先让我们考虑一个现实世界的类比。假设您想测试车祸对人体的影响。您可能不会自愿成为测试期间车内的人。也不允许您对车辆进行更改以便进行测试。但是您可以在测试期间将人类换成碰撞测试假人（猴子补丁）。

在代码中进行猴子补丁的过程与现实情况相同；更改仅在测试期间存在，并且在许多情况下对生产代码的影响很小。

对于熟悉 Ruby、Python 和 JavaScript 等动态语言的人来说，有一个快速说明：可以对单个类方法进行猴子补丁，并在某些情况下对标准库进行补丁。Go 只允许我们对变量进行补丁，这可以是对象或函数，正如我们将在本章中看到的。

# 猴子补丁的优点

猴子补丁作为一种 DI 形式，在实施和效果上与本书中介绍的其他方法非常不同。因此，在某些情况下，猴子补丁是唯一的选择或唯一简洁的选择。猴子补丁的其他优点将在本节详细介绍。

**通过 monkey patching 进行 DI 的实现成本低廉**——在这本书中，我们谈论了很多关于解耦的内容，即我们的代码的各个部分应该保持独立，即使它们使用/依赖于彼此。我们引入抽象并将它们注入到彼此中。让我们退后一步，考虑一下为什么我们首先要求代码解耦。这不仅仅是为了更容易测试。它还允许代码单独演变，并为我们提供了小组，可以单独思考代码的不同部分。正是这种解耦或分离，使得 monkey patching 可以应用。

考虑这个函数：

```go
func SaveConfig(filename string, cfg *Config) error {
   // convert to JSON
   data, err := json.Marshal(cfg)
   if err != nil {
      return err
   }

   // save file
   err = ioutil.WriteFile(filename, data, 0666)
   if err != nil {
      log.Printf("failed to save file '%s' with err: %s", filename, err)
      return err
   }

   return nil
}
```

我们如何将这个函数与操作系统解耦？换个说法：当文件丢失时，我们如何测试这个函数的行为？

我们可以用`*os.File`或`io.Writer`替换文件名，但这只是把问题推到了别处。我们可以将这个函数重构为一个结构体，将对`ioutil.WriteFile`的调用改为一个抽象，然后进行模拟。但这听起来像是很多工作。

使用 monkey patching，有一个更便宜的选择：

```go
func SaveConfig(filename string, cfg *Config) error {
   // convert to JSON
   data, err := json.Marshal(cfg)
   if err != nil {
      return err
   }

   // save file
   err = writeFile(filename, data, 0666)
   if err != nil {
      log.Printf("failed to save file '%s' with err: %s", filename, err)
      return err
   }

   return nil
}

// Custom type that allows us to Monkey Patch
var writeFile = ioutil.WriteFile
```

一行代码，我们就给自己提供了用模拟替换`writeFile()`的能力，这样我们就可以轻松测试正常路径和错误场景。

**允许我们模拟其他包，而不完全了解其内部情况**——在前面的例子中，您可能已经注意到我们在模拟一个标准库函数。您知道如何使`ioutil.WriteFile()`失败吗？当然，我们可以在标准库中进行搜索；虽然这是提高 Go 技能的好方法，但这不是我们得到报酬的方式。在这种情况下，`ioutil.WriteFile()`可能会失败并不重要。真正重要的是我们的代码如何对错误做出反应。

Monkey patching，就像其他形式的模拟一样，为我们提供了不必关心依赖的内部情况，但却能让它按我们需要的方式运行的能力。

我建议从*外部*进行测试，无论如何都是正确的。解耦我们对依赖的思考方式可以确保任何测试对内部情况的了解更少，因此不容易受到实现或环境变化的影响。如果`io.WriteFile()`的内部实现细节发生任何变化，它们都不会破坏我们的测试。我们的测试只依赖于我们的代码，因此它们的可靠性完全取决于我们自己。

**通过 monkey patching 进行 DI 对现有代码的影响很小**——在前面的例子中，我们将外部依赖定义如下：

```go
var writeFile = ioutil.WriteFile
```

让我们稍微改变一下：

```go
type fileWriter func(filename string, data []byte, perm os.FileMode) error

var writeFile fileWriter = ioutil.WriteFile
```

这让你想起了什么吗？在这个版本中，我们明确地定义了我们的需求，就像我们在第二章中的*Go 的 SOLID 设计原则*部分所做的那样。虽然这种改变完全是多余的，但它确实引发了一些有趣的问题。

让我们回过头来看看，如果不使用 monkey patching 来测试我们的方法，我们需要做哪些改变。第一个选择是将`io.WriteFile`注入到函数中，如下面的代码所示：

```go
func SaveConfig(writer fileWriter, filename string, cfg *Config) error {
   // convert to JSON
   data, err := json.Marshal(cfg)
   if err != nil {
      return err
   }

   // save file
   err = writer(filename, data, 0666)
   if err != nil {
      log.Printf("failed to save file '%s' with err: %s", filename, err)
      return err
   }

   return nil
}

// This custom type is not strictly needed but it does make the function 
// signature a little cleaner
type fileWriter func(filename string, data []byte, perm os.FileMode) error
```

这有什么问题吗？就我个人而言，我对此有三个问题。首先，这是一个小而简单的函数，只有一个依赖项；如果我们有更多的依赖项，这个函数将变得非常丑陋。换句话说，代码的用户体验很糟糕。

其次，它会破坏函数实现的封装（信息隐藏）。这可能会让人觉得我在进行狂热的争论，但我并不是这样认为的。想象一下，如果我们重构`SaveConfig()`的实现，以至于我们需要将`io.WriteFile`更改为其他内容。在这种情况下，我们将不得不更改我们函数的每次使用，可能会有很多更改，因此也会有很大的风险。

最后，这种改变可以说是测试引起的伤害，正如我们在第三章的*测试引起的伤害*部分所讨论的，*用户体验编码*，因为这是一种只用于改进测试而不增强非测试代码的改变。

另一个可能会想到的选择是将我们的函数重构为一个对象，然后使用更传统的 DI 形式，如下面的代码所示：

```go
type ConfigSaver struct {
   FileWriter func(filename string, data []byte, perm os.FileMode) error
}

func (c ConfigSaver) Save(filename string, cfg *Config) error {
   // convert to JSON
   data, err := json.Marshal(cfg)
   if err != nil {
      return err
   }

   // save file
   err = c.FileWriter(filename, data, 0666)
   if err != nil {
      log.Printf("failed to save file '%s' with err: %s", filename, err)
      return err
   }

   return nil
}
```

遗憾的是，这种重构遭受了与之前相似的问题，其中最重要的是它有可能需要大量的改变。正如你所看到的，monkey patching 需要的改变明显比传统方法少得多。

**通过 monkey patching 进行 DI 允许测试全局变量和单例** - 你可能会认为我疯了，Go 语言没有单例。严格来说可能不是，但你有没有读过`math/rand`标准库包（[`godoc.org/math/rand`](https://godoc.org/math/rand)）的代码？在其中，你会发现以下内容：

```go
// A Rand is a source of random numbers.
type Rand struct {
   src Source

   // code removed
}

// Int returns a non-negative pseudo-random int.
func (r *Rand) Int() int {
   // code changed for brevity
   value := r.src.Int63()
   return int(value)
}

/*
 * Top-level convenience functions
 */

var globalRand = New(&lockedSource{})

// Int returns a non-negative pseudo-random int from the default Source.
func Int() int { return globalRand.Int() }

// A Source represents a source of uniformly-distributed
// pseudo-random int64 values in the range 0, 1<<63).
type Source interface {
   Int63() int64

   // code removed
}
```

你如何测试`Rand`结构？你可以用一个返回可预测的非随机结果的模拟来交换`Source`，很容易。

现在，你如何测试方便函数`Int()`？这并不容易。这个方法，根据定义，返回一个随机值。然而，通过 monkey patching，我们可以，如下面的代码所示：

```go
func TestInt(t *testing.T) {
   // monkey patch
   defer func(original *Rand) {
      // restore patch after use
      globalRand = original
   }(globalRand)

   // swap out for a predictable outcome
   globalRand = New(&stubSource{})
   // end monkey patch

   // call the function
   result := Int()
   assert.Equal(t, 234, result)
}

// this is a stubbed implementation of Source that returns a 
// predictable value
type stubSource struct {
}

func (s *stubSource) Int63() int64 {
   return 234
}
```

通过 monkey patching，我们能够测试单例的使用，而不需要对客户端代码进行任何更改。通过其他方法实现这一点，我们将不得不引入一层间接，这反过来又需要对客户端代码进行更改。

# 应用 monkey patching

让我们将 monkey patching 应用到我们在[第四章中介绍的 ACME 注册服务上，*ACME 注册服务简介*。我们希望通过服务改进许多事情之一是测试的可靠性和覆盖范围。在这种情况下，我们将在`data`包上进行工作。目前，我们只有一个测试，看起来是这样的：

```go
func TestData_happyPath(t *testing.T) {
   in := &Person{
      FullName: "Jake Blues",
      Phone:    "01234567890",
      Currency: "AUD",
      Price:    123.45,
   }

   // save
   resultID, err := Save(in)
   require.Nil(t, err)
   assert.True(t, resultID > 0)

   // load
   returned, err := Load(resultID)
   require.NoError(t, err)

   in.ID = resultID
   assert.Equal(t, in, returned)

   // load all
   all, err := LoadAll()
   require.NoError(t, err)
   assert.True(t, len(all) > 0)
}
```

在这个测试中，我们进行了保存，然后使用`Load()`和`LoadAll()`方法加载新保存的注册。

这段代码至少有三个主要问题。

首先，我们只测试*快乐路径*；我们根本没有测试错误处理。

其次，测试依赖于数据库。有些人会认为这没问题，我不想加入这场辩论。在这种情况下，使用实时数据库会导致我们对`LoadAll()`的测试不够具体，这使得我们的测试不如可能的彻底。

最后，我们一起测试所有的函数，而不是孤立地测试。考虑当测试的以下部分失败时会发生什么：

```go
returned, err := Load(resultID)
require.NoError(t, err)
```

问题在哪里？是`Load()`出了问题还是`Save()`出了问题？这是关于孤立测试的论点的基础。

`data`包中的所有函数都依赖于`*sql.DB`的全局实例，它代表了一个数据库连接池。因此，我们将对该全局变量进行 monkey patching，并引入一个模拟版本。

# 介绍 SQLMock

SQLMock 包（[`github.com/DATA-DOG/go-sqlmock`](https://github.com/DATA-DOG/go-sqlmock)）自述如下：

一个模拟实现 sql/driver 的模拟库。它只有一个目的 - 在测试中模拟任何 sql driver 的行为，而不需要真正的数据库连接

我发现 SQLMock 很有用，但通常比直接使用数据库更费力。作为一个务实的程序员，我很乐意使用任何一种。通常，选择使用哪种取决于我希望测试如何工作。如果我想要非常精确，没有与表的现有内容相关的问题，并且没有由表的并发使用引起的数据竞争的可能性，那么我会花额外的精力使用 SQLMock。

当两个或更多 goroutines 同时访问变量，并且至少有一个 goroutine 正在写入变量时，就会发生数据竞争。

让我们看看如何使用 SQLMock 进行测试。考虑以下函数：

```go
func SavePerson(db *sql.DB, in *Person) (int, error) {
   // perform DB insert
   query := "INSERT INTO person (fullname, phone, currency, price) VALUES (?, ?, ?, ?)"
   result, err := db.Exec(query, in.FullName, in.Phone, in.Currency, in.Price)
   if err != nil {
      return 0, err
   }

   // retrieve and return the ID of the person created
   id, err := result.LastInsertId()
   if err != nil {
      return 0, err
   }
   return int(id), nil
}
```

这个函数以`*Person`和`*sql.DB`作为输入，将人保存到提供的数据库中，然后返回新创建记录的 ID。这个函数使用传统的 DI 形式将数据库连接池传递给函数。这使我们可以轻松地用假的数据库连接替换真实的数据库连接。现在，让我们构建测试。首先，我们使用 SQLMock 创建一个模拟数据库：

```go
testDb, dbMock, err := sqlmock.New()
require.NoError(t, err)
```

然后，我们将期望的查询定义为正则表达式，并使用它来配置模拟数据库。在这种情况下，我们期望一个单独的`db.Exec`调用返回`2`，即新创建记录的 ID，以及`1`，即受影响的行：

```go
queryRegex := `\QINSERT INTO person (fullname, phone, currency, price) VALUES (?, ?, ?, ?)\E`

dbMock.ExpectExec(queryRegex).WillReturnResult(sqlmock.NewResult(2, 1))
```

现在我们调用这个函数：

```go
resultID, err := SavePerson(testDb, person)
```

然后，我们验证结果和模拟的期望：

```go
require.NoError(t, err)
assert.Equal(t, 2, resultID)
assert.NoError(t, dbMock.ExpectationsWereMet())
```

现在我们已经有了如何利用 SQLMock 来测试我们的数据库交互的想法，让我们将其应用到我们的 ACME 注册代码中。

# 使用 SQLMock 进行 monkey patching

首先，快速回顾一下：当前的`data`包不使用 DI，因此我们无法像前面的例子中那样传入`*sql.DB`。该函数当前的样子如下所示：

```go
// Save will save the supplied person and return the ID of the newly 
// created person or an error.
// Errors returned are caused by the underlying database or our connection
// to it.
func Save(in *Person) (int, error) {
   db, err := getDB()
   if err != nil {
      logging.L.Error("failed to get DB connection. err: %s", err)
      return defaultPersonID, err
   }

   // perform DB insert
   query := "INSERT INTO person (fullname, phone, currency, price) VALUES (?, ?, ?, ?)"
   result, err := db.Exec(query, in.FullName, in.Phone, in.Currency, in.Price)
   if err != nil {
      logging.L.Error("failed to save person into DB. err: %s", err)
      return defaultPersonID, err
   }

   // retrieve and return the ID of the person created
   id, err := result.LastInsertId()
   if err != nil {
      logging.L.Error("failed to retrieve id of last saved person. err: %s", err)
      return defaultPersonID, err
   }
   return int(id), nil
}
```

我们可以重构成这样，也许将来我们可能会这样做，但目前我们几乎没有对这段代码进行任何测试，而没有测试进行重构是一个可怕的想法。你可能会想到类似于*但如果我们使用 monkey patching 编写测试，然后将来进行不同风格的 DI 重构，那么我们将不得不重构这些测试*，你是对的；这个例子有点牵强。也就是说，写测试来为你提供安全保障或高水平的信心，然后以后删除它们是没有错的。这可能会感觉像是在做重复的工作，但这肯定比在一个正在运行且人们依赖的系统中引入回归，以及调试这种回归的工作要少得多。

首先引人注目的是 SQL。我们几乎需要在我们的测试中使用完全相同的字符串。因此，为了更容易地长期维护代码，我们将其转换为常量，并将其移到文件顶部。由于测试将与我们之前的例子非常相似，让我们首先仅检查 monkey patching。从之前的例子中，我们有以下内容：

```go
// define a mock db
testDb, dbMock, err := sqlmock.New()
defer testDb.Close()

require.NoError(t, err)
```

在这些行中，我们正在创建`*sql.DB`的测试实例和一个控制它的模拟。在我们可以对`*sql.DB`的测试实例进行 monkey patching 之前，我们首先需要创建原始实例的备份，以便在测试完成后进行恢复。为此，我们将使用`defer`关键字。

对于不熟悉的人来说，`defer`是一个在当前函数退出之前运行的函数，也就是说，在执行`return`语句和将控制权返回给当前函数的调用者之间。`defer`的另一个重要特性是参数会立即求值。这两个特性的结合允许我们在`defer`求值时复制原始的`sql.DB`，而不用担心当前函数何时或如何退出，从而避免了潜在的大量*清理*代码的复制和粘贴。这段代码如下所示：

```go
defer func(original sql.DB) {
   // restore original DB (after test)
   db = &original
}(*db)

// replace db for this test
db = testDb

```

完成后，测试如下所示：

```go
func TestSave_happyPath(t *testing.T) {
   // define a mock db
   testDb, dbMock, err := sqlmock.New()
   defer testDb.Close()
   require.NoError(t, err)

   // configure the mock db
   queryRegex := convertSQLToRegex(sqlInsert)
   dbMock.ExpectExec(queryRegex).WillReturnResult(sqlmock.NewResult(2, 1))

   // monkey patching starts here
   defer func(original sql.DB) {
      // restore original DB (after test)
      db = &original
   }(*db)

   // replace db for this test
   db = testDb
   // end of monkey patch

   // inputs
   in := &Person{
      FullName: "Jake Blues",
      Phone:    "01234567890",
      Currency: "AUD",
      Price:    123.45,
   }

   // call function
   resultID, err := Save(in)

   // validate result
   require.NoError(t, err)
   assert.Equal(t, 2, resultID)
   assert.NoError(t, dbMock.ExpectationsWereMet())
}
```

太棒了，我们已经完成了快乐路径测试。不幸的是，我们只测试了函数中的 13 行中的 7 行；也许更重要的是，我们不知道我们的错误处理代码是否正确工作。

# 测试错误处理

有三种可能的错误需要处理：

+   SQL 插入可能会失败

+   未能获取数据库

+   我们可能无法检索到插入记录的 ID

那么，我们如何测试 SQL 插入失败呢？使用 SQLMock 很容易：我们复制上一个测试，而不是返回`sql.Result`，我们返回一个错误，如下面的代码所示：

```go
// configure the mock db
queryRegex := convertSQLToRegex(sqlInsert)
dbMock.ExpectExec(queryRegex).WillReturnError(errors.New("failed to insert"))
```

然后我们可以将我们的期望从结果更改为错误，如下面的代码所示：

```go
require.Error(t, err)
assert.Equal(t, defaultPersonID, resultID)
assert.NoError(t, dbMock.ExpectationsWereMet())
```

接下来是测试*无法获取数据库*，这时 SQLMock 无法帮助我们，但是可以使用 monkey patching。目前，我们的`getDB()`函数如下所示：

```go
func getDB() (*sql.DB, error) {
   if db == nil {
      if config.App == nil {
         return nil, errors.New("config is not initialized")
      }

      var err error
      db, err = sql.Open("mysql", config.App.DSN)
      if err != nil {
         // if the DB cannot be accessed we are dead
         panic(err.Error())
      }
   }

   return db, nil
}
```

让我们将函数更改为变量，如下面的代码所示：

```go
var getDB = func() (*sql.DB, error) {
    // code removed for brevity
}
```

我们并没有改变函数的实现。现在我们可以对该变量进行 monkey patch，得到如下的测试结果：

```go
func TestSave_getDBError(t *testing.T) {
   // monkey patching starts here
   defer func(original func() (*sql.DB, error)) {
      // restore original DB (after test)
      getDB = original
   }(getDB)

   // replace getDB() function for this test
   getDB = func() (*sql.DB, error) {
      return nil, errors.New("getDB() failed")
   }
   // end of monkey patch

   // inputs
   in := &Person{
      FullName: "Jake Blues",
      Phone:    "01234567890",
      Currency: "AUD",
      Price:    123.45,
   }

   // call function
   resultID, err := Save(in)
   require.Error(t, err)
   assert.Equal(t, defaultPersonID, resultID)
}
```

您可能已经注意到正常路径和错误路径测试之间存在大量重复。这在 Go 语言测试中有些常见，可能是因为我们有意地重复调用一个函数，使用不同的输入或环境，从根本上来说是在为我们测试的对象记录和强制执行行为契约。

鉴于这些基本职责，我们应该努力确保我们的测试既易于阅读又易于维护。为了实现这些目标，我们可以应用 Go 语言中我最喜欢的一个特性，即表驱动测试（[`github.com/golang/go/wiki/TableDrivenTests`](https://github.com/golang/go/wiki/TableDrivenTests)）。

# 使用表驱动测试减少测试膨胀

使用表驱动测试，我们在测试开始时定义一系列场景（通常是函数输入、模拟配置和我们的期望），然后是一个场景运行器，通常是测试的一部分，否则会重复。让我们看一个例子。`Load()`函数的正常路径测试如下所示：

```go
func TestLoad_happyPath(t *testing.T) {
   expectedResult := &Person{
      ID:       2,
      FullName: "Paul",
      Phone:    "0123456789",
      Currency: "CAD",
      Price:    23.45,
   }

   // define a mock db
   testDb, dbMock, err := sqlmock.New()
   require.NoError(t, err)

   // configure the mock db
   queryRegex := convertSQLToRegex(sqlLoadByID)
   dbMock.ExpectQuery(queryRegex).WillReturnRows(
      sqlmock.NewRows(strings.Split(sqlAllColumns, ", ")).
         AddRow(2, "Paul", "0123456789", "CAD", 23.45))

   // monkey patching the database
   defer func(original sql.DB) {
      // restore original DB (after test)
      db = &original
   }(*db)

   db = testDb
   // end of monkey patch

   // call function
   result, err := Load(2)

   // validate results
   assert.Equal(t, expectedResult, result)
   assert.NoError(t, err)
   assert.NoError(t, dbMock.ExpectationsWereMet())
}
```

这个函数大约有 11 行功能代码（去除格式化后），其中大约有 9 行在我们对 SQL 加载失败的测试中几乎是相同的。将其转换为表驱动测试得到如下结果：

```go
func TestLoad_tableDrivenTest(t *testing.T) {
   scenarios := []struct {
      desc            string
      configureMockDB func(sqlmock.Sqlmock)
      expectedResult  *Person
      expectError     bool
   }{
      {
         desc: "happy path",
         configureMockDB: func(dbMock sqlmock.Sqlmock) {
            queryRegex := convertSQLToRegex(sqlLoadAll)
            dbMock.ExpectQuery(queryRegex).WillReturnRows(
               sqlmock.NewRows(strings.Split(sqlAllColumns, ", ")).
                  AddRow(2, "Paul", "0123456789", "CAD", 23.45))
         },
         expectedResult: &Person{
            ID:       2,
            FullName: "Paul",
            Phone:    "0123456789",
            Currency: "CAD",
            Price:    23.45,
         },
         expectError: false,
      },
      {
         desc: "load error",
         configureMockDB: func(dbMock sqlmock.Sqlmock) {
            queryRegex := convertSQLToRegex(sqlLoadAll)
            dbMock.ExpectQuery(queryRegex).WillReturnError(
                errors.New("something failed"))
         },
         expectedResult: nil,
         expectError:    true,
      },
   }

   for _, scenario := range scenarios {
      // define a mock db
      testDb, dbMock, err := sqlmock.New()
      require.NoError(t, err)

      // configure the mock db
      scenario.configureMockDB(dbMock)

      // monkey db for this test
      original := *db
      db = testDb

      // call function
      result, err := Load(2)

      // validate results
      assert.Equal(t, scenario.expectedResult, result, scenario.desc)
      assert.Equal(t, scenario.expectError, err != nil, scenario.desc)
      assert.NoError(t, dbMock.ExpectationsWereMet())

      // restore original DB (after test)
      db = &original
      testDb.Close()
   }
}
```

抱歉，这里有很多内容，让我们把它分成几个部分：

```go
scenarios := []struct {
   desc            string
   configureMockDB func(sqlmock.Sqlmock)
   expectedResult  *Person
   expectError     bool
}{
```

这些行定义了一个切片和一个匿名结构，它将是我们的场景列表。在这种情况下，我们的场景包含以下内容：

+   **描述**：这对于添加到测试错误消息中很有用。

+   **模拟配置**：由于我们正在测试代码如何对来自数据库的不同响应做出反应，这就是大部分魔法发生的地方。

+   **预期结果**：相当标准，考虑到输入和环境（即模拟配置）。这是我们想要得到的。

+   **一个布尔值，表示我们是否期望出现错误**：我们可以在这里使用错误值；这样会更精确。但是，我更喜欢使用自定义错误，这意味着输出不是常量。我还发现错误消息可能随时间而改变，因此检查的狭窄性使测试变得脆弱。基本上，我在测试的特定性和耐久性之间进行了权衡。

然后我们有我们的场景，每个测试用例一个：

```go
{
   desc: "happy path",
   configureMockDB: func(dbMock sqlmock.Sqlmock) {
      queryRegex := convertSQLToRegex(sqlLoadAll)
      dbMock.ExpectQuery(queryRegex).WillReturnRows(
         sqlmock.NewRows(strings.Split(sqlAllColumns, ", ")).
            AddRow(2, "Paul", "0123456789", "CAD", 23.45))
   },
   expectedResult: &Person{
      ID:       2,
      FullName: "Paul",
      Phone:    "0123456789",
      Currency: "CAD",
      Price:    23.45,
   },
   expectError: false,
},
{
  desc: "load error",
  configureMockDB: func(dbMock sqlmock.Sqlmock) {
    queryRegex := convertSQLToRegex(sqlLoadAll)
    dbMock.ExpectQuery(queryRegex).WillReturnError(
        errors.New("something failed"))
  },
  expectedResult: nil,
  expectError: true,
},

```

现在有测试运行器，基本上是对所有场景的循环：

```go
for _, scenario := range scenarios {
   // define a mock db
   testDb, dbMock, err := sqlmock.New()
   require.NoError(t, err)

   // configure the mock db
   scenario.configureMockDB(dbMock)

   // monkey db for this test
   original := *db
   db = testDb

   // call function
   result, err := Load(2)

   // validate results
   assert.Equal(t, scenario.expectedResult, result, scenario.desc)
   assert.Equal(t, scenario.expectError, err != nil, scenario.desc)
   assert.NoError(t, dbMock.ExpectationsWereMet())

   // restore original DB (after test)
   db = &original
   testDb.Close()
}
```

这个循环的内容与我们原始测试的内容非常相似。通常先编写正常路径测试，然后通过添加其他场景将其转换为表驱动测试更容易。

也许我们的测试运行器和原始函数之间唯一的区别是我们在进行 monkey patch。我们不能在`for`循环中使用`defer`，因为`defer`只有在函数退出时才会运行；因此，我们必须在循环结束时恢复数据库。

在这里使用表驱动测试不仅减少了测试代码中的重复，而且还有其他两个重要的优点。首先，它将测试简化为输入等于输出，使它们非常容易理解，也很容易添加更多的场景。

其次，可能会发生变化的代码，即函数调用本身，只存在一个地方。如果该函数被修改以接受其他输入或返回其他值，我们只需要在一个地方进行修复，而不是每个测试场景一次。

# 包之间的猴子补丁

到目前为止，我们已经看到了在我们的`data`包内部进行测试的目的而进行猴子补丁私有全局变量或函数。但是如果我们想测试其他包会发生什么呢？将业务逻辑层与数据库解耦也许是个好主意？这样可以确保我们的业务逻辑层测试不会因为无关的事件（例如优化我们的 SQL 查询）而出错。

再次，我们面临一个困境；我们可以开始大规模的重构，但正如我们之前提到的，这是一项艰巨的工作，而且风险很大，特别是没有测试来避免麻烦。让我们看看我们拥有的最简单的业务逻辑包，即`get`包：

```go
// Getter will attempt to load a person.
// It can return an error caused by the data layer or 
// when the requested person is not found
type Getter struct {
}

// Do will perform the get
func (g *Getter) Do(ID int) (*data.Person, error) {
   // load person from the data layer
   person, err := data.Load(ID)
   if err != nil {
      if err == data.ErrNotFound {
         // By converting the error we are encapsulating the 
         // implementation details from our users.
         return nil, errPersonNotFound
      }
      return nil, err
   }

   return person, err
}
```

如你所见，这个函数除了从数据库加载人员之外几乎没有做什么。因此，你可以认为它不需要存在；别担心，我们稍后会赋予它更多的责任。

那么，我们如何在没有数据库的情况下进行测试呢？首先想到的可能是像之前一样对数据库池或`getDatabase()`函数进行猴子补丁。

这样做是可行的，但会很粗糙，并且会污染`data`包的公共 API，这是测试引起的破坏的明显例子。这也不会使该包与`data`包的内部实现解耦。事实上，这会使情况变得更糟。`data`包的实现的任何更改都可能破坏我们对该包的测试。

另一个需要考虑的方面是，我们可以进行任何想要的修改，因为这项服务很小，而且我们拥有所有的代码。这通常并非如此；该包可能由另一个团队拥有，它可能是外部依赖的一部分，甚至是标准库的一部分。因此，最好养成的习惯是保持我们的更改局限于我们正在处理的包。

考虑到这一点，我们可以采用我们在上一节中简要介绍的一个技巧，即*猴子补丁的优势*。让我们拦截`get`包对`data`包的调用，如下面的代码所示：

```go
// Getter will attempt to load a person.
// It can return an error caused by the data layer or 
// when the requested person is not found
type Getter struct {
}

// Do will perform the get
func (g *Getter) Do(ID int) (*data.Person, error) {
   // load person from the data layer
   person, err := loader(ID)
   if err != nil {
      if err == data.ErrNotFound {
         // By converting the error we are hiding the 
         // implementation details from our users.
         return nil, errPersonNotFound
      }
      return nil, err
   }

   return person, err
}

// this function as a variable allows us to Monkey Patch during testing
var loader = data.Load

```

现在，我们可以通过猴子补丁拦截调用，如下面的代码所示：

```go
func TestGetter_Do_happyPath(t *testing.T) {
   // inputs
   ID := 1234

   // monkey patch calls to the data package
   defer func(original func(ID int) (*data.Person, error)) {
      // restore original
      loader = original
   }(loader)

   // replace method
   loader = func(ID int) (*data.Person, error) {
      result := &data.Person{
         ID:       1234,
         FullName: "Doug",
      }
      var resultErr error

      return result, resultErr
   }
   // end of monkey patch

   // call method
   getter := &Getter{}
   person, err := getter.Do(ID)

   // validate expectations
   require.NoError(t, err)
   assert.Equal(t, ID, person.ID)
   assert.Equal(t, "Doug", person.FullName)
}
```

现在，我们的测试不依赖于数据库或`data`包的任何内部实现细节。虽然我们并没有完全解耦这些包，但我们已经大大减少了`get`包中的测试必须正确执行的事项。这可以说是通过猴子补丁实现 DI 的一个要点，通过减少对外部因素的依赖并增加测试的焦点，减少测试可能出错的方式。

# 当魔法消失时

在本书的早些时候，我挑战你以批判的眼光审视本书中提出的每种 DI 方法。考虑到这一点，我们应该考虑猴子补丁的潜在成本。

**数据竞争**——我们在示例中看到，猴子补丁是用执行特定测试所需的方式替换全局变量的过程。这也许是最大的问题。用特定的东西替换全局的，因此是共享的，会在该变量上引发数据竞争。

为了更好地理解这种数据竞争，我们需要了解 Go 如何运行测试。默认情况下，包内的测试是按顺序执行的。我们可以通过在测试中标记`t.Parallel()`来减少测试执行时间。对于我们当前的`data`包测试，将测试标记为并行会导致数据竞争出现，从而导致测试结果不可预测。

Go 测试的另一个重要特性是，Go 可以并行执行多个包。像`t.Parallel()`一样，这对我们的测试执行时间来说可能是很棒的。通过我们当前的代码，我们可以确保安全，因为我们只在与测试相同的包内进行了猴子补丁。如果我们在包边界之间进行了猴子补丁，那么数据竞争就会出现。

如果您的测试不稳定，并且怀疑存在数据竞争，您可以尝试使用 Go 的内置竞争检测器（[`golang.org/doc/articles/race_detector.html`](https://golang.org/doc/articles/race_detector.html)）：

```go
$ go test -race ./...
```

如果这样找不到问题，您可以尝试按顺序运行所有测试：

```go
$ go test -p 1 ./...
```

如果测试开始一致通过，那么您将需要开始查找数据竞争。

**详细测试**——正如您在我们的测试中所看到的，猴子补丁和恢复的代码可能会变得相当冗长。通过一点重构，可以减少样板代码。例如，看看这个：

```go
func TestSaveConfig(t *testing.T) {
   // inputs
   filename := "my-config.json"
   cfg := &Config{
      Host: "localhost",
      Port: 1234,
   }

   // monkey patch the file writer
   defer func(original func(filename string, data []byte, perm os.FileMode) error) {
      // restore the original
      writeFile = original
   }(writeFile)

   writeFile = func(filename string, data []byte, perm os.FileMode) error {
      // output error
      return nil
   }

   // call the function
   err := SaveConfig(filename, cfg)

   // validate the result
   assert.NoError(t, err)
}
```

我们可以将其更改为：

```go
func TestSaveConfig_refactored(t *testing.T) {
   // inputs
   filename := "my-config.json"
   cfg := &Config{
      Host: "localhost",
      Port: 1234,
   }

   // monkey patch the file writer
   defer restoreWriteFile(writeFile)

   writeFile = mockWriteFile(nil)

   // call the function
   err := SaveConfig(filename, cfg)

   // validate the result
   assert.NoError(t, err)
}

func mockWriteFile(result error) func(filename string, data []byte, perm os.FileMode) error {
   return func(filename string, data []byte, perm os.FileMode) error {
      return result
   }
}

// remove the restore function to reduce from 3 lines to 1
func restoreWriteFile(original func(filename string, data []byte, perm os.FileMode) error) {
   // restore the original
   writeFile = original
}
```

在这次重构之后，我们的测试中重复的部分大大减少，从而减少了维护的工作量，但更重要的是，测试不再被所有与猴子补丁相关的代码所掩盖。

**混淆的依赖关系**——这不是猴子补丁本身的问题，而是一般依赖管理风格的问题。在传统的 DI 中，依赖关系作为参数传递，使关系显式可见。

从用户的角度来看，这种缺乏参数可以被认为是代码 UX 的改进；毕竟，更少的输入通常会使函数更容易使用。但是，当涉及测试时，事情很快变得混乱。

在我们之前的示例中，“SaveConfig（）”函数依赖于“ioutil.WriteFile（）”，因此对该依赖进行模拟以测试“SaveConfig（）”似乎是合理的。但是，当我们需要测试调用“SaveConfig（）”的函数时会发生什么？

`SaveConfig（）`的用户如何知道他们需要模拟`ioutil.WriteFile（）`？

由于关系混乱，所需的知识增加了，测试长度也相应增加；不久之后，我们在每个测试的开头就会有半屏幕的函数猴子补丁。

# 总结

在本章中，我们学习了如何利用猴子补丁来在测试中*替换*依赖关系。通过猴子补丁，我们已经测试了全局变量，解耦了包，并且消除了对数据库和文件系统等外部资源的依赖。我们通过一些实际示例来改进了我们示例服务的代码，并坦率地讨论了使用猴子补丁的优缺点。

在下一章中，我们将研究第二种，也许是最传统的 DI 技术，即构造函数注入的依赖注入。通过它，我们将进一步改进我们服务的代码。

# 问题

1.  猴子补丁是如何工作的？

1.  猴子补丁的理想用例是什么？

1.  如何使用猴子补丁来解耦两个包而不更改依赖包？

# 进一步阅读

Packt 还有许多其他关于猴子补丁的学习资源：

+   **掌握 JQuery**：[`www.packtpub.com/mapt/book/web_development/9781785882166/12/ch12lvl1sec100/monkey-patching`](https://www.packtpub.com/mapt/book/web_development/9781785882166/12/ch12lvl1sec100/monkey-patching)

+   **学习使用 Ruby 编码**：[`www.packtpub.com/mapt/video/application_development/9781788834063/40761/41000/monkey-patching-ii`](https://www.packtpub.com/mapt/video/application_development/9781788834063/40761/41000/monkey-patching-ii)


# 第六章：构造函数注入的依赖注入

在本章中，我们将研究**依赖注入**（**DI**）最独特的形式之一，即猴子补丁，然后将其推向另一个极端，看看可能是最*正常*或传统的构造函数注入。

虽然构造函数注入是如此普遍，以至于您甚至可能在不知不觉中使用它，但它有许多微妙之处，特别是关于优缺点的考虑。

与上一章类似，我们将把这种技术应用到我们的示例服务中，从而获得显著的改进。

本章将涵盖以下主题：

+   构造函数注入

+   构造函数注入的优点

+   应用构造函数注入

+   构造函数注入的缺点

# 技术要求

熟悉我们在第四章中介绍的服务代码将是有益的，*ACME 注册服务简介*。

您可能还会发现阅读和运行本章的完整代码版本很有用，这些代码可以在[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch06`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch06)上找到。

获取代码并配置示例服务的说明可在此处的 README 中找到[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/)。

您可以在`ch06/acme`中找到我们的服务代码，并已应用了本章的更改。

# 构造函数注入

当对象需要一个依赖项来工作时，确保该依赖项始终可用的最简单方法是要求所有用户将其作为对象构造函数的参数提供。这被称为**构造函数注入**。

让我们通过一个示例来解释，我们将提取一个依赖项，将其概括，并实现构造函数注入。假设我们正在为一个在线社区构建网站。对于这个网站，我们希望在用户注册时向新用户发送电子邮件。这段代码可能是这样的：

```go
// WelcomeSender sends a Welcome email to new users
type WelcomeSender struct {
   mailer *Mailer
}

func (w *WelcomeSender) Send(to string) error {
   body := w.buildMessage()

   return w.mailer.Send(to, body)
}
```

我们将`*Mailer`设为私有，以确保类的内部封装。我们可以通过将其定义为构造函数的参数来注入`*Mailer`依赖项，如下面的代码所示：

```go
func NewWelcomeSender(in *Mailer) (*WelcomeSender, error) {
   // guard clause
   if in == nil {
      return nil, errors.New("programmer error: mailer must not provided")
   }

   return &WelcomeSender{
      mailer: in,
   }, nil
}
```

在前面的示例中，我们包含了一个守卫子句。其目的是确保提供的依赖项不是`nil`。这并非必需，是否包含取决于个人风格；这样做是完全可以接受的：

```go
func NewWelcomeSenderNoGuard(in *Mailer) *WelcomeSender {
   return &WelcomeSender{
      mailer: in,
   }
}
```

您可能会认为我们已经完成了。毕竟，我们正在将依赖项`Mailer`注入`WelcomeSender`。

遗憾的是，我们还没有完全达到目标。事实上，我们错过了 DI 的真正目的。不，这不是测试，尽管我们会做到这一点。DI 的真正目的是解耦。

在这一点上，我们的`WelcomeSender`没有`Mailer`实例就无法工作。它们之间耦合度很高。因此，让我们通过应用第二章中的*依赖反转原则*部分来解耦它们，*Go 的 SOLID 设计原则*。

首先，让我们看一下`Mailer`结构：

```go
// Mailer sends and receives emails
type Mailer struct{
   Host string
   Port string
   Username string
   Password string
}

func (m *Mailer) Send(to string, body string) error {
   // send email
   return nil
}

func (m *Mailer) Receive(address string) (string, error) {
   // receive email
   return "", nil
}
```

我们可以通过基于方法签名的接口将其转换为抽象：

```go
// Mailer sends and receives emails
type MailerInterface interface {
   Send(to string, body string) error
   Receive(address string) (string, error)
}
```

等一下，我们只需要发送电子邮件。让我们应用*接口隔离原则*，将接口减少到我们使用的方法，并更新我们的构造函数。现在，我们有这样的代码：

```go
type Sender interface {
   Send(to string, body string) error
}

func NewWelcomeSenderV2(in Sender) *WelcomeSenderV2 {
   return &WelcomeSenderV2{
      sender: in,
   }
}
```

通过这一个小改变，发生了一些方便的事情。首先，我们的代码现在完全自包含。这意味着任何错误、扩展、测试或其他更改只涉及这个包。其次，我们可以使用模拟或存根来测试我们的代码，阻止我们用电子邮件轰炸自己，并要求一个工作的电子邮件服务器来通过我们的测试。最后，我们不再受限于`Mailer`类。如果我们想要从欢迎电子邮件更改为短信或推特，我们可以将我们的输入参数更改为不同的`Sender`并完成。

通过将我们的依赖项定义为一个抽象（作为一个本地接口）并将该依赖项传递到我们的构造函数中，我们已经明确地定义了我们的要求，并在测试和扩展中给了我们更大的自由度。

# 解决房间里的鸭子

在我们深入研究构造函数注入之前，我们应该花一点时间来谈谈鸭子类型。

我们之前提到过 Go 对隐式接口的支持，以及我们如何利用它来执行依赖反转和解耦对象。对于熟悉 Python 或 Ruby 的人来说，这可能感觉像鸭子类型。对于其他人来说，什么是鸭子类型？它被描述如下：

**如果它看起来像一只鸭子，它叫起来像一只鸭子，那么它就是一只鸭子**

或者，更加技术性地说：

**在运行时，仅根据访问的对象部分动态确定对象的适用性**

让我们看一个 Go 的例子，看看它是否支持鸭子类型：

```go
type Talker interface {
   Speak() string
   Shout() string
}

type Dog struct{}

func (d Dog) Speak() string {
   return "Woof!"
}

func (d Dog) Shout() string {
   return "WOOF!"
}

func SpeakExample() {
   var talker Talker
   talker = Dog{}

   fmt.Print(talker.Speak())
}
```

正如你所看到的，我们的`Dog`类型并没有声明它实现了`Talker`接口，正如我们可能从 Java 或 C#中期望的那样，但我们仍然能够将它用作`Talker`。

从我们的例子来看，Go 可能支持鸭子类型，但存在一些问题：

+   在鸭子类型中，兼容性是在运行时确定的；Go 将在编译时检查我们的`Dog`类型是否实现了`Talker`。

+   在鸭子类型中，适用性仅基于访问的对象部分。在前面的例子中，只有`Speak()`方法被实际使用。然而，如果我们的`Dog`类型没有实现`Shout()`方法，那么它将无法编译通过。

那么如果它不是鸭子类型，那它是什么？有点类似的东西叫做**结构类型**。结构类型是一种静态类型系统，它根据类型的结构在编译时确定适用性。不要让这个不太花哨的名字愚弄你；结构类型是非常强大和极其有用的。Go 提供了编译时检查的安全性，而不需要明确声明实现的接口的强制形式。

# 构造函数注入的优势

对于许多程序员和编程语言，构造函数注入是它们的默认 DI 方法。因此，它具有许多优势也许并不奇怪。

**与依赖项生命周期的分离**-构造函数注入，像大多数 DI 方法一样，将依赖项的生命周期管理与被注入的对象分开。通过这样做，对象变得更加简单和易于理解。

**易于实现**-正如我们在之前的例子中看到的，将这个变得很容易：

```go
// WelcomeSender sends a Welcome email to new users
type WelcomeSender struct {
   Mailer *Mailer
}

func (w *WelcomeSender) Send(to string) error {
   body := w.buildMessage()

   return w.Mailer.Send(to, body)
}
```

并将其更改为：

```go
func NewWelcomeSender(mailer *Mailer) *WelcomeSender {
   return &WelcomeSender{
      mailer: mailer,
   }
}

// WelcomeSender sends a Welcome email to new users
type WelcomeSender struct {
   mailer *Mailer
}

func (w *WelcomeSender) Send(to string) error {
   body := w.buildMessage()

   return w.mailer.Send(to, body)
}
```

**可预测且简洁**-通过将依赖项的赋值移动到构造函数，我们不仅明确了我们的要求，而且还确保依赖项被设置并可用于我们的方法。如果在构造函数中包含了一个守卫子句，这一点尤其正确。没有构造函数，每个方法可能都必须包含一个守卫子句（如下例所示），否则可能会出现 nil 指针异常：

```go
type Car struct {
   Engine Engine
}

func (c *Car) Drive() error {
   if c.Engine == nil {
      return errors.New("engine ie missing")
   }

   // use the engine
   c.Engine.Start()
   c.Engine.IncreasePower()

   return nil
}

func (c *Car) Stop() error {
   if c.Engine == nil {

      return errors.New("engine ie missing")
   }

   // use the engine
   c.Engine.DecreasePower()
   c.Engine.Stop()

   return nil
}
```

而不是更简洁的以下内容：

```go
func NewCar(engine Engine) (*Car, error) {
  if engine == nil {
    return nil, errors.New("invalid engine supplied")
  }

  return &Car{
    engine: engine,
  }, nil
}

type Car struct {
   engine Engine
}

func (c *Car) Drive() error {
   // use the engine
   c.engine.Start()
   c.engine.IncreasePower()

   return nil
}

func (c *Car) Stop() error {
   // use the engine
   c.engine.DecreasePower()
   c.engine.Stop()

   return nil
}
```

通过扩展，方法还可以假定我们的依赖在访问依赖时处于良好的准备状态，因此无需在构造函数之外的任何地方处理初始化延迟或配置问题。此外，访问依赖时没有与数据竞争相关的问题。它在构造过程中设置，永远不会改变。

**封装** - 构造函数注入提供了关于对象如何使用依赖的高度封装。考虑一下，如果我们通过添加`FillPetrolTank()`方法来扩展我们之前的`Car`示例，如下面的代码所示：

```go
func (c *Car) FillPetrolTank() error {
   // use the engine
   if c.engine.IsRunning() {
      return errors.New("cannot fill the tank while the engine is running")
   }

   // fill the tank!
   return c.fill()
}
```

如果我们假设*加油*与`Engine`无关，并且在调用此方法之前没有填充`Engine`，那么原来的代码会发生什么？

如果没有构造函数注入来确保我们提供了`Engine`，这个方法将会崩溃并引发空指针异常。或者，这个方法也可以不使用构造函数注入来编写，如下面的代码所示：

```go
func (c *Car) FillPetrolTank(engine Engine) error {
   // use the engine
   if engine.IsRunning() {
      return errors.New("cannot fill the tank while the engine is running")
   }

   // fill the tank!
   return c.fill()
}
```

然而，这个版本现在泄漏了方法需要`Engine`来工作的实现细节。

**帮助发现代码异味** - 向现有结构或接口添加*只是一个*功能是一个容易陷阱。正如我们在*单一职责原则*的早期讨论中所看到的，我们应该抵制这种冲动，尽可能保持我们的对象和接口尽可能小。发现对象承担太多责任的一个简单方法是计算其依赖关系。通常，对象承担的责任越多，它积累的依赖关系就越多。因此，通过将所有依赖关系清楚地列在一个地方，即构造函数中，很容易就能察觉到可能有些不对劲。

# 改进测试场景覆盖率

我们要做的第一件事是在测试中消除对上游货币服务的依赖。然后，我们将继续添加测试来覆盖以前无法覆盖的其他场景。我们当前的测试看起来是这样的：

```go
func TestRegisterHandler_ServeHTTP(t *testing.T) {
   // ensure the test always fails by giving it a timeout
   ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
   defer cancel()

   // Create and start a server
   // With out current implementation, we cannot test this handler without
   // a full server as we need the mux.
   address, err := startServer(ctx)
   require.NoError(t, err)

   // build inputs
   validRequest := buildValidRequest()
   response, err := http.Post("http://"+address+"/person/register", "application/json", validRequest)

   // validate outputs
   require.NoError(t, err)
   require.Equal(t, http.StatusCreated, response.StatusCode)
   defer response.Body.Close()

   // call should output the location to the new person
   headerLocation := response.Header.Get("Location")
   assert.Contains(t, headerLocation, "/person/")
}
```

我们目前正在启动整个 HTTP 服务器；这似乎有些过分，所以让我们将测试范围缩小到只有`RegisterHandler`。

这种测试范围的缩减还将通过消除其他外围问题来改进测试，比如 HTTP 路由。

由于我们知道我们将有多个类似的场景需要测试，让我们从添加表驱动测试的框架开始：

```go
func TestRegisterHandler_ServeHTTP(t *testing.T) {
   scenarios := []struct {
      desc           string
      inRequest      func() *http.Request
      inModelMock    func() *MockRegisterModel
      expectedStatus int
      expectedHeader string
   }{
      // scenarios go here
   }

   for _, s := range scenarios {
      scenario := s
      t.Run(scenario.desc, func(t *testing.T) {
         // test goes here
      })
   }
}
```

从原始测试中，我们可以看到我们的输入是`*http.Request`和`*MockRegisterModel`。两者都有点复杂，需要创建和配置，所以我们选择用一个函数来构建它们。同样，从原始测试中，我们可以看到测试的输出是 HTTP 响应代码和`Location`头部。

这四个对象，`*http.Request`，`*MockRegistrationModel`，HTTP 状态码和`Location`头部，将构成我们测试场景的配置，如前面的代码所示。

为了完成我们的表驱动测试，我们将原始测试的内容复制到测试循环中，并替换输入和输出，如下面的代码所示：

```go
for _, s := range scenarios {
   scenario := s
   t.Run(scenario.desc, func(t *testing.T) {
      // define model layer mock
      mockRegisterModel := scenario.inModelMock()

      // build handler
      handler := &RegisterHandler{
         registerer: mockRegisterModel,
      }

      // perform request
      response := httptest.NewRecorder()
      handler.ServeHTTP(response, scenario.inRequest())

      // validate outputs
      require.Equal(t, scenario.expectedStatus, response.Code)

      // call should output the location to the new person
      resultHeader := response.Header().Get("Location")
      assert.Equal(t, scenario.expectedHeader, resultHeader)

      // validate the mock was used as we expected
      assert.True(t, mockRegisterModel.AssertExpectations(t))
   })
}
```

现在我们已经把所有的部分都准备好了，我们开始编写我们的测试场景，从正常情况开始：

```go
{
   desc: "Happy Path",
   inRequest: func() *http.Request {
      validRequest := buildValidRegisterRequest()
      request, err := http.NewRequest("POST", "/person/register", validRequest)
      require.NoError(t, err)

      return request
   },
   inModelMock: func() *MockRegisterModel {
      // valid downstream configuration
      resultID := 1234
      var resultErr error

      mockRegisterModel := &MockRegisterModel{}
      mockRegisterModel.On("Do", mock.Anything).Return(resultID, resultErr).Once()

      return mockRegisterModel
   },
   expectedStatus: http.StatusCreated,
   expectedHeader: "/person/1234/",
},
```

接下来，我们需要测试我们的代码是否能很好地处理错误。那么我们可以期望出现什么样的错误？我们可以检查代码，寻找类似`if err != nil`的代码。

这可能感觉像一个有用的快捷方式，但请考虑一下。如果我们的测试反映了当前的实现，当实现发生变化时会发生什么？

一个更好的角度是考虑的不是实现，而是功能本身以及其情况或使用。几乎总是有两个答案适用。*用户错误*，如不正确的输入，以及*从依赖项返回的错误*。

我们的*用户错误*场景如下所示：

```go
{
   desc: "Bad Input / User Error",
   inRequest: func() *http.Request {
      invalidRequest := bytes.NewBufferString(`this is not valid JSON`)
      request, err := http.NewRequest("POST", "/person/register", invalidRequest)
      require.NoError(t, err)

      return request
   },
   inModelMock: func() *MockRegisterModel {
      // Dependency should not be called
      mockRegisterModel := &MockRegisterModel{}
      return mockRegisterModel
   },
   expectedStatus: http.StatusBadRequest,
   expectedHeader: "",
},

```

我们从依赖项返回的*错误*如下所示：

```go
{
   desc: "Dependency Failure",
   inRequest: func() *http.Request {
      validRequest := buildValidRegisterRequest()
      request, err := http.NewRequest("POST", "/person/register", validRequest)
      require.NoError(t, err)

      return request
   },
   inModelMock: func() *MockRegisterModel {
      // call to the dependency failed
      resultErr := errors.New("something failed")

      mockRegisterModel := &MockRegisterModel{}
      mockRegisterModel.On("Do", mock.Anything).Return(0, resultErr).Once()

      return mockRegisterModel
   },
   expectedStatus: http.StatusInternalServerError,
   expectedHeader: "",
},

```

有了这三个测试，我们有了合理的测试场景覆盖，但我们遇到了一个问题。我们的*从依赖项返回的错误*场景导致 HTTP 状态码为`400`（错误请求），而不是预期的 HTTP`500`（内部服务器错误）。在查看模型层的实现后，显然`400`错误是有意的，并且应该表明请求不完整，因此验证失败。

我们的第一反应很可能是希望将验证移到 HTTP 层。但请考虑：如果我们添加另一种服务器类型，例如 gRPC，会发生什么？这种验证仍然需要执行。那么我们如何将用户错误与系统错误分开呢？

另一个选择是从模型返回命名错误以进行验证错误，另一个选择是其他错误。很容易检测和分别处理响应。然而，这将导致我们的代码与`model`包保持紧密耦合。

另一个选择是将我们对模型包的调用分成两个调用，也许是`Validate()`和`Do()`，但这会减少我们的`model`包的用户体验。我将留给您决定这些或其他选项是否适合您。

在对`RegisterHandler`和此包中的其他处理程序进行这些更改后，我们可以使用 Go 的测试覆盖工具来查看是否错过了任何明显的场景。

对于 Unix/Linux 用户，我在本章的源代码中包含了一个用于生成 HTML 覆盖率的脚本，步骤应该类似于其他平台。该脚本可以在[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/blob/master/ch06/pcov-html`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/blob/master/ch06/pcov-html)找到。

请注意，这里的测试覆盖百分比并不重要。重要的是要查看哪些代码没有被任何测试执行，并决定是否表明可能发生错误，因此我们需要添加的场景。

现在我们的`RegisterHandler`的形式好多了，我们可以以同样的方式将构造函数注入到`REST`包中的其他处理程序中。

这些更改的结果可以在本章的源代码中看到[`github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch06/acme/internal/rest`](https://github.com/PacktPublishing/Hands-On-Dependency-Injection-in-Go/tree/master/ch06/acme/internal/rest)。

# 应用构造函数注入

让我们将构造函数注入到我们的 ACME 注册服务中。这次我们将重构 REST 包，从`Register`端点开始。您可能还记得`Register`是我们服务中的三个端点之一，其他端点是`Get`和`List`。

`Register`端点有三个责任：

+   验证注册是否完成并有效

+   调用货币转换服务将注册价格转换为注册时请求的货币

+   保存注册和转换后的注册价格到数据库中

我们`Register`端点的代码目前如下所示：

```go
// RegisterHandler is the HTTP handler for the "Register" endpoint
// In this simplified example we are assuming all possible errors 
// are user errors and returning "bad request" HTTP 400.
// There are some programmer errors possible but hopefully these 
// will be caught in testing.
type RegisterHandler struct {
}

// ServeHTTP implements http.Handler
func (h *RegisterHandler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
   // extract payload from request
   requestPayload, err := h.extractPayload(request)
   if err != nil {
      // output error
      response.WriteHeader(http.StatusBadRequest)
      return
   }

   // register person
   id, err := h.register(requestPayload)
   if err != nil {
      // not need to log here as we can expect other layers to do so
      response.WriteHeader(http.StatusBadRequest)
      return
   }

   // happy path
   response.Header().Add("Location", fmt.Sprintf("/person/%d/", id))
   response.WriteHeader(http.StatusCreated)
}

// extract payload from request
func (h *RegisterHandler) extractPayload(request *http.Request) (*registerRequest, error) {
   requestPayload := &registerRequest{}

   decoder := json.NewDecoder(request.Body)
   err := decoder.Decode(requestPayload)
   if err != nil {
      return nil, err
   }

   return requestPayload, nil
}

// call the logic layer
func (h *RegisterHandler) register(requestPayload *registerRequest) (int, error) {
   person := &data.Person{
      FullName: requestPayload.FullName,
      Phone:    requestPayload.Phone,
      Currency: requestPayload.Currency,
   }

   registerer := &register.Registerer{}
   return registerer.Do(person)
}
```

令人失望的是，我们目前只对此函数进行了一个测试，并且它很容易出错。它需要数据库和我们的下游汇率服务都可访问和配置。

虽然我们可以确保我们的本地数据库正在工作，并且对其进行的任何更改不会影响除我们之外的任何人，但下游汇率服务在互联网上并且受到速率限制。我们无法控制它或它何时工作。

这意味着即使我们只有一个测试，该测试也有很高的潜力会因为我们无法控制的原因而变得烦人并且难以维护。

幸运的是，我们不仅可以消除这些依赖，还可以使用模拟来创建我们无法实现的情况。例如，通过模拟，我们可以测试当汇率服务停机或配额用完时的错误处理代码。

# 与依赖的解耦

第一步是确定我们希望注入的依赖项。对于我们的处理程序来说，这不是数据库或汇率调用。我们希望注入下一个软件层，也就是模型层。

具体来说，我们想要从我们的`register`方法中注入这一行：

```go
registerer := &register.Registerer{}
```

按照我们使用更容易的相同过程，我们首先将对象提升为成员变量，如下面的代码所示：

```go
// RegisterHandler is the HTTP handler for the "Register" endpoint
type RegisterHandler struct {
   registerer *register.Registerer
}
```

由于这对我们的代码与依赖的解耦没有任何作用，我们随后将我们的要求定义为一个本地接口，并更新成员变量，如下面的代码所示：

```go
// RegisterModel will validate and save a registration
type RegisterModel interface {
   Do(in *data.Person) (int, error)
}

// RegisterHandler is the HTTP handler for the "Register" endpoint
type RegisterHandler struct {
   registerer RegisterModel
}
```

# 构建构造函数

现在`RegisterHandler`需要一个抽象依赖项，我们需要确保通过应用构造函数注入来设置依赖项，如下面的代码所示：

```go
// NewRegisterHandler is the constructor for RegisterHandler
func NewRegisterHandler(model RegisterModel) *RegisterHandler {
   return &RegisterHandler{
      registerer: model,
   }
}
```

应用构造函数注入后，我们的`RegisterHandler`与模型层和外部资源（数据库和上游服务）的耦合性较小。我们可以利用这种较松散的耦合来改进和扩展我们的`RegisterHandler`的测试。

# 使用依赖图验证我们的改进

在我们结束对`REST`包的工作之前，让我们回顾一下我们的起点和现在的位置。当我们开始时，我们的处理程序与它们匹配的`model`包紧密耦合，并且测试不足。这两个问题都已得到解决。

让我们看看我们的依赖图是否显示出任何改善的迹象：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/4f8296e8-5655-44e8-9d61-3feda4dd019f.png)

遗憾的是，它看起来仍然和以前一样。在深入代码后，我们找到了罪魁祸首：

```go
// New will create and initialize the server
func New(address string) *Server {
   return &Server{
      address:         address,
      handlerGet:      NewGetHandler(&get.Getter{}),
      handlerList:     NewListHandler(&list.Lister{}),
      handlerNotFound: notFoundHandler,
      handlerRegister: NewRegisterHandler(&register.Registerer{}),
   }
}
```

我们在`Server`（`REST`包的一部分）的构造函数中实例化了我们的模型层对象。修复很容易，也很明显。我们将依赖项上推一级，如下面的代码所示：

```go
// New will create and initialize the server
func New(address string,
   getModel GetModel,
   listModel ListModel,
   registerModel RegisterModel) *Server {

   return &Server{
      address:         address,
      handlerGet:      NewGetHandler(getModel),
      handlerList:     NewListHandler(listModel),
      handlerNotFound: notFoundHandler,
      handlerRegister: NewRegisterHandler(registerModel),
   }
}
```

再次检查我们的依赖图，现在终于显示了一些改进：

![](https://github.com/OpenDocCN/freelearn-golang-zh/raw/master/docs/hsn-dep-inj-go/img/ebcea76d-8a3c-4d4a-bd7b-c33d36ca6ff7.png)

正如你所看到的，它更加平坦；`REST`包不依赖于模块层（`list`、`get`和`register`包）。

对`data`和`config`包的依赖仍然太多，但我们将在后面的章节中处理这个问题。

# 构造函数注入的缺点

遗憾的是，对于 DI 来说，没有银弹。尽管构造函数注入的效用很大，但并非所有情况都适用。本节介绍了构造函数注入的缺点和限制。

**可能导致大量更改**-将构造函数注入应用于现有代码时，可能会导致大量更改。如果代码最初是以函数形式编写的，这一点尤其真实。

考虑以下代码：

```go
// Dealer will shuffle a deck of cards and deal them to the players
func DealCards() (player1 []Card, player2 []Card) {
   // create a new deck of cards
   cards := newDeck()

   // shuffle the cards
   shuffler := &myShuffler{}
   shuffler.Shuffle(cards)

   // deal
   player1 = append(player1, cards[0])
   player2 = append(player2, cards[1])

   player1 = append(player1, cards[2])
   player2 = append(player2, cards[3])
   return
}
```

正如我们在前一节中看到的，要将其转换为使用构造函数注入，我们需要执行以下操作：

+   从函数转换为结构体

+   通过定义接口将对`*myShuffler`的依赖转换为抽象的

+   创建一个构造函数

+   更新所有当前使用该函数的地方，使用构造函数注入依赖

在所有的变化中，最令人担忧的是最后一个。在同一包中发生的更改，也就是说，在同一个包中更容易进行，因此风险更小，但对外部包的更改，特别是属于另一个团队的代码，风险显著更大。

除了非常小心外，减轻风险的最佳方法是进行测试。如果重构之前的代码几乎没有测试或没有测试，那么在开始任何重构之前首先创建一些测试是有益的。

使用猴子补丁的 DI 可能是一个吸引人的选择，可以在这些测试中替换任何依赖关系。是的，这些测试在切换到构造函数注入后需要重构或删除，但这并没有什么不对。有了测试，可以确保在重构之前代码是有效的，并且这些测试在重构过程中仍然具有信息性。换句话说，测试将有助于使重构更加安全。

**可能引起初始化问题**——在讨论构造函数注入的优势时，我们提到了将对象与其依赖的生命周期分离。这段代码和复杂性仍然存在，只是被推到了调用图的更高层。虽然能够分别处理这些问题显然是一个优势，但它也带来了一个次要问题：对象初始化顺序。考虑我们的 ACME 注册服务。它有三层，呈现层、模型层和数据层。

在呈现层能够工作之前，我们需要有一个可用的模型层。

在模型层能够工作之前，我们需要有一个可用的数据层。

在数据层能够正常工作之前，我们必须创建一个数据库连接池。

对于一个简单的服务来说，这已经变得有些复杂了。这种复杂性导致了许多 DI 框架的产生，我们将在第十章《现成的注入》中调查其中一个框架，谷歌的 Wire。

这里可能存在的另一个问题是在应用程序启动时将创建大量对象。虽然这会导致应用程序启动稍微变慢，但一旦支付了这个初始的“成本”，应用程序就不再会因为依赖关系的创建而延迟。

在这里需要考虑的最后一个初始化问题是调试。当依赖关系的创建和使用在代码的同一部分时，更容易理解和调试它们的生命周期和关系。

**滥用的危险**——鉴于这种技术如此易于理解和使用，滥用也是非常容易的。滥用的最明显迹象是构造函数参数过多。过多的构造函数参数可能表明对象承担了太多的责任，但也可能是提取和抽象了太多的依赖的症状。

在提取依赖之前，考虑封装。这个对象的用户需要了解哪些信息？我们能够隐藏与实现相关的信息越多，我们就越有灵活性进行重构。

另一个需要考虑的方面是：依赖关系是否需要被提取，还是可以留给配置？考虑以下代码：

```go
// FetchRates rates from downstream service
type FetchRates struct{}

func (f *FetchRates) Fetch() ([]Rate, error) {
   // build the URL from which to fetch the rates
   url := downstreamServer + "/rates"

   // build request
   request, err := http.NewRequest("GET", url, nil)
   if err != nil {
      return nil, err
   }

   // fetch rates
   response, err := http.DefaultClient.Do(request)
   if err != nil {
      return nil, err
   }
   defer response.Body.Close()

   // read the content of the response
   data, err := ioutil.ReadAll(response.Body)
   if err != nil {
      return nil, err
   }

   // convert JSON bytes to Go structs
   out := &downstreamResponse{}
   err = json.Unmarshal(data, out)
   if err != nil {
      return nil, err
   }

   return out.Rates, nil
}
```

虽然可以对 `*http.Client` 进行抽象和注入，但这真的有必要吗？事实上，唯一需要改变的方面是基本 URI。我们将在第八章《配置注入》中进一步探讨这种方法。

**不明显的要求**——在 Go 中使用构造函数不是一个必需的模式。在一些团队中，甚至不是一个标准模式。因此，用户可能甚至没有意识到构造函数的存在以及他们必须使用它。鉴于没有注入依赖关系，代码很可能会崩溃，这不太可能导致生产问题，但可能会有些烦人。

一些团队尝试通过将对象设为私有，只导出构造函数和接口来解决这个问题，如下面的代码所示：

```go
// NewClient creates and initialises the client
func NewClient(service DepService) Client {
   return &clientImpl{
      service: service,
   }
}

// Client is the exported API
type Client interface {
   DoSomethingUseful() (bool, error)
}

// implement Client
type clientImpl struct {
   service DepService
}

func (c *clientImpl) DoSomethingUseful() (bool, error) {
   // this function does something useful
   return false, errors.New("not implemented")
}
```

这种方法确保了构造函数的使用，但也有一些成本。

首先，我们现在必须保持接口和结构同步。这并不难，但这是额外的工作，可能会变得烦人。

其次，一些用户倾向于使用接口而不是在本地定义自己的接口。这会导致用户和导出接口之间的紧密耦合。这种耦合会使得向导出 API 添加内容变得更加困难。

考虑在另一个包中使用前面的示例，如下面的代码所示：

```go
package other

// StubClient is a stub implementation of sdk.Client interface
type StubClient struct{}

// DoSomethingUseful implements sdk.Client
func (s *StubClient) DoSomethingUseful() (bool, error) {
   return true, nil
}
```

现在，如果我们向`Client`接口添加另一个方法，上述的代码将会失效。

**构造函数不会被继承** - 与我们将在下一章中研究的方法和*方法注入*不同，构造函数在进行组合时不会被包括；相反，我们需要记住构造函数的存在并使用它们。

在进行组合时需要考虑的另一个因素是，内部结构的构造函数的任何参数都必须添加到外部结构的构造函数中，如下面的代码所示：

```go
type InnerService struct {
   innerDep Dependency
}

func NewInnerService(innerDep Dependency) *InnerService {
   return &InnerService{
      innerDep: innerDep,
   }
}

type OuterService struct {
   // composition
   innerService *InnerService

   outerDep Dependency
}

func NewOuterService(outerDep Dependency, innerDep Dependency) *OuterService {
   return &OuterService{
      innerService: NewInnerService(innerDep),
      outerDep:     outerDep,
   }
}
```

像前面的关系会严重阻碍我们改变`InnerService`，因为我们将被迫对`OuterService`进行匹配的更改。

# 总结

在本章中，我们已经研究了构造函数注入的 DI。我们已经看到了它是多么容易理解和应用。这就是为什么它是许多程序员和许多情况下的默认选择。

我们已经看到构造函数注入如何为对象和其依赖之间的关系带来了一定程度的可预测性，特别是当我们使用守卫子句时。

通过将构造函数注入应用于我们的`REST`包，我们得到了一组松散耦合且易于遵循的对象。因此，我们能够轻松扩展我们的测试场景覆盖范围。我们还可以期望，对模型层的任何后续更改现在不太可能会不适当地影响我们的`REST`包。

在下一章中，我们将介绍 DI 的方法注入，这是处理可选依赖项的一种非常方便的方式。

# 问题

1.  我们采用了哪些步骤来采用构造函数注入？

1.  什么是守卫子句，何时使用它？

1.  构造函数注入如何影响依赖项的生命周期？

1.  构造函数注入的理想用例是什么？
