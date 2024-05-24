# C++ 函数式编程实用指南（五）

> 原文：[`annas-archive.org/md5/873bfe33df74385c75906a2f129ca61f`](https://annas-archive.org/md5/873bfe33df74385c75906a2f129ca61f)
> 
> 译者：[飞龙](https://github.com/wizardforcel)
> 
> 协议：[CC BY-NC-SA 4.0](http://creativecommons.org/licenses/by-nc-sa/4.0/)

# 第十三章：不变性和架构 - 事件溯源

事件溯源是一种利用不变性进行存储的架构模式。事件溯源的基本思想是，与其存储数据的当前状态，不如存储修改数据的事件。这个想法可能看起来很激进，但并不新颖；事实上，您已经在使用基于这一原则的工具——例如 Git 等源代码控制系统遵循这种架构。我们将更详细地探讨这个想法，包括其优点和缺点。

本章将涵盖以下主题：

+   不变性的概念如何应用于数据存储

+   事件溯源架构的外观

+   在决定是否使用事件溯源时需要考虑的因素

# 技术要求

您需要一个支持 C++ 17 的编译器。我使用的是 GCC 7.4.0。

代码可以在 GitHub 上找到[https:/​/​github.​com/​PacktPublishing/​Hands-​On-​Functional-Programming-​with-​Cpp](https://github.%E2%80%8Bcom/PacktPublishing/Hands-On-Functional-Programming-with-Cpp)的`Chapter13`文件夹中。它包括并使用了`doctest`，这是一个单头开源单元测试库。您可以在其 GitHub 存储库中找到它[https:/​/github.​com/​onqtam/​doctest](https://github.%E2%80%8Bcom/onqtam/doctest)。

# 不变性和架构 - 事件溯源

直到 2010 年左右，数据存储的选择相当有限。无论您偏好的是 Oracle、MySQL 还是 PostgreSQL，您几乎都必须使用关系模型来存储数据。

然后，突然间，大量新的数据库引擎如雨后春笋般出现，对关系数据的支持部分或完全不足。它们如此不同，以至于无法进行积极的分类，因此世界最终以它们不做的事情来命名它们——NoSQL 数据库。事实上，它们唯一的共同点是对 SQL 的支持很少或根本没有。引擎的列表很长且不断变化，但在撰写本文时，一些引擎很普遍，包括 Redis、MongoDB、DynamoDb、Cassandra 和 Couchbase 等。每个引擎都有其自身的优势和劣势，它们出现的原因是为了优化各种场景，通常是在云计算的背景下。例如，Cassandra 具有高度分布式，而 MongoDB 允许轻松存储多种类型的数据。

大约在我听说 NoSQL 的同时，我开始听说一种称为事件溯源的新架构模式。与通常的 UI 服务器关系数据库模式相比，事件溯源对数据存储采取了一种根本不同的方法。事件溯源模式认为，与其存储系统的当前状态，不如我们将系统的增量更改编码为*领域事件*进行存储。

敏锐的读者会注意到这个想法的两个方面：

+   这听起来像是**领域驱动设计**（**DDD**）运动中的产物，事实上确实如此。领域事件可以作为我们在架构和领域模型演进中使用的另一种模式。

+   尽管对于业务应用程序来说，在数据存储中存储增量更改的想法可能是激进的，但在软件架构中并不新鲜。事实上，在撰写本书的过程中，我一直在使用基于这种模式的工具。您可能也使用它来获取代码示例。虽然使用了比我们将在事件溯源中讨论的历史更复杂的模型，但 Git 将增量更改与代码的当前状态一起存储。

Git 并不是唯一使用这种模式的工具。多年来，我们一直在运维中使用这样的工具进行数据备份。由于完整备份可能需要很长时间，一个好的策略是将频繁的增量备份与不经常的完整备份混合使用。然而，诀窍在于，当需要恢复时，我们可以依次应用增量备份，达到与完整备份相同的状态。这是在备份所需的时间和存储空间以及恢复备份所需的时间之间的一个很好的权衡。

到这一点，你可能会想知道事件溯源与 NoSQL 数据库有什么关系，除了与存储相关？虽然我无法证明，但我相信这两个想法都来自于 2010 年代围绕编程的思想潮流——通过消除技术障碍来优化开发速度，并为各种网络和基于云的架构优化系统。

让我们来思考一下 Twitter。在数据流方面，Twitter 有两个主要功能——发布消息和查看其他用户发布的消息。如果你不能立即看到另一个用户发布的消息，你甚至都不会知道，因此允许高延迟。然而，我们不希望丢失数据，所以需要尽快将用户消息存储起来。

实现这样的功能的标准方式是在请求时直接将消息保存到数据库中，并在响应时返回更新后的消息源。这使我们能够立即看到消息，但它也有一些缺点。首先，它使数据库成为瓶颈，因为每条发布的消息都执行了`INSERT`和`SELECT`语句。其次，它需要更多的服务器资源，从而增加了基于云的服务器成本。

如果我们换个思路呢？当你发布一条消息时，我们只是将事件保存到一个快速事件存储中，并立即返回。在未来的请求中更新消息源时，事件会被考虑进去，并返回更新后的消息源。数据存储不再是瓶颈，我们减少了服务器负载。然而，我们在系统中增加了一个新元素，即事件存储，这可能会增加一些成本，但事实证明，在高规模下，这可能比另一种选择更便宜、更响应。这是事件溯源的一个例子。

另一个选择是在数据引擎层解决这个问题，并像之前提到的那样分离写入和读取；然而，我们使用的数据存储是为写入进行了优化。缺点是数据的可读性比以前更高延迟，但这没关系。在未来的某个时候，数据变得可用，消息源也会更新。这是使用 NoSQL 数据库而不是关系数据库管理系统的一个例子。

2010 年代确实非常有趣，引发了软件架构和设计领域的许多新想法，同时将函数式编程引入了主流编程语言。顺便说一句，这个时期还因漫威电影宇宙（MCU）的一系列超级英雄电影而变得有趣。这两者之间没有联系，我只是喜欢漫威电影宇宙！然而，我必须停止对软件设计历史和漫威电影宇宙的狂热追捧，转而讨论另一个奇怪的想法——将不可变性引入数据存储。

# 将不可变性引入架构

我们已经看到不可变性对代码结构有深远影响，因此也对软件设计产生影响。我们还多次讨论过，I/O 基本上是可变的。我们将要展示的是，数据存储不一定是可变的，不可变的数据存储也对架构产生深远影响。

数据存储如何做到不可变？毕竟，许多软件应用的整个目的就是 CRUD——创建、检索、更新和删除。唯一不改变数据的操作是检索，尽管在某些情况下，检索数据可能会产生额外的副作用，如分析或日志记录。

然而，要记住我们面临着与数据结构相同的问题。可变数据结构在添加或删除元素时会改变其结构。然而，纯函数式语言支持不可变数据结构。

不可变数据结构具有以下特性——添加或删除项目不会改变数据结构。相反，它会返回初始数据结构的副本以及变化。为了优化内存，纯函数式编程语言实际上并不克隆数据，它们只是巧妙地利用指针来重用现有的内存。然而，对于程序员来说，就好像数据结构已经完全被克隆了。

考虑将相同的想法应用于存储。与其改变现有数据，每次写入或删除都会创建一个应用了变化的新版本的数据，同时保留之前的版本不变。想象一下可能性；我们得到了数据变化的整个历史，我们总是可以恢复它们，因为我们有一个非常近期的数据版本。

不过这并不容易。存储的数据往往很大，在每次变化时复制它将占用大量的存储空间，并且在这个过程中变得极其缓慢。与内存数据一样，同样的优化技术并不奏效，因为存储的数据往往更加复杂，而指针在文件系统中并不（还没有？）那么容易管理。

幸运的是，还有一种选择——一开始存储数据的版本，然后只存储数据的一些变化。我们可以在关系数据库中实现这一点（毕竟这些变化只是实体），但幸运的是，我们不必这样做。为了支持这种存储模型，一些被称为**事件存储**的存储引擎已经被实现。它们允许我们存储事件，并在需要时获取数据的最新版本。

这样的系统会如何运作呢？嗯，我们需要对领域和领域事件进行建模。让我们以 Twitter 为例来做这个。

![](https://github.com/OpenDocCN/freelearn-c-cpp-zh/raw/master/docs/hsn-fp-cpp/img/48cff6f2-742f-4b2e-82f6-cf016f2a3624.png)

如果我们使用传统的数据存储，我们只会以某种方式保存实体，但我们想要存储事件，所以我们将会有一个长长的增量变化列表，概念上看起来像这样：

```cpp
CreateUser name:alexboly -> userid 1
CreateUser name: johndoe -> userid 2
PostMessage userid: 1, message: 'Hello, world!' -> messageid 1
PostMessage userid: 2, message: 'Hi @alexboly' -> messageid 2
CreateNotification userid: 1, notification: "Message from johndoe"
PostMessage userid: 1, message: 'Hi @johndoe' -> messageid 3
CreateNotification userid: 2, notification: "Message from alexboly"
LikeMessage userid: 2, messageid: 3
...
```

在我们继续看一个实现的例子之前，我们需要记住我们正在讨论软件架构，没有解决方案是完美的。因此，我们必须停下来考虑一下在使用事件溯源时所做的权衡。

# 事件溯源的优势

如果事件溯源没有优势，我们就不会谈论它。

在概念层面，领域模型和领域事件可以很快地从领域专家那里提取出来，而且可以在非常快速、轻量级的会话中完成。事件风暴是一个促进会话，允许我们通过技术和领域专家之间的合作在几小时内设计一个复杂的系统。在这个事件中创造的知识不容小觑；这种共同的理解是知识工作中复杂努力中任何领域之间合作的强有力基础。

在软件设计层面，事件溯源比其他代码结构更好地揭示了意图。领域操作往往隐藏在实体内部；而在事件溯源中，领域模型的变化成为了架构的核心。我们实际上可以搜索数据可能经历的所有变化，并获得一个列表——这对其他代码结构来说是很困难的。

在编码层面，事件溯源简化了编程。虽然一开始可能很难以事件的方式思考，但它很快就会变得很自然。这种模型允许我们编写反映最重要业务特性的代码，从而使程序员和产品所有者或客户之间的理解更加容易。它还很好地封装了每种类型的变化，从而简化了我们的测试和代码。

在数据存储级别上，事件溯源允许我们查看对数据所做的更改列表，这对于其他数据存储模型来说是一个极端的壮举。增量备份在这种模型中更合适，因为它基本上是增量的。恢复内置于数据存储中，允许我们从任何过去的具体化存储开始，并应用所有事件。

此外，事件溯源允许我们回到过去。如果每个事件都有一个相反的事件，通常很容易做到，我们可以从末尾播放相反的事件到特定的时间戳，从而导致我们在那个时间点拥有的确切数据。

在性能水平上，事件溯源优化了数据的写入，使其对于大多数需要快速写入但可以处理读取延迟的应用程序非常有用（也被称为**大多数基于 Web 的系统**）。

但没有什么是免费的，那么什么可能出错呢？

# 事件溯源的缺点和注意事项

尽管事件溯源具有诸多优势，但在跳上这辆车之前，你需要考虑一些重要的缺点。

# 更改事件模式

第一个问题来自事件溯源的核心模型——如果我们需要在已经有大量数据的情况下更改事件的结构会怎样？例如，如果我们需要为每个事件添加时间戳怎么办？或者如果我们需要更改我们的`PostMessage`事件以包括一个可见性字段，该字段只能是接收者、只有关注者或所有人？

这个问题有解决方案，但每个解决方案都有自己的问题。一个解决方案是对事件模式进行版本控制，并且并排使用多个模式，这样做虽然有效，但会使具体化变得复杂。另一个解决方案是使用数据迁移脚本来更改过去的事件，但这会破坏不可变性的概念，而且必须做得正确。另一个选择是永远不更改事件模式，只是添加新的事件类型，但这可能会因多个已弃用的事件类型而导致混乱。

# 删除过去的数据

第二个问题是隐私。最近在**欧洲联盟**（**EU**）颁布的**通用数据保护条例**（**GDPR**）影响了世界各地许多软件系统，赋予用户要求从系统中完全删除私人数据的权利。在使用普通数据库时，这相对容易——只需删除与用户 ID 相关的记录——但在事件存储中该如何做呢？

我们可以从删除与用户相关的所有事件开始。但我们能这样做吗？如果事件具有时间关系，我们可能会遇到问题。例如，想象一下协同编辑文档的以下场景：

```cpp
CreateAuthor alexboly => authorid 1
CreateAuthor johndoe => authorid 2
...
AddText index: 2400, authorid:1, text: "something interesting here."
AddText index: 2427, authorid:2, text: "yes, that's interesting" => 
    "something interesting here. yes that's interesting"
DeleteText index: 2400, length: 10, authorid: 1 =>"interesting here. 
    yes that's interesting"
...
```

如果用户`alexboly`要求我们删除事件，让我们标记需要删除的事件：

```cpp
CreateAuthor alexboly => authorid 1
CreateAuthor johndoe => authorid 2
...
AddText index: 2400, authorid:1, text: "something interesting here."
AddText index: 2427, authorid:2, text: "yes, that's interesting" => 
    "something interesting here. yes that's interesting"
DeleteText index: 2400, length: 10, authorid: 1 =>"interesting here. 
    yes that's interesting"
...
```

你看到问题了吗？如果我们删除了突出显示的事件，不仅会丢失文档中的数据，而且索引也不再匹配！按顺序应用事件到空白文档将导致错误或损坏的数据。

我们可以做一些事情：

+   一个解决方案是删除用户的身份但保留数据。虽然这在特定情境下可能有效，但这个解决方案取决于删除请求的范围。有一种特殊情况，即用户已将个人数据（例如地址、电子邮件地址或 ID 号码）添加到文档中。如果我们删除了用户的身份，但也需要删除个人数据，我们将需要扫描所有事件以查找个人数据，并删除或用相同数量的空白字符替换它。

+   另一个解决方案是具体化数据库，删除数据，并从新的检查点开始处理未来事件。这破坏了事件溯源的核心理念之一——从空存储重建数据的能力——对于具有许多事件或许多删除的系统来说可能会很困难。但通过适当的规划和结构是可能的。

+   第三种解决方案是利用架构并使用`DeletePrivateData`的特殊事件。但是，这个事件不同，因为它将改变事件存储而不是数据。虽然它符合架构，但它是有风险的，并且需要广泛的测试，因为它可能会破坏一切。

+   第四种解决方案是设计事件，使它们不是时间上耦合的。从理论上讲，这听起来不错，但我们必须承认在实践中可能并不总是可能的。在前面的例子中，我们需要一些文本的位置，我向你挑战找到一种独立于现有文本的指定位置的方法。还要考虑到，我们将在一个罕见的情况下进行这种设计工作，这可能使所有事件都不那么容易理解。如果可以通过最小的更改实现，那就太好了；但如果不能，你就需要自己做出决定。

# 实现示例

接下来我们将看一个使用事件源的简单实现示例。我们将从我们的 Twitter 示例开始，然后开始编写一些测试。

首先，让我们创建一个用户，并在伪代码中检查正确的事件存储：

```cpp
TEST_CASE("Create User"){
    EventStore eventStore;
    ...
    auto alexId = createUser("alexboly", eventStore);
    ...
    CHECK_EQ(lastEvent, expectedEvent);
}
```

我们需要一些东西来编译这个测试。首先，一个可以存储事件的事件存储，但是如何表示可以存储的事件呢？我们需要一种可以保存属性名称和值的数据结构。最简单的是一个`map<string, string>`结构，它将属性的名称映射到它们的值。为了看到它的作用，让我们为`CreateUser`创建事件结构：

```cpp
auto makeCreateUserEvent = [](const string& handle, const int id){
    return map<string, string>{
            {"type", "CreateUser"}, 
            {"handle", handle}, 
            {"id", to_string(id)}
    };
};
```

`CreateUser`事件有一个类型，`CreateUser`，并且需要一个句柄，例如`alexboly`，以及用户的`id`。让我们使用`typedef`使其更加友好和明确：

```cpp
typedef map<string, string> Event;
auto makeCreateUserEvent = [](const string& handle, const int id){
    return Event{
            {"type", "CreateUser"}, 
            {"handle", handle}, 
            {"id", to_string(id)}
    };
};
```

现在我们可以创建我们的`EventStore`。因为它基本上是一个事件列表，让我们直接使用它：

```cpp
class EventStore : public list<Event>{
    public:
        EventStore() : list<Event>(){
        };
};
```

所以，现在我们的测试可以使用`EventStore`和`makeCreateUserEvent`函数来检查，在调用`createUser`后，正确的事件将在事件存储中：

```cpp
TEST_CASE("Create User"){
    auto handle = "alexboly";
    EventStore eventStore;

    auto alexId = createUser(handle, eventStore);

    auto expectedEvent = makeCreateUserEvent(handle, alexId);
    auto event = eventStore.back();
    CHECK_EQ(event, expectedEvent);
}
```

我们现在只需要为这个测试实现`createUser`。这很简单；调用`makeCreateUserEvent`并将结果添加到`EventStore`。我们需要一个`id`，但由于我们现在只有一个元素，让我们使用一个硬编码值`1`：

```cpp
int id = 1;
auto createUser = [](string handle, EventStore& eventStore){
    eventStore.push_back(makeCreateUserEvent(handle, id));
    return id;
};
```

测试通过了；现在我们可以执行事件，并它们将进入事件存储。

现在让我们看看新用户如何发布消息。我们将需要第二种事件类型`PostMessage`，以及类似的代码基础设施。让我们编写测试。首先，我们需要创建一个用户。其次，我们需要创建一个通过`userId`与用户关联的消息。以下是测试：

```cpp
TEST_CASE("Post Message"){
    auto handle = "alexboly";
    auto message = "Hello, world!";
    EventStore eventStore;

    auto alexId = createUser(handle, eventStore);
    auto messageId = postMessage(alexId, message, eventStore);
    auto expectedEvent = makePostMessageEvent(alexId, message, 
        messageId);
    auto event = eventStore.back();
    CHECK_EQ(event, expectedEvent);
}
```

`makePostMessageEvent`函数将只创建一个带有所有必需信息的`Event`结构。它还需要一个类型和`messageId`：

```cpp
auto makePostMessageEvent = [](const int userId, const string& message, int id){
    return Event{
            {"type", "PostMessage"}, 
            {"userId", to_string(userId)}, 
            {"message", message},
            {"id", to_string(id)}
    };
};
```

最后，`postMessage`只需将`makePostMessageEvent`的结果添加到`EventStore`中。我们再次需要一个 ID，但我们只有一条消息，所以我们可以使用相同的 ID`1`：

```cpp
auto postMessage = [](const int userId, const string& message, 
    EventStore& eventStore){
      eventStore.push_back(makePostMessageEvent(userId, message, id));
      return id;
};
```

所以，现在我们有一个用户可以通过事件发布消息。这相当不错，也没有像一开始看起来那么困难。

这个实现提出了一些有趣的问题。

# 你如何检索数据？

首先，如果我想通过他们的句柄或`id`搜索用户怎么办？这是 Twitter 上的一个真实使用场景。如果我在消息中提到另一个用户`@alexboly`，通知应该发布到具有句柄`alexboly`的用户。此外，我想在时间轴上显示与用户`@alexboly`相关的所有消息。

对此我有两个选择。第一个选择是仅存储事件，并在读取数据时运行所有事件。第二个选择是维护一个具有当前值的域存储，并像任何其他数据库一样查询它。重要的是要注意，这些存储中的每一个或两个可能都是内存中的，以便非常快速地访问。

无论当前值是缓存还是计算得出的，我们都需要一种执行事件并获取它们的方法。我们怎么做呢？

让我们编写一个测试来描述我们需要的内容。在运行一个或多个事件之后，我们需要执行这些事件并获取当前值，以便在需要时检索它们：

```cpp
TEST_CASE("Run events and get the user store"){
    auto handle = "alexboly";
    EventStore eventStore;

    auto alexId = createUser(handle, eventStore);
    auto dataStore = eventStore.play();

    CHECK_EQ(dataStore.users.back(), User(alexId, handle));
}
```

为了使测试通过，我们需要一些东西。首先，一个`User`领域对象，我们将保持非常简单：

```cpp
class User{
    public:
        int id;
        string handle;
        User(int id, string handle): id(id), handle(handle){};
};
```

其次，一个包含`users`列表的数据存储：

```cpp
class DataStore{
    public:
        list<User> users;
};
```

最后，`play`机制。现在让我们先使用一个丑陋的实现：

```cpp
  class EventStore : public list<Event>{
    public:
       DataStore play(){
            DataStore dataStore;
            for(Event event :  *this){
                if(event["type"] == "CreateUser"){
                    dataStore.users.push_back(User(stoi(event["id"]), 
                        event["handle"]));
                }
            };
            return dataStore;
        };
}
```

了解高阶函数后，我们当然可以看到我们在前面的片段中的`for`语句可以转换为函数式方法。实际上，我们可以通过调用`transform`将所有事件按`CreateUser`类型进行过滤，然后将每个事件转换为实体。首先，让我们提取一些较小的函数。我们需要一个将`CreateUser`事件转换为用户的函数：

```cpp
auto createUserEventToUser = [](Event event){
    return User(stoi(event["id"]), event["handle"]);
};
```

我们还需要另一个函数，它可以按类型过滤事件列表：

```cpp
auto createUserEventToUser = [](Event event){
    return User(stoi(event["id"]), event["handle"]);
};
```

现在我们可以提取一个`playEvents`函数，它接受一个事件列表，按类型进行过滤，并运行转换，得到一个实体列表：

```cpp
template<typename Entity>
auto playEvents = [](const auto& events, const auto& eventType, 
    auto playEvent){
      list<Event> allEventsOfType;
      auto filterEventByThisEventType = bind(filterEventByEventType, 
        _1, eventType);
      copy_if(events.begin(),events.end(),back_insert_iterator
        (allEventsOfType), filterEventByThisEventType);
      list<Entity> entities(allEventsOfType.size());
      transform(allEventsOfType.begin(), allEventsOfType.end(),    
        entities.begin(), playEvent); 
      return entities;
};
```

现在我们可以在我们的`EventStore`中使用这个函数来替换`CreateUser`的处理，并将其泛化到其他事件中：

```cpp
class EventStore : public list<Event>{
    public:
        EventStore() : list<Event>(){
        };
        DataStore play(){
            DataStore dataStore;
            dataStore.users = playEvents<User>(*this, "CreateUser", 
                createUserEventToUser);
            return dataStore;
        };
};
```

我们现在有了一种根据事件从我们的存储中检索数据的方法。是时候看看下一个问题了。

# 引用完整性怎么样？

到目前为止，我们已经看到了在使用事件时实体之间的关系是基于 ID 的，但是如果我们使用错误的`id`调用事件会怎样？看看下面片段中的例子：

```cpp
CreateUser handle:alexboly -> id 1
DeleteUser id: 1
PostMessage userId: 1, text: "Hello, world!" -> user with id 1 doesn't 
                                                exist anymore
```

我看到了这个问题的几个解决方案：

+   第一个解决方案是无论如何都运行事件。如果这不会在显示上创建额外的问题，那么这将起作用。在 Twitter 上，如果我看到一条消息，我可以导航到发布消息的用户。在这种情况下，导航将导致一个不存在的页面。这是一个问题吗？我认为对于像 Twitter 这样的东西，这不是一个很大的问题，只要它不经常发生，但你必须在你自己产品的上下文中判断它。

+   第二个解决方案是在没有任何检查的情况下运行事件，但运行一个重复的作业来检查引用问题并清理它们（通过事件，当然）。这种方法允许您最终使用事件源清理数据，而不会通过完整性检查减慢更新。再次，您需要弄清楚这在您的上下文中是否起作用。

+   第三种解决方案是在每次事件运行时运行完整性检查。虽然这可以确保引用完整性，但也会减慢一切速度。

检查可以通过两种方式进行——要么通过检查数据存储，要么通过检查事件存储。例如，你可以检查`DeleteUser`的 ID`1`从未发生过，或者它没有在`CreateUser`之后发生过（但你需要用户句柄）。

在选择事件源应用程序时请记住这一点！

# 总结

事件源是一种不可变数据存储方法，从一个简单的想法开始——我们存储导致当前状态的所有事件，而不是存储世界的当前状态？这种方法的优势很多，也很有趣——能够在时间上前进和后退，内置增量备份，并且以时间线而不是状态来思考。它也有一些注意事项——删除过去的数据非常困难，事件模式很难更改，引用完整性往往变得更松散。您还需要注意可能的错误，并定义处理它们的结构化和可重复的策略。

我们还看到了如何使用 lambda 作为事件实现简单的事件源架构。我们还可以看一下用于存储 lambda 的事件源，因为存储的事件基本上是一个命令模式，而命令模式的最简单实现是 lambda。好奇的读者可以尝试将事件序列化/反序列化为 lambda，并看看它如何改变设计。

像任何架构模式一样，我的建议是仔细考虑权衡，并对实施中提出的最重要的挑战有答案。如果您选择尝试事件溯源，我还建议您尝试一个成熟的事件存储，而不是自己构建一个。本章中我们编写的事件存储对展示事件溯源的核心原则和挑战很有用，但远未准备好投入生产使用。

现在是时候转向 C ++中函数式编程的未来了。在下一章中，我们将介绍 C ++ 17 中现有的函数式编程特性，并了解关于 C ++ 20 的最新消息。


# 第四部分：C++中函数式编程的现在和未来

我们已经学习了很多在函数式编程中可以使用的技术，从基本构建模块，到我们可以以以函数为中心的风格进行设计的方式，再到我们如何可以利用函数式编程来实现各种目标。现在是时候看看标准 C++ 17 和 20 中函数式编程的现在和未来了。

我们将首先使用令人惊叹的 Ranges 库进行实践，该库作为 C++ 17 的外部实现和 C++ 20 标准的一部分。我们将看到一个简单的想法，以轻量级的方式包装现有容器，结合组合运算符和我们广泛使用的高阶函数的新方法，使我们能够编写比标准 C++ 17 中的替代方案更简单、更快和更轻的代码。

然后，我们将讨论 STL 支持并看看接下来会发生什么。最后，我们将看一下函数式编程的主要构建模块以及它们在 C++中的支持情况。

本节将涵盖以下章节：

+   第十四章，使用 Ranges 库进行惰性求值

+   第十五章，STL 支持和提案

+   第十六章，标准语言支持和提案


# 第十四章：使用 ranges 库进行懒惰评估

在本书中，我们详细讨论了如何以函数的方式思考，以及函数链接和组合如何帮助创建模块化和可组合的设计。然而，我们遇到了一个问题——根据我们当前的方法，需要将大量数据从一个集合复制到另一个集合。

幸运的是，Eric Niebler 自己着手开发了一个库，使纯函数式编程语言中的解决方案——懒惰评估成为可能。该库名为**ranges**，随后被正式纳入 C++ 20 标准。在本章中，我们将看到如何利用它。

本章将涵盖以下主题：

+   为什么以及何时懒惰评估是有用的

+   ranges 库的介绍

+   如何使用 ranges 库进行懒惰评估

# 技术要求

你需要一个支持 C++ 17 的编译器。我使用的是 GCC 7.4.0。

该代码可以在 GitHub 上找到，网址为[https:/​/​github.​com/​PacktPublishing/​Hands-​On-​Functional-Programming-​with-​Cpp](https://github.%E2%80%8Bcom/PacktPublishing/Hands-On-Functional-Programming-with-Cpp)，在`Chapter14`文件夹中。它包括并使用了`doctest`，这是一个单头文件的开源单元测试库。你可以在它的 GitHub 仓库上找到它，网址为[https:/​/github.​com/​onqtam/​doctest](https://github.%E2%80%8Bcom/onqtam/doctest)。

# ranges 库概述

ranges 库为 C++程序员提供了各种有用的新工具。它们都很有用，但对于我们的函数式编程需求来说，许多工具尤其如此。

但首先，让我们看看如何设置它。要在 C++ 17 中使用 ranges 库，你需要使用来自[`ericniebler.github.io/range-v3/`](https://ericniebler.github.io/range-v3/)的指示。然后，你只需要包含`all.hpp`头文件：

```cpp
#include <range/v3/all.hpp>
```

至于 C++ 20，你只需要包含`<ranges>`头文件，因为该库已包含在标准中：

```cpp
#include <ranges>
```

然而，如果你在尝试上一行代码时遇到编译错误，不要感到惊讶。在撰写本文时，最新版本的 g++是 9.1，但 ranges 库尚未包含在标准中。由于其规模，实现预计会相当晚。在那之前，如果你想尝试它，你仍然可以使用 Eric Niebler 的版本。

那么，ranges 库提供了什么？嗯，一切都始于范围的概念。一个范围由一个起始迭代器和一个结束迭代器组成。这使我们首先可以在现有集合的基础上添加一个范围。然后，我们可以将一个范围传递给需要起始和结束迭代器的算法（如`transform`、`sort`或`accumulate`），从而消除了对`begin()`和`end()`的不便调用。

使用 ranges，我们可以构建视图。视图指定我们对部分或全部集合感兴趣，通过两个迭代器，但也允许懒惰评估和可组合性。由于视图只是集合的轻量级包装器，我们可以声明一系列操作，而不实际执行它们，直到需要结果。我们将在下一节详细介绍这是如何工作的，但这里有一个简单的示例，组合两个操作，将过滤出集合中所有的倍数为六的数字，首先通过过滤*所有的偶数*，然后再过滤出*是 3 的倍数*的数字：

```cpp
numbers | ranges::view::filter(isEven) | ranges::view::filter(isMultipleOf3)
```

在 ranges 上也可以进行突变，借助于操作。操作类似于视图，只是它们会就地改变底层容器，而不是创建副本。正如我们之前多次讨论过的那样，在函数式编程中，我们更喜欢不改变数据；然而，在某些情况下，我们可以通过这种解决方案优化性能，因此值得一提。下面是一个操作的示例...嗯，在操作中：

```cpp
numbers |= action::sort | action::take(5);
```

`|`运算符对于函数式编程者来说非常有趣，因为它是一种函数组合运算符。对于 Unix/Linux 用户来说，使用它也很自然，他们非常习惯组合操作。正如我们在第四章中所看到的，*函数组合的概念*，这样的运算符将非常有用。不幸的是，它还不支持任意两个函数的组合，只支持视图和操作的组合。

最后，ranges 库支持自定义视图。这打开了诸如数据生成之类的可能性，这对许多事情都很有用，特别是第十一章中的*基于属性的测试*。

让我们更详细地访问范围库的特性，并举例说明。

# 惰性求值

在过去的章节中，我们已经看到了如何以函数式的方式构造代码，通过对数据结构进行小的转换来利用。让我们举一个简单的例子——计算列表中所有偶数的和。结构化编程方法是编写一个循环，遍历整个结构，并添加所有偶数元素：

```cpp
int sumOfEvenNumbersStructured(const list<int>& numbers){
    int sum = 0;
    for(auto number : numbers){
        if(number % 2 == 0) sum += number;
    }
    return sum;
};
```

这个函数的测试在一个简单的例子上运行正确：

```cpp
TEST_CASE("Run events and get the user store"){
    list<int> numbers{1, 2, 5, 6, 10, 12, 17, 25};

    CHECK_EQ(30, sumOfEvenNumbersStructured(numbers));
}
```

当然，这种方法会改变数据，我们已经知道这不总是一个好主意。它也一次做了太多的事情。我们宁愿组合更多的函数。第一个函数需要决定一个数字是否是偶数：

```cpp
auto isEven = [](const auto number){
    return number % 2 == 0;
};
```

第二个函数从集合中挑选满足谓词的数字：

```cpp
auto pickNumbers  = [](const auto& numbers, auto predicate){
    list<int> pickedNumbers;
    copy_if(numbers.begin(), numbers.end(), 
        back_inserter(pickedNumbers), predicate);
    return pickedNumbers;
};
```

第三个计算集合中所有元素的和：

```cpp
auto sum = [](const auto& numbers){
    return accumulate(numbers.begin(), numbers.end(), 0);
};
```

这将我们带到了最终的实现，它包括所有这些函数：

```cpp
auto sumOfEvenNumbersFunctional = [](const auto& numbers){
    return sum(pickNumbers(numbers, isEven));
};
```

然后它通过了测试，就像结构化的解决方案一样：

```cpp
TEST_CASE("Run events and get the user store"){
    list<int> numbers{1, 2, 5, 6, 10, 12, 17, 25};

    CHECK_EQ(30, sumOfEvenNumbersStructured(numbers));
    CHECK_EQ(30, sumOfEvenNumbersFunctional(numbers));
}
```

函数式解决方案有明显的优势——它简单，由可以重新组合的小函数组成，而且它是不可变的，这也意味着它可以并行运行。然而，它也有一个缺点——它会复制数据。

我们已经在第十章中看到了如何处理这个问题，但事实上，最简单的解决方案是惰性求值。想象一下，如果我们可以链接函数调用，但是在我们需要其结果的时刻之前，代码实际上并没有执行，那将意味着什么。这个解决方案打开了编写我们需要编写的代码以及我们需要的方式的可能性，编译器最大限度地优化了函数链。

这就是 ranges 库正在做的事情，以及其他一些额外的功能。

# 使用 ranges 库进行惰性求值

ranges 库提供了一个名为**views**的工具。视图允许从迭代器构造不可变且廉价的数据范围。它们不会复制数据，只是引用数据。我们可以使用`view`来过滤我们的集合中的所有偶数：

```cpp
ranges::view::filter(numbers, isEven)
```

视图可以在不复制任何内容的情况下进行组合，并使用组合运算符`|`。例如，我们可以通过组合两个过滤器来获得能被`6`整除的数字列表：第一个是偶数，第二个是能被`3`整除的数字。给定一个新的谓词，检查一个数字是否是`3`的倍数，我们使用以下方法：

```cpp
auto isMultipleOf3 = [](const auto number){
    return number % 3 == 0;
};
```

我们通过以下组合获得能被`6`整除的数字列表：

```cpp
numbers | ranges::view::filter(isEven) | ranges::view::filter(isMultipleOf3)
```

重要的是要注意，当编写这段代码时实际上没有计算任何东西。视图已经初始化，并且正在等待命令。所以，让我们计算视图中元素的和：

```cpp
auto sumOfEvenNumbersLazy = [](const auto& numbers){
    return ranges::accumulate(ranges::view::
        filter(numbers, isEven), 0);
};
TEST_CASE("Run events and get the user store"){
    list<int> numbers{1, 2, 5, 6, 10, 12, 17, 25};

    CHECK_EQ(30, sumOfEvenNumbersLazy(numbers));
}
```

`ranges::accumulate`函数是 accumulate 的一个特殊实现，它知道如何与视图一起工作。只有在调用`accumulate`时，视图才会起作用；此外，实际上没有数据被复制——相反，ranges 使用智能迭代器来计算结果。

让我们也看看组合视图的结果。如预期的那样，向量中所有能被`6`整除的数字的和是`18`：

```cpp
auto sumOfMultiplesOf6 = [](const auto& numbers){
    return ranges::accumulate(
            numbers | ranges::view::filter(isEven) | 
                ranges::view::filter(isMultipleOf3), 0);
};
TEST_CASE("Run events and get the user store"){
    list<int> numbers{1, 2, 5, 6, 10, 12, 17, 25};

    CHECK_EQ(18, sumOfMultiplesOf6(numbers));
}
```

写代码的方式真好！它比以前的两种选项都要容易得多，同时内存占用也很低。

但这还不是 ranges 能做的全部。

# 使用操作进行可变更改

除了视图，范围库还提供了操作。操作允许急切的、可变的操作。例如，要对同一个向量中的值进行排序，我们可以使用以下语法：

```cpp
TEST_CASE("Sort numbers"){
    vector<int> numbers{1, 12, 5, 20, 2, 10, 17, 25, 4};
    vector<int> expected{1, 2, 4, 5, 10, 12, 17, 20, 25};

    numbers |= ranges::action::sort;

    CHECK_EQ(expected, numbers);
}
```

`|=`运算符类似于`ranges::action::sort(numbers)`调用，原地对向量进行排序。操作也是可组合的，可以通过直接方法调用或使用`|`运算符进行组合。这使我们能够编写代码，通过`sort`和`unique`操作的组合来对容器进行排序并保留唯一项：

```cpp
TEST_CASE("Sort numbers and pick unique"){
    vector<int> numbers{1, 1, 12, 5, 20, 2, 10, 17, 25, 4};
    vector<int> expected{1, 2, 4, 5, 10, 12, 17, 20, 25};

    numbers |= ranges::action::sort | ranges::action::unique;

    CHECK_EQ(expected, numbers);
}
```

然而，这还不是范围可以做的一切。

# 无限序列和数据生成

由于视图是惰性评估的，它们允许我们创建无限序列。例如，要生成一系列整数，我们可以使用`view::ints`函数。然后，我们需要限制序列，所以我们可以使用`view::take`来保留序列的前五个元素：

```cpp
TEST_CASE("Infinite series"){
    vector<int> values = ranges::view::ints(1) | ranges::view::take(5);
    vector<int> expected{1, 2, 3, 4, 5};

    CHECK_EQ(expected, values);
}
```

可以使用`view::iota`来进行额外的数据生成，例如对于`chars`类型，只要允许增量即可：

```cpp
TEST_CASE("Infinite series"){
    vector<char> values = ranges::view::iota('a') | 
        ranges::view::take(5);
    vector<char> expected{'a', 'b', 'c', 'd', 'e'};

    CHECK_EQ(expected, values);
}
```

此外，您可以使用`linear_distribute`视图生成线性分布的值。给定一个值间隔和要包含在线性分布中的项目数，该视图包括间隔边界以及足够多的内部值。例如，从[`1`，`10`]区间中取出五个线性分布的值会得到这些值：`{1, 3, 5, 7, 10}`：

```cpp
TEST_CASE("Linear distributed"){
    vector<int> values = ranges::view::linear_distribute(1, 10, 5);
    vector<int> expected{1, 3, 5, 7, 10};

    CHECK_EQ(expected, values);
}
```

如果我们需要更复杂的数据生成器怎么办？幸运的是，我们可以创建自定义范围。假设我们想要创建从`1`开始的每个`2`的十次幂的列表（即*2¹*，*2¹¹*，*2²¹*等）。我们可以使用 transform 调用来做到这一点；然而，我们也可以使用`yield_if`函数结合`for_each`视图来实现。下面代码中的粗体行显示了如何将这两者结合使用：

```cpp
TEST_CASE("Custom generation"){
    using namespace ranges;
    vector<long> expected{ 2, 2048, 2097152, 2147483648 };

 auto everyTenthPowerOfTwo = view::ints(1) | view::for_each([](int 
        i){ return yield_if(i % 10 == 1, pow(2, i)); });
    vector<long> values = everyTenthPowerOfTwo | view::take(4);

    CHECK_EQ(expected, values);
}
```

首先，我们生成从`1`开始的无限整数序列。然后，对于每个整数，我们检查该值除以`10`的余数是否为`1`。如果是，我们返回`2`的幂。为了获得有限的向量，我们将前面的无限序列传递给`take`视图，它只保留前四个元素。

当然，这种生成方式并不是最佳的。对于每个有用的数字，我们需要访问`10`，最好是从`1`，`11`，`21`等开始。

值得在这里提到的是，编写这段代码的另一种方法是使用 stride 视图。`stride`视图从序列中取出每个 n^(th)元素，正好符合我们的需求。结合`transform`视图，我们可以实现完全相同的结果：

```cpp
TEST_CASE("Custom generation"){
    using namespace ranges;
    vector<long> expected{ 2, 2048, 2097152, 2147483648 };

 auto everyTenthPowerOfTwo = view::ints(1) | view::stride(10) | 
        view::transform([](int i){ return pow(2, i); });
    vector<long> values = everyTenthPowerOfTwo | view::take(4);

    CHECK_EQ(expected, values);
}
```

到目前为止，您可能已经意识到数据生成对于测试非常有趣，特别是基于属性的测试（正如我们在第十一章中讨论的那样，*基于属性的测试*）。然而，对于测试，我们经常需要生成字符串。让我们看看如何做到这一点。

# 生成字符串

要生成字符串，首先我们需要生成字符。对于 ASCII 字符，我们可以从`32`到`126`的整数范围开始，即有趣的可打印字符的 ASCII 代码。我们取一个随机样本并将代码转换为字符。我们如何取一个随机样本呢？好吧，有一个叫做`view::sample`的视图，它可以从范围中取出指定数量的随机样本。最后，我们只需要将其转换为字符串。这就是我们如何得到一个由 ASCII 字符组成的长度为`10`的随机字符串：

```cpp
TEST_CASE("Generate chars"){
    using namespace ranges;

    vector<char> chars = view::ints(32, 126) | view::sample(10) | 
        view::transform([](int asciiCode){ return char(asciiCode); });
    string aString(chars.begin(), chars.end()); 

    cout << aString << endl;

    CHECK_EQ(10, aString.size());
}
```

以下是运行此代码后得到的一些样本：

```cpp
%.0FL[cqrt
#0bfgiluwy
4PY]^_ahlr
;DJLQ^bipy
```

正如你所看到的，这些是我们测试中使用的有趣字符串。此外，我们可以通过改变`view::sample`的参数来改变字符串的大小。

这个例子仅限于 ASCII 字符。然而，由于 UTF-8 现在是 C++标准的一部分，扩展以支持特殊字符应该很容易。

# 总结

Eric Niebler 的 ranges 库在软件工程中是一个罕见的成就。它成功地简化了现有 STL 高阶函数的使用，同时添加了惰性评估，并附加了数据生成。它不仅是 C++ 20 标准的一部分，而且也适用于较旧版本的 C++。

即使您不使用函数式的代码结构，无论您喜欢可变的还是不可变的代码，ranges 库都可以让您的代码变得优雅和可组合。因此，我建议您尝试一下，看看它如何改变您的代码。这绝对是值得的，也是一种愉快的练习。

我们即将结束本书。现在是时候看看 STL 和语言标准对函数式编程的支持，以及我们可以从 C++ 20 中期待什么，这将是下一章的主题。


# 第十五章：STL 支持和提案

自从 90 年代以来，**标准模板库**（**STL**）一直是 C++程序员的有用伴侣。从泛型编程和值语义等概念开始，它已经发展到支持许多有用的场景。在本章中，我们将看看 STL 如何支持 C++ 17 中的函数式编程，并了解一些在 C++ 20 中引入的新特性。

本章将涵盖以下主题：

+   使用`<functional>`头文件中的函数式特性

+   使用`<numeric>`头文件中的函数式特性

+   使用`<algorithm>`头文件中的函数式特性

+   `std::optional`和`std::variant`

+   C++20 和 ranges 库

# 技术要求

你需要一个支持 C++ 17 的编译器。我使用的是 GCC 7.4.0c。

代码在 GitHub 上的[https:/​/​github.​com/​PacktPublishing/​Hands-​On-​Functional-Programming-​with-​Cpp](https://github.%E2%80%8Bcom/PacktPublishing/Hands-On-Functional-Programming-with-Cpp)的`Chapter15`文件夹中。它包括并使用了`doctest`，这是一个单头开源单元测试库。你可以在它的 GitHub 仓库中找到它：[https:/​/github.​com/​onqtam/​doctest](https://github.%E2%80%8Bcom/onqtam/doctest)。

# `<functional>`头文件

我们需要从 STL 中的函数式编程支持中的某个地方开始，而名为`<functional>`的头文件似乎是一个不错的起点。这个头文件定义了基本的`function<>`类型，我们可以用它来表示函数，并且在本书中的几个地方已经使用过了 lambda 表达式：

```cpp
TEST_CASE("Identity function"){
    function<int(int)> identity = [](int value) { return value;};

    CHECK_EQ(1, identity(1));
}
```

我们可以使用`function<>`类型来存储任何类型的函数，无论是自由函数、成员函数还是 lambda。让我们看一个自由函数的例子：

```cpp
TEST_CASE("Free function"){
    function<int()> f = freeFunctionReturns2;

    CHECK_EQ(2, f());
}
```

这里有一个成员函数的例子：

```cpp
class JustAClass{
    public:
        int functionReturns2() const { return 2; };
};

TEST_CASE("Class method"){
    function<int(const JustAClass&)> f = &JustAClass::functionReturns2;
    JustAClass justAClass;

    CHECK_EQ(2, f(justAClass));
}
```

正如你所看到的，为了通过`function<>`类型调用成员函数，需要传递一个有效的对象引用。可以把它看作是`*this`实例。

除了这种基本类型之外，`<functional>`头文件还提供了一些已定义的函数对象，当在集合上使用函数式转换时非常方便。让我们看一个简单的例子，使用`sort`算法与定义的`greater`函数结合，以便按降序对向量进行排序：

```cpp
TEST_CASE("Sort with predefined function"){
    vector<int> values{3, 1, 2, 20, 7, 5, 14};
    vector<int> expectedDescendingOrder{20, 14, 7, 5, 3,  2, 1};

    sort(values.begin(), values.end(), greater<int>());

    CHECK_EQ(expectedDescendingOrder, values);
}
```

`<functional>`头文件定义了以下有用的函数对象：

+   **算术操作**：`plus`，`minus`，`multiplies`，`divides`，`modulus`和`negate`

+   **比较**：`equal_to`，`not_equal_to`，`greater`，`less`，`greater_equal`和`less_equal`

+   **逻辑操作**：`logical_and`，`logical_or`和`logical_not`

+   **位操作**：`bit_and`，`bit_or`和`bit_xor`

当我们需要将常见操作封装在函数中以便在高阶函数中使用时，这些函数对象可以帮助我们省去麻烦。虽然这是一个很好的集合，但我敢于建议一个恒等函数同样有用，尽管这听起来有些奇怪。幸运的是，实现一个恒等函数很容易。

然而，`<functional>`头文件提供的不仅仅是这些。`bind`函数实现了部分函数应用。我们在本书中多次看到它的应用，你可以在第五章中详细了解它的用法，*部分应用和柯里化*。它的基本功能是接受一个函数，绑定一个或多个参数到值，并获得一个新的函数：

```cpp
TEST_CASE("Partial application using bind"){
    auto add = [](int first, int second){
        return first + second;
    };

    auto increment = bind(add, _1, 1);

    CHECK_EQ(3, add(1, 2));
    CHECK_EQ(3, increment(2));
}
```

有了`function<>`类型允许我们编写 lambda 表达式，预定义的函数对象减少了重复，以及`bind`允许部分应用，我们就有了以函数式方式构造代码的基础。但是如果没有高阶函数，我们就无法有效地这样做。

# <algorithm>头文件

`<algorithm>`头文件包含了一些算法，其中一些实现为高阶函数。在本书中，我们已经看到了许多它们的用法。以下是一些有用的算法列表：

+   `all_of`，`any_of`和`none_of`

+   `find_if`和`find_if_not`

+   `count_if`

+   `copy_if`

+   `generate_n`

+   `sort`

我们已经看到，专注于数据并结合这些高阶函数将输入数据转换为所需的输出是你可以思考的一种方式，这是小型、可组合、纯函数的一种方式。我们也看到了这种方法的缺点——需要复制数据，或者对相同的数据进行多次遍历——以及新的 ranges 库如何以一种优雅的方式解决了这些问题。

虽然所有这些函数都非常有用，但有一个来自`<algorithm>`命名空间的函数值得特别提及——函数式`map`操作`transform`的实现。`transform`函数接受一个输入集合，并对集合的每个元素应用一个 lambda，返回一个具有相同数量元素但其中存储了转换值的新集合。这为我们适应数据结构提供了无限的可能性。让我们看一些例子。

# 从集合中投影每个对象的一个属性

我们经常需要从集合中获取每个元素的属性值。在下面的例子中，我们使用`transform`来获取一个向量中所有人的姓名列表：

```cpp
TEST_CASE("Project names from a vector of people"){
    vector<Person> people = {
        Person("Alex", 42),
        Person("John", 21),
        Person("Jane", 14)
    };

    vector<string> expectedNames{"Alex", "John", "Jane"};
    vector<string> names = transformAll<vector<string>>(
            people, 
            [](Person person) { return person.name; } 
    );

    CHECK_EQ(expectedNames, names);
}
```

再次使用`transform`和`transformAll`的包装器，以避免编写样板代码：

```cpp
template<typename DestinationType>
auto transformAll = [](auto source, auto lambda){
    DestinationType result;
    transform(source.begin(), source.end(), back_inserter(result), 
        lambda);
    return result;
};
```

# 计算条件

有时，我们需要计算一组元素是否满足条件。在下面的例子中，我们将通过比较他们的年龄与`18`来计算人们是否未成年：

```cpp
TEST_CASE("Minor or major"){
    vector<Person> people = {
        Person("Alex", 42),
        Person("John", 21),
        Person("Jane", 14)
    };

    vector<bool> expectedIsMinor{false, false, true};
    vector<bool> isMinor = transformAll<vector<bool>>(
            people, 
            [](Person person) { return person.age < 18; } 
    );

    CHECK_EQ(expectedIsMinor, isMinor);
}
```

# 将所有内容转换为可显示或可序列化格式

我们经常需要保存或显示一个列表。为了做到这一点，我们需要将列表的每个元素转换为可显示或可序列化的格式。在下面的例子中，我们正在计算列表中的`Person`对象的 JSON 表示：

```cpp
TEST_CASE("String representation"){
    vector<Person> people = {
        Person("Alex", 42),
        Person("John", 21),
        Person("Jane", 14)
    };

    vector<string> expectedJSON{
        "{'person': {'name': 'Alex', 'age': '42'}}",
        "{'person': {'name': 'John', 'age': '21'}}",
        "{'person': {'name': 'Jane', 'age': '14'}}"
    };
    vector<string> peopleAsJson = transformAll<vector<string>>(
            people, 
            [](Person person) { 
            return 
            "{'person': {'name': '" + person.name + "', 'age': 
                '" + to_string(person.age) + "'}}"; } 
    );

    CHECK_EQ(expectedJSON, peopleAsJson);
}
```

即使`transform`函数打开了无限的可能性，但与`reduce`（在 C++中为`accumulate`）高阶函数结合使用时，它变得更加强大。

# `<numeric>`头文件 - accumulate

有趣的是，形成`map`/`reduce`模式的两个高阶函数之一，即函数式编程中最常见的模式之一，最终出现在 C++的两个不同的头文件中。`transform`/`accumulate`组合需要`<algorithm>`和`<numeric>`头文件，可以解决许多具有以下模式的问题：

+   提供了一个集合。

+   集合需要转换为其他形式。

+   需要计算一个聚合结果。

让我们看一些例子。

# 计算购物车的含税总价

假设我们有一个`Product`结构，如下所示：

```cpp
struct Product{
    string name;
    string category;
    double price;
    Product(string name, string category, double price): name(name), 
        category(category), price(price){}
};
```

假设我们根据产品类别有不同的税率：

```cpp
map<string, int> taxLevelByCategory = {
    {"book", 5},
    {"cosmetics", 20},
    {"food", 10},
    {"alcohol", 40}
};
```

假设我们有一个产品列表，如下所示：

```cpp
    vector<Product> products = {
        Product("Lord of the Rings", "book", 22.50),
        Product("Nivea", "cosmetics", 15.40),
        Product("apple", "food", 0.30),
        Product("Lagavulin", "alcohol", 75.35)
    };

```

让我们计算含税和不含税的总价。我们还有一个辅助包装器`accumulateAll`可供使用：

```cpp
auto accumulateAll = [](auto collection, auto initialValue,  auto 
    lambda){
        return accumulate(collection.begin(), collection.end(), 
            initialValue, lambda);
};
```

要计算不含税的价格，我们只需要获取所有产品的价格并相加。这是一个典型的`map`/`reduce`场景：

```cpp
   auto totalWithoutTax = accumulateAll(transformAll<vector<double>>
        (products, [](Product product) { return product.price; }), 0.0, 
            plus<double>());
     CHECK_EQ(113.55, doctest::Approx(totalWithoutTax));
```

首先，我们将`Products`列表转换为价格列表，然后将它们进行`reduce`（或`accumulate`）处理，得到一个单一的值——它的总价。

当我们需要含税的总价时，一个类似但更复杂的过程也适用：

```cpp
    auto pricesWithTax = transformAll<vector<double>>(products, 
            [](Product product){
                int taxPercentage = 
                    taxLevelByCategory[product.category];
                return product.price + product.price * 
                    taxPercentage/100;
            });
    auto totalWithTax = accumulateAll(pricesWithTax, 0.0, 
        plus<double> ());
    CHECK_EQ(147.925, doctest::Approx(totalWithTax));
```

首先，我们将`Products`列表与含税价格列表进行`map`（`transform`）处理，然后将所有值进行`reduce`（或`accumulate`）处理，得到含税总价。

如果你想知道，`doctest::Approx`函数允许对浮点数进行小的舍入误差比较。

# 将列表转换为 JSON

在前一节中，我们看到如何通过`transform`调用将列表中的每个项目转换为 JSON。通过`accumulate`的帮助，很容易将其转换为完整的 JSON 列表：

```cpp
    string expectedJSONList = "{people: {'person': {'name': 'Alex', 
        'age': '42'}}, {'person': {'name': 'John', 'age': '21'}}, 
            {'person': {'name': 'Jane', 'age': '14'}}}"; 
    string peopleAsJSONList = "{people: " + accumulateAll(peopleAsJson, 
        string(),
            [](string first, string second){
                return (first.empty()) ? second : (first + ", " + 
                    second);
            }) + "}";
    CHECK_EQ(expectedJSONList, peopleAsJSONList);
```

我们使用`transform`将人员列表转换为每个对象的 JSON 表示的列表，然后我们使用`accumulate`将它们连接起来，并使用一些额外的操作来添加 JSON 中列表表示的前后部分。

正如你所看到的，`transform`/`accumulate`（或`map`/`reduce`）组合可以根据我们传递给它的函数执行许多不同的用途。

# 回到<algorithm> – find_if 和 copy_if

我们可以通过`transform`、`accumulate`和`any_of`/`all_of`/`none_of`实现很多事情。然而，有时我们需要从集合中过滤掉一些数据。

通常的做法是使用`find_if`。然而，如果我们需要找到集合中符合特定条件的所有项目，`find_if`就显得很麻烦了。因此，使用 C++ 17 标准以函数式方式解决这个问题的最佳选择是`copy_if`。以下示例使用`copy_if`在人员列表中找到所有未成年人：

```cpp
TEST_CASE("Find all minors"){
    vector<Person> people = {
        Person("Alex", 42),
        Person("John", 21),
        Person("Jane", 14),
        Person("Diana", 9)
    };

    vector<Person> expectedMinors{Person("Jane", 14), 
                                  Person("Diana", 9)};

    vector<Person> minors;
    copy_if(people.begin(), people.end(), back_inserter(minors), []
        (Person& person){ return person.age < 18; });

    CHECK_EQ(minors, expectedMinors);
}
```

# <optional>和<variant>

我们已经讨论了很多快乐路径的情况，即数据对我们的数据转换是有效的情况。那么对于边缘情况和错误情况，我们该怎么办呢？当然，在特殊情况下，我们可以抛出异常或返回错误情况，但是在我们需要返回错误消息的情况下呢？

在这些情况下，功能性的方式是返回数据结构。毕竟，即使输入无效，我们也需要返回一个输出值。但我们面临一个挑战——在错误情况下我们需要返回的类型是错误类型，而在有效数据情况下我们需要返回的类型是更多的有效数据。

幸运的是，我们有两种结构在这些情况下支持我们——`std::optional`和`std::variant`。让我们以一个人员列表为例，其中一些人是有效的，一些人是无效的：

```cpp
    vector<Person> people = {
        Person("Alex", 42),
        Person("John", 21),
        Person("Jane", 14),
        Person("Diana", 0)
    };
```

最后一个人的年龄无效。让我们尝试以一种功能性的方式编写代码，以显示以下字符串：

```cpp
Alex, major
John, major
Jane, minor
Invalid person
```

要有一系列的转换，我们需要使用`optional`类型，如下所示：

```cpp
struct MajorOrMinorPerson{
    Person person;
    optional<string> majorOrMinor;

    MajorOrMinorPerson(Person person, string majorOrMinor) : 
        person(person), majorOrMinor(optional<string>(majorOrMinor)){};

    MajorOrMinorPerson(Person person) : person(person), 
        majorOrMinor(nullopt){};
};
    auto majorMinorPersons = transformAll<vector<MajorOrMinorPerson>>
        (people, [](Person& person){ 
            if(person.age <= 0) return MajorOrMinorPerson(person);
            if(person.age > 0 && person.age < 18) return 
                MajorOrMinorPerson(person, "minor");
            return MajorOrMinorPerson(person, "major");
            });
```

通过这个调用，我们得到了一个人和一个值之间的配对列表，该值要么是`nullopt`，要么是`minor`，要么是`major`。我们可以在下面的`transform`调用中使用它，以根据有效条件获取字符串列表：

```cpp
    auto majorMinorPersonsAsString = transformAll<vector<string>>
        (majorMinorPersons, [](MajorOrMinorPerson majorOrMinorPerson){
            return majorOrMinorPerson.majorOrMinor ? 
            majorOrMinorPerson.person.name + ", " + 
                majorOrMinorPerson.majorOrMinor.value() :
                    "Invalid person";
            });
```

最后，调用 accumulate 创建了预期的输出字符串：

```cpp
    auto completeString = accumulateAll(majorMinorPersonsAsString, 
        string(), [](string first, string second){
            return first.empty() ? second : (first + "\n" + second);
            });
```

我们可以通过测试来检查这一点：

```cpp
    string expectedString("Alex, major\nJohn, major\nJane, 
                                    minor\nInvalid person");

    CHECK_EQ(expectedString, completeString);
```

如果需要，可以使用`variant`来实现另一种方法，例如，返回与人员组合的错误代码。

# C++ 20 和范围库

我们在第十四章中详细讨论了范围库，*使用范围库进行惰性评估*。如果你可以使用它，要么是因为你使用 C++ 20，要么是因为你可以将它作为第三方库使用，那么前面的函数就变得非常简单且更快：

```cpp
TEST_CASE("Ranges"){
    vector<Person> people = {
        Person("Alex", 42),
        Person("John", 21),
        Person("Jane", 14),
        Person("Diana", 0)
    };
    using namespace ranges;

    string completeString = ranges::accumulate(
            people |
            view::transform(personToMajorMinor) | 
            view::transform(majorMinor),
            string(),
            combineWithNewline
           ); 
    string expectedString("Alex, major\nJohn, major\nJane, 
                                    minor\nInvalid person");

    CHECK_EQ(expectedString, completeString);
}
```

同样，从人员列表中找到未成年人的列表在范围的`view::filter`中非常容易：

```cpp
TEST_CASE("Find all minors with ranges"){
    using namespace ranges;

    vector<Person> people = {
        Person("Alex", 42),
        Person("John", 21),
        Person("Jane", 14),
        Person("Diana", 9)
    };
    vector<Person> expectedMinors{Person("Jane", 14),
                                   Person("Diana", 9)};

    vector<Person> minors = people | view::filter(isMinor);

    CHECK_EQ(minors, expectedMinors);
}
```

一旦我们有了`isMinor`谓词，我们可以将它传递给`view::filter`来从人员列表中找到未成年人。

# 摘要

在本章中，我们对 C++ 17 STL 中可用的函数式编程特性进行了介绍，以及 C++ 20 中的新特性。通过函数、算法、`variant`和`optional`在错误或边缘情况下提供的帮助，以及使用范围库可以实现的简化和优化代码，我们对函数式编程特性有了相当好的支持。

现在，是时候进入下一章，看看 C++ 17 对函数式编程的语言支持，以及 C++ 20 中即将出现的有趣的事情了。


# 第十六章：标准语言支持和提案

在本书中，我们已经涉及了许多主题，现在是时候将它们全部归纳到一个方便的章节中，以帮助您记住我们涵盖的函数式编程技术的使用方法。我们将利用这个机会来看看 C++ 20 标准，并提及我们如何在我们的代码中使用这些新功能。

本章将涵盖以下主题：

+   C++中编写纯函数的支持方式和未来提案

+   C++中编写 lambda 的支持方式和未来提案

+   C++中柯里化的支持方式和未来提案

+   C++中函数组合的支持方式和未来提案

# 技术要求

您将需要一个支持 C++ 17 的编译器；我使用的是 GCC 7.4.0c。

代码在 GitHub 上的[https:/​/​github.​com/​PacktPublishing/​Hands-​On-​Functional-Programming-​with-​Cpp](https://github.%E2%80%8Bcom/PacktPublishing/Hands-On-Functional-Programming-with-Cpp)的`Chapter16`文件夹中。它包括并使用`doctest`，这是一个单头开源单元测试库。您可以在 GitHub 存储库中找到它：[https:/​/github.​com/​onqtam/​doctest](https://github.%E2%80%8Bcom/onqtam/doctest)。

# 标准语言支持和提案

到目前为止，我们已经探讨了在 C++中以函数式风格编写代码的几种方式。现在，我们将看看 C++ 17 标准允许的一些额外选项，以及 C++ 20 允许的一些选项。因此，让我们开始编写纯函数。

# 纯函数

纯函数是在接收相同输入时返回相同输出的函数。它们的可预测性使它们对于理解编写的代码与其运行时性能的相关性非常有用。

我们在第二章中发现，要在 C++中编写纯函数，需要结合`const`和`static`，具体取决于函数是类的一部分还是自由函数，并且取决于我们如何将参数传递给函数。为了方便起见，我将在此重述我们在纯函数语法上的结论：

+   类函数，按值传递：

+   `static int increment(const int value)`

+   `int increment(const int value) const`

+   类函数，按引用传递：

+   `static int increment(const int& value)`

+   `int increment(const int&value) const`

+   类函数，按值传递指针：

+   `static const int* increment(const int* value)`

+   `const int* increment(const int* value) const`

+   类函数，按引用传递指针：

+   `static const int* increment(const int* const& value)`

+   `const int* increment(const int* const& value) const`

+   独立函数，按值传递`int increment(const int value)`

+   独立函数，按引用传递`int increment(const int& value)`

+   独立函数，按指针传递值`const int* increment(const int* value)`

+   独立函数，按引用传递指针`const int* increment(const int* const& value)`

我们还发现，虽然编译器有助于减少副作用，但它并不总是告诉我们一个函数是纯的还是不纯的。在编写纯函数时，我们始终需要记住使用这三个标准，并小心应用它们：

+   它总是为相同的输入值返回相同的输出值。

+   它没有副作用。

+   它不会改变其参数值。

# Lambda 表达式

Lambda 是函数式编程的基本部分，允许我们对函数进行操作。C++自 C++11 以来就有 lambda，但最近对语法进行了一些添加。此外，我们将探讨一些 lambda 功能，在本书中我们还没有使用过，但对您自己的代码可能会有用。

让我们从一个简单的 lambda 开始——`increment`有一个输入并返回增加后的值：

```cpp
TEST_CASE("Increment"){
    auto increment =  [](auto value) { return value + 1;};

    CHECK_EQ(2, increment(1));
}
```

方括号（`[]`）指定了捕获值的列表，我们将在以下代码中看到。我们可以以与任何函数相同的方式指定参数的类型：

```cpp
TEST_CASE("Increment"){
    auto increment =  [](int value) { return value + 1;};

    CHECK_EQ(2, increment(1));
}
```

我们还可以在参数列表后立即指定返回值，并加上`->`符号：

```cpp
TEST_CASE("Increment"){
    auto increment =  [](int value) -> int { return value + 1;};

    CHECK_EQ(2, increment(1));
}
```

如果没有输入值，参数列表和圆括号`()`可以被忽略：

```cpp
TEST_CASE("One"){
    auto one =  []{ return 1;};

    CHECK_EQ(1, one());
}
```

通过指定名称来捕获一个值，这样它就会被复制：

```cpp
TEST_CASE("Capture value"){
    int value = 5;
    auto addToValue =  value { return value + toAdd;};

    CHECK_EQ(6, addToValue(1));
}
```

或者，我们可以通过引用捕获一个值，使用捕获说明中的`&`运算符：

```cpp
TEST_CASE("Capture value by reference"){
    int value = 5;
    auto addToValue =  &value { return value + toAdd;};

    CHECK_EQ(6, addToValue(1));
}
```

如果我们捕获多个值，我们可以枚举它们，也可以捕获所有值。对于按值捕获，我们使用`=`说明符：

```cpp
TEST_CASE("Capture all values by value"){
    int first = 5;
    int second = 10;
    auto addToValues = = { return first + second + 
        toAdd;};
    CHECK_EQ(16, addToValues(1));
}
```

要通过引用捕获所有值，我们使用`&`说明符而不带任何变量名：

```cpp
TEST_CASE("Capture all values by reference"){
    int first = 5;
    int second = 10;
    auto addToValues = & { return first + second + 
        toAdd;};
    CHECK_EQ(16, addToValues(1));
}
```

虽然不推荐，但我们可以在参数列表后使用`mutable`说明符使 lambda 调用可变：

```cpp
TEST_CASE("Increment mutable - NOT RECOMMENDED"){
    auto increment =  [](int& value) mutable { return ++value;};

    int value = 1;
    CHECK_EQ(2, increment(value));
    CHECK_EQ(2, value);
}

```

此外，从 C++ 20 开始，我们可以指定函数调用为`consteval`，而不是默认的`constexpr`：

```cpp
TEST_CASE("Increment"){
    auto one = []() consteval { return 1;};

    CHECK_EQ(1, one());
}
```

不幸的是，这种用法在 g++8 中尚不受支持。

异常说明也是可能的；也就是说，如果 lambda 没有抛出异常，那么`noexcept`可能会派上用场：

```cpp
TEST_CASE("Increment"){
    auto increment =  [](int value) noexcept { return value + 1;};

    CHECK_EQ(2, increment(1));
}

```

如果 lambda 抛出异常，可以指定为通用或特定：

```cpp
TEST_CASE("Increment"){
    auto increment =  [](int value) throw() { return value + 1;};

    CHECK_EQ(2, increment(1));
}
```

但是，如果您想使用通用类型怎么办？在 C++ 11 中，您可以使用`function<>`类型。从 C++ 20 开始，所有类型约束的好处都可以以一种简洁的语法用于 lambda。

```cpp
TEST_CASE("Increment"){
    auto increment =  [] <typename T>(T value) -> requires 
        NumericType<T> { return value + 1;};

    CHECK_EQ(2, increment(1));
}
```

不幸的是，这在 g++8 中也尚不受支持。

# 部分应用和柯里化

**部分应用**意味着通过在`1`（或更多，但少于*N*）个参数上应用具有*N*个参数的函数来获得一个新函数。

我们可以通过实现一个传递参数的函数或 lambda 来手动实现部分应用。以下是使用`std::plus`函数实现部分应用以获得一个`increment`函数的例子，将其中一个参数设置为`1`：

```cpp
TEST_CASE("Increment"){
    auto increment =  [](const int value) { return plus<int>()(value, 
        1); };

    CHECK_EQ(2, increment(1));
}
```

在本书中，我们主要关注了如何在这些情况下使用 lambda；然而值得一提的是，我们也可以使用纯函数来实现相同的目标。例如，相同的增量函数可以编写为普通的 C++函数：

```cpp
namespace Increment{
    int increment(const int value){
        return plus<int>()(value, 1);
    };
}

TEST_CASE("Increment"){
    CHECK_EQ(2, Increment::increment(1));
}
```

在 C++中可以使用`bind()`函数进行部分应用。`bind()`函数允许我们为函数绑定参数值，从而可以从`plus`派生出`increment`函数，如下所示：

```cpp
TEST_CASE("Increment"){
    auto increment = bind(plus<int>(), _1, 1);

    CHECK_EQ(2, increment(1));
}
```

`bind`接受以下参数：

+   我们想要绑定的函数。

+   要绑定到的参数；这些可以是值或占位符（如`_1`、`_2`等）。占位符允许将参数转发到最终函数。

在纯函数式编程语言中，部分应用与柯里化相关联。**柯里化**是将接受*N*个参数的函数分解为接受一个参数的*N*个函数。在 C++中没有标准的柯里化函数，但我们可以通过使用 lambda 来实现。让我们看一个柯里化`pow`函数的例子：

```cpp
auto curriedPower = [](const int base) {
    return base {
        return pow(base, exponent);
    };
};

TEST_CASE("Power and curried power"){
    CHECK_EQ(16, pow(2, 4));
    CHECK_EQ(16, curriedPower(2)(4));
}
```

如您所见，借助柯里化的帮助，我们可以通过只使用一个参数调用柯里化函数来自然地进行部分应用，而不是两个参数：

```cpp
    auto powerOf2 = curriedPower(2);
    CHECK_EQ(16, powerOf2(4));
```

这种机制在许多纯函数式编程语言中默认启用。然而，在 C++中更难实现。C++中没有标准支持柯里化，但我们可以创建自己的`curry`函数，该函数接受现有函数并返回其柯里化形式。以下是一个具有两个参数的通用`curry`函数的示例：

```cpp
template<typename F>
auto curry2(F f){
    return ={
        return ={
            return f(first, second);
        };
    };
}
```

此外，以下是如何使用它进行柯里化和部分应用：

```cpp
TEST_CASE("Power and curried power"){
    auto power = [](const int base, const int exponent){
        return pow(base, exponent);
    };
    auto curriedPower = curry2(power);
    auto powerOf2 = curriedPower(2);
    CHECK_EQ(16, powerOf2(4));
}
```

现在让我们看看实现函数组合的方法。

# 函数组合

函数组合意味着取两个函数*f*和*g*，并获得一个新函数*h*；对于任何值，*h(x) = f(g(x))*。我们可以手动实现函数组合，无论是在 lambda 中还是在普通函数中。例如，给定两个函数，`powerOf2`计算`2`的幂，`increment`增加一个值，我们将看到以下结果：

```cpp
auto powerOf2 = [](const int exponent){
    return pow(2, exponent);
};

auto increment = [](const int value){
    return value + 1;
};
```

我们可以通过简单地将调用封装到一个名为`incrementPowerOf2`的 lambda 中来组合它们：

```cpp
TEST_CASE("Composition"){
    auto incrementPowerOf2 = [](const int exponent){
        return increment(powerOf2(exponent));
    };

    CHECK_EQ(9, incrementPowerOf2(3));
}
```

或者，我们可以简单地使用一个简单的函数，如下所示：

```cpp
namespace Functions{
    int incrementPowerOf2(const int exponent){
        return increment(powerOf2(exponent));
    };
}

TEST_CASE("Composition"){
    CHECK_EQ(9, Functions::incrementPowerOf2(3));
}
```

然而，一个接受两个函数并返回组合函数的运算符非常方便，在许多编程语言中都有实现。在 C++中最接近函数组合运算符的是`|`管道运算符，它来自于 ranges 库，目前已经包含在 C++ 20 标准中。然而，虽然它实现了组合，但对于一般函数或 lambda 并不适用。幸运的是，C++是一种强大的语言，我们可以编写自己的 compose 函数，正如我们在第四章中发现的，*函数组合的概念*。

```cpp
template <class F, class G>
auto compose(F f, G g){
    return ={return f(g(value));};
}

TEST_CASE("Composition"){
    auto incrementPowerOf2 = compose(increment, powerOf2); 

    CHECK_EQ(9, incrementPowerOf2(3));
}
```

回到 ranges 库和管道运算符，我们可以在 ranges 的上下文中使用这种形式的函数组合。我们在第十四章中对这个主题进行了广泛探讨，*使用 ranges 库进行惰性求值*，这里有一个使用管道运算符计算集合中既是`2`的倍数又是`3`的倍数的所有数字的和的例子：

```cpp
auto isEven = [](const auto number){
    return number % 2 == 0;
};

auto isMultipleOf3 = [](const auto number){
    return number % 3 == 0;
};

auto sumOfMultiplesOf6 = [](const auto& numbers){
    return ranges::accumulate(
            numbers | ranges::view::filter(isEven) | 
                ranges::view::filter(isMultipleOf3), 0);
};

TEST_CASE("Sum of even numbers and of multiples of 6"){
    list<int> numbers{1, 2, 5, 6, 10, 12, 17, 25};

    CHECK_EQ(18, sumOfMultiplesOf6(numbers));
}
```

正如你所看到的，在标准 C++中有多种函数式编程的选项，而且 C++ 20 中还有一些令人兴奋的发展。

# 总结

这就是了！我们已经快速概述了函数式编程中最重要的操作，以及我们如何可以使用 C++ 17 和 C++ 20 来实现它们。我相信你现在掌握了更多工具，包括纯函数、lambda、部分应用、柯里化和函数组合，仅举几例。

从现在开始，你可以自行选择如何使用它们。选择一些，或者组合它们，或者慢慢将你的代码从可变状态转移到不可变状态；掌握这些工具将使你在编写代码的方式上拥有更多选择和灵活性。

无论你选择做什么，我祝你在你的项目和编程生涯中好运。愉快编码！


# 第十七章：评估

# 第一章

1.  什么是不可变函数？

不可变函数是一个不改变其参数值或程序状态的函数。

1.  如何编写一个不可变函数？

如果你希望编译器帮助你，将参数设为`const`。

1.  不可变函数如何支持代码简洁性？

因为它们不改变它们的参数，所以它们从代码中消除了任何潜在的复杂性，从而使程序员更好地理解它。

1.  不可变函数如何支持简单设计？

不可变函数很无聊，因为它们只做计算。因此，它们有助于长时间的维护。

1.  什么是高级函数？

高级函数是一个接收另一个函数作为参数的函数。

1.  STL 中可以给出哪些高级函数的例子？

STL 中有许多高级函数的例子，特别是在算法中。`sort`是我们在本章中使用的例子；然而，如果你查看`<algorithm>`头文件，你会发现许多其他例子，包括`find`、`find_if`、`count`、`search`等等。

1.  函数式循环相对于结构化循环的优势是什么？它们的潜在缺点是什么？

函数式循环避免了一次循环错误，并更清晰地表达了代码的意图。它们也是可组合的，因此可以通过链接多个循环来进行复杂的操作。然而，当组合时，它们需要多次通过集合，而这可以通过使用简单循环来避免。

1.  Alan Kay 的角度看 OOP 是什么？它如何与函数式编程相关？

Alan Kay 将 OOP 视为按细胞有机体原则构建代码的一种方式。细胞是通过化学信号进行通信的独立实体。因此，小对象之间的通信是 OOP 最重要的部分。

这意味着我们可以在表示为对象的数据结构上使用函数算法而不会产生任何冲突。

# 第二章

1.  什么是纯函数？

纯函数有两个约束条件，如下所示：

1.  +   它总是对相同的参数值返回相同的输出值。

+   它没有副作用。

1.  不可变性与纯函数有什么关系？

纯函数是不可变的，因为它们不会改变程序状态中的任何内容。

1.  如何告诉编译器防止传递的变量发生变化？

只需将参数定义为`const`，如下所示：

```cpp
int square(const int value)
```

1.  如何告诉编译器防止通过引用传递的变量发生变化？

只需将参数定义为`const&`，如下所示：

```cpp
int square(const int& value)
```

1.  如何告诉编译器防止通过引用传递的指针地址发生变化？

如果通过值传递指针，不需要任何操作，因为所有的更改都将局限于函数内部：

```cpp
int square(int* value)
```

如果通过引用传递指针，我们需要告诉编译器地址不能改变：

```cpp
int square(int*& const value)
```

1.  如何告诉编译器防止指针指向的值发生变化？

如果通过值传递指针，我们将应用与通过值传递的简单值相同的规则：

```cpp
int square(const int* value)
```

为了防止通过引用传递指针时对值和地址的更改，需要更多地使用`const`关键字：

```cpp
int square(const int&* const value)
```

# 第三章

1.  你可以写一个最简单的 lambda 吗？

最简单的 lambda 不接收参数并返回一个常量；可以是以下内容：

```cpp
auto zero = [](){return 0;};
```

1.  如何编写一个连接作为参数传递的两个字符串值的 lambda？

根据您喜欢的字符串连接方式，这个答案有几种变化。使用 STL 的最简单方法如下：

```cpp
auto concatenate = [](string first, string second){return first + second;};
```

1.  如果其中一个值是按值捕获的变量怎么办？

答案类似于前面的解决方案，但使用上下文中的值：

```cpp
auto concatenate = first{return first + second;};
```

当然，我们也可以使用默认的按值捕获符号，如下所示：

```cpp
auto concatenate = ={return first + second;};
```

1.  如果其中一个值是通过引用捕获的变量怎么办？

与前一个解决方案相比，除非您想要防止值的更改，否则几乎没有变化，如下所示：

```cpp
auto concatenate = &first{return first + second;};
```

如果要防止值的更改，我们需要转换为`const`：

```cpp
auto concatenate = &firstValue = as_const(first){return firstValue + second;};
```

1.  如果其中一个值是以值方式捕获的指针会怎样？

我们可以忽略不可变性，如下所示：

```cpp
auto concatenate = ={return *pFirst + second;};
```

或者，我们可以使用指向`const`类型的指针：

```cpp
const string* pFirst = new string("Alex");
auto concatenate = ={return *pFirst + second;};
```

或者，我们可以直接使用该值，如下所示：

```cpp
string* pFirst = new string("Alex");
first = *pFirst;
auto concatenate = ={return first + second;}
```

1.  如果其中一个值是以引用方式捕获的指针会怎样？

这使我们可以在 lambda 内部更改指向的值和指针地址。

最简单的方法是忽略不可变性，如下所示：

```cpp
auto concatenate = &{return *pFirst + second;};
```

如果我们想要限制不可变性，我们可以使用转换为`const`：

```cpp
auto concatenate = &first = as_const(pFirst){return *first + second;};
```

然而，通常最好的方法是直接使用该值，如下所示：

```cpp
string first = *pFirst;
auto concatenate = ={return first + second;};
```

1.  如果两个值都使用默认捕获说明符以值方式捕获，会怎么样？

这个解决方案不需要参数，只需要从上下文中捕获两个值：

```cpp
auto concatenate = [=](){return first + second;};
```

1.  如果两个值都使用默认捕获说明符以引用方式捕获，会怎么样？

如果我们不关心值的变化，我们可以这样做：

```cpp
auto concatenate = [&](){return first + second;};
```

为了保持不可变性，我们需要将其转换为`const`：

```cpp
auto concatenate = [&firstValue = as_const(first), &secondValue = as_const(second)](){return firstValue + secondValue;}
```

只使用默认的引用捕获说明符无法确保不可变性。请改用值方式捕获。

1.  如何在具有两个字符串值作为数据成员的类中将相同的 lambda 写为数据成员？

在类中，我们需要指定 lambda 变量的类型以及是否捕获两个数据成员或 this。

以下代码显示了如何使用`[=]`语法以复制方式捕获值：

```cpp
function<string()> concatenate = [=](){return first + second;};
```

以下代码显示了如何捕获`this`：

```cpp
function<string()> concatenate = [this](){return first + second;};
```

1.  如何在同一类中将相同的 lambda 写为静态变量？

我们需要将数据成员作为参数接收，如下所示：

```cpp
static function<string()> concatenate;
...
function<string()> AClass::concatenate = [](string first, string second){return first + second;};
```

我们已经看到，这比传递整个`AClass`实例作为参数更好，因为它减少了函数和类之间的耦合区域。

# 第四章

1.  什么是函数组合？

函数组合是函数的操作。它接受两个函数*f*和*g*，并创建第三个函数*C*，对于任何参数*x*，*C(x) = f(g(x))*。

1.  函数组合具有通常与数学操作相关联的属性。它是什么？

函数组合不是可交换的。例如，对一个数字的增量进行平方不同于对一个数字的平方进行增量。

1.  如何将带有两个参数的加法函数转换为带有一个参数的两个函数？

考虑以下函数：

```cpp
auto add = [](const int first, const int second){ return first + second; };
```

我们可以将前面的函数转换为以下形式：

```cpp
auto add = [](const int first){ 
    return first{
        return first + second;
    };
};
```

1.  如何编写一个包含两个单参数函数的 C++函数？

在本章中，我们看到借助模板和`auto`类型的魔力，这是非常容易做到的：

```cpp
template <class F, class G>
auto compose(F f, G g){
  return ={return f(g(value));};
}
```

1.  函数组合的优势是什么？

函数组合允许我们通过组合非常简单的函数来创建复杂的行为。此外，它允许我们消除某些类型的重复。它还通过允许以无限方式重新组合小函数来提高重用的可能性。

1.  实现函数操作的潜在缺点是什么？

函数的操作可以有非常复杂的实现，并且可能变得非常难以理解。抽象是有代价的，程序员必须始终平衡可组合性和小代码的好处与使用抽象操作的成本。

# 第五章

1.  什么是部分函数应用？

部分函数应用是从一个接受*N*个参数的函数中获取一个新函数的操作，该函数通过将其中一个参数绑定到一个值来接受*N-1*个参数。

1.  什么是柯里化？

柯里化是将接受*N*个参数的函数拆分为*N*个函数的操作，每个函数接受一个参数。

1.  柯里化如何帮助实现部分应用？

给定柯里化函数*f(x)(y)*，对*x = value*的*f*的部分应用可以通过简单地像这样调用*f*来获得：*g = f(value)*。

1.  **我们如何在 C++中实现部分应用？**

部分应用可以在 C++中手动实现，但使用`functional`头文件中的`bind`函数来实现会更容易。
